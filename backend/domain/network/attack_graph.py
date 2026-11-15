"""Attack paths and blast radius, built from an imported snapshot.

Pure Python (no Django). An edge A -> B means "an attacker who controls A can move to B" (network
reach, an instance profile, IAM assume-role, data access...). Probability of a hop is
``exploitability * (0.7 + 0.03 * cvss)`` where ``cvss`` is the highest score among the target's
known vulnerabilities (0 when none; snapshots carry no CVE data, so the factor is the 0.7 baseline).

Where the graph comes from
--------------------------
``build_attack_graph(config, extensions)`` derives it from the *same* configuration the rule engine
and the reachability engine use, so nothing is invented:

* internet -> instance and instance -> instance edges exist only where ``Reachability`` says
  ``allowed`` (``unknown`` is kept at half the exploitability and marked unverified);
* load balancer, database, bucket and IAM edges come from the optional ``extensions`` section and
  from security-group rules (databases and load balancers are checked against security groups only;
  NACLs are not evaluated for them, which the graph reports in ``warnings``).

Search
------
``attack_paths`` is a best-first search with an admissible bound (best achievable ``probability *
impact`` from each node, computed once by a reverse pass). It stops as soon as the best open
candidate cannot beat the current k-th result and also stops after ``MAX_EXPANSIONS`` expansions,
reporting ``truncated`` so a huge graph can never hang a request.

Simulation
----------
``simulate_fix`` removes nodes and/or edges. ``simulate_change`` applies a *validated security-group
change* (the same ``ProposedChange`` the digital-twin simulator uses) to a copy of the configuration,
rebuilds the graph and compares risk, which is how a real fix behaves (a rule or an edge changes,
not a whole host).
"""

from __future__ import annotations

import heapq
import ipaddress
import itertools
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from domain.network.extensions import Extensions
from domain.network.proposals import ProposedChange
from domain.network.reachability import ALLOWED, INTERNET, UNKNOWN, PathQuery, Reachability
from domain.network.rules import SENSITIVE_PORTS, world_open_ingress
from domain.network.schema import NetworkConfig, SecurityGroup
from domain.network.simulation import apply_change
from domain.network.topology import build_topology

ATTACK_GRAPH_VERSION = "1.0"

MAX_EXPANSIONS = 200_000
_TIE_TOLERANCE = 1e-9  # float noise when comparing a bound with a real risk
MAX_PATH_EVALUATIONS = 3_000  # reachability questions asked while building one graph
MAX_PORTS_PER_INSTANCE = 12
UNVERIFIED_FACTOR = 0.5

_WEB_PORTS = (80, 443, 8000, 8080, 8443)
_KNOWN_PORTS = tuple(sorted({port for port, _ in SENSITIVE_PORTS.values()} | set(_WEB_PORTS)))

# How easy a hop over this port is (0..1). Admin/database ports need credentials; legacy plain-text
# services and unauthenticated stores are easier.
_PORT_EXPLOITABILITY = {
    22: 0.5,
    3389: 0.55,
    23: 0.8,
    21: 0.6,
    445: 0.6,
    2375: 0.9,
    5432: 0.6,
    3306: 0.6,
    1433: 0.6,
    27017: 0.7,
    6379: 0.8,
    9200: 0.8,
    11211: 0.8,
}
_DEFAULT_PORT_EXPLOITABILITY = 0.5
_ACCESS_EXPLOITABILITY = {"read": 0.6, "write": 0.75, "admin": 0.9}


# --------------------------------------------------------------------------
# Graph model and search
# --------------------------------------------------------------------------


@dataclass
class Node:
    id: str
    name: str
    type: str  # internet, load_balancer, ec2, iam_role, s3, rds, lambda ...
    criticality: int = 1  # 1 (low) .. 10 (business critical)
    internet_exposed: bool = False
    crown_jewel: bool = False
    vulns: list = field(default_factory=list)  # [{"id": "CVE-..", "cvss": 9.8}]


@dataclass
class Edge:
    source: str
    target: str
    kind: str  # network, iam_assume, data_access ...
    exploitability: float = 0.5  # 0..1 how easy the hop is
    label: str = ""
    evidence: dict = field(default_factory=dict)


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.adj: dict[str, list[Edge]] = defaultdict(list)
        self.last_search: dict[str, Any] = {"expanded": 0, "truncated": False}

    # ---------- construction ----------
    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError(f"Unknown node in edge {edge.source}->{edge.target}")
        if not 0 <= edge.exploitability <= 1:
            raise ValueError("exploitability must be between 0 and 1")
        self.adj[edge.source].append(edge)

    @classmethod
    def from_dict(cls, data: dict) -> AttackGraph:
        g = cls()
        for n in data.get("nodes", []):
            g.add_node(Node(**n))
        for e in data.get("edges", []):
            g.add_edge(Edge(**e))
        return g

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for es in self.adj.values() for e in es],
        }

    def without(self, node_ids: Iterable[str] = (), edges: Iterable[tuple[str, str]] = ()) -> AttackGraph:
        """Copy of the graph with nodes and/or (source, target) edges removed."""
        drop_nodes = set(node_ids)
        drop_edges = {(s, t) for s, t in edges}
        g = AttackGraph()
        for n in self.nodes.values():
            if n.id not in drop_nodes:
                g.add_node(Node(**asdict(n)))
        for es in self.adj.values():
            for e in es:
                if e.source in drop_nodes or e.target in drop_nodes or (e.source, e.target) in drop_edges:
                    continue
                g.add_edge(Edge(**asdict(e)))
        return g

    # ---------- scoring ----------
    def _edge_prob(self, e: Edge) -> float:
        cvss = max((v.get("cvss", 0) for v in self.nodes[e.target].vulns), default=0)
        return min(0.99, e.exploitability * (0.7 + 0.03 * cvss))

    def entry_points(self) -> list[str]:
        return [n.id for n in self.nodes.values() if n.internet_exposed or n.type == "internet"]

    def _node_brief(self, nid: str) -> dict:
        n = self.nodes[nid]
        return {
            "id": n.id,
            "name": n.name,
            "type": n.type,
            "criticality": n.criticality,
            "crown_jewel": n.crown_jewel,
        }

    # ---------- attack paths ----------
    def _impact_bounds(self, target_set: set[str]) -> dict[str, float]:
        """Best possible ``probability * impact`` from each node to any target (upper bound).

        Reverse max-product pass. Probabilities are <= 1, so values only shrink along a path and a
        plain best-first (Dijkstra-style) order is exact for the bound.
        """
        reverse: dict[str, list[Edge]] = defaultdict(list)
        for edges in self.adj.values():
            for e in edges:
                reverse[e.target].append(e)
        bound = {t: float(self.nodes[t].criticality) for t in target_set if t in self.nodes}
        heap = [(-value, node) for node, value in bound.items()]
        heapq.heapify(heap)
        done: set[str] = set()
        while heap:
            _, node = heapq.heappop(heap)
            if node in done:
                continue
            done.add(node)
            for e in reverse[node]:
                if e.source in target_set:  # a path stops at the first target it reaches
                    continue
                candidate = self._edge_prob(e) * bound[node]
                if candidate > bound.get(e.source, 0.0):
                    bound[e.source] = candidate
                    heapq.heappush(heap, (-candidate, e.source))
        return bound

    def attack_paths(
        self,
        sources: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 6,
        top_k: int = 10,
        min_prob: float = 0.001,
        max_expansions: int = MAX_EXPANSIONS,
    ) -> list[dict]:
        """Top ``top_k`` simple paths from the entry points to crown jewels, by ``risk``."""
        sources = sources or self.entry_points()
        target_set = set(targets or [n.id for n in self.nodes.values() if n.crown_jewel])
        bound = self._impact_bounds(target_set)

        counter = itertools.count()
        open_states: list[tuple] = []
        for s in sources:
            if s in self.nodes and s in bound and s not in target_set:
                heapq.heappush(open_states, (-bound[s], -1, next(counter), s, (s,), (), 1.0))

        top: list[tuple[float, int, dict]] = []  # min-heap of the best top_k results
        expanded = 0
        truncated = False
        while open_states:
            neg_priority, _, _, node, path, edges, prob = heapq.heappop(open_states)
            floor = top[0][0] if len(top) >= top_k else 0.0
            if -neg_priority <= floor * (1 + _TIE_TOLERANCE):
                break  # nothing left can beat the current k-th result
            expanded += 1
            if expanded > max_expansions:
                truncated = True
                break

            if node in target_set and edges:
                impact = self.nodes[node].criticality
                result = {
                    "node_ids": list(path),
                    "nodes": [self._node_brief(x) for x in path],
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "kind": e.kind,
                            "label": e.label,
                            "probability": round(self._edge_prob(e), 3),
                        }
                        for e in edges
                    ],
                    "probability": round(prob, 4),
                    "impact": impact,
                    "risk": round(prob * impact, 4),
                    "hops": len(edges),
                }
                heapq.heappush(top, (prob * impact, next(counter), result))
                if len(top) > top_k:
                    heapq.heappop(top)
                continue  # stop at the first crown jewel on this branch
            if len(edges) >= max_depth:
                continue

            floor = top[0][0] if len(top) >= top_k else 0.0
            for e in self.adj[node]:
                nxt = e.target
                if nxt in path or nxt not in bound:
                    continue
                p = prob * self._edge_prob(e)
                if p < min_prob:
                    continue
                priority = p * bound[nxt]
                if priority <= floor * (1 + _TIE_TOLERANCE):
                    continue
                # equal priorities: deeper partial paths first, so a first full path is found quickly
                depth_key = -(len(edges) + 2)
                heapq.heappush(
                    open_states,
                    (-priority, depth_key, next(counter), nxt, path + (nxt,), edges + (e,), p),
                )

        self.last_search = {"expanded": expanded, "truncated": truncated}
        return sorted((item[2] for item in top), key=lambda r: r["risk"], reverse=True)

    # ---------- blast radius ----------
    def blast_radius(self, start: str, max_depth: int = 4, min_prob: float = 0.01) -> dict:
        if start not in self.nodes:
            raise KeyError(start)
        best: dict[str, tuple[float, int, str | None]] = {start: (1.0, 0, None)}
        heap = [(-1.0, start)]
        done: set[str] = set()
        while heap:
            _, u = heapq.heappop(heap)
            if u in done:
                continue
            done.add(u)
            p, d, _ = best[u]
            if d >= max_depth:
                continue
            for e in self.adj[u]:
                np_ = p * self._edge_prob(e)
                if np_ < min_prob:
                    continue
                if e.target not in best or np_ > best[e.target][0]:
                    best[e.target] = (np_, d + 1, u)
                    heapq.heappush(heap, (-np_, e.target))

        reachable, tree_edges = [], []
        by_type: dict[str, int] = defaultdict(int)
        score, jewels = 0.0, []
        for nid, (p, d, parent) in best.items():
            if nid == start:
                continue
            n = self.nodes[nid]
            item = {
                **self._node_brief(nid),
                "probability": round(p, 4),
                "hops": d,
                "impact_score": round(p * n.criticality, 3),
            }
            reachable.append(item)
            by_type[n.type] += 1
            score += p * n.criticality
            if n.crown_jewel:
                jewels.append(item)
            tree_edges.append({"source": parent, "target": nid})
        reachable.sort(key=lambda r: r["impact_score"], reverse=True)

        if any(j["probability"] >= 0.3 for j in jewels) or score >= 20:
            severity = "critical"
        elif jewels or score >= 10:
            severity = "high"
        elif score >= 4:
            severity = "medium"
        else:
            severity = "low"

        return {
            "start": self._node_brief(start),
            "reachable_count": len(reachable),
            "reachable": reachable,
            "edges": tree_edges,
            "by_type": dict(by_type),
            "crown_jewels_reached": jewels,
            "total_impact_score": round(score, 2),
            "severity": severity,
        }

    # ---------- choke points & simulation ----------
    @staticmethod
    def choke_points(paths: list[dict], top_n: int = 5) -> list[dict]:
        agg: dict[str, dict] = defaultdict(lambda: {"paths": 0, "risk": 0.0})
        total = sum(p["risk"] for p in paths) or 1.0
        for p in paths:
            for nid, brief in zip(p["node_ids"][1:-1], p["nodes"][1:-1], strict=False):
                a = agg[nid]
                a["paths"] += 1
                a["risk"] += p["risk"]
                a["name"], a["type"] = brief["name"], brief["type"]
        out = [
            {
                "id": k,
                "name": v["name"],
                "type": v["type"],
                "paths": v["paths"],
                "risk_share": round(v["risk"] / total, 3),
            }
            for k, v in agg.items()
        ]
        out.sort(key=lambda x: (x["risk_share"], x["paths"]), reverse=True)
        return out[:top_n]

    def simulate_fix(
        self,
        remove_nodes: list[str] | None = None,
        max_depth: int = 6,
        remove_edges: list[tuple[str, str]] | None = None,
        top_k: int = 1000,
    ) -> dict:
        """Risk before/after removing nodes and/or (source, target) edges."""
        remove_nodes = remove_nodes or []
        remove_edges = remove_edges or []
        before = self.attack_paths(max_depth=max_depth, top_k=top_k)
        after = self.without(remove_nodes, remove_edges).attack_paths(max_depth=max_depth, top_k=top_k)
        return _compare(before, after) | {
            "removed": remove_nodes,
            "removed_edges": [list(e) for e in remove_edges],
        }


def _path_key(path: dict) -> str:
    return ">".join(path["node_ids"])


def _compare(before: list[dict], after: list[dict]) -> dict:
    rb, ra = sum(p["risk"] for p in before), sum(p["risk"] for p in after)
    after_keys = {_path_key(p) for p in after}
    before_keys = {_path_key(p) for p in before}
    return {
        "paths_before": len(before),
        "paths_after": len(after),
        "risk_before": round(rb, 3),
        "risk_after": round(ra, 3),
        "risk_reduction_pct": round((1 - ra / rb) * 100, 1) if rb else 0.0,
        "resolved_paths": [p for p in before if _path_key(p) not in after_keys][:20],
        "new_paths": [p for p in after if _path_key(p) not in before_keys][:20],
    }


# --------------------------------------------------------------------------
# Building the graph from a snapshot
# --------------------------------------------------------------------------


@dataclass
class BuildInfo:
    warnings: list[dict[str, str]] = field(default_factory=list)
    evaluations: int = 0

    def warn(self, code: str, message: str) -> None:
        if not any(w["code"] == code for w in self.warnings):
            self.warnings.append({"code": code, "message": message})


class _EdgeBook:
    """Collects edges, keeping the strongest one per (source, target, kind)."""

    def __init__(self) -> None:
        self.edges: dict[tuple[str, str, str], Edge] = {}

    def add(
        self, source: str, target: str, kind: str, exploitability: float, label: str, **evidence: Any
    ) -> None:
        key = (source, target, kind)
        existing = self.edges.get(key)
        if existing is None or exploitability > existing.exploitability:
            self.edges[key] = Edge(source, target, kind, round(exploitability, 3), label, dict(evidence))


def _port_exploitability(port: int) -> float:
    return _PORT_EXPLOITABILITY.get(port, _DEFAULT_PORT_EXPLOITABILITY)


def _candidate_ports(groups: list[SecurityGroup]) -> list[int]:
    """TCP ports worth asking about for a resource protected by ``groups`` (bounded)."""
    ports: set[int] = set()
    for group in groups:
        for rule in group.ingress:
            if rule.protocol == "-1":
                ports.update(_KNOWN_PORTS)
            elif rule.protocol == "tcp" and rule.from_port is not None and rule.to_port is not None:
                inside = [p for p in _KNOWN_PORTS if rule.from_port <= p <= rule.to_port]
                ports.update(inside or [rule.from_port])
    return sorted(ports)[:MAX_PORTS_PER_INSTANCE]


def _allows_from(
    groups: list[SecurityGroup],
    port: int,
    *,
    peer_sg_ids: frozenset[str] = frozenset(),
    source_ip: str | None = None,
) -> bool:
    """Do the ingress rules of ``groups`` let TCP ``port`` in from this source?

    A source matches through a rule that names one of its security groups, a CIDR that contains its
    private IP, or a rule open to the whole address space.
    """
    for group in groups:
        if world_open_ingress(group, port):
            return True
        for rule in group.ingress:
            if rule.protocol != "-1" and not (
                rule.protocol == "tcp"
                and rule.from_port is not None
                and rule.to_port is not None
                and rule.from_port <= port <= rule.to_port
            ):
                continue
            if rule.peer_security_group_id and rule.peer_security_group_id in peer_sg_ids:
                return True
            if rule.cidr and source_ip:
                try:
                    if ipaddress.ip_address(source_ip) in ipaddress.ip_network(rule.cidr, strict=False):
                        return True
                except ValueError:
                    continue
    return False


def build_attack_graph(
    config: NetworkConfig, extensions: Extensions | None = None
) -> tuple[AttackGraph, BuildInfo]:
    """Derive the attack graph of a configuration (and its optional extensions)."""
    extensions = extensions or Extensions()
    info = BuildInfo()
    graph = AttackGraph()
    book = _EdgeBook()
    reach = Reachability(config)
    groups = {g.id: g for g in config.security_groups}
    subnet_public = {
        n.id: n.data.get("kind") == "public" for n in build_topology(config).nodes if n.type == "subnet"
    }

    graph.add_node(Node("internet", "Internet", "internet", criticality=1, internet_exposed=True))

    # ---- instances ----
    for inst in config.instances:
        tags = dict(inst.tags)
        try:
            criticality = min(10, max(1, int(tags.get("criticality", 4))))
        except (TypeError, ValueError):
            criticality = 4
        graph.add_node(Node(inst.id, inst.name or inst.id, "ec2", criticality=criticality))

    budget = MAX_PATH_EVALUATIONS

    def ask(source: str, destination: str, port: int):
        nonlocal budget
        if budget <= 0:
            info.warn(
                "EVALUATION_LIMIT",
                f"Stopped asking reachability questions after {MAX_PATH_EVALUATIONS}; some network "
                "edges may be missing in a very large snapshot.",
            )
            return None
        budget -= 1
        info.evaluations += 1
        return reach.evaluate(PathQuery(source, destination, "tcp", port))

    def factor(verdict: str) -> float:
        return 1.0 if verdict == ALLOWED else UNVERIFIED_FACTOR

    # internet -> instance
    for inst in config.instances:
        if not inst.public_ip:
            continue
        inst_groups = [groups[g] for g in inst.security_group_ids if g in groups]
        best: dict[str, Any] = {}
        for port in _candidate_ports(inst_groups):
            result = ask(INTERNET, inst.id, port)
            if result is None:
                break
            if result.result not in (ALLOWED, UNKNOWN):
                continue
            value = _port_exploitability(port) * factor(result.result)
            if not best or value > best["value"]:
                best["value"] = value
            best.setdefault("ports", []).append((port, result.result))
        if best:
            ports = ", ".join(f"tcp/{p}{'' if v == ALLOWED else '?'}" for p, v in best["ports"])
            graph.nodes[inst.id].internet_exposed = True
            book.add(
                "internet",
                inst.id,
                "network",
                best["value"],
                f"Internet reaches {ports}",
                ports=[p for p, _ in best["ports"]],
                security_groups=list(inst.security_group_ids),
                verified=all(v == ALLOWED for _, v in best["ports"]),
            )

    # instance -> instance (lateral movement)
    for dst in config.instances:
        dst_groups = [groups[g] for g in dst.security_group_ids if g in groups]
        ports = _candidate_ports(dst_groups)
        if not ports:
            continue
        for src in config.instances:
            if src.id == dst.id:
                continue
            best_value, hit_ports = 0.0, []
            for port in ports:
                result = ask(src.id, dst.id, port)
                if result is None:
                    break
                if result.result not in (ALLOWED, UNKNOWN):
                    continue
                best_value = max(best_value, _port_exploitability(port) * factor(result.result))
                hit_ports.append(port)
            if hit_ports:
                book.add(
                    src.id,
                    dst.id,
                    "network",
                    best_value,
                    "Allowed: " + ", ".join(f"tcp/{p}" for p in hit_ports),
                    ports=hit_ports,
                    security_groups=list(dst.security_group_ids),
                )

    # ---- load balancers ----
    for lb in extensions.load_balancers:
        lb_groups = [groups[g] for g in lb.security_group_ids if g in groups]
        graph.add_node(Node(lb.id, lb.name or lb.id, "load_balancer", criticality=3))
        public_subnet = any(subnet_public.get(s) for s in lb.subnet_ids)
        open_ports = [p for p in lb.listener_ports if any(world_open_ingress(g, p) for g in lb_groups)]
        if lb.scheme == "internet-facing" and public_subnet and open_ports:
            graph.nodes[lb.id].internet_exposed = True
            book.add(
                "internet",
                lb.id,
                "network",
                0.9,
                "Internet reaches listener " + ", ".join(f"tcp/{p}" for p in open_ports),
                ports=open_ports,
                security_groups=list(lb.security_group_ids),
            )
        for target_id in lb.target_instance_ids:
            target = next((i for i in config.instances if i.id == target_id), None)
            if target is None:
                continue
            target_groups = [groups[g] for g in target.security_group_ids if g in groups]
            for listener in lb.listener_ports:
                port = lb.target_port or listener
                if _allows_from(target_groups, port, peer_sg_ids=frozenset(lb.security_group_ids)):
                    book.add(
                        lb.id,
                        target_id,
                        "network",
                        0.7,
                        f"Load balancer forwards tcp/{port}",
                        ports=[port],
                        security_groups=list(target.security_group_ids),
                    )
                    break

    # ---- databases ----
    for db in extensions.databases:
        db_groups = [groups[g] for g in db.security_group_ids if g in groups]
        graph.add_node(
            Node(
                db.id,
                db.name or db.id,
                "rds",
                criticality=10 if db.sensitive else 6,
                crown_jewel=db.sensitive,
            )
        )
        if db.publicly_accessible and any(world_open_ingress(g, db.port) for g in db_groups):
            book.add(
                "internet",
                db.id,
                "network",
                0.7,
                f"Publicly accessible {db.engine} (tcp/{db.port})",
                ports=[db.port],
                security_groups=list(db.security_group_ids),
            )
        for inst in config.instances:
            if _allows_from(
                db_groups,
                db.port,
                peer_sg_ids=frozenset(inst.security_group_ids),
                source_ip=inst.private_ip,
            ):
                book.add(
                    inst.id,
                    db.id,
                    "data_access",
                    _port_exploitability(db.port),
                    f"{db.engine} tcp/{db.port} allowed by security group",
                    ports=[db.port],
                    security_groups=list(db.security_group_ids),
                )
    if extensions.databases or extensions.load_balancers:
        info.warn(
            "SG_ONLY_FOR_MANAGED",
            "Databases and load balancers are checked against security groups only; NACLs and routes "
            "are not evaluated for them.",
        )

    # ---- buckets ----
    for bucket in extensions.buckets:
        graph.add_node(
            Node(
                bucket.id,
                bucket.name or bucket.id,
                "s3",
                criticality=9 if bucket.sensitive else 4,
                crown_jewel=bucket.sensitive,
            )
        )
        if bucket.public:
            book.add("internet", bucket.id, "data_access", 0.95, "Public bucket", public=True)

    # ---- IAM roles ----
    data_ids = [d.id for d in extensions.databases] + [b.id for b in extensions.buckets]
    for role in extensions.iam_roles:
        is_admin = any(p.access == "admin" and "*" in p.resource_ids for p in role.permissions)
        graph.add_node(Node(role.id, role.name or role.id, "iam_role", criticality=9 if is_admin else 6))
    for role in extensions.iam_roles:
        for instance_id in role.instance_ids:
            if instance_id in graph.nodes:
                book.add(
                    instance_id,
                    role.id,
                    "iam_assume",
                    0.3 if role.imds_v2_required else 0.6,
                    "Instance profile credentials (IMDSv2 required)"
                    if role.imds_v2_required
                    else "Instance profile credentials (IMDS)",
                )
        for other in role.can_assume:
            book.add(role.id, other, "iam_assume", 0.5, "sts:AssumeRole")
        for permission in role.permissions:
            targets = data_ids if "*" in permission.resource_ids else list(permission.resource_ids)
            for target in targets:
                if target in graph.nodes:
                    book.add(
                        role.id,
                        target,
                        "data_access",
                        _ACCESS_EXPLOITABILITY[permission.access],
                        f"{permission.access} access",
                    )

    if extensions.nat_gateways or extensions.vpc_peerings:
        info.warn(
            "UNMODELLED_NETWORK",
            f"{len(extensions.nat_gateways)} NAT gateway(s) and {len(extensions.vpc_peerings)} VPC "
            "peering(s) are recorded but do not change attack paths (no reachability model yet).",
        )

    for edge in book.edges.values():
        graph.add_edge(edge)
    return graph, info


# --------------------------------------------------------------------------
# Fix simulation on a real change
# --------------------------------------------------------------------------


def simulate_change(
    config: NetworkConfig,
    extensions: Extensions | None,
    change: ProposedChange,
    *,
    max_depth: int = 6,
    top_k: int = 200,
) -> dict[str, Any]:
    """Attack-path risk before and after a validated security-group change.

    Nothing is applied anywhere: ``apply_change`` returns a modified copy of the configuration and
    the graph is rebuilt from that copy. Raises ``simulation.SimulationError`` when the change does
    not match any rule.
    """
    before_graph, _ = build_attack_graph(config, extensions)
    applied = apply_change(config, change)
    after_graph, info = build_attack_graph(applied.config, extensions)
    before = before_graph.attack_paths(max_depth=max_depth, top_k=top_k)
    after = after_graph.attack_paths(max_depth=max_depth, top_k=top_k)
    return _compare(before, after) | {
        "change": change.as_dict(),
        "modifications": list(applied.modifications),
        "warnings": list(applied.warnings) + info.warnings,
        "applied_to_cloud": False,
    }
