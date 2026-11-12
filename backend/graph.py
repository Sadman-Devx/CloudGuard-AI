"""Attack Path & Blast Radius engine for CloudGuard AI.

Models cloud assets as a directed graph. An edge A -> B means
"an attacker who controls A can move to B" (network reach, IAM assume-role,
data access, credential reuse ...).

Edge probability = exploitability * vulnerability factor of the target node.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field


@dataclass
class Node:
    id: str
    name: str
    type: str  # internet, load_balancer, ec2, iam_role, s3, rds, lambda, user ...
    criticality: int = 1  # 1 (low) .. 10 (business critical)
    internet_exposed: bool = False
    crown_jewel: bool = False
    vulns: list = field(default_factory=list)  # [{"id": "CVE-..", "cvss": 9.8}]


@dataclass
class Edge:
    source: str
    target: str
    kind: str  # network, iam_assume, data_access, credential ...
    exploitability: float = 0.5  # 0..1 how easy the hop is
    label: str = ""


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.adj: dict[str, list[Edge]] = defaultdict(list)

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

    def without(self, node_ids: Iterable[str]) -> AttackGraph:
        """Copy of the graph with nodes removed (used for fix simulation)."""
        drop = set(node_ids)
        g = AttackGraph()
        for n in self.nodes.values():
            if n.id not in drop:
                g.add_node(Node(**asdict(n)))
        for es in self.adj.values():
            for e in es:
                if e.source not in drop and e.target not in drop:
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
    def attack_paths(
        self,
        sources: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 6,
        top_k: int = 10,
        min_prob: float = 0.001,
    ) -> list[dict]:
        sources = sources or self.entry_points()
        target_set = set(targets or [n.id for n in self.nodes.values() if n.crown_jewel])
        results: list[dict] = []

        def dfs(node: str, path: list[str], edges: list[Edge], prob: float) -> None:
            if node in target_set and edges:
                impact = self.nodes[node].criticality
                results.append(
                    {
                        "node_ids": path,
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
                )
                return  # stop at first crown jewel on this branch
            if len(edges) >= max_depth:
                return
            for e in self.adj[node]:
                if e.target in path:  # simple paths only
                    continue
                p = prob * self._edge_prob(e)
                if p >= min_prob:
                    dfs(e.target, path + [e.target], edges + [e], p)

        for s in sources:
            if s in self.nodes:
                dfs(s, [s], [], 1.0)
        results.sort(key=lambda r: r["risk"], reverse=True)
        return results[:top_k]

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

    def simulate_fix(self, remove_nodes: list[str], max_depth: int = 6) -> dict:
        before = self.attack_paths(max_depth=max_depth, top_k=1000)
        after = self.without(remove_nodes).attack_paths(max_depth=max_depth, top_k=1000)
        rb, ra = sum(p["risk"] for p in before), sum(p["risk"] for p in after)
        return {
            "removed": remove_nodes,
            "paths_before": len(before),
            "paths_after": len(after),
            "risk_before": round(rb, 3),
            "risk_after": round(ra, 3),
            "risk_reduction_pct": round((1 - ra / rb) * 100, 1) if rb else 0.0,
        }
