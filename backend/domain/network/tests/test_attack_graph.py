"""Attack graph engine: demo graph parity, bounded search, snapshot-built graphs, change simulation."""

import copy
import json
from pathlib import Path

import pytest

from apps.attack_paths.demo_graph import SAMPLE_GRAPH
from domain.network.attack_graph import (
    AttackGraph,
    Edge,
    Node,
    build_attack_graph,
    simulate_change,
)
from domain.network.extensions import extensions_from_json
from domain.network.proposals import validate_change
from domain.network.schema import parse_config

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


def _load(name):
    raw = json.loads((SAMPLES / f"{name}.json").read_text())
    config = parse_config(raw)
    return raw, config, extensions_from_json(raw, config)


@pytest.fixture
def demo():
    return AttackGraph.from_dict(SAMPLE_GRAPH)


# ---- demo graph (ported from the old apps/test_graph.py) --------------------------------------


def test_paths_reach_crown_jewels(demo):
    paths = demo.attack_paths()
    assert paths
    assert all(p["nodes"][-1]["crown_jewel"] for p in paths)
    assert paths == sorted(paths, key=lambda p: p["risk"], reverse=True)


def test_blast_radius_from_web1(demo):
    r = demo.blast_radius("web1")
    ids = {x["id"] for x in r["reachable"]}
    assert {"app1", "rds", "role_web", "s3_backup"} <= ids
    assert r["severity"] in {"critical", "high"}
    assert "internet" not in ids


def test_blast_radius_depth_limit(demo):
    r = demo.blast_radius("internet", max_depth=1)
    assert {x["id"] for x in r["reachable"]} == {"alb", "jenkins"}


def test_unknown_node(demo):
    with pytest.raises(KeyError):
        demo.blast_radius("nope")


def test_simulation_reduces_risk(demo):
    res = demo.simulate_fix(["role_admin"])
    assert res["risk_after"] < res["risk_before"]
    assert res["risk_reduction_pct"] > 0


# ---- search is exact and bounded ---------------------------------------------------------------


def _layered(width, layers):
    """internet -> `layers` fully connected layers of `width` nodes -> one crown jewel."""
    g = AttackGraph()
    g.add_node(Node("internet", "Internet", "internet", internet_exposed=True))
    previous = ["internet"]
    for layer in range(layers):
        current = [f"n{layer}_{i}" for i in range(width)]
        for node in current:
            g.add_node(Node(node, node, "ec2", criticality=3))
        for a in previous:
            for b in current:
                g.add_edge(Edge(a, b, "network", 0.9))
        previous = current
    g.add_node(Node("jewel", "jewel", "rds", criticality=10, crown_jewel=True))
    for a in previous:
        g.add_edge(Edge(a, "jewel", "data_access", 0.9))
    return g


def test_top_k_matches_exhaustive_ranking_on_small_graph(demo):
    top = demo.attack_paths(top_k=3, max_depth=6)
    everything = demo.attack_paths(top_k=1000, max_depth=6)
    assert [p["risk"] for p in top] == [p["risk"] for p in everything[:3]]


def test_dense_graph_is_bounded():
    g = _layered(width=8, layers=5)  # 8**5 simple paths if enumerated blindly
    paths = g.attack_paths(top_k=5, max_depth=7, max_expansions=5_000)
    assert len(paths) == 5
    assert g.last_search["expanded"] <= 5_001


def test_truncation_is_reported():
    g = _layered(width=6, layers=4)
    g.attack_paths(top_k=1000, max_depth=7, max_expansions=50)
    assert g.last_search["truncated"] is True


def test_remove_edge_instead_of_node(demo):
    res = demo.simulate_fix([], remove_edges=[("internet", "jenkins")])
    assert res["risk_after"] < res["risk_before"]
    assert res["removed_edges"] == [["internet", "jenkins"]]


# ---- graph built from a snapshot ---------------------------------------------------------------


def test_graph_from_snapshot_has_real_nodes_and_paths():
    _, config, ext = _load("attack_path_demo")
    graph, info = build_attack_graph(config, ext)
    ids = set(graph.nodes)
    assert {"internet", "i-web-1", "i-app-1", "db-customers", "bkt-backups", "role-admin"} <= ids
    paths = graph.attack_paths(top_k=20)
    assert paths
    assert {p["node_ids"][-1] for p in paths} <= {"db-customers", "bkt-backups"}
    assert any(w["code"] == "UNMODELLED_NETWORK" for w in info.warnings)


def test_graph_without_extensions_uses_only_instances():
    _, config, ext = _load("exposed_database")
    graph, _ = build_attack_graph(config, ext)
    assert {n.type for n in graph.nodes.values()} <= {"internet", "ec2"}
    assert not graph.attack_paths()  # no crown jewel is modelled without extensions


def test_change_simulation_never_touches_the_original_config():
    raw, config, ext = _load("attack_path_demo")
    before = copy.deepcopy(raw)
    change = validate_change(
        {
            "action": "replace_ingress_source",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5432,
            "new_source_security_group_id": "sg-app",
        },
        config,
        "sg-db",
    )
    result = simulate_change(config, ext, change)
    assert result["applied_to_cloud"] is False
    assert result["risk_after"] <= result["risk_before"]
    assert raw == before
    assert config == parse_config(before)
