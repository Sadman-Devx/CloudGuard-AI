import pytest

from apps.attack_paths.demo_graph import SAMPLE_GRAPH
from graph import AttackGraph


@pytest.fixture
def g():
    return AttackGraph.from_dict(SAMPLE_GRAPH)


def test_paths_reach_crown_jewels(g):
    paths = g.attack_paths()
    assert paths
    assert all(p["nodes"][-1]["crown_jewel"] for p in paths)
    assert paths == sorted(paths, key=lambda p: p["risk"], reverse=True)


def test_blast_radius_from_web1(g):
    r = g.blast_radius("web1")
    ids = {x["id"] for x in r["reachable"]}
    assert {"app1", "rds", "role_web", "s3_backup"} <= ids
    assert r["severity"] in {"critical", "high"}
    assert "internet" not in ids


def test_blast_radius_depth_limit(g):
    r = g.blast_radius("internet", max_depth=1)
    assert {x["id"] for x in r["reachable"]} == {"alb", "jenkins"}


def test_unknown_node(g):
    with pytest.raises(KeyError):
        g.blast_radius("nope")


def test_simulation_reduces_risk(g):
    res = g.simulate_fix(["role_admin"])
    assert res["risk_after"] < res["risk_before"]
    assert res["risk_reduction_pct"] > 0


def test_choke_points(g):
    chokes = g.choke_points(g.attack_paths(top_k=100))
    assert chokes and chokes[0]["risk_share"] > 0
