import json
from pathlib import Path

from domain.network.risk_overlay import build_risk_overlay
from domain.network.schema import parse_config

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


def overlay(name="exposed_database"):
    return build_risk_overlay(parse_config(json.loads((SAMPLES / f"{name}.json").read_text())))


def test_the_open_ssh_group_and_its_instance_are_flagged_with_reasons():
    nodes = overlay()["nodes"]
    assert nodes["sg-web"]["severity"] == "high" and nodes["i-web-1"]["severity"] == "high"
    titles = {r["title"] for r in nodes["sg-web"]["reasons"]}
    assert "SSH (22) open to the internet" in titles
    via = [r for r in nodes["i-web-1"]["reasons"] if r.get("via")]
    assert via and via[0]["via"] == "sg-web"


def test_the_internet_path_is_verified_and_traced():
    result = overlay()
    path = next(p for p in result["paths"] if p["id"] == "i-web-1:22")
    assert path["verified"] and path["verdict"] == "allowed"
    assert path["steps"][0] == "internet" and "i-web-1" in path["steps"] and path["steps"][-1] == "sg-web"
    assert path["trace"] and path["explanation"]
    assert result["summary"]["verified_paths"] >= 1


def test_resources_on_the_path_are_marked_even_without_a_finding_of_their_own():
    nodes = overlay()["nodes"]
    assert nodes["igw-main"]["kind"] == "path" and nodes["igw-main"]["severity"] == "high"


def test_a_safe_network_has_no_paths():
    result = overlay("safe_network")
    assert result["paths"] == []
