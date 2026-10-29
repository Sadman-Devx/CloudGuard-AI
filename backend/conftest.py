"""Shared pytest fixtures."""

import copy
import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "sample_data" / "aws"

_VALID_CONFIG = {
    "schema_version": "1.0",
    "name": "unit-test network",
    "region": "us-east-1",
    "vpcs": [{"id": "vpc-1", "cidr": "10.0.0.0/16", "name": "main"}],
    "internet_gateways": [{"id": "igw-1", "vpc_id": "vpc-1"}],
    "route_tables": [
        {
            "id": "rtb-1",
            "vpc_id": "vpc-1",
            "routes": [
                {"destination_cidr": "10.0.0.0/16", "target": "local"},
                {"destination_cidr": "0.0.0.0/0", "target": "igw-1"},
            ],
        }
    ],
    "subnets": [
        {"id": "subnet-1", "vpc_id": "vpc-1", "cidr": "10.0.1.0/24", "route_table_id": "rtb-1"},
    ],
    "security_groups": [
        {
            "id": "sg-1",
            "vpc_id": "vpc-1",
            "name": "web",
            "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
            "egress": [{"protocol": "-1", "cidr": "0.0.0.0/0"}],
        },
        {
            "id": "sg-2",
            "vpc_id": "vpc-1",
            "name": "app",
            "ingress": [
                {"protocol": "tcp", "from_port": 8000, "to_port": 8000, "source_security_group_id": "sg-1"}
            ],
            "egress": [],
        },
    ],
    "network_acls": [
        {
            "id": "acl-1",
            "vpc_id": "vpc-1",
            "subnet_ids": ["subnet-1"],
            "ingress": [
                {
                    "rule_number": 100,
                    "action": "allow",
                    "protocol": "tcp",
                    "cidr": "0.0.0.0/0",
                    "from_port": 443,
                    "to_port": 443,
                }
            ],
            "egress": [{"rule_number": 100, "action": "allow", "protocol": "-1", "cidr": "0.0.0.0/0"}],
        }
    ],
    "instances": [
        {
            "id": "i-1",
            "name": "web-1",
            "subnet_id": "subnet-1",
            "private_ip": "10.0.1.10",
            "public_ip": "203.0.113.5",
            "security_group_ids": ["sg-1", "sg-2"],
            "tags": {"tier": "web"},
        }
    ],
}


@pytest.fixture
def valid_config() -> dict:
    """A fresh, minimal, valid configuration that tests can mutate freely."""
    return copy.deepcopy(_VALID_CONFIG)


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(params=sorted(p.stem for p in FIXTURES_DIR.glob("*.json")))
def sample_fixture(request) -> tuple[str, dict]:
    """Each bundled sample fixture as (name, parsed JSON)."""
    path = FIXTURES_DIR / f"{request.param}.json"
    return request.param, json.loads(path.read_text(encoding="utf-8"))
