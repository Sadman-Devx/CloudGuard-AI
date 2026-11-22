"""Terraform / CloudFormation / AWS describe importers: every result must pass the one validator."""

import json
from pathlib import Path

import pytest

from domain.network.importers import ImporterError
from domain.network.importers.aws_describe import import_aws_describe
from domain.network.importers.cloudformation import import_cloudformation
from domain.network.importers.terraform import import_terraform
from domain.network.schema import validate_config

DATA = Path(__file__).parent / "data"


def codes(report):
    return {w["code"] for w in report.warnings}


def assert_valid(report):
    result = validate_config(report.config)
    assert result.ok, [(e.path, e.message) for e in result.errors]


# ---- Terraform --------------------------------------------------------------------------------


@pytest.fixture
def plan():
    return json.loads((DATA / "terraform_plan.json").read_text())


def test_terraform_plan_becomes_a_valid_configuration(plan):
    report = import_terraform(plan)
    assert_valid(report)
    assert report.config["region"] == "us-east-1"
    assert report.stats["security_groups"] == 2 and report.stats["instances"] == 2


def test_terraform_references_are_resolved_through_the_configuration(plan):
    config = import_terraform(plan).config
    db = next(g for g in config["security_groups"] if g["id"] == "aws_security_group.db")
    # the db group's source is the web group, known only through a reference in a plan
    assert db["ingress"][0]["source_security_group_id"] == "aws_security_group.web"
    web = next(i for i in config["instances"] if i["id"] == "aws_instance.web")
    assert web["security_group_ids"] == ["aws_security_group.web"]


def test_terraform_open_ssh_rule_is_kept_for_the_rule_engine(plan):
    from domain.network.rules import evaluate
    from domain.network.schema import parse_config

    findings = evaluate(parse_config(import_terraform(plan).config))
    assert any(f.rule_id == "SG-001" and f.resource_id == "aws_security_group.web" for f in findings)


def test_terraform_reports_what_it_dropped_or_assumed(plan):
    report = import_terraform(plan)
    assert "UNSUPPORTED_ROUTE_TARGET" in codes(report)  # the private subnet routes via a NAT gateway
    assert {"PRIVATE_IP_ASSIGNED", "PUBLIC_IP_ASSIGNED"} <= codes(report)


def test_terraform_public_ip_follows_the_subnet_default(plan):
    config = import_terraform(plan).config
    web = next(i for i in config["instances"] if i["id"] == "aws_instance.web")
    db = next(i for i in config["instances"] if i["id"] == "aws_instance.db")
    assert web["public_ip"].startswith("203.0.113.") and "public_ip" not in db


@pytest.mark.parametrize("document", [[], {}, {"planned_values": {}}, "text"])
def test_terraform_rejects_things_that_are_not_plans(document):
    with pytest.raises(ImporterError):
        import_terraform(document)


# ---- CloudFormation ---------------------------------------------------------------------------


def test_cloudformation_yaml_with_short_form_functions():
    report = import_cloudformation((DATA / "stack.yaml").read_text())
    assert_valid(report)
    assert report.config["region"] == "eu-west-1"  # from the subnet's availability zone
    assert report.config["vpcs"][0]["cidr"] == "10.1.0.0/16"  # a parameter's Default
    assert "DEFAULT_EGRESS_ASSUMED" in codes(report)


def test_cloudformation_json_template_is_accepted():
    template = {
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.9.0.0/16"}},
            "Sub": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.9.1.0/24"},
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "GroupDescription": "g"},
            },
            "Vm": {
                "Type": "AWS::EC2::Instance",
                "Properties": {"SubnetId": {"Ref": "Sub"}, "SecurityGroupIds": [{"Ref": "Sg"}]},
            },
        }
    }
    report = import_cloudformation(json.dumps(template))
    assert_valid(report)
    assert report.stats["instances"] == 1


@pytest.mark.parametrize("content", ["", "just: text", "Resources: []", "{ not json or yaml"])
def test_cloudformation_rejects_non_templates(content):
    with pytest.raises(ImporterError):
        import_cloudformation(content)


# ---- AWS describe ----------------------------------------------------------------------------


def describe_data():
    return {
        "vpcs": [
            {"VpcId": "vpc-0a1b2c3d", "CidrBlock": "10.2.0.0/16", "Tags": [{"Key": "Name", "Value": "prod"}]}
        ],
        "internet_gateways": [
            {
                "InternetGatewayId": "igw-0aaa1111",
                "Attachments": [{"VpcId": "vpc-0a1b2c3d", "State": "available"}],
            }
        ],
        "route_tables": [
            {
                "RouteTableId": "rtb-0aaa1111",
                "VpcId": "vpc-0a1b2c3d",
                "Routes": [
                    {"DestinationCidrBlock": "10.2.0.0/16", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0aaa1111"},
                    {"DestinationCidrBlock": "192.168.0.0/16", "NatGatewayId": "nat-0123"},
                ],
                "Associations": [{"Main": True, "RouteTableId": "rtb-0aaa1111"}],
            }
        ],
        "subnets": [
            {
                "SubnetId": "subnet-0aaa1111",
                "VpcId": "vpc-0a1b2c3d",
                "CidrBlock": "10.2.1.0/24",
                "AvailabilityZone": "eu-west-1a",
            }
        ],
        "security_groups": [
            {
                "GroupId": "sg-0aaa1111",
                "GroupName": "web",
                "Description": "w",
                "VpcId": "vpc-0a1b2c3d",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        "UserIdGroupPairs": [],
                        "PrefixListIds": [],
                    }
                ],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": [],
                        "PrefixListIds": [],
                    }
                ],
            }
        ],
        "network_acls": [
            {
                "NetworkAclId": "acl-0aaa1111",
                "VpcId": "vpc-0a1b2c3d",
                "Associations": [{"SubnetId": "subnet-0aaa1111"}],
                "Entries": [
                    {
                        "RuleNumber": 100,
                        "Protocol": "-1",
                        "RuleAction": "allow",
                        "Egress": False,
                        "CidrBlock": "0.0.0.0/0",
                    },
                    {
                        "RuleNumber": 32767,
                        "Protocol": "-1",
                        "RuleAction": "deny",
                        "Egress": False,
                        "CidrBlock": "0.0.0.0/0",
                    },
                ],
            }
        ],
        "instances": [
            {
                "InstanceId": "i-0aaa1111",
                "State": {"Name": "running"},
                "SubnetId": "subnet-0aaa1111",
                "PrivateIpAddress": "10.2.1.20",
                "PublicIpAddress": "54.12.34.56",
                "SecurityGroups": [{"GroupId": "sg-0aaa1111"}],
                "Tags": [{"Key": "Name", "Value": "web-1"}],
            },
            {"InstanceId": "i-0dead", "State": {"Name": "terminated"}, "SubnetId": "subnet-0aaa1111"},
        ],
        "db_instances": [],
        "load_balancers": [],
        "listeners": {},
        "buckets": [{"name": "my-bucket", "public": True}],
    }


def test_aws_describe_is_mapped_and_valid():
    report = import_aws_describe(describe_data(), region="eu-west-1")
    assert_valid(report)
    assert report.config["instances"][0]["public_ip"] == "54.12.34.56"
    assert [i["id"] for i in report.config["instances"]] == ["i-0aaa1111"]  # terminated is ignored
    assert report.config["extensions"]["buckets"][0]["public"] is True


def test_aws_describe_keeps_ipv6_source_but_drops_nat_route_and_the_implicit_deny():
    report = import_aws_describe(describe_data(), region="eu-west-1")
    sg = report.config["security_groups"][0]
    assert {r["cidr"] for r in sg["ingress"]} == {"0.0.0.0/0", "::/0"}
    assert "UNSUPPORTED_ROUTE_TARGET" in codes(report)
    assert [e["rule_number"] for e in report.config["network_acls"][0]["ingress"]] == [100]


def test_aws_describe_without_vpcs_is_an_error():
    with pytest.raises(ImporterError):
        import_aws_describe({"vpcs": [], "subnets": []}, region="us-east-1")
