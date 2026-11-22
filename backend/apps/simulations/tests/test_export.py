from types import SimpleNamespace

import pytest

from apps.simulations.services.export import ExportError, build_export

RULE_ANY = {
    "protocol": "-1",
    "from_port": None,
    "to_port": None,
    "cidr": "0.0.0.0/0",
    "peer_security_group_id": None,
}
RULE_DB = {
    "protocol": "tcp",
    "from_port": 5432,
    "to_port": 5432,
    "cidr": None,
    "peer_security_group_id": "sg-db",
}


def simulation(mods, *, sg="sg-app", recommended=True, source="fixture"):
    summary = {"total": 4, "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 3, "info": 0}}
    after = {"total": 3, "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}}
    result = {
        "modifications": mods,
        "summary_lines": ["Resolves SG-006 on sg-app."],
        "findings": {
            "resolved": [{"rule_id": "SG-006", "resource_id": sg, "title": "Unrestricted outbound traffic"}],
            "before_summary": summary,
            "after_summary": after,
        },
        "connectivity": [
            {"key": "k1", "label": "i-app-1 -> i-db-1 tcp/5432", "change": "preserved", "required": True},
            {"key": "k2", "label": "i-app-1 -> i-web-1 tcp/22", "change": "still_blocked", "required": False},
        ],
        "warnings": [],
    }
    return SimpleNamespace(
        pk=7,
        outcome="improves_security",
        recommended=recommended,
        proposed_change_json={"action": "restrict_egress_rule", "security_group_id": sg, "protocol": "-1"},
        result_json=result,
        snapshot=SimpleNamespace(
            region="us-east-1",
            source_type=source,
            raw_json={"security_groups": [{"id": sg, "name": "app"}]},
        ),
    )


MODS = [
    {
        "security_group": "sg-app",
        "direction": "egress",
        "index": 0,
        "before": RULE_ANY,
        "after": RULE_DB,
        "note": None,
    }
]


def test_aws_cli_adds_before_it_removes_and_ends_with_a_rollback():
    out = build_export(simulation(MODS), "aws-cli")
    text = out["content"]
    assert text.index("authorize-security-group-egress") < text.index("revoke-security-group-egress")
    assert (
        "--ip-permissions 'IpProtocol=tcp,FromPort=5432,ToPort=5432,UserIdGroupPairs=[{GroupId=sg-db}]'"
        in text
    )
    assert "# Rollback" in text and out["filename"] == "fix-simulation-7.sh"
    # sample ids are not real AWS ids, and the user is told so
    assert any("not real AWS ids" in w for w in out["warnings"])


def test_terraform_patch_shows_the_old_and_new_rule():
    text = build_export(simulation(MODS), "terraform")["content"]
    assert "-  egress {" in text and "+  egress {" in text
    assert '+  security_groups = ["sg-db"]' in text
    assert 'cidr_blocks = ["0.0.0.0/0"]' in text


def test_pr_text_has_the_evidence_and_leaves_out_unchanged_noise():
    text = build_export(simulation(MODS), "pr")["content"]
    assert text.startswith("# fix(security):")
    assert "Resolves **SG-006**" in text and "Security score:" in text
    assert "i-app-1 -> i-db-1 tcp/5432: preserved (required)" in text
    assert "tcp/22" not in text.split("## Terraform")[0].split("## Verification")[1]


def test_nacl_entries_become_create_and_delete_commands():
    mods = [
        {
            "security_group": "sg-db",
            "network_acl": "acl-0abc1234",
            "direction": "ingress",
            "index": 90,
            "before": {
                "rule_number": 90,
                "action": "deny",
                "protocol": "tcp",
                "cidr": "10.0.0.0/8",
                "from_port": 5432,
                "to_port": 5432,
            },
            "after": None,
            "note": None,
        }
    ]
    text = build_export(simulation(mods, sg="sg-db"), "aws-cli")["content"]
    assert "delete-network-acl-entry --network-acl-id acl-0abc1234 --ingress --rule-number 90" in text
    assert "# aws ec2 create-network-acl-entry" in text  # the rollback


def test_unsafe_values_are_refused_not_escaped():
    bad = [{**MODS[0], "security_group": "sg-1; rm -rf /"}]
    with pytest.raises(ExportError):
        build_export(simulation(bad), "aws-cli")


def test_a_simulation_that_changes_nothing_cannot_be_exported():
    with pytest.raises(ExportError):
        build_export(simulation([]), "pr")


def test_unrecommended_and_iac_snapshots_get_loud_warnings():
    out = build_export(simulation(MODS, recommended=False, source="terraform"), "pr")
    joined = " ".join(out["warnings"])
    assert "did NOT recommend" in joined and "infrastructure-as-code" in joined
