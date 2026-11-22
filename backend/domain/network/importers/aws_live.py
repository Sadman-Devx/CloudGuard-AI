"""Live-AWS importer, network part: the read-only API calls.

Only ``Describe*`` / ``List*`` / ``Get*`` calls that read configuration are made; there is no call
that creates, changes or deletes anything, and the IAM policy in ``infra/aws-readonly-role.yaml``
grants nothing else, so a bug here still could not write.

Credentials are never accepted from the API. Two ways to authenticate, both on the *server*:

* the default boto3 chain (environment, shared config, instance/task role);
* ``role_arn`` (+ ``external_id``): the server's identity assumes that role for 15 minutes.
"""

from __future__ import annotations

import re
from typing import Any

ROLE_ARN = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,128}$")
EXTERNAL_ID = re.compile(r"^[\w+=,.@:/-]{2,1224}$")
VPC_ID = re.compile(r"^vpc-[0-9a-f]{8,17}$")
MAX_BUCKETS = 100
MAX_LOAD_BALANCERS = 50


class AwsImportError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def fetch_aws_data(
    region: str,
    *,
    role_arn: str | None = None,
    external_id: str | None = None,
    vpc_ids: list[str] | None = None,
    include_s3: bool = False,
    session_factory=None,
) -> dict[str, Any]:
    """Read the network configuration of one region. ``session_factory`` is for tests."""
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError as exc:  # pragma: no cover - boto3 is a declared dependency
        raise AwsImportError("boto3_missing", "boto3 is not installed on the server.", 503) from exc

    config = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=20)
    make_session = session_factory or boto3.Session
    try:
        session = make_session(region_name=region)
        if role_arn:
            params: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": "cloudguard-readonly",
                "DurationSeconds": 900,
            }
            if external_id:
                params["ExternalId"] = external_id
            creds = session.client("sts", config=config).assume_role(**params)["Credentials"]
            session = make_session(
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        ec2 = session.client("ec2", config=config)
        vpc_filter = [{"Name": "vpc-id", "Values": vpc_ids}] if vpc_ids else []

        def pages(client, operation: str, key: str, **kwargs) -> list[dict]:
            out: list[dict] = []
            for page in client.get_paginator(operation).paginate(**kwargs):
                out.extend(page.get(key, []))
            return out

        data: dict[str, Any] = {
            "vpcs": pages(
                ec2,
                "describe_vpcs",
                "Vpcs",
                Filters=[{"Name": "vpc-id", "Values": vpc_ids}] if vpc_ids else [],
            ),
            "subnets": pages(ec2, "describe_subnets", "Subnets", Filters=vpc_filter),
            "internet_gateways": pages(
                ec2,
                "describe_internet_gateways",
                "InternetGateways",
                Filters=[{"Name": "attachment.vpc-id", "Values": vpc_ids}] if vpc_ids else [],
            ),
            "route_tables": pages(ec2, "describe_route_tables", "RouteTables", Filters=vpc_filter),
            "security_groups": pages(ec2, "describe_security_groups", "SecurityGroups", Filters=vpc_filter),
            "network_acls": pages(ec2, "describe_network_acls", "NetworkAcls", Filters=vpc_filter),
            "instances": [
                instance
                for reservation in pages(ec2, "describe_instances", "Reservations", Filters=vpc_filter)
                for instance in reservation.get("Instances", [])
            ],
        }
        data.update(_optional(session, config, region, set(v["VpcId"] for v in data["vpcs"]), include_s3))
        return data
    except NoCredentialsError as exc:
        raise AwsImportError(
            "no_credentials",
            "The server has no AWS credentials. Configure a role or credentials for the CloudGuard backend.",
            503,
        ) from exc
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure"):
            raise AwsImportError(
                "access_denied",
                f"AWS denied the request ({code}). The role needs the read-only policy in "
                "infra/aws-readonly-role.yaml.",
                403,
            ) from exc
        raise AwsImportError("aws_error", f"AWS returned an error: {code or 'unknown'}.", 502) from exc
    except BotoCoreError as exc:
        raise AwsImportError(
            "aws_unreachable", f"Could not reach AWS: {exc.__class__.__name__}.", 502
        ) from exc


def _optional(session, config, region: str, vpcs: set[str], include_s3: bool) -> dict[str, Any]:
    """RDS, ALBs and (opt-in) S3. A missing permission here only skips that part."""
    from botocore.exceptions import ClientError

    out: dict[str, Any] = {}
    try:
        rds = session.client("rds", config=config)
        databases: list[dict] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            databases.extend(
                d for d in page.get("DBInstances", []) if (d.get("DBSubnetGroup") or {}).get("VpcId") in vpcs
            )
        out["db_instances"] = databases
    except ClientError:
        out["db_instances"] = []
    try:
        elb = session.client("elbv2", config=config)
        balancers: list[dict] = []
        for page in elb.get_paginator("describe_load_balancers").paginate():
            balancers.extend(b for b in page.get("LoadBalancers", []) if b.get("VpcId") in vpcs)
        balancers = balancers[:MAX_LOAD_BALANCERS]
        listeners: dict[str, list[int]] = {}
        for lb in balancers:
            arn = lb["LoadBalancerArn"]
            listeners[arn] = [
                listener["Port"]
                for page in elb.get_paginator("describe_listeners").paginate(LoadBalancerArn=arn)
                for listener in page.get("Listeners", [])
            ]
        out["load_balancers"], out["listeners"] = balancers, listeners
    except ClientError:
        out["load_balancers"], out["listeners"] = [], {}
    out["buckets"] = _buckets(session, config) if include_s3 else []
    return out


def _buckets(session, config) -> list[dict]:
    from botocore.exceptions import ClientError

    s3 = session.client("s3", config=config)
    result: list[dict] = []
    try:
        names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])][:MAX_BUCKETS]
    except ClientError:
        return result
    for name in names:
        public = False
        try:
            block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(
                block.get(k)
                for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            )
        except ClientError:
            fully_blocked = False  # no block configured
        if not fully_blocked:
            try:
                grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
                public = any(
                    (g.get("Grantee") or {}).get("URI", "").endswith("/global/AllUsers") for g in grants
                )
            except ClientError:
                public = False
        result.append({"name": name, "public": public})
    return result
