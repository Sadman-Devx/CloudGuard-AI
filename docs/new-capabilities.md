# New capabilities

All of this is read-only toward your cloud: CloudGuard describes, analyses and simulates. It never
creates, changes or deletes anything, and the "fix as code" output is text for a person to review.

## 1. Live AWS import (read-only)
`POST /api/projects/<id>/snapshots/from-aws/` `{ "region": "us-east-1", "role_arn"?, "external_id"?, "vpc_ids"?, "include_s3"? }`

* Uses boto3 `Describe*`/`List*`/`Get*` calls only (EC2 network, RDS instances, ALBs, optionally S3
  public-access settings). Deploy `infra/aws-readonly-role.yaml` in the account to analyse; its policy
  grants nothing else.
* **Credentials are never sent through the API.** The backend uses its own identity (environment,
  profile, instance/task role) and can assume `role_arn` (with `external_id`) for 15 minutes.
* **Off by default** (`AWS_IMPORT_ENABLED=false`) because the API has no sign-in yet: when it is on,
  anyone who can reach the backend can import what the server's identity can see. Turn it on only on a
  private deployment, and set `AWS_IMPORT_ALLOWED_ROLE_ARNS` / `AWS_IMPORT_ALLOWED_REGIONS`.
* `GET /api/aws-import/status/` tells the UI whether it is enabled.
* Not modelled yet (dropped and listed in the snapshot's warnings): routes via NAT/peering/transit
  gateways, prefix lists, IPv6 networks of VPCs/subnets/routes, IAM roles.

## 2. Terraform and CloudFormation import
`POST /api/projects/<id>/snapshots/from-iac/` `{ "format": "terraform" | "cloudformation", "content": "<file text>" }`

* Terraform: the output of `terraform show -json` for a plan or a state. Values only known at apply time
  (ids, IPs) are resolved through the plan's own references; resources keep their Terraform address as id
  (for example `aws_security_group.web`).
* CloudFormation: a template in JSON or YAML (short-form `!Ref`, `!GetAtt`, `!Sub` ... are understood).
  Parameter defaults are used; other computed values are reported as unknown.
* The file is parsed, never executed. Whatever cannot be represented is listed in `import_report.warnings`.
  Addresses that do not exist before apply (private/public IPs) are assigned for analysis and said so.

## 3. Fix as code
`GET /api/simulations/<id>/export/?format=aws-cli|terraform|pr`

* `aws-cli`: add the new access first, then remove the old, verify, and a commented rollback.
* `terraform`: a diff-style patch for the security-group / network-ACL resources (illustrative: apply it in
  the file that defines the resource).
* `pr`: a pull-request description with why, the change, digital-twin evidence, both of the above and a
  checklist.
* Every id/CIDR/port that reaches the output is validated against a strict pattern; an unsafe value is
  refused, not escaped. IDs that are not real AWS ids (samples, IaC imports) produce a warning.

## 4. Interactive topology with a risk overlay
Topology tab -> **Show risk overlay**. Backed by `GET /api/snapshots/<id>/topology/risk/`.

* Red nodes are resources with findings or on an internet path; the number is how many reasons they have.
* The panel lists the internet paths (internet -> gateway -> route table -> subnet -> instance -> security
  group). Click one to highlight it on the graph and read the reachability engine's step-by-step trace;
  click a node to see why it is flagged.

## 5. Before / after view
In a simulation result: the rule that changes (old on the left, new on the right), findings and score
before/after, and every path whose verdict flips. Network-ACL and egress changes are shown the same way.

## 6. Risk dashboard
Dashboard tab. `GET /api/dashboard/` (all projects), `GET /api/projects/<id>/dashboard/` (one),
`POST /api/projects/<id>/dashboard/refresh/` (analyse snapshots that have no analysis yet).

* Score = latest analysed snapshot; trend = every analysed snapshot, oldest first.
* Shows the severity mix, the rules causing most findings, the most serious findings and how many
  simulated fixes were recommended.
