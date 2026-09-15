# deploy/aws/

**A three-node mock-sts cluster in AWS, built and destroyed by Terraform, and a
workflow that tests it (issue #51).** Nothing here runs inside the service; the
Dockerfile removes this directory from the image.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the S3 state bucket `mock-sts-terraform-state-<account>` — not Terraform, because it holds Terraform's state | an administrator |
| `foundation/` | long-lived | the deployer IAM user, the role it assumes, the permissions boundary, the KMS key, the ECR repository, the container log group | an administrator |
| `environment/` | per run | VPC, NLB, RDS primary + replica, secrets, ECS cluster, task and execution roles, three services | the deployer role |
| `schema-init/` | per image | a `postgres:18` image that applies `postgres/schema.sql` as the RDS master user | built by CI |
| `run-suite.sh` | per run | waits for the NLB, mints an `/admin-api` token, runs the protocol suite | CI, or a person |
| `../../.github/workflows/aws-cluster.yml` | per run | build, apply, suite, report, destroy — one job | GitHub Actions (dispatch only) |

## The decisions, and what each costs

**ECS on Fargate, not VMs and not EKS.** Priced on 2026-09-15 for three nodes
for an hour: Fargate (1 vCPU, 3 GB) $0.16, three t3.medium $0.13, EKS $0.23+.
EC2's three cents buys an AMI, Docker and a log agent to maintain and one set
of credentials shared by every container on a host; Fargate gives each task
exactly the task role and ships logs with `awslogs`. The whole environment is
about $0.41 an hour, most of it the three nodes, the two RDS instances and log
ingestion. The ticket carries the itemised estimate.

**One ECS service per availability zone.** A service with three tasks spreads
them as it can; a service per AZ with one subnet and a desired count of one
makes one-node-per-AZ true by construction, and lets `node-a` reach steady
state before `node-b` and `node-c` are created — the deterministic first start
`cluster/CLAUDE.md` records.

**No NAT gateway.** Nodes sit in public subnets with a public IP and a security
group that accepts only the NLB's group on 8081. A NAT gateway would cost more
than the nodes' public addresses.

**TLS passes through the NLB.** TCP 443 → 8081 with PROXY protocol v2, client
IP preservation off, cross-zone on. Each node presents its own leaf chaining to
the cluster's one Root; `STS_TLS_HOSTNAMES` starts with the NLB's DNS name and
`STS_PUBLIC_BASE_URL` is `https://<nlb>`. Cross-zone matters to the suite:
without it `sts_cluster_alternation` sees only the node in the AZ its NLB
address is in.

**Development mode by default.** The suite drives development mode (most jobs
sign people in with no password, which product mode refuses by design). Keys
still persist, so the key-encryption key and the database password are read
from Secrets Manager through `common/secrets.js` — the path this issue exists to
exercise. `sts_mode = "product"` is a variable.

**The schema is an init container**, not a one-off task or a Terraform
provisioner: RDS is private, psql variables and `\gexec` need psql, and an init
container in every task (non-essential, `dependsOn: SUCCESS`) re-applies the
idempotent file on every start with nothing to orchestrate. It is the only
holder of the master password.

**Four secrets, each a plain string**, so `secrets.js` takes each whole and the
database password never borrows the key's location (the arrangement that file
refuses). Recovery window zero, so the next environment of the same name can
reuse the names.

**Backups are deleted with the environment by default**
(`delete_automated_backups = true`): retention is 14 days while it runs, and a
backup kept after a one-hour test environment is storage billed for an
environment that no longer exists.

**Logs outlive the environment**: the log group is in `foundation/`, streams
are `<environment>-<node>/<container>/<task-id>`, retention 14 days.

## The deployer's permissions, and how to extend them

`foundation/iam_deployer.tf`'s header is the argument: names where ARNs are
predictable, the `Project = STS` tag where they are not (EC2), a permissions
boundary on every role the deployer creates, one region. **A missing action
shows up as an AccessDenied naming it on plan or apply**; add it to the right
statement, keeping its scope, and have an administrator re-apply `foundation/`
— the deployer cannot widen its own policy, by design.

Found on the first apply and added: `ecr:ListTagsForResource` and
`logs:ListTagsForResource` (the provider reads tags on the two data sources),
and the boundary lookup changed from by-name (which needs `iam:ListPolicies`
over the whole account) to by-ARN.

## Running it by hand

```bash
deploy/aws/bootstrap-state.sh                         # once, administrator
terraform -chdir=deploy/aws/foundation init -backend-config=bucket=mock-sts-terraform-state-<account>
terraform -chdir=deploy/aws/foundation apply          # once, administrator

# as the deployer role, from here on
docker build -t <repo>:<tag> --build-arg STS_CLOUD_SDKS=@aws-sdk/client-secrets-manager \
  --build-arg STS_DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem .
docker build -t <repo>:schema-<tag> -f deploy/aws/schema-init/Dockerfile .
terraform -chdir=deploy/aws/environment init -backend-config=bucket=… -backend-config=key=environment/dev.tfstate
terraform -chdir=deploy/aws/environment apply -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
deploy/aws/run-suite.sh dev
terraform -chdir=deploy/aws/environment destroy -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
```
