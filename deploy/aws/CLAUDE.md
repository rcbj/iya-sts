# deploy/aws/

**A three-node mock-sts cluster in AWS, built and destroyed by Terraform, and a
workflow that tests it (issue #51).** Nothing here runs inside the service; the
Dockerfile removes this directory from the image.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the S3 state bucket `mock-sts-terraform-state-<account>` — not Terraform, because it holds Terraform's state | an administrator |
| `foundation/` | long-lived | the deployer IAM user, the role it assumes, the permissions boundary, the KMS key, the ECR repository, the container log group, the test report bucket `mock-sts-test-reports-<account>` | an administrator |
| `environment/` | per run | VPC, NLB (443, 9443, 389, 8082), RDS primary + replica, secrets, ECS cluster, task and execution roles, three services, and the suite runner's subnet, NAT gateway and task definition (`runner.tf`) | the deployer role |
| `schema-init/` | per image | a `postgres:18` image that applies `postgres/schema.sql` as the RDS master user | built by CI |
| `runner/` | per image | the suite runner image (the tests image plus the S3 client) and the two scripts its task runs | built by CI |
| `run-suite-in-aws.sh` | per run | starts the suite task in the VPC, waits, downloads the report — **every job** | CI, or a person |
| `reset-environment.js` | per run | removes every realm but the default one and clears the default realm's runtime overrides before a run, so an environment can be reused | both runners |
| `run-suite.sh` | per run | runs the suite from the machine it is started on, less the two jobs the nodes must call back to | a person |
| `../../.github/workflows/aws-cluster.yml` | per run | build, apply, suite, report, destroy — one job | GitHub Actions (dispatch only) |

## The decisions, and what each costs

**ECS on Fargate, not VMs and not EKS.** Priced on 2026-09-15 for three nodes
for an hour: Fargate (1 vCPU, 3 GB) $0.16, three t3.medium $0.13, EKS $0.23+.
EC2's three cents buys an AMI, Docker and a log agent to maintain and one set
of credentials shared by every container on a host; Fargate gives each task
exactly the task role and ships logs with `awslogs`. The whole environment is
about $0.35 an hour idle, most of it the three nodes, the two RDS instances and
the runner's NAT gateway, and about $0.53 for an hour with a suite running (the
suite task is 2 vCPU and 8 GB, $0.12 an hour while it runs). The ticket carries
the itemised estimate.

**One ECS service per availability zone.** A service with three tasks spreads
them as it can; a service per AZ with one subnet and a desired count of one
makes one-node-per-AZ true by construction, and lets `node-a` reach steady
state before `node-b` and `node-c` are created — the deterministic first start
`cluster/CLAUDE.md` records.

**No NAT gateway for the nodes; one for the suite runner.** Nodes sit in public
subnets with a public IP and a security group that accepts only the NLB's group
on the published ports. The suite task sits in a subnet of its own behind one
NAT gateway, because its Elastic IP is a FIXED address the NLB's security group
can admit before the task exists — a Fargate public IP is new every run.
`suite_runner = false` removes all of it (about $0.05 an hour).

**The suite runs inside the VPC** (`runner.tf`, `run-suite-in-aws.sh`). Two jobs
need the service to call the runner: `sts_gnap_core`'s push finish method and
`sts_xacml_remote_pep`'s nudge to a PEP that shares a certificate directory with
the job. Neither a developer machine nor a GitHub-hosted runner can be dialled.
The task is three containers sharing localhost and a volume — the credential
minter, the PEP, the suite — the shape `./docker-run-tests.sh` gives the same
jobs. The nodes reach the task directly; the task reaches the NLB through the
NAT gateway like any client, so every address it follows is the public one. The
report goes to the foundation's bucket, because the environment is destroyed at
the end of the run that wrote it.

**An environment is reusable, so each run starts by removing the previous
run's realms** (`reset-environment.js`, from both runners). Creating an environment
takes most of half an hour; the suite leaves every realm it creates standing,
which is the record a person reads after a red run and state the next run did
not make. The record is kept until the next run starts. The default realm's
runtime overrides are reset too (`tests/vendored/admin_api.js` requires none,
and the store keeps them), which is safe for `ldap.maxEntries` only because the
nodes start with `LDAP_MAX_ENTRIES = ldap_max_entries` (200,000). The default
realm's CONTENTS are not cleared — a job writing there names what it writes for
the run — so the directory grows by about 15,000 entries a run (the bulk loads),
held in every node's memory; destroy and re-create the environment, or raise
`ldap_max_entries` and `task_memory`, when that matters. The same growth fills
the default realm's application registry — a few hundred clients a run, against
a service default of 500 — so the nodes start with `STS_APPLICATIONS_MAX =
applications_max` (10,000). The second reuse of the dev cluster found it full:
every registration was refused `STS-REG-0020`, which `sts_userinfo_protected`
reported as an unencrypted UserInfo response.
`STS_SUITE_KEEP_REALMS=1` skips the reset.

**Four published ports.** 443 → 8081, and 9443 (the mutual-TLS listener), 389
(the directory) and 8082 (the plain-HTTP CRL/OCSP listener) on the same numbers
inside and out, because the service writes those numbers into what it
publishes: `PKI_DISTRIBUTION_BASE_URL` and `PKI_DISTRIBUTION_LDAP_HOST` name the
NLB, so a certificate's CRL address is followable. Every node listener reads the
PROXY v2 header (`common/proxy_protocol.js`). ECS allows five target groups per
service; this uses four.

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
over the whole account) to by-ARN. Added with the suite runner: the Elastic IP
and NAT gateway actions (tagged), `ecs:RunTask` on a project task definition in
a project cluster, reading the report bucket, and — in the BOUNDARY — writing
to it, which is the one thing the runner's role does.

## Running it by hand

```bash
deploy/aws/bootstrap-state.sh                         # once, administrator
terraform -chdir=deploy/aws/foundation init -backend-config=bucket=mock-sts-terraform-state-<account>
terraform -chdir=deploy/aws/foundation apply          # once, administrator

# as the deployer role, from here on
docker build -t <repo>:<tag> --build-arg STS_CLOUD_SDKS=@aws-sdk/client-secrets-manager \
  --build-arg STS_DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem .
docker build -t <repo>:schema-<tag> -f deploy/aws/schema-init/Dockerfile .
docker build -t mock-sts-tests -f tests/Dockerfile .
docker build -t <repo>:runner-<tag> --build-arg TESTS_IMAGE=mock-sts-tests \
  -f deploy/aws/runner/Dockerfile deploy/aws/runner
docker build -t <repo>:pep-<tag> -f xacml-pep/Dockerfile .
# push all four
terraform -chdir=deploy/aws/environment init -backend-config=bucket=… -backend-config=key=environment/dev.tfstate
terraform -chdir=deploy/aws/environment apply -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
deploy/aws/run-suite-in-aws.sh dev      # every job, inside the VPC
deploy/aws/run-suite.sh dev             # or from here, less gnap_core and remote_pep
terraform -chdir=deploy/aws/environment destroy -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
```
