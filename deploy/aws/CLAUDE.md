# deploy/aws/

**A three-node iya-sts cluster in AWS, built and destroyed by Terraform, and a
workflow that tests it (issue #51).** Nothing here runs inside the service; the
Dockerfile removes this directory from the image.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the S3 state bucket `mock-sts-terraform-state-<account>` — not Terraform, because it holds Terraform's state | an administrator |
| `foundation/` | long-lived | the deployer IAM user, the role it assumes, the permissions boundary, the KMS key, the ECR repository, the container log group, the test report bucket `mock-sts-test-reports-<account>` | an administrator |
| `environment/` | per run | VPC, NLB (443, 389, 636, and the plain-HTTP CRL/OCSP port — 8082, or 80 in `testidp` — plus TCP 88 for the KDC in `testidp`), and with `public_hostname` a public ACM certificate and a CNAME (`dns.tf`), RDS primary + replica, secrets, ECS cluster, task and execution roles, three services, and the suite runner's subnet, NAT gateway and task definition (`runner.tf`) | the deployer role |
| `environment/envs/<env>.tfvars` | per environment | what a named environment sets differently; `entrypoint.sh` passes it when it exists. `dev` and `ci` have none | the deployer role |
| `schema-init/` | per image | a `postgres:18` image that applies `postgres/schema.sql` as the RDS master user | built by CI |
| `cert-init/` | per image | an `aws-cli` image that exports the public ACM certificate into the task before the node starts, so the NODE presents it (only where `public_hostname` is set) | built by CI |
| `runner/` | per image | the suite runner image (the tests image plus the S3 client) and the two scripts its task runs | built by CI |
| `Dockerfile`, `entrypoint.sh` | per run | the Terraform image (AWS CLI v2, Terraform 1.16.2, node): one stack, one environment, one action — `init`, `validate`, `plan`, `apply`, `destroy`, `output`, `suite`, `ecr-password` — the parent project's `infra/` arrangement | the workflow, and `terraform-local.sh` |
| `terraform-local.sh` | per run | runs that image on a developer machine, with the credentials in the environment or the AWS CLI's session | a person |
| `run-suite-in-aws.sh` | per run | starts the suite task in the VPC, waits, downloads the report — **every job** | CI, or a person |
| `reset-environment.js` | per run | removes every realm but the default one and clears the default realm's runtime overrides before a run, so an environment can be reused | both runners |
| `run-suite.sh` | per run | runs the suite from the machine it is started on, less the two jobs the nodes must call back to | a person |
| `../../.github/workflows/aws-cluster.yml` | per run | ordered jobs — images, terraform, suite, teardown — in the Terraform image; actions `apply-and-test`, `apply`, `test`, `plan`, `destroy` | GitHub Actions (dispatch only) |
| `../../.github/workflows/testidp-deploy.yml`, `testidp-destroy.yml` | per deployment | build `testidp`'s two images and apply it, admitting only the address(es) given as `allowed_ip`; destroy it (typed confirmation) | GitHub Actions (dispatch only) |

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

**Four published ports.** 443 → 8081; 389 (the directory in the clear) and
**636 (the same directory behind TLS, since 2026-09-17)** on the same numbers
inside and out; and the plain-HTTP CRL/OCSP listener, **8082 inside and
`var.pki_listener_port` outside** — 8082 in `dev` and `ci`, 80 in `testidp`.
The service writes the OUTSIDE number into what it publishes:
`PKI_DISTRIBUTION_BASE_URL` is built from `published_ports.pki.listener` and
`PKI_DISTRIBUTION_LDAP_HOST` names the NLB, so a certificate's CRL address is
followable from outside. Every node listener reads the PROXY v2 header
(`common/proxy_protocol.ts`) — **LDAPS installs it on the `tls.Server` BEFORE
TLS**, which is what lets an NLB target group with `proxy_protocol_v2` sit in
front of a TLS listener at all. ECS allows five target groups per service; this
uses four.

**636 PRESENTS WHATEVER 443 DOES, AND NO TERRAFORM MAKES THAT SO.**
`ldap/ldap_server.js` builds its LDAPS listener from
`tlsServer.serverCertificate()` — the one record every socket in the process
shares (`tls/CLAUDE.md`) — so with the exported ACM certificate in the task an
LDAPS client dialling `test-idp.iyasec.io:636` gets a publicly trusted
certificate for that name, with no second certificate to issue, rotate or
trust. Measured on a real handshake: both ports present the same SHA-256.
**No suite job dials 636 yet** — it is published because a directory ought to
be reachable over TLS, and a job that wants it needs an `STS_LDAPS_URL` beside
the two LDAP variables in `environment/runner.tf`.

**AND TCP 88 IN `testidp` (2026-09-18, `var.publish_kerberos`)** — the KDC,
as a fifth row merged into the same map, so it costs what the others do and
reaches ECS's five-target-group limit. **Pure TCP**: a TCP listener, a TCP
target group behind PROXY v2 (which `server.js` installs on the KDC's TCP
socket) and a TCP-connect health check — nothing on it is HTTP. **UDP 88 is
not published, by rcbj's decision**: Kerberos over UDP does not do well across
the open internet, and a datagram could not carry the PROXY header anyway; a
client is pointed at TCP (`udp_preference_limit = 1`). Gated by a variable
rather than added for every environment because `dev` and `ci` have no job that
speaks raw Kerberos to the load balancer — the suite uses MS-KKDCP on 443 — and
they render the four rows they always did.

**Adding it re-deploys `dev` and `ci` once.** Every listener, target group,
security-group rule pair and container port mapping iterates
`published_ports`, so a new row is a new task-definition revision and three
services replaced on the next apply of any environment. That is the one place
this change is not free, and it was made knowingly: the alternative was a
fourth knob on a map that has so far been one shared list.

**AND IT MAKES LDAPS LOAD-BEARING.** ECS calls a task healthy only when it
passes the health check of EVERY target group it is registered in, so a node
whose 636 did not bind now fails to reach steady state and fails the apply,
where before it would have started with `GET /admin/ldap/service` reporting the
failure and nothing else noticing. The listener is recorded-not-thrown inside
the service on purpose (`ldap/CLAUDE.md`), and publishing the port is what
turns that recorded failure into a deployment that stops. The two ways it can
fail are the two 389 already had — not root, or the port taken — plus one of
its own: no server certificate at startup (`STS-LDAP-0029`), which cannot
happen while `global.https` is on.

**THE TWO SIDES OF THE PKI PORT NEED NOT MATCH, and since 2026-09-17 they do
not** (`var.pki_listener_port`). They were one number because that is the
arrangement that needs no thought, not because anything required it — the
mapping was already stated, in the `PKI_DISTRIBUTION_*` variables `ecs.tf`
builds from the map. What made it worth stating: **an `http://` address read
out of a certificate is expected on port 80**, and every CRL, OCSP and
caIssuers address `testidp` signs now reads `http://test-idp.iyasec.io/pki/…`
with no port at all. `locals.tf`'s `pki_public_url` leaves a default port OUT
of the URL, because `http://host:80` and `http://host` are one address to RFC
3986 and two strings to anything that compares one, and a certificate
extension cannot be edited after it is signed. **It changes nothing already
issued**: a certificate carries the address it was signed with.

**IT WAS FOUR UNTIL 2026-09-16**, the fourth being 9443, the service's
mutual-TLS listener, which `sts_global_logout`'s certificate sign-in reached.
That listener and the permissive one beside it were deleted (`tls/CLAUDE.md`)
and the sign-in is `GET /tls/sign-in` on 443, so the row came out of
`environment/locals.tf`'s `published_ports` and took an NLB listener, a target
group, a security-group rule pair, a port mapping and the runner's
`STS_MTLS_PORT` with it — every one of those iterates the map. **The XACML PEP
container's own `PEP_HTTPS_PORT=9443` is a different port in a different
container and is untouched.**

**TLS passes through the NLB — in EVERY environment, named or not.** TCP 443 →
8081 with PROXY protocol v2, client IP preservation off, cross-zone on. Without
a public name each node presents its own leaf chaining to the cluster's one
Root; `STS_TLS_HOSTNAMES` starts with the NLB's DNS name and
`STS_PUBLIC_BASE_URL` is `https://<nlb>`. Cross-zone matters to the suite:
without it `sts_cluster_alternation` sees only the node in the AZ its NLB
address is in.

**AND THE PUBLIC CERTIFICATE IS THE NODE'S TOO, since 2026-09-17.** For one
day (2026-09-16) a `public_hostname` made the 443 listener terminate TLS on an
ACM certificate, and that was a mistake with one consequence: **an NLB cannot
pass a client certificate through a TLS listener**, so `GET /tls/sign-in` and
RFC 8705 mutual TLS saw none on the one deployment a real client would be
pointed at. The listener is TCP again and the certificate moved DOWN to the
node:

* the certificate is requested **exportable** (`options { export = "ENABLED" }`
  in `dns.tf`), which is the only way AWS releases a public certificate's
  private key, is billed per certificate, and **cannot be turned on afterwards**
  — an existing certificate has to be replaced by one requested that way;
* `cert-init` exports it in the task, on every start, and writes the leaf-first
  chain and the unencrypted key into an ephemeral volume both containers mount.
  The passphrase ACM insists on is generated per run inside that container and
  never leaves it; **the key is in no Terraform state, no secret and no log**,
  which is the whole reason this is a container and not a resource;
* the node reads them through `tls.certificateFile` / `tls.keyFile` — which the
  service has always supported and which it deliberately leaves alone rather
  than re-issuing under its own Root (`tls/CLAUDE.md`, *The certificate can be
  one somebody else issued*). **No service code changed for any of this.**

The cost: `acm:ExportCertificate` in the task role *and* in the foundation's
workload boundary (below), an image to build, and a renewed certificate
reaching the node only at the next task start — the certificate is read when
the listeners bind. The node fails to start if the export fails, which is
deliberate: a node serving a self-signed certificate under a public name is the
one error this arrangement exists to prevent, and it would look healthy.

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

**THE BOOTSTRAP ADMINISTRATOR'S PASSWORD IS A FIFTH, IN PRODUCT MODE
(2026-09-17)** — `mock-sts/<environment>/bootstrap-admin-password`. It is the
only way into a fresh deployment and the one an operator actually goes looking
for, and until this it existed only as a log line: the service generates a
password and announces it ONCE (`common/CLAUDE.md`, `credentials.ts`), so the
log was sensitive and the credential was unrecoverable as soon as that line
rolled off — and on three nodes it was in whichever stream won the bootstrap
claim. Terraform generates it instead, stores it, and ECS injects it as
`STS_ADMIN_BOOTSTRAP_PASSWORD`; the service takes it in place of generating
one and **prints it nowhere**. Read it whenever:

```bash
aws secretsmanager get-secret-value --region us-west-2 \
  --secret-id mock-sts/testidp/bootstrap-admin-password \
  --query SecretString --output text
```

Three things follow. **It must satisfy the password policy** — a supplied
password is held to it where a generated one is not — so `random_password`
names four minimums rather than `special = false` like the three beside it; a
refusal is `STS-AUTHN-0205` and a service nobody can sign in to. **It is
injected, not written into the task definition**, which anybody with
`ecs:DescribeTaskDefinition` can read. And **it is product mode only**, because
the bootstrap is: `dev` and `ci` are development, where every password is
accepted, so they get the four secrets and the task definition they always had.
The workload boundary already covers it — it reads every secret under
`mock-sts/<environment>/`.

**AND THE KDC'S TWO, IN PRODUCT MODE (2026-09-18)** —
`mock-sts/<environment>/krb5-krbtgt-password` and `…/krb5-service-password`,
injected as `KRB5_KRBTGT_PASSWORD` and `KRB5_SERVICE_PASSWORD`. **A product
KDC builds neither `krbtgt/<realm>` nor the `krb5.servicePrincipal` account
while its password is the default the settings table publishes**
(`kerberos/CLAUDE.md`: a krbtgt from `krbtgt-mock-password` is a golden
ticket), so until these existed testidp answered every `kinit` with *Server
not found in Kerberos database* — the TGT's own principal — and issued no
ticket to anybody. Nobody types them, so they are forty letters and digits
like the database passwords. Rotating either (tainting the `random_password`)
invalidates every ticket issued under it and every keytab of the service.

**Backups are deleted with the environment by default**
(`delete_automated_backups = true`): retention is 14 days while it runs, and a
backup kept after a one-hour test environment is storage billed for an
environment that no longer exists.

**Logs outlive the environment**: the log group is in `foundation/`, streams
are `<environment>-<node>/<container>/<task-id>`, retention 14 days.

## A deployment beside the tests: `testidp` (2026-09-16)

**The test environments are the standard and do not change.** Every variable
added for a deployment defaults to what `dev` and `ci` already did; a `dev`
plan against its state showed two new empty outputs and nothing else.
`environment/envs/testidp.tfvars` holds what differs:

* **`public_hostname = test-idp.iyasec.io`** in the public `iyasec.io` zone.
  `dns.tf` requests an **exportable** ACM certificate for it (DNS-validated in
  that zone) and writes the CNAME to the NLB. **The NODES present it**, on
  their own 8081, through `tls.certificateFile` — the load balancer passes TCP
  through here exactly as it does for `dev` and `ci`, so a client certificate
  reaches the service and `GET /tls/sign-in` and RFC 8705 work under a
  publicly trusted name. `cert-init` is what puts the certificate in the task
  (*TLS passes through the NLB*, above). `STS_PUBLIC_BASE_URL`, the first
  `STS_TLS_HOSTNAMES` entry and the CRL/OCSP addresses use the public name.
* **`pki_listener_port = 80`** (2026-09-17): the plain-HTTP CRL/OCSP/caIssuers
  listener is published on 80 rather than 8082, so what a relying party reads
  out of a certificate is `http://test-idp.iyasec.io/pki/…` — the port an
  http:// address is expected on. The container is still 8082, and `dev` and
  `ci` keep 8082 on both sides. See *Four published ports* above.
* **Product mode with the dispatcher**: `tests/tools/modes.sh`'s `dispatch`
  row (three request workers, one surface worker, `*`, read-your-write) with
  `sts_mode = "product"`, from four `workers_*` variables. The bootstrap
  administrator's password is in Secrets Manager at
  `mock-sts/testidp/bootstrap-admin-password` and is printed nowhere (*Four
  secrets*, above); it was a log line in whichever node won the bootstrap
  claim until 2026-09-17.
* **iyasec.io names throughout (2026-09-18)**, through `extra_environment`:
  `LDAP_BASE_DN=dc=iyasec,dc=io`, `KRB5_REALM=IYASEC.IO` (so the Kerberos
  domain, the auto-created service domains and the PAC's domain name are
  `iyasec.io`), `KRB5_SERVICE_PRINCIPAL=HTTP/test-idp.iyasec.io` and
  `STS_SPIFFE_TRUST_DOMAIN=iyasec.io`. **None of the four can move under a
  store that already holds the old names**: the directory lives under its
  base DN, a Kerberos key is salted with its realm, and every certificate the
  persisted CA signed names the directory copy of its CRL by DN. So the apply
  that first carried them REPLACED THE DATABASE and kept everything else —
  the NLB, the certificate, the DNS record and the secrets, so the bootstrap
  password in Secrets Manager is still the one that signs in. It was done with
  every service scaled to 0 first, because a replaced RDS instance keeps its
  identifier and so its endpoint, and a node still running under the old
  names would have flushed its in-memory directory into the new database.
  Changing any of the four again costs the same.
* 2 vCPU / 8 GB nodes (five processes each), no suite runner,
  `10.52.0.0/16`. Backups are deleted on destroy, because the environment is
  built and torn down many times over the coming weeks.
* **Built with `terraform-local.sh`, `ALLOWED_CIDR` unset**, so the load
  balancer admits the building host's current address and nothing else:
  `IMAGE_TAG=<tag> deploy/aws/terraform-local.sh testidp apply`, and
  `… testidp destroy`.
* **Or from GitHub (2026-09-17)**: `testidp-deploy.yml` builds the service
  and schema-init images for the dispatched commit and applies;
  `testidp-destroy.yml` destroys, refusing unless `confirm` is typed as
  `testidp`. Both share `aws-cluster.yml`'s concurrency group for the
  environment, so nothing overlaps. **A workflow cannot see the address of the
  person who dispatched it** — the event names the account and carries no IP,
  and the runner's address is GitHub's — so the deploy takes `allowed_ip` as a
  required input (single public IPv4 addresses, each a /32; wider ranges and
  private addresses are refused before anything is built), and does NOT admit
  the runner, unlike `aws-cluster.yml`, whose suite needs it. The one-liner
  that fills it with your current address:
  `gh workflow run testidp-deploy.yml --ref develop -f allowed_ip="$(curl -fsS https://checkip.amazonaws.com)"`.
  Re-running with a new address replaces the list, which is how a changed
  address is let back in.

**`acm:ExportCertificate` IS IN THE WORKLOAD BOUNDARY, WHICH AN ADMINISTRATOR
APPLIES.** A boundary is a ceiling, so the task role's own statement (scoped to
the one certificate ARN) is inert until `foundation/` has been re-applied with
it. Until then `cert-init` fails with an AccessDenied naming the action and the
node does not start — which is the failure, not a silent one. The boundary's
statement names every certificate in the account and region, because a
long-lived stack cannot name a certificate an environment has not created yet;
the effective permission is the intersection, so a container reaches exactly
one.

The deployer gained ACM (created and changed only with `Project = STS`) and
Route53 (`foundation/variables.tf`'s `public_dns`: listed zones, and only the
listed record names in them — the validation record is `_<random>.<name>`,
hence the wildcard). Route53 requests carry us-east-1, so the region fence
exempts `route53:*`.

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

## The workflow, and why it looks like the parent's

`aws-cluster.yml` follows `id-proto-debugger/.github/workflows/website-deploy-test.yml`
and `terraform.yml`: Terraform runs **inside a container built from the
repository** (`deploy/aws/Dockerfile`), the same one `terraform-local.sh` runs,
so the workflow installs neither Terraform nor the AWS CLI and a plan behaves
the same on a laptop and in CI; **static-key secrets** (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`) are handed to `docker run`; the jobs are **ordered in
one workflow** and serialised per environment. Two things differ, and both are
about this stack rather than taste:

* **The key is `git_user6`'s, and the entrypoint assumes the deployer ROLE** —
  that user may do nothing else. It is the account's `git_userN` pattern
  (`git_user5` assumes `rcbj-deploy` for the rcbj.net site): path `/`, no login
  profile, no groups, one inline policy `assume-mock-sts-deployer`, and the role
  trusts it by name (`foundation/iam_deployer.tf`, `ci_user_name`). It is a
  SECOND principal of the role beside `mock-sts-deployer`, a person's, so either
  key can be rotated or revoked without the other. Its key was created by hand
  (`aws iam create-access-key`) and set as the repository's `AWS_ACCESS_KEY_ID`
  and `AWS_SECRET_ACCESS_KEY` secrets on 2026-09-15; it is in no Terraform state.
  The role ARN is built from the account, so there is no third secret.
* **`test` is its own action**, because an environment is reusable
  (`reset-environment.js`): apply once, test many times, destroy at the end.
  `apply-and-test` is the throwaway run, and its `teardown` job runs whatever the
  suite said unless `keep` is set.

Checked against `dev` on 2026-09-15 with the deployer user's key: `output`,
`plan` (no changes against the stack applied by hand) and `ecr-password`.

## Running it by hand

**`terraform-local.sh` NEVER LEAVES THE STATE LOCKED ON A LONG RUN OR AN
INTERRUPT (2026-09-18)**, which it did twice on testidp, each time costing a
`force-unlock` and a round of `terraform import`. There were two causes, and each has a fix:

* **Expired credentials.** An `aws login` session was handed to the container as a
  snapshot that lasted about fifteen minutes, and an apply that creates an RDS
  replica lasts longer. The launcher now serves your host session through
  `host-credentials.js`: a token-guarded endpoint on 127.0.0.1, in the ECS
  container-credentials shape, which the SDKs ask again before expiry. The
  container runs on the host network to reach it. Static `AWS_*` keys in the
  environment still travel as a snapshot.
* **An interrupt that killed rather than stopped.** Bash as the container's PID 1 never passed a
  signal on to terraform, and the launcher's foreground `docker run` was
  not interruptible either. Now INT or TERM to the launcher becomes `docker kill
  -s INT` on its named container, and `entrypoint.sh`'s `tf` passes that to
  terraform as an interrupt. Terraform finishes what is in flight, writes
  state and releases the lock (checked by interrupting a plan mid-refresh).
  The credentials helper ignores the interrupt and exits when the launcher's
  pipe closes, because terraform needs credentials to shut down cleanly.

`TF_CLI_ARGS_apply` (and `_plan`, `_destroy`) pass through, so
`TF_CLI_ARGS_apply='-target=…'` applies one resource.

```bash
deploy/aws/bootstrap-state.sh                         # once, administrator
terraform -chdir=deploy/aws/foundation init -backend-config=bucket=mock-sts-terraform-state-<account>
terraform -chdir=deploy/aws/foundation apply          # once, administrator

# as the deployer role, from here on
docker build -t <repo>:<tag> --build-arg STS_CLOUD_SDKS=@aws-sdk/client-secrets-manager \
  --build-arg STS_DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem .
docker build -t <repo>:schema-<tag> -f deploy/aws/schema-init/Dockerfile .
docker build -t <repo>:cert-<tag> -f deploy/aws/cert-init/Dockerfile .   # only with a public name
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

# or the same through the container, with nothing installed but docker:
IMAGE_TAG=<tag> deploy/aws/terraform-local.sh dev apply
deploy/aws/terraform-local.sh dev suite
deploy/aws/terraform-local.sh dev destroy
terraform -chdir=deploy/aws/environment destroy -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
```
