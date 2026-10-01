# deploy/aws/

**A three-node iya-sts cluster in AWS, built and destroyed by Terraform, and a
workflow that tests it (issue #51).** Nothing here runs inside the service; the
Dockerfile removes this directory from the image.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the S3 state bucket `iya-sts-terraform-state-<account>` — not Terraform, because it holds Terraform's state | an administrator |
| `foundation/` | long-lived | the deployer IAM user, the role it assumes, the two permissions boundaries (the workload one, and the ECS infrastructure role's since #214), the KMS key, the ECR repository, the container log group, the test report bucket `iya-sts-test-reports-<account>` — and since #98, for every region in `permitted_regions`, a single-region CELL key, a replica of the multi-region GLOBAL key, a log group and a replica of the repository (`modules/region`), with ECR replication to them (*Cells*, below) | an administrator |
| `environment/` | per run | VPC, NLB (443, 389, 636, the plain-HTTP CRL/OCSP port on 80, and TCP 88 for the KDC — the same in every environment since 2026-09-21), and with `public_hostname` a CNAME (`dns.tf`) — and the public certificate's ARN, READ from `certificate/`'s state, since 2026-10-01, RDS primary + replica, secrets, ECS cluster, task and execution roles, the ECS infrastructure role, with `mail_ses_domain` an SES identity and its DKIM records (`mail.tf`, #311), three services — each task with an EBS volume for risk dataset uploads (#214) | the deployer role |
| `certificate/` | **kept across destroys** | **the public ACM certificate (2026-10-01, rcbj)**: the exportable certificate the nodes present, its DNS validation records — one state per environment (`environment/<env>/certificate.tfstate`) and per cell (`environment/<env>/<cell>/certificate.tfstate`). Applied before every environment apply, NEVER destroyed with the environment, and its first apply ADOPTS an existing certificate rather than requesting one (*The public certificate is kept*, below) | the deployer role, through `entrypoint.sh` |
| `spiffe-realm/` | per realm | one trust realm's two SPIFFE ports (Workload API, SPIRE Server API) on an existing environment's NLB: two listeners, two target groups with the nodes registered BY ADDRESS, and the security-group rules — state at `environment/<env>/spiffe-realm/<realm>.tfstate` (*A realm's SPIFFE ports*, below) | the deployer role |
| `environment/envs/<env>.tfvars` | per environment | what a named environment sets differently; `entrypoint.sh` passes it when it exists. `dev` and `ci` have none | the deployer role |
| `environment/envs/<env>.cells.tfvars.json` | per environment | **a multi-cell environment's cells (#98)**: each cell's region, jurisdiction and VPC CIDR, which cell holds the global database's writer, and (since #367) each jurisdiction's pinned countries. Its presence is what makes an environment multi-cell; `testidpna` (two cells) and `globalidp` (six, the target test case) are the two there are | the deployer role |
| `environment/envs/<env>.conversion.tfvars.json` | per conversion | **a single-region environment converted into this one's cells (#98)**: which old environment, each converted cell's source snapshot and the copy it restores from, and the carry-over secret. Laid over the cells file by `entrypoint.sh` ONLY with `TF_CONVERT=1` (*Converting a single-region environment into cells*, below); `testidpna`'s converts `testidp` | the deployer role |
| `convert-to-cells.sh` | per conversion | the conversion's runbook: checks (read only, the default), `--carry-secrets`, `--copy-snapshot`, and the `terraform-local.sh` commands in order — never an apply or a destroy itself | a person |
| `*/tests/render.tftest.hcl` | — | **offline renders (#367)** of `foundation/`, `global/`, `environment/` and `certificate/`: `terraform test` with nothing asked of AWS — the region rule, the mesh, the DNS tree (*What was checked*, below) | a person, after changing a stack |
| `global/` | per multi-cell environment | the global tier of a multi-cell environment (#98): the global PostgreSQL writer and a cross-region read replica per other cell, the global secrets and their replicas, the peering mesh and the inter-cell name associations — state at `environment/<env>/global.tfstate` (*Cells*, below) | the deployer role, through `entrypoint.sh` |
| `schema-init/` | per image | a `postgres:18` image that applies `postgres/schema.sql` as the RDS master user | built by CI |
| `cert-init/` | per image | an `aws-cli` image that exports the public ACM certificate into the task before the node starts, so the NODE presents it (only where `public_hostname` is set) | built by CI |
| `runner/` | per image | the suite runner image (the tests image plus the S3 client) and the two scripts its task runs | built by CI |
| `Dockerfile`, `entrypoint.sh` | per run | the Terraform image (AWS CLI v2, Terraform 1.16.2, node): one stack, one environment, one action — `init`, `validate`, `plan`, `apply`, `destroy`, `output`, `output-json`, `ecr-password` (`suite` was removed on 2026-09-21) — the parent project's `infra/` arrangement | the workflow, and `terraform-local.sh` |
| `terraform-local.sh` | per run | runs that image on a developer machine, with the credentials in the environment or the AWS CLI's session | a person |
| `reset-environment.js` | per run | removes every realm but the default one and clears the default realm's runtime overrides before a run, so an environment can be reused | both runners |
| `run-suite.sh` | per run | **the whole suite against any environment, from this machine** (2026-09-18): every job runs here against the load balancer except the two the nodes must call back to, which run in an ephemeral `suite-callbacks/` task; one merged report (*Running the suite from this machine*, below). **Not a launcher since 2026-09-21, and the ONE AWS suite**: `../../run-tests.sh --target=aws:<env>` and `--target=aws-ephemeral` both run it, and so does `aws-cluster.yml` | `./run-tests.sh` |
| `suite-callbacks/` | per run | the callback task for one `run-suite.sh` run — a subnet, a NAT gateway the load balancer admits, a task role and a task definition (credential step, remote PEP, the two callback jobs) — applied at the start of the run and DESTROYED at its end, pass, fail or interrupt; state at `environment/<env>/suite-callbacks.tfstate` | `run-suite.sh` |
| `../../.github/workflows/aws-cluster.yml` | per run | ordered jobs — images, terraform, suite, teardown — in the Terraform image, the suite through `./run-tests.sh --target=aws:<env>` after re-applying `allowed_cidrs` with the suite runner's own address; actions `apply-and-test`, `apply`, `test`, `plan`, `destroy` | GitHub Actions (dispatch only) |
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

**No NAT gateway for the nodes.** Nodes sit in public subnets with a public IP
and a security group that accepts only the NLB's group on the published ports.

**THE SUITE RUNS FROM OUTSIDE, AND THERE IS ONE OF IT (2026-09-21).** Until that
day `dev` and `ci` ran the suite as a task INSIDE the VPC (`environment/runner.tf`,
`run-suite-in-aws.sh`, the Terraform image's `suite` action) while `testidp`
ran `run-suite.sh` from a developer's machine — two suites for one job. rcbj
asked for one, and chose `run-suite.sh`: it already ran every job, the two
that need the service to call back (`sts_gnap_core`'s push, `sts_xacml_remote_pep`'s
nudge) in its per-run `suite-callbacks/` task. The in-VPC runner, its subnet,
NAT gateway, Elastic IP, task definition, the `suite_runner` variable and the
four `runner_*` outputs were deleted. **The price is admission**: the suite now
reaches the load balancer from wherever it runs, so that address has to be in
`allowed_cidrs`. A person's run admits the building host (`ALLOWED_CIDR`
unset); `aws-cluster.yml`'s suite job, on a runner of its own, RE-APPLIES the
environment with its own address at the image tag already deployed (the
`image_tag` output) — rcbj's choice over running the suite in the apply's job
or letting the suite admit itself.

**An environment is reusable, so each run starts by removing what the
previous runs left** (`reset-environment.js`, from both runners). Creating an
environment takes most of half an hour; the suite leaves every realm it creates
standing, which is the record a person reads after a red run and state the next
run did not make. The record is kept until the next run starts, and then goes,
in this order:

1. **every realm but the default one**;
2. **the bulk-load people and groups in the default realm (#344, 2026-09-29)**
   — about 15,000 entries a run, named `bulk-<door>-…` by
   `tests/vendored/bulk_load.js`, deleted through SCIM Bulk (`/admin-api` has
   no person or group delete) with a token the script mints for the seeded
   `sts-management-api` client, so it needs `STS_ADMIN_API_CLIENT_SECRET` as
   well as the admin token (both runners have it);
3. **the applications suite runs registered in the default realm**, through
   `/admin-api/applications/forget`: the identifiers jobs name per run
   (`gl-all-<stamp>`, `portal-probe-…`, `consent-client-<digits>` — the list
   is `APPLICATION_PATTERNS`, surveyed on 2026-09-29, and a job that starts
   naming a default-realm application per run adds to it) and
   `sts_userinfo_protected.js`'s RFC 7591 registrations (`sts-client-…`
   redirecting only to its `http://localhost:9999/callback`). Never a seeded
   one, and never a FIXED identifier (`admin-api-test`, `dpop-test-client`…),
   which the next run finds again rather than adding;
4. **the default realm's runtime overrides** (`tests/vendored/admin_api.js`
   requires none, and the store keeps them). `ldap.maxEntries`, which the bulk
   loads raise and leave raised, resets to the nodes' `LDAP_MAX_ENTRIES =
   ldap_max_entries` — 50,000 since 2026-09-29, one run's bulk loads beside the
   seeded population. It was 200,000 while nothing was deleted between runs.

Only the suite's own names go; `node deploy/aws/reset-environment.js --dry-run
<url>` lists what would. Until #344 nothing in the default realm was deleted, so
its directory grew by about 15,000 entries and its registry by a few hundred
applications a run, held in every node process's memory — on testidp an idle
floor of 76–87 % of 8 GiB and a restart OOM-killed (#339). Other people and
groups a job makes in the default realm (named `<x>-<run stamp>`) are still
left; they are a few hundred a run. The registry's ceiling stays at
`STS_APPLICATIONS_MAX = applications_max` (10,000): the second reuse of the dev
cluster found the service default of 500 full, and every registration was
refused `STS-REG-0020`, which `sts_userinfo_protected` reported as an
unencrypted UserInfo response. `STS_SUITE_KEEP_REALMS=1` skips the reset.

**Four published ports.** 443 → 8081; 389 (the directory in the clear) and
**636 (the same directory behind TLS, since 2026-09-17)** on the same numbers
inside and out; and the plain-HTTP CRL/OCSP listener, **8082 inside and
`var.pki_listener_port` outside** — 80 in every environment since 2026-09-21 (it was 8082 everywhere but `testidp`).
The service writes the OUTSIDE number into what it publishes:
`PKI_DISTRIBUTION_BASE_URL` is built from `published_ports.pki.listener` and
`PKI_DISTRIBUTION_LDAP_HOST` names the NLB, so a certificate's CRL address is
followable from outside. Every node listener reads the PROXY v2 header
(`common/proxy_protocol.ts`) — **LDAPS installs it on the `tls.Server` BEFORE
TLS**, which is what lets an NLB target group with `proxy_protocol_v2` sit in
front of a TLS listener at all. ECS allows five target groups per service; this
uses four.

**Revocation is not consulted on these clusters (rcbj, #371, 2026-09-30).**
`node_environment` in `ecs.tf` sets `STS_PKI_REVOCATION_CHECK=off` and
`STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT=off` for every node of every
environment, so it survives restarts and a rebuilt environment; an
environment's `extra_environment` can set either back. A value set on the
console or through `/admin-api` is persisted in the cluster's database and
OUTRANKS the environment, so after applying this to a running cluster, check
Configuration → PKI for an override. The service's own defaults (`auto`) and
the local stacks are unchanged.

**636 PRESENTS WHATEVER 443 DOES, AND NO TERRAFORM MAKES THAT SO.**
`ldap/ldap_server.js` builds its LDAPS listener from
`tlsServer.serverCertificate()` — the one record every socket in the process
shares (`tls/CLAUDE.md`) — so with the exported ACM certificate in the task an
LDAPS client dialling `test-idp.iyasec.io:636` gets a publicly trusted
certificate for that name, with no second certificate to issue, rotate or
trust. Measured on a real handshake: both ports present the same SHA-256.
**No suite job dials 636 yet** — it is published because a directory ought to
be reachable over TLS, and a job that wants it needs an `STS_LDAPS_URL` beside
the two LDAP variables `run-suite.sh` hands the jobs.

**AND TCP 88 IN `testidp` (2026-09-18, `var.publish_kerberos`)** — the KDC,
as a fifth row merged into the same map, so it costs what the others do and
reaches ECS's five-target-group limit. **Pure TCP**: a TCP listener, a TCP
target group behind PROXY v2 (which `server.js` installs on the KDC's TCP
socket) and a TCP-connect health check — nothing on it is HTTP. **UDP 88 is
not published, by rcbj's decision**: Kerberos over UDP does not do well across
the open internet, and a datagram could not carry the PROXY header anyway; a
client is pointed at TCP (`udp_preference_limit = 1`). **Published in every
environment since 2026-09-21** (`publish_kerberos` defaults true), by rcbj's
decision that a temporary test environment publishes exactly the ports
`testidp` does, so the two cannot drift: until then only `testidp` had it,
and `sts_kerberos_spnego`, which does speak raw Kerberos to the load balancer,
timed out on `ci`. The variable stays, to take the port away; `run-suite.sh`
then tells the job, which declines.

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
  in `certificate/main.tf` since 2026-10-01, `dns.tf` before), which is the only way AWS releases a public certificate's
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
(2026-09-17)** — `iya-sts/<environment>/bootstrap-admin-password`. It is the
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
  --secret-id iya-sts/testidp/bootstrap-admin-password \
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
`iya-sts/<environment>/`.

**AND THE KDC'S TWO, IN PRODUCT MODE (2026-09-18)** —
`iya-sts/<environment>/krb5-krbtgt-password` and `…/krb5-service-password`,
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

**A RISK DATASET UPLOAD LANDS ON AN EBS VOLUME OF THE TASK'S OWN (#214,
2026-09-26).** #215 gave the console and `/admin-api` an upload that streams
the file to `risk.uploadDirectory`, expands it line by line into PostgreSQL
and deletes it; the compose stacks mount a volume there. Here each node task
gets an Amazon EBS volume through ECS's EBS integration for Fargate: the task
definition declares `risk-uploads` with `configure_at_launch`, and each
service's `volume_configuration { managed_ebs_volume }` makes it gp3,
encrypted with the project KMS key, `risk_upload_volume_gib` (10) with
`_throughput` (125) and `_iops` (3000) — gp3's free baseline. It is mounted
read-write in `iya-sts` at `/usr/src/sts/data/risk-uploads` and named to the
service as `STS_RISK_UPLOAD_DIRECTORY`, both from `locals.tf`. ECS creates it
as the task starts and deletes it as the task stops, so it is temporary space
and holds no state — which is what the upload needs: a file is deleted when
its import ends however it ends, and a task that dies mid-import is covered by
the `risk.stalled-imports` job (`risk/CLAUDE.md`). **The size is five times
`risk.uploadMaxBytes` (2 GiB)**: the largest file allowed, room for two uploads
to the same node at once, and the filesystem's overhead; the largest dataset
documented, DB-IP Lite's city file, is a few hundred megabytes compressed, and
nothing expanded is ever written. Raising `risk.uploadMaxBytes` through
`extra_environment` without the volume turns large uploads into
`STS-RISK-0029` refusals, which is the failure and not a silent one. `testidp`
takes the defaults; no `envs/*.tfvars` differs.

The two alternatives, and why each was refused:

* **Raising `ephemeral_storage` (up to 200 GiB).** Simpler — no role, no
  volume configuration — but that storage is SHARED with the container image
  layers and everything else the task writes, so a large upload competes with
  the image for the same space and a full disk is a node that cannot start its
  next write rather than an upload refused; it is encrypted by Fargate with an
  AWS-owned key rather than the project's; and its size cannot be given to the
  upload alone. **`ephemeral_storage` stays at the default (20 GiB)**, and the
  upload never uses it.
* **EFS.** Persistent and shared across nodes, and this needs neither: an
  upload is imported by the node that received it, into the shared database,
  and the file is deleted when that ends. A shared file system would add a
  mount target per AZ, a security-group pair, an access point and a monthly
  bill for a property nothing reads, and a file left on it by a crashed node
  would outlive the node — the opposite of what the cleanup job assumes.

**THE VOLUME TAKES A THIRD ROLE, AND A SECOND BOUNDARY.** ECS creates,
attaches and deletes the volume with an **infrastructure role**,
`iya-sts-env-<env>-ecs-infra` (`environment/iam.tf`), assumed by
`ecs.amazonaws.com` — the scheduler, not a task. Its policy is AWS's managed
`AmazonECSInfrastructureRolePolicyForVolumes` narrowed to this environment:
`CreateVolume`/`CreateTags` only with `AmazonECSManaged = true` and an
`AmazonECSCreated` task ARN in THIS environment's cluster, attach/detach/delete
only of volumes carrying those tags, no snapshot statement, and the project key
only through EC2 (`kms:ViaService`), for an EBS encryption context, the grant
only for an AWS resource. Its ceiling is **`iya-sts-ecs-infrastructure-
boundary`** (`foundation/iam_deployer.tf`), NOT the workload boundary: widening
the workload boundary would have let any task role be given EC2 volume and key
calls no container needs. The deployer may create a role of that one name only
with that boundary, pass it only to `ecs.amazonaws.com`, and is DENIED passing
it to anything else — so it can never become a task's role.
**`foundation/` must be re-applied by an administrator before the first
environment apply with the volume**: until then the boundary lookup in
`environment/locals.tf` fails on plan, naming the policy.

**UNTESTED ON AWS WHEN WRITTEN.** By rcbj's instruction it was written and
checked statically only (`terraform fmt -check`, `init -backend=false`,
`validate` in both roots); the first `--target=aws-ephemeral` run is its test.
Three things to look at first if it fails: an AccessDenied naming an EC2 or
KMS action on the volume (the `AmazonECSCreated` condition assumes ECS writes
the task's ARN, `task/<cluster>/<id>`, into that tag, as the managed policy
does; and the KMS `EncryptionContextKeys` condition assumes EBS's `aws:ebs:id`
context); a deployer AccessDenied on `iam:PassRole` (foundation not
re-applied); and **every node replaced on the first apply**, which is expected
— a new task definition revision in `dev` and `ci` too, because the volume is
unconditional: the upload job runs against every environment the suite is
pointed at.

## Mail: an SES identity per environment that asks for one (#311, 2026-09-28)

**`mail_ses_domain` turns it on, and only `testidp` sets it** (to its public
name). `environment/mail.tf` creates the SES v2 domain identity with Easy
DKIM and writes its three `._domainkey` CNAMEs; the task role may
`ses:SendEmail` from that one address — scoped by `ses:FromAddress` over
`identity/*`, because the SANDBOX also authorizes against the recipient's
identity and a policy naming only the domain's ARN was refused (the first
send, 2026-09-28); the nodes get `STS_MAIL_TRANSPORT=ses`,
`STS_MAIL_FROM` (`no-reply@<domain>` unless `mail_from` says otherwise) and
the region. Credentials are the task role's — `mail.sesRegion`'s description
says the transport never reads one from a setting. `dev` and `ci` set nothing
and plan no change.

* **The domain is the public host name, not the zone.** The DKIM names then
  fall under `*.test-idp.iyasec.io`, which the deployer could already write,
  and the zone's own mail records are out of reach. DMARC aligns on the DKIM
  `d=`, so SES's own envelope sender does not matter.
* **The foundation owes two statements**, so an administrator re-applies it
  first: `ses:SendEmail`/`SendRawEmail` in the WORKLOAD BOUNDARY from an
  address at a `public_dns` name (`local.ses_from_patterns`), and the identity
  actions for the deployer on identities named there
  (`local.ses_identity_arns`).
* **The image needs `@aws-sdk/client-sesv2` in `STS_CLOUD_SDKS`**, or a
  product node refuses to start (`STS-MAIL-0002`). `testidp-deploy.yml` and
  *Running it by hand* build it that way.
* **The account's SES sandbox is not Terraform's.** While the account is in
  it, SES sends only to VERIFIED recipient addresses (`aws sesv2
  create-email-identity --email-identity <address>`, then click the link);
  leaving it is a support request a person makes. A refused recipient is a
  dead letter on Monitoring → Mail outbox, not a silent loss.
* **`mail_allowed_recipients` limits whom it may mail** (testidp:
  `*@iyasec.io`), as an IAM `ses:Recipients` condition. The suite's people
  have invented addresses and every one is sent security notices; refused by
  IAM they cost no quota and cannot bounce against the account's reputation,
  and they dead-letter in the outbox with the AccessDenied as the reason.
* **The identity is destroyed with the environment** (the certificate is not, since 2026-10-01),
  and re-verified from the CNAMEs on the next build. Mail queued before it
  verifies waits in the outbox and is retried by `mail.deliver`.

## The public certificate is kept, and reused (2026-10-01)

**rcbj: the destroy step leaves the certificate in place, and later builds
reuse it.** The certificate is EXPORTABLE (`options { export }`, so a node
can present it — *TLS passes through the NLB*, above), an exportable ACM
certificate is billed per issuance, and an environment that requested one on
every apply and deleted it on every destroy made it the single largest line
item of September's AWS bill. So:

* **It is `certificate/`'s**, a stack of its own: the certificate, its DNS
  validation records and the validation, one state per environment
  (`environment/<env>/certificate.tfstate`) and per cell
  (`environment/<env>/<cell>/certificate.tfstate` — an ACM certificate is
  regional). It reads the environment's own `envs/<env>.tfvars` and cells
  file.
* **The environment READS the ARN** from that state
  (`environment/dns.tf`, `terraform_remote_state`) and owns no certificate;
  a `check` block says so when the certificate stack has not been applied.
* **`entrypoint.sh` applies the certificate stack before every environment
  apply** (`apply_certificate_stack`; per cell in a multi-cell apply). An
  unchanged certificate applies as no change and costs nothing.
* **No destroy touches it.** The environment's destroy, single-cell or
  multi-cell, the GitHub workflows and `run-tests.sh --target=aws-ephemeral`
  all go through `entrypoint.sh`, which: lists the certificate's state as
  *kept* among the dependent stacks; takes the three old certificate
  addresses out of an environment's state before destroying it
  (`forget_environment_certificate`), with `removed { destroy = false }`
  blocks in `dns.tf` saying the same thing to Terraform; and REFUSES
  `TF_STACK=certificate TF_ACTION=destroy` unless
  `STS_DESTROY_CERTIFICATE=yes`.
* **Its first apply adopts what is there** (`adopt_existing_certificate`):
  with no certificate in its state, it looks in ACM, in the stack's region,
  for an ISSUED, EXPORTABLE `EC_prime256v1` certificate for the name (and,
  for a cell, carrying the cell's console name), takes the newest, and
  `certificate/main.tf`'s import block takes it into the state. So the
  certificate an environment made before this change, or one a previous build
  left, is reused, not re-requested.
* **What still issues a new one** is a change that forces it — another name,
  a cell's console name added to the SANs, another key algorithm — once,
  created before the old one is deleted.
* **Deleting it on purpose**: `STS_DESTROY_CERTIFICATE=yes TF_STACK=certificate
  TF_ACTION=destroy` (with `TF_CELL` for a cell), after the environment is
  gone. Its validation records go with it; the certificate's ARN changes on
  the next build.

## A deployment beside the tests: `testidp` (2026-09-16)

**The test environments are the standard and do not change.** Every variable
added for a deployment defaults to what `dev` and `ci` already did; a `dev`
plan against its state showed two new empty outputs and nothing else.
`environment/envs/testidp.tfvars` holds what differs:

* **`public_hostname = test-idp.iyasec.io`** in the public `iyasec.io` zone.
  `certificate/` holds an **exportable** ACM certificate for it (DNS-validated in
  that zone, and kept across builds) and `dns.tf` writes the CNAME to the NLB. **The NODES present it**, on
  their own 8081, through `tls.certificateFile` — the load balancer passes TCP
  through here exactly as it does for `dev` and `ci`, so a client certificate
  reaches the service and `GET /tls/sign-in` and RFC 8705 work under a
  publicly trusted name. `cert-init` is what puts the certificate in the task
  (*TLS passes through the NLB*, above). `STS_PUBLIC_BASE_URL`, the first
  `STS_TLS_HOSTNAMES` entry and the CRL/OCSP addresses use the public name.
* **Its ports are every environment's since 2026-09-21.** The CRL/OCSP
  listener on 80 (so a certificate names `http://test-idp.iyasec.io/pki/…`,
  the port an http:// address is expected on) and the KDC on TCP 88 were set
  in `testidp.tfvars` until then; they are the variables' defaults now, so a
  temporary test environment publishes what this one does. See *Four
  published ports* above.
* **Product mode with the dispatcher**: `sts_mode = "product"` and four
  `workers_*` variables — **two request workers, no surface worker** since
  2026-09-29 (#340), `*`, read-your-write. It was `tests/tools/modes.sh`'s
  three request workers and one surface worker until then, which on 2 vCPU /
  8 GiB idled at 76–87 % after a few suite runs and was OOM-killed on a
  restart (#339); *Sizing a node*, below. The bootstrap
  administrator's password is in Secrets Manager at
  `iya-sts/testidp/bootstrap-admin-password` and is printed nowhere (*Four
  secrets*, above); it was a log line in whichever node won the bootstrap
  claim until 2026-09-17.
* **iyasec.io names throughout (2026-09-18)**, through `extra_environment`:
  `STS_DOMAIN=iyasec.io` (it was `LDAP_BASE_DN=dc=iyasec,dc=io` until
  `global.domain` replaced that setting later the same day — the same tree,
  `dc=iyasec,dc=io`, so nothing stored moved), `KRB5_REALM=IYASEC.IO` (so the Kerberos
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

## Sizing a node: every process is a whole copy (#340, 2026-09-29)

**A node runs 1 + `workers_request_count` + `workers_surface_count` node
processes, and each holds the whole directory and every store in its own
heap** — a request or surface worker is a fork of the whole service that
restores everything from postgres at start (`common/CLAUDE.md`, the two
pools; #339 for the measurements). So a node's memory grows with the PROCESS
COUNT, not with the load, and two rules follow:

* **`task_memory` ≥ (node processes × one process's working set) +
  headroom.** The working set is about 200 MB for a process that has only
  loaded the stack, plus whatever the directory and the minted stores hold —
  about 1.3 GiB per process on testidp after a few suite runs. The peak is a
  restart, when every process restores at the same moment, and past the limit
  Fargate's OOM killer takes them with an anonymous SIGKILL.
* **Node processes ≤ `task_cpu` / 1024 + 1.** A process beyond one per vCPU
  (plus the front, which mostly proxies) buys no parallelism and costs a whole
  copy of the memory.

**A surface worker is the first to go**: with `workers_surface_count = 0`
the console and portal are answered by the request workers, which is what the
service does whenever the count is 0. `workers_read_your_write` stays on with
two or more request workers — the surface pool refuses to start without it
(`STS-WORKER-0038`), and a caller writing through one request worker and
reading back through another needs it just the same. `testidp` and
`testidpna` run 2 + 0 on 2048 / 8192 (three processes); they ran 3 + 1 (five)
until #340.

The test modes are a different question and keep their counts:
`tests/tools/modes.sh`'s `single-node` and `cluster` run three request workers
and one surface worker ON PURPOSE, because one worker cannot show a routing
mistake and one surface worker crosses the pools on every console sign-in.

## Cells: one environment in several regions (#98, 2026-09-28)

**Issue #98's design, its AWS half.** The design and its decisions (D1–D8)
are in the issue; the code half — store tiers, the routing index, the
inter-cell operations — is `feature/98`'s. What is here is the infrastructure
that design runs on, and the one contract the two halves share: the
container environment below. **Written and checked statically only, by
instruction** (`terraform fmt -check`, `init -backend=false` and `validate`
in every stack, and the offline renders described under *What was checked*);
nothing was applied or planned against AWS. The first `testidpna` apply is
its test.

**A CELL IS `environment/` APPLIED ONCE PER REGION**, with `cell` set: its own
VPC, NLB, nodes, cell PostgreSQL (primary and same-region replica, exactly as
before), exportable ACM certificate for the SAME public name, and logs. The
unit of failure and of data residency. **The design also gives each cell an
SES identity, and there is none**: no environment here has one today, so
there was nothing to make per cell. A per-cell identity needs its
DKIM records' names in `foundation/`'s `public_dns` and `ses:*` in the
deployer's policy and the workload boundary — its own change. An environment's cells are
one JSON file, `environment/envs/<env>.cells.tfvars.json` — JSON so that
`entrypoint.sh` can read it with jq and Terraform can read the same file as a
variable file, so the two cannot disagree — and `envs/<env>.tfvars` holds
what every cell shares, as it does for a single-cell environment. `testidpna`
is the first: `usw2` (us-west-2, jurisdiction `us`, `10.61.0.0/16`, the
primary) and `cac1` (ca-central-1, `ca`, `10.62.0.0/16`, Canada pinned).
`globalidp` is the second and the target test case: six cells on three
continents (*globalidp*, below). **A cell in another region is a map entry**
— region, jurisdiction, a CIDR of its own — once `foundation/` permits the
region (*Adding a region*, below).

**`cell` EMPTY IS THE STACK THAT WAS, TO THE LETTER.** Every addition is
conditional on it; every name is spelt as it was; the state key, the task
definition, the policies, the secrets and the DNS record are unchanged for
`dev`, `ci` and `testidp`. Set, every globally unique name carries the cell —
resources `iya-sts-<env>-<cell>-…`, IAM roles `iya-sts-env-<env>-<cell>-…`
(IAM is global, so two cells would otherwise claim one role), secrets
`iya-sts/<env>/<cell>/…` — and the state key is
`environment/<env>/<cell>.tfstate`. A cell id is at most five characters and
the NLB checks that the prefix stays within the 27 a target group name
leaves room for.

**THE ENVIRONMENT NAME IS `testidpna`, NOT `testidp-na`**: an environment
name is 2–12 lower-case letters and digits everywhere it is checked, and
relaxing that for one name was not worth the audit. **It cannot run beside
`testidp`** — both answer to test-idp.iyasec.io, and a CNAME cannot share a
name with a geolocation record — so the two share one concurrency group in
the workflows, and one is destroyed before the other is applied.

**A CELL MAY BE ANOTHER CLOUD'S (#97, 2026-09-30).** A cell's `cloud`
(`aws` by default) says whose it is; a multi-cloud environment's cells file
is `deploy/multicloud/envs/<env>.cells.tfvars.json`, and its GCP cells are
PEERS here — in `STS_CELL_PEERS`, admitted on 8446 and by the global
database, and their private-services ranges admitted as subscribers of the
writer's publication. Everything this directory does WITH a cell (its state,
replica, peering, secret replicas) it does with the AWS cells only; the
public name's Route 53 tree is written by `deploy/multicloud/interconnect`
instead of by each cell; and only `deploy/multicloud/terraform-local.sh`
may orchestrate such an environment. `deploy/multicloud/CLAUDE.md` argues it.

### The apply order, and why it is two passes

A cell and the global tier need each other: the global database's writer
and replicas live IN the cells' VPCs, and a cell's nodes need the global
database's addresses before they can start. So a new cell is applied twice,
and `entrypoint.sh` (`orchestrate_cells`) does it when `environment` is
applied with no `TF_CELL`:

0. **every cell's region checked** (`preflight_regions`, #367): enabled on
   the account (an opt-in region refuses every call until it is), permitted
   to the deployer (a region-fence refusal means `foundation/` was not
   re-applied with it), and offering PostgreSQL at the cells' version on
   their instance class — before anything is made;
1. **each cell with no state yet, `cell_phase = base`, primary first** —
   everything but running nodes (every ECS service at a desired count of 0),
   including the subnet group, security group and Cloud Map namespace the
   global stack needs; no read of the global state;
2. **`global/`** — reads every cell's state and builds the global database,
   the global secrets, the peering and its routes, the name associations;
3. **every cell, `full`, primary first** — the nodes, told where the global
   tier is. The primary cell's nodes run `global-schema-init` against the
   writer (the same schema image and file as the cell's), so every other
   cell's nodes start against a schema that exists; a replica takes the
   schema, the `sts_app` role and its password by replication.

A cell that already has state skips step 1, because `base` scales its nodes
to zero and on a running cell that is an outage. Every later apply is steps
2 and 3. **A cell CONVERTED from a single-region environment** takes step 3
twice, with its nodes held at 0 and a one-off conversion task between
(*Converting a single-region environment into cells*, below). **Destroy** reverses it: every cell's dependent stacks
(`spiffe-realm`, `suite-callbacks` — whose state is under
`environment/<env>/<cell>/` now — the 2026-09-20 lesson, kept), then
`global/` while the cells it reads still exist (routes, peerings, zone
associations, the replicas and then the writer, which RDS will not delete
while it has replicas, the secrets and their replicas — everything it put
into a cell's VPC, which would not otherwise delete), then each cell in
`base` so that its destroy reads no global state that is gone. `plan` and
`output` do every cell and then global; `output-json`, `init`, `validate` and
`import` want a `TF_CELL` (or `TF_STACK=global`).

**AFTER THE PRIMARY, A STEP'S CELLS RUN AT ONCE (#367, 2026-09-30)** —
`TF_CELL_PARALLEL` at a time (6), each this script again with its own state,
lock, region and `TF_DATA_DIR`, its lines prefixed `[<cell>]`; the provider
is fetched into a shared plugin cache first (`warm_plugin_cache`), because
filling the cache from several inits at once is not promised safe. Six cells
one after another — a cell database and its replica each in `base` — did not
fit in the deployer's four-hour session. The primary still goes first and
alone in steps 1 and 3: its image is what ECR replicates from, and its nodes
make the global schema. A failed cell lets the others FINISH and then stops
the apply naming it; a cell whose conversion is pending is applied alone,
after the rest. Destroy takes every cell at once, after `global/`. **An
interrupt reaches the children as TERM**: a background command in a script
starts with SIGINT ignored and cannot trap it (measured), so `step()`'s INT
relay had never reached its child either — both send TERM, which the
child's `tf` turns into terraform's interrupt.

**REMOTE STATE, NOT SSM PARAMETERS, carries the global endpoints to the
cells.** The values are known at plan time, so a cell's plan shows the task
definition its nodes will get; the deployer already reads every state under
`environment/` and needs no new right, where parameters would need `ssm:*` in
every region and a second copy of every value; and the order it imposes —
global before a cell's `full` — is one the database imposes anyway. The
peers' inter-cell names need no read at all: they are deterministic.

### What is replicated, and what deliberately is not

| | Where | Replicated to the other cells |
|---|---|---|
| the global KEK (`iya-sts/<env>/kek`, `STS_KEYS_KEK_*`) | global/, primary region | **yes**, under the multi-region key's replica in each region |
| the global database's password, the management client's secret, product mode's bootstrap, krbtgt and service passwords | global/ | **yes** — every cell must hold the same values, and a per-cell value would be a different one in each, all but the first refused by the global tier |
| the global database's master password | global/ | no — only the primary cell's `global-schema-init` uses it |
| the global database | global/: writer in the primary cell's VPC | **yes**: one RDS cross-region read replica per other cell (D3) |
| the images | foundation/: pushed to the home region | **yes**: ECR replication into a repository made first in each region, so it carries the lifecycle policy |
| **the cell KEK (`iya-sts/<env>/<cell>/cell-kek`, `STS_CELL_KEK_*`)** | the cell | **NO, and never**: sealed under the cell's single-region key, which AWS will not replicate. A copy of the cell's rows taken elsewhere cannot be read there — the residency line of issue #98, §3 |
| **the cell database** | the cell | **NO**: its primary and same-region replica, as before, under the cell key |
| the cell's logs | the cell's region's log group | no — a log is personal data as much as a row is |

**THE KEYS ARE LONG-LIVED AND PER REGION, IN `foundation/`**, for the reason
the project key is: a key per environment would leave a seven-day
pending-deletion key behind every teardown. `alias/iya-sts-global` is a
multi-region key (primary in the home region, a replica in every other
permitted region) and seals only what every region may hold;
`alias/iya-sts-cell-<cell>` is single-region and seals the cell's own
secrets, database, upload volumes and log group. The project key stays what
single-cell environments use, and cannot be made multi-region after creation.

### The inter-cell channel: peering, and 8446 by a private name

**The cell VPCs are a full mesh of inter-region VPC peerings** (`global/`,
one module block per pair of the four regions the design names), each with
routes both ways from both route tables — the public one the nodes use and a
new PRIVATE one the databases use, which a cell has in place of the VPC's
main table because the main table is untagged and the deployer may route only
through tagged ones. What crosses it: the inter-cell listener and every
cell's writes to the global writer. RDS carries its own replication.

**8446 IS THE INTER-CELL MUTUAL-TLS LISTENER**, on the service's own `cell`
Issuing CA's certificates, so there is nothing here to issue. It is admitted
on the nodes' own security group from the OTHER cells' CIDRs only, and is on
no load balancer and in no public zone.

**IT IS REACHED THROUGH A CLOUD MAP NAME, NOT AN INTERNAL NLB — the one place
this departs from the brief.** An internal NLB was the first choice and ECS
rules it out: a service may carry five target groups and every cell's node
service already carries all five on the public load balancer (https, ldap,
ldaps, pki, kerberos). Registering the nodes in a sixth by address, as
`spiffe-realm/` does, goes stale at every task restart, and a stale
inter-cell target is a traveller who cannot sign in (D6 fails closed). So
each node service registers its tasks in a Cloud Map PRIVATE DNS namespace
(`service_registries`, which is not a target group):
`nodes.<cell>.<env>.iya-sts.internal`, one A record per healthy task, kept
by ECS. The namespace is a Route 53 private zone; `global/` associates each
cell's zone with every other cell's VPC, so the name resolves inside the
cells and nowhere else. It costs $0.50 a month per cell against an NLB's
hour and LCUs; it gives up a single stable address, since a peer is several A
records the service must try in turn. **The URL in `STS_CELL_PEERS` is
therefore `https://nodes.<cell>.<env>.iya-sts.internal:8446`**, and each node
is told its own as `STS_CELL_HOSTNAME` so the cell leaf can name it.

### Route 53 (D7)

The public name becomes a record tree: GEOLOCATION records for the
countries a JURISDICTION pins (`jurisdictions` in the cells file) aliasing
that jurisdiction's LATENCY set, `<jurisdiction>.cells.<name>`, with one
record per cell of the jurisdiction; and a DEFAULT geolocation record (`*`,
written by the primary cell) aliasing `cells.<name>`, a LATENCY set with one
record per cell. `CA` → `ca.cells.test-idp.iyasec.io` (cac1 alone); in
globalidp the 27 EU countries and IS, LI, NO → `eu.cells.global-idp.iyasec.io`
(euc1 or euw1, whichever is nearer and healthy), `SG` → sg, `MY` → my.
**Pinned to a jurisdiction, not a cell, since #367**: the law that asks for
the pin names a place, and with two EU cells a pin to one of them would
never fail over to the other. Each cell writes its two latency records;
a jurisdiction's pins are written by its first cell by id; so none reads
another's state for DNS. **A pinned country's record does not evaluate its target's health**:
Route 53 answers an unhealthy geolocation record with the default, which
would send the EU to the United States the moment every EU cell was down,
and the law that asks for the pin does not lapse with the cells (fail
closed; the service, not DNS, is authoritative on residency anyway). Inside
the jurisdiction's set the health checks count — one EU cell fails over to
the other — and a set whose every record is unhealthy is answered with all
of them. **The latency records carry the health checks**,
an HTTPS GET of `/healthcheck` on 443 of each cell's NLB from three checker
regions. The NLB admits `allowed_cidrs` only, so **the Route 53 health
checkers' published ranges for those three regions are admitted on 443 and
on no other port**, in a cell with a public name only — three regions,
Route 53's minimum, to keep that list short. A single-cell environment keeps
the one CNAME. Every cell requests a certificate for the same name, and ACM
validates it with the same record in every region, so each cell writes it
with `allow_overwrite` and a cell destroyed ALONE takes it with it; the cells
are destroyed together.

**AND EACH CELL HAS A NAME OF ITS OWN (#361, 2026-09-30)**: `<cell>.<public
name>` (`usw2.test-idp.iyasec.io`), one A alias to that cell's NLB and no
routing policy (`dns_cells.tf`'s `cell_console`), on that cell's
certificate as a subject alternative name, and handed to its nodes as
`STS_CELL_CONSOLE_URL` — every peer's in `STS_CELL_PEERS`' `consoleUrl` — so
Server configuration → Cells links each region's own console. Adding the
name REPLACES each cell's certificate once (`create_before_destroy`); the
nodes pick the new one up because the same apply changes their task
definition.

### The contract with the code half

Every node of a cell is given, beside everything a single-cell node already
is (`environment/cells.tf`, `cell_environment`):

| Variable | Value |
|---|---|
| `STS_CELL_ID`, `STS_CELL_JURISDICTION` | the cell, e.g. `usw2`, `us` (empty/unset: single-cell) |
| `STS_CELL_PORT` | `8446` |
| `STS_CELL_PEERS` | JSON array of `{ "id", "jurisdiction", "url" }` for every OTHER cell, `url` = `https://nodes.<cell>.<env>.iya-sts.internal:8446` |
| `STS_CELL_HOSTNAME` | **(added)** this cell's own inter-cell host name, the host of the `url` its peers are given |
| `STS_GLOBAL_DATABASE_URL` | the global writer, `sslmode=require`, no password |
| `STS_GLOBAL_DATABASE_READ_URL` | the replica in this cell's region; the writer in the primary cell |
| `STS_GLOBAL_DATABASE_PASSWORD_PROVIDER`, `_REF`, `_REGION` | `aws`, the replica of the password secret in this region, this region |
| `STS_CELL_KEK_PROVIDER`, `_REF`, `_REGION` | `aws`, the cell's own KEK secret, this region |

`STS_KEYS_KEK_*` keep naming the key-encryption key — the global one,
replicated into this region — `STS_DATABASE_URL` stays the cell database, and
`STS_PUBLIC_BASE_URL` stays the one public name in every cell. The global
variables appear only in `full`; a `base` cell runs no node.

### What it costs

Per cell, roughly `testidp` again: three 2 vCPU / 8 GB Fargate nodes (about
$0.35 an hour in us-west-2, some ten per cent more in ca-central-1), the cell
database and its replica (about $0.07), the NLB ($0.0225 plus LCUs), and for
every cell but the primary one a global read replica (about $0.035) — about
**$0.47–0.52 an hour a cell idle**, before storage (about $10 a month) and
inter-region transfer ($0.02 a GB on the peering and on the replication).
The primary cell also carries the global writer (about $0.035 an hour). The
small monthly items: a health check ($1.50 with HTTPS), a private zone
($0.50), six replicated secrets per non-primary cell ($2.40), and in
`foundation/` a cell key and a global-key replica per permitted region ($2).
Estimated from 2026-09 on-demand list prices and not measured; the whole
environment is applied and destroyed together, so nothing idles unbilled.

### What `foundation/` must be re-applied with first

**By an administrator, with `permitted_regions` listing every cell's region**
(its default since #367: the two `testidpna` needs and the five more
`globalidp` does) — which replaces the
one-region fence (`OnlyUsWest2ForRegionalServices` → the same deny over the
list, inside both boundaries too since #367 — the ARNs name any region and
the fence holds them to the list), and makes each region's keys, log group
and repository replica. **For `globalidp` it also adds `global-idp.iyasec.io`
and its wildcard to `public_dns`**, and ap-southeast-5 must be enabled on the
account first. A fourth
deployer policy, `iya-sts-deploy-cells`, holds what only cells do: the
peering (accepted in the other region, where the connection arrives
untagged, so scoped to this account's VPCs instead), Route 53 health checks
(which have no name to scope by), and Cloud Map with the private zones it
makes — a Deny keeps the public zones out of reach of `DeleteHostedZone`.
**`aws_ecr_replication_configuration` is the registry's WHOLE replication
configuration**; nothing else in the account replicates today, and a project
that needs to must add its rule there.

**ANY REGION, BY ONE LIST (#367, 2026-09-30).** Until then `foundation/`
and `global/` carried a provider block per region a cell could be in — four,
written out, because Terraform cannot make a provider per list element — a
module block per region, and `global/` a peering block per PAIR. AWS
provider 6 gives every regional resource a `region` argument, so each is one
`for_each` through one provider: `modules/region` over `permitted_regions`,
the replicas over the non-primary cells, the peerings over every pair (the
primary first, then the rest by id, so adding a cell re-orients no existing
pair). `moved` blocks carry the old instances to the new addresses — a
foundation plan that DESTROYED a cell key would schedule the deletion of
every cell database sealed under it — and **the first plan of each stack
after this change must show no destroy** before anything is applied.

**A cell's id is its region shortened by rule**, not a table: the area, the
direction's initials and the number — us-west-2 = usw2, us-east-2 = use2,
eu-west-1 = euw1, ap-southeast-5 = apse5 (`foundation/locals.tf`,
`cell_of_region`; the same rule is in the `cells` validation of
`environment/` and `global/`, because a validation sees no local — keep the
three in step). A region must be `area-direction-digit`, which keeps an id
within five characters.

**NO DEPLOYER POLICY GROWS WITH THE REGIONS.** They named every regional
ARN once per permitted region, and at seven regions `deploy-data` rendered
8,804 characters against IAM's 6,144 for a managed policy (5,621 at two — it
was near the edge already). Since #367 those ARNs carry a `*` region
(`locals.tf`, `rarn`) and the region FENCE — the deployer's `region-fence`
Deny, and the same Deny now inside both boundaries — is the one place the
regions are named. Rendered offline: every deployer policy is the same size
at 2, 7 and 15 regions; the boundaries grow by a few hundred characters (the
fence's list, and a cell key ARN per region).

### Adding a region

1. If it is an opt-in region (every one launched since 2019), an
   administrator enables it on the account and waits for `ENABLED`.
2. The region in `foundation/variables.tf`'s `permitted_regions`, and an
   administrator re-applies `foundation/` — its cell key, global-key replica,
   log group and repository replica are made, and the fence opens. The plan
   stops at `aws_regions.enabled` if step 1 was skipped.
3. The cell in the environment's cells file: its id (the rule), region,
   jurisdiction, a CIDR no other cell of the environment uses, and the
   jurisdiction's pinned countries if it is a new one.
4. `IMAGE_TAG=<tag> deploy/aws/terraform-local.sh <env> apply`. The
   preflight asks the region first; the new cell takes its `base`, the
   global stack adds its replica, peerings and zone associations, and every
   cell's `full` gives the others the new peer.

Nothing in `global/`, `environment/` or `entrypoint.sh` names a region.

### `globalidp`: the six-region test case (#367, 2026-09-30)

**rcbj's target test case for cells**: six cells on three continents behind
`global-idp.iyasec.io` — a name of its own, so it can stand beside `testidp`
or `testidpna` (they share `test-idp.iyasec.io` and cannot) — each cell's
console at `<cell>.global-idp.iyasec.io`.

| Cell | Region | Jurisdiction | VPC | Pinned |
|---|---|---|---|---|
| `usw2` | us-west-2 | `us` | 10.71.0.0/16 | — (the **primary**, the global writer) |
| `use2` | us-east-2 | `us` | 10.72.0.0/16 | — |
| `euc1` | eu-central-1 (Frankfurt) | `eu` | 10.73.0.0/16 | the EU 27 and IS, LI, NO, to the `eu` set |
| `euw1` | eu-west-1 (Ireland) | `eu` | 10.74.0.0/16 | (the same set) |
| `apse1` | ap-southeast-1 (Singapore) | `sg` | 10.75.0.0/16 | SG |
| `apse5` | ap-southeast-5 (Malaysia) | `my` | 10.76.0.0/16 | MY |

**Malaysia because there is no AWS region in the Philippines** (rcbj's first
choice): Manila is a Local Zone of ap-southeast-1, not a region, and cannot
be a cell. ap-southeast-5 is an **opt-in region**, which an administrator
enables on the account before `foundation/` is re-applied (*Adding a
region*). It is the region most likely to lack something: RDS offers
PostgreSQL on db.t4g there (AWS, 2025-05), which the preflight confirms at
the cells' version; Fargate, Cloud Map, an exportable ACM certificate and
Route 53 latency routing to it were not confirmed ahead and show up as
apse5's own `base` or `full` failing.

**Two cells in one jurisdiction is what this environment tests that
testidpna cannot**: a person homed in usw2 served by use2 crosses no
jurisdiction (`cells.permittedTransfers` needs no entry), and an EU client
fails over between euc1 and euw1 without leaving the EU (the DNS above).
`envs/globalidp.tfvars` carries testidpna's #361 transfer choice to every
pair of the four jurisdictions, so each region's console serves an
administrator homed in another; delete the line to test the strict default.

**What it costs**: six cells at *What it costs*'s figure — about **$3 an
hour** idle before transfer, with five global read replicas (one stream each
from the writer) and fifteen peerings; about $2,200 a month if left up.
Estimated, not measured.

**Written and checked offline only**, like the rest of *Cells*: the renders
(*What was checked*), `terraform validate` in every stack, shellcheck (no new
finding) and the parallel runner exercised with stub children (a failure,
and an interrupt). The first apply is its test, and it waits for rcbj.

### Converting a single-region environment into cells (2026-09-28)

**`testidp` becomes cell `usw2` of `testidpna` WITH ITS DATABASE** — the
risk datasets and their history in `sts_risk_*` above all, which take days
to import again and, for the refused-password and sign-in history, cannot be
imported at all. Everything a new cell does, it does; what differs is three
things in `environment/`, one in `global/`, one in the orchestration and a
runbook. **Written and checked statically only, by instruction**, like the
rest of *Cells*; nothing was planned or applied, and the first
`TF_CONVERT=1` apply is its test.

**THE TWO THINGS A DESTROY OF THE OLD ENVIRONMENT TAKES WITH IT, AND WHAT
KEEPS EACH.** `rds.tf` has `skip_final_snapshot = true` and
`delete_automated_backups`, so the database goes with no record; the
secrets have `recovery_window_in_days = 0`, so they go at once — and every
sealed row opens only under the old key-encryption key. So both are copied
OUT first, by `convert-to-cells.sh`, which refuses nothing and destroys
nothing and whose default run only reads:

* **the snapshot, RE-ENCRYPTED UNDER THE CELL KEY.** RDS restores a snapshot
  under the snapshot's own KMS key — `RestoreDBInstanceFromDBSnapshot` has no
  key parameter (RDS API reference) — and a copy is the only way to change
  it: `CopyDBSnapshot` with `KmsKeyId` "encrypt[s] the copy with a new KMS
  key" (RDS API reference, *CopyDBSnapshot*). `testidp`'s snapshot is under
  the project key; a cell's database is under `alias/iya-sts-cell-<cell>`
  (the residency line). Restoring the project-key snapshot as it is would
  put the cell's data under a key it must not be under, and the instance's
  `kms_key_id` would disagree with the config on every plan — the provider's
  answer to which is to REPLACE the database. `--copy-snapshot` makes
  `<source>-<cell>` under the cell key, in the cell's region (cross-region
  with `--source-region` for a cell elsewhere), and waits for it.
* **the carry-over secret**, `iya-sts/carryover/<old env>`: one JSON secret
  under the project key with the four values the restored rows depend on —
  the KEK, the management client's secret, the bootstrap administrator's
  password and the Kerberos service password. `global/secrets.tf`, *A
  converted environment's secrets*, argues each against the code and the
  two NOT carried: the krbtgt password (product mode does not read it since
  #169; the key is sealed on the directory entry and travels in the
  snapshot) and the database passwords (new ones, set on the restored
  instance and role). `--carry-secrets` reads each value into a file of its
  own process and never prints one.

**THE CONVERSION FILE IS AN OVERLAY, NOT AN EDIT OF THE CELLS FILE** —
`envs/testidpna.conversion.tfvars.json`, which `entrypoint.sh` lays over the
cells file only with `TF_CONVERT=1` (jq's deep merge, restricted to each
cell's `db_snapshot_identifier`, so it can add a snapshot and never a cell),
and whose `carryover_secret` it hands to `global/` alone. The cells file
could carry `db_snapshot_identifier` itself — the field is part of the cells
object — and deliberately does not for `testidpna`: every fresh apply of the
environment by anybody would then restore from a snapshot of a database that
stopped being current the day it was taken, run a conversion nobody asked
for, and FAIL on the day the snapshot or the carry-over secret was deleted.
A conversion is one event; the overlay is named on the one apply that is it.

**WHAT MAKES A LATER APPLY WITHOUT THE OVERLAY SAFE.** Two things read their
input once and keep it:

* `aws_db_instance.primary` IGNORES `snapshot_identifier` after creation
  (`lifecycle`). It forces a new instance when it changes, so without that
  the first apply after the conversion — which names no snapshot — would
  destroy the converted database and make an empty one. Ignored in every
  environment; null stays null for all the others.
* `global/`'s `terraform_data.carryover` takes the carried values when the
  global stack is first created and ignores its input from then on, so a
  later apply keeps the old KEK rather than putting a generated one in its
  place. **A carry-over named on a global stack that already generated its
  secrets is refused at plan**: its rows were sealed under the generated
  KEK, and carrying one in would lose them.

**WHERE THE CONVERSION RUNS, IN `orchestrate_cells`.** For a cell with a
snapshot and no state yet:

1. **a marker, `environment/<env>/<cell>.conversion.json`, set PENDING**,
   before anything is made;
2. `base` — the cell database is a `base` resource, so the RESTORE happens
   here (tens of minutes for the risk tables), then the same-region replica
   from it;
3. `global/` as always, with the carried secrets;
4. the cell's `full` **twice**: first with `TF_CELL_HOLD` (`cell_hold_nodes`
   — the task definitions, the global tier's addresses and a conversion task
   definition, and every node service at 0); then the conversion task, run
   once and waited for (`convert_cell`, up to `TF_CONVERT_TIMEOUT`, 7200 s);
   then the marker set DONE and `full` as usual, which starts the nodes.

**The conversion task** (`environment/conversion.tf`) is a node's task with
the service replaced by `node persistence/cell_convert.js`: the same roles,
image, subnet, security group, environment and secrets — less the public
certificate's two paths, since no `cert-init` runs and the tool binds
nothing — and the two schema inits first, in the same task, so the tool
opens two databases at the current schema with `sts_app` already on THIS
environment's password (schema-init ALTERs a role that exists, `postgres/
schema.sql`). A task definition of its own rather than the node's with a
command override: the node's declares the upload volume
`configure_at_launch`, which a RunTask would have to configure, and an
override of one container's command cannot put the schema inits before it.

**On failure** — the tool exits non-zero, a schema init fails, the task
cannot start — the apply STOPS: the cell's nodes stay at 0, the marker stays
PENDING, the cells after it are not applied, and the message names the task,
each container's exit and the log stream. The tool leaves its sources in
place, so the same `TF_CONVERT=1` command is the retry. **On re-apply**:
PENDING runs the held apply and the conversion again (the tool is
idempotent); a conversion task still RUNNING from an interrupted apply is
waited for rather than doubled; DONE skips it, reading nothing; and PENDING
without `TF_CONVERT` REFUSES rather than starting nodes on unconverted rows.
A snapshot named for a cell that already existed restored nothing and is
said so. The marker is deleted with the cell. Other cells are untouched by
any of it — `cac1` is made empty, exactly as before.

**The deployer's two new RDS actions** (`foundation/iam_deployer.tf`,
`RdsRestoreAndCopyProjectSnapshots`): `RestoreDBInstanceFromDBSnapshot`,
which the provider calls in place of `CreateDBInstance`, and
`CopyDBSnapshot`, for the runbook — on `iya-sts-*` snapshots and instances
only, and **no `DeleteDBSnapshot`**: the snapshot is the only record of the
database the conversion destroyed, and removing it is an administrator's
call. So `foundation/` is re-applied before the conversion, as it already
must be for any cell (*What foundation/ must be re-applied with first*).

**What it costs and what it loses.** The service is DOWN from the old
environment's destroy until the converted cell's nodes are healthy — a
destroy, a restore and a first cell apply, most of an hour. Anything written
after the snapshot was taken is lost; the runbook prints how to stop the old
environment's nodes and snapshot its primary first when that matters.

If the first conversion fails, look first at: `kms_key_id` planned to change
on `aws_db_instance.primary` (the snapshot named is not under the cell key —
stop, it would replace the database); an AccessDenied on
`RestoreDBInstanceFromDBSnapshot` (`foundation/` not re-applied); a restore
refused for storage (`db_allocated_storage` below the snapshot's); and the
conversion task's own log, `<env>-<cell>-convert/cell-convert/<task id>`.

### What was checked, and what to look at first

**Since #367 the renders are in the repository**, `<stack>/tests/render.tftest.hcl`
in `foundation/`, `global/` and `environment/`, reading the real cells files:
`terraform -chdir=deploy/aws/<stack> init -backend=false`, then `test`. No
credential is needed and nothing is asked of AWS. They hold the region rule
and its refusals, globalidp's fifteen peerings, five replicas and thirty zone
associations, testidpna keeping its pair and replica under the `moved`
blocks' addresses, the DNS tree cell by cell, and a single-cell environment
rendering no cell record. They are not run by the suite or CI. What they
cannot show is a plan against the real states — the `moved` blocks meeting
what the states hold — which is the zero-destroy plan owed before the first
apply (*Any region, by one list*). The paragraphs below are #98's.

`terraform fmt -check`, `init -backend=false` and `validate` in all five
stacks; shellcheck on the scripts (no new findings); actionlint on the two
workflows. And **offline renders with `terraform test`**, in a scratch copy,
with every data source that calls AWS overridden and a provider that makes no
call: `testidp` and `dev` rendered IDENTICALLY before and after this change —
the three task definitions, role names, secret names and keys, load
balancer, target groups, listeners, rule sets, subnets, databases, services
and the DNS record (the task and execution policies are deferred to apply in
a plan and were checked by reading); `testidpna`'s two cells in both phases
and its global stack rendered the contract above, the replica in cac1, the
routes both ways and the zone associations.

If the first apply fails, look first at: an AccessDenied on the ACCEPTER
side's `vpc/…` in `CreateVpcPeeringConnection` (the tag condition on a VPC in
another region — narrow it to `ec2:AccepterVpc`, keeping the requester's
tag); a Cloud Map `CreatePrivateDnsNamespace` AccessDenied naming a Route 53
or EC2 action the namespace needs on the caller's behalf; a cac1 task that
cannot pull its image because replication had not finished (ECS retries;
the primary cell is applied first for exactly this); and the global replica
taking longer than the four-hour deployer session allows on a first build.

## Running the suite from this machine: `run-suite.sh` (2026-09-18)

**rcbj's design, asked for against `testidp` and written for any environment:**
the suite runs from a developer's machine and hits the load balancer's
listeners, IN WHATEVER MODE THE ENVIRONMENT RUNS — `testidp` is product mode,
and making the suite pass there is part of the standard suite, not a special
case. Nothing about an environment is written into the script; it reads the
environment's outputs through `terraform-local.sh … output-json`.

```bash
deploy/aws/run-suite.sh testidp       # this machine must be in allowed_cidrs
```

1. It builds the tests image from the WORKING TREE, and from it `runner-<tag>`
   and `pep-<tag>` (the tag is HEAD plus a digest of what is not committed),
   and pushes those two.
2. It applies `suite-callbacks/` in the background, runs every other job in
   the tests image on this machine's network into
   `tests/report/aws-<env>/`, then runs the callback task once, downloads its
   report and merges it in (`tests/tools/merge-report.js`, which redraws the
   report with `run-report.js`'s own writers), and destroys the stack from an
   EXIT trap.

**THE TWO CALLBACK JOBS RUN IN AWS, AND WHY THAT IS THE WHOLE DESIGN.**
`sts_xacml_remote_pep` needs a PEP container the PDP nudges, and writes that
PEP's listener certificate into a directory the container reads — so the job
runs in the same task as the PEP. `sts_gnap_core` opens a listener the service
POSTs a GNAP push to. A machine behind NAT cannot be dialled, so both run in a
task inside the VPC that exists for one run: a NAT gateway (~$0.05/h, a few
minutes to create and destroy) and nothing that bills afterwards. It is
`environment/runner.tf` re-homed in a stack of its own, reading everything the
environment built by name; its subnet is the VPC's /24 number 21 so an
environment with its own runner does not collide. **A destroy that fails is
said loudly** — the NAT gateway bills until
`TF_STACK=suite-callbacks deploy/aws/terraform-local.sh <env> destroy` runs.
`STS_SUITE_CALLBACKS=0` skips that half.

It is the one suite for every environment since 2026-09-21: `run-suite-in-aws.sh`
and `environment/runner.tf`, which `aws-cluster.yml` used for `dev` and `ci`,
were deleted that day.

**OR THE WHOLE SUITE IN THE TASK: `STS_SUITE_IN_AWS=1` (#311, 2026-09-28).**
rcbj's call, the reverse of the design above for a long run: from a machine
on the internet a full run takes most of a day, one fresh TLS connection per
request. With it set nothing runs locally; the callback task (sized 4 vCPU /
16 GiB for Chrome and the bulk loads) runs every job, resets the previous
run's realms itself, and its report is the run's
(`tests/report/aws-<env>/latest`). The task may run eight hours
(`STS_SUITE_TASK_TIMEOUT_SECS`).

```bash
STS_SUITE_IN_AWS=1 ./run-tests.sh --target=aws:testidp
```

**What still cannot run there, and says so rather than failing:** the jobs
whose peer is a container the local stack brings up beside the service and
shares a volume with — the mail catcher (`sts_mail`), the outbound test CA
(#171), the OpenID conformance suite and the four SAML peers — and SPIFFE
unless its realm stack is applied and named (`STS_SPIFFE_WORKLOAD_URL`). Each
reads its variable as empty and reports itself skipped with the reason.

## A realm's SPIFFE ports: the default realm's in `environment/`, any other realm's in `spiffe-realm/`

**THE DEFAULT REALM'S TWO PORTS ARE PART OF EVERY ENVIRONMENT (#311,
2026-09-28, rcbj): not optional and not a separate stack.**
`environment/spiffe_default.tf` publishes 8092 (Workload API) and 8181 (SPIRE
Server API) — `spiffe_workload_port` / `spiffe_server_port` — with the same
address registration, rules and caveats as below, and outputs
`spiffe_default_ports`, which `run-suite.sh` reads to count SPIFFE as
published. Until that date it was `spiffe-realm/` with `REALM=default`, and a
build nobody applied it to skipped both SPIFFE jobs. **`spiffe-realm/` is for
ADDITIONAL realms only and refuses `default`** (a resource precondition, so an
old `REALM=default` state still destroys).

`spiffe-realm/` publishes ONE additional realm's two gRPC ports, the same
number outside and inside, and is applied once per realm, after the realm
exists and after `environment/`:

```bash
TF_STACK=spiffe-realm REALM=acme WORKLOAD_PORT=9092 SERVER_PORT=9181 \
  deploy/aws/terraform-local.sh testidp apply
TF_STACK=spiffe-realm REALM=acme deploy/aws/terraform-local.sh testidp destroy
```

**A REALM GETS PORTS OF ITS OWN HERE, NOT AN ADDRESS.** `spiffe/CLAUDE.md`
tells realms apart by address and keeps 8092 / 8181; a Fargate task has one
address, so every realm binds `0.0.0.0` on ports of its own, which the
service allows (`claimedBy()` compares host and port). **Terraform does not
configure the realm**: it must be given `spiffe.enabled` on and
`spiffe.workloadPort` / `spiffe.serverPort` set to the SAME two numbers, in
the console or through `/admin-api` — a realm is created with SPIFFE off and
both ports 0 (`common/realms.js`). The `realm_settings` output repeats them.
Until the realm has them, its target groups show every node unhealthy. The
stack refuses a port the environment already uses (80, 88, 389, 443, 636,
8081, 8082, the debugger's 8444) and, for any realm but `default`, 8092 and
8181.

**THE NODES ARE REGISTERED BY ADDRESS, AND A RESTARTED TASK FALLS OUT.** ECS
keeps a target group's members current only for the target groups on a
service's `load_balancer` blocks, and **ECS allows five per service — which
`testidp` already uses** (https, ldap, ldaps, pki, kerberos). So this stack
looks up the nodes' current private addresses (the in-use interfaces
carrying `<prefix>-nodes`) and registers them itself. **Re-apply every
realm's stack after any deploy or task restart**; until then the restarted
node is missing from these ports, and its old address fails health checks.
rcbj chose this over a Lambda following ECS task events, which the deployer
role cannot create.

**No PROXY protocol on these target groups**, unlike every other port:
SPIFFE's gRPC listeners do not read the header, and a header in front of gRPC
or TLS breaks the connection. The node sees the load balancer as the caller.

**THE WORKLOAD API PORT IS NOT SERVED HERE, AND THAT IS #166 WORKING.** The
nodes run in product mode, where the Workload API is bound over TCP only when
`spiffe.workloadTcpSourceAuthenticated` declares that the network
authenticates source addresses (SPIFFE Workload Endpoint section 3), and even
then never on a wildcard `spiffe.grpcHost` — and a Fargate realm binds
`0.0.0.0`, behind a load balancer whose address is every caller's `peer:`.
Neither condition can be met honestly on this network, so the workload
target group stays unhealthy and `sts_spiffe_grpc.js` asserts the refusal
instead (`GET /spiffe`'s `workloadAttestation.tcp` says `not served`). The
SPIRE Server API port, which is mutual TLS, is unaffected.
**Who may connect is copied from the environment's 443 rules**, so these
ports are exactly as open as the main port; a new `allowed_ip` on the
environment reaches them at this stack's next apply. Target groups are named
`<prefix>-sp-<port>`, since a realm id can be 31 characters.

**EVERY REALM'S STACK COMES DOWN BEFORE THE ENVIRONMENT, AND SINCE
2026-09-21 THE ENTRYPOINT DOES IT** (`destroy_dependent_stacks()`). Its
security-group rules cross-reference the environment's two groups, and a
group that another group's rule still names cannot be deleted — the rules
belong to THIS state, so the environment's Terraform cannot see them and
does not remove them.

**The day the order was not enforced cost 33 minutes and left the
environment standing: `testidp`, 2026-09-20.** The workflow destroyed
everything else, then spent fifteen minutes per group watching
`DeleteSecurityGroup` answer `DependencyViolation` — the default realm's
8092 and 8181 rules — retried once on the entrypoint's own rule, failed the
same way, and stopped with both groups, the VPC and this stack's state still
there. Re-running it could not help: the second run had the first run's
blind spot. The remains were removed by hand on 2026-09-21.

**An `environment` destroy now enumerates the dependent stacks from their
STATE KEYS and destroys each one first** — every
`environment/<env>/spiffe-realm/*.tfstate` and
`environment/<env>/suite-callbacks.tfstate` — so nothing has to be told
which realms an environment was given, and a dependent that will not destroy
stops the environment's destroy instead of being discovered afterwards. It
runs while the environment still EXISTS, which this stack requires: it reads
the environment's remote state and finds the load balancer by name.

## The deployer's permissions, and how to extend them

`foundation/iam_deployer.tf`'s header is the argument: names where ARNs are
predictable, the `Project = STS` tag where they are not (EC2), a permissions
boundary on every role the deployer creates, and the regions in
`permitted_regions` — one, us-west-2, until an environment has cells (*Cells*,
above). **A missing action
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
  profile, no groups, one inline policy `assume-iya-sts-deployer`, and the role
  trusts it by name (`foundation/iam_deployer.tf`, `ci_user_name`). It is a
  SECOND principal of the role beside `iya-sts-deployer`, a person's, so either
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
terraform -chdir=deploy/aws/foundation init -backend-config=bucket=iya-sts-terraform-state-<account>
terraform -chdir=deploy/aws/foundation apply          # once, administrator

# as the deployer role, from here on
docker build -t <repo>:<tag> --build-arg STS_CLOUD_SDKS="@aws-sdk/client-secrets-manager @aws-sdk/client-sesv2" \
  --build-arg STS_DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem .
docker build -t <repo>:schema-<tag> -f deploy/aws/schema-init/Dockerfile .
docker build -t <repo>:cert-<tag> -f deploy/aws/cert-init/Dockerfile .   # only with a public name
# push both (run-suite.sh builds and pushes the tests, runner and PEP images)
terraform -chdir=deploy/aws/environment init -backend-config=bucket=… -backend-config=key=environment/dev.tfstate
terraform -chdir=deploy/aws/environment apply -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
./run-tests.sh --target=aws:dev         # every job, from here

# or the same through the container, with nothing installed but docker:
IMAGE_TAG=<tag> deploy/aws/terraform-local.sh dev apply
deploy/aws/terraform-local.sh dev destroy
terraform -chdir=deploy/aws/environment destroy -var environment=dev -var image_tag=<tag> \
  -var 'allowed_cidrs=["<your ip>/32"]'
```
