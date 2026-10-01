# deploy/gcp/

**The standard three-node iya-sts cluster on Google Cloud, built and destroyed
by Terraform (issue #95)** — `deploy/aws/`'s single-region pattern
(`deploy/aws/CLAUDE.md`), rebuilt out of GCP's parts. Nothing here runs inside
the service; the service image's build removes `deploy/` altogether.

**WRITTEN AND CHECKED STATICALLY ONLY, BY rcbj'S INSTRUCTION (2026-09-30):**
nothing was applied, no image was built and no plan ran against GCP. The
checks were `terraform fmt -check`, `init -backend=false` and `validate` in
all three stacks, `bash -n` on every script, and an offline `terraform test`
render of `environment/` with a mocked provider for `dev` and `testidp`
(the cloud-init and the six units a node gets, read by eye). The first apply
is its test; *What to look at first*, below, lists what is most likely to
need a change.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the GCS state bucket `iya-sts-terraform-state-<project>`, versioned | an administrator |
| `foundation/` | long-lived | the APIs, the KMS key ring and key (and the service agents' use of it), Artifact Registry `iya-sts`, the log bucket and sink, **the public zone `gcp.iyasec.io`**, the deployer service account, **one node service account per environment**, and **one certificate secret per environment with a public name** | an administrator |
| `dns-delegation/` | once | the NS record `gcp.iyasec.io` in **the Route 53 zone `iyasec.io`**, naming Cloud DNS's name servers | an administrator with AWS **and** GCP credentials |
| `environment/` | per run | VPC, firewall, passthrough network load balancer, Cloud SQL primary + replica behind a Private Service Connect endpoint, secrets, three zonal managed instance groups of one VM each, the public A record | the deployer (impersonated) |
| `environment/envs/<env>.tfvars` | per environment | what a named environment sets differently; `dev` and `ci` have none | the deployer |
| `environment/units/` | per run | the systemd units (and the disk script) cloud-init writes on every node | — |
| `node-init/` | per image | `sts-secrets` and `sts-cert`: Secret Manager → env files, and the ACME certificate | built by hand for now |
| `schema-init/` | per image | `postgres/schema.sql` against Cloud SQL — **AWS's `apply.sh`, not a copy** | built by hand for now |
| `Dockerfile`, `entrypoint.sh`, `terraform-local.sh` | per run | the Terraform image and its launcher, AWS's arrangement | a person |

## AWS keeps iyasec.io; GCP answers gcp.iyasec.io

**AWS manages the `iyasec.io` public zone and always will** (rcbj,
2026-09-30). GCP gets a sub-domain: `foundation/dns.tf` makes the Cloud DNS
zone `gcp.iyasec.io`, and `dns-delegation/` writes one NS record into Route
53 naming its four name servers — read from the zone, so the two cannot
disagree. Until that record exists nothing under `gcp.iyasec.io` resolves
from the internet and an ACME DNS-01 challenge fails.

`testidp` on GCP is therefore **`test-idp.gcp.iyasec.io`**. One name served by
both clouds is #97's question (below), and Route 53 is where it will be
answered.

**No DNSSEC**: it would need a DS record in the parent beside the NS record,
and the parent's signing is AWS's.

## What each AWS piece became, and why

| AWS | GCP | Why this and not the obvious alternative |
|---|---|---|
| ECS on Fargate, one service per AZ, desired count 1 | **One zonal managed instance group per zone, size 1**, on Container-Optimized OS; `node-a`'s group STABLE before the others are made | Cloud Run publishes HTTP(S) on one port and terminates TLS — no 389/636/88/gRPC, no client certificate. GKE publishes everything and is a cluster to keep. COS is kept current by Google, which is what Fargate bought. A group, not a bare VM, because it **autoheals** on `/healthcheck` as ECS replaced a task |
| Task definition: `cert-init`, `schema-init`, `iya-sts` | systemd units from cloud-init: `sts-disk` → `sts-registry` → `sts-secrets` → `sts-cert` → `sts-schema` → `sts-node` | `Requires=`/`After=` is `dependsOn: SUCCESS`: a node whose certificate or schema failed does not start |
| ECS `secrets` injection | `sts-secrets` reads Secret Manager into env files on `/run` (a tmpfs); the containers take them as `--env-file` | Nothing secret is ever in instance metadata, which anybody who can describe the VM reads. The KEK and the database password are still read by the SERVICE through `common/secrets.js`'s `gcp` provider — the path #51 exists to exercise |
| NLB, TCP passthrough, PROXY v2, client-IP preservation off | **Regional external passthrough NLB** (backend-service based), one static address, two forwarding rules | A passthrough NLB is not a connection endpoint at all — the node's TLS is the client's, so `GET /tls/sign-in` and RFC 8705 work. It **preserves the client's address and sends no PROXY header**, so the nodes run `STS_PROXY_PROTOCOL=off` and trust no proxy |
| 443 → 8081, 80 → 8082 on the NLB | **Docker publishes them** (`-p 443:8081`, `-p 80:8082`, the rest 1:1) | A passthrough load balancer does not translate ports |
| Five target groups, and the SPIFFE ports registered BY ADDRESS by hand | One backend service (the three instance groups); SPIFFE's 8092/8181 are a second forwarding rule on the same address | A forwarding rule takes five ports. **The register-by-address workaround and its "re-apply after every restart" are gone**: the backend follows its instances |
| A health check per target group | One HTTPS GET of `/healthcheck` on 443 | A backend service takes one. **A node whose LDAPS failed to bind stays in service**, where on AWS it failed to reach steady state; the failure is still on `GET /admin/ldap/service` |
| Three security groups | Firewall rules targeted by the nodes' SERVICE ACCOUNT: `allowed_cidrs` → the LB address on the published ports; Google's health-check ranges on 443; egress 443, 53 (only with a public name, for the ACME client's propagation check) and 5432 to the endpoint, everything else denied | The client's packets reach the node directly, so the rule AWS put on the NLB is on the nodes, with the LB's address as its DESTINATION — an allowed client can reach the published ports and not a node's own address. A service account rather than a tag, because a tag is set by anybody who can edit an instance |
| RDS PG18 primary + replica, `rds.force_ssl`, project key | **Cloud SQL PG18 primary + replica** in two zones, CMEK, `ssl_mode = ENCRYPTED_ONLY`, `GOOGLE_MANAGED_CAS_CA`, 14 daily backups with PITR | — |
| Private subnets | A **Private Service Connect endpoint** (the private subnet's `.10`) | Private services access peers the VPC with Google's through a `servicenetworking` connection that does not tear down cleanly, and an environment is destroyed often |
| The RDS CA bundle baked into the image | The instance's CA, written by cloud-init and read as `NODE_EXTRA_CA_CERTS`; the node dials the instance's `dns_name`, mapped to the endpoint with `--add-host` | The CA arrives with the instance, so ONE image serves every environment; `--add-host` needs no private DNS zone, which the deployer could not make without the right to delete zones |
| Secrets Manager `iya-sts/<env>/<key>`, recovery window 0 | Secret Manager `iya-sts-<env>-<key>`, CMEK, one region | A secret id may not hold `/`. Read the bootstrap password with `gcloud secrets versions access latest --secret=iya-sts-testidp-bootstrap-admin-password` |
| An **exportable** ACM certificate, exported by `cert-init` on every start | An **ACME certificate** (Let's Encrypt, DNS-01 in `gcp.iyasec.io`) kept in the **foundation's** secret `iya-sts-<env>-tls`; `node-a` issues or renews it, the others wait | *The certificate*, below |
| The private zone for the service calling its own name (#311) | **Nothing** | A passthrough LB's address is configured locally on every backend by the guest agent, so a node dialling its public name is answered by itself |
| EBS volume for risk uploads (#214) | A second persistent disk per VM (10 GiB, CMEK), mounted at the same container path, **emptied on every start** | A persistent disk survives a reboot where the EBS volume did not; emptying it keeps it temporary space |
| `awslogs`, a log group in foundation | Docker's `gcplogs` driver, a sink into a 14-day CMEK log bucket in foundation | Logs are project-wide, so they outlive the environment by construction |
| Deployer ROLE with two permissions boundaries, fenced by name, tag and region | Deployer SERVICE ACCOUNT, **impersonated** (no key), fenced by the PROJECT and by creating NO identity | *The deployer*, below |
| `host-credentials.js` | Nothing | The provider refreshes impersonated tokens itself; the expired-session lock cannot happen |

## The certificate

**Google releases the private key of no certificate it issues** —
Certificate Manager's certificates can be presented only by a Google load
balancer that terminates TLS, which is the arrangement AWS reversed on
2026-09-17 because then no client certificate reaches the node. So the
certificate is an ACME one and the node obtains it:

* `foundation/tls_secrets.tf` makes an EMPTY secret per environment with a
  public name. The key is in **no Terraform state**; only the node writes a
  version.
* `node-init/cert.sh`, on every start of every node: read the bundle (key,
  leaf, issuers); if it names the host and has more than `acme_renew_days`
  (30) left, write the two files `tls.certificateFile`/`tls.keyFile` read,
  and stop. Otherwise **node-a alone** runs lego against a DNS-01 challenge
  (its account holds `dns.admin` on the one zone), adds the new bundle as a
  version, **disables** the old ones, and writes it out; node-b and node-c
  wait for it (they start after node-a is stable, so normally it is there).
* **In the foundation, not the environment, because of Let's Encrypt's limit
  of five certificates a week for one name.** testidp is rebuilt many times a
  week; a certificate destroyed with each environment would run out.
* A renewal reaches a node at its next start, as on AWS. A node that cannot
  get the certificate does not start — a self-signed certificate under a
  public name would look healthy.
* `acme_server` can point at Let's Encrypt's STAGING directory to try a new
  environment without spending the limit (untrusted certificates). Google's
  own public CA speaks ACME too but needs External Account Binding; not wired.

## The deployer, and what is weaker than AWS

GCP has no permissions boundary and scopes almost nothing by name or label,
so `foundation/iam_deployer.tf` fences the deployer three other ways: **the
project** (every project role is bounded by it — so this deployment wants a
project of its own), **no identity creation** (the node accounts are made by
the foundation, one per entry in `environments`, and the deployer may only
attach its environment's — `iam.serviceAccountUser` on that account), and
**resource-level grants** where the resource exists first (`dns.admin` on the
one zone, object admin on the state bucket). **An environment the foundation
does not list cannot be applied**: its account does not exist. Adding one is
an administrator's re-apply, as a new `public_dns` name is on AWS.

**Two things are weaker than on AWS, and they are stated rather than hidden:**

* **One identity per VM.** ECS read a task's secrets as the EXECUTION role and
  ran the container as the TASK role, so the service could never read the
  database master password. Every container on a VM reaches the same metadata
  server, so the service here COULD read every secret of its environment.
  Closing it would mean blocking the service container from the metadata
  server, and the service reads its KEK through it.
* **`secretmanager.admin` reads every secret in the project**, the
  foundation's certificate keys included — the price of the deployer granting
  per-secret access at all. A dedicated project keeps "every secret" small.

## Cloud SQL's names and TLS

**An instance name carries a random suffix** (`iya-sts-<env>-primary-<hex>`):
Cloud SQL will not give a deleted instance's name to a new one for up to a
week, and an environment is rebuilt far more often.

**The node verifies the server by name.** Under `GOOGLE_MANAGED_CAS_CA` the
certificate names the instance's `dns_name`, with the root's trailing dot;
node's TLS strips a trailing dot on both sides, so `STS_DATABASE_URL` names
the host without it and verification passes. **libpq does not strip it**, so
schema-init's psql runs `verify-ca` (`schema_init_sslmode`) — the CA is still
verified, the name is not. `deploy/aws/schema-init/apply.sh` learned
`STS_SCHEMA_SSLMODE` for this (verify-full by default and nothing weaker than
verify-ca; AWS sets nothing and is unchanged).

## What was not ported, and why

* **`run-suite.sh` and `suite-callbacks/`.** The suite can be pointed at
  `service_url` like any environment, but the two callback jobs need a
  GCP task of their own. The outputs keep AWS's names where there is a
  counterpart so the port is mostly the callback stack.
* **Cells (`global/`, #98) on GCP alone.** This is the standard
  single-region pattern. **A GCP cell of a multi-cloud environment is this
  stack with `cell` set (#97)** — the shared network, a region's key, the
  inter-cell load balancer, the Cloud SQL copy of the global tier —
  `deploy/multicloud/CLAUDE.md` argues it; `cell` empty renders what is
  described above.
* **Mail.** GCP has no mail-sending service; the service's SMTP, ACS and Gmail
  transports can be configured through `extra_environment`.
* **`spiffe-realm/` for additional realms.** A realm's ports would be one more
  forwarding rule on the same backend service — no address registration.
* **A GitHub workflow.** It should authenticate with Workload Identity
  Federation and impersonate the deployer, not hold a key.

## With #96 (Azure) and #97 (multi-cloud load balancing) in view

* The layout — `foundation/`, `environment/`, `envs/`, a launcher and an
  init image — is the one an Azure stack can copy, and the environment
  outputs keep AWS's names (`service_url`, `public_hostname`, `secrets`,
  `load_balancer_ports`, `spiffe_default_ports`, `image_tag`) plus `lb_address`
  and `cloud = "gcp"`, so a script reading several clouds reads one set of
  keys.
* **Route 53 stays the only place `iyasec.io` is answered**, so #97's
  cross-cloud records (latency, weighted or failover over AWS's NLB and GCP's
  `lb_address`) go there. A name served by both clouds would need both
  clouds' nodes to present a certificate for it — AWS's exportable ACM
  certificate and GCP's ACME one would be two different certificates for one
  name, which is allowed; `cert.sh` would need the shared name as a second
  domain, validated in Route 53 rather than Cloud DNS.

## What it costs

Estimated from 2026 on-demand list prices in us-west1, not measured:

* `dev`/`ci`: three e2-medium (~$0.10/h), two `db-custom-1-3840` Cloud SQL
  instances (~$0.13/h), the forwarding rules and the PSC endpoint
  (~$0.035/h), four external IPv4 addresses (~$0.02/h) — **about $0.29 an
  hour idle**, before disks and backups.
* `testidp`: three e2-standard-2 (~$0.20/h) — **about $0.39 an hour**.
* Long-lived: the key (~$0.06/month per version), a public zone ($0.20/month),
  the log bucket and the registry by volume.

## What to look at first on the first apply

* **The CAS certificate's name.** If the node's database connection fails
  hostname verification, look at the server certificate's SANs
  (`openssl s_client -starttls postgres`) against `dns_name`.
  `--add-host` also assumes `dns_name` is populated for a PSC instance.
* **Docker's port mapping to the LB address.** A passthrough packet arrives
  for the forwarding rule's address, which the guest agent adds to the local
  routing table; Docker's DNAT matches `dst-type LOCAL`, so it should map.
  If health checks never pass, check `ip route show table local` on a node
  for the LB address.
* **COS and cloud-init.** The units assume cloud-init re-runs `write_files`
  and `runcmd` on every boot (COS's `/etc` is not kept), and that
  `docker-credential-gcr` writes under `HOME=/var/lib/sts`.
* **`wait_for_instances_status = "STABLE"`** is meant to wait through
  autohealing's verification; if node-b is made before node-a is healthy,
  the ordering needs a health wait of its own.
* **lego's `gcloud` provider** with `GCE_ZONE_ID` (so it needs no project-wide
  zone listing), and the egress rule on 53 for its propagation check.
* **A 403 naming a permission** on plan or apply: add the narrowest role that
  has it in `foundation/iam_deployer.tf`, and an administrator re-applies.

## Running it by hand (NOT YET RUN)

```bash
GOOGLE_CLOUD_PROJECT=<project> deploy/gcp/bootstrap-state.sh           # once, administrator
terraform -chdir=deploy/gcp/foundation init -backend-config=bucket=iya-sts-terraform-state-<project>
terraform -chdir=deploy/gcp/foundation apply -var project_id=<project> \
  -var 'deployer_members=["user:<you>"]'                                # once, administrator
terraform -chdir=deploy/gcp/dns-delegation init -backend-config=bucket=iya-sts-terraform-state-<project>
terraform -chdir=deploy/gcp/dns-delegation apply -var project_id=<project>   # AWS + GCP credentials

# the three images, from the repository root
R=us-west1-docker.pkg.dev/<project>/iya-sts/iya-sts
docker build -t $R:<tag> --build-arg STS_CLOUD_SDKS="@google-cloud/secret-manager" .
docker build -t $R:schema-<tag> -f deploy/gcp/schema-init/Dockerfile .
docker build -t $R:init-<tag> -f deploy/gcp/node-init/Dockerfile .
gcloud auth print-access-token --impersonate-service-account=iya-sts-deployer@<project>.iam.gserviceaccount.com |
  docker login -u oauth2accesstoken --password-stdin us-west1-docker.pkg.dev
docker push $R:<tag>; docker push $R:schema-<tag>; docker push $R:init-<tag>

# as the deployer, from here on
GOOGLE_CLOUD_PROJECT=<project> IMAGE_TAG=<tag> deploy/gcp/terraform-local.sh dev apply
GOOGLE_CLOUD_PROJECT=<project> deploy/gcp/terraform-local.sh dev destroy
```

**The service image is built WITHOUT `STS_DATABASE_CA_URL`**: the Cloud SQL
CA is per instance and arrives on the VM (above).
