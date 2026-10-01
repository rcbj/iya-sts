# deploy/multicloud/

**One environment, six cells, two clouds, one public name (#97, 2026-09-30).**
`testidpmc` is the #98 cell design stretched across AWS and GCP: three
jurisdictions, each with one AWS cell and one GCP cell in the same metro,
behind one set of geographic routing records. Nothing here runs inside the
service; the image build removes `deploy/`.

**WRITTEN AND CHECKED, NEVER APPLIED, BY rcbj'S INSTRUCTION.** No stack was
planned against a cloud and no image was built. The checks:
- `terraform fmt -check` and `validate` in every stack touched.
- `bash -n` on every script.
- Offline `terraform test` renders with mocked providers of three stacks, each read by eye:
  - a GCP cell in both phases (its cloud-init, units and environment);
  - the AWS primary cell (its peers, the DNS gating, the publication env);
  - the interconnect over six mocked cell states (records, VPN, BGP).
- **The replication SQL, run for real.** `deploy/aws/schema-init/apply.sh` ran against two throwaway PostgreSQL 18 containers: publisher, subscriber, a replicated row, the read-only application role, and an idempotent re-run.

  That run found and fixed one bug: a plain server needs the `REPLICATION` attribute, where RDS uses the `rds_replication` grant. The renders found another, in the GCP cell's outputs.

## rcbj's decisions (2026-09-30)

| Question | Answer |
|---|---|
| Jurisdictions | **us, eu, sg**. Each has an AWS cell and a GCP cell in the same metro |
| How GCP cells get the global tier | **A Cloud SQL logical replica per GCP cell**, subscribed to the RDS writer |
| How the clouds connect | **HA VPN per jurisdiction pair** |
| Scope | **Implement; do not apply** |

| Jurisdiction | AWS cell | GCP cell | Pinned countries |
|---|---|---|---|
| us | `usw2` us-west-2, **the primary: global writer** | `gusw1` us-west1 (The Dalles, Oregon) | none: reached through the default |
| eu | `euc1` eu-central-1 | `geuw3` europe-west3 (Frankfurt) | the EU and the EEA (30) |
| sg | `apse1` ap-southeast-1 | `gase1` asia-southeast1 (Singapore) | `SG` |

**`envs/testidpmc.cells.tfvars.json` is the one description of the
environment**: its `cells`, `primary_cell`, and #367's `jurisdictions` —
the countries pinned to each jurisdiction, which were a cell's until #367
and are read here only by the interconnect's Route 53 tree. Every stack of it reads that file: both clouds' cells, AWS's
`global/`, both stacks here, and the GCP foundation. JSON, as #98's is, so
jq and Terraform read the same bytes. `envs/testidpmc.aws.tfvars` and
`envs/testidpmc.gcp.tfvars` hold what each cloud's cells share, and their
must-agree settings (mode, public base URL, names) are the same.

## The pattern for geographic routing across clouds

**It is DNS-level global traffic management, answered by the authoritative
DNS, and AWS keeps `iyasec.io`.** So Route 53 answers for all six cells
(`interconnect/routing.tf`):

```
test-idp.iyasec.io           GEOLOCATION
  each pinned country    →   <jurisdiction>.cells.test-idp.iyasec.io
  default (*)            →   cells.test-idp.iyasec.io
<j>.cells.test-idp…          GEOPROXIMITY over the jurisdiction's two cells, each health-checked
cells.test-idp…              GEOPROXIMITY over all six, each health-checked
<cell>.test-idp…             one A/alias per cell: its own console (#361)
```

**Why geoproximity rather than #98's latency routing.** Route 53's latency
routing knows only AWS regions. Geoproximity places a non-AWS endpoint by
**latitude and longitude**, as an ordinary record without a Traffic Flow
policy: AWS cells by `aws_region`, GCP cells by the `coordinates` in the
cells file.

**The alternatives, and why each was refused:**
- **GCP's global load balancer in front of both clouds** (hybrid endpoints).
  It proxies TCP, so the PROXY-less client certificate path and the raw LDAP
  and Kerberos ports suffer.
- **A third-party GTM** (Cloudflare, NS1). It would take the zone away from
  AWS, which rcbj ruled out.
- **Anycast.** Neither cloud offers it across the other.

**A pinned country now fails over, across clouds and inside its
jurisdiction.** #98's pin had no health check, because its only other answer
was the default, which leaves the jurisdiction.
- Here a pin answers the jurisdiction's own two-cell set. If one cloud's cell
  is down the other answers.
- If both are down, Route 53 answers both (a set with nothing healthy
  answers as if all were), and never a cell elsewhere.
- The geolocation record does not evaluate its target, so it cannot fall
  through to the default (issue #98, D6: fail closed).

**The GCP cells' health checks** are by address: HTTPS `/healthcheck` on
443, from the AWS cells' three checker regions. The GCP firewall admits those
checkers' ranges on 443, to the load balancers only.

**Certificates for one name in two clouds.**
- The AWS cells keep their exportable ACM certificate (validated by
  `_<hash>.<name>`).
- The GCP cells get an ACME one from `deploy/gcp/node-init/cert.sh`, covering
  the shared name and the cell's console name. A DNS-01 challenge for a
  Route 53 name would need AWS credentials on a GCP node. It does not:
  `_acme-challenge.<name>` is a Route 53 CNAME into `gcp.iyasec.io` (ACME
  challenge delegation), which lego follows and writes with the VM's own
  rights.
- Three GCP cells validate the shared name. Each certificate carries a
  different set of names (its console name), so Let's Encrypt's five-a-week
  limit counts each separately.

## The network

**One HA VPN per jurisdiction pair** (`interconnect/modules/pair`). This is
Google's documented pattern for HA VPN to AWS:
- a GCP HA VPN gateway and a Cloud Router;
- on the AWS cell's VPC, a virtual private gateway, two customer gateways and
  two Site-to-Site connections;
- **four tunnels**, each with BGP, and the learned routes propagated into both
  of the cell's route tables.

Inside addresses and pre-shared keys are chosen here, so both sides can be
written from them:
- four /30s of `169.254.100.0/24` per pair;
- VGW ASN `64520+n`, GCP ASN `64600+n`.

**The three GCP cells share one global VPC**, made by the GCP foundation
(`deploy/gcp/foundation/network_multicell.tf`), with GLOBAL dynamic routing.
- A route one region's VPN learns reaches every GCP region. So each AWS
  cell's one VPN, to its metro partner, joins it to all three GCP cells.
- AWS↔AWS traffic stays on #98's peering, which is not transitive, and never
  needs to be.
- A VPC per GCP cell would have needed three VPNs per AWS cell, or a transit
  hub.

The Cloud Router advertises the GCP subnets, plus two things by hand:
- **the private-services ranges** of the Cloud SQL copies, which subscribe to
  the RDS writer;
- **`35.199.192.0/19`**, where Cloud DNS forwarding comes from.

**Inter-cell names (8446, `STS_CELL_PEERS`), across clouds:**

| Name of | Inside AWS | Inside GCP |
|---|---|---|
| an AWS cell | its Cloud Map namespace (#98), associated among the AWS VPCs | a Cloud DNS **forwarding** zone → that cell's **Route 53 Resolver inbound endpoint**, at `.53` of its first two private /24s |
| a GCP cell | a Route 53 private zone (this stack) → the cell's internal load balancer | a Cloud DNS private zone (the GCP foundation) → the same |

- **A GCP cell's 8446 is an internal passthrough load balancer with global
  access**, at `.5` of its first /24 (`deploy/gcp/environment/intercell.tf`).
  That is an address that survives node replacement, so the record is fixed
  and written before the cell exists. AWS could not do this (ECS's
  five-target-group limit); GCP has no such limit.
- **Each AWS cell's names forward to that cell's own resolver.** When its
  region is down its names do not matter, and no region depends on another's
  resolver.
- **Two formulas are written twice and must stay in step:** the ILB's `.5`
  (foundation and cell) and the resolver's `.53` (foundation and pair
  module).

## The global tier across clouds: logical replication

**The writer stays the one writer**: RDS, in `usw2` (issue #98, D3). The
AWS cells read physical RDS replicas, as before. **Each GCP cell reads a
Cloud SQL copy** that subscribes to the writer's publication, using
PostgreSQL's native logical replication. rcbj chose this over reading the
paired AWS replica across the VPN: a GCP cell keeps reading the global tier
when AWS is down.

- **The publisher** (`deploy/aws/schema-init/apply.sh`, run by the primary
  AWS cell's global-schema-init on every start):
  - creates the `sts_repl` role, with RDS's `rds_replication` grant, or the
    `REPLICATION` attribute on a plain server;
  - creates publication `sts_global` over **every table but `sts_schema`**,
    which each database seeds with its own row and whose copy would collide;
  - publishes a table a later schema adds at the next start.

  **Every table has a primary key** (checked 2026-09-30). That matters,
  because publishing a table without one makes its UPDATEs and DELETEs fail
  **on the writer**.
- **The writer's parameters** (`deploy/aws/global/database.tf`, only when the
  environment is multi-cloud):
  - `rds.logical_replication=1`;
  - `max_slot_wal_keep_size` (10 GiB). A copy that is down, or a GCP cell
    destroyed without dropping its subscription, invalidates its slot instead
    of filling the writer's disk.
  - PG18's `idle_replication_slot_timeout` is not set: its RDS spelling and
    units were not confirmed. Add it once they are.
- **The subscriber** (the same script, run by each GCP node's
  `sts-global-schema` unit):
  - applies the schema;
  - **revokes writes from `sts_app`** (a write to a logical replica is not
    refused, it silently forks the copy);
  - creates the subscription `sts_global_<cell>` if missing, first emptying
    the tables it will fill, so a subscription remade after a lost slot
    re-syncs cleanly;
  - otherwise re-points it and refreshes the publication.
- **DDL is not replicated.** A schema change reaches a GCP copy at that
  cell's next node start. Until then the apply worker errors and retries on
  a new column, and heals itself once the schema is there.
- **Connection security.** `sslmode=require`, not `verify-full`: a Cloud SQL
  instance cannot be given the RDS CA. The connection runs inside the IPsec
  VPN and is encrypted either way. **This is the one place a database
  connection here does not authenticate its server by certificate.**
- **Where the copies live.** On **private services access** (the GCP
  foundation's shared VPC), not PSC as a cell database is (#95). A PSC-only
  instance cannot dial out, and a subscriber must.
- **`replicaLagMs()`** (`persistence/persistence_postgres.js`) reads
  `pg_stat_subscription` on a logical copy. It read 0 there before, because
  a subscriber is not in recovery.

## The order (`entrypoint.sh`)

1. every AWS cell with no state, `base`, the primary first;
2. every GCP cell with no state, `base`, on the shared network;
3. **`interconnect`**: the VPNs, resolvers, names, challenge delegations and
   the Route 53 tree. It reads every cell;
4. **AWS `global/`**: the writer with its publication parameters, the AWS
   replicas and peering, the global secrets (and `global-db-repl-password`);
5. **`gcp-global`**: the global secrets copied into Secret Manager, and each
   GCP cell's Cloud SQL copy. **The global KEK among them stays a secret on
   GCP** (#391): `envs/<env>.gcp.tfvars` sets `kek_provider = "secret"`,
   because deploy/gcp's default is a Cloud KMS key an AWS cell cannot use,
   and every cell must name the same KEK — `deploy/gcp/environment/kek.tf`
   refuses `kms` in a cell;
6. every AWS cell `full`, the primary first (its global-schema-init makes the
   publication); then every GCP cell `full` (each subscribes).

**Destroy is the reverse:** interconnect, gcp-global, AWS global, then every
cell in `base`. `TF_STEP=<step>` runs one step alone: `aws-cell:<id>:<phase>`,
`gcp-cell:<id>:<phase>`, `interconnect`, `aws-global` or `gcp-global`.
**It refuses to apply while `testidpna` stands**: both answer
`test-idp.iyasec.io`.

## What each cloud's foundation must be re-applied with first

- **AWS** (`deploy/aws/foundation/`, an administrator):
  - `permitted_regions = ["us-west-2", "ca-central-1", "eu-central-1", "ap-southeast-1"]`.
    Keep `ca-central-1`: removing it would destroy testidpna's cac1 keys.
  - the new fifth deployer policy, `mock-sts-deploy-multicloud`: VPN, the
    Resolver inbound endpoint and its interfaces, and records only under
    `*.mock-sts.internal`.
  - **The one unscoped EC2 write in the deployer is
    `ec2:DeleteNetworkInterface`.** Resolver's interfaces are untagged, and an
    attached interface cannot be deleted.
- **GCP** (`deploy/gcp/foundation/`, an administrator), with
  `multicell_environments = ["testidpmc"]` (the default). It makes:
  - key rings in europe-west3 and asia-southeast1;
  - the three cells' service accounts and certificate secrets;
  - the shared VPC with private services access;
  - the private and forwarding zones;
  - and it enables `servicenetworking`.

**Images:** the three GCP images (service, `schema-`, `init-`) go to
Artifact Registry and the AWS ones to ECR, **under the same tag**.

## What it costs (estimated, not measured)

- **Six cells**: roughly three testidpna cells ($0.47–0.52/h each) and three
  GCP cells (~$0.39/h each), so **about $2.7 an hour**.
- **Three HA VPNs**: 12 GCP tunnels ($0.05/h each) and 6 AWS VPN connections
  ($0.05/h each), so **about $0.90/h**.
- **Three inbound resolvers**: 2 interfaces each, $0.125/h per interface,
  so **about $0.75/h**.
- **Three Cloud SQL copies**: **about $0.20/h**.
- **In all, about $4.5 an hour idle.** Cross-cloud transfer is billed on top
  (VPN egress, and the replication stream).

## What to look at first on the first apply

- **HA VPN interfaces at plan.** `aws_customer_gateway` reads the GCP
  gateway's interface addresses, which are unknown until it exists. If a
  plan refuses the index, apply `-target` the gateway first.
- **BGP.** `gcloud compute routers get-status mock-sts-testidpmc-<aws cell>-vpn`
  should show four sessions up. An AWS VGW advertises only its VPC CIDR.
- **Cloud DNS forwarding over the VPN.** It needs `35.199.192.0/19`
  advertised (done) and admitted by the resolver's security group (done).
  Check that the VGW routes it back through the private route table.
- **A PSA copy's `dns_name`.** The copy's certificate is issued by CAS and
  names the instance. If the API gives no `dns_name` for a PSA instance, the
  output falls back to the address and the node's name check will fail
  loudly.
- **The subscription** (`SELECT * FROM pg_stat_subscription` on a copy, and
  `pg_replication_slots` on the writer). If a slot shows `wal_status = lost`,
  run `DROP SUBSCRIPTION` on the copy; the next node start re-subscribes and
  re-syncs.
- **lego following the challenge CNAME** into `gcp.iyasec.io` with
  `GCE_ZONE_ID` pinned.
- **An AWS 403** naming an action of policy 5, or of the Resolver's interface
  calls.
