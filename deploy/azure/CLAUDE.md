# deploy/azure/

**The standard iya-sts cluster on Azure, in one, two and three regions, built
and destroyed by Terraform (issue #96).** It combines `deploy/gcp/`'s
single-region pattern (`deploy/gcp/CLAUDE.md`) and `deploy/aws/`'s cells
(#98, #367; `deploy/aws/CLAUDE.md`, *Cells*), built from Azure's parts.
Nothing here runs inside the service; the service image's build removes
`deploy/` altogether.

**WRITTEN AND CHECKED STATICALLY ONLY (2026-09-30):** nothing was applied,
no service image was built, and no plan ran against Azure. The checks were:

* `terraform fmt -check`, `init -backend=false` and `validate` in all four
  stacks;
* `bash -n` and shellcheck on every script;
* an offline `terraform test` of `foundation/`, `environment/` and `global/`
  against a MOCKED azurerm provider (`*/tests/render.tftest.hcl`), which
  applies to the mock:
  * `dev`, `testidp`, a `testidpna` cell in each phase, and a `globalidp`
    cell;
  * both multi-region `global` stacks;
  * the foundation over all five environments;
* every node's cloud-init, units and environment rendered to files from those
  runs and read by eye; the two rendered scripts pass shellcheck;
* the Terraform image built;
* `postgres:18` confirmed to carry, once `ca-certificates` is installed, the
  two roots the schema image names.

The first apply is the real test. *What to look at first*, below, lists what
is most likely to need a change.

| Path | Lifetime | What it is | Applied by |
|---|---|---|---|
| `bootstrap-state.sh` | once | the state resource group, the account `iyaststate<subscription>` (shared keys off, versioned, soft delete) and its `tfstate` container | an administrator |
| `foundation/` | long-lived | per region (`modules/region`): a key vault with the two customer-managed keys, a disk-encryption set per key, the PostgreSQL key identity, a Log Analytics workspace and its syslog rule. Once: the registry (Premium, geo-replicated), **the public zone `azure.iyasec.io`**, and the deployer's custom role. **Per environment, and per cell:** a resource group with *Allowed locations* on it, the nodes' managed identity, the Key Vault its secrets and certificate are in, and every grant. **The key-encryption key** (`kek.tf`, #391): one per environment, and a multi-region environment's global vault for it | an administrator |
| `dns-delegation/` | once | the NS record `azure.iyasec.io` in **the Route 53 zone `iyasec.io`** | an administrator with AWS **and** Azure credentials |
| `environment/` | per run | one environment, or one CELL of a multi-region one: VNet, security groups, Standard Load Balancer, PostgreSQL primary + replica behind a private endpoint, secrets, three zonal scale sets of one VM each, the public record | the deployer |
| `global/` | per run | a multi-region environment's global tier and joins: the global writer and a replica per other cell, the VNet peering mesh, the shared secrets in every cell's vault, Traffic Manager | the deployer |
| `environment/envs/<env>.tfvars` | per environment | what a named environment sets differently; `dev` and `ci` have none | the deployer |
| `environment/envs/<env>.cells.tfvars.json` | per environment | a multi-region environment's cells, pinned countries, primary cell **and public name**, read by the foundation, every cell and `global/` | — |
| `environment/units/` | per run | the systemd units and scripts cloud-init writes on every node | — |
| `node-init/` | per image | `sts-secrets` and `sts-cert`: Key Vault → env files, and the ACME certificate | built by hand for now |
| `schema-init/` | per image | `postgres/schema.sql` against Flexible Server — **AWS's `apply.sh`, not a copy** | built by hand for now |
| `Dockerfile`, `entrypoint.sh`, `terraform-local.sh` | per run | the Terraform image and its launcher; the entrypoint orders a multi-region environment's stacks | a person |

## The three environments

| Environment | Regions | Name | Cells file |
|---|---|---|---|
| `testidp` — **one region** | westus2 | `test-idp.azure.iyasec.io` | none |
| `testidpna` — **two regions** | `zwus2` westus2 (`us`, **primary**), `zcnc` canadacentral (`ca`, `CA` pinned) | `na-idp.azure.iyasec.io` | `testidpna.cells.tfvars.json` |
| `globalidp` — **three regions** | `zwus2` westus2 (`us`, **primary**), `zgwc` germanywestcentral (`eu`, the EU 27 and IS, LI, NO pinned), `zsea` southeastasia (`sg`, `SG` pinned) | `global-idp.azure.iyasec.io` | `globalidp.cells.tfvars.json` |

They mirror AWS's `testidpna` and #97's us/eu/sg choice, and use AWS's names
for the environments. **Each has a name of its own**, so, unlike AWS's
`testidp` and `testidpna`, all three can stand at once. `dev` and `ci` are
single-region with no name, as on AWS and GCP. Two regions or three is only a
cells file: a new N-region environment is a JSON file and a line in the
foundation's `environments`.

**An Azure cell's id is `z` plus its region's short code**: westus2 is
`zwus2`, germanywestcentral `zgwc`, southeastasia `zsea`. Azure region names
have no shape a rule can shorten (AWS's us-west-2 is `usw2` by rule, #367), so
the codes are a TABLE, `region_codes`, taken from Microsoft's naming
abbreviations. `g` is GCP's prefix (#97) and `a…` would read as AWS's `ap-*`.
**The table is in three places**: `foundation/locals.tf`,
`environment/cells.tf` and `global/main.tf`, because one stack cannot read
another's locals. Keep them in step; adding a region is a row in each.

## AWS keeps iyasec.io; Azure answers azure.iyasec.io

This is GCP's arrangement (#95), and rcbj's standing rule. `foundation/`
makes the Azure DNS zone `azure.iyasec.io`, and `dns-delegation/` writes the
one NS record into Route 53, reading the name servers from the zone so the
two cannot disagree. Until that record exists, nothing under
`azure.iyasec.io` resolves and an ACME challenge fails. There is no DNSSEC,
for GCP's reason.

## What each piece became, and why

| AWS | GCP | Azure | Why this and not the obvious alternative |
|---|---|---|---|
| ECS on Fargate, a service per AZ | a zonal MIG per zone, COS | **A Flexible scale set per zone with one instance, Ubuntu 24.04 LTS, Docker from Ubuntu's archive**. `node-a`'s is made first. | Container Apps proxies what it publishes. Container Instances has no zonal load-balanced service that follows its instances. Neither gives 389/636/88/gRPC plus a client certificate at the node. AKS is a cluster to keep. Ubuntu's unattended-upgrades is the nearest thing to COS. A scale set rather than a bare VM because it **repairs**: the Application Health extension asks `/healthcheck`, and a failing node is replaced after `PT30M`. |
| task definition | systemd units | **The same units**, in order: `sts-disk` → `sts-registry` → `sts-secrets` → `sts-cert` → `sts-schema` (→ `sts-global-schema` in the primary cell) → `sts-node`. `sts-node` is enabled, so a reboot starts it again. | `Requires=`/`After=` is `dependsOn: SUCCESS` |
| ECS `secrets` | `sts-secrets` from Secret Manager | `sts-secrets` from **Key Vault** over REST with the VM's managed identity, into env files on `/run` | Nothing secret is in the VM's model. The database passwords are read by the SERVICE through `common/secrets.js`'s `azure` provider (`AZURE_CLIENT_ID` names the identity), and the KEK is a Key Vault KEY it wraps with (`azure-keys`, *The key-encryption key*, below) |
| ECR pull | `docker-credential-gcr` | `/etc/sts/registry-login.sh`: an Entra ID token from the metadata endpoint, exchanged at the registry. It runs before every start of the node. | The registry's token lasts about three hours, and systemd restarts the node long after boot |
| NLB, PROXY v2 | passthrough NLB, no PROXY | **Standard Load Balancer**: one zone-redundant public address, one rule per port translating 443 → 8081 and 80 → 8082, one HTTPS probe of `/healthcheck` | A pass-through: the client's certificate and address reach the node, so `STS_PROXY_PROTOCOL=off`. **No register-by-address workaround for SPIFFE**: the pool follows the scale sets |
| NAT-free public subnets | an ephemeral external IP per VM | **The load balancer's outbound rule**, on a second address; the nodes have NO public address, and the subnet's default outbound access is off | New VNets have no default outbound access (since 2025-09-30), and a NAT gateway is zonal. The fixed outbound address is also what the service calling its own public name arrives from |
| security groups | firewall rules by service account | **Two security groups** (nodes, private). Every rule is a resource of its own, and everything is denied at 4096 in both directions | A group's inline rules are its WHOLE list, so the global stack's rule would be deleted by the next cell apply. The deny rules sit ahead of Azure's defaults, which admit every peered VNet |
| #311's private zone for self-calls | nothing | **An inbound rule for the outbound address** (`self`, and `cells-self` from the global stack for every cell's) | The node's packet leaves by the outbound rule and comes back through the public frontend |
| RDS primary + replica | Cloud SQL + PSC endpoint | **Flexible Server 18, primary + a read replica in another zone**, CMK, `require_secure_transport`, 14 days of backups (not geo-redundant). A **private endpoint at a fixed address** (`.10` of the private subnet), which the node dials by the server's own name with `--add-host` | No VNet integration: a delegated subnet refuses to delete when a teardown runs out of order. No private DNS zone. **The certificate chains to a public root**, so node's own trust store verifies it and schema-init runs `verify-full`, unlike GCP |
| Secrets Manager `iya-sts/<env>/<key>` | Secret Manager `iya-sts-<env>-<key>` | **The environment's Key Vault** (the foundation's `ms<env><cell>-<hash>`), a secret per key: `kek`, `db-app-password`, … | *The vault*, below |
| an exportable ACM certificate | ACME in a foundation secret | **ACME** (Let's Encrypt, DNS-01 in `azure.iyasec.io` through lego's `azuredns` provider and the node's identity), in the vault's `tls` secret | *The certificate*, below |
| EBS for risk uploads | a second persistent disk | a data disk at LUN 0 (CMK), **emptied on every start** | GCP's argument |
| `awslogs` | `gcplogs` | Docker's `journald` driver → rsyslog → **the Azure Monitor agent → the REGION's workspace** | A log is personal data (#98). The data collection rule must be in its workspace's region |
| a project key / cell keys per region | a key ring per region | **A key vault per region** with `iya-sts` (single-cell and the global tier) and `iya-sts-cell` (a cell's own data), both purge-protected | A key is regional and never replicated, which is the residency line. The global tier needs no multi-region key here: a cross-region replica uses its own region's key |
| ECR, replicated | Artifact Registry | **ACR Premium, geo-replicated** into every region an environment uses | Premium is the tier that replicates. Nodes pull from their own region |
| the deployer role and its boundaries | an impersonated SA | **A custom role granted only on the foundation's resource groups** | *The deployer*, below |

## The vault, and why it belongs to the foundation

**A Key Vault's name is global, and a deleted vault keeps it (soft-delete) for
its retention period.** An environment that made its own vault each build
would find the name taken on the next one. So the foundation makes each
environment's vault, one per cell in a multi-region environment, once. The
environment writes its secrets into it.

A destroy deletes those secrets. They are soft-deleted for the vault's seven
days, and the next build **recovers** each by name and writes its new value
as a new version (the provider's `recover_soft_deleted_secrets`). Nothing is
purged. The vault's name is a formula of the subscription, environment and
cell, repeated in `environment/locals.tf` and `global/main.tf`, so no stack
reads the foundation's state.

## The key-encryption key: a Key Vault KEY, never its bytes (#391)

The service seals every value under a data encryption key and wraps each
data key under the KEK. **By default the KEK is a Key Vault key the service
never sees**: `STS_KEYS_KEK_PROVIDER=azure-keys`, `STS_KEYS_KEK_VAULT` the
vault, `STS_KEYS_KEK_REF` the key, and the vault wraps and unwraps each data
key (RSA-OAEP-256) through the node's managed identity, once per data key at
start. `foundation/kek.tf` and `environment/kek.tf` argue it in full.

* **The variables** (`environment/`):
  * `kek_provider`: `kms` (the default; the rule is most secure by default)
    or `secret`, the `kek` secret read into the service through the `azure`
    provider, as before #391. Anything else is refused.
  * `kek_migrating_from_secret` (default false, needs `kms`): also names the
    `kek` secret as `STS_PREVIOUS_KEK_*`.
* **The key is the FOUNDATION's**, not beside the `kek` secret: the deployer
  holds nothing on keys and assigns no role, and a node needs a role on the
  key. `kek-rsa`, RSA 3072, `key_opts` exactly `wrapKey` and `unwrapKey`.
* **Where:** a single-cell environment's own vault. A multi-region
  environment has **ONE key, in a vault of its own** (`ms<env>g-<hash>`, in
  the global group). The service stores `<vault>/keys/<name>` and the version
  in every wrapped row and refuses a row naming another, so every node of
  every cell names the identical URI (without Key Vault's trailing slash) and
  name. A vault of its own rather than the primary cell's because the service
  reads the global database password (which has no vault setting) from the
  KEK's vault: the global vault holds a copy of `global-db-app-password`,
  every cell's nodes may read its secrets, and no cell can read another's
  `cell-kek`. With `kms`, `STS_DATABASE_PASSWORD_VAULT` names the unit's own
  vault (set in both modes).
* **What a multi-region environment gives up:** a starting node in any cell
  dials the primary region's vault. Key Vault's failover to the paired region
  keeps wrap and unwrap working once Microsoft fails it over, which is not
  instant. The `kek` secret was copied into every cell.
* **The role:** *Key Vault Crypto User* for each unit's node identity,
  **scoped to the key** (`resource_versionless_id`), not the vault. It is
  wider than needed: `keys/update` (a node could disable the key, which is an
  outage, not a disclosure) and `keys/backup`. **It lacks
  `keyrotationpolicies/read`**, so `/admin/secrets` shows an error where the
  rotation policy would be; the key itself is reported. A custom role (read,
  wrap, unwrap, rotation-policy read) would be exact.
* **Rotation is a policy:** a new version a year after the last, each
  version expiring after two years, with notice 30 days before. The service
  re-wraps, at its next start, any data key wrapped under a version that is
  not current, so old versions must stay ENABLED until every node has
  restarted. Rotation disables nothing. An expired version still unwraps
  (Key Vault allows decrypt and unwrap outside the validity window). The
  current version never expires while rotation works.
* **Destroy and re-create:** the vaults soft-delete for 7 days and are not
  purge-protected. Within the 7 days a re-create RECOVERS the same key with
  every version. After that a re-create is a new key, and rows wrapped under
  the old one never open again. That is acceptable only because the
  environment's database goes with it.
* **The migration** from `secret` on an environment that holds data:
  1. Apply `kek_provider = "kms"` with `kek_migrating_from_secret = true`.
     Every node is replaced and re-wraps each data key from the secret to the
     key.
  2. Once every node of every cell has started, apply with `false`.

  The `kek` secret is still made in both modes: it is what the migration
  names, and it keeps the stacks' shape independent of the mode.
* **The cell key stays a SECRET** (`STS_CELL_KEK_*`, `cell-kek`): the service
  refuses a key management service for it.
* **RSA is not post-quantum.** An AES-256 `oct-HSM` key in a **Managed HSM**
  (or Key Vault Premium's oct-HSM, in preview) is stronger, and the service
  takes it (A256GCM, the row's binding as AAD). Nothing here builds one (a
  Managed HSM is about $3 an hour). To use an existing one, set
  `STS_KEYS_KEK_PROVIDER=azure-keys`, `STS_KEYS_KEK_VAULT=https://<hsm>.managedhsm.azure.net`
  and `STS_KEYS_KEK_REF=<key>` in `extra_environment`, and grant every node
  identity *Managed HSM Crypto User* on the key in the HSM's local RBAC.
* **The image needs `@azure/keyvault-keys`** beside `@azure/identity` in
  `STS_CLOUD_SDKS` (*Running it by hand*); without it the service refuses to
  start and names the package.

## The certificate

It is GCP's arrangement, argued in `deploy/gcp/CLAUDE.md`:

* **The certificate is ACME.** Azure's own certificate products issue names
  their own way and at a price.
* **It is kept in the foundation's vault.** Let's Encrypt allows five
  certificates a week for one set of names.
* **The foundation writes only a placeholder** (`not-issued`) and ignores
  every later value, so the key is in no Terraform state.
* **node-a alone issues.** Its identity holds a custom role that can write
  TXT records in the one zone and nothing else, which is narrower than GCP's
  `dns.admin`. It also holds Secrets Officer on the `tls` secret alone.

**In a multi-region environment each cell's node-a issues its own
certificate**, for the shared name and the cell's own (`<cell>.<name>`,
#361). The sets of names differ, so each cell has its own five a week. The
cells are applied one after another, not at once, because they share one
`_acme-challenge` TXT record set.

## The service image runs as uid 10001 (#254, 2026-10-06)

**The image's `USER` is `sts`, 10001:10001, and no longer root** (the root
`Dockerfile` argues it), so what the VM mounts into `iya-sts` is handed to
that user — `local.service_user`, spelt once in `environment/locals.tf`:

* **The upload disk**: `sts-disk.sh` chowns its mount point to it, still
  0700, after emptying it.
* **The TLS key**: `node-init/cert.sh` chowns `key.pem` (still 0400) and
  `certificate.pem` to `STS_TLS_OWNER`, which the `sts-cert` unit passes.
  The node-init image itself still runs as root.
* **The low ports**: `sts-node` passes
  `--sysctl net.ipv4.ip_unprivileged_port_start=0`, which Docker already
  sets in a bridged container; said so a daemon that did not fails loudly.
  Not `setcap` on node (a secure exec ignores `NODE_PATH` and
  `NODE_EXTRA_CA_CERTS`).

The database CA is a public one the image already trusts, so nothing is
mounted for it; the env files under `/etc/sts` and `/run/sts` stay root's
0600, because the Docker daemon reads them, not the container. **They put
every secret in the container's environment**, readable by anything that can
inspect the container or read its `/proc/1/environ`; that is unchanged here
and outside #254.

## The deployer, and what is weaker than AWS

Azure's natural fence is the RESOURCE GROUP, and `foundation/iam_deployer.tf`
builds on it:

1. **A custom role, granted only on the groups the foundation made.** There
   is no subscription-level grant.
2. **No identity and no role assignment.** The role holds no
   `Microsoft.Authorization/*/write` and no identity `write`. It may
   *attach* the identities made for it, and read a vault, never create one.
   This is GCP's rule, and the job AWS's boundaries do.
3. **The region fence** is Azure Policy's built-in *Allowed locations* on
   each group. A cell's group allows its own region; a global group allows
   every region of its cells. Global resources such as Traffic Manager and
   DNS records are exempt by the policy's definition.
4. **Resource-level grants for what is shared:**
   * DNS Zone Contributor on the zone;
   * AcrPush on the registry;
   * Secrets Officer on each environment's vault;
   * Managed Identity Operator on each region's PostgreSQL key identity;
   * blob data on the state container;
   * Reader on the foundation's groups, to FIND what it attaches.

**Who holds it:** `deployer_principal_ids`, preferably an Entra ID group.
There is no deployer credential. A person runs Terraform as themselves
(`az login`, handed to the container by `terraform-local.sh`), and the
provider refreshes the token, so AWS's expired-session lock cannot happen.
A workflow would be a service principal with a federated credential in the
same group; it is not built. **An environment the foundation does not list
cannot be applied**: its resource group does not exist.

**It is weaker than AWS in three places**, stated rather than hidden:

* **One identity per VM** (GCP's weakness). Every container on a node reaches
  the same metadata endpoint, so the service COULD read every secret in its
  vault, the master database password included.
* **The foundation's vaults and the registry accept public network access**
  (Entra ID and RBAC still apply). Denying it with the trusted-services
  bypass would suit the disks and databases, but it would also refuse an
  administrator's key creation from a laptop. It is the first hardening step
  for a real deployment, together with private endpoints for the vaults and a
  customer-managed key on the registry.
* **Key Vault replicates a vault's contents to its PAIRED region** for
  Microsoft's own disaster recovery:
  * westus2 ↔ westcentralus;
  * canadacentral ↔ canadaeast;
  * germanywestcentral ↔ germanynorth;
  * southeastasia ↔ eastasia (Hong Kong), which Microsoft documents as one of
    the regions whose Key Vault data stays in-region. **Confirm that before
    globalidp holds real data**: if it does not stay, `sg` data leaves `sg`.

  The other pairs stay inside their jurisdictions, but that is a property of
  the pairs, not of this design. A cell in a region whose pair crosses a border
  needs a vault with that replication turned off, or Managed HSM. Check it
  before adding one.

## Cells: two and three regions (#98 on Azure)

**A CELL IS `environment/` APPLIED ONCE PER REGION**, with `cell` set, exactly
as on AWS: `cells.tf`'s header lists what changes. The contract with the
service is AWS's, name for name (`deploy/aws/CLAUDE.md`, *The contract with
the code half*), with the `azure` provider where AWS has `aws`.

* **Every secret, the global ones included, is in the CELL's vault.** The
  global stack writes each shared value (`kek`, `global-db-app-password`,
  `admin-api-client-secret`, product mode's three) into every cell's vault.
  It writes the writer's administrator password into the primary cell's
  vault only. **The exception is the key-encryption KEY** (#391): one Key
  Vault key for the whole environment, in its global vault, beside a copy of
  `global-db-app-password` (*The key-encryption key*, below).
* **`STS_CELL_KEK_VAULT` names the cell key's vault.** It is a new setting,
  `keys.cellKekVault` (#96). The cell key has no fallback of any kind, so the
  `azure` provider had no vault URL to read it from, and a cell on Azure could
  not have started. The global database password falls back to the KEK's
  vault: the cell's own with `kek_provider = "secret"`, the environment's
  global vault with `kms`, where `global/` writes a copy.

### The apply order

AWS's two passes, run by `entrypoint.sh` when a multi-region environment is
applied with no `TF_CELL`:

1. **Base.** Each cell with no state yet is applied in `base`, the primary
   first: everything but running nodes (every scale set at 0 instances) and
   no read of the global state.
2. **`global/`.** It reads every cell's state and makes:
   * the global writer and the replicas;
   * a private endpoint for each in its cell;
   * the peering mesh;
   * the shared secrets;
   * Traffic Manager, the public name's alias, and each cell's `cells-self`
     rule.
3. **Full.** Each cell is applied `full`, the primary first. Its nodes are
   told where the global tier is, and the primary's nodes apply the global
   schema to the writer. A physical replica takes the schema, the role and
   its password by replication.

**Destroy** reverses the order: `global/` first, while the cells it reads
still exist, then each cell in `base`.

**The cells run ONE AFTER ANOTHER**, not six at once as AWS's do (#367). That
was for a four-hour session limit this launcher does not have, and it avoids
concurrent writers of one ACME TXT record set. `TF_CELL=<id>` (with
`TF_CELL_PHASE`) runs one cell; `TF_STACK=global` runs the global stack.

### What is where

| | Where | In the other cells |
|---|---|---|
| **the KEK, as a Key Vault key** (`kek_provider = "kms"`) | the environment's global vault, in the primary's region | **NO: one key, dialled from every cell** |
| the `kek` secret and the other shared secrets | every cell's vault, written by `global/` | **a copy in each** |
| the writer's administrator password | the primary cell's vault | no |
| the global database | the writer in the primary cell's region | **a physical cross-region read replica per other cell**, under that region's `iya-sts` key |
| the images | the registry, home region | **geo-replicated** |
| **the cell key (`cell-kek`)** | the cell's vault | **NO, never** |
| **the cell database, disks and logs** | the cell's region, under its `iya-sts-cell` key and workspace | **NO** |

### The inter-cell channel

* **Peering.** The cells' VNets are a **full mesh of global VNet peerings**,
  one half in each VNet's group. Forwarded traffic and gateway transit are
  off, and there are no route tables to write.
* **8446.** The inter-cell listener sits behind an **internal Standard Load
  Balancer at a fixed address**, `.5` of each cell's private subnet. This is
  GCP's choice (#97): Azure has no five-target-group limit that forced AWS
  onto Cloud Map.
* **No DNS.** Every address that crosses a cell is a formula of the cell's
  CIDR, so no cell reads another's state:
  * `.5`, the inter-cell load balancer;
  * `.10`, the cell database's endpoint;
  * `.12`, the global tier's endpoint.

  The formula is in `environment/cells.tf` and `global/main.tf`; keep them in
  step. A node maps each peer's `nodes.<cell>.<env>.iya-sts.internal`, the
  writer's name and its own replica's name to those addresses with
  `--add-host`. That avoids private DNS zones, which a VNet may link only one
  of per name.

### Routing: Traffic Manager (D7)

This is AWS's Route 53 tree, in the Azure DNS zone (`global/routing.tf`):

* **The public name** is an ALIAS to a **Geographic** parent profile.
* **A pinned jurisdiction's countries** map to a **Performance** child over
  that jurisdiction's cells.
* **`WORLD`** maps to a Performance child over every cell.
* **Each cell's own name**, `<cell>.<name>`, is an A record the cell writes.

* **The pin is a jurisdiction's, not a cell's** (#367).
* **A pinned country never fails over out of its jurisdiction**: Traffic
  Manager's geographic method answers only with the endpoint mapped to the
  country, healthy or not. This is AWS's fail-closed rule. Inside a child the
  health checks count.
* **The health checks** are an HTTPS GET of `/healthcheck` on each cell's 443.
  The probers are admitted by the `AzureTrafficManager` service tag rather
  than AWS's list of checker ranges.

**Performance** routing is by the region the endpoint is in, which is what
AWS's latency records do.

## What was not ported, and why

* **`run-suite.sh` and `suite-callbacks/`.** GCP's reason. The outputs keep
  AWS's names (`service_url`, `lb_address`, `vault`, `admin_api_client_secret`
  as a secret NAME in `vault`, and `cloud = "azure"`), so the port is mostly
  the callback stack.
* **Mail.** The service already has an Azure Communication Services transport
  (`common/mail_transports.ts`). A per-environment ACS resource and its
  connection string in the vault would be the counterpart of AWS's SES
  identity.
* **`spiffe-realm/` for additional realms.** A realm's ports would be more
  rules on the same load balancer.
* **A GitHub workflow.** It should be a service principal with a federated
  credential (OIDC), in the deployer group.
* **Azure cells in a MULTI-CLOUD environment.** The cells here are all
  Azure's (`cloud` must be `azure`). Joining them to #97's AWS and GCP cells
  would take:
  * a VPN gateway per pair;
  * the global tier as a logical subscriber (Flexible Server can subscribe,
    as Cloud SQL did);
  * the Route 53 tree naming Traffic Manager or the cells' addresses.
* **Zone-redundant HIGH AVAILABILITY on Flexible Server.** This is the Azure
  way to survive a zone. It is not AWS's arrangement (a replica, not a
  standby), so it was left out for parity, but it is the step to take for a
  real deployment.

## What it costs

These are estimates from 2026 list prices in westus2, not measurements:

* **`dev`/`ci`: about $0.55 an hour idle**, before storage.
  * three Standard_B2s (~$0.12/h);
  * two GP_Standard_D2ds_v5 servers (~$0.35/h; the replica needs General
    Purpose);
  * the load balancer's rules (~$0.05/h);
  * two public addresses and the endpoint (~$0.02/h).
* **`testidp`:** three Standard_D2s_v5 (~$0.29/h), **about $0.72 an hour**.
* **A cell:** `testidp` again, plus the inter-cell load balancer (~$0.03/h),
  a global server (~$0.17/h) and an endpoint. That is **about $0.93 an hour
  a cell**, so **`testidpna` about $1.9 and `globalidp` about $2.8 an hour**,
  plus inter-region transfer on the peering and the replication, and Traffic
  Manager's queries and health checks (a few dollars a month).
* **Long-lived, and the one surprise: ACR Premium is about $50 a month, and
  each geo-replica as much again.** With `globalidp` listed that is four
  regions, about **$200 a month**, for as long as the foundation lists them.
  A registry in Standard with no replication is $20 a month, and cells would
  pull across regions. Change `azurerm_container_registry.main` if that
  trade is wanted.
* **Also long-lived:**
  * per region, a key vault and keys (about $1 a month);
  * the key-encryption keys: software keys, charged per operation (a few
    operations per data key per node start), so cents a month;
  * a workspace, by volume;
  * the public zone ($0.50 a month).

## What to look at first on the first apply

* **The Azure Monitor agent's data collection rule association on a
  Flexible scale set.** It is associated with the scale set
  (`nodes.tf`). If no Syslog rows arrive, associate it with each VM instead.
* **Cross-region read replicas of a server that has only a private
  endpoint and public access off**, and the replica's own endpoint. If Azure
  refuses one, VNet integration is the documented path.
* **Flexible Server's `18`.** The provider accepts it. Check that the regions
  offer it on General Purpose.
* **A replica's `customer_managed_key`** naming its own region's key and
  identity.
* **The Application Health extension against a self-signed certificate** on
  8081 (`dev`, which has no public name). If it will not accept one, the probe
  can be `http` on a port the service answers plainly.
* **The private endpoint's `member_name`/`subresource_name`,
  `postgresqlServer`**, with a static address.
* **The load balancer's hairpin.** Check that a node reaching its own public
  name arrives from the outbound address the `self` rule admits.
* **The health probe's source is `AzureLoadBalancer`.** It is admitted
  explicitly because the deny rules sit ahead of Azure's defaults.
* **RBAC propagation.** A node that starts before its grants are honoured
  retries for five minutes (registry, vault). The foundation waits 90 s after
  its own grants before writing.
* **Traffic Manager's geographic behaviour when a pinned child is
  degraded.** Check it answers the child's endpoints, not the `WORLD` ones.
* **The key-encryption key.** Check that the rotation policy is accepted as
  written (`P1Y` rotation, `P2Y` expiry, `P30D` notice). Check that a node's
  first start logs the `kek-rsa` key and its version, and that
  `/admin/secrets` reports the key with only the rotation policy refused. In a
  multi-region environment, check that a non-primary cell starts and reads
  `global-db-app-password` from the global vault.
* **An `AuthorizationFailed` naming an action** on plan or apply: add it to
  `foundation/iam_deployer.tf`'s role, and an administrator re-applies.

## Running it by hand (NOT YET RUN)

```bash
AZURE_SUBSCRIPTION_ID=<id> deploy/azure/bootstrap-state.sh               # once, administrator
cp deploy/azure/foundation/foundation.tfvars.example deploy/azure/foundation/foundation.auto.tfvars   # fill in
TF_STACK=foundation AZURE_SUBSCRIPTION_ID=<id> deploy/azure/terraform-local.sh dev apply   # administrator
terraform -chdir=deploy/azure/dns-delegation init \
  -backend-config=subscription_id=<id> -backend-config=resource_group_name=iya-sts-terraform-state \
  -backend-config=storage_account_name=<account>
terraform -chdir=deploy/azure/dns-delegation apply -var subscription_id=<id>   # AWS + Azure credentials

# the three images, from the repository root
R=<registry login server>/iya-sts
docker build -t $R:<tag> --build-arg STS_CLOUD_SDKS="@azure/keyvault-secrets @azure/keyvault-keys @azure/identity" .
docker build -t $R:schema-<tag> -f deploy/azure/schema-init/Dockerfile .
docker build -t $R:init-<tag> -f deploy/azure/node-init/Dockerfile .
az acr login --name <registry name>
docker push $R:<tag>; docker push $R:schema-<tag>; docker push $R:init-<tag>

# as a deployer, from here on
AZURE_SUBSCRIPTION_ID=<id> IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidp apply     # 1 region
AZURE_SUBSCRIPTION_ID=<id> IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidpna apply   # 2 regions
AZURE_SUBSCRIPTION_ID=<id> IMAGE_TAG=<tag> deploy/azure/terraform-local.sh globalidp apply   # 3 regions
AZURE_SUBSCRIPTION_ID=<id> deploy/azure/terraform-local.sh globalidp destroy
```

**The foundation's `terraform-local.sh` run passes `dev` only because the
launcher wants an environment name**; the foundation ignores it. Its
variables come from `foundation.auto.tfvars`. The entrypoint passes the
subscription and derives the state account from it.
