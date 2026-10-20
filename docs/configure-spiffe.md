---
title: "Configuring SPIFFE"
---

# Configuring SPIFFE

This page shows how to set up iya-sts as a SPIFFE issuing authority: a trust
domain per trust realm, the bundle endpoint, registration entries, the
Workload API (on its own socket or through a workload agent beside the
workload), the SPIRE Server API, node attestation and join tokens,
federation, and the SPIFFE Broker API. Each recipe is given twice, once as
steps in the **admin console** (`/admin`) and once as calls to the
**Management API** (`/admin-api`).

**The values come from this repository's own test jobs**, and each recipe
names the job it is taken from. The jobs in `tests/vendored/` run against a
service over the network, in development and in product mode. The jobs in
`tests/` run in process and bind sockets no stack publishes. Change the
identifiers, addresses and trust domains to your own.

How each surface *behaves*, and every setting with its default, is on
[SPIFFE](spiffe.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token and the `api` shell helper used
below. Every SPIFFE operation here also works under `/realm/<id>/admin-api`,
in that realm.

**`GET /spiffe` is the live description** of all three surfaces: the state of
every socket, every SPIRE Server API method with the entities allowed to call
it, the six methods that are not implemented and why, and the node attestors
this build verifies. Add `?format=json` for the same as JSON. This page does
not copy that list.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/cert-issuance#cert-spiffe-overview` | **Protocols → Cert issuance → SPIFFE → Trust domain** | See the trust domain, the authorities and the sockets; **Rotate**; set or remove a federated bundle; change every `spiffe.*` setting at the foot of the page (**Save SPIFFE**). |
| `/admin/cert-issuance#cert-spiffe-entries` | **… → SPIFFE → Registration entries** | **Create a registration entry**; click an entry to change one field or delete it. |
| `/admin/cert-issuance#cert-spiffe-agents` | **… → SPIFFE → Agents** | Mint a join token (**Create the token**); click an agent to ban, unban or delete it. |
| `/admin/cert-issuance#cert-spiffe-brokers` | **… → SPIFFE → Brokers** | **Authorize a broker** for the Broker API, or **Remove** one. |
| `/admin/realms` | **Trust realms** | Define a realm; on a realm's row, **What this realm sets** → **Set it here** writes one setting on that realm. |
| `/admin/ldap/spiffe` | **Directory → SPIFFE entries** | Read the entries and agents as the directory holds them, with their attribute schema. |

The API equivalents:

| What | API |
|---|---|
| Read the trust domain, its authorities and sockets | `GET /admin-api/spiffe` |
| Rotate, federate | `POST /admin-api/spiffe/rotate`, `/spiffe/federation-set`, `/spiffe/federation-remove` |
| Registration entries | `GET /admin-api/spiffe/entries`; `POST /admin-api/spiffe/entries/create`, `/update`, `/delete` |
| Agents and join tokens | `GET /admin-api/spiffe/agents`; `POST /admin-api/spiffe/agents/join-token`, `/ban`, `/unban`, `/delete` |
| Brokers | `GET /admin-api/spiffe/brokers`; `POST /admin-api/spiffe/brokers/set`, `/remove` |
| A setting | `POST /admin-api/config/set` (in the realm the call is made in), or `POST /admin-api/realms/set` with `{id, key, value}` |

The gRPC surfaces register no HTTP route, so `GET /admin/sts-metadata` cannot
list them. `GET /spiffe` and the **Trust domain** tab report them.

## What development and product mode change

The same configuration behaves differently in the two modes (`global.mode`).
The full table is on [SPIFFE → Development and product mode](spiffe.md#development-and-product-mode).
What changes what you fill in:

* **A workload that matches no entry.** Development creates an entry for it
  and issues an SVID while `spiffe.autoCreateEntries` is on (the default).
  Product refuses it `PERMISSION_DENIED`. In product, register every workload
  first.
* **The Workload API over TCP.** Development serves it on `spiffe.grpcHost`
  and `spiffe.workloadPort` (8092), and anybody who can reach the port is
  answered. Product does not bind the port unless
  `spiffe.workloadTcpSourceAuthenticated` is on, and never on a wildcard
  address. See [The Workload API over TCP](#the-workload-api-over-tcp).
* **What an entry must select.** In product an entry must select something
  that identifies its workload. One that selects nothing, or only
  `transport:` and `endpoint:`, is refused at every door (`STS-SPIFFE-0122`).
* **Sample entries.** A development start seeds three entries (`/workload`,
  `/ns/default/sa/web`, `/ns/default/sa/db`). Product seeds none.
* **The Workload API's Unix socket** is not bound in product when the native
  peer-credentials module is missing (`STS-SPIFFE-0113`); development serves
  it unattested.
* **Settings refused in product**: `spiffe.attestWorkloads` off,
  `spiffe.acceptAssertedSelectors` on, `spiffe.requireSecurityHeader` off and
  `spiffe.k8sSkipKubeletVerification` on.

In both modes: the SPIRE Server API's TCP port is mutual TLS, every method is
authorized against SPIRE's own table, and node attestation refuses anything
it cannot verify.

## Turn SPIFFE on in a trust realm

The default realm's trust domain is `spiffe.trustDomain` (`example.org`), and
its sockets are bound when the process starts. **A realm is created with
SPIFFE off**, with its own DNS domain as its trust domain, its own Unix socket
paths, its TCP ports set to 0 and no administrators. Turning `spiffe.enabled`
on for the realm builds its authorities and binds its sockets. Nothing
restarts.

Taken from `sts_spiffe_broker.js` (the realm and the switch) and
`tests/spiffe_realm_domains.js` (the address and ports).

**Console:**
1. On **Trust realms** (`/admin/realms`), under **Define a realm**, enter the
   **Id** `acme`, a **Name** and the **Domain** `acme.example.net`, and click
   **Define it**.
2. On the realm's row, under **What this realm sets**, enter the **Key**
   `spiffe.enabled` and the **Value** `true`, and click **Set it here**.
3. To serve the realm over TCP, set `spiffe.grpcHost` to an address of the
   realm's own, and `spiffe.serverPort` (and, where it is allowed,
   `spiffe.workloadPort`) to a port, the same way.

**API:**
```bash
api realms/create '{"id":"acme","domain":"acme.example.net","name":"acme"}'
api realms/set '{"id":"acme","key":"spiffe.enabled","value":true}'

# to serve it over TCP: an address of its own, and the ports
api realms/set '{"id":"acme","key":"spiffe.grpcHost","value":"127.0.0.1"}'
api realms/set '{"id":"acme","key":"spiffe.serverPort","value":8181}'

# the realm's trust domain, authorities and sockets
curl -sk "$BASE/realm/acme/admin-api/spiffe" -H "Authorization: Bearer $TOKEN"
```

The settings can also go in the `overrides` of `realms/create`, as the broker
job does. The trust domain is `acme.example.net` unless you set
`spiffe.trustDomain` on the realm before turning SPIFFE on.

**A realm is told apart by address, not by path.** Two realms may not bind the
same address and port; the refusal names the realm that has it. The default
realm already holds `spiffe.grpcHost` (`0.0.0.0`) on 8092 and 8181, so a realm
needs an address of its own to use those ports. The compose files give the
container extra addresses for this (`STS_EXTRA_IPS`); see
[Trust realms → Separated — SPIFFE, by ADDRESS](trust-realms.md#separated--spiffe-by-address).

**The trust domain is fixed when the authorities are built.** A later change
is reported as drift on `GET /spiffe` and not acted on. To change it, turn the
realm's SPIFFE off, change `spiffe.trustDomain`, and turn it on again; that
discards the old authorities.

## Read the trust bundle

Anybody verifying an SVID, and a federation partner, reads the bundle:

```bash
curl -sk "$BASE/spiffe/bundle"               # the default realm
curl -sk "$BASE/realm/acme/spiffe/bundle"     # a realm
```

The answer is a JWK Set with `spiffe_sequence` and `spiffe_refresh_hint`.
Each key has `use` set to `x509-svid` (with the certificate in `x5c`) or
`jwt-svid`. Both test jobs read the X.509 anchors from the `x5c` of the
`x509-svid` keys, and verify the SPIRE Server API against them.

The path is `spiffe.bundlePath` (restart to change). The X.509 anchor is the
service's Root CA, so every realm publishes the same X.509 certificate; the
JWT keys are each realm's own. See [PKI](pki.md) for the hierarchy and
[SPIFFE → The bundle endpoint](spiffe.md#the-bundle-endpoint).

## Register a workload

A registration entry says which SPIFFE ID a workload is given, by the
selectors the workload must carry. **The entry's selectors must be a subset
of the caller's.** Entries live in the [directory](ldap.md) under
`ou=entries,ou=spiffe`, and a change takes effect on the next SVID.

Taken from `sts_spiffe_grpc.js` (entry W). That job creates its entries before
it calls the Workload API and deletes them at the end.

**Console:**
1. Open **Protocols → Cert issuance → SPIFFE → Registration entries**.
2. Under **Create a registration entry**, fill in:
   - **SPIFFE ID**: `spiffe://example.org/sts-test/spiffe-grpc/workload`
   - **Parent**: leave it empty for this server, or give the agent's SPIFFE ID
     for a workload behind an agent
   - **Selectors**: `unix:uid:1000` (comma-separated `type:value` pairs)
   - **DNS names**: `w.sts-test.invalid`
   - **X509-SVID TTL** `600` and **JWT-SVID TTL** `120` (empty uses
     `spiffe.svidTtl` and `spiffe.jwtSvidTtl`)
   - **Hint** and **Federates with**, if needed.
3. Click **Create**.
4. To change it, click the entry, then under **Change it** pick the **Field**,
   enter the **Value** and click **Set**. **Delete this entry** removes it.

**API:**
```bash
api spiffe/entries/create '{
  "spiffeId": "spiffe://example.org/sts-test/spiffe-grpc/workload",
  "selectors": "unix:uid:1000",
  "dnsNames": "w.sts-test.invalid",
  "hint": "sts-test",
  "x509SvidTtl": 600, "jwtSvidTtl": 120}'

# the reply carries the entry id; mark it admin, or change any other field
api spiffe/entries/update '{"entry":"<id>","field":"admin","value":"true"}'
api spiffe/entries/delete '{"entry":"<id>"}'
```

The fields `update` accepts are `spiffeId`, `parentId`, `selectors`,
`dnsNames`, `federatesWith`, `x509SvidTtl`, `jwtSvidTtl`, `hint`,
`expiresAt`, `admin`, `downstream` and `storeSvid`. A list takes
comma-separated values, and an empty value clears it.

**Selectors** are split on the first colon only: `docker:label:app:web` is the
type `docker` and the value `label:app:web`. Which types a caller carries
depends on how it arrived:

| The caller | Its selectors |
|---|---|
| on the Unix socket | what `spiffe.workloadAttestors` produces: `unix:uid:`, `unix:gid:`, `unix:user:`, `docker:label:`, `k8s:sa:`, `k8s:ns:`, `systemd:id:` and the rest ([SPIFFE → Workload attestation](spiffe.md#workload-attestation-on-the-unix-socket)) |
| over TCP | `transport:tcp`, `endpoint:<grpcHost>:<port>` and `peer:<address>` |
| through a workload agent | `unix:uid:`, `unix:gid:`, and `unix:user:` / `unix:group:` where the agent can read the names |

The job's two refusals are what every door refuses: an entry in another trust
domain (`spiffe://other-domain.invalid/…`) and one under the reserved `/spire`
path both get a 400. **In product**, the job's TCP entries also select the
job's own `peer:` address, because one selecting only `transport:` and
`endpoint:` is refused there.

## The Workload API on the Unix socket

This is the default and the recommended path. The socket is
`spiffe.workloadSocket`, SPIRE's own default path
`/tmp/spire-agent/public/api.sock`, so a client written for a SPIRE agent
needs no change to `SPIFFE_ENDPOINT_SOCKET`. A realm's socket is under
`/tmp/spire-agent/public/<realm>/`. To reach it from another container, mount
its directory as a volume.

When a connection is accepted, the kernel names the connecting process, and
the attestors in `spiffe.workloadAttestors` turn it into selectors. Taken from
`tests/spiffe_workload_attestation.js`:

```bash
api config/set '{"key":"spiffe.workloadAttestors","value":"unix"}'          # the default
api config/set '{"key":"spiffe.unixDiscoverWorkloadPath","value":true}'     # adds unix:path: and unix:sha256:
```

On the console these are rows at the foot of the **Trust domain** tab; change
them and click **Save SPIFFE**. Add `docker`, `k8s` or `systemd` to the list
for those attestors; each has its own settings, listed on
[SPIFFE → Configuration](spiffe.md#workload-attestors). `systemd` needs the
optional package `dbus-next` in the image.

Every call must carry the gRPC metadata `workload.spiffe.io: true`. Without
it the call is refused `INVALID_ARGUMENT`, which `sts_spiffe_grpc.js` asserts
first.

## The Workload API over TCP

A caller over TCP is not attested: there is no process to ask. It is
identified only by `transport:tcp`, `endpoint:<grpcHost>:<port>` and its
`peer:<address>`.

**Development** serves `spiffe.workloadPort` (8092) on `spiffe.grpcHost`,
and any caller that can reach it is answered. `sts_spiffe_grpc.js` registers
its entries with the two descriptive selectors there:

```bash
api spiffe/entries/create '{"spiffeId":"spiffe://example.org/sts-test/spiffe-grpc/workload",
  "selectors":"transport:tcp, endpoint:172.29.0.10:8092"}'
```

(`172.29.0.10` is the compose files' default `STS_SPIFFE_GRPC_HOST`. Use the
service's own bind address, not the address you dialled.)

**Product** binds the port only where the network authenticates source
addresses, which you declare, and only on an address you name. Taken from
`tests/spiffe_workload_tcp_product.js`:

```bash
# on a realm: applied when the realm's sockets are reconciled
api realms/set '{"id":"acme","key":"spiffe.workloadTcpSourceAuthenticated","value":true}'
api realms/set '{"id":"acme","key":"spiffe.grpcHost","value":"10.1.2.3"}'
api realms/set '{"id":"acme","key":"spiffe.workloadPort","value":8092}'

curl -sk -X POST "$BASE/realm/acme/admin-api/spiffe/entries/create" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"spiffeId":"spiffe://acme.example.net/web",
       "selectors":"transport:tcp, endpoint:10.1.2.3:8092, peer:10.1.2.20"}'
```

For the default realm these three are restart settings: set
`STS_SPIFFE_WORKLOAD_TCP_SOURCE_AUTHENTICATED=true`, `STS_SPIFFE_GRPC_HOST`
and `STS_SPIFFE_WORKLOAD_PORT` in the environment or the appconfig file, and
restart. The addresses here are this page's examples; the test binds
`127.0.0.1` and selects `peer:127.0.0.1`.

* `peer:` matches **exactly**. `peer:10.0.0.0/24` is a selector no caller
  carries.
* `0.0.0.0` and `::` are refused (`STS-SPIFFE-0121`).
* **Warning**: whoever holds an address an entry selects is issued its SVIDs.
  Declare the setting only on a network with anti-spoofing, such as a
  host-only bridge.

`GET /admin-api/spiffe` reports the result under `workloadAttestation.tcp`,
with whether the port is listening. Where it says the port is not served, use
a workload agent (next section). An AWS cluster does not publish 8092.

## A workload agent beside the workload

Where TCP cannot be declared honestly (an AWS load balancer is one such
network), the Workload API runs beside the workload instead.
`spiffe/workload_agent.js`, in the iya-sts image, spends one join token at the
SPIRE Server API and then serves the Workload API on a Unix socket next to the
workload. It binds no TCP port. Taken from `sts_spiffe_grpc.js` (its agent
path, used wherever `workloadAttestation.tcp` is not served) and
`tests/spiffe_workload_agent.js`.

**1. Mint a join token.**

Console: on **SPIFFE → Agents**, fill in **Lifetime in seconds** (empty uses
`spiffe.joinTokenTtl`, 600) and, optionally, **Alias SPIFFE ID, optional**,
then click **Create the token**.

API:
```bash
api spiffe/agents/join-token '{}'          # or {"ttl":600}, and optionally "agentId"
```

The answer carries `token`, `expiresAt` and `agentSpiffeId`. **The token is
shown once and not stored.** `agentSpiffeId` is
`spiffe://<trust domain>/spire/agent/join_token/<32 hex>`, a digest of the
token, and is safe to keep.

**2. Register the workload's entries under the agent.** Set **Parent** to
`agentSpiffeId`, and select the uid and gid the workload runs as:

```bash
api spiffe/entries/create '{"spiffeId":"spiffe://example.org/sts-test/spiffe-grpc/workload",
  "parentId":"spiffe://example.org/spire/agent/join_token/<32 hex>",
  "selectors":"unix:uid:10001, unix:gid:10001"}'
```

**3. Start the agent** in the workload's task, with the token in the
environment or a file. A `--join-token` flag is refused, because `ps` shows
the command line:

```bash
STS_SPIFFE_JOIN_TOKEN=<token> node spiffe/workload_agent.js \
  --server sts.example.net:8181 \
  --socket /run/spiffe/api.sock \
  --trust-domain example.org \
  --bundle-url https://sts.example.net/spiffe/bundle
```

| Option | What it is |
|---|---|
| `--server` | the SPIRE Server API, `host:port` (required) |
| `--socket` | the Unix socket to serve the Workload API on (required) |
| `--trust-domain` | the realm's trust domain (required) |
| `--bundle-url` or `--trust-bundle-file` | the anchors the server is verified against: an `https:` bundle URL, or a PEM file (one is required) |
| `--join-token-file` | a file holding the token, instead of `STS_SPIFFE_JOIN_TOKEN` |
| `--require-security-header`, `--attest-workloads` | both on by default; `false` turns one off |
| `--native` | the peer-credentials module, when it is not in `spiffe/native/` |

The bundle URL is fetched with Node's own certificate verification, so the
service's TLS certificate must chain to a CA the agent's Node trusts. Where it
chains to the service's own Root, give the agent `--trust-bundle-file` (the
PEM of the bundle's `x509-svid` certificates) instead, which is what
`sts_spiffe_grpc.js` does.

The agent needs the native peer-credentials module, which is built only in the
image. Without it, it creates no socket and exits (`STS-SPIFFE-0148`). Point the
workload's `SPIFFE_ENDPOINT_SOCKET` at `unix:///run/spiffe/api.sock`.

The host names, socket path and uid above are this page's examples; the jobs
use the service's own address, a temporary directory and the uid the job runs
as.

## Join tokens and node attestation

An agent joins the trust domain at `Agent.AttestAgent` on the SPIRE Server
API. The realm accepts only the types listed in `spiffe.nodeAttestors`
(default `join_token`), and only those this build can verify. Anything else is
refused `FAILED_PRECONDITION`.

### Join tokens

Taken from `sts_spiffe_grpc.js` (sections 10, 11 and 13). A join token comes
from three doors, all writing the same per-realm store: the **Create the
token** form, `POST /admin-api/spiffe/agents/join-token`, and
`Agent.CreateJoinToken` on the SPIRE Server API, which needs an administrator's
SVID. The job calls `CreateJoinToken` with `{"ttl": 300}`, then `AttestAgent`
with the attestation data type `join_token` and the token as the payload, and
a CSR.

A token is spent once, across every node of a cluster. A token this server did
not mint, an expired one, and one presented twice are refused. The settings are
`spiffe.joinTokenTtl` (600) and `spiffe.maxJoinTokens` (256).

**To stop an agent**, open it on **SPIFFE → Agents** and click **Ban this
agent**; **Unban this agent** reverses it. **Delete this agent** forgets it,
which lets trust-on-first-use evidence attest again. Through the API:

```bash
api spiffe/agents/ban '{"agent":"spiffe://example.org/spire/agent/join_token/<32 hex>"}'
api spiffe/agents/unban '{"agent":"spiffe://example.org/spire/agent/join_token/<32 hex>"}'
api spiffe/agents/delete '{"agent":"spiffe://example.org/spire/agent/join_token/<32 hex>"}'
```

The job asserts that the banned agent's SVID is refused `PERMISSION_DENIED`
on its next call.

### x509pop and the other attestors

Taken from `tests/spiffe_attestors.js`. Add the type to the list and give it
its trust anchors, as PEM text:

```bash
api config/set-many '{"spiffe.nodeAttestors":"join_token,x509pop",
  "spiffe.x509popCaBundle":"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"}'
```

An agent then presents a certificate chaining to that bundle and signs a fresh
challenge with its key (RSA, ECDSA or ML-DSA). Its SPIFFE ID is
`spiffe://<trust domain>/spire/agent/x509pop/<SHA-1 of the leaf>` unless
`spiffe.x509popAgentPathTemplate` says otherwise. An empty
`spiffe.x509popCaBundle` refuses every x509pop agent.

The other types (`sshpop`, `tpm_devid`, `k8s_psat`, `http_challenge`,
`aws_iid`, `gcp_iit`, `azure_imds`) are enabled the same way, each with its
own group of settings. Each type's group, and what an empty anchor setting
refuses, is on [SPIFFE → Configuration](spiffe.md#node-attestation-common-settings).
No credential is ever a setting: where SPIRE takes a key or a kubeconfig, this
service takes a file path or the cloud SDK's own credential chain.

## Administrators of the SPIRE Server API

The SPIRE Server API listens on `spiffe.serverPort` (8181), and its TCP port
is **mutual TLS in every mode**. The caller presents an X509-SVID; its SPIFFE
ID is read from the URI subjectAltName. The server presents
`spiffe://<trust domain>/spire/server`, so verify that name against the
bundle. Each method is allowed to the entities SPIRE's own table names
(`local`, `agent`, `admin`, `downstream`), which `GET /spiffe` lists per
method.

There are two ways to make an identity an administrator. Both are read on
every call, so a change takes effect at once.

**Mark a registration entry `admin`** (taken from `sts_spiffe_grpc.js`,
entry A). The workload holding that identity fetches its SVID from the
Workload API and uses it here.

Console: on the entry's page, under **Change it**, pick the **Field** `admin`,
enter `true`, and click **Set**.

API:
```bash
api spiffe/entries/create '{"spiffeId":"spiffe://example.org/sts-test/spiffe-grpc/admin",
  "selectors":"unix:uid:1000","x509SvidTtl":300,"jwtSvidTtl":60}'
api spiffe/entries/update '{"entry":"<id>","field":"admin","value":"true"}'
```

The job gives this entry the shortest lifetimes it makes, and deletes it as
soon as it is done; the admin SVID still in its hands is then refused the
admin methods.

**Or list the SPIFFE ID in `spiffe.adminIds`** (comma- or space-separated),
which needs no entry behind it:

```bash
api config/set '{"key":"spiffe.adminIds","value":"spiffe://example.org/ops/admin"}'
```

A realm is created with `spiffe.adminIds` empty.

**The `spire-server` CLI's private socket.** With
`spiffe.serverSocketEnabled` on, the API is also served on
`spiffe.serverSocket` (`/tmp/spire-server/private/api.sock`), and a caller
there is the `local` entity while `spiffe.trustLocalSocket` is on. In product
that is so only when the socket is private (0600, in a directory with no group
or other bits) and the caller runs as the service's own uid. Taken from
`tests/spiffe_local_socket.js`.

After SPIRE's table allows a call, the [XACML](xacml.md) access gate is asked
too. It permits by default.

## Federate with another trust domain

A foreign trust domain's bundle is **pushed in, never fetched**. Taken from
`sts_spiffe_broker.js`, which federates each of its realms with the trust
domain of a CA it made.

**Console:** on **SPIFFE → Trust domain**, under **Federated trust domains**,
enter the **Trust domain** (`other.example`), optionally the **Bundle
endpoint URL** and **Profile** (`https_web` or `https_spiffe`), paste the
**Bundle document**, and click **Set**.

**API:**
```bash
api spiffe/federation-set '{"trustDomain":"other.example",
  "document":{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…",
                       "use":"x509-svid","x5c":["<base64 DER>"]}],
              "spiffe_sequence":1,"spiffe_refresh_hint":300}}'
api spiffe/federation-remove '{"trustDomain":"other.example"}'
```

* Every JWK must carry a `use` (`x509-svid` or `jwt-svid`); a bundle without
  one is refused.
* A bundle endpoint URL is recorded and **not followed**. `RefreshBundle` on
  the SPIRE Server API is refused for the same reason. Push the new bundle
  when the partner's changes.
* No federated bundle may be named after a trust domain that any realm of
  this service serves.
* A realm holds at most `spiffe.maxFederatedBundles` (32).

An entry's **Federates with** names the trust domains whose bundles a holder
of that identity is given. `GET /spiffe/federated/other.example` shows the
bundle exactly as the realm holds it.

## The SPIFFE Broker API

A broker (a node proxy, or a service mesh's per-node component) asks for the
SVIDs of a workload it acts for, by naming the workload. Taken from
`sts_spiffe_broker.js`, which runs it in a development realm and a product
realm.

**1. Give the realm a Broker port, and turn SPIFFE on.** `spiffe.brokerPort`
is 0 by default, which binds nothing. The job uses 8193 for its development
realm and 8194 for its product realm:

```bash
api realms/create '{"id":"broker-dev","domain":"broker-dev.example.net",
  "name":"SPIFFE broker (development)",
  "overrides":{"spiffe.brokerPort":8193,"spiffe.workloadAttestors":"unix,k8s"}}'
api realms/set '{"id":"broker-dev","key":"spiffe.enabled","value":true}'
```

**2. Federate with the broker's trust domain**, if it is not this one (see
[above](#federate-with-another-trust-domain)).

**3. Authorize the broker**, with the reference types it may use: `pid` (a
process on this host), `k8s` (a pod) or `*` (both).

Console: on **SPIFFE → Brokers**, under **Authorize a broker**, enter the
**SPIFFE ID**, tick the reference types, and click **Save**. **Remove** takes
one off the list.

API (in the realm):
```bash
API="/realm/broker-dev/admin-api"
curl -sk -X POST "$BASE$API/spiffe/brokers/set" -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"id":"spiffe://broker.test/broker","referenceTypes":["pid","k8s"]}'
```

`brokers/remove` takes `{"id": …}`. **Allow `pid` only to a broker on this
host**: a process id means something only on the node it was read on.

**4. Register the workloads** the broker may ask for, by the selectors their
reference produces. The job registers one for a process (`unix:uid:10001`, the
uid the image runs as) and one for a pod (`k8s:pod-uid:<pod UID>`).

**5. The broker connects** with its X509-SVID over mutual TLS, verifies the
server as `spiffe://<trust domain>/spire/server`, and sends the metadata
`broker.spiffe.io: true` on every call. It calls `SubscribeToX509SVID`,
`SubscribeToX509Bundles`, `FetchJWTSVID` or `SubscribeToJWTBundles` with a
`WorkloadPIDReference` or a `KubernetesObjectReference` to a pod.

A pod reference is resolved through the kubelet, so the `k8s` attestor's
settings apply. The job points the realm at a test kubelet with
`spiffe.k8sNodeName`, `spiffe.k8sKubeletSecurePort` and
`spiffe.k8sUseAnonymousAuthentication`. In development it sets
`spiffe.k8sSkipKubeletVerification`; in product it names the kubelet's CA in
`spiffe.k8sKubeletCaFile` instead, because skipping verification is refused
there.

`GET /admin-api/spiffe/brokers` lists the brokers and the Broker listener's
state. The refusals and their gRPC codes are on
[SPIFFE → The SPIFFE Broker API](spiffe.md#the-spiffe-broker-api).

## Rotate the authorities

Both authorities rotate on the scheduler, in both modes, so nothing needs
configuring. To rotate by hand:

**Console:** on **SPIFFE → Trust domain**, under **Authorities**, choose
**the X.509 authority**, **the JWT authority** or **both**, and click
**Rotate**.

**API** (from `sts_admin_api_operations.js`):
```bash
api spiffe/rotate '{"which":"both"}'      # "x509" (the default), "jwt" or "both"
```

New SVIDs are signed by the new authority at once, and SVIDs already issued
keep verifying until they expire. Under the service Root the bundle does not
change. How the self-signed fallback differs is on
[SPIFFE → Trust domains and the authority](spiffe.md#trust-domains-and-the-authority).

## Related

* [SPIFFE](spiffe.md): the behaviour of every surface, and every setting.
* [PKI](pki.md): the Root, the realm Intermediate and the SPIFFE Issuing CA.
* [Trust realms](trust-realms.md): a trust domain and sockets per realm.
* [LDAP](ldap.md): the registry under `ou=spiffe`.
* [Configuring TLS and mutual TLS](configure-tls.md) and
  [Configuring certificate enrollment](configure-enrollment.md).
* [Management API](management-api.md): the token, and the OpenAPI document at
  `/admin-api/openapi.json`.
