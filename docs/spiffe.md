---
title: SPIFFE
---

# SPIFFE

iya-sts is a **SPIFFE issuing authority** in all three of its server-side
shapes: the **bundle endpoint** over HTTPS, the **SPIFFE Workload API** over
gRPC, and the **SPIRE Server API** over gRPC. It issues X509-SVIDs and JWT-SVIDs
per the [SPIFFE specifications](https://github.com/spiffe/spiffe/tree/main/standards)
(SPIFFE ID, Trust Domain and Bundle, X509-SVID, JWT-SVID, Workload API), and its
server API is SPIRE's own
[`spire-api-sdk`](https://github.com/spiffe/spire-api-sdk) protocol. **Every
[trust realm](trust-realms.md) can be a trust domain of its own**, with its own
authority and its own sockets on an address of its own.

| Surface | Transport | Who talks to it |
|---|---|---|
| The bundle endpoint | HTTPS, `GET /spiffe/bundle` | a federation partner, or anybody verifying an SVID |
| The Workload API | gRPC on a Unix socket, and on TCP | a workload, to be given an identity |
| The SPIRE Server API | gRPC on TCP (mutual TLS), and optionally a Unix socket | an operator and an agent: entries, attestation, bundles, minting |

## Features

### Trust domains and the authority

A realm's trust domain is the authority part of every SPIFFE ID it mints. The
default realm's is `spiffe.trustDomain` (`example.org`). **A realm created at
runtime gets its own DNS domain as its trust domain**, for example `iyasec.io`,
and may name another one outright. Two realms never share a trust domain by
default, because two authorities claiming one name make every SVID either one
mints ambiguous.

The trust domain is fixed when the realm's authorities are built. A later change
is reported as drift on `GET /spiffe` and `/admin/spiffe`, not acted on. To
change it, turn the realm's SPIFFE off and on again, which discards the old
authorities.

The X.509 authority is the realm's **SPIFFE Issuing CA** in the service's
[certificate hierarchy](pki.md):

```
Root CA (the service's)          <- what the bundle publishes
└── Intermediate CA (this realm)
     └── SPIFFE Issuing CA       <- signs X509-SVIDs
          ├── X509-SVID
          └── downstream CA      (NewDownstreamX509CA)
```

This is the arrangement SPIRE has with an `UpstreamAuthority` configured. **A
rotation of the Issuing CA leaves the bundle unchanged**, because the bundle is
the Root. Where no hierarchy exists (`pki.autoBuild` off, or a Root that could
not be built), the realm falls back to a self-signed X.509 authority. That
authority's rotations keep `spiffe.retainedAuthorities` authorities in the
bundle. The JWT authority is always the realm's own key.

Both authorities rotate automatically, in both modes. A scheduler job runs every
hour. It rotates the X.509 authority once it is past half its lifetime, and the
JWT authority once it is older than half `spiffe.caTtl`. **Rotate now** on
`/admin/spiffe` rotates either or both by hand. On a cluster, a realm's
authorities are made once and adopted by every node.

X509-SVIDs use EC P-256 by default (`spiffe.x509KeyType`), which is what SPIRE
issues. JWT-SVIDs are signed ES256 by default (`spiffe.jwtKeyType`). Ed25519 is
offered for X.509 only.

### The bundle endpoint

`GET /spiffe/bundle` (`spiffe.bundlePath`) returns the realm's trust bundle as a
JWK Set, with `spiffe_sequence` (which changes only when the bundle changes) and
`spiffe_refresh_hint` (`spiffe.refreshHint`). Every key carries a `use` of
`x509-svid` (with the certificate in `x5c`) or `jwt-svid`. It is served
`no-store`. A real federation partner refuses a plain-HTTP bundle endpoint, so
set `global.https`.

`GET /spiffe/federated/{trustDomain}` shows a foreign trust domain's bundle
exactly as this realm holds it, so that "the bundle I pushed" and "the bundle
workloads are given" can be compared.

### The Workload API

The gRPC service `SpiffeWorkloadAPI`, on:

* a **Unix socket** at `spiffe.workloadSocket`, SPIRE's own default path
  `/tmp/spire-agent/public/api.sock`, so `SPIFFE_ENDPOINT_SOCKET` needs no
  change for a client that was pointed at a SPIRE agent;
* **TCP** at `spiffe.workloadPort` (8092), for a caller in another container.
  **In product mode only where the network authenticates source addresses**:
  see *A caller over TCP* below.

Five of the specification's seven methods are implemented:

* `FetchX509SVID`: X509-SVIDs with their private keys and the bundle;
* `FetchX509Bundles` and `FetchJWTBundles`;
* `FetchJWTSVID`: a JWT-SVID for an audience, which is required;
* `ValidateJWTSVID`: a real verification, returning the claims.

The two WIT methods are not implemented. No specification defines the token
format yet, and inventing one would work here and interoperate with nothing.

**The streams stay open.** `FetchX509SVID` and the bundle streams are held for
the life of the connection and **re-sent at half the shortest SVID lifetime**,
so a client's rotation path runs without an hour's wait. A call without the
metadata header `workload.spiffe.io: true` is refused, because the specification
requires it (section 3, a hardening measure against server-side request
forgery). `spiffe.requireSecurityHeader` off serves such a call in development
mode only (#181); product ignores it and refuses turning it off.

**Which entries answer a caller.** A caller is given the registration entries
whose selectors are a **subset** of the caller's selectors, as SPIRE matches
them (`spiffe.attestWorkloads`; turning it off, which hands every caller every
entry, is development only). A caller that matches no entry gets an **empty
SVID list**, which is what a real agent answers an unregistered workload. In
development, `spiffe.autoCreateEntries` instead creates an entry for the caller
and issues it an SVID.

### Workload attestation on the Unix socket

The Workload API **authenticates nobody**, because its specification says it
MUST NOT: a workload has no credential until this call gives it one. What it
does is **attest**, as a SPIRE agent does. When a connection is accepted on the Unix
socket, the kernel names the connecting process (`SO_PEERCRED` and a pidfd, read
by a small native module built into the image). The workload attestors in
`spiffe.workloadAttestors` then turn that process into SPIRE's selectors:

* `unix`: `uid:`, `user:`, `gid:`, `group:` and the supplementary groups; with
  `spiffe.unixDiscoverWorkloadPath`, also the executable's `path:` and
  `sha256:`.
* `docker`: the container's `label:`, `env:`, `image_id:` and
  `image_config_digest:`, asked of the Docker Engine at
  `spiffe.dockerSocketPath`.
* `k8s`: the pod's `sa:`, `ns:`, `pod-name:`, `pod-label:`, `pod-owner:`,
  `container-name:`, `container-image:` and the rest of SPIRE's list, read from
  the kubelet.
* `systemd`: the unit's `id:` and `fragment_path:`, asked of systemd over
  D-Bus. Install the optional package `dbus-next` in the image
  (`STS_CLOUD_SDKS=dbus-next` at build time); without it, a realm naming
  `systemd` refuses every connection and says which package is missing.

**Podman.** The `docker` attestor asks Podman's Docker-compatible API instead of
the Engine when the container's cgroup says `libpod`: the rootful socket
(`spiffe.dockerPodmanSocketPath`), or a rootless user's socket
(`spiffe.dockerPodmanSocketPathTemplate`) — the rootless one only with
`spiffe.dockerUseRootlessPodman` on, because that socket belongs to the caller.
The selectors are still `docker:`.

**Signed images.** With `spiffe.dockerSigstoreEnabled`, a docker workload's
image must carry a cosign signature that verifies, and the attestation adds
SPIRE's `image-signature:verified`, `image-attestations:verified` and
`image-signature-subject:`, `-issuer:`, `-value:`, `-log-id:`, `-log-index:`,
`-integrated-time:` and `-signed-entry-timestamp:` selectors. Configure:

1. what a signature may verify under — cosign public key FILES
   (`spiffe.dockerSigstorePublicKeyFiles`), and for keyless signatures the
   sigstore trust root: through TUF (`spiffe.dockerSigstoreTufRootFile`, the
   `root.json` you trust, refreshed by the scheduler job
   `spiffe.sigstore-tuf-refresh`), or pinned
   (`spiffe.dockerSigstoreTrustedRootFile`);
2. for keyless signatures, the signers you accept
   (`spiffe.dockerSigstoreAllowedIdentities`, `issuer=subject`);
3. the registries the signatures may be fetched from
   (`spiffe.dockerSigstoreAllowedRegistries`) — Docker Hub is
   `index.docker.io`, and list its token host `auth.docker.io` and blob host
   too.

Every signature must carry its Rekor transparency-log bundle, and a keyless
certificate an embedded SCT. **A signature that does not verify refuses the
connection** (`UNAVAILABLE`); it never merely leaves out a selector.

A connection is attested once, when it is accepted. **Every call on it checks
that the process is still the one attested.** A process that has exited, a
reused pid or an `exec` of another program is refused `PERMISSION_DENIED`. An
attestor that fails refuses every call on the connection with `UNAVAILABLE`. A
peer in a pid namespace this service cannot see is attested on its kernel uid
and gid alone.

### A caller over TCP

**A caller over TCP is not attested**, because there is no peer process to ask.
It is identified by the selectors `transport:`, `endpoint:` and `peer:`. These
are deliberately spelt unlike any attestor's, so they cannot be mistaken for
attested facts.

The Workload Endpoint specification allows TCP only where "the underlying
network allows the Workload Endpoint server to strongly authenticate the
workload based on source IP address" (section 3), and forbids the other fixes:
TLS must not be required and a client must not be asked to authenticate. The
source address is therefore the only identity a TCP caller carries, and whether
the network guarantees it is something this service cannot see. So, in
**product mode** (#166):

* **The TCP port is not bound** (`STS-SPIFFE-0120`) unless
  `spiffe.workloadTcpSourceAuthenticated` is on. Turning it on declares the
  section 3 condition: a pod network with anti-spoofing, a host-only bridge.
  **Warning**: every host that reaches the port from an address an entry
  selects is issued that entry's SVIDs, so an address that can be spoofed,
  shared behind a NAT or reassigned hands the identity to whoever holds it.
* **With it on, a wildcard `spiffe.grpcHost`** (`0.0.0.0`, `::`) **is still
  refused** (`STS-SPIFFE-0121`). Name the address on the network you vouch for.
* **A realm switched to product** with the port already bound keeps the socket
  and refuses every call on it (`UNAVAILABLE`).
* **An entry must select something that identifies its workload**: never only
  `transport:` and `endpoint:`, which every caller of the port carries, and
  never nothing (`STS-SPIFFE-0122`). The console, `/admin-api` and the SPIRE
  Server API (`INVALID_ARGUMENT` per item) all refuse it. For a TCP caller that
  is `peer:<address>`, matched **exactly**: `peer:10.0.0.0/24` is a selector no
  caller carries, as in SPIRE. An entry written in development answers nobody
  once the realm is in product (`STS-SPIFFE-0123`).

`GET /spiffe`, `/admin/spiffe` and `GET /admin-api/spiffe` report the realm's
state under `workloadAttestation.tcp`: `served (development, not attested)`,
`not served (product, source not declared authenticated)`, `not served
(product, wildcard bind address)` or `served (product, source declared
authenticated)`, with whether the port is listening.

### The SPIFFE Broker API

A **broker** — a node proxy, a service mesh's per-node component — can ask for
the SVIDs of a workload it acts for, by naming the workload rather than being
it. This is the SPIFFE Broker API (Incubating), on a mutual-TLS listener of its
own:

1. Set `spiffe.brokerPort` on the realm (and `spiffe.grpcHost` where the realm
   needs an address of its own), then turn the realm's SPIFFE on.
2. Authorize the broker on **SPIFFE → Brokers** (`/admin/spiffe/brokers`) or
   `POST /admin-api/spiffe/brokers/set` with its SPIFFE ID and the references
   it may use: `pid`, `k8s` or `*`. A broker from another trust domain needs
   that domain's bundle federated first.
3. The broker connects with its X509-SVID, verifies this server as
   `spiffe://<trust domain>/spire/server` against the bundle, and sends
   `broker.spiffe.io: true` on every call.

It calls `SubscribeToX509SVID`, `SubscribeToX509Bundles`, `FetchJWTSVID` and
`SubscribeToJWTBundles`, each with a **workload reference**:

* a `WorkloadPIDReference` — a process on this host, attested by the workload
  attestors exactly as a Workload API caller is. The endpoint is TCP, so allow
  `pid` only to a broker running on this host;
* a `KubernetesObjectReference` to a **pod** (`pods`, group `core`), by UID or
  by namespace and name — found in this node's kubelet pod list and attested
  by the `k8s` attestor's pod selectors. Other Kubernetes objects are refused.

The workload gets the entries its selectors match, never an admin or downstream
entry. A refusal follows the specification's table — `INVALID_ARGUMENT` for a
missing header or a bad reference, `UNAUTHENTICATED` for no SVID,
`PERMISSION_DENIED` for a caller that is not a broker, a reference type it may
not use or a workload with no entry, `NOT_FOUND` for a workload that does not
exist — with a `google.rpc.ErrorInfo` in the `spiffe.io` domain. A stream ends
`NOT_FOUND` when its workload stops.

### The SPIRE Server API

SPIRE's six services, Entry, Agent, Bundle, SVID, TrustDomain and Debug, with
forty-two methods, on TCP `spiffe.serverPort` (8181, because SPIRE's own 8081 is
this service's HTTP port). They are also on a Unix socket at
`spiffe.serverSocket` when `spiffe.serverSocketEnabled` is on. Thirty-six
methods are implemented. **`GET /spiffe` lists every method, with a reason for
each of the six that are not.**

**The TCP port is mutual TLS, in every mode.** The server presents its own SVID
(`spiffe://<trust domain>/spire/server`). A caller presents an X509-SVID, which
is verified against the bundle, its validity window (with `spiffe.clockSkew`)
and the revocation register. Revoking the SPIFFE Issuing CA on `/admin/pki`
therefore refuses every SVID under it. The caller's SPIFFE ID is taken from the
URI subjectAltName. The port **asks for** a certificate without requiring one,
so that `AttestAgent` and `GetBundle` stay open to an agent that has no SVID
yet.

Each method is authorized against **SPIRE's own per-method table**, copied row
for row from `policy_data.json`. A caller is one or more of these entities:

| Entity | What it means |
|---|---|
| `local` | the call came in on the Unix socket while `spiffe.trustLocalSocket` is on — trusted outright in development; in product only when the socket is verified 0600 in a private directory and the caller's kernel uid is the service's own |
| `agent` | an attested, unbanned agent's SVID |
| `admin` | a SPIFFE ID in `spiffe.adminIds`, or one with a registration entry marked `admin` |
| `downstream` | a SPIFFE ID with a registration entry marked `downstream` (a nested SPIRE server) |
| anonymous | nothing verified |

Where a row looks surprising, that is SPIRE's own answer. For example,
`Debug.GetInfo` is local-only, so an admin SVID over TCP is refused it. After
SPIRE's table has allowed a call, the [XACML](xacml.md) access gate is asked. It
permits by default. An authenticated caller gets a [session](sessions.md) keyed
on its SPIFFE ID.

`RenewAgent` renews the agent **on the connection**, never an agent named in the
request.

### Node attestation

`Agent.AttestAgent` accepts only an attestation type that the realm lists in
`spiffe.nodeAttestors` **and** that this server can verify. Anything else is
refused `FAILED_PRECONDITION`, as SPIRE refuses an attestor it has no plugin
for. There is no fallback. All nine of SPIRE's server node attestors are
implemented, step for step:

| Type | What is verified | Configured by |
|---|---|---|
| `join_token` | a single-use token from `CreateJoinToken`, per realm, spent once across every node | `spiffe.joinTokenTtl`, `spiffe.maxJoinTokens` |
| `x509pop` | a certificate chaining to a configured bundle (or to the realm's SPIFFE bundle), and a signature over a fresh challenge. RSA, ECDSA and, beyond SPIRE, post-quantum keys | `spiffe.x509pop*` |
| `sshpop` | an SSH host certificate from a configured authority, and a signature by its host key | `spiffe.sshpop*` |
| `tpm_devid` | a DevID key resident in a TPM whose endorsement key a configured manufacturer certified, proved by credential activation | `spiffe.tpm*` |
| `k8s_psat` | a projected service account token that the cluster's own TokenReview authenticates | `spiffe.k8sPsatClusters` |
| `http_challenge` | a nonce served over HTTP from a host name the realm allows | `spiffe.httpChallenge*` |
| `aws_iid` | the EC2 instance identity document, with EC2 and IAM asked for selectors | `spiffe.awsIid*` |
| `gcp_iit` | the Compute Engine instance identity token | `spiffe.gcpIit*` |
| `azure_imds` | the attested document from Azure IMDS, minted for this server's nonce | `spiffe.azureImds*` |

**An attestor returns only selectors it verified.** A trust anchor is PEM text
in a setting, not a file path, so the console and `/admin-api` can set it. **No
credential is ever a setting.** Where SPIRE takes an access key, an app secret
or a kubeconfig, this server takes a file path or uses the cloud SDK's own
credential chain. The cloud SDKs are optional packages: a realm that enables
`aws_iid`, `gcp_iit` or `azure_imds` without the SDK installed is refused, and
the refusal names the missing package.

Evidence that cannot be re-attested, namely a join token and the
trust-on-first-use cloud documents (and `http_challenge` with `spiffe.httpChallengeTofu`), attests
**once**. Attesting the same agent again is refused until an operator deletes
the agent. Evidence is spent only after the agent's SVID exists, so a refused
attestation spends nothing. A challenge is a conversation on the same stream;
with no answer inside `spiffe.attestationChallengeTimeout`, the call fails
`DEADLINE_EXCEEDED`.

**`http_challenge` is the one place this server dials an address a caller
named.** The host name must match `spiffe.httpChallengeAllowedDnsPatterns`
before it is looked up. That list is empty by default, which refuses every
agent; this is stricter than SPIRE, whose empty list allows any name. In product
mode internal addresses are refused, and in every mode the request follows no
redirect and reads at most 64 bytes.

### The registry is the directory

Registration entries live in the [LDAP directory](ldap.md) under
`ou=entries,ou=spiffe` and attested agents under `ou=agents,ou=spiffe`.
**Nothing caches them.** A form on `/admin/spiffe/entries`, an `ldapmodify` and
`BatchUpdateEntry` are three ways to change one entry, and the next SVID
reflects the change. An entry is configuration. An agent is a record of
something that happened, so nothing on it is editable, and ban and delete are
the only controls.

Every workload identity that authenticates with an SVID, attests, or is issued
an X509-SVID gets **one** entry under `ou=users`, found by its SPIFFE ID
however it arrived. The entry records the last SVID's `x509*` attributes and a
count of how many were issued. **SPIFFE has no revocation.**
`spiffeCredentialStatus` on that entry records that an identity can no longer
obtain a new SVID (its last registration entry deleted, or its agent banned or
deleted). Nothing reads it back, and no certificate is refused because of it.

### Federation

**A foreign bundle is pushed in and never fetched.** Set it with
`POST /admin-api/spiffe/federation-set`, the form on `/admin/spiffe`, or
`BatchSetFederatedBundle`. `RefreshBundle` refuses, naming the URL it will not
follow. Federated bundles belong to a realm. None may be named after a trust
domain that any realm of this service serves, and every JWK in one must carry a
`use`.

### Not implemented

* Six SPIRE Server API methods (listed with reasons on `GET /spiffe`) and the
  two Workload API WIT methods.
* Revocation of an SVID. The answer is a short lifetime and rotation, and the
  bundle's `crl` field stays empty.
* Workload attestation of a TCP caller, which has no process to attest (so
  product mode serves TCP only on a declared network).
* In an image signature: the online Rekor lookup for a signature with no
  bundle (it is refused), the new sigstore bundle format and RFC 3161
  timestamps.
* In the Broker API: references to Kubernetes objects other than pods, SPIRE's
  cluster pod-reference scope, a Unix socket endpoint and gRPC server
  reflection.
* An interop run against a real `spire-agent`.

## Development and product mode

| | Product | Development |
|---|---|---|
| Unmatched Workload API caller | Empty SVID list | An entry is created and an SVID issued while `spiffe.autoCreateEntries` is on |
| Asserted selectors (`x-sts-workload-selector`) | Never believed, and `spiffe.acceptAssertedSelectors` cannot be turned on | Believed when `spiffe.acceptAssertedSelectors` is on |
| `spiffe.attestWorkloads` off | Ignored (logged once, `STS-CORE-0106`): a caller gets only the entries its selectors match. Turning it off is refused (`STS-CORE-0103`) | Every caller is answered with every entry |
| A caller on the SPIRE Server API's Unix socket | `local` only when the socket was made 0600 in a directory with no group or other bits (`STS-SPIFFE-0117`) and `SO_PEERCRED` says it runs as the service's own uid (`STS-SPIFFE-0118`; `STS-SPIFFE-0119` without the native module). Anybody else needs an administrator's X509-SVID on the TCP port | `local` on the socket's existence, while `spiffe.trustLocalSocket` is on |
| Workload API Unix socket without the native module | **Not bound** (`STS-SPIFFE-0113`) | Served unattested, and `GET /spiffe` says so |
| Workload API over TCP | **Not bound** (`STS-SPIFFE-0120`) unless `spiffe.workloadTcpSourceAuthenticated` declares the network authenticates source addresses, and never on a wildcard `spiffe.grpcHost` (`STS-SPIFFE-0121`) | Served on `spiffe.grpcHost`, the wildcard included |
| A registration entry selecting only `transport:` and `endpoint:`, or nothing | Refused at every door (`STS-SPIFFE-0122`); one already stored answers nobody (`STS-SPIFFE-0123`) | Accepted, and issued to every caller of that transport |
| Sample registration entries | None | Three, one of them selecting `unix:uid:1000` |
| `http_challenge` host | Internal addresses refused, and the resolved address pinned | Any address the allowed patterns admit |

These are the same in both modes: mutual TLS on the SPIRE Server API, SPIRE's
method table, node attestation, workload attestation where the native module is
present, and automatic authority rotation. See
[what is not checked](what-is-not-checked.md).

## Configuration

SPIFFE has about a hundred settings, grouped below. Every runtime setting can be
set per trust realm. The **restart** settings are fixed for the process at
startup. On a realm, the socket settings take effect when that realm's sockets
are reconciled, which happens whenever one of the realm's settings changes.

### The surface and the trust domain

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.enabled` | `STS_SPIFFE_ENABLED` | `true` | yes | Whether the three surfaces answer. On a realm (created off), it builds that realm's authorities and binds its sockets. |
| `spiffe.trustDomain` | `STS_SPIFFE_TRUST_DOMAIN` | `example.org` | restart (per realm) | The trust domain; lower-case letters, digits, dots, dashes and underscores. A realm defaults to its DNS domain. |
| `spiffe.bundlePath` | `STS_SPIFFE_BUNDLE_PATH` | `/spiffe/bundle` | restart | Where the trust bundle is published. |
| `spiffe.refreshHint` | `STS_SPIFFE_REFRESH_HINT` | `300` | yes | The `spiffe_refresh_hint` in the bundle, in seconds. |
| `spiffe.maxFederatedBundles` | `STS_SPIFFE_MAX_FEDERATED_BUNDLES` | `32` | yes | How many foreign trust domains' bundles a realm holds. |

### Authorities, keys and lifetimes

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.x509KeyType` | `STS_SPIFFE_X509_KEY_TYPE` | `ec-p256` | restart | The key type of every X509-SVID, and of the self-signed fallback authority. |
| `spiffe.jwtKeyType` | `STS_SPIFFE_JWT_KEY_TYPE` | `ec-p256` | restart | The JWT authority's key, which sets every JWT-SVID's `alg` (ES256, ES384, ES512 or RS256). |
| `spiffe.caTtl` | `STS_SPIFFE_CA_TTL` | `86400` | restart | How long the X.509 authority's certificate is valid; no SVID outlives it. |
| `spiffe.svidTtl` | `STS_SPIFFE_SVID_TTL` | `3600` | yes | The default X509-SVID lifetime; an entry's own `x509SvidTtl` wins. |
| `spiffe.jwtSvidTtl` | `STS_SPIFFE_JWT_SVID_TTL` | `300` | yes | The default JWT-SVID lifetime. |
| `spiffe.agentSvidTtl` | `STS_SPIFFE_AGENT_SVID_TTL` | `0` | yes | The lifetime of an agent's SVID from AttestAgent and RenewAgent; 0 means `spiffe.svidTtl`. |
| `spiffe.svidSubject` | `STS_SPIFFE_SVID_SUBJECT` | `C=US,O=SPIRE` | yes | The X.501 subject of every X509-SVID, SPIRE's own by default; it cannot be empty. |
| `spiffe.caSubject` | `STS_SPIFFE_CA_SUBJECT` | `CN=sts SPIFFE {kind} ({trustDomain}),O=sts` | yes | The subject of the self-signed fallback authority and of every downstream CA. |
| `spiffe.retainedAuthorities` | `STS_SPIFFE_RETAINED_AUTHORITIES` | `4` | yes | How many self-signed X.509 and JWT authorities a rotation keeps in the bundle (at least 2). |
| `spiffe.clockSkew` | `STS_SPIFFE_CLOCK_SKEW` | `60` | yes | How far out a caller's clock may be when its X509-SVID's validity is checked. |

### Sockets

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.workloadSocketEnabled` | `STS_SPIFFE_WORKLOAD_SOCKET_ENABLED` | `true` | restart | Whether the Workload API is served on a Unix socket. |
| `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` | `/tmp/spire-agent/public/api.sock` | restart | The Workload API's socket path, SPIRE's own default. |
| `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` | `8092` | restart | The Workload API over TCP; 0 turns it off. A new realm is seeded with 0. Not bound in product mode without the next row. |
| `spiffe.workloadTcpSourceAuthenticated` | `STS_SPIFFE_WORKLOAD_TCP_SOURCE_AUTHENTICATED` | `false` | restart | Product mode only: declares that the network authenticates source addresses, so the Workload API is served over TCP, on a named `spiffe.grpcHost`. **Warning**: whoever holds an address an entry selects is issued its SVIDs. |
| `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` | `8181` | restart | The SPIRE Server API over TCP (mutual TLS); 0 turns it off. A new realm is seeded with 0. |
| `spiffe.serverSocketEnabled` | `STS_SPIFFE_SERVER_SOCKET_ENABLED` | `false` | restart | Whether the SPIRE Server API is also served on a Unix socket. |
| `spiffe.serverSocket` | `STS_SPIFFE_SERVER_SOCKET` | `/tmp/spire-server/private/api.sock` | restart | That socket's path, SPIRE's own default. |
| `spiffe.brokerPort` | `STS_SPIFFE_BROKER_PORT` | `0` | restart | The SPIFFE Broker API over TCP (mutual TLS); 0, the default and a new realm's seed, binds nothing. |
| `spiffe.brokers` | `STS_SPIFFE_BROKERS` | (empty) | yes | The brokers, `<SPIFFE ID>=<types>` separated by spaces, the types from `pid`, `k8s` and `*`; managed on `/admin/spiffe/brokers`. **Warning**: allow `pid` only to a broker on this host. |
| `spiffe.grpcHost` | `STS_SPIFFE_GRPC_HOST` | `0.0.0.0` | restart | The address every TCP gRPC listener binds; each realm needs an address of its own. |

### The Workload API

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.requireSecurityHeader` | `STS_SPIFFE_REQUIRE_SECURITY_HEADER` | `true` | yes | Refuse a call without `workload.spiffe.io: true`, as the specification requires. Off is development mode only: product always requires the header and refuses turning it off (#181). |
| `spiffe.attestWorkloads` | `STS_SPIFFE_ATTEST_WORKLOADS` | `true` | yes | Answer a caller only with the entries its selectors match; off answers every caller with every entry, in development only. |
| `spiffe.autoCreateEntries` | `STS_SPIFFE_AUTOCREATE_ENTRIES` | `true` | yes | In development, create an entry for a caller that matches none; off gives it an empty SVID list. |
| `spiffe.acceptAssertedSelectors` | `STS_SPIFFE_ACCEPT_ASSERTED_SELECTORS` | `false` | yes | In development, believe selectors a caller sends in `x-sts-workload-selector`. Nothing verifies them. Refused in product. |
| `spiffe.maxEntries` | `STS_SPIFFE_MAX_ENTRIES` | `500` | yes | How many registration entries may live under `ou=spiffe`; past it a new one is refused. |

### Workload attestors

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.workloadAttestors` | `STS_SPIFFE_WORKLOAD_ATTESTORS` | `unix` | yes | Which of `unix`, `docker`, `k8s` and `systemd` run for a Unix-socket connection and a Broker API process reference. `systemd` needs the optional package `dbus-next`. |
| `spiffe.workloadProcRoot` | `STS_SPIFFE_WORKLOAD_PROC_ROOT` | `/proc` | yes | Where a caller's process is read from. |
| `spiffe.unixDiscoverWorkloadPath` | `STS_SPIFFE_UNIX_DISCOVER_WORKLOAD_PATH` | `false` | yes | Add `path:` and `sha256:` selectors for the caller's executable. |
| `spiffe.unixWorkloadSizeLimit` | `STS_SPIFFE_UNIX_WORKLOAD_SIZE_LIMIT` | `0` | yes | 0 hashes any size, a positive value refuses a larger executable, and -1 emits no `sha256:`. |
| `spiffe.dockerSocketPath` | `STS_SPIFFE_DOCKER_SOCKET_PATH` | `unix:///var/run/docker.sock` | yes | The Docker Engine asked about the caller's container. |
| `spiffe.dockerApiVersion` | `STS_SPIFFE_DOCKER_API_VERSION` | (empty) | yes | The Engine API version; empty uses the Engine's default. |
| `spiffe.dockerPodmanSocketPath` | `STS_SPIFFE_DOCKER_PODMAN_SOCKET_PATH` | `unix:///run/podman/podman.sock` | yes | docker: the rootful Podman API socket, asked when a container's cgroup says `libpod` (#170). |
| `spiffe.dockerPodmanSocketPathTemplate` | `STS_SPIFFE_DOCKER_PODMAN_SOCKET_PATH_TEMPLATE` | `unix:///run/user/%d/podman/podman.sock` | yes | docker: the rootless Podman socket; `%d` is the uid of the container's `user-<uid>.slice`, exactly once. |
| `spiffe.dockerUseRootlessPodman` | `STS_SPIFFE_DOCKER_USE_ROOTLESS_PODMAN` | `false` | yes | docker: attest rootless Podman containers. **WARNING**: that socket is in the caller's own runtime directory and answers what the caller likes; pair its entries with `unix:uid` or `unix:user`. Off, a rootless container gets no docker selectors. |
| `spiffe.dockerSigstoreEnabled` | `STS_SPIFFE_DOCKER_SIGSTORE_ENABLED` | `false` | yes | docker: require a cosign image signature that verifies, with its Rekor bundle, and add SPIRE's `image-signature…` selectors. A signature that does not verify refuses the connection (#170). |
| `spiffe.dockerSigstorePublicKeyFiles` | `STS_SPIFFE_DOCKER_SIGSTORE_PUBLIC_KEY_FILES` | (empty) | yes | docker sigstore: cosign public key FILES (ECDSA, RSA, Ed25519, ML-DSA, SLH-DSA, composite). |
| `spiffe.dockerSigstoreTrustedRootFile` | `STS_SPIFFE_DOCKER_SIGSTORE_TRUSTED_ROOT_FILE` | (empty) | yes | docker sigstore: a pinned sigstore `trusted_root.json` FILE — Fulcio CAs, Rekor and CT log keys — used while TUF is off. |
| `spiffe.dockerSigstoreAllowedIdentities` | `STS_SPIFFE_DOCKER_SIGSTORE_ALLOWED_IDENTITIES` | (empty) | yes | docker sigstore: `issuer=subject` pairs a keyless signer must match (regular expressions where they hold one of SPIRE's characters, unanchored as cosign's). Empty admits no keyless signer. |
| `spiffe.dockerSigstoreSkippedImages` | `STS_SPIFFE_DOCKER_SIGSTORE_SKIPPED_IMAGES` | (empty) | yes | docker sigstore: repository digests attested without verification. |
| `spiffe.dockerSigstoreAllowedRegistries` | `STS_SPIFFE_DOCKER_SIGSTORE_ALLOWED_REGISTRIES` | (empty) | yes | docker sigstore: the registry hosts (and token realms, and blob redirect hosts) signatures are fetched from; the image names the registry, so none other is dialled. Empty refuses every registry. Docker Hub is `index.docker.io`. |
| `spiffe.dockerSigstoreRegistryAuthFile` | `STS_SPIFFE_DOCKER_SIGSTORE_REGISTRY_AUTH_FILE` | (empty) | yes | docker sigstore: a Docker `config.json` FILE of registry credentials; empty is anonymous. |
| `spiffe.dockerSigstoreSkipTlog` | `STS_SPIFFE_DOCKER_SIGSTORE_SKIP_TLOG` | `false` | yes | docker sigstore: skip the Rekor transparency log. **WARNING**: a signature never logged — a stolen key's, or a keyless one past its certificate — then verifies. |
| `spiffe.dockerSigstoreIgnoreSct` | `STS_SPIFFE_DOCKER_SIGSTORE_IGNORE_SCT` | `false` | yes | docker sigstore: do not require the keyless certificate's embedded SCT. **WARNING**: a Fulcio certificate never logged is then accepted. |
| `spiffe.dockerSigstoreIgnoreAttestations` | `STS_SPIFFE_DOCKER_SIGSTORE_IGNORE_ATTESTATIONS` | `false` | yes | docker sigstore: do not require in-toto attestations; off (SPIRE's default) refuses an image that has none. |
| `spiffe.dockerSigstoreTufUrl` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_URL` | `https://tuf-repo-cdn.sigstore.dev` | yes (per process) | docker sigstore: the TUF repository the trust root is refreshed from. |
| `spiffe.dockerSigstoreTufRootFile` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_ROOT_FILE` | (empty) | yes (per process) | docker sigstore: the TUF `root.json` FILE first trusted; empty turns TUF off. A refresh that fails keeps the last verified set. |
| `spiffe.dockerSigstoreTufRefreshS` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_REFRESH_S` | `86400` | yes (per process) | docker sigstore: how often the scheduler job `spiffe.sigstore-tuf-refresh` runs; 0 is off. |
| `spiffe.k8sKubeletReadOnlyPort` | `STS_SPIFFE_K8S_KUBELET_READ_ONLY_PORT` | `0` | yes | Above 0, read the pod list over plain HTTP on loopback instead of the secure port. |
| `spiffe.k8sKubeletSecurePort` | `STS_SPIFFE_K8S_KUBELET_SECURE_PORT` | `0` | yes | The kubelet's secure port to dial; 0 is 10250. |
| `spiffe.k8sNodeName` | `STS_SPIFFE_K8S_NODE_NAME` | (empty) | yes | The kubelet host; empty reads the variable named by the next setting. |
| `spiffe.k8sNodeNameEnv` | `STS_SPIFFE_K8S_NODE_NAME_ENV` | `MY_NODE_NAME` | yes | The environment variable holding the node name. |
| `spiffe.k8sCertificateFile` | `STS_SPIFFE_K8S_CERTIFICATE_FILE` | (empty) | yes | A client certificate file for the kubelet; empty uses a token. |
| `spiffe.k8sPrivateKeyFile` | `STS_SPIFFE_K8S_PRIVATE_KEY_FILE` | (empty) | yes | That certificate's private key file. |
| `spiffe.k8sUseAnonymousAuthentication` | `STS_SPIFFE_K8S_USE_ANONYMOUS_AUTHENTICATION` | `false` | yes | Present no token and no certificate on the secure port. |
| `spiffe.k8sTokenFile` | `STS_SPIFFE_K8S_TOKEN_FILE` | (empty) | yes | The token file; empty is the in-cluster service account's. |
| `spiffe.k8sSkipKubeletVerification` | `STS_SPIFFE_K8S_SKIP_KUBELET_VERIFICATION` | `false` | yes | Do not verify the kubelet's certificate. **Development only** (#171): ignored in product mode, and refused on write there. |
| `spiffe.k8sKubeletCaFile` | `STS_SPIFFE_K8S_KUBELET_CA_FILE` | (empty) | yes | The kubelet's CA file; empty is the service account's `ca.crt`. |
| `spiffe.k8sMaxPollAttempts` | `STS_SPIFFE_K8S_MAX_POLL_ATTEMPTS` | `60` | yes | How often the pod list is read before a missing container fails attestation. |
| `spiffe.k8sPollRetryIntervalMs` | `STS_SPIFFE_K8S_POLL_RETRY_INTERVAL_MS` | `500` | yes | The wait between pod list reads. |
| `spiffe.k8sDisableContainerSelectors` | `STS_SPIFFE_K8S_DISABLE_CONTAINER_SELECTORS` | `false` | yes | Omit the container selectors. |
| `spiffe.k8sEnableNamespaceLabels` | `STS_SPIFFE_K8S_ENABLE_NAMESPACE_LABELS` | `false` | yes | Add `ns-label:` selectors, read from the API server. |

### The SPIRE Server API

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.trustLocalSocket` | `STS_SPIFFE_TRUST_LOCAL_SOCKET` | `true` | yes | Trust the server's Unix socket as the `local` entity — in product only for a caller running as the service's uid on a socket verified private; off demands an X509-SVID there too. |
| `spiffe.adminIds` | `STS_SPIFFE_ADMIN_IDS` | (empty) | yes | SPIFFE IDs that are administrators, SPIRE's `admin_ids`; no entry is needed. Empty on a new realm. |
| `spiffe.maxPageSize` | `STS_SPIFFE_MAX_PAGE_SIZE` | `1000` | yes | The cap on `page_size` for every `List*` method. |
| `spiffe.maxRecordedConnections` | `STS_SPIFFE_MAX_RECORDED_CONNECTIONS` | `512` | yes | How many connections are remembered so that an SVID is one authentication per connection. |
| `spiffe.maxAgents` | `STS_SPIFFE_MAX_AGENTS` | `200` | yes | How many attested agents are held; past it the oldest is dropped. |

### Node attestation: common settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.nodeAttestors` | `STS_SPIFFE_NODE_ATTESTORS` | `join_token` | yes | The attestation types AttestAgent accepts in this realm. |
| `spiffe.attestationChallengeTimeout` | `STS_SPIFFE_ATTESTATION_CHALLENGE_TIMEOUT` | `30` | yes | How long AttestAgent waits for a challenge response. |
| `spiffe.joinTokenTtl` | `STS_SPIFFE_JOIN_TOKEN_TTL` | `600` | yes | A join token's lifetime when the request names none. |
| `spiffe.maxJoinTokens` | `STS_SPIFFE_MAX_JOIN_TOKENS` | `256` | yes | How many unspent join tokens a realm holds; at the cap a new one is refused `RESOURCE_EXHAUSTED`. |

### x509pop, sshpop and tpm_devid

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.x509popMode` | `STS_SPIFFE_X509POP_MODE` | `external_pki` | yes | Verify against `spiffe.x509popCaBundle`, or (`spiffe`) against the realm's own SPIFFE bundle. |
| `spiffe.x509popCaBundle` | `STS_SPIFFE_X509POP_CA_BUNDLE` | (empty) | yes | PEM anchors an agent's certificate must chain to; empty refuses every x509pop agent. |
| `spiffe.x509popSpiffePrefix` | `STS_SPIFFE_X509POP_SPIFFE_PREFIX` | `/spire-exchange/` | yes | In `spiffe` mode, the path prefix the agent's SVID must carry. |
| `spiffe.x509popAgentPathTemplate` | `STS_SPIFFE_X509POP_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's `agent_path_template`; empty is SPIRE's default for the mode. |
| `spiffe.x509popMaxIntermediates` | `STS_SPIFFE_X509POP_MAX_INTERMEDIATES` | `4` | yes | The most intermediate certificates an attestation may carry. |
| `spiffe.x509popMaxRsaKeySize` | `STS_SPIFFE_X509POP_MAX_RSA_KEY_SIZE` | `8192` | yes | The largest RSA key accepted on any presented certificate. |
| `spiffe.x509popVerifyClientIp` | `STS_SPIFFE_X509POP_VERIFY_CLIENT_IP` | `false` | yes | Require the agent's address to be one of the leaf's IP subjectAltNames. |
| `spiffe.x509popGroupTemplate` | `STS_SPIFFE_X509POP_GROUP_TEMPLATE` | (empty) | yes | SPIRE's `group_template`, producing an `x509pop:group:` selector. |
| `spiffe.x509popAllowedGroups` | `STS_SPIFFE_X509POP_ALLOWED_GROUPS` | (empty) | yes | The only values the group template may produce a selector for. |
| `spiffe.sshpopCertAuthorities` | `STS_SPIFFE_SSHPOP_CERT_AUTHORITIES` | (empty) | yes | SSH CA public keys, one per line; empty refuses every sshpop agent. |
| `spiffe.sshpopCanonicalDomain` | `STS_SPIFFE_SSHPOP_CANONICAL_DOMAIN` | (empty) | yes | The domain the host certificate's first principal must end in. |
| `spiffe.sshpopAgentPathTemplate` | `STS_SPIFFE_SSHPOP_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's `agent_path_template` for sshpop. |
| `spiffe.sshpopVerifyClientIp` | `STS_SPIFFE_SSHPOP_VERIFY_CLIENT_IP` | `false` | yes | Require a `source-address` option naming the agent's address. |
| `spiffe.tpmDevidCaBundle` | `STS_SPIFFE_TPM_DEVID_CA_BUNDLE` | (empty) | yes | PEM anchors for DevID certificates; empty refuses every tpm_devid agent. |
| `spiffe.tpmEndorsementCaBundle` | `STS_SPIFFE_TPM_ENDORSEMENT_CA_BUNDLE` | (empty) | yes | PEM certificates of trusted TPM manufacturers; empty refuses every tpm_devid agent. |

### k8s_psat and http_challenge

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.k8sPsatClusters` | `STS_SPIFFE_K8S_PSAT_CLUSTERS` | (empty) | yes | SPIRE's `clusters`, as JSON from cluster name to its allow list, audience and API server; empty refuses every k8s_psat agent. |
| `spiffe.httpChallengeAllowedDnsPatterns` | `STS_SPIFFE_HTTP_CHALLENGE_ALLOWED_DNS_PATTERNS` | (empty) | yes | Regular expressions an agent's host name must match before it is dialled; empty refuses every agent. |
| `spiffe.httpChallengeRequiredPort` | `STS_SPIFFE_HTTP_CHALLENGE_REQUIRED_PORT` | `0` | yes | The port the challenge must be served on; 0 allows any. |
| `spiffe.httpChallengeAllowNonRootPorts` | `STS_SPIFFE_HTTP_CHALLENGE_ALLOW_NON_ROOT_PORTS` | `true` | yes | Off accepts only a privileged port. |
| `spiffe.httpChallengeTofu` | `STS_SPIFFE_HTTP_CHALLENGE_TOFU` | `true` | yes | A host name attests once until its agent is deleted. |
| `spiffe.httpChallengeVerifyClientIp` | `STS_SPIFFE_HTTP_CHALLENGE_VERIFY_CLIENT_IP` | `false` | yes | Require the agent's address to be one its host name resolves to. |

### aws_iid

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.awsIidPartition` | `STS_SPIFFE_AWS_IID_PARTITION` | `aws` | yes | The partition used to build the assume-role ARN. |
| `spiffe.awsIidAssumeRole` | `STS_SPIFFE_AWS_IID_ASSUME_ROLE` | (empty) | yes | A role name assumed in each node's account; empty uses the SDK credential chain. |
| `spiffe.awsIidSkipBlockDevice` | `STS_SPIFFE_AWS_IID_SKIP_BLOCK_DEVICE` | `false` | yes | Skip the check that the root volume and first interface were attached together. |
| `spiffe.awsIidDisableInstanceProfileSelectors` | `STS_SPIFFE_AWS_IID_DISABLE_INSTANCE_PROFILE_SELECTORS` | `false` | yes | Emit no `iamrole:` selectors and make no IAM call. |
| `spiffe.awsIidLocalValidAccountIds` | `STS_SPIFFE_AWS_IID_LOCAL_VALID_ACCOUNT_IDS` | (empty) | yes | SPIRE's `account_ids_for_local_validation`. |
| `spiffe.awsIidAgentPathTemplate` | `STS_SPIFFE_AWS_IID_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's `agent_path_template` for aws_iid. |
| `spiffe.awsIidVerifyOrganization` | `STS_SPIFFE_AWS_IID_VERIFY_ORGANIZATION` | (empty) | yes | JSON requiring the node's account to be an active member of an AWS Organization or a list. |
| `spiffe.awsIidEksClusterNames` | `STS_SPIFFE_AWS_IID_EKS_CLUSTER_NAMES` | (empty) | yes | EKS clusters one of whose node groups the instance must be in. |
| `spiffe.awsIidEndpoint` | `STS_SPIFFE_AWS_IID_ENDPOINT` | (empty) | yes | An endpoint every AWS client is pointed at instead of the public one. |

### gcp_iit

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.gcpIitProjectIdAllowList` | `STS_SPIFFE_GCP_IIT_PROJECT_ID_ALLOW_LIST` | (empty) | yes | The projects whose tokens are accepted; empty refuses every gcp_iit agent. |
| `spiffe.gcpIitAgentPathTemplate` | `STS_SPIFFE_GCP_IIT_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's `agent_path_template` for gcp_iit. |
| `spiffe.gcpIitUseInstanceMetadata` | `STS_SPIFFE_GCP_IIT_USE_INSTANCE_METADATA` | `false` | yes | Read the instance from the Compute Engine API for `tag:`, `label:` and `metadata:` selectors. |
| `spiffe.gcpIitAllowedLabelKeys` | `STS_SPIFFE_GCP_IIT_ALLOWED_LABEL_KEYS` | (empty) | yes | SPIRE's `allowed_label_keys`. |
| `spiffe.gcpIitAllowedMetadataKeys` | `STS_SPIFFE_GCP_IIT_ALLOWED_METADATA_KEYS` | (empty) | yes | SPIRE's `allowed_metadata_keys`. |
| `spiffe.gcpIitMaxMetadataValueSize` | `STS_SPIFFE_GCP_IIT_MAX_METADATA_VALUE_SIZE` | `128` | yes | A longer allowed metadata value refuses the attestation. |
| `spiffe.gcpIitServiceAccountFile` | `STS_SPIFFE_GCP_IIT_SERVICE_ACCOUNT_FILE` | (empty) | yes | A service account file; empty uses application default credentials. |
| `spiffe.gcpIitCertsUrl` | `STS_SPIFFE_GCP_IIT_CERTS_URL` | `https://www.googleapis.com/oauth2/v1/certs` | yes | Where Google publishes the token signing certificates. |

### azure_imds

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `spiffe.azureImdsTenants` | `STS_SPIFFE_AZURE_IMDS_TENANTS` | (empty) | yes | SPIRE's `tenants`, as JSON from tenant domain to its settings; empty refuses every azure_imds agent. |
| `spiffe.azureImdsAgentPathTemplate` | `STS_SPIFFE_AZURE_IMDS_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's `agent_path_template` for azure_imds. |
| `spiffe.azureImdsAllowedMetadataDomains` | `STS_SPIFFE_AZURE_IMDS_ALLOWED_METADATA_DOMAINS` | `metadata.azure.com` | yes | Domains the attested document's signing certificate must name. |
| `spiffe.azureImdsTrustBundle` | `STS_SPIFFE_AZURE_IMDS_TRUST_BUNDLE` | (empty) | yes | Extra CA certificates trusted beside the embedded DigiCert roots. |
| `spiffe.azureImdsIntermediateHost` | `STS_SPIFFE_AZURE_IMDS_INTERMEDIATE_HOST` | `www.microsoft.com` | yes | The only host the signing certificate's CA Issuers URL may name. |
| `spiffe.azureImdsDiscoveryUrl` | `STS_SPIFFE_AZURE_IMDS_DISCOVERY_URL` | `https://login.microsoftonline.com` | yes | Where a tenant domain's ID is looked up. |

These tables are a copy of the rows in the service's settings table. The live
source is **Protocols → SPIFFE** (`/admin/spiffe`), where every setting is
drawn, and `GET /admin-api/config`. `POST /admin-api/config/set` changes one.
See [Configuration](configuration.md) for how a value is resolved.

## Design decisions

* **A realm is told apart by address, not by path.** gRPC's path is the method
  name, fixed by the specifications, so a realm segment would be a method no
  client calls. A real deployment is the same: one SPIRE server is one trust
  domain.
* **A realm starts with SPIFFE off.** Turning SPIFFE on binds sockets and
  creates an authority. Creating a realm should not open ports or start issuing
  credentials nobody asked for.
* **A new realm gets no TCP gRPC ports and no administrators.** The inherited
  ports and address are already the default realm's. The network-reachable API
  that mints credentials is opened only by somebody who sets an address and
  ports on the realm.
* **The two gRPC surfaces are authenticated differently because their
  specifications say opposite things.** The Workload API must not authenticate
  its caller. A SPIRE server authorizes every method against what the caller is.
  Neither half is a setting.
* **SPIRE's authorization table is copied, not reasoned out.** A table derived
  from what each method "obviously" needs would differ from SPIRE in a few
  places, and a client author could not tell which end was wrong.
* **Attestation is not authentication.** The Unix socket attests the connecting
  process as an agent does. A TCP caller, which cannot be attested, is
  identified by selectors spelt so they cannot pass for attested facts.
* **Node attestation refuses what it cannot verify, in every mode.** A real
  agent pointed at a server that accepted any attestation type could join a
  trust domain with an invented one.
* **No credential is a setting.** Settings are shown on the console, returned
  by the management API and persisted. Cloud keys and tokens come from files or
  from the SDK's own credential chain.
* **A foreign bundle is pushed, never fetched.** Fetching a URL somebody
  registered, to obtain a key that will verify credentials, is a server-side
  request forgery. `http_challenge` is the one exception, and its allow list is
  empty by default.
* **Federated bundles belong to a realm, and none may shadow a served domain.**
  Otherwise one realm could register a bundle under another realm's trust domain
  and mint SVIDs that the other realm would accept.
* **The registry is the directory.** Entries are configuration an `ldapmodify`
  can change, with no cache to go stale. Agents are records, so they are not
  editable.
* **SPIFFE has no revocation, and nothing here pretends to.**
  `spiffeCredentialStatus` records who can no longer be issued an SVID. Short
  lifetimes and rotation are the mechanism. The streams re-send at half the
  lifetime, so clients exercise rotation.
* **An unregistered workload gets an empty SVID list** in product mode, and in
  development with `spiffe.autoCreateEntries` off, because that is what a real
  agent answers. It is the only way to test a client's "I have no identity"
  path.
* **A join token is stored only as a digest**, and its selector is
  `token-sha256:`, so neither the store nor the directory holds a usable token.

## In the running service

* **Protocols → SPIFFE → SPIFFE** (`/admin/spiffe`): the trust domain, the X.509
  and JWT authorities and the trust anchors, whether each of the four sockets
  actually bound, how Workload API callers are identified and attested, the
  federated bundles, and every `spiffe.*` setting. It has
  **Rotate** (X.509, JWT or both) and a form to set or remove a federated
  bundle.
* **Protocols → SPIFFE → Registration entries** (`/admin/spiffe/entries`): which
  workload gets which SPIFFE ID and what an SVID from each entry carries:
  parent, selectors, DNS names, federates-with, the two lifetimes, hint,
  expiry, and the `admin`, `downstream` and `storeSvid` flags. Create, edit and
  delete are here. A change takes effect on the next SVID.
* **Protocols → SPIFFE → Agents** (`/admin/spiffe/agents`): every agent that has
  attested, what it was given and when. **Ban**, **unban** and **delete** are
  the only controls. Deleting an agent lets trust-on-first-use evidence attest
  again.
* **Directory → SPIFFE entries** (`/admin/ldap/spiffe`): both containers as the
  directory holds them, with their attribute schema.
* `GET /spiffe` (add `?format=json`): all three surfaces, the state of every
  socket, every SPIRE method with its authorization row, the six unimplemented
  methods with their reasons, the node attestors this build verifies, and
  whether the Workload API socket is attested.
* The management API: `GET /admin-api/spiffe`,
  `POST /admin-api/spiffe/{action}` (`rotate`, `federation-set`,
  `federation-remove`), `/admin-api/spiffe/entries` and
  `/admin-api/spiffe/agents` with their actions.

`GET /admin/sts-metadata` cannot list the gRPC sockets, because they register no
HTTP route. `GET /spiffe` and `/admin/spiffe` report them. Every SPIFFE failure
is recorded under an `STS-SPIFFE-NNNN` code on the audit row and the log line,
and never sent to a client. See [error codes](error-codes.md).

## Related

* [PKI](pki.md): the Root, the realm Intermediate and the SPIFFE Issuing CA
* [LDAP](ldap.md): the registry under `ou=spiffe` and the workload entries under
  `ou=users`
* [Trust realms](trust-realms.md)
* [TLS and mutual TLS](tls.md)
* [XACML](xacml.md): the access gate after SPIRE's table
* [Sessions](sessions.md)
* [What is not checked](what-is-not-checked.md), especially *The Workload API is
  the opposite case*
* [Configuration](configuration.md)
