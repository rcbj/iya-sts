---
title: TLS and mutual TLS
---

# TLS and mutual TLS

iya-sts serves its **main port over TLS**
([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), TLS 1.2 and 1.3) with a
certificate issued by its own certificate authority, and **asks every connection
for a client certificate while requiring none**. Presenting one is the client's
decision: `GET /tls/sign-in` signs the holder of a verified certificate in, and
[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) binds tokens to it. The same
certificate is presented by LDAPS on 636 and by the embedded debugger's
listener, so one trust anchor covers every socket. The socket and its truststore
are **shared by every trust realm**; the session a certificate starts goes in
the realm of the authority that signed it.

## Features

### HTTPS on the main port

`global.https` makes the main port (`global.port`, 8081) HTTPS. Its built-in
default follows `oauth2.rfc9700` / `oauth2.oauth21`, and every appconfig file
this repository ships turns it on — so the port is HTTPS unless
`STS_HTTPS=false`. It is one listener in one scheme, never both.

The main port presents the same certificate as LDAPS 636 and the embedded
debugger's listener, so trusting this service is one decision for every socket
rather than three, and a caller who has trusted it for the other sockets does
not meet an unencrypted one on the port every protocol family answers on.

It costs one unverified call, necessarily. With HTTPS on there is no plain
listener left except `/pki/` on `pki.httpPort`, and in development the key does
not exist until the process starts, so nothing can hold an anchor for it in
advance. The first fetch of the certificate is made with verification off, and
everything after it is verified:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
curl --cacert /tmp/sts.pem https://localhost:8081/healthcheck    # verified from here on
export NODE_EXTRA_CA_CERTS=/tmp/sts.pem                          # for a node client
```

`GET /tls/server-certificate` exists so that a caller can put the certificate in
its own truststore rather than switching verification off, which is the habit
this workflow exists to break. It is on the main port because that is the port
reachable before anything is trusted.

`STS_HTTPS=false` restores the plain port, and it is a supported configuration
rather than an escape hatch: a client that cannot be taught to trust a
per-start certificate is exactly the thing this service exists to exercise.

`tls.minVersion` (TLS 1.2 by default), `tls.ciphers`, `tls.groups` and
`tls.signatureAlgorithms` apply to the main
port, LDAPS and the debugger's listener alike, and each binds `global.host`. A
cipher list that matches nothing stops the service at startup, naming the
setting.

### The listeners: TLS 1.2, the TLS 1.3 suites, post-quantum only, client certificates

**Server configuration → Listeners** (`/admin/listeners`,
`GET /admin-api/listeners`, #423) lists every socket this service answers on and
what each one is held to. Its settings are **runtime**: a change reaches every
listener at its next handshake, with no restart and no rebind.

| Setting | Default | What it does |
|---|---|---|
| `tls.disableTls12` | **on** (since #429) | Every TLS listener negotiates TLS 1.3 only, whatever `tls.minVersion` says. Off lets a client negotiate TLS 1.2 (see the warning below). |
| `tls.tls13CipherSuites` | `TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256` | The TLS 1.3 suites, ticked and numbered on the page; the server's order wins. Any of RFC 8446's five, CCM included. At least one is required. |
| `tls.pqcOnly` | off | TLS 1.3 only, the 256-bit suites only, and the ML-KEM groups only (see below). |
| `tls.mainPortDisableOptionalClientCertificate` / `tls.mainPortRequireClientCertificate` | off / off | The main port: send no CertificateRequest / require a certificate that chains to the client truststore. |
| `ldap.ldapsDisableOptionalClientCertificate` / `ldap.ldapsRequireClientCertificate` | **on** / off | LDAPS: the same pair. LDAPS asks for nothing by default, as it always did. |
| `debugger.disableOptionalClientCertificate` / `debugger.requireClientCertificate` | off / off | The protocol debugger's listener. |

"Require" wins over "do not ask". A required certificate is verified against the
client truststore (Protocols → TLS / mutual TLS → the truststore, and the
certificates this service issues), so a handshake without one is refused.

> **Warning.** Requiring a client certificate on the main port refuses every
> browser without one, discovery, the JWKS and every public document, and a
> load balancer's or container's HTTPS health check. Turning off "ask" on the
> main port stops RFC 8705 certificate-bound tokens and client authentication,
> `GET /tls/sign-in`, EST with a certificate and the remote XACML PEP there.

**What "post-quantum safe" means for a TLS 1.3 suite.** A suite names only the
record protection, the AEAD and its hash. Grover's algorithm halves a symmetric
key, so `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` (256-bit
keys) keep 128 bits against a quantum adversary and are marked post-quantum safe;
the AES-128 suites keep 64 and are not. CNSA 2.0 allows AES-256 alone. What stops
a session recorded today being decrypted later is the key EXCHANGE, so
`tls.pqcOnly` also keeps only the ML-KEM groups of `tls.groups` (X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM512/768/1024) and turns TLS 1.2 off,
which has no ML-KEM group. It does not restrict the signature algorithms: a
handshake cannot be forged after the fact. A choice that leaves nothing
post-quantum is refused (`STS-TLS-0043`), and one reaching the service from the
environment stops it (`STS-TLS-0042`).

> **Warning.** `TLS_AES_128_CCM_8_SHA256` has an 8-byte tag and RFC 8446 says it
> is not for general use; choose it only for a client that offers nothing else.

**The SPIFFE gRPC listeners and the channel between cells** take the TLS 1.2,
suite and post-quantum settings too, and have no client-certificate toggles:
their protocols decide. The SPIRE Server API must reach an agent with no SVID
yet, and the Broker API and the cell channel always require a certificate. The
cell channel is TLS 1.3 always.

**EVERY SETTING IS PER LISTENER (#429).** Each TLS listener has its own row for
every setting above and its TLS settings below, named `listener<Id>.<setting>`.
For example, `listenerLdaps.disableTls12` or `listenerMain.tls13CipherSuites`.

- **Listeners:** `Main`, `Ldaps`, `Debugger`, `SpiffeServer`, `SpiffeBroker`,
  `Cell`.
- **Inheritance:** each row inherits the service-wide value until it is set.
  `inherit` in a list of choices, or an empty box, means inherit.
- **Truststore:** a listener's own `trustAnchorsFile` replaces the service's
  file anchors for that listener alone. The runtime anchors from `/tls/trust`
  are shared by every listener.
- **Where they are edited:** Server configuration → Listeners has a tab per
  listener. Each tab shows what is in force there first, then its own rows.
  The *Service-wide defaults* tab holds what every listener inherits.
- **What some listeners lack:** the cell channel is TLS 1.3 always, so it has
  no TLS 1.2 rows. The SPIFFE listeners and the cell channel verify clients
  against their protocol's trust bundle, so they have no truststore rows.

> **Warning.** Turning TLS 1.2 on, service-wide or for one listener, lets a
> client negotiate it. FAPI 2.0 and BCP 195 still allow TLS 1.2 with the AES-GCM
> suites, but TLS 1.2 has no post-quantum key exchange.

**A custom listener** (#472 — the service's, or a realm's own) carries the
same settings in its definition's `tls` block, by their short names
(`disableTls12`, `pqcOnly`, `tls13CipherSuites`, ...), and its client
authentication as `clientAuth` (`none`, `optional`, `required`): see
[Listeners and hosted applications](listeners.md). Each has a tab of its own on
the Listeners page with the policy in force.

**The TLS 1.2 cipher list is BCP 195 by default** (`tls.ciphers`, the TLS 1.2
list alone since #423). TLS 1.3's suites come
first, and TLS 1.2 is limited to the four ECDHE AES-GCM suites RFC 9325
section 4.2 recommends. The server's order wins, so a client that speaks TLS
1.3 gets it. This is what the FAPI 2.0 Security Profile requires of a server
(section 5.2.2), and it is the default for every listener, not only in a
FAPI realm: a cipher suite belongs to the socket, not to a realm.
`tls.minVersion=TLSv1.3` requires TLS 1.3 alone.

**The key exchange is post-quantum first** (`tls.groups`, #212). The three
hybrid groups OpenSSL 3.5 implements — X25519MLKEM768, SecP256r1MLKEM768 and
SecP384r1MLKEM1024 — form the first tuple, X25519 and P-256 the second, X448,
P-384 and P-521 the third. A client that supports a hybrid but sent only an
X25519 key share is asked, with a HelloRetryRequest, for the hybrid one. The
finite-field groups are not offered. TLS 1.2 never negotiates a hybrid (they
are TLS 1.3 groups), and uses the curves in the same order.

**The signature algorithms leave out DSA and SHA-224** (`tls.signatureAlgorithms`,
#212). OpenSSL's default list advertised both in every TLS 1.2
CertificateRequest, and with them a `dss_sign` certificate type — an
invitation to answer the main port's certificate request with a DSA
certificate, an algorithm FIPS 186-5 no longer approves for signing.

**A client certificate on a curve outside the NIST set is refused** (#212).
Certificates whose EC key is on a curve other than P-256/P-384/P-521 (and the
other NIST-named curves) are refused before any certificate object is built (a
third-party runtime defect found by #212; details are held privately by the
maintainer). The rule covers the whole certificate CHAIN, not only the leaf:
every listener that asks for a certificate — the main port and the debugger's
— closes such a connection (`STS-TLS-0035`), whatever
`tls.signatureAlgorithms` says. Separately, brainpool is omitted from the
offered signature schemes by policy.

> **Warning.** Emptying `tls.groups` or `tls.signatureAlgorithms` restores
> node's and OpenSSL's defaults, with the finite-field groups, one hybrid
> group of three, and DSA and SHA-224 back in the lists above.

> **Warning.** An empty `tls.ciphers` means node's own list, and any other
> value replaces BCP 195's. Either can allow CBC-mode and non-forward-secret
> suites that BCP 195 recommends against, and a FAPI 2.0 deployment then no
> longer meets section 5.2.2. Widen it only to test an old client.

### The server certificate

* **Issued under this service's Root CA**, through a process Intermediate and a
  TLS Issuing CA rather than any one realm's, because the sockets that present
  it are shared by every realm. The chain (leaf, Issuing CA, Intermediate) goes
  on the wire, so a client that holds only the Root can build a path.
* **One anchor covers the main port, LDAPS 636, the debugger listener and every
  token this service signs.** In development mode the hierarchy is rebuilt at
  every start; where the keystore persists, it survives a restart.
  It is not a file in the image or the repository, because a certificate
  committed to a repository is a private key committed to a repository.
* **`GET /tls/server-certificate`** publishes the leaf (first), the chain and
  the Root — everything a client needs to build a truststore, and never a
  private key. It is served `Cache-Control: no-store`, since a cached copy
  outlives the key it describes. A truststore holding only the leaf builds no
  path, and fails with `unable to get local issuer certificate` about a Root it
  was never given. If the Root is rebuilt (`build-root` on `/admin/pki`), every
  socket is re-keyed onto the new hierarchy for the next handshake.
* **LDAPS presents the same certificate and key**, not a second pair, so one
  fetch is one anchor for `https://` *and* `ldaps://`; two key pairs would make
  an `ldapsearch` fail against a truststore built for the HTTPS port with the
  same `unable to get local issuer certificate`, which names nothing. The
  private key is held in memory by the process and nothing writes it to a
  response.
* **Names and addresses**: `tls.hostnames` (`localhost`, `sts`, `sts-mock`,
  `sts.example.com`) and `tls.ips` (`127.0.0.1`) go into the subjectAltName;
  the CN is the first host name.
* **A certificate somebody else issued**: set `tls.certificateFile` and
  `tls.keyFile` together (one alone is refused at startup). The file may be a
  chain, leaf first, and all of it is sent. A supplied certificate is never
  re-issued under this service's Root.
* **A random 128-bit serial**, so a browser that trusted a previous start's
  certificate does not meet `SEC_ERROR_REUSED_ISSUER_AND_SERIAL`.
* **The key is kept across restarts, per node, where minted state is.** In
  product mode on postgres, and in a cluster, each node makes its listener key
  once and keeps it in the database, encrypted under the key-encryption key
  like every other stored secret, under its node name (`cluster.nodeName`, or
  the host name; `STS_CLUSTER_NODE_NAME`). A node never holds another node's
  key. A restart presents the same key and, while it is still current, the
  same certificate. The certificate is re-issued over the same key when the
  Root or the TLS Issuing CA is rebuilt, when `tls.hostnames` or `tls.ips`
  change, and when less than a third of its validity is left. A new key is
  made when the database volume is wiped, when the node is renamed, when
  `tls.selfSignedKeyBits` or `tls.certificateAlgorithms` changes the key, and
  at every start in development, `memory` or `ldif` mode. **Give every node a
  name of its own**: two nodes with one name would share a listener key.
* **A changed certificate is announced over Shared Signals.** A receiver
  subscribed to `tls-certificate-changed` is told once the port is bound
  (`reason: restarted`) when a start presents a certificate other than the
  one last announced, and whenever the certificate is re-issued while the
  service runs. The last certificate announced is kept in the store, so this
  works only where minted state survives a restart (product mode on
  postgres, a cluster). In a cluster a node's start is announced whenever
  another node announced after it, because each node has its own listener
  key. **Pin the Root, not the leaf.** [Shared Signals](shared-signals.md)
  has the event.

### When a browser refuses the certificate

A browser trusts this service's certificate only once the service's **Root
CA** is in its trust store. Until then it refuses the certificate during the
handshake, and the service logs one line per refused connection:

```
[STS-TLS-0034] tls: the client at 172.29.0.1 REFUSED this service's certificate on the main port (8081) (it sent the TLS alert certificate_unknown, 46). …
```

(`unknown_ca`, 48, from OpenSSL and curl; `certificate_unknown`, 46, from
Chrome.) Because browsers open several connections at once, expect a few of
these per page load. To trust the Root:

```bash
curl -k https://localhost:8081/tls/server-certificate > sts-chain.pem   # leaf, chain, Root — the Root is LAST
# Chrome and Chromium on Linux read the NSS database:
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "iya-sts Root" -i sts-root.pem
```

Save the last certificate in `sts-chain.pem` as `sts-root.pem` first. Or
import it under `chrome://settings/certificates` → Authorities. Reach the
service by a name the certificate carries (`tls.hostnames`, `tls.ips`); a
laptop's host name or LAN address fails as a name mismatch instead. In
development mode the Root is rebuilt at every start, so re-import after a
restart; in product mode it survives restarts, but not `down -v` or a
`build-root`.

`STS-TLS-0021` is every OTHER failed handshake: a version or cipher
mismatch, or a client not speaking TLS.

### Post-quantum server certificates

`tls.certificateAlgorithms` is `rsa` by default and accepts `ml-dsa-44`,
`ml-dsa-65` and `ml-dsa-87` beside it. **More than one is the useful setting**:
with `rsa,ml-dsa-65`, OpenSSL serves whichever certificate matches the signature
algorithms the client offered, so an ordinary client gets RSA and a
post-quantum one gets ML-DSA ([RFC 9881](https://www.rfc-editor.org/rfc/rfc9881))
over the same port — how a migration actually runs. Each ML-DSA certificate is
also a leaf of the TLS Issuing CA.

* ML-DSA needs node 24 (OpenSSL 3.5), which the image uses; on an older runtime
  the algorithm is skipped with a warning and RSA is served.
* `GET /tls/server-certificate` returns **every** certificate; a truststore
  built from the first alone may not verify the connection a client actually
  gets.
* LDAPS on 636 serves the first certificate only.
* Nothing reports the post-quantum posture of a connection's key exchange any
  more; `GET /tls` and `/admin/crypto-metadata` list the certificates.

### Client certificates on the main port

The port is bound asking for a certificate and accepting a connection without
one (`requestCert: true, rejectUnauthorized: false`), so presenting one is the
client's decision and mutual TLS happens where every other protocol already
arrives. What a certificate is worth is decided where it is used:

| Where | What it takes |
|---|---|
| `GET /tls/sign-in` | a certificate that verified starts a sign-on session (below) |
| the token endpoint | RFC 8705: `tls_client_auth` and `self_signed_tls_client_auth` authenticate a client, and a token is bound to whatever certificate the connection carried |
| `/xacml/*` and `POST /xacml/pip` | a verified chain whose subject DN resolves to an entry holding `REMOTE_PEPS` or `XACML_USER` |
| `/scim/v2` | RFC 7644 section 2's client-certificate scheme |

Presenting a certificate anywhere else signs nobody in, and does nothing at all
at a route that reads no certificate. `GET /tls` describes all of it — what this
service presents, what it trusts, the protocol floor, the revocation policy —
and takes `?format=json`.

What happens to a certificate that is presented:

* **The handshake always completes.** A certificate that verifies against the
  truststore is *known*; one that chains to nothing still completes the
  handshake and can still bind a token under RFC 8705 section 3.
* **It is refused where it is used**: RFC 8705 client authentication at the
  token endpoint, `/xacml`, `/scim/v2`, `/tls/sign-in` and a GNAP key proved by
  mutual TLS under `gnap.mtlsTrust=pki` ([GNAP](gnap.md#mutual-tls-trust)) each
  decide for themselves, carrying OpenSSL's own reason (`authorizationError`)
  out whole.
* **A verified certificate is recorded as an authentication** when the
  connection is established — once per connection, not per request — under
  protocol `TLS` on `/admin/users` (see *Recording a verified certificate*
  below).
* A certificate is **never** read from a forwarded header (`X-Client-Cert` and
  its relatives) in any mode. Behind a balancer, TLS has to be passed through.
* **A handshake that fails is logged**, with OpenSSL's own reason
  (`tlsClientError`), and recorded as a refusal on the audit log. Such a
  handshake never reaches a handler, so without that it is invisible from both
  ends: the caller sees a closed socket and the server says nothing. On this
  port a client certificate is never required, so what lands there is a broken
  handshake rather than a refused credential.

### Recording a verified certificate

`/admin/users` answers "who has this service seen, in an interaction that
succeeded", and a mutual-TLS client whose certificate verified is exactly that.
So when a handshake completes with a certificate that verified, its subject is
filed through the same authentication record every other family uses, under
protocol `TLS`, and the embedded directory seeds an entry for it. It is a
**record** of what happened, not a credential: nothing consults the record or
the entry to decide anything (`/tls/sign-in` is what signs somebody in), and
`GET /tls` says so.

* It is recorded **at the handshake**, not per request. The handshake is where
  the credential was accepted, so a connection carrying six requests is one
  authentication, and a client that opens six connections presented its
  certificate six times.
* It is recorded **only when the certificate verified**; nothing is written for
  a certificate that failed or was never sent.
* The identity is the subject in **RFC 4514 form** — leaf first, no spaces after
  the commas, values escaped. That is a *different string* from the display DN
  shown beside it and from the one `openssl x509 -subject` prints.

**Where the directory entry goes.** A certificate subject is already a DN, but
it usually names an object in somebody *else's* directory:
`CN=alice,O=Example Corp,C=US` is not under `dc=example,dc=com`. So a subject
that already lies under this directory's base DN (with its parent present) is
created **at it, unchanged**; anything else is named by the subject's `CN` — or
its leaf RDN where there is none — under `ou=users`, with every other RDN kept
as an attribute and the full subject, issuer, serial, validity and fingerprint
written on as `x509*` attributes. Those names are this service's own: there is
no standard attribute for "the DN inside the certificate", and the standard one
for the certificate itself, `userCertificate`, is binary and transferred as
`userCertificate;binary`, so base64 under that name would be a value no client
could parse. The CN is preferred over the leaf RDN because openssl puts
`emailAddress` **last** in a subject, so the leaf RDN of a typical client
certificate is the address. What that costs is a collapse — two certificates
whose CNs match, from two different CAs, land on one entry — and it is made
visible: both subjects are listed under `x509subject`, and the console still
files them as two identities because it keys on the whole DN. A renewed
certificate for the same subject makes no second entry; its serial, validity
and fingerprint are **appended**, so the entry shows the history.

### The client truststore

The anchors client certificates are verified against. It **starts empty** and
is filled from four places:

| Source | When | Survives a restart? |
|---|---|---|
| `tls.trustAnchorsFile` | read at startup; the product-mode way to fill it | yes — the file brings it back |
| `/admin/tls/trust`, `POST /admin-api/tls/trust/{add,remove}` | at runtime, in both modes, gated by the console / an admin token | yes — written to the directory (`ou=trustAnchors` in the default realm) and restored before any listener binds |
| `POST /tls/trust` (a PEM body, or a `certificates` form field) and `POST /tls/trust/clear` | at runtime, **development mode only** | added anchors, yes |
| this service's own Root CA | always, while `tls.trustIssuedClientCertificates` is on | — |

The gated doors are strict: a bundle with one block that cannot be read is
refused whole. There is **no bulk clear** on them — removing is one row at a
time — and removing an anchor from the file lasts only until the next start.
The console page needs Admin Write to change anything, and the API needs an
`admin:write` token (`admin:read` to list). An anchor added in one process
reaches the others through the directory; with request workers, both doors are
answered by the front process, which is the one that holds the listener.

**Why it starts empty.** The certificate authority whose clients it verifies is
often generated in somebody's *browser* minutes before the connection, and
exists nowhere else, so no configuration file could hold it and no image could
bake it in. `POST /tls/trust` takes one or more PEM certificates (raw, or as the
`certificates` field of a form or JSON body) and applies them to the listener;
existing connections keep the truststore they were made under, and the next
handshake is judged against the new one. `POST /tls/trust/clear` empties it.
"Empty" is meant literally: node's bundled public root store is **not** used,
since a public root has no business verifying a client certificate from a
private CA, so the starting state is "nothing verifies". With HTTPS on, the
first POST of an anchor is made with verification off, as the first fetch of
the server certificate is.

**The service Root in the truststore** lets a person present the TLS client
certificate they issued themselves on `/portal/signing-key`. Every key pair this
service issues chains to the same Root, so the chain alone is not an identity:
only a leaf from a TLS client Issuing CA with `clientAuth` signs anybody in.

### Signing in with a certificate: `GET /tls/sign-in`

A request with a verified certificate starts a sign-on session — the same
session the password screen, the KDC and the SAML profiles start, so the holder
is signed in to every surface on the port. In order:

1. **revocation** is consulted (below); a refused certificate starts no session
   and is not recorded as an authentication;
2. **the identity gate**: a certificate this service issued must come from a TLS
   client Issuing CA; anything else issued here is reported as
   `refusedAsIdentity`;
3. **an application's certificate signs nobody in** — it is an RFC 8705 client
   credential, reported as `session.application`;
4. **the session starts in the certificate's realm**: for a certificate this
   service issued, the realm whose Issuing CA signed it and the person it names;
   for one from an anchor somebody installed, the default realm and the
   certificate's common name (the record keeps the full RFC 4514 subject).

The answer is **JSON**: `signedIn`, the session, whether a certificate was
presented and verified, the `x5t#S256` thumbprint the token endpoint would bind
a token to, and the revocation verdict. A caller that presents no certificate is
simply not signed in, and the answer says so. The session carries
`amr ["swk"]` (a software key) and `acr "1"`. A browser that already holds a
session keeps it and starts no second one.

**Why a client needs this answer.** A client knows what it sent. What it cannot
see is which chain the server built out of it, which anchor it verified against,
or whether the certificate was accepted at all. Under **TLS 1.3** it has not
even been told: the client sends its Certificate and Finished *last*, so its
handshake is complete before the server has said anything, and the verdict
arrives afterwards — as a post-handshake alert, or as a bare hang-up, which is
what node's own TLS server does. `GET /tls/sign-in` answers the one question of
that family this service answers: *did my certificate arrive, and as what.*

### Revocation is consulted

A presented certificate is checked for revocation under `pki.revocationCheck`
before it is used — at `/tls/sign-in`, when the connection is recorded, and by
every door that turns a certificate into an identity. A certificate this service
issued is looked up in its own register; one from another authority is checked
with the OCSP responder and the CRLs it names, so **a first request can wait on
those fetches** (each bounded by `pki.revocationFetchTimeoutMs`, then cached).

It is not done at the handshake: OpenSSL's CRL check would demand a list for
every issuer and fetches nothing. So the handshake completes, and the session,
the recorded identity and the request are what get refused. See [PKI](pki.md).

### Reverse proxies and load balancers

* **L7 (TLS-terminating) proxy**: `global.trustProxy` believes
  `X-Forwarded-Proto` and `X-Forwarded-Host`, and `global.trustedProxies`
  narrows that to the proxy's own addresses. `GET /tls/forwarded` shows what a
  request carried and what was believed. A client certificate cannot cross such
  a proxy.
* **L4 load balancer with TLS passthrough** — the supported front for client
  certificates: `global.proxyProtocol=v2` reads a HAProxy PROXY protocol v2
  header before TLS on every TCP listener (the main port, LDAP 389 and LDAPS
  636, the KDC's TCP 88, the debugger and the revocation listener), so the
  client's address is known and mutual TLS still terminates on the node. A
  connection from outside `global.trustedProxies` is closed, except one from
  this host. [Behind an L4 load balancer](configuration.md#behind-an-l4-load-balancer--the-proxy-protocol)
  has the AWS NLB recipe.

### Not implemented

* **Refusing an unverified client certificate at the handshake.** Refusing
  there is a property of a socket, and the main port carries every protocol:
  `rejectUnauthorized: true` would refuse every caller that presents no
  certificate, which is almost all of them. A certificate that does not verify
  is refused at the doors that use it — the same answer, one layer up. What is
  lost is the proof that a certificate was acceptable before any handler ran,
  and with it the chance to exercise a client's own mutual-authentication
  verdicts against a server that insists: `required`, and
  `required-and-rejected` (the case an operator hits most). Only
  `not-required`, the main port's posture, is reachable here.
* **A connection report.** No endpoint reports what the server made of a
  handshake (the request as it arrived, what TLS negotiated, the client
  certificate exactly as presented). It is a debugging surface rather than a
  protocol, and is being taken up in a separate project; nothing here should be
  read as pointing at a replacement.
* **Separate TLS ports.** There is no `tls.port` or `tls.mutualPort`; a
  deployment that sets `STS_TLS_PORT` or `STS_MTLS_PORT` gets an "unknown
  setting" warning at startup rather than a silent no-op.
* **Client certificates on LDAPS.** Port 636 asks for none.

## Development and product mode

| | Development | Product |
|---|---|---|
| `POST /tls/trust`, `POST /tls/trust/clear` | answer anybody | **403**, naming `tls.trustAnchorsFile`; use the file or the gated doors |
| Revocation (`pki.revocationCheck=auto`) | **soft-fail**: revoked is refused, an undeterminable status is accepted and reported | **hard-fail**: an undeterminable status is refused too |
| Which realm's mode decides the truststore | the **default** realm's, because the anchors are one list for the whole process | the same |

Everything else — the certificate, the sign-in order, the identity gate, the
refusal of an application's certificate — is the same in both modes. See
[What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `global.https` | `STS_HTTPS` | on when `oauth2.rfc9700` or `oauth2.oauth21` is (every shipped appconfig sets it on) | no | Serve the main port over HTTPS with the shared certificate, asking for a client certificate and requiring none. |
| `tls.hostnames` | `STS_TLS_HOSTNAMES` | `localhost,sts,sts-mock,sts.example.com` | no | The subjectAltName DNS entries of the shared certificate. |
| `tls.ips` | `STS_TLS_IPS` | `127.0.0.1` | no | The subjectAltName IP entries. |
| `tls.certificateAlgorithms` | `STS_TLS_CERT_ALGS` | `rsa` | no | Which server certificates to present: `rsa` and any of `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`. |
| `tls.certificateFile` | `STS_TLS_CERT_FILE` | *(empty)* | no | Serve a certificate (or chain) somebody else issued; set with `tls.keyFile`. |
| `tls.keyFile` | `STS_TLS_KEY_FILE` | *(empty)* | no | The unencrypted PKCS#8 or PKCS#1 key for `tls.certificateFile`. |
| `tls.minVersion` | `STS_TLS_MIN_VERSION` | `TLSv1.2` | no | The lowest TLS version the main port and LDAPS negotiate. |
| `tls.ciphers` | `STS_TLS_CIPHERS` | BCP 195: `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM-SHA{256,384}` | no | The TLS 1.2 cipher list for those sockets, in the server's order; empty means node's own TLS 1.2 list (see the warning above). A TLS 1.3 name is refused (`tls.tls13CipherSuites`). One matching nothing stops startup. |
| `tls.disableTls12`, `tls.tls13CipherSuites`, `tls.pqcOnly` and the client-certificate pairs | see *The listeners* above | | **yes** | Server configuration → Listeners. |
| `tls.groups` | `STS_TLS_GROUPS` | `X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024 / X25519:P-256 / X448:P-384:P-521` | no | The key-exchange groups, post-quantum hybrids first (see below); empty means node's `auto`. |
| `tls.signatureAlgorithms` | `STS_TLS_SIGALGS` | OpenSSL's list without DSA and SHA-224, brainpool omitted by policy | no | The signature schemes signed with, accepted, and asked for in a CertificateRequest; empty means OpenSSL's. |
| `tls.trustAnchorsFile` | `STS_TLS_TRUST_ANCHORS_FILE` | *(empty)* | no | A PEM file of CA certificates client certificates are verified against, loaded at startup; unreadable or empty is fatal. |
| `tls.trustIssuedClientCertificates` | `STS_TLS_TRUST_ISSUED_CLIENT_CERTIFICATES` | `true` | no | Add this service's Root to the client truststore, so a certificate a person issued on the portal signs them in. |
| `tls.selfSignedKeyBits` | `STS_TLS_SELF_SIGNED_KEY_BITS` | `2048` | no | The RSA key size of the listener certificate made at startup. |
| `tls.selfSignedValidityYears` | `STS_TLS_SELF_SIGNED_YEARS` | `2` | no | How long that certificate is valid. |
| `tls.selfSignedOrganization` | `STS_TLS_SELF_SIGNED_ORGANIZATION` | `sts` | no | The O= of its subject. |
| `tls.sessionTicketRotationS` | `STS_TLS_SESSION_TICKET_ROTATION_S` | `3600` | yes | In an active-active cluster, how often the session-ticket key every node's LDAPS listener and main port share is replaced (the old key is deleted); `0` shares nothing. Outside active-active nothing is shared. |
| `tls.mainPortSharedTickets` | `STS_TLS_MAIN_PORT_SHARED_TICKETS` | `true` | no | The main port seals its session tickets under the cluster's shared key, so a session resumes on any node. `false` keeps a key per node. |
| `tls.sessionTimeoutS` | `STS_TLS_SESSION_TIMEOUT_S` | `300` | yes | How long a TLS session may be resumed, on every TLS listener that does not set its own (`listener<Id>.sessionTimeoutS`; `-1` inherits). It was `tls.mainSessionTimeoutS`, the main port's alone, until #429. |
| `tls.sessionCacheSize` | `STS_TLS_SESSION_CACHE_SIZE` | `2048` | yes | How many TLS 1.2 session IDs a listener keeps for resumption; `0` keeps none and resumes by ticket only. Per listener as `listener<Id>.sessionCacheSize`. Not on the SPIFFE listeners: grpc-js offers no session-ID cache. |
| `tls.resumedChainWaitMs` | `STS_TLS_RESUMED_CHAIN_WAIT_MS` | `2000` | yes | How long a request on a session resumed from another node waits for that session's client-certificate chain to replicate; `0` never waits. |
| `http.keepAliveTimeoutS` | `STS_HTTP_KEEP_ALIVE_TIMEOUT_S` | `60` | yes | How long an HTTP listener keeps an idle HTTP/1.1 connection for the next request; pipelined requests are answered in order. It was `global.httpKeepAliveTimeoutS`, the main port's alone, until #429. |
| `http.headersTimeoutS` | `STS_HTTP_HEADERS_TIMEOUT_S` | `0` | yes | How long a request's headers may take to arrive; `0` is the keep-alive timeout plus one second, and a value at or below the keep-alive is raised to that. |
| `http.maxRequestsPerSocket` | `STS_HTTP_MAX_REQUESTS_PER_SOCKET` | `0` | yes | How many requests one connection may carry before it is closed; `0` is no limit. |
| `http.maxConnections` | `STS_HTTP_MAX_CONNECTIONS` | `0` | yes | How many connections an HTTP listener holds at once; `0` is no limit. |
| `global.trustProxy` | `STS_TRUST_PROXY` | `false` | yes | Believe `X-Forwarded-Proto` and `X-Forwarded-Host` from a TLS-terminating proxy. |
| `global.trustedProxies` | `STS_TRUSTED_PROXIES` | *(empty)* | yes | The addresses or CIDRs forwarded headers — and PROXY protocol headers — are believed from. |
| `global.proxyProtocol` | `STS_PROXY_PROTOCOL` | `off` | no | `v2` expects a PROXY protocol v2 header on every TCP listener, read before TLS. |
| `global.proxyProtocolTimeoutMs` | `STS_PROXY_PROTOCOL_TIMEOUT_MS` | `30000` | yes | How long a trusted proxy may take to send a complete header. |
| `pki.revocationCheck` | `STS_PKI_REVOCATION_CHECK` | `auto` | yes | Whether a presented certificate is checked for revocation: `off`, `soft-fail`, `hard-fail`, or `auto` (hard in product, soft in development). |
| `pki.revocationRequireDistributionPoint` | `STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT` | `auto` | yes | Under hard-fail, whether a CA-issued foreign certificate that names no CRL and no OCSP responder is refused: `auto` in product mode, `on` in both; **`off` accepts certificates nobody can ever revoke**. |
| `pki.revocationFetchTimeoutMs` | `STS_PKI_REVOCATION_FETCH_TIMEOUT_MS` | `3000` | yes | How long a fetch of a foreign CRL may take; a request waits on it the first time. |

The remaining `pki.revocation*` settings tune OCSP, CRL caching and LDAP
distribution points; they are on `/admin/pki` and in
[*Every setting*](configuration.md#every-setting). This table is a copy of rows in `common/config.js`; the live source is
`/admin/tls` and `GET /admin-api/config`.

See [Configuration](configuration.md) for how a value is resolved and where it
is changed: on `/admin/tls` (or `/admin/config` for `global.*`), through
`POST /admin-api/config/set`, or in an appconfig file.

## Design decisions

* **Ask for a certificate, require none.** RFC 8705 needs a certificate asked
  for on the port where tokens are issued, and every other protocol answers on
  that same port; requiring one would refuse almost every caller.
* **A certificate is refused where it is used, not at the handshake.** A
  handshake refusal is a property of the whole socket; each door that turns a
  certificate into an identity refuses it instead, with the reason.
* **A verified certificate is a sign-in, but only when asked.** It was once a
  side effect of reaching a listener; a sign-in that happens because somebody
  loaded a page is one nobody asked for, so it is a route of its own.
* **One certificate, one anchor, every socket.** The main port, LDAPS and the
  debugger share one certificate under one Root, so a caller trusts this
  service once rather than three times.
* **The certificate is under a process Intermediate, not a realm's.** One
  realm's authority signing the front door every realm uses would be that realm
  vouching for all the others.
* **Revocation is checked before a session starts, not at the handshake.**
  OpenSSL's handshake CRL check demands a list for every issuer and fetches
  nothing; checking after the handshake lets foreign certificates be checked
  by OCSP and fetched CRLs.
* **The chain alone is not an identity.** Every key pair this service issues
  chains to its Root; only a TLS client certificate, and never an
  application's, signs a person in.
* **The test-control truststore is closed in product mode.** An anchor anybody
  can add is a client certificate anybody can make verify, and anchors decide
  who a remote PEP or a SCIM caller is; product fills it from a file or through
  the gated doors.
* **No bulk clear on the gated doors.** A clear reaches every client
  certificate every other caller relies on.
* **No certificate is ever read from a header.** A forwarded certificate is one
  anybody can forge, so client certificates require TLS passthrough.
* **One LDAPS session-ticket key for the whole cluster, and none outside
  one.** Behind a balancer that picks a node per connection, a ticket sealed
  under one node's own key cannot be opened on the other, so resumption
  worked about half the time. In active-active mode the nodes' LDAPS
  listeners share one key, kept
  sealed in the store and replaced every `tls.sessionTicketRotationS` by the
  `tls.ticket-key-rotate` job; the old key is deleted, which bounds how long a
  resumed session's secrets can be recovered from a captured ticket. Anywhere
  else each listener keeps OpenSSL's own keys, which never leave the process.
  Each node still presents its own listener key, so a client that checks a
  second node's handshake against the first node's key fails; resumption
  does not care. **The main port shares the key too since #406
  (2026-10-02)** (`tls.mainPortSharedTickets`). It asks for a client
  certificate, and a resumed session carries only the leaf, so the chain the
  full handshake verified is replicated to every node (`tls.presentedChains`)
  and a request on a session resumed elsewhere waits up to
  `tls.resumedChainWaitMs` for it before its revocation check. The debugger's
  listener still keeps a key per node.
* **The main port keeps connections and sessions for 60 seconds (#406).**
  A browser holding a client certificate under one of the CAs the main port
  names is asked by Firefox whether to send it on every FULL handshake; a
  resumed session carries no CertificateRequest. With node's five-second
  keep-alive and a ticket key per node, a person clicking through the
  console or the portal behind a balancer was asked on nearly every click.
  `http.keepAliveTimeoutS` keeps an idle HTTP/1.1 connection 60
  seconds (pipelined requests are answered in order), `tls.sessionTimeoutS`
  lets a session resume for 300 seconds, and the shared key lets it resume on
  any node. Keep a load balancer's idle timeout above the keep-alive (an AWS
  NLB's is 350 seconds). HTTP/2 is not offered: express cannot run on node's
  own HTTP/2 server (#407).
* **The serial is random.** A constant serial made Firefox refuse the port after
  a restart with an error no "accept the risk" could get past.

## In the running service

* **Protocols → TLS / mutual TLS** (`/admin/tls`): the certificate the main
  port and LDAPS present, what the service does with a client certificate, and
  the `tls.*` settings. Whether the port is HTTPS at all is `global.https` on
  `/admin/config`.
* **Protocols → Client-certificate truststore** (`/admin/tls/trust`): every
  anchor with subject, issuer, serial, validity, SHA-256 fingerprint and source
  (`file` or `runtime`), an add form, and a Remove per row, in either mode. The
  service Root added by `tls.trustIssuedClientCertificates` is not listed there;
  `GET /tls` reports it.
* **Live descriptions**: `GET /tls` (what is presented, trusted and done with a
  client certificate), `GET /tls/server-certificate`, `GET /tls/forwarded`,
  `GET /tls/sign-in`.
* **Related pages**: `/admin/crypto-metadata` lists every certificate
  configured; `/admin/pki` issues and revokes; `/admin/users` shows TLS
  authentications.
* **Management API**: `GET /admin-api/tls`, `GET /admin-api/tls/trust` and
  `POST /admin-api/tls/trust/{add,remove}` — see `/admin-api/openapi.json`.
* Failures are recorded under `STS-TLS-NNNN`, `STS-PKI-NNNN` and
  `STS-PROXY-NNNN` codes — see [Error codes](error-codes.md).

## Related

* [OAuth security profiles](oauth-security.md) — RFC 8705 client
  authentication and certificate-bound tokens
* [PKI](pki.md) — the certificate authority and revocation
* [Sessions](sessions.md) — the session a certificate starts
* [Authentication](authentication.md) — the other ways to sign in
* [SCIM](scim.md), [XACML](xacml.md) and [Remote PEP](remote-pep.md) — doors
  that authenticate by client certificate
* [LDAP](ldap.md) — LDAPS on 636 presents the same certificate
* [Trust realms](trust-realms.md) — what a shared socket means for realms
* [AWS cluster](aws-cluster.md) — the load-balanced deployment
* [Configuration](configuration.md) — `global.https`
