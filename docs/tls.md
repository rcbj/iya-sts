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

With HTTPS on there is no plain listener left except `/pki/` on `pki.httpPort`,
so the first fetch of the certificate is made with verification off:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
curl --cacert /tmp/sts.pem https://localhost:8081/healthcheck
```

`tls.minVersion` (TLS 1.2 by default) and `tls.ciphers` apply to the main
port, LDAPS and the debugger's listener alike. A cipher list that matches
nothing stops the service at startup, naming the setting.

**The cipher list is BCP 195 by default.** TLS 1.3's three suites come
first, and TLS 1.2 is limited to the four ECDHE AES-GCM suites RFC 9325
section 4.2 recommends. The server's order wins, so a client that speaks TLS
1.3 gets it. This is what the FAPI 2.0 Security Profile requires of a server
(section 5.2.2), and it is the default for every listener, not only in a
FAPI realm: a cipher suite belongs to the socket, not to a realm.
`tls.minVersion=TLSv1.3` requires TLS 1.3 alone.

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
* **`GET /tls/server-certificate`** publishes the leaf (first), the chain and
  the Root — everything a client needs to build a truststore, and never a
  private key. If the Root is rebuilt (`build-root` on `/admin/pki`), every
  socket is re-keyed onto the new hierarchy for the next handshake.
* **Names and addresses**: `tls.hostnames` (`localhost`, `sts`, `sts-mock`,
  `sts.example.com`) and `tls.ips` (`127.0.0.1`) go into the subjectAltName;
  the CN is the first host name.
* **A certificate somebody else issued**: set `tls.certificateFile` and
  `tls.keyFile` together (one alone is refused at startup). The file may be a
  chain, leaf first, and all of it is sent. A supplied certificate is never
  re-issued under this service's Root.
* **A random 128-bit serial**, so a browser that trusted a previous start's
  certificate does not meet `SEC_ERROR_REUSED_ISSUER_AND_SERIAL`.

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
one. What happens to a certificate that is presented:

* **The handshake always completes.** A certificate that verifies against the
  truststore is *known*; one that chains to nothing still completes the
  handshake and can still bind a token under RFC 8705 section 3.
* **It is refused where it is used**: RFC 8705 client authentication at the
  token endpoint, `/xacml`, `/scim/v2` and `/tls/sign-in` each decide for
  themselves, carrying OpenSSL's own reason (`authorizationError`) out whole.
* **A verified certificate is recorded as an authentication** when the
  connection is established — once per connection, not per request — under
  protocol `TLS` on `/admin/users`.
* A certificate is **never** read from a forwarded header (`X-Client-Cert` and
  its relatives) in any mode. Behind a balancer, TLS has to be passed through.

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
An anchor added in one process reaches the others through the directory.

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
session starts no second one.

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
  this host. The README's *Behind an L4 load balancer* section has the AWS NLB
  recipe.

### Not implemented

* **Refusing an unverified client certificate at the handshake.** The main port
  carries every protocol, most of whose callers present no certificate; the
  refusal happens where the certificate is used. The two listeners that did
  this (8443 asking, 9443 requiring) were deleted on 2026-09-16.
* **A connection report.** `/tls/whoami`, which described what the server saw
  of a connection, went with those listeners and has no successor here.
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
| `tls.ciphers` | `STS_TLS_CIPHERS` | BCP 195: the TLS 1.3 suites, then `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM-SHA{256,384}` | no | An OpenSSL cipher list for those sockets, in the server's order; empty means node's own list (see the warning above). One matching nothing stops startup. |
| `tls.trustAnchorsFile` | `STS_TLS_TRUST_ANCHORS_FILE` | *(empty)* | no | A PEM file of CA certificates client certificates are verified against, loaded at startup; unreadable or empty is fatal. |
| `tls.trustIssuedClientCertificates` | `STS_TLS_TRUST_ISSUED_CLIENT_CERTIFICATES` | `true` | no | Add this service's Root to the client truststore, so a certificate a person issued on the portal signs them in. |
| `tls.selfSignedKeyBits` | `STS_TLS_SELF_SIGNED_KEY_BITS` | `2048` | no | The RSA key size of the listener certificate made at startup. |
| `tls.selfSignedValidityYears` | `STS_TLS_SELF_SIGNED_YEARS` | `2` | no | How long that certificate is valid. |
| `tls.selfSignedOrganization` | `STS_TLS_SELF_SIGNED_ORGANIZATION` | `sts` | no | The O= of its subject. |
| `global.trustProxy` | `STS_TRUST_PROXY` | `false` | yes | Believe `X-Forwarded-Proto` and `X-Forwarded-Host` from a TLS-terminating proxy. |
| `global.trustedProxies` | `STS_TRUSTED_PROXIES` | *(empty)* | yes | The addresses or CIDRs forwarded headers — and PROXY protocol headers — are believed from. |
| `global.proxyProtocol` | `STS_PROXY_PROTOCOL` | `off` | no | `v2` expects a PROXY protocol v2 header on every TCP listener, read before TLS. |
| `global.proxyProtocolTimeoutMs` | `STS_PROXY_PROTOCOL_TIMEOUT_MS` | `30000` | yes | How long a trusted proxy may take to send a complete header. |
| `pki.revocationCheck` | `STS_PKI_REVOCATION_CHECK` | `auto` | yes | Whether a presented certificate is checked for revocation: `off`, `soft-fail`, `hard-fail`, or `auto` (hard in product, soft in development). |
| `pki.revocationRequireDistributionPoint` | `STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT` | `false` | yes | Under hard-fail, also refuse a foreign certificate that names no CRL distribution point. |
| `pki.revocationFetchTimeoutMs` | `STS_PKI_REVOCATION_FETCH_TIMEOUT_MS` | `3000` | yes | How long a fetch of a foreign CRL may take; a request waits on it the first time. |

The remaining `pki.revocation*` settings tune OCSP, CRL caching and LDAP
distribution points; they are on `/admin/pki` and in the README's settings
table. This table is a copy of rows in `common/config.js`; the live source is
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
