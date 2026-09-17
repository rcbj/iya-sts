# CLAUDE.md — `acme/`

**The Automatic Certificate Management Environment** (RFC 8555), with RFC 9773
renewal information, RFC 8738's `ip` and RFC 8823's `email` identifier types,
draft-ietf-acme-profiles and draft-ietf-acme-device-attest's
`permanent-identifier` type, added 2026-09-13. `docs/acme.md` is the user-facing
half; this is why it is built the way it is.

**It is one of three enrollment families** — ACME, EST (`est/`) and SCEP
(`scep/`) — and everything about a certificate that is not a wire format is
`common/cert_enrollment.ts`'s: who may be issued what, what the certificate
says, where it is kept and how it is revoked. This directory is forbidden from
deciding any of that, and `common/CLAUDE.md` is where the core is argued. The
shared contract the three were built against is recorded in the session that
built them; its decisions are restated below where ACME applies them.

## The four decisions, as ACME reads them

| Decision (rcbj, 2026-09-13) | What it means here |
|---|---|
| A private key is kept only when this service generated it | ACME is CSR-only. The CA never sees a key, and nothing on an entry holds one for an ACME certificate |
| Authentication is protocol-native | **External Account Binding is REQUIRED** (`meta.externalAccountRequired: true`). An EAB key is issued for ONE person or application — by that person on the portal, or by an administrator on `/admin/acme` or `POST /admin-api/acme/create-eab` for any entry in the realm — and the account it binds is bound to that entry FOR LIFE |
| The CA, OCSP and KDC profiles are refused | `root-ca`, `intermediate-ca`, `issuing-ca`, `ocsp-responder`, `kdc` answer `invalidProfile` with the reason from `core.REFUSED_PROFILES` |
| A host name is issued only when REGISTERED on the entry | **No challenge dials out.** An identifier the bound entry owns gets a `valid` authorization at `newOrder`; one it does not own fails `newOrder` with `rejectedIdentifier` |

**THE ADMINISTRATOR'S PATH IN ACME IS AN EAB KEY**, and nothing else. EST and SCEP
let an Admin Write holder authenticate and name another entry in the request;
ACME has no such door, because an account is bound to one entry and every
identifier is checked against THAT entry. An administrator issues for somebody
else by creating an EAB key for their entry and handing it to whoever runs the
client. The certificate then names that entry and is kept on it, and the core
records the principal as the entry itself (`admin: false`, `hasEntry: true`).

## The modules

| Module | What it is |
|---|---|
| `acme_jws.ts` | The envelope, read strictly: the media type, the flattened JWS, strict base64url, the protected header, account keys and their RFC 7638 thumbprint, the signature (through `common/crypto.js`), the Replay-Nonce, the External Account Binding, the payload schemas, contacts, RFC 9773 certificate identifiers. A LIBRARY — no route, no state |
| `acme_store.ts` | Seven `realms.map({ persist })` stores: accounts, the key → account index, orders, authorizations, the certificate index, the renewal index, spent nonces |
| `acme.ts` | The fourteen routes under `/enroll/acme`, and `require('./acme_admin')` so the family is one require in `common/protocol_stack.ts` (23e), followed by two `register()` calls — `acme`, then `acme_admin` (#50's R1: neither registers anything when required) |
| `acme_console.ts` | The view and action model both admin doors render (no route, no `res`, no markup), `gnap/gnap_console.ts`'s arrangement |
| `acme_admin.ts` | `/admin/acme` (Protocols) and `/admin/acme/monitor` (Monitoring) |
| `acme_api.ts` | `ROUTES` for `/admin-api/acme`, `/admin-api/acme/monitor` and `/admin-api/acme/:action`, spread into `mgmt-api/admin_api.ts` |

## The routes, and the RFC sections behind each

| Route | RFC | Notes |
|---|---|---|
| `GET /enroll/acme/directory` | 8555 7.1.1, 9773, profiles | `meta.externalAccountRequired`, `website` (`/admin/acme`), `profiles` = the allowed ones of the nine with a description; a POST is 405 |
| `HEAD\|GET /enroll/acme/new-nonce` | 8555 7.2 | 200 / 204 |
| `POST /enroll/acme/new-account` | 8555 7.3, 7.3.1, 7.3.4 | `jwk`; existing key → 200 + Location; `onlyReturnExisting`; `contact` mailto: only; EAB required |
| `POST /enroll/acme/account/:id` | 8555 7.3.2, 7.3.6 | POST-as-GET, contact update, `status: deactivated` |
| `POST /enroll/acme/account/:id/orders` | 8555 7.1.2.1 | the non-invalid orders, `?page=`, `Link rel="next"` |
| `POST /enroll/acme/new-order` | 8555 7.4, 8738, 8823, device-attest, profiles, 9773 5 | identifiers `dns`/`ip`/`email`/`permanent-identifier`; `profile`; `replaces` |
| `POST /enroll/acme/order/:id` | 8555 7.1.3 | status derived on read |
| `POST /enroll/acme/order/:id/finalize` | 8555 7.4 | CSR names exactly the order's identifiers; issued through `core.issue()` |
| `POST /enroll/acme/authz/:id` | 8555 7.5, 7.5.2 | one `sts-entry-binding-01` challenge; deactivation |
| `POST /enroll/acme/challenge/:id` | 8555 7.5.1 | `{}` answers it; `Link rel="up"` |
| `POST /enroll/acme/cert/:id` | 8555 7.4.2, 9.1 | `application/pem-certificate-chain`: leaf, ACME Issuing CA, realm Intermediate — never the Root |
| `POST /enroll/acme/revoke-cert` | 8555 7.6 | by an account bound to the certificate's entry, or by the certificate's own key |
| `POST /enroll/acme/key-change` | 8555 7.3.5 | inner JWS by the new key; a key bound elsewhere → 409 + Location |
| `GET /enroll/acme/renewal-info/:id` | 9773 4 | window = last third of the validity, or an hour in the past when revoked; `Retry-After: 21600` |

Every other method on those paths answers 405 with `Allow`, as section 6.3
requires, rather than Express's `Cannot GET`.

**EVERY ACME RESPONSE CARRIES A FRESH `Replay-Nonce`, `Link rel="index"` AND
`Cache-Control: no-store`** — refusals and the directory included. Section 7.2
asks it of `newNonce`; the rest follows from the nonce being a single-use
credential.

## The decisions inside the family, and the reason for each

### The request pipeline's ORDER is the contract

`authenticate()` in `acme.ts`: media type → size → flattened JWS → protected
header → `alg` → the jwk/kid rule → the nonce's MAC and expiry → `url` → the
account (kid) or the key (jwk) → **the signature** → **the nonce spent** → the
per-identity throttle → the payload. Cheap refusals come first, and the nonce
is SPENT only after the signature verifies: a forged request cannot burn a nonce
a client is holding, and two copies of one signed request cannot both pass.

### The Replay-Nonce carries its own proof

A nonce has to be accepted by whichever process answers the NEXT request — the
front process or any request worker — and a replicated store arrives half a
second to a second late. So a nonce is `version | expiry | 16 random bytes |
MAC(realm, expiry, random)` under the `acme-nonce` secret
`cluster/cluster_secrets.ts` declares, put into `STS_ACME_NONCE_SECRET` before
any worker forks (`ssf/ssf_receivers.ts`'s channel). Any process can check it
with no lookup.

**Single use is the store half** (`acme.usedNonces`) and it CONVERGES rather
than synchronises — the DPoP `jti` set's trade. What a replay inside that window
can achieve is bounded by every resource's own state: an order finalizes once, a
certificate revokes once, an EAB key binds once. A nonce from before a restart
fails its MAC and is answered `badNonce` with a fresh one, which a client
retries (section 6.5).

**Several INDEPENDENTLY started processes behind one load balancer** — the
cluster (#46) — agree on the secret since 2026-09-14: on a postgres store it is
generated once, kept sealed in the store, and read by every node before it
serves (`cluster/CLAUDE.md`). On a store that cannot share it (memory, ldif) it
is per run, and each such process would refuse the others' nonces; the forked
request pool inherits its front process's value, and an operator can set the
variable on every node.

### `sts-entry-binding-01`, and why an authorization is created valid

Section 8's challenges prove control of a name by the CA fetching something.
This service does not dial an address a caller supplied (the root `CLAUDE.md`
non-goal row stays true). Ownership is `core.namesFor()`, run as a DRY RUN per
identifier, so there is one definition of *the entry owns this name* for all
three families: a registered host name, the person's `mail`, the entry's own
identifier. An unowned identifier fails `newOrder` with subproblems rather than
leaving a `pending` authorization no client could ever complete. The challenge
type's name says what happened.

### `permanent-identifier` names the ENTRY

draft-ietf-acme-device-attest defines it for a device serial. Here its value is
the bound entry's username or application identifier (or its `urn:sts:` URN),
and it becomes the certificate's `urn:sts:` subjectAltName — which the core adds
to EVERY certificate anyway, so the identifier is how an order asks for a
certificate that names nothing else.

### The CSR must name exactly the order's identifiers

Section 7.4, read as a set: every dNSName, iPAddress, rfc822Name and `urn:sts:`
URI in the CSR, plus the common name if there is one, must each be an identifier
of the order, and every identifier of the order must be named. A name of a kind
an order cannot contain is `badCSR`. **The one exception is the UPN otherName on
a `smartcard-logon` order**: it is not an ACME identifier type, and the core
holds it to the entry's `userPrincipalName` or `mail` (a person created through
`/admin-api` has no `userPrincipalName`, so it is the mail). The certificate's
content is built from the ORDER's identifiers and the entry, never copied from
the CSR.

### Profiles that need an identifier say so at `newOrder`

`tls-server` and `tls-server-client` need a `dns` or `ip` identifier, `email`
needs an `email` identifier, and `smartcard-logon` needs a person with
`userPrincipalName` or `mail`. The core would refuse all three at finalize; saying
so at `newOrder` (`malformed`, `STS-ACME-0045`) is what a client can act on.

### Revocation reasons a subscriber may give

0 `unspecified`, 1 `keyCompromise`, 3 `affiliationChanged`, 4 `superseded`,
5 `cessationOfOperation`, 9 `privilegeWithdrawn`. Refused as
`badRevocationReason`: 2 and 10 (an AUTHORITY's compromise), 6 (the one
reversible reason; nothing here un-holds), 7 (unassigned), 8 (delta CRLs only)
and anything above 10. The console and `/admin-api` action accepts every RFC
5280 reason, because an operator is not a subscriber.

**A revokeCert names a certificate by its DER, and the DER must be the one
recorded** — a certificate with the right serial and different bytes is not this
service's certificate and answers 404.

### RFC 9773 `replaces` does not revoke

The core's `replaces` supersedes (revokes) the old certificate. ARI's `replaces`
is a statement about renewal, and a client rolling over needs the old
certificate to keep working until it deploys the new one. So the order records
it, the old certificate index row gets `replacedBy`, a second order replacing it
is `alreadyReplaced` (409), and nothing is revoked.

### Account keys

RS256–RS512, PS256–PS512, ES256/384/512 (curve pinned to the algorithm) and
EdDSA (Ed25519). RSA of at least 2048 bits. `none`, every HMAC, ES256K and the
post-quantum algorithms are `badSignatureAlgorithm` with the list: **an account is
found by its key's RFC 7638 thumbprint**, and `AKP` has no thumbprint. A `jwk`
with a private member is `badPublicKey`, and only the required public members
are stored.

### An empty payload needed one line in `common/crypto.js`

`verifyCompactJws()` parsed the payload as JSON after the signature verified, so
a POST-as-GET — whose payload is the empty string — would have been refused after
verifying. It takes `emptyPayload: true` now, which answers `claims: null` for an
empty payload and changes nothing for any caller that does not pass it. ACME
still never hand-rolls a signature check.

## The documented exceptions

**Parts of the specifications not implemented, and why:**

| Not implemented | Why |
|---|---|
| `http-01`, `dns-01`, `tls-alpn-01` (RFC 8555 section 8, RFC 8737) | No challenge dials out; ownership is the directory entry (rcbj's decision) |
| `email-reply-00` (RFC 8823 section 3) | Nothing is sent to the address; an address is owned when it is the person's `mail` |
| `device-attest-01` and the attestation statement | Only the identifier type is used, to name the entry |
| `notBefore` / `notAfter` in an order | Refused `malformed`: the validity is `acme.certificateLifetimeDays`, clamped to the Issuing CA |
| `newAuthz` pre-authorization (7.4.1) | Not advertised: every authorization is created by the order that needs it |
| `termsOfService` in `meta` | This service has none; `termsOfServiceAgreed` is accepted and recorded |
| Alternate certificate chains (`Link rel="alternate"`, 7.4.2) | There is one chain per realm |
| The `processing` wait with `Retry-After` on finalize | Issuance is synchronous; the order is `valid` in the finalize response |
| Wildcard `dns` beyond an exactly registered `*.name` | A wildcard is issued only when written so on the entry |
| A non-mailto contact | `unsupportedContact`; section 7.3 lets the server choose |
| Account key recovery, and orders listed across deactivation | Out of scope for a service whose accounts are bound to entries an operator manages |

**`/admin/pki` profiles and approaches that cannot be issued over ACME:**

| Not over ACME | Why |
|---|---|
| `root-ca`, `intermediate-ca`, `issuing-ca` | The holder could issue certificates for anybody (`core.REFUSED_PROFILES`) |
| `ocsp-responder` | A delegated responder could sign `good` about a revoked certificate |
| `kdc` | The holder could impersonate the realm's KDC over PKINIT |
| A key-encapsulation key (ML-KEM) | It cannot sign, so it cannot make the CSR's proof of possession (RFC 9935 section 7) — `badPublicKey`. EST `/serverkeygen` is the route |
| A server-generated key pair | ACME is CSR-only by decision; EST `/serverkeygen` |
| A post-quantum ACCOUNT key | Its key type has no RFC 7638 thumbprint (the certificate KEY may still be ML-DSA or composite: the core verifies those CSRs) |
| An X.509 attribute certificate, a CA-signed CSR template, arbitrary extensions | The certificate's content is decided by the profile and the entry, never the CSR (`core` ignores requested KU/EKU/BC) |

## Several nodes: the nonce, the finalize and the EAB binding (2026-09-14, #46)

Three things this family spent by reading a replicated store and writing it
back, which two nodes both did inside the change log's window:

* **A Replay-Nonce** — `authenticate()` is ASYNCHRONOUS now (every handler
  that calls it is `async` and awaits it) because the nonce is spent through
  `acme_store.spendNonceOnce()`: the local `usedNonces` map first (no round
  trip for the ordinary replay), then a claim in the store. A claim another
  request holds is the replay it always was (`STS-ACME-0018`); a store that
  cannot be asked is `serverInternal` (`STS-ACME-0099`) — never `badNonce`, which
  would send a client round a retry loop against a store that is down.
* **A finalize** — the "ready" check and the "processing" write are an await
  apart (the CSR parse), so two finalizes of one order, each with its own fresh
  nonce, issued TWICE even on one node. The order is claimed once everything
  that refuses without side effects has run; a claimed order is
  `orderNotReady` (`STS-ACME-0098`), and a refused issuance gives the claim back
  with the order.
* **The EAB binding** — `core.bindEabOnce()` (`common/CLAUDE.md`). Its one
  cost: the same account retrying newAccount at a second node before the
  binding has replicated is refused once as a second account.

## Error codes

`STS-ACME-NNNN` in `common/error_codes.js`, between `// ===== ACME ====` and
`// ===== EST ====`. The core's own `STS-ENROLL-*` codes are kept on a refusal
the core made (a CSR it could not verify, a name it would not issue, the
transport rule, the throttle) — `coreRefusal()` maps its status onto an ACME
error type and marks the core's code.

| Range | Where |
|---|---|
| 0001–0003 | the gate: turned off, transport and throttle fallbacks |
| 0010–0028 | the envelope and resource ownership |
| 0030–0038 | accounts and the External Account Binding |
| 0040–0049 | orders |
| 0050–0056 | finalize, authorizations, challenges |
| 0060–0065 | revocation |
| 0070–0074 | key change |
| 0080–0082 | renewal information, the orders list |
| 0090–0097 | the console, the management API, an unexpected throw |
| 0098–0099 | several nodes: a finalize already claimed, a claim store that could not be asked |

`tests/error_codes.js` carries `acmeProblem(ctx` and `refusal('<type>', <status>`
as failure patterns.

## Tests

| File | What it holds |
|---|---|
| `tests/cluster_single_use_credentials.js` | a nonce another node claimed refused here, and one EAB key bound by one of two concurrent accounts, against a stub store with postgres's semantics |
| `tests/acme_jws.js` | the envelope's refusals one by one, RFC 7638's and RFC 9773's published values, the nonce's proof (another realm, a flipped bit, a version, an expiry at a chosen instant), the EAB's five shapes and a wrong MAC key, identifier values, and the seven stores per realm and purged with it |
| `tests/acme_protocol.js` | a CHILD PROCESS running the whole stack on a plain-HTTP port, driven by the independent client: every refusal by type, realm isolation at the door, finalize and the chain verified by OpenSSL, revocation (by account, by key, alreadyRevoked), key change and its 409, deactivation, renewal information, the monitor, `acme.enabled`, **product mode refusing plain HTTP** (which the HTTPS job cannot reach), and the console pages through their own handlers — the EAB key answered once on a 200 no-store page and absent from every view |
| `tests/vendored/sts_acme_enrollment.js` | over HTTPS against the running service: all nine profiles chained to the realm Intermediate and the Root with their EKUs, the UPN equal to the person's mail, an application for itself, OCSP `good` then `revoked`, the serial on `/pki/crl/{realm}/acme.crl` after revokeCert and after the console action, every refusal the brief lists, the expired nonce and the expired EAB key, the throttle, and a product-mode realm over TLS |
| `tests/vendored/acme_client.js` | the independent client: RFC 8555 flattened JWS signed with node's crypto (RS256, PS256, ES256, ES384, EdDSA), RFC 7638, the EAB MAC, the badNonce retry, key change, RFC 9773's identifier; CSRs through the vendored `x509.js` and a KEM CSR built with pkijs |

## Things that cost real time, and would again

* **The CSR set check first compared in ONE direction.** Every order identifier
  had to be named, and nothing checked that every CSR name was an identifier —
  so a CSR with an extra `dNSName` finalized, and the extra name simply did not
  appear (the core builds from the order). `tests/acme_protocol.js` found it on
  its first run; `csrNamesProblem()` checks both directions now.
* **`res.type('application/pem-certificate-chain')` on a string body appends
  `; charset=utf-8`**, which section 9.1's registration does not have. The
  header is set exactly and the body sent as a Buffer.
* **A JSON value written through the `Write` tool with `\u0000` in a regex
  arrives as a literal NUL byte**, which makes the file invisible to `grep`
  (`common/CLAUDE.md` records the same trap). The patterns here use `\x00`.
* **`acme_console.ts` cannot require `acme.ts` at load**: `acme.ts` requires
  `acme_admin.ts`, which requires the console model, so a require at load hands
  back the half-built exports. The console model reads the URLs lazily.
* **`acme_admin.ts` may not require `admin-core/admin_views.ts`**
  (`tests/admin_actions_layer.js` names the files that may), so the console
  session's actor is read through `acme_console.consoleActorOf()`.
* **The console's POST handler is asynchronous** (a revocation awaits the CA),
  so it answers from a promise and catches into a 303 rather than letting an
  unhandled rejection hang the request.
