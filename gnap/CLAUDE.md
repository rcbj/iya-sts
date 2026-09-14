# CLAUDE.md — `gnap/`

**The Grant Negotiation and Authorization Protocol** (RFC 9635) and its
**resource server connections** (RFC 9767), added 2026-09-12. `docs/gnap.md` is
the user-facing half; this is why it is built the way it is.

## What was asked for, and the four decisions that shaped it

rcbj asked for GNAP as a protocol subsystem with an isolated instance per trust
realm; all five RFC 9767 token formats (JWT formats through the existing JOSE
code, the others through libraries where a flexible one exists); every required
and optional feature; browser authentication through the one authn service with
an LDAP entry per person; an application object per GNAP client with GNAP as a
protocol option; positive and negative tests; a new error code subsystem;
`sts_metadata.js` registration; the Authorization Server profiles; sealed
credential attributes; Protocols → GNAP and Monitoring → GNAP console pages; and
CAEP/RISC for GNAP web applications. Asked, rcbj decided:

| Question | Decision |
|---|---|
| What seals `gnapSymmetricKey` / `gnapMacaroonKey` | the **process key-encryption key** (`keystore.seal()`), under the existing rule — sealed only when `keystore.persists()` |
| An unknown client key | **mode-gated**: development creates an application entry on first sight (`mode.autoCreates()`), product refuses `invalid_client` |
| CAEP / RISC | **GNAP sessions emit CAEP**, **GNAP web apps are scoped receivers**, **grant revocation emits CAEP** — and explicitly NOT "signals revoke grants" |
| Where the tests live | **owned here**: `tests/*.js` in process, plus `tests/vendored/` `local: true` jobs with an independent client |

Later in the same session: remembered approvals are stored in `common/consent.js`
as **digest tokens** (`gnap:<22 chars of base64url SHA-256 over the canonical
JSON of one access right>`) — rcbj approved that shape — and **every GNAP
endpoint validates its body against a JSON Schema and sanitises it**.

## The modules

Route-free libraries, each require-able from an in-process test:

| Module | What it is |
|---|---|
| `gnap_sf.js` | RFC 8941 structured fields, written out here — the signature base is the thing both ends must build byte for byte |
| `gnap_httpsig.js` | RFC 9421 sign and verify, RFC 9530 Content-Digest. `tests/gnap_httpsig.js` holds it to the RFC's Appendix B vectors |
| `gnap_keys.js` | key formats, proof method normalisation, thumbprints, the key descriptor every other module takes |
| `gnap_proof.js` | verifies a request's proof — httpsig, mtls, jwsd, jws, and the nested proofs of a key rotation |
| `gnap_schemas.js` | the six ajv 2020-12 JSON Schemas. Types, bounds, URI formats, and **no control character in any string**. No `required` or `enum`: those are the walker's, so a refusal names the RFC section |
| `gnap_request.js` | `checkEnvelope()` (depth/key bounds, then the schema, then the walker) and one parser per document |
| `gnap_access.js` | access rights: covers, intersect, the RFC 9767 token model and its presentation checks |
| `token_macaroon.js`, `token_biscuit.js`, `token_zcap.js` | the three library formats |
| `gnap_tokens.js` | the format dispatcher; the two JWT formats go through `helpers.signJwt` and `common/crypto.js` |
| `gnap_store.js` | twelve `realms.map({ persist })` stores — grants, continuations, interactions, user codes, tokens and their value index, management handles, instances, user references, resource sets, replay |
| `gnap_subject.js` | sub_ids and the `id_token` / `saml2` assertions |
| `gnap_http.js` | the push finish, the only outbound request here, modelled on `ssf/ssf_http.js` |
| `gnap_monitor.js` | per-application counters (`merge: 'own'`), the `xacml_monitor.js` model |
| `gnap_signals.js` | CAEP emission and the SSF subject scope |
| `gnap_grants.js` | the engine: identifying a caller, creating, continuing, modifying and revoking grants, issuing, rotating and deriving tokens |
| `gnap_rs.js` | introspection, registration, and judging a presented token |
| `gnap_console.js` | the view and action layer both admin doors render (no route, no `res`, no markup) |

Route modules: `gnap.js` (required from `common/protocol_stack.js`, **23d**,
after XACML and before logout), which requires `gnap_interact.js` (the
resource-owner pages) and `gnap_admin.js` (the two console pages), then installs
the SSF scope.

**After `admin-ui/admin`** and after `ssf/ssf` — it requires `gnap_admin.js`,
which draws two console pages in the shell, and installs its subject scope on
`ssf/ssf_streams.js` at require time. `mgmt-api/admin_api.js` reaches its view
layer (`gnap_console.js`) lazily, inside the three operations, so the management
API does not move `/gnap` ahead of itself. Requires `gnap_interact.js` and
`gnap_admin.js` itself, so the family is ONE line in the require order.

## Things that cost real time, and would again

* **`macaroon@3`'s `exportBinary()` is broken for V2.** `token_macaroon.js`
  writes the V2 binary encoding itself (`encodeBinaryV2()`), and
  `tests/vendored/sts_gnap_rs.js` decodes it with a decoder of its own.
* **`@biscuit-auth/biscuit-wasm` needs a custom WebAssembly loader** that walks
  `Module.imports`, and every authorization must go through
  `authorizeWithLimits` — Datalog carried in a token is code a holder wrote.
* **`@digitalbazaar/zcap` and the jsonld-signatures stack are ESM**, loaded by
  dynamic import, with an **offline document loader**: the contexts are
  vendored and nothing is fetched.
* **A ZCAP `invocationTarget` must be an absolute URI and an RS identifier
  usually is not.** Minting refused every zcap token for a resource server
  registered under a plain name; a non-URI audience is carried as
  `urn:gnap:rs:<id>` now. Found by `sts_gnap_rs.js`, not by the in-process
  format tests, whose audiences were all URLs.
* **The three library formats REFUSE by returning `{ ok: false }`; the JWT
  formats throw.** Both mint callers only caught a throw, so a refused mint put
  a token with no value into the store and the response. `gnap_tokens.js`'s
  `mintedOrThrow()` turns a returned refusal into a throw.
* **The JWT formats did not validate the model and could mint nothing.** The
  library formats validate in their own `mint()`; the JWT branch signed whatever
  it was handed, and a model with `nbf: null` (a minimal bearer token) put a
  `null` claim in front of jsonwebtoken and came back as an empty value with no
  error. Validation happens in the JWT branch now, a null time is omitted, and a
  signer that produced no JWS throws. Found when the JWT formats were put through
  `tests/gnap_token_formats.js`'s matrix — issuance always sets `nbf`, so no
  over-HTTP job could have reached it.
* **`applications.updateApplication()` refuses a derived attribute.**
  `gnapMacaroonKey` is written by this service, so it goes through
  `applications.seen()` — the door the service writes what it did through —
  and never reached an entry until the RS job asked for it.
* **ajv reports every branch of an `anyOf`.** A control character inside an
  object member came back as "must be string" from the string branch of the
  same union. `validate()` names a control character whenever one was found and
  otherwise reports the deepest path.
* **SSF's gate is synchronous across twelve endpoints; GNAP's resource server
  check is async** (a zcap signature). `gnap_rs.js` is split: `presentation()`
  is everything decidable from this service's own record of the token plus the
  key proof, and is what `ssf/ssf_auth.js` calls; `authenticate()` adds the
  format's own verification.
* **Which refusal is 403.** Only a rights shortfall (`STS-GNAP-0308`) is
  `insufficient_scope`; deciding on the sentence made nearly every format
  refusal a 403, because they begin "the access token …".
* **`req.rawBody`.** A proof covers the exact bytes, so `common/app.js`'s text
  parser keeps them (`verify`), and `common/cors.js` lets `OPTIONS /gnap`
  continue to the discovery handler whatever it decides about the origin.
* **`/:as/gnap` matches `/admin/gnap`.** Reserved first segments fall through
  (`RESERVED_AS_NAMES`); the console route is registered later and still wins.

## Shared Signals

`gnap_signals.js` does three things and its header argues each: grant and
token revocation send CAEP `session-revoked` (session `gnap-grant:<id>` /
`gnap-token:<jti>`), modification sends `token-claims-change`, and the scope
installed with `ssf_streams.setSubjectScope('gnap', …)` refuses a stream owned by
a GNAP web application (a `gnap-client` with a finish URI) any subject who never
approved a grant to it. `ssf/ssf.js`'s `emitProtocolEvent()` is the delivery,
and `ssf/ssf_auth.js`'s `gnap` scheme is how an application owns a stream as
itself. **Nothing listens to CAEP or RISC to revoke a grant**, by decision.

## A person's opaque identifier is over their subject (2026-09-14)

`gnap_subject.js`'s `opaqueIdFor()` HMACs the person's `urn:uuid:` subject where the
directory holds one, and the name only where it does not, and the user reference it
records keeps that subject. So a rename leaves the identifier and the reference naming
the renamed person, and a name deleted and re-created gets a different identifier while
the old reference names nobody — RFC 9635 section 3.4's "SHOULD NOT reuse" held across a
directory edit. Every identifier minted before the change moves once. `account` (an
`acct:` URI, RFC 7565) is a name by definition and still changes with one.
`tests/stable_subject.js` D9–D10.

## Error codes

`STS-GNAP-NNNN`, registered in `common/error_codes.js`:

| Range | Where |
|---|---|
| 0001–0199 | keys, request walkers, subjects, the grant engine, the routes |
| 0200–0299 | HTTP message signatures, Content-Digest, proofs |
| 0300–0399 | access rights and the token formats |
| 0400–0499 | the resource-owner pages |
| 0500–0599 | the RS-facing endpoints and the demonstration resource server |
| 0600–0649 | the push finish |
| 0650–0699 | the console, the monitor, application entries |
| 0700–0749 | signals |

`tests/error_codes.js` carries `gnapError(res` and `interactionError(res` as
failure patterns.

## Tests

| File | What it holds |
|---|---|
| `tests/gnap_httpsig.js` | RFC 9421 / 9530 / 8941, including the Appendix B vectors |
| `tests/gnap_token_formats.js` | one matrix over all five formats (the JWT two through an adapter), and attenuation for the three that attenuate |
| `tests/gnap_request.js` | which layer refuses what — the schemas, control characters, the walkers — RFC 7638's thumbprint and RFC 9635's two interaction hash vectors |
| `tests/realm_isolation.js` | the GNAP stores are per realm and purged with it, and no module-scope Map |
| `tests/vendored/sts_gnap_core.js` | the client instance's whole protocol over HTTP, every refusal by its error code |
| `tests/vendored/sts_gnap_rs.js` | RFC 9767: each token format verified by the job's OWN code, then each accepted, narrowed, rotated, revoked and expired at the demonstration RS; introspection, registration, derivation, mutual TLS |
| `tests/vendored/sts_gnap_signals.js` | a GNAP-owned stream, CAEP on revoke/modify, and the scope, against an unscoped control stream |

The three jobs share `tests/vendored/gnap_client.js` (an independent client
written from the RFCs) and `gnap_flow.js` (the resource owner and harness).

**What is not independently verified:** a zcap token's Ed25519Signature2020
proof needs RDF dataset canonicalization, which the RS job does not write out;
it resolves the verification method to the published key instead and says so.
