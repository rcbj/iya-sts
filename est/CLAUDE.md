# CLAUDE.md — `est/`

**Enrollment over Secure Transport** (RFC 7030, with RFC 8951's clarifications),
added 2026-09-13 as one of the three certificate-enrollment families beside
`acme/` and `scep/`. `docs/est.md` is the user-facing half; this is why it is
built the way it is.

**EVERYTHING THAT IS NOT A WIRE FORMAT IS `common/cert_enrollment.ts`'s.** Who
may be issued a certificate for whom, which names it may carry, whether a
request proves possession, the profiles and the five refused ones, what the
certificate contains, where it is kept, revocation and host names are decided
there and nowhere here. A second reading of any of it in this directory would be
the first of three that come to disagree. `common/CLAUDE.md` argues the core;
the contract it was built to is rcbj's four 2026-09-13 decisions (keys kept only
when generated here, native authentication, CA/OCSP/KDC refused, host names only
when registered).

## The modules

| Module | What it is |
|---|---|
| `est.ts` | The routes. Six operations at `/.well-known/est/` and under `/.well-known/est/:label/`, the checks every operation makes before a credential is read, EST's own authentication, and the answers. Requires `./est_admin` itself, so the family is ONE require in `common/protocol_stack.ts` (23f), followed by two `register()` calls — `est`, then `est_admin` (#50's R1: neither registers anything when required). |
| `est_codec.ts` | **The four wire shapes EST adds and nothing else**: a request body decoded strictly (RFC 8951), a certs-only CMS message, the CSR attributes document and the `multipart/mixed` server-key response. A LIBRARY (rule 3): no route, requires only `helpers.js`. |
| `est_console.ts` | The view and action model both admin doors render — `estView()`, `estMonitorView()`, `estAction()`. No route, no `res`, no markup (`gnap/gnap_console.ts`'s arrangement; `tests/admin_actions_layer.js` allows it to require `admin-core/admin_views`). |
| `est_admin.ts` | `GET/POST /admin/est` (Protocols) and `GET /admin/est/monitor` (Monitoring), drawn in the console shell through `admin.respond()`. |
| `est_api.ts` | `module.exports = { ROUTES }` — `GET /admin-api/est`, `GET /admin-api/est/monitor`, `POST /admin-api/est/:action` — spread into `mgmt-api/admin_api.ts`'s table. Requires `./est_console` LAZILY inside each handler (rule 1). |

## The decisions

* **A LABEL IS A PROFILE, NOT A CA.** RFC 7030 section 3.2.2 lets a server give
  its CAs labels; here there is one EST Issuing CA per realm, and the label says
  what kind of certificate is asked for. An unknown label is 404 (the RFC's
  answer for a label a server does not have); a label naming a refused profile
  or one `est.allowedProfiles` leaves out is 403 through `core.checkProfile()`.
  An UNLABELLED `/cacerts` or `/csrattrs` is never refused for the default
  profile being disallowed — a client asking for the CA is not asking for a
  profile. An unlabelled `/simplereenroll` renews as the profile the renewed
  certificate was issued for.
* **THE ORDER OF THE CHECKS IS A DECISION.** Query string, `est.enabled`,
  transport, label, the operation's own setting, the rate limit, the media type
  and the size are all decided with no credential read and no body decoded; then
  authentication; then the body. An unauthenticated client is never why this
  service parses and verifies a CSR.
* **A BASIC USERNAME IS A PERSON FIRST.** Then an application's `client_id`;
  and a name that is neither still goes to `core.authenticatePerson()`, because
  an administrator of the SERVICE may have no entry in the realm and that is
  where that case is decided. So a person and an application sharing a name
  authenticate as the person. With no `Authorization` header a TLS client
  certificate authenticates (`core.authenticateCertificate()`); with neither, 401
  and `WWW-Authenticate: Basic realm="EST"`.
* **THE CERTIFICATE BEING RENEWED** is the TLS client certificate when one is
  presented (and its entry is the target, so a Basic principal must be that
  entry or an administrator); with Basic alone it is found among the target's
  VALID EST certificates by the subject and names the request repeats — and the
  target is authorized BEFORE its certificates are searched, so a refusal says
  nothing about what somebody else's entry holds. "Repeats" is RFC 7030 section
  4.2.2's "identical": the subject compared attribute by attribute in encoded
  order (`subjectOfCertificate()` reads the certificate with pkijs in
  `parseCsr()`'s own `type=value` spelling), and the subjectAltName compared as a
  set, case-folded where the name is case-insensitive. The renewed serial is
  handed to the core as `replaces`, which supersedes it on the EST CRL.
* **A KEM KEY IS CERTIFIED FOR `key-encipherment` ONLY**, in `/serverkeygen` and
  in the console's issue-server-key. The core would issue an ML-KEM key under a
  `digitalSignature` profile; a certificate whose key usage its key cannot
  perform is refused here (`STS-EST-0017`).
* **THE CODEC WRITES DER BY HAND.** pkijs re-encodes a `Certificate` from its
  parsed fields when it serialises one, and a certs-only message must carry each
  certificate as the CA signed it. `tests/est_codec.js` asserts that byte for
  byte with an ML-DSA certificate.
* **A REQUEST BODY IS DECODED STRICTLY.** RFC 8951 made whitespace legal and no
  other byte; node's lenient base64 skips whatever it does not recognise, which
  turns half a PEM header into a DER value that happens to parse. So: the
  alphabet, `=` at the end, SP/HTAB/CR/LF anywhere, a length that is a multiple
  of four, and a re-encoding that matches (which catches non-zero bits before
  the padding). `application/pkcs10` is in `common/app.js`'s raw-parser list so
  the bytes checked are the bytes sent.
* **REFUSALS ARE PLAIN TEXT, ONE SENTENCE** — RFC 7030 section 4.2.3 asks for "a
  human-readable error message". `estError(req, res, ctx, status, sentence,
  headers)` is the one writer; the code is marked on `res` on the line before
  and read back for the monitor, never put in the body. A refusal at
  400/401/403/409/413/415 is counted against the caller with
  `core.countFailure()` — or, where the throttle is shared across nodes (#46),
  `core.countFailureShared()`, whose answer can turn the refusal into the
  throttle's 429; a 404 label, 405, 501 or 503 is the server's own shape and is
  not.
* **THE WRONG METHOD IS MIDDLEWARE, NOT `app.all()`.** Express 4 records `all` as
  every method it knows on the ROUTE, so `sts_metadata.ts` would list thirty-four
  methods per EST path. A middleware after the routes answers 405 with `Allow`.
* **THE CONSOLE'S ISSUE-SERVER-KEY ANSWERS A 200 PAGE**, not a 303, because its
  answer carries a private key; every other EST action goes through
  `admin.respondToAction()`. The console principal is an administrator by
  construction (the gate required Admin Write for the POST); the API principal
  is `admin-api` (the token gate required `admin:write`).

## A second-factor person's Basic password (2026-09-22, #101)

`common/cert_enrollment.ts`'s three verifications (`authenticatePerson()` and
both halves of `adminFor()`) pass `door: 'est'`, so in product a person who
holds or must hold a second factor — an administrator enrolling for somebody
else included — is refused their own password with the one 401 a wrong
password gets, counted by the enrollment throttle as one, and uses an app
password scoped to `est` or a realm-issued client certificate. The principal
records `appPassword` when one was used. `authn/CLAUDE.md` owns the rule.

## RFC coverage

| RFC 7030 section | Status |
|---|---|
| 3.2.2 operation paths and labels | implemented; a label is a profile |
| 3.2.3 HTTP Basic | implemented (person password, application client secret) |
| 3.3.2 TLS client certificate | implemented (a certificate this realm issued and the entry holds) |
| 3.5 tls-unique channel binding | **not implemented** — TLS 1.3 has no tls-unique (RFC 8446 C.5, RFC 9266); `challengePassword` is ignored |
| 4.1 CA certificates | implemented: EST Issuing CA, realm Intermediate, service Root |
| 4.2.1 simple enrollment | implemented |
| 4.2.2 re-enrollment | implemented, subject and SAN must repeat the renewed certificate |
| 4.2.3 enrollment response | implemented; **202 + Retry-After never sent** |
| 4.3 Full CMC | **not implemented** — 501 |
| 4.4 server-side key generation | implemented, PKCS#8 + certs-only in `multipart/mixed` |
| 4.4.1.2 / 4.4.2 encrypted private key (DecryptKeyIdentifier, AsymmetricDecryptKeyIdentifier) | **not implemented** — refused 501, as the RFC requires, never answered with a clear key |
| 4.5 CSR attributes | implemented, unauthenticated (4.5.1 permits either) |
| RFC 8951 base64 + CTE on responses and parts | implemented; whitespace tolerated in requests |

### Profiles and approaches that cannot be issued over EST

* `root-ca`, `intermediate-ca`, `issuing-ca`, `ocsp-responder`, `kdc` — refused
  over every enrollment protocol by the core, each with its `why`.
* `/admin/pki`'s cryptographic approaches beyond a single key: EST certifies ONE
  public key per request, so the workbench's hybrid (alternative-key) and
  composite-by-construction approaches have no request shape here. (A composite
  ML-DSA key presented in a CSR goes through the core's proof-of-possession
  check like any other; no test here drives one.)
* An ML-KEM key through `/simpleenroll` (no proof of possession, RFC 9935
  section 7) — `/serverkeygen` generates one, for `key-encipherment` only.
* Every requested key usage, extended key usage and basic constraint in a CSR is
  ignored: the profile decides.

## Error codes

`STS-EST-0001`–`0021` for the protocol surface, `0030`–`0033` for the console
and `/admin-api`; refusals decided by the core keep their `STS-ENROLL-*` code.
`tests/error_codes.js` carries `estError(req, res` as a failure pattern.

## Tests

| File | What it holds |
|---|---|
| `tests/est_codec.js` | the strict body decoder (the non-canonical case included), OID encoding, a certs-only message read back by pkijs with each certificate BYTE FOR BYTE (EC and ML-DSA), csrattrs structure, multipart framing |
| `tests/est_handlers.js` | in a child process: every refusal's STATUS AND CODE, plain HTTP answered in development and refused in a product-mode realm, product-mode passwords, a DecryptKeyIdentifier template (501), re-enrollment by client certificate and the supersede, the realm boundary of the certificate listing and the monitor, the Basic header's malformed shapes, the view model's refusals and that no view carries a private key |
| `tests/vendored/sts_est_libest.js` | **Cisco's libest estclient, the reference client** (#209), in the DEFAULT realm (it can name no other): `-g` bootstrapped from the Root and the answer used as the trust anchors after it, `-a` under a label, `-e` by Basic and by a certificate, `-e` with an `openssl` CSR for a registered host (CN the host, UID the entry), `-z`, `-r` and the superseded certificate then refused, `-q` with the key matching the certificate, and the refusals — none, a wrong password (product only), an unknown label, `root-ca`, an unregistered host, a self-signed certificate, `--auth-token`, `--srp` |
| `tests/vendored/sts_est_enrollment.js` | over HTTPS with `est_client.js` (nothing from `est/`): every profile labelled, the application for itself, an administrator for another person, both `/serverkeygen` templates, re-enrollment and the CRL, revocation through `/admin-api`, and the negatives — cross-realm credentials and certificates, a non-enrolled certificate, refused and disallowed profiles, unregistered names, bad PoP, KEM keys, 413/415/400/404/405/501/503, throttling, product-mode wrong password and secret |

Mutants confirmed caught: the canonical base64 check removed and a dropped
certificate (codec); the media-type check removed, the re-enrollment subject
comparison removed, the transport refusal removed, the DecryptKeyIdentifier check
removed, and the KEM-profile check removed from the console (handlers); the
`WWW-Authenticate` challenge removed (protocol job).

## What libest's estclient found (#209, 2026-09-24)

* **`-q` failed "OSSL error: (null)"** and wrote nothing usable: a
  `multipart/mixed` part's last base64 line reached the client unterminated —
  RFC 2046 section 5.1.1 gives the CRLF before a delimiter to the delimiter —
  and OpenSSL 1.1's base64 BIO drops such a line. `est_codec.ts` now ends each
  part's base64 with a CRLF of its own (whitespace RFC 8951 tells a reader to
  tolerate); `tests/est_codec.js` holds it. estclient STILL prints `OSSL
  error: (null)` on a successful `-q`: libest's
  `est_client_verify_key_and_cert()` dumps the (empty) error queue at its
  `end:` label whatever happened. The job accepts that exact line.
* **A realm other than the default cannot be reached by any RFC 7030 client**:
  the well-known URI is at the root (RFC 8615) and estclient takes only a host,
  a port and a label. Documented exception on #209; routing a realm by label
  or host name is an open question there.
* **Three warning lines are the client's**: its note that it has no
  certificate, the `HTTP auth failure` of the 401 that asks for Basic (it never
  sends credentials unasked), and — with only the Root as its trust anchors —
  "unable to get local issuer" on every `-r`, which the RFC's bootstrap (use
  `/cacerts` as the anchors) removes.

## Traps

* **`alice` exists in every development realm** (demo data), so a realm-boundary
  test using her proves nothing: `tests/est_handlers.js` uses a unique name.
* **The address rate-limit bucket is shared by every realm** — it is keyed by the
  client address, not the realm — so a job refusing many requests on purpose
  trips the default 60 in a realm it has not touched. The protocol job raises
  `est.attemptsPerAddress` in each of its realms.
* **The console's user page dumps the whole directory entry**, and in
  development mode nothing is sealed — so `stsEnrolledPrivateKey` was visible
  there when this family was first built. It is WITHHELD now, from every dump
  and every search in every mode (`cert_enrollment.withheldValues()`, called by
  `ldap/ldap_server.js`), and the enrollment attribute names are in
  `ldap_server.js`'s canonical list, so they no longer come back lower-cased.
  The EST view carries no private key either.
* **node's `X509Certificate` cannot read an ML-KEM key**, so the protocol job
  reads the SubjectPublicKeyInfo OID out of the DER itself.
