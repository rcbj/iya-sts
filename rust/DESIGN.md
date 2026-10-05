# The Rust runtime — design (#444)

**Status: PROPOSED, 2026-10-05; decisions D1–D4 settled the same day. Nothing in this directory is built, shipped or
tested yet.** This is phase 0 of [#444](https://github.com/rcbj/iya-sts/issues/444):
the design the conversion is held to. Every later phase updates this file in the
same commit that changes the decision it records.

## 1. What is being converted, and what is not

| Part | Today | After |
|---|---|---|
| Protocol handlers — every family in the root `CLAUDE.md` table, every raw socket (KDC 88, LDAP 389/636, SPIFFE gRPC, the cell channel, the revocation listener) | Node, one process plus `worker_threads` | **Rust**, `sts-runtime` |
| `/admin-api` and its OpenAPI document | Node (`mgmt-api/`) | **Rust**, same contract |
| The scheduler, every scheduled job, every cache, the store, the cluster | Node | **Rust**, in the runtime process |
| Remote XACML PEP (`xacml-pep/`) | Node container | **Rust**, `xacml-pep` binary, same container contract |
| Admin console `/admin`, user portal `/portal` | Node, in the service process, calling ~73 modules in process | **TypeScript single-page applications**, compiled to static files when the image is built, **served by the runtime**, talking to it **only through the management API** (owner, 2026-10-05). No Node process at runtime. **The console's source and build stay Node.js / TypeScript for good, and it is converted on the Node service first (#446)** |
| Embedded debugger (`debugger/`) | Parent project's build output served by Node | **Unchanged.** It is another project's artifact. The runtime starts it as a child process, as today. |
| `tests/vendored/` (the protocol half of the suite) | Runs against a URL | **Unchanged.** It is the oracle for equivalent behaviour. |

### The requirements this design must meet (from #444)

1. **Every cryptographic option available today is available after the conversion** (section 6).
2. **The same security model and the same authentication on every protocol surface**, in both `development` and `product` mode. That includes the turnstiles table in the root `CLAUDE.md` and every predicate in `common/mode.js`.
3. **The scheduler and every cache live in the runtime process.**
4. **Well-organized, object-oriented code that people can read and change later**, in the spirit of #50: a family is a type, its dependencies arrive through its constructor, and one composition root builds everything.
5. **Well-known libraries wherever one exists** (section 7). Where none does, the reason is written down next to the code.

### Size

About 400,000 lines of non-test service code, plus 386,000 lines of tests. The
largest parts are `common/` (226k), `admin-ui/` (83k, which becomes a TypeScript SPA),
`oauth-oidc/` (66k), and `xacml/`, `gnap/`, `spiffe/`, `mgmt-api/` and
`kerberos/` at 27k–30k each. The conversion cannot be one change. It is a
sequence of phases, each of which leaves a service that passes the suite
(section 10).

## 2. The end state

```
              :8081 HTTPS (and realm listeners, 88, 389/636, gRPC, 8082, 8446)
                                        │
         ┌──────────────────────────────▼──────────────────────────────┐
         │                     sts-runtime (Rust)                       │
         │  listeners · TLS · realm layer · CSP · every protocol family │
         │  /admin-api  /account-api  · scheduler · caches · store      │
         │  /admin/*, /portal/*  ── the two SPAs' static files          │
         │  the portal's backend-for-frontend: OIDC client, token holder│
         └──────────────────────────────▲──────────────────────────────┘
                                        │ same origin; console: DPoP-bound
                                        │ token, portal: session cookie
                     ┌──────────────────┴──────────────────┐
                     │  browser: console SPA · portal SPA   │
                     │  (TypeScript, built at image build)  │
                     └──────────────────────────────────────┘
```

* **One process.** The console and portal are TypeScript single-page
  applications, compiled when the image is built into static files the
  runtime serves at `/admin/` and `/portal/` (owner, 2026-10-05). There is no
  Node process at runtime. The paths, the origin and the cookies stay as they
  are today, so the OIDC redirect URIs and the suite's URLs do not move.
  **The console is converted on the Node service first (#446)**, which
  serves the same static files on the same paths. Its source and its build
  stay Node.js / TypeScript for good; only its output is in the runtime's
  image. The build tool is esbuild, as a bundler, with no front-end
  framework (owner, 2026-10-05): the console's existing renderers are kept.
* **The SPAs talk to the runtime only through the management API**
  (`/admin-api`, `/account-api`, section 5). Everything they show comes from
  an API response, and everything they change goes through an API call.
* **The console is a public client, and its tokens are bound to a key the
  browser cannot export (decision D9, REVERSED for the console by the owner
  the day it was made, #446).** The console runs the authorization code
  flow with PKCE and no client credential, holds its access and refresh
  tokens in memory only, and proves possession of a DPoP key (RFC 9449) on
  every call. The key is a WebCrypto key generated as non-extractable, so a
  script injected into the page can use a token while the page is open and
  cannot take one away. Refresh tokens rotate and are bound to the same
  key. `/admin-api`'s gate is unchanged — it already verifies `cnf.jkt` —
  and the roles it enforces are the person's. No cookie carries authority
  on `/admin-api`, so the console has no CSRF token. Three things follow,
  each the owner's decision:
  * In a realm with a FAPI profile on, the seeded console client is the one
    public client `fapi.js` allows, and the console is documented as not
    conforming there.
  * `adminApi.authRequired=false` is honoured in development mode only,
    because the API's gate is now the console's only gate.
  * The console's static files are public, so nothing secret is built into
    them.
* **The portal's tokens never reach the browser (decision D9, as first
  made).** The runtime is the portal's backend-for-frontend, as the IETF's
  *OAuth 2.0 for Browser-Based Applications* recommends: the portal stays a
  confidential OIDC client of the runtime's own authorization server, as
  today (`private_key_jwt`, PKCE), the runtime holds the person's access and
  refresh tokens server-side against an `HttpOnly`, `SameSite`, `Secure`
  session cookie, and an API call from the portal carries that cookie and is
  answered with the PERSON's token's authority — never a credential of the
  portal's own. A script injected into the page has no token to steal. A
  cookie-carried call that changes state also carries a CSRF token.
* **The SPAs run script, and nothing else here does (decision D10).** Every
  page of this service works without JavaScript today (`script-src 'none'`,
  thirteen argued exceptions). A single-page application cannot, so `/admin/`
  and `/portal/` get `script-src 'self'` — the SPA's own bundled files, never
  `'unsafe-inline'` and never another origin — and `frame-ancestors` and
  `base-uri` stay as everywhere. This is a deliberate REVERSAL of the
  works-without-script rule for those two surfaces, written down in the root
  `CLAUDE.md` when the SPAs land; every other surface keeps `script-src
  'none'`.
* **The runtime re-checks `frame-ancestors` on every response**, as `app.js`
  does today when a response is flushed.
* **The server-drawn pictures** (delegation map, federation diagram,
  geography map) are drawn by the SPA from API data, or served by the API as
  SVG, decided in the phase that moves each.

## 3. Getting there: a replacement, not a migration

**The owner's decision, 2026-10-05: no installation survives the transition.
Nobody runs this service yet, and the conversion should finish quickly.** That
removes the hardest constraint a migration has, and this section is shaped by
its absence:

* **No coexistence.** The Rust runtime does not join the Node cluster, and
  Node does not dispatch to it. The two are separate images. The Node service
  stays on `develop`, working, until the cutover, and is then deleted.
* **No data compatibility.** Nothing written by Node has to be read by Rust.
  The postgres schema, the minted-state rows, the LDAP entry encoding and the
  sealed-value formats belong to the Rust runtime and may change wherever a
  better design calls for it. `postgres/schema.sql` is the starting point, not
  a contract.
* **What IS still a contract**: everything a client, an operator or the
  console sees — every URL, port, protocol message, setting key, environment
  variable, error code and `/admin-api` operation. That is what the protocol
  suite tests, and it is why the suite stays the oracle.

### 3.1 How progress is measured

The protocol suite (`tests/vendored/`) drives a service over HTTP, raw TCP and
gRPC at a URL. **Each phase runs the suite against the Rust image**, and a
phase is done when the jobs for the families it moved pass there. The jobs not
yet ported fail against the Rust image, and the number passing is the progress
report. The Node image keeps passing every job on `develop` until the cutover.

About 175 of the suite's files set up their realms, users and settings through
`/admin-api` before they test anything. So the management API's realm, user,
application and settings operations come early (phase 3), before the families
whose jobs depend on them can pass.

### 3.2 The cutover

Phase 9 switches `Dockerfile`, the compose files and CI to the Rust runtime
with the two SPAs built into it, deletes the Node runtime and its in-process
tests, and from then on the full suite runs against Rust in every mode.

## 4. The organisation of the code

### 4.1 One Cargo workspace, a crate per responsibility

```
rust/
  Cargo.toml                     workspace; versions pinned once in [workspace.dependencies]
  crates/
    sts-core/                    settings table and its five layers, Mode predicates,
                                 error codes, the realm context, version, logging
    sts-crypto/                  every algorithm (section 6) behind traits; no I/O
    sts-pki/                     CA hierarchy, X.509, CRL, OCSP, CMS, PKCS#10/#12
    sts-store/                   Store trait: memory, ldif, postgres; RealmMap<T>;
                                 the change log; minted state; sealing with DEKs
    sts-cluster/                 membership, leases, fencing, claims, barrier, Scheduler
    sts-cache/                   CacheRegistry and the bounded caches it describes
    sts-http/                    the HTTP application: realm layer, CSP, CORS, bodies,
                                 call log, validation guard, error-code marking
    sts-directory/               the embedded directory model and the LDAP server
    sts-authn/                   the session, sign-in, second factors, WebAuthn
    sts-oauth/                   authorization server and OpenID provider
    sts-saml/  sts-wstrust/  sts-wsfed/  sts-federation/  sts-oidfed/
    sts-kerberos/  sts-scim/  sts-ssf/  sts-spiffe/  sts-oid4vc/  sts-gnap/
    sts-xacml/                   the engine: no I/O; shared by the runtime and the PEP
    sts-enrollment/              ACME, EST, SCEP over one CertEnrollment core
    sts-risk/  sts-attribute-sources/  sts-mail/  sts-cells/
    sts-mgmt-api/                /admin-api and /account-api, and their OpenAPI document
  bins/
    sts-runtime/                 main(): the composition root, listen(), shutdown
    xacml-pep/                   the remote PEP container
```

**The crates follow the dependency direction, and Cargo enforces it.** A
cycle between crates does not compile. The require-order cycles node
tolerated (rules 2, 3 and 3e of the root `CLAUDE.md`), which handed back a
half-initialised module with `undefined` exports, become compile errors here.

### 4.2 Object-oriented design, as Rust does it

The #50 conversion's rules carry over in their Rust form:

| #50 (TypeScript) | Rust |
|---|---|
| A module is a CLASS whose dependencies arrive through its constructor | A family is a `struct` built by `new(deps: FamilyDeps) -> Self`; its dependencies are `Arc<dyn Trait>` fields, never globals |
| `registerRoutes(app)`, called by `ProtocolStack` | The `ProtocolFamily` trait, implemented by every family and called by the composition root (below) |
| A small helper is a static method of a utility class | An associated function on a type, or a free function in a private module of the crate that owns it. Never a crate called `utils` |
| An inverted hook slot (`setDirectoryReader()`, …) filled by another module | **A trait object passed to the constructor.** The cycles that made a slot necessary do not exist when the composition root builds in dependency order. The few genuine late bindings that remain are a `OnceLock<Arc<dyn Trait>>`, each with a comment saying why |
| `export =` of an instance | No module-level instances. `static` holds only constants and the registries in section 4.4 |

```rust
/// What every protocol family is to the composition root.
pub trait ProtocolFamily: Send + Sync {
    /// The card name in sts_metadata's PROTOCOLS.
    fn name(&self) -> &'static str;
    /// Its HTTP routes. Merged by the root, which fails startup on a conflict.
    fn routes(&self) -> Router<AppState> { Router::new() }
    /// Its scheduled jobs: registered with the one Scheduler, never a timer of its own.
    fn jobs(&self) -> Vec<JobSpec> { Vec::new() }
    /// Its caches: each one described to the one CacheRegistry.
    fn caches(&self) -> Vec<CacheDescriptor> { Vec::new() }
    /// Its raw sockets: bound from listen(), and a failure is recorded, not fatal.
    fn listeners(&self) -> Vec<Box<dyn Listener>> { Vec::new() }
    /// Its /admin-api operations, declared beside the family (rule 7).
    fn operations(&self) -> Vec<Operation> { Vec::new() }
}
```

**The composition root is `bins/sts-runtime/src/stack.rs`**, the Rust
`ProtocolStack`. It builds the shared services (settings, store, crypto, PKI,
cluster, scheduler, cache registry, directory, sessions) in dependency order,
then the families in the order of the root `CLAUDE.md` table. It merges routes,
jobs, caches, listeners and operations, and refuses to start on a route
conflict, a duplicate job id, an unbounded cache or an operation without an
operation id.

**Route order.** Express runs handlers in registration order and a handler may
call `next()`. Axum matches by path specificity and panics on a conflict. So
**overlapping registrations become explicit**: where Express relied on order
(for example `krb5_home`'s `POST /KdcProxy` relaying and otherwise calling
`next()` to the KDC), the Rust route is ONE handler that asks the relay first
and then the KDC, in code a reader can see. The root `CLAUDE.md` order table
remains the order the composition root builds and wires families in, for its
load-time effects.

### 4.3 The ambient realm

Today the realm is ambient through `AsyncLocalStorage`, entered by the first
middleware. In Rust it is **a `tokio::task_local!` entered by the first layer
in `sts-http`**, with the same rule: nothing is routed above it. Code that
needs the realm takes it from `Realm::current()`.

Because the type system can be asked to check what a reader otherwise has to
remember, a per-realm store is **`RealmMap<K, V>`**: it is declared once,
partitioned by the ambient realm, and its `persist`, `retain` and `expiresAt`
options keep the meanings `common/realms.js` gives them. The guard
`tests/realm_isolation.js` becomes a Rust test that every `RealmMap` was
declared through the one constructor.

### 4.4 The three registries, and what is not a registry

* **Settings** (`sts-core::Settings`). The ~1,100 rows of `common/config.js`
  are the ONE table, and it moves into the runtime (`sts-core/settings/`, a
  data file per settings group, compiled in). The console reads each row's
  description, type and bounds through `/admin-api`, so there is still one
  copy. The five-level resolution is unchanged: realm override, runtime
  override, environment, appconfig file, defaults.
* **Error codes** (`sts-core::ErrorCode`). The same move for the 4,101 rows of
  `common/error_codes.js`, into a data file in `sts-core` from which `build.rs`
  generates a Rust `const` per code (so a code that is not in the table does
  not compile) and `docs/error-codes.md` is generated.
  The rule is unchanged: a code is recorded, never sent.
* **Mode** (`sts-core::Mode`). The ~80 predicates of `common/mode.js`, each a
  method named for its QUESTION, and the `REQUIREMENTS` table that describes
  them to `/admin/mode`. A behaviour that differs between modes is a predicate
  at the call site, never `mode.is_product()`. That is the existing style rule,
  and a Clippy lint (`disallowed_methods`) enforces it here.

The scheduler (`sts-cluster::Scheduler`) and the cache registry
(`sts-cache::CacheRegistry`) are services built by the root and passed to the
families. They are not global. `tests/no_periodic_timers.js`'s rule becomes a
Clippy `disallowed_methods` entry on `tokio::time::interval` and on spawning a
sleep loop outside `sts-cluster`.

### 4.5 Code style in Rust

* **The parent project's logging rule.** Every named function is entered and
  left out loud. In Rust this is `#[tracing::instrument(level = "debug")]` on
  the function, which logs entry and exit, rather than hand-written lines.
  Hot paths say so in a comment and leave the attribute off, as today. Logs
  are written by `tracing-bunyan-formatter`, so they keep the bunyan shape the
  operators and the suite read.
* **No swallowed error.** No `let _ =` on a `Result`, no `.ok()` that discards
  an error without a log line, no `unwrap()` outside tests (Clippy:
  `unwrap_used`, `let_underscore_must_use`).
* **A refusal carries an error code.** `Refusal::new(ErrorCode::STS_OAUTH_0123,
  spec_error)` is the only way a handler refuses, and the code goes to the
  audit row and the log, never into the response.
* **80 columns, `rustfmt` with `max_width = 80`.** SPDX headers on every file,
  as `tests/copyright_notices.js` requires.
* Comments carry the reasoning, at this repository's density.

## 5. The management API is the console's and the portal's only door

### 5.1 What exists, and the gap

`/admin-api` has ~460 operations declared as one route table
(`mgmt-api/admin_api.ts` plus ten feature-local `*_api.ts` tables), each
calling the same `admin-core` action or view function the console calls. Rule
7 (a console control has an API operation in the same commit) is enforced
from outside by `tests/vendored/admin_api.js`, `sts_admin_api_operations.js`
and `sts_admin_console.js`. **The console's WRITES are already clean**: 31
actions take `(body, actor)` and are shared with the API.

**What is not clean, and what this conversion has to close:**

1. **The console's reads** are ~170 view calls. Some are JSON views in
   `admin-core/admin_views.ts`, while ~40–90 in `admin.ts` build JSON and HTML
   together, and some page modules read stores directly. **The API even
   imports console modules** (`admin-ui/*_admin.ts`) for their JSON views.
2. **The portal does not use `/admin-api` at all.** Every self-service function
   is an in-process call, and the admin-scoped operations are the wrong shape
   for a person acting on their own entry.
3. **The API audits a client, never a person** (`actor: ''`).
4. **The hook slots** (`setDirectoryReader`, `setScimReader`, the SSF reporters,
   `setTruststore`, …) are in-process callbacks.

### 5.2 The decisions

1. **The console calls `/admin-api` with the signed-in operator's access
   token.** The console is already an OIDC relying party of this service
   (`common/oidc_rp.ts`). Its authorization request adds the `admin:read` /
   `admin:write` scopes and the API's audience. **The console holds that
   token itself, as a public client, bound to its DPoP key (section 2, D9
   as reversed, #446)**; the token names the sign-on session it came from
   and stops working when that session ends.
   **The API's gate is unchanged**: held roles ∩ carried scopes, checked at
   every call, so a role revoked after minting stops working at once. The
   audit `actor` becomes the token's subject. **This is the same security
   model with one improvement**: the API now sees the person, not the console.
2. **A second API, `/account-api`, for a person acting on their own entry.**
   The subject is the token's, never a parameter. The scope is
   `account:manage`, held by every person and declared only by
   `sts-user-portal`. It covers every portal-only function: password change
   with the current password, WebAuthn and TOTP enrolment ceremonies, backup
   codes, app passwords, the signing key and TLS client certificate, ACME EAB
   and SCEP challenges, the Kerberos keytab, CIBA and device-code approval,
   consents, GNAP grants, claims-provider links, `may_act`, SIOP enrolment,
   device registration by proof, risk feedback, email change, the RISC
   opt-out and the wider sign-out. **The token-spending pages (activation
   link, reset link, forgot-password, verify-email) stay unauthenticated
   operations that spend a single-use secret**, exactly as the pages do today.
3. **Every view moves to Rust as JSON; every page is drawn by the SPA.** The
   test for a view is that its JSON carries everything the page shows.
4. **The console's gate is an API operation**: `GET /admin-api/me` answers
   which roles the person holds, which realm they are confined to
   (`admin_scope`) and which pages they may reach.
5. **The SSF push receiver `/portal/signals/receive` moves into the runtime.**
   It is a protocol endpoint, not a page.
6. **The console's self-description is the SPA's** (`SETTING_HOMES`, the page
   list), and the settings schema it draws from is served by `/admin-api`
   (section 4.4).
7. **Rule 7 is unchanged and gains a twin**: a portal control has an
   `/account-api` operation in the same commit.
8. **The OpenAPI document is a contract.** `GET /admin-api/openapi.json` is
   snapshotted before the first operation moves. The Rust document, built with
   `utoipa` from the same declarations, must equal it, except for the
   operations a phase adds.

**The console is converted first, on the Node service (#446, owner,
2026-10-05)**: every page becomes a pure client of Node's `/admin-api`,
which is expanded until no page needs anything else. The Rust runtime then
inherits a finished console and an OpenAPI document that is complete. The
portal is written against the Rust runtime's API, family by family, as each
family's operations land there; it is a pure API client from its first
commit. The suite's Selenium jobs (`sts_admin_console.js`,
`sts_xacml_editor.js`) are adapted to pages drawn in the browser, and the
rule-7 parity jobs keep walking the console's page list.

## 6. Cryptography: every option, mapped

**The backend decision: OpenSSL 3.5, through the `openssl` crate, is the
primary provider.** It is the same library node 24 uses today. Matching the
library is the cheapest way to match behaviour, including the cases
(implicit rejection in PKCS#1 v1.5 decryption, hedged-only ML-DSA, TLS 1.0
when an operator asks for it, ML-DSA TLS certificates, the CCM suites) that
other libraries do not offer. RustCrypto crates fill the gaps OpenSSL
leaves, and each such use names the gap. **Where the `openssl` crate has no
safe binding** (ML-DSA, SLH-DSA, ML-KEM and HPKE, at the time of writing),
`sts-crypto` holds a small wrapper over `openssl-sys`. That wrapper is the
only `unsafe` code in the workspace, and the workspace denies `unsafe`
everywhere else (`#![forbid(unsafe_code)]`).

All of it sits behind the traits of `sts-crypto`:

```rust
pub trait Signer   { fn alg(&self) -> SigAlg; fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>; }
pub trait Verifier { fn alg(&self) -> SigAlg; fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>; }
pub trait Kem      { fn encapsulate(&self) -> Result<(Vec<u8>, Secret), CryptoError>; fn decapsulate(&self, ct: &[u8]) -> Result<Secret, CryptoError>; }
pub trait KeyWrap  { fn wrap(&self, cek: &Secret) -> Result<Vec<u8>, CryptoError>; fn unwrap(&self, w: &[u8]) -> Result<Secret, CryptoError>; }
pub trait ContentCipher { fn seal(&self, ..) -> ..; fn open(&self, ..) -> ..; }
```

**Algorithm tables are data plus one implementation per family of algorithms.**
A JOSE `alg`, an XML-DSig URI, a COSE integer and an X.509 OID all resolve to
the same `SigAlg`, so ML-DSA-65 is implemented once and named four ways, as it
is in `common/crypto.js` today. **What is refused stays refused, and in the same
modes**: `none`, `RSA1_5`, MD5/MD2, HMAC on the XML verify path, DES and 3DES
in CMS, RS1 unless `webauthn.insecureAlgorithms`, SHA-1 in XML unless
`saml.allowSha1Signatures`.

| Area | Every option today | Rust |
|---|---|---|
| **JWS** | HS256/384/512; RS256/384/512; PS256/384/512; ES256/384/512, ES256K; EdDSA (Ed25519, Ed448); ML-DSA-44/65/87; SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s; 6 composites (ML-DSA-44/65-ES256, ML-DSA-87-ES384, ML-DSA-44/65-Ed25519, ML-DSA-87-Ed448) | `openssl` (`PKey`, `Signer`, ML-DSA and SLH-DSA through `EVP_PKEY` by name); composites built from both halves in `sts-crypto`; JOSE framing written here, as it is today, over `serde_json` and `base64ct` |
| **JWE key management** | RSA-OAEP, RSA-OAEP-256; ECDH-ES(+A128/192/256KW) on P-256/384/521; A128/192/256KW; A128/192/256GCMKW; PBES2-HS256/384/512; `dir`; ML-KEM-512/768/1024(+KW); HPKE-0..16 and the `-KE` forms | `openssl` for RSA, ECDH, AES-KW, PBKDF2; `openssl` HPKE (`OSSL_HPKE_*`, 3.2+) for the DHKEM suites; ML-KEM through `openssl`; X-Wing and the ML-KEM hybrids composed in `sts-crypto` |
| **JWE content** | A128/192/256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512; `zip` | `openssl` ciphers; `flate2` for `zip` |
| **HPKE internals** | DHKEM P-256/384/521, X25519, X448; ML-KEM-512/768/1024, MLKEM768-P256, MLKEM1024-P384, MLKEM768-X25519; HKDF-SHA256/384/512, SHAKE128/256, TurboSHAKE128/256; AES-128/256-GCM, ChaCha20Poly1305, export-only; base and psk | `openssl` where it has the suite; the `sha3` crate for SHAKE and TurboSHAKE (OpenSSL has no TurboSHAKE); the KEM combiners composed in `sts-crypto` |
| **XML-DSig** | RSA PKCS#1 v1.5 (SHA-1/224/256/384/512, RIPEMD-160); RSASSA-PSS (MGF1 over SHA-1/2/3, RIPEMD-160); ECDSA (SHA-1/2/3, RIPEMD-160) with the product curve list including brainpool; EdDSA Ed25519/Ed448; DSA-SHA1/256; ML-DSA-44/65/87 and all 12 SLH-DSA sets (draft-eastlake-rfc9231bis); digests SHA-1/2/3, RIPEMD-160; exclusive and inclusive C14N 1.0 with and without comments; enveloped, base64, XPath, XPath Filter 2 | **A port of this repository's own `common/vendored/xmldsig.js`** (it is ours since #363) onto `libxml` (libxml2: the DOM, XPath and `xmlC14NExecute` for both C14N 1.0 forms), with signature methods from the `sts-crypto` registry. `libxmlsec1` is not used: it knows none of the post-quantum URIs |
| **XML-Enc** | AES-128/192/256-GCM and -CBC (3DES read by the engine); RSA-OAEP-MGF1P, RSA-OAEP (xenc11, SHA-1/256/384/512), RSA-1_5 by mode; ECDH-ES with ConcatKDF on P-256/384/521 with AES-KW; the engine's ML-KEM and FrodoKEM methods | The same port; ciphers from `openssl`. **FrodoKEM has no OpenSSL implementation**: `oqs` (liboqs) is the candidate, and the decision is recorded in phase 4 |
| **Post-quantum primitives** | ML-DSA-44/65/87; all 12 SLH-DSA sets; ML-KEM-512/768/1024; hedged and pure only | `openssl` (3.5), as today. RustCrypto `ml-dsa`, `slh-dsa` and `ml-kem` run as the second implementation in the cross-check tests, never in the service |
| **Composite and hybrid** | 18 X.509 composites (draft-ietf-lamps-pq-composite-sigs-19, OIDs 1.3.6.1.5.5.7.6.37–54); X-Wing; QSF hybrids ML-KEM-768 + P-256/P-384/X25519, ML-KEM-1024 + P-384/P-521/X448; ITU-T X.509 9.8 alternative keys across a chain | Composed in `sts-crypto` and `sts-pki` from `openssl` halves; X-Wing from `openssl` ML-KEM-768 and X25519 with the `sha3` combiner |
| **X.509 / PKI** | rsa-2048/3072/4096, ec-p256/384/521, ed25519, every ML-DSA and SLH-DSA set, composites, ML-KEM subject keys; sha1/256/384/512-rsa, -rsapss, -ecdsa; CRL and OCSP (RSA, RSA-PSS, ECDSA, Ed25519; CertID SHA-1/2); CMS for SCEP (RSA/ECDSA SHA-256/384/512, AES-CBC, RSAES-PKCS1-v1_5, RSAES-OAEP); PKCS#10 classical and PQ; PKCS#12 and encrypted PKCS#8 (PBES2, AES-256-CBC, PBKDF2-SHA256, 100,000 iterations); PKCS#7 for AWS IID | RustCrypto formats: `der`, `spki`, `x509-cert` (with its builder over the `signature` traits, so a PQ or composite signer plugs in), `x509-ocsp`, `cms`, `pkcs8`, `pkcs5`; `pkcs12` from `openssl` |
| **Kerberos** | enctypes 17, 18, 19, 20, 23; decode-only DES 1/2/3/5/7/16, 24, Camellia 25/26; checksums 15, 16, 19, 20, -138; RFC 4121 MIC and Wrap; PRF and KRB-FX-CF2 | `openssl` AES, HMAC and PBKDF2; RFC 3962 CTS mode written in `sts-kerberos` over AES-CBC (no crate is trustworthy enough); `md4`, `md-5` and `rc4` from RustCrypto for type 23; ASN.1 with `rasn-kerberos`. **See decision D1** |
| **Data Integrity and VCs** | ecdsa-jcs-2019, ecdsa-rdfc-2019, eddsa-jcs-2022, eddsa-rdfc-2022, mldsa44-jcs-2024, slhdsa128-jcs-2024, ecdsa-sd-2023; bbs-2023 (BLS12-381-SHA-256); SD-JWT (`_sd_alg` sha-256 to issue, sha-256/384/512 to verify); VC-JOSE-COSE; status-list CWT COSE algorithms | `serde_json_canonicalizer` for JCS (RFC 8785); `json-ld` with the repo's pinned contexts and **a closed loader that fetches nothing**, as today; `rdf-canon` for RDFC-1.0; `zkryptium` for BBS (the IETF BBS ciphersuite); `coset` for COSE |
| **WebAuthn** | COSE ES256/384/512, ESP256/384/512, EdDSA, Ed25519 (-19), Ed448 (-53), ES256K (-47), RS256/384/512, PS256/384/512, ML-DSA-44/65/87; RS1 only when allowed; formats packed, tpm, android-key, android-safetynet, fido-u2f, apple, compound, none; FIDO MDS3 | A port of this repository's own verifier (there is no library covering every format and the PQ algorithms), over `coset` and `ciborium` and the `sts-crypto` registry |
| **GNAP tokens and HTTP signatures** | rsa-pss-sha512, rsa-v1_5-sha256, hmac-sha256, ecdsa-p256-sha256, ecdsa-p384-sha384, ed25519, and the JWS algs; Content-Digest sha-256/512; Biscuit (Ed25519); macaroons (HMAC-SHA256); ZCAP (Ed25519Signature2020) | HTTP Message Signatures written in `sts-gnap` over `sfv` (RFC 8941 structured fields); `biscuit-auth` (the native crate the wasm build is made from); `macaroon`; ZCAP ported |
| **Passwords and KDFs** | scrypt `$scrypt$N$r$p$salt$hash` (logN 14–20, r 8, p 1, 32-byte output); TOTP/HOTP HMAC-SHA1/256/512; HKDF-SHA256 keyed digests; CSRF HMAC-SHA256 | `openssl` scrypt (the same output); `totp-rs`'s algorithm set, or the 30-line RFC 4226 over `openssl` HMAC if its parameter checks disagree with today's |
| **Envelope encryption** | `$aesgcm$2$` (AES-256-GCM, 96-bit IV, AAD = version + DEK id); `$aessiv$` (AES-256-SIV, RFC 5297); `$dekwrap$1$` (AES-256-GCM under HKDF-SHA256(KEK)); KMS wrapping in Vault transit, AWS KMS, GCP KMS, Azure Key Vault | `openssl` AES-GCM; `aes-siv` (RustCrypto) where OpenSSL's SIV is not exposed; `aws-sdk-kms` and `aws-sdk-secretsmanager`, `google-cloud-kms`, `azure_security_keyvault_keys` and `_secrets`, `vaultrs` |
| **DKIM** | rsa-sha256 (≥ 2048 bits), ed25519-sha256, relaxed/relaxed | `mail-auth` |
| **SSH and Sigstore** | ssh-rsa, ecdsa-sha2-nistp256/384/521, ssh-ed25519; Sigstore/TUF ECDSA-SHA256, RSA PKCS#1-SHA256, Ed25519; canonical JSON; DSSE PAE | `ssh-key`; `sigstore` for the TUF client, verification on `sts-crypto` |
| **TLS** | TLS 1.0–1.3 (`tls.minVersion`; 1.3-only by default); TLS 1.2 ECDHE-ECDSA/RSA-AES-GCM; TLS 1.3 AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305, AES-128-CCM, CCM-8; groups X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, X448, P-384, P-521, pure MLKEM512/768/1024 (`tls.pqcOnly`); signature schemes including mldsa44/65/87 and ed448; RSA and ML-DSA certificates together, chosen per client; optional client certificates; session tickets with rotation; JA4 | `openssl` with `tokio-openssl`. **`rustls` was considered and rejected for the listeners**: it has no TLS 1.0/1.1, no CCM suites, no Ed448 and no ML-DSA certificates, and any of those is an option an operator can select today. `rustls` with `aws-lc-rs` remains the outbound client where only verified TLS 1.2+ is ever offered |

**The rule for every row: a phase that ports an area ports EVERY option in its
row, or the row stays in Node.** There is no "most of the algorithms" step.

**How parity is proved (section 10.2):** a vector generator in Node writes,
for every algorithm in every row, signatures, ciphertexts, sealed values and
certificates. Rust must verify or decrypt every Node output, and Node must
verify or decrypt every Rust output. Deterministic schemes must match byte
for byte. Where a scheme is randomised, the test is cross-verification, and
the vectors are checked in.

## 7. Libraries

| Need | Crate | Why this one |
|---|---|---|
| Async runtime, HTTP | `tokio`, `hyper`, `axum`, `tower`, `tower-http` | The standard stack; `tower` layers map one-to-one onto the Express middleware chain in `common/app.js` |
| TLS (listeners) / TLS (outbound) | `openssl` + `tokio-openssl` / `rustls` | Section 6 |
| Postgres | `sqlx` (with `PgListener` for `LISTEN`/`NOTIFY`) | Compile-time checked queries against `postgres/schema.sql` |
| The operators' SQL databases (attribute sources) | `sqlx` (Postgres, MySQL), `tiberius` (SQL Server), `oracle` (Oracle, through ODPI-C) | Today's `knex` drivers, one for one |
| LDAP server | `ldap3_proto` | Kanidm's LDAPv3 codec. **The `node-ldapjs` fork's two options (`routeAnonymousBinds`, `encodeErrorMessage`) are behaviour of OUR server code here, not of a library** |
| gRPC (SPIFFE) | `tonic`, `prost`, built from the vendored `spiffe/protos/` | The standard; serves Unix sockets and TCP |
| XML | `libxml` (libxml2) | DOM, XPath and C14N in one library, and the one `xmlsec` itself is built on. Parsing hardened against external entities and expansion, as `@xmldom/xmldom` is configured today |
| ASN.1, X.509, CMS | RustCrypto `der`, `x509-cert`, `cms`, `x509-ocsp`; `rasn` for Kerberos | |
| JSON Schema / OpenAPI | `jsonschema` / `utoipa` | Replaces `ajv` and the hand-built document |
| Caches | `moka` | Bounded, with TTL; the registry wraps it so every cache is still described to `/admin/caches` |
| Cron | `croner` (Rust) | The same expression grammar as the `croner` npm package used today |
| Mail | `lettre` (SMTP, STARTTLS-required or implicit TLS), `aws-sdk-sesv2`, the Azure and Gmail REST APIs over `reqwest` | |
| Logging | `tracing`, `tracing-bunyan-formatter` | Section 4.5 |
| SCIM filters | `scim_v2` or a `nom` parser | Decided in the SCIM phase against the suite |
| QR codes | `qrcode` | Server-drawn SVG, as today |
| Zip (risk datasets) | `zip` | |
| User-agent, bot detection | `woothee`; the bot list decided in the risk phase | Today's `bowser` and `isbot` |

## 8. What does not change

* **Every URL, every port, every setting key and every environment variable.**
  `env/` keeps working unchanged against the Rust runtime.
* **The appconfig layers' content.** `env/*.js` become `env/*.json` (they
  are data), read by the Rust runtime; the Node runtime keeps its `.js` copies
  until the cutover deletes it.
* **The error-code table and every code in it.** The 57 suite files that
  assert codes keep asserting them.
* **The protocol suite.** Phases add Rust tests. They never edit a
  `tests/vendored/` copy, and they make a `local: true` job pass, never change
  its assertion to suit Rust.
* **The containers seen from outside**: `iya-sts` and `xacml-pep` keep their
  names, ports, health checks and environment. The service image gains a
  second process (the surfaces), started by the runtime.

## 9. Decisions needed from the owner

| # | Decision | Recommendation |
|---|---|---|
| **D1** | **Kerberos.** Eight codec files are locked copies of the parent project's `common/krb5/`, and the parent's tests COPY `krb5_kdc`, `krb5_service`, `spnego` and their closure from this repository. | **DECIDED by the owner, 2026-10-05: the files may be modified and DECOUPLED from the parent project.** The Kerberos phase ports them to `sts-kerberos` and the parent's COPY closure is retired. Interoperability is proved against a real Windows domain controller by the owner's existing compatibility tests, as well as by the protocol suite |
| **D2** | ~~The store during the migration.~~ | **Moot (owner, 2026-10-05)**: no installation survives, so there is no coexistence and no store shared between the two implementations (section 3) |
| **D3** | **The logging rule.** `#[tracing::instrument]` instead of hand-written Entering/Leaving lines. | **DECIDED by the owner, 2026-10-05, on one condition: the END RESULT of logging and tracing stays intact** — the same bunyan JSON lines, levels and fields, an entry and an exit line per named function at `debug`, error codes at the front of a line. `sts-core`'s logging layer formats `instrument`'s span events as `Entering NAME().` / `Leaving NAME().`, and a test holds it |
| **D4** | ~~One copy of the tables shared by both implementations.~~ | **Moot (owner, 2026-10-05)**: with no coexistence, the settings and error-code tables simply move into the runtime, and the console reads settings descriptions through `/admin-api` (section 4.4) |
| **D5** | **OpenSSL as the primary crypto provider.** | Accept it (section 6) |
| **D6** | **The in-process half of the suite** (`tests/*.js`, about 150k lines) does not run against Rust. | Rewrite each file as Rust tests in the phase that moves what it tests, and delete it from `tests/` in that commit, with `tests/CLAUDE.md`'s table updated |
| **D7** | **`/account-api`** as a second API rather than more `/admin-api` operations. | Accept it. A person acting on their own entry is a different authority from an operator acting on anyone's, and one API holding both would put that difference in a parameter |
| **D8** | **The embedded debugger** stays the parent project's Node build, run as a child process. | Accept it |
| **D9** | **Where the SPAs' tokens live.** | **DECIDED by the owner, 2026-10-05, and REVERSED FOR THE CONSOLE the same day (#446)**: the console is a public client whose tokens are in the browser, in memory, bound to a non-extractable DPoP key; it is exempt from FAPI's confidential-client rule; and `adminApi.authRequired=false` is development-only. **The portal keeps the first decision**: a backend-for-frontend in the runtime, the tokens server-side behind a session cookie (section 2) |
| **D10** | **Script on the console and portal.** | **DECIDED by the owner, 2026-10-05: `script-src 'self'` on `/admin/` and `/portal/` only**, reversing the works-without-script rule for those two surfaces (section 2) |

## 10. How each phase is proved

### 10.1 The suite, in every mode it runs today

A phase is finished when the suite jobs for the families it moved pass
against the Rust image (section 3.1). After the cutover, `./run-tests.sh`
passes in all four modes with the same job count as the Node service had.

### 10.2 Differential tests, new

* **Crypto vectors**: every row of section 6, both directions (section 6).
* **The OpenAPI contract**: the document matches the snapshot (section 5.2).
* **Shadow traffic, optional**: for a family whose behaviour is hard to
  enumerate (SAML, WS-*), the suite's recorded requests are replayed against
  both implementations and the responses compared after removing what is
  random (ids, timestamps, signatures, which are verified instead).

### 10.3 The security surfaces

For every row of the root `CLAUDE.md` turnstiles table, and every `mode.js`
predicate a phase moves, the phase adds a Rust test that the refusal happens,
with its code, in the mode it happens in today.

## 11. The phases

Each phase is one or more pull requests to `develop`, sized to be reviewed.
The order follows dependency: nothing is ported before what it calls.

| Phase | What moves | Why here |
|---|---|---|
| **0** | This document | |
| **1** | **The workspace and its conventions; `sts-xacml` (the engine, held to the vendored OASIS suite, 454/455 today); the `xacml-pep` binary replacing the Node container.** | The PEP is the one component that can be replaced END TO END with no coexistence machinery: it is already a separate container with an HTTP contract (`/xacml/pep/*`, `POST /xacml/pip`, mTLS), and `tests/vendored/sts_xacml_remote_pep.js` already holds that container to it. It proves the conventions on something real, and the engine crate is reused by the runtime in phase 6 |
| **2** | `sts-core` (settings, error codes, mode, logging), `sts-crypto` complete with the vector tests, `sts-pki`. | Every family depends on them. Nothing in production calls them yet |
| **3** | `sts-store` (memory, ldif, postgres), `sts-cluster` (membership, leases, fencing, claims, `Scheduler`), `sts-cache`, `sts-http`, the `sts-runtime` binary and image, realms, and the `/admin-api` operations every suite job sets itself up with (realms, users, groups, applications, settings). | Every later phase's suite jobs stand on these |
| **4** | First families, the self-contained ones: `pki` (revocation and `/crypto/metadata`), `oidfed`, `ssf`, `scim`, `xacml` (the PDP side), the enrollment trio. Each with its jobs, caches and `/admin-api` operations. The portal pages of each family switch to API calls in Node in the same phase; the console's pages switch under #446, on its own schedule. | Small surfaces, few session interactions |
| **5** | `sts-directory`: the directory and LDAP on 389/636. | Almost everything reads the directory; it moves before the big families |
| **6** | `sts-authn` (the session), `sts-oauth`, `logout`. | The centre of the service. The largest phase, and likely split |
| **7** | SAML 2.0 and 1.1, WS-Trust, WS-Federation, federation. | The XML families, on the XML-DSig port |
| **8** | OID4VC, GNAP, SPIFFE, Kerberos (decoupled from the parent project, D1), risk, attribute sources, mail, cells. | |
| **9** | **The cutover** (section 3.2): the Rust image, with the console and portal SPAs built into it, replaces the Node service in the Dockerfile, compose files and CI; the Node runtime and its in-process tests are deleted. | |

Phase sizes are not equal. Phase 6 alone is larger than phases 1–4 together.
**Each phase is estimated before it starts, against the credit available
then, and is not started if it cannot be finished.** A half-ported family is
worse than an unported one.
