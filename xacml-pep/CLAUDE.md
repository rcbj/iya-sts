# CLAUDE.md — `xacml-pep/`

**A REMOTE XACML POLICY ENFORCEMENT POINT, AND A RUST BINARY SINCE #444
(2026-10-05).** Everything the identity service runs is required by
`server.js`; this is a **second container**, which holds its own copy of the
XACML engine, PULLS the policy repository from the service's PDP and decides
locally. Its code is `rust/bins/xacml-pep` on the engine crate
`rust/crates/sts-xacml` (the runtime's engine too, `rust/DESIGN.md`); what is
in THIS directory is its image and its one shared expectation.

```
XACML_PEP_HTTP=true docker compose --profile xacml up --build

curl http://localhost:9090/
curl "http://localhost:9090/protected?subject=alice&employeeType=staff&action=GET"
```

**PLAIN HTTP IS OFF BY DEFAULT (#1760, rcbj 2026-11-14: "Disable the HTTP
listeners by default on the Remote XACML PEPs & reverse proxy").** Neither
`api-http` (`PEP_PORT`, 9090) nor `proxy-http` (`PEP_PROXY_PORT`, 9180)
binds unless its switch, `PEP_HTTP` or `PEP_PROXY_HTTP`, is `true`
(`options::plain_http`). The precedence: the switch decides (`true` on,
`false` off, anything else off and `STS-XPEP-0107`, because a typo must never
turn plaintext ON); unset, the listener is off, and **the port variable does
NOT turn it on** — a template that wrote `PEP_PORT=9090` down to document the
default would otherwise keep plaintext on without anybody choosing it, which
is what the default exists to stop. A port variable set with no switch is a
deployment that relied on the old default, so it gets `STS-XPEP-0106` once at
start naming the line that brings it back. **No managed setting**: these two
bind before the first pull; a listener defined on the Listener tab is the
service's way to serve plain HTTP, and a listener the PEP reports `off` holds
no port, so a definition may take 9090. Reported `off`/`http-off` on the
heartbeat. With the API's plain listener off, `start()` awaits nothing but its
tasks (`std::future::pending`), and **the healthcheck asks HTTPS on
`PEP_HTTPS_PORT`, certificate unverified** (its own loopback; liveness, not
identity) — a PEP with no pair yet is honestly unhealthy, answering nobody.
**The test stacks turn both on explicitly** (`docker-compose-run-tests.yml`
argues it: the job reaches the PEP before it issues the HTTPS pair); so do
the CI liveness check and the AWS suite task. `docker-compose.yml` sets no
notify URL since 2026-11-14 (`${XACML_PEP_NOTIFY_URL:-}`): the PEP derives
it (*THE NOTIFY URL IS DERIVED*, below).

**THE CRL POINT STAYS UP WITH HTTP OFF (2026-11-14), AND THAT WAS A DEFECT
OF THE DEFAULT ABOVE.** The client credential's CRL distribution point is
`http://<pep>:9090/crl` (`tests/tools/pep-credential.js --crl-base`, which
every launcher passes), and a product-mode service fetches it under hard-fail
before it believes the certificate. With plain HTTP off nothing answered on
9090, the certificate failed verification, and every pull was 403
"unauthenticated" — so "HTTP off by default" broke mutual TLS for every PEP
whose credential named its own plain port. Two fixes were weighed: point the
CRL somewhere always reachable, or keep the PEP serving it. **The PEP serves
it, on a CRL-ONLY listener** (`options::crl_listener`): with `PEP_HTTP` off,
`PEP_PORT` is bound for `GET /crl/<name>` and NOTHING else (`Transport.
crl_only`; anything else is a 404, `STS-XPEP-0114`), whenever there is a CRL
directory to serve. Why this and not the other:

* **A CRL is fetched in the clear by design** (RFC 5280 section 4.2.1.13, and
  this service's own revocation listener on 8082 is plain HTTP for the same
  reason): one behind TLS would have to be validated with the certificate it
  revokes. So plain HTTP on this one path re-opens nothing #1760 closed: the
  decision API, the nudge and AuthZEN stay HTTPS.
* **It is backwards compatible.** Every credential already minted names
  `:9090/crl`; moving the distribution point would have orphaned all of them,
  and "always reachable" elsewhere means a second process the operator has to
  run for a container whose CRLs nobody else holds.
* **Its own switch**, `PEP_CRL_HTTP`: unset is the default above, `false`
  never binds it, `true` binds it with no directory, anything else keeps the
  default and logs `STS-XPEP-0115`. With `PEP_HTTP=true` the API's listener
  serves `/crl/` as it always did and this is not bound.

It is reported as `api-http` with state `listening`, reason `crl-only` and
**purpose `crl`** (2026-11-15; it was `api`, so the console drew it as the
*decision API* it does not serve): `EnvKind::Crl` in `listeners.rs`, which
keeps the purpose when the bind fails too. The Listener tab, the listener's
page and the Visual picture draw it as *CRL distribution*, *listening, CRLs
only*. **Backwards compatible both ways**: a service older than this closes
the purpose to `api`/`proxy` and reads `api`, the reason still saying
CRLs only; a newer console reads an older PEP's `api` with `crl-only` as
*CRL distribution* too (`PepPicture.purposeOf()`). `cargo test`'s
`the_crl_only_listener_is_reported_with_the_purpose_crl`.

**A NUDGE WITH `full: true` PULLS EVERY DOCUMENT WHOLE (2026-11-16).** It
is what the console's Sync button sends. `/notify` reads at most 4 KiB of its
body for that one member, and nothing else in the body is trusted.
`Sync::pull_full()` asks for the settings, the policies, the AuthZEN catalogue
and callers, and the reverse proxy each without its token or ETag, so every one
is sent whole and loaded again. The endpoint is not authenticated, so
`claim_full_pull()` honours a full pull at most once a poll interval. A second
one inside that time is an ordinary pull, logged with `STS-XPEP-0120`. An older
PEP ignores the member and pulls as usual.
`a_full_pull_asks_without_its_token_once_an_interval` holds both.

**THE NUDGE IS HTTPS ONLY (2026-11-14, rcbj: "Let's assume always HTTPS").**
`POST /notify` is answered on an HTTPS listener alone; over plain HTTP — the
environment's `api-http` or a defined plain listener — it is a 404 naming the
HTTPS listener (`STS-XPEP-0112`). The service never dials an `http://` notify
URL (`xacml/CLAUDE.md`), so a nudge in the clear is not the PDP's. And the PEP
never ADVERTISES one: **a notify URL somebody SET that is not https is
REJECTED** (2026-11-14, rcbj: "If an http:// URL is given and is not allowed
per configuration, it should be rejected"; nothing allows http since
`xacml.pepNotifyAllowHttp` was retired).

* **What is rejected**: `settings::notify_rejected()` — a non-empty value
  that does not start `https://` (any case). `PEP_NOTIFY_URL`, and a managed
  `notifyUrl` an older service stored: `Managed::parse()` records that one
  as `rejected_notify` rather than in `refused`, because a refused setting
  FALLS BACK to the environment (`STS-XPEP-0102`) and a rejected one must
  not. Any other refusal of the row (a user name, a fragment) still falls
  back as before.
* **Rejected means NOTHING is advertised, not the derived URL**:
  `Options::notify_in_force()` answers `(advertised, rejected)`, and a
  rejected value is still the one in force at its place in the precedence,
  so `Now::notify_url` is empty and `Now::notify_rejected` holds it. The
  operator asked for something specific; a guess around it would hide that
  it is wrong. An https managed value still wins over a rejected
  `PEP_NOTIFY_URL`, the precedence being unchanged.
* **Said at ERROR, once per variable and value** (`say_notify_rejected()`,
  `STS-XPEP-0113`), naming `PEP_NOTIFY_URL` or the service's setting, why,
  that there is no fallback, and the fix. Said where it is in force, so a
  rejected `PEP_NOTIFY_URL` under an https managed value says nothing.
* **Reported rejected**: `Options::settings_report()` replaces the
  `notifyUrl` entry with the value given, its source (`environment`, or
  `service` — `Held::service_sets()` counts a rejected managed value as set)
  and `rejected: true`. `rejected` is a member of that entry alone in the
  model (`models/api/common.tsp`), the service keeps it only for that row
  and only when it is `true` (`xacml_pep_settings.ts`'s `inUseOf()`), and
  the console draws it on the Settings tab and in the Notify cell.
* `advertised_notify_url()` stays at the three places the URL is sent, as a
  guard that logs nothing: `Now::notify_url` is already https or empty.
* The service keeps its own refusals: `STS-XACML-0259` (no nudge to an http
  row) and `STS-XACML-0239` (the Settings tab refuses one).

**THE NOTIFY URL IS DERIVED WHEN NOBODY SET ONE (2026-11-14, rcbj: "The PEP
should attempt to derive the notify URL").** It read EMPTY by default until
then, on the argument that the PEP cannot know the name the service reaches
it by. The answer to that argument is the certificate: the service checks
the notify host against the PEP's HTTPS listener certificate
(`xacml/CLAUDE.md`), so a host taken FROM that certificate is one the check
can pass. `options::derive_notify_url()` builds
`https://<host>:<PEP_HTTPS_PORT>/notify`, `<host>` the first that is a DNS
name (`is_dns_name()`: no wildcard, no IP address) of:

1. **the subjectAltName DNS name equal to the hostname** (case and a trailing
   dot aside; `DerivedFrom::CertificateHostname`) of the certificate the
   9443 listener serves (`HttpsListener::dns_names()`, recorded at every
   `reload()` and `install()`) — rcbj's "option 1", 2026-11-14;
2. the first subjectAltName DNS name of that certificate;
3. `PEP_NAME` as SET — its default `pep-1` is not read, being a name no
   resolver knows;
4. the hostname (`HOSTNAME`, `/proc/sys/kernel/hostname`, `/etc/hostname`).

**Why the hostname's SAN first (the 8081 deploy, 2026-11-14).** The first-SAN
rule picked `remote-pep-1`: the realm's default certificate names the PEP's
REGISTERED name first (`xacml/xacml_pep_tls.ts`'s `derivedNames()`), and
that name is also its CN, which no resolver knows. The certificate was
`remote-pep-1, xacml-pep, localhost, 127.0.0.1` on a container named
`xacml-pep`. A SAN that is the hostname is both in the certificate (the
service's host check passes) and the name the container is known by on its
network (it resolves). The INFO line names the rule that picked the host
(`DerivedFrom::describe()`); the source reported is still `derived`.

**THE GAP THIS LEFT, CLOSED IN CODE (2026-11-14)**: a PEP that derives its
URL registers with NONE before it holds a certificate, so the realm's
default names were its registered name alone, and a certificate issued with
the defaults derived the registered name (rule 2). **So the PEP REPORTS ITS
HOSTNAME** — `options::reported_hostname()`, the value rule 4 reads, sent
only when `is_dns_name()` holds, lower-cased, a trailing dot dropped — as
`hostname` on the registration and every heartbeat (`sync.rs`), and the
service stores it (`xacmlPepHostname`, `PepRegistry.hostnameOf()`, 400
`STS-XACML-0261` for anything that is not a DNS name) and adds it to
`derivedNames()`, so the default certificate of the environment pair and of
a defined listener names it and rule 1 picks it. The PEP filters before it
sends because a refused registration would cost it its row. Backwards
compatible both ways: an older service ignores the member, and an older
PEP sends none and keeps the defaults it had. An operator still adds a name
by hand only where the service reaches the PEP by another one.
`options.rs`'s `a_reported_hostname_makes_the_default_certificate_derive_it`
and `only_a_dns_hostname_is_reported`; the service's half is
`xacml/CLAUDE.md`'s.

* **No certificate served, no URL**: `POST /notify` is HTTPS only, so there
  is nothing to advertise. Only the environment's `api-https` listener
  counts, because the URL names `PEP_HTTPS_PORT`; a listener the service
  defined is on another port.
* **The precedence is managed `notifyUrl`, `PEP_NOTIFY_URL`, derived, none**
  (`Options::notify_in_force()`), reported as `service`, `environment`,
  `derived`, `default` (`Held::source()`). `derived` is a source of
  `notifyUrl` ALONE: the service reads it for that row only
  (`xacml_pep_settings.ts`'s `DERIVED_KEYS`), its model's enum has it on
  that member only, and the catalogue's `precedence` stays the three every
  row has. An empty managed value is not set (the service never sends one),
  so it cannot hide the derived URL. **An explicit `http://` value still
  wins, and is REJECTED** (*THE NUDGE IS HTTPS ONLY*, above): nothing is
  advertised, the order is rcbj's, and a value somebody set is not
  overridden by a guess.
* **When it is derived**: once before the registration — `main.rs` reads
  the pair once before `register()` so the registration carries it — and
  after every reload of the pair. `Held::set_derived_notify()` answers
  whether it changed; a change is logged at INFO with its source, and when
  it changes the URL IN FORCE the reload loop sends a heartbeat at once,
  because the heartbeat's `notifyUrl` replaces the row's.
* **The test stacks DERIVE it** (2026-11-14): both compose files pass
  `PEP_NOTIFY_URL=${XACML_PEP_NOTIFY_URL:-}` — empty is unset here, so the
  `${VAR:-default}` form is right and the host's `XACML_PEP_NOTIFY_URL`
  keeps working; the BARE form would have read the host's `PEP_NOTIFY_URL`
  instead and silently dropped it. `docker-compose-run-tests.yml`'s PEP is
  hostname `xacml-pep` and the job issues its pair naming `xacml-pep`, and
  `sts_xacml_remote_pep.js`'s own bridge container is hostname `PEP_NAME`,
  which its certificate names; section 6 asserts the row's URL names it. Its
  host-network container still SETS `https://127.0.0.1:<port>/notify`: the
  service dials the loopback address, which derivation never yields, and the
  hostname there is the machine's. The AWS suite task sets the task's IP for
  the same reason.

**It replaced a Node container with the same contract** — the same
environment variables and defaults, ports, endpoints, JSON bodies, log lines
(bunyan, `Entering`/`Leaving` included, through `sts-core::log`) and error
codes — so the suite's job and the PDP see no difference. The Node files
(`pep.js`, `sync.js`, `pip.js`, `engine.js` and the `common/helpers.js`
shim) are in git history.

## What is here

| File | What it is |
|---|---|
| `Dockerfile` | Build context is the REPOSITORY ROOT: `cargo build --release -p xacml-pep` over `rust/`, then a `debian:bookworm-slim` image holding the binary, `VERSION` and the `version.json` the binary stamps. OpenSSL is built into the binary (D5). |
| `enforcement_cases.json` | **Section 7.2 as a table**, the seven cases BOTH enforcement points are held to — see *The enforcement rule*. |
| `authzen_cases.json` | **The AuthZEN mapping contract as a table** (#1179): the catalogue values and requests the service's `authzen/` and this container's port are BOTH held to — see *The AuthZEN edge PDP*. |
| `certs/` | The compose files' default certificate mount; empty and gitignored. |
| `openapi/` | **GENERATED (#1830)**: one OpenAPI 3.1 document per surface, from `models/pep/` — see *THE MODEL OF EVERY ENDPOINT*. Never edited by hand. |

| Rust module (`rust/bins/xacml-pep/src/`) | What it is (the Node file it replaces) |
|---|---|
| `options.rs` | The environment, read once (`pep.js`'s `options`). |
| `pdp_client.rs` | ONE HTTP client for every call to the PDP, with the client certificate on every call (`sync.js`'s `call()`). |
| `sync.rs` | Register, pull, heartbeat; what is held (`sync.js`) — and the two AuthZEN pulls, the catalogue (#1179) and the callers (#1189), with the caller list's strict grammar. |
| `pip.rs` | The walk, the batched `POST /xacml/pip`, the resolver (`pip.js`). |
| `enforce.rs` | The bias and the obligation rule (`pep.js`'s `enforce()`). |
| `listener.rs` | The HTTPS listener whose pair is re-read from disk, and which asks for a client certificate when `PEP_AUTHZEN_CLIENT_CA` is set (#1179). |
| `service.rs` | The one handler for both listeners, `/protected`'s decision, `GET /`. |
| `authzen_catalogue.rs`, `authzen_map.rs` | Ports of `authzen/authzen_catalogue.ts` and `authzen/authzen_map.ts`: the catalogue grammar, the request reading and the fail-closed mapping (#1179). Pure. |
| `authzen.rs` | The AuthZEN edge PDP's endpoints, the admission of a caller by the pulled list and the optional local narrowing (#1189), the batch and the metadata (#1179), and the forward of an evaluation about an application that enforces fine-grained authorization to the service (#564, P7). |
| `proxy.rs` | **The reverse proxy (#1760)**: its two listeners, the one handler, the session mechanism's `/.iya-pep/callback` and `/.iya-pep/logout`, and the streamed, bounded forward to the upstream. See *THE REVERSE PROXY*. |
| `proxy_config.rs` | The pulled configuration (D2, D3) read again by D2's rules and refused whole, the route table and its matching. Pure. |
| `proxy_request.rs` | The path normalised or refused, and the headers that may not cross in either direction. Pure. |
| `proxy_auth.rs` | The four mechanisms, local first and the service's validation endpoints behind, the identity endpoint (D11), and the JWKS cache. |
| `jwt.rs` | A JWS verified against the realm's JWKS with OpenSSL, the claim and `cnf` checks, strict base64url. Pure. |
| `saml_verify.rs` | A SAML 2.0 assertion's enveloped signature, with exclusive c14n written over roxmltree. Pure. |
| `rp_session.rs` | The session mechanism's sign-ins in flight (the library's `Transaction`) and proxy sessions, in memory and bounded. |
| `rp_set.rs` | The session mechanism's relying parties: one `oidc-caep-risc` `RelyingParty` per client, and its CAEP/RISC `SignalsReceiver`, built from the pull and rebuilt when it changes (D5). |
| `identity.rs` | How the identity reaches the application (D11): claim values as headers, the `jwt` mode's token cache, the `saml` mode's cookie jar. Pure. **A claim with no value sends no header** (2026-11-14): an empty string or list is no value, as absent and null always were, so a person in no group no longer sends `X-Iya-Groups:` empty. `X-Iya-Amr` reached nobody for another reason, the service's: its identity endpoint answered every proxy session's access token with `amr: []`, and reads the token's own `amr` now (`xacml/xacml_pep_proxy.ts`, `subjectOf()`). |
| `listeners.rs` | **Every listener, and the ones the service defines (#1760)**: the definitions read again, bound, rebound and unbound after each pull, an HTTPS one's key generated here and its certificate asked for, and the report on the heartbeat. See *THE LISTENERS THE SERVICE DEFINES*. |
| `main.rs` | Start-up, the backoff timers, the fault handler, `--stamp`, `--healthcheck`. |

## The tests, and which half each guards

| Test | What it holds |
|---|---|
| `cargo test -p xacml-pep` | **The SHAPE**: the PIP walk over ONE document holding a designator in five places (a target, a condition, a variable definition, an obligation assignment, a policy reached by `PolicyIdReference`) and NOT the resource-category one beside them; the PIP answer read with the engine's own request reader; the listener's reload rules and a real mutual-TLS handshake read by `peer_of()`; the enforcement rule against `enforcement_cases.json`; and the AuthZEN mapping against `authzen_cases.json`, the request it builds, the fail-closed result, the pulled caller list's grammar, admission by it and by the local narrowing, and the application scope; and (#564, P7) the catalogue's `fgaApplications` read whole or not at all, which applications are forwarded, the forwarded body, the service's every answer mapped to a decision or an error (never `false`), and the forward over a real socket to a mock service — the realm's path, `X-Request-ID`, a 500, a refusal of the PEP, a timeout and nobody listening; and (#1760) the reverse proxy — see *THE REVERSE PROXY*, *What holds it*. |
| `tests/model_pep.js` | **THE MODEL (#1830)**: the committed documents and `sts-model-pep`'s types are what `models/pep/` makes, each document well formed, and NO DRIFT either way between the documents' paths, the paths the PEP's dispatch matches and the `/xacml/pep/*` routes `xacml/xacml.ts` registers. |
| `tests/authzen_evaluation.js` X | **The service's real control-plane answers against the model (#1830)**: register, heartbeat, the five pulls, a refusal and two validation doors, each held to `pep-control-plane.json` with Ajv (`tests/tools/pep_model.js`). |
| `tests/authzen_map.js` S | **The service's mapping against the same `authzen_cases.json`** — so the two readings of one request are checked against one expectation, as the two enforcement rules are. |
| `tests/authzen_evaluation.js` K, P | The PDP's side of the two AuthZEN pulls, `GET /xacml/pep/authzen-catalogue` (K) and `GET /xacml/pep/authzen-callers` (P), in process — P holding each pulled caller's name to the one the certificate door gives a real handshake. |
| `cargo test -p sts-xacml` | The engine against the vendored OASIS suite, case for case as `tests/xacml_conformance.js` holds the service's. |
| `tests/xacml_pep.js` | The PDP's side (sync token, register, nudge refusals, change observer), the Dockerfile building and stamping the Rust binary, and **the service's `enforce()` against the same `enforcement_cases.json`** — so the two readings of section 7.2 are checked against one expectation. |
| `tests/xacml_request.js` E | The remote PEP builds through `sts-xacml`'s `AuthorizationRequest`, and every identifier that builder declares is spelt as `xacml_request.js`'s `VOCABULARY` spells it. |
| `tests/protocol/sts_xacml_remote_pep.js` | **THE DEPLOYMENT**: this image, on the service's own docker network — registering on a later attempt, pulling, deciding out here, converging by polling and by the nudge, the PIP end to end, the HTTPS listener, deciding correctly with the PDP taken away. **The only thing that runs what this Dockerfile produces.** |

**THE LAUNCHERS OWN THAT CONTAINER AND THE JOB DRIVES IT**: `./run-tests.sh`
brings one up beside the service and hands the job `XACML_PEP_URL`,
`XACML_PEP_NAME` and `XACML_PEP_REALM`; with none of those the job builds this
image and starts a container itself.


## Why this exists at all, which is not obvious

**IT IS THE DEMONSTRATION PEP SINCE #596 (2026-10-12; #591 P5).** The
service had one of its own, `GET /xacml/protected` in `xacml/xacml.ts`, with
its bias in `xacml.pepBias`: it built a request from `subject`, `resource` and
`action`, asked the PDP, applied the bias and the obligation rule, and
answered 200 or 403. Both were deleted, because the runtime ships no
demonstration code, and `GET /protected` here is the same thing — the request
through the same builder, `PEP_BIAS` as the PEP-side option, `enforce.rs` as
the rule — so nothing in this binary changed for it. Its tests moved with it:
`tests/protocol/sts_xacml_remote_pep.js` section 4b asserts the obligation
rule here, on policy this container pulled. What is still in the service is
`enforce()`, for `/admin/xacml/decide`'s what-if under both biases, held with
`enforce.rs` to `enforcement_cases.json`.

That embedded PEP was a correct implementation of section 7.2 and it
demonstrated almost nothing about a distributed deployment, because it
**shared a process with the PDP**. It could never be stale. It could never hold a policy the PDP no
longer had. It could never go on enforcing while the PDP was down. It could
not disagree with the PDP about anything, ever.

Every one of those is a state a real deployment lives in, and this container
makes all of them reachable:

* it can be STALE, and both ends say so — `GET /` here, and the row on
  `/admin/xacml/peps` over there;
* it can REFUSE a document the PDP accepted, and the two policy counts then
  disagree, which is what that column on the console is for;
* it can go on enforcing correctly with the PDP stopped, which is the trade
  `sync.rs` argues and the one worth being able to watch;
* **the two ends can disagree about whether it is stale**, because they measure
  different things — this PEP counts missed polls and the PDP counts missed
  heartbeats. A PEP that is pulling happily while its heartbeats are dropped
  looks fine here and stale there, and that is a genuinely confusing deployment
  state that is far easier to recognise when both numbers are visible.

---

## THE ENGINE IS A CRATE — WHICH IS WHAT THE SHIM USED TO PROVE

The Node container's most valuable property was a thirty-line `helpers.js`
shim: every engine module required `../common/helpers`, which in the service
pulls in the whole identity service, and in the image it resolved to the shim
— so an engine module that grew a dependency on the service THREW AT LOAD.
"The engine is a library with no I/O" was a checked claim rather than a
comment.

**The crate graph makes the same claim, more strongly.** `sts-xacml` depends
on no service crate, and Cargo will not compile one that reaches for
something it does not depend on. The image builds exactly the crates
`xacml-pep` needs — there is no COPY list to keep in step, and so no test
holding one. A change that gave the engine a dependency on the runtime would
be a visible line in `rust/crates/sts-xacml/Cargo.toml`, argued in
`rust/DESIGN.md` or refused.

**One copy of the engine in the tree** is unchanged: it is the crate the
runtime's PDP will use (phase 4), so the PEP and the PDP cannot drift.


## THERE IS NO POLICY INFORMATION POINT HERE, SO IT ASKS THE ONE THAT HAS ONE

The mock's PIP reads attributes off a person's entry in the embedded directory.
**This process has no directory and should not have one** — that half is
unchanged and is the reason this section exists. What changed on 2026-09-06 is
what happens next: the PDP publishes its PIP at `POST /xacml/pip`, and
`pip.rs` uses it.

### Why it had to change

Without it, an attribute a policy asks about had to be IN the request, and one
that was not produced an empty bag. That is an ordinary XACML result and a real
deployment shape — but it also meant **one policy deciding two ways in two
enforcement points**, which is exactly the drift a shared repository exists to
prevent, reappearing one layer down. The PDP permitted people this container
refused. `tests/protocol/sts_xacml_remote_pep.js` asserted that in both
directions and calls the inversion out where it does it.

### The hard part is that the engine's resolver is synchronous

`xacml_pdp.js` hands a resolver a designator and expects an array back; an HTTP
request is not that. Making the evaluator asynchronous would be a change to the
code every one of the 455 OASIS conformance cases runs through, for the benefit
of one deployment shape, and it was refused.

So **the fetch happens before evaluation**: `pip.rs` walks the policy for the
designators it could be asked about, fetches them ALL IN ONE REQUEST, and hands
`service.rs` a synchronous resolver over what came back. That is why the PDP's
endpoint takes a LIST of designators — the batch is not an optimisation, it is
what makes a synchronous engine able to use a remote PIP at all.

**The walk is STATIC and deliberately over-fetches**: targets, conditions,
variable definitions, obligation and advice assignments, and the children of a
policy set, with `PolicyIdReference` followed through the repository this PEP
holds. A branch never taken costs one entry in a batch that was going to be
sent anyway. The alternative was to evaluate TWICE, once with a recording
resolver returning empty bags — exact rather than over-approximate, and refused
because the first pass decides on deliberately wrong information, and any
obligation or side effect the engine grew later would be performed on it. **A
static walk cannot decide anything.**

### The degraded state is the OLD behaviour, and that is the whole safety story

`pip.rs` never rejects. A PDP that will not answer, a query the access policy
refuses, a policy designating more attributes than one query may carry — every
one of them comes back as a resolver answering empty bags, which is precisely
what this container did before that file existed. So the failure mode of a
remote PIP is *no PIP*, reported on `GET /`, rather than a PEP that stops
deciding. Same rule `sync.rs` follows about a failed pull: this component
enforces with what it has.

### It builds its requests with the service's builder (#306) — rule 3br

**IT BUILDS ITS REQUESTS WITH THE SERVICE'S BUILDER (#306).**
`xacml/xacml_request.js` is ported into the engine crate
(`sts-xacml::builder`) and `service.rs` makes its request through it, so this
container asks in the shape and spelling the service's own PEPs do; `pip.rs`
takes the subject-kind id from its vocabulary. `tests/xacml_request.js` holds
the two builders' spellings to each other.

**ROLES COME FROM THE PIP TOO (#303).** A policy naming `urn:sts:xacml:role`
gets the subject's configured roles from the PDP — the roles this service
would issue for — so a request about a subject with no scopes (a SAML
assertion's person, a Kerberos principal) is decided on roles without the
caller asserting any. `/protected?subject=payroll-worker&subjectKind=application`
says the subject is an APPLICATION: `service.rs` asserts
`urn:sts:xacml:subject-kind` (once — it is not a directory attribute, so not
under both spellings) and `pip.rs` forwards it in the PIP query, because the
same name could be a person holding different roles.

**`PEP_PIP=false` reaches the same state on purpose**, and so does a container
with no client certificate — the endpoint requires a verified one whose subject
holds `REMOTE_PEPS`. So the no-PIP deployment is a CONFIGURATION rather than a
limitation, which is what lets one container demonstrate both, and
`GET /protected?employeeType=staff` still works and still means what it always
meant: an attribute the SUBJECT asserted about itself, which no real deployment
would believe.

**A REQUEST-ASSERTED ATTRIBUTE STILL DECIDES where the directory holds
nothing**, which is worth stating because it is what a PIP does NOT fix. A PIP
removes the disagreements that come from MISSING information; it does not
remove the ones that come from a caller asserting something about itself. The
test asserts that too.

**EACH ONE IS ASSERTED UNDER BOTH SPELLINGS**, the bare name and
`urn:sts:xacml:attribute:<name>`, and that is not belt and braces. The
mock's `xacml_pip.js` answers BOTH from one directory attribute, so a policy
author over there may legitimately write either and the PDP decides identically.
A remote PEP asserting only one would decide differently for every policy that
used the other — which is precisely the disagreement this phase exists to make
impossible. **It cost a run to find**: the seeded RBAC policy names
`employeeType` bare, this container asserted only the prefixed form, and every
request was denied by a policy that was working perfectly.

---

## THE ENFORCEMENT RULE IS WRITTEN OUT, NOT IMPORTED

`xacml.ts`'s `enforce()` is fifty lines and this PEP does not share it. It is the
PEP's own decision — the bias and the obligation rule — and a PEP that imported
the PDP's would be demonstrating that two processes agree because they are one
program. That is the thing `tests/protocol/sts_dpop.js` refuses to do when it
writes its
own DPoP client rather than importing the wallet's.

Written out, this PEP can run a DIFFERENT bias from the one the console's
what-if draws (deny-biased; `/admin/xacml/decide`, which reports both since
#596), and the two then disagree about exactly the answers the two biases
disagree about — which is the demonstration worth having.

**`tests/xacml_pep.js` runs both implementations over the same seven decisions
under both biases and asserts they agree** — and asserts that the two biases
disagree somewhere, so that the agreement is a real comparison rather than two
functions that both say yes.

**That comparison is why the end-to-end job does NOT make it.** Every decision
`sts_xacml_remote_pep.js` asks for is a Permit or a Deny under a
deny-unless-permit policy, which is exactly where the two biases AGREE — so what
it measures is the POLICY reaching this process, not the enforcement rule. The
one state where the bias is what decides is an empty holding, and that job goes
there on purpose by disabling every policy and watching this PEP refuse the
admin it was permitting a second earlier. The OBLIGATION rule, though, is
driven here since #596 (section 4b), because an undischargeable obligation
refuses a Permit under either bias.

---

## The four endpoints

```
GET  /              what this PEP is, what it holds, what it has enforced
GET  /protected     THE RESOURCE. 200 or 403, decided here
POST /notify        the PDP's nudge: pull now
GET  /healthcheck   liveness
GET  /crl/<name>    this PEP's own credential's CRLs (#174), from PEP_CRL_DIR
```

and the AuthZEN edge PDP's three (#1179), *The AuthZEN edge PDP* below.
**The reverse proxy (#1760) is on ports of its own** (9180, 9543) and adds
nothing here but a `proxy` member on `GET /` — *THE REVERSE PROXY* below.

**`/crl/<name>` is not a fifth endpoint of the PEP's; it is its credential's
distribution point (#174, 2026-09-23).** A product-mode PDP refuses, under
hard-fail, a client certificate from an authority it does not hold that names
no CRL and no OCSP responder (STS-PKI-0190) — nobody could ever revoke it. So
`tests/tools/pep-credential.js --crl-base=http://xacml-pep:9090/crl` names the
Root's and the Issuing CA's lists in the chain it mints and writes them beside
the credential, and this container, the only thing alive for as long as that
credential is presented, serves them from `PEP_CRL_DIR` (by default the `crl/`
directory beside `PEP_TLS_CERT`). Only a name of the form `<word>.crl` is looked
up; the documents are public and signed, and this container holds no key that
could sign one.

**`/notify` answers 204 immediately and pulls afterwards.** The PDP times that
request out in two seconds by default, and holding it open for the length of a
pull would make a slow pull look like an unreachable PEP on somebody's console.

**Nothing in its body is trusted, and one member is read.** A nudge says only
that something changed; what changed is discovered by pulling from this PEP's
own configured PDP URL. A nudge that could tell this PEP what the policy now
is, or where to fetch it, would be an unauthenticated caller supplying policy —
and the whole reason a nudge is affordable on the PDP's side is that it carries
nothing. **`full` (#1829) is the one member read**: a Sync from the console
asks for every document whole rather than answered 304, which fetches nothing
a pull does not, and is honoured at most once a poll interval
(`STS-XPEP-0120`) because anybody reaching the listener can send it. The 204
has no body and so no `Content-Type` (#1830); it keeps `Cache-Control:
no-store`.

**`GET /` says which pull last changed the holding** (2026-09-26):
`holding.lastChangeCause` is `start`, `poll`, `nudge` or `heartbeat`, set only
by a pull that loaded a change. It is how the suite tells a nudge that worked
from a poll that raced it. It measured a latency until the suite began running
jobs side by side, and a busy PDP made a working nudge look like a poll.

**`/healthcheck` does not ask whether the policy is current.** A PEP holding a
stale copy is working, and a healthcheck that failed on staleness would turn a
PDP outage into a container restart loop — an outage of its own.

---

## What must work, and what is allowed to fail

**Only the pull has to work.** Everything else in `sync.rs` is subordinate to
that and the file is arranged so a failure elsewhere cannot stop it:

* **Registering is optional.** It buys a row on the PDP's console and an address
  for the nudge; it is not what lets this PEP enforce. A PEP that fails to
  register logs why and goes on deciding. Getting that backwards would make a
  monitoring feature into a hard dependency for authorization.

  **THAT IS STILL TRUE AND THE SENTENCE THAT USED TO FOLLOW IT IS NOT.** It
  read *`GET /xacml/pep/policies` needs no credential*, and that endpoint went
  behind a verified client certificate holding the built-in `REMOTE_PEPS` role
  on 2026-09-06. **A CREDENTIAL AND A REGISTRATION ARE STILL TWO DIFFERENT
  THINGS**, which is what keeps the bullet's point intact: the pull asks
  whether the certificate on the connection resolves to an entry in the group
  `roles.remotePepGroup` names, and it never asks whether that PEP has a row in
  `ou=peps`. So a PEP with a certificate and no registration pulls and enforces
  exactly as before, and a PEP with a registration and no usable certificate
  pulls nothing at all — which is the failure this container reports as stale
  policy rather than as silence.

  **AND SINCE 2026-09-06 IT IS RETRIED ON THE POLL TIMER UNTIL IT SUCCEEDS,
  WHICH IS A CORRECTION RATHER THAN AN ELABORATION.** It happened exactly once,
  at start, and a PEP that came up before its PDP — or survived a PDP restart it
  started during — then enforced correctly FOR EVER while appearing on nobody's
  console. That is the worst shape "optional" can take: the feature degrades
  invisibly and permanently, and `/admin/xacml/peps` reports an empty register
  on a deployment that is working. `depends_on: service_healthy` hides it in the
  compose file above and hides nothing anywhere else. The retry costs one
  request per interval while unregistered and nothing afterwards, it is logged
  at `warn` once and at `debug` from then on so a PDP refusing on policy grounds
  cannot fill a log, and `registration.attempts` is on `GET /` so that
  "registered on the fourth try" is visible rather than inferred.

  **It is asserted because the test arrangement depends on it**: both launchers
  point this container at a realm the suite creates minutes later, so
  `sts_xacml_remote_pep.js` asserts the registration took more than one attempt.
  A PEP that registers once and gives up would fail that job, which is the right
  place for it to fail.
* **The nudge is optional twice over**, and the poll arrives at most one interval
  later.
* **The heartbeat is optional**, and its failure is logged at `debug` rather than
  `warn`: a PEP that cannot report is still enforcing correctly, and a warning on
  a sixty-second timer would fill a log with the least important failure here.

* **An unexpected error is contained, not an exit (#355, 2026-09-29).** Once
  `start()` has finished, an uncaught exception (`STS-XPEP-0033`) or unhandled
  rejection (`STS-XPEP-0034`) is logged with its stack — a distinct fault at
  occurrences 1, 2, 3 and each power of ten — and the PEP carries on enforcing
  the policy it last pulled. An exit would enforce nothing until the container
  restarted. It is a small copy of `common/fault_boundary.ts`'s process half,
  because this image compiles no TypeScript; a failure while starting is still
  `STS-XPEP-0013` and exit 1.

### When the pull itself fails

**The last good policy set is KEPT and enforcement continues.** A PDP that is
down does not make this PEP stop deciding; it makes it go on deciding with what
it last pulled, and mark itself stale. The alternative — a PDP outage denying
everything everywhere — is the failure mode that makes people remove
authorization services.

That is a real trade and both surfaces say so rather than hiding it: a policy
change made during an outage is **not enforced here** until the next successful
pull. **`sts_xacml_remote_pep.js` section 9 is the first thing to check it**: it
turns `xacml.remotePeps` off in its realm under a running container (see the
next paragraph) and asserts that it goes on
deciding CORRECTLY IN BOTH DIRECTIONS — still permitting what the last pulled
policy permits, still refusing what it refuses — while reporting `lastPullOk:
false` and saying it is KEEPING what it has. Both halves matter and a mutant
that emptied the holding on a failed pull is caught there: a PEP that stopped
deciding would have satisfied any test that only checked a refusal. `GET /` reports `stale` and how long since the last successful pull;
`/admin/xacml/peps` reports the same thing from the other side.

**The PDP is taken away underneath it by `xacml.remotePeps` off in its realm,
which was a realm REMOVAL until 2026-09-06**, when this suite stopped removing
the realms it creates so that a failed run can be read afterwards.

**A PEP that has NEVER pulled successfully is a different state**, reported as
`loaded: false`. There is no policy, every decision is NotApplicable, and the
bias decides — which for the default deny-biased PEP means refusing everything.
"No policy" and "a policy that permits nothing" are indistinguishable from
outside and want opposite fixes, which is why they are two different reports.

### Several instances are NOT a cluster, and must not become one (#676)

**rcbj's decision on #676 (2026-11-03): no clustering concept.** The ticket
asked for one; reviewing it found nothing to coordinate. Everything an
instance holds is pulled (the policy set, the AuthZEN catalogue and callers),
its own (the counters, which a heartbeat SETS), read from disk (the listener
pair) or fetched per decision and not kept (the PIP). The PDP is already the
single source of policy, so a peer could only hand an instance a copy that
might be OLDER, and being behind is already the handled state above. Peer
coordination would add a failure mode and buy no correctness. **A change that
makes one instance depend on another, or hold something only another has, is
reversing that decision** and needs the argument made with rcbj first.

What scaling DOES involve is the credential choice, and it is the PDP's
register that makes it a choice: one certificate is one row, and a heartbeat
replaces the row's notify URL and counters, so instances sharing a
certificate show as one row that flips between them and are nudged one at a
time. `docs/remote-pep.md`, *Running more than one*, is where that is told to
an operator; it is not repeated here.

---

## Configuration

**From the environment, and since #1760 from the PEP's console page as well.**
This section said "all of it from the environment … a PEP has no console";
rcbj's request on #1760 gave it one: *all information about the remote PEP
(and reverse proxy) should be configurable on this new screen except the
minimum config required for the remote PEP to be able to initially connect.*

**THE PRECEDENCE IS THE SERVICE'S VALUE, THEN THE ENVIRONMENT'S, THEN THE
DEFAULT**, setting by setting (`src/settings.rs`, `Options::now()`). The
`Options` fields are still the environment's values, exactly as before; a
reader of a MANAGED setting reads `options.now()`, never the field, or a
change made on the console never reaches it — `now()` overlays what the last
settings pull applied. Twenty-three settings are managed (`settings::SETTINGS`,
the service's `xacml/xacml_pep_settings.ts` `SETTINGS` in Rust, with the same
keys, variables and bounds); the table below marks them.

* **THE PULL** is `GET /xacml/pep/settings`, FIRST in every round so the
  round's timers, timeouts and bias are the new ones: its own token, `?since=`
  and `If-None-Match`, a failure keeps what is held (`STS-XPEP-0100`), an
  OLDER SERVICE'S 404 is the environment in force, said once and anything an
  earlier pull applied dropped (`STS-XPEP-0101`). `configured: false` drops
  everything back to the environment.
* **EACH VALUE IS READ AGAIN BY ITS ROW**, and one that fails is left to the
  environment and named (`STS-XPEP-0102`) — per setting, not the whole
  document as the route table is refused, because one setting does not change
  what another means. **A member this PEP does not know is IGNORED**, so a
  newer service can add a setting without stranding an older PEP.
* **HOW EACH IS APPLIED WITHOUT A RESTART.** Read at its use through `now()`:
  the bias (`Pep::enforcer()` builds the rule per decision), the PIP switch
  (`RemotePip::governed_by()`), the resource, the AuthZEN switch, identifier
  and forward timeout, the body bounds, the session re-check and the
  upstream verification (its cached client is keyed by it). Asked before
  every wait: the poll, heartbeat and back-off intervals (`on_backoff()`
  takes a closure) and the HTTPS reload interval. Pushed by
  `Sync::apply_settings_effects()` after a pull: the PDP client's timeout and
  answer bound (per request, `PdpClient::set_limits()`), the proxy session
  store's bounds and the log level (`sts_core::log::set_level()`, the one
  change outside this crate: the installed layer's level is an atomic now).
  Pushed by `Proxy::reconcile()` after each poll: the JWKS lifetime and the
  relying parties' bounds, a changed bound rebuilding each party (its digest
  carries the poll and stale bounds); a library session store keeps the
  bounds it was built with, since it outlives rebuilds and holds signed-in
  people.
* **WHAT IT HAS IN FORCE** is `GET /`'s `settings` and the heartbeat's
  `settings` member: `{ token, values: { key: { value, source } } }`, the
  source `service`, `environment` or `default` (an environment variable
  counts as set when it was non-empty at start). The service holds it to its
  members and draws it beside what is set.
* **BOOTSTRAP STAYS HERE**: `PEP_PDP_URL`, `PEP_NAME`, `PEP_TLS_CERT`/`KEY`,
  `PEP_TLS_CA` and `PEP_TLS_INSECURE` (needed before the first pull), the
  four ports (a listening socket is not rebound while it serves), the files
  (`PEP_HTTPS_CERT`/`KEY`, `PEP_CRL_DIR`, `PEP_AUTHZEN_CLIENT_CA`,
  `PEP_PROXY_UPSTREAM_CA`), `PEP_PROXY` (whether the proxy's listeners start;
  the proxy configuration's `enabled` is the managed switch) and
  `PEP_AUTHZEN_CALLERS` (the operator's own narrowing of what the service
  sends, which the service could not set and still narrow anything).

| Variable | Default | What |
|---|---|---|
| `PEP_PDP_URL` | `https://localhost:8081` | The mock. |
| `PEP_NAME` | `pep-1` | **Ignored when a client certificate is presented** — the PDP names the row from the certificate. |
| `PEP_TLS_CERT` / `PEP_TLS_KEY` | — | The client certificate. Without it the PDP refuses the registration unless `xacml.pepRequireCertificate` is off. Enforcement is unaffected either way. |
| `PEP_TLS_CA` | — | An anchor for the PDP's certificate. |
| `PEP_TLS_INSECURE` | `false` | Do not verify the PDP. **The ordinary setting against the mock**, whose listener certificate is issued by a service Root that development mode regenerates on every start — so there is no fixed anchor to verify against (`tls/CLAUDE.md`). Logged on every start, for `federation_http.ts`'s reason. |
| `PEP_NOTIFY_URL` | derived | Where the PDP should nudge; unset, derived from the HTTPS certificate (*THE NOTIFY URL IS DERIVED*). *Managed* (`notifyUrl`). |
| `PEP_BIAS` | `deny-biased` | This PEP's own. *Managed* (`bias`). |
| `PEP_PIP` | `true` | Resolve designators the request did not carry against the PDP's embedded directory, through `POST /xacml/pip`, in one batched query before each evaluation. **`false` reaches the old behaviour deliberately** — and so does a container with no `PEP_TLS_CERT`, since that endpoint requires a verified certificate holding `REMOTE_PEPS`. On by default because the surprising state is the other one: a PEP enforcing the same policy as its PDP and reaching a different answer. *Managed* (`pip`). |
| `PEP_POLL_INTERVAL_MS` | `15000` | **The contract**, and since 2026-09-06 also the interval a FAILED REGISTRATION is retried on. *Managed* (`pollIntervalMs`). |
| `PEP_HEARTBEAT_INTERVAL_MS` | `60000` | *Managed* (`heartbeatIntervalMs`). |
| `PEP_PORT` | `9090` | The plain-HTTP API port, bound only with `PEP_HTTP=true` (#1760). |
| `PEP_HTTP` | `false` | **`true` binds plain HTTP on `PEP_PORT`.** Off by default since #1760; the precedence and the two notices are above. |
| `PEP_HTTPS_CERT` / `PEP_HTTPS_KEY` | — | **PATHS, re-read on an interval** — the listener's pair, issued by the PDP's realm. Unlike `PEP_TLS_CERT`, which is read once, because this pair normally does not exist when the container starts. See *The HTTPS listener*. |
| `PEP_HTTPS_PORT` | `9443` | |
| `PEP_HTTPS_RELOAD_INTERVAL_MS` | `5000` | Not the poll timer, deliberately: that one is the policy contract. *Managed* (`httpsReloadIntervalMs`). |
| `PEP_AUTHZEN` | `true` | The AuthZEN edge PDP (#1179). `false` answers 501 (`STS-XPEP-0044`). *Managed* (`authzen`). |
| `PEP_AUTHZEN_CLIENT_CA` | — | **A path, read once**: the CA bundle an AuthZEN caller's certificate must chain to. Set, the HTTPS listener ASKS every client for a certificate; unset or unreadable, the edge PDP admits nobody (`STS-XPEP-0039`). |
| `PEP_AUTHZEN_CALLERS` | — | **Optional since #1189.** A JSON array of `{ "name", "sha256", "applications" }`. Set, it NARROWS the callers pulled from the service to the certificates it names (`STS-XPEP-0054`), and before the first caller pull it decides alone, as #1179's door did (`STS-XPEP-0037`); unset, the pulled list alone decides and nothing is answered before it (`STS-XPEP-0050`). Set to a value that names nobody, it admits nobody. A malformed entry is left out (`STS-XPEP-0038`). |
| `PEP_AUTHZEN_PDP_IDENTIFIER` | — | The metadata's `policy_decision_point`, an `https` origin with no path; unset, the origin the HTTPS request arrived at (`STS-XPEP-0045` over plain HTTP). *Managed* (`authzenPdpIdentifier`). |
| `PEP_AUTHZEN_FORWARD_TIMEOUT_MS` | `5000` | How long an evaluation FORWARDED to the service (an application that enforces fine-grained authorization, #564) may take; past it the caller gets 504 (`STS-XPEP-0055`). Not `PEP_TIMEOUT_MS`, because a caller is waiting on this one and nobody waits on a pull. At least 1. *Managed* (`authzenForwardTimeoutMs`). |
| `PEP_RESOURCE`, `PEP_DESCRIPTION`, `PEP_TIMEOUT_MS`, `PEP_MAX_BODY_BYTES`, `PEP_LOG_LEVEL` | | `PEP_MAX_BODY_BYTES` also bounds a single AuthZEN evaluation's body (`STS-XPEP-0046`). *Managed* (`resource`, `description`, `timeoutMs`, `maxBodyBytes`, `logLevel`; `PEP_BACKOFF_MAX_MS` too, `backoffMaxMs`). |
| `PEP_PROXY` | `true` | **The reverse proxy (#1760).** `false` starts neither of its listeners and skips its pull. On, it answers 503 with `Retry-After` to everything until its first pull since the start succeeds (`STS-XPEP-0118`), and 404 to everything while the configuration it received is empty or switched off. |
| `PEP_PROXY_PORT` | `9180` | Its plain-HTTP listener, bound only with `PEP_PROXY_HTTP=true` (#1760). A port that will not bind is logged (`STS-XPEP-0063`) and the PEP goes on. |
| `PEP_PROXY_HTTP` | `false` | **`true` binds the proxy's plain-HTTP listener on `PEP_PROXY_PORT`.** Off by default since #1760, as `PEP_HTTP`. |
| `PEP_PROXY_HTTPS_PORT` | `9543` | Its HTTPS listener: the SAME `PEP_HTTPS_CERT`/`KEY` pair 9443 serves, re-read on the same interval, and a client is ASKED for a certificate (never required to present one) so a certificate-bound token's `cnf.x5t#S256` can be checked. No pair, no listener. |
| `PEP_PROXY_SESSION_RECHECK_MS` | `5000` | On a session route with `signals: false` (or whose receiver would not start): how old the service's last "live" answer about a proxy session may be before the next access asks `POST /xacml/pep/session` again. `0` asks on every access. *Managed* (`proxySessionRecheckMs`). |
| `PEP_PROXY_MAX_ACCOUNTS` | `5` | **Several accounts in one browser (#1760)**: the most accounts one browser's set holds on a `multipleAccounts` route, 1 to 32; past it a sign-in is refused (403, `STS-XPEP-0108`). *Managed* (`proxyMaxAccounts`). |
| `PEP_PROXY_SESSION_TTL_MS` | `28800000` (8 h) | The longest a proxy session lives, whatever the service says. *Managed* (`proxySessionTtlMs`). |
| `PEP_PROXY_MAX_SESSIONS` | `10000` | The most proxy sessions held — a new one past it is REFUSED (503, `STS-XPEP-0085`), never made by evicting somebody — and, separately, the most sign-ins in flight, where the OLDEST is dropped. *Managed* (`proxyMaxSessions`). |
| `PEP_PROXY_JWKS_TTL_MS` | `300000` | How long the realm's JWKS is used before it is fetched again. An unknown `kid` refetches at once after an ordinary fetch, then at most every 5 s. *Managed* (`proxyJwksTtlMs`). |
| `PEP_PROXY_UPSTREAM_CA` | — | **A path, read once**: anchors for an `https` upstream, beside the system's (`STS-XPEP-0092` when unreadable). |
| `PEP_PROXY_UPSTREAM_INSECURE` | `false` | Do not verify an `https` upstream's certificate. *Managed* (`proxyUpstreamInsecure`). |
| `PEP_PROXY_RP_ALLOW_INSECURE` | `false` | The session mechanism's relying party may talk to an `http` issuer (the library's `allowInsecure`): a development provider only. It never relaxes the redirect URI, which the library holds to https or loopback. *Managed* (`proxyRpAllowInsecure`). |
| `PEP_PROXY_SIGNALS_POLL_MS` | `5000` | How often the CAEP/RISC receiver polls the service's stream (at least 100). *Managed* (`proxySignalsPollMs`). |
| `PEP_PROXY_SIGNALS_STALE_MS` | `60000` | How long a receiver may go without a successful poll before its signals stop deciding whether a proxy session is live, and the service's session endpoint is asked instead (`STS-XPEP-0099`). Never less than three polls. *Managed* (`proxySignalsStaleMs`). |

`PEP_PROXY_MAX_SESSIONS` and `PEP_PROXY_SESSION_TTL_MS` also bound the
LIBRARY's session store (one per client): twice the first as entries, the
second as each entry's life after it was last written. Not settings of their
own, because the two stores hold the same set and two numbers that must
agree would one day not.

**The compose service, beyond the table** (moved from `docker-compose.yml`'s
comments on 2026-10-07): it is under `profiles: [xacml]`, so a plain `up` never
starts it; `XACML_PEP_IMAGE` is set per run for `STS_IMAGE`'s reason (an image
tag is machine-wide); the HTTPS listener is published on **9444**, not 9443,
which collided with the service's mutual-TLS listener until that was deleted
on 2026-09-16 — the default stays because every launcher, kept stack and
`XACML_PEP_HTTPS_URL` names it; `PEP_HTTPS_CERT`/`KEY` default EMPTY because a
default inside `xacml-pep/certs` would invite a private key into the source
tree; `PEP_HEARTBEAT_INTERVAL_MS` is a substitution because
`tests/protocol/sts_xacml_remote_pep.js` reads the counters the heartbeat
carries and cannot wait a minute; and `PEP_NOTIFY_URL` defaults EMPTY
(2026-11-14), so the PEP derives the HTTPS listener's from the certificate
the realm issued it — the SAN equal to the hostname, `xacml-pep` — which the
PDP verifies against the realm's `pep-tls` chain.

**The compose service ships with no certificate**, so out of the box it
registers unauthenticated and the mock refuses it — which is the honest default
rather than a broken one. **SINCE 2026-09-06 THAT REFUSAL IS THE ACCESS POLICY'S
RATHER THAN `xacml.pepRequireCertificate`'S**, and it is no longer optional: the
three endpoints require a client certificate this service VERIFIED that
resolves to a directory entry holding the built-in `REMOTE_PEPS` role. **Since
#1061 that entry is the one STORING the certificate** in `userCertificate`
(`common/CLAUDE.md` 3ag): the PEP's certificate comes from an outside
authority, and its subject DN is no longer read, so the certificate has to be
stored on the PEP's entry in the realm it pulls from or every call is refused
(`STS-XACML-0179`, `0180` when stored on two entries). Nothing in either image
can do that — the certificate is minted after the stack is up — so whoever
mints it stores it too: the launchers after `tests/tools/pep-credential.js`,
the job for a container it starts itself, and an operator upgrading an
existing deployment BEFORE the upgrade. Both launchers mint one and mount it
at `/certs`; a container without one starts, enforces what it can pull (nothing),
and says why. Generating one here would mean either committing a
private key to this repository (which `postgres/generate-tls.sh` exists
specifically to avoid) or a first-start script for a demonstration container.
Mount a pair to see the authenticated path. **Either way it enforces.**

**And the compose service's nudge is delivered once the PEP holds its pair**:
until then the dial fails, the PDP says why on the PEP's row, and the PEP
converges on its fifteen-second poll anyway.

**BOTH HALVES OF THAT ARE ASSERTED SINCE 2026-09-06**, and it took a container
to do it. `sts_xacml_remote_pep.js` runs its sections 1–5 with `xacml.pepNotify`
OFF in its own realm (since 2026-11-14; until then with an http notify URL the
PDP refused to dial), so every convergence there is the poll, and the
registration reply is checked for an https URL it calls usable. Then it turns
the nudge on and measures the other half, in whatever mode the realm is in:
the PDP dials this container's HTTPS `/notify` across the bridge, verifying it
against the realm's `pep-tls` chain with no CA file, the row records `The PEP
answered 204.`, and a change lands in tens of milliseconds against a
five-second poll. Section 9 asserts a plain-HTTP `/notify` is refused. **That outbound request is one of three
this service makes and was the only one with no test against a real listener
anywhere.**

---

## The two defects phase five actually had, both found by running it

1. **`certificatePlan()` takes DN fields as STRINGS and node hands back
   OBJECTS.** `getPeerCertificate()` returns `subject` and `issuer` as
   null-prototype objects of RDN types, and `String()` on one of those does not
   produce a DN — it throws `Cannot convert object to primitive value`. The
   registration answered 500 with a stack in it. Every existing caller had
   always put both through `helpers.dnRfc4514()` first, so the precondition was
   real and written down nowhere; it is written at `certificatePlan()` now. It
   was met **twice**, once per field — fixing the subject alone just moved the
   throw eighty lines down.

2. **The attribute spelling**, above. Every request denied by a policy that was
   working perfectly, which is the worst shape an authorization bug can take.

Neither would have been found by anything but running the container against the
service. **THAT SENTENCE IS THE ARGUMENT FOR
`tests/protocol/sts_xacml_remote_pep.js`, WHICH DID NOT EXIST WHEN IT WAS
WRITTEN**: running the container against the service was something a person did
by hand, and both defects were found by a person doing it. That job now does it
on every run — and each of those two defects lands squarely in it. The first is
a 500 out of the registration, which section 1 fails on; the second is every
request denied by a working policy, which is section 2 and every convergence
after it.

## The version this container reports

**It is `M.N.O.<build>` under the service's own rules (#1317)** — the
release from the one `VERSION` file the service reads, then a build number
that is the UTC build instant, `YYYYMMDDHHMMSS`, unless the image is built as
a RELEASE (`--build-arg STS_RELEASE=true --build-arg BUILD_NUMBER=0`, the
same two arguments the service's `Dockerfile` takes), when it is that number:
`1.0.0.0`. A release flag with no valid number fails the image build
(`STS-CORE-0164`) and without the flag `BUILD_NUMBER` is ignored. A build of
main also passes `STS_VERSION_RELEASE`, the next patch worked out from the git
tags, as the release in place of `VERSION`'s (`M.N.O` exactly, or
`STS-CORE-0175`; unset, nothing changes) — the rule is `common/CLAUDE.md`'s
*The scheme*. It is
stamped into `version.json` at image build time by the binary itself
(`xacml-pep --stamp .`, `sts-core::version`'s `stamp()`, a port of
`common/version.js` with `cargo test -p sts-core` holding the same cases as
`tests/version.js`), with `build`, `release`, the commit and the build
instant. It rides on the registration and every heartbeat, the PDP stores it
as `xacmlPepVersion`, and `/admin/xacml/peps` draws it — which is why it may
never be a hand-written label (it was `'mock-sts xacml-pep, phase five'`
until 2026-09-06). **A version may never stop this container starting**: an
unreadable `VERSION` is 0.0.0 (`STS-CORE-0040`), a corrupt stamp a computed
record, and a stamp a #1298 build wrote (no `build`) still loads, reporting
the bare `M.N.O`.

**The release must equal the PDP's and an ordinary build number need not**:
two images, built separately, each numbered by the instant it was built. Two
images built as the same release report the same version, and
`sts_xacml_remote_pep.js` then asserts the whole string. `GET /`'s `build`
carries `number`, `release`, `commit`, `at` and `stamped`, and `build.what`
says so. The crates' `Cargo.toml` versions are Cargo's and nothing reads them
at runtime.

## THE AUTHZEN EDGE PDP (#1179)

```
POST /access/v1/evaluation                 one evaluation (section 6)
POST /access/v1/evaluations                a batch (section 7)
GET  /.well-known/authzen-configuration    the metadata (section 9)
```

**A PEP in this container's network may ask a PDP nearby instead of the
service**, and gets the service's answer — because the question is mapped by
the service's contract and decided by the same engine over the same pulled
policy. AuthZEN is the OTHER model from `/protected` (the PEP asks per
decision rather than holding policy itself), and this container is the
place where both can be asked of one holding.

### One request, mapped one way, in two places

* **THE CATALOGUE IS PULLED WITH THE POLICIES.** `sync.rs` pulls `GET
  /xacml/pep/authzen-catalogue` after every policy pull, with its own sync
  token and `?since=`, and keeps the last good catalogue on a failure
  (`STS-XPEP-0040`, `-0041`), as it keeps the policies. Every row is read
  again through `authzen_catalogue.rs`, the port of the grammar — never taken
  on trust, as no pulled policy is — and a row it refuses is left out and
  named (`STS-XPEP-0042`). The pull carries the realm's AuthZEN settings
  that change the mapping or the answer, so `authzen.enabled`,
  `resolveSubjectTypes`, `batchEnabled`, `maxEvaluations`, `maxBodyBytes`
  and `returnReasons` are the realm's here, not a second copy of them.
* **`authzen_cases.json` IS THE CONTRACT, WRITTEN DOWN ONCE.** The service's
  `authzen/` modules and this container's ports are held to the same
  catalogue values and requests: the code each is refused with, and the
  paths and attributes an accepted one supplies and maps to. It is
  `enforcement_cases.json`'s arrangement, for the same reason — two
  implementations kept apart on purpose, and one expectation. Two details
  the port had to reproduce to pass it: members are walked in
  `Object.keys()` order (array-index names first), so a request with two
  problems is refused for the same one; and a JSON number is read as
  JavaScript reads it, a double, so `3.0` is the whole number 3 and an
  integer past 2^53 is not one exactly. **What is not byte-for-byte** is the
  sentence quoting the engine when a STRING will not parse at a row's
  datatype, and `reason_admin`; the code, the status and the decision are
  the contract.
* **THE REQUEST IS BUILT BY THE PORT OF THE ONE BUILDER** —
  `sts-xacml::builder::AuthorizationRequest::authzen()`, spelt as
  `xacml_request.js` spells it (`tests/xacml_request.js` E holds the
  identifiers, `REALM` among them now).
* **THE RESULT IS FAIL-CLOSED AND DENY-BIASED WHATEVER `PEP_BIAS` SAYS.**
  The bias is this PEP's rule for `/protected`; an AuthZEN caller enforces
  the answer itself, and the service's answer is `enforce()` deny-biased.
  A root policy the PDP sent and this engine would not load is a FAULT (500,
  or a batch item's `context.error`), as the service answers a root that
  will not load — not "no root", which would be an ordinary `false`.
* **THE PIP ONLY FOR A SUBJECT TYPE THE REALM RESOLVES**, through the same
  `POST /xacml/pip` `/protected` uses; another type is decided on the
  request alone, as the service's `decide({ resolve: false })` does.
* **NOTHING IS ANSWERED BEFORE BOTH PULLS HAVE LOADED** (`503`,
  `STS-XPEP-0043`): with no catalogue every property would be undeclared,
  which is an answer the service would not give.

### An application that enforces fine-grained authorization is FORWARDED (#564, P7)

**rcbj's decision of 2026-10-30, extending #564's decision 4: this
container does not decide an evaluation about an application that enforces
fine-grained authorization. It forwards it to the service, and an error
there is an error here — never `false`, never the root's answer.** The
application's policy is withheld from the policy pull, so the root is the
only thing it could answer from, and that would be the restriction silently
not applying.

* **WHICH.** The catalogue pull carries `fgaApplications` (`xacml/CLAUDE.md`),
  inside the catalogue's token, held on `Catalogue`. `evaluate_one()` reads
  the request and resolves the application EXACTLY as for any other
  (`authzen_map::read()`, then `application_of()`) and forwards when the
  application is on the list (`forwards()`). Reading first is right, not
  merely convenient: the service reads the same request with the same
  catalogue before it routes on the application, so a request refused here
  would be refused there with the same code, and an application out of the
  caller's scope never reaches the service at all.
* **THE FAIL-SAFE BEFORE THE FIRST PULL IS THE EXISTING ONE.** The list
  travels with the catalogue, and nothing is answered before a catalogue
  has loaded (`503`, `STS-XPEP-0043`), so there is no moment when an
  evaluation is answered without a list to classify it by. A member that is
  not a list of identifiers refuses the WHOLE catalogue and keeps the one
  held (`STS-XPEP-0059`; before any, `503` goes on) — unlike a malformed
  catalogue row or caller entry, which is left out and the rest used,
  because an identifier left out here is an enforcing application decided
  from the root. An ABSENT member is an empty list: a service that does not
  send it predates fine-grained authorization, so nothing there enforces it.
  The cost that remains is convergence: an application switched on is
  decided here from the root until the next catalogue poll, as a caller
  the service stops admitting is admitted until then.
* **ONE SINGLE EVALUATION PER FORWARDED ITEM, NOT THE BATCH.** A batch item
  is forwarded as `POST /access/v1/evaluation` with the batch's defaults
  merged in (`merged()`, the request the service would have read for that
  item). Forwarding the batch would hand the service items this container
  decides itself and a semantic (`deny_on_first_deny`,
  `permit_on_first_permit`) that has to stop at the first decisive item
  wherever it was decided; splitting keeps the semantic, the order and each
  item's own error here, in one place, and needs the PEP admitted to the
  single endpoint only. The cost is a round trip per forwarded item, in
  order. **There is no Search API here** (*What it cannot do*), so there is
  nothing of a search to forward.
* **WHAT IS SENT.** The caller's request for that evaluation
  (`forwarded_body()`), with `context.application` SET to the resolved
  application whether or not the caller sent it — the service scopes the
  question by the PEP's own scope, which may name several. The trusted
  facts are the service's: `urn:sts:xacml:authzen:caller` there is the PEP,
  and `supplied` names `context.application`. `X-Request-ID` is the
  caller's (a batch item's is `<batch id>#<index>`), so the service's audit
  row and this container's log line are found together. To
  `<PEP_PDP_URL>/access/v1/evaluation` — the realm prefix is the PDP URL's
  — through `PdpClient::call_with()`: the ONE client, so the same client
  certificate and the same verification of the PDP as the pull, with
  `PEP_AUTHZEN_FORWARD_TIMEOUT_MS` in place of `PEP_TIMEOUT_MS`. Neither
  the body nor a property value is logged.
* **WHAT COMES BACK** (`forwarded_result()`): a `200` with a boolean
  `decision` is the answer, its `context` passed on (reasons, obligations).
  `400`, `413`, `500`, `501`, `503` are the service's status and message —
  about the request or the application's policy (`500` is its
  `STS-AUTHZEN-0046`) — `STS-XPEP-0057`. `401`/`403` are the service
  refusing THIS PEP, which the caller cannot mend: `502` naming what the
  PEP's entry needs (AUTHZEN_PEPS, the application in
  `stsAuthzenApplication`), `STS-XPEP-0056`. Any other status `502`
  (`0057`); a `200` without a boolean decision `502` (`0058`); no answer
  `502`, or `504` past the timeout (`0055`). Each is the single endpoint's
  status or a batch item's `context.error`, and an item's error is
  `denied` for the batch semantic, as any item error is.
* **COUNTED AND LOGGED HERE**: `answered` counts it like any decision or
  error, and `answered.forwarded` apart; the log line is the usual one
  (types, action, caller, application, request id, never a value) saying it
  was forwarded, with the code when it failed. `GET /`'s
  `catalogue.fgaApplications` is a COUNT — `GET /` answers anybody.
* **WHAT THE OPERATOR OWES**, in `docs/remote-pep.md`: the PEP's own entry
  (the one its certificate is stored on, already holding REMOTE_PEPS) holds
  AUTHZEN_PEPS and has every enforcing application its callers ask about in
  its scope; and the realm's door admits a certificate. **Since #1210 the
  service writes the first two itself** when an application is enforced,
  for every member of `remote-peps` (`authzen/CLAUDE.md`); a PEP added to
  the group afterwards still owes them until the next enable. Nothing here
  checks that ahead of time: the service's answer is the check, and the
  `502`'s message says what to grant.
* **NOT A PROTOCOL JOB.** No protocol job configures this container's edge
  PDP (a client CA and a caller certificate presented to it), so the forward
  is held by `cargo test` against a mock service on a loopback socket, and
  the service's half — `fgaApplications` through a switch flip — by
  `tests/authzen_evaluation.js` K10–K12 and `tests/protocol/sts_fga.js`
  sections 3 and 10.

### Who may ask: mutual TLS, and the service's own list, pulled

rcbj's default for the service (`authzen.callerAuthentication=mtls`) is
this container's only door. **The HTTPS listener ASKS for a client
certificate when `PEP_AUTHZEN_CLIENT_CA` is set, and does not REQUIRE one**:
a certificate that does not verify still completes the handshake, as on the
service's main port, because `/protected` on the same listener takes none and
because the AuthZEN handler can say why it refused where a handshake alert
cannot. `listener.rs`'s `peer_of()` reads what was presented and whether it
verified; `main.rs` puts it on every request of the connection.

Then **the service's own answer decides** (#1189, rcbj's decision): `sync.rs`
pulls `GET /xacml/pep/authzen-callers` after the catalogue, with its own token
and `?since=`, keeps the last good list on a failure (`STS-XPEP-0047`,
`-0048`), and reads every entry again through its own strict grammar
(`parse_pulled_callers()`), leaving out and naming what it refuses
(`STS-XPEP-0049`) — never admitting what it cannot read. Each entry is a
caller the service admits to `/access/v1/*` NOW: the name a policy sees as
`urn:sts:xacml:authzen:caller` (the DN the service's certificate door resolves
the certificate to), the SHA-256 of the DER of every certificate that names
it, its application scope, and the endpoints its access-control policy admits
it to. A certificate is found by its SHA-256 — the byte-for-byte match the
service makes against `userCertificate` since #1061, rather than a subject DN
an outside authority could repeat — and the caller is that entry's name and
scope.

**The accepted cost, rcbj's words on #1189: anybody holding `REMOTE_PEPS` can
read who may ask the PDP.** Which is also why `GET /` here COUNTS the pulled
list and never names a caller: it answers whoever reaches the container.

**`PEP_AUTHZEN_CALLERS` STAYS, AS AN OPTIONAL NARROWING** — the default the
build took for the question #1189 left open, recorded so it can be reversed:
set, a pulled caller must also be on it (by SHA-256; its `name` and
`applications` are not used then), and before the first caller pull it
decides alone, so an edge configured for #1179 keeps answering while its PDP
is unreachable or older than #1189 (whose `404` keeps no list loaded). Unset,
the pulled list alone decides, and nothing is answered before it loads.

Each refusal is the service's status for the same situation and an `XPEP`
code of its own: no certificate or plain HTTP 401 (`-0035`), one that did not
verify 401 (`-0036`), nothing pulled and no local list 503 (`-0050`), a
realm whose door is a token 401 (`-0052` — `bearer` and `mtls+bearer` admit
no certificate alone, so the service sends no caller), a certificate the
pulled list does not name 403 (`-0051`), an endpoint its policy does not admit
it to 403 (`-0053`), one the local narrowing leaves out 403 (`-0054`), and,
before the first pull, one not on the local list 403 (`-0037`). No
`WWW-Authenticate`: a door of certificates alone has no HTTP scheme to name.

### What it cannot do that the service can

* **THE CALLER'S ROLE AND APPLICATION SCOPE ARE PULLED, NOT ASKED** (#1189).
  The service decides `AUTHZEN_PEPS` by its access-control policy at the
  moment a caller asks; here it is that answer as of the last poll, so a
  caller the service stops admitting is admitted here until the next one. The
  candidates are the group's members, so an entry a policy admits WITHOUT the
  role is admitted there and not here; and the certificates are those stored
  on the entry and the TLS client certificates the realm issued it, so one
  enrolled over ACME, EST or SCEP and not stored is not admitted here. Each
  is narrower, never wider.
* **WHAT LANDED BESIDE IT (#1175, #1177, #1178).** The edge PDP was written
  against the evaluation and batch APIs only: it serves no Search API, hands
  no Obligations Profile obligation (a Permit carrying one answers `false`,
  the service's answer to a PEP that declared none, and
  `context.supported_obligations` is an undeclared member here), and sends
  no `signed_metadata`, holding none of the realm's signing keys. Each is a
  follow-up, not a regression: the fail-closed answer is the same.
* **FINE-GRAINED AUTHORIZATION IS NOT DECIDED HERE** (#564): it is
  forwarded (above), so it costs a round trip and depends on the service
  being up, and a switch of enforcement reaches here on the next poll.
* **THE TOKEN DOORS.** `bearer` and `mtls+bearer` check a token's issuer,
  audience, revocation and client against the realm in process. Not here.
* **REVOCATION** of the caller's certificate is not checked here. A
  certificate the service's own register records as revoked leaves the
  pulled list on the next poll; an outside authority's CRL or OCSP answer is
  never consulted, there for the list or here.
* **THE PIP IS A NETWORK CALL**, the existing one: if `POST /xacml/pip`
  refuses or fails, the subject's attributes are an empty bag, as for
  `/protected` — the degraded state is the old one, here too.
* **THE AUDIT LOG.** One log line per evaluation, carrying what the service's
  `authzen.decision` row carries and nothing more (no property value, no id
  the caller sent, no credential), tagged `STS-AUTHZEN-0028`/`-0029` where
  the row would be; `GET /`'s `authzen.answered` counts them. They are
  counted apart from `enforced`, which the heartbeat reports: the AuthZEN
  caller enforced these, in its own process, so the PDP's console never
  sees them — the same reason the service's monitor counts AuthZEN
  decisions and not enforcements.
* **A CATALOGUE OR CALLER CHANGE IS NOT NUDGED**; each converges on the
  poll.

### The metadata

`policy_decision_point` is `PEP_AUTHZEN_PDP_IDENTIFIER` or, unset, the
origin the HTTPS request arrived at — section 9.2.3 has a PEP refuse a
document whose identifier is not the base it built the URL from, and the
endpoints are served at this container's root, so an identifier with a path
is refused at start (`STS-XPEP-0045`). It names the batch endpoint only
while the realm has it on, and nothing unimplemented, as the service's does.

## THE REVERSE PROXY (#1760)

```
PEP_PROXY_PORT        9180   plain HTTP, only with PEP_PROXY_HTTP=true
PEP_PROXY_HTTPS_PORT  9543   the pair 9443 serves, a client certificate asked for
GET  /.iya-pep/callback      the session mechanism's redirect URI
GET  /.iya-pep/logout        ends the proxy session, then the service's
GET  /.iya-pep/accounts      the account chooser (multipleAccounts routes)
GET  /.iya-pep/accounts/add  another account, prompt=login
POST /.iya-pep/accounts/{switch,logout,logout-all}
GET  /                       the start page, when no route matches /
GET  /.iya-pep/logo.png      the product logo that page draws
everything else              the route table
```

**SEVERAL ACCOUNTS IN ONE BROWSER (#1760, rcbj 2026-11-14)**, on a session
route with `multipleAccounts`. The pattern is the `oidc-caep-risc` libraries'
demo: an account set per browser, an active account, add, switch, and sign
out one or all. The Rust repository's own demo does not draw it; the Node.js
library's `demo/server.ts` does. **Built on the library's 0.3.0 API with
nothing faked**: `authorize_options` (`prompt=login`, `login_hint`,
`expected_sub`), one `complete_session` per account under its own proxy
session id, and the receiver's `track`/`untrack` per session. So the
library's CAEP `session-revoked` ends exactly the account whose sign-on
session it names. The set is `rp_session.rs`'s: per browser
(`iya_pep_accounts` cookie, never forwarded), ACTIVE per application client,
and an ended session drops ITS account and makes no other active (the
browser is sent to the chooser; an identity is never picked for the person).
The same subject signing in again replaces its own account's session.
**An account is named by USERNAME** (2026-11-14): it was filled from the ID
Token's `preferred_username` alone, which the service's ID Token does not
carry (#395), so the chooser labelled every account by its `urn:uuid`
subject, and the username a later session check learned reached the session
and never the account. The callback now asks `validation.session` once when
the ID Token names nobody, and `Stores::named()` writes a learned username,
and the display name (`name`, from the ID Token or the session answer),
onto the session AND the account it backs; the chooser draws `username — name`
and `?format=json` carries both. A
full set (`proxyMaxAccounts`) refuses, `STS-XPEP-0108`. The chooser and its
acts are server-drawn HTML, forms only, in the error page's document shell
(`proxy_page::document_shell`): the same style sheet admitted by its
SHA-256, and the same footer. It is not an error page. The active account
offers *Continue with this user*, a GET form to `return`, which changes
nothing. `return` is followed — by that form, by a switch, and by either
sign-out — only when its path matches a configured route
(`ProxyConfig::route_for`); otherwise those acts go to `/`.
Cross-site POSTs are refused (`STS-XPEP-0109`; the cookie is SameSite=Lax
as well). The active account is per browser, not per tab: a proxy cannot
tell tabs apart without rewriting the application's URLs.

**rcbj's ticket: this container in front of ONE application, deciding
locally whether a request goes through, on routes and mechanisms the
administrator configures in the service's Remote XACML section.** The
decisions D1–D11 on #1760 are the contract — D5 as rcbj revised it, D10
and D11 superseding the route members of the first draft; this is the
PEP's half of it (D2, D3, D4 and D11's identity endpoint as a client, D5's
relying party, D6, D7's local column, D8, D10, D11's delivery). The
service's half is `xacml/CLAUDE.md`'s.

**ON PORTS OF ITS OWN, FOR BACKWARDS COMPATIBILITY.** 9090, 9443, the four
endpoints, `GET /` and the AuthZEN edge are untouched; the one addition to
them is a `proxy` member on `GET /`, which COUNTS (routes, routes per
mechanism, answers by status, live sessions, sign-ins in flight) and names
no route, URL, credential or person — `GET /` answers whoever reaches the
container. `PEP_PROXY=false` starts neither listener and skips the pull.

### The configuration is pulled, read again, and loaded whole

`sync.rs` pulls `GET /xacml/pep/proxy` after the AuthZEN callers on every
poll, with the same client certificate, its own sync token (`?since=`) and
`If-None-Match` with the `ETag` it was last given. 304 is unchanged; a
failure keeps the configuration held (`STS-XPEP-0060`, `-0061`, a PDP older
than #1760 answering 404); `configured: false` holds nothing, and the proxy
then answers 404 to everything. **Before the first answer is loaded the
proxy answers 503, not 404** (below). **Every member is read again by D2's rules**
(`proxy_config.rs`): the upstream an absolute http(s) URL with no userinfo,
query or fragment; at most 64 routes with unique ids; a route path with no
dot segment, `//`, `%`, backslash or control character; the mechanisms and
match from their closed sets; each non-public route's `application` and
`resolved` (D10) and every route's `identity` (D11); `publicBaseUrl` when a
route uses `session`; the two bounds in range; each signing certificate a
PEM certificate; the validation URLs absolute. **Two route members are
REQUIRED**, and a route without either refuses the document:

* **`methods`**, from the closed set. **An EMPTY list allows NO method — the
  route is deny-all**; "any" is the whole set, stated. It meant "any" until
  rcbj's decision on #1760, so an absent list cannot be read either way
  without guessing, and is refused.
* **`authorization`** — `{ kind, policy, resource, actionModel, roles }`, the
  route's ONE authorization choice (`proxy_config.rs`'s `Authorization`).
  `kind` is `policy` (an administrator's own policy entry), `simple` (the
  one the service generated from the route's roles) or `public`; **public is
  a kind now, not a boolean**, and a public route takes no mechanism, names
  no application and has no `resolved` — the old boolean's rules, keyed on
  the kind (`Route::is_public()`). `policy` is required and non-empty for
  EVERY kind: the NAME of a policy entry (the `name` of a row of
  `GET /xacml/pep/policies`, never its PolicyId), the service naming the one
  it generated (`pep-<pep>-<route>`) for a simple or public route. `resource`
  is the resource-id sent, empty for the normalised path. `actionModel` is
  `method` (the HTTP method), `crud` (GET, HEAD, OPTIONS `read`; POST
  `create`; PUT, PATCH `update`; DELETE `delete`) or `read-write` (the three
  safe methods `read`, the four others `write`). `roles` is the service's
  own and is not read beyond being an object, the policy already saying it.
  The route members `public`, `resource` and `action` are gone.

**One refusal refuses the document WHOLE and the one held is kept**
(`STS-XPEP-0062`) — a route table loaded in part forwards what nobody
configured or refuses what somebody did. Unknown members are ignored, so a
service that adds one does not switch the proxy off. Not nudged: it
converges on the poll.

**THE DOCUMENT'S BACKWARDS COMPATIBILITY WAS NOT KEPT** for the change to
`methods` and `authorization` (rcbj: the proxy is unreleased, so its pulled
document changes shape freely). **A PEP older than it, reading a new
document**, ignores `authorization` as an unknown member and finds no
`public`, so it reads a public route as non-public with no mechanism and
refuses the document whole (`0062`), keeping what it held — but only when
the table HAS a public route: a table without one it would load, reading an
empty `methods` as "any" and deciding every route from the root with the
path and the method. **A PEP newer than it, reading an older service's
document** (no `authorization`, or a route without `methods`), refuses it
whole. The pair is upgraded together.

### A request, in order

`proxy.rs`'s `answer()`; each step's refusal is the first one met.

1. **The path is normalised or refused** (400, `STS-XPEP-0064`;
   `proxy_request.rs`): a `.` or `..` segment, `//`, a backslash, a NUL or
   control character, a byte that is not ASCII, an invalid percent-escape,
   and an ENCODED `.`, `/`, `\` or NUL (`%2e`, `%2f`, `%5c`, `%00`) —
   wherever it is, not only where it would make a segment, as D8 says. An
   escape of an UNRESERVED character is DECODED (RFC 3986 section 6.2.2.2),
   so `/%61pi` is matched and forwarded as `/api` and cannot slip past an
   exact route to a prefix route behind it; every other escape is kept, hex
   upper-cased. **The normalised path is what is matched AND what is
   forwarded**, so the route that decided and the resource the application
   serves are one string.
2. `/.iya-pep/callback` and `/.iya-pep/logout` are the session mechanism's,
   ahead of the route table.
3. **The route**: the FIRST whose path matches — exact, or prefix at a
   segment boundary (`/api` is `/api` and `/api/…`, never `/apix`; a
   configured trailing `/` is dropped). No route, or no configuration
   switched on: 404 (`STS-XPEP-0065`), and the application is never reached.
   **Before any configuration answer has been loaded since the start** this
   step is not reached: every path, `/.iya-pep/*` included, is 503 (below).
4. **The method**: a NON-EMPTY `methods` without it is 405 with `Allow`
   (`STS-XPEP-0066`); the next route is NOT tried. That is route matching,
   not authorization. **An EMPTY list is not a 405** — there is nothing to
   put in `Allow` — and the request goes on to be decided (7), then refused
   (7a).
4a. **The route's application** (D10): a non-public route the pull marked
   `usable: false` is 403 (`STS-XPEP-0093`), before any credential.
5. **A declared body over `maxBodyBytes`**: 413 before anything else
   (`STS-XPEP-0067`).
6. **The mechanism**, unless the route is public (below). A public route
   establishes no identity.
7. **The decision, for EVERY route, a public one included** (D8, and rcbj's
   decision on #1760: *all authorization decisions are made in XACML*):
   `service.rs`'s `decide_proxy()` — subject the username when known, else
   `sub`, and for a public route NO `subject-id` at all (the anonymous
   subject: the access-subject category sent empty, as `/protected` sends a
   request with no `subject`); resource `authorization.resource` or the
   normalised path (typed anyURI, as `/protected` types it); action by
   `authorization.actionModel`; through the one builder, **evaluated against
   the policy entry `authorization.policy` NAMES in what this PEP last
   pulled — never the root, which no route falls back to** — the PIP walking
   THAT policy and the repository answering its references, `enforce.rs`'s
   bias and obligation rule, counted with `/protected`'s counters (so the
   heartbeat reports them). `sync.rs`'s `Policies::by_name` holds every entry
   that loaded by its name (a name two rows carry is in neither); the route
   decision does not ask whether a root is held. **The named policy not
   held** — never pulled, withheld, disabled, renamed, failed to load — is
   403 (`STS-XPEP-0117`, logged at warn) WHATEVER THE BIAS, with nothing
   counted: a permit-biased PEP reading it as NotApplicable would open the
   route the moment its policy went missing. Not allowed: 403
   (`STS-XPEP-0086`).
7a. **Deny-all**: a route whose `methods` is EMPTY is refused now, 403
   (`STS-XPEP-0116`), after its decision was made and counted and even when
   the policy permitted — so a policy that permits too much cannot open a
   route that states no method. A missing policy is still `0117` (7 comes
   first). Nothing of 7 or 7a reaches the application.
8. **The identity** (D11, below), established BEFORE the forward — or the
   request is refused.
9. **The forward**, below.

### Not configured YET is 503, not 404 (rcbj, 2026-11-15)

**On 8081 a recreated PEP container answered every proxy path 404
`STS-XPEP-0065` for 56 seconds** — from its start at 19:03:59Z until
registration succeeded on its third attempt and the first pull loaded the
settings, the policies and 4 routes at 19:04:55 — and a browser was shown
"Page not found" for pages that existed. **rcbj's decision: until the
proxy has received its first configuration since the start it says "try
again later".** `Sync::proxy_received()` hands `answer()` the configuration
and `ProxyHolding::loaded` under one lock, and the rule is ahead of
everything, the callback, the sign-out and the account chooser included
(each needs the configuration's realm and routes):

| The proxy holds | Answered | Code |
|---|---|---|
| no configuration answer loaded since the start (a pull not yet made, refused, or failed) | **503** `temporarily_unavailable`, `Retry-After` the poll interval in whole seconds rounded up, at least 1; the page's "Try again later" | `STS-XPEP-0118` |
| an answer, `configured: false` or `enabled: false` | **404** `not_found`, deny by default. A browser's GET or HEAD of `/` is the start page (200) | `STS-XPEP-0065` |
| an answer with routes, and the path matches none | **404** `not_found`. A browser's GET or HEAD of `/` is the start page (200) when no route matches `/` | `STS-XPEP-0065` |

`loaded` never goes back to false: a later pull that fails keeps what was
received and its 404 or its routes. **The JSON is the other 503s' shape**
(`0085`, `0090`): `{error: "temporarily_unavailable", error_description}`,
the description a fixed sentence of its own (`shown_description()`), never
the code. **The log is the state change, not a line per request**
(`Sync::note_waiting()`): one warn line tagged `0118` when the first such
request arrives, a count at most once per `WAITING_SUMMARY_EVERY` (60 s)
while they go on, and one info line with the total when the first
configuration loads (`load_proxy()`). The per-request line, with the page's
incident ID, is at debug — the one refusal whose line is. The health check
and the decision API are untouched: `/protected` before its first policy
pull is decided by the bias (`0005`), and the AuthZEN endpoints already
answer 503 until their catalogue is pulled — neither had this 404.

### What a refused PERSON sees: the service's error page (2026-11-15)

**rcbj: the proxy's refusals are standardised on iya-sts's error page and
its diagnostic pane** (`common/error_page.ts`, #1326). Until then every
refusal was the JSON answer whatever asked, and `STS-XPEP-0108` was a bare
page of its own. **The rule is one line in `refuse()`: a request whose
`Accept` holds `text/html` — any method, so a form a person posted too
(`wants_html()`, `proxy_request.rs`) — gets `proxy_page.rs`'s page; anything
else gets the JSON it always got, byte for byte** (the
`error_description` of `STS-XPEP-0093` and `0117` now chosen in
`shown_description()` rather than written over the body afterwards). The
status and the headers are the refusal's either way: a 401's
`WWW-Authenticate`, a 405's `Allow`, a 429's and `0118`'s 503's
`Retry-After`. A browser on a
`session` route with no session is still REDIRECTED to sign in, not shown a
page; `0108` is always the page (the callback is a navigation).

* **The page is the service's, section for section** — title, the yellow
  box with the `error` as a value and a sentence (`wording()`, by code where
  the code says more than the status), what the person can do, the
  background in a `<details>`, the start-over note with a link to `/`, the
  Diagnostics box, and the copyright and version lines of the footer.
  **`GET /` is that start page** when no route is mounted there
  (`proxy_page::front_document`): the front door's card — the product logo
  (`docs/logo.png`, embedded, drawn at `/.iya-pep/logo.png`), the name, one
  sentence — and this shell's footer. It lists no route. A route mounted at
  `/` is that route. A client that does not accept HTML still gets the
  404, and until the first configuration `/` is the 503 above. **What
  the person can do** is offered only where the refusal is about WHO is
  asking (`0086`, `0095` at 403) on a `session` route: *Use a different
  account* (`/.iya-pep/accounts`) on a `multipleAccounts` route, a sign-out
  (`/.iya-pep/logout`) on any other. Adding an account stays on the
  chooser. English only: the PEP holds no
  catalogs, so the service's language chooser is not drawn.
* **The pane shows what the service's shows, and no code.** The time (UTC),
  the INCIDENT ID, then the application, the address, who is signed in, the
  `error` and the `error_description` — exactly what an API client of the
  same request is answered, so the page sends nothing the JSON did not. A
  5xx's description is the generic sentence, `0093`'s and `0117`'s too.
* **THE INCIDENT ID.** The service's is the `seq` of the audit row; this
  container has no audit log, so its incident ID is 64 random bits in hex,
  drawn for the page and written into the refusal's log line beside the
  code (`… with 403, page incident 3f9c…: …`). An operator searches the log
  for the number the person sends. A request answered JSON draws none and
  its line is as it was. `proxy.rs`'s `logged` module records each line for
  the tests, because a thread-local subscriber does not reliably see the
  server task's events across the suite's threads.
* **CSP**: no script. The page's one `<style>` element is admitted by its
  SHA-256 (`style-src 'sha256-…'` on top of the proxy's `default-src
  'none'; img-src 'self'; form-action 'self'; frame-ancestors 'none';
  base-uri 'none'`). Style and script stay narrower than `'self'`.
  `img-src 'self'` admits the start page's logo, which is this proxy's own
  path. **The CSS is a copy** of
  `error_page.ts`'s and of `web_footer.ts`'s two footer rules, since this
  image is built from `rust/` alone: change one, change the other.
* The account chooser (`chooser_html()`) is not an error page: no warning
  box, no diagnostics, no incident ID. It is drawn by `document_shell()`,
  so it has the error page's style sheet (centered column, the same type,
  the portal actions, the footer) and that sheet's hash in `style-src`.
  Its own rules in the sheet (`ul.accounts`, `button.portal`, `p.hint`)
  match nothing on the error page. Until 2026-11-15 it was bare markup
  under a policy with no `style-src`, which is the unstyled page a person
  met after *Use a different account*.

### The headers that may not cross

**To the application** (`forward_headers()`): the hop-by-hop headers gone —
`Connection` and every header it names, `Keep-Alive`, every `Proxy-*`, `TE`,
`Trailer`, `Transfer-Encoding`, `Upgrade`; every `X-Forwarded-*` and
`Forwarded` the CLIENT sent gone; `Host` gone (the client library writes the
upstream's); every identity header ANY route names gone (D11), on a
public route too; and unless the route says
`forwardCredentials`, `Authorization` and the `iya_pep_session` cookie gone;
and, WHATEVER `forwardCredentials` says, the identity provider's cookies gone
(2026-11-14, found on the 8081 demo): a browser sends cookies by HOST, not
port, so where the service and the proxy share a host
`__Host-sts_session`, `__Host-sts_accounts` and `__Host-sts_signin_step` were
forwarded to the application — a sign-on session's handle in somebody else's
log. **The service publishes its names rather than this binary writing them
down**: the pull's `realm.serviceCookiePrefixes` (`common/cookie_wire.ts`'s
`servicePrefixes()`, derived from the one pattern that names every cookie the
service writes), so a cookie added there is stripped here with no PEP
release; a pull with no member — an older service — stands on
`proxy_config::SERVICE_COOKIE_PREFIXES`, the same three prefixes, which is the
one hard-coded copy and is used only then. The managed `proxyStripCookies`
(`PEP_PROXY_STRIP_COOKIES`) adds names, a trailing `*` a prefix, for another
identity provider on the host. Nothing else is touched: the application's own
cookies are its own (`proxy_request::cookie_stripped`, a prefix only with
the `*`). Then set fresh: `X-Forwarded-For` (the
connection's peer, never a header), `X-Forwarded-Proto`, `X-Forwarded-Host`
(the client's `Host`), then the route's identity (D11). **To the client**:
the application's hop-by-hop headers gone (and, in mode `saml`, the
`Set-Cookie` of every jar cookie), everything else as it was.

### The forward

**The destination is never the request's**: the configured upstream base,
the normalised path and the original query, and the result checked to still
be on the upstream's origin and under its path (502, `STS-XPEP-0091`). One
`reqwest` client per `upstreamTimeoutMs`: no redirect followed (the
application's 302 is the client's), no environment proxy, the system's
anchors plus `PEP_PROXY_UPSTREAM_CA` (or `PEP_PROXY_UPSTREAM_INSECURE`).
**Both bodies stream.** The request body goes through a counting wrapper
that fails past `maxBodyBytes`, which is a 413 even mid-stream
(`STS-XPEP-0067`); a request with neither `Content-Length` nor
`Transfer-Encoding` is sent with no body at all, so a GET is not turned into
a chunked one. Past `upstreamTimeoutMs`, connect included: 504
(`STS-XPEP-0068`); unreachable or failed: 502 (`STS-XPEP-0069`). A 5xx body
is a generic sentence — the logged reason may name the service's or the
application's address.

### Each mechanism, here and at the service (D7)

**Chosen by the `Authorization` scheme** — `Bearer` (and `DPoP`) is
`oauth2`, `SAML` is `saml2`, `Basic` is `basic` — when the route takes it;
otherwise, on a route that takes `session`, the cookie. A scheme the route
does not take, or a header that cannot be read, is 401 (`STS-XPEP-0089`); no
credential at all is 401 (`STS-XPEP-0070`). **A 401 carries a
`WWW-Authenticate` for each mechanism the route allows** — `Bearer
realm="<pep>"` with `error="invalid_token"` when a token was refused,
`Basic realm="<pep>", charset="UTF-8"`, `SAML realm="<pep>"`; the session
mechanism has no scheme. **Every validation call goes through the ONE
client** (`PdpClient::call_url()`, the absolute URL the pull named), so the
PEP's certificate is presented and the PDP verified as for every pull. **A
service that cannot be asked refuses, never admits** (502,
`STS-XPEP-0075`).

| Mechanism | Here (`jwt.rs`, `saml_verify.rs`) | At the service |
|---|---|---|
| `oauth2` | A compact JWS: RS256/384/512, PS256/384/512, ES256/384/512 against the RSA and EC keys of the realm's JWKS (an OKP, AKP or encryption key is left out); strict base64url; `none` and a key of the wrong type refused; `iss` the realm's, `aud` (string or array) holding ANY of the route's resolved `audiences` (D10), `exp` required, `exp`/`nbf` with 60 s of skew (`STS-XPEP-0071`); `cnf.x5t#S256` equal to the SHA-256 of the certificate presented on THIS connection (`STS-XPEP-0073`, also for a `cnf` member it cannot check); `cnf.jkt`, and the `DPoP` scheme, refused by name (`STS-XPEP-0072`) | An opaque token, a JWS whose algorithm is not verified here (EdDSA, ML-DSA, a composite), or whose `kid` is unknown after one refetch: `POST validation.introspect { token }`, and only `active: true` with the realm's `iss`, one of the resolved audiences in `aud` and an acceptable `cnf` admits (`STS-XPEP-0074`) |
| `saml2` | `Authorization: SAML <base64>`: the one shape the service signs (below). An EncryptedAssertion is refused, here, and nobody is asked (`STS-XPEP-0076`) | **ANY local failure** — logged at info, `STS-XPEP-0077` — is `POST validation.saml { assertion, audience }` (the resolved `samlAudience`), and only `valid: true` admits (`STS-XPEP-0078`) |
| `basic` | never | always `POST validation.basic { username, password }`; `valid: false` is 401 (`STS-XPEP-0079`); its 429 is passed on with `Retry-After` from `retryAfterS` (`STS-XPEP-0080`); its `ticket` is the identity endpoint's evidence (D11) |
| `session` | the sign-in, by the `oidc-caep-risc` library; the proxy cookie | a sign-out through the library's CAEP/RISC receiver, or `POST validation.session { sid }` with `signals: false` (below) |

**The JWKS is cached** for `PEP_PROXY_JWKS_TTL_MS`; an unknown `kid` fetches
it again at once after an ordinary fetch (a rotation being picked up) and
then at most every five seconds, so tokens naming invented `kid`s cannot make
this PEP fetch per request. A fetch that fails keeps the keys held
(`STS-XPEP-0088`); with none, a JWS is the service's to introspect.

### The SAML check, and why a local failure is a question

`saml_verify.rs` reads exactly the shape `common/crypto_impl/xmldsig.js`'s
`signEnveloped()` makes for `saml/saml2.ts`: the document is the Assertion
(Version 2.0, an `ID`); no DOCTYPE; EXACTLY ONE `ds:Signature` in the
document, a direct child of the Assertion, holding SignedInfo,
SignatureValue and at most a KeyInfo (which is IGNORED — the key is a pulled
signing certificate's, never the document's); one Reference whose URI is
`#` + the ID, and no other element carrying that ID (signature wrapping);
the transforms exactly enveloped-signature then exclusive c14n, with no
InclusiveNamespaces, and exclusive c14n for the SignedInfo; RSA PKCS#1 v1.5
or ECDSA (r‖s) with SHA-256/384/512, and those digests. Then, **off the
verified node's own children and nothing else** — the digest is over that
node minus its Signature — the Issuer is `samlIssuer`, one Conditions with
a `NotOnOrAfter` and a `NotBefore` that hold (60 s skew) and nothing but
AudienceRestriction children, each holding the route's resolved
`samlAudience` (D10), and one
NameID (the subject; `uid` or its OID attribute is the username).

**Exclusive c14n (without comments) is written here**, over roxmltree, which
resolves namespaces but does not keep the PREFIX an element or attribute was
written with — and c14n renders prefixes. So each prefix is read from the
source text at the node's own range, never looked up by URI (two prefixes
may bind one URI). A declaration is rendered only where the element's own
name or an attribute uses it and the nearest rendered ancestor did not render
the same binding; `xmlns=""` only to undo a rendered default; attributes
sorted by namespace URI then local name; C14N 1.0's escapes; comments
dropped; a processing instruction is not read. The test vector's canonical
forms are written out BY HAND in the test and were checked, when written,
against lxml's independent exclusive c14n (all three agreed).

**A failure here is never a refusal**: an XML signature has more legitimate
shapes than this file reads, and refusing one would refuse a person the
service admits. So the cost of the narrow reader is a round trip, never a
wrong answer, and the security of the local path rests on its success being
strict: nothing is admitted here that the digest and the signature did not
cover.

### A route references an application (D10)

**rcbj's decision of 2026-11-14: a route names the application behind it,
and the configuration holds no copy of anything about it.** A non-public
route carries `application` (an identifier — here it is only a name for the
log) and the pull answers it RESOLVED from that application's own entry,
every pull: `resolved = { usable, why?, code?, audiences?, samlAudience?,
clientId? }`. `oauth2` admits a token whose `aud` holds ANY of `audiences`
(those the service writes into an access token for the application);
`saml2` takes `samlAudience` (the application's SP entity ID) as the
assertion's Audience; `session` takes `clientId`, whose secret, auth
method, redirect URI and scopes come in `realm.clients[clientId]`.

**`usable: false` — the application deleted, or no longer qualifying — is
REFUSED (403, `STS-XPEP-0093`), never admitted on what an earlier pull
said**, with no credential asked for and the service's `why` and `code` in
the log only (the body says the route cannot be used now). A later pull that
says `usable: true` makes it work again; nothing is held against it. **Read
strictly**: a non-public route without `application` or `resolved`, a
`usable` that is not a boolean, a usable route missing what its mechanisms
need (an audience for `oauth2`, a `samlAudience` for `saml2`, a `clientId`
for `session`), a usable session route whose client `realm.clients` does not
carry, or a client without a secret or redirect URI refuses the document
WHOLE (`STS-XPEP-0062`). A route whose `authorization.kind` is `public`
naming an application or a mechanism is refused too. D10 is about which
application a route fronts; WHO may reach it is the route's own policy
(*A request, in order*, 7).

### The session mechanism: the proxy is the application's relying party (D5)

**rcbj's decision (D5 revised): the proxy is the OpenID Connect relying
party ON BEHALF OF THE APPLICATION BEHIND IT** — an ordinary CONFIDENTIAL
client the administrator registered in iya-sts, with
`<publicBaseUrl>/.iya-pep/callback` among its redirect URIs — **and it is
implemented with rcbj's crate `oidc-caep-risc` (0.3.0 from crates.io, MIT, `features =
["tokio"]`; a git commit until it was published on 2026-11-14)**,
never a relying party written here (`rust/DESIGN.md` section 7). The
hand-written PKCE, nonce, token exchange and ID Token check of the first
draft are gone; `jwt.rs` stays for the `oauth2` mechanism.

**One `RelyingParty` per client** (`rp_set.rs`), made with
`RelyingParty::create` from the pull: `issuer` (the realm's) and its
`metadataUrl` (`<issuer>/.well-known/openid-configuration`), the
`clientId`, `clientSecret`, `tokenEndpointAuthMethod`, `redirectUri` and
`scopes` (with `openid` first) of `realm.clients`, `tlsCa` = the pulled
`realm.tlsCaChain` inline (the service's listener chain; the library adds
every certificate in it as an anchor and checks the host name), `signals`,
and `allowInsecure` from `PEP_PROXY_RP_ALLOW_INSECURE` (an `http` issuer, a
development provider only — it never relaxes the redirect URI, which the
library holds to https or loopback). An entry is keyed by a digest of all of
that plus the registered PEP name, so **a pull that changes any of it — a
rotated secret, a re-issued chain, registration completing — builds a new
relying party** and stops the old receiver; the
library's session store is handed from one to the next
(`set_session_store`), so a rotation signs nobody out. `proxy.reconcile()`
runs after every poll (`main.rs`) and builds what the pull calls for and
drops what it no longer does; a request also builds one on demand. **No
secret is logged, kept in a `Debug` line (`RpClient`'s is redacted) or shown
on `GET /`**, which counts relying parties and receivers only.

**THE LIBRARY'S ASYNC API** (its `tokio` feature): `create_async`,
`authorize_async`, `complete_session_async`, `session_access_token_async`
and a receiver's `start_async` are awaited; the library runs each on tokio's
blocking pool, never on the runtime's threads. Its HTTP client is still
`ureq`, so each call in flight holds one blocking-pool thread (at most the
library's 15 s timeout per request) and a dropped future does not cancel it.
That is the cost the proxy paid with its own `spawn_blocking` until 0.3.0,
and the library pays it now. Sign-ins are the only such calls on a request;
access checks (`session()`, `health()`) are map reads. A receiver's
`stop_async`, which waits only for a transmitter call in flight, runs as a
task of its own and is never awaited on a request; the receiver polls on its
one thread.

**A browser** — a GET or HEAD whose `Accept` holds `text/html` — on a
`session` route with no live proxy session of THAT application is sent
(302) to the URL the library's `authorize()` builds (the code flow, PKCE
S256, a `state` and a `nonce`, the application's scopes, PAR and DPoP when
the provider offers them). The library's `Transaction` and where the browser
was going (the normalised path and the original query, relative, NEVER
anything the callback brings) are kept here under the state, ten minutes.
Anything else is 401 (`STS-XPEP-0081`). A relying party that cannot be built
is 503 (`STS-XPEP-0090`); `authorize()` failing, 502 (`STS-XPEP-0075`).

**`/.iya-pep/callback`** takes the state ONCE (unknown, spent or expired:
401, `STS-XPEP-0082`), draws the proxy session's id (256 random bits), and
calls `complete_session(query, transaction, id)`: the library redeems the
code with the application's client authentication and verifies the ID
Token (signature against the provider's JWKS, `iss`, `aud`, nonce, `iat`
within ten minutes, `exp`, `typ` JWT and `at_hash`), refusing a reused code;
any refusal is 401 (`STS-XPEP-0083`, the library's code and message in the
log). The proxy session is made under THE SAME id the library keeps its
session under — subject `sub`, username `preferred_username` (else the
`username` claim), the provider's `sid` — and, with signals on, the session
is TRACKED by the receiver (`local_id`, `person`, `email`, `idp_session`).
Then `iya_pep_session` (`HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` on
the HTTPS listener) and a 302 to where the browser was going. A full store
refuses BEFORE the code is spent (503, `STS-XPEP-0085`).

**A session is the application's.** A proxy session made by one client is
not a session on a route of another application: that route sends the
browser to sign in to its own.

**A sign-out at the service ends access** (`STS-XPEP-0084`):

* **Signals on (the default).** The receiver (`SignalsReceiver` with
  `relying_party`, the issuer as the transmitter, `ssf.manage`, polled every
  `PEP_PROXY_SIGNALS_POLL_MS`) finds the poll stream, and a CAEP
  `session-revoked` naming the provider's session removes it from the
  library's cache — and, through the receiver's callback, the proxy session
  here. **Once registration has succeeded, every transmitter call carries
  `X-Iya-Pep-Name` with the name the service answered** (#1760 phase 3),
  so two members of one application client each poll the stream tagged
  with their own name. The name is in the party's digest: the library
  lists once, when the receiver starts, and does not list again when a
  poll fails, so a receiver built before the name was known would keep
  the untagged stream. A PEP that has not registered sends no header and
  keeps that untagged stream. A PEP that already held it and then starts
  sending the header creates a new tagged stream; until the old one ages
  out an event is delivered to both, and Security Event Tokens still
  queued on the old stream when the receiver is rebuilt are not
  collected. **Each access asks the library whether the session is still there**
  (`RelyingParty::session(id)`): a lookup in the library's in-memory store,
  no network, no lock held across an await — the cost of one `HashMap` get
  under the library's mutex. Nothing else is asked.
* **Signals off** (`signals: false` on the route), **or a receiver that
  would not start** (`STS-XPEP-0094`, logged once per build): the session
  endpoint, as the first draft did — `POST validation.session { sid }` when
  the last answer is older than `PEP_PROXY_SESSION_RECHECK_MS` (0 asks every
  time), `live: false` ending it, a service that cannot be asked a 502 with
  the session kept.

An ended session sends a browser to sign in again with the cookie cleared,
and anything else gets 401. **Including a cookie naming a session the proxy
no longer holds** (2026-11-14): the CAEP receiver removes the session before
the browser's next request arrives, so that request found NO session and was
redirected without the clearing `Set-Cookie`; a cookie that names nothing
held is now cleared on that redirect. **And the window before the signal**:
a sign-out at the service revokes the session's access tokens at once
(#1449), so for up to a second the identity endpoint refused the token and a
browser got 403 "the service refused the identity". `Proxy::ended_behind()`
answers that refusal of a PROXY SESSION's identity by asking
`validation.session` whether the sign-on session is live; ended, the proxy
session ends as a signal would have ended it (a browser to sign in, cookie
cleared, or the chooser on a `multipleAccounts` route; anything else 401); a
refusal of a live session stays the 403 it was. **`/.iya-pep/logout`** ends the proxy session
here and in the library (`remove_session`, and the receiver's `untrack`),
clears the cookie, and sends the browser to the library's
`end_session_url()` (the provider's `end_session_endpoint` from discovery,
with `id_token_hint` and `client_id`).

**What the library offered too little of, and what 0.3.0 changed**
(rcbj/oidc-caep-risc-rust PR #44; each gap confirmed here first):

* **A non-blocking API.** The `tokio` feature's `_async` calls, above.
* **A receiver's health.** `SignalsReceiver::health()`: running, the last
  successful poll, the last error, failures in a row, counters. **A stream
  that stops answering after start IS noticed now**: with no successful poll
  within `PEP_PROXY_SIGNALS_STALE_MS`, `Party::signals_live()` is false, so
  that client's routes ask the service's session endpoint (on
  `PEP_PROXY_SESSION_RECHECK_MS`) until a poll succeeds again, and a
  sign-out signalled while the stream is down is still caught.
  `STS-XPEP-0099` is logged when it goes stale and the recovery once, never
  per request. The service is not asked while the stream is healthy, or
  signals would buy nothing. `GET /`'s `proxy.signals` reports it:
  receivers, healthy, stale, the oldest last-success age, the most failures
  in a row, SETs accepted and refused, sessions ended, and the library
  stores' held / max / evicted / expired. Counts and ages only, no client
  id, URL or error text. **The heartbeat carries the same document as
  `signals`** (`Sync::heartbeat()`, only when a proxy built the reporter;
  a PEP with no proxy sends no member at all), and the service records it
  on the PEP's row as `xacmlPepSignals` and draws it on the console
  (`xacml/CLAUDE.md`). An older service ignores the member, so a newer PEP
  loses nothing against it.
* **Log integration.** `ReceiverOptions::on_error` takes the library's own
  lines (a failed poll, a refused SET), written to this log at debug; the
  state change that matters is the one `STS-XPEP-0099` line.
* **A bounded session store.** `MemorySessionStore::new(max, ttl)`, from
  `PEP_PROXY_MAX_SESSIONS` (twice it) and `PEP_PROXY_SESSION_TTL_MS`. The
  proxy's own store is still the admission rule and still removes the
  library's entry whenever it ends a session. The library's bound keeps
  memory finite when an entry is not removed (a proxy session that simply
  expired), and the headroom keeps such an entry from pushing a live one
  out.
* **Insecure TLS for development: deliberately NOT added.** The real need
  was trusting a CA the development stack regenerates on every start, and
  `tlsCa` already meets it: the pull carries the service's current listener
  chain on every poll, the library adds every certificate in it as an anchor
  and checks the host name, and a changed chain changes the digest and
  rebuilds the relying party. Skipping verification would trust whatever
  answers.
* **Still not offered: a separate transmitter URL.** The receiver is pointed
  at the realm's issuer; the pull names no SSF transmitter.

**In memory, bounded, purged at the insert, never on a timer**
(`rp_session.rs`): a proxy session lives at most `PEP_PROXY_SESSION_TTL_MS`;
past `PEP_PROXY_MAX_SESSIONS` live ones a new one is REFUSED (503,
`STS-XPEP-0085`), because evicting would sign somebody else out; past the
same number of sign-ins in flight the OLDEST is dropped, because anybody can
start one and refusing would let anybody stop everybody signing in. A
restart only sends each browser through a sign-in it will not see — the
service's session is still there. Two instances hold two sets, which the
#676 decision above already accepts.

### How the identity reaches the application (D11)

**rcbj's decision of 2026-11-14: one of three modes per route**, route
member `identity` (it replaced `subjectHeader` and `mechanismHeader`;
default `{ "mode": "headers", "headers": [] }`, which sends no identity).
`proxy.rs`'s `deliver()` establishes it AFTER the decision and BEFORE
anything is forwarded, and **a request is NEVER forwarded without the
identity its route was configured to send**: any failure refuses it — 403
when the service said 403, 502 otherwise — under its code. Whichever mode,
the incoming credentials are stripped unless `forwardCredentials`, and the
subject is the one the decision used. `identity.rs` is the pure half.

**FIRST, every identity header ANY route of the configuration names is
removed from EVERY request** (`identity_header_names()`, the union), on a
public route too and whatever route the request takes, so a client can
inject none of them anywhere. A header name is case-insensitive and arrives
lower-cased, so every spelling and every duplicate goes. **The application
must accept traffic only from the proxy**: a header carries no proof.

* **`headers`**: at most 16 `{ name, claim }`, the name an RFC 9110 token,
  unique case-insensitively, and not a hop-by-hop, framing, `Authorization`,
  `Cookie`, `Host`, `Forwarded`, `X-Forwarded-*` or `Proxy-*` name; the
  claim one of `sub`, `username`, `email`, `name`, `given_name`,
  `family_name`, `groups`, `mechanism`, `acr`, `amr`; `separator` one
  printable ASCII character that is not a letter or digit (default `,`).
  **The claims are taken from the credential when it already holds them** —
  a JWT verified here, an introspection answer, the service's SAML or Basic
  answer, the sign-in — and `mechanism` is always the proxy's own; only the
  claims MISSING are asked of `POST validation.identity` (`{ route,
  evidence, claims }` → `{ claims }`), and only the claims asked are taken
  from its answer. A claim with no value sends no header. A value holding
  CR, LF or NUL, a list member holding the separator, or an object is
  refused (502, `STS-XPEP-0096`), never forwarded.
* **`jwt`**: `POST validation.identity` → `{ accessToken, tokenType:
  "Bearer", expiresIn }`, an access token THE SERVICE issues for the
  route's application (its own claim configuration, the realm's JWKS), sent
  as `Authorization: Bearer` — the client's own `Authorization` replaced
  whatever `forwardCredentials` says. Cached per (proxy session, or subject
  and mechanism, and application) until THIRTY SECONDS before it expires,
  never past.
* **`saml`**: `POST validation.identity` → `{ samlResponse, acsUrl,
  notOnOrAfter }`, an assertion the service issues and signs for the
  route's application under its own SAML rules. **The proxy POSTs
  `SAMLResponse` (form-urlencoded) to `acsUrl` SERVER-SIDE**, as the
  HTTP-POST binding would, through the upstream client (no redirect
  followed; the ACS need not be on the upstream's origin, but must be an
  absolute http(s) URL), and keeps the cookies the application sets in a
  JAR of its own, keyed like the token cache — **never sent to the
  browser**: they go on the request to the application (a client's cookie
  of the same name is removed first, so it cannot shadow one) and every
  `Set-Cookie` the application answers for a jar cookie updates the jar and
  is stripped from the answer; its other cookies pass. An ACS that will
  not answer, answers 400 or more, or sets no cookie is 502
  (`STS-XPEP-0097`). **The session is established again** when the
  assertion's `NotOnOrAfter` has passed, or when the application answers
  401 or a redirect to its ACS or to the identity provider (the realm
  issuer's origin): the jar is dropped and — for a request with no body,
  the only kind that can be replayed — established and sent again ONCE;
  a request with a body gets the application's answer, and the next one
  starts with a new session.

**The evidence** (`{ kind, value }`, re-validated by the service, so a
`REMOTE_PEPS` holder cannot name a subject of its choosing): the oauth2
bearer token, or for a session route the RP's access token from the
library's `session_access_token()` (which refreshes it near its end) —
`access_token`; the saml2 credential, base64 — `saml_assertion`; the
`ticket` the service's Basic answer now carries (opaque, bound to this PEP
and subject, short-lived; never the password) — `ticket`. A credential that
gives none (a Basic answer without a ticket, a session whose token cannot be
had) is 502 (`STS-XPEP-0098`). The service's refusal, a 200 that is not the
mode's answer, or an endpoint the pull did not name is `STS-XPEP-0095`.
**Neither the evidence, the token, the assertion nor a cookie is ever
logged.** Both caches are bounded (10,000) and purged at the insert, never
on a timer.

### What it does not do, and what is unproven

* **It proves no DPoP key**: a `cnf.jkt` token and the DPoP scheme are
  refused by name, as D7 says for this ticket.
* **A path parameter (`;`) is forwarded as written.** `/api;x/admin` is not
  `/api/admin` here, and an application that strips `;` parameters (some
  servlet containers) would read it as that. An exact route in front of a
  prefix route on such an application can be reached past its exact match.
  Not refused because D8's list does not refuse it; a deployment in front
  of such an application should not rely on an exact route alone.
* **Case is not folded.** An application that matches paths without case
  sees `/API` where the route table saw no route (404, the safe side) — but
  a prefix route behind an exact one is the `;` case again.
* **No WebSocket or `Upgrade`**: the hop-by-hop rule strips it.
* **Unproven until a stack run**: the service's validation and identity
  endpoints' real answers (the shapes here are D4's and D11's); the
  library against the service itself — discovery under the realm's issuer
  reachable from the PEP's network (the issuer's host name must resolve
  there and match the pulled `tlsCaChain`'s leaf), the real ID Token
  (`typ`, `at_hash`, `sid`), the client-credentials token with
  `ssf.manage`, the SSF poll stream and a real `session-revoked`; the
  service's real JWKS and signed SAML assertion through the local path (the
  test vector is the service's SHAPE, signed here); the realm's redirect
  back through a browser; a real application's ACS; and a certificate-bound
  token over 9543 (the listener's ask-anybody handshake is held by
  `listener.rs`'s test; the `cnf` comparison by `jwt.rs`'s).

### What holds it

`cargo test -p xacml-pep`, 111 tests, of which the proxy's are: the
configuration's every refusal — D10's `application` and `resolved`, D11's
`identity`, and a route without `methods` or `authorization`, an unknown
`kind` or `actionModel`, an empty `policy` and the old `public` boolean
standing in for `authorization` among them — the contract's own example,
and every method under each action model (`proxy_config.rs`); the path rules and the header rules
(`proxy_request.rs`); every supported algorithm, a wrong key, a wrong key
type, `none`, a tampered signature, an unknown `kid`, strict base64url, and
the claim (any of several audiences) and `cnf` checks (`jwt.rs`); the
canonical forms by hand, the assertion verified, and every local failure
answered as a question (`saml_verify.rs`); the claim rendering, the token
margin and the jar's rules (`identity.rs`); the library's configuration
from the pull and a rotated secret being a rebuild (`rp_set.rs`); the
stores' bounds (`rp_session.rs`); the proxy listener's handshake
(`listener.rs`); and, OVER REAL SOCKETS (`proxy_tests.rs`), the proxy in
front of a mock application (an echo, and a SAML ACS that sets a session
cookie) beside a mock service that is also an OpenID provider and an SSF
poll transmitter good enough for `oidc-caep-risc`: every mechanism admitted
and refused, unrouted 404, 405 with `Allow`, 413 declared and streamed, 504,
502, a redirect not followed, traversal sent byte for byte over a raw socket
(a URL library resolves `..` before sending), credentials and forwarding
headers stripped, the decision refusing a subject and a route's resource, a
key rotation picked up by one refetch, Basic's 429 passed on, the SAML local
path and its fallback, a `usable: false` route refused and then usable
again, the session flow through the library (its `authorize()` URL, PKCE,
`complete_session()` with `client_secret_basic`, a refused nonce, a session
that is one application's only, `end_session_url()`), a sign-out at the
service ending access by the session endpoint (`signals: false`) and by a
CAEP `session-revoked` on the poll stream, each access asking the library's
cache, each identity mode end to end (claims from the service with a
ticket, an injected identity header stripped in every case and from every
route, a CR LF value and a 403 refused; a service token cached and not used
within 30 s of its end; an assertion posted to the ACS, the jar sent and
never shown to the browser, a 401 establishing it again; a session route's
evidence being the library's access token), the pull's token, `ETag`, 304,
failure and whole refusal (a route without `methods` or `authorization`, an
unknown `kind` or `actionModel`, the held table kept), and **each route
decided by its own policy** through the engine: a route naming a denying
policy refused under a permitting root and a route naming a permitting one
admitted under a denying root, or none; a policy not held, or withheld by a
later pull, refused with `0117` under either bias, uncounted and unforwarded;
the action-id the engine saw under each model (policies permitting exactly
`update`, `write` and `PUT`); the resource-id `authorization.resource` names
and the path when it is empty (policies permitting exactly one anyURI); a
public route permitted only for a request with NO `subject-id`, then refused
when its policy denies or is withheld; and an empty `methods` refusing every
method with `0116` after a counted Permit, public and not, the application
never reached, with `0117` first when the policy is missing too.

**Mutants, applied one at a time by hand and all caught**: the audience
check (any of the resolved audiences), the segment boundary, `%2e`
accepted, `Authorization` forwarded, a failed SAML digest admitted, the
session recheck, `cnf.jkt` accepted, a client's `X-Forwarded-For` kept, the
SAML Reference URI, the introspection issuer and audience, the 405, the
429, a `usable: false` route admitted, the library's cache not asked with
signals on, a session used on another application's route, `usable` not
required to be a boolean, a usable session route without its client, a
signed-in session not tracked by the receiver, an injected identity header
surviving, only the route's own identity headers stripped, forwarding when
the identity fails, the jar leaking to the browser, a cached token used to
its expiry, a CR LF claim accepted, a separator in a list member accepted,
jwt mode sending no Bearer, a client cookie shadowing the jar's, a 401 not
re-establishing the application session, the missing claims never asked,
and (#1760's route authorization) PUT sent as `write` under `crud`, the root
evaluated in place of the route's policy, an empty `methods` let through
when the policy permits, and a public route not decided. Four survived a first pass and the tests that catch them were added:
`%2e` not forming a segment, the introspected issuer, the library's cache
(the receiver's callback ended the proxy session as well, so the cookie
alone told), and a CR LF claim (the header library refused it too, so only a
direct test of the rule tells). `tests/protocol/sts_xacml_remote_pep.js` is
the deployment's.

### Its error codes

The managed settings' pull: `STS-XPEP-0100` (a failed pull, the held settings kept), `0101` (an older service's 404, the environment in force) and `0102` (one value refused, that setting the environment's).

`0060`–`0062` the pull; `0063` the plain listener (the HTTPS one reuses
`0029`–`0032`); `0064`–`0069` the route table, the body and the upstream;
`0070`–`0075` and `0088`, `0089` the credential and the service's
validation; `0076`–`0078` SAML; `0079`, `0080` Basic; `0081`–`0085`,
`0090` and `0094` the session mechanism; `0086` the decision; `0116` a
route whose `methods` is empty (deny-all), refused after its decision;
`0117` a route whose `authorization.policy` this PEP does not hold, refused
without one; `0118` every path before the first configuration since the
start (503, *Not configured YET*); `0087`
retired before release (the subject header D11 replaced); `0091` the
upstream URL; `0092` the upstream's anchors; `0093` an application the pull
says is not usable (D10); `0095`–`0098` the identity (D11). **No log line carries
a token, an assertion, a password, a session id or a query string**: the
method, the normalised path (at most 200 characters, quoted), the route and
the reason.


## THE MODEL OF EVERY ENDPOINT (#1830)

**rcbj, 2026-11-16: a TypeSpec model of every endpoint of the remote PEP, the
control plane included and the reverse proxy's configured routes not, with
OpenAPI generated for each and Rust data types.** It is `models/pep/`, four
`@apiDocument`s written with the API namespace's decorators
(`models/lib/api_lib.tsp`), so the OpenAPI writer is the one the five
published APIs use:

| Source | Document (`xacml-pep/openapi/`) | Rust module (`sts-model-pep`) | What |
|---|---|---|---|
| `pep_service.tsp` | `pep-service.json` | `pep_service` | `GET /`, `/healthcheck`, `/protected`, `POST /notify` (with the service's nudge as its body), `GET /crl/{name}` |
| `pep_authzen.tsp` | `pep-authzen.json` | `pep_authzen` | the edge PDP's evaluation, evaluations and metadata |
| `pep_proxy.tsp` | `pep-proxy.json` | `pep_proxy` | the proxy's own paths: `/.iya-pep/*` and the start page; what EVERY route answers whatever its configuration is in the document's description and `Refusal` |
| `pep_control_plane.tsp` | `pep-control-plane.json` | `pep_control_plane` | what the SERVICE serves the PEP: `/xacml/pep/*` and `POST /xacml/pip` |

**No WSDL**: nothing here is SOAP. The PIP's XML bodies are declared by media
type, with their root, namespace and content in the schema's description.

**`models/tools/generate_pep.mjs` writes both, and both are COMMITTED** —
unlike `models/generated/`, because `cargo` and this image build from a
checkout and run no TypeSpec compiler. `tests/tools/regenerate-pep-model.sh`
runs it in the tests image. **A change to an endpoint here owes its model in
the same commit**: `tests/model_pep.js` fails when a path is matched and not
described, described and not matched, or a committed file is not what the
model makes; the three `the_*_model_s` tests in `cargo test -p xacml-pep`
fail when an answer this binary gives has a member the model does not
declare or lacks one it requires; and `authzen_evaluation.js` X does the
same for the service's answers.

**`sts-model-pep` is its own crate, depending on no runtime crate**: the
Rust conversion's renderer (`models/lib/rust_lib.mjs`, #444 D15, copied
byte for byte from `feature/444`) writes a crate per document and a shared
`sts-model-base`; `models/lib/pep_lib.mjs` folds that into one crate with a
module per document, so the types read a member by the same rules the
runtime's do (optional is `Option`, nullable `Option<Option<_>>`, closed
objects `deny_unknown_fields`). The binary takes it as a DEV-dependency
today: the tests hold its answers to the types, and the hand-written readers
in `sync.rs`, `proxy_config.rs` and `authzen_map.rs` are unchanged. Moving
them onto the generated types is the next step, and it is a refactor of
those readers, not of the model.

**What modelling it found**, each declared as the code does it and left
unchanged (none is a fix for this ticket):

* The service never reads `If-None-Match`, which the PEP sends on the settings
  and proxy pulls; only `?since=` answers 304.
* `?pep=` on `/xacml/pep/policies` is not bound to the certificate, so any
  `REMOTE_PEPS` holder can touch another PEP's last-seen time.
* The heartbeat answers every registry refusal 404 (not registered, no
  directory, directory refused); register answers every one 400.
* The PIP answers its own refusals as XML `PIPError` and the gate's as JSON,
  and the PEP reads neither. (It sent `Accept: application/json` there until
  #1830; the PIP query now asks for `application/xml`, what it answers.)
* `basic` has two 429 bodies, its lockout's and the limiter's; the listener
  certificate's 200 carries a stray `ok: true`; the nudge's `pdp` is always
  empty.
* On `GET /`, `authzen.enabled` and `authzen.pdpIdentifier` report the
  environment, not the managed values in force (which `settings.values` has).
* The proxy's
  callback and sign-out are dispatched for any method; `/.iya-pep/` is not
  reserved as a whole, only its eight paths; HEAD on this handler is 404.
* The AuthZEN metadata reads only the `Host` header, which an HTTP/2 client
  does not send, so without `PEP_AUTHZEN_PDP_IDENTIFIER` it may be 404 over h2
  (inferred, not observed).

## Error codes

Every failure has an `STS-XPEP-nnnn` code in the service's ONE table
(`common/error_codes.js`), at the front of the log line through
`sts_core::log::tag()` — the only place it can be, there being no audit log
here, and never in a response. `tests/error_codes.js` scans `rust/`'s `.rs`
files with the rest. **Eight codes were retired with the Node container**
(0001, 0002, 0007, 0008, 0011, 0012, 0014, 0034): a registry or a version
module that could not be loaded, a URL that would not parse, a decision that
threw, a retried registration or a heartbeat that threw, the engine modules
not found, an unhandled promise rejection — conditions a Rust binary built
from one workspace cannot meet. A panic once started is `STS-XPEP-0033`,
contained and throttled as before. **0035–0046 are the AuthZEN edge PDP's**
(#1179), **0047–0054 its caller pull and admission by it** (#1189),
**0055–0059 the forward of a fine-grained authorization evaluation and the
catalogue's `fgaApplications`** (#564, P7); a request it refuses under the mapping contract is logged with the
`STS-AUTHZEN-*` code the service gives the same request. **0060–0092 are the
reverse proxy's** (#1760), with 0093–0099, 0108–0111 and 0116–0118, listed
in *THE REVERSE PROXY*. **0103–0105 are the
defined listeners'** (#1760): a refused bind, a certificate not obtained, a
definition left out.


## THE HTTPS LISTENER (2026-09-13)

**A remote PEP answers its CLIENTS — whoever calls `/protected` — and until this
date it answered them in plain http**, because a certificate had to come from
somewhere and the paragraph above about the client certificate explains why
this directory will not mint one. The answer is the same shape as that one: the
PDP's realm issues the pair and something outside the container puts it on the
mount. What differs is WHO issues it — this service, rather than a launcher's
private CA — and WHEN it can exist.

**IT IS ISSUED BY THE REALM THE PEP REGISTERED TO**, from that realm's
`pep-tls` Issuing CA (`common/pki.js`, argued in `common/CLAUDE.md`), through
`POST /admin-api/xacml/issue-pep-certificate` or the control on
`/admin/xacml/peps` (`xacml/xacml_pep_tls.ts`). The PEP's row in `ou=peps` is
what decides the realm and what supplies the default names, so an unregistered
PEP is refused. The private key is in that one reply and nowhere else.

### The files are watched because the order of events requires it

The certificate needs the registration, the registration needs this process
running, and the launchers point this container at a realm the suite creates
minutes later — so **the pair cannot exist when the container starts**, and a
listener that read its files once, as `PEP_TLS_CERT` is read, would never get
one. `HttpsListener::reload()` re-reads both paths every
`PEP_HTTPS_RELOAD_INTERVAL_MS`: a missing file is logged once at `info` (it is
the ordinary state), the listener starts the first time a usable pair appears,
and a pair that changes afterwards is swapped in for new connections, which
is also what a renewal needs.

**A BAD PAIR NEVER REPLACES A GOOD ONE.** Files are written one at a time, so
between the writes the certificate and key disagree. A pair is checked whole —
OpenSSL parses both, the certificate's public key is the key's, and an
`SslAcceptor` accepts them — before it is used; a listener already serving keeps its pair,
and one not yet started waits. `listener.rs`'s own test writes exactly that intermediate state.

**The digest of the two files is the change test**, not their mtimes: a mount
can report a new mtime for identical bytes, and a copy can keep an old one.

### What is deliberately not done

* **Plain HTTP is not turned off.** The image's healthcheck uses it, a container
  with no pair is still a PEP that enforces, and closing it is a decision for
  the network edge rather than this process.
* **The PDP's nudge still dials `PEP_NOTIFY_URL` as it always did.** An `https`
  notify URL at this listener would need the PDP to trust its own realm's
  hierarchy for an outbound request, and trusting the service Root there would
  accept ANY leaf this service issued under a matching name — so it would also
  need the chain checked for the `pep-tls` Issuing CA. That is a change to
  `xacml/xacml_pep_http.ts`'s verification, argued there if it is made, not a
  consequence of this listener existing.
* ~~Nothing reports the served certificate back to the PDP~~ — since #1760
  the heartbeat's `listeners` carries every listener's served certificate,
  and the PEP's page shows it beside what the realm issued.

### The one handler

`Pep::handle()` is shared by both listeners, so the four endpoints are decided by one
function whatever the transport — two listeners that answered differently would
be two enforcement points in one process. No Entering/Leaving pair on it: it is
the hot path, and the code style's exception says so above the function.

### Error codes

`STS-XPEP-0029` (only one of the two paths set), `-0030` (a pair missing,
unreadable or refused), `-0031` (the port would not bind), `-0032` (the served
certificate is outside its validity). The PDP side is `STS-XACML-0071` (the PEP
is not registered in this realm) and `-0072` (the issue failed), and the
certificate authority's are `STS-PKI-0165` to `-0167`.


## THE LISTENERS THE SERVICE DEFINES (#1760)

rcbj (2026-11-14): the Listener tab "modelled after the Server
configuration->Listeners", the HTTPS listener there now as the default, and
"the ability to define an arbitrary # of listeners (HTTP, HTTPS)".
`listeners.rs`; the service's half is `xacml/xacml_pep_listeners.ts`.

* **THE ENVIRONMENT'S FOUR STAY EXACTLY AS THEY WERE.** `PEP_PORT`,
  `PEP_HTTPS_PORT`, `PEP_PROXY_PORT` and `PEP_PROXY_HTTPS_PORT` are what let
  this process reach the service before it has pulled anything, so they are
  bootstrap: bound at start from the environment, never by the service, and
  reported under the reserved ids `api-http`, `api-https`, `proxy-http`,
  `proxy-https`. The proxy's plain listener is bound in `main.rs` now (it
  was `proxy::serve_http()`), so its result can be reported; the accept loop
  is `proxy::serve_on()` as before.
* **THE DEFINED ONES ARRIVE ON THE SETTINGS PULL** as `listeners` and are read
  again by the service's rules (`parse()`: the id, the closed sets, an IP
  address, a port, the names, a key this process can generate, no two on one
  address and port); one that fails is LEFT OUT and named (`STS-XPEP-0105`),
  the others are bound. A failed pull keeps what is held; an older
  service's 404 is no definitions, so only the four.
* **BOUND, REBOUND AND UNBOUND WHILE IT RUNS** (`ListenerSet::reconcile()`,
  after the start's pull and after every poll, one at a time): a removed
  listener's accept loop is aborted, which drops the socket and frees the
  port — a connection already open finishes; a changed protocol, purpose,
  address or port is unbound and bound again; a refused bind is `failed`
  with its reason (`STS-XPEP-0103`, once per sentence) and tried again after
  the next pull. **This reverses the settings' rule that a bound port is
  bootstrap** — for these listeners only: nothing depends on them to connect,
  so rebinding one costs its own clients a reconnect and nothing else.
* **AN HTTPS LISTENER'S KEY IS GENERATED HERE AND NEVER LEAVES.** The key
  (`ec-p256`, `ec-p384`, `rsa-2048` or `rsa-3072`, as the definition says) is
  made with OpenSSL, a PKCS #10 request over it is signed with it, and
  `POST /xacml/pep/listener-certificate` — over this PEP's mutual TLS, the
  heartbeat's gate — answers the certificate from the realm's `pep-tls`
  Issuing CA and its chain. `HttpsListener::install()` checks the pair WHOLE
  as a pair read from disk is, so a chain that is not for this key is
  refused and a pair already served is kept. Nothing is written to disk.
  A new key is made when the definition's names, key or `renew` change, or
  when a third of the certificate's life is left; until a certificate
  arrives the listener waits UNBOUND (`STS-XPEP-0104`), as the environment's
  waits for its files. A process that restarts makes a new key, and the
  service supersedes the old certificate when it issues the new one.
* **WHAT EACH IS DOING GOES ON THE HEARTBEAT** (`report()`, as `listeners`):
  every listener, the environment's first, with its state (`listening`,
  `waiting`, `failed`, `off`), a reason from a closed set (`bind_reason()`
  turns an `io::Error` into one; the sentence goes to the log, never the
  report) and the certificate it serves. An older service ignores the
  member. **`GET /` does not carry it**: it answers whoever reaches the
  container.
* **EACH LISTENER HAS THE SERVICE'S TUNING AND ITS OWN POOL.** The pull's
  `listeners[].tuning` and, separately, `environmentTuning` (the four
  bootstrap ids only; they are never members of `listeners`, which an older
  PEP would refuse) are applied by `ListenerRuntime` and, for HTTPS,
  `HttpsListener::set_tuning`. A defined listener's pool starts when its
  accept loop binds. An environment listener that is off is still reported
  and does not start workers. Defaults: the decision API starts 4 workers
  and may grow to 32; a reverse proxy starts 16 and may grow to 128, the
  highest. `api-http` uses the API defaults even when the process serves
  only CRLs. `sessionTimeoutS` other than 300 is logged (`STS-XPEP-0119`)
  and left at OpenSSL's 300 seconds, because this crate forbids the unsafe
  call that would set it; the listener's other settings are still applied.
  A knob the library refuses is the same code. When a pair is already
  served, that refusal keeps the previous acceptor.
* **THE HEARTBEAT'S `listeners` IS THE WHOLE REPORT.** `report()` is
  `{ listeners, memory?, paths? }`, and that object is what the heartbeat
  assigns to `listeners`. Each listener carries `stats`: accepted, open,
  refused, http1, http2, handshakes, handshakeFailures, and `pool` (min,
  max, current, busy, idle, queued, completed). Accepted and refused are
  disjoint: accepted was queued, refused was dropped before the queue or
  because the queue was full. A missing TLS acceptor is not a refusal, and
  a failed handshake counts as `handshakeFailures` only. `memory` is read
  from `/proc/self/status` and omitted when that file cannot be read.
  `paths` counts method and path since the process started, query stripped,
  capped at 256; 401, 403 and 503 increment `refused`, and a 404 does not.
  The counters are set from the process, not added to the service's copy,
  and a registration drops the snapshot. Monitoring → Remote PEPs reads
  them from `listenersInUse`.
* **A PROXY LISTENER WITH THE PROXY OFF** (`PEP_PROXY=false`) is not bound
  and is reported `off` / `proxy-off`.
* **THE SIGNAL STREAMS, ONE ROW EACH, ON THE HEARTBEAT ONLY**
  (`RpSet::streams_json()`): a row names the client the stream serves, which
  `GET /`'s `proxy.signals` promises never to do, so it rides in `signals`
  on the heartbeat over mutual TLS and the counts on `GET /` are unchanged.
  The times are AGES; the service turns them into times by the arrival.

### Why the environment's plain proxy listener is not held to product mode

The service refuses a DEFINED plain-HTTP proxy listener in product unless
`xacml.pepPlainHttpProxyListeners` is on (`xacml/CLAUDE.md`), because that
listener is the service's decision. `PEP_PROXY_PORT` is the operator's: it is
set in this container's environment by whoever deploys it, before this
process has asked the service anything, and it is in front of whatever the
deployment puts in front of it. That is the same explicit, named statement
the setting is — made where the operator makes deployment decisions — and
refusing it here would mean a PEP that cannot learn its realm's mode before
it binds would have to guess. The product deployment's answer is the one
the setting's description gives: leave `PEP_PROXY_PORT` behind something
that terminates TLS, or serve the proxy on `PEP_PROXY_HTTPS_PORT` only.

### Backwards compatibility

* **An older PEP** never reads `listeners`, sends no `listeners` on its
  heartbeat (its page says it does not report them) and binds its four.
* **This PEP against an older service** pulls no definitions (a 404 or a
  body without the member) and binds its four; the older service ignores
  the heartbeat's `listeners` and `signals.streams`.

`cargo test -p xacml-pep` holds it: `listeners::tests` binds and unbinds at
run time, moves a listener, refuses a bind on a held port and binds it once
freed, leaves a proxy listener off with no proxy, serves an HTTPS listener
the certificate a test CA issued over the key generated here, renews it to a
new serial on the same socket, and leaves one whose request is refused
waiting unbound.
