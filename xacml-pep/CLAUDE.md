# CLAUDE.md — `xacml-pep/`

**A REMOTE XACML POLICY ENFORCEMENT POINT, AND A RUST BINARY SINCE #444
(2026-10-05).** Everything the identity service runs is required by
`server.js`; this is a **second container**, which holds its own copy of the
XACML engine, PULLS the policy repository from the service's PDP and decides
locally. Its code is `rust/bins/xacml-pep` on the engine crate
`rust/crates/sts-xacml` (the runtime's engine too, `rust/DESIGN.md`); what is
in THIS directory is its image and its one shared expectation.

```
docker compose --profile xacml up --build

curl http://localhost:9090/
curl "http://localhost:9090/protected?subject=alice&employeeType=staff&action=GET"
```

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
| `certs/` | The compose files' default certificate mount; empty and gitignored. |

| Rust module (`rust/bins/xacml-pep/src/`) | What it is (the Node file it replaces) |
|---|---|
| `options.rs` | The environment, read once (`pep.js`'s `options`). |
| `pdp_client.rs` | ONE HTTP client for every call to the PDP, with the client certificate on every call (`sync.js`'s `call()`). |
| `sync.rs` | Register, pull, heartbeat; what is held (`sync.js`). |
| `pip.rs` | The walk, the batched `POST /xacml/pip`, the resolver (`pip.js`). |
| `enforce.rs` | The bias and the obligation rule (`pep.js`'s `enforce()`). |
| `listener.rs` | The HTTPS listener whose pair is re-read from disk. |
| `service.rs` | The one handler for both listeners, `/protected`'s decision, `GET /`. |
| `main.rs` | Start-up, the backoff timers, the fault handler, `--stamp`, `--healthcheck`. |

## The tests, and which half each guards

| Test | What it holds |
|---|---|
| `cargo test -p xacml-pep` | **The SHAPE**: the PIP walk over ONE document holding a designator in five places (a target, a condition, a variable definition, an obligation assignment, a policy reached by `PolicyIdReference`) and NOT the resource-category one beside them; the PIP answer read with the engine's own request reader; the listener's reload rules; and the enforcement rule against `enforcement_cases.json`. |
| `cargo test -p sts-xacml` | The engine against the vendored OASIS suite, case for case as `tests/xacml_conformance.js` holds the service's. |
| `tests/xacml_pep.js` | The PDP's side (sync token, register, nudge refusals, change observer), the Dockerfile building and stamping the Rust binary, and **the service's `enforce()` against the same `enforcement_cases.json`** — so the two readings of section 7.2 are checked against one expectation. |
| `tests/xacml_request.js` E | The remote PEP builds through `sts-xacml`'s `AuthorizationRequest`, and every identifier that builder declares is spelt as `xacml_request.js`'s `VOCABULARY` spells it. |
| `tests/vendored/sts_xacml_remote_pep.js` | **THE DEPLOYMENT**: this image, on the service's own docker network — registering on a later attempt, pulling, deciding out here, converging by polling and by the nudge, the PIP end to end, the HTTPS listener, deciding correctly with the PDP taken away. **The only thing that runs what this Dockerfile produces.** |

**THE LAUNCHERS OWN THAT CONTAINER AND THE JOB DRIVES IT**: `./run-tests.sh`
brings one up beside the service and hands the job `XACML_PEP_URL`,
`XACML_PEP_NAME` and `XACML_PEP_REALM`; with none of those the job builds this
image and starts a container itself.


## Why this exists at all, which is not obvious

The mock already has a PEP: `/xacml/protected`, in `xacml/xacml.ts`. It builds
a request, asks the PDP, applies the bias and the obligation rule, and answers
200 or 403. It is a correct implementation of section 7.2 and it demonstrates
almost nothing about a distributed deployment, because it **shares a process
with the PDP**. It can never be stale. It can never hold a policy the PDP no
longer has. It can never go on enforcing while the PDP is down. It cannot
disagree with the PDP about anything, ever.

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
refused. `tests/vendored/sts_xacml_remote_pep.js` asserted that in both
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
program. That is the thing `tests/vendored/sts_dpop.js` refuses to do when it
writes its
own DPoP client rather than importing the wallet's.

Written out, this PEP can run a DIFFERENT bias from the mock's embedded one, and
the two then disagree about exactly the answers the two biases disagree about —
which is the demonstration worth having.

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
admin it was permitting a second earlier.

---

## The four endpoints

```
GET  /              what this PEP is, what it holds, what it has enforced
GET  /protected     THE RESOURCE. 200 or 403, decided here
POST /notify        the PDP's nudge: pull now
GET  /healthcheck   liveness
GET  /crl/<name>    this PEP's own credential's CRLs (#174), from PEP_CRL_DIR
```

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

**Its body is not read and nothing in it is trusted.** A nudge says only that
something changed; what changed is discovered by pulling from this PEP's own
configured PDP URL. A nudge that could tell this PEP what the policy now is, or
where to fetch it, would be an unauthenticated caller supplying policy — and the
whole reason a nudge is affordable on the PDP's side is that it carries nothing.

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

---

## Configuration

All of it from the environment. No appconfig file and no settings table, and
that is not a shortcut: the mock's five-layer configuration exists to serve a
console that can change a setting while the service runs, and a PEP has no
console.

| Variable | Default | What |
|---|---|---|
| `PEP_PDP_URL` | `https://localhost:8081` | The mock. |
| `PEP_NAME` | `pep-1` | **Ignored when a client certificate is presented** — the PDP names the row from the certificate. |
| `PEP_TLS_CERT` / `PEP_TLS_KEY` | — | The client certificate. Without it the PDP refuses the registration unless `xacml.pepRequireCertificate` is off. Enforcement is unaffected either way. |
| `PEP_TLS_CA` | — | An anchor for the PDP's certificate. |
| `PEP_TLS_INSECURE` | `false` | Do not verify the PDP. **The ordinary setting against the mock**, whose listener certificate is issued by a service Root that development mode regenerates on every start — so there is no fixed anchor to verify against (`tls/CLAUDE.md`). Logged on every start, for `federation_http.ts`'s reason. |
| `PEP_NOTIFY_URL` | — | Where the PDP should nudge. |
| `PEP_BIAS` | `deny-biased` | This PEP's own. |
| `PEP_PIP` | `true` | Resolve designators the request did not carry against the PDP's embedded directory, through `POST /xacml/pip`, in one batched query before each evaluation. **`false` reaches the old behaviour deliberately** — and so does a container with no `PEP_TLS_CERT`, since that endpoint requires a verified certificate holding `REMOTE_PEPS`. On by default because the surprising state is the other one: a PEP enforcing the same policy as its PDP and reaching a different answer. |
| `PEP_POLL_INTERVAL_MS` | `15000` | **The contract**, and since 2026-09-06 also the interval a FAILED REGISTRATION is retried on. |
| `PEP_HEARTBEAT_INTERVAL_MS` | `60000` | |
| `PEP_PORT` | `9090` | |
| `PEP_HTTPS_CERT` / `PEP_HTTPS_KEY` | — | **PATHS, re-read on an interval** — the listener's pair, issued by the PDP's realm. Unlike `PEP_TLS_CERT`, which is read once, because this pair normally does not exist when the container starts. See *The HTTPS listener*. |
| `PEP_HTTPS_PORT` | `9443` | |
| `PEP_HTTPS_RELOAD_INTERVAL_MS` | `5000` | Not the poll timer, deliberately: that one is the policy contract. |
| `PEP_RESOURCE`, `PEP_DESCRIPTION`, `PEP_TIMEOUT_MS`, `PEP_MAX_BODY_BYTES`, `PEP_LOG_LEVEL` | | |

**The compose service, beyond the table** (moved from `docker-compose.yml`'s
comments on 2026-10-07): it is under `profiles: [xacml]`, so a plain `up` never
starts it; `XACML_PEP_IMAGE` is set per run for `STS_IMAGE`'s reason (an image
tag is machine-wide); the HTTPS listener is published on **9444**, not 9443,
which collided with the service's mutual-TLS listener until that was deleted
on 2026-09-16 — the default stays because every launcher, kept stack and
`XACML_PEP_HTTPS_URL` names it; `PEP_HTTPS_CERT`/`KEY` default EMPTY because a
default inside `xacml-pep/certs` would invite a private key into the source
tree; `PEP_HEARTBEAT_INTERVAL_MS` is a substitution because
`tests/vendored/sts_xacml_remote_pep.js` reads the counters the heartbeat
carries and cannot wait a minute; and the plain-http `PEP_NOTIFY_URL` is
refused by the PDP by default (`xacml.pepNotifyAllowHttp`, and always in
product, #171), so the demonstration converges on its poll.

**The compose service ships with no certificate**, so out of the box it
registers unauthenticated and the mock refuses it — which is the honest default
rather than a broken one. **SINCE 2026-09-06 THAT REFUSAL IS THE ACCESS POLICY'S
RATHER THAN `xacml.pepRequireCertificate`'S**, and it is no longer optional: the
three endpoints require a client certificate this service VERIFIED whose subject
DN resolves to a directory entry holding the built-in `REMOTE_PEPS` role. Both
launchers mint one with `tests/tools/pep-credential.js` and mount it at
`/certs`; a container without one starts, enforces what it can pull (nothing),
and says why. Generating one here would mean either committing a
private key to this repository (which `postgres/generate-tls.sh` exists
specifically to avoid) or a first-start script for a demonstration container.
Mount a pair to see the authenticated path. **Either way it enforces.**

**And the compose service's nudge is refused by default**: its notify URL is
plain `http` on the bridge and `xacml.pepNotifyAllowHttp` is off. That is
the design demonstrating itself — no nudge is delivered, the PDP says why on the
PEP's row, and the PEP converges on its fifteen-second poll anyway.

**BOTH HALVES OF THAT ARE ASSERTED SINCE 2026-09-06**, and it took a container
to do it. `sts_xacml_remote_pep.js` runs its sections 1–5 in exactly this
configuration — an http notify URL the PDP refuses to dial — so every
convergence there is the poll and the registration reply is checked for the
refusal. Then it turns `xacml.pepNotifyAllowHttp` on in its own realm — and,
when that realm is in product mode, asserts that plain http is STILL refused
(#171) and puts the realm in development mode for the rest — and
measures the other half: the PDP dials this container's `/notify` across the
bridge, the row records `The PEP answered 204.`, and a change lands in tens of
milliseconds against a five-second poll. **That outbound request is one of three
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
`tests/vendored/sts_xacml_remote_pep.js`, WHICH DID NOT EXIST WHEN IT WAS
WRITTEN**: running the container against the service was something a person did
by hand, and both defects were found by a person doing it. That job now does it
on every run — and each of those two defects lands squarely in it. The first is
a 500 out of the registration, which section 1 fails on; the second is every
request denied by a working policy, which is section 2 and every convergence
after it.

## The version this container reports

**It is `M.N.O` from the one `VERSION` file the service reads**, stamped into
`version.json` at image build time by the binary itself (`xacml-pep --stamp
.`, `sts-core::version`, a port of `common/version.js`). It rides on the
registration and every heartbeat, the PDP stores it as `xacmlPepVersion`, and
`/admin/xacml/peps` draws it — which is why it may never be a hand-written
label (it was `'mock-sts xacml-pep, phase five'` until 2026-09-06). **A
version may never stop this container starting**: an unreadable `VERSION` is
0.0 (`STS-CORE-0040`), a corrupt stamp a computed record.

**M.N must agree with the PDP and the build numbers need not**: two images,
built separately, each stamped with the instant it was built unless one
`BUILD_NUMBER` is passed to both. `GET /`'s `build.what` says so.

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
contained and throttled as before.


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
* **Nothing reports the served certificate back to the PDP.** The row on
  `/admin/xacml/peps` shows what the realm ISSUED; `GET /` here shows what is
  SERVED. The heartbeat could carry the second, and does not yet.

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
