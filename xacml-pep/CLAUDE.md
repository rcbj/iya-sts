# CLAUDE.md — `xacml-pep/`

**A REMOTE XACML POLICY ENFORCEMENT POINT. PHASE FIVE, AND THE ONLY DIRECTORY
IN THIS REPOSITORY THAT IS NOT PART OF THE MOCK.**

Everything else here is required by `server.js` (through
`common/protocol_stack.ts`) and runs in the identity service's process. This is
a **second container**: five files, two npm packages, no express, no config
table, no directory, and no key it generates — the two pairs it can hold, its
client certificate and (since 2026-09-13) its HTTPS listener's, are both handed
to it. It holds its own copy of the XACML engine, PULLS the policy repository
from the mock's PDP and decides locally.

```
docker compose --profile xacml up --build

curl http://localhost:9090/
curl "http://localhost:9090/protected?subject=alice&employeeType=staff&action=GET"
```

## What is here

| File | What it is |
|---|---|
| `engine.js` | Loads the seven engine modules and holds the ONE list of what "the engine" is. Pins `../common/helpers` to the shim. |
| `common/helpers.js` | **THE SHIM, AND THE POINT OF THE CONTAINER.** `log` and `xmlEscape`, thirty lines. |
| `sync.js` | The PDP client: register, pull, heartbeat. Holds what this PEP is enforcing. |
| `pip.js` | **The PDP's Policy Information Point, over HTTP (2026-09-06).** Walks the policy for every access-subject designator, asks `POST /xacml/pip` for all of them in ONE query, and hands `pep.js` a SYNCHRONOUS resolver over what came back — because the engine's resolver is synchronous and an HTTP request is not. It never rejects: every failure is a resolver answering empty bags, which is what this container did before it existed. |
| `pep.js` | The service: four endpoints, the enforcement rule, the poll and heartbeat timers — and, since 2026-09-13, the same four over an HTTPS listener whose pair it re-reads from disk. |
| `Dockerfile` | Build context is the REPOSITORY ROOT — the engine is copied out of `xacml/` at build time. |
| `package.json` | `@xmldom/xmldom`, `bunyan`. Nothing else. |

**TWO tests guard this directory and they guard opposite halves of it.** Both
live under `tests/`, with everything else:

| Test | What it holds this directory to |
|---|---|
| `tests/xacml_pep.js` | **The SHAPE.** The engine loads against the shim with none of the mock's modules in `require.cache`; the Dockerfile's COPY set is exactly `engine.js`'s `MODULES` **and every `.js` at the top of this directory has a COPY line** (guarded in one direction only until 2026-09-06, which is how `pip.js` could have been added and left out of the image); the two `enforce()` implementations agree over seven decisions under both biases; and **`pip.js`'s WALK is driven on one document holding a designator in five places** — a target, a condition, a variable definition, an obligation assignment and a policy reached by `PolicyIdReference` — because a designator the walk misses is an empty bag, an empty bag is a legal answer, and nothing else anywhere would report it. In process, as a child, **making no HTTP request at all** — `sync.js` is not loaded by it. |
| `tests/vendored/sts_xacml_remote_pep.js` | **THE DEPLOYMENT.** This container, on the mock's own docker network, in the suite's stack — a service of its own in `docker-compose-run-tests.yml` under `./run-tests.sh` (and `--profile xacml` under `./local-run-tests.sh` until that launcher was removed on 2026-09-16). It registers on a LATER attempt (its realm does not exist when it starts), pulls, decides out here, converges BY POLLING on a policy deployed at the PAP with the nudge undeliverable, stops enforcing a disabled policy, empties to the bias, recovers, **is dialled at `/notify` by the PDP across the bridge**, reports its counters onto the PDP's console, believes nothing in a hostile nudge body, and goes on deciding correctly when the PDP is taken away. **AND SINCE 2026-09-06 IT DRIVES `pip.js` END TO END**: `carol` asked for with the request asserting NOTHING, permitted because the designator was resolved against her entry in the mock's embedded directory, with the PDP reaching the same answer — the inversion of what that section used to hold. **It is the only thing anywhere that loads `sync.js` or makes a real PIP query, and the only thing that runs what this Dockerfile produces.** |

The split is worth keeping straight when either is edited: the first can never
see a bug in the register/pull/heartbeat client, and the second can never see
the engine quietly growing a dependency on the identity service.

**A THIRD SINCE 2026-09-13, `tests/pep_listener_certificate.js`**, holds the
HTTPS listener's reload rules in a child that requires `pep.js` and starts no
PDP client — see *The HTTPS listener* below — beside the certificate authority
half it depends on.

**THE LAUNCHERS OWN THAT CONTAINER AND THE JOB DRIVES IT**, which is a
constraint rather than a preference: `./run-tests.sh` runs the suite
inside a container with no docker in it, so a job that started its own PEP could
never run in the stack that gates this repository. Both launchers therefore
bring one up beside the service and hand the job `XACML_PEP_URL`,
`XACML_PEP_NAME` and `XACML_PEP_REALM`. With none of those — a bare
`run-report.js`, a coverage run — the job builds this image and starts a
container itself, which is the same deployment with a different owner.

**AND IT IS A CONTAINER RATHER THAN A CHILD PROCESS BECAUSE THE FIRST VERSION OF
IT WAS NOT, FOR ONE DAY, AND ASSERTED LESS THAN IT LOOKED LIKE.** Spawning `node pep.js` on the machine running the suite exercises this
directory's PROGRAM. It does not exercise the IMAGE — and the difference is
where this container's whole design lives: the Dockerfile names seven engine
modules one at a time, and on a developer's machine `engineDir()` finds them one
directory up whether or not that list is right. Dropping `xacml_functions.js`
from the COPY set is invisible to a host run and kills the container at load in
under three seconds. The same is true of the shim's path inside the image, the
two npm packages, `PEP_TLS_CA` against a certificate issued for the compose
name, and the nudge arriving over a bridge — none of which a host run touches.

---

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
  `sync.js` argues and the one worth being able to watch;
* **the two ends can disagree about whether it is stale**, because they measure
  different things — this PEP counts missed polls and the PDP counts missed
  heartbeats. A PEP that is pulling happily while its heartbeats are dropped
  looks fine here and stale there, and that is a genuinely confusing deployment
  state that is far easier to recognise when both numbers are visible.

---

## THE SHIM IS THE POINT, AND IT IS A STRUCTURAL ASSERTION RATHER THAN A FEATURE

Every engine module in `xacml/` opens with a header claiming **no I/O, no DOM,
no store**. Every one of them also opens with:

```js
const { log } = require('../common/helpers');
```

and `common/helpers.js` in the mock requires `config.js`, `crypto.js`,
`pq_jose.js`, `realms.js`, node-forge, jsonwebtoken and the vendored BBS
module — which is to say the whole identity service. **So the claim had a
loophole wide enough to drive anything through**, and a module that reached
past `log` into `config.value()` or `signJwt()` would have broken nothing and
nobody would have noticed.

`common/helpers.js` here exports `log` and `xmlEscape` and nothing else, and it
is what `../common/helpers` resolves to inside this image. An engine module that
grows a dependency on the mock does not degrade here — **it throws at load**,
and `tests/xacml_pep.js` fails naming it. That test also asserts that not one of
the mock's own modules appears in the child's `require.cache` after the engine
has loaded.

So "the engine is a library" stopped being a comment at the top of seven files
and became a thing that is checked. **That is the most valuable thing in this
directory** and it is worth more than the feature it came with.

**The shim is therefore NOT a stub to be fleshed out.** A third export is not a
convenience — it is a dependency the engine grew, and the right response is to
take it back out of the engine or to argue it in `xacml/CLAUDE.md`, because it
is a change to what the engine IS.

### And `require.cache` is primed, which needs saying out loud

In the image, `/usr/src/pep/xacml/xacml_pdp.js` resolves `../common/helpers` to
`/usr/src/pep/common/helpers.js` — the shim. On a developer's machine, running
`node pep.js` out of the checkout, the same require resolves to the MOCK's
`common/helpers.js`.

That difference would make the host run and the container run **two different
programs**, and the one CI checks would be the one nobody develops against. So
`engine.js` resolves `common/helpers` relative to the engine's own directory and
installs the shim under that exact path in `require.cache` before requiring
anything. In the image the two paths are the same file and the priming is a
no-op it says so about.

Priming the module cache is a blunt instrument. It is acceptable **here** —
this process is a PEP and nothing in it wants the mock's helpers — and it is
why `tests/xacml_pep.js` drives this container as a **child process** and never
requires it: `run.js` runs every test file in one process, so a shim installed
there would be what the next test got.

---

## THE ENGINE IS COPIED AT BUILD TIME. NOT VENDORED, NOT PACKAGED.

Three ways to get seven modules into a second container, and two are wrong:

* **A checked-in copy** — the `common/vendored/` shape. Refused, and the
  difference from `common/vendored/` is the whole argument: those are ANOTHER
  REPOSITORY'S files and the drift is between two projects, with a manifest, a
  drift check and a sync command to manage it. These would be copies of files in
  the same tree, edited in the same commits, stale the first time somebody fixed
  a combining algorithm. `xacml/CLAUDE.md`'s central rule is ONE MODEL, and a
  second copy of the evaluator is the most expensive possible way to break it.
* **An npm package** — publishing `xacml/` and depending on a version. Refused
  for a mock: it puts a release step between editing a function and watching the
  PEP decide differently, which is the loop this repository is arranged around.
* **A build-time copy** — the Dockerfile copies the seven modules out of
  `xacml/`. One source of truth in the tree, and the image cannot drift from it.

**The seven are named individually rather than `COPY xacml/ ./xacml/`**, which
looks like the fragile choice and is the safe one: a whole-directory copy would
put `xacml.js`, `xacml_admin.js` and `xacml_pep_registry.js` in the image, every
one of which requires `common/app.js`, `admin-ui/admin.ts` or `common/config.js`
— sitting there unloadable, waiting for a stack trace about express in a
container that has no express.

**And the list cannot go stale.** `tests/xacml_pep.js` parses the Dockerfile's
`COPY` lines and asserts they name exactly `engine.js`'s `MODULES`, in order. A
module added to the engine and not to the Dockerfile fails the suite naming
both. That is this repository's own version of the standing obligation the root
`CLAUDE.md` records the parent project having for its `sts/` COPY set —
**enforced rather than remembered.**

### What is deliberately NOT copied

`xacml_store.js` (the repository is `ou=policies` in the mock's directory; a PEP
holds what it pulled, in memory), `xacml_pip.js` (see below), `xacml_alfa.js`,
`xacml_templates.js`, `xacml_editor.js` (authoring — a PEP reads policy and
never writes it), `xacml.js` and `xacml_admin.js` (they register express routes
against the mock's app), and `xacml_pep_registry.js` / `xacml_pep_http.js` (the
PDP's side of phase five).

---

## THERE IS NO POLICY INFORMATION POINT HERE, SO IT ASKS THE ONE THAT HAS ONE

The mock's PIP reads attributes off a person's entry in the embedded directory.
**This process has no directory and should not have one** — that half is
unchanged and is the reason this section exists. What changed on 2026-09-06 is
what happens next: the PDP publishes its PIP at `POST /xacml/pip`, and
`pip.js` uses it.

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

So **the fetch happens before evaluation**: `pip.js` walks the policy for the
designators it could be asked about, fetches them ALL IN ONE REQUEST, and hands
`pep.js` a synchronous resolver over what came back. That is why the PDP's
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

`pip.js` never rejects. A PDP that will not answer, a query the access policy
refuses, a policy designating more attributes than one query may carry — every
one of them comes back as a resolver answering empty bags, which is precisely
what this container did before that file existed. So the failure mode of a
remote PIP is *no PIP*, reported on `GET /`, rather than a PEP that stops
deciding. Same rule `sync.js` follows about a failed pull: this component
enforces with what it has.

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

`xacml.js`'s `enforce()` is fifty lines and is not in the copy list. It is the
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
```

**`/notify` answers 204 immediately and pulls afterwards.** The PDP times that
request out in two seconds by default, and holding it open for the length of a
pull would make a slow pull look like an unreachable PEP on somebody's console.

**Its body is not read and nothing in it is trusted.** A nudge says only that
something changed; what changed is discovered by pulling from this PEP's own
configured PDP URL. A nudge that could tell this PEP what the policy now is, or
where to fetch it, would be an unauthenticated caller supplying policy — and the
whole reason a nudge is affordable on the PDP's side is that it carries nothing.

**`/healthcheck` does not ask whether the policy is current.** A PEP holding a
stale copy is working, and a healthcheck that failed on staleness would turn a
PDP outage into a container restart loop — an outage of its own.

---

## What must work, and what is allowed to fail

**Only the pull has to work.** Everything else in `sync.js` is subordinate to
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

## The version this container reports (2026-09-06)

**`options.version` WAS THE STRING `'mock-sts xacml-pep, phase five'` AND THAT
IS THE WHOLE REASON THIS SECTION EXISTS.** It is not a decoration: that value
rides on the registration `sync.js` sends, and on every heartbeat after it; the
PDP stores it as `xacmlPepVersion` on the entry in `ou=peps`; and
`/admin/xacml/peps` draws it in a column headed **Version**. So an operator
looking at the console to answer *which build is that enforcement point
running* was told the name of a development phase — a label that had not
changed since it was typed and could not, because nothing computed it.

It is `M.N.O` now, from the mock's own `common/version.js`, and it is on
`GET /` here as well as on the PDP's row.

**THE MODULE AND THE `VERSION` FILE ARE COPIED AT BUILD TIME, THE WAY THE
ENGINE IS.** Same argument as the engine's, one directory over: a checked-in
copy would be a second copy of a file edited in the same commits, stale the
first time somebody touched it. So the Dockerfile takes `VERSION` and
`common/version.js` out of the tree, and there is one of each.

**THEY GO TO THE CONTAINER ROOT AND NOT INTO `./common/`, AND THAT IS THE
DECISION WORTH READING.** The obvious line is `COPY common/version.js
./common/` — one word shorter, and it works. What it would cost is the only
thing that makes the shim worth having. `./common/` holds `helpers.js` and
nothing else, and the reason an engine module that grew a dependency on the
mock's config table, crypto module or realm registry THROWS AT LOAD is that
**there is nothing else in that directory to resolve**. `version.js` reads
files and shells out to git. A second file there turns *the shim is the
evidence* into *the shim plus whatever else we put there*, which is not
evidence at all — and it would have bought nothing, because a module at the
container root reports a build number exactly as well.

`tests/xacml_pep.js` pins it rather than leaving it to be remembered: **exactly
one COPY may write into the image's `./common/`**. A future reader tidying two
version files into the directory that already has a `common/` gets a failure
that says why.

**`pep.js` RESOLVES IT ACROSS BOTH LAYOUTS**, `./version` in the image and
`../common/version` in a checkout. Neither layout has both, so exactly one
candidate hits and the other miss is normal — the two-candidate shape the
parent project's `api/server.js` uses for its copy of the same module, for the
same reason. Missing from BOTH is reported and answers `unknown`: a PEP that
cannot name its build is still a PEP that enforces, and a version may not stop
this container starting.

**M.N MUST AGREE WITH THE PDP AND THE BUILD NUMBERS NEED NOT.** Both images are
built from this one tree and read one `VERSION` file, so a difference in the
RELEASE is not a stale container — it is a build that took its version from
somewhere else. The BUILD NUMBER is per image: these are two artifacts, compose
stamps each with the instant it was built, and passing one `BUILD_NUMBER` to
both is how you say they are one release. `GET /`'s `build.what` says this on
the page, because the question that page gets opened for is whether this PEP is
the same release as the PDP, and two timestamps four seconds apart do not
answer it. A difference in the build number is the ordinary case — and a PEP
left behind across a release is exactly what that console column exists to make
visible.

**Both halves are tested and on the usual line.** `tests/xacml_pep.js` holds
the SOURCE — that the Dockerfile copies and stamps, that `./common/` stays one
file, that `pep.js` computes the constant rather than assigning a literal.
`tests/vendored/sts_xacml_remote_pep.js` holds the TRIP: that the value
survives a registration, mutual TLS, a lower-cased directory attribute and a
read-back, and that the two containers report the same release. Every step in
that chain can drop a field in a way that renders as an empty column rather
than as an error.


## ERROR CODES IN A CONTAINER WITH NO AUDIT LOG (2026-09-12)

Every failure this container can hit has a code in the SAME table as the mock's
— `common/error_codes.js`, subsystem `XPEP` — and it is recorded at the front of
the container's log line (`[STS-XPEP-0017] …`). That is the only place it can
be: there is no audit log and no call-log funnel here, so `mark()` would record
nothing. A plain Deny, and a refusal decided by the bias alone, carry no code;
they are the answer.

**THE REGISTRY GOES TO THE CONTAINER ROOT, ON `version.js`'s ARGUMENT.**
`COPY common/error_codes.js ./error_codes.js` sits beside the version COPY,
because `./common/` is the shim and exactly one COPY may write into it.
`tests/xacml_pep.js` pins the line, and its existing one-COPY-into-`./common/`
assertion now guards this file as well.

**`pep.js` RESOLVES IT ACROSS BOTH LAYOUTS** — `./error_codes` in the image,
`../common/error_codes` in a checkout — exactly as it resolves the version, and
a missing registry never stops the container: it falls back to a local tag and
logs `STS-XPEP-0001` once. `sync.js` and `pip.js` are handed `tag` on
`options`, the way they are handed everything else `pep.js` decides at start.

**IT IS RESOLVED IN `pep.js` AND NOT IN `engine.js`**, because
`tests/xacml_pep.js` loads the engine alone in a child and asserts none of the
mock's modules is in its `require.cache` — and in a checkout the registry is
one of them. `engine.js`'s one code (`STS-XPEP-0014`, its modules not found) is
written into the thrown message as a literal for that reason.

**ONE CODE IS SHARED ACROSS BOTH CONTAINERS BY CONSTRUCTION**, which is why
there is one table and not two: an operator searching two containers' logs for
a code must never meet one number meaning two things.


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
one. `reloadListenerPair()` re-reads both paths every
`PEP_HTTPS_RELOAD_INTERVAL_MS`: a missing file is logged once at `info` (it is
the ordinary state), the listener starts the first time a usable pair appears,
and a pair that changes afterwards goes in through `setSecureContext()`, which
is also what a renewal needs.

**A BAD PAIR NEVER REPLACES A GOOD ONE.** Files are written one at a time, so
between the writes the certificate and key disagree. A pair is checked whole —
node parses both, `x509.checkPrivateKey()` holds, `tls.createSecureContext()`
accepts them — before it is used; a listener already serving keeps its pair,
and one not yet started waits. `tests/pep_listener_certificate.js` section F
writes exactly that intermediate state.

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

`handle()` is shared by both listeners, so the four endpoints are decided by one
function whatever the transport — two listeners that answered differently would
be two enforcement points in one process. No Entering/Leaving pair on it: it is
the hot path, and the code style's exception says so above the function.

### Error codes

`STS-XPEP-0029` (only one of the two paths set), `-0030` (a pair missing,
unreadable or refused), `-0031` (the port would not bind), `-0032` (the served
certificate is outside its validity). The PDP side is `STS-XACML-0071` (the PEP
is not registered in this realm) and `-0072` (the issue failed), and the
certificate authority's are `STS-PKI-0165` to `-0167`.
