# CLAUDE.md — `tests/`

## What this directory is for, and what it is NOT for

**THIS DIRECTORY HAS HELD BOTH HALVES OF THIS SERVICE'S COVERAGE SINCE
2026-08-28, AND EVERYTHING BELOW WAS WRITTEN WHEN IT HELD ONE.** Read the split
first or the rest of this file will read as though it contradicts itself:

| | What it is | Where it is authored |
|---|---|---|
| `tests/*.js` | the IN-PROCESS half — this repository's own module contracts, no port, no container, under a second | here |
| `tests/vendored/` | the PROTOCOL half — fourteen jobs driven over HTTP against a CONTAINER built from this tree, plus the wallet modules five of them verify against. NINE are byte-identical copies of the parent's mock-only jobs; **FIVE are this repository's own** | the nine: **the parent project**, not edited here. the five: **here**, and only here |

Everything this file says about what belongs HERE is about the first row. MOST
of the second row is copies, `tests/vendored/MANIFEST.js` argues them, and the
rule that governs them is `common/vendored/`'s: **edit the parent's copy, then
`./local-run-tests.sh --vendor-sync`.** A fix made in `tests/vendored/` is
overwritten by the next sync and never reaches the stack that gates that
project.

**THE NINE JOBS MARKED `local: true` IN THAT MANIFEST ARE THE EXCEPTION, AND
THE RULE IS EXACTLY INVERTED FOR THEM.** `sts_metadata.js`, `admin_api.js`,
`sts_admin_api_operations.js`, `sts_admin_console.js`,
`sts_delegated_permissions_example.js`, `sts_consent.js`,
`sts_xacml_endpoints.js`, `sts_xacml_editor.js` and `sts_roles.js` drive this
service's OWN `/admin` console and its `/admin-api`. The first four ran from the parent's
suite until 2026-08-28 and were deleted there that day, on the argument that a
test asserting something about this console belongs in the tree where a control
is ADDED to that console — the tree that should go red when the control loses
its operation. **There is no copy of them over there to sync from**, which is
what the flag is for: `allFiles()` leaves them out, so `--vendor-check` cannot
report them GONE UPSTREAM and `--vendor-sync` cannot overwrite them. They are
edited HERE, and only here.

**THE FIFTH WAS NEVER OVER THERE AND IT BREAKS ONE RULE ON PURPOSE.**
`sts_delegated_permissions_example.js` (2026-09-01) builds
`abcapp1`–`abcapp5` in the DEFAULT realm — five applications that each expose
`read` and `write` and each hold both on THE NEXT ONE ROUND, a ring rather than
the complete mesh it built for one day — and it does
NOT clean up after itself, where every other job that writes anything works in
a throwaway realm and removes it in a `finally`. That is not an oversight and
it is not a precedent: what the job produces IS the deliverable, an example
meant to be read at `/admin/delegation/allowed`, drawn there, and — since
2026-09-02 — listed under that drawing as ONE GROUP, whose own picture is at
`/admin/delegation/cluster?application=abcapp1`. A realm deleted on the way out
is an example nobody can open. What pays for it is that the job is IDEMPOTENT — the
identifiers are fixed, so it forgets every previous `abcapp*` before creating
anything — that nothing else in the suite asserts an application COUNT, and
that it runs after `sts_admin_console.js` so the console's own coverage walks
the console it has always walked. **A second job wanting the same exemption
needs the same three sentences**, not a reference to this one.

They still SIT in `tests/vendored/` rather than beside this file, and the reason
is how they RUN rather than where they belong: `tools/run-report.js` spawns them
as processes with that directory as their cwd and they
`require('./random_username.js')` and the rest out of it, where `run.js`
discovers `tests/*.js` and runs it IN PROCESS against `harness.js`. Moving them
would have been a rewrite of four files to buy a tidier path.

Why they are copies at all: this repository's launcher could previously run
those jobs only when the parent checkout happened to sit beside it, so on a
machine where it did not, thirteen of twenty-three jobs were quietly absent from
a run that said "Tests passed". The suite is self-contained now — it needs no
other checkout to run any of it.

---

**This is not where the protocol suite is WRITTEN.** The suite for this service is the
parent project's `../id-proto-debugger/tests/`, and a test that drives this
service's PROTOCOL SURFACE goes there — see the "Tests" section of the
repository root's `CLAUDE.md` for the decision and how it was made. It was made
the hard way: `tests/saml11_sso.js` was written here on 2026-08-25, the first
test this repository ever had, and moved to the parent project the same day
before a second one could be written beside it.

**What lives here is mostly a test that CANNOT live over there**, and there are
now two kinds of that plus one that is a different claim entirely:

| Kind | Where | Why it is not in the parent suite |
|---|---|---|
| An IN-PROCESS test of this repository's own MODULE CONTRACTS | here | It requires this repository's modules and `node_modules` directly, and some of what it asserts is invisible to any caller over HTTP |
| A test of this service's OWN `/admin` console or `/admin-api` | `tests/vendored/`, marked `local: true` | **Nothing stops it running over there, and it did until 2026-08-28.** It is here because the tree that ADDS a control to that console is the tree that should fail when the control loses its operation — an ownership argument rather than a capability one |
| A CONSOLE CONTROL WITH A PROTOCOL CONSEQUENCE | `tests/vendored/`, marked `local: true` | The assertion spans both doors and cannot be made from a repository holding one of them. `sts_consent.js` grants a global consent through `/admin-api/consent` and watches a sign-in stop being asked; `sts_xacml_endpoints.js` and `sts_xacml_editor.js` build a policy through `/admin-api/xacml` — or by pressing buttons on `/admin/xacml/editor` — and then ask `/xacml/pdp` and `/xacml/protected` what changed. **The XACML pair had no choice about it**: a PDP with an empty repository answers NotApplicable to everything, so there is no question worth asking that endpoint until an authoring door has been used |

There was a second row until 2026-08-26 — *an INTEGRATION test that needs
several copies of this service*, which was `../federation-e2e/` and its own
three-container stack. **TRUST REALMS closed it.** A realm is a whole logical
copy of this service on the same socket under a path prefix, so several copies
is one process now and the parent suite can reach the whole topology over HTTP:
that test is `tests/federation_sso.js` over there. Check whether realms already
answer the question before re-opening that row.

That second row is what this directory added on 2026-08-25, and the case for it
is a specific one rather than a general preference. `config_realm_layer.js`
asserts, among other things, that a trust realm carrying `oauth2.rfc9700` does
not thereby inherit `global.https`. **The parent suite could not have caught
that in any form**, because its launchers always start this service with
`STS_HTTPS=true`, and with the scheme pinned by the environment the broken and
the fixed code return the same answer. The bug is only visible with that
variable UNSET, which means varying how the process itself was started — and a
test over HTTP against a service somebody else launched cannot do that.

**SINCE 2026-08-30 THAT IS TRUE OF THIS REPOSITORY'S LAUNCHERS AS WELL** — every
appconfig file in `env/` carries `global.https: true` and both compose files set
`STS_HTTPS` — so there is now no stack ANYWHERE that could catch it, and the
only reason it is caught is that `config_realm_layer.js` deletes `CONFIG_FILE`
and varies the environment for itself. That makes the argument for this
directory stronger rather than stale, and it is the clearest example of what the
argument actually is: the thing a test here can do that no other test can is
choose how the process was started.

**So the line is: can this be asserted by driving the running service over
HTTP?** If yes, it belongs in the parent suite, where it costs one entry in
`run-report.js` and runs in the containerized stack, the host stack and the
narrowed launchers without anything being invented for it. Only if no does it
belong here.

**ONE QUESTION COMES BEFORE THAT ONE SINCE 2026-08-28**, and it is the second
row of the table above: is the thing under test this service's own `/admin`
console or its `/admin-api`? If it is, it belongs here whatever the answer about
HTTP — all four of those jobs are driven over HTTP and could have stayed over
there. The line above is about CAPABILITY; this one is about OWNERSHIP, and it
is the only place the two disagree.

## Running it

```bash
npm test              # from the repository root
LOG_LEVEL=debug npm test
node tests/run.js     # the same thing
node tests/run.js --only=ldif      # one file, by any part of its name
node tests/run.js --list           # what there is
```

It needs `npm install` to have been run (it uses `bunyan`, a normal dependency)
and **nothing else** — no port, no container, no browser, no network. The whole
suite is under a second. If a test here ever needs a listener, that is the
signal that it belongs in the parent suite instead.

**That paragraph is about `npm test` and the files in this directory, and it
stays exactly true.** The VENDORED half does need a port, a browser and a second
npm package (`tests/package.json` — see below); it is reached by
`./local-run-tests.sh` and never by `npm test`, which is byte for byte the run it
always was.

**`--only` IS A FILTER OVER THE DISCOVERED LIST, NOT A LIST**, which is the
distinction the design of `run.js` turns on — there is still nothing to keep up
to date — and a pattern matching nothing is an ERROR rather than an empty pass,
because a typo in a filter must never read as "everything passed".

### The report, and where the tooling lives

```bash
./local-run-tests.sh                 # ALL 44 jobs, with a report written —
                                     # the service in a container built from
                                     # this working tree
./local-run-tests.sh --no-docker     # the same, with the service run on this
                                     # machine
./local-run-tests.sh --keep-stack    # leave the container up afterwards
./local-run-tests.sh --no-protocol   # only the 25 in-process files
./local-run-tests.sh --only=crypto --open
./local-run-tests.sh --vendor-check  # is tests/vendored/ still in sync?
./local-run-tests.sh --vendor-sync   # re-copy the parent's files over it
./docker-run-tests.sh                # the same 44 jobs with the RUNNER in a
                                     # container too: docker and nothing else
./run-coverage.sh                    # the same set, with coverage collected —
                                     # in a container too, with the RUNNER in
                                     # it rather than the service, because V8
                                     # collects from inside the process it
                                     # measures. --no-docker is the host run
```

**`./docker-run-tests.sh` IS THE SAME SUITE AND A DIFFERENT ENVIRONMENT**, and
the three files in this directory that serve it are not tests: `Dockerfile`
(node, a Chrome and this working tree), `Dockerfile.dockerignore` (which exists
only because the repository root's excludes `tests`, since the SERVICE image
must not carry the suite) and `run-tests-in-container.sh` (the image's CMD —
wait for the service, then `tools/run-report.js --service-url=https://sts:8081`).
`../docker-compose-run-tests.yml` brings the pair up.

Which to reach for: **this one when the question is the environment**, because
it needs docker and nothing else and is what CI runs, so a failure here and a
pass locally is a difference in node, in an installed package or in the image;
**`./local-run-tests.sh` when the question is a test**, because there the jobs
are node processes on this machine and re-running one costs nothing where here
it costs an image build. The jobs, the runner and the report are the same in
both.

`./local-run-tests.sh` is this repository's answer to the parent project's
launcher of the same name, and `tests/tools/run-report.js` is what it drives.
It writes `tests/report/<timestamp>/` — `report.html`, JUnit `report.xml`,
`summary.json` and one log per job — and points `tests/report/latest` at it.
Both are gitignored.

**THE SERVICE THESE JOBS DRIVE IS TLS, AND THAT COST THE SUITE EXACTLY ONE
MODULE (2026-08-30).** `tools/trust.js` fetches the mock's certificate once the
service answers — with verification off, necessarily, since the key is
regenerated on every start and nothing that ran before it can have an anchor —
and `run-report.js` hands every protocol job `NODE_EXTRA_CA_CERTS` and
`STS_SPKI_PIN`. The second needed no new code at all: `vendored/browser_flags.js`
has read that variable for months, because the parent project's stacks have been
https for months.

**The PEM is written into the run's own report directory**, so the certificate a
run trusted sits beside that run's logs — when a job fails on a certificate the
question is always *which* certificate. Everything that PROBES rather than
tests — both launchers' `stsProbe`, `run-report.js`'s own wait,
`tools/service.js`'s readiness loop, both compose healthchecks — asks with
`rejectUnauthorized: false`, because the question there is whether the port
answers and not whether it is trusted. **The JOBS get a real anchor**, which is
what keeps an assertion about a certificate meaningful.

**THE STACK'S OWN DECISIONS ARE ARGUED WHERE THEY LIVE**, not here: why the test
stack is its own compose project on a free host port found at start (so a run
can never take, or tear down, the `sts` container a plain `docker compose up`
gives somebody), why it persists NOTHING, why the image is REBUILT every run,
and why a stack that will not come up is a FAILED run rather than a quiet fall
back to the host — all in `../local-run-tests.sh`'s header. The containerized
runner's three — no published port at all, no postgres, and the tests image
built from the SAME context behind `Dockerfile.dockerignore` — are in
`../docker-compose-run-tests.yml` and `Dockerfile`, the latter with a guard that
says so rather than failing later inside node.

**THE TOOLING IS IN `tools/`, AND THAT IS THE ONE DECISION IN IT WORTH
ARGUING.** `run.js` discovers a test as *any `.js` file in this directory that
is not itself or `harness.js`*, so a report generator sitting beside them would
have to be added to that exclusion list — and then so would the next tool, and
the list would be exactly the "second place to forget" this directory was
designed not to have. `readdirSync` is not recursive and `/\.js$/` does not
match a directory, so a subdirectory costs the discovery rule nothing.

Three things about the report runner are decisions rather than mechanics:

* **It runs each test file in a PROCESS OF ITS OWN**, where `npm test` runs
  them all in one. That buys three things — a file that HANGS is a job that
  times out rather than a suite that never finishes, a file that takes the
  process down is one red job rather than a run with no report, and the
  process-wide state rule below stops being able to make ANOTHER file fail.
  The rule still holds, because `npm test` is what CI runs and it still shares
  one process.
* **The assertion detail is PARSED out of what the harness already prints** —
  the bunyan record whose `msg` begins with a tick or a cross. No new protocol,
  no change to `harness.js`, and every file written before the report existed
  is reported in full by it.
* **THE PROTOCOL JOBS RUN BY DEFAULT AND A JOB THAT CANNOT RUN IS A FAILURE.**
  Both changed on 2026-08-28 and both were the same mistake seen twice. The
  default used to be the ten in-process files, so a bare run answered in three
  seconds having driven no protocol endpoint, no admin console and no browser —
  and said "Tests passed". And a throwaway service that failed to start left
  thirteen jobs marked `skipped`, which the summary counts as passing, so a run
  in which nothing was checked exited zero. A skip is now only for something
  deliberately left out (`--no-browser`, `--only`); an intended job that did not
  run is red, with the reason in the row.
* **THE TEST DEPENDENCIES ARE A SECOND npm PACKAGE**, `tests/package.json`,
  carrying `commander`, `selenium-webdriver` and the `@noble`/`node-forge`
  packages the vendored wallet modules need. They are not root
  `devDependencies` because `.npmrc` carries `omit=dev` — the same trap the
  coverage renderer below was written around — and not root `dependencies`
  because a browser driver has no business in the service's production image.
  `./local-run-tests.sh` installs them when they are missing; a job that cannot
  load because they are absent FAILS naming the command, rather than skipping.
* **The VENDORED jobs run against a copy of THIS working tree, IN A CONTAINER
  since 2026-08-28.** Most of what tests this service is authored over there by
  the rule at the top of this file, and their suite drives the pinned `sts/`
  gitlink — so those jobs do not otherwise run against what you just edited.
  `./local-run-tests.sh` builds an image from this tree, brings up one
  container from the repository's own `docker-compose.yml`, and hands this
  runner its URL with `--service-url`; the jobs themselves are still plain node
  processes on this machine. About a minute plus the image build, most of the
  minute being the two browser jobs — `sts_admin_console.js`, which walks every
  page, and `sts_xacml_editor.js`, which drives one page in depth.

  **THE LIFETIME RULE IS THAT WHOEVER STARTED IT STOPS IT**, and it is why
  `--service-url` exists rather than this runner learning to speak compose. A
  service handed in that way is never stopped here: the launcher's own trap
  owns it, which is what makes `--keep-stack` possible and what stops a run
  from tearing down a stack somebody asked to keep. `tools/service.js` — the
  throwaway process on nine ports of its own, stopped by the pid it started —
  is still what `--no-docker` uses and still the whole of what a COVERAGE run
  can use, because V8 writes its data from inside the process being measured
  and nothing here can reach into a container to collect it.

  **WHICH jobs is a LIST now, in `tests/vendored/MANIFEST.js`, and that reverses
  what this bullet said.** It used to be DERIVED — parsed out of the parent's
  own runner, so a job added or renamed over there arrived here with nothing
  edited, which is this directory's usual preference and was right while the
  files were read from over there. It stopped working when they became copies:
  the derivation's rule was "does the file mention `WSTRUST_STS_URL` or
  `OID4VCI_ISSUER_URL`", and of the nineteen files copied, `sts_applications.js`
  matches and is a HELPER while `sts_saml_encryption.js` is a job that declares
  no `--url` option at all. Two wrong answers in nineteen, and each wrong answer
  is a job that silently never runs — which is the exact failure the same day's
  other two changes were made to stop. The list is the price of vendoring; it is
  not a precedent for listing anything else here.

**A protocol job can be AHEAD of this tree** — that suite is developed against
its own checkout of this service — in which case it fails here naming a feature
this tree does not have. That is information about the two checkouts and not a
fault in the runner, which is why the report says which side every job came
from.

## Adding one

Drop a `.js` file in this directory. There is **no list to update** — `run.js`
discovers every `.js` file that is not itself or `harness.js` — and that is
deliberate: the standing objection to a second suite is that it means a second
place to forget, so this one has no such place. A test module exports:

```js
module.exports = {
  name: 'config_realm_layer',        // names its log lines
  describe: 'one line, printed before it runs',
  run: function (t) { ... }          // may be async
};
```

`t` is a harness from `harness.js`: `t.check(condition, what, detail)`,
`t.equal(actual, expected, what)`, `t.ok`, `t.bad`, and `t.log` (a bunyan
logger). **Do not throw for an ordinary failure** — a throw is reserved for a
test that could not RUN, and `run.js` reports that differently on purpose,
because a test that did not run has not passed.

Two rules that are not optional here:

* **MUTATION-TEST IT BEFORE COMMITTING IT.** Break the thing it guards, watch it
  go red, put it back. The whole reason this directory exists is that three
  defects in one day produced no error anywhere; a guard that has never failed
  has not been shown to guard anything. `config_realm_layer.js` was checked
  against four mutants — the derived-default fix reverted, `checkRealmOverride`
  dropping its `forRealm` argument, the `realmRuntime` marker deleted, and
  `create()` ignoring the overrides it was given — and each was caught by
  between four and seven assertions. `realm_isolation.js` was checked
  against two — the identity register put back to a plain `Map`, and one
  shared revocation `Set` behind the same call shape — caught by five
  assertions and by three. `realm_directory_lookups.js` was checked against
  four while the guards were per-lookup — each of the three group doors put
  back to a bare `getEntry()`, and `inRealm()` stripped of the default realm's
  carve-out — and against two more after the store was split per realm, which
  is what those guards became: a `getEntry()` that reaches into every realm's
  store (5 assertions red) and an `eachEntryInRealm()` that walks them all (1).
  **The file did not change between the two rounds**, which is the argument for
  asserting behaviour rather than mechanism: the mechanism was replaced and the
  test still guarded the thing that matters.
  `delegation_map_bands.js` was checked against four — the issuer put back into
  the dagre layout (5 assertions red), the label rows' overlap check removed so
  every label lands in one row (1), the hexagon placed at the left instead of
  centred (2), and the empty-picture case padded with the band it does not need
  (1). The third of those found a real coupling while it was being written: the
  hexagon's position was written out twice, once where it is placed and once
  where a label's line is solved for, and moving one drew every label a few
  pixels BESIDE its own line rather than drawing the hexagon in the wrong
  place. It is one `stsAt` now.
  `spnego_identity.js` was checked against six — `usernameFor()` stripping
  EVERY realm rather than only the local one (3 assertions red), `factorsFor()`
  claiming `pwd` for a ticket that claims nothing (10), reading `initial` as
  evidence that a password was checked (2), calling a lone hardware factor
  `mfa` because it is phishing-resistant (1), splitting the principal on the
  FIRST `@` rather than the last (1), and collapsing the four method sentences
  into one (1). The second of those is the case the file exists for and it is
  the one no test over HTTP could have run: this KDC requires
  pre-authentication, so no client can obtain a ticket claiming neither flag,
  and `hw-authent` is never set by anything here at all — a test over there
  would have exercised one branch of four and reported green over the rest.
* **CLEAN UP THE PROCESS-WIDE STATE YOU TOUCH.** The realm table and
  `process.env` are shared by every test in the run, so a realm left behind
  changes what a later test resolves. Use the `withEnv()` / `withRealm()` shape
  in `config_realm_layer.js`: save, act, restore in a `finally`.

  **This rule used to be justified by "and this service persists nothing", and
  that clause is gone as of 2026-08-27** — see `persistence/CLAUDE.md`. The rule
  is unchanged and is now slightly more important rather than less: leftover
  state was always visible to the rest of the run, and a test that reached a
  persistent store could leave it visible to the next RUN as well. In practice
  it cannot, because `persistence.mode` defaults to `memory` and every test here
  deletes `CONFIG_FILE` before requiring anything — so nothing in this directory
  opens a store — with ONE exception since 2026-08-28. **A test that
  deliberately turned one on would be the first, and it would have to clean up
  a directory or a database rather than a Map**; the codec test avoids that by
  testing the codec rather than the driver.

  **`appconfig_persistence.js` IS that test, and it took the condition this
  paragraph set.** It writes into a directory of its own under the system
  temporary directory, made per run with `mkdtemp`, and removes it in a
  `finally` — including when an assertion has failed, since a failing run is
  exactly the one that would otherwise leave the litter behind. It also puts
  back the five `STS_PERSISTENCE_*` variables, the override it sets and the
  realm it creates, and it STOPS the store before removing the realm, so a
  scheduled flush cannot fire against a table the realm has already gone from.

## What is in here

| File | What it guards |
|---|---|
| `config_realm_layer.js` | what a trust realm may and may not carry, at the writing end and at the reading end |
| `realm_isolation.js` | that a realm's identity register and its revocation set are its own, in both directions, and that removing a realm takes them with it |
| `realm_directory_lookups.js` | that a lookup BY DN answers about one realm — groups, people and applications — including that a refused cross-realm delete leaves the entry where it was |
| `delegation_map_bands.js` | that the delegation picture is TWO BANDS — the issuer above, centred, every party on one plane — and that no two edge labels are drawn on top of each other |
| `federation_map_bands.js` | that the federation picture is THREE BANDS — left asks, right authenticates — that the four relationship states are four distinguishable strokes, that a brokered partner is ONE arrow which keeps that pair's counts, and that the per-application counts either add up or report the difference |
| `spnego_identity.js` | what a SPNEGO sign-in claims: which part of a Kerberos principal becomes the session's username, and the `amr`/`acr` read off the ticket's own flags |
| `ldif_codec.js` | that every value this service can put in an attribute survives the RFC 2849 round trip `persistence.mode=ldif` writes — the base64 rules, the folding, `origin` riding as a comment, and a URL-valued attribute being refused rather than dereferenced |
| `appconfig_persistence.js` | that a setting change reaches the store ON DISK, comes back the way the next start puts it back, and that a realm's settings and the process's are two different files |
| `user_graph_permissions.js` | that a blue `reaches` line drawn from a TOKEN names the delegated permissions on it — both spellings a client may use, the `default permissions` fallback, the intersection that keeps `openid` off the label, and that a `reaches` line out of the delegation register says none of it |
| `xacml_pep.js` | **phase five, and the only file here that spawns a CHILD PROCESS.** That the XACML engine loads in `xacml-pep/` against a thirty-line helpers shim with NOT ONE of this service's own modules in its `require.cache`, and reaches the same decision there as here on the same policy — which is what makes "the engine is a library with no I/O" a checked claim rather than a comment at the top of seven files. That the container's Dockerfile copies exactly the modules `engine.js` loads, in order, which is this repository's own version of the parent project's standing COPY-set obligation, enforced rather than remembered. That the two implementations of section 7.2 agree over seven decisions under both biases — **and that the two biases disagree somewhere**, so the agreement is a comparison rather than two functions that both say yes. Plus the sync token being a digest of what would be SENT (a policy edited and edited back gives the ORIGINAL token, where a modification stamp would not), and the register's four decisions that each prevent a wrong reading. **A child process rather than a require, and that is not a preference**: `engine.js` primes `require.cache` so the host run and the image run load the same shim, and `run.js` runs every file in ONE process — so a require here would hand that shim to `xacml_service.js` next |
| `api_sessions.js` | **two claims.** First, that `ISSUANCE.SESSION` is asked at the FUNNEL — `startSession()` — and not at one door: it was asked only at this service's own sign-in screen while five other paths minted a session and never asked (a federated assertion, a SPNEGO ticket, a client certificate, a WS-Trust UsernameToken, the WebAuthn funnel), so an application narrowed to a role refused a password sign-in and admitted the same person through any of them. It pins that a refusal returns NULL and does not THROW — two callers wrap that call in a `try` that treats a failure as bookkeeping, so a thrown refusal would be swallowed and the session started anyway — that `gated: true` opts the one door that already asked out of being asked twice, and that a sign-in naming no application is allowed even when the decider refuses that very person, which is the existing rule and what keeps every caller unaffected. Mutation-tested against removing the gate and against throwing instead of returning null. Second, that the management API, SCIM and the SPIRE Server API sign in through **the one session store** — `authn.startSession()`, the same map browser sessions live in — with ONE ROW PER CREDENTIAL rather than one per request: twenty-six calls with the same fingerprint are one session, a different fingerprint is a different one, both appear in `logout.liveSessions()` and a global sign-out ends them through the same `terminate()`. **A register of their own was the obvious implementation and is what this file exists to prevent**: two answers to "is somebody signed in", with the wrong one being whichever surface a reader happened to look at (rule 3m). It also pins that one store does not mean one kind of ROW — an API session is drawn by its own surface, carries the fourth expiry rule (the only one extended by use) and reports calls rather than the relying parties a browser session carries — and, last so nothing above could pass by making every session an API session, that a browser session is exactly what it was |
| `xacml_service_own.js` | that the two policies this service decides its OWN boundaries with — `role-issuance` at the nine issuance sites and `access-control` at the five gated surfaces — are reported by the console, in four states: no override (both BUILT IN and both deciding, which is why neither has ever been in the editor's chooser), an enabled override (the stored document wins), a disabled one (neither falls back), and deleted (the built-in returns). **It is in process because two of those states are reached by DISABLING the override**, and disabling `role-issuance` takes issuance policy out of the decision for the whole service — over HTTP that is a change every other job in the run would meet. It found the sixteenth defect in `xacml/CLAUDE.md`'s list: `accessPolicy()`'s `typeof repository.get === 'function'` guard was false on every call, so `xacml.accessPolicy` had never once been honoured. Mutation-tested against both spellings of it — the assertion that catches a condition nothing ever satisfies is the one about the state FLIPPING when an override is created, not one about any single value |
| `access_policy.js` | that the XACML `access-control` policy makes OWNERSHIP a CONSTRAINT and not an alternative — a signed-in person reaches their own portal account and NOT somebody else's, for `manage-own` and for `read` separately, while the four ownerless surfaces go on behaving as plain RBAC. It exists for a regression: the policy was first written as three OR'd arms, "the resource requires nothing" was true for the portal (which narrows nobody), and it swallowed the owner comparison — so any signed-in person could reach any other person's account, with no error and no Indeterminate anywhere. `portal_access.js` stayed green throughout, because that file asserts the STRUCTURAL rule (the handler reads the identity from the session, never from the request) and this asserts what the POLICY decides once it has a trustworthy subject. Both halves are needed and neither implies the other. Mutation-tested against the OR spelling and against a wrong empty-owner reading |
| `key_residency.js` | that a private key is decrypted while it signs and not the rest of the time: nothing decrypted after `start()` (the startup decrypt is a KEK check whose plaintext is thrown away), the public half — certificate, kid, every curve key's public JWK, which is what the JWKS endpoint walks — readable with nothing decrypted, and the three retention words doing three different things. `resident` is asserted BEFORE the two purging words, so a `report()` that always answered "nothing held" could not pass the file; the `timed` case uses the key at 700ms and checks it is still held at 1400ms, which is what separates an IDLE clock from an absolute one. Every residency check is paired with a real RS256 signature verified against the published public key, so a feature that quietly broke signing would fail here. Mutation-tested against a purge that forgets the parsed `KeyObject` and against arming the timer on decrypt rather than on use |
| `worker_pool.js` | the four ways moving a computation into another process goes wrong: that a worker computes the SAME BYTES (literal equality for the nine deterministic algorithms; cross-verification for the three whose ECDSA half is randomized and must be), that the event loop is genuinely FREE while it does — counted in timer ticks, against an unpooled control that manages none — that a session's jobs go to one worker and unnamed ones spread, and that a SIGKILLed worker FAILS its jobs with a sentence rather than leaving a promise nobody settles. Plus `workers.count = 0` producing the same bytes here, and a realm being refused the setting at both ends |

**`sts_portal_sessions.js` IS THE NEWEST OWNED JOB (2026-09-06)** and it covers
three claims nothing else did over HTTP: that a sign-in at `/admin` and one at
`/portal` each create a session `GET /admin-api/sessions` lists, named by the
surface it came through; that a SIGNED-IN person reaching for somebody else's
portal account gets their own; and that signing out INVALIDATES the session
rather than merely tidying a list.

Three things about it are worth keeping if it is reworked.

**THE A01 CHECK IS THE AUDIT ROW AND NOT THE PAGE.** It posts a password change
with somebody else's name in the body and then reads `GET /admin-api/audit` back
for the actor. That was mutation-tested by making `/portal/password` read the
username from the request — the classic broken-access-control bug — and **the
page assertion still passed**: the response rendered the caller's own account
while the WRITE went to the person they had named. A rendered page proves the
page; only the audit row proves the write.

**THE SIGN-OUT IS TWO ASSERTIONS.** The session leaves the register AND the
cookie stops being accepted. A mutant that removed `sessions.delete(id)` was
caught by the first; a sign-out that forgot the row and left the credential
working would pass the first alone, which is why the second re-presents the same
cookie at the door it was made at.

**IT IS NOT A DUPLICATE OF `portal_access.js` OR `access_policy.js`.** Those two
are in process and assert different layers — the credential layer (an id is
looked up among the CALLER's own keys) and the policy layer (the XACML document
denies a non-owner). Neither sends a request, so neither could see a handler
that reads a name off the body. All three are needed and none implies another.

**`vendored/` is not in that table either, and for the opposite reason: it is
ALL tests** — nineteen jobs and the files they need, listed and argued in
`tests/vendored/MANIFEST.js`. **It is split by OWNERSHIP and the table below is
that split**, which is why the jobs are described here at all: the paragraph
this replaced said they were "not this repository's to describe", and that was
true while every one of them was a copy. TEN are this repository's own now, so
`docs/test-suite-map.md` over there describes the parent's and this describes
ours. For the copies the entry is deliberately short — that document is where
each of those is written down, and a second full copy here would drift.

Fourteen tests need only this service, and since 2026-08-28 they are OWNED by two
different repositories — which is the first thing to know about the table below,
because every one of them but the last ran from the parent's suite before that
date. **TEN are this repository's own**: `sts_metadata.js`, `admin_api.js`,
`sts_admin_api_operations.js` and `sts_admin_console.js`, deleted over there and
kept here, because each asserts something about this service's `/admin` console
or its `/admin-api` and the tree that adds a control is the tree that should
fail when the control loses its operation — and
`sts_delegated_permissions_example.js`, which was NEVER over there: it was
written here on 2026-09-01 and it drives `/admin-api` to build something for
`/admin` to draw — and `sts_consent.js`, written here the same day and here for
a THIRD reason worth keeping apart from those two. Half of it is an ordinary
protocol test and by the rule below belongs over there; the other half grants a
GLOBAL CONSENT through `/admin-api/consent` and then watches a sign-in stop
being asked, and the assertion that matters is that a console control changed
what the AUTHORIZATION ENDPOINT does. A test with the grant in one repository
and the sign-in in the other could not make it. **And `sts_xacml_endpoints.js`
and `sts_xacml_editor.js`, written here on 2026-09-05, are here for that third
reason and are the strongest case of it**: a PDP with an empty repository
answers NotApplicable to everything, so there is no question worth asking
`/xacml/pdp` until a policy exists, and the only way to put one there over HTTP
is `/admin-api/xacml`. Every assertion in either file therefore spans a console
door and a protocol door — a template built on `/admin-api` deciding at
`/xacml/pdp`, a policy disabled on the console vanishing from what a remote PEP
pulls, a rule built by pressing buttons on `/admin/xacml/editor` changing what
`/xacml/protected` allows. **AND `sts_roles.js`, written here on 2026-09-05,
which is that third reason at its widest**: a role is made on `/admin-api/roles`
and an application is NARROWED on `/admin-api/applications`, and what that
changes is what `/oauth2/token`, `/oauth2/authorize`, `/wstrust`, `/wsfed` and
both SAML profiles answer. The assertion that matters is not that the register
holds what was written — `tests/roles.js` makes that one in process — but that
somebody is REFUSED at a protocol endpoint, in that protocol's own words, and
that the person beside them is not. Neither half of that sentence is available
to a repository holding only one of the two doors. **AND `sts_roles_builtin.js`,
written here on 2026-09-05, is the tenth and is here for that same third
reason**: it turns `authn.unauthenticatedSessions` on through `/admin-api`,
presses a button on the sign-in screen, and then asks `/oauth2/authorize` and
`/oauth2/token` what changed — and the thing it asserts is that a party the
console can describe is refused at a protocol door in that protocol's own
words. **The other four are still the parent's**, and this repository
holds copies of three of them — `sts_persistence_postgres.js` is not vendored,
because it needs docker.

**Nineteen jobs run from `tests/vendored/`** — the fourteen below that a lone
mock can satisfy, plus five others — so they run against this working tree with
no parent checkout present. The paths in the first column are where each file is
READ FROM here; for the four the parent still owns, that copy is not the source
of truth. **The in-process pair `user_graph_permissions.js` and
`app_permissions.js` is deliberately NOT repeated here** — it sat in this table
while the table lived in the root `CLAUDE.md`, where the first table above was
out of sight; both files have a row up there and a section of their own below,
and carrying them twice is what made this table's own arithmetic wrong.

| Test | What it covers |
|---|---|
| `tests/vendored/sts_metadata.js` **(ours)** | the `/admin/sts-metadata` drift checks — that the page lists exactly what the router registers, that every method reaches a handler, that every link resolves, and that no specification claim is idle |
| `tests/vendored/admin_api.js` **(ours)** | the management API at `/admin-api`: its OpenAPI document, the PARITY it exists to keep — every `/admin` page and every action of its four handlers has an operation, read off this service's own answers rather than off a list in the test — every documented schema property checked against a live reply, and that a revocation made through the API is dead at `/oauth2/introspect`. It restores everything it changes, including the tokens its bulk revocations touched |
| `tests/sts_dpop.js` | RFC 9449 end to end over HTTP: all twelve section 4.3 checks, the `cnf.jkt` binding on access and refresh tokens, `dpop_jkt`, `jti` replay, and the nonce handshake in both shapes. Almost entirely negatives, because a DPoP server that issues bound tokens and accepts good proofs looks finished and can be worth nothing |
| `tests/oauth2_sts_endpoints.js` | every endpoint the RFC 8414 metadata advertises answers, and every token verifies against the advertised JWKS |
| `tests/vc_did.js` | the DID-named issuer chain: advertisement → resolution → domain linkage → the key that actually verifies the credential |
| `tests/vendored/sts_admin_api_operations.js` **(ours)** | **the other half of that API — EVERY operation it declares, driven for real, with a LEDGER that says so.** No count is written down in it, on purpose: it was ninety operations when the file was written and it is a hundred and thirty-one now (41 reads, 90 writes). Two things are asked of that ledger at the end of the run and both are about the FILE rather than the service — **every documented operation was driven**, or holds a row in `NOT_DRIVEN_HERE` naming who drives it instead (two rows, both the explorer, which `admin_api.js` owns along with its CSP), and **every write that succeeded was read back through the resource's own GET, in the scope it was written in**. Besides that: each documented example body replayed, so that a request property the document names and the handler does not read fails HERE rather than for the first caller who copies it; each handler's refusal sentence checked against the document both ways round (that sentence is what `admin_api.js` reads for the parity, so one short by an action turns the parity check off for it); every write read back through a DIFFERENT operation; and a configuration change followed as far as the persistence store's own write counters. Almost all of it in a trust realm it creates and removes |
| `tests/vendored/sts_admin_console.js` **(ours)** | **the `/admin` console itself, IN A REAL BROWSER since 2026-08-28: the gate, all thirty-eight pages, every link, every GET form and every button on them — and the value that comes back afterwards.** It was an HTTP job, and the argument for that (this console has no script on it, so a control IS a form and pressing a button IS posting it) is still true; what it missed is that a hand-built submission is the TEST's reading of the markup rather than the browser's, that the twenty-two GET forms had no POST target to walk and so were never checked at all, that the nested-`<form>` guard is a PARSER question the old file had to reason about instead of asking, and that a notice is not a value. Status codes and headers come from **WebDriver BiDi**, because `default-src 'none'` blocks a `fetch()` from the page — the thing under test. Plus: every link really visited, which covers the seven routes with no nav row by construction; the five handlers nothing had ever pressed, `/admin/rbac`'s own grant and revoke among them; refusals split into what the BROWSER will not send and what the handler will not accept; the realm switcher; and the browser's own console, which on this console must be empty |
| `tests/vendored/sts_delegated_permissions_example.js` **(ours)** | **THE DELEGATED PERMISSION REGISTER AS A RING, AND THE ONE JOB HERE THAT LEAVES ITS WORK BEHIND ON PURPOSE.** `abcapp1`–`abcapp5` in the DEFAULT realm, each declared for OAuth 2.0 and OpenID Connect with its supporting fields filled in, each exposing `read` and `write` under a base URI of its own, and each granted both on THE NEXT ONE ROUND — `abcapp1`→`abcapp2`→`abcapp3`→`abcapp4`→`abcapp5`→`abcapp1`: five resources, ten permissions, ten grants. **It was a complete mesh of forty grants until 2026-09-01** and the file argues the change rather than merely recording it: the mesh was the stronger test and the weaker EXAMPLE, and this job is both — forty lines between five boxes is the one graph shape that looks the same however it is drawn and however it is wrong, and this example exists to be LOOKED at. What survives is the assertion that matters: every grant still resolves to the RIGHT resource among five whose bases differ only in a digit, so a lookup matching on a prefix, a host or the bare name is wrong for four of the five pairs. What replaced the mesh's arithmetic is an EXACT-LIST assertion per entry — `abcapp2` holding `abcapp4`'s `read` would keep every count right and be wrong about the only thing the example says. Plus the two halves landing on the right ENTRIES (a grant written to the resource instead of the client reads correctly on `/permissions` and finds nothing at the token endpoint), the PICTURE — five boxes, ten lines, `may-reach` on every one and `acts` zero everywhere, because a configured grant has been exercised nought times and the renderer colours `acts && !issued` as a refusal — and the TOKEN, audienced to the one base URI of five that was asked for (its own successor, the only one it holds anything on), carrying the bare names on its scope claim, and moving exactly two of the ten grants to `asked`. It is IDEMPOTENT (the identifiers are fixed, so every previous `abcapp*` is forgotten first) and it does not tear down, because the example exists to be READ at `/admin/delegation/allowed`. **Since 2026-09-02 it also asserts the GROUPING** — that the five are ONE group and that nothing else in the default realm is in it, which are two different failures (a partition too fine, and one too coarse) that a service with only these five configured could not tell apart, and that all five applications resolve to it, since every one of them is both a client and a resource. What it deliberately does NOT assert is the direction decision: a ring is connected whichever way you walk it |
| `tests/vendored/sts_consent.js` **(ours)** | **THE CONSENT SCREEN, AND THE OVERRIDE THAT MAKES IT NOT APPEAR.** Mostly negatives, for `sts_dpop.js`'s reason: a screen that draws, takes an Allow and hands over a code looks finished and can be worth nothing. What it asserts is that a GET of the screen records NOTHING (or anything that prefetches a link has consented for somebody), that a consent id is spendable ONCE, that a consent asked of one person cannot be drawn OR answered by another's session and that every one of those refusals leaves the pending record answerable by the person it belongs to, that Deny records nothing and the refused scope is asked again, that a second request is silent and a new scope asks about ITSELF ALONE, that `prompt=none` answers `consent_required` and `prompt=consent` asks again without destroying what was already agreed. **And the half that is not drivable from the parent's suite and is why this file is here**: a delegated permission consented globally on an application's entry stops a person who has never been here being asked — with NOTHING written about them — while a second application asking for the same permission is still asked, and removing the override asks everybody again including the people it was covering |
| `tests/vendored/sts_xacml_endpoints.js` **(ours)** | **THE SEVEN `/xacml` ENDPOINTS, IN A THROWAWAY TRUST REALM.** Until it existed every route in `xacml/xacml.js` was uncovered — the in-process XACML suite holds the ENGINE to 455 OASIS cases and makes not one HTTP request. What is here is the surface in front of it: a template built on `/admin-api` deciding at `POST /xacml/pdp` against an attribute the request never carried; four malformed requests refused **400 and never Indeterminate**, which is the distinction a PEP most needs, since an Indeterminate would be enforced by its bias; the embedded PEP's two biases disagreeing on the one answer they are supposed to disagree on (NotApplicable, reachable only in a realm whose repository is empty); an obligation this PEP cannot discharge turning a Permit into a refusal and the SAME Permit standing once it is renamed to the one it knows; a remote PEP's pull, its ETag, its 304, and a disabled policy reaching nobody; **a registration named from the client CERTIFICATE and never from the body**, on the registration and on the heartbeat alike, which is the one defect in this family that would be a security bug; a PEP an administrator disabled staying disabled when it reconnects; a policy save that does not wait on an unreachable PEP; and both off-switches answering 501 in the realm while the default realm goes on answering. Mutation-tested against six mutants |
| `tests/vendored/sts_xacml_editor.js` **(ours)** | **THE GUIDED POLICY EDITOR, IN A REAL BROWSER.** `tests/xacml_pap.js` holds the editor's GRAMMAR in process; what it cannot see is whether any of it reaches a page — forty forms in one table, a hidden `path` per row, an `action` that is sometimes hidden and sometimes a `<select>`, and a nested-`<form>` hazard that is a parser question rather than a taste one. So this presses buttons: every row's menu equals the grammar's own answer for that row and Remove is drawn exactly where something may be removed; a Match offers no Add menu and its function list is the two-argument boolean predicates rather than the library; a rule stops offering a second Condition once it has one; an edit that would leave the policy invalid is refused, explained, and **the stored document is byte-for-byte what it was**, which is the property that makes a live editor tolerable. **And the assertion the file is for**: a rule built out of four form submissions makes `/xacml/protected` permit somebody it refused, alternatives are shown to be ORed and matches ANDed by watching that decision move, and removing the rule on the page brings the refusal back. It found one defect on its first run — every refusal on the three `/admin/xacml` pages redirected with an EMPTY `error=` — and was mutation-tested against four more |
| `tests/vendored/sts_roles.js` **(ours)** | **ROLES, AND THE NINE KINDS OF ISSUANCE THEY REFUSE PEOPLE AT.** In a throwaway trust realm, because this feature REFUSES people: a job that narrowed an application in the default realm and died before clearing it would leave every later job in the run signing in to a service that turned them away, and the failure would name the wrong file. Mostly negatives, for `sts_dpop.js`'s reason — a service that issues a token to somebody who holds the role is what an unmodified service does for everybody. What it asserts: the roles claim reaching a client; a narrowed application refusing at the token endpoint in **OAuth's own words** (`access_denied`, read as the error CODE rather than as a 400, because the two are a working gate and a broken handler); the person beside them not refused; a GROUP and an APPLICATION holding a role, which is the half `client_credentials` needs since there is no person in that grant at all; the six built-in roles never appearing in the claim; WS-Trust's optional AppliesTo; and `roles.enforceIssuance` off putting everything back. Mutation-tested against eight mutants |
| `tests/vendored/sts_roles_builtin.js` **(ours)** | **THE SIX BUILT-IN ROLES, ONE SECTION EACH, POSITIVE AND NEGATIVE.** `sts_roles.js` above drives the register and every role it uses is CONFIGURED; these six are computed from what the party IS, and three of them could not be held or failed by anything arriving at an endpoint until the day this was written. **EVERYBODY is the one with no negative case** — its `holds()` is `return true`, so it refuses nobody — and the file asserts that rather than leaving the gap to be noticed, by checking the catalogue still calls it the DEFAULT requirement. The other five are asserted both ways, at BOTH doors: the sign-in screen, which refuses with the page again and the reason on it, and the authorization endpoint, reached by making the session at the permissive application and carrying it to the strict one, which is the only way to see the second gate at all. Plus the unauthenticated session itself — that declining returns to the caller rather than answering `access_denied` like Cancel, that it is the stable `anonymous` principal on a real session id, that a signed-in session is NOT in that list, and that the setting is honoured at the DOOR and not only on the page. Section 6 asserts `oauth2.rfc9700` is OFF before it asserts anything else, because the claim there is that client authentication is OBSERVED without being ENFORCED. **It found the bug that made `ALL_AUTHENTICATED_USERS` refuse everybody.** Mutation-tested against seven mutants, none of which survived |
| `tests/sts_persistence_postgres.js` | **`persistence.mode=postgres`, and the only test anywhere that RESTARTS this service.** It starts its own database and its own mock, so it touches the shared one not at all. What survives — the realm registry with each realm's overrides, the directory in both realms, the appconfig overrides with their source — and, just as much, **what must not**: the signing key is regenerated, so the `kid` differs and a token minted before the restart is dead at introspection. Plus the two claims nothing else could check: that two processes on one database do NOT see each other's writes (`coordinates: false`, demonstrated rather than read back), and that a database that is not there leaves this service RUNNING out of its seeded directory. Skips, naming which, without docker or without a complete checkout to run |

They are plain node scripts using `assert` and `bunyan`, and they take
`WSTRUST_STS_URL` / `OID4VCI_ISSUER_URL` to locate the service. **All but two
are driven over HTTP with no browser; `sts_admin_console.js` and
`sts_xacml_editor.js` are the exceptions** and the first has been a Selenium job
since 2026-08-28 — the reasoning is in
its own header and in `docs/test-suite-map.md` over there, and the short version
is that a console whose every control is a form is exactly the case where the
BROWSER is the independent implementation of what a form submits.
`sts_dpop.js` writes its **own** DPoP client rather than importing the wallet's, on
purpose: if both sides of the exchange came from one implementation, a shared
misunderstanding would make the test pass and interoperate with nobody. Keep that
property when porting.


`tools/` is not in that table because nothing in it is a test:
`run-report.js` (the report generator), `coverage-report.js` (the V8 coverage
renderer), `vendor-check.js` (the drift check over `vendored/`, and a TOOL
rather than a job on purpose — its own header argues why a check that needs the
other checkout must not be what decides whether this repository is green),
`service.js` (one throwaway copy of this service, started and
stopped by pid, on nine ports of its own) and `coverage_entry.js` (`server.js`
started so that its coverage survives being stopped — V8 writes on a CLEAN
exit, and a service is stopped with a signal, so without this the protocol half
of a coverage run is silently empty).

Both realm files bend the rule at the top of this file, and each says so in
its own header rather than leaving a reader to catch it.
`realm_directory_lookups.js` carries one gap worth knowing: the LDAP SOCKET
half of the same fix — a subtree search is scoped to the realm its base
names — needs a listener to test, so by this file's own rule it is not
asserted here. It was verified by hand, and `ldap/CLAUDE.md` records what
was checked.

`spnego_identity.js` passes it on the same clause `config_realm_layer.js`
does — **the cases worth asserting cannot be produced by driving the running
service.** A ticket carrying neither `pre-authent` nor `hw-authent` is where an
implementation is most tempted to fill in a plausible value, and this KDC
requires pre-authentication so no client can obtain one; `hw-authent` is set by
nothing in this repository, so the two-factor branch is unreachable from
outside the process entirely. The end-to-end claim — a real AP-REQ over a real
socket producing a real session — needs a listener and belongs in the parent
suite beside `krb5_spnego_http.js`, which already drives the acceptor that door
shares.

`delegation_map_bands.js` passes the rule at the top of this file on a
different clause from the realm files': `render()` is a pure function from a
graph to an SVG document — no store, no config, no request — so the cases worth
asserting are ones the running service cannot be made to produce on demand. A
graph whose issuer lines all end within a few pixels of each other, or an
issuer with nothing attached to it at all, would mean driving protocol traffic
until the register happened to hold the right shape. The geometry would have to
be parsed back out of the answer either way; what cannot be done from over
there is CHOOSING the graph. What it does NOT assert is the model half of the
same change — that an access token's audience becomes a line at all — because
that one IS drivable over HTTP and belongs in the parent suite by the rule
above. It was verified by hand against a four-tier chain; `common/CLAUDE.md`
rule 3p records what the rule is.

`federation_map_bands.js` passes on both of `delegation_map_bands.js`'s clauses
at once, which is why it is one file rather than two. The DRAWING half is a pure
function from a graph to an SVG document, so the cases worth asserting — a
relationship in each of the four states at once, a broker whose onward partner
is disabled — are ones the running service cannot be made to produce on demand.
The MODEL half asserts arithmetic a page rounds off: *the per-application rows
sum to less than the relationship's own total, by exactly the number of sign-ins
that named no configured application* is a statement about two registers, and
the only way to see it over HTTP is to have already trusted the number being
checked. What it does NOT assert is the SIGN-IN PATH that fills the attribute —
that the login endpoint carries the application across the round trip, and that
all five `completeSignIn()` call sites pass it — because that IS drivable over
HTTP and belongs in the parent suite by the rule at the top of this file. It was
verified by hand against five real federated sign-ins; `federation/CLAUDE.md`
records what was checked.

It was mutation-tested against SIX mutants and each was caught: the `asks` arrow
reversed in the model (5 assertions red), the broker dedupe removed so a
brokered partner is drawn twice (5), the layout flipped to `rankdir: 'RL'` (4),
a partner shape dropped so its box is never emitted (1),
`applicationConfiguredFor()` replaced with "believe whatever the request named"
(2), and the unattributed remainder stopped being computed (2). **The first of
those is worth reading**: it was caught by the BROKER assertions and not by the
band ones, because the band assertions build their graph by hand — so the two
halves guard different things and the mutants that prove it are the layout ones,
which the band assertions did catch. A guard that had only the hand-built graph
would not have noticed the renderer.

`realm_isolation.js` is the one closest to the line: the leak it guards IS
observable over HTTP. It is here because the parent project's
`sts/` gitlink is pinned at a commit from before this repository was
reorganised — so a guard written over there today does not run against this
code — and because the purge half of it cannot be seen from outside at all,
where "purged" and "never existed" look identical. If the pin is ever bumped
the first reason goes away and the second one does not.

`ldif_codec.js` passes the rule at the top of this file on the clearest clause
any file here has had: **the failure is invisible until a restart, and it
happens in a different process.** A value written wrongly — a leading space
eaten, a folded line rejoined without its fold, UTF-8 mangled — is still in
memory and still correct on every endpoint for the whole life of the process
that wrote it. Nothing an HTTP client can ask shows it. The damage appears on
the next start, as an attribute that is quietly not what it was, in a file that
is still perfectly valid LDIF. The codec is also a pure function of a string, so
a test that started a listener to reach it would be slower and no more
convincing.

`appconfig_persistence.js` passes on the same clause one step further along,
and it is the file that says what the line is FOR. The parent suite's
`sts_admin_console.js` and `sts_admin_api_operations.js` go as far as anything
driving the running service from outside can — the first of them in a real
browser since 2026-08-28, which changes nothing about this line: they watch `/admin-api/persistence`'s write counter move, its dirty
flag clear and its failure counter stay put. That is still an assertion about a
number the service computed about itself. **What is IN the file cannot be asked
over HTTP at all**, and the failure is invisible until a restart, in a different
process — a value written with the wrong type, or not written, is correct on
every endpoint for the whole life of the process that made it, and the damage
appears on the next start as a setting that has quietly gone back to its
default. So this file drives the real modules in process against a temporary
directory and then READS the files.

**It drives `ldif` and not `postgres`, and that is this directory's rule rather
than an omission.** Both modes sit behind ONE driver interface, so everything
asserted there — which of the three things is dirty, which store it belongs in,
what `applyPersistedOverrides()` does with what comes back — is the same code
path either way; what differs is the driver's own SQL, and reaching that needs a
database, which is the one thing the *Running it* section says a test here may
not need. The postgres driver is covered by
`tests/sts_persistence_postgres.js` in the parent suite, which stands up a
database and a mock of its own and RESTARTS it — the assertion no test in
either directory could make before, because every other job drives a service
somebody else started.

It fills `persistence.setDirectory()` with two functions rather than requiring
`ldap/ldap_server.js`, and that is a decision rather than a shortcut: the
directory half has its own coverage in `ldif_codec.js`, what is under test here
is the APPCONFIG and REALM halves, and requiring the real directory would mean
requiring the console, which requires the authorization server, which is most of
the service.

**Its mutation record carries the same lesson `ldif_codec.js`'s does, and found
it the same way.** Four mutants, and one of them survived the first version
TWICE, for two different reasons. `setOverride()` writing into the process-wide
map regardless of the realm was caught (2 assertions red), and `clearOverride()`
not telling the store was caught (1). The realm branch of `configChanged()`
switched off entirely was caught by NOTHING: the first version set the realm's
value through `realms.setOverride()`, which writes the realm row directly and
fires the realm change event, so it never reaches `configChanged()` at all. The
write goes through `config.setOverride()` with the realm AMBIENT now, which is
what every door a person uses actually does — and that still was not enough,
because creating a realm makes the registry dirty on its own, so the create's
write and the override's write coalesced into one and the assertion passed
whether or not the override had scheduled anything. **The line that catches it
is a `flush()` between the two**, and it is commented as such, because it reads
like tidiness and is the whole guard.

The fourth mutant — `checkOverride()` losing its `forRealm` default — is NOT
caught here and is not meant to be. `setOverride()` passes that argument
explicitly because it has the realm in hand, so in process the default is
unreachable; what it fixes is the three call sites in `admin-ui/admin.js` that
pre-validate a whole section before writing any of it, and those are only
reachable over HTTP. That mutant is caught by `tests/vendored/sts_admin_console.js` in
the parent suite, which presses the Save button those call sites are behind.
**Two halves of one fix, each guarded where it is observable**, is what this
directory's line looks like when it is working.

**`ldif_codec.js`'s mutation record is the one to read before writing the next
file here**,
because one of its four mutants SURVIVED the first version and the reason is
general. Three were caught immediately: dropping the trailing-space rule from
`needsBase64()` (1 assertion red), folding one column too wide (3), and ignoring
the `# sts-origin:` comment on the way in (2). The fourth — unfolding with
`.trim()` instead of `.slice(1)`, which eats the value's own whitespace at a
fold boundary — was caught by NOTHING, because every folded value the file tried
was a run of one repeated letter and trimming removed nothing. The assertion
that catches it had to be constructed: a value whose own space falls exactly on
the fold boundary, so the continuation line begins with two spaces. **A round
trip over convenient data is the shape that passes while proving nothing**, and
the only reason that was found before it was committed is that the mutation
round is mandatory here.

## TWO CI-ONLY FAILURES, AND WHAT EACH ONE TEACHES (2026-08-30)

Both were found by a manual `workflow_dispatch` of `.github/workflows/tests.yml`
on `develop`, both were invisible on a developer machine, and neither was a
defect in the service. They are recorded together because the lesson is the
same one twice: **a test that is timing-dependent passes on the machine it was
written on and fails on the machine that matters.**

### `sts_admin_console` — a 60ms sleep where a wait belonged

The gate section presses a real form POST with the cookie jar emptied under it
and asserts the console REFUSES rather than redirects. On the runner it failed
with `expected exactly one POST while posting a form with no session; the
browser made 0: []`.

Nothing about the console was wrong. `settleAfterSubmit()` waited for
`document.readyState === "complete"` and then slept 60ms "so the BiDi events
for what just loaded have been delivered" — and `readyState` and BiDi event
delivery are **two different clocks**. On a two-core runner the
`responseCompleted` event for the POST arrived after the sleep expired.

**The fix was already written in the same file, one function up.** `go()` had
met this race for GETs and refused to sleep through it: it calls
`waitForResponse(url, from)`. The POST path now has the sibling —
`waitForMethod(method, from)` — and `fillAndPress()` reads the form's own
`method` so that all 35 call sites, GET forms included, wait for the response
they caused instead of guessing how long it takes.

**IT WAS MUTATION-TESTED IN BOTH DIRECTIONS**, which for a timing bug means
making the machine slow rather than making the code wrong: a probe that delayed
every recorded BiDi event by 400ms was installed, the fixed file passed under
it, and the same probe with the wait disabled reproduced the runner's message
byte for byte. A timing fix that has only been seen to pass on a fast machine
has not been shown to fix anything.

**The rule to take from it**: in this file, `readyState`, `driver.get()`
resolving and an element being clickable say nothing about when the network
event describing that navigation reaches this process. Wait for the event.

### `sts_userinfo_protected` — a watchdog that was already fixed, on a branch that had it

**THIS SECTION RECORDS A MISTAKE AS WELL AS A BUG, and the mistake is the more
useful half.**

The bug: `run-report.js`'s per-job watchdog is a flat 300s. That job signs and
verifies twenty-five algorithms, several of them lattice or hash-based, and
under `NODE_V8_COVERAGE` on a two-core runner it takes about eleven minutes —
against roughly thirty seconds for the whole job, uninstrumented, on a developer
machine. A 300s watchdog kills it partway through.

**What made it expensive to read is what it did next.** The killed job left the
throwaway service still working through what it had been given, so `vc_did` —
the job after it — failed with a connect timeout. The run reported TWO failures
of which one was real. **A watchdog that fires on a healthy job does not merely
lose that job; it corrupts the ones behind it**, which is the reason to give it
headroom rather than trim it to fit.

**THE FIX ALREADY EXISTED.** `run-coverage.sh` has passed
`--timeout=${STS_COVERAGE_JOB_TIMEOUT_MS:-900000}` since `d6459da`, *Scale the
coverage run's per-job watchdog to what instrumentation costs* — and that is
where it belongs: instrumentation is what makes a job slow, and the LAUNCHER is
what knows a run is instrumented. `run-report.js` is handed a number and has no
business inferring one.

What went wrong on 2026-08-30 is that `d6459da` was on `main` and not on
`develop`, a manual `workflow_dispatch` was run on `develop`, and the failure
was diagnosed correctly and then fixed a SECOND time — a `COVERAGE_TIMEOUT_FACTOR`
in `run-report.js` that read `COVERAGE` out of the environment and multiplied
the default. It worked, and it was still wrong: on `main` it was DEAD CODE,
because it only fires when no `--timeout=` was passed and `run-coverage.sh`
always passes one. It was removed as soon as that was noticed.

**Two rules come out of it, and the second is the one that cost the time:**

* **The launcher owns the timeout.** A run that needs a different watchdog says
  so on the command line. Nothing downstream of `--timeout=` may infer one from
  the environment, or there are two answers to one question and only one of them
  is read.
* **BEFORE FIXING A CI FAILURE ON ONE BRANCH, CHECK WHETHER ANOTHER BRANCH
  ALREADY FIXED IT.** `main` was eleven commits ahead of `develop` at the time,
  and among them were this watchdog, the `stsFetch` retry in
  `vendored/sts_userinfo_protected.js`, four vendored `xmldsig.js` syncs and the
  worker pool that moves post-quantum signing off the thread owning every
  socket. A failure seen on the branch that is BEHIND is very often a fix that
  has not been merged forward, and `git log origin/develop..origin/main` is the
  whole of the check.

**AND THE ROOT CAUSE HAS ITS OWN FIX, WHICH IS NOT A TIMEOUT.** A job waiting on
this service under coverage is waiting on an event loop blocked by a signature;
`common/worker_pool.js` is the answer to that, and widening a client-side window
is not. `vendored/sts_userinfo_protected.js`'s `BUSY_WINDOW_MS` is a hard-coded
90s and has been seen to be exceeded once on a contended runner even with the
pool in place — but that file is VENDORED, so the fix for it is upstream and a
sync, never an edit here.

**Neither of these is a reason to weaken an assertion.** The gate check still
demands exactly one POST and still demands a refusal; the userinfo job still
drives every advertised algorithm. What changed is how long the harness is
willing to wait to find out.

## What it does not do

No framework, no `describe`/`it`, no assertion library, no `devDependencies`.
The moment this needs a dependency to RUN, it stops being cheaper than the
parent suite and the argument for its existence goes with it.

**THAT SENTENCE SAID "no coverage, no reporter plug-in" UNTIL 2026-08-28, AND
BOTH OF THOSE NOW EXIST — WITH THE RULE ITSELF UNCHANGED**, which is the only
reason they were allowed. `npm test` is byte for byte the run it always was:
`bunyan` and node, nothing added, nothing to install. The report generator and
the coverage renderer are separate entry points in `tools/` that use node
builtins and the same one dependency, and NOTHING requires them.

The coverage renderer is the case that had to be argued rather than assumed.
The obvious answer is `c8`, which is what the parent project renders two of its
three domains with — and it is the wrong answer HERE for a specific reason:
`.npmrc` in this repository carries `omit=dev` and the Dockerfile passes
`--omit=dev` besides (it is what keeps ldapjs's ~200 test packages out), so a
`devDependency` added for coverage would be **silently not installed** by the
ordinary `npm install` and the script would fail for everybody with a message
about a missing binary. So the collection is node's own `NODE_V8_COVERAGE` —
no wrapper binary in the spawn path, nothing for a test to opt into — and
`tools/coverage-report.js` renders V8's data directly. The raw JSON is left in
`coverage/raw/` for anybody who would rather point c8 at it themselves.

**What that report can and cannot say is written at the top of that file and is
worth reading before quoting a number from it.** Function coverage is exact:
V8 counted the calls. Line coverage is DERIVED — a line's count is that of the
innermost V8 range containing its first non-blank character, and a line counts
as code when it is neither blank nor wholly a comment. There are no branch
numbers at all, because V8's block ranges are not branch arms and a percentage
with no definition is worse than none.

## THE CRYPTO REPORT'S GUARD IS IN `tests/vendored/admin_api.js` (2026-08-30)

`/admin/crypto-metadata` claims that every algorithm table on it is READ FROM
THE MODULE THAT PERFORMS THE ALGORITHM rather than written down. That claim is
the whole reason the page is worth having, and it is exactly the kind of claim
that is true the day it is made and quietly false a month later.

It went in `tests/vendored/admin_api.js` — this repository's own file — rather
than in `tests/` here, by the line the root `CLAUDE.md` draws: **every one of
the assertions can be made by driving the running service over HTTP.** Three
things are checked and each answers a different way of the page going wrong:

* **The drift report, in all three directions** — a protocol family this mock
  advertises with no crypto profile, a profile naming a family that is not
  advertised, and a family citing an envelope with no row in the standards
  table. The page reports all three on itself; this is what makes them FAIL.
* **Every coverage note starts `full`, `partial` or `mock`**, the rule
  `sts_metadata.js`'s specification list already follows.
* **Five algorithm lists are compared against the SERVICE'S OWN DISCOVERY
  DOCUMENTS** — the ID Token and UserInfo signing lists, the two JWE lists and
  the DPoP list, read off `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`. **This is the check that makes
  "derived" mean something**: reading the report on its own says nothing,
  because a hand-written list is well-formed too. It needs two doors onto one
  table, and this is the only place in the suite where both exist.

**All three were mutation-tested before they were committed**, which is not
optional here: a renamed family row (caught, naming SCIM in both directions), a
hand-written ID Token list of two algorithms (caught, naming the discovery
document), and a coverage note rewritten to open with "we do all of this"
(caught, naming the `jws` row).

---

## `app_permissions.js` (2026-09-01) — the line drawn at "choosing the graph"

Most of the delegated-permission feature is NOT in this directory, and that is
the line this file exists to draw. That a permission must be defined before it
is granted, that a base URI is normalised, that an ungranted scope is refused
`invalid_scope` when the setting is on, that a grant lands on the CLIENT's entry
and not the resource's — every one of those can be driven against the running
service, and `tests/vendored/sts_admin_api_operations.js` drives all five
operations and reads them back through two different doors.

Two halves cannot be driven, and they are what is here:

* **CHOOSING THE GRAPH.** The states worth asserting are ones a running service
  will not produce on demand: a DANGLING grant (a permission removed from under
  one), and an application granted its OWN permission — which
  `updateApplication()` refuses through both console doors, so only an
  `ldapmodify` can write it. Reaching either over HTTP would mean driving the
  LDAP socket to build a state the API exists to prevent and then parsing
  geometry back out of an SVG. The parsing is the same either way; what cannot
  be done over there is choosing the graph. Same argument as
  `delegation_map_bands.js` and `user_graph_signin.js`.
* **THE PURE FUNCTIONS.** `base + name` and `name|description` are string rules
  with edge cases no request can reach: a description containing the delimiter,
  a base already ending in `#`, a base written by hand and therefore not
  normalised.

**THE GROUPINGS JOINED IT ON 2026-09-02 AND THEY ARE THE SAME LINE AGAIN.**
`app_permissions.clusters()` partitions the register into sets of applications
that can be reached from one another by following grants with the direction
IGNORED, and `/admin/delegation/cluster` draws one of them. The list operation
and the drill-down are driven over HTTP — the generic GET walk in
`sts_admin_api_operations.js` reaches `GET /admin-api/permissions/groups`, and
`sts_delegated_permissions_example.js` asserts that its ring of five is ONE
group — so what is here is only what those cannot reach:

* **THE DIRECTION DECISION NEEDS A REGISTER THE SERVICE WILL NOT BUILD ON
  DEMAND.** The shape that tells *ignore the direction* from *follow the
  arrows* is TWO CLIENTS OF ONE RESOURCE: following the arrows, the second
  client is reachable from the first only by walking a grant backwards. A RING —
  which is the fixture over there, and the one an example wants — is connected
  whichever way you walk it and cannot tell the two apart at all.
* **AND THE THREE GROUPS OF ONE ARE `app_permissions.js`'s OWN STATES.** A
  dangling grant and a self-grant are two of them, and both are the "choosing
  the graph" argument above, unchanged.

**It was mutation-tested against five mutants before it was committed**, as the
rule here requires: dropping the base-URI separator, a configured box claiming
an act (which would draw every grant in the refusal colour), the `may-reach`
look ignoring whether the grant was ever asked for, a self-grant drawing a loop,
and a dangling grant drawing a line. Each was caught.

**The partition was mutation-tested against nine more, and one of them
survived** — which is the part worth writing down. Caught: joining only one way
round, naming a group after the union-find root, dropping the resources with no
grants out of the membership universe, joining a dangling grant to its
permission identifier, counting every grant as a line, sorting smallest-first,
filing only granted permissions, and a `clusterFor()` that case-folds. **The
survivor was a `join()` that moved a node only while it was still its own
root** — a first-write-wins union — and it survived because the original fixture
had no client holding permissions on TWO resources, which is the only shape that
reaches the second write. The fixture grew one and the mutant was then caught.
The lesson is the one this directory keeps relearning: a mutant that survives is
usually telling you about the FIXTURE and not about the assertion. A tenth was
written and thrown away rather than counted: filing each grant under its
RESOURCE's group instead of its client's is behaviour-preserving, because the
two are in one group whenever there is a resource at all — an equivalent mutant
is not a hole, and counting one would inflate the number this paragraph is
for.

**It touches no process-wide state** — every graph it draws is built in the
file — so the restore rule does not apply to it.

---

## `user_graph_permissions.js` (2026-09-02) — the same line, read the other way

`app_permissions.js` above is about the CONFIGURED register. This is about an
ISSUED TOKEN read against it: `/admin/delegation/allowed` draws a `may-reach`
line carrying the permission it is a grant of, and the pictures drawn from what
actually happened draw the same `reaches` relation from a token and carried the
mechanism, a credential count and nothing about the permission. So the one
picture showing what a client DID was the one that could not say what it did it
WITH. `common/user_graph.js`'s `permissionsAddressedTo()` is the rule that
closed that; this is its guard.

**The end-to-end claim is deliberately NOT here.**
`tests/vendored/sts_delegated_permissions_example.js` builds five real
applications and spends a real token against them, which is what proves the rule
reaches a page. Three things cannot be driven over there and every case in this
file turns on one — all three are `app_permissions.js`'s "choosing the graph"
argument said about a different register:

* **an audience NOBODY answers to**, which is what a real resource server looks
  like here and which the picture has to draw without inventing a permission for;
* **a scope value that looks like a permission and is not** — `read` against a
  resource that defines no `read`, which the token endpoint will not produce
  against a resource that does;
* **a resource carrying permissions and NO BASE URI**, which `permissionsOf()`
  gives an empty identifier on purpose and which `updateApplication()` refuses
  from both console doors, so only an `ldapmodify` writes it.

It asserts the MODEL and the RENDERER together, for `user_graph_signin.js`'s
reason: the fold putting the array on the edge while the label drops it, and the
label drawing a line the fold never fills, are both green in a test that looks at
one of them.

**It was mutation-tested against NINE mutants and each was caught**: the
`forPermissionBase()` lookup dropped from the resolver (3 assertions red), the
intersection removed so every scope value is reported as a permission (7), that
lookup comparing the entry's raw base instead of the normalised one (1), the same
lookup's empty-base guard removed so it answers with the first entry that has no
base (2), an empty permission list drawn as a blank line instead of `default
permissions` (1), the four-line label cap put back to three (1), the audience
block put back inside `if (holder)` so a client_credentials token draws no
resource at all (13), the edge seeding no `permissions` member so the renderer
cannot tell a token line from an act line (1), and the fold taking the last
credential's answer instead of the union across the line (1).

**Two of those survived the first round and are the reason the file is longer
than it was.** The raw-base mutant passed because every fixture entry held a
base written the normalised way, so only the value ASKED FOR was ever being
normalised — the entry that an `ldapmodify` wrote the other way is the case that
matters and there was none. And the empty-base mutant passed because
`permissionsAddressedTo()` returns early on an empty audience, so the guard
inside the lookup was never reached from there; it is asserted against
`applications.forPermissionBase()` directly now. **A guard reached only through
a caller that already refuses is a guard that has not been tested.**

**It restores `applications.setDirectory()`.** The registry's store is one
reference for the whole process and every later file in the run reads through it,
so a fake left installed would answer every subsequent question about
applications with this file's four entries.

## `consent.js` (2026-09-01) — and the half of that feature that IS over HTTP

The line this directory is on is *can it be asserted by driving the running
service over HTTP?*, and most of the consent feature can: that the screen is
drawn, that Allow issues a code and Deny returns `access_denied`, that
`prompt=none` answers `consent_required`, that a global consent suppresses the
prompt for a real sign-in. All of that is `tests/vendored/sts_consent.js` and is
not here.

What is here is the three things that CANNOT be:

* **THE VALUE GRAMMAR.** `<when> <scope> <client_id>` is a string rule whose
  whole justification is an edge case no request can produce on demand: a
  client_id containing a SPACE or a `|`. The rule is that the client_id is LAST
  and takes the remainder, and the only way to show it holds is to write such a
  value and read it back.
* **THE PRECEDENCE.** Which of three answers covers a scope — the person's own,
  the application's override, or neither — is a pure function of two attribute
  sets. Producing all six combinations over HTTP would mean six sign-ins, six
  directory writes and a race against the clock in the timestamp; here it is a
  stub and six assertions.
* **THE STATE ONLY AN `ldapmodify` CAN WRITE.** A value on somebody's entry that
  is not in the shape this service writes. Both console doors and the management
  API produce well-formed values by construction, so reaching it over HTTP would
  mean driving the LDAP socket to create a state the API exists to prevent.

**IT FILLS TWO SLOTS AND IS THE FIRST FILE HERE TO FILL `consent.setDirectory()`.**
`applications.setDirectory()` needs `readApplication` as well as
`allApplications` — this feature reads ONE entry by identifier where
`user_graph_permissions.js` only ever walks the container, and a stub short by
that member throws inside `load()` rather than answering "no such application",
which is a failure that names `applications.js` and has nothing to do with it.

**THE ONE ASSERTION TO READ FIRST** is the BOTH-WAYS case: a scope covered by
the override AND by the person's own answer must report as the person's,
because that is the fact that survives the override being taken away. Reporting
it the other way round would make `revoke-global-consent` look as though it had
started asking people who had already agreed.

## RESTORE A SETTING WITH `reset`, NOT BY WRITING THE OLD VALUE BACK

A job that changes an appconfig setting must put it back through
`POST /admin-api/config/reset`, not with a second `set` carrying the value it
read first. **The two do not leave the same state.** A `set` leaves the row
reading `source: override` even when the value is identical to the default, and
`vendored/admin_api.js` asserts that a row nobody has overridden does not say
that — so restoring by writing back passes in the job that did it and fails the
next job in the run, naming a setting that file never touched.

This is the same shape as the slot rule below and the throwaway-realm rule
above: **this service holds everything in memory and never restarts between
jobs**, so anything a job leaves behind is another job's starting state. It is
also why the counters those jobs assert are read as DELTAS rather than as
absolute numbers — a test that only passes when it runs first is a test that has
to be scheduled.

## RESTORE THE SLOT YOU STUBBED — WITH WHAT WAS THERE, NOT WITH `null`

`run.js` runs every file in ONE process, so `applications.js`'s directory slot
is one reference shared by all of them. Two files stub it to answer without a
directory, a socket or a realm, and until 2026-09-04 one restored `null` and the
other restored nothing at all.

Both were fine by accident. The files that need a REAL backing —
`federation_map_bands.js`, `realm_directory_lookups.js` — were the first to
require `ldap/ldap_server.js`, whose require-time `setDirectory()` repaired the
damage on the way past. The moment any earlier file required that module (which
`caep_initiating_entity.js` does, through `logout/logout.js`), node's module
cache meant it was not required again, the repair never happened, and two tests
failed **inside `common/applications.js`** naming a function a stub in a third
file does not have.

The lesson is the general one and it is why this is here rather than in a
comment: **a test that leaves process-wide state behind is a test whose failure
lands on somebody else's file**, in a run whose order it does not control. And
restoring a *plausible* value is not restoring: `null` is right only in a
process where `ldap_server.js` was never loaded, which is a fact about the file
list rather than about the test. `applications.directoryInstalled()` exists so
the honest restore is available; it is called by nothing in the service.

## `roles.js` and `sts_roles.js`: the same feature, split on the usual line

They landed together on 2026-09-05 and the split between them is the cleanest
illustration of this directory's one rule — *can it be asserted by driving the
running service over HTTP?*

**`tests/roles.js` is in process because five of its assertions have no HTTP
shape at all.** A gate with NO DECIDER installed (which is what `npm test`, the
parent's in-process Kerberos jobs and the remote PEP container all are, and the
state in which every issuance must be ALLOWED); a decider that THROWS, which
must also allow, because an authorization subsystem that bricks a mock by being
half-loaded is the worst thing to put in front of one; the three shapes an
incoming roles claim can take; a directory that throws under a lookup; and the
six built-in roles answered across their four contexts. A running service cannot
be asked to have no decider — that is a property of how the process was started,
which is the same line `config_realm_layer.js` and `crypto_module.js` sit on.

**`tests/vendored/sts_roles.js` is a protocol job and is THIS repository's own**
(`local: true`), for the third reason `sts_consent.js` gives and at its widest:
every assertion in it spans an AUTHORING door and a DECIDING door. A role is
made on `/admin-api/roles`, an application is narrowed on
`/admin-api/applications`, and what that changes is what `/oauth2/token`,
`/oauth2/authorize`, `/wstrust`, `/wsfed` and both SAML profiles answer. A test
with the two halves in two repositories could not make the assertion that
matters.

### It runs in a throwaway realm, and the reason is sharper than tidiness

`ou=roles` and `ou=applications` are both per realm, so a realm of its own gives
the job a register whose entire contents it wrote — which is what makes "alice
holds exactly one role" an exact claim rather than "at least one".

**But the load-bearing reason is that this feature REFUSES people.** A job that
narrowed an application in the DEFAULT realm and died before clearing it would
leave every later job in the run signing in to a service that turned them away,
and the failure would name the wrong file. Inside a realm nothing it does
reaches anything else, and removing the realm takes the roles, the applications
and the settings with it. `roles.enforceIssuance` is turned off and on inside it
for the same reason — it is process-wide at the top level and realm-scoped
there.

### Mostly negatives, and one of them is about the ERROR CODE

A service that issues a token to somebody who holds the role looks finished and
can be worth nothing: it is what an unmodified service does for everybody. What
is worth asserting is that somebody is REFUSED, that the refusal is in the
protocol's own words, that the person beside them is not refused, and that
clearing the requirement lets them back in — the only shape that distinguishes a
working gate from a service refusing for some other reason.

The one to keep when editing it: the token endpoint's refusal is read as the
RFC 6749 error CODE (`access_denied`) and not as a 400. A gate that works and a
handler that has fallen over both produce a 400, and only the code tells them
apart.

It carries a FLOOR on its own check count, for `sts_admin_console.js`'s reason:
a section that stops being called takes its assertions with it and the run still
says "passed", which is the one failure mode a suite cannot report about itself.
Mutation-tested against eight mutants before it was committed.
