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

**THE JOBS MARKED `local: true` IN THAT MANIFEST ARE THE EXCEPTION, AND
THE RULE IS EXACTLY INVERTED FOR THEM.** `sts_metadata.js`, `admin_api.js`,
`sts_admin_api_operations.js`, `sts_admin_console.js`,
`sts_delegated_permissions_example.js`, `sts_consent.js`,
`sts_xacml_endpoints.js`, `sts_xacml_editor.js`, `sts_xacml_remote_pep.js` and
`sts_roles.js` among them drive this
service's OWN `/admin` console and its `/admin-api`. **THE MANIFEST IS THE
COUNT AND THIS SENTENCE IS NOT** — it used to open by naming a number, and the
number went stale twice before anybody noticed, which is the drift a manifest
exists to stop. The first four ran from the parent's
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
a throwaway realm (which nothing removes any more — see *No job removes a
realm* below, 2026-09-06). That is not an oversight and
it is not a precedent: what the job produces IS the deliverable, an example
meant to be read at `/admin/delegation/allowed`, drawn there, and — since
2026-09-02 — listed under that drawing as ONE GROUP, whose own picture is at
`/admin/delegation/cluster?application=abcapp1`. A realm deleted on the way out
is an example nobody can open — an argument the whole directory has since come
round to. What pays for it is that the job is IDEMPOTENT — the
identifiers are fixed, so it forgets every previous `abcapp*` before creating
anything — that nothing else in the suite asserts an application COUNT, and
that it runs after `sts_admin_console.js` so the console's own coverage walks
the console it has always walked. **A second job wanting the same exemption
needs the same three sentences**, not a reference to this one.

**AND THREE ASKED FOR IT AND WROTE THEM (2026-09-06).** The
`sts_directory_bulk_load_*.js` jobs each create 5000 people, 50 groups and 5000
memberships in the DEFAULT realm and delete none of it. Their three sentences
are their own and are in `sts_directory_bulk_load_scim.js`'s header rather than
here: the MEASUREMENT is of a directory that already holds thousands of
entries, which a fresh realm is by definition not; the ENTRIES are the
deliverable, because a job that deleted them would leave a number in a log and
nothing to check it against; and every name they invent carries the DOOR and
`names.runStamp()`, so three jobs in one suite and two runs of the suite never
meet. What pays for it, as with the example above, is the ORDER — they are last
in `MANIFEST.js`, so every job that walks a page or reads a register has run
before the store grows — and that nothing in the suite asserts a directory
COUNT. **They are also the only jobs that raise their own watchdog**
(`timeoutMs` in the manifest) and the only ones that leave a SETTING changed:
`ldap.maxEntries`, which each raises for what it is about to add and none puts
back, because a ceiling restored under fifteen thousand new entries is a
service that refuses the next create by anybody.

**THERE ARE THREE OF THEM BECAUSE THERE ARE THREE DOORS, AND THE POINT IS THE
COMPARISON.** One job that wrote its people through `/admin-api` and its groups
over SCIM measured a mixture and could not be compared with anything, including
itself. The three now drive SCIM, the raw LDAP socket and the management API
respectively, everything they share is in `tests/vendored/bulk_load.js`, and a
difference between their numbers is a difference in the door. What they do NOT
share is the door itself: not one line of that module opens a socket or knows
what a SCIM resource looks like.

**THE THREE `users.create` ROWS ARE NOT DIRECTLY COMPARABLE AND THE REPORT SAYS
SO ON EVERY ONE OF THEM.** The jobs run one after another against one directory
that nothing deletes from, so each starts against a bigger store than the last
— and **a create here is not constant-time in the size of that store**. Within
the SCIM job alone it went from 9ms at the five hundredth person to 54ms at the
five thousandth. That is itself the most interesting thing these jobs measure,
and it means reading the three tables side by side as "LDAP is faster than
SCIM" would be reading the store's growth as a property of the door.
`directoryEntriesBefore` is on each report for lining them up; **the membership
rows are the comparison that holds** — a membership write touches one group
entry whose size is the same in all three runs, and there the doors differ by
two orders of magnitude (LDAP 0.15ms, `/admin-api` 0.97ms, SCIM 28ms) for
reasons that are about the door. One job against a freshly started mock is how
to compare like with like.

**WHAT SPLITTING THEM COST WAS TWO OPERATIONS AND A COMPOSE FILE**, and both
are worth knowing because neither is about testing:

* `POST /admin-api/groups/create` and `POST /admin-api/groups/add-member` DID
  NOT EXIST. `/admin-api/groups` was a read, `/admin/groups` was a read, and
  the only two doors onto a group in this directory were an `ldapadd` and
  `POST /scim/v2/Groups`. **Rule 7 could not have found that**: it is a parity
  check between the console and the API, and it is satisfied exactly when both
  are missing. Writing a job named "through the management API" and finding it
  could not be written is what found it.
* `tests/docker-compose-ldap.yml` publishes 389 for the test stack and for
  nothing else. `./docker-run-tests.sh` needs none of it — its runner is a
  container on the bridge with the service — but `./local-run-tests.sh`'s
  runner is a host process, and `docker-compose.yml` deliberately publishes
  neither 389 nor 636, because the host most likely to want a mock directory is
  a host already running slapd. That launcher picks a free host port with the
  same `freePort()` it uses for 8081, layers the override, and exports
  `STS_LDAP_URL`. The THIRD arrangement is the throwaway service
  (`--no-docker`, and every coverage run), where `run-report.js` builds the URL
  from `instance.ports.LDAP_PORT` — by NAME rather than `base + 5`, so a
  listener added to that block in the middle cannot silently move it.

**THE SUITE TRIPPED THE RATE LIMITER UNTIL 2026-09-06, AND THAT IS WORTH
KNOWING BECAUSE OF WHAT IT LOOKED LIKE.** `security.rateLimitPerAddress` ships
at 20 per 60s and **every job here comes from one address** — the runner — so
the address bucket counted the whole suite as one caller. `sts_portal_sessions`
and `sts_admin_console` each issue and open several activation links, the
address bucket is not cleared by an activation that WORKS the way a sign-in's
is, and both jobs failed with **429 on a link the console had just handed
over** — which reads exactly like a broken handler and is not one. It was an
ORDERING artefact too: re-running either job alone passed, because the window
is only sixty seconds.

The fix is in the three appconfig files these stacks read — 500 per address,
100 per identity, against a measured peak of 25 — and NOT in `env/defaults.js`,
which still ships 20 and 5. `env/CLAUDE.md` carries the measurement and the
argument for that placement. **`tests/rate_limiter.js` is what the change
owed**: the limiter was tested by nothing, the suite's own 429s were the only
thing exercising it, and raising the limit without that file would have turned a
security control off where nobody would notice.

**AND IT FOUND SOMETHING IN ITS FIRST MINUTE, WHICH IS THE ARGUMENT FOR IT.**
A search matching more than `ldap.sizeLimit` (500) returned its five hundred
entries and then **no result message at all** — the size-limit branch of the
search handler ended with a bare `next()`, so no `SearchResultDone` was ever
sent and every client waited for ever on an idle connection. The log line, the
audit row and the comment above the branch all said result code 4 was being
returned; nothing returned it. It had been that way for as long as the handler
had existed, and it needed both halves of this job to see: five thousand
entries, because the seeded directory holds twenty-six, AND the raw socket,
because every other reader of this directory comes in over HTTP.
`ldap/CLAUDE.md` writes it up. **The same ldapjs gotcha bit the test** — a
search that ends in a non-success code emits `error` and NEVER `end` — so its
search helper settles on either and carries a deadline of its own, because a
promise that can hang is the one failure a suite cannot report about itself.

**THE LDAP JOB IS NOT MARKED `docker: true` AND THAT IS DELIBERATE.** That flag
is for a job needing a DAEMON, and this one needs a PORT. Run with neither
launcher and no `STS_LDAP_URL`, it FAILS on its own connect, naming the
variable and both launchers — it is never skipped, because the socket is the
thing under test and a job reporting green having driven nothing is worse than
one that is honestly absent.

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

| A test that needs A SECOND CONTAINER on this service's own docker network, and drives the seam between them | `tests/vendored/`, marked `local: true` **and `docker: true`** | **There is exactly one, and it is `sts_xacml_remote_pep.js`.** BOTH LAUNCHERS bring a remote XACML PEP up as part of their stack and hand it `XACML_PEP_URL`, `XACML_PEP_NAME` and `XACML_PEP_REALM`; it creates the realm that container has been polling, deploys policy through `/admin-api/xacml`, and asserts that what THAT container allows and refuses changes with it. The parent suite drives a URL; it has no way to say "put this other image on that network, then ask it". It answers the console question above as well, so both arguments put it here |

There was a second row until 2026-08-26 — *an INTEGRATION test that needs
several copies of this service*, which was `../federation-e2e/` and its own
three-container stack. **TRUST REALMS closed it.** A realm is a whole logical
copy of this service on the same socket under a path prefix, so several copies
is one process now and the parent suite can reach the whole topology over HTTP:
that test is `tests/federation_sso.js` over there. Check whether realms already
answer the question before re-opening that row.

**The row added above is NOT that row coming back, and the difference is worth
keeping straight.** A realm is another copy of THIS service, and that is why
several copies of it stopped needing several containers. `xacml-pep/pep.js` is
a DIFFERENT PROGRAM — a second implementation of one half of a protocol, with
its own engine, its own memory and no realm at all — and no number of realms
produces one. That is the test to hold a future candidate against: if the
second process would be another mock, it is a realm; if it would be something
else, it is this row.

**AND IT IS A CONTAINER RATHER THAN A CHILD PROCESS, WHICH WAS A CORRECTION
RATHER THAN AN ELABORATION.** That job spawned `node xacml-pep/pep.js` on the
machine running the suite for one day. It asserted the PROGRAM and it quietly
did not assert the DEPLOYMENT, and the gap was not academic — six things are
only true of the container, and each is a way the feature can break while a
host run stays green: the image is BUILT from this tree (so the Dockerfile's
seven-module COPY set is executed and not merely compared as text); the PEP
resolves the PDP by COMPOSE DNS rather than a published port on localhost; it
VERIFIES that certificate, issued for that name, with an anchor copied in; the
PDP can actually DELIVER the nudge across the bridge, which is this
repository's third outbound request and had no test against a real listener
anywhere; `docker cp` puts a client certificate where `pep.js` reads one, so
the registration is a real mutual-TLS handshake between two containers; and the
unit that dies is a container with a log, which every failure message quotes.
**Mutation-testing the two versions is the argument in one line**: dropping
`xacml_functions.js` from `xacml-pep/Dockerfile` is invisible to a host run —
the module is one directory up and always there — and kills the container at
load in 2.6 seconds.

**THE LAUNCHER OWNS THAT CONTAINER, AND THE REASON IS THE CONTAINERIZED
RUNNER.** `./docker-run-tests.sh` puts the suite INSIDE a container with no
docker socket in it, deliberately — that file argues why where it also excludes
the parent suite's postgres job — so a job that started its own PEP could never
run in the stack that gates this repository. Both launchers therefore bring one
up beside the service and hand the job three variables; the job shells out to
nothing at all, and **the same test runs in both stacks**.

It needs a docker daemon only when NEITHER launcher is involved — a bare
`node tests/tools/run-report.js`, or a coverage run, both of which drive a
service that is a plain process with no compose network to join. There the job
builds the image and starts a container of its own, and where there is no daemon
`tools/run-report.js` reports it SKIPPED with the reason — amber in the report,
`<skipped>` in the JUnit, a named line in the summary saying what is therefore
unchecked. That is the one skip in this directory and it is a narrow one: an
intended job that did not run is otherwise a FAILURE here, and the exception is
for something deliberately left out.

**THE CONTAINER IS POINTED AT A REALM THAT DOES NOT EXIST WHEN IT STARTS**, and
that is the arrangement rather than a defect: `PEP_PDP_URL` is decided when the
stack comes up, minutes before the job runs, and the realm is the job's own. So
the container fails to register, fails to pull, says so, and keeps trying —
which is why `xacml-pep/sync.js` retries its registration on the poll timer.
**That retry was written for this and is right independently of it**: before it,
a PEP that came up before its PDP, or survived a PDP restart it started during,
enforced correctly for ever while appearing on nobody's console. The job asserts
it took more than one attempt, so the retry is covered by the arrangement that
needed it.

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
./local-run-tests.sh                 # EVERY job, with a report written —
                                     # the service in a container built from
                                     # this working tree
./local-run-tests.sh --no-docker     # the same, with the service run on this
                                     # machine
./local-run-tests.sh --keep-stack    # leave the container up afterwards
./local-run-tests.sh --no-protocol   # only the in-process files
./local-run-tests.sh --only=crypto --open
./local-run-tests.sh --vendor-check  # is tests/vendored/ still in sync?
./local-run-tests.sh --vendor-sync   # re-copy the parent's files over it
./docker-run-tests.sh                # the same jobs with the RUNNER in a
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
It writes `tests/report/<mode>/<timestamp>/` — `report.html`, JUnit
`report.xml`, `summary.json` and one log per job — and points
`tests/report/<mode>/latest` at it. Both are gitignored. **The `<mode>` segment
is the mode matrix's and both launchers pass it as `--report-dir`**, so the
bare `tests/report/latest` is not any current run's report; three places named
it anyway until 2026-09-07 (both launchers' log capture, and the CI workflow's
upload, which had therefore been uploading nothing at all).

**TWO FILES IN THAT `logs/` DIRECTORY ARE THE LAUNCHER'S RATHER THAN THE
RUNNER'S, AND BOTH RECORD SOMETHING THAT IS GONE BY THE TIME THE REPORT IS
READ.**

| File | What it is | Where it comes from |
|---|---|---|
| `logs/00-mock-sts-service.log` | the mock's own account of what it issued | `run-report.js` writes it in `--no-docker` mode, where it started the service itself; otherwise the launcher takes it out of `docker compose logs sts` before the teardown removes the container |
| `logs/00-test-runner.log` | **the RUNNER's own output** — which jobs it chose, the ones it could not start and why, the reason a job was reported SKIPPED, the summary | `./docker-run-tests.sh` takes it out of `docker compose logs tests`, because there the runner IS a container; `./local-run-tests.sh` tees it, because there it is a node process |

**THE SECOND ONE IS NOT THE JOBS' LOGS AND THAT IS THE WHOLE REASON IT EXISTS.**
`logs/NN-<job>.log` holds the JOB's output, so **a job that never started has no
file there** — and a run in which something could not start is exactly the run
somebody comes back to a report for an hour later. Until 2026-09-07 what the
runner said about it lived in a terminal and in nothing else, which for
`./docker-run-tests.sh` meant a container that was removed at the end of the
run.

Where a mode could not write a report at all — it died bringing the service up —
both files fall back to `tests/report/<mode>-00-*.log`, named for the mode so
that three modes falling back are three files. That is precisely the run whose
logs are the only evidence there is.

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
| `realm_isolation.js` | that a realm's identity register, its revocation set and — since 2026-09-06 — its SCIM traffic counters are its own, in both directions, and that removing a realm takes them with it. **The third store is here rather than in a file of its own because this file's header asks for it**: `admin_stats.js`'s `scimCounts` was a plain object for the same reason the other two were, and that reason (the directory is shared) expired on 2026-08-25 |
| `realm_directory_lookups.js` | that a lookup BY DN answers about one realm — groups, people and applications — including that a refused cross-realm delete leaves the entry where it was |
| `delegation_map_bands.js` | that the delegation picture is TWO BANDS — the issuer above, centred, every party on one plane — and that no two edge labels are drawn on top of each other |
| `federation_map_bands.js` | that the federation picture is THREE BANDS — left asks, right authenticates — that the four relationship states are four distinguishable strokes, that a brokered partner is ONE arrow which keeps that pair's counts, and that the per-application counts either add up or report the difference |
| `spnego_identity.js` | what a SPNEGO sign-in claims: which part of a Kerberos principal becomes the session's username, and the `amr`/`acr` read off the ticket's own flags |
| `ldif_codec.js` | that every value this service can put in an attribute survives the RFC 2849 round trip `persistence.mode=ldif` writes — the base64 rules, the folding, `origin` riding as a comment, and a URL-valued attribute being refused rather than dereferenced |
| `postgres_schema.js` | that `postgres/schema.sql` and `persistence/persistence_postgres.js` hold the SAME schema, and that the role the script creates cannot change it. The DDL is written down twice on purpose since 2026-09-06 — an OWNER builds the store, and the role this service dials with holds four verbs on the rows and no `CREATE` on the schema — so this file compares the two `CREATE` lists in both directions, checks that the version row the script writes is the driver's `SCHEMA_VERSION`, and reads the grants: exactly `SELECT, INSERT, UPDATE, DELETE`, no `GRANT ALL`, no `TRUNCATE`/`REFERENCES`/`TRIGGER`, and a `REVOKE` of `CREATE` that is not merely an absence of a grant — PUBLIC holds it on `public` before PostgreSQL 15. It also pins the role NAME across the three files that spell it, because a connection string cannot be built out of the variables beside it. **In process because every claim is a comparison between two FILES in this repository**, which no running service could be asked — the same shape as `xacml_pep.js`'s Dockerfile COPY-set check. The failure it exists to prevent is quiet: a column added to the driver and not to the script gives a database one column short and a service that is not allowed to add it, arriving as a permission error naming neither the column nor the file |
| `appconfig_persistence.js` | that a setting change reaches the store ON DISK, comes back the way the next start puts it back, and that a realm's settings and the process's are two different files |
| `minted_persistence.js` | **what this process MINTS across a restart, in product mode** (2026-09-06). That the journal names exactly the keys that moved and no others — including `push` and `shift`, which a Proxy over a real array does not see unless the mutating methods are wrapped, and which is how the audit ring is written; that every row is SEALED and the plaintext is not in the stored form; that a restore puts a session back and does NOT bring back a key that was deleted; that a restore leaves nothing for the next flush to write; **that another process's counter reaches the fan-in and never this process's own tally**, which is what stops the counts doubling on every restart; that retention DELETES rather than merely skipping; that development mode journals and writes nothing at all; and that the `ldif` store is refused with a reason. In process because every one of those is correct on every endpoint for the whole life of the process that got it wrong — the damage appears on the next start, in a different process |
| `replication.js` | **several processes against one store** (2026-09-06), and the four ways it goes wrong silently: applying your OWN writes (an exchange that never ends, with both services answering correctly throughout), applying OUT OF ORDER (the loser of a race wins on the reader, and nothing errors), advancing the high-water mark PAST a failure (a permanent gap nothing names), and ONE BAD ROW WEDGING THE PAGE (converging stops while the status still says coordinating). Plus an unknown change kind skipped rather than fatal, which is the ordinary case in a rolling upgrade, and **the apply running inside the change's own realm** — the single most likely bug in the feature, because an apply outside a realm context puts one realm's session in another silently. In process because none of it can be asked of a running service and reproducing it against a real database would mean two containers and a race |
| `user_graph_permissions.js` | that a blue `reaches` line drawn from a TOKEN names the delegated permissions on it — both spellings a client may use, the `default permissions` fallback, the intersection that keeps `openid` off the label, and that a `reaches` line out of the delegation register says none of it |
| `xacml_pep.js` | **phase five, and the only file here that spawns a CHILD PROCESS.** **Since 2026-09-06 it also holds THE VERSION THAT CONTAINER REPORTS, in source-tree form**: that the Dockerfile copies `VERSION` and `common/version.js` and stamps them, that `pep.js` COMPUTES its `VERSION` rather than assigning a literal (it was the hand-written `'mock-sts xacml-pep, phase five'` — a Version column on the PDP's console that could not change), that it resolves the module across both layouts, and — the assertion that guards a DECISION rather than a defect — that **exactly one COPY writes into the image's `./common/`**, because a second file beside the thirty-line shim turns "the shim is the evidence" into "the shim plus whatever else we put there". The over-HTTP half, that the value survives a registration, mutual TLS, a directory attribute and a read-back onto the PDP's row, is `tests/vendored/sts_xacml_remote_pep.js`. That the XACML engine loads in `xacml-pep/` against a thirty-line helpers shim with NOT ONE of this service's own modules in its `require.cache`, and reaches the same decision there as here on the same policy — which is what makes "the engine is a library with no I/O" a checked claim rather than a comment at the top of seven files. That the container's Dockerfile copies exactly the modules `engine.js` loads, in order, which is this repository's own version of the parent project's standing COPY-set obligation, enforced rather than remembered. That the two implementations of section 7.2 agree over seven decisions under both biases — **and that the two biases disagree somewhere**, so the agreement is a comparison rather than two functions that both say yes. Plus the sync token being a digest of what would be SENT (a policy edited and edited back gives the ORIGINAL token, where a modification stamp would not), and the register's four decisions that each prevent a wrong reading. **A child process rather than a require, and that is not a preference**: `engine.js` primes `require.cache` so the host run and the image run load the same shim, and `run.js` runs every file in ONE process — so a require here would hand that shim to `xacml_service.js` next. **It asserts nothing about a RUNNING PEP and never did** — no registration, no pull, no HTTP at all; `xacml-pep/sync.js` is not loaded here. That half is `tests/vendored/sts_xacml_remote_pep.js`, which starts the program |
| `api_sessions.js` | **two claims.** First, that `ISSUANCE.SESSION` is asked at the FUNNEL — `startSession()` — and not at one door: it was asked only at this service's own sign-in screen while five other paths minted a session and never asked (a federated assertion, a SPNEGO ticket, a client certificate, a WS-Trust UsernameToken, the WebAuthn funnel), so an application narrowed to a role refused a password sign-in and admitted the same person through any of them. It pins that a refusal returns NULL and does not THROW — two callers wrap that call in a `try` that treats a failure as bookkeeping, so a thrown refusal would be swallowed and the session started anyway — that `gated: true` opts the one door that already asked out of being asked twice, and that a sign-in naming no application is allowed even when the decider refuses that very person, which is the existing rule and what keeps every caller unaffected. Mutation-tested against removing the gate and against throwing instead of returning null. Second, that the management API, SCIM and the SPIRE Server API sign in through **the one session store** — `authn.startSession()`, the same map browser sessions live in — with ONE ROW PER CREDENTIAL rather than one per request: twenty-six calls with the same fingerprint are one session, a different fingerprint is a different one, both appear in `logout.liveSessions()` and a global sign-out ends them through the same `terminate()`. **A register of their own was the obvious implementation and is what this file exists to prevent**: two answers to "is somebody signed in", with the wrong one being whichever surface a reader happened to look at (rule 3m). It also pins that one store does not mean one kind of ROW — an API session is drawn by its own surface, carries the fourth expiry rule (the only one extended by use) and reports calls rather than the relying parties a browser session carries — and, last so nothing above could pass by making every session an API session, that a browser session is exactly what it was |
| `xacml_service_own.js` | that the two policies this service decides its OWN boundaries with — `role-issuance` at the nine issuance sites and `access-control` at the five gated surfaces — are reported by the console, in four states: no override (both BUILT IN and both deciding, which is why neither has ever been in the editor's chooser), an enabled override (the stored document wins), a disabled one (neither falls back), and deleted (the built-in returns). **It is in process because two of those states are reached by DISABLING the override**, and disabling `role-issuance` takes issuance policy out of the decision for the whole service — over HTTP that is a change every other job in the run would meet. It found the sixteenth defect in `xacml/CLAUDE.md`'s list: `accessPolicy()`'s `typeof repository.get === 'function'` guard was false on every call, so `xacml.accessPolicy` had never once been honoured. Mutation-tested against both spellings of it — the assertion that catches a condition nothing ever satisfies is the one about the state FLIPPING when an override is created, not one about any single value |
| `xacml_monitor.js` | **the decision counters behind `/admin/xacml/monitor`, and the two distinctions a single number would lose.** That a NotApplicable which was REFUSED is counted as a refusal and NOT as a Deny — `allowed` is not `permit`, because what maps between the four decisions and the two outcomes is the PEP's bias; and that a Permit the PEP refused for an obligation it could not discharge is section 7.2 working rather than a contradiction. That `POST /xacml/pdp`'s row has `allowed` and `refused` **null rather than 0**, because this service produced that decision for somebody else's PEP and never saw the enforcement. That `allowed + refused + unenforced == decisions` on every row — the assertion the `unenforced` figure exists for, since a total that does not add up makes a reader distrust every other number beside it. **In process because two of the cases cannot be reached over HTTP at all**: a decision value the catalogue has never heard of, and a counter whose input throws. The second found a defect in its first run — `record()` incremented `decisions` and THEN read the outcome, so a throw left the row permanently one short with nothing to say why; the reads happen before any write now, and a throw records NOTHING |
| `scim_monitor.js` | **the traffic counters behind `/admin/scim/monitor`, and the three claims that page makes which nothing else would notice going wrong.** That a caller the GATE REFUSED is in no client row even when the credential carried a name — the assertion passes a principal WITH a refusal on purpose, because attributing traffic to an identity this service declined to believe is the one mistake there that would matter, and Basic and Digest both put a name on the wire. That an ABSENT MEASUREMENT IS NULL AND NOT ZERO: a success rate of 100% on no requests and an average of 0.0ms over no samples are the two most misleading numbers the page could print, because both look like a healthy service. And that a counter CANNOT THROW INTO ITS CALLER and, when its input does, **records nothing rather than half a row** — the same defect `xacml_monitor.js` found one module over, asserted here before it could be made again. Plus the ring being bounded while the tallies are not, and an application being told from a person by the credential's own answer rather than by the shape of the name. **In process because two of the cases cannot be reached over HTTP**: a detail object that throws when it is read, and the client cap, which would need two hundred and one distinct credentials on the wire |
| `access_policy.js` | that the XACML `access-control` policy makes OWNERSHIP a CONSTRAINT and not an alternative — a signed-in person reaches their own portal account and NOT somebody else's, for `manage-own` and for `read` separately, while the four ownerless surfaces go on behaving as plain RBAC. It exists for a regression: the policy was first written as three OR'd arms, "the resource requires nothing" was true for the portal (which narrows nobody), and it swallowed the owner comparison — so any signed-in person could reach any other person's account, with no error and no Indeterminate anywhere. `portal_access.js` stayed green throughout, because that file asserts the STRUCTURAL rule (the handler reads the identity from the session, never from the request) and this asserts what the POLICY decides once it has a trustworthy subject. Both halves are needed and neither implies the other. Mutation-tested against the OR spelling and against a wrong empty-owner reading |
| `key_residency.js` | that a private key is decrypted while it signs and not the rest of the time: nothing decrypted after `start()` (the startup decrypt is a KEK check whose plaintext is thrown away), the public half — certificate, kid, every curve key's public JWK, which is what the JWKS endpoint walks — readable with nothing decrypted, and the three retention words doing three different things. `resident` is asserted BEFORE the two purging words, so a `report()` that always answered "nothing held" could not pass the file; the `timed` case uses the key at 700ms and checks it is still held at 1400ms, which is what separates an IDLE clock from an absolute one. Every residency check is paired with a real RS256 signature verified against the published public key, so a feature that quietly broke signing would fail here. Mutation-tested against a purge that forgets the parsed `KeyObject` and against arming the timer on decrypt rather than on use |
| `version.js` | **M.N.O, and the fact that every one of its failure modes is QUIET** — a wrong version still renders, still serves, still answers 200, and nothing anywhere goes red. That the repo-root `VERSION` file is `M.N` and nothing else (a stray third component, a `v` prefix or a trailing comment is ignored and the version silently becomes `0.0`, which is the module's deliberate never-fail-a-build behaviour and is exactly why the FILE has to be checked and not only the parser); that `BUILD_NUMBER` and `GIT_COMMIT` override, since a CI system setting one that was ignored would report a number nobody could match back to a build; and **that the stamp survives a restart** — two `load()` calls returning the same record, which is the entire reason a stamp exists rather than the version being computed at startup. Plus a corrupt stamp falling back rather than throwing, because six modules read this at require time and a throw is a service that does not start over a file whose job is to be printed in a footer. **The last section is the one that would have caught the state this replaced**: five surfaces draw a version and two of them read `package.json`, whose patch is a placeholder, so every build ever made reported `0.9.0` — so it asserts the SOURCE each module reads and not the string it renders, because two pages reading two different sources agree perfectly right up until they stop. **In process because two claims choose how the process was started** (a directory with a stamp and one without, twice) **and one is a property of the SOURCE TREE** (the manifests in step with VERSION), which no running service could be asked. **The over-HTTP half is in two owned jobs**: `admin_api.js`'s `everySurfaceReportsTheSameBuild()` — which is what caught the one-record bug, since a container never shows it — and `sts_xacml_remote_pep.js`, for the seventh surface. It failed on itself the first time it ran, and the fix is written down in it: the two files that document having STOPPED reading `package.json` say so in a comment containing the pattern, so the check strips full-line comments — a maintainer must never have to choose between deleting the explanation and deleting the check |
| `directory_indexes.js` | that the two caches over the directory never cost the property they exist beside: a write is visible to the very next read, however many kept-index writes surround it. The username index across creates, `invent: true`, and the TWO-WRITE shape a SCIM create actually is; the group index across a group create, a membership write and person writes on either side of it; and that the two answer separately, since one shared "is it current" flag is the tidy-looking mistake |
| `readme_ports.js` | **the README's *The ports* table, against the table that decides the ports.** It exists because that section is the exact shape this repository has been bitten by twice — the root CLAUDE.md's *a number written here as well went stale twice* — and because **the one mechanism this service already has for keeping a list honest cannot see any of it**: `/admin/sts-metadata` walks the live Express router, and a raw socket registers no route, so nine of the ten bindings are invisible to it. So it is held to `config.js`'s `SETTINGS` instead, in BOTH directions: a binding with no row (the failure people expect) and **a row naming no setting** (what a RENAME produces, and the one that goes unnoticed, because the table still looks complete). Defaults are compared too — a row naming the right setting and the wrong number is worse than a missing row, because a reader acts on it. Plus the COUNT in the prose above the table, asserted as *port settings + 1* rather than against a constant, so the KDC's second socket stays accounted for; and the Dockerfile's `EXPOSE` set against the same list, `88/udp` named separately. **In process because every claim is a comparison between two FILES in this repository** — the same shape as `postgres_schema.js` and `xacml_pep.js`'s COPY-set check. **It found two things on its first run**: the Dockerfile had never `EXPOSE`d 8888, the Kerberos test service, and neither had the comment above that list enumerating "the listeners that are NOT HTTP"; and a table row cited `spiffe.authRequired`, which stopped existing on 2026-09-06 when `global.mode` replaced it. Mutation-tested against a renamed setting, a wrong default, a bumped count and a deleted EXPOSE |
| `worker_pool.js` | the four ways moving a computation into another process goes wrong: that a worker computes the SAME BYTES (literal equality for the nine deterministic algorithms; cross-verification for the three whose ECDSA half is randomized and must be), that the event loop is genuinely FREE while it does — counted in timer ticks, against an unpooled control that manages none — that a session's jobs go to one worker and unnamed ones spread, and that a SIGKILLed worker FAILS its jobs with a sentence rather than leaving a promise nobody settles. Plus `workers.count = 0` producing the same bytes here, and a realm being refused the setting at both ends |

**`sts_portal_sessions.js` IS THE NEWEST OWNED JOB (2026-09-06)** and it covers
five claims nothing else did over HTTP: that a sign-in at `/admin` and one at
`/portal` each create a session `GET /admin-api/sessions` lists, named by the
surface it came through; that a SIGNED-IN person reaching for somebody else's
portal account gets their own; that signing out INVALIDATES the session rather
than merely tidying a list; **that an ACTIVATION LINK ends at a sign-in that
works**; and **that no page this service draws links to a bare
`/authn/login`**.

**THE LAST TWO WERE ADDED THE DAY THE FLOW WAS REPORTED BROKEN, AND THEY ARE
THE CLEAREST ARGUMENT IN THIS FILE FOR AN OVER-HTTP JOB.** Setting a password
at `/portal/activate` worked; the account was real, the credential was stored,
the audit row was written, and the button at the end of it — labelled *Sign in*
— pointed at a bare `/authn/login`, which draws a form for a PENDING
AUTHENTICATION RECORD and answers **400 `There is no sign-in waiting under that
id`** to a request naming none. So the last step of setting up an account was an
OAuth error page. **Every function involved was correct**: the only thing wrong
was one `href`, in a string, on a page — which is precisely the class of defect
no in-process test can see and no unit test would have been written for.

Three things about how it is asserted:

* **THE LINK IS FOLLOWED, NOT MERELY READ.** Checking that the page renders
  passes on the broken version, and checking that the href is different from
  the old one would pass for any wrong value. The job follows it and requires
  an `authn_id` on what comes back, then signs in with the password it just set
  and lands on `/portal` as that person.
* **THE WHOLE SECTION RUNS WITH NO SESSION, WHICH IS THE PREMISE.** A
  password-set link is followed by somebody who cannot sign in yet, so the
  cookie jar is asserted EMPTY when the form is drawn and again after the link
  is spent. That second one is `portal/CLAUDE.md`'s rule made checkable: a setup
  link that signed anybody in would be a magic link and a standing bypass of the
  mechanism the person is in the middle of choosing.
* **THE PAGE SCAN IS THE RULE THE FIRST ONE IS AN INSTANCE OF.** The same
  mistake was in THREE files that day — the portal's account-ready page, the
  federation index and the admin console's 401 for a form posted with an expired
  session — each written separately, each looking obviously right. So the job
  fetches the pages an unauthenticated reader can reach and fails on
  `href="/authn/login"`, and checks the console's 401 separately because that
  one is a POST and its link has to be an ABSOLUTE URL in the DEFAULT realm.
  All three assertions were mutation-tested by putting each dead link back.

Three more things about it are worth keeping if it is reworked.

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

**`tools/pep-credential.js` IS NOT A TEST EITHER, AND IT IS THE FIRST TOOL HERE
THAT BOTH LAUNCHERS RUN AGAINST A LIVE SERVICE.** It builds a Root CA, an
Issuing CA and a TLS client leaf on `common/vendored/x509.js` — the debugger's
own PKI engine, already in this repository, already what `spiffe/spiffe_ca.js`
issues X509-SVIDs with, and held to roughly 240 certificates against OpenSSL by
`tests/pki_x509.js` over there — and POSTs the Root to `/tls/trust`. That is the
flow the parent's `tests/pki_mutual_tls.js` has always used, with a command line
instead of a browser.

It exists because the three `/xacml/pep` endpoints are gated: a remote PEP is
admitted by a certificate this service VERIFIES whose DN holds `REMOTE_PEPS`, and
**nothing in the mock or in the PEP image provides that certificate** — the
launchers mint it and mount it. `tests/vendored/sts_xacml_endpoints.js` requires
the same file for `mint()`, so there is one implementation of how a chain is
built rather than one per caller.

**`vendored/` is not in that table either, and for the opposite reason: it is
ALL tests** — the jobs and the files they need, listed and argued in
`tests/vendored/MANIFEST.js`, **which is the count**: one was written down here
as well and went stale, which is the whole reason that file has a list. **It is split by OWNERSHIP and the table below is
that split**, which is why the jobs are described here at all: the paragraph
this replaced said they were "not this repository's to describe", and that was
true while every one of them was a copy. Most are this repository's own now, so
`docs/test-suite-map.md` over there describes the parent's and this describes
ours. For the copies the entry is deliberately short — that document is where
each of those is written down, and a second full copy here would drift.

The seventeen tests in the table below need only this service, and since
2026-08-28 they are OWNED by two
different repositories — which is the first thing to know about it,
because every one of them but the last ran from the parent's suite before that
date. **MOST ARE THIS REPOSITORY'S OWN, AND `MANIFEST.js` IS THE COUNT** — what
follows is the ARGUMENT for each, which is the thing worth keeping here:
`sts_metadata.js`, `admin_api.js`,
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
written here on 2026-09-05, is here for that same third
reason**: it turns `authn.unauthenticatedSessions` on through `/admin-api`,
presses a button on the sign-in screen, and then asks `/oauth2/authorize` and
`/oauth2/token` what changed — and the thing it asserts is that a party the
console can describe is refused at a protocol door in that protocol's own
words.

**AND `sts_xacml_remote_pep.js`, written here on 2026-09-06, is the only one
here for a FOURTH reason: it builds an image and starts a container.** It
answers the third reason too — the policy it deploys goes in through
`/admin-api/xacml`, and so does the setting that lets the nudge through — but
that is not what settles where it lives. It builds `xacml-pep/Dockerfile` from
this tree, puts the result on the SERVICE'S OWN docker network, and asserts that
what THAT container allows changes when the policy does. The parent's suite
drives a URL somebody else started; there is no shape of test over there that
says "build this image, put it on that network, and then ask it". Two other
tests hold one side of that seam each and neither loads `xacml-pep/sync.js` at
all, which was the registrar and the poller going untested since phase five
landed.

**The other four are still the parent's**, and this repository
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
| `tests/vendored/sts_admin_api_operations.js` **(ours)** | **the other half of that API — EVERY operation it declares, driven for real, with a LEDGER that says so.** No count is written down in it, on purpose: it was ninety operations when the file was written and it is a hundred and thirty-one now (41 reads, 90 writes). Two things are asked of that ledger at the end of the run and both are about the FILE rather than the service — **every documented operation was driven**, or holds a row in `NOT_DRIVEN_HERE` naming who drives it instead (two rows, both the explorer, which `admin_api.js` owns along with its CSP), and **every write that succeeded was read back through the resource's own GET, in the scope it was written in**. Besides that: each documented example body replayed, so that a request property the document names and the handler does not read fails HERE rather than for the first caller who copies it; each handler's refusal sentence checked against the document both ways round (that sentence is what `admin_api.js` reads for the parity, so one short by an action turns the parity check off for it); every write read back through a DIFFERENT operation; and a configuration change followed as far as the persistence store's own write counters. Almost all of it in a trust realm it creates and LEAVES STANDING; `removeRealm` is consequently the one operation of that API driven only by its refusal, which the ledger accepts because a refusal is recorded as DRIVEN and not ACCEPTED |
| `tests/vendored/sts_admin_console.js` **(ours)** | **the `/admin` console itself, IN A REAL BROWSER since 2026-08-28: the gate, all thirty-eight pages, every link, every GET form and every button on them — and the value that comes back afterwards.** It was an HTTP job, and the argument for that (this console has no script on it, so a control IS a form and pressing a button IS posting it) is still true; what it missed is that a hand-built submission is the TEST's reading of the markup rather than the browser's, that the twenty-two GET forms had no POST target to walk and so were never checked at all, that the nested-`<form>` guard is a PARSER question the old file had to reason about instead of asking, and that a notice is not a value. Status codes and headers come from **WebDriver BiDi**, because `default-src 'none'` blocks a `fetch()` from the page — the thing under test. Plus: every link really visited, which covers the seven routes with no nav row by construction; the five handlers nothing had ever pressed, `/admin/rbac`'s own grant and revoke among them; refusals split into what the BROWSER will not send and what the handler will not accept; the realm switcher; and the browser's own console, which on this console must be empty. **Since 2026-09-06 it also holds the assertion `/admin/users/new` rests on**: a create with two boxes filled and the rest empty is read back OUT OF THE STORE and the five attributes `namePlan()` invents are asserted ABSENT. That is the one thing about that page nothing else could show — a person is invented in two places, the create succeeds either way, and the fiction is visible only in an `ldapsearch`. Beside it: Fill fills the empty boxes, leaves a typed one alone and creates nobody; a generated password is shown once and stored as a scrypt hash; and the activation link the page hands over is SPENT, because a link that 400s looks identical on the page that issued it |
| `tests/vendored/sts_delegated_permissions_example.js` **(ours)** | **THE DELEGATED PERMISSION REGISTER AS A RING, AND THE ONE JOB HERE THAT LEAVES ITS WORK BEHIND ON PURPOSE.** `abcapp1`–`abcapp5` in the DEFAULT realm, each declared for OAuth 2.0 and OpenID Connect with its supporting fields filled in, each exposing `read` and `write` under a base URI of its own, and each granted both on THE NEXT ONE ROUND — `abcapp1`→`abcapp2`→`abcapp3`→`abcapp4`→`abcapp5`→`abcapp1`: five resources, ten permissions, ten grants. **It was a complete mesh of forty grants until 2026-09-01** and the file argues the change rather than merely recording it: the mesh was the stronger test and the weaker EXAMPLE, and this job is both — forty lines between five boxes is the one graph shape that looks the same however it is drawn and however it is wrong, and this example exists to be LOOKED at. What survives is the assertion that matters: every grant still resolves to the RIGHT resource among five whose bases differ only in a digit, so a lookup matching on a prefix, a host or the bare name is wrong for four of the five pairs. What replaced the mesh's arithmetic is an EXACT-LIST assertion per entry — `abcapp2` holding `abcapp4`'s `read` would keep every count right and be wrong about the only thing the example says. Plus the two halves landing on the right ENTRIES (a grant written to the resource instead of the client reads correctly on `/permissions` and finds nothing at the token endpoint), the PICTURE — five boxes, ten lines, `may-reach` on every one and `acts` zero everywhere, because a configured grant has been exercised nought times and the renderer colours `acts && !issued` as a refusal — and the TOKEN, audienced to the one base URI of five that was asked for (its own successor, the only one it holds anything on), carrying the bare names on its scope claim, and moving exactly two of the ten grants to `asked`. It is IDEMPOTENT (the identifiers are fixed, so every previous `abcapp*` is forgotten first) and it does not tear down, because the example exists to be READ at `/admin/delegation/allowed`. **Since 2026-09-02 it also asserts the GROUPING** — that the five are ONE group and that nothing else in the default realm is in it, which are two different failures (a partition too fine, and one too coarse) that a service with only these five configured could not tell apart, and that all five applications resolve to it, since every one of them is both a client and a resource. What it deliberately does NOT assert is the direction decision: a ring is connected whichever way you walk it |
| `tests/vendored/sts_consent.js` **(ours)** | **THE CONSENT SCREEN, AND THE OVERRIDE THAT MAKES IT NOT APPEAR.** Mostly negatives, for `sts_dpop.js`'s reason: a screen that draws, takes an Allow and hands over a code looks finished and can be worth nothing. What it asserts is that a GET of the screen records NOTHING (or anything that prefetches a link has consented for somebody), that a consent id is spendable ONCE, that a consent asked of one person cannot be drawn OR answered by another's session and that every one of those refusals leaves the pending record answerable by the person it belongs to, that Deny records nothing and the refused scope is asked again, that a second request is silent and a new scope asks about ITSELF ALONE, that `prompt=none` answers `consent_required` and `prompt=consent` asks again without destroying what was already agreed. **And the half that is not drivable from the parent's suite and is why this file is here**: a delegated permission consented globally on an application's entry stops a person who has never been here being asked — with NOTHING written about them — while a second application asking for the same permission is still asked, and removing the override asks everybody again including the people it was covering |
**`sts_metadata.js` CALLS EVERY METHOD OF EVERY ENDPOINT, AND ONE OF THEM USED
TO EMPTY THE CLIENT TRUSTSTORE (2026-09-06).** That walk carries NO SESSION
deliberately, so a bodyless POST to a console form is refused 401 — a handler
answering, which is the whole of what the check asks. **That argument holds for
everything behind a gate and for nothing in front of one**, and
`POST /tls/trust/clear` is in front of one: it needs no credential, it succeeds,
and it removes every anchor the launcher posted.

Nothing depended on that until 2026-09-06. A client certificate was a turnstile
and `GET /xacml/pep/policies` needed none; now the remote PEP container's pull,
its heartbeat and its PIP queries all resolve a VERIFIED chain to a directory
entry. So in a run where this job happened to come FIRST — which
`--only=xacml,roles,metadata` produces and the full suite's ordering does not —
that container authenticated as nobody for the rest of the run, reporting
`UNABLE_TO_GET_ISSUER_CERT_LOCALLY` about an anchor that had been posted
correctly before anything started. **The symptom names a certificate and the
cause is another job.**

It is skipped by name now, and the list is one entry. The test for a second is
not *this changes something* — every POST in that walk changes something — it
is: **this endpoint needs no credential AND destroys state another job depends
on.**

| `tests/vendored/sts_xacml_endpoints.js` **(ours)** | **THE EIGHT `/xacml` ENDPOINTS, IN A THROWAWAY TRUST REALM.** Until it existed every route in `xacml/xacml.js` was uncovered — the in-process XACML suite holds the ENGINE to 455 OASIS cases and makes not one HTTP request. What is here is the surface in front of it: a template built on `/admin-api` deciding at `POST /xacml/pdp` against an attribute the request never carried; four malformed requests refused **400 and never Indeterminate**, which is the distinction a PEP most needs, since an Indeterminate would be enforced by its bias; the embedded PEP's two biases disagreeing on the one answer they are supposed to disagree on (NotApplicable, reachable only in a realm whose repository is empty); an obligation this PEP cannot discharge turning a Permit into a refusal and the SAME Permit standing once it is renamed to the one it knows; a remote PEP's pull, its ETag, its 304, and a disabled policy reaching nobody; **a registration named from the client CERTIFICATE and never from the body**, on the registration and on the heartbeat alike, which is the one defect in this family that would be a security bug; a PEP an administrator disabled staying disabled when it reconnects; a policy save that does not wait on an unreachable PEP; and both off-switches answering 501 in the realm while the default realm goes on answering. **AND SINCE 2026-09-06 TWO MORE SECTIONS.** *The gate* is an INVERTED MATRIX and that is the whole value of it: four callers — nobody, a verified certificate in no group, `XACML_USER`, `REMOTE_PEPS` — against all eight endpoints, so the two DIAGONAL cells are asserted. A single "an anonymous caller is refused" check would pass against a service that had collapsed the two roles into one, which is the change somebody tidying up will make; the diagonals are the only assertions anywhere that say admitting a caller to the demonstration surface has not silently admitted it to the endpoints publishing the documents this service enforces its own access with. It ends by turning `xacml.enforceAccess` off and back on, because a gate with no documented way out is one somebody works around with a worse one — and because leaving it off would silently un-gate every section below. *The PIP over HTTP* asserts the SHAPE as hard as the content: the `<Attributes>` come back in the XACML CORE namespace, an unresolved designator is an **absent** `<Attribute>` rather than an empty one (the schema forbids an empty one, and absence is what a request that never carried it looks like to every engine), `IncludeInResult="false"` is explicit, both spellings of a directory attribute resolve, and the five empty-bag reasons arrive in a namespace of this service's own so that a PEP reading only OASIS's never meets them. Mutation-tested against six mutants |
| `tests/vendored/sts_xacml_remote_pep.js` **(ours, `docker: true`)** | **THE REMOTE PEP AS A SECOND CONTAINER ON THE SERVICE'S OWN DOCKER NETWORK, IN BOTH LAUNCHERS' STACKS.** It asserts the seam the other two PEP tests each hold one side of: `tests/xacml_pep.js` compares the container's MODULES with this service's in a child process and never makes a request; `sts_xacml_endpoints.js` drives the three PEP endpoints with the TEST impersonating a PEP, so it asserts the pull's bytes and nothing evaluates them. **`xacml-pep/sync.js` — the registrar and the poller, the whole client half — was loaded by no test at all.** The launcher brings the container up (`--profile xacml` locally, a service in `docker-compose-run-tests.yml` in CI) pointed at a realm that does not exist yet; the job creates it and asserts nine things. **It registers on a LATER attempt**, because its PDP appeared minutes after it did — the retry `sync.js` grew for this. It pulls what was deployed, dialling the compose name on the internal port rather than a published one, and is marked UNAUTHENTICATED because the shipped container carries no client certificate (the authenticated path is `sts_xacml_endpoints.js`'s, with a real handshake). It decides four cases in its own memory, naming the PEP and the token that decided. **AND SINCE 2026-09-06 IT SHOWS THE PIP REACHING THE MOCK'S EMBEDDED LDAP, which is the exact inversion of what that section used to hold.** It asked about `carol` **asserting nothing** — no employeeType, no attribute of any kind, only a name and an action — and the container PERMITS her, because `xacml-pep/pip.js` resolved the policy's `employeeType` designator against her entry under `ou=users` through `POST /xacml/pip`. Four checks rule out the four ways of being right by accident: the Permit, a name the directory has never heard of refused the same way, the answer's own `pip` block saying the query was made and how many designators came back with values, and **the PDP reaching the same decision** — which is the property the whole phase exists for and the one this section used to record the ABSENCE of. The old behaviour is still asserted beside it and is now a CONFIGURATION: a request-asserted attribute still decides where the directory holds nothing, because a PIP removes the disagreements that come from MISSING information and not the ones that come from a caller asserting something about itself. **It converges BY POLLING** on a policy created and promoted through `/admin-api/xacml`, with the nudge deliberately undeliverable and section 1 asserting the PDP said so. It watches a disabled policy STOP BEING ENFORCED out there, fall back to the one enabled document, empty to `loaded: false` where the bias is what decides, then recover. **Then it takes the nudge's other half**: `xacml.pepNotifyAllowInsecure` on, and the PDP dials the container across the bridge — this repository's third outbound request, with no test against a real listener anywhere until this — the row recording `The PEP answered 204.` and the change landing in tens of milliseconds against a five-second poll. It reads the PDP's console showing counters for decisions it never saw, compared against the PEP's own rather than constants. It feeds the PEP a hostile nudge BODY carrying a permit-everything policy and asserts nothing in it is believed. And it **takes the PDP away under the running container — `xacml.remotePeps` off in the realm since 2026-09-06, which was a realm removal until then — and asserts it goes on deciding correctly in both directions while reporting itself stale** — the trade `sync.js` argues at length and nothing had ever checked. Mutation-tested against five mutants, all caught: the pull no longer filtering disabled policies, the PEP never pulling twice, a module dropped from `xacml-pep/Dockerfile` (which kills the container at load and is invisible to anything that is not the image), the PDP nudging nobody, and a failed pull emptying the holding |
| `tests/vendored/sts_xacml_editor.js` **(ours)** | **THE GUIDED POLICY EDITOR, IN A REAL BROWSER.** `tests/xacml_pap.js` holds the editor's GRAMMAR in process; what it cannot see is whether any of it reaches a page — forty forms in one table, a hidden `path` per row, an `action` that is sometimes hidden and sometimes a `<select>`, and a nested-`<form>` hazard that is a parser question rather than a taste one. So this presses buttons: every row's menu equals the grammar's own answer for that row and Remove is drawn exactly where something may be removed; a Match offers no Add menu and its function list is the two-argument boolean predicates rather than the library; a rule stops offering a second Condition once it has one; an edit that would leave the policy invalid is refused, explained, and **the stored document is byte-for-byte what it was**, which is the property that makes a live editor tolerable. **And the assertion the file is for**: a rule built out of four form submissions makes `/xacml/protected` permit somebody it refused, alternatives are shown to be ORed and matches ANDed by watching that decision move, and removing the rule on the page brings the refusal back. It found one defect on its first run — every refusal on the three `/admin/xacml` pages redirected with an EMPTY `error=` — and was mutation-tested against four more |
| `tests/vendored/sts_roles.js` **(ours)** | **ROLES, AND THE NINE KINDS OF ISSUANCE THEY REFUSE PEOPLE AT.** In a throwaway trust realm, because this feature REFUSES people: a job that narrowed an application in the default realm and died before clearing it would leave every later job in the run signing in to a service that turned them away, and the failure would name the wrong file. Mostly negatives, for `sts_dpop.js`'s reason — a service that issues a token to somebody who holds the role is what an unmodified service does for everybody. What it asserts: the roles claim reaching a client; a narrowed application refusing at the token endpoint in **OAuth's own words** (`access_denied`, read as the error CODE rather than as a 400, because the two are a working gate and a broken handler); the person beside them not refused; a GROUP and an APPLICATION holding a role, which is the half `client_credentials` needs since there is no person in that grant at all; the six built-in roles never appearing in the claim; WS-Trust's optional AppliesTo; and `roles.enforceIssuance` off putting everything back. Mutation-tested against eight mutants |
| `tests/vendored/sts_roles_builtin.js` **(ours)** | **THE SIX BUILT-IN ROLES, ONE SECTION EACH, POSITIVE AND NEGATIVE.** `sts_roles.js` above drives the register and every role it uses is CONFIGURED; these six are computed from what the party IS, and three of them could not be held or failed by anything arriving at an endpoint until the day this was written. **EVERYBODY is the one with no negative case** — its `holds()` is `return true`, so it refuses nobody — and the file asserts that rather than leaving the gap to be noticed, by checking the catalogue still calls it the DEFAULT requirement. The other five are asserted both ways, at BOTH doors: the sign-in screen, which refuses with the page again and the reason on it, and the authorization endpoint, reached by making the session at the permissive application and carrying it to the strict one, which is the only way to see the second gate at all. Plus the unauthenticated session itself — that declining returns to the caller rather than answering `access_denied` like Cancel, that it is the stable `anonymous` principal on a real session id, that a signed-in session is NOT in that list, and that the setting is honoured at the DOOR and not only on the page. Section 6 asserts `oauth2.rfc9700` is OFF before it asserts anything else, because the claim there is that client authentication is OBSERVED without being ENFORCED. **It found the bug that made `ALL_AUTHENTICATED_USERS` refuse everybody.** Mutation-tested against seven mutants, none of which survived |
| `tests/vendored/bulk_load.js` **(ours, a HELPER)** | Not a job. **WHAT THE THREE BULK-LOAD JOBS SHARE, WHICH IS EVERYTHING EXCEPT THE DOOR**: the sizes, the five thousand deterministic invented people (from the index rather than `Math.random()`, so a failure at person 3,417 is reproducible), the stopwatch that keeps every lap, the preflight that raises `ldap.maxEntries` and reads the attribute catalogue, and the report. Not one line of it opens a socket or knows what a SCIM resource looks like — that is the thing under test, and a shared implementation of it would be three jobs measuring one piece of code three times |
| `tests/vendored/sts_directory_bulk_load_scim.js` **(ours)** | **FIVE THOUSAND PEOPLE, FIFTY GROUPS, FIVE THOUSAND MEMBERSHIPS, ALL OF IT OVER SCIM 2.0, AND HOW LONG EACH KIND OF WRITE TOOK.** The first of three jobs whose subject is TIME rather than behaviour, and each is still a test. `POST /scim/v2/Users`, `POST /scim/v2/Groups`, and the memberships ONE AT A TIME through `PATCH /scim/v2/Groups/{id}` — five thousand writes, each rewriting a member list one longer than the last, which is the number that would show this service getting slower as a group fills. **It BUILDS every resource out of the mapping published at `GET /admin-api/scim` rather than out of a copy** — `type`, `parent` and `extension` were added to that document for this job, and one projection replaced the two that had already drifted. One catalogue attribute (`description`) has no SCIM member at all; the drop is reported with the reason and the read-back checks only what was sent. It was `sts_directory_bulk_load.js` until 2026-09-06, when its user creates went through `/admin-api` and it measured a mixture |
| `tests/vendored/sts_directory_bulk_load_ldap.js` **(ours)** | The same work over **RFC 4511 ON THE RAW SOCKET**, and **the only job in either suite that touches it**. Everything else that reaches this directory reaches it over HTTP and goes through `ldap_server.js`'s FUNCTIONS rather than its PROTOCOL — so the BER codec, the ldapjs submodule, the add handler's four refusals and the modify handler's change loop were exercised by nothing here at all. One bind, five thousand `add`s on it, fifty `groupOfNames`, five thousand `modify`s. The read-back goes through BOTH doors: a sample over the socket (which also drives SEARCH, half of this protocol) and one entry out of `/admin-api/ldap/directory`, because a store answering the socket out of something the HTTP views cannot see would otherwise pass. Needs the socket published — `tests/docker-compose-ldap.yml` and `STS_LDAP_URL`, argued above — and FAILS rather than skipping without it |
| `tests/vendored/sts_directory_bulk_load_ldap_50k.js` **(ours)** | **FIFTY THOUSAND PEOPLE OVER THE RAW LDAP SOCKET, and it asks a different question from the three above.** Those are the door-to-door COMPARISON and share their sizes for that reason; this one asks whether the add path stays CONSTANT-TIME an order of magnitude further out. It is worth asking separately because the answer was no until 2026-09-07: a create walked the whole realm to enforce one-entry-per-person, so the cost rose with the number of people already there — 0.73ms at the five hundredth and 13.45ms at the five thousandth. At five thousand that reads as a slow service; at fifty thousand it is a service that stops. **It drives `sts_directory_bulk_load_ldap.js`'s file at a different scale rather than copying its client** — each job owning its own DOOR is an argument for three jobs driving three protocols, not for two jobs driving one protocol twice — and owns only the SCALE and the NAMES: `BULK_USERS=50000`, `BULK_GROUPS`/`BULK_MEMBERS_PER_GROUP` at 1 (the group phases are the other job's to measure, and `checkSizes()` refuses nought), and `BULK_DOOR=ldap50k` so two LDAP jobs in one suite do not meet on every invented name. Measured 2026-09-07: **50,000 in 40.0s, mean 0.77ms, and the mean FALLING across the run** — which is the property it exists to keep. Last in the manifest, because it leaves the directory an order of magnitude larger than the others found it |
| `tests/vendored/sts_directory_bulk_load_api.js` **(ours)** | The same work through **`/admin-api`**, and the job that cost two operations: `POST /admin-api/groups/create` and `POST /admin-api/groups/add-member` did not exist until it was written. `invent: false`, which is what the console's own New user form sends. It is the only one of the three whose door REFUSES an unknown attribute — which is why the shared preflight reads that catalogue for all three: it is the strictest of the doors, and a population that satisfies it satisfies the other two |
| `tests/sts_persistence_postgres.js` | **`persistence.mode=postgres`, and the only test anywhere that RESTARTS this service.** It starts its own database and its own mock, so it touches the shared one not at all. What survives — the realm registry with each realm's overrides, the directory in both realms, the appconfig overrides with their source — and, just as much, **what must not**: the signing key is regenerated, so the `kid` differs and a token minted before the restart is dead at introspection. Plus the two claims nothing else could check: that two processes on one database do NOT see each other's writes (`coordinates: false`, demonstrated rather than read back), and that a database that is not there leaves this service RUNNING out of its seeded directory. Skips, naming which, without docker or without a complete checkout to run. **THAT FIRST CLAIM IS FALSE AS OF 2026-09-06 AND THE JOB IS THE PARENT'S TO FIX** — see the obligation below |

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

## EVERY JOB CARRIES AN `/admin-api` ACCESS TOKEN NOW (2026-09-09)

`/admin-api` required no credential at all until that day and required one
after it: an OAuth 2.0 access token this service issued, audienced to that API,
carrying `admin:read` for a read and `admin:write` for a write. **Twenty-odd
jobs here drive that API and not one of them shares an HTTP helper** — each
builds its own `fetch` or `https.request` — so making them all authenticate was
either twenty-odd edits saying the same thing, or one place saying it once.

**IT IS ONE PLACE, AND IT IS THREE FILES:**

| File | What it does |
|---|---|
| `tools/admin-api-token.js` | Mints the token. The seeded `sts-management-api` client, `client_credentials`, `resource=<base>/admin-api`. It is the ONE place the client id, the grant and the form shape are written down. |
| `tools/attach-admin-token.js` | Presents it. Preloaded into every job by `run-report.js` with `--require`; it wraps global `fetch` and `http`/`https.request` and adds the header to `/admin-api` calls that do not already carry one. |
| the launchers | Mint it once per mode, before any job runs, and hand it over as `STS_ADMIN_API_TOKEN`. |

**WHY A PRELOAD AND NOT A SHARED CLIENT.** A shared client is the right answer
for a suite being written today. Adopting one across twenty-odd files that each
have their own conventions is a large change with no test behind it, and every
one of those files would be touched for a reason that has nothing to do with
what it asserts. The shim leaves the jobs about what they test.

**THE SHIM IS DELIBERATELY NARROW AND THE NARROWNESS IS THE SAFETY.** It
touches `/admin-api` and nothing else, and it NEVER replaces an Authorization
header a job set itself — several jobs authenticate as somebody on purpose
(SCIM's six schemes, the XACML gate's four callers, a token the job just
minted), and a shim that overwrote those would silently rewrite the thing under
test. **A job that means to drive `/admin-api` UNAUTHENTICATED sends
`Authorization: none`**, which the shim leaves alone and the service reads as no
token at all.

**THE FAILURE IS THE RUN'S AND NOT THE JOB'S.** Both launchers mint the token
before starting anything and abort the mode if they cannot: without one, every
job that touches that API reports a 401 and the report names twenty problems
where there is one. `docker-run-tests.sh` mints it **once per mode** rather than
once per run, which is the one thing about it that is easy to get wrong — the
token is SIGNED by a key this service regenerates on every start, and that
launcher tears its whole stack down between modes. (The remote PEP's client
certificate is the opposite and is minted once, because it is anchored by a CA
the launcher keeps as text.)

**AND THE BOOTSTRAP HAD TO BE SOLVED BEFORE ANY OF THIS WORKED.** The seeded
client's secret is minted per start and is readable only THROUGH the API it
unlocks. `adminApi.clientSecret` pins it; both launchers generate a fresh one
per run and pass it to the stack, so it lives as long as one stack and never
reaches a repository. **A compose file that does not forward
`ADMIN_API_CLIENT_SECRET` makes the pinning inert**, and that is not
hypothetical — it was inert in both compose files for the first day of this
feature's life, and nothing failed, because development mode does not verify a
client secret at the token endpoint. It would have failed the moment anybody
ran the suite in RFC 9700 mode or against a product-mode stack.

### `sts_admin_api_auth.js` is the gate's own job, and it exists because hand-verification is not a test

Every refusal was checked by hand with curl on the day the gate was written,
which is a claim about one afternoon. The job asserts the four refusals (no
token, a token this service did not sign, a token audienced elsewhere, a token
without the scope the action needs), the read/write split IN BOTH DIRECTIONS,
and the service-wide credential working inside a trust realm.

**Three of those would go unnoticed by every other job in this suite**, which
is the argument for having it: drop the audience check and everything still
passes, because every job presents a token minted for this API; collapse the
two scopes into one and everything still passes, because the run's own token
carries both; verify with the AMBIENT realm's key instead of the default
realm's and everything still passes, because the jobs that use a realm mint
nothing of their own — while a realm's own signing key minting that realm's
administrator credential is precisely the hole the console's two roles are
pinned to the default realm to avoid.

**Two cases are deliberately absent and the file says so rather than looking
complete.** A signed-in BROWSER reaching `/admin-api` — a console session must
never become an API credential — needs the OIDC code flow in a real browser,
which is `sts_admin_console.js`'s equipment; that file asserts the half a
browser can reach, which is that a browser with no session gets a 401 rather
than a redirect to a sign-in screen. And `adminApi.authRequired=false` would
mean turning the gate off on the service every other job in the run is sharing.

## AN OBLIGATION ON THE PARENT PROJECT: `sts_persistence_postgres.js` (2026-09-06)

**That job asserts `coordinates: false` and demonstrates it** — it starts two
mocks against one database and shows that neither sees the other's writes. As of
2026-09-06 that is no longer true, and **the job will go red against this tree**
the next time the `sts/` gitlink is bumped across this change.

It is recorded here rather than fixed here because of the rule at the top of
this file: that job is the parent's, it is not vendored (it needs docker), and
editing a copy we do not have would reach nothing.

**What it should assert instead** is the inversion, which is a stronger test
than the one it replaces and needs the same two processes it already starts:

* process A writes an entry; **process B sees it** within
  `persistence.pollInterval` without restarting — the claim the old assertion
  was the absence of;
* `status.coordinates` is `true` and `status.replication.appliedSeq` moves;
* with `STS_PERSISTENCE_COORDINATE=false` the OLD behaviour is back, unchanged,
  which is what keeps that setting honest;
* and the parts that still do not coordinate stay not-coordinated: a token
  minted in A is still dead at B's introspection, because **the signing keys are
  not adopted mid-life** — `applyKeysChange()` logs and does nothing, since
  taking a new key would strand everything the process has already signed.

That last bullet is the one worth keeping from the old job verbatim: it asserted
that the `kid` differs across a restart, and in product mode it no longer does.
The claim there has to become mode-aware rather than being deleted.

## `minted_persistence.js` and `replication.js`: the mutation record (2026-09-06)

**THIRTEEN MUTANTS, TEN CAUGHT, AND THE THREE SURVIVORS ARE THE USEFUL PART** —
every one of them was telling me about the FIXTURE rather than the assertion,
which is the lesson `ldif_codec.js` and `app_permissions.js` both record from
the other end.

Caught: the own-origin skip removed (1 red), the page not coalesced (1), the
apply not wrapped in `realms.run()` (7), **a synchronous throw not caught (1 —
and this one was a real defect, see below)**, the journal reporting nothing for
a delete (1), an array mutator not wrapped so `push`/`shift` are unseen (1),
rows written in the clear (2), another process's counter adopted into this one
(3), development mode persisting anyway (2), and a stale row skipped but never
deleted (1).

**IT FOUND A REAL DEFECT BEFORE ANY OF THIS SHIPPED, WHICH IS THE ARGUMENT FOR
THE ROUND BEING MANDATORY.** `applyRows()` wrapped each applier as
`Promise.resolve(applier(row)).catch(…)` — which handles a REJECTED promise and
does nothing at all for a SYNCHRONOUS throw: the throw happens while the
argument is being evaluated, so it escapes the `.catch` written for it,
propagates into the chain, and takes every later row in the page with it. Both
applier shapes are real (`applyKeysChange()` is synchronous and the rest are
not), so the wrong half was the one nothing else here would have exercised. The
`try` is around the CALL now.

### The three survivors, and what each was really saying

* **"the own-origin skip removed" survived the first round** because the STUB
  DRIVER filtered by origin, exactly as the real one does in SQL — so the
  assertion was a test of the stub, green whatever the module did. The stub
  hands over everything now, and the module grew the second skip that makes the
  assertion meaningful. **Belt and braces on purpose**: the failure it prevents
  is the one unbounded one in the whole feature.
* **"persistence.coordinate ignored" survived** because it was mutated in
  `enabled()`, which is the belt; the braces are the check in `start()`. Mutated
  there, it is caught. Worth keeping as a note rather than a fix: two reads of
  one restart-only setting is cheap and neither is the only one.
* **"a restore journals what it just read" survived even with THREE guards
  broken at once**, and that was entirely the fixture: the section emptied the
  live store and FLUSHED before restoring, which deletes the rows — so the
  restore had nothing to restore and could not have journalled anything whatever
  it did. It seeds the store directly now, and asserts first that the row really
  came back, so the assertion below it is about a restore that did something.
  With that fixed, all three guards broken together is CAUGHT.

**One equivalent mutant is recorded rather than counted**, per this file's own
rule: advancing the high-water mark before the apply is behaviour-preserving
here, because `applyRows()` contains per-row failures by design and therefore
never rejects. Counting it would inflate the number this paragraph is for.

### And a trap that cost real time, which is not about testing at all

`persistence_replication.js` became **invisible to `grep`** partway through the
work: a NUL separator written as a literal byte instead of the six-character
escape made the whole file binary. `node` read it, every test passed, and
`grep -n 'function'` returned nothing at all — which reads as "the file is
empty" and is not. `file` says `data` rather than `UTF-8 text`, and that is the
check. Two files in this repository legitimately contain one (`ldif_codec.js`
tests exactly this, and `xacml-pep/pip.js`); a third appearing is a mistake.

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

## NO JOB REMOVES A REALM (2026-09-06)

**A trust realm a test run created STAYS.** Seven jobs here create one; not one
of them removes it any more, and a job added tomorrow must not either. This is
an operator requirement and it overrides the tidiness argument every one of
those teardowns used to make.

**Why:** a realm is a whole logical copy of this service — its own directory
subtree, its registries, its claim sets, its policies, its tokens, its
overrides and its audit log. That makes it the ONE place where the whole record
of what a job actually did survives the job. A teardown that removed it deleted
that record at exactly the moment somebody wanted it: the run went red, and the
evidence went with the realm before anybody could read it.

**What paid for the teardowns is paid for elsewhere, which is why this costs
nothing:**

* **Collision.** Every realm id carries `names.runStamp()`, so two runs against
  one long-lived service mint two realms rather than meeting each other's
  leavings. The teardown was never what made that safe.
* **Isolation.** A realm reaches nothing outside itself, so a service holding
  ten of them behaves for every other job exactly as it did holding none —
  including a realm left with `xacml.enabled: false` or a narrowed application
  on it, which was the case those teardowns were most afraid of.
* **Accumulation.** Nothing this service mints is persisted, and a realm is not
  persisted either unless a store is configured, so they go when the process
  does. A person who wants them gone restarts the mock or removes them by hand.

**The three things it does cost, all of them recorded where they bite:**

1. **`POST /admin-api/realms/remove` is driven only by its REFUSAL.**
   `sts_admin_api_operations.js` asks it to remove the realm the call arrived in
   and it says no. Its coverage ledger accepts that without an exemption row,
   because `post()` records a refusal as DRIVEN and not ACCEPTED — and that
   file says so in a paragraph rather than leaving it to be noticed.
2. **The console's Remove button is drawn and never pressed.**
   `sts_admin_console.js` asserts it is THERE, on the realm's own page rather
   than on the list, and stops short of pressing it. That check lives in the
   create section and not in the teardown, because an assertion made in a
   `finally` replaces whatever failure got you there.
3. **`sts_xacml_remote_pep.js` cannot run twice against one service.** Its realm
   id is FIXED when a launcher owns the PEP container, so the second run meets
   "already defined" and fails — with a message that says so and names the way
   out. That is deliberate: reusing the realm would assert against a previous
   run's policy documents, and removing it would throw away the record. Both
   launchers give it a fresh stack, so only a hand-run against `--keep-stack`
   sees it.

**The one section that used a removal as its INSTRUMENT was rewritten rather
than dropped.** Section 9 of that same file makes the PDP go away under a
running container, and it made it go away by deleting the realm. It turns
`xacml.remotePeps` off in the realm instead: the three `/xacml/pep` endpoints
answer 501 to that container and to nothing else in the service, `sync.js` takes
any non-200 through the same `keep()`, and the outage is now REVERSIBLE and
scoped to the seam under test. It is left off on purpose — turning it back on
would erase the state the section asserts from a realm somebody is meant to be
able to read.

## ASSERT AGAINST THE WHOLE LIST, NOT AGAINST PAGE ONE (2026-09-06)

A page that pages is a page whose first screen depends on how much the rest of
the run has created. `sts_portal_sessions.js` created three applications and
looked for them on `/portal/applications` — one fetch, no `page` — and it
passed for as long as it was the only job that had ever registered one. In a
whole suite run the jobs ahead of it register well over the twenty rows that
page shows, the list is ALPHABETICAL, and `Portal Probe Open <stamp>` sorts
onto page two: the assertion failed against a page drawing exactly what it
should, three runs in a row, and re-running the job alone passed. **That is the
same shape as the rate-limit ordering above** — a job that passes in isolation
and fails in the suite is nearly always reading state the suite shares.

The rule is the one that fell out of it: **a claim about what a policy or a
register CONTAINS is a claim about the whole list**, so walk the pager (its own
"Page 1 of N" marker says how far) and assert against everything it returns.
Reading the first page is only correct for a claim that is ABOUT the first page
— which the counts at the foot of that one are not either: they are totals, and
page one's are the whole list's.

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

## `directory_indexes.js` (2026-09-07) — guarding a fix that cannot fail loudly

The two caches over the embedded directory — a username index behind
`existingUserEntry()` and a group index behind `groupsOfUser()` — are kept
current by stamping `directoryVersion` forward across writes that provably
cannot have changed them. `ldap/CLAUDE.md` has the measurements.

**A PERFORMANCE FIX IS NOT WHAT THE FILE TESTS**, and that is the whole of why
it exists. A cache that is merely slow is a cache that works. What the stamping
could take away is the property `groupsOfUser()` has no TTL for: **an `ldapadd`
changes the very next token**. A stamp applied one step too widely would leave
that read answering out of a stale index, and the symptom is a `groups` claim
that is correct-looking, verifiable and wrong.

It is here rather than over HTTP on a narrower clause than most files use. A
stale index CAN be seen over HTTP — a token missing a group somebody was just
added to. What cannot is WHICH index answered, or whether it was rebuilt or
kept, and those are the distinctions the stamping introduces. **A test driving
HTTP would pass just as happily against a version of the module with no indexes
in it at all**, which is the shape of test that stops guarding a thing the day
somebody rewrites it.

**The interleaving is the method rather than a flourish.** A single write
followed by a single read passes against any implementation. What finds a bad
stamp is a write of the kind that IS invalidating, followed by writes of the
kind that are NOT, followed by the read.

**Its mutation record is in `ldap/CLAUDE.md` beside the fix**, including two
mutants that were EQUIVALENT rather than missed — both mutated the removal loop
that an overwrite runs, and both are behaviour-preserving because the loop that
re-adds the entry's current names follows immediately. Counting them would
inflate the number, which is this directory's standing rule.

**AND THE FIRST VERSION OF THE FILE COULD NOT REACH ONE OF ITS OWN BRANCHES**,
which is the lesson `ldif_codec.js` and `app_permissions.js` each record from a
different angle. The overwrite section was built on entries at
`uid=<name>,ou=users`, where the old uid is ALSO the RDN value — so a name is
never actually departed, nothing is removed, and a mutant deleting the removal
passed. The shape that reaches it is an entry whose RDN is not its uid, which is
what a client certificate's entry is here. **A round trip over convenient data
is the shape that passes while proving nothing**, said for the third time in
this file about a third feature.

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
reaches anything else — which is what lets the realm be LEFT STANDING at the
end rather than removed. `roles.enforceIssuance` is turned off and on inside it
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
