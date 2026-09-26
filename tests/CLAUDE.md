# CLAUDE.md — `tests/`

## What this directory is for, and what it is NOT for

**THIS DIRECTORY HAS HELD BOTH HALVES OF THIS SERVICE'S COVERAGE SINCE
2026-08-28, AND EVERYTHING BELOW WAS WRITTEN WHEN IT HELD ONE.** Read the split
first or the rest of this file will read as though it contradicts itself:

| | What it is | Where it is authored |
|---|---|---|
| `tests/*.js` | the IN-PROCESS half — this repository's own module contracts, no fixed port, no container, no stack | here |
| `tests/vendored/` | the PROTOCOL half — jobs driven over HTTP against a CONTAINER built from this tree, plus the wallet modules several of them verify against. A few are byte-identical copies of the parent's mock-only jobs; **most are this repository's own** (`local: true`), and `MANIFEST.js` is the count of each | the copies: **the parent project**, not edited here. the `local` ones: **here**, and only here |

Everything this file says about what belongs HERE is about the first row. The
COPIES in the second row are argued in `tests/vendored/MANIFEST.js`, and the
rule that governs them is `common/vendored/`'s: **edit the parent's copy, then
`node tests/tools/vendor-check.js --sync`.** A fix made in `tests/vendored/` is
overwritten by the next sync and never reaches the stack that gates that
project.

**THE JOBS MARKED `local: true` IN THAT MANIFEST ARE THE EXCEPTION, AND
THE RULE IS EXACTLY INVERTED FOR THEM.** `sts_metadata.js`, `admin_api.js`,
`sts_admin_api_operations.js`, `sts_admin_console.js`,
`sts_delegated_permissions_example.js`, `sts_consent.js`,
`sts_xacml_endpoints.js`, `sts_xacml_editor.js`, `sts_xacml_remote_pep.js` and
`sts_roles.js` among them drive this
service's OWN `/admin` console and its `/admin-api`. **TWO OF THEM DRIVE NO
CONSOLE AND ARE OWNED HERE FOR A DIFFERENT REASON** — `sts_route_inputs.js` and
`sts_metadata_anonymous.js` READ THIS WORKING TREE, one for the route list it
probes and the other for the protocol-family table it checks its coverage
against, so a copy over there would be reading the pinned `sts/` gitlink rather
than the service that is running. **THE MANIFEST IS THE
COUNT AND THIS SENTENCE IS NOT** — it used to open by naming a number, and the
number went stale twice before anybody noticed, which is the drift a manifest
exists to stop. The first four ran from the parent's
suite until 2026-08-28 and were deleted there that day, on the argument that a
test asserting something about this console belongs in the tree where a control
is ADDED to that console — the tree that should go red when the control loses
its operation. **There is no copy of them over there to sync from**, which is
what the flag is for: `allFiles()` leaves them out, so
`tools/vendor-check.js` cannot report them GONE UPSTREAM and its `--sync`
cannot overwrite them. They are
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
  nothing else. `./run-tests.sh` needs none of it — its runner is a
  container on the bridge with the service — but `./local-run-tests.sh`'s
  runner was a host process, and `docker-compose.yml` deliberately publishes
  neither 389 nor 636, because the host most likely to want a mock directory is
  a host already running slapd. That launcher picked a free host port with the
  same `freePort()` it used for 8081, layered the override, and exported
  `STS_LDAP_URL`. **No launcher layers the file since that one was removed
  (2026-09-16)**; it is kept for a hand run. The other arrangement still in
  use is the throwaway service (every coverage run, and a bare
  `run-report.js`), where `run-report.js` builds the URL
  from `instance.ports.LDAP_PORT` — by NAME rather than as an offset from the
  base, so a listener added to or removed from the middle of that block cannot
  silently move it.
* **AND THE THIRD ARRANGEMENT DID NOT REACH THE COVERAGE RUN UNTIL 2026-09-09,
  BECAUSE THE IMAGE ANSWERED FIRST.** `tests/Dockerfile` carries `ENV
  STS_LDAP_URL=ldap://sts:389` for the compose stack, and `run-report.js` reads
  `process.env.STS_LDAP_URL || <the throwaway port>` so that a LAUNCHER's answer
  wins — which it cannot tell from an image default. Under `./run-coverage.sh`
  there is no `sts` host at all (the service is a child of the runner, in the
  same container), so both bulk-load LDAP jobs died on `getaddrinfo ENOTFOUND
  sts`. `./run-coverage.sh` empties it with `-e STS_LDAP_URL=`, which is the
  third variable it empties for exactly this reason — `STS_TEST_SERVICE_URL`
  and `XACML_PEP_URL` were already there and carry the same argument.
* **THE PORTS OF THAT THROWAWAY SERVICE ARE ALL HANDED OVER NOW, not one at a
  time as each job's failure is noticed.** `chosenPorts()` passes every entry of
  `instance.ports` under the name it was bound with, a launcher's own value
  always winning. What forced it: `sts_global_logout` dialled the directory on
  `STS_LDAP_PORT` and the mutual-TLS listener on `STS_MTLS_PORT`, got
  ECONNREFUSED from both on the throwaway path, NOTED each and PASSED — two
  protocols' worth of sign-in that no run starting its own service had ever
  exercised. (Its certificate sign-in is `GET /tls/sign-in` on the BASE URL
  since 2026-09-16, when 8443 and 9443 were deleted, so it asks this map for
  nothing now; the directory half is still exactly the case.)
  **`STS_LDAP_PORT` still has a line of its own** because it is the
  one name that differs on the two sides: the service reads `LDAP_PORT` and the
  job reads `STS_LDAP_PORT`, so the loop cannot match them.

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
variable and the launcher — it is never skipped, because the socket is the
thing under test and a job reporting green having driven nothing is worse than
one that is honestly absent.

They still SIT in `tests/vendored/` rather than beside this file, and the reason
is how they RUN rather than where they belong: `tools/run-report.js` spawns them
as processes with that directory as their cwd and they
`require('./random_username.js')` and the rest out of it, where `run.js`
discovers `tests/*.js` and runs it IN PROCESS against `harness.js`. Moving them
would have been a rewrite of four files to buy a tidier path.

**`tools/` HOLDS ONE SHARED TEST HELPER NOW, AND ITS PLACE IS THE RULE'S**
(2026-09-17): `tools/saml_signing_kit.js` makes a key, a hand-built
certificate and a signature in every XML signature family, and lends the three
SAML follow-up files the fake request and response they drive the routes with.
It is in `tools/` because `run.js` discovers `tests/*.js` and would otherwise
run it as a test with no `run` — the same reason the report generator lives
there — and it is ONE copy because a second signer is a second place for
exclusive canonicalization to be wrong, which is the argument
`tests/vendored/saml_xmldsig.js` already carries.

Why they are copies at all: this repository's launcher could previously run
those jobs only when the parent checkout happened to sit beside it, so on a
machine where it did not, thirteen of twenty-three jobs were quietly absent from
a run that said "Tests passed". The suite is self-contained now — it needs no
other checkout to run any of it.

---

**This is not where the protocol suite is WRITTEN.** The suite for this service is the
parent project's `../id-proto-debugger/tests/`, and a test that drives this
service's PROTOCOL SURFACE goes there — see *So the line is* at the end of
this section for the decision, and what follows for how it was made. It was made
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
| A test that needs A SECOND CONTAINER on this service's own docker network, and drives the seam between them | `tests/vendored/`, marked `local: true` **and `docker: true`** | **There is exactly one, and it is `sts_xacml_remote_pep.js`.** BOTH LAUNCHERS bring a remote XACML PEP up as part of their stack and hand it `XACML_PEP_URL`, `XACML_PEP_NAME` and `XACML_PEP_REALM` — and, since 2026-09-13, `XACML_PEP_HTTPS_URL` and `XACML_PEP_SERVER_CERT_DIR`, where the job writes the listener pair it has the PEP's realm issue; it creates the realm that container has been polling, deploys policy through `/admin-api/xacml`, and asserts that what THAT container allows and refuses changes with it. The parent suite drives a URL; it has no way to say "put this other image on that network, then ask it". It answers the console question above as well, so both arguments put it here |

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
resolves the PDP by COMPOSE DNS rather than a published port on localhost —
though it does NOT yet verify that certificate: every path runs it with
`PEP_TLS_INSECURE=true`, because development mode regenerates the service Root
on every start (the job's own header records that this sentence once said
otherwise); the PDP can actually DELIVER the nudge across the bridge, which is
this repository's third outbound request and had no test against a real
listener anywhere; a mount puts a client certificate where `pep.js` reads one,
so the registration is a real mutual-TLS handshake between two containers; and
the unit that dies is a container with a log, which every failure message
quotes.
**Mutation-testing the two versions is the argument in one line**: dropping
`xacml_functions.js` from `xacml-pep/Dockerfile` is invisible to a host run —
the module is one directory up and always there — and kills the container at
load in 2.6 seconds.

**THE LAUNCHER OWNS THAT CONTAINER, AND THE REASON IS THE CONTAINERIZED
RUNNER.** `./run-tests.sh` puts the suite INSIDE a container with no
docker socket in it, deliberately — that file argues why where it also excludes
the parent suite's postgres job — so a job that started its own PEP could never
run in the stack that gates this repository. The launcher therefore brings one
up beside the service and hands the job three variables; the job shells out to
nothing at all. (`./local-run-tests.sh` did the same until it was removed on
2026-09-16, and **the same test ran in both stacks**.)

It needs a docker daemon only when NEITHER launcher is involved — a bare
`node tests/tools/run-report.js`, or a coverage run, both of which drive a
service that is a plain process with no compose network to join. There the job
builds the image and starts a container of its own, and where there is no daemon
`tools/run-report.js` reports it SKIPPED with the reason — amber in the report,
`<skipped>` in the JUnit, a named line in the summary saying what is therefore
unchecked. That is the one skip in this directory and it is a narrow one: an
intended job that did not run is otherwise a FAILURE here, and the exception is
for something deliberately left out.

**THAT SELF-STARTED CONTAINER HAD NO CLIENT CERTIFICATE UNTIL 2026-09-09, AND
THE COMMENT ABOVE IT SAID SO WHILE CALLING THE TWO DEPLOYMENTS IDENTICAL.** It
read "configured IDENTICALLY to the one the launchers start — no client
certificate, no anchor", which was true of both until 2026-09-06, the day
`/xacml/pep/*` began requiring a VERIFIED chain holding `REMOTE_PEPS`. The
launchers were taught to mint one; this path was not, so the container
registered as an unauthenticated caller and the PDP refused it with a 403. **No
run ever reached it**: both launchers take the attach path, and the two that
take this one were red on `/admin-api`'s own gate from the same day, dying in
the preflight 136ms earlier. One masked gate hid another, which is the argument
for fixing the first one where every path can see it.

**THE IDENTITY IS CREATED RATHER THAN FOUND, AND THAT FOLLOWS FROM THE NAME.**
An authenticated registration is named by the PDP from the CERTIFICATE and never
from the body — `xacml.js` argues it: a PEP that could name itself while holding
a certificate could take over somebody else's row, which is the one thing in
that family that would be a security bug rather than a fidelity one. The job's
`PEP_NAME` is its container's hostname and the `?pep=` on every pull, so the
common name has to be that too. The launchers get this free by pinning both to
the seeded `remote-pep-1`; a container whose name must be unique per run cannot,
so the job writes the entry and the `remote-peps` membership through
`/admin-api` first — **the same two writes `ldap_server.js`'s seed comment
already describes** ("a deployment using a different common name adds its own
member to this group"), performed rather than described.

One assertion moved with it: the row's identity DN is matched as
`(cn|uid)=<name>` rather than `cn=`. What it claims is WHICH ENTRY the
certificate resolved to, and that is the RDN's value; which attribute carries it
is a property of the door the entry came in through — the seed writes `cn=` and
`POST /admin-api/users/create` writes `uid=`. Naming `cn=` was asserting the
seed.

**AND `./run-coverage.sh` WAS NOT TAKING THAT PATH AT ALL, WHICH IS A THIRD
THING THE 401 HID.** `docker-compose-run-tests.yml` gives the `tests` service a
DEFAULT `XACML_PEP_URL=http://xacml-pep:9090` — right for `./run-tests.sh`,
which brings that container up beside the service. The coverage run uses
`--no-deps` and starts no such container, so the variable named a host that does
not exist, and the job read a non-empty `XACML_PEP_URL` as *a launcher provided
one*, attached to it, and waited out its timeout against nothing. That launcher
now empties it, exactly as it already empties `STS_TEST_SERVICE_URL` and for the
same reason — and with it empty the job takes the self-start path, finds no
docker socket in that container, and is reported SKIPPED with the reason. **A
skip is honest there; a timeout against a container nobody started is not.**

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
belong here — a test that needs to choose how the PROCESS was started, that
hands a document to an independent implementation in the same address space,
**or that needs A SECOND CONTAINER on this service's own docker network and
drives the seam between them.**

**THE "IF YES" HALF WAS REVERSED ON 2026-09-21, BY rcbj: a new test that CAN
be asserted over HTTP is written HERE, in `tests/vendored/`, marked
`local: true`** — not in the parent suite. What forced it is where the suite
now runs. `./run-tests.sh --target=aws:<env>` and the `product` mode both reach
the service only over the wire, so the protocol half is the ONLY coverage
either of them has, and a family whose features are asserted in process alone
(PAR, JAR, RAR, JWT introspection, SAML request signatures, most of SPIFFE,
XACML conformance, the VC status lists — the list the 2026-09-21 audit
produced) is simply untested there. A job in the parent's suite reaches this
tree only through a gitlink that trails it; a `local` job runs against this
working tree in every mode and every target. **Everything above this paragraph
is the record of the rule it replaced**, kept because the reasons in-process
tests exist at all — choosing how the process starts, a second container, a
socket no stack publishes — are unchanged.

**ONE QUESTION COMES BEFORE THAT ONE SINCE 2026-08-28**, and it is the second
row of the table above: is the thing under test this service's own `/admin`
console or its `/admin-api`? If it is, it belongs here whatever the answer about
HTTP — the first of those jobs were driven over HTTP and could have stayed over
there. The line above is about CAPABILITY; this one is about OWNERSHIP, and it
is the only place the two disagree.

**AND A THIRD KIND SINCE 2026-09-06: a test that needs a SOCKET THIS SERVICE
BINDS AND NO STACK PUBLISHES.** `tests/vendored/sts_directory_bulk_load_ldap.js`
writes five thousand entries over RFC 4511 on TCP 389, and it was **the first
job in either suite to drive the directory's own socket in earnest** — beyond
`sts_global_logout.js`'s single bind, everything else that reaches this
directory reaches it over HTTP, through `ldap_server.js`'s FUNCTIONS rather than
its PROTOCOL, so the BER codec, the ldapjs submodule, the add handler's refusals
and the modify handler's change loop were exercised by nothing anywhere. `docker-compose.yml` deliberately publishes neither 389 nor
636 — the host most likely to want a mock directory is a host already running
slapd — so the parent's stacks cannot reach it and this one has to arrange it:
the containerized runner is on the bridge and needs nothing,
the throwaway service hands its own `LDAP_PORT` over, and
`./local-run-tests.sh` layered `tests/docker-compose-ldap.yml` on a free host
port until it was removed on 2026-09-16. **It is not
`docker: true`** — that flag is for a job needing a DAEMON, and this one needs
a PORT — so with neither launcher it FAILS naming the variable rather than
reporting green having driven nothing.

## Running it

```bash
./docker-npm-test.sh                 # from the repository root (#50)
./docker-npm-test.sh --only=ldif     # one file, by any part of its name
./docker-npm-test.sh --list          # what there is
```

**IN THE TESTS IMAGE SINCE 2026-09-16 (#50).** Part of the service is
TypeScript and is compiled only inside an image build, so `npm test` and
`node tests/run.js` on a checkout refuse (`common/compiled_tree.js`,
`STS-CORE-0093`) rather than dying at the first converted module.
`docker-npm-test.sh` builds `tests/Dockerfile` (which compiles the tree) under
a tag of its own and runs `npm test -- <args>` in a throwaway container.
Inside it, `npm test` and `node tests/run.js` are what they always were, and
what the paragraphs below describe.

It needs `npm install` to have been run (it uses `bunyan`, a normal dependency)
and **nothing else** — no fixed port, no container, no browser, no network. The
suite was once under a second; it is minutes now, because many files fork a
CHILD PROCESS (the reasons are in each file), and several of those serve the
stack on an EPHEMERAL loopback port they choose themselves — which is choosing
how the process was started, this directory's rule, and never a port somebody
else's stack is using. A test here that needs a listener a STACK provides still
belongs in the parent suite.

**That paragraph is about `npm test` and the files in this directory.** The
VENDORED half does need a stack, a browser and a second npm package
(`tests/package.json` — see below); it is reached by `./run-tests.sh`
and `./run-coverage.sh`, and never by `npm test`.

**Since #50 neither half runs on a checkout.** Part of the service is
TypeScript compiled only inside an image build, so `npm test` refuses there
(`common/compiled_tree.js`, STS-CORE-0093) and `./docker-npm-test.sh` runs it
in the tests image instead — `./docker-npm-test.sh --only=<substring>`,
`./docker-npm-test.sh --list`.

**`--only` IS A FILTER OVER THE DISCOVERED LIST, NOT A LIST**, which is the
distinction the design of `run.js` turns on — there is still nothing to keep up
to date — and a pattern matching nothing is an ERROR rather than an empty pass,
because a typo in a filter must never read as "everything passed".

### The report, and where the tooling lives

```bash
./run-tests.sh                # EVERY job, with a report written — the
                                     # service AND the runner in containers
                                     # built from this working tree
./run-tests.sh --modes=memory # one mode of tools/modes.sh, not all
                                     # three; --modes=cluster is the fourth
./run-tests.sh --no-build     # reuse the images already built
./run-tests.sh --only=crypto --no-browser
                                     # anything else goes to run-report.js
./docker-npm-test.sh                 # only the in-process files, in the
                                     # tests image (--only=<substring>, --list)
./run-coverage.sh                    # coverage, on its own — the RUNNER in a
                                     # container and the service its child,
                                     # because V8 collects from inside the
                                     # process it measures
node tests/tools/vendor-check.js         # is tests/vendored/ still in sync?
node tests/tools/vendor-check.js --sync  # re-copy the parent's files over it
```

`vendor-check.js` needs the parent project checked out beside this one (or
`--parent=<dir>`) and this repository's `npm install`; it reads files and runs
nothing of the parent's. `./local-run-tests.sh`, which carried all of these as
options, was removed on 2026-09-16.

**`./run-tests.sh` IS THE WHOLE SUITE**, and the two files in this
directory that serve it are not tests: `Dockerfile`
(node, a Chrome and this working tree, built with the repository root's
`.dockerignore` — see below) and `run-tests-in-container.sh` (the image's CMD —
wait for the service, then `tools/run-report.js --service-url=https://sts:8081`).
`../docker-compose-run-tests.yml` brings the pair up.

There were two launchers until 2026-09-16: this one for the environment, and
`./local-run-tests.sh` — the jobs as node processes on the host, the
development loop — for a test. #50 ended the second, because a job run on a
checkout meets the refusal above, so re-running one job is now
`./run-tests.sh --only=<job> --modes=memory` and costs an image build
(`--no-build` when the service has not changed).

`tests/tools/run-report.js` is what the launcher drives, inside the tests
container. It writes `tests/report/<mode>/<timestamp>/` — `report.html`, JUnit
`report.xml`, `summary.json` and one log per job — and points
`tests/report/<mode>/latest` at it. Both are gitignored. **The `<mode>` segment
is the mode matrix's and the launcher passes it as `--report-dir`**, so the
bare `tests/report/latest` is not any current run's report; three places named
it anyway until 2026-09-07 (both launchers' log capture, and the CI workflow's
upload, which had therefore been uploading nothing at all).

**TWO FILES IN THAT `logs/` DIRECTORY ARE THE LAUNCHER'S RATHER THAN THE
RUNNER'S, AND BOTH RECORD SOMETHING THAT IS GONE BY THE TIME THE REPORT IS
READ.**

| File | What it is | Where it comes from |
|---|---|---|
| `logs/00-mock-sts-service.log` | the mock's own account of what it issued | `run-report.js` writes it when it started the service itself (a coverage run, or a bare run); otherwise the launcher takes it out of `docker compose logs sts` before the teardown removes the container |
| `logs/00-test-runner.log` | **the RUNNER's own output** — which jobs it chose, the ones it could not start and why, the reason a job was reported SKIPPED, the summary | `./run-tests.sh` takes it out of `docker compose logs tests`, because there the runner IS a container (`./local-run-tests.sh` tee'd it, until it was removed on 2026-09-16) |

**THE SECOND ONE IS NOT THE JOBS' LOGS AND THAT IS THE WHOLE REASON IT EXISTS.**
`logs/NN-<job>.log` holds the JOB's output, so **a job that never started has no
file there** — and a run in which something could not start is exactly the run
somebody comes back to a report for an hour later. Until 2026-09-07 what the
runner said about it lived in a terminal and in nothing else, which for
`./run-tests.sh` meant a container that was removed at the end of the
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
question is always *which* certificate.

**AND IT IS RE-READ BEFORE EVERY PROTOCOL JOB SINCE 2026-09-12, WHICH IS THE FIX
FOR A WHOLE RUN RATHER THAN A PRECAUTION.** Fetching it once was right for as
long as this certificate could only change when the service restarted. It
stopped being right on 2026-09-11, when `/admin/pki` gave an operator a Root CA
to rebuild: `POST /admin-api/pki/build-root` replaces the Root, every
Intermediate and Issuing CA under it, **and the leaf this listener is already
serving** — so a truststore pinned before that request is stale the moment it
returns.

`sts_admin_api_operations.js` drives every declared operation of that API,
`build-root` among them. On 2026-09-12 that made **the twenty-nine jobs after it
fail in the `memory` and `postgres` modes**, each with `fetch failed` or
`unable to get local issuer certificate` — an error that names a certificate and
says nothing about the cause, on a service that was answering perfectly the
whole time. `--only` hid it both ways: any narrowing that left that job out
passed, and running one of the twenty-nine alone passed.

Three things about `refreshTrust()` are decisions rather than mechanics:

* **THE BUNDLE IS REPLACED, NOT ACCUMULATED.** A truststore that kept every
  anchor a run had ever seen would go on trusting a hierarchy the service has
  thrown away, and this suite contains assertions about certificates being
  REFUSED. One live certificate, exactly as `tools/trust.js`'s header argues.
* **THE PATH DOES NOT CHANGE.** `NODE_EXTRA_CA_CERTS` is read by node once per
  child, so a rewritten file is picked up by the next job and by nothing already
  running; a second path would leave the report directory holding several
  certificates with nothing saying which was live.
* **THE SPKI PIN IS USUALLY UNCHANGED AND THE MESSAGE SAYS SO.** A rebuild
  re-certifies the listener over the key it already had, so the browser jobs'
  pin survives it and the node jobs' anchor does not. A line reporting
  only the pin would say *nothing changed* about the one event that breaks every
  node-driven job in the run.

**The service-side half of the same day is in `tls/CLAUDE.md`**: a request
worker was certifying a certificate it does not serve, and the front process was
not re-issuing the one it does. Everything that PROBES rather than
tests — `run-report.js`'s own wait,
`tools/service.js`'s readiness loop, both compose healthchecks — asks with
`rejectUnauthorized: false`, because the question there is whether the port
answers and not whether it is trusted. **The JOBS get a real anchor**, which is
what keeps an assertion about a certificate meaningful.

**THE STACK'S OWN DECISIONS ARE ARGUED WHERE THEY LIVE**, not here. The
host-run stack's — why it was its own compose project on a free host port
found at start (so a run could never take, or tear down, the `sts` container a
plain `docker compose up` gives somebody), why it persisted NOTHING, why the
image was REBUILT every run, and why a stack that would not come up was a
FAILED run rather than a quiet fall back to the host — were in
`../local-run-tests.sh`'s header, and went with it on 2026-09-16 (git history
has them). The containerized runner's
three — no published port at all, a database with NO VOLUME, and the
tests image built from the SAME context and the SAME `.dockerignore` as the
service — are in `../docker-compose-run-tests.yml` and `Dockerfile`, the latter
with a guard that says so rather than failing later inside node.

**TWO OF THOSE THREE WERE WRITTEN DIFFERENTLY AND BOTH WERE OVERTAKEN.** This
said "no postgres", which was true while the suite ran once in `memory`; two of
the three modes in `tools/modes.sh` are DEFINED by having a store, and until
2026-09-09 they brought the mock up with `persistence.mode` set and nothing to
connect to — so the service refused to start, correctly and naming the store,
and two modes ran nothing at all. What that bullet was actually defending is
kept by the missing volume rather than by the missing service: the cluster
lives in the container's writable layer and the teardown between modes takes it
with the container, so no mode and no run can start from another's leavings. It
said "behind `Dockerfile.dockerignore`" too, which is the BuildKit arrangement
that lasted one build — `../.dockerignore`'s own header is the record of why
there is one rule set and the service image deletes what it does not want.

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
* **AND A UNIT JOB DOES NOT INHERIT THE STACK'S DEPLOYMENT VARIABLES**
  (2026-09-12). Both launchers EXPORT the mode's environment — they have to:
  that is how `docker compose` and a host-mode service are handed the mode —
  and this runner's unit children inherited it. Harmless for as long as no mode
  set anything a MODULE reads, and `dispatch` mode set one: `keys.source` went
  to `persisted` so that the key-encryption key really comes out of the OpenBao
  container, and **eight unit jobs went red in a run where the same eight
  passed in the other two modes** — five at `keystore.start()`'s refusal (*key
  material is configured to persist … and no persistence store is open*, which
  is product mode's own rule and is correct), three further in at the seal. Not
  one of the failures was about the service. So the runner reads the variable
  NAMES out of `tests/tools/modes.sh` — that file says it is the one place the
  modes are defined, and a list copied into `run-report.js` would drift — and
  deletes them from a unit job's environment. `tests/unit_job_environment.js`
  pins it, and also checks modes.sh's own rule that every mode names every
  variable, which nothing had been checking. **`database_metrics.js`'s local
  deletes are the same problem met one file at a time**, and they stay: a file
  that is right when somebody runs it by hand with those variables exported is
  worth more than one that relies on a runner.
* **THE TEST DEPENDENCIES ARE A SECOND npm PACKAGE**, `tests/package.json`,
  carrying `commander`, `selenium-webdriver` and the `@noble`/`node-forge`
  packages the vendored wallet modules need. They are not root
  `devDependencies` because `.npmrc` carries `omit=dev` — the same trap the
  coverage renderer below was written around — and not root `dependencies`
  because a browser driver has no business in the service's production image.
  `tests/Dockerfile` installs them into the tests image (`./local-run-tests.sh`
  installed them on the host when they were missing, until it was removed on
  2026-09-16); a job that cannot load because they are absent FAILS naming the
  command, rather than skipping.
* **The VENDORED jobs run against a copy of THIS working tree, IN A CONTAINER
  since 2026-08-28.** The copied ones are authored over there by the rule at
  the top of this file, and that suite drives the pinned `sts/` gitlink — so
  those jobs do not otherwise run against what you just edited.
  `./run-tests.sh` builds the service image and the tests image from
  this tree, brings both up from `docker-compose-run-tests.yml`, and the tests
  container hands this runner the service's URL with `--service-url`.
  (`./local-run-tests.sh` did the same with `docker-compose.yml` and ran the
  jobs as node processes on the host, until it was removed on 2026-09-16.) It
  was about a minute plus the image build when
  this was written; it is far longer now (the bulk loads alone take minutes),
  and the two browser jobs — `sts_admin_console.js`, which walks every page,
  and `sts_xacml_editor.js`, which drives one page in depth — are among the
  slowest.

  **THE LIFETIME RULE IS THAT WHOEVER STARTED IT STOPS IT**, and it is why
  `--service-url` exists rather than this runner learning to speak compose. A
  service handed in that way is never stopped here: the launcher's own trap
  owns it, which is what makes `--keep-stack` possible and what stops a run
  from tearing down a stack somebody asked to keep. `tools/service.js` — the
  throwaway process on a block of ports of its own, stopped by the pid it
  started — is still the whole of what a COVERAGE run can use, because V8 writes its data from inside the process being measured
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

**A copied protocol job can be AHEAD of this tree** — that suite is developed against
its own checkout of this service — in which case it fails here naming a feature
this tree does not have. That is information about the two checkouts and not a
fault in the runner, which is why the report says which side every job came
from.

## `wallet_kit.js` is not a test either (#38's follow-ups)

`run.js` skips it by name, beside `harness.js`, and the reason is the same one
that keeps a test in this directory rather than in the parent's suite: the five
wallet sign-in files each need the whole protocol stack on an ephemeral port, a
cookie jar per browser, an OID4VCI issuance done the way a wallet does it, and
a presentation in each of the three formats — and five copies of that would be
five places for a wallet to drift from the one the service actually answers.
`inAChild(t, childMain, name)` is the parent half; `boot()` is the child's.

**The wallet in it is deliberately NOT the service's own code** — its proofs,
Key Binding JWTs and VP JWTs are signed with node's crypto — with two
exceptions it states where they are made: the BBS derived proof uses the same
`@digitalbazaar/bbs-signatures` the issuer uses, because there is no second BBS
implementation here, and the `ldp_vc` holder proof uses
`oid4vc/vc_data_integrity.ts`, whose own test holds it to the W3C's published
vectors.

## `scheduler_kit.js` is not a test either (#49, 2026-09-22)

`run.js` skips it by name. It is the simulated cluster `scheduler.js` and
`scheduler_cluster.js` drive real `Scheduler` instances through: one virtual
DATABASE clock with each node's own skewed from it, virtual timers that
`advance()` fires in order — **nothing sleeps** — and one store, one claim
table and one lease table shared by every node, with nodes that heartbeat, die
and wake. It is a kit and not a copy of `cluster/`: the claims keep a lifetime
and are re-claimable once it lapses, the leases carry a token that goes up per
tenure, and that is all the scheduler relies on.

## Adding one

Drop a `.js` file in this directory. There is **no list to update** — `run.js`
discovers every `.js` file that is not itself, `harness.js` or
`wallet_kit.js` — and that is
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

**A route module you require gives you NO ROUTES unless you register them
(#50's R1, 2026-09-16).** Until that day requiring a route module was what
registered its routes (rule 1 in the root `CLAUDE.md`), so a test that did
`require('../scep/scep')` and then drove the shared app, or read
`app._router.stack`, found the module's handlers there. A module converted to
TypeScript registers nothing when required now: it exports
`registerRoutes(app)`, and `common/protocol_stack.ts` calls it at the module's
place in the route order. So a test that needs the handlers either calls the
module's own `registerRoutes(app)` after requiring it — once, on the shared app
from `common/app`, and for every module whose routes it needs (a family's
`_admin` module is separate: `scep` and `scep_admin` are two calls) — or loads
the whole stack with `require('../common/protocol_stack')`, in a CHILD
PROCESS, the way `protocol_endpoints.js` does. A test that only calls a
module's exported functions needs neither. **The JavaScript route modules are
the exception** — `ldap/ldap_server.js`, `tls/tls_server.js` and the
Kerberos files still register at require (`sts_metadata.ts` has not since it
became TypeScript: call its `registerRoutes(app)`). The failure when this is
forgotten is a 404 (Express's `Cannot GET`) or an empty route filter, not a
load error.

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
  deletes `CONFIG_FILE` before requiring anything — so a store is opened only
  where a file sets out to open one. **Such a test has to clean up a directory
  or a database rather than a Map**; the codec test avoids that by testing the
  codec rather than the driver.

  **`appconfig_persistence.js` WAS THE FIRST (2026-08-28), and it took the
  condition this paragraph set** — the later files that open an `ldif` store
  (`truststore_persistence.js`, `used_assertions.js` and others) follow its
  arrangement. It writes into a directory of its own under the system
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
| `realm_isolation.js` | that a realm's identity register, its revocation set and — since 2026-09-06 — its SCIM traffic counters are its own, in both directions, and that removing a realm takes them with it. **The third store is here rather than in a file of its own because this file's header asks for it**: `admin_stats.js`'s `scimCounts` was a plain object for the same reason the other two were, and that reason (the directory is shared) expired on 2026-08-25. **Plus KERBEROS'S THREE since 2026-09-15** — `krb5.principals`, `krb5.replayCache` and `spnego.pending` were declared `scope: 'shared'` ON PURPOSE while the KDC answered in no realm, and are `realms.map()` now that each trust realm has a KDC of its own (#33); the declaration is what is checked, the behaviour being `kerberos_realm_routing.js`'s. **Seven more since 2026-09-12** — the CAEP and RISC registers (both ways, across a purge, and their in-place edits against a real persistence observer), `vc_offers.deferredAccessTokens` (keyed by a digest, never the token), `spiffe_auth.js`'s recorded connections (the realm of the LISTENER), and as declarations `scim_auth.js`'s three challenge stores and `federation.js`'s release index. Two sections run in a CHILD PROCESS, because those modules register routes on the shared app. Twenty mutants across it and the file below, all caught |
| `vci_request_encryption_key.js` | **THE OPENID4VCI REQUEST-ENCRYPTION KEY IS A MEMBER OF THE REALM'S KEY SET** (2026-09-12). It was generated by `vc_issuer.js`, handed down the fork in the environment and shared by every realm in a pooled process. Six claims: one key per realm, of the size the realm asked for even when its set is built through `.of()` from outside it, and a JWE to one refused by another — by the kid and, with the kid forged, by the unwrap; the key channel carries it, ON THE SET a sibling's blob builds (asserted before anything asks, or the backfill would hide a broken `plainKeySet()`); in product-shaped mode it is written down sealed, restored, publishes without a decrypt, and a LEGACY row is backfilled once — asking the store first, so a process holding a stale set adopts a sibling's backfill rather than making a second key; the two-member enrichment rule in both directions (the one-member mutant survived until the reverse case was added); the environment hand-off gone, as source; and the issuer itself in a CHILD PROCESS, including `/oid4vci/last_request` per realm |
| `cross_surface_sso.js` | that `/admin` and `/portal` share a sign-on session IN EVERY REALM and each still holds a session of its own. The end-to-end flow is `tests/vendored/sts_portal_sessions.js`'s; what is here is the half it cannot see — **which PARTITION a record is in.** A console session AUTHORIZES in the ambient realm and LIVES in the default realm's, so its parent is in a different partition from itself, and three pieces of machinery had to learn that: the parent check (looking in the wrong partition ends every console session in a realm on sight), the expiry (looking in the wrong partition gives it a full fresh lifetime and lets it outlive its parent) and **the cascade** (walking only the parent's partition means the sign-on session ends and the console session goes on working). Mutation-tested against all three. **The cascade assertion reads the STORE and not the reader**, and it was written the other way round first and survived both cascade mutants — `relyingPartySessionOf()` ends an orphan as it finds one, so asking IT whether the session is gone passes whether the cascade ran or the reader tidied up. One branch is recorded as unreachable rather than left looking covered |
| `oidc_rp_renewal.js` | **THE CONSOLE AND THE PORTAL RENEW THEIR TOKENS INSIDE THE SAME SESSION** (2026-09-12). An operator was sent back through the sign-in screen an hour after signing in, although the sign-in had been issued a refresh token and thrown it away. The end-to-end half is `tests/vendored/sts_hosted_surface_renewal.js`; what is here is what that job cannot choose: a renewable session's expiry is its renewal window and not its sign-on session's (and one with no refresh token is unchanged); **a parent that RAN OUT leaves a renewable session standing while one that vanished EARLY is still ended as an orphan** — over HTTP both are "the parent is gone", and the second means breaking the cascade; the decision table (not due, renew, leave to run out, end, window closed); a renewed ID Token about another issuer, subject or authentication time refused; the renewal writing onto the same record with no token in its audit row; and, as SOURCE, both surfaces registering the renewal ABOVE their gate and first route (rule 1). Mutants: the parent-ran-out exception removed, a renewable session expiring with its parent (**caught here and NOT by the job**, because a renewal re-derives the expiry before the job can see it — which is what this half is for), the console registration removed, the subject check removed, the window never closing — all caught |
| `realm_directory_lookups.js` | that a lookup BY DN answers about one realm — groups, people and applications — including that a refused cross-realm delete leaves the entry where it was |
| `delegation_map_bands.js` | that the delegation picture is TWO BANDS — the issuer above, centred, every party on one plane — and that no two edge labels are drawn on top of each other |
| `federation_map_bands.js` | that the federation picture is THREE BANDS — left asks, right authenticates — that the four relationship states are four distinguishable strokes, that a brokered partner is ONE arrow which keeps that pair's counts, and that the per-application counts either add up or report the difference |
| `spnego_identity.js` | what a SPNEGO sign-in claims: which part of a Kerberos principal becomes the session's username, and the `amr`/`acr` read off the ticket's own flags |
| `oid4vp_sign_in.js` | **SIGNING IN WITH A WALLET** (2026-09-17, #38 and its follow-ups), in a CHILD PROCESS on an ephemeral loopback port, with a wallet written in the file: the button and `oid4vp.signIn`; the wait page — ONE script (`/authn/wallet.js`), a real submit button, `script-src 'self'` with `frame-ancestors` kept, and no `<meta>` refresh — the plain QR code OFF by default in BOTH modes and its own `?qr=1` page (no script, a `<meta>` refresh, the base policy) when it is on; the signed request asking for this issuer's credential in all three formats with a `credential_set`; a credential issued over HTTP and presented with a Key Binding JWT signing in its entry with `amr ["pop"]`/`acr "1"` and completing the pending authentication; another browser refused even with the `response_code`, a wrong `response_code`, a second `direct_post`, a second collection, expiry, a sign-out withdrawing an uncollected sign-in, a different person's session replaced; each refusal with its own code; and **DISOWNING** — a global sign-out through `logout.terminate()` and through `POST /logout`, an administrator's revocation and its restore, a suspension and its reinstatement, INVALID being final, a credential issued AFTER a sign-out signing in again, and an ordinary session sign-out disowning nothing |
| `oid4vp_sign_in_formats.js` | **EVERY FORMAT SIGNS IN** (#38's follow-ups), on `wallet_kit.js`: each of `dc+sd-jwt`, `jwt_vc_json` and `ldp_vc` issued, recorded in the register in its own shape, and signing in — and refused with no holder proof, a wrong nonce, a wrong audience, a wrong key, on a token this realm did not verify, and from another realm; an **ML-DSA-44 holder key** in every format and an **ML-DSA-44 issuer key**; `oid4vp.signInFormats` narrowing the query; and the parent project's wallet SHAPES, signed with the vendored `jws.js` it signs with — its KB-JWT and VP JWT sign in, its bare `ldp_vc` envelope is refused by name |
| `oid4vp_dc_api.js` | **THE DIGITAL CREDENTIALS API** (#38's follow-ups): the signed `openid4vp-v1-signed` request with `expected_origins`, `dc_api.jwt` and an encryption key of its own and no `response_uri`/`redirect_uri`/`state`; an encrypted answer with the `origin:<origin>` audience signing the browser in; a presentation made for `direct_post` refused; another origin (`STS-VC-0074`), another browser (`STS-VC-0055`), a second answer, a mixed `direct_post`-then-DC-API answer (`STS-VC-0057`), an unencrypted answer and a wrong protocol (`STS-VC-0073`); the no-script path (`STS-VC-0081`); and `dc_api` in the clear, with every format |
| `oid4vp_wallet_mfa.js` | **A WALLET AS A FACTOR** (#38's follow-ups): a wallet then a password (`/authn/password-factor`) or an authenticator app — `amr ["pop","pwd"]`/`["pop","otp"]`, `acr "mfa"` — the realm-wide requirement reaching this door, a password then a wallet (`amr ["pwd","pop"]`) with somebody else's credential refused (`STS-VC-0084`), one factor staying one factor, **key attestations** (Appendix D) raising it to `hwk` and `acr "mfa"` and answering `forceMfa` alone, an untrusted attestation refused at issuance, `oid4vci.keyAttestationRequired`, the `attestation` proof type, and `appAuthnMechanism: wallet` |
| `vc_status_list.js` | **THE STATUS LISTS** (#38's follow-ups): the Token Status List as JWT and CWT with its `Cache-Control`, the aggregation endpoint, 501 for a historical request, the Bitstring Status List credentials; the reference in every format's credential; revoking and suspending flipping the right bit in the right list; the Verifier refusing a revoked credential at the BAR DOOR; a trusted foreign issuer's list fetched from a local HTTP server, verified, cached, honoured, and — unreachable — refused; **a status reference required (#165)**: a foreign SD-JWT VC or `jwt_vc_json` naming none refused `STS-VC-0088` under `oid4vp.requireStatusReference` all, accepted under own-only and when its issuer certificate's thumbprint (hex, colon-hex, base64url) is in `oid4vp.statusOptionalIssuers`, an exempt issuer's NAMED status still honoured, this realm's own credential with none refused in every format unless `off`, the bar door's `ldp_vc` query asking for `credentialStatus`, and an `ldp_vc` WITHHOLDING it refused `STS-VC-0089` valid or revoked (`STS-VC-0072` with it disclosed and revoked), accepted under `off` in development and refused in product with `off` still stored, whose write is refused `STS-CORE-0103`; and every new store on `/admin/caches` with `/admin/vc-status`'s own report |
| `vc_status_codec.js` | The status-list ENCODINGS as a library: the draft's own byte arrays and every Appendix C vector, a minimal CBOR codec (boundaries, refusals, bombs), COSE_Sign1 signing and verifying in ES256, EdDSA, RS256, PS256, ES256K and ML-DSA-44 (synchronously and through the pool), the JWT form's claims, the references, and the W3C bitstring's MSB-first packing, minimum size and multibase |
| `vc_data_integrity.js` | The HOLDER'S Data Integrity proof as a library: the W3C's published vectors for `ecdsa-jcs-2019`, `eddsa-jcs-2022` and `mldsa44-jcs-2024` (canonical forms, hashes, and a reproduced `proofValue`), round trips for P-256, P-384, Ed25519 and ML-DSA-44, `did:jwk` and `did:key`, and eighteen refusals each naming its own check |
| `ldif_codec.js` | that every value this service can put in an attribute survives the RFC 2849 round trip `persistence.mode=ldif` writes — the base64 rules, the folding, `origin` riding as a comment, and a URL-valued attribute being refused rather than dereferenced |
| `postgres_schema.js` | that `postgres/schema.sql` and `persistence/persistence_postgres.js` hold the SAME schema, and that the role the script creates cannot change it. The DDL is written down twice on purpose since 2026-09-06 — an OWNER builds the store, and the role this service dials with holds four verbs on the rows and no `CREATE` on the schema — so this file compares the two `CREATE` lists in both directions, checks that the version row the script writes is the driver's `SCHEMA_VERSION`, and reads the grants: exactly `SELECT, INSERT, UPDATE, DELETE`, no `GRANT ALL`, no `TRUNCATE`/`REFERENCES`/`TRIGGER`, and a `REVOKE` of `CREATE` that is not merely an absence of a grant — PUBLIC holds it on `public` before PostgreSQL 15. It also pins the role NAME across the three files that spell it, because a connection string cannot be built out of the variables beside it. **In process because every claim is a comparison between two FILES in this repository**, which no running service could be asked — the same shape as `xacml_pep.js`'s Dockerfile COPY-set check. The failure it exists to prevent is quiet: a column added to the driver and not to the script gives a database one column short and a service that is not allowed to add it, arriving as a permission error naming neither the column nor the file |
| `postgres_minted_writes.js` | **THE POSTGRES DRIVER'S MINTED WRITE AGAINST A `pg` THAT RECORDS STATEMENTS** (2026-09-12): every row lock taken in (handle, realm, key) order with upserts and deletes interleaved, and the change log chunked under the protocol's 65,535 bind parameters. A dispatched run deadlocked on `sts_minted` ~112 times, each failure re-queued a larger batch until `recordChanges()` wrapped the parameter count, and — with the retry fault `minted_persistence.js` section 5a pins — one worker reached 5.6 GB with the read barrier stalled behind it and the SCIM bulk load killed at thirty minutes. In process because both claims are about the ORDER and SHAPE of statements, which no request sees; `pg` is placed in the require cache for one `create()` call. Two mutants, both caught |
| `appconfig_persistence.js` | that a setting change reaches the store ON DISK, comes back the way the next start puts it back, and that a realm's settings and the process's are two different files |
| `minted_persistence.js` | **what this process MINTS across a restart, in product mode** (2026-09-06). That the journal names exactly the keys that moved and no others — including `push` and `shift`, which a Proxy over a real array does not see unless the mutating methods are wrapped, and which is how the audit ring is written; that every row is SEALED and the plaintext is not in the stored form; that a restore puts a session back and does NOT bring back a key that was deleted; that a restore leaves nothing for the next flush to write; **that another process's counter reaches the fan-in and never this process's own tally**, which is what stops the counts doubling on every restart; that retention DELETES rather than merely skipping; that development mode journals and writes nothing at all; and that the `ldif` store is refused with a reason. In process because every one of those is correct on every endpoint for the whole life of the process that got it wrong — the damage appears on the next start, in a different process |
| `minted_flush_order.js` | **ONE MINTED FLUSH AT A TIME PER PROCESS, SO A LATER VALUE IS NEVER OVERWRITTEN IN THE STORE BY AN EARLIER ONE** (2026-09-13). `persistence_minted.js`'s flush reads a value when it takes the journal and writes it when its transaction commits, and it had two callers that did not wait for each other; a session's ARRIVAL row and the sign-in that upgraded it went out in two transactions from one worker and the arrival committed LAST, so every other worker held an anonymous row — which is `sts_global_logout`'s intermittent `dispatch` failure (a WS-Federation session the sign-out could not see and `prompt=none` still honoured). A store that COMMITS WHEN TOLD TO makes the inversion a line rather than a race: the second write does not start while the first is in flight, the stored value is the newer one, a failed slow write brings nothing older back, five waiters become one write, and `reset()` forgets a write in flight. **The assertions run in a CHILD PROCESS** and its first version did not: `appconfig_persistence.js`'s un-awaited `persistence.stop()` reaches `minted.stop()`, which marks the module stopped after its flush — and with a flush now waiting on the one in flight, that mark landed inside this file after `reset()`, green alone and red in the suite. Four mutants caught, two equivalent (a marker clear the waiter's own clear makes redundant) |
| `replication.js` | **several processes against one store** (2026-09-06), and the four ways it goes wrong silently: applying your OWN writes (an exchange that never ends, with both services answering correctly throughout), applying OUT OF ORDER (the loser of a race wins on the reader, and nothing errors), advancing the high-water mark PAST a failure (a permanent gap nothing names), and ONE BAD ROW WEDGING THE PAGE (converging stops while the status still says coordinating). Plus an unknown change kind skipped rather than fatal, which is the ordinary case in a rolling upgrade, and **the apply running inside the change's own realm** — the single most likely bug in the feature, because an apply outside a realm context puts one realm's session in another silently. In process because none of it can be asked of a running service and reproducing it against a real database would mean two containers and a race. **Section 8b (2026-09-15): a read barrier waits out a transaction still committing** — `syncNow()` gave up after two hundred pulls that each met a hole and returned in a millisecond, so `sts_acme_enrollment`'s finalize in `dispatch` mode was answered from a copy missing the order behind the hole ("gave up at 20799 of 20804"). It is a deadline now; a hole filling after 400ms is caught up. The count-based loop and a 150ms deadline both fail it |
| `user_graph_permissions.js` | that a blue `reaches` line drawn from a TOKEN names the delegated permissions on it — both spellings a client may use, the `default permissions` fallback, the intersection that keeps `openid` off the label, and that a `reaches` line out of the delegation register says none of it |
| `xacml_pep.js` | **phase five, and the first file here to spawn a CHILD PROCESS.** **Since 2026-09-06 it also holds THE VERSION THAT CONTAINER REPORTS, in source-tree form**: that the Dockerfile copies `VERSION` and `common/version.js` and stamps them, that `pep.js` COMPUTES its `VERSION` rather than assigning a literal (it was the hand-written `'mock-sts xacml-pep, phase five'` — a Version column on the PDP's console that could not change), that it resolves the module across both layouts, and — the assertion that guards a DECISION rather than a defect — that **exactly one COPY writes into the image's `./common/`**, because a second file beside the thirty-line shim turns "the shim is the evidence" into "the shim plus whatever else we put there". The over-HTTP half, that the value survives a registration, mutual TLS, a directory attribute and a read-back onto the PDP's row, is `tests/vendored/sts_xacml_remote_pep.js`. That the XACML engine loads in `xacml-pep/` against a thirty-line helpers shim with NOT ONE of this service's own modules in its `require.cache`, and reaches the same decision there as here on the same policy — which is what makes "the engine is a library with no I/O" a checked claim rather than a comment at the top of seven files. That the container's Dockerfile copies exactly the modules `engine.js` loads, in order, which is this repository's own version of the parent project's standing COPY-set obligation, enforced rather than remembered. That the two implementations of section 7.2 agree over seven decisions under both biases — **and that the two biases disagree somewhere**, so the agreement is a comparison rather than two functions that both say yes. Plus the sync token being a digest of what would be SENT (a policy edited and edited back gives the ORIGINAL token, where a modification stamp would not), and the register's four decisions that each prevent a wrong reading. **A child process rather than a require, and that is not a preference**: `engine.js` primes `require.cache` so the host run and the image run load the same shim, and `run.js` runs every file in ONE process — so a require here would hand that shim to `xacml_service.js` next. **It asserts nothing about a RUNNING PEP and never did** — no registration, no pull, no HTTP at all; `xacml-pep/sync.js` is not loaded here. That half is `tests/vendored/sts_xacml_remote_pep.js`, which drives the container |
| `api_sessions.js` | **two claims.** First, that `ISSUANCE.SESSION` is asked at the FUNNEL — `startSession()` — and not at one door: it was asked only at this service's own sign-in screen while five other paths minted a session and never asked (a federated assertion, a SPNEGO ticket, a client certificate, a WS-Trust UsernameToken, the WebAuthn funnel), so an application narrowed to a role refused a password sign-in and admitted the same person through any of them. It pins that a refusal returns NULL and does not THROW — two callers wrap that call in a `try` that treats a failure as bookkeeping, so a thrown refusal would be swallowed and the session started anyway — that `gated: true` opts the one door that already asked out of being asked twice, and that a sign-in naming no application is allowed even when the decider refuses that very person, which is the existing rule and what keeps every caller unaffected. Mutation-tested against removing the gate and against throwing instead of returning null. Second, that the management API, SCIM and the SPIRE Server API sign in through **the one session store** — `authn.startSession()`, the same map browser sessions live in — with ONE ROW PER CREDENTIAL rather than one per request: twenty-six calls with the same fingerprint are one session, a different fingerprint is a different one, both appear in `logout.liveSessions()` and a global sign-out ends them through the same `terminate()`. **A register of their own was the obvious implementation and is what this file exists to prevent**: two answers to "is somebody signed in", with the wrong one being whichever surface a reader happened to look at (rule 3m). It also pins that one store does not mean one kind of ROW — an API session is drawn by its own surface, carries the fourth expiry rule (the only one extended by use) and reports calls rather than the relying parties a browser session carries — and, last so nothing above could pass by making every session an API session, that a browser session is exactly what it was |
| `xacml_service_own.js` | that the two policies this service decides its OWN boundaries with — `role-issuance` at the nine issuance sites and `access-control` at the five gated surfaces — are reported by the console, in four states: no override (both BUILT IN and both deciding, which is why neither has ever been in the editor's chooser), an enabled override (the stored document wins), a disabled one (neither falls back), and deleted (the built-in returns). **It is in process because two of those states are reached by DISABLING the override**, and disabling `role-issuance` takes issuance policy out of the decision for the whole service — over HTTP that is a change every other job in the run would meet. It found the sixteenth defect in `xacml/CLAUDE.md`'s list: `accessPolicy()`'s `typeof repository.get === 'function'` guard was false on every call, so `xacml.accessPolicy` had never once been honoured. Mutation-tested against both spellings of it — the assertion that catches a condition nothing ever satisfies is the one about the state FLIPPING when an override is created, not one about any single value |
| `xacml_monitor.js` | **the decision counters behind `/admin/xacml/monitor`, and the two distinctions a single number would lose.** That a NotApplicable which was REFUSED is counted as a refusal and NOT as a Deny — `allowed` is not `permit`, because what maps between the four decisions and the two outcomes is the PEP's bias; and that a Permit the PEP refused for an obligation it could not discharge is section 7.2 working rather than a contradiction. That `POST /xacml/pdp`'s row has `allowed` and `refused` **null rather than 0**, because this service produced that decision for somebody else's PEP and never saw the enforcement. That `allowed + refused + unenforced == decisions` on every row — the assertion the `unenforced` figure exists for, since a total that does not add up makes a reader distrust every other number beside it. **In process because two of the cases cannot be reached over HTTP at all**: a decision value the catalogue has never heard of, and a counter whose input throws. The second found a defect in its first run — `record()` incremented `decisions` and THEN read the outcome, so a throw left the row permanently one short with nothing to say why; the reads happen before any write now, and a throw records NOTHING |
| `scim_monitor.js` | **the traffic counters behind `/admin/scim/monitor`, and the three claims that page makes which nothing else would notice going wrong.** That a caller the GATE REFUSED is in no client row even when the credential carried a name — the assertion passes a principal WITH a refusal on purpose, because attributing traffic to an identity this service declined to believe is the one mistake there that would matter, and Basic and Digest both put a name on the wire. That an ABSENT MEASUREMENT IS NULL AND NOT ZERO: a success rate of 100% on no requests and an average of 0.0ms over no samples are the two most misleading numbers the page could print, because both look like a healthy service. And that a counter CANNOT THROW INTO ITS CALLER and, when its input does, **records nothing rather than half a row** — the same defect `xacml_monitor.js` found one module over, asserted here before it could be made again. Plus the ring being bounded while the tallies are not, and an application being told from a person by the credential's own answer rather than by the shape of the name. **In process because two of the cases cannot be reached over HTTP**: a detail object that throws when it is read, and the client cap, which would need two hundred and one distinct credentials on the wire |
| `access_policy.js` | that the XACML `access-control` policy makes OWNERSHIP a CONSTRAINT and not an alternative — a signed-in person reaches their own portal account and NOT somebody else's, for `manage-own` and for `read` separately, while the four ownerless surfaces go on behaving as plain RBAC. It exists for a regression: the policy was first written as three OR'd arms, "the resource requires nothing" was true for the portal (which narrows nobody), and it swallowed the owner comparison — so any signed-in person could reach any other person's account, with no error and no Indeterminate anywhere. `portal_access.js` stayed green throughout, because that file asserts the STRUCTURAL rule (the handler reads the identity from the session, never from the request) and this asserts what the POLICY decides once it has a trustworthy subject. Both halves are needed and neither implies the other. Mutation-tested against the OR spelling and against a wrong empty-owner reading |
| `key_residency.js` | that a private key is decrypted while it signs and not the rest of the time: nothing decrypted after `start()` (the startup decrypt is a KEK check whose plaintext is thrown away), the public half — certificate, kid, every curve key's public JWK, which is what the JWKS endpoint walks — readable with nothing decrypted, and the three retention words doing three different things. `resident` is asserted BEFORE the two purging words, so a `report()` that always answered "nothing held" could not pass the file; the `timed` case uses the key at 700ms and checks it is still held at 1400ms, which is what separates an IDLE clock from an absolute one. Every residency check is paired with a real RS256 signature verified against the published public key, so a feature that quietly broke signing would fail here. Mutation-tested against a purge that forgets the parsed `KeyObject` and against arming the timer on decrypt rather than on use |
| `pep_listener_certificate.js` | **A remote PEP's HTTPS listener certificate (2026-09-13)**, the half no request can choose. That a realm branch built BEFORE the `pep-tls` use case existed gets that one Issuing CA added under its EXISTING Intermediate with nothing superseded — the rebuild it replaced would pass every other section and revoke a product-mode realm's published chain on a restart; that the leaf is `serverAuth` only, not a CA, carries the names asked for and the key handed back, and that a node TLS client holding ONLY the service Root completes a verified handshake by that name through THIS realm's Intermediate (and trusting the Intermediate alone does not); the four refusals by code; that a reissue supersedes on the issuer's list and no private key is in the realm's row; the names a registration implies. **And the container's reload rules, in a CHILD** that requires `xacml-pep/pep.js` for `reloadListenerPair()` — a child for `tests/xacml_pep.js`'s reason, the shim priming `require.cache` — writing a missing pair, halves that disagree, a good pair, a new pair and a bad pair after a good one. The deployment half is section 1b of `tests/vendored/sts_xacml_remote_pep.js` |
| `tls_client_certificates.js` | **A PERSON'S TLS CLIENT CERTIFICATE AND THE IDENTITY GATE** (2026-09-13), in ONE CHILD PROCESS (the CA, the realm and the revocation register are process state; it also read the listeners' ports at require time until they were deleted). The certificate — `clientAuth`, CN and `urn:sts:person:` name, the rfc822Name, this realm's TLS Client Issuing CA, the key handed back, no private key in the register, the three refusals by code; the files — a PKCS#12 **OpenSSL** opens with the password whose client certificate is the one issued, an encrypted PEM key that opens and matches, a three-certificate chain; the gate — a TLS client leaf an identity in its realm, with or without its chain, and refused as one by an RFC 7523 key pair for the same person, a `clientAuth` leaf from the `assertions` authority, a `tls-client` leaf with no `clientAuth`, and one whose CN and SAN disagree; another realm's certificate refused at a main-port door and by `mtls.peerVerified()`; and over a REAL HANDSHAKE, on a listener the child builds itself with the MAIN PORT'S POSTURE (`requestCert: true, rejectUnauthorized: false` over `common/app`, the way `rfc8705_mtls.js` does), the Root in the truststore, `GET /tls/sign-in` signing the holder in to their realm and reporting the certificate presented and verified, the assertion key pair verifying and starting NO session as not an identity, somebody else's revocation refused, and the holder's leaving it signing nobody in — refused on revocation while the chain still VERIFIES. **Section D was 8443 and 9443 until 2026-09-16**; those listeners were deleted and the sign-in became a route on the main port, so the same four claims are made against it and NO STATUS is asserted for a refusal — the route answers 200 and says `signedIn: false`, because the handshake refusal 9443 made is a property of a socket that now carries every protocol and has no successor. Nine mutants, all caught — **three only after the fixtures were split so each breaks one rule**: the only refused leaf at first was an assertion key pair failing two checks, so deleting either left the other refusing it |
| `version.js` | **M.N.O, and the fact that every one of its failure modes is QUIET** — a wrong version still renders, still serves, still answers 200, and nothing anywhere goes red. That the repo-root `VERSION` file is `M.N` and nothing else (a stray third component, a `v` prefix or a trailing comment is ignored and the version silently becomes `0.0`, which is the module's deliberate never-fail-a-build behaviour and is exactly why the FILE has to be checked and not only the parser); that `BUILD_NUMBER` and `GIT_COMMIT` override, since a CI system setting one that was ignored would report a number nobody could match back to a build; and **that the stamp survives a restart** — two `load()` calls returning the same record, which is the entire reason a stamp exists rather than the version being computed at startup. Plus a corrupt stamp falling back rather than throwing, because six modules read this at require time and a throw is a service that does not start over a file whose job is to be printed in a footer. **The last section is the one that would have caught the state this replaced**: five surfaces draw a version and two of them read `package.json`, whose patch is a placeholder, so every build ever made reported `0.9.0` — so it asserts the SOURCE each module reads and not the string it renders, because two pages reading two different sources agree perfectly right up until they stop. **In process because two claims choose how the process was started** (a directory with a stamp and one without, twice) **and one is a property of the SOURCE TREE** (the manifests in step with VERSION), which no running service could be asked. **The over-HTTP half is in two owned jobs**: `admin_api.js`'s `everySurfaceReportsTheSameBuild()` — which is what caught the one-record bug, since a container never shows it — and `sts_xacml_remote_pep.js`, for the seventh surface. It failed on itself the first time it ran, and the fix is written down in it: the two files that document having STOPPED reading `package.json` say so in a comment containing the pattern, so the check strips full-line comments — a maintainer must never have to choose between deleting the explanation and deleting the check |
| `directory_indexes.js` | that the two caches over the directory never cost the property they exist beside: a write is visible to the very next read, however many kept-index writes surround it. The username index across creates, `invent: true`, and the TWO-WRITE shape a SCIM create actually is; the group index across a group create, a membership write and person writes on either side of it; and that the two answer separately, since one shared "is it current" flag is the tidy-looking mistake |
| `readme_ports.js` | **the README's *The ports* table, against the table that decides the ports.** It exists because that section is the exact shape this repository has been bitten by twice — the root CLAUDE.md's *a number written here as well went stale twice* — and because **the one mechanism this service already has for keeping a list honest cannot see any of it**: `/admin/sts-metadata` walks the live Express router, and a raw socket registers no route, so nine of the ten bindings are invisible to it. So it is held to `config.js`'s `SETTINGS` instead, in BOTH directions: a binding with no row (the failure people expect) and **a row naming no setting** (what a RENAME produces, and the one that goes unnoticed, because the table still looks complete). Defaults are compared too — a row naming the right setting and the wrong number is worse than a missing row, because a reader acts on it. Plus the COUNT in the prose above the table, asserted as *port settings + 1* rather than against a constant, so the KDC's second socket stays accounted for; and the Dockerfile's `EXPOSE` set against the same list, `88/udp` named separately. **In process because every claim is a comparison between two FILES in this repository** — the same shape as `postgres_schema.js` and `xacml_pep.js`'s COPY-set check. **It found two things on its first run**: the Dockerfile had never `EXPOSE`d 8888, the Kerberos test service, and neither had the comment above that list enumerating "the listeners that are NOT HTTP"; and a table row cited `spiffe.authRequired`, which stopped existing on 2026-09-06 when `global.mode` replaced it. Mutation-tested against a renamed setting, a wrong default, a bumped count and a deleted EXPOSE |
| `readme_settings.js` | **the SETTINGS tables in `docs/configuration.md` (README.md's until it became a landing page), against the table that declares the settings — `readme_ports.js`'s check pointed at the other two hundred rows.** It exists because of what that file caught and could not reach. On 2026-09-06 `common/mode.js` took over *is authentication required here*, a question that had had four answers, and `admin.authRequired`, `scim.authRequired`, `spiffe.authRequired` and `ssf.authRequired` stopped existing; the code was swept and the prose was not. Four days later this repository still documented all four as live, **three of them as ROWS in the settings table** — a default, an environment variable, a Change-while-running column — in the one document a reader consults to find out what they can configure. `readme_ports.js` had already caught the fifth instance of exactly this in its own ten rows and reported it the day it was written, which is the argument for this file in one sentence: **the check worked and was pointed at ten rows out of two hundred and ten.** It asserts the direction that goes unnoticed — **a row naming no setting**, what a RENAME and a REMOVAL both produce, because the table still looks complete — and the environment variable on every row that does name one. **It deliberately does NOT assert the other direction**, that every setting has a row: 102 of 304 had none when it was written, most of them recent (`keys.*`, `backupCodes.*`, `workers.*`, and `global.mode` itself), so asserting it would make the file red on arrival and disabled within a day. The count is LOGGED every run instead, so the gap is visible and can be closed deliberately — and when it reaches zero, make it an assertion. **In process because every claim is a comparison between two FILES in this repository**, `readme_ports.js`'s shape exactly |
| `admin_api_token_wiring.js` | **every path that runs a job arranges an `/admin-api` access token, which is a claim about the LAUNCHERS and therefore one no job can make.** It exists because the gate that landed on 2026-09-09 taught the two docker launchers to mint and missed the third path — the throwaway `run-report.js` starts itself, which is `./run-coverage.sh`, `--no-docker` and a bare `run-report.js`. CI's coverage job then ran the whole protocol half against a gated API with no credential and reported **nineteen failures for one missing token**, two of which described a SAML defect that did not exist. `sts_admin_api_auth.js` already fails loudly on an empty token and did exactly that — **detection was never the gap**; what nothing could see is the launcher that never minted one, because a launcher is not something a job can look at. So it asserts both docker launchers still call `tools/admin-api-token.js` and export the result, and that `run-report.js` pins a client secret, starts the service and mints — **in that order**, which is the assertion the file is really for: the seeded client reads `adminApi.clientSecret` while it is being seeded, so a secret chosen after the child is up is one the running service never heard of, and the failure that produces names a client secret and says nothing about ordering. Plus the `--service-url` case being REPORTED rather than silently tolerated, and the preload still being attached, since a token minted and never presented is the same outcome as never minting one. **In process because every claim is a comparison between FILES in this repository** — `readme_ports.js`'s shape, and nothing here starts a service or mints anything. Mutation-tested against removing the pin |
| `webauthn_policy.js` | **the WebAuthn ceremony's thirteen settings (2026-09-10), and the four ways a settings layer over a ceremony fails SILENTLY.** Twelve of the thirteen are values handed to a BROWSER, which no test can hold — so what is asserted is not *does the ceremony work* but the places where a wrong value produces an error indistinguishable from broken hardware. **The offer can never name an algorithm the verifier cannot check**, because `pubKeyCredParams` naming one produces a credential that registers perfectly and then fails EVERY assertion it is ever used for, weeks later, on somebody else's machine — the two tables are in two modules and the only thing keeping this true is that one is derived from the other. **An unusable setting falls back rather than producing an empty offer**, since `pubKeyCredParams: []` is refused by the browser with the same error it reports for a declined prompt, a missing authenticator and a timeout. **`authenticatorAttachment` is ABSENT and not the string `"any"`**, the dictionary having no value meaning *no preference*. **And the RP ID suffix rule is four lines that `endsWith()` alone gets wrong**: `mple.com` is a string suffix of `example.com` and is not a domain suffix of it, which is the exact confusion WebAuthn's binding exists to prevent — and the value only ever appears inside a ceremony a browser performs, so no request can ask what it was. The fifth section is the POLICY half, which is not WebAuthn at all, and it is here for `roles.js`'s reason: the refusal has to be at the ONE place a key is written, and asserting it at a door proves it for that door. Mutation-tested against six mutants, all caught — the filter removed, `endsWith()` alone, the attachment sent as `"any"`, `roleAllowed()` always allowing, the empty-offer fallback removed, and the per-person key cap removed |
| `spiffe_operations.js` | **THE TWO gRPC SURFACES AS OPERATIONS** (2026-09-12), and the second family to fill the request pool's operation channel after the directory. Forty-two of the forty-seven methods are dispatched and the FIVE SERVER STREAMS are not — that exclusion is read off the loaded protos rather than written down, so a method that becomes a stream, or stops being one, is caught here rather than by a client that hangs. Four claims a gRPC client cannot make, because a client on a socket cannot see which process answered it: that a dispatched method gives the SAME answer as the handler called directly; that a `bytes` field survives the channel **as a Buffer**, which is the trap the directory's codec never met and which is asserted through a REAL FORK rather than modelled — `structuredClone()` is the algorithm the documentation names and it downgrades a Buffer to a Uint8Array, so the first version of this section failed against a service that was working; that a refusal keeps its gRPC status while a non-status throw acquires NONE, since one is an instruction to a client and the other is a defect in this service; and that the caller — the one thing a worker cannot derive, because it is read off a connection the front process accepted — reaches the handler. **Section 7 is the rule the whole change turned on**: the worker table is filled only in a worker, because requiring `common/request_worker.ts` pulls `common/service_state.ts` in at module scope and `run.js` runs every file in ONE process — unconditional registration made `tests/spiffe_pki.js` red in the suite while it passed alone. Eight mutants, all caught; **two survived the first round and both were the FIXTURE**, this directory's standing lesson: the file was building the request shape itself and rebuilding the result by hand, so a codec sending `caller: null` and a worker dropping the status code both passed. The order of its sections is a CONSTRAINT — four of them register a probe method into module-wide tables, so the two that COUNT run first, and both ignore `Probe*` besides |
| `ldap_anonymous_bind.js` | **AN ANONYMOUS LDAP BIND REACHES THE SERVICE'S BIND HANDLER** (2026-09-18). node-ldapjs answered an empty-name, empty-password bind itself, so product mode's refusal (48) never happened; the `routeAnonymousBinds` option in the `rcbj/node-ldapjs` fork routes it to the handler. On two loopback servers of its own: the CONTROL (without the option the library answers success without asking a handler that would refuse), the option's server answering 48 while a named bind still succeeds, and as source that `ldap_server.js` creates both servers with the option and asks each whether it took. In process because the difference shows only in product mode and every stack the suite starts is development mode. `tests/vendored/sts_ldaps.js` is the over-network half and is what found it |
| `persistence_origin.js` | **WHAT A RESTART MUST NOT LOSE** (2026-09-18). A: the stores holding configuration, accounts, records and accumulators declare `retain: 'keep'` and the nonces, codes and pending flows `'age'` (the restore half is `minted_persistence.js` section 6). B: the postgres driver's `adoptOrigin()` against a fake `pg` whose `sts_cluster_claims` two drivers share, with a clock the file moves — the first process takes `n:<name>`; a second is refused while it is held and keeps a random origin; after the first's claim lapses a third takes it; the first's next write is FENCED before anything is written and its renewal refused; a release lets the next take it at once; no name keeps a random origin — and, as source, `persistence.js` adopting by node and slot and releasing at stop, and `request_pool.js` handing each worker its slot. C: the SCIM counts, what `POST /ssf/receive` received and the SSF sweep history each include another origin's contribution. D: `scim.digestCounts`, `scim.hobaSeen` and the sweep history are declared. Eight mutants here and two in `minted_persistence.js`, all caught |
| `user_register_fan_in.js` | **THE USERS REGISTER IS EVERY PROCESS'S** (2026-09-19). `admin_stats.users` is `merge: 'own'`, so another node's records, and this node's from before a restart, reach a process as contributions, and `userRows()` never read them: after a testidp redeploy `/admin/users` had 1 authenticated row out of 423, and `abcapp1`, an OAuth client known only by a client_credentials token, showed as a person with no directory entry. Asserted: a contribution alone is a row with its count and `isClient`; one person's record here and elsewhere is ONE row, summed, events merged in order; `knownUser()` (product mode's enrolment door) knows somebody only another process saw; the view edits neither side; a client_credentials token alone makes a client and a person's token does not; a rename adds a shared protocol family's count. Six mutants, all caught |
| `directory_read_security.js` | **THE PRODUCT-MODE LDAP BIND AND READ RULES** (2026-09-12), the half `directory_write_authorization.js` does not hold: anonymous, plain-listener and empty-password binds refused before a password is read; FAILED binds rate limited per DN and per address, with a correct password during a lockout refused like a wrong one and a success that never resets its address's count; a read on an unbound connection refused, the root DSE excepted; credential attributes never returned, invisible to a search FILTER and refused to a compare, administrator included; operational attributes unwritable; and the dispatched codec carrying the client address. **The filter assertion is asked in both modes**, so the product-mode zero is a refusal rather than a filter that matches nothing. Through `performOperation()`, for the write file's reason. Thirteen mutants, all caught — run as require-hooked COPIES of the module, because another session was editing it at the time and mutating a shared file in place would have raced them |
| `directory_read_authorization.js` | **WHO MAY READ WHAT OVER THE DIRECTORY'S SOCKET, PER IDENTITY (#106, 2026-09-23).** Through `performOperation()` in both modes: a person reads their own entry whole; with `ldap.directoryReadableAttributes` empty another person answers noSuchObject (`STS-LDAP-0013`) exactly as a missing DN, on a base search and a compare; widened, only the listed attributes show, a FILTER cannot see the rest (`(telephoneNumber=*)` matches the reader alone, a substring on another's number matches nothing), and a compare of an unlisted attribute is 50 (`STS-LDAP-0099`) whether or not the entry holds it; a group only to its members and without its member list unless `ldap.groupMembersReadable`; an application invisible and `ou=applications` answering with itself alone; Admin Read reads everything but credentials; a realm's own administrator reads their realm and is an outsider in the default one; an application's DN cannot bind (49, `STS-LDAP-0100`); the audit row counts `withheldEntries`; development answers every one. **Then over the wire**: a child per mode starts the directory's own LDAPS listener on 127.0.0.1:0 and a real ldapjs client asks the same questions (it runs this file's `overTheSocket()`). Seven mutants, all caught |
| `application_form_roles.js` | **EVERY ROLE THE APPLICATION REGISTRY DECLARES HAS A SECTION ON `/admin/applications/new`** (2026-09-12). `applications.declarationAttributes()` gives each family attribute a role, and three readers take that list: `createApplication()`, `GET /admin-api/applications/new`, and the console form — which alone draws a section PER ROLE, by name. So a new role reaches the API and silently not the form, and `delivery` (`ssfDeliveryEndpoint`) did exactly that from the day it was added until this file. A SOURCE check, both ways round, because nothing over HTTP fails when a field is merely absent and requiring the console would register every /admin route in `run.js`'s one process. Mutation-tested against the delivery section removed |
| `application_cors_field.js` | **`appCorsOrigin` ON THE CREATE FORM AND ON AN APPLICATION'S PAGE** (2026-09-18). The attribute configures CORS on every published endpoint and was accepted by `createApplication()` and the API but drawn by no form, because the form draws a section per ROLE of `declarationAttributes()` and it was not in that list. Through the functions the console's forms post to: the row (role `cors`, `families: []`, `everyFamily`) published by `GET /admin-api/applications/new`; a create with several origins and NO family stored normalised and de-duplicated; one value that is not an origin refusing the whole create (`STS-REG-0150`); the page's Add and per-row Remove; and what `common/cors.js` reads for a request naming that client, and for one naming none. The HTML is `application_form_roles.js`'s section check plus a render made by hand |
| `application_generate_secret.js` | **GENERATE SECRET ON `/admin/applications/new`** (2026-09-18). `applications.mintClientSecret()` is `oauth2.registeredSecretBytes` bytes, base64url, different every call; the `generate-secret` action names no application, hands one back and writes nothing; a create carrying it with OAuth 2.0 ticked and no method is recorded as `client_secret_basic`; and `common/app.js`'s realm link rewrite now reaches `formaction`, which it never did, so every `formaction` button in the console posted to the default realm from inside any other. The HTML is not rendered here, for `application_cors_field.js`'s reason |
| `audit_client_address.js` | **EVERY AUDIT ROW NAMES THE CLIENT'S ADDRESS** (2026-09-18), through `audit.withSource()`'s ambient source rather than a parameter. A row outside any source has none; inside one it carries the source's address with `::ffff:` taken off, across an `await`; a REQUEST source resolves through `client_address.js`; an address on the event wins; `recordAuthentication()` — handed no request — writes its `authentication` row, and the person's own event that `/admin/users` lists (2026-09-19), with the source's address, a caller-named address winning in both; `/admin/audit`'s and `GET /admin-api/audit`'s `address` filter is a PREFIX (`10.0.0.1` not inside `110.0.0.12`); and, in a CHILD PROCESS, a real bind on the directory's own listener and a datagram to the KDC's own UDP socket write rows naming 127.0.0.1. The HTTP path is not driven end to end here — `app.js`'s middleware is one line and the request resolution is section 3 |
| `consent_paging.js` | **MONITORING → CONSENT, BOTH HALVES PAGED THROUGH BOTH DOORS** (2026-09-18). `/admin/consent` paged its two tables and `GET /admin-api/consent` answered the whole register, so the door a script reads grew for ever. Both read `adminViews.consentPageView()` now, and this holds it to: one page of each half and never the list beside it, `counts` still the totals; `globalsPage` and `usersPage` each moving only their own table (the recorded half's pager was `consentsPage`, renamed after its array by the API's rule), `per` sizing both; a page past the end clamped; `q` narrowing only the recorded half; and a walk of every page reading every row once — what `tests/vendored/sts_consent.js` now does instead of reading page one. The markup (each pager keeping the other's page, every form's `back` keeping both, the search resetting its own) was checked by rendering the route below the gate |
| `gnap_httpsig.js` | **RFC 9421 HTTP MESSAGE SIGNATURES, RFC 9530 CONTENT-DIGEST AND RFC 8941 STRUCTURED FIELDS** (2026-09-12), the three documents GNAP's `httpsig` proof rests on — held to RFC 9421's Appendix B test vectors, because a signature base built by one function at both ends verifies and interoperates with nobody. In process because a vector is a chosen key, a chosen message and a chosen instant, and no request may name the instant |
| `gnap_token_formats.js` | **THE FIVE RFC 9767 TOKEN FORMATS AS LIBRARIES** (2026-09-12): one matrix — round trip, nbf/exp, audience, three binding kinds, access, tamper, another AS's key, garbage — run over all five, plus attenuation for the three that attenuate. **The two JWT formats joined the matrix later the same day** through an adapter, "another AS key" being another REALM's; it found that a JWT was minted from an invalid model without complaint and that a model with no `nbf` minted an EMPTY token, because `null` reached jsonwebtoken as a claim. **A zcap audience that is not a URI** is carried as `urn:gnap:rs:<id>`; that case was added after `tests/vendored/sts_gnap_rs.js` found every zcap token for a plainly named resource server refused, because every audience in this file was a URL |
| `gnap_mtls_trust.js` | **A GNAP KEY PROVED BY MUTUAL TLS, PINNED OR HELD TO A PKI** (#107, 2026-09-23), in a child on an HTTPS listener that asks for a client certificate as the main port does, with a foreign CA and two self-signed certificates OpenSSL makes at run time. The registry's combination of `gnap.mtlsTrust` and an entry's `gnapMtlsTrust` (stricter wins, `auto` by mode) and its two write refusals; then, at the grant endpoint: STS-GNAP-0277 and 0278 (a certificate key and a JWK), a pinned realm-issued certificate refused once revoked (STS-PKI-0118), and under pki the self-signed key refused (0287), a realm-issued certificate bound by value with its thumbprint recorded, rotation at the authority, an instance identifier proving a newer certificate, another entry's certificate (0291), one no longer held (0292), a revoked one, a foreign certificate bound by its RFC 8705 subject and refused for another (0290), none (0288) and two (0289); the override stricter and never weaker; and `auto` refusing in product and accepting in development |
| `gnap_request.js` | **WHICH LAYER REFUSES A GNAP DOCUMENT** (2026-09-12) — the depth and key bound, the ajv JSON Schema (bounds, URI formats, no control character in any member) and the RFC walker — asserted by error code, because over HTTP all three produce `invalid_request` and a schema that stopped applying would be invisible behind the walker. Plus two EXTERNAL answers: RFC 7638 section 3.1's thumbprint and RFC 9635 section 4.2.3's sha-256 and sha3-512 interaction hashes. **It found two things on its first run**: a control character inside an object member was reported as the `anyOf` string branch's "must be string", and a sub_id carrying a member its format does not describe was accepted, which RFC 9493 section 3 forbids |
| `email_factor.js` | **THE EMAILED CODE AND SIGN-IN LINK, END TO END** (#64, 2026-09-23), the whole stack in a child process over HTTP, reading the capture transport: off by default (no button, a hand-made POST refused); the opt-in refused for an unverified address and making a verified person a second-factor holder; a code as the second factor — only a HASH on the step, the verified address in the layout, a wrong code counting down, the right one (typed with a space) signing in `amr ["pwd","otp"]`, `acr "mfa"`, kind `email-code`, once; a resend too soon refused and the step ENDED at `emailCodeAttempts`; a code as the first factor `amr ["otp"]`, `acr "1"`, with an unknown account and an unverified one answered by the SAME page and mailed nothing; a link refused without its binding cookie on the GET and the POST, the GET spending nothing, Continue signing in and the waiting page saying so; the failure limit turning the factor off; nothing offered without mail. Three mutants caught (no browser binding, a plain secret on the step, a decoy that mails) |
| `error_codes.js` | **EVERY FAILURE HAS A CODE, THE TABLE IS COMPLETE AND CURRENT, AND NO CODE REACHES A CLIENT** (2026-09-12). Five claims about `common/error_codes.js` and the tree around it: the table is well formed and in order; every code the source uses is registered and every registered code is raised somewhere; `docs/error-codes.md` is exactly what the table generates; **every line matching a FAILURE PATTERN has a code within a few lines or a `// error-code: none — <why>` exemption with its reason** — the check that makes future failures carry a code, and the list a new protocol's own error helper must be added to; and a code literal never sits on a line that writes a response. The last claim is also asserted as BYTES: a small express app with the call-log funnel's own recorder on `finish`, a route that marks and refuses the way a protocol handler does, the raw status line, headers and body searched for the code, and the audit row read back carrying it — including a marked 302, which must be recorded as a refusal. **It scans `xacml-pep/`** although that is a second container, because its codes are in the one table. `scan()` is exported so a maintainer can check one directory while adding codes to it |
| `worker_pool.js` | the four ways moving a computation into another process goes wrong: that a worker computes the SAME BYTES (literal equality for the eight deterministic algorithms; cross-verification for the three whose ECDSA half is randomized and must be), that the event loop is genuinely FREE while it does — counted in timer ticks, against an unpooled control that manages none — that a session's jobs go to one worker and unnamed ones spread, and that a SIGKILLed worker FAILS its jobs with a sentence rather than leaving a promise nobody settles. Plus `workers.count = 0` producing the same bytes here, and a realm being refused the setting at both ends |
| `protocol_endpoints.js` | **EVERY PROTOCOLS PAGE LISTS THE CONCRETE ENDPOINTS OF THE REALM IT IS READ IN** (2026-09-13). In a CHILD PROCESS, because it loads the whole stack. `admin-core/protocol_endpoints.ts` and `SECTIONS` agree both ways (a Protocols page with no row, a row naming a page not under Protocols); every listed route is registered and described in `sts_metadata.ts`; a route taken off the child's router is flagged `registered: false`; every HTTP URL is absolute under the request's base with `{name}` segments; under a realm every URL carries that realm's prefix, a named authorization server is listed by id at both discovery addresses, LDAP at the realm's base DN, and the ONE client-certificate row with no prefix (it was the two TLS listeners until 2026-09-16; both were deleted and a client certificate is presented to the main port); `respond()` adds the member for the page and not for a page drawn under its tab; and `GET /admin-api/saml2` answers the same rows while `/admin-api/users` answers none. Five mutants in the module, all caught — **the `registered` flag only after the router case was added**, since every route in the table really is registered |
| `realm_support.js` | **THE TRUST REALMS TABLE ANSWERS FOR EVERY PROTOCOL FAMILY** (2026-09-18). `/admin/realms` and `GET /realms` draw *What is separated, and what is shared* from `realms.realmSupport()`, which called itself the whole list and was short by ten families (GNAP, Shared Signals, XACML, federation, the certificate authority, ACME, EST, SCEP, the portal, logout) with nothing to say so. Each row names the `sts_metadata.ts` PROTOCOLS cards it answers for in `cards`; in a CHILD PROCESS (PROTOCOLS requires the console) it asserts every card is named by exactly one row, every name is a card, and every row has a unique family, a state the page draws, a discriminator, a note and a `cards` list (empty for a row that is not a protocol family). Four mutants through a `NODE_OPTIONS` require hook — a row removed, a card renamed, a card claimed twice, a row with no `cards` — all caught |
| `realm_domain.js` | **A TRUST REALM'S DNS DOMAIN** (2026-09-18). The shape (one label, a numeric top-level label, a bad character, a leading hyphen and a 64-character label each `STS-CORE-0099`; lower-cased, trimmed, an internationalised name kept as its A-label); a realm with none given `<id>.<global.domain>`, whose base is the `dc=<id>` beneath the default realm's every realm had before; one with its own rooted at the RFC 2247 mapping, not under the default realm's; the names seeded from it (URN entity IDs, the trust domain, the Kerberos realm in capitals, Kerberos still off, the OpenID4VP client id keeping its id suffix, the service principal NOT seeded) and a caller's override winning; `STS-CORE-0100` for another realm's domain and the default realm's; a domain INSIDE another realm's accepted; `STS-CORE-0101` for a change and the same domain again accepted; through `performOperation()`, every realm's base in the root DSE, a tree outside the default realm's reachable, a DN in no tree refused, and a subtree search from the parent returning none of the nested realm's entries; and the invented mail address in the ambient realm's domain. Every realm it makes is removed. **Its first run found a committed defect**: #74 had added a second `function inRealmOf(id, fn)` to `ldap_server.js`, hoisted over the socket's `inRealmOf(dn, fn)`, so every LDAP operation on any non-default realm's DN answered from the default realm's store — renamed `inRealmById`. Six mutants, all caught |
| `ldap_logout.js` | **a sign-out reaching a directory connection the process answering has neither seen nor can close** (2026-09-09). In LDAP the connection IS the session (RFC 4511 section 4.2), and a request worker binds no port — so `boundConnections()` there answered "there are none", the sign-out driver had nothing to end, and a global logout in `dispatch` mode reported that it had ended everything while a bound connection went on being signed in. Five claims: that a mirrored process reads the front process's list and that no socket rides along in it; that a sign-out driven through the real `logout.terminate()` ASKS the process holding the socket and reports the row ended; that an ask which cannot be made or is refused reports the connection NOT ended, with the reason, rather than claiming success — which is the original bug one layer up; that the two processes spell the header the same way, since a rename in either is silent in both; and that the front process's snapshot is published AFTER the bind handler has run, because ldapjs sets the bound DN only then and a snapshot taken inside the handler names nobody. **The end-to-end job cannot say which half broke, and in one launcher it was not asking at all** — `sts_global_logout` sees only a socket that is still open, so "the worker never saw it" and "the worker could not close it" look identical from there; and until 2026-09-09 that job dialled 389 on the HOST under `./local-run-tests.sh`, got ECONNREFUSED, noted it and passed. This file needs no port and cannot degrade to green that way |
| `front_process_writes.js` | **that a write by the process holding the UNDISPATCHED sockets marks every request worker stale** (2026-09-09). The read-your-write generation moved in one place — a worker announcing its commit — and this process answers on five socket families that never reach a worker at all: the two TLS listeners (their own handler, not `app`), the directory, the KDC and SPIFFE's gRPC pair. So a sign-on session minted by a client certificate on 9443 was invisible to the worker answering `/logout`, and a global sign-out reported ending everything while leaving a live way in. **Four families since 2026-09-16**: the two TLS listeners were deleted and the certificate sign-in is a route on the main port — `app`, but kept in this process by `request_pool.js`'s `NEVER_DISPATCHED` (`/tls` is on it), so its writes are still this process's own — and the file is unchanged, because what it asserts is `noteLocalWrites()`'s comparison of two integers and never was about any one family. **Intermittent by construction** — the worker catches up on the replication poll, so it failed once in a three-mode run and passed when the job was run alone, which is the least useful evidence there is. The decision underneath is a comparison of two integers and that is what is asserted: the first sample is a baseline, a growing count moves it by one, a repeated or BACKWARDS count moves nothing, and with `workers.readYourWrite` off nothing moves at all. `noteLocalWrites()` takes the count rather than reading it, precisely so the decision is testable apart from the store that counts |
| `closed_sets.js` | **THE CLOSED SETS, IN PROCESS** (#86, 2026-09-26). A: `common/closed_sets.ts`'s rules one by one — the sentence, `collect()` finding flat, array-item, nested and `$ref`'d enums and leaving `oneOf` to ajv, a `$ref` cycle ending, only flat fields reaching the console register, an empty form or query value absent, case exact, a repeated field and a comma-separated array parameter each of their values, and a page's `''` row a fallback only on a page with no actions. B, in a CHILD (loading the management API loads most of the service): `registerRoutes()` against a fake app captures every POST handler and each is called with one enum outside its set — every one answers 400 with the sentence and never reaches the operation (116 on the day); every control in the console register refuses outside each field (154); no console control is held to two different sets by two routes; and the one list written out by hand held equal to its owner (CAEP's `initiating_entity` to `ssf_events`' `CAEP_COMMON_MEMBERS`) |
| `request_barrier.js` | **that a request no worker answered releases its read-barrier ticket** (2026-09-11), and it is the other half of `front_process_writes.js`'s subject. Every dispatched request takes a TICKET; it ARMS when this process has piped the response out; it CLEARS when the worker that answered announces its flush covered it. `proxy()` armed the ticket from `upstream.on('error')` too — the path where the worker never answered and the client is handed a **502** — and the worker, having never run the handler, announces nothing ever. **So the ticket sat armed for the life of the process and every read after it waited the full 2,000ms bound and then served stale anyway.** It is a cliff and not a slope: the run that found it left a service 41 minutes idle with 5,521 stuck tickets, `GET /admin-api/ldap/directory?per=1` taking 2.6s, and all four bulk-load jobs failing on a **10-second CONNECT timeout** rather than on any assertion — the SCIM one got through 536 of 5,000 creates in 405s against 93s for all 5,000 in the same suite's single-process mode. **Nothing could see it**: every answer was correct, and the only signal was the line the barrier prints when a flush is merely slow. Asserted in process on `front_process_writes.js`'s argument — the decision is integers and the integers are what was wrong; a real pool would test node's unix-socket proxying, which is not what wedged. Five sections: the mechanism working (an armed ticket blocks another worker's reader and a commit releases it, and the answering worker never waits for itself), the regression, a ticket that is merely SLOW surviving its first timeout, the 30-second reaper, and the switch honoured. The reaper takes its clock as a parameter, because thirty seconds of a run to assert one comparison is thirty seconds nobody spends. **Four more sections since 2026-09-13**, for the storm that wedged `sts_directory_bulk_load_scim` in `dispatch` mode: (6) a reader that TIMED OUT leaves the waiter list, and a commit announcement against ten thousand live readers and six thousand in flight stays cheap — the leak held 10,000 settled waiters, and walking each against the outstanding set made one announcement 980ms of CPU (74s for fifty with the per-waiter walk put back); (7) readers behind one worker share ONE sync round, a reader wanting more waits for exactly one queued round, and a late round never moves a worker's generation backwards; (8) with real sockets, a client that gives up releases a request queued behind `workers.maxSockets` — `aborted` is not emitted for a complete body, so nothing did; (9) an announcing worker that was behind is not marked current. Six mutants for 6–8 and one for 9, all caught |
| `request_proxy_replay.js` | **that a dispatched request none of whose bytes reached its worker is sent again, one that was delivered never is, and every dispatched request has a connection of its own** (#77, 2026-09-26). Real sockets in `request_barrier.js` section 8's arrangement: an express front calling `proxy()` and a unix-socket worker that misbehaves on purpose. (1) the CI failure's shape — the first connection dropped on accept, before a byte is written — answered 200 by the worker, once, on a second connection; (2) a request the worker read whole and then dropped is a 502 and ran once; (3) a body over the 1 MiB copy bound is not repeated; (4) five requests through a one-connection agent reach the worker on five connections, each saying `Connection: close`, with the client's `Keep-Alive` and the header its `Connection` named stripped and the framing kept |
| `request_worker_replacement.js` | **that a request worker which dies is replaced** (2026-09-26). (1) `replacementFor()`'s decision: the dead worker's own slot, the first free one for a worker with none, nothing while stopping, after giving up, or past the configured size (the surface pool sized on its own). (2)–(4) drive the REAL `fork()` and `reap()` with real child processes running a stub worker this file writes to the temp directory (`pool.useWorkerModule()`; `begin` in, `ready` out, an HTTP server on the socket): a SIGKILLed worker and one that exits on its own are each replaced in their slot and answer on their socket; `stop()` forks nothing; a stub that answers `ready: false` is ended and retried, and after three failed starts the pool gives up with nothing left running. Two mutants (no replacement, no end for a failed start), both caught |
| `flush_waiters_and_commit_counts.js` | **A FLUSH ASKED FOR DURING A FLUSH IS ONE QUEUED FLUSH, AND A CHANGE ROW IS COUNTED AT COMMIT** (2026-09-13). `persistence.flush()` gave every caller arriving during a flush a waiter of its own, and a postgres store has a caller per write, so under a load the waiters re-chained on every commit and never drained: measured, over 3 GB allocated in fifteen seconds in that line, a single-process postgres service killed by `JavaScript heap out of memory` during the 50k LDAP load, which the suite read as `fetch failed`. In a CHILD PROCESS (it opens an ldif store): two callers during one flush get one promise, twenty thousand get one, it is not the running flush, and a write made after they arrived is on disk when it settles. In process against a `pg` whose COMMIT the file releases: nothing counted before COMMIT returns, nothing for a failed COMMIT or a rolled-back statement. Plus a source check that a worker's `wrote` compares with its last announcement. Four mutants, all caught |
| `worker_server_certificate.js` | **THE LISTENER CERTIFICATE BELONGS TO THE PROCESS HOLDING THE LISTENER** (2026-09-12), which is the SECOND thing in this service to be a socket rather than a row — the root CLAUDE.md said a second would need the argument made again rather than the mechanism copied, and this file is what the argument owes. `POST /admin-api/pki/build-root` is dispatched like any other request, so it lands on ONE request worker, and two processes then disagreed about a certificate neither could see the other holding: **the worker re-certified its own copy of the handed-in record** and pinned a leaf under the new Root while the socket it dials on the loopback still presented the old one, and **the front process adopted the new hierarchy and went on serving the old leaf**, so `trustAnchorPems()` correctly refused to publish an anchor at all and `GET /tls/server-certificate` answered a bundle terminating nowhere. Six jobs of the suite's dispatch mode, not one of whose failures mentions a certificate. **Section A runs in a CHILD PROCESS** and that is not fastidiousness: the environment has to be set before `tls/tls_server.js` loads, and a module loaded once per process cannot be asked the question twice — `tls_trust_anchor.js`'s first section forks for the same reason. It asserts that a handed-in process presents and pins what it was handed AFTER `pki.start()` has built it a hierarchy of its own — **and that it HAS one**, which is what makes the line above an assertion rather than a description of a process with no PKI — and that it takes a SECOND hand-off, since the first one travelled in `process.env` and is a snapshot. Section B is in process because only a caller inside one can replace a Root without its branches (`pki_anchor_drift.js`'s argument), and it pins that reconciling is FREE while the chain is good, repairs it when it is not, and that the bundle the pool sends out carries the anchor and the chain and **no private key** — a worker pins and reports this certificate and never presents it. Seven mutants, all caught |
| `listener_branch_adoption.js` | **THE LISTENER IS RE-ISSUED UNDER THE PROCESS BRANCH THIS PROCESS HOLDS, AND A DISPATCHED FRONT PROCESS NEVER BUILDS THAT BRANCH BESIDE A WORKER** (2026-09-13). `sts_pki_distribution_points` failed in `dispatch` mode only — one CRL address named by two Intermediate CA (Process) certificates — because the socket chained to a branch the front process built itself after a worker's `build-root` published the Root ahead of the branch it was rebuilding, and the reconcile then called that listener current because the Root signs both. Five claims, in a CHILD PROCESS (it replaces the Root twice): a branch rebuilt elsewhere under the same Root re-issues the listener; a Root ahead of its branch is WAITED FOR — nothing built, listener untouched, `listenerAwaitsBranch()` true, and `certifyRegistered({ repairBranch: false })` refusing too; the branch arriving re-issues; the default reconcile still repairs; and through `request_pool.js`, the fallback armed and disarmed and ONE pass at a time with calls coalesced (the reconcile swapped for one that counts overlaps). Eight mutants, all caught, run through a require hook rather than by editing shared files |
| `tls_trust_anchor.js` | **what a loopback caller PINS this service against, before and after its certificate acquired an issuer** (2026-09-11). The hour `pki.start()` began certifying the listener certificate, three callers broke together and not one of them said what had changed: `common/oidc_rp.ts`'s back channel — so the admin console answered *Signing in did not complete* with `unable to get local issuer certificate` under it — `ssf/ssf_http.ts`'s push to this service's own receivers, and `tests/tools/trust.js`, which hands every node-driven job in the protocol half its `NODE_EXTRA_CA_CERTS`, so that half could not open a connection at all. All three pinned `serverCertificate().certPem`, which OpenSSL takes as an anchor while it is SELF-SIGNED and refuses once it is certified — **so the pin does not weaken, it refuses everything**, which reads as a broken server. **Asserted as a HANDSHAKE on an ephemeral port and not as a comparison of subjects and issuers**: every version of this that compared fields passed on a truststore OpenSSL would reject, which is exactly the state the service was in. The invariant it holds is that the ANCHOR IS SELF-SIGNED — the Root when there is one, the leaf when there is not — rather than that it is any particular certificate, so `npm test` and a supplied `tls.certificateFile` keep working. **Section 1 runs in a CHILD PROCESS**, and that is not fastidiousness: `run.js` runs every file in one process and `pki_hierarchy.js` builds the hierarchy, so the before state is gone by the time this file runs — it passed alone and failed in the suite, which is the shape of flake that gets a test deleted rather than fixed. Section 4 is a SOURCE check, for `version.js`'s reason: what went wrong was the wrong FIELD being read, and a fourth caller added tomorrow would pass a behavioural one |
| `scim_conformance_fixes.js` | **WHAT THE TWO SCIM CONFORMANCE HARNESSES FOUND, HELD IN PROCESS** (#206, 2026-09-26), one check per fix, over HTTP to a listener in a child process: `/Schemas` lists no member the directory cannot hold and `emails.type` offers only `work`; a Group member has no `display` and a `$ref`; `schemas` survives `?attributes=`; a manager goes out as an id with a `$ref`, never a DN; a removed `members` is left out rather than sent as `[]`; a duplicate email is stored once, a `home` one refused, and `primary` never invented; `userName eq "UPPER"` finds the lower-case name while `id` still compares exactly, and `active gt true` is `invalidFilter` (`STS-SCIM-0082`); `If-Match` on a write is 412 (`STS-SCIM-0081`) and `*` is not; an unknown path is a SCIM 404 (`STS-SCIM-0080`); a PATCH on a whole extension, adding a value naming its own schema and removing every attribute; and `scim.inventOnCreate` both ways. So a change to `scim/` that brings one back fails `npm test` without either harness installed |
| `scim_basic_off_thread.js` | **A SCIM BASIC PASSWORD IS HASHED IN THE WORKER POOL, NOT ON THE REQUEST THREAD** (2026-09-21). `attemptBasic()` is synchronous, so in product mode it ran scrypt (about 70ms at the default cost) on the thread answering every other request; `authenticateSpent()`, the path `scim.ts` takes, now asks `credentials.verifyAsync()` first and leaves the verdict on the request. With the two verifiers replaced by counters: the asynchronous path verifies once in the pool and never on the thread, and the decision is the pool's verdict, accepted and refused; the synchronous `authenticate()` still verifies on the thread; a verdict is not used for a password it was not reached for; a disabled Basic scheme verifies nothing; a failing pool falls back to the thread. Two mutants, both caught. The same measurement moved `sts_directory_bulk_load_scim` off Basic onto a `scim:write` access token, because 10,000 password hashes were the whole of what it measured in the production modes |
| `scope_policy.js` | **A SCOPE IS TIED TO THE CLIENT** (#110, 2026-09-22). `common/scope_policy.ts`'s truth table in both modes: this service's protected scopes (admin:*, the SCIM and Shared Signals scopes by their SETTINGS' names, the debugger permission) refused `STS-OAUTH-0577` to a client that does not declare them and allowed to one that does; every other scope free in development and, in product, held to the client's `oauthAllowedScope` or — with none — the default set (`STS-OAUTH-0578`), a permission and another application's client_id left to their own rules; the seeded clients declaring what they use; `tokenSet()` NARROWING a refresh and an exchange with one audit row (`STS-OAUTH-0579`); delegated permissions enforced in product whatever the setting says; and the debugger permission spelt as `debugger_access.ts` spells it. **In process because both modes and a realm setting are needed in one run, and a grant carrying its scope from earlier is a refresh token minted before the allowance was removed.** The HTTP half is `sts_scope_policy.js` |
| `delegation_policy.js` | **WHO MAY ACT FOR WHOM AT WS-TRUST AND RFC 8693** (#108, 2026-09-23). `common/delegation_policy.ts`'s truth table in both modes — only `enforced` differs: delegation by `appAllowedToDelegateTo` (an audience resolved to its application first), impersonation needing `appTrustedToImpersonate`, the subject groups, `stsNotDelegated` and the console roster, an unallowed or absent target, the resource-based `appAllowedToActOnBehalfOf`, a person as intermediary, `may_act` standing in for the flag and the groups but not the target, the self case; the DENY-ONLY XACML layer (a policy denying action-id `delegate` for one intermediary, and nothing else changed); `stsMayAct` to `may_act`; the attributes' grammar (`STS-REG-0194`) and `list()`; WS-Trust through `handleRst()` — `wst:RequestFailed` as the SOAP 1.2 Subcode and the SOAP 1.1 faultcode, a person requester (`STS-WSTRUST-0019`), development's "would have been refused"; and the console's door (`usersAction()`) and the paged view. The HTTP half is `sts_delegation_policy.js`; the token endpoint's half is `token_exchange_product.js` |
| `tls_resumed_chain.js` | **A RESUMED TLS SESSION STILL HAS A CHAIN TO WALK** (2026-09-21). Node hands a server a resumed session's LEAF alone — no `issuerCertificate` — while `socket.authorized` stays true, so `common/revocation_status.js` found the leaf's issuer "neither held here nor in the chain that was presented" and product mode's hard-fail refused a certificate that had verified; the remote XACML PEP resumes on every reconnect, so in `single-node` it never registered and the XACML jobs failed the same way in `cluster`. On a real TLS 1.2 listener with a client that resumes: the control (the resumed session really has no chain), `fromSocket()` handing it the chain its full handshake showed and the walk then reaching the anchor, an UNVERIFIED leaf remembered for nobody, and — as source — `request_pool.js`'s `peerOf()` reading the chain through `fromSocket()` rather than a walk of its own. Two mutants (no hand-back; remembering unverified chains), both caught |
| `truststore_admin.js` | **THE CLIENT-CERTIFICATE TRUSTSTORE'S GATED DOORS** (2026-09-12) — `/admin/tls/trust` and `/admin-api/tls/trust/{add,remove}`, the runtime door product mode did not have. Five claims: the primitives against the real `tls/tls_server.js` in THIS process (a strict add refused WHOLE on one unreadable block, a duplicate counted and not added, a remove under either fingerprint spelling, a fingerprint not held removing nothing), with every anchor it adds removed in a `finally` and the truststore asserted identical afterwards, because the array is process-wide; `admin.setTruststore()` refusing a partial object; the actions and the view through that slot, the house refusal sentence, paging and the audit row; the front-process pin in `NEVER_DISPATCHED`, realm prefix and query string included and `/admin/tls` and `/admin-api/tlsx` excluded; and product mode's 403 naming the new doors. **Claims 2, 3 and 5 run in a CHILD PROCESS**, because requiring `admin-ui/admin.ts` registers the whole console on the shared app in `run.js`'s one process. Ten mutants, all caught, **two only on the second round**: a remove that never called `applyAnchors()` survived a check on `clientTruststoreOptions().ca`, which rebuilds from the array on every call — replaced by a REAL HANDSHAKE on a registered listener — and a refusal that lost the console path from its sentence survived a search of the whole JSON body, which carries that path in a member of its own |
| `pki_hierarchy.js` | **ONE ROOT FOR THE SERVICE, AN INTERMEDIATE PER SCOPE, AN ISSUING CA PER USE CASE** (2026-09-11), and four claims no running service can be asked. **THE BOUNDARY MOVED DOWN A TIER**: until that date every realm had a Root of its own, so "does this chain to our Root" WAS the realm boundary — one Root makes that test true of every certificate this service has ever issued, so it silently stopped being one, and what replaced it is that the path must pass through THIS realm's own Intermediate. Over HTTP the two are indistinguishable: both refuse the foreign certificate and only one of them refuses it for a reason that survives the next realm being created. **THE STARTUP ORDER** — the hierarchy must exist before a key is certified and before anything binds, and the only way to assert an ordering is to run it. **WHAT IS NOT A LEAF AND WHY** — this section is empty of families now: **the eleven post-quantum keys were the last, until 2026-09-13**, when they came UNDER the realm's JOSE Issuing CA and `tests/pq_key_certification.js` took the positive claim; **the SPIFFE authority was the second until 2026-09-11**, when it came UNDER the Root. What this file keeps of that section is the narrower claim that no SVID is in the certificate register, because `issueUnder()` records nothing, and `tests/spiffe_pki.js` asserts the chain that replaced the absence. **THE FOUR EDITING ACTS ARE FOUR DIFFERENT THINGS** — a renewal must leave every key verifying and a reissue must not, which is one assertion apart and a world apart. Eight mutants, all caught; **one survived the first round and the fixture was the bug**, which is this directory's standing lesson: the key-set section used a realm id nobody had created, so `stsKeysFor.of()` handed it the DEFAULT realm's keys and certificates were being written into a row those keys never read |
| `pqc_support.js` | **THE POST-QUANTUM ICON ON `/admin/pki` AND `/admin/keys`** (2026-09-13): the classifier and the mark. **Every algorithm in every spelling** — each of `pq_jose.PQ_ALGS`, and each of the vendored registry's signature and KEM ids as its id, its lower-case key-material spelling and its OID, plus node's key types — comes out with the right kind (`pq`, `composite`, `kem`), and twenty-five classical spellings come out unmarked; a table, because a page shows only the keys it holds. **A certificate is classified by its KEY, not its signature**: an ML-DSA key under an RSA Issuing CA is marked, an EC key under an ML-DSA issuer is not, and an EC key whose certificate carries an alternative ML-DSA-65 key is a `hybrid` — the last two are certificates this service does not issue by itself, so they are built here. **The mark, in a child process** (the renderer requires the console): nothing for a classical key, one labelled image per kind with the sentence as `title` and `aria-label`, the hybrid dashed, no script or image request, a label escaped, and a legend drawn with the renderer itself. Three mutants — classify by the signature, ignore the alternative key, the hybrid drawn like the rest — all caught |
| `certificate_details.js` | **THE CERTIFICATE DETAILS DIALOG ON `/admin/pki` AND `/admin/crypto-metadata`** (2026-09-13): the model, the catalogue and the one renderer. **The fields against OpenSSL** — fingerprints, serial, dates and the RSA modulus against node's `X509Certificate`, the Subject Key Identifier, `basicConstraints` and the extension count against `openssl x509 -text` — because the model reads with pkijs and a field it misread would otherwise be wrong only on a page. **The chain is built by signature, not by name**: an IMPOSTOR carrying the Root's exact subject (a certificate no request can make this service hold) must not complete the path, and beside the real Root the walk must take the one whose key verifies. **The catalogue**: both fingerprint spellings, a PEM refused as a handle, a code recorded and not serialised, and the realm boundary both ways — a realm's own Issuing CA refused in the default realm and opened inside it. **A composite ML-DSA key named as the composite** — the first screenshot of the dialog read "Key: Ed25519", because the vendored inspector summarises a composite by its classical half. **The renderer in a CHILD PROCESS** (requiring it requires the console): a modal dialog, an X and a real Close `<button>` both returning to the page's section, no script, no handler, no `target`, a `from` that is not an element id dropped, a refusal still opened, and a hostile subject and label escaped. Three mutants — a walk by name only, every realm's branch in the catalogue, an unescaped label — all caught. The over-HTTP half is `sts_admin_api_operations.js`'s `theCertificateDetailsAnswer()` |
| `pq_key_certification.js` | **THE POST-QUANTUM KEYS ARE ISSUED FROM THE EMBEDDED CA** (2026-09-13), which reversed the last entry on `/admin/pki`'s *what one anchor does not cover*. Six claims, none of them in an HTTP reply — the JWKS is byte for byte what it was. **THE TABLE**: `pki.PQ_JOSE_IN_X509` names exactly `pq_jose.PQ_ALGS`, and each composite maps to the X.509 id carrying the SAME domain-separator label, because a mapping to the wrong composite is a certificate over a key whose signatures verify as nothing. **THE WIRING**: warming a realm's keys certifies all eleven there and none in another realm — with a REAL realm, for `pki_hierarchy.js`'s fixture lesson. **THE CROSSING IS A CHECK, AND IT IS THE POINT**: `common/vendored/CLAUDE.md` forbids wiring `pq_jose.js` to the certificate encoder, and what crosses is the public key alone — so a `pq_jose.js` signature is verified under the VENDORED X.509 reading against the key read back out of the CERTIFICATE (not the register's copy, which would compare a value with itself), and the same signature against the untranslated JOSE bytes of an ECDSA composite is shown NOT to verify, which is why the one 0x04 translation is written out. **REALM ISOLATION** — each leaf verifies in its realm and is refused in another for the Intermediate reason, with nothing new written for it. **PUBLIC HALVES ONLY, IDEMPOTENT, SUPERSEDED, RENEWABLE** — every private-key getter throws and nothing reads one; a second certification issues nothing; a different key in a slot supersedes the old certificate at the JOSE Issuing CA; and renewal works for the composites, whose keys node's OpenSSL cannot read, because the register now keeps the subject key. **THE ML-DSA LISTENER CERTIFICATE**, in a child process because `tls.certificateAlgorithms` must be set before `tls_server.js` loads: certified at startup, and re-issued with the RSA one when the Root is replaced. That half needs node 24 and says so rather than passing silently on 22. Four mutants — no 0x04, no idempotency, no generation-time wiring, a renewal that parses the certificate — all caught |
| `pki.js` | **the certificate authority, and the check a security claim rests on** (2026-09-10). Three of its four sections cannot be reached over HTTP at all, and the reason is the same each time: **what `common/pki.js` HANDS OUT is deliberately less than what it holds**, so an assertion that the Root's key is not in the reply is about a function that has already run — over HTTP the only evidence would be the absence of a string. The PATH CHECK, whose interesting inputs are chains a client cannot be made to send (a complete chain to somebody else's anchor, every link of which verifies; a leaf under an intermediate that did not sign it); the ALGORITHM PAIRING, where an EC key's digest is decided by its CURVE and a P-521 key under SHA-256 is legal, verifying and nobody's intention; and the REALM BOUNDARY, which over HTTP is two base URLs and here is the store itself. Plus the lifetimes read off the vendored PROFILES rather than a table, the leaf carrying no extendedKeyUsage, and a leaf clamped to its Issuing CA's expiry. **It found two real defects on its first run**: the issued JWK's `x5c` was dropping the Issuing CA (a `slice(1)` over a list that does not contain the leaf), and `verifyLeaf()` grafted this realm's tiers onto a chain that already terminated, so a foreign chain was refused with a message about a signature when the thing that is wrong is the ANCHOR. Mutation-tested against six, all caught — and the clientAuth one **survived the first round** because the assertion matched on an extension NAME the encoder never writes; it matches on the OID now |
| `kerberos_principals_paging.js` | **THE TWO LISTS ON `/admin/kerberos/principals` PAGE ON `peoplePage` AND `servicesPage`** (2026-09-13). The view passed `pagedRows()` a `param` option that `pagingOf()` never reads, so both lists followed a bare `?page=` while the page's links wrote the other two and every next link reloaded page 1 — with the nav's own *page 2 of 3* line saying otherwise, because the route re-attached the right name to it. Asserted: each parameter moves its own list and not the other, in the paging and in the rows; a bare `?page=2` moves NEITHER (which tells the fix from one making both follow one parameter); every link the page draws names a parameter the view reads; following the services link draws rows 4–6; and the People links on that page keep the services position. The two list functions are replaced for the file and restored in a `finally`, because more than one page of real service principals is that many random keys sealed on directory entries. With the bug put back, six assertions fail |
| `pki_key_pair_paging.js` | **THE APPLICATIONS AND PEOPLE TABLES ON `/admin/pki` ARE PAGED** (2026-09-13), separately on `issuedPage` and `personsPage` with one `per`. Four claims: the JSON keeps `issued` and `persons` WHOLE with `issuedPaging`/`personsPaging` beside them; the page draws exactly the slice each asks for, with Applications on page 2 while People is on page 1; every paging link and every Take-off button's `back` carries both tables' state; and `pkiReturnTo()` rebuilds that `back` — page numbers kept, a `//host` and a CRLF dropped — into the address the 303 names. **In process because the page is behind the console gate**: the route's own handler is called with a request carrying only a query. It issues P-256 key pairs to five applications and three people so both tables have Take-off buttons, and removes all of them. Six mutants, all caught; **one survived the first version** — the Applications Take-off losing `back` — because those applications held only a declared issuer and so drew no button |
| `pki_authoring.js` | **THE CERTIFICATE & KEY CONFIGURATION PANE'S MODEL** (2026-09-10), and four things a running service cannot be asked. **THE FORM AGAINST THE PAGE**: the field table is declared in `common/pki_authoring.ts` and DRAWN in `admin-ui/pki_admin.ts`, and the two going out of step is the failure this arrangement is most likely to produce — a field parsed and never drawn falls back to its default on every round trip, one drawn and never parsed is a control that does nothing, and NEITHER IS AN ERROR ANYWHERE. **THE SIX LINE GRAMMARS AND THEIR REFUSALS**, which is the interesting half: a test that checks only the accepted forms passes just as happily against a parser that DROPS what it cannot read, and that is the outcome that matters here because a certificate quietly missing a name VERIFIES. **THE THREE SUBJECT RULES** — "a Common Name somebody typed is never overwritten" is a statement about two calls with a person's edit in between, and no request expresses it. And **what is stored against what is handed out**, where over HTTP the evidence is the absence of a string. It does NOT re-assert the encoder, which is the parent's file held to ~240 certificates against OpenSSL over there; what it checks is that the FORM reaches it, by OID rather than by extension name — `pki.js` records the mutant that survived a round for matching on a name the encoder never writes. **It found a real defect in its first run** (`pki_selected` absent whenever the store was empty) and a second through its over-HTTP half. Fourteen mutants, all caught — one after the fixture grew the case that reaches it: `!!raw` for a flag is right for everything a BROWSER sends, and wrong for the `"false"` a JSON caller may |
| `spiffe_authority.js` | **THE SPIFFE AUTHORITY IS THE SERVICE'S AND NOT ONE PROCESS'S** (2026-09-08) — the declared store, the Buffer encoding that survives the journal's `JSON.stringify`, prepend-and-retain rotation, and the sequence moving. **IT RUNS IN A CHILD PROCESS SINCE 2026-09-11 AND THAT IS NOT FASTIDIOUSNESS**: what it asserts is the SELF-SIGNED path, which is unreachable once a hierarchy exists — and `run.js` runs every file in one process with `pki_hierarchy.js` building one. Read in this process it passed alone and failed in the suite, which is `tls_trust_anchor.js`'s lesson word for word. That path is still three supported configurations (`pki.autoBuild: false`, a Root that could not be built, and every in-process caller), and the file now ASSERTS it is on it — `authoritySource === 'self-signed'` — rather than assuming, because with a hierarchy every section below would be about a different authority and would fail in a way that reads as a broken store. Its own fixture bug is recorded in it: the first version read `state()` once at the END, so three before-rotation claims were compared with an after-two-rotations answer |
| `spiffe_pki.js` | **THE SPIFFE AUTHORITY IS A LEAF OF THE SERVICE'S OWN ROOT** (2026-09-11), which reversed a documented non-goal that `/admin/pki` carried on the page. Four claims, three of them unreachable over HTTP. **THE PATH IS VERIFIED BY OPENSSL AND NOT BY THE LIBRARY THAT BUILT IT** — `pkijs` encoded every certificate in the chain, so asking `pkijs` whether it verifies is this implementation agreeing with itself (`pki_revocation.js`'s argument, and `crypto_module.js`'s); node's `checkIssued()`/`verify()` are OpenSSL. **THE `pathLen` ARITHMETIC**, which is the whole reason the feature needed a design: `NewDownstreamX509CA` asks that authority for a CA, so the use case carries `1` and the realm Intermediate is widened to `2`, and **both numbers or neither** — widening one gives a chain that encodes cleanly and is refused at the far end of somebody else's path builder, naming neither certificate. It reads the encoded numbers, with the TLS branch as the control that must stay at 0/1. **THE ANCHOR IS SHARED WHILE THE AUTHORITY IS NOT**, which is the single sentence that made a per-realm SPIFFE authority coherent with four sockets answering in one realm (a realm has sockets of its own since 2026-09-12) — two realms' bundles compared byte for byte, and an SVID from each building a path to the other's anchor. Plus the chain an SVID actually carries, in both shapes the two gRPC surfaces take. **Section 4b guards a fix nothing else can reach**: a tier's stored `signatureAlg` is what its PARENT signed it with, and both `certify()` and `issueUnder()` handed it to the primitive as the algorithm to sign a leaf with using that tier's OWN key — the two coincide in every branch whose tiers share a key family, which every branch this service had ever built was, so the SPIFFE authority is the only certificate here under which the mutant is reachable. **It builds the hierarchy itself** rather than relying on `pki_hierarchy.js` having run, because a file that passes only when something else ran first is the flake this directory records getting a test deleted for. Eight mutants, all caught |
| `pki_revocation.js` | **CRLs AND OCSP: THE REGISTER, THE TWO DOCUMENTS, AND THE ROTATION THAT FILLS THEM** (2026-09-11). The over-HTTP half is `tests/vendored/sts_pki_revocation.js`; what is here is what a request cannot ask. **A CRL AND AN OCSP RESPONSE ARE BINARY DOCUMENTS THIS SERVICE SIGNS**, so what is worth asserting is their STRUCTURE — v2, the cRLNumber, the AKI, the per-entry reason — and it is read by **OpenSSL rather than by pkijs**, which built them: parsing them with the library that wrote them is this implementation agreeing with itself, the argument `tests/crypto_module.js` makes about keeping xml-crypto as a dependency nothing requires. **ROTATION IS WHAT FILLS THESE LISTS** and asserting it means reissuing an Issuing CA and counting what landed on TWO authorities — the leaves on its own list, the replaced CA on the Intermediate's — which no HTTP call does and then lets you look at. **THE NEGATIVES ARE MOST OF THE FILE**: `unknown` for a serial the authority never issued, `unauthorized` for a request built from ANOTHER issuer (a different branch and a different danger — that certificate exists and is good at its own responder; it was a signed `unknown` until 2026-09-13, which no client could verify), `unauthorized` for an authority that does not exist, `malformedRequest` for bytes that are not DER, four refusals that must put nothing on a list, and a release that must refuse everything but a `certificateHold`. **THE OCSP REQUESTS ARE BUILT BY OPENSSL IN THIS PROCESS**, and both halves of that are load-bearing: pkijs's `toSchema(true)` returns CACHED TBS bytes so a serial set afterwards never reaches the wire, and in development mode the hierarchy is regenerated per start so a request built by an earlier process names a CA that no longer exists and EVERY answer is `unknown` — green, asserting nothing. **Section F is a regression test and it cost the Root CA**: `saveRow()` counted a row with no tiers, no objects and no intermediate as empty and removed it, the SERVICE row holds a Root and nothing else, and `revoke()` saves through that function — so a rotation revoking the Intermediate it replaced DELETED THE ROOT, reported success, and surfaced one call later as `trustAnchorsFor()` returning an empty array. **The first version of that section did not catch it**: a permanent revocation leaves entries on the row, and a row with entries is not empty by any reading, so the mutant survived. It had to hold, check, RELEASE and check again — mutation testing decided the ORDER of three lines |
| `crl_directory_publication.js` | **THE DIRECTORY COPY OF EVERY CRL** (2026-09-13), and it exists because two mutants SURVIVED the over-HTTP job beside it (`sts_pki_distribution_points`) for reasons no socket can get around. **A LIST PUBLISHED WITH NO REALM AMBIENT** — the startup pass and the refresh timer — landed in the DEFAULT realm's store under a `dc=<realm>` DN, so every realm's `ldap://` distribution point answered `noSuchObject`; over HTTP every publication a job can cause happens inside a request, and a deferred publish inherits that request's realm through AsyncLocalStorage, so it lands correctly BY ACCIDENT. Here it is one `publishAll()` at top level. **PRODUCT MODE**: an unbound BASE search of a `cRLDistributionPoint` entry is answered where every other unbound read is refused, and the suite runs every stack in development mode, where no read needs a bind — so neither the exemption nor its narrowness is visible on the wire. The scope probe is based AT the CRL entry, because one based at `ou=crl` is refused by the path test first and passed against an exemption that ignored scope. Also: one DN per authority (the process branch and the default realm shared one), and RFC 4522's binary option naming ONE attribute whichever way a request or a filter spells it. Nine mutants, eight caught, one EQUIVALENT (the path test alone removed, with the objectClass test still guarding the same entries) |
| `database_metrics.js` | **THE `/admin/database` CONTRACTS THAT NEED NO DATABASE** (2026-09-11). `npm test` has no PostgreSQL and must not need one; what this holds is everything about that page decided by this repository rather than by a server. **EVERY STATEMENT IS A READ AND A LITERAL**, asserted against the SQL rather than trusted: no probe may contain a write verb, a statement separator or a parameter — the role this service dials with can INSERT, UPDATE and DELETE on six tables, so sending it something else is the one thing this page could get catastrophically wrong. The write-verb check matches WHOLE WORDS, because `UPDATE` is a substring of `n_tup_upd` and a naive `indexOf` fails on the very columns the page exists to draw, which is how a check like this comes to be deleted for being wrong rather than fixed. **THE PROBE TABLE AGAINST THE PAGE'S SECTIONS, BOTH WAYS**: a probe whose group has no section is run on every render, costs a round trip and is shown to nobody, and a section with no probe is an empty heading that reads as a feature that broke — neither is an error anywhere, which is `pki_authoring.js`'s field-table argument one layer out. **AND THE CLAIM THAT MAKES THE PAGE SURVIVE A MAJOR VERSION**: the statistics views are asked for ALL their columns, so the page is right on a server nobody tested it against — the alternative fails silently, because a column this build named and that server lacks reads as a blank cell. It also pins that no probe GUARDS itself on the server version: asking whether the server is at least 17 and then asking for `pg_stat_checkpointer` is two round trips and a second thing to get wrong. **It found a real inconsistency on its first run** — the `pg_stat_replication` probe named seven columns without composing, which would have been the one place on that page where *everything available* quietly meant *the seven somebody thought of*. Five mutants, all caught. **IT DELETES `STS_PERSISTENCE_MODE` AND `STS_DATABASE_URL` AS WELL AS `CONFIG_FILE` SINCE 2026-09-12**, and the reason generalises: section E reaches the no-database state by starting no store, which was the whole of it while this file was only ever run by `npm test`. Both launchers run the suite once per mode and export each mode's environment into the runner, which hands `process.env` to every in-process job — so in the `postgres` and `dispatch` modes this file read `persistence.mode` as `postgres` while having opened nothing, asserted `memory`, and failed twice, in two modes, about a page that was correct. **Deleted rather than set**, for the reason the `CONFIG_FILE` line above it gives: the state it wants is the DEFAULT, so it removes what is overriding the default rather than writing the default back over it |
| `key_agreement_storm.js` | **A REALM CREATED AT RUNTIME MUST NOT MAKE ITS SIGNING KEYS IN EVERY PROCESS** (2026-09-12). `common/pki.js`'s realm watcher ended with `certifyKeySet(id, keySetProvider(id))` under a comment saying it certified keys *if they have been generated already* — and that provider is `helpers.stsKeysFor.of()`, which GENERATES. So it did not certify a realm's keys, it MADE them, in every process that saw the realm appear: on a `--modes=dispatch` run, FOUR key sets in four processes within 95ms, all but one arbitrated away afterwards. They converge and they do not converge BEFORE answering, which reached the suite as `sts_jwt_bearer_grant` section 7 reading an RSA key from `/oauth2/jwks` on one worker and decrypting on another — `oaep decoding error`, naming nothing. **IT CANNOT STAND UP FOUR PROCESSES** and does not try: what it pins is the contract that made the race unavoidable, which is a property of one handler. **THE ASSERTION IS THE CACHE AND NOT A CALL COUNT** — a first version counted calls to providers it installed itself, and `run.js` runs every file in ONE process where `service_state.js` has already installed its own, so the counters measured a function nobody was calling. **AND IT WAITS FOR THE BRANCH RATHER THAN FOR A DURATION**, because an *it did not happen* assertion passes for free against a handler that has not run yet. Section C reads `common/service_state.ts` as SOURCE, which a mutation run showed was owed: the fix lives in two files and deleting the production wiring left every other assertion green. Three mutants, all caught. It removes its realm in `finally` — `realm_isolation.js` asserts that only the default realm is left, so a realm left behind fails a different file about a service that is correct |
| `secret_store_report.js` | **THE `/admin/secrets` CONTRACTS THAT NEED NO SECRET STORE** (2026-09-12). `npm test` has no OpenBao, no AWS and no Azure and must not need one. **THE ONE THING THAT PAGE COULD GET CATASTROPHICALLY WRONG IS PRINTING A SECRET**, and that is most of this file: the deny-list guard is asserted DIRECTLY, against objects shaped like the answers the providers really give — `auth/token/lookup-self` puts the live token in a member called `id`, a kv-v2 read nests it under `data.data`, `GetSecretValue` answers `SecretString` — because a guard tested against invented shapes is a guard tested against nothing. **AND THAT IT DOES NOT DELETE EVERYTHING**, which is the half that would otherwise pass every assertion above and leave the page useless: the `mounts` probe DID answer `{}` against a store with four engines mounted, because it named its members `secret` and `auth` and both are on the list. Then a REAL report, with both secrets read and held by the process, asserted to carry neither value — the state in which a leak is actually possible rather than a report built over nothing. **THE LEDGER BOTH WAYS**: a successful read recorded, and a failed one recorded rather than swallowed, which is the row an operator most needs and the one a service that did not start cannot show anybody. **TWO SECRETS IN ONE FILE ARE ONE STORE AND TWO FIELD PROBES**, which pins the two dedup rules at once. And every provider against its probe table and every secret against its note on the page, BOTH WAYS ROUND — neither is an error anywhere else, which is `pki_authoring.js`'s field-table argument two pages along. **IT DELETES THE NINE SECRET-STORE ENVIRONMENT VARIABLES** for `database_metrics.js`'s reason above, and moves settings through the ENVIRONMENT rather than `config.setOverride()` for `database_password.js`'s: every one of them is restart-only, so an override would be refused and the file would silently assert against the defaults |
| `cache_registry.js` | **MONITORING → CACHES** (#74, 2026-09-17). Checks:<br>• the registry refuses an incomplete descriptor whole (`STS-CORE-0094`);<br>• size, valid/expired and the hit ratio are right against a held clock, and the ratio is null before any lookup;<br>• a row carries exactly five members, whatever its descriptor returned, so a value planted in a descriptor's rows never reaches the reply or the page;<br>• a throwing descriptor costs only its own rows;<br>• **every store `docs/caches.md` names is registered by its owner** (the `OWNERS` table), and a real lookup (`jose_kid`) moves a real counter;<br>• the view model pages entries soonest-deadline first, clamps a page past the end, answers an unknown name with `found: false`, and takes the first of a repeated `cache`;<br>• the page, called below the gate, links every store, keeps `cache=` on every pager link, draws the trail back, draws no value, and marks an unknown name `STS-ADMIN-0021`;<br>• **every real store reports a finite bound and says whether it is enforced or structural** (2026-09-18); `makeRoom()` drops the oldest, drops the expired first, or refuses and logs `STS-CORE-0097` once, and counts each; a per-realm store compares its fullest realm; a store reporting no bound is flagged `STS-CORE-0096`; the cluster snapshot carries the figures and no row; and GNAP's real signature history answers `full` at a bound of two;<br>• the other nodes: the page draws another node's snapshot and this node's front process, not this process or a node that left, and `cluster.js` (as source) attaches the snapshot without taking one on the heartbeat.<br>Eight mutants, all caught — refusal ignored, no-bound not flagged, an owner unbounded again, GNAP's full ignored, no snapshot on the row, this process not excluded, fullest realm replaced by size, the bound lost in the snapshot.<br>The test's own stores are `forget()`-ed in a `finally`. |
| `encryption_report.js` | **WHAT `/admin/encryption` REPORTS** (2026-09-11), and the two things behind that page nothing else can check. **THE TABLE AND THE CALL SITES AGREE**: the page names each sealed class by a LABEL (`DATA_CLASSES` in `admin-ui/encryption_admin.ts` — six when this was written, more since), the labels are passed from the modules that seal, and a class described and never sealed or a label passed with no row is an error NOWHERE — the page renders perfectly either way. It is `pki_authoring.js`'s field-table argument one layer along, and it is checked in both directions, including by sealing something under an invented label and requiring it to appear in `unclassified`. **THE COUNTERS COUNT**, at the one funnel both operations pass through rather than at the call sites, because a total assembled from call sites is wrong the first time somebody adds another and is wrong SILENTLY. The valuable assertions are the negatives: a decryption under the wrong key-encryption key still THROWS and is counted as a FAILURE and not as a decryption (nine hundred decryptions and nine hundred with four hundred failures are very different reports); a caller that passes no label is still in the TOTAL, under `(unlabelled)`; and no PEM, no ciphertext and no key-encryption key appears anywhere in the reply. **`present` and `persists` are asserted as DIFFERENT QUESTIONS** — development mode HAS a key, an ephemeral one, and persists nothing, so a report carrying only the first would say *encrypted* about a service whose key dies with the process, which is why every write site tests `keystore.persists()` and not `keystore.sealed()`. Four mutants, all caught; **one needed the byte assertion tightened** — the decrypt counts the plaintext it produced, so a check made after a round trip passes even when the encrypt counts nothing |
| `assertion_grant.js` | **RFC 7521 and RFC 7523's encryption matrix, and the two claims that look alike** (2026-09-10). The whole flow is `tests/vendored/sts_jwt_bearer_grant.js`'s; what is here is what a request cannot ask. **Ninety-six combinations** — sixteen key management algorithms against six content encryption ones, wrapped and unwrapped — because a wrap and an unwrap that disagree produce a ciphertext that parses perfectly and an authentication tag that does not verify, and because ninety-six token requests is not a test. `PROTOCOL_CLAIMS` as a LIST rather than as a behaviour: over HTTP the only observable is that one claim did not appear, which is satisfied by a token with no claims on it. The nested-JWT checks, the PBES2 ceiling, and that a certificate presented WITH a signature is not evidence unless this service issued it. **The PBES2 salt mutant SURVIVED the first round**, which is `ldif_codec.js`'s lesson said again: the wrap and the unwrap derive through ONE function, so they agree with each other whatever the salt is built from — a mutant that dropped the algorithm name from it passed all ninety-six. It is checked against **RFC 7517 Appendix C's published vector** now, which is an EXTERNAL answer and the only kind that means anything about a derivation. Eight mutants, all caught |
| `saml_assertion_grant.js` | **RFC 7522's eleven items as a TABLE, and the assertion the whole design rests on** (2026-09-11). The flow is `tests/vendored/sts_saml2_bearer_grant.js`'s; what is here is what a request cannot ask. **The eleven items of section 3 as a loop** — twenty ways of being wrong is twenty token requests over HTTP and one table here — with the three whose LENIENT reading is the usual bug asserted by name: an expiry on EITHER `NotOnOrAfter` satisfying item 4, an expired `<SubjectConfirmation>` DISCARDED and the live one beside it used (item 6's own distinction, which nearly every implementation collapses), and an unrecognised `<Condition>` making the assertion Invalid rather than being ignored (item 11 by way of SAML core §2.5.1). **The two attribute sets are disjoint, which is a property of the MODULES and not of a request**: a comparison of two name lists, plus a read of both modules' SOURCE, because the failure being guarded against is somebody adding `|| fields.oauthAssertionCertificate` as a fallback — invisible to every behavioural assertion. And **the crossing**: a real leaf this realm's own CA issued minutes earlier is REFUSED when it is the other profile's, and the SAME certificate registered under the RFC 7522 attribute is accepted — one attribute is the whole difference. **It was the first file in `tests/` to require from `tests/vendored/`**, and the reason — which every later one shares — is in its header: there is ONE independent XML Signature implementation here and a second copy would be a second place for exclusive canonicalization to be wrong, which is the one thing a wrong copy would hide. **It found a real defect on its first run**: an `ID=" "` passed the "is there an ID" check, so every whitespace-ID assertion in the realm shared one replay key — the first remembered and every later one refused as a replay of a document nobody had sent. The ID is trimmed now, which is what a schema-aware parser does to an xsd:ID anyway |
| `signer_chain_validation.js` | **THE SIGNER CERTIFICATE'S WHOLE CHAIN, VALIDATED WHEREVER AN RFC 7523 OR RFC 7522 SIGNATURE IS** (2026-09-13). Four sections: `pki.verifyLeaf()` refusing a certificate forged under a PERSON's own issued leaf (`STS-PKI-0158` — every link verified and it passed through the realm's Intermediate, and it was accepted) and an Issuing CA presented as the signer (`0159`); `pki.verifySignerChain()`'s three anchors — a realm leaf registered alone or in x5c spelling, another realm's leaf refused with its branch, an external chain accepted root-first and refused without its root or alone, a self-signed certificate pinned even with `cA=TRUE`; what must hold at every use — an expired leaf and an expired pinned certificate (`0157`), a chain through an end-entity certificate, a CA without keyCertSign and a broken pathLen (`0158`), a CA or a no-digitalSignature leaf as signer (`0159`), a certificate holding another key (`0160`), an unreadable one (`0161`), and a registered realm leaf refused once its branch is rebuilt; and the three verifiers refusing a signature that VERIFIED — the grant (with a bare key still accepted and the forged x5c header refused), client authentication, and RFC 7522 by value (chain beside it in the same value), managed and pinned. In process for `application_credentials.js`'s reason: every input is a hierarchy nobody would deploy. Thirteen mutants run through a require hook, all caught; **the keyCertSign one survived the first round** because the end-entity fixture is refused on basicConstraints before KeyUsage is read, so a CA whose only fault is its KeyUsage was added |
| `jose_certificate_header.js` | **A SIGNED TOKEN NAMES THE CERTIFICATE CHAIN OF ITS KEY** (2026-09-13). Three sections: the use-case table against the eleven `config.js` rows (an enum of exactly none/x5c/x5u/both, `x5u` by default, runtime so per realm, in a group a protocol page draws, no stray row); a SOURCE SCAN failing on any JWS signing call outside `common/crypto.js` that names no use case and carries no `// certificate-header: none — <why>`, and on a row no signer names; and, in a CHILD PROCESS for `refresh_token_encryption.js`'s reason, the whole path — a token from `/oauth2/token` carrying `x5u`, that address answering the PEM chain leaf to Root with every link verified by OpenSSL, the token verifying with the key IN the leaf, the leaf naming its CRL and OCSP responder, then `x5c`, `both`, `none` byte for byte, one use case moving without another, a realm's override staying in its realm, `signed_metadata`'s cache seeing the setting, ES256, HMAC, no request, a pinned base, a register row over another key giving nothing, the refresh token's inner JWS, a SET, and the endpoint's 404s. Eleven service mutants through a require hook, one source mutant on disk, all caught. **Its first protocol run found the Domain Linkage Credential must be exempt** — `vc_did.js` holds its header to the DIF rule of `alg` and `kid` only |
| `jose_kid.js` | **A SIGNED TOKEN'S `kid` MAY BE ITS KEY'S RFC 9278 THUMBPRINT URI** (2026-09-13). In process: RFC 7638 section 3.1's example key to its published thumbprint and RFC 9278's URI, an AKP key hashing exactly `alg`, `kty` and `pub`, `keys.kidFormat` an enum of exactly the library's formats (internal by default, runtime, not per-process, in a drawn group), and `common/jose_kid.js` off and on — the published kid, the second JWKS entry over the same key, a key with no thumbprint falling back with no entry, a lookup accepting either name and neither a foreign URI nor a foreign kid. In a CHILD PROCESS: an access token and ID Token under the internal kid, then the URI; the JWKS listing every signing key twice with the RSA key still first and the second entries before the encryption keys; the token verified by node against the entry its kid names and an earlier token against the internal one; `x5u` unchanged; ES256 and ML-DSA-44 under their keys' URIs; RS256 and ES256 SETs verified by `ssf_events.verifySet()`; `/gnap/keys` naming the URI; off again restoring both while a URI still names the key here; and a realm's own override reaching that realm and not the default one. **Its first run failed C17 on the FIXTURE**: a process-wide override reaches every realm, as any setting does. **Writing the `signed_metadata` check found a real defect**: that document's cache key named the algorithm and the certificate header and not the kid format, so a switch went unseen for a minute — C1b fetches it before the switch so C4b meets a cached copy. Fourteen mutants through a require hook, all caught (the AKP row removed is caught as a throw, which the harness reports as a test that could not run) |
| `used_assertions.js` | **AN RFC 7523 OR RFC 7522 ASSERTION IS ACCEPTED ONCE, EVER** (2026-09-13). Six claims about `common/used_assertions.js` and its callers: ONE history keyed by the document and not the use (a grant then a client assertion is a replay; a SAML `ID` equal to a `jti` is not); spent only when the response finishes 2xx, released on a non-2xx and on a `close` before `finish`, with a racing replay refused on the reservation; the ldif store keeping a claim across a restart **with no other write after it** — the first version claimed three assertions and a claim that was never written survived, because the second one's RELEASE rewrote the whole file; the postgres claim as ONE `INSERT … ON CONFLICT` whose update touches only an expired row, against a `pg` that records statements; the token endpoint's two questions about one client assertion getting one answer per request, and the same JWT then refused at the grant verifier's key; and none of the three verifiers keeping a cache of its own. **The live half is not here and could not be**: twenty-five concurrent claims against a real PostgreSQL, the least-privilege role, and a version-3 database refused until `schema.sql` is re-run were run by hand against a throwaway container and are recorded in `common/CLAUDE.md` 3ae. Thirteen mutants: nine at the first round, two after the fixture above, one by the source check, one equivalent |
| `cluster_single_use_credentials.js` | **SECOND FACTORS, LINKS, ENROLLMENT CREDENTIALS AND THE BOOTSTRAP, SPENT ONCE ACROSS NODES** (2026-09-14, #46). `persistence.clusterStore()` is replaced by a stub with postgres's semantics answering on a later tick, so two calls genuinely interleave; a second node is a second concurrent call or a STALE COPY of the entry written back. Seven claims: `cluster_counters.advance()` refuses a repeat and a lower value, accepts an always-zero counter and fails closed; one TOTP code at two nodes is accepted once and an entry whose `lastCounter` went backwards does not reopen the step; one recovery code twice is accepted once, a code a stale write-back resurrected is refused and the entry repaired, a spend writes back another node's code, and the reconcile repairs one nobody presents; a WebAuthn challenge answered once, a counter below the highest refused with the challenge given back, a synced passkey's zero accepted; an activation and a reset link spent once and a released claim taken again; one EAB key bound by one of two accounts, one SCEP challenge redeemed once, a nonce another node claimed refused; one bootstrap for two cold-starting nodes, the loser running nothing, a store that cannot be asked running nothing. What it does not reach: the portal, ACME finalize, the SCEP transaction wait and the SPIFFE join token handlers, which are argued in their files and were not run against two nodes |
| `cert_enrollment.js` | **THE CERTIFICATE-ENROLLMENT CORE ACME, EST AND SCEP ISSUE THROUGH (2026-09-13)**, in process: the nine issued profiles and the five refused as a TABLE, the PKCS#10 proof of possession for RSA, ECDSA, Ed25519 and ML-DSA and a CSR signed with a different key (which no honest client library produces), an ML-KEM key refused and accepted as a template, the identity rule, every name rule refused BY NAME, all nine profiles issued with their extended key usages read by OpenSSL and their chains verified by node, what is kept on the entry (and a server-generated key withheld from the directory dump), the per-entry cap, re-enrollment superseding, both credentials single-use, and realm isolation of credentials AND certificate authentication. The administrator roster is STUBBED, because a member left in `admin-write` closes the console's empty-roster door for every later file (the rule that still holds where no bootstrap account was seeded, which `run.js`'s process is — `admin-ui/admin_rbac.ts`). Fifteen mutants: fourteen caught (two after the fixture was fixed — a non-canonical kid that never passed the regex, and no certificate presented that its entry did not hold) and one EQUIVALENT, recorded in the file |
| `acme_jws.js` | **THE ACME ENVELOPE, READ STRICTLY** (2026-09-13): the flattened JWS and its protected header, account keys against RFC 7638's published thumbprint, the self-describing Replay-Nonce's MAC and realm, the External Account Binding, RFC 9773 certificate identifiers against the RFC's example, and ACME's seven stores per realm. **And that the nonce secret is in the environment when the module is REQUIRED**, asserted in a child process with the variable removed: `request_pool.js` forks eagerly, so a secret generated on the first nonce was one every worker generated for itself — caught by removing the require-time call |
| `acme_protocol.js` | ACME end to end in a CHILD PROCESS on plain HTTP, driven by `vendored/acme_client.js`, plus the console handlers called directly — including the product-mode plain-HTTP refusal no HTTPS stack can reach |
| `est_codec.js` | EST's wire formats: strict RFC 8951 base64, a certs-only CMS written byte for byte, the `csrattrs` document and `multipart/mixed` |
| `est_handlers.js` | EST's handlers through the router stack: the media type, the re-enrollment subject rule, the transport refusal, the refused DecryptKeyIdentifier and the console's KEM-profile check |
| `scep_enrollment.js` | SCEP's CMS codec and handlers in process: the signer's signature, the implicit rejection a failed RSA unwrap gets, the transaction store per realm, and the zod schema against the OpenAPI body |
| `teardown_bounds.js` | **that a stack which will not come down is not a verdict on the tree** (2026-09-10). CI's `tests` job was reported as a failure for a tree with nothing wrong with it: all three modes ran, the last finished 78 of 78, the report was written and the runner exited 0 — and then `up --abort-on-container-exit`, which stops the stack once the runner is done, sat on `Container sts-postgres-docker-tests  Stopping` for twenty-three minutes until the job's wall clock cancelled the run. **No compose flag covers that**: `up` already waits ten seconds and already follows with SIGKILL (the `xacml-pep` container spends all ten on every run), so the kill was reached and did not land, and the only lever left is to stop WAITING. Three claims: every teardown has a wall clock; **a bound that is REACHED is not turned into a test failure** — the mode's real verdict is recovered from the runner container, which has already exited and whose exit code docker has recorded; and the CI job's own timeout stays above the sum of ours, so the bound that fires can always explain itself. The middle one is load-bearing — without it the bound is a NEW way to throw a green suite away, arriving sooner than the CI timeout did and just as wrong — and it is available at all only because `up --abort-on-container-exit --exit-code-from tests` does two separable things and only the first decides anything. **In process because every claim is a comparison between FILES** — the two launchers, the compose helper they share and the workflow that runs one of them — which is `admin_api_token_wiring.js`'s shape and for its reason: a launcher is not something a job can look at, so the only run that would have caught this is the one that had already lost. Thirteen mutants, all caught |
| `admin_bootstrap.js` | **THE BOOTSTRAP ADMINISTRATOR AND THE FORCED PASSWORD CHANGE** (2026-09-13), in two CHILD PROCESSES, because the seed runs against the whole stack and `admin.bootstrapUsername` is restart-only. Sections: (1) the seed creates `admin` in both role groups with `pwdReset` set, and a second seed changes nothing; (2) any signed-in person holds both roles until that account signs in to the console; (3) its first console sign-in closes the window, a sign-in through another realm does not, the account keeps its roles, and a later seed leaves the claim alone; (4) a roster that already named somebody closes the window at seed time; (5) the account cannot be deleted, while an ordinary person can, and a trust realm's own `admin` is an ordinary person there; (6) in product mode, a right password flagged `pwdReset` is refused at a door that cannot ask for a new one, and a wrong password is still just wrong; (7) the change step over HTTP: the form is drawn in place of a session, a mismatch and the reserved password are refused, a good change clears the flag and continues the sign-in, the step is spent, and in product mode the policy refuses a weak new password. Seven mutants, all caught: the older empty-roster rule put back, the realm check removed, the delete guard removed, the reset refusal removed, the forced change skipped, the administered-roster close skipped, and the flag never cleared. They were run by copying and restoring the shared files, not through a require hook |
| `console_bootstrap_product.js` | **PRODUCT MODE NEVER OPENS THE CONSOLE TO WHOEVER SIGNS IN, AND THE BOOTSTRAP ADMINISTRATOR CLAIMS IT ONLY WITH ITS PASSWORD** (2026-09-22, #103), in a CHILD PROCESS for `admin_bootstrap.js`'s reason. (1) development keeps its window and any sign-in as `admin` claims it; (2) a realm carrying `global.mode: product` opens nothing in a development process — the mode is asked in the roster's realm; (3) product, with `admin.openWhenEmpty` on: a person holding no role holds nothing (`withheld`), the roster view reports `openToAnyone` false and `bootstrapPasswordRequired`, and `admin` holds its roles with `claimPending`; (4) `passwordSignIn()` over ten sessions — `pwd` from this service yes; SPNEGO's `pwd`, a partner's `federated pwd`, a certificate, a wallet, a passwordless key, no recorded authority, no; (5) none of those claims the console, nor a password through another realm; (6) the debugger refuses the unclaimed `admin` (`STS-DBG-0033`) and takes the permission off its grant, and a portal session's enrollment authority waits; (7) THE GATE over a loopback socket with relying-party sessions made over real sign-on sessions: a certificate and a federated session as `admin` refused `bootstrap_password_required`, a password-signed person holding no role refused `insufficient_role`, the password session let in and claiming, the certificate session then an ordinary member's; (8) an un-seeded product realm is closed and `reportClosedConsole()` prints `STS-ADMIN-0798`, a seeded or development realm prints nothing |
| `admin_credential_controls.js` | **WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS, AND THE SECOND FACTOR A SIGN-IN MAY ENROL** (2026-09-13), in a CHILD PROCESS for `admin_bootstrap.js`'s reason. The six actions on a person's `/admin/users` page through `usersAction()`: a reset returns a generated password once and sets `pwdReset`; a reset link is absolute on the base the action was given, REMOVES the password, checks, and is refused two hours later as expired (the clock moved, not waited for); `/portal/reset-password` over HTTP draws the form, answers one sentence for a bad link, refuses a mismatch, sets the password and spends the link; disable-primary-keys refuses somebody with no password and otherwise takes only primary keys; disable-mfa takes the app, the mfa keys and the recovery codes and refuses somebody holding none; require/stop-requiring write the flag. Every one's CAEP and RISC SETs are read off a poll stream's queue. Then the sign-in over HTTP: the set-up step with no session, a wrong code keeping the step, the right one enrolling and signing in, the step spent, the next sign-in asking for the code, a passwordless sign-in refused under the requirement, the realm setting reaching somebody with no flag, the security-key choice drawing the ceremony, and a refusal naming the settings when neither mechanism is offered. Eight mutants, all caught — **two only after the fixture was fixed**: nothing moved the clock past a link's expiry, and the passwordless check matched `/required/` for a person holding no primary key, who was refused for that instead |
| `person_attribute_editor.js` | **A PERSON'S ATTRIBUTES, SET, ADDED TO AND REMOVED FROM** (#228, 2026-09-26), in a CHILD PROCESS for `admin_bootstrap.js`'s reason. `ldap/person_editor.ts` through `usersAction()`. The list: title, telephoneNumber, manager, schacDateOfBirth, c and employeeStatus are editable; userPassword, jpegPhoto, userPKCS12, uid and mail are withheld with a reason; memberOf, stsTotpCredential and federationLink are on neither. Set replaces, add appends (the name in any case), remove takes one value off, and an empty set removes the attribute, with the entryUUID, the password hash and every other attribute untouched. Every refusal's code: STS-ADMIN-0518 and STS-LDAP-0102 to 0109, including a `cn=`-named entry's cn (0104) and the editor saying so for that entry only. The shaped values (country codes upper-cased, dates to YYYYMMDD, language ranges, http(s) labeledURI, a DN's shape, no line break, 1024 characters). The account observer is told with before and after. The view's `attributeEditor`, the page's section and selects, and `set-mail` from its form |
| `admin_actions_layer.js` | **THAT THE DECISIONS BOTH ADMIN SURFACES MAKE LIVE IN A LAYER NEITHER OF THEM OWNS** (2026-09-12). Thirty-one actions moved from `admin-ui/admin.ts` to `admin-core/admin_actions.ts`, and `mgmt-api/admin_api.ts` requires that directly rather than reaching its decisions through the console module. Four claims: the layer registers no ROUTE (it is required by two modules, so a route in it would be registered twice and rule 1 means the second can never win); it touches no `req`, no `res` and no markup (an action that read the request would work from one door and throw from the other — the exact defect the split exists to make impossible); the management API calls no action on the console module and the console does not re-export one either (**the quietest way this could rot**: one `admin.xAction()` added back restores the old direction for that operation and NOTHING fails); and each forwarded collaborator (`FORWARDED` names them per half) has exactly one writer besides its declaration, which is what makes two caches one answer rather than two. Plus the load-order rule the directory exists to state — the layer pulls in four route-registering modules, so only those two files may require it. **IT GREW A SECOND HALF THE SAME DAY**, when `admin-core/admin_views.ts` took the thirty-eight PURE view functions — so every refusal is asked of both files, with one difference stated rather than smoothed over: an ACTION may not touch `req` at all, a VIEW may read `req.query` and nothing else, and neither may touch `res`. Plus two checks that exist because the move shipped defects past `npm test`: **that every name each half uses is in scope there** — five `ReferenceError`s (`numberWord`, `signJwt`, `baseUrlOf`, `stsKeysFor`, `sessions`) came from `admin.js` destructuring fourteen names over comment-interleaved lines, each found by a different HTTP job, one at a time — and **that nothing anywhere reaches a moved function through `admin.*`**, which is how `api_explorer.ts` kept calling `admin.gateStateFor()` after it stopped existing, loading fine and throwing when somebody opened the page. **AND THE VIEWS WERE SPLIT AFTER THAT, WHICH THIS FILE CANNOT SEE AT ALL.** Twelve families of page had their computation lifted into the layer and their markup left behind, and ELEVEN OF THE TWELVE shipped a defect the two HTTP jobs caught: a dropped page parameter, locals of a sort comparator lifted as though they were the page's, a value declared after the markup that needed it, a dispatcher reading `?id=` where the page reads `?relationship=`, a missing no-directory branch, a blanket text replacement that hit four other functions, and one resource handed `undefined` because two sibling functions return different shapes. Not one was found by reading and not one by `npm test`. **In process on `teardown_bounds.js`'s argument, and the file says out loud what it CANNOT check**: whether the actions still work. Nothing here would have caught `numberWord is not defined`, which is what the first run of `tests/vendored/sts_admin_api_operations.js` answered on one refusal path — a helper the move had not carried across, from a destructure spread over thirty comment-interleaved lines. That job and `sts_admin_console.js` are what verify this change; this file only stops it drifting back |
| `ssf_receivers.js` (sections B2, B3) | **ONE STREAM PER SURFACE HOWEVER MANY PROCESSES SEED IT** (2026-09-12) — **and B3 (2026-09-14): another realm's receiver stream in this realm is swept by its id, while an ordinary receiver's stream beside it survives** (one mutant, caught). The check above it — seed, seed again, nothing made — passes in ONE process and always will: the second call finds the first call's record in the same in-memory store. **What it cannot see is the arrangement this service actually runs in `dispatch` mode**: the front process and every request worker load the protocol stack and each calls `seedStreams()`, against a store that is SHARED because it is persisted and coordinated. With a random stream id each of them created one of its own and the store kept them all — measured on a four-hour stack, **fourteen streams in the default realm where two belong**, seven pairs at seven timestamps, and a bulk load pushing every one of 16,421 events to twelve of them: ~197,000 loopback pushes, 19,737 `connect EAGAIN`, the front process pinned at a full core and four bulk-load jobs failing on a CONNECT timeout rather than on any assertion. Three claims: a process that never set the `internalSurface` marker still finds the stream (the lookup asks for the DERIVED id first, because the marker is the half a persisted round-trip can lose — and a miss would now OVERWRITE a stream somebody had paused); a legacy duplicate delivering to the same loopback path is SWEPT, identified by where it delivers rather than by that marker; and rotating the per-run receiver secret seeds nothing, because an id derived from THAT would agree across one run's processes and mint a fresh set on the next start — the same defect one level along. **Asserted through `seedStreams()` rather than by rebuilding the id**, since a test that recomputes the string it checks proves only that two copies of one expression agree, which is what the first version did. Three mutants, all caught |
| `ssf_queue_rows.js` | **A SHARED SIGNALS STREAM'S QUEUE IS ONE JOURNALLED ROW PER SET** (2026-09-13). Queueing, a poll's acknowledgement and a refusal never reached the persistence journal — the queue was an array on the record — so in `dispatch` mode `sts_ssf_allowed_events` polled `[]` after an emission and `sts_gnap_signals` was handed a SET it had acknowledged. "Another worker wrote this" is the two accessor calls `persistence_minted.js`'s `applyLocally()` makes, and "this process wrote that" is what reached a real persist observer, in a CHILD PROCESS for `realm_isolation.js`'s reason. Asserted: each SET change journals THAT SET's key; a STALE record replicated from another process neither takes SETs away nor, queueing from it, puts an acknowledged one back — the race a `touch()` on a whole-valued record would have left open; a redelivery writes no row; a replicated delete is final; a replaced record is not written back and `liveRecord()` answers the one held; a disable and a removal drop the rows. Plus a source guard that nothing in `ssf/` or `gnap/gnap_signals.ts` reads `record.queue`. Four mutants, all caught |
| `oidc_core_units.js` | **OPENID CONNECT CORE'S PURE HALVES** (#118, 2026-09-22): `idTokenHalfHash()` for EVERY algorithm in the signing table against node's own digests — a new algorithm fails until it is given a hash on purpose — including this service's choice where Core is silent (EdDSA, ML-DSA, SLH-DSA, the composites); `oidcSubjectMetadataProblem()`'s pairwise, sector and signing-alg rules; `essentialAcrValuesOf()` making only an ESSENTIAL acr a requirement; `usesFragment()`'s default response mode |
| `fapi_baseline_units.js` | **FAPI 1.0 BASELINE'S LIBRARY AND THE HOSTED SURFACES' KEY** (#138, 2026-09-22), in a child process: `oauth2.fapi` on a realm and a named server's ambient value that may opt out, RFC 9700 mode implied; the authorization, client-identifier, client-method and registration refusals with their codes; the 600-second cap; the metadata; consent required and global consent ignored; the `fapi` member's refusal; the seeded surfaces as `private_key_jwt` with no secret; and `oidc_rp.ts` over stand-ins for the registry, the CA and the claim store — a key issued once and reused, replaced within 30 days of expiry, waited for when another process holds the claim, and the two refusals (`STS-AUTHN-0207`, `0209`) |
| `fapi_advanced_units.js` | **FAPI 1.0 ADVANCED AND JARM'S LIBRARIES** (#139, #143, 2026-09-22), in a child process: the Advanced rules of `fapi.js` (PKCE only when pushed, the response types, the client methods, registration's types and algorithms and RSA1_5, the metadata, the request object's exp/nbf/aud, the sender constraint with and without `oauth2.fapiRequireMtls`, the PS256 default); `signJwt()` with PS256, ES256 and EdDSA and `verifyOwnJws()`/`verifyOwnCompactJws()` verifying each, and refusing an HMAC token keyed by the public certificate; `jarm.ts`'s transports, query.jwt rule, grammar, a signed response, an encrypted one opened, PS256 under Advanced; the access-token algorithm from the setting, a named server's member (and its refusal) and FAPI's default |
| `fapi2_units.js` | **THE FAPI 2.0 SECURITY PROFILE'S LIBRARY** (#140, 2026-09-22), in a child process: 2-security as a profile of its own with its own table; code only, PKCE always, redirect_uri required, http only to a loopback address; the client methods; registration's types, algorithms (EdDSA allowed), 224-bit EC and 2048-bit RSA keys; the 60-second future timestamp rule; rotation off, forced by the setting, and ON under FAPI 1.0; a 60-second code and a 599-second request_uri; the ordinary consent rules; the metadata (code, PAR required, DPoP's algorithm list); PAR's client authentication and the string aud |
| `fapi2_message_signing_units.js` | **FAPI 2.0 MESSAGE SIGNING'S LIBRARY** (#141, 2026-09-22), in a child process: `2-message-signing` as the Security Profile and more, its report the 2.0 table plus its own rows; the signed request object required and held to exp, nbf and aud; JARM required (any JARM mode, never a plain one) with the Security Profile's code-only rule still in force; the metadata (JARM's modes only, a signed request object and PAR required); and the Security Profile alone asking none of it |
| `caep_credential_units.js` | **CAEP FROM EVERY DOOR, THE PURE HALVES** (#145, 2026-09-22), in a child process: `certificateIdentifiers()` against a fixed certificate (RFC 4514 issuer with an escaped comma, lower-case serial, empty for junk); `userAgentFingerprint()`; `aaguidString()` and `keyCredentialType()`; `certificateChanged()` sending `x509` with issuer and serial and never the PEM; `claimsChangeFor()` naming only the claims that moved, `null` for an emptied one, a nested claim nested, the whole groups list for membership and `memberOf`, nothing for a write that moved no claim; `holdsLiveIssuance()` for a valid, another person's and a revoked token |
| `risc_acts_units.js` | **RISC ON ITS OWN, THE REGISTER'S HALVES** (#146, 2026-09-22), in a child process: the `iss_sub` default (item 1, which nothing held); a disable's reason sent only when the administrator gave one of RISC's two; `identifier-recycled` inside `risc.recycleWindowDays` and not at 0; a phone move filed as the phone with its old value released; section 2.8's moves from each state, the delay stamp and `optOutsDue()`; `credential-compromise` carrying `credential_type` |
| `ssf_spec_conformance.js` | **SSF 1.0 FINAL AGAINST WHAT #144 FOUND** (2026-09-22), in a CHILD PROCESS with a real push receiver on a port. A: RFC 9493's registered names (`iss_sub`, `did`) accepted and the drafts' refused; a complex subject needs `"format": "complex"` and may carry `application` and an additional member; section 3.5's `jwt_id`, `saml_assertion_id` and `ip-addresses`. B: a stream is its creator's, a list is the caller's own, this service's own stream is nobody's whatever principal it was created under, and `ssf.maxStreams` is per receiver. C: `aud` is Transmitter-Supplied — the receiver's own identifier by default, refused when it is somebody else's, and an update carrying a changed one is refused and changes nothing. D: SSF's own events go on a stream that did not agree them, carry a `txn` and an opaque stream-id `sub_id`; a pause sends stream-updated BEFORE the stream stops, a paused push stream HOLDS, and enabling sends stream-updated and then pushes what was held, in order. E: a stopped poll stream hands out only its stream-updated events, and a disable keeps them. F: the stream-maintenance job pauses an inactive stream and announces it, sends a stateless verification to a stream that is due one, publishes `inactivity_timeout`, and leaves the internal streams alone. Three mutants (the hold, the internal exclusion, announce-before-stop), all caught |
| `stack_network.js` | **THAT NAMING A COMPOSE PROJECT ISOLATES THE NETWORK AS WELL AS THE CONTAINERS** (2026-09-12), and it is the THIRD thing to escape that sentence. `./local-run-tests.sh`'s own header was the record of the first two (that launcher was removed on 2026-09-16; git history has it): a project scopes containers, networks and volumes, `container_name` is machine-wide, and for a while `STS_TEST_COMPOSE_PROJECT=mine` handed the other run's containers straight back. Then a realm's SPIFFE listeners needed ADDRESSES that do not move between starts — `spiffe.grpcHost` is a literal IP — and both compose files grew a subnet written out as a literal. **AN ADDRESS SPACE IS MACHINE-WIDE IN EXACTLY THE WAY A `container_name` IS**, so the second run in this tree, however it was named, was refused with `invalid pool request: Pool overlaps with other one on this address space` before ONE container started — which names nothing in the tree and reads as a service that never came up. Five claims: the scan exists and is SHARED (`freeSubnet()` in `tests/tools/compose.sh`, beside the three functions there for the same reason); it asks BOTH questions the daemon asks, docker's networks AND this machine's routes, because the same refusal is what a VPN route or a libvirt bridge produces; the launcher calls it with a base DIFFERENT from `docker-compose.yml`'s, so a test run beside a development stack never reaches the scan (until 2026-09-16 this compared the two launchers' bases, `./local-run-tests.sh`'s being that file's); each base is its own compose file's declared default, which is what keeps a plain run on an idle machine byte-for-byte what it was; and all four variables travel together, because three of them are addresses INSIDE the first. **The last claim is the one an edit trips**: an address built from the BASE rather than from the chosen subnet is right for `<base>.0.0/24` and wrong for the other 255 — so it is correct on every machine where the scan changes nothing, and wrong on exactly the second run the scan exists for. In process on `teardown_bounds.js`'s argument, every claim being a comparison between FILES. **Fourteen mutants, all caught**, and one of them only after the file was tightened: the scan asks docker in TWO calls — `network ls` for the names, `network inspect` for the subnet each holds — and a check that accepted either would pass a helper that answers *nothing is in use* |
| `unit_job_environment.js` | **that the in-process half runs in the configuration it describes, and not in the stack's** (2026-09-12). Both launchers export `tests/tools/modes.sh`'s variables — that is how the compose stack is handed the mode — and the report runner's unit children inherited them, which was silent until `dispatch` mode set `STS_KEYS_SOURCE=persisted` and **eight unit jobs failed in one mode about a service none of them touches**: a keystore turned on in a process with no store to open. What is asserted is the SEAM rather than the symptom — `tests/keystore.js` already owns the refusal — because what can break again is the LIST: a mode grows a fourth variable and the next unit job to read it fails for a reason three files away. So the names are read from `modes.sh` here too, by an expression written independently of the runner's, and the two have to agree. It also holds modes.sh's OWN stated rule, which nothing was checking: every mode names every variable any mode names, because an unnamed one is not off — it is whatever the previous mode in the same shell exported. And it checks that no unit file READS one of them without setting it first, which is what makes the scrub safe rather than merely correct |
| `oidc_rp_addresses.js` | **THE CONSOLE'S AND THE PORTAL'S REDIRECT URI, AND WHAT IS WRITTEN ONTO THEIR OWN CLIENT ENTRIES** (2026-09-12). An anonymous `GET /admin` with an invented `Host` wrote a callback onto `sts-admin-console` for good — `forwardedFrom()` reads the Host header whether or not `global.trustProxy` is on, which the comment above the learning said it did not. Four claims, each asserted by reading the REGISTRY after the call rather than the redirect, because a refusal that still wrote and a pinned redirect that still learnt both produce the right response: product mode refuses an unregistered address before a browser is sent anywhere; `global.publicBaseUrl` is used and never learnt; development still learns, up to `oidcRp.maxRedirectUris`; the back channel dials `helpers.loopbackHost()`. **It found that learning had never worked at all** — `updateApplication()` was handed one object where it takes an identifier and a change — so the development half asserts a behaviour that first happened the day this was written. Nine mutants, all caught; the socket's host survived until a source check was added, since dialling it for real means binding this service's port on another interface in a shared process |
| `return_address_provenance.js` | **A RETURN ADDRESS DEVELOPMENT LEARNT IS NOT ONE PRODUCT BELIEVES** (2026-09-12). A development sighting that ADDS a SAML ACS URL, a `shire`, a `wreply` or a learnt console callback marks it on `appReturnAddressObserved`, and one that repeats a registered address does not demote it; in product `applications.returnAddressesOf()` withholds a marked address and `saml/return_address.ts` refuses it with `STS-REG-0049` and the confirm operation named, including for an entry holding ONLY observed addresses and a request naming none; confirm keeps the address and drops the mark, discard drops both, an explicit `add`, a `remove` and an RFC 7592 registration each settle the mark, and an `observed` flag can mark nothing in product; the console's own client is refused in product at a learnt callback and used once confirmed. Section G reads the three protocol modules and `clientConfigOf()` as SOURCE, because a call site reading the raw attribute passes every behavioural check here — the saml2 mutant is caught ONLY there. **In process because the claim is what is WRITTEN and what a mode believes**; `sts_admin_api_operations.js` drives the two operations and the product refusal over HTTP and `sts_admin_console.js` presses the buttons. Seventeen mutants, all caught |
| `session_clocks.js` | **THE SESSION LIFETIME AND IDLE TIMEOUT, AND WHO A SIGN-OUT MAY NAME** (2026-09-12). The lifetime was a literal hour with no idle timeout anywhere; `authn.sessionIdleTimeoutS`'s ZERO means none and is the case `Number(x) \|\| fallback` gets wrong, so it is asserted first. An idle session is ENDED — out of the store, through `expireSession()` — not merely refused; a read writes nothing unless an idle timeout is in force; reading the console's session touches the sign-on session behind it, or the sweep would idle the parent out under somebody using the console; `logout.liveSessions()` asks `authn.sessionEnded()`. Plus the two waiting clocks, the expiry sentences built from the settings, and an anonymous `/logout?username=` refused in product mode while naming yourself still works. Ten mutants, all caught |
| `password_policy.js` | **THE PASSWORD POLICY, AND THE SCRYPT COST OF A NEW HASH** (2026-09-12). The first half was a length-only rule for a few hours and is now the default PROFILE: composition (every broken rule named, Unicode classes, a space not a symbol, code points not UTF-16 units), the HISTORY (current plus the last N refused, trimmed, only hashes remembered, recorded in development too), a GENERATED password always meeting it, the profile as a directory entry (a partial save refused by name, a second profile refused, the cross-field rule, form strings and JSON alike, read back in the schema's own spelling, a reset putting the defaults back), **the LDAP door driven through the real modify handler** — a weak value a CONSTRAINT VIOLATION with nothing written, a strong one stored as a HASH that the sign-in verifier accepts, its own history met through the socket, `pwdHistory` and a pre-hashed value refused in product, a pre-hashed value kept and a clear one hashed in development — and a create naming no credential GENERATING one. In process because a stored entry state (a clear `userPassword` an older build wrote) is not something any door offers. Eight mutants for that half, all caught, and **one survived the first round**: skipping the schema's `learnName()` merge passed, because the policy's own reader looks the attribute up both ways — the assertion now reads the entry's spellings, which is what that merge is for. The second half: `security.passwordHash{LogN,R,P}` writing the NEXT hash under new parameters while a hash written under the old ones keeps verifying — the half worth asserting, because a change that broke stored hashes is caught in a minute and one that silently wrote weaker ones is not. Includes the worker-pool door, whose job must carry the parameters it encodes. Six mutants, all caught |
| `directory_write_authorization.js` | **WHO MAY WRITE THE DIRECTORY OVER ITS OWN SOCKET, IN PRODUCT MODE** (2026-09-12). Every operation goes through `ldapServer.performOperation()` — the function a request worker runs a dispatched operation with — so the one fact a worker cannot derive, the BOUND DN, is shown to reach the check. Development still refuses nothing; an anonymous write is 50 with `STS-LDAP-0052`; a person on their own entry may change what `ldap.selfWritableAttributes` names (case-insensitively, the setting honoured when edited) and nothing else, and a modify mixing the two is refused WHOLE; add, delete, rename and another person's entry are 50 with `STS-LDAP-0053`; an administrator writes anything; a self-service `userPassword` still meets the password policy (19, not 50) and is announced to the Kerberos key register once, after the commit. **Two assertions guard the two ways this would be quietly wrong.** The ESCALATION: `admin_rbac.ts` reads a person's own `memberOf`, so the file writes `memberOf: cn=admin-write` on its own entry and checks both the refusal and that nothing landed. And the EMPTY ROSTER: while no role group has a member the console treats everybody as holding Admin Write, which must not make them an administrator of the directory — asserted with that state as a checked PRECONDITION. Plus a DN in another realm carrying an administrator's name. Eleven mutants, ten caught; the eleventh — an explicit is-this-DN-in-the-default-realm test — was EQUIVALENT (a foreign DN is never an entry in the default realm's store) and was deleted rather than counted. It grants and revokes Admin Write and removes its realm in a `finally`, because a left-over member closes the console's empty-roster door for every later file |
| `webauthn_addresses.js` | **`webauthn.allowedOrigins`, AND AN RP ID THAT DOES NOT FIT REFUSED IN PRODUCT** (2026-09-12). The list is the whole answer where it is set — the request's own origin is not accepted just for being the request's — and product mode refuses a ceremony whose configured RP ID is not the host or a label-boundary suffix of it, where development falls back to the host. Section 3 reads both ceremonies' SOURCE for the same two calls, `/portal/keys` included, because the only other evidence is a ceremony a browser performs. Five mutants, all caught |
| `pki_defaults.js` | **THE CA'S SETTINGS ARE THE DEFAULTS OF EVERY BUILD** (2026-09-12): `pki.signatureAlgorithm` read by `algorithmsFrom()` (the auto-build, a runtime realm and the drift repair all passed `{}`), the three tier lifetimes with zero meaning the profile's, `pki.leafLifetimeDays` read by `issueSigningKeyPair()` (it had the literal 365), and a full workbench store REFUSING rather than discarding its oldest object's private key. Nine mutants, all caught; the replacement-has-room branch survived until the file asked about an id already held |
| `pki_rebuild_recertifies.js` | **A REALM BRANCH REBUILT UNDER ITS SIGNING KEYS LEAVES THEM PUBLISHING CERTIFICATES FROM THE NEW BRANCH** (2026-09-15, #46). Two claims `sts_pki_distribution_points` found the absence of over HTTP: `pki_admin.ts`'s `build` action — the one `/admin-api/pki/build` reaches — re-mints the realm's JOSE and XML certificates from the new Issuing CAs, so the key set publishes a certificate and chain from the NEW Intermediate (the keys are certified BEFORE the rebuild, the order #46's `app.js` now runs a runtime realm in); and `certify()` signs again from the current authority when the Issuing CA was replaced between its signature and its record, driven deterministically by reissuing the use case from inside a wrapped `x509.issueCertificate`, with an authority replaced on every signature refused, bounded, as `STS-PKI-0186`. Two mutants (the re-mint removed; the sign-again branch disabled), both caught. |
| `pki_scope_builds.js` | **A REALM'S CERTIFICATE BRANCH AND THE SERVICE ROOT ARE BUILT ONCE, HOWEVER MANY CALLERS ASK AT ONCE** (2026-09-12). Three concurrent `ensureRoot()` calls on a service with no Root, four concurrent `ensureScope()` calls for one realm, and an `ensureScope()` beside a deliberate `buildScope()` — each compared by CERTIFICATE SERIAL rather than by answer, because every racing caller answers `ok: true`: one built, all were told about the one the store still holds, and the deliberate rebuild still replaces. Then the realm watcher: it builds for a realm created in the process and NOT for one `realms.create()` was told arrived `restored`, which is how a replicated realm reaches every other process. In a child process, because a fresh process has no Root and no watcher and both are under test. Four mutants, all caught — the queue not waited on, `ensureRoot()` outside it, the restored skip removed, and the flag not passed |
| `scan_and_rate_limits.js` | **A RATE LIMIT PER BUCKET, AND THREE SCAN CAPS AS SETTINGS** (2026-09-12). `websecurity.attempt()` taking `{ identity, address }` so the portal's signing-key door stops giving everybody behind one NAT a shared five; `credentials.factorScanLimit`, `portal.applicationScanLimit` and `xacml.pipMaxDesignators` read from their rows. The two whose bound is only reachable with a signed-in session and a thousand applications, or five RSA key generations, are read as source |
| `mode_hardcoded_foundation.js` | **THE SHARED HALF OF THE 2026-09-12 SWEEP FOR HARD-CODED VALUES** — what every protocol family was handed before its own fixes. The four new `common/mode.js` predicates answering the OPPOSITE of product mode (one answering `isProduct()` would turn every demo seed on in product and off in development with every page still rendering); `userFor()` inventing nothing in product and exactly what it always invented in development, which is the half that keeps the parent suite green; `global.publicBaseUrl` pinning `baseUrlOf()` whatever `Host` a request carried; the bind and loopback host helpers; `pki.crlLifetimeMinutes` honouring its own declared floor of one minute rather than a silent sixty; and **a SIGHTING being refused a return address in product** — `applications.seen()` would otherwise write the ACS URL a request named into the very attribute product mode checks that request against. Mutation-tested against the sighting guard removed |
| `oauth_oid4vc_hardcoded.js` | **THE OAUTH 2.0 / OIDC AND OPENID4VC HALF OF THE SWEEP** (2026-09-12). In process for the library claims — a client assertion's `exp` and lifetime cap, a full replay cache REFUSING rather than forgetting a live entry, the persona gate, the DPoP windows, did:web parsing — and in a CHILD PROCESS on an ephemeral loopback port for the endpoint claims: the password grant verifying through `credentials.verifyAsync()` in product, a directory-backed ID Token and UserInfo with `email_verified` never invented, `/dpop/nonce-mode` per realm and refused in product, open registration refused, Transaction Code attempts spending the pre-authorized code, `/issuer/offer` minting for the signed-in person, wallet allowlists, and a realm's DID resolving at its own `did.json`. **The child process is not fastidiousness**: an in-process draft built a certificate authority inside `run.js`'s shared process and broke `pki.js` |
| `oauth21_mode.js` | **OAUTH 2.1 MODE (draft-ietf-oauth-v2-1-16), EVERY DECISION `oauth-oidc/oauth21.js` MAKES** (2026-09-13). That `oauth2.oauth21` implies RFC 9700 mode per realm, names itself as `enabled_by`, and moves `global.https` for the process and not for a realm; PKCE for a confidential client except under the OpenID Connect nonce exemption, which needs a credential ON FILE (not a declared method), `openid` and a nonce, and a missing method refused as missing; **the token request that omits `redirect_uri` accepted in 2.1 mode and refused in RFC 9700 mode**, with a nonce-exempt code still requiring it; the code refusals and the ten-minute cap; `clientConfigOf().declared` over a real directory (a sighted entry declares nothing, one with its own redirect URI does); the token-endpoint refusals (undeclared client, SAML client authentication, a presented credential that did not verify, client credentials unauthenticated, two methods) and the pre-authorized code exemption; no fallback to `oauth2.redirectUris` and the unconfirmed case named; the loopback wildcard ignoring its setting; private-use sign-out addresses believed only off a client's own list; repetition, the `error_description` grammar, the registration and metadata mirrors; and the JWT client assertion's sole-issuer audience **through `client_auth.verify()` itself**, including one request asked with two policies getting two answers. **Its realms are CREATED**: `realms.run()` with a record nobody created carries no overrides, and the first run passed every *outside the mode* assertion for that reason. Mutation-tested with the next file, twenty mutants through a require hook, all caught |
| `redirect_uri_schemes.js` | **WHICH ADDRESSES AN OAUTH REDIRECT MAY BE, IN EVERY MODE** (2026-09-13): `common/validation.js`'s allowlist — http(s) with a host, or a private-use scheme containing a period — against `localhost:3000/cb`, `myapp:/cb`, `ms-msdt:`, `https:/cb` and a fragment, the zod type refusing with the function's own reason, and `uri` NOT narrowed; `applications.js` refusing an unusable address at registration (`register()` writing nothing), at create and at an update ADD while a legacy value on the entry can still be REMOVED and RE-SAVED; and `frontchannel_logout.js` skipping a stored `javascript:` when it reads. **The re-save assertion was added when a mutant checking every SET survived** — the case is a console form posting its whole state back |
| `cors.js` | **THE CORS ALLOWLIST** (2026-09-13): `validation.normaliseOrigin()` and `originProblem()` — case, the default port, IDN and IPv6 normalised; a path, query, fragment, user name, `*`, a wildcard host, `null` and no host refused; the register's create refusing a list with one bad value whole (`STS-REG-0150`), storing two spellings of one origin once, an add normalised, and a remove finding the value by its other spelling; and THE DECISION over real HTTP through `common/cors.js`'s two middlewares in `app.js`'s order on a small express app of its own (probe routes on the shared app would reach every later file): discovery allowed for an origin any application lists and not for a stranger; a token request allowed for the named client's own origin and REFUSED for another application's, for an unknown client_id and for a client with an empty list; a Basic credential, a client assertion's `sub`, an access token's `client_id` and `azp` each naming their client, two names both required to allow; a Basic person off `/oauth2/` treated as naming nobody while an application's `scimClientId` is judged; a preflight answered with the method and headers asked for, never credentials, and a refused one a 204 with no headers; this service's own origin and `global.corsOrigins` allowed whatever is named; a navigation not decided; RFC 9700 section 2.6 asked ahead of a client that lists the origin (its predicate answered for one request — the mode is restart-only); and GNAP's OPTIONS discovery reaching its route both ways; plus the CODE each withheld decision is logged under, asked of `decide()` directly. Eleven mutants in `common/cors.js`, all caught — **the unknown-client refusal removed survived the first version**, because the per-client rule behind it withholds the same header and only the code differs |
| `software_statement.js` | **RFC 7591 SECTION 2.3 SOFTWARE STATEMENTS** (2026-09-13), in a CHILD PROCESS for `oauth_oid4vc_hardcoded.js`'s reason (the mode and four settings flip between requests): a trusted statement's claims beating the JSON and echoed unmodified, the entry's three facts, an RFC 7592 read; `invalid_software_statement` for alg none, HMAC, a foreign key, expiry, a foreign `aud` (and an `aud` of the registration endpoint accepted), a non-JWS, and one of this realm's own JWTs without the type (asserted on the REASON); `unapproved_software_statement` for an undeclared issuer, and that refusal off accepting it unverified with the JSON winning; the issue action's statement, its entry, a registration with it, no-`exp`, and its five refusals; product mode's closed endpoint opened only by a trusted statement, the discovery document following the setting, and a statement-admitted client unable to PUT without the same issuer's statement; `oauth2.softwareStatementRequired`; delete clearing the facts; and the application view model. Three mutants — precedence, the `typ` check, the update binding — all caught; **the `typ` mutant survived the first version**, because the fixture JWT carried an `aud` and was refused by the audience check instead |
| `rfc9068_access_tokens.js` | **EVERY ACCESS TOKEN IS AN RFC 9068 JWT ACCESS TOKEN, AND EVERY RESOURCE SERVER HERE CHECKS SECTION 4** (2026-09-13). In process: `jwt_access_token.js`'s `typ` reading, the issuer and audience readings against a base and the named authorization servers under it (an address is part of an issuer; a partner URL ending in `/resource` is not this resource server), section 4's three refusals in order with their codes, and `audiencePlan()` — the default audience, the API-only token with OpenID Connect scopes left off, the three section 3 refusals and the two multi-audience tokens allowed — plus a source check that its six OIDC scopes are `protocolScopes()`'s six. In a CHILD PROCESS, for `oauth_oid4vc_hardcoded.js`'s reason: the issued header and claims for client_credentials and the password grant, UserInfo refusing an ID Token, a token under another host name and a partner-audienced token, `/admin-api` refusing an ID Token, an `openid profile <API>` token for the API alone, and the token endpoint's `invalid_scope` / `invalid_target`. **Not mutation-tested yet**, and the authorization endpoint's refusal and implicit mint are exercised through the shared plan rather than over HTTP |
| `rfc7009_revocation.js` | **RFC 7009 TOKEN REVOCATION** (#102, 2026-09-22). `mode.opensRevocation()` in both modes and its `/admin/mode` row; then in a CHILD PROCESS, in development: an anonymous caller still revokes, a presented secret that fails is 401 (with the Basic challenge), a verified one is refused another client's token `invalid_grant`, an unregistered client_id with a secret goes on unidentified, an ID Token is `unsupported_token_type`, no token is `invalid_request`, an unknown hint is ignored, an invalid token is 200, and a refresh token in a chain that does not rotate takes the refresh token it came from and both access tokens with it; in product: no credential and a wrong secret 401 revoking nothing, another client's token `invalid_grant` with the audit row naming both clients, an access token revoked alone, a public client revoking its own with its client_id and refused another's, an unknown client_id 401 with or without a secret, the token-type, missing-token and hint rows, a ROTATING chain's refresh token taking every access token of the grant, and a named authorization server narrowing `revocation_endpoint_auth_methods_supported`; discovery's list equal to introspection's. The HTTP half is `sts_token_revocation.js` |
| `rfc9701_introspection.js` | **RFC 9701, THE JWT INTROSPECTION RESPONSE** (2026-09-13). In process: the Accept reading as a table (a JWT only where the media type is NAMED, q-values and `application/*` read per RFC 9110), section 6's defaults and refusals, section 5's inactive claim rebuilt as `{"active":false}`, the recipient key from a JWKS object and from text, and `applications.introspectionResponseProblem()`. In a CHILD PROCESS: anonymous JSON unchanged in development, an unauthenticated or wrongly authenticated JWT request refused 400, the media type, `typ`, `iss`/`aud`/`iat`, no `sub`/`exp`, the signature verified by THIS FILE's own code in RS256, ES256 and HS256, an RSA-OAEP-256 / A128CBC-HS256 Nested JWT decrypted by this file's own code, `none` and a lone `enc` refused at the registry, a lone `enc` left behind answered 500, RFC 7591 refusing `none` and honouring PS384, the three discovery members, a named authorization server's issuer, and product mode's 401 for anonymous JSON. **And, the same day, the three items the first pass listed as not done**: section 5's intended-for rule in the library (own token, default resource, a refresh token its client's alone) and at the endpoint (an API's token `active:false` to another resource server and active to the API and to its own client, an `oauthAudience` match, a permission base with and without its trailing slash, a refresh token, anonymous and unchecked development JSON unrestricted, product JSON restricted); a named authorization server's profile refusing the RS256 default and an unlisted auth method, a removed member not checking, the document matching; OAuth 2.1's two-method refusal in a realm and not outside it; and `/admin/crypto-metadata`'s introspection rows against the discovery document. Twenty mutants, all caught — **the permission-base normalisation only after the fixture grew a resource written without its slash**, because every token `oauth2.js` composes already carries it |
| `oidc_registration.js` | **OPENID CONNECT REGISTRATION, RFC 7591/7592's GAPS AND A FETCHED `jwks_uri`** (#120, 2026-09-22). In process: every `oidcRegistrationProblem()` rule (REG-0181..0188, the `code id_token` leniency, `response_types` defaulting only beside a redirect grant), `initiateLoginUriOf()`, and `step_up.ts`'s registered defaults each overridden by its own parameter. In a CHILD PROCESS with a second loopback listener playing the clients' key host: registration's defaults and refusals, RFC 7592's `client_id`/`client_secret` binding and 401 for a deleted client, the per-server routes, `response_types` and `grant_types` enforced, a client assertion verified against a fetched `jwks_uri` — cached, fetched again for a new `kid` only past `oauth2.clientJwksRefetchS`, refused for a non-set and a redirect, never dialled over http with the policy off — and an encrypted-ID-Token registration refused when its `jwks_uri` gives no key. **Not reached**: a refresh token withheld from a client that registered no `refresh_token` grant (`STS-OAUTH-0600`), and the portal's `initiate_login_uri` link drawn |
| `session_management.js` | **OPENID CONNECT SESSION MANAGEMENT 1.0** (#121, 2026-09-23). In process: section 3's `session_state` recomputed by hand, the cookie's attributes on each kind of port, which redirect URIs have an origin, nothing owed while off; and **the OP iframe's served script in a node vm** with a fake window, cookie and `postMessage` (rcbj's choice over a browser) — `unchanged`, `changed` for another origin, state or a tampered value, `error` for malformed messages. In a CHILD PROCESS: off → a 404 naming the setting and no `session_state`; on → discovery, the iframe's narrowed `frame-ancestors` and no X-Frame-Options, a real sign-in's `session_state` over the cookie written beside it, `prompt=none` with and without a session, a sign-out clearing the state, a new sign-in minting a new one, and no `session_state` without `openid`. `tests/vendored/sts_session_management.js` is the over-HTTP half |
| `rp_initiated_logout.js` | **OPENID CONNECT RP-INITIATED LOGOUT 1.0** (#124 with #115, 2026-09-23), in a CHILD PROCESS against real sign-ins: a malformed request and a non-form POST refused as pages with the session alive; the confirmation page (real button, no script), "stay signed in", a forged `confirm_for` asked again, a cross-site POST asked and no cookie cleared, the page's form signing out and returning WITH `state`; a verified hint for the session signing out at once by GET and POST; a tampered hint, a `client_id` it was not issued to, refused; a mismatched `logout_hint` asking; the registered list held exactly, a private-use address nobody registered not followed, development following a registration-less client's address, and a page (not "mock" text) with nowhere to return |
| `ida_claims_registration.js` | **THE IDENTITY ASSURANCE CLAIMS REGISTRATION** (#128, 2026-09-23), in process: the ISO 3166-1 and ICAO tables (Germany `D`), every section 4.1 claim in the catalogue with `job_title` beside the honorific `title`, the replaced names gone, the conversions, a claims request answering each and `address` whole with `country_code`, federation's inbound names (`place_of_birth` by dotted member, the address untouched), SCIM's `name.honorificPrefix` and extension, and the account page's group |
| `rfc9101_request_objects.js` | **RFC 9101, JWT-SECURED AUTHORIZATION REQUESTS, EVERY FEATURE POSITIVE AND NEGATIVE** (2026-09-13). In process: the `typ` rules, OIDC 6.2's fragment digest, section 6.3's assembly and the `jar_prompt_honoured` marker, and `applications.requestObjectMetadataProblem()` by mode. In a CHILD PROCESS, with a SECOND loopback listener playing the client's host: the realm's RSA and EC `use: enc` keys through the keystore and `enriches()`; a signed object by value to a code with the query's `redirect_uri`, `scope` and `state` ignored; ES256, RS256, PS256 and HS256, the kid rule, a foreign key, a wrong secret, `iss`, `aud` (the issuer or the endpoint), `client_id`, `exp`, an unknown algorithm, a header that is not JSON; unsigned objects accepted in development and refused when required and in product; `typ` and both require settings; `require_signed_request_object` from the setting, a client and a named authorization server; `request_uri` registered and fetched, unregistered and NEVER dialled, `application/jwt`, 404, a redirect not followed, oversize, a timeout, the fragment digest both ways, the cache counted by hits, product refusing plain http before dialling, both parameters, no `client_id`, a repeated parameter; encryption by THIS FILE's own RSA-OAEP-256 JWE, ECDH-ES, A256KW / A128GCMKW / `dir` under OIDC Core 10.2's derived key (and the raw secret refused), a foreign kid, a tampered JWE, a non-JWS inside, a client registered for encryption refused a plain object and another algorithm, another realm's key; a profile's two booleans (a PAR URN exempt from the second), its signing and encryption lists; `prompt=login` honoured once without a loop; the sign-in and consent screens naming the verified object; both discovery documents, the requirement dropping `none`, a named server's document; RFC 7591 and 7592 with the five members and two refusals; the console's three attribute refusals and one write; and `/admin/crypto-metadata` against the metadata. Twenty-seven mutants through a require hook, all caught. **Not reached**: the product media-type refusal, because product refuses the plain-http `request_uri` a loopback server offers first |
| `rfc9101_request_object_jti.js` | **AN RFC 9101 REQUEST OBJECT'S `jti` IS ACCEPTED ONCE** (#35, 2026-09-17). In process: what `onceOf()` remembers an object by (with `exp`, without it for `oauth2.requestObjectJtiRetentionS`, no `jti`, the switch off), `lookUp()` and `spend()` and their refusals, `used_assertions.peek()`, and `claim()`'s `keepBelow` — a 302 keeps a claim under 400 and releases it under the 2xx rule, a 500 releases it either way — and one namespace per issuer with RFC 7523 (a client assertion reusing a spent object's `jti` is a replay). In a CHILD PROCESS: the passes before and after the sign-in screen and after the consent screen are one use; a replay is refused 400 before the sign-in screen; a flow started before the spend is refused on its return; a `login_required` error spends nothing; no `jti` is never remembered; another client's `jti` is another document; the switch turns it off and on; by reference the same; a pushed object is spent at the push, its URN still issues, and it is refused at a second push and by value; an object spent at the authorization endpoint is refused at the push; and the used-assertion history lists them as spent `request-object` rows. Four mutants, all caught, recorded in the header (with the one that shows the look is not the guard) |
| `par.js` | **RFC 9126, PUSHED AUTHORIZATION REQUESTS, EVERY FEATURE POSITIVE AND NEGATIVE** (2026-09-13). In process: the `request_uri` namespace and its 256-bit reference, a push bound to nobody refused, reads that do not spend and a spend that does, unknown / another client's / another authorization server's / spent / expired (the clock MOVED, not waited for) each by code, a full store refusing rather than forgetting, the listing's paging and filters, the delete, the counters, and `require_pushed_authorization_requests` at registration and as an attribute. In a CHILD PROCESS: both discovery documents and a named server's own URL; a push to a TOKEN with the PUSHED state, redirect_uri and PKCE used and the query's ignored, the round trip carrying only the `request_uri`, a replay refused; 405, 413, a JSON body, a malformed and a repeated parameter (and `resource` repeated kept), `request_uri` in a push, no client and two clients, 429; the push refused for its response_type, redirect_uri, claims, resource, authorization_details, response_mode and PKCE method; client authentication observed in development, refused in an RFC 9700 realm (with the Basic challenge), two methods in an OAuth 2.1 realm, product mode's public client, and a client assertion to the PAR endpoint, the issuer, the token endpoint and another audience; section 2.4 on, off, for a failed credential, for a public client, and turned off after the push; the require policy globally, per client, through RFC 7591 and per authorization server, with a removed member not checking; a pushed request object, parameters beside it, another client_id, no client_id claim, a bad signature, a plain push where a signed object is required and the requirement arriving after the push; a DPoP proof binding the code (refused without the key, redeemed with it), a mismatched dpop_jkt and a proof for another URL; the sign-in and consent markers stripped; switched off with an earlier `request_uri` still usable; a realm's full store 503; OAuth 2.1's default redirect_uri; and the counters. **Twenty-two mutants through a `NODE_OPTIONS` require hook, all caught** — the client, authorization-server, expiry and capacity checks, the spend (in `par.js` and at its call), the client and global require policies, both halves of section 2.4, the request_uri refusal, the marker strip, the dpop_jkt and client_id-claim checks, the vetting of a push, product mode, the signed-object refusals at push and after, the registration write, the metadata removal, 413 and 429. |
| `rfc9470_step_up.js` | **RFC 9470, STEP-UP AUTHENTICATION** (2026-09-13). In process: `oauth-oidc/step_up.ts` — the parse, the ordered levels and the three key aliases (`hwk` not met by a one-time code), the most preferred REQUESTED value in the token, when the screen must demand two factors (`mfa 1` does not), the session assessment with and without the return marker (max_age=0 does not loop; a session older than the sign-in window is refused), the three authorization-endpoint refusals and the resource server's by code, and the challenge header; and `applications.js`'s two attributes, `stepUpRequirementOf()` ignoring a hand-written bad value, `audienceNamesEntry()`, the acr pattern held equal to the library's. In a CHILD PROCESS: `acr_values_supported` in both documents; acr/auth_time in the access token and introspection; the stand-in resource's challenge and its four earlier refusals; a one-factor session sent to sign in again for `acr_values=mfa`, the screen demanding the factor, a TOTP code, the marker on the return, `mfa` tokens, 200 at the resource, a refresh keeping the acr; an mfa session answering `acr_values=1` with "1" in the token; `max_age` 3600 met and 0 re-authenticating once with `auth_time` moving; `prompt=none`; an unmeetable URN refused on the return, a forged marker refused, a sign-in POST dropping the hidden second-factor field still asked for it; an unusable acr value `invalid_request`, a push with the marker stripped; UserInfo challenged under both settings; the two write doors refusing by code; and the eight counters EXACT. **Twenty-six mutants through a require hook across the library, `oauth2.js`, `dpop.js`, `jwt_access_token.js`, `applications.js`, `authn.js` and the monitor view, all caught — the write-door check only after 3.0b/3.0c were added**, since the library half calls the grammar directly. The over-HTTP half is `tests/vendored/sts_step_up.js` |
| `backchannel_logout.js` | **OPENID CONNECT BACK-CHANNEL LOGOUT 1.0** (2026-09-17, #36). In process: the two registration members refused when not http(s) or carrying a fragment, at registration (0070) and at a console write (0071), and read back with the RFC 7591 default; `plan()` planning nothing with `oauth2.backchannelLogout` off, planning the same session TWICE giving one row (the derived id), a session with no recorded issuer DEAD-LETTERED 0542 (and the caller's fallback used), a hand-written `javascript:` address dead-lettered 0544 when read; the Logout Token's claims (no nonce, sub and sid, exp two minutes on) and its `logout+jwt` header; and product mode refusing a loopback address through `federation_http.deliverForm()` and through a delivery (0534, one attempt, no socket opened), against a development-mode control. In a CHILD PROCESS with a relying party of its own on a second port: discovery under the setting; `sid` in the ID Token; `/oauth2/logout` producing ONE form POST whose token is verified against `/oauth2/jwks` and names the ID Token's iss, sub and sid; the console's global logout (`adminActions.logoutAction`, the `/admin-api` door too) answering `pending` for three deliveries that then end 503-503-204 SENT after three attempts, 400 dead after one (0536) and 500 dead after three (0537), with ONE audit row each; the list on `/admin/logout`'s model; `wsignout1.0` sending one; the selective `oidc-rp` row sending one and the session staying, and the later session end not telling that client twice; and the setting off sending nothing while `sid` stays until front-channel logout is off too. Four mutants caught (400 retried, a nonce added, discovery ignoring the setting, the session end not dispatching), run by copying and restoring the files |
| `mail.js` | **THE MAIL CHANNEL** (#63, 2026-09-22), in process, every section over a stub directory and a transport of the test's own unless it says otherwise. Templates: a value HTML-escaped in the HTML part and stripped of line breaks in the subject and text (no header injection); a realm's wording refused for an address of its own, an image, a CSS `url()`, an event handler, a script, an unknown placeholder, a link missing from the text part, an href that is not a link placeholder, a two-line subject, a `javascript:` URI; RFC 2798 `preferredLanguage` ordering. Recipients from the directory only (an address in the request ignored; nobody 0012, no mail 0011, two addresses 0023). Security notices and requested links cannot be declined (0034). The per-category and per-recipient ceilings (0010) and duplicate suppression. ONCE ACROSS TWO NODES: two instances over one store and one claim table, exactly one sends; a lapsed lease taken over under the same attempt, and the stalled node's late outcome fenced out. A transient failure retried then dead-lettered, a permanent one dead at once keeping its body, a hand retry a new generation, a sent message keeping none; development capturing. Product: `off` by default (0001), `capture` refused on write (0003), no link without `global.publicBaseUrl` (0015), a realm whose SMTP transport cannot be built failing `startupProblem()` (0002), a link built on the pin and the realm prefix, a caller's absolute URL rendering empty. The cloud transports with stubbed SDKs: SES v2's raw message, region and configuration set, throttling retried and a rejection final; Azure managed identity and connection string, tracking off, a Failed operation final; the Gmail API's delegation to the sender with `gmail.send` only; a missing SDK 0005. **SMTP against a real `smtp-server` in the process** (tests/package.json), with a CA made by `outbound_test_ca.js`: delivered over STARTTLS with AUTH PLAIN from the secret and a DKIM signature that verifies; no STARTTLS offered, or an untrusted certificate, refused 0014 and nothing sent in the clear; 5xx final, 4xx retried; a DKIM domain with no key 0022. DKIM against **nodemailer's own independent signer** (its signature verifies with ours; the body hashes agree), Ed25519, and a 1024-bit RSA key refused. The uses: verification end to end (spent once, bound to the address), forgot password (one answer for everything; only a verified address mailed; RISC recovery-activated as the person), an administrator's link mailed, the notices (none for an app password or a recovery already mailed), the address change told to the FORMER address. Realms: an override, and outboxes that do not mix. **#64 added three sections**: THE LAYOUT (every message wrapped, the body in once and escaped once, a layout without `{{content}}` or with it twice refused, not sendable, a realm's own); THE RECOVERY-CODE RESET (username, address and code, each wrong one the one sentence and no link, a wrong code notifying the owner, the code spent); THE ADDRESS CHANGE (pending until followed, mailed to the new address, then `mail`, verified, the former told, and a link bound to the address it was sent under). Six mutants caught (no HTML escaping, STARTTLS not required, no fence after a send, the ceiling off by one, a sent message keeping its body, verification as a flag rather than the address) |
| `mail_address_sources.js` | **WHO WROTE AN ADDRESS DECIDES WHETHER IT IS VERIFIED** (#64, 2026-09-23), against the embedded directory: a typed address on the console's create verified, an INVENTED one not, `set-mail` verified and refusing a non-address; a SCIM write verified, a rewrite with no source leaving a changed address unverified; an LDAP modify bound as the PERSON not verified, bound as an administrator verified; a federation partner's verified unless it said `email_verified: false`. One mutant caught (`verifyWrittenMail()` ignoring the source) |
| `backchannel_logout_gaps.js` | **BACK-CHANNEL LOGOUT's TWO GAPS (#123, 2026-09-23)**, in a CHILD PROCESS. Section 2.2: an http `backchannel_logout_uri` refused for a public client (`STS-REG-0189`) and for anybody while the outbound policy would not dial it (`STS-REG-0190`) at registration, a create and an attribute write, and accepted from a confidential client once `federation.outboundAllowHttp` is on. Section 2.7 in DEVELOPMENT mode: a real sign-in holding an `offline_access` refresh token, an online one and one for an entry with `oauthRevokeRefreshOnLogout: FALSE`; after `/oauth2/logout` only the online one introspects inactive |
| `backchannel_durable.js` | **THE DELIVERIES AS PERSISTED ROWS** (2026-09-17, the #36 follow-up), in a CHILD PROCESS with a relying party of its own. A "process" is a `BackchannelLogout` built from the real class with ONE dependency replaced — the store and the claims are the real ones, which is what two processes against one store share. A POST that TIMES OUT retried and sent, resending the same token; a process that DIES mid-delivery (its POST never returns) leaving the row in flight, a sweep inside the lease sending nothing, the survivor claiming the SAME attempt once the lease lapses and sending once, and the dead process's late outcome FENCED out when it wakes (plus `compareRows()` itself); two processes ending one session planning one row and POSTing once; a GLOBAL logout going through the session-end claim against a FAKE shared claim store — held by "another node" it sends nothing and the sweep sends it once, free it sends once through `dropSession()`; a 400 dead-lettered, listed, retried by `retry-backchannel` as generation 2 with a NEW jti, and a retry of a sent delivery refused; a retry surviving a RESTART (a process whose timer never fired, a fresh one sweeping); retention dead-lettering a row pending too long (0548) and removing a finished one; the summary line counting by code; Logout Tokens signed ES256 and **ML-DSA-44** verified against the JWKS, one RSA-OAEP-256 encrypted and one **ML-DSA-65 signed then ECDH-ES+A256KW encrypted** decrypted with the relying party's key; **ID TOKEN ENCRYPTION** end to end (the discovery members, three registration refusals, an encrypted `id_token` decrypted and verified); an EXPIRED session sending (absolute and idle) and silent with `oauth2.backchannelLogoutOnExpiry` off; and the list paged, filtered, searched and carrying a row applied from "another node" |
| `wsfed_wauth_step_up.js` | **WS-FEDERATION `wauth` AS A STEP-UP** (2026-09-17, #36), in a CHILD PROCESS: a password `wauth` answered at once; a multi-factor `wauth` on a one-factor session SENT TO SIGN IN AGAIN (it was a 400), the screen demanding the second factor, the marker on the return, a one-time code producing `multipleauthn`, and the same demand then met at once; a HARDWARE `wauth` whose screen offers exactly the key alone or the key after a password (the follow-up's `forceKey`), a one-time code at the second-factor door refused STS-AUTHN-0204, a person holding a code and no key told to enrol one, and a session still keyless on the way back refused STS-WSFED-0009; a REAL WebAuthn ceremony — a software authenticator built in the file, `webauthn_session.js`'s — meeting the demand passwordless AND as a second factor, with the assertion saying `HardwareToken` and `multipleauthn` respectively; a forged marker refused with 0010; no session still demanding the factor; an unknown method still 0006; and `step_up.screenDemandFor()` answering for the authorization endpoint's key aliases. `totp.window` is raised to 2 and each code is for a LATER step than the last, because an earlier step than one spent is a replay |
| `account_disable.js` | **A DISABLED ACCOUNT** (2026-09-17, the #36 follow-up), in a CHILD PROCESS with a relying party of its own — and its point is the LIST OF DOORS, each with a control before the disable: the sign-in screen's password and its passwordless path (refused before any ceremony), `authn.startSession()` with the shape federation, SPNEGO, `GET /tls/sign-in`, the OID4VP wallet door and WS-Trust each hand it, `credentials.verify()` (what an LDAP bind, the password grant, a UsernameToken, SCIM and SSF Basic and EST present a password to), a Kerberos AS-REQ answered KDC_ERR_CLIENT_REVOKED (18) where the control gets 25, the token endpoint's password grant and a REFRESH TOKEN issued before the disable both `invalid_grant`, `issuance_gate.check()` (what the SAML profiles, WS-Federation, WS-Trust, GNAP and the TGS ask), and the management API refusing a token issued to the person. Then what the disable DOES — every session ended, the relying parties POSTed their Logout Tokens, an `account.disable` row naming the operator — SCIM `active: false` and `true` mapping onto the same state (with the sessions ended by the DIRECTORY's hand-off) and leaving the lock alone when the member is not sent, and the enable restoring the sign-in |
| `rfc8705_mtls.js` | **RFC 8705, BOTH HALVES, OVER REAL HANDSHAKES** (2026-09-13). In process: `certificate_subject.js` — a DN compared as a name (case, spaces, an OID, a hex escape; RDN order significant; a multi-valued RDN in either order), a dNSName without case, an IP by value, an email's domain without case and local part with it, a URI exactly, and the registration grammar — and `applications.js`'s at-most-one rule at registration and at a console write. In a CHILD PROCESS on an HTTPS listener that asks for a client certificate, with a foreign CA, its leaf and two self-signed certificates made by OPENSSL: the Credentials door issuing an application a `clientAuth` certificate and its files once; `tls_client_auth` by that certificate with nothing registered and the token bound to it; refused with no certificate (in development mode), with another application's, with one its record no longer lists, with a revoked one, and with a leaf whose CN and `urn:sts:application:` disagree; the door's refusals; the foreign certificate by each of the five subject parameters, and refused for a wrong subject, for none registered, for an unverified chain and for two an `ldapmodify` left; `self_signed_tls_client_auth` by a jwks `x5c` and a thumbprint, and its two refusals; PAR holding the declaration; section 3.4's refusal and binding; UserInfo with the certificate, none and another, and introspection's `cnf`; a public client's bound refresh token, a certificate client refreshing on a NEW certificate and rebinding, and another certificate client refused that refresh token; RFC 7591 registration, its three refusals; `/admin-api` refusing a bound token without its certificate; and an application's certificate starting no session at `GET /tls/sign-in` (it was 9443 until that listener was deleted on 2026-09-16; the child's own listener is the main port's posture, so the claim moved onto it unchanged). Every refusal by protocol error AND by STS code off `/admin-api/audit`. **Twenty-seven mutants through a require hook, all caught — two only after fixtures were added** (a declared self-signed client with nothing registered was short-circuited as half-configured, and no leaf had a mismatched application CN) |
| `rfc9396_authorization_details.js` | **RFC 9396, RICH AUTHORIZATION REQUESTS, EVERY FEATURE POSITIVE AND NEGATIVE** (2026-09-13). In process: a resource's type definition in every shape (a name, a JSON definition with a schema that compiles and validates, a stray member, bad JSON, the built-in `openid_credential`, a schema that does not compile, a location with a fragment or relative, a bad name or description), a client's `authorization_details_types` at registration and on the console by code; the parser's refusals by code in order (0450 JSON/array/count, 0451 entry/type, 0452 each common field, 0453 unknown, 0454 client, 0455 server, the built-in hand-off keeping its code), section 6's `covers()` and `narrow()` (subsets, identical members, a widening, another type, an enriched grant), the consent digest ignoring member order, the one-time Allow per person and array, and `audiencePlan()`'s details input (two resources 0459, a foreign scope and resource 0460, the details deciding the audience, several locations of one resource not ambiguous). In a CHILD PROCESS: both realms' metadata; a flow whose consent screen draws the type, description, amount, resource and audience, to a code, a token response, a claim addressed to the location, and introspection; a refresh narrowed and the rotated refresh token keeping the whole grant; a widening and a different amount refused; consent asked again for the same details; a code redeemed with a subset and with more; Deny, `prompt=none`; an unknown type and a two-resource request refused WITHOUT a consent screen; schema, location, `resource` and scope conflicts, a client's registered types, a named server's narrower list and its document, unreadable JSON; a type two applications declare belonging to the first; `client_credentials` with details and four refusals; details inside a request object; a pushed request refused; `openid_credential` with no forced consent and its identifiers; RFC 7591/7592 read-back and refusal; the console's writes and a type supported at once; the RFC 9728 import's proposal. Thirty-six mutants through a require hook across the library, `jwt_access_token.js`, `oauth2.js`, `consent_screen.js`, `applications.js` and the import, all caught |
| `saml_request_signatures.js` | **A SAML 2.0 SERVICE PROVIDER'S SIGNATURES ARE CHECKED, AND ITS METADATA IS CONSUMED** (2026-09-17, #37). The `saml2.requireSignedAuthnRequests` policy in both modes, its product default and a service provider's AuthnRequestsSigned overriding it; the HTTP Redirect query signature verified over the parameters AS RECEIVED (lower-case percent-encoding included) and refused when RelayState or SigAlg changed after signing, when made by an unregistered key (`STS-SAML-0061`), with no SigAlg or an RSA-MD5 one (`0062`), an ECDSA SigAlg swapped onto an RSA signature (`0061`), SHA-1 refused (`0073`) unless `saml.allowSha1Signatures` is on; an enveloped POST signature verified, an altered request refused, a signature-wrapping attempt refused (`0062`), an unsigned root around a signed original treated as unsigned, inclusive c14n VERIFIED since the #37 follow-up; a KeyInfo-only certificate recorded as OBSERVED and never trusted, encrypted to in development and not in product, confirmed and discarded through the console action; unsigned accepted or refused (`0063`) by the setting and the mode; `WantAuthnRequestsSigned` following both, per service provider; metadata consumed into every field, with the entityID, expiry and metadata-signature refusals and a second document retiring the first's endpoints; the consumed endpoints USED — default, index, registered URL, unknown index and PAOS (`0069`), unregistered URL in development (`0070`), `InvalidNameIDPolicy` (`0071`), `WantAssertionsSigned` per mode; a signed LogoutRequest answered at the consumed ResponseLocation, a tampered one ending no session, an unsigned one refused where required, a wrongly signed LogoutResponse refused. **In process because a signed request needs a key the test holds and several claims need product mode mid-run**; `sts_admin_api_operations.js` drives the certificate actions over HTTP and replays the upload's documented example |
| `nist_pkits.js` | **NIST PKITS AGAINST THE PATH VALIDATORS** (#201, 2026-09-24). The 224 tests (249 subparts) of PKITS.pdf; the data (with a PKCS #12 of every private key) fetched from csrc.nist.gov by `tools/fetch-nist-pkits.sh` with the PDF and BoringSSL's ISC-licensed transcription of the test table, each pinned by SHA-256, into `STS_NIST_PKITS_DIR`; the file FAILS naming that variable anywhere else. Two drivers: `pki.verifyPathToAnchors()` with each subpart's four policy inputs, the user-constrained-policy-set compared, then every certificate below the anchor through the CRL route with the test's lists in hand (`revocation_status.crlInHandVerdict()`, `unknown` scored as hard-fail's refusal); and `pki.verifySignerChain()` with the defaults and the same revocation. Every disagreement is an `EXCEPTIONS` entry with its reason (DSA, a policy input no caller sets, a signer that must be a signing leaf) or a failure. **In process** for `x509_limbo.js`'s reason; under a minute. It found RFC 5280 policy processing missing entirely and four CRL-route defects (see `common/CLAUDE.md`, *3w, ONE SET OF PATH RULES*) |
| `x509_limbo.js` | **C2SP x509-LIMBO AGAINST EVERY CERTIFICATE PATH VALIDATOR** (#201, 2026-09-24). The corpus — 9802 testcases at a pinned commit, about two hundred of them carrying a leaf's private key — is NOT in the repository: `tests/Dockerfile` fetches it with `tools/fetch-x509-limbo.sh`, which refuses anything but the pinned SHA-256, into `STS_X509_LIMBO_DIR`, and this file FAILS naming that variable anywhere else. Six drivers: `pki.verifyPathToAnchors()` (every case), `pki.verifySignerChain()` with the case registered as a chain (every case; its rules are `verifyLeaf()`'s), `pki.verifyIssuedDirectly()` (the SPIRE API caller and key attestation door; every case), `revocation_status.crlInHandVerdict()` (the 17 CRL cases), and REAL loopback handshakes for OpenSSL as the main port runs it (`tls_server.holdToPathRules()`, the CLIENT cases carrying a key) and as `outbound_tls.ts` configures a request (`OutboundTls.checkServerIdentity()`, the SERVER cases carrying a key). A case runs at its own validation time (a `Date` replaced for its duration; a handshake cannot, which is an exception). Every disagreement is either an entry of `EXCEPTIONS` — a rule deliberately not applied, or a case a driver cannot put faithfully, each with its reason — or a failure, and an exception that no longer excuses anything fails too. **In process because the validators are functions over certificates** and the TLS drivers need only loopback; it takes about two minutes. It found, and #201 fixed: name constraints unevaluated everywhere (refused wholesale by one door, ignored by three), greedy path building, self-issued certificates counted against pathLen, SHA-1/MD5 certificate signatures accepted, no critical-extension check at the signer and upload doors, one-hop doors checking a signature and nothing else, OpenSSL accepting chains the rules refuse on both TLS surfaces, node's CN fallback and partial wildcards in the outbound host check (RFC 9525), and a CRL reader that could not read a CRL with more than ~2000 entries, used a list with no or a critical cRLNumber, and answered a duplicated serial by whichever entry came last |
| `saml_signature_algorithms.js` | **EVERY XML SIGNATURE FAMILY IS VERIFIED ON EVERY SAML PATH, AND SHA-1 IS A SETTING** (2026-09-17, #37 follow-up). `common/crypto.js` section 1a's table against the families `tools/saml_signing_kit.js` signs with (RSA PKCS#1 v1.5 with SHA-224/256/512, RSASSA-PSS with SHA-256, SHA3-384 and RSAPSSParams, ECDSA on P-256/384/521 with SHA-224/256/384/512 and SHA3-256, Ed25519, Ed448, DSA-SHA256, ML-DSA-44/87, SLH-DSA-SHA2-128f); for each, a POST and a Redirect AuthnRequest verified and a tampered one refused (`STS-SAML-0061`), the certificate registered and consumed, a signed metadata document verified and a tampered one refused; signed LogoutRequest and LogoutResponse for three families; MD5, HMAC and HSS/LMS refused as not checkable; an X25519 certificate refused at registration (`STS-REG-0160`); SHA-1 by SignatureMethod (RSA, ECDSA) and by DigestMethod refused (`0073`, `STS-KEYS-0062`, metadata by name) and accepted-and-weak with the setting, default false in both modes; the other paths — a federation partner's EC, Ed448, ML-DSA and SLH-DSA assertion, RFC 7522 with EC, Ed25519 and ML-DSA certificates this realm issued (tampered: `STS-OAUTH-0067`), and SHA-1 refused then accepted on federation, RFC 7522, WS-Federation, WS-Trust, SAML 1.1 and GNAP. **In process because every family needs a key the test holds** — the certificates are hand-built, since nothing here issues Ed448, DSA or SLH-DSA ones |
| `w3c_xmlsec.js` | **THE W3C XML SIGNATURE, XML ENCRYPTION AND C14N INTEROP CASES AGAINST `common/crypto.js`** (#193, 2026-09-24). The working groups' own published cases — XML Signature 1.1 (Oracle), merlin-xmldsig-twenty-three, phaos-xmldsig-three, the three Exclusive C14N sets, the Second Edition's C14N 1.1 / defCan / XPointer / DN cases, merlin-decrypt-two, XML Encryption 1.1 (Oracle, Microsoft, IBM), merlin-xmlenc-five and phaos-xmlenc-3 — every signature case in development, development with `saml.allowSha1Signatures`, and product; every encryption case in both modes; every published `c14n-N.txt` canonical form. The expectation is the file's OWN table (the algorithms section 1a verifies and refuses by name, the SHA-1 policy by mode, the cases published as must-fail), never crypto.js's answer read back; each case not expected to verify is listed with its reason in `EXCEPTIONS` and still run, asserting it was not reported verified or decrypted. **THE CORPUS CARRIES PRIVATE KEYS AND IS NOT IN THIS REPOSITORY**: `tests/Dockerfile` fetches it at build time with `tools/fetch-w3c-xmlsec.sh`, every file pinned by sha256 in `tools/w3c-xmlsec.sha256` (provenance and licence: `tools/W3C-XMLSEC-PROVENANCE.md`), and names it `STS_W3C_XMLSEC_DIR`; without that variable the file FAILS naming it rather than skipping. **In process because the cases are documents, not requests** — crypto.js answers them with no port, realm or clock, and the modes are settings changed mid-run |
| `saml_metadata_lifecycle.js` | **SERVICE PROVIDER METADATA AFTER IT IS CONSUMED** (2026-09-17, #37 follow-up). Expiry: a document consumed two seconds before its validUntil refuses SSO and SLO afterwards (`STS-SAML-0074`, product too), the view says `expired`, a newer document ends it, and an aggregate's PARENT validUntil and shortest cacheDuration are the effective ones; the background refresher against a LOCAL HTTP SERVER — a stale document with a URL refreshed by one sweep, a request answered while stale dialling nothing, a failing fetch changing nothing and recorded as a state with the old document still working, the switch; an uploaded stale document shown stale, not fetched, and working; xs:duration; a realm trust anchor (unsigned and foreign-signed refused, anchor-signed verified, an unusable anchor named), aggregates signed as a whole or by the entity, tampered and entity-less ones refused, an unqualified EC key registered for signing and not encryption; MDQ — unconfigured (`0075`), the URL shape, an import creating and consuming through the console/API action, a 404 creating nothing, product's loopback refusal (`0079`) dialling nothing, an entry refreshed from MDQ, a request from an unknown SP answered first and looked up after, once, and a name nobody publishes asked for once; encryption — development in clear and product Responder (`STS-SAML-0011`) with no certificate, and metadata's encryption key obeyed in both modes with the setting off |
| `saml_artifact_and_simplesign.js` | **THE ARTIFACT'S CALLER, AND HTTP-POST-SimpleSign** (2026-09-17, #37 follow-up). `/saml2/ars`: unsigned where required (`STS-SAML-0077`), another key (`0061`), SHA-1 (`0073`), another service provider or no Issuer (`0078`) — none of which SPENDS the artifact, which the right EC-signed request then resolves once; SHA-1 with the setting; a TLS client certificate that is and is not the registered one; development and product defaults; expired metadata (`0074`). `/saml11/responder`: the same for a signed `<samlp:Request>`, another relying party's path (`0078`), TLS, development. SimpleSign: AuthnRequest, LogoutRequest and LogoutResponse verified over the form values — the RAW XML, not its base64, since #189 — and refused when tampered, foreign-signed or signed over the base64, a repeated control uncheckable; a Response SENT on it to a consumed SimpleSign ACS — the endpoint chosen, the ProtocolBinding honoured, SigAlg and Signature fields verifying over the octets, no enveloped Response signature; and the binding published in the IdP metadata. **In process because the artifact store is filled directly and a TLS certificate is a stub on the socket** |
| `saml_interop_findings.js` | **WHAT THE FOUR SAML INTEROPERABILITY HARNESSES FOUND** (#189–#192), held where no peer runs: an AuthnRequest addressed elsewhere or signed with no Destination (`STS-SAML-0085`), stale, future or missing IssueInstant (`0086`), Version 1.1 (`0087`), replayed (`0088`), and a LogoutRequest addressed elsewhere; a back-channel LogoutRequest ending the session its SessionIndex names, and another NameID ending nothing (`0090`, UnknownPrincipal, the second-level code now actually sent); identity-provider-initiated LogoutRequests signed on the query string with the NameID the session gave; `/saml2/unsolicited` and its refusals (`0091`–`0093`, `0082`) and an unsolicited Response carrying the X.500/LDAP names; `/saml2/aa` — UnknownPrincipal (`0094`), no query (`0095`), Success with the qualifiers echoed and no AuthnStatement, narrowing, product refusing an unauthenticated caller; the AttributeAuthorityDescriptor, no artifact SingleSignOnService, SAML 1.1's `urn:mace:shibboleth:1.0`; Shibboleth's lower-case `target`, the profile from the shire's binding, `saml11.doNotCacheCondition`, the SAML 1.1 attribute names and the product query release policy (`0039`, `0096`). The SimpleSign octets are `saml_artifact_and_simplesign.js`'s. **In process because settings change mid-run and sessions are put in place directly** |
| `saml_listener_key.js` | **THE SAML METADATA PUBLISHES THE BACK CHANNEL'S TLS CERTIFICATE** (#248): `saml/listener_keys.ts` — nothing while `global.https` is off, every leaf the socket presents as its own `use="signing"` KeyDescriptor, a re-issued leaf named at the next ask (nothing cached), cluster peers' leaves once each, an unreadable certificate a document without it (`STS-SAML-0097`); both profiles' documents carrying it LAST in the IDPSSODescriptor and the AttributeAuthorityDescriptor with the XML key still first; and, each in a CHILD PROCESS (the environment has to be set before `tls/tls_server.js` loads, and a cluster membership cannot be started in `run.js`'s process), the request worker presenting the front process's leaves including the extras handed with it and a re-issue's, the socket owner's bundle carrying its extras, and a node's leaves riding on its join and heartbeat with only LIVE nodes' read back |
| `saml_family_hardcoded.js` | **THE SAML 2.0, SAML 1.1, WS-FEDERATION, WS-TRUST AND FEDERATION HALF OF THE SWEEP** (2026-09-12). WS-Trust refusing no credential, an unsigned assertion and an unbounded lifetime in product; the return address (ACS, `shire`, `wreply`) matched against the registration in product with no fallback to the built-in mock service providers; the SAML 1.1 queries refused in product and never asserting an authentication that did not happen in any mode; **the AuthnContext read off the session in ALL modes** — a certificate, Kerberos or anonymous sign-in stopped being reported as a password, while a password sign-in is byte-for-byte what it was; and federation refusing an assertion addressed to another service provider or a relationship with no `fedPeer`, in every mode, because that surface is the one that cannot be made permissive. Ten mutants, all caught |
| `kerberos_product_mode.js` | **THE KDC AND THE ACCEPTOR IN PRODUCT MODE** (2026-09-12): no fixture accounts, no delegation rules and no trusted realm; `krbtgt` and the service account built only on passwords that are not the ones published in this repository; the acceptor's account built from `krb5.servicePrincipal` rather than a literal; `/krb5/principals` withholding the passwords; and **a full replay cache REFUSING a new Authenticator rather than evicting one still inside its window**, which was a way to push out a captured AP-REQ and replay it. **Product mode runs in a CHILD PROCESS** because the principal database is built at require time in the process's mode, and a module loaded once cannot be asked in two. Real AP-REQs throughout |
| `kerberos_realm_routing.js` | **A KDC PER TRUST REALM ON THE SHARED PORT 88** (2026-09-15, issue #33). Three sections, and the first two cannot be asked of a running service at all. **THE SETTING RULES**, which are what stop two realms answering to one name: a realm is created with `krb5.enabled` seeded off; turning it on with no `krb5.realm` of its own is `STS-KRB-0123`; a name another realm answers to — another realm's, the default realm's, `krb5.trustedRealm`, or one differing only in case — is `STS-KRB-0124`; a rename or a clear while it is on is `STS-KRB-0125`, and off-rename-on is the way round it. **THE DATABASE**: a realm's fixtures are salted with its own Kerberos realm, it has a krbtgt of its own and NO trust with the development second realm, its service domains are derived from its own name, the DEFAULT realm's database is untouched, a rebuild after a `BUILT_FROM` setting changes carries the sign-out stamp onto the record the new settings built, and turning Kerberos off takes the principals away. **THE ROUTING**, by handing `handleMessage()` the bytes a client would send: the default realm answers its own name as it always did, another realm's name reaches THAT realm's KDC on the same socket, a name nobody serves is `KDC_ERR_WRONG_REALM` **without listing the other realms' names** (port 88 is unauthenticated), a realm's own `/realm/<id>/KdcProxy` is pinned and refuses another realm's name, and a TGS-REQ for an unserved realm is refused where it used to fall back silently to the default realm's database. The store DECLARATIONS are `realm_isolation.js`'s section 5b-ii |
| `kerberos_principal_store.js` | **THE PRINCIPAL DATABASE ACROSS A RESTART AND ACROSS PROCESSES** (2026-09-12), two gaps `kerberos/CLAUDE.md` had recorded as open. **A RESTORED ROW OVERRODE THE SETTINGS**: `krb5.principals` put back whole rows, so a changed `krb5.servicePassword` did not take effect for an account already in the store, and a development fixture with a published password came back into a product process. The rule is `realms.sharedMap()`'s `reconcile` option, at the two accessors BOTH doors call — so it is asserted three ways: at the accessors in process (every configuration field kept, the sign-out fields merged as the LATER instant since #111 — a row without the stamp does not unstamp it, a later undo instant clears it, an unconfigured non-runtime row dropped, a runtime-made row whole, a configured removal refused, a reconciler that throws applying nothing); through the REAL doors, `minted.restore()` and `minted.applyChange()` over sealed rows, in a product-mode CHILD with a changed password and salt; and in that child's LOG, which must name the drifted fields (`STS-KRB-0111`) and carry no stored password. **TWO PROCESSES HANDED ONE RID TO TWO ACCOUNTS**: the RID is derived from the name now, so a SECOND PROCESS is asked for the same names and must agree, an existing account keeps its RID, and a slot another principal holds is probed past. **In process on `minted_persistence.js`'s clause** — every claim is correct on every endpoint for the life of the process that gets it wrong. Sixteen mutants across it, `common/realms.js` and `kerberos/krb5_principals.js`, all caught; the probe counting a name's OWN record as taken survived until the fixture asked about an account sitting on its own slot |
| `ldap_tls_product_mode.js` | **THE DIRECTORY'S SEED AND THE TLS POLICY IN PRODUCT MODE** (2026-09-12; the TLS listeners it was written against were deleted on 2026-09-16): no demo people, groups, bind account or privileged XACML identities; the two role groups seeded under the names `roles.*` gives them rather than literals; generated credential attributes not written; `POST /tls/trust` and `/tls/trust/clear` refused; every listener binding `global.host`; and `tls.minVersion` enforced — asserted as a REAL HANDSHAKE, a TLSv1.2 client refused under TLSv1.3, because a setting read and never applied passes every comparison. **That handshake is LDAPS 636 since 2026-09-16**, having been 8443 until that listener was deleted: `ldap_server.js` builds its secure server from the same `tlsServer.protocolOptions()`, so it is one statement of the policy reaching a socket a module other than the test built — which is why it was not moved onto a listener the child would have had to assemble itself |
| `ssf_spiffe_scim_hardening.js` | **THE SCIM, SHARED SIGNALS AND SPIFFE HALF OF THE SWEEP** (2026-09-12). Federated SPIFFE bundles per realm and **never under a trust domain this service itself serves**, in every mode — before it, one realm could register a bundle named after another's domain and its SVIDs authenticated there; SSF Basic verified in product; the SCIM Digest password never printed outside development and the scheme not offered in product; the SSF realm prefix appearing ONCE in the issuer and every endpoint; SET subjects taken from the directory and not invented; the SPIRE Server API socket 0600 in a 0700 directory; the registry seed and the invented `/workload` gated; join tokens refusing at the cap rather than evicting a live one; and HOBA key registration refused for somebody else's account. Twelve mutants, all caught |
| `typecheck.js` | **THE TYPE CHECKER, AS A TEST (#50, 2026-09-16).** Runs `tsc -p tsconfig.json` and fails on any error, and checks that every non-vendored file in a type-checked directory (every service directory, plus `server.js`, since 2026-09-16) starts with `// @ts-check` and that `tsconfig.json` includes each one, so a new file is checked from its first commit; the root's TypeScript module, `sts_metadata.ts`, must be in that `include` too (`ROOT_SOURCES`). `tsc` is a dependency of `tests/package.json`, for `.npmrc`'s reason; a missing compiler FAILS naming that file. Adding a directory to the check is a line in `CHECKED_DIRS` and a pattern in the root `tsconfig.json`'s `include`; the eight Kerberos codec copies are `NOT_OURS` |
| `spiffe_authorized_entries.js` | **AN AGENT IS TOLD ONLY ABOUT, AND ISSUED ONLY FROM, THE ENTRIES BENEATH IT (2026-09-16).** Builds a registry with entries under two agents, a node alias matching one agent's recorded selectors, an alias with no selectors and an expired entry, then asks `Entry.GetAuthorizedEntries` as each agent, as an unverified caller and as no caller; and asks `BatchNewX509SVID` and `NewJWTSVID` for another agent's entry (PERMISSION_DENIED, `STS-SPIFFE-0077`) and for its own (through to the CSR and audience checks). In a child process, for `spiffe_join_token.js`'s reason. It fails four ways against the old every-entry answer |
| `spiffe_authority_waits_for_branch.js` | **A REALM'S SPIFFE START WAITS FOR THE BRANCH ANOTHER NODE IS WRITING** (2026-09-24). `SpiffeCa.awaitSpiffeIssuer()` with the PKI and the keystore stubbed: an Issuing CA already held answered at once after one pull, and one that arrives from the store 700ms later waited for and found on the pull that brings it; and, as source, `buildTrustMaterial()` asking it before the self-signed fallback. In `cluster` the non-creating node built a self-signed authority for a realm whose branch was still on its way, and `sts_spiffe_broker` was refused. Mutant (the wait skipped) caught by the source check |
| `spiffe_join_token.js` | **A SPIFFE JOIN TOKEN IS NEVER HELD IN THE CLEAR** (2026-09-12). Mints a token through `Agent.CreateJoinToken` and attests an agent with it through `Agent.AttestAgent` — the real gRPC wrappers, a real PKCS#10 request — then looks for the token in every KEY and every BODY of the token store (a persisted row's key is written unsealed, and the store used to be keyed by the token), on the attested agent's registry entry (whose selector used to be `payload:<token>`) and in the audit log. **It also asserts the token still WORKS and is spent once**, because a store that could no longer find the token would pass every *not stored* check by refusing every agent. In a child process, for `spiffe_authority.js`'s reason. Three mutants, all caught: the key back to the token, the join-token selector branch skipped, and the token put back in the body |
| `spiffe_node_attestation.js` | **SPIFFE NODE ATTESTATION IS VERIFIED OR REFUSED** (#40, 2026-09-21). Drives `Agent.AttestAgent` through the real bidi wrapper with a real PKCS#10 request, on a `SpiffeApi` instance built in the child with three test attestors in its own table: a type the realm does not accept, one it accepts that nothing verifies, and an empty type are refused and record no agent; a challenge is a CONVERSATION (the next message is the answer; no answer is DEADLINE_EXCEEDED, a non-answer INVALID_ARGUMENT, the client ending CANCELLED, and the claim is given back); a client's half-close waits for the answer (it used to end the stream while the join token was spent); non-re-attestable evidence attests once; and `CreateJoinToken`'s `agent_id` is an ALIAS entry the agent is authorized for, where it used to make the token unusable. In a child process for `spiffe_join_token.js`'s reason. |
| `spiffe_attestors.js` | **x509pop, sshpop AND tpm_devid VERIFY REAL EXCHANGES** (#40 phase two, 2026-09-21). Drives each through `Agent.AttestAgent`'s real bidi wrapper with a software client doing what `spire-agent` does: x509pop leaves from the vendored engine (ECDSA, RSA-PSS and an ML-DSA-44 leaf answering the post-quantum member), an OpenSSH host certificate assembled byte by byte and signed by an ECDSA authority, and a SOFTWARE TPM (EK, AK and DevID public areas, a TPM2_Certify signed by the AK, TPM2_ActivateCredential) written independently of `spiffe/spiffe_tpm.ts` so the server's KDFa is not merely repeated. Every acceptance sits beside its refusals: a bad signature, a certificate from an unconfigured authority, a USER or expired SSH certificate, a wrong activation secret, a certification naming another key, an EK that is not the certificate's, a template using unsupported Go syntax. In a child process for `spiffe_join_token.js`'s reason; its program is a function passed to `node -e` as source. |
| `spiffe_attestors_cloud.js` | **k8s_psat, http_challenge, aws_iid, gcp_iit AND azure_imds** (#40 phase three, 2026-09-21). k8s_psat against a REAL HTTPS API server started in the child (TokenReview, the pod, the node; its CA and bearer token read from files, and the bearer asserted), http_challenge against a REAL HTTP listener serving the challenge's nonce, and the three clouds with FAKE SDKs handed in through the attestors' constructor dependencies — SPIRE's own tests stub the clouds that way — over documents built here: an RSA-2048 PKCS#7 (pkijs, not `crypto.js`) and an RSA-1024 signature over an identity document, a Google RS256 token, and an Azure PKCS#7 whose signer chains through an AIA intermediate. Each acceptance beside its refusals: a stale pod UID, a service account not allowed, the wrong nonce, localhost, an unlisted host, a forged document, the block device check, an account outside the organization, another audience or project, a tenant or subscription not allowed, a signer outside the metadata domains, an AIA on the wrong host, trust on first use — and each cloud with its SDK missing refused with the package named. In a child process; its program is a function passed to `node -e` as source. |
| `spiffe_workload_attestation.js` | **THE WORKLOAD API'S UNIX SOCKET ATTESTS ITS CALLER** (#40 phase four, 2026-09-21). A throwaway realm binds the socket (the socket rows are restart-only for the process and settable on a realm), and a CHILD PROCESS calls `FetchX509Bundles` over it and holds the connection: the facts must name the child's pid, uid and gid with a pidfd, and the `unix` attestor's uid, gid, path and SHA-256; a changed start time or executable inode must read as another process, and an exited child as gone. An executable over `spiffe.unixWorkloadSizeLimit` must refuse the call UNAVAILABLE with the reason. Beside it, the attestors over fakes: containerinfo over cgroup files (docker, kubepods, two containers refused), `unix` over a fake `/proc`, `docker` over a fake Engine, `k8s` over a fake kubelet (polling, read-only and secure port). **Needs `spiffe/native/peercred.node`, which only the tests image builds — its absence is a failure, not a skip.** |
| `kerberos_person_keys.js` | **STORED KERBEROS LONG-TERM KEYS: A PERSON'S FROM THEIR OWN PASSWORD, A SERVICE'S AT RANDOM** (2026-09-12). RFC 3962 Appendix B's string-to-key vectors (iterations 1, 2 and 1200, AES128 and AES256) through `krb5_crypto.js`, because a derivation that agrees only with itself is `assertion_grant.js`'s PBES2 lesson; the MIT 0x502 keytab writer round-tripped through an INDEPENDENT reader written in the file (a 32-bit kvno of 300, a hole, a truncation refused); development mode unchanged — the observer fires and nothing is derived, the KDC still answers from its fixture database; and a **PRODUCT CHILD PROCESS** (`STS_MODE=product`, `STS_KEYS_SOURCE=persisted`, a file KEK) driving a real AS-REQ with PA-ENC-TIMESTAMP: a directory person with no keys refused with the sentence that says what to do, keys derived on a set and upgraded on a verified sign-in without delaying it, the kvno bumped on a password change and kept on a re-verification, the value sealed on the entry and withheld from the directory dump, an LDAP search, the audit ring and `/krb5/principals`, a copied value refused under another name, and a service principal created, its keytab parsed, a ticket accepted by the acceptor under the stored key, rotated (kvno+1, the old keytab refused) and deleted. **In a child process because the principal database is built at require time in the process's mode.** Sixteen mutants, all caught, three only on a second round — the name binding survived until the copied entry carried a `userPassword` too (the stamp refused it first), a key in the audit DETAIL survived because `detailOf()` stringifies objects (recorded as equivalent, reformulated as a key in the summary), and a development-mode derivation survived until the file installed a recording directory. Plus a vendored mutant — `deleteServicePrincipal()` skipping its write — caught by both `sts_admin_api_operations.js` (the read-back after the delete) and `sts_admin_console.js` (the page after Delete). **PREVIOUS KEY VERSIONS (later the same day)** added section 5, in the same child, with a real TGS-REQ built in the file beside the AS-REQ and AP-REQ: a TGT and a ticket sealed under a person's own key still accepted after a password change while the old password is refused and new tickets are issued at the new kvno; the COUNT bound (kvno 3 refused 44 once 4 and 5 exist) and the LIFETIME bound (a one-second `krb5.retainedKeyTtlS` refuses, clearing it restores); drop-now refusing 44 with the current sign-in untouched; a rotation's keytab read by the independent reader holding both kvnos with the create's own kvno-3 keys; the acceptor and the TGS accepting both kvnos, a second rotation keeping one, and drop-now refusing the kept one while the current is accepted. Sixteen more mutants by exact string replace and revert, fifteen caught; **the principal-side expiry check removed survives**, because the source applies the same clock in the same call — recorded as belt and braces rather than counted. **And one vendored mutant that SURVIVED the first round** — a drop that cleared the public list and kept the versions in the seal passed both `sts_admin_api_operations.js` and `sts_admin_console.js`, because every read over HTTP is the public half; the API job now asks for a SECOND drop and requires `dropped: 0`, which is the one answer over HTTP that comes from inside the seal, and catches it |
| `kerberos_fast_otp.js` | **A PASSWORD ALONE IS NO KERBEROS TICKET FOR A TWO-FACTOR ACCOUNT, AND FAST WITH OTP IS** (#173, 2026-09-22). `common/crypto.js`'s section 9 against EXTERNAL answers — RFC 3961's n-fold vectors, MIT's `t_prf.c` PRF vectors for the four AES enctypes and `t_cf2.expected` for KRB-FX-CF2 over all five; `krb5_fast_codec.ts`'s DER against bytes written by hand (RFC 6560's IMPLICIT tags, which MIT's `kinit` found wrong before anything here did, and MIT's `iterationCount 0`); `spnego_authn.ts` counting the indicator `otp` only from this realm's tickets; and a **PRODUCT CHILD** (`kerberos_person_keys.js`'s arrangement, a KEK made at run time) driving real AS-REQs, TGS-REQs and an AP-REQ: the refusal decision for a person with an authenticator app, one required on their entry, everybody under the authentication policy's `requireSecondFactor: always` (it was `authn.mfaRequired` until #64), and nobody — `KDC_ERR_POLICY` for the right password, `PREAUTH_FAILED` for a wrong one; FAST armored by a host principal's TGT, the armored method list, the encrypted challenge refused alone and its replay `KRB_AP_ERR_REPEAT`, a critical FAST option, a req-checksum over another body, armor without a subkey; OTP with the enrolment's own step refused (one counter with `/authn/totp`), a wrong and a missing PIN, a nonce this KDC did not issue, the right code, and the same code again; and the `otp` indicator read out of a service ticket with the service's key and by the acceptor. The wire half is `tests/vendored/sts_kerberos_fast_otp.js` |
| `wycheproof.js` | **C2SP WYCHEPROOF AGAINST `common/crypto.js`** (#202, 2026-09-24). Every file in the pinned corpus is CLASSIFIED — applied through one or more of crypto.js's own doors, or listed as not applicable with the reason — and an unclassified file fails the run. The doors: `jwsSignatureValid()` (what `verifyCompactJws()` checks), `verifyXmlSignatureValue()`, `verifyRawSignature()`, `verifyCoseSignature()`, `verifyWithPublicKey()`, `openJweContent()` / `sealJweContent()`, `aesKeyWrap()` / `aesKeyUnwrap()`, `verifyCompactJws()`, `decryptJweCompact()` (ECDH-ES from the `_webcrypto` JWKs, RSA-OAEP) and `decryptElement()` (AES-GCM/CBC content, rsa-oaep with its OAEPparams, rsa-1_5, ECDH-ES from the `_ecpoint` points) — a framed door gets the vector put into its frame and is read back through its own refusal codes. `valid` must be accepted and `invalid` refused; every `acceptable` flag met is decided in `ACCEPTABLE` with the reason; where a door's profile is narrower than the primitive (JWE's 96-bit IV and 128-bit tag, the JWS MAC being the whole HMAC, RSA1_5 refused, the XML Encryption 1.1 section 5.2 padding) the expectation is the profile's and counted apart; two corpus errata are listed in `ERRATA`. A **PRODUCT CHILD** re-runs the JOSE and rsa-1_5 files, whose answers differ by mode. ~83,000 vectors, about 30 s. It found twelve defects, all fixed in `crypto.js` — the last two (weak XML ECDSA curves, the AES-CBC padding oracle) on review; the CBC door through `decryptElement()` now asserts that EVERY failure is the one refusal `STS-KEYS-0078` with one sentence, and the padding verdict is held to the vectors through `openXmlContent()` (`common/CLAUDE.md`, *Held to Wycheproof and ACVP*). The corpus is fetched at image build (*The external test vectors*, below); `STS_WYCHEPROOF_ONLY=<regex>` narrows a hand run to some files |
| `acvp_pqc.js` | **NIST ACVP FOR FIPS 203, 204 AND 205** (#203, 2026-09-24). All ten ML-KEM, ML-DSA and SLH-DSA vector sets, both revisions: ML-DSA keyGen through crypto.js's JWS signer (a signature from NIST's seed verifies under NIST's pk with node's OpenSSL) and the vendored engine's `publicFromPrivate()` / `expandPrivate()`; deterministic sigGen byte for byte through `jwsSignatureOver(…, { deterministic: true })` (ML-DSA from a seed, SLH-DSA-SHA2-128s and SHAKE-128s from sk) — the internal parameter that exists for this comparison, since the service signs HEDGED — and the default, hedged signature of each case held to differ and to verify under NIST's key; every sigGen and sigVer signature through every verify door (JWS, COSE, XML on node, the raw proof on the vendored engine) for all three ML-DSA and all twelve SLH-DSA sets; SLH-DSA keyGen through noble's keygen with NIST's three seeds; ML-KEM keyGen (EST `/serverkeygen`'s path) from `d || z`. Context strings, the pre-hash variants, the internal interface, external mu and ML-KEM encapsulation reach no door here and are COUNTED as not applicable, by reason, on each set's line. ~90 s, 70 of them SLH-DSA's SHAKE `s` key generations, run in full rather than sampled. No vector has failed |
| `kerberos_person_keytab.js` | **A PERSON'S KEYTAB, FROM A PASSWORD IN HAND** (2026-09-22, #59). A product child and a development child. Every keytab `personKeytab()` or `reset-person-keytab` answers is read by an INDEPENDENT reader in the file and then SIGNS IN: its key, not a password, pre-authenticates a real AS-REQ built with the vendored codec and opens the AS-REP. Product: the person's own keytab at the current kvno and no other, nothing on the account changed; a wrong or empty password `STS-KRB-0132` with no keytab; nobody and a non-principal name `0130`, a disabled account `0134` (the reset refusing it BEFORE setting a password), a realm with no KDC `0128`; the administrator's reset moving the kvno by one with a keytab at that kvno only, the old password refused 24 and the new one accepted, NO forced change, an outstanding reset link spent, the keytab from the old password no longer signing in; `random` signing in with no `password` member in the reply; neither/both `STS-ADMIN-0802` and a policy refusal leaving the stored hash and kvno untouched; no keytab or password in the audit ring and none in `personKerberosState()` or the user page's `kerberos`. Development: the keytab is `krb5.userPassword`'s key whatever was typed, and signs in. **In child processes** for `kerberos_person_keys.js`'s reason: the principal database is built in the process's mode. `tests/vendored/sts_kerberos_keytab.js` is the over-the-wire half, with MIT `kinit -k -t` |
| `kerberos_signout_instant.js` | **A KERBEROS SIGN-OUT OUTLIVES THE NEXT AS EXCHANGE** (#111, 2026-09-23). The KDC driven in process (development database) by `tests/vendored/krb5_wire.js`: the whole-second boundary (a stamp with milliseconds rounded up), the horizon (the stamp plus the longer lifetime plus the skew; past it the stamp answers as none; a later sign-out under shorter lifetimes never shortens it), the development undo as a THIRD instant rather than a null, and the stamp on the KDC's clock (`krb5.clockOffset`); each sign-out field merging as the LATER instant at the accessors both persistence doors call, for a configured principal and a runtime-made one; and the exchanges — sign in, sign out early in a second, the old TGT refused 20, a new AS exchange in that same second answered after the boundary and accepted, the old TGT and a RENEW of it still refused 20, a renewal of the new one keeping its authtime — once plainly and once under a 120 s clock offset. Mutants: the AS clear restored, the AS wait dropped, either merge made last-writer, the stamp on `Date.now()`, the horizon ignored, the undo winning over a newer stamp — all caught; the TGS comparison without the ceiling SURVIVES and is EQUIVALENT (an `authtime` is a whole second, so `authtime < stamp` and `authtime < ceil(stamp)` agree). The wire half is `tests/vendored/sts_kerberos_signout.js` |
| `protected_resource_metadata.js` | **THE RFC 9728 IMPORT (2026-09-13)**: every section 2 refusal by code, extension members kept, `signed_metadata` decoded and not applied; section 3.1 both ways and 3.3's verdict; internal addresses including both IPv4-mapped spellings; the authorization-server comparison; the plan (prefix stripped, a scope not under the resource kept, an unusable or duplicate one left out); the two mode-gated MUSTs; the fetch against a local server — a redirect, a 404, the size cap, the outbound switch, and in product a loopback URL and a name resolving to loopback refused WITH NO REQUEST REACHING THE SERVER; the third tab's document; multipart parsing with a boundary-like line in a file; and the create-time permission and metadata checks against a stub directory. Thirteen mutants through a require hook: twelve caught (the extension one after the fixture checked the KEPT document, not only the list), one equivalent — node's BlockList already matches IPv4-mapped IPv6 against IPv4 rules |
| `debugger_access.js` | **WHO MAY BE GRANTED THE EMBEDDED DEBUGGER'S PERMISSION, AND WHAT ITS API MAY DIAL** (2026-09-13). The permission, client and resource spelled once across `debugger/debugger_access.ts`, `common/applications.js`'s seed and `common/oidc_rp.ts`'s surface, and the seeded entries defining and granting it; **the EMPTY ROSTER refused (`STS-DBG-0024`) while the console treats the same person as holding Admin Write** — rcbj's rule, mutation-tested by removing the check (three assertions across this file and the next); `narrowScope()` taking it off for a non-administrator, an application, an unauthenticated subject and any realm but the default one while leaving every other scope value alone; **the policy unable to WIDEN it** — this process has no XACML decider, so `access_gate.js` would say yes to anything and a subject with no console role is still refused; `oauth2.js` asking at the authorization endpoint and in `tokenSet()` (source); and the api child's product-mode allow-list — loopback, the extra ranges, a non-range left out and reported. **The non-default realm is an AMBIENT record, not a created realm**: the first version created one, `pki.js`'s realm watcher built the service Root in the background, and `tests/pki.js` — which asserts on the Root it builds — failed in the suite and passed alone |
| `debugger_server.js` | **THE EMBEDDED DEBUGGER'S GATE, DRIVEN OVER HTTP IN PROCESS** (2026-09-13): the listener's own express app bound on an ephemeral port with a stand-in api on a unix socket. A browser with no session sent to THIS service's authorization endpoint as `sts-debugger-ui` with its callback on the debugger origin; an api call with none 401 with a Bearer challenge and no code in the body; `/api/samlacs` reaching the forwarder with no credential while `/api/samlresponse` is gated; the OAuth landing forwarding GET and form_post; a bearer token refused for its typ, audience, permission, expiry and signature, **and for a subject holding no console role even when it carries the permission**, and for everybody while neither role group has a member; the static site with the placeholder substituted, traversal refused, GET only; and forwarding with the prefix stripped, Cookie and Authorization dropped, the forwarded headers added, the api's Set-Cookie dropped and a Location rewritten to the browser's origin. What it does NOT drive is the full sign-in through the authorization server and a real api child — that was run by hand against an isolated instance and is recorded in `debugger/CLAUDE.md` |
| `debugger_api_process.js` | **THE EMBEDDED DEBUGGER'S API CHILD, SUPERVISED** (2026-09-13), with a stand-in api written in the file: the child holds only the contract's variables and PATH, HOME, LANG, TZ — a variable only this process holds does not cross — and its own embedded configuration and the anchor it was given; ready only once it reports listening, in an owner-only directory; **a new trust anchor replaces it** (the same anchor nothing, not ready at once, a successor reading the NEW anchor, not counted as a failure); a child that keeps dying given up on at `debugger.restartLimit` after exactly the restarts it is owed; `stop()` removing the directory. Four mutants, all caught — the replacement counted as a failure, ready while replacing, the new anchor not recorded, the environment inherited |
| `realm_row_arrival.js` | **A REPLICATED ROW FOR A REALM THIS PROCESS HAS NOT HEARD OF YET WAITS IN THAT REALM'S PARTITION** (2026-09-14). `realms.js`'s `partitionId()` sent an unknown id to the DEFAULT realm, so a dispatch run's default realm held forty other realms' receiver streams and pushed every event to all of them. In a CHILD PROCESS, through the `restore` accessor `applyLocally()` calls, for a map, an array and an object: not in the default realm, there once the realm arrives, refused for a realm this process removed (so a realm defined again starts empty), and `''` still the default realm. Two mutants — the old expression, and no removed-realm check — both caught |
| `minted_keyless_realm.js` | **A PRODUCT-MODE REALM IN A KEYLESS DEVELOPMENT PROCESS SAYS STS-STORE-0018 ONCE** (2026-09-14). `persistence_minted.js`'s `enabled()` reads `global.mode` through the ambient realm, so a postgres-mode suite run logged that code at ERROR on every flush a product realm's traffic scheduled — eleven lines about one configuration. In a CHILD PROCESS reading the module's own log lines: four flushes in a product realm write nothing and warn exactly once; three flushes with the PROCESS in product mode and no key are three errors; `enabled()` is unchanged in both, because `restore()` reads it and a keyless product process must still fail that fatally. Two mutants — always an error, and warning every time — both caught |
| `token_exchange_jti.js` | **A TOKEN EXCHANGE THAT MINTS NO ID TOKEN OR REFRESH TOKEN LOGS NO STS-OAUTH-0182** (2026-09-14). `oauth2.js`'s `jtiOf()` was asked about `exchanged.id_token` and `exchanged.refresh_token` whether or not they existed, and base64-decoded the word "undefined" — `Unexpected token '�', "�w^~)�"` at ERROR once per suite mode. In a CHILD PROCESS serving the stack on a loopback port and reading its own stdout: an exchange with and without `openid` logs nothing, and the delegation act still names the exchanged access token's jti. Two mutants — the guard removed, and `jtiOf()` answering empty always — both caught |
| `front_process_realm_arrival.js` | **A REQUEST THE FRONT PROCESS KEEPS IS PLACED IN A REALM THAT ARRIVED WHILE IT WAITED** (2026-09-15). `app.js`'s realm middleware runs before `request_pool.js`'s catch-up, so a NEVER_DISPATCHED request naming a realm a worker created moments earlier kept its `/realm/<id>` prefix and got `Cannot POST` — `sts_admin_api_operations` in `dispatch` mode. The pool is handed `enterRealm` and asks it again after the catch-up. In a CHILD PROCESS: the realm created between the two looks is entered (prefix stripped, `req.realm`, ambient), a request already in a realm is not asked again, and `app.js` wires it (source). Three mutants — no second ask, no realm guard, unwired — all caught |
| `rate_limit_replication.js` | **EVERY FAILURE A RATE-LIMIT BUCKET COUNTS IS JOURNALLED** (2026-09-14): three failures are three writes of the bucket (it was one, so each request worker kept its own count and `sts_est_enrollment` was never throttled in `dispatch` mode), and a count another worker wrote is the one refused on. In a CHILD PROCESS, for the persist observer. The journalling mutant is caught |
| `request_batch_lane.js` | **THE DISPATCHER'S BATCH LANE** (2026-09-14): which paths are batch (the realm segment stripped, a segment boundary, empty turning it off); the lane's size (at least one, fewer than the pool below 100%) and that it is the first workers by fork order; admission — the cap, release starting the next in order and counting once, a full queue answered 503 `STS-WORKER-0040` with Retry-After, a timed-out wait `STS-WORKER-0041`, a departed client dropped, a cap of 0 queuing nothing; and, as SOURCE, that `workerFor()` honours a held binding before the lane narrows. Five mutants: four caught, one equivalent (a clamp the floor already guaranteed) removed from the code |
| `ssf_allowed_events_cache.js` | **A STREAM OWNER'S `ssfAllowedEvents` IS CACHED UNTIL `ou=applications` CHANGES, AND NOT A MOMENT LONGER** (2026-09-14). The lookup was a view of every application per event per stream and a 2,412-session sweep blocked postgres mode for 58 seconds. In a CHILD PROCESS: tightened, loosened and moved by identifier; a receiver id taken away and added; a change through the LDAP modify handler (an unlocated touch) with the answer already cached. Two mutants — a cache that never invalidates, and a version that ignores unlocated writes — both caught |
| `ssf_dead_letters.js` | **UNDELIVERABLE SETs, DEAD STREAMS AND THE PUSH CAP** (2026-09-14), in a CHILD PROCESS: the dead-letter store (the reason, code and status kept, the per-stream cap deleting the oldest, the sweep's summary handed back and reset, retention, a removed stream's letters); dead/revived/half-open state; the push cap against a real listener that holds its answers (two in flight, one waiting, the next refused `STS-SSF-0092`); and through `transmit()` against a listener that refuses then accepts — a refused push dead-lettered OFF the live queue with no `ssf.event.refused` row, a SET to a dead stream dead-lettered unsigned with nothing pushed, and the sweep's probe reviving the stream. Eight mutants, all caught |
| `outbound_tls.js` | **THE OUTBOUND TRANSPORT POLICY, BY DIALLING** (#171, 2026-09-23), in this process, for GNAP's push finish, SSF push, federation's `fetchJson()` and the XACML nudge against https listeners it runs on 127.0.0.1: a self-signed one refused in product even with the family's skip stored on (and the view saying the skip is not in force), one certified by a CA reached in product through the family's `…CaFile`, an unreadable or empty CA file refusing (`STS-CORE-0104`), the skip still working in development; plain http refused without `…AllowHttp`, allowed with it in development, refused in product with each family's code — to loopback too, except GNAP (RFC 9635 section 2.5.2.1); a product write of every skip refused by `setOverride()` and `checkWrite()` (`STS-CORE-0103`) while `checkOverride()`, what a STORED value is restored through, is not; SPIRE's kubelet skip held to the same rule; each removed key refused naming its replacements, and a child process whose environment names one refusing to start (`STS-CORE-0105`); and `mode.report()` carrying the `outbound-tls` row |
| `mode_development_only.js` | **THE DEVELOPMENT-ONLY SETTINGS, BOTH HALVES** (#104, 2026-09-23). The write, in process: `oauth2.breakIdTokenNonce`, `ssf.breakSetSignature`, `ssf.legacySubClaim`, `spiffe.acceptAssertedSelectors` on and `spiffe.attestWorkloads` off refused in product by `setOverride()` and `checkWrite()` (`STS-CORE-0103`) while `checkOverride()` is not, the default accepted, and every one accepted in development. The read, in a CHILD PROCESS that loads the directory, `oauth2.ts`, the SSF signer and the SPIFFE registry for itself: each switch honoured in development (a spoiled ID Token nonce, a SET that does not verify and carries `sub`, asserted selectors believed, every entry handed to a caller matching none), IGNORED in product with every value still stored, twice over, each logged exactly ONCE with `STS-CORE-0106`, and honoured again back in development; and `mode.report()` carrying the new rows |
| `mode_weak_settings.js` | **SIX MORE DEVELOPMENT-ONLY SETTINGS, AND THE MODE'S PAGES** (#181, 2026-09-23), in a CHILD PROCESS that loads the whole protocol stack. The write: `risc.googleSubjectType`, `krb5.clockOffset`, `saml2.signAssertion`, `saml11.signAssertion`, `saml11.signResponse`, `spiffe.requireSecurityHeader`, `saml.allowSha1Signatures` and the weak values of `saml.signatureAlgorithm`, `saml2.keyTransportAlgorithm` and `pki.signatureAlgorithm` refused in product by `setOverride()` and `checkWrite()` (`STS-CORE-0103`) while `checkOverride()` is not, a stronger value accepted, every one accepted in development; an application's `saml2SignAssertion`, `saml2KeyTransportAlgorithm` and `saml11SignResponse` refused in product by `updateApplication()` and a create (`STS-REG-0193`). The read, in development (each honoured, service-wide and per application), in product with every value STILL stored (twice), and back: the RISC subject member, the XML SignatureMethod, the SHA-1 verdict, an `rsa-1_5` EncryptedKey unwrapped in development and refused (`STS-KEYS-0070`) in product, the SAML 2.0 assertion signature and key transport per service provider, the SAML 1.1 Response signature, the Workload API header and `GET /spiffe`, the KDC's clock on `GET /krb5/principals`, a CA's configured and named SHA-1 (`STS-PKI-0191`); each ignored setting and overriding attribute logged ONCE (`STS-CORE-0106`); `mode.report()`'s new rows and `developmentOnlySettings`, `GET /admin-api/mode`, and both routes registered. The HTTP half is `sts_mode_weak_settings.js` |
| `spiffe_local_socket.js` | **THE SPIRE SERVER API'S `local` SOCKET, VERIFIED IN PRODUCT** (#104, 2026-09-23). `SpiffeAuth.localTrust()` over stubbed peer facts and a stubbed uid — no credentials read (`STS-SPIFFE-0119`), a socket not verified private (`STS-SPIFFE-0117`), a foreign uid (`STS-SPIFFE-0118`), the verified case, development trusting with nothing read, the setting off — and `authorize()` carrying the code; `restrictSocket()` and `socketPrivacy()` over a real socket (0600 in 0700 is private; a 0666 socket, a 0755 directory and a failed chmod are not); and a realm's SPIRE Server API bound on a Unix socket with a CLI in a CHILD PROCESS calling `Entry.CountEntries`: answered in product, refused `UNAUTHENTICATED` naming the mode once the socket is 0666, and answered again in development. Needs the native module (a failure without it, `spiffe_workload_attestation.js`'s rule); its realm is left standing with SPIFFE off |
| `spiffe_workload_tcp_product.js` | **THE WORKLOAD API OVER TCP IN PRODUCT, AND WHAT AN ENTRY MUST SELECT** (#166, 2026-09-23), in a CHILD PROCESS that requires the protocol stack. `SpiffeAuth.workloadTcpPosture()` in a realm: development served; product undeclared `STS-SPIFFE-0120`; declared with `0.0.0.0` or `::` `STS-SPIFFE-0121`; declared on a named address served; port 0 off. A real bind on 127.0.0.1: product undeclared not listening (the code a mark on the row), nothing answering a connection, `GET /spiffe` saying so with no code in it; declared and wildcard not listening; declared and named listening, a gRPC client over TCP issued a JWT-SVID for the `peer:127.0.0.1` entry and nothing for a transport-only entry written in development (`STS-SPIFFE-0123`); the declaration withdrawn with the port bound refused `UNAVAILABLE`; development bound undeclared. The entry refusal (`STS-SPIFFE-0122`) through the registry, `BatchCreateEntry`/`BatchUpdateEntry` and the console's action layer, for transport only, endpoint only, both and none; development accepting it. `peer:` exact. Its realm is left standing with SPIFFE off |
| `ssf_dead_letter_report.js` | **MONITORING → SHARED SIGNALS → DEAD LETTERS COUNTS WHAT THE QUEUES HOLD** (2026-09-14), in a CHILD PROCESS: STS-SSF-0092, -0093 and -0096 counted as causes of their own and every other code as a push that failed, with the counts per cause, code, status and event type each adding up to what is held; no token in the report; a letter added in one realm in no other realm's report; the retention window in sixty one-minute buckets, a round bucket size for a longer window, and letters older than the window counted beside it; dead, half-open and failing told apart, dead first, and a delivering stream with no letters not a row; the sweep history's twenty kept with totals, per realm; and `admin_views.ssfDeadLettersState()`'s exact `dlstream`/`dlcause`, substring `dlq`, combined, and paging after the narrowing. Five mutants, all caught. The page and `GET /admin-api/ssf/dead-letters` are walked by `sts_admin_console.js`, `admin_api.js` and `sts_admin_api_operations.js` with no change to them |
| `realm_administrators.js` | **A TRUST REALM'S OWN ADMINISTRATORS** (2026-09-14, #32), in a CHILD PROCESS because it loads the stack. Seven sections: the roster is per realm (a grant in a realm lands in its `ou=groups` and the default realm's roster does not move); the per-realm bootstrap `admin` and its window, in a fresh realm, closed by that realm's own sign-in and not by another realm's; the account protected from deletion in its realm; `gateStateFor()`'s `authority`, `identityRealm` and `outsideRealm` from a stubbed session, including one username signed in through two realms; `admin_scope.ts`'s tables — service pages, actions, `REALM_READS`, prefixes, keys, and a `perProcess` row no prefix names (`spiffe.maxRecordedConnections`); `realm_chooser.decide()` — nothing to choose before any realm exists, the page, the redirect built from the registry, an unknown id, a deep link; and certificate enrollment asking a realm's roster. Ten mutants, all caught — two only after the fixture grew the per-process row and the no-realm question |
| `session_reauthentication.js` | **THE SAME PERSON SIGNING IN AGAIN IS A RE-AUTHENTICATION, AND A SESSION COOKIE IS `<sid>.<handle>`** (2026-09-14). `authn/CLAUDE.md`'s *What an authenticated identity is here* is the design and this is its contract. A step-up by the same person keeps the SAME record and sid, adds an event, moves `acr`/`amr`/`auth_time`/`via` to the latest while `sessionStartedAt()` and `expires` stay, keeps the relying parties and the derived portal session, and tells the observer `reauthenticated` and nothing else; the handle rotates (the old cookie, a bare sid and a bare relying-party id all refused, only a hash stored); a step-down lowers `acr`; CAEP's `assurance-level-change` on `urn:sts:acr` with `increase`/`decrease` and nothing for an unchanged level; a DIFFERENT person still replaces the session and its derived one; an arrival cookie does not survive the sign-in that upgrades its row (fixation); the event list bounded at `MAX_SESSION_EVENTS` keeping the first. In a CHILD PROCESS, because `oauth2.rfc9700` is restart-only: a step-up revoking no refresh token, and a forged-handle cookie ending nothing when somebody else signs in on it. **The defect was measured by a probe first** — the session dropped, the portal session ended, the parties forgotten, two `session-revoked`, and in RFC 9700 mode a refresh token revoked. Mutation: the re-authentication branch disabled, caught. **Since the same day** also: a keyed API session's touch journalled, `/admin/sessions` rows keeping `startedAt` while `authTime` moves, and `signOnFactsFor()` answering a portal session's step-up from its parent (with the portal's card read as source) — four more mutants, all caught |
| `stable_subject.js` | **A PERSON'S `sub` IS `urn:uuid:<entryUUID>`, AND A SCIM ID IS THE `entryUUID`** (2026-09-14), in TWO CHILD PROCESSES, because it serves the whole stack on a loopback port and two of its claims are about determinism across processes. The directory: assigned (v4 for a door, v5 for a seed), kept through an overwrite that hands one of its own and through a rename, new on a delete and re-create, backfilled on a replicated row, refused to an LDAP add and modify in DEVELOPMENT mode, returned on a search only when asked, and `deleteOldRdn` removing the old uid; the subject: `userFor()`, `identityOf()` and `nameForSubject()` both ways, the legacy form still read, no subject for somebody with no entry, no phantom entry for a subject naming nobody and no create under one; sessions: the entry made first, `ldap.autocreateUsers` off refusing an unprovisioned person (`STS-AUTHN-0180`) while an existing one, a keyed caller and an unauthenticated session are not; the token endpoint over HTTP: the ID Token and access token `sub`, a refresh after a rename keeping it, a refresh refused once the person is deleted AND re-created under the same name, a password grant refused for nobody; SCIM over HTTP: the id, a GET by it and by a DN, a member id stored as a DN; and a partner's `urn:uuid:` never resolved locally. **Since the same day**: a create race between two processes keeping both UUIDs (the lower primary, the other an alias, the same answer in either order, written back once, a re-create not merged, the alias carried by a modify and a replace and unwritable), a refresh token and a browser session under an aliased subject, a WS-Trust JWT refused for nobody, GNAP's opaque identifier surviving a rename, one `/admin/users` row and one RISC row across a rename, and a SCIM list over a row with no timestamps. Mutation-tested with the next file, sixteen mutants through a `NODE_OPTIONS` require hook, all caught, and twenty-three more for the additions |
| `federation_subject_policy.js` | **WHICH PEOPLE A FEDERATION PARTNER MAY ASSERT** (#109, 2026-09-22), in a CHILD PROCESS per mode — its listener serves https under a CA the child makes and names in `federation.outboundCaFile`, because product mode refuses a plain-http back channel (#171) — the service provider's realm in development and then in product — through a real OIDC federated sign-in between two realms: `link-at-first-sign-in` (the linking screen with the name fixed and no passwordless or anonymous door, nothing written before the link, a wrong password, Cancel `STS-FED-0099`, the right password recording `<relationship> <iss> <sub>`, a held TOTP factor asked for — development only, since an in-process product realm has no key-encryption key to seal one — a required factor's enrolment step, and a namespaced entry for a subject naming nobody); the administrator refusal `STS-FED-0093` with a link and its override; `pre-linked` `STS-FED-0091` and a link made by the admin action; a link on a second person refused; `jit-namespaced`; `any-existing` as the mode says (`STS-FED-0094`, `STS-FED-0095`); the domain, pattern and group rules; an unlink ending the partner's sessions; SCIM's extension creating, refusing and removing a link; and the two paged views |
| `federation_provisioning.js` | **DYNAMIC PROVISIONING, PRE-PROVISIONING AND THE ATTRIBUTE REFRESH SWITCH, THROUGH A REAL FEDERATED SIGN-IN** (2026-09-14), in a CHILD PROCESS: the default realm's OpenID Provider and a service-provider realm of the file's own, joined by an OIDC relationship — code flow, PKCE, the back-channel token request, the ID Token verified against the published keys, `preferred_username` as the username and `email` onto `mail`. Both switches on by default; provisioning ON creates the entry; OFF refuses somebody nobody provisioned (403 *has not been provisioned*, `STS-AUTHN-0180` in the service provider's audit) and signs in a person pre-provisioned over `POST /scim/v2/Users` onto that entry, with the same entryUUID SCIM returned; refresh ON overwrites a returning person's `mail`, OFF leaves the SCIM value and still records the relationship, OFF with provisioning ON still writes a created entry's attributes, an edit made in the directory survives the next sign-in, and turning refresh back on overwrites it again |
| `certificate_holder_rename.js` | **A PERSON'S CERTIFICATE FOLLOWS THEIR ENTRY, NOT THEIR NAME** (2026-09-14), in a CHILD PROCESS (the stack for the subject resolver, and a certificate authority). A `tls-client` certificate and an ACME-enrolled one: the identity gate names the holder; after a rename it names the renamed person, and `stillHeld()` and `findEnrolled()` still find the certificate; after that person is deleted and somebody new created under the old name, the certificate is refused `HOLDER_GONE` and the lookup finds nobody. Six mutants — the resolution skipped, either issuing door not recording the subject, `pki.certify()` not keeping it, the lookup by name, the still-held comparison by the resolved name — all caught |
| `saml2_force_authn.js` | **A SAML 2.0 REQUEST MAKES ONE TRIP TO THE SIGN-IN SCREEN** (2026-09-14), in a CHILD PROCESS serving the whole stack. `ForceAuthn` and Cancel both looped for ever between the screen and `/saml2/sso` — the held request was re-read from its XML on the way back, and `authn_error` was checked after the session. Asserted: ForceAuthn with no session is one trip and Success; with a session the screen is still shown once and the Response's AuthnInstant is fresh; coming back WITHOUT authenticating is `AuthnFailed` (`STS-SAML-0055`), not a second trip; Cancel is `AuthnFailed` after one trip and reported as a cancellation (`STS-SAML-0009`); an unmet multi-factor RequestedAuthnContext on the way back is `NoAuthnContext` (`STS-SAML-0056`); and unchanged, single sign-on with no screen and `IsPassive` → `NoPassive`. Four mutants, all caught — the cancellation one only after the test asserted how a cancellation is reported |
| `scheduler.js` | **The scheduler in one process** (#49, 2026-09-22; the plan's T1), through its constructor in `scheduler_kit.js`'s simulated world: registration refused whole (`STS-SCHED-0009`); a request worker never leads; once per slot by the DATABASE clock with the node's own an hour off; an interval from a setting at runtime, 0 meaning off; cron through croner in UTC, and the catch-up of a missed occurrence once; failed (`0001`), timed out (`0002`) with the claim given back and the late result fenced; every off-reason on the report; manual runs (queued once, same run on a repeat, `0004`/`0005`/`0006`/`0012`); the report in every state; per-process jobs in every process; history keeping each job's latest run; and the real module's three jobs registered by their owners. **Mutants, all caught (2026-09-22):** the run's claim replaced by one that always succeeds (`scheduler_cluster.js` C: B ran while A's claim was live), the fence check removed (C: A's late result overwrote B's, no `0003`), `nowMs()` reading the local clock (C, D, H here and H there), a finished slot re-run (D, E), and the worker check removed (B). |
| `scheduler_cluster.js` | **The scheduler across nodes** (#49; T2): two or three instances over ONE store, claim table and lease table. One leader of three; exactly one succeeded run in every one of over a hundred slots across ten step-downs, the job CALLED once per slot; a leader dying mid-run taken over only after its claim lapses, its attempt recorded `abandoned` (`0011`) and its late outcome fenced out (`0003`); three missed slots one run; a manual run asked on B run by the leader A, and one asked as A dies run by B once; a per-process job on all six processes of two nodes with no claim; a node that never started never leads; a step-down that is not taken straight back; the same leader, last run and next run from nodes three minutes apart. |
| `scheduler_jobs.js` | **The two jobs P1 moved onto the scheduler** (#49; T3), against the real modules: `authn.session-expiry` ends each expired session once (one `session.end` row and one CAEP `session-revoked`, initiated by the `policy`), a second run ends nothing, the lazy lookup still refuses and ends a session first, and `authn.sessionSweepS` at 0 is off; `pki.crl-directory-refresh` is registered once per process, off with `pki.publishCrlToDirectory` off, and publishes every authority's list through the directory it is handed (the test's own, and the one that was there is put back). |
| `key_generations.js` | **Signing key GENERATIONS** (#42, P2), the whole stack in a child: the XML key split (an assertion verifies against `STS.xml` and not the JOSE key), `ensureNextGenerations()` minting a next key once per unit and the generation counter moving, the next key in the JWKS (RSA and a curve unit), the SAML 2.0 metadata and `/crypto/metadata` before it signs anything; every form of that document (Accept, `no-store`, the JWS and the XML Signature verifying as this realm's own, the XSD, the links from discovery and SAML metadata, no private half); `promoteGenerations()` with what was signed before it still verifying; `retireExpiredGenerations()` past the grace, after which it does not. Five mutants caught on 2026-09-22 (the JWKS's RSA and curve standby, a current-only verifier, a document with no standby, a retire that drops nothing). |
| `signing_history.js` | **EVERY SIGNING KEY A REALM HAS EVER HELD** (#42's follow-up, 2026-09-22), the record that outlives the key: a row per key the set holds, nothing private in one (searched for the PEM, the `KeyObject` and the BBS secret at every stage), observing twice recording nothing, a rotation moving the old key to `retired` and the new one to `current`, **a key the set no longer holds marked DROPPED with its certificate KEPT** — which is option B in one assertion — timestamps that never restamp, a certificate captured once and not replaced by a re-certification, newest first, an unknown unit NOT FOUND rather than empty, and a process holding no key set for the realm dropping nothing. Sections A–E over injected dependencies (every input is a state a service reaches only by rotating keys for months); section F drives the REAL `helpers` generations end to end in a realm of its own. **Eight mutants, seven caught**, one recorded EQUIVALENT at its layer (private fields carried into `keysOfSet()` never reach a row, because `rowFor()` builds from a fixed field list — the combined mutant that IS observable is caught); two survived the first round and both were the FIXTURE — a fake that threw on a null key set made the held-keys guard unreachable, and the re-certification check ran after the drop, where a dropped key is never looked at again |
| `signing_rotation.js` | **Signing key rotation on the scheduler** (#42, P3), with the hierarchy built and a clock the test moves: the two realm-scoped cluster jobs, off in development and at an interval of 0; a first run that only mints next keys, a second that does nothing, and one a whole interval later that promotes every unit and the refresh-token keys (D7); the grace (a client's longer refresh token, `signing.retiredKeyGraceDays`, a credential lifetime stretching only the credential signer's, D3); the credential signer's own interval against the token interval; a refresh token sealed before the rotation opening after it and refused past the grace; `retireDue()` dropping the retired keys and superseding their certificates; the audit rows and the SSF notice that never names the refresh keys (D4). Six mutants caught on 2026-09-22. |
| `scheduler_p5_jobs.js` | **What P5 of #49 moved onto the scheduler**, the whole stack in a child: each former timer and piggy-backed purge is a job of the argued kind and owner (the change-log pull a QUIET per-process job at `persistence.pollInterval`, the trim a cluster job, off once replication stops), SPIFFE's authorities rotated only past half their lifetime (D6), and a GNAP biscuit minted before the `jose:EdDSA:Ed25519` unit rotates still verifying, with `/gnap/keys` and the ZCAP controller listing both keys; and the tracked tokens — a revocation dropped at its token's expiry, the record after `oauth2.expiredTokenRetentionS`, a live token untouched. `scheduler.js` L holds the two scheduler changes (a sub-tick interval, a quiet job). Six mutants caught on 2026-09-22. |
| `cache_eject.js` | **Expired cache and replay-store entries ejected by a scheduler job** (#49 P5): `ejectExpired()` calls each ejector once, sums and counts evictions, survives one that throws, refuses a non-function `eject`; exactly the twenty-four expiring stores eject (the Logout Token deliveries and decrypted keys deliberately not); `caches.eject-expired` is quiet and per-process; through ACME's and GNAP's own doors a live entry is kept and an expired one is gone. Two mutants caught on 2026-09-22 (an ejector that deletes a live entry, one that deletes nothing). |
| `client_secret_rotation.js` | **Client-secret rotation and expiry** (#49 P5): `rotate-secret` keeps the old secret authenticating through `oauth2.clientSecretOverlapS` and no longer (the time alone refuses it; the daily sweep then clears it), `regenerate-secret` still ends it at once; an expired secret refused in product (`STS-OAUTH-0558`) and accepted in development; the sweep's expiring and expired lists with their audit rows; the daily job registered per realm. Three mutants caught on 2026-09-22. |
| `no_periodic_timers.js` | **Anything periodic is a scheduler job, enforced** (#49; T4): every `setInterval`, and every `setTimeout` in a function that re-arms itself, outside `cluster/scheduler.ts` is on its `ALLOWED` list with the job it becomes or the reason it is permanent; a new one fails, and an entry whose timer has gone fails too, so the list only shrinks. Reads statements, not lines. **Mutant, caught (2026-09-22):** a `setInterval` added to `common/helpers.js`. |
| `random_values.js` | **Random values from node's generator, drawn uniformly** (#65): `common/crypto.js` section 13's `randomString()` over GNAP's 31-character alphabet against a chi-square bound, **with the old `byte % 31` computed beside it as the control** — a distribution test that cannot fail the code it replaced asserts nothing; the refusals (under 128 bits, a repeated character); `genId()`'s shape; the service's source read, comments and strings blanked, for `Math.random(`, forge's generator, `pseudoRandomBytes`, forge's envelope and key encryption, a random byte taken modulo anything or scaled by 256, an integer read from a buffer taken modulo anything, a require of a second random-value package, and an RSA encrypt or decrypt handed a forge scheme name; **the tests' own files (the parent's copies excepted) for `Math.random(`**, because CodeQL follows a test's value into the service and reported sixteen alerts on `ldap/ldap_server.js` that way; the detector against twenty-five shapes, found and ignored; **node's `randomBytes` watched while forge draws, signs and encrypts** (the second pass: `forge.random` had left the call sites and not the library); `rsa-oaep-mgf1p` and `rsa-1_5` wrapped through `publicEncrypt()` and unwrapped by forge, an independent RSA; the password generator's distribution with its excluded characters never drawn; and no second random-value package in `package.json`. No allow list. |

**`sts_portal_sessions.js` WAS THE NEWEST OWNED JOB WHEN THIS WAS WRITTEN
(2026-09-06)** and it covers
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
own PKI engine, already in this repository, already what `spiffe/spiffe_ca.ts`
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

The tests in the table below need only this service, and since 2026-08-28
they are OWNED by two different repositories — which is the first thing to
know about it, because the first of them ran from the parent's suite before
that date. **MOST ARE THIS REPOSITORY'S OWN, AND `MANIFEST.js` IS THE COUNT** — what
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

**The rest are still the parent's**, and this repository holds copies of
the ones a lone mock can satisfy (`MANIFEST.js` lists them; three have a row
below) — `sts_persistence_postgres.js` is not vendored, because it needs docker.

**Every job in `MANIFEST.js` runs from `tests/vendored/`**, so they run against
this working tree with no parent checkout present. The paths in the first
column are where each file is READ FROM here; for the copies the parent owns,
that copy is not the source of truth. **The in-process pair `user_graph_permissions.js` and
`app_permissions.js` is deliberately NOT repeated here** — it sat in this table
while the table lived in the root `CLAUDE.md`, where the first table above was
out of sight; both files have a row up there and a section of their own below,
and carrying them twice is what made this table's own arithmetic wrong.

| Test | What it covers |
|---|---|
| `tests/vendored/sts_metadata.js` **(ours)** | the `/admin/sts-metadata` drift checks — that the page lists exactly what the router registers, that every method reaches a handler, that every link resolves, and that no specification claim is idle |
| `tests/vendored/sts_cluster_alternation.js` **(ours)** | **THE MODE IS WHAT THE LAUNCHER SAYS IT IS** (2026-09-14, #46): in the `cluster` mode both nodes answer `GET /admin-api/cluster` through `fetch()` and `https.request()`, a quarter each at least, and both are live members; in every other mode one identity answers everything. First in the manifest. The keep-alive mutant is caught only because of a 20ms pause between requests — *THE `cluster` MODE* below |
| `tests/vendored/sts_metadata_anonymous.js` **(ours)** | **EVERY METADATA DOCUMENT THIS SERVICE PUBLISHES, FETCHED BY A CALLER HOLDING NOTHING** — nineteen of them across ten protocol families, plus the two RFC 8414 issuer-path forms and the per-partner SAML documents. The row above is about the INDEX and this one is about the documents, and they fail for opposite reasons: one goes red when the page and the router disagree, the other when a document a client must read BEFORE it can authenticate stops answering somebody who cannot yet authenticate. Five questions of each: 200 with no redirect, the media type the specification names, a shape (the issuer this service claims, a non-empty key set, a signature on the SAML metadata, and no PRIVATE member on any published key), no `Set-Cookie` **except the request pool's own routing pin**, and `Cache-Control: no-store` — that last one found `/sts/cert` served without it, which is a certificate this process regenerates on every start being cacheable. **The cookie exemption is the one thing in this job that is about the DEPLOYMENT rather than the document** (2026-09-11): in `dispatch` mode `common/request_pool.js` is a load balancer in front of three workers and appends a sticky-routing cookie to any response whose request arrived with nothing to route it by — which every document here is — so this job was red in that mode and green in the two single-process ones over a cookie no handler set and no handler can see. It is not a session: it names a worker, nothing is authorized by it, and the pool STRIPS it from the request before a worker sees it. The exempt name is **read off `common/request_pool.js`** rather than written down, the way the `PROTOCOLS` coverage check is, so a rename there closes the exemption instead of widening it into "any cookie at all". **Four gated surfaces are driven as CONTROLS** (`/admin-api/status`, `/scim/v2/Users`, `/xacml/policies`, `/admin/sts-metadata`), each refusing differently, because the failure this file has to rule out is its own: a fetch that follows redirects reports the console open to strangers, since `/admin/sts-metadata`'s 303 ends at a sign-in screen answering 200. **The /admin-api control sends `Authorization: none`** and a section of its own says why — `tools/attach-admin-token.js` is preloaded into every job and would otherwise attach the run's admin token to a request written to carry nothing. Coverage is checked against THIS TREE: every family in `sts_metadata.ts`'s `PROTOCOLS` either publishes a document here or is named in `NO_PUBLIC_METADATA` with its reason (Kerberos and SPNEGO have no such document, LDAP's is the rootDSE on a socket no stack publishes to this job), and every `/.well-known` path this tree REGISTERS is accounted for |
| `tests/vendored/admin_api.js` **(ours)** | the management API at `/admin-api`: its OpenAPI document, the PARITY it exists to keep — every `/admin` page and every action of its four handlers has an operation, read off this service's own answers rather than off a list in the test — every documented schema property checked against a live reply, and that a revocation made through the API is dead at `/oauth2/introspect`. It restores everything it changes, including the tokens its bulk revocations touched |
| `tests/vendored/sts_dpop.js` | RFC 9449 end to end over HTTP: all twelve section 4.3 checks, the `cnf.jkt` binding on access and refresh tokens (a refresh token issued to its secret-authenticated client is unbound since #176, and refreshes with a new key — section 5; the job accepts either, the parent running an older service), `dpop_jkt`, `jti` replay, and the nonce handshake in both shapes. Almost entirely negatives, because a DPoP server that issues bound tokens and accepts good proofs looks finished and can be worth nothing |
| `tests/vendored/oauth2_sts_endpoints.js` | every endpoint the RFC 8414 metadata advertises answers, and every token verifies against the advertised JWKS |
| `tests/vendored/vc_did.js` | the DID-named issuer chain: advertisement → resolution → domain linkage → the key that actually verifies the credential |
| `tests/vendored/sts_admin_api_operations.js` **(ours)** | **the other half of that API — EVERY operation it declares, driven for real, with a LEDGER that says so.** No count is written down in it, on purpose: it was ninety operations when the file was written, a hundred and thirty-one a few days later, and 337 on 2026-09-16 (97 reads, 240 writes). Two things are asked of that ledger at the end of the run and both are about the FILE rather than the service — **every documented operation was driven**, or holds a row in `NOT_DRIVEN_HERE` naming who drives it instead (a table that is empty as of 2026-09-16; its last rows were the explorer's, which `admin_api.js` owns along with its CSP), and **every write that succeeded was read back through the resource's own GET, in the scope it was written in**. Besides that: each documented example body replayed, so that a request property the document names and the handler does not read fails HERE rather than for the first caller who copies it; each handler's refusal sentence checked against the document both ways round (that sentence is what `admin_api.js` reads for the parity, so one short by an action turns the parity check off for it); every write read back through a DIFFERENT operation; and a configuration change followed as far as the persistence store's own write counters. Almost all of it in a trust realm it creates and LEAVES STANDING; `removeRealm` is consequently the one operation of that API driven only by its refusal, which the ledger accepts because a refusal is recorded as DRIVEN and not ACCEPTED |
| `tests/vendored/sts_admin_console.js` **(ours)** | **the `/admin` console itself, IN A REAL BROWSER since 2026-08-28: the gate, every page (thirty-eight when it moved into a browser, well over a hundred since), every link, every GET form and every button on them — and the value that comes back afterwards.** It was an HTTP job, and the argument for that (this console has no script on it, so a control IS a form and pressing a button IS posting it) is still true; what it missed is that a hand-built submission is the TEST's reading of the markup rather than the browser's, that the twenty-two GET forms had no POST target to walk and so were never checked at all, that the nested-`<form>` guard is a PARSER question the old file had to reason about instead of asking, and that a notice is not a value. Status codes and headers come from **WebDriver BiDi**, because `default-src 'none'` blocks a `fetch()` from the page — the thing under test. Plus: every link really visited, which covers the seven routes with no nav row by construction; the five handlers nothing had ever pressed, `/admin/rbac`'s own grant and revoke among them; refusals split into what the BROWSER will not send and what the handler will not accept; the realm switcher; and the browser's own console, which on this console must be empty. **Since 2026-09-06 it also holds the assertion `/admin/users/new` rests on**: a create with two boxes filled and the rest empty is read back OUT OF THE STORE and the five attributes `namePlan()` invents are asserted ABSENT. That is the one thing about that page nothing else could show — a person is invented in two places, the create succeeds either way, and the fiction is visible only in an `ldapsearch`. Beside it: Fill fills the empty boxes, leaves a typed one alone and creates nobody; a generated password is shown once and stored as a scrypt hash; and the activation link the page hands over is SPENT, because a link that 400s looks identical on the page that issued it |
| `tests/vendored/sts_realm_administrators.js` **(ours)** | **A TRUST REALM'S OWN ADMINISTRATORS OVER HTTP** (2026-09-14, #32), in two realms it creates and leaves standing. The chooser on a bare `/admin` and `/portal` (a list in development, a text box in product), `?realm=<id>` redirecting under the prefix, an unknown id refused, `?realm=default`, a deep link and a prefixed surface never asked; a person signed in through a realm reading its pages, with no service page in the navigation and none of the runtime footer's store and secret facts, refused four service pages under their own prefix, the default realm's console (`outside_realm`) and another realm's, a per-process setting, a realm create (and nothing created) and `build-root`; the service administrator reading service pages at the root and under both realms; the service administrator's USERNAME signed in through the realm refused a service page; and a realm's own `sts-management-api` token reading its realm, 401 at the root and another realm, 403 at four service-wide operations, allowed a realm setting, while the service token still works under the prefix and the same scopes from another client in the realm are refused. It grants the default realm's Admin Write only if that realm's console is not open to anyone (`openToAnyone`), and revokes it; in product, which never opens a window (#103), it grants the realm person Admin Write in the realm first. Floor of forty checks. **Eight service mutants through a require hook preloaded into the throwaway service, all caught** — the service-page rule, `outsideRealm`, the realm token's client check, the chooser, the footer, the realm token never tried, the settings rule, and the roster read by name rather than by sign-in realm; **the navigation check first matched a Persistence link in the Tokens page's prose, and reading the page for it found the runtime footer drawing the database host and secret-store paths to a realm administrator** — the footer shows them the mode only now |
| `tests/vendored/sts_console_bootstrap_product.js` **(ours)** | **THE CONSOLE BEFORE ITS BOOTSTRAP ADMINISTRATOR ARRIVES, OVER HTTP, IN BOTH MODES** (2026-09-22, #103), in a realm it creates and leaves standing. `/admin-api/rbac` reports the window open in development and closed with `bootstrapPasswordRequired` in product; a person holding no role, signed in with a password, is let in by development and refused `insufficient_role` by product; a client certificate (`GET /tls/sign-in`, under this job's own anchor added through `/admin-api/tls/trust/add`) holding no role is refused in product and let in by development exactly while the default window is open; in product, while the default realm is unclaimed, a certificate naming `admin` is refused `bootstrap_password_required`, is drawn the page that says so, and claims nothing (never tried in development, where it would claim the default console for every later job); the realm's `admin` signs in with the password its create handed back, answers the change step, holds both roles and claims the console, after which the person holding no role is refused in both modes. Floor of nine checks in product, eight in development |
| `tests/vendored/sts_delegated_permissions_example.js` **(ours)** | **THE DELEGATED PERMISSION REGISTER AS A RING, AND THE ONE JOB HERE THAT LEAVES ITS WORK BEHIND ON PURPOSE.** `abcapp1`–`abcapp5` in the DEFAULT realm, each declared for OAuth 2.0 and OpenID Connect with its supporting fields filled in, each exposing `read` and `write` under a base URI of its own, and each granted both on THE NEXT ONE ROUND — `abcapp1`→`abcapp2`→`abcapp3`→`abcapp4`→`abcapp5`→`abcapp1`: five resources, ten permissions, ten grants. **It was a complete mesh of forty grants until 2026-09-01** and the file argues the change rather than merely recording it: the mesh was the stronger test and the weaker EXAMPLE, and this job is both — forty lines between five boxes is the one graph shape that looks the same however it is drawn and however it is wrong, and this example exists to be LOOKED at. What survives is the assertion that matters: every grant still resolves to the RIGHT resource among five whose bases differ only in a digit, so a lookup matching on a prefix, a host or the bare name is wrong for four of the five pairs. What replaced the mesh's arithmetic is an EXACT-LIST assertion per entry — `abcapp2` holding `abcapp4`'s `read` would keep every count right and be wrong about the only thing the example says. Plus the two halves landing on the right ENTRIES (a grant written to the resource instead of the client reads correctly on `/permissions` and finds nothing at the token endpoint), the PICTURE — five boxes, ten lines, `may-reach` on every one and `acts` zero everywhere, because a configured grant has been exercised nought times and the renderer colours `acts && !issued` as a refusal — and the TOKEN, audienced to the one base URI of five that was asked for (its own successor, the only one it holds anything on), carrying the bare names on its scope claim, and moving exactly two of the ten grants to `asked`. It is IDEMPOTENT (the identifiers are fixed, so every previous `abcapp*` is forgotten first) and it does not tear down, because the example exists to be READ at `/admin/delegation/allowed`. **Since 2026-09-02 it also asserts the GROUPING** — that the five are ONE group and that nothing else in the default realm is in it, which are two different failures (a partition too fine, and one too coarse) that a service with only these five configured could not tell apart, and that all five applications resolve to it, since every one of them is both a client and a resource. What it deliberately does NOT assert is the direction decision: a ring is connected whichever way you walk it |
| `tests/vendored/sts_gnap_core.js` **(ours)** | **GNAP (RFC 9635) AS A CLIENT INSTANCE DRIVES IT** (2026-09-12): every interaction start mode and finish method, the four key proofs, continuation, modification, revocation, token and key rotation, subject assertions, key references, instance identifiers, authorization server profiles, `too_fast` and realm isolation — every refusal asserted by its GNAP error CODE and `no-store`. The client is `gnap_client.js`, written from the RFCs with node's crypto and nothing from `gnap/`; the resource owner signs in through the real sign-in screen in `gnap_flow.js`'s cookie-jar browser. A FLOOR on its check count. **Section 6's push listener presents a certificate from a CA the job makes at run time and sets `gnap.pushCaFile` to it (#171, 2026-09-23)** — product mode ignores every skip of verification — so the push is VERIFIED, and the job passes in the product modes where it used to fail on the push; with no directory shared with the service the section is skipped |
| `tests/vendored/sts_gnap_rs.js` **(ours)** | **THE RESOURCE SERVER'S HALF (RFC 9767), AND EACH TOKEN FORMAT CHECKED BY THE JOB'S OWN CODE** rather than by asking introspection whether the authorization server agrees with itself: the JWS against `/oauth2/jwks` with `cnf.jkt` recomputed, the JWE opened with the job's own RSA key, the macaroon V2 binary decoded and its HMAC chain recomputed, the biscuit protobuf walked and its authority signature verified, the zcap verification method resolved to the published key. **Section 2b then puts every format through the whole lifecycle at the demonstration resource server** — accepted for read and write, refused to another key and without a proof, narrowed to read only (403 on write), rotated, revoked, a bearer variant, and expired — because modification and rotation RE-MINT in the token's own format and the resource server's format-specific checks run only on an acceptance. Two mutants (rotation and modification minting jwt-signed regardless) are caught there. Then introspection active and six ways inactive, registration, derivation and its three refusals, revocation reaching introspection, and a self-signed certificate proved by mutual TLS. **It found two defects on its first run**: the macaroon root key was never written onto the resource server's entry (`updateApplication()` refuses a derived attribute), and every zcap token for a resource server with a plain name failed to mint. Five server-side mutants, all caught |
| `tests/vendored/sts_gnap_mtls.js` **(ours)** | **GNAP MUTUAL TLS AGAINST A RUNNING SERVICE, BOTH TRUST MODELS** (#107, 2026-09-23): grant requests whose only proof is the client certificate on the main port, from trusted clients so a 200 means proved and bound. `auto` pins in development and refuses a self-signed key in product (0287); `pinned` accepts it, and refuses no certificate (0277), another one (0278) and a revoked realm-issued one (STS-PKI-0118); `pki` binds certificates from the realm's Credentials door by value and records the thumbprint, rotates to a second one, refuses the revoked first and another entry's (0291), and binds a foreign authority's leaf — which names a CRL the job serves — by `oauthTlsClientAuthSanDns`, refusing another subject (0290) and none (0288); `gnapMtlsTrust=pki` in a pinned realm refuses (0287) and `pinned` in a pki realm is refused on write (STS-REG-0196). Every code read off the realm's audit. `sts_gnap_rs.js` section 6 sets its realm to `pinned` for its self-signed certificate |
| `tests/vendored/sts_gnap_signals.js` **(ours)** | **A GNAP WEB APPLICATION AS A SHARED SIGNALS RECEIVER**: it creates and polls a stream with its own GNAP access token, receives signed CAEP `session-revoked` for a revoked grant and a revoked token and `token-claims-change` for a modified grant, and hears NOTHING about a person who never approved it — asserted against an unscoped control stream receiving the same event, which is what proves the silence is the scope and not a broken pipe. `gnap.caepEvents` off is asserted with a second revocation drained after it, because delivery is not awaited by the revoking request |
| `tests/vendored/sts_mail.js` **(ours)** | **THE MAIL CHANNEL DELIVERING TO A REAL SMTP SERVER** (#63, 2026-09-22), in a product-mode realm it creates and leaves standing. The stack runs **Mailpit** (MIT), requiring STARTTLS with a certificate `openbao/generate-tls.js` mints at run time into the shared directory (`mailpit-tls`, then `mailpit`, both unattached in the launcher); the job points the realm's SMTP transport at it with that certificate as `mail.smtpCaFile` and reads what arrived through Mailpit's HTTP API. `capture` refused in product (`STS-MAIL-0003`); a test message delivered (From, Auto-Submitted, no image); an address an administrator provided already verified, so the verification an administrator asks for sends nothing (#64 moved the link flow to `sts_email_verification.js`); forgot password in its ONE-FIELD form (`mail.resetRequiresBackupCode=false`) answering an unknown account and a known one identically, the known one's verified address mailed a link that sets a new password, and the password-changed notice after it; an administrator's reset link with `deliver: "mail"` not returned but mailed; a dead letter (implicit TLS against the STARTTLS port, one attempt) retried and delivered; the outbox with no body. **Skips its delivery sections where `MAILPIT_API_URL` is unset** (an AWS target, the coverage run). Floor of seventeen checks |
| `tests/vendored/sts_email_factor.js` **(ours)** | **THE EMAILED CODE AND SIGN-IN LINK OVER HTTP** (#64, 2026-09-23), in a DEVELOPMENT realm it creates (a product realm's portal cannot sign anybody in on a service that is not itself in product), delivering to the same Mailpit. The Policies resource carrying both policies as kinds, the email rows off by default and DISABLED with the reason where the realm cannot send mail, a save turning one on refused, and the realm following the DEFAULT realm's profile until the default's is removed; a person opting in on `/portal/mfa`, their next sign-in mailing a code in the layout, a wrong one counting down, the right one signing in `amr ["pwd","otp"]`, `acr "mfa"`; a code alone signing in `amr ["otp"]`, `acr "1"`, and an unknown name answered with the SAME page; a link whose GET spends nothing, refused in another browser, and signing in on Continue in the one that asked. Registers the realm portal's callback first. Skips all but section 0 where `MAILPIT_API_URL` is unset. Floor of twenty-one checks |
| `tests/vendored/sts_email_verification.js` **(ours)** | **WHICH ADDRESSES ARE VERIFIED, A PERSON'S OWN CHANGE, AND THE RECOVERY-CODE RESET** (#64, 2026-09-23), in a realm it creates in development and switches to product for the reset. An administrator's address verified at create and by `set-mail`, the former address told; a person's change on `/portal/email` PENDING until the link sent to the new address is followed (the GET spends nothing, the form once), then the account's, verified, the former told; the three-field forgot-password form, a wrong recovery code with the right name and address notifying the owner, every combination answered alike, the right one mailing a link that sets a password, the same code a second time mailing nothing. Skips entirely where `MAILPIT_API_URL` is unset. Floor of nineteen checks |
| `tests/vendored/sts_person_attributes.js` **(ours)** | **A PERSON'S ATTRIBUTES THROUGH `/admin-api`, OVER HTTP** (#228, 2026-09-26), in a realm it creates and leaves standing. `GET /admin-api/users?user=` publishes `attributeEditor` with the entry in the realm's own tree, title editable, userPassword and mail withheld. set-attribute, add-attribute (twice) and remove-attribute are read back on the next GET, with the country upper-cased. userPassword, mail, an add to displayName and a country that is not a code are 400s naming why, and the same name in the DEFAULT realm is nobody there. The OpenAPI document declares the three operations. Floor of nine checks |
| `tests/vendored/sts_outbound_tls.js` **(ours)** | **NOTHING GOES OUT OVER TLS IT DID NOT VERIFY, IN PRODUCT, OVER HTTP** (#171, 2026-09-23), in a development realm and a product realm it creates and leaves standing, so both halves are asserted whatever mode the service runs in. A realm create naming product mode and a skip in one body refused and nothing created (`STS-CORE-0103`); every `…SkipTlsVerification` and `spiffe.k8sSkipKubeletVerification` refused `true` in the product realm through `config/set`, `realms/set` and an all-or-nothing `config/set-many` that writes nothing, accepted `false`, and accepted `true` in development; a removed `…AllowInsecure` refused naming its replacements. **SSF push to this job's own listeners**: a self-signed listener reached in development with the skip, NOT reached once the realm is switched to product with the skip still stored (and dead-lettered with the certificate failure), a listener certified by a CA the job makes at run time reached in product through `ssf.pushCaFile` (skipped with no shared directory), and a plain-http endpoint refused in product whatever `ssf.pushAllowHttp` says. The RFC 9728 import under federation's policy (a self-signed document loaded only with the skip, in development; plain http refused in product), and `GET /admin-api/xacml/peps` reporting a stored nudge skip as not in force. Floor of twenty-five checks; the listeners are on `OUTBOUND_TEST_HOST` or `GNAP_PUSH_HOST` |
| `tests/vendored/sts_spiffe_broker.js` **(ours)** | **THE SPIFFE BROKER API OVER MUTUAL TLS** (#170, 2026-09-23), in a development realm and a product realm it creates and leaves standing with SPIFFE off. A CA of the job's own for a trust domain of its own, federated into each realm, and X509-SVIDs under it for a broker, a pod-only broker and a stranger; the brokers through `/admin-api/spiffe/brokers/set` (a non-SPIFFE ID and an empty type list refused). No `broker.spiffe.io` header INVALID_ARGUMENT, no client certificate UNAUTHENTICATED, a stranger PERMISSION_DENIED; no reference INVALID_ARGUMENT with a `google.rpc.ErrorInfo` (WORKLOAD_REFERENCE_INVALID); a type not allowed PERMISSION_DENIED; a missing pid NOT_FOUND (WORKLOAD_NOT_FOUND); pid 1 attested by the unix attestor and answered (FetchJWTSVID, SubscribeToX509SVID; `STS_SPIFFE_BROKER_PID_UID`, 0); a pod by UID over a fake kubelet on `OUTBOUND_TEST_HOST`/`GNAP_PUSH_HOST` — skip-verified in development, through `spiffe.k8sKubeletCaFile` in product (skipped with no shared directory) — and a pod with no entry WORKLOAD_NOT_ENTITLED; a removed broker refused. Ports `STS_SPIFFE_BROKER_PORT_DEV`/`_PROD` (8193, 8194); an endpoint this runner cannot reach is a skip. Thirty-two checks |
| `tests/vendored/sts_development_only_settings.js` **(ours)** | **THE DEVELOPMENT-ONLY SETTINGS, OVER HTTP** (#104, 2026-09-23), in a development realm and a product realm it creates and leaves standing. A realm create naming product mode and `oauth2.breakIdTokenNonce` in one body refused and nothing created; every marked value refused in the product realm through `config/set` and `realms/set`, an all-or-nothing `config/set-many` writing nothing, and the default accepted; every value accepted in development. Then, in the development realm with the defects on: an authorization code flow's ID Token carrying a spoiled nonce, a poll stream's verification SET failing to verify against the realm's published keys, and `GET /spiffe` reporting both loosening switches; the realm switched to product with every value STILL STORED (and `risk.assessSignIns` off in it, so #62's product-mode risk policy does not ask this job's automated client for a security key): the next ID Token carrying the nonce asked for, `GET /oauth2/rfc9700` reporting the defect not in force, the next SET verifying, `GET /spiffe` reporting attestation on, and a new defect refused. Floor of twenty-five checks |
| `tests/vendored/sts_mode_weak_settings.js` **(ours)** | **SIX MORE DEVELOPMENT-ONLY SETTINGS, AND THE MODE'S PAGES, OVER HTTP** (#181, 2026-09-23), in a development realm and a product realm it creates and leaves standing: `GET /admin-api/mode` per realm (the three new requirements, every marked setting, `notYet`), `getMode` in the OpenAPI document, and `GET /admin/mode` in the console with its `?format=json` equal to the API's; every weak value refused through `config/set` and `realms/set` in the product realm and a stronger value accepted, three application overrides refused through `applications/set`, all accepted in development; then, with every value stored, the development realm's metadata signed RSA-SHA1, `GET /spiffe` not requiring the header and the RISC view writing `subject_type` — and after switching it to product, RSA-SHA256, the header required, `format`, `/admin-api/mode` listing every stored value as ignored, and a CA build naming `sha1-rsa` refused |
| `tests/vendored/sts_admin_risk_upload.js` **(ours)** | **A RISK DATASET UPLOADED AS A FILE, OVER HTTP, IN EVERY MODE** (#215, 2026-09-24): a synthetic `.gz` through `POST /admin-api/risk/upload` answered 202 while `loading` and then `active`, a lookup inside it; Monitoring → Risk's multipart form (the file last, no script) and a `.zip` posted through it with a real console session and the page's own CSRF token, redirected with a notice and then `active`; a realm's list uploaded under `/realm/<id>/admin-api`; and the refusals — a declared length over `risk.uploadMaxBytes` (413 on the headers alone, the connection closed; in `single-node` and `cluster` that is the request pool flushing a large body's headers to its worker), a zip of two files and a gzip bomb each `refused` with its reason, a console upload with no token (403), a body type the API does not take (415), a session holding Admin Read only (403). The files are built at run time by `zip_writer.js` (a local helper) and node's zlib; none is committed |
| `tests/vendored/sts_admin_closed_sets.js` **(ours)** | **EVERY CLOSED SET AN ADMINISTRATOR CAN TYPE INTO, HELD AT EVERY DOOR** (#86, 2026-09-26). Discovered from the published OpenAPI document, never listed: every `enum` in a request body (nested members, array items, `$ref`'d components) posted a value outside its set and refused 400 with `common/closed_sets.ts`'s sentence naming the field and every value — and posted a value FROM it beside a member no schema defines, so the validator refuses on that member and must say nothing about the enum, which proves the accepted value is accepted without the operation running (an operation whose top level takes any member is left out of that half, and named); every query-parameter enum refused outside its set and, on a GET, every value in it not refused; every `POST /admin…` control an operation's description says it mirrors posted its flat enums as a real form (a console session, the page's CSRF token, the operation's `action`) and refused `invalid_value`; every runtime `enum` setting, and every `csv` one carrying `csvValues`, refused through `POST /admin-api/config/set-many` and the console's `set-many`, and afterwards no setting holds the value. Floors on each count, for the discovering job's failure: some rows, not none. Every probe is refused before a handler runs, so nothing is written |
| `tests/risk_upload.js` | **THE SAME UPLOAD IN PROCESS** (#215), both doors driven with synthetic request streams on the memory store: gzip, zip (beside a directory and a `__MACOSX/` entry) and plain to `active` with their files deleted; a gzip bomb, a zip whose declared size is over the allowance, a zip of two entries and a truncated gzip refused with their codes and the active version untouched; the cap on a declared and an undeclared body and a full disk (an injected `statfs`); a wrong CSRF token, a token after the file, a field after the file, no file, a second file and unaccepted terms, all before a byte is written; the console route refusing a session without Admin Write; the API's body types, parameters and an empty file; the exemption predicate; `abandonStalled()` and the per-process sweep; and a `.gz` and `.zip` imported by path |
| `tests/vendored/sts_oid4vp_status_reference.js` **(ours)** | **A STATUS REFERENCE ON EVERY PRESENTED CREDENTIAL, OVER HTTP** (#165, 2026-09-23), in a development realm and a product realm it creates and leaves standing, each trusting a certificate this job makes at run time (`outbound_test_ca.js`). `oid4vp.requireStatusReference` reported `all` in both; `off` refused in the product realm through `config/set` and `realms/set`, `own-only` accepted there, `off` accepted in development; the bar door's `ldp_vc` DCQL query asking for `credentialStatus`; a foreign SD-JWT VC and a foreign `jwt_vc_json` naming no status refused `invalid_request` under `all`, accepted when `oid4vp.statusOptionalIssuers` names the issuer certificate's thumbprint (colon-hex, hex), refused again when it names another, and accepted under `own-only`; and `off` stored in development accepting such a credential, then IGNORED once the realm is switched to product. This realm's own `ldp_vc` withholding its status is `tests/vc_status_list.js`'s (no independent BBS here). Floor of thirty checks |
| `tests/vendored/sts_siop.js` **(ours)** | **SIOPv2 AS THE RELYING PARTY, OVER HTTP** (#129, 2026-09-23), in a throwaway realm with `oid4vp.signInSelfIssued` on: the Entity Configuration at `/.well-known/openid-federation`; a key enrolled by value through `/admin-api` and listed, and enrolled twice refused; the self-issued sign-in from the sign-in screen (a signed `id_token` request with `scope=openid` and the section 8 metadata, answered by an ES256 ID Token of node's own) completing the waiting authorization request; an unenrolled key signing nobody in and another nonce refused `invalid_request`; a person enrolling their own key BY PROOF from their session, the portal page listing both, and removing one there; a removed key signing nobody in; and the bar door's by-value `form_post` request. Floor of fourteen checks |
| `tests/vendored/sts_native_sso.js` **(ours)** | **OPENID CONNECT NATIVE SSO AND THE DEVICE REGISTER, OVER HTTP** (#130, 2026-09-23), in a throwaway realm with four public clients (two in one group, one in another, one not enabled): discovery; the first app's code grant returning a `device_secret` with `ds_hash` and `sid`; the `ou=devices` entry through `/admin-api`; the second app's section 4 exchange in the same session; the refusals — `device_sso` to a client not enabled, another group, the wrong audience, a wrong secret, no `subject_token_type`, an ID Token declared an access token; the same device and secret on a new sign-in; the exchange refused once the session is revoked; `/oauth2/revoke` of the secret; `/portal/devices`; and removal. Floor of fifteen checks |
| `tests/vendored/sts_oidfed.js` **(ours)** | **OPENID FEDERATION 1.1 OVER HTTP** (#132, 2026-09-23), the default realm a Trust Anchor and a throwaway realm its subordinate: both Entity Configurations served as `application/entity-statement+jwt` with no parameter and no-store, typed and self-signed (the job verifies the ES256 signatures itself); the anchor with fetch and list and no authority_hints, the realm naming it; fetch pinning the realm's keys, and 8.9's `invalid_request` and `not_found`; the listing; a signed resolve response with the three-statement chain, and `invalid_request`, `invalid_trust_anchor` and `not_found` (an entity nobody resolved — never walked, 18.1); Trust Marks through `/admin-api` — carried in the realm's configuration, verified in the resolution, handed out, listed, `active` then `revoked` at the status endpoint and gone from the resolution, a foreign mark 404; a registered subordinate with a metadata policy making the realm an Intermediate, its statement carrying the policy, the listing filtered by entity type; a rotation by hand (queued on the scheduler), the retired key in the Historical Keys `jwk-set+jwt`, then revoked with its reason; an emergency rotation without its confirmation refused. Floor of fifteen checks |
| `tests/vendored/sts_ciba.js` **(ours)** | **OPENID CONNECT CIBA, OVER HTTP** (#131, 2026-09-23), in a throwaway realm with `oauth2.ciba` on: discovery (the endpoint, the three modes, the grant); the endpoint's refusals — no client authentication, a client with no delivery mode, no `openid`, two hints, and `unknown_user_id` for a name nobody holds; poll — the acknowledgement, `authorization_pending` then `slow_down`, the person approving on `/portal/ciba` with the binding message shown, and the tokens once; a denial `access_denied`; the user code — `missing_user_code`, the person setting one on the portal, `invalid_user_code`, the right one accepted; and ping and push to a listener of the job's own (`GNAP_PUSH_HOST`), the ping carrying the client's Bearer and the push the tokens, its ID Token naming the request, and a push client refused a poll. Floor of fourteen checks |
| `tests/vendored/sts_ssf_allowed_events.js` **(ours)** | **`ssfAllowedEvents` ON AN APPLICATION ENTRY** (2026-09-12): a stream the application owns is agreed only the event types its entry allows, a tightened entry stops a type reaching a stream that already exists, a lifted one does not hand back what was withheld at agreement, SSF's verification event is always allowed, and both write refusals. Every delivery assertion is made against an UNRESTRICTED CONTROL stream asking for the same types, which is what makes an absence mean the limit rather than a broken pipe. Events are emitted by hand through `/admin-api/risc/emit`. **Six mutants, two surviving the first version**: narrowing at agreement is invisible while the limit is in force — delivery and the stream's own configuration both apply the current limit — so the job had to lift it and read what was stored |
| `tests/vendored/sts_scope_policy.js` **(ours)** | **A SCOPE IS TIED TO THE CLIENT, OVER HTTP** (#110, 2026-09-22), in a throwaway realm left behind: SCIM, Shared Signals and `/admin-api` each refuse `invalid_scope` to a client that does not declare their scope, issue it once an administrator declares it through `/admin-api/applications/add`, accept the token, and refuse THAT SAME TOKEN 403 once the declaration is removed — `/admin-api` in the DEFAULT realm, where any client's token used to be accepted; RFC 7591's `scope` refused with a protected scope and returned as registered by the registration and RFC 7592's read; and every other scope issued in development and held to the list or the default set in product (it reads the mode). Verified against a development and a product container |
| `tests/vendored/sts_delegation_policy.js` **(ours)** | **WHO MAY ACT FOR WHOM, OVER HTTP** (#108, 2026-09-23), in a throwaway realm left behind: WS-Trust `ActAs` refused with `wst:RequestFailed` until `appAllowedToDelegateTo` is set through `/admin-api`, `OnBehalfOf` needing `appTrustedToImpersonate` too, a person requester and a `stsNotDelegated` subject (set through `/admin-api/users/set-not-delegated`) refused; RFC 8693 impersonation refused `invalid_request` without the flag; `act` nesting across two exchanges; `stsMayAct` (set through `/admin-api/users/set-may-act`) putting `may_act` on the token issued, an exchange by anybody else refused in every mode and by the named party issued; a wider scope `invalid_scope`; and `GET /admin-api/delegation/policy` paged. Product's refusals, development's "would have been refused" (it reads the mode). Verified against a development and a product container |
| `tests/vendored/sts_ssf_conformance.js` **(ours)** | **SSF 1.0 FINAL OVER THE WIRE** (#144, 2026-09-22), two receivers in a throwaway realm. All ten endpoints that take a `stream_id` answer 404 for the other receiver's stream, word for word as for one that does not exist, and leave it unchanged; a list is the caller's own; this service's own receiver stream cannot be read. `aud` is the client_id by default, an `ssfReceiverId` when named, refused when it names the other receiver, and unchangeable by PATCH. `iss_sub` added and `issuer_subject_id` refused; the final complex subject with `application`; `ip-addresses`. The section 7.2 inserted-path discovery form and `spec_version` `1_0`. Verification is 204 and the SET is typed and carries a `txn`. A paused poll stream hands out only stream-updated and holds a RISC event until enabled. `/ssf/receive` refuses a foreign `iss`, a foreign `aud` and an untyped token |
| `tests/vendored/sts_token_revocation.js` **(ours)** | **RFC 7009 OVER HTTP** (#102, 2026-09-22), in a throwaway realm left behind, with tokens from the authorization code flow: discovery's `revocation_endpoint_auth_methods_supported` equal to introspection's with `none`; no credential 401 in product and revoking in development; a wrong secret 401 with the challenge in both; another client's token `invalid_grant` and still active; an ID Token `unsupported_token_type`; no token `invalid_request`; an unknown hint ignored and the access token revoked alone; a refreshed grant's refresh token revoked taking both access tokens and both refresh tokens, and refused at the refresh grant; a public client revoking its own token with its client_id (checked at UserInfo) and, in product, refused another's. Reads the mode |
| `tests/vendored/sts_oidc_core.js` **(ours)** | **OPENID CONNECT CORE OVER THE WIRE** (#118, 2026-09-22), in a throwaway realm with registration opened: at_hash and c_hash computed here for ID Tokens signed RS256, RS384, PS512, ES512, EdDSA and ML-DSA-44; a hybrid error in the fragment and a code error in the query; POST at the authorization endpoint; openid, prompt=none-alone and the implicit nonce; id_token_hint (own, another person's under prompt=none, forged) and select_account; section 5.4's claims at UserInfo (address and phone) and in the ID Token only for response_type=id_token; UserInfo's form-body token; a code refused to another client and without its redirect_uri, exact redirect matching; token_endpoint_auth_signing_alg; pairwise subjects and both sector refusals; offline_access granted only with a recorded consent, an online refresh token refused after sign-out and an offline one not; an essential acr as a refusal. Reads RFC 9700 mode and takes the hybrid type without a token where it is on, so it runs in product mode too; 34 checks either way |
| `tests/vendored/sts_discovery_realms.js` **(ours)** | **DISCOVERY ON THE REALM MODEL AND WEBFINGER** (#119, 2026-09-22), in a throwaway realm with a named server in it: RFC 8414's inserted form for the realm and for the server answered inside the realm (issuer and JWKS), the appended form agreeing, four paths that name nothing answered 404 with no server created, and WebFinger — acct: and a bare e-mail at the realm's domain, acct: at the default realm's domain, an https URL by its /realm/<id> path, rel filtering, the JRD and `Access-Control-Allow-Origin: *`, 400 for a missing or unreadable resource and 404 for an unknown domain. 17 checks |
| `tests/vendored/sts_realm_overlapping_domains.js` **(ours)** | **THREE REALMS WHOSE DOMAINS OVERLAP** (#85, 2026-09-26): dev.iyasec.io, test.iyasec.io and prod.iyasec.io (ids `dev-iyasec-io` and so on, since an id holds no dot), sharing every `dc=` RDN but the first. An application and a person in each, their DNs ending in their own realm's base DN; each person signed in by the authorization code flow at their own realm — the ID Token's `iss` that realm, its `sub` the subject the realm's directory holds, its key in that realm's JWKS and in neither other's, the access token good at its own UserInfo and 401 at the other two; every realm and the default realm asked for every other realm's person by NAME, exact DN and SUBJECT, and for its application by identifier and by list search, knowing none of them (with each realm finding its own by that DN and subject as the control); and one username in all three realms as three entries whose DNs differ only in the realm's RDNs, three subjects, and — in product mode — one realm's password signing nobody in at another. The domains are fixed and unique, so a realm already holding one (a kept stack, testidp) is REUSED; everything inside carries the run stamp. 10 checks in development, 11 in product |
| `tests/vendored/sts_two_realm_domains.js` **(ours)** | **TWO REALMS WITH TWO UNRELATED DOMAINS, AND WHERE EVERY OBJECT LANDS** (#87, 2026-09-26): `alpha-<stamp>.com` and `beta-<stamp>.corp.net` — no shared `dc=` RDN and different depths, so a base cut to a fixed number of labels is wrong for one of them. Each directory's base is its domain's RFC 2247 mapping with `ou=users`, `ou=applications` and `ou=groups` beneath it; an application at exactly `cn=<identifier>,ou=applications,<base>`, a person at `uid=<name>,ou=users,<base>` (the realm's users container, an `entryUUID`), a group at `cn=<name>,ou=groups,<base>` whose `member` is the person's exact DN; the authorization code flow at each realm with `sub` = `urn:uuid:<the entry's entryUUID>`, UserInfo agreeing and the other realm answering 401; the WHOLE tree of each realm, every page, under its own base and none under the other's, every DN-valued attribute value inside the realm, and the run's own entries exactly the three expected DNs (selected by RDN value: the stamp is in the domain too, so `q=<stamp>` matches every entry); neither realm knowing the other's person by name, DN or subject, its application or its group. Per-run domains, so nothing is reused. 11 checks, in development and in product realms |
| `tests/vendored/sts_fapi_baseline.js` **(ours)** | **FAPI 1.0 BASELINE OVER THE WIRE** (#138, 2026-09-22), in a throwaway realm carrying `oauth2.fapi=1-baseline`: `GET /oauth2/fapi` and RFC 9700 mode implied; discovery with S256 alone and no secret method; registration refusing a secret method, an http redirect URI and a 1024-bit key; the authorization request without PKCE, with plain PKCE, openid without nonce, no openid and no state, and no redirect_uri; the consent screen shown despite a global consent; a `private_key_jwt` client's code and client_credentials tokens at 600 s or less with scope, the code spent once, a `client_secret_basic` client and a two-client request refused `invalid_client`; a named server opting out with `fapi=off`; and the portal signing a person in under FAPI with its own consent and a key the realm's CA issued. 23 checks |
| `tests/vendored/sts_fapi_advanced.js` **(ours)** | **FAPI 1.0 ADVANCED AND JARM OVER THE WIRE** (#139, #143, 2026-09-22), in a throwaway realm on `1-advanced`: the report and PS256 access tokens; discovery narrowed (types, PS256/ES256, no RSA1_5, JARM, a signed request object, mtls_endpoint_aliases); registration refusing client_secret_jwt, a public client, a token-bearing type and an RS256 ID Token; request objects refused for no nbf, a foreign aud and too long a life, and a push without PKCE; a pushed signed request answered with a JARM response verified against the JWKS; an unbound token refused and a DPoP-bound one issued PS256; the hybrid flow's c_hash and s_hash; `oauth2.fapiRequireMtls` refusing DPoP alone; the portal signing in under Advanced with mTLS required (PAR, JARM and the loopback client certificate); and JARM outside FAPI on a named server, query.jwt answered and refused with an id_token in clear. 23 checks |
| `tests/vendored/sts_fapi2.js` **(ours)** | **THE FAPI 2.0 SECURITY PROFILE OVER THE WIRE** (#140, 2026-09-22), in a throwaway realm on `2-security`: the report; discovery (code alone, PAR required, PS256/ES256/EdDSA, no public or secret method); registration refusing a public client, client_secret_jwt, code id_token and RS256; an unpushed request, an unauthenticated push, a push without PKCE or redirect_uri, an array aud and an assertion two minutes ahead refused; the pushed flow with the global consent counting, an unbound token refused and a DPoP-bound PS256 one issued; the refresh token redeemed twice (no rotation); the portal signing in under 2.0; and the BCP 195 handshakes — TLS 1.3 preferred, a TLS 1.2 GCM suite accepted, a CBC suite refused. 22 checks |
| `tests/vendored/sts_fapi2_message_signing.js` **(ours)** | **FAPI 2.0 MESSAGE SIGNING OVER THE WIRE** (#141, 2026-09-22), in a throwaway realm on `2-message-signing`: the report's rows; discovery with JARM's modes only and a signed request object and PAR required; a plain push, a signed push asking for no JARM mode, and one with no nbf refused; a signed push answered with a PS256 JARM response verified here and redeemed for a DPoP-bound token; an RFC 9701 introspection response signed PS256 and verified; the portal signing in under the profile. 10 checks |
| `tests/vendored/sts_fapi_conformance.js` **(ours)** | **THE OPENID FOUNDATION'S CONFORMANCE SUITE** (#176, 2026-09-24) — the independent check the four rows above are not. FAPI 2.0 Security Profile, FAPI 2.0 Message Signing, FAPI 1.0 Advanced and FAPI-CIBA, one plan each in a throwaway realm under the profile it tests, every module run through the suite's API; a FAILED or timed-out module fails the job unless `EXPECTED` names it with its reason (empty). `conformance: true`: SKIPPED with the reason where the launcher brought no suite up. See *The OpenID conformance suite*, below |
| `tests/vendored/sts_scim_conformance.js` **(ours)**, with `tests/scim_conformance_fixes.js` in process | **TWO SCIM 2.0 CONFORMANCE HARNESSES AGAINST `/scim/v2`** (#206, 2026-09-26) — python-scim's **scim2-tester** (discovery, then create / read / list / `.search` / `attributes` / replace / PATCH add-remove-replace of every published attribute / delete per resource type, and a random URL) and **scim2/test-suite** (one result per RFC 7643 / 7644 requirement: filters, sort, pagination, Bulk, If-Match and the rest scim2-tester has no check for), both in a throwaway realm with a `scim:read scim:write` client_credentials token and `scim.inventOnCreate` off. Any scim2-tester ERROR, CRITICAL or DEVIATION and any test-suite FAIL or WARN fails the job unless `EXCEPTIONS` names it with its reason (each also on #206); an exception that did not occur is reported. See *The SCIM conformance harnesses*, below |
| `tests/vendored/sts_claims_aggregation.js` **(ours)**, with `tests/claims_aggregation.js` in process | **OPENID CONNECT CLAIMS AGGREGATION** (#147, 2026-09-24), with a second realm of this service as the Claims Provider (a configured `credit_score` in its signed UserInfo): the provider registered by discovery, linking on `/portal/claim-sources` across both realms (the job's cookie jar keeps each cookie's Path, since the realms share a host and their cookie names), aggregated claims in the ID Token and UserInfo verified against the provider realm's JWKS, distributed claims, revocation. A local stack cannot dial itself over TLS, so the job publishes the service's Root in the shared test-CA directory and names it as the OP realm's `federation.outboundCaFile` (development without that directory skips verification in the OP realm; product fails and says why). The in-process file covers what HTTP cannot reach: the consuming side refusing an unregistered issuer or endpoint without dialling it, a JWT about another subject or by another key, a flow finished by another person, sealing, refresh |
| `tests/vendored/sts_xml_schema_validation.js` **(ours)** | **EVERY SAML 2.0, SAML 1.1, WS-TRUST AND WS-FEDERATION DOCUMENT THIS SERVICE EMITS, AGAINST THE PUBLISHED OASIS AND W3C XML SCHEMAS** (#188, 2026-09-24), in a development realm and a product realm it creates and a third realm federating to the first, all left standing: metadata (SAML 2.0 unscoped and per service provider, SAML 1.1, WS-Federation, every federation relationship's); the SAML 2.0 Response on HTTP-POST, HTTP-Redirect, POST-SimpleSign and HTTP-Artifact, with an EncryptedAssertion, the ArtifactResponse, two error Responses, logout in both directions with an EncryptedID, the mock service provider's AuthnRequests; the SAML 1.1 Browser/POST Response and the responder's six answers; WS-Trust 2004/04, 2005/02 and 1.3 over SOAP 1.1 and 1.2 (Issue, Renew, Validate, Cancel; SAML 2.0 and JWT), encrypted, ActAs, OnBehalfOf and the faults; the WS-Federation sign-in response in all four token/wrapper pairs; the federation module's outbound AuthnRequest and LogoutRequest and the partner's answers. Valid means `xmllint --nonet` passes it with no error or warning AND every namespace it uses is loaded AND every element is declared in its namespace's schema (lax wildcards skip the rest silently). Four self-checks prove the validator refuses. See *The published XML Schemas*, below |
| `tests/vendored/sts_saml_interop_shibboleth.js` **(ours)** | **THE SHIBBOLETH SP 3 AGAINST BOTH SAML IDENTITY PROVIDERS** (#189): SAML 2.0 SP-initiated (Redirect and POST AuthnRequests, the Response on POST, POST-SimpleSign and Artifact), identity-provider-initiated (POST and Artifact), SAML 1.1 Browser/POST and Browser/Artifact, the SAML 2.0 and 1.1 attribute queries, Single Logout both ways — in a development and a product realm, with Shibboleth's own log as the error source; and (#248) the back channel authenticated from metadata alone, with a control that strips the listener key and is refused. `samlPeer: 'shibboleth'`. See *The SAML peers*, below |
| `tests/vendored/sts_saml_interop_pysaml2.js` **(ours)** | **PYSAML2 AS A SCRIPTED SP, NEGATIVE CASES INCLUDED** (#190): every request/response binding pair, an unsigned request (refused while its metadata says it signs, then decided by `saml2.requireSignedAuthnRequests` off, on and auto), ForceAuthn and IsPassive, NameIDPolicy in four formats, identity-provider-initiated SSO, Single Logout both ways, and the refusals — a bad signature, a wrong Destination, a stale IssueInstant, a replayed ID. `samlPeer: 'pysaml2'` |
| `tests/vendored/sts_saml_interop_simplesamlphp.js` **(ours)** | **SIMPLESAMLPHP AS AN SP** (#191): its metadata validator on the identity provider's metadata, SP-initiated SSO with the AuthnRequest on HTTP-Redirect and on HTTP-POST (encrypted), ForceAuthn, IsPassive, NameIDPolicy, identity-provider-initiated SSO and Single Logout both ways, with `debug.validatexml` on so its log names a document that does not validate. `samlPeer: 'simplesamlphp'` |
| `tests/vendored/sts_saml_interop_keycloak.js` **(ours)** | **KEYCLOAK AS A SAML 2.0 BROKERING SP** (#192), configured entirely through its admin API: brokered sign-ins (Redirect and POST AuthnRequests, assertions signed and encrypted, attribute mappers), NameIDPolicy in four formats, and Single Logout back-channel, front-channel and identity-provider-initiated. `samlPeer: 'keycloak'` |
| `tests/vendored/sts_frontchannel_logout.js` **(ours)** | **OPENID CONNECT FRONT-CHANNEL LOGOUT OVER THE WIRE** (#122, 2026-09-22), in a throwaway realm with registration opened: discovery's `frontchannel_logout_session_supported` (and not the registration member it used to publish) and `sid` in claims_supported; section 2's origin rule refusing another host and another port at registration and at `/admin-api`; a person signed in through a NAMED authorization server and signed out at the realm's own `/oauth2/logout`, whose iframe carries the named server's `iss` and the session's `sid`, with `frame-src` naming the relying party and `frame-ancestors` kept; section 4's return as a `<meta>` refresh after `oauth2.frontchannelLogoutWaitS`, and no refresh at 0; a stored URI whose redirect URI was removed skipped and reported rather than framed |
| `tests/vendored/sts_caep_credential_changes.js` **(ours)** | **CAEP FROM EVERY DOOR OVER THE WIRE** (#145, 2026-09-22), in a throwaway realm with a poll stream covering everybody: `credential-change` (`password`, `create`, `admin`) for a person created with a password; `session-established` whose `fp_ua` is the base64url SHA-256 of the sign-in's `User-Agent`; `token-claims-change` carrying `family_name` after a SCIM `PATCH`, and the groups claim as the whole list after a group join, about the person; none for a person holding nothing live; `credential-change` `x509` with `x509_issuer` and `x509_serial` for a signing key pair issued on `/admin-api/pki` |
| `tests/vendored/sts_risc_acts.js` **(ours)** | **RISC ON ITS OWN OVER THE WIRE** (#146, 2026-09-22), in a throwaway realm with a poll stream covering everybody: an administrator's reset link marked compromised sends `account-credential-change-required`, `recovery-activated` and `credential-compromise` (`password`), each `iss_sub`; a disable with a RISC `reason` carries it, one without carries none, and an invented reason is refused; an address a SCIM-deleted account held, given to a new account, sends `identifier-recycled` about the address; the account holder's opt-out on `/portal/signals` — initiated, a refused out-of-diagram move (409), cancelled, initiated again, made effective by running `risc.opt-out-effective` with the delay at 0, and opted back in |
| `tests/vendored/sts_hosted_surface_renewal.js` **(ours)** | **THE CONSOLE AND THE PORTAL STAY SIGNED IN PAST THEIR TOKENS** (2026-09-12), in a throwaway realm with the clients' token lifetimes shortened and `oidcRp.renewBeforeExpiryS` at the token lifetime, which renews on every request. Five sections: the portal page answers 200 on the SAME session id with the SAME CSRF token, `session.renew` rows are written and no second `session.start`; revoking the sign-on session still ends the portal session; a revoked refresh token ends the session (`STS-AUTHN-0137`) and the code flow brings the browser back to the page it was on without a sign-in; the console renews too, its row in the DEFAULT realm's audit log; and with `authn.sessionLifetimeS` at its sixty-second floor the portal session outlives its sign-on session. Raised watchdog, because section 5 waits that minute out. Mutants caught: the portal middleware unregistered, the console middleware unregistered, the authorization server dropping `auth_time` on a refresh, the nonce demanded of a renewed ID Token, a refused renewal not ending the session, and the parent-ran-out exception removed |
| `tests/vendored/sts_acme_enrollment.js` **(ours)** | **ACME (RFC 8555) OVER HTTPS WITH AN INDEPENDENT CLIENT** (2026-09-13), `vendored/acme_client.js`, in a throwaway realm: EAB-bound accounts for a person, an application and — through an administrator's `create-eab` — another person; all nine profiles by identifier type; the chain, the SAN URN, OCSP and revocation; and the negatives — bad and reused nonces, a wrong `url`, `jwk` with `kid`, an EAB reused or with a wrong MAC or from another realm, CSR names that are not the order's, revocation by an unrelated account, and a key change to a key already bound |
| `tests/vendored/sts_est_enrollment.js` **(ours)** | **EST (RFC 7030) WITH AN INDEPENDENT CLIENT**, `vendored/est_client.js`: every labelled profile, Basic as a person and as an application, re-enrollment with the client certificate a previous enrollment issued (the old one superseded on the CRL), server key generation for an EC key and an ML-KEM template, an administrator naming another person, and the negatives — an unknown user, a wrong password and a wrong secret in a product-mode realm, a certificate from another realm or not enrolled, illegal base64, `fullcmc` and an unknown label |
| `tests/vendored/sts_scep_enrollment.js` **(ours)** | **SCEP (RFC 8894) WITH AN INDEPENDENT CLIENT**, `vendored/scep_client.js` on node-forge: GetCACaps, GetCACert, PKIOperation over POST and GET for all nine profiles, RenewalReq, CertPoll and the idempotent retry, and the negatives — a wrong, reused, expired or foreign-realm challenge, a URL profile disagreeing with the challenge, a tampered signature, the wrong recipient, an EC requester key, a foreign-realm renewal. Raised watchdog: it waits out a sixty-second challenge |
| `tests/vendored/sts_acme_certbot.js` **(ours)** | **EFF'S CERTBOT AGAINST THE ACME SERVER** (#207, 2026-09-26), certbot 5.8.0 from the tests image, in a throwaway realm: EAB registration (refused without one and with a wrong MAC), `certonly` with no profile, `--required-profile tls-server`, `--preferred-profile tls-server-client`, `root-ca` and an unregistered host refused, `renew --force-renewal` and a plain `renew` consulting `renewalInfo`, `revoke --reason keycompromise` onto the CRL, `update_account`, `unregister`, the spent EAB key refused — and no WARNING or ERROR in certbot's DEBUG log for any success. Floor of fifteen checks |
| `tests/vendored/sts_acme_lego.js` **(ours)** | **GO-ACME'S LEGO AGAINST THE ACME SERVER** (#208), lego v5.5.2, in a throwaway realm: EAB registration, `run --profile tls-server` with the authorization already valid, the default profile, `--not-after`, `root-ca` and an unregistered host refused, `renewalInfo` then `--renew-force`, `accounts keyrollover` and an order under the new key, `certificates revoke --reason 4` onto the CRL; no `level=WARN`/`ERROR` but lego's back-up-your-keys notice |
| `tests/vendored/sts_est_libest.js` **(ours)** | **CISCO'S LIBEST ESTCLIENT AGAINST THE EST SERVER** (#209), at a464ba8, in the DEFAULT realm with people of its own (an EST client can name no other realm): bootstrap from the Root then `/cacerts` as the anchors, csrattrs, enroll by Basic, by certificate and with an openssl CSR for a host, `-z`, re-enroll and the superseded certificate refused, serverkeygen with the key matching, and eight refusals (password in product only). Three client lines accepted by name, argued in the file |
| `tests/vendored/sts_scep_sscep.js` **(ours)** | **SSCEP AGAINST THE SCEP SERVER** (#210), at cb3e539, over the plain-HTTP listener, in two throwaway realms: GetCACaps, GetCACert, the `/admin-api` hint run literally, a portal-made challenge, `-R`, GetCert, GetCRL, the historical renewal onto the CRL, and the refusals (reused, unknown, another realm's RA, 3DES, SHA-1) |
| `tests/vendored/sts_scep_micromdm.js` **(ours)** | **MICROMDM'S SCEPCLIENT AGAINST THE SCEP SERVER** (#211), v2.3.0: its transport over HTTPS and plain HTTP, three recipient selections, and the `badAlg` its fixed SHA-1/DES draws — it cannot be issued a certificate here, by design (`scep/CLAUDE.md`) — which spends no challenge |
| `tests/vendored/sts_portal_certificates.js` **(ours)** | **`/portal/certificates` WITH TWO SIGNED-IN BROWSERS** (2026-09-13): an ACME binding key and a SCEP challenge made for the signed-in person whatever the body names and shown once; a refused profile; no CSRF token; the other person's key not deletable and their EST certificate not revocable — each answered as not found and still on the other person's own page; revoking one's own; ACME turned off hiding the card and refusing the door. Both ownership checks mutation-tested through a hook preloaded into the throwaway service |
| `tests/vendored/sts_oauth21.js` **(ours)** | **OAUTH 2.1 MODE AT THE REAL ENDPOINTS** (2026-09-13), in two throwaway realms — one in OAuth 2.1 mode, one in RFC 9700 mode beside it. **The section to read first is a POSITIVE**: a public client with PKCE and NO `redirect_uri` at the token endpoint gets a token in the 2.1 realm and the SAME request is refused `invalid_grant` in the RFC 9700 realm, which is what makes the acceptance the mode rather than a service that stopped checking. Then the authorization request's `redirect_uri` defaulted to the one registered (and refused with two), an unregistered client refused ON THE SERVER with nothing redirected, PKCE refused for a confidential client (as a PAGE, because RFC 9700's authenticate-before-redirect applies before sign-in) and the nonce exemption issuing, refusing redemption without client authentication and without `redirect_uri`, and redeeming with both; the token endpoint refusing a client that declares nothing (asserted on a REFRESH, because client_credentials is refused by section 4.2 first and cannot show which rule answered — a mutant removing the declaration check survived until then), a public client's client_credentials and its presented secret, two methods, a repeated parameter, SAML client authentication (by the metadata that stops advertising it), and a client assertion addressed to the token endpoint while one to the issuer alone is accepted; three wrong secrets then a 429 that the right secret does not open while another client is unaffected; and registration's two mirrors. Six service mutants through a require hook preloaded into the throwaway service, all caught |
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

| Test | What it covers |
|---|---|
| `tests/vendored/sts_jwt_bearer_grant.js` **(ours)** | **RFC 7521 AND RFC 7523 AT A REAL TOKEN ENDPOINT, AND THE CERTIFICATE AUTHORITY THAT MAKES THEM USABLE** (2026-09-10). Here for the THIRD reason and it is a plain instance of it: **every assertion spans an AUTHORING door and a PROTOCOL door.** A signing key pair does not exist until `/admin-api/pki` issues one and an assertion issuer is not trusted until `oauthAssertionIssuer` is written through `/admin-api/applications`, so there is no question worth asking `/oauth2/token` until both have been used — the shape `sts_xacml_endpoints.js` has with a repository that starts empty. Thirteen sections in a throwaway realm, because a CA is per realm and a realm of its own gives it a hierarchy whose entire contents it built, which is what makes *this leaf chains here and not there* an exact claim. **Mostly negatives, for `sts_dpop.js`'s reason.** The one to read first is section 3: **an assertion from an undeclared issuer is refused BEFORE the issuer is declared, and the same assertion is accepted afterwards** — one attribute on a directory entry is the whole difference, which is what makes it a gate rather than a service refusing for some other reason. Then a replay, a wrong key, a foreign audience, an expiry, a missing `jti`, `exp` or `sub`, `alg: "none"` cited by claim number, a lifetime over the ceiling, an encrypted assertion that is not signed inside, and an `x5c` chain accepted here and refused at another realm's token endpoint. **It writes its own JWS signer and its own JWE**, thirty lines of node crypto, for `sts_dpop.js`'s reason word for word: if both sides of the exchange came from one implementation, a shared misunderstanding would make the test pass and interoperate with nobody. It carries a FLOOR on its check count. **It found a real defect on its first run**: `unwrapAssertion()` decided a nested JWT's plaintext was a JWS by COUNTING DOTS, and a claims object carrying an `iss` of `https://issuer.example.test/…` splits into exactly three parts — so an unsigned document was read as signed and the refusal named a base64 problem instead of the rule it broke. It parses the protected header now. Mutation-tested against four, all caught |
| `tests/vendored/sts_saml2_bearer_grant.js` **(ours)** | **RFC 7521 AND RFC 7522 AT A REAL TOKEN ENDPOINT, AND THE TWO KEY PAIRS THAT MAY NOT SIGN FOR EACH OTHER** (2026-09-11). Here for the THIRD reason, which is the job above's word for word: the key pair comes from `/admin-api/pki` — with `purpose: "saml"`, a control on this repository's own console — and the trust decision from `/admin-api/applications`. Twelve sections in a throwaway realm. **The one it exists for is section 6**: both key pairs are issued to ONE application and then each is presented at the OTHER profile's grant. A SAML assertion signed with the RFC 7523 key is refused, a JWT signed with the RFC 7522 key is refused at the JWT grant, **and the JWT signed with its own key is accepted at that same endpoint seconds later** — which is what turns two refusals into a rule rather than a service that has stopped working. Section 3 has the same shape one level up: declaring the issuer for RFC 7523 does NOT declare it for RFC 7522, asserted before the SAML declaration is written. Then the fourteen refusals — a replay on the assertion `ID`, a wrong key, a **broken reference digest** (the half of an XML Signature a verifier checking only the SignatureValue would wave through, and how signature wrapping gets in), a foreign audience, a foreign `Recipient`, an expiry, no expiry at all, no `<Subject>`, an UNSIGNED assertion cited by item number, a lifetime over the ceiling, and an unknown `<Condition>`. Section 8 drives §2.2 client authentication with RFC 9700 mode ON **in that realm only** — without it a bad assertion is not refused and the section would assert nothing. Section 12: taking one profile's key pair off leaves the other's working, at the endpoint and on the entry. **It signs with `saml_xmldsig.js`**, this suite's own XML Signature, canonical by construction — for `sts_dpop.js`'s reason with more force than usual, since exclusive canonicalization is where every XML Signature implementation ever written has had a bug. It carries a FLOOR on its check count |
| `tests/vendored/sts_database_metrics.js` **(ours)** | **THE DATABASE REPORT AGAINST A REAL POSTGRESQL** (2026-09-11), and the only job in either suite whose subject is a surface whose SHAPE this repository does not decide. `tests/database_metrics.js` holds what needs no server; this holds the four things that do. **THAT THE STATEMENTS ARE VALID SQL FOR THIS SERVER AT ALL** — they are PostgreSQL's grammar and catalog, and an in-process test asserting they parse would be asserting its own opinion of both. **THAT THE COLUMNS ARRIVE**, which it checks by COUNT and never by name: naming one would be this test having exactly the opinion the page exists not to have. **THAT A PROBE THE LEAST-PRIVILEGE ROLE CANNOT READ COSTS A ROW AND NOT THE PAGE**, carrying PostgreSQL's SQLSTATE, because 42P01 (an older server) and 42501 (a missing grant) are different things to do about and a message alone would make a client parse English. **AND THAT NO CONNECTION STRING OR PASSWORD IS IN THE REPLY.** It also pins the two normalisations a reader would never think to check: `reltuples` is `-1` for a never-analysed table — every table in a database this service has just built — so a page that printed it would report minus one row; and a PRIMARY KEY with no scans is never called an unused index, which would make the one actionable number on the page noise. **IT SKIPS RATHER THAN FAILS WITHOUT A DATABASE**, which is this suite's standing refusal and is argued rather than assumed: `persistence.mode` is RESTART-ONLY, so unlike a job that needs a realm or a setting there is no door this one could knock on — and it still asserts the no-database sentence on the way past, which is the half that IS true of a memory-mode service |
| `tests/vendored/sts_pki_revocation.js` **(ours)** | **THE CRL AND OCSP ENDPOINTS AND THE REVOCATION PANE, OVER HTTP** (2026-09-11). `tests/pki_revocation.js` holds the register and the documents and sends no request; this is the wiring, which is where a feature like this actually breaks. **THE ENDPOINTS ARE UNGATED AND HAVE TO BE** — a relying party fetches a CRL before it has decided to trust anything, so a list behind this console's gate is a revocation nobody acts on, and that is one line of middleware away from being true. Asserted with **`Authorization: none`**, without which the launchers' preloaded admin token rides along and the job would be proving anonymity while sending a credential. **THE MEDIA TYPES ARE THE PROTOCOL**: `application/pkix-crl`, `application/pkix-cert`, `application/ocsp-response` — a handler sending DER as `text/html` passes every test that parses the body itself. **AND THE BYTES SURVIVE THE TRANSPORT**, which is the class of failure every in-process assertion about a document's structure still passes. It asserts the CRL is the ONE cacheable document here (it carries its own `nextUpdate`) where everything else that publishes key material is `no-store`; that a 404 is PLAIN TEXT naming the index rather than an HTML page a revocation client cannot parse; that an OCSP refusal is a **200 inside the protocol**; that revoking through `/admin-api/pki` grows the PUBLISHED list on the next fetch; that a second revocation cannot move a date forward; and that only a `certificateHold` releases. **It found the defect that made the whole POST endpoint unreachable**: `common/app.js`'s text parser takes EVERY content type, so a handler reading the request stream itself found it already drained — every POST hung, `curl` reported `000`, nothing was logged, and the service answered everything else in milliseconds. The fix is a content type in that file's raw-parser list, which is the same row Kerberos MS-KKDCP already needed and for the same two reasons |
| `tests/vendored/sts_pki_distribution_points.js` **(ours)** | **EVERY REVOCATION ADDRESS EVERY CERTIFICATE NAMES, FOLLOWED AS WRITTEN, IN EVERY TRUST REALM** (2026-09-13). The job above built `/pki/crl/<scope>/<ca>` by hand and was green while every certificate named `https://localhost:8081/…` on a stack published on 18081 — **THE RULE HERE IS THAT NOTHING IS REWRITTEN**: no URL re-based onto the address the job was handed, no port substituted, because a job that "helpfully" fixed the port is the test that kept the defect hidden. It collects every certificate the service publishes (each realm's JWKS, both SAML metadata documents, WS-Federation metadata, `/sts/cert`, `/tls/server-certificate`, the SPIFFE bundle, the main port's handshake, every authority's own certificate from its caIssuers address, and key pairs it issues to an application and a person in a realm of its own), and holds what they name to **RFC 5280** (http AND ldap CRL points, OCSP and caIssuers, NO https or ldaps — section 8), each CRL from every scheme to section 5 (issuer bytes, signature, v2, AKI = the issuer's SKI, cRLNumber, nextUpdate still ahead, and a NEW number when a second signing has a later thisUpdate), the `ldap://` fetch to **RFC 4516/4523** anonymously, and every responder to **RFC 6960, 5019 and 8954** for every certificate naming it — POST with a nonce and GET of the base64 form, CertID and nonce echoed, `good`, signature from the issuer, whole-second GeneralizedTimes, the §6.2 cache headers, `unknown` for a serial never issued, `unauthorized` for another issuer's certificate, `malformedRequest` for a 33-octet nonce, and a 400 rather than a 404 for a GET of the bare address. Then it does the same for **every authority in `/pki/revocation`**, named by a collected certificate or not. **IT NEEDS THE LAUNCHER TO HAVE TOLD THE SERVICE ITS PUBLISHED PORTS** — `PKI_DISTRIBUTION_PORT` from `STS_PKI_HOST_PORT`, `PKI_DISTRIBUTION_LDAP_PORT` from `STS_LDAP_HOST_PORT`, or `PKI_DISTRIBUTION_BASE_URL`/`PKI_DISTRIBUTION_LDAP_HOST` naming `sts` under `./run-tests.sh` — and failing there is the point. Mutation-tested against twelve; ten caught here, and the two survivors (publication with no realm ambient; the product-mode anonymous read) are `crl_directory_publication.js`'s |
| `tests/vendored/sts_pki_workbench.js` **(ours)** | **THE CERTIFICATE & KEY CONFIGURATION PANE THROUGH BOTH ITS DOORS** (2026-09-10), in a throwaway realm that is left standing. `tests/pki_authoring.js` holds the model and makes no request; what is here is the four things it cannot see. **THE ROUND TRIP IS THE FEATURE**: with no script the form IS the state, so a field the page fails to re-render falls back to its default on every press — silently, for ever — and the only way to ask is to POST what a browser would and read what comes back. Beside it, every field the service SAYS it reads is checked against the markup of the page it SERVED, which is the half that catches a control drawn only in some states. **THE DOWNLOAD IS NOT A PAGE**: media type, `Content-Disposition` and the body's first byte being a DER SEQUENCE rather than an HTML error wearing the right media type. **THE GATE**, which is middleware on a path. And **rule 7**, compared across two live doors — a CA made in the BROWSER, a leaf issued from it through `/admin-api`, and the store reporting both with no private key anywhere in the reply. **It found the defect that makes "post back what came back" true**: every action answers with the whole form, whose flags are JSON booleans, and a `false` matched none of the string cases and read as TRUE — so apply-profile then issue-certificate turned every cleared box on. Six mutants, five caught; **the sixth is RECORDED rather than papered over** — `mayWrite()` in the export handler is reachable only by a session holding Admin Read and not Admin Write, and producing one means putting a member in the DEFAULT realm's role roster, which, when this was written, closed the console's empty-roster window and took console writes away from every other job in the run. The window has been the bootstrap account's since 2026-09-13 (`admin-ui/admin_rbac.ts`); the mutant is still recorded rather than reached |
| `tests/vendored/sts_portal_backup_keys.js` **(ours)** | **TWO SECURITY KEYS, THE FIRST ONE LOST, AND THE SECOND STILL SIGNING THEM IN (2026-09-10).** The point of a backup is the day the original is gone, so that is the shape: enrol two from `/portal/keys`, take the first away, require the second still works and that the person tidies up without an operator. It exists because none of it was possible — that page said *there is no enrol button here, because a WebAuthn ceremony belongs to a sign-in and this page is not one*, which is false (a ceremony belongs to whoever is asking), and the sign-in screen's checkbox is reserved for people holding no second factor, so there was **one key per person and no door to add another**. Four claims: the portal can enrol at all, and the page relaxes `script-src` to `'self'` **while keeping `frame-ancestors`** — asserted on the `script-src` DIRECTIVE and not the whole header, because `style-src 'unsafe-inline'` is the service-wide default and reading the whole policy calls a correct service broken; **the SAME authenticator is refused a second time** and the armed page's `data-exclude` names the key they hold, since a second row for one device is a backup lost with the original; **EITHER key completes a sign-in** and a third nobody enrolled does not; and the lost one is removed self-service while the last `mfa` key may go, because it was never a way IN. **THE COOKIE JAR KEEPS COOKIES BY NAME**, and the one-line version used elsewhere here does not — a signed-in portal browser holds the sign-on cookie AND the portal's own, whichever arrived last evicts the other, and what that looks like is a GET succeeding and the POST beside it redirecting to the authorization endpoint: a server that forgot to check its session. It cost an hour. Mutation-tested against five, all caught — the duplicate check at the write, `excludeCredentials` never sent, the label dropped, the CSP not relaxed, and **the enrolment id not checked, which survived until the fixture grew a `finish` naming a different one** |
| `tests/vendored/sts_webauthn_second_factor.js` **(ours)** | **A REAL WEBAUTHN CEREMONY AGAINST THE SIGN-IN SCREEN, AND THE JOB THAT PROVES THE TWO CREDENTIAL STORES BECAME ONE (2026-09-10).** `authn/authn.ts` kept a map of one key per person while `common/credentials.ts` kept the keys on the directory entry with their ROLES — and `credentials.addKey()` had NO CALLER, so the store everything read was empty. **The assertion that finds that is the SECOND sign-in**: a key enrolled at that screen was never asked for again, because `mfaRequired` could not become true from one, so anybody who knew the password signed in without it while `/portal/keys` showed an account with a second factor on it. Every other assertion here passes against the broken version. Sections: the enrolment ceremony is drawn and ACCEPTED by the real verifier; the key reaches the store `/portal/keys`, `/admin/users` and the sign-in screen all read, carrying the role it was enrolled in and the credential id the browser sent; **the second sign-in demands it with the checkbox untouched and draws an ASSERTION rather than another enrolment** (a `create` there is the bypass — register your own authenticator and be signed in claiming two factors); a valid ceremony from an authenticator this person never enrolled is refused; the signature counter advances through `noteKeyUsed()`; the *use your key instead* link is reachable, its own gate having refused everybody; and an operator's `clear-key` removes a key that really exists and the demand stops. **It carries its own AUTHENTICATOR** — a real P-256 key, real CBOR, a real signature over the real signed bytes — rather than importing the verifier, on `sts_dpop.js`'s rule. **The origin and RP ID are computed from the service's base** and not written down, or the fixture passes on one stack and fails on the other two with a message about a rejected ceremony. Mutation-tested against five, four caught here — the page always drawing an enrolment, the counter never recorded, the role hardcoded, and `removeKey()` ignoring the removed key's role — and **the fifth survived and is recorded in `tests/webauthn_policy.js`**: checking the assertion against `usable[0]` instead of the credential the browser NAMED passes this file perfectly, because its person holds exactly one key and the two are then the same key. It found a second defect in its first run: `removeKey()`'s last-way-in guard did not look at the ROLE of the key being removed, so clearing a second factor for somebody with no password — the ordinary state in development mode — was refused with *that is the only way they can sign in*, about a credential that could not sign them in at all |
| `tests/vendored/sts_ldap_read_authorization.js` **(ours)** | **PER-IDENTITY LDAP READS OVER LDAPS (#106, 2026-09-23)**, in two throwaway realms created with `global.mode` `product` and `development`, so both modes are asserted whichever mode the stack runs in. Each gets a reader, another person, a realm-roster Admin Read holder, a group the reader is in and one they are not, and an application (`/admin-api`). Product: own entry readable, another person's DN and a missing DN both 32, a subtree search and a compare that do not find them, the group they are not in and the application 32, `ou=applications` alone; widened, mail but not telephoneNumber, a filter blind to it, a compare 50; the administrator reads everything; an application DN's bind is 49. Development: all of it answers and the application binds. **It reaches LDAPS at `STS_LDAPS_URL`, or 636 on the service's host**, verified with the runner's trust (a hand run against a bridge IP needs `STS_TLS_IPS` to include it) |
| `tests/vendored/sts_second_factor_doors.js` **(ours)** | **THE FIVE PASSWORD-ONLY DOORS AND APP PASSWORDS (#101, 2026-09-22)**, in a throwaway realm with a poll stream for `credential-change`. A person makes an app password on `/portal/app-passwords` (a real submit button, no script, shown once on a `no-store` 200); a second factor is then required of them, and at an LDAPS bind, a WS-Trust UsernameToken, SCIM, SSF and EST Basic their own RIGHT password is refused **with exactly the answer a wrong password gets** (a normalised string comparison — any difference is a password oracle) in product and accepted in development, while the app password and a no-second-factor person's password are accepted in both. In product the app password is refused at the sign-in screen and at a door outside its scope; `/admin-api` makes one (answered once) that a password reset leaves working, pages the list and revokes it; a disabled account is refused its app password; `authn.passwordAloneDoors` admits only the door it lists; each make and revoke is a `credential-change` with the right `initiating_entity`. **It reaches LDAPS at 636 or `STS_LDAPS_PORT`**, `sts_ldaps.js`'s convention — a hand run against a container publishes 636 somewhere and says where. `tests/second_factor_doors.js` is the in-process half, where the recorded codes (`STS-AUTHN-0213`, `0213`) can be read back |
| `tests/vendored/sts_kerberos_fast_otp.js` **(ours)** | **FAST AND OTP OVER TCP 88 (#173, 2026-09-22)**, in both modes, against the service's published address (`STS_KDC_HOST` / `STS_KDC_PORT` as `sts_kerberos_spnego.js` has them). A host principal made through `/admin-api` — its keytab, handed over once, read by `krb5_wire.js` — gets the armor TGT; a person enrols an authenticator on `/portal/mfa` with a code computed here. Their right password alone is `KDC_ERR_POLICY` in product and a TGT in development; a wrong one `PREAUTH_FAILED` in both; FAST advertised, the armored method list, the encrypted challenge; OTP with the PORTAL's spent step refused at the KDC, the next code accepted, the same code refused; the `otp` indicator read out of a service ticket with the host key; the SPNEGO session's `amr [pwd, otp]`. **And real MIT Kerberos where `kinit` is installed** — `kinit -k` for the armor, `kinit` with the password alone, `kinit -T` answering the OTP and PIN prompts, `kvno`, and the code again refused — skipped with a sentence where it is not (the tests image has no `krb5-user`). Its client is `krb5_wire.js`'s FAST half, written apart from the KDC's; the keytab lives in a temporary directory for the MIT section only |
| `tests/vendored/sts_kerberos_signout.js` **(ours)** | **A KERBEROS SIGN-OUT OUTLIVES THE NEXT AS EXCHANGE (#111, 2026-09-23)**, over TCP 88 in both modes: a renewable TGT buys a service ticket; `POST /admin-api/logout/global`; the TGT refused `KDC_ERR_TGT_REVOKED` (20); a new AS exchange straight after it succeeds with an authtime at or after the sign-out's whole second (the instant still reported on the sign-out view) and its TGT is accepted; the OLD TGT still refused 20 and a RENEW of it refused 20, a renewal of the new one accepted with its authtime kept; `restore-kerberos` refused 400 in product with the old TGT still refused, and in development clearing the instant so the old TGT is accepted again |
| `tests/vendored/sts_second_factor_pages.js` **(ours)** | **THE TWO SECOND-FACTOR MECHANISM PAGES AND THE ROSTER THAT ABSORBED `/admin/mfa` (2026-09-10).** **Since 2026-09-14 each page may also carry the second-factor requirement's group** (`authn.mfaRequired` until #64 moved it to the authentication policy; `authn.passwordAloneDoors` and the app-password rows are what is left), the one group `SETTING_HOMES` draws on both — and the job asserts it is on both, where it had asserted every row was the mechanism's own and failed in all three modes. That page lasted hours: it edited the eight `totp.*` settings AND drew a roster of who held a second factor, and one page cannot be filed by both halves. This job is what the split owes. **THE STATUS ALONE SAYS NOTHING ABOUT THE REMOVAL and the first version of it asserted otherwise** — the root CLAUDE.md's `Cannot GET /path` rule is about paths the ROUTER reaches, and the console's gate is middleware on the whole `/admin` prefix, so every unrouted path under it answers 303 to the code flow. The 303 is therefore asserted to be THE GATE, by asking a path nobody ever registered and requiring the same answer, and the claim that the page is gone is made against the console's own PAGE LIST — which is what `admin_api.js`'s parity walks and therefore the list that has to be right. Then: both new pages carry their settings and an operation each; **the mechanism report FOLLOWS the settings rather than being written down** (the report is CHANGED through `/config/set-many` and read back, because reading it on its own says nothing — a hand-written table is well-formed too); a person who has never authenticated is on `/admin/users` at all, which the old population would not have shown and which is the whole reason the roster moved there; `factor=none` finds them and `factor=any` does not, since a filter matching everybody would pass the first check; the drill-down ANSWERS for somebody the registry has never seen, which it did not until the list started showing them; and both spellings of the two Clear actions reach one switch, `/admin-api/mfa/*` and `/admin-api/users/*`, because the console control moved and a caller's script did not. **A `finally` that throws replaces the failure that got you there** — the first run reported a reset complaining about an override that was never made, hiding a malformed request shape entirely — so every restore goes through `resetQuietly()`. Mutation-tested against four, all caught: the union removed from `peopleRows()`, the `factor` filter ignored, `clear-totp` dropped from the users switch, and the report's offered list written down |
| `tests/vendored/sts_xacml_endpoints.js` **(ours)** | **THE EIGHT `/xacml` ENDPOINTS, IN A THROWAWAY TRUST REALM.** Until it existed every route in `xacml/xacml.ts` was uncovered — the in-process XACML suite holds the ENGINE to 455 OASIS cases and makes not one HTTP request. What is here is the surface in front of it: a template built on `/admin-api` deciding at `POST /xacml/pdp` against an attribute the request never carried; four malformed requests refused **400 and never Indeterminate**, which is the distinction a PEP most needs, since an Indeterminate would be enforced by its bias; the embedded PEP's two biases disagreeing on the one answer they are supposed to disagree on (NotApplicable, reachable only in a realm whose repository is empty); an obligation this PEP cannot discharge turning a Permit into a refusal and the SAME Permit standing once it is renamed to the one it knows; a remote PEP's pull, its ETag, its 304, and a disabled policy reaching nobody; **a registration named from the client CERTIFICATE and never from the body**, on the registration and on the heartbeat alike, which is the one defect in this family that would be a security bug; a PEP an administrator disabled staying disabled when it reconnects; a policy save that does not wait on an unreachable PEP; and both off-switches answering 501 in the realm while the default realm goes on answering. **AND SINCE 2026-09-06 TWO MORE SECTIONS.** *The gate* is an INVERTED MATRIX and that is the whole value of it: four callers — nobody, a verified certificate in no group, `XACML_USER`, `REMOTE_PEPS` — against all eight endpoints, so the two DIAGONAL cells are asserted. A single "an anonymous caller is refused" check would pass against a service that had collapsed the two roles into one, which is the change somebody tidying up will make; the diagonals are the only assertions anywhere that say admitting a caller to the demonstration surface has not silently admitted it to the endpoints publishing the documents this service enforces its own access with. It ends by turning `xacml.enforceAccess` off and back on, because a gate with no documented way out is one somebody works around with a worse one — and because leaving it off would silently un-gate every section below. *The PIP over HTTP* asserts the SHAPE as hard as the content: the `<Attributes>` come back in the XACML CORE namespace, an unresolved designator is an **absent** `<Attribute>` rather than an empty one (the schema forbids an empty one, and absence is what a request that never carried it looks like to every engine), `IncludeInResult="false"` is explicit, both spellings of a directory attribute resolve, and the five empty-bag reasons arrive in a namespace of this service's own so that a PEP reading only OASIS's never meets them. Mutation-tested against six mutants |
| `tests/vendored/sts_xacml_remote_pep.js` **(ours, `docker: true`)** | **THE REMOTE PEP AS A SECOND CONTAINER ON THE SERVICE'S OWN DOCKER NETWORK, IN BOTH LAUNCHERS' STACKS.** It asserts the seam the other two PEP tests each hold one side of: `tests/xacml_pep.js` compares the container's MODULES with this service's in a child process and never makes a request; `sts_xacml_endpoints.js` drives the three PEP endpoints with the TEST impersonating a PEP, so it asserts the pull's bytes and nothing evaluates them. **`xacml-pep/sync.js` — the registrar and the poller, the whole client half — was loaded by no test at all.** The launcher brings the container up (`--profile xacml` locally, a service in `docker-compose-run-tests.yml` in CI) pointed at a realm that does not exist yet; the job creates it and asserts nine things. **It registers on a LATER attempt**, because its PDP appeared minutes after it did — the retry `sync.js` grew for this. It pulls what was deployed, dialling the compose name on the internal port rather than a published one, and is marked UNAUTHENTICATED because the shipped container carries no client certificate (the authenticated path is `sts_xacml_endpoints.js`'s, with a real handshake). It decides four cases in its own memory, naming the PEP and the token that decided. **AND SINCE 2026-09-06 IT SHOWS THE PIP REACHING THE MOCK'S EMBEDDED LDAP, which is the exact inversion of what that section used to hold.** It asked about `carol` **asserting nothing** — no employeeType, no attribute of any kind, only a name and an action — and the container PERMITS her, because `xacml-pep/pip.js` resolved the policy's `employeeType` designator against her entry under `ou=users` through `POST /xacml/pip`. Four checks rule out the four ways of being right by accident: the Permit, a name the directory has never heard of refused the same way, the answer's own `pip` block saying the query was made and how many designators came back with values, and **the PDP reaching the same decision** — which is the property the whole phase exists for and the one this section used to record the ABSENCE of. The old behaviour is still asserted beside it and is now a CONFIGURATION: a request-asserted attribute still decides where the directory holds nothing, because a PIP removes the disagreements that come from MISSING information and not the ones that come from a caller asserting something about itself. **It converges BY POLLING** on a policy created and promoted through `/admin-api/xacml`, with the nudge deliberately undeliverable and section 1 asserting the PDP said so. It watches a disabled policy STOP BEING ENFORCED out there, fall back to the one enabled document, empty to `loaded: false` where the bias is what decides, then recover. **Then it takes the nudge's other half**: `xacml.pepNotifyAllowHttp` on (and, in a product realm, the plain-http refusal asserted first and the realm put in development mode for the rest, #171), and the PDP dials the container across the bridge — this repository's third outbound request, with no test against a real listener anywhere until this — the row recording `The PEP answered 204.` and the change landing in tens of milliseconds against a five-second poll. It reads the PDP's console showing counters for decisions it never saw, compared against the PEP's own rather than constants. It feeds the PEP a hostile nudge BODY carrying a permit-everything policy and asserts nothing in it is believed. And it **takes the PDP away under the running container — `xacml.remotePeps` off in the realm since 2026-09-06, which was a realm removal until then — and asserts it goes on deciding correctly in both directions while reporting itself stale** — the trade `sync.js` argues at length and nothing had ever checked. Mutation-tested against five mutants, all caught: the pull no longer filtering disabled policies, the PEP never pulling twice, a module dropped from `xacml-pep/Dockerfile` (which kills the container at load and is invisible to anything that is not the image), the PDP nudging nobody, and a failed pull emptying the holding |
| `tests/vendored/sts_xacml_editor.js` **(ours)** | **THE GUIDED POLICY EDITOR, IN A REAL BROWSER.** `tests/xacml_pap.js` holds the editor's GRAMMAR in process; what it cannot see is whether any of it reaches a page — forty forms in one table, a hidden `path` per row, an `action` that is sometimes hidden and sometimes a `<select>`, and a nested-`<form>` hazard that is a parser question rather than a taste one. So this presses buttons: every row's menu equals the grammar's own answer for that row and Remove is drawn exactly where something may be removed; a Match offers no Add menu and its function list is the two-argument boolean predicates rather than the library; a rule stops offering a second Condition once it has one; an edit that would leave the policy invalid is refused, explained, and **the stored document is byte-for-byte what it was**, which is the property that makes a live editor tolerable. **And the assertion the file is for**: a rule built out of four form submissions makes `/xacml/protected` permit somebody it refused, alternatives are shown to be ORed and matches ANDed by watching that decision move, and removing the rule on the page brings the refusal back. It found one defect on its first run — every refusal on the three `/admin/xacml` pages redirected with an EMPTY `error=` — and was mutation-tested against four more |
| `tests/vendored/sts_roles.js` **(ours)** | **ROLES, AND THE NINE KINDS OF ISSUANCE THEY REFUSE PEOPLE AT.** In a throwaway trust realm, because this feature REFUSES people: a job that narrowed an application in the default realm and died before clearing it would leave every later job in the run signing in to a service that turned them away, and the failure would name the wrong file. Mostly negatives, for `sts_dpop.js`'s reason — a service that issues a token to somebody who holds the role is what an unmodified service does for everybody. What it asserts: the roles claim reaching a client; a narrowed application refusing at the token endpoint in **OAuth's own words** (`access_denied`, read as the error CODE rather than as a 400, because the two are a working gate and a broken handler); the person beside them not refused; a GROUP and an APPLICATION holding a role, which is the half `client_credentials` needs since there is no person in that grant at all; the built-in roles never appearing in the claim; WS-Trust's optional AppliesTo; and `roles.enforceIssuance` off putting everything back. Mutation-tested against eight mutants |
| `tests/vendored/sts_roles_builtin.js` **(ours)** | **THE SIX COMPUTED BUILT-IN ROLES, ONE SECTION EACH, POSITIVE AND NEGATIVE** (there are ten built-in roles; the other four are held through directory groups). `sts_roles.js` above drives the register and every role it uses is CONFIGURED; these six are computed from what the party IS, and three of them could not be held or failed by anything arriving at an endpoint until the day this was written. **EVERYBODY is the one with no negative case** — its `holds()` is `return true`, so it refuses nobody — and the file asserts that rather than leaving the gap to be noticed, by checking the catalogue still calls it the DEFAULT requirement. The other five are asserted both ways, at BOTH doors: the sign-in screen, which refuses with the page again and the reason on it, and the authorization endpoint, reached by making the session at the permissive application and carrying it to the strict one, which is the only way to see the second gate at all. Plus the unauthenticated session itself — that declining returns to the caller rather than answering `access_denied` like Cancel, that it is the stable `anonymous` principal on a real session id, that a signed-in session is NOT in that list, and that the setting is honoured at the DOOR and not only on the page. Section 6 asserts `oauth2.rfc9700` is OFF before it asserts anything else, because the claim there is that client authentication is OBSERVED without being ENFORCED. **It found the bug that made `ALL_AUTHENTICATED_USERS` refuse everybody.** Mutation-tested against seven mutants, none of which survived |
| `tests/vendored/bulk_load.js` **(ours, a HELPER)** | Not a job. **WHAT THE THREE BULK-LOAD JOBS SHARE, WHICH IS EVERYTHING EXCEPT THE DOOR**: the sizes, the five thousand deterministic invented people (from the index rather than `Math.random()`, so a failure at person 3,417 is reproducible), the stopwatch that keeps every lap, the preflight that raises `ldap.maxEntries` and reads the attribute catalogue, and the report. Not one line of it opens a socket or knows what a SCIM resource looks like — that is the thing under test, and a shared implementation of it would be three jobs measuring one piece of code three times |
| `tests/vendored/sts_directory_bulk_load_scim.js` **(ours)** | **FIVE THOUSAND PEOPLE, FIFTY GROUPS, FIVE THOUSAND MEMBERSHIPS, ALL OF IT OVER SCIM 2.0, AND HOW LONG EACH KIND OF WRITE TOOK.** The first of three jobs whose subject is TIME rather than behaviour, and each is still a test. `POST /scim/v2/Users`, `POST /scim/v2/Groups`, and the memberships ONE AT A TIME through `PATCH /scim/v2/Groups/{id}` — five thousand writes, each rewriting a member list one longer than the last, which is the number that would show this service getting slower as a group fills. **It BUILDS every resource out of the mapping published at `GET /admin-api/scim` rather than out of a copy** — `type`, `parent` and `extension` were added to that document for this job, and one projection replaced the two that had already drifted. One catalogue attribute (`description`) has no SCIM member at all; the drop is reported with the reason and the read-back checks only what was sent. It was `sts_directory_bulk_load.js` until 2026-09-06, when its user creates went through `/admin-api` and it measured a mixture |
| `tests/vendored/sts_directory_bulk_load_ldap.js` **(ours)** | The same work over **RFC 4511 ON THE RAW SOCKET**, and **the first job in either suite to drive it in earnest** (`sts_global_logout.js` makes one bind). Everything else that reaches this directory reaches it over HTTP and goes through `ldap_server.js`'s FUNCTIONS rather than its PROTOCOL — so the BER codec, the ldapjs submodule, the add handler's four refusals and the modify handler's change loop were exercised by nothing here at all. One bind, five thousand `add`s on it, fifty `groupOfNames`, five thousand `modify`s. The read-back goes through BOTH doors: a sample over the socket (which also drives SEARCH, half of this protocol) and one entry out of `/admin-api/ldap/directory`, because a store answering the socket out of something the HTTP views cannot see would otherwise pass. Needs the socket published — `tests/docker-compose-ldap.yml` and `STS_LDAP_URL`, argued above — and FAILS rather than skipping without it |
| `tests/vendored/sts_directory_bulk_load_ldap_50k.js` **(ours — DISABLED 2026-09-13 for suite speed; its `MANIFEST.js` entry is commented out, and restoring that entry re-enables it)** | **FIFTY THOUSAND PEOPLE OVER THE RAW LDAP SOCKET, and it asks a different question from the three above.** Those are the door-to-door COMPARISON and share their sizes for that reason; this one asks whether the add path stays CONSTANT-TIME an order of magnitude further out. It is worth asking separately because the answer was no until 2026-09-07: a create walked the whole realm to enforce one-entry-per-person, so the cost rose with the number of people already there — 0.73ms at the five hundredth and 13.45ms at the five thousandth. At five thousand that reads as a slow service; at fifty thousand it is a service that stops. **It drives `sts_directory_bulk_load_ldap.js`'s file at a different scale rather than copying its client** — each job owning its own DOOR is an argument for three jobs driving three protocols, not for two jobs driving one protocol twice — and owns only the SCALE and the NAMES: `BULK_USERS=50000`, `BULK_GROUPS`/`BULK_MEMBERS_PER_GROUP` at 1 (the group phases are the other job's to measure, and `checkSizes()` refuses nought), and `BULK_DOOR=ldap50k` so two LDAP jobs in one suite do not meet on every invented name. Measured 2026-09-07: **50,000 in 40.0s, mean 0.77ms, and the mean FALLING across the run** — which is the property it exists to keep. Last in the manifest, because it leaves the directory an order of magnitude larger than the others found it |
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

**What each surface still has NO test for is recorded in that surface's own
file**, not here — `scim/`, `spiffe/`, `oauth-oidc/` (the UserInfo claims
request), `ws-federation/`, `federation/` (the refusals, which is the surface
where the gap costs most, because it is the only one here whose bugs are
SECURITY bugs rather than fidelity bugs), `saml/` and `kerberos/`. Each of those
lists is almost entirely NEGATIVES, for the reason `tests/vendored/sts_dpop.js` gives: an
identity provider that hands a working relying party a signed assertion looks
finished and can be worth nothing.


`tools/` is not in that table because nothing in it is a test:
`run-report.js` (the report generator), `coverage-report.js` (the V8 coverage
renderer), `vendor-check.js` (the drift check over `vendored/`, and a TOOL
rather than a job on purpose — its own header argues why a check that needs the
other checkout must not be what decides whether this repository is green),
the compose-stack helpers (`compose.sh`, shared by `./run-tests.sh`
and `./run-coverage.sh`),
`service.js` (one throwaway copy of this service, started and
stopped by pid, on a block of ports of its own) and `coverage_entry.js` (`server.js`
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
and it is the file that says what the line is FOR. The protocol half's
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
unreachable; what it fixes is the three call sites in `admin-ui/admin.ts` that
pre-validate a whole section before writing any of it, and those are only
reachable over HTTP. That mutant is caught by `tests/vendored/sts_admin_console.js`
in the protocol half, which presses the Save button those call sites are behind.
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

## A CA MADE AT RUN TIME, AND THE DIRECTORY IT REACHES THE SERVICE THROUGH (#171, 2026-09-23)

Since #171 product mode ignores every `…SkipTlsVerification`, so a job that
runs a push or notify listener of its own and wants the SERVICE to reach it in
product has to present a certificate the service trusts — and what product uses
to trust a private CA is a `…CaFile` setting, a path on the SERVICE's
filesystem, which a job reaching the service over HTTP cannot write by itself.

**No key or certificate is committed for this (rcbj's ruling, 2026-09-23).**
`tests/vendored/outbound_test_ca.js` makes a fresh CA key pair and certificate
at run time, and the listener certificates under it, with the vendored PKI
encoder (`common/vendored/x509.js`, `key_material.js`) — the in-process files
(`outbound_tls.js`, `federation_subject_policy.js`) use the same helper and a
temp directory. Only the CA CERTIFICATE is ever written, to a directory both
sides can see, named twice because they see it at different paths:
`OUTBOUND_TEST_CA_DIR` (where the runner writes) and `OUTBOUND_TEST_CA_FILE`
(the path the service reads; its file name is the one written).

* the compose stacks mount the named volume `sts-test-shared` at
  `/run/sts-test` in the runner and, read-only, in `sts` (and `sts2`, through
  `extends`), and default both variables to it;
* `./run-coverage.sh`, whose service is a child of the runner, names one temp
  directory for both;
* a private container started by hand needs a `-v` of a host directory at the
  service-side path, `OUTBOUND_TEST_CA_DIR` pointing at the host side and
  `OUTBOUND_TEST_CA_FILE` at the service side.

**With neither variable set there is no shared directory — an AWS target, or a
hand run without the mount — and the sections that need one SKIP, saying so**:
`sts_gnap_core` section 6 (the push finish) and `sts_outbound_tls`'s
CA-file delivery in product. Everything else in both jobs still runs. A mount
that is named but not seen by the service is a misconfiguration and fails, on
`STS-CORE-0104`.

## EVERY CHAIN A JOB PRESENTS NAMES ITS CAs' LISTS (#174, 2026-09-23)

Since #174 a product-mode service refuses, under hard-fail, a certificate from
an authority it does not hold that names no CRL and no OCSP responder
(`pki.revocationRequireDistributionPoint=auto`, `STS-PKI-0190`): nobody could
ever revoke it. Every chain this suite mints and presents — or registers —
used to be exactly that, so each certificate below a Root now names its
issuer's list, and the list is a REAL one: empty, signed by that CA, fetched and
verified by the service like any other.

* **`tests/vendored/test_crl_host.js`** (a LOCAL helper) signs the list and
  serves it from the JOB'S own process, on `OUTBOUND_TEST_HOST` or
  `GNAP_PUSH_HOST` — the address a job's push listeners are already reached
  at — `unref()`ed so it never holds a job open. `reserve()` hands back the
  URL before the list exists, because the child certificate has to name it.
* **`tests/tools/pep-credential.js`'s `mint()`** uses it by default, so every
  job that mints a PEP or XACML-user chain gets lists without a line changed;
  `sts_global_logout.js`, `sts_console_bootstrap_product.js` and the two
  credentials jobs' external hierarchies name theirs directly.
* **The launcher's PEP credential outlives its minter**, so `--crl-base`
  names `http://xacml-pep:9090/crl` (the AWS runner: the task's address) and
  writes `root.crl` and `issuing.crl` beside the credential; the PEP container
  serves them at `GET /crl/<name>` (`xacml-pep/CLAUDE.md`).

Nothing is committed: the CA is made at run time, and a CRL is a public signed
document. **A new job that presents a CA-issued chain to a product-mode
service owes the same**, or it is refused for a reason that has nothing to do
with what it tests.

## THE EXTERNAL TEST VECTORS (#202, #203, 2026-09-24)

Two corpora nobody here wrote hold `common/crypto.js` to answers it did not
choose: `wycheproof.js` and `acvp_pqc.js` (the table above).

| Corpus | Where from | Pinned at | Licence |
|---|---|---|---|
| C2SP Wycheproof, `testvectors_v1/` | `github.com/C2SP/wycheproof` (the archive of the whole tree) | `3fa63dd0344abb611f1fb1d77e119938603ea230` (2026-09-02) | Apache-2.0 — its `LICENSE` is kept beside the vectors |
| NIST ACVP-Server, `gen-val/json-files/<set>/internalProjection.json` for the ten ML-KEM, ML-DSA and SLH-DSA sets | `github.com/usnistgov/ACVP-Server` | `975de31eb83d87039ec88934fdc47d8c312b892d` (v1.1.0.43, 2026-08-12) | a work of the US government, public domain in the United States |

**FETCHED AT IMAGE BUILD TIME AND NEVER COMMITTED**, because both carry test
keys — RSA and EC private keys, ML-DSA and ML-KEM seeds — and this
repository commits no key material. `tests/tools/fetch-vectors.sh` runs in
`tests/Dockerfile` above the source copy (cached until it or the checksums
change), fetches each corpus at its commit and checks it against
`tests/tools/vectors.sha256`; a mismatch fails the build. It writes
`tests/vectors/` in the image, which `.gitignore` and `.dockerignore` both
exclude so a host copy can neither be committed nor overwrite the checked one.
`STS_WYCHEPROOF_DIR` and `STS_ACVP_DIR` point a hand run elsewhere.

**BUMPING A PIN** is: change the commit in the script, fetch, write the new
sums into `vectors.sha256`, and run both files — a new Wycheproof file that
no door and no not-applicable rule claims fails `wycheproof.js` until it is
classified, and a new ACVP group is either applied or counted by reason.

**WHAT "NOT APPLICABLE" MEANS** is recorded per file (Wycheproof) and per
reason (ACVP), in each file's log, and on #202 and #203. The short version:
crypto.js has no ChaCha20, no X25519, no AES-SIV/CCM/EAX, no ML-KEM
encapsulation, no context strings or pre-hash for ML-DSA and SLH-DSA, and
its ECDH doors agree over P-256/384/521 only. What crypto.js offers that
neither corpus covers: SLH-DSA verification has no Wycheproof file, the
composite ML-DSA JOSE algorithms are in neither, nor are the Kerberos PRF
(held to RFC 3961 and MIT by `kerberos_fast_otp.js`), TPM KDFa, DKIM,
scrypt, JWE PBES2 or RFC 7518's Concat KDF (exercised end to end through
the ECDH-ES vectors).

## THE OPENID CONFORMANCE SUITE (#176, 2026-09-24)

rcbj's decision on #142: **a job in `./run-tests.sh` that fails when a module
fails.** The job is `tests/vendored/sts_fapi_conformance.js`; the suite is the
OpenID Foundation's own published images — its server (a JVM), a MongoDB and
its nginx — in `docker-compose-run-tests.yml` behind the `conformance` compose
profile, pinned by tag (`CONFORMANCE_SUITE_TAG`, `release-v5.3.1`).

* **Which modes.** `STS_TEST_CONFORMANCE_MODES` (default `memory`) names the
  modes whose runner `up` activates the profile and hands the job
  `CONFORMANCE_SUITE_URL`; such a mode's bound grows by
  `STS_CONFORMANCE_TIMEOUT` (1800 s). Everywhere else the runner reports the
  job SKIPPED with the reason (`run-report.js`, the `conformance` flag — a
  deliberate exclusion, as `docker: true` is). `memory` because FAPI-CIBA
  approves through a development-mode test control, and each plan runs in a
  realm of its own under its FAPI profile, so a persisting mode would check the
  same rules again.
* **The names are the suite's.** Its nginx proxies to `server:8080` and answers
  as `localhost.emobix.co.uk`, the name its server builds every URL on and its
  scripted browser follows back — network aliases on this network, nothing
  published. The three are PINNED at `.40`–`.42`: the service adds `.11`–`.13`
  to its own interface, which docker's allocator cannot see.
* **What the job does per plan**: a throwaway realm with `oauth2.fapi` set, a
  person with a password, two clients registered with EC keys made at run time
  (no key material in git), certificates from the realm's CA for the mTLS
  plans, the protected Grant Management scopes declared by an administrator
  (#110), and the plan's configuration: the discovery URL, the `browser`
  commands that sign in on `/authn/login` and allow the consent screen, and
  per-module `override`s — Cancel for user-rejects-authentication, and a first
  visit that only loads the sign-in page for the reused-request_uri module.
  FAPI-CIBA's `automated_ciba_approval_url` is an HTTP listener in the job
  that answers through `/admin-api/users/answer-ciba-request` with the `acr`
  the request asked for.
* **A module has five minutes** (`CONFORMANCE_MODULE_SECONDS`); one still
  running is stopped through the suite's API and fails. Measured on
  2026-09-24: FAPI 1.0 Advanced 106 s, FAPI-CIBA 180 s, the whole four 940 s
  under `./run-tests.sh`.
* **No FAPI 1.0 Baseline plan**: the suite (v5.3.1) publishes none any more —
  Advanced is 1.0's only plan — so `sts_fapi_baseline.js` is Baseline's only
  check.
* **WARNING is not a failure, and every module has one**: the realm's JWKS
  carries post-quantum keys the suite cannot parse. `oauth-oidc/CLAUDE.md` 3bg
  lists what the first runs found in the service and the warnings that stay.

**By hand, beside a service of your own**: start the three images on one
docker network with the aliases above (`mongodb`, `server`,
`localhost.emobix.co.uk`; the server wants the placeholder
`OIDC_GOOGLE_*`/`OIDC_GITLAB_*` values the compose file passes), then run the
job from the tests image on that network with `CONFORMANCE_SUITE_URL`,
`CONFORMANCE_CALLBACK_HOST` (its own name there, for the CIBA approver) and
`CONFORMANCE_PLANS=fapi2sp,fapi2ms,fapi1adv,fapiciba` to choose. The suite's
own pages at `https://localhost.emobix.co.uk:8443/plan-detail.html?plan=<id>`
(the job logs the id) show every module's log.

## THE SCIM CONFORMANCE HARNESSES (#206, 2026-09-26)

**No official SCIM conformance suite exists** — the IETF working group
published none — so `sts_scim_conformance.js` runs the two independent ones,
and neither is vendored: both are fetched and pinned when the tests image is
BUILT, above the source copy, and nothing of them is committed.

| Harness | Licence | Pin | How it gets into the image |
|---|---|---|---|
| python-scim **scim2-tester** 0.4.0 (<https://github.com/python-scim/scim2-tester>), with scim2-models, scim2-client and their dependencies | Apache-2.0 (the three scim2 packages; the rest their own) | every package `==` a version AND `--hash=sha256:` in `tests/scim-conformance/requirements.txt`; `pip install --require-hashes` | a virtual environment, `/opt/scim2-tester` (`STS_SCIM2_TESTER_PYTHON`) |
| **scim2/test-suite** (<https://github.com/scim2/test-suite>), no release tagged | Apache-2.0 (its `LICENSE` is copied beside the binary) | commit `3d80a46970a02ce114efeeb38f3f112b5d736d16` and the tarball's sha256 in `tests/scim-conformance/build-test-suite.sh`; its Go modules by upstream's `go.sum` | compiled (`go test -c ./compliance/`) in the `scim2-test-suite` stage of `tests/Dockerfile` (`golang:1.26`), and only the binary, `LICENSE` and `COMMIT` copied into the runner, `/opt/scim2-test-suite` (`STS_SCIM2_TEST_SUITE`) |

**Why two.** #206 named scim2-tester, which exercises discovery, CRUD, PATCH
and the `attributes` parameter per resource type and NOTHING ELSE — no filter
expression, `sortBy`, `startIndex`/`count`, Bulk or `If-Match`. The ticket
said to evaluate scim2/test-suite for what it left uncovered; it covers all of
those, requirement by requirement, so it runs too.

**What this repository adds** is `tests/scim-conformance/scim2_tester_driver.py`,
which calls scim2-tester's `check_server()` unchanged (its CLI calls
`discover()` first and crashes on a description it cannot compose, and prints
text) and prints every result as JSON. It adapts what the harness SENDS in
three places, never what it checks, each argued in the file: a `userName` is
prefixed so it is not UUID-shaped (`STS-LDAP-0090` refuses one as a subject
identifier); a Group member's `type` agrees with the `$ref` the harness itself
chose; and this service's own `federationLinks` name the service-provider-side
relationship the job creates, since a random one is refused (`STS-FED-0105`).

**The exceptions** are the job's `EXCEPTIONS` table and a comment on #206, one
reason each: scim2/test-suite's `TestResource` resource type, which only its
built-in server defines; its hard-coded `nickName` and `home` email, both no
longer published because the directory cannot hold them; its fuzzed Group
member `$ref` at `https://example.com/…`; its joining of an ABSOLUTE `$ref`
onto its base URL; and, in scim2-tester, `active` (always said — `scim/CLAUDE.md`)
and an add to `federationLinks` on a resource it had already given one.

**By hand on a host**: point `STS_SCIM2_TESTER_PYTHON` at a virtual
environment made from `requirements.txt` (any Python the wheels install on)
and `STS_SCIM2_TEST_SUITE` at the binary, or at a wrapper that runs it in a
`golang` container with `--network=host` (it needs a newer glibc than most
hosts), and drive the job with the recipe for any local job.

## THE PUBLISHED XML SCHEMAS (#188, 2026-09-24)

The job is `tests/vendored/sts_xml_schema_validation.js`. OASIS publishes no
conformance tool for SAML, WS-Trust or WS-Federation — only the schemas — so
the schemas ARE the official machine check, and until this job nothing here
validated a single emitted document against them.

* **Fetched when the tests image is built, never vendored.**
  `tests/xml-schemas/SCHEMAS` names thirty-one files (SAML 2.0 and 1.1,
  WS-Trust 2004/04, 2005/02, 1.3 and 1.4, WS-Security 1.0/1.1, WS-Federation
  1.2 and WS-Authorization, WS-SecurityPolicy, WS-Policy, WS-Addressing in
  three vintages, SOAP 1.1 and 1.2, MEX, XML Signature 1.0/1.1, XML
  Encryption 1.0/1.1, `xml.xsd` and the two DTDs `xmldsig-core-schema.xsd`
  names) with the sha256 of each; `tests/tools/fetch-xml-schemas.sh` fetches
  them into `/opt/xml-schemas` in `tests/Dockerfile` and FAILS THE BUILD on a
  single differing byte. www.w3.org answers a scripted https fetch with a
  Cloudflare challenge (429), so the W3C files are named over http, and any
  file whose publisher refuses is asked of the Internet Archive's raw capture
  of the same URL — accepted only at the same digest.
* **`catalog.xml` and `all.xsd` are this repository's.** The catalogue maps
  every schemaLocation the published files import each other by to the local
  copy, so the job runs `xmllint --nonet`; `all.xsd` imports every namespace,
  because the containers of these formats hold their content in
  `processContents="lax"` wildcards, which skip an element whose namespace is
  not loaded. The job adds this service's own `/crypto/metadata.xsd` at run
  time for the one extension element the SAML metadata carries.
* **Valid is three things**: xmllint passes it with no error and no warning
  (the schema set's own "Skipping import" notes are set aside by name); every
  namespace an element or attribute uses is loaded (`coverageProblems()`); and
  every element's local name is declared in its namespace's schema — lax
  content would pass a misspelled element otherwise. The job's first four
  checks prove each refusal fires.
* **ONE DERIVED FILE, recorded on #188 as a schema/specification conflict**:
  the OASIS Standard's `ws-trust-1.3.xsd` declares its targetNamespace with a
  trailing slash (`.../ws-trust/200512/`) that the specification's namespace,
  the 1.4 schema's own `xmlns:wst` and every implementation do not have. The
  fetch keeps the original (the digest is of it) and writes
  `ws-trust-1.3-ns.xsd` with that one string changed, which `all.xsd` imports.
* **A scenario that yields no document FAILS** (`capturedOne()`), and the
  job asserts a floor on how many were validated: a flow that silently
  stopped emitting its message would otherwise take its coverage with it.
* **What the first run found**, each fixed in the module that owns it: the
  WS-Trust 2004/04 answers used three elements that version does not have
  (`ws-trust/CLAUDE.md`); the federation module's WS-Federation relationship
  metadata lacked the required `fed:ApplicationServiceEndpoint`
  (`federation/CLAUDE.md`); and `cm:CryptoMetadataLocation`, in the SAML 2.0
  metadata's Extensions, was declared by no schema, the service's own
  included (`pki/crypto_metadata_document.ts`).

**By hand**: `tests/tools/fetch-xml-schemas.sh <dir>`, then the job with
`STS_XML_SCHEMA_DIR=<dir>` and the usual `--url`, token and CA — or inside
the tests image, where the directory is already there.

**A new document type in these four families owes a scenario here** in the
change that adds it.

## THE CERTIFICATE ENROLLMENT CLIENTS (#207-#211, 2026-09-26)

No official conformance suite exists for ACME, EST or SCEP, so the strongest
independent check of each server is the client its operators run. Five of
them drive the service from five `local: true` jobs (the table above):

| Client | Pinned at | Licence | Built |
|---|---|---|---|
| certbot (EFF) | 5.8.0 | Apache-2.0 | pip into a venv in the runner, every package hash-pinned in `tests/tools/certbot-requirements.txt` (`--require-hashes --no-deps`) |
| lego (go-acme) | v5.5.2 | MIT | `go install` in the `enroll-go` stage, checked against sum.golang.org (its `--version` says v5.6.1+dev-release: upstream's generated constant, not the module) |
| scepclient (micromdm/scep) | v2.3.0 | MIT | the same stage (`-version` says "unknown": `go install` stamps none) |
| estclient (cisco/libest) | a464ba8 (`main`, 2022-09-22) | BSD-3-Clause | the `enroll-c` stage, statically against OpenSSL 1.1.1w (it does not build on OpenSSL 3), both archives sha256-checked |
| sscep (certnanny) | cb3e539 (`master`, 2024-08-14) | BSD-style | the same stage, against the base's OpenSSL 3, sha256-checked (v0.10.0 cannot GetCert from a CA with a separate RA) |

**IN THE TESTS IMAGE, NOT A COMPOSE PROFILE — and that is the argument.** Each
client is a command line a job runs and whose files it reads: a second
container would need a way to be told what to run and to hand the files back,
which is a server of our own in front of the real client. So they are built in
two stages of `tests/Dockerfile` (compilers, OpenSSL 1.1 and the Go toolchain
stay out of the runner) and copied in with their licences
(`/opt/enroll-clients/licenses`), above the source copy so an edited job
rebuilds nothing. Nothing is vendored and no key material exists before a run:
every key, CSR and account is made by the job or the client at run time. The
cost is about five minutes on a cold tests-image build.

**Every local mode runs them**; nothing is wired into `./run-tests.sh` beyond
the jobs themselves, because there is no second container to start. The shared
plumbing — the management API, a trust-bundle FILE for a client that is not
node, an ASYNCHRONOUS bounded runner (spawnSync blocked the event loop while
the service closed the job's keep-alive connection, and the next fetch failed
"other side closed"), the portal sign-in under a realm, the CRL reader — is
`tests/vendored/enroll_clients_kit.js`.

**Each job checks the client's own output**: a successful command may log no
warning and no error, and the few lines a client prints about itself are
accepted by name, each argued in the job's header. What the clients found in
the service, and the exceptions, are in `acme/CLAUDE.md`, `est/CLAUDE.md` and
`scep/CLAUDE.md`, *What the real clients found*, and on the tickets.

**By hand**, inside the tests image on the stack's network: the job with the
usual `WSTRUST_STS_URL`, `OID4VCI_ISSUER_URL`, `NODE_EXTRA_CA_CERTS`, the
admin token and the preload — the clients themselves are on the PATH.

## THE SAML PEERS (#189–#192, 2026-09-24)

There is no maintained SAML conformance tool — Kantara's interoperability
programme ended and `saml2test` was archived in 2014 — so the check is four
INDEPENDENT implementations, each a second container under the `saml-peers`
compose profile and each driven by a `local: true` job of its own:

| Peer | Built from | Driven through |
|---|---|---|
| Shibboleth SP 3.6.0 (`saml-shib`) | the Shibboleth Consortium's RPM repository on Rocky Linux 9 — the vendor's packages on the vendor's platform; the Consortium publishes no image | a small control server (`control.py`, port 9090) that writes the identity provider's two metadata documents — and, since #248, nothing else — and restarts shibd; `/Shibboleth.sso/*`; `/peer/env`, a CGI answering the session's environment as JSON |
| pysaml2 7.5.5 (`saml-pysaml2`) | PyPI, under python:3.12-slim with xmlsec1 | `peer.py`, an SP over `Saml2Client` the job scripts — `/configure`, `/login?...&fault=`, `/acs`, `/last`, `/logout`, `/slo` |
| SimpleSAMLphp 2.5.3.1 (`saml-ssp`) | the release tarball, pinned by version and sha256, under php:8.3-apache | four pages under `/peer` — `configure.php` (SAMLParser and the schema validator), `login.php`, `env.php`, `logout.php` |
| Keycloak 26.6.4 (`saml-keycloak`) | its official image, the tag the parent project runs | its own admin REST API: a realm, a SAML identity provider imported from this service's metadata, mappers, a client — no exported realm file |

* **How they run.** `./run-tests.sh` brings the profile up in the modes
  `STS_TEST_SAML_PEERS_MODES` names (`memory,single-node` by default — CI's
  `tests` job; not `cluster`, whose job has no room under the 120-minute
  ceiling `teardown_bounds.js` holds, so `STS_TEST_SAML_PEERS_MODES=cluster
  ./run-tests.sh --modes=cluster` runs them there), builds their images with
  the rest, hands each job `SAML_PEER_<NAME>_URL`, and adds
  `STS_SAML_PEERS_TIMEOUT` (900 s) to the mode's bound. Elsewhere — another
  mode, an AWS target, a hand run without them — each job is SKIPPED by the
  runner with the reason (`samlPeer` in MANIFEST.js, as `conformance` is).
  Their addresses are PINNED at `.43`–`.46`, for #176's reason.
* **Each job, per realm.** It makes a development and a product realm (a
  realm's `global.mode` is its own), each with a person; registers the peer
  by CONSUMING the peer's own SP metadata (#37); hands the peer the per-SP
  identity provider metadata this service publishes for it (and, for
  pysaml2 and Keycloak only, the TLS anchor for its back channel — #248); and
  then walks the scenarios as a browser
  would — `saml_peer_kit.js`'s `walk()`, cookies per host, redirects and
  auto-posting forms on both origins, this service's sign-in screen — with a
  browser's User-Agent, because the risk evaluator scores node's own as an
  automated client and a product realm's issuance policy refuses it (#62).
* **THE PEER'S OWN LOG IS THE ERROR-AND-WARNING SOURCE.** Each peer writes
  its log to its directory of the `sts-test-shared` volume (#171), which the
  runner mounts too (`SAML_PEERS_LOG_DIR`); every scenario remembers where
  each log ended and fails on any WARN/ERROR line it gained. Two warnings are
  set aside BY NAME, each about the peer and never about a message this
  service sent: Shibboleth 3.6's "SAML 1.1 support is removed from next major
  version", and Keycloak's "Non-secure context detected" for the plain-HTTP
  front door every peer has on this private bridge.
* **No key is in git.** Every peer makes its key pair when it starts (and
  Keycloak its admin password, and SimpleSAMLphp its secret salt); the
  service's anchor travels from the job at run time. **Keycloak starts only
  when its job hands it that anchor** — its truststore is read once, and a
  job may rebuild the Root mid-run — so its JVM's minute is inside its job.
* **Shibboleth's trust of the back channel is the metadata ALONE since #248**:
  the identity provider's documents publish the certificate the listener
  presents (`saml/CLAUDE.md`, *THE BACK CHANNEL'S TLS CERTIFICATE IS IN THE
  METADATA*), so the SP's `ExplicitKey` engine authenticates artifact
  resolution and the attribute query with no anchor handed over; the
  `StaticPKIX` engine over the service's anchor that stood beside it until
  then is gone. The job's `backchannel` section checks the published key is
  the one the service presents, and a development-realm CONTROL strips it
  and expects the SP to refuse both. pysaml2 and Keycloak still take a CA
  file — neither reads a metadata key for TLS (`requests`' `ca_certs`, the
  Java truststore) — and SimpleSAMLphp, whose SOAP client would pin to the
  metadata key, cannot use the artifact profile at all (#191).

**What they found** is in `saml/CLAUDE.md` (*What four independent service
providers found*), each finding fixed with a check in
`tests/saml_interop_findings.js`; the exceptions are on the tickets.

**By hand**, beside a service container on a network of your own: build and
run each `tests/saml-peers/<peer>` image with a network alias of its compose
service name and the shared directory mounted at `/run/sts-test`, then run
the job from the tests image with `SAML_PEER_<NAME>_URL`, `SAML_PEERS_LOG_DIR`
and the usual `WSTRUST_STS_URL`, token and CA. `SAML_PEER_SECTIONS=<a,b>`
runs a job's named sections only.

## THREE CI-ONLY FAILURES, AND WHAT EACH ONE TEACHES (2026-08-30, 2026-09-10)

The first two were found by a manual `workflow_dispatch` of
`.github/workflows/tests.yml` on `develop`, both were invisible on a developer
machine, and neither was a defect in the service. They are recorded together
because the lesson is the same one twice: **a test that is timing-dependent passes on the machine it was
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

### The third was not a test at all: a teardown that would not finish (2026-09-10)

**THE SUITE PASSED AND THE JOB WAS REPORTED AS A FAILURE.** All three modes
ran; the last of them finished `78 job(s), 78 passed, 0 failed, 0 skipped, 1441
assertion(s)`, wrote its report and exited 0. Then `up
--abort-on-container-exit` — which stops the rest of the stack once the runner
is done — printed `Container sts-postgres-docker-tests  Stopping` and sat there
for **twenty-three minutes**, until the job hit its 45-minute wall clock and
GitHub cancelled it: no summary, no exit code, and only the `if: always()`
upload step to show for the run.

Nothing was wrong with the tree, and nothing in this repository could have
prevented the hang. Modes one and two stopped that same container in 0.17s and
0.48s; the run the day before stopped it three times out of three. **No compose
flag covers it either**: `up` already takes a shutdown grace, already defaults
to ten seconds and already follows with SIGKILL — the `xacml-pep` container
spends every one of those ten seconds on every run and dies on the kill — so
the kill was reached and did not land. A stop that outlives SIGKILL is a wedged
daemon or a process the kernel will not interrupt.

**What this repository decides is what happens NEXT, and the answer was "wait
for ever, then lose the run".** It is now two bounds `./run-tests.sh` reaches ITSELF
(`STS_MODE_TIMEOUT`, `STS_TEARDOWN_TIMEOUT`), and the difference that matters is
that a bound reached HERE can say what happened, capture the container logs,
keep the report and still give the mode a verdict, where the CI timeout catches
things only by throwing the run away.

**THE RECOVERY IS THE PART TO GET RIGHT, NOT THE BOUND.** `up
--abort-on-container-exit --exit-code-from tests` does two separable things and
only the first is the suite: it runs the stack until the runner exits, and THEN
stops everything else before reporting that runner's code. So by the time the
second half can hang, the answer already exists on a stopped container.
`recoverModeVerdict()` asks docker for it. Without that, a bound would simply be
a faster way to throw a green suite away.

**AND THE FIRST VERSION OF THAT RECOVERY WAS CONFIDENTLY WRONG IN THE ONE CASE
NOBODY WOULD CHECK.** Reaching the bound SIGTERMs compose, and compose answers a
SIGTERM by stopping the stack — the runner included. So a suite that was still
going is a container that has EXITED by the time the recovery looks at it,
killed 137 by a teardown this launcher caused. Read as a verdict, the mode fails
for the right reason by accident and the launcher announces *THE SUITE FINISHED*
about a run four minutes from finishing. **128+N is a signal and not an answer**;
only a smaller code is something the runner decided.

**It was found by forcing the bound on a real run** (`STS_MODE_TIMEOUT=100
./run-tests.sh --modes=memory`), which is the only way it could have
been: every in-process assertion about the recovery was green, and the five
cases were verified against real exited containers before the wiring was driven
end to end. **A timing fix that has only been seen to pass has not been shown to
fix anything** — the same sentence the first of these three failures ends with.

`tests/teardown_bounds.js` is the guard, thirteen mutants, all caught.

## EVERY JOB CARRIES AN `/admin-api` ACCESS TOKEN NOW (2026-09-09)

`/admin-api` required no credential at all until that day and required one
after it: an OAuth 2.0 access token this service issued, audienced to that API,
carrying `admin:read` for a read and `admin:write` for a write. **Twenty-odd
jobs here drive that API and not one of them shares an HTTP helper** — each
builds its own `fetch` or `https.request` — so making them all authenticate was
either twenty-odd edits saying the same thing, or one place saying it once.

**IT IS ONE PLACE, AND THESE ARE ITS PARTS:**

| File | What it does |
|---|---|
| `tools/admin-api-token.js` | Mints the token. The seeded `sts-management-api` client, `client_credentials`, `resource=<base>/admin-api`. It is the ONE place the client id, the grant and the form shape are written down. |
| `tools/attach-admin-token.js` | Presents it. Preloaded into every job by `run-report.js` with `--require`; it wraps global `fetch` and `http`/`https.request` and adds the header to `/admin-api` calls that do not already carry one. |
| `tools/browser-user-agent.js` | **A browser's User-Agent** (#62 P3, 2026-09-22). Preloaded into every job, in every mode, the same way: a `fetch()` with no `user-agent` of its own gets a desktop Chrome's, and a Selenium `Builder` whose Chrome options carry no `--user-agent` gets one. Product mode refuses a first sign-in from an automated client (the issuance policy on its risk), and node's `fetch()` says `node` and headless Chrome says `HeadlessChrome` — rcbj's decision was to keep the policy and have the suite look like a browser. The automated-client decision itself is tested in process, by `tests/risk_engine.js` and `tests/risk_decisions.js`. |
| the two DOCKER launchers | Mint it once per mode, before any job runs, and hand it over as `STS_ADMIN_API_TOKEN`. They have to: the service is a CONTAINER they brought up, so nothing downstream can choose its client secret. |
| `tools/run-report.js` | Mints it for a service **it** started — the throwaway. It pins `ADMIN_API_CLIENT_SECRET` before the child starts and mints once it answers. See *The third path* below. |
| `.github/workflows/build-container.yml` + `tools/container-smoke.js` | **Not a job runner, and the one path that is not a launcher** (2026-09-15). The workflow's smoke test pins the secret on `docker run`, mints through `tools/admin-api-token.js`, and `container-smoke.js` requires the preload itself, signs in with `vendored/console_signin.js` and reads `/admin/sts-metadata`. It passed `ADMIN_AUTH_REQUIRED=false` for a curl until then — a setting removed on 2026-09-06 that nothing failed on, so every merge to main from 2026-09-09 died at that step with a 303. `admin_api_token_wiring.js` does not look at it. |

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

**THE FAILURE IS THE RUN'S AND NOT THE JOB'S.** Both docker launchers mint the
token before starting anything and abort the mode if they cannot: without one,
every job that touches that API reports a 401 and the report names twenty
problems where there is one. `run-tests.sh` mints it **once per mode**
rather than once per run, which is the one thing about it that is easy to get
wrong — the
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

### The third path, and it is where this went wrong (2026-09-09)

**"THE LAUNCHERS MINT IT" WAS NOT A COMPLETE SENTENCE AND THIS SECTION SAID IT
ANYWAY.** There are three ways a job here reaches a service and only two of them
go through a launcher that mints:

* `./local-run-tests.sh` and `./run-tests.sh` — a CONTAINER they started,
  and they mint against it
* **`./run-coverage.sh`, `./local-run-tests.sh --no-docker`, and a bare `node
  tests/tools/run-report.js`** — a THROWAWAY `run-report.js` started itself

(`./local-run-tests.sh` and its `--no-docker` were removed on 2026-09-16; the
other paths are unchanged.)

The gate landed with the first two taught and the third untouched, and the third
is what CI's coverage job runs. That job drove the whole protocol half against a
gated API with no credential: **57 passed, 19 failed**, and only seventeen of
the nineteen mentioned the API at all. `sts_saml_encryption` reported that this
identity provider would not encrypt an assertion — 14 failures, every algorithm
pair — because the service provider certificate it writes through `/admin-api`
was refused and it does not assert that write. `sts_saml11` reported eleven
SAML 1.1 defects for the same reason. **Two jobs describing a protocol bug that
did not exist is what a missing credential looks like from the report**, and it
is why the fix went into `run-report.js` rather than into a fourth copy of the
minting block.

**THE ORDERING IS THE LOAD-BEARING PART.** `applications.js` seeds
`sts-management-api` with a secret minted at every start, readable only THROUGH
the API it unlocks — so the secret has to be pinned BEFORE the child starts and
the token asked for AFTER it answers. That is two functions rather than one, and
`tests/admin_api_token_wiring.js` pins the direction between them: the failure a
reversed pair produces names a client secret and says nothing about ordering.

**A SERVICE HANDED IN WITH `--service-url` IS WARNED ABOUT RATHER THAN FIXED.**
This runner cannot know the secret a service somebody else started chose, and
reading it back goes through the API that is asking for the token. Whoever
started it is who can mint against it — so the runner says that, at `warn`, in
one line, instead of letting nineteen jobs say it badly.

**AND IT IS NOT FATAL HERE, WHICH IS THE OPPOSITE OF WHAT THE LAUNCHERS DO.** A
launcher fails having run nothing; exiting costs a report that does not exist
yet. `run-report.js` has by then started a service and is about to run every job
in the manifest, most of which never touch that API — so aborting would throw
away the unit half and the coverage to protect the nineteen. It logs at `error`
naming the cause, and `sts_admin_api_auth.js` is still there to fail on it.

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
nothing of their own — while a realm's own signing key minting the SERVICE
administrator credential is precisely the hole this gate's default-realm key
keeps shut. **Since 2026-09-14 a realm's key does sign a credential — that
realm's own, believed under that realm's prefix only and refused every
service-wide operation** — and `sts_realm_administrators.js` is where that half
is asserted.

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
check. Several files in this repository legitimately contain one — as of
2026-09-16 `tests/ldif_codec.js` (which tests exactly this),
`tests/minted_persistence.js`, `tests/minted_flush_order.js`,
`common/certificate_subject.js`, `common/tls_client_certificates.js` and
`xacml-pep/pip.js` — so a new one is worth a second look before it is
committed, and `grep -a` reads them all.

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
than in `tests/` here, by the line drawn under *What this directory is for*
above: **every one of
the assertions can be made by driving the running service over HTTP.** Three
things are checked and each answers a different way of the page going wrong:

* **The drift report, in all three directions** — a protocol family this mock
  advertises with no crypto profile, a profile naming a family that is not
  advertised, and a family citing an envelope with no row in the standards
  table. The page reports all three on itself; this is what makes them FAIL.
* **Every coverage note starts `full`, `partial` or `mock`**, the rule
  `sts_metadata.ts`'s specification list already follows.
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
WITH. `common/user_graph.ts`'s `permissionsAddressedTo()` is the rule that
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

**A trust realm a test run created STAYS.** Many jobs here create one; not one
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
* **Accumulation.** A realm is persisted only where a store is configured, and
  the suite's stacks keep theirs in a container with no volume, so they go when
  the stack does. A person who wants them gone restarts the mock or removes
  them by hand.

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
above: **this service keeps its state across jobs and never restarts between
them**, so anything a job leaves behind is another job's starting state. It is
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
`caep_initiating_entity.js` does, through `logout/logout.ts`), node's module
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
six computed built-in roles answered across their four contexts. A running service cannot
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

## THE ACCOUNT-PAGE PAIR, AND THE ASSERTION THAT PINS A DESIGN (2026-09-11)

| File | Where | What it can see |
|---|---|---|
| `tests/inetorgperson.js` | in process, no port | the SCHEMA — the union of three object classes, the MUST set, and the two refusals inside `rowFor()` |
| `tests/vendored/sts_portal_directory_attributes.js` | over HTTP, `local: true` | the PAGE — that it reads the directory rather than the session, names all fifty, and leaks none of the credentials stored beside them |

**THE OVER-HTTP JOB HAS ONE ASSERTION THAT IS WORTH MORE THAN THE OTHER
SEVENTEEN**, and it is the model for how to test a design rather than an
output. The account page could have been written to iterate the entry; this
service stores a TOTP shared secret, recovery codes, a WebAuthn credential and
an activation token on that same entry. So the job enrols an authenticator, and
then requires that the secret is nowhere in the HTML. **Claims 1 to 4 all pass
against the dump-the-entry implementation. Only that one fails.**

**ITS FIRST VERSION PASSED FOR THE WRONG REASON**, which is the part to
remember: it STARTED an enrolment rather than confirming one, and a started
enrolment is held in memory and writes nothing — so the assertion ran against
an entry with nothing on it to leak, and the mutation it exists to catch
survived. It now confirms the enrolment and asks `/admin-api` whether the
attribute is really there before asserting that it is not on the page. An
assertion that cannot fail is worse than none, and the way to find out is to
break the thing on purpose.

### The in-process file exists because two refusals are not reachable over HTTP

`rowFor()` refuses to return a password hash and refuses to return octets. The
page has a branch of its own that words those cells, so **the over-HTTP job
passes with the module's refusal deleted** — belt and braces, which is right for
a password hash and means the page cannot tell whether the module still
refuses. `tests/inetorgperson.js` pins it at the function.

That file also compares the two LDAP catalogues' RFC citations attribute by
attribute. It cannot check either against an RFC — nothing in that process can
reach one — so **it enforces agreement rather than correctness**, and the
correctness was established once by reading the documents. It found six wrong
citations in this repository on the day it was written.

## THE RECOVERY CODE PAIR, AND THE GAP IT RECORDS (2026-09-10)

The same split as the TOTP pair below, arrived at for a different reason, and
worth reading beside it.

| File | Where | What it can see |
|---|---|---|
| `tests/backup_codes.js` | in process, no port | the RULES, and since 2026-09-11 the REVERSAL of two of them — a set is generated when the person ASKS, shown once and stored (as scrypt hashes) only when they confirm, with nothing written before that and a shown code working NOWHERE until it is; confirming REPLACES; a set written by an older build still verifies and is reported as `legacy` rather than migrated; the two verification doors refuse in one order; a code is spent exactly once (a spend that fails to write REFUSING is the one branch not reached — below); and it is never a way in or the factor a sign-in demands |
| `tests/vendored/sts_portal_backup_codes.js` | over HTTP, `local: true` | the DOORS — the enrolment that issues a set, the page that shows it, the recovery screen, the spend, and A01 |

**THE FORCE IS DIFFERENT FROM TOTP'S.** There, the in-process file exists
because RFC 6238's vectors need a chosen instant no request may name. Here there
are no vectors at all — no specification defines a recovery code — so the
in-process file exists because two of its four claims reach INSIDE the
credential store: *issued once* means asserting that a second enrolment did not
rewrite an attribute, and what would have been rewritten is never on the wire.
**No endpoint in this service returns somebody's recovery codes** except their
own `/portal/mfa`, which is a property the over-HTTP job asserts rather than
works around: it reads the codes off the page, the way a person does.

### One claim is not tested and the test file records it

`verifyBackupCode()` REFUSES a code that verified when the spend will not write
— the opposite of what `verifyTotp()` does with its counter, because a one-time
code that cannot be counted is replayable for ninety seconds and a recovery code
that cannot be marked spent works for ever. Nothing reaches that branch, and
`tests/backup_codes.js`'s header says why at length: the store fails its read
and its write together (one `locateEntry()` behind both),
`credentials.setDirectory()` would install a half-broken table with no way to
put the real one back, and the remaining route needs an environment variable set
before `common/config.js` is first required — which another file in the same
process has already done.

**Exporting a hook table from `ldap/ldap_server.js` so that the branch could be
reached was considered and refused.** Production API whose only caller is a test
is worse than a written-down gap. What the file asserts instead is the property
the branch exists to protect — *no refusal, of any reason, ever spends a code* —
which is the half a future edit is likely to break.

## THE TOTP PAIR: WHY TWO FILES AND NOT ONE (2026-09-10)

RFC 6238 arrived with a test on each side of the line this file draws, and the
pair is the clearest example of it in the repository.

| File | Where | What it can see |
|---|---|---|
| `tests/totp.js` | in process, no port | the ARITHMETIC — RFC 4226 Appendix D and RFC 6238 Appendix B, the skew window, the accept-once rule, base32 |
| `tests/vendored/sts_portal_totp.js` | over HTTP, `local: true` | the DOORS — enrolment, that the sign-in screen demands the code unprompted, A01, the activation flow, the operator's reset |

**NEITHER IMPLIES THE OTHER AND THE SPLIT IS FORCED**, which is the part worth
knowing rather than the table.

The vectors are not reachable over HTTP. RFC 6238's Appendix B is a table of
(time, mode, code) and it needs a CHOSEN INSTANT — and this service will never
let a caller name the moment a code is computed at, because a verifier that took
the time from the request would be a verifier with no clock. Nothing over the
wire can ask *what would the code have been at 1970-01-01T00:00:59Z*, and
nothing should be able to.

And the doors are invisible to the in-process file. Every defect the second one
exists to catch — a screen that never asks for the code, a step id that is not
spent, a body parameter that lets somebody enrol for another person — passes the
first one perfectly.

### The over-HTTP job carries an implementation of its own, and checks it first

Thirty lines of RFC 4226 written for that file rather than required from
`common/totp.ts`. The reason is the only claim a person actually cares about:
that a THIRD PARTY holding the secret this service handed out can produce a code
this service accepts. A job that imported the service's own generator would
prove that a function agrees with itself.

**It is checked against RFC 6238 Appendix B before it is trusted**, in section 0,
because a test-side generator that agreed with a broken service would be worse
than no test at all. That is `tests/webauthn_cross_impl.js`'s arrangement: two
implementations written apart, each checked against the specification, then
checked against each other.

**The RFC's own errata matter here.** Appendix B's prose says one twenty-byte
ASCII seed for all three digests and the published values are only reproducible
with a seed as long as the digest (errata 2866). Both files apply it, and both
say so — a table used with the wrong seeds fails against a CORRECT
implementation, which is how a published vector set gets quietly abandoned.

### The assertion that means something is a TRANSITION, in both directions

*The code screen appeared* would pass on a service that always asked. So the job
asserts that a password ALONE stops working once an authenticator is enrolled
(section 2) and starts working again once an operator clears it (section 5) —
and the sign-in helper refuses BOTH ways round, so a caller that expected one
factor and met two fails just as loudly as the reverse.

## THE `dispatch` MODE CARRIES A THIRD AXIS SINCE 2026-09-12: THE SECRET STORE

`tests/tools/modes.sh` ran three modes that differed in what SHARES state
between processes. The `dispatch` mode now differs in one more thing, and it is
deliberate rather than incidental: **`STS_KEYS_SOURCE=persisted`**, which turns
the keystore on WITHOUT product mode (`tests/keystore.js` records that as the
reason that setting exists) — so the key-encryption key is really fetched, from
the **OpenBao container the stack brings up**, with a client certificate that
store issued and a policy that lets it read and not write.

**THE DATABASE PASSWORD COMES OUT OF THAT STORE IN EVERY MODE**, because the
compose files' connection strings no longer carry one at all. What is particular
to `dispatch` is the KEK, which needs a keystore to be on before anything reads
it.

**BOTH COMPOSE FILES GREW THE THREE SERVICES**, and the duplication is this
suite's existing bargain: `docker-compose-run-tests.yml` carries its own
postgres and its own sts for the same reason, and CI runs that file — a stack
without the store there would be a CI run that could not start the mode at all,
leaving the feature covered only on a developer's machine.

### What asserts what, which is the part worth keeping straight

* **`openbao/seed.js` proves the STORE's side on every start.** It logs in with
  the certificate it has just issued, reads the two secrets, attempts the write
  that must be refused, and fails the whole stack if it is accepted. A widened
  policy therefore stops the stack rather than reaching a report.
* **`tests/vendored/sts_secret_store.js` proves the SERVICE's side**, which is
  the half the seeder cannot see: a perfectly configured store says nothing
  about whether the service used it, and a service still reading a key file
  comes up exactly as green. It asserts against what the service reports about
  itself — the provider, the client-certificate authentication, that the
  connection string carries no password, and that neither secret appears in
  either report.
* **It SKIPS, naming what it saw, where there is no store**: a throwaway
  service started by `run-report.js` has no stack behind it, and asserting the
  vault provider there would be asserting the launcher's configuration rather
  than the service's behaviour.
* **AND IT HAS TWO GATES RATHER THAN ONE, WHICH COST TWO MODES BEFORE IT DID**
  (2026-09-12). The sentence above used to say the `memory` and `postgres`
  modes were skipped too, and that was half right: **the DATABASE PASSWORD
  comes out of the store in every mode**, because the compose file's connection
  string carries none at all, and only the **KEY-ENCRYPTION KEY** waits for the
  keystore to be on. Gating the whole file on *is anything coming from vault*
  therefore ran the key half in both of those modes and failed with `no key was
  read at all` about a service behaving exactly as the mode defines. The key
  half is gated on the report saying a key is present, the floor is per mode,
  and the run says which half it is doing.

## THE `cluster` MODE: TWO PRODUCTION NODES BEHIND A LOAD BALANCER (2026-09-14, issue #46)

**SINCE 2026-09-21 THE LOCAL MODES ARE `memory`, `single-node` AND `cluster`,
AND A BARE `./run-tests.sh` RUNS ALL THREE** (`tests/tools/modes.sh` argues
it). `single-node` is a production deployment on one node — product mode,
postgres, request workers — replacing the `product` and `dispatch` modes;
`cluster` is two such nodes, and it was a development-mode, one-process-per-node
fourth mode asked for by name until that day. Single-node and multi-node are
kept apart because they differ in too much to read one run's failure: the
thing under test here is BETWEEN containers, which is what `cluster/` exists
for.

**CI RUNS IT ON EVERY PUSH SINCE 2026-09-15**, as a `cluster` job of its own in
`.github/workflows/tests.yml` beside `tests` (which names
`--modes=memory,single-node`) and `coverage` — two production stacks in one
job would outrun its 120 minutes. Both run `./run-tests.sh`.
`teardown_bounds.js` holds each job to the same arithmetic.

**THE STACK** is an override layered over the mode's usual compose files and
read in no other mode, so `memory` and `single-node` start exactly the stacks
they would without it:

| | What it is |
|---|---|
| node A | the existing `sts` service, with `STS_CLUSTER_MODE=active-active` and `STS_CLUSTER_NODE_NAME=node-a` |
| node B | `sts2`, which `extends` node A — one definition, so nothing the override does not name can differ — started only once node A is HEALTHY, so a cold start's first key set is never a race the suite depends on |
| the store | ONE postgres and ONE OpenBao, shared; the key-encryption key comes out of OpenBao (`STS_KEYS_SOURCE=persisted`), without which active-active refuses to start (`STS-CLUSTER-0008`) |
| `sts-lb` | HAProxy (`haproxy:3.2.23-alpine`, pinned), `mode tcp`, round robin, **TLS passed through**, `send-proxy-v2` (below), on 8081, 8082, 389, 636, 88/tcp and 8444 (8443 and 9443 were there until 2026-09-16, when both listeners were deleted; mutual TLS rides 8081, which is why passthrough is still right), a TCP-connect health check on each. It owns every published port under the variables the service used to, so every address a launcher computes is the balancer's with no second set of names |
| the files | `tests/docker-compose-run-tests-cluster.yml` (over `docker-compose-run-tests.yml`, `./run-tests.sh`) and `tests/cluster/haproxy.cfg`. `tests/docker-compose-cluster.yml`, its twin for the removed `./local-run-tests.sh`, was deleted on 2026-09-21; the argument its header carried is in the live file's |

Both nodes are **product mode with request workers** (three protocol workers
and one surface worker each), by rcbj's decision on 2026-09-21 — they were
development mode, one process each, until then, partly because two nodes of
four processes had been killed for memory on this machine; if that recurs it is
a finding, not a reason to shrink the mode. Both get the launcher's per-run
product values (`sts2` extends `sts`), are on the balancer's
`global.publicBaseUrl` and with `sts-lb` in `tls.hostnames`, and identical in
every setting on `cluster/cluster.js`'s `AGREEMENT_SETTINGS` — a node that
differed would refuse to join, which is a stack that does not start rather than
a quiet difference. **`STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES` is not set**:
the gate has to pass with nothing accepted, and a node that refuses is a finding.

**WHAT A RESULT MEANS.** Red here and green in `single-node` is a CLUSTER
defect — something one node holds that the other cannot see, or two nodes
deciding one thing twice. The comparison is the point, and it is why a failure
in this mode is not triaged until the same job has been run in `single-node`
(it was `postgres` until 2026-09-21).

### A new connection per request, or the mode tests one node

The balancer picks a node per CONNECTION, and node's clients keep connections
alive — `fetch()` in its global dispatcher and, since node 19, `http.globalAgent`
too. **A job would then make every request on its first connection, and the mode
would report two nodes of which each job saw one**, green and meaningless. So in
this mode `run-report.js` preloads `tools/fresh-connections.js` into every
protocol job (`STS_TEST_FRESH_CONNECTIONS=1`, named by the mode): every `fetch()`
is dispatched with undici's `reset: true` and both global agents stop keeping
alive. A preload because most of the clients are in VENDORED files, which are
not edited here — `tools/attach-admin-token.js` is the precedent. What it cannot
reach is said here: **Chrome's own connections** (the browser jobs are balanced
per connection Chrome opens) and a socket that is one connection by definition
(an LDAP session).

**`tests/vendored/sts_cluster_alternation.js` IS WHAT WOULD GO RED IF EITHER
HALF STOPPED WORKING**, and it is first in `MANIFEST.js` for that reason. It asks
`GET /admin-api/cluster` — whose `status.self` is the answering node — through
`fetch()` and through `https.request()`, and in this mode asserts both nodes
answered each client, neither took under a quarter, and both are live members;
in every other mode it asserts one identity answered everything, so it runs in
all four. **Its first mutation run passed the `fetch()` half with keep-alive
back ON**: back-to-back requests let undici's pool open a second connection
before the first was idle, and two pooled connections on two nodes alternate
exactly like fresh ones. A twenty-millisecond pause between requests is what
makes a keeping-alive client reuse its connection and pin; with it, the mutant
(`STS_TEST_FRESH_CONNECTIONS=0`) fails three runs out of three and the real
thing alternates node-a, node-b for every request.

### Each node presents a leaf of its own, and Chrome pins keys

Both nodes serve one Root, Intermediate and Issuing CA and **different listener
keys** — a node's listener is the node's. The node-driven jobs never notice,
because `NODE_EXTRA_CA_CERTS` terminates at the shared Root whichever node's
bundle was fetched. The browser jobs would: `STS_SPKI_PIN` is a truststore of
one key, so every connection the balancer gave the other node would meet an
interstitial. `tools/trust.js`'s `readTrust()` therefore fetches the
certificate on fresh connections until it has seen a leaf per node, and hands
over every bundle and a comma-separated pin list, which is
`--ignore-certificate-errors-spki-list`'s own syntax; in every other mode it is
the one fetch it always was.

### What this mode does not cover

* **UDP 88.** HAProxy balances TCP; the KDC's datagram socket is node A's alone.
  The suite speaks Kerberos over MS-KKDCP and TCP.
* **Per-node sockets**: a realm's SPIFFE listeners bind addresses of their own,
  node B adds none, and they are node A's.
* **Anything that reaches a node AROUND the balancer.** PROXY protocol v2 is
  ON in this mode: HAProxy sends a header naming the real peer and both nodes
  run `global.proxyProtocol=v2` with the balancer's pinned address (`.30`) as
  their ONE trusted proxy — not the subnet, which would let any container on
  the network name its own client address. So a non-loopback connection to a
  node from anywhere else is refused, and the suite has no such client (the
  healthchecks are loopback, the remote PEP dials `sts-lb`).
  `STS_TEST_CLUSTER_PROXY_PROTOCOL=off ./run-tests.sh` runs the mode
  without it, which is how a PROXY-protocol failure is told from a cluster
  one. The rate limits needed no raising either way: the suite already came
  from ONE address (the runner's), and the budget is shared by both nodes
  (`cluster_counters.js`).
* **Failure, except the scheduler's.** Since 2026-09-22 (#49, D10) the
  mode ends by CRASHING a node: `run-tests.sh`'s `schedulerTakeover()` asks
  `tests/tools/scheduler-takeover.js` which node leads the scheduler, `docker
  kill`s that container, and the tool asserts through the balancer that the
  other node leads within the node lifetime and three ticks, runs a run queued
  then, and ran every slot of the session-expiry job once
  (`tests/report/cluster-99-scheduler-takeover.log`). It is LAST because it
  removes a node, the mode runs detached for it, and a `--keep-stack` stack is
  never crashed. The planned handover is `sts_scheduler.js`'s step-down, in
  every cluster run. Every other takeover and fail-stop is still verified by
  hand in `cluster/CLAUDE.md`.
* (It listed **workers inside a node, and product mode** here until
  2026-09-21; both are what each node runs now.)

### What its first runs found (2026-09-14)

**THE FIRST RUN FAILED 42 OF 58 PROTOCOL JOBS FOR ONE REASON**: a development
node with no request workers did not persist what it MINTED
(`persistence_minted.js`'s `enabled()` asked about several PROCESSES, not
several NODES), so a sign-in pending on one node was unknown to the other —
pinning every hop of the console sign-in to one node passed, alternating
failed with `STS-AUTHN-0003` — and nothing refused the configuration. Fixed the
same day, with `cluster.js` now refusing an explicit cluster mode with
`persistence.minted` off. **Before trusting a run, `GET /admin-api/persistence`
must report `status.minted.persisting: true` on both nodes.**

With that fixed, 17 jobs failed here and passed in `postgres` (whose own 8
failures came from test files older than the service they drive), from six
causes each measured rather than inferred where it says so: a realm created on
one node answering 404 on the other's first request (the realm middleware runs
before the barrier; 2 of 6 across nodes, 0 of 6 on one); the BBS key pair made
per node; three pending-enrolment stores in `common/credentials.ts` never
persisted; the audit read-back of a refused request; SAML IdP-initiated logout;
and throughput — a directory create through SCIM went from 16ms to ~500ms and
through `/admin-api` from 2.3ms to 190ms, so two bulk loads outran their
watchdog and their token. **Which jobs a timing cause catches differs run to
run**: the realm race caught six jobs in one pass and eight in the next. The
PROXY v2 pass changed no outcome that was not that race; a connection to a node
around the balancer was reset in 36ms and a loopback one served.

### And the image tag was the fourth thing a project name failed to scope

Building this mode in a second checkout while another session ran the suite
from the first found it: both launchers built and ran `rcbj/sts`, a tag is
machine-wide exactly as a `container_name` and a subnet are, and
`./run-tests.sh` builds once and `up`s each later mode from whatever the
tag points at by then. A named project (`STS_TEST_COMPOSE_PROJECT`,
`STS_DOCKER_TEST_PROJECT`) now builds and runs `rcbj/sts:<project>` and its
PEP and runner twins; `image: ${STS_IMAGE:-rcbj/sts}` in both compose files
keeps an unnamed run exactly as it was.

The service logs are `logs/00-mock-sts-service.log` (node A, the name every mode
uses), `logs/00-mock-sts-service-node-b.log` and `logs/00-load-balancer.log`.
`!reset` in the local override needs docker compose 2.24 or later.

## APPLICATION CREDENTIALS: THE PAIR, AND THE SPLIT (2026-09-13)

| File | Where | What it can see |
|---|---|---|
| `tests/application_credentials.js` | in process | the CHAIN RULES of an uploaded certificate — a private key refused, an incomplete chain (leaf alone; no root), an unrelated extra, an end-entity issuer, a pathLen broken, a CA as the leaf, an expired leaf, a short RSA key, Ed25519 and secp256k1 accepted for BOTH profiles since the #37 follow-up (the XML Signature verifier takes them now), a full chain accepted root-first and stored in path order with its root, this realm's own leaf accepted alone, ANOTHER realm's leaf refused with its branch — then the action writing over an issued pair (its private key gone, the provenance set), the view's JSON carrying no secret or private key, the provenance vocabulary, and the client secret: never quoted by the generic Set, regenerated off the audit log, refused for a pinned `sts-management-api` |
| `tests/vendored/sts_application_credentials.js` | over HTTP, `local: true` | the FEATURE — an issued key pair signs an accepted JWT bearer grant; after an external certificate is uploaded the OLD key is refused `invalid_grant` and the application's OWN ES256 key is accepted; refused uploads change nothing; this realm's certificate uploaded alone; a regenerated secret handed back once, absent from `/admin-api/audit`, and — with RFC 9700 mode on in that realm — the old secret refused `invalid_client` and the new one accepted |

**The in-process half builds hierarchies nobody would deploy**, which is why it
is in process: each one over HTTP would be the test building a CA in a JSON
body. **Two mutants survived its first version** and both are recorded: a
private-key write of `undefined` is EQUIVALENT (it clears exactly as `''` does),
replaced by the real mutant — the upload skipping that write — which is caught;
and the secp256k1-for-SAML refusal had no case until one was added.

**`sts_admin_console.js` presses the three controls in a browser**
(`theCredentialsSectionIsPressed()`), because two of them post to `/admin/pki`
and come back through `from`, which neither file above can see: it asserts the
browser LANDED on this application's section in this realm, not only that the
entry changed. Mutation-tested by making `pkiReturnTo()` always answer
`/admin/pki` — caught — and that run found `notice=undefined`: every PKI
success carries its sentence as `why`, which `respondToAction()` never read,
invisible on `/admin/pki` (it draws no notice) and visible on the application
page (it does). The route maps `why` to `message` now, and the job asserts the
notice.

## PERSON CREDENTIALS: THE PAIR (2026-09-13)

| File | Where | What it can see |
|---|---|---|
| `tests/person_credentials.js` | in process | a person's RFC 7522 key pair on `stsSamlAssertion*` with the JWT set untouched; `issuerFor()` finding a person under the profile they hold a key pair for and not the other; the SAML grant accepting a person's assertion about themselves (`issuerKind: person`) and refusing their key naming somebody else (`STS-OAUTH-0242`) and their JWT key signing SAML; an external chain replacing a person's key pair (the issued private key gone, the old key refused, the held key accepted) and a JWT upload used by the JWT grant, still self-only; a realm leaf issued to an application or another person refused for a person, a person's own accepted alone, a person's leaf refused for an application (`STS-PKI-0155`); the self-signed refusal naming no by-value attribute; the page's model carrying no private key while one is held; `userReturnTo()` rebuilding the address; one profile taken off leaving the other; the two retired codes |
| `tests/vendored/sts_user_credentials.js` | over HTTP, `local: true` | the same at `/oauth2/token` through `/admin-api/pki/{issue,upload-certificate,revoke}` with `target=person` and `GET /admin-api/users?user=`'s `credentials` |

**Fourteen in-process mutants, all caught — two only after the fixture was
fixed**: a write that never wrote the private key passed because nothing asserted
the issued key WAS on the entry before an upload "removed" it, and a view leaking
the private key passed because the only leak check ran when no key was held. Four
HTTP mutants were run with the hook preloaded into the throwaway service through
`NODE_OPTIONS`, all caught. **And the first run of the HTTP pair found a real
over-reach**: the subject rule refused one application's realm certificate for
another, which `sts_application_credentials.js` and the console job do on purpose;
the rule was narrowed to the two registrations that widen a key holder.
`sts_admin_console.js`'s `thePersonCredentialsSectionIsPressed()` is the browser
half.

**Both credentials files put the certificate authority back the way they found
it** (`restoreAuthority()`): a service Root either one built was the Root
`tests/pki.js` met next, so its "the Root carries the organisation it was asked
for" failed in the suite and passed alone. Mutation-tested by deleting the Root
removal — caught. **Since 2026-09-14 `certificate_details.js` and
`crl_directory_publication.js` carry the same pair**, and it was NOT enough:
once any file has armed `pki.js`'s realm watcher, every realm a later file
creates builds a service Root in the background (`oauth21_mode.js` did it in a
full run, and passes beside `pki.js` alone). **So `pki.js` sets aside a Root it
did not build before asserting about the one it builds** — the fix is where the
assertion is, not in every file that creates a realm. Mutation-tested through a
require hook with `assertion_grant,oauth21_mode,pki`: without the set-aside that
chain fails the assertion, with it the chain passes.

**`sts_portal_signing_key.js` covers the portal's RFC 7522 card** (section 8,
2026-09-13): issued, used at the SAML grant, refused about somebody else,
neither key signing for the other profile, taken off alone. Its "the other
person holds nothing" check reads the Credentials section's `held` flags now;
it searched the reply for `stsassertionjwks`, which the section prints as an
attribute NAME whether or not anything is held.

## THE THIRD-PARTY CORPORA ARE ONE PRIVATE IMAGE ON GHCR.IO (#253, 2026-09-26)

The schemas (#188), x509-limbo and NIST PKITS (#201), the W3C XML Signature
and Encryption interop cases (#193) and Wycheproof with NIST ACVP (#202,
#203) are no longer fetched by `tests/Dockerfile`. They sat below the package
files, `node-ldapjs` and both npm installs, so nearly every build re-fetched
all of them — about 340 paced requests to w3.org alone — and on 2026-09-26
w3.org answered 429 for an hour and no run could start.

* **`tests/corpora/Dockerfile`** fetches them with the same five scripts and
  the same sha256 checks into a `scratch` image. **`tests/tools/build-corpora-image.sh`**
  builds it, pushes `ghcr.io/rcbj/iya-sts-test-corpora:<date>-<commit>`, and
  rewrites the `ARG STS_CORPORA_IMAGE=` line at the top of `tests/Dockerfile`
  to the REGISTRY DIGEST it got back. Run it after any change to a fetch
  script, `w3c-xmlsec.sha256`, `vectors.sha256` or `tests/xml-schemas`, and
  commit the rewritten line; until then the tests image reads the old digest.
* **`tests/Dockerfile` pins that digest** and `COPY --from`s the five trees to
  the paths they always had, so no test and no `STS_*_DIR` changed.
* **PRIVATE, and it stays so** (rcbj): the W3C and PKI corpora carry published
  test private keys. Pulling needs `docker login ghcr.io` with
  `read:packages` — `gh auth token | docker login ghcr.io -u <user>
  --password-stdin`. **`tests/tools/corpora-preflight.sh`** asks first in
  `./run-tests.sh`, `./docker-npm-test.sh` and `deploy/aws/run-suite.sh`, and
  says so in a sentence rather than as a pull error. CI logs in with
  `GITHUB_TOKEN` under `packages: read` (`tests.yml`, `aws-cluster.yml`), and
  the package grants this repository access.
