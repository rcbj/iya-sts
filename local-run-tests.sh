#!/bin/bash
#
# local-run-tests.sh — run this repository's tests, on this machine.
#
# It is this project's answer to ../id-proto-debugger/local-run-tests.sh, and it
# is a great deal shorter than that one for a reason worth knowing before
# reaching for a feature from over there: that script has to BUILD and PROVISION
# a whole stack — Keycloak realms, two walt.id services, a WildFly side-car,
# browser bundles, an extension — because the tests it runs drive a browser
# against all of it. Here there is ONE container and it is this service.
#
# The tests are in two halves and only the FIRST needs nothing at all: the
# in-process suite in tests/ asserts this repository's own module contracts and
# needs `npm install` and no more — no port, no container, no browser, no
# network. The second half is the parent project's protocol jobs, driven over
# HTTP against a RUNNING copy of this service, and one of those drives a
# browser. See tests/CLAUDE.md for where the line between the halves is and
# what belongs on each side of it.
#
# ---------------------------------------------------------------------------
# THE SERVICE THE PROTOCOL JOBS DRIVE IS A CONTAINER SINCE 2026-08-28, BROUGHT
# UP FROM THIS REPOSITORY'S OWN docker-compose.yml.
#
# It used to be a throwaway `node server.js` started on nine ports of its own,
# and that still exists behind `--no-docker`. What the container buys is that
# THE THING UNDER TEST IS THE IMAGE: the same Dockerfile, the same
# `npm install --omit=dev` against the committed lock, the same node version,
# the same `COPY . ./` with .dockerignore deciding what is in it. Several of
# the failures this repository has actually had are properties of the image and
# not of the source — an uninitialised nested submodule that installs a package
# with no `main`, a module that is present in the tree and excluded from the
# build context, a devDependency that .npmrc's `omit=dev` quietly did not
# install — and every one of them is invisible to a suite that runs the source
# out of a developer's own node_modules. The container is also how the run
# stops depending on which node happens to be on the PATH.
#
# THE TESTS THEMSELVES ARE STILL PLAIN SCRIPTS ON THIS MACHINE. Nothing is
# containerized but the service. They are node processes started by
# tests/tools/run-report.js with this repository as their cwd, which is what
# keeps the loop short (edit a test, re-run it, no image), what lets the five
# jobs that load this service's modules IN PROCESS keep doing so, and what lets
# the browser job drive the Chrome that is already installed here.
#
# FOUR THINGS ABOUT THE STACK ARE DECISIONS RATHER THAN MECHANICS:
#
#   IT IS ITS OWN COMPOSE PROJECT, ON ITS OWN PORT, UNDER ITS OWN CONTAINER
#   NAMES. `docker compose up` in this directory gives you `sts` on 8081, and
#   that is somebody's dev stack — very likely the same person's, in another
#   terminal. A test run that took that name would refuse to start while it was
#   held, and a test run that took that PORT would fail to bind; worse, the
#   teardown at the end of this script would remove the container somebody was
#   using. So the run is `mock-sts-tests`, the container is `sts-tests`, and the
#   host port is a FREE one found at start rather than a fixed number.
#
#   IT PERSISTS NOTHING. `STS_PERSISTENCE_MODE=memory`, and `--no-deps` so the
#   postgres service in that file is never started. A suite that persisted
#   would be a suite whose second run started from the first run's leavings,
#   which is the failure that looks like a flaky test and is not one.
#
#   THE IMAGE IS REBUILT EVERY RUN, because the whole point is to test what is
#   in the working tree, and an image is a snapshot of when it was built. That
#   is the run's largest fixed cost after the browser job, and `--no-build` is
#   there for the loop where nothing in the service changed — it says out loud
#   that the image may be older than the tree, because a stale service that
#   answers every request has already cost this project a page of false passes.
#
#   A STACK THAT WILL NOT COME UP IS A FAILED RUN, not a skip and not a quiet
#   fallback to running the service on the host. Which of those it is matters:
#   a run that silently ran the source instead of the image is a run whose
#   green does not mean what the last three paragraphs say it means. The one
#   exception is a machine with NO DOCKER AT ALL, where this falls back to the
#   in-process service and says so in three lines — because there the choice is
#   between the old suite and no suite. Passing `--docker` makes even that an
#   error.
#
#   AND THE STACK IS LEFT UP WHEN THE RUN FINISHES, SINCE 2026-09-01. That
#   reverses this script's default and it is the one decision here that is
#   about a PERSON rather than about what is under test: almost everything a
#   run tells you that the report does not is read off the service itself —
#   /admin/delegation/allowed after the delegated permission example built it,
#   /admin/sts-metadata after a drift failure, an entry on /admin/applications
#   that a job says is wrong — and a container torn down at the last line of
#   the run is a container that is gone by the time the report says to look at
#   it. Re-running the whole suite to see one page is a minute for a question
#   that is already answered somewhere.
#
#   Three things make it affordable and it would not be a good default without
#   them. startStack() ALREADY brings its project down before bringing it up,
#   so a leftover container is removed by the next run rather than met by it —
#   that has been true since this stack was written, for the interrupted-run
#   case. The project, the container name and the host port are this run's own,
#   so what is left behind can never be somebody's dev stack. And nothing is
#   persisted, so a container left up all week holds only what the run put in
#   it.
#
#   What it costs is a container and a network on this machine until the next
#   run or a `--tear-down`, which the last lines of a run print the command
#   for. NOTHING IN CI IS AFFECTED: the workflow runs ./docker-run-tests.sh and
#   ./run-coverage.sh, neither of which goes through this script's stack —
#   the first tears its own compose project down with `--exit-code-from`, and a
#   coverage run never brings the `sts` container up at all. `--tear-down` is
#   there for a person who wants the old behaviour anyway.
# ---------------------------------------------------------------------------
#
# What this adds over `npm test` is a REPORT — tests/report/<mode>/<timestamp>/
# with report.html, JUnit report.xml and one log per test file — and the OTHER
# half of this service's coverage:
#
# TWO OF THE FILES IN THAT logs/ DIRECTORY ARE THIS SCRIPT'S RATHER THAN THE
# RUNNER'S, and both are things that are gone by the time somebody reads a
# report:
#
#   logs/00-mock-sts-service.log   the container's own account of what the mock
#                                  issued, taken before the teardown removes it
#   logs/00-test-runner.log        THE RUNNER'S OWN OUTPUT — which jobs it
#                                  chose, the ones it could not start and why,
#                                  the reason a job was reported SKIPPED, the
#                                  summary. A job that never started has no
#                                  per-job log, so this is the only place what
#                                  happened to it is written down. Tee'd, so
#                                  the terminal still shows everything it
#                                  always did
#
# Where a report could not be written — a run that died bringing the service up
# — they go to tests/report/<mode>-00-*.log instead, which is precisely when
# they are the only evidence there is.
#
#   THE PROTOCOL JOBS, AGAINST THIS WORKING TREE. Fourteen jobs that drive a
#   RUNNING service over HTTP — the Selenium admin-console job among them.
#   This builds an image from this tree, brings up one container from
#   docker-compose.yml, runs them against it, and LEAVES IT UP (--tear-down
#   removes it; see AND THE STACK IS LEFT UP above).
#
# THE SUITE IS SELF-CONTAINED AS OF 2026-08-28, AND THAT WAS UNTRUE THE DAY
# BEFORE.
#
# Those thirteen jobs used to be READ OUT OF the parent project's tests/ — the
# decision the root CLAUDE.md argues — so this script could only run them on a
# machine that had both checkouts, and a machine with only this repository on
# it silently ran ten in-process files instead. They are under tests/vendored/
# now — nine byte-identical copies plus the four this repository OWNS, with
# tests/vendored/MANIFEST.js recording where each came from, which are jobs,
# and which four have no upstream at all. Nothing in a test run reaches outside
# this checkout any more.
#
# AND THEY RUN BY DEFAULT, which reverses what this script did for its first
# three days. They used to need `--protocol`, so the bare run was ten files in
# about three seconds — which says "Tests passed" having driven no protocol
# endpoint, no admin console and no browser at all. A default that hides
# thirteen of twenty-three jobs behind a flag is a default that gets trusted
# wrongly. The whole set is what you get; it takes about a minute, most of it
# the browser job.
#
# A JOB THAT CANNOT RUN IS REPORTED AS A FAILURE, not a skip. The throwaway
# service failing to start used to leave thirteen jobs marked `skipped`, which
# the summary counts as passing — so a run in which nothing was checked exited
# zero and said so in small grey text.
#
# THE PARENT IS STILL THE SOURCE OF TRUTH FOR NINE OF THE THIRTEEN. Those are
# not edited here — the rule `common/vendored/` carries. Fix the parent's copy,
# then `--vendor-sync`. `--vendor-check` reports drift and needs both checkouts.
#
# THE OTHER FOUR ARE OURS AND THE RULE IS INVERTED. sts_metadata.js,
# admin_api.js, sts_admin_api_operations.js and sts_admin_console.js drive this
# service's own /admin console and /admin-api. They left the parent's suite on
# 2026-08-28 — a test of this console belongs in the tree where a control is
# added to it — so there is nothing over there to sync from. MANIFEST.js marks
# them `local: true`, which keeps them out of both the check and the sync, and
# they are edited HERE.
#
# Options:
#   --only=<substr>[,<substr>...]
#                    Only the test files (and protocol jobs) whose name
#                    contains one of these. A bare word means the same.
#   --modes=<mode>[,<mode>...]
#                    Which of the three configurations in tests/tools/modes.sh
#                    to run the whole suite in. The default is ALL THREE, which
#                    is what a green run is supposed to mean — and what makes a
#                    bare run take about an hour rather than about ten minutes.
#                    `--modes=memory` is the development loop: the baseline
#                    configuration, no database, no request workers. Narrowing
#                    the modes narrows what the run says, exactly as --only
#                    narrows the jobs — a pass in `memory` alone says nothing
#                    about persistence or dispatch, which is the whole reason
#                    the other two exist.
#   --list           Name what would run, and run none of it.
#   --protocol       Run the parent project's mock-only jobs as well. The
#                    DEFAULT since 2026-08-28; the flag is kept because
#                    scripts and fingers still pass it.
#   --no-protocol    Leave them out: the in-process suite only, three seconds,
#                    and nothing said about any protocol surface or /admin.
#   --unit-only      The same as --no-protocol.
#   --no-browser     Leave out the jobs that drive a browser. One does:
#                    tests/sts_admin_console.js, which is the admin console's
#                    only coverage against this working tree — so a run with
#                    this flag says nothing about /admin. Browser jobs are run
#                    one at a time like everything else here; this runner is
#                    serial, so there is never a second Chrome open.
#   --protocol-only  Run only those.
#   --no-docker      Run the service the OLD way: a throwaway `node server.js`
#   --host-service   started by tests/tools/service.js on nine ports of its
#                    own, out of this working tree and this machine's
#                    node_modules. Faster by however long an image build takes,
#                    and blind to everything about the image — see the section
#                    above. Passed on to --coverage, which has the same two
#                    modes: a coverage run never drives the `sts` container
#                    (V8 collects from inside the process it measures), but it
#                    runs in one of its own by default.
#   --docker         The default, spelt. What it adds is that a missing or
#                    broken docker is then an ERROR rather than a fall back to
#                    --no-docker: pass it in CI, where a silent change of what
#                    was under test is worse than a red run.
#   --no-build       Do not rebuild the image before starting the container.
#                    The image may then be OLDER than this working tree, which
#                    this says out loud every time, because a service that
#                    answers every request while being a week old is the most
#                    expensive kind of green there is.
#   --keep-stack     THE DEFAULT SINCE 2026-09-01, and this flag is now the
#                    way to SPELL it rather than the way to ask for it. The
#                    container is left running when the run finishes and this
#                    script prints how to reach it and how to stop it — for
#                    reading /admin, or re-running one job by hand against the
#                    same service. See AND THE STACK IS LEFT UP above.
#   --tear-down      The old default: take the container down when the run
#   --no-keep-stack  finishes. For a machine where a container left running is
#                    a container somebody will trip over. CI does not need it —
#                    it runs ./docker-run-tests.sh, which tears its own down.
#   --sts-port=N     Publish the container's 8081 on this host port instead of
#                    a free one chosen at start. Only useful when something
#                    outside this run has to reach the service at a known
#                    address.
#   --vendor-check   Compare tests/vendored/ against the parent checkout and
#                    report drift; run nothing else. Needs both checkouts, and
#                    says so and exits 0 when there is no parent beside this
#                    one, because the suite does not need one.
#   --vendor-sync    Re-copy the parent's files over tests/vendored/, then run
#                    nothing else. The ONLY sanctioned way those files change.
#   --parent=<dir>   Where the parent project is, for the two commands above.
#                    Default: the sibling ../id-proto-debugger, then
#                    ../oauth2-oidc-debugger. It no longer affects a test run.
#   --coverage       Hand over to ./run-coverage.sh, passing everything else on
#                    — including --no-docker / --docker / --no-build when they
#                    were asked for. That script runs the whole instrumented
#                    suite in a container of its own by default.
#   --no-report      Plain `npm test`: one process, bunyan on the terminal, no
#                    report written. The fastest loop there is. It runs the
#                    in-process suite only — starting and stopping a service is
#                    the report runner's work — so it implies --no-protocol
#                    rather than refusing, and says so as it goes.
#   --log-level=L    LOG_LEVEL for the tests (trace|debug|info|warn|error|fatal).
#   --sts-log-level=L
#                    The log level of the service the protocol jobs drive — the
#                    container or, under --no-docker, the in-process copy; it
#                    reaches both. DEFAULT `info`, which is this script's and
#                    not the service's: run by hand it still logs at `debug` —
#                    every request and every signed artifact written down,
#                    which is what a failing protocol job is read from, and
#                    about half of its CPU. --sts-log-level=debug asks for that
#                    whole record back, and gets it: the level picks the
#                    appconfig file (env/local.js or env/test.js) as well as
#                    STS_LOG_LEVEL, because the vendored crypto modules read
#                    only the file. See THE SERVICE'S LOG LEVEL below.
#   --timeout=MS     Per-job watchdog. Default 300000. 0 disables it.
#   --quiet          Do not echo each job's output as it runs; the logs still
#                    have all of it.
#   --open           Open the report when it has been written. With more than
#                    one mode that is the LAST mode's, which is the one whose
#                    stack is left standing.
#   --verbose        set -x, for debugging this script.
#   -h|--help        This.
#
# Exit code is the suite's: non-zero if anything failed.
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

# ---------------------------------------------------------------------------
# THE MODE MATRIX. `tests/tools/modes.sh` is the one definition of what the
# three configurations are, shared with ./docker-run-tests.sh so the two
# launchers cannot come to disagree about what a green run covers.
# ---------------------------------------------------------------------------
# shellcheck source=tests/tools/modes.sh
. "${CURRENT_DIR}/tests/tools/modes.sh"
RUN_MODES=("${STS_ALL_MODES[@]}")

ONLY=""
LIST=0
PROTOCOL="on"
PROTOCOL_ASKED=0
PARENT=""
VENDOR=""
COVERAGE=0
NO_REPORT=0
LOG_LEVEL_ARG=""
STS_LOG_LEVEL_ARG=""
TIMEOUT_ARG=""
QUIET=0
BROWSER=1
OPEN=0
PASSTHROUGH=()

# ---------------------------------------------------------------------------
# THE CONTAINER. Every one of these is either a name that must not collide with
# a dev stack or a value docker-compose.yml substitutes; the header argues each.
#
# SERVICE is `docker` or `host`, and SERVICE_ASKED separates "the default" from
# "somebody asked for this" — the same distinction --no-report/--protocol
# already make below, and for the same reason: a default may fall back with a
# warning, an explicit request must fail instead.
# ---------------------------------------------------------------------------
SERVICE="docker"
SERVICE_ASKED=0
BUILD=1
# LEFT UP WHEN THE RUN FINISHES, since 2026-09-01. See AND THE STACK IS LEFT UP
# in the header for the argument; --tear-down is the way back to what this was.
KEEP_STACK=1
STS_PORT_ARG=""
COMPOSE_FILE="docker-compose.yml"
# ---------------------------------------------------------------------------
# AND A SECOND COMPOSE FILE, LAYERED OVER IT, THAT PUBLISHES THE DIRECTORY'S
# OWN SOCKET (2026-09-06).
#
# `tests/vendored/sts_directory_bulk_load_ldap.js` writes five thousand people
# over RFC 4511 on TCP 389. In THIS stack the jobs are host processes and the
# service is a container, so that socket has to be published — and
# docker-compose.yml deliberately does not publish it, because 389 is the
# assigned LDAP port and the host most likely to want a mock directory is a
# host already running slapd. An override is the only way to give one stack a
# published port and leave the operator's `docker compose up` untouched; that
# file's own header argues it.
#
# ./docker-run-tests.sh needs none of this: over there the runner is a
# container on the bridge with the service and reaches ldap://sts:389 with
# nothing published at all.
LDAP_COMPOSE_FILE="tests/docker-compose-ldap.yml"
# Every compose invocation in this file goes through this array rather than
# naming -f twice in seven places — which is how one of the seven eventually
# gets the layer and the other six do not, and the symptom is a stack that
# comes up without the port on exactly the code path nobody tested.
COMPOSE_FILE_ARGS=(-f "${COMPOSE_FILE}" -f "${LDAP_COMPOSE_FILE}")
# Chosen at run time like the other two, so that two runs on one machine do not
# collide with each other and neither collides with a real directory on 389.
STS_LDAP_HOST_PORT=""
# The plain-HTTP revocation listener's host port (2026-09-13), for the same two
# reasons. See composeUp().
STS_PKI_HOST_PORT=""
# Overridable so that two runs on one machine (a CI agent with two workspaces)
# do not share a project — compose scopes containers, networks and volumes by
# it, so two runs sharing one would tear down each other's stack.
COMPOSE_PROJECT="${STS_TEST_COMPOSE_PROJECT:-mock-sts-tests}"
# Every `down` in this file runs under it — see stackTeardown(). Seconds,
# and overridable, exactly as in ./docker-run-tests.sh.
STS_TEARDOWN_TIMEOUT="${STS_TEARDOWN_TIMEOUT:-300}"
STS_TEST_CONTAINER="sts-tests"
STS_TEST_PG_CONTAINER="sts-tests-postgres"
# THE SECRET STORE AND ITS TWO ONE-SHOT CONTAINERS (2026-09-12). Named here for
# the reason the block below gives about the other two: `container_name` is
# machine-wide, so a second run in this tree would take the first run's store —
# and this one holds the key-encryption key every mode's data is sealed under.
STS_TEST_BAO_CONTAINER="sts-tests-openbao"
STS_TEST_BAO_TLS_CONTAINER="sts-tests-openbao-tls"
STS_TEST_BAO_SEED_CONTAINER="sts-tests-openbao-seed"
# ---------------------------------------------------------------------------
# NAMING A PROJECT MUST ISOLATE THE WHOLE RUN, AND UNTIL 2026-09-07 IT DID NOT.
#
# `STS_TEST_COMPOSE_PROJECT` scoped the compose PROJECT and left the three
# container names hard-coded above — and `container_name` is machine-wide, not
# project-scoped, which docker-compose.yml says in as many words. So a second
# run on this machine took the first run's containers whatever project it was
# given: compose saw a container by that name, recreated it, and the run already
# using it started answering ECONNREFUSED half way through.
#
# **THAT IS NOT HYPOTHETICAL — IT HAPPENED THREE TIMES IN ONE DAY**, and each
# time it read as a broad, alarming test failure rather than as two runs sharing
# a name: jobs 1-46 pass, then everything after the moment the other run brought
# the stack up fails on a closed socket.
#
# The defaults are untouched, so a plain run is exactly what it was and every
# reference to `sts-tests` still finds it. Naming a project now also names the
# containers, which is what makes two runs on one machine actually possible:
#
#   STS_TEST_COMPOSE_PROJECT=mine ./local-run-tests.sh
#
# **AND THE NETWORK WAS THE THIRD THING TO ESCAPE THIS, ON 2026-09-12.** A
# subnet arrived in docker-compose.yml as a literal, because a realm's SPIFFE
# listeners need addresses that do not move between starts — and an address
# space is machine-wide in the same way a `container_name` is. The second run
# in this tree was then refused outright, with `invalid pool request: Pool
# overlaps with other one on this address space` and nothing brought up. It is
# chosen per run now, in composeUp() beside the three ports; the same sentence
# reaching one more thing.
# ---------------------------------------------------------------------------
if [ -n "${STS_TEST_COMPOSE_PROJECT:-}" ];
then
  STS_TEST_CONTAINER="${COMPOSE_PROJECT}-sts"
  STS_TEST_PG_CONTAINER="${COMPOSE_PROJECT}-postgres"
  STS_TEST_BAO_CONTAINER="${COMPOSE_PROJECT}-openbao"
  STS_TEST_BAO_TLS_CONTAINER="${COMPOSE_PROJECT}-openbao-tls"
  STS_TEST_BAO_SEED_CONTAINER="${COMPOSE_PROJECT}-openbao-seed"
fi
# ---------------------------------------------------------------------------
# THE REMOTE XACML PEP THIS STACK ALSO BRINGS UP (2026-09-06).
#
# `tests/vendored/sts_xacml_remote_pep.js` drives a SECOND CONTAINER — the
# remote Policy Enforcement Point in xacml-pep/ — on the same network as the
# service, and asserts that policy deployed through /admin-api reaches it and
# changes what it allows. It cannot be asserted any other way: the whole point
# of that component is that it holds its own copy of the engine in another
# process, and the interesting states (converging by poll, a nudge arriving
# over the bridge, a PDP that has gone away) only exist between two containers.
#
# THE LAUNCHER OWNS IT RATHER THAN THE JOB, for the reason ./docker-run-tests.sh
# has no choice about: over there the suite runs INSIDE a container with no
# docker in it, so a job that started its own could never run in CI. One
# arrangement for both launchers is worth more than a shorter one here.
#
# THE REALM IS FIXED AND THE JOB OWNS IT. That container is pointed at
# /realm/${XACML_PEP_REALM} before the realm exists; the job creates it, works
# in it, and removes it at the end (its last section is a PDP outage made that
# way). The PEP retries its registration on the poll timer, so it converges on
# a console row once the realm appears — see xacml-pep/sync.js.
# ---------------------------------------------------------------------------
XACML_PEP_CONTAINER="xacml-pep-tests"
# Isolated with the other two — see the block above them.
if [ -n "${STS_TEST_COMPOSE_PROJECT:-}" ];
then
  XACML_PEP_CONTAINER="${COMPOSE_PROJECT}-xacml-pep"
fi
XACML_PEP_REALM="${XACML_PEP_REALM:-pep-e2e}"
# **THE REGISTERED NAME IS THE CERTIFICATE'S COMMON NAME AND NOT THIS**, since
# the endpoints were gated. `xacml.js` names a registration from the client
# certificate and ignores anything the body or the environment says, because a
# PEP that could name itself while holding a certificate could take over
# another PEP's row — which is the one thing in this family that would be a
# security bug rather than a fidelity one. So this is DERIVED from the subject
# below rather than set beside it: `sync.js` sends `?pep=<PEP_NAME>` on every
# pull to move its own lastSeen, and a name that differed from the row's would
# leave a registered PEP that no pull ever touched.
XACML_PEP_NAME=""
XACML_PEP_HOST_PORT=""
# Its HTTPS listener's published port (2026-09-13), picked beside the one above.
XACML_PEP_HTTPS_HOST_PORT=""
# ---------------------------------------------------------------------------
# THE PEP'S CLIENT CERTIFICATE (2026-09-06).
#
# The three /xacml/pep endpoints are gated: a remote PEP is admitted by a
# client certificate the service VERIFIES, whose subject DN resolves to a
# directory entry in the `remote-peps` group, which grants the built-in
# REMOTE_PEPS role. Nothing in the mock or in the PEP image provides that
# certificate — this launcher mints one with tests/tools/pep-credential.js,
# which builds a Root CA, an Issuing CA and a client leaf on the vendored PKI
# engine and POSTs the root to /tls/trust.
#
# THE COMMON NAME IS `remote-pep-1` BECAUSE THAT IS THE SEEDED IDENTITY. Every
# realm's directory carries `cn=remote-pep-1,ou=users,…` and a `cn=remote-peps`
# group holding it, so the ordinary path needs no directory editing. A
# different name mints a certificate that VERIFIES and is refused, which is a
# thing the suite asserts on purpose.
XACML_PEP_SUBJECT="${XACML_PEP_SUBJECT:-CN=remote-pep-1,OU=remote-peps,O=mock-sts}"
XACML_PEP_CERT_DIR=""
# The common name out of that subject, which is what the PDP will file the
# registration under. `sed` rather than a shell parameter expansion because the
# CN is not always first and a DN may carry spaces.
XACML_PEP_NAME="$(printf '%s' "${XACML_PEP_SUBJECT}" \
  | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
if [ -z "${XACML_PEP_NAME}" ];
then
  echo "XACML_PEP_SUBJECT (${XACML_PEP_SUBJECT}) names no CN, and the CN is" >&2
  echo "what the mock files a PEP registration under. Nothing would find it." >&2
  exit 1
fi
# The appconfig layer the SERVICE reads — the container, and since the log
# level below became a default of this script, the --no-docker copy too.
#
# EMPTY here on purpose and resolved after the arguments have been parsed, by
# THE SERVICE'S LOG LEVEL further down: which of env/local.js and env/test.js
# this run wants is decided by the level, because those two files differ in
# nothing else. Set STS_TEST_CONFIG_FILE in the environment to pin a file and
# that block leaves it alone.
#
# `CONFIG_FILE` itself is deliberately never exported into this shell: it is a
# variable the in-process tests read too, and one exported here would reach
# every unit job as well as compose. This one carries its own name for exactly
# that reason, and run-report.js reads it under that name for the host-mode
# service.
STS_TEST_CONFIG_FILE="${STS_TEST_CONFIG_FILE:-}"
# Filled in by the lifecycle below. STACK_UP gates the teardown, so that a run
# that never started a container cannot tear down somebody else's.
STACK_UP=0
STS_URL=""
STS_HOST_PORT=""
COMPOSE_CMD=""
DOCKER_SUDO=""
COMPOSE_ENV=()

# The header of this file IS the usage, printed by reading it back rather than
# by keeping a second copy of it in a here-document — which is the only way the
# two cannot drift apart.
usage()
{
  awk 'NR > 1 { if ($0 !~ /^#/) { exit } sub(/^# ?/, ""); print }' "$0"
}

while [ $# -gt 0 ];
do
  case "$1" in
    --only=*)          ONLY="${1#--only=}"; PASSTHROUGH+=("$1") ;;
    # WHICH MODES TO RUN. The default is all three; this is for narrowing a
    # loop while working on one of them, exactly as --only narrows the jobs.
    --modes=*)         IFS=',' read -r -a RUN_MODES <<< "${1#--modes=}" ;;
    --list)            LIST=1; PASSTHROUGH+=("$1") ;;
    --protocol)        PROTOCOL="on"; PROTOCOL_ASKED=1 ;;
    --protocol-only)   PROTOCOL="only"; PROTOCOL_ASKED=1 ;;
    --no-protocol)     PROTOCOL="off" ;;
    --unit-only)       PROTOCOL="off" ;;
    --parent=*)        PARENT="${1#--parent=}" ;;
    --vendor-check)    VENDOR="check" ;;
    --vendor-sync)     VENDOR="sync" ;;
    --coverage)        COVERAGE=1 ;;
    --no-report)       NO_REPORT=1 ;;
    --log-level=*)     LOG_LEVEL_ARG="${1#--log-level=}" ;;
    --sts-log-level=*) STS_LOG_LEVEL_ARG="${1#--sts-log-level=}" ;;
    --timeout=*)       TIMEOUT_ARG="${1#--timeout=}" ;;
    --quiet)           QUIET=1 ;;
    --no-browser)      BROWSER=0 ;;
    --docker)          SERVICE="docker"; SERVICE_ASKED=1 ;;
    --no-docker)       SERVICE="host"; SERVICE_ASKED=1 ;;
    --host-service)    SERVICE="host"; SERVICE_ASKED=1 ;;
    --no-build)        BUILD=0 ;;
    --keep-stack)      KEEP_STACK=1 ;;
    --tear-down)       KEEP_STACK=0 ;;
    --no-keep-stack)   KEEP_STACK=0 ;;
    --sts-port=*)      STS_PORT_ARG="${1#--sts-port=}" ;;
    --open)            OPEN=1 ;;
    --verbose)         set -x ;;
    -h|--help)         usage; exit 0 ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# The vendor commands. They run INSTEAD of a suite and exit — they are about
# the two checkouts rather than about this service, which is the same reason
# tools/vendor-check.js is a tool and not a job in the report.
# ---------------------------------------------------------------------------
if [ -n "${VENDOR}" ];
then
  VARGS=()
  [ "${VENDOR}" = "sync" ] && VARGS+=("--sync")
  [ -n "${PARENT}" ] && VARGS+=("--parent=${PARENT}")
  node tests/tools/vendor-check.js ${VARGS[@]+"${VARGS[@]}"}
  exit $?
fi

# ---------------------------------------------------------------------------
# --coverage is a different script rather than a flag here, and that is the
# parent project's shape too (run-coverage.sh beside local-run-tests.sh). It
# collects into ./coverage and renders, which is a longer run with a different
# output; the flag exists only so that nobody has to remember two names.
# ---------------------------------------------------------------------------
if [ "${COVERAGE}" = "1" ];
then
  # A COVERAGE RUN NEVER DRIVES THE `sts` CONTAINER, AND SINCE 2026-08-29 THAT
  # IS NOT THE SAME AS RUNNING ON THIS MACHINE. V8 writes its coverage from
  # INSIDE the process being measured, into a directory that process can write,
  # so a service this script only talks HTTP to can never be under the report —
  # that much is unchanged and is why the container started below is not
  # handed over. What run-coverage.sh does instead is put the RUNNER in a
  # container and let it start the service it measures in there, so `docker`
  # and `host` are still both available and mean what they mean everywhere
  # else. --no-docker is therefore passed on when somebody asked for it, and
  # nothing is said when nobody did: the default is a container either way, and
  # a line explaining a difference that no longer exists is worse than silence.
  if [ "${SERVICE}" = "host" ] && [ "${SERVICE_ASKED}" = "1" ] \
     && [ "${PROTOCOL}" != "off" ];
  then
    echo "Collecting coverage on this machine (--no-docker). The container"
    echo "form of the same run is ./run-coverage.sh with no flag."
    echo ""
  fi
  ARGS=()
  [ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
  ARGS+=("--protocol=${PROTOCOL}")
  [ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
  [ -n "${LOG_LEVEL_ARG}" ] && ARGS+=("--log-level=${LOG_LEVEL_ARG}")
  [ -n "${STS_LOG_LEVEL_ARG}" ] && ARGS+=("--sts-log-level=${STS_LOG_LEVEL_ARG}")
  [ "${QUIET}" = "1" ] && ARGS+=("--quiet")
  [ "${BROWSER}" = "0" ] && ARGS+=("--no-browser")
  [ "${OPEN}" = "1" ] && ARGS+=("--open")
  # WHERE, and only when it was ASKED for. An unasked default here would pin
  # that script's own default rather than passing a request through, and the
  # two scripts must be free to have different ones.
  if [ "${SERVICE_ASKED}" = "1" ];
  then
    [ "${SERVICE}" = "host" ] && ARGS+=("--no-docker")
    [ "${SERVICE}" = "docker" ] && ARGS+=("--docker")
  fi
  [ "${BUILD}" = "0" ] && ARGS+=("--no-build")
  exec "${CURRENT_DIR}/run-coverage.sh" ${ARGS[@]+"${ARGS[@]}"}
fi

# ---------------------------------------------------------------------------
# THE CONTAINER'S LIFECYCLE.
#
# Six functions — four here and TWO SOURCED from tests/tools/compose.sh since
# 2026-08-29, because ./docker-run-tests.sh needs the same two — and the shape
# is the parent project's: resolve the compose command once, forward the
# variables compose substitutes EXPLICITLY, bring the service up, prove it is
# answering before anything is run against it, collect its log, take it down. What is deliberately NOT copied from over there is the
# unconditional `sudo`: that stack needs it because its CI runs as a user with
# no docker group, and paying a sudo prompt on a machine where docker already
# answers is a cost for nothing.
# ---------------------------------------------------------------------------

# resolveCompose() and docker_compose() are SHARED with ./docker-run-tests.sh
# and live in tests/tools/compose.sh. They were written here and moved there on
# 2026-08-29, when the second launcher arrived needing the same two answers:
# which compose command this machine has, and how to hand it the variables a
# compose file substitutes. A second copy of the `sudo` reasoning is a second
# copy that can be fixed in one place and stay broken in the other.
COMPOSE_SH="${CURRENT_DIR}/tests/tools/compose.sh"
if [ ! -r "${COMPOSE_SH}" ];
then
  echo "Cannot find ${COMPOSE_SH}, which defines resolveCompose() and"
  echo "docker_compose(). Without it nothing here can bring a container up."
  exit 1
fi
. "${COMPOSE_SH}"

# A free TCP port at or above $1, answered by BINDING it — the only question
# that matters, and the one tests/tools/service.js asks for the same reason.
# 0.0.0.0 because that is where docker publishes, so a port free only on
# loopback is not free for this.
freePort()
{
  node -e '
    var net = require("net");
    var start = Number(process.argv[1]);
    (function next(p) {
      if (p > start + 500) { process.exit(1); }
      var s = net.createServer();
      s.once("error", function () { next(p + 1); });
      s.once("listening", function () {
        s.close(function () { process.stdout.write(String(p)); });
      });
      s.listen(p, "0.0.0.0");
    })(start);
  ' "$1"
}

# ---------------------------------------------------------------------------
# IS THE MAIN PORT TLS ON THIS RUN, AND WHAT SCHEME DOES THAT MAKE ITS URL.
#
# ONE answer, read in four places — the URL handed to every protocol job, the
# variable forwarded to compose, the readiness probe and the diagnosis when it
# fails — because four independent guesses is how a launcher comes to print a
# URL nothing is listening on.
#
# TRUE BY DEFAULT since 2026-08-30, matching every appconfig file in env/ and
# the ${STS_HTTPS:-true} in both compose files. `STS_HTTPS=false
# ./local-run-tests.sh` is the whole of the way back to a plain port, and it
# works for the container run and the --no-docker one alike: tests/tools/
# service.js reads the same variable with the same default.
# ---------------------------------------------------------------------------
stsHttps()
{
  if [ "${STS_HTTPS:-true}" = "true" ];
  then
    echo "true"
  else
    echo "false"
  fi
}

stsScheme()
{
  if [ "$(stsHttps)" = "true" ];
  then
    echo "https"
  else
    echo "http"
  fi
}

# The HTTP status the service gives, or 000 if the socket said nothing. node
# rather than curl, because this suite already requires node 18 and requires
# curl nowhere; `rejectUnauthorized: false` because the certificate is
# self-signed and regenerated on every start, so nothing can have an anchor for
# it — this asks whether the port answers, not whether it is trusted.
stsProbe()
{
  node -e '
    var url = new URL(process.argv[1]);
    var m = url.protocol === "https:" ? require("https") : require("http");
    var req = m.get({ host: url.hostname, port: url.port, path: url.pathname,
                      rejectUnauthorized: false, timeout: 5000 },
      function (res) { process.stdout.write(String(res.statusCode)); process.exit(0); });
    req.on("error", function () { process.stdout.write("000"); process.exit(0); });
    req.on("timeout", function () { req.destroy(); process.stdout.write("000"); process.exit(0); });
  ' "$1" 2> /dev/null
}

# ---------------------------------------------------------------------------
# WHERE A RUN'S OWN LOGS GO, AND WHY IT IS A FUNCTION RATHER THAN A PATH.
#
# Each mode is handed `--report-dir=tests/report/<mode>`, so `latest` under
# THAT directory is the run this mode just wrote. The bare `tests/report/latest`
# is not: it is whatever the last mode-less run left behind, quite possibly
# weeks old, and both callers of this named it until 2026-09-07 — which put a
# service log beside a report it had nothing to do with, the one failure mode
# worse than having no log at all.
#
# The fallback carries the mode in the FILENAME, because three modes falling
# back would otherwise be three writes to one path with only the last surviving.
# It is reached whenever there is no report to sit beside — a run that died in
# composeUp() before anything was written, which is precisely when these logs
# are the only evidence there is.
# ---------------------------------------------------------------------------
runLogPath()
{
  local mode="$1" name="$2"
  local logs="${CURRENT_DIR}/tests/report/${mode}/latest/logs"
  if [ -d "${logs}" ] && touch "${logs}/${name}" 2> /dev/null;
  then
    printf '%s\n' "${logs}/${name}"
    return 0
  fi
  # mkdir here as well as before the tee: this is also the path a run that died
  # in composeUp() takes, and on a first ever run nothing has made tests/report
  # by then — which would turn "the service never came up" into a redirection
  # error naming a directory.
  mkdir -p "${CURRENT_DIR}/tests/report" 2> /dev/null || true
  printf '%s\n' "${CURRENT_DIR}/tests/report/${mode}-${name}"
}

# Write the container's own log where the run's other logs are, and say where.
# Called after the run and on every failure path: the service's account of what
# it did is what a failing protocol job is read from, and a container that is
# about to be removed takes it with it.
captureContainerLog()
{
  local mode="$1" dest
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  dest="$(runLogPath "${mode}" "00-mock-sts-service.log")"
  docker_compose "${COMPOSE_FILE_ARGS[@]}" logs --no-color sts > "${dest}" 2>&1 || true
  echo "Service log: ${dest}"
}

# ---------------------------------------------------------------------------
# THE RUNNER'S OWN LOG, WHICH DID NOT EXIST ANYWHERE UNTIL 2026-09-07.
#
# THE JOBS' LOGS ARE NOT IT. run-report.js writes one file per test file and
# those hold the JOB'S output; what the RUNNER said — which jobs it chose, the
# ones it could not start and why, the reason a job was reported SKIPPED, the
# summary — went to this terminal and to nowhere else. A job that never ran has
# no log in that directory to read, and that is exactly the run somebody comes
# back to a report for an hour later.
#
# ./docker-run-tests.sh has the same thing and gets it from `docker compose
# logs tests`, because over there the runner IS a container. Here it is a plain
# node process, so the output is TEE'd as it goes and the file is moved into the
# report afterwards — the report directory is named for the instant the runner
# started and does not exist until it has.
#
# TEE'D RATHER THAN REDIRECTED, because this launcher's whole shape is that a
# person is watching it: --quiet already decides how much each job says, and a
# run that went silent to gain a log file would have traded the loop for the
# record.
# ---------------------------------------------------------------------------
captureRunnerLog()
{
  local mode="$1" from="$2" dest
  if [ ! -f "${from}" ];
  then
    return 0
  fi
  # `--list` answers a question about the FILES and runs nothing, so it writes
  # no report — and moving its listing into whatever `latest` happens to point
  # at would put it in a PREVIOUS run's logs directory, labelled as that run's
  # runner output. Thrown away instead.
  if [ "${LIST}" = "1" ];
  then
    rm -f "${from}"
    return 0
  fi
  dest="$(runLogPath "${mode}" "00-test-runner.log")"
  # A FAILED MOVE REPORTS THE PATH THE FILE IS ACTUALLY AT. The tee'd file is
  # still where it was written, and a message naming a destination with nothing
  # at it would be worse than not printing one at all.
  if [ "${dest}" != "${from}" ] && ! mv -f "${from}" "${dest}" 2> /dev/null;
  then
    dest="${from}"
  fi
  echo "Runner log:  ${dest}"
}

# ---------------------------------------------------------------------------
# Bring the service up and do not return until it ANSWERS.
#
# `up -d` reports success for a container that was created and then exited
# seconds later — which is exactly how this service fails when a port is taken
# or a module is missing from the image — so being up is asked separately from
# being answering, and neither is inferred from the other.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# THE REMOTE PEP CONTAINER, BROUGHT UP BESIDE THE SERVICE.
#
# `--profile xacml` because that service is opt-in in docker-compose.yml, and
# `--no-deps` because the `sts` it depends on is already up and healthy — a
# second `up` of it here would recreate the container this run is already
# driving.
#
# **A FAILURE HERE IS NOT FATAL TO THE RUN, AND THAT IS DELIBERATE.** One job
# out of the suite drives this container; fifty-odd others do not care whether
# it exists. So a PEP image that will not build, or a container that will not
# start, must fail THAT job with a message naming it — not take down a run that
# was going to check the other fifty. The job says what is wrong: without
# XACML_PEP_URL it looks for a docker daemon to start its own container with,
# and without one of those it is reported SKIPPED with the reason.
#
# IT IS NOT WAITED FOR. That container listens only after its first
# registration and pull have been attempted, and both fail until the job
# creates the realm it polls — so there is nothing here worth waiting for that
# the job is not already waiting for properly.
# ---------------------------------------------------------------------------
composePepUp()
{
  # ---- THE CLIENT CREDENTIAL, BEFORE THE CONTAINER THAT PRESENTS IT --------
  #
  # It has to be minted AFTER the service is answering (the Root CA is POSTed
  # to its truststore) and BEFORE the PEP container starts (`pep.js` reads the
  # files at process start and never again). This is the one window, and it is
  # why this runs here rather than beside the other setup above.
  #
  # A FAILURE IS NOT FATAL TO THE RUN, for composePepUp()'s own reason: one job
  # drives this container and fifty-odd others do not care. The PEP then starts
  # with no certificate, is refused by the access policy, and the job that
  # drives it says so — which is a readable failure rather than a silent one.
  echo "Minting the remote PEP's client certificate (${XACML_PEP_SUBJECT})"
  echo "and adding its Root CA to the mock's truststore..."
  if ! node "${CURRENT_DIR}/tests/tools/pep-credential.js" \
       --url="${STS_URL}" --out="${XACML_PEP_CERT_DIR}" \
       --subject="${XACML_PEP_SUBJECT}" > /dev/null;
  then
    echo ""
    echo "WARNING: the remote PEP's client certificate could not be minted or"
    echo "         its Root CA could not be trusted. That container will start"
    echo "         without one and every /xacml/pep call it makes will be"
    echo "         refused by the access policy; sts_xacml_remote_pep will say"
    echo "         so and the rest of the run is unaffected."
    echo ""
  fi

  # BUILT FROM THIS WORKING TREE, ON THE SAME TERMS AS THE SERVICE IMAGE ABOVE.
  #
  # **THIS IS NOT OPTIONAL TIDINESS AND IT COST A MUTATION TEST TO FIND.**
  # `up` builds an image only when it is MISSING, so without this line a stack
  # started here reuses whatever `rcbj/xacml-pep` was last built — from another
  # branch, from another repository, from an hour ago — and the one job that
  # drives it reports green about an engine nobody is running. It is exactly
  # the failure the `--no-build` warning above is written for, except silent,
  # because nothing on screen would have named the PEP at all.
  #
  # The Dockerfile copies the seven engine modules out of xacml/ at build time,
  # so this build is also what makes that COPY set an assertion: a module added
  # to engine.js and not to that file produces a container that dies at load,
  # and the job says so.
  if [ "${BUILD}" = "1" ];
  then
    echo "Building the remote XACML PEP image from this working tree..."
    if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" --profile xacml build xacml-pep;
    then
      echo ""
      echo "WARNING: the remote XACML PEP image would not build. The one job"
      echo "         that drives it (sts_xacml_remote_pep) will say so; the"
      echo "         rest of the run is unaffected."
      echo ""
      return 0
    fi
  fi
  echo "Starting the remote XACML PEP container ${XACML_PEP_CONTAINER} on"
  echo "http://localhost:${XACML_PEP_HOST_PORT} (polling /realm/${XACML_PEP_REALM},"
  echo "which tests/vendored/sts_xacml_remote_pep.js creates and LEAVES"
  echo "standing — no job in this suite removes a realm; the mock container is"
  echo "recreated on every run, so the next one meets a clean service)."
  if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" --profile xacml \
       up -d --no-deps --force-recreate xacml-pep;
  then
    echo ""
    echo "WARNING: the remote XACML PEP container would not start. The one job"
    echo "         that drives it (sts_xacml_remote_pep) will say so; the rest"
    echo "         of the run is unaffected. \`${COMPOSE_CMD} -p ${COMPOSE_PROJECT}"
    echo "         -f ${COMPOSE_FILE} logs xacml-pep\` is where the reason is."
    echo ""
    return 0
  fi
  # WHERE THE JOB LOOKS FOR IT. Exported rather than passed, because
  # run-report.js hands every protocol job a copy of this process's
  # environment — the same route STS_TEST_SERVICE_URL takes. All three
  # together or none: the job refuses a URL with no realm rather than
  # asserting against a container pointed somewhere else.
  export XACML_PEP_URL="http://localhost:${XACML_PEP_HOST_PORT}"
  export XACML_PEP_NAME
  export XACML_PEP_REALM
  # AND ITS HTTPS LISTENER (2026-09-13): where the job dials it, and where the
  # job writes the pair it issues. `localhost` is the name the job asks the
  # certificate to carry, because it is the name this host dials it by.
  export XACML_PEP_HTTPS_URL="https://localhost:${XACML_PEP_HTTPS_HOST_PORT}"
  export XACML_PEP_SERVER_CERT_DIR="${XACML_PEP_CERT_DIR}/server"
  # AND THE ROOT CA, AS TEXT, SO THE JOB CAN PUT IT BACK.
  #
  # This anchor is posted to /tls/trust once, here, before the container
  # starts — and the truststore is a Map in the service's process that ANY job
  # can empty: `POST /tls/trust/clear` needs no credential, and a job that
  # exercises the truststore is entitled to use it. Until 2026-09-06 nothing
  # noticed, because a client certificate was a turnstile; the container's
  # pull, heartbeat and PIP queries all resolve a VERIFIED chain now, so one
  # such job left this container authenticating as nobody for the rest of the
  # run — reporting UNABLE_TO_GET_ISSUER_CERT_LOCALLY about an anchor that was
  # posted correctly before anything started.
  #
  # **THE FIX IS NOT TO STOP OTHER JOBS CLEARING IT.** It is for the job that
  # DEPENDS on this anchor to re-establish it, which is what every other
  # credential in that file already does for itself. The PEM travels in the
  # environment rather than as a path because the containerized runner cannot
  # see this directory.
  if [ -f "${XACML_PEP_CERT_DIR}/ca.crt" ];
  then
    XACML_PEP_CA_PEM="$(cat "${XACML_PEP_CERT_DIR}/ca.crt")"
    export XACML_PEP_CA_PEM
  fi
  return 0
}

composeUp()
{
  STS_HOST_PORT="${STS_PORT_ARG}"
  if [ -z "${STS_HOST_PORT}" ];
  then
    STS_HOST_PORT="$(freePort 18081)"
    if [ -z "${STS_HOST_PORT}" ];
    then
      echo "No free host port could be found above 18081 for the service."
      return 1
    fi
  fi
  # https since 2026-08-30: every appconfig file in env/ carries
  # `global.https: true` and docker-compose.yml sets STS_HTTPS, so the
  # container's main port is TLS. STS_HTTPS in this shell overrides both and is
  # forwarded below, so the scheme here is read off the same answer the
  # container will get rather than assumed twice.
  STS_URL="$(stsScheme)://localhost:${STS_HOST_PORT}"

  # The PEP's published port, picked the same way and for the same reason.
  XACML_PEP_HOST_PORT="$(freePort 19090)"
  if [ -z "${XACML_PEP_HOST_PORT}" ];
  then
    echo "No free host port could be found above 19090 for the remote PEP."
    return 1
  fi
  # AND ITS HTTPS LISTENER'S (2026-09-13), searched from one above the HTTP
  # port for the reason the revocation listener's search below gives:
  # freePort() binds nothing, so two searches from one start answer one port.
  XACML_PEP_HTTPS_HOST_PORT="$(freePort "$((XACML_PEP_HOST_PORT + 1))")"
  if [ -z "${XACML_PEP_HTTPS_HOST_PORT}" ];
  then
    echo "No free host port could be found above ${XACML_PEP_HOST_PORT} for"
    echo "the remote PEP's HTTPS listener."
    return 1
  fi

  # THE DIRECTORY'S SOCKET, picked the same way and for two reasons rather than
  # one: two runs on this machine must not collide with each other, and NEITHER
  # must collide with a real slapd on 389. The container side stays 389 — see
  # tests/docker-compose-ldap.yml, which this launcher layers over the compose
  # file for exactly this mapping.
  STS_LDAP_HOST_PORT="$(freePort 11389)"
  if [ -z "${STS_LDAP_HOST_PORT}" ];
  then
    echo "No free host port could be found above 11389 for the LDAP socket."
    return 1
  fi

  # THE PLAIN-HTTP REVOCATION LISTENER (2026-09-13). Every certificate the
  # service issues names it for its CRL, its OCSP responder and its issuer's
  # certificate, and `sts_pki_distribution_points` follows those addresses from
  # this host EXACTLY AS WRITTEN — so it is published on a free port like the
  # three above, and docker-compose.yml hands the same number to the service as
  # PKI_DISTRIBUTION_PORT, which is how the address inside a certificate comes
  # to be the address this mapping made. Searched from ONE ABOVE the service's
  # own port: freePort() binds nothing, so two searches started at 18081 and
  # 18082 would both answer 18082 whenever 18081 was taken.
  STS_PKI_HOST_PORT="$(freePort "$((STS_HOST_PORT + 1))")"
  if [ -z "${STS_PKI_HOST_PORT}" ];
  then
    echo "No free host port could be found above ${STS_HOST_PORT} for the"
    echo "plain-HTTP revocation listener."
    return 1
  fi
  # INSIDE THE RUN'S OWN REPORT DIRECTORY rather than /tmp, so that a private
  # key this script generates lives beside the run that needed it and goes when
  # somebody clears the reports. It has to be an ABSOLUTE path: compose
  # resolves a bind mount's source against the compose file's directory, and a
  # relative one here would name a directory that does not exist.
  XACML_PEP_CERT_DIR="${CURRENT_DIR}/tests/report/pep-credential"
  rm -rf "${XACML_PEP_CERT_DIR}"
  mkdir -p "${XACML_PEP_CERT_DIR}"
  # Where sts_xacml_remote_pep.js writes the HTTPS listener's pair once it has
  # issued one (2026-09-13). Made now, because the container mounts its parent.
  mkdir -p "${XACML_PEP_CERT_DIR}/server"

  # ---------------------------------------------------------------------------
  # THE STACK'S OWN SUBNET, PICKED THE WAY THE THREE PORTS ABOVE ARE
  # (2026-09-12), AND FOR THE REASON THE PROJECT-NAME BLOCK NEAR THE TOP OF
  # THIS FILE IS A RECORD OF.
  #
  # docker-compose.yml names a subnet now rather than letting compose allocate
  # one, because a realm's SPIFFE listeners need addresses that are the same on
  # every start — and a network, like a `container_name`, is MACHINE-WIDE. So
  # the literal `172.29.0.0/24` put every run in this tree back where naming a
  # project had just got them out of: the second one refused to start at all,
  #
  #   invalid pool request: Pool overlaps with other one on this address space
  #
  # with nothing brought up and nothing in the tree wrong. It is the same
  # sentence as the container names — naming a project must isolate the WHOLE
  # run — reaching one more thing.
  #
  # AN IDLE MACHINE IS UNAFFECTED: freeSubnet() offers the compose file's own
  # default first, so a plain run takes the addresses it always took. The four
  # variables move TOGETHER because three of them are addresses INSIDE the
  # first — which is the whole reason they are derived here from one answer
  # rather than named four times.
  #
  # AN OPERATOR'S OWN `STS_NETWORK_SUBNET` IS HONOURED and the addresses are
  # derived from it, so the one lever docker-compose.yml documents still moves
  # the whole arrangement in one place.
  # ---------------------------------------------------------------------------
  if [ -z "${STS_NETWORK_SUBNET:-}" ];
  then
    STS_NETWORK_SUBNET="$(freeSubnet 172.29)"
    if [ -z "${STS_NETWORK_SUBNET}" ];
    then
      echo "No free /24 could be found in 172.29.0.0/16 for the stack's own"
      echo "network. Every one of the 256 overlaps a docker network or a route"
      echo "on this machine — \`docker network ls\` and \`ip route\` say which."
      echo "STS_NETWORK_SUBNET names one explicitly."
      return 1
    fi
  fi
  # The three addresses inside it. `.10` is the service, and `.11`-`.13` are
  # what the container adds to its own interface for a realm's SPIFFE
  # listeners — see the STS_EXTRA_IPS block in docker-compose.yml.
  #
  # DERIVED FROM THE SUBNET RATHER THAN FROM THE BASE, which is not the same
  # thing and was wrong for an edit: the scan hands back `172.29.1.0/24` as
  # readily as `172.29.0.0/24`, and an address built from the first two octets
  # would then sit outside the network compose was about to create — which
  # compose refuses at `up` with a message about an invalid address, one layer
  # away from the thing that chose it.
  STS_NETWORK_BITS="${STS_NETWORK_SUBNET##*/}"
  STS_NETWORK_PREFIX="${STS_NETWORK_SUBNET%/*}"
  STS_NETWORK_PREFIX="${STS_NETWORK_PREFIX%.*}"
  STS_SERVICE_ADDRESS="${STS_NETWORK_PREFIX}.10"
  STS_SERVICE_EXTRA_IPS="${STS_NETWORK_PREFIX}.11/${STS_NETWORK_BITS}"
  STS_SERVICE_EXTRA_IPS="${STS_SERVICE_EXTRA_IPS} ${STS_NETWORK_PREFIX}.12/${STS_NETWORK_BITS}"
  STS_SERVICE_EXTRA_IPS="${STS_SERVICE_EXTRA_IPS} ${STS_NETWORK_PREFIX}.13/${STS_NETWORK_BITS}"


  COMPOSE_ENV=(
    "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}"
    "STS_HOST_PORT=${STS_HOST_PORT}"
    # WHAT tests/docker-compose-ldap.yml SUBSTITUTES. Named here rather than
    # left to that file's own default, for the reason tests/tools/compose.sh's
    # header gives: `sudo` empties the environment, so an exported variable
    # reaches compose as unset and the file substitutes its default with
    # nothing said — which on this machine, where docker needs sudo, would put
    # the socket on 11389 whatever port this launcher picked and told the job
    # about.
    "STS_LDAP_HOST_PORT=${STS_LDAP_HOST_PORT}"
    # AND THE REVOCATION LISTENER'S, which docker-compose.yml publishes and
    # passes to the service as PKI_DISTRIBUTION_PORT. Named here for the
    # reason the line above is: under sudo an exported variable reaches compose
    # as unset, and the default would put every certificate's address on a
    # port this launcher did not choose.
    "STS_PKI_HOST_PORT=${STS_PKI_HOST_PORT}"
    "STS_CONTAINER_NAME=${STS_TEST_CONTAINER}"
    # THE NETWORK AND THE ADDRESSES IN IT, chosen above. Named here for the
    # reason every other variable in this array is: a compose file default is
    # what a run that does not name one gets, and these four defaults are the
    # same literals for every run in this tree.
    "STS_NETWORK_SUBNET=${STS_NETWORK_SUBNET}"
    "STS_ADDRESS=${STS_SERVICE_ADDRESS}"
    "STS_SPIFFE_GRPC_HOST=${STS_SERVICE_ADDRESS}"
    "STS_EXTRA_IPS=${STS_SERVICE_EXTRA_IPS}"
    "STS_POSTGRES_CONTAINER_NAME=${STS_TEST_PG_CONTAINER}"
    "CONFIG_FILE=${STS_TEST_CONFIG_FILE}"
    # ---- THE MODE, and this was a hardcoded `memory` until 2026-09-07 -----
    #
    # It said "NOT A TUNING CHOICE — a suite that persisted would be a suite
    # whose second run started from the first run's leavings", which was right
    # while there was ONE run. There are three now (tests/tools/modes.sh) and
    # two of them are about persistence, so a hardcoded value here does not
    # merely ignore the matrix — it DEFEATS it silently: the `postgres` mode
    # ran as a second `memory` mode and reported itself green, and `dispatch`
    # refused to start because the pool will not dispatch without coordination.
    # The first was worse than the second, because it looked like coverage.
    #
    # The leavings the old comment worried about are handled by the mode loop
    # bringing the stack DOWN --volumes between modes, so the database a
    # `postgres` run starts from is a fresh one.
    #
    # Passed from the exported environment the loop set, with the old default
    # kept for a composeUp() reached outside the loop.
    "STS_PERSISTENCE_MODE=${STS_PERSISTENCE_MODE:-memory}"
    "STS_PERSISTENCE_COORDINATE=${STS_PERSISTENCE_COORDINATE:-false}"
    "STS_WORKERS_REQUEST_COUNT=${STS_WORKERS_REQUEST_COUNT:-0}"
    "STS_WORKERS_SURFACE_COUNT=${STS_WORKERS_SURFACE_COUNT:-0}"
    "STS_WORKERS_DISPATCH=${STS_WORKERS_DISPATCH:-}"
    "STS_WORKERS_READ_YOUR_WRITE=${STS_WORKERS_READ_YOUR_WRITE:-false}"
    # THE KEYSTORE, AND THEREFORE THE SECRET STORE (2026-09-12). `persisted`
    # turns the keystore on without product mode, which is what makes the
    # `dispatch` mode read its key-encryption key out of the OpenBao container
    # the stack brings up. The other two modes generate a key per start and
    # never dial it — see tests/tools/modes.sh, which sets this per mode for
    # the reason that file's header gives about naming every variable.
    #
    # The DATABASE PASSWORD is not here because it is not per mode: the compose
    # file's connection string carries none in any mode, and the store supplies
    # it every time.
    "STS_KEYS_SOURCE=${STS_KEYS_SOURCE:-generated}"
    # The OpenBao containers' names, for the same reason every other container
    # in this stack has one: two runs in one tree must not collide, and the
    # compose default (`sts-openbao`) is the name a plain `docker compose up`
    # in this directory takes.
    "STS_BAO_CONTAINER_NAME=${STS_TEST_BAO_CONTAINER}"
    "STS_BAO_TLS_CONTAINER_NAME=${STS_TEST_BAO_TLS_CONTAINER}"
    "STS_BAO_SEED_CONTAINER_NAME=${STS_TEST_BAO_SEED_CONTAINER}"
    # TLS ON THE MAIN PORT. Named EXPLICITLY rather than left to the compose
    # file's own `${STS_HTTPS:-true}` default, and the reason is the one the
    # header of tests/tools/compose.sh gives: `sudo` empties the environment,
    # so an operator's `STS_HTTPS=false` in this shell would reach compose as
    # unset and the file would substitute `true` with nothing said. Passing it
    # here is what makes the override real on a machine where docker needs
    # sudo — which is this one.
    "STS_HTTPS=$(stsHttps)"
    # ---- the remote PEP container -------------------------------------
    # Its own free port rather than 9090, so a run can never take the port of
    # a `docker compose --profile xacml up` somebody is looking at; its own
    # container name for the same reason. The PDP URL names the throwaway
    # realm the job owns — the compose file's default is the DEFAULT realm,
    # which is the demonstration's answer and would have this job disabling
    # policy that every other job in the run decides against. The two
    # intervals are shortened because the job MEASURES against them.
    "XACML_PEP_CONTAINER_NAME=${XACML_PEP_CONTAINER}"
    "XACML_PEP_HOST_PORT=${XACML_PEP_HOST_PORT}"
    "XACML_PEP_NAME=${XACML_PEP_NAME}"
    "XACML_PEP_PDP_URL=$(stsScheme)://sts:8081/realm/${XACML_PEP_REALM}"
    "XACML_PEP_POLL_INTERVAL_MS=5000"
    "XACML_PEP_HEARTBEAT_INTERVAL_MS=2000"
    # The credential composePepUp() writes, mounted read-only at /certs.
    "XACML_PEP_CERT_DIR=${XACML_PEP_CERT_DIR}"
    "XACML_PEP_TLS_CERT=/certs/pep.crt"
    "XACML_PEP_TLS_KEY=/certs/pep.key"
    # THE HTTPS LISTENER'S PAIR (2026-09-13): two paths under that mount that
    # are EMPTY when the container starts. sts_xacml_remote_pep.js issues the
    # pair once the PEP has registered in the realm it creates, and writes it
    # into ${XACML_PEP_CERT_DIR}/server, which is this directory on the host.
    "XACML_PEP_HTTPS_HOST_PORT=${XACML_PEP_HTTPS_HOST_PORT}"
    "XACML_PEP_HTTPS_CERT=/certs/server/pep-server.crt"
    "XACML_PEP_HTTPS_KEY=/certs/server/pep-server.key"
    "XACML_PEP_HTTPS_RELOAD_INTERVAL_MS=1000"
  )
  # Only when it HAS a value: an empty STS_LOG_LEVEL makes bunyan throw
  # `unknown level name: ""` while this service is still loading its modules,
  # so it never listens and the run reports a service that would not answer
  # rather than a log level. Since the default above it is `info` this is
  # always taken on a run started by this script; the guard stays because
  # startStack() is also reachable with the variable exported empty by
  # somebody's shell, which is the case it was written for.
  if [ -n "${STS_LOG_LEVEL:-}" ];
  then
    COMPOSE_ENV+=("STS_LOG_LEVEL=${STS_LOG_LEVEL}")
  fi

  # ---------------------------------------------------------------------------
  # THE MANAGEMENT API'S CLIENT SECRET, PINNED FOR THIS RUN (2026-09-09).
  #
  # `/admin-api` requires an OAuth 2.0 access token, and the token is obtained
  # by the seeded `sts-management-api` client with `client_credentials`. That
  # client's secret is minted at every start and is readable only THROUGH the
  # API it unlocks — a bootstrap hole — so `adminApi.clientSecret` exists to
  # pin it and this is where the run does so.
  #
  # A FRESH SECRET PER RUN rather than a constant in this file: it lives as
  # long as one stack, it never reaches a repository, and two runs on one
  # machine cannot lend each other a token.
  # ---------------------------------------------------------------------------
  ADMIN_API_CLIENT_SECRET="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
  export ADMIN_API_CLIENT_SECRET
  COMPOSE_ENV+=("ADMIN_API_CLIENT_SECRET=${ADMIN_API_CLIENT_SECRET}")

  # A stack left behind by an interrupted run holds the container name and the
  # volumes this one is about to ask for. Removing it is safe BECAUSE of the
  # project name: this touches `mock-sts-tests` and can never reach the `sts`
  # container a `docker compose up` in this directory creates.
  #
  # **`--profile xacml` IS LOAD-BEARING ON A `down` AND THAT IS NOT OBVIOUS.**
  # `down` removes the containers of services in the ACTIVE profiles, and the
  # remote PEP is in one — so without this it survives, its network cannot be
  # removed ("Resource is still in use"), and the next run inherits both. It
  # was found by running the teardown and looking, which is the only way this
  # kind of thing is ever found. `--remove-orphans` does NOT cover it: a
  # profiled service is defined in the file, so it is not an orphan.
  #
  # BOUNDED since 2026-09-10, for ./docker-run-tests.sh's reason and with the
  # same default: a `down` that never returns holds a run open after
  # everything it was asked to do has finished. That launcher's version of
  # this cost CI a green suite; this one would cost a developer a terminal.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    "${COMPOSE_FILE_ARGS[@]}" --profile xacml \
    down --remove-orphans --volumes > /dev/null 2>&1 || true

  if [ "${BUILD}" = "1" ];
  then
    echo "Building the mock STS image from this working tree..."
    if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" build sts;
    then
      echo "The image would not build. Nothing was run."
      return 1
    fi
  else
    echo "NOT rebuilding the image (--no-build): the container may be running"
    echo "code OLDER than this working tree, and it will answer every request"
    echo "either way. Drop --no-build if a result surprises you."
  fi

  # ---- DOES THIS MODE NEED THE DATABASE? --------------------------------
  #
  # `--no-deps` was unconditional until 2026-09-07, on the argument that "the
  # postgres service is for an operator keeping a mock around for a week, and
  # this run persists nothing". That is still true of the `memory` mode and is
  # FALSE of the other two: with it, the `postgres` and `dispatch` modes came
  # up with no database at all — which the service reported honestly and which
  # made one mode a duplicate of another and the third refuse to start.
  #
  # So the flag follows the mode. Dropping it lets compose bring `postgres` up
  # through the `sts` service's own depends_on, which is the same path a plain
  # `docker compose up` takes.
  local depsArgs=()
  if stsModeNeedsPostgres "${STS_MODE_NAME:-memory}";
  then
    echo "Starting the mock STS container on ${STS_URL} (project"
    echo "${COMPOSE_PROJECT}, container ${STS_TEST_CONTAINER}, with postgres,"
    echo "persistence=${STS_PERSISTENCE_MODE:-memory})."
  else
    depsArgs=(--no-deps)
    echo "Starting the mock STS container on ${STS_URL} (project"
    echo "${COMPOSE_PROJECT}, container ${STS_TEST_CONTAINER}, persistence off)."
  fi
  # --force-recreate so that a container from a previous run is never reused
  # with a new image.
  if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" up -d ${depsArgs[@]+"${depsArgs[@]}"} --force-recreate sts;
  then
    echo "The stack would not start."
    STACK_UP=1   # something may exist; let the teardown and the log reach it
    return 1
  fi
  STACK_UP=1

  # ---- is it answering? ---------------------------------------------------
  local deadline code
  deadline=$(( $(date +%s) + ${STS_TEST_READY_SECONDS:-180} ))
  while :;
  do
    code="$(stsProbe "${STS_URL}/healthcheck")"
    if [ "${code}" = "200" ];
    then
      echo "The mock STS is answering on ${STS_URL}."
      # WHERE THE LDAP JOB LOOKS FOR THE SOCKET. Exported rather than passed,
      # because run-report.js hands every protocol job a copy of this process's
      # environment — the same route STS_TEST_SERVICE_URL and XACML_PEP_URL
      # take. Set only once the service is ANSWERING, so that a stack which
      # never came up leaves the job to fail on its own connect with a message
      # naming both launchers rather than on a URL this script promised.
      export STS_LDAP_URL="ldap://localhost:${STS_LDAP_HOST_PORT}"
      # -------------------------------------------------------------------
      # AND WHERE THE SERVICE CAN DIAL BACK INTO THIS MACHINE (2026-09-12).
      #
      # `sts_gnap_core` section 6 runs a listener in the JOB and has the
      # authorization server POST an RFC 9635 push finish to it. The job
      # defaulted the host to `localhost`, which from inside the service's
      # container is the container itself — so every mode of every run
      # failed with "0 !== 1 pushes", while the service logged that it had
      # dialled `http://localhost:<port>` and been refused. The runner is a
      # host process here, so the address is this compose network's GATEWAY:
      # docker gives a user-defined network `.1`, and it is derived from the
      # SUBNET chosen above for that block's reason. An operator's own value
      # wins. `--no-docker` never reaches this line, and `localhost` is
      # right there.
      # -------------------------------------------------------------------
      export GNAP_PUSH_HOST="${GNAP_PUSH_HOST:-${STS_NETWORK_PREFIX}.1}"
      # -------------------------------------------------------------------
      # AND THE PORT ON ITS OWN, BECAUSE TWO JOBS ASK TWO DIFFERENT QUESTIONS
      # (2026-09-09).
      #
      # `sts_directory_bulk_load_ldap` reads the URL above. `sts_global_logout`
      # builds its own from the SERVICE's hostname and `STS_LDAP_PORT` — which
      # this launcher did not set, so it dialled 389 on the host, got
      # ECONNREFUSED, and reported "LDAP bind did not sign in" as a note.
      #
      # **THE JOB THEN PASSED**, which is the part worth writing down: the one
      # assertion in this suite that proves a sign-out reaches a directory
      # connection was quietly not being made in this launcher at all, and the
      # containerized one made it because its runner shares a network with the
      # service and 389 is simply there. That is how a real defect in
      # `dispatch` mode reached a green local run.
      # -------------------------------------------------------------------
      export STS_LDAP_PORT="${STS_LDAP_HOST_PORT}"
      echo "The directory's own socket is published at ${STS_LDAP_URL} for" \
           "sts_directory_bulk_load_ldap and sts_global_logout."
      composePepUp
      return 0
    fi
    if [ "$(date +%s)" -ge "${deadline}" ];
    then
      echo ""
      echo "ERROR: the mock STS container is not answering on ${STS_URL}"
      echo "       (last status: ${code:-000})."
      # The one diagnosis worth making by hand, because it reaches a test as a
      # closed socket and never names itself: in this service the scheme is a
      # property of the LISTENER, so a container bound in one scheme and probed
      # in the other is silent in exactly the way a container that never
      # started is. Since 2026-08-30 the default is https, so the mistake to
      # catch is an appconfig file that does not set global.https — which is
      # the reverse of what it used to be, hence the swap rather than a
      # hard-coded scheme.
      local other otherScheme
      if [ "$(stsScheme)" = "https" ];
      then
        otherScheme="http"
      else
        otherScheme="https"
      fi
      other="$(stsProbe "${otherScheme}://localhost:${STS_HOST_PORT}/healthcheck")"
      if [ "${other}" = "200" ];
      then
        echo "       SOMETHING IS ANSWERING ${otherScheme} THERE INSTEAD. In"
        echo "       this service the scheme is a property of the LISTENER:"
        echo "       global.https, which every file in env/ now sets to true"
        echo "       and which STS_HTTPS overrides. This run asked for"
        echo "       $(stsScheme)."
        echo "       ${STS_TEST_CONFIG_FILE} is what this container was told to read."
      fi
      return 1
    fi
    sleep 2
  done
}

# ---------------------------------------------------------------------------
# THE ACCESS TOKEN EVERY JOB DRIVES `/admin-api` WITH (2026-09-09).
#
# Minted once per run, after the service answers and before any job starts,
# audienced to this stack's own `/admin-api` and carrying both scopes —
# `admin:read` for reads and `admin:write` for writes, which
# `common/roles.js` turns into ADMIN_READ and ADMIN_WRITE and the XACML
# access policy asks for.
#
# `run-report.js` hands it to every job together with
# `tools/attach-admin-token.js`, which presents it. A failure here is FATAL
# rather than a warning: without a token every job that touches that API would
# fail with 401 and the run would report twenty-three broken tests instead of
# one broken login.
# ---------------------------------------------------------------------------
mintAdminApiToken()
{
  local token
  if ! token="$(STS_ADMIN_API_CLIENT_SECRET="${ADMIN_API_CLIENT_SECRET}"         node "${CURRENT_DIR}/tests/tools/admin-api-token.js" "${STS_URL}" 2>&1)";
  then
    echo "Could not obtain an access token for ${STS_URL}/admin-api:" >&2
    echo "  ${token}" >&2
    echo "  Every job that drives that API needs one. adminApi.authRequired" >&2
    echo "  turns the requirement off if you need the old open API back." >&2
    return 1
  fi
  STS_ADMIN_API_TOKEN="${token}"
  export STS_ADMIN_API_TOKEN
  echo "Minted an /admin-api access token (admin:read admin:write, audience"
  echo "${STS_URL}/admin-api)."
}

# The teardown, and it is a TRAP rather than a line at the end of the script:
# an interrupted run (^C, a failing preflight, `set -e` in a future edit) would
# otherwise leave a container and a network behind, and the next run would then
# be the one that had to explain them.
stackTeardown()
{
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  if [ "${KEEP_STACK}" = "1" ];
  then
    echo ""
    echo "The stack is still up (the default; --tear-down removes it):"
    echo "  service:  ${STS_URL}    console: ${STS_URL}/admin"
    echo "  logs:     ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} logs -f sts"
    # THE SECOND CONTAINER IS PART OF THE RECIPE TOO. Somebody who kept the
    # stack to poke at it will find a remote PEP in it and no explanation
    # anywhere on screen otherwise — and the realm it polls is gone by then,
    # because the job that owns it removes it as its last assertion. Both facts
    # are surprising and both are one line.
    if [ -n "${XACML_PEP_HOST_PORT}" ];
    then
      echo "  pep:      http://localhost:${XACML_PEP_HOST_PORT}/    (the remote XACML PEP,"
      echo "            container ${XACML_PEP_CONTAINER}; it polls /realm/${XACML_PEP_REALM},"
      echo "            which sts_xacml_remote_pep.js creates and REMOVES again — so a"
      echo "            kept stack shows it stale and still enforcing what it last pulled,"
      echo "            which is the state that job's last section asserts)"
      echo "  pep logs: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} logs -f xacml-pep"
    fi
    echo "  stop it:  ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} down -v"
    # THE CERTIFICATE IS PART OF THE RECIPE NOW. With the main port on TLS a
    # job run by hand meets a self-signed certificate this machine has no
    # anchor for and fails with DEPTH_ZERO_SELF_SIGNED_CERT, which names
    # neither this service nor the fix. run-report.js writes the PEM into the
    # run's own report directory; `curl -k ${STS_URL}/tls/server-certificate`
    # fetches it again from the container that is still up.
    if [ "$(stsHttps)" = "true" ];
    then
      echo "  cert:     curl -k ${STS_URL}/tls/server-certificate > /tmp/sts.pem"
    fi
    echo "  one job:  (cd tests/vendored && WSTRUST_STS_URL=${STS_URL} \\"
    echo "             OID4VCI_ISSUER_URL=${STS_URL} MOCK_STS_DIR=${CURRENT_DIR} \\"
    if [ "$(stsHttps)" = "true" ];
    then
      echo "             NODE_EXTRA_CA_CERTS=/tmp/sts.pem \\"
    fi
    echo "             CONFIG_FILE=./env/local.js node sts_metadata.js)"
    return 0
  fi
  # `--profile xacml` for the reason composeUp() gives at its own `down`: the
  # remote PEP container is in a profile, and a `down` without it leaves that
  # container running and the network undeletable.
  #
  # BOUNDED since 2026-09-10, for ./docker-run-tests.sh's reason and with the
  # same default: a `down` that never returns holds a run open after
  # everything it was asked to do has finished. That launcher's version of
  # this cost CI a green suite; this one would cost a developer a terminal.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    "${COMPOSE_FILE_ARGS[@]}" --profile xacml \
    down --remove-orphans --volumes > /dev/null 2>&1 || true
  STACK_UP=0
}
trap stackTeardown EXIT

# ---------------------------------------------------------------------------
# THE PREFLIGHT, and every check here is one that has already cost somebody an
# afternoon in this repository.
# ---------------------------------------------------------------------------
preflight()
{
  if ! command -v node > /dev/null 2>&1;
  then
    echo "node is not on the PATH. This suite runs on node 18 or newer (it"
    echo "uses the global fetch() to wait for the service under --protocol)."
    return 1
  fi
  local major
  major="$(node -p 'process.versions.node.split(".")[0]')"
  if [ "${major}" -lt 18 ];
  then
    echo "node ${major} is too old: the runner uses global fetch(), which"
    echo "arrived in node 18."
    return 1
  fi

  # node_modules. `bunyan` is an ordinary dependency and the tests require the
  # service's real modules, so there is no run without it.
  if [ ! -d "${CURRENT_DIR}/node_modules" ];
  then
    echo "node_modules is missing; running npm install once."
    echo "(.npmrc carries omit=dev on purpose — see the root CLAUDE.md: it is"
    echo "what keeps ldapjs's ~200 test packages out of this tree.)"
    npm install || return 1
  fi

  # THE NESTED SUBMODULE. This repository is itself a submodule of the parent
  # project, so node-ldapjs is one level deeper than `--init` reaches: an
  # uninitialised one is an EMPTY DIRECTORY, npm installs a package with no
  # `main`, and the failure arrives at runtime as `Cannot find module 'ldapjs'`
  # — which names a package and not a checkout. Two of this suite's files reach
  # modules that require it.
  if [ ! -f "${CURRENT_DIR}/node-ldapjs/package.json" ];
  then
    echo "node-ldapjs/ is empty — it is a git SUBMODULE and this repository is"
    echo "itself one, so it needs:"
    echo ""
    echo "    git submodule update --init --recursive"
    echo ""
    echo "(and then npm install again, since ldapjs is installed from it)."
    return 1
  fi
  if [ ! -d "${CURRENT_DIR}/node_modules/ldapjs" ];
  then
    echo "node_modules/ldapjs is missing although node-ldapjs/ is checked out;"
    echo "run npm install."
    return 1
  fi

  # THE TEST DEPENDENCIES, WHICH ARE A SECOND PACKAGE ON PURPOSE. The vendored
  # protocol jobs need `commander` and `selenium-webdriver`, and those are in
  # tests/package.json rather than the root one because .npmrc carries
  # `omit=dev` — a devDependency added at the root would be SILENTLY not
  # installed and thirteen jobs would die with a stack trace naming a package
  # instead of a command. See tests/package.json.
  #
  # Installed here rather than merely reported, because this is the one
  # preflight whose fix is a command with no decision in it. A run that is
  # missing them still FAILS the affected jobs rather than skipping them —
  # run-report.js says so before it spawns anything — so nothing is hidden if
  # this install cannot be done.
  if [ "${PROTOCOL}" != "off" ] && [ ! -d "${CURRENT_DIR}/tests/node_modules" ];
  then
    echo "tests/node_modules is missing; installing the test dependencies once."
    echo "(they are a separate package from the service's — see"
    echo " tests/package.json for the .npmrc reason.)"
    npm install --prefix "${CURRENT_DIR}/tests" || return 1
  fi
  return 0
}

preflight || exit 1

# ---------------------------------------------------------------------------
# DOCKER, OR THE OLD IN-PROCESS SERVICE?
#
# The default is the container and the fallback is loud, because the two runs
# do not test the same thing — one drives the IMAGE and one drives this
# machine's node_modules — and a run that quietly became the other one is a
# green that does not mean what the header says it means. `--docker` turns the
# fallback into an error, which is what CI should pass.
# ---------------------------------------------------------------------------
resolveServiceMode()
{
  if [ "${SERVICE}" != "docker" ];
  then
    return 0
  fi
  if resolveCompose;
  then
    return 0
  fi
  if [ "${SERVICE_ASKED}" = "1" ];
  then
    echo "--docker was asked for and there is no usable docker here."
    echo "Either the daemon is not running, or this user cannot reach it and"
    echo "sudo would need a password (this script never prompts for one)."
    echo "Drop --docker to run the service on this machine instead."
    return 1
  fi
  echo "No usable docker here, so the protocol jobs will drive a service"
  echo "started on THIS machine out of this working tree — the way they ran"
  echo "before 2026-08-28. Every job still runs; what is not covered is"
  echo "anything that is a property of the IMAGE rather than of the source."
  echo "(\`--docker\` makes this an error instead, for CI.)"
  echo ""
  SERVICE="host"
  return 0
}

# ---------------------------------------------------------------------------
# Would this run drive a service at all? Asked of the RUNNER rather than
# guessed from the flags, because `--only=crypto` matches four in-process files
# and no protocol job — and building an image for a run that has nothing to
# point it at is a minute spent on nothing. `--list` is the runner's own answer
# to exactly this question, so the two can never disagree.
# ---------------------------------------------------------------------------
needsService()
{
  local listing
  listing="$(node tests/tools/run-report.js ${LIST_ARGS[@]+"${LIST_ARGS[@]}"} \
               --list 2> /dev/null)" || return 1
  printf '%s\n' "${listing}" | grep -q '^protocol'
}

# ---------------------------------------------------------------------------
# The plain run. `npm test` is the one every contributor already knows and it
# stays exactly what it was — one process, bunyan on the terminal, under two
# seconds — so --no-report is a passthrough and not a second implementation.
# ---------------------------------------------------------------------------
if [ "${NO_REPORT}" = "1" ];
then
  # --no-report cannot run the protocol jobs: they need a service to be started
  # and stopped, which is the report runner's work. Now that those jobs are the
  # DEFAULT this can no longer be a refusal — it would refuse every bare
  # `--no-report` — so an unasked-for default is dropped with a line saying so,
  # and an EXPLICIT --protocol is still an error, because that one is somebody
  # asking for two things that cannot both happen.
  if [ "${PROTOCOL_ASKED}" = "1" ];
  then
    echo "--no-report cannot run the protocol jobs: they need a service to be"
    echo "started and stopped, which is the report runner's work. Drop one of"
    echo "the two flags."
    exit 2
  fi
  if [ "${PROTOCOL}" != "off" ];
  then
    echo "--no-report runs the in-process suite only; the protocol jobs need"
    echo "the report runner. Drop --no-report for the whole set."
  fi
  [ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"
  if [ -n "${ONLY}" ];
  then
    node tests/run.js "--only=${ONLY}"
  else
    node tests/run.js
  fi
  exit $?
fi

# ---------------------------------------------------------------------------
# The reported run.
# ---------------------------------------------------------------------------
# The arguments that decide WHICH jobs run, and only those: needsService()
# hands them to the runner's own --list so that the question "is a service
# wanted" is answered by the same code that will answer "which jobs ran".
LIST_ARGS=()
[ -n "${ONLY}" ] && LIST_ARGS+=("--only=${ONLY}")
LIST_ARGS+=("--protocol=${PROTOCOL}")
[ "${BROWSER}" = "0" ] && LIST_ARGS+=("--no-browser")

ARGS=()
[ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
[ "${LIST}" = "1" ] && ARGS+=("--list")
ARGS+=("--protocol=${PROTOCOL}")
[ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
[ -n "${TIMEOUT_ARG}" ] && ARGS+=("--timeout=${TIMEOUT_ARG}")
[ "${QUIET}" = "1" ] && ARGS+=("--quiet")
[ "${BROWSER}" = "0" ] && ARGS+=("--no-browser")

[ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"
# ---------------------------------------------------------------------------
# THE SERVICE'S LOG LEVEL, WHICH DEFAULTS TO `info` FOR A TEST RUN AND TO
# NOTHING OF THE KIND ANYWHERE ELSE — AND TAKES TWO KNOBS, NOT ONE.
#
# This script used to pass STS_LOG_LEVEL through only when somebody had set it,
# so a plain run drove the service at its appconfig level — `debug`, every
# request, every response and every artifact both before and after signing.
# That is the point of a mock and it is what a failing job is read from; it is
# also about half of that service's CPU, and under this runner almost none of
# it is ever read, because the jobs pass and the log goes away with the
# container. So `info` is the default HERE and nowhere else: no appconfig file
# is edited, no default moves, and a service run by hand or by
# `docker compose up` is untouched.
#
# THE SECOND KNOB IS THE APPCONFIG FILE, AND LEAVING IT OUT WOULD HAVE MADE
# THIS CHANGE LOOK LIKE IT WORKED WHILE DOING ALMOST NOTHING. STS_LOG_LEVEL
# reaches the loggers `config.js` registers — its own, and the `sts` logger in
# helpers.js that every protocol module destructures. It does NOT reach the six
# VENDORED modules under common/vendored/, which each build a bunyan logger at
# load from `require(process.env.CONFIG_FILE).logLevel` and cannot be edited
# here (they are the parent project's files). On the run that measured this,
# STS_LOG_LEVEL=info alone left 3,869 debug lines of 3,951 — 3,582 of them from
# `xmldsig`, which is every canonicalization of every signed document. The
# krb5_* codec modules do the same and `common/config.js` says so in its
# `registerLogger()` header.
#
# So the level picks the FILE as well: env/test.js is env/local.js with
# `logLevel: "info"` and nothing else different (`diff` them — it is one key
# and the header comment), so choosing between them changes the log and no
# behaviour. A run that asks for trace or debug gets env/local.js and therefore
# the WHOLE record, which is what --sts-log-level=debug is asking for; anything
# else gets env/test.js. And it goes the other way round as well —
# STS_TEST_CONFIG_FILE named in the environment with no level beside it turns
# this default OFF rather than being half-overridden, because naming a file
# says something more specific than a level does and a service logging at
# `info` out of a file that says `debug` is nobody's idea of an answer.
#
# EVERY APPCONFIG FILE IN env/ IS AT `info` SINCE 2026-09-12, env/local.js and
# env/docker-tests.js included, because every function now logs its entry and
# exit at debug. So the file this block picks no longer changes the level: a
# trace or debug run raises what STS_LOG_LEVEL reaches, and the vendored
# modules stay at info unless CONFIG_FILE names a file that says otherwise.
#
# The three branches rather than a `:-`: an EMPTY STS_LOG_LEVEL is not a
# harmless default. bunyan throws `unknown level name: ""` while the service is
# still loading its modules, so it never starts, and the run then reports a
# service that would not answer rather than a log level. One exported empty is
# therefore treated as unset.
# ---------------------------------------------------------------------------
[ -n "${STS_LOG_LEVEL_ARG}" ] && STS_LOG_LEVEL="${STS_LOG_LEVEL_ARG}"
if [ -n "${STS_LOG_LEVEL:-}" ];
then
  # A level was asked for. It decides the file too, so that debug means the
  # WHOLE record rather than two thirds of it.
  export STS_LOG_LEVEL
  if [ -z "${STS_TEST_CONFIG_FILE}" ];
  then
    case "${STS_LOG_LEVEL}" in
      trace|debug) STS_TEST_CONFIG_FILE="./env/local.js" ;;
      *)           STS_TEST_CONFIG_FILE="./env/test.js" ;;
    esac
  fi
elif [ -n "${STS_TEST_CONFIG_FILE}" ];
then
  # A FILE was named and no level was. The file decides, both halves of it, and
  # this script exports no level of its own — otherwise pinning the debug file
  # would have produced a service logging at info out of one that says debug,
  # which is the confusing half-answer this whole block exists to avoid.
  :
else
  export STS_LOG_LEVEL="info"
  STS_TEST_CONFIG_FILE="./env/test.js"
fi
# EXPORTED, unlike CONFIG_FILE itself: run-report.js reads this name for the
# service it starts under --no-docker, where the vendored modules would
# otherwise read the ./env/local.js that tests/tools/service.js falls back to.
export STS_TEST_CONFIG_FILE

# ---------------------------------------------------------------------------
# THE SERVICE, IF THIS RUN HAS ANYTHING TO POINT AT IT.
#
# `--list` runs nothing, so it starts nothing. Everything else asks the runner
# whether a protocol job survived the filters, and only then pays for an image.
#
# In `host` mode this does nothing at all: run-report.js starts and stops its
# own throwaway process, exactly as it did before any of this existed. The two
# modes meet at one variable — STS_TEST_SERVICE_URL, which means "somebody else
# started this and somebody else will stop it".
# ---------------------------------------------------------------------------
# UNSET first, always. run-report.js reads STS_TEST_SERVICE_URL as the
# environment fallback for --service-url, so one left exported in this shell —
# by an interrupted run that kept its stack, which is now the default — would
# decide what a
# --no-docker run drove, silently and against the flag that was passed. In this
# script the flags decide; the environment fallback is for somebody calling the
# runner directly.
unset STS_TEST_SERVICE_URL

# The stack is brought up INSIDE the mode loop below, because each mode needs
# its own — different persistence, different worker settings. The one variable
# the two halves meet at is still `STS_TEST_SERVICE_URL`, exported there rather
# than passed as an argument so that ./run-coverage.sh, which builds its own
# argument list, cannot pick it up by accident.

# ===========================================================================
# THE SUITE RUNS ONCE PER MODE, AND THE MODES ARE IN tests/tools/modes.sh.
#
# `memory`, `postgres` and `dispatch` differ in what SHARES state between the
# parts of this service, and a build can be green in one and red in another —
# which is not a hypothesis: on 2026-09-07 `sts_admin_api_operations` passed in
# `memory` and failed in `postgres` with dispatching off in both. A suite that
# ran only the first would have called that build good. That file argues each
# mode and is the ONE definition of them, shared with ./docker-run-tests.sh.
#
# EACH MODE GETS ITS OWN REPORT TREE — tests/report/<mode>/<timestamp> — so a
# failure is attributable to a configuration rather than to "the last run".
#
# THE LAST MODE'S STACK IS LEFT UP. `dispatch` runs last on purpose: it is the
# configuration hardest to reproduce by hand — postgres, coordination and three
# request workers — so it is the one worth having standing when the run ends.
# The earlier modes are torn down as they finish, because two stacks on one
# compose project cannot coexist.
# ===========================================================================
# `--list` and `--vendor-check` answer a question about the FILES and drive no
# service, so they run once whatever the matrix says — three identical listings
# would be noise pretending to be coverage.
if [ "${LIST}" = "1" ];
then
  RUN_MODES=("${RUN_MODES[0]}")
fi

RC=0
MODES_RUN=()
MODES_FAILED=()
MODE_COUNT="${#RUN_MODES[@]}"
MODE_INDEX=0

for MODE in "${RUN_MODES[@]}";
do
  MODE_INDEX=$((MODE_INDEX + 1))
  echo ""
  echo "==========================================================="
  echo " MODE ${MODE_INDEX} of ${MODE_COUNT}: ${MODE}"
  echo " $(stsModeDescription "${MODE}")"
  echo "==========================================================="

  # The mode's environment, exported so composeUp() passes it through and so a
  # host-mode service inherits it. Every mode names every variable it cares
  # about — see modes.sh — so a later mode cannot inherit an earlier one's.
  #
  # `STS_MODE_NAME` is how composeUp() knows whether to bring the database up;
  # it is the mode's NAME rather than one of its settings, because "does this
  # need postgres" is a question about the mode and modes.sh answers it.
  export STS_MODE_NAME="${MODE}"
  while IFS= read -r line;
  do
    [ -n "${line}" ] && export "${line?}"
  done < <(stsModeEnv "${MODE}")

  if [ "${LIST}" != "1" ] && needsService;
  then
    resolveServiceMode || exit 1
    if [ "${SERVICE}" = "docker" ];
    then
      if ! composeUp;
      then
        captureContainerLog "${MODE}"
        echo ""
        echo "Tests FAILED in mode ${MODE}: the service under the protocol jobs"
        echo "never came up, so nothing was checked. This is a failure and not"
        echo "a skip on purpose — a run in which nothing ran must never read"
        echo "as a pass."
        exit 1
      fi
      export STS_TEST_SERVICE_URL="${STS_URL}"
    fi
  fi

  # TEE'D INTO THE FALLBACK PATH AND MOVED INTO THE REPORT AFTERWARDS — see
  # captureRunnerLog(). The runner names its own directory after the instant it
  # starts, so there is nowhere to write this until it has finished.
  #
  # ${PIPESTATUS[0]} AND NOT $?, WHICH WOULD BE tee's. tee exits 0 for a suite
  # that failed every job, so a plain `$?` here would have made every mode pass
  # for as long as this pipe existed.
  #
  # The report directory, made HERE because tee opens its file when the pipeline
  # starts and run-report.js does not create tests/report until a moment later.
  # On a first ever run that is the difference between a log and a `tee: No such
  # file or directory` in front of the whole suite's output.
  # THE TOKEN, BEFORE ANY JOB RUNS. `/admin-api` requires one and twenty-three
  # jobs drive it, so a failure here is the run's failure rather than theirs —
  # see mintAdminApiToken().
  if [ -n "${STS_URL}" ];
  then
    mintAdminApiToken || exit 1
  fi

  mkdir -p "${CURRENT_DIR}/tests/report" || exit 1
  RUNNER_LOG="${CURRENT_DIR}/tests/report/${MODE}-00-test-runner.log"
  node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"} \
    "--report-dir=${CURRENT_DIR}/tests/report/${MODE}" 2>&1 \
    | tee "${RUNNER_LOG}"
  MODE_RC="${PIPESTATUS[0]}"
  captureRunnerLog "${MODE}" "${RUNNER_LOG}"
  MODES_RUN+=("${MODE}")
  if [ "${MODE_RC}" -ne 0 ];
  then
    RC="${MODE_RC}"
    MODES_FAILED+=("${MODE}")
  fi

  # Torn down between modes, and NOT after the last one — see the header. The
  # next mode needs this project's containers gone before it can bring its own
  # up with different settings.
  if [ "${MODE_INDEX}" -lt "${MODE_COUNT}" ] && [ "${STACK_UP}" = "1" ];
  then
    # THE SERVICE LOG FIRST (2026-09-14). The `down` below removes the
    # container and its log with it, and the only other capture is the LAST
    # mode's, after the loop — so every mode but the last had no
    # 00-mock-sts-service.log, and a postgres-mode failure
    # (sts_directory_bulk_load_ldap, one modify timing out) had nothing on the
    # service side to read. runLogPath() puts it in this mode's report.
    captureContainerLog "${MODE}"
    # NOT `stackTeardown`, which honours --keep-stack and would therefore
    # PRINT rather than remove — leaving the next mode's composeUp to collide
    # with this mode's containers on the same compose project. Between modes
    # the removal is unconditional; the LAST mode's stack is what --keep-stack
    # is about, and that one is never reached by this branch.
    #
    # BOUNDED since 2026-09-10, for ./docker-run-tests.sh's reason and with the
    # same default: a `down` that never returns holds a run open after
    # everything it was asked to do has finished. That launcher's version of
    # this cost CI a green suite; this one would cost a developer a terminal.
    docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
      "${COMPOSE_FILE_ARGS[@]}" --profile xacml \
      down --remove-orphans --volumes > /dev/null 2>&1 || true
    STACK_UP=0
  fi
done

if [ "${MODE_COUNT}" -gt 1 ];
then
  echo ""
  echo "==========================================================="
  echo " ${MODE_COUNT} mode(s): ${MODES_RUN[*]}"
  if [ "${#MODES_FAILED[@]}" -gt 0 ];
  then
    echo " FAILED in: ${MODES_FAILED[*]}"
  else
    echo " all modes passed"
  fi
  echo " reports: tests/report/<mode>/latest"
  echo "==========================================================="
fi

# The container's own account of what it did, kept beside the jobs' logs and
# named as the in-process service's log is, so a report reads the same either
# way. It has to happen HERE: the teardown below removes the container, and a
# removed container takes its log with it — and the LAST mode's stack is the one
# this launcher leaves standing, so this is the last chance at it.
#
# The `[ -d tests/report/latest/logs ]` guard that used to be on this line went
# with the path: runLogPath() decides where the file goes and has a fallback for
# there being no report at all, so a guard here could only have suppressed the
# capture in exactly the case it is most wanted.
# `${MODE}` is the loop variable and still holds the LAST mode run, which is the
# one whose stack is standing. Defaulted, because a `--modes=` naming nothing
# never entered the loop and would leave it unset under `set -u`.
if [ "${STACK_UP}" = "1" ] && [ -n "${MODE:-}" ];
then
  captureContainerLog "${MODE}"
fi

# WHERE EACH MODE'S REPORT LANDED, one block per mode. This named
# `tests/report/latest` until 2026-09-07, which stopped being this run's report
# the day the mode matrix landed: every mode writes under
# tests/report/<mode>/, so the bare `latest` is whatever the last mode-less run
# left behind — a path that exists and holds a report that is not this one's.
REPORT=""
if [ "${LIST}" != "1" ];
then
  for MODE in ${MODES_RUN[@]+"${MODES_RUN[@]}"};
  do
    MODE_REPORT="${CURRENT_DIR}/tests/report/${MODE}/latest/report.html"
    if [ -f "${MODE_REPORT}" ];
    then
      echo ""
      echo "Report (${MODE}):   ${MODE_REPORT}"
      echo "Logs:              ${CURRENT_DIR}/tests/report/${MODE}/latest/logs/"
      echo "JUnit:             ${CURRENT_DIR}/tests/report/${MODE}/latest/report.xml"
      # --open opens the LAST mode's, which is the one whose stack is left up.
      REPORT="${MODE_REPORT}"
    fi
  done
fi
if [ -n "${REPORT}" ] && [ "${OPEN}" = "1" ];
then
  # Best effort and quiet: a headless machine has no opener, and failing to
  # open a report must not change the exit code of the run it describes.
  (xdg-open "${REPORT}" > /dev/null 2>&1 &) || true
fi

if [ "${RC}" -ne 0 ];
then
  echo "Tests FAILED (exit ${RC})."
else
  echo "Tests passed."
fi
exit ${RC}
