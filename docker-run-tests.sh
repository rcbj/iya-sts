#!/bin/bash
#
# docker-run-tests.sh — the WHOLE suite, in containers, on a host that has
# nothing but docker.
#
# It builds and brings up docker-compose-run-tests.yml: the `sts` service from
# this repository's own Dockerfile, and a `tests` container with node, a Chrome
# and this working tree in it. The tests container runs
# tests/run-tests-in-container.sh — all twenty-seven jobs, the Selenium
# admin-console one included — against the service by its compose DNS name, and
# compose exits when it does. This script's exit code is that container's
# (`--exit-code-from tests`), and the stack is always torn down.
#
# THIS IS THE COMMAND CI RUNS (.github/workflows/tests.yml). It is this
# repository's answer to ../id-proto-debugger/docker-run-tests.sh, and the two
# differ in one way worth knowing before porting anything between them: that
# stack has ten services and has to PROVISION most of them — Keycloak realms, a
# WS-Federation side-car, two walt.id services, browser bundles — before a test
# can run. This one has four and provisions almost nothing, because the service
# under test accepts any client, any entityID and any username on first sight.
# That is what it is for. The two things it does prepare are CREDENTIALS rather
# than configuration, each is obtained FROM the service, and both are therefore
# minted once per MODE — the remote PEP's client certificate and an /admin-api
# access token — because the stack is torn down between modes and a fresh
# service remembers neither.
#
# ---------------------------------------------------------------------------
# WHICH LAUNCHER TO USE, AND WHY THERE ARE TWO.
#
#   ./local-run-tests.sh   the DEVELOPMENT loop. The service in a container,
#                          the tests as plain node processes on this machine,
#                          driving this machine's Chrome. Edit a test, re-run
#                          it, no image rebuild. Needs node, npm install, a
#                          Chrome and docker.
#   ./docker-run-tests.sh  THIS. Everything in containers. Needs docker and
#                          nothing else — no node, no npm install, no Chrome —
#                          which is what makes it the CI command and what makes
#                          it the thing to reach for when a run passes locally
#                          and somebody else cannot reproduce it.
#
# They run the SAME twenty-seven jobs through the same runner, so a difference
# between them is a difference in the environment and nothing else, which is
# the whole point of having both.
#
# ---------------------------------------------------------------------------
# WHAT IT WILL NOT TOUCH.
#
# `docker compose up` in this directory gives somebody a mock called `sts` on
# port 8081, quite possibly in another terminal of the same person's. This run
# is its own compose PROJECT (`mock-sts-docker-tests`), its own container names
# (`sts-docker-tests`, `mock-sts-test-runner`) and publishes NO PORT AT ALL, so
# the teardown at the end of this script can never reach that container and the
# start of it can never fail because that container holds the port. The two
# variables at the top are there for a CI agent with two workspaces, where even
# two runs of THIS script must not share a project.
#
# Usage:
#   ./docker-run-tests.sh
#   ./docker-run-tests.sh --no-build          # reuse the images already built
#   ./docker-run-tests.sh --keep-stack        # leave it up to look at
#   ./docker-run-tests.sh --modes=dispatch    # one mode of tests/tools/modes.sh
#                                             # rather than all three, in that
#                                             # file's own spelling
#   ./docker-run-tests.sh --only=crypto --no-browser
#                                             # anything else is passed straight
#                                             # to tests/tools/run-report.js
#   STS_LOG_LEVEL=debug ./docker-run-tests.sh # the service's full record back;
#                                             # this stack runs it at info. See
#                                             # below
#   CONFIG_FILE=./env/docker-tests.js ./docker-run-tests.sh
#                                             # or name the file, which then
#                                             # decides the level by itself
#   STS_MODE_TIMEOUT=2400 ./docker-run-tests.sh
#                                             # seconds a single mode may take
#                                             # before this script stops waiting
#                                             # on docker (default 1500); see
#                                             # THE TWO WALL CLOCKS below
#   STS_TEARDOWN_TIMEOUT=600 ./docker-run-tests.sh
#                                             # the same for every `down` and
#                                             # `logs` (default 300)
#
# ---------------------------------------------------------------------------
# WHAT THIS RUN LEAVES BEHIND TO BE READ AFTERWARDS.
#
# Everything containerized is also everything that DISAPPEARS: this launcher
# tears the stack down after every mode, and a removed container takes its log
# with it. So both containers' logs are collected into the report before that
# happens, beside the per-job logs run-report.js writes:
#
#   tests/report/<mode>/latest/report.html          the run
#   tests/report/<mode>/latest/logs/NN-<job>.log    one job's output
#   tests/report/<mode>/latest/logs/00-mock-sts-service.log
#                                                   the mock's own account of
#                                                   what it issued
#   tests/report/<mode>/latest/logs/00-test-runner.log
#                                                   THE RUNNER'S own output —
#                                                   see captureContainerLogs()
#
# The report is written from inside the tests container, which is root through
# the bind mount, so a log that cannot be put in that directory goes to
# tests/report/<mode>-00-*.log instead — which is also where a run that died
# before writing any report at all puts them.
#
# Exit code is the suite's.
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

# The mode matrix — the same file ./local-run-tests.sh reads. See its header.
# shellcheck source=tests/tools/modes.sh
. "${CURRENT_DIR}/tests/tools/modes.sh"
RUN_MODES=("${STS_ALL_MODES[@]}")

# resolveCompose() and docker_compose(), shared with ./local-run-tests.sh. See
# that file for why they are not duplicated and tests/tools/compose.sh for the
# globals they read.
COMPOSE_SH="${CURRENT_DIR}/tests/tools/compose.sh"
if [ ! -r "${COMPOSE_SH}" ];
then
  echo "Cannot find ${COMPOSE_SH}." >&2
  exit 1
fi
. "${COMPOSE_SH}"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose-run-tests.yml}"
# Overridable so that two runs on one machine — a CI agent with two workspaces —
# do not share a project: compose scopes containers, networks and images by it,
# so two runs sharing one would tear down each other's stack.
COMPOSE_PROJECT="${STS_DOCKER_TEST_PROJECT:-mock-sts-docker-tests}"
STS_CONTAINER_NAME="${STS_CONTAINER_NAME:-sts-docker-tests}"
# THE SECRET STORE AND ITS TWO ONE-SHOT CONTAINERS (2026-09-12). Named for the
# reason every other container here is: `container_name` is machine-wide, and
# this one holds the key-encryption key the `dispatch` mode's data is sealed
# under.
STS_BAO_CONTAINER_NAME="${STS_BAO_CONTAINER_NAME:-sts-docker-tests-openbao}"
STS_BAO_TLS_CONTAINER_NAME="${STS_BAO_TLS_CONTAINER_NAME:-sts-docker-tests-openbao-tls}"
STS_BAO_SEED_CONTAINER_NAME="${STS_BAO_SEED_CONTAINER_NAME:-sts-docker-tests-openbao-seed}"
STS_TESTS_CONTAINER_NAME="${STS_TESTS_CONTAINER_NAME:-mock-sts-test-runner}"
# The appconfig layer the SERVICE reads. EMPTY here and resolved after the
# arguments are parsed, by THE SERVICE'S LOG LEVEL below: which file this stack
# wants is decided by the level, because the candidates differ in nothing else.
# env/docker-tests.js exists for this stack and names it in its own header —
# env/local.js with the log level kept at debug, which is what a failing
# protocol job is read from — and env/test.js is the same file at `info`.
# Setting CONFIG_FILE in the environment pins one and that block leaves it be.
CONFIG_FILE="${CONFIG_FILE:-}"

# ---------------------------------------------------------------------------
# THE TWO WALL CLOCKS, AND WHY A LAUNCHER THAT ALREADY HAS A CI TIMEOUT NEEDS
# THEM (2026-09-10).
#
# tests/tools/compose.sh's docker_compose_bounded() carries the incident: a run
# whose last mode passed every one of its 78 jobs was reported as a FAILURE,
# because compose then sat twenty-three minutes trying to stop a database
# container and the job hit its wall clock with no summary, no exit code and no
# report uploaded.
#
# The job timeout in .github/workflows/tests.yml cannot fix that and is not
# meant to: it is the backstop for a runner that has wedged, and everything it
# catches it catches by throwing the run away. These two are the opposite — a
# bound this script reaches ITSELF, so it can say what happened, capture the
# container logs, keep the report and give the mode the verdict the suite
# actually reached.
#
#   STS_MODE_TIMEOUT      the suite, once, for one mode. The slowest mode ever
#                         measured here is `dispatch` at 16m; 25m is that with
#                         half again on top, which is roughly the spread
#                         between a fast runner and a slow one.
#   STS_TEARDOWN_TIMEOUT  every `down`, and the `logs` that precedes it. These
#                         are seconds of work when they work at all, so five
#                         minutes is already the pathological case.
#
# Both are seconds and both are overridable, because a machine slower than any
# CI runner is a machine somebody will run this on.
# ---------------------------------------------------------------------------
STS_MODE_TIMEOUT="${STS_MODE_TIMEOUT:-1500}"
STS_TEARDOWN_TIMEOUT="${STS_TEARDOWN_TIMEOUT:-300}"

BUILD=1
KEEP_STACK=0
STS_TEST_ARGS="${STS_TEST_ARGS:-}"
DOCKER_SUDO=""
COMPOSE_CMD=""
COMPOSE_ENV=()
STACK_UP=0

# The header of this file IS the usage, printed by reading it back rather than
# by keeping a second copy of it in a here-document — which is the only way the
# two cannot drift apart. The same trick as ./local-run-tests.sh's.
usage()
{
  awk 'NR > 1 { if ($0 !~ /^#/) { exit } sub(/^# ?/, ""); print }' "$0"
}

# ---------------------------------------------------------------------------
# ARGUMENTS. Two are this script's own and everything else is the SUITE's —
# collected into STS_TEST_ARGS, which the compose file hands to the tests
# container and its entrypoint splits. That is what keeps this launcher from
# growing a copy of run-report.js's option list, which would then be a second
# place for an option to be added and forgotten.
# ---------------------------------------------------------------------------
while [ $# -gt 0 ];
do
  case "$1" in
    --no-build)   BUILD=0 ;;
    --keep-stack) KEEP_STACK=1 ;;
    # WHICH MODES TO RUN, AND THIS LAUNCHER LACKED IT UNTIL 2026-09-09.
    # ./local-run-tests.sh has had `--modes=` since the matrix arrived, and the
    # asymmetry cost an afternoon: the failure being chased was in `dispatch`,
    # on a listener only THIS stack publishes, so reproducing it meant running
    # `memory` and `postgres` first every time. Same spelling and same meaning
    # as the other launcher's, so what a developer learns on one works on the
    # other. A run with no `--modes=` is unchanged: all three, in order.
    --modes=*)    IFS=',' read -r -a RUN_MODES <<< "${1#--modes=}" ;;
    --verbose)    set -x ;;
    -h|--help)    usage; exit 0 ;;
    *)            STS_TEST_ARGS="${STS_TEST_ARGS} $1" ;;
  esac
  shift
done
STS_TEST_ARGS="${STS_TEST_ARGS# }"

# ---------------------------------------------------------------------------
# PREFLIGHT. Each of these is a failure this repository has actually had, and
# each of them would otherwise arrive minutes later naming something else.
# ---------------------------------------------------------------------------
preflight()
{
  if ! resolveCompose;
  then
    echo "No usable docker here. This launcher containerizes EVERYTHING —" >&2
    echo "the service and the tests — so there is no fallback to fall back" >&2
    echo "to: without docker there is nothing to run. Either the daemon is" >&2
    echo "not running, or this user cannot reach it and sudo would need a" >&2
    echo "password (this script never prompts for one)." >&2
    echo "" >&2
    echo "./local-run-tests.sh --no-docker runs the same jobs on this" >&2
    echo "machine, if node and a Chrome are installed." >&2
    return 1
  fi

  # THE NESTED SUBMODULE, checked here although both Dockerfiles also guard it.
  # This repository is itself a submodule of the parent project, so node-ldapjs
  # is one level deeper than `git submodule update --init` reaches, and an
  # uninitialised submodule is an EMPTY DIRECTORY: the COPY succeeds, npm
  # installs a package with no `main`, both images build, and the failure
  # arrives at container start as `Cannot find module 'ldapjs'` — a message
  # naming a package rather than a checkout. Catching it before a five-minute
  # build is worth three lines.
  if [ ! -f "${CURRENT_DIR}/node-ldapjs/package.json" ];
  then
    echo "node-ldapjs/ is empty — it is a git SUBMODULE, and this repository" >&2
    echo "is itself one, so it needs:" >&2
    echo "" >&2
    echo "    git submodule update --init --recursive" >&2
    echo "" >&2
    echo "Without it both images build and the service dies at startup with" >&2
    echo "Cannot find module 'ldapjs'." >&2
    return 1
  fi

  # The report's bind mount. Created HERE, by this user, rather than left to
  # docker: the daemon creates a missing mount point as root, and the next
  # `./local-run-tests.sh` on this machine then cannot write its own report
  # into it. It is still written by root INSIDE the container — which is why
  # the workflow chowns it before uploading — but the directory itself stays
  # the developer's.
  mkdir -p "${CURRENT_DIR}/tests/report" || return 1
  return 0
}

preflight || exit 1

# ---------------------------------------------------------------------------
# THE SERVICE'S LOG LEVEL, WHICH IS `info` ON THIS STACK, AND TAKES TWO KNOBS.
#
# THIS BLOCK ARGUED THE OPPOSITE UNTIL IT WAS CHANGED. It forwarded
# STS_LOG_LEVEL only when somebody had set it and said that quietening the
# service was "a choice a run makes rather than one that should be made for
# it". What that missed is that this stack makes the choice cost something a
# hand run does not: the mock logs every request, every response and every
# artifact both before and after signing at `debug`, which is about half of its
# CPU, and on a run that passes the whole record goes into a container that is
# removed at the end. So `info` is the default of THIS SCRIPT and of nothing
# else — no appconfig file is edited and a service started any other way is
# untouched — and `STS_LOG_LEVEL=debug ./docker-run-tests.sh` is the run that
# is being read asking for the record back.
#
# THE SECOND KNOB IS THE APPCONFIG FILE, AND WITHOUT IT THIS WOULD LOOK LIKE IT
# WORKED WHILE DOING ALMOST NOTHING. STS_LOG_LEVEL reaches the loggers
# config.js registers — its own, and the `sts` logger in helpers.js that every
# protocol module destructures. It does NOT reach the six VENDORED modules
# under common/vendored/, which each build a bunyan logger at load from
# `require(process.env.CONFIG_FILE).logLevel` and cannot be edited here. On the
# run that measured this, the level alone left 3,869 debug lines of 3,951 —
# 3,582 of them from `xmldsig`, which is every canonicalization of every signed
# document. `common/config.js`'s registerLogger() header says the same thing
# about the krb5_* codec modules.
#
# So the level picks the FILE too: trace or debug gets env/docker-tests.js and
# therefore the whole record, anything else gets env/test.js, and those two
# differ in one key and a header comment. And it goes the other way round as
# well — a CONFIG_FILE named in the environment with no level beside it turns
# this default OFF rather than being half-overridden, because naming a file
# says something more specific than a level does and a service logging at
# `info` out of a file that says `debug` is nobody's idea of an answer.
#
# The branches rather than a `:-`: an EMPTY STS_LOG_LEVEL is not a harmless
# default, because bunyan throws `unknown level name: ""` from config.js while
# the service is still loading its modules — so it never listens, and on this
# stack that arrives as a healthcheck timeout that names nothing. An exported
# empty one is therefore treated as unset.
#
# LOG_LEVEL — the SUITE's, forwarded below — gets no default because it already
# has one that is `info`: run-report.js reads it as
# `process.env.LOG_LEVEL || 'info'`, so there is nothing here to set.
# ---------------------------------------------------------------------------
STS_LEVEL="${STS_LOG_LEVEL:-}"
if [ -n "${STS_LEVEL}" ];
then
  # A level was asked for. It decides the file too, so that debug means the
  # WHOLE record rather than two thirds of it.
  if [ -z "${CONFIG_FILE}" ];
  then
    case "${STS_LEVEL}" in
      trace|debug) CONFIG_FILE="./env/docker-tests.js" ;;
      *)           CONFIG_FILE="./env/test.js" ;;
    esac
  fi
elif [ -n "${CONFIG_FILE}" ];
then
  # A FILE was named and no level was. The file decides, both halves of it, and
  # this script forwards no level of its own — otherwise pinning the debug file
  # would have produced a service logging at info out of one that says debug,
  # which is the confusing half-answer this whole block exists to avoid.
  :
else
  STS_LEVEL="info"
  CONFIG_FILE="./env/test.js"
fi

# ---------------------------------------------------------------------------
# THE REMOTE PEP'S IDENTITY. The subject is what the certificate carries and
# the CN out of it is what the mock files the registration under; the realm is
# the one tests/vendored/sts_xacml_remote_pep.js creates and LEAVES STANDING
# (no job here removes a realm since 2026-09-06). The stack is built fresh for
# every run, so nothing carries over between them.
# ---------------------------------------------------------------------------
XACML_PEP_SUBJECT="${XACML_PEP_SUBJECT:-CN=remote-pep-1,OU=remote-peps,O=mock-sts}"
XACML_PEP_REALM="${XACML_PEP_REALM:-pep-e2e}"
XACML_PEP_NAME="$(printf '%s' "${XACML_PEP_SUBJECT}" \
  | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
# ABSOLUTE, because compose resolves a bind mount's source against the compose
# file's directory. Inside the run's own report directory so that a private key
# this script generates goes when somebody clears the reports.
XACML_PEP_CERT_DIR="${CURRENT_DIR}/tests/report/pep-credential"

ADMIN_API_CLIENT_SECRET="${ADMIN_API_CLIENT_SECRET:-$(head -c 24 /dev/urandom \
  | base64 | tr -d '/+=' | head -c 24)}"
export ADMIN_API_CLIENT_SECRET

# ---------------------------------------------------------------------------
# THE STACK'S OWN SUBNET (2026-09-12), chosen exactly as ./local-run-tests.sh
# chooses its own and for the same reason — see freeSubnet() in
# tests/tools/compose.sh, which argues it once for both launchers.
#
# docker-compose-run-tests.yml names `172.30.0.0/24` because a realm's SPIFFE
# listeners need addresses that do not move between starts, and a network is
# MACHINE-WIDE however the project is named. So two runs of this launcher — a
# CI agent with two workspaces, which is the case STS_DOCKER_TEST_PROJECT
# exists for — collided on the address space before either brought up a
# container.
#
# THE BASE IS 172.30 AND THE OTHER LAUNCHER'S IS 172.29, which is what keeps
# one run of each off the scan entirely. Placed after the preflight because
# freeSubnet() asks docker, and whether that needs `sudo` is what
# resolveCompose() answers.
# ---------------------------------------------------------------------------
if [ -z "${STS_NETWORK_SUBNET:-}" ];
then
  STS_NETWORK_SUBNET="$(freeSubnet 172.30)"
  if [ -z "${STS_NETWORK_SUBNET}" ];
  then
    echo "No free /24 could be found in 172.30.0.0/16 for the stack's own" >&2
    echo "network. Every one of the 256 overlaps a docker network or a route" >&2
    echo "on this machine — \`docker network ls\` and \`ip route\` say which." >&2
    echo "STS_NETWORK_SUBNET names one explicitly." >&2
    exit 1
  fi
fi
# The addresses inside it, derived from the SUBNET and never from the base:
# the scan hands back `172.30.1.0/24` as readily as `172.30.0.0/24`, and an
# address built from the first two octets would sit outside the network
# compose is about to create.
STS_NETWORK_BITS="${STS_NETWORK_SUBNET##*/}"
STS_NETWORK_PREFIX="${STS_NETWORK_SUBNET%/*}"
STS_NETWORK_PREFIX="${STS_NETWORK_PREFIX%.*}"
STS_SERVICE_ADDRESS="${STS_NETWORK_PREFIX}.10"
STS_SERVICE_EXTRA_IPS="${STS_NETWORK_PREFIX}.11/${STS_NETWORK_BITS}"
STS_SERVICE_EXTRA_IPS="${STS_SERVICE_EXTRA_IPS} ${STS_NETWORK_PREFIX}.12/${STS_NETWORK_BITS}"
STS_SERVICE_EXTRA_IPS="${STS_SERVICE_EXTRA_IPS} ${STS_NETWORK_PREFIX}.13/${STS_NETWORK_BITS}"

COMPOSE_ENV=(
  "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}"
  # The network and the three addresses in it, chosen above. Named here for the
  # reason every other variable in this array is: what a run does not name is
  # the compose file's default, and that default is the same literal for every
  # run on this machine.
  "STS_NETWORK_SUBNET=${STS_NETWORK_SUBNET}"
  "STS_ADDRESS=${STS_SERVICE_ADDRESS}"
  "STS_SPIFFE_GRPC_HOST=${STS_SERVICE_ADDRESS}"
  "STS_EXTRA_IPS=${STS_SERVICE_EXTRA_IPS}"
  "STS_CONTAINER_NAME=${STS_CONTAINER_NAME}"
  "STS_BAO_CONTAINER_NAME=${STS_BAO_CONTAINER_NAME}"
  "STS_BAO_TLS_CONTAINER_NAME=${STS_BAO_TLS_CONTAINER_NAME}"
  "STS_BAO_SEED_CONTAINER_NAME=${STS_BAO_SEED_CONTAINER_NAME}"
  # The keystore, per mode — see tests/tools/modes.sh. `persisted` in the
  # `dispatch` mode is what makes the key-encryption key come out of the store.
  "STS_KEYS_SOURCE=${STS_KEYS_SOURCE:-generated}"
  "STS_TESTS_CONTAINER_NAME=${STS_TESTS_CONTAINER_NAME}"
  "CONFIG_FILE=${CONFIG_FILE}"
  "STS_TEST_ARGS=${STS_TEST_ARGS}"
  # ---------------------------------------------------------------------
  # TLS ON THE MAIN PORT (2026-08-30), and the URL the runner dials with it.
  #
  # BOTH, because they are two variables in the compose file and a stack where
  # they disagree is a stack where thirteen protocol jobs fail on a closed
  # socket. The compose file defaults each to the same answer; naming them
  # here is what makes an operator's `STS_HTTPS=false ./docker-run-tests.sh`
  # actually reach compose, since `sudo` empties the environment — see
  # tests/tools/compose.sh.
  #
  # `sts` and not `localhost`: this runner publishes no port at all, and that
  # hostname is one of the certificate's SANs (common/crypto.js: localhost,
  # sts, sts-mock, sts.example.com, 127.0.0.1). A different name here would be
  # a certificate error in every job rather than a connection error in one.
  # ---------------------------------------------------------------------
  "STS_HTTPS=${STS_HTTPS:-true}"
  "STS_TEST_SERVICE_URL=$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)://sts:8081"
  # ---- the remote PEP and the client certificate it presents --------------
  # The three /xacml/pep endpoints are gated: a PEP is admitted by a client
  # certificate this service VERIFIES, whose subject DN resolves to a directory
  # entry in the `remote-peps` group. Nothing in either image provides that
  # certificate — mintThePepCredential() below makes one between bringing the
  # service up and starting the PEP, which is the only window: pep.js reads the
  # files at process start and never again.
  "XACML_PEP_CERT_DIR=${XACML_PEP_CERT_DIR}"
  "XACML_PEP_TLS_CERT=/certs/pep.crt"
  "XACML_PEP_TLS_KEY=/certs/pep.key"
  # THE REGISTERED NAME IS THE CERTIFICATE'S COMMON NAME. `xacml.js` files a
  # registration under the certificate and ignores the body, so a PEP_NAME that
  # differed would leave `sync.js` polling with a `?pep=` nobody has a row for.
  "XACML_PEP_NAME=${XACML_PEP_NAME}"
  "XACML_PEP_REALM=${XACML_PEP_REALM}"
  "XACML_PEP_URL=http://xacml-pep:9090"
  # ---- the management API's client secret, pinned for this run ------------
  # `/admin-api` requires an access token, and the token is obtained by the
  # seeded `sts-management-api` client with `client_credentials`. That client's
  # secret is minted at every start and is readable only THROUGH the API it
  # unlocks — a bootstrap hole — so `adminApi.clientSecret` exists to pin it.
  #
  # A FRESH SECRET PER RUN rather than a constant in this file: it lives as
  # long as one stack, it never reaches a repository, and two runs on one
  # machine cannot lend each other a token. It is generated at the top of this
  # block rather than inside the mode loop because the CLIENT is seeded once
  # per start and the token is minted per mode — one secret, three tokens.
  "ADMIN_API_CLIENT_SECRET=${ADMIN_API_CLIENT_SECRET}"
)
if [ -n "${STS_LEVEL}" ];
then
  COMPOSE_ENV+=("STS_LOG_LEVEL=${STS_LEVEL}")
fi
# The SUITE's level, forwarded only when it has one; see the block above for
# why it needs no default of its own.
if [ -n "${LOG_LEVEL:-}" ];
then
  COMPOSE_ENV+=("LOG_LEVEL=${LOG_LEVEL}")
fi

# ---------------------------------------------------------------------------
# THE CONTAINERS' OWN LOGS, KEPT BESIDE THE JOBS'.
#
# TWO of them, and the second arrived 2026-09-07. The `sts` one is the mock's
# account of what it actually issued, which is what a failing protocol job is
# read from. The `tests` one is THE RUNNER'S OWN, and until that day it existed
# nowhere at all: this launcher streams it to the terminal through
# `up --abort-on-container-exit` and then removes the container, so everything
# the runner said ABOUT the run — which jobs it chose, the ones it could not
# start and why, the summary, the reason a job was reported SKIPPED — lived in
# a scrollback buffer and in nothing else. The per-job logs run-report.js
# writes are the jobs' output and not the runner's; a job that never started
# has no log there to read, and that is exactly the case somebody comes back to
# a report for.
#
# BOTH HAVE TO BE COLLECTED BEFORE THE TEARDOWN, because a removed container
# takes its log with it. Named `00-` so they sort above the jobs in the
# report's logs directory, exactly as the in-process service's log is named by
# run-report.js.
#
# THE DESTINATION IS PER MODE, AND IT WAS `tests/report/latest` UNTIL
# 2026-09-07 — which had stopped being this run's report the day the mode
# matrix landed. Each mode is handed `--report-dir=tests/report/<mode>`, so
# `latest` under that directory is the one this mode wrote and the bare
# `tests/report/latest` is whatever the last mode-less run left behind, quite
# possibly weeks old. The symptom was the worst kind: a service log sitting
# beside a report it had nothing to do with.
# ---------------------------------------------------------------------------
captureContainerLogs()
{
  local mode="$1"
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  captureOneContainerLog "${mode}" sts   "00-mock-sts-service.log" "Service log"
  captureOneContainerLog "${mode}" tests "00-test-runner.log"      "Runner log"
}

# BESIDE THE JOBS' LOGS IF THAT IS POSSIBLE, AND ONE DIRECTORY UP IF IT IS NOT.
# The report is written from inside the tests container, which runs as ROOT
# through the bind mount, so `tests/report/<mode>/latest/logs` belongs to root
# and this script does not. `tests/report` itself was made by the preflight as
# the user running this, so a file can always be put there. Both cases are
# ordinary rather than exceptional — the second is also what a run that failed
# before writing any report at all gets, which is precisely when these logs are
# the only evidence there is. The fallback name carries the MODE, because three
# modes falling back would otherwise be three writes to one path and only the
# last of them would survive.
captureOneContainerLog()
{
  local mode="$1" service="$2" name="$3" label="$4"
  local logs="${CURRENT_DIR}/tests/report/${mode}/latest/logs"
  local dest="${logs}/${name}"
  if ! ( [ -d "${logs}" ] && touch "${dest}" 2> /dev/null );
  then
    mkdir -p "${CURRENT_DIR}/tests/report" 2> /dev/null || true
    dest="${CURRENT_DIR}/tests/report/${mode}-${name}"
  fi
  # BOUNDED for the reason the teardown below is: this runs against a stack
  # that has just been stopped, and the case worth collecting a log for is
  # exactly the case where that stop did not go well.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    -f "${COMPOSE_FILE}" logs --no-color "${service}" \
    > "${dest}" 2>&1 || true
  printf '%-12s %s\n' "${label}:" "${dest}"
}

# Always tear the stack down, even when the tests fail, so the next run starts
# clean. A TRAP rather than a line at the end: an interrupted run (^C, a failing
# step) would otherwise leave two containers and a network behind, and the next
# run would be the one that had to explain them.
teardown()
{
  if [ "${KEEP_STACK}" = "1" ] && [ "${STACK_UP}" = "1" ];
  then
    echo ""
    echo "The stack is still up, as asked (--keep-stack):"
    echo "  logs:    ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} logs -f sts"
    echo "  a shell: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} exec sts bash"
    echo "  the port is NOT published — to reach the console, add"
    echo "           --service-ports to a \`run\` of the sts service."
    echo "  stop it: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} down -v"
    return 0
  fi
  # BOUNDED. This is the EXIT trap, so an unbounded call here can hold a run
  # open after everything it was asked to do is finished and reported — which
  # is the shape of the 2026-09-10 incident, one function along.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
    > /dev/null 2>&1 || true
}
trap teardown EXIT

# A stack left behind by an interrupted run holds the container names this one
# is about to ask for. Removing it is safe BECAUSE of the project name: this
# reaches `mock-sts-docker-tests` and can never reach the `sts` container a
# plain `docker compose up` in this directory creates.
docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
  -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
  > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# BUILD, THEN RUN.
#
# The build is a step of its own rather than `up --build` so that an image that
# will not build says so as itself: with `--abort-on-container-exit` a failed
# build inside `up` is reported as the stack coming down, and the reason
# scrolls past above it. Both images are rebuilt every run, because the whole
# point is to test what is in the working tree and an image is a snapshot of
# when it was built.
# ---------------------------------------------------------------------------
if [ "${BUILD}" = "1" ];
then
  echo "Building the service and test images from this working tree..."
  if ! docker_compose -f "${COMPOSE_FILE}" build;
  then
    echo "" >&2
    echo "The images would not build. Nothing was run." >&2
    exit 1
  fi
else
  echo "NOT rebuilding (--no-build): the images may be OLDER than this working"
  echo "tree, and they will answer every request either way. Drop --no-build if"
  echo "a result surprises you."
fi

# ---------------------------------------------------------------------------
# THE SERVICE FIRST, THEN THE CREDENTIAL, THEN EVERYTHING ELSE.
# The remote PEP presents a client certificate the mock has to have been told
# to trust, and `pep.js` reads it at process start — so there is exactly one
# window for minting it, between the service answering and the PEP starting.
# That is why this launcher no longer brings the whole stack up in one `up`.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# WAITED FOR WITH COMPOSE'S OWN HEALTHCHECK rather than a probe of our own:
# this host is meant to need docker and nothing else, so there is no curl and
# no node here to ask with. `docker inspect` reads the verdict the healthcheck
# in docker-compose-run-tests.yml already produces.
#
# A FUNCTION SINCE 2026-09-09 because there are two callers now — the PEP's
# certificate and the management API's access token, both of which need the
# service answering and neither of which can be obtained after the runner has
# started. Two copies of a timeout loop is two places for the timeout to differ.
# ---------------------------------------------------------------------------
waitForStsHealthy()
{
  local waited=0 state=""
  while [ "${waited}" -lt "${STS_TEST_READY_SECONDS:-180}" ];
  do
    state="$(docker inspect -f '{{.State.Health.Status}}' \
             "${STS_CONTAINER_NAME}" 2>/dev/null || echo unknown)"
    if [ "${state}" = "healthy" ];
    then
      return 0
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  echo "The mock STS did not become healthy in ${waited}s (last: ${state})." >&2
  return 1
}

# ---------------------------------------------------------------------------
# THE MANAGEMENT API'S ACCESS TOKEN, ONCE PER MODE (2026-09-09).
#
# `/admin-api` requires an OAuth 2.0 access token — audienced to this stack's
# own `/admin-api`, carrying `admin:read` and `admin:write`, which
# `common/roles.js` turns into ADMIN_READ and ADMIN_WRITE and the XACML access
# policy asks for. `run-report.js` inside the runner container hands it to
# every job together with `tools/attach-admin-token.js`, which presents it.
#
# **PER MODE AND NOT ONCE PER RUN, WHICH IS THE WHOLE REASON THIS IS NOT WHERE
# THE PEP'S CERTIFICATE IS MINTED.** That certificate is minted before the mode
# loop and survives it, because it is anchored by a CA this script keeps as
# text. A token cannot be: it is SIGNED by the service's key, that key is
# regenerated on every start in development mode, and this launcher tears the
# whole stack down between modes. A token minted once would verify in mode one
# and be a 401 on every job in modes two and three.
#
# **RUN IN THE SERVICE IMAGE, WHICH IS HOW THIS STAYS "DOCKER AND NOTHING
# ELSE"** — the same argument mintThePepCredential() makes, and cheaper here:
# `admin-api-token.js` requires nothing but node's own `http` and `https`, so
# the repository is mounted read-only and the image supplies the runtime. On
# the project's network, dialling `sts` by the name in the certificate.
# ---------------------------------------------------------------------------
mintAdminApiToken()
{
  local token
  if ! token="$(docker run --rm \
       --network "${COMPOSE_PROJECT}_default" \
       -v "${CURRENT_DIR}:/repo:ro" \
       -e "STS_ADMIN_API_CLIENT_SECRET=${ADMIN_API_CLIENT_SECRET}" \
       -w /usr/src/sts \
       "${STS_IMAGE:-rcbj/sts}" \
       node /repo/tests/tools/admin-api-token.js \
         "$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)://sts:8081" \
       2>&1)";
  then
    echo "" >&2
    echo "Could not obtain an access token for ${COMPOSE_PROJECT}'s" >&2
    echo "/admin-api:" >&2
    echo "  ${token}" >&2
    echo "  Every job that drives that API needs one, so this is the RUN's" >&2
    echo "  failure rather than theirs: without it the report would say" >&2
    echo "  twenty-odd tests are broken when one login is." >&2
    echo "  ADMIN_API_AUTH_REQUIRED=false restores the open API." >&2
    return 1
  fi
  # The last line, because the tool writes the token on stdout and anything
  # else it has to say on stderr — which `2>&1` above has folded in so that a
  # failure is reportable.
  STS_ADMIN_API_TOKEN="$(printf '%s' "${token}" | tail -n 1)"
  export STS_ADMIN_API_TOKEN
  echo "Minted an /admin-api access token (admin:read admin:write)."
  return 0
}

# ---------------------------------------------------------------------------
# THE PEP'S CREDENTIAL, ONCE PER MODE, AGAINST A SERVICE THAT IS ALREADY UP.
#
# **IT WAS ONCE PER RUN UNTIL 2026-09-09 AND THAT WAS WRONG THE MOMENT THIS
# LAUNCHER GREW MODES.** The truststore is a Map in the service's process, this
# loop tears the stack DOWN between modes, and the mock generates a fresh
# self-signed server certificate on every start — so mode 2 and mode 3 met a
# service whose truststore had never been filled, while their PEP container
# came up beside it and started registering. It failed in `postgres` and
# `dispatch` with UNABLE_TO_GET_ISSUER_CERT_LOCALLY, and passed in `memory`
# for a reason worth knowing: compose recreates a container when the resolved
# configuration changes, so the FIRST mode reused the container this ran
# against and the other two did not.
#
# It is not `mintAdminApiToken`'s neighbour by accident: both are credentials
# obtained FROM the service and both are therefore per mode. The window is the
# same one — after `up -d sts` and before the `up` that starts the PEP and the
# runner — and it is the only window there is, because pep.js reads its
# certificate files at process start and never again.
#
# A FAILURE HERE IS A WARNING AND NOT THE MODE'S FAILURE, which is unchanged:
# one job asserts what an unauthenticated PEP cannot do, and the rest of the
# suite has no opinion about this certificate at all.
# ---------------------------------------------------------------------------
mintThePepCredential()
{
  rm -rf "${XACML_PEP_CERT_DIR}"
  mkdir -p "${XACML_PEP_CERT_DIR}"
  echo "Minting the remote PEP's client certificate (${XACML_PEP_SUBJECT})"
  echo "and adding its Root CA to the mock's truststore..."
  # ---------------------------------------------------------------------
  # RUN IN THE SERVICE IMAGE, WHICH IS HOW THIS STAYS "DOCKER AND NOTHING
  # ELSE". The tool is a node script that needs `common/vendored/x509.js` and
  # its three npm packages; this host may have neither node nor node_modules.
  # The service image has both — so the REPOSITORY is mounted read-only for the
  # tool itself (the image deletes ./tests, see the root Dockerfile) and
  # MOCK_STS_DIR points the tool at the image's own copy of the engine.
  #
  # On the project's network, so it dials `sts` by the name in the
  # certificate rather than a published port this stack does not have.
  # ---------------------------------------------------------------------
  if ! docker run --rm \
       --network "${COMPOSE_PROJECT}_default" \
       -v "${CURRENT_DIR}:/repo:ro" \
       -v "${XACML_PEP_CERT_DIR}:/out" \
       -e MOCK_STS_DIR=/usr/src/sts \
       -w /usr/src/sts \
       "${STS_IMAGE:-rcbj/sts}" \
       node /repo/tests/tools/pep-credential.js \
         --url="$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)://sts:8081" \
         --out=/out --subject="${XACML_PEP_SUBJECT}" > /dev/null;
  then
    echo "" >&2
    echo "WARNING: the remote PEP's client certificate could not be minted." >&2
    echo "         That container will start without one, every /xacml/pep" >&2
    echo "         call it makes will be refused by the access policy, and" >&2
    echo "         sts_xacml_remote_pep will say so. The rest of the run is" >&2
    echo "         unaffected." >&2
    echo "" >&2
  fi
  # THE FILES HAVE TO BE READABLE INSIDE THE PEP CONTAINER, which runs as a
  # different user from whatever wrote them. `pep-credential.js` chmods the key
  # to 0600 for the ordinary reason and that is 0600 for the WRITER — so it is
  # relaxed here, deliberately and narrowly, because this key exists for the
  # length of one test run and protects nothing.
  chmod 0644 "${XACML_PEP_CERT_DIR}/pep.key" 2>/dev/null || true
  return 0
}

# ---------------------------------------------------------------------------
# WHAT A MODE'S BOUND BEING REACHED ACTUALLY MEANS (2026-09-10).
#
# `up --abort-on-container-exit --exit-code-from tests` does two things in one
# call, and only the first of them is the suite: it runs the stack until the
# runner exits, and THEN stops every other container before reporting that
# runner's exit code. So by the time the second half can go wrong, the answer
# already exists — it is recorded on a container that has exited, and docker
# will hand it over.
#
# **THAT IS THE WHOLE OF THIS FUNCTION, AND IT IS WHY THE BOUND IS SAFE TO
# ADD.** Without it a bound would be a new way to throw a green suite away —
# faster than the CI timeout did on 2026-09-10, and just as wrong. With it,
# the two cases the bound can catch are told apart by ASKING:
#
#   the runner EXITED      the suite finished and the stop phase is what hung.
#                          Its exit code is the mode's verdict, exactly as
#                          `--exit-code-from` would have reported it, and the
#                          stack being wedged is a warning.
#   the runner is running   the suite itself did not finish inside the bound.
#   (or docker cannot      That is a failure of the mode and is reported as
#    say)                  one — 124 is `timeout`'s own code and is kept.
#
# It writes its reasoning to stderr and the code to stdout, because it is read
# through a command substitution. `docker inspect` and not `compose ps`: this
# has to work while compose is the thing that is stuck, and the container name
# is one this launcher already pins for the healthcheck loop.
# ---------------------------------------------------------------------------
recoverModeVerdict()
{
  local mode="$1" bounded="$2" state="" code=""
  echo "" >&2
  echo "Mode ${mode} did not finish within ${STS_MODE_TIMEOUT}s of compose" >&2
  echo "being asked to run it. Asking docker what the runner actually did." >&2
  state="$(docker inspect -f '{{.State.Status}}' \
           "${STS_TESTS_CONTAINER_NAME}" 2>/dev/null || echo unknown)"
  if [ "${state}" != "exited" ];
  then
    echo "The test runner is '${state}' — the SUITE did not finish, so this" >&2
    echo "mode is a failure. Raise STS_MODE_TIMEOUT if the run was merely" >&2
    echo "slow; the container log captured below is what says which." >&2
    echo "${bounded}"
    return 0
  fi
  code="$(docker inspect -f '{{.State.ExitCode}}' \
          "${STS_TESTS_CONTAINER_NAME}" 2>/dev/null || echo "")"
  case "${code}" in
    ''|*[!0-9]*)
      echo "The test runner had exited but docker would not say with what." >&2
      echo "Reporting the mode as failed, because a verdict nobody can read" >&2
      echo "is not a pass." >&2
      echo "${bounded}"
      return 0
      ;;
  esac
  # -------------------------------------------------------------------------
  # 128+N IS A SIGNAL AND NOT A VERDICT, AND THIS BRANCH IS THE ONE THE FIRST
  # VERSION GOT WRONG.
  #
  # Reaching the bound SIGTERMs compose, and compose's own handler answers a
  # SIGTERM by stopping the stack — the runner container included. So a suite
  # that was still going when the bound fired is a container that has EXITED by
  # the time this function looks at it, killed 137 by a teardown this script
  # caused. Read as a verdict that is a mode failing, which is the right
  # outcome for the wrong reason and with an explanation that is simply false:
  # measured on 2026-09-10 with STS_MODE_TIMEOUT=100, the launcher announced
  # "THE SUITE FINISHED" about a run that was four minutes from finishing.
  #
  # A code at or above 128 means the process was signalled. Only a smaller one
  # is something the runner DECIDED, which is what makes it the answer
  # `--exit-code-from` would have reported. Written as the POSIX convention
  # rather than as "0 or 1", so that a runner which grows a third exit code is
  # not silently mis-read here.
  # -------------------------------------------------------------------------
  if [ "${code}" -ge 128 ];
  then
    echo "The test runner had exited ${code} — which is a SIGNAL and not an" >&2
    echo "answer: reaching the bound stops the stack, and that is what killed" >&2
    echo "it. The suite did not finish, so this mode is a failure. Raise" >&2
    echo "STS_MODE_TIMEOUT if the run was merely slow." >&2
    echo "${bounded}"
    return 0
  fi
  echo "The test runner had already exited ${code}: THE SUITE FINISHED and" >&2
  echo "what hung is compose stopping the rest of the stack. That is the" >&2
  echo "mode's verdict, and the wedged stack is a warning rather than a" >&2
  echo "result — see the report and the container logs below." >&2
  echo "${code}"
  return 0
}

echo "Bringing up ${COMPOSE_PROJECT}: the mock STS, the remote PEP and the"
echo "test runner."
if [ -n "${STS_TEST_ARGS}" ];
then
  echo "Passing to the suite: ${STS_TEST_ARGS}"
fi

# --abort-on-container-exit stops the stack as soon as the tests container
# finishes; --exit-code-from tests makes compose — and therefore this script —
# exit with ITS status rather than with the service's, which is always 0 or 137
# and says nothing about the suite.
# ===========================================================================
# ONCE PER MODE. `tests/tools/modes.sh` is the one definition of the three, and
# ./local-run-tests.sh reads the same file — so the launcher CI runs and the one
# a developer runs cannot come to disagree about what a green run covers.
#
# EACH MODE GETS ITS OWN REPORT TREE, and the stack is brought DOWN between
# modes: this launcher's whole point is that the runner is a container too, so
# two modes cannot share a compose project any more than two runs can.
#
# Unlike ./local-run-tests.sh, NOTHING IS LEFT UP at the end. That launcher
# keeps its last stack for debugging; this one is what CI runs, and a CI job
# that left containers behind would leak them run after run.
# ===========================================================================
RC=0
MODES_RUN=()
MODES_FAILED=()
MODE_COUNT="${#RUN_MODES[@]}"
MODE_INDEX=0

# THE STACK'S ENVIRONMENT AS IT IS BEFORE ANY MODE HAS ADDED TO IT. Each pass
# rebuilds COMPOSE_ENV from this rather than appending to whatever the last one
# left, which is the same rule modes.sh states about the modes themselves: a
# mode that inherited the previous mode's settings would be a mode that never
# ran, reported as a pass.
BASE_COMPOSE_ENV=(${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"})

for MODE in "${RUN_MODES[@]}";
do
  MODE_INDEX=$((MODE_INDEX + 1))
  echo ""
  echo "==========================================================="
  echo " MODE ${MODE_INDEX} of ${MODE_COUNT}: ${MODE}"
  echo " $(stsModeDescription "${MODE}")"
  echo "==========================================================="

  # The mode's environment, added to what compose is already given. Every mode
  # names every variable it cares about — see modes.sh — so a later mode cannot
  # inherit an earlier one's.
  MODE_ENV=()
  while IFS= read -r line;
  do
    [ -n "${line}" ] && MODE_ENV+=("${line}")
  done < <(stsModeEnv "${MODE}")

  # WHERE THE RUNNER WRITES. The tests container has this repository mounted, so
  # the path is the one inside it and the report lands in the host tree beside
  # every other mode's.
  MODE_ENV+=("STS_TEST_REPORT_DIR=/usr/src/sts/tests/report/${MODE}")

  # -------------------------------------------------------------------------
  # THE SERVICE FIRST, THEN ITS CREDENTIALS, THEN THE RUNNER (2026-09-09).
  #
  # This loop used to be one `up`. It is two because a credential that has to
  # be obtained FROM the service cannot be obtained after the container that
  # spends it has started, and `--abort-on-container-exit` means the runner
  # begins the moment compose brings it up. Both credentials live in the gap:
  # the PEP's certificate, whose anchor has to be in the truststore before that
  # container's first handshake, and the management API's token.
  #
  # `up -d sts` starts its dependencies too, so the database comes with it in
  # the two modes that have one.
  # -------------------------------------------------------------------------
  #
  # THE MODE'S VARIABLES REACH COMPOSE THROUGH COMPOSE_ENV AND NOT THROUGH
  # `env`. `docker_compose` is a SHELL FUNCTION — tests/tools/compose.sh — so
  # `env NAME=value docker_compose ...` asks the kernel to execute a program by
  # that name and gets `env: 'docker_compose': No such file or directory`, which
  # is what every mode of this launcher did on its first run. That function
  # already prefixes COMPOSE_ENV onto the compose command for the `sudo` reason
  # its own header gives, so a mode has a channel and needs no second one.
  COMPOSE_ENV=(
    ${BASE_COMPOSE_ENV[@]+"${BASE_COMPOSE_ENV[@]}"}
    ${MODE_ENV[@]+"${MODE_ENV[@]}"}
  )

  STACK_UP=1
  MODE_RC=0
  if ! docker_compose -f "${COMPOSE_FILE}" up -d sts;
  then
    echo "The mock STS would not start in mode ${MODE}. Nothing was run." >&2
    MODE_RC=1
  elif ! waitForStsHealthy;
  then
    echo "The mock STS never became healthy in mode ${MODE}. Nothing was" >&2
    echo "run — see the container log captured below." >&2
    MODE_RC=1
  else
    # THE PEP'S CERTIFICATE FIRST, because the anchor has to be in this
    # service's truststore before the container that presents it starts — and
    # the `up` below is what starts it. See the function's header.
    mintThePepCredential

    # THE ROOT CA AS TEXT, SO THAT sts_xacml_remote_pep.js CAN PUT IT BACK.
    #
    # The truststore is a Map in the service's process that ANY job can empty:
    # `POST /tls/trust/clear` needs no credential, and a job exercising the
    # truststore is entitled to use it. Nothing noticed until 2026-09-06, when
    # a client certificate stopped being a turnstile — this container's pull,
    # its heartbeat and its PIP queries all resolve a VERIFIED chain now, so
    # one such job left it authenticating as nobody for the rest of the run,
    # reporting UNABLE_TO_GET_ISSUER_CERT_LOCALLY about an anchor posted
    # correctly before anything started.
    #
    # **THE FIX IS NOT TO STOP OTHER JOBS CLEARING IT.** It is for the job that
    # DEPENDS on this anchor to re-establish it, which is what every other
    # credential in that file already does for itself. It travels as TEXT
    # because the runner container cannot see the directory the PEP mounts.
    #
    # Read per mode, because the certificate above is minted per mode.
    if [ -f "${XACML_PEP_CERT_DIR}/ca.crt" ];
    then
      COMPOSE_ENV+=("XACML_PEP_CA_PEM=$(cat "${XACML_PEP_CERT_DIR}/ca.crt")")
    fi

    if ! mintAdminApiToken;
    then
      MODE_RC=1
    else
      COMPOSE_ENV+=("STS_ADMIN_API_TOKEN=${STS_ADMIN_API_TOKEN}")
      docker_compose_bounded "${STS_MODE_TIMEOUT}" -f "${COMPOSE_FILE}" up \
        --abort-on-container-exit --exit-code-from tests
      MODE_RC=$?
      if [ "${MODE_RC}" -ge 124 ];
      then
        MODE_RC="$(recoverModeVerdict "${MODE}" "${MODE_RC}")"
      fi
    fi
  fi
  MODES_RUN+=("${MODE}")
  if [ "${MODE_RC}" -ne 0 ];
  then
    RC="${MODE_RC}"
    MODES_FAILED+=("${MODE}")
  fi

  captureContainerLogs "${MODE}"

  # Down between every mode INCLUDING the last — see the header. Bounded, so
  # that a stack which will not come down costs the next mode a warning rather
  # than the whole run's remaining budget.
  if ! docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
       -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
       > /dev/null 2>&1;
  then
    echo "The stack did not come down cleanly after mode ${MODE}." >&2
    echo "That is NOT a verdict on the suite — the mode's result above is." >&2
  fi
  STACK_UP=0
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

# WHERE EACH MODE'S REPORT LANDED. One block per mode rather than one naming
# `tests/report/latest`, which is what this said until 2026-09-07 and had been
# pointing at whatever the last mode-less run left behind since the mode matrix
# landed — a path that exists, contains a report, and is not this run's.
#
# There is no captureContainerLogs() call here any more, and there was one
# until 2026-09-07. It could never do anything: the loop above tears the stack
# down after every mode including the last, so STACK_UP is 0 by the time
# control reaches this line and the function returned immediately. The logs are
# collected inside the loop, which is the only place the containers still
# exist.
for MODE in ${MODES_RUN[@]+"${MODES_RUN[@]}"};
do
  REPORT="${CURRENT_DIR}/tests/report/${MODE}/latest/report.html"
  if [ -f "${REPORT}" ];
  then
    echo ""
    echo "Report (${MODE}):   ${REPORT}"
    echo "Logs:              ${CURRENT_DIR}/tests/report/${MODE}/latest/logs/"
    echo "JUnit:             ${CURRENT_DIR}/tests/report/${MODE}/latest/report.xml"
  fi
done
# Said once, plainly, because the first thing anybody does with a report is
# try to delete the old ones. It is written from inside the container, which
# is root; the workflow chowns it before uploading and a person can too:
#   sudo chown -R "$(id -u):$(id -g)" tests/report

if [ "${RC}" -ne 0 ];
then
  echo "Tests FAILED (exit ${RC})."
  exit "${RC}"
fi

cat <<'EOF'
   _   _ _   _            _                                  _
  / \ | | | | |_ ___  ___| |_ ___   _ __   __ _ ___ ___  ___| |
 / _ \| | | | __/ _ \/ __| __/ __| | '_ \ / _` / __/ __|/ _ \ |
/ ___ \ | | | ||  __/\__ \ |_\__ \ | |_) | (_| \__ \__ \  __/_|
/_/   \_\_|_|  \__\___||___/\__|___/ | .__/ \__,_|___/___/\___(_)
                                     |_|
EOF

exit 0
