#!/bin/bash
#
# run-tests.sh — THE ONE LAUNCHER FOR THE WHOLE SUITE, WHEREVER THE SERVICE IS
# (2026-09-21; it was ./run-tests.sh, which only knew the first target).
#
#   ./run-tests.sh                          a compose stack here, once per mode
#   ./run-tests.sh --target=aws:testidp     an AWS environment that exists
#   ./run-tests.sh --target=aws-ephemeral   apply `ci`, test it, destroy it
#
# The targets are argued under THE TARGET below. What follows until then is
# the default, `local`, which is also what CI runs.
#
# It builds and brings up docker-compose-run-tests.yml: the `sts` service from
# this repository's own Dockerfile, and a `tests` container with node, a Chrome
# and this working tree in it. The tests container runs
# tests/run-tests-in-container.sh — every job (tests/vendored/MANIFEST.js and
# tests/run.js's discovery are the count), the Selenium admin-console one
# included — against the service by its compose DNS name, and
# compose exits when it does. This script's exit code is that container's
# (`--exit-code-from tests`), and the stack is always torn down.
#
# THIS IS THE COMMAND CI RUNS (.github/workflows/tests.yml). It is this
# repository's answer to ../id-proto-debugger/docker-run-tests.sh, and the two
# differ in one way worth knowing before porting anything between them: that
# stack has ten services and has to PROVISION most of them — Keycloak realms, a
# WS-Federation side-car, two walt.id services, browser bundles — before a test
# can run. This one has a handful (the service, its database and secret store,
# the remote PEP and the runner) and provisions almost nothing, because the
# service under test accepts any client, any entityID and any username on first
# sight.
# That is what it is for. The two things it does prepare are CREDENTIALS rather
# than configuration, each is obtained FROM the service, and both are therefore
# minted once per MODE — the remote PEP's client certificate and an /admin-api
# access token — because the stack is torn down between modes and a fresh
# service remembers neither.
#
# ---------------------------------------------------------------------------
# WHICH LAUNCHER TO USE, AND WHY THIS IS THE ONLY ONE FOR THE WHOLE SUITE.
#
#   ./run-tests.sh         THIS. Every job, everything in containers. Needs
#                          docker and nothing else for `local` — no node, no npm
#                          install, no Chrome — which is what makes it the CI
#                          command; the AWS targets add the AWS CLI and your
#                          credentials.
#   ./docker-npm-test.sh   the in-process suite alone, in the tests image
#                          (`--only=<substring>`, `--list`).
#   ./run-coverage.sh      a coverage run, on its own; see its header.
#
# deploy/aws/run-suite.sh and deploy/aws/run-suite-in-aws.sh were launchers of
# their own until 2026-09-21 (the second was deleted that day; see THE TARGET) and are the AWS targets' machinery now — see THE
# TARGET. There were two whole-suite launchers until 2026-09-16. The other,
# ./local-run-tests.sh, ran the jobs as node processes on this machine against
# a service container, and it was removed when #50 made the service partly
# TypeScript compiled only inside an image build: a job run on a checkout
# meets the refusal in common/compiled_tree.js (STS-CORE-0093).
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
#   ./run-tests.sh
#   ./run-tests.sh --no-build                 # reuse the images already built
#   ./run-tests.sh --keep-stack               # leave the LAST mode's stack
#                                             # running, to look at
#   ./run-tests.sh --modes=single-node        # one mode of tests/tools/modes.sh
#                                             # rather than all three (memory,
#                                             # single-node, cluster), in that
#                                             # file's own spelling
#   ./run-tests.sh --modes=memory,single-node # what CI's `tests` job runs; its
#                                             # `cluster` job runs the third
#                                             # (2026-09-21)
#   ./run-tests.sh --only=crypto --no-browser
#                                             # anything else is passed straight
#                                             # to tests/tools/run-report.js
#   STS_LOG_LEVEL=debug ./run-tests.sh        # the service's full record back;
#                                             # this stack runs it at info. See
#                                             # below
#   CONFIG_FILE=./env/docker-tests.js ./run-tests.sh
#                                             # or name the file, which then
#                                             # decides the level by itself
#   STS_MODE_TIMEOUT=2400 ./run-tests.sh
#                                             # seconds a single mode may take
#                                             # before this script stops waiting
#                                             # on docker (default 3000); see
#                                             # THE TWO WALL CLOCKS below
#   STS_TEARDOWN_TIMEOUT=600 ./run-tests.sh
#                                             # the same for every `down` and
#                                             # `logs` (default 300)
#   STS_TEST_CONFORMANCE_MODES=memory,single-node ./run-tests.sh
#                                             # the modes that run the OpenID
#                                             # conformance suite's FAPI plans
#                                             # (#176; default `memory`, empty
#                                             # for none); see below
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

# The mode matrix. See tests/tools/modes.sh's header.
# shellcheck source=tests/tools/modes.sh
. "${CURRENT_DIR}/tests/tools/modes.sh"
RUN_MODES=("${STS_ALL_MODES[@]}")

# resolveCompose() and docker_compose(), shared with ./run-coverage.sh. See
# tests/tools/compose.sh for why they are not duplicated and for the globals
# they read.
COMPOSE_SH="${CURRENT_DIR}/tests/tools/compose.sh"
if [ ! -r "${COMPOSE_SH}" ];
then
  echo "Cannot find ${COMPOSE_SH}." >&2
  exit 1
fi
. "${COMPOSE_SH}"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose-run-tests.yml}"
# ---------------------------------------------------------------------------
# THE `cluster` MODE'S LAYER (2026-09-14, issue #46): a second service
# container and an HAProxy load balancer, over the file above, and the runner
# and the remote PEP pointed at the balancer. Every compose command in this
# file goes through COMPOSE_FILE_ARGS, which the mode loop sets per mode, so
# no other mode's stack reads the layer. The layer's own header argues its
# contents; tests/tools/modes.sh defines the mode.
CLUSTER_COMPOSE_FILE="tests/docker-compose-run-tests-cluster.yml"
COMPOSE_FILE_ARGS=(-f "${COMPOSE_FILE}")
# Overridable so that two runs on one machine — a CI agent with two workspaces —
# do not share a project: compose scopes containers, networks and images by it,
# so two runs sharing one would tear down each other's stack.
COMPOSE_PROJECT="${STS_DOCKER_TEST_PROJECT:-mock-sts-docker-tests}"
STS_CONTAINER_NAME="${STS_CONTAINER_NAME:-sts-docker-tests}"
# THE SECRET STORE AND ITS TWO ONE-SHOT CONTAINERS (2026-09-12). Named for the
# reason every other container here is: `container_name` is machine-wide, and
# this one holds the key-encryption key the production modes' data is sealed
# under (`single-node` and `cluster`).
STS_BAO_CONTAINER_NAME="${STS_BAO_CONTAINER_NAME:-sts-docker-tests-openbao}"
STS_BAO_TLS_CONTAINER_NAME="${STS_BAO_TLS_CONTAINER_NAME:-sts-docker-tests-openbao-tls}"
STS_BAO_SEED_CONTAINER_NAME="${STS_BAO_SEED_CONTAINER_NAME:-sts-docker-tests-openbao-seed}"
STS_TESTS_CONTAINER_NAME="${STS_TESTS_CONTAINER_NAME:-mock-sts-test-runner}"
# The `cluster` mode's node B and load balancer (2026-09-14), named for the
# same reason.
STS2_CONTAINER_NAME="${STS2_CONTAINER_NAME:-sts-docker-tests-node-b}"
STS_LB_CONTAINER_NAME="${STS_LB_CONTAINER_NAME:-sts-docker-tests-lb}"
# The OpenID conformance suite's three (#176), named for the same reason.
STS_CONFORMANCE_MONGO_CONTAINER_NAME="${STS_CONFORMANCE_MONGO_CONTAINER_NAME:-sts-docker-tests-conformance-mongo}"
STS_CONFORMANCE_SERVER_CONTAINER_NAME="${STS_CONFORMANCE_SERVER_CONTAINER_NAME:-sts-docker-tests-conformance-server}"
STS_CONFORMANCE_NGINX_CONTAINER_NAME="${STS_CONFORMANCE_NGINX_CONTAINER_NAME:-sts-docker-tests-conformance-nginx}"
# And the one that mints the suite's listener certificate (#187).
STS_CONFORMANCE_TLS_CONTAINER_NAME="${STS_CONFORMANCE_TLS_CONTAINER_NAME:-sts-docker-tests-conformance-tls}"
# ---------------------------------------------------------------------------
# AND THE IMAGE TAGS, WHEN A PROJECT IS NAMED (2026-09-14). A tag is
# machine-wide like a container name: this launcher builds once and then
# `up`s each mode from whatever `rcbj/sts` points at by then, so another
# checkout building that name mid-run changed the code under the remaining
# modes with every job still green. A named project builds its own tags; an
# unnamed run keeps the compose files' names.
# ---------------------------------------------------------------------------
if [ -n "${STS_DOCKER_TEST_PROJECT:-}" ];
then
  STS_IMAGE="${STS_IMAGE:-rcbj/sts:${COMPOSE_PROJECT}}"
  XACML_PEP_IMAGE="${XACML_PEP_IMAGE:-rcbj/xacml-pep:${COMPOSE_PROJECT}}"
  STS_TESTS_IMAGE="${STS_TESTS_IMAGE:-rcbj/mock-sts-tests:${COMPOSE_PROJECT}}"
fi
# The appconfig layer the SERVICE reads. EMPTY here and resolved after the
# arguments are parsed, by THE SERVICE'S LOG LEVEL below: which file this stack
# wants is decided by the level, because the candidates differ in nothing else.
# env/docker-tests.js exists for this stack and names it in its own header —
# env/local.js with a comment of its own — and env/test.js is the same file.
# All three are at `info` since 2026-09-12; see THE SERVICE'S LOG LEVEL below.
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
#   STS_MODE_TIMEOUT      the suite, once, for one mode — every mode but
#                         `cluster`, which has a bound of its own
#                         (STS_CLUSTER_MODE_TIMEOUT, 100m; tests/tools/modes.sh,
#                         stsModeTimeout(), says why). The slowest mode ever
#                         measured here was `dispatch` at 16m when this was
#                         25m; the suite has grown to 225 jobs since, and on
#                         2026-09-14 `dispatch` was killed at 25m at job 203
#                         of 225 with nothing wrong. 50m is that measurement
#                         (about 28m) with most of it again on top.
#   STS_TEARDOWN_TIMEOUT  every `down`, and the `logs` that precedes it. These
#                         are seconds of work when they work at all, so five
#                         minutes is already the pathological case.
#
# Both are seconds and both are overridable, because a machine slower than any
# CI runner is a machine somebody will run this on.
# ---------------------------------------------------------------------------
STS_MODE_TIMEOUT="${STS_MODE_TIMEOUT:-3000}"
# The bound a mode gets unless modes.sh names one of its own; each mode's is
# set at the top of the loop below.
STS_BASE_MODE_TIMEOUT="${STS_MODE_TIMEOUT}"
STS_TEARDOWN_TIMEOUT="${STS_TEARDOWN_TIMEOUT:-300}"

# ---------------------------------------------------------------------------
# THE OPENID FOUNDATION'S CONFORMANCE SUITE (#176, 2026-09-24).
#
# rcbj's decision on #142: "a job in ./run-tests.sh that fails when a module
# fails". The jobs are tests/vendored/sts_fapi_conformance.js and, since #187,
# five more — OpenID Connect, Shared Signals, OpenID Federation, OpenID4VCI
# and OpenID4VP (tests/CLAUDE.md, *The other plans*); the suite is four
# containers in docker-compose-run-tests.yml behind the `conformance` compose
# profile — its server (a JVM), its MongoDB, its nginx and the one-shot that
# mints the nginx a certificate — started only in the modes named here, and
# the jobs are SKIPPED, with the reason, in every other one.
#
#   STS_TEST_CONFORMANCE_MODES   a comma list of modes, in modes.sh's
#                                spelling (default `memory`); empty runs the
#                                suite in none. `memory` because the FAPI-CIBA
#                                plan approves through a development-mode test
#                                control, and every plan runs in a realm of
#                                its own under the FAPI profile it tests, so a
#                                persisting mode would check the same rules
#                                over again for sixteen more minutes.
#   STS_CONFORMANCE_TIMEOUT      seconds ADDED to such a mode's bound (default
#                                10800). #176's four plans took about sixteen
#                                minutes; with #187's the six jobs took about
#                                two hours and a quarter on 2026-09-24 (the
#                                OpenID Connect job alone about ninety
#                                minutes), and the JVM a minute to start.
# ---------------------------------------------------------------------------
STS_TEST_CONFORMANCE_MODES="${STS_TEST_CONFORMANCE_MODES-memory}"
STS_CONFORMANCE_TIMEOUT="${STS_CONFORMANCE_TIMEOUT:-10800}"

BUILD=1
KEEP_STACK=0
TARGET=local
MODES_GIVEN=0
STS_TEST_ARGS="${STS_TEST_ARGS:-}"
DOCKER_SUDO=""
COMPOSE_CMD=""
COMPOSE_ENV=()
STACK_UP=0

# The header of this file IS the usage, printed by reading it back rather than
# by keeping a second copy of it in a here-document — which is the only way the
# two cannot drift apart. The same trick as ./run-coverage.sh's.
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
    # ./local-run-tests.sh (removed 2026-09-16) had `--modes=` since the
    # matrix arrived, and the asymmetry cost an afternoon: the failure being
    # chased was in `dispatch`, on a listener only THIS stack publishes, so
    # reproducing it meant running `memory` and `postgres` first every time.
    # It took the other launcher's spelling and meaning. A run with no
    # `--modes=` is unchanged: all three, in order.
    --modes=*)    IFS=',' read -r -a RUN_MODES <<< "${1#--modes=}"
                  MODES_GIVEN=1 ;;
    # WHERE THE SUITE RUNS (2026-09-21) — see *THE TARGET* below.
    --target=*)   TARGET="${1#--target=}" ;;
    --verbose)    set -x ;;
    -h|--help)    usage; exit 0 ;;
    *)            STS_TEST_ARGS="${STS_TEST_ARGS} $1" ;;
  esac
  shift
done
STS_TEST_ARGS="${STS_TEST_ARGS# }"

# ---------------------------------------------------------------------------
# THE TARGET: WHERE THE SUITE RUNS (2026-09-21).
#
# **THIS IS THE ONE LAUNCHER FOR THE WHOLE SUITE, WHEREVER THE SERVICE IS.**
# There were three until that day — this file as ./run-tests.sh (a
# compose stack here, once per mode), deploy/aws/run-suite.sh (an existing AWS
# environment, driven from this machine) and the apply-test-destroy sequence
# that only .github/workflows/aws-cluster.yml performed — and rcbj asked for
# one. `run-suite.sh` is not deleted: it is what BOTH AWS targets run, and it is
# not a launcher any more; this is. `run-suite-in-aws.sh` — the suite as a task
# inside the VPC, behind the Terraform image's `suite` action — WAS deleted
# that day, with `environment/runner.tf`: rcbj asked for one AWS suite for an
# ephemeral environment and a long-lived one alike, and `run-suite.sh` already
# ran every job, the two that need a callback in a task of their own.
#
#   --target=local          (the default) the compose stack below, once per
#                           mode of tests/tools/modes.sh. Both halves: the
#                           in-process files AND every protocol job, in every
#                           mode — which is what "every mode runs all jobs"
#                           means and what tests/report/<mode>/ records.
#   --target=aws:<env>      an AWS environment that already EXISTS, e.g.
#                           aws:testidp. deploy/aws/run-suite.sh <env>: the
#                           protocol jobs from here, the two that need the
#                           service to call back in an ephemeral task in the
#                           VPC, one merged report in tests/report/aws-<env>.
#                           Never destroys the environment.
#   --target=aws-ephemeral[:<env>]
#                           build and push this tree's images, APPLY <env>
#                           (default `ci`), run deploy/aws/run-suite.sh against
#                           it from this machine, and
#                           DESTROY it — on success, failure or interrupt. It
#                           refuses an environment that already exists, so it
#                           can never destroy something it did not create, and
#                           refuses `testidp` by name.
#
# **AN AWS TARGET RUNS THE PROTOCOL HALF ONLY, AND CANNOT DO OTHERWISE.** The
# in-process files require this tree's modules and start processes of their
# own; there is nothing in them to point at a URL. And an AWS environment is in
# the ONE mode Terraform built it in (`testidp` is product), so `--modes=` means
# nothing there and is refused rather than ignored.
#
# **THE SUITE'S OWN OPTIONS DO NOT CROSS TO AN AWS TARGET**, because
# run-report.js's `--only=` is a substring filter and the AWS runners take a
# comma-separated list of job FILES. Rather than translate one into the other
# and be subtly wrong, an AWS target refuses them and names the variables those
# runners already read: STS_SUITE_ONLY, STS_SUITE_EXCLUDE, STS_SUITE_KEEP_REALMS
# and STS_SUITE_JOB_TIMEOUT_MS (deploy/aws/CLAUDE.md).
# ---------------------------------------------------------------------------
awsTargetRefusals()
{
  local problems=()
  [ "${MODES_GIVEN}" = "1" ] && \
    problems+=("--modes= (an AWS environment is in the one mode it was built in)")
  [ "${KEEP_STACK}" = "1" ] && \
    problems+=("--keep-stack (there is no compose stack; aws:<env> never destroys, and STS_SUITE_KEEP_ENVIRONMENT=1 keeps an ephemeral one)")
  [ -n "${STS_TEST_ARGS}" ] && \
    problems+=("'${STS_TEST_ARGS}' (use STS_SUITE_ONLY / STS_SUITE_EXCLUDE, comma-separated job files)")
  if [ "${#problems[@]}" -gt 0 ];
  then
    echo "--target=${TARGET} does not take:" >&2
    printf '  %s\n' "${problems[@]}" >&2
    exit 2
  fi
}

# The tag an ephemeral run pushes its images under: the commit, and a digest of
# whatever in the working tree is not committed, so two runs of one tree reuse
# a tag and a changed tree never does. The same derivation run-suite.sh uses.
ephemeralTag()
{
  local head dirty
  head="$(git rev-parse --short=12 HEAD)"
  dirty="$( { git diff HEAD; git ls-files --others --exclude-standard -z | \
    xargs -0 -r sha256sum; } | sha256sum | cut -c1-8)"
  echo "eph-${head}-${dirty}"
}

# The images `environment/` deploys, built from this tree and pushed: the
# service and its schema-init. The tests, runner and PEP images are
# run-suite.sh's own to build — it tags them from the same working tree.
# The build arguments are the ones
# .github/workflows/aws-cluster.yml's `images` job passes; cert-init is not
# built, because only an environment with a public name uses it and an
# ephemeral one has none.
buildAndPushEphemeralImages()
{
  local env="$1" tag="$2" account registry repo commit
  account="$(aws sts get-caller-identity --query Account --output text)" || return 1
  registry="${account}.dkr.ecr.${AWS_REGION:-us-west-2}.amazonaws.com"
  repo="${registry}/mock-sts"
  commit="$(git rev-parse HEAD)"
  echo "==> building the ${tag} images from this working tree"
  docker build -q -t "${repo}:${tag}" \
    --build-arg STS_CLOUD_SDKS=@aws-sdk/client-secrets-manager \
    --build-arg STS_DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
    --build-arg GIT_COMMIT="${commit}" . > /dev/null || return 1
  docker build -q -t "${repo}:schema-${tag}" \
    -f deploy/aws/schema-init/Dockerfile . > /dev/null || return 1
  echo "==> pushing them to ${repo}"
  deploy/aws/terraform-local.sh "${env}" ecr-password | \
    docker login -u AWS --password-stdin "${registry}" > /dev/null || return 1
  local image
  for image in "${tag}" "schema-${tag}";
  do
    docker push -q "${repo}:${image}" > /dev/null || return 1
  done
  return 0
}

# Whether <env> already has an applied environment — `exists` when its outputs
# name a service, `absent` when they do not, and `unknown` when they could not
# be read at all. THREE ANSWERS AND NOT TWO, AND THE THIRD IS A REFUSAL: the
# first version answered a failed read as "absent", and its first test run
# failed exactly that way — the Terraform image could not be BUILT (apt in the
# build had no network), so the probe said nothing existed, which is the one
# answer that lets this target apply and then DESTROY an environment it did not
# create. A guard that fails open is not a guard.
awsEnvironmentState()
{
  local outputs
  if ! outputs="$(deploy/aws/terraform-local.sh "$1" output-json 2> /dev/null)";
  then
    echo unknown
    return 0
  fi
  if printf '%s' "${outputs}" | grep -q '"service_url"';
  then
    echo exists
  else
    echo absent
  fi
}

runAwsEphemeral()
{
  local env="${1:-ci}" tag rc
  if [ "${env}" = "testidp" ];
  then
    echo "--target=aws-ephemeral refuses testidp: it is a deployment, and this" >&2
    echo "target DESTROYS what it applies. --target=aws:testidp tests it." >&2
    exit 2
  fi
  case "$(awsEnvironmentState "${env}")" in
    exists)
      echo "The ${env} environment already exists, and --target=aws-ephemeral" >&2
      echo "destroys what it ran against — it will not destroy something it did" >&2
      echo "not create. Test it with --target=aws:${env}, or destroy it first" >&2
      echo "(deploy/aws/terraform-local.sh ${env} destroy)." >&2
      exit 2
      ;;
    unknown)
      echo "Could not read ${env}'s Terraform state, so this run cannot tell" >&2
      echo "whether ${env} already exists — and --target=aws-ephemeral DESTROYS" >&2
      echo "what it ran against, so it refuses rather than guess. Check that" >&2
      echo "deploy/aws/terraform-local.sh ${env} output-json works." >&2
      exit 2
      ;;
  esac
  if [ "${BUILD}" = "1" ];
  then
    tag="$(ephemeralTag)"
    buildAndPushEphemeralImages "${env}" "${tag}" || {
      echo "The images could not be built or pushed; nothing was applied." >&2
      exit 1
    }
  else
    tag="${IMAGE_TAG:?--no-build with --target=aws-ephemeral needs IMAGE_TAG, the tag the images were already pushed under}"
  fi
  # DESTROYED ON EVERY WAY OUT FROM HERE, because an apply that fails half way
  # has still created things that bill. `entrypoint.sh`'s destroy takes the
  # environment's dependent stacks down first (2026-09-21) — the gap that left
  # testidp standing on 2026-09-20.
  trap 'ephemeralTeardown "'"${env}"'"' EXIT
  trap 'exit 130' INT TERM
  echo "==> applying ${env} with images ${tag}"
  IMAGE_TAG="${tag}" deploy/aws/terraform-local.sh "${env}" apply || {
    echo "The apply of ${env} failed; it is destroyed below." >&2
    exit 1
  }
  echo "==> the suite, against ${env}, from this machine"
  "${CURRENT_DIR}/deploy/aws/run-suite.sh" "${env}"
  rc=$?
  exit "${rc}"
}

ephemeralTeardown()
{
  local env="$1"
  if [ "${STS_SUITE_KEEP_ENVIRONMENT:-0}" = "1" ];
  then
    echo "==> ${env} KEPT (STS_SUITE_KEEP_ENVIRONMENT=1). It bills until" >&2
    echo "    deploy/aws/terraform-local.sh ${env} destroy." >&2
    return 0
  fi
  echo "==> destroying ${env}"
  deploy/aws/terraform-local.sh "${env}" destroy || {
    echo "" >&2
    echo "THE DESTROY OF ${env} FAILED — it may still be running and billing." >&2
    echo "Run deploy/aws/terraform-local.sh ${env} destroy again." >&2
  }
}

case "${TARGET}" in
  local)
    ;;
  aws:?*)
    awsTargetRefusals
    [ "${BUILD}" = "1" ] || export STS_SUITE_SKIP_BUILD=1
    exec "${CURRENT_DIR}/deploy/aws/run-suite.sh" "${TARGET#aws:}"
    ;;
  aws-ephemeral|aws-ephemeral:?*)
    awsTargetRefusals
    ENV_NAME="${TARGET#aws-ephemeral}"
    runAwsEphemeral "${ENV_NAME#:}"
    ;;
  *)
    echo "--target=${TARGET}: there is no such target. There are: local," >&2
    echo "aws:<environment>, aws-ephemeral[:<environment>]." >&2
    exit 2
    ;;
esac

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
  # host-side writer of tests/report (./run-coverage.sh --no-docker, or
  # somebody clearing old reports) then cannot write into it. It is still
  # written by root INSIDE the container — which is why the workflow chowns it
  # before uploading — but the directory itself stays the developer's.
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
# untouched — and `STS_LOG_LEVEL=debug ./run-tests.sh` is the run that
# is being read asking for the record back.
#
# THE SECOND KNOB IS THE APPCONFIG FILE, AND WITHOUT IT THIS WOULD LOOK LIKE IT
# WORKED WHILE DOING ALMOST NOTHING. STS_LOG_LEVEL reaches the loggers
# config.js registers — its own, and the `sts` logger in helpers.js that every
# protocol module destructures. It does NOT reach the VENDORED modules under
# common/vendored/, which each build a bunyan logger at load from
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
# EVERY APPCONFIG FILE IN env/ IS AT `info` SINCE 2026-09-12, env/local.js and
# env/docker-tests.js included, because every function now logs its entry and
# exit at debug. So the file this block picks no longer changes the level: a
# trace or debug run raises what STS_LOG_LEVEL reaches, and the vendored
# modules stay at info unless CONFIG_FILE names a file that says otherwise.
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

# A secret for one stack's life, in the shape the client secret above uses.
freshSecret()
{
  head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24
}

# ---------------------------------------------------------------------------
# THE STACK'S OWN SUBNET (2026-09-12), chosen as ./local-run-tests.sh chose
# its own until it was removed (2026-09-16) — see freeSubnet() in
# tests/tools/compose.sh, which argues it.
#
# docker-compose-run-tests.yml names `172.30.0.0/24` because a realm's SPIFFE
# listeners need addresses that do not move between starts, and a network is
# MACHINE-WIDE however the project is named. So two runs of this launcher — a
# CI agent with two workspaces, which is the case STS_DOCKER_TEST_PROJECT
# exists for — collided on the address space before either brought up a
# container.
#
# THE BASE IS 172.30; THE REMOVED LAUNCHER'S WAS 172.29, which kept one run of
# each off the scan entirely. Placed after the preflight because
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
  # production modes is what makes the key-encryption key come out of the store.
  "STS_KEYS_SOURCE=${STS_KEYS_SOURCE:-generated}"
  "STS_TESTS_CONTAINER_NAME=${STS_TESTS_CONTAINER_NAME}"
  "STS2_CONTAINER_NAME=${STS2_CONTAINER_NAME}"
  "STS_LB_CONTAINER_NAME=${STS_LB_CONTAINER_NAME}"
  "STS_CONFORMANCE_MONGO_CONTAINER_NAME=${STS_CONFORMANCE_MONGO_CONTAINER_NAME}"
  "STS_CONFORMANCE_SERVER_CONTAINER_NAME=${STS_CONFORMANCE_SERVER_CONTAINER_NAME}"
  "STS_CONFORMANCE_NGINX_CONTAINER_NAME=${STS_CONFORMANCE_NGINX_CONTAINER_NAME}"
  "STS_CONFORMANCE_TLS_CONTAINER_NAME=${STS_CONFORMANCE_TLS_CONTAINER_NAME}"
  # The conformance suite's three, pinned above the service's extra
  # addresses (`.11` to `.13`), which docker's allocator cannot see.
  "CONFORMANCE_MONGO_ADDRESS=${STS_NETWORK_PREFIX}.40"
  "CONFORMANCE_SERVER_ADDRESS=${STS_NETWORK_PREFIX}.41"
  "CONFORMANCE_NGINX_ADDRESS=${STS_NETWORK_PREFIX}.42"
  "CONFORMANCE_TLS_ADDRESS=${STS_NETWORK_PREFIX}.43"
  "CONFIG_FILE=${CONFIG_FILE}"
  "STS_TEST_ARGS=${STS_TEST_ARGS}"
  # ---------------------------------------------------------------------
  # TLS ON THE MAIN PORT (2026-08-30), and the URL the runner dials with it.
  #
  # BOTH, because they are two variables in the compose file and a stack where
  # they disagree is a stack where every protocol job fails on a closed
  # socket. The compose file defaults each to the same answer; naming them
  # here is what makes an operator's `STS_HTTPS=false ./run-tests.sh`
  # actually reach compose, since `sudo` empties the environment — see
  # tests/tools/compose.sh.
  #
  # `sts` and not `localhost`: this runner publishes no port at all, and that
  # hostname is one of the certificate's SANs (`tls.hostnames` in
  # common/config.js: localhost, sts, sts-mock, sts.example.com). A different
  # name here would be a certificate error in every job rather than a
  # connection error in one.
  # ---------------------------------------------------------------------
  "STS_HTTPS=${STS_HTTPS:-true}"
  "STS_TEST_SERVICE_URL=$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)://sts:8081"
  # AND THE ADDRESS INSIDE EVERY CERTIFICATE (2026-09-13): the CRL, OCSP and
  # caIssuers URLs the service writes are followed by
  # sts_pki_distribution_points from this runner, so they must name the
  # service the way the runner does — `sts`, on the plain-HTTP revocation
  # listener, which is plain whatever STS_HTTPS says about the main port.
  "PKI_DISTRIBUTION_BASE_URL=http://sts:8082"
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
  # ---- the PEP's HTTPS listener (2026-09-13) -------------------------------
  # The pair is issued by the realm the PEP registers to, so it cannot exist
  # before the job creates that realm: the PEP is pointed at two paths under
  # its mount that are empty when it starts, and sts_xacml_remote_pep.js writes
  # the pair there after issuing it. The job sees the same directory under the
  # report mount, which is why XACML_PEP_SERVER_CERT_DIR is a path inside the
  # tests container and the other two are paths inside the PEP's.
  "XACML_PEP_HTTPS_CERT=/certs/server/pep-server.crt"
  "XACML_PEP_HTTPS_KEY=/certs/server/pep-server.key"
  "XACML_PEP_HTTPS_URL=https://xacml-pep:9443"
  "XACML_PEP_SERVER_CERT_DIR=/usr/src/sts/tests/report/pep-credential/server"
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
if [ -n "${STS_IMAGE:-}" ];
then
  COMPOSE_ENV+=("STS_IMAGE=${STS_IMAGE}")
fi
if [ -n "${XACML_PEP_IMAGE:-}" ];
then
  COMPOSE_ENV+=("XACML_PEP_IMAGE=${XACML_PEP_IMAGE}")
fi
if [ -n "${STS_TESTS_IMAGE:-}" ];
then
  COMPOSE_ENV+=("STS_TESTS_IMAGE=${STS_TESTS_IMAGE}")
fi
# ---------------------------------------------------------------------------
# WHERE THE SERVICE IS, AS THE LAUNCHER'S OWN ONE-SHOT CONTAINERS DIAL IT
# (2026-09-14). `sts` in every mode but `cluster`, where it is the balancer —
# the token is minted and the PEP's anchor posted THROUGH it, like everything
# a job does. Set per mode by the loop.
# ---------------------------------------------------------------------------
SERVICE_HOST="sts"
serviceUrl()
{
  printf '%s://%s:8081' \
    "$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)" \
    "${SERVICE_HOST}"
}

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
  # The `cluster` mode's node B and balancer, whose logs go with their
  # containers too (2026-09-14). Node A keeps the name every mode uses.
  if stsModeIsCluster "${mode}";
  then
    captureOneContainerLog "${mode}" sts2   "00-mock-sts-service-node-b.log" \
      "Node B log"
    captureOneContainerLog "${mode}" sts-lb "00-load-balancer.log" \
      "Balancer log"
  fi
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
#
# **AND ONLY BESIDE A REPORT THIS MODE WROTE (2026-09-14).** `latest` is the
# newest report of that mode from ANY run — ./local-run-tests.sh's included,
# while it existed (removed 2026-09-16) —
# so a mode whose runner never started wrote its two logs over another run's
# `00-mock-sts-service.log` and `00-test-runner.log`, destroying that report's
# evidence and leaving this run's where nobody would look for it.
MODE_MARKER="${CURRENT_DIR}/tests/report/.run-tests-mode-start"

# Did the runner write a report under tests/report/<mode> after this mode's
# `up` began? A report directory's `logs` gains an entry per job, so its
# modification time moves during the mode.
modeWroteReport()
{
  local mode="$1"
  local logs="${CURRENT_DIR}/tests/report/${mode}/latest/logs"
  [ -f "${MODE_MARKER}" ] && [ -d "${logs}" ] &&
    [ "${logs}" -nt "${MODE_MARKER}" ]
}

captureOneContainerLog()
{
  local mode="$1" service="$2" name="$3" label="$4"
  local logs="${CURRENT_DIR}/tests/report/${mode}/latest/logs"
  local dest="${logs}/${name}"
  if ! modeWroteReport "${mode}" ||
     ! ( [ -d "${logs}" ] && touch "${dest}" 2> /dev/null );
  then
    mkdir -p "${CURRENT_DIR}/tests/report" 2> /dev/null || true
    dest="${CURRENT_DIR}/tests/report/${mode}-${name}"
  fi
  # BOUNDED for the reason the teardown below is: this runs against a stack
  # that has just been stopped, and the case worth collecting a log for is
  # exactly the case where that stop did not go well.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    "${COMPOSE_FILE_ARGS[@]}" logs --no-color "${service}" \
    > "${dest}" 2>&1 || true
  printf '%-12s %s\n' "${label}:" "${dest}"
}

# ---------------------------------------------------------------------------
# THE SCHEDULER SURVIVES A CRASHED LEADER (#49, rcbj's D10(a), 2026-09-22).
#
# The LAST step of the `cluster` mode, because it removes a node: the runner
# has finished, the stack is still up (the mode runs detached for this), and
# `tests/tools/scheduler-takeover.js` names the scheduler's leader, this
# function `docker kill`s that node's container — a crash, so its lease is not
# released — and the tool asserts through the balancer that the other node
# leads within the node lifetime and three ticks, runs a run queued now, and
# ran every slot of the session-expiry job once. Its output is
# tests/report/<mode>-99-scheduler-takeover.log. STS_TEST_SCHEDULER_TAKEOVER=0
# skips it; a kept stack (--keep-stack) is never crashed.
# ---------------------------------------------------------------------------
schedulerTakeover()
{
  local mode="$1" out leader container rc
  local dest="${CURRENT_DIR}/tests/report/${mode}-99-scheduler-takeover.log"
  # A FRESH TOKEN, NOT THE MODE'S (2026-09-24). The one minted when the mode
  # started is over an hour old by now — the cluster mode took 3702s on the
  # 8d6ce58 run, past an access token's lifetime, across jobs that rotate the
  # default realm's signing keys — and was refused `invalid_token`, so the
  # takeover never named a leader. Minted here, against the stack as it is.
  if ! mintAdminApiToken;
  then
    echo "  The scheduler's crash takeover needs an /admin-api token." >&2
    return 1
  fi
  local tool=(docker run --rm --network "${COMPOSE_PROJECT}_default"
              -v "${CURRENT_DIR}:/repo:ro"
              -e "STS_ADMIN_API_TOKEN=${STS_ADMIN_API_TOKEN:-}"
              -e NODE_PATH=/usr/src/sts/node_modules
              -w /usr/src/sts "${STS_IMAGE:-rcbj/sts}"
              node /repo/tests/tools/scheduler-takeover.js)
  mkdir -p "${CURRENT_DIR}/tests/report" 2> /dev/null || true
  echo ""
  echo "Mode ${mode}: the scheduler's crash takeover — the last step, because"
  echo "it stops a node."
  if ! out="$("${tool[@]}" before "$(serviceUrl)" 2>&1)";
  then
    printf '%s\n' "${out}" > "${dest}"
    echo "  The scheduler's leader could not be named; see ${dest}." >&2
    return 1
  fi
  printf '%s\n' "${out}" > "${dest}"
  leader="$(printf '%s' "${out}" | tail -n 1)"
  case "${leader}" in
    node-a) container="${STS_CONTAINER_NAME}" ;;
    node-b) container="${STS2_CONTAINER_NAME}" ;;
    *)
      echo "  The leader is \"${leader}\", which is neither node." >&2
      return 1
      ;;
  esac
  echo "  ${leader} leads; killing ${container}."
  if ! docker kill "${container}" > /dev/null 2>&1;
  then
    echo "  docker kill ${container} failed." >&2
    return 1
  fi
  "${tool[@]}" after "$(serviceUrl)" "${leader}" >> "${dest}" 2>&1
  rc=$?
  grep -E '✓|FAILED' "${dest}" | sed 's/^/  /' || true
  if [ "${rc}" -ne 0 ];
  then
    echo "  The scheduler did NOT survive its leader's crash; see ${dest}." >&2
  fi
  return "${rc}"
}

# Always tear the stack down, even when the tests fail, so the next run starts
# clean. A TRAP rather than a line at the end: an interrupted run (^C, a failing
# step) would otherwise leave the stack's containers, volumes and network
# behind, and the next run would be the one that had to explain them.
teardown()
{
  if [ "${KEEP_STACK}" = "1" ] && [ "${STACK_UP}" = "1" ];
  then
    echo ""
    # EVERY file the kept mode was brought up with: a `cluster` stack is two,
    # and a command naming one addresses half of it.
    local files="${COMPOSE_FILE_ARGS[*]}"
    echo "The last mode's stack is still up, as asked (--keep-stack):"
    echo "  logs:    ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} ${files} logs -f sts"
    echo "  a shell: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} ${files} exec sts bash"
    echo "  the port is NOT published — to reach the console, add"
    echo "           --service-ports to a \`run\` of the sts service."
    echo "  stop it: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} ${files} down -v"
    return 0
  fi
  # BOUNDED. This is the EXIT trap, so an unbounded call here can hold a run
  # open after everything it was asked to do is finished and reported — which
  # is the shape of the 2026-09-10 incident, one function along.
  docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
    "${COMPOSE_FILE_ARGS[@]}" down --remove-orphans --volumes \
    > /dev/null 2>&1 || true
}
trap teardown EXIT

# A stack left behind by an interrupted run holds the container names this one
# is about to ask for. Removing it is safe BECAUSE of the project name: this
# reaches `mock-sts-docker-tests` and can never reach the `sts` container a
# plain `docker compose up` in this directory creates.
docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
  "${COMPOSE_FILE_ARGS[@]}" down --remove-orphans --volumes \
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
  if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" build;
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
# ELSE"** — the same argument mintThePepCredential() makes: the repository is
# mounted read-only and the image supplies the runtime. On the project's
# network, dialling `sts` by the name in the certificate.
#
# **NODE_PATH, BECAUSE THE TOOL IS NOT DEPENDENCY-FREE ANY MORE.** It said
# here that `admin-api-token.js` needed only node's `http` and `https`, and
# the 2026-09-12 style sweep gave it (and `pep-credential.js`) a bunyan
# logger. node resolves a package by walking up from the SCRIPT, which is
# /repo/tests/tools — the host checkout, which has node_modules on a
# developer's machine and none on a CI runner — and `-w` does not change
# that. So every CI run of this launcher failed here with `Cannot find module
# 'bunyan'` in all three modes while every local run passed. The image's own
# /usr/src/sts/node_modules has bunyan; NODE_PATH is where node looks when
# the walk finds nothing, so a checkout that has its own still uses it.
# ---------------------------------------------------------------------------
mintAdminApiToken()
{
  local token
  if ! token="$(docker run --rm \
       --network "${COMPOSE_PROJECT}_default" \
       -v "${CURRENT_DIR}:/repo:ro" \
       -e "STS_ADMIN_API_CLIENT_SECRET=${ADMIN_API_CLIENT_SECRET}" \
       -e NODE_PATH=/usr/src/sts/node_modules \
       -w /usr/src/sts \
       "${STS_IMAGE:-rcbj/sts}" \
       node /repo/tests/tools/admin-api-token.js \
         "$(serviceUrl)" \
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
# loop tears the stack DOWN between modes, and the mock generated a fresh
# self-signed server certificate on every start (a fresh Root and a server
# certificate under it, since) — so mode 2 and mode 3 met a
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
  # its three npm packages (and bunyan, for its logger — see NODE_PATH at
  # mintAdminApiToken()); this host may have neither node nor node_modules.
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
       -e NODE_PATH=/usr/src/sts/node_modules \
       -e "STS_ADMIN_API_TOKEN=${STS_ADMIN_API_TOKEN:-}" \
       -w /usr/src/sts \
       "${STS_IMAGE:-rcbj/sts}" \
       sh -c '
         # THE SERVICE'"'"'S OWN CERTIFICATE FIRST (2026-09-21). The gated
         # door VERIFIES the connection, because it carries the token, and
         # this one-shot container had no anchor for the per-start
         # certificate: the handshake was aborted, the tool fell back to the
         # open POST /tls/trust, product mode refused it, and the PEP ran the
         # whole mode unverified. This is the fetch run-report.js makes for
         # every job (tests/tools/trust.js), made here for this child.
         case "$1" in
           https:*)
             node -e "require(\"/repo/tests/tools/trust.js\")
               .readTrust(process.argv[1]).then(function (t) {
                 require(\"fs\").writeFileSync(
                   \"/out/sts-certificate.pem\", t.pem); })" "$1" || exit 1
             export NODE_EXTRA_CA_CERTS=/out/sts-certificate.pem ;;
         esac
         exec node /repo/tests/tools/pep-credential.js \
           --url="$1" --out=/out --subject="$2" \
           --crl-base=http://xacml-pep:9090/crl' \
         sh "$(serviceUrl)" "${XACML_PEP_SUBJECT}" > /dev/null;
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
  # WHERE THE JOB WRITES THE HTTPS LISTENER'S PAIR, made now because the PEP
  # container mounts its parent and the job — in the tests container — writes
  # into it later. World-writable because that container may not be this user;
  # it holds one test run's key and is removed with the reports.
  mkdir -p "${XACML_PEP_CERT_DIR}/server"
  chmod 0777 "${XACML_PEP_CERT_DIR}/server" 2>/dev/null || true
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
# ONCE PER MODE. `tests/tools/modes.sh` is the one definition of the modes, so
# they are named in one place however many launchers read them (two until
# ./local-run-tests.sh was removed on 2026-09-16).
#
# EACH MODE GETS ITS OWN REPORT TREE, and the stack is brought DOWN between
# modes: this launcher's whole point is that the runner is a container too, so
# two modes cannot share a compose project any more than two runs can.
#
# NOTHING IS LEFT UP at the end, unless --keep-stack asks. CI never passes
# it, and a CI job that left containers behind would leak them run after run.
# With it, the LAST mode runs detached and skips its down (2026-09-21) — until
# then the option spared only a stack the EXIT trap found still up, and
# `--abort-on-container-exit` plus this loop's down meant it never found one
# running.
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
  STS_MODE_TIMEOUT="$(stsModeTimeout "${MODE}")"
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
  # ---- THE `cluster` MODE: TWO NODES AND A BALANCER (2026-09-14) ---------
  #
  # The layer, the three services `up -d` has to start, and every address the
  # runner is handed moved to the balancer — the service URL, the directory,
  # the base URL both nodes issue under (on the cluster's must-agree list, and
  # the audience of the token minted below through the same URL) and the
  # revocation addresses inside every certificate. These entries come AFTER the
  # base array's, and `env` applies assignments in order, so they win.
  COMPOSE_FILE_ARGS=(-f "${COMPOSE_FILE}")
  UP_SERVICES=(sts)
  SERVICE_HOST="sts"
  if stsModeIsCluster "${MODE}";
  then
    COMPOSE_FILE_ARGS+=(-f "${CLUSTER_COMPOSE_FILE}")
    UP_SERVICES=(sts sts2 sts-lb)
    SERVICE_HOST="sts-lb"
    MODE_ENV+=(
      "STS_TEST_SERVICE_URL=$(serviceUrl)"
      "STS_PUBLIC_BASE_URL=$(serviceUrl)"
      "STS_LDAP_URL=ldap://sts-lb:389"
      "PKI_DISTRIBUTION_BASE_URL=http://sts-lb:8082"
      "PKI_DISTRIBUTION_LDAP_HOST=sts-lb"
      "STS2_ADDRESS=${STS_NETWORK_PREFIX}.20"
      # PROXY protocol v2 and its one trusted source, the balancer pinned at
      # `.30`. Not the subnet: a trusted list that named the whole subnet
      # would let any container on this network forge a client address,
      # which is the thing the setting exists to stop.
      # STS_TEST_CLUSTER_PROXY_PROTOCOL=off runs the mode without it.
      "STS_PROXY_PROTOCOL=${STS_TEST_CLUSTER_PROXY_PROTOCOL:-v2}"
      "STS_LB_ADDRESS=${STS_NETWORK_PREFIX}.30"
      "STS_TRUSTED_PROXIES=${STS_NETWORK_PREFIX}.30/32"
    )
  fi

  # ---- A PRODUCT-MODE MODE: WHAT A DEPLOYMENT IS GIVEN (2026-09-21) ------
  # (`single-node` and `cluster` since that evening; it was written for the
  # `product` mode they replaced, and asks the mode's own STS_MODE, so it
  # needed no change.)
  #
  # Product mode refuses the development shortcuts, so a stack running it
  # needs what `deploy/aws/environment/ecs.tf` hands a product node, and the
  # first product run here showed which of those this stack lacked:
  #
  #   STS_PUBLIC_BASE_URL   the hosted surfaces (/admin, /portal) start their
  #                         OIDC sign-in only at an address registered on
  #                         their client, and product mode registers nothing a
  #                         request names (STS-ADMIN-0002, STS-PORTAL-0011,
  #                         STS-AUTHN-0114). Pinned to the address this stack
  #                         is reached at, every console and portal job
  #                         answered 503 until it was.
  #   KRB5_KRBTGT_PASSWORD, KRB5_SERVICE_PASSWORD
  #                         product mode builds no krbtgt and no service
  #                         account on the passwords published in this
  #                         repository, so the KDC had no krbtgt at all
  #                         (KDC_ERR_S_PRINCIPAL_UNKNOWN). Fresh per mode, as
  #                         AWS generates them into Secrets Manager.
  #
  # Only for a mode that is product: the development modes keep the fixture
  # passwords their Kerberos jobs are written against, and learn their
  # address as they always did.
  if printf '%s\n' "${MODE_ENV[@]}" | grep -qx 'STS_MODE=product';
  then
    MODE_ENV+=(
      "STS_PUBLIC_BASE_URL=$(serviceUrl)"
      "KRB5_KRBTGT_PASSWORD=$(freshSecret)"
      "KRB5_SERVICE_PASSWORD=$(freshSecret)"
    )
  fi

  # ---- THE CONFORMANCE SUITE, IN THE MODES THAT RUN IT (#176) -----------
  #
  # The profile starts its three containers with the runner's `up`, the URL
  # is what tells the job they are there, and the mode's bound grows by what
  # the plans take. Not attached: the JVM's log is thousands of lines, and
  # the job reports every module itself.
  UP_NO_ATTACH=(--no-attach openbao-tls --no-attach openbao-seed
                --no-attach mailpit-tls --no-attach mailpit)
  if printf ',%s,' "${STS_TEST_CONFORMANCE_MODES}" | grep -q ",${MODE},";
  then
    MODE_ENV+=(
      "COMPOSE_PROFILES=conformance"
      "CONFORMANCE_SUITE_URL=https://localhost.emobix.co.uk:8443/"
    )
    UP_NO_ATTACH+=(--no-attach conformance-mongo
                   --no-attach conformance-server
                   --no-attach conformance-nginx
                   --no-attach conformance-tls)
    STS_MODE_TIMEOUT=$(( STS_MODE_TIMEOUT + STS_CONFORMANCE_TIMEOUT ))
    echo " The OpenID conformance suite runs in this mode (#176); its bound" \
         "is ${STS_MODE_TIMEOUT}s."
  fi

  COMPOSE_ENV=(
    ${BASE_COMPOSE_ENV[@]+"${BASE_COMPOSE_ENV[@]}"}
    ${MODE_ENV[@]+"${MODE_ENV[@]}"}
  )

  STACK_UP=1
  MODE_RC=0
  # This mode's start, which modeWroteReport() compares a report against, so a
  # report from an earlier mode or run is never taken for this one's.
  mkdir -p "${CURRENT_DIR}/tests/report" 2> /dev/null || true
  touch "${MODE_MARKER}"
  if ! docker_compose "${COMPOSE_FILE_ARGS[@]}" up -d "${UP_SERVICES[@]}";
  then
    echo "The mock STS would not start in mode ${MODE}. Nothing was run." >&2
    MODE_RC=1
  elif ! waitForStsHealthy;
  then
    echo "The mock STS never became healthy in mode ${MODE}. Nothing was" >&2
    echo "run — see the container log captured below." >&2
    MODE_RC=1
  elif ! mintAdminApiToken;
  then
    MODE_RC=1
  else
    COMPOSE_ENV+=("STS_ADMIN_API_TOKEN=${STS_ADMIN_API_TOKEN}")

    # -----------------------------------------------------------------------
    # THE TOKEN FIRST AND THE PEP'S CERTIFICATE SECOND (2026-09-21) — it was
    # the other way round, and the `product` mode is why it moved. The PEP's
    # anchor has to be in the service's truststore before the container that
    # presents it starts, and a PRODUCT-mode service accepts an anchor only
    # through `POST /admin-api/tls/trust/add`, which wants this token
    # (tests/tools/pep-credential.js tries that door first whenever it is
    # handed one — the AWS runner's pep-credential.sh already mints the token
    # first for exactly this). Minted the old way round, the certificate step
    # fell back to the open `POST /tls/trust`, which product mode refuses, and
    # every /xacml/pep call the container made was refused as an unknown
    # chain. Nothing about the order matters to the development modes: the
    # token needs only a service that answers, which `waitForStsHealthy`
    # established.
    # -----------------------------------------------------------------------
    mintThePepCredential

    # THE ROOT CA AS TEXT, SO THAT sts_xacml_remote_pep.js CAN PUT IT BACK.
    #
    # The truststore is a Map in the service's process that ANY job can empty:
    # `POST /tls/trust/clear` needs no credential in development mode (every
    # mode but `product`, which refuses it), and a job exercising the truststore is entitled
    # to use it. Nothing noticed until 2026-09-06, when
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

    # THE TWO ONE-SHOT CONTAINERS ARE NOT ATTACHED (2026-09-14), OR THEIR
    # FINISHING ENDS THE MODE. `openbao-tls` and `openbao-seed` exit 0 by
    # design, and so does `mailpit-tls` (#63; `mailpit` is not attached
    # either, because its log is every message the suite sends). The `up -d
    # sts` above already ran both; this `up` names every
    # service, so compose STARTS them again, and `--abort-on-container-exit`
    # counts an ATTACHED container's exit — any container's — as the signal
    # to stop the stack. So each mode stopped `sts` a few seconds after
    # starting it, the runner never ran, and the screen showed the OpenBao
    # containers exiting and nothing after. Not attaching them keeps their
    # exit out of that rule; the runner's exit is still what ends the mode.
    # Reproduced with a two-step `up` against a toy stack before this was
    # written.
    #
    # **--keep-stack RUNS THE LAST MODE DETACHED (2026-09-21).** Until then it
    # kept nothing: `--abort-on-container-exit` STOPS every container the
    # moment the runner exits, and the loop below ran `down` after every mode
    # including the last, so the teardown's "the stack is still up" branch was
    # never reached with anything running. Kept, the stack comes up with
    # `up -d`, the runner's output is followed, and `wait tests` is its exit
    # code — the same verdict `--exit-code-from tests` gives, with nothing
    # stopped. Only the LAST mode is kept: the next mode needs the names.
    KEEP_THIS_MODE=0
    if [ "${KEEP_STACK}" = "1" ] && [ "${MODE_INDEX}" -eq "${MODE_COUNT}" ];
    then
      KEEP_THIS_MODE=1
    fi
    # THE `cluster` MODE RUNS DETACHED TOO (#49, 2026-09-22), for the same
    # reason a kept mode does: `--abort-on-container-exit` stops every
    # container the moment the runner exits, and the scheduler's crash
    # takeover below needs the stack still up to kill a node of.
    DETACHED_MODE="${KEEP_THIS_MODE}"
    if stsModeIsCluster "${MODE}";
    then
      DETACHED_MODE=1
    fi
    if [ "${DETACHED_MODE}" = "0" ];
    then
      docker_compose_bounded "${STS_MODE_TIMEOUT}" "${COMPOSE_FILE_ARGS[@]}" up \
        "${UP_NO_ATTACH[@]}" \
        --abort-on-container-exit --exit-code-from tests
      MODE_RC=$?
    else
      docker_compose_bounded "${STS_MODE_TIMEOUT}" "${COMPOSE_FILE_ARGS[@]}" up -d
      MODE_RC=$?
      if [ "${MODE_RC}" -eq 0 ];
      then
        # Bounded like every other call here: a follow that outlives the
        # runner would hold the run open (tests/teardown_bounds.js).
        docker_compose_bounded "${STS_MODE_TIMEOUT}" "${COMPOSE_FILE_ARGS[@]}" \
          logs -f --no-log-prefix tests &
        KEEP_LOG_PID=$!
        docker_compose_bounded "${STS_MODE_TIMEOUT}" "${COMPOSE_FILE_ARGS[@]}" \
          wait tests
        MODE_RC=$?
        wait "${KEEP_LOG_PID}" 2> /dev/null || true
      fi
    fi
    if [ "${MODE_RC}" -ge 124 ];
    then
      MODE_RC="$(recoverModeVerdict "${MODE}" "${MODE_RC}")"
    fi
    # The crash takeover, LAST in the cluster mode, and never on a kept stack.
    if stsModeIsCluster "${MODE}" && [ "${KEEP_THIS_MODE}" = "0" ] &&
       [ "${STS_TEST_SCHEDULER_TAKEOVER:-1}" = "1" ] &&
       modeWroteReport "${MODE}";
    then
      if ! schedulerTakeover "${MODE}";
      then
        MODE_RC=1
      fi
    fi
    # A MODE WHOSE RUNNER WROTE NO REPORT DID NOT PASS, whatever compose
    # returned. The stack stopping before the runner started is exactly the
    # case compose can report as 0, and a green mode that ran no job is the
    # one verdict this launcher must never give.
    if [ "${MODE_RC}" -eq 0 ] && ! modeWroteReport "${MODE}";
    then
      echo "" >&2
      echo "Mode ${MODE}: compose returned 0, but the test runner wrote no" >&2
      echo "report under tests/report/${MODE} during this mode. Nothing was" >&2
      echo "run, so the mode is a failure. The runner log below says why." >&2
      MODE_RC=1
    fi
  fi
  MODES_RUN+=("${MODE}")
  if [ "${MODE_RC}" -ne 0 ];
  then
    RC="${MODE_RC}"
    MODES_FAILED+=("${MODE}")
  fi

  captureContainerLogs "${MODE}"

  # KEPT: the last mode under --keep-stack stays up for the teardown trap to
  # describe, and is the one stack this launcher leaves behind.
  if [ "${KEEP_THIS_MODE:-0}" = "1" ];
  then
    continue
  fi

  # Down between every mode INCLUDING the last — see the header. Bounded, so
  # that a stack which will not come down costs the next mode a warning rather
  # than the whole run's remaining budget.
  if ! docker_compose_bounded "${STS_TEARDOWN_TIMEOUT}" \
       "${COMPOSE_FILE_ARGS[@]}" down --remove-orphans --volumes \
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
