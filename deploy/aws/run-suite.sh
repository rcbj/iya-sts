#!/usr/bin/env bash
#
# File: deploy/aws/run-suite.sh
#
# ---------------------------------------------------------------------------
# THE WHOLE PROTOCOL SUITE AGAINST A DEPLOYED AWS ENVIRONMENT, FROM THIS
# MACHINE (issue #51; reworked 2026-09-18).
#
#   deploy/aws/run-suite.sh <environment>        # e.g. testidp, dev, ci
#
# Needs docker, node and the AWS CLI on this machine, AWS credentials (the
# deployer user's key, role credentials, or an `aws login` session), and THIS
# MACHINE'S ADDRESS IN THE ENVIRONMENT'S `allowed_cidrs` — the jobs reach the
# load balancer from here, exactly as a client would. Nothing about an
# environment is written into this file: everything is read from its
# Terraform outputs, so it runs against any environment `environment/` built,
# in whatever mode that environment runs (testidp is PRODUCT mode, and the
# suite is expected to pass there).
#
# WHAT IT DOES, IN ORDER:
#   1. reads the environment's outputs (terraform-local.sh ... output-json);
#   2. builds the tests image from THIS WORKING TREE, and from it the runner
#      and remote-PEP images, and pushes those two as runner-<tag> and
#      pep-<tag> (the tag names the tree: HEAD plus a digest of what is not
#      committed);
#   3. APPLIES deploy/aws/suite-callbacks/ in the background — a subnet, a NAT
#      gateway the load balancer admits, and a task definition — which is
#      where the two jobs the SERVICE must call back run (see below);
#   4. waits for the load balancer, mints an /admin-api token, removes the
#      previous run's realms (reset-environment.js; STS_SUITE_KEEP_REALMS=1
#      keeps them), and runs every other job in the tests image on this
#      machine's network, into tests/report/aws-<environment>/;
#   5. runs the callback task once, with the two jobs, waits for it, downloads
#      its report and MERGES it into the local one (tests/tools/merge-report.js),
#      so one report answers for the run;
#   6. DESTROYS the callback stack — pass, fail or interrupt (an EXIT trap).
#
# THE TWO CALLBACK JOBS, and why they cannot run here:
#   sts_xacml_remote_pep  the PDP nudges a remote PEP container, and the job
#                         writes that PEP's listener certificate into a
#                         directory the container reads — so the job runs in
#                         the same task as the PEP, which the nodes can reach
#   sts_gnap_core         the service POSTs a GNAP push to a listener the job
#                         opens
# A machine behind NAT cannot be dialled. rcbj's design (2026-09-18): the rest
# of the suite runs here, those two run in an ephemeral task in the VPC that
# exists only for the run. STS_SUITE_CALLBACKS=0 skips the callback half (no
# stack, no images pushed; the two jobs are listed as not run).
#
# THE PER-JOB WATCHDOG IS TWENTY MINUTES, NOT THE RUNNER'S FIVE. Every request
# crosses the internet on a new TLS connection (so the balancer spreads them),
# and the first run against AWS lost eight jobs to the 300-second default
# rather than to any assertion. STS_SUITE_JOB_TIMEOUT_MS overrides it.
#
# Other knobs: STS_SUITE_EXCLUDE (comma-separated job files to leave out),
# STS_SUITE_ONLY (the local job list, replacing the computed one — for
# re-running what failed), STS_SUITE_REPORT_DIR, STS_SUITE_TASK_TIMEOUT_SECS
# (default 3600), STS_SUITE_SKIP_BUILD=1 (reuse mock-sts-tests:<tag> and the
# pushed images, when nothing changed since the last run).
# ---------------------------------------------------------------------------
set -euo pipefail

ENVIRONMENT="${1:?usage: deploy/aws/run-suite.sh <environment>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
REPORT_DIR="${STS_SUITE_REPORT_DIR:-${ROOT}/tests/report/aws-${ENVIRONMENT}}"
RUN_ID="$(date -u +%Y-%m-%dT%H-%M-%S)"
CALLBACK_JOBS="sts_xacml_remote_pep.js,sts_gnap_core.js"
WITH_CALLBACKS="${STS_SUITE_CALLBACKS:-1}"
export AWS_REGION="${AWS_REGION:-us-west-2}"

say() { echo "run-suite: $*" >&2; }
die() { echo "run-suite: ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required."
command -v node >/dev/null 2>&1 || die "node is required on this machine."
command -v aws >/dev/null 2>&1 || die "the AWS CLI is required on this machine."

# terraform-local.sh, for one stack of this environment. Its own progress goes
# to stderr, so stdout is the action's answer.
tfl() {
  local stack="$1" action="$2"
  shift 2
  env "$@" TF_STACK="${stack}" "${ROOT}/deploy/aws/terraform-local.sh" \
    "${ENVIRONMENT}" "${action}"
}

# The deployer USER may do nothing but assume the deployer role, which
# terraform-local.sh does inside its container; the AWS CLI calls this script
# makes itself need the role too.
identity="$(aws sts get-caller-identity --query Arn --output text)" || \
  die "no usable AWS credentials."
case "${identity}" in
  *:user/mock-sts-deployer|*:user/mock-sts/mock-sts-deployer|*:user/git_user6)
    account="$(aws sts get-caller-identity --query Account --output text)"
    say "assuming the deployer role for the AWS CLI calls made here"
    creds="$(aws sts assume-role \
      --role-arn "arn:aws:iam::${account}:role/mock-sts-deployer" \
      --role-session-name "run-suite-${ENVIRONMENT}" --duration-seconds 14400 \
      --query Credentials --output json)"
    AWS_ACCESS_KEY_ID="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).AccessKeyId)' "${creds}")"
    AWS_SECRET_ACCESS_KEY="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).SecretAccessKey)' "${creds}")"
    AWS_SESSION_TOKEN="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).SessionToken)' "${creds}")"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    ;;
esac

# --- 1. the environment -------------------------------------------------------
say "reading ${ENVIRONMENT}'s outputs"
ENV_JSON="$(tfl environment output-json)"
out() {
  node -e 'const o = JSON.parse(process.argv[1]); const k = process.argv[2];
    const v = o[k] && o[k].value;
    process.stdout.write(v === undefined || v === null ? "" :
      (typeof v === "string" ? v : JSON.stringify(v)));' "${ENV_JSON}" "$1"
}
URL="$(out service_url)"
SECRET_ARN="$(out admin_api_client_secret_arn)"
NLB_DNS="$(out nlb_dns_name)"
LDAP_PORT="$(node -e 'process.stdout.write(String(JSON.parse(process.argv[1]).ldap.listener))' "$(out load_balancer_ports)")"
NODES="$(node -e 'process.stdout.write(String(Object.keys(JSON.parse(process.argv[1])).length))' "$(out ecs_services)")"
# WHAT THIS ENVIRONMENT DOES NOT PUBLISH (2026-09-21), for the jobs that
# dial a port of their own rather than the main one. Kerberos TCP 88 is a
# row of `load_balancer_ports` only where `publish_kerberos` is on (testidp);
# SPIFFE's ports come from the separate spiffe-realm stack, which this
# environment's outputs cannot see, so they count as unpublished unless the
# caller names a socket (STS_SPIFFE_WORKLOAD_URL). Without this both jobs
# dialled the load balancer on a port nobody listens on and failed on a
# timeout, as though the service were broken; now each declines and says why.
UNPUBLISHED="$(node -e 'const p = JSON.parse(process.argv[1]); const u = [];
  if (!p.kerberos) { u.push("kerberos"); }
  if (!process.env.STS_SPIFFE_WORKLOAD_URL) { u.push("spiffe"); }
  process.stdout.write(u.join(","));' "$(out load_balancer_ports)")"
[ -n "${URL}" ] || die "${ENVIRONMENT} has no service_url output; is it applied?"
say "${ENVIRONMENT} at ${URL}, ${NODES} node(s), run ${RUN_ID}"

# --- 2. images ----------------------------------------------------------------
HEAD_SHORT="$(git rev-parse --short=12 HEAD)"
DIRTY="$( { git diff HEAD; git ls-files --others --exclude-standard -z | xargs -0 -r sha256sum; } | sha256sum | cut -c1-8)"
TAG="suite-${HEAD_SHORT}-${DIRTY}"
TESTS_IMAGE="mock-sts-tests:${TAG}"
if [ "${STS_SUITE_SKIP_BUILD:-0}" != "1" ];
then
  say "building ${TESTS_IMAGE} from this working tree"
  # The test corpora are a PRIVATE image on ghcr.io (#253).
  tests/tools/corpora-preflight.sh
  docker build -q -t "${TESTS_IMAGE}" -f tests/Dockerfile . >/dev/null
fi

REGISTRY=""
if [ "${WITH_CALLBACKS}" = "1" ];
then
  account="$(aws sts get-caller-identity --query Account --output text)"
  REGISTRY="${account}.dkr.ecr.${AWS_REGION}.amazonaws.com"
  REPO="${REGISTRY}/mock-sts"
  if [ "${STS_SUITE_SKIP_BUILD:-0}" != "1" ];
  then
    say "building and pushing runner-${TAG} and pep-${TAG}"
    docker build -q -t "${REPO}:runner-${TAG}" --build-arg TESTS_IMAGE="${TESTS_IMAGE}" \
      -f deploy/aws/runner/Dockerfile deploy/aws/runner >/dev/null
    docker build -q -t "${REPO}:pep-${TAG}" -f xacml-pep/Dockerfile \
      --build-arg GIT_COMMIT="$(git rev-parse HEAD)" . >/dev/null
    tfl environment ecr-password | docker login -u AWS --password-stdin "${REGISTRY}" >/dev/null
    docker push -q "${REPO}:runner-${TAG}" >/dev/null
    docker push -q "${REPO}:pep-${TAG}" >/dev/null
  fi
fi

# --- 3. the callback stack, applied while the local half runs -----------------
APPLY_PID=""
APPLIED=0
TASK_ARN=""
CLUSTER=""
LOGDIR="${REPORT_DIR}/stack-logs"
mkdir -p "${LOGDIR}"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "${TASK_ARN}" ] && [ -n "${CLUSTER}" ];
  then
    aws ecs stop-task --cluster "${CLUSTER}" --task "${TASK_ARN}" \
      --reason "run-suite cleanup" >/dev/null 2>&1 || true
  fi
  if [ -n "${APPLY_PID}" ];
  then
    # An apply still running is told to stop cleanly (terraform-local.sh
    # relays the interrupt), so the destroy below finds released state.
    kill -INT "${APPLY_PID}" 2>/dev/null || true
    wait "${APPLY_PID}" 2>/dev/null || true
  fi
  if [ "${APPLIED}" = "1" ];
  then
    say "destroying the callback stack (log: ${LOGDIR}/${RUN_ID}-destroy.log)"
    if ! IMAGE_TAG="${TAG}" tfl suite-callbacks destroy > "${LOGDIR}/${RUN_ID}-destroy.log" 2>&1;
    then
      say "THE CALLBACK STACK DID NOT DESTROY — its NAT gateway bills until it is. Re-run:"
      say "  TF_STACK=suite-callbacks deploy/aws/terraform-local.sh ${ENVIRONMENT} destroy"
      rc=1
    fi
  fi
  exit "${rc}"
}
trap cleanup EXIT
trap 'say "interrupted"; exit 130' INT TERM

if [ "${WITH_CALLBACKS}" = "1" ];
then
  say "applying the callback stack in the background (log: ${LOGDIR}/${RUN_ID}-apply.log)"
  APPLIED=1
  # terraform-local.sh ITSELF in the background, not a subshell around it, so
  # the interrupt cleanup() sends reaches the launcher that relays it to
  # terraform and releases the state lock.
  IMAGE_TAG="${TAG}" TF_STACK=suite-callbacks \
    "${ROOT}/deploy/aws/terraform-local.sh" "${ENVIRONMENT}" apply \
    > "${LOGDIR}/${RUN_ID}-apply.log" 2>&1 &
  APPLY_PID=$!
fi

# --- 4. the local half ----------------------------------------------------------
deadline=$(( $(date +%s) + ${STS_SUITE_WAIT_SECS:-900} ))
until curl -fsSk --max-time 10 "${URL}/healthcheck" > /dev/null 2>&1;
do
  if [ "$(date +%s)" -ge "${deadline}" ];
  then
    curl -vsk --max-time 10 "${URL}/healthcheck" || true
    die "${URL}/healthcheck did not answer. Is this machine's address in ${ENVIRONMENT}'s allowed_cidrs?"
  fi
  sleep 10
done
say "${URL}/healthcheck answers."

CLIENT_SECRET="$(aws secretsmanager get-secret-value --secret-id "${SECRET_ARN}" \
  --query SecretString --output text)"

EXCLUDE="${CALLBACK_JOBS}${STS_SUITE_EXCLUDE:+,${STS_SUITE_EXCLUDE}}"
ONLY="$(EXCLUDE="${EXCLUDE}" node -e '
  const skip = new Set(process.env.EXCLUDE.split(",").filter(Boolean));
  const jobs = require("./tests/vendored/MANIFEST.js").JOBS
    .map(function (j) { return j.file; })
    .filter(function (f) { return !skip.has(f); });
  process.stdout.write(jobs.join(","));
')"
if [ -n "${STS_SUITE_ONLY:-}" ];
then
  ONLY="${STS_SUITE_ONLY}"
fi
say "$(echo "${ONLY}" | tr ',' '\n' | wc -l) job(s) here; ${CALLBACK_JOBS} in the callback task."

mkdir -p "${REPORT_DIR}"
chmod 0777 "${REPORT_DIR}"
set +e
docker run --rm --network host \
  -v "${REPORT_DIR}:/report" \
  -e STS_ADMIN_API_CLIENT_SECRET="${CLIENT_SECRET}" \
  -e URL="${URL}" \
  -e KEEP="${STS_SUITE_KEEP_REALMS:-}" \
  -e ONLY="${ONLY}" \
  -e JOB_TIMEOUT="${STS_SUITE_JOB_TIMEOUT_MS:-1200000}" \
  -e STS_TEST_CLUSTER_NODES="${STS_TEST_CLUSTER_NODES:-${NODES}}" \
  -e STS_TEST_FRESH_CONNECTIONS=1 \
  -e STS_TEST_UNPUBLISHED="${UNPUBLISHED}" \
  -e STS_SPIFFE_WORKLOAD_URL="${STS_SPIFFE_WORKLOAD_URL:-}" \
  -e STS_SPIFFE_SERVER_URL="${STS_SPIFFE_SERVER_URL:-}" \
  -e STS_CLUSTER_ALTERNATION_REQUESTS="${STS_CLUSTER_ALTERNATION_REQUESTS:-200}" \
  -e STS_PUBLIC_BASE_URL="${URL}" \
  -e STS_TEST_SERVICE_URL="${URL}" \
  -e STS_LDAP_URL="ldap://${NLB_DNS}:${LDAP_PORT}" \
  -e STS_LDAP_PORT="${LDAP_PORT}" \
  "${TESTS_IMAGE}" bash -c '
    set -uo pipefail
    TOKEN="$(node tests/tools/admin-api-token.js "${URL}")" || {
      echo "run-suite: could not mint an /admin-api token." >&2; exit 2; }
    export STS_ADMIN_API_TOKEN="${TOKEN}"
    if [ "${KEEP}" != "1" ]; then
      node deploy/aws/reset-environment.js "${URL}" || exit 2
    fi
    node tests/tools/run-report.js --protocol=only --service-url="${URL}" \
      --timeout="${JOB_TIMEOUT}" --report-dir=/report --only="${ONLY}"
    rc=$?
    chmod -R a+rwX /report 2>/dev/null
    exit ${rc}'
LOCAL_RC=$?
set -e
LOCAL_RUN="$(readlink -f "${REPORT_DIR}/latest" || true)"
say "the local half exited ${LOCAL_RC}; report ${LOCAL_RUN}/report.html"

# --- 5. the callback half ---------------------------------------------------------
CALLBACK_RC=0
if [ "${WITH_CALLBACKS}" = "1" ];
then
  say "waiting for the callback stack"
  if ! wait "${APPLY_PID}";
  then
    APPLY_PID=""
    say "the callback stack did not apply; see ${LOGDIR}/${RUN_ID}-apply.log"
    CALLBACK_RC=1
  else
    APPLY_PID=""
    CB_JSON="$(IMAGE_TAG="${TAG}" tfl suite-callbacks output-json)"
    cb() {
      node -e 'const o = JSON.parse(process.argv[1]);
        process.stdout.write(String(o[process.argv[2]].value));' "${CB_JSON}" "$1"
    }
    CLUSTER="$(cb cluster)"
    FAMILY="$(cb task_definition)"
    SUBNET="$(cb subnet_id)"
    SG="$(cb security_group_id)"
    BUCKET="$(cb reports_bucket)"
    LOG_GROUP="$(cb log_group)"
    PEP_REALM="pep-$(date -u +%m%d%H%M%S)"
    OVERRIDES="$(RUN_ID="${RUN_ID}" PEP_REALM="${PEP_REALM}" ONLY="${CALLBACK_JOBS}" \
      JT="${STS_SUITE_JOB_TIMEOUT_MS:-}" node -e '
      const env = function (pairs) {
        return Object.keys(pairs).filter(function (k) { return pairs[k]; })
          .map(function (k) { return { name: k, value: pairs[k] }; });
      };
      process.stdout.write(JSON.stringify({ containerOverrides: [
        { name: "suite", environment: env({
            STS_SUITE_RUN_ID: process.env.RUN_ID,
            XACML_PEP_REALM: process.env.PEP_REALM,
            STS_SUITE_ONLY: process.env.ONLY,
            STS_SUITE_KEEP_REALMS: "1",
            STS_SUITE_JOB_TIMEOUT_MS: process.env.JT || "" }) },
        { name: "xacml-pep", environment: env({
            XACML_PEP_REALM: process.env.PEP_REALM }) }
      ] }));')"
    TASK_ARN="$(aws ecs run-task --cluster "${CLUSTER}" --task-definition "${FAMILY}" \
      --launch-type FARGATE --count 1 \
      --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],securityGroups=[${SG}],assignPublicIp=DISABLED}" \
      --overrides "${OVERRIDES}" \
      --tags "key=Project,value=STS" "key=Environment,value=${ENVIRONMENT}" "key=SuiteRun,value=${RUN_ID}" \
      --query 'tasks[0].taskArn' --output text)"
    [ -n "${TASK_ARN}" ] && [ "${TASK_ARN}" != "None" ] || die "ecs run-task started nothing."
    TASK_ID="${TASK_ARN##*/}"
    say "callback task ${TASK_ID}; logs: aws logs tail ${LOG_GROUP} --log-stream-names ${ENVIRONMENT}-callbacks/suite/${TASK_ID} --follow"
    tdeadline=$(( $(date +%s) + ${STS_SUITE_TASK_TIMEOUT_SECS:-3600} ))
    while :;
    do
      status="$(aws ecs describe-tasks --cluster "${CLUSTER}" --tasks "${TASK_ARN}" \
        --query 'tasks[0].lastStatus' --output text)"
      [ "${status}" = "STOPPED" ] && break
      if [ "$(date +%s)" -ge "${tdeadline}" ];
      then
        say "the callback task ran past STS_SUITE_TASK_TIMEOUT_SECS; stopping it."
        aws ecs stop-task --cluster "${CLUSTER}" --task "${TASK_ARN}" \
          --reason "run-suite timeout" >/dev/null 2>&1 || true
      fi
      sleep 20
    done
    read -r code reason < <(aws ecs describe-tasks --cluster "${CLUSTER}" --tasks "${TASK_ARN}" \
      --query 'tasks[0].[containers[?name==`suite`].exitCode | [0], stoppedReason]' --output text)
    TASK_ARN=""
    say "the callback task stopped (${reason}); its suite exited ${code}."
    case "${code}" in ''|None) CALLBACK_RC=1 ;; *) CALLBACK_RC="${code}" ;; esac
    CB_DIR="${REPORT_DIR}/callbacks-${RUN_ID}"
    mkdir -p "${CB_DIR}"
    if aws s3 cp "s3://${BUCKET}/${ENVIRONMENT}/${RUN_ID}/report.tar.gz" \
         "${CB_DIR}/report.tar.gz" --only-show-errors;
    then
      tar -C "${CB_DIR}" -xzf "${CB_DIR}/report.tar.gz"
      rm -f "${CB_DIR}/report.tar.gz"
      chmod -R a+rwX "${CB_DIR}"
      if [ -n "${LOCAL_RUN}" ] && [ -d "${LOCAL_RUN}" ];
      then
        docker run --rm -v "${REPORT_DIR}:/report" "${TESTS_IMAGE}" \
          node tests/tools/merge-report.js \
            --into="/report/$(basename "${LOCAL_RUN}")" \
            --from="/report/callbacks-${RUN_ID}/latest" --label=callbacks || true
      fi
    else
      say "the callback task uploaded no report."
      CALLBACK_RC=1
    fi
  fi
fi

# --- 6. what happened ---------------------------------------------------------------
if [ -n "${LOCAL_RUN}" ] && [ -f "${LOCAL_RUN}/summary.json" ];
then
  node -e '
    const s = require(process.argv[1]);
    const count = {};
    s.jobs.forEach(function (j) { count[j.status] = (count[j.status] || 0) + 1; });
    console.log("run-suite: " + JSON.stringify(count));
    s.jobs.filter(function (j) { return j.status !== "passed"; })
      .forEach(function (j) { console.log("  " + j.status + "  " + j.name); });
  ' "${LOCAL_RUN}/summary.json" || true
  say "report: ${LOCAL_RUN}/report.html"
fi
if [ "${LOCAL_RC}" != "0" ] || [ "${CALLBACK_RC}" != "0" ];
then
  exit 1
fi
exit 0
