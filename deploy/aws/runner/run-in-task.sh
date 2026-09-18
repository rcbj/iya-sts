#!/usr/bin/env bash
#
# File: deploy/aws/runner/run-in-task.sh
#
# ---------------------------------------------------------------------------
# THE PROTOCOL SUITE, INSIDE AN AWS ENVIRONMENT (issue #51).
#
# The `suite` container of environment/runner.tf's task; started by
# deploy/aws/run-suite-in-aws.sh, never by hand. What deploy/aws/run-suite.sh
# does from outside, with three differences that are why it exists:
#
#   * NO JOB IS EXCLUDED. The nodes can reach this task, so sts_gnap_core's
#     push listener (GNAP_PUSH_HOST, this task's own address) and the PEP
#     container beside it (localhost) work; the load balancer publishes
#     389, 636 and the plain-HTTP CRL/OCSP port (8082 here, 80 in testidp)
#     beside 443, so sts_global_logout, the LDAP bulk load and
#     sts_pki_distribution_points do — the last follows whatever address the
#     certificate carries. Nothing dials 636 yet; see run-suite.sh. (It published 9443 too until 2026-09-16,
#     for the service's mutual-TLS listener; that listener was deleted and a
#     certificate sign-in is GET /tls/sign-in on the main port.)
#   * THE REPORT GOES TO S3, at s3://$STS_REPORTS_BUCKET/<environment>/<run id>/
#     as report.tar.gz and summary.json, because nothing outside the task can
#     see its file system.
#   * THE EXIT CODE IS run-report.js's, and ECS records it on the container,
#     which is what run-suite-in-aws.sh reports.
#
# Environment (the task definition sets all but the overrides):
#   STS_SUITE_SERVICE_URL, STS_SUITE_ENVIRONMENT, STS_REPORTS_BUCKET,
#   STS_ADMIN_API_CLIENT_SECRET (injected from Secrets Manager),
#   STS_SUITE_RUN_ID            the report's key prefix (override per run)
#   STS_SUITE_EXCLUDE, STS_SUITE_ONLY, STS_SUITE_JOB_TIMEOUT_MS (overrides)
#   STS_SUITE_KEEP_REALMS=1     do not remove the previous run's realms first
# ---------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "$(realpath "$0")")/../../.." || exit 1

URL="${STS_SUITE_SERVICE_URL:?}"
URL="${URL%/}"
ENVIRONMENT="${STS_SUITE_ENVIRONMENT:?}"
RUN_ID="${STS_SUITE_RUN_ID:-$(date -u +%Y-%m-%dT%H-%M-%S)}"
REPORT_DIR=/tmp/sts-report
KEY_PREFIX="${ENVIRONMENT}/${RUN_ID}"

echo "run-in-task: ${ENVIRONMENT} at ${URL}, run ${RUN_ID}"

# This task's own address, which the nodes reach directly (security.tf).
TASK_IP="$(node -e '
  fetch(process.env.ECS_CONTAINER_METADATA_URI_V4 + "/task")
    .then(function (r) { return r.json(); })
    .then(function (t) {
      process.stdout.write(t.Containers[0].Networks[0].IPv4Addresses[0]);
    });')"
if [ -z "${TASK_IP}" ];
then
  echo "run-in-task: could not read this task's address from the metadata" \
       "endpoint; sts_gnap_core's push will not be deliverable." >&2
fi
export GNAP_PUSH_HOST="${TASK_IP:-localhost}"

deadline=$(( $(date +%s) + ${STS_SUITE_WAIT_SECS:-900} ))
until node -e '
  require("https").get(process.argv[1] + "/healthcheck",
    { rejectUnauthorized: false, timeout: 5000 },
    function (r) { process.exit(r.statusCode === 200 ? 0 : 1); })
    .on("error", function () { process.exit(1); })
    .on("timeout", function () { process.exit(1); });' "${URL}";
do
  if [ "$(date +%s)" -ge "${deadline}" ];
  then
    echo "run-in-task: ${URL}/healthcheck did not answer in time." >&2
    exit 1
  fi
  sleep 10
done
echo "run-in-task: ${URL}/healthcheck answers."

if [ -f "${XACML_PEP_CA_PEM_FILE:-/nonexistent}" ];
then
  export XACML_PEP_CA_PEM="$(cat "${XACML_PEP_CA_PEM_FILE}")"
fi

TOKEN="$(node tests/tools/admin-api-token.js "${URL}")" || {
  echo "run-in-task: could not mint an /admin-api token." >&2
  exit 1
}

# THE PREVIOUS RUN'S REALMS AND OVERRIDES GO FIRST, so the environment can be
# reused: the suite leaves every realm it creates, and a long-lived cluster
# would otherwise carry every run's. deploy/aws/reset-environment.js argues it;
# a failure to remove one is the run's failure, because a realm with a fixed id
# left behind fails the job that creates it with a message about something
# else.
STS_ADMIN_API_TOKEN="${TOKEN}" node deploy/aws/reset-environment.js "${URL}" || {
  echo "run-in-task: the previous run's realms could not all be removed." >&2
  exit 1
}

EXCLUDE="${STS_SUITE_EXCLUDE:-}"
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
echo "run-in-task: $(echo "${ONLY}" | tr ',' '\n' | wc -l) job(s)" \
     "${EXCLUDE:+, excluded ${EXCLUDE}}."

mkdir -p "${REPORT_DIR}"
STS_ADMIN_API_TOKEN="${TOKEN}" \
STS_TEST_CLUSTER_NODES="${STS_TEST_CLUSTER_NODES:-3}" \
STS_TEST_FRESH_CONNECTIONS=1 \
STS_CLUSTER_ALTERNATION_REQUESTS="${STS_CLUSTER_ALTERNATION_REQUESTS:-200}" \
STS_PUBLIC_BASE_URL="${URL}" \
  node tests/tools/run-report.js --protocol=only \
    --service-url="${URL}" \
    --timeout="${STS_SUITE_JOB_TIMEOUT_MS:-1200000}" \
    --report-dir="${REPORT_DIR}" \
    --only="${ONLY}"
rc=$?
echo "run-in-task: run-report.js exited ${rc}"

# The report, as one archive and the summary beside it. `latest` is a symlink
# to the run's own directory; -h archives what it points at.
latest="${REPORT_DIR}/latest"
if [ -e "${latest}" ];
then
  tar -C "${REPORT_DIR}" -chzf /tmp/report.tar.gz latest
  node deploy/aws/runner/upload-report.js /tmp/report.tar.gz \
    "${STS_REPORTS_BUCKET}" "${KEY_PREFIX}/report.tar.gz" application/gzip \
    || echo "run-in-task: the report archive could not be uploaded." >&2
  if [ -f "${latest}/summary.json" ];
  then
    node deploy/aws/runner/upload-report.js "${latest}/summary.json" \
      "${STS_REPORTS_BUCKET}" "${KEY_PREFIX}/summary.json" application/json \
      || echo "run-in-task: the summary could not be uploaded." >&2
  fi
else
  echo "run-in-task: run-report.js wrote no report under ${REPORT_DIR}." >&2
fi
printf '%s' "${rc}" > /tmp/exit-code
node deploy/aws/runner/upload-report.js /tmp/exit-code \
  "${STS_REPORTS_BUCKET}" "${KEY_PREFIX}/exit-code" text/plain || true
exit "${rc}"
