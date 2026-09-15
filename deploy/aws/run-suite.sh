#!/usr/bin/env bash
#
# File: deploy/aws/run-suite.sh
#
# ---------------------------------------------------------------------------
# THE PROTOCOL SUITE AGAINST A DEPLOYED AWS ENVIRONMENT (issue #51).
#
# Run from the repository root, with AWS credentials that can read the
# environment's admin API client secret (the deployer role can), after
# `terraform apply` in deploy/aws/environment/:
#
#   deploy/aws/run-suite.sh <environment>        # e.g. dev, ci
#
# What it does, in order:
#   1. reads the service URL and the client secret's ARN from Terraform output;
#   2. waits for the load balancer to answer (DNS for a new NLB takes minutes);
#   3. mints an /admin-api access token with that secret;
#   4. runs `tests/tools/run-report.js --protocol=only` against the URL, with
#      the cluster-mode settings for three nodes behind a load balancer, and
#      every vendored job EXCEPT the four that cannot work through a single
#      public 443 endpoint.
#
# THE FOUR EXCLUSIONS, and each is a fact about the deployment rather than a
# defect: `sts_xacml_remote_pep` (a PEP container on the RUNNER that the
# cluster would have to reach), `sts_directory_bulk_load_ldap` (LDAP 389, not
# exposed), `sts_pki_distribution_points` (follows http://…:8082 and ldap://
# addresses written into certificates, not exposed) and `sts_gnap_core` (the
# service posts back to a listener on the runner). The job list is computed
# from tests/vendored/MANIFEST.js minus those four, so a job added there runs
# here without this file being edited.
#
# THE PER-JOB WATCHDOG IS TWENTY MINUTES, NOT THE RUNNER'S FIVE. Every request
# crosses the internet on a new TLS connection (so the balancer spreads them),
# and the first run against AWS lost eight jobs — the cluster alternation job
# among them, passing its checks — to the 300-second default rather than to any
# assertion. STS_SUITE_JOB_TIMEOUT_MS overrides it; a job whose manifest entry
# asks for longer keeps its own.
#
# STS_SUITE_EXCLUDE adds more (comma-separated file names), e.g. the two
# remaining bulk loads for a faster run:
#   STS_SUITE_EXCLUDE=sts_directory_bulk_load_scim.js,sts_directory_bulk_load_api.js
# ---------------------------------------------------------------------------
set -euo pipefail

ENVIRONMENT="${1:?usage: deploy/aws/run-suite.sh <environment>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TF_DIR="${ROOT}/deploy/aws/environment"
REPORT_DIR="${STS_SUITE_REPORT_DIR:-${ROOT}/tests/report/aws-${ENVIRONMENT}}"

cd "${ROOT}"

URL="$(terraform -chdir="${TF_DIR}" output -raw service_url)"
SECRET_ARN="$(terraform -chdir="${TF_DIR}" output -raw admin_api_client_secret_arn)"
echo "run-suite: ${ENVIRONMENT} at ${URL}"

# A new NLB's DNS name can take several minutes to resolve, and a node that
# passed its health check a moment ago is already registered — so wait for
# the healthcheck through the balancer rather than for the DNS alone.
deadline=$(( $(date +%s) + ${STS_SUITE_WAIT_SECS:-900} ))
until curl -fsSk --max-time 10 "${URL}/healthcheck" > /dev/null 2>&1;
do
  if [ "$(date +%s)" -ge "${deadline}" ];
  then
    echo "run-suite: ${URL}/healthcheck did not answer in time." >&2
    curl -vsk --max-time 10 "${URL}/healthcheck" || true
    exit 1
  fi
  sleep 10
done
echo "run-suite: ${URL}/healthcheck answers."

CLIENT_SECRET="$(aws secretsmanager get-secret-value --secret-id "${SECRET_ARN}" \
  --query SecretString --output text)"
if [ -n "${GITHUB_ACTIONS:-}" ];
then
  echo "::add-mask::${CLIENT_SECRET}"
fi

# The audience is <base>/admin-api, so the URL has no port (443 is implied).
TOKEN="$(STS_ADMIN_API_CLIENT_SECRET="${CLIENT_SECRET}" \
  node tests/tools/admin-api-token.js "${URL}")"
if [ -n "${GITHUB_ACTIONS:-}" ];
then
  echo "::add-mask::${TOKEN}"
fi

EXCLUDE="sts_xacml_remote_pep.js,sts_directory_bulk_load_ldap.js,sts_pki_distribution_points.js,sts_gnap_core.js"
if [ -n "${STS_SUITE_EXCLUDE:-}" ];
then
  EXCLUDE="${EXCLUDE},${STS_SUITE_EXCLUDE}"
fi
ONLY="$(EXCLUDE="${EXCLUDE}" node -e '
  const skip = new Set(process.env.EXCLUDE.split(",").filter(Boolean));
  const jobs = require("./tests/vendored/MANIFEST.js").JOBS
    .map(function (j) { return j.file; })
    .filter(function (f) { return !skip.has(f); });
  process.stdout.write(jobs.join(","));
')"
# STS_SUITE_ONLY replaces the computed list — for re-running the jobs a
# previous run failed without paying for the ones that passed.
if [ -n "${STS_SUITE_ONLY:-}" ];
then
  ONLY="${STS_SUITE_ONLY}"
fi
echo "run-suite: $(echo "${ONLY}" | tr ',' '\n' | wc -l) job(s); excluded ${EXCLUDE}."

mkdir -p "${REPORT_DIR}"
set +e
STS_ADMIN_API_TOKEN="${TOKEN}" \
STS_ADMIN_API_CLIENT_SECRET="${CLIENT_SECRET}" \
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
set -e
echo "run-suite: run-report.js exited ${rc}; report under ${REPORT_DIR}/latest"
exit "${rc}"
