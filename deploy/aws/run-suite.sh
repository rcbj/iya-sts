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
#      every vendored job EXCEPT the two that need the service to reach the
#      machine running them.
#
# THIS IS THE FROM-OUTSIDE PATH. deploy/aws/run-suite-in-aws.sh runs every job,
# as a task inside the VPC, and is what the workflow uses; this one is for a
# quick run from a developer machine whose address is in allowed_cidrs.
#
# THE TWO EXCLUSIONS, and each is a fact about where this runs rather than a
# defect: `sts_xacml_remote_pep` (a PEP container beside the runner that the
# cluster nudges) and `sts_gnap_core` (the service posts back to a listener on
# the runner) — nothing behind NAT can be dialled. The load balancer publishes
# 9443, 389 and 8082 as well as 443 (environment/locals.tf), so the mutual-TLS
# sign-in, the LDAP bulk load and the CRL addresses in certificates all work
# from here. The job list is computed from tests/vendored/MANIFEST.js minus
# the two, so a job added there runs here without this file being edited.
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

# The previous run's realms, removed so the environment can be reused
# (deploy/aws/reset-environment.js). STS_SUITE_KEEP_REALMS=1 keeps them.
STS_ADMIN_API_TOKEN="${TOKEN}" node deploy/aws/reset-environment.js "${URL}"

EXCLUDE="sts_xacml_remote_pep.js,sts_gnap_core.js"
NLB_HOST="${URL#https://}"
NLB_HOST="${NLB_HOST%%/*}"
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
STS_LDAP_URL="ldap://${NLB_HOST}:389" \
STS_LDAP_PORT=389 \
STS_MTLS_PORT=9443 \
  node tests/tools/run-report.js --protocol=only \
    --service-url="${URL}" \
    --timeout="${STS_SUITE_JOB_TIMEOUT_MS:-1200000}" \
    --report-dir="${REPORT_DIR}" \
    --only="${ONLY}"
rc=$?
set -e
echo "run-suite: run-report.js exited ${rc}; report under ${REPORT_DIR}/latest"
exit "${rc}"
