#!/usr/bin/env bash
#
# File: deploy/aws/run-suite-in-aws.sh
#
# ---------------------------------------------------------------------------
# THE WHOLE PROTOCOL SUITE, RUN INSIDE AN AWS ENVIRONMENT (issue #51).
#
#   deploy/aws/run-suite-in-aws.sh <environment>
#
# Run from the repository root with the deployer role's credentials, after
# `terraform apply` in deploy/aws/environment/ with `suite_runner` on (the
# default) and the runner and PEP images pushed:
#
#   1. starts the suite task (environment/runner.tf) with `ecs run-task`, in
#      the runner subnet, with a run id and a realm of its own for the PEP;
#   2. waits for it to stop, saying every few minutes which job the suite is
#      on (read from the task's log stream);
#   3. downloads report.tar.gz from the report bucket into
#      tests/report/aws-<environment>/<run id>/ and prints the summary;
#   4. exits with the suite container's exit code.
#
# Every job in tests/vendored/MANIFEST.js runs, after every realm but the
# default one is removed (reset-environment.js) so an environment can be reused;
# STS_SUITE_EXCLUDE, STS_SUITE_ONLY, STS_SUITE_JOB_TIMEOUT_MS and
# STS_SUITE_KEEP_REALMS are passed through to the task.
# STS_SUITE_TASK_TIMEOUT_SECS (default 10800) stops a task that will not
# finish, rather than waiting for ever.
# ---------------------------------------------------------------------------
set -euo pipefail

ENVIRONMENT="${1:?usage: deploy/aws/run-suite-in-aws.sh <environment>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TF_DIR="${ROOT}/deploy/aws/environment"
cd "${ROOT}"

out() { terraform -chdir="${TF_DIR}" output -raw "$1"; }
CLUSTER="$(out ecs_cluster)"
FAMILY="$(out runner_task_definition)"
SUBNET="$(out runner_subnet_id)"
SG="$(out runner_security_group_id)"
BUCKET="$(out reports_bucket)"
URL="$(out service_url)"
if [ -z "${FAMILY}" ];
then
  echo "run-suite-in-aws: this environment has no suite runner" \
       "(suite_runner = false); use deploy/aws/run-suite.sh." >&2
  exit 1
fi

RUN_ID="$(date -u +%Y-%m-%dT%H-%M-%S)"
# A realm per run for the PEP: its id is fixed for the life of a stack, and a
# second run would meet the first run's realm (tests/CLAUDE.md, *No job
# removes a realm*).
PEP_REALM="pep-$(date -u +%m%d%H%M%S)"
REPORT_DIR="${STS_SUITE_REPORT_DIR:-${ROOT}/tests/report/aws-${ENVIRONMENT}}"

OVERRIDES="$(RUN_ID="${RUN_ID}" PEP_REALM="${PEP_REALM}" node -e '
  const env = function (pairs) {
    return Object.keys(pairs).filter(function (k) { return pairs[k]; })
      .map(function (k) { return { name: k, value: pairs[k] }; });
  };
  process.stdout.write(JSON.stringify({ containerOverrides: [
    { name: "suite", environment: env({
        STS_SUITE_RUN_ID: process.env.RUN_ID,
        XACML_PEP_REALM: process.env.PEP_REALM,
        STS_SUITE_EXCLUDE: process.env.STS_SUITE_EXCLUDE || "",
        STS_SUITE_ONLY: process.env.STS_SUITE_ONLY || "",
        STS_SUITE_JOB_TIMEOUT_MS: process.env.STS_SUITE_JOB_TIMEOUT_MS || "",
        STS_SUITE_KEEP_REALMS: process.env.STS_SUITE_KEEP_REALMS || ""
      }) },
    { name: "xacml-pep", environment: env({
        XACML_PEP_REALM: process.env.PEP_REALM }) }
  ] }));')"

echo "run-suite-in-aws: ${ENVIRONMENT} at ${URL}, run ${RUN_ID}, PEP realm ${PEP_REALM}"
TASK_ARN="$(aws ecs run-task \
  --cluster "${CLUSTER}" \
  --task-definition "${FAMILY}" \
  --launch-type FARGATE \
  --count 1 \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],securityGroups=[${SG}],assignPublicIp=DISABLED}" \
  --overrides "${OVERRIDES}" \
  --tags "key=Project,value=STS" "key=Environment,value=${ENVIRONMENT}" "key=SuiteRun,value=${RUN_ID}" \
  --query 'tasks[0].taskArn' --output text)"
if [ -z "${TASK_ARN}" ] || [ "${TASK_ARN}" = "None" ];
then
  echo "run-suite-in-aws: ecs run-task started nothing." >&2
  exit 1
fi
TASK_ID="${TASK_ARN##*/}"
echo "run-suite-in-aws: task ${TASK_ID}"
echo "  logs: aws logs tail /mock-sts/containers --log-stream-names ${ENVIRONMENT}-suite/suite/${TASK_ID} --follow"

stopTheTask() {
  aws ecs stop-task --cluster "${CLUSTER}" --task "${TASK_ARN}" \
    --reason "run-suite-in-aws interrupted" > /dev/null 2>&1 || true
}
trap 'echo "run-suite-in-aws: interrupted; stopping the task." >&2; stopTheTask; exit 130' INT TERM

deadline=$(( $(date +%s) + ${STS_SUITE_TASK_TIMEOUT_SECS:-10800} ))
last_note=0
while :;
do
  status="$(aws ecs describe-tasks --cluster "${CLUSTER}" --tasks "${TASK_ARN}" \
    --query 'tasks[0].lastStatus' --output text)"
  [ "${status}" = "STOPPED" ] && break
  now=$(date +%s)
  if [ "${now}" -ge "${deadline}" ];
  then
    echo "run-suite-in-aws: the task ran past STS_SUITE_TASK_TIMEOUT_SECS; stopping it." >&2
    stopTheTask
  fi
  if [ $(( now - last_note )) -ge 180 ];
  then
    last_note=${now}
    job="$(aws logs get-log-events --log-group-name /mock-sts/containers \
      --log-stream-name "${ENVIRONMENT}-suite/suite/${TASK_ID}" \
      --start-from-head --output text --query 'events[].message' 2>/dev/null \
      | tr '\t' '\n' | grep -oE '\[[0-9]+/[0-9]+\] protocol — [a-z0-9_]+' | tail -1 || true)"
    echo "run-suite-in-aws: $(date -u +%H:%M) ${status}${job:+ — ${job}}"
  fi
  sleep 20
done

read -r code reason < <(aws ecs describe-tasks --cluster "${CLUSTER}" --tasks "${TASK_ARN}" \
  --query 'tasks[0].[containers[?name==`suite`].exitCode | [0], stoppedReason]' --output text)
echo "run-suite-in-aws: the task stopped (${reason}); the suite exited ${code}."

dest="${REPORT_DIR}/${RUN_ID}"
mkdir -p "${dest}"
if aws s3 cp "s3://${BUCKET}/${ENVIRONMENT}/${RUN_ID}/report.tar.gz" "${dest}/report.tar.gz" --only-show-errors;
then
  tar -C "${dest}" -xzf "${dest}/report.tar.gz"
  rm -f "${dest}/report.tar.gz"
  ln -sfn "${RUN_ID}/latest" "${REPORT_DIR}/latest"
  echo "run-suite-in-aws: report at ${dest}/latest/report.html"
  node -e '
    const s = require(process.argv[1]);
    const count = {};
    s.jobs.forEach(function (j) { count[j.status] = (count[j.status] || 0) + 1; });
    console.log("run-suite-in-aws: " + JSON.stringify(count));
    s.jobs.filter(function (j) { return j.status !== "passed"; })
      .forEach(function (j) { console.log("  " + j.status + "  " + j.name); });
  ' "${dest}/latest/summary.json" || true
else
  echo "run-suite-in-aws: no report was uploaded for this run." >&2
fi

case "${code}" in
  ''|None) exit 1 ;;
  *) exit "${code}" ;;
esac
