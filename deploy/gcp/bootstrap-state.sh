#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/bootstrap-state.sh
#
# ---------------------------------------------------------------------------
# THE BUCKET TERRAFORM KEEPS ITS STATE IN, CREATED ONCE (issue #95).
#
# deploy/aws/bootstrap-state.sh's arrangement on Cloud Storage, and NOT
# managed by Terraform for the same reason: it holds Terraform's state, so the
# stack that would create it has nowhere to record having done so.
#
#   mock-sts-terraform-state-<project>   versioned, uniform bucket-level
#                                        access, public access prevented,
#                                        in the home region
#
# THE GCS BACKEND LOCKS WITH A LOCK OBJECT beside the state (no table, unlike
# S3 before `use_lockfile`), so nothing else is needed. Versioning is what
# makes a bad apply recoverable: the previous state is a noncurrent version.
#
# Idempotent: an existing bucket is left as it is and the settings below are
# (re)applied, which changes nothing when they already hold.
#
# Run with credentials allowed to create a bucket — an administrator, once:
#   GOOGLE_CLOUD_PROJECT=<project> deploy/gcp/bootstrap-state.sh
# ---------------------------------------------------------------------------
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2> /dev/null)}"
[ -n "${PROJECT}" ] || {
  echo "ERROR: set GOOGLE_CLOUD_PROJECT (or gcloud config set project)." >&2
  exit 1
}
REGION="${GCP_REGION:-us-west1}"
STATE_BUCKET="${STATE_BUCKET:-mock-sts-terraform-state-${PROJECT}}"

if gcloud storage buckets describe "gs://${STATE_BUCKET}" \
     --project "${PROJECT}" > /dev/null 2>&1;
then
  echo "==> gs://${STATE_BUCKET} exists; re-applying its settings."
else
  echo "==> Creating gs://${STATE_BUCKET} in ${REGION}."
  gcloud storage buckets create "gs://${STATE_BUCKET}" \
    --project "${PROJECT}" \
    --location "${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention
fi

gcloud storage buckets update "gs://${STATE_BUCKET}" \
  --project "${PROJECT}" \
  --versioning \
  --uniform-bucket-level-access \
  --public-access-prevention

# Old state versions are kept for ninety days and then go: long enough to
# recover from any apply a person notices, short enough not to keep every
# state of every environment for ever.
policy="$(mktemp)"
trap 'rm -f "${policy}"' EXIT
cat > "${policy}" <<'JSON'
{ "rule": [ { "action": { "type": "Delete" },
              "condition": { "isLive": false, "daysSinceNoncurrentTime": 90 } } ] }
JSON
gcloud storage buckets update "gs://${STATE_BUCKET}" \
  --project "${PROJECT}" --lifecycle-file "${policy}"

echo "==> Done. Next: terraform -chdir=deploy/gcp/foundation init" \
     "-backend-config=bucket=${STATE_BUCKET}"
