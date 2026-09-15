#!/usr/bin/env bash
#
# File: deploy/aws/bootstrap-state.sh
#
# ---------------------------------------------------------------------------
# THE BUCKET TERRAFORM KEEPS ITS STATE IN, CREATED ONCE (issue #51).
#
# Deliberately NOT managed by Terraform: it holds Terraform's state, so the
# stack that would create it has nowhere to record having done so. This is the
# parent project's arrangement (`infra/bootstrap-state.sh`), with a bucket of
# this project's own — the account already holds another project's state bucket
# and nothing here touches it.
#
# Idempotent: an existing bucket is left as it is, and the settings below are
# (re)applied, which changes nothing when they already hold.
#
# Run with credentials allowed to create a bucket — an administrator, once.
#   deploy/aws/bootstrap-state.sh
# ---------------------------------------------------------------------------
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
STATE_BUCKET="${STATE_BUCKET:-mock-sts-terraform-state-${ACCOUNT_ID}}"

if aws s3api head-bucket --bucket "${STATE_BUCKET}" 2> /dev/null;
then
  echo "bootstrap-state: ${STATE_BUCKET} already exists."
else
  echo "bootstrap-state: creating ${STATE_BUCKET} in ${AWS_REGION}."
  aws s3api create-bucket --bucket "${STATE_BUCKET}" --region "${AWS_REGION}" \
    --create-bucket-configuration "LocationConstraint=${AWS_REGION}" > /dev/null
fi

# Versioned, so a state file overwritten by a bad apply can be recovered.
aws s3api put-bucket-versioning --bucket "${STATE_BUCKET}" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "${STATE_BUCKET}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
aws s3api put-public-access-block --bucket "${STATE_BUCKET}" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-tagging --bucket "${STATE_BUCKET}" \
  --tagging 'TagSet=[{Key=Project,Value=STS},{Key=ManagedBy,Value=bootstrap-state.sh}]'

echo "bootstrap-state: s3://${STATE_BUCKET} is versioned, encrypted, private" \
     "and tagged Project=STS."
