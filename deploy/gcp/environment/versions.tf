# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE THREE-NODE iya-sts ENVIRONMENT ON GCP, CREATED AND DESTROYED PER RUN
# (issue #95) — deploy/aws/environment/'s single-region pattern, rebuilt out
# of GCP's parts. deploy/gcp/CLAUDE.md maps each piece to the AWS one and
# argues every place they differ.
#
# Applied as the `iya-sts-deployer` service account (impersonated), never as
# an owner: its roles (../foundation/iam_deployer.tf) are the proof that this
# stack needs no more. The foundation must exist first, and must list this
# environment in its `environments` (the node service account is made there).
#
# The state prefix names the environment:
#   terraform init -backend-config="bucket=iya-sts-terraform-state-<project>" \
#                  -backend-config="prefix=environment/dev"
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "gcs" {}
}
