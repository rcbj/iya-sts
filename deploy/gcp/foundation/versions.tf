# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE LONG-LIVED GCP FOUNDATION (issue #95), applied by an administrator.
#
# deploy/aws/foundation/'s counterpart: what outlives every environment, and
# the identities an environment runs as. State at `foundation/` in the bucket
# deploy/gcp/bootstrap-state.sh made:
#   terraform init -backend-config="bucket=mock-sts-terraform-state-<project>"
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.0"
    }
  }

  backend "gcs" {
    prefix = "foundation"
  }
}
