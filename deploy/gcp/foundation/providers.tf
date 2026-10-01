# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# `project = sts` is AWS's `Project = STS` tag, lower-cased because a GCP
# label value may not hold a capital letter. Nothing here is fenced by it the
# way the AWS deployer is (a GCP IAM condition cannot test a label on most of
# these resources); THE PROJECT IS THE FENCE on this side, and the label is
# for the bill and for a reader.
provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = merge(var.labels, {
    project = "sts"
    stack   = "mock-sts-foundation"
  })
}

# For `google_project_service_identity`, which is still beta: the service
# agents that must be allowed to use the project key are created here rather
# than assumed to exist.
provider "google-beta" {
  project = var.project_id
  region  = var.region
}

data "google_project" "current" {}
