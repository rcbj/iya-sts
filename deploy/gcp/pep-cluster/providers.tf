# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = merge(var.labels, {
    project     = "sts"
    environment = var.environment
    pep-cluster = var.cluster
  })
}
