# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE APIS THIS PROJECT USES, TURNED ON HERE AND NEVER OFF.
#
# `disable_on_destroy = false`: turning an API off destroys what it holds
# (every Cloud SQL instance, every secret), and a destroy of this stack is not
# a request for that. The environment stack turns nothing on; the deployer
# cannot (iam_deployer.tf), which is the point.
# ---------------------------------------------------------------------------
locals {
  apis = [
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    # Private services access, for the global tier's Cloud SQL copies in a
    # multi-cloud environment (#97).
    "servicenetworking.googleapis.com",
    "serviceusage.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = each.key
  disable_on_destroy = false
}
