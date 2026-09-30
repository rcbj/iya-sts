# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# AWS's `Project = STS` and `Environment` tags, as labels (lower case: a label
# value may not hold a capital). On AWS the tag is also a fence the deployer
# is held to; here the project is (foundation/iam_deployer.tf), and the
# labels are for the bill and for a reader.
provider "google" {
  project = var.project_id
  # A CELL IS IN ITS OWN REGION (#97, cells.tf); a single-cell environment in
  # `region`.
  region = var.cell != "" ? var.cells[var.cell].region : var.region

  default_labels = merge(var.labels, {
    project     = "sts"
    environment = var.environment
  })
}
