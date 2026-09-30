# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

locals {
  project_number = data.google_project.current.number
  state_bucket   = var.state_bucket != "" ? var.state_bucket : "${var.name}-terraform-state-${var.project_id}"

  # The environments with a public name: they get a certificate secret, and
  # their node account may write the DNS-01 challenge into the zone.
  public_environments = {
    for k, v in var.environments : k => v if v.public_hostname != ""
  }

  # Where the images are pushed and pulled:
  #   <region>-docker.pkg.dev/<project>/mock-sts/<image>:<tag>
  registry_host = "${var.region}-docker.pkg.dev"
  registry_url  = "${local.registry_host}/${var.project_id}/${var.name}"
}
