# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  project_number = data.google_project.current.number
  state_bucket   = var.state_bucket != "" ? var.state_bucket : "${var.name}-terraform-state-${var.project_id}"

  # The environments with a public name: they get a certificate secret, and
  # their node account may write the DNS-01 challenge into the zone.
  public_environments = {
    for k, v in var.environments : k => v if v.public_hostname != ""
  }

  # Where the images are pushed and pulled:
  #   <region>-docker.pkg.dev/<project>/iya-sts/<image>:<tag>
  registry_host = "${var.region}-docker.pkg.dev"
  registry_url  = "${local.registry_host}/${var.project_id}/${var.name}"

  # THE MULTI-CELL ENVIRONMENTS' CELLS (#97), from their shared file.
  multicell = {
    for e in var.multicell_environments :
    e => jsondecode(file("${path.module}/../../multicloud/envs/${e}.cells.tfvars.json"))
  }
  gcp_cells = merge([
    for e, f in local.multicell : {
      for id, c in f.cells : "${e}-${id}" => merge(c, { env = e, id = id })
      if lookup(c, "cloud", "aws") == "gcp"
    }
  ]...)
  aws_cells = merge([
    for e, f in local.multicell : {
      for id, c in f.cells : "${e}-${id}" => merge(c, { env = e, id = id })
      if lookup(c, "cloud", "aws") == "aws"
    }
  ]...)

  # Every region a key ring is needed in: the home region, and each GCP
  # cell's — Cloud SQL, a disk and a regional secret take a key in their own
  # region only.
  other_regions = setsubtract(toset([for c in values(local.gcp_cells) : c.region]), [var.region])
  kms_keys = merge(
    { (var.region) = google_kms_crypto_key.main.id },
    { for r, k in google_kms_crypto_key.regional : r => k.id },
  )
}
