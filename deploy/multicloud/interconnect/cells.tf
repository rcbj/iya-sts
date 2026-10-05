# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# Every cell, as its own `base` apply left it: AWS cells from the AWS bucket,
# GCP cells from the GCP bucket.

locals {
  aws_cells = { for id, c in var.cells : id => c if c.cloud == "aws" }
  gcp_cells = { for id, c in var.cells : id => c if c.cloud == "gcp" }

  jurisdictions = distinct([for c in values(var.cells) : c.jurisdiction])

  # Each jurisdiction's pair: its AWS cell and its GCP cell (variables.tf
  # holds that there is exactly one of each).
  pair_of = {
    for j in local.jurisdictions : j => {
      aws = one([for id, c in local.aws_cells : id if c.jurisdiction == j])
      gcp = one([for id, c in local.gcp_cells : id if c.jurisdiction == j])
    }
  }
  # The same, by AWS cell — what the pair modules are keyed by.
  partner = { for j, p in local.pair_of : p.aws => p.gcp }
}

data "terraform_remote_state" "aws_cell" {
  for_each = local.aws_cells
  backend  = "s3"
  config = {
    region = var.state_region
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key    = "environment/${var.environment}/${each.key}.tfstate"
  }
}

data "terraform_remote_state" "gcp_cell" {
  for_each = local.gcp_cells
  backend  = "gcs"
  config = {
    bucket = "${var.name}-terraform-state-${var.project_id}"
    prefix = "environment/${var.environment}/${each.key}"
  }
}

locals {
  aws = {
    for id, c in local.aws_cells : id => {
      id                   = id
      region               = c.region
      vpc_id               = data.terraform_remote_state.aws_cell[id].outputs.vpc_id
      vpc_cidr             = data.terraform_remote_state.aws_cell[id].outputs.vpc_cidr
      route_table_ids      = data.terraform_remote_state.aws_cell[id].outputs.route_table_ids
      private_subnet_ids   = data.terraform_remote_state.aws_cell[id].outputs.private_subnet_ids
      private_subnet_cidrs = data.terraform_remote_state.aws_cell[id].outputs.private_subnet_cidrs
      nlb_dns_name         = data.terraform_remote_state.aws_cell[id].outputs.nlb_dns_name
      nlb_zone_id          = data.terraform_remote_state.aws_cell[id].outputs.nlb_zone_id
      health_check_id      = data.terraform_remote_state.aws_cell[id].outputs.route53_health_check_id
    }
  }
  gcp = {
    for id, c in local.gcp_cells : id => {
      id                = id
      region            = c.region
      coordinates       = c.coordinates
      lb_address        = data.terraform_remote_state.gcp_cell[id].outputs.lb_address
      intercell_address = data.terraform_remote_state.gcp_cell[id].outputs.intercell_address
      service_account   = data.terraform_remote_state.gcp_cell[id].outputs.node_service_account
      network           = data.terraform_remote_state.gcp_cell[id].outputs.network
    }
  }
}
