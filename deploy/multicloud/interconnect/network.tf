# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

data "google_compute_network" "shared" {
  name = "${var.name}-${var.environment}"
}

locals {
  # What every pair's Cloud Router advertises beyond the GCP subnets
  # (modules/pair): the global tier copies' private-services ranges, and the
  # range Cloud DNS forwards from.
  advertised_ranges = concat(
    compact([for c in values(local.gcp_cells) : c.global_db_cidr]),
    ["35.199.192.0/19"],
  )

  pair_inputs = {
    for id, c in local.aws : id => {
      prefix = "${var.name}-${var.environment}-${id}"
      aws_cell = {
        id                   = id
        vpc_id               = c.vpc_id
        vpc_cidr             = c.vpc_cidr
        route_table_ids      = c.route_table_ids
        private_subnet_ids   = c.private_subnet_ids
        private_subnet_cidrs = c.private_subnet_cidrs
      }
      gcp_region = var.cells[local.partner[id]].region
    }
  }
}

# ---------------------------------------------------------------------------
# ONE HA VPN PER AWS CELL, TO ITS PARTNER'S REGION. A block per region an AWS
# cell may be in, as deploy/aws/global has, each present only when its cell
# is; `index` numbers the pair's inside addresses and ASNs.
# ---------------------------------------------------------------------------
module "pair_usw2" {
  source    = "./modules/pair"
  count     = contains(keys(local.aws), "usw2") ? 1 : 0
  providers = { aws = aws.usw2 }

  prefix            = local.pair_inputs["usw2"].prefix
  index             = 0
  aws_cell          = local.pair_inputs["usw2"].aws_cell
  gcp_region        = local.pair_inputs["usw2"].gcp_region
  network           = data.google_compute_network.shared.self_link
  advertised_ranges = local.advertised_ranges
}

module "pair_cac1" {
  source    = "./modules/pair"
  count     = contains(keys(local.aws), "cac1") ? 1 : 0
  providers = { aws = aws.cac1 }

  prefix            = local.pair_inputs["cac1"].prefix
  index             = 1
  aws_cell          = local.pair_inputs["cac1"].aws_cell
  gcp_region        = local.pair_inputs["cac1"].gcp_region
  network           = data.google_compute_network.shared.self_link
  advertised_ranges = local.advertised_ranges
}

module "pair_euc1" {
  source    = "./modules/pair"
  count     = contains(keys(local.aws), "euc1") ? 1 : 0
  providers = { aws = aws.euc1 }

  prefix            = local.pair_inputs["euc1"].prefix
  index             = 2
  aws_cell          = local.pair_inputs["euc1"].aws_cell
  gcp_region        = local.pair_inputs["euc1"].gcp_region
  network           = data.google_compute_network.shared.self_link
  advertised_ranges = local.advertised_ranges
}

module "pair_apse1" {
  source    = "./modules/pair"
  count     = contains(keys(local.aws), "apse1") ? 1 : 0
  providers = { aws = aws.apse1 }

  prefix            = local.pair_inputs["apse1"].prefix
  index             = 3
  aws_cell          = local.pair_inputs["apse1"].aws_cell
  gcp_region        = local.pair_inputs["apse1"].gcp_region
  network           = data.google_compute_network.shared.self_link
  advertised_ranges = local.advertised_ranges
}

# ---------------------------------------------------------------------------
# THE GCP CELLS' INTER-CELL NAMES, INSIDE EVERY AWS VPC: a private zone per
# GCP cell, `<cell>.<env>.mock-sts.internal`, associated with each AWS cell's
# VPC, holding the one record the foundation also holds on the GCP side —
# `nodes` at the cell's internal load balancer. The AWS cells' own names are
# their Cloud Map namespaces, which deploy/aws/global associates among the
# AWS VPCs and which the GCP side forwards to (modules/pair, the resolver).
# ---------------------------------------------------------------------------
resource "aws_route53_zone" "gcp_intercell" {
  for_each = local.gcp
  name     = "${each.key}.${var.environment}.${var.name}.internal"
  comment  = "mock-sts ${var.environment}: GCP cell ${each.key}'s inter-cell name, inside the AWS cells (#97)"

  dynamic "vpc" {
    for_each = local.aws
    content {
      vpc_id     = vpc.value.vpc_id
      vpc_region = vpc.value.region
    }
  }
}

resource "aws_route53_record" "gcp_intercell" {
  for_each = local.gcp
  zone_id  = aws_route53_zone.gcp_intercell[each.key].zone_id
  name     = "nodes.${each.key}.${var.environment}.${var.name}.internal"
  type     = "A"
  ttl      = 60
  records  = [each.value.intercell_address]
}
