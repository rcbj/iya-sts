# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE PUBLIC NAME OVER SIX CELLS IN TWO CLOUDS: ROUTE 53 (#97).
#
# THE STANDARD PATTERN FOR THIS IS DNS-LEVEL GLOBAL TRAFFIC MANAGEMENT by the
# authoritative DNS, and AWS keeps iyasec.io, so Route 53 answers for both
# clouds. Two of its routing policies take a non-AWS endpoint — GEOLOCATION
# (by the client's country) and GEOPROXIMITY, which places an endpoint by
# latitude and longitude where it is not in an AWS region, with no Traffic
# Flow policy needed. Latency routing, which #98's AWS-only tree uses, knows
# only AWS regions and cannot. So the tree is:
#
#   test-idp.iyasec.io        GEOLOCATION
#     each pinned country  →  <jurisdiction>.cells.test-idp.iyasec.io
#     default (*)          →  cells.test-idp.iyasec.io
#   <j>.cells.test-idp…       GEOPROXIMITY over the jurisdiction's TWO cells,
#                             one per cloud, each with a health check
#   cells.test-idp…           GEOPROXIMITY over all six, each with its check
#
# A PINNED COUNTRY NOW FAILS OVER — ACROSS CLOUDS, AND ONLY INSIDE ITS
# JURISDICTION. #98's pin had no health check at all, because the only other
# answer was the default, which leaves the jurisdiction. Here a pin answers
# the jurisdiction's own set: if its AWS cell is down, its GCP cell answers,
# and if both are, Route 53 answers both (a set with nothing healthy answers
# as if everything were) — never a cell elsewhere. The geolocation record
# itself does not evaluate its target, so it can never fall through to the
# default (issue #98, D6: fail closed).
#
# THE GCP CELLS ARE CHECKED BY ADDRESS: an HTTPS GET of /healthcheck on 443
# of the cell's load balancer, from the AWS cells' three checker regions.
# Their ranges are let in on 443 only, to the GCP load balancers only.
#
# EACH CELL'S OWN CONSOLE NAME (#361): the AWS cells write theirs
# (dns_cells.tf); the GCP cells' are here.
#
# THE GCP CELLS' CERTIFICATES are issued by ACME for the SAME public name, and
# a DNS-01 challenge for a Route 53 name would need AWS credentials on a GCP
# node. It does not: `_acme-challenge.<name>` is a CNAME here into the Cloud
# DNS zone, and the ACME client follows it (ACME challenge delegation,
# RFC 8555 section 8.4's record placed by alias). The AWS cells' ACM
# validation uses `_<hash>.<name>` and is untouched.
# ---------------------------------------------------------------------------
data "aws_route53_zone" "public" {
  name         = var.public_zone_name
  private_zone = false
}

locals {
  cells_name = "cells.${var.public_hostname}"

  # The countries pinned to each jurisdiction (#367's `jurisdictions`).
  pinned = {
    for j in local.jurisdictions : j => try(var.jurisdictions[j].geolocation_countries, [])
  }
  pinned_jurisdictions = { for j, countries in local.pinned : j => countries if length(countries) > 0 }
  pinned_places = merge([
    for j, countries in local.pinned_jurisdictions : { for c in countries : c => j }
  ]...)

  # Every set a cell is in: the whole set, and its jurisdiction's if pinned.
  memberships = merge(
    { for id, c in var.cells : "all-${id}" => { set = local.cells_name, cell = id } },
    { for id, c in var.cells : "${c.jurisdiction}-${id}" => {
      set  = "${c.jurisdiction}.${local.cells_name}"
      cell = id
    } if contains(keys(local.pinned_jurisdictions), c.jurisdiction) },
  )

  # A name's challenge label under the Cloud DNS zone:
  # `_acme-challenge.gusw1.test-idp.iyasec.io` → `_acme-challenge.gusw1.test-idp.gcp.iyasec.io`.
  acme_names = concat(
    [var.public_hostname],
    [for id in keys(local.gcp) : "${id}.${var.public_hostname}"],
  )
}

# ---- The GCP cells' health checks, and the firewall that lets them in -----
resource "aws_route53_health_check" "gcp" {
  for_each          = local.gcp
  type              = "HTTPS"
  ip_address        = each.value.lb_address
  fqdn              = var.public_hostname
  port              = 443
  resource_path     = "/healthcheck"
  request_interval  = 30
  failure_threshold = 3
  regions           = var.health_check_regions
  tags              = { Name = "${var.name}-${var.environment}-${each.key}-https" }
}

data "aws_ip_ranges" "route53_health_checkers" {
  services = ["route53_healthchecks"]
  regions  = var.health_check_regions
}

resource "google_compute_firewall" "route53_health_checkers" {
  name        = "${var.name}-${var.environment}-route53-checks"
  network     = data.google_compute_network.shared.id
  description = "Route 53's health checkers, on 443, to the GCP cells' public load balancers (#97)"
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = data.aws_ip_ranges.route53_health_checkers.cidr_blocks
  destination_ranges      = [for c in values(local.gcp) : "${c.lb_address}/32"]
  target_service_accounts = [for c in values(local.gcp) : c.service_account]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# ---- The geoproximity sets ------------------------------------------------
resource "aws_route53_record" "set_aws" {
  for_each       = { for k, m in local.memberships : k => m if var.cells[m.cell].cloud == "aws" }
  zone_id        = data.aws_route53_zone.public.zone_id
  name           = each.value.set
  type           = "A"
  set_identifier = each.value.cell

  geoproximity_routing_policy {
    aws_region = var.cells[each.value.cell].region
  }

  alias {
    name                   = local.aws[each.value.cell].nlb_dns_name
    zone_id                = local.aws[each.value.cell].nlb_zone_id
    evaluate_target_health = true
  }

  health_check_id = local.aws[each.value.cell].health_check_id
}

resource "aws_route53_record" "set_gcp" {
  for_each       = { for k, m in local.memberships : k => m if var.cells[m.cell].cloud == "gcp" }
  zone_id        = data.aws_route53_zone.public.zone_id
  name           = each.value.set
  type           = "A"
  ttl            = 60
  set_identifier = each.value.cell
  records        = [local.gcp[each.value.cell].lb_address]

  geoproximity_routing_policy {
    coordinates {
      latitude  = local.gcp[each.value.cell].coordinates.latitude
      longitude = local.gcp[each.value.cell].coordinates.longitude
    }
  }

  health_check_id = aws_route53_health_check.gcp[each.value.cell].id
}

# ---- The public name ------------------------------------------------------
resource "aws_route53_record" "pinned" {
  for_each       = local.pinned_places
  zone_id        = data.aws_route53_zone.public.zone_id
  name           = var.public_hostname
  type           = "A"
  set_identifier = "pin-${each.key}"

  geolocation_routing_policy {
    country = each.key
  }

  alias {
    name                   = "${each.value}.${local.cells_name}"
    zone_id                = data.aws_route53_zone.public.zone_id
    evaluate_target_health = false
  }

  # Route 53 refuses an alias to a name with no record yet.
  depends_on = [aws_route53_record.set_aws, aws_route53_record.set_gcp]
}

resource "aws_route53_record" "default" {
  zone_id        = data.aws_route53_zone.public.zone_id
  name           = var.public_hostname
  type           = "A"
  set_identifier = "default"

  geolocation_routing_policy {
    country = "*"
  }

  alias {
    name                   = local.cells_name
    zone_id                = data.aws_route53_zone.public.zone_id
    evaluate_target_health = true
  }

  depends_on = [aws_route53_record.set_aws, aws_route53_record.set_gcp]
}

# ---- Each GCP cell's console name (#361) ----------------------------------
resource "aws_route53_record" "gcp_console" {
  for_each = local.gcp
  zone_id  = data.aws_route53_zone.public.zone_id
  name     = "${each.key}.${var.public_hostname}"
  type     = "A"
  ttl      = 60
  records  = [each.value.lb_address]
}

# ---- ACME challenge delegation into Cloud DNS -----------------------------
resource "aws_route53_record" "acme_challenge" {
  for_each = toset(local.acme_names)
  zone_id  = data.aws_route53_zone.public.zone_id
  name     = "_acme-challenge.${each.key}"
  type     = "CNAME"
  ttl      = 300
  records  = ["_acme-challenge.${trimsuffix(each.key, ".${var.public_zone_name}")}.${var.gcp_zone_name}"]
}
