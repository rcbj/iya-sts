# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE PUBLIC NAME OF A MULTI-CELL ENVIRONMENT: A ROUTE 53 RECORD TREE
# (#98, D7, 2026-09-28).
#
#   test-idp.iyasec.io   GEOLOCATION  country CA  → cac1's load balancer
#                                     (later: each EU/EEA country → euc1,
#                                      SG → apse1)
#                                     default (*)  → cells.test-idp.iyasec.io
#   cells.test-idp.iyasec.io  LATENCY  one record per cell → that cell's load
#                                      balancer, each behind a health check
#
# Every cell writes its own records — the ones for the countries pinned to
# it, and its latency record — and the PRIMARY cell writes the default, so no
# cell reads another's state for DNS. A single-cell environment keeps the one
# CNAME in dns.tf, exactly as it was.
#
# A PINNED COUNTRY HAS NO HEALTH CHECK, AND THAT IS THE POINT. Route 53 answers
# an unhealthy geolocation record by falling back to the default — which is
# the latency set, which would send a Canadian client to the United States
# the moment cac1 was down. The law that requires the pin does not lapse when
# the cell does, so the pin is answered whatever the cell's health (fail
# closed, D6); the SERVICE, not DNS, is authoritative on residency anyway
# (issue #98, section 6), and a client that lands in the wrong cell is relayed
# or refused there.
#
# THE LATENCY RECORDS DO HAVE ONE, which is how the default fails over: an
# HTTPS GET of /healthcheck on 443 of each cell's load balancer. The load
# balancer admits `allowed_cidrs` only, so the Route 53 health checkers'
# published ranges are admitted too — ON 443 ONLY, the one port the check
# uses, and only in a cell with a public name — and the checkers are held to
# three regions (`health_check_regions`, the minimum Route 53 allows) so that
# their ranges stay a handful of rules rather than every checker AWS runs.
# The check does not verify the certificate (Route 53 never does); it asks
# whether a node answers, which is what the load balancer's own check asks
# too.
#
# One more thing every cell shares: the ACM validation record. Every cell
# requests a certificate for the same name (dns.tf), and ACM validates a name
# with the same CNAME in every region of an account, so each cell writes that
# record with `allow_overwrite` and the last destroy removes it. The cells of
# an environment are applied and destroyed together (entrypoint.sh); a cell
# destroyed on its own takes the record with it, and the others' next renewal
# would need it written again by an apply.
# ---------------------------------------------------------------------------
locals {
  cells_dns    = local.multi && local.public_name
  latency_name = "cells.${var.public_hostname}"
  # EACH CELL'S OWN CONSOLE NAME (#361, rcbj 2026-09-30): `<cell>.<public
  # name>`, aimed at this cell's load balancer alone and on this cell's
  # certificate, so an administrator can open a given region's console from
  # Server configuration → Cells. Deterministic, like the inter-cell names,
  # so no cell reads another's state to know its peers'.
  cell_console_host = local.cells_dns ? "${var.cell}.${var.public_hostname}" : ""
  pinned_places     = local.cells_dns ? toset(local.this_cell.geolocation_countries) : toset([])

  # Three is Route 53's minimum. Chosen for spread (two continents) and kept
  # this short because each region's checker ranges are security-group rules
  # on the load balancer.
  health_check_regions = ["us-east-1", "us-west-1", "eu-west-1"]
}

data "aws_ip_ranges" "route53_health_checkers" {
  count    = local.cells_dns ? 1 : 0
  services = ["route53_healthchecks"]
  regions  = local.health_check_regions
}

resource "aws_vpc_security_group_ingress_rule" "nlb_health_checkers" {
  for_each          = local.cells_dns ? toset(data.aws_ip_ranges.route53_health_checkers[0].cidr_blocks) : toset([])
  security_group_id = aws_security_group.nlb.id
  description       = "Route 53 health checker, 443 only (#98, dns_cells.tf)"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.published_ports.https.listener
  to_port           = local.published_ports.https.listener
}

resource "aws_route53_health_check" "cell" {
  count             = local.cells_dns ? 1 : 0
  type              = "HTTPS"
  fqdn              = aws_lb.main.dns_name
  port              = local.published_ports.https.listener
  resource_path     = "/healthcheck"
  request_interval  = 30
  failure_threshold = 3
  regions           = local.health_check_regions
  tags              = { Name = "${local.prefix}-https" }
}

# IN A MULTI-CLOUD ENVIRONMENT (#97) THE TREE IS NOT THE CELLS' TO WRITE:
# deploy/multicloud/interconnect writes it, over every cell of both clouds,
# with geoproximity where this file has latency (Route 53's latency routing
# knows only AWS regions). Each AWS cell still makes its health check, which
# that stack reads, and its own console name.
resource "aws_route53_record" "latency" {
  count          = local.cells_dns && !local.multi_cloud ? 1 : 0
  zone_id        = data.aws_route53_zone.public[0].zone_id
  name           = local.latency_name
  type           = "A"
  set_identifier = var.cell

  latency_routing_policy {
    region = local.region
  }

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }

  health_check_id = aws_route53_health_check.cell[0].id
}

resource "aws_route53_record" "pinned" {
  for_each       = local.multi_cloud ? toset([]) : local.pinned_places
  zone_id        = data.aws_route53_zone.public[0].zone_id
  name           = var.public_hostname
  type           = "A"
  set_identifier = "${var.cell}-${each.value}"

  geolocation_routing_policy {
    country = each.value
  }

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "default" {
  count          = local.cells_dns && local.is_primary && !local.multi_cloud ? 1 : 0
  zone_id        = data.aws_route53_zone.public[0].zone_id
  name           = var.public_hostname
  type           = "A"
  set_identifier = "default"

  geolocation_routing_policy {
    country = "*"
  }

  alias {
    name                   = local.latency_name
    zone_id                = data.aws_route53_zone.public[0].zone_id
    evaluate_target_health = true
  }

  # AFTER this cell's latency record (#311): Route 53 refuses an alias to a
  # name that has no record yet ("that target was not found"), and the first
  # testidpna apply created this one first.
  depends_on = [aws_route53_record.latency]
}

# THIS CELL'S OWN CONSOLE NAME (#361): one record, this cell's load
# balancer and no other — never the latency or geolocation tree, which is
# what sends the shared name to whichever cell is nearest.
resource "aws_route53_record" "cell_console" {
  count   = local.cell_console_host != "" ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = local.cell_console_host
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = false
  }
}
