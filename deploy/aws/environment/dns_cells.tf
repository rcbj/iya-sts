# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE PUBLIC NAME OF A MULTI-CELL ENVIRONMENT: A ROUTE 53 RECORD TREE
# (#98, D7, 2026-09-28; pinned to JURISDICTIONS since #367, 2026-09-30).
#
#   <name>                   GEOLOCATION  each pinned country → the latency
#                                         set of ITS JURISDICTION's cells
#                                         (globalidp: DE, FR, ... → eu;
#                                          SG → sg; MY → my)
#                                         default (*) → cells.<name>
#   <jurisdiction>.cells.<name>  LATENCY  one record per cell of that
#                                         jurisdiction → its load balancer
#   cells.<name>             LATENCY      one record per cell → its load
#                                         balancer
#   each latency record behind the cell's health check
#
# WHY A COUNTRY IS PINNED TO A JURISDICTION AND NOT TO A CELL. The law that
# asks for the pin names a place, not a data centre: a German client must be
# served in the EU, and globalidp has two EU cells (euc1, euw1). Pinned to
# one of them, Germany would be sent to Frankfurt from anywhere and never
# fail over to Ireland; pinned to the jurisdiction's own latency set it goes
# to whichever EU cell is nearer and healthy — and to NO cell outside the
# EU, whatever their health (below). A jurisdiction with one cell (sg, my,
# testidpna's ca) has a set of one, which answers exactly as the old
# per-cell pin did. The pins are `jurisdictions`, beside `cells` in the
# cells file.
#
# Every cell writes its own two latency records, and the pinned countries of
# a jurisdiction are written by ONE of its cells — the first by id — so no
# cell reads another's state for DNS and no record is written twice; the
# PRIMARY cell writes the default. A single-cell environment keeps the one
# CNAME in dns.tf, exactly as it was.
#
# A PINNED COUNTRY IS ANSWERED WHATEVER ITS CELLS' HEALTH, AND THAT IS THE
# POINT. Its geolocation record does not evaluate its target's health: if it
# did, a jurisdiction whose every cell was down would make the record
# unhealthy, and Route 53 would fall back to the default — the latency set of
# every cell — which would send an EU client to the United States. Inside the
# jurisdiction's set the health checks DO count, so one EU cell fails over to
# the other; and when every record of a set is unhealthy Route 53 answers
# with all of them rather than none, so the client still lands in the
# jurisdiction. The law that requires the pin does not lapse when the cells
# do (fail closed, D6); the SERVICE, not DNS, is authoritative on residency
# anyway (issue #98, section 6), and a client that lands in the wrong cell is
# relayed or refused there.
#
# THE LATENCY RECORDS DO HAVE ONE, which is how the sets fail over: an
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

  # THIS CELL'S JURISDICTION'S LATENCY SET (#367), and whether this cell is
  # the one that writes the jurisdiction's pinned countries: the first of
  # its cells by id, a choice every cell can make from the cells file alone.
  jurisdiction      = local.multi ? local.this_cell.jurisdiction : ""
  jurisdiction_name = "${local.jurisdiction}.cells.${var.public_hostname}"
  jurisdiction_cells = local.multi ? sort([
    for id, c in var.cells : id if c.jurisdiction == local.jurisdiction
  ]) : []
  writes_pins = local.cells_dns && try(local.jurisdiction_cells[0], "") == var.cell
  pinned_places = local.writes_pins ? toset(
    try(var.jurisdictions[local.jurisdiction].geolocation_countries, [])
  ) : toset([])

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

# THIS CELL IN ITS JURISDICTION'S SET (#367): what a pinned country's
# record aliases. The same load balancer and the same health check as the
# record above; only the set differs. Not in a multi-cloud environment (#97),
# whose jurisdiction sets deploy/multicloud/interconnect writes over both
# clouds' cells.
resource "aws_route53_record" "jurisdiction_latency" {
  count          = local.cells_dns && !local.multi_cloud ? 1 : 0
  zone_id        = data.aws_route53_zone.public[0].zone_id
  name           = local.jurisdiction_name
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
  set_identifier = "${local.jurisdiction}-${each.value}"

  geolocation_routing_policy {
    country = each.value
  }

  # To the jurisdiction's set, NEVER evaluating its health (the header: an
  # unhealthy pin would fall through to the default, out of the jurisdiction).
  alias {
    name                   = local.jurisdiction_name
    zone_id                = data.aws_route53_zone.public[0].zone_id
    evaluate_target_health = false
  }

  # Route 53 refuses an alias to a name with no record yet; this cell's own
  # record in the set is the one it can be sure of.
  depends_on = [aws_route53_record.jurisdiction_latency]
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
