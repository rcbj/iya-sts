# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A PRIVATE ZONE PER PUBLIC NAME, SO A NODE CAN REACH ITS OWN NAME (#311).
#
# Inside an environment's VPC the public name (test-idp.iyasec.io) resolves,
# through the public zone, to the load balancer's PUBLIC addresses; a node that
# dials it leaves through the internet gateway with its own public address,
# which the load balancer's security group does not admit (it admits
# `allowed_cidrs` only). So the service could not call itself by its public
# name — a Shared Signals receiver reading this service's configuration
# document, an OpenID Provider Command to its own mock relying party, a
# verification event pushed to its own receivers — and the in-AWS suite lost
# those jobs to timeouts. A private zone of the same name, associated with the
# environment's VPC, answers the load balancer's PRIVATE addresses instead
# (environment/dns.tf), and the node reaches it from inside.
#
# **IT IS HERE, NOT IN `environment/`, FOR ONE REASON: DELETING A ZONE.**
# A private zone's id is not predictable, and Route53 scopes nothing by tag,
# so a deployer that could create and delete zones could delete any of the
# account's public zones. Created here once, by an administrator, the
# environment needs only to ASSOCIATE its VPC with this one zone and write
# its A record — both scoped to this zone's ARN in the deployer policy.
#
# A private zone must name a VPC when it is created, hence the anchor: an
# empty VPC that exists only to hold the zone. The environments' own
# associations are made by `environment/` and ignored here.
# ---------------------------------------------------------------------------
locals {
  inside_names = [
    for n in distinct(flatten(values(var.public_dns))) : n
    if !startswith(n, "*")
  ]
}

resource "aws_vpc" "dns_anchor" {
  cidr_block           = "10.255.255.0/28"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-dns-anchor" }
}

resource "aws_route53_zone" "inside" {
  for_each = toset(local.inside_names)
  name     = each.key
  comment  = "${var.name}: the public name answered inside an environment's VPC"

  vpc {
    vpc_id = aws_vpc.dns_anchor.id
  }

  # environment/ associates its own VPC with this zone; without this, the
  # next foundation apply would remove that association.
  lifecycle {
    ignore_changes = [vpc]
  }
}
