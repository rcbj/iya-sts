# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE INTER-CELL CHANNEL: 8446 ON EVERY NODE, REACHED FROM THE OTHER CELLS
# ONLY, BY A PRIVATE NAME (#98, 2026-09-28).
#
# Issue #98, section 4: cells talk to each other over mutual TLS — a
# traveller's credential relayed to the home cell, subject state, revocation
# fan-out — on a listener of its own, with certificates from the service's own
# `cell` Issuing CA. There is nothing for Terraform to issue. What it owes is
# a way for one cell's nodes to reach another's, and a guarantee that nothing
# else can: 8446 is NEVER on the public load balancer and NEVER in public DNS.
#
# THE NODES ARE DIALLED DIRECTLY, BY A NAME ECS KEEPS CURRENT — NOT THROUGH AN
# INTERNAL LOAD BALANCER. That was the first choice, and ECS rules it out: a
# service may have FIVE target groups, and every cell uses all five on the
# public load balancer already (https, ldap, ldaps, pki, kerberos —
# locals.tf's `published_ports`). A sixth, on an internal NLB, cannot be
# attached; registering the nodes in it by address, as spiffe-realm/ does for
# SPIFFE, goes stale at every task restart — and a stale inter-cell target is
# a traveller who cannot sign in (D6 fails closed). So each node service
# registers its tasks in AWS Cloud Map instead (`service_registries`, which
# is not a target group and has no such limit): a PRIVATE DNS namespace per
# cell, `<cell>.<environment>.mock-sts.internal`, whose `nodes` name holds an A
# record per healthy task, added and removed by ECS as tasks start and stop.
# That is "the target IPs", kept current by the scheduler rather than by a
# re-apply.
#
# THE NAME RESOLVES ONLY INSIDE THE CELLS. The namespace is a Route 53
# PRIVATE hosted zone, associated with this cell's VPC here and with every
# other cell's VPC by the global/ stack (which is applied after every cell
# exists); it is in no public zone. The name is deterministic, so a cell is
# told its peers' (`STS_CELL_PEERS`, cells.tf) without reading their state.
#
# THE PORT IS OPEN TO THE OTHER CELLS' CIDRs ONLY, on the nodes' own group —
# not to the load balancer's, not to this cell's own VPC, not to the world.
# The traffic crosses the inter-region peering (global/), and the nodes'
# public addresses are never used for it.
#
# What it costs: a private hosted zone per cell ($0.50 a month) and Cloud Map
# queries, which are free within the VPC resolver's DNS; against an NLB's
# $0.0225 an hour and its LCUs per cell. What it gives up: a single stable
# address — a peer is several A records, and the service must try each (the
# same thing an HTTPS client does with any multi-address name).
# ---------------------------------------------------------------------------
resource "aws_service_discovery_private_dns_namespace" "cells" {
  count       = local.multi ? 1 : 0
  name        = local.intercell_zone
  description = "mock-sts ${var.environment} ${var.cell}: the inter-cell name (#98), private to the VPCs of the cells"
  vpc         = aws_vpc.main.id
}

resource "aws_service_discovery_service" "nodes" {
  count = local.multi ? 1 : 0
  name  = "nodes"

  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.cells[0].id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 10
    }
  }

  # ECS reports each task's health from its container health check, so a
  # node that is starting or failing is not answered for.
  health_check_custom_config {}

  # The provider reads an empty health_check_custom_config back as absent,
  # so every plan wanted to REPLACE this service — and once a cell's nodes
  # are registered in it the delete fails (ResourceInUse), stopping the
  # apply (testidpna, 2026-09-30). The block can only be set at creation, so
  # ignoring the phantom diff loses nothing.
  lifecycle {
    ignore_changes = [health_check_custom_config]
  }
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_cells" {
  for_each          = local.multi ? toset(local.peer_cell_cidrs) : toset([])
  security_group_id = aws_security_group.nodes.id
  description       = "The inter-cell listener, from the VPC of another cell over the peering"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.intercell_port
  to_port           = local.intercell_port
}

resource "aws_vpc_security_group_egress_rule" "nodes_to_cells" {
  for_each          = local.multi ? toset(local.peer_cell_cidrs) : toset([])
  security_group_id = aws_security_group.nodes.id
  description       = "The inter-cell listener of another cell, over the peering"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.intercell_port
  to_port           = local.intercell_port
}

# THE GLOBAL DATABASE, from the nodes: the replica in this cell's VPC and the
# writer in the primary cell's, so every cell's CIDR (global_db.tf). The cell
# database keeps its own rule by group (security.tf).
resource "aws_vpc_security_group_egress_rule" "nodes_to_global_database" {
  for_each          = local.multi ? toset(local.all_cell_cidrs) : toset([])
  security_group_id = aws_security_group.nodes.id
  description       = "The global database (#98), in the VPC of a cell"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.db_port
  to_port           = local.db_port
}
