# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# WHERE THE GLOBAL DATABASE SITS IN THIS CELL (#98, 2026-09-28).
#
# The global tier's PostgreSQL (issue #98, D3) is one writer in the primary
# cell and one cross-region read replica in every other cell, and each lives
# IN its cell's VPC, beside the cell's own database. The instances are the
# global/ stack's; the place they go — a subnet group over this cell's
# private subnets, and a security group — is made HERE, because it is this
# VPC's, and because the cell is applied before global/ exists (cells.tf,
# *The two phases*). global/ finds both through this stack's outputs.
#
# WHO MAY CONNECT: every cell's CIDR, not this cell's nodes' group. The writer
# is written to by EVERY cell's nodes, across the peering, and a security
# group cannot name a group in another region; so each cell's whole VPC is
# admitted, on 5432 only, and a replica admits the same list rather than a
# narrower one it would have to be told apart by. Nothing but nodes runs in
# those VPCs that could use it, and TLS is required on the listener as it is
# on the cell database (global/ sets `rds.force_ssl`).
#
# By CIDR also so that no rule in another state names a group in this one:
# the lesson of spiffe-realm/ (deploy/aws/CLAUDE.md) is that such a rule keeps
# a group alive past its own stack's destroy.
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "global" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-global"
  description = "mock-sts ${var.environment} ${var.cell}: the global database, in the private subnets of this cell"
  subnet_ids  = aws_subnet.private[*].id
}

resource "aws_security_group" "global_database" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-global-db"
  description = "mock-sts ${var.environment} ${var.cell}: the global database, reachable from the VPC of every cell"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-global-db" }
}

resource "aws_vpc_security_group_ingress_rule" "global_database_from_cells" {
  for_each          = local.multi ? toset(local.all_cell_cidrs) : toset([])
  security_group_id = aws_security_group.global_database[0].id
  description       = "PostgreSQL from the VPC of a cell"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.db_port
  to_port           = local.db_port
}

# THE GCP CELLS' COPIES OF THE GLOBAL TIER (#97): each GCP cell's Cloud SQL
# subscribes to this writer's publication over the HA VPN, from the
# private-services range its instance was given — not from the cell's VPC
# CIDR, which the rule above admits for the GCP nodes' own writes.
resource "aws_vpc_security_group_ingress_rule" "global_database_from_gcp_subscribers" {
  for_each          = local.multi ? toset(local.gcp_global_db_cidrs) : toset([])
  security_group_id = aws_security_group.global_database[0].id
  description       = "PostgreSQL logical replication, from a GCP cell's copy of the global tier (#97)"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.db_port
  to_port           = local.db_port
}
