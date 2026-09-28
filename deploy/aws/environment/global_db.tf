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
  description = "mock-sts ${var.environment} ${var.cell}: the global database, in this cell's private subnets"
  subnet_ids  = aws_subnet.private[*].id
}

resource "aws_security_group" "global_database" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-global-db"
  description = "mock-sts ${var.environment} ${var.cell}: the global database, reachable from every cell's VPC"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-global-db" }
}

resource "aws_vpc_security_group_ingress_rule" "global_database_from_cells" {
  for_each          = local.multi ? toset(local.all_cell_cidrs) : toset([])
  security_group_id = aws_security_group.global_database[0].id
  description       = "PostgreSQL from a cell's VPC"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.db_port
  to_port           = local.db_port
}
