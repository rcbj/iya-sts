# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# ONE INTER-REGION VPC PEERING BETWEEN TWO CELLS, AND ITS ROUTES (issue #98).
# ../../peering.tf argues the mesh; this is one edge of it.
#
# REQUESTED from the first cell's region and ACCEPTED in the second's — two
# regions, each resource naming its own (AWS provider 6's per-resource
# `region`, #367; it was a provider per side until then), because a
# cross-region peering cannot be auto-accepted by the side that asks for it. Each side then routes the other's CIDR over it, from
# both of its route tables: the public one the nodes use, and the private one
# the databases use (so the global writer's replies find their way back).
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "pair" {
  description = "The two cells: id, region, vpc_id, vpc_cidr and route_table_ids (public, private) of each."
  type        = any
}

variable "common" {
  description = "The global stack's name prefix and the account id."
  type = object({
    prefix     = string
    account_id = string
  })
}

locals {
  name = "${var.common.prefix}-${var.pair.requester.id}-${var.pair.accepter.id}"
}

resource "aws_vpc_peering_connection" "this" {
  region = var.pair.requester.region

  vpc_id        = var.pair.requester.vpc_id
  peer_vpc_id   = var.pair.accepter.vpc_id
  peer_region   = var.pair.accepter.region
  peer_owner_id = var.common.account_id
  auto_accept   = false

  tags = { Name = local.name, Side = "requester" }
}

resource "aws_vpc_peering_connection_accepter" "this" {
  region = var.pair.accepter.region

  vpc_peering_connection_id = aws_vpc_peering_connection.this.id
  auto_accept               = true

  tags = { Name = local.name, Side = "accepter" }
}

resource "aws_route" "requester" {
  region   = var.pair.requester.region
  for_each = var.pair.requester.route_table_ids

  route_table_id            = each.value
  destination_cidr_block    = var.pair.accepter.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.this.id

  # A route over a peering that is not yet active is refused.
  depends_on = [aws_vpc_peering_connection_accepter.this]
}

resource "aws_route" "accepter" {
  region   = var.pair.accepter.region
  for_each = var.pair.accepter.route_table_ids

  route_table_id            = each.value
  destination_cidr_block    = var.pair.requester.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.this.id
}

output "peering_connection_id" {
  description = "The peering's id."
  value       = aws_vpc_peering_connection.this.id
}
