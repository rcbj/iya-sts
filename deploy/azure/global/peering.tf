# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE CELLS' VNETS, A FULL MESH OF GLOBAL PEERINGS (#98's inter-cell channel;
# deploy/aws/global/peering.tf).
#
# What crosses it: the inter-cell listener (8446, through each cell's
# internal load balancer), every cell's writes to the global writer, and a
# replica's cell reaching nothing else. Azure carries the replication
# itself. An Azure peering is two halves, one in each VNet's own resource
# group, and it routes by itself — no route table to write, where AWS
# writes a route per pair in both directions.
#
# NO FORWARDED TRAFFIC AND NO GATEWAY TRANSIT: a cell reaches another cell's
# own addresses and nothing that cell could route onward. What each side
# admits is its security groups' business (../environment/nsg.tf), which
# deny everything they do not name.
# ---------------------------------------------------------------------------
locals {
  # Every ordered pair: one half of a peering each.
  peering_halves = {
    for pair in setproduct(keys(var.cells), keys(var.cells)) :
    "${pair[0]}-to-${pair[1]}" => { from = pair[0], to = pair[1] }
    if pair[0] != pair[1]
  }
}

resource "azurerm_virtual_network_peering" "cells" {
  for_each                     = local.peering_halves
  name                         = "${var.name}-${var.environment}-${each.value.from}-to-${each.value.to}"
  resource_group_name          = local.cell[each.value.from].resource_group
  virtual_network_name         = local.cell[each.value.from].vnet_name
  remote_virtual_network_id    = local.cell[each.value.to].vnet_id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = false
  allow_gateway_transit        = false
  use_remote_gateways          = false
}
