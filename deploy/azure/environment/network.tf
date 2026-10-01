# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A VNET OF THE ENVIRONMENT'S OWN (deploy/aws/environment/network.tf).
#
#   <prefix>-nodes    10.x.0.0/24   the nodes, with NO public address
#   <prefix>-private  10.x.10.0/24  the database's private endpoint, and in a
#                                    cell the global tier's and the inter-cell
#                                    load balancer (cells.tf's addresses)
#
# An Azure subnet spans the region's zones, so where AWS has three of each
# this has one, as GCP does; the zones are the scale sets' (nodes.tf).
#
# EGRESS THROUGH THE LOAD BALANCER'S OUTBOUND RULE (lb.tf), not a public
# address per node and not a NAT gateway: a VNet made since 2025-09-30 has
# no default outbound access, a NAT gateway is zonal, and the outbound rule
# gives all three zones one fixed source address — which is also what the
# service calling its own public name arrives from (nsg.tf).
#
# The nodes' subnet refuses the default outbound path outright
# (`default_outbound_access_enabled = false`), so a node the outbound rule
# does not cover has no egress rather than an address nobody listed.
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "main" {
  name                = local.prefix
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  address_space       = [local.vpc_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                            = "${local.prefix}-nodes"
  resource_group_name             = data.azurerm_resource_group.unit.name
  virtual_network_name            = azurerm_virtual_network.main.name
  address_prefixes                = [local.nodes_cidr]
  default_outbound_access_enabled = false
}

resource "azurerm_subnet" "private" {
  name                            = "${local.prefix}-private"
  resource_group_name             = data.azurerm_resource_group.unit.name
  virtual_network_name            = azurerm_virtual_network.main.name
  address_prefixes                = [local.private_cidr]
  default_outbound_access_enabled = false
  # A private endpoint obeys the subnet's security group only when the
  # subnet says so; without it the rules below would not apply to the
  # database's endpoint at all.
  private_endpoint_network_policies = "NetworkSecurityGroupEnabled"
}

resource "azurerm_subnet_network_security_group_association" "nodes" {
  subnet_id                 = azurerm_subnet.nodes.id
  network_security_group_id = azurerm_network_security_group.nodes.id
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private.id
}
