# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PEP ENVIRONMENT'S OWN NETWORK: a VNet peered with nothing, two subnets.
#
#   gateway   Application Gateway WAF_v2, alone, as it must be: a v2 gateway
#             takes a subnet of its own
#   members   the member VMs: no public address, default outbound access OFF
#             (new VNets have none anyway since 2025-09-30), out through ONE
#             NAT gateway — the environment's single egress address
#             (`egress_ip`), the one the identity service admits
#
# ONE NAT GATEWAY, REGIONAL (no zone). AWS's argument: one address to admit
# and one hourly charge; a member that loses its pulls keeps enforcing what
# it last pulled. A zonal NAT gateway per zone would be one address per zone.
#
# THE SECURITY GROUPS DENY EVERYTHING AT 4096, ahead of Azure's defaults
# (deploy/azure/environment/nsg.tf's reason: the defaults admit the whole
# VNet), and every rule is a resource of its own.
# ---------------------------------------------------------------------------

locals {
  gateway_cidr = cidrsubnet(var.vnet_cidr, 8, 0)
  members_cidr = cidrsubnet(var.vnet_cidr, 8, 10)
}

resource "azurerm_virtual_network" "main" {
  name                = "${local.prefix}-vnet"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "gateway" {
  name                 = "gateway"
  resource_group_name  = data.azurerm_resource_group.pep.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.gateway_cidr]
}

resource "azurerm_subnet" "members" {
  name                            = "members"
  resource_group_name             = data.azurerm_resource_group.pep.name
  virtual_network_name            = azurerm_virtual_network.main.name
  address_prefixes                = [local.members_cidr]
  default_outbound_access_enabled = false
}

resource "azurerm_public_ip" "nat" {
  name                = "${local.prefix}-nat"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway" "main" {
  name                    = "${local.prefix}-nat"
  location                = var.region
  resource_group_name     = data.azurerm_resource_group.pep.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  tags                    = local.tags
}

resource "azurerm_nat_gateway_public_ip_association" "main" {
  nat_gateway_id       = azurerm_nat_gateway.main.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "members" {
  subnet_id      = azurerm_subnet.members.id
  nat_gateway_id = azurerm_nat_gateway.main.id
}

# --- Security groups ----------------------------------------------------------

resource "azurerm_network_security_group" "gateway" {
  name                = "${local.prefix}-gateway"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  tags                = local.tags
}

resource "azurerm_network_security_group" "members" {
  name                = "${local.prefix}-members"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  tags                = local.tags
}

locals {
  # The gateway's client ports: 443, 80 (redirected) and the decision API
  # from allowed_cidrs; each notify port from notify_cidrs. The WAF holds the
  # same allowlist (gateway.tf); the group is the floor.
  client_ports = concat([80, 443], var.publish_decision_api ? [var.decision_port] : [])

  gateway_rules = merge(
    {
      # Application Gateway v2's own control plane, which Microsoft requires
      # admitted on the gateway subnet or the gateway will not provision.
      gateway-manager = {
        priority = 100, source = "GatewayManager", port = "65200-65535"
      }
      # Its health probes and the platform's.
      load-balancer = {
        priority = 110, source = "AzureLoadBalancer", port = "*"
      }
    },
    { for i, pair in setproduct(local.client_ports, var.allowed_cidrs) :
      "client-${pair[0]}-${replace(pair[1], "/[./]/", "-")}" => {
        priority = 200 + i, source = pair[1], port = tostring(pair[0])
      }
    },
    { for i, pair in setproduct(values(local.notify_ports), var.notify_cidrs) :
      "notify-${pair[0]}-${replace(pair[1], "/[./]/", "-")}" => {
        priority = 1000 + i, source = pair[1], port = tostring(pair[0])
      }
    },
  )

  member_rules = {
    # The gateway, to the members' two ports — its probes and its forwards.
    gateway = {
      priority = 100, source = local.gateway_cidr, port = "${local.pep_https_port},${local.pep_proxy_port}"
    }
    # The platform: the Application Health extension and the agent.
    load-balancer = {
      priority = 110, source = "AzureLoadBalancer", port = "*"
    }
  }
}

resource "azurerm_network_security_rule" "gateway" {
  for_each                    = local.gateway_rules
  name                        = each.key
  resource_group_name         = data.azurerm_resource_group.pep.name
  network_security_group_name = azurerm_network_security_group.gateway.name
  priority                    = each.value.priority
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = each.value.source
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_ranges     = split(",", each.value.port)
}

resource "azurerm_network_security_rule" "members" {
  for_each                    = local.member_rules
  name                        = each.key
  resource_group_name         = data.azurerm_resource_group.pep.name
  network_security_group_name = azurerm_network_security_group.members.name
  priority                    = each.value.priority
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = each.value.source
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_ranges     = split(",", each.value.port)
}

# EVERYTHING ELSE IN, DENIED — the companion's 9700 among it, which no rule
# names. Outbound is left to Azure's defaults: the members leave through the
# NAT gateway (registry, vault, ACME, the identity service), the gateway to
# its backends and to Key Vault.
resource "azurerm_network_security_rule" "gateway_deny" {
  name                        = "deny-inbound"
  resource_group_name         = data.azurerm_resource_group.pep.name
  network_security_group_name = azurerm_network_security_group.gateway.name
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_address_prefix       = "*"
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_range      = "*"
}

resource "azurerm_network_security_rule" "members_deny" {
  name                        = "deny-inbound"
  resource_group_name         = data.azurerm_resource_group.pep.name
  network_security_group_name = azurerm_network_security_group.members.name
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_address_prefix       = "*"
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_range      = "*"
}

resource "azurerm_subnet_network_security_group_association" "gateway" {
  subnet_id                 = azurerm_subnet.gateway.id
  network_security_group_id = azurerm_network_security_group.gateway.id
}

resource "azurerm_subnet_network_security_group_association" "members" {
  subnet_id                 = azurerm_subnet.members.id
  network_security_group_id = azurerm_network_security_group.members.id
}
