# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE NETWORK SECURITY GROUPS: AWS'S THREE SECURITY GROUPS, ON TWO SUBNETS.
#
#   allowed_cidrs ──443,389,636,80,88,8092,8181──▶ LB ──▶ nodes (8081, …)
#   the LB's own outbound address ──same──▶ nodes      (the service calling
#                                                       its own public name)
#   Azure's load balancer probes ──any──▶ nodes
#   Traffic Manager's probers ──8081──▶ nodes          (a cell with a name)
#   the other cells ──8446──▶ nodes                    (a cell)
#   nodes ──443 / 80 / 53──▶ internet   nodes ──5432──▶ the private subnets
#
# THE LOAD BALANCER IS A PASS-THROUGH, as GCP's is: a client's packet
# arrives at the node with the CLIENT's address as its source and the NODE's
# as its destination, the port translated to the container's. So the rule
# AWS put on the NLB is on the nodes' subnet here, naming the CONTAINER
# ports — and the nodes have no public address, so an allowed client reaches
# them only through the load balancer.
#
# EVERYTHING ELSE IS DENIED at 4096, in both directions, ahead of Azure's
# default rules (AllowVnetInBound, AllowInternetOutBound at 65000+), which
# would otherwise admit every peered cell on every port and let a node dial
# anything. The platform's own addresses — the instance metadata endpoint
# the nodes' credentials come from, and Azure's DNS at 168.63.129.16 — are
# reachable whatever a rule says.
#
# EGRESS ON 80 is Ubuntu's package mirror, which cloud-init installs Docker
# from (azure.archive.ubuntu.com is http, signed by apt). 53 only with a
# public name, for the ACME client's check that its TXT record reached Azure
# DNS's own name servers.
#
# **EVERY RULE IS A RESOURCE OF ITS OWN, AND THE GROUPS HOLD NONE INLINE**:
# the provider treats a group's inline rules as the WHOLE list, so a rule
# added beside them — the global/ stack's for the other cells' outbound
# addresses — would be deleted by this stack's next apply, and put back by
# the global stack's.
# ---------------------------------------------------------------------------
locals {
  container_ports = sort(distinct([for p in values(local.all_ports) : tostring(p.container)]))

  nodes_rules = merge(
    {
      clients = {
        description = "The published ports, from allowed_cidrs, through the load balancer"
        priority    = 100, direction = "Inbound", protocol = "Tcp"
        sources     = var.allowed_cidrs, source_tag = null
        dests       = [local.nodes_cidr], ports = local.container_ports
      }
      # THE SERVICE CALLING ITS OWN PUBLIC NAME (AWS #311: the console and
      # the portal are OIDC clients of the service's own token endpoint). The
      # node's packet leaves by the outbound rule and comes back through the
      # public frontend with the OUTBOUND address as its source. AWS needed a
      # private zone for this; GCP, nothing. In a cell the name may be
      # another cell's, and the global/ stack admits every cell's outbound
      # address (priority 120) in each.
      self = {
        description = "The published ports, from this environment's own outbound address"
        priority    = 110, direction = "Inbound", protocol = "Tcp"
        sources     = ["${azurerm_public_ip.outbound.ip_address}/32"], source_tag = null
        dests       = [local.nodes_cidr], ports = local.container_ports
      }
      load-balancer-probes = {
        description = "Azure's load balancer health probes"
        priority    = 150, direction = "Inbound", protocol = "*"
        sources     = [], source_tag = "AzureLoadBalancer"
        dests       = [local.nodes_cidr], ports = ["*"]
      }
      https-out = {
        description = "The registry, Key Vault, Entra ID, Azure Monitor and the ACME server"
        priority    = 100, direction = "Outbound", protocol = "Tcp"
        sources     = [local.nodes_cidr], source_tag = null
        dests       = ["Internet"], ports = ["443"]
      }
      apt-out = {
        description = "Ubuntu's package mirror (cloud-init installs Docker from it)"
        priority    = 110, direction = "Outbound", protocol = "Tcp"
        sources     = [local.nodes_cidr], source_tag = null
        dests       = ["Internet"], ports = ["80"]
      }
      database-out = {
        description = "PostgreSQL: the cell database's endpoint, and in a cell the global tier's in every cell"
        priority    = 130, direction = "Outbound", protocol = "Tcp"
        sources     = [local.nodes_cidr], source_tag = null
        dests = local.multi ? [
          for id in sort(keys(var.cells)) : local.cell_private[id].private_cidr
        ] : [local.private_cidr]
        ports = [tostring(local.db_port)]
      }
    },
    local.public_name ? {
      dns-out = {
        description = "The ACME client's check of Azure DNS's own name servers"
        priority    = 120, direction = "Outbound", protocol = "*"
        sources     = [local.nodes_cidr], source_tag = null
        dests       = ["Internet"], ports = ["53"]
      }
    } : {},
    # Traffic Manager's HTTPS probe of /healthcheck, through the load
    # balancer (../global/routing.tf) — a service tag rather than AWS's list
    # of checker ranges, so it stays current by itself.
    local.multi && local.public_name ? {
      traffic-manager = {
        description = "Traffic Manager's health probes of /healthcheck"
        priority    = 130, direction = "Inbound", protocol = "Tcp"
        sources     = [], source_tag = "AzureTrafficManager"
        dests       = [local.nodes_cidr], ports = [tostring(local.published_ports.https.container)]
      }
    } : {},
    # THE INTER-CELL LISTENER (intercell.tf): from the other cells' VNets,
    # over the peering, and to their load balancers.
    local.multi ? {
      intercell-in = {
        description = "The inter-cell listener, from the VNet of another cell (#98)"
        priority    = 140, direction = "Inbound", protocol = "Tcp"
        sources     = local.peer_cidrs, source_tag = null
        dests       = [local.nodes_cidr], ports = [tostring(local.intercell_port)]
      }
      intercell-out = {
        description = "The inter-cell listener of another cell, over the peering (#98)"
        priority    = 140, direction = "Outbound", protocol = "Tcp"
        sources     = [local.nodes_cidr], source_tag = null
        dests       = [for id in sort(keys(local.peers)) : "${local.cell_private[id].intercell_ip}/32"]
        ports       = [tostring(local.intercell_port)]
      }
    } : {},
    {
      deny-inbound = {
        description = "Everything not admitted above"
        priority    = 4096, direction = "Inbound", protocol = "*"
        sources     = [], source_tag = "*"
        dests       = ["*"], ports = ["*"]
      }
      deny-outbound = {
        description = "Everything not admitted above"
        priority    = 4096, direction = "Outbound", protocol = "*"
        sources     = [], source_tag = "*"
        dests       = ["*"], ports = ["*"]
      }
    },
  )

  # THE PRIVATE SUBNET: PostgreSQL from the nodes — in a cell from every
  # cell's nodes, because the global tier's endpoint here is dialled by
  # every cell (the writer) or by this one (a replica), and the rule does not
  # tell them apart.
  private_rules = {
    database-in = {
      description = "PostgreSQL, from the nodes"
      priority    = 100, direction = "Inbound", protocol = "Tcp"
      sources = local.multi ? [
        for id in sort(keys(var.cells)) : cidrsubnet(var.cells[id].vpc_cidr, 8, 0)
      ] : [local.nodes_cidr]
      source_tag = null
      dests      = [local.private_cidr], ports = [tostring(local.db_port)]
    }
    deny-inbound = {
      description = "Everything not admitted above"
      priority    = 4096, direction = "Inbound", protocol = "*"
      sources     = [], source_tag = "*"
      dests       = ["*"], ports = ["*"]
    }
  }
}

resource "azurerm_network_security_group" "nodes" {
  name                = "${local.prefix}-nodes"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  tags                = local.tags
}

resource "azurerm_network_security_group" "private" {
  name                = "${local.prefix}-private"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  tags                = local.tags
}

# One resource, both groups: a single-address field and a list field each
# take their value only where the other is empty (the API refuses both).
resource "azurerm_network_security_rule" "rules" {
  for_each = merge(
    { for k, r in local.nodes_rules : "nodes-${k}" => merge(r, { nsg = azurerm_network_security_group.nodes.name, rule = k }) },
    { for k, r in local.private_rules : "private-${k}" => merge(r, { nsg = azurerm_network_security_group.private.name, rule = k }) },
  )

  name                        = each.value.rule
  description                 = each.value.description
  resource_group_name         = data.azurerm_resource_group.unit.name
  network_security_group_name = each.value.nsg
  priority                    = each.value.priority
  direction                   = each.value.direction
  access                      = startswith(each.value.rule, "deny-") ? "Deny" : "Allow"
  protocol                    = each.value.protocol
  source_port_range           = "*"

  source_address_prefix   = each.value.source_tag
  source_address_prefixes = each.value.source_tag == null ? each.value.sources : null

  destination_address_prefix   = length(each.value.dests) == 1 ? each.value.dests[0] : null
  destination_address_prefixes = length(each.value.dests) > 1 ? each.value.dests : null

  destination_port_range  = length(each.value.ports) == 1 ? each.value.ports[0] : null
  destination_port_ranges = length(each.value.ports) > 1 ? each.value.ports : null
}
