# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PUBLIC NAME: TRAFFIC MANAGER OVER THE CELLS (#98's D7 on Azure;
# deploy/aws/environment/dns_cells.tf is the Route 53 tree this mirrors).
#
#   <public name>  CNAME (alias) ─▶  the GEOGRAPHIC parent profile
#     pinned countries of a jurisdiction ─▶ its PERFORMANCE child, over that
#                                           jurisdiction's cells only
#     WORLD (everyone else)             ─▶ the PERFORMANCE child over every
#                                           cell
#
# PINNED TO A JURISDICTION, NOT A CELL (#367): the law that asks for the pin
# names a place, and a jurisdiction with two cells should fail over between
# them. `CA` → the `ca` child (zcnc alone) in testidpna; the EU 27 and IS,
# LI, NO → the `eu` child (zgwc), SG → `sg` (zsea) in globalidp.
#
# **A PINNED COUNTRY NEVER FAILS OVER OUT OF ITS JURISDICTION** — AWS's rule,
# for AWS's reason (the law does not lapse with the cells). Traffic
# Manager's geographic method answers a region ONLY with the endpoint mapped
# to it, healthy or not; so when every cell of a jurisdiction is down its
# pinned clients get that jurisdiction's endpoints anyway, and fail, rather
# than the nearest cell elsewhere. Inside a child the health checks count.
#
# PERFORMANCE, NOT GEOPROXIMITY: Traffic Manager's performance method is
# latency by the region an endpoint is in, which is AWS's latency records
# (testidpna) — the nearest healthy cell.
#
# THE HEALTH CHECK is Traffic Manager's HTTPS GET of /healthcheck on 443 of
# each cell's load balancer, its probers admitted by service tag
# (../environment/nsg.tf). An endpoint is the cell's public ADDRESS, which
# carries a DNS name for this reason (../environment/lb.tf).
#
# A CELL'S OWN NAME, `<cell>.<public name>` (#361), is the cell's own record
# (../environment/dns.tf).
# ---------------------------------------------------------------------------
locals {
  public_name = var.public_hostname != ""
  # The jurisdictions that pin countries, and their cells.
  pinned = {
    for j, v in var.jurisdictions : j => {
      countries = v.geolocation_countries
      cells     = sort([for id, c in var.cells : id if c.jurisdiction == j])
    } if length(v.geolocation_countries) > 0
  }
  # A Traffic Manager profile's relative name is global under
  # trafficmanager.net, hence the suffix.
  tm_suffix = substr(sha1("${local.subscription_id}/${var.name}/${var.environment}"), 0, 6)

  tm_monitor = {
    protocol = "HTTPS"
    port     = 443
    path     = "/healthcheck"
  }

  # A child profile per pinned jurisdiction, and `world` over every cell.
  children = merge(
    { world = sort(keys(var.cells)) },
    { for j, v in local.pinned : j => v.cells },
  )
  child_endpoints = merge([
    for child, cells in local.children : {
      for id in cells : "${child}-${id}" => { child = child, cell = id }
    }
  ]...)
}

resource "azurerm_traffic_manager_profile" "child" {
  for_each               = local.public_name ? local.children : {}
  name                   = "${local.prefix}-${each.key}"
  resource_group_name    = data.azurerm_resource_group.global.name
  traffic_routing_method = "Performance"

  dns_config {
    relative_name = "${var.name}-${var.environment}-${each.key}-${local.tm_suffix}"
    ttl           = 60
  }

  monitor_config {
    protocol                     = local.tm_monitor.protocol
    port                         = local.tm_monitor.port
    path                         = local.tm_monitor.path
    interval_in_seconds          = 30
    timeout_in_seconds           = 10
    tolerated_number_of_failures = 3
    expected_status_code_ranges  = ["200-200"]
  }

  tags = local.tags
}

resource "azurerm_traffic_manager_azure_endpoint" "cell" {
  for_each           = local.public_name ? local.child_endpoints : {}
  name               = each.value.cell
  profile_id         = azurerm_traffic_manager_profile.child[each.value.child].id
  target_resource_id = local.cell[each.value.cell].lb_public_ip_id
  enabled            = true
}

resource "azurerm_traffic_manager_profile" "parent" {
  count                  = local.public_name ? 1 : 0
  name                   = local.prefix
  resource_group_name    = data.azurerm_resource_group.global.name
  traffic_routing_method = "Geographic"

  dns_config {
    relative_name = "${var.name}-${var.environment}-${local.tm_suffix}"
    ttl           = 60
  }

  monitor_config {
    protocol                     = local.tm_monitor.protocol
    port                         = local.tm_monitor.port
    path                         = local.tm_monitor.path
    interval_in_seconds          = 30
    timeout_in_seconds           = 10
    tolerated_number_of_failures = 3
    expected_status_code_ranges  = ["200-200"]
  }

  tags = local.tags
}

resource "azurerm_traffic_manager_nested_endpoint" "child" {
  for_each                = local.public_name ? local.children : {}
  name                    = each.key
  profile_id              = azurerm_traffic_manager_profile.parent[0].id
  target_resource_id      = azurerm_traffic_manager_profile.child[each.key].id
  minimum_child_endpoints = 1
  geo_mappings            = each.key == "world" ? ["WORLD"] : local.pinned[each.key].countries
  enabled                 = true

  depends_on = [azurerm_traffic_manager_azure_endpoint.cell]
}

# The public name, an ALIAS to the parent profile: a CNAME that Azure DNS
# keeps pointed at the profile, so a re-created profile needs no edit here.
data "azurerm_dns_zone" "public" {
  count               = local.public_name ? 1 : 0
  name                = var.dns_zone_name
  resource_group_name = "${var.name}-foundation"
}

resource "azurerm_dns_cname_record" "public" {
  count               = local.public_name ? 1 : 0
  name                = trimsuffix(var.public_hostname, ".${var.dns_zone_name}")
  zone_name           = data.azurerm_dns_zone.public[0].name
  resource_group_name = data.azurerm_dns_zone.public[0].resource_group_name
  ttl                 = 60
  target_resource_id  = azurerm_traffic_manager_profile.parent[0].id
  tags                = local.tags

  lifecycle {
    precondition {
      condition     = endswith(var.public_hostname, ".${var.dns_zone_name}")
      error_message = "public_hostname must be a name inside dns_zone_name."
    }
  }
}

# ---------------------------------------------------------------------------
# EVERY CELL ADMITS EVERY CELL'S OUTBOUND ADDRESS on the published ports:
# the service calls its own public name (../environment/nsg.tf, `self`), and
# Traffic Manager may answer that with another cell. Priority 120, which
# ../environment/nsg.tf leaves free for this rule.
# ---------------------------------------------------------------------------
resource "azurerm_network_security_rule" "cells_self" {
  for_each                    = var.cells
  name                        = "cells-self"
  description                 = "The published ports, from every cell's outbound address (the service calling its own public name)"
  resource_group_name         = local.cell[each.key].resource_group
  network_security_group_name = local.cell[each.key].nodes_nsg_name
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  source_address_prefixes     = sort([for id in keys(var.cells) : "${local.cell[id].outbound_address}/32"])
  destination_address_prefix  = cidrsubnet(each.value.vpc_cidr, 8, 0)
  destination_port_ranges     = local.cell[each.key].container_ports
}
