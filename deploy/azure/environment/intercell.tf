# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE INTER-CELL LISTENER, 8446, AT A FIXED PRIVATE ADDRESS (#98 on Azure).
#
# The service's own mutual TLS between cells (issue #98, section 4), on the
# cell Issuing CA's certificates — nothing here to issue — and never on the
# public load balancer or in public DNS.
#
# AN INTERNAL STANDARD LOAD BALANCER, GCP's choice (#97) and not AWS's Cloud
# Map: AWS could not put an internal NLB in front (ECS allows five target
# groups per service), and Azure has no such limit. A load balancer gives an
# address that does not change when a node is replaced — .5 of the cell's
# private subnet, a formula of its CIDR (cells.tf, `cell_private`) — so the
# other cells know it without reading this state, and it is reached across
# the global VNet peering (the global/ stack) from any region.
#
# NO DNS AT ALL: each peer's name, `nodes.<cell>.<env>.iya-sts.internal`,
# is mapped to that address inside the node's container (`--add-host`,
# nodes.tf), as the database's is. The name exists so the cell leaf the
# service issues can carry it (`STS_CELL_HOSTNAME`), and so a URL in a log
# says which cell it meant.
# ---------------------------------------------------------------------------
resource "azurerm_lb" "intercell" {
  count               = local.multi ? 1 : 0
  name                = "${local.prefix}-intercell"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  sku                 = "Standard"
  tags                = local.tags

  frontend_ip_configuration {
    name                          = "intercell"
    subnet_id                     = azurerm_subnet.private.id
    private_ip_address_allocation = "Static"
    private_ip_address            = local.cell_private[var.cell].intercell_ip
    zones                         = local.zones
  }
}

resource "azurerm_lb_backend_address_pool" "intercell" {
  count           = local.multi ? 1 : 0
  name            = "nodes"
  loadbalancer_id = azurerm_lb.intercell[0].id
}

# A TCP connect: the listener asks every caller for a certificate, and a
# probe has none to give.
resource "azurerm_lb_probe" "intercell" {
  count               = local.multi ? 1 : 0
  name                = "intercell"
  loadbalancer_id     = azurerm_lb.intercell[0].id
  protocol            = "Tcp"
  port                = local.intercell_port
  interval_in_seconds = 10
  number_of_probes    = 3
  probe_threshold     = 2
}

resource "azurerm_lb_rule" "intercell" {
  count                          = local.multi ? 1 : 0
  name                           = "intercell"
  loadbalancer_id                = azurerm_lb.intercell[0].id
  frontend_ip_configuration_name = "intercell"
  protocol                       = "Tcp"
  frontend_port                  = local.intercell_port
  backend_port                   = local.intercell_port
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.intercell[0].id]
  probe_id                       = azurerm_lb_probe.intercell[0].id
  floating_ip_enabled            = false
  tcp_reset_enabled              = true
  idle_timeout_in_minutes        = 15
}
