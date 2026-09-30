# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE PUBLIC FRONT DOOR: A STANDARD LOAD BALANCER (deploy/aws/environment/nlb.tf,
# deploy/gcp/environment/lb.tf).
#
# PASS-THROUGH, NOT PROXY, for AWS's reason: mock-sts terminates its own TLS,
# and a client certificate presented to the main port reaches the service
# only if the TCP stream does. An Azure load balancer is a layer-4
# pass-through — it rewrites the destination to a node and forwards the
# packet — so the node's TLS is the client's, and `GET /tls/sign-in` and RFC
# 8705 mutual TLS work as on AWS and GCP.
#
# **THE CLIENT'S ADDRESS ARRIVES AS THE PEER, AND THERE IS NO PROXY HEADER**
# (GCP's arrangement): the source of the packet is the client, so the nodes
# run `STS_PROXY_PROTOCOL=off` and trust no proxy (nodes.tf).
#
# ONE RULE PER PUBLISHED PORT, each translating the listener to the
# container's port (443 → 8081, 80 → 8082) — which GCP's could not do — and
# so, like GCP and unlike AWS, **the SPIFFE ports need no register-by-address
# workaround**: the backend pool is the scale sets' network interfaces, which
# follow their instances.
#
# ONE HEALTH PROBE for every rule, an HTTPS GET of /healthcheck on the node's
# 8081. As on GCP, a node whose LDAPS failed to bind stays in service; the
# service records that failure on `GET /admin/ldap/service` either way.
#
# THE OUTBOUND RULE IS EVERY NODE'S EGRESS (network.tf): a second public
# address, a frontend with no inbound rule, SNAT for the backend pool. The
# inbound rules turn their own SNAT off, as Azure requires once an outbound
# rule exists.
#
# BOTH ADDRESSES ARE ZONE-REDUNDANT, so losing a zone loses the nodes in it
# and not the front door.
# ---------------------------------------------------------------------------
resource "random_id" "lb_label" {
  byte_length = 3
}

resource "azurerm_public_ip" "lb" {
  name                = "${local.prefix}-lb"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  sku                 = "Standard"
  allocation_method   = "Static"
  zones               = local.zones
  # A CELL'S ADDRESS HAS A NAME, because a Traffic Manager endpoint that is
  # an Azure public address must have one (../global/routing.tf). Unique in
  # the region, hence the suffix; nobody types it.
  domain_name_label = local.multi ? "${local.prefix}-${random_id.lb_label.hex}" : null
  tags              = local.tags
}

resource "azurerm_public_ip" "outbound" {
  name                = "${local.prefix}-outbound"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  sku                 = "Standard"
  allocation_method   = "Static"
  zones               = local.zones
  tags                = local.tags
}

resource "azurerm_lb" "public" {
  name                = "${local.prefix}-lb"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  sku                 = "Standard"
  tags                = local.tags

  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = azurerm_public_ip.lb.id
  }

  frontend_ip_configuration {
    name                 = "outbound"
    public_ip_address_id = azurerm_public_ip.outbound.id
  }
}

resource "azurerm_lb_backend_address_pool" "nodes" {
  name            = "nodes"
  loadbalancer_id = azurerm_lb.public.id
}

resource "azurerm_lb_probe" "https" {
  name                = "https"
  loadbalancer_id     = azurerm_lb.public.id
  protocol            = "Https"
  port                = local.published_ports.https.container
  request_path        = "/healthcheck"
  interval_in_seconds = 10
  number_of_probes    = 3
  probe_threshold     = 2
}

resource "azurerm_lb_rule" "published" {
  for_each                       = local.all_ports
  name                           = each.key
  loadbalancer_id                = azurerm_lb.public.id
  frontend_ip_configuration_name = "public"
  protocol                       = "Tcp"
  frontend_port                  = each.value.listener
  backend_port                   = each.value.container
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.nodes.id]
  probe_id                       = azurerm_lb_probe.https.id
  floating_ip_enabled            = false
  tcp_reset_enabled              = true
  idle_timeout_in_minutes        = 15
  disable_outbound_snat          = true
}

resource "azurerm_lb_outbound_rule" "nodes" {
  name                    = "egress"
  loadbalancer_id         = azurerm_lb.public.id
  protocol                = "All"
  backend_address_pool_id = azurerm_lb_backend_address_pool.nodes.id
  # 64,512 ports on one address: 16,000 a node leaves room for three and a
  # replacement being made beside them.
  allocated_outbound_ports = 16000
  tcp_reset_enabled        = true
  idle_timeout_in_minutes  = 15

  frontend_ip_configuration {
    name = "outbound"
  }
}
