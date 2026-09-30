# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# A PUBLIC NAME, WHEN `public_hostname` IS SET (deploy/aws/environment/dns.tf).
#
#   test-idp.azure.iyasec.io   A  <the load balancer's address>
#
# In the foundation's Azure DNS zone, which Route 53's iyasec.io delegates
# (deploy/azure/dns-delegation/). An A record and not a CNAME: the load
# balancer has an address and no name.
#
# A CELL WRITES ITS OWN NAME AND NOT THE SHARED ONE (#361, AWS's
# `cell_console`): `<cell>.<public name>` → this cell's load balancer, on this
# cell's certificate, handed to its nodes as STS_CELL_CONSOLE_URL. The
# shared name is a CNAME to Traffic Manager, which the global/ stack writes,
# because it spans every cell.
#
# THE CERTIFICATE IS NOT HERE: it is an ACME certificate node-a obtains at
# start and keeps in the foundation's vault (deploy/azure/node-init/cert.sh).
# ---------------------------------------------------------------------------
locals {
  # A record's name is relative to its zone.
  dns_record = local.public_name ? trimsuffix(local.multi ? local.cell_console_host : var.public_hostname, ".${var.dns_zone_name}") : ""
}

resource "azurerm_dns_a_record" "public" {
  count               = local.public_name ? 1 : 0
  name                = local.dns_record
  zone_name           = data.azurerm_dns_zone.public[0].name
  resource_group_name = data.azurerm_dns_zone.public[0].resource_group_name
  ttl                 = 300
  records             = [azurerm_public_ip.lb.ip_address]
  tags                = local.tags
}
