# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

output "service_url" {
  description = "The one public address of all six cells."
  value       = "https://${var.public_hostname}"
}

output "cells" {
  description = "Each cell's cloud, jurisdiction and public load balancer."
  value = merge(
    { for id, c in local.aws : id => { cloud = "aws", jurisdiction = var.cells[id].jurisdiction, load_balancer = c.nlb_dns_name } },
    { for id, c in local.gcp : id => { cloud = "gcp", jurisdiction = var.cells[id].jurisdiction, load_balancer = c.lb_address } },
  )
}

output "pinned_countries" {
  description = "Which jurisdiction each pinned country is answered by."
  value       = local.pinned_places
}

output "vpn_status_commands" {
  description = "Where to look for each pair's BGP sessions."
  value = merge(
    { for m in module.pair_usw2 : "usw2" => m.tunnels_up_hint },
    { for m in module.pair_cac1 : "cac1" => m.tunnels_up_hint },
    { for m in module.pair_euc1 : "euc1" => m.tunnels_up_hint },
    { for m in module.pair_apse1 : "apse1" => m.tunnels_up_hint },
  )
}
