# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "public_url" {
  description = "The reverse proxy, through the WAF and the gateway: the cluster's publicBaseUrl."
  value       = "https://${var.public_hostname}"
}

output "decision_url" {
  description = "The decision API and AuthZEN edge PDP."
  value       = var.publish_decision_api ? "https://${var.public_hostname}:${var.decision_port}" : null
}

output "egress_ip" {
  description = "The ONE address the members reach the identity service from (the NAT gateway). The identity service must admit it — for an Azure iya-sts environment, in its ALLOWED_CIDR."
  value       = azurerm_public_ip.nat.ip_address
}

output "gateway_ip" {
  description = "The gateway's public address, which public_hostname names."
  value       = azurerm_public_ip.gateway.ip_address
}

output "members" {
  description = "Each member's PEP_NAME: its scale set, its secret's name in the vault, and its notify URL (with notify_cidrs)."
  value = {
    for m, v in local.members : m => {
      scale_set  = azurerm_orchestrated_virtual_machine_scale_set.member[m].name
      vms        = v.instances
      issuer     = v.issuer
      secret     = "pep-${var.cluster}-${m}"
      notify_url = local.notify ? "https://${var.public_hostname}:${local.notify_ports[m]}/notify" : null
    }
  }
}

output "vault" {
  description = "The PEP environment's vault (the foundation's)."
  value       = data.azurerm_key_vault.pep.name
}

output "pdp_url" {
  description = "PEP_PDP_URL: the identity service, as every member dials it."
  value       = local.pdp_url
}

output "credential_mode" {
  value = var.credential_mode
}

output "nudged" {
  description = "Whether the identity service can nudge the members (notify_cidrs). false: provision.sh stops nudging their rows and they poll."
  value       = local.notify
}

output "gateway_trusts_members" {
  description = "Whether member_trust_anchor was given. false: the gateway cannot verify the members' listener pairs and every backend is unhealthy — run provision.sh's second pass, then apply again."
  value       = local.anchored
}

output "autoscale" {
  value = local.autoscale ? { min = var.instance_count, max = var.autoscale_max, cpu_target = var.autoscale_cpu_target } : null
}

output "companion_upstream" {
  description = "With companion = true: the upstream a cluster route names to reach each member's own companion."
  value       = var.companion ? "http://127.0.0.1:${local.companion_port}" : null
}

output "waf_policy_id" {
  value = azurerm_web_application_firewall_policy.main.id
}

output "cloud" {
  value = "azure"
}
