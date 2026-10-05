# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "subscription_id" {
  description = "The subscription everything is in."
  value       = local.subscription_id
}

output "home_region" {
  description = "The home region."
  value       = var.home_region
}

output "registry_login_server" {
  description = "Where images are pushed: <login server>/iya-sts:<tag>."
  value       = azurerm_container_registry.main.login_server
}

output "dns_zone" {
  description = "The Azure DNS zone's name and resource group."
  value = {
    name           = azurerm_dns_zone.public.name
    resource_group = azurerm_dns_zone.public.resource_group_name
  }
}

output "dns_name_servers" {
  description = "Azure DNS's name servers for the zone: the NS record deploy/azure/dns-delegation/ writes into Route 53."
  value       = azurerm_dns_zone.public.name_servers
}

output "units" {
  description = "Each environment or cell: its resource group, node identity and vault."
  value = {
    for k, u in local.units : k => {
      region         = u.region
      resource_group = azurerm_resource_group.unit[k].name
      node_identity  = azurerm_user_assigned_identity.nodes[k].client_id
      vault          = azurerm_key_vault.unit[k].vault_uri
    }
  }
}

output "key_encryption_keys" {
  description = "Each single-cell environment's and each multi-region environment's key-encryption key (kek.tf): the vault URI and key name every one of its nodes must name, identically."
  value = {
    for k, key in azurerm_key_vault_key.kek : k => {
      vault = trimsuffix(contains(keys(azurerm_key_vault.global), k) ? azurerm_key_vault.global[k].vault_uri : azurerm_key_vault.unit[k].vault_uri, "/")
      key   = key.name
    }
  }
}

output "global_resource_groups" {
  description = "Each multi-region environment's global group."
  value       = { for k, g in azurerm_resource_group.global : k => g.name }
}

output "regions" {
  description = "Every prepared region: its group, keys and log workspace."
  value = {
    for r, m in module.region : r => {
      resource_group = m.resource_group
      key_ids        = m.key_ids
      workspace_id   = m.workspace_id
    }
  }
}

output "deployer_role" {
  description = "The deployer's custom role."
  value       = azurerm_role_definition.deployer.name
}
