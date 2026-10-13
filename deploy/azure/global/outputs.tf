# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# What each cell's `full` apply reads from this stack's state
# (../environment/cells.tf, `local.global`). A rename here is a rename there.

output "writer_host" {
  description = "The global database's WRITER: its name, which every cell maps to the writer's endpoint in the primary cell (STS_GLOBAL_DATABASE_URL)."
  value       = azurerm_postgresql_flexible_server.writer.fqdn
}

output "read_hosts" {
  description = "Where each cell reads the global tier, by cell: its own replica, or the writer in the primary cell (STS_GLOBAL_DATABASE_READ_URL)."
  value       = { for id, s in local.servers : id => s.fqdn }
}

output "db_port" {
  description = "The global database's port."
  value       = local.db_port
}

output "db_name" {
  description = "The global database's database name."
  value       = local.db_name
}

output "db_app_user" {
  description = "The least-privilege role the nodes connect as (made by the primary cell's global schema-init)."
  value       = local.db_app_user
}

output "traffic_manager_fqdn" {
  description = "The parent profile's name, which the public name aliases; empty without one."
  value       = local.public_name ? azurerm_traffic_manager_profile.parent[0].fqdn : ""
}

output "peerings" {
  description = "Every half of every inter-cell peering."
  value       = sort(keys(azurerm_virtual_network_peering.cells))
}
