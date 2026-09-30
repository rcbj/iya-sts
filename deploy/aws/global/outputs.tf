# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# What each cell's `full` apply reads from this stack's state
# (../environment/cells.tf, `local.global`). A rename here is a rename there.

output "primary_address" {
  description = "The global database's WRITER, in the primary cell's VPC (TLS required): STS_GLOBAL_DATABASE_URL in every cell."
  value       = aws_db_instance.primary.address
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
  description = "The least-privilege role the nodes connect as (set by the primary cell's global-schema-init)."
  value       = local.db_app_user
}

output "read_addresses" {
  description = "Where each cell reads the global tier, by cell: its own replica, or the writer in the primary cell. STS_GLOBAL_DATABASE_READ_URL."
  value       = local.read_addresses
}

output "secret_arns" {
  description = "Each global secret's ARN in each cell's region, by cell then name (the replicas' ARNs differ from the primary's in the region only)."
  value       = local.secret_arns
}

output "master_secret_arn" {
  description = "The global database's master password, in the primary cell's region only; read by that cell's global-schema-init."
  value       = aws_secretsmanager_secret.db_master.arn
}

output "peering_connection_ids" {
  description = "Every inter-cell peering, by pair."
  value = merge(
    { for m in module.peering_usw2_cac1 : "usw2_cac1" => m.peering_connection_id },
    { for m in module.peering_usw2_euc1 : "usw2_euc1" => m.peering_connection_id },
    { for m in module.peering_usw2_apse1 : "usw2_apse1" => m.peering_connection_id },
    { for m in module.peering_cac1_euc1 : "cac1_euc1" => m.peering_connection_id },
    { for m in module.peering_cac1_apse1 : "cac1_apse1" => m.peering_connection_id },
    { for m in module.peering_euc1_apse1 : "euc1_apse1" => m.peering_connection_id },
  )
}
