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
  value       = { for k, m in module.peering : k => m.peering_connection_id }
}

# ---------------------------------------------------------------------------
# WHAT A MULTI-CLOUD ENVIRONMENT'S GCP SIDE READS (#97): the publication and
# its role, and where each global secret is in the primary region — the
# values are copied from there into GCP Secret Manager
# (deploy/multicloud/gcp-global).
# ---------------------------------------------------------------------------
output "publication" {
  description = "The writer's publication the GCP cells subscribe to; empty unless multi-cloud."
  value       = local.multi_cloud ? local.publication : ""
}

output "repl_user" {
  description = "The role a GCP cell's subscription connects as; empty unless multi-cloud."
  value       = local.multi_cloud ? local.repl_user : ""
}

output "writer_region" {
  description = "The primary cell's region: where the writer and the global secrets are."
  value       = local.primary_region
}

output "global_secret_names" {
  description = "Each replicated global secret's name in the primary region."
  value       = { for k, s in aws_secretsmanager_secret.global : k => s.name }
}
