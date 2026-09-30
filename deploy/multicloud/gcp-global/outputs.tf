# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# What a GCP cell's `full` phase reads (deploy/gcp/environment/cells.tf).

output "writer_address" {
  description = "The global writer (RDS, in the primary AWS cell), dialled across the HA VPN."
  value       = local.aws.primary_address
}

output "db_port" {
  description = "The global database's port."
  value       = local.aws.db_port
}

output "db_name" {
  description = "The global database's name."
  value       = local.aws.db_name
}

output "db_app_user" {
  description = "The application role, on the writer and on every copy."
  value       = local.aws.db_app_user
}

output "publication" {
  description = "The writer's publication each copy subscribes to."
  value       = local.aws.publication
}

output "repl_user" {
  description = "The role each copy's subscription connects as."
  value       = local.aws.repl_user
}

output "secret_names" {
  description = "Each global secret's copy in Secret Manager, by the AWS name's last part."
  value       = { for k, s in google_secret_manager_secret.global : k => s.id }
}

output "writer_ca_pem" {
  description = "The RDS CA bundle for the writer's region (public certificates)."
  value       = data.http.writer_ca.response_body
}

output "copies" {
  description = "Each GCP cell's copy of the global tier: the name its certificate carries, its private address, its CA, and its master password's secret."
  value = {
    for id, i in google_sql_database_instance.copy : id => {
      # The CAS-issued certificate names the instance by `dns_name`; the
      # address stands in only where the API gives no name, and then the
      # node's name check fails loudly (deploy/multicloud/CLAUDE.md).
      hostname      = i.dns_name != "" ? trimsuffix(i.dns_name, ".") : i.private_ip_address
      address       = i.private_ip_address
      ca_pem        = nonsensitive(join("\n", [for c in i.server_ca_cert : c.cert]))
      master_secret = google_secret_manager_secret.copy_master[id].id
    }
  }
}
