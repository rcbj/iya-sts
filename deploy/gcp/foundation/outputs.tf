# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "project_id" {
  description = "The project everything is in."
  value       = var.project_id
}

output "region" {
  description = "The home region."
  value       = var.region
}

output "deployer_email" {
  description = "The service account deploy/gcp/terraform-local.sh impersonates."
  value       = google_service_account.deployer.email
}

output "environment_service_accounts" {
  description = "What each environment's nodes run as."
  value       = { for k, s in google_service_account.environment : k => s.email }
}

output "kms_key" {
  description = "The project key's resource name."
  value       = google_kms_crypto_key.main.id
}

output "registry_url" {
  description = "Where images are pushed: <registry_url>/<image>:<tag>."
  value       = local.registry_url
}

output "dns_zone" {
  description = "The Cloud DNS zone's resource name and DNS name."
  value = {
    name     = google_dns_managed_zone.public.name
    dns_name = google_dns_managed_zone.public.dns_name
  }
}

output "dns_name_servers" {
  description = "Cloud DNS's name servers for the zone: the NS record deploy/gcp/dns-delegation/ writes into Route 53."
  value       = google_dns_managed_zone.public.name_servers
}

output "tls_secrets" {
  description = "Each public environment's certificate secret (resource name)."
  value       = { for k, s in google_secret_manager_secret.tls : k => s.id }
}

output "log_bucket" {
  description = "Where container logs are kept."
  value       = google_logging_project_bucket_config.containers.id
}

output "multicell_networks" {
  description = "Each multi-cloud environment's shared GCP network (#97)."
  value       = { for e, n in google_compute_network.multicell : e => n.name }
}

output "cell_service_accounts" {
  description = "Each GCP cell's node service account, by <env>-<cell> (#97)."
  value       = { for k, s in google_service_account.cell : k => s.email }
}

output "kms_keys" {
  description = "The project key in every region that has one, by region (#97)."
  value       = local.kms_keys
}
