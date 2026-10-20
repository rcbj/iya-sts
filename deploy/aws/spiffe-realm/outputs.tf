# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "realm" {
  description = "The realm these ports belong to."
  value       = var.realm
}

output "workload_api_endpoint" {
  description = "The Workload API is the local agent's Unix socket in the workload's own task (#324). It is not a load-balancer address. workload_port is accepted and is not published; the SPIRE Server API is spire_server_api_address."
  value       = "unix:///tmp/spire-agent/public/api.sock (workload_port ${var.workload_port} is not published)"
}

output "spire_server_api_address" {
  description = "This realm's SPIRE Server API (gRPC, mutual TLS with an X509-SVID)."
  value       = "${local.public_host}:${var.server_port}"
}

output "registered_node_addresses" {
  description = "The node addresses registered on this apply. A task that restarts comes back on a new one; re-apply then."
  value       = sort(tolist(local.node_ips))
}

output "allowed_cidrs" {
  description = "Who may connect: copied from the environment's 443 rules at this apply."
  value       = sort(tolist(local.allowed_cidrs))
}

output "realm_settings" {
  description = "What the realm itself must be set to, in the console or through /admin-api — Terraform does not set it."
  value = {
    "spiffe.enabled"    = true
    "spiffe.serverPort" = var.server_port
  }
}
