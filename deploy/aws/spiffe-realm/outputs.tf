output "realm" {
  description = "The realm these ports belong to."
  value       = var.realm
}

output "workload_api_endpoint" {
  description = "What a workload sets SPIFFE_ENDPOINT_SOCKET to, to reach this realm's Workload API."
  value       = "tcp://${local.public_host}:${var.workload_port}"
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
    "spiffe.enabled"      = true
    "spiffe.workloadPort" = var.workload_port
    "spiffe.serverPort"   = var.server_port
  }
}
