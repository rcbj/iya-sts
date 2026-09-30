# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The names follow deploy/aws/environment/outputs.tf wherever there is a
# counterpart, so a script reading either cloud's outputs (run-suite.sh, and
# #97's cross-cloud balancing) reads the same keys.

output "service_url" {
  description = "The cluster's public address (443 on the load balancer, allowed_cidrs only)."
  value       = local.public_base_url
}

output "public_hostname" {
  description = "The A record clients use, when public_hostname is set; empty otherwise."
  value       = var.public_hostname
}

output "lb_address" {
  description = "The load balancer's IPv4 address — what a record for this cluster in another zone (#97) points at. AWS's counterpart is `nlb_dns_name`."
  value       = google_compute_address.lb.address
}

output "tls_secret" {
  description = "The foundation's secret holding the ACME certificate every node presents, when public_hostname is set."
  value       = local.public_name ? data.google_secret_manager_secret.tls[0].id : ""
}

output "instance_groups" {
  description = "One managed instance group per node, by node name (AWS: ecs_services)."
  value = merge(
    { "node-a" = google_compute_instance_group_manager.first.name },
    { for k, m in google_compute_instance_group_manager.others : k => m.name },
  )
}

output "node_zones" {
  description = "Which zone each node is in (AWS: node_availability_zones)."
  value       = { for k, i in local.nodes : k => local.zones[i] }
}

output "database_primary" {
  description = "The Cloud SQL primary: its instance, the name the nodes dial, and the PSC endpoint that name maps to."
  value = {
    instance = google_sql_database_instance.primary.name
    hostname = local.db_hostname
    endpoint = google_compute_address.database.address
  }
}

output "database_replica" {
  description = "The read-only replica's instance (no endpoint: nothing dials it)."
  value       = google_sql_database_instance.replica.name
}

output "admin_api_client_secret" {
  description = "The secret the suite mints its /admin-api token with (AWS: admin_api_client_secret_arn)."
  value       = local.shared_secret_names["admin-api-client-secret"]
}

output "secrets" {
  description = "Every secret this environment created (AWS: secret_arns)."
  value       = local.secret_names
}

output "node_service_account" {
  description = "What the nodes run as (AWS: task_role_arn)."
  value       = data.google_service_account.nodes.email
}

output "load_balancer_ports" {
  description = "Every port the load balancer publishes, and the node port Docker maps it to."
  value       = local.published_ports
}

output "spiffe_default_ports" {
  description = "The default realm's SPIFFE ports on the load balancer: workload and server."
  value       = local.spiffe_default_ports
}

output "image_tag" {
  description = "The service image tag the nodes run."
  value       = var.image_tag
}

output "region" {
  description = "The region this environment is in (AWS: aws_region)."
  value       = local.region
}

output "cloud" {
  description = "Which cloud this environment is in — `gcp` — for a script that reads outputs from several (#97)."
  value       = "gcp"
}

output "container_logs" {
  description = "Where the nodes' container logs are: the log name, and the bucket the foundation's sink routes it to."
  value       = "projects/${var.project_id}/logs/gcplogs-docker-driver (bucket ${var.name}-containers)"
}

# ---------------------------------------------------------------------------
# WHAT deploy/multicloud/interconnect READS OF A GCP CELL (#97).
# ---------------------------------------------------------------------------
output "cell" {
  description = "This cell's id; empty for a single-cell environment."
  value       = var.cell
}

output "cell_jurisdiction" {
  description = "This cell's jurisdiction; empty for a single-cell environment."
  value       = local.multi ? local.this_cell.jurisdiction : ""
}

output "vpc_cidr" {
  description = "The CIDR the cell's subnets are cut from."
  value       = local.vpc_cidr
}

output "intercell_address" {
  description = "The inter-cell listener's fixed private address (intercell.tf); empty outside a cell."
  value       = local.multi ? google_compute_address.intercell[0].address : ""
}

output "intercell_url" {
  description = "Where the other cells reach this one: https://nodes.<cell>.<env>.mock-sts.internal:8446; empty outside a cell."
  value       = local.multi ? "https://${local.intercell_hostname}:${local.intercell_port}" : ""
}

output "network" {
  description = "The network the cell's nodes are on (the environment's shared one, in a cell)."
  value       = local.network_name
}
