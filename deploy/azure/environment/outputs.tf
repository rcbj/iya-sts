# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# The names follow deploy/aws/environment/outputs.tf and
# deploy/gcp/environment/outputs.tf wherever there is a counterpart, so a
# script reading any cloud's outputs (run-suite.sh, a multi-cloud stack)
# reads the same keys.

output "service_url" {
  description = "The cluster's public address (443 on the load balancer, allowed_cidrs only)."
  value       = local.public_base_url
}

output "public_hostname" {
  description = "The name clients use, when public_hostname is set; empty otherwise."
  value       = var.public_hostname
}

output "lb_address" {
  description = "The load balancer's IPv4 address. AWS's counterpart is `nlb_dns_name`."
  value       = azurerm_public_ip.lb.ip_address
}

output "outbound_address" {
  description = "The address every node's egress leaves from (the load balancer's outbound rule)."
  value       = azurerm_public_ip.outbound.ip_address
}

output "vault" {
  description = "The foundation's vault this environment's secrets and certificate are in."
  value       = local.vault_uri
}

output "scale_sets" {
  description = "One scale set per node, by node name (AWS: ecs_services; GCP: instance_groups)."
  value       = { for k, s in local.node_scale_sets : k => s.name }
}

output "node_zones" {
  description = "Which availability zone each node is in (AWS: node_availability_zones)."
  value       = { for k, i in local.nodes : k => local.zones[i] }
}

output "database_primary" {
  description = "The PostgreSQL primary: its server, the name the nodes dial, and the private endpoint that name maps to."
  value = {
    server   = azurerm_postgresql_flexible_server.primary.name
    hostname = local.db_hostname
    endpoint = local.db_endpoint_ip
  }
}

output "database_replica" {
  description = "The read replica's server (no endpoint: nothing dials it); empty without one."
  value       = var.db_replica ? azurerm_postgresql_flexible_server.replica[0].name : ""
}

output "admin_api_client_secret" {
  description = "The secret the suite mints its /admin-api token with: its name in `vault` (AWS: admin_api_client_secret_arn)."
  value       = "admin-api-client-secret"
}

output "secrets" {
  description = "Every secret this environment wrote into its vault, by name."
  value       = sort(keys(local.secrets))
}

output "node_identity" {
  description = "What the nodes run as: the managed identity's client id (AWS: task_role_arn)."
  value       = data.azurerm_user_assigned_identity.nodes.client_id
}

output "load_balancer_ports" {
  description = "Every port the load balancer publishes, and the node port it maps to."
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
  description = "The region this environment (or cell) is in (AWS: aws_region)."
  value       = local.region
}

output "cloud" {
  description = "Which cloud this environment is in — `azure` — for a script that reads outputs from several."
  value       = "azure"
}

output "container_logs" {
  description = "Where the nodes' container logs are: the region's Log Analytics workspace, Syslog table, tag mock-sts/<unit>/<node>."
  value       = "${var.name}-${local.region_code} (Syslog, ProcessName mock-sts/${local.unit}/*)"
}

# ---------------------------------------------------------------------------
# WHAT THE global/ STACK READS OF A CELL (../global/main.tf). A rename here
# is a rename there.
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
  description = "The VNet's address space."
  value       = local.vpc_cidr
}

output "vnet_id" {
  description = "The VNet, which the global/ stack peers with every other cell's."
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "The VNet's name."
  value       = azurerm_virtual_network.main.name
}

output "resource_group" {
  description = "The cell's resource group (the foundation's)."
  value       = data.azurerm_resource_group.unit.name
}

output "private_subnet_id" {
  description = "The private subnet the global tier's endpoint goes in."
  value       = azurerm_subnet.private.id
}

output "nodes_nsg_name" {
  description = "The nodes' security group, which the global/ stack adds the other cells' outbound addresses to."
  value       = azurerm_network_security_group.nodes.name
}

output "container_ports" {
  description = "The node ports behind the published ones, which the global/ stack admits every cell's outbound address on."
  value       = local.container_ports
}

output "lb_public_ip_id" {
  description = "The load balancer's public address, which Traffic Manager names as an endpoint."
  value       = azurerm_public_ip.lb.id
}

output "intercell_address" {
  description = "The inter-cell load balancer's fixed private address (intercell.tf); empty outside a cell."
  value       = local.multi ? local.cell_private[var.cell].intercell_ip : ""
}

output "intercell_url" {
  description = "Where the other cells reach this one: https://nodes.<cell>.<env>.mock-sts.internal:8446; empty outside a cell."
  value       = local.multi ? "https://${local.intercell_hostname}:${local.intercell_port}" : ""
}
