# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "service_url" {
  description = "The cluster's public address (443 on the NLB, allowed_cidrs only)."
  value       = local.public_base_url
}

output "public_hostname" {
  description = "The CNAME clients use, when public_hostname is set; empty otherwise."
  value       = var.public_hostname
}

output "public_certificate_arn" {
  description = "The exportable ACM certificate every NODE presents on 8081, when public_hostname is set; the load balancer passes TLS through."
  value       = local.public_certificate_arn
}

output "nlb_dns_name" {
  description = "The load balancer's DNS name, also the first TLS hostname on every node."
  value       = aws_lb.main.dns_name
}

output "ecs_cluster" {
  description = "The ECS cluster the nodes run in."
  value       = aws_ecs_cluster.main.name
}

output "ecs_services" {
  description = "One service per node, by node name."
  value = merge(
    { "node-a" = aws_ecs_service.first.name },
    { for k, s in aws_ecs_service.others : k => s.name },
  )
}

output "node_availability_zones" {
  description = "Which AZ each node's subnet is in."
  value       = { for k, i in local.nodes : k => local.azs[i] }
}

output "database_primary_endpoint" {
  description = "The RDS primary (private; TLS required)."
  value       = aws_db_instance.primary.endpoint
}

output "database_replica_endpoint" {
  description = "The read-only replica (private; TLS required)."
  value       = aws_db_instance.replica.endpoint
}

output "admin_api_client_secret_arn" {
  description = "The secret the workflow mints its /admin-api token with."
  value       = local.shared_secret_arns["admin-api-client-secret"]
}

output "secret_arns" {
  description = "Every secret this environment created. A cell's global ones are the global/ stack's (#98)."
  value       = { for k, s in aws_secretsmanager_secret.main : k => s.arn }
}

output "container_log_group" {
  description = "Where the nodes' logs are, with stream prefix `<environment>-<node>`."
  value       = data.aws_cloudwatch_log_group.containers.name
}

output "task_role_arn" {
  description = "What the mock-sts containers run as."
  value       = aws_iam_role.task.arn
}

output "load_balancer_ports" {
  description = "Every port the load balancer publishes, and the node port behind it."
  value       = local.published_ports
}

output "spiffe_default_ports" {
  description = "The default realm's SPIFFE ports on the load balancer (spiffe_default.tf): workload and server."
  value       = local.spiffe_default_ports
}

output "reports_bucket" {
  description = "Where the suite task uploads its report, under <environment>/<run id>/."
  value       = local.reports_bucket
}

output "image_tag" {
  description = "The service image tag the nodes run. The workflow's suite job re-applies with it when it admits its own runner's address (allowed_cidrs), so admitting a runner never changes what is deployed."
  value       = var.image_tag
}

# ---------------------------------------------------------------------------
# A CELL'S OUTPUTS (#98): what the global/ stack reads from each cell's state
# to place the global database, peer the VPCs and share the inter-cell names,
# and what run-suite.sh needs to talk to the cell's own region. Empty or null
# in a single-cell environment — and ADDED, so that stack's existing outputs
# are exactly what they were.
# ---------------------------------------------------------------------------
output "aws_region" {
  description = "The region this environment (or cell) is in."
  value       = local.region
}

output "cell" {
  description = "This cell's id; empty for a single-cell environment."
  value       = var.cell
}

output "cell_jurisdiction" {
  description = "This cell's jurisdiction; empty for a single-cell environment."
  value       = local.multi ? local.this_cell.jurisdiction : ""
}

output "vpc_id" {
  description = "The environment's VPC."
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The VPC's CIDR (a cell's is distinct from every other cell's)."
  value       = local.vpc_cidr
}

output "route_table_ids" {
  description = "A cell's two route tables (public: the nodes and the load balancer; private: the databases), which the peering adds routes to. Empty for a single-cell environment."
  value = local.multi ? {
    public  = aws_route_table.public.id
    private = aws_route_table.private[0].id
  } : {}
}

output "global_db_subnet_group" {
  description = "Where the global database's instance in this cell is placed (global_db.tf); empty for a single-cell environment."
  value       = local.multi ? aws_db_subnet_group.global[0].name : ""
}

output "global_db_security_group_id" {
  description = "The global database's security group in this cell; empty for a single-cell environment."
  value       = local.multi ? aws_security_group.global_database[0].id : ""
}

output "intercell_zone_id" {
  description = "The private hosted zone of this cell's inter-cell name (intercell.tf), which global/ associates with every other cell's VPC; empty for a single-cell environment."
  value       = local.multi ? aws_service_discovery_private_dns_namespace.cells[0].hosted_zone : ""
}

output "intercell_url" {
  description = "Where the other cells reach this cell's nodes: https://nodes.<cell>.<env>.mock-sts.internal:8446, never public; empty for a single-cell environment."
  value       = local.multi ? "https://${local.intercell_hostname}:${local.intercell_port}" : ""
}

output "cell_kek_secret_arn" {
  description = "The cell's own key-encryption key, replicated nowhere; empty for a single-cell environment."
  value       = local.multi ? aws_secretsmanager_secret.main["cell-kek"].arn : ""
}

# ---------------------------------------------------------------------------
# A CONVERTED CELL'S ONE-OFF TASK (conversion.tf, #98): what entrypoint.sh
# needs to run it — the task definition, and the subnet and security group a
# node would get. Empty in every cell that names no snapshot, and in `base`.
# ---------------------------------------------------------------------------
output "db_snapshot_identifier" {
  description = "The snapshot this cell's database was restored from; empty for one made empty."
  value       = local.db_snapshot_identifier
}

output "conversion_task_definition" {
  description = "The conversion task's definition ARN, in a restored cell's `full` phase; empty otherwise."
  value       = local.converted && local.full ? aws_ecs_task_definition.convert[0].arn : ""
}

output "conversion_network" {
  description = "Where the conversion task runs: node-a's public subnet (it pulls its image and reads its secrets with no NAT, as a node does) and the nodes' security group."
  value = {
    subnets          = [aws_subnet.public[0].id]
    security_groups  = [aws_security_group.nodes.id]
    assign_public_ip = "ENABLED"
  }
}

# ---------------------------------------------------------------------------
# WHAT deploy/multicloud/interconnect READS OF AN AWS CELL (#97): where its
# VPN attaches and routes, where its inbound resolver sits, and what the
# Route 53 tree aliases and checks.
# ---------------------------------------------------------------------------
output "private_subnet_ids" {
  description = "The cell's private subnets (the databases; the inbound resolver endpoint of a multi-cloud cell)."
  value       = aws_subnet.private[*].id
}

output "private_subnet_cidrs" {
  description = "The private subnets' CIDRs, in order: the resolver endpoint's fixed addresses are .53 of the first two."
  value       = aws_subnet.private[*].cidr_block
}

output "nlb_zone_id" {
  description = "The load balancer's Route 53 zone, for an alias record to it."
  value       = aws_lb.main.zone_id
}

output "route53_health_check_id" {
  description = "This cell's HTTPS health check on its load balancer; empty without a public name or outside a cell."
  value       = local.cells_dns ? aws_route53_health_check.cell[0].id : ""
}

output "cloud" {
  description = "Which cloud this environment (or cell) is in, for a script reading several (#97)."
  value       = "aws"
}
