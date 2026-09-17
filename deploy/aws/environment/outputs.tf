output "service_url" {
  description = "The cluster's public address (443 on the NLB, allowed_cidrs only)."
  value       = local.public_base_url
}

output "public_hostname" {
  description = "The CNAME clients use, when public_hostname is set; empty otherwise."
  value       = var.public_hostname
}

output "public_certificate_arn" {
  description = "The ACM certificate the 443 listener presents, when public_hostname is set."
  value       = local.public_name ? aws_acm_certificate.public[0].arn : ""
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
  value       = aws_secretsmanager_secret.main["admin-api-client-secret"].arn
}

output "secret_arns" {
  description = "Every secret this environment created."
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

output "runner_task_definition" {
  description = "The suite task's family (run-suite-in-aws.sh runs its latest revision)."
  value       = var.suite_runner ? aws_ecs_task_definition.suite[0].family : ""
}

output "runner_subnet_id" {
  description = "The subnet the suite task runs in."
  value       = var.suite_runner ? aws_subnet.runner[0].id : ""
}

output "runner_security_group_id" {
  description = "The suite task's security group."
  value       = var.suite_runner ? aws_security_group.runner[0].id : ""
}

output "runner_egress_ip" {
  description = "The NAT gateway address the suite task reaches the load balancer from."
  value       = var.suite_runner ? aws_eip.runner[0].public_ip : ""
}

output "reports_bucket" {
  description = "Where the suite task uploads its report, under <environment>/<run id>/."
  value       = local.reports_bucket
}
