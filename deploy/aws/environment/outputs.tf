output "service_url" {
  description = "The cluster's public address (443 on the NLB, allowed_cidrs only)."
  value       = local.public_base_url
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
