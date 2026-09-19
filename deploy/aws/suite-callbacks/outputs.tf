output "cluster" {
  description = "The ECS cluster the task runs in."
  value       = local.env.ecs_cluster
}

output "task_definition" {
  description = "The callback task's family."
  value       = aws_ecs_task_definition.callbacks.family
}

output "subnet_id" {
  description = "The subnet the task runs in."
  value       = aws_subnet.callbacks.id
}

output "security_group_id" {
  description = "The task's security group."
  value       = aws_security_group.callbacks.id
}

output "egress_ip" {
  description = "The NAT address the task reaches the load balancer from."
  value       = aws_eip.callbacks.public_ip
}

output "reports_bucket" {
  description = "Where the task uploads its report, under <environment>/<run id>/."
  value       = local.env.reports_bucket
}

output "log_group" {
  description = "The container log group; streams are <environment>-callbacks/<container>/<task id>."
  value       = local.env.container_log_group
}
