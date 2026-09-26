output "deployer_user_name" {
  description = "Create its access key by hand: aws iam create-access-key --user-name <this>"
  value       = aws_iam_user.deployer.name
}

output "deployer_role_arn" {
  description = "The role the deployer user assumes for every environment apply and destroy."
  value       = aws_iam_role.deployer.arn
}

output "workload_boundary_arn" {
  description = "The permissions boundary every environment role must carry."
  value       = aws_iam_policy.workload_boundary.arn
}

output "ecs_infrastructure_boundary_arn" {
  description = "The permissions boundary an environment's ECS infrastructure role (upload volumes, #214) must carry."
  value       = aws_iam_policy.ecs_infrastructure_boundary.arn
}

output "kms_key_arn" {
  description = "The project key: secrets, RDS storage and backups, container logs."
  value       = aws_kms_key.main.arn
}

output "ecr_repository_url" {
  description = "Where the service and schema-init images are pushed."
  value       = aws_ecr_repository.main.repository_url
}

output "container_log_group" {
  description = "The CloudWatch log group every environment's containers write to."
  value       = aws_cloudwatch_log_group.containers.name
}

output "state_bucket" {
  description = "The Terraform state bucket (created by bootstrap-state.sh)."
  value       = local.state_bucket
}

output "reports_bucket" {
  description = "Where a suite run inside AWS uploads its report, under <environment>/<run id>/."
  value       = aws_s3_bucket.reports.bucket
}

output "ci_user_name" {
  description = "GitHub Actions' IAM user. Create its key by hand: aws iam create-access-key --user-name <this>"
  value       = aws_iam_user.ci.name
}
