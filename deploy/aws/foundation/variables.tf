variable "aws_region" {
  description = "The one region this project deploys to."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = <<-EOT
    The prefix every resource name in this project starts with. The deployer
    policy scopes names to it, so changing it after the first apply strands the
    deployer from what it created.
  EOT
  type        = string
  default     = "mock-sts"
}

variable "tags" {
  description = "Tags beside Project = STS, which is always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-foundation"
  }
}

variable "log_retention_days" {
  description = "How long container logs are kept after an environment is gone."
  type        = number
  default     = 14
}

variable "deployer_session_seconds" {
  description = <<-EOT
    The longest session the deployer role issues. A CI run creates RDS (about
    twenty minutes), runs the suite and destroys everything in one job, so an
    hour is not enough and credentials that expire before the destroy leave
    the environment running.
  EOT
  type        = number
  default     = 14400
}

variable "ci_user_name" {
  description = <<-EOT
    The IAM user GitHub Actions authenticates as (.github/workflows/aws-cluster.yml),
    named in the account's git_userN series. Like git_user5, it has no console
    login, no groups and one inline policy: assume the deployer role. Its access
    key is created by hand so the secret never lands in Terraform state.
  EOT
  type        = string
  default     = "git_user6"
}
