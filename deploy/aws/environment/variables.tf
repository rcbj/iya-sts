variable "aws_region" {
  description = "The one region this project deploys to."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix. Must match the foundation stack's `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = <<-EOT
    This environment's name: `dev` for a hand-deployed one, `ci` for the
    workflow's. It goes into every resource name, and the load balancer's name
    is limited to 32 characters, hence the length.
  EOT
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "allowed_cidrs" {
  description = <<-EOT
    Who may connect to the load balancer on 443. No default, deliberately: a
    committed address goes stale and the symptom is a timeout against a
    healthy cluster. The workflow passes the runner's address.
  EOT
  type        = list(string)
  validation {
    condition = length(var.allowed_cidrs) > 0 && alltrue([
      for c in var.allowed_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"
    ])
    error_message = "allowed_cidrs is one or more CIDRs, and never 0.0.0.0/0."
  }
}

variable "image_tag" {
  description = "The service image tag in the project ECR repository (the commit)."
  type        = string
}

variable "schema_image_tag" {
  description = "The schema-init image tag. Empty means `schema-<image_tag>`."
  type        = string
  default     = ""
}

variable "sts_mode" {
  description = <<-EOT
    `development` or `product`. The test suite drives development mode — most
    of its jobs sign people in without a password, which product mode refuses
    by design — and development mode still reads the key-encryption key and
    the database password from Secrets Manager, because keys persist here.
  EOT
  type        = string
  default     = "development"
  validation {
    condition     = contains(["development", "product"], var.sts_mode)
    error_message = "sts_mode is development or product."
  }
}

variable "node_count" {
  description = "How many nodes, one per availability zone. Three AZs are used."
  type        = number
  default     = 3
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 3
    error_message = "node_count is 1 to 3 (one node per AZ)."
  }
}

variable "task_cpu" {
  description = "Fargate CPU units per node."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate memory (MiB) per node."
  type        = number
  default     = 3072
}

variable "db_instance_class" {
  description = "The RDS instance class for the primary and the replica."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "RDS PostgreSQL version. 18.x only; the parameter group family is postgres18."
  type        = string
  default     = "18.6"
}

variable "db_allocated_storage" {
  description = "GiB of gp3 storage per instance."
  type        = number
  default     = 20
}

variable "backup_retention_days" {
  description = "Automated backup retention on the primary."
  type        = number
  default     = 14
}

variable "delete_automated_backups" {
  description = <<-EOT
    Whether destroying the environment deletes its automated backups. True for
    a test environment: a kept backup outlives the environment it belongs to
    and bills storage for up to the retention period.
  EOT
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "The environment's own VPC. Clear of the account's existing 10.0.0.0/24 and 172.31.0.0/16."
  type        = string
  default     = "10.51.0.0/16"
}

variable "extra_environment" {
  description = "Additional environment variables for every mock-sts container."
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags beside Project = STS and Environment, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-environment"
    Lifecycle = "destroy-after-test-run"
  }
}
