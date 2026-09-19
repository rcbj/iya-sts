variable "aws_region" {
  description = "The one region this project deploys to."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix. Must match the foundation and environment stacks' `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = "The environment whose load balancer gets the ports (`testidp`). entrypoint.sh sets it from TF_ENV."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "realm" {
  description = <<-EOT
    The trust realm whose SPIFFE listeners are published — an EXISTING realm's
    id, or `default` for the default realm. Terraform does not create the realm
    or turn its SPIFFE on; see deploy/aws/CLAUDE.md, *A realm's SPIFFE ports*.
  EOT
  type        = string
  validation {
    # The service's own realm-id grammar (common/realms.js, ID_PATTERN).
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,30}$", var.realm))
    error_message = "realm is a realm id: 1-31 lower-case letters, digits and hyphens, not starting with a hyphen."
  }
}

variable "workload_port" {
  description = <<-EOT
    The realm's Workload API TCP port — its `spiffe.workloadPort`. Published on
    the SAME number on the load balancer. The default realm's is 8092.
  EOT
  type        = number
  validation {
    condition     = var.workload_port >= 1024 && var.workload_port <= 65535 && floor(var.workload_port) == var.workload_port
    error_message = "workload_port is a whole number from 1024 to 65535."
  }
}

variable "server_port" {
  description = <<-EOT
    The realm's SPIRE Server API TCP port — its `spiffe.serverPort`. Published
    on the SAME number on the load balancer. The default realm's is 8181.
  EOT
  type        = number
  validation {
    condition     = var.server_port >= 1024 && var.server_port <= 65535 && floor(var.server_port) == var.server_port
    error_message = "server_port is a whole number from 1024 to 65535."
  }
}
