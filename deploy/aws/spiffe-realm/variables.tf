# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

variable "aws_region" {
  description = "The environment's region; a cell's own region in a multi-cell environment (entrypoint.sh sets it, #98)."
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

variable "cell" {
  description = <<-EOT
    The cell of a multi-cell environment whose load balancer this is for
    (issue #98; ../environment/cells.tf). EMPTY — the default — is a
    single-cell environment, exactly as before. entrypoint.sh sets it from
    TF_CELL, and sets `aws_region` to that cell's region.
  EOT
  type        = string
  default     = ""
  validation {
    condition     = var.cell == "" || can(regex("^[a-z][a-z0-9]{1,4}$", var.cell))
    error_message = "cell is empty or a cell id (2-5 lower-case letters and digits)."
  }
}

variable "state_region" {
  description = "The state bucket's region — the home region, which a cell's is not (#98)."
  type        = string
  default     = "us-west-2"
}
