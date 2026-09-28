# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

variable "name" {
  description = "The project prefix. Must match the foundation and environment stacks' `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = "The multi-cell environment (e.g. `testidpna`). entrypoint.sh sets it from TF_ENV."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "cells" {
  description = <<-EOT
    Every cell of the environment — the same map the cells are applied with,
    from `../environment/envs/<env>.cells.tfvars.json` (see
    ../environment/cells.tf for what each field means). This stack reads each
    cell's state by its id.
  EOT
  type = map(object({
    region                = string
    jurisdiction          = string
    vpc_cidr              = string
    geolocation_countries = optional(list(string), [])
  }))
  validation {
    condition     = length(var.cells) >= 2
    error_message = "a multi-cell environment has at least two cells; one cell is a single-cell environment, which has no global/ stack."
  }
  validation {
    # The cells this stack has a provider for (providers.tf), and each in
    # the region its id names.
    condition = alltrue([
      for id, c in var.cells : lookup({
        usw2  = "us-west-2"
        cac1  = "ca-central-1"
        euc1  = "eu-central-1"
        apse1 = "ap-southeast-1"
      }, id, "") == c.region
    ])
    error_message = "each cell must be one of usw2 (us-west-2), cac1 (ca-central-1), euc1 (eu-central-1), apse1 (ap-southeast-1), in the region its id names."
  }
}

variable "primary_cell" {
  description = "The cell whose VPC holds the global database's writer (issue #98, D3)."
  type        = string
  validation {
    condition     = contains(keys(var.cells), var.primary_cell)
    error_message = "primary_cell must be a key of cells."
  }
}

variable "state_region" {
  description = "The state bucket's region (the home region), for reading the cells' states."
  type        = string
  default     = "us-west-2"
}

variable "db_instance_class" {
  description = "The instance class of the global primary and of every replica. The global tier is written rarely (issue #98, section 3), and read by every node of the cell it is in."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "RDS PostgreSQL version, the cells' own: 18.x only."
  type        = string
  default     = "18.6"
}

variable "db_allocated_storage" {
  description = "GiB of gp3 storage for the global primary (a replica takes the primary's)."
  type        = number
  default     = 20
}

variable "backup_retention_days" {
  description = "Automated backup retention on the global primary. More than zero is REQUIRED: RDS makes a read replica only of a source with backups."
  type        = number
  default     = 14
  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "backup_retention_days must be at least 1: a cross-region read replica needs its source's backups."
  }
}

variable "delete_automated_backups" {
  description = "Whether destroying the global primary deletes its automated backups, as the cells' `delete_automated_backups` does for theirs."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags beside Project, Environment and Stack, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
  }
}
