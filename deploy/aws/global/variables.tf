# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

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
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "") # the cell's; unread here
    # A MULTI-CLOUD ENVIRONMENT'S GCP CELLS (#97): unread here but for
    # `cloud`, which keeps them out of everything this stack does with an
    # AWS cell — its state, its replica, its peering and its secret replicas.
    # Their copies of the global tier subscribe to the publication below and
    # are deploy/multicloud/gcp-global's.
    cloud          = optional(string, "aws")
    coordinates    = optional(object({ latitude = string, longitude = string }))
    global_db_cidr = optional(string, "")
  }))
  validation {
    condition     = length(var.cells) >= 2
    error_message = "a multi-cell environment has at least two cells; one cell is a single-cell environment, which has no global/ stack."
  }
  validation {
    # EACH CELL IN THE REGION ITS ID NAMES, by foundation/locals.tf's rule
    # (`cell_of_region`, #367 — keep the copies in step): the area, the
    # direction's initials and the number, us-west-2 = usw2, ap-southeast-5 =
    # apse5. It was a table of the four regions this stack had providers for.
    condition = alltrue([
      for id, c in var.cells : c.cloud != "aws" || (
        can(regex("^[a-z]{2}-(north|south|east|west|central|northeast|northwest|southeast|southwest)-[1-9]$", c.region)) &&
        id == join("", [
          split("-", c.region)[0],
          lookup({
            north     = "n", south = "s", east = "e", west = "w", central = "c",
            northeast = "ne", northwest = "nw", southeast = "se", southwest = "sw",
          }, split("-", c.region)[1], "?"),
          split("-", c.region)[2],
      ]))
    ])
    error_message = "each AWS cell's id must be its region shortened by rule (us-west-2 is usw2, eu-central-1 euc1, ap-southeast-5 apse5), in a commercial region of the form area-direction-digit."
  }
}

variable "jurisdictions" {
  description = "The environment's jurisdictions and the countries pinned to each (../environment/dns_cells.tf). In the cells file, which this stack also reads; unread here."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
}

variable "primary_cell" {
  description = "The cell whose VPC holds the global database's writer (issue #98, D3)."
  type        = string
  validation {
    condition     = try(var.cells[var.primary_cell].cloud, "") == "aws"
    error_message = "primary_cell must be an AWS cell of cells: the global writer is RDS (#97 keeps it there)."
  }
}

variable "carryover_secret" {
  description = <<-EOT
    The name of a CARRY-OVER secret in the primary cell's region — e.g.
    `mock-sts/carryover/testidp`, written by deploy/aws/convert-to-cells.sh —
    whose values replace the generated ones for the secrets a converted
    single-region environment's database was written under (secrets.tf, *A
    converted environment's secrets*). EMPTY — the default, and every
    environment that was not converted — generates every value. Read once,
    when the global secrets are first made; entrypoint.sh passes it only with
    TF_CONVERT=1 (envs/<env>.conversion.tfvars.json).
  EOT
  type        = string
  default     = ""
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

variable "max_slot_wal_keep_size_mb" {
  description = <<-EOT
    A MULTI-CLOUD ENVIRONMENT ONLY (#97): the most WAL the writer keeps for a
    logical replication slot that has fallen behind — a GCP cell's subscriber
    that is down, or that was destroyed without dropping its subscription.
    Past it the slot is invalidated and that subscriber must be re-synced
    (its node's schema-init drops and re-creates the subscription), rather
    than the writer's disk filling and every cell losing its global writes.
  EOT
  type        = number
  default     = 10240
}
