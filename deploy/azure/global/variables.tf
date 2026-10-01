# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "subscription_id" {
  description = "The Azure subscription (the foundation's)."
  type        = string
}

variable "name" {
  description = "The project prefix. Must match the foundation and environment stacks' `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = "The multi-region environment (e.g. `testidpna`). entrypoint.sh sets it from TF_ENV."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "cells" {
  description = "Every cell of the environment — the same map the cells are applied with, from ../environment/envs/<env>.cells.tfvars.json (../environment/cells.tf describes each field)."
  type = map(object({
    region       = string
    jurisdiction = string
    vpc_cidr     = string
    cloud        = optional(string, "azure")
  }))
  validation {
    condition     = length(var.cells) >= 2
    error_message = "a multi-region environment has at least two cells; one cell is a single-cell environment, which has no global/ stack."
  }
  validation {
    condition = alltrue([
      for id, c in var.cells : id == "z${lookup(local.region_codes, c.region, "?")}"
    ])
    error_message = "each cell's id must be `z` and its region's short code (main.tf, `region_codes`)."
  }
}

variable "jurisdictions" {
  description = "The environment's jurisdictions and the ISO 3166 countries Traffic Manager PINS to each (routing.tf). From the cells file."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
  validation {
    condition = alltrue([
      for j, v in var.jurisdictions :
      length(v.geolocation_countries) == 0 ||
      contains([for c in values(var.cells) : c.jurisdiction], j)
    ])
    error_message = "a jurisdiction that pins countries must have a cell: Traffic Manager would have nowhere to send them."
  }
  validation {
    condition = length(flatten([
      for v in values(var.jurisdictions) : v.geolocation_countries
      ])) == length(distinct(flatten([
        for v in values(var.jurisdictions) : v.geolocation_countries
    ])))
    error_message = "a country is pinned to one jurisdiction at most: Traffic Manager maps each to one endpoint."
  }
  validation {
    condition = alltrue([
      for v in values(var.jurisdictions) : alltrue([
        for c in v.geolocation_countries : can(regex("^[A-Z]{2}$", c))
      ])
    ])
    error_message = "a pinned country is an ISO 3166-1 alpha-2 code, upper case (DE, SG)."
  }
}

variable "primary_cell" {
  description = "The cell whose region holds the global database's writer (issue #98, D3)."
  type        = string
  validation {
    condition     = contains(keys(var.cells), var.primary_cell)
    error_message = "primary_cell must be a key of cells."
  }
}

variable "state_storage_account" {
  description = "The state storage account, for reading the cells' states. entrypoint.sh sets it."
  type        = string
}

variable "state_resource_group" {
  description = "The state storage account's resource group."
  type        = string
  default     = "mock-sts-terraform-state"
}

variable "public_hostname" {
  description = "The environment's one public name (e.g. `na-idp.azure.iyasec.io`), from the cells file, which every stack of the environment reads. Empty: no Traffic Manager and no name."
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "The Azure DNS zone the public name is in (../foundation/home.tf)."
  type        = string
  default     = "azure.iyasec.io"
}

variable "db_sku" {
  description = "The writer's and every replica's SKU: the cells' own (a cross-region replica needs General Purpose)."
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "db_version" {
  description = "PostgreSQL 18, the cells' own."
  type        = string
  default     = "18"
}

variable "db_storage_mb" {
  description = "The writer's storage (a replica takes the writer's)."
  type        = number
  default     = 32768
}

variable "backup_retention_days" {
  description = "The writer's automated backups, in days (7 to 35)."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Tags beside Project, Environment and Cell, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-global"
  }
}
