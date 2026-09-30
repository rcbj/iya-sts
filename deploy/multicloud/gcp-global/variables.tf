# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

variable "project_id" {
  description = "The GCP project (the GCP foundation's)."
  type        = string
}

variable "name" {
  description = "The project prefix, the same in every stack."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = "The multi-cloud environment (e.g. `testidpmc`)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,10}$", var.environment))
    error_message = "a multi-cloud environment's name is 2-11 lower-case letters and digits: a GCP cell's service account is mock-sts-env-<env>-<cell>, at most 30 characters."
  }
}

variable "cells" {
  description = "Every cell, from deploy/multicloud/envs/<env>.cells.tfvars.json (deploy/aws/environment/cells.tf describes each field)."
  type = map(object({
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "")
    cloud                  = optional(string, "aws")
    coordinates            = optional(object({ latitude = string, longitude = string }))
    global_db_cidr         = optional(string, "")
  }))
}

variable "primary_cell" {
  description = "The AWS cell holding the global writer."
  type        = string
}

variable "state_region" {
  description = "The AWS state bucket's region (the AWS home region)."
  type        = string
  default     = "us-west-2"
}

variable "db_tier" {
  description = "Each GCP cell's copy of the global tier: written only by replication, read by the cell's nodes."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_version" {
  description = "The copies' PostgreSQL: the writer's major version, 18."
  type        = string
  default     = "POSTGRES_18"
}

variable "db_disk_gib" {
  description = "Each copy's disk (it grows automatically)."
  type        = number
  default     = 20
}

variable "jurisdictions" {
  description = "The jurisdictions and the countries pinned to each (#367's model), from the cells file. Unread here."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
}
