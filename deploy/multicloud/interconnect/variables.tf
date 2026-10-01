# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "project_id" {
  description = "The GCP project."
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
}

variable "cells" {
  description = "Every cell, from deploy/multicloud/envs/<env>.cells.tfvars.json."
  type = map(object({
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "")
    cloud                  = optional(string, "aws")
    coordinates            = optional(object({ latitude = string, longitude = string }))
    global_db_cidr         = optional(string, "")
  }))
  validation {
    # One AWS cell and one GCP cell per jurisdiction: each jurisdiction is a
    # pair joined by its own VPN, and survives either cloud's regional loss.
    condition = alltrue([
      for j in distinct([for c in values(var.cells) : c.jurisdiction]) :
      length([for c in values(var.cells) : c if c.jurisdiction == j && c.cloud == "aws"]) == 1 &&
      length([for c in values(var.cells) : c if c.jurisdiction == j && c.cloud == "gcp"]) == 1
    ])
    error_message = "every jurisdiction must have exactly one AWS cell and one GCP cell."
  }
  validation {
    condition     = alltrue([for c in values(var.cells) : c.cloud != "gcp" || c.coordinates != null])
    error_message = "every GCP cell needs coordinates: Route 53 places a non-AWS endpoint by latitude and longitude."
  }
}

variable "primary_cell" {
  description = "The AWS cell holding the global writer. Unread here beyond its existence."
  type        = string
}

variable "public_hostname" {
  description = "The one public name every cell answers, in the Route 53 zone AWS manages."
  type        = string
  default     = "test-idp.iyasec.io"
}

variable "public_zone_name" {
  description = "The Route 53 public zone (AWS manages it, always)."
  type        = string
  default     = "iyasec.io"
}

variable "gcp_zone_name" {
  description = "The Cloud DNS zone delegated from it, where a GCP cell's ACME challenge is answered."
  type        = string
  default     = "gcp.iyasec.io"
}

variable "state_region" {
  description = "The AWS state bucket's region."
  type        = string
  default     = "us-west-2"
}

variable "health_check_regions" {
  description = "Route 53's checker regions — the AWS cells' three (deploy/aws/environment/dns_cells.tf), so one firewall list serves both clouds."
  type        = list(string)
  default     = ["us-east-1", "us-west-1", "eu-west-1"]
}

variable "jurisdictions" {
  description = "The jurisdictions and the countries pinned to each (#367's model), from the cells file. Each pinned country answers its jurisdiction's two-cell set (routing.tf)."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
}
