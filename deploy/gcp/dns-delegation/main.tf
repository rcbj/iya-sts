# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

variable "project_id" {
  description = "The GCP project the foundation's zone is in."
  type        = string
}

variable "gcp_zone_name" {
  description = "The Cloud DNS managed zone's resource name (foundation/dns.tf names it after its DNS name)."
  type        = string
  default     = "gcp-iyasec-io"
}

variable "parent_zone_name" {
  description = "The Route 53 public zone AWS manages."
  type        = string
  default     = "iyasec.io"
}

variable "aws_region" {
  description = "Any region: Route 53 is global. The AWS stacks' home region."
  type        = string
  default     = "us-west-2"
}

variable "ttl" {
  description = "The NS record's TTL. A day: the delegation changes only when the zone is re-created."
  type        = number
  default     = 86400
}

provider "google" {
  project = var.project_id
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "STS"
      ManagedBy = "terraform"
      Stack     = "mock-sts-gcp-dns-delegation"
    }
  }
}

data "google_dns_managed_zone" "gcp" {
  name = var.gcp_zone_name
}

data "aws_route53_zone" "parent" {
  name         = var.parent_zone_name
  private_zone = false
}

locals {
  # `gcp.iyasec.io.` → `gcp.iyasec.io`, which Route 53 takes either way.
  delegated_name = trimsuffix(data.google_dns_managed_zone.gcp.dns_name, ".")
}

resource "aws_route53_record" "delegation" {
  zone_id = data.aws_route53_zone.parent.zone_id
  name    = local.delegated_name
  type    = "NS"
  ttl     = var.ttl
  records = data.google_dns_managed_zone.gcp.name_servers

  lifecycle {
    precondition {
      condition     = endswith(local.delegated_name, ".${var.parent_zone_name}")
      error_message = "The Cloud DNS zone ${local.delegated_name} is not inside ${var.parent_zone_name}; a delegation can only name a child."
    }
  }
}

output "delegation" {
  description = "The NS record written in the parent zone."
  value = {
    name         = aws_route53_record.delegation.fqdn
    name_servers = aws_route53_record.delegation.records
  }
}
