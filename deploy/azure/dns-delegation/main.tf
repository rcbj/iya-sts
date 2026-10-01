# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "subscription_id" {
  description = "The Azure subscription the foundation's zone is in."
  type        = string
}

variable "azure_zone_name" {
  description = "The Azure DNS zone (foundation/home.tf)."
  type        = string
  default     = "azure.iyasec.io"
}

variable "azure_zone_resource_group" {
  description = "The foundation's resource group, which holds the zone."
  type        = string
  default     = "mock-sts-foundation"
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

provider "azurerm" {
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
  features {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "STS"
      ManagedBy = "terraform"
      Stack     = "mock-sts-azure-dns-delegation"
    }
  }
}

data "azurerm_dns_zone" "azure" {
  name                = var.azure_zone_name
  resource_group_name = var.azure_zone_resource_group
}

data "aws_route53_zone" "parent" {
  name         = var.parent_zone_name
  private_zone = false
}

resource "aws_route53_record" "delegation" {
  zone_id = data.aws_route53_zone.parent.zone_id
  name    = data.azurerm_dns_zone.azure.name
  type    = "NS"
  ttl     = var.ttl
  # Azure lists its name servers with the root's trailing dot; Route 53
  # takes them either way.
  records = [for ns in data.azurerm_dns_zone.azure.name_servers : trimsuffix(ns, ".")]

  lifecycle {
    precondition {
      condition     = endswith(data.azurerm_dns_zone.azure.name, ".${var.parent_zone_name}")
      error_message = "The Azure DNS zone ${data.azurerm_dns_zone.azure.name} is not inside ${var.parent_zone_name}; a delegation can only name a child."
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
