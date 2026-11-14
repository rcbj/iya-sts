# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  # Project = STS is not optional: the deployer role may only create EC2
  # resources that carry it, and may only change or delete ones that do.
  # Cell only in a cell (#98): a new tag on every resource of a single-cell
  # environment would be a change to every resource it has.
  provider_tags = merge(var.tags, {
    Project     = "STS"
    Environment = var.environment
  }, var.cell != "" ? { Cell = var.cell } : {})
}

provider "aws" {
  # A cell's region is its own (cells.tf); a single-cell environment's is
  # `aws_region`.
  region = var.cell != "" ? var.cells[var.cell].region : var.aws_region

  default_tags {
    tags = local.provider_tags
  }
}

# CloudFront's certificate and web ACL exist only here (cloudfront.tf).
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.provider_tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
