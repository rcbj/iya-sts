# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

provider "aws" {
  # A cell's region is its own (cells.tf); a single-cell environment's is
  # `aws_region`.
  region = var.cell != "" ? var.cells[var.cell].region : var.aws_region

  # Project = STS is not optional: the deployer role may only create EC2
  # resources that carry it, and may only change or delete ones that do.
  default_tags {
    # Cell only in a cell (#98): a new tag on every resource of a single-cell
    # environment would be a change to every resource it has.
    tags = merge(var.tags, {
      Project     = "STS"
      Environment = var.environment
    }, var.cell != "" ? { Cell = var.cell } : {})
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
