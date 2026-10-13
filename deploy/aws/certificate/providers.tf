# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# An ACM certificate is regional: a cell's is in the cell's region, beside the
# load balancer and the nodes that present it.
provider "aws" {
  region = var.cell != "" ? var.cells[var.cell].region : var.aws_region

  # Project = STS is not optional: the deployer role may only request an ACM
  # certificate that carries it, and may only read or change one that does
  # (foundation/iam_deployer.tf, AcmCreateOnlyTagged / AcmChangeOnlyTagged).
  default_tags {
    tags = merge(var.tags, {
      Project     = "STS"
      Environment = var.environment
    }, var.cell != "" ? { Cell = var.cell } : {})
  }
}
