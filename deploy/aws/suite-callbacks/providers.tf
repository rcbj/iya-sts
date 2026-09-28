# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

provider "aws" {
  region = var.aws_region

  # Project = STS is not optional: the deployer role may only create EC2
  # resources that carry it. Stack says these are the run's, destroyed with it.
  default_tags {
    tags = merge({
      Project     = "STS"
      Environment = var.environment
      Stack       = "suite-callbacks"
    }, var.cell != "" ? { Cell = var.cell } : {})
  }
}

data "aws_caller_identity" "current" {}
