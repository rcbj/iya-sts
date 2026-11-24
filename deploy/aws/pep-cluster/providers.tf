# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

provider "aws" {
  region = var.aws_region

  # Project = STS is not optional: the deployer role may only create EC2
  # resources — a VPC, its subnets, route tables, security-group rules —
  # that carry it. PepCluster says which cluster a resource is.
  default_tags {
    tags = merge({
      Project     = "STS"
      Environment = var.environment
      PepCluster  = var.cluster
      Stack       = "iya-sts-pep-cluster"
    }, var.tags)
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
