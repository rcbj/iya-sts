# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

provider "aws" {
  region = var.aws_region

  # Every resource this stack creates carries the project tag. The deployer
  # policy (iam_deployer.tf) keys its tag conditions on the same pair.
  default_tags {
    tags = merge(var.tags, { Project = local.project_tag })
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
