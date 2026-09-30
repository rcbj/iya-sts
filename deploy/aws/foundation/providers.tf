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

# ---------------------------------------------------------------------------
# ONE PROVIDER, EVERY REGION (#367, 2026-09-30). Until then this file carried
# a provider block per region a cell could be in — four, written out, because
# Terraform cannot make a provider per list element. AWS provider 6 gives
# every regional resource a `region` argument instead, so modules/region is
# one module block with a `for_each` over `permitted_regions`
# (regions.tf), each instance naming its region on every resource it makes,
# through this provider. A region is opened by the list alone.
# ---------------------------------------------------------------------------
