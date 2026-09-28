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
# ONE PROVIDER PER REGION A CELL MAY BE IN (#98, 2026-09-28).
#
# Terraform cannot make a provider per element of a list, so the four regions
# the design names are written out, and `regions.tf` gives each a module
# instance that exists only when `permitted_regions` names that region. A
# provider whose region is not permitted is configured and never used: it
# holds no resource and reads no data source, so it makes no call the region
# fence would refuse.
# ---------------------------------------------------------------------------
provider "aws" {
  alias  = "usw2"
  region = "us-west-2"
  default_tags {
    tags = merge(var.tags, { Project = local.project_tag })
  }
}

provider "aws" {
  alias  = "cac1"
  region = "ca-central-1"
  default_tags {
    tags = merge(var.tags, { Project = local.project_tag })
  }
}

provider "aws" {
  alias  = "euc1"
  region = "eu-central-1"
  default_tags {
    tags = merge(var.tags, { Project = local.project_tag })
  }
}

provider "aws" {
  alias  = "apse1"
  region = "ap-southeast-1"
  default_tags {
    tags = merge(var.tags, { Project = local.project_tag })
  }
}
