# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  tags = {
    Project     = "STS"
    Environment = var.environment
    Stack       = "iya-sts-interconnect"
    ManagedBy   = "terraform"
  }
}

# The default: the primary AWS cell's region. Route 53, which is global, and
# the state reads go through it.
provider "aws" {
  region = var.cells[var.primary_cell].region
  default_tags {
    tags = local.tags
  }
}

# ---------------------------------------------------------------------------
# ONE PROVIDER PER REGION AN AWS CELL MAY BE IN — deploy/aws/global's four,
# written out for its reason (a provider cannot be made per element of a
# map), each used by the pair module whose AWS cell is there.
# ---------------------------------------------------------------------------
provider "aws" {
  alias  = "usw2"
  region = "us-west-2"
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "cac1"
  region = "ca-central-1"
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "euc1"
  region = "eu-central-1"
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "apse1"
  region = "ap-southeast-1"
  default_tags {
    tags = local.tags
  }
}

provider "google" {
  project = var.project_id

  default_labels = {
    project     = "sts"
    environment = var.environment
    stack       = "iya-sts-interconnect"
  }
}

data "aws_caller_identity" "current" {}
