# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# THE DEFAULT PROVIDER IS THE PRIMARY CELL'S REGION: the global database's
# writer and the global secrets (whose replicas are made from here) live
# there. Route 53, which is global, is reached through it too.
provider "aws" {
  region = var.cells[var.primary_cell].region

  default_tags {
    tags = local.tags
  }
}

# ---------------------------------------------------------------------------
# ONE PROVIDER PER REGION A CELL MAY BE IN. Terraform cannot make a provider
# per element of `cells`, so the four regions issue #98 names are written out
# (the same four foundation/ permits), and each module block in
# database.tf and peering.tf exists only when its cells do. A cell in any
# other region is refused by the validation in variables.tf; adding one is a
# provider here, a replica block in database.tf, and a peering block per pair
# in peering.tf.
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

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
