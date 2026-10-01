# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

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
# ONE PROVIDER, EVERY CELL'S REGION (#367, 2026-09-30). This file carried a
# provider block per region a cell could be in — four, written out — and
# database.tf and peering.tf a module block per region and per PAIR of
# regions, until AWS provider 6's per-resource `region` argument let one
# provider reach them all. The replicas and the peerings are one `for_each`
# each now, over `cells`, and a cell in a new region needs nothing here.
# ---------------------------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
