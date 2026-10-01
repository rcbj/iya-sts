# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # `mock-sts-<env>-global`: every name here, under the `mock-sts-*` the
  # deployer's policy scopes RDS and Secrets Manager to.
  prefix      = "${var.name}-${var.environment}-global"
  secret_path = "${var.name}/${var.environment}"

  primary        = var.cells[var.primary_cell]
  primary_region = local.primary.region
  # THE AWS CELLS (#97): everything this stack does with a cell — read its
  # state, make its replica, peer its VPC, replicate a secret into its
  # region — it does with these. A GCP cell is deploy/multicloud's.
  aws_cells     = { for id, c in var.cells : id => c if c.cloud == "aws" }
  multi_cloud   = length(local.aws_cells) < length(var.cells)
  replica_cells = { for id, c in local.aws_cells : id => c if id != var.primary_cell }

  # THE PUBLICATION A MULTI-CLOUD ENVIRONMENT'S GCP CELLS SUBSCRIBE TO, and
  # the role they subscribe as (#97) — made by the primary cell's
  # global-schema-init (deploy/aws/schema-init/apply.sh), named here once.
  publication = "sts_global"
  repl_user   = "sts_repl"

  tags = merge(var.tags, {
    Project     = "STS"
    Environment = var.environment
    Stack       = "mock-sts-global"
  })

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432
}

# ---------------------------------------------------------------------------
# EVERY CELL, AS ITS OWN APPLY LEFT IT. What this stack needs of a cell — its
# VPC and CIDR, its two route tables, the subnet group and security group the
# global database goes in, its inter-cell namespace's zone — is an output of
# `../environment/` (outputs.tf, *A cell's outputs*), which is why every cell
# is applied (at least in its `base` phase) before this stack.
# ---------------------------------------------------------------------------
data "terraform_remote_state" "cell" {
  for_each = local.aws_cells
  backend  = "s3"
  config = {
    region = var.state_region
    bucket = "${var.name}-terraform-state-${local.account_id}"
    key    = "environment/${var.environment}/${each.key}.tfstate"
  }
}

locals {
  cell = {
    for id, c in local.aws_cells : id => {
      region                      = c.region
      vpc_id                      = data.terraform_remote_state.cell[id].outputs.vpc_id
      vpc_cidr                    = data.terraform_remote_state.cell[id].outputs.vpc_cidr
      route_table_ids             = data.terraform_remote_state.cell[id].outputs.route_table_ids
      global_db_subnet_group      = data.terraform_remote_state.cell[id].outputs.global_db_subnet_group
      global_db_security_group_id = data.terraform_remote_state.cell[id].outputs.global_db_security_group_id
      intercell_zone_id           = data.terraform_remote_state.cell[id].outputs.intercell_zone_id
    }
  }
}
