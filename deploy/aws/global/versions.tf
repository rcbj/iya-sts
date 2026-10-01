# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE GLOBAL TIER OF A MULTI-CELL ENVIRONMENT (issue #98, 2026-09-28).
#
# One per environment that has cells (`envs/<env>.cells.tfvars.json`), applied
# as the deployer role BETWEEN the cells' two phases (../environment/cells.tf):
#
#   1. each NEW cell, `base`   — its VPC, load balancer, cell database, the
#                                subnet group and security group the global
#                                database will use, its inter-cell namespace;
#                                no running node
#   2. THIS STACK              — reads every cell's state, and builds what
#                                joins them
#   3. every cell, `full`      — the nodes, told where the global tier is;
#                                the primary cell first, because its nodes
#                                apply the global schema
#
# and destroyed between the cells' dependent stacks and the cells themselves
# (entrypoint.sh does both orders).
#
# WHAT IT HOLDS:
#   * the GLOBAL DATABASE (D3): one writable PostgreSQL 18 primary in the
#     primary cell's VPC and one cross-region read replica in every other
#     cell's (database.tf, modules/replica);
#   * the GLOBAL SECRETS, made once and replicated into every cell region
#     under the multi-region key (secrets.tf): the key-encryption key every
#     cell shares, the global database's application password, and the
#     values that must be identical in every cell;
#   * the INTER-CELL NETWORK: a full mesh of inter-region VPC peerings with
#     their routes, and each cell's private inter-cell name made resolvable in
#     every other cell's VPC (peering.tf, modules/peering).
#
# The state key is `environment/<env>/global.tfstate`, under the one prefix
# the deployer may write state under:
#   terraform init -backend-config="bucket=mock-sts-terraform-state-<account>" \
#                  -backend-config="key=environment/testidpna/global.tfstate"
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # The STATE BUCKET's region — the home region — not a cell's.
  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
