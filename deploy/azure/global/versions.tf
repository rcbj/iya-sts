# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A MULTI-REGION ENVIRONMENT'S GLOBAL TIER AND WHAT JOINS ITS CELLS (#96) —
# deploy/aws/global/'s arrangement on Azure:
#
#   database.tf  the global PostgreSQL writer in the primary cell's region,
#                a cross-region read replica in every other cell's, each
#                with a private endpoint in its cell's VNet
#   peering.tf   a full mesh of global VNet peerings between the cells
#   secrets.tf   the values every cell shares, made once and written into
#                every cell's vault
#   routing.tf   the public name: Traffic Manager over the cells, and each
#                cell admitting every other's outbound address
#
# Applied by entrypoint.sh between the cells' `base` and `full` phases, and
# destroyed before them (deploy/azure/CLAUDE.md, *The apply order*). The
# state key is `environment/<env>/global.tfstate`, beside the cells'.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.50"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "azurerm" {
    container_name   = "tfstate"
    use_azuread_auth = true
  }
}
