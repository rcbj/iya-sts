# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE THREE-NODE mock-sts ENVIRONMENT ON AZURE — OR ONE CELL OF A
# MULTI-REGION ONE — CREATED AND DESTROYED PER RUN (issue #96).
#
# deploy/gcp/environment/'s single-region pattern and deploy/aws/environment/'s
# cells, rebuilt out of Azure's parts. deploy/azure/CLAUDE.md maps each piece
# to AWS's and GCP's and argues every place they differ.
#
# Applied as the deployer — a person holding the foundation's custom role on
# this environment's resource group and nothing wider
# (../foundation/iam_deployer.tf) — never as an owner. The foundation must
# exist first, and must list this environment (its resource group, node
# identity and vault are made there).
#
# The state key names the environment, and the cell in a cell:
#   terraform init -backend-config=storage_account_name=<account> \
#                  -backend-config=resource_group_name=mock-sts-terraform-state \
#                  -backend-config=key=environment/dev.tfstate
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
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    container_name   = "tfstate"
    use_azuread_auth = true
  }
}
