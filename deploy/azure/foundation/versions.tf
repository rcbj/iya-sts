# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE LONG-LIVED AZURE FOUNDATION (issue #96), applied by an administrator.
#
# deploy/aws/foundation/'s and deploy/gcp/foundation/'s counterpart: what
# outlives every environment, and every identity and grant an environment
# runs with. State at `foundation.tfstate` in the storage account
# deploy/azure/bootstrap-state.sh made:
#   terraform init -backend-config=storage_account_name=<account> \
#                  -backend-config=resource_group_name=iya-sts-terraform-state
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.50"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  backend "azurerm" {
    container_name   = "tfstate"
    key              = "foundation.tfstate"
    use_azuread_auth = true
  }
}
