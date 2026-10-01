# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# azure.iyasec.io DELEGATED FROM ROUTE 53 (#96) — deploy/gcp/dns-delegation/
# for the Azure zone.
#
# AWS manages the iyasec.io public zone and always will. This stack writes ONE
# record into it — `azure.iyasec.io NS <Azure DNS's four name servers>` —
# read from the Azure foundation's zone, so the two cannot disagree.
#
# Applied ONCE, by an administrator holding BOTH clouds' credentials, after
# the Azure foundation: neither cloud's deployer may write it (GCP's
# argument). Re-applied only if the Azure zone is ever re-created, which
# changes its name servers.
#
# STATE IN THE AZURE STATE ACCOUNT, beside the foundation's:
#   terraform -chdir=deploy/azure/dns-delegation init \
#     -backend-config=storage_account_name=<account> \
#     -backend-config=resource_group_name=iya-sts-terraform-state
#   terraform -chdir=deploy/azure/dns-delegation apply -var subscription_id=<id>
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.50"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "azurerm" {
    container_name   = "tfstate"
    key              = "dns-delegation.tfstate"
    use_azuread_auth = true
  }
}
