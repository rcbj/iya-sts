# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# ONE PROVIDER FOR EVERY REGION: an Azure resource names its own `location`,
# so the regional parts (modules/region) are one `for_each` through it — the
# arrangement AWS reached with provider 6's per-resource `region` (#367).
provider "azurerm" {
  subscription_id     = var.subscription_id
  storage_use_azuread = true

  # The administrator registers the resource providers every stack needs,
  # once; the deployer holds no subscription-level right and registers
  # nothing (deploy/azure/environment/providers.tf).
  resource_provider_registrations = "extended"

  features {
    key_vault {
      # A vault here is LONG-LIVED and its name is global: a deleted one
      # keeps its name for its retention period, so it is recovered rather
      # than left to block a re-apply, and never purged by Terraform.
      purge_soft_delete_on_destroy          = false
      recover_soft_deleted_key_vaults       = true
      purge_soft_deleted_keys_on_destroy    = false
      purge_soft_deleted_secrets_on_destroy = false
      recover_soft_deleted_secrets          = true
    }
    resource_group {
      # An environment's group holds what the DEPLOYER made in it; deleting
      # the group from here while an environment stands would delete that
      # too, behind the environment's own state. Refused instead.
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}
