# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

provider "azurerm" {
  subscription_id     = var.subscription_id
  storage_use_azuread = true

  # The deployer registers no resource provider (../environment/providers.tf).
  resource_provider_registrations = "none"

  features {
    resource_group {
      # The group is the foundation's; this stack never deletes it.
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}
