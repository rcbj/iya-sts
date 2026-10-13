# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# AWS's `Project = STS` and `Environment` tags, on every resource through the
# resource group's own (locals.tf, `tags`). On AWS the tag is also a fence
# the deployer is held to; here the resource group is
# (../foundation/iam_deployer.tf), and the tags are for the bill and a reader.
provider "azurerm" {
  subscription_id     = var.subscription_id
  storage_use_azuread = true

  # THE DEPLOYER REGISTERS NO RESOURCE PROVIDER: it holds no
  # subscription-level right, and the foundation's administrator registered
  # every one this stack uses. Left to its default the provider would try,
  # and fail, on every plan.
  resource_provider_registrations = "none"

  features {
    key_vault {
      # The vault is the foundation's; the SECRETS are this environment's and
      # go with it. A secret deleted by the last destroy is still in the vault,
      # soft-deleted, under the same name — so the next build RECOVERS it and
      # writes the new value as its next version, rather than failing on the
      # name. Nothing is purged from here (the deployer may not).
      purge_soft_deleted_secrets_on_destroy = false
      recover_soft_deleted_secrets          = true
    }
    resource_group {
      # The group is the foundation's; this stack never deletes it.
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}
