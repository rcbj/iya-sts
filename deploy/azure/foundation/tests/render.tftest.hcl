# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#96): `terraform test` against MOCKED
# azurerm and time providers, so nothing is read from or made in Azure. It
# holds the units (every environment and every cell), the regions they need,
# the vault names' length, and the deployer's grants.
#
#   terraform -chdir=deploy/azure/foundation init -backend=false
#   terraform -chdir=deploy/azure/foundation test
# ---------------------------------------------------------------------------
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      subscription_id = "00000000-0000-0000-0000-000000000001"
      tenant_id       = "00000000-0000-0000-0000-000000000002"
      object_id       = "00000000-0000-0000-0000-000000000003"
    }
  }
  mock_data "azurerm_policy_definition" {
    defaults = {
      id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
    }
  }
  mock_data "azurerm_storage_account" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/mock-sts-terraform-state/providers/Microsoft.Storage/storageAccounts/mockststate"
    }
  }
  mock_resource "azurerm_resource_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg"
    }
  }
  mock_resource "azurerm_key_vault" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v"
    }
  }
  mock_resource "azurerm_key_vault_key" {
    defaults = {
      versionless_id          = "https://v.vault.azure.net/keys/k"
      resource_versionless_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/keys/k"
    }
  }
  mock_resource "azurerm_key_vault_secret" {
    defaults = {
      resource_versionless_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/secrets/tls"
    }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w"
    }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/i"
      principal_id = "00000000-0000-0000-0000-000000000009"
    }
  }
  mock_resource "azurerm_role_definition" {
    defaults = {
      role_definition_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-00000000000a"
    }
  }
  mock_resource "azurerm_dns_zone" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/dnsZones/azure.iyasec.io"
    }
  }
  mock_resource "azurerm_container_registry" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/r"
    }
  }
}

mock_provider "time" {}

run "every_unit" {
  variables {
    subscription_id        = "00000000-0000-0000-0000-000000000001"
    state_storage_account  = "mockststate0000000000000"
    deployer_principal_ids = ["00000000-0000-0000-0000-0000000000d1"]
  }
  assert {
    condition = jsonencode(sort(keys(local.units))) == jsonencode([
      "ci", "dev", "globalidp-zgwc", "globalidp-zsea", "globalidp-zwus2",
      "testidp", "testidpna-zcnc", "testidpna-zwus2",
    ])
    error_message = jsonencode(sort(keys(local.units)))
  }
  assert {
    condition     = jsonencode(sort(tolist(local.regions))) == jsonencode(["canadacentral", "germanywestcentral", "southeastasia", "westus2"])
    error_message = jsonencode(local.regions)
  }
  assert {
    condition     = alltrue([for n in values(local.unit_vault_names) : length(n) <= 24 && can(regex("^[a-z][a-z0-9-]+$", n))])
    error_message = jsonencode(local.unit_vault_names)
  }
  assert {
    condition     = local.units["testidpna-zcnc"].public_hostname == "na-idp.azure.iyasec.io" && jsonencode(local.units["globalidp-zsea"].alt_names) == jsonencode(["zsea.global-idp.azure.iyasec.io"])
    error_message = "a cell's name is its environment's, from the cells file, and its own beside it"
  }
  assert {
    condition     = length(azurerm_key_vault_secret.tls) == 6 && !contains(keys(azurerm_key_vault_secret.tls), "dev")
    error_message = jsonencode(keys(azurerm_key_vault_secret.tls))
  }
  assert {
    condition     = jsonencode(sort(keys(azurerm_resource_group.global))) == jsonencode(["globalidp", "testidpna"]) && azurerm_resource_group.global["globalidp"].location == "westus2"
    error_message = "a global group per multi-region environment, in its primary's region"
  }
  assert {
    condition     = length(azurerm_role_assignment.deployer_groups) == 10
    error_message = "the deployer's role on eight units and two global groups"
  }
  assert {
    condition     = jsonencode(sort(jsondecode(azurerm_resource_group_policy_assignment.global_locations["globalidp"].parameters).listOfAllowedLocations.value)) == jsonencode(["germanywestcentral", "southeastasia", "westus2"])
    error_message = "the global group admits every cell's region"
  }
  assert {
    condition     = jsonencode(sort(keys(azurerm_key_vault_key.kek))) == jsonencode(["ci", "dev", "globalidp", "testidp", "testidpna"])
    error_message = "a key-encryption key per single-cell environment and ONE per multi-region environment"
  }
  assert {
    condition = alltrue([
      for k in values(azurerm_key_vault_key.kek) :
      k.name == "kek-rsa" && k.key_type == "RSA" && k.key_size == 3072 && jsonencode(sort(k.key_opts)) == jsonencode(["unwrapKey", "wrapKey"])
    ])
    error_message = "RSA-3072, wrapKey and unwrapKey only"
  }
  assert {
    condition     = azurerm_key_vault_key.kek["testidp"].rotation_policy[0].automatic[0].time_after_creation == "P1Y" && azurerm_key_vault_key.kek["testidp"].rotation_policy[0].expire_after == "P2Y" && azurerm_key_vault_key.kek["testidp"].rotation_policy[0].notify_before_expiry == "P30D"
    error_message = "rotated yearly; a version expires a year after its successor"
  }
  assert {
    condition     = length(azurerm_role_assignment.nodes_kek) == 8 && alltrue([for a in values(azurerm_role_assignment.nodes_kek) : a.role_definition_name == "Key Vault Crypto User"])
    error_message = "every unit's nodes are Crypto Users"
  }
  assert {
    condition     = azurerm_role_assignment.nodes_kek["globalidp-zsea"].scope == azurerm_key_vault_key.kek["globalidp"].resource_versionless_id && azurerm_role_assignment.nodes_kek["testidp"].scope == azurerm_key_vault_key.kek["testidp"].resource_versionless_id && strcontains(azurerm_role_assignment.nodes_kek["testidp"].scope, "/keys/")
    error_message = "scoped to the KEY, a cell's to its environment's one key"
  }
  assert {
    condition     = local.unit_kek_holder["testidpna-zcnc"] == "testidpna" && local.unit_kek_holder["dev"] == "dev"
    error_message = jsonencode(local.unit_kek_holder)
  }
  assert {
    condition     = jsonencode(sort(keys(azurerm_key_vault.global))) == jsonencode(["globalidp", "testidpna"]) && azurerm_key_vault.global["globalidp"].location == "westus2" && alltrue([for n in values(local.global_vault_names) : length(n) <= 24 && can(regex("^[a-z][a-z0-9-]+$", n))])
    error_message = jsonencode(local.global_vault_names)
  }
  assert {
    condition     = length(azurerm_role_assignment.nodes_read_global_vault) == 5 && length(azurerm_role_assignment.deployer_global_vaults) == 2 && length(azurerm_role_assignment.admin_kek_vault) == 5
    error_message = "every cell reads its global vault; the deployer writes secrets in it; the administrator makes each key"
  }
}
