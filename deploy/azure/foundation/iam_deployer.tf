# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE DEPLOYER: WHAT deploy/azure/environment/ AND global/ ARE APPLIED AS
# (#96).
#
# AWS scopes its deployer by NAME, TAG and REGION and caps every role it
# makes with a permissions boundary; GCP fences by PROJECT and by making no
# identity. Azure's natural fence is the RESOURCE GROUP, and this is built on
# it:
#
#   1. A CUSTOM ROLE, `iya-sts deployer`, granted ONLY on the resource groups
#      units.tf made — one per environment or cell, and a multi-region
#      environment's global group. It can build networks, load balancers,
#      scale sets, PostgreSQL servers and Traffic Manager profiles there, and
#      nowhere else: there is no subscription-level grant.
#   2. NO IDENTITY AND NO ROLE ASSIGNMENT. The role holds no
#      `Microsoft.Authorization/*/write` and no identity `write`, so nothing
#      it builds can be given a right an administrator did not give here —
#      GCP's rule, and the job AWS's boundaries do. It may ATTACH the
#      identities made for it (`…/assign/action`), and read a vault, never
#      create or delete one.
#   3. THE REGION FENCE: *Allowed locations* on each group (units.tf).
#   4. RESOURCE-LEVEL GRANTS where the resource is shared: DNS Zone
#      Contributor on the one public zone, AcrPush on the registry, Secrets
#      Officer on each environment's vault (to write its secrets), Managed
#      Identity Operator on each region's PostgreSQL key identity, blob data
#      on the state container, and Reader on the foundation's groups so
#      that it can FIND what it attaches (a disk-encryption set, a data
#      collection rule).
#
# WHO HOLDS IT: `deployer_principal_ids`, preferably an Entra ID group. There
# is no deployer service principal and no secret: a person runs Terraform as
# themselves (az login), and the provider refreshes their token as it
# expires — so AWS's expired-session lock (deploy/aws/CLAUDE.md) cannot
# happen. A GitHub workflow would be a service principal with a federated
# credential in the same group; it is not built yet.
#
# A MISSING PERMISSION shows up as an AuthorizationFailed naming the action
# on plan or apply: add the action to the role below (the narrowest one that
# names it), and an administrator re-applies. The deployer cannot widen
# itself.
# ---------------------------------------------------------------------------
resource "azurerm_role_definition" "deployer" {
  name        = "${var.name} deployer"
  scope       = "/subscriptions/${local.subscription_id}"
  description = "iya-sts (#96): builds an environment inside the resource groups the foundation granted it. Makes no identity and assigns no role."

  permissions {
    actions = [
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Resources/deployments/*",
      "Microsoft.Authorization/*/read",
      "Microsoft.Network/*",
      "Microsoft.Compute/*",
      "Microsoft.DBforPostgreSQL/*",
      "Microsoft.Insights/dataCollectionRuleAssociations/*",
      "Microsoft.Insights/diagnosticSettings/*",
      "Microsoft.KeyVault/vaults/read",
      "Microsoft.ManagedIdentity/userAssignedIdentities/read",
      "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
    ]
    # What `Microsoft.Compute/*` and `Microsoft.Network/*` would otherwise
    # let it do that an environment never needs, and that would reach past
    # its own group: a disk-encryption set of its own (the foundation's are
    # the sealed ones), a DNS zone (the one public zone is granted below).
    not_actions = [
      "Microsoft.Compute/diskEncryptionSets/write",
      "Microsoft.Compute/diskEncryptionSets/delete",
      "Microsoft.Network/dnsZones/write",
      "Microsoft.Network/dnsZones/delete",
    ]
  }

  assignable_scopes = ["/subscriptions/${local.subscription_id}"]
}

locals {
  deployer_groups = merge(
    { for k, g in azurerm_resource_group.unit : "unit-${k}" => g.id },
    { for k, g in azurerm_resource_group.global : "global-${k}" => g.id },
  )

  deployer_group_grants = {
    for pair in setproduct(keys(local.deployer_groups), var.deployer_principal_ids) :
    "${pair[0]}-${pair[1]}" => { scope = local.deployer_groups[pair[0]], principal = pair[1] }
  }

  # Reader, to FIND what it attaches: the foundation's group (the registry,
  # the zone) and every region's (a disk-encryption set, a key identity, a
  # data collection rule, a key vault's metadata).
  reader_groups = merge(
    { foundation = azurerm_resource_group.foundation.id },
    { for r, m in module.region : "region-${r}" => m.resource_group_id },
  )

  deployer_reader_grants = {
    for pair in setproduct(keys(local.reader_groups), var.deployer_principal_ids) :
    "${pair[0]}-${pair[1]}" => { scope = local.reader_groups[pair[0]], principal = pair[1] }
  }

  deployer_vault_grants = {
    for pair in setproduct(keys(local.units), var.deployer_principal_ids) :
    "${pair[0]}-${pair[1]}" => { unit = pair[0], principal = pair[1] }
  }

  deployer_region_grants = {
    for pair in setproduct(tolist(local.regions), var.deployer_principal_ids) :
    "${pair[0]}-${pair[1]}" => { region = pair[0], principal = pair[1] }
  }
}

resource "azurerm_role_assignment" "deployer_groups" {
  for_each           = local.deployer_group_grants
  scope              = each.value.scope
  role_definition_id = azurerm_role_definition.deployer.role_definition_resource_id
  principal_id       = each.value.principal
}

resource "azurerm_role_assignment" "deployer_readers" {
  for_each             = local.deployer_reader_grants
  scope                = each.value.scope
  role_definition_name = "Reader"
  principal_id         = each.value.principal
}

# Each environment's secrets, written into the vault the foundation made.
resource "azurerm_role_assignment" "deployer_vaults" {
  for_each             = local.deployer_vault_grants
  scope                = azurerm_key_vault.unit[each.value.unit].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = each.value.principal
}

# A database's customer-managed key is read as the region's identity, which
# the deployer attaches to the server; and the key's metadata is read to
# name its version-less id.
resource "azurerm_role_assignment" "deployer_postgres_identity" {
  for_each             = local.deployer_region_grants
  scope                = module.region[each.value.region].postgres_identity_id
  role_definition_name = "Managed Identity Operator"
  principal_id         = each.value.principal
}

resource "azurerm_role_assignment" "deployer_key_reader" {
  for_each             = local.deployer_region_grants
  scope                = module.region[each.value.region].key_vault_id
  role_definition_name = "Key Vault Reader"
  principal_id         = each.value.principal
}

# The environments' A and CNAME records (and a global stack's Traffic
# Manager name), in the one zone.
resource "azurerm_role_assignment" "deployer_dns" {
  for_each             = toset(var.deployer_principal_ids)
  scope                = azurerm_dns_zone.public.id
  role_definition_name = "DNS Zone Contributor"
  principal_id         = each.key
}

# Pushing the three images a build makes (deploy/azure/CLAUDE.md, *Running
# it by hand*) — AWS's deployer pushes to ECR the same way.
resource "azurerm_role_assignment" "deployer_push" {
  for_each             = toset(var.deployer_principal_ids)
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPush"
  principal_id         = each.key
}

# Every environment's state, in the one container. Blob data rather than the
# account's keys: the backend runs with `use_azuread_auth`, and the account
# has shared-key access turned off (bootstrap-state.sh).
data "azurerm_storage_account" "state" {
  name                = var.state_storage_account
  resource_group_name = var.state_resource_group
}

resource "azurerm_role_assignment" "deployer_state" {
  for_each             = toset(var.deployer_principal_ids)
  scope                = "${data.azurerm_storage_account.state.id}/blobServices/default/containers/tfstate"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.key
}
