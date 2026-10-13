# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT EVERY REGION AN ENVIRONMENT MAY BE IN NEEDS, AND OUTLIVES IT (#96).
#
# AWS's modules/region (a cell key, a global-key replica, a log group, a
# repository replica per permitted region) and GCP's regional key rings, in
# Azure's parts. One resource group per region, `iya-sts-<code>`, holding:
#
#   msk<code>-<hash>        a Key Vault for customer-managed KEYS only —
#                           purge protection on, which Azure requires of a
#                           vault a disk or a database is encrypted from
#     iya-sts              the key a single-cell environment and the
#                           global tier are sealed under (AWS's project key
#                           and `alias/iya-sts-global`)
#     iya-sts-cell         a cell's own data (AWS's `alias/iya-sts-cell-*`)
#   iya-sts-<code>         a disk-encryption set per key, for the nodes'
#   iya-sts-<code>-cell    disks
#   iya-sts-<code>-postgres  the identity a PostgreSQL server reads its key
#                           as (Flexible Server takes a user-assigned one)
#   iya-sts-<code>         a Log Analytics workspace and the data
#                           collection rule the nodes' agent sends syslog by
#
# **A KEY IS NEVER REPLICATED OUT OF ITS REGION**, and a cell's data is
# under its own region's `iya-sts-cell` key — issue #98's residency line.
# (The GLOBAL tier needs no multi-region key here, as it did on AWS: a
# cross-region read replica of Flexible Server is encrypted under a key in
# its own region, which is this module's `iya-sts` in that region.)
#
# LONG-LIVED, for the reasons AWS's and GCP's keys are: a key whose versions
# are gone makes every disk, database and backup under it unreadable, so it
# is `prevent_destroy`, and the vault's purge protection means a deleted key
# is recoverable for ninety days whatever anyone does.
#
# LOGS PER REGION, NOT ONE WORKSPACE: a log is personal data as much as a
# row is (deploy/aws/CLAUDE.md, *What is replicated*), and a data collection
# rule must be in its workspace's region.
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
    time = {
      source = "hashicorp/time"
    }
  }
}

variable "region" {
  description = "The Azure region (e.g. westus2)."
  type        = string
}

variable "code" {
  description = "The region's short code (e.g. wus2), from ../../locals.tf."
  type        = string
}

variable "name" {
  description = "The project prefix."
  type        = string
}

variable "subscription_id" {
  description = "The subscription, hashed into the vault's name."
  type        = string
}

variable "tenant_id" {
  description = "The Entra ID tenant the vault trusts."
  type        = string
}

variable "admin_object_id" {
  description = "Who is applying this: made a Crypto Officer on the vault, to create the keys."
  type        = string
}

variable "tags" {
  description = "Every resource's tags."
  type        = map(string)
}

variable "log_retention_days" {
  description = "The workspace's retention."
  type        = number
}

variable "key_rotation_days" {
  description = "Days after creation each key rotates."
  type        = number
}

locals {
  prefix     = "${var.name}-${var.code}"
  vault_name = "msk${var.code}-${substr(sha1("${var.subscription_id}/${var.name}/${var.region}"), 0, 6)}"
  keys = {
    main = "${var.name}"
    cell = "${var.name}-cell"
  }
}

resource "azurerm_resource_group" "region" {
  name     = local.prefix
  location = var.region
  tags     = var.tags
}

resource "azurerm_key_vault" "keys" {
  name                = local.vault_name
  location            = var.region
  resource_group_name = azurerm_resource_group.region.name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  # Reached from the internet with Entra ID credentials. Denying it by
  # default with the trusted-services bypass would suit the disks and the
  # databases, and would refuse the administrator's own key creation from a
  # laptop; deploy/azure/CLAUDE.md lists it as a hardening step.
  public_network_access_enabled = true

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_role_assignment" "admin_crypto_officer" {
  scope                = azurerm_key_vault.keys.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = var.admin_object_id
}

# A new role assignment takes up to a few minutes to be honoured by Key
# Vault's data plane; creating a key before then is a 403.
resource "time_sleep" "rbac" {
  depends_on      = [azurerm_role_assignment.admin_crypto_officer]
  create_duration = "90s"
}

resource "azurerm_key_vault_key" "keys" {
  for_each     = local.keys
  name         = each.value
  key_vault_id = azurerm_key_vault.keys.id
  key_type     = "RSA"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]

  rotation_policy {
    automatic {
      time_after_creation = "P${var.key_rotation_days}D"
    }
  }

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [time_sleep.rbac]
}

# THE NODES' DISKS: a set per key, rotated to the key's latest version by
# the platform. The set's own identity reads the key.
resource "azurerm_disk_encryption_set" "keys" {
  for_each                  = local.keys
  name                      = each.key == "main" ? local.prefix : "${local.prefix}-cell"
  location                  = var.region
  resource_group_name       = azurerm_resource_group.region.name
  key_vault_key_id          = azurerm_key_vault_key.keys[each.key].versionless_id
  auto_key_rotation_enabled = true
  encryption_type           = "EncryptionAtRestWithCustomerKey"

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

resource "azurerm_role_assignment" "disk_sets" {
  for_each             = local.keys
  scope                = azurerm_key_vault_key.keys[each.key].resource_versionless_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_disk_encryption_set.keys[each.key].identity[0].principal_id
}

# THE DATABASES' KEY READER: Flexible Server takes a USER-assigned identity
# for a customer-managed key, which the deployer attaches (it may not make
# one, ../../iam_deployer.tf).
resource "azurerm_user_assigned_identity" "postgres" {
  name                = "${local.prefix}-postgres"
  location            = var.region
  resource_group_name = azurerm_resource_group.region.name
  tags                = var.tags
}

resource "azurerm_role_assignment" "postgres" {
  for_each             = local.keys
  scope                = azurerm_key_vault_key.keys[each.key].resource_versionless_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_user_assigned_identity.postgres.principal_id
}

# ---------------------------------------------------------------------------
# THE CONTAINER LOGS: the nodes run the containers with Docker's journald
# driver, journald hands them to rsyslog, and the Azure Monitor agent sends
# rsyslog's `daemon` and `user` facilities here by this rule (the
# environment associates each node with it). AWS's log group, GCP's bucket.
# ---------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "logs" {
  name                = local.prefix
  location            = var.region
  resource_group_name = azurerm_resource_group.region.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

resource "azurerm_monitor_data_collection_rule" "syslog" {
  name                = "${local.prefix}-syslog"
  location            = var.region
  resource_group_name = azurerm_resource_group.region.name
  kind                = "Linux"
  description         = "iya-sts (#96): the nodes' container logs, by syslog, into the region's workspace"

  destinations {
    log_analytics {
      name                  = "workspace"
      workspace_resource_id = azurerm_log_analytics_workspace.logs.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["workspace"]
  }

  data_sources {
    syslog {
      name           = "containers"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["daemon", "user"]
      log_levels     = ["Debug", "Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
    }
  }

  tags = var.tags
}

output "resource_group" {
  description = "The region's resource group."
  value       = azurerm_resource_group.region.name
}

output "resource_group_id" {
  description = "The region's resource group's id."
  value       = azurerm_resource_group.region.id
}

output "key_vault_id" {
  description = "The key vault's id."
  value       = azurerm_key_vault.keys.id
}

output "key_ids" {
  description = "The two keys' versionless ids, by `main` and `cell`."
  value       = { for k, v in azurerm_key_vault_key.keys : k => v.versionless_id }
}

output "disk_encryption_set_ids" {
  description = "The two disk-encryption sets, by `main` and `cell`."
  value       = { for k, v in azurerm_disk_encryption_set.keys : k => v.id }
}

output "postgres_identity_id" {
  description = "The identity a database reads its key as."
  value       = azurerm_user_assigned_identity.postgres.id
}

output "workspace_id" {
  description = "The log workspace."
  value       = azurerm_log_analytics_workspace.logs.id
}

output "data_collection_rule_id" {
  description = "The syslog rule a node is associated with."
  value       = azurerm_monitor_data_collection_rule.syslog.id
}
