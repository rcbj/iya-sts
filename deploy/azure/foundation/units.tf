# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT EACH ENVIRONMENT — EACH CELL, IN A MULTI-REGION ONE — IS GIVEN (#96).
#
# GCP's identities.tf and tls_secrets.tf, and more, because Azure scopes the
# deployer by RESOURCE GROUP and a group has to exist before a role can be
# granted on it. Per unit (locals.tf: a single-cell environment, or a cell):
#
#   mock-sts-<unit>              the resource group — in the unit's region,
#                                the deployer's role granted on it and on
#                                nothing else it may write (iam_deployer.tf),
#                                and Azure Policy's *Allowed locations* on it
#                                holding it to that region (the region fence)
#   mock-sts-<unit>-nodes        the managed identity every node runs as
#   ms<env><cell>-<hash>         the Key Vault its secrets are kept in: the
#                                environment writes them, the nodes read them
#     tls                        with a public name: the ACME certificate and
#                                its key, written by node-a alone
#
# WHY THE VAULT IS HERE AND NOT IN THE ENVIRONMENT. A vault's name is global
# and a deleted vault keeps it, soft-deleted, for its retention period — so
# an environment that made its own vault on every build would find the name
# taken on the next. And the certificate must outlive the environment
# anyway, for GCP's reason: Let's Encrypt issues at most FIVE certificates a
# week for one set of names, and testidp is rebuilt more often than that.
# The environment's secrets come and go with it, INSIDE this vault
# (deploy/azure/environment/secrets.tf).
#
# WHY THE IDENTITY IS HERE: the deployer creates no identity and assigns no
# role (iam_deployer.tf), so everything a node may do is decided here, by an
# administrator — Key Vault Secrets User on its vault, AcrPull on the
# registry, and with a public name the TXT records of its zone and a new
# version of its certificate.
#
# ONE IDENTITY PER VM, as on GCP: every container on a node reaches the same
# instance metadata endpoint, so the service COULD read every secret in its
# vault, the database master password included. deploy/azure/CLAUDE.md
# records it with GCP's, as the place this is weaker than AWS.
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "unit" {
  for_each = local.units
  name     = "${var.name}-${each.key}"
  location = each.value.region
  tags = merge(local.common_tags, {
    Environment = each.value.env
    Cell        = each.value.cell
  })
}

resource "azurerm_user_assigned_identity" "nodes" {
  for_each            = local.units
  name                = "${var.name}-${each.key}-nodes"
  location            = each.value.region
  resource_group_name = azurerm_resource_group.unit[each.key].name
  tags                = azurerm_resource_group.unit[each.key].tags
}

resource "azurerm_key_vault" "unit" {
  for_each            = local.units
  name                = local.unit_vault_names[each.key]
  location            = each.value.region
  resource_group_name = azurerm_resource_group.unit[each.key].name
  tenant_id           = local.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true
  # The environment's secrets are DELETED with it and RECOVERED by the next
  # build under the same names (the provider's `recover_soft_deleted_secrets`,
  # ../environment/providers.tf); purge protection would only keep a
  # destroyed environment's database passwords readable for longer.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  public_network_access_enabled = true

  tags = azurerm_resource_group.unit[each.key].tags
}

# The administrator writes the certificate's placeholder below; nothing else
# of an environment's secrets is ever written by this stack.
resource "azurerm_role_assignment" "admin_unit_vault" {
  for_each             = local.units
  scope                = azurerm_key_vault.unit[each.key].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "time_sleep" "unit_vault_rbac" {
  depends_on      = [azurerm_role_assignment.admin_unit_vault]
  create_duration = "90s"
}

# ---------------------------------------------------------------------------
# THE CERTIFICATE'S SECRET, EMPTY UNTIL node-a FILLS IT.
#
# The KEY IS IN NO TERRAFORM STATE: this writes a placeholder that is not a
# PEM bundle — which deploy/azure/node-init/cert.sh reads as "not issued
# yet" — and ignores every later value, and the only writer of a real one is
# node-a. A secret must exist before a role can be scoped to it, which is
# why the placeholder is here at all.
# ---------------------------------------------------------------------------
locals {
  public_units = { for k, u in local.units : k => u if u.public_hostname != "" }
}

resource "azurerm_key_vault_secret" "tls" {
  for_each     = local.public_units
  name         = "tls"
  key_vault_id = azurerm_key_vault.unit[each.key].id
  value        = "not-issued"
  content_type = "application/x-pem-file"
  tags = {
    public-hostname = each.value.public_hostname
  }

  lifecycle {
    ignore_changes = [value, content_type, tags, expiration_date, not_before_date]
  }

  depends_on = [time_sleep.unit_vault_rbac]
}

# ---------------------------------------------------------------------------
# WHAT A NODE MAY DO, for the life of the unit.
# ---------------------------------------------------------------------------
resource "azurerm_role_assignment" "nodes_read_vault" {
  for_each             = local.units
  scope                = azurerm_key_vault.unit[each.key].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.nodes[each.key].principal_id
}

# A new version of the ONE secret, and disabling the ones it replaces —
# scoped to that secret, not the vault.
resource "azurerm_role_assignment" "nodes_write_tls" {
  for_each             = local.public_units
  scope                = azurerm_key_vault_secret.tls[each.key].resource_versionless_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.nodes[each.key].principal_id
}

resource "azurerm_role_assignment" "nodes_pull" {
  for_each             = local.units
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.nodes[each.key].principal_id
}

# The ACME DNS-01 challenge (deploy/azure/node-init/cert.sh): node-a writes
# `_acme-challenge.<name>` TXT records and removes them. A custom role that
# can touch TXT records only, on this one zone — narrower than GCP's
# dns.admin, which Azure's per-record-type actions make possible.
resource "azurerm_role_definition" "acme_txt" {
  name        = "${var.name} ACME DNS-01 TXT writer"
  scope       = "/subscriptions/${local.subscription_id}"
  description = "mock-sts (#96): write and remove TXT records in the public zone, for an ACME DNS-01 challenge. Nothing else."

  permissions {
    actions = [
      "Microsoft.Network/dnsZones/read",
      "Microsoft.Network/dnsZones/TXT/*",
    ]
    not_actions = []
  }

  assignable_scopes = ["/subscriptions/${local.subscription_id}"]
}

resource "azurerm_role_assignment" "nodes_acme" {
  for_each           = local.public_units
  scope              = azurerm_dns_zone.public.id
  role_definition_id = azurerm_role_definition.acme_txt.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.nodes[each.key].principal_id
}

# ---------------------------------------------------------------------------
# A MULTI-REGION ENVIRONMENT'S GLOBAL GROUP: the global tier's writer and
# replicas, and Traffic Manager (../global/). No identity and no vault of its
# own — the global secrets are written into every cell's vault, where that
# cell's nodes read them.
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "global" {
  for_each = local.global_groups
  name     = "${var.name}-${each.key}-global"
  location = each.value.region
  tags = merge(local.common_tags, {
    Environment = each.key
    Cell        = "global"
  })
}

# ---------------------------------------------------------------------------
# THE REGION FENCE: AWS's `OnlyUsWest2ForRegionalServices` Deny, as Azure
# Policy's built-in *Allowed locations* on each group. A unit's group admits
# its own region; a global group every region its environment's cells are
# in (the replicas live there). Resources whose location is `global` —
# Traffic Manager, a DNS record — are exempt by the definition itself.
# ---------------------------------------------------------------------------
data "azurerm_policy_definition" "allowed_locations" {
  display_name = "Allowed locations"
}

resource "azurerm_resource_group_policy_assignment" "unit_locations" {
  for_each             = local.units
  name                 = "${var.name}-${each.key}-locations"
  resource_group_id    = azurerm_resource_group.unit[each.key].id
  policy_definition_id = data.azurerm_policy_definition.allowed_locations.id
  description          = "mock-sts (#96): the region fence"
  parameters = jsonencode({
    listOfAllowedLocations = { value = [each.value.region] }
  })
}

resource "azurerm_resource_group_policy_assignment" "global_locations" {
  for_each             = local.global_groups
  name                 = "${var.name}-${each.key}-global-locations"
  resource_group_id    = azurerm_resource_group.global[each.key].id
  policy_definition_id = data.azurerm_policy_definition.allowed_locations.id
  description          = "mock-sts (#96): the region fence"
  parameters = jsonencode({
    listOfAllowedLocations = { value = each.value.regions }
  })
}
