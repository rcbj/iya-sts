# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE KEY-ENCRYPTION KEY AS A KEY VAULT KEY THAT NEVER LEAVES THE VAULT
# (#391), for `kek_provider = "kms"` in ../environment/ — the default there.
#
# Since #391 the service seals every value under a data encryption key and
# wraps each data key under the KEK. With the `azure-keys` provider
# (common/secrets.js) the KEK is THIS key: the service calls getKey once at
# start and wrapKey / unwrapKey (RSA-OAEP-256) once per data key, through
# the node's managed identity, and never holds the KEK's bytes — which the
# `azure` provider and the `kek` SECRET did.
#
# WHY IT IS HERE AND NOT BESIDE THE `kek` SECRET. The secret is written by
# the environment stack (one region) or the global stack (several), as the
# deployer. The key cannot be: the deployer holds Secrets Officer on the
# vaults and nothing on their keys, and it assigns no role
# (iam_deployer.tf) — and a node is useless without a role on the key. So
# the administrator makes the key, and its one grant, here, as units.tf
# makes the `tls` placeholder and ITS one grant. It also means the key
# outlives every rebuild of the environment, which is harmless: the
# environment's database goes with each destroy, and the rotation policy
# adds a version a year.
#
# WHERE, AND WHY THERE:
#   a single-cell environment   in its own vault (units.tf), `kek-rsa`
#   a multi-region environment  in a vault of its own, `ms<env>g-<hash>`,
#                               in the global group (the primary cell's
#                               region), `kek-rsa` — ONE key for every cell
#
# ONE KEY FOR EVERY CELL, BECAUSE THE SERVICE ASKS IT. Every wrapped data
# key row carries `<vault>/keys/<name>` and the key version, and a row
# naming another vault or name is refused — so every node of every cell must
# name the IDENTICAL vault URI and key name. The global tier's rows are read
# in every cell, so a key per cell vault would make each cell refuse the
# others' rows. A copy per vault is what the `kek` SECRET does
# (../global/secrets.tf); a key cannot be copied across regions at all.
#
# WHY A VAULT OF ITS OWN FOR IT, AND NOT THE PRIMARY CELL'S. The service
# reads the global database password (and any secret with no vault row of
# its own) from the KEY-ENCRYPTION KEY'S vault — `persistence.global
# DatabasePassword*` has no vault setting (common/secrets.js,
# GLOBAL_DATABASE_PASSWORD). In the primary cell's vault every other cell's
# nodes would need a read on a vault that also holds the primary's own
# database passwords and its `cell-kek`, which #98 forbids. So the
# environment's global vault holds the key and a copy of
# `global-db-app-password` (../global/secrets.tf) and nothing else, and
# every cell's nodes may read that vault's secrets. A
# `persistence.globalDatabasePasswordVault` row in the service would make
# the copy unnecessary.
#
# WHAT A MULTI-REGION ENVIRONMENT GIVES UP FOR IT. The `kek` secret is in
# every cell's vault, so a cell starts when the primary region is down; the
# key is in one region, so a starting node in any cell dials it. Key Vault's
# own failover to the paired region keeps wrap and unwrap working, read-only,
# once Microsoft fails it over — that is not instant, and it is the paired
# region (deploy/azure/CLAUDE.md, *The deployer*, lists the pairs). Nothing
# per request reaches the vault: a data key is unwrapped at start and kept.
#
# RSA-3072, AND WHAT IS STRONGER. A Standard-tier vault offers RSA and EC
# software keys only. The service refuses RSA below 3072 bits (~112-bit
# strength, under the AES-256 it would protect) and takes `wrapKey` and
# `unwrapKey` and nothing else; key_opts allows exactly those, so a node's
# role cannot sign or decrypt with it. **RSA IS NOT POST-QUANTUM**: a
# quantum adversary holding a wrapped data key row could recover the data
# key. An AES-256 `oct-HSM` key in a MANAGED HSM (or Key Vault Premium's
# oct-HSM, in preview as of 2026-10) is the stronger choice, and the service
# takes it too (A256GCM with the row's binding as AAD). Nothing here builds
# one — a Managed HSM is ~$3 an hour, per pool, for as long as it stands. To
# use an existing one, set in the environment's `extra_environment`:
#   STS_KEYS_KEK_PROVIDER = azure-keys
#   STS_KEYS_KEK_VAULT    = https://<hsm>.managedhsm.azure.net
#   STS_KEYS_KEK_REF      = <key name>
# and grant every node identity *Managed HSM Crypto User* on that key in the
# HSM's local RBAC, which this stack does not manage.
#
# ROTATION IS A POLICY, AND THE SERVICE FOLLOWS IT. A new version is made a
# year after the last (`time_after_creation`). The service names the version
# in every wrapped row, sees at its next start that a row's version is not
# the current one, and re-wraps it — so a rotation needs nothing else, as
# long as the OLD versions stay enabled until every node has restarted. A
# rotation disables nothing. Each version EXPIRES two years after it was
# made: one year past its successor, so the current version never expires
# while rotation works (an expired version refuses wrapKey, and a new data
# key would fail to wrap), and notice comes 30 days before. An EXPIRED
# version still unwraps — Key Vault allows decrypt and unwrap outside a
# key's validity window — so a node that has not restarted in a year is not
# locked out of its own rows; it re-wraps them when it does.
#
# DESTROY AND RE-CREATE. The vaults keep a deleted key for 7 days
# (soft-delete) and are NOT purge-protected (units.tf argues it). Removing
# an environment from `environments` deletes its key; the provider never
# purges (providers.tf), and a re-create within the 7 days RECOVERS the same
# key with every version, so rows wrapped under it still open. After the 7
# days it is purged, and a re-create is a NEW key: any row wrapped under the
# old one can never be opened again. That is acceptable only because the
# environment's database is destroyed with it; a deployment that keeps data
# across a foundation change should turn purge protection on first.
# ---------------------------------------------------------------------------
locals {
  # The key's name, repeated in ../environment/kek.tf. Not `kek`: keys and
  # secrets are separate collections in one vault, but a reader comparing
  # `az keyvault key show --name kek` with the secret would be misled.
  kek_key_name = "kek-rsa"

  # A MULTI-REGION ENVIRONMENT'S GLOBAL VAULT: the unit formula with `g` as
  # its cell (no cell id starts with `g`; Azure cells start with `z`).
  # Repeated in ../environment/kek.tf and ../global/main.tf.
  global_vault_names = {
    for e, g in local.global_groups :
    e => "ms${e}g-${substr(sha1("${local.subscription_id}/${var.name}/${e}/global"), 0, 4)}"
  }

  # WHO HOLDS A KEY: each single-cell unit, and each multi-region
  # environment. The vault ids are the two resources' below.
  kek_holders = merge(
    { for k, u in local.units : k => azurerm_key_vault.unit[k].id if u.cell == "" },
    { for e, g in local.global_groups : e => azurerm_key_vault.global[e].id },
  )

  # WHICH KEY EACH UNIT'S NODES WRAP WITH: its own, or its environment's.
  unit_kek_holder = {
    for k, u in local.units : k => u.cell == "" ? k : u.env
  }
}

resource "azurerm_key_vault" "global" {
  for_each            = local.global_groups
  name                = local.global_vault_names[each.key]
  location            = each.value.region
  resource_group_name = azurerm_resource_group.global[each.key].name
  tenant_id           = local.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true
  # units.tf's settings and its argument: the secret here is the
  # environment's and comes and goes with it.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  public_network_access_enabled = true

  tags = azurerm_resource_group.global[each.key].tags
}

# The administrator makes the key and its rotation policy: Crypto Officer,
# on each vault that holds one. Nothing else of a key is the
# administrator's.
resource "azurerm_role_assignment" "admin_kek_vault" {
  for_each             = local.kek_holders
  scope                = each.value
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "time_sleep" "kek_rbac" {
  depends_on      = [azurerm_role_assignment.admin_kek_vault]
  create_duration = "90s"
}

resource "azurerm_key_vault_key" "kek" {
  for_each     = local.kek_holders
  name         = local.kek_key_name
  key_vault_id = each.value
  key_type     = "RSA"
  key_size     = 3072
  # The two the service asks for, and nothing a node's role could otherwise
  # do with it (sign, decrypt, encrypt).
  key_opts = ["wrapKey", "unwrapKey"]

  rotation_policy {
    automatic {
      time_after_creation = "P1Y"
    }
    expire_after         = "P2Y"
    notify_before_expiry = "P30D"
  }

  tags = {
    Environment = each.key
    Purpose     = "key-encryption key (#391)"
  }

  depends_on = [time_sleep.kek_rbac]
}

# ---------------------------------------------------------------------------
# WHAT A NODE MAY DO WITH IT: *Key Vault Crypto User* SCOPED TO THE KEY, not
# the vault — every cell's nodes on their environment's one key.
#
# Crypto User is wider than the service needs, and it is said here rather
# than hidden. It carries keys/read, wrap and unwrap, which the service uses
# (and encrypt, decrypt, sign, verify, which key_opts refuses), and also
# keys/update — a node could DISABLE the key, an outage for every node, not
# a disclosure — and keys/backup, a blob only a vault in this subscription
# and geography can restore. It does NOT carry keyrotationpolicies/read, so
# /admin/secrets shows an error where the rotation policy would be; the key
# itself is reported. A custom role of read, wrap, unwrap and rotation
# policy read would be exact, and is the step to take if that matters.
# ---------------------------------------------------------------------------
resource "azurerm_role_assignment" "nodes_kek" {
  for_each             = local.units
  scope                = azurerm_key_vault_key.kek[local.unit_kek_holder[each.key]].resource_versionless_id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.nodes[each.key].principal_id
}

# A cell's nodes read the global vault's secrets: `global-db-app-password`,
# which the service looks for in the KEK's vault (the header argues it).
# The vault holds no other secret.
resource "azurerm_role_assignment" "nodes_read_global_vault" {
  for_each             = { for k, u in local.units : k => u if u.cell != "" }
  scope                = azurerm_key_vault.global[each.value.env].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.nodes[each.key].principal_id
}
