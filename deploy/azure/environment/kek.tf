# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHERE THE NODES' KEY-ENCRYPTION KEY IS (#391), AS THE SERVICE IS TOLD IT.
#
# `kek_provider` (variables.tf) chooses, for every node of this environment
# or cell:
#
#   kms     STS_KEYS_KEK_PROVIDER=azure-keys — the foundation's RSA-3072 key
#           `kek-rsa` (../foundation/kek.tf argues the key, its rotation and
#           the one grant a node holds on it). The service wraps and unwraps
#           each data key IN the vault and never holds the KEK.
#   secret  STS_KEYS_KEK_PROVIDER=azure — the `kek` secret's 32 bytes, read
#           into the service at start (secrets.tf, ../global/secrets.tf).
#           What every environment did before #391.
#
# WHICH VAULT. A single-cell environment's key is in its own vault, the one
# its secrets are in. A multi-region environment's ONE key is in its global
# vault (`ms<env>g-<hash>`, in the global group), named identically by every
# cell — the service refuses a wrapped data key whose row names another
# vault or key, and the global tier's rows are read in every cell. The vault
# URI is spelt without Key Vault's trailing slash, as the service stores it.
#
# WHAT ELSE MOVES WITH IT. The service looks for a secret with no vault
# setting of its own in the KEK's vault. So with `kms`:
#   * the database password names THIS unit's vault itself
#     (STS_DATABASE_PASSWORD_VAULT) — set in both modes, so the rule does not
#     depend on the mode;
#   * in a cell, the global database password has no vault setting at all
#     and is read from the GLOBAL vault, where ../global/secrets.tf writes a
#     copy of `global-db-app-password` and where the foundation lets every
#     cell's nodes read secrets.
# The cell key (STS_CELL_KEK_*, cells.tf) stays a SECRET in the cell's vault:
# the service refuses a key management service for it.
#
# THE `kek` SECRET IS STILL GENERATED WITH `kms`, deliberately. It is what
# `kek_migrating_from_secret` names as the PREVIOUS key, so an environment
# can move to `kms` without losing what it holds; it keeps the stack's shape
# the same in both modes, so switching back is an apply rather than a
# rebuild of the secrets; and it is no weaker to have it there — a node's
# identity could read it either way (*The deployer*, deploy/azure/CLAUDE.md).
#
# THE MIGRATION, from `secret` to `kms` on an environment that holds data:
#   1. apply with kek_provider = "kms", kek_migrating_from_secret = true —
#      every node is replaced (a changed environment is a new scale set,
#      nodes.tf) and starts with the Key Vault key as the KEK and the `kek`
#      secret as STS_PREVIOUS_KEK_*, and re-wraps every data key it finds
#      under the old one;
#   2. once every node of every cell has started that way, apply with
#      kek_migrating_from_secret = false.
# Going back to `secret` is the same with the roles swapped, and is not
# built: there is no setting here that names the Key Vault key as previous.
# ---------------------------------------------------------------------------
locals {
  kek_kms = var.kek_provider == "kms"

  # ../foundation/kek.tf's name and global vault formula; keep them in step.
  kek_key_name = "kek-rsa"

  kek_vault_uri = local.multi && local.kek_kms ? trimsuffix(data.azurerm_key_vault.global_kek[0].vault_uri, "/") : local.vault_uri

  kek_environment = merge(
    local.kek_kms ? {
      STS_KEYS_KEK_PROVIDER = "azure-keys"
      STS_KEYS_KEK_VAULT    = local.kek_vault_uri
      STS_KEYS_KEK_REF      = local.kek_key_name
      } : {
      STS_KEYS_KEK_PROVIDER = "azure"
      STS_KEYS_KEK_VAULT    = local.vault_uri
      STS_KEYS_KEK_REF      = "kek"
    },
    # The secret the environment ran with until now — in a cell, the copy
    # the global stack wrote into THIS cell's vault (the same value in each).
    local.kek_kms && var.kek_migrating_from_secret ? {
      STS_PREVIOUS_KEK_PROVIDER = "azure"
      STS_PREVIOUS_KEK_VAULT    = local.vault_uri
      STS_PREVIOUS_KEK_REF      = "kek"
    } : {},
  )
}

# The global vault, found by name (../foundation/kek.tf's formula). Only a
# cell with `kms` reads it; the deployer's role on the global group reads a
# vault's metadata, and nothing here reads the key itself — the deployer
# holds nothing on keys.
data "azurerm_key_vault" "global_kek" {
  count               = local.multi && local.kek_kms ? 1 : 0
  name                = "ms${var.environment}g-${substr(sha1("${local.subscription_id}/${var.name}/${var.environment}/global"), 0, 4)}"
  resource_group_name = "${var.name}-${var.environment}-global"
}
