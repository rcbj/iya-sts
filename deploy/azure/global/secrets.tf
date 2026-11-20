# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE GLOBAL SECRETS: MADE ONCE, AND WRITTEN INTO EVERY CELL'S VAULT (#98;
# deploy/aws/global/secrets.tf argues each).
#
#   kek                      the key-encryption key EVERY cell shares — what
#                            STS_KEYS_KEK_* name in every cell with
#                            kek_provider = "secret". With "kms" (the
#                            default) the KEK is ONE Key Vault key in the
#                            global vault (../foundation/kek.tf) and this is
#                            only what a migration names as the previous key
#   global-db-app-password   the global database's `sts_app` password; the
#                            role is made on the writer by the primary
#                            cell's global schema-init and reaches every
#                            replica by replication
#   admin-api-client-secret  the seeded management client's secret: an
#                            application, which is global
#   bootstrap-admin-password, krb5-krbtgt-password, krb5-service-password
#                            product mode's three: each is seeded ONCE into
#                            the global tier, so one value in every cell.
#                            Made in development mode too (AWS's reason: a
#                            stack whose shape does not depend on the mode)
#   edge-secret              Front Door's origin secret (#1341,
#                            ../environment/frontdoor.tf): the primary cell's
#                            profile sends it and EVERY cell's nodes require
#                            it of an edge. Made whether or not the
#                            environment has Front Door, for that reason
# NOT IN EVERY CELL:
#   global-db-master-password  the writer's administrator's, in the PRIMARY
#                            cell's vault only — only its global schema-init
#                            uses it
#
# A COPY PER VAULT, NOT A REPLICA: Key Vault replicates nothing across
# regions that the deployer can name, so the value is written once per cell,
# from this state. Each copy is in its cell's region and read there, so a
# cell's nodes never cross a region to start, and still start when the
# primary region is the one that failed.
#
# AND ONE MORE COPY, IN THE ENVIRONMENT'S GLOBAL VAULT: `global-db-app-
# password`. The service reads the global database password from the
# key-encryption key's vault (it has no vault setting of its own), and with
# kek_provider = "kms" that is the global vault the key is in
# (../environment/kek.tf). Written in both modes, so this stack has no mode.
#
# THE CELL KEY-ENCRYPTION KEYS ARE NOT HERE, AND THAT IS THE POINT: each
# cell's `cell-kek` is its own stack's, in its own vault only (issue #98,
# section 3).
# ---------------------------------------------------------------------------
resource "random_bytes" "kek" {
  length = 32
}

resource "random_password" "db_app" {
  length  = 40
  special = false
}

resource "random_password" "db_master" {
  length  = 40
  special = false
}

resource "random_password" "admin_api_client_secret" {
  length  = 48
  special = false
}

# A person types this one; the four minimums are the service's default
# password policy (deploy/aws/environment/secrets.tf argues it).
resource "random_password" "bootstrap_admin" {
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#%*+-=?@^_~"
}

# THE BOOTSTRAP ADMINISTRATOR'S NAME (rcbj, 2026-11-10; AWS's secrets.tf
# argues it): product mode replaces a default name with one derived from a key
# in the database (#1447), which was then in one log line and nowhere else.
# Generated here, `admin-` and sixteen hex digits, stored beside the password
# and handed to the node as STS_ADMIN_BOOTSTRAP_USERNAME. Read once and kept
# (`ignore_changes`): the account is created once and cannot be renamed.
# TF_VAR_bootstrap_admin_username names an account that already exists, on
# the apply that first creates the secret.
resource "random_id" "bootstrap_admin_username" {
  count       = 1
  byte_length = 8
}

resource "terraform_data" "bootstrap_admin_username" {
  count = 1
  input = sensitive(trimspace(var.bootstrap_admin_username) != "" ? trimspace(var.bootstrap_admin_username) :
  "admin-${random_id.bootstrap_admin_username[0].hex}")

  lifecycle {
    ignore_changes = [input]
    precondition {
      condition     = !contains(["admin", "root", "sa", "administrator"], lower(trimspace(var.bootstrap_admin_username)))
      error_message = "bootstrap_admin_username is a default account name, which product mode replaces (common/bootstrap_name.ts); name the account the service actually created."
    }
  }
}

resource "random_password" "krb5_krbtgt" {
  length  = 40
  special = false
}

resource "random_password" "edge_secret" {
  length  = 48
  special = false
}

resource "random_password" "krb5_service" {
  length  = 40
  special = false
}

locals {
  global_secrets = {
    kek                      = random_bytes.kek.base64
    global-db-app-password   = random_password.db_app.result
    admin-api-client-secret  = random_password.admin_api_client_secret.result
    bootstrap-admin-password = random_password.bootstrap_admin.result
    bootstrap-admin-username = terraform_data.bootstrap_admin_username[0].output
    krb5-krbtgt-password     = random_password.krb5_krbtgt.result
    krb5-service-password    = random_password.krb5_service.result
    edge-secret              = random_password.edge_secret.result
  }

  secret_copies = merge(
    {
      for pair in setproduct(keys(var.cells), keys(local.global_secrets)) :
      "${pair[0]}-${pair[1]}" => { cell = pair[0], name = pair[1], value = local.global_secrets[pair[1]] }
    },
    {
      "${var.primary_cell}-global-db-master-password" = {
        cell  = var.primary_cell
        name  = "global-db-master-password"
        value = random_password.db_master.result
      }
    },
  )
}

resource "azurerm_key_vault_secret" "global" {
  for_each     = local.secret_copies
  name         = each.value.name
  key_vault_id = data.azurerm_key_vault.cell[each.value.cell].id
  value        = each.value.value
  content_type = "text/plain"
  tags = {
    Environment = var.environment
    Cell        = each.value.cell
    Tier        = "global"
  }
}

resource "azurerm_key_vault_secret" "global_vault" {
  name         = "global-db-app-password"
  key_vault_id = data.azurerm_key_vault.global.id
  value        = random_password.db_app.result
  content_type = "text/plain"
  tags = {
    Environment = var.environment
    Cell        = "global"
    Tier        = "global"
  }
}
