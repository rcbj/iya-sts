# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE SAME SECRETS AS AWS AND GCP, IN THE FOUNDATION'S VAULT FOR THIS
# ENVIRONMENT (deploy/aws/environment/secrets.tf argues each): four, and
# three more in product mode.
#
#   kek                      32 random bytes, base64 — the key-encryption
#                            key with kek_provider = "secret", read by the
#                            service itself through common/secrets.js's
#                            `azure` provider; with "kms" (the default) the
#                            KEK is a Key Vault KEY instead and this is only
#                            the PREVIOUS key a migration names (kek.tf
#                            argues why it is still made)
#   db-app-password          the `sts_app` role's — read by the service the
#                            same way, and set on the role by schema-init
#   db-master-password       the server's administrator's, schema-init only
#   admin-api-client-secret  the seeded management client's
#   bootstrap-admin-password, krb5-krbtgt-password, krb5-service-password
#                            product mode only, for AWS's reasons
#
# NAMED BY THEIR KEY ALONE (`kek`, not `iya-sts-dev-kek`): the vault is this
# environment's, so the name needs nothing else. Read the bootstrap password
# with
#   az keyvault secret show --vault-name <vault> --name bootstrap-admin-password --query value -o tsv
#
# THE VAULT IS THE FOUNDATION'S, THE SECRETS ARE THIS STACK'S. A destroy
# deletes them — soft-deleted, for the vault's seven days — and the next
# build RECOVERS each under its name and writes its new value as a new
# version (providers.tf); nothing is purged, and nothing of the last build
# is READ, because the new version is the current one.
#
# HOW THEY REACH A NODE (units/): the ones the service reads for itself are
# NAMED in its environment (STS_KEYS_KEK_REF or the key's name, kek.tf;
# STS_DATABASE_PASSWORD_REF; in a
# cell STS_CELL_KEK_REF and STS_GLOBAL_DATABASE_PASSWORD_REF), as on AWS; the
# rest are read by the `sts-secrets` unit into a file on a tmpfs that the
# containers take as `--env-file` — what ECS's `secrets` injection did. None
# is ever in the VM's model: custom data is readable by whoever can read the
# scale set.
# ---------------------------------------------------------------------------
resource "random_bytes" "kek" {
  count  = local.multi ? 0 : 1
  length = 32
}

resource "random_password" "db_app" {
  length  = 40
  special = false
}

resource "random_password" "admin_api_client_secret" {
  count   = local.multi ? 0 : 1
  length  = 48
  special = false
}

# A CELL'S OWN KEY-ENCRYPTION KEY (#98, AWS's `cell-kek`): its resident and
# local tiers, in its own region's vault and nowhere else.
resource "random_bytes" "cell_kek" {
  count  = local.multi ? 1 : 0
  length = 32
}

# A person types this one; the four minimums are the service's default
# password policy (AWS's comment argues the symbol set).
resource "random_password" "bootstrap_admin" {
  count            = local.product && !local.multi ? 1 : 0
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#%*+-=?@^_~"
}

resource "random_password" "krb5_krbtgt" {
  count   = local.product && !local.multi ? 1 : 0
  length  = 40
  special = false
}

resource "random_password" "krb5_service" {
  count   = local.product && !local.multi ? 1 : 0
  length  = 40
  special = false
}

locals {
  product = var.sts_mode == "product"

  # IN A CELL, only what is the cell's own: its database's two passwords and
  # its KEK. Every value the cells share — the global KEK, the management
  # client's secret, product mode's three passwords, the global database's —
  # the global/ stack writes into this same vault, under the names below,
  # so a node reads them the same way in either kind of environment.
  secrets = local.multi ? {
    db-app-password    = random_password.db_app.result
    db-master-password = random_password.db_master.result
    cell-kek           = random_bytes.cell_kek[0].base64
    } : merge({
      kek                     = random_bytes.kek[0].base64
      db-app-password         = random_password.db_app.result
      db-master-password      = random_password.db_master.result
      admin-api-client-secret = random_password.admin_api_client_secret[0].result
      }, local.product ? {
      bootstrap-admin-password = random_password.bootstrap_admin[0].result
      krb5-krbtgt-password     = random_password.krb5_krbtgt[0].result
      krb5-service-password    = random_password.krb5_service[0].result
  } : {})

  # What the `sts-secrets` unit puts in each env file (units/): the
  # container environment variable, and the secret it comes from. ECS's two
  # `secrets` lists, for the node and for schema-init. In a cell the shared
  # names are the global stack's — and product mode's three exist there
  # whatever the mode, AWS's global/ rule.
  node_secret_env = merge({
    ADMIN_API_CLIENT_SECRET = "admin-api-client-secret"
    }, local.product ? {
    STS_ADMIN_BOOTSTRAP_PASSWORD = "bootstrap-admin-password"
    KRB5_KRBTGT_PASSWORD         = "krb5-krbtgt-password"
    KRB5_SERVICE_PASSWORD        = "krb5-service-password"
  } : {})

  schema_secret_env = {
    PGPASSWORD          = "db-master-password"
    STS_DB_APP_PASSWORD = "db-app-password"
  }

  # THE PRIMARY CELL'S SECOND SCHEMA-INIT, AGAINST THE GLOBAL WRITER (AWS's
  # `global-schema-init`): the writer's administrator password, which the
  # global/ stack writes into the primary cell's vault only, and the global
  # application password its `sts_app` is given. The replicas take the
  # schema, the role and its password by replication.
  global_schema_secret_env = local.is_primary && local.full ? {
    PGPASSWORD          = "global-db-master-password"
    STS_DB_APP_PASSWORD = "global-db-app-password"
  } : {}
}

resource "azurerm_key_vault_secret" "main" {
  for_each     = local.secrets
  name         = each.key
  key_vault_id = data.azurerm_key_vault.unit.id
  value        = each.value
  content_type = "text/plain"
  tags = {
    Environment = var.environment
    Cell        = var.cell
  }
}
