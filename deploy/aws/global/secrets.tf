# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE GLOBAL SECRETS: MADE ONCE, IN THE PRIMARY CELL'S REGION, AND REPLICATED
# INTO EVERY OTHER CELL'S (issue #98, 2026-09-28).
#
#   kek                      the key-encryption key EVERY cell shares — what
#                            STS_KEYS_KEK_* name in every cell, the single-cell
#                            environment's `kek` become global (D8: one set of
#                            signing keys per realm, held in the global tier,
#                            sealed under this)
#   global-db-app-password   the global database's `sts_app` password
#                            (STS_GLOBAL_DATABASE_PASSWORD_*); the role is
#                            made on the writer by the primary cell's
#                            global-schema-init and reaches every replica by
#                            replication, so one password is right everywhere
#   admin-api-client-secret  the seeded management client's secret: an
#                            application, which is global (issue #98, §3)
#   bootstrap-admin-password, krb5-krbtgt-password, krb5-service-password
#                            product mode's three (../environment/secrets.tf):
#                            each is seeded ONCE into the global tier, so a
#                            value made per cell would be a different value in
#                            each, and all but the first cell's refused
# NOT REPLICATED:
#   global-db-master-password  the global database's master user's, which only
#                            the primary cell's global-schema-init uses, in
#                            this region
#
# A REPLICA IS THE SAME SECRET: the same name, value and ARN but for the
# region, sealed under the multi-region key's replica in its region, and read
# where the cell is — so a cell's nodes never cross a region to start, and
# still start when the primary region is the one that failed. Terraform
# writes the value once; Secrets Manager keeps the replicas in step.
#
# THE CELL KEY-ENCRYPTION KEYS ARE NOT HERE, AND THAT IS THE POINT: each
# cell's `cell-kek` is its own stack's, under its single-region cell key, and
# is replicated nowhere (issue #98, §3).
#
# Recovery window zero, as the cells' are: an environment is rebuilt, and a
# secret kept thirty days would stop the next apply making one of that name.
# The four product-mode-only values are made in development mode too — the
# cost is four secrets' storage, and a stack whose shape does not depend on
# the mode its cells run in is one fewer thing to keep in step.
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
# password policy (../environment/secrets.tf argues it).
resource "random_password" "bootstrap_admin" {
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#%*+-=?@^_~"
}

resource "random_password" "krb5_krbtgt" {
  length  = 40
  special = false
}

resource "random_password" "krb5_service" {
  length  = 40
  special = false
}

# The replication role's (#97). Made in every global stack so that turning a
# GCP cell on or off does not replace it; stored only in a multi-cloud one.
resource "random_password" "db_repl" {
  length  = 40
  special = false
}

data "aws_kms_key" "global" {
  key_id = "alias/${var.name}-global"
}

# ---------------------------------------------------------------------------
# A CONVERTED ENVIRONMENT'S SECRETS (#98, 2026-09-28): WHERE A VALUE MUST BE
# THE OLD ENVIRONMENT'S, NOT A NEW ONE.
#
# A cell restored from a single-region environment's snapshot
# (../environment/conversion.tf) holds rows that were written under that
# environment's secrets, and those secrets are DELETED with it
# (`recovery_window_in_days = 0`). So before it is destroyed,
# deploy/aws/convert-to-cells.sh copies the four whose values the restored
# rows depend on into one JSON secret, `iya-sts/carryover/<old env>`, and
# `carryover_secret` names it here. Each, and the code that makes it matter:
#
#   kek                       EVERY SEALED ROW — the signing keys and their
#                             generations, the CA's private keys, the krbtgt
#                             key (below), whatever else is sealed at rest —
#                             opens only under the key-encryption key it was
#                             sealed with, and a product node whose keys will
#                             not open does not start (common/keystore.js,
#                             common/secrets.js)
#   admin-api-client-secret   the seeded `sts-management-api` entry is
#                             written ONCE and never over an existing one
#                             (common/applications.js, the seed and
#                             regenerateClientSecret's STS-REG-0061), so the
#                             restored entry keeps the old secret; a new
#                             setting would be a value the token endpoint
#                             refuses and /admin-api unreachable
#   bootstrap-admin-password  read only where nobody in the realm holds a
#                             credential (config.js, admin.bootstrapPassword)
#                             — never, on a restored database — so it changes
#                             nothing in the service; it is carried so that
#                             the secret an operator reads still names the
#                             password the stored administrator has, rather
#                             than one nothing accepts
#   krb5-service-password     the acceptor's account keys are DERIVED from it
#                             at every start and a stored row may not
#                             override them (kerberos/krb5_principals.js,
#                             *A restored row does not get to override the
#                             settings*): a new value is a new key, and every
#                             service ticket and exported keytab for the SPN
#                             stops working
#
# NOT CARRIED, AND WHY:
#   krb5-krbtgt-password      product mode does not read it at all since #169
#                             (common/mode.js, derivesKrbtgtFromPassword): the
#                             krbtgt key is random and kept SEALED ON THE
#                             DIRECTORY ENTRY, so it travels in the snapshot
#                             under the carried KEK
#   the database passwords    new ones: schema-init ALTERs the restored
#                             `sts_app` role to the new cell's password, and
#                             the provider sets the new master password on
#                             the restored instance
#
# READ ONCE AND KEPT. The values are taken into `terraform_data.carryover`
# when the global stack is first applied and never re-read (`ignore_changes`),
# so a later apply without TF_CONVERT — or after the carry-over secret has
# been deleted — keeps them, instead of putting random values back in place
# of the KEK every row is sealed under. For the same reason a carry-over
# named on an environment whose secrets were ALREADY generated is REFUSED at
# plan rather than ignored: its rows were sealed under the generated KEK, and
# replacing that would lose them.
# ---------------------------------------------------------------------------
data "aws_secretsmanager_secret_version" "carryover" {
  count     = var.carryover_secret != "" ? 1 : 0
  secret_id = var.carryover_secret
}

locals {
  carried_keys = [
    "kek", "admin-api-client-secret", "bootstrap-admin-password",
    "krb5-service-password",
  ]
  carried_now = var.carryover_secret != "" ? {
    for k, v in jsondecode(data.aws_secretsmanager_secret_version.carryover[0].secret_string) :
    k => tostring(v) if contains(local.carried_keys, k)
  } : {}
}

resource "terraform_data" "carryover" {
  input = local.carried_now

  lifecycle {
    ignore_changes = [input]
    # The two without which the converted database cannot be used; the
    # other two are product mode's, and absent from a development one.
    precondition {
      condition = var.carryover_secret == "" || alltrue([
        for k in ["kek", "admin-api-client-secret"] :
        contains(nonsensitive(keys(local.carried_now)), k)
      ])
      error_message = "carryover_secret names a secret without `kek` and `admin-api-client-secret`; run deploy/aws/convert-to-cells.sh <from> <to> --carry-secrets again."
    }
  }
}

locals {
  carried = terraform_data.carryover.output

  replicated_secrets = merge({
    kek                      = lookup(local.carried, "kek", random_bytes.kek.base64)
    global-db-app-password   = random_password.db_app.result
    admin-api-client-secret  = lookup(local.carried, "admin-api-client-secret", random_password.admin_api_client_secret.result)
    bootstrap-admin-password = lookup(local.carried, "bootstrap-admin-password", random_password.bootstrap_admin.result)
    krb5-krbtgt-password     = random_password.krb5_krbtgt.result
    krb5-service-password    = lookup(local.carried, "krb5-service-password", random_password.krb5_service.result)
    }, local.multi_cloud ? {
    # THE REPLICATION ROLE'S PASSWORD (#97): what a GCP cell's subscription
    # connects to the writer with. Copied into GCP Secret Manager by
    # deploy/multicloud/gcp-global, like every other global value.
    global-db-repl-password = random_password.db_repl.result
  } : {})
}

resource "aws_secretsmanager_secret" "global" {
  for_each                = local.replicated_secrets
  name                    = "${local.secret_path}/${each.key}"
  description             = "iya-sts ${var.environment}: ${each.key} (global tier, replicated to every cell region)"
  kms_key_id              = data.aws_kms_key.global.arn
  recovery_window_in_days = 0

  dynamic "replica" {
    for_each = local.replica_cells
    content {
      region = replica.value.region
      # The alias is the same name in every region (foundation/modules/region).
      kms_key_id = "alias/${var.name}-global"
    }
  }
}

resource "aws_secretsmanager_secret_version" "global" {
  for_each      = local.replicated_secrets
  secret_id     = aws_secretsmanager_secret.global[each.key].id
  secret_string = each.value

  lifecycle {
    # A carry-over named on an environment that already has its own KEK (the
    # header, *Read once and kept*).
    precondition {
      condition     = var.carryover_secret == "" || length(nonsensitive(keys(local.carried))) > 0
      error_message = "carryover_secret is set, but this environment's global secrets were already generated without it; carrying values in now would replace the KEK its rows are sealed under. Destroy the environment first, or apply without TF_CONVERT."
    }
  }
}

resource "aws_secretsmanager_secret" "db_master" {
  name                    = "${local.secret_path}/global-db-master-password"
  description             = "iya-sts ${var.environment}: the global database's master user (primary region only)"
  kms_key_id              = data.aws_kms_key.global.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id     = aws_secretsmanager_secret.db_master.id
  secret_string = random_password.db_master.result
}

locals {
  # Each global secret's ARN IN EACH CELL'S REGION: a replica's ARN is the
  # primary's with the region changed.
  secret_arns = {
    for id, c in local.aws_cells : id => {
      for k, s in aws_secretsmanager_secret.global :
      k => replace(s.arn, ":${local.primary_region}:", ":${c.region}:")
    }
  }
}
