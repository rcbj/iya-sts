# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
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

data "aws_kms_key" "global" {
  key_id = "alias/${var.name}-global"
}

locals {
  replicated_secrets = {
    kek                      = random_bytes.kek.base64
    global-db-app-password   = random_password.db_app.result
    admin-api-client-secret  = random_password.admin_api_client_secret.result
    bootstrap-admin-password = random_password.bootstrap_admin.result
    krb5-krbtgt-password     = random_password.krb5_krbtgt.result
    krb5-service-password    = random_password.krb5_service.result
  }
}

resource "aws_secretsmanager_secret" "global" {
  for_each                = local.replicated_secrets
  name                    = "${local.secret_path}/${each.key}"
  description             = "mock-sts ${var.environment}: ${each.key} (global tier, replicated to every cell region)"
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
}

resource "aws_secretsmanager_secret" "db_master" {
  name                    = "${local.secret_path}/global-db-master-password"
  description             = "mock-sts ${var.environment}: the global database's master user (primary region only)"
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
    for id, c in var.cells : id => {
      for k, s in aws_secretsmanager_secret.global :
      k => replace(s.arn, ":${local.primary_region}:", ":${c.region}:")
    }
  }
}
