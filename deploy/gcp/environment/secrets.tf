# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE SAME SECRETS AS AWS, IN SECRET MANAGER (deploy/aws/environment/secrets.tf
# argues each): four, and three more in product mode.
#
#   kek                      32 random bytes, base64 — read by the service
#                            itself through common/secrets.js's `gcp` provider
#   db-app-password          the `sts_app` role's — read by the service the
#                            same way, and set on the role by schema-init
#   db-master-password       the master user's, schema-init only
#   admin-api-client-secret  the seeded management client's
#   bootstrap-admin-password, krb5-krbtgt-password, krb5-service-password
#                            product mode only, for AWS's reasons
#
# NAMED `mock-sts-<env>-<key>`: a secret id may not contain `/`, so AWS's
# `mock-sts/<env>/<key>` becomes this. Read the bootstrap password with
#   gcloud secrets versions access latest --secret=mock-sts-testidp-bootstrap-admin-password
#
# UNDER THE PROJECT KEY, in the environment's region only (user-managed
# replication with CMEK — AWS's single-region secrets). Deleted with the
# environment at once; Secret Manager has no recovery window to set to zero.
#
# HOW THEY REACH A NODE (units/): the two the service reads for itself are
# NAMED in its environment (STS_KEYS_KEK_REF, STS_DATABASE_PASSWORD_REF),
# as on AWS; the rest are read by the `sts-secrets` unit into a file on a
# tmpfs that the containers take as `--env-file` — what ECS's `secrets`
# injection did. None is ever in instance metadata, which anybody who can
# describe the instance can read.
# ---------------------------------------------------------------------------
resource "random_bytes" "kek" {
  length = 32
}

resource "random_password" "db_app" {
  length  = 40
  special = false
}

resource "random_password" "admin_api_client_secret" {
  length  = 48
  special = false
}

# A person types this one; the four minimums are the service's default
# password policy (AWS's comment argues the symbol set).
resource "random_password" "bootstrap_admin" {
  count            = local.product ? 1 : 0
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#%*+-=?@^_~"
}

resource "random_password" "krb5_krbtgt" {
  count   = local.product ? 1 : 0
  length  = 40
  special = false
}

resource "random_password" "krb5_service" {
  count   = local.product ? 1 : 0
  length  = 40
  special = false
}

locals {
  product = var.sts_mode == "product"

  secrets = merge({
    kek                     = random_bytes.kek.base64
    db-app-password         = random_password.db_app.result
    db-master-password      = random_password.db_master.result
    admin-api-client-secret = random_password.admin_api_client_secret.result
    }, local.product ? {
    bootstrap-admin-password = random_password.bootstrap_admin[0].result
    krb5-krbtgt-password     = random_password.krb5_krbtgt[0].result
    krb5-service-password    = random_password.krb5_service[0].result
  } : {})

  # A secret's resource name without a version: the `gcp` provider completes
  # it with /versions/latest.
  secret_names = { for k, s in google_secret_manager_secret.main : k => s.id }

  # What the `sts-secrets` unit puts in each env file (units/): the
  # container environment variable, and the secret it comes from. ECS's two
  # `secrets` lists, for the node and for schema-init.
  node_secret_env = merge({
    ADMIN_API_CLIENT_SECRET = local.secret_names["admin-api-client-secret"]
    }, local.product ? {
    STS_ADMIN_BOOTSTRAP_PASSWORD = local.secret_names["bootstrap-admin-password"]
    KRB5_KRBTGT_PASSWORD         = local.secret_names["krb5-krbtgt-password"]
    KRB5_SERVICE_PASSWORD        = local.secret_names["krb5-service-password"]
  } : {})

  schema_secret_env = {
    PGPASSWORD          = local.secret_names["db-master-password"]
    STS_DB_APP_PASSWORD = local.secret_names["db-app-password"]
  }
}

resource "google_secret_manager_secret" "main" {
  for_each  = local.secrets
  secret_id = "${local.secret_path}-${each.key}"

  labels = {
    environment = var.environment
  }

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = data.google_kms_crypto_key.main.id
        }
      }
    }
  }
}

resource "google_secret_manager_secret_version" "main" {
  for_each    = local.secrets
  secret      = google_secret_manager_secret.main[each.key].id
  secret_data = each.value
}

# THE NODES MAY READ EACH OF THIS ENVIRONMENT'S SECRETS, ONE BY ONE — and
# nothing else's; the foundation gave the account no project-wide secret
# role. (All of them, the master password included: deploy/gcp/CLAUDE.md,
# *One identity per VM*.)
resource "google_secret_manager_secret_iam_member" "nodes" {
  for_each  = local.secrets
  secret_id = google_secret_manager_secret.main[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = data.google_service_account.nodes.member
}
