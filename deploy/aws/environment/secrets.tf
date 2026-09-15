# ---------------------------------------------------------------------------
# FOUR SECRETS, GENERATED HERE AND ENCRYPTED WITH THE PROJECT KEY.
#
#   kek                      32 random bytes, base64 — the key-encryption key
#                            `common/secrets.js` reads (STS_KEYS_KEK_PROVIDER=aws)
#   db-app-password          the least-privilege `sts_app` role's password,
#                            read by the service (STS_DATABASE_PASSWORD_PROVIDER=aws)
#                            and set on the role by the schema-init container
#   db-master-password       the RDS master user's, used by schema-init only
#   admin-api-client-secret  the seeded `sts-management-api` client's secret,
#                            injected by ECS; the workflow mints its token with it
#
# EACH IS A PLAIN STRING, NOT JSON. `secrets.js` takes a non-JSON value whole,
# and a separate secret per value means the database password never "borrows"
# the key's location — the one arrangement that file refuses.
#
# RECOVERY WINDOW ZERO: a test environment is destroyed after an hour, and a
# secret kept for thirty days would stop the next apply of the same
# environment creating one with the same name.
#
# The values are in Terraform state, which is encrypted in a private bucket;
# that is the parent project's arrangement for the krb5 stack's passwords.
# ---------------------------------------------------------------------------
resource "random_bytes" "kek" {
  length = 32
}

# Letters and digits only: they travel through a URL, psql `-v` and an
# environment variable, and none of those should have to quote anything.
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

locals {
  secrets = {
    kek                     = random_bytes.kek.base64
    db-app-password         = random_password.db_app.result
    db-master-password      = random_password.db_master.result
    admin-api-client-secret = random_password.admin_api_client_secret.result
  }
}

resource "aws_secretsmanager_secret" "main" {
  for_each                = local.secrets
  name                    = "${local.secret_path}/${each.key}"
  description             = "mock-sts ${var.environment}: ${each.key}"
  kms_key_id              = data.aws_kms_key.main.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "main" {
  for_each      = local.secrets
  secret_id     = aws_secretsmanager_secret.main[each.key].id
  secret_string = each.value
}
