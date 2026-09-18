# ---------------------------------------------------------------------------
# FOUR SECRETS, GENERATED HERE AND ENCRYPTED WITH THE PROJECT KEY — AND A
# FIFTH IN PRODUCT MODE.
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
# AND, IN PRODUCT MODE ONLY (2026-09-17):
#
#   bootstrap-admin-password the BOOTSTRAP ADMINISTRATOR'S PASSWORD — the only
#                            way into a fresh deployment, and the one an
#                            operator actually goes looking for
#
# **THE POINT OF THE FIFTH IS THAT IT IS NOT IN A LOG.** The service generates
# a bootstrap password and announces it ONCE (`common/credentials.ts`), which
# makes the log sensitive and the credential unrecoverable as soon as that
# line rolls off — and on a three-node cluster it is in whichever node's
# stream won the bootstrap claim. Generating it HERE instead and handing it to
# the nodes as `STS_ADMIN_BOOTSTRAP_PASSWORD` means it exists before the first
# node starts and can be read whenever it is wanted:
#
#   aws secretsmanager get-secret-value --region us-west-2 \
#     --secret-id mock-sts/testidp/bootstrap-admin-password \
#     --query SecretString --output text
#
# The service does not print a supplied password anywhere.
#
# IT MUST SATISFY THE PASSWORD POLICY, which the service holds a SUPPLIED
# password to (a generated one skips the rules that are about a person
# choosing): twelve characters, an uppercase letter, a digit and a symbol by
# default (`common/password_policy.ts`). Hence the four `min_*` below — a
# `special = false` value like the other three would be refused, and the
# refusal (`STS-AUTHN-0205`) is a service nobody can sign in to.
#
# PRODUCT MODE ONLY, because the bootstrap itself is: development mode accepts
# every password, so there is nothing to bootstrap and a secret holding one
# would say otherwise. `dev` and `ci` are development, so they get four
# secrets and the task definition they always had.
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

# A HUMAN TYPES THIS ONE, so the symbol set is the safe half: nothing a shell,
# a URL or a copy-and-paste out of a terminal can turn into something else,
# and no character a reader has to look twice at. The four minimums are the
# service's default password policy, stated here because a value this file
# generates and the service then refuses would be an environment nobody can
# sign in to, found at the end of a twenty-minute apply.
resource "random_password" "bootstrap_admin" {
  count            = local.bootstrap_secret ? 1 : 0
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#%*+-=?@^_~"
}

locals {
  # PRODUCT MODE ONLY — see the header. `dev` and `ci` are development, and a
  # new secret and a new environment variable there would be a new task
  # definition revision in the environments whose job is to be unchanged.
  bootstrap_secret = var.sts_mode == "product"

  secrets = merge({
    kek                     = random_bytes.kek.base64
    db-app-password         = random_password.db_app.result
    db-master-password      = random_password.db_master.result
    admin-api-client-secret = random_password.admin_api_client_secret.result
    }, local.bootstrap_secret ? {
    bootstrap-admin-password = random_password.bootstrap_admin[0].result
  } : {})
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
