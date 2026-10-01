# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
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
#   krb5-krbtgt-password     (2026-09-18) the default realm's krbtgt password,
#                            as KRB5_KRBTGT_PASSWORD
#   krb5-service-password    (2026-09-18) the acceptor's service account
#                            password, as KRB5_SERVICE_PASSWORD
#
# **WITHOUT THE LAST TWO A PRODUCT KDC ISSUES NO TICKET AT ALL.** Product mode
# refuses to build `krbtgt/<realm>` or the `krb5.servicePrincipal` account
# while their passwords are the defaults the settings table publishes
# (`krbtgt-mock-password` is a golden ticket handed out in the README;
# kerberos/CLAUDE.md) — so testidp answered every `kinit` with "Server not
# found in Kerberos database" until these existed. Nobody types them: they
# only derive keys, so they are long and alphanumeric like the database
# passwords. Rotating one invalidates every ticket issued under it.
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

# The KDC's two long-term secrets (the header). Nobody types them.
resource "random_password" "krb5_krbtgt" {
  count   = local.bootstrap_secret ? 1 : 0
  length  = 40
  special = false
}

resource "random_password" "krb5_service" {
  count   = local.bootstrap_secret ? 1 : 0
  length  = 40
  special = false
}

# ---------------------------------------------------------------------------
# A CELL'S SECRETS ARE ITS OWN, AND FEWER (#98, 2026-09-28).
#
# In a cell, what must be THE SAME IN EVERY CELL is not made here but by the
# global/ stack, once, and replicated into every cell region under the global
# multi-region key: the key-encryption key every cell shares (`kek`, which is
# what STS_KEYS_KEK_* keep naming), the seeded management client's secret, and
# in product mode the bootstrap administrator's and the KDC's passwords — a
# value generated here per cell would be a different value in each, and the
# one the cluster seeded first would win in the global tier while the others
# were refused. What a cell keeps is what is ITS OWN:
#
#   db-app-password, db-master-password   the CELL database's two
#   cell-kek                              the cell's own key-encryption key
#                                         (STS_CELL_KEK_*), for its resident
#                                         and local tiers — sealed under the
#                                         cell's single-region key, and
#                                         REPLICATED NOWHERE: that is the
#                                         residency line (issue #98, §3)
#
# The random values of the single-cell secrets are still generated in a cell
# (they are resources without a `count`, and giving them one would move them
# in every single-cell state); nothing stores or reads them there.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# A SINGLE-CELL ENVIRONMENT RESTORED FROM A SNAPSHOT CARRIES ITS SECRETS IN
# (2026-09-30), exactly as global/secrets.tf does for a converted cell and for
# the same four values — that file argues each, and the two not carried
# (krb5-krbtgt-password, the database passwords). Read ONCE into
# `terraform_data.carryover` and kept (`ignore_changes`), so a later apply
# that names no carry-over, or runs after the secret was deleted, keeps the
# KEK the rows are sealed under; and REFUSED on an environment whose secrets
# were already generated without it, whose rows are sealed under those.
# ---------------------------------------------------------------------------
data "aws_secretsmanager_secret_version" "carryover" {
  count     = !local.multi && var.carryover_secret != "" ? 1 : 0
  secret_id = var.carryover_secret
}

locals {
  carried_keys = [
    "kek", "admin-api-client-secret", "bootstrap-admin-password",
    "krb5-service-password",
  ]
  carried_now = !local.multi && var.carryover_secret != "" ? {
    for k, v in jsondecode(data.aws_secretsmanager_secret_version.carryover[0].secret_string) :
    k => tostring(v) if contains(local.carried_keys, k)
  } : {}
}

resource "terraform_data" "carryover" {
  input = local.carried_now

  lifecycle {
    ignore_changes = [input]
    precondition {
      condition = local.multi || var.carryover_secret == "" || alltrue([
        for k in ["kek", "admin-api-client-secret"] :
        contains(nonsensitive(keys(local.carried_now)), k)
      ])
      error_message = "carryover_secret names a secret without `kek` and `admin-api-client-secret`."
    }
  }
}

locals {
  carried = terraform_data.carryover.output
}

resource "random_bytes" "cell_kek" {
  count  = local.multi ? 1 : 0
  length = 32
}

locals {
  # PRODUCT MODE ONLY — see the header. `dev` and `ci` are development, and a
  # new secret and a new environment variable there would be a new task
  # definition revision in the environments whose job is to be unchanged.
  product = var.sts_mode == "product"
  # ... and made HERE only in a single-cell environment; a cell's are global.
  bootstrap_secret = local.product && !local.multi

  secrets = local.multi ? {
    db-app-password    = random_password.db_app.result
    db-master-password = random_password.db_master.result
    cell-kek           = random_bytes.cell_kek[0].base64
    } : merge({
      kek                     = lookup(local.carried, "kek", random_bytes.kek.base64)
      db-app-password         = random_password.db_app.result
      db-master-password      = random_password.db_master.result
      admin-api-client-secret = lookup(local.carried, "admin-api-client-secret", random_password.admin_api_client_secret.result)
      }, local.bootstrap_secret ? {
      bootstrap-admin-password = lookup(local.carried, "bootstrap-admin-password", random_password.bootstrap_admin[0].result)
      krb5-krbtgt-password     = random_password.krb5_krbtgt[0].result
      krb5-service-password    = lookup(local.carried, "krb5-service-password", random_password.krb5_service[0].result)
  } : {})

  # THE SECRETS EVERY CELL SHARES, by name: this stack's own in a single-cell
  # environment, the global/ stack's replica in this region in a cell — empty
  # strings in a cell's `base` phase, when no node reads them.
  shared_secret_arns = {
    for k in [
      "kek", "admin-api-client-secret", "bootstrap-admin-password",
      "krb5-krbtgt-password", "krb5-service-password",
    ] :
    k => local.multi ? lookup(local.global_secret_arns, k, "") : try(aws_secretsmanager_secret.main[k].arn, "")
  }
}

resource "aws_secretsmanager_secret" "main" {
  for_each                = local.secrets
  name                    = "${local.secret_path}/${each.key}"
  description             = "mock-sts ${var.environment}: ${each.key}"
  kms_key_id              = local.kms_key_arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "main" {
  for_each      = local.secrets
  secret_id     = aws_secretsmanager_secret.main[each.key].id
  secret_string = each.value

  lifecycle {
    # A carry-over named on an environment that already generated its KEK
    # would replace the key every row is sealed under (the header above).
    precondition {
      condition     = local.multi || var.carryover_secret == "" || length(nonsensitive(keys(local.carried))) > 0
      error_message = "carryover_secret is set, but this environment's secrets were already generated without it; carrying values in now would replace the KEK its rows are sealed under. Destroy the environment first, or apply without TF_VAR_carryover_secret."
    }
  }
}
