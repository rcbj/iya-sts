# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE CUSTOMER-MANAGED KEY FOR THE PROJECT.
#
# It encrypts the Secrets Manager secrets (the database passwords, the admin
# API client secret, and the key-encryption key's secret — which since #391
# is the KEK only in an environment with `kek_provider = "secret"`; by
# default the KEK is the `kek` key below, in KMS), both RDS instances' storage
# and their automated backups, and the container log group.
#
# LONG-LIVED ON PURPOSE. A key created per environment would enter a seven-day
# pending-deletion window on every teardown, and a CI job that runs daily would
# keep a week of them. One key, $1 a month.
#
# The key policy delegates to IAM (the account statement) and adds the one
# service principal that cannot be granted through IAM: CloudWatch Logs.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid = "CloudWatchLogsEncryptsTheContainerLogGroup"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["${local.arn.logs}:/${var.name}/*"]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "iya-sts (issue #51): secrets, RDS storage and backups, container logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.main.key_id
}

# ---------------------------------------------------------------------------
# THE GLOBAL KEY: MULTI-REGION, PRIMARY HERE, A REPLICA IN EVERY PERMITTED
# REGION (#98, 2026-09-28).
#
# What it encrypts is what EVERY cell must be able to read: the global
# key-encryption key and the other global secrets (the multi-cell
# environment's `global/` stack replicates each to every cell region), the
# global-tier database's storage and its cross-region read replicas, and the
# replicas of the image repository. A secret or an RDS replica in another
# region must be encrypted by a key IN that region, and a multi-region replica
# is the same key material under the same key id — so a replica secret is the
# same secret, decryptable by the same key, where a per-region key would be a
# re-encryption at every hop.
#
# NOT THE PROJECT KEY ABOVE, which cannot be made multi-region after creation
# and which keeps everything a single-cell environment already uses.
#
# AND NOT A CELL'S OWN DATA. A cell's key-encryption key and its database are
# sealed under its CELL key (modules/region), which is single-region and has
# no replica anywhere — that is the data-residency line (issue #98, §3): a copy
# of a cell's rows taken to another region cannot be read there.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "global_kms" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "global" {
  description             = "iya-sts (issue #98): the GLOBAL tier - global KEK and secrets, global database, image replicas; multi-region"
  multi_region            = true
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.global_kms.json
}

resource "aws_kms_alias" "global" {
  name          = "alias/${var.name}-global"
  target_key_id = aws_kms_key.global.key_id
}

# ---------------------------------------------------------------------------
# THE KEY-ENCRYPTION KEY, AS A KEY THAT NEVER LEAVES KMS (#391, 2026-10-01):
# MULTI-REGION, PRIMARY HERE, A REPLICA IN EVERY OTHER PERMITTED REGION.
#
# Since #391 every value the service seals is sealed under a data encryption
# key (DEK), and only the DEKs are wrapped by the key-encryption key (KEK).
# With an environment's `kek_provider = "kms"` (its default) the KEK is THIS
# key: a node calls kms:Encrypt and kms:Decrypt on it, with the DEK's identity
# as the encryption context, and the key material is never in a secret, a
# task, a state file or a log. `kek_provider = "secret"` keeps the old
# arrangement, 32 random bytes in Secrets Manager (../environment/secrets.tf).
#
# A KEY OF ITS OWN, NOT THE PROJECT KEY AND NOT THE GLOBAL KEY. Those two
# encrypt STORAGE on a service's behalf — Secrets Manager, RDS, CloudWatch
# Logs, EBS — and every grant on them is "through that service"
# (`kms:ViaService`). This one is called DIRECTLY by the container, so the
# right to call it is a different right, on a different principal, and it is
# granted on this key alone: a task that may wrap a DEK may not, by the same
# statement, decrypt a secret or a snapshot without going through the service
# that owns it. Its rotation, its policy and one day its deletion are
# decisions about the service's own data and nobody else's.
#
# MULTI-REGION BECAUSE THE SERVICE COMPARES THE REFERENCE. A wrapped DEK row
# records the KEK reference it was wrapped under, and the service refuses to
# unwrap a row whose reference is not the one configured (common/secrets.js,
# `aws-kms`). Every node of every cell must therefore be told the SAME string,
# and the one string that is valid in every region is a multi-region key's ID
# (`mrk-…`, identical in the primary and each replica). Each node names it
# with its OWN region in STS_KEYS_KEK_REGION, so a cell keeps unwrapping when
# the home region is the thing that failed. A regional ARN or an alias would
# be a different string in each region — never configure either.
#
# LONG-LIVED, for the project key's reason: a key per environment would sit
# thirty days in pending deletion after every teardown, and a KEK deleted is
# every row it ever wrapped lost. Shared by every environment in the account,
# as the project key is. What keeps one environment's DEKs from another's is
# what keeps its secrets apart under the project key: each lives in its own
# environment's database, and the encryption context binds a wrapped DEK to
# that DEK's own id, scope, realm and class.
#
# ROTATED BY AWS (`enable_key_rotation`), behind the one key ID: KMS keeps
# every backing key and decrypts with the one a ciphertext names, so nothing
# is asked of the service. ENCRYPT_DECRYPT and SYMMETRIC_DEFAULT, which the
# service checks with kms:DescribeKey at start and refuses otherwise.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "kek_kms" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "kek" {
  description              = "iya-sts (issue #391): the KEY-ENCRYPTION KEY - wraps the service's data encryption keys; multi-region, called directly by the nodes"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region             = true
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.kek_kms.json
}

resource "aws_kms_alias" "kek" {
  name          = "alias/${var.name}-kek"
  target_key_id = aws_kms_key.kek.key_id
}
