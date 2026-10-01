# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE CUSTOMER-MANAGED KEY FOR THE PROJECT.
#
# It encrypts the Secrets Manager secrets (the key-encryption key, the database
# passwords, the admin API client secret), both RDS instances' storage and
# their automated backups, and the container log group.
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
