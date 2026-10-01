# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE PERMITTED REGION'S LONG-LIVED PARTS (#98, 2026-09-28): its cell key,
# and — outside the home region — a replica of the global key, a container
# log group and a replica of the image repository. ../../regions.tf argues
# why each is here; this file argues the details.
#
# No provider block, and no provider per region: every resource names
# `var.region` itself (AWS provider 6's per-resource `region`, #367), so the
# caller's one provider makes them all. Every name matches what the home
# region's resources are called, so an environment in any region finds them
# by the same lookup.
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "region" {
  description = "The region this instance is for; every resource here is made in it."
  type        = string
}

variable "cell" {
  description = "The cell this region holds: its id by the rule in ../../locals.tf (us-west-2 is usw2, ap-southeast-5 apse5)."
  type        = string
}

variable "common" {
  description = "What every region's instance shares, from ../../regions.tf."
  type = object({
    name                 = string
    home_region          = string
    account_id           = string
    partition            = string
    global_key_arn       = string
    log_retention_days   = number
    ecr_lifecycle_policy = string
  })
}

locals {
  home = var.region == var.common.home_region
  logs = "arn:${var.common.partition}:logs:${var.region}:${var.common.account_id}:log-group"
}

# ---------------------------------------------------------------------------
# THE CELL KEY: SINGLE-REGION, AND NEVER REPLICATED — ON PURPOSE.
#
# It seals what issue #98 calls a cell's RESIDENT and LOCAL tiers: the cell's
# own key-encryption key (the secret `iya-sts/<env>/<cell>/cell-kek`), the
# cell database's storage and backups, its secrets and each node's upload
# volume. A multi-region key would be the easier thing to reach for and the
# wrong one: its replicas can be made in any region by anyone allowed to, and
# the whole point here is that a copy of this cell's rows taken elsewhere
# cannot be decrypted there. `multi_region` is false, and a replica of this key
# cannot be created later — AWS refuses to replicate a single-region key.
#
# LONG-LIVED, like the project key, for the same reason: an environment is
# built and destroyed many times, and a key per build would leave a seven-day
# pending-deletion key behind every teardown. It is per REGION, not per
# environment, so every environment's cell in this region shares it; what an
# environment owns is the secret it seals.
#
# CloudWatch Logs is the one principal that cannot be granted through IAM; the
# region's container log group is encrypted with this key.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "cell" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${var.common.partition}:iam::${var.common.account_id}:root"]
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
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["${local.logs}:/${var.common.name}/*"]
    }
  }
}

resource "aws_kms_key" "cell" {
  region                  = var.region
  description             = "iya-sts cell ${var.cell} (issue #98): the cell KEK and resident data; single-region, never replicated"
  multi_region            = false
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.cell.json
}

resource "aws_kms_alias" "cell" {
  region        = var.region
  name          = "alias/${var.common.name}-cell-${var.cell}"
  target_key_id = aws_kms_key.cell.key_id
}

# ---------------------------------------------------------------------------
# THE GLOBAL KEY, REPLICATED HERE (not in the home region, which holds the
# primary). Same key material, same key id, a regional ARN — so a global
# secret replicated to this region and the global database's read replica
# here are encrypted by a key in this region, as AWS requires, without a
# second key to keep in step. Its alias is the primary's name.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "global" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${var.common.partition}:iam::${var.common.account_id}:root"]
    }
  }
}

resource "aws_kms_replica_key" "global" {
  count                   = local.home ? 0 : 1
  region                  = var.region
  description             = "iya-sts (issue #98): replica of the GLOBAL multi-region key"
  primary_key_arn         = var.common.global_key_arn
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.global.json
}

resource "aws_kms_alias" "global" {
  count         = local.home ? 0 : 1
  region        = var.region
  name          = "alias/${var.common.name}-global"
  target_key_id = aws_kms_replica_key.global[0].key_id
}

# ---------------------------------------------------------------------------
# THIS REGION'S CONTAINER LOG GROUP. A node's log is personal data as much as
# its database is (addresses, user agents, names in error lines), so a cell
# writes to a group in its own region, sealed under its own cell key. Same
# name as the home region's, so the environment stack looks it up the same
# way wherever it runs.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "containers" {
  region            = var.region
  count             = local.home ? 0 : 1
  name              = "/${var.common.name}/containers"
  retention_in_days = var.common.log_retention_days
  kms_key_id        = aws_kms_key.cell.arn
}

# ---------------------------------------------------------------------------
# THE IMAGE REPOSITORY'S REPLICA. Made here, before anything is replicated
# into it, so that it carries the home repository's lifecycle policy — a
# repository ECR creates for a replication has none, and would keep every
# image ever pushed.
#
# AES256, NOT A KMS KEY. ECR replicates through its own service-linked role,
# and a destination encrypted with a customer key needs that role granted on
# the key; the images are the public source tree built, not data, and the
# home repository's KMS encryption is kept for the one that is pushed to.
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "replica" {
  region               = var.region
  count                = local.home ? 0 : 1
  name                 = var.common.name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "replica" {
  region     = var.region
  count      = local.home ? 0 : 1
  repository = aws_ecr_repository.replica[0].name
  policy     = var.common.ecr_lifecycle_policy
}

output "cell_key_arn" {
  description = "This region's cell key (alias/<name>-cell-<cell>)."
  value       = aws_kms_key.cell.arn
}

output "global_replica_key_arn" {
  description = "The global key's replica here; empty in the home region, where the primary is."
  value       = local.home ? "" : aws_kms_replica_key.global[0].arn
}

output "log_group_arn" {
  description = "This region's container log group; empty in the home region (logs.tf's)."
  value       = local.home ? "" : aws_cloudwatch_log_group.containers[0].arn
}

output "ecr_repository_arn" {
  description = "This region's replica of the image repository; empty in the home region."
  value       = local.home ? "" : aws_ecr_repository.replica[0].arn
}
