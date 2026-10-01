# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE KEY-ENCRYPTION KEY: A KEY IN KMS BY DEFAULT, A SECRET IF ASKED (#391,
# 2026-10-01).
#
# Since #391 every value the service seals is sealed under a data encryption
# key (DEK), and only the DEKs are wrapped by the key-encryption key (KEK).
# Where the KEK lives is `kek_provider`:
#
#   kms     (THE DEFAULT) foundation/kms.tf's `alias/mock-sts-kek`, a
#           multi-region key with a replica in every permitted region. The
#           node calls kms:Encrypt and kms:Decrypt on it for each DEK, with
#           the DEK's id, scope, realm and class as the encryption context;
#           the key material never leaves KMS — not into a secret, a task
#           definition, the Terraform state or a log.
#             STS_KEYS_KEK_PROVIDER = aws-kms
#             STS_KEYS_KEK_REF      = the key's ID, mrk-…
#             STS_KEYS_KEK_REGION   = THIS node's region
#   secret  the arrangement before #391: 32 random bytes in Secrets Manager
#           (`mock-sts/<env>/kek`, or global/'s replica in a cell), read by
#           the node at start and held in its memory.
#             STS_KEYS_KEK_PROVIDER = aws
#             STS_KEYS_KEK_REF      = the secret's ARN
#             STS_KEYS_KEK_REGION   = this node's region
#
# KMS IS THE DEFAULT BECAUSE IT IS THE MORE SECURE OF THE TWO, which is the
# project's rule for a default. A secret KEK is a value any holder of
# GetSecretValue and the project key can copy out and use anywhere, for ever;
# a KMS KEK can be used only by a principal KMS lets call it, only while it
# may, and every call is in CloudTrail.
#
# THE REFERENCE IS THE KEY'S ID, NEVER A REGIONAL ARN OR THE ALIAS. The
# service writes the reference into every wrapped DEK row and refuses to
# unwrap a row whose reference is not the one it is configured with, so every
# node of every cell must be given the SAME string. A multi-region key's ID is
# the same in the primary's region and in every replica's; its ARN and the
# alias's ARN name a region. Each node pairs the one ID with its OWN region,
# so a cell wraps and unwraps against the replica beside it and keeps doing
# so when the home region is down.
#
# MIGRATING AN ENVIRONMENT THAT RAN WITH "secret" (`kek_migrating_from_secret`):
# its DEK rows are wrapped under the secret, and a node told only about the
# KMS key cannot open them. So the migration is two applies:
#
#   1. kek_provider = "kms", kek_migrating_from_secret = true. Every node is
#      ALSO given the secret as the PREVIOUS KEK (STS_PREVIOUS_KEK_*), and at
#      start re-wraps every DEK it can open only under the previous key
#      under the KMS key and writes it back (common/keystore.js). Let EVERY
#      node of EVERY cell start this way — each node service at steady state.
#   2. kek_migrating_from_secret = false. The previous KEK is gone from the
#      task definition and the secret from the task role's reach.
#
# Skipping step 1 is a service that does not start on its own rows; leaving
# step 2 out keeps a copy of the old KEK readable by every node for nothing.
#
# THE `kek` SECRET IS STILL MADE IN BOTH MODES (secrets.tf, global/secrets.tf).
# The migration above reads it, and the carry-over of a converted
# environment (convert-to-cells.sh, `carryover_secret`) requires `kek` and
# validates on it — a converted environment must carry the KEK its rows
# were sealed under, whichever provider it runs with now. A secret nothing
# reads costs $0.40 a month, and the task role cannot read it unless the
# environment is "secret" or migrating (iam.tf).
#
# THERE IS NO WAY BACK BUILT IN. "kms" to "secret" would need the KMS key as
# the previous KEK, which this stack does not offer: a DEK wrapped in KMS is
# opened only by KMS, and the key is long-lived precisely so that one is
# never stranded.
#
# THE CELL KEK (STS_CELL_KEK_*, cells.tf) IS UNCHANGED, AND MUST BE: the
# service refuses a key management service for any secret but the KEK and
# the previous KEK, so a cell's own key stays a Secrets Manager secret under
# the cell's single-region key.
#
# AND A MULTI-CLOUD ENVIRONMENT IS "secret" (#97): its GCP cells read the
# global KEK from Secret Manager (deploy/multicloud/gcp-global), and a KMS
# key in AWS would need AWS credentials on every GCP node. Since the
# reference must be the same in every cell, the AWS cells cannot differ —
# the validation below refuses "kms" with a cell whose cloud is not aws.
#
# THE IMAGE NEEDS `@aws-sdk/client-kms` in STS_CLOUD_SDKS for "kms", or the
# node refuses to start naming the package (the workflows and run-tests.sh
# build it in).
# ---------------------------------------------------------------------------
variable "kek_provider" {
  description = <<-EOT
    Where the key-encryption key lives (#391): `kms` (the default) — the
    foundation's multi-region `alias/<name>-kek`, named to every node by its
    key ID with the node's own region — or `secret`, 32 random bytes in
    Secrets Manager as before #391. A multi-cloud environment must be
    `secret`. kek.tf argues both.
  EOT
  type        = string
  default     = "kms"
  validation {
    condition     = contains(["kms", "secret"], var.kek_provider)
    error_message = "kek_provider is kms or secret."
  }
  validation {
    condition     = var.kek_provider == "secret" || alltrue([for c in values(var.cells) : c.cloud == "aws"])
    error_message = "kek_provider must be \"secret\" in a multi-cloud environment: its GCP cells read the global KEK from Secret Manager, every cell must name the same KEK, and a GCP node cannot call AWS KMS (deploy/aws/environment/kek.tf)."
  }
}

variable "kek_migrating_from_secret" {
  description = <<-EOT
    With kek_provider = "kms": also hand every node the Secrets Manager `kek`
    secret as the PREVIOUS key-encryption key, so an environment that ran
    with "secret" re-wraps its data encryption keys under the KMS key at the
    next start. Apply once with it true, let every node of every cell start,
    then apply with it false (kek.tf).
  EOT
  type        = bool
  default     = false
  validation {
    condition     = !var.kek_migrating_from_secret || var.kek_provider == "kms"
    error_message = "kek_migrating_from_secret migrates TO a KMS key-encryption key; it needs kek_provider = \"kms\"."
  }
}

# The foundation's key, found by its alias — the primary in the home region,
# the replica in a cell's — and checked to be what the service will accept,
# so a plan stops here rather than a node at its first start. The service
# makes the same checks with kms:DescribeKey (common/secrets.js).
data "aws_kms_key" "kek" {
  count  = var.kek_provider == "kms" ? 1 : 0
  key_id = "alias/${var.name}-kek"

  lifecycle {
    postcondition {
      condition     = self.enabled && self.multi_region && self.key_usage == "ENCRYPT_DECRYPT" && self.customer_master_key_spec == "SYMMETRIC_DEFAULT"
      error_message = "alias/${var.name}-kek is not an enabled multi-region symmetric ENCRYPT_DECRYPT key. foundation/ makes it (kms.tf) and a replica in every permitted region; re-apply foundation/ first."
    }
  }
}

locals {
  kek_in_kms = var.kek_provider == "kms"

  # Whether a node reads the `kek` secret at all: as THE key with "secret",
  # as the PREVIOUS key while migrating. The task role's right to read it
  # follows this (iam.tf).
  kek_reads_secret = !local.kek_in_kms || var.kek_migrating_from_secret

  # The key's ID, identical in every region: the reference every node of
  # every cell is given.
  kek_key_id = local.kek_in_kms ? data.aws_kms_key.kek[0].id : ""

  # The key in EVERY region it exists in — the primary and each replica —
  # for the task role. A node calls the one in its own region; naming them
  # all keeps the policy the same in every cell and lets a node reach another
  # region's copy if it is ever pointed there. Nothing broader: no other key,
  # no wildcard.
  kek_key_arns = local.kek_in_kms ? distinct(concat(
    [for k in data.aws_kms_key.kek[0].multi_region_configuration[0].primary_key : k.arn],
    [for k in data.aws_kms_key.kek[0].multi_region_configuration[0].replica_keys : k.arn],
  )) : []

  # What every node is told (ecs.tf, `node_environment`; and so the
  # conversion task, conversion.tf). `shared_secret_arns["kek"]` is this
  # stack's secret in a single-cell environment and global/'s replica in this
  # region in a cell.
  kek_environment = merge(
    local.kek_in_kms ? {
      STS_KEYS_KEK_PROVIDER = "aws-kms"
      STS_KEYS_KEK_REF      = local.kek_key_id
      STS_KEYS_KEK_REGION   = local.region
      } : {
      STS_KEYS_KEK_PROVIDER = "aws"
      STS_KEYS_KEK_REF      = local.shared_secret_arns["kek"]
      STS_KEYS_KEK_REGION   = local.region
    },
    local.kek_in_kms && var.kek_migrating_from_secret ? {
      STS_PREVIOUS_KEK_PROVIDER = "aws"
      STS_PREVIOUS_KEK_REF      = local.shared_secret_arns["kek"]
      STS_PREVIOUS_KEK_REGION   = local.region
    } : {},
  )
}
