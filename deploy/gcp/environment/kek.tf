# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHERE THE SERVICE'S KEY-ENCRYPTION KEY IS (#391): IN CLOUD KMS BY DEFAULT.
#
# Since #391 every value the service seals is sealed under a data encryption
# key (DEK), and every DEK is wrapped by the key-encryption key (KEK). Two
# places it can be here:
#
#   kms     (THE DEFAULT) the foundation's Cloud KMS key `<name>-kek`
#           (../foundation/kms.tf). STS_KEYS_KEK_PROVIDER=gcp-kms and
#           STS_KEYS_KEK_REF its resource name. THE KEY NEVER LEAVES THE KMS:
#           the node asks Cloud KMS to wrap and unwrap each DEK, once per DEK
#           at start, and no KEK bytes are ever in the process, a secret, the
#           state or a backup. Rotation is the key's own schedule.
#   secret  what #95 built: 32 random bytes in the Secret Manager secret
#           `kek` (secrets.tf), read INTO the process through
#           common/secrets.js's `gcp` provider. Anybody who can read that
#           secret — the node, the deployer, a project owner — holds the key
#           that unwraps everything.
#
# KMS IS THE DEFAULT because the project's rule is the most secure choice by
# default, and the weaker one only on request.
#
# THE NODE'S RIGHTS ON THE KEY ARE THE FOUNDATION'S GRANT, not this stack's:
# encrypt/decrypt and viewer (the service's getCryptoKey at start needs
# cloudkms.cryptoKeys.get, which the encrypter role lacks), on that one key,
# to every listed environment's node account — the deployer holds no IAM
# administration role and cannot make the grant here. A 403 on that key at
# start means the foundation predates #391: an administrator re-applies it.
#
# A GCP CELL OF A MULTI-CLOUD ENVIRONMENT (#97) MUST STAY ON `secret`, and
# the validation below refuses anything else: a cell's KEK is the GLOBAL one,
# made by AWS and shared by every cell on both clouds
# (deploy/multicloud/gcp-global). The service stores the KEK's name in every
# wrapped DEK and refuses a row whose name differs, so all cells must name
# the same KEK — and an AWS cell cannot use a Cloud KMS key.
# deploy/multicloud/envs/<env>.gcp.tfvars says so explicitly. (The CELL KEK,
# STS_CELL_KEK_*, cannot be a KMS key at all — the service refuses one — and
# is a secret in every case, cells.tf.)
#
# MOVING AN ENVIRONMENT FROM `secret` TO `kms` (its database holds DEKs
# wrapped under the secret):
#
#   1. apply with  kek_provider = "kms"  kek_migrating_from_secret = true.
#      Every node starts with the KMS key as its KEK and the secret as
#      STS_PREVIOUS_KEK_*, and re-wraps every DEK under the KMS key.
#   2. let EVERY node start that way (the groups replace their instances on
#      the new template; wait for all three to be healthy).
#   3. apply with  kek_migrating_from_secret = false. The node no longer
#      reads the secret, and loses its right to.
#
# An environment that is BUILT on `kms` — every new one — needs neither step.
#
# THE `kek` SECRET IS STILL GENERATED ON `kms` (secrets.tf): step 1 reads it,
# and a database backup taken before the migration holds DEKs wrapped under
# it, so restoring one needs it. Only the node's RIGHT to read it is
# withdrawn while it is not the KEK or the previous KEK.
# ---------------------------------------------------------------------------
variable "kek_provider" {
  description = "Where the key-encryption key is: `kms` (the default — the foundation's Cloud KMS key, which never leaves it) or `secret` (32 bytes in the Secret Manager secret `kek`, read into the process). A GCP cell of a multi-cloud environment must be `secret`. See kek.tf."
  type        = string
  default     = "kms"
  validation {
    condition     = contains(["kms", "secret"], var.kek_provider)
    error_message = "kek_provider is kms or secret."
  }
  validation {
    condition     = var.kek_provider == "secret" || var.cell == ""
    error_message = "A GCP cell of a multi-cloud environment must set kek_provider = \"secret\": its KEK is the global one AWS made and every cell shares (kek.tf)."
  }
}

variable "kek_migrating_from_secret" {
  description = "With kek_provider = `kms`: also hand every node the Secret Manager `kek` as its PREVIOUS key-encryption key, so an environment that ran on `secret` re-wraps every data key under the KMS key at start. Apply true, let every node start, apply false (kek.tf)."
  type        = bool
  default     = false
  validation {
    condition     = !var.kek_migrating_from_secret || var.kek_provider == "kms"
    error_message = "kek_migrating_from_secret is a migration TO kms: it needs kek_provider = \"kms\"."
  }
}

locals {
  kek_in_kms = var.kek_provider == "kms"

  # Whether the nodes read the `kek` secret at all: as the KEK, or as the
  # previous one during a migration. secrets.tf grants the read only then.
  nodes_read_secret_kek = !local.kek_in_kms || var.kek_migrating_from_secret

  # What every node is told about its KEK — merged into node_environment
  # (nodes.tf), so all three nodes agree by construction.
  kek_environment = merge(
    local.kek_in_kms ? {
      STS_KEYS_KEK_PROVIDER = "gcp-kms"
      STS_KEYS_KEK_REF      = data.google_kms_crypto_key.kek[0].id
      } : {
      STS_KEYS_KEK_PROVIDER = "gcp"
      STS_KEYS_KEK_REF      = local.shared_secret_names["kek"]
    },
    local.kek_in_kms && var.kek_migrating_from_secret ? {
      STS_PREVIOUS_KEK_PROVIDER = "gcp"
      STS_PREVIOUS_KEK_REF      = local.secret_names["kek"]
    } : {},
  )
}

# The foundation's key, found by name in the home ring. Only on `kms`, so an
# environment on `secret` applies against a foundation that predates #391.
# The ring is `main`'s lookup: a `kms` environment is never a cell (the
# validation above), so its region is the home region.
data "google_kms_crypto_key" "kek" {
  count    = local.kek_in_kms ? 1 : 0
  name     = "${var.name}-kek"
  key_ring = data.google_kms_key_ring.main.id
}
