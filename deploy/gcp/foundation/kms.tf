# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE CUSTOMER-MANAGED KEY FOR THE PROJECT (deploy/aws/foundation/kms.tf).
#
# It encrypts every secret in Secret Manager, both Cloud SQL instances' disks
# and their backups, the nodes' boot and upload disks, the image repository
# and the container log bucket. (The service's own key-encryption key is a
# SECOND key in the same ring, `kek`, at the end of this file — #391.)
#
# LONG-LIVED, AND ON GCP MORE SO THAN ON AWS: a key ring can never be
# deleted, and a key only has its versions destroyed. One ring and one key for
# the project, never one per environment.
#
# THE KEY IS USED BY SERVICE AGENTS, NOT BY THE DEPLOYER. Each Google service
# that writes CMEK-encrypted data does it as its own agent account, which must
# hold roles/cloudkms.cryptoKeyEncrypterDecrypter on the key — AWS's key
# policy statement for CloudWatch Logs, five times. The deployer only NAMES
# the key in a resource and needs no right on it.
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "main" {
  name     = var.name
  location = var.region

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "main" {
  name            = var.name
  key_ring        = google_kms_key_ring.main.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  # A key whose versions were destroyed makes every secret, disk and backup
  # under it unreadable. Terraform refuses to plan that.
  lifecycle {
    prevent_destroy = true
  }
}

# The service agents, made to exist before they are granted anything: an
# agent is created lazily by its service, and a grant to one that does not
# exist yet fails.
resource "google_project_service_identity" "agents" {
  provider = google-beta
  for_each = toset([
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "sqladmin.googleapis.com",
  ])
  project = var.project_id
  service = each.key

  depends_on = [google_project_service.apis]
}

# Cloud Logging's agent for CMEK on a log bucket is reported by this data
# source rather than made by `google_project_service_identity`.
data "google_logging_project_cmek_settings" "main" {
  project = var.project_id

  depends_on = [google_project_service.apis]
}

locals {
  kms_users = {
    artifactregistry = "serviceAccount:${google_project_service_identity.agents["artifactregistry.googleapis.com"].email}"
    secretmanager    = "serviceAccount:${google_project_service_identity.agents["secretmanager.googleapis.com"].email}"
    cloudsql         = "serviceAccount:${google_project_service_identity.agents["sqladmin.googleapis.com"].email}"
    # Compute Engine's agent encrypts the nodes' boot and upload disks. It
    # exists once the compute API is on, and has no identity resource.
    compute = "serviceAccount:service-${local.project_number}@compute-system.iam.gserviceaccount.com"
    logging = "serviceAccount:${data.google_logging_project_cmek_settings.main.service_account_id}"
  }
}

resource "google_kms_crypto_key_iam_member" "service_agents" {
  for_each      = local.kms_users
  crypto_key_id = google_kms_crypto_key.main.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}

# ---------------------------------------------------------------------------
# A RING AND A KEY IN EVERY OTHER REGION A GCP CELL IS IN (#97): the same
# name in each, because a ring's name is per location. A cell's database,
# disks, secrets and certificate are sealed under ITS region's key, and a key
# is never replicated — the residency line #98 draws with AWS's single-region
# cell keys. The home region keeps the key above, under its own address.
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "regional" {
  for_each = local.other_regions
  name     = var.name
  location = each.key

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "regional" {
  for_each        = local.other_regions
  name            = var.name
  key_ring        = google_kms_key_ring.regional[each.key].id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  regional_kms_users = {
    for pair in setproduct(tolist(local.other_regions), keys(local.kms_users)) :
    "${pair[0]}-${pair[1]}" => { region = pair[0], member = local.kms_users[pair[1]] }
  }
}

resource "google_kms_crypto_key_iam_member" "regional_service_agents" {
  for_each      = local.regional_kms_users
  crypto_key_id = google_kms_crypto_key.regional[each.value.region].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value.member
}

# ---------------------------------------------------------------------------
# THE SERVICE'S KEY-ENCRYPTION KEY, IN CLOUD KMS (#391) — a SECOND key in the
# home ring, beside `main`, and never `main` itself.
#
# Since #391 the service seals every value under a data encryption key (DEK)
# and wraps each DEK under the key-encryption key (KEK). With
# `STS_KEYS_KEK_PROVIDER=gcp-kms` that KEK is THIS key, and it NEVER LEAVES
# Cloud KMS: the node calls encrypt and decrypt with each DEK and its
# additional authenticated data, once per DEK at start, and holds no KEK
# bytes at all — where the `gcp` provider read 32 bytes out of a Secret
# Manager secret into the process (deploy/gcp/CLAUDE.md, *The key-encryption
# key*). An environment chooses with `kek_provider` (environment/kek.tf).
#
# NOT `main`, BECAUSE IT IS A DIFFERENT PURPOSE WITH A DIFFERENT GRANTEE.
# `main` is used by Google's SERVICE AGENTS to encrypt storage; this one is
# used by the NODES to wrap the service's own keys. A node account holding
# encrypt/decrypt on `main` could decrypt — through the KMS — whatever the
# agents sealed under it; on this key it can do nothing but wrap and unwrap
# DEKs. And the two rotate on different schedules for different reasons.
#
# LONG-LIVED, ONE FOR THE PROJECT, NEVER ONE PER RUN: a Cloud KMS key cannot
# be deleted — only its versions destroyed — so a key made by each
# environment apply would leave one more key behind every time `dev` or `ci`
# is torn down. Every environment that uses KMS names this one key.
#
# THE SERVICE STORES THE KEY'S RESOURCE NAME IN EVERY WRAPPED DEK and refuses
# a row whose name differs, so every node of an environment must configure
# the IDENTICAL name — which is why the environment reads it from here rather
# than spelling it, and why it is the KEY's name and never a version's (the
# service refuses a version: Cloud KMS encrypts under the primary and
# decrypts under whichever version the ciphertext names).
#
# ROTATION IS THE KEY'S OWN: a new primary version every
# `kek_rotation_period`; at its next start a node re-wraps every DEK that was
# wrapped under a version that is no longer primary, so an old version can be
# DISABLED once every node has restarted, and nothing else is needed. Never
# DESTROY a version a database backup may still need: a backup holds DEKs
# wrapped under the version that was primary when it was taken.
#
# A key in the home region serves an environment in any region: Cloud KMS is
# called over its API, and residency here is the key's, not the caller's.
# ---------------------------------------------------------------------------
resource "google_kms_crypto_key" "kek" {
  name            = "${var.name}-kek"
  key_ring        = google_kms_key_ring.main.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kek_rotation_period

  # What the service checks at start (getCryptoKey): ENCRYPT_DECRYPT of
  # GOOGLE_SYMMETRIC_ENCRYPTION with an enabled primary. Spelt, not left to
  # the default, because a different algorithm is refused and the service
  # would not start. SOFTWARE as `main` is: an HSM key cannot be had by
  # changing this later — the protection level is fixed at creation.
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  # A key whose versions were destroyed makes every DEK wrapped under it —
  # and so every value the service sealed — unreadable for good.
  lifecycle {
    prevent_destroy = true
  }
}

# EACH ENVIRONMENT'S NODE ACCOUNT MAY USE THIS KEY AND NO OTHER KMS RIGHT —
# granted HERE, on the key, because the deployer holds no IAM administration
# role and so cannot grant it from environment/ (iam_deployer.tf, fence 2).
# Two roles, both on this one key:
#
#   cryptoKeyEncrypterDecrypter  wrapping and unwrapping each DEK
#   viewer                       cloudkms.cryptoKeys.get: the service reads
#                                the key at start (getCryptoKey) to check its
#                                purpose, algorithm and primary version, and
#                                the encrypter role does NOT include that
#                                permission — without it the node stops at
#                                start with a 403
#
# Every listed environment gets them, whatever its `kek_provider`, because an
# environment chooses at its own apply and the deployer could not add the
# grant then. An environment on `secret` holds a right on a key it never
# calls. The GCP CELLS of a multi-cloud environment (identities.tf's `cell`
# accounts) get NOTHING: their KEK is the global one AWS made, shared with
# the AWS cells, and stays a secret (environment/kek.tf).
locals {
  kek_grants = {
    for pair in setproduct(keys(var.environments), [
      "roles/cloudkms.cryptoKeyEncrypterDecrypter",
      "roles/cloudkms.viewer",
    ]) : "${pair[0]}-${pair[1]}" => { env = pair[0], role = pair[1] }
  }
}

resource "google_kms_crypto_key_iam_member" "kek_nodes" {
  for_each      = local.kek_grants
  crypto_key_id = google_kms_crypto_key.kek.id
  role          = each.value.role
  member        = google_service_account.environment[each.value.env].member
}
