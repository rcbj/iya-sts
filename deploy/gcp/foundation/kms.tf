# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE CUSTOMER-MANAGED KEY FOR THE PROJECT (deploy/aws/foundation/kms.tf).
#
# It encrypts every secret in Secret Manager, both Cloud SQL instances' disks
# and their backups, the nodes' boot and upload disks, the image repository
# and the container log bucket.
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
