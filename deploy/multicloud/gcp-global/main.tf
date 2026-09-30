# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

provider "google" {
  project = var.project_id

  default_labels = {
    project     = "sts"
    environment = var.environment
    stack       = "mock-sts-gcp-global"
  }
}

# Reads only: the AWS global stack's state and the secrets it made, in the
# writer's region.
provider "aws" {
  region = var.cells[var.primary_cell].region
}

data "aws_caller_identity" "current" {}

data "terraform_remote_state" "aws_global" {
  backend = "s3"
  config = {
    region = var.state_region
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key    = "environment/${var.environment}/global.tfstate"
  }
}

locals {
  gcp_cells = { for id, c in var.cells : id => c if c.cloud == "gcp" }
  regions   = toset([for c in values(local.gcp_cells) : c.region])
  aws       = data.terraform_remote_state.aws_global.outputs
  network   = "${var.name}-${var.environment}"

  db_master_user = "stsadmin"

  # The global secrets' names — the key set every copy below iterates, so no
  # for_each walks a map that holds a secret value.
  global_keys = toset(keys(local.aws.global_secret_names))
}

data "google_kms_crypto_key" "region" {
  for_each = local.regions
  name     = var.name
  key_ring = "projects/${var.project_id}/locations/${each.key}/keyRings/${var.name}"
}

data "google_service_account" "cell" {
  for_each   = local.gcp_cells
  account_id = "${var.name}-env-${var.environment}-${each.key}"
}

data "google_compute_network" "shared" {
  name = local.network
}

# ---------------------------------------------------------------------------
# THE GLOBAL SECRETS, COPIED (the header). The copy's value is in this
# stack's state, as the original's is in AWS's global state — both states
# are the environment's, encrypted, in private buckets.
# ---------------------------------------------------------------------------
data "aws_secretsmanager_secret_version" "global" {
  for_each  = local.global_keys
  secret_id = local.aws.global_secret_names[each.key]
}

resource "google_secret_manager_secret" "global" {
  for_each  = local.global_keys
  secret_id = "${var.name}-${var.environment}-global-${each.key}"

  labels = {
    environment = var.environment
    tier        = "global"
  }

  replication {
    user_managed {
      dynamic "replicas" {
        for_each = local.regions
        content {
          location = replicas.key
          customer_managed_encryption {
            kms_key_name = data.google_kms_crypto_key.region[replicas.key].id
          }
        }
      }
    }
  }
}

resource "google_secret_manager_secret_version" "global" {
  for_each    = local.global_keys
  secret      = google_secret_manager_secret.global[each.key].id
  secret_data = data.aws_secretsmanager_secret_version.global[each.key].secret_string
}

locals {
  secret_cell_pairs = {
    for pair in setproduct(tolist(local.global_keys), keys(local.gcp_cells)) :
    "${pair[0]}-${pair[1]}" => { secret = pair[0], cell = pair[1] }
  }
}

resource "google_secret_manager_secret_iam_member" "global" {
  for_each  = local.secret_cell_pairs
  secret_id = google_secret_manager_secret.global[each.value.secret].id
  role      = "roles/secretmanager.secretAccessor"
  member    = data.google_service_account.cell[each.value.cell].member
}

# ---------------------------------------------------------------------------
# EACH GCP CELL'S COPY OF THE GLOBAL DATABASE (the header).
#
# ON PRIVATE SERVICES ACCESS, not Private Service Connect as a cell database
# is (#95): a subscriber DIALS OUT to the publisher, and an instance reached
# only through a PSC endpoint has no route out. Its address comes from the
# range the foundation reserved for this cell (`allocated_ip_range`), which
# the Cloud Router advertises to AWS and the writer's security group admits
# (deploy/aws/environment/global_db.tf).
#
# NO BACKUPS: it is a copy, and the writer's are the record. A lost copy is
# made again and re-synced by the next node start (apply.sh empties and
# re-subscribes).
#
# A RANDOM SUFFIX for #95's reason: a deleted instance's name is held a week.
# ---------------------------------------------------------------------------
resource "random_id" "copy" {
  for_each    = local.gcp_cells
  byte_length = 3
}

resource "random_password" "copy_master" {
  for_each = local.gcp_cells
  length   = 40
  special  = false
}

resource "google_sql_database_instance" "copy" {
  for_each            = local.gcp_cells
  name                = "${var.name}-${var.environment}-${each.key}-global-${random_id.copy[each.key].hex}"
  region              = each.value.region
  database_version    = var.db_version
  encryption_key_name = data.google_kms_crypto_key.region[each.value.region].id
  deletion_protection = false

  settings {
    tier                        = var.db_tier
    edition                     = "ENTERPRISE"
    availability_type           = "ZONAL"
    disk_type                   = "PD_SSD"
    disk_size                   = var.db_disk_gib
    disk_autoresize             = true
    deletion_protection_enabled = false

    ip_configuration {
      ipv4_enabled       = false
      private_network    = data.google_compute_network.shared.id
      allocated_ip_range = "${var.name}-${var.environment}-${each.key}-psa"
      ssl_mode           = "ENCRYPTED_ONLY"
      server_ca_mode     = "GOOGLE_MANAGED_CAS_CA"
    }

    backup_configuration {
      enabled = false
    }

    database_flags {
      name  = "ssl_min_protocol_version"
      value = "TLSv1.2"
    }
  }
}

resource "google_sql_database" "copy" {
  for_each = local.gcp_cells
  name     = local.aws.db_name
  instance = google_sql_database_instance.copy[each.key].name
}

resource "google_sql_user" "copy_master" {
  for_each        = local.gcp_cells
  name            = local.db_master_user
  instance        = google_sql_database_instance.copy[each.key].name
  password        = random_password.copy_master[each.key].result
  deletion_policy = "ABANDON"
}

# The copy's master password, for its subscriber init only — in its cell's
# region, readable by that cell's nodes and no other.
resource "google_secret_manager_secret" "copy_master" {
  for_each  = local.gcp_cells
  secret_id = "${var.name}-${var.environment}-${each.key}-global-db-master-password"

  labels = {
    environment = var.environment
    cell        = each.key
  }

  replication {
    user_managed {
      replicas {
        location = each.value.region
        customer_managed_encryption {
          kms_key_name = data.google_kms_crypto_key.region[each.value.region].id
        }
      }
    }
  }
}

resource "google_secret_manager_secret_version" "copy_master" {
  for_each    = local.gcp_cells
  secret      = google_secret_manager_secret.copy_master[each.key].id
  secret_data = random_password.copy_master[each.key].result
}

resource "google_secret_manager_secret_iam_member" "copy_master" {
  for_each  = local.gcp_cells
  secret_id = google_secret_manager_secret.copy_master[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = data.google_service_account.cell[each.key].member
}

# ---------------------------------------------------------------------------
# THE RDS CA FOR THE WRITER'S REGION, which a GCP node verifies the writer
# with (NODE_EXTRA_CA_CERTS; the image carries no RDS bundle, #95). The
# region's bundle rather than the global one: a few kilobytes, where the
# global one would not fit in a VM's metadata beside everything else.
# ---------------------------------------------------------------------------
data "http" "writer_ca" {
  url = "https://truststore.pki.rds.amazonaws.com/${local.aws.writer_region}/${local.aws.writer_region}-bundle.pem"

  lifecycle {
    postcondition {
      condition     = self.status_code == 200 && strcontains(self.response_body, "BEGIN CERTIFICATE")
      error_message = "The RDS CA bundle for the writer's region could not be fetched."
    }
  }
}
