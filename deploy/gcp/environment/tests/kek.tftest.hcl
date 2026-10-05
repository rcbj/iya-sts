# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF WHERE THE KEY-ENCRYPTION KEY IS (#391, kek.tf):
# `terraform test` with the google and random providers MOCKED, so nothing is
# read from or made in GCP and no credential is needed. It holds that
#
#   * the default is Cloud KMS: every node is told gcp-kms and the
#     foundation key's resource name, and loses the read on the `kek` secret
#     (which is still made);
#   * `secret` renders #95's environment, the secret as the KEK;
#   * a migration adds the secret as STS_PREVIOUS_KEK_*, and the read back;
#   * an unknown provider, a migration on `secret`, and `kms` in a GCP cell
#     of a multi-cloud environment are refused.
#
# The node's rights on the KMS key are the foundation's grant, held by
# ../foundation/tests/kek.tftest.hcl.
#
#   terraform -chdir=deploy/gcp/environment init -backend=false
#   terraform -chdir=deploy/gcp/environment test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "google" {
  mock_data "google_compute_zones" {
    defaults = { names = ["us-west1-a", "us-west1-b", "us-west1-c"] }
  }
  mock_data "google_service_account" {
    defaults = {
      email  = "iya-sts-env-dev@p.iam.gserviceaccount.com"
      member = "serviceAccount:iya-sts-env-dev@p.iam.gserviceaccount.com"
    }
  }
  mock_data "google_compute_image" {
    defaults = { self_link = "https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos" }
  }
}

mock_provider "random" {}

override_data {
  target = data.google_kms_crypto_key.kek
  values = { id = "projects/p/locations/us-west1/keyRings/iya-sts/cryptoKeys/iya-sts-kek" }
}

variables {
  project_id    = "p"
  environment   = "dev"
  image_tag     = "t"
  allowed_cidrs = ["203.0.113.4/32"]
}

run "default_is_cloud_kms" {
  command = apply
  assert {
    condition     = var.kek_provider == "kms"
    error_message = "the default must be kms"
  }
  assert {
    condition = alltrue([for n in ["node-a", "node-b", "node-c"] :
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_KEYS_KEK_PROVIDER=gcp-kms") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_KEYS_KEK_REF=projects/p/locations/us-west1/keyRings/iya-sts/cryptoKeys/iya-sts-kek")
    ])
    error_message = "every node must name the Cloud KMS key"
  }
  assert {
    condition     = !strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_PREVIOUS_KEK")
    error_message = "no previous KEK unless migrating"
  }
  assert {
    condition     = contains(keys(google_secret_manager_secret.main), "kek") && !contains(keys(google_secret_manager_secret_iam_member.nodes), "kek")
    error_message = "the kek secret is still made, and the nodes may not read it"
  }
  assert {
    condition     = contains(keys(google_secret_manager_secret_iam_member.nodes), "db-app-password")
    error_message = "the other secrets are still readable"
  }
}

run "secret_is_95s_environment" {
  command = apply
  variables {
    kek_provider = "secret"
  }
  assert {
    condition     = strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_KEYS_KEK_PROVIDER=gcp\n") && strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_KEYS_KEK_REF=${google_secret_manager_secret.main["kek"].id}\n")
    error_message = "secret must name the Secret Manager kek with the gcp provider"
  }
  assert {
    condition     = length(data.google_kms_crypto_key.kek) == 0 && contains(keys(google_secret_manager_secret_iam_member.nodes), "kek")
    error_message = "secret reads no KMS key and grants the read on the kek secret"
  }
  assert {
    condition     = !strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_PREVIOUS_KEK")
    error_message = "no previous KEK on secret"
  }
}

run "migrating_adds_the_previous_kek" {
  command = apply
  variables {
    kek_migrating_from_secret = true
  }
  assert {
    condition = alltrue([for n in ["node-a", "node-b", "node-c"] :
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_KEYS_KEK_PROVIDER=gcp-kms") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_PREVIOUS_KEK_PROVIDER=gcp\n") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_PREVIOUS_KEK_REF=${google_secret_manager_secret.main["kek"].id}\n")
    ])
    error_message = "every node must have the KMS key as KEK and the secret as previous"
  }
  assert {
    condition     = contains(keys(google_secret_manager_secret_iam_member.nodes), "kek")
    error_message = "a migrating node must be able to read the old secret"
  }
}

run "unknown_provider_refused" {
  command = plan
  variables {
    kek_provider = "hsm"
  }
  expect_failures = [var.kek_provider]
}

run "migrating_on_secret_refused" {
  command = plan
  variables {
    kek_provider              = "secret"
    kek_migrating_from_secret = true
  }
  expect_failures = [var.kek_migrating_from_secret]
}

# deploy/multicloud's real cells file, and one of its GCP cells in the
# `base` phase (no global state is read).
run "kms_in_a_cell_refused" {
  command = plan
  variables {
    cell         = "gusw1"
    cell_phase   = "base"
    primary_cell = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).primary_cell
    cells        = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).cells
  }
  expect_failures = [var.kek_provider]
}

# What deploy/multicloud/envs/testidpmc.gcp.tfvars sets: the cell renders the
# global secret's provider and no KMS key is looked up.
run "secret_in_a_cell_is_accepted" {
  command = apply
  variables {
    kek_provider = "secret"
    cell         = "gusw1"
    cell_phase   = "base"
    primary_cell = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).primary_cell
    cells        = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).cells
  }
  assert {
    condition     = length(data.google_kms_crypto_key.kek) == 0 && strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_KEYS_KEK_PROVIDER=gcp\n") && strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_CELL_KEK_PROVIDER=gcp\n")
    error_message = "a cell keeps the secret KEK and its secret cell KEK"
  }
}
