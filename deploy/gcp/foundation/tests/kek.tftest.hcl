# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THE SERVICE'S KEY-ENCRYPTION KEY IN CLOUD KMS (#391,
# kms.tf `kek`): `terraform test` with google and google-beta MOCKED, so
# nothing is read from or made in GCP and no credential is needed. It holds
# that the key is a dedicated one beside `main`, of the purpose and
# algorithm the service checks at start, rotating on its own period; that
# every environment's node account — and no GCP cell's — gets exactly the
# encrypter and viewer roles on THAT key; and that a sub-day rotation is
# refused.
#
#   terraform -chdir=deploy/gcp/foundation init -backend=false
#   terraform -chdir=deploy/gcp/foundation test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "google" {
  mock_data "google_project" {
    defaults = { number = "123456789012" }
  }
  mock_data "google_logging_project_cmek_settings" {
    defaults = { service_account_id = "cmek-p@gcp-sa-logging.iam.gserviceaccount.com" }
  }
}

mock_provider "google-beta" {}

# A service account's `member` is checked by the IAM resources' validation,
# so the mock's random string will not do. The environments' accounts and
# the cells' are told apart, so the grant can be shown to reach one and not
# the other.
override_resource {
  target = google_service_account.deployer
  values = { member = "serviceAccount:mock-sts-deployer@p.iam.gserviceaccount.com", name = "projects/p/serviceAccounts/mock-sts-deployer@p.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.environment
  values = { member = "serviceAccount:mock-sts-env@p.iam.gserviceaccount.com", name = "projects/p/serviceAccounts/mock-sts-env@p.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.cell
  values = { member = "serviceAccount:mock-sts-cell@p.iam.gserviceaccount.com", name = "projects/p/serviceAccounts/mock-sts-cell@p.iam.gserviceaccount.com" }
}

variables {
  project_id             = "p"
  deployer_members       = ["user:someone@example.com"]
  multicell_environments = ["testidpmc"]
}

run "a_dedicated_kek_with_two_grants_per_environment" {
  command = apply
  assert {
    condition     = google_kms_crypto_key.kek.name == "mock-sts-kek" && google_kms_crypto_key.kek.key_ring == google_kms_key_ring.main.id && google_kms_crypto_key.kek.name != google_kms_crypto_key.main.name
    error_message = "the KEK is its own key in the home ring"
  }
  assert {
    condition     = google_kms_crypto_key.kek.purpose == "ENCRYPT_DECRYPT" && google_kms_crypto_key.kek.version_template[0].algorithm == "GOOGLE_SYMMETRIC_ENCRYPTION" && google_kms_crypto_key.kek.rotation_period == "31536000s"
    error_message = "ENCRYPT_DECRYPT, GOOGLE_SYMMETRIC_ENCRYPTION, a year's rotation"
  }
  assert {
    condition     = output.kek_key == google_kms_crypto_key.kek.id
    error_message = "kek_key is the key's resource name"
  }
  assert {
    condition = length(google_kms_crypto_key_iam_member.kek_nodes) == 6 && alltrue([
      for e in ["dev", "ci", "testidp"] : alltrue([
        for r in ["roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.viewer"] :
        google_kms_crypto_key_iam_member.kek_nodes["${e}-${r}"].crypto_key_id == google_kms_crypto_key.kek.id &&
        google_kms_crypto_key_iam_member.kek_nodes["${e}-${r}"].member == google_service_account.environment[e].member
      ])
    ])
    error_message = "each environment's node account holds encrypter and viewer on the KEK"
  }
  assert {
    condition = alltrue([
      for g in values(google_kms_crypto_key_iam_member.kek_nodes) :
      !contains([for s in values(google_service_account.cell) : s.member], g.member)
    ])
    error_message = "no GCP cell's account is granted the KEK"
  }
  assert {
    condition = alltrue([
      for g in values(google_kms_crypto_key_iam_member.service_agents) :
      g.crypto_key_id == google_kms_crypto_key.main.id
    ])
    error_message = "the service agents keep `main` and are not on the KEK"
  }
}

run "sub_day_rotation_refused" {
  command = plan
  variables {
    kek_rotation_period = "3600s"
  }
  expect_failures = [var.kek_rotation_period]
}
