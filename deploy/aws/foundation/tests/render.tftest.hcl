# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#367, 2026-09-30): `terraform test` with
# a provider that is never asked anything (the data sources that would call AWS overridden), so nothing is read from or made in AWS and no credential is needed.
# It holds the region rule — every default region's cell id, one region module each, regional ARNs whose region is a wildcard — and the two refusals: a region the account has not enabled, and a region name the rule cannot shorten.
#
#   terraform -chdir=deploy/aws/foundation init -backend=false
#   terraform -chdir=deploy/aws/foundation test
#
# Not run by the suite or CI; run it after changing this stack
# (deploy/aws/CLAUDE.md, *What was checked*).
# ---------------------------------------------------------------------------
provider "aws" {
  region                      = "us-west-2"
  access_key                  = "x"
  secret_key                  = "x"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_caller_identity.current
  values = { account_id = "111122223333" }
}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_data {
  target = data.aws_route53_zone.public
  values = { arn = "arn:aws:route53:::hostedzone/Z1", zone_id = "Z1" }
}

override_data {
  target = data.aws_regions.enabled
  values = { names = ["us-west-2", "ca-central-1", "us-east-2", "eu-central-1", "eu-west-1", "ap-southeast-1", "ap-southeast-5"] }
}

run "every_default_region_gets_its_cell" {
  command = plan
  assert {
    condition = local.cell_of_region == {
      "us-west-2"      = "usw2", "ca-central-1" = "cac1", "us-east-2" = "use2",
      "eu-central-1"   = "euc1", "eu-west-1" = "euw1",
      "ap-southeast-1" = "apse1", "ap-southeast-5" = "apse5",
    }
    error_message = jsonencode(local.cell_of_region)
  }
  assert {
    condition     = length(module.region) == 7 && alltrue([for p in local.rarn.rds : strcontains(p, ":rds:*:")])
    error_message = "a region module per permitted region, and regional ARNs with a wildcard region"
  }
}

run "a_region_not_enabled_stops_the_plan" {
  command = plan
  override_data {
    target = data.aws_regions.enabled
    values = { names = ["us-west-2", "ca-central-1"] }
  }
  expect_failures = [data.aws_regions.enabled]
}

run "a_region_of_another_shape_is_refused" {
  command = plan
  variables {
    permitted_regions = ["us-west-2", "us-gov-west-1"]
  }
  expect_failures = [var.permitted_regions]
}

# THE KEY-ENCRYPTION KEY IN KMS (#391): one multi-region symmetric key for
# encryption, rotated, thirty days to delete, and its alias. Its replicas
# are made by the same rule as the global key's (modules/region, `local.home`)
# and their ARNs are unknown until apply, so a plan cannot show them; the
# home region holding none can be shown.
run "the_kek_is_a_multi_region_key" {
  command = plan
  assert {
    condition     = aws_kms_key.kek.multi_region == true && aws_kms_key.kek.enable_key_rotation == true && aws_kms_key.kek.key_usage == "ENCRYPT_DECRYPT" && aws_kms_key.kek.customer_master_key_spec == "SYMMETRIC_DEFAULT" && aws_kms_key.kek.deletion_window_in_days == 30
    error_message = "the KEK key's shape"
  }
  assert {
    condition     = aws_kms_alias.kek.name == "alias/iya-sts-kek" && module.region["us-west-2"].kek_replica_key_arn == ""
    error_message = aws_kms_alias.kek.name
  }
}
