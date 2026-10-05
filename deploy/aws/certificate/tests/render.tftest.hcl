# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THE CERTIFICATE STACK (2026-10-01): `terraform test`
# with AWS mocked, so nothing is read from or made in AWS.
#
#   terraform -chdir=deploy/aws/certificate init -backend=false
#   terraform -chdir=deploy/aws/certificate test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "aws" {
  mock_resource "aws_acm_certificate" {
    override_during = plan
    defaults        = { domain_validation_options = [{ domain_name = "x", resource_record_name = "_x", resource_record_type = "CNAME", resource_record_value = "_y" }] }
  }
}

run "single_cell_one_exportable_certificate" {
  command = plan
  variables {
    environment      = "testidp"
    public_hostname  = "test-idp.iyasec.io"
    public_zone_name = "iyasec.io"
  }
  assert {
    condition     = length(aws_acm_certificate.public) == 1 && aws_acm_certificate.public[0].domain_name == "test-idp.iyasec.io" && length(aws_acm_certificate.public[0].subject_alternative_names) == 0 && aws_acm_certificate.public[0].options[0].export == "ENABLED"
    error_message = "single-cell certificate"
  }
}

run "a_cell_names_its_console" {
  command = plan
  variables {
    environment      = "testidpna"
    cell             = "cac1"
    cells            = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).cells
    public_hostname  = "test-idp.iyasec.io"
    public_zone_name = "iyasec.io"
  }
  assert {
    condition     = length(aws_acm_certificate.public[0].subject_alternative_names) == 1 && contains(aws_acm_certificate.public[0].subject_alternative_names, "cac1.test-idp.iyasec.io")
    error_message = "cell console SAN"
  }
}

run "no_public_name_no_certificate" {
  command = plan
  variables {
    environment = "dev"
  }
  assert {
    condition     = length(aws_acm_certificate.public) == 0 && output.certificate_arn == ""
    error_message = "no public name"
  }
}
