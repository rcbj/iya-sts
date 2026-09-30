# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#367, 2026-09-30): `terraform test` with
# every AWS data source and resource mocked, so nothing is read from or made in AWS and no credential is needed.
# It holds the DNS tree of globalidp's cells (who writes which pins, the jurisdiction latency sets), testidpna's CA pin in its new form, the refusal of a pin with no cell, and a single-cell environment rendering no cell record at all.
#
#   terraform -chdir=deploy/aws/environment init -backend=false
#   terraform -chdir=deploy/aws/environment test
#
# Not run by the suite or CI; run it after changing this stack
# (deploy/aws/CLAUDE.md, *What was checked*).
# ---------------------------------------------------------------------------
mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["a1", "b1", "c1"], zone_ids = ["z1", "z2", "z3"] }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_ip_ranges" {
    defaults = { cidr_blocks = ["192.0.2.0/24"] }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:111122223333:key/k" }
  }
  mock_data "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/p" }
  }
  mock_data "aws_ecr_repository" {
    defaults = { arn = "arn:aws:ecr:us-west-2:111122223333:repository/mock-sts", repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/mock-sts" }
  }
  mock_data "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-west-2:111122223333:log-group:/mock-sts/containers" }
  }
  mock_resource "aws_acm_certificate" {
    override_during = plan
    defaults        = { domain_validation_options = [{ domain_name = "x", resource_record_name = "_x", resource_record_type = "CNAME", resource_record_value = "_y" }] }
  }
  mock_data "aws_network_interfaces" {
    defaults = { ids = [] }
  }
}
override_data {
  target = data.terraform_remote_state.global
  values = { outputs = {
    primary_address = "p", db_port = 5432, db_name = "sts", db_app_user = "sts_app",
    read_addresses  = {}, secret_arns = {}, master_secret_arn = "m"
  } }
}
variables {
  image_tag        = "t"
  allowed_cidrs    = ["203.0.113.4/32"]
  public_hostname  = "global-idp.iyasec.io"
  public_zone_name = "iyasec.io"
  primary_cell     = "usw2"
  cells            = jsondecode(file("envs/globalidp.cells.tfvars.json")).cells
  jurisdictions    = jsondecode(file("envs/globalidp.cells.tfvars.json")).jurisdictions
}
run "euc1_writes_the_eu_pins" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "euc1"
  }
  assert {
    condition     = length(aws_route53_record.pinned) == 30 && aws_route53_record.pinned["DE"].alias[0].name == "eu.cells.global-idp.iyasec.io" && aws_route53_record.pinned["DE"].set_identifier == "eu-DE"
    error_message = "pins=${length(aws_route53_record.pinned)}"
  }
  assert {
    condition     = aws_route53_record.jurisdiction_latency[0].name == "eu.cells.global-idp.iyasec.io" && aws_route53_record.latency[0].name == "cells.global-idp.iyasec.io" && length(aws_route53_record.default) == 0
    error_message = "latency"
  }
  assert {
    condition     = length(jsondecode(local.cell_environment.STS_CELL_PEERS)) == 5 && local.cell_environment.STS_CELL_JURISDICTION == "eu"
    error_message = local.cell_environment.STS_CELL_PEERS
  }
}
run "euw1_writes_no_pins" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "euw1"
  }
  assert {
    condition     = length(aws_route53_record.pinned) == 0 && aws_route53_record.jurisdiction_latency[0].name == "eu.cells.global-idp.iyasec.io" && aws_route53_record.cell_console[0].name == "euw1.global-idp.iyasec.io"
    error_message = "euw1"
  }
}
run "apse5_pins_my" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "apse5"
  }
  assert {
    condition     = keys(aws_route53_record.pinned) == ["MY"] && aws_route53_record.pinned["MY"].alias[0].name == "my.cells.global-idp.iyasec.io" && aws_route53_record.jurisdiction_latency[0].latency_routing_policy[0].region == "ap-southeast-5"
    error_message = "apse5"
  }
}
run "usw2_writes_default" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "usw2"
  }
  assert {
    condition     = length(aws_route53_record.default) == 1 && length(aws_route53_record.pinned) == 0 && aws_route53_record.jurisdiction_latency[0].name == "us.cells.global-idp.iyasec.io"
    error_message = "usw2"
  }
}
run "testidpna_cac1_pins_ca" {
  command = plan
  variables {
    environment     = "testidpna"
    cell            = "cac1"
    public_hostname = "test-idp.iyasec.io"
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = keys(aws_route53_record.pinned) == ["CA"] && aws_route53_record.pinned["CA"].alias[0].name == "ca.cells.test-idp.iyasec.io" && aws_route53_record.pinned["CA"].alias[0].evaluate_target_health == false
    error_message = "cac1"
  }
}
run "orphan_pin_refused" {
  command = plan
  variables {
    environment   = "globalidp"
    cell          = "usw2"
    jurisdictions = { jp = { geolocation_countries = ["JP"] } }
  }
  expect_failures = [var.jurisdictions]
}
run "single_cell_dev_unchanged" {
  command = plan
  variables {
    environment     = "dev"
    public_hostname = ""
    cells           = {}
    jurisdictions   = {}
    primary_cell    = ""
  }
  assert {
    condition     = length(aws_route53_record.pinned) == 0 && length(aws_route53_record.jurisdiction_latency) == 0 && length(aws_route53_record.latency) == 0 && local.cell_environment == {}
    error_message = "single"
  }
}
