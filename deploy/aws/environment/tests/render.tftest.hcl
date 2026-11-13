# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#367, 2026-09-30): `terraform test` with
# every AWS data source and resource mocked, so nothing is read from or made in AWS and no credential is needed.
# It holds the DNS tree of globalidp's cells (who writes which pins, the jurisdiction latency sets), testidpna's CA pin in its new form, the refusal of a pin with no cell, and a single-cell environment rendering no cell record at all — and (#391) the key-encryption key: the KMS key by default, by ID with each node's own region and the task role limited to its ARNs, the secret with `kek_provider = "secret"`, the previous KEK while migrating, and the refusals (another provider, migrating without KMS, KMS in a multi-cloud environment).
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
    defaults = { arn = "arn:aws:ecr:us-west-2:111122223333:repository/iya-sts", repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts" }
  }
  mock_data "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-west-2:111122223333:log-group:/iya-sts/containers" }
  }
  mock_data "aws_network_interfaces" {
    defaults = { ids = [] }
  }
}
mock_provider "aws" {
  alias = "us_east_1"
}
override_data {
  target = data.terraform_remote_state.global
  values = { outputs = {
    primary_address = "p", db_port = 5432, db_name = "sts", db_app_user = "sts_app",
    read_addresses  = {}, secret_arns = {}, master_secret_arn = "m"
  } }
}
# THE KEY-ENCRYPTION KEY (kek.tf, #391): the foundation's multi-region key as
# DescribeKey would describe it — the alias resolved in us-west-2, a primary
# there and two replicas.
override_data {
  target = data.aws_kms_key.kek
  values = {
    id                       = "mrk-0123456789abcdef0123456789abcdef"
    arn                      = "arn:aws:kms:us-west-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef"
    enabled                  = true
    multi_region             = true
    key_usage                = "ENCRYPT_DECRYPT"
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
    multi_region_configuration = [{
      multi_region_key_type = "PRIMARY"
      primary_key           = [{ arn = "arn:aws:kms:us-west-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef", region = "us-west-2" }]
      replica_keys = [
        { arn = "arn:aws:kms:eu-central-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef", region = "eu-central-1" },
        { arn = "arn:aws:kms:ca-central-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef", region = "ca-central-1" },
      ]
    }]
  }
}
# The public certificate is deploy/aws/certificate's (dns.tf), read from its
# state.
override_data {
  target = data.terraform_remote_state.certificate
  values = { outputs = {
    certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/c",
    public_hostname = "global-idp.iyasec.io"
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
  override_data {
    target = data.terraform_remote_state.certificate
    values = { outputs = {
      certificate_arn = "arn:aws:acm:ca-central-1:111122223333:certificate/c",
      public_hostname = "test-idp.iyasec.io"
    } }
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
# #695: a worker start timeout the 600 s grace cannot hold is refused at
# plan; 300000 (the environments' own) plus the margin fits.
run "start_timeout_inside_grace" {
  command = plan
  variables {
    environment       = "dev"
    public_hostname   = ""
    cells             = {}
    jurisdictions     = {}
    primary_cell      = ""
    extra_environment = { STS_WORKERS_START_TIMEOUT_MS = "300000" }
  }
}

run "start_timeout_past_grace_refused" {
  command = plan
  variables {
    environment       = "dev"
    public_hostname   = ""
    cells             = {}
    jurisdictions     = {}
    primary_cell      = ""
    extra_environment = { STS_WORKERS_START_TIMEOUT_MS = "900000" }
  }
  expect_failures = [aws_ecs_service.first]
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

# ---------------------------------------------------------------------------
# THE KEY-ENCRYPTION KEY (kek.tf, #391). The default is the KMS key, named by
# its ID with the node's own region, the task role allowed the four calls on
# that key's ARNs only and NOT the `kek` secret; "secret" is the arrangement
# before #391; migrating adds the secret as the previous KEK; and the two
# refusals.
# ---------------------------------------------------------------------------
override_resource {
  target          = aws_secretsmanager_secret.main["kek"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/dev/kek-AbCdEf" }
}
override_resource {
  target          = aws_secretsmanager_secret.main["db-app-password"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/dev/db-app-password-GhIjKl" }
}
run "kek_default_is_the_kms_key" {
  command = plan
  variables {
    environment     = "dev"
    public_hostname = ""
    cells           = {}
    jurisdictions   = {}
    primary_cell    = ""
  }
  assert {
    condition = local.kek_environment == {
      STS_KEYS_KEK_PROVIDER = "aws-kms"
      STS_KEYS_KEK_REF      = "mrk-0123456789abcdef0123456789abcdef"
      STS_KEYS_KEK_REGION   = "us-west-2"
    }
    error_message = jsonencode(local.kek_environment)
  }
  assert {
    condition     = local.node_environment.STS_KEYS_KEK_PROVIDER == "aws-kms" && !contains(keys(local.node_environment), "STS_PREVIOUS_KEK_PROVIDER")
    error_message = "the node's environment"
  }
  assert {
    condition = toset(one([for st in data.aws_iam_policy_document.task.statement : st.resources if st.sid == "WrapAndUnwrapWithTheKeyEncryptionKey"])) == toset([
      "arn:aws:kms:us-west-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef",
      "arn:aws:kms:eu-central-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef",
      "arn:aws:kms:ca-central-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef",
    ]) && toset(one([for st in data.aws_iam_policy_document.task.statement : st.actions if st.sid == "WrapAndUnwrapWithTheKeyEncryptionKey"])) == toset(["kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GetKeyRotationStatus"])
    error_message = "the task role's KMS statement"
  }
  assert {
    condition     = !contains(one([for st in data.aws_iam_policy_document.task.statement : st.resources if st.sid == "ReadTheKeyAndTheDatabasePassword"]), aws_secretsmanager_secret.main["kek"].arn)
    error_message = "the task role may not read the kek secret with a KMS KEK"
  }
}
run "kek_in_a_cell_names_the_same_id_and_its_own_region" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "euc1"
  }
  assert {
    condition     = local.node_environment.STS_KEYS_KEK_REF == "mrk-0123456789abcdef0123456789abcdef" && local.node_environment.STS_KEYS_KEK_REGION == "eu-central-1" && local.node_environment.STS_CELL_KEK_PROVIDER == "aws"
    error_message = jsonencode(local.kek_environment)
  }
}
run "kek_secret_is_the_old_arrangement" {
  command = plan
  variables {
    environment     = "dev"
    public_hostname = ""
    cells           = {}
    jurisdictions   = {}
    primary_cell    = ""
    kek_provider    = "secret"
  }
  assert {
    condition = local.kek_environment == {
      STS_KEYS_KEK_PROVIDER = "aws"
      STS_KEYS_KEK_REF      = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/dev/kek-AbCdEf"
      STS_KEYS_KEK_REGION   = "us-west-2"
    }
    error_message = jsonencode(local.kek_environment)
  }
  assert {
    condition     = length(data.aws_kms_key.kek) == 0 && length([for st in data.aws_iam_policy_document.task.statement : st if st.sid == "WrapAndUnwrapWithTheKeyEncryptionKey"]) == 0
    error_message = "no KMS key and no KMS statement with a secret KEK"
  }
  assert {
    condition     = contains(one([for st in data.aws_iam_policy_document.task.statement : st.resources if st.sid == "ReadTheKeyAndTheDatabasePassword"]), aws_secretsmanager_secret.main["kek"].arn)
    error_message = "the task role reads the kek secret"
  }
}
run "kek_migrating_adds_the_previous_kek" {
  command = plan
  variables {
    environment               = "dev"
    public_hostname           = ""
    cells                     = {}
    jurisdictions             = {}
    primary_cell              = ""
    kek_migrating_from_secret = true
  }
  assert {
    condition = local.kek_environment == {
      STS_KEYS_KEK_PROVIDER     = "aws-kms"
      STS_KEYS_KEK_REF          = "mrk-0123456789abcdef0123456789abcdef"
      STS_KEYS_KEK_REGION       = "us-west-2"
      STS_PREVIOUS_KEK_PROVIDER = "aws"
      STS_PREVIOUS_KEK_REF      = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/dev/kek-AbCdEf"
      STS_PREVIOUS_KEK_REGION   = "us-west-2"
    }
    error_message = jsonencode(local.kek_environment)
  }
  assert {
    condition     = contains(one([for st in data.aws_iam_policy_document.task.statement : st.resources if st.sid == "ReadTheKeyAndTheDatabasePassword"]), aws_secretsmanager_secret.main["kek"].arn)
    error_message = "the task role reads the kek secret while migrating"
  }
}
run "kek_provider_of_another_kind_is_refused" {
  command = plan
  variables {
    environment     = "dev"
    public_hostname = ""
    cells           = {}
    jurisdictions   = {}
    primary_cell    = ""
    kek_provider    = "vault"
  }
  expect_failures = [var.kek_provider]
}
run "kek_migrating_needs_the_kms_key" {
  command = plan
  variables {
    environment               = "dev"
    public_hostname           = ""
    cells                     = {}
    jurisdictions             = {}
    primary_cell              = ""
    kek_provider              = "secret"
    kek_migrating_from_secret = true
  }
  expect_failures = [var.kek_migrating_from_secret]
}
# #1309: the id comparison moved into try(), so the rule must still refuse an
# AWS cell whose id is not its region's (usw9 in us-west-2), and still take
# a GCP cell's region it cannot take apart (the multi-cloud run below).
run "aws_cell_id_must_name_its_region" {
  command = plan
  variables {
    environment = "globalidp"
    cell        = "usw2"
    cells = merge(jsondecode(file("envs/globalidp.cells.tfvars.json")).cells, {
      usw9 = merge(jsondecode(file("envs/globalidp.cells.tfvars.json")).cells["usw2"],
      { vpc_cidr = "10.250.0.0/16" })
    })
  }
  expect_failures = [var.cells]
}
run "kek_kms_refused_in_a_multi_cloud_environment" {
  command = plan
  variables {
    environment     = "testidpmc"
    cell            = "usw2"
    public_hostname = "test-idp.iyasec.io"
    cells           = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).jurisdictions
  }
  override_data {
    target = data.terraform_remote_state.certificate
    values = { outputs = {
      certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/c",
      public_hostname = "test-idp.iyasec.io"
    } }
  }
  expect_failures = [var.kek_provider]
}
run "kek_secret_in_a_multi_cloud_environment_plans" {
  command = plan
  variables {
    environment     = "testidpmc"
    cell            = "usw2"
    public_hostname = "test-idp.iyasec.io"
    cells           = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).jurisdictions
    kek_provider    = "secret"
  }
  override_data {
    target = data.terraform_remote_state.certificate
    values = { outputs = {
      certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/c",
      public_hostname = "test-idp.iyasec.io"
    } }
  }
  assert {
    condition     = local.node_environment.STS_KEYS_KEK_PROVIDER == "aws" && length(data.aws_kms_key.kek) == 0
    error_message = jsonencode(local.kek_environment)
  }
}

# CLOUDFRONT (cloudfront.tf): the BREACH decision and the fixed forwarded headers
# are what would fail quietly, so they are what this holds.
run "testidp_behind_cloudfront" {
  command = plan
  variables {
    environment           = "testidp"
    public_hostname       = "test-idp.iyasec.io"
    public_zone_name      = "iyasec.io"
    cloudfront_enabled    = true
    direct_hostname       = "direct.test-idp.iyasec.io"
    cloudfront_log_bucket = "iyasec-logs"
    cloudfront_log_prefix = "test-idp/"
  }
  override_data {
    target = data.terraform_remote_state.certificate[0]
    values = { outputs = {
      certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/c",
      public_hostname = "test-idp.iyasec.io"
    } }
  }
  assert {
    condition     = aws_cloudfront_distribution.main[0].price_class == "PriceClass_All"
    error_message = "Every edge location was asked for."
  }
  assert {
    condition     = aws_cloudfront_distribution.main[0].default_cache_behavior[0].compress == false
    error_message = "An API or protocol answer must not be compressed at the edge (BREACH)."
  }
  assert {
    condition     = length(aws_cloudfront_distribution.main[0].ordered_cache_behavior) == 4 && alltrue([for b in aws_cloudfront_distribution.main[0].ordered_cache_behavior : b.compress])
    error_message = "Every static path compresses."
  }
  assert {
    condition     = nonsensitive(toset(flatten([for o in aws_cloudfront_distribution.main[0].origin : [for h in o.custom_header : h.name]]))) == toset(["X-Forwarded-Host", "X-Forwarded-Proto", "X-Origin-Verify"])
    error_message = "A viewer's X-Forwarded-Host and -Proto must be overwritten."
  }
  assert {
    condition     = aws_route53_record.public[0].type == "A" && aws_route53_record.direct[0].type == "CNAME"
    error_message = "The public name goes to CloudFront; the direct name stays on the load balancer."
  }
  assert {
    condition     = local.node_environment.STS_TRUST_PROXY == "true" && strcontains(local.node_environment.STS_TRUSTED_PROXIES, "192.0.2.0/24")
    error_message = "The edges must be the trusted peers, or a caller can forge its address."
  }
  assert {
    condition     = strcontains(local.pki_public_url, "direct.test-idp.iyasec.io")
    error_message = "The plain-HTTP revocation listener cannot be reached through CloudFront."
  }
}

run "no_cloudfront_by_default" {
  command = plan
  variables {
    environment      = "dev"
    public_hostname  = "test-idp.iyasec.io"
    public_zone_name = "iyasec.io"
  }
  override_data {
    target = data.terraform_remote_state.certificate[0]
    values = { outputs = {
      certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/c",
      public_hostname = "test-idp.iyasec.io"
    } }
  }
  assert {
    condition     = length(aws_cloudfront_distribution.main) == 0 && aws_route53_record.public[0].type == "CNAME" && local.node_environment.STS_TRUST_PROXY == "false"
    error_message = "Nothing changes without cloudfront_enabled."
  }
}

# CLOUDFRONT IN A MULTI-CELL ENVIRONMENT (#1341): one distribution, the
# primary's, in its `full` phase; the cells' tree at the direct name, which is
# the distribution's origin; every cell admitting the edges and reading the
# global tier's replica of the origin secret.
run "globalidp_primary_holds_the_distribution" {
  command = plan
  variables {
    environment        = "globalidp"
    cell               = "usw2"
    cloudfront_enabled = true
    direct_hostname    = "direct.global-idp.iyasec.io"
  }
  override_data {
    target = data.terraform_remote_state.global[0]
    values = { outputs = {
      primary_address = "p", db_port = 5432, db_name = "sts", db_app_user = "sts_app",
      read_addresses  = {}, master_secret_arn = "m", edge_secret = "s3cret",
      secret_arns     = { usw2 = { "edge-secret" = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/globalidp/edge-secret" } }
    } }
  }
  assert {
    condition     = length(aws_cloudfront_distribution.main) == 1 && one([for o in aws_cloudfront_distribution.main[0].origin : o.domain_name]) == "direct.global-idp.iyasec.io"
    error_message = "The primary's distribution has the cells' tree, at the direct name, as its origin."
  }
  assert {
    condition     = length(aws_route53_record.default) == 1 && aws_route53_record.default[0].name == "global-idp.iyasec.io" && aws_route53_record.default[0].alias[0].evaluate_target_health == false
    error_message = "The public name's default is the distribution."
  }
  assert {
    condition     = aws_route53_record.direct_default[0].name == "direct.global-idp.iyasec.io" && aws_route53_record.direct_default[0].alias[0].name == "cells.direct.global-idp.iyasec.io" && aws_route53_record.latency[0].name == "cells.direct.global-idp.iyasec.io"
    error_message = "The tree is at the direct name."
  }
  assert {
    condition     = length(aws_route53_record.direct) == 0 && length(aws_route53_record.direct_inside) == 1 && length(random_password.edge_secret) == 0
    error_message = "A cell's direct name outside is the tree, and its secret is the global tier's."
  }
  assert {
    condition     = contains([for s in local.node_secrets : s.valueFrom if s.name == "STS_EDGE_SECRET"], "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/globalidp/edge-secret")
    error_message = "The nodes read the global tier's replica of the origin secret."
  }
}

run "globalidp_primary_base_has_no_distribution" {
  command = plan
  variables {
    environment        = "globalidp"
    cell               = "usw2"
    cell_phase         = "base"
    cloudfront_enabled = true
    direct_hostname    = "direct.global-idp.iyasec.io"
  }
  assert {
    condition     = length(aws_cloudfront_distribution.main) == 0 && length(aws_route53_record.default) == 0 && length(aws_route53_record.direct_default) == 1
    error_message = "No distribution before the global tier holds its secret; the direct name's tree is written already."
  }
  assert {
    condition     = length([for s in local.node_secrets : s if s.name == "STS_EDGE_SECRET"]) == 0
    error_message = "An empty valueFrom is dropped in `base`."
  }
}

run "globalidp_cell_behind_cloudfront" {
  command = plan
  variables {
    environment        = "globalidp"
    cell               = "euc1"
    cloudfront_enabled = true
    direct_hostname    = "direct.global-idp.iyasec.io"
  }
  override_data {
    target = data.terraform_remote_state.global[0]
    values = { outputs = {
      primary_address = "p", db_port = 5432, db_name = "sts", db_app_user = "sts_app",
      read_addresses  = {}, master_secret_arn = "m", edge_secret = "s3cret",
      secret_arns     = { euc1 = { "edge-secret" = "arn:aws:secretsmanager:eu-central-1:111122223333:secret:iya-sts/globalidp/edge-secret" } }
    } }
  }
  assert {
    condition     = length(aws_cloudfront_distribution.main) == 0 && length(aws_wafv2_web_acl.allowlist) == 0 && length(aws_route53_record.default) == 0
    error_message = "Only the primary writes the distribution."
  }
  assert {
    condition     = aws_route53_record.pinned["DE"].name == "direct.global-idp.iyasec.io" && aws_route53_record.pinned["DE"].alias[0].name == "eu.cells.direct.global-idp.iyasec.io"
    error_message = "The pins are at the direct name."
  }
  assert {
    condition     = length(aws_security_group.nlb_cloudfront) == 1 && local.node_environment.STS_TRUST_PROXY == "true" && local.node_environment.STS_EDGE_PROXIES == "192.0.2.0/24"
    error_message = "Every cell admits and believes the edges."
  }
  assert {
    condition     = contains([for s in local.node_secrets : s.valueFrom if s.name == "STS_EDGE_SECRET"], "arn:aws:secretsmanager:eu-central-1:111122223333:secret:iya-sts/globalidp/edge-secret")
    error_message = "A cell reads the replica in its own region."
  }
}
