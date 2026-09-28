# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

locals {
  project_tag = "STS"
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  region      = var.aws_region

  # EVERY REGION AN ENVIRONMENT MAY USE (#98, 2026-09-28): the home region and
  # the regions of the cells. The deployer's region fence, its ARNs and the two
  # boundaries all cover exactly this list, so a region is opened by adding it
  # here and re-applying, and by nothing else.
  regions = var.permitted_regions

  # THE CELL A REGION HOLDS. A cell's id names its region — it is the unit of
  # data residency, and one cell per region is the design (issue #98, §2) —
  # so the table is fixed, and a region absent from it has no provider below
  # (providers.tf) and cannot be permitted (variables.tf).
  cell_of_region = {
    "us-west-2"      = "usw2"
    "ca-central-1"   = "cac1"
    "eu-central-1"   = "euc1"
    "ap-southeast-1" = "apse1"
  }

  # THE SAME ARN PREFIX IN EVERY PERMITTED REGION, per service:
  #   rarn.rds = ["arn:aws:rds:us-west-2:<account>", "arn:aws:rds:ca-central-1:<account>"]
  # A statement that names a regional resource names it in each of them; with
  # the default (one region) every list has one element and renders exactly as
  # the single ARN did before.
  rarn = {
    for svc in [
      "secretsmanager", "logs", "rds", "ecs", "ec2", "elasticloadbalancing",
      "acm", "ecr", "servicediscovery",
    ] : svc => [for r in local.regions : "arn:${local.partition}:${svc}:${r}:${local.account_id}"]
  }

  state_bucket   = "${var.name}-terraform-state-${local.account_id}"
  reports_bucket = "${var.name}-test-reports-${local.account_id}"

  # Names the environment stack creates, spelt here because the deployer policy
  # and the permissions boundary scope to them. Keep in step with
  # ../environment/locals.tf.
  env_role_prefix   = "${var.name}-env-"
  secret_prefix     = "${var.name}/"
  container_log_grp = "/${var.name}/containers"

  arn = {
    iam_role     = "arn:${local.partition}:iam::${local.account_id}:role"
    iam_policy   = "arn:${local.partition}:iam::${local.account_id}:policy"
    secret       = "arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret"
    logs         = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group"
    rds          = "arn:${local.partition}:rds:${local.region}:${local.account_id}"
    ecs          = "arn:${local.partition}:ecs:${local.region}:${local.account_id}"
    ec2          = "arn:${local.partition}:ec2:${local.region}:${local.account_id}"
    elb          = "arn:${local.partition}:elasticloadbalancing:${local.region}:${local.account_id}"
    ecr_repo     = "arn:${local.partition}:ecr:${local.region}:${local.account_id}:repository/${var.name}"
    acm          = "arn:${local.partition}:acm:${local.region}:${local.account_id}:certificate/*"
    state_bucket = "arn:${local.partition}:s3:::${local.state_bucket}"
    reports      = "arn:${local.partition}:s3:::${local.reports_bucket}"
  }
}
