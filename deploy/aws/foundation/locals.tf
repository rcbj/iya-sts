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

  # THE CELL A REGION HOLDS, BY RULE (#367, 2026-09-30). A cell's id names
  # its region — it is the unit of data residency, and one cell per region is
  # the design (issue #98, section 2) — and it is the region's name shortened:
  # the area, the direction's initials and the number, so us-west-2 is usw2,
  # eu-central-1 euc1, ap-southeast-5 apse5. It was a table of the four
  # regions #98 named, which made a fifth region a code change; the rule makes
  # it a list entry. A cell id is at most five characters (the names it goes
  # into are limited to 32), which a one-digit region number keeps it within —
  # variables.tf refuses any other shape.
  #
  # THE SAME RULE IS IN THREE VALIDATIONS — ../environment/cells.tf and
  # ../global/variables.tf, `cells` — because a variable's validation can see
  # no local. Keep the four in step.
  region_direction = {
    north     = "n", south = "s", east = "e", west = "w", central = "c",
    northeast = "ne", northwest = "nw", southeast = "se", southwest = "sw",
  }
  cell_of_region = {
    for r in local.regions : r => join("", [
      split("-", r)[0], local.region_direction[split("-", r)[1]], split("-", r)[2],
    ])
  }

  # EVERY REGIONAL ARN PREFIX, per service, WITH THE REGION A WILDCARD
  # (#367, 2026-09-30):
  #   rarn.rds = ["arn:aws:rds:*:<account>"]
  # The regions are held to `permitted_regions` by the REGION FENCE instead —
  # the deployer's `region-fence` policy and the same Deny inside both
  # boundaries (`region_fence_statement`, iam_deployer.tf) — which says it
  # once for every statement. Until #367 each prefix was written out once
  # per permitted region, so every regional statement grew with the list:
  # at seven regions the deployer's data policy rendered 8,804 characters
  # against IAM's 6,144 for a managed policy (5,621 at two), and no apply
  # could have added a sixth cell. The permission is the same — an action
  # the fence denies is denied whatever the ARN says — and a policy's size
  # no longer depends on how many regions there are. Still a list of one, so
  # the statements that iterate it are unchanged.
  rarn = {
    for svc in [
      "secretsmanager", "logs", "rds", "ecs", "ec2", "elasticloadbalancing",
      "acm", "ecr", "servicediscovery",
    ] : svc => ["arn:${local.partition}:${svc}:*:${local.account_id}"]
  }

  # THE SERVICES THE REGION FENCE EXEMPTS: global ones, whose requests carry
  # us-east-1 (Route 53) or no region a fence could compare.
  fence_exempt = ["iam:*", "sts:*", "s3:*", "route53:*"]

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

  # The SES identities an environment may create and send as (#311): every
  # public name in `public_dns` that is a name rather than a wildcard.
  ses_identity_arns = [
    for n in distinct(flatten(values(var.public_dns))) :
    "arn:${local.partition}:ses:${local.region}:${local.account_id}:identity/${n}"
    if !startswith(n, "*")
  ]
  ses_from_patterns = [
    for n in distinct(flatten(values(var.public_dns))) : "*@${n}"
    if !startswith(n, "*")
  ]
}
