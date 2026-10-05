# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "aws_region" {
  description = <<-EOT
    The HOME region: where this stack, the state bucket, the image repository
    that is pushed to, the multi-region key's primary and every single-cell
    environment live. Other regions are `permitted_regions`.
  EOT
  type        = string
  default     = "us-west-2"
}

variable "permitted_regions" {
  description = <<-EOT
    Every region an environment may deploy to (#98, 2026-09-28): the home
    region and the region of each cell. It replaced the one-region fence
    (`OnlyUsWest2ForRegionalServices`): the deployer's fence, the ARNs its
    policy names and both permissions boundaries cover exactly this list, and
    each region in it gets a cell key, a replica of the global key, a log group
    and a replica of the image repository (modules/region). A region is
    opened by adding it here and having an administrator re-apply.

    ANY COMMERCIAL REGION NAMED area-direction-digit (#367, 2026-09-30):
    each gets its modules/region instance from the one `for_each`
    (regions.tf) and its cell id by the rule in locals.tf. It was four
    regions, each a provider block and a module block written out, until AWS
    provider 6 let one provider reach every region.

    AN OPT-IN REGION MUST BE ENABLED ON THE ACCOUNT FIRST — ap-southeast-5,
    and every region launched since 2019 — which is an administrator's act in
    the console (Account → AWS Regions) or `aws account enable-region`, and
    takes minutes to hours. Until it is, the plan stops at regions.tf's
    `aws_regions` check, naming the region, before anything is made.
  EOT
  type        = list(string)
  # WHAT THE ACCOUNT IS TO HOLD. us-west-2 and ca-central-1 since 2026-09-29
  # (#311, testidpna's cells); since 2026-09-30 (#367) also every region of
  # `globalidp`, the six-region test case: us-east-2, eu-central-1,
  # eu-west-1, ap-southeast-1 and ap-southeast-5. Narrowing the list DESTROYS
  # the dropped regions' cell keys (thirty-day deletion), global-key replicas,
  # log groups and repository replicas at the next apply — do it only once no
  # environment has a cell there.
  default = [
    "us-west-2", "ca-central-1", "us-east-2",
    "eu-central-1", "eu-west-1", "ap-southeast-1", "ap-southeast-5",
  ]
  validation {
    condition = contains(var.permitted_regions, var.aws_region) && alltrue([
      for r in var.permitted_regions :
      can(regex("^[a-z]{2}-(north|south|east|west|central|northeast|northwest|southeast|southwest)-[1-9]$", r))
    ]) && length(distinct(var.permitted_regions)) == length(var.permitted_regions)
    error_message = "permitted_regions must include aws_region, name each region once, and each must be a commercial region of the form area-direction-digit (us-west-2, ap-southeast-5): the cell id is made from that shape (locals.tf)."
  }
}

variable "name" {
  description = <<-EOT
    The prefix every resource name in this project starts with. The deployer
    policy scopes names to it, so changing it after the first apply strands the
    deployer from what it created.
  EOT
  type        = string
  default     = "iya-sts"
}

variable "tags" {
  description = "Tags beside Project = STS, which is always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "iya-sts-foundation"
  }
}

variable "log_retention_days" {
  description = "How long container logs are kept after an environment is gone."
  type        = number
  default     = 14
}

variable "deployer_session_seconds" {
  description = <<-EOT
    The longest session the deployer role issues. A CI run creates RDS (about
    twenty minutes), runs the suite and destroys everything in one job, so an
    hour is not enough and credentials that expire before the destroy leave
    the environment running.
  EOT
  type        = number
  default     = 14400
}

variable "ci_user_name" {
  description = <<-EOT
    The IAM user GitHub Actions authenticates as (.github/workflows/aws-cluster.yml),
    named in the account's git_userN series. Like git_user5, it has no console
    login, no groups and one inline policy: assume the deployer role. Its access
    key is created by hand so the secret never lands in Terraform state.
  EOT
  type        = string
  default     = "git_user6"
}

variable "public_dns" {
  description = <<-EOT
    The public Route53 zones an environment may write in, and the record names
    it may write there (environment/dns.tf: a CNAME and the ACM validation
    record, which is `_<random>.<name>`). The deployer may change nothing else
    in those zones and nothing at all in any other.

    A MULTI-CELL ENVIRONMENT (#98) writes the SAME two names: the geolocation
    records are the public name itself, and the latency sets they fall
    through to — `cells.<name>`, one `<jurisdiction>.cells.<name>` per
    jurisdiction (#367) — and each cell's own `<cell>.<name>` are under the
    wildcard. What it adds is health checks, which have no name to scope by
    (iam_deployer.tf, `Route53HealthChecks`).

    `global-idp.iyasec.io` is `globalidp`'s, the six-region test case
    (#367, 2026-09-30): a name of its own, so it stands beside testidp or
    testidpna rather than taking their name in turn.
  EOT
  type        = map(list(string))
  default = {
    "iyasec.io" = [
      "test-idp.iyasec.io", "*.test-idp.iyasec.io",
      "global-idp.iyasec.io", "*.global-idp.iyasec.io",
    ]
  }
}
