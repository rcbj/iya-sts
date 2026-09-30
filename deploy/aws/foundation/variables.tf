# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

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

    ONLY THE FOUR REGIONS THE DESIGN NAMES ARE ACCEPTED — us-west-2 (usw2),
    ca-central-1 (cac1), eu-central-1 (euc1), ap-southeast-1 (apse1) — because
    Terraform cannot create a provider per list element: each has a provider
    block and a module block written out in providers.tf and regions.tf. A
    fifth region is those two blocks and a row in `locals.tf`'s
    `cell_of_region`, then an entry here.
  EOT
  type        = list(string)
  # BOTH REGIONS SINCE 2026-09-29 (#311): the foundation was applied with
  # ca-central-1 for testidpna's cac1 cell, and this is the value the account
  # now holds. A default of us-west-2 alone would make the next foundation
  # apply from any checkout DESTROY ca-central-1's cell key, global-key
  # replica, log group and repository replica. Narrow it only on purpose.
  default = ["us-west-2", "ca-central-1"]
  validation {
    condition = contains(var.permitted_regions, var.aws_region) && alltrue([
      for r in var.permitted_regions :
      contains(["us-west-2", "ca-central-1", "eu-central-1", "ap-southeast-1"], r)
    ])
    error_message = "permitted_regions must include aws_region, and each entry must be one of us-west-2, ca-central-1, eu-central-1, ap-southeast-1 (the regions with a provider block)."
  }
}

variable "name" {
  description = <<-EOT
    The prefix every resource name in this project starts with. The deployer
    policy scopes names to it, so changing it after the first apply strands the
    deployer from what it created.
  EOT
  type        = string
  default     = "mock-sts"
}

variable "tags" {
  description = "Tags beside Project = STS, which is always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-foundation"
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
    records are `test-idp.iyasec.io` itself, and the latency set they fall
    through to is `cells.test-idp.iyasec.io`, which the wildcard already
    covers. What it adds is health checks, which have no name to scope by
    (iam_deployer.tf, `Route53HealthChecks`).
  EOT
  type        = map(list(string))
  default = {
    "iyasec.io" = ["test-idp.iyasec.io", "*.test-idp.iyasec.io"]
  }
}
