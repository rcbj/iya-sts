# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "project_id" {
  description = <<-EOT
    The GCP project the whole iya-sts deployment lives in. A PROJECT OF ITS
    OWN, deliberately: GCP has no permissions boundary, and the deployer's
    project-level roles (iam_deployer.tf) are bounded by the project they are
    granted in. Sharing it with anything else widens the deployer to that too.
  EOT
  type        = string
}

variable "region" {
  description = "The home region: the key ring, the image repository, the log bucket and every environment (us-west1, Oregon, beside AWS's us-west-2)."
  type        = string
  default     = "us-west1"
}

variable "name" {
  description = "The prefix every resource name starts with. Must match the environment stack's `name`."
  type        = string
  default     = "iya-sts"
}

variable "labels" {
  description = "Labels beside project = sts, which is always added."
  type        = map(string)
  default = {
    managed-by = "terraform"
  }
}

variable "environments" {
  description = <<-EOT
    EVERY ENVIRONMENT THAT MAY BE BUILT, and its public name if it has one.
    Each gets a node service account here (identities.tf) — the deployer
    cannot create one (iam_deployer.tf) — and one with a `public_hostname`
    gets the secret its ACME certificate is kept in (tls_secrets.tf) and the
    right to answer the DNS-01 challenge for it. An environment not listed
    cannot be applied: its service account does not exist. Adding one is an
    administrator's re-apply, as a new `public_dns` name is on AWS.

    `public_hostname` must be inside `dns_zone_name`.
  EOT
  type = map(object({
    public_hostname = optional(string, "")
  }))
  default = {
    dev     = {}
    ci      = {}
    testidp = { public_hostname = "test-idp.gcp.iyasec.io" }
  }
  validation {
    condition = alltrue([
      for k, v in var.environments : can(regex("^[a-z][a-z0-9]{1,11}$", k))
    ])
    error_message = "An environment name is 2-12 lower-case letters and digits, starting with a letter (the AWS rule)."
  }
}

variable "dns_zone_name" {
  description = <<-EOT
    The public zone this project answers: a SUB-DOMAIN of iyasec.io, delegated
    to Cloud DNS by an NS record in the Route 53 zone that AWS keeps managing
    (deploy/gcp/dns-delegation/). Never the apex.
  EOT
  type        = string
  default     = "gcp.iyasec.io"
}

variable "deployer_members" {
  description = <<-EOT
    Who may ACT AS the deployer service account (roles/iam.serviceAccountTokenCreator
    on it), e.g. ["user:someone@example.com"]. The deployer has no key: a person
    impersonates it (terraform-local.sh), and a workflow would through Workload
    Identity Federation, which is not built yet. Empty means nobody but a project
    owner can use it.
  EOT
  type        = list(string)
  default     = []
}

variable "state_bucket" {
  description = "The state bucket bootstrap-state.sh made. Empty means iya-sts-terraform-state-<project>."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "How long container logs are kept after an environment is gone."
  type        = number
  default     = 14
}

variable "kms_rotation_period" {
  description = "How often the project key rotates (Cloud KMS's own automatic rotation)."
  type        = string
  default     = "7776000s"
}

variable "multicell_environments" {
  description = <<-EOT
    THE MULTI-CELL, MULTI-CLOUD ENVIRONMENTS (#97), by name. Each is read from
    deploy/multicloud/envs/<env>.cells.tfvars.json — the one file every stack
    of the environment reads — and gets here what the deployer may not make:
    a node service account and a certificate secret per GCP cell, a key ring
    in each GCP cell's region, the one global VPC the GCP cells share, its
    private-services ranges (the global tier's Cloud SQL copies), and the
    private DNS zones the cells find each other by (network_multicell.tf).
  EOT
  type        = list(string)
  default     = ["testidpmc"]
}
