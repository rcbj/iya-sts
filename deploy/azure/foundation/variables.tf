# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "subscription_id" {
  description = <<-EOT
    The Azure subscription the whole iya-sts deployment lives in. A
    SUBSCRIPTION OF ITS OWN is best, as GCP's project is: the deployer's
    custom role is assignable at this subscription and granted only on the
    resource groups this stack makes (iam_deployer.tf), but a subscription
    shared with other work shares its quotas, its provider registrations and
    its owners.
  EOT
  type        = string
}

variable "home_region" {
  description = "The home region: the registry, the public DNS zone, and every single-cell environment (West US 2, beside AWS's us-west-2 and GCP's us-west1)."
  type        = string
  default     = "westus2"
}

variable "name" {
  description = "The prefix every resource name starts with. Must match the environment and global stacks' `name`."
  type        = string
  default     = "iya-sts"
}

variable "tags" {
  description = "Tags beside Project = STS, which is always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
  }
}

variable "environments" {
  description = <<-EOT
    EVERY ENVIRONMENT THAT MAY BE BUILT, and its public name if it has one.

    An environment with a CELLS FILE — ../environment/envs/<env>.cells.tfvars.json
    — is multi-region (#98): each of its cells gets what a single-cell
    environment gets, in the cell's region, and the environment gets a
    `global` resource group in its primary cell's region besides. Every
    other environment is single-cell, in `home_region`.

    What each gets here, because the deployer may make none of it
    (iam_deployer.tf): a resource group, the managed identity its nodes run
    as, the Key Vault its secrets and certificate are kept in, and the grants
    that tie them together. An environment not listed cannot be applied: its
    resource group does not exist, and the deployer's role is granted on
    nothing else. Adding one is an administrator's re-apply, as a new
    `public_dns` name is on AWS.

    `public_hostname` must be inside `dns_zone_name`. A multi-region
    environment's is in its cells file instead, beside its cells, because
    every stack of the environment reads that file.
  EOT
  type = map(object({
    public_hostname = optional(string, "")
  }))
  default = {
    dev     = {}
    ci      = {}
    testidp = { public_hostname = "test-idp.azure.iyasec.io" }
    # Multi-region: their names are in their cells files.
    testidpna = {}
    globalidp = {}
  }
  validation {
    condition = alltrue([
      for k, v in var.environments : can(regex("^[a-z][a-z0-9]{1,11}$", k))
    ])
    error_message = "An environment name is 2-12 lower-case letters and digits, starting with a letter (the AWS rule)."
  }
  validation {
    condition = alltrue([
      for k, v in var.environments :
      v.public_hostname == "" || endswith(v.public_hostname, ".${var.dns_zone_name}")
    ])
    error_message = "Every public_hostname must be a name inside dns_zone_name."
  }
}

variable "dns_zone_name" {
  description = <<-EOT
    The public zone this subscription answers: a SUB-DOMAIN of iyasec.io,
    delegated to Azure DNS by an NS record in the Route 53 zone that AWS
    keeps managing (deploy/azure/dns-delegation/). Never the apex.
  EOT
  type        = string
  default     = "azure.iyasec.io"
}

variable "deployer_principal_ids" {
  description = <<-EOT
    The Entra ID OBJECT IDS that hold the deployer's grants (iam_deployer.tf):
    a person, a group of people, or — later — a workflow's service principal
    with a federated credential. A GROUP is the arrangement to prefer, so that
    adding a person is a membership rather than a re-apply. Empty means
    nobody but a subscription owner can apply an environment.
  EOT
  type        = list(string)
  default     = []
}

variable "extra_regions" {
  description = <<-EOT
    Regions to prepare beyond those the environments use — a key vault and
    keys, the disk-encryption sets, a log workspace and a registry replica
    each — so a cell can be added in one without this stack first. Every
    region must be in `local.region_codes` (locals.tf).
  EOT
  type        = list(string)
  default     = []
}

variable "state_resource_group" {
  description = "The resource group bootstrap-state.sh made the state account in."
  type        = string
  default     = "iya-sts-terraform-state"
}

variable "state_storage_account" {
  description = "The state storage account bootstrap-state.sh made (it prints the name)."
  type        = string
}

variable "log_retention_days" {
  description = "How long container logs are kept after an environment is gone. Thirty is Log Analytics' minimum (AWS and GCP keep fourteen)."
  type        = number
  default     = 30
  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days is 30 to 730, Log Analytics' own range."
  }
}

variable "key_rotation_days" {
  description = "Each customer-managed key rotates automatically this many days after its current version was made (Key Vault's own rotation policy)."
  type        = number
  default     = 90
}
