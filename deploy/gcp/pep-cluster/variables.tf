# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# deploy/aws/pep-cluster/variables.tf's variables, with AWS's names and
# defaults where there is a counterpart. What differs is said on the
# variable: GCP's global load balancer publishes 80 and 443 only, so the
# decision API and the nudge are told apart by HOST NAME, not by port.

variable "project_id" {
  description = "The project the foundation was applied to."
  type        = string
}

variable "region" {
  description = "The region the PEP environment is built in."
  type        = string
  default     = "us-west1"
}

variable "name" {
  description = "The project prefix every name starts with."
  type        = string
  default     = "iya-sts"
}

variable "labels" {
  description = "Labels on everything, beside the provider's defaults."
  type        = map(string)
  default = {
    managed-by = "terraform"
  }
}

variable "environment" {
  description = <<-EOT
    The PEP ENVIRONMENT's own name (TF_ENV), e.g. `testpep`. It must be in the
    foundation's `pep_environments`, which made the service account its
    members run as. It is not the name of the iya-sts environment the members
    pull from: this stack reads nothing of that one.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "cluster" {
  description = "The cluster's name: the PEP cluster's name in the service, and the prefix of every member's PEP_NAME (`<cluster>-pep-<n>`)."
  type        = string
  default     = "aws"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,11}$", var.cluster))
    error_message = "cluster must be 1-12 characters of [a-z0-9-], starting with a letter (it is in GCP resource names)."
  }
}

variable "idp_url" {
  description = "The identity service the members register with and pull from: its publicBaseUrl (the token endpoint takes only that as a resource, RFC 8707). It must admit this environment's `egress_ip`."
  type        = string
}

variable "realm" {
  description = "The trust realm the members register to and pull from. Empty is the default realm."
  type        = string
  default     = ""
}

variable "public_hostname" {
  description = "The name the reverse proxy is reached at, inside `dns_zone_name`, on the load balancer's Google-managed certificate."
  type        = string
}

variable "dns_zone_name" {
  description = "The public Cloud DNS zone the foundation made, by its DNS name."
  type        = string
  default     = "gcp.iyasec.io"
}

variable "allowed_cidrs" {
  description = "Who may reach the cluster: the Cloud Armor allowlist rule admits them and nobody else. No default, deliberately (AWS's argument)."
  type        = list(string)
}

variable "waf_rate_limit" {
  description = "Requests per minute one address may send before Cloud Armor answers 429."
  type        = number
  default     = 400
}

variable "credential_mode" {
  description = "per-instance: one member, one instance group of one VM, one entry and key each. shared: one regional instance group of `instance_count` VMs sharing one entry and key, autoscaled with `autoscaling_max`."
  type        = string
  default     = "per-instance"

  validation {
    condition     = contains(["per-instance", "shared"], var.credential_mode)
    error_message = "credential_mode is per-instance or shared."
  }
}

variable "instance_count" {
  description = "per-instance: the number of members. shared: the group's size (and the autoscaling minimum)."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 9
    error_message = "instance_count is 1 to 9."
  }
}

variable "autoscaling_max" {
  description = "shared only: the most VMs the autoscaler may run, by average CPU. 0, or anything not above instance_count, is no autoscaler."
  type        = number
  default     = 0
}

variable "autoscaling_cpu_target" {
  description = "shared with autoscaling: the average CPU utilisation, 0 to 1, the group is scaled to."
  type        = number
  default     = 0.6
}

variable "image_tag" {
  description = "The PEP image is `pep-<image_tag>`, the companion `companion-<image_tag>` and node-init `init-<image_tag>` in the project's Artifact Registry repository."
  type        = string
}

variable "pep_image" {
  description = "A whole image reference, in place of the repository's `pep-<image_tag>`."
  type        = string
  default     = ""
}

variable "machine_type" {
  description = "Each member's machine type."
  type        = string
  default     = "e2-small"
}

variable "boot_disk_gib" {
  description = "Each member's boot disk."
  type        = number
  default     = 20
}

variable "subnet_cidr" {
  description = "The members' subnet. Its own VPC, peered with nothing."
  type        = string
  default     = "10.61.0.0/24"
}

variable "publish_decision_api" {
  description = <<-EOT
    Publish the decision API and the AuthZEN edge PDP (the members' 9443) at
    `decision_hostname`, behind the same Cloud Armor policy. The load
    balancer ends TLS, so an AuthZEN caller that authenticates with a client
    certificate cannot do so through it.
  EOT
  type        = bool
  default     = true
}

variable "decision_hostname" {
  description = "Where the decision API is published (GCP's global load balancer serves 443 only, so it is a name rather than AWS's port 9443). Required with publish_decision_api."
  type        = string
  default     = ""
}

variable "notify_cidrs" {
  description = <<-EOT
    The identity service's EGRESS addresses, when it has fixed ones. With
    any, each member gets a notify name of its own,
    `<member>.<public_hostname>`, routed to that member's 9443 alone and
    admitted only from these (a Cloud Armor policy of its own), and
    advertises it. EMPTY, the default: no notify name, and provision.sh stops
    nudging each member's row, so the members converge on their poll.
  EOT
  type        = list(string)
  default     = []
}

variable "health_check_grace_seconds" {
  description = "How long autohealing leaves a new member alone: until provision.sh's second pass a member has no HTTPS listener (the realm issues the pair only to a registered PEP)."
  type        = number
  default     = 900
}

variable "poll_interval_ms" {
  description = "PEP_POLL_INTERVAL_MS: how often each member pulls when it is not nudged."
  type        = number
  default     = 15000
}

variable "extra_environment" {
  description = "More PEP_* settings for every member. Not secrets."
  type        = map(string)
  default     = {}
}

variable "companion" {
  description = "Run the development companion's /pep-app beside each member, in the member's network namespace, so the route's upstream http://127.0.0.1:9700 is each member's own. No firewall rule admits 9700."
  type        = bool
  default     = false
}

variable "companion_image" {
  description = "A whole image reference for the companion, in place of the repository's `companion-<image_tag>`."
  type        = string
  default     = ""
}
