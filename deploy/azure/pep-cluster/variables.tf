# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "subscription_id" {
  description = "The subscription the foundation was applied to (entrypoint.sh passes it)."
  type        = string
}

variable "name" {
  description = "The project prefix every name starts with."
  type        = string
  default     = "iya-sts"
}

variable "environment" {
  description = <<-EOT
    The PEP ENVIRONMENT's own name (TF_ENV), e.g. `testpep`: a row of the
    foundation's `pep_environments`, never of its `environments`. It is not
    the iya-sts environment the members pull from; this stack reads nothing
    of that one, and reaches it only at `idp_url`.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "region" {
  description = "The foundation's home_region, where it made this environment's group, identities and vault."
  type        = string
  default     = "westus2"
}

variable "cluster" {
  description = <<-EOT
    The cluster's name: the PEP cluster's name in the service
    (`create-pep-cluster`), the prefix of every member's PEP_NAME and part of
    the state key. A member is `<cluster>-pep-<n>`.
  EOT
  type        = string
  default     = "azure"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,11}$", var.cluster))
    error_message = "cluster must be 1-12 characters of [a-z0-9-], starting with a letter or digit."
  }
}

variable "idp_url" {
  description = <<-EOT
    The identity service the members register with and pull from, at its
    public base URL (`https://test-idp.azure.iyasec.io`). It must be the
    service's `publicBaseUrl`: the token endpoint takes only that as an
    RFC 8707 resource. The service must admit `egress_ip`.
  EOT
  type        = string
}

variable "realm" {
  description = "The trust realm the members register to and pull from. Empty is the default realm."
  type        = string
  default     = ""
}

variable "public_hostname" {
  description = "The cluster's name: an A record to the gateway's address, and the name on its listener certificate. Must be the foundation's `pep_environments` name for this environment."
  type        = string
}

variable "dns_zone_name" {
  description = "The foundation's public zone."
  type        = string
  default     = "azure.iyasec.io"
}

variable "allowed_cidrs" {
  description = "Who may reach the cluster: the gateway's security group admits them, and the WAF blocks everybody else."
  type        = list(string)
}

variable "waf_rate_limit" {
  description = "Requests per five minutes one client address may send before the WAF blocks it."
  type        = number
  default     = 2000
}

variable "waf_body_limit_kb" {
  description = <<-EOT
    The largest request body the WAF accepts and inspects, in KB (CRS 3.2's
    request-body limit and inspection limit). The proxy forwards an
    application's own POSTs, so this is a guess about that application; a
    larger one is refused with a 413.
  EOT
  type        = number
  default     = 128
}

variable "waf_file_upload_limit_mb" {
  description = "The largest multipart upload the WAF lets through, in MB."
  type        = number
  default     = 100
}

variable "credential_mode" {
  description = <<-EOT
    docs/v1.2.0/remote-pep.md, *One certificate per instance, or one shared*:
      per-instance  one entry and one assertion key per member, a fixed count:
                    `instance_count` scale sets of one VM each. Every member a
                    row on the console.
      shared        one entry and one key for every VM of ONE scale set,
                    which may autoscale (`autoscale_max`). One row.
  EOT
  type        = string
  default     = "per-instance"

  validation {
    condition     = contains(["per-instance", "shared"], var.credential_mode)
    error_message = "credential_mode is per-instance or shared."
  }
}

variable "instance_count" {
  description = "per-instance: the number of members. shared: the scale set's instance count (and the autoscale minimum)."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 9
    error_message = "instance_count is 1 to 9 (a member's notify port is notify_port_base + n)."
  }
}

variable "autoscale_max" {
  description = <<-EOT
    shared only: the most VMs Azure Monitor autoscale may run, by average CPU.
    0, the default, or anything not above instance_count, is no autoscale.
    Needs the foundation re-applied first (the deployer's
    `Microsoft.Insights/autoscaleSettings/*`).
  EOT
  type        = number
  default     = 0
}

variable "autoscale_cpu_target" {
  description = "shared with autoscale: scale out above this average CPU, in per cent, and in below half of it."
  type        = number
  default     = 60
}

variable "image_tag" {
  description = "The PEP image is `pep-<image_tag>` in the foundation's registry, the companion `companion-<image_tag>` and node-init `init-<image_tag>`."
  type        = string
}

variable "pep_image" {
  description = "A whole image reference, in place of the registry's `pep-<image_tag>` (e.g. iyasec/iya-sts-xacml-pep:1.1.0)."
  type        = string
  default     = ""
}

variable "vm_size" {
  description = "Each member VM's size. Docker, the PEP and (with the companion) node fit in a B2s."
  type        = string
  default     = "Standard_B2s"
}

variable "vnet_cidr" {
  description = "The environment's VNet. Its own, peered with nothing."
  type        = string
  default     = "10.62.0.0/16"
}

variable "publish_decision_api" {
  description = <<-EOT
    Publish the decision API and the AuthZEN edge PDP (the members' 9443) on
    the gateway's `decision_port`, behind the same WAF. The gateway ends TLS,
    so an AuthZEN caller that authenticates with a client certificate cannot
    do so through it.
  EOT
  type        = bool
  default     = true
}

variable "decision_port" {
  description = "The gateway port for the decision API."
  type        = number
  default     = 9443
}

variable "notify_cidrs" {
  description = <<-EOT
    The identity service's EGRESS addresses, when it has fixed ones. With
    any, each member gets a notify listener of its own on the gateway
    (notify_port_base + n), admitted from these only, and advertises it, so
    a policy change nudges every member. EMPTY, the default: no notify
    listener, provision.sh stops nudging each member's row, and the members
    converge on `poll_interval_ms`. An Azure iya-sts environment DOES have a
    fixed egress address (its load balancer's outbound rule, deploy/azure/
    CLAUDE.md), so it can be named here.
  EOT
  type        = list(string)
  default     = []
}

variable "notify_port_base" {
  description = "A member's notify port on the gateway is notify_port_base + n (with notify_cidrs)."
  type        = number
  default     = 9450
}

variable "repair_grace" {
  description = <<-EOT
    How long a member VM failing its health check is left before the scale
    set replaces it (ISO 8601, PT10M-PT90M). A member provisioned before it
    ever registered has no HTTPS listener pair yet (the realm issues one only
    to a registered PEP), so its 9443 is closed until provision.sh's second
    pass; this keeps the scale set from replacing it in the meantime (AWS's
    health_check_grace_seconds).
  EOT
  type        = string
  default     = "PT60M"
}

variable "poll_interval_ms" {
  description = "PEP_POLL_INTERVAL_MS: how often each member pulls when it is not nudged."
  type        = number
  default     = 15000
}

variable "extra_environment" {
  description = "More PEP_* settings for every member (docs/v1.2.0/remote-pep.md, *Configuration*). Not secrets."
  type        = map(string)
  default     = {}
}

variable "companion" {
  description = <<-EOT
    Run the development companion (companion/) beside each member, as a
    second container on the VM, so the cluster's reverse proxy has `/pep-app`
    to protect: register the route with upstream `http://127.0.0.1:9700`
    (provision.sh --pep-app). A demonstration, off by default. No security
    group admits 9700, so nothing but the member beside it can send it the
    identity headers it trusts.
  EOT
  type        = bool
  default     = false
}

variable "companion_image" {
  description = "A whole image reference for the companion, in place of the registry's `companion-<image_tag>`."
  type        = string
  default     = ""
}

variable "member_trust_anchor" {
  description = <<-EOT
    The identity service's Root, PEM — what the gateway verifies each
    member's listener certificate against (Application Gateway v2 refuses an
    HTTPS backend whose chain it cannot verify). PUBLIC: provision.sh's
    second pass writes it to anchors/<env>.crt, and terraform-local.sh hands
    that file over as this variable. Empty until then: the gateway is built,
    and its backends stay unhealthy until a second apply carries it.
  EOT
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "The ACME account's contact address, for the gateway's listener certificate."
  type        = string
  default     = ""
}

variable "acme_server" {
  description = "The ACME directory. Let's Encrypt's staging directory saves the week's limit while a new environment is tried."
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "acme_renew_days" {
  description = "Member 1 renews the listener certificate when fewer than this many days are left, at its next start."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags on everything this stack makes."
  type        = map(string)
  default     = {}
}
