# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "aws_region" {
  description = "The region the PEP environment is built in."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix every name starts with."
  type        = string
  default     = "iya-sts"
}

variable "environment" {
  description = <<-EOT
    The PEP ENVIRONMENT's own name (TF_ENV), e.g. `testpep`. It is not the
    name of the iya-sts environment the members pull from: this stack reads
    nothing of that one, and reaches it only at `idp_url`, as any customer's
    deployment would.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{2,12}$", var.environment))
    error_message = "environment is 2-12 characters of [a-z0-9]."
  }
}

variable "cluster" {
  description = <<-EOT
    The cluster's name. It is the PEP cluster's name in the service
    (`create-pep-cluster`), the prefix of every member's PEP_NAME and part of
    the state key: a member is `<cluster>-pep-<n>`.
  EOT
  type        = string
  default     = "aws"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,11}$", var.cluster))
    error_message = "cluster must be 1-12 characters of [a-z0-9-], starting with a letter or digit."
  }
}

variable "idp_url" {
  description = <<-EOT
    The identity service the members register with and pull from: its public
    base URL, as every other client of it uses (`https://test-idp.iyasec.io`).
    It must be the service's `publicBaseUrl`, because the token endpoint takes
    only that as a resource (RFC 8707). The service has to admit this
    environment's egress address (output `egress_ip`).
  EOT
  type        = string
}

variable "realm" {
  description = "The trust realm the members register to and pull from. Empty is the default realm."
  type        = string
  default     = ""
}

variable "public_hostname" {
  description = "The name the cluster is reached at: an alias record to its load balancer and the name on its public certificate."
  type        = string
}

variable "public_zone_name" {
  description = "The public Route 53 zone `public_hostname` is written in."
  type        = string
}

variable "allowed_cidrs" {
  description = <<-EOT
    Who may reach the cluster. The load balancer's security group admits them
    on its listeners and the WAF's allowlist rule admits them and nobody else.
  EOT
  type        = list(string)
}

variable "waf_rate_limit" {
  description = "Requests per five minutes one address may send before the WAF blocks it."
  type        = number
  default     = 2000
}

variable "credential_mode" {
  description = <<-EOT
    docs/v1.2.0/remote-pep.md, *One certificate per instance, or one shared*:
      per-instance  one entry and one assertion key per member, a fixed count
                    (`instance_count` ECS services of one task each). Every
                    member is its own row on the console.
      shared        one entry and one key for every task of ONE ECS service,
                    which may autoscale (`autoscaling_max`). One row.
  EOT
  type        = string
  default     = "per-instance"

  validation {
    condition     = contains(["per-instance", "shared"], var.credential_mode)
    error_message = "credential_mode is per-instance or shared."
  }
}

variable "instance_count" {
  description = "per-instance: the number of members. shared: the service's desired count (and the autoscaling minimum)."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 9
    error_message = "instance_count is 1 to 9 (a member's notify port is notify_port_base + n)."
  }
}

variable "autoscaling_max" {
  description = <<-EOT
    shared only: the most tasks Application Auto Scaling may run, by average
    CPU (`autoscaling_cpu_target`). 0, the default, or anything not above
    instance_count, is no autoscaling. Needs foundation/ re-applied by an
    administrator first (the deployer's application-autoscaling grant).
  EOT
  type        = number
  default     = 0
}

variable "autoscaling_cpu_target" {
  description = "shared with autoscaling: the average CPU utilisation, in per cent, the service is scaled to."
  type        = number
  default     = 60
}

variable "image_tag" {
  description = "The PEP image is `pep-<image_tag>` in the project repository (and the companion `companion-<image_tag>`)."
  type        = string
}

variable "pep_image" {
  description = "A whole image reference, in place of the project repository's `pep-<image_tag>` (e.g. iyasec/iya-sts-xacml-pep:1.1.0)."
  type        = string
  default     = ""
}

variable "task_cpu" {
  description = "Fargate CPU units per PEP task."
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate memory (MiB) per PEP task."
  type        = number
  default     = 512
}

variable "vpc_cidr" {
  description = "The environment's VPC. Its own, peered with nothing."
  type        = string
  default     = "10.60.0.0/16"
}

variable "publish_decision_api" {
  description = <<-EOT
    Publish the decision API and the AuthZEN edge PDP (the members' 9443) on
    the load balancer's `decision_port`, behind the same WAF. The load
    balancer ends TLS, so an AuthZEN caller that authenticates with a client
    certificate cannot do so through it; one that uses the pulled caller list
    by token, or a call from inside the VPC, can.
  EOT
  type        = bool
  default     = true
}

variable "decision_port" {
  description = "The load balancer port for the decision API."
  type        = number
  default     = 9443
}

variable "notify_cidrs" {
  description = <<-EOT
    The identity service's EGRESS addresses, when it has fixed ones. With
    any, each member gets a notify listener of its own on the load balancer
    (notify_port_base + n) admitting only these, and advertises it, so a
    policy change nudges every member. EMPTY, the default: no notify
    listener, and provision.sh stops nudging each member's row, so the
    members converge on `poll_interval_ms`. An iya-sts environment's nodes
    leave from task addresses that change on every start, so testidp has no
    such address to give.
  EOT
  type        = list(string)
  default     = []
}

variable "notify_port_base" {
  description = "A member's notify port on the load balancer is notify_port_base + n (with notify_cidrs)."
  type        = number
  default     = 9450
}

variable "health_check_grace_seconds" {
  description = <<-EOT
    How long ECS ignores the load balancer's health checks after a task
    starts. A member provisioned before it ever registered has no HTTPS
    listener pair yet (the realm issues one only to a registered PEP), so
    its 9443 is closed until provision.sh's second pass; this keeps ECS
    from replacing it in the meantime.
  EOT
  type        = number
  default     = 900
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
    second container in the member's task, so the cluster's reverse proxy
    has `/pep-app` to protect: register the route with upstream
    `http://127.0.0.1:9700` (provision.sh --pep-app). A demonstration, off
    by default. No security group admits 9700, so nothing but the member
    beside it can send it the identity headers it trusts.
  EOT
  type        = bool
  default     = false
}

variable "companion_image" {
  description = "A whole image reference for the companion, in place of the project repository's `companion-<image_tag>`."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags on everything, beside the provider's defaults."
  type        = map(string)
  default     = {}
}
