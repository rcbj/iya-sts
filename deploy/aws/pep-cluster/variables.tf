# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

variable "aws_region" {
  description = "The environment's region (a cell's region in a multi-cell environment)."
  type        = string
  default     = "us-west-2"
}

variable "state_region" {
  description = "The state bucket's region."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix every name starts with."
  type        = string
  default     = "iya-sts"
}

variable "environment" {
  description = "The environment this cluster stands on (TF_ENV)."
  type        = string
}

variable "cell" {
  description = "The cell whose load balancer this cluster is on, in a multi-cell environment (#98). Empty for a single-region one."
  type        = string
  default     = ""
}

variable "cluster" {
  description = <<-EOT
    The cluster's name. It is the PEP cluster's name in the service
    (`create-pep-cluster`), the prefix of every member's PEP_NAME and part of
    the state key, so it follows a realm id's grammar and is kept short:
    a member is `<cluster>-pep-<n>`.
  EOT
  type        = string
  default     = "aws"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,11}$", var.cluster))
    error_message = "cluster must be 1-12 characters of [a-z0-9-], starting with a letter or digit."
  }
}

variable "realm" {
  description = "The trust realm the members register to and pull from. Empty is the default realm."
  type        = string
  default     = ""
}

variable "credential_mode" {
  description = <<-EOT
    docs/v1.2.0/remote-pep.md, *One certificate per instance, or one shared*:
      per-instance  one entry and one assertion key per member, a fixed count
                    (`instance_count` ECS services of one task each). Every
                    member is its own row on the console and is nudged on its
                    own notify port.
      shared        one entry and one key for every task of ONE ECS service,
                    which may autoscale (`autoscaling_max`). One row, and the
                    nudge reaches one task; the rest converge on their poll.
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
    instance_count, is no autoscaling. NEEDS foundation/ re-applied by an
    administrator first: the deployer's application-autoscaling grant
    (deploy/aws/CLAUDE.md, *A remote PEP cluster*).
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
  description = "The PEP image's tag in the project repository is `pep-<image_tag>`. Empty: the environment's own image tag."
  type        = string
  default     = ""
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

variable "decision_port" {
  description = "The load balancer port for the decision API and AuthZEN edge PDP (the PEP's 9443). Round robin."
  type        = number
  default     = 9443
}

variable "proxy_port" {
  description = "The load balancer port for the reverse proxy (the PEP's 9543). Sticky by client address."
  type        = number
  default     = 9543
}

variable "notify_port_base" {
  description = <<-EOT
    A member's notify port on the load balancer is notify_port_base + n
    (per-instance; the shared service has one, notify_port_base + 1). Only
    the nodes may reach these ports: they carry the PDP's nudge to ONE
    member's 9443.
  EOT
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
  description = <<-EOF2
    Run the development companion (companion/) beside each member, as a
    second container in the member's task, so the cluster's reverse proxy
    has `/pep-app` to protect: register the route with upstream
    `http://127.0.0.1:9700` (provision.sh --pep-app). A demonstration, off
    by default. It listens on the task's own loopback only as far as any
    caller is concerned: no security group admits 9700, so nothing but the
    member beside it can send it the identity headers it trusts.
  EOF2
  type        = bool
  default     = false
}

variable "companion_image" {
  description = "A whole image reference for the companion, in place of the project repository's `companion-<image_tag>`."
  type        = string
  default     = ""
}
