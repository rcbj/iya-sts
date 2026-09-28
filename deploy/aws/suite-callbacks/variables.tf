# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

variable "aws_region" {
  description = "The environment's region; a cell's own region in a multi-cell environment (entrypoint.sh sets it, #98)."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix. Must match the foundation and environment stacks' `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = "The environment the suite runs against. entrypoint.sh sets it from TF_ENV."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "image_tag" {
  description = "The run's image tag: the task runs `runner-<tag>` and `pep-<tag>` from the project repository, which run-suite.sh builds from the working tree and pushes."
  type        = string
}

variable "task_cpu" {
  description = "Fargate CPU units for the callback task."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate memory (MiB) for the callback task."
  type        = number
  default     = 4096
}

variable "cell" {
  description = <<-EOT
    The cell of a multi-cell environment whose load balancer this is for
    (issue #98; ../environment/cells.tf). EMPTY — the default — is a
    single-cell environment, exactly as before. entrypoint.sh sets it from
    TF_CELL, and sets `aws_region` to that cell's region.
  EOT
  type        = string
  default     = ""
  validation {
    condition     = var.cell == "" || can(regex("^[a-z][a-z0-9]{1,4}$", var.cell))
    error_message = "cell is empty or a cell id (2-5 lower-case letters and digits)."
  }
}

variable "state_region" {
  description = "The state bucket's region — the home region, which a cell's is not (#98)."
  type        = string
  default     = "us-west-2"
}
