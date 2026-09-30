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

# SIZED FOR THE WHOLE SUITE (#311, 2026-09-28): with STS_SUITE_IN_AWS=1 this
# task runs every job, Chrome and the 5000-person bulk loads among them, which
# 1 vCPU / 4 GiB does not hold. The task lives for one run, so the larger size
# costs cents even when it runs only the two callback jobs.
variable "task_cpu" {
  description = "Fargate CPU units for the callback task."
  type        = number
  default     = 4096
}

variable "task_memory" {
  description = "Fargate memory (MiB) for the callback task."
  type        = number
  default     = 16384
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
