# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# The same names as the environment stack's, so the environment's own
# envs/<env>.tfvars and envs/<env>.cells.tfvars.json are this stack's input
# too. The many other variables in those files are not declared here, and
# Terraform says so in one warning and ignores them.

variable "aws_region" {
  description = "The region of a single-cell environment. A cell's is `cells[cell].region`."
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "The environment this certificate is for (entrypoint.sh sets it from TF_ENV)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "cell" {
  description = "The cell this certificate is for; empty in a single-cell environment."
  type        = string
  default     = ""
}

variable "cells" {
  description = "Every cell of the environment, by id, from envs/<env>.cells.tfvars.json. Only `region` is read here."
  type = map(object({
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "")
    cloud                  = optional(string, "aws")
    coordinates            = optional(object({ latitude = string, longitude = string }))
    global_db_cidr         = optional(string, "")
  }))
  default = {}
}

variable "tags" {
  description = "Tags beside Project = STS and Environment, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-certificate"
    # NOT destroy-after-test-run: this stack outlives every environment
    # destroy (main.tf says why).
    Lifecycle = "keep-across-environment-destroys"
  }
}

variable "public_hostname" {
  description = "The name clients use, e.g. `test-idp.iyasec.io`. EMPTY makes this stack hold nothing."
  type        = string
  default     = ""
}

variable "public_zone_name" {
  description = "The public Route53 zone `public_hostname` is in, e.g. `iyasec.io`."
  type        = string
  default     = ""
}
