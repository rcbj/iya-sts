variable "aws_region" {
  description = "The one region this project deploys to."
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
