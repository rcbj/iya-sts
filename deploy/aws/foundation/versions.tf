# ---------------------------------------------------------------------------
# THE LONG-LIVED HALF (issue #51).
#
# What an environment needs and must not re-create on every run: the project's
# deployer identity, the KMS key everything is encrypted with, the image
# repository, and the log group and test report bucket that outlive every
# environment. Applied ONCE,
# by an administrator, because it creates the identity every later apply runs
# as — the deployer cannot create itself.
#
# `environment/` is the other half and is created and destroyed per run.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # The bucket is created by ../bootstrap-state.sh, not by Terraform. The key is
  # this stack's alone; `environment/` keys its state by environment name.
  backend "s3" {
    key          = "foundation/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
