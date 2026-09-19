# ---------------------------------------------------------------------------
# THE SUITE'S CALLBACK TASK FOR ONE RUN AGAINST AN ENVIRONMENT (2026-09-18).
# Created and destroyed by deploy/aws/run-suite.sh around each run; main.tf
# argues why it exists.
#
# The state key names the environment, under `environment/` because that is
# the one prefix the deployer role may write state under
# (foundation/iam_deployer.tf, TerraformStateObjects):
#   terraform init -backend-config="bucket=mock-sts-terraform-state-<account>" \
#                  -backend-config="key=environment/testidp/suite-callbacks.tfstate"
# entrypoint.sh builds that key from TF_ENV.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
