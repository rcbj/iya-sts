# ---------------------------------------------------------------------------
# ONE THREE-NODE mock-sts ENVIRONMENT, CREATED AND DESTROYED PER RUN (issue #51).
#
# Applied as the `mock-sts-deployer` role, never as an administrator: the
# deployer's policy (../foundation/iam_deployer.tf) is the proof that this
# stack needs no more than it grants. Everything here depends on the
# long-lived foundation stack existing first.
#
# The state key names the environment, so `dev` and `ci` never share state:
#   terraform init -backend-config="bucket=mock-sts-terraform-state-<account>" \
#                  -backend-config="key=environment/dev.tfstate"
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
