# ---------------------------------------------------------------------------
# ONE TRUST REALM'S SPIFFE PORTS ON AN ENVIRONMENT'S LOAD BALANCER
# (2026-09-18). A stack of its own, applied once per realm AFTER the realm
# exists and after `environment/` is up: it adds listeners, target groups and
# security-group rules to what that stack built, and changes nothing of it.
#
# The state key names the environment AND the realm, so two realms never
# share state and destroying one realm's ports leaves every other's alone.
# It is under `environment/` because that is the one prefix the deployer role
# may write state under (foundation/iam_deployer.tf, TerraformStateObjects):
#   terraform init -backend-config="bucket=mock-sts-terraform-state-<account>" \
#                  -backend-config="key=environment/testidp/spiffe-realm/acme.tfstate"
# entrypoint.sh builds that key from TF_ENV and TF_REALM.
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
