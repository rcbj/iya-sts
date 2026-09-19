provider "aws" {
  region = var.aws_region

  # Project = STS is not optional: the deployer role may only create EC2
  # resources — security-group rules among them — that carry it. Realm is
  # what tells one realm's rules and target groups from another's.
  default_tags {
    tags = {
      Project     = "STS"
      Environment = var.environment
      Realm       = var.realm
    }
  }
}

data "aws_caller_identity" "current" {}
