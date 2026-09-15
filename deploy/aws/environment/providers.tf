provider "aws" {
  region = var.aws_region

  # Project = STS is not optional: the deployer role may only create EC2
  # resources that carry it, and may only change or delete ones that do.
  default_tags {
    tags = merge(var.tags, {
      Project     = "STS"
      Environment = var.environment
    })
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
