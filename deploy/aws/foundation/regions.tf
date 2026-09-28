# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# WHAT EVERY PERMITTED REGION HOLDS (#98, 2026-09-28) — modules/region, once
# per region, with the provider for that region.
#
#   a CELL key          single-region, never replicated: the cell's own
#                       key-encryption key, its database, its upload volumes
#   the GLOBAL key      a replica of kms.tf's multi-region key (not in the
#                       home region, where the primary is)
#   a log group         /mock-sts/containers (not in the home region, where
#                       logs.tf's is): a cell's logs stay in its region
#   the image repository  a replica of ecr.tf's (not in the home region),
#                       which the replication configuration below fills
#
# FOUR BLOCKS, NOT A for_each, because a module's provider cannot be chosen
# per element (providers.tf). Each exists only when `permitted_regions` names
# its region, so the default — the home region alone — adds one module
# instance: the home region's cell key.
# ---------------------------------------------------------------------------
locals {
  region_common = {
    name                 = var.name
    home_region          = var.aws_region
    account_id           = local.account_id
    partition            = local.partition
    global_key_arn       = aws_kms_key.global.arn
    log_retention_days   = var.log_retention_days
    ecr_lifecycle_policy = aws_ecr_lifecycle_policy.main.policy
  }
}

module "region_usw2" {
  source    = "./modules/region"
  count     = contains(local.regions, "us-west-2") ? 1 : 0
  providers = { aws = aws.usw2 }

  region = "us-west-2"
  cell   = local.cell_of_region["us-west-2"]
  common = local.region_common
}

module "region_cac1" {
  source    = "./modules/region"
  count     = contains(local.regions, "ca-central-1") ? 1 : 0
  providers = { aws = aws.cac1 }

  region = "ca-central-1"
  cell   = local.cell_of_region["ca-central-1"]
  common = local.region_common
}

module "region_euc1" {
  source    = "./modules/region"
  count     = contains(local.regions, "eu-central-1") ? 1 : 0
  providers = { aws = aws.euc1 }

  region = "eu-central-1"
  cell   = local.cell_of_region["eu-central-1"]
  common = local.region_common
}

module "region_apse1" {
  source    = "./modules/region"
  count     = contains(local.regions, "ap-southeast-1") ? 1 : 0
  providers = { aws = aws.apse1 }

  region = "ap-southeast-1"
  cell   = local.cell_of_region["ap-southeast-1"]
  common = local.region_common
}

locals {
  # Every region's module, as one list, for the statements that name a key,
  # a log group or a repository in each permitted region.
  region_modules = concat(module.region_usw2, module.region_cac1, module.region_euc1, module.region_apse1)

  cell_key_arns        = [for m in local.region_modules : m.cell_key_arn]
  global_replica_arns  = compact([for m in local.region_modules : m.global_replica_key_arn])
  regional_log_arns    = compact([for m in local.region_modules : m.log_group_arn])
  regional_ecr_arns    = compact([for m in local.region_modules : m.ecr_repository_arn])
  all_global_key_arns  = concat([aws_kms_key.global.arn], local.global_replica_arns)
  all_project_key_arns = concat([aws_kms_key.main.arn], local.all_global_key_arns, local.cell_key_arns)
  all_log_group_arns   = concat([aws_cloudwatch_log_group.containers.arn], local.regional_log_arns)
  all_ecr_arns         = concat([aws_ecr_repository.main.arn], local.regional_ecr_arns)
  replica_regions      = [for r in local.regions : r if r != var.aws_region]
}

# ---------------------------------------------------------------------------
# EVERY PUSH TO THE HOME REPOSITORY IS COPIED TO EACH OTHER PERMITTED REGION.
#
# A cell pulls its images from its own region: a Fargate task in ca-central-1
# pulling from us-west-2 would pay inter-region transfer on every start and
# would stop starting when us-west-2 was the thing that failed. Images are
# pushed once, to the home region, as they always were; ECR copies them, and
# modules/region has already made the destination repository, so the copy
# lands under the lifecycle policy rather than in a repository ECR invents
# with none.
#
# **THIS RESOURCE IS THE REGISTRY'S WHOLE REPLICATION CONFIGURATION**, not a
# rule of it: ECR keeps one per registry per region. Nothing else in this
# account replicates today (2026-09-28); a project that needs to must add its
# rule HERE, or the two will overwrite each other on every apply.
#
# The copy is asynchronous — usually seconds, not guaranteed. A cell task
# that starts before its tag has arrived fails to pull, and ECS starts it
# again; `entrypoint.sh` applies the home cell first, which is time enough in
# practice (deploy/aws/CLAUDE.md, *Cells*).
# ---------------------------------------------------------------------------
resource "aws_ecr_replication_configuration" "main" {
  count = length(local.replica_regions) > 0 ? 1 : 0

  replication_configuration {
    rule {
      dynamic "destination" {
        for_each = local.replica_regions
        content {
          region      = destination.value
          registry_id = local.account_id
        }
      }
      repository_filter {
        filter      = var.name
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}
