# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT EVERY PERMITTED REGION HOLDS (#98, 2026-09-28) — modules/region, once
# per region, every resource of it made in that region.
#
#   a CELL key          single-region, never replicated: the cell's own
#                       key-encryption key, its database, its upload volumes
#   the GLOBAL key      a replica of kms.tf's multi-region key (not in the
#                       home region, where the primary is)
#   the KEK             a replica of kms.tf's key-encryption key (#391), the
#                       same way and for the same reason
#   a log group         /mock-sts/containers (not in the home region, where
#                       logs.tf's is): a cell's logs stay in its region
#   the image repository  a replica of ecr.tf's (not in the home region),
#                       which the replication configuration below fills
#
# ONE MODULE BLOCK, A for_each OVER `permitted_regions` (#367, 2026-09-30).
# It was four blocks, one per region the #98 design named, each bound to a
# provider of its own; AWS provider 6's per-resource `region` argument lets
# one provider reach every region, so the module takes its region as a
# variable and a new region is an entry in the list.
# ---------------------------------------------------------------------------
locals {
  region_common = {
    name                 = var.name
    home_region          = var.aws_region
    account_id           = local.account_id
    partition            = local.partition
    global_key_arn       = aws_kms_key.global.arn
    kek_key_arn          = aws_kms_key.kek.arn
    log_retention_days   = var.log_retention_days
    ecr_lifecycle_policy = aws_ecr_lifecycle_policy.main.policy
  }
}

# EVERY PERMITTED REGION IS ENABLED ON THE ACCOUNT, or nothing is planned.
# An opt-in region (ap-southeast-5, and every one launched since 2019) that
# an administrator has not enabled refuses every call, and the apply would
# stop half way with a KMS key made in some regions and not others. This
# asks EC2 which regions the account may use — the enabled ones, which is
# what `aws_regions` answers by default — and stops the plan first.
data "aws_regions" "enabled" {
  lifecycle {
    postcondition {
      condition     = length(setsubtract(local.regions, self.names)) == 0
      error_message = "permitted_regions names regions this account has not enabled: ${join(", ", setsubtract(local.regions, self.names))}. An administrator enables an opt-in region first (Account -> AWS Regions, or `aws account enable-region --region-name <r>`), and waits until `aws account get-region-opt-status` says ENABLED."
    }
  }
}

module "region" {
  source   = "./modules/region"
  for_each = toset(local.regions)

  region = each.key
  cell   = local.cell_of_region[each.key]
  common = local.region_common
}

# THE FOUR BLOCKS' INSTANCES ARE THIS ONE'S NOW, NOT NEW ONES. Without these
# a plan would destroy every region's cell key (a thirty-day deletion that
# strands every cell database, secret and upload volume sealed under it) and
# make another. A `moved` from an instance the state never had is ignored.
moved {
  from = module.region_usw2[0]
  to   = module.region["us-west-2"]
}

moved {
  from = module.region_cac1[0]
  to   = module.region["ca-central-1"]
}

moved {
  from = module.region_euc1[0]
  to   = module.region["eu-central-1"]
}

moved {
  from = module.region_apse1[0]
  to   = module.region["ap-southeast-1"]
}

locals {
  # Every region's module, as one list, for the statements that name a key,
  # a log group or a repository in each permitted region.
  region_modules = values(module.region)

  cell_key_arns        = [for m in local.region_modules : m.cell_key_arn]
  global_replica_arns  = compact([for m in local.region_modules : m.global_replica_key_arn])
  regional_log_arns    = compact([for m in local.region_modules : m.log_group_arn])
  regional_ecr_arns    = compact([for m in local.region_modules : m.ecr_repository_arn])
  all_global_key_arns  = concat([aws_kms_key.global.arn], local.global_replica_arns)
  all_project_key_arns = concat([aws_kms_key.main.arn], local.all_global_key_arns, local.cell_key_arns)
  all_log_group_arns   = concat([aws_cloudwatch_log_group.containers.arn], local.regional_log_arns)
  all_ecr_arns         = concat([aws_ecr_repository.main.arn], local.regional_ecr_arns)
  replica_regions      = [for r in local.regions : r if r != var.aws_region]

  # THE KEK IN EVERY REGION AT ONCE, AS ONE ARN (#391): a multi-region key's
  # replicas share its key ID, so `key/<mrk id>` with the region a wildcard
  # names the primary and its replicas and no other key, and the region
  # fence holds the region to the permitted list. Used where a policy's size
  # matters (the boundary, the deployer); an environment's task role names
  # each regional ARN (../environment/iam.tf).
  kek_key_arn_any_region = "arn:${local.partition}:kms:*:${local.account_id}:key/${aws_kms_key.kek.key_id}"
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
