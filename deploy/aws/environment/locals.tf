locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = var.aws_region

  # Every name starts `mock-sts-<environment>`; the deployer policy scopes
  # ELB, ECS, RDS and IAM to `mock-sts-*`. Roles take `mock-sts-env-` so the
  # policy can tell an environment's roles from the deployer's own.
  prefix      = "${var.name}-${var.environment}"
  role_prefix = "${var.name}-env-${var.environment}"
  secret_path = "${var.name}/${var.environment}"

  azs = slice(sort(data.aws_availability_zones.available.names), 0, 3)

  public_cidrs  = [for i in range(3) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidrs = [for i in range(3) : cidrsubnet(var.vpc_cidr, 8, 10 + i)]

  nodes = { for i in range(var.node_count) : "node-${substr("abc", i, 1)}" => i }

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  ecr_repository_url = data.aws_ecr_repository.main.repository_url
  schema_image_tag   = var.schema_image_tag != "" ? var.schema_image_tag : "schema-${var.image_tag}"

  public_base_url = "https://${aws_lb.main.dns_name}"
  container_port  = 8081
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

# The foundation stack's resources, found by name. Read-only lookups; this
# stack never changes them.
data "aws_kms_key" "main" {
  key_id = "alias/${var.name}"
}

data "aws_ecr_repository" "main" {
  name = var.name
}

data "aws_cloudwatch_log_group" "containers" {
  name = "/${var.name}/containers"
}

# By ARN, not by name: a lookup by name lists every policy in the account,
# which the deployer is deliberately not allowed to do.
data "aws_iam_policy" "workload_boundary" {
  arn = "arn:${local.partition}:iam::${local.account_id}:policy/${var.name}-workload-boundary"
}
