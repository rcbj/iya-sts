locals {
  project_tag = "STS"
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  region      = var.aws_region

  state_bucket = "${var.name}-terraform-state-${local.account_id}"

  # Names the environment stack creates, spelt here because the deployer policy
  # and the permissions boundary scope to them. Keep in step with
  # ../environment/locals.tf.
  env_role_prefix   = "${var.name}-env-"
  secret_prefix     = "${var.name}/"
  container_log_grp = "/${var.name}/containers"

  arn = {
    iam_role     = "arn:${local.partition}:iam::${local.account_id}:role"
    iam_policy   = "arn:${local.partition}:iam::${local.account_id}:policy"
    secret       = "arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret"
    logs         = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group"
    rds          = "arn:${local.partition}:rds:${local.region}:${local.account_id}"
    ecs          = "arn:${local.partition}:ecs:${local.region}:${local.account_id}"
    elb          = "arn:${local.partition}:elasticloadbalancing:${local.region}:${local.account_id}"
    ecr_repo     = "arn:${local.partition}:ecr:${local.region}:${local.account_id}:repository/${var.name}"
    state_bucket = "arn:${local.partition}:s3:::${local.state_bucket}"
  }
}
