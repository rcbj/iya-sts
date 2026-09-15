# ---------------------------------------------------------------------------
# THE TWO ROLES A NODE'S TASK RUNS WITH, EACH WITH THE LEAST IT NEEDS.
#
# TASK ROLE — what the mock-sts CONTAINER can do with its credentials: read
# the key-encryption key and the database password (GetSecretValue at startup,
# DescribeSecret for the /admin/secrets report), and decrypt them with the
# project key, only through Secrets Manager. Nothing else: no S3, no RDS API,
# no other secret. The schema-init container shares it and uses none of it.
#
# EXECUTION ROLE — what ECS itself does on the task's behalf before a container
# runs: pull the two images, write to the log group, and inject the three
# secrets that arrive as environment variables (the admin API client secret
# into mock-sts; the master and application passwords into schema-init).
#
# Both carry the foundation's permissions boundary; the deployer cannot create
# a role without it.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "task" {
  name                 = "${local.role_prefix}-task"
  description          = "mock-sts ${var.environment}: the container reads its key and database password"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = data.aws_iam_policy.workload_boundary.arn
}

data "aws_iam_policy_document" "task" {
  statement {
    sid     = "ReadTheKeyAndTheDatabasePassword"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [
      aws_secretsmanager_secret.main["kek"].arn,
      aws_secretsmanager_secret.main["db-app-password"].arn,
    ]
  }
  statement {
    sid       = "DecryptThemThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.main.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "read-secrets"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_iam_role" "execution" {
  name                 = "${local.role_prefix}-exec"
  description          = "mock-sts ${var.environment}: ECS pulls images, writes logs, injects secrets"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = data.aws_iam_policy.workload_boundary.arn
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "PullTheProjectImages"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [data.aws_ecr_repository.main.arn]
  }
  statement {
    sid       = "WriteContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${data.aws_cloudwatch_log_group.containers.arn}:*"]
  }
  statement {
    sid     = "InjectTheThreeEnvironmentSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.main["admin-api-client-secret"].arn,
      aws_secretsmanager_secret.main["db-master-password"].arn,
      aws_secretsmanager_secret.main["db-app-password"].arn,
    ]
  }
  statement {
    sid       = "DecryptThemThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.main.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "pull-log-inject"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}
