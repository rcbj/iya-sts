# ---------------------------------------------------------------------------
# THE TWO ROLES A NODE'S TASK RUNS WITH, EACH WITH THE LEAST IT NEEDS.
#
# TASK ROLE — what the mock-sts CONTAINER can do with its credentials: read
# the key-encryption key and the database password (GetSecretValue at startup,
# DescribeSecret for the /admin/secrets report), and decrypt them with the
# project key, only through Secrets Manager. Nothing else: no S3, no RDS API,
# no other secret. The schema-init container shares it and uses none of it.
#
# AND, WHERE THERE IS A PUBLIC NAME, ONE MORE THING — `acm:ExportCertificate`
# on THAT ONE CERTIFICATE, which the `cert-init` container uses and the other
# two never call (2026-09-17). It is scoped to the certificate's own ARN
# rather than `*`, so the credential cannot be turned on any other certificate
# in the account, and it is absent entirely in `dev` and `ci`, which request
# none. The statement is useless without the matching one in the foundation's
# WORKLOAD BOUNDARY, which an administrator applies — a permissions boundary
# is a ceiling, and a role policy cannot rise above it.
#
# EXECUTION ROLE — what ECS itself does on the task's behalf before a container
# runs: pull the images, write to the log group, and inject the three
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

  # cert-init, and only where there is a certificate to export. ACM encrypts
  # the key under a passphrase the caller supplies, so this action alone does
  # not hand anybody a usable key — but it is the whole of what it takes to
  # get one, so it names the certificate.
  dynamic "statement" {
    for_each = local.public_name ? [1] : []
    content {
      sid       = "ExportThePublicCertificateForTheNodeToServe"
      actions   = ["acm:ExportCertificate"]
      resources = [aws_acm_certificate.public[0].arn]
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

  # THE FOURTH, IN PRODUCT MODE (2026-09-17): the bootstrap administrator's
  # password, injected into mock-sts so that the only way into a fresh
  # deployment is in Secrets Manager rather than in a log (secrets.tf).
  #
  # A statement of its own rather than a fourth ARN in the one above, so that
  # the policy `dev` and `ci` render is the policy they rendered before —
  # their whole job is to be the unchanged standard, and even a sid that says
  # "three" when it means four is a diff on their next apply.
  dynamic "statement" {
    for_each = local.bootstrap_secret ? [1] : []
    content {
      sid       = "InjectTheBootstrapAdministratorPassword"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [aws_secretsmanager_secret.main["bootstrap-admin-password"].arn]
    }
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
