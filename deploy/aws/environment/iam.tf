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
#
# A THIRD ROLE, AT THE END OF THIS FILE, IS NOT A TASK'S (#214): the ECS
# infrastructure role, with which ECS itself manages each node's upload volume.
# It carries a boundary of its own.
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

  # THE PRODUCT-MODE THREE (2026-09-17, the KDC's two 2026-09-18): the
  # bootstrap administrator's password, injected into mock-sts so that the
  # only way into a fresh deployment is in Secrets Manager rather than in a
  # log, and the krbtgt and service account passwords without which a product
  # KDC issues nothing (secrets.tf).
  #
  # A statement of its own rather than a fourth ARN in the one above, so that
  # the policy `dev` and `ci` render is the policy they rendered before —
  # their whole job is to be the unchanged standard, and even a sid that says
  # "three" when it means four is a diff on their next apply.
  dynamic "statement" {
    for_each = local.bootstrap_secret ? [1] : []
    content {
      sid     = "InjectTheProductModeSecrets"
      actions = ["secretsmanager:GetSecretValue"]
      resources = [
        aws_secretsmanager_secret.main["bootstrap-admin-password"].arn,
        aws_secretsmanager_secret.main["krb5-krbtgt-password"].arn,
        aws_secretsmanager_secret.main["krb5-service-password"].arn,
      ]
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

# ---------------------------------------------------------------------------
# THE ECS INFRASTRUCTURE ROLE: ECS CREATES, ATTACHES AND DELETES EACH NODE'S
# RISK DATASET UPLOAD VOLUME WITH IT (#214).
#
# Not a task role and never one: it is assumed by `ecs.amazonaws.com` (the
# service scheduler), not `ecs-tasks.amazonaws.com`, and no container ever
# holds its credentials. It carries a boundary of its OWN,
# `mock-sts-ecs-infrastructure-boundary`, rather than the workload boundary,
# so that nothing a container may do was widened to make room for it; and the
# deployer may pass a role of this name to ECS itself and to nothing else
# (foundation/iam_deployer.tf).
#
# LEAST PRIVILEGE, BY TAG. AWS's managed `AmazonECSInfrastructureRolePolicy-
# ForVolumes` is the model, narrowed to this environment:
#   * a volume is created only with the two tags ECS puts on one it manages,
#     `AmazonECSManaged = true` and `AmazonECSCreated = <the task's ARN>`, and
#     the task must be in THIS environment's cluster;
#   * a volume is attached, detached and deleted only if it carries those
#     tags — so the role cannot touch any other volume in the account;
#   * no snapshot statement: the volume starts empty, from no snapshot.
# THE INSTANCE side of an attach is Fargate's, in an account that is not this
# one, which is why that resource names no account (as the managed policy's
# does not).
#
# THE KEY: EBS encrypts under the project key on the caller's behalf, which is
# a data key made without plaintext and a GRANT the volume uses for as long as
# it is attached. Both are asked only through EC2 (`kms:ViaService`), only for
# an EBS volume's encryption context, and the grant only for an AWS resource.
# The key policy delegates to IAM (foundation/kms.tf), so this is the whole of
# it — no key policy edit.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_infrastructure_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "ecs_infrastructure" {
  name                 = "${local.role_prefix}-ecs-infra"
  description          = "mock-sts ${var.environment}: ECS creates, attaches and deletes each node's upload volume"
  assume_role_policy   = data.aws_iam_policy_document.ecs_infrastructure_trust.json
  permissions_boundary = data.aws_iam_policy.ecs_infrastructure_boundary.arn
}

locals {
  # The ARN a task of THIS environment's cluster has, which ECS writes into
  # the `AmazonECSCreated` tag of every volume it creates for one.
  ecs_task_arns = "arn:${local.partition}:ecs:${local.region}:${local.account_id}:task/${local.prefix}/*"
  ec2_volumes   = "arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*"
}

data "aws_iam_policy_document" "ecs_infrastructure" {
  statement {
    sid       = "CreateOnlyEcsManagedVolumesForThisCluster"
    actions   = ["ec2:CreateVolume"]
    resources = [local.ec2_volumes]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:RequestTag/AmazonECSCreated"
      values   = [local.ecs_task_arns]
    }
  }
  statement {
    sid       = "TagThemOnlyWhileCreating"
    actions   = ["ec2:CreateTags"]
    resources = [local.ec2_volumes]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateVolume"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:RequestTag/AmazonECSCreated"
      values   = [local.ecs_task_arns]
    }
  }
  statement {
    sid       = "FollowTheirState"
    actions   = ["ec2:DescribeVolumes", "ec2:DescribeAvailabilityZones"]
    resources = ["*"]
  }
  statement {
    sid       = "AttachAndDetachOnlyThem"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume"]
    resources = [local.ec2_volumes]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:ResourceTag/AmazonECSCreated"
      values   = [local.ecs_task_arns]
    }
  }
  statement {
    sid       = "ToTheFargateHost"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume"]
    resources = ["arn:${local.partition}:ec2:${local.region}:*:instance/*"]
  }
  statement {
    sid       = "DeleteOnlyThem"
    actions   = ["ec2:DeleteVolume"]
    resources = [local.ec2_volumes]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:ResourceTag/AmazonECSCreated"
      values   = [local.ecs_task_arns]
    }
  }

  statement {
    sid       = "DescribeTheProjectKey"
    actions   = ["kms:DescribeKey"]
    resources = [data.aws_kms_key.main.arn]
  }
  statement {
    sid       = "EncryptTheVolumeThroughEc2"
    actions   = ["kms:GenerateDataKeyWithoutPlaintext"]
    resources = [data.aws_kms_key.main.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values   = ["aws:ebs:id"]
    }
  }
  statement {
    sid       = "GrantTheKeyToTheVolumeThroughEc2"
    actions   = ["kms:CreateGrant"]
    resources = [data.aws_kms_key.main.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values   = ["aws:ebs:id"]
    }
  }
}

resource "aws_iam_role_policy" "ecs_infrastructure" {
  name   = "manage-upload-volumes"
  role   = aws_iam_role.ecs_infrastructure.id
  policy = data.aws_iam_policy_document.ecs_infrastructure.json
}
