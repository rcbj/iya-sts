# ---------------------------------------------------------------------------
# THE PROJECT'S DEPLOYER: ONE USER, ONE ROLE, ONE BOUNDARY (issue #51).
#
# The USER has one permission: assume the ROLE. Its access key is what GitHub
# Actions holds (created by hand, `aws iam create-access-key`, so the secret
# never lands in Terraform state). The ROLE holds everything an environment
# apply and destroy needs, and nothing else.
#
# How "minimum" is enforced, in three layers:
#
#   * NAMES — ELB, ECS, RDS, IAM, Secrets Manager, S3 and ECR resources are
#     scoped to ARNs starting `mock-sts`. Nothing already in the account
#     carries that prefix.
#   * TAGS — EC2 resources have no predictable ARN (vpc-0abc…), so creation
#     requires `aws:RequestTag/Project = STS` and every change or deletion
#     requires `aws:ResourceTag/Project = STS`. The deployer cannot touch the
#     account's two existing VPCs, or anything else it did not tag.
#   * A PERMISSIONS BOUNDARY — the deployer must create roles (the ECS task and
#     execution roles). A role creator with no boundary can create a role more
#     powerful than itself and pass it to a task; so every role it creates must
#     carry `mock-sts-workload-boundary`, which permits only what a mock-sts
#     container can ever need, and the deployer cannot remove it.
#
# The actions were chosen from what the AWS provider calls for these resources
# and refined against real AccessDenied errors on the first apply; each
# statement says what it is for.
# ---------------------------------------------------------------------------

resource "aws_iam_user" "deployer" {
  name = "${var.name}-deployer"
  path = "/${var.name}/"
}

data "aws_iam_policy_document" "deployer_user" {
  statement {
    sid       = "AssumeTheDeployerRoleOnly"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = [aws_iam_role.deployer.arn]
  }
}

resource "aws_iam_user_policy" "deployer" {
  name   = "assume-${var.name}-deployer"
  user   = aws_iam_user.deployer.name
  policy = data.aws_iam_policy_document.deployer_user.json
}

data "aws_iam_policy_document" "deployer_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.deployer.arn]
    }
  }
}

resource "aws_iam_role" "deployer" {
  name                 = "${var.name}-deployer"
  description          = "Creates and destroys mock-sts test environments (issue #51)"
  assume_role_policy   = data.aws_iam_policy_document.deployer_trust.json
  max_session_duration = var.deployer_session_seconds
}

# ---------------------------------------------------------------------------
# THE BOUNDARY EVERY ROLE THE DEPLOYER CREATES MUST CARRY.
#
# The union of what the ECS task role (mock-sts reading its two secrets) and the
# ECS execution role (pulling the image, writing logs, injecting two secrets)
# can do. A role's effective permissions are the intersection of its own policy
# and this, so a policy that grants more is inert.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "workload_boundary" {
  statement {
    sid       = "ReadProjectSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = ["${local.arn.secret}:${local.secret_prefix}*"]
  }
  statement {
    sid       = "DecryptWithTheProjectKeyThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "PullTheProjectImage"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.main.arn]
  }
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.containers.arn}:*"]
  }
}

resource "aws_iam_policy" "workload_boundary" {
  name        = "${var.name}-workload-boundary"
  description = "The most any role a mock-sts environment creates may do"
  policy      = data.aws_iam_policy_document.workload_boundary.json
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 1 OF 3: THE NETWORK AND THE LOAD BALANCER.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_network" {
  statement {
    sid       = "Ec2ReadAnything"
    actions   = ["ec2:Describe*", "ec2:Get*"]
    resources = ["*"]
  }

  statement {
    sid = "Ec2CreateOnlyTagged"
    actions = [
      "ec2:CreateVpc", "ec2:CreateSubnet", "ec2:CreateInternetGateway",
      "ec2:CreateRouteTable", "ec2:CreateSecurityGroup",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  # A subnet, route table or security group is created INSIDE a VPC, and the
  # VPC is a resource of that call too — it must be the project's.
  statement {
    sid = "Ec2CreateInsideTheProjectVpc"
    actions = [
      "ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup",
    ]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:vpc/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "Ec2TagOnlyWhileCreating"
    actions   = ["ec2:CreateTags"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values = [
        "CreateVpc", "CreateSubnet", "CreateInternetGateway",
        "CreateRouteTable", "CreateSecurityGroup",
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
      ]
    }
  }

  statement {
    sid = "Ec2ChangeOnlyTagged"
    actions = [
      "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
      "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
      "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:CreateRoute", "ec2:ReplaceRoute", "ec2:DeleteRoute",
      "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      "ec2:DeleteSecurityGroup", "ec2:CreateTags", "ec2:DeleteTags",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # A rule is its own resource (security-group-rule/sgr-…) with the tag set on
  # it at creation, so revoking or describing one is decided by its own tag too
  # — which the statement above covers. Nothing here reaches a rule in another
  # project's group, because the group is a resource of the same call.

  statement {
    sid       = "ElbRead"
    actions   = ["elasticloadbalancing:Describe*"]
    resources = ["*"]
  }

  statement {
    sid = "ElbOnlyProjectNamed"
    actions = [
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyListenerAttributes",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
    ]
    resources = [
      "${local.arn.elb}:loadbalancer/net/${var.name}-*",
      "${local.arn.elb}:targetgroup/${var.name}-*",
      "${local.arn.elb}:listener/net/${var.name}-*",
    ]
  }

  statement {
    sid       = "ServiceLinkedRolesForElbEcsRds"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "elasticloadbalancing.amazonaws.com", "ecs.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }
  }
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 2 OF 3: THE DATABASE, THE SECRETS, THE KEY, THE STATE.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_data" {
  statement {
    sid       = "RdsRead"
    actions   = ["rds:Describe*", "rds:ListTagsForResource"]
    resources = ["*"]
  }

  statement {
    sid = "RdsOnlyProjectNamed"
    actions = [
      "rds:CreateDBInstance", "rds:CreateDBInstanceReadReplica",
      "rds:ModifyDBInstance", "rds:DeleteDBInstance", "rds:RebootDBInstance",
      "rds:PromoteReadReplica",
      "rds:CreateDBSubnetGroup", "rds:ModifyDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:CreateDBParameterGroup", "rds:ModifyDBParameterGroup",
      "rds:DeleteDBParameterGroup",
      "rds:DeleteDBInstanceAutomatedBackup",
      "rds:AddTagsToResource", "rds:RemoveTagsFromResource",
    ]
    resources = [
      "${local.arn.rds}:db:${var.name}-*",
      "${local.arn.rds}:subgrp:${var.name}-*",
      "${local.arn.rds}:pg:${var.name}-*",
      "${local.arn.rds}:auto-backup:*",
      # The default option group, which a PostgreSQL instance is placed in and
      # which CreateDBInstance names as a resource of the call. Using it
      # changes nothing about it.
      "${local.arn.rds}:og:default:postgres-18",
    ]
  }

  statement {
    sid = "SecretsOnlyProjectNamed"
    actions = [
      "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource", "secretsmanager:UntagResource",
      "secretsmanager:GetResourcePolicy", "secretsmanager:RestoreSecret",
    ]
    resources = ["${local.arn.secret}:${local.secret_prefix}*"]
  }

  statement {
    sid       = "SecretsRandomPassword"
    actions   = ["secretsmanager:GetRandomPassword"]
    resources = ["*"]
  }

  # The KEY is used, never administered: RDS and Secrets Manager encrypt with
  # it on the deployer's behalf (the grant is how RDS keeps using it), and
  # Terraform reads its description. Rotation, policy and deletion stay with an
  # administrator.
  statement {
    sid = "UseTheProjectKey"
    actions = [
      "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
    ]
    resources = [aws_kms_key.main.arn]
  }

  statement {
    sid       = "GrantTheProjectKeyToAwsServicesOnly"
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = [aws_kms_key.main.arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid       = "TerraformStateList"
    actions   = ["s3:ListBucket"]
    resources = [local.arn.state_bucket]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["environment/*"]
    }
  }

  # Only the environments' state. Foundation state (this stack) is written by
  # an administrator, so a deployer cannot rewrite the record of its own grant.
  statement {
    sid       = "TerraformStateObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.arn.state_bucket}/environment/*"]
  }

  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "EcrPushAndPullTheProjectRepository"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
      "ecr:DescribeImages", "ecr:DescribeRepositories",
    ]
    resources = [aws_ecr_repository.main.arn]
  }

  statement {
    sid       = "ReadTheContainerLogs"
    actions   = ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.containers.arn}:*"]
  }

  statement {
    sid       = "LogsDescribe"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 3 OF 3: ECS, AND THE ROLES ITS TASKS RUN AS.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_compute" {
  statement {
    sid = "EcsReadAndTaskDefinitions"
    actions = [
      "ecs:Describe*", "ecs:List*",
      # Task definitions have no name-scoped ARN at registration time.
      "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition",
      "ecs:DeleteTaskDefinitions",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "EcsCreateClusterTagged"
    actions   = ["ecs:CreateCluster", "ecs:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "EcsOnlyProjectNamed"
    actions = [
      "ecs:DeleteCluster", "ecs:UpdateCluster", "ecs:PutClusterCapacityProviders",
      "ecs:CreateService", "ecs:UpdateService", "ecs:DeleteService",
      "ecs:StopTask", "ecs:TagResource", "ecs:UntagResource",
    ]
    resources = [
      "${local.arn.ecs}:cluster/${var.name}-*",
      "${local.arn.ecs}:service/${var.name}-*",
      "${local.arn.ecs}:task/${var.name}-*",
      "${local.arn.ecs}:task-definition/${var.name}-*",
    ]
  }

  statement {
    sid = "EnvironmentRolesRead"
    actions = [
      "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
      "iam:ListRoleTags",
    ]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*"]
  }

  # Creating a role, or changing what it may do, requires the boundary.
  statement {
    sid = "EnvironmentRolesWriteOnlyWithTheBoundary"
    actions = [
      "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy",
      "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary",
    ]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.workload_boundary.arn]
    }
  }

  statement {
    sid = "EnvironmentRolesMaintain"
    actions = [
      "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole",
      "iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy",
    ]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*"]
  }

  statement {
    sid       = "PassEnvironmentRolesToEcsTasksOnly"
    actions   = ["iam:PassRole"]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }

  statement {
    sid       = "ReadTheBoundaryItMustAttach"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = [aws_iam_policy.workload_boundary.arn]
  }

  # The boundary cannot be taken off a role, by the deployer or through it.
  statement {
    sid       = "NeverRemoveTheBoundary"
    effect    = "Deny"
    actions   = ["iam:DeleteRolePermissionsBoundary"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "deploy_network" {
  name   = "${var.name}-deploy-network"
  policy = data.aws_iam_policy_document.deploy_network.json
}

resource "aws_iam_policy" "deploy_data" {
  name   = "${var.name}-deploy-data"
  policy = data.aws_iam_policy_document.deploy_data.json
}

resource "aws_iam_policy" "deploy_compute" {
  name   = "${var.name}-deploy-compute"
  policy = data.aws_iam_policy_document.deploy_compute.json
}

resource "aws_iam_role_policy_attachment" "deployer" {
  for_each = {
    network = aws_iam_policy.deploy_network.arn
    data    = aws_iam_policy.deploy_data.arn
    compute = aws_iam_policy.deploy_compute.arn
  }
  role       = aws_iam_role.deployer.name
  policy_arn = each.value
}

# Everything the deployer does is confined to one region.
data "aws_iam_policy_document" "region_fence" {
  statement {
    sid         = "OnlyUsWest2ForRegionalServices"
    effect      = "Deny"
    not_actions = ["iam:*", "sts:*", "s3:*"]
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [local.region]
    }
  }
}

resource "aws_iam_role_policy" "region_fence" {
  name   = "region-fence"
  role   = aws_iam_role.deployer.name
  policy = data.aws_iam_policy_document.region_fence.json
}
