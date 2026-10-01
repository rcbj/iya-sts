# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PROJECT'S DEPLOYER: ONE USER, ONE ROLE, ONE BOUNDARY (issue #51).
#
# The USER has one permission: assume the ROLE. Its access key is a person's
# (created by hand, `aws iam create-access-key`, so the secret never lands in
# Terraform state); GitHub Actions holds the key of a SECOND such user, the
# `ci` one below. The ROLE holds everything an environment apply and destroy
# needs, and nothing else.
#
# How "minimum" is enforced, in three layers:
#
#   * NAMES — ELB, ECS, RDS, IAM, Secrets Manager, S3 and ECR resources are
#     scoped to ARNs starting `iya-sts`. Nothing already in the account
#     carries that prefix.
#   * TAGS — EC2 resources have no predictable ARN (vpc-0abc…), so creation
#     requires `aws:RequestTag/Project = STS` and every change or deletion
#     requires `aws:ResourceTag/Project = STS`. The deployer cannot touch the
#     account's two existing VPCs, or anything else it did not tag.
#   * A PERMISSIONS BOUNDARY — the deployer must create roles (the ECS task and
#     execution roles). A role creator with no boundary can create a role more
#     powerful than itself and pass it to a task; so every role it creates must
#     carry `iya-sts-workload-boundary`, which permits only what an iya-sts
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

# ---------------------------------------------------------------------------
# THE WORKFLOW'S USER, IN THE ACCOUNT'S git_userN SERIES.
#
# Modelled on git_user5 (which assumes rcbj-deploy for the rcbj.net site): path
# `/`, no login profile, no groups, and ONE inline policy named
# `assume-<role>` allowing sts:AssumeRole on ONE role, which trusts it by name.
# It is a second principal of the deployer role rather than a replacement for
# iya-sts-deployer, so a person's key and the workflow's key can be rotated or
# revoked apart: the workflow's secrets hold this user's key and nothing else.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "ci" {
  name = var.ci_user_name
  path = "/"
}

data "aws_iam_policy_document" "ci_user" {
  statement {
    sid       = "AssumeDeployRole"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = [aws_iam_role.deployer.arn]
  }
}

resource "aws_iam_user_policy" "ci" {
  name   = "assume-${var.name}-deployer"
  user   = aws_iam_user.ci.name
  policy = data.aws_iam_policy_document.ci_user.json
}

data "aws_iam_policy_document" "deployer_trust" {
  statement {
    sid     = "IamUsersMayAssume"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.deployer.arn, aws_iam_user.ci.arn]
    }
  }
}

resource "aws_iam_role" "deployer" {
  name                 = "${var.name}-deployer"
  description          = "Creates and destroys iya-sts test environments (issue #51)"
  assume_role_policy   = data.aws_iam_policy_document.deployer_trust.json
  max_session_duration = var.deployer_session_seconds
}

# ---------------------------------------------------------------------------
# THE BOUNDARY EVERY ROLE THE DEPLOYER CREATES MUST CARRY.
#
# The union of what the ECS task role (iya-sts reading its two secrets, and
# cert-init exporting the public certificate), the ECS execution role (pulling
# the images, writing logs, injecting the environment's secrets) and the suite
# runner's role (uploading its report) can do. A role's effective permissions
# are the intersection of its own policy and this, so a policy that grants
# more is inert.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "workload_boundary" {
  # IN EVERY PERMITTED REGION (#98): a cell's task reads its own secrets and
  # the global ones replicated to its region, decrypts them with its cell key
  # or its replica of the global key, pulls from its region's repository and
  # logs to its region's group. The ARNs name any region and the fence below
  # holds them to the permitted ones (locals.tf, `rarn`, #367).
  statement {
    sid         = "OnlyPermittedRegionsForRegionalServices"
    effect      = "Deny"
    not_actions = local.fence_exempt
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.regions
    }
  }
  statement {
    sid       = "ReadProjectSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [for p in local.rarn.secretsmanager : "${p}:secret:${local.secret_prefix}*"]
  }
  statement {
    sid       = "DecryptWithTheProjectKeyThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = local.all_project_key_arns
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in local.regions : "secretsmanager.${r}.amazonaws.com"]
    }
  }
  statement {
    sid       = "PullTheProjectImage"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = local.all_ecr_arns
  }
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for a in local.all_log_group_arns : "${a}:*"]
  }
  # The suite task (environment/runner.tf) uploads its report. Objects only:
  # no listing, no reading, no deleting another run's report.
  statement {
    sid       = "WriteTestReports"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${local.arn.reports}/*"]
  }
  # THE PUBLIC CERTIFICATE THE NODE SERVES (2026-09-17). `cert-init`
  # (deploy/aws/cert-init/) exports it into the task on every start, because
  # the load balancer no longer terminates TLS and a node cannot present a
  # certificate whose key it does not hold. EXPORT ONLY — not
  # `RequestCertificate`, not `DeleteCertificate`, not `ImportCertificate`:
  # this ceiling is what an iya-sts CONTAINER may ever do, and a container
  # that could issue or remove a certificate for a public name is a different
  # thing entirely.
  #
  # The resource is every certificate in this account and region rather than
  # one ARN, because a boundary is written once in `foundation/` and cannot
  # name a certificate an environment has not created yet. The ENVIRONMENT's
  # own task-role policy names the single ARN (environment/iam.tf), and the
  # effective permission is the intersection — so the container reaches
  # exactly one certificate.
  statement {
    sid       = "ExportThePublicCertificate"
    actions   = ["acm:ExportCertificate"]
    resources = [for p in local.rarn.acm : "${p}:certificate/*"]
  }
  # MAIL THROUGH SES (#311): send FROM an address at a public name an
  # environment may use (environment/mail.tf), and nothing else in SES — no
  # identity management, no account settings. Any identity, because the SES
  # sandbox authorizes against the RECIPIENT's verified identity too; the
  # `ses:FromAddress` condition is the scope. The environment's task role
  # names its one From address; this is the ceiling over every environment.
  statement {
    sid       = "SendMailFromAnEnvironmentAddress"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["arn:${local.partition}:ses:${local.region}:${local.account_id}:identity/*"]
    condition {
      test     = "StringLike"
      variable = "ses:FromAddress"
      values   = local.ses_from_patterns
    }
  }
}

resource "aws_iam_policy" "workload_boundary" {
  name        = "${var.name}-workload-boundary"
  description = "The most any role an iya-sts environment creates may do"
  policy      = data.aws_iam_policy_document.workload_boundary.json
}

# ---------------------------------------------------------------------------
# THE BOUNDARY THE ECS INFRASTRUCTURE ROLE MUST CARRY (#214).
#
# Each environment creates one role that is not a task's: ECS assumes it to
# create, attach and delete each node's risk dataset upload volume
# (environment/iam.tf). What that takes — EC2 volume calls and the project key
# through EC2 — is kept OUT of the workload boundary above, so no container
# role can ever be given it, and in a ceiling of its own that the deployer may
# attach only to a role named `iya-sts-env-<environment>-ecs-infra` and pass
# only to `ecs.amazonaws.com` (below). The environment's own policy narrows it
# further, to volumes of that environment's cluster; the effective permission
# is the intersection.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_infrastructure_boundary" {
  # The region fence, as in the workload boundary above (#367).
  statement {
    sid         = "OnlyPermittedRegionsForRegionalServices"
    effect      = "Deny"
    not_actions = local.fence_exempt
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.regions
    }
  }
  statement {
    sid       = "CreateAndTagOnlyEcsManagedVolumes"
    actions   = ["ec2:CreateVolume", "ec2:CreateTags"]
    resources = [for p in local.rarn.ec2 : "${p}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:RequestTag/AmazonECSCreated"
      values   = [for p in local.rarn.ecs : "${p}:task/${var.name}-*/*"]
    }
  }
  statement {
    sid       = "DescribeVolumes"
    actions   = ["ec2:DescribeVolumes", "ec2:DescribeAvailabilityZones"]
    resources = ["*"]
  }
  statement {
    sid       = "AttachDetachDeleteOnlyEcsManagedVolumes"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume", "ec2:DeleteVolume"]
    resources = [for p in local.rarn.ec2 : "${p}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AmazonECSManaged"
      values   = ["true"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:ResourceTag/AmazonECSCreated"
      values   = [for p in local.rarn.ecs : "${p}:task/${var.name}-*/*"]
    }
  }
  # The Fargate host is in an account that is not this one.
  statement {
    sid       = "AttachDetachAtTheFargateHost"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume"]
    resources = ["arn:${local.partition}:ec2:*:*:instance/*"]
  }
  # A single-cell environment's volumes are sealed under the project key, a
  # cell's under its CELL key (#98) — resident data, never the global key.
  statement {
    sid       = "DescribeTheProjectKey"
    actions   = ["kms:DescribeKey"]
    resources = concat([aws_kms_key.main.arn], local.cell_key_arns)
  }
  statement {
    sid       = "UseTheProjectKeyForEbsThroughEc2"
    actions   = ["kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant"]
    resources = concat([aws_kms_key.main.arn], local.cell_key_arns)
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in local.regions : "ec2.${r}.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "ecs_infrastructure_boundary" {
  name        = "${var.name}-ecs-infrastructure-boundary"
  description = "The most an environment's ECS infrastructure role (upload volumes) may do"
  policy      = data.aws_iam_policy_document.ecs_infrastructure_boundary.json
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 1 OF 4: THE NETWORK AND THE LOAD BALANCER.
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
      # The suite runner's egress (environment/network.tf): one Elastic IP and
      # the NAT gateway it is attached to.
      "ec2:AllocateAddress", "ec2:CreateNatGateway",
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
    resources = [for p in local.rarn.ec2 : "${p}:vpc/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # A NAT gateway is created FROM an Elastic IP and IN a subnet, both resources
  # of the call — each must be the project's. Found on the first apply: the
  # request-tag statement above covers the gateway, not the address it uses.
  statement {
    sid     = "Ec2NatGatewayFromProjectAddressAndSubnet"
    actions = ["ec2:CreateNatGateway"]
    resources = flatten([
      for p in local.rarn.ec2 : ["${p}:elastic-ip/*", "${p}:subnet/*"]
    ])
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
        "AllocateAddress", "CreateNatGateway", "CreateVpcPeeringConnection",
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
      "ec2:DeleteNatGateway", "ec2:ReleaseAddress", "ec2:DisassociateAddress",
      # The inter-cell peering (#98), from either side once it is tagged.
      "ec2:DeleteVpcPeeringConnection", "ec2:RejectVpcPeeringConnection",
      "ec2:ModifyVpcPeeringConnectionOptions",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # A RULE IS ITS OWN RESOURCE (security-group-rule/sgr-…), and one created
  # WITH tags — which is how the provider creates every
  # `aws_vpc_security_group_*_rule` — is a resource of the Authorize call that
  # does not exist yet, so the `aws:ResourceTag` condition above refuses it.
  # Found on the first apply: the rules sat in "Creating..." retrying
  # UnauthorizedOperation on `security-group-rule/*`. The new rule is judged by
  # the tag it is created with; the group it goes in is still judged by its own
  # tag in the statement above, so no rule reaches another project's group.
  statement {
    sid = "Ec2SecurityGroupRulesCreatedTagged"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
    ]
    resources = [for p in local.rarn.ec2 : "${p}:security-group-rule/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

}

# THE REST OF WHAT WAS `deploy_network` (#311, 2026-09-29): load balancers,
# certificates, Route 53, the SES identity and the service-linked roles. One
# document held all of it until #98 wrote every regional ARN once per permitted
# region, and with two regions it passed IAM's 6,144-character limit on a
# managed policy (LimitExceeded on the foundation apply). Split, not trimmed:
# the deployer is attached to both, so it may do exactly what it could before.
data "aws_iam_policy_document" "deploy_edge" {
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
    resources = flatten([
      for p in local.rarn.elasticloadbalancing : [
        "${p}:loadbalancer/net/${var.name}-*",
        "${p}:targetgroup/${var.name}-*",
        "${p}:listener/net/${var.name}-*",
      ]
    ])
  }

  # A PUBLIC CERTIFICATE (environment/dns.tf). An ACM certificate's ARN is a
  # UUID, so it is scoped by the Project tag like EC2: created only with it,
  # read, changed and deleted only with it.
  statement {
    sid       = "AcmCreateOnlyTagged"
    actions   = ["acm:RequestCertificate", "acm:AddTagsToCertificate"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "AcmChangeOnlyTagged"
    actions = [
      "acm:DescribeCertificate", "acm:GetCertificate",
      "acm:ListTagsForCertificate", "acm:AddTagsToCertificate",
      "acm:RemoveTagsFromCertificate", "acm:DeleteCertificate",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "AcmList"
    actions   = ["acm:ListCertificates"]
    resources = ["*"]
  }

  # ITS NAME IN A PUBLIC ZONE: the zones in `public_dns` only, and in each only
  # the names listed for it. The zone is not the project's and holds other
  # records, which is why the names are the scope rather than the zone.
  statement {
    sid       = "Route53FindZones"
    actions   = ["route53:ListHostedZones", "route53:ListHostedZonesByName"]
    resources = ["*"]
  }

  statement {
    sid = "Route53ReadTheListedZones"
    actions = [
      "route53:GetHostedZone", "route53:ListResourceRecordSets",
      "route53:ListTagsForResource",
    ]
    resources = [for z in data.aws_route53_zone.public : z.arn]
  }

  statement {
    sid       = "Route53WriteOnlyTheListedNames"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = [for z in data.aws_route53_zone.public : z.arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = distinct(flatten(values(var.public_dns)))
    }
  }

  # AN SES IDENTITY FOR MAIL (#311, environment/mail.tf): the public names
  # only, so an environment can verify the name it serves and no other domain
  # in the account. Its DKIM CNAMEs fall under the names already allowed
  # above (`*.<name>`).
  statement {
    sid = "SesIdentityOnlyForTheListedNames"
    actions = [
      "ses:CreateEmailIdentity", "ses:GetEmailIdentity",
      "ses:DeleteEmailIdentity", "ses:PutEmailIdentityDkimAttributes",
      "ses:PutEmailIdentityDkimSigningAttributes",
      "ses:PutEmailIdentityMailFromAttributes",
      "ses:PutEmailIdentityFeedbackAttributes",
      "ses:PutEmailIdentityConfigurationSetAttributes",
      "ses:TagResource", "ses:UntagResource", "ses:ListTagsForResource",
    ]
    resources = local.ses_identity_arns
  }

  # THE PRIVATE ZONE PER PUBLIC NAME (#311, dns_inside.tf): an environment
  # associates its VPC with it and writes its record there. This zone's ARN
  # only — never a create or a delete of any zone.
  statement {
    sid = "Route53TheInsideZones"
    actions = [
      "route53:GetHostedZone", "route53:ListResourceRecordSets",
      "route53:ListTagsForResource", "route53:ChangeResourceRecordSets",
      "route53:AssociateVPCWithHostedZone",
      "route53:DisassociateVPCFromHostedZone",
    ]
    resources = [for z in aws_route53_zone.inside : z.arn]
  }

  statement {
    sid       = "Route53ListZonesByVpc"
    actions   = ["route53:ListHostedZonesByVPC"]
    resources = ["*"]
  }

  statement {
    sid       = "Route53WaitForChanges"
    actions   = ["route53:GetChange"]
    resources = ["arn:${local.partition}:route53:::change/*"]
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
# DEPLOY POLICY 2 OF 4: THE DATABASE, THE SECRETS, THE KEY, THE STATE.
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
    # In every permitted region (#98): a cell's database, and the global
    # database's cross-region read replicas, which name the primary's ARN in
    # its region as the source of the call.
    resources = flatten([
      for p in local.rarn.rds : [
        "${p}:db:${var.name}-*",
        "${p}:subgrp:${var.name}-*",
        "${p}:pg:${var.name}-*",
        "${p}:auto-backup:*",
        # The default option group, which a PostgreSQL instance is placed in
        # and which CreateDBInstance names as a resource of the call. Using it
        # changes nothing about it.
        "${p}:og:default:postgres-18",
      ]
    ])
  }

  # A CELL CONVERTED FROM A SINGLE-REGION ENVIRONMENT (#98, 2026-09-28):
  # its database is RESTORED from a snapshot of the old one's, and that
  # snapshot is first COPIED under the cell's key, because a restore keeps
  # the snapshot's key (environment/conversion.tf,
  # deploy/aws/convert-to-cells.sh). Only project-named snapshots and
  # instances. **NO DeleteDBSnapshot**: the snapshot is the record of the
  # database that was destroyed to make the cell, and removing it is an
  # administrator's decision, taken after the cell is known to be good.
  statement {
    sid = "RdsRestoreAndCopyProjectSnapshots"
    actions = [
      "rds:RestoreDBInstanceFromDBSnapshot", "rds:CopyDBSnapshot",
      "rds:AddTagsToResource",
    ]
    resources = flatten([
      for p in local.rarn.rds : [
        "${p}:snapshot:${var.name}-*",
        "${p}:db:${var.name}-*",
        "${p}:subgrp:${var.name}-*",
        "${p}:pg:${var.name}-*",
        "${p}:og:default:postgres-18",
      ]
    ])
  }

  statement {
    sid = "SecretsOnlyProjectNamed"
    actions = [
      "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource", "secretsmanager:UntagResource",
      "secretsmanager:GetResourcePolicy", "secretsmanager:RestoreSecret",
      # The global secrets' replicas in each cell region (#98). A replica is
      # made by Secrets Manager with the CALLER's rights in the replica's
      # region, which the ARNs below already cover in every permitted region.
      "secretsmanager:ReplicateSecretToRegions",
      "secretsmanager:RemoveRegionsFromReplication",
    ]
    resources = [for p in local.rarn.secretsmanager : "${p}:secret:${local.secret_prefix}*"]
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
  #
  # The keys (#98): the project key, the global multi-region key and its
  # replicas, and each permitted region's cell key — used, never administered.
  statement {
    sid = "UseTheProjectKey"
    actions = [
      "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
    ]
    resources = local.all_project_key_arns
  }

  statement {
    sid       = "GrantTheProjectKeyToAwsServicesOnly"
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = local.all_project_key_arns
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

  # A suite run's report, downloaded by run-suite-in-aws.sh and the workflow.
  statement {
    sid       = "ReadTestReports"
    actions   = ["s3:ListBucket"]
    resources = [local.arn.reports]
  }

  statement {
    sid       = "ReadTestReportObjects"
    actions   = ["s3:GetObject"]
    resources = ["${local.arn.reports}/*"]
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
      "ecr:ListTagsForResource",
    ]
    resources = [aws_ecr_repository.main.arn]
  }

  # A cell region's replica of the repository (#98): read, never pushed to —
  # the home repository is the one images are pushed to, and ECR copies them.
  statement {
    sid = "EcrReadTheRegionalReplicas"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer", "ecr:DescribeImages",
      "ecr:DescribeRepositories", "ecr:ListTagsForResource",
    ]
    resources = local.all_ecr_arns
  }

  statement {
    sid       = "ReadTheContainerLogs"
    actions   = ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:DescribeLogStreams"]
    resources = [for a in local.all_log_group_arns : "${a}:*"]
  }

  statement {
    sid       = "ReadTheContainerLogGroupTags"
    actions   = ["logs:ListTagsForResource"]
    resources = local.all_log_group_arns
  }

  statement {
    sid       = "LogsDescribe"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 3 OF 4: ECS, AND THE ROLES ITS TASKS RUN AS.
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
    resources = flatten([
      for p in local.rarn.ecs : [
        "${p}:cluster/${var.name}-*",
        "${p}:service/${var.name}-*",
        "${p}:task/${var.name}-*",
        "${p}:task-definition/${var.name}-*",
      ]
    ])
  }

  # The suite runs as a one-off task (environment/runner.tf), started by
  # run-suite-in-aws.sh. Only a project task definition, only in a project
  # cluster.
  statement {
    sid       = "EcsRunTheSuiteTask"
    actions   = ["ecs:RunTask"]
    resources = [for p in local.rarn.ecs : "${p}:task-definition/${var.name}-*"]
    condition {
      test     = "ArnLike"
      variable = "ecs:cluster"
      values   = [for p in local.rarn.ecs : "${p}:cluster/${var.name}-*"]
    }
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

  # THE ECS INFRASTRUCTURE ROLE (#214) — one name per environment, and only
  # with the boundary of its own. The statement above also matches the name,
  # with the WORKLOAD boundary, which gives such a role nothing it could use.
  statement {
    sid = "EcsInfrastructureRoleWriteOnlyWithItsBoundary"
    actions = [
      "iam:CreateRole", "iam:PutRolePolicy", "iam:PutRolePermissionsBoundary",
    ]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*-ecs-infra"]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.ecs_infrastructure_boundary.arn]
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

  # ECS itself, not a task, assumes the infrastructure role, and a service
  # names it in its `volume_configuration` (#214).
  statement {
    sid       = "PassTheEcsInfrastructureRoleToEcsOnly"
    actions   = ["iam:PassRole"]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*-ecs-infra"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs.amazonaws.com"]
    }
  }

  # AND NEVER TO A TASK: the statement allowing roles to be passed to
  # `ecs-tasks.amazonaws.com` matches this name too, and a task running as the
  # infrastructure role would hold EC2 volume and key permissions no container
  # needs. Its trust policy names `ecs.amazonaws.com` only, but the deployer
  # may change a trust policy; this does not depend on it.
  statement {
    sid       = "NeverPassTheEcsInfrastructureRoleToATask"
    effect    = "Deny"
    actions   = ["iam:PassRole"]
    resources = ["${local.arn.iam_role}/${local.env_role_prefix}*-ecs-infra"]
    condition {
      test     = "StringNotEquals"
      variable = "iam:PassedToService"
      values   = ["ecs.amazonaws.com"]
    }
  }

  statement {
    sid     = "ReadTheBoundaryItMustAttach"
    actions = ["iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = [
      aws_iam_policy.workload_boundary.arn,
      aws_iam_policy.ecs_infrastructure_boundary.arn,
    ]
  }

  # The boundary cannot be taken off a role, by the deployer or through it.
  statement {
    sid       = "NeverRemoveTheBoundary"
    effect    = "Deny"
    actions   = ["iam:DeleteRolePermissionsBoundary"]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 4 OF 4: WHAT ONLY A MULTI-CELL ENVIRONMENT DOES (#98,
# 2026-09-28) — the peering between cell VPCs, the health checks behind the
# latency records, and the private names the cells find each other by. A
# policy of its own because a managed policy holds 6,144 characters and the
# network policy, with every ARN now written once per permitted region, is
# the one closest to it; and so that what a single-cell environment can do is
# still read in the first three.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_cells" {
  # ---- THE INTER-CELL PEERING (#98, 2026-09-28): the global/ stack joins
  # every pair of cell VPCs, across regions. -------------------------------
  #
  # REQUESTED only tagged, and only between the project's own VPCs: the
  # request names both VPCs as resources, and each must carry Project = STS.
  # This is the one statement here that asks a tag of a resource in ANOTHER
  # region (the accepter VPC); if the first multi-cell apply answers
  # AccessDenied on the accepter's `vpc/…`, that condition is what to narrow
  # to `ec2:AccepterVpc`, keeping the requester's tag.
  statement {
    sid       = "Ec2PeeringRequestedTagged"
    actions   = ["ec2:CreateVpcPeeringConnection"]
    resources = [for p in local.rarn.ec2 : "${p}:vpc-peering-connection/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "Ec2PeeringBetweenProjectVpcs"
    actions   = ["ec2:CreateVpcPeeringConnection"]
    resources = [for p in local.rarn.ec2 : "${p}:vpc/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # ACCEPTED in the other region, where the connection arrives UNTAGGED — tags
  # are per region, and the requester's do not travel — so it cannot be
  # scoped by tag. It is scoped instead to a connection both of whose VPCs are
  # in this account and a permitted region; only the statements above can
  # create one from a project VPC. The accepter then tags its side, which is
  # what lets the change-only-tagged statement above delete it.
  statement {
    sid       = "Ec2PeeringAcceptedBetweenThisAccountsVpcs"
    actions   = ["ec2:AcceptVpcPeeringConnection"]
    resources = [for p in local.rarn.ec2 : "${p}:vpc-peering-connection/*"]
    condition {
      test     = "ArnLike"
      variable = "ec2:RequesterVpc"
      values   = [for p in local.rarn.ec2 : "${p}:vpc/*"]
    }
    condition {
      test     = "ArnLike"
      variable = "ec2:AccepterVpc"
      values   = [for p in local.rarn.ec2 : "${p}:vpc/*"]
    }
  }

  statement {
    sid       = "Ec2PeeringTagTheAccepterSide"
    actions   = ["ec2:CreateTags"]
    resources = [for p in local.rarn.ec2 : "${p}:vpc-peering-connection/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
    condition {
      test     = "ArnLike"
      variable = "ec2:RequesterVpc"
      values   = [for p in local.rarn.ec2 : "${p}:vpc/*"]
    }
  }

  # A MULTI-CELL ENVIRONMENT'S HEALTH CHECKS (#98): one per cell, on its load
  # balancer, behind that cell's latency record. A health check has no name
  # and no tag it can be created with, so it cannot be scoped the way the
  # records are; it can only make HTTPS requests to an address, which is what
  # it is for.
  statement {
    sid       = "Route53CreateHealthChecks"
    actions   = ["route53:CreateHealthCheck"]
    resources = ["*"]
  }

  statement {
    sid = "Route53HealthChecks"
    actions = [
      "route53:GetHealthCheck", "route53:UpdateHealthCheck",
      "route53:DeleteHealthCheck", "route53:ChangeTagsForResource",
      "route53:ListTagsForResource", "route53:GetHealthCheckStatus",
    ]
    resources = ["arn:${local.partition}:route53:::healthcheck/*"]
  }

  # THE INTER-CELL NAMES (#98): each cell's nodes register, through ECS, in
  # a Cloud Map private DNS namespace — a PRIVATE hosted zone Cloud Map makes
  # with the caller's rights — and the global/ stack associates each cell's
  # zone with the other cells' VPCs, so the name resolves only inside the
  # peered VPCs and in no public zone (environment/intercell.tf argues it
  # against an internal load balancer). A zone Cloud Map creates has an id
  # nobody can know in advance, so these name every hosted zone; the Deny
  # below keeps the public zones in `public_dns` out of reach of the deletion.
  statement {
    sid = "Route53PrivateZonesForCloudMap"
    actions = [
      "route53:CreateHostedZone", "route53:DeleteHostedZone",
      "route53:GetHostedZone", "route53:ListHostedZonesByName",
      "route53:AssociateVPCWithHostedZone",
      "route53:DisassociateVPCFromHostedZone",
      "route53:ListResourceRecordSets", "route53:ChangeTagsForResource",
      "route53:ListTagsForResource", "route53:ListHostedZonesByVPC",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Route53NeverDeleteThePublicZones"
    effect    = "Deny"
    actions   = ["route53:DeleteHostedZone", "route53:AssociateVPCWithHostedZone"]
    resources = [for z in data.aws_route53_zone.public : z.arn]
  }

  statement {
    sid       = "CloudMapCreateTagged"
    actions   = ["servicediscovery:CreatePrivateDnsNamespace", "servicediscovery:CreateService", "servicediscovery:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "CloudMapChangeOnlyTagged"
    actions = [
      "servicediscovery:DeleteNamespace", "servicediscovery:DeleteService",
      "servicediscovery:UpdateService",
      "servicediscovery:UpdatePrivateDnsNamespace",
      "servicediscovery:TagResource", "servicediscovery:UntagResource",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "CloudMapRead"
    actions = [
      "servicediscovery:Get*", "servicediscovery:List*",
      "servicediscovery:DiscoverInstances",
    ]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------
# DEPLOY POLICY 5 OF 5: WHAT ONLY A MULTI-CLOUD ENVIRONMENT DOES (#97,
# 2026-09-30) — deploy/multicloud/interconnect joins each AWS cell to its GCP
# partner. A policy of its own for the reason policy 4 is one: the size of a
# managed policy, and so that what an AWS-only environment can do is still
# read in the first four.
#
#   * the HA VPN's AWS half: a virtual private gateway on the cell's VPC, two
#     customer gateways (the GCP HA VPN gateway's two interfaces), two
#     Site-to-Site connections, and route propagation into the cell's route
#     tables — created only tagged, changed and deleted only tagged;
#   * a Route 53 Resolver INBOUND endpoint per AWS cell, so GCP's Cloud DNS
#     can forward the AWS cells' inter-cell names to it over the VPN;
#   * the records of the private zones that name the GCP cells inside the AWS
#     VPCs — only names under `.iya-sts.internal`, which no public zone holds.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_multicloud" {
  statement {
    sid = "Ec2VpnCreateOnlyTagged"
    actions = [
      "ec2:CreateVpnGateway", "ec2:CreateCustomerGateway",
      "ec2:CreateVpnConnection",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "Ec2VpnChangeOnlyTagged"
    actions = [
      "ec2:AttachVpnGateway", "ec2:DetachVpnGateway", "ec2:DeleteVpnGateway",
      "ec2:DeleteCustomerGateway", "ec2:DeleteVpnConnection",
      "ec2:ModifyVpnConnectionOptions", "ec2:ModifyVpnTunnelOptions",
      "ec2:EnableVgwRoutePropagation", "ec2:DisableVgwRoutePropagation",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "Route53ResolverCreateOnlyTagged"
    actions   = ["route53resolver:CreateResolverEndpoint", "route53resolver:TagResource"]
    resources = [for p in local.rarn.route53resolver : "${p}:resolver-endpoint/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid = "Route53ResolverChangeOnlyTagged"
    actions = [
      "route53resolver:DeleteResolverEndpoint",
      "route53resolver:UpdateResolverEndpoint",
      "route53resolver:AssociateResolverEndpointIpAddress",
      "route53resolver:DisassociateResolverEndpointIpAddress",
      "route53resolver:UntagResource",
    ]
    resources = [for p in local.rarn.route53resolver : "${p}:resolver-endpoint/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "Route53ResolverRead"
    actions   = ["route53resolver:Get*", "route53resolver:List*"]
    resources = ["*"]
  }

  # THE ENDPOINT'S INTERFACES are made with the CALLER's rights, in a
  # project subnet behind a project security group. Resolver does not tag
  # them, so their deletion cannot be scoped by tag: an interface still
  # attached cannot be deleted, which bounds what this can reach. If the
  # first apply answers AccessDenied on another ec2 action, it is named here.
  statement {
    sid       = "Ec2ResolverInterfacesInProjectSubnets"
    actions   = ["ec2:CreateNetworkInterface"]
    resources = [for p in local.rarn.ec2 : "${p}:subnet/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  statement {
    sid       = "Ec2ResolverInterfaces"
    actions   = ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"]
    resources = [for p in local.rarn.ec2 : "${p}:network-interface/*"]
  }

  statement {
    sid       = "Ec2ResolverInterfacesBehindProjectGroups"
    actions   = ["ec2:CreateNetworkInterface"]
    resources = [for p in local.rarn.ec2 : "${p}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # THE GCP CELLS' INTER-CELL NAMES, in private zones this deployer makes
  # (policy 4, Route53PrivateZonesForCloudMap): only `.iya-sts.internal`
  # names, which the public zones cannot hold.
  statement {
    sid       = "Route53PrivateInterCellRecords"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:${local.partition}:route53:::hostedzone/*"]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = ["*.iya-sts.internal"]
    }
  }
}

resource "aws_iam_policy" "deploy_multicloud" {
  name   = "${var.name}-deploy-multicloud"
  policy = data.aws_iam_policy_document.deploy_multicloud.json
}

resource "aws_iam_policy" "deploy_network" {
  name   = "${var.name}-deploy-network"
  policy = data.aws_iam_policy_document.deploy_network.json
}

resource "aws_iam_policy" "deploy_edge" {
  name   = "${var.name}-deploy-edge"
  policy = data.aws_iam_policy_document.deploy_edge.json
}

resource "aws_iam_policy" "deploy_data" {
  name   = "${var.name}-deploy-data"
  policy = data.aws_iam_policy_document.deploy_data.json
}

resource "aws_iam_policy" "deploy_compute" {
  name   = "${var.name}-deploy-compute"
  policy = data.aws_iam_policy_document.deploy_compute.json
}

resource "aws_iam_policy" "deploy_cells" {
  name   = "${var.name}-deploy-cells"
  policy = data.aws_iam_policy_document.deploy_cells.json
}

resource "aws_iam_role_policy_attachment" "deployer" {
  for_each = {
    network = aws_iam_policy.deploy_network.arn
    edge    = aws_iam_policy.deploy_edge.arn
    data    = aws_iam_policy.deploy_data.arn
    compute = aws_iam_policy.deploy_compute.arn
    cells   = aws_iam_policy.deploy_cells.arn
    # #97: the HA VPN, the inbound resolver and the private inter-cell
    # records of a multi-cloud environment.
    multicloud = aws_iam_policy.deploy_multicloud.arn
  }
  role       = aws_iam_role.deployer.name
  policy_arn = each.value
}

# EVERYTHING THE DEPLOYER DOES IS CONFINED TO THE PERMITTED REGIONS. It was
# one region, `OnlyUsWest2ForRegionalServices`, until #98 (2026-09-28); the
# list is `permitted_regions`. SINCE #367 (2026-09-30) THIS IS THE ONLY
# PLACE THE DEPLOYER'S REGIONS ARE NAMED: its statements' ARNs carry a `*`
# region (locals.tf, `rarn`), so that adding a region grows no policy, and
# the two boundaries carry this same Deny for the roles the deployer makes.
data "aws_iam_policy_document" "region_fence" {
  # Route53 is global, and its requests carry us-east-1.
  statement {
    sid         = "OnlyPermittedRegionsForRegionalServices"
    effect      = "Deny"
    not_actions = local.fence_exempt
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.regions
    }
  }
}

resource "aws_iam_role_policy" "region_fence" {
  name   = "region-fence"
  role   = aws_iam_role.deployer.name
  policy = data.aws_iam_policy_document.region_fence.json
}

data "aws_route53_zone" "public" {
  for_each     = var.public_dns
  name         = each.key
  private_zone = false
}
