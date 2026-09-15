# ---------------------------------------------------------------------------
# ONE CUSTOMER-MANAGED KEY FOR THE PROJECT.
#
# It encrypts the Secrets Manager secrets (the key-encryption key, the database
# passwords, the admin API client secret), both RDS instances' storage and
# their automated backups, and the container log group.
#
# LONG-LIVED ON PURPOSE. A key created per environment would enter a seven-day
# pending-deletion window on every teardown, and a CI job that runs daily would
# keep a week of them. One key, $1 a month.
#
# The key policy delegates to IAM (the account statement) and adds the one
# service principal that cannot be granted through IAM: CloudWatch Logs.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid = "CloudWatchLogsEncryptsTheContainerLogGroup"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["${local.arn.logs}:/${var.name}/*"]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "mock-sts (issue #51): secrets, RDS storage and backups, container logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.main.key_id
}
