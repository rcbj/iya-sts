# ---------------------------------------------------------------------------
# WHERE A SUITE RUN INSIDE AWS LEAVES ITS REPORT.
#
# The suite runs as an ECS task in an environment's VPC (environment/runner.tf),
# so nothing on the machine that started it sees the report directory. The task
# uploads it here, under `<environment>/<run id>/`, and run-suite-in-aws.sh or
# the workflow downloads it. It lives in the foundation rather than in an
# environment because an environment is destroyed at the end of the run that
# produced the report.
#
# Encrypted with S3-managed keys rather than the project KMS key: a report is a
# test run's HTML and logs, and a KMS key would put a kms:GenerateDataKey grant
# on the runner's role for nothing. Kept 30 days, the workflow artifact's
# retention.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "reports" {
  bucket        = local.reports_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-reports"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
