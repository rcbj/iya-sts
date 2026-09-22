# ---------------------------------------------------------------------------
# THE IMAGE REPOSITORY.
#
# Four images per commit: `<sha>` (the service, built with the AWS SDK and the
# RDS CA bundle), `schema-<sha>` (the init container), `runner-<sha>` (the
# suite runner) and `pep-<sha>` (the remote XACML PEP the suite task runs).
# Private, scanned on push, and trimmed so a CI job that builds on every run
# does not accumulate storage for ever.
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "main" {
  name                 = var.name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }
}

resource "aws_ecr_lifecycle_policy" "main" {
  repository = aws_ecr_repository.main.name
  # TIGHTER SINCE 2026-09-21, from "keep the 30 most recent": a cap of 30
  # never let the repository shrink, and it had reached 26 images and 6 GB —
  # storage billed for builds nobody would deploy again. Count-based rather
  # than age-based ON PURPOSE: an age rule would in time expire the image a
  # long-lived `testidp` node is running, and that node could not then be
  # restarted. Sixteen is four builds of the four images a build pushes
  # (service, schema, runner, PEP), so any recent deployment's images stay.
  # Untagged images — what a re-pushed tag leaves behind — go after a day.
  # ECR applies rules in priority order and an image one rule selects is
  # never expired by a later one.
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after a day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the 16 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 16
        }
        action = { type = "expire" }
      }
    ]
  })
}
