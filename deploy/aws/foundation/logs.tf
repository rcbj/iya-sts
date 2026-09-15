# ---------------------------------------------------------------------------
# CONTAINER LOGS, KEPT AFTER THE ENVIRONMENT THAT WROTE THEM IS GONE.
#
# Here and not in `environment/` because a log group destroyed with the
# environment takes the evidence with it, and the reason for keeping logs is to
# read them after a failed run has been torn down. Each ECS task writes a stream
# named `<environment>-<node>/<container>/<task-id>`, so several environments share
# the group without meeting.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "containers" {
  name              = local.container_log_grp
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}
