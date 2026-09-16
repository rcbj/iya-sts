# ---------------------------------------------------------------------------
# THE PROTOCOL SUITE, RUN INSIDE THE VPC AS A ONE-OFF TASK (issue #51).
#
# WHY INSIDE AWS. Two jobs need the SERVICE to open a connection to the
# RUNNER: sts_gnap_core's push finish method posts to a listener the job
# opens, and sts_xacml_remote_pep's PDP nudges a PEP container that shares a
# certificate directory with the job. A developer machine behind NAT and a
# GitHub-hosted runner can make outbound connections only. A task in the VPC
# can be reached by the nodes directly, and every request it makes is a
# round trip inside one region rather than across the internet — the first
# suite run from outside took over an hour for half the jobs.
#
# NOT A SERVICE. run-suite-in-aws.sh starts it with `ecs run-task`, waits for
# it to stop, and reads the report the task uploaded to the foundation's
# report bucket. Nothing runs, or bills, between suite runs except the NAT
# gateway (network.tf).
#
# THREE CONTAINERS SHARING A NETWORK NAMESPACE AND ONE TASK VOLUME, which is
# the shape ./docker-run-tests.sh gives the same jobs with three compose
# services and a bind mount:
#
#   pep-credential  mints the remote PEP's client certificate and posts its
#                   Root to the service's truststore (tests/tools/pep-credential.js),
#                   then exits. Not essential: a failure costs one job.
#   xacml-pep       the remote PEP, started once the credential exists. It reads
#                   its client certificate at start, and its HTTPS listener's
#                   pair, which the job issues later, from the shared volume.
#                   It registers the task's own address as the one to nudge.
#   suite           deploy/aws/runner/run-in-task.sh: the protocol half of
#                   run-report.js against the load balancer, every job in the
#                   manifest, then the report to S3. Its exit code is the run's.
#
# The PEP is reached by the job on localhost; the realm it polls is
# `XACML_PEP_REALM`, which run-suite-in-aws.sh sets per run on both containers
# so a second run against one environment does not meet the first run's realm.
# ---------------------------------------------------------------------------
locals {
  runner_container_log = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = data.aws_cloudwatch_log_group.containers.name
      awslogs-region        = local.region
      awslogs-stream-prefix = "${var.environment}-suite"
    }
  }

  pep_subject = "CN=remote-pep-1,OU=remote-peps,O=mock-sts"
  pep_name    = "remote-pep-1"
  pep_realm   = "pep-e2e"

  # The task's own address, read from the ECS task metadata endpoint — the
  # address the nodes can reach. Node 22 in the PEP image has fetch.
  task_ip_js = "fetch(process.env.ECS_CONTAINER_METADATA_URI_V4+'/task').then(r=>r.json()).then(t=>process.stdout.write(t.Containers[0].Networks[0].IPv4Addresses[0]))"
}

resource "aws_iam_role" "runner" {
  count                = var.suite_runner ? 1 : 0
  name                 = "${local.role_prefix}-runner"
  description          = "mock-sts ${var.environment}: the suite task uploads its report"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = data.aws_iam_policy.workload_boundary.arn
}

data "aws_iam_policy_document" "runner" {
  statement {
    sid       = "UploadThisEnvironmentsReports"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["arn:${local.partition}:s3:::${local.reports_bucket}/${var.environment}/*"]
  }
}

resource "aws_iam_role_policy" "runner" {
  count  = var.suite_runner ? 1 : 0
  name   = "upload-reports"
  role   = aws_iam_role.runner[0].id
  policy = data.aws_iam_policy_document.runner.json
}

resource "aws_ecs_task_definition" "suite" {
  count = var.suite_runner ? 1 : 0

  family                   = "${local.prefix}-suite"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.runner_task_cpu
  memory                   = var.runner_task_memory
  task_role_arn            = aws_iam_role.runner[0].arn
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "shared"
  }

  container_definitions = jsonencode([
    {
      name        = "pep-credential"
      image       = "${local.ecr_repository_url}:${local.runner_image_tag}"
      essential   = false
      command     = ["bash", "deploy/aws/runner/pep-credential.sh"]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      environment = [
        { name = "STS_SUITE_SERVICE_URL", value = local.public_base_url },
        { name = "XACML_PEP_SUBJECT", value = local.pep_subject },
      ]
      logConfiguration = local.runner_container_log
    },
    {
      name        = "xacml-pep"
      image       = "${local.ecr_repository_url}:${local.pep_image_tag}"
      essential   = false
      dependsOn   = [{ containerName = "pep-credential", condition = "COMPLETE" }]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      entryPoint  = ["sh", "-c"]
      command = [
        "export PEP_PDP_URL=\"${local.public_base_url}/realm/$${XACML_PEP_REALM}\"; export PEP_NOTIFY_URL=\"http://$(node -e \"${local.task_ip_js}\"):9090/notify\"; exec node pep.js",
      ]
      environment = [
        { name = "XACML_PEP_REALM", value = local.pep_realm },
        { name = "PEP_NAME", value = local.pep_name },
        { name = "PEP_TLS_CERT", value = "/shared/pep/pep.crt" },
        { name = "PEP_TLS_KEY", value = "/shared/pep/pep.key" },
        { name = "PEP_HTTPS_CERT", value = "/shared/pep/server/pep-server.crt" },
        { name = "PEP_HTTPS_KEY", value = "/shared/pep/server/pep-server.key" },
        { name = "PEP_HTTPS_PORT", value = "9443" },
        { name = "PEP_HTTPS_RELOAD_INTERVAL_MS", value = "1000" },
        { name = "PEP_TLS_INSECURE", value = "true" },
        { name = "PEP_RESOURCE", value = "https://example.test/records" },
        { name = "PEP_BIAS", value = "deny-biased" },
        { name = "PEP_PIP", value = "true" },
        { name = "PEP_POLL_INTERVAL_MS", value = "5000" },
        { name = "PEP_HEARTBEAT_INTERVAL_MS", value = "2000" },
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "node -e \"require('http').get({host:'localhost',port:9090,path:'/healthcheck'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))\""]
        interval    = 10
        timeout     = 5
        retries     = 6
        startPeriod = 10
      }
      logConfiguration = local.runner_container_log
    },
    {
      name        = "suite"
      image       = "${local.ecr_repository_url}:${local.runner_image_tag}"
      essential   = true
      dependsOn   = [{ containerName = "xacml-pep", condition = "START" }]
      command     = ["bash", "deploy/aws/runner/run-in-task.sh"]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      environment = [
        { name = "STS_SUITE_ENVIRONMENT", value = var.environment },
        { name = "STS_SUITE_SERVICE_URL", value = local.public_base_url },
        { name = "STS_REPORTS_BUCKET", value = local.reports_bucket },
        { name = "AWS_REGION", value = local.region },
        { name = "STS_TEST_CLUSTER_NODES", value = tostring(var.node_count) },
        { name = "STS_LDAP_URL", value = "ldap://${aws_lb.main.dns_name}:${local.published_ports.ldap.listener}" },
        { name = "STS_LDAP_PORT", value = tostring(local.published_ports.ldap.listener) },
        # `STS_MTLS_PORT` was here until 2026-09-16 and named the service's own
        # 9443 listener, which was deleted with 8443. A certificate sign-in is
        # GET /tls/sign-in on the main port now, which the suite already has
        # from STS_SUITE_SERVICE_URL. The XACML PEP's own 9443 below is a
        # DIFFERENT port, in a different container, and is untouched.
        { name = "XACML_PEP_URL", value = "http://localhost:9090" },
        { name = "XACML_PEP_HTTPS_URL", value = "https://localhost:9443" },
        { name = "XACML_PEP_SERVER_CERT_DIR", value = "/shared/pep/server" },
        { name = "XACML_PEP_CA_PEM_FILE", value = "/shared/pep/ca.crt" },
        { name = "XACML_PEP_NAME", value = local.pep_name },
        { name = "XACML_PEP_REALM", value = local.pep_realm },
      ]
      secrets = [
        { name = "STS_ADMIN_API_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.main["admin-api-client-secret"].arn },
      ]
      logConfiguration = local.runner_container_log
    },
  ])
}
