# ---------------------------------------------------------------------------
# THE SUITE'S CALLBACK HALF, IN THE ENVIRONMENT'S VPC, FOR THE LENGTH OF ONE
# RUN (2026-09-18).
#
# The protocol suite runs from a developer's machine against an environment's
# load balancer (deploy/aws/run-suite.sh). Two jobs cannot: the SERVICE has to
# open a connection to them, and a machine behind NAT cannot be dialled.
#
#   sts_xacml_remote_pep  the PDP nudges a remote PEP container, and the job
#                         writes that PEP's HTTPS listener certificate into a
#                         directory the container reads
#   sts_gnap_core         the service POSTs a GNAP push finish to a listener
#                         the job opens
#
# So this stack puts exactly what they need inside the VPC — a subnet with a
# NAT gateway (a FIXED address the load balancer admits, known before the task
# exists), a security group the nodes may call back into, and a task of three
# containers sharing a volume: the credential step, the remote PEP, and the two
# jobs. run-suite.sh applies it, runs the task once, reads the report the task
# uploads, and DESTROYS it — pass, fail or interrupt. rcbj's design, chosen on
# 2026-09-18 over a runner that lives with the environment: nothing of it bills
# between runs.
#
# IT IS environment/runner.tf RE-HOMED, NOT REWRITTEN. The containers, their
# settings and the three scripts they run (deploy/aws/runner/) are that file's;
# what differs is that everything the environment built is LOOKED UP here, so
# the stack can be created and destroyed without touching the environment's
# state. The subnet is the VPC's /24 number 21 — runner.tf's is 20, so an
# environment that also has its own runner (`suite_runner`, dev and ci) does
# not collide.
# ---------------------------------------------------------------------------

locals {
  prefix      = "${var.name}-${var.environment}"
  role_prefix = "${var.name}-env-${var.environment}"
  env         = data.terraform_remote_state.environment.outputs
  ecr_url     = data.aws_ecr_repository.main.repository_url

  runner_image = "${local.ecr_url}:runner-${var.image_tag}"
  pep_image    = "${local.ecr_url}:pep-${var.image_tag}"

  # Every port the load balancer publishes, admitted from the NAT address, so
  # the jobs reach the service exactly as any client does.
  listener_ports = { for k, p in local.env.load_balancer_ports : k => p.listener }

  pep_subject = "CN=remote-pep-1,OU=remote-peps,O=mock-sts"
  pep_name    = "remote-pep-1"
  pep_realm   = "pep-e2e"

  task_ip_js = "fetch(process.env.ECS_CONTAINER_METADATA_URI_V4+'/task').then(r=>r.json()).then(t=>process.stdout.write(t.Containers[0].Networks[0].IPv4Addresses[0]))"

  container_log = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = local.env.container_log_group
      awslogs-region        = var.aws_region
      awslogs-stream-prefix = "${var.environment}-callbacks"
    }
  }
}

# --- What the environment built ---------------------------------------------

data "terraform_remote_state" "environment" {
  backend = "s3"
  config = {
    region = var.aws_region
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key    = "environment/${var.environment}.tfstate"
  }
}

data "aws_ecr_repository" "main" {
  name = var.name
}

data "aws_vpc" "main" {
  tags = { Name = "${local.prefix}-vpc" }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
  tags = { Name = "${local.prefix}-public-*" }
}

# The NAT gateway goes in the first public subnet, and the task's subnet in the
# same availability zone.
data "aws_subnet" "nat" {
  id = sort(data.aws_subnets.public.ids)[0]
}

data "aws_security_group" "nlb" {
  name   = "${local.prefix}-nlb"
  vpc_id = data.aws_vpc.main.id
}

data "aws_security_group" "nodes" {
  name   = "${local.prefix}-nodes"
  vpc_id = data.aws_vpc.main.id
}

data "aws_iam_role" "execution" {
  name = "${local.role_prefix}-exec"
}

data "aws_iam_policy" "workload_boundary" {
  arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.name}-workload-boundary"
}

# --- The subnet and its way out ---------------------------------------------

resource "aws_subnet" "callbacks" {
  vpc_id            = data.aws_vpc.main.id
  cidr_block        = cidrsubnet(data.aws_vpc.main.cidr_block, 8, 21)
  availability_zone = data.aws_subnet.nat.availability_zone
  tags              = { Name = "${local.prefix}-callbacks-${data.aws_subnet.nat.availability_zone}" }
}

resource "aws_eip" "callbacks" {
  domain = "vpc"
  tags   = { Name = "${local.prefix}-callbacks-nat" }
}

resource "aws_nat_gateway" "callbacks" {
  allocation_id = aws_eip.callbacks.id
  subnet_id     = data.aws_subnet.nat.id
  tags          = { Name = "${local.prefix}-callbacks-nat" }
}

resource "aws_route_table" "callbacks" {
  vpc_id = data.aws_vpc.main.id
  tags   = { Name = "${local.prefix}-callbacks-rt" }
}

resource "aws_route" "callbacks_default" {
  route_table_id         = aws_route_table.callbacks.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.callbacks.id
}

resource "aws_route_table_association" "callbacks" {
  subnet_id      = aws_subnet.callbacks.id
  route_table_id = aws_route_table.callbacks.id
}

# --- Security groups ----------------------------------------------------------
# The task reaches the load balancer from the NAT address like any client, and
# the nodes reach the task directly (the GNAP push, the PDP's nudge to 9090).

resource "aws_security_group" "callbacks" {
  name        = "${local.prefix}-callbacks"
  description = "mock-sts ${var.environment}: the suite callback task, reachable from the nodes only"
  vpc_id      = data.aws_vpc.main.id
  tags        = { Name = "${local.prefix}-callbacks" }
}

resource "aws_vpc_security_group_ingress_rule" "callbacks_from_nodes" {
  security_group_id            = aws_security_group.callbacks.id
  description                  = "Callbacks from the nodes (GNAP push, PEP notify)"
  referenced_security_group_id = data.aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 1
  to_port                      = 65535
}

resource "aws_vpc_security_group_egress_rule" "callbacks_out" {
  security_group_id = aws_security_group.callbacks.id
  description       = "Anything, through the NAT gateway"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_egress_rule" "nodes_to_callbacks" {
  security_group_id            = data.aws_security_group.nodes.id
  description                  = "Call back to the suite callback task (GNAP push, PEP notify)"
  referenced_security_group_id = aws_security_group.callbacks.id
  ip_protocol                  = "tcp"
  from_port                    = 1
  to_port                      = 65535
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_callbacks" {
  for_each          = local.listener_ports
  security_group_id = data.aws_security_group.nlb.id
  description       = "Port ${each.value} from the suite callback task"
  cidr_ipv4         = "${aws_eip.callbacks.public_ip}/32"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
}

# --- The task -----------------------------------------------------------------

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
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "callbacks" {
  name                 = "${local.role_prefix}-callbacks"
  description          = "mock-sts ${var.environment}: the suite callback task uploads its report"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = data.aws_iam_policy.workload_boundary.arn
}

data "aws_iam_policy_document" "callbacks" {
  statement {
    sid       = "UploadThisEnvironmentsReports"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["arn:aws:s3:::${local.env.reports_bucket}/${var.environment}/*"]
  }
}

resource "aws_iam_role_policy" "callbacks" {
  name   = "upload-reports"
  role   = aws_iam_role.callbacks.id
  policy = data.aws_iam_policy_document.callbacks.json
}

resource "aws_ecs_task_definition" "callbacks" {
  family                   = "${local.prefix}-callbacks"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  task_role_arn            = aws_iam_role.callbacks.arn
  execution_role_arn       = data.aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "shared"
  }

  # The same three containers as environment/runner.tf's suite task, argued
  # there. The suite container runs deploy/aws/runner/run-in-task.sh, which
  # run-suite.sh points at the two callback jobs with STS_SUITE_ONLY and tells
  # to leave the local run's realms alone with STS_SUITE_KEEP_REALMS.
  container_definitions = jsonencode([
    {
      name        = "pep-credential"
      image       = local.runner_image
      essential   = false
      command     = ["bash", "deploy/aws/runner/pep-credential.sh"]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      environment = [
        { name = "STS_SUITE_SERVICE_URL", value = local.env.service_url },
        { name = "XACML_PEP_SUBJECT", value = local.pep_subject },
      ]
      # The anchor goes through /admin-api on a product-mode service, so this
      # container mints the management API's token (pep-credential.sh).
      secrets = [
        { name = "STS_ADMIN_API_CLIENT_SECRET", valueFrom = local.env.admin_api_client_secret_arn },
      ]
      logConfiguration = local.container_log
    },
    {
      name        = "xacml-pep"
      image       = local.pep_image
      essential   = false
      dependsOn   = [{ containerName = "pep-credential", condition = "COMPLETE" }]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      entryPoint  = ["sh", "-c"]
      command = [
        "export PEP_PDP_URL=\"${local.env.service_url}/realm/$${XACML_PEP_REALM}\"; export PEP_NOTIFY_URL=\"http://$(node -e \"${local.task_ip_js}\"):9090/notify\"; exec node pep.js",
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
      logConfiguration = local.container_log
    },
    {
      name        = "suite"
      image       = local.runner_image
      essential   = true
      dependsOn   = [{ containerName = "xacml-pep", condition = "START" }]
      command     = ["bash", "deploy/aws/runner/run-in-task.sh"]
      mountPoints = [{ sourceVolume = "shared", containerPath = "/shared" }]
      environment = [
        { name = "STS_SUITE_ENVIRONMENT", value = var.environment },
        { name = "STS_SUITE_SERVICE_URL", value = local.env.service_url },
        { name = "STS_REPORTS_BUCKET", value = local.env.reports_bucket },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "STS_TEST_CLUSTER_NODES", value = tostring(length(local.env.ecs_services)) },
        { name = "STS_LDAP_URL", value = "ldap://${local.env.nlb_dns_name}:${local.env.load_balancer_ports.ldap.listener}" },
        { name = "STS_LDAP_PORT", value = tostring(local.env.load_balancer_ports.ldap.listener) },
        { name = "XACML_PEP_URL", value = "http://localhost:9090" },
        { name = "XACML_PEP_HTTPS_URL", value = "https://localhost:9443" },
        { name = "XACML_PEP_SERVER_CERT_DIR", value = "/shared/pep/server" },
        { name = "XACML_PEP_CA_PEM_FILE", value = "/shared/pep/ca.crt" },
        { name = "XACML_PEP_NAME", value = local.pep_name },
        { name = "XACML_PEP_REALM", value = local.pep_realm },
      ]
      secrets = [
        { name = "STS_ADMIN_API_CLIENT_SECRET", valueFrom = local.env.admin_api_client_secret_arn },
      ]
      logConfiguration = local.container_log
    },
  ])
}
