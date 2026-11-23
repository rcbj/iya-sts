# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE REMOTE XACML PEP AS A SCALED SERVICE ON AWS (#1284).
#
# #676 concluded the remote PEP needs no clustering mechanism: instances are
# stateless, share nothing, and converge on the PDP by themselves. So this is
# a plain service — the PEP image on Fargate, with a count, behind the
# environment's own network load balancer — and nothing new in the service.
# deploy/aws/CLAUDE.md, *A remote PEP cluster*, carries the reasoning; the
# user's half is docs/v1.2.0/aws-cluster.md and docs/v1.2.0/remote-pep.md,
# *Running more than one*.
#
# THE ONE CHOICE IS `credential_mode`, the table in remote-pep.md:
#   per-instance  one ECS service of ONE task per member, each with its own
#                 entry, assertion key, listener pair and notify port. A
#                 fixed count; every member a row and every member nudged.
#   shared        one ECS service of `instance_count` tasks (autoscaling
#                 optional) sharing one entry, key and pair. One row; the
#                 nudge reaches one task, the rest converge on their poll.
#
# THE KEYS COME FROM SECRETS MANAGER, NEVER FROM THIS STATE OR GIT. Each
# member's secret, `<secret path>/pep/<cluster>/<member>`, is created and
# written by provision.sh, which generates the key where it runs and sends
# the service only a certificate request; this stack looks the secret up by
# NAME (`aws_secretsmanager_secret` reads no value) and ECS injects its four
# JSON members into the container, which writes them to files and becomes
# the PEP. No private key is in any Terraform state.
#
# THE LOAD BALANCER IS THE ENVIRONMENT'S, so a PEP is reached at the name the
# service is (`direct_hostname`), on ports of its own:
#   decision_port (9443)      the decision API and the AuthZEN edge PDP,
#                             round robin — each decision stands alone
#   proxy_port (9543)         the reverse proxy, STICKY BY CLIENT ADDRESS:
#                             a sign-in, its session and its DPoP key live
#                             in one member (remote-pep.md, *The load
#                             balancer must keep a browser on one instance*)
#   notify_port_base + n      member n's 9443 alone, for the PDP's nudge. The
#                             nodes are the only source admitted.
# TLS passes through (TCP listeners), as it does for the service: the PEP
# terminates its own, with the pair the realm issued it, and an AuthZEN
# caller's client certificate still reaches it.
#
# WHY A NOTIFY PORT PER MEMBER, rather than service discovery: a Fargate
# task's address changes on every start, `hostname` is not available in
# awsvpc mode, and the deployer role has no Cloud Map grant. A target group
# per member is a stable name (the load balancer's) that reaches exactly one
# member — which is what "every member is nudged" needs, and what the
# member's listener certificate can name.
# ---------------------------------------------------------------------------

locals {
  # A cell's names carry the cell (#98, ../environment/locals.tf).
  prefix            = var.cell != "" ? "${var.name}-${var.environment}-${var.cell}" : "${var.name}-${var.environment}"
  role_prefix       = var.cell != "" ? "${var.name}-env-${var.environment}-${var.cell}" : "${var.name}-env-${var.environment}"
  secret_path       = var.cell != "" ? "${var.name}/${var.environment}/${var.cell}" : "${var.name}/${var.environment}"
  log_stream_prefix = var.cell != "" ? "${var.environment}-${var.cell}" : var.environment

  env     = data.terraform_remote_state.environment.outputs
  ecr_url = data.aws_ecr_repository.main.repository_url

  image_tag = var.image_tag != "" ? var.image_tag : local.env.image_tag
  image     = var.pep_image != "" ? var.pep_image : "${local.ecr_url}:pep-${local.image_tag}"

  # The name a member dials the service at and is dialled at. INSIDE the
  # VPC it resolves to the load balancer's private addresses
  # (environment/dns.tf, `inside`; cloudfront.tf, `direct_inside`), which is
  # what lets the security groups below name each other instead of an
  # address. An environment with no public name has no such record — its
  # load balancer's own DNS name resolves to public addresses everywhere —
  # so it is refused below rather than built to fail.
  public_name = try(local.env.public_hostname, "") != ""
  direct_host = try(local.env.direct_hostname, "")
  realm_path  = var.realm == "" ? "" : "/realm/${var.realm}"
  pdp_url     = "https://${local.direct_host}${local.realm_path}"

  # THE MEMBERS. per-instance: `<cluster>-pep-1` … `-<n>`, one task each.
  # shared: `<cluster>-pep`, `instance_count` tasks. `n` picks the notify
  # port and, per-instance, the subnet (spread over the three zones).
  per_instance = var.credential_mode == "per-instance"
  members = local.per_instance ? {
    for i in range(1, var.instance_count + 1) : "${var.cluster}-pep-${i}" => {
      n       = i
      desired = 1
    }
    } : {
    "${var.cluster}-pep" = { n = 1, desired = var.instance_count }
  }

  autoscaling = !local.per_instance && var.autoscaling_max > var.instance_count

  # The PEP's own ports, inside the task.
  pep_https_port = 9443
  pep_proxy_port = 9543

  # Where the container writes what ECS injected. The image runs as root and
  # /run is the container's own; nothing here is a volume, so a stopped task
  # leaves nothing behind.
  cred_dir = "/run/pep"

  # What the container does before it becomes the PEP: write the four
  # injected values to files, name the service's anchor when there is one,
  # forget the variables, exec. A pair that is still empty (provision.sh's
  # first pass) leaves the two paths absent, which is the documented "start
  # with paths that do not exist yet" state: the PEP registers, polls, and
  # starts its HTTPS listener within PEP_HTTPS_RELOAD_INTERVAL_MS of the
  # files appearing — here, at the next deployment after the second pass.
  start_script = join("\n", [
    "set -eu",
    "umask 077",
    "D=${local.cred_dir}",
    "mkdir -p \"$D/server\"",
    "printf '%s\\n' \"$PEP_SECRET_ASSERTION_KEY\" > \"$D/pep-assertion.key\"",
    "if [ -n \"$PEP_SECRET_HTTPS_CERT\" ] && [ -n \"$PEP_SECRET_HTTPS_KEY\" ]; then",
    "  printf '%s\\n' \"$PEP_SECRET_HTTPS_CERT\" > \"$D/server/pep-server.crt\"",
    "  printf '%s\\n' \"$PEP_SECRET_HTTPS_KEY\" > \"$D/server/pep-server.key\"",
    "fi",
    "if [ -n \"$PEP_SECRET_SERVICE_CA\" ]; then",
    "  printf '%s\\n' \"$PEP_SECRET_SERVICE_CA\" > \"$D/service-ca.pem\"",
    "  export PEP_TLS_CA=\"$D/service-ca.pem\"",
    "fi",
    "unset PEP_SECRET_ASSERTION_KEY PEP_SECRET_HTTPS_CERT PEP_SECRET_HTTPS_KEY PEP_SECRET_SERVICE_CA",
    "exec xacml-pep",
  ])

  # The four members of a member's secret, in the order provision.sh writes
  # them. ALL FOUR MUST BE PRESENT (an empty string is fine): ECS refuses to
  # start a task whose `valueFrom` names a JSON key the secret lacks.
  secret_keys = {
    PEP_SECRET_ASSERTION_KEY = "assertion_key"
    PEP_SECRET_HTTPS_CERT    = "https_cert"
    PEP_SECRET_HTTPS_KEY     = "https_key"
    PEP_SECRET_SERVICE_CA    = "service_ca"
  }

  container_log = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = local.env.container_log_group
      awslogs-region        = var.aws_region
      awslogs-stream-prefix = "${local.log_stream_prefix}-pep-${var.cluster}"
    }
  }

  # Every load-balancer port this stack publishes, and the PEP port behind
  # it. The notify ports are the nodes' alone.
  notify_ports = { for m, v in local.members : m => var.notify_port_base + v.n }
  client_ports = {
    decision = { listener = var.decision_port, container = local.pep_https_port }
    proxy    = { listener = var.proxy_port, container = local.pep_proxy_port }
  }

  # THE ADDRESSES THE ENVIRONMENT ADMITS on 443 are the ones admitted here:
  # read off the load balancer's group, as spiffe-realm/ does, so a cluster
  # is never open to more than the service it stands beside.
  allowed_cidrs = toset([
    for r in data.aws_vpc_security_group_rule.nlb : r.cidr_ipv4
    if !r.is_egress && r.from_port == 443 && r.cidr_ipv4 != null && r.cidr_ipv4 != ""
  ])

  # Ports a cluster may not take: everything the environment and the
  # default realm's SPIFFE listener already use (../spiffe-realm/main.tf).
  reserved_ports = [80, 88, 389, 443, 636, 8081, 8082, 8092, 8181, 8444]
  all_lb_ports   = concat([var.decision_port, var.proxy_port], values(local.notify_ports))
  port_problem = length(setintersection(toset(local.all_lb_ports), toset(local.reserved_ports))) > 0 ? "A PEP cluster port collides with one the environment uses (${join(", ", [for p in local.reserved_ports : tostring(p)])})." : (
    length(distinct(local.all_lb_ports)) != length(local.all_lb_ports) ? "decision_port, proxy_port and the notify ports (notify_port_base + 1..n) must all differ." : ""
  )
}

# --- What the environment built ---------------------------------------------

data "terraform_remote_state" "environment" {
  backend = "s3"
  config = {
    region = var.state_region
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key    = var.cell != "" ? "environment/${var.environment}/${var.cell}.tfstate" : "environment/${var.environment}.tfstate"
  }
}

data "aws_ecr_repository" "main" {
  name = var.name
}

data "aws_lb" "main" {
  name = local.prefix
}

data "aws_security_group" "nlb" {
  name   = "${local.prefix}-nlb"
  vpc_id = data.aws_lb.main.vpc_id
}

data "aws_security_group" "nodes" {
  name   = "${local.prefix}-nodes"
  vpc_id = data.aws_lb.main.vpc_id
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_lb.main.vpc_id]
  }
  filter {
    name   = "tag:Name"
    values = ["${local.prefix}-public-*"]
  }
}

data "aws_vpc_security_group_rules" "nlb" {
  filter {
    name   = "group-id"
    values = [data.aws_security_group.nlb.id]
  }
}

data "aws_vpc_security_group_rule" "nlb" {
  for_each               = toset(data.aws_vpc_security_group_rules.nlb.ids)
  security_group_rule_id = each.value
}

# The key each member's secret is sealed under: provision.sh creates it with
# the project key, or a cell's own (../environment/locals.tf).
data "aws_kms_key" "secrets" {
  key_id = var.cell != "" ? "alias/${var.name}-cell-${var.cell}" : "alias/${var.name}"
}

# EACH MEMBER'S SECRET, BY NAME. Metadata only — this data source reads no
# value — and it FAILS when the secret is missing, which is the point: run
# provision.sh first.
data "aws_secretsmanager_secret" "member" {
  for_each = local.members
  name     = "${local.secret_path}/pep/${var.cluster}/${each.key}"
}

# --- The members' network ---------------------------------------------------

resource "aws_security_group" "pep" {
  name        = "${local.prefix}-pep-${var.cluster}"
  description = "iya-sts ${var.environment}: remote PEP cluster ${var.cluster}, reachable from the load balancer only"
  vpc_id      = data.aws_lb.main.vpc_id

  lifecycle {
    precondition {
      condition     = local.public_name && local.direct_host != ""
      error_message = "A PEP cluster needs an environment with public_hostname: the members reach the service, and the nodes reach the members, at the name the VPC resolves to the load balancer's private addresses. ${var.environment} has none."
    }
    precondition {
      condition     = local.port_problem == ""
      error_message = local.port_problem
    }
    precondition {
      condition     = !(local.per_instance && var.autoscaling_max > 0)
      error_message = "autoscaling_max is for credential_mode = shared: per-instance members are a fixed count, each with its own key."
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "pep_from_nlb" {
  for_each                     = toset([tostring(local.pep_https_port), tostring(local.pep_proxy_port)])
  security_group_id            = aws_security_group.pep.id
  description                  = "The load balancer on ${each.value}"
  referenced_security_group_id = data.aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
}

# ECR, Secrets Manager, CloudWatch Logs, and the service itself (the load
# balancer's 443, at its private addresses).
resource "aws_vpc_security_group_egress_rule" "pep_https" {
  security_group_id = aws_security_group.pep.id
  description       = "AWS APIs and the service, on 443"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_pep" {
  security_group_id            = data.aws_security_group.nlb.id
  description                  = "PEP cluster ${var.cluster}: the members calling the service on 443"
  referenced_security_group_id = aws_security_group.pep.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_pep" {
  for_each                     = toset([tostring(local.pep_https_port), tostring(local.pep_proxy_port)])
  security_group_id            = data.aws_security_group.nlb.id
  description                  = "PEP cluster ${var.cluster}: forward and health-check on ${each.value}"
  referenced_security_group_id = aws_security_group.pep.id
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
}

# The PEP's clients: whoever the environment admits on 443.
resource "aws_vpc_security_group_ingress_rule" "nlb_clients" {
  for_each = {
    for pair in setproduct(keys(local.client_ports), local.allowed_cidrs) :
    "${pair[0]}-${pair[1]}" => { port = local.client_ports[pair[0]].listener, cidr = pair[1] }
  }
  security_group_id = data.aws_security_group.nlb.id
  description       = "PEP cluster ${var.cluster}: port ${each.value.port} from an allowed address"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

# THE NUDGE: the nodes, and only the nodes, to each member's notify port.
resource "aws_vpc_security_group_ingress_rule" "nlb_notify_from_nodes" {
  for_each                     = local.notify_ports
  security_group_id            = data.aws_security_group.nlb.id
  description                  = "PEP cluster ${var.cluster}: the nodes nudging ${each.key}"
  referenced_security_group_id = data.aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}

resource "aws_vpc_security_group_egress_rule" "nodes_notify" {
  for_each                     = local.notify_ports
  security_group_id            = data.aws_security_group.nodes.id
  description                  = "PEP cluster ${var.cluster}: nudge ${each.key}"
  referenced_security_group_id = data.aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}

# --- The load balancer ------------------------------------------------------
#
# Named `<prefix>-<load-balancer port>`: the environment's own groups are
# `<prefix>-<container port>` (8081, 636, 8082, 88) and spiffe-realm's carry
# `-sp-`/`-s`, so none of these ports can collide with them, and a cell's
# 27-character prefix still fits ELB's 32. NO PROXY PROTOCOL and no client
# address preserved: the PEP reads neither.

resource "aws_lb_target_group" "client" {
  for_each = local.client_ports

  name                   = "${local.prefix}-${each.value.listener}"
  port                   = each.value.container
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = data.aws_lb.main.vpc_id
  proxy_protocol_v2      = false
  preserve_client_ip     = "false"
  deregistration_delay   = 30
  connection_termination = true

  # Affinity by client address on the proxy only. The decision API needs
  # none: each decision stands alone.
  stickiness {
    type    = "source_ip"
    enabled = each.key == "proxy"
  }

  # BOTH ASK THE PEP'S 9443 /healthcheck, the image's own liveness question.
  # The proxy listener answers only once a route is configured on the
  # service, and a member with no route yet is still a live member.
  health_check {
    protocol            = "HTTPS"
    port                = tostring(local.pep_https_port)
    path                = "/healthcheck"
    matcher             = "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "notify" {
  for_each = local.notify_ports

  name                   = "${local.prefix}-${each.value}"
  port                   = local.pep_https_port
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = data.aws_lb.main.vpc_id
  proxy_protocol_v2      = false
  preserve_client_ip     = "false"
  deregistration_delay   = 10
  connection_termination = true

  health_check {
    protocol            = "HTTPS"
    port                = "traffic-port"
    path                = "/healthcheck"
    matcher             = "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "client" {
  for_each          = local.client_ports
  load_balancer_arn = data.aws_lb.main.arn
  port              = each.value.listener
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.client[each.key].arn
  }
}

resource "aws_lb_listener" "notify" {
  for_each          = local.notify_ports
  load_balancer_arn = data.aws_lb.main.arn
  port              = each.value
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.notify[each.key].arn
  }
}

# --- What the tasks run as --------------------------------------------------
#
# AN EXECUTION ROLE OF ITS OWN, NO TASK ROLE: ECS pulls the image, writes the
# logs and injects THIS cluster's secrets; the PEP itself calls no AWS API.
# The environment's execution role is not reused, so that no node can be
# given a PEP's key and no PEP a node's database password.

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

data "aws_iam_policy" "workload_boundary" {
  arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/${var.name}-workload-boundary"
}

resource "aws_iam_role" "execution" {
  name                 = "${local.role_prefix}-pep-${var.cluster}-exec"
  description          = "iya-sts ${var.environment}: PEP cluster ${var.cluster}'s tasks pull, log and receive their keys"
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
    resources = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${local.env.container_log_group}:*"]
  }
  statement {
    sid       = "InjectTheMembersSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for s in data.aws_secretsmanager_secret.member : s.arn]
  }
  statement {
    sid       = "DecryptThemThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.secrets.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "pep-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# --- The members --------------------------------------------------------------

resource "aws_ecs_task_definition" "member" {
  for_each = local.members

  family                   = "${local.prefix}-pep-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name       = "xacml-pep"
      image      = local.image
      essential  = true
      entryPoint = ["/bin/sh", "-c"]
      command    = [local.start_script]

      portMappings = [
        { containerPort = local.pep_https_port, protocol = "tcp" },
        { containerPort = local.pep_proxy_port, protocol = "tcp" },
      ]

      secrets = [
        for env, key in local.secret_keys : {
          name      = env
          valueFrom = "${data.aws_secretsmanager_secret.member[each.key].arn}:${key}::"
        }
      ]

      environment = [
        for k, v in merge({
          PEP_PDP_URL       = local.pdp_url
          PEP_NAME          = each.key
          PEP_CLIENT_ID     = "sts-remote-pep"
          PEP_ASSERTION_KEY = "${local.cred_dir}/pep-assertion.key"
          PEP_HTTPS_CERT    = "${local.cred_dir}/server/pep-server.crt"
          PEP_HTTPS_KEY     = "${local.cred_dir}/server/pep-server.key"
          PEP_HTTPS_PORT    = tostring(local.pep_https_port)
          # THE NUDGE GOES THROUGH THE LOAD BALANCER, to this member's own
          # port: the name is the one its listener certificate carries
          # (provision.sh asks for it), so the service's check of the host
          # against the certificate passes.
          PEP_NOTIFY_URL       = "https://${local.direct_host}:${local.notify_ports[each.key]}/notify"
          PEP_POLL_INTERVAL_MS = tostring(var.poll_interval_ms)
          PEP_LOG_LEVEL        = "info"
        }, var.extra_environment) : { name = k, value = v }
      ]

      # NO CONTAINER HEALTH CHECK. The image's own (`xacml-pep --healthcheck`)
      # reports a member with no listener pair yet as unhealthy, which is
      # accurate, and ECS would replace an essential container that reports
      # it — before provision.sh's second pass could ever issue the pair.
      # The load balancer's check, with health_check_grace_seconds, is the one
      # that replaces a member.
      logConfiguration = local.container_log
    }
  ])
}

resource "aws_ecs_service" "member" {
  for_each = local.members

  name            = "${local.prefix}-pep-${each.key}"
  cluster         = local.env.ecs_cluster
  task_definition = aws_ecs_task_definition.member[each.key].arn
  desired_count   = each.value.desired
  launch_type     = "FARGATE"

  # A per-instance member in one zone, spread round the three; a shared
  # service across all of them.
  network_configuration {
    subnets = local.per_instance ? [
      sort(data.aws_subnets.public.ids)[(each.value.n - 1) % length(data.aws_subnets.public.ids)]
    ] : data.aws_subnets.public.ids
    security_groups  = [aws_security_group.pep.id]
    assign_public_ip = true
  }

  dynamic "load_balancer" {
    for_each = local.client_ports
    content {
      target_group_arn = aws_lb_target_group.client[load_balancer.key].arn
      container_name   = "xacml-pep"
      container_port   = load_balancer.value.container
    }
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.notify[each.key].arn
    container_name   = "xacml-pep"
    container_port   = local.pep_https_port
  }

  health_check_grace_period_seconds  = var.health_check_grace_seconds
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  propagate_tags                     = "SERVICE"

  depends_on = [
    aws_lb_listener.client,
    aws_lb_listener.notify,
    aws_iam_role_policy.execution,
  ]

  lifecycle {
    # Application Auto Scaling owns the count of a shared, autoscaled
    # service, so Terraform never sets it back. The cost: a CHANGED
    # instance_count reaches a running shared service only through
    # `aws ecs update-service --desired-count` (or the autoscaling minimum).
    # A per-instance member's count is always 1, and its members are added
    # and removed as services.
    ignore_changes = [desired_count]
  }
}

# --- Autoscaling (shared only) ------------------------------------------------

resource "aws_appautoscaling_target" "shared" {
  count              = local.autoscaling ? 1 : 0
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${local.env.ecs_cluster}/${aws_ecs_service.member["${var.cluster}-pep"].name}"
  min_capacity       = var.instance_count
  max_capacity       = var.autoscaling_max
}

resource "aws_appautoscaling_policy" "shared_cpu" {
  count              = local.autoscaling ? 1 : 0
  name               = "${local.prefix}-pep-${var.cluster}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.shared[0].service_namespace
  scalable_dimension = aws_appautoscaling_target.shared[0].scalable_dimension
  resource_id        = aws_appautoscaling_target.shared[0].resource_id

  target_tracking_scaling_policy_configuration {
    target_value = var.autoscaling_cpu_target
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
