# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER AS AN ENVIRONMENT OF ITS OWN (#1284).
#
# #676 concluded the remote PEP needs no clustering mechanism: instances are
# stateless, share nothing, and converge on the PDP by themselves. So this is
# a plain service — the PEP image on Fargate behind a load balancer — in a
# VPC, an ECS cluster and a load balancer of its own, reaching the identity
# service at `idp_url` over the internet, the way a customer's deployment
# beside their application would. IT READS NOTHING OF ANY iya-sts
# ENVIRONMENT: no remote state, no shared load balancer, no shared security
# group (rcbj, 2026-11-23: "Make the remote pep-cluster a separate
# environment. don't chain it to the iya-sts cluster's environment").
# deploy/aws/CLAUDE.md, *A remote PEP cluster*, carries the reasoning; the
# user's half is docs/v1.2.0/aws-cluster.md.
#
#   browser ──443──▶ WAF ▶ ALB (ACM cert) ─HTTPS, sticky cookie─▶ member 9543
#   app     ──9443─▶ WAF ▶ ALB             ─HTTPS, round robin──▶ member 9443
#   member  ──443──▶ NAT (egress_ip) ──────────────────────────▶ idp_url
#
# AN APPLICATION LOAD BALANCER, BECAUSE THE WAF NEEDS ONE. AWS WAF attaches to
# an ALB, CloudFront or API Gateway, never to an NLB. The ALB ends TLS with a
# PUBLIC certificate for `public_hostname`, so a browser always sees that one
# certificate whichever member answers (each member's own listener pair,
# issued by the realm, is what the ALB re-encrypts to and does not check),
# and it keeps a browser on one member with its own cookie — a sign-in, its
# session and its DPoP key live in one member (remote-pep.md, *The load
# balancer must keep a browser on one instance*).
#
# THE MEMBERS ARE IN PRIVATE SUBNETS AND LEAVE THROUGH ONE NAT GATEWAY, so
# the environment has ONE fixed egress address (`egress_ip`) for the
# identity service to admit — testidp's WAF admits only its allowed_cidrs.
#
# THE ONE CHOICE IS `credential_mode`, the table in remote-pep.md:
#   per-instance  one ECS service of ONE task per member, each with its own
#                 entry, assertion key and listener pair. A fixed count;
#                 every member a row on the console.
#   shared        one ECS service of `instance_count` tasks (autoscaling
#                 optional) sharing one entry, key and pair. One row.
#
# THE NUDGE IS OPTIONAL (`notify_cidrs`). The service nudges a PEP by
# dialling it; here that is the load balancer, which admits only the
# addresses it is given. An identity service with fixed egress addresses
# names them and each member gets a notify port of its own; one without
# (testidp's nodes leave from addresses that change with every task) gets
# none, provision.sh stops nudging the members' rows, and they converge on
# their poll — a 304 while nothing changed.
#
# THE KEYS COME FROM SECRETS MANAGER, NEVER FROM THIS STATE OR GIT. Each
# member's secret, `<secret path>/pep/<cluster>/<member>`, is created and
# written by provision.sh, which generates the key where it runs and sends
# the service only a certificate request; this stack looks the secret up by
# NAME (`aws_secretsmanager_secret` reads no value) and ECS injects its four
# JSON members into the container, which writes them to files and becomes
# the PEP. No private key is in any Terraform state.
# ---------------------------------------------------------------------------

locals {
  prefix      = "${var.name}-${var.environment}"
  role_prefix = "${var.name}-env-${var.environment}"
  secret_path = "${var.name}/${var.environment}"

  ecr_url = data.aws_ecr_repository.main.repository_url
  image   = var.pep_image != "" ? var.pep_image : "${local.ecr_url}:pep-${var.image_tag}"

  idp_base   = trimsuffix(var.idp_url, "/")
  realm_path = var.realm == "" ? "" : "/realm/${var.realm}"
  pdp_url    = "${local.idp_base}${local.realm_path}"

  # THE MEMBERS. per-instance: `<cluster>-pep-1` … `-<n>`, one task each.
  # shared: `<cluster>-pep`, `instance_count` tasks. `n` picks the notify
  # port and, per-instance, the subnet (spread over the zones).
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
  notify      = length(var.notify_cidrs) > 0
  notify_ports = local.notify ? {
    for m, v in local.members : m => var.notify_port_base + v.n
  } : {}

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
      awslogs-group         = data.aws_cloudwatch_log_group.containers.name
      awslogs-region        = var.aws_region
      awslogs-stream-prefix = "${var.environment}-${var.cluster}"
    }
  }

  # THE COMPANION SIDECAR (`var.companion`): `/pep-app`, the application the
  # demonstrations put behind the reverse proxy. A container in EACH
  # member's task rather than a service of its own, for two reasons. Its
  # `/pep-app/protected` and `/whoami` take the person from identity
  # HEADERS the proxy sets (#1972), so it must be reachable by the proxy
  # and by nothing else; inside one task the proxy reaches it at
  # 127.0.0.1:9700 and no security group rule names 9700, so no other
  # caller can. And a cluster route has one upstream for every member,
  # which `http://127.0.0.1:9700` is — each member's own companion. It is
  # not essential: a companion that stops costs `/pep-app` a 502 and leaves
  # the member deciding. The task grows to hold a second node process.
  companion_image = var.companion_image != "" ? var.companion_image : "${local.ecr_url}:companion-${var.image_tag}"
  companion_port  = 9700
  task_cpu        = var.companion ? max(var.task_cpu, 512) : var.task_cpu
  task_memory     = var.companion ? max(var.task_memory, 1024) : var.task_memory
  companion_container = {
    name      = "companion"
    image     = local.companion_image
    essential = false
    environment = [
      for k, v in {
        COMPANION_PORT       = tostring(local.companion_port)
        COMPANION_PUBLIC_URL = "http://127.0.0.1:${local.companion_port}"
        # The service, at its public name, verified against the image's
        # roots. `/pep-app` dials it only for a realm's metadata and JWKS,
        # in the proxy's jwt and saml identity modes.
        COMPANION_STS_URL           = local.pdp_url
        COMPANION_STS_PUBLIC_URL    = local.pdp_url
        COMPANION_KRB5_SERVICE_PORT = "off"
      } : { name = k, value = v }
    ]
    logConfiguration = local.container_log
  }
}

# --- What the foundation built ----------------------------------------------

data "aws_ecr_repository" "main" {
  name = var.name
}

data "aws_cloudwatch_log_group" "containers" {
  name = "/${var.name}/containers"
}

# The key each member's secret is sealed under: provision.sh creates it with
# the project key.
data "aws_kms_key" "secrets" {
  key_id = "alias/${var.name}"
}

# EACH MEMBER'S SECRET, BY NAME. Metadata only — this data source reads no
# value — and it FAILS when the secret is missing, which is the point: run
# provision.sh first.
data "aws_secretsmanager_secret" "member" {
  for_each = local.members
  name     = "${local.secret_path}/pep/${var.cluster}/${each.key}"
}

# --- What the tasks run as --------------------------------------------------
#
# AN EXECUTION ROLE AND NO TASK ROLE: ECS pulls the image, writes the logs and
# injects this cluster's secrets; the PEP itself calls no AWS API.

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
    resources = ["${data.aws_cloudwatch_log_group.containers.arn}:*"]
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

resource "aws_ecs_cluster" "main" {
  name = local.prefix
}

resource "aws_ecs_task_definition" "member" {
  for_each = local.members

  family                   = "${local.prefix}-pep-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = local.task_cpu
  memory                   = local.task_memory
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode(concat([
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
          PEP_PDP_URL          = local.pdp_url
          PEP_NAME             = each.key
          PEP_CLIENT_ID        = "sts-remote-pep"
          PEP_ASSERTION_KEY    = "${local.cred_dir}/pep-assertion.key"
          PEP_HTTPS_CERT       = "${local.cred_dir}/server/pep-server.crt"
          PEP_HTTPS_KEY        = "${local.cred_dir}/server/pep-server.key"
          PEP_HTTPS_PORT       = tostring(local.pep_https_port)
          PEP_POLL_INTERVAL_MS = tostring(var.poll_interval_ms)
          PEP_LOG_LEVEL        = "info"
          }, local.notify ? {
          # THE NUDGE THROUGH THE LOAD BALANCER, to this member's own port,
          # at the name on the load balancer's public certificate — which is
          # the name the service checks the notify URL's host against.
          PEP_NOTIFY_URL = "https://${var.public_hostname}:${local.notify_ports[each.key]}/notify"
        } : {}, var.extra_environment) : { name = k, value = v }
      ]

      # NO CONTAINER HEALTH CHECK. The image's own (`xacml-pep --healthcheck`)
      # reports a member with no listener pair yet as unhealthy, which is
      # accurate, and ECS would replace an essential container that reports
      # it — before provision.sh's second pass could ever issue the pair.
      # The load balancer's check, with health_check_grace_seconds, is the one
      # that replaces a member.
      logConfiguration = local.container_log
    }
  ], var.companion ? [local.companion_container] : []))
}

resource "aws_ecs_service" "member" {
  for_each = local.members

  name            = "${local.prefix}-pep-${each.key}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.member[each.key].arn
  desired_count   = each.value.desired
  launch_type     = "FARGATE"

  # PRIVATE SUBNETS, NO PUBLIC ADDRESS: in through the load balancer only,
  # out through the NAT gateway only. A per-instance member in one zone,
  # spread round them; a shared service across all of them.
  network_configuration {
    subnets = local.per_instance ? [
      aws_subnet.private[(each.value.n - 1) % length(aws_subnet.private)].id
    ] : aws_subnet.private[*].id
    security_groups  = [aws_security_group.pep.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "xacml-pep"
    container_port   = local.pep_proxy_port
  }

  dynamic "load_balancer" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.decision[0].arn
      container_name   = "xacml-pep"
      container_port   = local.pep_https_port
    }
  }

  dynamic "load_balancer" {
    for_each = local.notify ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.notify[each.key].arn
      container_name   = "xacml-pep"
      container_port   = local.pep_https_port
    }
  }

  health_check_grace_period_seconds  = var.health_check_grace_seconds
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  propagate_tags                     = "SERVICE"

  depends_on = [
    aws_lb_listener.https,
    aws_lb_listener.decision,
    aws_lb_listener.notify,
    aws_iam_role_policy.execution,
    aws_route.private_default,
  ]

  lifecycle {
    # Application Auto Scaling owns the count of a shared, autoscaled
    # service, so Terraform never sets it back. The cost: a CHANGED
    # instance_count reaches a running shared service only through
    # `aws ecs update-service --desired-count` (or the autoscaling minimum).
    # A per-instance member's count is always 1, and its members are added
    # and removed as services.
    ignore_changes = [desired_count]

    precondition {
      condition     = !(local.per_instance && var.autoscaling_max > 0)
      error_message = "autoscaling_max is for credential_mode = shared: per-instance members are a fixed count, each with its own key."
    }
  }
}

# --- Autoscaling (shared only) ------------------------------------------------

resource "aws_appautoscaling_target" "shared" {
  count              = local.autoscaling ? 1 : 0
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.member["${var.cluster}-pep"].name}"
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
