# ---------------------------------------------------------------------------
# THREE mock-sts NODES ON FARGATE, ONE SERVICE PER AVAILABILITY ZONE.
#
# WHY THREE SERVICES AND NOT ONE WITH A DESIRED COUNT OF THREE: a single
# service spreads tasks across its subnets as best it can, and a replacement
# can land beside another node. A service per AZ, each given that AZ's subnet
# and a desired count of one, makes "each node in a separate AZ" true by
# construction rather than by the scheduler's current mood.
#
# AND IT ORDERS THE COLD START. node-a is created and waited on (steady state,
# which includes passing the load balancer's health check) before node-b and
# node-c are created. The cluster work recorded two nodes cold-starting against
# an empty database as the way to get two signing key sets
# (cluster/CLAUDE.md); later arbitration covers it, and the order is kept
# because a deterministic first start is cheap. It also means the schema is
# applied once, by node-a's init container, before anything else runs it.
#
# EACH TASK HAS TWO CONTAINERS:
#   schema-init  runs postgres/schema.sql as the RDS master user and exits;
#                non-essential, so its exit does not stop the task.
#   mock-sts     waits for schema-init to exit 0 (`dependsOn: SUCCESS`); a
#                schema that fails to apply is a node that never starts,
#                with the reason in the log.
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = local.prefix

  # Container Insights bills per metric; the logs are what is wanted here.
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

locals {
  # The settings every node agrees on. The cluster refuses to start a node
  # whose must-agree settings (global.mode, publicBaseUrl, keys.source, …)
  # differ from the others', so they are spelt once.
  node_environment = merge({
    STS_MODE                    = var.sts_mode
    STS_PERSISTENCE_MODE        = "postgres"
    STS_PERSISTENCE_COORDINATE  = "true"
    STS_KEYS_SOURCE             = "persisted"
    STS_CLUSTER_MODE            = "active-active"
    STS_PUBLIC_BASE_URL         = local.public_base_url
    STS_TLS_HOSTNAMES           = join(",", distinct([local.public_host, aws_lb.main.dns_name, "localhost"]))
    STS_PROXY_PROTOCOL          = "v2"
    STS_TRUSTED_PROXIES         = join(",", local.public_cidrs)
    STS_WORKERS_REQUEST_COUNT   = tostring(var.workers_request_count)
    STS_WORKERS_SURFACE_COUNT   = tostring(var.workers_surface_count)
    STS_WORKERS_DISPATCH        = var.workers_dispatch
    STS_WORKERS_READ_YOUR_WRITE = tostring(var.workers_read_your_write)
    AWS_REGION                  = local.region

    # The key-encryption key and the database password, from Secrets Manager
    # through common/secrets.js — the path issue #51 exists to exercise.
    STS_KEYS_KEK_PROVIDER          = "aws"
    STS_KEYS_KEK_REF               = aws_secretsmanager_secret.main["kek"].arn
    STS_KEYS_KEK_REGION            = local.region
    STS_DATABASE_PASSWORD_PROVIDER = "aws"
    STS_DATABASE_PASSWORD_REF      = aws_secretsmanager_secret.main["db-app-password"].arn
    STS_DATABASE_PASSWORD_REGION   = local.region

    # No password in the URL: it is read from the secret and injected.
    STS_DATABASE_URL                     = "postgres://${local.db_app_user}@${aws_db_instance.primary.address}:${local.db_port}/${local.db_name}?sslmode=require"
    STS_DATABASE_TLS_REJECT_UNAUTHORIZED = "true"
    NODE_EXTRA_CA_CERTS                  = "/opt/sts-sdk/database-ca.pem"

    # WHERE A CERTIFICATE SAYS ITS CRL AND OCSP ADDRESSES ARE. Without these
    # the node writes its own container ports on `localhost`, which no relying
    # party can follow; sts_pki_distribution_points follows them as written.
    # THE FRONT-END PORT, not the container's: the address is read from outside
    # the load balancer, and `locals.tf` leaves a default port out of the URL
    # altogether (`pki_public_url`).
    PKI_DISTRIBUTION_BASE_URL  = local.pki_public_url
    PKI_DISTRIBUTION_LDAP_HOST = local.public_host
    PKI_DISTRIBUTION_LDAP_PORT = tostring(local.published_ports.ldap.listener)

    # The directory's ceiling, as the ENVIRONMENT's value rather than an
    # override, so resetting the override the bulk loads leave lands here
    # (variables.tf, reset-environment.js).
    LDAP_MAX_ENTRIES     = tostring(var.ldap_max_entries)
    STS_APPLICATIONS_MAX = tostring(var.applications_max)
    },
    # THE PUBLIC CERTIFICATE, WHERE THERE IS ONE. `cert-init` has written both
    # files into the shared volume before this container is allowed to start, so
    # the node serves the ACM leaf on its own 8081 rather than the self-signed
    # one it would otherwise make — and the load balancer, passing TCP through,
    # is not in the handshake at all. The service leaves a supplied certificate
    # alone rather than re-issuing it under its own Root (tls/CLAUDE.md).
    # Both settings or neither: one alone is refused at startup by name.
    local.public_name ? {
      STS_TLS_CERT_FILE = local.tls_cert
      STS_TLS_KEY_FILE  = local.tls_keyfile
    } : {},
  var.extra_environment)
}

resource "aws_ecs_task_definition" "node" {
  for_each = local.nodes

  family                   = "${local.prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # THE SHARED VOLUME cert-init WRITES AND mock-sts READS. Ephemeral and of
  # the task's own — no host path, no EFS: the certificate is fetched from ACM
  # on every start, so there is nothing here worth surviving the task, and a
  # private key that outlived the task would be a private key on a disk
  # somebody has to remember to wipe.
  #
  # `dynamic`, and not an unconditional block that costs nothing, because it
  # would cost exactly one thing: A NEW TASK DEFINITION REVISION IN `dev` AND
  # `ci`, and with it a redeploy of three services in environments whose whole
  # job is to be the unchanged standard. Every addition here defaults to what
  # they already did.
  dynamic "volume" {
    for_each = local.public_name ? [1] : []
    content {
      name = local.tls_volume
    }
  }

  container_definitions = jsonencode(concat(local.public_name ? [
    {
      name      = "cert-init"
      image     = "${local.ecr_repository_url}:${local.cert_image_tag}"
      essential = false
      environment = [
        # The VALIDATED certificate's ARN, so the export cannot run against
        # one that has not been issued yet.
        { name = "STS_ACM_CERTIFICATE_ARN", value = aws_acm_certificate_validation.public[0].certificate_arn },
        { name = "STS_TLS_DIR", value = local.tls_dir },
        { name = "AWS_REGION", value = local.region },
      ]
      mountPoints = [
        { sourceVolume = local.tls_volume, containerPath = local.tls_dir, readOnly = false },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = data.aws_cloudwatch_log_group.containers.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "${var.environment}-${each.key}"
        }
      }
    },
    ] : [], [
    {
      name      = "schema-init"
      image     = "${local.ecr_repository_url}:${local.schema_image_tag}"
      essential = false
      environment = [
        { name = "PGHOST", value = aws_db_instance.primary.address },
        { name = "PGPORT", value = tostring(local.db_port) },
        { name = "PGDATABASE", value = local.db_name },
        { name = "PGUSER", value = local.db_master_user },
        { name = "STS_DB_APP_USER", value = local.db_app_user },
      ]
      secrets = [
        { name = "PGPASSWORD", valueFrom = aws_secretsmanager_secret.main["db-master-password"].arn },
        { name = "STS_DB_APP_PASSWORD", valueFrom = aws_secretsmanager_secret.main["db-app-password"].arn },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = data.aws_cloudwatch_log_group.containers.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "${var.environment}-${each.key}"
        }
      }
    },
    merge({
      name      = "mock-sts"
      image     = "${local.ecr_repository_url}:${var.image_tag}"
      essential = true
      # BOTH INIT CONTAINERS MUST HAVE SUCCEEDED. A node that could not get
      # the public certificate must not start: it would serve a self-signed
      # one under a public name, which is the single error this deployment
      # exists to avoid, and it would do it looking healthy.
      dependsOn = concat(
        [{ containerName = "schema-init", condition = "SUCCESS" }],
        local.public_name ? [{ containerName = "cert-init", condition = "SUCCESS" }] : [],
      )
      portMappings = [
        for p in values(local.published_ports) :
        { containerPort = p.container, protocol = "tcp" }
      ]
      environment = [
        for k, v in merge(local.node_environment, { STS_CLUSTER_NODE_NAME = each.key }) :
        { name = k, value = v }
      ]
      secrets = concat(
        [{ name = "ADMIN_API_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.main["admin-api-client-secret"].arn }],
        # THE BOOTSTRAP ADMINISTRATOR'S PASSWORD, in product mode. Injected by
        # ECS from Secrets Manager rather than written into the task
        # definition, like the three secrets beside it: a task definition is
        # readable by anybody with `ecs:DescribeTaskDefinition`, and this one
        # is the way in. The service takes it instead of generating one and
        # prints it nowhere (common/credentials.ts, admin.bootstrapPassword),
        # so the value exists only in Secrets Manager and in the scrypt hash
        # on the entry.
        local.bootstrap_secret ? [
          { name = "STS_ADMIN_BOOTSTRAP_PASSWORD", valueFrom = aws_secretsmanager_secret.main["bootstrap-admin-password"].arn },
          # And the KDC's two (secrets.tf, 2026-09-18): without them a product
          # KDC builds no krbtgt and no service account, and issues nothing.
          { name = "KRB5_KRBTGT_PASSWORD", valueFrom = aws_secretsmanager_secret.main["krb5-krbtgt-password"].arn },
          { name = "KRB5_SERVICE_PASSWORD", valueFrom = aws_secretsmanager_secret.main["krb5-service-password"].arn },
        ] : [],
      )
      # The main port is HTTPS on a certificate the cluster issues itself, so
      # the probe does not verify it; it asks whether the service answers.
      # Loopback connections are served without the PROXY header.
      healthCheck = {
        command     = ["CMD", "node", "-e", "require('https').get({host:'127.0.0.1',port:8081,path:'/healthcheck',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
        interval    = 15
        timeout     = 5
        retries     = 4
        startPeriod = 180
      }
      ulimits = [{ name = "nofile", softLimit = 65536, hardLimit = 65536 }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = data.aws_cloudwatch_log_group.containers.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "${var.environment}-${each.key}"
        }
      }
      },
      # MERGED IN RATHER THAN WRITTEN ABOVE AS `[]`, for the reason the volume
      # is `dynamic`: an empty `mountPoints` where there was no key at all is
      # a difference, and `dev` and `ci` are meant to see none. READ-ONLY —
      # the node reads the certificate and must never be able to change it.
      local.public_name ? {
        mountPoints = [
          { sourceVolume = local.tls_volume, containerPath = local.tls_dir, readOnly = true },
        ]
    } : {}),
  ]))
}

locals {
  service_common = {
    health_check_grace_period_seconds = 300
  }
}

resource "aws_ecs_service" "first" {
  name            = "${local.prefix}-node-a"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.node["node-a"].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # One task per service: replacing it means stopping it first.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  health_check_grace_period_seconds  = local.service_common.health_check_grace_period_seconds
  wait_for_steady_state              = true
  propagate_tags                     = "SERVICE"

  network_configuration {
    subnets          = [aws_subnet.public[0].id]
    security_groups  = [aws_security_group.nodes.id]
    assign_public_ip = true
  }

  dynamic "load_balancer" {
    for_each = local.published_ports
    content {
      target_group_arn = aws_lb_target_group.nodes[load_balancer.key].arn
      container_name   = "mock-sts"
      container_port   = load_balancer.value.container
    }
  }

  # The replica is not needed to start, but a node that starts before the
  # primary's parameter group and security rules exist cannot connect.
  depends_on = [
    aws_lb_listener.ports,
    aws_iam_role_policy.execution,
    aws_iam_role_policy.task,
    aws_secretsmanager_secret_version.main,
    aws_vpc_security_group_ingress_rule.database_from_nodes,
    aws_vpc_security_group_egress_rule.nodes_to_database,
    aws_vpc_security_group_egress_rule.nodes_https,
    aws_route.public_default,
    aws_route_table_association.public,
  ]

  timeouts {
    create = "30m"
    update = "30m"
  }
}

resource "aws_ecs_service" "others" {
  for_each = { for k, v in local.nodes : k => v if k != "node-a" }

  name            = "${local.prefix}-${each.key}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.node[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  health_check_grace_period_seconds  = local.service_common.health_check_grace_period_seconds
  wait_for_steady_state              = true
  propagate_tags                     = "SERVICE"

  network_configuration {
    subnets          = [aws_subnet.public[each.value].id]
    security_groups  = [aws_security_group.nodes.id]
    assign_public_ip = true
  }

  dynamic "load_balancer" {
    for_each = local.published_ports
    content {
      target_group_arn = aws_lb_target_group.nodes[load_balancer.key].arn
      container_name   = "mock-sts"
      container_port   = load_balancer.value.container
    }
  }

  depends_on = [aws_ecs_service.first]

  timeouts {
    create = "30m"
    update = "30m"
  }
}
