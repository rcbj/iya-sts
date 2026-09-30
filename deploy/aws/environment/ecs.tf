# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
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
    STS_KEYS_KEK_REF               = local.shared_secret_arns["kek"]
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

    # REVOCATION IS NOT CONSULTED ON THESE CLUSTERS (rcbj, #371). A
    # certificate presented to a node, or registered and used, is not checked
    # against a CRL or an OCSP responder — this service's own register
    # included — and one whose issuer cannot be found through its caIssuers
    # address is not refused. In the task definition, so it survives every
    # restart and a rebuilt environment; an environment's `extra_environment`
    # can still set either back. A value set on the console or through
    # /admin-api is persisted in the cluster's database and outranks this.
    STS_PKI_REVOCATION_CHECK                      = "off"
    STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT = "off"

    # The directory's ceiling, as the ENVIRONMENT's value rather than an
    # override, so resetting the override the bulk loads leave lands here
    # (variables.tf, reset-environment.js).
    LDAP_MAX_ENTRIES     = tostring(var.ldap_max_entries)
    STS_APPLICATIONS_MAX = tostring(var.applications_max)

    # WHERE A RISK DATASET UPLOAD IS WRITTEN (#214): the task's own EBS volume,
    # below. Set explicitly, although it is the setting's default resolved,
    # so that the mount and the setting are read side by side here rather than
    # agreeing by coincidence with a default in another repository file.
    STS_RISK_UPLOAD_DIRECTORY = local.risk_upload_dir
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
    # OUTBOUND MAIL, WHERE AN SES IDENTITY IS DECLARED (#311, mail.tf). The
    # task role is the credential; the region is this one, where the identity
    # is.
    local.mail_ses ? {
      STS_MAIL_TRANSPORT  = "ses"
      STS_MAIL_FROM       = local.mail_from
      STS_MAIL_SES_REGION = local.region
    } : {},
    # A CELL'S CONTRACT WITH THE SERVICE (cells.tf, #98): which cell, its
    # peers, the global database and the cell's own key-encryption key. Empty
    # in a single-cell environment.
    local.cell_environment,
  var.extra_environment)

  # THE GLOBAL SCHEMA IS APPLIED BY THE PRIMARY CELL'S NODES (#98), as the cell
  # schema is by every node: the same image and the same idempotent file,
  # against the global database's writer, which is in this cell's VPC. Only
  # the primary cell runs it — every other cell reads a replica, which takes
  # the schema (and the `sts_app` role and its password) from the writer by
  # replication — and `entrypoint.sh` applies the primary cell first, so a
  # node anywhere starts against a schema that exists.
  global_schema_init = local.is_primary && local.full
}

# ---------------------------------------------------------------------------
# THE CONTAINERS MORE THAN ONE TASK DEFINITION RUNS, SPELT ONCE (#98's
# conversion, 2026-09-28). The node task definitions below run them, and so
# does a restored cell's one-off conversion task (conversion.tf) — the same
# two schema inits against the same two databases, logged under the same
# stream prefix with the task's own name at the end — so each is a map keyed
# by the task it is in: `node-a`, `node-b`, `node-c`, and `convert`. Written
# in place until then; moving it here changed no rendered task definition,
# because `jsonencode` renders the same object wherever it was built.
# ---------------------------------------------------------------------------
locals {
  container_tasks = concat(keys(local.nodes), ["convert"])

  container_log = {
    for t in local.container_tasks : t => {
      logDriver = "awslogs"
      options = {
        awslogs-group         = data.aws_cloudwatch_log_group.containers.name
        awslogs-region        = local.region
        awslogs-stream-prefix = "${local.log_stream_prefix}-${t}"
      }
    }
  }

  global_schema_init_container = {
    for t in local.container_tasks : t => {
      name      = "global-schema-init"
      image     = "${local.ecr_repository_url}:${local.schema_image_tag}"
      essential = false
      environment = concat([
        { name = "PGHOST", value = local.global.primary_address },
        { name = "PGPORT", value = tostring(local.global.db_port) },
        { name = "PGDATABASE", value = local.global.db_name },
        { name = "PGUSER", value = local.db_master_user },
        { name = "STS_DB_APP_USER", value = local.global.db_app_user },
        ], local.multi_cloud ? [
        # THE PUBLICATION THE GCP CELLS SUBSCRIBE TO (#97), made by the same
        # idempotent run: every table but sts_schema, which each database
        # seeds for itself (deploy/aws/schema-init/apply.sh).
        { name = "STS_DB_PUBLICATION", value = local.global.publication },
        { name = "STS_DB_REPL_USER", value = local.global.repl_user },
      ] : [])
      secrets = concat([
        { name = "PGPASSWORD", valueFrom = local.global.master_secret_arn },
        { name = "STS_DB_APP_PASSWORD", valueFrom = lookup(local.global_secret_arns, "global-db-app-password", "") },
        ], local.multi_cloud ? [
        { name = "STS_DB_REPL_PASSWORD", valueFrom = lookup(local.global_secret_arns, "global-db-repl-password", "") },
      ] : [])
      logConfiguration = local.container_log[t]
    }
  }

  schema_init_container = {
    for t in local.container_tasks : t => {
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
      logConfiguration = local.container_log[t]
    }
  }

  # A cell's `base` phase has no global secrets yet (cells.tf) and runs no
  # node; ECS refuses an empty `valueFrom` even in a task definition
  # nothing starts, so those are left out until `full`. In a single-cell
  # environment every value is present and the list is the one it was.
  node_secrets = [for s in concat(
    [{ name = "ADMIN_API_CLIENT_SECRET", valueFrom = local.shared_secret_arns["admin-api-client-secret"] }],
    # THE BOOTSTRAP ADMINISTRATOR'S PASSWORD, in product mode. Injected by
    # ECS from Secrets Manager rather than written into the task
    # definition, like the three secrets beside it: a task definition is
    # readable by anybody with `ecs:DescribeTaskDefinition`, and this one
    # is the way in. The service takes it instead of generating one and
    # prints it nowhere (common/credentials.ts, admin.bootstrapPassword),
    # so the value exists only in Secrets Manager and in the scrypt hash
    # on the entry.
    #
    # In a cell (#98) all three are the global/ stack's, replicated into
    # this region, because every cell must hold the same values.
    local.product ? [
      { name = "STS_ADMIN_BOOTSTRAP_PASSWORD", valueFrom = local.shared_secret_arns["bootstrap-admin-password"] },
      # And the KDC's two (secrets.tf, 2026-09-18): without them a product
      # KDC builds no krbtgt and no service account, and issues nothing.
      { name = "KRB5_KRBTGT_PASSWORD", valueFrom = local.shared_secret_arns["krb5-krbtgt-password"] },
      { name = "KRB5_SERVICE_PASSWORD", valueFrom = local.shared_secret_arns["krb5-service-password"] },
    ] : [],
  ) : s if s.valueFrom != ""]
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

  # THE RISK DATASET UPLOAD VOLUME (#214): an Amazon EBS volume CONFIGURED AT
  # LAUNCH — the task definition names it and says nothing else; its size,
  # type and key are the SERVICE's `volume_configuration` below, and ECS
  # creates it as the task starts and deletes it as the task stops. Temporary
  # space, therefore, holding no state: a file in it is deleted when its
  # import ends however it ends, and a task that dies mid-import takes the
  # volume with it (the version it was loading is refused by the
  # `risk.stalled-imports` job, risk/CLAUDE.md).
  #
  # UNCONDITIONAL, unlike the TLS volume above, and so a new revision in
  # `dev` and `ci` too: the upload job runs against every environment the
  # suite is pointed at, and a node without the volume would write the upload
  # onto the task's 20 GiB of ephemeral storage, shared with the image layers
  # — which is the thing this volume exists to prevent.
  volume {
    name                = local.risk_upload_volume
    configure_at_launch = true
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
      logConfiguration = local.container_log[each.key]
    },
    ] : [],
    local.global_schema_init ? [local.global_schema_init_container[each.key]] : [],
    [
      local.schema_init_container[each.key],
      {
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
          local.global_schema_init ? [{ containerName = "global-schema-init", condition = "SUCCESS" }] : [],
        )
        # And in a cell, the inter-cell listener (intercell.tf), which no load
        # balancer carries.
        portMappings = concat([
          for p in values(local.published_ports) :
          { containerPort = p.container, protocol = "tcp" }
          ], local.multi ? [
          { containerPort = local.intercell_port, protocol = "tcp" },
        ] : [])
        environment = [
          for k, v in merge(local.node_environment, { STS_CLUSTER_NODE_NAME = each.key }) :
          { name = k, value = v }
        ]
        # A cell's `base` phase has no global secrets yet (cells.tf) and runs no
        # node; ECS refuses an empty `valueFrom` even in a task definition
        # nothing starts, so those are left out until `full`. In a single-cell
        # environment every value is present and the list is the one it was.
        # The secrets, from `local.node_secrets` below (the conversion task
        # takes the same list, conversion.tf).
        secrets = local.node_secrets
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
        # THE UPLOAD VOLUME, READ-WRITE: the node writes, hashes, reads back
        # and deletes each uploaded file here (#214). AND THE CERTIFICATE,
        # READ-ONLY, where there is one — the node reads it and must never be
        # able to change it. `mountPoints` was merged in only with a public name
        # until the upload volume made it unconditional.
        mountPoints = concat(
          [{ sourceVolume = local.risk_upload_volume, containerPath = local.risk_upload_dir, readOnly = false }],
          local.public_name ? [
            { sourceVolume = local.tls_volume, containerPath = local.tls_dir, readOnly = true },
          ] : [],
        )
        logConfiguration = local.container_log[each.key]
      },
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
  # 1; 0 only in a new cell's `base` phase (cells.tf), before the global
  # database it needs exists.
  desired_count = local.node_desired_count
  launch_type   = "FARGATE"

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

  # THE UPLOAD VOLUME'S SHAPE (#214), for the task definition's volume that is
  # configured at launch. gp3, ENCRYPTED WITH THE PROJECT KEY — the one that
  # already seals the secrets, RDS and the logs — rather than EBS's default
  # key, so the one key policy and its rotation cover it too. ECS creates it
  # through the infrastructure role (iam.tf) and deletes it when the task
  # stops; a service-managed volume is always deleted on termination.
  volume_configuration {
    name = local.risk_upload_volume
    managed_ebs_volume {
      role_arn         = aws_iam_role.ecs_infrastructure.arn
      encrypted        = true
      kms_key_id       = local.kms_key_arn
      volume_type      = "gp3"
      size_in_gb       = var.risk_upload_volume_gib
      throughput       = var.risk_upload_volume_throughput
      iops             = var.risk_upload_volume_iops
      file_system_type = "xfs"
      # The service's tags (Project, Environment, …) on the volume, so the
      # bill and a search by tag find it beside the rest of the environment.
      tag_specifications {
        resource_type  = "volume"
        propagate_tags = "SERVICE"
      }
    }
  }

  dynamic "load_balancer" {
    for_each = local.published_ports
    content {
      target_group_arn = aws_lb_target_group.nodes[load_balancer.key].arn
      container_name   = "mock-sts"
      container_port   = load_balancer.value.container
    }
  }

  # A CELL'S NODES ARE NAMED TO THE OTHER CELLS BY CLOUD MAP (intercell.tf,
  # #98), which is not a target group and so not held to the five above.
  dynamic "service_registries" {
    for_each = local.multi ? [1] : []
    content {
      registry_arn = aws_service_discovery_service.nodes[0].arn
    }
  }

  # The replica is not needed to start, but a node that starts before the
  # primary's parameter group and security rules exist cannot connect.
  depends_on = [
    aws_lb_listener.ports,
    aws_iam_role_policy.execution,
    aws_iam_role_policy.task,
    # The upload volume is created and deleted through this role, so its
    # policy must be in place before the first task and stay until the last
    # one has stopped — which is also the order a destroy then takes.
    aws_iam_role_policy.ecs_infrastructure,
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
  desired_count   = local.node_desired_count
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

  # THE UPLOAD VOLUME'S SHAPE (#214), for the task definition's volume that is
  # configured at launch. gp3, ENCRYPTED WITH THE PROJECT KEY — the one that
  # already seals the secrets, RDS and the logs — rather than EBS's default
  # key, so the one key policy and its rotation cover it too. ECS creates it
  # through the infrastructure role (iam.tf) and deletes it when the task
  # stops; a service-managed volume is always deleted on termination.
  volume_configuration {
    name = local.risk_upload_volume
    managed_ebs_volume {
      role_arn         = aws_iam_role.ecs_infrastructure.arn
      encrypted        = true
      kms_key_id       = local.kms_key_arn
      volume_type      = "gp3"
      size_in_gb       = var.risk_upload_volume_gib
      throughput       = var.risk_upload_volume_throughput
      iops             = var.risk_upload_volume_iops
      file_system_type = "xfs"
      # The service's tags (Project, Environment, …) on the volume, so the
      # bill and a search by tag find it beside the rest of the environment.
      tag_specifications {
        resource_type  = "volume"
        propagate_tags = "SERVICE"
      }
    }
  }

  dynamic "load_balancer" {
    for_each = local.published_ports
    content {
      target_group_arn = aws_lb_target_group.nodes[load_balancer.key].arn
      container_name   = "mock-sts"
      container_port   = load_balancer.value.container
    }
  }

  # A CELL'S NODES ARE NAMED TO THE OTHER CELLS BY CLOUD MAP (intercell.tf,
  # #98), which is not a target group and so not held to the five above.
  dynamic "service_registries" {
    for_each = local.multi ? [1] : []
    content {
      registry_arn = aws_service_discovery_service.nodes[0].arn
    }
  }

  depends_on = [aws_ecs_service.first]

  timeouts {
    create = "30m"
    update = "30m"
  }
}
