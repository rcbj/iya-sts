locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = var.aws_region

  # Every name starts `mock-sts-<environment>`; the deployer policy scopes
  # ELB, ECS, RDS and IAM to `mock-sts-*`. Roles take `mock-sts-env-` so the
  # policy can tell an environment's roles from the deployer's own.
  prefix      = "${var.name}-${var.environment}"
  role_prefix = "${var.name}-env-${var.environment}"
  secret_path = "${var.name}/${var.environment}"

  azs = slice(sort(data.aws_availability_zones.available.names), 0, 3)

  public_cidrs  = [for i in range(3) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidrs = [for i in range(3) : cidrsubnet(var.vpc_cidr, 8, 10 + i)]
  # Not in public_cidrs, which is STS_TRUSTED_PROXIES: the runner is a client,
  # and a client in a trusted-proxy range could name its own address.
  runner_cidr = cidrsubnet(var.vpc_cidr, 8, 20)

  nodes = { for i in range(var.node_count) : "node-${substr("abc", i, 1)}" => i }

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  ecr_repository_url = data.aws_ecr_repository.main.repository_url
  schema_image_tag   = var.schema_image_tag != "" ? var.schema_image_tag : "schema-${var.image_tag}"
  runner_image_tag   = var.runner_image_tag != "" ? var.runner_image_tag : "runner-${var.image_tag}"
  pep_image_tag      = var.pep_image_tag != "" ? var.pep_image_tag : "pep-${var.image_tag}"
  reports_bucket     = "${var.name}-test-reports-${local.account_id}"

  # The name clients use: `public_hostname` when set (dns.tf), otherwise the
  # load balancer's own DNS name.
  public_host     = var.public_hostname != "" ? var.public_hostname : aws_lb.main.dns_name
  public_base_url = "https://${local.public_host}"
  container_port  = 8081

  # EVERY PORT THE LOAD BALANCER PUBLISHES, and the node port behind it. The
  # main port is 443 outside and 8081 inside; the other two are the same
  # number on both sides, because a job dials the number the service writes
  # into what it publishes (a certificate's CRL address, a directory URL).
  #   ldap  389   the embedded directory (the LDAP bulk load, sts_global_logout,
  #               the ldap:// CRL addresses)
  #   pki   8082  the plain-HTTP CRL/OCSP/caIssuers listener
  #
  # `mtls` (9443, the mutual-TLS listener) WAS THE FOURTH UNTIL 2026-09-16,
  # when that listener and the permissive one beside it were deleted from the
  # service. It cost a target group and an NLB listener, and what it carried —
  # a certificate sign-in — is `GET /tls/sign-in` on the main port now, which
  # asks every connection for a client certificate and requires none. Removing
  # the row is the whole change: `nlb.tf`, `security.tf`, `ecs.tf` and
  # `outputs.tf` all iterate this map.
  # Three target groups per ECS service; the limit is five.
  published_ports = {
    https = { listener = 443, container = 8081 }
    ldap  = { listener = 389, container = 389 }
    pki   = { listener = 8082, container = 8082 }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

# The foundation stack's resources, found by name. Read-only lookups; this
# stack never changes them.
data "aws_kms_key" "main" {
  key_id = "alias/${var.name}"
}

data "aws_ecr_repository" "main" {
  name = var.name
}

data "aws_cloudwatch_log_group" "containers" {
  name = "/${var.name}/containers"
}

# By ARN, not by name: a lookup by name lists every policy in the account,
# which the deployer is deliberately not allowed to do.
data "aws_iam_policy" "workload_boundary" {
  arn = "arn:${local.partition}:iam::${local.account_id}:policy/${var.name}-workload-boundary"
}
