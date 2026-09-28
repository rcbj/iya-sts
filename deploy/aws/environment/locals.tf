# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  # A CELL'S REGION IS ITS OWN (cells.tf, #98); a single-cell environment's is
  # `aws_region`, as it always was.
  region = local.multi ? local.this_cell.region : var.aws_region

  # Every name starts `mock-sts-<environment>`; the deployer policy scopes
  # ELB, ECS, RDS and IAM to `mock-sts-*`. Roles take `mock-sts-env-` so the
  # policy can tell an environment's roles from the deployer's own.
  #
  # A CELL IS IN EVERY NAME THAT MUST BE UNIQUE (#98): IAM roles are global,
  # so two cells of one environment would otherwise claim the same role, and
  # the rest follow for the reader's sake and for the load balancer's, whose
  # name is limited to 32 characters (hence the 5-character cell id).
  prefix      = local.multi ? "${var.name}-${var.environment}-${var.cell}" : "${var.name}-${var.environment}"
  role_prefix = local.multi ? "${var.name}-env-${var.environment}-${var.cell}" : "${var.name}-env-${var.environment}"
  secret_path = local.multi ? "${var.name}/${var.environment}/${var.cell}" : "${var.name}/${var.environment}"

  # Log streams are `<environment>-<node>/…`, and `<environment>-<cell>-<node>/…`
  # in a cell — each region has a log group of its own (foundation/regions.tf),
  # but the cell in the stream is what a reader of one looks for.
  log_stream_prefix = local.multi ? "${var.environment}-${var.cell}" : var.environment

  vpc_cidr = local.multi ? local.this_cell.vpc_cidr : var.vpc_cidr

  azs = slice(sort(data.aws_availability_zones.available.names), 0, 3)

  public_cidrs  = [for i in range(3) : cidrsubnet(local.vpc_cidr, 8, i)]
  private_cidrs = [for i in range(3) : cidrsubnet(local.vpc_cidr, 8, 10 + i)]
  # /24 number 20 was the in-VPC suite runner's until 2026-09-21 and is left
  # unused; suite-callbacks/ takes number 21.

  nodes = { for i in range(var.node_count) : "node-${substr("abc", i, 1)}" => i }

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  ecr_repository_url = data.aws_ecr_repository.main.repository_url
  schema_image_tag   = var.schema_image_tag != "" ? var.schema_image_tag : "schema-${var.image_tag}"
  runner_image_tag   = var.runner_image_tag != "" ? var.runner_image_tag : "runner-${var.image_tag}"
  cert_image_tag     = var.cert_init_image_tag != "" ? var.cert_init_image_tag : "cert-${var.image_tag}"
  pep_image_tag      = var.pep_image_tag != "" ? var.pep_image_tag : "pep-${var.image_tag}"
  reports_bucket     = "${var.name}-test-reports-${local.account_id}"

  # The name clients use: `public_hostname` when set (dns.tf), otherwise the
  # load balancer's own DNS name.
  public_host     = var.public_hostname != "" ? var.public_hostname : aws_lb.main.dns_name
  public_base_url = "https://${local.public_host}"
  container_port  = 8081

  # THE PLAIN-HTTP FRONT DOOR AS A URL, because a URL is what goes inside a
  # certificate and a host and a port are not. A DEFAULT PORT IS LEFT OUT of
  # it: `http://host:80` and `http://host` are one address to RFC 3986 and two
  # STRINGS to everything that compares one, and a cRLDistributionPoints or
  # authorityInfoAccess value is a durable document nobody can edit after it is
  # signed. `ecs.tf` passes it as `PKI_DISTRIBUTION_BASE_URL`.
  pki_public_url = var.pki_listener_port == 80 ? "http://${local.public_host}" : "http://${local.public_host}:${var.pki_listener_port}"

  # WHERE cert-init LEAVES THE PUBLIC CERTIFICATE AND THE NODE READS IT: a
  # volume of the task's own, mounted by both containers, made again from ACM
  # on every start. Named here because three places have to agree about it —
  # the volume, the two mount points and the two settings — and a fourth
  # spelling of a path is how one of them goes stale.
  tls_volume  = "public-tls"
  tls_dir     = "/var/run/sts-tls"
  tls_cert    = "/var/run/sts-tls/certificate.pem"
  tls_keyfile = "/var/run/sts-tls/key.pem"

  # WHERE AN UPLOADED RISK DATASET IS WRITTEN WHILE IT IS IMPORTED (#214): the
  # task's EBS volume (ecs.tf), mounted in mock-sts and named to the service
  # as `risk.uploadDirectory`. The same path the compose stacks mount their
  # volume at, `risk.uploadDirectory`'s default resolved against the package
  # root, so a reader of either finds the other. Spelt once for the reason the
  # TLS paths above are: the volume, the mount and the setting must agree.
  risk_upload_volume = "risk-uploads"
  risk_upload_dir    = "/usr/src/sts/data/risk-uploads"

  # EVERY PORT THE LOAD BALANCER PUBLISHES, and the node port behind it. The
  # main port is 443 outside and 8081 inside.
  #   ldap  389   the embedded directory, in the clear (the LDAP bulk load,
  #               sts_global_logout, the ldap:// CRL addresses) — the same
  #               number on both sides, because a job dials the number the
  #               service writes into what it publishes and 389 is where a
  #               directory URL points anyway
  #   ldaps 636   THE SAME DIRECTORY, BEHIND TLS (2026-09-17). Also the same
  #               number on both sides, and for a reason of its own: 636 is
  #               what an LDAP client assumes when it is told ldaps://, and a
  #               directory reachable only on a port nobody assumes is a
  #               directory somebody has to be told about.
  #   pki   80 or 8082  the plain-HTTP CRL/OCSP/caIssuers listener
  #
  # **636 PRESENTS THE SAME CERTIFICATE AS THE MAIN PORT, AND NOTHING HERE
  # MAKES THAT SO** — `ldap/ldap_server.js` builds its LDAPS listener from
  # `tlsServer.serverCertificate()`, the one record every socket in the
  # process shares (`tls/CLAUDE.md`). So where `public_hostname` is set and
  # `cert-init` has put the exported ACM certificate in the task, an LDAPS
  # client dialling the public name gets a publicly trusted certificate for
  # it, with no second certificate to issue, rotate or trust. The load
  # balancer passes the TCP through, as it does for 443.
  #
  # **THE FRONT-END PORT IS WHAT GOES INSIDE A CERTIFICATE, AND THEY NEED NOT
  # MATCH (2026-09-17).** `pki` was 8082 on both sides for the reason the ldap
  # row still gives, and it did not have to be: `ecs.tf` already builds the
  # published addresses from `each.value.listener`, so the mapping is stated
  # rather than avoided. `testidp` publishes the plain-HTTP listener on 80 —
  # where a relying party expects an http:// address read out of a certificate
  # — and `dev` and `ci` keep 8082 (`var.pki_listener_port`).
  #
  # `mtls` (9443, the mutual-TLS listener) WAS THE FOURTH UNTIL 2026-09-16,
  # when that listener and the permissive one beside it were deleted from the
  # service. It cost a target group and an NLB listener, and what it carried —
  # a certificate sign-in — is `GET /tls/sign-in` on the main port now, which
  # asks every connection for a client certificate and requires none. Removing
  # the row is the whole change: `nlb.tf`, `security.tf`, `ecs.tf` and
  # `outputs.tf` all iterate this map.
  # FOUR target groups per ECS service since 2026-09-17 (five with the KDC);
  # the limit is five.
  #
  # **AND THE KDC WHERE `var.publish_kerberos` SAYS SO (2026-09-18)** — TCP 88
  # on both sides, `testidp` only. It is a row like the others and costs what
  # they do (a listener, a target group, two security-group rules, a port
  # mapping), which is why it is merged in rather than written as a resource of
  # its own: every file that iterates this map takes it with no edit. Merged
  # CONDITIONALLY so `dev` and `ci` render the four rows they always did. With
  # it, a service has five target groups, which is ECS's limit.
  # `health` is how the load balancer checks the port (2026-09-21): a GET of
  # /healthcheck where the port speaks HTTP, a TCP connect where it does not.
  published_ports = merge({
    https = { listener = 443, container = 8081, health = "HTTPS" }
    ldap  = { listener = 389, container = 389, health = "TCP" }
    ldaps = { listener = 636, container = 636, health = "TCP" }
    pki   = { listener = var.pki_listener_port, container = 8082, health = "HTTP" }
    }, var.publish_kerberos ? {
    kerberos = { listener = 88, container = 88, health = "TCP" }
  } : {})
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
#
# THE PROJECT KEY EXISTS IN THE HOME REGION ONLY, and a cell seals its own
# data under its CELL key instead (foundation/modules/region, #98): single-
# region and replicated nowhere, which is the residency line. The global key
# is the multi-region one, replicated into every permitted region; a cell
# decrypts the global secrets replicated here with it.
data "aws_kms_key" "main" {
  count  = local.multi ? 0 : 1
  key_id = "alias/${var.name}"
}

data "aws_kms_key" "cell" {
  count  = local.multi ? 1 : 0
  key_id = "alias/${var.name}-cell-${var.cell}"
}

data "aws_kms_key" "global" {
  count  = local.multi ? 1 : 0
  key_id = "alias/${var.name}-global"
}

locals {
  # The key this stack's own storage, secrets and volumes are sealed under.
  kms_key_arn = local.multi ? data.aws_kms_key.cell[0].arn : data.aws_kms_key.main[0].arn
  # The key the global secrets replicated into this region are sealed under;
  # none in a single-cell environment.
  global_kms_key_arn = local.multi ? data.aws_kms_key.global[0].arn : ""
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

# The ceiling the ECS infrastructure role must carry (iam.tf, #214) — a
# boundary of its own, so that no task role can ever be given what attaching a
# volume takes. Also by ARN.
data "aws_iam_policy" "ecs_infrastructure_boundary" {
  arn = "arn:${local.partition}:iam::${local.account_id}:policy/${var.name}-ecs-infrastructure-boundary"
}
