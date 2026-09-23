variable "aws_region" {
  description = "The one region this project deploys to."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "The project prefix. Must match the foundation stack's `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = <<-EOT
    This environment's name: `dev` for a hand-deployed one, `ci` for the
    workflow's. It goes into every resource name, and the load balancer's name
    is limited to 32 characters, hence the length.
  EOT
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "allowed_cidrs" {
  description = <<-EOT
    Who may connect to the load balancer on 443. No default, deliberately: a
    committed address goes stale and the symptom is a timeout against a
    healthy cluster. The workflow passes the runner's address.
  EOT
  type        = list(string)
  validation {
    condition = length(var.allowed_cidrs) > 0 && alltrue([
      for c in var.allowed_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"
    ])
    error_message = "allowed_cidrs is one or more CIDRs, and never 0.0.0.0/0."
  }
}

variable "image_tag" {
  description = "The service image tag in the project ECR repository (the commit)."
  type        = string
}

variable "schema_image_tag" {
  description = "The schema-init image tag. Empty means `schema-<image_tag>`."
  type        = string
  default     = ""
}

variable "runner_image_tag" {
  description = "The suite runner image tag. Empty means `runner-<image_tag>`."
  type        = string
  default     = ""
}

variable "pep_image_tag" {
  description = "The remote XACML PEP image tag. Empty means `pep-<image_tag>`."
  type        = string
  default     = ""
}

variable "ldap_max_entries" {
  description = <<-EOT
    The directory's entry ceiling (LDAP_MAX_ENTRIES) on every node. The service
    default is 2000; the three bulk-load jobs leave about 15,000 entries in the
    default realm on every run, and an environment is reused run after run, so
    reset-environment.js resets the override they leave back to THIS value
    rather than to one that refuses every later create. Entries are held in
    each node's memory: raise the task memory with it.
  EOT
  type        = number
  default     = 200000
}

variable "applications_max" {
  description = <<-EOT
    How many entries the default realm's ou=applications may hold
    (STS_APPLICATIONS_MAX) on every node. The service default is 500, and a
    suite run registers a few hundred OAuth clients and relying parties in the
    default realm that no run removes. On a reused environment the registry
    filled on the fourth run and every later registration was refused
    (STS-REG-0020) — which sts_userinfo_protected reported as an unencrypted
    UserInfo response.
  EOT
  type        = number
  default     = 10000
}

variable "runner_task_cpu" {
  description = "Fargate CPU units for the suite task (runner, PEP and credential containers)."
  type        = number
  default     = 2048
}

variable "runner_task_memory" {
  description = "Fargate memory (MiB) for the suite task. Chrome runs in it."
  type        = number
  default     = 8192
}

variable "sts_mode" {
  description = <<-EOT
    `development` or `product`. The test suite drives development mode — most
    of its jobs sign people in without a password, which product mode refuses
    by design — and development mode still reads the key-encryption key and
    the database password from Secrets Manager, because keys persist here.
  EOT
  type        = string
  default     = "development"
  validation {
    condition     = contains(["development", "product"], var.sts_mode)
    error_message = "sts_mode is development or product."
  }
}

variable "node_count" {
  description = "How many nodes, one per availability zone. Three AZs are used."
  type        = number
  default     = 3
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 3
    error_message = "node_count is 1 to 3 (one node per AZ)."
  }
}

variable "task_cpu" {
  description = "Fargate CPU units per node."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate memory (MiB) per node."
  type        = number
  default     = 3072
}

variable "db_instance_class" {
  description = "The RDS instance class for the primary and the replica."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "RDS PostgreSQL version. 18.x only; the parameter group family is postgres18."
  type        = string
  default     = "18.6"
}

variable "db_allocated_storage" {
  description = "GiB of gp3 storage per instance."
  type        = number
  default     = 20
}

variable "backup_retention_days" {
  description = "Automated backup retention on the primary."
  type        = number
  default     = 14
}

variable "delete_automated_backups" {
  description = <<-EOT
    Whether destroying the environment deletes its automated backups. True for
    a test environment: a kept backup outlives the environment it belongs to
    and bills storage for up to the retention period.
  EOT
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "The environment's own VPC. Clear of the account's existing 10.0.0.0/24 and 172.31.0.0/16."
  type        = string
  default     = "10.51.0.0/16"
}

variable "extra_environment" {
  description = "Additional environment variables for every mock-sts container."
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags beside Project = STS and Environment, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-environment"
    Lifecycle = "destroy-after-test-run"
  }
}

variable "public_hostname" {
  description = <<-EOT
    The name clients use, e.g. `test-idp.iyasec.io`. EMPTY (the default) keeps
    the test arrangement: TLS passes through the load balancer and the nodes'
    own certificates are what a client sees, under the NLB's DNS name. SET, the
    443 listener TERMINATES TLS on a public ACM certificate for this name
    (DNS-validated in `public_zone_name`), re-encrypts to the nodes, and a
    CNAME in that zone points the name at the load balancer (dns.tf).
  EOT
  type        = string
  default     = ""
}

variable "public_zone_name" {
  description = "The public Route53 zone `public_hostname` is in, e.g. `iyasec.io`. Required when public_hostname is set."
  type        = string
  default     = ""
}

# `tls_policy` was here until 2026-09-17, for the NLB's TLS listener. There is
# no TLS listener any more — the node presents the public certificate and the
# load balancer passes TCP through (nlb.tf) — so the protocol floor and the
# cipher list are the SERVICE's `tls.minVersion` and `tls.ciphers`, which
# apply to every socket this process owns.

variable "cert_init_image_tag" {
  description = <<-EOT
    The cert-init image tag; empty derives `cert-<image_tag>`, as schema-init
    and the runner do. It is used ONLY where `public_hostname` is set, so
    `dev` and `ci` never pull it and it need not exist for them.
  EOT
  type        = string
  default     = ""
}

variable "publish_kerberos" {
  description = <<-EOT
    Publish the KDC on the load balancer: TCP 88 outside and inside, through a
    PROXY v2 target group like every other published port (server.js installs
    the PROXY protocol on the KDC's TCP listener). TRUE BY DEFAULT SINCE
    2026-09-21, for every environment, by rcbj's decision that a temporary
    test environment publishes exactly what `testidp` does: it was `testidp`
    only, so `sts_kerberos_spnego` had no KDC to reach on `ci` and timed out.
    False takes the port away again (and run-suite.sh tells the Kerberos job,
    which then declines).

    PURE TCP, AND UDP 88 IS NOT PUBLISHED — rcbj's decision (2026-09-18):
    Kerberos over UDP does not do well across the open internet (fragmented
    and dropped datagrams, no retransmission a client can rely on), so the KDC
    is offered on the one transport that does. It is also the only one that
    fits here: an NLB target group cannot put a PROXY header on a datagram, and
    every row in `published_ports` is TCP behind one. A client that tries UDP
    first is told to use TCP (MIT: `udp_preference_limit = 1`). Nothing on this
    listener is HTTP — a TCP listener, a TCP target group and a TCP-connect
    health check, as 389 and 636 have. It is the fifth target group on each ECS
    service, which is the limit.
  EOT
  type        = bool
  default     = true
}

variable "pki_listener_port" {
  description = <<-EOT
    The load balancer's FRONT-END port for the plain-HTTP CRL, OCSP and
    caIssuers listener; the container is always on `pki.httpPort` (8082)
    behind it. 80 BY DEFAULT SINCE 2026-09-21, for every environment — where
    a relying party expects to find an http:// address it read out of a
    certificate — by rcbj's decision that a temporary test environment
    publishes what `testidp` does. It was `testidp` only, with 8082 (the same
    number on both sides) everywhere else.

    IT IS THE FRONT-END PORT THAT GOES INSIDE EVERY CERTIFICATE, because that
    is the side a relying party reaches: `ecs.tf` builds
    `PKI_DISTRIBUTION_BASE_URL` from this, and a node cannot see the mapping
    from inside its container. Changing it re-issues nothing already signed.
  EOT
  type        = number
  default     = 80
}

variable "workers_request_count" {
  description = "STS_WORKERS_REQUEST_COUNT on every node: request workers running the whole service. 0 is off."
  type        = number
  default     = 0
}

variable "workers_surface_count" {
  description = "STS_WORKERS_SURFACE_COUNT on every node: workers running only /admin and /portal. 0 is off."
  type        = number
  default     = 0
}

variable "workers_dispatch" {
  description = "STS_WORKERS_DISPATCH on every node: which paths go to the workers (`*` for all). Empty dispatches nothing."
  type        = string
  default     = ""
}

variable "workers_read_your_write" {
  description = "STS_WORKERS_READ_YOUR_WRITE on every node. Required by the surface pool."
  type        = bool
  default     = false
}
