# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Every variable that has an AWS counterpart keeps its name and its default,
# so an `envs/<env>.tfvars` reads the same on both sides where it can.

variable "project_id" {
  description = "The GCP project (the foundation's)."
  type        = string
}

variable "region" {
  description = "The region (the foundation's home region: the key ring, the registry and the log bucket are there)."
  type        = string
  default     = "us-west1"
}

variable "name" {
  description = "The project prefix. Must match the foundation stack's `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = <<-EOT
    This environment's name, the same names as AWS (`dev`, `ci`, `testidp`).
    It goes into every resource name; the rule is AWS's, 2-12 lower-case
    letters and digits. It must be listed in the foundation's `environments`.
  EOT
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "allowed_cidrs" {
  description = <<-EOT
    Who may connect to the load balancer. No default, deliberately (AWS's
    reason: a committed address goes stale and the symptom is a timeout
    against a healthy cluster). terraform-local.sh passes this host's address.
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
  description = "The service image tag in the project's Artifact Registry repository (the commit)."
  type        = string
}

variable "schema_image_tag" {
  description = "The schema-init image tag. Empty means `schema-<image_tag>`."
  type        = string
  default     = ""
}

variable "init_image_tag" {
  description = "The node-init image tag (secrets and the ACME certificate). Empty means `init-<image_tag>`."
  type        = string
  default     = ""
}

variable "sts_mode" {
  description = "`development` (what the suite drives) or `product`. AWS's variable, AWS's default."
  type        = string
  default     = "development"
  validation {
    condition     = contains(["development", "product"], var.sts_mode)
    error_message = "sts_mode is development or product."
  }
}

variable "node_count" {
  description = "Nodes, one per zone. Three, like AWS; the zones are the region's first three."
  type        = number
  default     = 3
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 3
    error_message = "node_count is 1 to 3: one node per zone, and three zones."
  }
}

variable "machine_type" {
  description = <<-EOT
    A node's machine type. e2-medium (2 shared vCPU, 4 GB) is the nearest to
    AWS's 1 vCPU / 3 GB test node; e2-standard-2 (2 vCPU, 8 GB) is testidp's
    2048 / 8192. deploy/aws/CLAUDE.md, *Sizing a node*, applies unchanged:
    every node process is a whole copy of the service.
  EOT
  type        = string
  default     = "e2-medium"
}

variable "boot_disk_gib" {
  description = "The boot disk (Container-Optimized OS, the image layers and Docker's own storage). Fargate's ephemeral storage was 20 GiB."
  type        = number
  default     = 30
}

variable "db_tier" {
  description = "The Cloud SQL machine tier for both instances. db-custom-1-3840 (1 vCPU, 3.75 GB) beside RDS's db.t4g.small."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_version" {
  description = "Cloud SQL's PostgreSQL version: 18, as on RDS."
  type        = string
  default     = "POSTGRES_18"
}

variable "db_disk_gib" {
  description = "Each instance's disk (it grows automatically)."
  type        = number
  default     = 20
}

variable "backup_retention_days" {
  description = "Automated backups kept, as a count of daily backups (AWS: 14 days)."
  type        = number
  default     = 14
}

variable "vpc_cidr" {
  description = "The environment's address space: a /16, as on AWS. Two /24s of it are used."
  type        = string
  default     = "10.51.0.0/16"
}

variable "ldap_max_entries" {
  description = "LDAP_MAX_ENTRIES on every node: deploy/aws/environment/variables.tf argues the value."
  type        = number
  default     = 50000
}

variable "applications_max" {
  description = "STS_APPLICATIONS_MAX on every node: deploy/aws/environment/variables.tf argues the value."
  type        = number
  default     = 10000
}

variable "extra_environment" {
  description = "More container environment for every node, laid over what this stack sets."
  type        = map(string)
  default     = {}
}

variable "labels" {
  description = "Labels beside project = sts and environment, which are always added."
  type        = map(string)
  default = {
    managed-by = "terraform"
    stack      = "mock-sts-environment"
  }
}

variable "public_hostname" {
  description = <<-EOT
    The name clients use, e.g. `test-idp.gcp.iyasec.io`, inside `dns_zone_name`.
    EMPTY (the default) keeps the load balancer's address as the service's
    name, as AWS does with the NLB's DNS name; set, it gets an A record and an
    ACME certificate every node presents (deploy/gcp/node-init/cert.sh).
    The foundation must list the same name for this environment, which is
    what made the certificate's secret.
  EOT
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "The Cloud DNS zone public names go in (foundation/dns.tf), delegated from Route 53."
  type        = string
  default     = "gcp.iyasec.io"
}

variable "acme_server" {
  description = <<-EOT
    The ACME directory the certificate is issued from. Let's Encrypt's
    production directory by default. Its staging directory
    (https://acme-staging-v02.api.letsencrypt.org/directory) is for trying a
    new environment without spending the weekly limit — its certificates
    are not publicly trusted.
  EOT
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "acme_email" {
  description = "The ACME account's contact address (expiry notices). Required with `public_hostname`."
  type        = string
  default     = ""
}

variable "acme_renew_days" {
  description = "node-a renews the certificate when it has fewer days left than this, at its next start."
  type        = number
  default     = 30
}

variable "publish_kerberos" {
  description = "Publish TCP 88 (the KDC). On by default, AWS's rule since 2026-09-21; no UDP."
  type        = bool
  default     = true
}

variable "pki_listener_port" {
  description = "The plain-HTTP CRL/OCSP port on the load balancer (the node's is 8082). 80, as on AWS."
  type        = number
  default     = 80
}

variable "spiffe_workload_port" {
  description = "The default realm's SPIFFE Workload API port, the same outside and on the node."
  type        = number
  default     = 8092
}

variable "spiffe_server_port" {
  description = "The default realm's SPIRE Server API port, the same outside and on the node."
  type        = number
  default     = 8181
}

variable "workers_request_count" {
  description = "STS_WORKERS_REQUEST_COUNT: request workers per node (0 = none)."
  type        = number
  default     = 0
}

variable "workers_surface_count" {
  description = "STS_WORKERS_SURFACE_COUNT: surface workers per node (0 = none)."
  type        = number
  default     = 0
}

variable "workers_dispatch" {
  description = "STS_WORKERS_DISPATCH: what the request workers take (`*` for everything)."
  type        = string
  default     = ""
}

variable "workers_read_your_write" {
  description = "STS_WORKERS_READ_YOUR_WRITE. Required on with two or more request workers."
  type        = bool
  default     = false
}

variable "risk_upload_volume_gib" {
  description = "Each node's risk-dataset upload disk (AWS: the EBS volume, #214)."
  type        = number
  default     = 10
}

variable "schema_init_sslmode" {
  description = <<-EOT
    The TLS mode schema-init's psql connects with. `verify-ca` by default and
    NOT verify-full: a Cloud SQL server certificate under GOOGLE_MANAGED_CAS_CA
    names the instance by a DNS name with a trailing dot, which libpq does not
    match. The CA is still verified; the node's own connection (node's TLS,
    which strips the dot) verifies the name. Set `verify-full` once a first
    apply has shown libpq accepts it (deploy/gcp/CLAUDE.md, *What to look at
    first*).
  EOT
  type        = string
  default     = "verify-ca"
  validation {
    condition     = contains(["verify-ca", "verify-full"], var.schema_init_sslmode)
    error_message = "schema_init_sslmode is verify-ca or verify-full."
  }
}
