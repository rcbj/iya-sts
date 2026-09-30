# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Every variable that has an AWS or GCP counterpart keeps its name and its
# default, so an `envs/<env>.tfvars` reads the same on every side where it can.

variable "subscription_id" {
  description = "The Azure subscription (the foundation's)."
  type        = string
}

variable "region" {
  description = "The region of a single-cell environment: the foundation's home region. A cell's is its own (cells.tf)."
  type        = string
  default     = "westus2"
}

variable "name" {
  description = "The project prefix. Must match the foundation stack's `name`."
  type        = string
  default     = "mock-sts"
}

variable "environment" {
  description = <<-EOT
    This environment's name, the same names as AWS (`dev`, `ci`, `testidp`,
    `testidpna`, `globalidp`). It goes into every resource name; the rule is
    AWS's, 2-12 lower-case letters and digits. It must be listed in the
    foundation's `environments`.
  EOT
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.environment))
    error_message = "environment is 2-12 lower-case letters and digits, starting with a letter."
  }
}

variable "state_storage_account" {
  description = "The state storage account (bootstrap-state.sh); read here only for the global stack's state in a cell. entrypoint.sh sets it."
  type        = string
  default     = ""
}

variable "state_resource_group" {
  description = "The state storage account's resource group."
  type        = string
  default     = "mock-sts-terraform-state"
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
  description = "The service image tag in the foundation's registry (the commit)."
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
  description = "Nodes, one per availability zone. Three, like AWS and GCP."
  type        = number
  default     = 3
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 3
    error_message = "node_count is 1 to 3: one node per zone, and three zones."
  }
}

variable "vm_size" {
  description = <<-EOT
    A node's VM size. Standard_B2s (2 vCPU, 4 GB, burstable) is the nearest
    to AWS's 1 vCPU / 3 GB test node and GCP's e2-medium; Standard_D2s_v5
    (2 vCPU, 8 GB) is testidp's 2048 / 8192. deploy/aws/CLAUDE.md, *Sizing a
    node*, applies unchanged: every node process is a whole copy of the
    service.
  EOT
  type        = string
  default     = "Standard_B2s"
}

variable "os_disk_gib" {
  description = "The OS disk (Ubuntu, the image layers and Docker's own storage). Fargate's ephemeral storage was 20 GiB."
  type        = number
  default     = 30
}

variable "db_sku" {
  description = <<-EOT
    The Flexible Server SKU of both instances. GP_Standard_D2ds_v5 (2 vCores,
    8 GB): the smallest GENERAL PURPOSE size, because a read replica — the
    cell database's and the global tier's — is refused on the Burstable tier
    that would otherwise sit beside RDS's db.t4g.small.
  EOT
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "db_version" {
  description = "PostgreSQL's major version: 18, as on RDS and Cloud SQL."
  type        = string
  default     = "18"
}

variable "db_storage_mb" {
  description = "Each server's storage, in MB (it grows automatically). 32 GiB is Flexible Server's smallest."
  type        = number
  default     = 32768
}

variable "db_replica" {
  description = "Whether the cell database has a read replica in a second zone, as on AWS and GCP. It is a copy and a promotable standby, not a failover target."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Automated backups kept (AWS: 14 days). Flexible Server takes 7 to 35."
  type        = number
  default     = 14
}

variable "vpc_cidr" {
  description = "The environment's VNet address space: a /16, as on AWS and GCP. Two /24s of it are used. A cell's is its own, from the cells file."
  type        = string
  default     = "10.80.0.0/16"
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

variable "tags" {
  description = "Tags beside Project = STS and Environment, which are always added."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Stack     = "mock-sts-environment"
  }
}

variable "public_hostname" {
  description = <<-EOT
    The name clients use, e.g. `test-idp.azure.iyasec.io`, inside
    `dns_zone_name`. EMPTY (the default) keeps the load balancer's address as
    the service's name, as AWS does with the NLB's DNS name; set, it gets a
    record and an ACME certificate every node presents
    (deploy/azure/node-init/cert.sh). The foundation must list the same name
    for this environment, which is what gave the nodes the right to answer the
    challenge and made the certificate's secret. A multi-region
    environment's is in its cells file, which every stack of it reads.
  EOT
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "The Azure DNS zone public names go in (../foundation/home.tf), delegated from Route 53."
  type        = string
  default     = "azure.iyasec.io"
}

variable "acme_server" {
  description = <<-EOT
    The ACME directory the certificate is issued from. Let's Encrypt's
    production directory by default. Its staging directory
    (https://acme-staging-v02.api.letsencrypt.org/directory) is for trying a
    new environment without spending the weekly limit — its certificates are
    not publicly trusted.
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
    The TLS mode schema-init's psql connects with. `verify-full` — unlike
    GCP, whose Cloud SQL names the instance with a trailing dot libpq does
    not match: a Flexible Server's certificate names its FQDN under a public
    root, so the name is verified too. `verify-ca` is kept only as the
    escape hatch deploy/aws/schema-init/apply.sh allows.
  EOT
  type        = string
  default     = "verify-full"
  validation {
    condition     = contains(["verify-ca", "verify-full"], var.schema_init_sslmode)
    error_message = "schema_init_sslmode is verify-ca or verify-full."
  }
}
