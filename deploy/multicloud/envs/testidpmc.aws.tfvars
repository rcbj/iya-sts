# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# testidpmc's AWS CELLS (#97): what every AWS cell shares — testidpna's
# settings (deploy/aws/environment/envs/testidpna.tfvars argues each). The
# GCP cells' twin is testidpmc.gcp.tfvars; the cells themselves are
# testidpmc.cells.tfvars.json, which every stack of the environment reads.
#
# THE SAME PUBLIC NAME AS testidpna, so the two cannot run together; the
# multi-cloud launcher refuses while testidpna's state exists.
#
# NO STS_CELL_PERMITTED_TRANSFERS: each jurisdiction has a cell in each cloud,
# so a session held away from home inside its jurisdiction is no transfer; one
# ACROSS jurisdictions (us, eu, sg) is refused by the strict default until
# somebody decides otherwise.
# ---------------------------------------------------------------------------
public_hostname  = "test-idp.iyasec.io"
public_zone_name = "iyasec.io"

extra_environment = {
  STS_DOMAIN                       = "iyasec.io"
  KRB5_REALM                       = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL           = "HTTP/test-idp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN          = "iyasec.io"
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
}

# THE KEY-ENCRYPTION KEY IS THE SECRET, NOT THE KMS KEY (#391). The AWS
# stack's default is foundation's multi-region KMS key, but every cell must
# name the SAME KEK, and the GCP cells read it from Secret Manager (copied by
# gcp-global from AWS's `kek` secret) — a GCP node cannot call AWS KMS
# without AWS credentials. deploy/aws/environment refuses "kms" with a cell
# whose cloud is not aws (kek.tf).
kek_provider = "secret"

sts_mode                = "product"
workers_request_count   = 2
workers_surface_count   = 0
workers_dispatch        = "*"
workers_read_your_write = true

task_cpu    = 2048
task_memory = 8192

delete_automated_backups = true

tags = {
  ManagedBy = "terraform"
  Stack     = "mock-sts-environment"
  Lifecycle = "long-lived"
}
