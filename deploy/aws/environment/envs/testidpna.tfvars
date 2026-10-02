# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `testidpna`: `testidp` AS TWO CELLS — North America, issue #98's first
# geography (D5): usw2 (us-west-2, jurisdiction `us`) and cac1 (ca-central-1,
# jurisdiction `ca`), behind the same public name.
#
# WHAT EVERY CELL SETS. The cells themselves — their regions, jurisdictions,
# VPC CIDRs, the countries Route 53 pins to each, and which one holds the
# global database's writer — are `testidpna.cells.tfvars.json`, beside this
# file, which the global/ stack reads too and entrypoint.sh reads to know the
# cells (a JSON file because a shell has jq and no HCL parser). Applied like
# any environment, and the entrypoint does the rest in order:
#   IMAGE_TAG=<tag> deploy/aws/terraform-local.sh testidpna apply
#   deploy/aws/terraform-local.sh testidpna destroy
#
# THE ENVIRONMENT'S NAME IS `testidpna`, NOT `testidp-na`: an environment name
# is 2-12 lower-case letters and digits (it is in every resource name, and a
# cell's names carry the cell as well — `iya-sts-testidpna-cac1-8081`).
#
# **IT CANNOT RUN BESIDE `testidp`.** Both answer to test-idp.iyasec.io, and a
# CNAME (testidp's) cannot share a name with the geolocation records a cell
# writes. Destroy one before applying the other.
#
# Everything else is `testidp.tfvars`'s, for its reasons — read that file.
# ---------------------------------------------------------------------------
public_hostname  = "test-idp.iyasec.io"
public_zone_name = "iyasec.io"

extra_environment = {
  STS_DOMAIN              = "iyasec.io"
  KRB5_REALM              = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL  = "HTTP/test-idp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN = "iyasec.io"
  # AS ON testidp (#311): room for a worker to start after a day of runs, no
  # V8 heap limit while memory is measured (#341), minted rows kept two hours
  # past expiry (rcbj). NOT testidp's LDAP_WORKER_DIRECTORY=postgres-lru: the
  # directory window requires a single cell (ldap.workerDirectory), so the
  # surface worker stays at 0 here, as each extra process holds the whole
  # directory. NOT its mail either: a cell has no SES identity of its own yet
  # (deploy/aws/CLAUDE.md, *Cells*).
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
  # rcbj, 2026-09-30 (#361): a person's session may be held in the other
  # region, both ways, so each region's own console (Server configuration ->
  # Cells) serves an administrator homed in the other. A realm-level
  # loosening of #98 D4's strict default; the credential-free profile is
  # what is held.
  STS_CELL_PERMITTED_TRANSFERS = "us>ca,ca>us"
}

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
  Stack     = "iya-sts-environment"
  Lifecycle = "long-lived"
}
