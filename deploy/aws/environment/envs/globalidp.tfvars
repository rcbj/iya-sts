# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `globalidp`: THE SIX-REGION TEST CASE (#367, rcbj 2026-09-30) — iya-sts as
# six cells on three continents behind global-idp.iyasec.io:
#
#   usw2  us-west-2       us   the PRIMARY: the global database's writer
#   use2  us-east-2       us
#   euc1  eu-central-1    eu   Frankfurt   } the EU and EEA countries are
#   euw1  eu-west-1       eu   Ireland     } pinned to these two, by latency
#   apse1 ap-southeast-1  sg   Singapore     Singapore pinned
#   apse5 ap-southeast-5  my   Malaysia      Malaysia pinned (there is no
#                                            AWS region in the Philippines)
#
# The cells, their CIDRs and the pinned countries are
# `globalidp.cells.tfvars.json`, beside this file. Applied like any
# multi-cell environment, and the entrypoint does the order:
#   IMAGE_TAG=<tag> deploy/aws/terraform-local.sh globalidp apply
#   deploy/aws/terraform-local.sh globalidp destroy
#
# BEFORE THE FIRST APPLY an administrator enables ap-southeast-5 on the
# account (an opt-in region) and re-applies foundation/ with its default
# `permitted_regions` and `public_dns`, which name every region and the name
# here (deploy/aws/CLAUDE.md, *globalidp*).
#
# A NAME OF ITS OWN, so it stands beside testidp or testidpna rather than
# taking test-idp.iyasec.io in turn; each cell's console is
# `<cell>.global-idp.iyasec.io`.
#
# Everything else is testidpna's, for its reasons — read that file.
# ---------------------------------------------------------------------------
public_hostname  = "global-idp.iyasec.io"
public_zone_name = "iyasec.io"

extra_environment = {
  STS_DOMAIN              = "iyasec.io"
  KRB5_REALM              = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL  = "HTTP/global-idp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN = "iyasec.io"
  # AS ON testidpna: room for a worker to start, no V8 heap limit while
  # memory is measured (#341), minted rows kept two hours past expiry; no
  # directory window (it requires a single cell) and no mail (a cell has no
  # SES identity of its own yet).
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
  # testidpna's #361 choice (rcbj, 2026-09-30), carried to every pair of
  # this environment's four jurisdictions: a person's session may be held in
  # any other jurisdiction, so each region's own console (Server
  # configuration -> Cells) serves an administrator homed elsewhere. A
  # realm-level loosening of #98 D4's strict default, the credential-free
  # profile being what is held; delete this line to test the strict default.
  # Two cells of ONE jurisdiction need no entry: staying in a jurisdiction
  # is always allowed.
  STS_CELL_PERMITTED_TRANSFERS = "us>eu,us>sg,us>my,eu>us,eu>sg,eu>my,sg>us,sg>eu,sg>my,my>us,my>eu,my>sg"
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
  Lifecycle = "test-case"
}
