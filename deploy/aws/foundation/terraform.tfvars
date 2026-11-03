# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ONE REGION (rcbj, 2026-11-03, #1293). Terraform loads this file by itself,
# by hand and inside deploy/aws/Dockerfile's container alike, so an apply
# can no longer fall back to `permitted_regions`' default — the seven
# regions of `globalidp` (#367), one of which (ap-southeast-5) the account
# has not enabled. The fence, both boundaries, the replication rule and the
# per-region keys follow this list (variables.tf). A cells environment
# (`testidpna`, `globalidp`) needs its regions added back here, and an
# administrator's re-apply, before it can deploy.
permitted_regions = ["us-west-2"]
