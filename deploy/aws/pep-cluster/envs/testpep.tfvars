# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `testpep`: a remote PEP cluster of two members in front of the companion's
# /pep-app, pulling from testidp at its public name (rcbj, 2026-11-23).
#   TF_STACK=pep-cluster IMAGE_TAG=<tag> deploy/aws/terraform-local.sh testpep apply
# ALLOWED_CIDR unset admits this host's current address, as for testidp.
# testidp must admit this environment's `egress_ip` in its own ALLOWED_CIDR.
# ---------------------------------------------------------------------------
idp_url          = "https://test-idp.iyasec.io"
public_hostname  = "test-pep.iyasec.io"
public_zone_name = "iyasec.io"
vpc_cidr         = "10.60.0.0/16"
instance_count   = 2
companion        = true
