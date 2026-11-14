# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: openbao/admin-secret.hcl
#
# ===========================================================================
# WHAT A START-UP OR OPERATOR TOKEN MAY DO: READ THE START-UP SECRETS (#254).
#
# `secret/sts-admin` holds what the service needs before it has loaded
# anything — the management API client's secret, and on a product test stack
# the two Kerberos passwords — and it is a path of its OWN, apart from
# `secret/sts`, so that the identity the service holds while it runs (the
# client certificate, `read-only.hcl`) cannot read it. A shell that has the
# running service's credential has the key-encryption key's USE and the
# database password; it does not have `/admin-api`.
#
# Two kinds of token carry this policy, both minted by `openbao/seed.js`
# through the `sts-admin-secret` token role and nothing else:
#
#   * a START-UP token per node, response-wrapped and single-use, which
#     `openbao/startup-secrets.js` unwraps as root in the service container,
#     spends on one read and revokes;
#   * an OPERATOR token, printed by the seeder, which is how a person reads
#     the management API secret for the FIRST token on a stack they own —
#     after that the documented path is an application of their own
#     (`docs/management-api.md`).
#
# Read on the data path and on the metadata path (the version), and nothing
# else: no write, no list, no other path. The default policy beside it gives
# a token `lookup-self`, `renew-self` and `revoke-self`.
# ===========================================================================

path "secret/data/sts-admin" {
  capabilities = ["read"]
}

path "secret/metadata/sts-admin" {
  capabilities = ["read"]
}
