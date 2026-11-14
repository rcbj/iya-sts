# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: openbao/seeder.hcl
#
# ===========================================================================
# WHAT THE SEEDER MAY DO AFTER THE FIRST RUN: TWO THINGS (#254, 2026-10-06).
#
# The root token `PUT /v1/sys/init` hands back is used for the run that
# initialised the store and then REVOKED (rcbj's decision on #254): nothing
# on disk holds root. A stack still has to be brought up again, though, and
# every `up` needs two things from the store that only a token can ask for:
#
#   * a renewed CLIENT CERTIFICATE for the service when the one it holds is
#     within `STS_BAO_RENEW_WITHIN_DAYS` of expiring — `update` on
#     `pki/issue/sts-client`, the one role, which issues CLIENT certificates
#     only (`openbao/seed.js`, `ensurePki()`), whose name is pinned to the
#     service's by the cert auth binding;
#   * a fresh START-UP TOKEN per node, and an operator token — `update` on
#     `auth/token/create/sts-admin-secret`, the one token role, which can
#     mint nothing but `admin-secret.hcl`'s read;
#   * the start-up secrets THEMSELVES, read and written, because a launcher
#     pins a new management API secret on every run (and a kept stack is
#     brought up again with it), and the value the seeder cannot store is the
#     value the next start reads. It adds no reach: a token that can mint a
#     reader of `secret/sts-admin` already has what is in it.
#
# So this token, kept in the store's own volume as `seed/seeder.token` (0600),
# can give somebody the management API secret (and change it), and a client
# certificate the service's own policy is bound to. It cannot read the
# key-encryption key, the database password or any other path, cannot write
# a policy, a mount or an auth method, and cannot make a token with any other
# policy. A change to
# those is an operator's act with a root token made for it
# (`bao operator generate-root`, from the recovery key) or a fresh stack.
#
# It is a PERIODIC token, renewed by every seeder run (`renew-self`, from the
# default policy): a stack brought up at least once a period keeps it for
# ever, and one left longer comes back proving only (`openbao/CLAUDE.md`).
# ===========================================================================

path "pki/issue/sts-client" {
  capabilities = ["update"]
}

path "auth/token/create/sts-admin-secret" {
  capabilities = ["update"]
}

path "secret/data/sts-admin" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/sts-admin" {
  capabilities = ["read"]
}
