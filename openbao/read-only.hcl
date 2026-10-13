# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: openbao/read-only.hcl
#
# ===========================================================================
# WHAT THE IDENTITY SERVICE MAY DO IN THE SECRET STORE: READ TWO VALUES.
#
# The client certificate `openbao/seed.js` issues is mapped to this policy and
# to nothing else, so the whole of what this service can do with the store is
# below — and every capability it does NOT list is denied, because Vault and
# OpenBao deny by default.
#
# **IT CANNOT WRITE ITS OWN SECRETS**, which is the property worth having and
# the one a test asserts: a compromised identity service cannot rotate the
# key-encryption key out from under the data it sealed, cannot change the
# database password, and cannot plant a key of its own. What it can do is read
# the two values it was given at startup — which is all `common/secrets.js`
# ever asks for.
#
# `secret/data/sts` is the kv-v2 READ path and `secret/metadata/sts` is what a
# client needs to see the version; neither `create` nor `update` nor `delete`
# nor `list` appears on either.
#
# **AND THE USE OF ONE TRANSIT KEY (#391)**: `transit/keys/sts-kek` to read the
# key's type and versions (never its material: it is not exportable), and
# `update` on `transit/encrypt/sts-kek` and `transit/decrypt/sts-kek`, which is
# how Transit spells "use". That is the key-encryption key with
# `keys.kekProvider=vault-transit`: it wraps each data encryption key in the
# store and never leaves it. **NOT `transit/keys/sts-kek/rotate`, nor
# `…/config`**, for the reason above: a compromised service must not be able
# to change the key its data is sealed under — or make it exportable or
# deletable. The key is rotated by an operator, and the console's *Rotate the
# key-encryption key* answers STS-KEYS-0105 here, as it does on the cloud
# deployments. `openbao/seed.js` proves all of it with the certificate.
# ===========================================================================

path "secret/data/sts" {
  capabilities = ["read"]
}

path "secret/metadata/sts" {
  capabilities = ["read"]
}

# The token this service logs in with renews itself rather than logging in
# again on every read; without this it would have to hold a certificate
# handshake open for the life of the process.
path "transit/keys/sts-kek" {
  capabilities = ["read"]
}

path "transit/encrypt/sts-kek" {
  capabilities = ["update"]
}

path "transit/decrypt/sts-kek" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
