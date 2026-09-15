# File: openbao/bao.hcl
#
# ===========================================================================
# THE SECRET STORE THIS STACK READS ITS KEY-ENCRYPTION KEY AND ITS DATABASE
# PASSWORD FROM (2026-09-12).
#
# OpenBao rather than HashiCorp Vault: it is the same API, the same CLI and the
# same auth methods under an open licence, so `common/secrets.js`'s `vault`
# provider and the `node-vault` SDK behind it reach it unchanged — which is the
# point. A deployment pointing this service at a real Vault changes one URL.
#
# ---------------------------------------------------------------------------
# `seal "static"` IS WHAT MAKES THIS SELF-UNLOCKING, AND IT IS A REAL AUTO
# SEAL RATHER THAN DEV MODE.
#
# A sealed secret store is one somebody has to unseal by hand with a quorum of
# key shares, which is correct for a production vault and impossible for a
# stack that has to come up on `docker compose up` and in a test run. The
# alternative usually reached for is `bao server -dev`, and it was refused:
# dev mode holds everything IN MEMORY, so the key-encryption key would change
# on every restart — and a service whose KEK changes cannot read back a single
# thing it sealed, which is the exact failure this whole arrangement exists to
# prevent.
#
# So this is an ordinary server with ordinary storage, and the seal is a
# builtin `static` one: the unseal key is handed to the process in
# `BAO_STATIC_SEAL_CURRENT_KEY` and it unseals ITSELF at startup, every time,
# with no operator and no quorum. **The key must be base64 of exactly 32
# bytes** — 31 fails initialisation with `invalid key size`, and a failed
# initialisation leaves the storage dirty enough that the next attempt answers
# "already initialized" with no root token anywhere.
#
# **WHAT IT COSTS IS HONEST AND IS THE WHOLE TRADE**: the key that unseals this
# store travels beside it, so the store protects what is IN it from a reader of
# the database, and not from somebody who can read this stack's environment.
# That is the same trade the compose stack already makes with every other
# credential in it, and a deployment that wants the real thing sets
# `BAO_STATIC_SEAL_CURRENT_KEY` from its own orchestrator's secret — or
# replaces this stanza with a `transit`, `awskms`, `gcpckms` or
# `azurekeyvault` seal, which is the same one line.
#
# ---------------------------------------------------------------------------
# TLS IS NOT OPTIONAL HERE AND IT IS NOT DECORATION.
#
# This stack authenticates with a CLIENT CERTIFICATE (`auth/cert`), and a
# client certificate on a plaintext listener is not a thing — there is no
# handshake to present it in. The pair is minted before the server starts by
# `openbao/generate-tls.js`, with this repository's own encoder, into the
# volume below.
#
# `storage "raft"` rather than `file`: the file backend is deprecated in
# OpenBao 2.6 and removed in 2.7, and raft is a single-node store here with no
# cluster to join. The path is under `/openbao/file` because THAT directory
# exists in the image owned by the server's own user, so a fresh named volume
# inherits the ownership — a volume at `/openbao/data` is created root-owned
# and the server cannot write to it.
# ===========================================================================

storage "raft" {
  path    = "/openbao/file/raft"
  node_id = "sts-openbao"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/openbao/file/tls/server.crt"
  tls_key_file  = "/openbao/file/tls/server.key"
}

# The key and its id come from BAO_STATIC_SEAL_CURRENT_KEY and
# BAO_STATIC_SEAL_CURRENT_KEY_ID — the environment overrides OpenBao reads for
# this seal. They are NOT written here: a config file in a repository is the
# one place an unseal key must never be.
seal "static" {}

# The address this node advertises. `openbao` is the compose service name and
# is what the certificate above carries as a subjectAltName.
api_addr     = "https://openbao:8200"
cluster_addr = "https://openbao:8201"
ui           = false
