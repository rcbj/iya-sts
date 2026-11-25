---
title: "Sigstore trust material as truststores"
kind: added
issue: 2152
---

The SPIFFE Docker workload attestor's cosign public keys, pinned Sigstore
trusted root and TUF root may now come from truststores (#2152): three
new use cases, `sigstore-cosign-key`, `sigstore-trusted-root` and
`sigstore-tuf-root`, each defaulting to today's setting, so nothing
changes until an administrator assigns a truststore. Several trusted roots
are combined; a TUF root is one. `POST /admin-api/truststores/create` and
`set-keys` take `document`.
