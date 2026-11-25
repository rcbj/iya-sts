---
title: "WS-Trust requests signed by Apache WSS4J or CXF"
kind: fixed
issue: 1918
---

A WS-Security signature carrying an `InclusiveNamespaces` prefix list on its
`SignedInfo`, which WSS4J and Apache CXF write by default, was refused as a
signature that does not verify (`STS-KEYS-0012`). It is now verified as its
signer made it.
