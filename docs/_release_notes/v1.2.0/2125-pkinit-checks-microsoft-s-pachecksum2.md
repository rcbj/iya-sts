---
title: "PKINIT checks Microsoft's paChecksum2"
kind: added
issue: 2125
---

The KDC now checks MS-PKCA's `paChecksum2` — the request body's SHA-256,
SHA-384 or SHA-512 — whenever a PKINIT client sends one, beside RFC 4556's
SHA-1 `paChecksum`, which stays required. A mismatch is refused
(`STS-KRB-0261`), and so is one over SHA-1 in product mode or over an
unlisted digest (`STS-KRB-0260`). The new setting
`krb5.pkinitRequirePaChecksum2` (off by default, because MIT Kerberos does
not send one) refuses a request without it (`STS-KRB-0262`). See
[Kerberos](kerberos.md).
