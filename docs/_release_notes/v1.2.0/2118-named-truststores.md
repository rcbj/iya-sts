---
title: "named truststores"
kind: added
issue: 2118
---

Every place the service checks a signature, a certificate chain or the
certificate of a server it connects to is now a **use case** that trusts a
list of named **truststores**: node's default store (`system`), this
service's Root, the shipped vendor roots, the signer and client-certificate
truststores, what each older anchor or CA setting names, SPIFFE trust domain
bundles, and truststores you create. Protocols → PKI trust gains
**Truststores**, **Use cases** and **System truststore** tabs, and
`/admin-api/truststores` is the same controls. **Nothing changes on upgrade**:
each use case's default list names exactly what it trusted before, and every
older setting and page keeps working. A use case's truststores are consulted
in development as well as product mode; paranoid PKI mode decides only what
is checked. Two defects are fixed on the way: a CA file named for an outbound
family or the SMTP relay no longer drops the signer truststore under paranoid
PKI mode, and PKINIT can be given an outside smart-card CA. New refusals:
`STS-PKI-0300` to `0307`. See [Truststores](truststores.md).
