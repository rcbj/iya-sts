---
title: "every specification listed, on one page"
kind: added
issue: 2272
---

A new page, [Specifications](specifications.md), names every specification
the service implements, grouped, and the README carries the same list.
`/admin/sts-metadata` and `GET /admin-api/sts-metadata` now list ten that the
service already implemented but did not name there, each with its coverage:
RFC 4121 (the Kerberos GSS-API mechanism), RFC 4880 (OpenPGP v4 keys),
RFC 9629 (KEM recipients in CMS), RFC 9935 (ML-KEM in X.509), ALFA for XACML,
FIDO U2F, PKCS #11 3.2, RFC 7512 (PKCS #11 URIs), and OpenSSH's certificate
keys and key revocation lists. Nothing the service does changes.
