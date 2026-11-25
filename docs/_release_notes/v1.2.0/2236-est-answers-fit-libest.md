---
title: "EST answers fit libest's sixteen header lines again"
kind: fixed
issue: 2236
---

Cisco's libest `estclient`, the reference EST client, reads at most sixteen
header lines of an answer and counts the rest as the body. Since the CSP
reporting header (#2164) and `Cross-Origin-Resource-Policy` (#2181) were added
to every response, a product deployment with request workers answered
`/.well-known/est/cacerts` with seventeen, and `estclient` failed with
"Content Length and body length mismatch". A certificate or CMS body (EST,
SCEP, ACME, CRLs, OCSP) is no longer treated as a page: it gets the narrower
policy without `style-src` and `img-src`, and no `Reporting-Endpoints`. EST
answers also no longer carry an `ETag`, which validated nothing on a
`no-store` answer. Nothing else in what EST answers changed.
