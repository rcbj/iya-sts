---
title: "Every TLS listener staples an OCSP response"
kind: security
issue: 2254
---
The main port, LDAPS 636, the debugger listener and every custom listener now
answer a client that asks for the certificate status (RFC 6066
`status_request`, TLS 1.2 and 1.3) with a stapled OCSP response: the answer
this service's own OCSP responder gives for the listener certificate, made in
the process holding the socket with no network fetch, and refreshed by the new
per-process job `tls.ocsp-staple-refresh` before its `nextUpdate` (and at once
when the certificate is renewed or revoked in that process). The new setting
`tls.ocspStapling` is `auto` (on in product mode, off in development); `on`
and `off` force it. A certificate from an outside authority is not stapled, a
staple that cannot be made never fails a handshake (`STS-TLS-0079`), and one
that says `revoked` is logged (`STS-TLS-0080`). The issued certificates carry
no must-staple extension. ASVS 5.0.0 12.1.4; the TLS page's *OCSP stapling*
section has the rest.
