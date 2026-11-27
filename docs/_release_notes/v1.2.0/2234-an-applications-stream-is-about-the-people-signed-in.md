---
title: "an application's Shared Signals stream is about the people signed in to it"
kind: behaviour-change
issue: 2234
---

A stream an application owns (created with its client credentials, its GNAP
key or its TLS client certificate) now carries a CAEP or RISC event about a
person only while that person has an **active session on that
application**: a live sign-on session it is a relying party of (OpenID
Connect or OAuth client, SAML 2.0 or 1.1 service provider, WS-Federation
relying party), or a live GNAP grant the person approved to it. It used to
be sent every person's events in the realm. The event that ends such a
session (a sign-out's `session-revoked`, a RISC `account-disabled` or
`account-purged` about the same act) still reaches the application whose
session it ended. Events with no subject, and events about the application
itself or another non-person, are unchanged. Add Subject naming a person
with no active session on the application answers 403 (`STS-SSF-0164`).
`ssf.applicationStreamScope: all` restores the old behaviour per realm. See
[Shared Signals](shared-signals.md).
