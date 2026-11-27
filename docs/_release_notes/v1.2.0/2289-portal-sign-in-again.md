---
title: "The portal asks you to sign in again instead of failing"
kind: fixed
issue: 2289
---
On the user portal, some changes need a recent sign-in: enrolling or
reporting a security key or smart card, issuing or revoking an SSH
certificate, and OpenPGP keys. If your sign-in was older than
`account.recentAuthMinutes` (15 minutes in product mode), those changes failed
with *The service could not produce a valid answer*. The service's own
"sign in again" answer did not match the models of those operations, so it was
blocked. They now send you to sign in again, as the other sensitive changes
always have. Every `/account-api` operation that requires a recent sign-in is
now held to accepting that answer, including operations added later.
