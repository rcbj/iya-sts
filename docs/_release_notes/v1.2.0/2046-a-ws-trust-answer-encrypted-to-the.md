---
title: "a WS-Trust answer encrypted to the request's signing certificate"
kind: added
issue: 2046
---

`wstrustRecipientIgnoresKeyUsage` (the realm's `wstrust.recipientIgnoresKeyUsage`,
off by default) lets an application's answers be encrypted to a certificate whose
`keyUsage` does not permit encryption, such as the request's signing certificate:
this realm's message-signing certificates permit `digitalSignature` only. Only that
check is waived; the certificate's validity, path and revocation are still checked.
It is in the **Message encryption → Response message processing** section of the
application's WS-Trust tab. See [WS-Trust](ws-trust.md#xml-encryption).
