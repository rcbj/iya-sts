---
title: "an anonymous wallet keeps the scopes its offer named"
kind: behaviour-change
issue: 2169
---

A Credential Offer's pre-authorized code may be redeemed by a wallet that
names no client (OpenID4VCI 1.0 section 6.1). Its access token now carries
the scopes of the configurations the offer named, read from the offer and
not from the request, and keeps them in product mode, where the change above
would otherwise have issued that absent client `openid` alone. Without them
the credential was issued but not recorded for the person: `/portal/wallet`
did not list it and it could not sign them in. Until 1.2.0 such a token
always carried `identity_credential`, whichever configuration was offered.
A wallet that names a client is still issued only what that client
declares.
