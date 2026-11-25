---
title: "an option to issue only sender-constrained access tokens"
kind: added
issue: 2183
---

`oauth2.accessTokenRequireSenderConstraint`, **off by default**. On, the token
endpoint issues an access token only to a request that binds it, by a DPoP
proof or the connection's client certificate (ASVS 5.0.0 10.3.5 and
10.4.14), and the authorization endpoint refuses a `token` response type. It
is for a realm whose every client can bind its tokens; most cannot. New
refusals: `STS-OAUTH-1013`, `1014`.
