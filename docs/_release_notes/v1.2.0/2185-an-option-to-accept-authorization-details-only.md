---
title: "an option to accept `authorization_details` only in a pushed request"
kind: added
issue: 2185
---

`oauth2.authorizationDetailsRequirePar`, **off by default**. On, the
authorization endpoint refuses a request that carries RFC 9396
`authorization_details` and did not come through `/oauth2/par`, so a rich
authorization request never travels in the browser's address (ASVS 5.0.0
10.4.15). Requests without `authorization_details` are unaffected;
`oauth2.requirePushedAuthorizationRequests` still makes every request
pushed (10.4.13). New refusal: `STS-OAUTH-1015`.
