---
title: "An application can be held to the response modes it needs"
kind: security
issue: 2247
---

A new application attribute, `oauthResponseMode`, lists the `response_mode`
values a client may use: `query`, `fragment`, `form_post`, and JARM's `jwt`,
`query.jwt`, `fragment.jwt` and `form_post.jwt`. With a list, the authorization
endpoint refuses any other mode with `unauthorized_client` (`STS-OAUTH-1016`).
A request that names no mode is judged by its response type's default
(`query` for `code`, `fragment` otherwise). Empty, the default, restricts
nothing beyond the server's `response_modes_supported`, so existing clients are
unchanged. Set it on the console's application editor or through
`POST /admin-api/applications/add` (ASVS 5.0.0 10.4.12).
