---
title: "product mode keeps the build to administrators"
kind: changed
issue: 2142
---

In product mode the page footer no longer shows the version and its build
line, the sign-in (`/authn-api`) and portal (`/account-api`) OpenAPI documents
give `info.version` as `1`, the front page's, portal's and reports' answers
carry an empty version, and the User-Agent of the requests this service makes
to partners is `sts (<component>)` without `/<version>` (ASVS 5.0.0 13.4.6).
The console and `/admin-api` show the build as before, and development mode is
unchanged. A page's cached files are now keyed by a random key the image build
draws rather than by the build instant and commit. The new setting
`security.publishBuildInfo` (`auto`, `on`, `off`; environment
`STS_SECURITY_PUBLISH_BUILD_INFO`) puts the build back everywhere with `on`.
