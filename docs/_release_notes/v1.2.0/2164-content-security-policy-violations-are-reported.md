---
title: "Content Security Policy violations are reported"
heading: "Content Security Policy violations are reported"
kind: added
issue: 2164
---

Every page's Content Security Policy now names a report endpoint
(`report-uri` and `report-to`, with a `Reporting-Endpoints` header), and
browsers report what the policy blocked to `POST /web/csp-report` (ASVS
5.0.0 3.4.7). The endpoint needs no credential, reads at most 16 KiB, takes
60 reports a minute from one address, records the directive, the page's
path without its query and the blocked origin, and logs each report as
`STS-HTTP-0027`. Monitoring → CSP reports counts them per realm, and
`cspReports.forwardUrl` (off by default) forwards each to a collector. See
[OAuth security](oauth-security.md#content-security-policy-violation-reports).

**Upgrading.** Nothing to run. A proxy or a firewall in front of the service
that allows only listed paths needs `POST /web/csp-report` (and
`/realm/<id>/web/csp-report`) added, or the reports stop there.
