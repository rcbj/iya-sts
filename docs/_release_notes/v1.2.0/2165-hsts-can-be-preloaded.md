---
title: "HSTS can be preloaded"
heading: "HSTS can be preloaded"
kind: added
issue: 2165
---

A new setting, `security.hstsPreload` (off by default), adds `preload` to
the `Strict-Transport-Security` header product mode sends, so the domain
can be submitted to the browsers' HSTS preload list (ASVS 5.0.0 3.7.4). It
is sent only while `security.hstsIncludeSubDomains` is on; with that off
the header carries no `preload`, `/admin/mode` says so and the log records
`STS-CORE-0181`. Preloading binds the whole registrable domain and takes
months to undo: see [Preloading](tls.md#preloading).

**Upgrading.** Nothing changes until the setting is turned on.
