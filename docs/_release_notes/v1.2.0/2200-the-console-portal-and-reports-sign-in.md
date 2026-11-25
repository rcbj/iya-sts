---
title: "the console, portal and reports sign in with read scopes"
kind: behaviour-change
issue: 2200
---

The admin console, the user portal and the reports application used to ask
for every scope they might ever use on every sign-in, so somebody who only
looked at a page held `admin:write` and `admin:security` (ASVS 5.0.0
10.2.3). Each now signs in with read scopes only: the console with `openid
admin:read admin:console`, the portal with `openid account:read owner:read`,
and the reports application with `report:read`. The first time a page
saves something, the API refuses the read token with `insufficient_scope`
naming the scope it needs, and the page asks for it by a second
authorization in a small window: silently (`prompt=none`) while the sign-on
session lasts, and for `admin:security` only on a sign-in less than five
minutes old (`max_age=300`), asking you to sign in again otherwise. The change
waits in memory and is sent once the scope is in hand. The write token is
used for changes only, is never refreshed, and is dropped after ten minutes
or at its expiry; reads keep the read token. A browser that blocks the
window gets a bar with a **Continue** button.

A service administrator working on another realm's pages through the realm
switcher is asked for the write scope by the realm they signed in at, where
their account is, not by the realm on screen; and the pages that draw their
own write controls (Sign-out's end-session buttons, the roles page) draw
them from the roles the person holds, as the rest of the console does, while
the change itself still needs the scope (#2200).

Two new read scopes: `account:read` (`/account-api`, GETs only) and
`report:read` (`/report-api`, GETs only, authorized by `REPORT_USE` or
`REPORT_ADMIN`). `/admin-api` now names the missing scope on its
refusals (`WWW-Authenticate: … error="insufficient_scope"` on
`STS-API-0005` and `STS-API-0138`; the status, code and body are
unchanged), and `GET /admin-api/me` gains `holds`, the roles the caller may
be issued a token for.

**Upgrading.** Nothing to run. On the first start, `sts-user-portal` and
`sts-report` are given the delegated permission grants and global consent
of the new read scopes, and `sts-account-api` and `sts-report-api` define
them. Tokens carrying `account:manage`, `report:use`, `report:admin` or
`admin:write` work exactly as before, so programs and the protocol suite's
clients need no change. See [Admin console](admin-console.md),
[Account API](account-api.md#getting-a-token) and [Reporting](reporting.md).
