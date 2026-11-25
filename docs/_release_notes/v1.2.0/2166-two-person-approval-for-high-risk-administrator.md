---
title: "two-person approval for high-risk administrator acts"
kind: added
issue: 2166
---

A realm can now require a second administrator for its highest-risk acts
(ASVS 5.0.0 2.3.5). This is new setting `admin.dualControl`, off by default
and per realm. While it is on, these acts wait on a new console page,
**Pending approvals** (`/admin/approvals`):

* removing a realm
* granting an administrator role
* re-keying or revoking a CA
* replacing a trust anchor
* rotating, importing or retiring a signing key
* rotating the key-encryption key
* turning the setting off

A second, different administrator with the same authority approves the act,
and it then runs as the first administrator's act, or refuses it. The
requester may withdraw it. Undecided, it expires after
`admin.dualControlLifetimeHours` (default 24).

The management API answers a held act with HTTP 202 and the request's id,
and adds `GET /admin-api/approvals` and `POST /admin-api/approvals/{approve,
refuse, withdraw}`. When fewer than two people could decide an act, it runs
and is recorded as `STS-ADMIN-0976`, so a realm can never be locked out. The
**Mode** page shows whether the control is in force.

**Upgrading.** Nothing to run. With the setting off, which is the default,
nothing changes. The held acts are kept in the existing store, so there is
no schema change. See
[Two-person approval](admin-console.md#two-person-approval).
