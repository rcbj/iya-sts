---
title: "a client that declares no scopes is issued `openid` alone"
kind: behaviour-change
issue: 1589
---

In product mode a client whose `oauthAllowedScope` lists nothing, typically
one that registered itself (RFC 7591) without a `scope` member, is now
issued `openid` and nothing else. Every other scope it asks for is refused
`invalid_scope` (`STS-OAUTH-0578`) until it is declared. Until 1.2.0 such a
client got `openid`, `profile`, `email`, `address`, `phone`,
`offline_access` and the realm's OpenID4VCI scopes, so a client nobody had
thought about could hold refresh tokens that outlive the person's session
(ASVS 5.0.0 10.4.11).

`oauth2.undeclaredClientScopes` chooses the set: `openid` (the default),
`identity` (the identity scopes, never `offline_access`), or `legacy` (the
old set). Development mode still issues any scope a client asks for. This
service's own clients declare their scopes and are not affected. A client's
OAuth tab now names the set it gets when it declares none.

**Upgrading from 1.1.** Run the upgrade script before starting the 1.2.0
image ([The audit log is append-only](#new-the-audit-log-is-append-only-in-the-database)
says why it must come first). It stores `legacy` for a store that holds any
application and has no value of its own, so every existing client keeps the
scopes it had. A second run writes nothing. A store still on 1.0.0 runs
`upgrade-1.0.0.sql` first.

```bash
docker compose exec -T postgres \
  psql -U sts -d sts -v ON_ERROR_STOP=1 \
  -f - < postgres/upgrade-1.1.0.sql

mariadb --abort-source-on-error -u root -p sts \
  < mariadb/upgrade-1.1.0.sql
```

A store that is only in memory starts fresh and gets the default. Without a
database (the LDIF store), or in a cell or tier database that does not hold
both the directory and the settings, set `oauth2.undeclaredClientScopes` to
`legacy` yourself. While it is `legacy` or `identity`, `/admin/mode` reports
ASVS 5.0.0 10.4.11 as not met. Declare in each client's `oauthAllowedScope`
the scopes it needs, then set the setting to `openid`.
