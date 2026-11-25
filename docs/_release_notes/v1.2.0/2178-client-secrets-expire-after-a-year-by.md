---
title: "client secrets expire after a year by default"
kind: behaviour-change
issue: 2178
---

`oauth2.clientSecretLifetimeDays` now defaults to **365** (it was 0, never),
for ASVS 5.0.0 13.3.4. Every client secret minted or given from now on,
including a dynamically registered client's, carries an expiry one year out,
and RFC 7591's `client_secret_expires_at` says so. **A secret that already
exists keeps the expiry it has**: the lifetime is stamped on each secret when
it is made and never recalculated. In product mode an expired secret is
refused at the token endpoint, so rotate secrets before they expire (an
application's **Client secrets** list shows each one's expiry). Set the
setting to `0` to keep secrets that never expire. The secrets this service
uses for its own clients are unaffected: they hold none.
