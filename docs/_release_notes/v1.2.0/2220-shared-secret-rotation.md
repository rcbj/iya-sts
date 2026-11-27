---
title: "Shared secrets, the database password, client secrets, the cell key and the DKIM key can be rotated"
kind: security
issue: 2220
---
The shared secrets that are keys (the CSRF, ACME nonce, Shared Signals
receiver, OpenID Federation page, sign-out result and DBSC keys) now rotate
every `cluster.secretRotationDays` (90) on a store shared through the
database. A new value is published before it is used, and the old one is
still accepted for `cluster.secretOverlapS` (one day). A value stored by an
earlier release is first rotated that many days after the upgrade, never at
it. The pairwise subject secret is an identifier and never rotates, and the
generated bootstrap administrator's name now comes from a secret of its own,
seeded from the CSRF key's current value, so the name does not change.

The database password is read again from its secret store every
`persistence.databasePasswordRefreshS` (an hour) and when the database
refuses a login, and new connections use it without a restart. Rotating it
at the database is still your secret store's or your job.

An application listed in `oauth2.clientSecretAutoRotate` has its client
secret rotated `oauth2.clientSecretAutoRotateDays` (30) before it expires,
with the new secret pushed to its secret destination first or read from its
RFC 7592 configuration. The management API client's secret can now be
rotated while `adminApi.clientSecret` pins it, a changed setting is adopted
at start with an overlap, and a newly seeded secret expires after
`oauth2.clientSecretLifetimeDays`.

A cell's key-encryption key can be rotated with the new
`keys.previousCellKek*` settings. The DKIM key can be rotated under a new
selector with `mail.dkimNextSelector`, `mail.dkimNextKeyField` and
`mail.dkimSwitchAt`; signing moves only once DNS publishes the new key. The
mail transport reads its secrets again at least once an hour.
