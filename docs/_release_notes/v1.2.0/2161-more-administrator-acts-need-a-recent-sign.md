---
title: "more administrator acts need a recent sign-in"
kind: behaviour-change
issue: 2161
---

Until now, only changing a person's credentials through the console or
`/admin-api` asked an administrator to have signed in within
`account.recentAuthMinutes` (15 minutes in product mode). The same is now
asked for granting or removing a role, an administrator role included;
creating, changing or removing a trust realm; every PKI act, including a
CA, an Intermediate, a certificate, a revocation and the signer truststore;
the signing keys, the data keys and the key-encryption key; the TLS client
truststore; the secret push destinations; the krbtgt key and a person's
keytab; every setting, the mode among them; and every change only a
Security Administrator may make (ASVS 5.0.0 7.5.3). The console asks for
the sign-in again and carries on. The API answers 401 with RFC 9470's
`insufficient_user_authentication` and `max_age` (`STS-API-0145`).

**Upgrading.** Nothing to run. A program calling `/admin-api` with its own
client credentials is not asked. A script that uses a person's token for
these acts must sign that person in again when it gets the 401. Development
mode does not ask, since `account.recentAuthMinutes` is 0 there.
