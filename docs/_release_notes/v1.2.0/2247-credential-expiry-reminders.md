---
title: "A person is reminded before a certificate of theirs expires"
kind: security
issue: 2247
---
A person is now mailed before a certificate they hold expires: one this
realm issued over ACME, EST or SCEP, a PIV smart card certificate, an S/MIME
certificate, a TLS client certificate from the portal, or one stored on
their entry for certificate sign-in (ASVS 5.0.0 6.4.5). They are reminded 30,
7 and 1 days before by default, once at each, with every certificate due in
one message saying when it expires and how to renew it. It is a security
notice, on by default wherever a mail transport is configured:
`mail.expiryReminders`, `mail.expiryReminderDays` and
`mail.expiryReminderKinds` set it per realm. The new `mail.credential-expiry`
scheduler job sends them, reading an index of expiry dates kept in step with
every write of a person's entry; certificates held before the upgrade are
added to it a slice of the realm's people per run. The new message,
`credential-expiring`, is translated into every built-in mail language. See
the Mail page.
