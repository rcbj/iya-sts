---
title: "a person is mailed when a credential of theirs is added or removed"
kind: added
issue: 2163
---

Until now only a password change was mailed. A person is now also told when
any of these is added or removed (ASVS 5.0.0 6.3.7):

- a passkey or security key, an authenticator app or an app password
- a one-time code token or a YubiKey OTP
- a set of recovery codes, a certificate or a certificate sign-in binding
- an S/MIME certificate or an OpenPGP key

The message says what changed, when, and whether the person or an
administrator did it, and what to do if it was not them. Several changes made
by one act, such as an administrator removing every second factor, are one
message. Assigning an OATH or YubiKey OTP token through `/admin-api`, and
retiring a lost token's one-time code credentials, now also send a CAEP
`credential-change` event, as the other doors already did.

**Upgrading.** Nothing to run. The notices are on wherever a transport is
configured. To keep the old behaviour, set `mail.credentialChangeNotices` to
`false`. See [Mail](mail.md#the-uses).
