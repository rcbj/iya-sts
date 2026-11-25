---
title: "S/MIME mail is authenticated encryption"
kind: behaviour-change
issue: 2124
---

Mail encrypted to a person's S/MIME certificate is now a CMS
AuthEnvelopedData (RFC 5083) under AES-256-GCM (RFC 5084), sent as
`application/pkcs7-mime; smime-type=authEnveloped-data` as S/MIME 4.0
(RFC 8551) asks, so the recipient can tell the message was not changed on
the way (ASVS 5.0.0 11.3.3). Until 1.2.0 it was an EnvelopedData under
AES-256-CBC (`smime-type=enveloped-data`), which has no integrity
protection. RSA, EC and ML-KEM certificates are handled as before; only the
content encryption and its container changed.

**Upgrading.** Nothing to run: an existing deployment sends GCM from the
first message after the upgrade, retries of mail already queued included.
For a recipient whose mail client cannot read AuthEnvelopedData, set
`mail.smimeContentEncryption` to `aes256-cbc` (in the realm, or
`STS_MAIL_SMIME_CONTENT_ENCRYPTION`) to send exactly what 1.1 sent. While it
is `aes256-cbc` in product mode, `/admin/mode` reports ASVS 5.0.0 11.3.3 as
not met. See [OpenPGP and S/MIME](openpgp.md#encrypted-mail).
