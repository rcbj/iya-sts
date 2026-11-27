---
title: "The portal no longer lists Security keys and OpenPGP beside Tokens and keys"
kind: changed
issue: 2308
---

How I sign in keeps Tokens and keys for hardware tokens, one-time code
tokens, YubiKey OTP, PIV, SSH user certificates, and OpenPGP and S/MIME.
Security keys and OpenPGP and mail encryption were the same cards a second
time, and they are no longer in the column. An old address opens the
matching tab: `/portal/tokens` the hardware tokens tab, and
`/portal/openpgp` the OpenPGP and S/MIME tab. A credential-expiry mail
names Tokens and keys for a PIV certificate and for an S/MIME certificate.

See [Hardware tokens](hardware-tokens.md#seeing-them) and
[OpenPGP keys and encrypted mail](openpgp.md#registering-a-key).
