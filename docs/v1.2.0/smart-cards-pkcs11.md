---
title: PKCS #11
nav_order: 24
---

# PKCS #11

Part of [Smart cards](smart-cards.md).

## The standard

**PKCS #11** (OASIS, *PKCS #11 Specification Version 3.2*) is the C
interface a program uses to ask a token, a smart card or a hardware security
module, to sign or decrypt with a key that never leaves it. **RFC 7512**
names an object on a token as a `pkcs11:` URI, such as `pkcs11:id=%01` for a
PIV card's slot 9a key under OpenSC.

## Where it is used with a card: on the client

**The service never opens a person's card.** A card is behind the
client's own middleware, most often OpenSC's `opensc-pkcs11.so`, and the
service sees only what the client sends: a TLS CertificateVerify, a CMS
signature in a PKINIT request, a certificate request signed on the card. So
no PKCS #11 setting of the service has anything to do with a person's card.

The clients this service's tests drive a card with, through PKCS #11 (most
are in [Hardware tokens → Tested with real clients](hardware-tokens.md#tested-with-real-clients)):

* `yubico-piv-tool` and OpenSC, to make keys in slots 9a, 9c and 9d and sign
  a certificate request on the card;
* `curl` with the card's key as a `pkcs11:` URI, for a TLS sign-in at
  `GET /tls/sign-in`;
* MIT `kinit -X X509_user_identity=PKCS11:…`, for PKINIT
  ([Configuring Kerberos → PKINIT](configure-kerberos.md#pkinit-a-certificate-as-the-pre-authentication));
* `openssl cms -decrypt` with the 9d key, for S/MIME mail
  ([OpenPGP and S/MIME → Encrypted mail](openpgp.md#encrypted-mail));
* `ssh -I opensc-pkcs11.so`, for an OpenSSH user certificate on a card's key
  ([PKI → OpenSSH user certificates](pki.md#openssh-user-certificates)).

A browser reaches a card the same way, through the PKCS #11 module or the
platform's smart-card service it is configured with; that is the browser's
setup, not this service's.

## Where the service itself uses it: an HSM

The service is a PKCS #11 client of a hardware security module, for its own
keys: the key-encryption key (`keys.kekProvider=pkcs11`) and a realm's
classical signing keys (`keys.signingKeyStore=pkcs11`, off by default).
That is [Keys in a hardware security module](hsm.md). It is not a smart-card
feature: the HSM holds the service's keys, never a person's.

## What it does not implement

* Reading or writing a person's card from the server, or a server-side
  PKCS #11 module for people's cards.
* Card keys for the service's own signatures: a realm's signing keys go in
  an HSM, not on a smart card.

## Related

[Keys in a hardware security module](hsm.md) ·
[Specifications](specifications.md)
