---
title: Kerberos PKINIT
nav_order: 23
---

# Kerberos PKINIT

Part of [Smart cards](smart-cards.md). A card's key as the Kerberos
pre-authentication, so a person gets a ticket with no password.

* TOC
{:toc}

## The standards

* **RFC 4556**, PKINIT: the AS-REQ carries a CMS signature over an AuthPack
  made with the client's certificate key, and the reply key is agreed by
  Diffie-Hellman. It also requires `paChecksum`, the SHA-1 of the request
  body.
* **RFC 5349**: elliptic-curve Diffie-Hellman for PKINIT.
* **RFC 8070**: the freshness token, which stops an AuthPack signed in
  advance on a stolen card from being replayed later.
* **RFC 8636**: key-derivation agility, binding the whole exchange into the
  reply key.
* **RFC 8062**: anonymous PKINIT, which gives a machine with no keytab FAST
  armor.
* **RFC 8129**: authentication indicators in the ticket.
* **MS-PKCA section 2.2.3**: `paChecksum2`, the request body's SHA-256,
  SHA-384 or SHA-512, which recent Windows clients send beside RFC 4556's
  `paChecksum`.

## What iya-sts implements

PKINIT is on in every realm (`krb5.pkinit`), with the freshness token
required (`krb5.pkinitRequireFreshness`), RFC 8636's KDFs required unless
`krb5.pkinitLegacyKdf` is set, and `paChecksum2` checked whenever a client
sends it (required only with `krb5.pkinitRequirePaChecksum2`, off by
default because MIT Kerberos does not send it). RSA key transport of the
reply key, MODP group 2 and SHA-1 signatures are refused.
[Kerberos → PKINIT](kerberos.md#a-certificate-as-the-pre-authentication-pkinit-179)
has the whole account.

**Which certificates get a ticket.** One this realm issued to the person,
from one of its identity Issuing CAs, with `id-pkinit-KPClientAuth` or
smart-card logon in its extended key usage: a `piv-auth` certificate for a
card's slot 9a, a `smartcard-logon` certificate enrolled over ACME, EST or
SCEP, or a certificate whose `id-pkinit-san` names the person exactly. A
revoked certificate is answered `KDC_ERR_REVOKED_CERTIFICATE`; a slot 9e
certificate is refused unless the authentication policy's *PIV card
authentication key* row lets it sign in.

**What the ticket says.** Every PKINIT ticket carries the `pkinit`
indicator. An attested card's key adds `pkinit-hardware` (the `H` flag) and
`pkinit-smartcard`, which `/authn/spnego` turns into `amr` `hwk` and `sc`.
By default (`hardwareTokens.hardwareClaims` `inference`) a smart-card logon
certificate over a key this service did not generate earns
`pkinit-hardware` too. A SPNEGO sign-in on a ticket carrying
`pkinit-smartcard` is governed by the authentication policy's *Kerberos
PKINIT with a smart card* row; the AS exchange itself is not gated by it
([Smart cards (#2031)](authentication.md#smart-cards-2031)).

**The KDC's own certificate** comes from the realm's *Kerberos KDC* Issuing
CA, made the first time PKINIT is used, so a client needs only the service
Root as its anchor.

## What it does not implement

* **A card from an outside CA gets no ticket.** The KDC requires the leaf to
  come from this realm's own Issuing CAs (`STS-KRB-0184`), whatever the
  `pkinit` truststore use case is assigned. A federal PIV or CAC holder signs
  in over TLS instead.
* Post-quantum PKINIT: none is standardised.
* MIT Kerberos 1.20 signs through PKCS #11 with RSA only, so the slot 9a key
  must be RSA for `kinit` from a card. That is the client's limit, not the
  KDC's.

## Where it is configured

| What | Console | Setting or call |
|---|---|---|
| PKINIT and its options | **Protocols → Kerberos → Global settings** | `krb5.pkinit`, `krb5.pkinitRequireFreshness`, `krb5.pkinitRequirePaChecksum2`, `krb5.pkinitLegacyKdf`, `krb5.pkinitKdcKeyAlgorithm`, `krb5.anonymousPkinit` ([Configuration → Kerberos](configuration.md#kerberos)) |
| Its status | the same page | `GET /admin-api/kerberos`, `status.pkinit` |
| The card's certificate | see [PIV](smart-cards-piv.md) | `est.allowedProfiles` must include `piv-auth` |
| What a ticket earns | **Protocols → Hardware tokens** | `hardwareTokens.hardwareClaims` |

The client side, `krb5.conf` and `kinit` from a card, is
[Configuring Kerberos → PKINIT](configure-kerberos.md#pkinit-a-certificate-as-the-pre-authentication),
and the recipe is [Guide: PKINIT](smart-cards-guide.md#pkinit-for-kerberos).

## Related

[Kerberos and SPNEGO](kerberos.md) ·
[Configuring Kerberos and SPNEGO](configure-kerberos.md) ·
[Hardware tokens](hardware-tokens.md#what-a-sign-in-claims)
