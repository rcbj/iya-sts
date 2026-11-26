---
title: PIV and YubiKey PIV attestation
nav_order: 21
---

# PIV and YubiKey PIV attestation

Part of [Smart cards](smart-cards.md).

* TOC
{:toc}

## The standards

**FIPS 201-3**, *Personal Identity Verification (PIV) of Federal Employees
and Contractors*, defines the PIV credential: a smart card with keys and
certificates the issuing agency bound to one person. **NIST SP 800-73-4**
defines the card's interface, and the four key slots this service's profiles
follow:

| Slot | SP 800-73-4 key | PIN | This service's profile |
|---|---|---|---|
| 9a | PIV Authentication | yes | `piv-auth`: client authentication, PKINIT and smart-card logon |
| 9c | Digital Signature | yes | `piv-sign`: signing, with `nonRepudiation` |
| 9d | Key Management | yes | `piv-key-management`: decrypting mail |
| 9e | Card Authentication | **no** | `piv-card-auth`: physical access; signs nobody in by default |

**The FIPS 201 card UUID** is a `urn:uuid:` URI in the PIV Authentication
certificate's subjectAltName, the same for every certificate on one card and
new on a reissued card. It is what this service can bind an outside card to
without trusting any name the CA wrote.

**The Federal PKI certificate policies** say what kind of card a certificate
is on. Two are this service's defaults for an outside card:
`id-fpki-common-authentication` (`2.16.840.1.101.3.2.1.3.13`, PIV
Authentication) and `id-fpki-certpcy-pivi-hardware`
(`2.16.840.1.101.3.2.1.3.18`, PIV-I). A CAC is handled as an outside PIV
card: add the CAC issuer's own hardware policies to the list.

**YubiKey PIV attestation** is Yubico's, not NIST's: the YubiKey signs a
certificate for a slot's key with its factory f9 key, which chains to
Yubico's PIV root, and so proves the key was made on the card. This service
reads it from the enrolment form, or from a certificate request's
`id-aa-attestation` attribute as
[draft-ietf-lamps-csr-attestation](https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/)
defines it.

## What iya-sts implements

* **The four slot profiles**, issued from the realm's EST Issuing CA by the
  PIV enrolment form (portal, console, `POST /admin-api/hardware-tokens/enrol-piv`)
  and by ACME, EST and SCEP. No realm issues them until they are added to
  the family's `allowedProfiles`. [PIV certificate profiles](hardware-tokens.md#piv-certificate-profiles)
  has each one's key usage, extended key usage and names.
* **Attestation checks** at enrolment: the attested key is the request's, the
  chain runs through the f9 certificate to a PIV attestation anchor, the
  serial is present, the slot fits the profile, and the PIN and touch
  policies meet `piv.pinPolicy` and `piv.touchPolicy`. A verified card is
  recorded in the hardware token register with evidence `piv-attestation`.
  [PIV key attestation](hardware-tokens.md#piv-key-attestation) lists every
  check and its refusal.
* **Slot 9e is held apart.** Its key works without a PIN, so its certificate
  is never hardware evidence, is refused by PKINIT, and signs in over TLS
  only where the authentication policy's *PIV card authentication key* row
  allows it ([Smart cards (#2031)](authentication.md#smart-cards-2031)).
* **Escrow of 9d keys**, off by default (`piv.keyEscrow`):
  [Escrowed encryption keys](hardware-tokens.md#escrowed-encryption-keys).
* **Outside PIV and CAC cards by card UUID.** Two ways, both reading the
  person's `stsPivCardUuid`: `piv.externalIssuers`, which accepts a card only
  from a listed issuing CA ([Outside PIV and CAC cards](hardware-tokens.md#outside-piv-and-cac-cards)),
  and a certificate sign-in profile with the `card-uuid` binding, which
  names a root and checks the Federal PKI policies over the whole path,
  mappings included ([Example: federal PIV cards](configure-tls.md#example-federal-piv-cards)).
* **Renewal after sign-in**: [The PIV re-issue](post-login-activities.md#the-piv-re-issue),
  and an expiry reminder by mail 30, 7 and 1 days before
  ([Mail](mail.md#the-uses)).

## What it does not implement

* Any attestation format but YubiKey PIV attestation. A card whose slot
  certificates carry no Yubico serial, or are not signed by its f9
  certificate, is refused at the serial or chain check.
* Card management: the CHUID, the FASC-N, the card's PIN and PUK, and the
  card's other data objects are never read or written. The certificate's
  subjectAltName is the only place the card UUID is read from.
* A post-quantum key in a slot. A YubiKey 5 attests a classical key, so
  `pivTarget` `rekey` in the re-issue asks nobody.

## Where it is configured

| What | Console | Setting or call |
|---|---|---|
| The PIV settings | **Protocols → PIV** (`/admin/piv`) | `piv.*` ([Configuration → PIV](configuration.md#piv)) |
| Which profiles are issued | **Protocols → Cert issuance**, each family's settings | `est.allowedProfiles`, `acme.allowedProfiles`, `scep.allowedProfiles` |
| Enrolling a card for a person | **Directory → Hardware tokens → Enrol PIV**, or the person's **Credentials → PIV** sub-tab | `POST /admin-api/hardware-tokens/enrol-piv` |
| A person enrolling their own | the portal's **Tokens and keys → PIV** tab | `POST /account-api/tokens` with `action` `enrol-piv` |
| A person's outside card UUID | **Directory → Users →** the person, *Outside PIV or CAC card UUIDs* | the `stsPivCardUuid` attribute |
| The attestation roots | **Protocols → PIV** | `piv.attestationAnchors`, or the `piv-attestation` use case ([Truststores](truststores.md#smart-cards-and-certificate-sign-in)) |

Recipes: [Smart-card guide](smart-cards-guide.md).

## Related

[Hardware tokens](hardware-tokens.md) ·
[PKI → PIV smart-card certificates](pki.md#piv-smart-card-certificates) ·
[Specifications](specifications.md) ·
[Error codes → STS-PIV](error-codes.md#sts-piv)
