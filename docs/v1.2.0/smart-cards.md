---
title: Smart cards
nav_order: 20
---

# Smart cards

iya-sts signs people in with the certificate on a PIV card, a CAC or any
other X.509 smart card, issues and renews the certificates for a card's
slots, and retires a card that is lost. This page says what it does with a
card and where each part is documented. It repeats none of it: every row
links to the section that has the detail.

* TOC
{:toc}

## The cards it handles

| Card | Who issues its certificates | What the service knows about the key | Where it is set up |
|---|---|---|---|
| **A YubiKey's PIV applet**, enrolled with the card's attestation | This realm's EST Issuing CA, under the four PIV slot profiles | The key was made on the card and never left it. The card is recorded in the realm's hardware token register under its serial, and a sign-in with it records `amr` `hwk` and `sc` | [PIV key attestation](hardware-tokens.md#piv-key-attestation), [PIV certificate profiles](hardware-tokens.md#piv-certificate-profiles) |
| **A federal PIV card, a CAC, or an enterprise smart card** | An outside certification authority | Nothing: the service never sees the card, so a sign-in records `swk`. It is still a *smart card* to the authentication policy when a profile or the card-UUID mapping says so | [Smart-card and certificate sign-in](configure-tls.md#smart-card-and-certificate-sign-in), [Outside PIV and CAC cards](hardware-tokens.md#outside-piv-and-cac-cards) |
| **Any card holding a certificate this realm issued** without an attestation (`smartcard-logon` over ACME, EST or SCEP, or a PIV profile while `piv.requireAttestation` is off) | This realm's ACME, EST or SCEP Issuing CA | What its enrolment recorded; no hardware evidence | [PKI → PIV smart-card certificates](pki.md#piv-smart-card-certificates), [EST](est.md) |

A card that does not attest the way a YubiKey does is refused at
attestation and recorded as no token
([PIV key attestation](hardware-tokens.md#piv-key-attestation)). Its
certificates can still be issued without an attestation, or come from an
outside CA.

## Where a card is used

* **Browser sign-in over TLS client authentication.** The sign-in screen
  offers **Continue as *name* with your certificate**, and `GET /tls/sign-in`
  starts a session with no screen. A card can be asked for on a listener of
  its own (the *handoff*), so people who type a password are not asked for a
  PIN. See [Sign in with a client certificate](configure-tls.md#sign-in-with-a-client-certificate)
  and [A listener of its own for the card](configure-tls.md#a-listener-of-its-own-for-the-card-the-handoff).
* **Certificate sign-in profiles and bindings.** For a whole population of
  outside cards, a profile per CA says what a certificate must carry and how
  the one account it belongs to is found (`issuer-serial`, `card-uuid`,
  `spki-sha256` and others). See [What decides a certificate](configure-tls.md#what-decides-a-certificate)
  and [Binding methods](configure-tls.md#binding-methods).
* **Kerberos PKINIT.** `kinit` signs the AS-REQ with the card's key through
  PKCS #11 and gets a ticket with no password. Only a certificate this realm
  issued gets one. See [PKINIT](smart-cards-pkinit.md).
* **LDAPS.** A connection that presented a card's certificate binds with SASL
  EXTERNAL, once port 636 asks for a certificate. See
  [LDAP → Binding with a client certificate](ldap.md#binding-with-a-client-certificate)
  and [Configuring LDAP](configure-ldap.md#ask-for-or-require-a-client-certificate-on-636).
* **The other doors that take a certificate as a person**: SCIM, the XACML
  gates, Shared Signals and WS-Trust ask the same question as the sign-in
  ([What decides a certificate](configure-tls.md#what-decides-a-certificate)).
* **Mail and SSH.** A card's slot 9d key decrypts the S/MIME mail this
  service sends; an OpenPGP card's key can be registered; an OpenSSH user
  certificate can be issued for a card's key. See
  [Card-held keys](smart-cards-keys.md).
* **Renewal: the post-login PIV re-issue.** After sign-in, a person whose slot
  certificate is expiring, or was signed by a classical CA once the EST
  Issuing CA is post-quantum, is asked to enrol a new one. See
  [The PIV re-issue](post-login-activities.md#the-piv-re-issue).
* **A lost card.** Reporting it lost revokes every certificate on it for
  `keyCompromise` and ends the sessions they started. See
  [Reporting a token lost](hardware-tokens.md#reporting-a-token-lost).
* **The authentication policy.** Three rows govern a smart card separately
  from other certificates, and `requireAttestedHardware` can require an
  attested card or key of everybody. See
  [Smart cards (#2031)](authentication.md#smart-cards-2031) and
  [Attested hardware for everybody](authentication.md#attested-hardware-for-everybody).
* **What a token says about it.** A card sign-in is one factor (`acr "1"`).
  Its `amr` is `swk`, or `hwk` and `sc` on an attested card
  ([What a sign-in claims](hardware-tokens.md#what-a-sign-in-claims)). It
  earns OpenID Connect EAP's `phr`, never `phrh`
  ([Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh)).
* **Which truststores a card is checked against**:
  [Truststores → Smart cards and certificate sign-in](truststores.md#smart-cards-and-certificate-sign-in).

## I want to …

| I want to … | Read |
|---|---|
| accept federal PIV or CAC cards from an outside CA | [Guide: outside PIV and CAC cards](smart-cards-guide.md#accept-outside-federal-piv-and-cac-cards) |
| work out a CA's or a card's digest for a profile or a binding | [Working out the values](configure-tls.md#working-out-the-values) |
| record which person a card belongs to | [Recording a binding on a person](configure-tls.md#recording-a-binding-on-a-person) |
| issue YubiKey PIV certificates with attestation | [Guide: YubiKey PIV certificates](smart-cards-guide.md#issue-your-own-yubikey-piv-certificates-with-attestation) |
| let people sign in to an OpenID Connect or SAML application with a card | [Guide: card sign-in to an application](smart-cards-guide.md#card-sign-in-to-an-openid-connect-or-saml-application) |
| get a Kerberos ticket with a card | [Guide: PKINIT](smart-cards-guide.md#pkinit-for-kerberos) |
| require a card of administrators | [Guide: administrators](smart-cards-guide.md#require-a-card-for-administrators) |
| put a TLS-terminating proxy in front | [Guide: a proxy in front](smart-cards-guide.md#a-tls-terminating-proxy-in-front) |
| renew or re-issue card certificates | [Guide: renewal and re-issue](smart-cards-guide.md#renewal-and-re-issue) |
| deal with a lost card | [Guide: a lost card](smart-cards-guide.md#a-lost-card) |
| require a verified revocation status | [Require a verified revocation status](configure-tls.md#require-a-verified-revocation-status) |
| keep 9d keys so old mail stays readable after a card is lost | [Escrowed encryption keys](hardware-tokens.md#escrowed-encryption-keys) |
| see what the service made of a certificate | [See what the service made of your certificate](configure-tls.md#see-what-the-service-made-of-your-certificate) |
| look up a `STS-PIV-` error code | [Error codes → STS-PIV](error-codes.md#sts-piv) |
| find every setting | [Configuration → Certificate sign-in](configuration.md#certificate-sign-in), [→ PIV](configuration.md#piv), [→ Hardware tokens](configuration.md#hardware-tokens) |

## The standards involved

| Page | Covers |
|---|---|
| [PIV and YubiKey PIV attestation](smart-cards-piv.md) | FIPS 201-3, NIST SP 800-73-4's slots, the FIPS 201 card UUID, the Federal PKI policies, and Yubico's attestation in a certificate request |
| [Client certificates in TLS](smart-cards-tls.md) | RFC 8446's client authentication, RFC 5280 path validation and policy processing, OCSP and CRLs, RFC 9440 from a proxy, RFC 4513's SASL EXTERNAL |
| [Kerberos PKINIT](smart-cards-pkinit.md) | RFC 4556, RFC 8070, RFC 8636, RFC 5349, RFC 8062, RFC 8129 and MS-PKCA's `paChecksum2` |
| [PKCS #11](smart-cards-pkcs11.md) | How clients reach a card, and the one place the service itself uses PKCS #11 |
| [Card-held keys: S/MIME, OpenPGP and SSH](smart-cards-keys.md) | RFC 8551 mail to a slot 9d key, an OpenPGP card's key, OpenSSH certificates for a card's key |

The configuration and use-case recipes are in the
[Smart-card guide](smart-cards-guide.md).

## What it does not do

* **It never talks to the card.** The card checks its own PIN, and the
  service sees only a TLS handshake, a CMS signature or a certificate
  request. So a card sign-in is **one factor** (`acr "1"`). In product mode
  everybody also owes a second factor, unless `authn.allowOptionalSecondFactor`
  is on ([Requiring a second factor of everybody](authentication.md#requiring-a-second-factor-of-everybody)),
  so a card holder is asked for one after the card. `GET /tls/sign-in`
  starts no session for a person who owes one (`STS-TLS-0060`); they use
  the screen.
* **A card sign-in never earns `phrh`**, even on an attested YubiKey:
  `phrh` is earned only by a WebAuthn assertion. And a sign-in screen drawn
  for a request naming only `phr` or `phrh` asks for a security key or
  passkey and does not offer the certificate.
* **An outside card is never attested hardware.** The `attested-hardware`
  mechanism and `requireAttestedHardware` accept a credential on a token the
  hardware token register recorded from attestation, which only an enrolment
  here records.
* **PKINIT takes only certificates this realm issued.** A federal PIV or CAC
  card gets no Kerberos ticket, even with its CA assigned to the `pkinit`
  use case.
* **Attestation is YubiKey PIV attestation only.** No other card's
  attestation format is read.
* **No post-quantum key on a card.** A YubiKey makes none today, so the PIV
  re-issue renews the certificate and keeps the classical key.
* **No card management.** The service does not reset a PIN, unblock a card,
  write a card's certificates or read its CHUID; the holder does that with
  the card's own tools (`ykman`, `yubico-piv-tool`).
* **No test drives a physical outside card, the handoff over two real
  listeners, or a real proxy.** Those are held by in-process tests. The
  YubiKey path is tested with the clients a person uses
  ([Tested with real clients](hardware-tokens.md#tested-with-real-clients)).

## Related

See also [Phishing-resistant sign-in](phishing-resistance.md), every defence
against phishing in one place.

[Hardware tokens](hardware-tokens.md) ·
[Configuring TLS and mutual TLS](configure-tls.md) ·
[TLS and mutual TLS](tls.md) ·
[The sign-in service](authentication.md) ·
[Authentication pathways](authentication-pathways.md) ·
[PKI](pki.md) ·
[Truststores](truststores.md) ·
[Kerberos and SPNEGO](kerberos.md) ·
[Post-login activities](post-login-activities.md)
