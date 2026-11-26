---
title: "Smart cards: a central section, the standards involved and a guide"
kind: added
issue: 2277
---
[Smart cards](smart-cards.md) gathers everything iya-sts does with PIV, CAC
and other X.509 smart cards: the kinds of card it handles, every place a card
is used, a table from "I want to …" to the section that covers it, and what
it does not do. A page for each standard involved sits beside it
([PIV and YubiKey PIV attestation](smart-cards-piv.md),
[Client certificates in TLS](smart-cards-tls.md),
[Kerberos PKINIT](smart-cards-pkinit.md), [PKCS #11](smart-cards-pkcs11.md),
[Card-held keys](smart-cards-keys.md)), and the
[Smart-card guide](smart-cards-guide.md) has step-by-step recipes: outside
federal PIV and CAC cards, your own YubiKey PIV certificates, card sign-in to
an application, PKINIT, a card for administrators, a proxy in front, renewal
and a lost card. The pages link to the existing sections rather than
repeating them.

[Truststores](truststores.md#smart-cards-and-certificate-sign-in) gains the
use cases a card's certificate is checked under, and its
[Scope](truststores.md#scope-service-wide-and-per-realm) section now says
which service-wide use cases a realm may override, what `STS-PKI-0302`
refuses, and that a `setting:` view is read in the realm that asks.
