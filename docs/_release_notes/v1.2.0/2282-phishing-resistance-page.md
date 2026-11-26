---
title: "A page on phishing-resistant sign-in"
kind: added
issue: 2282
---
New documentation: [Phishing-resistant sign-in](phishing-resistance.md)
gathers what iya-sts implements against phishing, with the specification
behind each. It covers passkeys and their origin binding, attestation and
policy; OpenID Connect EAP's `phr` and `phrh` and how each protocol asks for
them; smart cards; account recovery; Device Bound Session Credentials;
sender-constrained tokens; the authorization request's integrity; and
detection. It ends with what is not implemented. Documentation only: no
setting or behaviour changes.
