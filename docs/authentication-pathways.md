---
title: Authentication pathways
nav_order: 15
---

# Authentication pathways

This page lists every way a person or a program can authenticate to iya-sts in
product mode, how strong each is, and the rules that hold for all of them.

## Rules that hold on every path

* **One session funnel.** Every session is created in one place. A disabled
  account, a retiring realm, a missing directory entry, and a refusal by the
  issuance policy are refused there, whichever door was used.
* **A second factor is required of everybody** at the sign-in screen, unless
  `authn.allowOptionalSecondFactor` is on. Somebody who holds none enrols one
  before a session starts. An exempt service account stays exempt.
* **Rate limits.** `security.rateLimitPerIdentity` and
  `security.rateLimitPerAddress` limit attempts at every door that checks a
  credential.
* **The session records how it was made**, with `amr` and `acr`, and every token
  carries that.
* **An account is never locked for failed attempts.** See
  [How repeated password guesses are slowed](authentication.md#how-repeated-password-guesses-are-slowed).

## People

| Pathway | What is proved | `amr` | `acr` | Second factor |
|---|---|---|---|---|
| **Sign-in screen**, password then a second factor | Password, and a TOTP code, passkey, recovery code or wallet | `pwd` and the factor, such as `otp` or `hwk` | `mfa` | Required |
| **Passkey alone** (passwordless) | One passkey | `hwk` | `1` | Refused under the requirement above, because one key is one factor. Asks for a password instead |
| **Continue with your certificate** on the screen | A verified TLS client certificate | `swk` | `1` | Asked afterwards where one is required |
| **`GET /tls/sign-in`** | A verified TLS client certificate | `swk` | `1` | **Required in product.** This door has no screen, so it starts no session for somebody who needs a second factor. They use the screen's certificate button instead |
| **SPNEGO** (`/authn/spnego`) | A Kerberos ticket | From the ticket's flags | `mfa` if the ticket records two factors, otherwise `1` | Enforced at the KDC when the ticket was issued. See below |
| **Kerberos AS-REQ** | Password and FAST with OTP, a passkey, or PKINIT | `pwd` and `otp`, among others | From the factors | A person who holds or must hold a second factor gets no ticket on a password alone |
| **Wallet** (`/authn/wallet`) | A credential this realm issued, with a holder proof | `pop` | `1`, or `mfa` with hardware and user attestation | Asked afterwards where one is required |
| **Federation partner** | A verified assertion from a configured partner | `federated` and the partner's own values | From the partner | **Not asked** by this rule. The issuance policy can demand a local second factor as a step-up |
| **Emailed code or link** | Possession of a verified mailbox | | | Off by default. NIST SP 800-63B-4 does not count email as an authenticator |
| **Recovery code** | A single-use code | With the password | `mfa` | It is the second factor, for when the usual one is lost |
| **Remembered browser** | An earlier second factor on this browser | | | Off by default. Only if the authentication policy's `rememberedBrowserSkipsSecondFactor` is on, and never for an administrator |
| **Anonymous** | Nothing | none | `0` | Off by default (`authn.unauthenticatedSessions`) |

> **Note.** A federated session has whatever strength the partner states, and
> this service does not ask for a second factor on top. A partner is the
> authentication. To keep such a session out of applications that need two
> factors, name them in the [issuance policy](authorization.md) or have the
> application request `acr_values` of `mfa`.
>
> Programs that present a client certificate, such as WS-Trust, token exchange,
> mutual-TLS client authentication, LDAP SASL EXTERNAL and PKINIT, are not asked
> either. Nobody is there to answer.

## Doors that take only a password

An LDAP bind, a WS-Trust UsernameToken, SCIM, Shared Signals and EST Basic cannot
ask for a second factor. **In product mode they refuse the person's own password**
and accept an **app password** scoped to that door. An app password is generated,
shown once, stored as a scrypt hash and revocable. It works without a second
factor on purpose, and `amr` records it as a password. See
[The password-only doors](authentication.md#the-password-only-doors-and-app-passwords).

`authn.passwordAloneDoors` lists doors that accept the password alone. Each door
listed is one factor for those people.

LDAP also accepts SASL EXTERNAL with a client certificate over LDAPS. See
[LDAP](ldap.md).

## Programs

| Pathway | Credential | Notes |
|---|---|---|
| OAuth client authentication | Client secret, `private_key_jwt`, mutual TLS (RFC 8705), client attestation | The client's registered method |
| RFC 7523 and RFC 7522 assertions | A key or certificate the realm has declared for the issuer | Accepted once only. A person's assertion is recorded as a delegation |
| Management API, account API, report API | A token audienced to that API | With the required scope. The console and portal tokens are DPoP-bound |
| SPIRE Server API, Broker API | An X509-SVID | |
| XACML and AuthZEN endpoints | A client certificate holding the required role | |

A service account is refused a browser session.

## Strength and step-up

A protocol can ask for more than a door gave:

* OAuth and OpenID Connect `acr_values`, `max_age` and `prompt=login`, and RFC 9470
  step-up, add an authentication to the existing session.
* SAML `ForceAuthn` does the same.
* An application's own authentication policy (`appAuthnPolicy`) can restrict which
  mechanisms it accepts.

See [Sessions](sessions.md) for how a re-authentication changes a session, and
[Policies](policies.md) for selecting a policy.

## Related

* [Authentication](authentication.md)
* [What is not checked](what-is-not-checked.md)
* [Passkeys](passkeys.md)
* [Federation](federation.md)
