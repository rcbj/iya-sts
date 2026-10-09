---
title: User-facing pages
---

# User-facing pages

These are all the things this service shows a person in a browser, an inbox or
an authenticator prompt. Everything else it serves is for programs: token,
metadata and discovery endpoints, the management API, SCIM, Kerberos and LDAP.

Paths are given for the default realm. In a [trust realm](trust-realms.md),
put `/realm/<id>` in front.

The **Language** column says whether the page can be drawn in another
language ([Languages and regions](languages.md)):

- **Yes**: translated, with the language chooser on the page.
- **Yes, no chooser**: translated, but the page cannot carry a chooser. A
  page that submits itself has nothing to redraw.
- **Planned (phase N)**: not yet translated. Issue #539 is converting the
  pages in phases.
- **English**: deliberately not translated. Error and refusal text is always
  English, everywhere.

## Signing in

The authentication service. Every protocol sends a person here, whichever one
started the sign-in.

| Page | Path | What a person does there | Language |
|---|---|---|---|
| Sign-in screen | `/authn/login` | Types a username and password, or picks a passkey, an emailed code or link, a federation partner, Kerberos or a wallet | Yes |
| Choose an identity provider | `/authn/select-idp` | Picks one of the federation partners an application allows | Yes |
| Forced password change | `/authn/password-change` | Sets a new password before the sign-in continues | Yes |
| Second-factor set-up | `/authn/mfa-setup` | Enrols an authenticator app or a passkey that the realm requires | Yes |
| Passkey step | `/authn/webauthn` | Uses or registers a passkey (WebAuthn) | Yes |
| One-time code step | `/authn/totp` | Types the code from an authenticator app | Yes |
| Recovery code step | `/authn/backup-code` | Types one recovery code instead of the usual second factor | Yes |
| Password as the second factor | `/authn/password-factor` | Types a password after a passkey or wallet first factor | Yes |
| Emailed code | `/authn/email-code` | Types the code that was mailed | Yes |
| Emailed sign-in link | `/authn/email-link`, `/authn/email-link/open` | Waits for the link, then opens it | Yes |
| Wallet sign-in | `/authn/wallet`, `/authn/wallet/wait` | Presents a credential from a wallet, on this device or by QR code | Yes |
| Kerberos sign-in | `/authn/spnego` | Nothing to type: the browser presents a ticket. A page is seen only when there is no ticket, or once signed in. | Yes (a refused ticket is English) |
| Moving to the home cell | (inside a sign-in) | Is sent on to the region that holds the account | Yes, no chooser |
| Language chooser | `/authn/language` | Every page above posts here when another language is chosen | n/a (it only redirects) |

## Consent, hand-offs and signing out

| Page | Path | What a person does there | Language |
|---|---|---|---|
| Consent screen | `/oauth2/consent` | Allows or refuses what an application asks for | Yes |
| Returning to the application (`form_post`) | from `/oauth2/authorize` | Nothing, unless JavaScript is off; then presses Continue | Yes, no chooser |
| SAML 2.0, SAML 1.1 and WS-Federation hand-offs | `/saml2/sso/…`, `/saml2/slo/…`, `/saml11/sso/…`, `/wsfed` | The same: a page that posts the response to the application | Yes, no chooser |
| Federation hand-offs | `/federation/login/…`, `/federation/acs/…`, `/federation/slo/…` | Is posted to or from a partner identity provider | Yes, no chooser |
| Link an account | `/federation/link/…` | Joins a partner's account to one here at first sign-in. The person sees the sign-in screen, fixed to that account. | Yes |
| Application sign-out (RP-initiated logout) | `/oauth2/logout` | Confirms signing out of an application, then sees "Signed out" | Yes |
| Sign out of everything | `/logout` | Sees every live session and signs out of them | Yes |
| Device sign-in (RFC 8628) | `/portal/device` | Types the code shown on a TV or console | Yes |
| GNAP | `/gnap/code`, `/gnap/approve/…` | Types a user code; approves or refuses a grant | Yes |
| The OP iframe | `/oauth2/check_session` | Nothing visible: a relying party's session check | n/a |

## The front door and the realm chooser

| Page | Path | What a person does there | Language |
|---|---|---|---|
| Front door | `/` | Finds the console, the portal and the documentation | Yes |
| Choose your realm | at `/admin` and `/portal` | Says which realm to sign in through, where trust realms exist | Yes |

## The user portal

A person's own account, at `/portal`. **Every page is translated**, with the
language chooser in the header beside Refresh and Sign out, and on the pages
drawn for nobody (activation, a password reset, address verification). The
Overview has a **Language and region** card: it sets the person's own
`preferredLanguage`, or removes it to follow the browser
(`POST /portal/language`). Error text stays English.

| Page | Path |
|---|---|
| Your account | `/portal` |
| Email address and verification | `/portal/email`, `/portal/verify-email` |
| Forgotten password | `/portal/forgot-password`, `/portal/reset-password` |
| Account activation | `/portal/activate` |
| Change your password | `/portal/password` |
| Your applications | `/portal/applications` |
| Your security activity | `/portal/signals` |
| Passkeys | `/portal/keys` |
| Authenticator app and recovery codes | `/portal/mfa` |
| Certificates | `/portal/certificates` |
| Who may act for you | `/portal/delegate` |
| Connected claim sources | `/portal/claim-sources` |
| Sign-in requests (CIBA) | `/portal/ciba` |
| Your devices | `/portal/devices` |
| Your self-issued IDs | `/portal/self-issued` |
| App passwords | `/portal/app-passwords` |
| Kerberos | `/portal/kerberos` |
| Recent sign-ins | `/portal/sign-ins` |
| Consents | `/portal/consents` |
| GNAP grants | `/portal/gnap` |
| Your signing key | `/portal/signing-key` |
| Sign in a device | `/portal/device` |

## The admin console

The console at `/admin` is one application with many pages under Directory,
Protocols, Server configuration and Monitoring. Its navigation, labels, forms
and messages are planned for **phase 5**. Its long explanatory prose is
**phase 6**. The API explorer at `/admin/api-explorer` is part of it.

## Mail

| Message | Sent when | Language |
|---|---|---|
| Password reset link | A person asks on `/portal/forgot-password` | Yes |
| Address verification | An address is added or changed | Yes |
| Activation and other administrator links | An administrator sends one | Yes |
| Emailed sign-in code or link | The sign-in uses one | Yes |
| Security notices | A credential, address or session changes | Yes |

A message is written in the recipient's language: the built-in wording ships
in every catalog language, and a realm's own wording on `/admin/mail` wins
over it in that language. The facts filled in (who, what kind, when) are
translated too. A reason somebody typed is sent as written. See
[Mail](mail.md#messages).

## In the browser's own dialogs

| What | Where it comes from | Language |
|---|---|---|
| The passkey prompt | The browser and the operating system. This service supplies only the names it shows: the realm's relying-party name and the person's display name. | The browser's own |
| The Digital Credentials API wallet chooser | The browser | The browser's own |

## Pages that are not for end users

They are listed so the list above is complete. None is planned for
translation:

- **The embedded protocol debugger**, on its own listener (`debugger.port`). It
  is a separate application from the parent project.
- **Demonstration pages** that exist only in development mode: the sample
  credential issuer ("Mock University") at `/oid4vci/…` and the sample
  verifier ("The Bar Door") at `/oid4vp/verifier`.
- **Operator and diagnostic views**: `/tls` and its sub-pages, `/xacml`, and
  the SPIFFE, SCIM and Shared Signals status pages.
- **Error pages**: "This request could not be completed" and every other
  refusal. These are English by design.
