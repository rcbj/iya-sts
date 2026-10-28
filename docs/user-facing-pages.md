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
| Post-login activity | `/authn/post-login` | After signing in, registers a post-quantum passkey the realm asks for, or skips it while allowed ([Post-login activities](post-login-activities.md)) | Yes |
| Emailed code | `/authn/email-code` | Types the code that was mailed | Yes |
| Emailed sign-in link | `/authn/email-link`, `/authn/email-link/open` | Waits for the link, then opens it | Yes |
| Wallet sign-in | `/authn/wallet`, `/authn/wallet/wait` | Presents a credential from a wallet, on this device or by QR code | Yes |
| Kerberos sign-in | `/authn/spnego` | Nothing to type: the browser presents a ticket. A page is seen only when there is no ticket, or once signed in. | Yes (a refused ticket is English) |
| Moving to the home cell | (inside a sign-in) | Is sent on to the region that holds the account | Yes, no chooser |
| Language chooser | `/authn/language` | Every page above posts here when another language is chosen | n/a (it only redirects) |

**Since #571 the sign-in screen, the identity-provider chooser and the
forced password change are static pages**: the browser draws them, in its
own language, from [`/authn-api`](authn-api.md) and sends what was typed
there, so they need JavaScript; with scripts blocked the page says so. A
passkey with no username, and the browser fingerprint where a realm turns
it on, run in the same script. **Since #572 and #573 the pages after them —
the second-factor set-up, the passkey, one-time code, recovery code and
password steps, and the emailed code and link pages — are the same kind of
page**, drawn from `/authn-api/mfa/{id}`: the passkey ceremony and the
set-up step's QR code run in the browser, and the link's waiting page checks
every few seconds. The mailed link still opens `/authn/email-link/open`, and
opening it spends nothing until Continue is pressed.

## Consent, hand-offs and signing out

| Page | Path | What a person does there | Language |
|---|---|---|---|
| Consent screen | `/oauth2/consent` | Allows or refuses what an application asks for | Yes |
| Returning to the application (`form_post`) | from `/oauth2/authorize` | Nothing, unless JavaScript is off; then presses Continue | Yes, no chooser |
| SAML 2.0, SAML 1.1 and WS-Federation hand-offs | `/saml2/sso/…`, `/saml2/slo/…`, `/saml11/sso/…`, `/wsfed` | The same: a page that posts the response to the application | Yes, no chooser |
| Federation hand-offs | `/federation/login/…`, `/federation/acs/…`, `/federation/slo/…` | Is posted to or from a partner identity provider | Yes, no chooser |
| Link an account | `/federation/link/…` | Joins a partner's account to one here at first sign-in. The person sees the sign-in screen, fixed to that account. | Yes |
| Application sign-out (RP-initiated logout) | `/oauth2/logout` | Confirms signing out of an application, then sees "Signed out" | Yes |
| Sign out of everything | `/logout` | Sees every live session and signs out of them; drawn in the browser, so it needs JavaScript. Where the sign-out has applications to tell, the person lands on `/logout/signed-out` | Yes |
| Device sign-in (RFC 8628) | `/portal/device` | Types the code shown on a TV or console | Yes |
| GNAP | `/gnap/code`, `/gnap/approve/…` | Types a user code; approves or refuses a grant | Yes |
| The OP iframe | `/oauth2/check_session` | Nothing visible: a relying party's session check | n/a |

**Since #576 the consent screen is a static page too**, drawn from
[`/authn-api/consent/{id}`](authn-api.md#the-consent-screen) in the browser's
own language, with Allow and Deny sent there; it needs JavaScript, and with
scripts blocked it says so. The authorization endpoint, its redirects and
how the answer reaches the application are unchanged.

## The front door and the realm chooser

| Page | Path | What a person does there | Language |
|---|---|---|---|
| Front door | `/` | Finds the console, the portal, reports and the documentation | Yes |
| Choose your realm | at `/admin` and `/portal` | Chooses which realm to sign in through, from a list of every realm; the browser remembers the choice | Yes |

**Since #579 the front door is a static page**, the first of the public
pages to become one: the browser draws it, in its own language, from
`GET /home-api/front` — a JSON view of the version, the mode and the six
links — so it needs JavaScript; with scripts blocked it says so and links
the documentation.

## The user portal

A person's own account, at `/portal`. **Since #568 it is a static
application**, like the admin console: the page signs in in the browser as
the public client `sts-user-portal`, holds a DPoP-bound token in memory, and
draws every page from the [account API](account-api.md), `/account-api`.
Every form is sent there too. The paths below still name the pages, so a
link mailed to a person and the browser's history work as before. The
portal needs JavaScript; with scripts blocked it says so and shows nothing.

**Every page is translated**, with the language chooser in the header beside
Refresh and Sign out, and on the pages drawn for nobody (activation, a
password reset, address verification). The Overview has a **Language and
region** card: it sets the person's own `preferredLanguage`, or removes it
to follow the browser. Error text stays English. Its **Times you have signed
in** is the service's own count of this person's accepted sign-ins, the same
figure the admin console's user page shows; in product mode it is read from
the store, so it survives a restart of the service and is not bounded by what
one process keeps in memory.

**Sign out** in the header ends the sign-on session, and with it the
portal's tokens. A person signed in to the admin console is signed in to the
portal through single sign-on, with no screen.

**Switch user**, with [several accounts in one browser](multiple-accounts.md)
on in the realm (the default), is a menu in the header beside Sign out: it lists
the other accounts signed in to this browser — choosing one draws this tab
as that person with nothing typed — and **Sign in with another account**,
which adds an account. The account the tab leaves stays signed in, so you
can switch back to it from the same menu. With the setting off the menu is
not drawn.

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
| Add a credential to your wallet, and the ones issued to you | `/portal/wallet` |
| App passwords | `/portal/app-passwords` |
| Kerberos | `/portal/kerberos` |
| Recent sign-ins | `/portal/sign-ins` |
| Consents | `/portal/consents` |
| GNAP grants | `/portal/gnap` |
| Your signing key | `/portal/signing-key` |
| Sign in a device | `/portal/device` |
| Resources I own: roles, groups, service accounts, applications | `/portal/owned/roles`, `/portal/owned/groups`, `/portal/owned/service-accounts`, `/portal/owned/applications` |

**Resources I own** is a section of the portal's column with four pages. Each
lists the roles, groups, service accounts or applications whose owners name
the person, or a group the person is in, and says which, twenty to a page with
a pager under the list. An administrator sets owners on the console's Owners
tabs.

**An owner can change what they own.** Each name opens that object's page,
where an owner can:

| Kind | What an owner can change |
|---|---|
| Role | its display name and description; its members (people, groups, applications); its owners |
| Group | its members (add); its owners |
| Service account | where its rotated password is pushed; rotate the password now; its owners |
| Application | its name, home page, CORS origins, redirect and logout addresses, SAML endpoints; a new client secret (shown once); its owners |

An owner can add and remove other owners, but not the last one; an
administrator can. Nobody can create, delete or rename an object here.

The page reads and writes through the [management API](management-api.md#owners)
with a second access token the portal gets from the same sign-in. The
access-control policy decides every read and change, so the page refuses
whatever the policy refuses and says why. A person who owns nothing is not
issued that token.

**Some objects are closed to their owners**, and their row says so. These are
the service's own roles, the console's administrator groups, the service's own
applications, anything that holds or grants one of the service's own
permissions, and anything an administrator has marked. An administrator
changes those.

## The admin console

The console at `/admin` is one application with many pages under Directory,
Protocols, Server configuration and Monitoring. **Every page is translated**:
the navigation, page titles, labels, forms and the explanatory prose each page
writes. Its language chooser sits in the page header, beside the account
menu, and saves the administrator's own `preferredLanguage`
(`POST /admin-api/console/language`). The API explorer at
`/admin/api-explorer` is part of it.

Two kinds of text on a console page stay English for now. The first is error
and refusal text, as everywhere. The second is text the server writes into a
page's data: each setting's description, a policy's rule sentences, and the
explanations some server modules supply.

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

## The demonstration issuer and verifier (development only)

The service draws no sample issuer or verifier page. A sample credential
issuer ("Example University") and a sample verifier ("The Bar Door"), for trying
a wallet against this service, are the development
[companion](docker-compose.md#the-companion-development-only), a separate
container in front of the service. Until #594 the service drew them itself at
`/issuer`, `/issuer/offer`, `/oid4vp/verifier`, `/oid4vp/start` and
`/oid4vp/done`; those paths are gone in every mode.

The companion uses only the service's own doors:

* **Its issuer page** reads the issuer metadata and makes a same-device
  Credential Offer itself (the authorization code grant). A person's
  pre-authorized offer into their own wallet is the portal's
  (`/portal/wallet`, #589).
* **Its verifier page** starts a verification at
  `POST /admin-api/verifications/start`, naming its own completion page as
  the `redirect_uri`, and reads the verdict at
  `GET /admin-api/verifications?state=` (#587).

What a wallet sees is the protocol's and lives in the service: the offer
served by reference (`/oid4vci/credential-offer/{id}`), the request object
(`/oid4vp/request/{id}`), the response endpoint (`/oid4vp/response`), the
Verifier's certificate, the issuer metadata, the credential, nonce, deferred
and notification endpoints, the token endpoint's pre-authorized grant and the
status lists.

## The protocol families' description pages

Six protocol families answer a page at the root of their own path that
says what the family is here: its endpoints, its settings as they are in
force, and what it checks and does not. No specification defines any of
these six paths — each is this service's own documentation, written for a
person — so they are converted (issue #584). The endpoints beneath them are
the protocols' and are not. Issue #584 inventoried them on 2026-10-12,
before turning them into static pages:

| Page | Path | What a person sees | Handler, before #584 | Gate | Answers by request |
|---|---|---|---|---|---|
| SAML 2.0 | `/saml2` | The identity provider's entityID and base; the six endpoints (SSO, artifact resolution, SLO, IdP-initiated SSO, the attribute authority, metadata); how per-service-provider metadata is minted, with two examples; the generic endpoints as absolute URLs | `saml/saml2_sso.ts`, `GET /saml2` (`sendPage()`) | none | HTML only; no JSON form |
| SAML 1.1 | `/saml11` | The two browser profiles and the responder; the three endpoints; four ways SAML 1.1 differs from 2.0; a link to the metadata | `saml/saml11_sso.ts`, `GET /saml11` (`describeProfilePage()`) | none | HTML only; no JSON form |
| XACML 3.0 | `/xacml` | Whether XACML is on; the repository's policy counts and root; every endpoint with the role it requires; how a caller gets in (the client certificate, the two groups, or enforcement off); remote enforcement points and the sync token; the Policy Information Point over HTTP; what is not here yet | `xacml/xacml.ts`, `GET /xacml` (`description()` and an inline page) | a verified client certificate holding XACML_USER (`xacmlAccess()`, before the query is read); 403 otherwise, or 200 to anybody with `xacml.enforceAccess` off | `?format=json` → the description as JSON; `?format=` other than `json`, `xml`, `html` → 400 `STS-XACML-0016`; anything else HTML |
| Shared Signals | `/ssf` | The issuer and whether SSF is on; that SSF is the pipe, not the vocabulary; the metadata URL; every endpoint; the event types and whether each is offered; the signing algorithm; the RFC 9493 subject formats and complex-subject members; the authentication schemes; the streams that exist now; what it does not do; the things that can be made to fail | `ssf/ssf.ts`, `GET /ssf` (`description()` and `pageShell()`) | none | `?format=json` (any case) → the description as JSON; anything else HTML |
| SCIM 2.0 | `/scim` | The base URL and whether SCIM is on; that the endpoints require a credential and what is checked of it, per mode; what `active: false` does; the directory it provisions into and its counts; why the `id` is the DN; every authentication scheme and the access-control policy; the endpoints; what it does not do; the things that can be made to fail; the User mapping | `scim/scim.ts`, `GET /scim` (`description()` and `pageShell()`) | none (not `/scim/v2`) | `?format=json` (any case) → the description as JSON; anything else HTML |
| SPIFFE | `/spiffe` | The trust domain; whether SPIFFE is on and the issuing authority is ready; what is attested and what is not; whether the SPIRE Server API authenticates; the bundle endpoint; the authorities and the trust anchors; the Workload API, SPIRE Server API and Broker API listeners and methods; who may call the SPIRE Server API and SPIRE's per-method table; what is not checked and what is refused; the registry; links elsewhere | `spiffe/spiffe_server.ts`, `GET /spiffe` (`description()` and `page()`) | none | `?format=json` (exactly) → the description as JSON; anything else HTML |

Before #584 every one answered 200, `Cache-Control: no-store`, `text/html`,
drawn by the server under the service's `script-src 'none'`, in English only.

**What is not a page here, and is unchanged by #584**, because a
specification defines it: every SAML 2.0 and SAML 1.1 endpoint — the bare
`GET /saml2/sso`, `GET /saml2/ars`, `GET /saml11/sso` and
`GET /saml11/responder` descriptions included, and the bare `GET /wsfed` —
`/xacml/pdp`, `/xacml/policies`, `/xacml/pep/*`, `POST /xacml/pip`,
`/.well-known/ssf-configuration` and the stream endpoints, `/scim/v2/*`, and
the SPIFFE bundle endpoints.

**Since #584 the six pages are static pages**, drawn in the browser's own
language from the view the page carries, so they need JavaScript; with
scripts blocked they say so. The facts a page shows — the endpoint
descriptions, the lists of what is and is not checked — are each family's
description document and stay in English. Every one answers its
description as JSON to `?format=json` or to an `Accept` that prefers
`application/json`; for SAML 2.0 and SAML 1.1 that form is new. `/xacml`
keeps its gate, over the page, its script and its JSON alike.

## Pages that are not for end users

They are listed so the list above is complete. None is planned for
translation:

- **The embedded protocol debugger**, on its own listener (`debugger.port`). It
  is a separate application from the parent project.
- **Demonstration pages**: the sample credential issuer ("Example University")
  and the sample verifier ("The Bar Door") are the development companion's,
  not the service's — see *The demonstration issuer and verifier* above.
- **Operator and diagnostic views**: the XACML,
  SPIFFE, SCIM, Shared Signals and SAML description pages are translated
  since #584 — see *The protocol families' description pages* above.
- **Error pages**: "This request could not be completed" and every other
  refusal. These are English by design.
