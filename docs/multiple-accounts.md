---
title: Several accounts in one browser
nav_order: 10
---

# Several signed-in accounts in one browser

By default a browser holds **one** sign-on session here (see
[Sessions](sessions.md)): signing in as somebody else ends the session the
browser had. With `authn.multipleAccounts` on, one browser may stay signed in
as **several people at once** — a person with a work account and an
administrator account, a support desk trying two test users side by side — and
choose between them as it goes.

The setting is **off by default in both modes**. Off, nothing on this page
exists: no extra cookie, no account picker, no new prompt, and every protocol
answers exactly as it does without it.

## Turning it on

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `authn.multipleAccounts` | `STS_AUTHN_MULTIPLE_ACCOUNTS` | `false` | yes — at the next request | One browser may hold sign-on sessions for several people; a request that does not say which one it is for, while more than one is signed in, is sent to the account picker. |
| `authn.maxBrowserAccounts` | `STS_AUTHN_MAX_BROWSER_ACCOUNTS` | `10` | yes | The most accounts one browser keeps, signed in and signed out together (1–50). |
| `authn.rememberedAccountDays` | `STS_AUTHN_REMEMBERED_ACCOUNT_DAYS` | `30` | yes | How long a browser keeps offering an account that signed out there (1–365). |

All three are **per trust realm**: set them on the realm's *Web security*
settings in the console, or with `POST /admin-api/config/set` under the realm's
prefix. This table is a copy of rows in `common/config.js`; the live source is
the console page and `GET /admin-api/config` ([Configuration](configuration.md)).

**Turning it on ends nothing.** A browser that was already signed in keeps its
session, which becomes the first account of its list the next time it is
needed. **Turning it off ends nothing either**: the browser's current account
carries on alone, and the others run out on their own clocks or are signed out
at `/logout`.

## What a person sees

**Signing in as somebody else adds an account** rather than replacing the one
the browser had. Each account keeps its own session with its own lifetime,
idle timeout, second factors and sign-out; nothing about one account's session
is shared with another's. Signing in again as a person who is already signed in
in that browser re-authenticates their session — one live session per person
per browser.

**The account picker**, `/authn/accounts`, appears when an application asks for
a sign-in without saying who for and the browser holds more than one signed-in
account. It lists:

* the accounts signed in to this browser — choosing one carries on as that
  person, without typing anything;
* the accounts that **signed out** here recently, with their names filled in —
  choosing one goes to the sign-in screen for that person;
* **Use another account**, which goes to the sign-in screen with nothing
  filled in;
* **Forget** beside a signed-out account, which removes it from the list. A
  signed-in account cannot be forgotten; sign it out first.

The picker never shows a session identifier or a token, and what it remembers
about a signed-out account — the username, the display name and the subject —
is kept on the server, never a credential.

**Every page of this service** (the front door, the sign-out page, the
description pages, the federation pages and the others) shows, beside the
language chooser, which accounts are signed in and a **Sign in with another
account** link. That link goes to the user portal, which starts a fresh
sign-in.

**The user portal and the admin console keep one account per browser tab.** A
tab remembers which account it is for, so two tabs can show two different
people side by side, and a reload keeps each tab's account. Signing out from a
tab asks about that tab's account. The device sign-in page, `/portal/device`,
says which account an approval will sign the device in as whenever more than
one is signed in.

### Switch user, in the console and the portal

Both have **Switch user** in their account menu (the console's under your
name, the portal's beside Sign out):

* **each other account signed in to this browser** — choosing one signs this
  tab in as that person with nothing typed, and draws the page again for
  them;
* **Sign in with another account** — a fresh sign-in (`prompt=login`) that
  adds an account to the browser, and this tab becomes it;
* a line saying **the account this tab leaves stays signed in**, so switching
  back is a press in the same menu, never a password. With no other account
  signed in yet the menu says so.

A switch abandons what the tab was doing (it asks first where a form has
unsaved changes), and changes only this tab. The account switched to gets what
its own session and roles give it and nothing the previous account had. In the
console, a person holding no console role sees the console's usual answer for
them; an account the console refuses outright gets a page that says so, with
the same Switch user list and Sign out. Switching is a different act from the
console's *Sign in again* window, which appears when a session ends: that
window signs the tab's own account in again, and refuses a different person
rather than switching to them.

With `authn.multipleAccounts` off, the menus have no Switch user: signing in
as somebody else there ends the browser's session, so there would be nobody
to switch back to.

## How each protocol behaves

A request can **say which account it is for**; where it does, that account is
answered silently, as single sign-on always was. Where it does not and only one
account is signed in, that one is answered. Where it does not and several are,
the person chooses at the picker. **A hint that names nobody signed in to this
browser never falls back to another account**: the sign-in screen is drawn with
the name filled in.

| Protocol | What names an account | What else changes |
|---|---|---|
| OpenID Connect and OAuth 2.0 | `login_hint`; the `sub` and `sid` of a verified `id_token_hint` | `prompt=select_account` always shows the picker; `prompt=login` is a fresh sign-in and never the picker; `prompt=none` with several accounts and nothing naming one is answered **`account_selection_required`** (OpenID Connect Core section 3.1.2.6). `max_age` and requested `acr` values are asked of the chosen account's session as of any session. |
| SAML 2.0 Web Browser SSO | the AuthnRequest's `<saml:Subject>` NameID (a username or e-mail address); a `transient` NameID names nobody | `ForceAuthn` is a fresh sign-in, never the picker; `IsPassive` with a choice to make is answered with the status **`NoPassive`**, because the picker is user interface. |
| SAML 1.1 browser profiles | nothing — the profile has no way to name a person | the picker, where there is a choice. |
| WS-Federation | nothing — `whr` names a home realm, not a person | the picker, where there is a choice; `wfresh` is a fresh sign-in. |
| GNAP | the grant request's `user` | otherwise the picker on the interaction page. |
| Federation (signing in through a partner) | — | the account the partner signs in is added, and the flow continues as it. |
| Kerberos (SPNEGO), wallet and certificate sign-in | the credential itself | the account whose credential it is is added, or re-authenticated where it is already signed in. |
| OpenID Connect Session Management | — | the OP iframe answers `unchanged` for every account still signed in, and `changed` only to the relying parties of an account that left. |

## Signing out

[Signing out](signing-out.md) describes the sign-outs themselves. With several
accounts signed in:

* **`/logout` asks which account first** — one of them, or every account in
  this browser — and then shows that person's sign-out page as it always does.
  A `login_hint` preselects an account (the console and the portal pass the
  tab's own). The JSON form of `/logout` answers `409` with
  `account_choice_required` and the accounts, by key, rather than guessing.
* **Every account in this browser** signs each person out as their own
  sign-out would, one after another.
* **RP-Initiated Logout** with an `id_token_hint` ends the session that token's
  `sid` names, where that session is signed in to this browser; with no hint
  that chooses, the confirmation page asks which account.
* **SAML 2.0 Single Logout** ends the session its `SessionIndex` names.
* **WS-Federation**: `wsignout1.0` asks which account where more than one
  signed in to that relying party; `wsignoutcleanup1.0`, which arrives as an
  image and cannot ask, ends every session in the browser that signed in to it.
* **The other accounts stay signed in.** Signing one account out moves it to
  the browser's signed-out list; where it was the browser's current account,
  the most recently added remaining account becomes the current one.

## Limits

* **One browser, one realm.** The list belongs to one browser in one trust
  realm; each realm keeps its own, and nothing is shared between browsers or
  devices.
* **`authn.maxBrowserAccounts`** bounds the list. Past it the account that
  signed out longest ago is dropped; when every place is held by a signed-in
  account, a further sign-in is refused (`STS-AUTHN-0340`) until one is signed
  out.
* **Signed-out accounts are forgotten** after `authn.rememberedAccountDays`, by
  the scheduler job `authn.account-set-expiry`, or at once with Forget.
* **A request that cannot show the picker cannot choose.** `prompt=none` and
  SAML `IsPassive` are answered with their protocol's "a choice is needed"
  error; send a hint, or retry without them. Neither answer says how many
  accounts the browser holds.
* **Every choice at the picker renews the `sts_accounts` cookie**, so a copy
  of it taken earlier opens nothing. A choice made in a second tab before the
  first tab's answer arrived is refused, and that tab's picker asks again.
* **When the list cannot be read** (the session store is unavailable), the
  picker answers `503` with `Retry-After` instead of drawing a partial list or
  sending the person to sign in again; try again once the store is back.
* **Choosing an account never gets past what the application asked for.** A
  demand for a second factor that the chosen account's session does not meet
  sends the person to sign in again as that account.
* **The picker and the account menus need script**, as every page of this
  service does.

## In the running service

* `GET /authn-api/accounts` answers the accounts this browser holds — key,
  names, whether each is signed in or out — and never a session identifier or
  a token. Its operations are in the sign-in API's OpenAPI document
  (`/authn-api/openapi.json`, [The sign-in API](authn-api.md)).
* The audit log records `account.add`, `account.select`, `account.switch`,
  `account.forget` and `account.ambiguous`, each with the account set and the
  session it concerns.
* `/admin/sessions` lists every sign-on session as before; each account's
  session is a row of its own.

## Related

[Sessions](sessions.md) · [Signing out](signing-out.md) ·
[Trust realms](trust-realms.md) · [User-facing pages](user-facing-pages.md) ·
[Configuration](configuration.md) · [Error codes](error-codes.md)
