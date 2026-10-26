---
title: The sign-in API
---

# The sign-in API (`/authn-api`)

Since #571 the sign-in screen at `/authn/login` — with the identity-provider
chooser at `/authn/select-idp` and the forced password change at
`/authn/password-change` — is a static page: the browser draws it from
`/authn-api` and sends what was typed there. Its OpenAPI document is
`GET /authn-api/openapi.json`.

## How a sign-in reaches it

A protocol that needs a person signed in sends the browser to
`/authn/login?authn=<id>`. The id names the **pending sign-in**: whoever
holds it may act on that sign-in, so it is a bearer value, like the
`authn_id` the old form carried. The page then asks:

| Operation | What it answers or does |
|---|---|
| `GET /authn-api/pending/{id}` | What the screen offers — the mechanisms the realm's authentication policy accepts, the passkey options, the demands of the request (two factors, a security key), the federation partners, the Kerberos and wallet doors — and `csrf`, the token every act on this sign-in carries. After a classical passkey was refused where a post-quantum one is required, `postQuantumRequired` carries the page's links (`register`, and `upgrade`, which is `/portal/keys?upgrade=post-quantum` when `webauthn.pqcUpgrade` offers the in-place upgrade and empty when it does not) |
| `POST /authn-api/pending/{id}/password` | Sign in with a username and password (or `webauthn_only` for a passkey instead) |
| `POST /authn-api/pending/{id}/passkey/options`, `…/passkey` | A passkey with no username: the challenge, then the ceremony's result |
| `POST /authn-api/pending/{id}/email` | An emailed code or link as the first factor, where the policy allows it |
| `POST /authn-api/pending/{id}/anonymous` | Continue without signing in, where the realm allows it |
| `POST /authn-api/pending/{id}/cancel` | Decline: the application is told `access_denied` |
| `GET /authn-api/pending/{id}/partners` | The partners an application lets a person choose between |
| `GET`, `POST /authn-api/password-change/{id}` | A password that must be changed before the sign-in continues |
| `POST /authn-api/password-change/{id}/start-over` | **Start over**: leave the forced password change without changing anything; answers `next: redirect` to the sign-in screen for the same request |

## The steps after the screen

Since #572 and #573 the second-factor pages (`/authn/totp`,
`/authn/webauthn`, `/authn/backup-code`, `/authn/password-factor`,
`/authn/mfa-setup`) and the emailed code and link pages
(`/authn/email-code`, `/authn/email-link`, `/authn/email-link/open`) are
drawn the same way. A step's id — the `mfa` in the page's address — is a
bearer value like the pending sign-in's.

| Operation | What it answers or does |
|---|---|
| `GET /authn-api/mfa/{id}?page=` | What the step's page shows (`page`: `totp`, `webauthn`, `backup-code`, `password`, `setup`, `email-code`, `email-link`, `email-link-open`) and `csrf`. Refused where the page could never be drawn for the step |
| `POST /authn-api/mfa/{id}/totp` | A one-time code (`code`) |
| `POST /authn-api/mfa/{id}/backup-code` | A recovery code, spent |
| `POST /authn-api/mfa/{id}/password` | A password as the second factor, after a wallet |
| `POST /authn-api/mfa/{id}/webauthn/options`, `…/webauthn` | The passkey ceremony's options, then its result (`credential`). The options take `key` (a chosen passkey), `lane` (`classical` or `pqc`) and, for a registration that failed on the device, `algorithms: "classical"`: the retry with the classical algorithms only, refused (400, `STS-AUTHN-0420`) where a classical passkey is not allowed. A registration's options carry `fallback`: `asksPostQuantum`, `classical` (whether that retry may be offered) and `retrying` |
| `POST /authn-api/mfa/{id}/setup/totp`, `…/setup/confirm`, `…/setup/webauthn` | Setting up a second factor: an authenticator app (its `otpauth:` URI is in the view; the first `code` confirms it) or a passkey |
| `POST /authn-api/mfa/{id}/skip` | Ignore an offered second factor, where it was offered rather than required |
| `POST /authn-api/mfa/{id}/email/send` | Mail a code or link (`kind`); answers `next: stay` |
| `POST /authn-api/mfa/{id}/email/code` | An emailed code |
| `POST /authn-api/mfa/{id}/email-link/open` | The mailed link's token (`t`), only in the browser that asked for it |
| `POST /authn-api/mfa/{id}/start-over` | **Start over**, on every step's page: the step ends with whatever it held (a mailed code, a link, an enrolment in progress), no session is started, and the pending sign-in is put back, so the answer is `next: redirect` to the sign-in screen for the same request. A step that has already ended is refused (400) |

A wrong code, a passkey that does not verify or a rate limit is shown on the
step's own page, and the step is kept. When the account cannot be signed in
at the end of a step, the answer is `refused` with `location` naming the
sign-in screen, which shows why. An emailed factor's refusal that ends the
sign-in also carries `end`, with the page's title.

## The consent screen

Since #576 the OAuth consent screen (`/oauth2/consent`) is a page of the
same kind. The authorization endpoint still sends a signed-in person to
`/oauth2/consent?consent=<id>` when a request asks for a scope they have
not agreed to; that address answers the page (or a 400, as before, when
nothing is waiting under the id or the browser is signed in as somebody
else), and the page is drawn from, and answered to, these. The id is a
bearer value like the pending sign-in's, and both operations answer only
the browser whose session is the person who was asked.

| Operation | What it answers or does |
|---|---|
| `GET /authn-api/consent/{id}` | What the screen asks: the application (its name and `client_id`), each scope and the permission it names, each [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) authorization detail member by member, the limits a detail carries, what was already agreed, the request's own parameters — and `csrf` |
| `POST /authn-api/consent/{id}` | `action`: `allow` or `deny`. With `allow`, a detail's limits may be lowered (never raised) under the names the page draws, `lim_t0r<n>_<member>`. Answers `next: redirect` with the authorization request to go back to, which then issues, or answers the application `access_denied` |

A raised limit is `refused`, and the screen can be answered again.

## What every act needs

Each `POST` is sent by a page of this service, and the API checks it:

- `Content-Type: application/json`;
- an `Origin` header naming this service;
- `X-CSRF-Token`: the `csrf` the view answered, which is bound to the
  browser's `sts_session` cookie. The sign-in page sets that cookie when a
  browser arrives without one.

## What an act answers

The answer names the next step; the page follows it.

| `next` | Meaning |
|---|---|
| `redirect` | Go to `location` with a GET — back to the application's request. When the sign-in completed, the `sts_session` cookie is set on this answer. |
| `mfa` | A second factor, or setting one up, on the page at `location` (`step` says which: `totp`, `webauthn`, `enrol`, `email-code`, `email-link`). |
| `password-change` | The password must be changed first, at `location`. |
| `home-cell` | The account is held in another region: send `form` (its method, address and fields) as it is. |
| `refused` | `errors` says why, in English. The page shows it and the sign-in can be tried again. |

Refusals never carry an error code; the service records the code in its
audit log. Sign-in attempts are rate limited exactly as they were, and a
rate-limited attempt answers `429`.
