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
| `GET /authn-api/pending/{id}` | What the screen offers — the mechanisms the realm's authentication policy accepts, the passkey options, the demands of the request (two factors, a security key), the federation partners, the Kerberos and wallet doors — and `csrf`, the token every act on this sign-in carries |
| `POST /authn-api/pending/{id}/password` | Sign in with a username and password (or `webauthn_only` for a passkey instead) |
| `POST /authn-api/pending/{id}/passkey/options`, `…/passkey` | A passkey with no username: the challenge, then the ceremony's result |
| `POST /authn-api/pending/{id}/email` | An emailed code or link as the first factor, where the policy allows it |
| `POST /authn-api/pending/{id}/anonymous` | Continue without signing in, where the realm allows it |
| `POST /authn-api/pending/{id}/cancel` | Decline: the application is told `access_denied` |
| `GET /authn-api/pending/{id}/partners` | The partners an application lets a person choose between |
| `GET`, `POST /authn-api/password-change/{id}` | A password that must be changed before the sign-in continues |

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
| `POST /authn-api/mfa/{id}/webauthn/options`, `…/webauthn` | The passkey ceremony's options, then its result (`credential`) |
| `POST /authn-api/mfa/{id}/setup/totp`, `…/setup/confirm`, `…/setup/webauthn` | Setting up a second factor: an authenticator app (its `otpauth:` URI is in the view; the first `code` confirms it) or a passkey |
| `POST /authn-api/mfa/{id}/skip` | Ignore an offered second factor, where it was offered rather than required |
| `POST /authn-api/mfa/{id}/email/send` | Mail a code or link (`kind`); answers `next: stay` |
| `POST /authn-api/mfa/{id}/email/code` | An emailed code |
| `POST /authn-api/mfa/{id}/email-link/open` | The mailed link's token (`t`), only in the browser that asked for it |

A wrong code, a passkey that does not verify or a rate limit is shown on the
step's own page, and the step is kept. When the account cannot be signed in
at the end of a step, the answer is `refused` with `location` naming the
sign-in screen, which shows why. An emailed factor's refusal that ends the
sign-in also carries `end`, with the page's title.

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
