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
