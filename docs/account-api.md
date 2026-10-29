---
title: Account API
---

# Account API

`/account-api` is the API behind the [user portal](user-facing-pages.md#the-user-portal).
Since #568 the portal at `/portal` is a static application: the page you load
is a script that signs you in and then draws every page from an
`/account-api` answer. Every form on it is sent here too. Whatever a person
can see or change about their own account in the portal, they can do through
this API.

It works per [trust realm](trust-realms.md). In the realm `acme` it is
`/realm/acme/account-api`, and it answers only to tokens issued by that
realm's authorization server.

## The person is always the token's subject

No operation takes a username, an id or a DN that says whose account to act
on. The account is the one whose access token was presented, and nothing in
the request can change that. This is the portal's own rule (OWASP A01,
broken access control), now enforced at the API.

The exceptions are the operations behind links that a person is mailed: an
account activation, a password reset, an address verification and the
forgotten-password form. Nobody is signed in when those are used, so they
take no token. Their authority is the single-use secret in the link they
carry. In the OpenAPI document they are marked `x-access: link` (or
`public` for the forgotten-password form, which spends nothing).

## Getting a token

The portal signs in as the seeded public client **`sts-user-portal`**, in
every realm, using:

- the authorization code flow with PKCE (`S256`);
- `scope=openid account:manage`;
- `resource` set to the realm's `/account-api` URL ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707));
- a **DPoP** proof ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) on
  the token request.

The client holds no secret. Every token issued to it is DPoP-bound, and the
token endpoint refuses that client a request without a proof. Send the token
as `Authorization: DPoP <token>`, with a `DPoP` header carrying `ath` on
every call.

A call is refused (`401`, or `403` where noted) when the token:

- was issued by another realm, or by another issuer or audience (`403`);
- has expired or been revoked;
- belongs to a disabled account;
- was issued on a sign-on session that has since ended (a sign-out, or the
  session running out);
- is presented without its proof, or as a Bearer token;
- does not carry `account:manage` (`403`);
- was issued to a client that no longer declares that scope (`403`).

The access policy is then asked, as it was for the portal's pages:
resource `user-portal`, action `read` for a GET and `manage-own` for
anything else, with the owner being the subject.

`account:manage` is a protected scope. A client gets it only if its
application entry declares it in `oauthAllowedScope`, and only
`sts-user-portal` declares it out of the box. To let a native application
manage a person's own account, declare the scope on that application. It
then signs the person in the same way.

The API itself is represented in every realm by the application
**`sts-account-api`**, which holds the audience a token for it names. It is an
OAuth 2.0 resource and never a client: its client_id is refused at the
authorization and token endpoints (`STS-OAUTH-0985`). The seeded machine
client `sts-api-client` does not call this API, because every operation acts
on a signed-in person and a client-credentials token has none.

## The document

The OpenAPI 3.1 document is built from the same table that registers the
routes. Read it rather than any list here:

- `GET /account-api/openapi.json`. It is public: it describes the API and
  carries no secret.
- **Admin console → Account API** (`/admin/account-api`), which draws the
  same document by tag: each operation, the portal page or form it backs,
  who may call it, its parameters and its request body. The console page
  calls nothing, because every operation acts on the signed-in person's own
  account.
- `GET /admin-api/account-api` returns the same document to a management API
  token.

`GET /account-api` is the index: each operation's method and path, its access
(`person`, `link` or `public`), and `mirrors`, the portal page or form it is
the door of (`GET /portal/keys`, `POST /portal/keys`).

## What an answer looks like

A page's GET operation answers that page's view as JSON. A POST answers one
of the following:

| Answer | Meaning |
|---|---|
| `{ "ok": true, "message": "…" }` | Done. The message is in the person's language. |
| `{ "ok": true, "view": { … } }` | Done, and here is something to show once: a generated secret, recovery codes, a private key. It is shown on the page and never put in a URL. |
| `{ "ok": true, "go": "/portal/…" }` | Done; the portal moves to that page. |
| `{ "ok": false, "errors": ["…"] }` | Refused, with a 4xx status. A `view` may come with it. |
| `{ "ok": false, "stepUp": { "acrValues": "…" } }` | Sign in again, more strongly, then retry (CIBA and GNAP approvals). |
| `{ "ok": true, "location": "https://…" }` | Continue at another site (linking a claim source). |

Request bodies are JSON (`Content-Type: application/json`) and are checked
against the operation's schema before anything is done. Error text is in
English, as everywhere in this service, and every refusal is recorded under
an [error code](error-codes.md) (the `ACCOUNT` subsystem for the gate).

## In a cluster of cells

A request is answered at the person's home cell. It is relayed there when it
arrives elsewhere: the token's person for a signed-in call, or the person a
link names.

## Related

- [User-facing pages](user-facing-pages.md): the portal's pages.
- [Management API](management-api.md): the administrator's API, `/admin-api`.
- [Signing out](signing-out.md): the portal's Sign out ends the sign-on
  session, and with it every token issued on it.
