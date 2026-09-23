---
title: Accepted tokens
nav_order: 16
---

# Accepted tokens

Every door on this service that takes a token from a caller, what it must be to
get through, and what happens in each mode. It is a companion to
[What is not checked](what-is-not-checked.md), which covers passwords,
assertions, certificates and everything else. This page covers the one question
that page used to answer badly: **will a token this service did not issue get
through?**

The short answer is **no, except at the three OpenID4VCI endpoints in
development mode.** Until 2026-09-18 the documentation said "except at
UserInfo". That meant UserInfo was the one door that *refused* a foreign token,
and it read as though UserInfo were the one door that accepted one. Neither is
true now: every door below verifies.

"Verifies" here means the signature verifies against the realm's own signing
key (the one published at `/oauth2/jwks`, or the realm's own under
`/realm/{id}/`), the token is inside its `exp` and `nbf`, and — unless the row
says otherwise — its `jti` has not been revoked on `/admin/tokens`. Every
token this service signs is signed with the same key, so a door that needs an
*access* token also reads `typ` to tell one from an ID Token or a refresh
token. An access token also meets RFC 9068 section 4 wherever it is presented:
an `at+jwt` header, an issuer this service publishes at the address the request
arrived on, and this resource server in `aud`.

This list was made by reading the code on 2026-09-21. It is not generated, and a
door added after that date is not on it. The live list of endpoints is
[`/admin/sts-metadata`](endpoints.md).

## Access tokens at a resource

| Door | Must be | Development | Product |
|---|---|---|---|
| `GET`/`POST /oauth2/userinfo` | Verified, `typ` `Bearer`, not revoked, carrying `openid` | The same | The same |
| `/scim/v2` (Bearer or DPoP) | Verified, `typ` `Bearer`, not revoked, carrying `scim:read` or `scim:write`. SCIM's other five credential schemes are separate | The same | The same |
| The Shared Signals endpoints | Verified, `typ` `Bearer`, carrying `ssf:read` or `ssf:write` | The same | The same |
| The step-up resource (RFC 9470) | Verified, then assessed against `oauth2.stepUpAcrValues` and `max_age` | The same | The same |
| `/admin-api` | Verified against the default realm's key, or the ambient realm's under a realm prefix, audienced to the API, carrying `admin:read` or `admin:write`. A realm's token is confined to that realm | The same | The same |
| The embedded debugger's listener | Verified, audienced to `urn:sts:debugger-api:`, carrying the debugger permission, which only a console administrator is issued | The same | The same |
| The OpenID4VCI credential, deferred credential and notification endpoints | A token this realm issued is verified like any other | **A token this realm cannot verify is read without verifying**, because OpenID4VCI lets the authorization server be somebody else. A credential issued that way can never be used to sign in | Refused, and so is a revoked one (`invalid_token`) |
| The GNAP resource server (`/gnap/rs/*`) | A token the GNAP authorization server holds a record of and has not revoked or expired, under the scheme its binding needs (`Bearer` for a bearer token, `GNAP` with a key proof otherwise). Nothing is decoded | The same | The same |

Any of the OAuth rows above that is presented with the DPoP scheme also needs
a proof that verifies against the token's `cnf.jkt`, and a certificate-bound
token needs the certificate on the connection (RFC 8705). Four settings make
one of the two mandatory; see *Require DPoP or mutual TLS* in
[What is not checked](what-is-not-checked.md).

## Tokens handed to the authorization server

| Door | Token | Development | Product |
|---|---|---|---|
| `POST /oauth2/introspect` | `token` | A token that does not verify, or was revoked, is `{"active": false}`. The caller authenticates for an RFC 9701 JWT response | The same, and the caller authenticates for a JSON response too |
| `POST /oauth2/revoke` | `token` | Revoked if it verifies; otherwise nothing is revoked and the answer is still 200, as RFC 7009 says. The caller is not authenticated | The same |
| `POST /oauth2/token`, `grant_type=refresh_token` | `refresh_token` | Opened, verified, not revoked. Whether it was issued to the client presenting it, and whether the scope asked for is no wider than the one granted, is checked only in RFC 9700 or OAuth 2.1 mode | Product implies RFC 9700 mode, so both are checked, and a refresh token presented twice revokes its whole family |
| `POST /oauth2/token`, token exchange (RFC 8693) | `subject_token`, `actor_token` | **Read without verifying** if they do not verify, so a client under test can exchange a token from anywhere | Verified and not revoked, or refused with `invalid_request`. **The token's `typ` is not compared with the declared `subject_token_type`** — [#116](https://github.com/rcbj/iya-sts/issues/116) |
| `POST /oauth2/token`, JWT or SAML bearer grant; JWT client authentication | `assertion`, `client_assertion` | Verified against a key registered for a declared issuer, accepted once ever. See [JWT assertions](jwt-assertions.md) and [SAML 2.0 assertions](saml-assertions.md) | The same |
| `GET`/`PUT`/`DELETE /oauth2/register/{client_id}` (RFC 7592) | The registration access token | Compared with the one issued at registration, in constant time; an empty one never matches | The same |
| `GET`/`POST /oauth2/logout` (RP-Initiated Logout) | `id_token_hint` | Verified as an ID Token this authorization server issued (an expired one still counts); its audience is the client, and a `client_id` it was not issued to is refused. A hint for the current session signs out at once; otherwise the person confirms (#124, #115) | The same |

## Other tokens

| Door | Token | Development | Product |
|---|---|---|---|
| SPIFFE `ValidateJWTSVID` | A JWT-SVID | Verified against the bundle of the trust domain its `sub` names, with the audience the caller gives and no clock leeway. A trust domain with no bundle is refused | The same |
| `POST /ssf/receive` | A Security Event Token | **Recorded whether or not it verifies**, and shown as unverified. Nothing acts on it | The same unless `ssf.receiveRequireSignature` is on — [#117](https://github.com/rcbj/iya-sts/issues/117) |
| The console's and portal's own SSF receivers | A Security Event Token | The stream's own authorization secret, and this receiver in `aud`. An unverified one is recorded unless `ssf.receiveRequireSignature` is on. Nothing acts on it | The same |

## Where the two open issues are

| Issue | What |
|---|---|
| [#116](https://github.com/rcbj/iya-sts/issues/116) | Token exchange in product mode accepts an ID Token as a `subject_token` declared to be an access token |
| [#117](https://github.com/rcbj/iya-sts/issues/117) | `/ssf/receive` stores Security Event Tokens it cannot verify in product mode as well as development |
