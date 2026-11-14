---
title: "Using the OAuth2 / OIDC workflow"
nav_order: 10
---

# Using the OAuth2 / OIDC workflow

> Copied from the [id-proto-debugger](https://github.com/rcbj/id-proto-debugger) release 0.9.3 user guide, which is the debugger this service embeds. Its addresses are the embedded ones: the debugger is `https://localhost:8444/` and its api `https://localhost:8444/api`. [Accessing the debugger](../access.md) says how to reach, enable and disable it.

The OAuth2 / OIDC workflow lets you run every OAuth 2.0 authorization grant
and every OpenID Connect authentication flow against a real authorization
server, one step at a time. At each step you see the request before it is sent
and the response after it comes back.

These pages show how to use it:

* **[OAuth 2.0 authorization grants](oauth2-grants.md)**: Authorization Code
  (with and without PKCE), Implicit, Resource Owner Password Credentials,
  Client Credentials, Device Authorization, Refresh Token, and Token Exchange.
* **[OpenID Connect authentication flows](oidc-flows.md)**: the Authorization
  Code flow, both Implicit flows, all three Hybrid flows, and DPoP-bound
  tokens.
* **[Dynamic client registration](dynamic-client-registration.md)**: the
  registration pane on step 1.
* **[Token detail, introspection, UserInfo, and JWKS](related-tools.md)**:
  the pages step 2 opens for a token you already hold, and the logout
  status page.

This page covers the parts every grant and flow have in common. Read it first.

**The screenshots come from the test suite.** Each one was taken by the
Selenium job that drives that grant or flow (see
[Regenerating the screenshots](#regenerating-the-screenshots)). The
authorization server in them is iya-sts
([`rcbj/iya-sts`](../../index.md)), running at
`https://localhost:8081`. It is the same server the test suite uses, and it
signs anybody in with any password except the literal `invalid`, so you can
repeat every step here and still reach a refusal.
To follow along against your own identity provider, use its discovery URL,
client IDs and secrets in place of the ones shown.

* TOC
{:toc}

## Before you start

### Start the debugger

Open `https://localhost:8444/` and sign in as a console administrator
([Accessing the debugger](../access.md)), then pick the **OAuth2 / OIDC**
card.

### Register a client at your identity provider

The debugger is a **client**. Your identity provider must know about it first.
Register a client with:

| Setting | Value |
|---|---|
| Redirect URI | `https://localhost:8444/callback` (or your debugger's address + `/callback`) |
| Grant types / response types | the ones you plan to test |
| Client type | *public* (no secret) for browser-style tests, *confidential* (with a secret) for server-style tests |
| Web origins / CORS | the debugger's origin, if token requests will be sent from the browser |

For iya-sts, see
[Configuring OAuth 2.0 grants](../../configure-oauth2-grants.md)
and
[Configuring OpenID Connect flows](../../configure-oidc-flows.md).
In development mode it accepts a client it has never seen. The Device
Authorization grant is the exception: that client must be registered first.

## How the workflow is laid out

The workflow is two pages.

| Page | What you do there |
|---|---|
| **Step 1** (`oauth2_oidc_1.html`) | Load the provider's metadata, choose a grant or flow, and send the **authorization request** (or the device authorization request). |
| **Step 2** (`oauth2_oidc_2.html`) | See what the authorization endpoint returned, send the **token request**, and work with the tokens: refresh, introspect, revoke, exchange, call UserInfo, or log out. |

Grants that have no authorization request (Client Credentials and Resource
Owner Password Credentials) take you straight to step 2 when you choose them.

Every section of both pages is a pane you can collapse or expand by clicking
its title. The pages remember which panes you had open.

## Step 1: load the provider's metadata

Every grant and flow starts the same way. In **Metadata Retrieval**:

1. Choose the **Metadata Source**:
   * **OIDC Discovery 1.0** for a URL ending in
     `/.well-known/openid-configuration`.
   * **OAuth 2.0 Authorization Server Metadata (RFC 8414)** for a URL ending
     in `/.well-known/oauth-authorization-server`.
2. Enter the **Metadata Endpoint URL**, for example
   `https://localhost:8081/.well-known/openid-configuration`.
3. Click **Retrieve**. The document is shown as a table, one row per member.
4. Click **Populate Meta Data** below the table. This copies the endpoints
   and the advertised capabilities into the Configuration Parameters pane.

**Populate never sends every advertised scope.** `scopes_supported` stays
in the metadata table for you to pick from. The authorization request's
**Scope** starts as `openid profile email`, limited to what the provider
advertises, for an OIDC flow, and empty for an OAuth 2.0 grant. On step 2
the token request's scope is empty for a code exchange and a refresh
(RFC 6749 sections 4.1.3 and 6). Resource-owner password starts from the
authorization scope, or `openid profile email` when that is empty. Client
credentials starts from the authorization scope without `openid`,
`profile`, `email`, `address`, `phone` and `offline_access`, which are
about a user that grant does not have, and sends no scope when nothing is
left. Once you type into a token or refresh scope field, that value is
kept across reloads, even when it matches the default. Pressing
**Populate Meta Data** again resets both fields to the default.

![Metadata Retrieval pane after Retrieve, showing the provider's discovery document as a table](images/oauth2-authorization-code-01-metadata.png)

If you have no metadata document, skip this step and type the endpoints into
the Configuration Parameters pane yourself.

## Step 1: check the configuration

The **Configuration Parameters** pane holds the settings shared by every
request:

![Configuration Parameters pane with the Authorization Grant selector, the endpoints filled in from discovery, and the switches at the bottom](images/oauth2-authorization-code-02-configuration.png)

| Field | What it does |
|---|---|
| **RFC 9700 compliance mode** | Makes the debugger refuse to send anything the OAuth 2.0 Security Best Current Practice forbids. Off by default, so you can test providers that do not comply. See [RFC 9700 compliance mode](https://github.com/rcbj/id-proto-debugger/blob/0.9.3/docs/rfc9700.md). |
| **Authorization Grant** | Chooses the grant or flow. The rest of both pages changes to match it. |
| **Endpoints** | Authorization, token, introspection, revocation, registration, UserInfo and JWKS. Filled in by **Populate Meta Data**. |
| **Device Authorization Endpoint** | The RFC 8628 endpoint. The row stays hidden until discovery advertises `device_authorization_endpoint`, or until a value saved earlier is restored. **Populate Meta Data** fills it and shows the row. |
| **Provider metadata** | The rest of the discovery document, for reference. |
| **Display OIDC Related Artifacts?** | Shows or hides the ID token, nonce and UserInfo controls. |
| **SSL Certificate Validation** | Set to **No** when the provider uses a self-signed certificate and token requests go through the back end. |
| **Use Refresh Token** | Shows the refresh pane on step 2. |
| **Use PKCE** | Adds a PKCE `code_challenge` (RFC 7636) to the authorization request and the `code_verifier` to the token request. |

## Step 2: send the token request

Each grant has a token request pane on step 2. Its title depends on the grant,
for example *Exchange Authorization Code for Access Token*. These fields work
the same way in every grant:

| Field | What it does |
|---|---|
| **Client ID / Client Secret** | The client's credentials. Leave the secret empty for a public client. |
| **Auth Style** | **POST** sends `client_id` and `client_secret` in the form body (`client_secret_post`). **Header** sends them as HTTP Basic authentication (`client_secret_basic`). |
| **Initiate Token Endpoint Call From front or backend** | See [Front end or back end](#front-end-or-back-end). |
| **DPoP (RFC 9449)** | Binds the access token to a key held by the page. See [DPoP](oidc-flows.md#sender-constrained-tokens-with-dpop). |
| **Add Resource field?** | Adds an RFC 8707 `resource` parameter. |
| **Custom query parameters** | Adds parameters the provider needs that the form does not have a field for. |
| **Request** | The exact request that **Get Token** will send. It updates as you type. |

Every pane that sends a request has two tabs. **Parameters** is the form.
**HTTP** shows the request and response exactly as they were exchanged, with
headers and timing, once the call has been made. The tab title shows the
status code, for example **HTTP · 200**.

### Front end or back end

A token request can be sent two ways:

* **Front**: the browser calls the token endpoint directly. The provider must
  allow the debugger's origin with CORS, or the browser blocks the call. When
  that happens the result shows `status: 0`, which means the request never
  reached the provider; it does not mean the provider refused it. A DPoP proof
  can only be sent this way.
* **Back**: the debugger's API service (`https://localhost:8444/api`) sends the
  request from the server, so CORS does not apply. Use this when the provider
  does not allow the debugger's origin. The deployed static sites have no API
  service, so this option is disabled there.

## Step 2: read the results

Results appear in panes below the token request:

| Pane | What it shows |
|---|---|
| **Authorization Endpoint Results** | Tokens that came back on the redirect from the authorization endpoint. Only the Implicit and Hybrid flows return tokens there. |
| **Token Endpoint Results** | The most recent tokens from the token endpoint. |
| **Token Endpoint Results for Refresh Token Call** | The tokens from the most recent refresh, shown beside the originals so you can compare them. |
| **Token History** | Every set of tokens this page has obtained. Click one to show it in **Currently Viewing**. |

Each token comes with buttons and links:

* **The token's name** (for example *Access Token*) opens the
  [token detail page](related-tools.md#token-detail). It decodes the JWT,
  explains each claim using the IANA registry, and lets you verify the
  signature with a shared secret, a certificate, or the provider's JWKS.
  JWKS verification is by `kid` and is not limited to RSA.
* **Introspect Token** sends it to the introspection endpoint (RFC 7662).
* **Get UserInfo Data** calls the UserInfo endpoint with the access token.
* **Revoke Token** sends it to the revocation endpoint (RFC 7009).
* **Copy Token** copies an access token as RFC 6750 credentials
  (`Bearer <token>`, or `DPoP <token>` when that response's token type
  is DPoP). That is the Authorization header value from RFC 6750
  section 2.1. RFC 9700 section 4.3.2 forbids putting the token in a
  query string. A refresh token and an ID token are copied unchanged.
  The textarea still shows the raw token, which is what a field on
  another page stores. Those fields also accept the credentials form.

## After the flow

Further down step 2 are panes that work with the tokens you now hold:

* **RP-initiated Logout**: ends the session at the provider (OpenID Connect
  RP-Initiated Logout 1.0).
* **Token Revocation (RFC 7009)**: revokes any token you paste in.
* **Token Exchange (RFC 8693)**: exchanges a token for a different one. See
  [Token Exchange](oauth2-grants.md#token-exchange-rfc-8693).

## What the debugger remembers

Everything you type is saved in the browser's `localStorage`, so the forms are
filled in again next time, with two exceptions:

* **Client secrets and passwords are never saved**, in any storage. That
  includes the Client Secret fields on step 2 (token request, refresh,
  revocation, token exchange), the resource-owner password, the
  introspection and UserInfo client secrets, the HMAC key on the token
  detail page, and a `client_secret` a dynamic registration issues. A
  secret typed on a page is used for that page load only. After the
  identity provider redirects you back to step 2, or after you return from
  a token detail page, type the secret again.
* **Bearer tokens that are inputs**, the registration access token, the
  initial access token and the introspection page's bearer token, are kept
  in `sessionStorage`: they survive the redirect in the same tab and are
  gone when the tab closes.

Copies an older version saved are removed when the pages load. To start
over, click
**Clear Storage** in the Metadata Retrieval pane or clear the site data for
the debugger in your browser.

## Regenerating the screenshots

The screenshots are taken by the debugger project's own Selenium jobs, against
the standalone debugger and this service, so the address bar in them shows
`https://localhost:3000` where the embedded debugger is
`https://localhost:8444`. How to retake them is in that project's
[guide](https://github.com/rcbj/id-proto-debugger/blob/0.9.3/docs/oauth2-oidc/index.md#regenerating-the-screenshots).
