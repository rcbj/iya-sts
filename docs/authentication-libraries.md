---
title: Authentication libraries
nav_order: 21
---

# Authentication libraries

These libraries are the relying party's side of a protocol iya-sts
implements, packaged so an application can sign people in without writing
the protocol itself. They are the start of a set of client libraries for
integrating applications with iya-sts. Each one listed here has been run
against iya-sts and is written to its specification, so it also works with
other providers that implement the same specification.

**Libraries for other languages will be added as they are published.** The
first section is Node.js.

How a library is called is in that library's own documentation. How
iya-sts behaves as the provider is on the protocol page for that family:
[OAuth 2.0 and OpenID Connect](oauth-oidc.md),
[SAML 2.0 Web Browser SSO](saml2-sso.md),
[WS-Federation](ws-federation.md), [GNAP](gnap.md) and
[Shared Signals](shared-signals.md).

A longer guide to the browser OpenID Connect client, and to the Swift
client for native macOS apps, is
[OpenID Connect and CAEP clients](client-libraries.md).

## Node.js (TypeScript and JavaScript)

Six modules, published on npm by
[rcbj](https://www.npmjs.com/~rcbj). Each is written in TypeScript and can
be required from JavaScript. Install one with `npm install <name>`.

| Module | Description | Repository | Documentation |
|---|---|---|---|
| [`oidc-caep-client`](https://www.npmjs.com/package/oidc-caep-client) | In-browser OpenID Connect public client (PKCE, PAR, DPoP, RFC 9207) with token caching and auto-refresh, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/oidc-caep-client](https://github.com/rcbj/oidc-caep-client) | [documentation](https://rcbj.github.io/oidc-caep-client/) |
| [`oidc-caep-risc-nodejs`](https://www.npmjs.com/package/oidc-caep-risc-nodejs) | Server-side OpenID Connect confidential client: Authorization Code with PKCE, client authentication, and a CAEP and RISC Shared Signals receiver | [rcbj/oidc-caep-risc-nodejs](https://github.com/rcbj/oidc-caep-risc-nodejs) | [documentation](https://rcbj.github.io/oidc-caep-risc-nodejs/) |
| [`gnap-caep-client`](https://www.npmjs.com/package/gnap-caep-client) | In-browser GNAP (RFC 9635) client: HTTP message signature key proofs, redirect interaction, subject information for user sign-in, key-bound token caching and rotation, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/gnap-caep-js](https://github.com/rcbj/gnap-caep-js) | [documentation](https://rcbj.github.io/gnap-caep-js/) |
| [`gnap-caep-risc-nodejs`](https://www.npmjs.com/package/gnap-caep-risc-nodejs) | Server-side GNAP (RFC 9635) client for traditional web applications: a registered key proved by mutual TLS, HTTP message signatures or detached JWS, key-bound tokens, redirect and push interaction finish, and a CAEP and RISC Shared Signals receiver | [rcbj/gnap-caep-risc-nodejs](https://github.com/rcbj/gnap-caep-risc-nodejs) | [documentation](https://rcbj.github.io/gnap-caep-risc-nodejs/) |
| [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs) | Server-side SAML 2.0 service provider: signed AuthnRequests on HTTP-Redirect or HTTP-POST, and Responses on HTTP-POST, HTTP-Redirect or HTTP-Artifact (with SOAP artifact resolution), validated strictly | [rcbj/saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs) | [documentation](https://rcbj.github.io/saml2-sp-nodejs/) |
| [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs) | Server-side WS-Federation relying party: the passive requestor profile (`wsignin1.0`, `wsignout1.0`, `wsignoutcleanup1.0`) with SAML 2.0 assertions validated strictly, and a CAEP and RISC receiver that ends sessions | [rcbj/wsfed-caep-nodejs](https://github.com/rcbj/wsfed-caep-nodejs) | [documentation](https://rcbj.github.io/wsfed-caep-nodejs/) |

## Other languages

Libraries for other languages will be listed in their own sections as they
are published. A Swift client for native macOS apps is already documented,
with the browser OpenID Connect client, on
[OpenID Connect and CAEP clients](client-libraries.md).
