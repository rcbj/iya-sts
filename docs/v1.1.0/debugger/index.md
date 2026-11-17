---
title: The protocol debugger
nav_order: 1
---

# The protocol debugger

This service carries a copy of the **identity protocol debugger**,
[id-proto-debugger](https://github.com/rcbj/id-proto-debugger). It is a
client of nearly every protocol this service speaks. You use it to run an
OAuth 2.0 grant or an OpenID Connect flow one step at a time, send a SAML
AuthnRequest or a WS-Trust RST, build and decode tokens and assertions, and
see every message in both directions, with each field decoded and each
signature checked. It works against this service and against any other
identity provider it can reach.

The debugger is served by this process on a listener of its own, port **8444**
by default, so its pages have an origin of their own and are not on the
console's. You reach it by signing in through this service, and only a console
administrator gets in.

* **[Accessing the debugger](access.md)**: where it is, who may use it, how to
  turn it on, and how to leave it out of a production build.
* **[What a protocol debugger is](what-is-a-protocol-debugger.md)**: what the
  tool is for, and what it deliberately is not.

The user guides below are copied from the debugger's release **0.9.3**, which
is the version this service's image embeds
(`ghcr.io/rcbj/id-proto-debugger-embedded:0.9.3`):

| Guide | What it covers |
|---|---|
| [Using the OAuth2 / OIDC workflow](oauth2-oidc/index.md) | The steps every grant and flow share: metadata, client settings, front end or back end |
| [OAuth 2.0 authorization grants](oauth2-oidc/oauth2-grants.md) | Authorization Code (with and without PKCE), Implicit, Password, Client Credentials, Device Authorization, Refresh Token, Token Exchange |
| [OpenID Connect authentication flows](oauth2-oidc/oidc-flows.md) | The Authorization Code flow, both Implicit flows, the three Hybrid flows, DPoP |
| [Dynamic client registration](oauth2-oidc/dynamic-client-registration.md) | The registration pane on step 1 |
| [Token detail, introspection, UserInfo and JWKS](oauth2-oidc/related-tools.md) | The pages that read a token you already hold, and the logout status page |
| [Using the SAML workflow](saml.md) | The SAML 2.0 request and response pages |
| [SAML Assertion Tool](saml-assertion.md) | Build, sign and encrypt an assertion in the browser |
| [SAML decoders and certificate details](saml-decoders.md) | Read an AuthnRequest, a Response or a certificate you already have |
| [Using the WS-Trust workflow](wstrust.md) | A WS-Trust RST and the response |
| [JWT Tools](jwt-tools.md) | Build, sign, encrypt, verify and decrypt a JWT |
| [Digital Signature](digital-signature.md) | Generate keys, then sign or MAC a value and check it |

The debugger has workflows these guides do not cover yet, among them
Kerberos and SPNEGO, LDAP, SCIM, Shared Signals with CAEP and RISC, SPIFFE,
PKI, WebAuthn, smart cards, GNAP and XACML. Their notes are in the debugger's
own [`docs/`](https://github.com/rcbj/id-proto-debugger/tree/0.9.3/docs)
directory. They are written for somebody changing the debugger, but each page
is also documented on screen.
