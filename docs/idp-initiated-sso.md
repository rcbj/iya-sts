---
title: Identity-provider-initiated sign-in
nav_order: 9
---

# Identity-provider-initiated sign-in

Most sign-ins start at the application: it sends the browser here with a
request (an `<samlp:AuthnRequest>`, a `wsignin1.0`, an OpenID Connect
authorization request), and this service answers it. That is
**service-provider-initiated** (SP-initiated) sign-in.

An **identity-provider-initiated** (IdP-initiated) sign-in starts here
instead: the person clicks a link at this identity provider and arrives at the
application already signed in. Each protocol has its own form of it:

| Protocol | What is sent | Specification |
|---|---|---|
| SAML 2.0 | an unsolicited `<samlp:Response>`, with no `InResponseTo` | SAML 2.0 Profiles section 4.1.5 |
| SAML 1.1 | a Browser/POST or Browser/Artifact response for a `TARGET` | SAML 1.1 Bindings and Profiles section 4.1 |
| WS-Federation | a sign-in response to the relying party's registered reply URL | WS-Federation 1.2 section 13 |
| OpenID Connect | the browser is sent to the client's `initiate_login_uri`, and the client starts an ordinary authorization request | OpenID Connect Core 1.0 section 4 |

**It is off by default for every application.** An unsolicited response
answers no request, so the application cannot tell a response it was sent
from one somebody else pushed into its browser. Turn it on only for an
application that expects it.

This service does **not** post an unsolicited ID Token straight to an OpenID
Connect client's `redirect_uri`, which some providers offer: it carries no
`state` and no `nonce`, so the client cannot tell it from a forged one.
Section 4 is the OpenID Connect way to do this.

## The link

Every application has one link, the same wherever it is used:

```
https://sts.example.com/launch/{application}
https://sts.example.com/realm/acme/launch/{application}?protocol=saml2
```

* `{application}` is the application's identifier (its entity ID, `wtrealm`
  or `client_id`), URL-encoded.
* `protocol` is `saml2`, `saml11`, `wsfed` or `oidc`. Without it, the link
  uses the one protocol switched on for the application, or its
  `appLaunchProtocol` when more than one is.
* `target` is where to land afterwards. It is sent as SAML 2.0's
  `RelayState`, SAML 1.1's `TARGET`, WS-Federation's `wctx`, or OpenID
  Connect's `target_link_uri`. Without it, OpenID Connect uses the
  application's home page.
* **For OpenID Connect, `target` must be an address registered on the
  client**, in every mode: exactly one of its redirect URIs
  (`oauthRedirectUri`), its `oauthInitiateLoginUri` or its home page
  (`appHomePageUrl`), https only. The match is exact once both are parsed
  as URLs — a longer path, an added query, another host or `http` do not
  match — and a redirect URI this service only *saw* a client use
  (`appRedirectUriObserved`, or one marked in `appReturnAddressObserved`)
  does not count. Any other `target` is refused (400, `STS-LAUNCH-0007`)
  rather than dropped. For the other three protocols `target` is data the
  application receives at its own registered address; this service never
  sends the browser to it.

You will find the link in two places:

* **The user portal.** `/portal/applications` shows a **Sign in** link beside
  each application the person may use and that has IdP-initiated sign-in on.
* **The console.** Each protocol sub-tab of the application
  (**Applications → the application → Configuration**) shows its link at the
  top, with a copy button. It is greyed while the switch is off, and says what
  is missing when the application has nowhere registered to send a sign-in.
  `/admin-api` returns the same links as `launchUrls` in the application view.

The link also works anywhere else: a bookmark, an intranet page, an email.

## Turning it on

Each protocol has two switches: may this identity provider start a sign-in,
and may the application. Each is a realm setting that an application's own
entry overrides; both are on the protocol's sub-tab under **Who may start a
sign-in**.

| Protocol | IdP-initiated (default off) | SP-initiated (default on) |
|---|---|---|
| SAML 2.0 | `saml2IdpInitiatedSso` / `saml2.idpInitiatedSso` | `saml2SpInitiatedSso` / `saml2.spInitiatedSso` |
| SAML 1.1 | `saml11IdpInitiatedSso` / `saml11.idpInitiatedSso` | `saml11SpInitiatedSso` / `saml11.spInitiatedSso` |
| WS-Federation | `wsfedIdpInitiatedSso` / `wsfed.idpInitiatedSso` | `wsfedSpInitiatedSso` / `wsfed.spInitiatedSso` |
| OpenID Connect | `oauthThirdPartyInitiatedLogin` / `oauth2.thirdPartyInitiatedLogin` | `oauthSpInitiatedSso` / `oauth2.spInitiatedSso` |

With the management API:

```bash
api applications/set '{"application":"https://sp.example.com/saml",
  "attribute":"saml2IdpInitiatedSso","value":"TRUE"}'
```

What each SP-initiated switch does when it is off:

* **SAML 2.0**: an `<samlp:AuthnRequest>` is answered with a `RequestDenied`
  Response.
* **SAML 1.1** and **WS-Federation**: the application's request is refused.
  These requests are unsigned URLs, so turning this off closes the door
  rather than proving who opened it.
* **OpenID Connect**: `/oauth2/authorize` answers the client only when the
  request follows a `/launch` of it on the same session within
  `oauth2.launchWindowS` (300 seconds by default). Any other request gets
  `unauthorized_client`. Grants that do not use the authorization endpoint are
  not affected.

## What each protocol needs

| Protocol | Needs |
|---|---|
| SAML 2.0, SAML 1.1 | a registered assertion consumer service (`samlAssertionConsumerService`, or consumed metadata) |
| WS-Federation | a registered reply URL (`wsfedReplyUrl`); a `wreply` on the link is refused |
| OpenID Connect | `oauthInitiateLoginUri`: the client's `initiate_login_uri`, https without a fragment. RFC 7591 registration writes it, and the console and `/admin-api` edit it. |

## It is the same sign-in

An IdP-initiated sign-in is checked exactly like an SP-initiated one. The
person signs in on the same screen, with the same risk assessment. The
issuance policy is asked with the session's risk and device. A Shared
Signals `session-presented` event is sent. The application is recorded on
the session, so [signing out](signing-out.md) reaches it. When the policy
asks for a stronger sign-in because of risk, the person is asked to sign in
again and the launch continues, rather than being refused.

## Errors

The link answers a short page with a code in the `STS-LAUNCH` range when it
cannot start a sign-in: the application does not exist, the protocol is not
one of the four or not one the application uses, the switch is off, there
is nowhere registered to send the sign-in, or an OpenID Connect `target` is
not one of the client's registered addresses. See [error codes](error-codes.md).
