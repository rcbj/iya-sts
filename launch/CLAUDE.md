# launch/

`GET /launch/{app}`: the one link that starts a sign-in to an application
**here**, at this identity provider, rather than at the application (#426,
#713). `launch.ts` answers it; `common/launch_links.ts` builds it, and is a
library so that the account API and the management API can require it long
before this route is registered.

## One URL, three readers

The same URL is:

* the user portal's **Sign in** link on `/portal/applications`, one per
  protocol the application can be launched in (`/account-api/applications`
  returns them as `launches`);
* the card at the top of each protocol sub-tab of the application in the
  console (the management API's application view carries `launchUrls`, so a
  script reads the same thing);
* whatever an operator pastes elsewhere — a bookmark, an intranet page.

They are one URL on purpose. A portal that linked straight to
`/saml2/unsolicited/{sp}` and a console that showed `/launch/{app}` would be
two links to keep honest, and the portal used to link OpenID Connect clients
straight to their `initiate_login_uri`, which bypassed the switch below.

## It does no sign-in of its own

It chooses the protocol, checks that identity-provider-initiated sign-in is
on, and sends the browser (303) to that protocol's own endpoint:

| `protocol` | Sent to | Built by |
|---|---|---|
| `saml2` | `/saml2/unsolicited/{sp}` | #711 |
| `saml11` | `/saml11/sso/{rp}?providerId=…` | #711 |
| `wsfed` | `/wsfed/initiate/{rp}` | #712 |
| `oidc` | the client's `initiate_login_uri` (OpenID Connect Core section 4) | here |

**Each endpoint checks the switch again**, so going to it directly is not a
way round this door, and each one does what its SP-initiated sign-in does:
`sessionOf()` or `beginAuthentication({ application, protocol })` (the
sign-in's own risk assessment and CAEP `session-established`), the issuance
gate with the session (its risk and device facts), `notePresented()`, and the
protocol's issuer, which records the relying party on the session where
`/logout`, Single Logout and back-channel logout read it. **A risk denial is
a step-up, not a refusal**, on all three IdP-initiated endpoints (#711, #712).
Duplicating any of that here would be a second copy of it.

`target` is each protocol's own word for where to land: RelayState, TARGET,
wctx, `target_link_uri` (https only, Core section 4).

## An OpenID Connect `target` is a REGISTERED address or it is refused

rcbj on #714 (2026-10-19): `target` "should only work with registered URIs
for an application object". Until then any https `target` became
`target_link_uri`, so anybody could build a launch link that had the client
send the person, signed in, wherever they chose. Now
`LaunchLinks.registeredTarget()` passes it on only when it EXACTLY matches —
both sides parsed with `new URL()` and compared as `href`, no prefix, origin
or path matching — one of `LaunchLinks.registeredTargetsOf()`:

* `oauthRedirectUri`, less any value `appReturnAddressObserved` marks as a
  development sighting;
* `oauthInitiateLoginUri` (through `initiateLoginUriOf()`);
* `appHomePageUrl` (through `homePageOf()`), which is also the default;

https only. Never `appRedirectUriObserved`, and never a marked value **in
any mode** — the same rule as `/wsfed/initiate`'s reply address and
`missingOf()`'s WS-Federation branch, not `returnAddressesOf()`'s
development belief, because a link anybody can build is not a development
convenience. `oauthPostLogoutRedirectUri` is not on the list: it is where a
sign-OUT lands. The registered spelling is what is sent.

Anything else is refused 400 with `STS-LAUNCH-0007`, before any sign-in,
rather than dropped — `/wsfed/initiate` refuses a `wreply` for the same
reason (STS-WSFED-0026): whoever built the link learns the address was not
used. No `target` is not a refusal; the home page is used, as before.

**The other three need no such check, and were looked at for it**: RelayState
(`/saml2/unsolicited`), TARGET (`/saml11/sso`, both the POST form and the
artifact redirect, which goes to the registered assertion consumer with
TARGET as a parameter) and wctx (`/wsfed/initiate`, which posts only to the
registered reply) are carried to the application's REGISTERED address as
data. This service never sends the browser to them.

## OpenID Connect is the exception, because section 4 ends at the client

The door signs the person in HERE first — through the same sign-in every
protocol uses — so `login_hint` names them and the launch can be recorded on
their session (`session.launches[client_id]`, seconds). Then the browser goes
to the client, which starts an ordinary authorization request.

That record is what makes `oauthSpInitiatedSso` FALSE mean anything: the one
thing an identity provider can refuse on the second half of section 4 is an
authorization request that did not follow a launch. `/oauth2/authorize`
answers such a client only with a launch of it on the session no older than
`oauth2.launchWindowS`, and refuses any other `unauthorized_client`
(STS-OAUTH-0959). The launch is TAKEN when the authorization response goes
out, not when the request is checked: a request that sends the person to the
sign-in screen comes round a second time and must still count.

**The unsolicited ID Token** some providers post straight to a
`redirect_uri` is not offered (rcbj on #426): it carries no `state` and no
`nonce`, so a client cannot tell one it was sent from a forged one.

## Which protocol, when the link does not say

`?protocol=` when given (400 if it is not one of the four, 404 if the
application is not declared or recorded for it); otherwise the one protocol
switched on; otherwise `appLaunchProtocol` among several; otherwise 409.
Nothing switched on is answered as off (403), not as ambiguous, because that
is the reason the person needs.

An OAuth 2.0 client counts for `oidc` only when it declared OpenID Connect or
has an `initiate_login_uri`: a resource server is an OAuth client too, and a
launch it can never answer would be a dead card on its sub-tab.

## Off by default

Every IdP-initiated switch is off until an application opts in (rcbj on
#426): an unsolicited response carries no request it answers, so the
relying party cannot tell one it was sent from one pushed into its browser.
The switches and their realm defaults are #710's, in
`common/applications.js` and `common/config.js`.

## Refusals are pages, in English

Nothing has named a relying party to hand a protocol error to yet, so a
refusal is a short page with an `STS-LAUNCH-*` code (#539: refusals are not
translated). No script, so the service's default policy needs no change.

## Tests

`tests/launch.js` (in process): the four protocols' destinations, the switch
refusing and allowing, the choice of protocol, an OpenID Connect `target`
passed on when registered and refused (0007) when it is unregistered,
observed, a prefix or extension, another scheme or host, the launch
record and `/oauth2/authorize` honouring and spending it, and the portal's
and the console's links.

`tests/vendored/sts_idp_initiated_launch.js` (over HTTP, `local: true`,
#715): the same sections in a throwaway realm, run in `memory`, `single-node`
and `cluster` — **the product-mode coverage**, and across nodes in
`cluster`. The switches are set through `/admin-api`, the person signs in
with a real password, the launch window is set to 10 s and waited out, and
the links are read from `/admin-api`'s `launchUrls` and the portal's
`/account-api/applications`. That the launch is on the session is asserted
through its effect at `/oauth2/authorize`.
