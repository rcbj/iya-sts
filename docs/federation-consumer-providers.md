---
title: Consumer and social providers
---

# Consumer and social providers

iya-sts can sign people in through consumer and social identity providers:
Google, Apple, Microsoft personal accounts, GitHub, Discord and the others
listed below ([#565](https://github.com/rcbj/iya-sts/issues/565)). This page
covers:

* what is supported, and how far each provider has been tested;
* how to turn the feature on and add a provider;
* what to register at each provider;
* who a person becomes when they sign in;
* how people connect a provider to an account they already have;
* how risk scoring and the issuance policy treat these sign-ins;
* the security properties, the limits, and what to check when something
  fails.

## At a glance

* **Applications need nothing new.** An application keeps using its iya-sts
  integration: OpenID Connect, OAuth 2.0, SAML or WS-Federation. It is issued
  iya-sts's own tokens and assertions whichever provider the person used. No
  provider library or provider credential goes into an application.
* **Each provider is a federation relationship of its own category,
  *consumer*.** It is created from a built-in profile for that provider and
  lives beside the enterprise partners in the same realm. It works wherever an
  enterprise partner does: the sign-in screen, an application's own list of
  partners (`appFederationRelationship`), and a broker relationship.
* **The category is off by default.** A realm turns it on with
  `federation.consumerProviders`.
* **A newcomer gets an account of their own.** An email address is never used
  to match an existing person. People with an account already connect a
  provider to it themselves, from the portal.
* **Provider tokens are not kept.** iya-sts reads the person's profile at
  sign-in, then discards the provider's access token. It asks for no refresh
  token.

## Supported providers

16 provider profiles, plus 2 generic profiles for a provider outside the
catalogue. **None has yet been run against its live provider.** Doing so needs
an application registered at each provider, with its credentials.

The *Tested* column says how each profile is exercised by
`tests/federation_consumer_providers.js` and
`tests/vendored/sts_federation_consumer.js`:

* **Sign-in** means a full sign-in through a server that behaves the way the
  provider documents: the authorization request, the token request with the
  provider's client authentication, the profile calls, and the entry created.
* **Profile only** means the profile exists and is checked when a
  relationship is created, with no sign-in driven through it.

| Provider (`fedProvider`) | Protocol | The person's identifier | The email address | Tested |
|---|---|---|---|---|
| Google (`google`) | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true | Sign-in |
| Discord (`discord`) | OAuth 2.0 | `/users/@me`'s `id` | `email`, verified where `verified` is true | Sign-in |
| GitHub (`github`) | OAuth 2.0 | `/user`'s numeric `id`, never `login`, which can be renamed | the primary address on `/user/emails`, verified where GitHub says so; `/user`'s own `email` is the public one and is not used | Sign-in |
| Apple (`apple`) | OpenID Connect, `form_post`, a client secret iya-sts signs | the ID Token's `sub`, per team | `email`, possibly a private relay address, verified where `email_verified` is true; the name from the one-time `user` field | Sign-in, notifications |
| X (`x`) | OAuth 2.0 with PKCE | `/2/users/me`'s `data.id` | none, without an elevated access tier | Sign-in |
| TikTok (`tiktok`) | OAuth 2.0 (Login Kit), `client_key` | the token response's `open_id`, per app | none | Sign-in |
| Microsoft, personal accounts (`microsoft`) | OpenID Connect, `consumers` authority | the ID Token's `sub` | `email`, never verified: Microsoft makes no statement | Profile only |
| Microsoft, allowed tenants (`microsoft-any`) | OpenID Connect, `common` authority | the ID Token's `sub` | `email`, never verified | The tenant rule only |
| LinkedIn (`linkedin`) | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true | Profile only |
| Yahoo (`yahoo`) | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true | Profile only |
| Slack (`slack`) | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true | Profile only |
| Twitch (`twitch`) | OpenID Connect, with a `claims` request | the ID Token's `sub` | `email`, verified where `email_verified` is true | Creation only |
| Salesforce (`salesforce`) | OpenID Connect | the ID Token's `sub`, a URL naming the org and the user | `email`, verified where `email_verified` is true | Profile only |
| Facebook (`facebook`) | OAuth 2.0, Graph API `/me` | the app-scoped `id` | `email`, never verified | Profile only |
| Amazon (`amazon`) | OAuth 2.0, `/user/profile` | `user_id` | `email`, never verified | Profile only |
| Spotify (`spotify`) | OAuth 2.0, `/v1/me` | `id` | `email`, never verified | Profile only |
| Another OpenID Connect provider (`generic-oidc`) | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true | Sign-in, over HTTP |
| Another OAuth 2.0 provider (`generic-oauth2`) | OAuth 2.0 | `sub`, `id` or `user_id` | `email`, verified where `email_verified` is true | Profile only |

**Not supported:**

* **Netflix** publishes no interface for signing a person in to a third
  party.
* **Sentry**'s OAuth exists to authorize an integration's API calls. Whether
  it can sign a person in has not been established.

The [feasibility record](#feasibility-of-the-platforms-requested) at the end
of this page has what each provider's own documentation says.

## How it works

1. The person chooses **Continue with \<provider\>** on the sign-in screen,
   or an application's own list of partners sends them straight there.
2. iya-sts sends the browser to the provider's authorization endpoint, with
   `state`, a `nonce` for OpenID Connect, and PKCE. PKCE is always sent.
3. The provider sends the browser back to the relationship's assertion
   consumer service, `/federation/acs/<id>`. iya-sts redeems the code at the
   provider's token endpoint, using the provider's own client authentication.
4. iya-sts establishes who the person is:
   * **OpenID Connect providers:** the ID Token is verified against the
     provider's keys. That covers the signature, the issuer, the audience,
     the expiry and the nonce. The person is the token's `sub`.
   * **OAuth 2.0 providers:** iya-sts calls the profile endpoint the profile
     names, and a second endpoint where the provider keeps the address
     elsewhere (GitHub's `/user/emails`). The person is the identifier the
     profile names.
5. The provider's answer is read through its **profile**. The profile says
   where the identifier, the address, its verification and the person's other
   details come from. The result goes through the relationship's attribute
   mapping into the person's directory entry.
6. The sign-in is assessed by risk scoring and decided by the issuance policy.
   A session starts. The application is answered with iya-sts's own tokens or
   assertion, and the session's `amr` begins `federated`.

## Turning it on

The realm setting **`federation.consumerProviders` is off by default.** While
it is off:

* a consumer provider cannot be added to the realm or enabled;
* a sign-in through one is refused at every door, including a relationship
  written directly into the directory (`STS-FED-0171`, `STS-FED-0175`).

Enterprise relationships are not affected in either position. Set it on the
realm's federation settings page, or through the management API:

```
POST /admin-api/config/set   { "key": "federation.consumerProviders", "value": "true" }
```

In a trust realm, use the realm's own prefix:
`/realm/<realm>/admin-api/config/set`.

## Adding a provider

1. **Register an application at the provider** (see
   [What to register at each provider](#what-to-register-at-each-provider)).
   Its redirect URI is the relationship's assertion consumer service:
   * `https://<host>/federation/acs/<id>` in the default realm;
   * `https://<host>/realm/<realm>/federation/acs/<id>` in a trust realm.

   `<id>` is the id you will give the relationship. Its page shows the exact
   address once it exists.
2. **Add it in the console.** Go to **Protocols → Federation → Consumer and
   social providers**, find the provider, and enter an id, the client ID and
   the client secret. Then select **Add**.
3. **Fill in anything the provider needs beyond that.** The relationship's
   page lists what is still missing. Apple needs its team id, key id and
   signing key. A generic provider needs its endpoints.
4. **Enable the relationship.** It is created disabled, like every
   relationship.

The same, through the management API:

```
POST /admin-api/federation/create
{ "id": "google", "role": "service-provider", "protocol": "oidc",
  "provider": "google", "clientId": "<client id>", "clientSecret": "<secret>" }

POST /admin-api/federation/enable   { "id": "google" }
```

The response never repeats the client secret. `GET /admin-api/federation?category=consumer`
lists the consumer providers, and `?category=enterprise` lists the rest.

**What the profile writes, and what it reads.** When a relationship is added,
its profile writes the provider's endpoints, issuer, scope and token-endpoint
authentication onto it. These are ordinary fields on the relationship's page,
and you can change them there. Every address iya-sts calls is one of these
fields.

Where the person's identifier, address and verification come from is
different. That is the provider's profile, and it is read at every sign-in.
So a corrected profile in a later release reaches every relationship of that
provider.

### What to register at each provider

Provider consoles change their names and layouts, so take these as
directions rather than click paths. In every case:

* register a **web application**, also called a confidential client;
* add the redirect URI above;
* copy the client ID and the client secret into iya-sts.

| Provider | Where | What it needs besides the redirect URI |
|---|---|---|
| Google | Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web application) | The OAuth consent screen configured. |
| Apple | Apple Developer → Certificates, Identifiers & Profiles: an App ID with Sign in with Apple, a **Services ID** (the client ID), and a **key** with Sign in with Apple enabled | The Services ID's return URL. The team id, the key id and the key's `.p8` file go into iya-sts (see [Sign in with Apple](#sign-in-with-apple)). Needs an Apple Developer Program membership. |
| Microsoft (`microsoft`) | Microsoft Entra admin center → App registrations → New registration | Supported account types: **personal Microsoft accounts only**. A client secret under Certificates & secrets. |
| Microsoft (`microsoft-any`) | The same | Supported account types that include the organisations you list in `fedAllowedTenants`. |
| GitHub | Settings → Developer settings → OAuth Apps → New OAuth App | The authorization callback URL is the redirect URI. |
| Discord | Discord Developer Portal → Applications → OAuth2 | Add the redirect. Scopes `identify email` (set by the profile). |
| LinkedIn | LinkedIn Developer Portal → your app → Products | Add **Sign In with LinkedIn using OpenID Connect**, then the redirect under Auth. |
| Yahoo | Yahoo Developer Network → Create an App | OpenID Connect permissions, with the email and profile scopes. |
| Slack | api.slack.com → Your Apps → OAuth & Permissions | The redirect URL. Sign in with Slack uses the OpenID scopes (set by the profile). |
| Twitch | Twitch Developer Console → Register Your Application | The OAuth redirect URL. Category: website integration. |
| Salesforce | Setup → App Manager → a connected or external client app with OAuth enabled | The callback URL, and the `openid`, `email` and `profile` scopes. A My Domain login is an enterprise relationship. |
| Facebook | Meta for Developers → your app → Facebook Login → Settings | The redirect under *Valid OAuth Redirect URIs*. The `email` permission may need app review. |
| Amazon | Login with Amazon console → a security profile → Web Settings | The redirect under *Allowed Return URLs*. |
| Spotify | Spotify Developer Dashboard → your app → Settings | The redirect URI. |
| X | X Developer Portal → your project's app → User authentication settings | OAuth 2.0, type *Web App* (confidential client), the callback URL. An address needs an elevated access tier. |
| TikTok | TikTok for Developers → your app → Login Kit | The redirect URI. The client key is the client ID. App review is required. |

### Sign in with Apple

Apple needs three things beyond the client ID, which is the **Services ID**.
Enter them on the relationship's page:

* **`fedTeamId`**: your Apple Developer team id.
* **`fedKeyId`**: the id of your Sign in with Apple key.
* **`fedClientSigningKey`**: that key's `.p8` file, pasted whole. It is
  sealed wherever keys persist and is never shown again.

iya-sts signs a fresh, five-minute client secret for every token request. The
code comes back by `form_post`. The person's name arrives once, on their first
authorization only, and unsigned. It is used as a display value only.

Register `https://<host>/federation/notifications/<id>` as the relationship's
**server-to-server notification endpoint** at Apple:

* **`consent-revoked` and `account-delete`** remove the person's connection
  through Apple, and end the sessions it started. The person's account here
  stays.
* **`email-disabled` and `email-enabled`** are recorded.

A notification is verified against Apple's keys and accepted only once.
Without an `exp`, it is accepted only while its `iat` is recent. In a service
deployed as cells it reaches every cell. If a cell cannot be reached, it is
answered `503`, so Apple's retry is accepted.

**Connecting Apple from the portal needs HTTPS.** Apple's `form_post` is a
cross-site POST, so the browser binding has to be a `SameSite=None; Secure`
cookie.

### Microsoft for allowed organisations

`microsoft-any` uses the `common` authority, whose tokens each name their own
tenant. List the tenant ids whose people may sign in, in **`fedAllowedTenants`**.
The personal-account tenant is listed by default. A token from any other tenant
is refused. A single organisation is usually better added as an enterprise
OpenID Connect relationship.

### A provider outside the catalogue

Use `generic-oidc` or `generic-oauth2`, and fill in the endpoints by hand, as
for an enterprise partner. For an OAuth 2.0 provider whose profile answer names
the person somewhere other than `sub`, `id` or `user_id`, set
**`fedSubjectClaim`** to the field's path, for example `data.id`. If the
provider needs extra authorization request parameters, add them as
**`fedAuthorizeParams`**, one `name=value` per entry. The parameters iya-sts
sets itself, such as `state`, `nonce` and `redirect_uri`, are refused.

## Who a person becomes

* **A newcomer gets an entry of their own.** It is named after the
  relationship and the provider's stable identifier for them, for example
  `discord~80351110224678912`. Relationships of this category default to
  `fedSubjectPolicy` `jit-namespaced`, with `fedAutocreateUsers` on in both
  modes.
* **An email address is never used to find an existing person**, whether or
  not it is verified. A local person with the same name and the same address
  is left exactly as they were. `any-existing` is refused on these
  relationships in every mode (`STS-FED-0172`).
* **An address is unverified unless the provider says it is verified.** It is
  still written to the entry. An unverified address opens no flow that needs
  a verified one, such as emailed codes.
* **The provider's details go through the same mapping as any partner's.**
  `fedAttributeMap` and the default table decide what reaches the entry. A
  provider's own field, such as GitHub's `company`, is listed under *Sent and
  not written* until it is mapped. What is on the entry reaches the tokens
  iya-sts issues through the usual release rules.
* **A provider's own MFA claim does not count as MFA here.** The session
  records the sign-in as `federated`. Nothing a provider says about how the
  person authenticated satisfies a step-up.

## Connecting a provider to an existing account

People who already have an account connect a provider to it on the portal's
**Connected accounts** page (`/portal/connected-accounts`). They are signed in
as themselves, select **Connect**, and sign in at the provider. From then on,
a sign-in through that provider is them. **Disconnect** removes the connection
and ends the sessions it started. Only a consumer provider's connection can be
removed there. An enterprise partner's link is an administrator's.

A connect needs:

* a sign-in whose risk is LOW or unscored;
* an authentication within `federation.connectRecentAuthMinutes` (ten
  minutes by default). Otherwise the person is asked to sign in again first.
  Any sign-in counts, including through a provider: an account a provider
  created has no password here.

A connect is refused:

* **in another browser.** It is finished only in the browser it was started
  in.
* **for a provider account already connected to somebody else** here
  (`STS-FED-0182`).
* **for a console administrator's account**, unless the relationship sets
  `fedMayAssertAdministrators` (`STS-FED-0183`).

The person is mailed a security notice when a connect succeeds.

## Risk scoring and the issuance policy

Consumer sign-ins are scored like any other ([Risk scoring](risk-scoring.md)),
with three signals of their own:

| Signal | Factor | When |
|---|---|---|
| `new-federated-provider` | ×2 | the person's first sign-in through a relationship they have not used before, once they have history enough |
| `network-signups` | ×3 | `risk.networkSignupThreshold` (ten) or more accounts created by federated sign-ins from one network in the hour; not counted for an allow-listed network |
| `federated-provider-weight` | the operator's | a relationship weighted with `federation:<id>=<factor>` in `risk.signalFactors` |

* **A newcomer is assessed too.** Their first sign-in is not scored, but it is
  decided on the evidence, such as a network that has created many accounts in
  the hour.
* **Creating an account is its own policy question** (`create-account`). A
  policy can refuse creation while existing people still sign in
  (`STS-FED-0179`). Nobody is created when it refuses.
* **A step-up is answered here.** When the policy asks an existing person's
  federated sign-in for a step-up, the person answers with an authenticator
  app or security key they hold here. That is never a password and never an
  enrolment. Someone who holds neither is refused (`STS-RISK-0018`). The
  session then records `federated` plus the factor, with `acr` `mfa`.
* **The policy is told the category.** The issuance request carries:
  * `urn:sts:xacml:authn-category`: `consumer` or `enterprise`;
  * `urn:sts:xacml:authn-provider`: the provider;
  * `urn:sts:xacml:email-verified`: `true` or `false`.

## A provider's security events

A provider that sends Shared Signals about its users is configured exactly as
an enterprise partner's are: in the relationship's *Shared Signals from this
partner* section ([Shared Signals](shared-signals.md#receiving-from-a-federation-partner)).
Its events end the sessions it started, and can block its own sign-ins of a
person, and do nothing beyond that relationship. Google's Cross-Account
Protection uses RISC this way. Whether its stream configuration works with
this receiver **has not been verified**. Apple's notifications are their own
endpoint, described [above](#sign-in-with-apple).

## Security properties

* **Every answer is verified against the relationship's own configuration.**
  An ID Token is checked against the provider's keys, issuer and audience, and
  never against a key the token brings with it. Google's bare-host issuer
  spelling is accepted only while the relationship's issuer is still Google's.
* **PKCE and `state` are always sent.** A response this service did not start
  is refused.
* **The client secret is sealed** under the key-encryption key wherever keys
  persist. Apple's signing key is sealed the same way. Neither is ever shown
  or returned by the management API, nor written to the audit log.
* **The provider's tokens are not kept**, and no refresh token is asked for.
* **Every address iya-sts calls is a field an administrator set**, or one the
  profile wrote when the relationship was added. It is never an address taken
  from a request.
* **The provider's libraries are not used.** The libraries the providers
  publish were evaluated (Google's `google-auth-library`, GitHub's Octokit,
  Apple's browser SDK; Discord publishes none). Each would have called the
  provider outside iya-sts's outbound controls, or verified tokens outside its
  one crypto module, so iya-sts's own flow is used for all of them.

## Limits and what is not verified

* **No profile has been run against its live provider.** Each one is built
  from the provider's published documentation. Six are exercised against
  servers that behave as the documentation describes. Providers change their
  endpoints, scopes and review rules, so the first live sign-in through each
  is the real test.
* **The over-HTTP job has run in development mode only.**
* **Sign-in buttons are text only.** Provider logos are under each provider's
  brand rules, and are not included.
* **Applications cannot use the provider's tokens** to call the provider's
  APIs. iya-sts keeps none.
* **Whether Apple retries a notification answered `503`** is Apple's
  behaviour, and has not been verified.
* **Google's RISC stream** with this receiver has not been verified.

## Troubleshooting

Every refusal has an error code on the audit row and in the log, and never in
the response ([Error codes](error-codes.md)).

| Code | What happened | What to check |
|---|---|---|
| `STS-FED-0170` | the provider, or the role or protocol beside it, is not valid | the provider id; a consumer provider is always `service-provider` in its profile's protocol |
| `STS-FED-0171` | a consumer provider cannot be added or enabled | `federation.consumerProviders` is off in this realm |
| `STS-FED-0175` | a sign-in through a consumer provider was refused | `federation.consumerProviders` is off in this realm |
| `STS-FED-0006` | the relationship is enabled and not fully configured | its page lists what is missing |
| `STS-FED-0172` | `any-existing` was refused | it is never allowed on a consumer relationship |
| `STS-FED-0176` | GitHub's `/user/emails` did not answer | the `user:email` scope; the sign-in went on without an address |
| `STS-FED-0177` | the provider's answer named nobody | `fedSubjectClaim` on a generic OAuth 2.0 relationship |
| `STS-FED-0179` | the policy refused to create the account | the issuance policy's `create-account` rules and the risk facts |
| `STS-FED-0178` | a step-up after a provider was not finished | the person must answer with a factor they hold here, in the same browser |
| `STS-RISK-0018` | a step-up was asked of someone who holds no second factor here | expected for a newcomer; an existing person can add an authenticator app on the portal |
| `STS-FED-0182`, `STS-FED-0183`, `STS-FED-0111` | a connect from the portal was refused | the provider account is someone else's; an administrator's account; another browser |
| `STS-FED-0185` | Apple's client secret could not be signed | `fedTeamId`, `fedKeyId`, `fedClientSigningKey` (a P-256 `.p8`) and the client ID |
| `STS-FED-0186`, `STS-FED-0187` | an Apple notification was refused | not signed by Apple, already accepted, or too old; or the relationship takes none |
| `STS-FED-0180` | an extra authorization parameter was refused | it names a parameter iya-sts sets itself |

## Feasibility of the platforms requested

**Ticket #565 names seventeen platforms.** This table records what each
provider's published developer documentation says about signing a person in,
as read when the catalogue was started (October 2026). Each row is checked
again when its profile is used live, because providers change their terms,
endpoints and review requirements.

| Platform | Protocol | Identifier | Email | Restrictions and notes | State |
|---|---|---|---|---|---|
| Google | OpenID Connect | `sub` (stable per Google account) | `email` with `email_verified` | `hd` names a Workspace domain. The ID Token's issuer has two spellings, both accepted. | **Built**; sign-in tested against a provider-shaped server |
| Discord | OAuth 2.0, no ID Token | `id` (a snowflake) | `email` with `verified`, scope `email` | `mfa_enabled` describes the account, not this sign-in. | **Built**; sign-in tested against a provider-shaped server |
| GitHub | OAuth 2.0, no ID Token | numeric `id` | the primary address on `/user/emails` (scope `user:email`) | The token endpoint answers JSON only when asked to. The secret is sent in the request body. | **Built**; sign-in tested against a provider-shaped server |
| LinkedIn | OpenID Connect ("Sign In with LinkedIn using OpenID Connect") | `sub` | `email` with `email_verified` | The product must be added to the app in LinkedIn's developer portal. The token endpoint takes the secret in the body. | **Built** (profile) |
| Microsoft | OpenID Connect | `sub` (per application) | `email`, which Microsoft does not guarantee is verified | `microsoft` uses the `consumers` authority for personal accounts. `microsoft-any` uses the `common` authority for the tenants `fedAllowedTenants` lists. | **Built** (both profiles) |
| Yahoo | OpenID Connect | `sub` | `email` with `email_verified` | | **Built** (profile) |
| Slack | OpenID Connect ("Sign in with Slack") | `sub` / `https://slack.com/user_id` | `email` with `email_verified` | A Slack identity belongs to a workspace (`https://slack.com/team_id`). | **Built** (profile) |
| Twitch | OpenID Connect | `sub` | `email` with `email_verified`, only when requested with the `claims` parameter | Needs extra authorization parameters. | **Built** (profile, with its `claims` request in `fedAuthorizeParams`) |
| Salesforce | OpenID Connect | `sub` (a URL naming the org and user) | `email` with `email_verified` | Login and test domains. A My Domain is an enterprise relationship. | **Built** (profile) |
| Apple | OpenID Connect with Apple-specific parts | `sub` (per team) | `email`, possibly a private relay address | The client secret is a short-lived ES256 JWT signed with the developer's key. `form_post` is required when a name or an address is asked for, and the name arrives once, unsigned. Apple sends server-to-server notifications. Needs an Apple Developer Program membership. | **Built**; sign-in and notifications tested against a provider-shaped server |
| Facebook | OAuth 2.0 on the web, Graph API `/me` | app-scoped `id` | `email` with no verification statement, so unverified here | The OpenID Connect form (Limited Login) is for mobile apps. Some permissions need app review. | **Built** (profile) |
| Amazon (Login with Amazon) | OAuth 2.0, `/user/profile` | `user_id` | `email` with no verification statement | | **Built** (profile) |
| X / Twitter | OAuth 2.0 with PKCE, `/2/users/me` | `data.id` | Only with an elevated access tier and its email scope | The profile is nested under `data`. Access tiers and pricing apply. | **Built**; sign-in tested against a provider-shaped server |
| TikTok (Login Kit) | OAuth 2.0 | `open_id` (per app), from the token response | none | Uses `client_key` instead of `client_id`. App review required. | **Built**; sign-in tested against a provider-shaped server |
| Spotify | OAuth 2.0, `/v1/me` | `id` | `email`, editable by the user, with no verification statement | The documentation frames it as authorization for its Web API rather than as sign-in. | **Built** (profile; the address is unverified) |
| Sentry | OAuth 2.0 for integrations | to be established | to be established | Its OAuth exists to authorize an integration's API calls. Whether it supports signing a person in is not established. | Not yet feasible |
| Netflix | none published | — | — | Netflix publishes no interface for signing a person in to a third party. | **Not feasible** |

## Related

* [Federation](federation.md): relationships, links, provisioning and the
  subject policies these relationships use.
* [Risk scoring](risk-scoring.md): the signals and the levels.
* [Shared Signals](shared-signals.md): a partner's or provider's security
  events.
* [Configuration](configuration.md): `federation.consumerProviders`,
  `federation.connectRecentAuthMinutes` and `risk.networkSignupThreshold`.
