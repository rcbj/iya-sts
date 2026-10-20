---
title: Consumer and social providers
---

# Consumer and social providers

iya-sts can sign people in through consumer and social identity providers
such as Google, Discord and GitHub
([#565](https://github.com/rcbj/iya-sts/issues/565)). Each one is a
[federation](federation.md) relationship of its own category, configured on
**Protocols → Federation → Consumer and social providers**. An application
does not need anything new. It keeps using its iya-sts integration, and the
person signs in through a provider wherever an enterprise partner could
appear: the sign-in screen, an application's own list of partners
(`appFederationRelationship`), or a broker relationship.

## Turning it on

The realm setting `federation.consumerProviders` is **off by default**. While
it is off, a realm cannot be given a consumer provider and cannot enable one.
A sign-in through one is refused at every door, including a relationship
written directly into the directory. Enterprise relationships are not
affected by the setting.

## Adding a provider

1. Register an application (an "OAuth app" or "client") at the provider. As
   its redirect URI, use the relationship's assertion consumer service:
   `<base>/federation/acs/<id>`, or `<base>/realm/<realm>/federation/acs/<id>`
   in a trust realm. The relationship's page shows the exact value.
2. On the **Consumer and social providers** tab, find the provider and enter
   an id, the client ID and the client secret, then select **Add**.
   `POST /admin-api/federation/create` with `provider`, `clientId` and
   `clientSecret` does the same.
3. Enable the relationship.

The provider's endpoints, issuer, scope and token-endpoint authentication are
written onto the relationship when it is added. They are ordinary fields,
shown on its page and editable there. **Where the person's identifier, email
address and its verification come from is the provider's profile**, read at
every sign-in, so a correction to a profile reaches every relationship of that
provider.

## Who a person becomes

* **A newcomer gets an entry of their own**, named after the relationship and
  the provider's stable identifier for them, for example
  `discord~80351110224678912`. Relationships of this category default to
  `fedSubjectPolicy` `jit-namespaced`, with `fedAutocreateUsers` on.
* **An email address is never used to find an existing person**, whether or
  not it is verified. `any-existing` is refused on these relationships in
  every mode. Two different policies still link an existing account:
  `pre-linked` and `link-at-first-sign-in`. With `link-at-first-sign-in`, the
  person must sign in here first.
* **An address is unverified unless the provider says it is verified.** It is
  still written to the entry. An unverified address opens no flow that needs
  a verified one, such as emailed codes.
* **The provider's attributes go through the same mapping as any partner's.**
  `fedAttributeMap` and the default table decide what reaches the entry. A
  provider's own member, such as GitHub's `company`, is listed under
  *Sent and not written* until it is mapped. What is on the entry reaches the
  tokens iya-sts issues through the usual release rules.
* **A provider's own MFA claim does not count as MFA here.** The session
  records the sign-in as `federated`, and nothing a provider says about how
  the person authenticated satisfies a step-up.
* **The provider's tokens are not kept.** The access token is used to read the
  person's profile and then dropped, and no refresh token is asked for.

## The catalogue

| Provider (`fedProvider`) | Protocol | The person is | The address is |
|---|---|---|---|
| `google` | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true |
| `discord` | OAuth 2.0 | `/users/@me`'s `id` | `email`, verified where `verified` is true |
| `github` | OAuth 2.0 | `/user`'s numeric `id` (never `login`, which can be renamed) | the primary address on `/user/emails`, verified where GitHub says so. `/user`'s own `email` is the public one and is not used. |
| `generic-oidc` | OpenID Connect | the ID Token's `sub` | `email`, verified where `email_verified` is true |
| `generic-oauth2` | OAuth 2.0 | `sub`, `id` or `user_id` | `email`, verified where `email_verified` is true |

Use the two generic profiles for a provider outside the catalogue. Fill in its
endpoints by hand, as you would for an enterprise partner.

## Feasibility of the platforms requested

**Ticket #565 names seventeen platforms.** This table records what each
provider's published developer documentation says about signing a person in,
as read when the catalogue was started (October 2026). Each row is checked
again when its profile is built, because providers change their terms,
endpoints and review requirements. **Built** means a profile exists today.

| Platform | Protocol | Identifier | Email | Restrictions and notes | State |
|---|---|---|---|---|---|
| Google | OpenID Connect | `sub` (stable per Google account) | `email` with `email_verified` | `hd` names a Workspace domain. The ID Token's issuer has two spellings, both accepted. | **Built** |
| Discord | OAuth 2.0, no ID Token | `id` (a snowflake) | `email` with `verified`, scope `email` | `mfa_enabled` describes the account, not this sign-in. | **Built** |
| GitHub | OAuth 2.0, no ID Token | numeric `id` | the primary address on `/user/emails` (scope `user:email`) | The token endpoint answers JSON only when asked to. The secret is sent in the request body. | **Built** |
| LinkedIn | OpenID Connect ("Sign In with LinkedIn using OpenID Connect") | `sub` | `email` with `email_verified` | The product must be added to the app in LinkedIn's developer portal. The token endpoint takes the secret in the body. | Next: a profile only |
| Microsoft (personal accounts) | OpenID Connect, `consumers` authority | `sub` (per application) | `email`, which Microsoft does not guarantee is verified | The issuer names the personal-account tenant. Organizational tenants are enterprise relationships, or the planned `microsoft-any` profile with an allow-list of tenants. | Planned: issuer adapter |
| Yahoo | OpenID Connect | `sub` | `email` with `email_verified` | | Next: a profile only |
| Slack | OpenID Connect ("Sign in with Slack") | `sub` / `https://slack.com/user_id` | `email` with `email_verified` | A Slack identity belongs to a workspace (`https://slack.com/team_id`). | Next: a profile only |
| Twitch | OpenID Connect | `sub` | `email` with `email_verified`, only when requested with the `claims` parameter | Needs extra authorization parameters. | Next: a profile and extra parameters |
| Salesforce | OpenID Connect | `sub` (a URL naming the org and user) | `email` with `email_verified` | Login and test domains. A My Domain is an enterprise relationship. | Next: a profile only |
| Apple | OpenID Connect with Apple-specific parts | `sub` (per team) | `email`, possibly a private relay address | The client secret is a short-lived ES256 JWT signed with the developer's key. `form_post` is required when name or email is asked for, and the name arrives once, unsigned. Apple sends server-to-server notifications. Needs an Apple Developer Program membership. | Planned: adapters |
| Facebook | OAuth 2.0 on the web, Graph API `/me` | app-scoped `id` | `email` with no verification statement, so treated as unverified | The OpenID Connect form (Limited Login) is for mobile apps. Some permissions need app review. | Next: a profile only |
| Amazon (Login with Amazon) | OAuth 2.0, `/user/profile` | `user_id` | `email` with no verification statement | | Next: a profile only |
| X / Twitter | OAuth 2.0 with PKCE, `/2/users/me` | `data.id` | Only with an elevated access tier and its email scope | The profile is nested under `data`. Access tiers and pricing apply. | Next: a profile only |
| TikTok (Login Kit) | OAuth 2.0 | `open_id` (per app), from the token response | none | Uses `client_key` instead of `client_id`. App review required. | Planned: adapter |
| Spotify | OAuth 2.0, `/v1/me` | `id` | `email`, editable by the user, with no verification statement | The documentation frames it as authorization for its Web API rather than as sign-in. | Possible: unverified address |
| Sentry | OAuth 2.0 for integrations | to be established | to be established | Its OAuth exists to authorize an integration's API calls. Whether it supports signing a person in is not established. | Not yet feasible |
| Netflix | none published | — | — | Netflix publishes no interface for signing a person in to a third party. | **Not feasible** |

## Related

* [Federation](federation.md): relationships, links, provisioning and the
  subject policies these relationships use.
* [Risk scoring](risk-scoring.md): consumer sign-ins are scored like any
  other.
* [Configuration](configuration.md): `federation.consumerProviders`.
