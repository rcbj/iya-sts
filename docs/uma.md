---
title: User-Managed Access
---

# User-Managed Access 2.0

User-Managed Access (UMA) 2.0 lets a **resource owner** decide, ahead of
time, who may reach the resources a **resource server** holds for them, and
lets a **requesting party** who is not the owner obtain a token for them
through this authorization server. It is two Kantara Initiative
Recommendations:

* [UMA 2.0 Grant for OAuth 2.0 Authorization](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html):
  the permission ticket, the `urn:ietf:params:oauth:grant-type:uma-ticket`
  grant, the requesting party token (RPT), claims gathering and discovery.
* [Federated Authorization for UMA 2.0](https://docs.kantarainitiative.org/uma/wg/rec-federated-authz-2.0.html):
  the protection API — the protection API access token (PAT), resource
  registration, the permission endpoint and RPT introspection.

This page describes what this service implements, phase by phase (#1168).
**Nothing on this page is decided in code**: every permission is a question
put to the XACML engine, and this page says which policies answer it.

## Where it stands

| Phase | What | State |
|---|---|---|
| 1 (#1190) | The contract: the facts, the two policy templates, the stores, the settings, the error codes | built |
| 2 (#1191) | The protection API: the PAT, resource registration, the permission endpoint, discovery | built |
| 3 (#1192) | The resource owner's own policy, and the portal's *Sharing* section | built |
| 4 (#1193) | The `uma-ticket` grant: the layers, `need_info`, the RPT, the PCT, upgrade, introspection, revocation | built |
| 5 (#1194) | Claims interaction, `claim_token`, `request_submitted` and the owner's approval | built |
| 6 (#1195) | The console, `/admin-api` and the monitor | |
| 7 (#1196) | Protocol tests with Keycloak as the independent peer | |

## The protection API

A **resource server** is an application declared for the protocol `uma`
(**Applications → the application → Protocols**). Its client needs a
delegated permission grant of `urn:sts:uma-protection-api:uma_protection` on
the realm's `sts-uma-protection-api` object.

**The protection API access token (PAT)** is an ordinary access token of the
realm, audienced to its `/uma` and carrying `uma_protection`. Its subject is
the **resource owner** of everything registered with it:

* obtained by the **authorization code flow**, the owner is the person who
  signed in and consented;
* obtained by **`client_credentials`**, the owner is the application itself,
  which is allowed only where the application carries `umaOwnsResources`
  `TRUE`.

Nothing a resource server sends names an owner. The PAT is checked in every
mode.

| Endpoint | What it does |
|---|---|
| `POST /uma/rreg` | Registers a resource. `resource_scopes` is required; `name`, `type`, `description` and an https `icon_uri` are optional; other members are not stored. Answers 201 with `_id`, `user_access_policy_uri` and a `Location`. |
| `GET /uma/rreg` | Lists the `_id`s this resource server registered for this owner. |
| `GET`, `PUT`, `DELETE /uma/rreg/{_id}` | Reads, replaces or deletes one. A resource another owner or resource server registered is `not_found`. Withdrawing a scope, or deleting the resource, revokes every RPT that carried it. |
| `POST /uma/perm` | Takes one `{resource_id, resource_scopes}` object or an array of them, and answers 201 with one permission `ticket`. An unregistered resource is `invalid_resource_id`; an unregistered scope is `invalid_scope`. |
| `GET /.well-known/uma2-configuration` | The realm's RFC 8414 metadata plus `permission_endpoint`, `resource_registration_endpoint` and `uma_profiles_supported`. The `uma-ticket` grant and `claims_interaction_endpoint` appear once they are performed. Also answered at the inserted form, `/.well-known/uma2-configuration/realm/{id}`. |
| `GET /uma` | A page describing UMA in the realm; `?format=json` for the same as data. |

While `uma.enabled` is off, every one of these answers 501.

## Sharing on the portal

A person's resources, and who may reach them, are on the portal under
**Sharing**:

* **What I share** (`/portal/shared`) lists every resource a resource server
  registered for you. Under each one, the **Share** form names the scopes,
  and who the share is with:
  * a person, by username;
  * a group, by name (its direct members);
  * anyone signed in to this realm;
  * anyone whose gathered claim has a given value.

  A share may also end on a date, require an authentication level, and
  **ask me each time**. **Remove** takes a share away and ends every
  requesting party token that carried it.
* **Shared with me** (`/portal/shared-with-me`) lists what others share with
  you: each resource, its owner, the scopes and until when.

**Each share is one rule of your own XACML policy.** The page reads the
policy back and draws every rule of the form's shape as a share. A rule you
did not write with the form is drawn as *A custom rule*, read-only. Where the
realm turns on `uma.ownerAlfaEditing`, the page also offers your whole
policy as ALFA; saving it ends every token issued over your resources.

Your policy is kept in a store of its own, never in the realm's policy
repository, and is only ever asked about your own resources. It is deleted
with your account.

## The grant

A client presents the ticket a resource server handed it at the token
endpoint:

```
POST /oauth2/token
grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&ticket=...
```

with its own client authentication, and optionally:

* `pct`, a persisted claims token from an earlier answer;
* `rpt`, an RPT to upgrade;
* `scope`, further scopes of the ticket's resources (section 3.3.4).

The client must declare the grant type (`oauthGrantType`). A ticket is
spent once, and only the client that first presented it may present it
again. The answer is one of:

| Answer | When |
|---|---|
| 200 with `access_token` (the RPT) | Every permission asked was granted, or some were and `uma.partialRpt` is on. `upgraded: true` where an RPT was upgraded; the old one is revoked. |
| 403 `need_info` | A policy needs something about the requesting party that is not known yet. Carries a new `ticket` and `required_claims`. |
| 403 `request_denied` | Nothing was granted, or not everything with `uma.partialRpt` off, or the issuance policy refused the RPT. |
| 400 `invalid_grant`, `invalid_scope` | The ticket, PCT or RPT cannot be used here, or a scope names nothing in the ticket. |
| 500 `server_error` | A policy could not be evaluated. Nobody decided, so it is never `request_denied`. |

**The RPT** is an RFC 9068 access token: `aud` is the resource server,
`permissions` lists each resource and its granted scopes, and there is no
`scope` claim. Where a resource's `type` is an `authorization_details` type
the resource server declares, the same permissions are also written as
`authorization_details`. It lives no longer than `uma.rptLifetimeS`, and has
no refresh token unless `uma.rptRefreshToken` is on.

**Introspection.** A resource server introspects an RPT at
`/oauth2/introspect` with its PAT as `Authorization: Bearer`. The answer adds
`permissions` and has no `scope`; an RPT issued for another resource server
is `active: false`.

**Revocation.** Removing a share, deleting a resource, narrowing its scopes,
an owner's ALFA edit, and the owner's account being disabled or deleted each
revoke the RPTs that carried what changed, so introspection answers
`active: false`. A PCT is revoked at `/oauth2/revoke`. **An RPT is what the
owner allowed when it was issued**: a resource server that needs the current
answer asks [AuthZEN](authzen.md)'s `/access/v1/evaluation`.

## When the requesting party is not known yet

A policy that needs to know who is asking answers `need_info` with
`redirect_user: true`. The client then does one of two things:

* **Sends the person to the claims interaction endpoint**,
  `GET /uma/claims?client_id=...&ticket=...&claims_redirect_uri=...&state=...`.
  They sign in with this service's normal sign-in, and are sent back to the
  `claims_redirect_uri` with `authorization_state=claims_submitted`, a new
  `ticket` and the `state`. The `claims_redirect_uri` must be one the client
  registered in **`oauthClaimsRedirectUri`**, matched exactly; any other is
  told to the person and never redirected to. A ticket that cannot be used
  goes back with `authorization_state=not_authorized`.
* **Pushes a `claim_token`** with
  `claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken`:
  an ID Token this realm issued, or one from a declared assertion issuer,
  audienced to the client and naming a person of this realm. Its other
  claims reach the policy as `urn:sts:xacml:uma:claim:<name>`.

Either way the grant then answers with a **`pct`**, a persisted claims token
the client may present next time instead.

## When the owner asked to be asked

A share saved with **Ask me each time** answers `request_submitted` with a new
`ticket` and an `interval`. The owner finds the request under **Requests
waiting for you** on `/portal/shared`, and is mailed where mail is set up.
**Approve** adds a share with that person for a day, as a rule of the owner's
policy; **Refuse** ends it. The client polls with its latest ticket: while
nobody has answered it is told `request_submitted` again; after an approval
it gets its RPT; after a refusal, or after `uma.pendingLifetimeS`, it gets
`request_denied`.

## How a permission is decided

An RPT carries **permissions**: one registered resource and the scopes
granted on it. Each (resource, scope) pair is a separate question, and it is
issued only when every one of these answers Permit, in this order:

1. **The realm's `uma-authorization` policy.** Built in and called like the
   issuance policy; a policy of the name `uma.authorizationPolicy` gives in
   the realm's `ou=policies` overrides it. It is the administrator's layer:
   whether the resource server is declared for the protocol `uma`, whether the
   client registered the UMA grant type, whether a pushed `claim_token`'s
   issuer is declared, and whether a requesting party is known at all. With
   nobody known its answer is an Indeterminate over a missing attribute of the
   access-subject category, which the token endpoint answers as `need_info`.
   A realm tightens by adding a Deny rule.
2. **The resource owner's own document.** A real XACML policy per owner,
   authored by the portal's share form from the `uma-owner-default` template,
   kept in a store of its own rather than in `ou=policies`, and decided alone.
   **An owner with no document is NotApplicable, which refuses: absence is
   never consent.**
3. **The resource server's fine-grained policy**, when the application
   [enforces one](fga.md). Its Deny stands over an owner's Permit.
4. **The issuance gate**: `issue-access-token` for the RPT as a token, as
   for every access token.

Deny, NotApplicable and an Indeterminate over a missing attribute about the
resource refuse the permission. An Indeterminate over a missing attribute
about the requesting party is `need_info`. A fault — a policy that will not
parse, an engine error — is `server_error`, never `request_denied`: nobody
decided.

### The facts a policy may read

Every identifier is in the `urn:sts:xacml:` namespace, which the AuthZEN and
fine-grained catalogues refuse to map onto, so neither a caller's property nor
a detail's member can forge one.

| Category | Attribute | What it is |
|---|---|---|
| resource | `resource-id` | the registered resource's `_id` |
| resource | `urn:sts:xacml:uma:resource-type`, `uma:resource-server`, `uma:resource-server-declared`, `uma:owner`, `uma:owner-kind` | the registration and the PAT that made it |
| action | `action-id` | the scope on the owner's layer; `issue-uma-permission` on the realm's, `grant-uma-permission` on the resource server's |
| action | `urn:sts:xacml:uma:scope` | the scope, on every layer |
| access-subject | `subject-id`, `urn:sts:xacml:subject-kind`, `urn:sts:xacml:client-id` | the requesting party once known, and the client |
| access-subject | `urn:sts:xacml:uma:requesting-party-known`, `uma:requesting-party-is-owner`, `uma:claim-source`, `uma:claim-issuer`, `uma:claim-issuer-declared`, `uma:client-grant-declared`, `urn:sts:xacml:acr` | how the requesting party became known |
| access-subject | `urn:sts:xacml:uma:claim:<name>` | each gathered claim, from a verified token or the session, never a value a client asserted |
| environment | `urn:sts:xacml:protocol` = `uma`, `urn:sts:xacml:grant-type`, `urn:sts:xacml:realm`, `urn:sts:xacml:uma:layer`, `uma:stage`, `uma:ticket-age`, `uma:rpt-presented`, the mode and the settings | as every issuance question carries them |

A share saved with *Ask me each time* is a Permit carrying the obligation
`urn:sts:xacml:obligation:uma-approval`; the token endpoint answers
`request_submitted` and the owner decides on the portal.

## Configuration

Every setting is the realm's, in the `UMA` group, homed on **Protocols → UMA**
once that page exists. **UMA is off by default.**

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `uma.enabled` | `STS_UMA_ENABLED` | `false` | yes | When on, the protection API answers under `/uma`, the token endpoint performs and advertises the `uma-ticket` grant, and `/.well-known/uma2-configuration` is served. Off, the routes answer 501 and the grant is `unsupported_grant_type`. |
| `uma.authorizationPolicy` | `STS_UMA_AUTHORIZATION_POLICY` | `uma-authorization` | yes | The `ou=policies` entry that decides the realm's layer; with none of that name the built-in template decides, and a disabled entry does not fall back. |
| `uma.ticketLifetimeS` | `STS_UMA_TICKET_LIFETIME_S` | `300` | yes | How long a permission ticket may be presented. Every `need_info`, `request_submitted` and `request_denied` rotates it. |
| `uma.rptLifetimeS` | `STS_UMA_RPT_LIFETIME_S` | `600` | yes | How long an RPT lives. Short on purpose: a permission is what the owner allowed when it was issued. |
| `uma.rptRefreshToken` | `STS_UMA_RPT_REFRESH_TOKEN` | `false` | yes | Whether a refresh token is issued beside an RPT. Off by default; on, a refresh re-decides every permission. |
| `uma.pctLifetimeS` | `STS_UMA_PCT_LIFETIME_S` | `2592000` | yes | How long a persisted claims token keeps the gathered claims for one client. |
| `uma.partialRpt` | `STS_UMA_PARTIAL_RPT` | `true` | yes | Whether an RPT is issued for the granted subset when some permissions are refused; `request_denied` only when none is. |
| `uma.ownerAlfaEditing` | `STS_UMA_OWNER_ALFA_EDITING` | `false` | yes | Whether a resource owner may edit their whole document as ALFA on the portal. Off, a rule the form did not write is read-only. |
| `uma.requestingPartyAttributes` | `STS_UMA_REQUESTING_PARTY_ATTRIBUTES` | `uid,mail,memberOf` | yes | The directory attributes of a requesting party the owner's layer may read. |
| `uma.pendingLifetimeS` | `STS_UMA_PENDING_LIFETIME_S` | `86400` | yes | How long a `request_submitted` request waits for the owner's answer. |
| `uma.maxPendingPerOwner` | `STS_UMA_MAX_PENDING_PER_OWNER` | `50` | yes | The most requests waiting for one owner at a time. |
| `uma.maxOwnerPolicyBytes` | `STS_UMA_MAX_OWNER_POLICY_BYTES` | `262144` | yes | The largest an owner's document may be. |
| `uma.maxOwnerRules` | `STS_UMA_MAX_OWNER_RULES` | `500` | yes | The most rules an owner's document may hold. |
| `uma.maxResourcesPerOwner` | `STS_UMA_MAX_RESOURCES_PER_OWNER` | `1000` | yes | The most resources registered on one owner's behalf. |
| `uma.maxResourceScopes` | `STS_UMA_MAX_RESOURCE_SCOPES` | `64` | yes | The most `resource_scopes` one resource may carry. |

## The stores

Six per-realm stores hold UMA's state, every one persisted and every one
cell-tier (somebody's, or minted here): the registered resources, the owners'
documents, the permission tickets, the persisted claims tokens, the issued
RPTs' permissions (indexed by resource, owner and requesting party, so a
withdrawn share finds the tokens that carried it) and the approvals waiting
for an owner. A ticket and a PCT are stored by digest: a dump of the store
holds no working handle. A ticket is spent once across the cluster.

## Error codes

`STS-UMA-*`, listed on [Error codes](error-codes.md).
