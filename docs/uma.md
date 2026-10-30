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
| 3 (#1192) | The resource owner's own policy, and the portal's *Sharing* section | |
| 4 (#1193) | The `uma-ticket` grant: the layers, `need_info`, the RPT, the PCT, upgrade, introspection, revocation | |
| 5 (#1194) | Claims interaction, `claim_token`, `request_submitted` and the owner's approval | |
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
