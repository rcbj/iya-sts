---
title: Authorization overview
---

# Authorization overview

This service makes two kinds of authorization decision, and keeps them apart:

* **What it ISSUES.** Whether a session, a token, an assertion or a ticket is
  issued at all, which scopes and permissions it carries, and which RFC 9396
  `authorization_details` it carries. This service decides these itself,
  because it is the one issuing.
* **What a token's holder may DO at a resource.** That is the resource
  server's decision. This service can answer it on the resource server's
  behalf, as a Policy Decision Point. A resource server can ask per request
  (AuthZEN), or a remote PEP can pull the policies and decide them locally
  (XACML).

A token being issued is not a decision about the next access. A token can be
issued validly, and a later request to a particular resource can still be
refused.

Every decision on this page is asked of an **XACML 3.0 policy**. A built-in
policy decides unless an operator overrides it, so what is permitted can be
read, edited and tried on `/admin/xacml/decide`. No authorization rule here
lives in code that a policy cannot change.

## The pieces, and where each is documented

| Piece | What it decides | Where it is documented |
|---|---|---|
| **Roles** | Who holds what: realm roles, app roles, and the built-in roles held through directory groups | [Configuration: Roles](configuration.md#roles), [Admin console: Roles](admin-console.md#roles--adminroles) |
| **The issuance policy** (`role-issuance`) | Every kind of issuance, against the role an application requires; each requested scope; each RFC 9396 type; each GNAP right; each registered device | [XACML: the embedded PEPs](xacml.md#the-embedded-peps-this-services-own-issuance-and-access), [Require a role to use an application](configure-xacml.md#require-a-role-to-use-an-application), [GNAP access types](gnap.md#access-types-and-the-issuance-policy), [Devices](devices.md#the-issuance-policy) |
| **Scopes** | Which scopes a client may be issued, and which are gated by role | [OAuth 2.0: Scopes a client may be issued](oauth-oidc.md#scopes-a-client-may-be-issued) |
| **Delegated permission grants** | Which permissions on another application a client may use on a person's behalf, and which a client holds for itself through a role | [OAuth 2.0: Permissions on another application](oauth-oidc.md#permissions-on-another-application-delegated-or-the-applications-own), [Admin console: Delegated permissions](admin-console.md#delegated-permissions) |
| **Consent** | Whether the person agreed to what is issued on their behalf | [OAuth 2.0: Consent](oauth-oidc.md#consent) |
| **Rich authorization requests** (RFC 9396) | Which `authorization_details` types exist, who declares them, and how a request's details are checked and carried | [OAuth 2.0: Rich authorization requests](oauth-oidc.md#rich-authorization-requests-rfc-9396) |
| **Fine-grained authorization** | Each detail of an application's own types, decided by that application's own policy, at issuance and at access time | [Fine-grained authorization](fga.md) |
| **Who may act for whom** | Delegation and impersonation in a token exchange, S4U and WS-Trust | [Delegation and impersonation](delegation.md) |
| **The access policy** (`access-control`) | Who may reach the console, the management API, the portal, SCIM, the SPIRE Server API, the debugger, `/xacml` and the report API | [XACML: the embedded PEPs](xacml.md#the-embedded-peps-this-services-own-issuance-and-access) |
| **The engine and the repository** | XACML 3.0, written in XML, JSON or ALFA, in a repository kept per realm | [XACML 3.0 and ALFA](xacml.md), [Configuring XACML and ALFA](configure-xacml.md) |
| **Decisions for resource servers** | An AuthZEN Authorization API 1.0 evaluation endpoint, and a remote PEP that pulls the policies | [AuthZEN](authzen.md), [Remote PEP](remote-pep.md) |

## How a request with `authorization_details` is decided

Using the [Fine-grained authorization](fga.md) page's example, a client asks
for a `document_access` detail on an application that enforces FGA. The
service asks, in order:

1. **Is the detail valid?** The type must be declared by a resource
   application, and the detail must meet its schema. If not, the answer is
   `invalid_authorization_details`, in every mode.
2. **Does the issuance policy allow the type for this client?** This is the
   `issue-authorization-detail` question, asked together with the scopes and
   the role the application requires.
3. **Does the application's own policy permit this detail?** This is the
   `grant-authorization-detail` question. The detail's actions, identifier,
   locations and mapped members are attributes of the request. A refusal is
   `access_denied` at the authorization endpoint and
   `invalid_authorization_details` at the token endpoint. A policy that cannot
   be evaluated is `server_error`, never a permit.
4. **Did the person consent?** The consent screen shows only the details that
   passed steps 1 to 3.

Afterwards, the resource server checks the token. It can ask about a specific
access through AuthZEN, which the application's policy decides while the
application enforces FGA.

## Related

* [Fine-grained authorization](fga.md)
* [XACML 3.0 and ALFA](xacml.md)
* [AuthZEN](authzen.md)
* [Remote PEP](remote-pep.md)
* [Delegation and impersonation](delegation.md)
* [Error codes](error-codes.md): the `STS-XACML-*`, `STS-FGA-*` and
  `STS-AUTHZEN-*` codes
