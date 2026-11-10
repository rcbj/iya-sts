---
title: Input validation
---

# Input validation

Every request this service accepts is checked for its shape before anything acts
on it. Shape is checked the same way in development and product mode, with one
exception: a repeated parameter on a protocol endpoint, below. Whether a
client, a person or a password is known or correct is a separate question, and
[What is not checked](what-is-not-checked.md) covers it.

## Rules every request follows

| Rule | What happens |
|---|---|
| **Control characters** | None are allowed in a query parameter, path parameter or header. In a body field, tab, newline and carriage return are allowed, and nothing else below U+0020. |
| **A repeated parameter** | Refused, unless that parameter is defined as repeatable (RFC 8707's `resource` and RFC 8693's `audience`, for example). In product mode this service never picks one value and discards the rest. In development mode the OAuth authorization and token endpoints take the last value instead, unless the realm is in OAuth 2.1 mode ([OAuth 2.0 and OpenID Connect](oauth-oidc.md)). In product mode, SAML 2.0, SAML 1.1 and WS-Federation also refuse a parameter given in both the query string and the body. |
| **Parameter names that pollute objects** | `__proto__` and similar names are refused everywhere. |
| **Unknown parameters** | Ignored on protocol endpoints, because RFC 6749 and OpenID Connect require it. On the [management](management-api.md#query-parameters-and-headers), [account](account-api.md#what-a-request-may-name), [sign-in](authn-api.md#what-a-request-may-name) and [report](reporting.md#what-a-request-may-name) APIs, a query parameter the operation does not list, a value that does not fit its declared type, and a custom header nothing declares are each refused with a 400, and so is an unknown member of a JSON body the operation's schema closes. |
| **Body size** | 5 MB at most, and less wherever a field states a limit. |
| **Request line and headers** | A request line or headers longer than the HTTP parser accepts get `431`, and a request it cannot parse gets `400`. The answer is written before the connection closes, so a client reads the status rather than a reset connection. |

## Limits by kind of value

| Kind | Longest accepted | Used for |
|---|---|---|
| Identifier | 256 | a `client_id`, a realm id, an application id, a `kid` |
| Name | 256 | a username, a group name, a principal name |
| Token | 4,096 | an authorization code, a token, an artifact |
| URI | 2,048 | a redirect URI and any other address |
| Scope | 2,048 | a space-separated list of scopes |
| Text | 65,536 | a policy, a PEM block, an LDIF fragment |
| Message | 1,048,576 | a SAML message, a SOAP envelope, an XACML document |
| Anything else | 4,096 | a field with no limit of its own |

## Formats

| Input | Rule |
|---|---|
| Redirect URIs | Must be absolute, with no fragment. `javascript:`, `data:` and similar schemes are refused. |
| Origins | A scheme, a host and an optional port, and nothing else. |
| Distinguished names | Limited in length and free of NUL characters. Values are escaped whenever a DN is built from them. |
| XML | Parsed with no external entities and no document type declaration. |
| Compressed messages | Inflated up to a fixed limit, so a small message cannot expand without bound. |
| Passwords | The realm's [password policy](authentication.md#passwords). |
| Text this service sends back | A directory entry's `description`, and an application permission's name or description, may not contain anything shaped like one of this service's [error codes](error-codes.md) (`STS-…-NNNN`). A code is recorded and never sent, so such a value is refused and not stored, and the refusal does not repeat it. A `description` is checked on an LDAP write too; a permission written with `ldapmodify` is not. |

## Checks across fields

Some values are valid alone and wrong together. These are the combinations the
service checks. A failure is refused, with the error the specification names,
if it names one, and otherwise `400`.

| Where | The rule |
|---|---|
| Client registration | `grant_types` and `response_types` must agree. `jwks` and `jwks_uri` are not both accepted, and a `jwks_uri` must be https. A `native` client's redirect URIs must be loopback `http` or a private-use scheme, and a `web` client using the implicit grant must use `https` and not `localhost` |
| An authorization request | `request` and `request_uri` are not both accepted |
| A code redeemed | A code issued with PKCE needs its `code_verifier`. A code is bound to the client and redirect URI it was issued for |
| A refresh grant | A DPoP-bound refresh token needs a DPoP proof with the same key |
| Rich authorization | An `amount` needs its `currency` |
| An OpenID4VCI request | `credential_identifier` and `credential_configuration_id` are not both accepted. A proof may not carry both a `jwk` and a `kid` |
| An ACME request | A JWS carries exactly one of `jwk` and `kid`, the one the resource takes |
| HTTP/2 | `:authority` and `Host` must name the same host |
| WS-Trust | `OnBehalfOf` and `ActAs` are not both accepted |
| Kerberos | `PA-FOR-USER` and `cname-in-addl-tkt` are not both accepted |
| WebAuthn settings | `webauthn.pqcAlongsideClassical` and `webauthn.pqcOnly` cannot both be on. A passkey policy's `lanes` must be consistent with its algorithms |
| Certificate authoring | Reusing a key pair needs both key boxes filled in |
| Settings for cells | A cell's id needs a jurisdiction, and `cells.peers` may not name this cell |
| Listeners | Applications that share the sign-on cookie on different host names need `authn.cookieDomain`. `oidfed` must be on the listener `oauth-oidc` is advertised on |
| Risk datasets | A file's extension must fit the format chosen |
| Custom attributes | Portal-editable implies portal-visible, and the two are stored that way |
| A person's values | Each custom attribute's value is checked against its syntax, and the realm's attribute policy says which attributes a person must hold |

The service does not check that free-form values in a person's profile agree
with each other: a postal code against a city, for example. It stores what the
directory is given. If your deployment needs that, enforce it in the system that
provisions the data.

## The rules for each operation

The [OpenAPI reference](openapi/) gives, for every operation of the management,
account, sign-in and report APIs, each parameter and body member with its type
and limits. Requests are validated against those same definitions, and so are
the answers. The protocol endpoints follow their specifications; see
[Endpoints](endpoints.md).

A refused request gets the specification's own error where there is one, or a
`400` that says what was wrong. The reason is logged under an
[error code](error-codes.md).
