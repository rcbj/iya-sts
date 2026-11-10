---
title: Input validation
---

# Input validation

Every request this service accepts is checked for its shape before anything acts
on it. Shape is checked the same way in development and product mode. Whether a
client, a person or a password is known or correct is a separate question, and
[What is not checked](what-is-not-checked.md) covers it.

## Rules every request follows

| Rule | What happens |
|---|---|
| **Control characters** | None are allowed in a query parameter, path parameter or header. In a body field, tab, newline and carriage return are allowed, and nothing else below U+0020. |
| **A repeated parameter** | Refused, unless that parameter is defined as repeatable (RFC 8707's `resource` and RFC 8693's `audience`, for example). This service never picks one value and discards the rest. In product mode, SAML 2.0, SAML 1.1 and WS-Federation also refuse a parameter given in both the query string and the body. |
| **Parameter names that pollute objects** | `__proto__` and similar names are refused everywhere. |
| **Unknown parameters** | Ignored in a query string and on protocol endpoints, because RFC 6749 and OpenID Connect require it. An unknown member of a JSON body on the management API is refused. |
| **Body size** | 5 MB at most, and less wherever a field states a limit. |

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
