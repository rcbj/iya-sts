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
| **A repeated parameter** | Refused, unless that parameter is defined as repeatable (RFC 8707's `resource` and RFC 8693's `audience`, for example). This service never picks one value and discards the rest. |
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

## The rules for each operation

The [OpenAPI reference](openapi/) gives, for every operation of the management,
account, sign-in and report APIs, each parameter and body member with its type
and limits. Requests are validated against those same definitions, and so are
the answers. The protocol endpoints follow their specifications; see
[Endpoints](endpoints.md).

A refused request gets the specification's own error where there is one, or a
`400` that says what was wrong. The reason is logged under an
[error code](error-codes.md).
