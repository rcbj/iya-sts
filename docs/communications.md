---
title: Communication inventory
nav_order: 15
---

# Communication inventory

This page lists every connection iya-sts accepts and every connection it makes:
who it authenticates and what it carries. It describes product mode.

`GET /admin/sts-metadata` lists every HTTP endpoint from the running service.
[Listeners](listeners.md) covers ports and which application answers on each.

## Inbound

| Port (default) | Protocol | Who connects | How they are authenticated | What it carries |
|---|---|---|---|---|
| 8081, `global.port` | HTTPS | Browsers, applications, API clients | Per endpoint: session cookie, client authentication, token, DPoP, mutual TLS | Every HTTP protocol, the console and the portal |
| Custom listeners | HTTPS | As you define | `clientAuth` on the listener, then per endpoint | Hosted applications mapped to them |
| 8082 | Plain HTTP | Anyone | None. RFC 5280, RFC 5019 and RFC 8894 expect it | CRLs, OCSP, issuer certificates, SCEP |
| 88, TCP and UDP | Kerberos | Clients | Kerberos pre-authentication | Tickets |
| 636 | LDAPS | Directory clients | Simple bind, app password, or SASL EXTERNAL with a client certificate | Directory operations |
| 389 | Plain LDAP | Directory clients | Off in product (`ldap.plainListener`). On, it answers only the root DSE in product | Root DSE |
| SPIFFE sockets | gRPC, per realm | Workloads and agents | Workload API has no authentication by specification, SPIRE Server API needs an X509-SVID | SVIDs and bundles |
| Cell channel | HTTPS, mutual TLS 1.3 | Other cells | Their certificate | Cell traffic, when cells are configured |
| Embedded debugger, 8444 | HTTPS | Administrators | A token only console administrators are issued | The debugger, when installed |
| Unix socket | Internal | Request workers | Local to the container | Dispatched requests |

The remote PEP container connects in over mutual TLS.

## Outbound: infrastructure you configure

| Connects to | Named by | Authenticates | Carries |
|---|---|---|---|
| The database (PostgreSQL) | `persistence.databaseUrl` | The database's certificate, verified; a password from `persistence.databasePasswordProvider` | The store |
| The secret store or key management service | `keys.kekProvider` and related settings | The service's client certificate or cloud identity | Key wrapping, secrets |
| A mail relay or provider | `mail.transport` | The transport's credential. Verified TLS | Mail |
| The malware scanner | `malwareScan.url` | Verified TLS in product | Uploaded files |
| An attribute source's database | An attribute source, limited by `attributeSources.hostPatterns` | Verified TLS and its credential | Attribute lookups |
| Audit export destinations | The administrator, on Audit export | Verified TLS and the destination's token | Audit events |
| Secret push destinations | The administrator, on the destination | Verified TLS and its write credential | Rotated passwords |
| Outbound SCIM services | The administrator, on the client entry | The client's bearer token | Provisioning |
| Container task metadata | The platform, on ECS | None: a link-local address in the task | The task's addresses, for SPIFFE targeting |
| Risk dataset and FIDO downloads | `risk.mdsUrl`, dataset sources, `devices.androidStatusUrl` | Verified TLS | Public datasets |
| The Pwned Passwords API | `risk.breachApiUrl` | Verified TLS | A five-character prefix of a password's SHA-1 hash, and nothing else |
| CRL and OCSP responders | The certificate being checked, only once its chain verified | The answer's signature, from the certificate's issuer | Revocation lookups |

## Outbound: addresses an administrator or a partner names

A signed or configured record names these. A request cannot.

| Connects to | Named by |
|---|---|
| Federation partners: token, UserInfo, JWKS, metadata and sign-out endpoints | A federation relationship |
| Back-channel logout, CIBA notification, and provider command callbacks | A client's registration |
| Shared Signals receivers and a partner's transmitter | A stream, or a federation relationship |
| OpenID Connect claims providers | `/admin/claim-providers` |
| OpenID Federation Trust Chain and Entity Collection | The realm's Trust Anchors and subtree, and bounded by `oidfed.maxChainDepth` and related limits |
| A SAML metadata lookup (MDQ) | `saml2.mdqBaseUrl`, with only the entityID as a path |
| A GNAP resource server's owner lookup | The resource server's entry |
| Sigstore registries for image signatures | `spiffe.dockerSigstoreAllowedRegistries` |
| A partner's profile photo | A partner's verified assertion, after sign-in, never awaited |

## Outbound: locations a caller can name

Some URLs below are supplied by a caller, such as GNAP's push address. In each
case the listed condition decides whether it is dialled, and in product mode an
internal address is always refused.

| What | Condition |
|---|---|
| A client's `jwks_uri` | The registered value, when a key is needed |
| GNAP `interact.finish` push URI | Named by the client in its grant request. Held to `gnap.pushFinish` and https in product |
| XACML PEP notification URL | Configured for the PEP. Held to the same address rules |
| A `sector_identifier_uri` | Fetched once, when the client registers it |
| An RFC 9101 `request_uri` | Only the address the client registered |
| A status list in a credential | Only under a signature from a trusted issuer |
| RFC 9728 metadata import | An administrator with Admin Write, by address |
| A `did:web` in SIOPv2 | Only when enrolled, or during a person's own enrolment after every other check passed |
| A person's WebFinger host | Off by default per relationship (`fedWebFinger`). The result must fall within the partner |
| SPIFFE `http_challenge` | Only if the realm's `spiffe.httpChallengeAllowedDnsPatterns` matches |
| An AuthZEN callback | Must equal a URL registered for the requesting PEP |
| A Bluesky account's data server | Reached only with a DID the relationship's issuer answered, from `federation.atprotoPlcDirectory` |

These requests follow the same rules in product mode: no redirects, internal
and private addresses refused with the connection pinned, a response size cap
(`federation.maxResponseBytes`) and a timeout (`federation.outboundTimeoutMs`).
Each is https with verified TLS, except SPIFFE's `http_challenge`, which fetches
a 64-byte value over plain HTTP by its nature. `federation.outbound` turns off
the partner back channels.

**To limit these requests to hosts you name**, set
`security.outboundAllowedHosts` to a comma-separated list: an exact host name, or
a leading dot for a whole domain (`.example.com`). A request to any other host
is refused before its name is resolved, in either mode; in development a listed
host is still dialled even when it is an internal address. Empty, the default,
allows any public host. The CRL and OCSP addresses a certificate names obey the
same list in either mode: an http(s) address whose host is not on it is not
dialled. See [PKI](pki.md).

## What is not reached

Nothing dereferences WS-Federation's `wreqptr`. Nothing dials a service
provider's metadata address while issuing.

## Related

* [Listeners and hosted applications](listeners.md)
* [TLS](tls.md)
* [Docker Compose](docker-compose.md#ports)
* [Federation](federation.md)
