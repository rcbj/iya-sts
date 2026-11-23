---
title: Accessing the debugger
nav_order: 2
---

# Accessing the debugger

* TOC
{:toc}

## Where it is

The debugger is served on a listener of its own:

| What | Address |
|---|---|
| The debugger | `https://<host>:8444/` |
| Its api | `https://<host>:8444/api/` |
| Your debugger session, and sign-out | `https://<host>:8444/_sts/` |
| Its status, for an operator | `/admin/debugger` on the console, and `GET /admin-api/debugger` |

It uses the main port's scheme and certificate. A browser that already trusts
`https://<host>:8081` trusts this port as well.

The debugger works out its own addresses from the address the browser used,
so the addresses its pages fill in are on this origin. When you register the
debugger as a client of an identity provider, use these:

| The debugger as | Address |
|---|---|
| OAuth 2.0 / OpenID Connect redirect URI | `https://<host>:8444/callback` |
| SAML service provider entityID | `https://<host>:8444/saml/sp` |
| SAML assertion consumer service | `https://<host>:8444/api/samlacs` |
| SAML single logout | `https://<host>:8444/api/samlslo` |
| WS-Federation reply address | `https://<host>:8444/api/wsfed` |
| Shared Signals push receiver | `https://<host>:8444/api/ssf/receiver/<id>` |

The [user guides](index.md) were written for the standalone debugger, at
`https://localhost:3000` with its api at `https://localhost:4000`. The copies
here are rewritten to the addresses above, but the screenshots still show the
standalone address.

## Who may use it

**Console administrators, and nobody else.** That means a member of the Admin
Read or Admin Write group of the default realm. No setting opens it to
anybody else.

* **You sign in through this service.** Opening `https://<host>:8444/` sends
  the browser through this service's authorization code flow, as the client
  `sts-debugger-ui`, and back. That client is confidential: its tokens stay on
  this service, and the browser holds only a session cookie.
* **It is single sign-on.** A browser already signed in to the console on the
  same host goes straight in, with no second prompt. A cookie belongs to a
  host, not to a port.
* **The roles are checked on every request.** A role taken away from somebody
  already signed in stops working at their next request. Somebody who signs in
  without a console role is shown *The debugger is for administrators*, with a
  way to sign out.
* **The debugger accepts no access token.** The gate reads its own session
  cookie and nothing else, so the debugger's own `Authorization` and `DPoP`
  headers pass through to its api untouched. Examples are a UserInfo call's
  Bearer token and introspection's Basic client credentials.
* In **development mode**, a console role held only because nobody holds one
  yet does not count. The console opens to everybody while its role groups are
  empty; the debugger does not. Grant somebody a role on `/admin/rbac` first.
* In **product mode**, the bootstrap administrator is refused until it has
  signed in to `/admin` with its password once.

To sign out of the debugger, use the button at `https://<host>:8444/_sts/`.
Signing out of the console ends the debugger session too.

## What it can reach

The debugger's api makes the calls a page asks it to make: token requests,
SAML and WS-Trust calls, Kerberos, LDAP, TLS handshakes and gRPC. It is a
separate process, which this service starts and stops.

* **Development mode**: no limit. It may dial anything, private networks
  included.
* **Product mode**: it may dial **only this service's own addresses**, plus
  the CIDR ranges in `debugger.allowedDestinations`
  (`STS_DEBUGGER_ALLOWED_DESTINATIONS`, comma-separated). To test another
  identity provider from a product-mode service, add its address range there.

A call a page makes from the browser is not limited by this, because it goes
from your browser rather than from this service. The OAuth 2.0 and WS-Trust
pages choose with **Initiate … From**: front end (browser) or back end
(proxy).

## Turning it on

The debugger is part of every image built since iya-sts #1743. Whether it
runs is decided by `debugger.enabled` (`STS_DEBUGGER_ENABLED`), which is read
once, at start:

| Value | Effect |
|---|---|
| `auto` (the setting's default) | On in development mode, off in product mode |
| `on` | On in either mode |
| `off` | Off |

**Both compose files turn it on.** [The compose stack](../docker-compose.md)
and the [quick start](../getting-started.md#with-postgresql-and-openbao-from-published-images)
run in product mode, where `auto` would leave it off. So they set
`STS_DEBUGGER_ENABLED=on` and publish port 8444. With either one,
`docker compose up` serves it.

From `docker run`, set the variable and publish the port:

```bash
docker run --rm -p 8081:8081 -p 8444:8444 \
  -e STS_DEBUGGER_ENABLED=on iyasec/iya-sts
```

**Publish the same port number on both sides.** The sign-in sends the browser
back by the host and port it used. To move the debugger, set
`STS_DEBUGGER_PORT` and publish that number on both sides. In the compose
files the variable is `STS_DEBUGGER_PORT` or `DEBUGGER_PORT`, and it moves
both sides. If a proxy stands in front, so that a browser reaches the debugger
somewhere else, set `debugger.publicBaseUrl` (`STS_DEBUGGER_PUBLIC_BASE_URL`)
to that scheme, host and port.

Confirm it on `/admin/debugger`, which shows whether the debugger is embedded,
whether its listener is bound, its port and origin, and what its api process
is doing. The log says `debugger: the identity protocol debugger is on port
8444` at start. Every setting is in the
[configuration reference](../configuration.md#protocol-debugger).

## Leaving it out of a production deployment

There are two levels, and a production deployment should use both.

**1. Off at runtime.** Set `STS_DEBUGGER_ENABLED=off`, or leave the setting at
`auto` in product mode and do not use the compose files' `on`. Do not publish
port 8444. With it off, nothing listens on that port and no api process is
started. The debugger's application entry, `sts-debugger-ui`, is still seeded,
but it grants nothing: nothing answers at its redirect URI.

```bash
# in the .env beside either compose file
STS_DEBUGGER_ENABLED=off
```

**2. Out of the image.** The image takes the debugger from a published image
at build time, through the build argument `DEBUGGER_IMAGE`. Its default is
`ghcr.io/rcbj/id-proto-debugger-embedded:0.9.3`. Build with `debugger-none`,
and the image carries no debugger files at all:

```bash
docker build --build-arg DEBUGGER_IMAGE=debugger-none -t iya-sts:no-debugger .
# or, with the compose stack
DEBUGGER_IMAGE=debugger-none docker compose build sts
```

An image built that way starts as it always did. `/admin/debugger` says the
debugger is not installed (`STS-DBG-0015` in the log if it is turned on
anyway), and nothing else in the service changes.

To build with a different debugger, such as a newer release or a local build
of it, pass its image instead:

```bash
DEBUGGER_IMAGE=ghcr.io/rcbj/id-proto-debugger-embedded:<version> \
  docker compose build sts
```

## Related

* [The protocol debugger](index.md): the chapter, and the user guides.
* [Admin console](../admin-console.md#the-embedded-protocol-debugger): the
  debugger's console page.
* [Applications](../applications.md#the-applications-that-are-this-service):
  `sts-debugger-ui`, the client it signs in as.
* [The compose stack](../docker-compose.md): ports and variables.
