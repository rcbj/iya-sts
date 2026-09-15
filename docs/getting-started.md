---
title: Getting started
nav_order: 2
---

# Getting started

## Clone it with `--recursive`

```bash
git clone --recursive https://github.com/rcbj/mock-sts.git
```

The LDAP directory is built on [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs),
which is a git **submodule** pinned as `"ldapjs": "file:node-ldapjs"` in
`package.json`. Without `--recursive` the directory exists but is empty, `npm
install` installs a package with no `main`, and the failure arrives at startup as
`Cannot find module 'ldapjs'` — a message that names a package rather than a
submodule.

If you have already cloned:

```bash
git submodule update --init --recursive
```

`--recursive` rather than `--init` alone matters if you reached this repository
through the [OAuth2/OIDC Debugger](https://idptools.com), where it is itself a
submodule: a plain `--init` there stops one level short of this one.

## Run it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js
```

`CONFIG_FILE` selects a file in `env/` — `local.js`, `test.js` or
`docker-tests.js`. At the default `debug` level every endpoint call and every
artifact before and after signing is logged. That is the point of a mock, so
resist quietening it; `env/test.js` is the quiet one if you need it — and it is
what the three test launchers select for themselves, since a suite that passes
throws its log away and the level is about half of this service's CPU. Ask any
of them for `--sts-log-level=debug` (or `STS_LOG_LEVEL=debug`) and the whole
record comes back, appconfig file and all.

The path is relative to the repository root, wherever you run node from and
whichever module reads it. That has been true since the modules moved into
subdirectories, and it is `common/config_file.js` that keeps it true.

## The ports

Only the first is HTTP. The rest are separate listeners, and several of them
will not bind on an ordinary user account.

| Port | What | Setting | Environment |
|---|---|---|---|
| 8081 | The main service — every protocol endpoint, the console, the API. **HTTPS**, since every appconfig file here sets `global.https`; `STS_HTTPS=false` makes it plain HTTP | `global.port` | `STS_PORT` |
| 88 (TCP+UDP) | The Kerberos KDC | `krb5.kdcPort` | `KRB5_KDC_PORT` |
| 8888 | The Kerberos-protected test service | `krb5.servicePort` | `KRB5_SERVICE_PORT` |
| 389 | The LDAP directory | `ldap.port` | `LDAP_PORT` |
| 636 | The same directory over TLS (LDAPS) | `ldap.tlsPort` | `LDAPS_PORT` |
| 8443 | TLS, asking for a client certificate | `tls.port` | `STS_TLS_PORT` |
| 9443 | Mutual TLS, requiring one | `tls.mutualPort` | `STS_MTLS_PORT` |
| 8092 | The SPIFFE Workload API over gRPC | `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` |
| 8181 | The SPIRE Server API over gRPC | `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` |
| — | The Workload API's **Unix socket**, at `/tmp/spire-agent/public/api.sock` | `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` |

**A port that will not bind does not stop the service.** 88, 389 and 636 all need
root, and a host run is usually not root. The failure is RECORDED rather than
thrown — a `require` that throws would take the whole service down where a route
cannot — and each listener publishes its own result, because "389 is up and 636
is not" is the ordinary outcome and one flag could only report one of them:

- `GET /admin/ldap/service` — `listening` / `listenError`, and a `tls` object with its own pair
  (an admin console page since 2026-09-01, so it needs a session; `GET
  /admin-api/ldap/service` is the same object and is not gated)
- `GET /tls` — the same for 8443 and 9443
- `GET /spiffe` — all four SPIFFE sockets, separately
- `GET /krb5/principals` — the KDC

So a page answering 200 is not evidence that the listener behind it came up. Read
the flag.

## Running two copies

Everything is in memory and nothing is shared, so a second instance is just a
second process — but every default port collides. Give the second one its own:

```bash
CONFIG_FILE=./env/local.js \
  STS_PORT=8091 LDAP_PORT=3891 LDAPS_PORT=6391 \
  KRB5_KDC_PORT=8891 KRB5_SERVICE_PORT=8891 \
  STS_TLS_PORT=8493 STS_MTLS_PORT=9493 \
  STS_SPIFFE_WORKLOAD_PORT=8093 STS_SPIFFE_SERVER_PORT=8182 \
  STS_SPIFFE_WORKLOAD_SOCKET=/tmp/spire-agent-2/public/api.sock \
  node server.js
```

The SPIFFE Unix socket is the one thing this service puts on a filesystem, and
two instances sharing a path is the one collision that is not a bind error: the
second unlinks the first's socket as "stale" and takes it over. It says so in the
log when it does.

## In a container

```bash
docker build -t rcbj/sts .
docker run --rm -p 8081:8081 rcbj/sts
```

The image copies the whole build context (`.dockerignore` decides what is in it)
so that adding a protocol directory cannot be forgotten, installs with
`--omit=dev`, and defaults `CONFIG_FILE` to `./env/local.js`. `EXPOSE` documents
every port above; publishing them is the caller's decision.

The Workload API's Unix socket is inside the container. To reach it from the host
or another container, mount its directory as a volume — publishing 8092 is the
alternative and needs the client pointed at `tcp://host:8092` explicitly.

## Confirming it works

```bash
curl -sk https://localhost:8081/healthcheck
curl -sk -L https://localhost:8081/admin/sts-metadata | head -40
```

**The `-k` is the bootstrap and not a shrug.** The main port is TLS on a
self-signed certificate this service generates at every start, so nothing that
existed before this process can verify it — and with `global.https` on there is
no plain listener left to fetch it from either. One unverified call gets it, and
everything after that can be verified:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
curl --cacert /tmp/sts.pem https://localhost:8081/healthcheck
export NODE_EXTRA_CA_CERTS=/tmp/sts.pem      # for a node client
```

It is the same certificate 8443, 9443 and LDAPS 636 serve, so that is one trust
decision for the whole service rather than four.

The second one is **behind the console gate**, which is unconditional: with no
session it answers a 302 to the sign-in screen, which is why the `-L` is there
and why what comes back is that screen rather than the page. Open it in a
browser and sign in — any username, since this service checks no password in
its default `development` mode. There is no setting that opens the console;
`admin.authRequired` was removed on 2026-09-06 when `global.mode` took over the
question. `/admin-api` reads the same service for a program, and takes an OAuth
2.0 access token of its own.

A protocol you can drive end to end in a browser with nothing else installed is
**SAML 2.0**: open `https://localhost:8081/saml2/sp`, pick one of the three bindings, sign
in with any username, and the mock service provider verifies the response it gets
back check by check. `https://localhost:8081/saml2/metadata` is the identity provider
metadata; `https://localhost:8081/saml2/metadata/anything-you-like` is a document of its
own for a service provider by that name, minted on the spot.

`/admin/sts-metadata` is the sharper of the two. It reads the endpoint list off the
live Express router, so it answers only once every protocol module has registered
its routes — a module that loaded but registered nothing shows up there and not
in the liveness probe. Add `?format=json` and look at `undocumentedPaths`,
`stalePaths` and `unknownSpecIds`: all three empty is the service agreeing with
its own description of itself.

## Which build am I running?

Every page says so, and so does the log. The version is **M.N.O** — a release
from the repo-root `VERSION` file plus a build number:

```
0.1.20260906143205
│ │ └── the build: the UTC instant the image was built (or BUILD_NUMBER)
│ └──── minor
└────── major
```

The quickest ways to read it:

```bash
curl -sk https://localhost:8081/admin-api | head -8   # version, build, commit, stamped
curl -sk https://localhost:8081/                      # the front page's version line
node common/version.js                                # from a checkout, without running it
```

It is also in the foot of every admin console page and every user portal page,
in the first paragraph of `/admin/sts-metadata`, and in the first line the
service logs when it starts.

**The remote XACML PEP reports one too**, if you are running it
(`docker compose --profile xacml up`). It is on that container's own `GET /`
and in the Version column of `/admin/xacml/peps` on this service's console:

```bash
curl -s http://localhost:9090/ | head -20      # the PEP's own page
```

Its **M.N always matches** this service's — both images are built from one tree
and one `VERSION` file — while its **build number is its own**, because they are
two images built at two instants. So a different release on that row is a PEP
left behind across an upgrade, and a different build number is just two
artifacts. Pass one `BUILD_NUMBER` to both builds to say they are one release.

**`stamped` is the field worth knowing about.** A container reports a build
number that was fixed when the image was built, so restarting it reports the
same one. A checkout run with `node server.js` was never built at all — it
computes a number when the process starts and reports `stamped: false`, and
every page says so in as many words. Two instances of the same release with
different build numbers mean nothing if neither was ever built.

To give an image a build number and a commit of your own:

```bash
BUILD_NUMBER=1234 GIT_COMMIT=$(git rev-parse HEAD) docker compose build sts
```

The commit is a build argument rather than something the image works out,
because the build context deliberately carries no `.git`.
