---
title: Getting started
nav_order: 2
---

# Getting started

## Clone it with `--recursive`

```bash
git clone --recursive https://github.com/rcbj/iya-sts.git
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
```docker-compose up```

or  

```docker compose up```

or

```bash
docker build -t iya-sts .
docker run --rm -p 8081:8081 -e CONFIG_FILE=./env/local.js iya-sts
```

**From an image, not from a checkout.** Part of the service
is written in TypeScript and is compiled only while the image is built, so
`node server.js` on a checkout stops and says so. Every setting below that is
shown as an environment variable is passed with `-e`.

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
| 8081 | The main service — every protocol endpoint, the console, the API. **HTTPS**, since every appconfig file here sets `global.https`; `STS_HTTPS=false` makes it plain HTTP. It asks every connection for a client certificate and requires none, so it is also where mutual TLS happens | `global.port` | `STS_PORT` |
| 88 (TCP+UDP) | The Kerberos KDC | `krb5.kdcPort` | `KRB5_KDC_PORT` |
| 8888 | The Kerberos-protected test service | `krb5.servicePort` | `KRB5_SERVICE_PORT` |
| 389 | The LDAP directory | `ldap.port` | `LDAP_PORT` |
| 636 | The same directory over TLS (LDAPS) | `ldap.tlsPort` | `LDAPS_PORT` |
| 8092 | The SPIFFE Workload API over gRPC (product mode: only where `spiffe.workloadTcpSourceAuthenticated` is on) | `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` |
| 8181 | The SPIRE Server API over gRPC | `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` |
| — | The Workload API's **Unix socket**, at `/tmp/spire-agent/public/api.sock` | `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` |

**A port that will not bind does not stop the service.** 88, 389 and 636 all need
root, and a host run is usually not root. The failure is RECORDED rather than
thrown — a `require` that throws would take the whole service down where a route
cannot — and each listener publishes its own result, because "389 is up and 636
is not" is the ordinary outcome and one flag could only report one of them:

- `GET /admin/ldap/service` — `listening` / `listenError`, and a `tls` object with its own pair
  (an admin console page, so it needs a session; `GET
  /admin-api/ldap/service` is the same object and is not gated)
- `GET /spiffe` — all four SPIFFE sockets, separately
- `GET /krb5/principals` — the KDC

So a page answering 200 is not evidence that the listener behind it came up. Read
the flag.

**Two TLS ports have left this table.** 8443 (`tls.port`) asked for a
client certificate and never required one; 9443 (`tls.mutualPort`) required one
at the handshake. Both listeners and both settings were deleted, and neither
setting has a replacement — a deployment that still sets one gets an "unknown
setting" warning at startup. The main port already asked for a client
certificate and required none, so that half moved nowhere; `GET /tls/sign-in`
signs the holder of a verified one in. **Nothing requires a certificate at the
handshake any more**, deliberately: the port that would have to do it carries
every other protocol, so a certificate that does not verify is refused where it
is USED — at the token endpoint under RFC 8705, at `/xacml`, at `/scim/v2` and
at `/tls/sign-in`.

## Running two copies

Everything is in memory and nothing is shared, so a second instance is just a
second process — but every default port collides. Give the second one its own:

```bash
docker run --rm -p 8091:8091 \
  -e CONFIG_FILE=./env/local.js \
  -e STS_PORT=8091 -e LDAP_PORT=3891 -e LDAPS_PORT=6391 \
  -e KRB5_KDC_PORT=8891 -e KRB5_SERVICE_PORT=8891 \
  -e STS_SPIFFE_WORKLOAD_PORT=8093 -e STS_SPIFFE_SERVER_PORT=8182 \
  -e STS_SPIFFE_WORKLOAD_SOCKET=/tmp/spire-agent-2/public/api.sock \
  iya-sts
```

In separate containers the default ports no longer collide inside them; the
different values matter for what you publish with `-p`.

The SPIFFE Unix socket is the one thing this service puts on a filesystem, and
two instances sharing a path is the one collision that is not a bind error: the
second unlinks the first's socket as "stale" and takes it over. It says so in the
log when it does.

## In a container

```bash
docker build -t iya-sts .
docker run --rm -p 8081:8081 iya-sts
```

The image copies the whole build context (`.dockerignore` decides what is in it)
so that adding a protocol directory cannot be forgotten, installs with
`--omit=dev`, and defaults `CONFIG_FILE` to `./env/local.js`. `EXPOSE` documents
every port above; publishing them is the caller's decision.

**The service runs as `sts`, uid and gid 10001, not as root.** It still binds
88, 389 and 636 inside the container, because Docker sets
`net.ipv4.ip_unprivileged_port_start=0` in every container's network
namespace; a runtime that does not set it needs
`--sysctl net.ipv4.ip_unprivileged_port_start=0`. The one directory the
service writes under its tree, `/usr/src/sts/data`, belongs to that user, so
a volume mounted there must be writable by uid 10001. A file you mount for
the service to read, such as a key-encryption key file, must be readable by
uid 10001.

**The image's JavaScript carries no comments.** The build takes them out of
every `.js` it ships, compiled from TypeScript or not, because Node keeps the
source text of every module in memory for as long as the process runs, and
this repository's comments were about 80 MB of every process's heap. Nothing
else is changed: no name is shortened and no module is bundled. Every line
break is kept, so **a line number in a stack trace from the image is the line
number in the repository** — read the comments there. A column number can
differ on a line that had a comment in the middle of it. The copyright and
licence headers go with the other comments; `LICENSES/` and `REUSE.toml` are
still in the image. The build also writes characters such as `—` in string
literals as `\u2014` escapes, which gives the same strings and halves the
memory Node needs for each file's source; a line in the image can therefore
read differently from the repository while meaning the same.

The Workload API's Unix socket is inside the container. To reach it from the host
or another container, mount its directory as a volume — publishing 8092 is the
alternative and needs the client pointed at `tcp://host:8092` explicitly.

## With PostgreSQL and OpenBao, from published images

`docker compose up` in a checkout builds the image and starts the service the
way a deployment runs it: **product mode**, its store in **PostgreSQL**, and
its key-encryption key and database password in an **OpenBao** secret store.
[The compose stack](docker-compose.md) describes that file: its services,
ports, volumes and variables. The same stack can be run from published images
alone, with no checkout and nothing built:

| Image | From |
|---|---|
| `iyasec/iya-sts` | Docker Hub; the same image is `ghcr.io/rcbj/iya-sts` |
| `postgres:18` | Docker Hub (official) |
| `openbao/openbao` | Docker Hub |

The database's TLS and schema scripts and OpenBao's configuration and seeder
are in the `iya-sts` image, so two one-shot containers of that image copy them
into volumes before anything else starts.

Put this in a directory of its own as `docker-compose.yml`:

```yaml
name: iya-sts

services:
  postgres-init:
    image: iyasec/iya-sts:${IYA_STS_TAG:-latest}
    restart: "no"
    user: "0"
    volumes:
      - db-initdb:/out/initdb
      - db-share:/out/share
    command:
      - sh
      - -c
      - |
        cp postgres/require-tls.sh /out/initdb/00-require-tls.sh
        cp postgres/apply-schema.sh /out/initdb/10-apply-schema.sh
        cp postgres/generate-tls.sh postgres/schema.sql /out/share/
        chmod 755 /out/initdb/*.sh /out/share/generate-tls.sh
        chmod 644 /out/share/schema.sql

  postgres:
    image: postgres:18
    depends_on:
      postgres-init:
        condition: service_completed_successfully
    environment:
      POSTGRES_USER: sts
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: sts
      STS_DB_APP_USER: sts_app
      STS_DB_APP_PASSWORD: ${STS_DB_APP_PASSWORD:?set STS_DB_APP_PASSWORD in .env}
    volumes:
      - db-data:/var/lib/postgresql
      - db-initdb:/docker-entrypoint-initdb.d:ro
      - db-share:/usr/local/share/sts:ro
    command:
      - bash
      - -c
      - >-
        /usr/local/share/sts/generate-tls.sh &&
        exec docker-entrypoint.sh postgres
        -c ssl=on
        -c ssl_cert_file=/var/lib/postgresql/tls/server.crt
        -c ssl_key_file=/var/lib/postgresql/tls/server.key
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sts -d sts"]
      interval: 5s
      timeout: 5s
      retries: 10

  openbao-tls:
    image: iyasec/iya-sts:${IYA_STS_TAG:-latest}
    restart: "no"
    user: "0"
    environment:
      STS_BAO_TLS_DIR: /openbao/file/tls
      STS_BAO_TLS_NAMES: openbao,localhost
      STS_BAO_TLS_IPS: 127.0.0.1
    volumes:
      - bao-file:/openbao/file
    command:
      - sh
      - -c
      - |
        node openbao/generate-tls.js
        mkdir -p /openbao/file/config
        cp openbao/bao.hcl /openbao/file/config/bao.hcl
        chown -R 100:1000 /openbao/file

  openbao:
    image: openbao/openbao:latest
    hostname: openbao
    depends_on:
      openbao-tls:
        condition: service_completed_successfully
    cap_add:
      - IPC_LOCK
    environment:
      BAO_STATIC_SEAL_CURRENT_KEY_ID: sts
      BAO_STATIC_SEAL_CURRENT_KEY: ${STS_BAO_SEAL_KEY:?set STS_BAO_SEAL_KEY in .env}
    volumes:
      - bao-file:/openbao/file
    command: ["server", "-config=/openbao/file/config/bao.hcl"]

  openbao-seed:
    image: iyasec/iya-sts:${IYA_STS_TAG:-latest}
    restart: "no"
    user: "0"
    depends_on:
      openbao:
        condition: service_started
    environment:
      STS_BAO_ADDR: https://openbao:8200
      STS_BAO_CA_FILE: /openbao/file/tls/server.crt
      STS_BAO_POLICY_FILE: /usr/src/sts/openbao/read-only.hcl
      STS_BAO_CLIENT_CN: sts
      STS_DB_APP_PASSWORD: ${STS_DB_APP_PASSWORD:?set STS_DB_APP_PASSWORD in .env}
      STS_ADMIN_API_CLIENT_SECRET: ${ADMIN_API_CLIENT_SECRET:-}
      STS_BAO_STARTUP_NODES: sts
      STS_BAO_STARTUP_DIR: /openbao/startup
      STS_BAO_PRINT_CREDENTIALS: "true"
    volumes:
      - bao-file:/openbao/file
      - bao-client:/openbao/client
      - bao-startup:/openbao/startup
    command: ["node", "openbao/seed.js"]

  sts:
    image: iyasec/iya-sts:${IYA_STS_TAG:-latest}
    hostname: sts
    user: "0"
    sysctls:
      - net.ipv4.ip_unprivileged_port_start=0
    depends_on:
      postgres:
        condition: service_healthy
      openbao-seed:
        condition: service_completed_successfully
    ports:
      - "${STS_PORT:-8081}:8081"
      - "${PKI_PORT:-8082}:8082"
    environment:
      STS_MODE: product
      STS_PERSISTENCE_MODE: postgres
      STS_DATABASE_URL: postgres://sts_app@postgres:5432/sts?sslmode=require
      STS_DATABASE_PASSWORD_PROVIDER: vault
      STS_DATABASE_PASSWORD_REF: secret/data/sts
      STS_DATABASE_PASSWORD_FIELD: databasePassword
      STS_KEYS_KEK_PROVIDER: vault-transit
      STS_KEYS_KEK_VAULT: https://openbao:8200
      STS_KEYS_KEK_REF: sts-kek
      STS_KEYS_VAULT_CLIENT_CERT: /run/secrets/openbao/client.crt
      STS_KEYS_VAULT_CLIENT_KEY: /run/secrets/openbao/client.key
      STS_KEYS_VAULT_CA_CERT: /run/secrets/openbao/bao-ca.crt
      PKI_DISTRIBUTION_PORT: "${PKI_PORT:-8082}"
      STS_ADMIN_BOOTSTRAP_PASSWORD: ${STS_ADMIN_BOOTSTRAP_PASSWORD:-}
    volumes:
      - bao-client:/run/secrets/openbao:ro
      - bao-startup:/run/secrets/openbao-startup
      - sts-data:/usr/src/sts/data
    tmpfs:
      - /run/sts-startup:mode=0700,uid=10001,gid=10001
    command:
      - sh
      - -c
      - |
        find /usr/src/sts/data ! -user 10001 -exec chown 10001:10001 {} +
        STARTUP="$$(node openbao/startup-secrets.js)" || exit 1
        eval "$$STARTUP"
        exec setpriv --reuid=10001 --regid=10001 --clear-groups \
          --inh-caps=-all --bounding-set=-all --no-new-privs node server.js
    healthcheck:
      test: ["CMD-SHELL", "node -e \"require('https').get({host:'localhost',port:8081,path:'/healthcheck',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))\""]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 20s

volumes:
  db-data:
  db-initdb:
  db-share:
  bao-file:
  bao-client:
  bao-startup:
  sts-data:
```

Beside it, a `.env` file with three secrets of your own. The seal key unseals
OpenBao at every start: lose it and nothing sealed under it can be read again.

```bash
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
STS_DB_APP_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
STS_BAO_SEAL_KEY=$(openssl rand -base64 32)
EOF
chmod 600 .env
docker compose up -d --wait
```

`--wait` returns once `sts` is healthy, a minute or two on a first start.

* **Signing in.** The console's first account is `admin`, with a password
  generated on the first start and printed once in the log; it has to be
  changed at the first sign-in. To choose it instead, put
  `STS_ADMIN_BOOTSTRAP_PASSWORD=...` in `.env` before the first start.

  ```bash
  docker compose logs sts | grep -A6 'PRODUCT MODE BOOTSTRAP'
  ```

  Then open `https://localhost:8081/admin` and accept the certificate.
* **`/admin-api`, the first time.** The seeded `sts-management-api`
  client's secret is generated by the seeder on the first start and kept in
  OpenBao at `secret/sts-admin`. The service reads it once at each `up`,
  and its own OpenBao identity cannot read it at all. To read it yourself,
  take the **operator token** the seeder prints (read-only on that one path,
  for 24 hours):

  ```bash
  docker compose logs --no-log-prefix openbao-seed \
    | grep 'OPERATOR TOKEN' | tail -1 | jq -r .msg   # the token ends the line
  BAO_OPERATOR_TOKEN='<token>'

  SECRET=$(docker compose exec -T -e BAO_TOKEN="$BAO_OPERATOR_TOKEN" openbao \
    bao kv get -address=https://127.0.0.1:8200 \
      -ca-cert=/openbao/file/tls/server.crt \
      -field=adminApiClientSecret secret/sts-admin)
  curl -sk -u "sts-management-api:$SECRET" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode 'scope=admin:read admin:write' \
    --data-urlencode resource=https://localhost:8081/admin-api \
    https://localhost:8081/oauth2/token
  ```

  **Use that token once**, to create an application of your own with the
  `ADMIN_READ` and `ADMIN_WRITE` roles and a client secret, and get every
  later token as that application with the client credentials grant.
  [Management API → An application of your own](management-api.md#an-application-of-your-own-for-every-token-after-that)
  has the steps. To choose the management API secret instead of having it
  generated, put `ADMIN_API_CLIENT_SECRET=...` in `.env` before the first
  start; it goes to the seeder, not to the service.
* **The OpenBao recovery key.** On the first start the seeder prints the
  store's recovery key, once (`docker compose logs openbao-seed | grep
  'RECOVERY KEY'`), and then revokes the root token. Nothing on disk keeps
  either one. Keep the recovery key: `bao operator generate-root` needs it
  to make a root token again.
* **`docker compose up`, not `restart`.** Every `up` runs the seeder, which
  gives the service a new single-use start-up token. `docker compose restart
  sts` does not run the seeder, so the service starts without the pinned
  management API secret and mints one that nobody can read.
* **The service runs as uid 10001, not root.** The `sts` container starts as
  root only to take the start-up secret, then drops to uid 10001 with every
  capability removed before the service starts. A shell as that user can read
  the service's own OpenBao client credential (mode 0600), and no other
  secret on disk or in its environment.
* **Stopping it.** `docker compose down` keeps everything in the named
  volumes, and the next `up` comes back with the same directory, signing keys
  and sessions. `docker compose down -v` deletes it all.
* **Which build.** `IYA_STS_TAG` picks the image tag: `latest` is the newest
  build of `main`, and every build also has its `M.N.O`. `STS_PORT` and
  `PKI_PORT` move the two published ports.

What the checkout's own `docker-compose.yml` has and this does not: the optional
remote XACML PEP (the `xacml` profile), and the extra addresses a realm's own
SPIFFE listeners bind. Kerberos and LDAP are running but not published; add
`88`, `389` or `636` to `ports` to reach them from the host.
[Configuration](configuration.md) covers every setting the `environment` block
can take.

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

It is the same certificate LDAPS 636 and the embedded debugger's listener
serve, so that is one trust decision for the whole service rather than three.

The second one is **behind the console gate**, which is unconditional: with no
session it answers a 302 to the sign-in screen, which is why the `-L` is there
and why what comes back is that screen rather than the page. Open it in a
browser and sign in — any username, since this service checks no password in
its default `development` mode. There is no setting that opens the console;
`admin.authRequired` is gone; `global.mode` answers that question. `/admin-api` reads the same service for a program, and takes an OAuth
2.0 access token of its own.

A protocol you can drive end to end in a browser with nothing else installed is
**SAML 2.0**: open `https://localhost:8081/saml2/sp`, pick a response binding, sign
in with any username, and the mock service provider verifies the response it gets
back check by check. `https://localhost:8081/saml2/metadata` is the identity provider
metadata; `https://localhost:8081/saml2/metadata/anything-you-like` is a document of its
own for a service provider by that name, minted on the spot — in development mode
only. In product mode that is a 404 until the service provider is registered.

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


## First-Time Admin Login
Go to: ```https://localhost:8081```

Enter ```admin``` as the username.

Search the through startup logs for the following line:
```sts               | {"name":"sts","hostname":"sts","pid":1,"level":40,"msg":"=======================================================\nPRODUCT MODE BOOTSTRAP — THIS IS SHOWN ONCE AND NEVER AGAIN.\n\n  username: admin\n  password: *****************\n\nNobody in this realm's directory held a credential, so this one was generated so that the service is reachable. It is stored as a scrypt hash and CANNOT be recovered — only reset.\n\nCHANGE IT. Sign in at /admin, or POST /admin-api/users/set-password.\n=======================================================","time":"2026-09-25T21:39:17.999Z","v":0}```

Take note of the temporary password. 

Remember the admin password. 

Enter the temporary password into the password field.

Click the Login button.

You will be prompted to change the password. The password must comply with the default password policy, which can be changed later.
