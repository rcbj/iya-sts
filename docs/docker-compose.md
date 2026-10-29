---
title: The compose stack
nav_order: 13
---

# The compose stack

`docker-compose.yml` in the repository root runs the service the way a
deployment runs it:

* **product mode**: signing keys survive a restart, and every credential the
  console, SCIM and the management API ask for is checked;
* **PostgreSQL** as the store, over TLS, as a role that cannot change the schema;
* **OpenBao** as the secret store, holding the key-encryption key and the
  database password;
* **two request workers** take the protocol handlers off the thread that owns
  the sockets.

The file has no comments. This page explains it. To run the same stack from
published images, without a checkout, see
[Getting started](getting-started.md#with-postgresql-and-openbao-from-published-images).

```bash
docker compose up --build        # build from this checkout and start
docker compose up                # start; pulls the published image if there is none
docker compose up -d --wait      # start in the background, return when healthy
docker compose down              # stop, keeping every volume
docker compose down -v           # stop and delete all data
```

The main port is **HTTPS** on a certificate the service issues itself. Fetch it
once without verification, then trust it:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
curl --cacert /tmp/sts.pem https://localhost:8081/healthcheck
```

## Building from this checkout, or pulling the published image

The three services built from this repository (`openbao-tls`, `openbao-seed`
and `sts`) name the image `iyasec/iya-sts`, the one published on Docker Hub,
and also say how to build it. Which one you get depends on the command:

| Command | What runs |
|---|---|
| `docker compose up` | An `iyasec/iya-sts:latest` already on this machine, whatever it was built from. If there is none, Compose pulls it from Docker Hub, and builds only if the pull fails. |
| `docker compose up --build` | A build of this checkout, made before the containers start |
| `docker compose build`, then `docker compose up` | The same, in two steps |
| `docker compose pull`, then `docker compose up` | The newest published image |

**A local build is tagged with the published name.** A later
`docker compose pull` replaces it without a word, and the reverse is true too:
`docker images` cannot tell you which of the two you have. To keep a build of
this checkout apart from the published image, give it a name no registry has:

```bash
STS_IMAGE=iya-sts:local docker compose up --build
STS_IMAGE=iya-sts:local docker compose up        # later starts, same name
```

Put `STS_IMAGE=iya-sts:local` in a `.env` file beside `docker-compose.yml` to
make it the default. The remote PEP works the same way, with
`XACML_PEP_IMAGE` (published as `iyasec/iya-sts-xacml-pep`).

To check which build a running container is, see
[Which build am I running?](getting-started.md#which-build-am-i-running).

## Services

| Service | Image | What it does |
|---|---|---|
| `postgres` | `postgres:18` | The store. On the start that creates its volume it generates a self-signed TLS pair, rewrites `pg_hba.conf` so that only TLS connections are accepted, and runs `postgres/schema.sql`. That script creates the tables (owned by `sts`) and the role `sts_app`, which can read and write rows and cannot create, alter or drop a table. |
| `openbao-tls` | this repository's | One-shot. Mints the certificate for OpenBao's listener before OpenBao starts. |
| `openbao` | `openbao/openbao` | The secret store. Unseals itself at every start (`seal "static"`), and runs with `IPC_LOCK` so its memory is never swapped. |
| `openbao-seed` | this repository's | One-shot, idempotent. Initialises the store, writes the secrets, creates the Transit key `sts-kek`, issues the service its client certificate, and hands each node a single-use start-up token. |
| `sts` | this repository's (`iyasec/iya-sts`) | The service. It waits until the database is healthy and the seeder has finished. |
| `xacml-pep` | `iyasec/iya-sts-xacml-pep`, built from `xacml-pep/Dockerfile` | The [remote XACML PEP](remote-pep.md). It is only started with `--profile xacml`. |
| `companion` | `iya-sts-companion`, built from `companion/` | **Development only.** The click-through demonstrations, played by a separate party in front of the service: a Example University issuer and a bar-door verifier for OpenID4VC, and a Kerberos-protected page and TCP service (see [The companion](#the-companion-development-only)). It is only started with `--profile companion`. |

The `sts` container starts as root for three steps:

1. add the SPIFFE addresses (see [Network](#network-and-spiffe-addresses));
2. hand `/usr/src/sts/data` to uid 10001;
3. take its start-up secrets.

It then `exec`s the service as **uid 10001 with every capability dropped** and
`no_new_privs` set. The low ports need no capability, because the stack sets
`net.ipv4.ip_unprivileged_port_start=0`. A shell as the service's user can read
the service's own OpenBao client credential and no other secret on disk or in
its environment.

**Use `docker compose up`, not `docker compose restart sts`.** Every `up` runs
the seeder, which issues a new single-use start-up token. A `restart` does not,
so the service starts without the pinned management API secret.

## Ports

| Host port | Container | What | Moved by |
|---|---|---|---|
| 8081 | 8081 | The main port: every HTTP protocol, the console, the portal | `STS_HOST_PORT` |
| 8082 | 8082 | Plain-HTTP revocation listener: the CRL, OCSP and issuer certificate every issued certificate points at | `STS_PKI_HOST_PORT` |
| 88, TCP and UDP | 88 | The Kerberos KDC, so `kinit` and a browser's SPNEGO sign-in work from the host ([Kerberos](#kerberos)) | `STS_KDC_HOST_PORT` |
| 9090, 9444 | 9090, 9443 | Remote PEP, HTTP and HTTPS (`xacml` profile only) | `XACML_PEP_HOST_PORT`, `XACML_PEP_HTTPS_HOST_PORT` |
| 9700 | 9700 | The development companion, plain HTTP (`companion` profile only) | `COMPANION_HOST_PORT` (and `COMPANION_PUBLIC_URL`) |
| 8888 | 8888 | The companion's Kerberos-protected TCP service (`companion` profile only) | `COMPANION_KRB5_HOST_PORT` |

To move the main port, change only the host side. The service builds its
published URLs from the `Host` header of each request. `STS_PKI_HOST_PORT` is
also passed to the service as `PKI_DISTRIBUTION_PORT`, so certificates name the
port that is actually published.

**Not published by default**, because the standard ports collide with a
directory server or database that is often already running on the host. Add a
mapping under `sts` → `ports` (or `postgres` → `ports`) to reach one:

| Add | For |
|---|---|
| `"389:389"`, `"636:636"` (or `"1389:389"`, `"1636:636"`) | LDAP and LDAPS. LDAPS serves the same certificate as the main port. |
| `"8444:8444"` | The [embedded debugger](admin-console.md). Both sides must be the same number, because the debugger's sign-in sends the browser back to the service by the host name it used. It runs only when the image was built with `DEBUGGER_IMAGE`. |
| `"5432:5432"` under `postgres` | To look at the database with `psql` |

A realm's SPIFFE listeners are not published either. A published port maps to
one container address, so it would answer for only one realm. Reach them from
another container on the stack's network.

## Kerberos

The stack is ready for a Kerberos sign-in from the host with nothing set on
the server. Three things in the file make it so:

* **The KDC is published on 88**, TCP and UDP. A host that already runs a KDC
  on 88 moves it with `STS_KDC_HOST_PORT` (and names that port in its
  `krb5.conf`).
* **`KRB5_SERVICE_PRINCIPAL` defaults to `HTTP/localhost`**, the SPN a browser
  asks for when it opens `https://localhost:8081`. A browser always asks for
  `HTTP/<the host in the URL>`, and product mode creates no SPN on demand, so a
  stack reached by another name sets `KRB5_SERVICE_PRINCIPAL=HTTP/<that name>`.
* **No `KRB5_SERVICE_PASSWORD`**: product mode refuses the published one and
  keys the SPN at random instead, sealed in the store under the same
  key-encryption key as everything else. Set a password of your own only to
  accept tickets another KDC issues for that SPN; it wins over the random key.

The client side — a `krb5.conf`, `kinit`, and the Chrome and Firefox settings —
is in [Kerberos: signing in from a browser](kerberos.md#signing-in-from-a-browser-on-the-base-installation).
The test stacks (`docker-compose-run-tests*.yml`) publish nothing, 88
included.

## Volumes

Every named volume survives `docker compose down` and is deleted by
`docker compose down -v`.

| Volume | Mounted at | Holds |
|---|---|---|
| `sts-db` | `/var/lib/postgresql` (postgres) | The database and its TLS pair: the directory, the trust realms, the setting changes made in the console, and in product mode the sealed signing keys and everything the service has minted |
| `sts-db-ca` | `/run/sts-db-ca` (postgres), `/run/secrets/database-ca`, read-only (sts) | The database's certificate, `postgres.crt`, copied there by the postgres container on every start — never its key. The service trusts it for its database connection. |
| `sts-bao-file` | `/openbao/file` (OpenBao and both one-shots) | OpenBao's storage, its listener's TLS pair, and the seeder's state |
| `sts-bao-client` | `/run/secrets/openbao`, read-only (sts) | The client certificate and key the service authenticates to OpenBao with, and OpenBao's CA |
| `sts-bao-startup` | `/run/secrets/openbao-startup` (sts, seeder) | One single-use start-up token per node. Readable only by root; the start command takes and deletes it. |
| `sts-data` | `/usr/src/sts/data` (sts) | Where `ldif` persistence writes. Empty in `postgres` mode. It is mounted in both modes so that switching is one variable. |
| `sts-risk-uploads` | `/usr/src/sts/data/risk-uploads` (sts) | An uploaded [risk dataset](risk-scoring.md) while it is being imported. It must be large enough for the largest compressed file you upload; a file it cannot hold is refused (`STS-RISK-0029`). Empty between uploads. |

**Delete `sts-bao-file` and `sts-db` together.** The data in the database is
sealed under the key in OpenBao. Losing either loses both.

`./env` is a **bind mount**, read-only, of the repository's appconfig
directory. Edit `env/local.js` on the host and the next start reads it, with no
rebuild. The service never writes to it. Setting changes made in the console go
to the store, which overrides the file. Do not edit `env/defaults.js`; it is
generated from `common/config.js`.

## Network and SPIFFE addresses

The stack declares its own network, `172.29.0.0/24` (`STS_NETWORK_SUBNET`), and
gives the `sts` container a fixed address, `172.29.0.10` (`STS_ADDRESS`).

A realm with SPIFFE turned on binds its own Workload API and SPIRE Server API.
Realms are told apart by **address**, because gRPC has nowhere in the request
to name one. `spiffe.grpcHost` on a realm is a literal IP, so the addresses must
be the same on every start. The container adds three more addresses to its own
interface on the way up:

| Variable | Default | |
|---|---|---|
| `STS_ADDRESS` | `172.29.0.10` | The container's own address |
| `STS_SPIFFE_GRPC_HOST` | `172.29.0.10` | The default realm's SPIFFE listeners. Not the wildcard `0.0.0.0`, which would take the port on every address and make another realm's bind fail with `EADDRINUSE`. |
| `STS_EXTRA_IPS` | `172.29.0.11/24 172.29.0.12/24 172.29.0.13/24` | Space-separated CIDRs for other realms' `spiffe.grpcHost` |

Adding an address needs **`NET_ADMIN`**, which the `sts` service is given. If
an address cannot be added, the container says so and starts anyway, and the
realm configured for it reports that its listener did not come up.

If `172.29.0.0/24` is in use on your machine, set `STS_NETWORK_SUBNET` and the
address variables together. See [SPIFFE](spiffe.md) and
[Trust realms](trust-realms.md).

## Environment variables

Every value in the file is `${VAR:-default}`, so any of them can be changed
from the shell or a `.env` file beside it. The ones you are likely to change:

| Variable | Default | What it does |
|---|---|---|
| `STS_MODE` | `product` | `development` gives the permissive test mode: no password checks, keys regenerated per start |
| `STS_PERSISTENCE_MODE` | `postgres` | `ldif` writes one RFC 2849 file per realm to `sts-data` and needs no database; `memory` keeps nothing |
| `STS_DATABASE_URL` | `postgres://sts_app@postgres:5432/sts?sslmode=verify-full` | Replaces the whole connection string, to use your own database. The password is read from OpenBao and added to it at start. |
| `STS_DATABASE_TLS_CA_FILE` | `/run/secrets/database-ca/postgres.crt` | The CA certificate (or a directory of them) the service trusts for its database connection, and for nothing else. Point it at your database's CA when you replace `STS_DATABASE_URL`, or at a directory; a file that cannot be read stops the service (`STS-STORE-0079`). |
| `STS_HTTPS` | `true` | `false` serves the main port as plain HTTP, for a client that cannot be made to trust the certificate |
| `KRB5_SERVICE_PRINCIPAL` | `HTTP/localhost` | The SPN the Kerberos acceptor holds: `HTTP/<the host a browser opens>` ([Kerberos](#kerberos)) |
| `STS_KDC_HOST_PORT` | `88` | The host port the KDC is published on, TCP and UDP |
| `STS_LOG_LEVEL` | unset (the appconfig's `info`) | `debug` logs every request, every artifact before and after signing, and every function's entry and exit |
| `CONFIG_FILE` | `./env/local.js` | The appconfig file |
| `STS_WORKERS_REQUEST_COUNT` | `2` | Request workers |
| `STS_WORKERS_SURFACE_COUNT` | `0` | Workers for `/admin` and `/portal` only, so they never queue behind protocol traffic |
| `UV_THREADPOOL_SIZE` | `32` | Threads in libuv's pool, where post-quantum signing, scrypt password hashing and node's file and DNS work run. Node's own default is 4, which queued sign-ins under load. |
| `STS_RESTART` | `unless-stopped` | The `sts` service's restart policy. With it, an `sts` that exits (for example STS-CLUSTER-0011, a node fencing itself off) is back within seconds instead of staying down. `no` keeps an exited service down; the test launchers set it. |
| `ADMIN_API_CLIENT_SECRET` | unset (generated) | Fixes the secret of `sts-api-client`, the seeded client that calls the management API. It is given to the seeder, which stores it in OpenBao; the service never sees it in its environment. See [Management API](management-api.md). |
| `ADMIN_API_AUDIENCE`, `ADMIN_API_AUTH_REQUIRED` | unset | Passed through to the service when set |
| `PKI_DISTRIBUTION_BASE_URL` | empty | The base URL certificates name for CRL and OCSP, when the stack is reached by a host name rather than `localhost` ([PKI](pki.md)) |
| `STS_POSTGRES_SHARED_BUFFERS` | `2GB` | The database's `shared_buffers`. Lower it on a small machine; see [the database's settings](#the-databases-settings) |
| `STS_DB_APP_USER`, `STS_DB_APP_PASSWORD` | `sts_app`, `sts_app` | The database role the service uses. If you change the user, change it in `STS_DATABASE_URL` too. |
| `STS_BAO_SEAL_KEY`, `STS_BAO_SEAL_KEY_ID` | a fixed demonstration key, `sts` | OpenBao's unseal key: base64 of exactly 32 bytes |
| `STS_BAO_PRINT_CREDENTIALS` | `true` | Whether the seeder prints the operator token, and on the first run the recovery key |
| `STS_KEYS_KEK_PROVIDER` | `vault-transit` | `vault` reads the key from KV (`STS_KEYS_KEK_REF=secret/data/sts`) instead of using the Transit key |
| `OPENBAO_TAG` | `latest` | The OpenBao image tag |
| `STS_IMAGE`, `XACML_PEP_IMAGE`, `STS_COMPANION_IMAGE` | `iyasec/iya-sts`, `iyasec/iya-sts-xacml-pep`, `iya-sts-companion` | Image names. Set them to a name no registry has to keep a local build apart from the published image ([above](#building-from-this-checkout-or-pulling-the-published-image)) |
| `BUILD_NUMBER`, `GIT_COMMIT`, `DEBUGGER_IMAGE` | empty | Build arguments: see [Which build am I running?](getting-started.md#which-build-am-i-running) and the embedded debugger |
| `*_CONTAINER_NAME` | `sts`, `sts-postgres`, `sts-openbao`, … | Container names, which are machine-wide; change them to run a second stack beside this one |

`OID4VCI_WALLET_URL` is not in the file. Add it under `sts` → `environment`
when the wallet is not at `http://localhost:3000`. Otherwise the portal's
Credential Offer and a verification's wallet link send the browser to the
wrong place, and the symptom looks like an unrelated timeout.

`STS_REPORT_NODE` is not in the file. Set it to the string `true` only on a
service that should hold the lease `ops.reporting`. Do not add it to the
default `sts` service. Any other value leaves the lease unoffered. With the
cluster off, `report.drain`, `report.retention` and `report.schedule` run on
the front process and no lease is taken. In a cluster those three run on a
front that does not hold the lease and sees no other reporter still live.
The three `.here` jobs run only in the process that holds `ops.reporting`.
[Reports](reporting.md) says what that lease runs.

## The companion (development only)

The service ships no demonstration pages. The OpenID4VC issuer and verifier a
person clicks through, and the Kerberos-protected page and service — what the
embedded debugger's credential and Kerberos pages point at — are a second
container, started only when asked:

```bash
ADMIN_API_CLIENT_SECRET=$(openssl rand -base64 24) \
  docker compose --profile companion up -d
```

Then open `http://localhost:9700`. It uses the service as any issuer's or
verifier's web site would:

* **The issuer's page** reads `/.well-known/openid-credential-issuer` and
  makes a Credential Offer with the authorization code grant (no
  `issuer_state`), so the wallet signs the person in at the service. A
  **pre-authorized** offer is the person's own, so the page links to the
  service's `/portal/wallet`.
* **The bar door** starts a verification at `POST
  /admin-api/verifications/start`, naming its own `/verifier/done` as the
  page the wallet is sent to afterwards, and reads the verdict at `GET
  /admin-api/verifications?state=`.
* **The Kerberos-protected page** (`/spnego`, `/spnego/protected`) and **TCP
  service** (port 8888, `/krb5/service` describes it) are a Kerberos service
  of the companion's own, accepted by MIT Kerberos with a keytab the KDC made
  for it: at the first request that needs one, the companion asks `POST
  /admin-api/kerberos/principals/create-service` for its principal — after a
  restart, `rotate-service` — and writes the keytab only it can read.
  [Kerberos](kerberos.md#the-demonstration-the-companions-kerberos-protected-page-and-service)
  says what it does.

  Its principal is `HTTP/<the host of COMPANION_PUBLIC_URL>`, the name a
  client derives from the URL. At `localhost` that is `HTTP/localhost`, the
  name the service's own `/authn/spnego` is reached under too, so give the
  companion a host of its own (`COMPANION_PUBLIC_URL=http://companion.localhost:9700`,
  or `COMPANION_KRB5_SPN`). The KDC is the service's: over port 88, or over
  MS-KKDCP, which `kinit` speaks with `kdc = https://localhost:8081/KdcProxy`
  in its `krb5.conf`.

It calls `/admin-api` as an application of its own, `iya-sts-companion`,
holding Admin Read and Admin Write. Give it either
`COMPANION_CLIENT_ID`/`COMPANION_CLIENT_SECRET` for an application you
registered (it must declare `admin:read admin:write`, be a member of
`ADMIN_READ` and `ADMIN_WRITE`, and list the companion's `/verifier/done` as a
redirect URI), or let it register itself: it reads the secret of the seeded
client `sts-api-client` from `ADMIN_API_CLIENT_SECRET` once, creates the application, and uses
only its own credentials afterwards.

| Variable | Default | What it does |
|---|---|---|
| `COMPANION_PUBLIC_URL` | `http://localhost:9700` | Where a browser reaches the companion; its completion page is under it |
| `COMPANION_STS_URL` | `https://sts:8081` | Where the companion dials the service |
| `COMPANION_STS_PUBLIC_URL` | `https://localhost:8081` | Where a browser and a wallet reach the service, a realm's prefix included (`…/realm/acme`). Sent as the `Host`, so the addresses the service builds are reachable |
| `COMPANION_STS_CA_FILE` | empty | The service Root to verify its certificate against |
| `COMPANION_STS_TLS_INSECURE` | `true` | With no CA file, do not verify the service's certificate. Development only |
| `COMPANION_WALLET_URL` | empty | A wallet's issuance page for the offer's link, besides the `openid-credential-offer://` link and QR code |
| `COMPANION_KRB5_SPN` | empty | The Kerberos demonstration's service principal; empty is `HTTP/<the host of COMPANION_PUBLIC_URL>` |
| `COMPANION_KRB5_SERVICE_PORT` | `8888` | The protected TCP service's port inside the container; `off` binds none |
| `COMPANION_KRB5_KEYTAB_DIR` | a fresh temporary directory | Where the keytab is written (mode 0600) |

[Configuration](configuration.md) lists every setting and its environment
variable.

## The database's settings

The `postgres` service starts the server with these settings, on its command
line. They come from measuring the service under an LDAP bulk load (#630).
They apply when the container starts, so an existing stack takes them at its
next restart; nothing in the volume changes. The quick start in
[Getting started](getting-started.md#with-postgresql-and-openbao-from-published-images)
and the containerized test suite start the database with the same settings.

| Setting | Value | Why |
|---|---|---|
| `shared_buffers` | `2GB` (`STS_POSTGRES_SHARED_BUFFERS`) | The default 128 MB held little of a multi-gigabyte directory |
| `max_wal_size`, `checkpoint_timeout` | `8GB`, `15min` | Checkpoints ran because the WAL filled, not on time |
| `wal_compression` | `lz4` | An add wrote several full-page images |
| `max_parallel_workers_per_gather` | `0` | Parallel plans tripled the CPU of the service's small lookups |
| `track_io_timing`, `log_lock_waits` | `on` | Time spent on I/O and lock waits, in the statistics and the log |
| `shared_preload_libraries` | `pg_stat_statements,auto_explain` | Statement statistics, and the plan of any statement over 200 ms written to the log (with buffers, without per-node timing) |

`postgres/schema.sql` creates the `pg_stat_statements` view. Query it as the
owner (`docker compose exec postgres psql -U sts -d sts -c 'SELECT … FROM
pg_stat_statements …'`). The service's own role, `sts_app`, is not given the
right to read other roles' statements. Its plans arrive in the container's
log (`docker compose logs postgres`).

## Things to know before relying on it

* **The passwords in the file are demonstration values**: the database owner
  `sts`/`sts`, the role `sts_app`/`sts_app` and OpenBao's unseal key. The
  database is reachable only on the stack's private network. For a real
  deployment, set `STS_BAO_SEAL_KEY` from your orchestrator's secrets, or
  replace the `seal` stanza in `openbao/bao.hcl` with `transit`, `awskms`,
  `gcpckms` or `azurekeyvault`. With the static seal, anyone who can read the
  stack's configuration can unseal the store.
* **The database connection is encrypted and authenticated.** Its certificate
  is self-signed, so the postgres container shares the certificate (not the
  key) in `sts-db-ca`, and the service trusts that file for the database alone
  and dials `sslmode=verify-full`. Verification is on by default; turning
  `STS_DATABASE_TLS_REJECT_UNAUTHORIZED` off leaves the database
  unauthenticated and is not something to do outside a throwaway stack. See
  [Persistence](persistence.md#the-compose-database-is-tls-and-the-service-verifies-it).
* **The connection string carries no password.** `docker compose config` and
  `/admin/config` show none.
* **Older volumes need `docker compose down -v`**: a `sts-db` volume written by
  PostgreSQL 16 (before 2026-08-30) stops the database with "database files are
  incompatible with server", and one created before 2026-09-06 has no `sts_app`
  role, so the service restart-loops with `password authentication failed for
  user "sts_app"`. The database init scripts run only on a volume with no
  cluster in it.
* **The service will not start until the database accepts connections and the
  seeder has finished.** A configured store that cannot be opened stops the
  service. An outage while it is running is recorded and survived.
* **The health check is liveness only**: `GET /healthcheck` answers 200. It
  picks HTTP or HTTPS from `STS_HTTPS` and does not verify the certificate.
  The process holding the listener answers it at once, never a request
  worker, so a busy worker cannot make the probe time out; it says nothing
  about the workers' health (Monitoring → Node Health does).

## Related

* [Getting started](getting-started.md): the same stack from published images
* [Persistence](persistence.md) and [PostgreSQL schema](postgres-schema.md)
* [Encryption at rest](encryption-at-rest.md): OpenBao, the Transit key, rotation
* [Management API](management-api.md): the first token on this stack
* [Remote PEP](remote-pep.md): the `xacml` profile
* [OpenID4VCI](oid4vci.md), [OpenID4VP](oid4vp.md) and [Kerberos](kerberos.md): what the companion demonstrates
