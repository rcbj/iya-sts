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
docker compose up --build        # build and start
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

## Services

| Service | Image | What it does |
|---|---|---|
| `postgres` | `postgres:18` | The store. On the start that creates its volume it generates a self-signed TLS pair, rewrites `pg_hba.conf` so that only TLS connections are accepted, and runs `postgres/schema.sql`. That script creates the tables (owned by `sts`) and the role `sts_app`, which can read and write rows and cannot create, alter or drop a table. |
| `openbao-tls` | this repository's | One-shot. Mints the certificate for OpenBao's listener before OpenBao starts. |
| `openbao` | `openbao/openbao` | The secret store. Unseals itself at every start (`seal "static"`), and runs with `IPC_LOCK` so its memory is never swapped. |
| `openbao-seed` | this repository's | One-shot, idempotent. Initialises the store, writes the secrets, creates the Transit key `sts-kek`, issues the service its client certificate, and hands each node a single-use start-up token. |
| `sts` | this repository's (`rcbj/sts`) | The service. It waits until the database is healthy and the seeder has finished. |
| `xacml-pep` | `rcbj/xacml-pep` | The [remote XACML PEP](remote-pep.md). It is only started with `--profile xacml`. |

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
| 9090, 9444 | 9090, 9443 | Remote PEP, HTTP and HTTPS (`xacml` profile only) | `XACML_PEP_HOST_PORT`, `XACML_PEP_HTTPS_HOST_PORT` |

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
| `"88:88"`, `"88:88/udp"` | The Kerberos KDC |
| `"8444:8444"` | The [embedded debugger](admin-console.md). Both sides must be the same number, because the debugger's sign-in sends the browser back to the service by the host name it used. It runs only when the image was built with `DEBUGGER_IMAGE`. |
| `"5432:5432"` under `postgres` | To look at the database with `psql` |

A realm's SPIFFE listeners are not published either. A published port maps to
one container address, so it would answer for only one realm. Reach them from
another container on the stack's network.

## Volumes

Every named volume survives `docker compose down` and is deleted by
`docker compose down -v`.

| Volume | Mounted at | Holds |
|---|---|---|
| `sts-db` | `/var/lib/postgresql` (postgres) | The database and its TLS pair: the directory, the trust realms, the setting changes made in the console, and in product mode the sealed signing keys and everything the service has minted |
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
| `STS_MODE` | `product` | `development` gives the permissive mock: no password checks, keys regenerated per start |
| `STS_PERSISTENCE_MODE` | `postgres` | `ldif` writes one RFC 2849 file per realm to `sts-data` and needs no database; `memory` keeps nothing |
| `STS_DATABASE_URL` | `postgres://sts_app@postgres:5432/sts?sslmode=require` | Replaces the whole connection string, to use your own database. The password is read from OpenBao and added to it at start. |
| `STS_HTTPS` | `true` | `false` serves the main port as plain HTTP, for a client that cannot be made to trust the certificate |
| `STS_LOG_LEVEL` | unset (the appconfig's `info`) | `debug` logs every request, every artifact before and after signing, and every function's entry and exit |
| `CONFIG_FILE` | `./env/local.js` | The appconfig file |
| `STS_WORKERS_REQUEST_COUNT` | `2` | Request workers |
| `STS_WORKERS_SURFACE_COUNT` | `0` | Workers for `/admin` and `/portal` only, so they never queue behind protocol traffic |
| `ADMIN_API_CLIENT_SECRET` | unset (generated) | Fixes the management API client's secret. It is given to the seeder, which stores it in OpenBao; the service never sees it in its environment. See [Management API](management-api.md). |
| `ADMIN_API_AUDIENCE`, `ADMIN_API_AUTH_REQUIRED` | unset | Passed through to the service when set |
| `PKI_DISTRIBUTION_BASE_URL` | empty | The base URL certificates name for CRL and OCSP, when the stack is reached by a host name rather than `localhost` ([PKI](pki.md)) |
| `STS_DB_APP_USER`, `STS_DB_APP_PASSWORD` | `sts_app`, `sts_app` | The database role the service uses. If you change the user, change it in `STS_DATABASE_URL` too. |
| `STS_BAO_SEAL_KEY`, `STS_BAO_SEAL_KEY_ID` | a fixed demonstration key, `sts` | OpenBao's unseal key: base64 of exactly 32 bytes |
| `STS_BAO_PRINT_CREDENTIALS` | `true` | Whether the seeder prints the operator token, and on the first run the recovery key |
| `STS_KEYS_KEK_PROVIDER` | `vault-transit` | `vault` reads the key from KV (`STS_KEYS_KEK_REF=secret/data/sts`) instead of using the Transit key |
| `OPENBAO_TAG` | `latest` | The OpenBao image tag |
| `STS_IMAGE`, `XACML_PEP_IMAGE` | `rcbj/sts`, `rcbj/xacml-pep` | Image names |
| `BUILD_NUMBER`, `GIT_COMMIT`, `DEBUGGER_IMAGE` | empty | Build arguments: see [Which build am I running?](getting-started.md#which-build-am-i-running) and the embedded debugger |
| `*_CONTAINER_NAME` | `sts`, `sts-postgres`, `sts-openbao`, … | Container names, which are machine-wide; change them to run a second stack beside this one |

`OID4VCI_WALLET_URL` is not in the file. Add it under `sts` → `environment`
when the wallet is not at `http://localhost:3000`. Otherwise the Credential
Offer and presentation pages send the browser to the wrong place, and the
symptom looks like an unrelated timeout.

[Configuration](configuration.md) lists every setting and its environment
variable.

## Things to know before relying on it

* **The passwords in the file are demonstration values**: the database owner
  `sts`/`sts`, the role `sts_app`/`sts_app` and OpenBao's unseal key. The
  database is reachable only on the stack's private network. For a real
  deployment, set `STS_BAO_SEAL_KEY` from your orchestrator's secrets, or
  replace the `seal` stanza in `openbao/bao.hcl` with `transit`, `awskms`,
  `gcpckms` or `azurekeyvault`. With the static seal, anyone who can read the
  stack's configuration can unseal the store.
* **The database connection is encrypted, not authenticated.** Its certificate
  is self-signed, so the service uses `sslmode=require` rather than
  `verify-full`. `/admin/persistence` shows this as two separate facts. See
  [Persistence](persistence.md#the-compose-database-is-tls-and-requires-it).
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

## Related

* [Getting started](getting-started.md): the same stack from published images
* [Persistence](persistence.md) and [PostgreSQL schema](postgres-schema.md)
* [Encryption at rest](encryption-at-rest.md): OpenBao, the Transit key, rotation
* [Management API](management-api.md): the first token on this stack
* [Remote PEP](remote-pep.md): the `xacml` profile
