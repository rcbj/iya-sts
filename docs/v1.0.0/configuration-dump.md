---
title: Configuration dump
nav_order: 12
---

# Configuration dump

A configuration dump is one JSON document holding every configuration parameter
of a running iya-sts: the global values, and the values each trust realm sets
for itself. You can get it from the admin console, from the command line, or
from the management API. All three return the same document.

The dump holds parameters only. Directory objects (people, groups, applications,
federation relationships) are not in it.

* TOC
{:toc}

## What is masked

The service masks every sensitive value before it answers, so the console, the
command line and the API all return the same masked document. A masked value reads `********`, and its row carries
`"masked": true`.

| Masked | Example |
|---|---|
| A parameter the service marks as secret | `global.edgeSecret` |
| A parameter whose name says it holds a secret: a password, secret, token, salt, credential, or private, client or API key | `adminApi.clientSecret`, `krb5.servicePassword`, `keys.kekToken` |
| A password inside a URL | `postgres://sts:********@db:5432/sts` |
| A secret inside any other value: a PEM private key, a JWT, an `Authorization` value, a `password=` or `AccessKey=` assignment, a JWK's private members | |

These stay visible, because they are not secrets:

* **A parameter that says where a secret is**, such as `mail.smtpPasswordRef`,
  `persistence.databasePasswordField` or `tls.keyFile`.
* **A number, a boolean or a choice from a fixed list**, such as a token
  lifetime.
* **An empty value.** A secret that was never set reads `""`, so you can tell
  it apart from one that was.

A dump is still a description of your deployment: it names hosts, file paths
and where your secrets are kept. Handle it as internal material. Every dump is
recorded in the audit log as `admin.config-dump`, with who asked for it.

## Who can get one

You need the **Admin Read** role and, on the management API, a token with the
`admin:read` scope. See [Getting a token](management-api.md#getting-a-token).

What you get depends on where you ask:

| Where | What the dump holds |
|---|---|
| The default realm | Every parameter's effective value there, in `settings`, and what each other realm sets, in `realms` |
| A realm (`/realm/{id}`) | That realm's effective value of every parameter, in `settings`. `realms` is empty |

A realm administrator can dump their own realm only.

## From the admin console

1. Sign in to the console.
2. Go to **Server configuration → Configuration dump** (`/admin/config-dump`).
   For a single realm, open `/realm/{id}/admin/config-dump` and sign in as an
   administrator of that realm.
   The page shows how many parameters there are, how many values were masked,
   and each other realm with the number of parameters it sets.
3. Click **Download JSON**.

The file is named `iya-sts-config-{realm}-{time}.json`.

## From the command line

`config-dump.js` is a client with no dependencies beyond Node. It is in the
service image at `/usr/src/sts/utilities/config-dump.js`, and in a checkout at
`utilities/config-dump.js`.

It reads the client secret from `ADMIN_API_CLIENT_SECRET`, from the file named
by `ADMIN_API_CLIENT_SECRET_FILE`, or from `--secret-file`. It never takes the
secret as an argument. Use an
[application of your own](management-api.md#an-application-of-your-own-for-every-token-after-that)
with `--client`, or `sts-api-client` for
[the first token on a stack you run](management-api.md#the-first-token-on-a-stack-you-run).

Inside the running container, passing the variable through from your shell:

```bash
docker exec -e ADMIN_API_CLIENT_SECRET sts \
  node /usr/src/sts/utilities/config-dump.js \
  --url https://localhost:8081 --insecure > config-dump.json
```

`sts` is the default container name. `--insecure` is reasonable there, because
the connection does not leave the container. From anywhere else, trust the service's certificate:

```bash
export ADMIN_API_CLIENT_SECRET_FILE=/path/to/secret
node utilities/config-dump.js \
  --url https://sts.example.net --ca-file ca.pem \
  --client ops-automation --output config-dump.json
```

`--output` creates the file readable only by you.

| Option | Meaning |
|---|---|
| `--url URL` | The service's base URL. Required |
| `--realm ID` | Dump this realm only |
| `--realm-client` | The client belongs to `--realm`, not to the default realm. A realm administrator's client needs this |
| `--client ID` | The `client_id`. The default is `sts-api-client` |
| `--secret-file F` | A file holding the client secret |
| `--ca-file F` | A PEM file of the CA to trust |
| `--insecure` | Do not verify the certificate |
| `--output F` | Write to a file instead of standard output |

The exit status is 0 when the dump was saved, 1 when it failed, and 2 for a
usage error.

## From the management API

```bash
BASE=https://localhost:8081
TOKEN=$(curl -sk -u "sts-api-client:$ADMIN_API_CLIENT_SECRET" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode scope=admin:read \
  --data-urlencode resource=$BASE/admin-api \
  $BASE/oauth2/token | jq -r .access_token)

# The whole service
curl -sk -H "Authorization: Bearer $TOKEN" \
  $BASE/admin-api/config-dump > config-dump.json

# One realm
curl -sk -H "Authorization: Bearer $TOKEN" \
  $BASE/realm/acme/admin-api/config-dump > config-dump-acme.json
```

The operation is `getConfigDump` in the
[OpenAPI document](openapi/admin-api-configuration.md).

## Reading the dump

```json
{
  "format": "iya-sts-config-dump/1",
  "generatedAt": "2026-11-09T12:00:00.000Z",
  "version": "1.0.0.20261109120000",
  "scope": "service",
  "realm": "default",
  "configFile": "/usr/src/sts/env/local.js",
  "defaultsFile": "/usr/src/sts/env/defaults.js",
  "settingCount": 1416,
  "masking": { "mask": "********", "maskedValues": 9 },
  "settings": [
    { "key": "global.logLevel", "group": "Global", "type": "enum",
      "value": "info", "default": "info", "source": "appconfig",
      "env": "STS_LOG_LEVEL", "overridden": false, "editable": true },
    { "key": "adminApi.clientSecret", "group": "Management API",
      "type": "string", "value": "********", "default": "", "source": "env",
      "env": "ADMIN_API_CLIENT_SECRET", "overridden": false,
      "editable": false, "masked": true }
  ],
  "realms": [
    { "id": "acme", "settings": [ ] }
  ]
}
```

`source` says where the effective value came from. The values are described on
[Configuration](configuration.md). To list the masked parameters:

```bash
jq -r '.settings[] | select(.masked) | .key' config-dump.json
```

To compare two instances, or one instance over time, remove the timestamp and
compare what remains:

```bash
diff <(jq -S 'del(.generatedAt)' before.json) \
     <(jq -S 'del(.generatedAt)' after.json)
```

A dump is for reading and comparing. It cannot be loaded back, because the
masked values are gone.

## The same masking elsewhere

`GET /admin-api/config`, `GET /admin-api/realms`, `GET /admin-api/mode`, the
settings on every console page, and the answers of the `config` operations mask
the same values. A masked field in the console shows `********`. Saving a form with that field unchanged keeps the existing
value, and typing a new value replaces it.
