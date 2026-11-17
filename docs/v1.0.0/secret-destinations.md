---
title: Secret push destinations
---

# Secret push destinations

A **secret push destination** is a secrets manager this service writes a
service account's password to. When a service account's password is rotated,
the new password is pushed to its destination as a new version of a secret
**before** the service starts accepting it. If the push fails, nothing
changes: the old password stays the one in force.

Destinations are registered per realm on **Directory → Secret destinations**
(`/admin/secret-destinations`) or through `/admin-api/secret-destinations`.
A service account names its destination and the secret's name on its own
page.

## What a destination is

Each destination is an **application entry** in the realm, declared for the
*Secret push destination* family. It holds:

| Member | Provider | What it is |
|---|---|---|
| provider | all | `aws`, `gcp`, `azure`, `vault`, or `file` (development mode only) |
| payload | all | `password` (the bare password) or `json` |
| region | aws | The AWS region the secrets are in |
| project | gcp | The project a short secret name is in |
| endpoint | azure, vault | The Key Vault URL, or the Vault / OpenBao address. **https only** |
| mount | vault | The KV version 2 mount; `secret` when empty |
| field | vault | With the `password` payload, the field written; `value` when empty |
| CA certificates | vault | PEM certificates of the CA the Vault listener chains to |
| directory | file | The absolute directory a secret name is a file in |
| write credential | all but file | See below. **Write-only** |

The `json` payload is:

```json
{ "username": "svc-backup", "password": "…", "realm": "acme",
  "rotatedAt": "2026-10-06T12:00:00.000Z" }
```

A consumer takes the password out of it by its field, as this service does
with its own secrets (`keys.kekField` and the like).

## The write credential

Each destination has **its own** credential, separate from the read-only ones
this service uses for its own key-encryption key and database password:

| Provider | Credential | What it needs to be allowed |
|---|---|---|
| aws | `{"accessKeyId", "secretAccessKey"[, "sessionToken"]}` | `secretsmanager:PutSecretValue` on the named secrets |
| gcp | a service account key file's JSON | `secretmanager.versions.add` on the named secrets |
| azure | `{"tenantId", "clientId", "clientSecret"}` | `list` and `set` on secrets |
| vault | a token | `read` on `<mount>/metadata/<name>`, `create` and `update` on `<mount>/data/<name>` |

The credential is sealed under the key-encryption key, and is **never shown
again** once set: not on any page, not in any `/admin-api` answer, not in a
directory read, not in the audit log. `reveal-secret` refuses it. To change
it, set a new one; to keep it, leave the box empty.

## A push never creates a secret

**The secret must already exist** at the destination. A push writes a new
version of it and nothing else, so the credential needs write on named secrets
only. A push to a secret that does not exist is refused (`STS-SECDEST-0003`).

- **AWS Secrets Manager**: `PutSecretValue`.
- **Google Cloud Secret Manager**: `AddSecretVersion`. A short name is put
  under the destination's project.
- **Azure Key Vault**: the secret's versions are listed first, because
  `setSecret` would create a missing secret; then `setSecret`.
- **Vault or OpenBao (KV version 2)**: the secret's metadata is read for its
  current version, and the write names that version (check-and-set). If
  somebody wrote a newer version in between, the push is refused
  (`STS-SECDEST-0004`) and nothing is overwritten.
- **A file**, in **development mode only**: the password is written into an
  existing file under the destination's directory. A name that leaves the
  directory, or a link, is refused. Product mode refuses a file destination
  (`STS-SECDEST-0006`): a password on this container's disk is not in a
  secrets manager.

## Test push

**Test push** writes a canary — a random password nobody uses — to a secret
you name. Use a secret kept for testing: it proves the credential, the
address and the secret exist before a rotation depends on them. A secret a
service account's rotation writes is refused (`STS-SECDEST-0010`).

## Network

Every address is the one an administrator configured on the destination; no
request can name one. An Azure or Vault address must be `https`, and the
certificate is always verified — for Vault, against the destination's own CA
certificates as well as the public roots.

## Errors

Every refusal has a code in the `STS-SECDEST-` range; see
[Error codes](error-codes.md).
