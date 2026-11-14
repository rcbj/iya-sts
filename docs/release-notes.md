---
title: Release notes
---

# Release notes

## 1.1.0

1.1.0 upgrades a deployment that is already running 1.0.0. Keep the
database volume. The 1.0.0 service can keep answering while the database
is upgraded. Start the 1.1.0 image after the upgrade script exits 0.

A store that is only in memory has nothing to upgrade. A database whose
schema version is below 31 is a pre-release build, and the script refuses
it. Those builds are covered under
[Not backwards compatible with earlier builds](#not-backwards-compatible-with-earlier-builds).

### PostgreSQL

Release 1.0.0's database is schema version 31. 1.1.0 adds two indexes on
`sts_sessions` and records schema version 32 beside it:

* `sts_sessions_started`, so the console's session pages can list sessions
  newest first without sorting the whole table.
* `sts_sessions_subject_band`, used by the per-subject session sweep.

Run the script as the table owner, from a checkout of 1.1.0. On the
compose stack the owner is `sts`. The application role `sts_app` cannot
create an index.

```bash
docker compose exec -T postgres \
  psql -U sts -d sts -v ON_ERROR_STOP=1 \
  -f - < postgres/upgrade-1.0.0.sql
```

Against a database you reach directly:

```bash
psql -v ON_ERROR_STOP=1 -f postgres/upgrade-1.0.0.sql \
     "postgres://owner@host:5432/sts"
```

Do not pass `--single-transaction`. The indexes are built with
`CREATE INDEX CONCURRENTLY`, which PostgreSQL refuses inside a
transaction. For a large `sts_sessions` table,
`-v sts_maintenance_work_mem=1GB` gives this session more memory for the
build and does not change the server. `-v sts_schema=sts` selects the
schema and is the default.

Then start the 1.1.0 image. If it starts before the script has run, it
still starts and answers every request; the session pages and the
per-person session sweep are slower until the indexes exist:

* As the application role (`sts_app`, the normal case), which cannot
  create an index, it logs `STS-STORE-0172` once, naming the two indexes
  and this script. Run the script; nothing needs restarting afterwards.
* As a role that owns `sts_sessions`, it builds the missing indexes
  itself, in the background, with `CREATE INDEX CONCURRENTLY`, without
  holding up writes or its own start. A build that fails logs
  `STS-STORE-0173` and is tried again at the next start.

Replacing the image before the script does not damage the volume.

**Leave the volume in place.** `docker compose down -v` deletes the
directory, the realm registry and the setting overrides, and in product
mode the sealed signing keys and everything minted under them.

**Do not run `postgres/schema.sql` again for this upgrade.** On a 1.0.0
database that script rebuilds `sts_ldap_entries_asked_names`, which
version 31 already has, and sets the application role's password again.
`postgres/upgrade-1.0.0.sql` does neither.

A second run finds the indexes already valid and changes nothing else. If
the script stops because an index of one of those names has the wrong
definition, drop that index and run the script again. An index left
invalid by an interrupted build is dropped and built again by the script.

Returning to the 1.0.0 image ignores both indexes. Leave them.

[PostgreSQL schema](postgres-schema.md) records what version 32 adds.

### MariaDB

MariaDB is the [second engine](persistence.md#a-second-engine-mariadb).
Its upgrade adds `sts_sessions_started` and records schema version 32.
`sts_sessions_subject_band` is PostgreSQL only. The build does not block
writers. Run it as an account that can `ALTER` the table,
in the service's database, and pass `--abort-source-on-error`:

```bash
mariadb --abort-source-on-error -u root -p sts \
  < mariadb/upgrade-1.0.0.sql
```

`sts` is that database's name. Use the name from the connection string
when it differs (`sts_store` in the MariaDB example). The same cautions
apply: leave the database in place, and do not run `mariadb/schema.sql`
again, which sets the application account's password on every run. A
second run inserts nothing. A valid index of the wrong shape is left as
it is; drop it and run the script again, then start the 1.1.0 image.
A 1.1.0 image started first still starts: an account that may not alter
the table logs `STS-STORE-0172`, and one that may builds the index in
place in the background (`STS-STORE-0173` if that fails).

### Behaviour changes: a deleted object leaves nothing behind

1.1.0 makes a delete complete. An application, person or group created
again under a deleted one's identifier, username or DN inherits nothing
from it. Each of these changes what 1.0.0 did:

* **Over LDAP, a group may not list a member that does not exist.** An
  add or modify that names a `member`, `uniqueMember` or `memberUid` with
  no entry behind it is refused with result code 19
  (`constraintViolation`). 1.0.0 accepted it. A script that adds a group's
  members before their entries must create the entries first. A dangling
  member that a 1.0.0 directory already holds is kept, and the console
  still reports it.
* **A delete takes the deleted entry's references with it.** A deleted
  person, group or application is taken out of every group that listed
  it and every role it was a member of. A deleted application no longer
  confers any role, and a deleted person or group is no longer an owner
  of any role, group, application or service account. 1.0.0 left these
  references in place, so whatever was next created under the same name
  or DN got them. Each removal is written to the audit log.
* **Deleting an application deletes the roles it owns.** A role made for
  one application (`<role>@<application>`, its `roleApplication` naming
  that application) is deleted with it, as the console's Delete role
  deletes one, with a `roles.delete` audit row for each. Its members and
  permissions go with it. A role owned by another application, and a
  realm-wide role, are not touched. In 1.0.0 these roles stayed, and an
  application registered again under the same identifier found them
  waiting, members included. If you still need such a role, create it
  again once the new application exists.

None of these changes the stored data or needs a migration step. They
apply to deletes made after the 1.1.0 image starts. References a 1.0.0
service left behind before the upgrade stay until you remove them on the
console or through `/admin-api`.

### AuthZEN ignores members it does not define

In 1.0.0, an [AuthZEN](authzen.md) request carrying a member that AuthZEN
1.0 does not define was refused with 400. In 1.1.0 it is accepted, and the
member is ignored, as AuthZEN 1.0 section 10.1.1 requires ("receivers MUST
ignore unknown fields"). This covers every request under `/access/v1`:
an evaluation, an evaluations batch, the three searches and an access
request. It applies at the top level and inside `subject`, `action`,
`resource`, `page` and `options`. An Action Search's `action`, which the
search does not define, is ignored too.

Nothing else about a request changes. A defined member is still checked
for type and presence. A property inside `properties` or `context` still
needs a conversion rule. BULK's `items` on an access request is still
refused. A request that worked in 1.0.0 gets the same answer.

`STS-AUTHZEN-0009` is retired. Other APIs still refuse members they do not
declare. The remote PEP's AuthZEN endpoint in the `xacml-pep` container
follows the same rule.

### A federated OpenID Provider may leave out its `issuer`

This applies to a federation relationship that finds its OpenID Provider
through an [OpenID Federation](configure-oidfed.md#this-service-as-a-federated-relying-party) Trust Anchor
(`fedTrustAnchor`). In 1.0.0, the sign-in was refused with `STS-FED-0149`
when the provider's resolved `openid_provider` metadata had no `issuer`.
In 1.1.0 an absent `issuer` is read as the provider's Entity Identifier.
OpenID Federation for OpenID Connect 1.1 section 5.1.2 allows no other
value. An `issuer` that is present and names another entity is still
refused. The ID Token's `iss` is still checked against the Entity
Identifier. Nothing this service publishes changes.

### New: export and import a person as LDIF

A person's page under **Directory → Users** has an **Import / export** tab,
the one an application's page has had since 1.0.0. **Export** saves the
person as an LDIF file of one record: the attributes a create takes, and,
only when its box is ticked, their credentials **unencrypted** (the
password as its stored hash, the authenticator app, passkeys, recovery
codes, app passwords and stored certificates). **Import** creates a person
from such a file in the realm the console is in, and never overwrites one
who is already there. Both need Admin Write and a recent sign-in. The API
is `POST /admin-api/users/export-ldif` and `/import-ldif`; see
[Exporting and importing a person as LDIF](admin-console.md#exporting-and-importing-a-person-as-ldif).
Nothing that existed in 1.0.0 changes.

## 1.0.0

1.0.0 is the first release of iya-sts. Every build before it was a
pre-release.

### SAML service provider metadata written through the API is read

Writing an application's `samlSpMetadata` through `POST /admin-api/applications/set`
or `add`, or through the console's field grid, now reads the document the way
creating the application or uploading the document always has: its assertion
consumer services, their bindings and its certificates are registered. Until
1.1.0 those doors stored the text and registered nothing, so a SAML 1.1 relying
party updated that way was answered with the Browser/POST profile at a consumer
its metadata declares for Browser/Artifact.

A document that does not describe the application is now refused with HTTP 400
and nothing is written, as the create and upload doors already refuse it
(`STS-ADMIN-0935`). Writing an empty value still clears it.

### An inbound OpenID Connect ID Token's `iat` is held to the sign-in

A federation relationship that signs people in from an OpenID Connect partner
now refuses an ID Token whose `iat` is before the sign-in started or after now,
each end widened by `oauth2.clockSkewS` (OpenID Connect Core 3.1.3.7, step 10;
`STS-FED-0253`). Nothing is redeemed and UserInfo is not asked after the
refusal. Until 1.1.0 any `iat` was accepted, so an ID Token issued a week
earlier signed a person in. This applies to every relationship, not only the
FAPI profiles. A partner whose clock is behind this service's by more than the
skew is now refused; raise `oauth2.clockSkewS` for it.

### Not backwards compatible with earlier builds

**1.0.0 is not backwards compatible with the pre-release builds that came
before it.** Moving an existing deployment from a pre-release build to 1.0.0
works in many situations, but there are edge cases with no clean upgrade path.
Stored settings, directory entries, persisted data or client configurations
created by an earlier build may need to be recreated rather than carried
forward.

This is deliberate. The earlier builds were pre-release versions, and we are
not attempting to keep 1.0.0 compatible with them.

**If this causes you trouble, open an issue** on the GitHub repository:
[github.com/rcbj/iya-sts/issues](https://github.com/rcbj/iya-sts/issues). Say
which build you are moving from and what did not carry over.

### Backwards compatibility from here on

**Our goal is backwards compatibility going forward.** Releases after 1.0.0
are intended to upgrade cleanly from 1.0.0 and from each other. The steps
from a running 1.0.0 deployment to 1.1.0 are in
[1.1.0](#110) above. Where a later release cannot upgrade cleanly, its
notes on this page will say so and describe the path.

### Version numbers

A build reports its version as `M.N.O.<build>`. `M.N.O` is the release, and
for 1.0.0 the release build is `1.0.0.0`. Other builds of the same code carry
the UTC time they were built as their build number. After 1.0.0, each change
published from `main` is the next patch release (1.0.1, 1.0.2, …), and a new
minor or major release starts when the repository's `VERSION` file is set to
it. **A release that needs an upgrade script is a minor (or major) release,
never a patch**: going from one patch release to the next never asks you to
run anything against your database. That is why the release after 1.0.0 is
1.1.0. The running service shows its version on the admin console and in its
metadata.
