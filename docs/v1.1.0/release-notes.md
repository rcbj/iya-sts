---
title: Release notes
---

# Release notes

## Unreleased

These changes are on a feature branch and are not part of any release yet.

### The remote PEP authenticates with its key; the client certificate is retired

A remote XACML PEP authenticates every call it makes to the service — the
registration, the pulls, the heartbeat, the PIP, the decision records and
the AuthZEN forward — with a DPoP-bound access token from an RFC 7523
assertion it signs with its own key (`PEP_ASSERTION_KEY`). The key is
generated where the PEP runs and certified with `issue-pep-credential`; the
service never holds it ([How the PEP authenticates to the service](remote-pep.md#how-the-pep-authenticates-to-the-service)).

* **`xacml.pepAuthentication` defaults to `token`.** A PEP that presents only
  a client certificate is refused (401, `STS-XACML-0289`). `either` and
  `certificate` stay available for an older PEP image or another
  implementation.
* **The 1.1.0 upgrade script keeps a 1.0.0 deployment's PEPs working.**
  Every PEP 1.0.0 registered authenticated by its client certificate, so
  `postgres/upgrade-1.0.0.sql` and `mariadb/upgrade-1.0.0.sql` store
  `xacml.pepAuthentication` = `either` in every realm with at least one
  registered remote PEP (an entry under its `ou=peps`), only where the realm
  stores no value. When the default realm has a PEP its `either` is
  service-wide, so the script also stores `token` in each other realm with no
  PEP and no value. A realm with no PEP, and a new installation, get
  `token`.
* **Then move each realm to `token`**: give each PEP its key
  (`issue-pep-credential`, then `PEP_ASSERTION_KEY` on the 1.1.0 PEP image),
  and once every PEP in the realm holds its tokens, set
  `xacml.pepAuthentication` to `token` or reset it
  ([Upgrading a deployment whose PEPs use a certificate](remote-pep.md#upgrading-a-deployment-whose-peps-use-a-certificate)).
  Without the script (the LDIF store, or a split cell database), set
  `either` yourself before the PEPs reconnect. If a PEP is refused anyway,
  the 401 says that `either` would accept its certificate, and the service
  logs a warning under `STS-XACML-0289` once per realm.
* **The PEP ignores `PEP_TLS_CERT`** and says so once at start
  (`STS-XPEP-0135`). `PEP_TLS_KEY` is still read as the assertion key while
  `PEP_ASSERTION_KEY` is unset. `GET /`'s `credential.clientCertificate` is
  always `false`.
* **The CRL-only plain listener binds only with `PEP_CRL_HTTP=true`.** It
  served the client certificate's CRLs. A PEP with a CRL directory and no
  switch says once that it is not bound (`STS-XPEP-0136`).
* **An anonymous request to `/xacml/pep/*`** is now a 401 (`STS-XACML-0289`)
  in a realm on the default, where it was the access policy's 403.
* **The seeded client `sts-remote-pep`** no longer declares
  certificate-bound tokens; an entry a pre-release build seeded with the flag
  has it removed at the next start (audited as `application.update`). A token
  request through it with no DPoP proof is `STS-OAUTH-1012`.
* **The test stacks and the AWS suite runner** mint no client certificate
  for the PEP and post no trust anchor for it.

### A remote PEP's directory entry is a service account

The entry a remote XACML PEP's client certificate maps to is now a
[service account](service-accounts.md), owned by the realm's Admin Write
group, or by its bootstrap administrator where that group does not exist
([details](remote-pep.md#the-peps-entry-is-a-service-account)).

* **When it happens.** An entry becomes one when it joins `remote-peps`. The
  seeded `remote-pep-1` and every entry already in the group become one at
  the next start, so an existing deployment needs no step of its own.
* **What changes.** The PEP's connection is unaffected: mutual TLS is not a
  service-account door. A browser sign-in as the entry is now refused
  (STS-SVCACCT-0010) unless the realm's service-account policy allows it.
* **When it waits.** A realm with no Admin Write group and no bootstrap
  administrator leaves the entry as it is and logs STS-SVCACCT-0051: a
  service account is never made without an owner.
* **The console and the API.** The PEP's Overview tab shows it, with the
  owners and a link to the person's Service account tab. Each row of
  `GET /admin-api/xacml/peps` carries `identityAccount`. The change is
  additive.

### The remote PEP binds no plain-HTTP listener by default

The remote XACML PEP container (`iyasec/iya-sts-xacml-pep`) no longer binds
its plain-HTTP decision API on 9090 or its plain-HTTP reverse proxy on 9180
unless you ask for them. Over HTTPS, 9443 and 9543 behave as before.

* **To keep the old behaviour**, add `PEP_HTTP=true` (the API) and
  `PEP_PROXY_HTTP=true` (the proxy) to the container's environment. With
  `docker-compose.yml`, set `XACML_PEP_HTTP=true` and
  `XACML_PEP_PROXY_HTTP=true` on the host.
* **A container that sets `PEP_PORT` or `PEP_PROXY_PORT` without the
  switch** logs `STS-XPEP-0106` once at start, naming the line that brings
  the listener back. A switch set to anything other than `true` or `false`
  leaves the listener off and logs `STS-XPEP-0107`.
* **The image's healthcheck** probes `/healthcheck` over HTTPS on
  `PEP_HTTPS_PORT` when plain HTTP is off. A PEP with no HTTPS pair yet
  reports itself unhealthy until it has one. If something gates on that
  health, turn `PEP_HTTP=true` on.
* **`docker-compose.yml`'s default `PEP_NOTIFY_URL`** is now
  `https://xacml-pep:9443/notify`. The old `http://` default was refused unless
  `xacml.pepNotifyAllowHttp` was on.
* **The client credential's CRL stays reachable.** A credential minted with
  `tests/tools/pep-credential.js --crl-base=http://<pep>:9090/crl` names the
  PEP's plain port, and with plain HTTP off nothing answered there, so the
  service could not fetch the list and refused every pull as
  unauthenticated. With `PEP_HTTP` off the PEP now binds `PEP_PORT` for
  `GET /crl/<name>` and nothing else, whenever it has a CRL directory to
  serve. `PEP_CRL_HTTP=false` turns it off and `PEP_CRL_HTTP=true` binds it
  even with no directory; a value that is neither logs `STS-XPEP-0115`.
  **Since the client certificate was retired (above), only
  `PEP_CRL_HTTP=true` binds it.**
  Anything else asked of that port is a 404 (`STS-XPEP-0114`). The Listener
  tab shows it as *listening, CRLs only*.
* **Admin console**: the remote PEP's Listener tab shows the two listeners as
  *off*, each with its switch. A listener the PEP reports *off* no longer
  holds its port, so a listener defined on the tab may use 9090. A listener
  the PEP has not reported, or reported with no state, reads *not reported*
  (it read *listening* before), and an environment plain-HTTP listener with
  no report reads as its default, *off*.

### The nudge to a remote PEP is HTTPS only, and verifies with no setting

The service sends a remote PEP's "pull now" nudge over HTTPS only, in every
mode, and always verifies the PEP's certificate.

* **Trust with nothing set.** The PEP's HTTPS listener certificate is issued
  by the realm's Remote PEP listeners (`pep-tls`) Issuing CA, and the nudge
  verifies against that chain by default, with the host checked against the
  notify URL's. A certificate from this service's Root but another Issuing
  CA (another realm's PEP, a custom listener) is refused (`STS-XACML-0260`).
  `xacml.pepNotifyCaFile` is still read, as an additional anchor for a PEP
  certified elsewhere. The nudge that 8081 refused with "self-signed
  certificate in certificate chain" (`STS-XACML-0070`) is delivered.
* **`xacml.pepNotifyAllowHttp` and `xacml.pepNotifySkipTlsVerification` are
  retired.** Both are still accepted, so a configuration naming them keeps
  starting, and both are ignored; one that is on logs `STS-XACML-0258` once
  per process. Remove them. `GET /admin-api/xacml/peps`' `notify.transport`
  reports `allowHttp` and `skipTlsVerification` as `false`.
* **A PEP registered with an `http://` notify URL** is shown with that URL
  unusable, *plain http, the nudge is sent over HTTPS only*, and goes on
  converging by polling. Set its notify URL to
  `https://<host>:<PEP_HTTPS_PORT>/notify` (the PEP's Settings tab now
  refuses an `http://` one, `STS-XACML-0239`). `STS-XACML-0259` is recorded
  for a nudge refused that way; `STS-XACML-0073` and `STS-XACML-0074` are
  retired.
* **The PEP** answers `POST /notify` on its HTTPS listener only (a 404 over
  plain HTTP, `STS-XPEP-0112`), and **rejects** an `http://`
  `PEP_NOTIFY_URL`, or an `http://` `notifyUrl` an older service stored
  (`STS-XPEP-0113`, at ERROR, once per value). A rejected URL means the PEP
  advertises no notify URL at all, not the derived one, until it is fixed
  or unset. It is reported with `rejected: true`
  (`peps[].settingsInUse.values.notifyUrl.rejected` on
  `GET /admin-api/xacml/peps`), and the PEP's Settings tab and Notify column
  say it is rejected.
* **Admin console**: the Notify column of the Remote PEPs tab, and the PEP's
  Overview, show *usable*, *unusable* with a one-line reason, or *none*, and
  two words about the last nudge; the full sentences are under *Details*.
* **The PEP derives its notify URL when none is set.** With neither the
  PEP's Settings tab `notifyUrl` nor `PEP_NOTIFY_URL` set, the PEP advertises
  `https://<host>:<PEP_HTTPS_PORT>/notify`. `<host>` is the DNS name in the
  HTTPS listener certificate it serves that equals its hostname, else the
  certificate's first DNS name, else `PEP_NAME` if that is a DNS name, else
  the container's hostname. So a certificate naming the PEP's registered
  name first and `xacml-pep` second, on a container named `xacml-pep`, gives
  `xacml-pep`. A PEP with no HTTPS certificate yet
  advertises none until it has one, and a new certificate derives the URL
  again. The PEP logs the derived URL at INFO, and reports its source as
  `derived` (`GET /admin-api/xacml/peps`'
  `peps[].settingsInUse.values.notifyUrl.source`). The Notify column says
  *derived by the PEP from its HTTPS listener certificate*. The service still
  checks the URL as before: https only, the certificate verified, and the
  host checked against it. **`docker-compose.yml` and the test stack no
  longer set a notify URL**, so they derive it. `XACML_PEP_NOTIFY_URL`
  still sets one, and an empty one now means unset.
* **The PEP reports its hostname, and the realm's default certificate names
  it.** The PEP sends `hostname` (the value the derivation reads) on its
  registration and heartbeat. The service stores it and adds it to the
  default names of the PEP's HTTPS listener certificate, beside the
  registered name and the notify host, for both the environment pair and a
  defined listener's certificate. So on a fresh install the derived notify
  URL uses the hostname with no names added by hand. The PEP's Overview tab
  and `GET /admin-api/xacml/peps` (`peps[].hostname`) show it. The service
  accepts only a DNS name, never an IP address, and refuses anything else
  with 400 (`STS-XACML-0261`). A PEP that reports none keeps today's
  defaults, and an older service ignores the member. A certificate issued
  before this does not name the hostname: issue it again, or let a defined
  listener renew.

### The reverse proxy's fixes from the 8081 demonstration

* **The service's cookies never reach the application.** A browser sends
  cookies by host, not port, so where the service and the proxy share a host
  `__Host-sts_session` and the rest were forwarded upstream. The proxy now
  strips every cookie the service names on the pull
  (`realm.serviceCookiePrefixes`: `sts_*`, `__Host-sts_*`, `__Secure-sts_*`),
  and the managed setting `proxyStripCookies` (`PEP_PROXY_STRIP_COOKIES`) adds
  names, a trailing `*` for a prefix. The application's own cookies are
  untouched. A service older than this sends no list, and the PEP strips the
  same three prefixes.
* **An identity header with no value is not sent.** A person in no group sent
  an empty `X-Iya-Groups`; an empty string or list now sends no header, for
  every identity header.
* **`X-Iya-Amr` is sent.** The identity endpoint answered every proxy
  session's access token with no `amr`; it now reads the token's own `amr`,
  `acr` and `auth_time`.
* **A proxy session a CAEP signal ended clears its cookie** on the redirect
  to sign in, as the documentation said.
* **Between a sign-out and its signal**, a browser whose identity the service
  refused because its session had ended got a 403; it is now sent to sign in
  with the proxy session ended, and anything else gets a 401.
* **The account chooser shows usernames.** The service's ID Token carries no
  `preferred_username`, so an account was labelled by its `urn:uuid` subject;
  the sign-in now asks the service's session endpoint, whose answer also
  carries the person's display name (`name`), shown beside it.
* **A route's identity is edited on the route's own page.** The Reverse
  proxy tab drew a *How route … forwards the identity* form under its table
  for every route; that is now only the identity part of the route page's
  form, which the route id in the table links to.
  `POST /admin-api/xacml/set-pep-route-identity` is unchanged.
* **`/admin-api/xacml/*` PEP acts take `pep` as well as `name`**, the name
  `GET /admin-api/xacml/peps` takes as `?pep=`. `name` still works; both
  naming different PEPs is refused (`STS-XACML-0038`).

[Plain HTTP is off by default](remote-pep.md#plain-http-is-off-by-default)
has the precedence and the reasons.

### New: a remote PEP route's own page, and several accounts in one browser

* Each reverse-proxy route has a console page of its own, where every
  value can be edited and the route renamed
  ([A route's own page](remote-pep.md#a-routes-own-page)).
* A session route can let one browser hold several signed-in accounts and
  switch between them (`multipleAccounts`, off by default; the bound is
  `proxyMaxAccounts`, `PEP_PROXY_MAX_ACCOUNTS`, default 5;
  [Several accounts in one browser](remote-pep.md#several-accounts-in-one-browser)).

### Changed: every reverse-proxy route is authorized by its own policy

* **Every request on every route is decided in XACML by that route's own
  policy, never by the realm's root.** Each route makes one `authorization`
  choice: an existing policy, a simple generated policy (a resource, CRUD
  or read/write, and the roles for each action), or Public, which generates
  a policy too ([Authorizing a route](xacml.md#authorizing-a-route)). The
  route forms draw the choice as one selector, with a search for the policy
  and for each action's roles.
* **An empty methods list is deny-all**, and a route takes any method by
  listing all seven. Every route states its `methods`.
* **Not compatible with the proxy documents of earlier builds**, which the
  proxy feature's unreleased state allows: `public`, `resource` and
  `action` are refused as members, `methods` and `authorization` are
  required, and a remote PEP and the service upgrade together. Save each
  route's choice again (or edit the document) after the upgrade.

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

The script also stores `xacml.pepAuthentication` = `either` in every realm
that has a registered remote PEP and no value of its own, so PEPs that
authenticate by client certificate keep working on 1.1.0's new default,
`token` ([The remote PEP authenticates with its key](#the-remote-pep-authenticates-with-its-key-the-client-certificate-is-retired)).
It prints what it stored. That step needs the directory and the settings
in the same database; in a cell or tier database that lacks either, it
writes nothing and says so.

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
Its upgrade adds `sts_sessions_started`, records schema version 32, and
stores `xacml.pepAuthentication` = `either` in each realm with a registered
remote PEP, as the PostgreSQL script does.
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

### Behaviour changes: a service account is for good

1.1.0 holds three rules about [service accounts](service-accounts.md#it-cannot-be-undone)
at every door: the console, `/admin-api` and an LDAP modify. Each changes
what 1.0.0 did:

* **A service account cannot be made an ordinary person again.**
  `POST /admin-api/users/set-service-account` with `serviceAccount: false`
  on a service account is answered 400 (`STS-SVCACCT-0060`), and an LDAP
  modify that deletes or replaces `stsServiceAccount` is refused with
  result code 19 (`STS-SVCACCT-0064`). 1.0.0 cleared the flag, the owners,
  the destination and the rotation state. The console's **Make them an
  ordinary person** button is gone, and its **Make them a service
  account** button now asks you to confirm that it cannot be undone.
  Deleting the entry is still allowed.
* **A service account that has an owner always keeps one**, whatever the
  policy's `requireOwner` says. Removing the last owner, sending
  `owners: []`, or an LDAP modify deleting the last
  `stsServiceAccountOwner` is refused (`STS-SVCACCT-0061`,
  `STS-SVCACCT-0065`). In 1.0.0 this was allowed while `requireOwner` was
  off. An account made with no owner under `requireOwner` off can still
  be edited without naming one.
* **An owner cannot remove themselves.** Taking your own DN off an
  account's owners, or the group that is your only way of owning it, is
  refused (`STS-SVCACCT-0062`, `STS-SVCACCT-0063`; over LDAP, for the bound
  DN, `STS-SVCACCT-0066`, `STS-SVCACCT-0067`). Another administrator may
  remove you.
* **Deleting an account's last owner makes the realm's administrator the
  owner.** When the person or group that is a service account's only owner
  is deleted (SCIM `DELETE`, an LDAP delete), the realm's Admin Write group
  becomes its owner, or the realm's bootstrap administrator if there is no
  such group. An `admin.service-account.owner-added` row by `system` says
  so. In 1.0.0 the account was left with no owner. If the realm has
  neither, it still is, and `STS-SVCACCT-0068` is logged.

Existing service accounts are unchanged, and nothing needs a migration
step. A script that un-made a service account, or emptied its owners,
gets the refusal instead.

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

### AuthZEN requires `Content-Type: application/json`

AuthZEN 1.0 section 10.1 says a request MUST carry `Content-Type:
application/json`. In 1.0.0 the evaluation, the evaluations batch and the
three searches read any body as JSON, whatever it was labelled. In 1.1.0
a request labelled anything else, or not labelled at all, is answered
`415 Unsupported Media Type` (`STS-AUTHZEN-0117`) once the caller is
admitted. A `charset` parameter is accepted. A caller that sent JSON as
`text/plain`, or with no `Content-Type`, has to send the header. The
remote PEP's AuthZEN endpoint is unchanged.

### An AuthZEN resource search names the policy's resource ids

In 1.0.0 a [Resource Search](authzen.md#searching) for a resource type
this service has no objects of (anything but `application`, `api` and
`delegation`) answered no results, whatever the policy permitted. In
1.1.0 its candidates are the resource ids the realm's policies compare
`resource-id` with, and each is a result only where the policy permits
it as that type. Section 8.5 asks for every resource of the type the
subject may act on. The three types this service has objects of answer as
before.

### Policies can be exported and imported, whole or one at a time

New in 1.1.0: Directory → Policies has an **Export and import** tab, and
`/admin-api` has `POST /admin-api/policies/transfer/export`, `inspect` and
`import` with `GET /admin-api/policies/transfer` beside them. An export is a
JSON document signed under the realm's new Policy Export Signing CA, with the
signer's whole chain inside it. An import from another realm asks whether to
trust that realm's signer first. An export may carry every policy the realm
stores or only the ones named, each by its kind and name, and every stored
policy has an Export button of its own. An import may write every policy in
the document or only the ones ticked. [Policies](policies.md#export-and-import)
has the details.

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
