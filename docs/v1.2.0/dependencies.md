---
title: Dependencies, limits and timeouts
nav_order: 15
---

# What iya-sts connects to, and how it behaves when a dependency is slow, full or down

This page is for operators who size, monitor and run a product deployment. For
every system iya-sts connects to, it says how many connections the service
opens, what happens at that limit, how long it waits, whether it tries again,
and what a caller sees when the system is down. It satisfies ASVS 5.0.0 13.1.2
(connection limits, and behaviour at the limit) and 13.1.3 (timeouts, retries
and fail-open or fail-closed behaviour, per dependency).

Defaults are the same in product and development mode unless a row says
otherwise. Where a limit is fixed in the code rather than a setting, the row
says "fixed" and names the file. Error codes are in [Error codes](error-codes.md).
They are recorded in the audit log and the service log, and never sent to a
client.

## The overall rule

**Every outbound call has a timeout. A request a person or client is waiting on
does not retry a failed call: it fails, or carries on without the answer, at
once.** Work that has to be delivered is written down first and delivered in
the background, and only that background work retries, with a growing wait:

* the scheduler's jobs (see [Cluster concepts](cluster-concepts.md));
* the mail outbox (`mail.deliver`);
* the shared delivery queue for back-channel logout, CIBA notifications,
  Provider Commands and deliveries between cells;
* Shared Signals push and polling;
* the outbound SCIM client;
* audit export (`audit.export`);
* the database write-behind flush.

A dependency the service cannot start without (the database, the
key-encryption key) stops the start. A dependency it can run without is
reported and the request fails closed, except where a row below says the
service fails open, and why.

**Exceptions to "no retry in a request".** Each is bounded, and none waits
long:

| Where | What is repeated | Bound |
|---|---|---|
| A database transaction that meets a deadlock or a serialization failure (PostgreSQL `40P01`, `40001`; MariaDB `1213`, `1205`) | The transaction | 3 more attempts, each after a random pause of about 10 to 130 ms (`persistence/persistence_postgres.js`, `DEADLOCK_RETRIES`). MariaDB's portable stores allow up to 8 (`persistence/store_portable.js`) |
| The listener process handing a request to a request worker, when the connection to the worker fails before any answer | The hand-off, once, on a new connection to the same worker | Once (`common/request_pool.js`) |
| A FAPI request to a federation partner answered `use_dpop_nonce` | The request, with the nonce | Once, as RFC 9449 section 8 requires (`federation/fapi_client.ts`) |
| A Claims Provider answering `401` while an ID Token or UserInfo answer is built | The call, after a token refresh | Once (`oauth-oidc/claims_providers.ts`) |
| A transmitter answering `401` to this service's Shared Signals receiver | The call, with a new token | Once (`ssf/ssf_transmitters.ts`) |
| An administrator's **Send event** on a Shared Signals stream | The push | `ssf.pushRetries` times, 0 by default |
| A call to another cell that cannot connect or times out | The call, to the cell's next address | One try per address (`common/cell_channel.ts`) |
| An HSM operation that finds its session or token gone | The operation, on a fresh session | Once (`common/crypto_impl/pkcs11.js`) |
| An OpenBao or Vault Transit call answered `403` | The call, after logging in again | Once (`common/secrets.js`) |
| A client's `jwks_uri` with no key of the presented `kid` | The fetch | Once, at most every `oauth2.clientJwksRefetchS` (30 s) |
| Creating a directory entry whose name another node has just claimed | The claim | Every 50 ms for up to 5 s, then refused as in progress (`ldap/directory_create_claims.ts`) |

## Infrastructure

| Dependency | Connections or concurrency | At the limit | Timeouts | Retries | When it is down | Settings |
|---|---|---|---|---|---|---|
| **PostgreSQL and MariaDB** (the store) | A pool per process of `max(4, 2 × workers)` connections, where workers is `workers.requestCount` + `workers.surfaceCount`. A second pool of 2 for counters, a read pool of the same size when a read replica is set, and one listening connection (PostgreSQL) per process | A caller waits for a free connection, in order, for up to 5 s, then fails | Connect 5 s, idle connection closed after 30 s, both fixed (`persistence/persistence_postgres.js`, `persistence/knex_store.js`). No statement timeout on ordinary queries. `persistence.metricsTimeoutMs` (5000) bounds the queries behind `/admin/database` | Deadlocks and serialization failures: see above. A failed write-behind flush is retried from 1 s, doubling to 30 s, until it succeeds (`STS-STORE-0002`). The PostgreSQL change listener reconnects from 1 s, doubling to 30 s (`STS-STORE-0035`, `STS-STORE-0036`) | **At start: the service does not start** (`STS-CORE-0036`). Running: a request whose write cannot be committed is answered `503` with `Retry-After: 5` (`STS-STORE-0066`), and an LDAP operation `unavailable` (52, `STS-STORE-0067`). Reads are served from memory | `persistence.mode`, `persistence.databaseUrl`, `persistence.databasePasswordProvider`, `persistence.globalDatabaseUrl`, `persistence.globalDatabaseReadUrl`, `workers.requestCount`, `workers.surfaceCount` |
| **Secret store: OpenBao or Vault** (key-encryption key, database password, PKCS#11 PIN, mail and other secrets) | 8 connections per process, kept alive (`common/secrets.js`) | Calls wait for a connection | **None is set** on the Vault client (`common/secrets.js`). The `/admin/secrets` probe is bounded by `keys.storeProbeTimeoutMs` (5000). Pushing a rotated password to a Vault destination times out after 10 s, fixed | A Transit call answered `403` logs in again and repeats once. Nothing else | **At start: the service does not start** when the key-encryption key or the database password cannot be read (`STS-KEYS-0043`, `STS-KEYS-0044`, then `STS-CORE-0035` or `STS-CORE-0036`). Secrets are read once at start and held in memory, so a store that goes down later does not affect a running process. With a Transit key-encryption key, a data key that cannot be wrapped is not written (`STS-KEYS-0103`) | `keys.kekProvider`, `keys.kekVault`, `keys.kekRef`, `keys.kekField`, `keys.kekTransitMount`, `keys.vaultClientCert`, `keys.vaultCaCert`, `keys.storeProbeTimeoutMs`, `secrets.allowLocalSecrets` |
| **Cloud key management and secret managers** (AWS KMS and Secrets Manager, Google Cloud KMS and Secret Manager, Azure Key Vault) | At start, at most 8 data keys unwrapped at once, 4 key rows at a time: 32 calls in flight per process (`common/keystore.js`). One unwrap in flight per data key afterwards | Calls wait | **None set by the service.** Each cloud SDK's own default applies (`common/secrets.js`) | **None set by the service.** Each SDK's own default applies | As for OpenBao: no start without the key-encryption key or the database password. A wrap or unwrap that fails at run time is `STS-KEYS-0103`, and the data key stays wrapped | `keys.kekProvider`, `keys.kekRef`, `keys.kekRegion`, `keys.previousKekProvider` |
| **PKCS#11 HSM** | `keys.pkcs11Sessions` (4) sessions per token in each thread, plus one for blocking calls. A warning `STS-KEYS-0210` at start when the total reaches libuv's thread pool size | A call waits for a free session, with no limit on the queue and no timeout (`common/crypto_impl/pkcs11.js`) | **None** on HSM operations. A thread waiting to re-initialise the module waits 30 s, or 2 s for a blocking call (`STS-KEYS-0212`, `STS-KEYS-0213`) | On a lost session or token (`CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`, `CKR_SESSION_HANDLE_INVALID` and others), the operation opens a new session, logs in and runs once more, re-initialising the module once if it must | A data key that cannot be unwrapped at start stops the start. At run time the operation is refused (`STS-KEYS-0201`) and the service keeps running. See [Keys in a hardware security module](hsm.md) | `keys.pkcs11Module`, `keys.pkcs11Sessions`, `keys.pkcs11PinProvider`, `keys.signingKeyStore`, `keys.signingKeyToken`, `keys.pkcs11SynchronousSign` |
| **Mail relay** (SMTP, Amazon SES, Azure Communication Services, Gmail) | No connection pool: one SMTP connection per message. A delivery run sends `mail.concurrency` (4) at a time. The first attempt, made just after a message is queued, is not limited | The outbox holds `mail.maxRows` (10,000) rows per realm. Past it, the oldest finished rows are removed. A pending message is never removed to make room, so pending rows can exceed the cap | `mail.timeoutMs` (30,000) for connect, greeting and each socket read, and the whole SMTP transaction within 1 s more. The same bound for the cloud transports | In the `mail.deliver` job, every `mail.deliverS` (15 s): up to `mail.attempts` (5), waiting `mail.backoffS` (60 s) doubled each time. Only a timeout, a lost connection, an SMTP `4xx` or a cloud throttle or `5xx` is retried. A rejected recipient or a failed sign-in is final | **Fails open for the request**: the action that sent the mail succeeds, and the mail is queued. A message still pending after `mail.retentionS` (7 days) is dead-lettered (`STS-MAIL-0019`) and can be sent again from the console. See [Mail](mail.md) | `mail.transport`, `mail.timeoutMs`, `mail.concurrency`, `mail.deliverS`, `mail.attempts`, `mail.backoffS`, `mail.retentionS`, `mail.maxRows` |
| **Attribute-source databases** (PostgreSQL, MySQL or MariaDB) | 4 connections per source per process, fixed (`attribute-sources/attribute_source_drivers.ts`) | A lookup waits for a connection, up to the source's timeout | Each source's own **timeout** (2000 ms by default, 100 to 30,000) bounds the wait for a connection and the query, which is cancelled at the limit (`STS-ATTR-0003`). No separate connect timeout | None. A failure other than a timeout drops the pool, and the next lookup builds a new one | Each source's **On failure**: `keep` (the default) **fails open**, and the person signs in with the attributes their entry holds (`STS-ATTR-0002`, `STS-ATTR-0003`); `refuse` **fails closed** and refuses the sign-in (`STS-ATTR-0012`). See [Attribute sources](attribute-sources.md) | The source's timeout and On failure; `attributeSources.hostPatterns`, `attributeSources.refreshBatch` |
| **Malware scanner** (ICAP, such as c-icap with ClamAV) | No limit: one connection per file scanned (`common/malware_scan.ts`) | None | `malwareScan.timeoutMs` (30,000) of inactivity on the socket, plus 1 s per MiB of a file. No total deadline | None | **Fails closed** while scanning is on: an upload is refused `503` (`STS-CORE-0169`). A flagged file is refused `422` (`STS-CORE-0168`). With scanning off, files are not scanned. See [Malware scanning](malware-scanning.md) | `malwareScan.enabled`, `malwareScan.url`, `malwareScan.timeoutMs`, `malwareScan.allowCleartext` |
| **Audit export destinations** (syslog, file, webhook, Splunk HEC, LogRhythm) | Each process delivers its own audit log; every destination at once, each in order, one event at a time. A run sends at most `auditExport.batch` (50) events per destination within `auditExport.budgetMs` (2000) | Events wait in the audit ring, `audit.maxEvents` (5000). Rows the ring drops before delivery are counted and logged (`STS-AUDIT-0009`) | `auditExport.timeoutMs` (5000) for connect and each write | In the `audit.export` job, every `auditExport.intervalS` (5 s). The cursor holds and the wait doubles from `auditExport.retryInitialMs` (1 s) to `auditExport.retryMaxMs` (5 min), or follows a `Retry-After` up to 1 hour. After `auditExport.retryMaxPeriodMs` (1 day) of failure, a batch that fails again is given up (`STS-AUDIT-0011`) | **Fails open**: the audited action is never refused because export failed. Delivery is at least once. See [Audit export](audit-export.md) | `auditExport.*`, `audit.maxEvents` |
| **Secret destinations** (where a rotated service-account password is pushed: AWS, Google Cloud, Azure, Vault, file) | One push per rotation | None | Vault: 10 s, fixed. Cloud SDKs: the SDK's default | None in the push. The hourly `service-accounts.rotate` job tries the rotation again, and raises an alarm after the policy's **Alarm after failures** (3) | **Fails closed**: the password is not changed unless the push succeeded (`STS-SVCACCT-0044`, `STS-SECDEST-0015`) | The service-account policy |

## Partners, clients and other services over HTTP

Most of these go through one dialer, `federation/federation_http.ts`. It
follows no redirect, stops reading at a size cap, and in product mode refuses
an internal address for a location a partner or caller can name (see
[Communications](communications.md#outbound-locations-a-caller-can-name)).
`federation.outbound` (on) switches the dialer off entirely.

**The dialer uses Node.js's global HTTP agent, which has no limit on the number
of open connections.** Nothing caps how many connections the service holds
open to partners at once.

| Dependency | Connections or concurrency | At the limit | Timeouts | Retries | When it is down | Settings |
|---|---|---|---|---|---|---|
| **Federation partners**: OpenID Connect discovery, token and UserInfo, JWKS, PAR | No limit (global agent) | None | `federation.outboundTimeoutMs` (15,000) of inactivity. Answers past `federation.maxResponseBytes` (256 KiB) are refused (`STS-FED-0050`) | None, except FAPI's DPoP nonce (above). Discovery and the partner's JWKS are fetched on every sign-in, not cached. An unknown `kid` is refused, not fetched again | **Fails closed**: the sign-in ends on an error page, `STS-FED-0054` for a timeout, `STS-FED-0055` for a network or TLS failure, `STS-FED-0051` for an error status | `federation.outbound`, `federation.outboundTimeoutMs`, `federation.maxResponseBytes`, `security.outboundAllowedHosts` |
| **A client's `jwks_uri`** | No limit (global agent). At most 256 key sets cached per realm | None | `federation.outboundTimeoutMs` | One fetch more for an unknown `kid`, at most every `oauth2.clientJwksRefetchS` (30 s). Cached for `oauth2.clientJwksCacheS` (300 s) | Serves the cached set when it has one. Without one, the client's signature is refused (`STS-OAUTH-0599`) | `oauth2.clientJwksCacheS`, `oauth2.clientJwksRefetchS` |
| **A client's `request_uri`** (RFC 9101) | No limit | None | `oauth2.requestUriTimeoutMs` (5000), including the connect. At most `oauth2.requestUriMaxBytes` (64 KiB) | None. `oauth2.requestUriCacheS` (0, off) caches it | **Fails closed**: `invalid_request_uri` | `oauth2.requestUriTimeoutMs`, `oauth2.requestUriMaxBytes`, `oauth2.requestUriCacheS` |
| **A client's `sector_identifier_uri`** | No limit | None | `federation.outboundTimeoutMs` | None | **Fails closed**: registration answers `invalid_client_metadata` (`STS-REG-0169`) | `federation.outboundTimeoutMs` |
| **SAML service provider metadata** and MDQ | No limit | None | `federation.outboundTimeoutMs` of inactivity, at most `saml2.spMetadataMaxBytes` (512 KiB) | In the background only: the `saml2.sp-metadata-refresh` job, every `saml2.spMetadataRefreshIntervalS` (300 s). An MDQ lookup a request starts runs after the answer and is not awaited | The metadata held is kept and used. Failures are `STS-SAML-0046` to `STS-SAML-0051` | `saml2.spMetadataRefreshIntervalS`, `saml2.spMetadataMaxBytes` |
| **Shared Signals: pushing to receivers** | `ssf.pushConcurrency` (8) per process | Each receiver's queue holds `ssf.pushBacklog` (2000) events. Past it an event is dead-lettered (`STS-SSF-0092`) | `ssf.pushTimeoutMs` (10,000) of inactivity, answers up to `ssf.pushMaxResponseBytes` (64 KiB) | `ssf.pushRetries` (0) more attempts, `ssf.pushRetryDelayMs` (1000) apart, for a timeout, network failure, `5xx` or `429`. An application may set its own | The event is dead-lettered. Nothing the receiver does refuses a sign-in | `ssf.pushDelivery`, `ssf.pushTimeoutMs`, `ssf.pushConcurrency`, `ssf.pushBacklog`, `ssf.pushRetries`, `ssf.pushRetryDelayMs` |
| **Shared Signals: polling transmitters** (this service as receiver) | Polled by the `ssf.foreign-poll` job, not by a request | A poll reads at most `ssf.foreignPollMaxRounds` (5) rounds of `ssf.foreignPollMaxEvents` (50) events | `ssf.foreignTimeoutMs` (10,000) | The next run, every `ssf.foreignPollS` (30 s). A `401` is asked again once with a new token | Logged (`STS-SSF-0162`); events wait at the transmitter | `ssf.foreignPollS`, `ssf.foreignTimeoutMs`, `ssf.foreignPollMaxRounds`, `ssf.foreignPollMaxEvents` |
| **Back-channel logout, CIBA notifications, Provider Commands, deliveries between cells** (one durable queue, `oauth-oidc/outbound_delivery.ts`) | Back-channel logout `oauth2.backchannelLogoutConcurrency` (8); CIBA `oauth2.cibaNotifyConcurrency` (8); commands `oauth2.commandConcurrency` (8); cells `cells.deliveryConcurrency` (8) | Each queue keeps up to its **max rows** (logout 2000, CIBA 2000, commands 5000, cells 100,000); past it the oldest finished rows are removed, never a pending one | Logout `oauth2.backchannelLogoutTimeoutMs` (5000); CIBA `oauth2.cibaNotifyTimeoutMs` (5000); commands `oauth2.commandTimeoutMs` (10,000); cells `cells.relayTimeoutMs` (10,000) | Written first, sent after the answer, then retried for a timeout, a connection failure, `5xx`, `408` or `429`: logout 3 attempts from 1 s; CIBA 5 from 2 s; commands 5 from 2 s; cells 12 from 2 s, each wait doubling | A delivery that is never accepted becomes a dead letter, which an administrator can send again. The sign-out or the act that caused it has already succeeded | `oauth2.backchannelLogout*`, `oauth2.cibaNotify*`, `oauth2.command*`, `cells.delivery*` |
| **Outbound SCIM** (provisioning into another system) | A durable queue, delivered by the `scim-client.deliver` and `scim-client.reconcile` jobs | On `429` or `5xx` the client pauses until the backoff ends | `scimClient.timeoutMs` (15,000). Answers up to 16 MiB, fixed (`scim/scim_client.ts`) | Up to `scimClient.attempts` (8), from `scimClient.backoffMs` (10 s) with random spread, up to `scimClient.maxBackoffMs` (1 hour), following `Retry-After`. A `412` is read again and retried `scimClient.etagRetries` (3) times | The change becomes a dead letter. The directory change itself has already been made. **Test connection** in the console makes one attempt | `scimClient.*` |
| **OpenID Federation** (entity statements and trust chains) | No limit | None | `oidfed.fetchTimeoutMs` (5000), at most `oidfed.fetchMaxBytes` (256 KiB) per statement and `oidfed.maxChainDepth` (6) | None. A resolved chain is cached for `oidfed.resolveCacheS` (1 hour), up to `oidfed.resolveCacheMax` (1000) | **Fails closed**: the entity is not trusted (`STS-OIDFED-0024`, `STS-OIDFED-0026`, `STS-OIDFED-0027`) | `oidfed.fetchTimeoutMs`, `oidfed.fetchMaxBytes`, `oidfed.resolveCacheS` |
| **CRL and OCSP responders** (for presented certificates) | One fetch per address at a time; up to `pki.revocationCrlCacheEntries` (256) cached | Other requests wait for the fetch in flight | `pki.revocationFetchTimeoutMs` (3000); a CRL up to `pki.revocationMaxCrlBytes` (1 MiB) | None. A failure is remembered for `pki.revocationFailureRetryS` (60 s) before the address is dialled again | `pki.revocationCheck` `auto`: **fails closed in product** (the certificate is refused, `STS-PKI-0119`) and open in development. See [PKI](pki.md) | `pki.revocationCheck`, `pki.revocationFetchTimeoutMs`, `pki.revocationMaxCrlBytes`, `pki.revocationFailureRetryS` |
| **GNAP push finish** (to a client's `finish` URI) | No limit | None | `gnap.pushTimeoutMs` (5000) | None | **Fails open**: the interaction finishes, the push is recorded as not delivered (`STS-GNAP-0604`) | `gnap.pushFinish`, `gnap.pushTimeoutMs` |
| **Claims providers** (aggregated claims) | No limit | None | `federation.outboundTimeoutMs` | A `401` refreshes the token and asks once more | **Fails open**: the ID Token or UserInfo answer is issued without those claims (`STS-OAUTH-0682`) | `federation.outboundTimeoutMs` |
| **Remote XACML PEPs** (a policy-change notice to `notifyUrl`) | One notice per change, not awaited | None | `xacml.pepNotifyTimeoutMs` (2000) | None, by design: the PEP also polls | Recorded; the PEP picks the change up when it next polls | `xacml.pepNotify`, `xacml.pepNotifyTimeoutMs`, `xacml.pepNotifyAllowedHosts` |
| **Other cells** (synchronous calls, mutual TLS) | A new connection per call | None | `cells.relayTimeoutMs` (10,000) | The next address of the cell, once per address | Handled as the cell being unreachable, under `cells.homeUnreachable` (`STS-CELL-0030`, `STS-CELL-0032`) | `cells.relayTimeoutMs`, `cells.homeUnreachable` |
| **Breached-password check** (the range API) | No limit | None | `risk.breachTimeoutMs` (3000) | None. Answers are cached for `risk.breachCacheMinutes` (60), up to `risk.breachCacheSize` (5000) | **Fails open**: the password is accepted unscreened and the failure logged (`STS-AUTHN-0224`) | `risk.breachCheck`, `risk.breachApiUrl`, `risk.breachTimeoutMs` |
| **Android attestation status list** and the FIDO metadata service | One download, in the `devices.android-status-refresh` and `risk.mds-refresh` jobs | None | `federation.outboundTimeoutMs` | The next run, daily by default (`devices.androidStatusRefreshS`, `risk.mdsRefreshS`) | The list held is kept. Past `devices.androidStatusStaleHours` (48), revocation is recorded as not checked (`STS-RISK-0046` for the failure) | `devices.androidStatusUrl`, `devices.androidStatusRefreshS`, `risk.mdsUrl`, `risk.mdsRefreshS` |
| **Content Security Policy report forward** | 8 forwards in flight per process, fixed (`common/csp_reports.ts`) | A report past that is counted and not forwarded | 5 s, fixed | None | Dropped; one warning until a forward succeeds again (`STS-HTTP-0031`) | `cspReports.forwardUrl` |
| **A partner's profile photo** | One per sign-in that copies it | None | 10 s, fixed (`common/profile_photo.ts`) | None | The person's photo is left as it was | — |

**Kerberos and LDAP do not dial out.** The KDC issues cross-realm referral
tickets that the client follows, and the directory does not chase referrals.
CRLs published over LDAP are fetched by the revocation check above, over LDAPS
unless `pki.revocationLdap` allows plain LDAP.

## Limits on the service's own listeners

The inbound limits are on [Availability and resource limits](availability.md).
In short:

* **Request bodies** are read up to 5 MB, fixed (`common/app.js`).
* **Connections** per listener: `http.maxConnections` (0, no limit),
  `http.maxRequestsPerSocket` (0, no limit), `http.keepAliveTimeoutS` (60) and
  `http.headersTimeoutS` (0: one second above the keep-alive timeout). The HTTP
  server's own request timeout is five minutes.
* **Requests from one address**: `security.requestsPerAddressPerMinute`, 6000
  in product and no limit in development; past it, `429` with `Retry-After: 60`.
* **Request workers**: `workers.requestCount` (1) and `workers.surfaceCount`
  (0) threads. The listener process holds at most `workers.maxSockets` (64)
  connections to one worker; past that a request waits for a connection.
* **The batch lane** (SCIM bulk, Shared Signals receive): a queue of
  `workers.batchQueueLimit` (5000), waiting at most `workers.batchQueueTimeoutS`
  (60). Past either, `503` with `Retry-After` (`STS-WORKER-0040`,
  `STS-WORKER-0041`).
* **Periodic jobs**: `scheduler.maxConcurrentRuns` and `scheduler.runTimeoutS`
  (600).

## Known gaps

These are what this page found with no limit, or no documented behaviour. Each
is a follow-up.

1. **No cap on outbound connections to partners.** `federation/federation_http.ts`
   passes no agent, so Node.js's global agent applies, with no `maxSockets`
   (ASVS 5.0.0 13.2.6). Closing it: a shared agent with a `maxSockets` setting,
   used by every dialer.
2. **The outbound timeouts are inactivity timeouts, with no overall deadline.**
   `federation.outboundTimeoutMs`, `ssf.pushTimeoutMs`, `gnap.pushTimeoutMs`,
   `malwareScan.timeoutMs` and the CRL fetch reset on every byte received, so a
   peer that answers slowly keeps the call open. There is no separate connect
   timeout. Closing it: a total deadline per call, and a connect timeout.
3. **No statement timeout on database queries.** Only the liveness, heartbeat
   and metrics queries set one (`persistence/persistence_postgres.js`). Closing
   it: a `statement_timeout` (and MariaDB's `max_statement_time`) setting for
   the pool.
4. **The database pool size and its 5 s waits are not settings**
   (`persistence/persistence_postgres.js`, `POOL_FLOOR`; `knex_store.js`).
5. **No timeout or retry policy is set for the secret store or the cloud SDKs.**
   The Vault client gets no timeout (`common/secrets.js`), and the AWS, Google
   Cloud and Azure clients use their SDKs' defaults, which this page does not
   state.
6. **HSM calls have no timeout, and the queue for a session has no limit**
   (`common/crypto_impl/pkcs11.js`, `acquire()`).
7. **No limit on concurrent malware scans** (`common/malware_scan.ts`): every
   upload opens its own connection to the scanner.
8. **The mail outbox's first attempt is not bounded by `mail.concurrency`**
   (`common/mail.ts`, `dispatch`), and pending rows may exceed `mail.maxRows`.
9. **A synchronous call to another cell reads its answer with no size cap**
   (`common/cell_channel.ts`, `call()`).
10. **Attribute-source pools are fixed at 4 connections** with no setting
    (`attribute-sources/attribute_source_drivers.ts`).
11. **A failed database flush is retried by a timer of its own**, not a
    scheduler job (`persistence/persistence.js`, `RETRY_FIRST_MS`), and so is a
    delivery queue's retry at its due time (`oauth-oidc/outbound_delivery.ts`,
    `later()`), with the sweep job as the net.

## Related

* [Availability and resource limits](availability.md)
* [Communication inventory](communications.md)
* [Where a request waits](request-path.md)
* [Key management](key-management.md)
* [Security in product mode](product-security.md)
