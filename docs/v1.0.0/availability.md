---
title: Availability and resource limits
nav_order: 15
---

# Availability and resource limits

This page lists what is expensive in iya-sts, how the service stops overuse from
taking it down, and how it avoids making a caller wait past its own timeout.

## What is expensive

| Feature | Why | Defence | Setting or limit |
|---|---|---|---|
| **Password hashing** (scrypt) | Costs memory and CPU on purpose | Runs on libuv's thread pool, off the event loop. Attempts are rate limited per identity and per address, and a growing wait follows each refused password | `security.rateLimitPerIdentity` (5), `security.rateLimitPerAddress` (20), `security.rateLimitWindowS` (60). The compose stack sets `UV_THREADPOOL_SIZE` to 32 |
| **Post-quantum signing and key generation** | Slow algorithms | Run natively on the same thread pool | Off the event loop |
| **Protocol request handling** | Every request runs on one of a few threads | Worker threads run the protocol stack, so the listener is not blocked. Each thread has a heap limit, and one that reaches it is replaced | `workers.requestCount`, `workers.surfaceCount`, `workers.heapLimitMb` |
| **SCIM bulk and Shared Signals receive** | Large writes | A dedicated lane, so a bulk load cannot fill every worker. Past the queue, the answer is `503` with `Retry-After` | `workers.batch`, `workers.batchWorkerShare` (50%), `workers.batchConcurrency` (8), `workers.batchQueueLimit` (5,000), `workers.batchQueueTimeoutS` (60), `scim.bulkMaxOperations` (100), `scim.bulkMaxPayloadSize` (1 MiB) |
| **Directory searches** | A broad filter can read many rows | Paged in a windowed process, stopping at the first limit reached. The partial answer is marked incomplete | `ldap.sizeLimit` (500), `ldap.timeLimit` (30 s) |
| **Reports** | Can read a whole realm | Bounded synchronously, and queued above that. Limited per realm and per person | `report.syncMaxRows` (500), `report.syncMaxBytes` (1 MB), `report.syncMaxMs` (10 s), `report.asyncMaxRows` (100,000), `report.asyncMaxBytes` (32 MB), `report.asyncMaxMs` (120 s), `report.maxConcurrentPerRealm` (2), `report.maxConcurrentPerSubject` (1) |
| **Risk dataset import** | Files up to 2 GiB | Streamed and imported in the background. The upload answers as soon as the file is stored | `risk.uploadMaxBytes`, `risk.expandedMaxBytes`, `risk.expansionMaxRatio`, `risk.importStallMinutes` (15) |
| **Periodic jobs** | Every realm's hourly job falls due together | At most a fixed number run at once, each with a time limit | `scheduler.maxConcurrentRuns` (0: two runs, or one fewer than the request worker threads when that is more), `scheduler.runTimeoutS` (600) |
| **Outbound requests** | A partner may be slow or hostile | A timeout and a response cap. A fetch not needed for the answer is never awaited | `federation.outboundTimeoutMs`, `federation.maxResponseBytes` |
| **Compressed and XML messages** | Can expand without bound | Inflated up to a fixed limit, parsed with no document type | Fixed |
| **Request bodies** | Memory | 5 MB at most, unless a field states less | Fixed |
| **Requests from one address** | Any endpoint, repeated | A ceiling per address per minute in each process. Past it, the answer is `429` with `Retry-After: 60`, and one warning per address per minute is logged (`STS-CORE-0172`). `/healthcheck` is not counted | `security.requestsPerAddressPerMinute` (6000 in product mode, `0`, no ceiling, in development) |
| **Connections** | File descriptors and memory | Limited per listener | `http.maxConnections`, `http.maxRequestsPerSocket`, `http.headersTimeoutS`, `http.keepAliveTimeoutS` |
| **Sessions and in-flight sign-ins** | Memory and store rows | Capped. At the cap a new row is refused, and nothing is ended to make room for somebody else | `authn.maxSessions` (100,000), `authn.maxSessionsPerSubject` (32), `oidcRp.maxFlows` (200) |
| **Shared Signals push** | A slow receiver | One queue per receiver. Past it, an event is dead-lettered | `ssf.pushBacklog` (2,000) |
| **The audit log** | Grows without bound | A ring. The oldest rows drop, and the page shows how many | `audit.maxEvents` (5000) |

## Answering before the caller gives up

The service answers quickly or tells the caller to come back. It does not hold a
connection for slow work.

* **Queued work.** A large report is a job: the caller gets an id and polls for
  the result.
* **Answer first, finish later.** A risk dataset answers when stored, and
  `POST /ssf/verify` answers `204` when queued.
* **Polling protocols.** ACME orders, the device flow and CIBA return at once and
  the client polls.
* **Refuse rather than wait.** A full batch lane answers `503` with `Retry-After`
  within `workers.batchQueueTimeoutS`.
* **A search ends with a partial answer** at its time limit.

The HTTP server's own request timeout is five minutes. The whole of a very large
upload has to arrive in that time. For a very large risk dataset, use
`risk.datasetsDirectory`.

## What you must add

The service limits credential attempts and the costly features above. It also
puts a ceiling on all requests from one address:
`security.requestsPerAddressPerMinute`, 6000 a minute in product mode and off in
development. Behind a proxy, set `global.trustedProxies` so the address is read
correctly. The ceiling is counted per process, so a cluster of N nodes allows N
times as much. There is no per-client limit and no limit on how many requests
one client can run at once. Put a rate limit sized for your users in front of
the service, in your load balancer or gateway, and size the thread pool and the
workers for your load.

## Related

* [Where a request waits](request-path.md)
* [Architecture](architecture.md)
* [Reports](reporting.md)
