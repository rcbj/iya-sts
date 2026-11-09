---
title: Logging inventory
nav_order: 15
---

# Logging inventory

This page lists every place iya-sts and its stack write a log, what goes there,
who can read it and how long it stays.

**The destinations are a closed set.** The service process writes log records to
standard output and standard error, to its audit store, and to the export
destinations an administrator configures. It writes them nowhere else. The
service never opens a log file of its own and never sends a log over the
network except through audit export.

## The inventory

| Layer | What is logged | Format | Where it goes | How it is used | Who can read it | How long it is kept |
|---|---|---|---|---|---|---|
| **Service process**, including every request worker | Start-up, configuration problems, each failure with its error code, refusals recorded on the audit log, scheduler activity. Debug level adds every function entry, request and response | Bunyan: one JSON object per line. An unexpected failure starts with its code, `STS-<SUBSYSTEM>-<NNNN>` | Standard output, plus standard error before the logger exists | Diagnosing faults. Codes are listed on [Error codes](error-codes.md) | Whoever can read the container's output | Your container runtime's log retention. The service does not rotate or keep it |
| **Audit log** | Each credential accepted, session started or ended, directory operation, console and API action, and protocol call | Structured rows: time, category, action, outcome, actor, target, address, error code, summary | Memory, and in product on PostgreSQL the sealed audit store | Security review, investigation, `/admin/audit`, reports | Admin Read in that realm, at `/admin/audit` and `GET /admin-api/audit` (`admin:read`). Report users, in the `auditEvents` report source | `audit.maxEvents` rows (5000) per realm. The oldest are dropped, and the page shows how many |
| **Audit export** | The audit rows, after redaction | RFC 5424 syslog, or one JSON line per event in a file, a webhook or an HTTP collector | The destinations you configure: `syslog`, `logrhythm`, `file`, `webhook`, `splunk` | Your SIEM | Whoever you give access there | The destination's own retention |
| **A person's sign-in history** | That person's assessed sign-ins | Rows on the portal | Derived from the audit log and the risk tables | Lets a person spot misuse | The person | `audit.authenticationHistoryDays` (30), within the audit log's own cap |
| **Risk history** | Each sign-in's assessment, and refused passwords | Database rows; the address is sealed and kept as a network | `sts_risk_*` tables | Risk scoring | Admin Read in the realm | `risk.assessmentRetentionDays` (90), `risk.historyRetentionDays` (180), `risk.failureRetentionDays` (30) |
| **Scheduler runs** | Each job run and its outcome | Rows | The store | Operations, `/admin/scheduler` | Admin Read | `scheduler.runHistoryCount` and `scheduler.runHistoryHours` |
| **Shared Signals dead letters** | Events that could not be delivered, per stream | Rows | The store | Retrying delivery | Admin Read | `ssf.deadLetterRetentionS` |
| **Remote PEP container** | Its decisions and failures, in the same shape | Bunyan-shaped JSON lines | Its standard output | Diagnosing the PEP | Whoever can read that container | Your container runtime |
| **PostgreSQL** | Slow-query plans and lock waits on the shipped stack, and the server's own messages | PostgreSQL's log format | The database container's output | Tuning | Whoever can read that container | Your container runtime |
| **Secret store** (OpenBao, on the shipped stack) | Its own operations | OpenBao's format | That container's output | Operations | Whoever can read that container | Your container runtime |
| **Reverse proxy or load balancer** | Your choice | Your choice | Your choice | Your choice | Your choice | Your choice |

## Rules that apply to every log

* **No credential is recorded in the audit log or in an export.** No password,
  bearer token, assertion, or request or response body. A capability in a path
  or query is replaced with `(redacted)`. See
  [Data classification](data-classification.md).
* **The audit log never fails an operation.** A write that cannot be recorded
  is logged and the operation continues.
* **An error code is recorded and never sent to a client**, apart from pages
  and fixed help text that are themselves for administrators.
* **An audit row records who acted.** Reading the audit log is itself recorded.

## Log level

The shipped configuration runs at `info`. `global.logLevel` can be changed at
run time.

> **Warning.** At `debug` or `trace` the service log receives every request and
> response, headers and bodies included, and every token and assertion before and
> after it is signed. Nothing is removed. That is Restricted and Bearer data.
> Product mode does not refuse the setting, so use it only on a deployment with
> no real data.

The generated password of the first administrator is written to the file
`bootstrap-admin-password` in `persistence.dataDir`, not to the log, unless
`admin.logBootstrapPassword` is on.

## Where the service log goes

The service writes to standard output and leaves storage to you. Run it under a
container runtime or a process manager that keeps the output, rotates it, and
limits who can read it. If you need a tamper-evident record, export the audit log
to a destination that provides one. See [Audit export](audit-export.md).

## Related

* [Admin console → Audit log](admin-console.md#audit-log--adminaudit)
* [Audit export destinations](audit-export.md)
* [Error codes](error-codes.md)

## Time

Every timestamp is in UTC. Run the service on hosts whose clocks are synchronized
with NTP, so that timestamps agree across nodes and with the systems you send logs
to.
