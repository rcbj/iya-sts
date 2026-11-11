---
title: Audit export destinations
nav_order: 12
---

# Audit export destinations

This page shows how to add each kind of audit export destination: syslog,
a file, a webhook, Splunk HTTP Event Collector, and LogRhythm. Each recipe
is the fields on **Monitoring → Audit export** (`/admin/audit-export`) and
the same call on the management API.

What the page draws, and how a failure is retried, is on
[Admin console → Audit export](admin-console.md#audit-export--adminaudit-export).
The fourteen settings, with their defaults, are on
[Configuration → Audit export](configuration.md#audit-export). This page
covers what to fill in, what the other side receives, and where that other
side documents the listener.

* TOC
{:toc}

## Before you add one

Open **Monitoring → Audit export**. **Add a destination** asks for an
**Identifier**, a **Name**, a **Type**, and then every field of every type.
Fill the fields for the type you picked and leave the others empty. The
identifier starts with a letter or a digit and then uses lower-case
letters, digits and hyphens, up to 63 characters (`siem`,
`splunk-cloud`). It stays as you first saved it. **Enabled** is ticked
for a new destination. **Test** on the row sends one synthetic event
straight away. The job that carries ordinary audit events runs every
`auditExport.intervalS` seconds (5 by default).

The same calls are `POST /admin-api/audit-export/{add,update,remove,enable,disable,test}`
with `admin:write`. `GET /admin-api/audit-export` is `admin:read`.
[Getting a token](management-api.md#getting-a-token) shows how to obtain
one. The examples below use this helper:

```bash
BASE=https://localhost:8081            # add /realm/<id> for a trust realm
TOKEN=...                              # management-api.md#getting-a-token

api() {   # api <path under /admin-api> '<json body>'
  curl -sk -X POST "$BASE/admin-api/$1" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d "$2"
}
```

A token and a secret header are sealed when they are saved. The page and
every API answer leave them out. On a later save, an empty **Token** box
keeps the sealed token. An empty **Secret headers** box keeps every sealed
header, and a line with a blank value keeps that one name.

Each process delivers the audit events it recorded itself. The event id
the destination receives is that process's origin and the event's `seq`,
written `origin:seq`. Delivery is at least once: a crash after the
destination has accepted an event can deliver that event again. Downstream
systems deduplicate on `id`. A destination you have just enabled receives
the events this process still holds, and then each new one.

A webhook or Splunk URL uses `https`. In development mode
`auditExport.allowHttp` may allow `http`, and that delivery is logged.
Product mode uses `https`. A loopback, link-local or private address,
including RFC 6598 `100.64.0.0/10`, is refused in product mode unless
`auditExport.allowPrivateDestinations` is on. Cloud metadata addresses
(`169.254.169.254`, `metadata.google.internal`, `metadata.azure.com`,
`instance-data`, `instance-data.ec2.internal`, and their subdomains) stay
refused when that setting is on. A name that does not resolve yet can
still be saved. Delivery waits until it does. TLS verification is on.
Name a private CA in `auditExport.caFile`. `auditExport.skipTlsVerification`
is development mode only.

## What a destination receives

File, webhook (with an empty template) and Splunk all carry this object.
Syslog and LogRhythm carry the same facts in an RFC 5424 line. A webhook
template may name the placeholders in the last column.

| Field | What it is | Template placeholder |
|---|---|---|
| `id` | `origin:seq`, or `test:<destination>:<time>` for a test | `{id}` |
| `seq` | The audit sequence number. `0` on a test | |
| `origin` | The process that recorded the event | `{origin}` |
| `timestamp` | The event time, ISO 8601 | `{timestamp}` |
| `at` | The same time, Unix milliseconds | |
| `severity` | `notice` for success, `warning` for a refusal, `error` otherwise | `{severity}` |
| `category` | The audit category | `{category}` |
| `action` | The audit action | `{event_type}` |
| `outcome` | `success`, `refused` or `error` | `{outcome}` |
| `errorCode` | The recorded code, when there is one | |
| `source` | Where the call came from | |
| `realm` | The trust realm. Empty in the default realm | `{realm}` |
| `subject` | Who acted | `{subject}` |
| `subjectForm` | How that subject was named | |
| `client` | The client or application, when the detail names one | |
| `address` | The client address | `{address}` |
| `target` | What the action was about | `{target}` |
| `protocol` | The protocol family | `{protocol}` |
| `channel` | The channel. `audit-export` on a test | `{channel}` |
| `message` | The one-line summary | `{message}` |
| `attributes` | The detail, after redaction | |

A placeholder this table does not list is left as you wrote it.
Replacement is one pass, so a value that itself contains `{message}` is
sent with those braces still in it.

`password`, `secret`, `token`, `authorization`, `client_secret`,
`assertion`, `access_token`, `refresh_token` and `id_token` are removed
from `attributes` even when `auditExport.redactKeys` is empty. The
setting adds names, and **Attributes to exclude** adds more for that one
destination. Matching is case-insensitive and walks nested objects. A
removed value is the string `[redacted]`.

**Test** sends a synthetic event with `message` `IYA-STS audit export
test`, `action` `audit.export.test` and `attributes.test` `true`. That
synthetic event stays off the audit log. The fact that somebody pressed
Test is an ordinary audit row, `admin.audit-export.test`, and that row is
delivered with everything else. A successful test answers `ok: true` and
a `diagnostic.disposition` of `accepted` (a file, or an HTTP collector
that answered 2xx) or `transmitted` (syslog handed to the socket).

## Syslog

The message is [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424). TCP
and TLS framing is [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587)
octet counting: a decimal length, a space, and the message, with no
newline added. TLS uses that framing on port 6514, the port
[RFC 5425](https://www.rfc-editor.org/rfc/rfc5425) assigns. UDP sends one
datagram per message, with no length prefix. A listener that splits a
TCP stream on a newline holds these frames until a newline arrives. Point
TCP and TLS at a collector that implements octet counting, such as
rsyslog's `imtcp` or syslog-ng's syslog driver.

| Console field | API member | What to put |
|---|---|---|
| Type | `type` | `syslog` |
| Host | `host` | The collector's host name or address |
| Port | `port` | Empty for 514, or 6514 when Transport is `tls`. `0` is the same |
| Transport | `transport` | `tcp` (the default), `udp` or `tls` |
| Facility | `facility` | Empty for local0, which is 16. Any RFC 5424 facility from 0 to 23 |
| Application name | `appName` | Empty for `iya-sts`. At most 48 characters |

Plain TCP is its own transport. `auditExport.allowHttp` covers webhook
and Splunk URLs.

**Product mode accepts a syslog or LogRhythm destination over `tls` only**, so
the audit log does not cross the network unencrypted. Name `tls` as the
transport, since `tcp` is the default. `tcp` and `udp`, as in the examples below,
are refused (`STS-AUDIT-0016`) unless `audit.allowPlainSyslog` is on. Turn it on
only for a collector on a network you trust.

On **Monitoring → Audit export**, **Add a destination**:

| Field | Value |
|---|---|
| Identifier | `siem` |
| Name | `Office SIEM` |
| Type | `syslog` |
| Host | `siem.example` |
| Port | leave empty |
| Transport | `tcp` |
| Facility | leave empty |
| Application name | leave empty |

```bash
api audit-export/add '{
  "id": "siem",
  "name": "Office SIEM",
  "type": "syslog",
  "host": "siem.example",
  "transport": "tcp"
}'
```

**Test** on this destination, facility local0, comes out as one RFC 5424
line. `<133>` is facility 16 and severity notice (5): the priority is
`facility × 8 + severity`. A refusal is warning (4) and any other
outcome is error (3). The structured-data id `iyaAudit` is a local
name. It is not registered with IANA.

```text
<133>1 2026-11-02T12:00:00.000Z sts-1 iya-sts 18 audit.export.test [iyaAudit id="test:siem:1793620800000" realm="" origin="" seq="0" category="service" outcome="success"] IYA-STS audit export test
```

HOSTNAME (`sts-1` here) is this process's host name. APP-NAME is the
application name. PROCID is the process id. MSGID is the action, with
spaces turned into underscores. `origin` is this process's id in the
store, and it is empty until the store has one. An ordinary audit event
uses its own action as MSGID and `origin:seq` as `id`. A message that is not ASCII is sent with a leading
byte-order mark, as RFC 5424 allows. UDP counts as transmitted when the
datagram has been handed to the kernel. TCP and TLS count as transmitted
when the write completes.

For TLS, set Transport to `tls` and leave Port empty (6514), or type the
port the collector actually listens on. The certificate is checked
against the host name you configured. Put that collector's CA in
`auditExport.caFile` when it is not in the public store.

## Filesystem

The destination is one absolute path. Each event is appended as one JSON
line, the object in [What a destination receives](#what-a-destination-receives).
Create the directory before the first delivery. The service creates the
file. On the [compose stack](docker-compose.md) the `sts-data` volume is
`/usr/src/sts/data` and the process runs as uid 10001:

```bash
docker exec sts mkdir -p /usr/src/sts/data/audit-export
docker exec sts chown 10001:10001 /usr/src/sts/data/audit-export
```

Set `auditExport.fileRoots` to that directory. With the setting empty,
any absolute path an administrator names is accepted. A relative path,
a path containing `..`, and a path outside the roots are refused.

| Console field | API member | What to put |
|---|---|---|
| Type | `type` | `file` |
| Path | `path` | An absolute path, at most 1024 characters |
| File mode | `mode` | Three octal digits, such as `640`. Empty is `640` |
| Rotation (bytes) | `rotateBytes` | `0` or empty leaves the file to grow. A positive size renames the file and starts a new one |

The mode is the mode of a file this service creates. An existing file
keeps the mode it already has. The owner is the user the process runs
as. When the file reaches the rotation size it is renamed to the path
plus a timestamp, for example
`audit.ndjson.2026-11-02T04-05-47-348Z`, and a new file is opened at the
original path.

Each process appends its own events. Two processes writing the same path
can interleave a line longer than 4096 bytes. Give each process a path
of its own when every line must stay a single record.

| Field | Value |
|---|---|
| Identifier | `audit-file` |
| Name | `Local audit file` |
| Type | `file` |
| Path | `/usr/src/sts/data/audit-export/audit.ndjson` |
| File mode | `640` |
| Rotation (bytes) | `104857600` |

```bash
api audit-export/add '{
  "id": "audit-file",
  "name": "Local audit file",
  "type": "file",
  "path": "/usr/src/sts/data/audit-export/audit.ndjson",
  "mode": "640",
  "rotateBytes": 104857600
}'
```

A full disk or a permission error pauses the destination and keeps the
event. The next run tries the same line again.

## Webhook

The request is an HTTP POST to the URL you name. A 3xx answer pauses
the destination, and the next attempt uses the same URL. There is no
required JSON schema. With **Body
template** empty, the body is the canonical event as JSON and the
content type is `application/json`. With a template, the body is that
text and the content type is `text/plain; charset=utf-8`, unless
**Content type** is set.

| Console field | API member | What to put |
|---|---|---|
| Type | `type` | `webhook` |
| URL | `url` | An `https` URL, at most 2048 characters. No user name or password in it |
| Content type | `contentType` | Empty for the default above |
| Body template | `template` | Empty for the JSON object, or a line of `{placeholders}` |
| Headers | `headers` | Plain headers, one `Name: value` a line |
| Secret headers | `secretHeaders` | The same shape, sealed |

A header named like a credential (`Authorization`, `token`, `api-key`,
`secret`, in any case) is sealed even when it is typed in **Headers**.
`Host`, `Content-Type`, `Content-Length`, `Transfer-Encoding` and
`User-Agent` in that box are dropped, because this service sets them.
The user agent is `sts/<version> (audit-export)`. The response body is
not recorded. An answer larger than 64 KiB is closed.

HTTP 200–299 accepts the event. HTTP 400 counts that one event
permanently failed and moves on to the next. HTTP 401 and 403 pause and
keep the event, so a corrected credential delivers it later. HTTP 429
and 5xx pause as well, and a `Retry-After` of a number of seconds or an
HTTP date is honoured, up to one hour.

The template from a typical line-oriented collector is:

```text
{timestamp} {severity} {event_type} {subject} {message}
```

which, for a test of this destination, sends:

```text
2026-11-02T12:00:00.000Z notice audit.export.test audit-export IYA-STS audit export test
```

| Field | Value |
|---|---|
| Identifier | `hooks` |
| Name | `Audit hook` |
| Type | `webhook` |
| URL | `https://logs.example/hooks/iya` |
| Body template | `{timestamp} {severity} {event_type} {subject} {message}` |
| Headers | `X-Request-Source: iya-sts` |
| Secret headers | `X-Api-Key: replace-with-the-real-key` |

```bash
api audit-export/add '{
  "id": "hooks",
  "name": "Audit hook",
  "type": "webhook",
  "url": "https://logs.example/hooks/iya",
  "template": "{timestamp} {severity} {event_type} {subject} {message}",
  "headers": "X-Request-Source: iya-sts",
  "secretHeaders": "X-Api-Key: replace-with-the-real-key"
}'
```

Leave the template out to post the JSON object instead. Saving again
with `"headers": ""` clears the plain headers. A secret header stays
until you replace its value.

## Splunk HTTP Event Collector

Create a token in Splunk, then point this service at the collector URL.
Splunk's own steps are
[Set up and use HTTP Event Collector in Splunk Web](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector),
the event shape is
[Format events for HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector),
and worked requests are
[HTTP Event Collector examples](https://docs.splunk.com/Documentation/SplunkCloud/latest/Data/HECExamples).

On a Splunk Enterprise instance: **Settings → Data inputs → HTTP Event
Collector**, enable the collector in **Global Settings**, then **New
Token**. Copy the token. The usual URL is
`https://splunk.example:8088/services/collector/event` (port 8088 is
Splunk's default). On Splunk Cloud the host is the stack's
`http-inputs` name, for example
`https://http-inputs-EXAMPLE.splunkcloud.com/services/collector/event`.
Either `/services/collector/event` or `/services/collector` is accepted.

This service posts JSON with `Authorization: Splunk <token>`. The body
is the HEC event envelope: `time` (the event's Unix seconds), `host`
(this process's host name), `source`, `sourcetype`, `index` when you set
one, and `event` (the canonical object). An empty index uses the
default index on the token. An empty sourcetype is `iya:audit`. An
empty source is `iya-sts`.

```json
{
  "time": 1793620800,
  "host": "sts-1",
  "source": "iya-sts",
  "sourcetype": "iya:audit",
  "index": "audit",
  "event": {
    "id": "test:splunk-cloud:1793620800000",
    "timestamp": "2026-11-02T12:00:00.000Z",
    "severity": "notice",
    "action": "audit.export.test",
    "message": "IYA-STS audit export test",
    "attributes": { "test": true }
  }
}
```

HTTP 2xx with HEC `code` 0, or with no `code`, accepts the event. Any
other HEC code pauses the destination and keeps the event.

**Indexer acknowledgement** matches Splunk's
[indexer acknowledgement](https://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHECIDXAck).
Enable it on the token in Splunk, and tick **Indexer acknowledgement**
here. This service then sends one event at a time, with
`X-Splunk-Request-Channel` set to a channel id it keeps for that
destination on this process, and polls the acknowledgement URL with
`{"acks":[<id>]}` before it sends the next. A URL ending in `/event`
is polled at the same path with `/ack` instead. A URL ending in
`/collector` gains `/ack`. The query string is not forwarded. Splunk
documents indexer acknowledgement for Splunk Enterprise. Splunk's page
says Splunk Cloud Platform supports it for Amazon Kinesis Data
Firehose. Leave the box unticked for a Splunk Cloud token that was
created without acknowledgement.

| Field | Value |
|---|---|
| Identifier | `splunk-cloud` |
| Name | `Splunk Cloud` |
| Type | `splunk` |
| URL | `https://splunk.example:8088/services/collector/event` |
| Token | the HEC token |
| Index | `audit` |
| Sourcetype | `iya:audit` |
| Source | `iya-sts` |
| Indexer acknowledgement | unticked, unless the token has it enabled |

```bash
api audit-export/add '{
  "id": "splunk-cloud",
  "name": "Splunk Cloud",
  "type": "splunk",
  "url": "https://splunk.example:8088/services/collector/event",
  "token": "replace-with-the-hec-token",
  "index": "audit",
  "sourcetype": "iya:audit",
  "source": "iya-sts",
  "ack": false
}'
```

The token is absent from the answer. A later update that omits `token`,
or sends it empty, keeps the sealed value.

## LogRhythm

LogRhythm is the syslog destination with `type` set to `logrhythm`.
The message, the transports and the fields are the
[Syslog](#syslog) section. LogRhythm's collector is the System Monitor
agent:
[Syslog Collection](https://docs.logrhythm.com/lrsiem/docs/syslog-collection)
and
[Configure a Device or Host for Syslog Collection](https://docs.logrhythm.com/lrsiem/docs/configure-a-device-or-host-for-syslog-collection).
Per-device syslog guides are listed under
[Syslog Log Sources](https://docs.logrhythm.com/devices/docs/syslog-log-sources).

On the LogRhythm side, open Deployment Manager, the System Monitors
tab, the agent's **Syslog and Flow Settings**, and enable the syslog
server. The agent listens on UDP and TCP port 514 unless
`SyslogUDPPort` or `SyslogTCPPort` says otherwise. Accept the new log
source and choose the log source type and processing policy that match
a generic syslog feed.

Send that agent **UDP**. LogRhythm's syslog server splits a TCP stream
on a newline (and, when `SyslogUseEnhancedTCPDelimiters` is on, on CR,
CRLF or NUL). This service's TCP frames are RFC 6587 octet counts, so
a newline splitter holds them. UDP carries one message per datagram,
which is the framing that page describes. Secure syslog to a Windows
System Monitor is documented at
[Configure Secure Syslog to System Monitor Agent](https://docs.logrhythm.com/OCbeats/docs/configure-secure-syslog-to-system-monitor-agent)
and listens on 6514. Use Transport `tls` only after confirming that
listener accepts octet-counted frames. Linux System Monitors, on
LogRhythm's page, collect ordinary syslog.

| Field | Value |
|---|---|
| Identifier | `logrhythm` |
| Name | `LogRhythm` |
| Type | `logrhythm` |
| Host | `logrhythm-agent.example` |
| Port | leave empty |
| Transport | `udp` |
| Facility | leave empty |
| Application name | `iya-sts` |

```bash
api audit-export/add '{
  "id": "logrhythm",
  "name": "LogRhythm",
  "type": "logrhythm",
  "host": "logrhythm-agent.example",
  "transport": "udp"
}'
```

The line on the agent is the RFC 5424 example in the syslog section.
Filter a test on the message `IYA-STS audit export test`.

## Try the destination

**Test** on the row, or:

```bash
api audit-export/test '{"id":"siem"}'
```

A failure is reported on the page and as `ok: false` from the API. The
recorded code for a failed test is `STS-AUDIT-0010`. Codes are written
on the audit row and in the log. The list is
[Audit export (`STS-AUDIT`)](error-codes.md#sts-audit).

The row then shows Healthy, Paused, Failing or Disabled, the queue
depth, how many events have been delivered, and the last success. The
figures are this process. Another process has its own. Disable keeps
the place it had reached. Enable continues from that place. Remove
deletes the destination.

```bash
api audit-export/disable '{"id":"siem"}'
api audit-export/enable '{"id":"siem"}'
api audit-export/remove '{"id":"siem"}'
```

Changing a destination, including a test, is itself an audit event and
is delivered to the destinations that are enabled.

## Related

* [Admin console → Audit export](admin-console.md#audit-export--adminaudit-export):
  the page, the counters, and how a failure is retried
* [Configuration → Audit export](configuration.md#audit-export):
  the fourteen settings
* [Management API](management-api.md): the token, and the operation list
* [Error codes](error-codes.md#sts-audit): `STS-AUDIT-0001` through
  `STS-AUDIT-0015`
* [Persistence](persistence.md): what the audit log keeps across a restart
* [The compose stack](docker-compose.md): the `sts-data` volume
