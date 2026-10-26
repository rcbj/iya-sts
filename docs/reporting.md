---
title: Reports
nav_order: 11
---

# Reports

Reports is an application at `/report`. It reads this realm's catalog —
people, groups, applications, federation relationships, authentication
mechanisms, the audit ring still held here, the live service counters, and
the report jobs themselves — and returns JSON, CSV or PDF.

A query is a JSON document. It names one source, the fields to return, a
filter, an order and a limit. This service does not accept a SQL statement,
and it does not forward one to PostgreSQL or to an attribute source.

## Who can open it

Open `/report` and sign in. The browser uses the public client `sts-report`.

- **`report:admin`** is issued only to this realm's administrators (Admin
  Read or Admin Write). An administrator sees every definition and every
  job in the realm.
- **`report:use`** is issued to those administrators, and to members of the
  directory group named by `report.usersGroup`. When that setting is empty,
  only the administrators are issued it.

You see the definitions you own. Sharing a definition with a directory
group lets members of that group run it and download the result. Sharing
does not let them edit or delete it. A definition or a job you may not see
is answered as not found.

When several accounts in one browser are enabled, this application uses the
same account switcher as the portal.

## Running a query

Use **Query** on the page, or `POST /report-api/queries` with the document.
The [endpoint list](endpoints.md) names every path. After you are signed
in, `GET /report-api/openapi.json` is the API's own description.

A small query on a source the catalog marks as bounded is answered in the
same call. A larger one is stored as a job. **Jobs** lists it, and the
bytes stay available until `report.artifactRetentionS` (a day, unless you
change it). The job's row stays for `report.jobRetentionS` (a week). A job
that is still running is kept.

PDF has its own row and page caps. Past either one, the call asks for CSV.
A result over the byte cap or the time cap is refused whole. The service
does not send a partial body.

The caps, and who may be issued `report:use`, are
[Reporting](configuration.md#reporting). Server configuration
(`/admin/config`) draws the same group.

## Saving and scheduling

**Definitions** stores the document under a name you choose. A schedule is
a UTC cron expression on that definition. When it comes due, the service
runs it as the owner, and only while that owner may still run it. Leave
the schedule empty when the definition is only for running by hand.

A finished job can mail the owner (`report-ready`). If that notice cannot
be sent, the job still stands as finished.

## A dedicated reporting node

With the cluster off, the front process drains the queue, drops expired
results and enqueues schedules that are due. Nothing else has to be set.

In a cluster, set `STS_REPORT_NODE` to the string `true` on the service
that should hold the lease `ops.reporting`. Leave it unset on the default
`sts` service. While a reporting node is live, the other fronts leave the
queue to it. The process that holds the lease drains, retains and
schedules on its own. The [compose stack](docker-compose.md) says how to
pass the variable. It is not in the file as shipped.

A running job's fence is held in the process that claimed it. If that
process is gone, the job is failed. Another node does not finish it.
