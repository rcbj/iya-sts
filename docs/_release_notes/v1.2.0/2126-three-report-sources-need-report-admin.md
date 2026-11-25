---
title: "three report sources need `REPORT_ADMIN`"
kind: behaviour-change
issue: 2126
---

The report sources `auditEvents`, `authActivity` and `credentialHolders`
hold who did what, from where, and who holds which credential, which the
console keeps behind Admin Read. A report over one of them now needs
`REPORT_ADMIN` (ASVS 5.0.0 8.2.3, #2126). A caller holding only
`REPORT_USE` is refused (`forbidden`, `STS-REPORT-0061`) a query, a job, a
saved definition, a run and a download over them; every other source is
unchanged. The catalog marks the three `adminOnly`, the page offers them
only to a caller who may use them, and the access-control policy decides
them too, with `reportAdminSources` for sources a realm adds.

**Upgrading.** Nothing is removed. A definition a report user saved over one
of these sources stays visible to its owner, who may change its source or
delete it; its runs and its schedule are refused with `STS-REPORT-0061`
(each skipped occurrence noted on the definition) until its owner holds
`REPORT_ADMIN`. A realm that overrides `access-control` keeps its override:
the catalog's check refuses these sources without it, and rebuilding the
override from the template adds the rule to the policy. See
[Reports](reporting.md#who-can-open-it) and
[Field access](field-access.md#reports).
