# Security policy

## Reporting a vulnerability

Report a vulnerability privately to the owner of this repository. Do not open a
public issue for one.

## How quickly a vulnerable dependency is remediated

This is the patching policy ASVS 5.0.0 requirement 15.1.1 asks for. It covers
every third-party component this service ships, directly or transitively.

| Severity of the advisory | Remediated within |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Moderate | 90 days |

* The clock starts when the advisory is **published**, not when someone next
  looks.
* Every direct dependency is reviewed for an update at least every **90 days**,
  whether or not there is an advisory against it. A package another one pulls in
  moves with its parent, and is held to the advisory windows above.
* Remediated means upgraded, removed, or shown not to be reachable from this
  service, with the reasoning recorded on a ticket.
* A protocol exception, or an operator's choice of a private certificate
  authority, is not a dependency exception.

`tests/tools/dependency-windows.js` runs on every CI run and fails the build
when an advisory is past its window. A daily workflow runs it too, against the
published image as well as the lockfile, so that the operating system's packages,
the Node runtime and everything else shipped are covered and an advisory cannot
pass its window between merges. A finding with no fixed version yet is listed
and cannot fail the check.

The same daily run fails on a direct dependency whose first newer release was
published more than 90 days ago, unless `.github/dependency-reviews.json` records
a review of that pinned version within the last 90 days and the reason it stays. Builds install exactly what the lockfiles
name (`npm ci`), so an image cannot pick up a version nobody reviewed.
