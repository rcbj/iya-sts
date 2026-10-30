---
title: Fine-grained authorization
---

# Application-scoped fine-grained authorization

An application that declares its own `authorization_details` types (RFC 9396,
`oauthAuthorizationDetailsType` on the application) can also own an XACML
policy that decides each detail of those types. This page
describes what exists today: every application's own policy, the switch that
will make it enforced, and what happens to the policy when the application is
deleted. **Nothing is enforced yet.** The rules that map a detail's fields to
policy attributes, enforcement when a token is issued, and AuthZEN decisions
against an application's policy are added in later releases, and this page
grows with them.

## Features

* **One policy per application.** When an application is created on
  **Applications → New**, through the management API, or by importing an LDIF
  file, the service writes a default policy for it into the realm's
  `ou=policies`. The policy has one rule that permits every detail. It is a
  real Permit decision, not a fallback: delete the rule and the policy denies.
* **The application names its policy.** The application entry carries the
  policy's entry name in `appFgaPolicy`. The policy carries the application's
  identifier in `xacmlApplication`.
* **A switch, off by default.** `appFgaEnforced` is `TRUE` when the
  application's policy is enforced. It starts absent, which means off.
  Switching it on creates the policy first if the application has none. It is
  refused while the policy is disabled or does not parse, because an enforced
  application with such a policy would refuse every detail.
* **Deleting an application keeps its policy.** The policy is disabled and
  marked `xacmlOrphanedAt` with the time of the deletion. It stays in
  `ou=policies` for audit until an administrator deletes it on
  **XACML → Policies**. If an application with the same identifier is created
  again, it gets a new policy; it never inherits the orphan.
* **Never the root.** An application's policy is never the repository's root,
  is never reached by a `PolicyIdReference` from the root, and is never
  counted when the service picks "the only enabled policy" as the root. A
  realm with one ordinary policy keeps it as its root however many
  applications it has.
* **Never sent to a remote PEP.** `GET /xacml/pep/policies` withholds every
  application's policy and lists its name in `withheld`, as it does for this
  service's own two policies. The sync token ignores them, so creating an
  application does not make the remote PEPs pull again. Fine-grained
  authorization is decided only by this service.

## Which applications get a policy when

| How the application appeared | Its policy |
|---|---|
| Created on **Applications → New**, through `/admin-api`, or by an LDIF import | Created with it |
| Registered by a client (`POST /oauth2/register`), seen in development mode, or one of this service's own seeded applications | Created the first time fine-grained authorization is switched on for it |

Registrations and sightings do not write a policy, because they can be made
by callers who are not administrators. A policy for each of them would let
such a caller fill `ou=policies` up to `xacml.maxPolicies` and stop
administrators writing policies at all.

## The default policy

The `fga-default` template on **XACML → Policies** builds the same document,
so you can see it before any application has one. Its `PolicyId` is
`urn:sts:xacml:fga:` followed by the application's identifier, with every
character outside letters, digits and `-._~` percent-encoded. For the
application `https://rs.example/api` it is
`urn:sts:xacml:fga:https%3A%2F%2Frs.example%2Fapi`. The entry name is
`fga-`, a readable form of the identifier and twelve hexadecimal digits that
keep two similar identifiers apart, for example
`fga-https-rs-example-api-1715052a2eea`.

Edit it in the **Editor** like any other policy. Saving, enabling or
disabling it keeps its owner. **Make root** is not offered for it, and the
management API's `setXacmlRootPolicy` refuses it.

## Development and product mode

Nothing here differs between the two modes.

## Configuration

There is no setting of its own yet. Every application's policy counts toward
`xacml.maxPolicies` (default 200), the most entries `ou=policies` may hold.
An application created when the container is full is still created, without
a policy, and gets one when fine-grained authorization is switched on after
there is room. Raise `xacml.maxPolicies` in a realm with many applications.

## In the running service

* `GET /admin-api/xacml/policies` and `GET /xacml/policies` list every policy
  with `application` (its owner, or `null`) and `orphanedAt`.
* `GET /admin-api/ldap/applications` and `/admin/ldap/directory` show
  `appFgaPolicy` and `appFgaEnforced` on an application entry.
* `GET /xacml/pep/policies` names withheld policies in `withheld`.
* Failures are recorded under `STS-FGA-*` codes; see
  [error codes](error-codes.md).

## Related

* [XACML 3.0 and ALFA](xacml.md) — the engine and the repository.
* [Configuring XACML and ALFA](configure-xacml.md) — the templates and the
  policy operations.
* [AuthZEN](authzen.md) — access evaluations against the realm's root policy.
* [Remote PEP](remote-pep.md) — what a remote PEP pulls.
