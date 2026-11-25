---
title: "More administrator changes need a recent sign-in, and administrators have a write budget"
kind: security
issue: 2247
---

Two changes to `/admin-api` and the admin console, from the ASVS 5.0.0
Level 3 re-sweep.

**A recent sign-in for every change that decides who signs in (7.5.3).**
Since 1.2.0's #2161 a role grant, a trust realm, the PKI, the keys and any
setting needed a sign-in within `account.recentAuthMinutes` (15 minutes in
product). The same now holds for the access policies (XACML and ALFA, the
PEPs, AuthZEN), applications (secrets, certificates, redirect addresses,
client authentication, grant types, scopes, claims), federation
relationships, SAML service providers, authorization servers, OpenID
Federation, SPIFFE registrations, named policies, delegated permission
grants and global consent, owners, groups, devices, token lifetimes, the
claims and attributes tokens carry, outbound SCIM clients, risk datasets,
UMA, ACME, EST and SCEP, attribute sources, hardware tokens, mail-encryption
keys, cross-realm Kerberos trusts, claim providers, Shared Signals streams,
the listeners, the audit export and mail templates; on a person, an
activation link, MFA no longer required, a certificate added, the
service-account settings, who may act for them and a CIBA answer; and
restoring a revoked token. A stale sign-in is answered 401 with RFC 9470's
`insufficient_user_authentication`, and the console asks you to sign in
again and carries on. Programs using their own credentials are not asked.

**A write budget per administrator (2.4.2).** In product mode one person may
make 1200 changes through `/admin-api` (the console included) in ten minutes,
counted by their token's subject rather than by address
(`adminApi.writesPerSubject` in `adminApi.writeWindowS`). Past it a change is
refused with HTTP 429 and `Retry-After` (`STS-API-0148`); reading goes on.
Programs — `client_credentials` tokens and service accounts — are counted
only against `adminApi.programWritesPerSubject`, which is 0 (no limit) by
default in every mode, because provisioning bursts are legitimate. The person
budget is off (0) in development.

**Upgrading.** Nothing to run. An administrator working for more than 15
minutes since signing in is asked to sign in again at the next of these
changes, once per window. A script that drives `/admin-api` with a person's
token faster than two changes a second should use a program's credentials,
or have `adminApi.writesPerSubject` raised.
