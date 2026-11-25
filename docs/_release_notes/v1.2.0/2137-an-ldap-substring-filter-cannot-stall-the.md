---
title: "an LDAP substring filter cannot stall the directory"
kind: fixed
issue: 2137
---

An LDAP search's substring assertion (`(cn=*smith*)`) is matched in one
linear pass instead of by a regular expression, which a filter such as
`(cn=*a*a*a*...*b)` against a long value made backtrack for a very long time
(ASVS 5.0.0 1.3.12, #2137). Ordinary filters match exactly what they matched
before; a value holding a line break is now matched across it, as RFC 4517
asks. A search whose substring assertion holds more than 32 components is
refused with adminLimitExceeded (11), recorded as `STS-LDAP-0226`. See
[LDAP](ldap.md#how-a-filter-value-is-matched).
