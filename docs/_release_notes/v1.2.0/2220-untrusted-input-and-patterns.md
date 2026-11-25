---
title: "LDAP messages have a maximum size, and regular expressions are bounded"
kind: security
issue: 2220
---
**An LDAP message is held to a maximum size before any of it is read.** The
directory reads each message's BER header on 389 and 636 before the LDAP
library buffers anything, and closes a connection whose next message declares
more than `ldap.maxMessageBytesBeforeBind` (128 KiB) before a bind, or
`ldap.maxMessageBytes` (5 MiB) after one, or uses BER's indefinite length
(`STS-LDAP-0227`). Search results are not counted.

**A regular expression somebody else wrote is bounded.** The check federation
already applied to `fedSubjectPattern` (no backreference, no quantifier on a
group that is itself quantified or an alternation, a length limit) now
applies to:

* XACML's six `*-regexp-match` functions: a policy whose literal pattern fails
  it is refused when saved (`STS-XACML-0338`), and at evaluation such a
  pattern, or a value longer than 4096 characters, is Indeterminate
  (`STS-XACML-0339`). The remote PEP's engine decides the same way.
* `spiffe.httpChallengeAllowedDnsPatterns` and
  `spiffe.dockerSigstoreAllowedIdentities`, refused at a save
  (`STS-CORE-0182`) and warned about at startup when set in the environment or
  an appconfig file (`STS-CORE-0183`).
* An RFC 9396 access type's definition: its `schema` is held to the keyword
  subset a `limits` schema uses, and every `pattern` to the same bound, when it
  is written (`STS-REG-0374`).

**What is stored is still read.** A policy, a setting or an access type
stored before 1.2.0 still loads. An access type is still used as written,
marked on its application's Access types tab and listed on `/admin/mode`'s
new `access-type-schemas` row; a setting is refused only at its next save. A
policy is the one behaviour change: it still loads and decides, its unsafe
pattern is listed among its problems on the Policies page, and the
regexp-match holding that pattern is Indeterminate rather than evaluated.
