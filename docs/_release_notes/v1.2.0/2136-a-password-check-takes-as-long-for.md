---
title: "a password check takes as long for an account that does not exist"
kind: fixed
issue: 2136
---

In product mode, a password presented for a name with no stored password, for
an account holding a stored value this service cannot read, for a disabled
account, or for a service account at a door its policy closes was refused at
once, while a wrong password for a real person took one password-hash
computation. The response time said which accounts exist (ASVS 5.0.0 6.3.8).
Those refusals now verify the presented password against a hash nobody holds,
made once per process at the password policy's current parameters, and discard
the result, so every refusal costs the same. What is refused, and the error
code recorded for it, are unchanged. This applies at every door that checks a
person's password: the sign-in screen, the password grant, an LDAP bind, a
WS-Trust UsernameToken, SCIM, SSF and EST HTTP Basic.
