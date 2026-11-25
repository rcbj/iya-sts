---
title: "a password an administrator types is temporary"
kind: behaviour-change
issue: 2160
---

In product mode, a password an administrator types for somebody must now
be changed at that person's next sign-in, as a generated one already had
to be (ASVS 5.0.0 6.4.6). The administrator knows it, so it should not stay
the person's password. This covers `POST /admin-api/users/set-password` with
`password` (the console's **Set password**), a person created with
`credential: "password"`, and an administrator's LDAP modify or add of
somebody else's `userPassword`. Each sets `pwdReset`. The sign-in screen
asks for a new password, and the doors that cannot ask (an LDAP bind, the
password grant, WS-Trust, Kerberos, SCIM Basic) refuse it until the person
has chosen one (`STS-AUTHN-0142`). Typed passwords are still accepted, and
the answer says the password is temporary. Three cases are not affected: a
service account, whose password is a program's; a person changing their own
password; and development mode.

**Reset password and download keytab** no longer cancels a change the
person already owes. In product mode it is refused for such a person
(`STS-ADMIN-0969`) and changes nothing, because the KDC would refuse the
keytab. It still does not make the person change the password it sets,
because that would end the keytab.

**Upgrading.** Nothing to run. Passwords set before the upgrade are not
changed. A script that creates people with a typed password and then signs
in as them (an LDAP bind, the password grant, WS-Trust or Kerberos) must
first sign in once at the sign-in screen and choose a new password. Or it
can use a service account, if the account is a program.
