---
title: "A console token is no longer revoked by the Kerberos keys of the password just chosen"
kind: fixed
issue: 2236
---
In product mode, a person who chose their password at the sign-in screen
(or on the portal) could find the console's or the portal's token refused
moments later (`STS-API-0122`, and its refresh `STS-OAUTH-0214`). The
Kerberos keys derived from the new password sent their own CAEP
`credential-change`, as `system` and dated after the sign-in, and the
console, which acts on every credential change that is not the person's
own, revoked the token it had just been issued. The keys' event now carries
the password act's `initiating_entity` and `event_timestamp`, so a change the
person made themselves ends nothing. Seen intermittently in the single-node,
mariadb and cluster test modes (#2105).
