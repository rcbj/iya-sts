---
title: "Making a person a service account clears a password change they owed"
kind: changed
issue: 2236
---
`POST /admin-api/users/set-service-account` (and the console's
**Service account** tab) now clears a pending password change (`pwdReset`)
on the account it makes a service account. In product mode a password an
administrator types for an ordinary person is temporary (#2160), and a
service account's password belongs to a program, which has no sign-in screen
to choose a new one at: until now such an account's right password was
refused at every door it uses (`STS-AUTHN-0142`). The audit row of the act
records `passwordResetCleared` when it clears one.
