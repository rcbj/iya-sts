---
title: "A trust realm's own administrators are treated as administrators"
kind: fixed
issue: 2236
---

Three checks that treat console administrators differently looked the
person up on the default realm's console roster even when they were
signing in to another trust realm. Each now reads the roster of the realm
the person is signing in to. The default realm behaves as before.

- **The console's compliant-device requirement**
  (`devices.requireCompliantDeviceForAdmin`) is armed the first time one
  of a realm's console administrators signs in from their own compliant
  registered device. A trust realm was never armed, so it kept admitting
  administrators with no device, and a person with the same name on the
  default realm's roster could have armed it.
- **The second factor for administrators** (the authentication policy's
  `requireSecondFactorForAdministrators`) was never offered to, or required
  of, a trust realm's own administrators. It was offered to a person with
  the same name as a default-realm administrator.
- **A remembered browser** never skips the second factor for an
  administrator. In a trust realm it could skip it for that realm's own
  administrators, and it was refused to a person with the same name as a
  default-realm administrator.
