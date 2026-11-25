---
title: "A trust realm's own administrators arm the console's device requirement"
kind: fixed
issue: 2236
---

The console's compliant-device requirement
(`devices.requireCompliantDeviceForAdmin`) is armed in a realm the first
time one of that realm's console administrators signs in from their own
compliant registered device. In a trust realm other than the default one,
the check looked up the person on the default realm's console roster
instead of the realm's own. So a trust realm was never armed and kept
admitting administrators with no device, and a person with the same name
on the default realm's roster could have armed it. The check now reads the
roster of the realm being armed. The default realm behaves as before.
