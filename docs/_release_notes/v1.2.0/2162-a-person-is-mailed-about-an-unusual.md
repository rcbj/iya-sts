---
title: "a person is mailed about an unusual sign-in"
kind: added
issue: 2162
---

A sign-in that succeeds looking unusual is now mailed to the person (ASVS 5.0.0
6.3.5). Unusual means a new device or browser, a new country, an anonymising
network such as Tor, refused passwords just before, or a risk level at or
above `mail.signInAlertLevel` (MEDIUM). The message gives the time, roughly
where, the browser or device, the method, and a link to **Recent sign-ins**,
where saying it was not them signs every session out. A run of refused
passwords on the account is mailed too, at the sign-in limit's own count,
whether or not anybody signed in. Each kind is mailed at most once in
`mail.signInAlertWindowS` (a day).

**Upgrading.** Nothing to run. The alerts are on wherever a mail transport is
configured. Set `mail.signInAlerts` to `false` to keep the old behaviour. See
[Risk scoring](risk-scoring.md#the-person-is-told-of-an-unusual-sign-in).
