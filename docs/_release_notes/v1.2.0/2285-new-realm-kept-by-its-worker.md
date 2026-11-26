---
title: "A realm just created no longer vanishes from the worker that made it"
kind: fixed
issue: 2285
---

With request workers or cluster nodes, a realm created through `/admin-api`
or the console could disappear from the worker that created it a moment
later: that worker was reading the realm list for another realm's change
while its own write of the new realm landed, took the older answer for a
removal made elsewhere, removed the realm here and deleted its signing keys
and data keys from the store. Every request for the realm that worker then
answered was a 404, and the other processes could no longer open what was
sealed under the destroyed keys. A realm list or settings read that this
process's own write overtakes is now read again, and such a read never
removes a realm. A single process with no workers was not affected.
