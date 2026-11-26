---
title: "pep-policies-changed reaches an embedded PEP when the service runs workers or nodes"
kind: fixed
issue: 2028
---

An embedded PEP's `pep-policies-changed` Shared Signals event was lost
whenever the policy change was made in a different request worker or cluster
node from the one that had answered the PEP's last policy pull: what each PEP
was last sent was remembered in that one process only. It is now kept in the
store, so the event is sent whichever worker or node makes the change. A
single-process service was not affected.
