---
title: "dependencies, limits and timeouts, and a rotation schedule"
kind: added
issue: 2205
---

A new page, [Dependencies, limits and timeouts](dependencies.md), lists every
system iya-sts connects to. For each one it gives the connection limit, what
happens at the limit, the timeouts, the retries, and what a caller sees when
the system is down (ASVS 5.0.0 13.1.2, 13.1.3). [Key
management](key-management.md#rotation-schedule) now has a rotation schedule
for every key and secret (ASVS 5.0.0 13.1.4). Both pages end with the gaps
they found.
