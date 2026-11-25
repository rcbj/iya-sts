---
title: "the daily dependency review checks security advisories only"
kind: changed
issue: 2219
---
The daily dependency workflow (`.github/workflows/dependency-windows.yml`)
now checks only the security advisory windows of
[`SECURITY.md`](https://github.com/rcbj/iya-sts/blob/main/SECURITY.md):
7 days for critical, 30 for high and 90 for moderate, over both lockfiles
(the root's and `sdk/`'s) and the image. The 90-day update review runs only
when someone asks for it, by dispatching the workflow with `updates` or by
running `node tests/tools/dependency-windows.js --updates`. It reads the
root lockfile only. The optional SDKs pinned in `sdk/` are still held to
the advisory windows, but an SDK that falls behind with no advisory
against it no longer fails the day. See
[Risky third-party components](risky-components.md#how-the-list-is-kept).
