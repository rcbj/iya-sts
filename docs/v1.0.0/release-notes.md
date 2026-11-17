---
title: Release notes
---

# Release notes

## 1.0.0

1.0.0 is the first release of iya-sts. Every build before it was a
pre-release.

### Not backwards compatible with earlier builds

**1.0.0 is not backwards compatible with the pre-release builds that came
before it.** Moving an existing deployment from a pre-release build to 1.0.0
works in many situations, but there are edge cases with no clean upgrade path.
Stored settings, directory entries, persisted data or client configurations
created by an earlier build may need to be recreated rather than carried
forward.

This is deliberate. The earlier builds were pre-release versions, and we are
not attempting to keep 1.0.0 compatible with them.

**If this causes you trouble, open an issue** on the GitHub repository:
[github.com/rcbj/iya-sts/issues](https://github.com/rcbj/iya-sts/issues). Say
which build you are moving from and what did not carry over.

### Backwards compatibility from here on

**Our goal is backwards compatibility going forward.** Releases after 1.0.0
are intended to upgrade cleanly from 1.0.0 and from each other. Where a later
release cannot, its notes on this page will say so and describe the upgrade
path.

### Version numbers

A build reports its version as `M.N.O.<build>`. `M.N.O` is the release, and
for 1.0.0 the release build is `1.0.0.0`. Other builds of the same code carry
the UTC time they were built as their build number. The running service shows
its version on the admin console and in its metadata.
