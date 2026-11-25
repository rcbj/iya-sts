---
title: "The supply-chain gaps on the risky components page are closed"
kind: security
issue: 2220
---
The service image no longer carries xml-crypto, which only the tests use, and
its npm install runs no package's install script. Every package the images
install that has had no release for three years, and the `node-ldapjs` fork,
is listed on the Risky third-party components page with its
last release, why it is kept and what would replace it, and a test fails when
one is missing. The remote PEP's `Cargo.lock` is audited against the RustSec
advisories every day, its image carries a CycloneDX SBOM that names the
OpenSSL built into it, and it moves to `url` 2.5.9 for RUSTSEC-2026-0592. The
ICAP adapter's c-icap packages are pinned. The daily image scan now covers the
remote PEP, the ICAP adapter and ClamAV as well as the service.
