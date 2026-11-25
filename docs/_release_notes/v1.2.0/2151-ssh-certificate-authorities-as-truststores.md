---
title: "SSH certificate authorities as truststores"
kind: added
issue: 2151
---

A truststore may now hold SSH certificate authority public keys (#2151).
The new use case `spiffe-sshpop`, which the SPIFFE sshpop node attestor
checks host certificates against, defaults to the setting
`spiffe.sshpopCertAuthorities`, so nothing changes until an administrator
assigns a truststore. `POST /admin-api/truststores/create` and `set-keys`
take `sshKeys`.
