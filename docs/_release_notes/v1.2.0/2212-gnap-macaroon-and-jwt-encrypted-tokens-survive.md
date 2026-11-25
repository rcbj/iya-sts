---
title: "GNAP macaroon and `jwt-encrypted` tokens survive a signing rotation"
kind: fixed
issue: 2212
---

A signing rotation no longer stops GNAP macaroons and `jwt-encrypted`
tokens issued before it from verifying (#2212). They are verified under
every replaced realm secret the rotation keeps, and it keeps one for at
least the longest GNAP access-token lifetime. A resource server's
`gnapMacaroonKey` is rewritten when the first macaroon for it is minted
after a rotation. Tokens issued before the upgrade keep verifying.
Nothing needs an upgrade script.
