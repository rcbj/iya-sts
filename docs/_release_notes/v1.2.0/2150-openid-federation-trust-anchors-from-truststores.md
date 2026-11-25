---
title: "OpenID Federation Trust Anchors from truststores"
kind: added
issue: 2150
---

A realm's OpenID Federation Trust Anchors may now come from key-set
truststores bound to `oidfed-anchor:<entity id>`, named by the new
`oidfed-anchor` use case (#2150). Its default, `registered-keys`, keeps
the anchors registered under OpenID Federation, so nothing changes until
an administrator assigns a key set. An anchor's key set is always pasted
keys, never a `jwks_uri`.
