---
title: "key sets as truststores"
kind: added
issue: 2149
---

A truststore may now hold a key set bound to one party: a client, a
federation relationship or a claims provider, as pasted public keys or a
`jwks_uri` (#2149). Four new use cases, `client-jws`, `federation-jwt`,
`ssf-set` and `claims-provider-jwt`, decide which keys verify a JSON Web
Token or signature from each kind of party. Each defaults to
`registered-keys`, each party's own registration, so nothing changes until
an administrator assigns a key set. A key set is never shared between
parties. `POST /admin-api/truststores/create` takes `kind`, `party`,
`jwks` and `jwksUri`, and the new `POST /admin-api/truststores/set-keys`
replaces a key set's keys.
