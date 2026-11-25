---
title: "Post-quantum: ML-KEM S/MIME certificates issued, LDAPS serves ML-DSA, key exchange counted, SLH-DSA in the HSM and in OpenPGP"
kind: added
issue: 2220
---
Five post-quantum gaps of the migration plan are closed (#2220, section E).
**ML-KEM S/MIME certificates are issued**, not only uploaded: on
`/portal/openpgp` (the account API's `smime-kem-challenge` and
`smime-kem-issue`) a person sends an ML-KEM public key, the service
encapsulates to it, and on the secret coming back (the
challenge-response proof of possession of RFC 9810 section 5.2.8.3.3,
`KEMKPOPChallengeResp` in section 5.2.8.4) the realm's EST Issuing CA issues an
`email`-profile certificate with `keyEncipherment` alone (RFC 9935), which
becomes their S/MIME certificate (`STS-OPENPGP-0035` to `-0039`). **LDAPS on
636 serves every listener certificate**, so `tls.certificateAlgorithms`
`rsa,ml-dsa-65` offers RSA and ML-DSA side by side there as on the main
port. **The key exchange each TLS handshake negotiated is counted** per
listener and group, read from the session OpenSSL holds:
`/admin/crypto-metadata`'s Post-quantum tab and the new
`GET /admin-api/tls/key-exchange` draw the counts, and `GET
/admin-api/tls-connection` gains `connection.keyExchange`. **With keys in an
HSM**, the realm's published ML-DSA and SLH-DSA keys are made in the module
when it offers PKCS#11 3.2's `CKM_ML_DSA` or `CKM_SLH_DSA` (and in software
otherwise; the composites always), and an ML-DSA key in the module now signs
a JWS. **OpenPGP accepts SLH-DSA** (RFC 9980 section 7: SLH-DSA-SHAKE-128s,
-128f and -256s on v6 keys), added to the default `openpgp.algorithms`; a
realm that set its own list keeps it. Every remaining *Future* step on the
post-quantum migration page names its trigger: the specification or library
release it waits on, and what iya-sts does when it arrives.
