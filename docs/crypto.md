---
title: Signature algorithms
nav_order: 7
---

# Signature algorithms

Every realm decides which signature algorithms it signs with and accepts, surface by surface. **Everything here is optional.** With nothing configured, a realm does what it always did, and the certified OpenID Connect output does not change.

To see what a realm does now, open **Cryptography → Algorithms** at `/admin/crypto-metadata`, or read `signaturePolicy` in `GET /admin-api/crypto`. Each row says whether the realm signs with an algorithm and accepts it, and why not. `GET /crypto/metadata` publishes the same answer, with no sign-in.

## The settings

Each is per realm and takes effect at once. Set them on `/admin/config` or with `POST /admin-api/config/set`. Each list holds algorithm names, as the Algorithms tab shows them.

| Surface | What it covers | Signs with, in order | Accepts |
|---|---|---|---|
| JOSE | Tokens, ID Tokens, client assertions, DPoP, request objects, wallet proofs, federation statements | `keys.signingAlgorithms` | `keys.acceptedSigningAlgorithms` |
| HTTP Message Signatures | RFC 9421, from OAuth and GNAP clients | | `oauth2.httpSignatureAcceptedAlgorithms` |
| COSE | Status-list CWTs, `vc+cose` credentials, mdoc | `cose.algorithms` | `cose.acceptedAlgorithms` |
| XML | SAML, WS-Security | `saml.signatureAlgorithms` | `saml.acceptedSignatureAlgorithms`, `saml.acceptedDigestAlgorithms` |
| Data Integrity | VC API, status lists, zcap, bbs-2023 | `vc.cryptosuites` | `vc.acceptedCryptosuites` |
| X.509 | Certificates in a path this realm validates | | `pki.acceptedSignatureAlgorithms` |

Passkeys have their own settings, `webauthn.algorithms`, `webauthn.pqcOnly` and `webauthn.insecureAlgorithms`, and none of the settings above change them.

[Every setting](configuration.md) has its full description.

## How a list behaves

**Empty means today.** An empty list leaves every algorithm the surface otherwise has, in the order it uses now, and each use case keeps its own default.

**A configured signing list is a preference.** Its first usable algorithm becomes the default, and discovery publishes the list in that order.

**A specification's default still wins.** A client that registered no ID Token algorithm gets RS256, as OpenID Connect requires, whatever the list puts first. FAPI 1.0 Advanced keeps PS256 or ES256.

**A signature outside an accept list is refused before any key is used.** A signature the realm is asked to make outside its signing list is refused too, unless a setting chose the algorithm. Then the realm signs with its default and says so once in its log (`STS-KEYS-0178`).

**Some writes are refused**, so a realm cannot lock itself out:

- A list may not name an algorithm twice (`STS-KEYS-0189`).
- An accept list must include what the realm signs with, or it would refuse its own tokens (`STS-KEYS-0190`). Where no signing list is set, that means RS256 on JOSE and XML.
- A setting that names one algorithm, such as `saml.signatureAlgorithm`, must name one in its list (`STS-KEYS-0192`). To change both, send them together with `POST /admin-api/config/set-many`.

**The family switches still apply.** Listing an algorithm does not turn its family on. `keys.postQuantumSigning` and `keys.eddsaSigning` cover JOSE, and `keys.postQuantumSigning` also covers HTTP signatures that use a JWS name. Neither changes passkeys, XML, TLS or certificates.

## Signing post-quantum only

`keys.pqcOnly` narrows the JOSE, COSE, XML and Data Integrity signing lists to their post-quantum algorithms, or to all of them where a list names none.

- **RS256 stays for ID Tokens**, because OpenID Connect Discovery requires it. It is used only for a client that registered it or registered no algorithm.
- **What the realm accepts does not change**, so a classical client assertion still verifies.
- **Certificate algorithms and DKIM do not change.** XML signatures need a post-quantum key, which only a realm in the `hybrid-groups` signer model holds.

> **Warning:** a client or relying party that cannot verify ML-DSA cannot read what the realm signs. Most can't yet, so try it in a test realm first.

`keys.pqcOnly` cannot be on while `keys.postQuantumSigning` is off.

## What is published

Discovery, the authorization server document, the JWK Set, OpenID4VCI metadata and the Entity Configuration all follow these settings. A signing list narrows what the realm says it signs with and which keys it publishes. An accept list narrows what it says it accepts.

**SAML metadata** carries `<alg:SigningMethod>` and `<alg:DigestMethod>` from the [SAML V2.0 Metadata Profile for Algorithm Support](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.html). They say what this realm can verify, strongest first, and never a weak method. A partner that does not know the profile ignores them. Turn them off with `saml2.publishAlgorithmSupport`.

## Related

- [Certificate authority](pki.md) for `pki.signatureAlgorithm`, which chooses what the CA issues with
- [PKI use cases](pki-use-cases.md) for how a certificate is validated
- [Error codes](error-codes.md) for what each refusal means
