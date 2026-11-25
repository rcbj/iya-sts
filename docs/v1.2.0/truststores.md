---
title: Truststores
nav_order: 7
---

# Truststores

A **truststore** is a named set of certificate authorities, of the public
keys that may verify one party's signatures (a **key set**), of SSH
certificate authority keys, or of Sigstore trust material. Every
place this service checks a signature, a certificate chain or the
certificate of a server it connects to belongs to a **use case**. Each use case trusts the
truststores it is **assigned**, in order, or its default list until it is
assigned one. Protocols → PKI trust (`/admin/pki/trust`) shows and changes
both, and `/admin-api/truststores` is the same controls for a machine.

## Nothing changes until you assign something

Each use case's default list names exactly what it trusted before truststores
existed. The older settings and stores are still read where they are kept,
and the pages that edit them still work:

* `signers` is the [signer truststore](signer-truststore.md) of the realm.
* `client-certificates` is the
  [client-certificate truststore](tls.md#the-client-truststore).
* `setting:<key>` is what one older setting names, for example
  `setting:federation.outboundCaFile`. Change it by changing the setting.
* `registered-keys` is each party's own registered keys: a client's `jwks`
  or `jwks_uri`, a federation relationship's `fedJwks` or `fedJwksUri`, a
  claims provider's key set, and the Trust Anchors registered under OpenID
  Federation. Change them where each party is registered.

An upgrade therefore trusts exactly what it trusted before, and needs no
migration step.

## Kinds of truststore

| Kind | Names | What it holds | Changed |
|---|---|---|---|
| Built-in | `system` | Node's default store: the bundled Mozilla roots and `NODE_EXTRA_CA_CERTS`. The **System truststore** tab lists every certificate | by rebuilding the image or setting `NODE_EXTRA_CA_CERTS` |
| Built-in | `service-root` | This service's own Root CA | never by hand |
| Built-in | `fido-mds`, `fido-mds-signer` | The attestation roots the FIDO Metadata Service lists for an authenticator; the anchor of the Metadata Service BLOB | by the Metadata Service |
| Built-in | `yubico-piv`, `device-vendors`, `cloud-attestation`, `k8s-in-cluster`, `mdoc-own-iaca` | Yubico's PIV roots, Google's and Apple's device attestation roots, Azure's IMDS roots, the Kubernetes service account CA, this realm's mdoc Issuing Authority CA | shipped with the image |
| View | `signers`, `client-certificates` | The two older stores | on their own pages |
| Setting | `setting:<key>` | What an older anchor or CA setting names | by the setting |
| SPIFFE bundle | `spiffe:<trust domain>` | A trust domain's whole bundle: its X.509 authorities **and** its JWT-SVID keys | through SPIFFE federation |
| View | `registered-keys` | Each party's own registered keys (see [Key sets](#key-sets)) | where each party is registered |
| Named | any name you choose | Certificate authorities you add | on the **Truststores** tab |
| Named key set | any name you choose | Public keys bound to one party, pasted or fetched from a `jwks_uri` | on the **Truststores** tab |
| Named SSH CA | any name you choose | SSH certificate authority public keys (see [SSH certificate authorities](#ssh-certificate-authorities)) | on the **Truststores** tab |
| Named document | any name you choose | cosign public keys, a Sigstore trusted root or a TUF root (see [Sigstore trust material](#sigstore-trust-material)) | on the **Truststores** tab |

A named truststore holds at most 32 anchors (self-signed CAs) and 64
intermediates, and a realm holds at most 64 named truststores. A leaf
certificate is never admitted; pin a leaf on the entry that uses it.

## What every realm starts with

A new realm, and the default realm of a new installation, holds no named
truststores: every truststore it can name at first is built in, a view of
an older store, or a view of a setting. Each one is read-only on the
**Truststores** tab. The names are the same in every realm; what a
realm-scoped one holds can differ, because it reads that realm's own store
or setting. All 50 are listed below.

**Built in** (service-wide: the same contents in every realm):

| Truststore | What it holds |
|---|---|
| `system` | Node's default store: the Mozilla roots bundled with the image's Node.js (about 120) and anything in `NODE_EXTRA_CA_CERTS` |
| `service-root` | This service's own Root CA |
| `fido-mds` | The attestation roots the FIDO Metadata Service lists for the authenticator being checked; empty until one is checked |
| `fido-mds-signer` | GlobalSign Root CA - R3, the anchor of the FIDO Metadata Service BLOB |
| `yubico-piv` | Yubico's PIV attestation roots and intermediates (2 and 5), shipped and pinned |
| `device-vendors` | Google's Android Key Attestation and Apple's App Attest roots (3), shipped and pinned |
| `cloud-attestation` | The Azure roots SPIRE embeds for its IMDS attestor (3, and 1 intermediate), shipped and pinned |
| `k8s-in-cluster` | The Kubernetes service account CA, only when the service runs in a cluster; empty otherwise |
| `mdoc-own-iaca` | This realm's own mdoc Issuing Authority CA, once one exists |

**Views of the older stores:**

| Truststore | Scope | What it holds |
|---|---|---|
| `signers` | each realm | The realm's [signer truststore](signer-truststore.md); empty until you add to it |
| `client-certificates` | service-wide | The [client-certificate truststore](tls.md#the-client-truststore) |
| `registered-keys` | each realm | Each party's own registered keys (see [Key sets](#key-sets)) |

**Views of settings**, one per setting that used to name trusted
certificates, keys or files, each read in the realm. Each is empty while
its setting is empty, which is the default for all of them except
`tls.trustIssuedClientCertificates`, which holds `service-root` while that
setting is on:

| Area | Truststores |
|---|---|
| TLS client certificates | `setting:tls.trustIssuedClientCertificates` |
| SAML | `setting:saml2.metadataTrustAnchors` |
| OAuth client attestation | `setting:oauth2.clientAttestationTrustAnchors` |
| WebAuthn and passkeys | `setting:webauthn.attestationTrustAnchors`, `setting:webauthn.attestationEvidenceTsaTrustAnchors`, `setting:risk.mdsTrustAnchors` |
| Devices | `setting:devices.androidAttestationTrustAnchors`, `setting:devices.appleAppAttestTrustAnchors`, `setting:devices.tpmTrustAnchors` |
| PIV | `setting:piv.attestationAnchors`, `setting:piv.externalIssuers` |
| Verifiable credentials | `setting:oid4vp.trustedIssuerCertificates`, `setting:oid4vp.mdocTrustAnchors`, `setting:oid4vci.keyAttestationTrustedCertificates` |
| SPIFFE attestation | `setting:spiffe.x509popCaBundle`, `setting:spiffe.tpmDevidCaBundle`, `setting:spiffe.tpmEndorsementCaBundle`, `setting:spiffe.azureImdsTrustBundle`, `setting:spiffe.k8sKubeletCaFile`, `setting:spiffe.sshpopCertAuthorities` (SSH CA keys) |
| SPIFFE Sigstore | `setting:spiffe.dockerSigstorePublicKeyFiles` (cosign keys), `setting:spiffe.dockerSigstoreTrustedRootFile` (a trusted root), `setting:spiffe.dockerSigstoreTufRootFile` (a TUF root) |
| Revocation | `setting:pki.revocationCrlIssuersFile`, `setting:pki.revocationHttpsCaFile`, `setting:pki.revocationLdapCaFile` |
| Outbound connections | `setting:federation.outboundCaFile`, `setting:ssf.pushCaFile`, `setting:gnap.pushCaFile`, `setting:xacml.pepNotifyCaFile`, `setting:auditExport.caFile`, `setting:authzen.externalPdpCaFile`, `setting:scimClient.caFile`, `setting:mail.smtpCaFile`, `setting:malwareScan.caFile` |
| Infrastructure (not assignable) | `setting:persistence.databaseTlsCaFile`, `setting:keys.vaultCaCert` |

**SPIFFE:** `spiffe:<trust domain>` for the realm's own trust domain, and
one more for each trust domain the realm federates with. In the default
realm the trust domain is `spiffe.trustDomain` (`example.org` until you set
it); in any other realm it is the realm's DNS domain.

**In a realm other than the default**, the default realm's named
truststores also appear, read-only: they are service-wide.

Which of these each use case trusts before you assign anything is its
**Default** in [The use cases](#the-use-cases).

## Key sets

A **key-set truststore** holds the public keys that may verify a JSON Web
Token or signature from **one party**: a client (`client:<client_id>`), a
federation relationship (`federation:<relationship id>`, which also covers
an SSF transmitter partner) or a claims provider
(`claims-provider:<provider id>`). The party is fixed when the key set is
created. A JSON Web Key does not say who owns it, so a key set is never a
pool: when a token arrives, only a key set bound to the party that sent it
is consulted, whatever else the use case names.

A key set holds either pasted keys, a JSON Web Key Set of **public** keys
only (at most 32), or a `jwks_uri`, which is fetched under the same outbound
policy and cache as a client's registered `jwks_uri`. A private or symmetric
key is refused (`STS-PKI-0308`).

Five use cases verify with key sets: `client-jws`, `federation-jwt`,
`ssf-set`, `claims-provider-jwt` and `oidfed-anchor`. Each defaults to the built-in view
**`registered-keys`**: each party's own registered keys, read exactly as
before. Assign a use case `registered-keys` and a key set to add keys for
one party, for example to pin a partner's current keys while its
`jwks_uri` is unreliable. Leave `registered-keys` out and every party of
that use case is verified only against key sets bound to it. A key set and
a certificate truststore are never interchangeable (`STS-PKI-0309`).

**OpenID Federation Trust Anchors** (#2150) are key sets too, bound to
`oidfed-anchor:<entity id>`. Naming one in the `oidfed-anchor` use case
makes that entity a Trust Anchor of the realm with those keys, or adds the
keys to an anchor already registered under OpenID Federation; leaving
`registered-keys` out makes the key sets the realm's only anchors. An
anchor's keys are trusted out of band, so its key set is always pasted
keys, never a `jwks_uri`. Trust Mark issuers are not configured here: a
Trust Mark is verified with its issuer's keys as established through the
issuer's own chain to an anchor.

## SSH certificate authorities

An **SSH CA truststore** (#2151) holds SSH certificate authority public
keys in `authorized_keys` form, one per line, at most 32. An SSH CA vouches
for many hosts and its certificate names the principals it is for, so an
SSH CA truststore is shared like a certificate truststore, not bound to one
party. The use case `spiffe-sshpop` is what the SPIFFE sshpop node attestor
checks a host certificate against; it defaults to the setting
`spiffe.sshpopCertAuthorities`, so nothing changes until you assign a
truststore. SSH CA keys and certificates never stand in for each other
(`STS-PKI-0309`).

## Sigstore trust material

The SPIFFE Docker workload attestor's Sigstore check (#2152) trusts three
kinds of document, each a truststore kind of its own that holds one
document as text, at most 256 KiB:

* **`cosign`**: 1 to 32 PEM public keys, for keyed signatures. Use case
  `sigstore-cosign-key`, default `setting:spiffe.dockerSigstorePublicKeyFiles`.
* **`sigstore-root`**: a Sigstore `trusted_root.json` (Fulcio, Rekor and CT
  log keys), used while TUF is off. Several are combined into one, as the
  format already lists several authorities and logs. Use case
  `sigstore-trusted-root`, default
  `setting:spiffe.dockerSigstoreTrustedRootFile`.
* **`tuf-root`**: the TUF `root.json` the trusted root is delivered under.
  TUF starts from exactly one root, so the first one the use case names
  counts. TUF is on while `sigstore-tuf-root` names a root and
  `spiffe.dockerSigstoreTufUrl` is set. Use case `sigstore-tuf-root`,
  default `setting:spiffe.dockerSigstoreTufRootFile`.

Each default reads the setting's files as before, under
`security.fileRoots`, so nothing changes until you assign a truststore.

## Scope: service-wide and per realm

Truststores you create in the **default realm** are service-wide. A
**service** use case is decided with no realm in hand: a TLS handshake, a
connection this service makes, the database. It may name only service-wide
truststores, built-ins and views (`STS-PKI-0302`). A **realm** use case may
name its own realm's truststores and the service-wide ones.

**A realm may override an outbound service-wide use case** (#2148): the
connections this service makes from that realm, to a partner, a mail relay,
a SCIM target and the like, can trust a list of that realm's own, naming its
own truststores and the service-wide ones. A realm with no override trusts
the default realm's list, and clearing the override returns it there. The
override changes nothing for the default realm or any other realm. A
handshake (`tls-client`) and the fixed infrastructure use cases are still
assigned from the default realm only (`STS-PKI-0302`), because nothing
there says which realm is asking.

A SPIFFE use case names only SPIFFE bundle truststores, and nothing else
names one (`STS-PKI-0304`). Assigning `spiffe-svid` or `spiffe-jwt-svid` a
list narrows which federated trust domains are accepted; `spiffe:*`, the
default, accepts every bundle the realm holds.

## In every mode

What a use case is assigned is what it trusts, in development and in
product. [Paranoid PKI mode](pki.md#paranoid-pki-mode) decides what is
**checked** on the path (key usage, revocation, the path rules), never which
truststores are consulted.

## The use cases

`Kind` says whether a use case is assigned truststores: `x509` and `spiffe`
are; `pins` trusts the certificate registered on each entry; `fixed` is this
service's own hierarchy, or a connection made before the directory that
holds the truststores can be read; `admission` is the rule a certificate is
admitted into a store under. `Fallback` is used only while the use case is
unassigned and its default list holds no anchor.

| Use case | What it checks | Scope | Kind | Default | Fallback |
|---|---|---|---|---|---|
| `tls-client` | A client certificate at a TLS handshake | service | x509 | `client-certificates`, `setting:tls.trustIssuedClientCertificates` |  |
| `tls-client-self-signed` | A self-signed TLS client certificate a client registered | realm | pins | — |  |
| `jose-signer` | The certificate of a key that signed a JWT this service relies on | realm | x509 | `service-root`, `signers` |  |
| `saml-signer` | The certificate of a key that signed a SAML message | realm | x509 | `signers` |  |
| `saml-metadata-signer` | The certificate that signed a service provider's metadata | realm | x509 | `setting:saml2.metadataTrustAnchors` |  |
| `federation-partner` | A federation partner's signing certificate | realm | x509 | `signers` |  |
| `wss-x509-token` | The certificate that signed a WS-Trust request | realm | x509 | `service-root`, `signers` |  |
| `jose-bare-key` | The x5c of a key a partner published in a key set | realm | x509 | `signers` |  |
| `encryption-recipient` | A certificate this service encrypts to | realm | x509 | `signers` |  |
| `policy-signer` | The certificate that signed an imported policy bundle | realm | x509 | `signers` |  |
| `client-attestation` | An OAuth client attestation's certificate chain | realm | x509 | `setting:oauth2.clientAttestationTrustAnchors`, `signers` |  |
| `webauthn-attestation` | A passkey's attestation certificate chain | realm | x509 | `setting:webauthn.attestationTrustAnchors`, `fido-mds`, `signers` |  |
| `fido-mds` | The FIDO Metadata Service BLOB's signer | service | x509 | `setting:risk.mdsTrustAnchors`, `signers` | `fido-mds-signer`, `signers` |
| `timestamp-authority` | The RFC 3161 timestamp authority behind passkey evidence | realm | x509 | `setting:webauthn.attestationEvidenceTsaTrustAnchors` |  |
| `device-attestation-android` | An Android Key Attestation chain | realm | x509 | `setting:devices.androidAttestationTrustAnchors`, `signers` | `device-vendors`, `signers` |
| `device-attestation-apple` | An Apple App Attest chain | realm | x509 | `setting:devices.appleAppAttestTrustAnchors`, `signers` | `device-vendors`, `signers` |
| `device-attestation-tpm` | A TPM attestation key's certificate chain | realm | x509 | `setting:devices.tpmTrustAnchors`, `signers` |  |
| `piv-attestation` | A YubiKey PIV key attestation | realm | x509 | `setting:piv.attestationAnchors` | `yubico-piv` |
| `piv-card` | An outside PIV or CAC card's issuing CA | realm | x509 | `setting:piv.externalIssuers` |  |
| `vc-issuer` | A verifiable credential issuer's certificate | realm | x509 | `setting:oid4vp.trustedIssuerCertificates`, `signers` |  |
| `vc-issuer-mdoc` | An mdoc Issuing Authority CA | realm | x509 | `setting:oid4vp.mdocTrustAnchors`, `mdoc-own-iaca`, `signers` |  |
| `vc-key-attestation` | A wallet's key attestation chain | realm | x509 | `setting:oid4vci.keyAttestationTrustedCertificates`, `signers` |  |
| `pkinit` | A Kerberos PKINIT client certificate | realm | x509 | `service-root` |  |
| `enrollment-credential` | An EST client certificate or SCEP renewal signer this service issued | realm | fixed | `service-root` |  |
| `spiffe-attestation-x509pop` | A SPIFFE node's x509pop certificate | realm | x509 | `setting:spiffe.x509popCaBundle`, `signers` |  |
| `spiffe-attestation-tpm-devid` | A SPIFFE node's TPM DevID certificate | realm | x509 | `setting:spiffe.tpmDevidCaBundle`, `signers` |  |
| `spiffe-attestation-tpm-ek` | A SPIFFE node's TPM endorsement key certificate | realm | x509 | `setting:spiffe.tpmEndorsementCaBundle`, `signers` |  |
| `spiffe-attestation-azure` | An Azure IMDS attested document's signer | realm | x509 | `setting:spiffe.azureImdsTrustBundle`, `cloud-attestation`, `signers` |  |
| `spiffe-svid` | An X509-SVID, against the bundle of its trust domain | realm | spiffe | `spiffe:*` |  |
| `spiffe-jwt-svid` | A JWT-SVID, against the bundle of its trust domain | realm | spiffe | `spiffe:*` |  |
| `client-jws` | A JWT or signature a client made: private_key_jwt, an RFC 7523 assertion, a request object, an HTTP message signature | realm | jwks | `registered-keys` |  |
| `federation-jwt` | A token a federation partner signed: its ID Token, logout token or signed response | realm | jwks | `registered-keys` |  |
| `ssf-set` | A Security Event Token an SSF transmitter partner signed | realm | jwks | `registered-keys` |  |
| `claims-provider-jwt` | Aggregated or distributed claims a claims provider signed | realm | jwks | `registered-keys` |  |
| `oidfed-anchor` | A Trust Anchor an OpenID Federation trust chain ends at, and its keys | realm | jwks | `registered-keys` |  |
| `spiffe-sshpop` | An SSH host certificate a SPIFFE sshpop agent presents | realm | ssh | `setting:spiffe.sshpopCertAuthorities` |  |
| `sigstore-cosign-key` | A cosign public key an image signature is verified with | realm | cosign | `setting:spiffe.dockerSigstorePublicKeyFiles` |  |
| `sigstore-trusted-root` | A pinned Sigstore trusted root (Fulcio, Rekor and CT log keys), while TUF is off | realm | sigstore-root | `setting:spiffe.dockerSigstoreTrustedRootFile` |  |
| `sigstore-tuf-root` | The TUF root the Sigstore trusted root is delivered under | realm | tuf-root | `setting:spiffe.dockerSigstoreTufRootFile` |  |
| `revocation-signer` | A CRL issuer outside the path of the certificate checked | service | x509 | `setting:pki.revocationCrlIssuersFile` |  |
| `cell-peer` | Another cell of this deployment | service | fixed | `service-root` |  |
| `ca-import` | A certificate authority imported into this service's hierarchy | realm | admission | — |  |
| `anchor-admission` | A certificate added to a truststore | realm | admission | — |  |
| `outbound-federation` | Federation partners, and every fetch that uses their transport | service | x509 | `system`, `setting:federation.outboundCaFile` |  |
| `outbound-ssf` | Shared Signals push delivery | service | x509 | `system`, `setting:ssf.pushCaFile` |  |
| `outbound-gnap` | GNAP push interaction finish | service | x509 | `system`, `setting:gnap.pushCaFile` |  |
| `outbound-xacml-pep` | The remote XACML PEP notification | service | x509 | `system`, `service-root`, `setting:xacml.pepNotifyCaFile` |  |
| `outbound-audit` | Audit export to a webhook, Splunk HEC or syslog over TLS | service | x509 | `system`, `setting:auditExport.caFile` |  |
| `outbound-authzen-pdp` | The external AuthZEN PDP | service | x509 | `setting:authzen.externalPdpCaFile` | `system`, `setting:federation.outboundCaFile` |
| `outbound-scim` | Outbound SCIM provisioning | service | x509 | `system`, `setting:scimClient.caFile` |  |
| `outbound-secret-push` | A rotated password pushed to a secret store | service | x509 | `system` |  |
| `outbound-attribute-source` | An operator's SQL attribute source | service | x509 | `system` |  |
| `outbound-smtp` | The SMTP relay | service | x509 | `system`, `setting:mail.smtpCaFile` |  |
| `outbound-icap` | The ICAP malware scanner | service | x509 | `system`, `setting:malwareScan.caFile` |  |
| `outbound-revocation-http` | OCSP responders and CRLs over HTTPS | service | x509 | `system`, `setting:pki.revocationHttpsCaFile` |  |
| `outbound-revocation-ldap` | CRLs over LDAPS | service | x509 | `system`, `setting:pki.revocationLdapCaFile` |  |
| `outbound-database` | The persistence database: dialled before the directory that holds the truststores can be read, so its own setting decides | service | fixed | `setting:persistence.databaseTlsCaFile` | `system` |
| `outbound-secret-store` | The Vault or OpenBao secret store: dialled before the directory can be read, so its own setting decides | service | fixed | `setting:keys.vaultCaCert` | `system` |
| `outbound-kubelet` | The kubelet a SPIFFE workload runs on | service | x509 | `setting:spiffe.k8sKubeletCaFile` | `k8s-in-cluster` |
| `outbound-k8s-api` | The Kubernetes API server (TokenReview) | service | x509 | `k8s-in-cluster` | `system` |
| `outbound-cloud-sdk` | AWS, Google Cloud and Azure APIs: their SDKs build their own TLS from node's store and NODE_EXTRA_CA_CERTS | service | fixed | `system` |  |
| `outbound-loopback` | This service, dialled by itself | service | fixed | `service-root` |  |

## Managing truststores

On `/admin/pki/trust`:

* **Truststores** lists every truststore the realm can name. Create a named
  truststore, add certificates to it (PEM, one or more blocks, each through
  the [admission rule](signer-truststore.md#what-belongs-in-it)), remove
  them, or delete it. A truststore a use case still trusts is not deleted
  (`STS-PKI-0307`). To create a key set, choose **a key set bound to one
  party** as what it holds, name the party, and paste its public keys or
  give a `jwks_uri`; **Replace the keys** on its row changes them later. Its
  party never changes. SSH CA keys (`sshKeys`) and the three Sigstore
  documents (`document`) are created and replaced the same way.
* **Use cases** lists every use case, what it trusts now and its default.
  Assign a use case a list, or clear its assignment to return it to its
  default. A service-wide inbound use case is assigned from the default
  realm only (`STS-PKI-0302`): it trusts the same truststores in every
  realm. In any other realm, an outbound one may be given that realm's own
  list, shown as *this realm's own list*.
* **System truststore** lists node's default store.

The management API:

```bash
# Every truststore and use case in the realm
curl https://sts.example/admin-api/truststores -H "Authorization: Bearer $TOKEN"

# Create a truststore, add a CA, and point a use case at it
curl -X POST https://sts.example/admin-api/truststores/create \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "partners", "description": "Our federation partners"}'
curl -X POST https://sts.example/admin-api/truststores/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "partners", "certificates": "-----BEGIN CERTIFICATE-----\n..."}'
curl -X POST https://sts.example/admin-api/truststores/assign \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"useCase": "saml-signer", "truststores": ["partners", "signers"]}'

# A key set for one client, added to what the client registered
curl -X POST https://sts.example/admin-api/truststores/create \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "acme-keys", "kind": "jwks", "party": "client:acme",
       "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}]}}'
curl -X POST https://sts.example/admin-api/truststores/assign \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"useCase": "client-jws", "truststores": ["registered-keys", "acme-keys"]}'
```

The other actions are `show`, `remove`, `delete`, `unassign` and
`set-keys`, which replaces a key set's keys, an SSH CA truststore's keys or
a document; the
[Management API reference](openapi/admin-api-pki.md) has each one.

Truststores are kept in the directory under `ou=truststores` in each realm
(see the [LDAP schema](ldap-schema.md)), so they survive a restart and reach
every node of a cluster wherever the directory does. A listener's client
truststore is re-applied when a service-wide truststore or assignment
changes.

## What cannot be assigned

* The **database** (`outbound-database`) and the **secret store**
  (`outbound-secret-store`) are connected before the directory can be read,
  so `persistence.databaseTlsCaFile` and `keys.vaultCaCert` still decide.
* The **AWS, Google Cloud and Azure SDKs** (`outbound-cloud-sdk`) build their
  own TLS from node's default store and `NODE_EXTRA_CA_CERTS`.
* A **separate process** (the SPIFFE workload agent, the health check probe,
  the embedded debugger's API) is configured by its own flags.
