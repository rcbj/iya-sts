---
title: Signer truststore
nav_order: 7
---

# The signer truststore, at `/admin/pki/trust`

The signer truststore holds the certificate authorities, and the intermediates
under them, that a **third party's certificate** may chain to when this service
relies on it for anything but a TLS handshake: under a signature, as an
encryption recipient, or in an attestation.

Protocols → PKI trust is the page, and `GET /admin-api/pki/trust` with
`POST /admin-api/pki/trust/{add,remove}` are the same controls for a machine.

## What belongs in it

* **An anchor** is a self-signed CA certificate.
* **An intermediate** is a CA certificate that chains to an anchor already held.
  Add one when a partner's leaf arrives with no chain, so the chain can be
  completed from here.
* **A leaf never does.** A certificate you want to pin goes on the application
  entry or the federation relationship that uses it, where it is listed on the
  page's *Pinned certificates* tab.

## How it differs from the client-certificate truststore

| | Signer truststore | [Client-certificate truststore](tls.md#the-client-truststore) |
|---|---|---|
| Asked for | anything but a TLS handshake | a client certificate at a TLS handshake |
| Scope | **one per trust realm**; a realm does not inherit the default realm's | one for the process, because a handshake has no realm in it |
| Page | `/admin/pki/trust` | `/admin/tls/trust` |
| File | `pki.signerTrustAnchorsFile` | `tls.trustAnchorsFile` |
| Holds | at most 32 anchors and 64 intermediates per realm | at most 32 anchors |

The two are never merged. A CA you add to one is not trusted by the other.

## Who it is consulted for

The table of [use cases](pki-use-cases.md) says, per use case, whether it may
reach this store. The store is consulted only while
[paranoid PKI mode](pki.md#paranoid-pki-mode) applies to that use case.

An entry may name **use cases** when it is added. An entry naming none serves
every use case; an entry naming some serves only those, so you can trust a CA for
`saml-signer` and not for `jose-signer`.

## Adding a certificate

Paste one or more PEM blocks on the *Signer truststore* tab, or:

```bash
curl -X POST https://sts.example/admin-api/pki/trust/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificates": "-----BEGIN CERTIFICATE-----\n...",
       "purposes": ["saml-signer"]}'
```

Each block is judged on its own, and each refusal is named in the answer. The
order inside a bundle does not matter. Adding one that is already held is counted
and changes nothing. Under a realm's prefix (`/realm/acme/admin-api/...`) the
entry goes in that realm's store.

| The certificate | Refused because | Code |
|---|---|---|
| is not a CA | a leaf never goes in a truststore | `STS-PKI-0234` |
| is offered as an anchor and is not self-signed, or its self-signature does not verify | an anchor vouches for itself | `STS-PKI-0228` |
| states `cA` false where a CA is asked | | `STS-PKI-0229` |
| states a keyUsage without `keyCertSign` | it may not sign certificates | `STS-PKI-0230` |
| is outside its validity window | | `STS-PKI-0231` |
| holds a weak key or signature, or a critical extension nothing reads | | `STS-PKI-0232` |
| is an intermediate that chains to nothing held | add its anchor first, or in the same bundle | `STS-PKI-0233` |
| would pass a cap | 32 anchors, 64 intermediates, or a full directory | `STS-PKI-0236` |
| is not a certificate | | `STS-PKI-0238` |

An entry that stops being admissible where it sits (an anchor expires) stays, is
flagged on the page, and is reported by the daily audit. You remove it.

## Accepting one certificate by name

Under [paranoid PKI mode](pki.md#paranoid-pki-mode), outbound TLS refuses a server
that presents a self-signed leaf. The log line (`STS-PKI-0242`) names the certificate
and points here.

To accept one such certificate, tick *Accept this one server certificate by name* on
the *Signer truststore* tab, or:

```bash
curl -X POST https://sts.example/admin-api/pki/trust/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificates": "-----BEGIN CERTIFICATE-----\n...", "kind": "accepted"}'
```

This is one certificate, byte for byte, in that realm, for outbound TLS only. It
vouches for nothing else. It must still be in date, of an acceptable strength, and
fit server authentication where it states a usage. A revocation source it names is
still asked. Renewing the server's certificate means accepting the new one. Removing
the row takes the acceptance back.

A certificate authority cannot be accepted this way (`STS-PKI-0267`): it goes in as
an anchor, because trusting it trusts everything it signs. `pki.paranoidOutboundTls`
off goes back to the earlier behaviour for every outbound request in the realm.

A certificate you configured as a dialer's own CA is already accepted, byte for
byte, so nothing is owed for the OpenBao and postgres certificates the shipped
`docker-compose.yml` generates and delivers: `keys.vaultCaCert` and the database's
CA file name them.

## The file

`pki.signerTrustAnchorsFile` names a PEM bundle read when the process starts,
into the **default realm's** store only. A named file that cannot be read, or
holds no certificate, stops the service from starting (`STS-PKI-0237`). A block
in it the rule refuses is left out and logged. Its entries come back at every
start, so the page refuses to remove one: take it out of the file.

## Where it is kept

Runtime entries are written to the directory, in
`ou=signerTrustAnchors,<realm base>` ([schema](ldap-schema.md)). They survive a
restart wherever the directory does and reach every other process through it.
Anybody the directory lets write that container can add an entry, as with every
other container: authorize the directory accordingly.

## Related

* [PKI: certificate validation and paranoid PKI mode](pki.md#certificate-validation-what-is-checked-and-where)
* [PKI use cases](pki-use-cases.md)
* [TLS: the client truststore](tls.md#the-client-truststore)
