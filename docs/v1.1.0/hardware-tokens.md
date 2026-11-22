---
title: Hardware tokens
---

# Hardware tokens

A **hardware token** is one physical security key or smart card, such as a
YubiKey. One token can hold several credentials: passkeys, certificates,
one-time code secrets imported from a vendor's seed file (see
[One-time code tokens](one-time-code-tokens.md)), and in later releases SSH
and OpenPGP keys. Each
trust realm keeps a **register of its hardware tokens**. There is one record
per physical token, keyed by its vendor and serial number. The record holds:

- who holds the token (the person's directory entry);
- its model, firmware and form factor, where its evidence gives them;
- every credential on it, with who registered it;
- the evidence the serial came from;
- whether it is in use or was reported lost.

The register is a sibling of the [device register](devices.md), not part of
it. A device there is the computer or phone a person signs in *from*, and a
roaming security key identifies no such device.

## Where a token comes from

**A serial is recorded only from attestation.** No form, API or import takes
a serial typed by a person or an administrator. A self-declared serial would
let anybody claim somebody else's key.

Two sources record tokens: **a security key registered with enterprise
attestation** (see [Passkeys and WebAuthn](passkeys.md)), and **a PIV
certificate issued from a YubiKey PIV key attestation** (below). The service
recognises two places a key's attestation certificate can carry a serial:
the certificate subject's `serialNumber` attribute, or Yubico's serial
extension. The service must also trust the attestation, and the registration
must have asked for enterprise attestation. When all of that holds, the
service records a token at the moment it writes the passkey.

A key registered without enterprise attestation still works as a passkey. It
does not appear among the person's hardware tokens.

A second source is **a vendor's PSKC seed file**: when an administrator
assigns an imported one-time code token, or its holder claims it, the
service records the token by the serial the file's `DeviceInfo` names, with
evidence `pskc-import`. See [One-time code tokens](one-time-code-tokens.md).
A YubiKey PIV key attestation records a smart-card certificate the same way,
with evidence `piv-attestation`.

| Evidence source | What records it |
|---|---|
| `fido-enterprise-attestation` | A passkey registration whose trusted enterprise attestation names a serial |
| `piv-attestation` | A certificate issued from a verified YubiKey PIV key attestation |
| `pskc-import` | The serial a vendor's PSKC seed file names, recorded when that token is assigned or claimed |
| `vendor-import` | An administrator's import of a vendor's token file (a later release) |

## Seeing them

- **People** see their own tokens on the portal's **Security keys** page
  (`/portal/tokens`, under *How I sign in*). The page draws from
  `GET /account-api/tokens`.
- **Administrators** see the realm's tokens under **Directory → Hardware
  tokens** (`/admin/hardware-tokens`). The list can be filtered by status
  and searched by serial or by person. Where the store is read on demand,
  the unsearched list shows the newest thousand tokens and says so. The page
  draws from `GET /admin-api/hardware-tokens`.

## Reporting a token lost

The person, from the portal, or an administrator, from the console or with
`POST /admin-api/hardware-tokens/lost` and `{ "key": "<vendor>/<serial>" }`,
can report a token lost. The service then does all of the following at once:

1. The token is marked **lost**. From that moment none of its credentials
   counts as hardware evidence.
2. Each **passkey** on it is removed from its holder's entry. The removal
   goes through even when the key was the person's only way to sign in,
   because whoever found the key could otherwise still use it. A person left
   with no way in needs an activation link or their recovery codes. The
   portal says so.
3. Each **certificate** on it is revoked for `keyCompromise` through the
   ordinary revocation path, so the CRL and OCSP show it.
   Each **one-time code secret** imported from a seed file is taken off its
   holder's entry (where it is still that token's), and the token is marked
   retired in the inventory, never to be assigned again.
4. A CAEP **credential-change** is sent through Shared Signals for each
   credential, and the sign-on sessions those credentials started are ended.
5. An audit row (`hardware-token.lost`) lists what was retired and what was
   not.
6. A person whose **every passkey** was on the lost token is handed to the
   [account recovery](passkeys.md) rules: a `lost-key` recovery is recorded
   on their entry before the keys go. Under the passkey policy's
   `recoveryAssurance` `not-weaker` (the default in product mode), the next
   sign-in that a passkey did not answer leads to registering a new passkey
   and not to an application. A passkey sign-in then completes the
   recovery. Under `any` nothing is recorded.

The portal retires only the caller's own credentials, and asks for a recent
sign-in. Someone else might have registered a credential on the same physical
key; the portal leaves those for an administrator. When an administrator
reports lost a token held by a Security Administrator, the act needs
`admin:security`, as clearing that person's factors does.

If a credential cannot be retired, the service names it in the answer and on
the audit row, and that credential is still live. A key that turns up again is
registered again as a new passkey.

## What a sign-in claims

RFC 8176 `amr` values that say a key is in hardware are earned from
**evidence**:

- A **certificate sign-in** (`/tls/sign-in`, or a certificate on the sign-in
  screen) records `swk`, as before. The service records `hwk` only when a
  hardware token's attestation evidence covers the certificate. It adds `sc`
  when that evidence says the key is on a smart card.
- A **PKINIT** sign-in earns `pkinit-hardware` (and `hwk`) from that
  evidence, and `pkinit-smartcard` (and `sc`) when the key is on a card. By
  default it also keeps the inference it used before: a smart-card logon
  certificate whose key this service did not generate. The setting
  `hardwareTokens.hardwareClaims` (in the *Devices* group) controls this.

| `hardwareTokens.hardwareClaims` | PKINIT earns a hardware claim from |
|---|---|
| `inference` (the default) | the inference above, or recorded evidence |
| `evidence` | recorded evidence only |

A passkey sign-in records `hwk` as it always has. Whether its attestation was
trusted is a separate fact, and phishing-resistance policy reads it (`phrh`).

## Requiring a hardware token

Each sign-in records the token its passkey or certificate is on, if a token
holds it. Policy can use that fact in two ways:

- **The authentication policy's `attested-hardware` mechanism.** A named
  authentication policy's first-factor list (`stsAuthnPolicyMechanism`)
  may name `attested-hardware`. A sign-in satisfies it only with a passkey
  or certificate on an attested token that is still in use. An application
  whose policy names only `attested-hardware` therefore gets a sign-in
  screen with a passkey and, where the realm accepts one, a certificate,
  and no password field. A session made any other way is asked again.
- **XACML attributes**, sent as environment attributes on every browser
  issuance. No built-in rule reads them; they are there for a realm's own
  rules.

| Attribute | Value |
|---|---|
| `urn:sts:xacml:hardware-token-attested` | boolean: the credential is on an attested token still in use (always sent) |
| `urn:sts:xacml:hardware-token-key` | `<vendor>/<serial>` |
| `urn:sts:xacml:hardware-token-vendor` | e.g. `yubico` |
| `urn:sts:xacml:hardware-token-model` | e.g. `YubiKey 5 NFC` |
| `urn:sts:xacml:hardware-token-evidence` | `fido-enterprise-attestation`, `piv-attestation`, `vendor-import` or `pskc-import` |
| `urn:sts:xacml:hardware-token-smart-card` | boolean: the evidence says the key is on a smart card |
| `urn:sts:xacml:hardware-token-holder-matches` | boolean: the subject is the token's recorded holder |
| `urn:sts:xacml:hardware-token-status` | `active` or `lost` |
| `urn:sts:xacml:hardware-token-pin-policy` | a PIV key's attested PIN policy: `never`, `once`, `always`, `match-once` or `match-always` |
| `urn:sts:xacml:hardware-token-touch-policy` | a PIV key's attested touch policy: `never`, `cached` or `always` |
| `urn:sts:xacml:hardware-token-firmware` | the token's firmware, e.g. `5.4.3` |
| `urn:sts:xacml:hardware-token-form-factor` | e.g. `usb-a`, `usb-c`, `lightning` |
| `urn:sts:xacml:hardware-token-fips` | boolean, sent only when true: the key is FIPS certified |

The last five are sent only for a token still attested whose attestation
said them, so a rule about them does not apply to any other sign-in. A rule
over `hardware-token-touch-policy` can, for example, let administrators sign
in only with a key whose touch policy is `always`. The settings
`piv.pinPolicy` and `piv.touchPolicy` still decide which keys may be
enrolled at all.

A token reported lost after the sign-in reads `attested` false from then on.

## PIV key attestation

A YubiKey can prove that the key in one of its PIV slots was generated on the
key and has never left it. `ykman piv keys attest <slot>` produces an
**attestation certificate** for the slot's key, signed by the key's factory
**f9 attestation certificate**, which chains to Yubico's PIV root. The service
accepts that proof when a certificate is enrolled, in two ways:

1. **Inside the certificate request**, in the `id-aa-attestation` attribute
   (`1.2.840.113549.1.9.16.2.59`) of
   [draft-ietf-lamps-csr-attestation](https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/)
   (read in revision 33). This works over EST, SCEP and ACME alike. The
   attribute holds one `AttestationBundle`. Its `attestations` list holds one
   `AttestationStatement` whose `type` is `1.3.6.1.4.1.41482.3.2` and whose
   `stmt` is the slot attestation certificate (DER). Its `certs` list holds the
   f9 certificate, and any intermediate after it. The draft defines no
   statement type for a PIV attestation, so this type is this service's
   choice: Yubico's own identifier for an attestation certificate.
2. **On the enrolment form**: the portal's **Security keys** page, and the
   console's **Directory → Hardware tokens → Enrol PIV** tab
   (`POST /admin-api/hardware-tokens/enrol-piv`). Paste the certificate request
   from `ykman piv certificates request`, the slot attestation certificate and
   the f9 certificate. The form issues over the realm's EST Issuing CA, so the
   profile must be in `est.allowedProfiles`. A person enrols only themselves;
   an administrator names the person.

```
ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy ALWAYS 9a public.pem
ykman piv certificates request --subject "CN=alice" 9a public.pem request.csr
ykman piv keys attest 9a attestation.pem
ykman piv certificates export f9 f9.pem
```

The service checks all of the following, and refuses the request if any one
fails. An attestation that does not verify is never "issued without
evidence": the client sent it, so it meant it.

- The attested public key is the request's key.
- The chain reaches one of the realm's **PIV attestation anchors** through the
  validation door (use case `piv-attestation`, see
  [PKI use cases](pki-use-cases.md)). By default the anchors are Yubico's two
  published roots, shipped with the service and pinned by their SHA-256:
  *Yubico PIV Root CA Serial 263751*, and *Yubico Attestation Root 1* for
  firmware 5.7.4 and later, with Yubico's PIV intermediates. Setting
  `piv.attestationAnchors` replaces the roots.
- The attestation names the key's serial number.
- The slot in the attestation certificate's subject ("YubiKey PIV Attestation
  9a") is the slot of the profile asked for.
- The key's PIN and touch policies meet the realm's `piv.pinPolicy` and
  `piv.touchPolicy`.

The service reads Yubico's extensions: `1.3.6.1.4.1.41482.3.3` (firmware,
three octets), `.3.7` (serial, an integer), `.3.8` (PIN policy, then touch
policy), `.3.9` (form factor), and `.3.10` and `.3.11` (FIPS and CSPN keys) on
the f9 certificate. These are documented on Yubico's
[PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html)
page.

When the attestation verifies, the issued certificate's record is marked
`attested-hardware`, with the attestation's facts. The YubiKey is recorded in
the register under its serial, with the certificate on it as a smart-card
credential. From then on, a TLS certificate sign-in with that certificate
records `hwk` and `sc`, and PKINIT records `pkinit-hardware` and
`pkinit-smartcard`. If the key is reported lost, the certificate is revoked.

A request for a PIV profile without an attestation is still issued, with no
hardware evidence, unless `piv.requireAttestation` is on.

## PIV certificate profiles

Four certificate profiles follow the YubiKey's PIV slots (NIST SP 800-73-4
and FIPS 201-3). They are available over ACME, EST and SCEP and on the
enrolment form, but **no realm issues them until an operator adds them** to
the family's `allowedProfiles`.

| Profile | Slot | Key usage | Extended key usage | Names |
|---|---|---|---|---|
| `piv-auth` | 9a | digitalSignature | clientAuth, id-pkinit-KPClientAuth, smart-card logon | the person's Kerberos principal (id-pkinit-san), and their `userPrincipalName` where they have one |
| `piv-sign` | 9c | digitalSignature, nonRepudiation | emailProtection | the person's mail address |
| `piv-key-management` | 9d | keyEncipherment, keyAgreement | emailProtection | the person's mail address |
| `piv-card-auth` | 9e | digitalSignature | id-PIV-cardAuth | — |

The PIV profiles are issued to people only. **A `piv-card-auth` certificate
does not sign anybody in** by default: the 9e key works without a PIN, for
door readers. `piv.cardAuthSignIn` lets it sign in over TLS. PKINIT never
accepts it, because it carries neither PKINIT purpose.

## Escrowed encryption keys

A 9d key decrypts S/MIME mail. A key generated on the card is lost with the
card, and so is every message encrypted to it. A realm can turn on
**`piv.keyEscrow`** (off by default). Then EST `/serverkeygen` for the
`piv-key-management` profile generates the key pair here, returns it to the
client to import into slot 9d (`ykman piv keys import 9d key.pem`), and keeps
it, sealed under the key-encryption key. Where no key-encryption key is held,
the request is refused rather than the key kept in plain. With escrow off,
`/serverkeygen` refuses that profile.

- An escrowed key is **never hardware evidence**: this service had it in
  memory. Its certificate earns no `hwk`.
- **The holder** recovers their own escrowed key on the portal's Security keys
  page, after a fresh sign-in.
- **An administrator** recovers a person's escrowed key on Directory →
  Hardware tokens → Escrowed keys, or with
  `POST /admin-api/hardware-tokens/recover-key` and
  `{ "username": "...", "serial": "..." }`. Admin Write is not enough. The
  access-control policy decides it (resource `piv-key-escrow`, action
  `recover-key`), and the built-in policy permits only a caller holding the
  **PIV_KEY_RECOVERY** role. That role is held by members of the group that
  `roles.pivKeyRecoveryGroup` names (`piv-key-recovery` by default). Nobody is
  in that group until an administrator adds them.
- Every recovery, and every refused one, is on the audit log
  (`piv-escrow.recover`), and the holder is told over CAEP.
- `GET /admin-api/hardware-tokens/escrowed?username=...` lists a person's
  escrowed certificates, never a key.
- The holder can note which YubiKey an escrowed key was loaded on ("It is on
  this key"). If that key is then reported lost, the escrowed certificate is
  revoked with the rest, and **the escrow is kept**, so old mail can still be
  read.

## Outside PIV and CAC cards

A realm can let government-issued PIV and CAC cards sign people in, by the
card's **FIPS 201 card UUID**. This is off by default. Set
`piv.externalIssuers` to the issuing CAs that sign the cards (PEM). A client
certificate is then mapped to a person when all of these hold:

- one of those issuing CAs issued it directly (use case `piv-card`);
- it asserts one of the policies in `piv.externalPolicyOids` (by default
  `id-fpki-common-authentication`, the Federal PKI Common Policy's PIV
  Authentication, and `id-fpki-certpcy-pivi-hardware`, PIV-I);
- its subjectAltName carries exactly one `urn:uuid:` URI, the card UUID;
- exactly one person's entry holds that UUID in `stsPivCardUuid`.

An administrator records the UUID on the person's page (Directory → Users,
*Outside PIV or CAC card UUIDs*), or by LDAP, SCIM or an import. Every write
normalises it (a `urn:uuid:` prefix is removed and the value lower-cased) and
refuses one that is not an RFC 9562 UUID, the nil UUID, or one another entry
already holds. A person cannot set it on the portal.

The certificate's name is never used: an issuing CA this service does not run
could write anybody's. No entry is created. A UUID on two entries maps
nobody. A reissued card has a new UUID, which an administrator records again.
The issuing CA must also be in a client truststore, or the TLS handshake
refuses the certificate before this mapping is asked.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `piv.attestationAnchors` | empty (Yubico's roots) | The roots a PIV attestation must chain to |
| `piv.requireAttestation` | off | Refuse a PIV profile without an attestation |
| `piv.pinPolicy` | `any` | The weakest PIN policy an attested key may have (`once`, `always`) |
| `piv.touchPolicy` | `any` | The weakest touch policy an attested key may have (`cached`, `always`) |
| `piv.cardAuthSignIn` | off | Let a `piv-card-auth` certificate sign in over TLS |
| `piv.keyEscrow` | off | Escrow `piv-key-management` keys from EST `/serverkeygen` |
| `piv.externalIssuers` | empty | The outside PIV and CAC issuing CAs mapped by card UUID |
| `piv.externalPolicyOids` | the two PIV Authentication policies | The policies an outside card must assert |
| `roles.pivKeyRecoveryGroup` | `piv-key-recovery` | The group whose members hold PIV_KEY_RECOVERY |
| `pki.paranoidPivAttestation`, `pki.paranoidPivCard` | on | The two use cases' rows under paranoid PKI mode |

## Error codes

The `STS-HWTOKEN-*` and `STS-PIV-*` codes are listed in
[Error codes](error-codes.md).
