---
title: Hardware tokens
---

# Hardware tokens

A **hardware token** is one physical security key or smart card, such as a
YubiKey. One token can hold several credentials: passkeys, certificates, and
in later releases one-time-password secrets and SSH and OpenPGP keys. Each
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

Today one source records tokens: **a security key registered with enterprise
attestation** (see [Passkeys and WebAuthn](passkeys.md)). The service
recognises two places a key's attestation certificate can carry a serial:
the certificate subject's `serialNumber` attribute, or Yubico's serial
extension. The service must also trust the attestation, and the registration
must have asked for enterprise attestation. When all of that holds, the
service records a token at the moment it writes the passkey.

A key registered without enterprise attestation still works as a passkey. It
does not appear among the person's hardware tokens. Later releases add PIV key
attestation for smart-card certificates, and vendor seed-file imports.

| Evidence source | What records it |
|---|---|
| `fido-enterprise-attestation` | A passkey registration whose trusted enterprise attestation names a serial |
| `piv-attestation` | A PIV key attestation (a later release) |
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
4. A CAEP **credential-change** is sent through Shared Signals for each
   credential, and the sign-on sessions those credentials started are ended.
5. An audit row (`hardware-token.lost`) lists what was retired and what was
   not.

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

## Error codes

The `STS-HWTOKEN-*` codes are listed in [Error codes](error-codes.md).
