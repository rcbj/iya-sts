---
title: One-time code tokens (HOTP and PSKC)
---

# One-time code tokens (HOTP and PSKC)

A **one-time code token** makes a new code each time it is pressed. Two
kinds are common:

- a **YubiKey's OTP slot** programmed for HOTP, which types a code when it
  is touched, with no app;
- a **vendor's pre-provisioned token**, a key fob or card with a display,
  which an organisation buys with a **seed file** of its secrets.

The service accepts their codes as a **second factor**, beside an
authenticator app (TOTP). The counter-based algorithm is HOTP,
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). A seed file is a
Portable Symmetric Key Container (PSKC,
[RFC 6030](https://www.rfc-editor.org/rfc/rfc6030)). Like an authenticator
app, a token is never a first factor: the service holds the same secret the
token does. HOTP and a PSKC seed have no post-quantum MAC. The MAC is
HMAC-SHA-1, SHA-256 or SHA-512. A seed file that names ML-DSA, ML-KEM or
SLH-DSA is skipped.

## Setting one up yourself

On the portal, **Authenticator app** (`/portal/mfa`) has a
*One-time code token* card. *Set up a one-time code token* shows:

- a QR code holding an `otpauth://hotp/` URI with its counter, for an app
  that reads HOTP;
- the `ykman` command that programs a YubiKey's second OTP slot with the
  same secret (`ykman otp hotp 2 <secret>`);
- the secret, to type by hand.

Nothing is stored until a code confirms it: give the first code the token
shows. That code is spent, so it cannot also sign anybody in.

A person may hold one token beside one authenticator app. Setting up a
token again replaces the old one.

## Signing in

Every door that takes a one-time code takes a token's code too:

- the sign-in screen's code step, and through it step-up and recent sign-in;
- Kerberos FAST OTP pre-authentication (`kinit -T`);
- a claim of an imported token (below).

The step asks for "a one-time code". A person who holds both an app and a
token may type either. A code of the wrong length for the app is tried
against the token.

**Each press moves the token's counter on.** A press that never reached the
service (a code typed in the wrong window, a touch by accident) moves the
token ahead. The service accepts a code at the expected counter or up to
`hotp.window` presses after it, and then moves past it. A code from before
the counter is never accepted.

**A token pressed too often falls out of that window.** On the card,
*Codes not accepted?* takes **two consecutive codes**. The service searches
up to `hotp.resyncWindow` presses ahead for the pair, and moves past both.
**The sign-in step offers the same thing**, under *My token is out of step*
on the one-time code page, so a person whose only second factor is the
token is not locked out of the portal where the card is. The two codes
resynchronise the token and finish the sign-in, behind the same attempt
budget as one code (`POST /authn-api/mfa/{id}/totp` with `code` and
`code2`).

**A claim must spend the code it presents.** A claim whose code another
request already spent is refused (`STS-OATH-0051`), and two assignments of
one token at once install it on one person only: the inventory row is taken
by compare-and-set before the secret is installed.

**A code is accepted once, across the whole cluster.** The counter is
advanced by a compare-and-set in the store, so two nodes, or two workers
of one node, can never both accept the same code. The second is refused as
already used.

Code attempts are limited per person and per address, with the sign-in's
own budget for codes.

## What a sign-in claims

A token's code adds RFC 8176 `otp` to the session's `amr`, as an app's
code does. It is never phishing-resistant (`phr`): a typed code can be
relayed.

A code from a token an administrator **imported from its vendor's seed
file** also earns `hwk`, while the token is in use in the
[hardware token register](hardware-tokens.md). Its secret was made for the
device and existed only inside it and in the vendor's encrypted file. A
secret set up from a QR code or the `ykman` command never earns `hwk`.

An imported token is a second factor. It does not satisfy the
authentication policy's `attested-hardware` mechanism, which is a passkey
or certificate on an attested token.

## Importing a vendor's seed file

On the console, **Directory → Hardware tokens**, the *OATH tokens* tab
imports a PSKC file (or `POST /admin-api/hardware-tokens/import-pskc`).
Paste the file or load it from disk, and give how it is protected:

| The file is protected by | Give |
|---|---|
| a pre-shared key (RFC 6030 section 6.1: AES-128, -192 or -256 in CBC, or AES Key Wrap) | the key, in hexadecimal or base64 |
| a password (section 6.2: PBKDF2) | the password |
| nothing (plaintext) | nothing; refused in product mode unless `pskc.allowPlaintextImport` is on |

**The key and the password are never stored**, logged or shown again.
They are used to open the file and then dropped.

**The file's MAC is checked first** (section 6.1.1). A wrong key, a wrong
password and an altered file are all refused the same way, and nothing is
imported.

Each HOTP or TOTP key becomes an **unassigned** token, kept by vendor,
serial and key id. Its secret is sealed under the key-encryption key, as an
authenticator app's is. A key that cannot be imported is listed with the
reason, and the rest are imported:

- a PIN key (Figure 5 of the RFC) is skipped, never imported as a factor;
- a key with no device serial (`DeviceInfo/SerialNo`);
- a response format other than 6 to 8 decimal digits;
- a TOTP time origin other than 0, or an encrypted counter;
- a key already in the inventory.

A file encrypted to a certificate (section 6.3) is refused whole.

## Giving a token to a person

An unassigned token reaches a person in one of two ways:

- **An administrator assigns it**, by serial, on the OATH tab (or
  `POST /admin-api/hardware-tokens/assign-oath` with `key` and
  `username`).
- **The person claims it** on the portal, **Security keys**
  (`/portal/tokens`), *Claim a token you were given*: the serial printed on
  it and a code it shows now. The code is spent. A wrong serial and a wrong
  code get the same answer, so a claim cannot be used to learn which
  serials are in stock.

Either way, an HOTP token becomes the person's one-time code token. A TOTP
token becomes their authenticator, replacing an app. The hardware token
register records the token with evidence `pskc-import`, and the inventory
drops its copy of the secret.

The authentication policy's rows decide whether either kind may be given:
`hotp` (*One-time code token (HOTP)*) and `totp`.

Tested with OATH Toolkit's `oathtool` computing the codes from the seed in
the vendor's file: `oathtool --hotp --counter=<n> <hex seed>` for an HOTP
token and `oathtool --totp --time-step-size=30s <hex seed>` for a TOTP one.
The code a claim spends is refused at the next sign-in. An HOTP code a few
presses ahead signs in and moves the counter, after which the skipped codes
are refused.

## A lost token

Report the token lost on the *Hardware tokens* tab or the person's portal
(see [Hardware tokens](hardware-tokens.md)). Its secret is taken off the
person's entry, the sessions its codes signed in end, and the inventory
marks it retired. A retired token is never assigned again: its secret may
be with whoever found it.

An administrator can also clear one person's token on their row under
**Directory → Users** (or `POST /admin-api/users/clear-hotp`).

## The MAC

A token set up on the portal always uses HMAC-SHA-1 (RFC 4226 section 5).
The `otpauth://hotp/` URI carries `algorithm=SHA1`. There is no
`hotp.algorithm` setting, and nothing on **Protocols → TOTP MFA**
(`/admin/totp`) changes that MAC.

`hotp.digits` (`STS_HOTP_DIGITS`, 6 by default, from 6 to 8) changes the
length of a new portal token. An imported token keeps the length its seed
file names. `hotp.window` (`STS_HOTP_WINDOW`) and `hotp.resyncWindow`
(`STS_HOTP_RESYNC_WINDOW`) are live for every token and change how far
ahead a code may be. They do not change the MAC.

An imported PSKC seed keeps the MAC the file names: HMAC-SHA-1, SHA-256 or
SHA-512. A seed that names ML-DSA, ML-KEM or SLH-DSA is skipped. There is
no post-quantum MAC.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `hotp.digits` | 6 | Digits of a new token set up on the portal (6 to 8). An imported token keeps its own. |
| `hotp.window` | 10 | Presses that never reached the service, forgiven (0 to 100; 0 accepts only the next code). |
| `hotp.resyncWindow` | 100 | How far ahead two consecutive codes are searched (2 to 1000). |
| `pskc.allowPlaintextImport` | off | Lets product mode import a plaintext seed file. |

The authentication policy's *One-time code token (HOTP)* row is off until
an operator turns it on. While it is off, new enrolments and claims are
refused. A person who already holds a token is still asked for it.

## What is not supported

- Encryption to a certificate (RFC 6030 section 6.3), a MAC key by
  reference, Triple DES and Camellia.
- A signature on the container (section 7) is not checked.
- OCRA (RFC 6287) challenge-response.
- Producing a seed file.

## Error codes

The `STS-OATH-*` codes are listed in [Error codes](error-codes.md).
