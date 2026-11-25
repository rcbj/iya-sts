---
title: OpenPGP keys and encrypted mail
---

# OpenPGP keys and encrypted mail

A person can register their **OpenPGP public key** with this service, publish
it in the **Web Key Directory** so that mail programs find it, and choose to
have the mail this service sends them **encrypted**: with PGP/MIME to that
key, or with S/MIME to their certificate. A trust realm can also require
encryption for chosen messages, such as password reset links.

Everything here is per realm, and nothing changes for a realm until somebody
uses it: the Web Key Directory is off by default, and mail is encrypted only
for a person who chose it or a message the realm named.

## Registering a key

On the portal, **OpenPGP and mail encryption** (`/portal/openpgp`), or the
**OpenPGP and S/MIME** tab of **Tokens and keys**
(`/portal/tokens-and-keys`), which draws the same page:

1. Choose **Get a challenge**. The page shows a few lines of text naming the
   realm, your account, your address and a random value. It is good for
   `openpgp.challengeLifetimeS` (10 minutes by default), and you have one at
   a time.
2. Sign it exactly as shown:

   ```bash
   gpg --clearsign > signed.txt       # paste the challenge, then Ctrl-D
   gpg --armor --export you@example.org
   ```

   On a YubiKey or another OpenPGP card, the card makes the signature (it
   asks for your PIN, and for a touch if the card is set to).
3. Paste your public key and the whole signed message, from
   `-----BEGIN PGP SIGNED MESSAGE-----` to the end, and choose **Register the
   key**.

The key is accepted only if all of these hold:

- it is one **public** key (a secret key is refused and never stored);
- it is neither revoked nor expired, and only signatures made by the key
  itself are believed: a subkey with no binding signature, a revocation or
  an expiry that does not verify is ignored, and a subkey is encrypted to
  only when its binding's key flags name an encryption use;
- a valid user ID of it carries **the address on your account**;
- the signed message carries **exactly one** signature (`STS-OPENPGP-0029`
  otherwise), made by a signing key of it, over exactly the challenge,
  after the challenge was issued (allowing `openpgp.signatureSkewS` for the
  signing computer's clock);
- its algorithms are ones this service accepts, for every subkey it would
  sign or be encrypted with, not only the one in use today.

| Use | Accepted | Refused |
|---|---|---|
| Signing | ML-DSA-65+Ed25519 and ML-DSA-87+Ed448 (RFC 9980), SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f and SLH-DSA-SHAKE-256s (RFC 9980 section 7, on a v6 key only), then Ed25519, Ed448, ECDSA on P-256, P-384 and P-521, RSA of `openpgp.minRsaBits` (3072 at least) | DSA, Brainpool curves, SLH-DSA on a v4 key, shorter RSA |
| Encryption | ML-KEM-768+X25519 and ML-KEM-1024+X448 (RFC 9980), then X25519, X448, ECDH on Curve25519, P-256, P-384 and P-521, RSA of `openpgp.minRsaBits` | ElGamal, Brainpool curves, shorter RSA |

The list is `openpgp.algorithms`, post-quantum names first. A composite name
counts as post-quantum, not as its classical half, and so does SLH-DSA, which
is a post-quantum signature on its own. `openpgp.pqcOnly` (off by default)
narrows a **new** registration to those algorithms. A classical key
already registered still verifies and still receives mail.
`openpgp.pqcAlongsideClassical` (also off, and not together with
`openpgp.pqcOnly`) asks a new key to carry a post-quantum algorithm and a
separate classical one.

### Configuring the algorithms

`openpgp.algorithms` (`STS_OPENPGP_ALGORITHMS`) is per realm and takes
effect while the service is running. On **Protocols → OpenPGP**
(`/admin/openpgp-settings`) each name is a checkbox and an order number. **Select
all** ticks every name, or only the post-quantum ones (the four composites
and the three SLH-DSA names) while `openpgp.pqcOnly` is on. At least one name must stay ticked; a save of an
empty list is refused (`STS-ADMIN-0840`). The same value can be set with
`POST /admin-api/config/set`.

The default names every algorithm below, post-quantum first:
`ML-DSA-65+Ed25519`, `ML-DSA-87+Ed448`, `SLH-DSA-SHAKE-128s`,
`SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-256s`, `ML-KEM-768+X25519`,
`ML-KEM-1024+X448`, `ed25519`, `ed448`, `eddsaLegacy/ed25519Legacy`,
`ecdsa/nistP256`, `ecdsa/nistP384`, `ecdsa/nistP521`, `rsaSign`,
`rsaEncryptSign`, `x25519`, `x448`, `ecdh/curve25519Legacy`,
`ecdh/nistP256`, `ecdh/nistP384`, `ecdh/nistP521`, `rsaEncrypt`.

A name left out of the list is refused at registration and at verification
(`STS-OPENPGP-0004`). DSA, ElGamal and the Brainpool curves are never
accepted. A realm that set its own `openpgp.algorithms` before 1.2.0 keeps
its list, and accepts SLH-DSA only once it adds the names.

**SLH-DSA (#2220).** RFC 9980 section 7 defines SLH-DSA-SHAKE-128s (32),
SLH-DSA-SHAKE-128f (33) and SLH-DSA-SHAKE-256s (34) as standalone signing
algorithms for v6 keys, each bound to one digest: SHA3-256 for the two
128-bit sets and SHA3-512 for 256s. A self-signature or a signed challenge
over any other digest is not believed, and an SLH-DSA key in a v4 packet is
refused. The signature is checked by node's OpenSSL; a runtime that cannot
check it refuses the key (`STS-OPENPGP-0026`) rather than storing it
unchecked. The key's encryption subkey, if it has one, must be one of the
RFC 9980 ML-KEM composites for mail to be encrypted to it.

`openpgp.pqcOnly` (`STS_OPENPGP_PQC_ONLY`) and
`openpgp.pqcAlongsideClassical` (`STS_OPENPGP_PQC_ALONGSIDE_CLASSICAL`)
are on the same page. They cannot both be on (`STS-OPENPGP-0027`).

Both version 4 keys (RFC 4880, what GnuPG 2.2 and 2.4 make) and version 6 keys
(RFC 9580) are read. An RFC 9980 key is read by this service's own reader,
which checks both halves of a composite signature, and an SLH-DSA
signature over its bound digest. A new registration replaces
the key you had.

**The service cannot tell a key on a card from one in a file.** A signature
made by a YubiKey's OpenPGP card is the same bytes as one made by GnuPG with
a key on disk, so nothing is recorded as hardware-bound.

An administrator can do the same for a person on **Directory → OpenPGP
keys** (`/admin/openpgp`), on the **OpenPGP and S/MIME** sub-tab of the
person's Credentials (Directory → Users), or through
`POST /admin-api/openpgp/<action>`. The
challenge is still the person's: the administrator issues it, hands it over,
and pastes back what the person signed. Nobody can register a key whose
holder did not sign the challenge.

Removing the key (**Remove this key**) also takes it out of the Web Key
Directory, and stops mail being encrypted to it. If the key is on a security
key that is [reported lost](hardware-tokens.md), the key is removed the same
way.

## The Web Key Directory

The Web Key Directory (`draft-koch-openpgp-webkey-service`) is how GnuPG,
Thunderbird and other mail programs find a public key for an address
without a keyserver. A realm answers it when `openpgp.wkd` is on, for the
mail domains in `openpgp.wkdDomains` (the realm's own DNS domain when that is
empty), and only for people who chose **Publish my key** on the portal.

| Method | URL |
|---|---|
| Advanced | `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>` |
| Direct | `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>` |
| Policy file | `/.well-known/openpgpkey/<domain>/policy` and `/.well-known/openpgpkey/policy` |

`<hash>` is the z-base-32 SHA-1 of the local part in lower case: `Joe.Doe`
is `iy9q119eutrkn8s1mk4r39qejnbu3n5q`. A key is answered as the binary
transferable public key, `application/octet-stream`, `Cache-Control:
no-store`. Anything not published is `404`. The policy file is empty: no Web
Key Service (key submission by mail) is offered.

To serve it, point the DNS name `openpgpkey.<domain>` (advanced) or the domain
itself (direct) at this service's HTTPS listener, with a certificate for that
name. A request carries no realm in its path, so it is answered by the realm
that serves its domain — the default realm first, then the others by id.

One way to do that without replacing the main certificate is a
[custom listener](tls.md) of the service's own, on port 443, for
`openpgpkey.<domain>`. With no certificate file given, the service issues
its certificate. Then map the **Certificate authority** application, which
holds the Web Key Directory, onto that listener as well as `main`. A
realm's own listener does not work for this, because it answers only paths
under that realm's prefix. Tested that way with GnuPG 2.2:
`gpg --auto-key-locate clear,wkd,nodefault --locate-keys` found a key whose
private half is on an OpenPGP card, and after **Withdraw**, the same lookup
answered `No data`.

**CORS.** The draft suggests `Access-Control-Allow-Origin: *`. This service
never sends a wildcard: a Web Key Directory answer gets the realm's union of
`appCorsOrigin`, as discovery documents do. A desktop mail program does not
use CORS at all; a web mail client needs its origin listed on its
application.

Check a published key with GnuPG:

```bash
gpg --auto-key-locate clear,wkd --locate-keys you@example.org
```

### Moving to a post-quantum key

The [post-login activity](post-login-activities.md#the-mail-encryption-activity)
`pqc-mail-encryption` asks a person whose mail is encrypted to a classical
key to register a post-quantum one (an RFC 9980 key with an ML-KEM
encryption subkey), or to upload an ML-KEM S/MIME certificate. When it
replaces a classical OpenPGP key, the classical key is **kept beside the
new one** for the profile's `mailKeepClassical` days (90 by default): it
stays on the person's entry and the Web Key Directory answers **both keys**,
the post-quantum one first, so a correspondent that cannot use the new key
can still find the old one. Mail from this service goes to the new key at
once. An administrator may also
[start the activity](post-login-activities.md#starting-an-activity) for a
group, which mails its people a reminder to sign in and move. When the time is up, the key is no longer answered, and the job
`post-login.mail-classical-retire` removes it from the entry. Removing the
person's key removes a kept key with it. A registration on this page, outside
the activity, replaces the key as it always did.

## Encrypted mail

On the same page, under **Encrypted mail**, a person chooses:

- **Do not encrypt my mail** (the default);
- **Encrypt with my OpenPGP key** — PGP/MIME (RFC 3156): `multipart/encrypted`
  with the message encrypted to the key's encryption subkey;
- **Encrypt with my S/MIME certificate** — S/MIME 4.0 (RFC 8551):
  `application/pkcs7-mime; smime-type=authEnveloped-data`, a CMS
  AuthEnvelopedData (RFC 5083) with AES-256-GCM content encryption (RFC 5084:
  a 12-octet nonce and a 16-octet authentication tag), so the recipient's
  mail client can tell that nobody changed the message on the way. An RSA
  certificate takes the content key under RSA-OAEP (SHA-256). An EC
  certificate takes it under ECDH (P-256, P-384, P-521). An ML-KEM
  certificate (RFC 9935) takes it as a KEMRecipientInfo (RFC 9629), with
  HKDF-SHA-256 and AES key wrap, in the same AuthEnvelopedData. A runtime
  that cannot encapsulate does not send the message under RSA or ECDH
  instead.

  **A mail client that cannot read AuthEnvelopedData.** `openssl cms
  -decrypt` opens it from OpenSSL 3.0 on; an older client may not. For a
  recipient whose client cannot, set
  `mail.smimeContentEncryption` to `aes256-cbc`: mail then goes out as
  `smime-type=enveloped-data`, a CMS EnvelopedData under AES-256-CBC, which
  is what every message was before 1.2.0. CBC has no integrity protection,
  so while the setting is `aes256-cbc` in product mode, **Server
  configuration → Mode** (`/admin/mode`) reports ASVS 5.0.0 requirement
  11.3.3 as not met. The setting is a realm's, and it is read when each
  message is sent, so a change applies to retries of mail already queued.

The S/MIME certificate is the person's `userSMIMECertificate`. They can set
it on the same page (a PEM certificate that can receive S/MIME now and names
their address), an administrator can, and so can anything that writes the
attribute over LDAP. **The entry is the master copy**, and there is no
other: a value written by any door is what mail is encrypted to, and a value
that holds no certificate is taken off the entry again and audited
(`STS-OPENPGP-0034`), so mail is never encrypted to nothing. An administrator
sees it on the person's **OpenPGP and S/MIME** sub-tab, read-only beside
**Stored certificates** on the Key pairs sub-tab, and in
`GET /admin-api/users/certificates` (`smimeCertificates`), described as the
stored certificates are; it signs nobody in.

**An S/MIME certificate on a smart card.** A YubiKey's key-management key
(PIV slot 9d) can receive this mail: enrol a `piv-key-management`
certificate for it with its attestation
([Hardware tokens](hardware-tokens.md#piv-key-attestation)), then set that
certificate here. The card decrypts; with OpenSC,
`openssl cms -decrypt -engine pkcs11 -keyform engine -inkey 'pkcs11:id=%03'`
reads the message, and nothing without the card can. A key generated on the
card is lost with it, and so is every message encrypted to it; a realm that
must keep old mail readable generates and escrows 9d keys instead
([Escrowed encryption keys](hardware-tokens.md#escrowed-encryption-keys)).

### An ML-KEM S/MIME certificate issued here

A person can also have this service **issue** them a post-quantum S/MIME
certificate (#2220), under **An ML-KEM certificate from this service** on
the same page. An ML-KEM key cannot sign, so it cannot sign a certification
request; possession is proved the way RFC 9810 (CMP) section 5.2.8.3
proves it for a key that cannot sign, by a challenge:

1. Make a key with OpenSSL 3.5 or later and send its public half:

   ```bash
   openssl genpkey -algorithm ML-KEM-768 -out mlkem.key
   openssl pkey -in mlkem.key -pubout
   ```

   ML-KEM-512 and ML-KEM-1024 are accepted too. The service encapsulates a
   secret to the key and shows the ciphertext. It keeps only the SHA-256 of
   the secret, for `openpgp.challengeLifetimeS`.
2. Recover the secret with the private key and send it back:

   ```bash
   base64 -d > challenge.bin        # paste the ciphertext
   openssl pkeyutl -decap -inkey mlkem.key -in challenge.bin -secret secret.bin
   xxd -p -c 64 secret.bin
   ```

   The 64 hex characters (or the base64 of the 32 octets) are the answer.
   The challenge is spent by the first answer, right or wrong: a wrong one
   is refused (`STS-OPENPGP-0038`) and a new challenge must be asked for.
3. On a match the realm's **EST Issuing CA** issues the certificate under
   the `email` profile, through the same enrollment core as EST itself: it
   names the address on the entry, its only key usage is `keyEncipherment`
   (RFC 9935), its extended key usage `emailProtection`, and
   `est.allowedProfiles`, the lifetime and
   `pki.enrollmentMaxCertificatesPerEntry` apply. It becomes the person's
   S/MIME certificate at once, and the page shows it once, with its chain,
   to save and import with the private key into a mail program.

The same two acts are `POST /account-api/openpgp` with `action`
`smime-kem-challenge` (`publicKey`) and `smime-kem-issue` (`secret`); the
challenge is in the view's `smimeKemChallenge`, and the certificate in the
answer's `view.smimeKemIssued`. A key that is not ML-KEM is refused
(`STS-OPENPGP-0035`), as is the whole request where the runtime cannot
encapsulate (`STS-OPENPGP-0036`). Uploading a certificate works as before.

An encrypted message's **Subject is not encrypted**, so it goes out under a
neutral subject for its kind — "A security notice from …", "A message from
…", "A notification from …" in the recipient's language. The real subject,
sender and recipient are inside, as protected headers. Nothing new is signed:
the outer message is signed with [DKIM](mail.md) as every message is.

### A key belongs to its address

A key is used only for an address one of its valid user IDs names, and a
certificate only for an address it names.

- **Mail to your own address** is encrypted to the key. If the key no longer
  names that address, the choice cannot be kept and the message is not
  queued (`STS-MAIL-0241`).
- **Mail to another address** — the notice that your address changed, sent
  to the former address, or a verification link sent to a new address you
  asked for — is encrypted only if the key names that address. Otherwise it
  is sent **unencrypted**, even when `mail.encryptionRequired` names its
  template: a message encrypted to a key that address does not hold could
  not be read there, and refusing it would leave the change impossible to
  finish.
- **When your address changes** to one the key does not name, the key is
  removed from your entry and from the Web Key Directory, your choice goes
  back to **Do not encrypt my mail**, and the audit log records it
  (`openpgp.key-removed`). Register a key whose user ID carries the new
  address. A key that names the new address too is kept, and its
  publication moves to the new address. An S/MIME choice whose certificate
  does not name the new address goes back to no encryption the same way.

### Messages that must be encrypted

`mail.encryptionRequired` names templates (see [Mail](mail.md#messages)) that
are sent **only** encrypted, for example:

```
password-reset,account-activation,sign-in-code,sign-in-link,credential-compromised
```

A message is never sent in the clear against either the realm's requirement
or the person's choice:

| Situation | What happens | Code |
|---|---|---|
| The template is required and the person chose no encryption | Not queued | `STS-MAIL-0240` |
| The person's choice cannot be kept now (the key expired, the certificate can no longer receive) | Not queued | `STS-MAIL-0241` |
| The realm's transport is Azure Communication Services, which cannot carry a composed MIME message | Not queued | `STS-MAIL-0242` |
| The key or certificate no longer reads when the message is sent | Dead letter | `STS-MAIL-0243` |

A message that is not queued is handled as any refused message is: the
forgot-password form answers the same sentence whatever happened, an
administrator mailing a link is told it was not sent, and every refusal is on
the audit log.

## Settings

The `openpgp.*` rows are drawn on **Protocols → OpenPGP**
(`/admin/openpgp-settings`), whose Metadata tab also lists the realm's Web
Key Directory endpoints. **Directory → OpenPGP keys** (`/admin/openpgp`)
shows one person's key and draws no setting; until #2049 the group was homed
there, and could not be changed in the console.

| Setting | Default | What it does |
|---|---|---|
| `openpgp.wkd` | `false` | Answer the Web Key Directory |
| `openpgp.wkdDomains` | empty | The mail domains it answers for; empty is the realm's DNS domain |
| `openpgp.challengeLifetimeS` | `600` | How long a registration challenge is good |
| `openpgp.signatureSkewS` | `300` | How far the signing computer's clock may be off |
| `openpgp.algorithms` | the RFC 9980 composites, then the classical names | Which algorithms a key may use, in order |
| `openpgp.pqcOnly` | `false` | A new registration must use a post-quantum composite |
| `openpgp.pqcAlongsideClassical` | `false` | A new registration must carry a post-quantum algorithm and a separate classical one |
| `openpgp.minRsaBits` | `3072` | The shortest RSA key accepted |
| `mail.encryptionRequired` | empty | The templates sent only encrypted |

All are per realm. The error codes are under `STS-OPENPGP` on
[Error codes](error-codes.md).

## Not offered

- Signing in with an OpenPGP key: there is no standard for it. Use a passkey
  or a [PIV certificate](hardware-tokens.md).
- Signing or decrypting mail, a keyserver, or the Web Key Service.
