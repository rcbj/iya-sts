---
title: "Card-held keys: S/MIME, OpenPGP and SSH"
nav_order: 25
---

# Card-held keys: S/MIME, OpenPGP and SSH

Part of [Smart cards](smart-cards.md). A card holds keys for more than
signing in. This page says which of them the service uses and how.

* TOC
{:toc}

## S/MIME mail to a PIV slot 9d key

**The standard.** S/MIME 4.0 (RFC 8551) encrypts a message to the
recipient's certificate as a CMS AuthEnvelopedData or EnvelopedData. The recipient's card decrypts it with its Key Management
key, PIV slot 9d.

**What iya-sts does.** It *sends* mail encrypted to a person's
`userSMIMECertificate` when they chose S/MIME. A `piv-key-management`
certificate enrolled for their card's 9d key, with its attestation, can be
that certificate, and then only the card reads the mail
(`openssl cms -decrypt` with the 9d key through PKCS #11). See
[OpenPGP and S/MIME → Encrypted mail](openpgp.md#encrypted-mail). A key made
on the card is lost with it, and so is the mail encrypted to it; a realm
that must keep old mail readable turns on `piv.keyEscrow`, so the 9d key is
made here, imported into the card and kept sealed
([Escrowed encryption keys](hardware-tokens.md#escrowed-encryption-keys)).

**Not implemented**: signing or decrypting mail on the service's side
([Not offered](openpgp.md#not-offered)). The `piv-sign` (9c) certificate is
issued for the person's own mail client to use.

## An OpenPGP card's key

**The standard.** OpenPGP (RFC 9580) keys can live on an OpenPGP card, such
as a YubiKey's OpenPGP applet, which makes signatures and decrypts behind a
PIN.

**What iya-sts does.** A person registers their OpenPGP public key by
signing a challenge, and the card makes that signature. Mail can then be
encrypted to the key and the key is published in the Web Key Directory when
that is on. See [Registering a key](openpgp.md#registering-a-key).

**Not implemented**: the service cannot tell a key on a card from one in a
file, so an OpenPGP key is never recorded as hardware-bound and earns
nothing. Signing in with an OpenPGP key is not offered
([Not offered](openpgp.md#not-offered)). An OpenPGP card cannot hold an
RFC 9980 post-quantum key yet, so the post-quantum mail key is kept in
software ([Hardware tokens](hardware-tokens.md)).

## OpenSSH user certificates for a card's key

**The format.** OpenSSH's own certificate format (`PROTOCOL.certkeys`) and
key revocation list (`PROTOCOL.krl`), which an SSH server checks with
`TrustedUserCAKeys` and `RevokedKeys`.

**What iya-sts does.** Each realm has an OpenSSH user CA, and a person can
be issued a certificate for the public key of a card's slot. `ssh` then
uses the key through PKCS #11
(`ssh -I opensc-pkcs11.so -i card.pub -o CertificateFile=card-cert.pub`).
Where the key is one an attested PIV certificate of the person's certifies,
the certificate is issued as hardware-backed, up to
`pki.sshHardwareLifetimeSeconds` (an hour) rather than
`pki.sshSoftwareLifetimeSeconds` (five minutes), and is recorded on the
card's token, so reporting the card lost revokes it and puts it on the KRL.
See [PKI → OpenSSH user certificates](pki.md#openssh-user-certificates) and
[The SSH user CA](pki.md#the-ssh-user-ca).

**Not implemented**: the service cannot make an SSH server fetch the KRL;
the operator's deployment refreshes the file.

## Where it is configured

| What | Console | Setting or page |
|---|---|---|
| The person's S/MIME certificate and OpenPGP key | the portal's **Tokens and keys → OpenPGP and S/MIME**; **Directory → OpenPGP keys** | [OpenPGP → Settings](openpgp.md#settings) |
| The 9d and 9c certificates | **Protocols → PIV**, and the PIV enrolment | [PIV](smart-cards-piv.md) |
| SSH user certificates | the portal's **SSH user certificates** tab; **Directory → Hardware tokens → SSH certificates**; **Protocols → SSH user certificates** (`/admin/ssh-user-ca`) | [The SSH user CA](pki.md#the-ssh-user-ca) |

## Related

[OpenPGP keys and encrypted mail](openpgp.md) ·
[Hardware tokens](hardware-tokens.md) ·
[PKCS #11](smart-cards-pkcs11.md)
