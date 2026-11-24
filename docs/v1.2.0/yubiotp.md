---
title: YubiKey OTP
---

# YubiKey OTP

A YubiKey's OTP slot, checked on this service. The format is [Yubico's published OTP](https://developers.yubico.com/OTP/OTPs_Explained.html): a modhex public identity, then one AES-128 block. The AES key stays here, so a sign-in records `amr` `otp` and never `hwk`. Nothing is sent to YubiCloud. There is no post-quantum parameter: the OTP is AES-128-ECB of one 16-byte block, and a YK-VAL signature is HMAC-SHA1.

Enrolment is off until an operator turns on both `yubiotp.offered` and the authentication policy's `yubico-otp` second-factor row. That row is off by default. Off on that row, nobody may enrol, assign or claim one, even when `yubiotp.offered` is on. A credential already held is still checked at the one-time-code step. The settings are in [Configuration](configuration.md#yubikey-otp).

## The algorithms are fixed

There is no signature-algorithm setting for a YubiKey OTP. The OTP itself is AES-128-ECB of one 16-byte block, which is Yubico's format. A YK-VAL request is signed with HMAC-SHA1, which is Validation Protocol 2.0. Neither can be changed.

`yubiotp.offered` (`STS_YUBIOTP_OFFERED`), `yubiotp.ykval` (`STS_YUBIOTP_YKVAL`) and `yubiotp.allowPlaintextImport` (`STS_YUBIOTP_ALLOW_PLAINTEXT_IMPORT`) are the YubiKey OTP group, on **Protocols → YubiKey OTP** (`/admin/yubiotp`). Until #2049 the first two were on Protocols → TOTP MFA and the third on Protocols → Device registration; their keys, variables and defaults did not change. All three take effect while the service is running. They turn enrolment, the verify endpoint and plaintext import on or off. They leave AES-128-ECB and HMAC-SHA1 as they are.

## Set one up

On `/portal/mfa`, or the **YubiKey OTP** tab of **Tokens and keys** (`/portal/tokens-and-keys`), **Set up a YubiKey OTP** shows one line:

```bash
ykman otp yubiotp 1 --public-id … --private-id … --key …
```

Run it once with the key inserted. It programs the first OTP slot. Touch the key, paste the password it types, and confirm. That password is spent. The line is shown only while the enrolment is pending, and it is not written to the log.

## Import a batch

An administrator posts a CSV to `POST /admin-api/hardware-tokens/import-yubiotp`; the console has no import form for it. The columns are the serial, the modhex public identity, the private identity in hexadecimal, and the AES key in hexadecimal. In product mode a file in the clear is refused unless `yubiotp.allowPlaintextImport` is on. Each row is kept unassigned, and the secret is sealed.

`assign-yubiotp` gives a serial to a person and spends one OTP. In the console it is **Assign** on the **YubiKey OTP** sub-tab of the person's Credentials (Directory → Users). The person can do the same from `/portal/mfa`, or the YubiKey OTP tab of Tokens and keys, with the serial and one touch (`yubiotp-claim`). An assigned token is retired by reporting the hardware token lost, which also takes the secret off the entry.

## On the person's entry

An assigned YubiKey is on its holder's entry, in `stsYubiOtpToken`: one JSON value with its serial, public identity, status, and when it was imported and assigned. Never the AES key, which is sealed in the person's YubiKey OTP credential. The entry is the master copy; the inventory and the public-identity index YK-VAL answers from are derived from it ([Hardware tokens](hardware-tokens.md#on-the-persons-directory-entry)). Removing the value by another door — the attribute editor, `/admin-api`, SCIM, an `ldapmodify` — retires the token: its credential is removed, its public identity is dropped, it is never assigned again, and the audit row (`yubiotp.retire`) names who removed it. Adding or changing a value is refused and put back (`STS-HWTOKEN-0017`). A row nobody has been assigned stays in the inventory, its secret sealed, until it is assigned or claimed.

## YK-VAL

`GET` and `POST /wsapi/2.0/verify` speak [YubiKey Validation Protocol 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html). The route is always registered. While `yubiotp.ykval` is off it answers `OPERATION_NOT_ALLOWED` and signs nothing. On, the client id and the HMAC-SHA1 are checked in every mode, including development. A nonce is spent for the whole cluster, by a compare-and-set in the store, and remembered for five minutes, so a request replayed to another node is `REPLAYED_REQUEST` there too. `sl` in an `OK` answer is `100`. An OTP of a **disabled account** is answered `BAD_OTP` (`STS-YUBIOTP-0032`) and nothing is spent: a PAM or RADIUS caller does not let in somebody this service refuses at its own sign-in. **Every verify is on the audit log** (`ykval.verify`): the client id, the OTP's public identity (never the OTP) and the status, with the error code of a refusal. The use counter is read as fifteen bits, as Yubico's own validation server reads it: the top bit is a flag.

A refusal is decided in the order of Yubico's own validation server (`yubikey-val`), since the protocol names no order:

| Check | Status |
|---|---|
| no `nonce` | `MISSING_PARAMETER` |
| `otp` not 32 to 48 modhex characters | `BAD_OTP` (`STS-YUBIOTP-0033`) |
| no `id` | `MISSING_PARAMETER` |
| `nonce` not 16 to 40 letters and digits | `MISSING_PARAMETER` (`STS-YUBIOTP-0034`) |
| no client with that `id` | `NO_SUCH_CLIENT`, unsigned |
| no `h` | `MISSING_PARAMETER` |
| `h` does not match | `BAD_SIGNATURE`, unsigned |

So an unknown client with a malformed OTP is `BAD_OTP`, and an unknown client with a well-formed OTP is `NO_SUCH_CLIENT` whether it signed the request or not. The protocol makes `h` optional; this service requires it from every client. A refusal before the client lookup is signed when the `id` names a client, and unsigned otherwise.

`ykval-client-add` creates a client. The id is 1 to 16 digits. The HMAC key is in the answer once and is not logged.

### pam_yubico

Yubico's PAM module, `pam_yubico` 2.26, works against this endpoint. Tested with `pamtester` and OTPs from Yubico's `ykgenerate`. Give it the client's id and key, the realm's endpoint as its URL, and the service's CA certificate as `cainfo`:

```
auth required pam_yubico.so id=<client id> key=<client key> urllist=https://<host>/realm/<realm>/wsapi/2.0/verify authfile=/etc/yubikey_mappings cainfo=/etc/ssl/sts-ca.pem
```

`authfile` maps a user name to the token's public identity (`user:<public id>`). With the right key the module checks every answer's signature. With a wrong key, the service answers `BAD_SIGNATURE` unsigned, and the module refuses it (`BAD_SERVER_SIGNATURE`, PAM's `AUTHINFO_UNAVAIL`). After a token is reported lost, its OTPs are `BAD_OTP`.

## What the users page does not count

A person whose only second factor is a YubiKey OTP is omitted from the realm-wide second-factor tile. The same limit applies to an HOTP-only person. Counting them would add an index, which this release does not do. The person's own page still shows the credential, on the **YubiKey OTP** sub-tab of their Credentials: the public identity, how it was provisioned, and when it was last used. Clearing it is `POST /admin-api/users/clear-yubi` (and `POST /admin-api/mfa/clear-yubi`). A token lost with the key is better reported lost, which retires every credential on it.
