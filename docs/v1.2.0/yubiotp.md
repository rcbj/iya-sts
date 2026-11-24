---
title: YubiKey OTP
---

# YubiKey OTP

A YubiKey's OTP slot, checked on this service. The format is [Yubico's published OTP](https://developers.yubico.com/OTP/OTPs_Explained.html): a modhex public identity, then one AES-128 block. The AES key stays here, so a sign-in records `amr` `otp` and never `hwk`. Nothing is sent to YubiCloud. There is no post-quantum parameter: the OTP is AES-128-ECB of one 16-byte block, and a YK-VAL signature is HMAC-SHA1.

Enrolment is off until an operator turns on both `yubiotp.offered` and the authentication policy's `yubico-otp` second-factor row. That row is off by default. Off on that row, nobody may enrol, assign or claim one, even when `yubiotp.offered` is on. A credential already held is still checked at the one-time-code step. The settings are in [Configuration](configuration.md#yubikey-otp).

## The algorithms are fixed

There is no signature-algorithm setting for a YubiKey OTP. The OTP itself is AES-128-ECB of one 16-byte block, which is Yubico's format. A YK-VAL request is signed with HMAC-SHA1, which is Validation Protocol 2.0. Neither can be changed.

`yubiotp.offered` (`STS_YUBIOTP_OFFERED`) and `yubiotp.ykval` (`STS_YUBIOTP_YKVAL`) are on **Protocols → TOTP MFA** (`/admin/totp`). `yubiotp.allowPlaintextImport` (`STS_YUBIOTP_ALLOW_PLAINTEXT_IMPORT`) is in the Devices group, on **Protocols → Device registration** (`/admin/device-registration`). All three take effect while the service is running. They turn enrolment, the verify endpoint and plaintext import on or off. They leave AES-128-ECB and HMAC-SHA1 as they are.

## Set one up

On `/portal/mfa`, **Set up a YubiKey OTP** shows one line:

```bash
ykman otp yubiotp 1 --public-id … --private-id … --key …
```

Run it once with the key inserted. It programs the first OTP slot. Touch the key, paste the password it types, and confirm. That password is spent. The line is shown only while the enrolment is pending, and it is not written to the log.

## Import a batch

An administrator posts a CSV to `POST /admin-api/hardware-tokens/import-yubiotp`. The columns are the serial, the modhex public identity, the private identity in hexadecimal, and the AES key in hexadecimal. In product mode a file in the clear is refused unless `yubiotp.allowPlaintextImport` is on. Each row is kept unassigned, and the secret is sealed.

`assign-yubiotp` gives a serial to a person and spends one OTP. The person can do the same from `/portal/mfa` with the serial and one touch (`yubiotp-claim`). An assigned token is retired by reporting the hardware token lost, which also takes the secret off the entry.

## YK-VAL

`GET` and `POST /wsapi/2.0/verify` speak [YubiKey Validation Protocol 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html). The route is always registered. While `yubiotp.ykval` is off it answers `OPERATION_NOT_ALLOWED` and signs nothing. On, the client id and the HMAC-SHA1 are checked in every mode, including development. A nonce is spent for the whole cluster, by a compare-and-set in the store, and remembered for five minutes, so a request replayed to another node is `REPLAYED_REQUEST` there too. `sl` in an `OK` answer is `100`. An OTP of a **disabled account** is answered `BAD_OTP` (`STS-YUBIOTP-0032`) and nothing is spent: a PAM or RADIUS caller does not let in somebody this service refuses at its own sign-in. **Every verify is on the audit log** (`ykval.verify`): the client id, the OTP's public identity (never the OTP) and the status, with the error code of a refusal. The use counter is read as fifteen bits, as Yubico's own validation server reads it: the top bit is a flag.

`ykval-client-add` creates a client. The id is 1 to 16 digits. The HMAC key is in the answer once and is not logged.

### pam_yubico

Yubico's PAM module, `pam_yubico` 2.26, works against this endpoint. Tested with `pamtester` and OTPs from Yubico's `ykgenerate`. Give it the client's id and key, the realm's endpoint as its URL, and the service's CA certificate as `cainfo`:

```
auth required pam_yubico.so id=<client id> key=<client key> urllist=https://<host>/realm/<realm>/wsapi/2.0/verify authfile=/etc/yubikey_mappings cainfo=/etc/ssl/sts-ca.pem
```

`authfile` maps a user name to the token's public identity (`user:<public id>`). With the right key the module checks every answer's signature. With a wrong key, the service answers `BAD_SIGNATURE` unsigned, and the module refuses it (`BAD_SERVER_SIGNATURE`, PAM's `AUTHINFO_UNAVAIL`). After a token is reported lost, its OTPs are `BAD_OTP`.

## What the users page does not count

A person whose only second factor is a YubiKey OTP is omitted from the realm-wide second-factor tile. The same limit applies to an HOTP-only person. Counting them would add an index, which this release does not do. The person's own page still shows the credential: the public identity, how it was provisioned, and when it was last used. Clearing it is `POST /admin-api/users/clear-yubi` (and `POST /admin-api/mfa/clear-yubi`). A token lost with the key is better reported lost, which retires every credential on it.
