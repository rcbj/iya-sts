---
title: YubiKey OTP
---

# YubiKey OTP

A YubiKey's OTP slot, checked on this service. The format is [Yubico's published OTP](https://developers.yubico.com/OTP/OTPs_Explained.html): a modhex public identity, then one AES-128 block. The AES key stays here, so a sign-in records `amr` `otp` and never `hwk`. Nothing is sent to YubiCloud. There is no post-quantum parameter: the OTP is AES-128-ECB of one 16-byte block, and a YK-VAL signature is HMAC-SHA1.

Enrolment is off until an operator turns on both `yubiotp.offered` and the authentication policy's `yubico-otp` second-factor row. That row is off by default. Off on that row, nobody may enrol, assign or claim one, even when `yubiotp.offered` is on. A credential already held is still checked at the one-time-code step. The settings are in [Configuration](configuration.md#yubikey-otp).

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

`GET` and `POST /wsapi/2.0/verify` speak [YubiKey Validation Protocol 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html). The route is always registered. While `yubiotp.ykval` is off it answers `OPERATION_NOT_ALLOWED` and signs nothing. On, the client id and the HMAC-SHA1 are checked in every mode, including development. A nonce is remembered for five minutes. `sl` in an `OK` answer is `100`.

`ykval-client-add` creates a client. The id is 1 to 16 digits. The HMAC key is in the answer once and is not logged.

## What the users page does not count

A person whose only second factor is a YubiKey OTP is omitted from the realm-wide second-factor tile. The same limit applies to an HOTP-only person. Counting them would add an index, which this release does not do. The person's own page still shows the credential: the public identity, how it was provisioned, and when it was last used. Clearing it is `POST /admin-api/users/clear-yubi` (and `POST /admin-api/mfa/clear-yubi`). A token lost with the key is better reported lost, which retires every credential on it.
