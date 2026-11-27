---
title: "Certificates, CAs and signing and decryption keys are renewed on a schedule"
kind: security
issue: 2220
---
Five keys and certificates that were renewed only at a restart or by hand now
have scheduler jobs, each on `/admin/scheduler`, with its own settings, audit
rows and error codes.

* **The listener certificate** (main port, LDAPS, the debugger) is renewed
  over the same key without a restart by `tls.server-certificate-renew`, in
  every node's front process, once less than a third of its validity is left
  (`tls.serverCertificateRenewal`, `tls.serverCertificateRenewLeadDays`).
* **The Root, Intermediate and Issuing CAs** are renewed over the same key and
  subject by the daily `pki.ca-renew`, the Root first
  (`pki.caRenewal`, `pki.rootRenewalLeadDays`, `pki.caRenewalLeadDays`).
  Everything they signed keeps verifying and a pin on a CA's key holds. A
  renewed Root is published beside the one it replaced, at
  `/pki/ca/service/root-previous.cer`, until that one expires.
* **This service's own Kerberos acceptor key** is rotated by
  `krb5.service-key-rotate`, keeping the previous key for the tickets already
  issued (`krb5.serviceKeyRotationIntervalDays`). A service key whose keytab
  was handed to another service is reported as due, not rotated.
* **The dedicated credential signers** move to a new key per family with
  `keys.credential-signer-rotate` (`keys.credentialSignerRotationIntervalDays`).
  The old key stays published, so every credential it signed keeps verifying.
* **The request object encryption keys, the OpenID4VCI request-encryption key
  and the KEM decryption keys** are replaced by `keys.encryption-key-rotate`
  (`keys.encryptionKeyRotationIntervalDays`). The new key is published at
  once, and the old one still decrypts for `keys.encryptionKeyOverlapDays`.

An upgrade rotates nothing on its first start: the key schedules count from
when they first see a key, and the Kerberos one from the key's own creation.
The key schedules run in product mode only. No upgrade script is needed.
