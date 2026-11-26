---
title: Smart-card guide
nav_order: 26
---

# Smart-card guide: configuration and use cases

Recipes for the common smart-card deployments. Each step names the console
page and the `/admin-api` call, and links to the section that explains every
option, which is not repeated here. What each part *is* is on
[Smart cards](smart-cards.md).

The API examples use the `api` helper and the `$BASE` and `$TOKEN` variables
of [Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start).
A setting is per [trust realm](trust-realms.md): call
`$BASE/realm/<id>/admin-api/...` to set it in a realm other than the default.
The settings below can all be changed while the service runs, except
`tls.trustAnchorsFile`.

* TOC
{:toc}

## Accept outside federal PIV and CAC cards

For cards an agency, the DoD or your own enterprise CA issued, signing
people in by issuer and serial or by the FIPS 201 card UUID.

1. **Trust the roots and the intermediates the browsers do not send.**
   **Protocols → Client-certificate truststore** (`/admin/tls/trust`) →
   **Add anchors**, or:
   ```bash
   jq -n --arg c "$(cat fpki-root-and-intermediates.pem)" '{certificates:$c}' |
     curl -sk -X POST "$BASE/admin-api/tls/trust/add" \
       -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
       --data-binary @-
   ```
   The truststore is service-wide and holds at most 32 anchors. In product
   mode, load it at startup with `tls.trustAnchorsFile`
   ([Trust a CA for client certificates](configure-tls.md#trust-a-ca-for-client-certificates)),
   or assign the `tls-client` use case a named truststore
   ([Truststores → Smart cards](truststores.md#smart-cards-and-certificate-sign-in)).
2. **Work out the root's SubjectPublicKeyInfo SHA-256** with the `openssl`
   lines in [Working out the values](configure-tls.md#working-out-the-values).
   On the console the profile form computes it when you pick the CA.
3. **Write a certificate sign-in profile.** On **Protocols → PIV** or
   **Server configuration → Listeners → Certificate sign-in**, *Add a
   profile*; or by API, keeping the array in `profiles.json`:
   ```json
   [{
     "id": "fpki-piv",
     "issuers": ["<SHA-256 of the root's SubjectPublicKeyInfo>"],
     "keyUsage": ["digitalSignature"],
     "policies": ["2.16.840.1.101.3.2.1.3.13"],
     "bindings": ["issuer-serial", "card-uuid"],
     "smartCard": true
   }]
   ```
   ```bash
   api config/set "$(jq -n --arg v "$(jq -c . profiles.json)" \
     '{key:"certSignIn.profiles", value:$v}')"
   ```
   `"smartCard": true` (the form's *The certificates it covers are smart
   cards* box) makes these sign-ins the authentication policy's *Smart card
   (PIV/CAC) certificate* row rather than *TLS client certificate*. For a CAC,
   add the DoD's PIV Authentication policy OIDs to `policies`; for PIV-I add
   `2.16.840.1.101.3.2.1.3.18`. The members, the binding methods and their
   refusals are in [The members of a profile](configure-tls.md#the-members-of-a-profile)
   and [Binding methods](configure-tls.md#binding-methods), and this profile is
   [Example: federal PIV cards](configure-tls.md#example-federal-piv-cards).
4. **Record whose card is whose.** For `card-uuid`, the card's UUID on the
   person's entry, *Outside PIV or CAC card UUIDs* on **Directory → Users →**
   the person; for `issuer-serial`, **Credentials → Certificate sign-in →
   Derive the bindings** from the person's certificate. By API:
   ```bash
   api users/add-attribute '{"user":"jane","attribute":"stsPivCardUuid",
     "value":"urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301"}'
   api users/add-attribute '{"user":"jane","attribute":"stsCertificateBinding",
     "value":"issuer-serial:<issuing CA SPKI SHA-256>:<serial hex>"}'
   ```
   Every value is normalised and must be unique in the realm
   ([Recording a binding on a person](configure-tls.md#recording-a-binding-on-a-person)).
   LDAP, SCIM and a bulk import write the same attributes.
5. **Make revocation reachable.** In product mode a certificate sign-in
   already requires a verified status (`certSignIn.requireRevocation` `auto`);
   in development set it `on` to behave the same:
   ```bash
   api config/set '{"key":"certSignIn.requireRevocation","value":"on"}'
   ```
   The service must reach the CRLs and OCSP responders the cards name
   ([Require a verified revocation status](configure-tls.md#require-a-verified-revocation-status),
   [PKI → Consulting revocation](pki.md#consulting-revocation)).
6. **Let the policy take a smart card.** **Directory → Policies →
   Authentication policy**: *Smart card (PIV/CAC) certificate* follows *TLS
   client certificate*, which is on by default, so nothing is needed unless
   you want cards and nothing else: set the smart card row *Yes* and *TLS
   client certificate* *No* ([Smart cards (#2031)](authentication.md#smart-cards-2031);
   the API form is in [Require a card for administrators](#require-a-card-for-administrators)).
7. **Check one card.** With the card in the reader,
   `GET /admin-api/tls-connection` (**Monitoring → TLS connection**) says
   whether the certificate verified, its revocation verdict and what the
   identity gate made of it
   ([See what the service made of your certificate](configure-tls.md#see-what-the-service-made-of-your-certificate)).

**The shorter alternative** is `piv.externalIssuers`: the agencies' issuing
CAs as PEM, cards mapped by card UUID only, one hop, with
`piv.externalPolicyOids` checked on the leaf
([Outside PIV and CAC cards](hardware-tokens.md#outside-piv-and-cac-cards)).
A profile is what to use when the cards chain through a bridge or several
agency CAs.

These cards earn `swk`, never `hwk`, never meet `attested-hardware`, and
get no Kerberos ticket ([What it does not do](smart-cards.md#what-it-does-not-do)).

## Issue your own YubiKey PIV certificates with attestation

1. **Let EST issue the PIV profiles.** `est.allowedProfiles` is a list, so
   set all of it: the default plus the slots you issue.
   ```bash
   api config/set '{"key":"est.allowedProfiles","value":"tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon,device,piv-auth,piv-sign,piv-key-management"}'
   ```
   On the console it is the EST settings on **Protocols → Cert issuance**.
   Add `piv-card-auth` only for door readers
   ([PIV certificate profiles](hardware-tokens.md#piv-certificate-profiles)).
2. **Decide what an attestation must show** (**Protocols → PIV**):
   ```bash
   api config/set-many '{"piv.requireAttestation":true,
     "piv.pinPolicy":"once","piv.touchPolicy":"cached"}'
   ```
   The attestation roots default to Yubico's; `piv.attestationAnchors` or
   the `piv-attestation` truststore use case replaces them.
3. **Make the key and the request on the card**, and export the
   attestation, as in [PIV key attestation](hardware-tokens.md#piv-key-attestation):
   `ykman piv keys generate`, `ykman piv certificates request`,
   `ykman piv keys attest`, `ykman piv certificates export f9`. For PKINIT
   from MIT `kinit`, make the 9a key RSA.
4. **Enrol it.** The person on the portal's **Tokens and keys → PIV** tab;
   an administrator on **Directory → Hardware tokens → Enrol PIV** or the
   person's **Credentials → PIV** sub-tab; or:
   ```bash
   api hardware-tokens/enrol-piv "$(jq -n --arg csr "$(cat request.csr)" \
     --arg slot "$(cat attestation.pem)" --arg f9 "$(cat f9.pem)" \
     '{username:"alice", profile:"piv-auth", csr:$csr,
       attestationCertificate:$slot, attestationIssuer:$f9}')"
   ```
   The answer carries `certificatePem` and `chainPem`. A request over EST
   can carry the attestation in its `id-aa-attestation` attribute instead.
5. **Write the certificate to the card**:
   `ykman piv certificates import 9a certificate.pem`.
6. **Check it.** **Directory → Hardware tokens** lists the YubiKey under its
   serial with evidence `piv-attestation` (`GET /admin-api/hardware-tokens`).
   A sign-in with it now records `hwk` and `sc`.

The portal certificate needs no anchor added: this service's Root is trusted
for its own client certificates while `tls.trustIssuedClientCertificates` is
on ([A PIV smart card's certificate](configure-tls.md#a-piv-smart-cards-certificate)).
For S/MIME on the 9d key see [Card-held keys](smart-cards-keys.md); to keep
9d keys recoverable, `piv.keyEscrow`.

## Card sign-in to an OpenID Connect or SAML application

Nothing is configured on the application for a card to sign in to it: every
browser protocol sends the person to the sign-in screen, which offers
**Continue as *name* with your certificate** when the connection carried a
certificate that names a person in the realm
([On the sign-in screen](configure-tls.md#on-the-sign-in-screen)).

1. **Cards set up** as in one of the two recipes above.
2. **Optionally move the PIN prompt to a listener of its own**, so nobody
   who types a password is asked for a card
   ([A listener of its own for the card](configure-tls.md#a-listener-of-its-own-for-the-card-the-handoff)):
   ```bash
   api listeners/set-listeners '{"value":[{"id":"smartcard","port":8443,
     "publicBaseUrl":"https://sts.example.com:8443","clientAuth":"optional"}]}'
   api listeners/set-applications '{"value":{
     "certificate-sign-in":{"listeners":["smartcard"]}}}'
   api config/set '{"key":"certSignIn.handoff","value":true}'
   api config/set '{"key":"tls.mainPortDisableOptionalClientCertificate","value":true}'
   ```
   The listener must share the main port's host name, or both be under
   `authn.cookieDomain`. Turning off the main port's question also stops
   RFC 8705, `GET /tls/sign-in`, EST with a certificate and the remote PEP
   there.
3. **Expect a second factor in product mode.** A card is one factor, and
   product mode asks everybody for a second unless
   `authn.allowOptionalSecondFactor` is on
   ([Requiring a second factor of everybody](authentication.md#requiring-a-second-factor-of-everybody)).
4. **What the application receives.** For the card, `acr "1"` and
   `amr ["swk"]`, or `["hwk","sc"]` on an attested card
   ([What a sign-in claims](hardware-tokens.md#what-a-sign-in-claims)). A
   card sign-in earns `phr` and never `phrh`
   ([Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh)).

**Requiring `phr` for the application.** A client's `acr_values=phr`, or a
SAML request naming only the EAP phishing-resistant class URIs, makes the
sign-in screen ask for a security key or passkey, and the certificate is
not offered on that screen. To let a card answer, do not demand the value in
the request: put the floor in the issuance policy instead, with its
`requirePhishingResistant` option for the application, which refuses
issuance on a sign-in that did not earn `phr` whatever the client asked
([Configuring OpenID Connect flows → Phishing-resistant sign-in](configure-oidc-flows.md#phishing-resistant-sign-in-phr-and-phrh)).
`requireHardwareProtected` (`phrh`) can never be met by a card.

**Limiting an application to cards.** An application that names a
[named authentication policy](authentication.md#named-authentication-policies)
with a mechanism list is offered the certificate only if the list names
`attested-hardware`, which an attested YubiKey PIV certificate meets and an
outside card never does. An application cannot be limited to outside cards;
the realm's smart-card rows apply to every application.

## PKINIT for Kerberos

1. **Issue the card a `piv-auth` certificate** for an RSA key in slot 9a,
   with its attestation ([the recipe above](#issue-your-own-yubikey-piv-certificates-with-attestation)).
   A `smartcard-logon` certificate over EST works too. An outside card's
   certificate gets no ticket.
2. **PKINIT is on** (`krb5.pkinit`); check `status.pkinit` in
   `GET /admin-api/kerberos`, or **Protocols → Kerberos → Global settings**.
3. **Give the client the anchors**: the Root as `pkinit_anchors` and the
   Issuing CA and Intermediate from `GET /.well-known/est/cacerts` as
   `pkinit_pool`, then
   `kinit -X X509_user_identity=PKCS11:module_name=…/opensc-pkcs11.so:certid=01`.
   [Configuring Kerberos → PKINIT](configure-kerberos.md#pkinit-a-certificate-as-the-pre-authentication)
   has the `krb5.conf` and every step.
4. **For a browser sign-in on that ticket** (`/authn/spnego`), the
   authentication policy's *Kerberos PKINIT with a smart card* row decides;
   it follows *Kerberos (SPNEGO)* until set
   ([Smart cards (#2031)](authentication.md#smart-cards-2031)).
5. **Windows clients** send MS-PKCA's `paChecksum2`; to require it of every
   client, `krb5.pkinitRequirePaChecksum2` — not while any client is MIT
   Kerberos ([Kerberos → PKINIT](kerberos.md#a-certificate-as-the-pre-authentication-pkinit-179)).

## Require a card for administrators

The console's people hold Admin Read or Admin Write through the groups
`admin.readGroup` and `admin.writeGroup` name (`admin-read` and
`admin-write` by default). A named authentication policy that allows only
`attested-hardware`, named by those groups, holds them to an attested
credential:

1. **Make the policy** (**Directory → Policies → Authentication policy →
   New policy**, first factor *Attested hardware* only):
   ```bash
   api policies/save-named-authn-policy '{"name":"admin-hardware",
     "description":"Administrators sign in with attested hardware",
     "precedence":10,"mechanisms":["attested-hardware"],"secondFactors":[]}'
   ```
2. **Name it from the groups** (each group's page, or):
   ```bash
   api groups/set-policy '{"group":"admin-write","attribute":"stsAuthnPolicy","policy":"admin-hardware"}'
   api groups/set-policy '{"group":"admin-read","attribute":"stsAuthnPolicy","policy":"admin-hardware"}'
   ```
   The lowest precedence among the policies an application and a person's
   groups name applies, so 10 beats an application's default 100
   ([Named authentication policies](authentication.md#named-authentication-policies)).
3. **Before you sign out**, have every administrator enrol an attested
   YubiKey PIV certificate ([above](#issue-your-own-yubikey-piv-certificates-with-attestation))
   or an attested security key, and keep a session open while you check one
   of them signs in.

What this does and does not mean:

* `attested-hardware` is met by an attested YubiKey PIV certificate **or** an
  attested passkey or security key; it cannot say "a card and nothing else".
* An **outside** PIV or CAC card never meets it, because the register holds
  no attestation for it. A deployment whose administrators carry outside
  cards has no per-group way to require one; the realm-wide rows (*Smart
  card* *Yes*, every other first factor *No*) are the only lever, and they
  apply to everybody in the realm.
* **For everybody in the realm**, `requireAttestedHardware` `always` on the
  authentication policy does the same as the named policy, and exempts the
  default realm's built-in administrator (`admin.bootstrapUsername`)
  ([Attested hardware for everybody](authentication.md#attested-hardware-for-everybody)).

The realm's own policy is saved whole: read its fields, change some, send
them all back.

```bash
curl -sk "$BASE/admin-api/policies" -H "Authorization: Bearer $TOKEN" |
  jq '[.authn.fields[] | {(.key): .value}] | add
      + {smartCardPrimary: true, certificatePrimary: false}' > authn.json
api policies/save-authn-policy "$(cat authn.json)"
```

## A TLS-terminating proxy in front

When TLS ends at a proxy, the card's certificate reaches the service only as
RFC 9440's `Client-Cert` header, from a proxy named by both its client
certificate and its address. The steps, and what the proxy must do, are in
[A TLS-terminating proxy in front of certificate sign-in](configure-tls.md#a-tls-terminating-proxy-in-front-of-certificate-sign-in):

1. Add the proxy's own CA to the client truststore, and give the proxy a
   listener that asks for a certificate (the main port does unless
   `tls.mainPortDisableOptionalClientCertificate` is on).
2. Pin it and its addresses:
   ```bash
   api config/set-many '{"tls.trustedProxyCertificates":"spki:<SPKI SHA-256 hex>",
     "tls.trustedProxyAddresses":"10.20.0.0/24"}'
   ```
3. Configure the proxy to strip any `Client-Cert` and `Client-Cert-Chain` a
   client sends and set them from its own handshake.

The forwarded certificate is then verified here and decided exactly as a
handshake's, profiles and revocation included. An L4 load balancer with TLS
passthrough and the PROXY protocol needs none of this
([TLS → Reverse proxies and load balancers](tls.md#reverse-proxies-and-load-balancers)).

## Renewal and re-issue

**Certificates this realm issued to a card.**

* **Reminders.** Every holder of a PIV slot certificate is mailed 30, 7 and
  1 days before it expires while `mail.expiryReminders` is on (the default)
  ([Mail](mail.md#the-uses)).
* **At sign-in.** **Directory → Policies → Post-login activity policy**, the
  PIV re-issue block: *Ask for PIV certificate re-issue* (`pivEnabled`), the
  slots, and `pivTrigger` (`expiring`, `classical-issuer` or `both`). A due
  person enrols a new certificate after signing in, and the old one is
  revoked (`superseded`) the first time the new one signs them in
  ([The PIV re-issue](post-login-activities.md#the-piv-re-issue)).
* **For people who rarely sign in**, start the activity: **Directory →
  Post-login activities → Start an activity**, `piv-reissue`, for their
  groups, or `POST /admin-api/post-login-activities/start`. It asks at sign-in
  even where the policy is off, and mails a reminder
  ([Starting an activity](post-login-activities.md#starting-an-activity)).
* **Moving to a post-quantum CA.** Rebuild the EST Issuing CA with an ML-DSA
  or SLH-DSA key on **Protocols → PKI**; `classical-issuer` then asks for new
  certificates. The key on the card stays classical.

**Outside cards.** Nothing is issued here, so nothing is re-issued. What a
renewal costs depends on the binding method: nothing for `card-uuid` or
`spki-sha256` on the same card, a new serial for `issuer-serial`, a new
UUID for a new card
([When a certificate is renewed](configure-tls.md#when-a-certificate-is-renewed)).
A CA that re-keys needs its new key beside the old in the profile's
`issuers`.

## A lost card

**A card this realm enrolled** (it is in the hardware token register):

1. Report it lost: the person on the portal's **Tokens and keys → Hardware
   tokens** tab (`POST /account-api/tokens` with `action` `lost`), or an
   administrator on **Directory → Hardware tokens**, or:
   ```bash
   api hardware-tokens/lost '{"key":"yubico/12345678"}'
   ```
2. Every certificate on it is revoked for `keyCompromise` and published on
   the CRL and OCSP, the sessions it started end, a CAEP credential-change is
   sent, and its SSH certificates go on the KRL. The same `curl` starts no
   session and the same `kinit` is answered `KDC_ERR_REVOKED_CERTIFICATE`
   ([Reporting a token lost](hardware-tokens.md#reporting-a-token-lost)).
3. If the 9d key was escrowed, the holder or a PIV key recovery
   administrator recovers it to read old mail
   ([Escrowed encryption keys](hardware-tokens.md#escrowed-encryption-keys)).
4. Enrol a new card as in the YubiKey recipe.

**An outside card** is not in the register and cannot be reported lost here.
Its issuer revokes it, and with a verified revocation status required (step
5 of the first recipe) the card stops signing in once the CRL or OCSP says
so. To stop it at once, remove its binding from the person:
```bash
api users/remove-attribute '{"user":"jane","attribute":"stsPivCardUuid",
  "value":"3f2504e0-4f89-41d3-9a0c-0305e82c3301"}'
```
(or the `stsCertificateBinding` value, or the stored certificate). To end
the sessions it already started, revoke them on **Monitoring → Sessions**
(`/admin/sessions`, `POST /admin-api/sessions/revoke`;
[Sessions → How one ends](sessions.md#how-one-ends)).

## Related

[Smart cards](smart-cards.md) ·
[Configuring TLS and mutual TLS](configure-tls.md) ·
[Hardware tokens](hardware-tokens.md) ·
[The sign-in service](authentication.md) ·
[Post-login activities](post-login-activities.md) ·
[Configuring Kerberos and SPNEGO](configure-kerberos.md) ·
[Truststores](truststores.md)
