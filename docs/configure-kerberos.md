---
title: "Configuring Kerberos and SPNEGO"
---

# Configuring Kerberos and SPNEGO

This page shows how to set up iya-sts's Kerberos v5 KDC and its SPNEGO
sign-in: the principals to create, the settings to change, and what a client
then runs. Each recipe is given twice, once as steps in the **admin console**
(`/admin`) and once as calls to the **Management API** (`/admin-api`).

**The values come from this repository's own test jobs** in
`tests/vendored/` (and, where a case can only be driven inside the process,
`tests/`), and each recipe names the job it is taken from. Most of those jobs
run against a service in both development and product mode. Change the
realm names, host names and passwords to your own.

How the KDC, the acceptor and `/authn/spnego` *behave*, and every setting
with its default, are on [Kerberos, KKDCP and SPNEGO](kerberos.md). This page
covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute forms. Read it first. Calls that read
rather than write use `curl` with the same token:

```bash
get() {   # get <path under /admin-api>
  curl -sk "$BASE/admin-api/$1" -H "Authorization: Bearer $TOKEN"
}
```

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/kerberos` | **Protocols → Kerberos** | Five tabs: **Metadata** (the HTTP endpoints), **Global settings** (every `krb5.*` setting, saved with **Save Kerberos**), **PAC claims**, **Principals** and **Trusts**. |
| `/admin/kerberos#kerberos-tab-principals` | **Protocols → Kerberos → Principals** | Create, rotate and delete service principals; clear a person's keys; drop previous key versions; rotate the `krbtgt` key. |
| `/admin/kerberos#kerberos-tab-trusts` | **Protocols → Kerberos → Trusts** | Add, edit, enable, disable, rotate, pair and remove trusts with other Kerberos realms. |
| `/admin/users?user=<name>` | **Directory → Users**, then the person | **Reset password and download keytab**; **Require MFA for this person**; **Never delegate this person**. |
| `/admin/applications?application=<SPN@REALM>` | **Directory → Applications**, then the service | The **Configuration** tab: delegation lists on **Every protocol** (*Delegation / Impersonation*), Kerberos fields on **Kerberos v5**; required roles on the **Roles** tab. |
| `/admin/delegation` | the delegation register | Every delegation act, refusals included, and the published policy. |
| `/admin/scheduler` | **Monitoring → Scheduler** | The `krb5.krbtgt-rotate` and `krb5.krbtgt-rotate-now` jobs. |
| `/portal/kerberos` | the user portal | A person makes a keytab from their own password. |

The Management API equivalents are `GET /admin-api/kerberos` (settings and
status), `GET /admin-api/kerberos/principals`, `POST
/admin-api/kerberos/principals/{action}`, `GET /admin-api/kerberos/trusts`,
`POST /admin-api/kerberos/trusts/{action}`, and `GET` / `POST
/admin-api/kerberos/claims`. Every request and response body is in
`/admin-api/openapi.json`.

**Settings, and which can change at runtime.** Most `krb5.*` settings are
restart-only for the service as a whole, because the default realm's
principal database is built from them when the process starts. A
restart-only setting is refused by `config/set`, so set it in the
environment (`KRB5_REALM`, `KRB5_SERVICE_PRINCIPAL`, `KRB5_ENCTYPES` and so
on) or an appconfig file, and restart. A [trust realm](trust-realms.md) is
different: it builds its database when its Kerberos is turned on, so it can
carry `krb5.realm`, `krb5.servicePrincipal`, `krb5.enctypes` and the other
key-shaping settings as realm settings. The
[configuration table](kerberos.md#configuration) says which settings are
runtime.

## What development and product mode change

The two modes (`global.mode`) need different things filled in:

* **Who can get a ticket.** Development mode creates any user name on first
  sight and keys every user from one published password, `krb5.userPassword`
  (`password!`). Product mode creates nobody: a person must exist in the
  directory, and their keys are derived from their own password when it is
  set or a sign-in verifies it. So in product mode every recipe below starts
  by creating the person with a password.
* **Service principals.** Development mode creates a service principal on
  demand for any host in `krb5.serviceDomains` (by default the realm's
  domain, `localhost`, `sts` and `127.0.0.1`). Product mode creates none: make
  each one with **Create and show the keytab**
  (`kerberos/principals/create-service`).
* **The acceptor's key.** In development the SPNEGO acceptor is keyed from
  `krb5.servicePassword`. In product the published default is refused; unless
  you set a password of your own, the service gives `krb5.servicePrincipal` a
  random key and keeps it sealed.
* **The `krbtgt` key.** Development derives it from `krb5.krbtgtPassword`.
  Product keys it at random and rotates it every
  `krb5.krbtgtRotationIntervalDays` (180).
* **rc4-hmac (23)** is used in development only. Product reads
  `krb5.enctypes` without it and refuses a write that names it.
* **A password alone**, for a person who holds or must hold a second factor,
  gets a ticket in development and `KDC_ERR_POLICY` in product. Such a person
  uses FAST with OTP, or PKINIT.
* **Fixtures.** Development seeds alice, bob, misconfigured accounts,
  delegation services and a trust with `PARTNER.COM`. Product seeds none of
  them.

---

## Point a client at the KDC

The KDC answers on TCP and UDP port `krb5.kdcPort` (88), and over HTTPS at
`/KdcProxy` (MS-KKDCP). `docker-compose.yml` publishes 88 on both protocols
(`STS_KDC_HOST_PORT` moves it). The `krb5.conf` here is the one
`sts_kerberos_keytab.js` and `sts_kerberos_fast_otp.js` write for MIT
Kerberos:

```ini
# /tmp/sts-krb5.conf
[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1
  rdns = false
[realms]
  EXAMPLE.COM = {
    kdc = localhost:88
  }
```

```bash
export KRB5_CONFIG=/tmp/sts-krb5.conf KRB5CCNAME=FILE:/tmp/sts-krb5cc
kinit alice@EXAMPLE.COM
klist
```

* `EXAMPLE.COM` is `krb5.realm`. The jobs read it from `GET
  /admin-api/config` rather than assuming it.
* `udp_preference_limit = 1` makes MIT use TCP. UDP works too; a reply
  larger than `krb5.udpMaxReplyBytes` (1465) is answered
  `KRB_ERR_RESPONSE_TOO_BIG` and the client retries over TCP.
* `rdns = false` stops MIT replacing a host name with its reverse lookup
  before it asks for a service ticket.
* In development, `alice`'s password is `krb5.userPassword`. In product it is
  the password on her directory entry.

**Over MS-KKDCP.** `sts_kerberos_spnego.js` runs the same AS exchange at
`POST /KdcProxy` and checks that it agrees with TCP 88. It drives the proxy
with its own client. With MIT Kerberos and its `k5tls` plugin, the realm's
`kdc` line becomes `kdc = https://localhost:8081/KdcProxy`, with the
service's certificate in `http_anchors`; no job here runs that line.
`/realm/<id>/KdcProxy` is pinned to one trust realm (see
[A KDC per trust realm](#a-kdc-per-trust-realm)).

## A person as a principal

Taken from `sts_kerberos_spnego.js`.

A person's principal is their user name in the realm: `alice` is
`alice@EXAMPLE.COM`. There is no separate Kerberos account to create.

**Console:**
1. On **Directory → Users**, create the person with a password.
2. In product mode, that password is now their Kerberos password. Their keys
   appear on **Protocols → Kerberos → Principals**, under **People**, a moment
   later.

**API:**
```bash
api users/create '{"username":"alice","invent":false,"credential":"password",
  "password":"Krb5-Spnego-Passw0rd!-123456",
  "attributes":{"cn":"Alice","givenName":"Alice","sn":"Example",
                "mail":"alice@example.com"}}'
```

* **The keys lag the password by a moment** in product mode. Until they are
  stored the KDC refuses the person `KDC_ERR_C_PRINCIPAL_UNKNOWN` with the
  e-text *this principal has no Kerberos keys yet*. The jobs wait up to 20
  seconds for them.
* **A person who had a password before keys were stored** gets them at their
  next verified sign-in anywhere, for example at `/authn/login`.
* **A password change** moves the kvno up by one. A ticket sealed under the
  previous key is still accepted for `krb5.retainedKeyTtlS`, but the old
  password no longer signs in.
* **Clear the keys** on the person's row (API
  `kerberos/principals/clear-person-keys` with `{"username":"alice"}`) removes
  them; the next verified sign-in derives new ones.
* `krb5.personKeys` off makes the KDC refuse every person. It is for a
  deployment that uses this service only as an acceptor.

## A person's keytab

Taken from `sts_kerberos_keytab.js`.

A person's keytab is always derived from a password in hand. There are two
ways to get one.

**The person, on the portal:** on `/portal/kerberos`, under **Download a
keytab**, they type **Your current password** and click **Make and download a
keytab**. Nothing about their account changes.

**An administrator** resets the person's password and gets the keytab derived
from it. **This changes their password everywhere and signs them out.**

**Console:**
1. On **Directory → Users**, open the person.
2. Under **Reset password and download keytab**, type a **New password**, or
   tick **or a generated one that is never shown**.
3. Click **Reset password and download keytab**, then **Save** the file the
   page shows. It is shown once.

**API:**
```bash
api kerberos/principals/reset-person-keytab \
  '{"username":"alice","password":"Keytab-Reset-Passw0rd!-123456"}' |
  jq -r .keytab | base64 -d > alice.keytab

# or with a password nobody is shown
api kerberos/principals/reset-person-keytab '{"username":"alice","random":true}' |
  jq -r .keytab | base64 -d > alice.keytab
```

```bash
klist -k -e alice.keytab
kinit -k -t alice.keytab alice@EXAMPLE.COM
```

* The keytab holds the current kvno only, one entry per enctype.
* In development every user is keyed from `krb5.userPassword`, so the keytab
  holds that key and the reply says `"source": "development"`.
* Giving both `password` and `random`, or neither, is refused with 400.

## A service principal and its keytab

Taken from `sts_kerberos_delegation.js`, `sts_kerberos_fast_otp.js` and
`sts_kerberos_krbtgt_rotation.js`.

A service principal gets a random key for every enctype in `krb5.enctypes`,
stored sealed on the application entry `<SPN>@<REALM>`. Its keytab is
handed over once, by the act that made the key.

**Console:**
1. On **Protocols → Kerberos → Principals**, under **Create a service
   principal**, enter the **SPN**, for example `HTTP/app.example.com`.
2. Click **Create and show the keytab**, then **Save** the file. It cannot be
   downloaded again.

**API:**
```bash
api kerberos/principals/create-service '{"spn":"HTTP/app.example.com"}' |
  jq -r .keytab | base64 -d > app.keytab
```

The SPN may carry `@EXAMPLE.COM` or not. It is refused when it already holds
a key, when it is `krbtgt/…`, when it names another realm, and when it is not
two or more `/`-separated parts. The service then uses the keytab as any
Kerberos service does; a host principal (`host/ws1.example.com`) is made the
same way and used with `kinit -k -t`.

**Later acts on the same row** (each takes `{"spn": …}`):

| Console | API | What it does |
|---|---|---|
| **Rotate and show the keytab** | `kerberos/principals/rotate-service` | New keys at the next kvno. The keytab carries the kept previous version too (`keytabKvnos`). |
| **Drop previous versions** | `kerberos/principals/drop-previous-service-keys` | Stops accepting tickets under kept versions now, for example after a keytab leaks. |
| **Delete the key** | `kerberos/principals/delete-service` | Removes the stored key. The application entry stays. |

How long a previous version is kept is `krb5.retainedKeyVersions` (1) and
`krb5.retainedKeyTtlS` (0, meaning the ticket lifetime plus the clock skew).

**The acceptor's own SPN.** `/authn/spnego` accepts tickets for
`krb5.servicePrincipal`. If you create that SPN here, the acceptor uses the
stored key in place of `krb5.servicePassword`.

## Encryption types

Taken from `sts_kerberos_rc4.js`.

`krb5.enctypes` lists the RFC 3961 numbers used, strongest first. The
default is `18,17,20,19,23`. 23 (rc4-hmac) is used in development only.

**For the service as a whole** it is restart-only: set `KRB5_ENCTYPES` and
restart.

```bash
KRB5_ENCTYPES=18,20
```

**For a trust realm** it can be changed at runtime. On that realm's
**Protocols → Kerberos → Global settings**, edit **Encryption types** and
click **Save Kerberos**. Through the API:

```bash
api realms/set '{"id":"r1","key":"krb5.enctypes","value":"18,20"}'
```

In a product realm `18,23` is refused, naming the setting; `18,20` is
accepted. In a development realm `18,23` is accepted. The value in force is
on `GET /admin-api/mode`, which lists `krb5.enctypes` with 23 dropped in
product.

The job's MIT client restricts itself to RC4 with these `[libdefaults]`
lines, to see the refusal in product and a TGT in development:

```ini
  permitted_enctypes = rc4-hmac
  default_tkt_enctypes = rc4-hmac
```

## A KDC per trust realm

Taken from `sts_kerberos_krbtgt_rotation.js` and `sts_kerberos_trusts_api.js`.

Every trust realm can answer as a Kerberos realm of its own, on the same port
88. Port 88 routes each request by the Kerberos realm name inside it. A
realm is created with Kerberos off, and turning it on is refused until it has
a `krb5.realm` that no other realm uses.

**Console:**
1. Create the realm on `/admin/realms` (see [Trust realms](trust-realms.md)),
   and switch to it.
2. On **Protocols → Kerberos → Global settings**, set **Realm** to
   `R1.EXAMPLE.NET` and click **Save Kerberos**.
3. Tick **Enable Kerberos** and click **Save Kerberos** again.

**API:** both settings at creation, in one call:
```bash
api realms/create '{"id":"r1","domain":"r1.example.net","name":"r1",
  "overrides":{"krb5.enabled":true,"krb5.realm":"R1.EXAMPLE.NET"}}'
```

The jobs name the Kerberos realm after the realm's domain in upper case.
Every principal in the realm follows its domain: the acceptor defaults to
`HTTP/web.r1.example.net`, and a person `bob` there is `bob@R1.EXAMPLE.NET`.

To act in that realm, put its prefix in `BASE`:

```bash
BASE=https://localhost:8081/realm/r1
api users/create '{"username":"bob","invent":false,"credential":"password",
  "password":"Krbtgt-Rotation-Passw0rd!-123456",
  "attributes":{"cn":"Bob","givenName":"Bob","sn":"Example","mail":"bob@r1.example.net"}}'
api kerberos/principals/create-service '{"spn":"HTTP/app.r1.example.net"}'
```

A client lists the realm beside the default one, both at the same KDC
address, as `sts_kerberos_heimdal.js` does:

```ini
[realms]
  EXAMPLE.COM = {
    kdc = localhost:88
  }
  R1.EXAMPLE.NET = {
    kdc = localhost:88
  }
```

`/realm/r1/KdcProxy` answers only for `R1.EXAMPLE.NET` and refuses another
realm's name with `KDC_ERR_WRONG_REALM`. A bare `/KdcProxy` routes by name,
like port 88. Renaming `krb5.realm` while the realm's Kerberos is on is
refused, because every key is salted with it.

## FAST armor and a second factor (OTP)

Taken from `sts_kerberos_fast_otp.js`.

In product mode, a person who holds an authenticator app, or of whom a second
factor is required, gets no ticket on a password alone. They use FAST armor
(RFC 6113) with OTP pre-authentication (RFC 6560): the authenticator code,
with their password as the PIN. No setting is needed; FAST is always offered.

**1. A host principal for the armor ticket.** The armor is a TGT the client
host gets with its own keytab. Make the host a service principal
([above](#a-service-principal-and-its-keytab)):

```bash
api kerberos/principals/create-service '{"spn":"host/ws1.example.com"}' |
  jq -r .keytab | base64 -d > host.keytab
```

**2. The person's authenticator app.** The person enrols one on the portal's
MFA page, `/portal/mfa`. An administrator can require a second factor of them with
**Require MFA for this person** on their page under **Directory → Users**
(API `users/require-mfa` with `{"user":"alice"}`).

**3. The client**, with MIT Kerberos:

```bash
kinit -k -t host.keytab -c FILE:/tmp/armor host/ws1.example.com@EXAMPLE.COM
kinit -T FILE:/tmp/armor alice@EXAMPLE.COM
# Enter OTP Token Value: <the six digits>
# OTP Token PIN: <alice's password>
```

* MIT asks for the code first and the PIN second.
* A code is used once. The same code again is refused, and a code already
  spent at the sign-in screen is refused at the KDC.
* The ticket carries the RFC 8129 indicator `otp`, so
  [`/authn/spnego`](#spnego-sign-in-at-authnspnego) makes the session two
  factors (`amr` `["pwd","otp"]`).
* In development, `kinit alice@EXAMPLE.COM` with the password alone still
  gets a TGT. In product it is refused with *KDC policy rejects request*.

Heimdal's client has no OTP; `sts_kerberos_heimdal.js` checks only that its
password-alone request is refused inside FAST in product.

## PKINIT: a certificate as the pre-authentication

Taken from `sts_kerberos_pkinit.js`.

PKINIT (RFC 4556) is on in every realm (`krb5.pkinit`). It is how a person
whose second factor is a security key or smart card gets a ticket in product
mode. The certificate must be one this realm issued to the person, with
PKINIT client authentication or smart-card logon in its extended key usage.

**1. The certificate.** The job enrols a smart-card logon certificate over
EST with the person's own password. Using `openssl` and `curl`:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout alice.key -outform DER -out alice.csr -subj /CN=alice
base64 alice.csr > alice.csr.b64
curl -sk -u 'alice:<her password>' -H 'Content-Type: application/pkcs10' \
  --data-binary @alice.csr.b64 \
  https://localhost:8081/.well-known/est/smartcard-logon/simpleenroll |
  base64 -d | openssl pkcs7 -inform DER -print_certs > alice.pem
```

The subject in the request is only a label: the certificate is named from
the person's directory entry. ACME and SCEP can issue the same profile; see [EST](est.md),
[ACME](acme.md) and [SCEP](scep.md).

**2. The anchors.** `GET /.well-known/est/cacerts` answers three
certificates: the EST Issuing CA, the realm's Intermediate, and the service
Root. The Root is MIT's `pkinit_anchors`; the other two are `pkinit_pool`.
The job's `krb5.conf`:

```ini
[realms]
  EXAMPLE.COM = {
    kdc = localhost:88
    pkinit_anchors = FILE:/tmp/sts/root.pem
    pkinit_pool = FILE:/tmp/sts/pool.pem
  }
```

**3. The client**, with MIT Kerberos and its PKINIT plugin
(`krb5-pkinit`):

```bash
kinit -X X509_user_identity=FILE:alice.pem,alice.key alice@EXAMPLE.COM
klist -f      # flags include H: hardware authenticated
```

A certificate issued to somebody else is refused *Client name mismatch*.

**Anonymous PKINIT** (RFC 8062, `krb5.anonymousPkinit`, on by default) gives
a machine with no host keytab FAST armor:

```bash
kinit -n -c FILE:/tmp/armor @EXAMPLE.COM
kinit -T FILE:/tmp/armor bob@EXAMPLE.COM
```

**The settings to leave alone.** `krb5.pkinitRequireFreshness` (on) and
`krb5.pkinitLegacyKdf` (off) are the safe values. Change them only for a
client too old to work otherwise. `krb5.pkinitKdcKeyAlgorithm` (`ec-p256`)
is the key the KDC signs its replies with.

`GET /admin-api/kerberos` answers `status.pkinit`, which says whether PKINIT,
anonymous PKINIT and the freshness token are on. **Protocols → Kerberos →
Global settings** shows the same status above the settings.

## Delegation: S4U2Self, S4U2Proxy, RBCD and forwarded TGTs

Taken from `sts_kerberos_delegation.js`.

A Kerberos service is the application entry `<SPN>@<REALM>` that
`create-service` makes. Who may delegate to whom is set on those entries, and
the same delegation policy decides WS-Trust and the OAuth 2.0 token exchange
([Delegation and impersonation](delegation.md)). The rules are enforced in
both modes.

The job makes five services with `create-service` and sets:

| Service | Attribute | Value | Active Directory equivalent |
|---|---|---|---|
| `HTTP/kd-front.example.com` | `appAllowedToDelegateTo` (add) | `HTTP/kd-back.example.com@EXAMPLE.COM` | `msDS-AllowedToDelegateTo` |
| `HTTP/kd-front.example.com` | `appDelegationSemantics` (add) | `delegation`, then `impersonation` | `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` |
| `HTTP/kd-notrusted.example.com` | `appAllowedToDelegateTo` (add) | `HTTP/kd-back.example.com@EXAMPLE.COM` | the same, without protocol transition |
| `HTTP/kd-rbcd.example.com` | `appAllowedToActOnBehalfOf` (add) | `HTTP/kd-front.example.com@EXAMPLE.COM` | `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `HTTP/kd-trusted.example.com` | `krb5TrustedForDelegation` (set) | `TRUE` | `TRUSTED_FOR_DELEGATION` (unconstrained) |

(The job adds a random suffix to each host name.)

**Console:**
1. Make each service on **Protocols → Kerberos → Principals** ([above](#a-service-principal-and-its-keytab)).
2. Open the front end under **Directory → Applications**. On its
   **Configuration** tab, **Every protocol** sub-tab, section *Delegation /
   Impersonation*, add the back end to `appAllowedToDelegateTo` and tick
   `delegation` and `impersonation` in `appDelegationSemantics`. Click the
   sub-tab's **Save**.
3. For resource-based delegation, open the **back end** instead and add the
   front end to `appAllowedToActOnBehalfOf`.
4. For unconstrained delegation, set `krb5TrustedForDelegation` to `TRUE` on
   the **Kerberos v5** sub-tab.

**API:**
```bash
FRONT='HTTP/kd-front.example.com@EXAMPLE.COM'
BACK='HTTP/kd-back.example.com@EXAMPLE.COM'
api applications/add "{\"application\":\"$FRONT\",\"attribute\":\"appAllowedToDelegateTo\",\"value\":\"$BACK\"}"
api applications/add "{\"application\":\"$FRONT\",\"attribute\":\"appDelegationSemantics\",\"value\":\"delegation\"}"
api applications/add "{\"application\":\"$FRONT\",\"attribute\":\"appDelegationSemantics\",\"value\":\"impersonation\"}"
api applications/add '{"application":"HTTP/kd-rbcd.example.com@EXAMPLE.COM",
  "attribute":"appAllowedToActOnBehalfOf","value":"HTTP/kd-front.example.com@EXAMPLE.COM"}'
api applications/set '{"application":"HTTP/kd-trusted.example.com@EXAMPLE.COM",
  "attribute":"krb5TrustedForDelegation","value":"TRUE"}'
```

**A protected person.** **Never delegate this person** on their page
(`stsNotDelegated`) is Active Directory's `NOT_DELEGATED`:

```bash
api users/set-not-delegated '{"user":"carol","value":true}'
```

What the job then sees:

* **S4U2Self** by the front end is forwardable, because it allows
  `impersonation`. By `kd-notrusted` it is issued but not forwardable, and
  classic S4U2Proxy then fails on that evidence. For a protected person it is
  never forwardable.
* **Classic S4U2Proxy** reaches the back end the front end names, and is
  refused for any other.
* **Resource-based S4U2Proxy** to `kd-rbcd` needs `PA-PAC-OPTIONS` with the
  RBCD bit from the client, as [MS-SFU] requires.
* **Unconstrained:** only `kd-trusted`'s tickets carry `ok-as-delegate`, which
  tells a client it may forward its TGT there. A protected person's TGT is
  never forwardable.
* Every act, issued or refused, appears on `/admin/delegation` and `GET
  /admin-api/delegation`. A refusal names the attribute in its e-text.

The job drives these exchanges with its own client. With MIT Kerberos, the
front end gets a TGT from its keytab and `kvno -U <user> -P <back-end SPN>`
asks for both S4U steps; no job here runs that command.

**A role the target requires, under S4U.** When a service's entry requires a
role (`appRequiredRole`), the KDC asks whether the ticket's subject holds it
before issuing, and refuses `KDC_ERR_POLICY` (`STS-KRB-0039`) otherwise.
Under S4U2Self and S4U2Proxy (classic or resource-based) there are two
candidate subjects, and `krb5.s4uRoleSubject` chooses:

| Value | Who must hold the role |
|---|---|
| `service` (default) | the service that asks — the front end, whose TGT is presented |
| `user` | the person the ticket is for — the PA-FOR-USER user, or the evidence ticket's client |

[MS-SFU] decides only whether the front end may impersonate or delegate, not
whose roles an extra check like this one reads, so this is a setting, and the
default keeps the behaviour the KDC had. A person who came across a trust is
asked about as `user@REALM`, with the SIDs their PAC carried after
filtering. An ordinary TGS request has one subject and is not affected.
Per realm, at runtime, on **Protocols → Kerberos → Global settings**
(**Whose role a service requires under S4U**), or:

```bash
api realms/set '{"id":"r1","key":"krb5.s4uRoleSubject","value":"user"}'
```

## A trust between two realms of this service

Taken from `sts_kerberos_trusts_api.js` (#430).

Two trust realms of this service trust each other's Kerberos only through a
trust record on each side. Create both realms with Kerberos on
([above](#a-kdc-per-trust-realm)):

```bash
api realms/create '{"id":"trusta","domain":"trusta.example.net","name":"trusta",
  "overrides":{"krb5.enabled":true,"krb5.realm":"TRUSTA.EXAMPLE.NET"}}'
api realms/create '{"id":"trustb","domain":"trustb.example.net","name":"trustb",
  "overrides":{"krb5.enabled":true,"krb5.realm":"TRUSTB.EXAMPLE.NET"}}'
```

**Console**, in realm `trusta`:
1. On **Protocols → Kerberos → Trusts**, under **Add a trust**: **Partner
   realm** `TRUSTB.EXAMPLE.NET`, **Type** *Trust realm here*, **Trust realm
   (for a trust realm here)** `trustb`, **Direction** *Both ways*, **Key source** *Trust password* and a
   **Trust password** of at least 16 characters. Leave `quarantined` ticked.
   Set **Routed DNS suffixes** to `trustb.example.net`.
2. Click **Add the trust**. Its **Health** says that `trustb` holds no
   matching record.
3. Click **Pair** on the row. That writes `trustb`'s record for `trusta` in
   the same act.

**API:**
```bash
BASE=https://localhost:8081/realm/trusta
api kerberos/trusts/add '{"partnerRealm":"TRUSTB.EXAMPLE.NET","type":"trust-realm",
  "partnerTrustRealm":"trustb","direction":"bidirectional",
  "keySource":"password","password":"Trust-Passw0rd-12345678-shared-between-two-realms",
  "attributes":["quarantined"],"suffixes":["trustb.example.net"]}'
api kerberos/trusts/pair '{"partnerRealm":"TRUSTB.EXAMPLE.NET"}'
get 'kerberos/trusts?trust=TRUSTB.EXAMPLE.NET'
```

Both records then hold both keys at kvno 1. **Pair** and a mirrored rotation
write the other realm's directory, so they need a service administrator, not
a realm's own administrator. `pair` with `otherRealm` (a realm id) in place
of `partnerRealm` writes both records from nothing; its body is in
`/admin-api/openapi.json`.

**With a KDC elsewhere** (MIT, Heimdal or Active Directory), use **Type**
*External KDC* (`"type":"external"`), and give the partner's administrator
the same trust password, or the keys a `"keySource":"generate"` shows once
in `shown`.

**What the trust attributes mean** is on
[Kerberos trusts](kerberos.md#kerberos-trusts). A contradiction, such as
`no-tgt-delegation` with `enable-tgt-delegation`, is refused with 400.

**Rotate the trust key.** **Rotate key** on the row, with *Rotate the
partner trust realm's record too* ticked:

```bash
api kerberos/trusts/rotate-key '{"partnerRealm":"TRUSTB.EXAMPLE.NET",
  "keySource":"generate","mirror":true}'
```

Both realms move to kvno 2. The previous incoming key still opens the
partner's tickets for `krb5.trustKeyGraceSeconds` (0, meaning the ticket
lifetime plus the clock skew).

**Disable, enable, remove.**

```bash
BASE=https://localhost:8081/realm/trustb
api kerberos/trusts/disable '{"partnerRealm":"TRUSTA.EXAMPLE.NET"}'   # keys kept
api kerberos/trusts/enable  '{"partnerRealm":"TRUSTA.EXAMPLE.NET"}'
BASE=https://localhost:8081/realm/trusta
api kerberos/trusts/remove '{"partnerRealm":"TRUSTB.EXAMPLE.NET","confirm":"TRUSTB.EXAMPLE.NET"}'
```

`remove` without the partner realm in `confirm` is refused. In the console,
**Remove** asks you to type it.

### Letting the partner's people reach a service

A principal that arrived through a trust holds **none of the built-in roles**:
`EVERYBODY` means authenticated in this realm. So a service that requires
only `EVERYBODY`, the default, refuses everybody from the other realm with
`KDC_ERR_POLICY`. To admit them, grant a role (`/admin/roles`; see
[XACML](xacml.md#the-embedded-peps-this-services-own-issuance-and-access))
to their whole
name (`alice@TRUSTA.EXAMPLE.NET`) or to a SID their PAC carries, such as the
partner's Domain Users (`<partner domain SID>-513`). Then make the service
require `EVERYBODY` or that role (`appRequiredRole`, the application's
**Roles** tab).

The in-process job `kerberos_cross_realm_delegation.js` does this with a role
named `trust-partners` (a name it invented), granted to each partner's
`-513` and `-515` SIDs, and sets the requirement on the service's entry,
`HTTP/web.beta.test@BETA.TEST` — the name `create-service` gives it. An entry
named by the bare SPN, `HTTP/web.beta.test`, is read first if you made one,
so set the requirement on whichever of the two the service has.

### Delegation across the trust

Taken from `sts_kerberos_trusts_api.js` (the settings) and
`kerberos_cross_realm_delegation.js` (the exchanges, in process).

* **Resource-based delegation crosses a trust with no setting.** On the back
  end in `trustb`, name the front end of `trusta` with its realm:

  ```bash
  BASE=https://localhost:8081/realm/trustb
  api applications/create '{"identifier":"HTTP/back.trustb.example.net@TRUSTB.EXAMPLE.NET",
    "name":"back end","protocols":["krb5"],
    "fields":{"krb5ServicePrincipalName":["HTTP/back.trustb.example.net"],
              "appAllowedToActOnBehalfOf":["HTTP/front.trusta.example.net@TRUSTA.EXAMPLE.NET"],
              "krb5S4uSelfRealm":["TRUSTA.EXAMPLE.NET"]}}'
  ```

  The application's **Kerberos v5** sub-tab then has an *Across trusts*
  section saying whether each foreign front end has a usable trust path. The
  API answers the same in `page.krb5Across` of `GET
  /admin-api/applications?application=…`.
* **S4U2Self for a user of another realm** needs that realm in the service's
  `krb5S4uSelfRealm`, and a trust that accepts it.
* **Classic constrained delegation** (`appAllowedToDelegateTo`) crosses a
  trust only while `krb5.crossRealmClassicDelegation` is on in **both**
  realms. It is off by default.
* **A TGT delegated across a trust** follows the trust's attributes:
  `within-forest` or `enable-tgt-delegation` allow it; `no-tgt-delegation` or
  `quarantined` refuse it. `krb5ForeignTgtDelegation` set to `deny` on the
  target refuses it whatever the trust says.
* **In product mode** a trust that is not `quarantined` is not used while
  `krb5.requireSidFilteringInProduct` is on (the default).

## Rotate the krbtgt key

Taken from `sts_kerberos_krbtgt_rotation.js`.

The job works in a throwaway realm, because an invalidation ends every TGT in
the realm it runs in. In product mode the key also rotates on its own every
`krb5.krbtgtRotationIntervalDays` (180; 0 is off).

**Console:** on **Protocols → Kerberos → Principals**, the block **The
krbtgt key** shows its kvno, last and next rotation and kept versions.
1. **Rotate the krbtgt key** makes a new key at the next kvno and keeps the
   current one, so every existing TGT goes on working until it expires.
2. **Rotate and invalidate**, after typing `invalidate`, keeps nothing: every
   TGT in the realm is refused `KRB_AP_ERR_BADKEYVER` at its next use. Use it
   for a key you believe is compromised.

Both need **Admin Write**.

**API:**
```bash
BASE=https://localhost:8081/realm/r1
api kerberos/principals/rotate-krbtgt '{}'
api kerberos/principals/rotate-krbtgt-invalidate '{"confirm":"invalidate"}'
get kerberos/principals          # the krbtgt block: kvno, retained, lastRotatedAt
```

* Both acts are **queued** on the scheduler (`krb5.krbtgt-rotate-now`) and
  answer `queued` and a `runId`. The kvno changes once the scheduler's leader
  has run it, normally within a scheduler tick; the job waits up to two
  minutes.
* `rotate-krbtgt-invalidate` without `"confirm":"invalidate"` is refused with
  400.
* An invalidation, or an ordinary rotation while `krb5.retainedKeyVersions`
  is 0, sends the Shared Signals event
  `urn:iya:sts:secevent:event-type:kerberos-tickets-invalidated`.
* **Drop previous versions** (`drop-previous-service-keys` with
  `{"spn":"krbtgt/R1.EXAMPLE.NET"}`) ends a rotation's window early.
* **Monitoring → Scheduler** lists `krb5.krbtgt-rotate` (off in development,
  on in product) and `krb5.krbtgt-rotate-now`.

## PAC claims

Taken from `sts_kerberos_pac_claims.js`.

While `krb5.pacClaims` is on (off by default), every ticket's PAC carries the
client's claims ([MS-PAC] 2.11), which Windows' claims-based access control
reads. The job turns it on in a new realm:

```bash
api realms/create '{"id":"pac1","domain":"pac1.example.net","name":"pac1",
  "overrides":{"krb5.enabled":true,"krb5.realm":"PAC1.EXAMPLE.NET","krb5.pacClaims":true}}'
```

**Console:** in that realm, on **Protocols → Kerberos → PAC claims**, add the
rows of the realm's claim set, and tick the directory attributes to send. To
give one service a row of its own, create it with `create-service` first,
then use **PAC claims** on that application's **Configuration** tab.

**API:**
```bash
BASE=https://localhost:8081/realm/pac1
api kerberos/claims/replace '{"set":"kerberos-pac","claims":[
  {"name":"department","type":"string","value":"Sales"},
  {"name":"level","type":"int64","value":"-7"},
  {"name":"who","type":"string","value":"${username}"},
  {"name":"mailclaim","type":"string","attribute":"mail"}]}'
api kerberos/claims/attributes '{"set":"kerberos-pac","attributes":["ou","title"]}'
api applications/set-custom-claim '{"application":"HTTP/own.pac1.example.net@PAC1.EXAMPLE.NET",
  "set":"kerberos-pac","name":"department","type":"string","value":"Own team"}'
get 'kerberos/claims?user=bob'      # the claim ids, and what bob's TGT would carry
```

* A claim's `type` is `string`, `int64`, `uint64` or `boolean`.
* Each claim's id, `ad://ext/<name>:<16 hex digits>`, is in the `GET`
  answer. It is the same on every node and in every realm.
* A service ticket carries its TGT's claims, with the service's own rows
  added and winning by name.
* `krb5.pacClaims` off on the realm: the next ticket has a PAC and no claims.

## SPNEGO sign-in at `/authn/spnego`

Taken from `sts_kerberos_spnego.js` and `sts_kerberos_heimdal.js`.

`/authn/spnego` turns a Kerberos ticket into a browser session. It is on by
default (`krb5.spnegoAuthentication`), and `/authn/login` offers **Sign in
with Kerberos** (`krb5.spnegoLoginButton`). With
`krb5.spnegoAuthentication` off the endpoint answers 403 naming the setting.

**The acceptor's SPN.** A client asks for `HTTP/<the host in the URL>`, so
`krb5.servicePrincipal` must match the name people use to reach the service.
`docker-compose.yml` sets `KRB5_SERVICE_PRINCIPAL=HTTP/localhost`. Reach it
by another name and set `KRB5_SERVICE_PRINCIPAL=HTTP/<that name>` (it is
restart-only). The first `401 Negotiate` answer carries the SPN in
`X-Krb5-Service-Principal`, and the job reads it from there.

In a trust realm, `sts_kerberos_heimdal.js` sets it at creation and, in
product mode, gives it a key:

```bash
api realms/create '{"id":"spn1","domain":"spn1.example.net","name":"spn1",
  "overrides":{"krb5.enabled":true,"krb5.realm":"SPN1.EXAMPLE.NET",
               "krb5.servicePrincipal":"HTTP/sts.example.com"}}'
BASE=https://localhost:8081/realm/spn1
api kerberos/principals/create-service '{"spn":"HTTP/sts.example.com"}'   # product mode
```

Here `sts.example.com` stands for the host in the service's URL. The
client's `krb5.conf` maps that host to the realm:

```ini
[domain_realm]
  sts.example.com = SPN1.EXAMPLE.NET
```

**From a terminal:**
```bash
kinit dave@SPN1.EXAMPLE.NET
curl --negotiate -u : --cacert sts.pem https://sts.example.com:8081/realm/spn1/authn/spnego
```

A good ticket answers 200, a `sts_session` cookie and an AP-REP in
`WWW-Authenticate` (mutual authentication). The session's `amr` comes from
the ticket's flags: `pwd` for a pre-authenticated ticket, `pwd` and `otp`
after [FAST with OTP](#fast-armor-and-a-second-factor-otp). The session is
listed on `/admin-api/sessions`.

**From a browser**, the browser must be allowed to use Kerberos for the host:
Chrome's `--auth-server-allowlist` (the `AuthServerAllowlist` policy), or
Firefox's `network.negotiate-auth.trusted-uris`.
[Signing in from a browser on the base installation](kerberos.md#signing-in-from-a-browser-on-the-base-installation)
walks through it.

**Only Kerberos for one application.** To send an application's people
straight to `/authn/spnego` without the sign-in screen, make `spnego` its
only allowed mechanism:

* **Console:** on the application's **Configuration** tab, **Every
  protocol** sub-tab, tick `spnego` in `appAuthnMechanism` and **Save**.
* **API:**
  ```bash
  api applications/add '{"application":"my-app","attribute":"appAuthnMechanism","value":"spnego"}'
  ```

This is enforced at every browser sign-in to that application, in both
modes (`authn_mechanism_enforcement.js`). Listing several mechanisms draws
the sign-in screen with only those offered. A federation relationship does
the same with `fedAuthnMechanism: spnego` ([Federation](federation.md)).

**What `/authn/spnego` refuses**, as the job asserts: a replayed
Authenticator (`KRB_AP_ERR_REPEAT`, across a cluster too), a TGT presented
as a service ticket (`KRB_AP_ERR_NOT_US`), a tampered Authenticator, and one
outside `krb5.clockSkew` (`KRB_AP_ERR_SKEW`). None of these starts a session.

## Related

* [Kerberos, KKDCP and SPNEGO](kerberos.md): the protocol in depth, and every
  setting.
* [Delegation and impersonation](delegation.md) and [Trust realms](trust-realms.md).
* [Authentication](authentication.md), [Sessions](sessions.md) and
  [Signing out](signing-out.md): a sign-out also stops older Kerberos TGTs
  (`logout.kerberosSignOut`).
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md) and
  [Configuring SAML profiles](configure-saml.md).
