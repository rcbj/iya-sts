---
title: Remote PEP
nav_order: 15
---

# The remote Policy Enforcement Point

`xacml-pep/` is a **second container**. It holds its own copy of this service's
XACML engine, **pulls** the policy repository from this service's Policy Decision
Point, and decides in its own process. The service never sees the requests it
decides.

It is the one directory in this repository that is not part of the service, and it
is opt-in: a plain `docker compose up` does not start it.

```
   your client                xacml-pep                     iya-sts
                          (the PEP: engine                (the PDP, the PAP,
                           + pulled policy)                and the PIP)

  GET /protected  ──────────▶  decides HERE
                               200 / 403
                                    │
                                    ├── GET  /xacml/pep/policies ──▶  pull, every 15s
                                    ├── GET  /xacml/pep/authzen-catalogue ▶ beside it
                                    ├── GET  /xacml/pep/authzen-callers ──▶ and after it
                                    ├── POST /xacml/pip ───────────▶  attributes, per decision
                                    ├── POST /xacml/pep/register ──▶  a row on the console
                                    ├── POST /xacml/pep/heartbeat ─▶  counters, every 60s
                                    │
                               POST /notify  ◀────────────────────── the nudge (optional)
```

## The demonstration PEP is this one

Until #596 the service had a Policy Enforcement Point of its own at
`GET /xacml/protected`, with its bias in the `xacml.pepBias` setting. Both are
gone: the service ships no demonstration code, and this container's
`GET /protected` is the same thing — the same request built from `subject`,
`resource` and `action`, the same section 7.2 rule (an obligation it cannot
discharge turns a Permit into a 403), and the bias as this PEP's own option,
`PEP_BIAS` (`deny-biased` by default, or `permit-biased`).

It is also the more honest demonstration. A PEP sharing a process with the PDP
can never be stale, can never hold a policy the PDP no longer has, and can
never go on enforcing while the PDP is down. Every one of those is a state a
real deployment lives in, and this container makes all of them reachable — and
reports them rather than hiding them.

## Its four endpoints

| | |
|---|---|
| `GET /` | what this PEP is, what it holds, what it has enforced. **The page to read first when something is wrong** |
| `GET /protected` | the protected resource: 200 or 403, decided here |
| `POST /notify` | the PDP's nudge, meaning *pull now*. Answers 204 and pulls afterwards. **HTTPS only**: over plain HTTP it is a 404 |
| `GET /healthcheck` | liveness. It deliberately does **not** ask whether the policy is current |

They are served over **HTTPS on 9443** once the PEP has been given a
certificate by the realm it registered to, which is the section below — and
over plain HTTP on port 9090 **only when you turn it on** (next section). The HTTPS listener also answers AuthZEN, as an
[edge PDP](#an-authzen-edge-pdp). The container generates no key of its own:
both key pairs it can hold, the client certificate and the listener's, are
handed to it.

## Plain HTTP is off by default

**The PEP binds no plain-HTTP listener unless you ask it to** — neither the
decision API's on 9090 nor the reverse proxy's on 9180. Until #1760 both were
bound whenever the container started. Turn each on with one line in the
container's environment:

| Variable | Default | What it binds |
|---|---|---|
| `PEP_HTTP` | `false` | the decision API (`GET /`, `/protected`, `/healthcheck`, `/crl/<name>`) in plain HTTP on `PEP_PORT` (9090). `POST /notify` is not answered there |
| `PEP_CRL_HTTP` | *(unset)* | with `PEP_HTTP` off, `GET /crl/<name>` alone on `PEP_PORT`. Unset, it is bound when the PEP has a CRL directory to serve; `false` never, `true` always |
| `PEP_PROXY_HTTP` | `false` | the reverse proxy in plain HTTP on `PEP_PROXY_PORT` (9180) |

**The precedence**, highest first:

1. **The switch.** `true` binds the listener and `false` does not. Any other
   value leaves it off and is logged as `STS-XPEP-0107`, since a typo should
   never turn plaintext on.
2. **Unset, the listener is off.** The port variable does not turn it on by
   itself. A container started with `PEP_PORT` (or `PEP_PROXY_PORT`) set and
   no switch was most likely written while plain HTTP was on by default, so it
   logs `STS-XPEP-0106` once at start, naming the line that brings the
   listener back.

**The way back is one line**: `PEP_HTTP=true` (and `PEP_PROXY_HTTP=true` for
the proxy). With the shipped `docker-compose.yml` that is
`XACML_PEP_HTTP=true` and `XACML_PEP_PROXY_HTTP=true` on the host.

**The service's equivalent is a listener, not a setting.** These two listeners
are bound before the PEP has pulled anything, so they belong to its
environment. To serve plain HTTP from the console, define an HTTP listener on
the PEP's Listener tab (*Its listeners*, below). It binds at the next pull,
and in product mode a plain-HTTP proxy listener still needs
`xacml.pepPlainHttpProxyListeners`. Once the PEP reports a listener off, that
listener's port is free, so a defined listener can take 9090.

**What else moved with it:**

* **The image's healthcheck** (`xacml-pep --healthcheck`) asks `/healthcheck`
  over HTTPS on `PEP_HTTPS_PORT`. It does not verify the certificate, because
  it is the container's own loopback and the question is liveness. With
  `PEP_HTTP=true` it asks 9090 as before. A PEP with HTTP off and no HTTPS
  pair yet reports itself unhealthy, which is accurate: it is answering
  nobody.
* **`docker-compose.yml` sets no notify URL.** The PEP derives one from its
  HTTPS listener certificate (*The PEP derives its notify URL*, below): the
  certificate's DNS name that equals the container's hostname, `xacml-pep`.
  `XACML_PEP_NOTIFY_URL` still sets one. The nudge is HTTPS only (*The nudge
  is HTTPS only*, below), and the listener certificate the realm issues
  verifies with nothing set.
* **The CRL point stays up.** A client credential minted with
  `tests/tools/pep-credential.js --crl-base=http://<pep>:9090/crl` names the
  PEP's plain port, and a product-mode service fetches that list under
  hard-fail before it believes the certificate. So with `PEP_HTTP` off the PEP
  still binds `PEP_PORT` for `GET /crl/<name>` and nothing else (anything
  else is a 404, `STS-XPEP-0114`). A CRL is fetched in the clear by convention
  (RFC 5280 section 4.2.1.13): one behind TLS would have to be validated with
  itself. `PEP_CRL_HTTP` switches it (`STS-XPEP-0115` for a value that is
  neither true nor false).
* **The Listener tab** shows `api-http` and `proxy-http` as *off*, together
  with the switch that turns each on, and `api-http` as *listening, CRLs
  only* when the CRL point is bound. A listener the PEP has not reported reads
  *not reported*, never *listening*.
* **The test stacks turn both switches on explicitly**, and
  `docker-compose-run-tests.yml` explains why: the job reaches the PEP before
  it issues the HTTPS pair. The CRL point and the nudge no longer need it.

The examples on this page use `http://localhost:9090` because it is the
shortest form, and they assume `PEP_HTTP=true`. Once the PEP holds its pair,
the same calls work at `https://localhost:9444` with
`--cacert service-root.pem`.

## The quickest look

```bash
XACML_PEP_HTTP=true docker compose --profile xacml up --build

curl -s http://localhost:9090/ | jq '.holding, .registration.why'
```

Without `XACML_PEP_HTTP=true` the PEP has no listener you can read until it
holds an HTTPS pair, and `docker logs xacml-pep` is where it says what it is
doing.

**Out of the box it holds nothing, and that is the honest default rather than a
broken one.** The compose service ships with no client certificate, and the three
`/xacml/pep/*` endpoints require one — so the registration is refused with a 403,
the pull brings back nothing, `loaded` is `false`, and every decision is
`NotApplicable` with the deny bias turning it into a 403:

```json
{
  "loaded": false, "policyCount": 0, "lastPullOk": false,
  "lastPullWhy": "The PDP answered 403: ... it requires REMOTE_PEPS ... NOTHING IS HELD, so there is no policy to enforce: every decision is NotApplicable and the bias decides."
}
```

Generating a certificate inside the image would have meant committing a private
key to this repository. Mount one instead — that is the rest of this page.

## Admitting the PEP: three things, and each is a real check

None of this is a turnstile. A perfectly valid certificate for the wrong common
name is refused while being fully authenticated, because **the certificate says
who and the group says whether**:

1. **A client certificate this service verifies.** The issuing CA goes into the
   truststore, which starts empty: add it at runtime on the admin
   console's `/admin/tls/trust` page (Admin Write) or with
   `POST /admin-api/tls/trust/add` (a token carrying `admin:write`), or put it
   in a PEM file named by `tls.trustAnchorsFile`, read at startup. An anchor
   added at runtime is written to `ou=trustAnchors` in the default realm's
   directory, so it survives a restart wherever the directory is persisted.
2. **That certificate, stored on the PEP's directory entry.** The leaf is
   stored byte for byte in the entry's `userCertificate` — the person page's
   **Stored certificates**, or `POST /admin-api/users/add-certificate` — and
   on no other entry. Its common name and subject are never read. A
   certificate stored on no entry resolves to nobody and is refused
   (`STS-XACML-0179`), and one stored on two entries too (`STS-XACML-0180`).
   A renewed certificate is stored again ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority)).
3. **That entry in the group `roles.remotePepGroup` names** — `remote-peps` by
   default, which is what grants the built-in `REMOTE_PEPS` role.

`cn=remote-pep-1` and `cn=remote-peps` are **seeded in every realm** with the
first already a member of the second, so using that entry costs you steps 1
and 2: the certificate is minted outside this service, so no seed can store
it. A second enforcement point needs its own entry, its stored certificate and
its own membership.
**In development mode.** In product mode the group (named by
`roles.remotePepGroup`) is seeded EMPTY and `cn=remote-pep-1` is not seeded at all —
a predictable identity printed in this repository is not a grant a deployment should
inherit — so every enforcement point needs its entry and its membership.

### The PEP's entry is a service account

The entry a PEP's certificate maps to is a program's identity, not a person's,
so it is a [service account](service-accounts.md). An entry becomes one when it
joins the `remote-peps` group, whichever way it joins: the console's **Add
member**, `POST /admin-api/groups/add-member`, an LDAP modify or a bulk
import. The seeded `cn=remote-pep-1` becomes one when the service starts and
when a realm is created, after the realm's administrators exist. So does any
entry that was already in the group before this release.

- **The owner** is the realm's Admin Write group (`admin.writeGroup`, default
  `admin-write`). A realm without that group is given its bootstrap
  administrator instead. You can add or change owners on the person's
  **Credentials → Service account** tab, as for any service account. An entry
  that was already a service account keeps the owners it has.
- **Nobody to own it.** Suppose a realm has no Admin Write group and no
  bootstrap administrator. Then the entry is not changed, because a service
  account is never made without an owner, STS-SVCACCT-0051 is logged, and it is tried
  again at the next start and the next change to the group.
- **The PEP's connection is unchanged.** Mutual TLS maps the certificate to
  the entry, and the entry's `REMOTE_PEPS` role is checked by the access
  policy. A service account's door rules apply to passwords and browser
  sign-ins only, so they are never asked on this path.
- **A browser sign-in as the entry is refused** (STS-SVCACCT-0010), unless the
  realm's service-account policy allows browser sign-in. Sessions the entry
  already held are ended when it becomes a service account.
- **Nothing rotates.** The entry has no password and names no push
  destination, so the rotation job passes over it.

The PEP's **Overview** tab shows the entry's service-account status and its
owners, with a link to the person's Service account tab.
`GET /admin-api/xacml/peps` carries the same facts as `identityAccount` on
each row.

### Minting the certificate

`tests/tools/pep-credential.js` builds a Root CA, an Issuing CA and a client leaf
on this repository's own PKI code, writes them out, and POSTs the **root alone**
to the service's truststore — so the service has to build a path from what arrives to
an anchor it holds, which is the commonest thing to get wrong in mutual TLS.

```bash
node tests/tools/pep-credential.js \
  --url=https://localhost:8081 \
  --out=/tmp/pep-certs \
  --subject="CN=remote-pep-1,OU=remote-peps,O=iya-sts" \
  --root-subject="CN=remote-pep-1 Root CA,O=iya-sts"
```

**The flags take `=`**; a space between the flag and its value is reported as an
unknown option. The tool posts the root through `POST /admin-api/tls/trust/add`,
so set `STS_ADMIN_API_TOKEN` to a management API token first, and it verifies
the service's certificate on that call, so node must trust the service's Root
(for example through `NODE_EXTRA_CA_CERTS`). It writes `pep.crt` (the leaf **followed by** the issuing CA),
`pep.key`, `ca.crt` and `chain.txt`, and prints the leaf's DN as its last line.

**Then store the leaf on the PEP's entry**, in the realm it will pull from —
the first certificate in `pep.crt`, not the issuing CA after it. The tool
does it when given `--store-on=<username>` (and `--realm=<id>` for a realm
other than the default), through the same API call as by hand:

```bash
openssl x509 -in /tmp/pep-certs/pep.crt -out /tmp/pep-certs/pep-leaf.crt
api users/add-certificate "$(jq -n --rawfile pem /tmp/pep-certs/pep-leaf.crt \
  '{user:"remote-pep-1", certificate:$pem}')"
```

**Give the root a subject of your own** with `--root-subject`, for example
`--root-subject="CN=Example PEP Root CA,O=Example"`. Without it the root is
`CN=iya-sts test Root CA,O=iya-sts tests`, the name the test suite's own roots
carry, and on a reused AWS test environment the suite's reset
(`deploy/aws/reset-environment.js`) removes every runtime trust anchor with
that common name before a run: a PEP whose root kept the default loses its
trust at the next suite run.

Until it is stored, the PEP's certificate verifies and is still refused
(`STS-XACML-0179`). A deployment upgraded from a version that matched the
PEP by its common name stores it **before** the upgrade, or the PEP is cut off
until it does; nothing migrates it.

To hand these to the compose service:

```yaml
volumes:
  - /tmp/pep-certs:/certs:ro
environment:
  - PEP_TLS_CERT=/certs/pep.crt
  - PEP_TLS_KEY=/certs/pep.key
```

## A worked example: an authorization decision for an application

An application is a **resource** to this PEP. What follows protects
`https://expenses.example.test`, lets staff read and write it, and asks the PEP
about two people who differ only in a directory attribute neither of them sends.

### 1. Get a management API token

Everything under `/admin-api` needs an OAuth 2.0 access token audienced to that
API. Pin the seeded client `sts-api-client`'s secret with `adminApi.clientSecret`
(`ADMIN_API_CLIENT_SECRET`) before starting the service, or the secret is minted
per start and readable only through the API it unlocks. On the compose stack
the secret is in OpenBao instead, and any application of your own that holds
the admin roles works here too
([Management API → Getting a token](management-api.md#getting-a-token)).

```bash
TOKEN=$(curl -sk -u sts-api-client:$ADMIN_API_CLIENT_SECRET \
  -X POST https://localhost:8081/oauth2/token \
  -d grant_type=client_credentials -d 'scope=admin:read admin:write' \
  --data-urlencode 'resource=https://localhost:8081/admin-api' \
  | jq -r .access_token)
```

### 2. Deploy the policy at the PAP

The `abac` template takes the resource, the actions, and one subject attribute
to test. Nothing here is XML you have to write.

```bash
curl -sk -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -X POST https://localhost:8081/admin-api/xacml/create-from-template \
  -d '{"template":"abac","name":"expense-app-access",
       "p_resource":"https://expenses.example.test",
       "p_actions":"GET, POST",
       "p_subjectAttribute":"employeeType","p_subjectValue":"staff",
       "p_clearanceAttribute":""}'

# The first policy in an empty repository becomes the root. Otherwise:
curl -sk -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -X POST https://localhost:8081/admin-api/xacml/set-root \
  -d '{"name":"expense-app-access"}'
```

The console does the same thing on the **Policies** tab of **Protocols →
XACML**, with a guided editor on the **Policy editor** tab.

### 3. Start the PEP

```bash
docker compose --profile xacml up --build      # with the volume above
```

or, against a checkout, with no container at all (the PEP is a Rust binary
since 2026-10-05; `cargo` builds it from the `rust/` workspace):

```bash
PEP_PDP_URL=https://localhost:8081 \
PEP_NAME=remote-pep-1 \
PEP_TLS_CERT=/tmp/pep-certs/pep.crt \
PEP_TLS_KEY=/tmp/pep-certs/pep.key \
PEP_TLS_INSECURE=true \
PEP_RESOURCE=https://expenses.example.test \
cargo run --manifest-path rust/Cargo.toml --release -p xacml-pep
```

`PEP_TLS_INSECURE=true` is the ordinary setting against this service in development: in
development mode its listener certificate is issued by a service Root that is
regenerated on every start, so there is no fixed anchor to verify against
(point `PEP_TLS_CA` at the current Root to verify anyway). It is logged on every
start rather than once.

You should see, within a second or two:

```
xacml-pep: Registered over mutual TLS as "remote-pep-1".
xacml-pep: pulled 1 policy(ies), token cfwK-me7DUsHSd01xp-vAiqRiEmlT-2Wk2QVaj2sREU.
```

### 4. Ask it for a decision

**This is the call.** `subject`, `resource` and `action` are the three XACML
ones; the resource is the application.

```bash
curl -s "http://localhost:9090/protected?subject=alice&resource=https://expenses.example.test&action=GET"
```

```json
{
  "decision": "Permit",
  "allowed": true,
  "bias": "deny-biased",
  "why": "The PDP policy said Permit.",
  "status": { "code": "urn:oasis:names:tc:xacml:1.0:status:ok" },
  "obligations": [],
  "advice": [],
  "applicablePolicies": [
    { "kind": "Policy",
      "id": "urn:sts:xacml:policy:expense-app-access",
      "version": "1.0" }
  ],
  "decidedBy": {
    "pep": "remote-pep-1",
    "syncToken": "oo5dHgxDaLWFfjVEyiX0UZzkaSBW0FlKaOYhUZJGMyg",
    "note": "Decided IN THIS PROCESS, against the policy this PEP last pulled. The PDP did not see this request."
  },
  "pip": { "used": true, "subject": "alice", "designators": 1,
           "resolved": 1, "unresolved": [] }
}
```

**HTTP 200 with `allowed: true`, or 403 with `allowed: false`.** The body is the
same shape either way, because a refusal you cannot read is a refusal you cannot
debug.

Note what alice did *not* send. The policy decides on `employeeType`; she
asserted nothing. `"pip": { "used": true, "resolved": 1 }` is the PEP having
asked the PDP's Policy Information Point for the designators the request did not
carry, in one batched query, before evaluating.

### 5. The refusals

With `alice` (`employeeType: staff`) and `carol` (`employeeType: admin`) in the
seeded directory:

| Request | Answer | Why |
|---|---|---|
| `subject=alice&resource=…/expenses…&action=GET` | **200** Permit | staff, and GET is permitted |
| `subject=carol&resource=…/expenses…&action=GET` | **403** Deny | admin is not staff |
| `subject=alice&resource=…/expenses…&action=DELETE` | **403** | DELETE is not in the policy's actions |
| `subject=alice&resource=https://payroll.example.test&action=GET` | **403** | the policy's target selects the other application |
| `subject=nobody-at-all&…` | **403** | no entry, so an empty bag, so no match |

The last four are worth reading together: only the second is a **Deny**. The
others are `NotApplicable` — nothing in the policy applied — and it is the
**deny bias** that turns them into refusals. `why` says which of the two happened
on every answer.

## What the caller asserts about itself

Every query parameter other than `subject`, `resource` and `action` becomes a
**subject attribute the caller asserted**, under both the bare name and the
`urn:sts:xacml:attribute:` form the service's own PIP answers to.

```bash
curl -s ".../protected?subject=carol&resource=https://expenses.example.test&action=GET&employeeType=staff"
# 200 — carol is an admin in the directory and said she was staff
```

That is not a bug and it is not a hole the PIP closes. **A PIP removes the
disagreements that come from missing information; it does not remove the ones
that come from a caller asserting something about itself**, which no real
deployment would believe and which is exactly the sort of thing a test service exists to
let you try. Set `PEP_PIP=false` to watch the behaviour this container had before
the PIP existed, where *every* attribute has to arrive this way.

## Changing the policy: the pull is the contract

Deploy a second application's policy and promote it, and watch the running PEP
change its mind with nothing pushed to it:

```
t+ 2s  carol@payroll=403  alice@expenses=200
t+ 4s  carol@payroll=403  alice@expenses=200
t+ 6s  carol@payroll=200  alice@expenses=403      ← the poll landed
t+ 8s  carol@payroll=200  alice@expenses=403
```

**The nudge is an optimisation over the polling interval and never a replacement
for it.** The PDP dials a registered PEP's `POST /notify` when the repository
changes, which brings a change down in tens of milliseconds instead of up to
`PEP_POLL_INTERVAL_MS` — but a nudge that never arrives costs latency and never
a change, and the nudge body is not read and nothing in it is trusted.

### The nudge is HTTPS only

**The service nudges a PEP over HTTPS and nothing else, in every mode, and
always verifies the PEP's certificate** (since 2026-11-14):

* **Trust with nothing set.** The PEP's HTTPS listener certificate is issued
  by the realm's Remote PEP listeners (`pep-tls`) Issuing CA, so the nudge
  verifies the PEP against that chain (the Issuing CA, the realm's
  Intermediate and the service Root), and checks the notify URL's host
  against the certificate's names. A certificate that chains to this
  service's Root through any other Issuing CA, such as another realm's PEP or
  a custom listener, is refused (`STS-XACML-0260`).
* **`xacml.pepNotifyCaFile`** adds anchors for a PEP whose listener
  certificate comes from elsewhere, beside node's own store. A file that
  cannot be read refuses the nudge (`STS-CORE-0104`).
* **An `http://` notify URL** is shown unusable on the PEP's row, with the
  reason, and the registration reply says the same. The PEP converges on its
  poll. The PEP itself **rejects** an `http://` `PEP_NOTIFY_URL`, or an
  `http://` `notifyUrl` an older service stored (`STS-XPEP-0113`), and the
  PEP's Settings tab refuses one (*A notify URL that is not https is
  rejected*, below).
* **The PEP derives its notify URL when none is set** (*The PEP derives its
  notify URL*, below).
* **Retired settings.** `xacml.pepNotifyAllowHttp` and
  `xacml.pepNotifySkipTlsVerification` are still accepted, so a
  configuration naming them starts, and they are ignored: one that is on logs
  `STS-XACML-0258` once per process.

So the compose service's nudge is delivered once the PEP holds the pair the
realm issued it (*Its HTTPS listener certificate*, below), in development and
product alike. Until then the dial fails, the PDP records why on the PEP's
row, and the PEP converges on its poll anyway.

### The PEP derives its notify URL

**With neither the Settings tab's `notifyUrl` nor `PEP_NOTIFY_URL` set, the
PEP derives a notify URL** and advertises it on the registration, the
heartbeat and its own `GET /`:

```
https://<host>:<PEP_HTTPS_PORT>/notify
```

`<host>` is the first of these that is a DNS name:

1. **the DNS name in the HTTPS listener certificate the PEP serves that
   equals the PEP's hostname**, ignoring case and a trailing dot. The service
   checks the notify URL's host against that certificate, so a name taken
   from it can pass the check, and the hostname is the name the container is
   known by on its network, so it resolves;
2. **otherwise the first DNS name in that certificate**;
3. **otherwise `PEP_NAME`**, if it is set and is a DNS name;
4. **otherwise the container's or system's hostname** (`HOSTNAME`, else the
   kernel's).

A wildcard and an IP address are passed over at every step.

For example, a certificate naming `remote-pep-1, xacml-pep, localhost,
127.0.0.1` on a container whose hostname is `xacml-pep` gives
`https://xacml-pep:9443/notify`. The first name, `remote-pep-1`, is the
PEP's registered name, which the realm puts in the certificate by default
and which nothing resolves.

**The realm names the hostname by default.** The PEP reports its hostname
(the same value step 4 reads) on its registration and every heartbeat, and
the PEP's page shows it on the Overview tab. The realm's default
certificate names the PEP's registered name, that hostname and the host of
its notify URL, so a certificate issued with no extra names on a fresh
install already holds the name step 1 picks. Add a DNS name by hand only if
the service reaches the PEP by a name other than its hostname.

The service accepts only a DNS name as the hostname: labels of letters,
digits and hyphens, 253 characters at most, never an IP address. It refuses
a registration or heartbeat that carries anything else (`STS-XACML-0261`).
The PEP sends the member only when its hostname is such a name. A PEP
older than this sends none, and its default names are as before. An older
service ignores the member.

* **No HTTPS certificate, no URL.** `POST /notify` is answered on HTTPS only,
  so a PEP with no pair yet advertises nothing and converges by polling. The
  URL is derived again on every reload of the pair. A new certificate that
  names another host changes it, and the PEP sends a heartbeat at once so the
  service holds the new one.
* **The precedence** is the Settings tab's `notifyUrl`, then
  `PEP_NOTIFY_URL`, then the derived URL, then none. An explicit `http://`
  value is rejected, and the PEP does not fall back to the derived URL (*A
  notify URL that is not https is rejected*, below). The Settings tab shows
  the source as *derived by the PEP*. The Notify column says *derived by the
  PEP from its HTTPS listener certificate*.
* **The log** names the derived URL and which rule picked its host at INFO,
  once, and again whenever it changes.
* **Set `PEP_NOTIFY_URL`** when the service reaches the PEP by a name that is
  not its hostname, for example behind a load balancer, or by an IP address.
  `docker-compose.yml` and the test stack derive it. The protocol job's PEP
  on the host network still sets it, because the service dials it at the
  loopback address.

### A notify URL that is not https is rejected

**An `http://` notify URL is rejected, not ignored.** The nudge is sent over
HTTPS only, and no setting allows plain HTTP any more. So a `PEP_NOTIFY_URL`,
or a Settings tab `notifyUrl` an older service stored, that is not an
`https://` URL:

* **is logged at ERROR** with `STS-XPEP-0113`, once per value, naming the
  variable or setting and saying why;
* **leaves the PEP advertising no notify URL.** It does **not** fall back to
  the derived URL. Somebody asked for a specific URL, and it has to be fixed
  or unset, not guessed around. The PEP converges by polling until then;
* **is reported rejected.** The PEP's settings in use carry the value it was
  given, its source and `rejected: true`. The Settings tab shows *rejected:
  not https*, and the Notify column says the PEP rejected it.

The service keeps its own refusals: it never nudges an `http://` notify URL
a registration or a heartbeat carries, and shows it unusable on the PEP's row
(`STS-XACML-0259`), and the Settings tab refuses to save one
(`STS-XACML-0239`).

## When the PDP goes away

**The last good policy set is kept and enforcement continues.** Stop the service and
the PEP goes on deciding correctly in both directions — still permitting what the
last pulled policy permits, still refusing what it refuses — while `GET /`
reports `lastPullOk: false` and says it is keeping what it has.

That is a real trade and both ends say so rather than hiding it: **a policy
change made during an outage is not enforced here until the next successful
pull.** The alternative, a PDP outage denying everything everywhere, is the
failure mode that makes people remove authorization services.

## Running more than one

**Run as many as the load needs, side by side, and put a load balancer in
front.** Instances share nothing and never talk to each other. There is no
cluster to join, because nothing a PEP holds needs coordinating:

| What an instance holds | Where it comes from |
|---|---|
| the policy set | pulled from the PDP. A new instance holds exactly what the others hold after one pull |
| the AuthZEN catalogue and caller list | pulled from the PDP |
| its decision counters | its own. Each instance counts only what it decided |
| its HTTPS listener pair | the two files `PEP_HTTPS_CERT` and `PEP_HTTPS_KEY` name |
| a person's attributes | asked of `POST /xacml/pip` before each decision, and not kept |

The service is already the one place the policy comes from, so instances
converge on it on their own: each within one `PEP_POLL_INTERVAL_MS`, or at once
when nudged. An instance that cannot reach the service keeps enforcing what it
last pulled, [as above](#when-the-pdp-goes-away). A peer could only hand it the
same copy or an older one.

### One certificate per instance, or one shared

**This is the one choice to make.** The service files a remote PEP by its
client certificate, so one certificate is one row on
[the **Remote PEPs** tab](configure-xacml.md#stop-nudging-or-forget-a-pep). Both
choices decide correctly. What differs is what you can see and how fast a
change arrives:

| | One certificate per instance | One certificate shared by every instance |
|---|---|---|
| rows on the **Remote PEPs** tab | one per instance | one for the whole deployment |
| the nudge on a policy change | reaches every instance | reaches one instance: whichever registered or sent a heartbeat last, because its `PEP_NOTIFY_URL` replaces the row's. The rest pick the change up on their next poll |
| decision counters, build, bias | each instance's own | whichever instance sent the last heartbeat. Each heartbeat replaces the row's numbers, so the row jumps between instances and is never the total |
| an instance that stops | its row goes stale | hidden while any other instance still sends heartbeats |
| stopping nudges, or revoking the certificate | one instance at a time | every instance at once |
| adding an instance | first mint a certificate and store it on an entry in `remote-peps` ([Minting the certificate](#minting-the-certificate)) | start a container with the same files |
| the HTTPS listener certificate | issued per instance, naming its own notify host | one certificate whose `dnsNames` include the load balancer's name |

**For a fixed number of instances, give each its own certificate.** The console
then tells you about every instance, and every one is nudged.

**For an autoscaling group, share one certificate**, because a new instance
then needs nothing minted before it starts. Accept the costs in the right-hand
column: one row that is not a total, a policy change that reaches most
instances on the poll rather than the nudge, and a dead instance you see in
your load balancer's health checks rather than on the console. If a change has
to arrive faster, lower `PEP_POLL_INTERVAL_MS`: an unchanged policy answers the
poll with `304`, so that costs the service very little.

### What more instances cost the service

**Polling costs almost nothing per instance**: one conditional request every
`PEP_POLL_INTERVAL_MS`, answered `304` while the policy is unchanged, and a
heartbeat every `PEP_HEARTBEAT_INTERVAL_MS`.

**The PIP query is the load that grows**, because it is one batched
`POST /xacml/pip` per decision that needs an attribute the request did not
carry. More PEP instances spread the decisions out but send the service the
same number of queries. To cut that load, have the caller send the attributes
in the request, or set `PEP_PIP=false` where the policy needs nothing from the
directory.

## An HTTPS listener, certified by the realm it registered to

A PEP answers its own clients, and it can answer them over HTTPS with a
certificate **this service issues it**. Every trust realm has a **Remote PEP
listeners** Issuing CA (`pep-tls`) under its own Intermediate, beside the JOSE,
XML, assertion and SPIFFE authorities — you can see it on `/admin/pki`. A
certificate from it chains to the service Root, so a client that installed that
one anchor verifies the PEP, and the chain still says which realm vouched for
it.

**The PEP has to be registered first**: the certificate comes from the realm it
registered to, and its row in that realm is how this service knows which one
that is. So the order is always the same:

1. Start the PEP with `PEP_HTTPS_CERT` and `PEP_HTTPS_KEY` naming two paths that
   **do not exist yet**. It registers, and `GET /` says it is waiting:

   ```bash
   curl -s http://localhost:9090/ | jq .https
   # { "configured": true, "listening": false,
   #   "problem": "no HTTPS listener yet: /certs/server/pep-server.crt does not exist. …" }
   ```

2. Issue the pair through the management API, **in the PEP's realm**, naming
   the host your clients will dial. The certificate always names the PEP's
   registered name, the hostname it reported and the host of its notify URL
   too:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"remote-pep-1","dnsNames":["pep.example.test"]}' \
     https://localhost:8081/realm/acme/admin-api/xacml/issue-pep-certificate > issued.json
   ```

   The same button is on each row of `/admin/xacml/peps` in the console. Either
   way **the private key is in that reply and nowhere else** — this service
   keeps the certificate (its issuer's CRL and OCSP responder answer for it)
   and no copy of the key.

3. Write the two halves where the PEP looks, on its mount:

   ```bash
   jq -r .fullChainPem  issued.json > certs/server/pep-server.crt   # leaf + Issuing CA + Intermediate + Root
   jq -r .privateKeyPem issued.json > certs/server/pep-server.key
   jq -r .anchorPem     issued.json > service-root.pem              # what a client trusts
   ```

   Within `PEP_HTTPS_RELOAD_INTERVAL_MS` the listener starts — **no restart** —
   and `GET /` reports the certificate it is serving:

   ```bash
   curl --cacert service-root.pem https://pep.example.test:9444/protected?subject=alice
   ```

**Reissuing replaces.** Issue again and write the new pair: the listener swaps
it in and the old certificate goes on its issuer's revocation list as
`superseded`. A pair whose two files disagree — the moment between writing one
and the other — is never used, and a listener already serving keeps the pair it
has.

**Plain HTTP on 9090 is off unless `PEP_HTTP=true`** (*Plain HTTP is off by
default*, above). Once the pair is served, the healthcheck uses it. `/admin/xacml/peps` says which
certificate the realm *issued*; only the PEP's `GET /` can say which one it is
*serving*.

## An AuthZEN edge PDP

The container also answers [AuthZEN](authzen.md) access evaluations itself, so a
PEP in its network can ask a PDP nearby instead of the service:

```
POST /access/v1/evaluation                 one evaluation
POST /access/v1/evaluations                a batch
GET  /.well-known/authzen-configuration    its metadata
```

**A request is mapped exactly as the service maps it.** What a property of a
request means is the realm's AuthZEN attribute catalogue, and the container
pulls it from `GET /xacml/pep/authzen-catalogue` beside the policies, on the
same poll, with its own sync token — the same credential and the same
`REMOTE_PEPS` role as the policy pull. The pull also carries the realm's
AuthZEN settings that change the mapping or the answer
(`authzen.enabled`, `authzen.resolveSubjectTypes`, `authzen.batchEnabled`,
`authzen.maxEvaluations`, `authzen.maxBodyBytes`, `authzen.returnReasons`), so
switching one on the service switches it here at the next poll. The
identifiers, the value rules, the refusals and their statuses, the batch's
three semantics and bounds, `X-Request-ID` and the fail-closed result are the
service's: `true` only on a Permit carrying nothing it cannot discharge
(`urn:sts:xacml:obligation:log` is the one it can), whatever `PEP_BIAS` says.
It decides against the root policy it pulled, and asks the service's PIP
(`POST /xacml/pip`) about a subject whose type the realm resolves, as
`/protected` does.

A catalogue change converges on the poll — the service's nudge is about the
policy repository. Until the container has pulled both the policies and the
catalogue, the AuthZEN endpoints answer `503` rather than map a request
differently from the service.

### Applications that enforce fine-grained authorization: forwarded

An application that enforces [fine-grained authorization](fga.md) is decided
against **its own policy**, and only the service decides it: application
policies are withheld from `GET /xacml/pep/policies`, so the container never
holds them. **The container does not answer an evaluation about such an
application. It forwards it to the service.**

```
   a resource server        the remote PEP (edge PDP)          iya-sts (the realm)

  POST /access/v1/evaluation
  { …, context: {           1. admit the caller, read the
    application: "docs" } }    request, resolve the application
                            2. "docs" is on fgaApplications
                               ──▶ POST <PEP_PDP_URL>/access/v1/evaluation
                                   (mutual TLS, the PEP's own     3. decided against
                                    certificate)                     the application's
                                                                     own policy
  { "decision": false } ◀── 4. the service's answer         ◀──
```

* **Which applications.** The catalogue pull carries `fgaApplications`, the
  identifiers of the applications whose fine-grained authorization is
  enforced (the switch on the application's *Fine-grained authorization*
  tab). The member is inside the catalogue's sync token, so switching
  enforcement on or off reaches the container at its next poll
  (`PEP_POLL_INTERVAL_MS`, 15 seconds by default). Until then an application
  just switched **on** is still decided here from the root, and one just
  switched off is still forwarded.
* **Which evaluations.** The application is resolved exactly as for any other
  evaluation — `context.application` checked against the caller's scope, or
  the caller's only application. Applications not on the list are decided
  here, as before.
* **What is sent.** The caller's request for that evaluation, unchanged but
  for `context.application`, which is always set to the resolved application.
  A batch item is forwarded **as one single evaluation** (the batch's
  defaults merged into it, as the service would have read the item); the
  batch's semantic and order are kept here, and the other items are decided
  here. `X-Request-ID` is passed on (for a batch item, the batch's id and the
  item's index). The service's answer, including its `context`, is the
  item's answer.
* **Who asks.** The container itself, on the client certificate it already
  presents to pull (`PEP_TLS_CERT`). At the service it is an AuthZEN caller
  like any other, so a policy there sees **the PEP** as
  `urn:sts:xacml:authzen:caller`, not the caller that asked the container,
  and the `urn:sts:xacml:authzen:supplied` bag names `context.application`
  even when the caller left it out.
* **Errors are errors, never `false`.** If the service answers an error, the
  caller gets an error, as a status from the single endpoint or a batch
  item's `context.error`:

  | The service | The caller of the edge PDP gets |
  |---|---|
  | a decision | that decision |
  | `400`, `413`, `500`, `501` or `503` (a `500` is the service's "the application's policy cannot be used") | the same status and the service's message |
  | `401` or `403` — it does not admit **the PEP** | `502`, saying the PEP's entry needs `AUTHZEN_PEPS` and the application in its scope |
  | any other status, or a `200` that is not a decision | `502` |
  | no answer within `PEP_AUTHZEN_FORWARD_TIMEOUT_MS` | `504` |
  | could not be reached | `502` |

* **Before the first catalogue pull** nothing is answered (`503`), since
  without the catalogue the container cannot tell which applications must be
  forwarded. A catalogue whose `fgaApplications` it cannot read is refused
  whole and the one it holds is kept.

**What the operator must grant.** The PEP's own directory entry — the one its
client certificate is stored on, which already holds `REMOTE_PEPS` — must
also:

1. hold **`AUTHZEN_PEPS`** (be a member of `roles.authzenPepGroup`,
   `authzen-peps`, and be admitted by the access-control policy on
   `authzen-api`); and
2. have **every application that enforces fine-grained authorization** that
   its callers ask about in its **application scope**
   (`stsAuthzenApplication`, on the AuthZEN tab).

**Enforcing an application grants both.** Every time fine-grained
authorization is switched on for an application (**Enforce** on its
**Fine-grained authorization** tab, or `POST /admin-api/applications/fga-enable`),
each member of `roles.remotePepGroup` (`remote-peps`) — a person, a service
account or an application — is added to `authzen-peps` if it is not a member,
and has the application added to its scope if it is absent. Nothing else in
its scope changes. The answer lists which PEPs were granted, which already
held both, and which could not be granted and why (`STS-FGA-0025`); a PEP that
cannot be granted does not stop the application being enforced. Switching
enforcement off takes nothing away. A PEP added to `remote-peps` afterwards
is granted by enabling again (the tab's **Grant the remote PEPs again**), or
by hand on the AuthZEN tab. See
[What enforcing grants the remote PEPs](fga.md#what-enforcing-grants-the-remote-peps).

Membership of `remote-peps` itself still admits a PEP only to `/xacml/pep/*`
and `POST /xacml/pip`, and a registration in `ou=peps` grants nothing; the
AuthZEN grant is written when an administrator enforces an application.

Without them the service answers `401` or `403`, and the container answers
`502` with a message saying exactly this. The realm's
`authzen.callerAuthentication` must admit a certificate (`mtls`, the
default); a realm whose door is a token admits no caller to the container
anyway.

### Its callers: mutual TLS, admitted by the service's own list

The AuthZEN endpoints answer on the **HTTPS listener** (above) to a caller
presenting a client certificate, and to nobody else — the service's default
door, `authzen.callerAuthentication=mtls`. `PEP_AUTHZEN_CLIENT_CA` is the CA
bundle a caller's certificate must chain to. With it set the listener **asks**
every client for a certificate (`/protected` still takes none); without it the
AuthZEN endpoints admit nobody.

**Who may ask is pulled from the service.** After the catalogue the container
pulls `GET /xacml/pep/authzen-callers`, on the same poll, with the same
credential and the same `REMOTE_PEPS` role, and its own sync token. It lists,
for every caller the realm admits to `/access/v1` **now**:

* the **name** a policy sees as `urn:sts:xacml:authzen:caller` — the DN of the
  directory entry the service's certificate door resolves the caller's
  certificate to, exactly as the service would put it there;
* the **SHA-256 of the DER** of every certificate the service would resolve to
  that entry: the ones stored in `userCertificate` on it, and the TLS client
  certificates its realm issued it that are still valid;
* its **application scope** (`stsAuthzenApplication`, set by an administrator
  on the AuthZEN tab), checked against `context.application` exactly as the
  service checks it;
* the **endpoints** the access-control policy admits it to.

The list is the **outcome**, not the membership: the candidates are the members
of the group named by `roles.authzenPepGroup` (`authzen-peps`), and each is
listed only if the access-control policy on resource `authzen-api` admits it,
as it would admit the same caller asking the service. The container admits a
certificate only if the list names it, under that name and scope.

**Anybody holding `REMOTE_PEPS` can read this list** — who may ask the PDP,
and with which certificates. That is the accepted cost of the edge admitting
by the service's answer rather than by a second copy of it. Nothing else is
sent: no certificate, no attribute, no group.

**It converges on the poll.** The list's token moves when a member is added to
or taken out of the group, a certificate is stored on or taken off an entry, a
certificate the realm issued is issued, expires or is revoked, a scope is set,
the realm's `authzen.callerAuthentication` changes, or the access-control
policy's answer about a caller changes. Nothing is pushed: a caller the service
stops admitting is still admitted here until the next poll
(`PEP_POLL_INTERVAL_MS`, 15 seconds by default). A failed pull keeps the last
good list.

**A realm whose door is a token lists nobody.** With
`authzen.callerAuthentication` set to `bearer` or `mtls+bearer` a certificate
alone is not enough at the service, and the container cannot check a token, so
the list is empty and the edge PDP answers `401` to everybody.

#### `PEP_AUTHZEN_CALLERS`, the optional narrowing

`PEP_AUTHZEN_CALLERS` is a JSON array of `{ "name", "sha256", "applications" }`
naming certificates by their SHA-256. It is **optional**:

* **unset** — the pulled list alone decides, and the AuthZEN endpoints answer
  `503` until the first caller pull has loaded;
* **set** — a pulled caller must **also** be on it, so an operator can confine
  an edge to some of the service's callers. The pulled name and scope are
  used; the local `name` and `applications` are not. Before the first caller
  pull — or against a service older than the caller list, which answers `404`
  — the local list decides alone, as it did before the list existed. Set to a
  list that names nobody, it admits nobody.

  ```bash
  PEP_AUTHZEN_CLIENT_CA=/certs/authzen-ca.pem
  PEP_AUTHZEN_CALLERS='[{"name":"uid=todo-pep,ou=users,dc=acme,dc=example",
                         "sha256":"3f:1a:…:9c",
                         "applications":["todo-app"]}]'
  ```

The narrowing is the default chosen while this was built; it can be reversed
(the list removed, or made to decide alone) if that is the better answer.

```bash
curl --cacert service-root.pem --cert pep.crt --key pep.key \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},
       "resource":{"type":"document","id":"doc-1"}}' \
  https://pep.example.test:9444/access/v1/evaluation
# {"decision":true}
```

The metadata names the container's own PDP identifier:
`PEP_AUTHZEN_PDP_IDENTIFIER` (an `https` origin, such as
`https://pep.example.test:9444`) or, unset, the origin the HTTPS request
arrived at.

### What it cannot do that the service can

| The service | The edge PDP |
|---|---|
| A caller holds `AUTHZEN_PEPS`, decided by the access-control policy, at the moment it asks | The same answer, pulled: a caller the service admits now is admitted here from the next poll, and one it stops admitting is admitted here until then |
| Any entry the access-control policy admits | The members of `roles.authzenPepGroup` the policy admits. A policy written to admit an entry outside the group admits it at the service and not here |
| Every certificate the door resolves to an entry | The certificates stored on the entry and the TLS client certificates the realm issued it. A certificate enrolled over ACME, EST or SCEP and not stored on the entry is not listed |
| Three doors: `mtls`, `bearer` and `mtls+bearer` | Mutual TLS only. It cannot check a token's issuer, audience, revocation or client against the realm, so a realm whose door is a token admits nobody here |
| A client certificate is checked for revocation | Not checked. A certificate the service's own register records as revoked leaves the pulled list on the next poll; an outside authority's CRL or OCSP answer is never consulted |
| The PIP answers from the directory in process | The PIP is the service's `POST /xacml/pip`, asked over the network; if that fails the subject's attributes are an empty bag, as for `/protected` |
| One `authzen.decision` row per evaluation in the audit log, and a row on `/admin/xacml/monitor` | A log line per evaluation with the same content, never a property value or an id the caller sent; `GET /` counts the answers. Nothing reaches the service's audit log |
| `reason_admin` is the service's sentence | It is this container's; the decision and the code are the same |
| The three Search APIs (`/access/v1/search/*`) | Not served. The metadata does not list them |
| The Obligations Profile: an obligation is handed in `context.obligations` when the PEP declares its type in `context.supported_obligations` | Not implemented. A Permit carrying any obligation but `urn:sts:xacml:obligation:log` answers `false`; `context.supported_obligations` is an undeclared member |
| `signed_metadata` in the metadata document | Not sent; the edge PDP holds no signing key of the realm's |
| An evaluation about an application that enforces [fine-grained authorization](fga.md) is decided against that application's own policy ([AuthZEN](authzen.md#applications-with-their-own-policy)) | Not decided here: forwarded to the service, which decides it ([above](#applications-that-enforce-fine-grained-authorization-forwarded)). It costs a round trip, needs the PEP's entry to hold `AUTHZEN_PEPS` with the application in its scope, and follows a switch of enforcement from the next poll |

`GET /`'s `authzen` block says what it holds: the catalogue's token, its rows,
the settings, the last pull, how many callers and certificates the pulled
list holds (counted, never named — `GET /` answers whoever reaches the
container), whether `PEP_AUTHZEN_CALLERS` narrows it, how many applications
enforce fine-grained authorization (`catalogue.fgaApplications`, a count), and
what it has answered (`answered.forwarded` counts the evaluations the service
decided).

## Reading `GET /` when something is wrong

| What you see | What it means |
|---|---|
| `holding.loaded: false` | it has **never** pulled successfully. There is no policy, every decision is `NotApplicable`, and the bias decides. Not the same as an empty repository |
| `stale: true` | three polling intervals without a successful pull. It is still enforcing what it last held |
| `holding.lastPullWhy` | the reason, in a sentence. A 403 here almost always means the credential chain above |
| `holding.refused` | documents the PDP sent that **this** engine would not accept. The two policy counts then disagree, which is what the console column is for |
| `registration.registered: false` | it is not on the PDP's console and will not be nudged. It is retried on every poll, and `registration.attempts` says how many it took |
| `pip.credentialed: false` | no client certificate, so the PIP query is refused and only what the request asserts decides |
| `https.listening: false` | no usable listener pair yet. `https.problem` says whether the files are missing (issue one) or refused (the key is not the certificate's, or a file will not parse) |
| `authzen.catalogue.loaded: false` | no AuthZEN catalogue pulled yet, so the AuthZEN endpoints answer `503`. `authzen.catalogue.lastPullWhy` says why; a `404` means a service older than the catalogue endpoint |
| `authzen.pulledCallers.loaded: false` | no caller list pulled yet. Without `PEP_AUTHZEN_CALLERS` the AuthZEN endpoints answer `503`; with it, that list alone decides. `authzen.pulledCallers.lastPullWhy` says why; a `404` means a service older than the caller list |
| `authzen.answered.errors` rising with `answered.forwarded` | evaluations forwarded to the service are failing. The container's log says why; `STS-XPEP-0056` means the service does not admit the PEP itself — give its entry `AUTHZEN_PEPS` and the application in its scope |
| `authzen.pulledCallers.door` other than `mtls` | the realm authenticates its AuthZEN callers by a token, so the list is empty and every caller is refused `401` |

**The two ends can disagree about staleness, and that is deliberate**: this PEP
counts missed *polls* and the PDP counts missed *heartbeats*. A PEP pulling
happily while its heartbeats are dropped looks fine here and stale there. Both
numbers are visible so that state is recognisable.

The PDP's side of it is `/admin/xacml/peps` in the console, or
`GET /admin-api/xacml/peps`, which carries each PEP's name, whether it
authenticated, its build, its policy count, its sync token and the decision
counters it reported. **Those counters arrive on the heartbeat**, once a minute
by default, so a freshly started PEP reads as zeroes for up to a minute.

## In front of an application: the reverse proxy (#1760)

A registered PEP can stand in front of an application as a reverse proxy.
What it enforces is a configuration the service holds for it, set on the
**Remote PEPs** tab of `/admin/xacml` or with
`POST /admin-api/xacml/set-pep-proxy` (`clear-pep-proxy` removes it). The PEP
pulls it over its mutual TLS from `GET /xacml/pep/proxy`, which answers `304`
to `?since=<syncToken>` while nothing changed.

The document names the upstream, the `publicBaseUrl` a browser reaches the
proxy at (https in product mode, and always for a session route), the
timeouts, and an ordered list of routes; the first route that matches wins and
a request no route matches is refused `404`. Every route states its `methods`
(all seven for any method, none for **deny-all**) and makes one
**authorization** choice — see [Authorizing a route](xacml.md#authorizing-a-route):
every request on it, a public route's included, is decided in XACML by that
route's own policy, never by the realm's root. Each route that is not public
names the **application** in the realm's registry that it fronts. Nothing is
copied from the application: what each mechanism needs is read from its entry
when the configuration is saved and again at every pull.

| Mechanism | The application must have |
|---|---|
| `oauth2` | an audience (`oauthAudience` or `oauthPermissionBaseUri`) |
| `saml2` | a SAML entity ID (`samlEntityId`) |
| `session` | a confidential OpenID Connect client: `client_secret_basic` or `client_secret_post`, the `authorization_code` grant, `<publicBaseUrl>/.iya-pep/callback` registered as a redirect URI, and an unexpired client secret |
| `basic` | nothing |

A rotated client secret or an edited application reaches the PEP on its next
pull; a deleted one leaves its route `usable: false`. The application's own
page lists the PEP routes in front of it.

### How the identity reaches the application

Each route's `identity` says what the proxy forwards about the caller:

* **`headers`** (the default): up to 16 request headers, each carrying one of
  `sub`, `username`, `email`, `name`, `given_name`, `family_name`, `groups`,
  `mechanism`, `acr` or `amr`. A list (`groups`, `amr`) is joined with the
  route's `separator`, `,` by default. A header may not be a hop-by-hop or
  framing header, `Authorization`, `Cookie`, `Host`, `Forwarded` or
  `X-Forwarded-*`, and the proxy strips a client's own copy of each. **A
  claim with no value sends no header**: absent, an empty string, or an empty
  list (a person in no group sends no `X-Iya-Groups` at all). `amr`, `acr`
  and `auth_time` are read from the access token behind a proxy session, so
  a route mapping `amr` carries how the person signed in.
* **`saml`**: a signed SAML 2.0 Response about the caller, for the
  application's registered assertion consumer service. The application needs
  `samlEntityId` and `samlAssertionConsumerService`.
* **`jwt`**: an access token about the caller, issued to the application and
  addressed to its audience.

On the console it is edited on the route's own page (the route id in the
Reverse proxy tab's table links to it), in the identity part of that page's
form: a mode, a table of header and claim, and the separator. The API's
`POST /admin-api/xacml/set-pep-route-identity` sets it alone.

### Signing a browser in: the `session` mechanism

The proxy signs a person in for the application behind it, as that
application's OpenID Connect relying party. Register the application in the
realm as an ordinary confidential client, and add
`<publicBaseUrl>/.iya-pep/callback` to its redirect URIs. Then name the
application on the route. The client secret travels to the PEP only over its
mutual TLS pull. It is never on a console page or in an `/admin-api` answer.

1. A browser asking for a `session` route with no proxy session is redirected
   to the realm's `/oauth2/authorize` with PKCE.
2. The person signs in at the service, which redirects back to
   `/.iya-pep/callback`.
3. The proxy redeems the code and checks the ID Token. It then keeps a proxy
   session of its own behind the `iya_pep_session` cookie. The cookie is
   `HttpOnly` and `SameSite=Lax`, `Secure` over https, and never forwarded.
4. **A sign-out at the service ends access.** The proxy receives the
   application's CAEP and RISC events on a Shared Signals poll stream, and a
   `session-revoked` event ends the proxy session. Give the application the
   `client_credentials` grant and the `ssf.read` and `ssf.manage` scopes for
   this, and turn on the realm's transmitter. A route with `signals: false`
   asks `POST /xacml/pep/session` instead, at most every
   `PEP_PROXY_SESSION_RECHECK_MS`. Either way the browser is sent to sign in
   again with the `iya_pep_session` cookie cleared.
5. **Between the sign-out and the signal**, a fraction of a second, the
   service already refuses the session's access token. When the identity
   endpoint refuses a proxy session's identity, the proxy asks
   `POST /xacml/pep/session` whether the sign-on session is still live; if it
   is not, the proxy session ends as a signal would have ended it: a browser
   is sent to sign in, anything else gets a 401. A refusal of a live session
   is still the 403 it was.

**Watching the streams.** The PEP's `GET /` shows each stream's state under
`proxy.signals`, and the PEP sends the same numbers on its heartbeat. The
console draws them under **CAEP/RISC signal streams** in the PEP's reverse
proxy section of **Remote PEPs**, and `GET /admin-api/xacml/peps` carries them
as the row's `signals`: how many streams there are, how many are healthy and
how many stale, the oldest successful poll, the most failures in a row, the
events accepted and refused, the sessions ended, and the library's session
stores. There are only counts and ages, never a client id, a URL or an error
message. A PEP from before this change sends none, and its row shows **not
reported**. A newer PEP works with an older service, which ignores the extra
heartbeat member. A stale stream shows when the stream stopped answering;
its routes then ask the service's session endpoint until it polls again.

`/.iya-pep/logout` ends the proxy session and sends the browser to the realm's
end-session endpoint. A request that is not from a browser and has no proxy
session gets `401`.

The relying party is rcbj's crate
[`oidc-caep-risc`](https://github.com/rcbj/oidc-caep-risc-rust) (MIT, from
crates.io). It verifies the service's listener certificate against the chain
the pull carries, so the host name in `PEP_PDP_URL` must be one that
certificate names.

### Before you put it in front of an application

* **The application must accept traffic only from the proxy.** An identity
  header carries no proof. The proxy strips every configured identity header
  from the incoming request, in any case and however many times it was sent,
  but an application reachable some other way can be sent any header.
* **The proxy never chooses where to send a request.** The upstream is fixed
  by the configuration. A path with a dot segment, `//`, a backslash or an
  encoded `.`, `/` or `\` is refused `400`.
* **What the client sent to authenticate is not forwarded**, unless the route
  sets `forwardCredentials`. That covers `Authorization` and the proxy's own
  cookie.
* **The identity provider's cookies are never forwarded**, whatever
  `forwardCredentials` says. A browser sends cookies by host, not port, so
  where the service and the proxy share a host the service's
  `__Host-sts_session` and the rest would reach the application. The service
  names its cookie prefixes on every pull (`realm.serviceCookiePrefixes`:
  `sts_*`, `__Host-sts_*`, `__Secure-sts_*`), and the managed setting
  `proxyStripCookies` (`PEP_PROXY_STRIP_COOKIES`) adds more: names separated
  by commas, a trailing `*` a prefix. The application's own cookies are never
  removed unless they are named there. Hop-by-hop headers are dropped in both directions. `X-Forwarded-For`,
  `X-Forwarded-Proto` and `X-Forwarded-Host` are the proxy's own, never the
  client's.
* **A request is never forwarded without the identity its route sends.** When
  the service will not issue it, the request is refused: `403` when the
  policy refused, `502` otherwise.
* The status codes: `404` for no route, `405` with `Allow` for a method the
  route does not take, `401` with a challenge for each mechanism the route
  accepts, `403` for a refusal and for a route whose application no longer
  qualifies, `413` over `maxBodyBytes`, `502` when the upstream cannot be
  reached, and `504` after `upstreamTimeoutMs`.
* WebSockets are not proxied, because `Upgrade` is a hop-by-hop header.

### What a person sees when the proxy refuses them

A request whose `Accept` header includes `text/html`, such as a browser
loading a page or posting a form, is refused with the same error page
iya-sts shows. The status code and headers stay the same. Any other request
gets the JSON answer it always got: `{"error": …, "error_description": …}`.

The page has a title and a sentence saying what went wrong: no access under
the policy, the page closed to every request (a route with no methods), the
policy not available, a sign-in that failed, the application not reachable,
and so on. A collapsed note explains why the page appeared, and a link goes
to the start page. When the policy refused the person signed in on a
`session` route, the page also offers another account. On a route with
**Several accounts** that is *Use a different account* and *Sign in with
another account*; on any other session route it is a sign-out.

At the bottom, a **Diagnostics** box lists the time (UTC), an **incident
ID**, the application, the address, who is signed in, and the `error` and
`error_description` an API client would get. Error codes never appear on the
page. The PEP's log line for that refusal carries the code and the same
incident ID (`… with 403, page incident 3f9c0d…: …`). When someone sends you
the diagnostics, search the PEP's log for the incident ID.

The page runs no script. Its `Content-Security-Policy` is the proxy's own,
plus `style-src` with the hash of its one style sheet. The page is in
English.

### What the PEP asks the service

Everything the proxy cannot decide by itself it asks over its mutual TLS, and
every such request needs `REMOTE_PEPS` and is audited as
`xacml.pep.validate`:

| Endpoint | Answers |
|---|---|
| `POST /xacml/pep/introspect` | RFC 7662 introspection of an access token |
| `POST /xacml/pep/basic` | whether a Basic username and password are valid, and a `ticket` for the identity request (opaque, bound to this PEP and the person, 120 seconds). In product mode a person presents an app password scoped to `xacml-pep` |
| `POST /xacml/pep/saml` | whether a SAML assertion this realm issued is valid for the route's audience |
| `POST /xacml/pep/session` | whether a sign-on session is still live |
| `POST /xacml/pep/identity` | for one of this PEP's routes and the caller's evidence (an access token, a SAML assertion or a Basic ticket, each validated again), the claims, access token or SAML Response the route forwards. The issuance policy decides the last two; a refusal is `403`, and what cannot be issued is `422` |

## Its page on the console

Each row of **Protocols → XACML → Remote PEPs** opens the PEP's own page,
`/admin/xacml/pep?pep=<name>` (`GET /admin-api/xacml/peps?pep=<name>`), with
the trail *Admin console › XACML › Remote PEPs › the PEP*, its Remote PEPs
crumb leading back to the tab, followed by the tab and sub-tab you have open
(*› Listener › Create a new listener*). Every act on a PEP under
`POST /admin-api/xacml/` takes the PEP as `pep`, the same name, or as `name`
as it always has; both naming different PEPs is refused. Its tabs:

| Tab | What is on it |
|---|---|
| Overview | what it registered as — its certificate subject, directory identity (and whether that entry is a [service account](#the-peps-entry-is-a-service-account), with its owners) and thumbprint, the date, its version, description, resource and bias — whether it is current and when it was last seen, the notify URL the nudge dials, and Stop nudging and Forget |
| Decisions | the counts it reports on its heartbeat, and how many policies it loaded |
| Settings | every setting this service sets for it (below) |
| Listener | two sub-tabs: **Configured Listeners**, every listener it has — the four its environment binds and the ones defined here — each with its protocol, address and port, purpose, state, certificate and source, each id a link to the listener's own page (below); and **Create a new listener**, the form that defines one and the environment's HTTPS pair with Issue or Reissue (below). Each listener is edited, renewed and removed on its own page |
| Reverse proxy | three sub-tabs: **Configured Routes**, whether the proxy is enabled, its upstream and public base URL, and its routes as a table, each id a link to the route's own page (below) and each application linked; **Create a New Route**, the form that adds one; and **Manifest**, the whole configuration document with Save, Remove, Download and Load from file (below). Each route, its application included, is edited on its own page |
| Signal streams | its CAEP/RISC stream health: the totals, then a table with one row per stream (below) |

**Every field and column on these tabs has a tooltip**, as do the Remote PEPs
table and the issue form. Hover over a field's name. Each tooltip says what
the field does, which values it takes and its default, when a change takes
effect and, for a setting, the precedence: a value set here, then the PEP's
environment variable, then the default. The tooltips are in all seven console
languages. This page and the management API's field descriptions say the
same things.

### Its listeners

The **Listener** tab is modelled on Server configuration → Listeners, in
two sub-tabs laid out as the Reverse proxy tab's are. **Configured
Listeners** (`#xacml-pep-listeners-configured`) is the table, one row per
listener the PEP has, each id a link to [the listener's own
page](#a-listeners-own-page). **Create a new listener**
(`#xacml-pep-listeners-new`) holds the form that defines one, laid out as
Create a New Route is — **Listener** (id, protocol, purpose), **Address**
(address, port) and **Certificate (HTTPS only)** (DNS names, IP addresses,
key), which shows only while the protocol is HTTPS — and once it is saved,
the new listener's page opens. Below it, under its own heading, is the
environment's HTTPS pair: the certificate issued, then the names and key
for the next one and Issue or Reissue. A listener's own page edits it in
the same layout. The listeners are:

* **The four its environment binds** — `api-http` (`PEP_PORT`), `api-https`
  (`PEP_HTTPS_PORT`), `proxy-http` (`PEP_PROXY_PORT`) and `proxy-https`
  (`PEP_PROXY_HTTPS_PORT`). They are what lets the PEP reach this service
  before it has pulled anything, so they are shown read-only and only its
  environment changes them. **The two plain-HTTP ones are off unless
  `PEP_HTTP` or `PEP_PROXY_HTTP` is `true`**. The tab shows each of them as
  *off* and names its switch. The two HTTPS ones serve the pair on the PEP's
  own mount, which **Issue certificate** at the bottom of the tab issues
  (*An HTTPS listener, certified by the realm it registered to*, above).
* **Any number defined here** (up to 32), each HTTP or HTTPS, for the
  decision API (`api`: `/protected`, `GET /` and the AuthZEN endpoints) or
  the reverse proxy (`proxy`), on an address and port of its choosing. They
  are kept on the PEP's entry (`xacmlPepListeners`), sent on the settings
  pull, and **bound, rebound and unbound while the PEP runs** — no restart.

For each, the PEP reports on its heartbeat whether it is `listening`,
`waiting` (an HTTPS listener with no certificate yet), `failed` or `off`, and
why — the address in use, a port it may not bind, an address that is not its
own, a refused certificate request, the proxy switched off — and the
certificate it serves: its subject, names, issuer, validity, serial and
SHA-256 fingerprint. A PEP older than this reports none, and the tab says so.

**An HTTPS listener defined here gets its certificate without its key ever
leaving the PEP.** The PEP generates the key (`ec-p256` unless the definition
names `ec-p384`, `rsa-2048` or `rsa-3072`), sends a PKCS #10 request to
`POST /xacml/pep/listener-certificate` over its mutual TLS, and is answered
the certificate from the realm's **Remote PEP listeners** Issuing CA and its
chain. The certificate names the PEP, its notify host and the definition's
DNS names and IP addresses — never what the request asks for. **Renew the
certificate** makes the PEP generate a new key and ask again on its next
pull; changing the names does the same, and so does a certificate with a
third of its life left.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"remote-pep-1","id":"public-https","protocol":"https","purpose":"proxy","port":8443,"dnsNames":["app.example.test"]}' \
  https://localhost:8081/realm/acme/admin-api/xacml/set-pep-listener
```

`remove-pep-listener` and `renew-pep-listener-certificate` take `name` and
`listener`. A definition is checked on save: the id (not one of the four),
`http` or `https`, `api` or `proxy`, an IP address and a port from 1 to
65535, no address and port another listener holds — the environment's as the
PEP last reported them — and, for HTTPS, at most 16 names of each kind and a
key it can generate. **In product mode a plain-HTTP reverse-proxy listener is
refused** (`STS-XACML-0249`) unless `xacml.pepPlainHttpProxyListeners` is on:
a browser signs in through the proxy and carries its session cookie there, so
in the clear it is right only behind something that terminates TLS.

* **An older PEP** never reads the definitions and binds only its
  environment's four.
* **A newer PEP talking to an older service** gets no definitions and binds
  only its environment's four.
* **A port that will not bind** is reported `failed` and tried again after
  the next pull (`STS-XPEP-0103`); the others are unaffected.

### A listener's own page

**Click a listener's id** in the Configured Listeners table to open
`/admin/xacml/pep/listener?pep=<name>&listener=<id>`. It is laid out as [a
route's own page](#a-routes-own-page): three rows of tabs — the XACML
page's with **Remote PEPs** open, the PEP page's with **Listener** open,
and the Listener sub-tabs with **Configured Listeners** open and the
listener drawn in it — each tab a link to its own page and anchor. Just
below the tab rows is **← Back to listeners**, then the heading **Listener
detail: <id>** with its protocol and address. The trail is *Admin console ›
XACML › Remote PEPs › the PEP › Listener › Configured Listeners › the
listener*.

* **Configuration**: the id, source, protocol, purpose, address and port,
  and for an HTTPS listener defined here its DNS names, IP addresses and
  key algorithm.
* **What the PEP reported**: where it listens, its state and why, and the
  certificate it serves (subject, names, issuer, validity, serial and
  SHA-256 fingerprint) beside the one this realm issued.
* **For a listener defined here**: the edit form (every value but the id,
  saved by `set-pep-listener` through the same checks as the create form),
  **Renew the certificate** for HTTPS, and **Remove** behind a
  confirmation box. A save stays on the page; a removal opens Configured
  Listeners.
* **For one of the environment's four**: the same page, read-only, with
  the variable that sets its port (and, for a plain-HTTP one, the switch
  that turns it on), since only the PEP's environment changes it.

The page answers `GET /admin-api/xacml/peps?pep=<name>`: the listener is a
row of that PEP's `listenerRows`, so the management API has no operation
of its own for it.

### Its routes, one at a time

The **Create a New Route** sub-tab of the **Reverse proxy** tab
(`#xacml-pep-proxy-new-route`) has a form to add a route — its path, prefix or exact, its methods, the
mechanisms it accepts, its application (found with a search of the
realm's applications, below), its authorization (below), whether credentials are
forwarded, whether CAEP/RISC signals end its sessions, and where it goes in
the list. Once it is saved, the new route's own page opens, as a new
application's does. To change a route, or the application it fronts, click
its id in the **Configured Routes** table (`#xacml-pep-proxy-routes`): its
own page holds the edit form (below). Every setting of the proxy itself
(`enabled`, `upstream`, `publicBaseUrl`, `upstreamTimeoutMs`,
`maxBodyBytes`) is a member of the document, changed on the **Manifest**
sub-tab (`#xacml-pep-proxy-manifest`). Every form saves the
whole document through the same checks as the editor, so a route a form can
save is a route the document could hold, and the reverse. The operations are
`set-pep-route` and `remove-pep-route`. `set-pep-route-application`, which
binds a route to an application of the registry, stays on the management
API, though the console no longer has a form for it.

### A route's own page

**Click a route's id** in the Configured Routes table to open
`/admin/xacml/pep/route?pep=<name>&route=<id>`. The trail is *Admin
console › XACML › Remote PEPs › the PEP › Reverse proxy › Configured Routes
› the route*: the PEP crumb opens the PEP's page, the Reverse proxy crumb
its Reverse proxy tab and the Configured Routes crumb that sub-tab. The
page draws three rows of tabs: the XACML page's, with **Remote PEPs**
open; inside it the PEP page's, with **Reverse proxy** open; and inside
that the sub-tabs, with **Configured Routes** open and the route drawn in
it. Every tab, the open ones included, is a link: an XACML tab opens
`/admin/xacml` at that tab, and a PEP tab or sub-tab opens the PEP's page
at that tab, so **Configured Routes** leads back to the list. Just below
the tab rows is **← Back to routes**, then the heading **Route detail:
<id>** with the route's path, and below it a fourth row, the route's own
tabs: **Metadata** (its effective state and the listeners that serve it),
**Edit the route** and **Remove the route**; a reader sees Metadata alone.
With no fragment Metadata is open. The trail ends at the open tab, *›
Configured Routes › the route › Edit the route*, and follows every tab
press, Back and Forward and a reload. A Save lands back on Edit the route,
and a refusal is drawn on the tab the form is on. A
PEP's own page draws the first two rows the same way.
The page answers `GET /admin-api/xacml/peps?pep=<name>&route=<id>`, whose
`routeDetail` member holds what the page draws.

* **Metadata**, the **Effective state**: whether the route is usable now (and why not), its
  application linked to the application's page, its position in the list,
  the PEP's upstream, and the reverse-proxy listeners that serve it, each
  with what the PEP last reported. Every proxy listener serves every route.
* **Edit the route**, one form for every value: the id, path and match, methods, the
  mechanisms, the application, the authorization, credential
  forwarding, signals, the position, and the identity (its mode, headers and
  claims, separator), one field per line, grouped under *Matching*,
  *Authentication*, *Authorization*, *Order* and *Identity sent to the
  application*. The Create a New Route form has the same layout and groups,
  without the identity. **Save** sends `set-pep-route` with the route's current
  id in `from` and every member of the form. The save goes through the same
  checks as the document editor and the other forms.
* **Methods** has a **None** and an **All** box on both forms, ahead of the
  seven methods. **All** ticks every method, which is how a route takes any
  method: the seven are stored. **None** unticks them all, and a route with
  no method is **deny-all**: its path still matches, so no later route is
  tried, the PEP asks the route's policy (so the decision is counted) and
  then refuses every request `403`: `STS-XPEP-0116`, or `STS-XPEP-0086`
  where the policy itself denied. Nothing reaches the application. Ticking a method by hand updates both.
  They are shortcuts only: the methods saved are the ones ticked. Through
  the API a route with no `methods` member is refused (`STS-XACML-0262`).
* **Authorization** is one selector with the matching fields below it:
  **An existing policy** (found with a search of the realm's policies a
  route may choose, and the action the PEP sends: the HTTP method, CRUD or
  read/write), **A simple policy** (an action model, CRUD or read/write, a
  box per action, and for each ticked action the roles that may take it,
  each found with a search of the realm's configured roles), or **Public**.
  The **XACML resource** box is shared: empty, a simple or public route is
  sent as the proxy's base URL and its path, and an existing-policy route as
  the request's path. On the route's page the application's home page
  (`appHomePageUrl`) is shown beside the default, with **Use** to take it,
  and a different origin is flagged; the policy that decides the route is
  linked to the editor, with why the PEP would refuse every request if it
  is missing, disabled or never sent to a PEP, and **Generate the policy
  again** rewrites a simple or public route's policy. A new route starts
  with no choice, and a save without one is refused (`STS-XACML-0263`).
* **The application is chosen by a search**, on this form and on Create a
  New Route alike. The chosen application is shown linked to its page. Type
  part of an application's identifier or name in the box and press **Find**
  (or Enter): the realm's applications are listed five to a page, with
  **Previous** and **Next**, each with **Use**, which makes it the route's
  application. **Clear** empties it. A public route names no application,
  and a route that checks credentials must name one, so the save refuses
  either mismatch (`STS-XACML-0197`). Find, Use and Clear save nothing and
  keep everything else typed in the form; only the form's own button saves.
* **Renaming is allowed.** Change the id and save. The page then opens at
  the new id. A new id that another route already holds is refused
  (`STS-XACML-0192`). Until the PEP's next poll, it holds the old document,
  so for that one poll interval, a request on the route may be refused
  while the PEP asks for an identity under the old id.
* **The upstream is not on the form.** The model has one upstream per PEP,
  not one per route. Change `upstream` in the configuration document on
  the Reverse proxy tab's **Manifest** sub-tab (`#xacml-pep-proxy-manifest`),
  which the page's note links to.
* **Remove** asks for a confirmation (a box to tick) and then sends
  `remove-pep-route`. The page lands on the PEP's Configured Routes. A route
  with a generated policy names it in the box, which sends
  `removePolicy: true`, and the policy goes with the route
  (`STS-XACML-0268` without it).

Opened without `route`, the page lists every PEP's routes as links.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8081/admin-api/xacml/peps?pep=pep-1&route=orders" | jq .routeDetail

curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"pep-1","from":"orders","id":"orders-api","path":"/orders",
       "match":"prefix","methods":["GET","POST"],"mechanisms":["session"],
       "application":"orders-app","authzKind":"simple",
       "authzActionModel":"read-write","authzActions":["read","write"],
       "authzRole.read":["orders-users"],"authzRole.write":["orders-admins"],
       "mode":"headers",
       "headerName":["X-Remote-User"],"headerClaim":["username"]}' \
  https://localhost:8081/admin-api/xacml/set-pep-route
```

### Moving a proxy configuration between PEPs

The **Manifest** sub-tab has four buttons on one row: **Save the
configuration**, **Remove the configuration** (tick its box first),
**Download** and **Load from file**.

1. On the PEP that has the configuration, press **Download**. The browser
   saves `<pep-name>-proxy.json`: the document exactly as it is stored and
   as the PEP pulls it, pretty-printed. It holds no secret. The document
   has no member that could hold one, and a URL in it may not carry a user
   name or password. A session route's client secret is read from its
   application's entry at each pull and is never in the document.
2. Open the other PEP's page, its **Reverse proxy** tab, **Manifest**, and
   press **Load from file**. Choose the file. Its text replaces what the
   editor holds. Nothing is saved yet, so you can change it first (for
   example `upstream`, or `publicBaseUrl`, which each PEP has its own of).
3. Press **Save the configuration**. The document goes through the same
   checks as any other save, `set-pep-proxy`. Every route's application
   must be in this realm's registry. A file from a PEP of another realm
   whose routes name that realm's applications is refused by name
   (`STS-XACML-0217`), and the stored configuration is kept.

The same file can be sent with the management API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg name pep-2 --slurpfile proxy pep-1-proxy.json \
        '{name: $name, proxy: $proxy[0]}')" \
  https://localhost:8081/admin-api/xacml/set-pep-proxy
```

### Several accounts in one browser

A session route with **`multipleAccounts: true`** (the route page's and the
route forms' *Several accounts*, false by default) lets one browser hold
several signed-in accounts and switch between them. This follows the pattern
of the `oidc-caep-risc` libraries' demo: an account set per browser, an
active account, adding an account, switching, and signing one or all out.

| Address on the proxy | What it does |
|---|---|
| `GET /.iya-pep/accounts?return=<path>` | the chooser: every account in this browser by username (and display name, where the service gives one), with its application, the active one marked, and *Switch to this account*, *Sign out*, *Add another account* and *Sign out of all accounts*. `?format=json` answers the same list as JSON. |
| `GET /.iya-pep/accounts/add?return=<path>` | signs another account in with `prompt=login`, so the service asks for a sign-in rather than reusing the session it holds. With `&account=<id>`, it signs that account in again, sending its `login_hint` and requiring that the ID Token name the same subject. |
| `POST /.iya-pep/accounts/switch` (`account`, `return`) | makes that account the active one |
| `POST /.iya-pep/accounts/logout` (`account`, `return`) | signs that account out here; the others stay |
| `POST /.iya-pep/accounts/logout-all` (`return`) | signs every account in this browser out here |

* **Only the active account's identity is forwarded**, through the route's
  identity mode. The proxy strips forged identity headers first and makes
  the same XACML decision as for a single sign-in. The account-set cookie
  (`iya_pep_accounts`) never reaches the application, even with
  `forwardCredentials`.
* **Each account is its own sign-on session at the service.** So a CAEP
  `session-revoked` (or a sign-out the session endpoint reports) ends only
  that account. No other account is made active in its place: a browser is
  sent to the chooser to pick one, and an API client gets a 401.
* **The bound** is the managed setting `proxyMaxAccounts`
  (`PEP_PROXY_MAX_ACCOUNTS`, 1 to 32, default 5). A sign-in past it is
  refused with the error page, status 403 (`STS-XPEP-0108`), rather than
  signing another account out. The same person signing in again replaces their own
  account's session.
* **The account pages** are the proxy's own: plain forms, no script, and
  `Content-Security-Policy: default-src 'none'; form-action 'self';
  frame-ancestors 'none'; base-uri 'none'`, `no-store`. A switch or sign-out
  posted from another site is refused (`STS-XPEP-0109`). The pages are in
  English: the PEP holds no message catalogs.
* **The active account is per browser, not per tab.** Every tab of one
  browser sends the same cookie, and the proxy cannot tell tabs apart
  without changing the application's URLs, which a proxy does not do. In
  one tab you can hold several accounts and switch between them. Two tabs
  show the same active account.
* **With iya-sts as the provider** (`authn.multipleAccounts`, on by
  default), adding an account adds a session to the service's own account
  set for that browser, so the person can also choose between the same
  accounts on the service's own pages.
* **Backwards compatible**: a route without the member is one sign-in per
  browser, as before. An older PEP ignores the member and serves one sign-in.

### Its signal streams

The **Signal streams** tab gives the totals, then a table with one row per
CAEP/RISC stream: the application and routes it serves (linked), its stream
id, whether it runs, when it started, last polled and last succeeded, its
failures in a row, its polls, the SETs it accepted and refused, the sessions
it ended, and healthy or stale. The times are worked out from the ages the
PEP reports and when the report arrived. A PEP older than the per-stream
report gives the totals only, and one that reports nothing is *not
reported*.

### The settings this service sets for it

Every setting the PEP used to take only from its environment, apart from the
minimum it needs to reach this service the first time, may be set on the
**Settings** tab or with `POST /admin-api/xacml/set-pep-settings`. They are
kept on the PEP's own entry (`xacmlPepSettings`), validated on save — a value
out of its bounds, outside its closed set or of the wrong type is refused
with a code — and the PEP pulls them from `GET /xacml/pep/settings` on every
poll and applies them without a restart.

**The precedence is the service's value, then the PEP's environment variable,
then the built-in default.** A box left empty is not set, so the PEP goes on
using its environment for it, exactly as it did before this page existed.
`clear-pep-settings` puts every setting back to the environment.

* **An older PEP** never asks for its settings and goes on using its
  environment.
* **A newer PEP talking to an older service** gets `404` for the settings
  pull, logs it once (`STS-XPEP-0101`) and uses its environment.
* **A value the PEP cannot read** (out of its own bounds) is left to the
  environment and logged (`STS-XPEP-0102`); a failed pull keeps what it holds
  (`STS-XPEP-0100`). A setting a newer service sends that the PEP does not
  know is ignored.
* **What it has in force** is reported on its heartbeat, each value with
  where it came from (`service`, `environment` or `default`), and the tab
  shows it beside what is set, and whether the PEP has applied the latest.
* **In product mode** `proxyUpstreamInsecure` and `proxyRpAllowInsecure`
  cannot be set to `true`.

When a change takes effect: at once for the bias, the PIP switch, the
timeouts, the body bound, the log level, the AuthZEN settings and the proxy
session bounds; from the next round of the timer for the poll, heartbeat and
back-off intervals; at the next re-read of the HTTPS pair for its interval;
and after the next poll for the JWKS lifetime and the relying-party and
CAEP/RISC bounds, which rebuild the proxy's relying parties. A library
session store keeps the bounds it was built with.

**What stays in the environment, and why**: `PEP_PDP_URL`, `PEP_NAME`,
`PEP_TLS_CERT`, `PEP_TLS_KEY`, `PEP_TLS_CA` and `PEP_TLS_INSECURE` are needed
to reach and authenticate to the service before the first pull; `PEP_PORT`,
`PEP_HTTPS_PORT`, `PEP_PROXY_PORT` and `PEP_PROXY_HTTPS_PORT` are the ports
of the four listeners that let the PEP connect first, and `PEP_HTTP`,
`PEP_CRL_HTTP` and `PEP_PROXY_HTTP` switch the plain-HTTP ones (further
listeners are defined on the Listener tab);
`PEP_HTTPS_CERT`, `PEP_HTTPS_KEY`, `PEP_CRL_DIR`, `PEP_AUTHZEN_CLIENT_CA` and
`PEP_PROXY_UPSTREAM_CA` name files on the PEP's own disk; `PEP_PROXY` says
whether the proxy's listeners start at all (its configuration's `enabled` is
the switch set on the Reverse proxy tab's Manifest sub-tab); and `PEP_AUTHZEN_CALLERS` is the
operator's own narrowing of the callers the service sends, which the service
could not set and still narrow anything.

## Configuration

From the environment, and — for every variable marked *managed* below — from
the PEP's page on the console as well, which wins where it sets a value (see
*The settings this service sets for it*). The service's value, then the
environment's, then the default.

| Variable | Default | |
|---|---|---|
| `PEP_PDP_URL` | `https://localhost:8081` | the service. Append `/realm/<id>` for a trust realm |
| `PEP_NAME` | `pep-1` | **ignored when a client certificate is presented** — the PDP names the row from the certificate |
| `PEP_TLS_CERT` / `PEP_TLS_KEY` | — | the client certificate. The leaf followed by the issuing CA |
| `PEP_TLS_CA` | — | an anchor for the PDP's certificate |
| `PEP_TLS_INSECURE` | `false` | do not verify the PDP. The ordinary setting against this service in development |
| `PEP_NOTIFY_URL` | derived | where the PDP should nudge: this PEP's HTTPS listener, `https://<host>:<PEP_HTTPS_PORT>/notify`. Unset, the PEP derives it (*The PEP derives its notify URL*). An `http://` value is rejected and no notify URL is advertised (`STS-XPEP-0113`) — *managed*: `notifyUrl`, https only |
| `PEP_BIAS` | `deny-biased` | this PEP's own. `permit-biased` is the other — *managed*: `bias` |
| `PEP_PIP` | `true` | resolve designators the request did not carry against the PDP's directory — *managed*: `pip` |
| `PEP_POLL_INTERVAL_MS` | `15000` | **the contract**, and the interval a failed registration is retried on — *managed*: `pollIntervalMs` |
| `PEP_HEARTBEAT_INTERVAL_MS` | `60000` | — *managed*: `heartbeatIntervalMs` |
| `PEP_PORT` | `9090` | the decision API's plain-HTTP port, bound with `PEP_HTTP=true`, or for the CRLs alone with it off |
| `PEP_HTTP` | `false` | `true` binds plain HTTP on `PEP_PORT` (*Plain HTTP is off by default*) |
| `PEP_CRL_HTTP` | *(unset)* | with `PEP_HTTP` off, `GET /crl/<name>` alone on `PEP_PORT`: bound by default where there is a CRL directory, `false` never, `true` always |
| `PEP_HTTPS_CERT` / `PEP_HTTPS_KEY` | — | the **listener's** pair, issued by the PEP's realm: the leaf followed by its chain, and the key. Both or neither. They may not exist yet when the container starts |
| `PEP_HTTPS_PORT` | `9443` | published on 9444 by `docker-compose.yml` |
| `PEP_HTTPS_RELOAD_INTERVAL_MS` | `5000` | how often the two files are re-read — *managed*: `httpsReloadIntervalMs` |
| `PEP_RESOURCE` | | the resource id used when a request names none — *managed*: `resource` |
| `PEP_AUTHZEN` | `true` | the AuthZEN edge PDP. `false` answers `501` — *managed*: `authzen` |
| `PEP_AUTHZEN_CLIENT_CA` | — | the CA bundle an AuthZEN caller's certificate must chain to. Unset, nobody is admitted |
| `PEP_AUTHZEN_CALLERS` | — | optional: a JSON array of `{ "name", "sha256", "applications" }`. Set, it narrows the callers pulled from the service to the certificates it names, and decides alone until the first caller pull; unset, the pulled list alone decides |
| `PEP_AUTHZEN_PDP_IDENTIFIER` | — | the PDP identifier the metadata names, an `https` origin with no path. Unset, the origin the request arrived at — *managed*: `authzenPdpIdentifier` |
| `PEP_AUTHZEN_FORWARD_TIMEOUT_MS` | `5000` | how long an evaluation forwarded to the service (an application that enforces fine-grained authorization) may take before the caller is answered `504` — *managed*: `authzenForwardTimeoutMs` |
| `PEP_PROXY` | `true` | the reverse proxy. Until the service sends a configuration, it answers `404` to everything |
| `PEP_PROXY_PORT` | `9180` | the proxy's plain-HTTP port, bound only with `PEP_PROXY_HTTP=true` |
| `PEP_PROXY_HTTP` | `false` | `true` binds the proxy's plain-HTTP listener on `PEP_PROXY_PORT` |
| `PEP_PROXY_HTTPS_PORT` | `9543` | the proxy's HTTPS listener, with the pair 9443 serves. It asks a client for a certificate and never requires one |
| `PEP_PROXY_SESSION_RECHECK_MS` | `5000` | on a `signals: false` session route: how old the service's last answer that a session is live may be. `0` asks on every access — *managed*: `proxySessionRecheckMs` |
| `PEP_PROXY_SESSION_TTL_MS` | `28800000` | the longest a proxy session lives — *managed*: `proxySessionTtlMs` |
| `PEP_PROXY_MAX_SESSIONS` | `10000` | the most proxy sessions held. A new one past it is refused `503` — *managed*: `proxyMaxSessions` |
| `PEP_PROXY_MAX_ACCOUNTS` | `5` | the most accounts one browser holds on a `multipleAccounts` route, 1 to 32. A sign-in past it is refused `403` — *managed*: `proxyMaxAccounts` |
| `PEP_PROXY_JWKS_TTL_MS` | `300000` | how long the realm's JWKS is kept — *managed*: `proxyJwksTtlMs` |
| `PEP_PROXY_SIGNALS_POLL_MS` | `5000` | how often the CAEP and RISC stream is polled — *managed*: `proxySignalsPollMs` |
| `PEP_PROXY_STRIP_COOKIES` | *(empty)* | more cookies the proxy never forwards upstream, beside the service's own: names separated by commas, a trailing `*` a prefix — *managed*: `proxyStripCookies` |
| `PEP_PROXY_SIGNALS_STALE_MS` | `60000` | how long the stream may go without a successful poll. After that, sessions are checked with the service's session endpoint until it answers again. `GET /` shows the stream's state under `proxy.signals` — *managed*: `proxySignalsStaleMs` |
| `PEP_PROXY_UPSTREAM_CA` | — | a path: anchors for an `https` upstream |
| `PEP_PROXY_UPSTREAM_INSECURE` | `false` | do not verify an `https` upstream — *managed*: `proxyUpstreamInsecure` |
| `PEP_PROXY_RP_ALLOW_INSECURE` | `false` | let the relying party use an `http` issuer, for development only. Redirect URIs stay https — *managed*: `proxyRpAllowInsecure` |
| `PEP_DESCRIPTION`, `PEP_TIMEOUT_MS`, `PEP_MAX_BODY_BYTES`, `PEP_BACKOFF_MAX_MS`, `PEP_LOG_LEVEL` | | *managed*: `description`, `timeoutMs`, `maxBodyBytes`, `backoffMaxMs`, `logLevel` |

## Against a trust realm

Point it at the realm's prefix and everything above works unchanged:

```bash
PEP_PDP_URL=https://localhost:8081/realm/acme \
cargo run --manifest-path rust/Cargo.toml --release -p xacml-pep
```

**The policy repository and the directory are both per realm**, so the policies
it pulls, the group membership that admits it and the attributes its PIP queries
resolve are all that realm's. `cn=remote-pep-1` and `cn=remote-peps` are seeded
in every realm; a PEP's entry, its **stored certificate** and its membership
are needed **in the realm it will pull from**, and a certificate stored on an
entry of the default realm authenticates to no entry in `acme` unless it is
stored there too.

## What guards this

Two tests, on opposite halves, and it is worth knowing which is which if you
change anything here:

- **`cargo test -p xacml-pep` and `cargo test -p sts-xacml`** (in `rust/`) hold
  the *shape*: the engine against the OASIS conformance suite, the PIP's walk,
  the listener's reload rules, and the enforcement rule against
  `xacml-pep/enforcement_cases.json` — the table **`tests/xacml_pep.js`** holds
  the service's own enforcement rule to as well, so the two agree over seven
  decisions under both biases — and the AuthZEN mapping against
  `xacml-pep/authzen_cases.json`, which **`tests/authzen_map.js`** holds the
  service's mapping to as well, and the caller list's grammar and the
  admission by it, and the forward of a fine-grained authorization
  evaluation — the only part that makes an HTTP request, to a mock service
  on a loopback port.
- **`tests/authzen_evaluation.js`** holds the service's side of the two
  AuthZEN pulls in process: the catalogue (K, with `fgaApplications` through
  a switch of enforcement) and the callers (P), whose names it checks
  against what the certificate door names over a real handshake.
  **`tests/protocol/sts_fga.js`** holds `fgaApplications` against a running
  service. No job drives the container's edge PDP itself over the network.
- **`tests/protocol/sts_xacml_remote_pep.js`** holds the *deployment*: this
  container on the service's own docker network, registering, pulling, converging,
  being nudged, reporting its counters, and going on deciding after the PDP is
  taken away — and being issued its listener certificate,
  picking it up without a restart, and answering a client that trusts only the
  service Root.
- **`tests/pep_listener_certificate.js`** holds the listener certificate's
  rules in process: a realm branch built before the Issuing CA existed gets it
  added rather than rebuilt, the certificate verifies through the realm's own
  Intermediate, and a reissue supersedes. That the container's reload never
  replaces a good pair with a bad one is `rust/bins/xacml-pep`'s own test.

## See also

- [Authorization overview](authorization.md) — every authorization decision this service makes, and where each is documented
- [What is not checked](what-is-not-checked.md) — the permissive posture, and where this family is the exception
- [Trust realms](trust-realms.md) — what a realm separates
- [Configuration](configuration.md) — how the service's own settings resolve, `xacml.*` among them
