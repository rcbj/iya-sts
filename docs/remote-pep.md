---
title: Remote PEP
nav_order: 15
---

# The remote Policy Enforcement Point

`xacml-pep/` is a **second container**. It holds its own copy of this service's
XACML engine, **pulls** the policy repository from the mock's Policy Decision
Point, and decides in its own process. The mock never sees the requests it
decides.

It is the one directory in this repository that is not part of the mock, and it
is opt-in: a plain `docker compose up` does not start it.

```
   your client                xacml-pep                     iya-sts
                          (the PEP: engine                (the PDP, the PAP,
                           + pulled policy)                and the PIP)

  GET /protected  ──────────▶  decides HERE
                               200 / 403
                                    │
                                    ├── GET  /xacml/pep/policies ──▶  pull, every 15s
                                    ├── POST /xacml/pip ───────────▶  attributes, per decision
                                    ├── POST /xacml/pep/register ──▶  a row on the console
                                    ├── POST /xacml/pep/heartbeat ─▶  counters, every 60s
                                    │
                               POST /notify  ◀────────────────────── the nudge (optional)
```

## Why not just use `/xacml/protected`

The mock already has a Policy Enforcement Point at `GET /xacml/protected`, and
for learning what a PEP *is* it is the better one to read. What it cannot
demonstrate is anything that makes a **distributed** deployment hard, because it
shares a process with the PDP: it can never be stale, can never hold a policy the
PDP no longer has, and can never go on enforcing while the PDP is down.

Every one of those is a state a real deployment lives in, and this container
makes all of them reachable — and reports them rather than hiding them.

## Its four endpoints

| | |
|---|---|
| `GET /` | what this PEP is, what it holds, what it has enforced. **The page to read first when something is wrong** |
| `GET /protected` | the protected resource: 200 or 403, decided here |
| `POST /notify` | the PDP's nudge, meaning *pull now*. Answers 204 and pulls afterwards |
| `GET /healthcheck` | liveness. It deliberately does **not** ask whether the policy is current |

They are plain HTTP on port 9090 — and the same four over **HTTPS on 9443**
once the PEP has been given a certificate by the realm it registered to, which
is the section below. The container generates no key of its own: both key pairs
it can hold, the client certificate and the listener's, are handed to it.

## The quickest look

```bash
docker compose --profile xacml up --build

curl -s http://localhost:9090/ | jq '.holding, .registration.why'
```

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
   truststore with `POST /tls/trust`, which starts empty — in development mode.
   In product mode that endpoint is refused; add the CA at runtime on the admin
   console's `/admin/tls/trust` page (Admin Write) or with
   `POST /admin-api/tls/trust/add` (a token carrying `admin:write`), or put it
   in a PEM file named by `tls.trustAnchorsFile`, read at startup. Only the file
   survives a restart — the two runtime doors persist nothing.
2. **A subject DN that resolves to a directory entry.** A certificate resolving
   to no entry is an unauthenticated caller however well it verifies.
3. **That entry in the group `roles.remotePepGroup` names** — `remote-peps` by
   default, which is what grants the built-in `REMOTE_PEPS` role.

`cn=remote-pep-1` and `cn=remote-peps` are **seeded in every realm** with the
first already a member of the second, so using that common name costs you only
step 1. A second enforcement point needs its own entry and its own membership.
**In development mode.** In product mode the group (named by
`roles.remotePepGroup`) is seeded EMPTY and `cn=remote-pep-1` is not seeded at all —
a predictable identity printed in this repository is not a grant a deployment should
inherit — so every enforcement point needs its entry and its membership.

### Minting the certificate

`tests/tools/pep-credential.js` builds a Root CA, an Issuing CA and a client leaf
on this repository's own PKI code, writes them out, and POSTs the **root alone**
to the mock's truststore — so the mock has to build a path from what arrives to
an anchor it holds, which is the commonest thing to get wrong in mutual TLS.

```bash
node tests/tools/pep-credential.js \
  --url=https://localhost:8081 \
  --out=/tmp/pep-certs \
  --subject="CN=remote-pep-1,OU=remote-peps,O=mock-sts"
```

**The flags take `=`**; a space between the flag and its value is reported as an
unknown option. It writes `pep.crt` (the leaf **followed by** the issuing CA),
`pep.key`, `ca.crt` and `chain.txt`, and prints the leaf's DN as its last line.

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
API. Pin the seeded client's secret with `adminApi.clientSecret`
(`ADMIN_API_CLIENT_SECRET`) before starting the service, or the secret is minted
per start and readable only through the API it unlocks.

```bash
TOKEN=$(curl -sk -u sts-management-api:$ADMIN_API_CLIENT_SECRET \
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

The console does the same thing at `/admin/xacml/policies`, with a guided editor
that has no JavaScript in it.

### 3. Start the PEP

```bash
docker compose --profile xacml up --build      # with the volume above
```

or, against a checkout, with no container at all:

```bash
PEP_PDP_URL=https://localhost:8081 \
PEP_NAME=remote-pep-1 \
PEP_TLS_CERT=/tmp/pep-certs/pep.crt \
PEP_TLS_KEY=/tmp/pep-certs/pep.key \
PEP_TLS_INSECURE=true \
PEP_RESOURCE=https://expenses.example.test \
node xacml-pep/pep.js
```

`PEP_TLS_INSECURE=true` is the ordinary setting against this mock: in
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
`urn:sts:xacml:attribute:` form the mock's own PIP answers to.

```bash
curl -s ".../protected?subject=carol&resource=https://expenses.example.test&action=GET&employeeType=staff"
# 200 — carol is an admin in the directory and said she was staff
```

That is not a bug and it is not a hole the PIP closes. **A PIP removes the
disagreements that come from missing information; it does not remove the ones
that come from a caller asserting something about itself**, which no real
deployment would believe and which is exactly the sort of thing a mock exists to
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

By default the compose service's nudge is **refused**, because its notify URL is
plain `http` and `xacml.pepNotifyAllowHttp` is off. That is the design
demonstrating itself: no nudge is delivered, the PDP says why on the PEP's row,
and the PEP converges on its poll anyway. Set
`STS_XACML_PEP_NOTIFY_ALLOW_HTTP=true` on a mock in development mode to watch
the other half; product mode refuses a plain-http nudge whatever it says
(#171), and a PEP it nudges must serve https with a certificate that verifies,
against node's store or `xacml.pepNotifyCaFile`.

## When the PDP goes away

**The last good policy set is kept and enforcement continues.** Stop the mock and
the PEP goes on deciding correctly in both directions — still permitting what the
last pulled policy permits, still refusing what it refuses — while `GET /`
reports `lastPullOk: false` and says it is keeping what it has.

That is a real trade and both ends say so rather than hiding it: **a policy
change made during an outage is not enforced here until the next successful
pull.** The alternative, a PDP outage denying everything everywhere, is the
failure mode that makes people remove authorization services.

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
   registered name and the host of its notify URL too:

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
   jq -r .fullChainPem  issued.json > certs/server/pep-server.crt   # leaf + Issuing CA + Intermediate
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

**Plain HTTP stays on 9090.** The container's healthcheck uses it, and turning it
off is a decision for your network edge. `/admin/xacml/peps` says which
certificate the realm *issued*; only the PEP's `GET /` can say which one it is
*serving*.

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

**The two ends can disagree about staleness, and that is deliberate**: this PEP
counts missed *polls* and the PDP counts missed *heartbeats*. A PEP pulling
happily while its heartbeats are dropped looks fine here and stale there. Both
numbers are visible so that state is recognisable.

The PDP's side of it is `/admin/xacml/peps` in the console, or
`GET /admin-api/xacml/peps`, which carries each PEP's name, whether it
authenticated, its build, its policy count, its sync token and the decision
counters it reported. **Those counters arrive on the heartbeat**, once a minute
by default, so a freshly started PEP reads as zeroes for up to a minute.

## Configuration

All of it from the environment — there is no appconfig file and no settings
table here, because the mock's five-layer configuration exists to serve a console
and a PEP has none.

| Variable | Default | |
|---|---|---|
| `PEP_PDP_URL` | `https://localhost:8081` | the mock. Append `/realm/<id>` for a trust realm |
| `PEP_NAME` | `pep-1` | **ignored when a client certificate is presented** — the PDP names the row from the certificate |
| `PEP_TLS_CERT` / `PEP_TLS_KEY` | — | the client certificate. The leaf followed by the issuing CA |
| `PEP_TLS_CA` | — | an anchor for the PDP's certificate |
| `PEP_TLS_INSECURE` | `false` | do not verify the PDP. The ordinary setting against this mock |
| `PEP_NOTIFY_URL` | — | where the PDP should nudge |
| `PEP_BIAS` | `deny-biased` | this PEP's own. `permit-biased` is the other |
| `PEP_PIP` | `true` | resolve designators the request did not carry against the PDP's directory |
| `PEP_POLL_INTERVAL_MS` | `15000` | **the contract**, and the interval a failed registration is retried on |
| `PEP_HEARTBEAT_INTERVAL_MS` | `60000` | |
| `PEP_PORT` | `9090` | |
| `PEP_HTTPS_CERT` / `PEP_HTTPS_KEY` | — | the **listener's** pair, issued by the PEP's realm: the leaf followed by its chain, and the key. Both or neither. They may not exist yet when the container starts |
| `PEP_HTTPS_PORT` | `9443` | published on 9444 by `docker-compose.yml` |
| `PEP_HTTPS_RELOAD_INTERVAL_MS` | `5000` | how often the two files are re-read |
| `PEP_RESOURCE` | | the resource id used when a request names none |
| `PEP_DESCRIPTION`, `PEP_TIMEOUT_MS`, `PEP_LOG_LEVEL` | | |

## Against a trust realm

Point it at the realm's prefix and everything above works unchanged:

```bash
PEP_PDP_URL=https://localhost:8081/realm/acme node xacml-pep/pep.js
```

**The policy repository and the directory are both per realm**, so the policies
it pulls, the group membership that admits it and the attributes its PIP queries
resolve are all that realm's. `cn=remote-pep-1` and `cn=remote-peps` are seeded
in every realm; a PEP under a different common name needs its entry and its
membership created **in the realm it will pull from**, and a certificate that
works against the default realm authenticates to no entry in `acme` if that name
is not there.

## What guards this

Two tests, on opposite halves, and it is worth knowing which is which if you
change anything here:

- **`tests/xacml_pep.js`** holds the *shape*: the engine loads with none of the
  mock's modules present, the image copies exactly the engine's module list, and
  the PEP's enforcement rule agrees with the mock's over seven decisions under
  both biases. It makes no HTTP request at all.
- **`tests/vendored/sts_xacml_remote_pep.js`** holds the *deployment*: this
  container on the mock's own docker network, registering, pulling, converging,
  being nudged, reporting its counters, and going on deciding after the PDP is
  taken away — and being issued its listener certificate,
  picking it up without a restart, and answering a client that trusts only the
  service Root.
- **`tests/pep_listener_certificate.js`** holds the listener certificate's
  rules in process: a realm branch built before the Issuing CA existed gets it
  added rather than rebuilt, the certificate verifies through the realm's own
  Intermediate, a reissue supersedes, and the container's reload never replaces
  a good pair with a bad one.

## See also

- [What is not checked](what-is-not-checked.md) — the permissive posture, and where this family is the exception
- [Trust realms](trust-realms.md) — what a realm separates
- [Configuration](configuration.md) — how the mock's own settings resolve, `xacml.*` among them
