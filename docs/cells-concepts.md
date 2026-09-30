---
title: How cells work
nav_order: 20
---

# How cells work, with diagrams

[Several regions (cells)](cells.md) says what an operator sets and what a
person sees. This page explains the machinery behind it, one idea at a time.
Every diagram shows a two-cell service: cell `usw2` in the United States and
cell `cac1` in Canada.

## 1. The words

| Word | Meaning |
|---|---|
| **Cell** | One complete copy of the service in one region, with its own database. Every cell runs every protocol. |
| **Jurisdiction** | The legal area a cell sits in, such as `us`, `ca` or `eu`. Several cells may share one. |
| **Geography** | A label for grouping cells, such as North America. It routes nothing and decides nothing. |
| **Home** | The one cell where a person's data lives. Every person has exactly one. |
| **Global tier** | The configuration every cell needs and that holds no personal data. There is one writable copy for the whole service. |
| **Cell tier** | Everything about the people homed in a cell, and everything that cell minted. It never leaves the cell's jurisdiction. |
| **Relay** | Passing a request, whole, to the cell that owns it, and passing that cell's answer back. |
| **Projection** | A copy of a person's entry with every credential removed, lent to another cell so it can hold their session. |

## 2. One name, many cells

Clients see one service. Every cell answers on the same public name, signs
with the same keys and publishes the same metadata, so no client can tell
which cell answered.

```
                      https://idp.example.com
                     (one name, one issuer, one JWKS)
                                  │
                        DNS: geolocation, then
                        latency to a healthy cell
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
   ┌──────────────────────────┐   ┌──────────────────────────┐
   │ cell usw2   jurisdiction │   │ cell cac1   jurisdiction │
   │ us-west-2   us           │   │ ca-central-1  ca         │
   │                          │   │                          │
   │  nodes ── cell database  │   │  nodes ── cell database  │
   │     │     (people homed  │   │     │     (people homed  │
   │     │      here)         │   │     │      here)         │
   │     │                    │   │     │                    │
   │     └── global database  │   │     └── global replica   │
   │         (THE writer)  ───┼───┼──▶     (read-only copy)  │
   └────────────┬─────────────┘   └────────────┬─────────────┘
                │   inter-cell channel, 8446    │
                └──────── mutual TLS 1.3 ───────┘
                   (private addresses only)
```

- **The public name** routes by country first, where a country is pinned to
  a cell, and otherwise to the nearest healthy cell.
- **The inter-cell channel** is private. It is on no public load balancer,
  and no published document names a cell or its address.

## 3. Two tiers: what is shared and what stays

Every stored thing belongs to exactly one tier. `persistence/tiers.js`
decides which, and a test fails if a new store is added without being
classified. There is no default tier, because a default would be a default
answer to "which country may this person's data be in".

```
  GLOBAL TIER  (one writer; a read replica in every cell)
  ┌────────────────────────────────────────────────────────────────────┐
  │ realms   settings   applications   policies (XACML)   roles        │
  │ signing keys   certificate authorities   federation partners       │
  │ a group's DEFINITION, and its non-person members                   │
  │ an application's devices                                           │
  │ the ROUTING INDEX: keyed digests only, never a name or an address  │
  └────────────────────────────────────────────────────────────────────┘
                 ▲ read locally           │ writes go to the one writer
                 │                        ▼
  CELL TIER  (one per cell; never replicated out of the jurisdiction)
  ┌────────────────────────────────────────────────────────────────────┐
  │ RESIDENT: the people homed here and their credentials, second      │
  │           factors, devices and group memberships                   │
  │ LOCAL:    sessions, codes, refresh tokens, consent records and     │
  │           risk history that this cell minted                       │
  │ sealed under THIS CELL's own key-encryption key                    │
  └────────────────────────────────────────────────────────────────────┘
```

**A group is split in two.** Its definition is configuration, so it is
global. Its members who are people are personal data, so each cell holds only
the members homed there:

```
  cn=admins (global half)           cn=admins (cell half, in usw2)
  ├── description, owner, ...       ├── member: uid=alice   (homed in usw2)
  └── member: an application        └── memberUid: alice

                                    cn=admins (cell half, in cac1)
                                    └── member: uid=bob     (homed in cac1)
```

A cell reads the group as the two halves joined. `memberUid` values are login
names, so they always go to the cell half.

## 4. Keys: which are shared and which stay in one region

```
                     ┌─────────────────────────────┐
                     │ SERVICE key-encryption key  │  the same in every
                     │ (operator-provided)         │  cell
                     └──────────────┬──────────────┘
          seals and opens           │
   ┌────────────────────────────────┼─────────────────────────────┐
   ▼                                ▼                             ▼
 realm signing keys          certificate authorities      the keyed digests
 (one set per realm,         (one Root, an Intermediate   of the routing
  SHARED by every cell,      per realm, and a `cell`       index and the
  so a token from any cell   Issuing CA for the channel)   locator tags
  verifies everywhere)

   ┌─────────────────────────────┐   ┌─────────────────────────────┐
   │ CELL key-encryption key     │   │ CELL key-encryption key     │
   │ usw2: in us-west-2 only     │   │ cac1: in ca-central-1 only  │
   └──────────────┬──────────────┘   └──────────────┬──────────────┘
                  ▼                                 ▼
     usw2's resident and local rows    cac1's resident and local rows
```

- **Where a cell key lives.** A cell key exists only in its own region. A
  copy of a cell's database taken to another region cannot be read there.
- **No fallback.** In product mode a cell refuses to start without its cell
  key, and it refuses a cell key that equals the service key.
- **New realm keys.** When a realm is created, every cell has to end up with
  the same signing keys. The cells arbitrate through the global tier, so
  exactly one set wins.

## 5. The routing index: finding a person's home

Any cell may be asked about anyone, so every cell needs to find a person's
home without holding the person. The routing index is a global table of keyed
digests:

```
   keyed digest under the service key of
     realm + "\n" + "name" + "\n" + lower(login name)
     realm + "\n" + "uuid" + "\n" + lower(entryUUID)
                        │
                        ▼
   ┌────────────────────────────────────┬────────┐
   │ digest (unreadable without the key)│ cell   │
   ├────────────────────────────────────┼────────┤
   │ 9f2c...e1                          │ usw2   │   ← alice, by name
   │ 03ab...77                          │ usw2   │   ← alice, by entryUUID
   │ c4d1...0b                          │ cac1   │   ← bob, by name
   └────────────────────────────────────┴────────┘
```

- **No names in the global tier.** A reader of the global database learns how
  many people each cell holds, and no one's name.
- **One claim per login name, service-wide.** A creation from the console,
  `/admin-api` or SCIM claims the name first. If another cell already holds
  it, the answer is `409 conflict`. A creation that names another home is
  relayed there, and the home cell claims the name before it answers. A
  sign-in may follow at once.

```
   admin at usw2: create "carol", homeCell=cac1
        │
        ▼
   usw2 ── relay ──▶ cac1: claim "carol" in the routing index ──▶ create
        ◀───────────────────────── 200 ────────────────────────────┘

   admin at usw2: create "carol" again
        │
        ▼
   usw2: claim "carol" → already cac1's → 409 conflict (nothing is created)
```

## 6. The inter-cell channel

Cells talk to each other for only two reasons.

```
   RELAY    a whole HTTP request that belongs to the other cell
   ─────    usw2 ──[the client's request, verbatim]──────────────▶ cac1
            usw2 ◀─[cac1's answer, piped back unchanged]────────── cac1

   OP       a JSON operation one cell asks of another
   ──       usw2 ──POST /_cell/v1/subject-state {realm, uuid}────▶ cac1
            usw2 ◀─{ enabled, signedOutAt, pwdChangedTime, ... }── cac1
```

- **Who counts as a cell.** A peer is accepted only when its certificate
  meets all three conditions:
  - it chains to the service Root;
  - it was issued by the `cell` Issuing CA;
  - it names a configured cell in a `urn:sts:cell:<id>` subject alternative
    name.

  A person's TLS client certificate also chains to the Root, so the first
  condition alone would not be enough.
- **What the client sent is preserved.** A relay forwards the client's
  address, its TLS client certificate and the host it addressed. The sending
  cell strips any `x-sts-cell-*` header the client tried to set. The
  receiving cell trusts those headers only from an authenticated peer.
- **One hop.** A relayed request is never relayed again. A cell that receives
  something it does not own answers it as best it can, so two cells that
  disagree cannot pass a request back and forth.

## 7. Placement: which cell serves a request

DNS delivers a request to some cell. Placement decides whether that cell
serves it or relays it. Every route has a row in one table
(`common/cell_placement.ts`), and a test fails on a route no row covers.

```
                 request arrives at the cell DNS chose
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
   AT THE EDGE (before the body is read)   IN THE HANDLER (reads the body)
   ─────────────────────────────────────   ───────────────────────────────
   affinity  the browser's sts_cell        a code or refresh token at
             cookie pins it to a cell      /oauth2/token; a login name at
   artifact  a code, request_uri,          /authn/login; a SAML artifact
             device code... in the URL     in a SOAP body; a SCIM userName
   bearer    an access token's jti         ...
   selector  ?cell=<id> on /admin-api
   local     metadata, keys, scripts:
             every cell answers the same
               │                                     │
               └──────────────────┬──────────────────┘
                                  ▼
                 owner is this cell? ── yes ──▶ serve here
                                  │
                                  no
                                  ▼
                  relay to the owner over the channel
```

| Strategy | Examples | How the owning cell is found |
|---|---|---|
| `local` | `/.well-known/*`, `/oauth2/jwks`, scripts | It isn't needed: every cell answers the same. |
| `affinity` | `/authn`, `/oauth2`, `/saml2`, `/admin` | The browser's `sts_cell` cookie, when present. |
| `artifact` | `/oauth2/authorize?request_uri=…`, `/oid4vp/request` | The locator tag on the artifact (section 8). |
| `bearer` | `/oauth2/userinfo`, `/oid4vci/credential` | The locator tag on the access token's `jti`. |
| `selector` | `/admin-api/…?cell=cac1` | The administrator named the cell. |
| `handler` | `/oauth2/token`, `/authn/login`, `/scim` | The handler reads the body and asks. |

**The affinity cookie** holds `<realm>:<tag>` for each realm, where the tag
is the keyed tag from section 8. The cookie cannot be decoded into a cell
name. A browser is pinned when its session is minted in a cell, and when
section 9's restart sends it home.

## 8. The locator: which cell minted an artifact

A relying party's server resolves the public name to the cell nearest *it*,
which is often not the cell nearest the browser. So a code minted in `cac1`
is often redeemed at `usw2`. Each artifact therefore carries a short keyed
tag naming the cell that minted it:

```
  authorization code, refresh token, device code, CIBA id,
  request_uri, OpenID4VC transaction, GNAP handle, ACME id:

     ┌──────────── random value ─────────────┬── tag (12 chars) ──┐
     │ Xq3bG8...nR0                          │ kP4vZ1aQwE9s       │
     └───────────────────────────────────────┴────────────────────┘
                                   tag = first 72 bits of
                                   HMAC(service key, cell id)

  SAML artifact (fixed layout, so the tag goes inside the handle):

     TypeCode │ EndpointIndex │ SourceID (20) │ MessageHandle (20)
                                              ├─ 16 random ─┬ tag 4 ┤
```

- **Nothing readable names a cell.** Without the key a tag is noise. The
  only thing an outsider can see is that two artifacts share a suffix.
- **No new characters.** The stamped value is still base64url, only twelve
  characters longer, so no validation rule had to change.
- **SAML keeps the specification's floor.** A SAML handle keeps the 16
  random bytes the specification requires, so its tag is 4 bytes. If two
  cells' 4-byte tags collide, the artifact is served where it lands.
- **Single-cell mode stamps nothing.**

## 9. Signing in away from home: the restart (D9)

A person homed in `cac1` reaches `usw2` and starts signing in. The password
is never read in `usw2`: the flow restarts at home.

```
 browser                usw2 (visiting)                  cac1 (home)
    │                         │                                │
    │ GET /oauth2/authorize   │                                │
    ├────────────────────────▶│ records where the flow started │
    │◀── 302 /authn/login ────┤                                │
    │ POST username=bob       │                                │
    ├────────────────────────▶│ routing index: bob → cac1      │
    │                         │ (the password is NOT read)     │
    │◀── 302 back to /oauth2/authorize,                        │
    │    Set-Cookie: sts_cell=<realm>:<cac1's tag>             │
    │                         │                                │
    │ GET /oauth2/authorize   │ the cookie pins it to cac1     │
    ├────────────────────────▶│── relay ──────────────────────▶│ runs the
    │                         │                                │ whole
    │  ... sign-in screen, password, second factor, consent ...│ flow HERE
    │◀────────────────────────┼◀───────────────────────────────┤
    │ 302 to the client with ?code=...<cac1's tag>             │
```

The person types their username twice. Nothing personal crosses into `usw2`:
not the password, and not the entry.

- **A pushed authorization request** (RFC 9126) names the cell that stored
  it, so it is handed to the home cell before the browser goes there.
- **A federation partner's assertion** about a person homed elsewhere
  restarts the flow at home in the same way.
- **This service's own console and portal** restart from their own start
  page, because their authorization request is already the second step of a
  flow they began.

## 10. Holding a session near the traveller (D4, D6)

By default the session stays at home, and every later request is relayed
there. That is always lawful, and slower. If the realm lists the transfer
(`cells.permittedTransfers`, for example `ca>us`) and the policy allows it,
home copies the session to the visiting cell:

```
     cac1 (home)                                        usw2 (visiting)
 ┌──────────────────┐   adopt-session: the session  ┌──────────────────────┐
 │ bob's entry      │   plus a PROJECTION           │ bob's PROJECTION     │
 │  userPassword    │ ─────────────────────────────▶│  cn, mail, groups... │
 │  totpSecret      │   (every credential removed)  │  no password         │
 │  keys, devices   │                               │  no second factor    │
 │  memberOf ...    │   pin moves to usw2 on the    │  no private keys     │
 │                  │   response that leaves the    │ sealed under usw2's  │
 │ export recorded: │   service                     │ cell key, in memory  │
 │  usw2 holds one  │                               │ only; never a row    │
 └────────┬─────────┘                               └──────────┬───────────┘
          │                                                    │
          │ HOME STAYS IN CHARGE                               │
          │   disable, password change, sign-out everywhere:   │
          ├── revoke-subject / refresh-projection ────────────▶│ (a durable,
          │                                                    │  retried
          │   before a refresh or a token exchange, and        │  delivery)
          │   whenever the last answer is older than           │
          │   cells.subjectCheckS:                             │
          │◀─────────────── subject-state? ────────────────────┤
          ├──────── { enabled, signedOutAt, ... } ────────────▶│
          │                                                    │
          │   a write to the projection (such as consent)      │
          │◀────────────── projection-write ───────────────────┤
          │   applied at home; a credential in it is refused   │
```

- **What a moved session carries.** Its identity, and for each
  authentication its method, level and time. It carries no IP address, user
  agent or fingerprint: that context stays in the risk history at home.
- **The portal is always served at home**, because it edits the person's
  own entry.
- **A sign-in or step-up is always at home.** The projection never answers
  "this person is homed here".

**When home cannot be reached:**

```
   usw2 asks cac1 "subject-state?" ── no answer ──▶ cells.homeUnreachable
                                                         │
                        ┌────────────────────────────────┴──────────┐
                        ▼                                           ▼
               fail-closed  (default)                    fail-open
               refresh:   invalid_grant                  refresh: allowed for
               sign-in:   503 (STS-CELL-0030)            cells.failOpenGraceS
               LDAP bind: unavailable (52)               sign-in: still 503
                                                         (a new sign-in
                                                          always needs home)
```

> **Warning.** In `fail-open`, a disable or revocation made at home during
> the outage is not seen in other cells until home answers again.

## 11. Every border decision is policy

Code gathers facts, and the realm's XACML issuance policy decides. Three
questions are asked, each with its own action:

```
   facts ──────────────────────────────────────────▶ issuance policy
     home jurisdiction          (cac1 → ca)             │
     serving jurisdiction       (usw2 → us)             │  built-in rules =
     the client's country       (when known)            │  the strict default;
     transfer listed?           (cells.permittedTransfers)  a realm's own
     hard geofence?             (cells.hardGeofence)    │  policy may differ
                                                        ▼
   ┌──────────────────────┬──────────────────────────────────────────────┐
   │ hold-session         │ May the session and projection be held here? │
   │                      │ No → stays at home, relayed. Not a refusal.  │
   ├──────────────────────┼──────────────────────────────────────────────┤
   │ serve-request        │ May this cell handle the request at all,     │
   │                      │ even by relaying it? No → refused (the hard  │
   │                      │ geofence).                                   │
   ├──────────────────────┼──────────────────────────────────────────────┤
   │ release-attributes   │ May this cell's residents be shown to a      │
   │                      │ reader at a cell in another jurisdiction?    │
   │                      │ Asked by the cell that holds them.           │
   └──────────────────────┴──────────────────────────────────────────────┘
```

With the defaults, a session is held only where the realm lists the
transfer, every request is served (by relaying where needed), and residents
are released only where the transfer is listed.

## 12. Administering several cells (D11)

Each cell answers management reads with its own residents. To reach another
cell's residents, an administrator names that cell, and the cell that holds
the people asks its release policy before it answers:

```
   admin ─▶ usw2: GET /admin-api/users                 → usw2's people only
   admin ─▶ usw2: GET /admin-api/users?cell=cac1
                  usw2 ── relay ──▶ cac1: release-attributes?
                                     ├─ permit   → cac1's people
                                     └─ withhold → refused, STS-CELL-0184
```

**Server configuration → Cells** (`/admin/cells`, and `GET /admin-api/cells`)
shows:
- each cell, its jurisdiction, and whether it can be reached;
- the store tiers;
- the channel's status;
- the number of people homed in each cell.

The configured peer list, with its private addresses, appears only in the
administrators' settings block.

## 13. Moving a person to another cell

Only an administrator moves a person's home, and does it at the cell that
holds them now. Where a person signs in never moves them.

```
  cac1 (current home)                                  usw2 (new home)
   1. check the target: a known cell, in a jurisdiction the realm allows
   2. end everything bob holds, here and in every cell holding an export
   3. open bob's sealed values under cac1's key
   4. adopt-person ────────────────────────────────▶ seal them again under
      (entry + devices + group memberships,           usw2's key; keep the
       entryUUID carried, so `sub` is unchanged)     SAME entryUUID
   5. move the routing index rows ─────────────────▶ bob → usw2
   6. remove bob's entry, devices and memberships from cac1
```

Re-homing is the only act that sends a person's credentials between cells,
and it is exactly what a residency move is: the data then lives in the new
cell.

## 14. Background jobs: once per cell, or once for the service

A cluster job runs on one node of its cluster, and each cell is its own
cluster. That suits cell work, but a job that changes global state would run
once in every cell. Those jobs claim their runs in the global tier instead:

```
   cell work (claimed in the cell's database)   global work (claimed in the
                                                global database)
   ─────────────────────────────────────────    ───────────────────────────────
   session sweep, mail delivery, cache          signing-key rotation, krbtgt
   ejection, this cell's deliveries,            rotation, SPIFFE authority,
   the change-log pull ...                      OpenID Federation key,
                                                client-secret expiry, used-
   runs in EVERY cell                           assertion purge ...

                                                runs in ONE cell per slot
```

The list is `GLOBAL_JOBS` in `persistence/tiers.js`, and a new job that
writes global state belongs on it.

## 15. What is not placed yet

A Kerberos request sent over raw TCP or UDP port 88 is answered by the cell
that receives it. The KDC's socket code belongs to the parent project, which
needs a hook for it (rcbj/id-proto-debugger#317). Over HTTPS, at
`/KdcProxy`, a Kerberos request is placed at the client's home like any other
request.

## 16. Trying it on one machine

```
./run-tests.sh --modes=cells --only=sts_cells --protocol=only --no-browser
STS_TEST_CELLS_ENTRY=b ./run-tests.sh --modes=cells  # whole suite via cell B
```

These start two cells (`cella` in `us` and `cellb` in `ca`), a global
database, and a switchable link between the cells. They run the nine
`sts_cells_*` jobs, which check every idea on this page over HTTP.
[A cluster in AWS](aws-cluster.md) describes the same arrangement in AWS
regions.
