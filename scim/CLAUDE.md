# scim/

SCIM 2.0 (RFC 7642/7643/7644) — a provisioning endpoint at `/scim/v2` that writes
into the LDAP directory, entry for entry, with **no store of its own**.

| File | What it is |
|---|---|
| `scim.js` | The seventeen routes, and the scimmy resources behind them. |
| `scim_auth.js` | Who is asking. The only authentication this service ENFORCES anywhere. |
| `scim_map.js` | Which LDAP attribute each SCIM member is, in both directions. |

6a. **`scim.js` must stay after `ldap_server.js`, and the interesting thing
   about it is that it is a PLAIN REQUIRE where five things in that file are
   inverted hooks.** It requires that module directly, for the twelve functions
   that make `ou=users` and `ou=groups` a store, and requiring it from anywhere
   EARLIER would pull every `/ldap` route into the express router at that point.
   Rule 3e says a slot is what you reach for when a require would close a cycle
   or move a route, and to test a new proposal BOTH WAYS ROUND before adding one.
   This proposal fails that test both ways — there is no cycle (`ldap_server.js`
   knows nothing about SCIM) and no route moves (the `/ldap` routes are already
   registered by the time this file is read) — so it is a require. It must still
   come before `sts_metadata.js`, which is last for everybody, and it starts
   NOTHING: it is HTTP all the way down, so requiring it is the whole of its
   installation.

   **IT PROVISIONS INTO THE DIRECTORY AND THERE IS NO SECOND STORE.** A
   `POST /scim/v2/Users` and an `ldapadd` create the same entry, a SCIM PATCH and
   an `ldapmodify` change it the same way, and a person provisioned over SCIM
   appears on `/admin/users`, is swept for credential-claim attributes, and lands
   in whatever group a client puts them in. That is the one-store rule (rule 5)
   with a fourth door, and it is what makes the feature worth having: the
   interesting property of a SCIM endpoint is that what it writes is what
   everything else then reads.

   **AND THE FOURTH DOOR CALLS THE SAME FUNCTION THE SECOND AND THIRD DO.** A
   SCIM create goes through `createUser()` — the one the console's form and
   `POST /admin-api/users/create` already share — so there is ONE reading of what
   creating a person means at every door but `ldapadd`. This module builds no DN,
   runs no uniqueness scan and applies no name rule of its own; it translates
   that function's refusals into a status and a `scimType`, which is the only
   part a SCIM client needs and the only part `createUser()` cannot know.

   **It was written the other way first and each of the three home-made rules was
   weaker**, which is why this is worth stating rather than assuming: the DN was
   built as `uid=<name>,ou=users` directly, skipping `namePlan()`'s FOLD onto an
   entry that is already this person's under another naming attribute — two
   objects for one person, the exact thing that fold exists to prevent; the
   uniqueness scan compared the `uid` ATTRIBUTE only, so somebody whose entry a
   client certificate had named by `cn` was invisible to it and SCIM created them
   twice; and the name-syntax list had already drifted from `createUser()`'s by
   one character. `nameUsableInDn()` and `normalizeDn()` are exported from
   `ldap_server.js` for the same reason — a group create has no `createUser()` to
   defer to, so the CHECK is shared even though the door is not.

   **ONE ACT IS ONE AUDIT ROW.** `createUser()` writes its own `user.create`, and
   it now takes a `protocol` so that row says SCIM rather than LDAP; `scim.js`
   therefore records only the update and the delete. A row from both would be one
   act counted twice at the SAME layer, which is rule 3c's warning — unlike the
   HTTP call row `app.js` writes, which is a different layer and is meant to be
   there.

   **IT IS THE FIFTEENTH PROTOCOL FAMILY, AND IT BECAME THE FIFTEENTH
   AUTHENTICATION ONE WHEN THESE ENDPOINTS STARTED REQUIRING A CREDENTIAL** —
   which is why "fourteen" became fifteen throughout this file and README.md —
   and then sixteen, when the SPIRE Server API started requiring an X509-SVID
   (rule 3k). Both counts mean "families reaching `recordAuthentication()`".
   The change is narrower than it sounds and both halves have to be kept
   straight. Three of the schemes `scim_auth.js` offers present a credential on
   EVERY REQUEST (Basic, Digest, HOBA), so accepting one is an authentication
   like a WS-Trust UsernameToken and reaches `recordAuthentication()`; the other
   three do NOT, because each continues an authentication already recorded where
   it was accepted — a token when it was issued, a cookie when its session
   began, a certificate once per CONNECTION, which is a decision
   `tls_server.js` made deliberately and which counting per request here would
   undo from the other end.

   **WHAT DID NOT CHANGE IS THAT BEING PROVISIONED IS NOT AUTHENTICATING.** The
   person a SCIM client CREATES has signed in to nothing, so they still have a
   directory entry with `origin: scim` and no row on `/admin/users` until they
   turn up and authenticate. That is the distinction this service draws
   everywhere else between an identity being RECORDED and one having
   AUTHENTICATED, and it survives intact; do not add a `recordAuthentication()`
   call for the provisioned person to make the two pages agree.


6a-ii. **`scim_auth.js` IS WHO IS ASKING AT `/scim/v2`, AND IT IS THE ONLY
   AUTHENTICATION THIS SERVICE ENFORCES ANYWHERE.** A library like `scim_map.js`
   — it registers nothing and NEVER TOUCHES `res`: it decides and `scim.js`
   answers in SCIM's own error shape, the same split `oauth2_bcp.js` has with
   `oauth2.js`. It requires `helpers.js`, `config.js`, `dpop.js`, `mtls.js`,
   `admin_stats.js`, `audit.js` by way of those, `authn.js`, `tls_server.js` and
   `ldap_server.js`; the last three register routes, and requiring them is safe
   for rule 3e's reason applied rather than assumed — `scim.js` is the only
   thing that requires this file and it already sits after all three in
   `server.js`, so there is no cycle and no route moves. Eight things:

   **THE TABLE IS THE MODULE.** `SCHEMES` is the single source for the
   WWW-Authenticate challenge, for `authenticationSchemes` in the
   ServiceProviderConfig, for `GET /scim`, and for `/admin/scim`'s per-scheme
   counters. A scheme turned off vanishes from the challenge and from the
   published document TOGETHER, which is the property that matters: a client
   reads a published scheme as a promise and a challenge as an instruction.
   **Do not add a scheme RFC 7644 section 2 does not name** — the temptation is
   an API key in a header, which is what most real integrations use, is in no
   specification, and would interoperate with nothing.

   **RFC 7644 SECTION 2 HAS EXACTLY TWO NORMATIVE SENTENCES** and both are
   implemented rather than approximated: a provider SHALL indicate its schemes
   in `WWW-Authenticate` (every 401 carries one header per offered scheme), and
   a provider MUST be able to map an authenticated client to an access control
   policy (two OAuth scopes, with every other scheme granting both). The section
   NAMES six schemes and all six are here. It defines no credential of its own.

   **THE BEARER CHECK IS `dpop.presentedAccessToken()` THROUGH A CAPTURING
   RESPONSE.** That function is the single check `/oauth2/userinfo` and the
   three credential endpoints share and it carries the DPoP proof and nonce
   handshake, the RFC 8705 certificate binding, the RFC 9700 query-string
   refusal and the audience check — so a fifth implementation was out of the
   question. What it will not do is speak SCIM: it ANSWERS, with an OAuth-shaped
   body. So it is handed a response object that records, and what it would have
   said is translated. THE HEADERS IT SET ARE KEPT VERBATIM, which is the part
   that matters — `DPoP-Nonce` and `use_dpop_nonce` are how a wallet learns to
   retry.

   **ONLY THE OAUTH SCHEMES CARRY SCOPES, AND THAT HAS A CONSEQUENCE WORTH
   STATING.** A caller who cannot get a scope can use Basic instead. Which is
   why every scheme has a switch of its own: a deployment exercising a client's
   scope handling turns the other five off. `scim:read` and `scim:write` do NOT
   imply one another, deliberately, so that a read-only provisioning credential
   is something this service can produce.

   **TWO SCHEMES REALLY VERIFY SOMETHING AND IT IS THE KERBEROS ARGUMENT BOTH
   TIMES.** Digest hashes the password into the response, so a server accepting
   anything would not be performing the exchange and the client's own digest
   code would go unexercised — hence any username, one shared password
   (`scim.digestPassword`). HOBA's signature is genuinely verified for the same
   reason; what is permissive there is the REGISTRATION, which is
   unauthenticated for the reason `POST /tls/trust` is — it is how a caller GETS
   a credential. Between them they make five negatives reachable that no
   permissive server can produce, including the one worth knowing: a replayed
   nonce count is refused WITHOUT `stale=true`, because `stale` means "your
   credential was fine, try again" and a replay is the opposite claim.

   **WHICH SCHEMES REACH THE AUTHENTICATION FUNNEL IS `recorded` ON THE ROW**,
   and the rule is the one this service applies everywhere: recorded at the
   moment a credential is ACCEPTED, never again while that act continues. See
   rule 6a above for the three and three.

   **THE DISCOVERY ENDPOINTS ARE OPEN BY DEFAULT** (`scim.authDiscovery`), which
   is `POST /tls/trust`'s bootstrapping argument: the ServiceProviderConfig is
   where a client READS which schemes exist, so demanding a credential to fetch
   it means a client must already know the answer to the question it is asking.

   **A CREDENTIAL THAT WAS PRESENTED AND FAILED IS ALWAYS A REFUSAL**, and was
   one even while `scim.authRequired` could turn the requirement off. A client
   testing its expired-token path must not get
   a 200 because the endpoint would also have accepted nobody.

   **THE ServiceProviderConfig PUBLISHES THREE SCHEMES scimmy CANNOT
   VALIDATE.** RFC 7643 section 5's five canonical `type` values do not cover
   RFC 7644 section 2's six schemes — there is none for a client certificate, a
   cookie or HOBA — and scimmy enforces the five, correctly. So the four
   canonical rows go through `SCIMMY.Config` and the other three are appended to
   the SERIALISED document by `scim.js`, from the same table. Note also that
   `authenticationSchemes` is the one scimmy property that is CUMULATIVE:
   `applyCapabilities()` resets it before setting it, or the array would grow by
   four every time somebody read the document.

   **THE ROUTES ARE REGISTERED ONE BY ONE AND NOT BEHIND `scimmy-routers`.** That
   package exists and would have done it in a line. It mounts an express
   `Router`, and `registeredRoutes()` in `sts_metadata.js` skips any layer with
   no `.route` — so every SCIM endpoint would have been INVISIBLE to the drift
   check, silently, which is the one thing that page exists to prevent. Its
   constructor also REQUIRES an authentication scheme and a handler, and what
   this service would have installed is a handler that accepts everything dressed
   as a check.

   **THE DEPENDENCY WAS WEIGHED THE OPPOSITE WAY FROM `swagger-ui-dist`.**
   `scimmy` is 735 KB unpacked with NO runtime dependencies, and it brings the
   RFC 7643 schema characteristics, the section 3.4.2.2 filter grammar and the
   section 3.5.2 PATCH path grammar — the last being where every hand-rolled SCIM
   server is subtly wrong, since `emails[type eq "work"].value` is a path and not
   a property name. TWO THINGS IT DOES NOT DO look as though it does.
   `Resource#read()` does NOT apply the filter it parsed — it hands the resource
   instance to the egress handler, so a handler ignoring `.filter` returns
   everybody for every query and looks correct until somebody filters. And
   `Filter#match()` THROWS on a nested attribute a resource lacks
   (`Object.entries(undefined)`), which for `emails.value co "…"` against anybody
   with no mail is the ordinary case; `toScimUser()` pads every multi-valued and
   complex member and `prune()` takes the padding off before the wire. Both are
   documented where they are worked around, the way `toSearchEntry()`'s ldapjs
   workaround is.

   **ANYTHING A HANDLER THROWS THAT IS NOT A `SCIMMY.Types.Error` COMES BACK AS A
   404.** `Resource#read()` and `#write()` catch and re-throw as "Resource not
   found", so an ordinary programming mistake inside an egress handler surfaces
   to the client as a missing user. `handle()` logs the original whole, which is
   the only thing that makes such a defect findable.


---

3d-iii. **`scim_map.js` is the FOURTH library over that catalogue's territory,
   and it is the only one of the four that is NOT a selection.** `vc_claims.js`
   says what a CREDENTIAL carries, `vc_verifier_config.js` what the Verifier ASKS
   FOR, `claim_attributes.js` which ATTRIBUTES a token carries, and each of those
   is a set of tick boxes. This says which LDAP attribute each SCIM MEMBER is, in
   both directions, and there is nothing to tick: RFC 7643 decides what a User
   carries, so the only question left is where each member is stored. That is a
   mapping, and a mapping is a table. It registers no route and requires
   `helpers.js` and `vc_claims.js`, neither of which requires it back.

   **THE CONVERSIONS ARE HERE RATHER THAN IN `scim.js` FOR ONE REASON**, and it
   is the route-order one: `admin.js` draws the mapping table on `/admin/scim`
   and must be able to require what it draws. A require from the console into
   `scim.js` would drag every `/scim` route — and, since that module requires
   `ldap_server.js`, every `/ldap` route — into the express router ahead of the
   console's own, and `/admin/sts-metadata` is built by walking that router. So there
   are two readers of two different halves: `scim.js` reads the CONVERSIONS on
   every request, `admin.js` reads the CATALOGUE to draw it.

   **NOTHING IN IT TOUCHES A DIRECTORY.** It is handed an entry object — the
   `{dn, origin, createdAt, modifiedAt, attributes}` shape `entryObject()`
   produces — and hands back a SCIM resource, or the reverse. The placement rules
   (where a person's entry goes, what counts as a group) stay in the one module
   that already owns them.

   **AND SINCE 2026-09-06 IT ALSO OWNS THE PROJECTION THAT PUBLISHES THE TABLE,
   BECAUSE TWO EXISTED AND HAD ALREADY DRIFTED.** `GET /scim` rendered the
   mapping through a projection in `scim.js` and `/admin/scim` and
   `GET /admin-api/scim` through one in `admin.js`, and the two carried
   different members — one had `required`, `schema` and `note`, the other did
   not. So one service published one table at two endpoints and described it
   differently depending on which you asked. **Nothing failed, because nothing
   read either of them**: they were documentation, and documentation that
   disagrees with itself is exactly the shape of defect this repository's "one
   copy of each fact" rule is for.

   What turned it up was a READER.
   `tests/vendored/sts_directory_bulk_load_scim.js` builds every resource it
   sends out of the published mapping rather than out of a copy — a copy in a
   test would drift, and the drift would show up as five thousand creates
   quietly dropping an attribute, which no status code reports. To do that it
   needs `type`, `parent` and `extension`, and neither projection had them: two
   rows both map to `phoneNumbers` and only `type` tells `telephoneNumber` from
   `mobile`, five rows are members of one `addresses` entry and only `parent`
   says so, and an extension member goes under the enterprise URN rather than at
   the top level. Adding them to one projection would have left the other still
   unusable and a reader unable to say which endpoint was right.

   `describeRow()` and `describeMapping()` are now the one projection, here
   beside the table, and both endpoints call them. **`type` and `parent` are
   `null` rather than absent** where a row has none, so a client can tell "this
   mapping has no type" from "this document does not report types" — which is
   the question that job has to answer about the version of the service it is
   running against.

   **THE SPELLINGS ARE CHECKED AGAINST THE CATALOGUE, NOT COPIED FROM IT.**
   `checkSpellings()` runs at require time and WARNS where a row disagrees with
   `vc_claims.js` — the same rule `learnName()` follows, one module earlier, and
   able to name which of the two tables is wrong where that function could only
   report that a second spelling had turned up. Its two INVENTIONS,
   `scimActive` and `scimExternalId`, are merged into `CANONICAL_NAMES` through
   `learnName()` like every other name; they are a FIFTH source into that table,
   which is affordable only because the check exists.

   **FIVE DECISIONS IN IT ARE LOAD-BEARING and each is easy to undo.** The SCIM
   `id` IS THE ENTRY'S DN — RFC 7643 section 3.1 asks for an opaque
   server-assigned identifier and the DN already is one, where a `uid` is not
   unique in this tree and a synthesised id would be a stored second definition
   that goes stale on a rename; the cost, that a rename gives the same person a
   new id, is stated on the page rather than hidden. A PUT REPLACES ONLY WHAT IS
   INSIDE THE MAPPING'S WINDOW, because read strictly it would delete
   `schacDateOfBirth`, `authnMethod` and every `x509*` attribute the moment a
   client updated a phone number — facts SCIM never knew about and cannot
   restore. THREE ATTRIBUTES ARE DROPPED ON THE WAY THROUGH — `entryDN`,
   `createTimestamp`, `modifyTimestamp` — because none of them is really on the
   entry, and carrying them through WROTE `entryDN`, which is exactly the stored
   copy of the DN the synthesis exists to prevent. And A TYPE ON A MULTI-VALUED
   MEMBER IS SCIM'S IDEA: `telephoneNumber` and `mobile` are two attribute types
   and one SCIM member, so the type says which one a value came from and which
   one it goes to, and `primary` is emitted and never stored. FINALLY THE
   MAPPING IS TOTAL: `userName` is RFC 7643's one required User attribute and
   scimmy enforces it on the way OUT, so the entry a client certificate seeds —
   named `cn=<CN>,ou=users`, with no `uid` on it at all — made `GET /Users`
   answer 400 `Required attribute 'userName' is missing` for the WHOLE
   directory until somebody deleted it — a message naming an attribute and no
   entry, on a request that had nothing wrong with it. `toScimUser()` falls
   back to the RDN VALUE — `usernameOfEntry()`, exported from
   `ldap_server.js` and passed in by `scim.js` for the reason
   `normalizeDn()` is, so that the name SCIM reports is the one a create would
   collide with — and then to the DN, exactly as `toScimGroup()` already did for
   `displayName`. One unmappable entry must never be able to hide every other
   person, which is what a mapping that can throw halfway through a list does.


---

## What it deliberately does not do

* **SCIM WRITES INTO THE DIRECTORY AND IS THE ONE SURFACE HERE THAT ASKS WHO IS
  DOING IT.** The `/scim/v2` endpoints create, replace, patch and DELETE
  accounts, so they are the exception to everything above: a credential is
  REQUIRED — unconditionally, in both modes, `mode.gatesScim()` — all six
  schemes RFC 7644 section 2 names are
  offered, and the OAuth ones must carry `scim:read` or `scim:write` — the first
  scope requirement anywhere in this service. **It is still a turnstile rather
  than a lock** IN DEVELOPMENT MODE, which is a different sentence and the one
  that matters: anybody can get a token with either scope from any grant, any
  password but `invalid` passes Basic, any username passes Digest with the one
  shared password, and anybody can register a HOBA key for any name. **In
  product mode none of those four halves holds** — see the audit section at the
  foot of this file. What it buys is that a client's
  401, 403, challenge-response and scope handling can be exercised at all — none
  of which an open endpoint can produce. See rule 6a-ii and `scim_auth.js`.
  **`active: false` DEACTIVATES NOBODY**: it is
  stored as `scimActive` and read by nothing, so no bind is refused, no token
  withheld and no session ended. That is the same carrying-is-not-acting
  distinction this service draws about a group, and it matters more here than
  anywhere else because deprovisioning is the single most common thing a SCIM
  client is built to do — a mock that pretended to disable an account would let
  somebody ship a path that has never worked. There is no ETag and no
  `changePassword`, both ADVERTISED as unsupported rather than half-implemented
  (a version over a one-second timestamp is a concurrency control a client
  trusts and that is wrong; and no password here is checked outside Digest).
  `/Me` is an ALIAS now that there can be an authenticated subject, delegating
  to the same User handlers, and its 501 is kept for the two cases where it is
  still right — an anonymous caller, and POST. A member naming nothing is
  ACCEPTED, because refusing it would make the
  dangling-member state `/admin/groups` exists to report impossible to produce.

## There is no test for this in either repository, and it is the cheapest one left to write

**By the root `CLAUDE.md`'s rule it belongs in the PARENT project's suite** —
every assertion below is made by driving the running service over HTTP.
It is plain JSON over HTTP with no browser, no signature and
no XML, its whole surface is seventeen routes, and the interesting half is
negatives that are hard to provoke from a permissive server and are deliberately
reachable here: `invalid` as a userName, a duplicate userName, an unevaluable
filter, a `.search` body with no schema URN, `/Me`. What a test would also pin
down is the property the feature exists for and no single request demonstrates —
that a `POST /scim/v2/Users` and an `ldapsearch` see ONE entry, that a PUT leaves
`schacDateOfBirth` alone, and that `entryDN` is never written.

## A SCIM CREDENTIAL NOW STARTS A SESSION, AND THE POLICY IS ASKED ABOUT IT (2026-09-06)

Both happen in `authenticate()` and nowhere else, which is that function's whole
reason to exist: it is the ONE place a SCIM credential is accepted, so an
endpoint added tomorrow gets both without its author knowing they exist. Eleven
route handlers would be ten that do and one that does not.

**THE SESSION IS `authn.startSession()` AND NOT A REGISTER OF THIS DIRECTORY'S.**
`common/CLAUDE.md` carries the argument and it is not repeated here; the short
form is that a second store would be a second answer to *is somebody signed in*.
Two things about it are SCIM's own:

* **The key is the SCHEME AND THE PRINCIPAL, not the credential.** This module
  never keeps what was presented — a bearer token reaching a register would be
  a second place to steal one from — so there is nothing here to hash. And the
  right unit is the CLIENT: one that refreshes its token mid-run is the same
  client on the same surface, and keying on the token would give it a second
  row and leave the first until it expired.
* **An anonymous decision gets no session**, which is not a special case:
  a request that presented nothing — the open ServiceProviderConfig, or, while
  `scim.authRequired` existed, that setting off — means nobody authenticated and a session recording that they had would be untrue.

**THE POLICY RUNS AFTER THE SCOPE CHECK AND NOT INSTEAD OF IT.** RFC 7644
section 2's mapping from an authenticated client to an access policy is this
file's own and is unchanged — the OAuth schemes still need `scim:read` or
`scim:write`, and one still does not imply the other. The gate is the layer
ABOVE that, so a deployment can narrow this surface by policy and an unedited
one behaves exactly as it did: the built-in document asks for a role only where
somebody has required one. A refusal from it says outright that the credential
WAS accepted, because "you may not" and "authenticate" are different
instructions to a client and this endpoint already distinguishes them.

## TWO CONSOLE PAGES SINCE 2026-09-06, AND WHERE THE LINE BETWEEN THEM IS

`/admin/scim` was the only one, and it answered two questions that turned out
to want different readers. **`/admin/scim/monitor` is the second, and the
console files it under MONITORING rather than under Protocols &rarr; SCIM.**

**The filing is decided by the QUESTION and never by the path or the module.**
That is the rule `/admin/xacml/monitor` established a day earlier and it is the
same rule here: `/admin/scim` answers *what is this surface* — the six schemes,
the endpoints, the four things it will not do, the five things you can make
fail, which LDAP attribute each SCIM member is, and the eighteen `scim.*`
settings. The monitor answers *how much traffic is there, from whom, and how
much of it is failing*, which is what somebody asks when a provisioning client
is misbehaving rather than when it is being set up. Both are drawn by
`admin-ui/admin.js` and both live under `/admin/scim`; `SECTIONS` is the only
place placement is stated.

**ONE STORE, TWO VIEWS, AND THAT IS WHY THEY CANNOT DISAGREE.**
`common/admin_stats.js` holds one set of counters and offers
`scimSnapshot()` — the summary `/admin/scim` keeps, because a page about a
surface with no evidence anything ever called it is a page about a hypothesis —
and `scimMonitorSnapshot()`, which is everything. There is no second tally
anywhere and there must never be one.

**WHAT THE MONITOR COUNTS THAT NOTHING DID BEFORE** is the traffic's SHAPE:
the outcome, latency and bytes of each operation rather than a bare count; the
status CLASS beside the exact codes; who is calling; and the last fifty requests
individually, because an aggregate cannot answer *what did the call that just
failed look like*. The measurement points are unchanged — `handle()` stamps the
request on the way in and `sendScim()`/`sendScimError()` count it on the way
out, which is the funnel argument this file already makes about the gate: one
place, not eighteen, and the eighteenth is the one that would have been missed.

Four things about it are this module's own and are easy to get wrong:

* **A CLIENT IS AN AUTHENTICATED PRINCIPAL, NOT A CONNECTION.** SCIM is
  stateless HTTP — no session, no registration, nothing to be connected — so
  the only honest reading of "how many clients" is how many distinct names have
  successfully authenticated since the process started. The figure never goes
  down: a client that has stopped calling is indistinguishable from one that is
  between calls. The name is `authenticate()`'s `principal`, which is the same
  unit the session it starts is keyed on and for the same reason.
* **A CALLER THE GATE REFUSED IS NOT A CLIENT.** Basic and Digest both put a
  name on the wire and the gate can still turn it away; those calls are counted
  in `refused` and appear in no client row. Attributing traffic to an identity
  this service declined to believe is the one mistake this page could make that
  would matter, and `tests/scim_monitor.js` provokes it deliberately by passing
  a principal WITH a refusal.
* **AN ABSENT MEASUREMENT IS NULL AND NEVER ZERO.** A success rate of 100% on
  no requests, and an average of 0.0ms over no samples, are the two most
  misleading numbers this page could print: both look like a healthy service.
* **THE OPERATION COUNTS DO NOT SUM TO THE CALL TOTAL**, on purpose and for the
  reason `/admin/scim`'s table already gives: one `POST /scim/v2/Bulk` carrying
  five creates is one `bulk` AND five `create`s, because each of the five really
  is performed.

**THE COUNTERS ARE PER TRUST REALM AND WERE NOT UNTIL THIS PAGE WAS WRITTEN.**
`scimCounts` was a plain object beside a file in which everything else is
`realms.map()`, `realms.arr()` or `realms.obj()` — the third store found
process-wide for a reason that had stopped being true. `/scim/v2` is
realm-prefixed and writes into a directory that has been a subtree per realm
since 2026-08-25, so a client provisioning under `/realm/acme` created entries
in acme and was counted in the default realm's totals, beside a directory count
that was correctly partitioned. The guard is in `tests/realm_isolation.js`,
beside the other two stores, because that file's header asks for a third one
there rather than in a file of its own.

**THERE IS NO RESET BUTTON AND IT WAS REFUSED RATHER THAN FORGOTTEN.**
`resetScimForTests()` exists and nothing on the console calls it. A console that
could zero its own monitoring would make every number on the page a number
somebody might have zeroed, and the audit log — which is the durable record of
what SCIM was ASKED to do, with the actor and the target — cannot be reset
either.

## A FULL DIRECTORY TOOK THE WHOLE PROCESS DOWN (2026-09-13)

A User or Group write refused as `full` (`ldap.maxEntries`) was raised as a
SCIM error with status **507**. RFC 7644 section 3.12 lists no 507, scimmy's
`ErrorResponse` refuses to build an error whose status the section does not
list, and `sendScimError()` is called from a promise's `.catch()` — so the throw
was an unhandled rejection and node exited. One `POST /scim/v2/Groups` ended
every protocol on every socket; the suite saw it as the SCIM bulk load dying on
`other side closed` and the next two jobs on ECONNREFUSED. Two changes:

* **a full directory is 500**, the listed status for a server-side failure, with
  the directory's own sentence and `STS-LDAP-0007` kept;
* **`sendScimError()` cannot throw on an off-list status or scimType**: it logs
  `STS-SCIM-0075` naming the status and the code it was raised with, and sends
  500 with the same detail. Checked by putting 507 back on the group path —
  500, the log line, the service still answering.

The HOBA registration's 507 is unaffected: that route answers plain JSON and
never builds an `ErrorResponse`.

## THE 2026-09-12 AUDIT OF HARD-CODED VALUES, AND WHAT IT CHANGED HERE

`tests/ssf_spiffe_scim_hardening.js` holds every item below.

* **HTTP DIGEST IS NOT OFFERED IN PRODUCT MODE**, whatever `scim.authDigest`
  says. An RFC 7616 response is a hash over `username:realm:password`, so the
  server must hold the password or that hash; product mode holds a salted
  scrypt hash, from which neither can be computed. The only Digest left is
  every user sharing `scim.digestPassword` — a password printed in the
  configuration table, authenticating any name to endpoints that delete
  accounts. Storing H(A1) per person was considered and refused: it is a
  password-equivalent with no work factor, bound to one realm string. A Digest
  credential in product is refused with that reason; `describe()` carries
  `refusedByMode` so an ON setting that is not an offer says why.
* **THE SHARED PASSWORD IS NO LONGER PRINTED IN A 401** unless
  `mode.opensTestControls()`. (With Digest off in product that branch is only
  reachable if the predicates ever diverge; it is the right answer then too.)
* **HOBA REGISTRATION WAS ACCOUNT TAKEOVER.** `POST /.well-known/hoba/register`
  let anybody add a key to any account, and a registered key authenticates at
  `/scim/v2` as that person. Outside development a key may be added to an
  EXISTING account only by somebody whose sign-on session IS that account
  (`mode.opensTestControls()`, 403 otherwise), and a registration never CREATES
  one (`mode.autoCreates()`, 404). **In every mode** a `kid` already registered
  to another account is refused 409: `entryForHobaKid()` takes the first entry
  holding a kid, so a duplicate made authentication depend on directory order.
* **CAPS THAT COULD RE-OPEN A REPLAY.** `scim.maxHobaSeen` (5000) replaces a
  constant, and the seen store maps each triple to its challenge so that
  evicting a triple forgets the challenge too — the copied signature is then
  refused rather than accepted twice. Expired triples go first.
  `scim.maxDigestNonces` (2000) and `scim.maxHobaChallenges` (2000) are safe to
  lower for a simpler reason: a forgotten nonce or challenge is refused, never
  accepted.
* **`scim.digestMd5`** (true) drops MD5 from the challenges and refuses an MD5
  credential naming the setting. `DIGEST_ALGORITHMS` stays the table of what the
  BUILD computes, for the crypto report.
* **`scim.digestNonceSeconds` and `scim.hobaMaxAgeSeconds` carry `min: 1`** and
  are read straight through; they were `Number(...) || 300` and `|| 600`, which
  rewrote a value the table accepted without saying so.

## THE `id` IS THE ENTRY'S `entryUUID` (2026-09-14)

It was the DN, and `README.md`'s *The `id` is the entry's `entryUUID`* records why it was
and why that lost: RFC 7643 section 3.1's id must never be reassigned, a rename reassigned
the DN, and once a person's `sub` became `urn:uuid:<entryUUID>` a SCIM id that a rename
changed would have been the one identifier here that still moved. Five things follow.

* **`scim_map.js`'s `scimIdOf()` reads the id off the entry** (its `entryUUID`, and its DN
  for an entry with none), so that module still asks the directory nothing.
* **Member, group and manager values are ids on the wire and DNs in the store.** The
  handlers translate: `groupResourceFor()` and `groupsOf()` add each DN's id, the Group
  ingress turns member ids into DNs before writing, and the User ingress does the same for
  `manager`. A value naming no entry is kept as it was sent — this directory does no
  referential integrity, as the dangling-member paragraph above says.
* **A DN presented as an id still resolves**, through the directory's
  `dnForResourceId()`, for a client that stored one before the change; the resource comes
  back with its new id.
* **A rename keeps the id**, which the paragraph beside the PUT handler used to say it
  would not.
* The `nameUsableInDn()` refusals stand for a different reason now: the DN is still built
  from the name, so a name carrying an RFC 4514 special character still gives an entry the
  other doors cannot name.

`tests/stable_subject.js` section E drives it over HTTP; `sts_directory_bulk_load_scim.js`
asserts every created id is a UUID and sends them back as member values.
