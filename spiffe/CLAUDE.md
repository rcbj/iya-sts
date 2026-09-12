# spiffe/

An issuing authority for one trust domain, in all three of its server-side
shapes: the bundle endpoint over plain HTTPS, and the Workload API and SPIRE
Server API over gRPC on FOUR MORE SOCKETS — a Unix socket and a TCP port each.

`protos/` holds the SPIFFE project's own `workloadapi.proto` and the
`spire-api-sdk`'s, VERBATIM. `spiffe_grpc.js` reads them at module scope through
`path.join(__dirname, 'protos')`, so they moved into this directory with it; a
missing one is not a degraded SPIFFE feature, it is a service that does not start.
The wire matching what a real client expects is the entire reason
`@grpc/grpc-js` is a dependency here, so a local edit to one of these would give
that up silently.

3k. **SPIFFE IS SIX MODULES AND THE SPLIT IS BY WHAT WOULD OTHERWISE DRIFT.**
   `spiffe_id.js` (the ID grammar), `spiffe_ca.js` (the authorities, minting,
   the bundle), `spiffe_registry.js` (entries and agents, directory-backed),
   `spiffe_grpc.js` (loading the protos, binding, the wrappers),
   `spiffe_workload.js`, `spiffe_api.js` (the handlers) and `spiffe_auth.js`
   (who is calling) are all LIBRARIES — they register nothing — and only
   `spiffe_server.js` registers routes and starts listeners. Nine things are
   load-bearing:

   **THE TWO SURFACES ARE AUTHENTICATED DIFFERENTLY BECAUSE THEIR
   SPECIFICATIONS SAY OPPOSITE THINGS, and reading that as an inconsistency is
   the mistake to avoid.** The SPIFFE Workload Endpoint specification says the
   endpoint "MUST NOT require any direct authentication of its clients" and that
   "Transport Layer Security MUST NOT be required" — bootstrapping: a workload
   has no secret and no root of trust until this call gives it one. A real SPIRE
   *server*, by contrast, binds a TCP port whose callers present an X509-SVID
   over mutual TLS and authorizes every method against what the caller IS. So:
   the mutual TLS requirement reaches the SPIRE Server API and DELIBERATELY NOT
   the Workload API. Do not "fix" the asymmetry. (`spiffe.authRequired` used to
   be the name of it; `global.mode` replaced it on 2026-09-06 and the
   requirement became unconditional.)

   **NOTHING ATTESTS A WORKLOAD OR A NODE, WHICH IS A DIFFERENT CLAIM FROM
   "NOBODY IS AUTHENTICATED" AND THE TWO MUST STAY APART.** A real agent reads
   the peer credentials of its Unix socket — `SO_PEERCRED`, giving pid and from
   that uid, gid, executable, container, pod — and turns them into selectors.
   **Node has no portable way to read them**: `net.Socket` exposes no such call
   and `/proc/net/unix` does not record the peer. So `spiffe_auth.js` identifies
   a Workload API caller by the TRANSPORT it arrived on, the ENDPOINT it reached
   and its PEER ADDRESS, and by nothing else. Two consequences:

   * **Selector matching now DECIDES the answer** (`spiffe.attestWorkloads`,
     on by default). `selectorsMatch()` computes exactly what SPIRE would — the
     entry's selectors a SUBSET of the workload's, not equal, not intersecting —
     and the Workload API uses it, which it did not before. An INVENTED entry
     carries the caller's STABLE selectors (transport and endpoint, never
     `peer:` — its port is ephemeral and a fresh entry would be invented per
     connection until the registry hit its cap).
   * **The selectors are spelt `transport:`, `endpoint:` and `peer:`** and never
     `unix:` or `k8s:`. Writing `unix:uid:1000` for a uid nothing read would be
     inventing an attested fact, which is the `wauth` argument again. An
     ASSERTED selector — `spiffe.acceptAssertedSelectors`, OFF by default, sent
     in an `x-sts-mock-workload-selector` header — is passed through VERBATIM,
     because it is the caller's own claim rather than this service's invention,
     and it exists so that a client's "these matched and those did not" path can
     be exercised at all.

   **THE SPIRE SERVER API'S AUTHORIZATION TABLE IS SPIRE'S OWN, COPIED ROW FOR
   ROW.** `POLICY` in `spiffe_auth.js` is `pkg/server/authpolicy/policy_data.json`
   restricted to the forty-two methods here, and it is copied rather than
   reasoned out: a table derived from what each method "obviously" needs
   disagrees with SPIRE in two or three places and the client author who meets
   the disagreement cannot tell which end is wrong. Where a row looks surprising
   — `Debug.GetInfo` is LOCAL-ONLY, so an admin SVID over TCP is refused it —
   that is SPIRE's answer and the surprise is the point. A method with NO ROW is
   REFUSED and logged as a defect here; the other default fails silently
   forever. **It decides and never answers**: `spiffe_auth.js` returns a
   `{ status, message }` descriptor and `spiffe_grpc.js` maps it, the same split
   `oauth2_bcp.js` has with `oauth2.js`. **The check is in the wrapper**, so
   there is no authorization code in any of the forty-two handlers and there
   must not be.

   **THE `admin` AND `downstream` FLAGS ON AN ENTRY ARE NOW READ.** They were
   recorded, reported, and consulted by nothing, and this file said so. They are
   read on every call and never cached, so an `ldapmodify` of `spiffeAdmin`
   changes what that identity may do on the NEXT one. `spiffe.adminIds` is the
   other way in and is SPIRE's own `admin_ids`: it needs no entry.

   **`Agent.RenewAgent` STOPPED BEING UNIMPLEMENTED because of it**, and the
   refusal it replaced is the argument to keep in view: "nothing here
   authenticates the caller, so answering would mean renewing whichever agent
   the caller named". Something does now, so the method renews the agent on the
   CONNECTION and never one named in the request — and where nothing identifies
   the caller it answers `Unimplemented` with that same sentence.

   **AN ACCEPTED CREDENTIAL IS AN IDENTITY**, through the funnel every other
   family uses. Three acceptances reach it: an X509-SVID over mutual TLS (ONCE
   PER CONNECTION — the credential was accepted at the handshake, which is
   `tls_server.js`'s decision made again), an agent attesting, and a JWT-SVID
   verified at `ValidateJWTSVID`. `ldap_server.js`'s `spiffePlan()` is the
   fourth placement plan (rule 6) and `entryBySpiffeSubject()` is what makes the
   same identity arriving three ways ONE entry.

   **AND SO IS AN ISSUED CERTIFICATE, WHICH IS A FOURTH WAY IN AND NOT A FOURTH
   ACCEPTANCE.** This file used to say "being ISSUED an SVID is not one of
   them", and the sentence was right about what it denied and wrong about what
   it implied: receiving a credential is still not presenting one, but a trust
   domain whose whole output is certificates needs a directory that can say
   which identities hold one. So an X509-SVID mint reaches the directory too,
   and the two events are kept APART rather than merged — `admin_stats.js`'s
   one observer slot now carries an `event` of `authentication`, `issuance` or
   `credential-status`, and only the first is COUNTED as an authentication or
   written to the audit log as one. An issuance that inflated that count would
   be visible immediately: an agent holding `FetchX509SVID` open re-mints every
   half-lifetime, so one workload left running overnight would read as several
   hundred sign-ins. The identity is still ON `/admin/users` — the SVID is an
   artifact, so it lands in the "seen only as a subject" tile with `never` in
   the authenticated column, which is what that tile has always been for.

   **THE FUNNEL IS `stats.recordSvid('X.509', …)`**, which the five X509-SVID
   mints already called, and the sixth fact each now passes is
   `svid.certificate` — `spiffe_ca.js`'s `certificateFacts()`, read back off
   the certificate `issueLeaf()` has just built with `crypto.X509Certificate`.
   Reading it back rather than assembling it from the inputs is the load-bearing
   part: the directory writes THE SAME SIX `x509*` ATTRIBUTES a verified TLS
   client certificate writes, and node prints four of the six identically on
   both paths while the two DNs go through the ONE `dnRfc4514()` — which is why
   that function moved into `common/helpers.js`. `spiffe.svidSubject` is the
   string `C=US,O=SPIRE`, which is not the RFC 4514 form of itself; writing it
   straight onto an entry would have been a second spelling of one DN, which is
   two people on `/admin/users`.

   **ASSIGNED, NOT APPENDED, AND THAT IS THE ONE RULE THAT DIFFERS FROM THE TLS
   PATH.** `certificatePlan()` appends its facts because a renewed client
   certificate is rare and seeing both is the point. An SVID is minted afresh at
   half its lifetime for as long as the workload runs, so appending would grow
   the entry by six values an hour for ever. `x509svidsIssued`, `x509firstIssued`
   and `x509lastIssued` are what is left of the history. A ROTATION IS THE SAME
   OBJECT with no code to make it so: `entryBySpiffeSubject()` keys on the
   SPIFFE ID and on nothing about the certificate.

   **`spiffeCredentialStatus` IS NOT A REVOCATION AND MUST NEVER BE DESCRIBED AS
   ONE.** SPIFFE has none — the answer is a short lifetime and rotation, the
   `crl` field stays empty because empty is the conforming value, and nothing
   here reads this attribute back or refuses a certificate on it. What it
   records is the three things in `spiffe_registry.js` that end an identity's
   ability to obtain a NEW credential: its LAST registration entry deleted (the
   qualifier is checked, because several entries may name one SPIFFE ID and
   deleting one of them ends nothing), its agent banned, its agent deleted. Each
   is reversible and the reverse is written the same way, so the flag is the
   current state rather than a tombstone, and `spiffeRevokedAt` is never cleared
   — `mfaLastAuthTime`'s rule. **THE ENTRY IS NEVER REMOVED.** That module
   reaches `admin_stats.js` by a PLAIN REQUIRE, arrived at by rule 3e's test
   both ways round: no cycle, no route moves, and its own `setDirectory()` slot
   is the SPIFFE containers' store rather than `ou=users`.

   **`spiffe.autoCreateEntries` OFF IS THE INTERESTING SETTING**, and it is the
   one thing here that must not be quietly removed: with it off, a caller
   matching no entry gets an EMPTY SVID LIST, which is what a real agent does
   for an unregistered workload and the only way to run a client's "I have no
   identity" path.

   **THE STREAMS STAY OPEN.** Four Workload API methods are server streams and a
   real client holds `FetchX509SVID` for the life of the process. `serverStream()`
   in `spiffe_grpc.js` deliberately does NOT call `end()`, and
   `pushOnRotation()` re-sends at half the SVID lifetime. A Workload API that
   writes once and ends looks perfect on the first fetch and puts `go-spiffe`
   into a reconnect loop — and re-sending is what makes a client's ROTATION path
   run without anybody waiting an hour. The push callback returns false once the
   peer has gone, which is what stops the timer; a timer that outlived its stream
   writes to a dead one and grpc-js reports that as an unhandled server error.

   **THE REGISTRY IS THE DIRECTORY, exactly as `applications.js`'s is** (rule
   3g). Two containers, because they hold different KINDS of thing: an entry
   under `ou=entries,ou=spiffe` is CONFIGURATION deciding what gets issued, and
   an entry under `ou=agents,ou=spiffe` is a RECORD of something that happened —
   which is why `EDITABLE` covers the first and nothing about an agent is
   editable. NO MAP SHADOWS THEM, so an `ldapmodify` of `spiffeX509SvidTtl`
   changes the next SVID. `ldap_server.js` fills `setDirectory()` at its require
   time and the dependency is NOT inverted (rule 3e's test fails both ways
   round: no cycle, no route moves).

   **THE X.509 AUTHORITY IS A LEAF OF THIS SERVICE'S OWN ROOT SINCE
   2026-09-11, AND THIS PARAGRAPH SAID THE OPPOSITE.** It read: *TWO PKIs IN
   ONE PROCESS, ON PURPOSE. The SPIFFE CA is not `tls_server.js`'s certificate
   and must not become it: that one is a leaf with `CA:FALSE` and `serverAuth`,
   and a trust domain's root and a host's TLS identity are unrelated trust
   decisions.* Every clause of that is still true and **none of it was ever an
   argument against a shared ROOT** — it is an argument against the SPIFFE
   authority being the TLS certificate, which it is not and never becomes.
   `/admin/pki`'s own page carried the same argument and ended by saying the
   SPIFFE Issuing CA was built and certifying nothing *so that reversing this is
   a decision rather than a rebuild*. The decision was taken.

   The shape now, per realm:

   ```
   Root CA (the service's, shared by every realm)   <- THE BUNDLE
   └── Intermediate CA — this realm      pathLen 2
        └── SPIFFE Issuing CA            pathLen 1  <- the X.509 authority
             ├── X509-SVID               a leaf
             └── downstream CA           pathLen 0  (NewDownstreamX509CA)
                  └── a leaf
   ```

   **THE SHORTEST TRUE DESCRIPTION IS THAT THIS SERVICE'S PKI IS NOW SPIRE'S
   UpstreamAuthority.** The bundle publishes the ROOT, not the authority — which
   is exactly what SPIRE publishes with an upstream plugin configured — and an
   X509-SVID carries the Issuing CA and this realm's Intermediate in its own
   chain. Three things follow and each is worth knowing before editing anything
   here:

   * **A ROTATION NO LONGER CHANGES THE BUNDLE.** Re-issuing the Issuing CA
     leaves the anchor where it is, so an SVID minted a minute ago goes on
     building a path and nobody has to re-fetch anything. The
     prepend-and-retain machinery and `MAX_RETAINED_AUTHORITIES` exist for the
     SELF-SIGNED path alone now, and `rotateX509Authority()` says which
     mechanism ran rather than reporting the two identically.
   * **`trustAnchors` AND `x509Authorities` ARE TWO LISTS AND WERE ONE.** What
     SIGNS an SVID and what a consumer INSTALLS are different certificates now;
     they coincided only because a self-signed authority is both. Every report
     — `state()`, `GET /spiffe`, `/admin/spiffe`, the crypto report — carries
     both, and `spiffe_auth.js` deliberately verifies a presented SVID against
     the ISSUING one (a direct-issuer check) while `spiffe_grpc.js`'s client
     truststore takes the ANCHOR (OpenSSL will not treat a non-self-signed
     certificate as an anchor without `X509_V_FLAG_PARTIAL_CHAIN`).
   * **THE `pathLen` NUMBERS ARE DERIVED IN `common/pki.js` AND MUST STAY
     DERIVED.** `NewDownstreamX509CA` asks this authority for a CA, so the
     `spiffe` use case carries `pathLen: 1` and `intermediatePathLen()` widens
     the realm Intermediate to 2 from that one number. Setting either by hand
     is how they come apart, and a chain whose depth exceeds a constraint
     encodes cleanly and is refused at the far end of somebody else's path
     builder with a message naming neither certificate.

   **IT IS PER REALM AND THE TRUST DOMAIN IS NOT, WHICH IS THE ONE THING TO
   GET STRAIGHT.** `spiffe.trustDomain` is read once, service-wide; the
   AUTHORITY is a realm's, because `common/pki.js`'s SPIFFE Issuing CA is. That
   is coherent with four shared sockets only because the anchor is shared:
   every realm's bundle is byte-identical, the gRPC sockets answer in the
   DEFAULT realm (a socket still has no path to put a segment in), and what the
   chain adds is which realm issued the SVID. `tests/spiffe_pki.js` asserts all
   of it.

   **AND THERE IS STILL A SELF-SIGNED PATH, REACHED BY THREE SUPPORTED
   CONFIGURATIONS**: `pki.autoBuild: false`, a Root that could not be built
   (never fatal, by `pki.start()`'s own rule), and every in-process caller that
   does not run `common/service_state.js` — `npm test`, the parent project's
   in-process Kerberos jobs. There this module does what it always did, says so
   on every surface that reports an authority, and nothing about SPIFFE stops
   working. `tests/spiffe_authority.js` holds that path, in a child process
   because the suite builds a hierarchy before it runs.

   The X.509 authority is **EC P-256 by
   default** — what SPIRE issues — which is why the four PKI modules are
   VENDORED from the debugger: `node-forge`, which `helpers.js` and
   `tls_server.js` use, cannot sign with an EC key at all. **That survived the
   move**: the `spiffe` use case carries a key-algorithm PREFERENCE that
   `common/pki.js` honours when nobody chose one, so out of the box an SVID is
   still ES256-signed even though the branch above it is RSA. An operator who
   names an algorithm for their certificate authority gets it for this Issuing
   CA too, which is what choosing one means.

   **`spiffe_ca.js`'s
   initialisation is ASYNC** (Web Crypto), which nothing else in this service is.
   **It is TWO STEPS since 2026-09-11 and the split is forced by the startup
   order**: `initialise()` validates the trust domain once at require time, and
   `ensureTrustMaterial(realm)` resolves a realm's authorities on FIRST USE —
   because `pki.start()` runs after the whole protocol stack is required, so an
   authority resolved at require time is resolved when there is provably no
   hierarchy. Every entry point still awaits `ready()` itself so no caller can
   forget. `state()` is the one synchronous exception and says why.

   **A FOREIGN BUNDLE IS PUSHED IN AND NEVER FETCHED.** `RefreshBundle` refuses,
   naming the URL it is not fetching. Same refusal as `wreqptr` and `jwks_uri`,
   and holding it in two files and not a third would be no position at all. The
   bundle document IS checked — every JWK needs a `use`, because a consumer MUST
   IGNORE one without it, so an unchecked bundle verifies nothing and reports no
   error.

   **SIX OF THE 42 SPIRE METHODS ARE UNIMPLEMENTED AND EACH PUBLISHES A
   REASON**, in `NOT_IMPLEMENTED` and on `GET /spiffe`. A table saying 42 of 42
   would be the most misleading thing in this repository — the same rule
   `oauth2_bcp.js` follows by publishing its `enforced: 'no'` rows. It was SEVEN
   until `RenewAgent` became answerable; the note above that table records what
   its reason was and why it no longer holds. **Do not implement a WIT method by
   inventing the token format**: that is the `wauth`-is-a-refusal argument, and
   code written against the invention would work here and interoperate with
   nothing.

   **TWO gRPC TRAPS, BOTH ALREADY PAID FOR.** `keepCase: true` does not reach
   protobufjs's built-in well-known types, so a `google.protobuf.Struct` is built
   with **camelCase** members (`stringValue`, not `string_value`) while every
   other field in the family is snake_case — the wrong spelling serialises to
   NOTHING, with no throw and no warning. And protobufjs wraps exactly one
   well-known type, `Any`: a plain object assigned to a Struct field becomes a
   Struct with no fields. `ValidateJWTSVID` answered 200 with empty `claims`
   until a real client asked for them.


---

6a. **`spiffe_server.js` must stay after `ldap_server.js` AND after
   `tls_server.js`, and it INVERTS one dependency the way `ldap_server.js`
   inverts five.** The `tls_server.js` half is the newer of the two and is a
   plain require rather than an inversion, arrived at by rule 3e's test applied
   both ways round: `spiffe_auth.js` needs `dnRfc4514()` — the ONE spelling of a
   certificate subject, which `scim_auth.js` requires for the same reason, since
   two spellings of one DN is two people on `/admin/users` — and that module
   knows nothing about SPIFFE, so there is no cycle, and its `/tls*` routes are
   already registered by the time this is read, so no route moves. The plain half first: the
   SPIFFE registry's store is the directory under `ou=spiffe`, and that module
   fills `spiffe_registry.js`'s `setDirectory()` slot at ITS require time — so
   requiring this any earlier leaves the registry with no store at the moment
   `listen()` writes the seed entries. It is the FOURTH module whose own
   listeners start from `listen()` in `server.js` rather than at require time,
   and for the reason the other three carry: binding can fail, and a `require`
   that throws takes the whole service down where a route cannot. FOUR sockets,
   each reported SEPARATELY (`GET /spiffe`, `/admin/spiffe`), because "the
   Workload API socket is up and the SPIRE Server API port is not" is an
   ordinary outcome and one flag could only report one of them — the lesson
   `ldap_server.js` records about 389 and 636, applied before it had to be learnt
   again.

   **The inversion is the CONSOLE.** `/admin/spiffe` must report which listeners
   bound, and only this module knows — but `admin.js` cannot require it, because
   `server.js` requires `admin.js` FIRST and the require would pull `/spiffe` and
   the bundle endpoint into the router ahead of every `/admin` route, which
   `GET /admin/sts-metadata` walks. So `admin.js` offers `setSpiffeReader()` and this
   module fills it at require time — the same shape `setDirectoryReader()`,
   `setGroupReader()` and `setScimReader()` have. `admin.js` DOES require
   `spiffe_ca.js` and `spiffe_registry.js` directly: they register nothing, so
   neither thing that forces a slot applies.

   **THE UNIX SOCKET IS THE ONE THING THIS SERVICE PUTS ON A FILESYSTEM**, and
   the distinction is worth keeping: it is a rendezvous point, it holds no bytes,
   it is unlinked on close, and a fresh process makes a fresh one. TCP-only would
   have been filesystem-clean and unreachable by every real client, because
   `SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to `go-spiffe`,
   `spiffe-helper` and the SPIRE agent. A STALE socket is unlinked before
   binding; something at that path that is NOT a socket is left alone and
   reported, because deleting a file named in configuration on the strength of a
   typo is not this service's decision to make.


---

## Nothing here is attested, and that is a narrower sentence than it was

* **NOTHING IN SPIFFE IS ATTESTED, AND THAT IS NOW A NARROWER SENTENCE THAN IT
  WAS.** No workload and no node: a Workload API caller is identified by its
  transport, the endpoint it reached and its peer address — node cannot read a
  Unix socket's peer credentials — so any caller that reaches the socket still
  gets an identity, and an agent's attestation payload is written down as
  claimed, which is why every agent entry carries a selector valued
  `unverified:true`. **What changed is the OTHER half**: the SPIRE Server API's
  TCP port is MUTUAL TLS, its callers present an X509-SVID verified against the
  trust bundle, and every method is authorized against SPIRE's own table. Those
  are two different claims and merging them back into one gets both wrong.
  Selector matching also DECIDES which entries answer a Workload API caller
  now (`spiffe.attestWorkloads`), which is narrowing without attesting. **AND
  THE DIRECTORY NOW RECORDS WHAT WAS ISSUED, WHICH IS A THIRD DIFFERENT CLAIM.**
  An entry under `ou=users` carrying `x509serialNumber` says this authority
  minted that certificate for that identity — which it knows, because it minted
  it — and says nothing whatever about whether the workload holding it is the
  one it was meant for. Nothing was attested. `spiffeCredentialStatus` beside it
  is not a revocation either; see rule 3k.
  What IS refused: a Workload API call with no `workload.spiffe.io: true` header
  (every conforming implementation refuses it, and a client that omits it has a
  bug nothing else will report), a JWT-SVID with no audience, a
  `ValidateJWTSVID` that does not really verify, an entry in another trust
  domain or under `/spire`, a banned agent, a join token this server did not
  mint or that has expired or been spent or was minted for another agent, an
  X509-SVID that no authority here signed or that is outside its validity
  window, every method the caller's entity is not allowed, and a federated
  bundle whose JWKs have no `use`. The old posture is no longer reachable:
  `spiffe.authRequired` restored it and was removed on 2026-09-06. See rule 3k, `spiffe_auth.js` and `GET /spiffe`.

## There is no test for this in either repository, and it is the largest untested surface here

**By the root `CLAUDE.md`'s rule it belongs in the PARENT project's suite** —
all of it is driven over gRPC against a running service.

What a test would have to cover is not the happy
path — an SVID that verifies against the bundle it came with proves very little —
but the things that were actually wrong during the build and would be silently
wrong again: a `google.protobuf.Struct` whose members serialise to nothing
(`ValidateJWTSVID` answered 200 with empty `claims`), a server stream that ends
when it should stay open, an X509-SVID whose private key does not match its
certificate, `keepCase` spellings, the `MATCH_SUBSET`/`SUPERSET`/`ANY` selector
behaviours, an output mask that is ignored, paging that returns a `next_page_token`
forever, and every one of the refusals above. **The authentication half now has
its own list and it is mostly negatives**: an anonymous caller refused
`UNAUTHENTICATED` and an insufficient one refused `PERMISSION_DENIED` (they are
different instructions and collapsing them is easy); `AttestAgent` and
`GetBundle` reachable with no credential at all, because an agent has none yet;
`Debug.GetInfo` refused to an admin SVID over TCP and allowed on the socket; an
agent allowed `GetAuthorizedEntries` and refused `ListEntries`; a certificate
with no URI SAN, with two, signed by nothing here, outside its validity window,
or naming a trust domain the signing authority does not own; a join token never
minted, expired, replayed, or minted for another agent; `RenewAgent` renewing
the agent on the CONNECTION and never one named in the request; and the same run
with the SPIRE Server API unauthenticated, which must behave exactly as the
service did before any of it existed — a run that needs arranging now that
`spiffe.authRequired` is gone. Also that one identity presented three ways is ONE
directory entry — **and now that one identity ISSUED a certificate fifty times
is still one entry**, with `x509serialNumber` equal to the last SVID and
`x509svidsIssued` equal to fifty, which is the assertion that catches the
append-versus-assign rule being "simplified" into agreement with
`certificatePlan()`. Beside it: that an issuance adds NOTHING to
`/admin/users`'s authentication count (an agent holding `FetchX509SVID` open
would otherwise read as hundreds of sign-ins overnight); that the `x509subject`
an SVID writes is byte-for-byte the string a client certificate with that
subject would write, because two spellings of one DN is two people; that
deleting ONE of two registration entries naming an identity leaves it active and
deleting the second marks it revoked; that a ban and an unban round-trip while
`spiffeRevokedAt` survives the unban; and that nothing anywhere is ever deleted
from `ou=users`. Drive it with `@grpc/grpc-js` as a
CLIENT — which is what `tests/sts_dpop.js` does by writing its own DPoP client
rather than importing the wallet's, and for the same reason: if both ends came
from one implementation, a shared misunderstanding passes and interoperates with
nobody.

## THE SPIRE SERVER API ASKS THE ACCESS POLICY, AFTER SPIRE'S OWN TABLE (2026-09-06)

In `spiffe_grpc.js`'s `prepareCall()`, as `auth.authorize(caller, method) ||
policyRefusal(caller, method)` — and the ORDER is the whole of it.

**SPIRE'S PER-METHOD TABLE IS UNCHANGED AND STILL DECIDES FIRST.** What an agent
may call is that project's answer, copied from its `policy_data.json`, and not
this service's to reinvent. The gate is the layer above it, so a deployment can
narrow this surface by policy; on an unedited service the built-in document
permits, because it asks for a role only where somebody has required one.

**AFTER, so the refusal a caller sees is the most specific one.** *Your SVID is
not an admin and this method is admins only* is a sentence somebody can act on;
*the policy denied it* is not. Reaching the second first would hide the first
for every ordinary misconfiguration.

**EVERY METHOD IS `write` AT THE GATE, AND THAT IS NOT LAZINESS.** What comes out
of this surface is a credential another service will believe. SPIRE's table is
where read and write are told apart, per method, and it has already run; a
second, coarser split here would invite a policy author to think `read` on this
resource meant something SPIRE agrees with.

**A CALLER THAT AUTHENTICATED NOBODY GETS NO SESSION.** The local Unix socket is
trusted by path and presents no credential, and a port where nothing is checked
presents none either — both reach here with `authenticated` false, and a session
recording a sign-in would be untrue. An authenticated caller gets one through
`authn.startSession()` keyed on its SPIFFE ID rather than its certificate: an
agent that rotates its SVID mid-run is the same agent, and keying on the
certificate would give it a second row per rotation. `common/CLAUDE.md` argues
why it is that store and not one of this directory's.

**THE WORKLOAD API IS DELIBERATELY UNTOUCHED.** It authenticates nobody because
its specification says it MUST NOT — a workload has no root of trust until that
call gives it one — so there is no subject to decide about and no session to
record. Only the `server` surface asks.
