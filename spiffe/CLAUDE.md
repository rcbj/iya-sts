# spiffe/

An issuing authority for one trust domain **per trust realm**, in all three of
its server-side shapes: the bundle endpoint over plain HTTPS, and the Workload
API and SPIRE Server API over gRPC on FOUR MORE SOCKETS — a Unix socket and a
TCP port each, per realm that has SPIFFE turned on.

---

## A TRUST DOMAIN AND A PAIR OF SOCKETS PER REALM (2026-09-12)

**This file said "one trust domain" everywhere until this date, and
`realms.realmSupport()` reported SPIFFE as the one family here with NO realm
discriminator at all.** Both are reversed, at rcbj's instruction, and the
instruction named the shape: *give each realm its own trust domain and socket …
a common root domain + unique issuer for each domain … for the SPIFFE service,
a unique IP will be used … a realm should be spun up without the SPIFFE
protocol enabled … make the trust domain configurable per realm … and issue
join tokens that are scoped per realm.*

**SPIFFE LEFT THE ROOT `CLAUDE.md`'s LIST OF SHARED SOCKET FAMILIES THAT DAY,
AND THE SENTENCE IT LEFT BEHIND IS WORTH KEEPING**: it read *SPIFFE's sockets
are still shared and its X.509 authority is not, since 2026-09-11, and the two
facts are compatible for exactly one reason — the trust ANCHOR is the service
Root, which no realm owns … a realm still gets no trust domain, no bundle
endpoint of its own in any meaningful sense, and no socket.* Every clause was
true and the last one is what changed.

**THE DISCRIMINATOR IS THE ENDPOINT ADDRESS, AND IT COULD NOT HAVE BEEN
ANYTHING ELSE.** Every other family in this service is told which realm it is
in by a segment at the front of the path. gRPC has a path and it is the METHOD:
`/SpiffeWorkloadAPI/FetchX509SVID` is fixed by the Workload API specification
and `spire.api.server.entry.v1.Entry/BatchCreateEntry` by SPIRE's, so a realm
segment in it would be a method no conforming client calls — which is the same
answer this repository gave when asked whether `/realm/<id>/admin-api` on these
sockets would be conformant. It is also what a real deployment does: one SPIRE
server is one trust domain, and several trust domains are several endpoints.

Six things follow, and each is where to look:

1. **THE TRUST DOMAIN IS SEEDED WHEN THE REALM IS CREATED**, as the realm's
   own DNS DOMAIN since 2026-09-18 — `iyasec.io`, or `acme.example.com` for a
   realm created without one — by the same mechanism that gives a realm its own
   entityID: `realms.js`'s `NAMED_BY_REALM`. It was `<realm>.<the process's>`
   (`acme.example.org`) until the realm had a domain to use; the domain is
   unique among realms, which is the property the trust domain needs. A realm
   may name its own outright instead. `spiffe.trustDomain` is `realmRuntime` in config.js — restart-only
   for the process, settable on a realm — and the argument for the marker's
   second holder is at the head of the SPIFFE group there.
2. **IT IS FIXED WHEN THAT REALM'S AUTHORITIES ARE BUILT.** `spiffe_ca.ts`
   records the name in the realm's authority record and goes on using it; a
   later change is reported as DRIFT on `GET /spiffe` and `/admin/spiffe`
   rather than acted on, because every certificate that realm has issued names
   the old one. The way to change it is to turn that realm's SPIFFE off, which
   discards the authorities, and on again.
3. **A REALM IS CREATED WITH SPIFFE OFF**, seeded in `realms.js` beside the
   socket paths. Turning it on BINDS SOCKETS, and a realm that bound two
   listeners merely by existing would make `POST /admin-api/realms/create` an
   operation that opens ports — and would hand out credentials from an
   authority nobody asked to exist. **A REALM OPTS IN, AND THE SEEDED `false`
   IS NOT WHAT MAKES THAT TRUE**: `enabledIn()` reads the realm's OWN override
   rather than the effective value, because a realm created before this
   existed — or restored from a store an older build wrote — carries no row and
   would otherwise inherit the process's `true`, which is a key generation and
   a pair of refused binds for every such realm on the next start. The seeded
   row is what makes the state visible on `/admin/realms`.
4. **THE SOCKETS ARE RECONCILED, NOT RESTARTED.** `realms.setOverride()` fires
   `realms.onChange()`, and `spiffe_server.ts`'s `reconcile()` binds what is
   newly wanted and closes what is not. It is QUEUED — two overlapping passes
   both bound the same realm and the second's failures overwrote the first's
   working bindings, which is `EADDRINUSE` on a socket created seconds earlier
   — and it is a no-op in a process that never called `listen()`, which is
   every request worker.
5. **TWO REALMS MAY NOT SHARE AN ADDRESS**, and the refusal names the realm
   that has it and the setting to change. Left to grpc-js this is `Failed to
   bind`, which is also what a port taken by another process says, and the two
   need different things done about them.
6. **JOIN TOKENS ARE PER REALM.** `spiffe_api.ts`'s store was `sharedMap()`
   with `scope: 'shared'`, which was right while there was one trust domain; a
   join token is a credential for joining a trust domain, and a token minted on
   one realm's SPIRE Server API and redeemed on another's would attest an agent
   into a trust domain nobody issued it for.

   **AND THIS SERVICE HOLDS NO JOIN TOKEN IN THE CLEAR (2026-09-12).** The
   store was keyed by the token, and a persisted row's KEY is written unsealed
   (`persistence_minted.js` seals only the body), so every unspent token sat in
   `sts_minted` and `sts_changes` in the clear; the store is keyed by a SHA-256
   of the token now (`joinTokenKey()`), and the body carries only the expiry and
   the agent it was minted for. And `selectorsFromAttestation()` put any short
   printable payload on the agent's entry as `payload:<text>` — which for a join
   token was the token itself, in the directory; a join token's selector is
   `token-sha256:<16 hex>` instead, so somebody holding the token can still find
   the agent it attested and nobody can reconstruct it.
   (`selectorsFromAttestation()` and its `payload:` selectors are gone
   altogether since 2026-09-21: an
   attestor returns only the selectors it VERIFIED — see *Node attestation is
   a table* below.)
   `tests/spiffe_join_token.js` looks for the token in every key and body of the
   store, on the agent's entry and in the audit log.

**WHAT IS STILL SHARED**: the DEFAULT realm's four listeners, which are bound
at startup and stay bound with `spiffe.enabled` off (they answer `Unavailable`;
a socket that vanished would read as a service that had stopped). **The
FEDERATED bundles were on this line until the same day and it was a security
defect rather than a leftover** — see *Federated bundles are a realm's own*
below.

**HOW THE HANDLERS KNOW.** They do not. Not one line of `spiffe_workload.ts` or
`spiffe_api.ts` mentions a realm: they call `ca.trustDomain()`,
`registry.entriesFor()` and the rest, every one of which reads the AMBIENT
realm. `spiffe_server.ts` builds a realm's gRPC server from the SAME handler
table wrapped in `realms.run()`, so the realm a call is in is decided by the
socket it arrived on and nowhere else — and a streaming handler's re-send timer
is armed inside that context, which an explicit realm argument would have had
to be remembered at.

`tests/spiffe_realm_domains.js` holds all of it, including the one assertion
that cannot be made anywhere else: a real gRPC client on a realm's own Unix
socket gets THAT realm's trust domain back from `FetchX509Bundles`.

---

`protos/` holds the SPIFFE project's own `workloadapi.proto` and the
`spire-api-sdk`'s, VERBATIM. `spiffe_grpc.ts` reads them at module scope through
`path.join(__dirname, 'protos')`, so they moved into this directory with it; a
missing one is not a degraded SPIFFE feature, it is a service that does not start.
The wire matching what a real client expects is the entire reason
`@grpc/grpc-js` is a dependency here, so a local edit to one of these would give
that up silently.

3k. **SPIFFE IS SIX MODULES AND THE SPLIT IS BY WHAT WOULD OTHERWISE DRIFT.**
   `spiffe_id.ts` (the ID grammar), `spiffe_ca.ts` (the authorities, minting,
   the bundle), `spiffe_registry.ts` (entries and agents, directory-backed),
   `spiffe_grpc.ts` (loading the protos, binding, the wrappers),
   `spiffe_workload.ts`, `spiffe_api.ts` (the handlers) and `spiffe_auth.ts`
   (who is calling) are all LIBRARIES — they register nothing — and only
   `spiffe_server.ts` registers routes and starts listeners. Nine things are
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
   and `/proc/net/unix` does not record the peer. So `spiffe_auth.ts` identifies
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
     inventing an attested fact, which is the argument that stops `wauth`
     being answered with a factor that did not happen. An
     ASSERTED selector — `spiffe.acceptAssertedSelectors`, OFF by default, sent
     in an `x-sts-workload-selector` header — is passed through VERBATIM,
     because it is the caller's own claim rather than this service's invention,
     and it exists so that a client's "these matched and those did not" path can
     be exercised at all.

   **THE SPIRE SERVER API'S AUTHORIZATION TABLE IS SPIRE'S OWN, COPIED ROW FOR
   ROW.** `POLICY` in `spiffe_auth.ts` is `pkg/server/authpolicy/policy_data.json`
   restricted to the forty-two methods here, and it is copied rather than
   reasoned out: a table derived from what each method "obviously" needs
   disagrees with SPIRE in two or three places and the client author who meets
   the disagreement cannot tell which end is wrong. Where a row looks surprising
   — `Debug.GetInfo` is LOCAL-ONLY, so an admin SVID over TCP is refused it —
   that is SPIRE's answer and the surprise is the point. A method with NO ROW is
   REFUSED and logged as a defect here; the other default fails silently
   forever. **It decides and never answers**: `spiffe_auth.ts` returns a
   `{ status, message }` descriptor and `spiffe_grpc.ts` maps it, the same split
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
   `svid.certificate` — `spiffe_ca.ts`'s `certificateFacts()`, read back off
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
   records is the three things in `spiffe_registry.ts` that end an identity's
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
   in `spiffe_grpc.ts` deliberately does NOT call `end()`, and
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
     both, and `spiffe_auth.ts` deliberately verifies a presented SVID against
     the ISSUING one (a direct-issuer check) while `spiffe_grpc.ts`'s client
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
   GET STRAIGHT.** *(Superseded the next day: since 2026-09-12 the trust domain
   and the sockets are a realm's too — see* A TRUST DOMAIN AND A PAIR OF
   SOCKETS PER REALM *at the top. What follows is the 2026-09-11 state.)*
   `spiffe.trustDomain` is read once, service-wide; the AUTHORITY is a
   realm's, because `common/pki.js`'s SPIFFE Issuing CA is. That is coherent with four shared sockets only because the anchor is shared:
   every realm's bundle is byte-identical, the gRPC sockets answer in the
   DEFAULT realm (a socket still has no path to put a segment in), and what the
   chain adds is which realm issued the SVID. `tests/spiffe_pki.js` asserts all
   of it.

   **AND THERE IS STILL A SELF-SIGNED PATH, REACHED BY THREE SUPPORTED
   CONFIGURATIONS**: `pki.autoBuild: false`, a Root that could not be built
   (never fatal, by `pki.start()`'s own rule), and every in-process caller that
   does not run `common/service_state.ts` — `npm test`, the parent project's
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

   **`spiffe_ca.ts`'s
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
   inventing the token format**: that is the argument that stops `wauth`
   being answered with a factor that did not happen, and code written against
   the invention would work here and interoperate with nothing.

   **TWO gRPC TRAPS, BOTH ALREADY PAID FOR.** `keepCase: true` does not reach
   protobufjs's built-in well-known types, so a `google.protobuf.Struct` is built
   with **camelCase** members (`stringValue`, not `string_value`) while every
   other field in the family is snake_case — the wrong spelling serialises to
   NOTHING, with no throw and no warning. And protobufjs wraps exactly one
   well-known type, `Any`: a plain object assigned to a Struct field becomes a
   Struct with no fields. `ValidateJWTSVID` answered 200 with empty `claims`
   until a real client asked for them.


---

6a. **`spiffe_server.ts` must stay after `ldap_server.js` AND after
   `tls_server.js`, and it INVERTS one dependency the way `ldap_server.js`
   inverts five.** The `tls_server.js` half is the newer of the two and is a
   plain require rather than an inversion, arrived at by rule 3e's test applied
   both ways round: `spiffe_auth.ts` needs `dnRfc4514()` — the ONE spelling of a
   certificate subject, which `scim_auth.js` requires for the same reason, since
   two spellings of one DN is two people on `/admin/users` — and that module
   knows nothing about SPIFFE, so there is no cycle, and its `/tls*` routes are
   already registered by the time this is read, so no route moves. The plain half first: the
   SPIFFE registry's store is the directory under `ou=spiffe`, and that module
   fills `spiffe_registry.ts`'s `setDirectory()` slot at ITS require time — so
   requiring this any earlier leaves the registry with no store at the moment
   `listen()` writes the seed entries. It is one of the socket owners whose
   own listeners start from `listen()` in `server.js` rather than at require
   time (the root `CLAUDE.md` lists them), and for the reason they all carry:
   binding can fail, and a `require` that throws takes the whole service down
   where a route cannot. FOUR sockets,
   each reported SEPARATELY (`GET /spiffe`, `/admin/spiffe`), because "the
   Workload API socket is up and the SPIRE Server API port is not" is an
   ordinary outcome and one flag could only report one of them — the lesson
   `ldap_server.js` records about 389 and 636, applied before it had to be learnt
   again.

   **The inversion is the CONSOLE.** `/admin/spiffe` must report which listeners
   bound, and only this module knows — but `admin.js` cannot require it, because
   `common/protocol_stack.ts` requires `admin.js` FIRST and the require would pull `/spiffe` and
   the bundle endpoint into the router ahead of every `/admin` route, which
   `GET /admin/sts-metadata` walks. So `admin.js` offers `setSpiffeReader()` and this
   module fills it at require time — the same shape `setDirectoryReader()`,
   `setGroupReader()` and `setScimReader()` have. `admin.js` DOES require
   `spiffe_ca.ts` and `spiffe_registry.ts` directly: they register nothing, so
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

## Node attestation is a table, and nothing is taken on trust (#40, 2026-09-21)

**`AttestAgent` used to accept ANY attestation type.** Only `join_token` was
checked; every other type was issued an agent SVID under
`/spire/agent/<type>/<digest of the payload>` with its payload unread and a
selector `<type>:unverified:true` on the agent's entry — reported honestly on
every page, and granting that agent everything beneath its id all the same. A
real SPIRE agent pointed here could join a trust domain with an invented type.
rcbj's decision on #40: **refuse, in every mode**, and implement SPIRE's
node attestors instead (`join_token`, `x509pop`, `sshpop`, `tpm_devid`,
`k8s_psat`, `aws_iid`, `gcp_iit`, `azure_imds`, `http_challenge` — all nine
are in since phase three).

* **THE TABLE IS `spiffe_node_attestation.ts`** and each attestor is a class in
  a `spiffe_attestor_<type>.ts` of its own, returning the shapes in
  `types/spiffe-attestation.d.ts`: the agent's id by SPIRE's template, the
  selectors IT VERIFIED, `canReattest`, and a `commit()`/`release()` pair.
  `spiffe.nodeAttestors` (per realm, default `join_token`) names what a realm
  accepts; a type absent from it, or present and not in the table, is
  FAILED_PRECONDITION (`STS-SPIFFE-0078`) — SPIRE's answer for an attestor it
  has no plugin for. There is no fallback attestor and there must not be one.
* **AN ATTESTOR NEVER RETURNS A SELECTOR IT DID NOT ESTABLISH.** The selector
  types are SPIRE's, and a registration entry written against SPIRE's
  documentation trusts them.
* **EVIDENCE IS SPENT WHEN THE SVID EXISTS, NOT WHEN IT VERIFIED.** The
  attestor claims what it must (a join token through `cluster_claims`, as
  #46 required), `AttestAgent` calls `commit()` after the agent is recorded
  and `release()` on any failure after the attestor returned, so a refusal
  spends nothing.
* **EVIDENCE THAT IS NOT RE-ATTESTABLE ATTESTS ONCE.** An agent that exists
  and whose attestor says `canReattest: false` is refused
  (`STS-SPIFFE-0083`) until an operator deletes it — SPIRE's rule for a join
  token and the trust-on-first-use cloud documents. `reattestable` in the
  answer is the attestor's, no longer `type !== 'join_token'`.
* **A CHALLENGE IS A CONVERSATION ON THE SAME STREAM.** `spiffe_grpc.ts`'s
  `bidiStream()` hands the handler `conversation.challenge(message, ms)`,
  which writes `{ challenge }` and resolves with the client's NEXT message
  instead of dispatching it as a new request. Timeout
  (`spiffe.attestationChallengeTimeout`) is DEADLINE_EXCEEDED
  (`STS-SPIFFE-0080`), a next message without `challenge_response` is
  INVALID_ARGUMENT (`0081`), the client ending or cancelling with one
  outstanding is CANCELLED (`0082`).
* **A CLIENT'S HALF-CLOSE WAITS FOR THE HANDLERS IN FLIGHT.** `bidiStream()`
  answered `end` with `call.end()` at once, so a client that sent its one
  message and half-closed got an empty stream while `AttestAgent` went on to
  SPEND THE JOIN TOKEN — every retry then refused as spent.
  `tests/vendored/sts_spiffe_grpc.js` recorded it as a service defect and
  worked round it; the stream now ends once every handler has answered.
* **`CreateJoinToken`'s `agent_id` IS AN ALIAS ENTRY, AS IN SPIRE.** It was
  stored and compared with the attesting agent's id, which is always
  `/spire/agent/join_token/<digest>` — so a token minted for a named agent
  could never attest (`STS-SPIFFE-0057`, retired). It now registers an entry
  naming `agent_id`, parented on the token's agent and selecting
  `spiffe_id:<that agent>`, checked BEFORE the token exists
  (`STS-SPIFFE-0084`); `entriesAuthorizedFor()` reaches it because it starts
  from the agent itself.
* **`GET /spiffe` carries `nodeAttestation`**: every type this build
  verifies, whether the realm accepts it, and any configured name nothing
  verifies.

### x509pop, sshpop and tpm_devid: proof of possession (#40 phase two)

Each is SPIRE's server plugin step for step, because a real `spire-agent` is
the client: `spiffe_attestor_x509pop.ts`, `spiffe_attestor_sshpop.ts`,
`spiffe_attestor_tpm_devid.ts`.

**NO CERTIFICATE AND NO SIGNATURE IS CHECKED IN THIS DIRECTORY.** What stands
in for the Go packages SPIRE uses was written here as three libraries on the
day and MOVED the same day, at rcbj's direction, into the modules that check
every other certificate and signature in this service: `common/pki.js`
(`verifyPathToAnchors()` — Go's `x509.Certificate.Verify()` with caller
roots — and the OpenSSH certificate reader and `checkSshHostCertificate()`)
and `common/crypto.js` (section 8: `verifyRawSignature()` for RSA, RSA-PSS,
ECDSA, EdDSA and the post-quantum families, and TPM 2.0 `tpmKdfa()` and
`tpmMakeCredential()`). What stays here is `spiffe_tpm.ts`, a CODEC for the
TPM's byte layout that hands every signature and derivation to `crypto.js`,
and `spiffe_agent_path.ts`, which is SPIRE's template language and no kind of
crypto. The vendored `x509.js` is where the chain signatures are finally
checked, and it is not edited here. Six things were decided rather than
copied, and each is the place to look first:

* **A TRUST ANCHOR IS PEM TEXT IN A SETTING, NOT A FILE PATH.** SPIRE takes
  `ca_bundle_path`, `devid_ca_path`, `endorsement_ca_path` and
  `cert_authorities_path`; here they are `spiffe.x509popCaBundle`,
  `spiffe.tpmDevidCaBundle`, `spiffe.tpmEndorsementCaBundle` and
  `spiffe.sshpopCertAuthorities`, per realm, as
  `oid4vp.trustedIssuerCertificates` is — so the console and `/admin-api`
  (rule 7) can set them. An attestor with none configured refuses every agent
  with FAILED_PRECONDITION (`STS-SPIFFE-0085`), which is SPIRE's "not
  configured".
* **THE STATUS CODES ARE SPIRE'S, EVEN WHERE THEY LOOK WRONG.** x509pop
  answers a bad path PERMISSION_DENIED; tpm_devid answers the same thing
  INVALID_ARGUMENT; sshpop answers almost everything INTERNAL, because
  `handshake.go` wraps it so. A client may branch on the code, and one that
  works against SPIRE must work here.
* **THE PATH BUILDER (`pki.js`) FAILS CLOSED WHERE GO WOULD EVALUATE.** An unhandled
  critical extension is refused (Go refuses them too; tpm_devid allows a
  critical subjectAltName on the EK certificate, as SPIRE strips it), and a
  CA with nameConstraints is refused outright, because the constraints are
  not evaluated here. A path accepted unchecked would be wrong; one refused
  says why. Signatures are checked by the vendored `x509.verifyChain()`,
  which reads ML-DSA, SLH-DSA and composite signatures — so a post-quantum
  CA above an x509pop or DevID leaf verifies.
* **x509pop CHALLENGES A POST-QUANTUM KEY, BEYOND SPIRE.** SPIRE's challenge
  has an RSA and an ECDSA member; a leaf with an ML-DSA, SLH-DSA or composite
  key is challenged here with `pqc_signature` (`{"nonce", "algorithm"}`,
  answered `{"nonce", "signature"}` over the same SHA-256 of both nonces). A
  stock agent never holds such a key and never sees the member.
* **AGENT PATH TEMPLATES ARE A SUBSET OF GO'S, AND SAY WHERE IT ENDS.**
  `spiffe_agent_path.ts` evaluates field references (`.Subject.CommonName`,
  `.URISanSelectors.k`), pipelines, and sprig's string, hash and encoding
  functions from SPIRE's list; `if`, `range`, variables and any other
  function are refused when the template is parsed — a template rendered
  differently here from SPIRE would give an agent a different identity.
* **NOTHING IS CLAIMED.** Each of the three proves possession by answering a
  challenge this server chose, so its `commit()` and `release()` are empty
  and all three are re-attestable, as in SPIRE.

`tests/spiffe_attestors.js` drives all three with software clients —
certificates from the vendored engine, an OpenSSH host certificate assembled
byte by byte, and a software TPM whose ActivateCredential is written
independently of `spiffe_tpm.ts` — and asserts every refusal beside each
acceptance. A real `spire-agent` (and swtpm) is phase five's.

### k8s_psat, http_challenge and the three clouds (#40 phase three)

`spiffe_attestor_k8s_psat.ts`, `spiffe_attestor_http_challenge.ts`,
`spiffe_attestor_aws_iid.ts`, `spiffe_attestor_gcp_iit.ts` and
`spiffe_attestor_azure_imds.ts`, each SPIRE's server plugin step for step. The
certificates and signatures they need are `common/pki.js`'s and
`common/crypto.js`'s (`verifyPkcs7SignedData()`, `verifyJws()`,
`verifyPathToAnchors()`, and the AWS and Azure anchors SPIRE embeds, generated
into `common/pki_cloud_anchors.json`). Five decisions:

* **THEY DIAL, AND TWO DIFFERENT ARGUMENTS COVER IT.** Every Kubernetes API
  server, Google certificate URL, Microsoft discovery document and AIA
  intermediate is the ADMINISTRATOR'S kind of URL — a setting, or SPIRE's
  constant made settable — and goes through `federation_http.ts`'s
  `requestConfigured()` (`fetchJson()`'s argument: no internal-address
  refusal, because an API server lives on one; https, with a cluster's own CA
  as the roots; plain http only for a `signedArtifact`, the intermediate,
  whose signature is checked before a byte is believed). `http_challenge` is
  the CALLER'S kind and is the root `CLAUDE.md`'s sixth exception:
  `fetchHttpChallenge()`, only after the host matched
  `spiffe.httpChallengeAllowedDnsPatterns` — **empty refuses every agent,
  stricter than SPIRE**, whose empty list allows any name — with the
  internal-address refusal and pinning in product mode, no redirect and 64
  bytes.
* **NO CREDENTIAL IS EVER A SETTING.** A setting is drawn on the console,
  returned by `/admin-api` and persisted — and `secret: true` on a row is read
  by nothing. So where SPIRE takes an access key, an app secret or a
  kubeconfig, this takes a FILE PATH (`tokenFile`, `caFile`,
  `spiffe.gcpIitServiceAccountFile`, an Azure `tokenAuth.tokenPath`) or each
  SDK's own credential chain.
* **THE CLOUD SDKs ARE OPTIONAL PEER DEPENDENCIES** (rcbj, 2026-09-21),
  `common/secrets.js`'s arrangement: `@aws-sdk/client-ec2`, `-iam`,
  `-organizations`, `-eks`, `-auto-scaling`, `@aws-sdk/credential-providers`,
  `@google-cloud/compute` (only for `spiffe.gcpIitUseInstanceMetadata`),
  `@azure/identity`, `@azure/arm-resourcegraph`, `@azure/arm-compute`. A realm
  that enables one of these attestors without its SDK is refused with
  FAILED_PRECONDITION naming the package (`STS-SPIFFE-0106`). Each attestor
  takes its SDK through `load` in its constructor dependencies, which is how
  `tests/spiffe_attestors_cloud.js` hands it fakes.
* **TRUST ON FIRST USE IS THE PHASE-ONE RULE, NOT A NEW ONE.** aws_iid,
  gcp_iit, azure_imds and a TOFU http_challenge answer `canReattest: false`,
  and `AttestAgent` refuses a second attestation of an existing agent
  (`STS-SPIFFE-0083`) — SPIRE's `AssessTOFU()`, which reads its agent store
  the same way.
* **azure_imds CHALLENGES FIRST**: its evidence is a document minted FOR the
  nonce, so the conversation `bidiStream()` gained in phase one carries it —
  the initial payload is empty and the attested document arrives as the
  challenge response.

## Workloads are attested on the Unix socket (#40 phase four, 2026-09-21)

**THIS SERVICE IS THE SPIRE AGENT FOR ITS OWN WORKLOAD API**, so it attests
the workload that connects the way an agent does. Five modules, each a
library, wired by `spiffe_server.ts`:

* `native/peercred.c` — an N-API module with five functions and no state:
  `SO_PEERCRED`, `SO_PEERPIDFD` (Linux 6.5+), `pidfd_open` as the fallback,
  `pidfd_send_signal(0)` for liveness, `close`. rcbj's decision on #40: a
  small addon, compiled ONLY in an image build (`build-native.sh`, gcc in the
  `typescript` stage of `Dockerfile` and in `tests/Dockerfile`), never on the
  host, and no general FFI in the process. `spiffe/native/*.node` is ignored.
* `spiffe_peer.ts` — `observe(socket)` at ACCEPT (pid, uid, gid, a pidfd, the
  process's start time and executable inode) and `stillValid(facts)` on EVERY
  CALL: the pidfd alive, the start time and the inode unchanged. That refuses
  the two things SPIRE's per-call attestation exists for — a reused pid and an
  `exec` — without running the attestors per call.
* `spiffe_workload_attestation.ts` — the table (`spiffe.workloadAttestors`,
  default `unix`) and SPIRE's containerinfo extractor over
  `/proc/<pid>/cgroup`.
* `spiffe_workload_attestor_unix.ts`, `_docker.ts`, `_k8s.ts` — SPIRE's
  three plugins' selectors. Docker is asked over `spiffe.dockerSocketPath`
  (`federation_http.requestLocalSocket()`); the kubelet over its read-only port
  on loopback or its secure port (`requestConfigured()`), with the token, the
  client certificate and the CA read from FILES — no credential is a setting,
  because settings are drawn, returned by `/admin-api` and persisted.

**THE SEAM IS `spiffe_grpc.ts`'s `bindAttestedSocket()`.** grpc-js does not
expose an accepted connection's file descriptor, so the Workload API's Unix
socket is bound by a `net.Server` of this module's, each connection is PAUSED,
attested in the listener's realm, TAGGED (`remoteAddress` =
`unix:attested-<n>`, which grpc-js carries to `call.getPeer()`) and only then
handed over through `server.createConnectionInjector()`. **Do not resume the
socket before the injection**: a resume with no reader emits what the client
sent while the attestors ran — its HTTP/2 preface — to nobody, and the
connection dies with nothing refused. The first version did that and passed
every refusal test, because a refused connection had not yet sent anything.

`prepareCall()` looks the tag up: an attestation that FAILED refuses every call
(`UNAVAILABLE`, `STS-SPIFFE-0111`), a process that changed refuses it
(`PERMISSION_DENIED`, `STS-SPIFFE-0112`), and otherwise `caller.attested`
carries the facts and `spiffe_auth.workloadSelectors()` adds their selectors.
All of that runs in the FRONT process, which accepted the connection; what
crosses to a request worker is the caller, already plain.

**What is still not attested, and why each is a sentence rather than a gap:**

* **A caller over TCP** — no peer process to ask. It keeps the `transport:`,
  `endpoint:` and `peer:` selectors.
* **A peer in another pid namespace** (pid 0 from `SO_PEERCRED`) — attested on
  its kernel uid and gid alone; nothing that needs the process is invented.
* **The socket without the native module** — development serves it
  unattested and `GET /spiffe`'s `workloadAttestation` says so; **product does
  not bind it** (`STS-SPIFFE-0113`, `mode.requiresWorkloadAttestation()`).
  Asserted selectors are not believed in product
  (`mode.believesAssertedSelectors()`).
* SPIRE's `systemd` attestor, docker's sigstore checks and Podman sockets, and
  the Kubernetes broker — follow-ups recorded on #40.

`tests/spiffe_workload_attestation.js` drives a real connection from a child
process and asserts the child's pid, uid, gid and selectors, the revalidation,
and a failing attestor's refusal; the attestors over fake `/proc`, Engine and
kubelet beside it.

**THE SPIRE SERVER API IS THE OTHER HALF**, and it came first: its TCP port is
MUTUAL TLS, its callers present an X509-SVID verified against the trust bundle,
and every method is authorized against SPIRE's own table. Those are two
different claims and merging them back into one gets both wrong.

* Selector matching also DECIDES which entries answer a Workload API caller
  now (`spiffe.attestWorkloads`), which is narrowing without attesting. **AND
  THE DIRECTORY NOW RECORDS WHAT WAS ISSUED, WHICH IS A THIRD DIFFERENT CLAIM.**
  An entry under `ou=users` carrying `x509serialNumber` says this authority
  minted that certificate for that identity — which it knows, because it minted
  it — and says nothing whatever about whether the workload holding it is the
  one it was meant for — attestation is on the connection, not the entry.
  `spiffeCredentialStatus` beside it
  is not a revocation either; see rule 3k.
  What IS refused: a Workload API call with no `workload.spiffe.io: true` header
  (every conforming implementation refuses it, and a client that omits it has a
  bug nothing else will report), a JWT-SVID with no audience, a
  `ValidateJWTSVID` that does not really verify, an entry in another trust
  domain or under `/spire`, a banned agent, an attestation type nothing here
  verifies, a join token this server did not
  mint or that has expired or been spent, an
  X509-SVID that no authority here signed or that is outside its validity
  window, every method the caller's entity is not allowed, and a federated
  bundle whose JWKs have no `use`. The old posture is no longer reachable:
  `spiffe.authRequired` restored it and was removed on 2026-09-06. See rule 3k, `spiffe_auth.ts` and `GET /spiffe`.

## There is no end-to-end protocol test for this in either repository, and it is the largest untested surface here

*The in-process `tests/spiffe_*.js` files (realm domains, operations, PKI,
authority, join tokens) cover pieces of it — one of them with a real gRPC client
on a realm's Unix socket — and are argued where each is cited above. What is
missing is the protocol suite's job below.*

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
CLIENT — which is what `tests/vendored/sts_dpop.js` does by writing its own DPoP client
rather than importing the wallet's, and for the same reason: if both ends came
from one implementation, a shared misunderstanding passes and interoperates with
nobody.

## FORTY-TWO OF THE FORTY-SEVEN METHODS RUN IN A REQUEST WORKER (2026-09-12)

`common/request_pool.js` dispatches non-HTTP work by OPERATION — a
`{ kind, args }` pair the front process sends to a worker while keeping the
socket and the framing. `ldap/ldap_server.js` was the first family to use it and
this is the second: both unary Workload API methods and all forty of the SPIRE
Server API's leave the thread that owns every socket this service has. The five
server streams do not, and that is argued below rather than omitted.

**THE SEAM IS `spiffe_grpc.ts`'s `unary()` WRAPPER AND NOTHING ELSE.** Every
method on both surfaces is registered through `unary()`, `serverStream()` or
`bidiStream()`, so wrapping there covers all of them by construction — and
**`spiffe_workload.ts` and `spiffe_api.ts` are not edited at all**. That is
`ldap_server.js`'s registration-point argument met again: forty-two handlers
each remembering to offer themselves to the pool is forty-two chances to forget,
and what was forgotten would be invisible — the method would run in the front
process and everything would work, slightly slower, for ever.

### A handler reads exactly two things off the call

Counted across both handler files: `call.request` (35 uses) and
`call.spiffeCaller` (4). Nothing else — no metadata, no deadline, no peer, no
headers. So the worker is handed an object with exactly those two on it, and a
fuller fake would be offering a surface no handler uses.

**AN ERROR NEEDS NO TABLE.** `statusError()` is an `Error` carrying a NUMERIC
gRPC status, and the number IS the protocol — so a refusal crosses as
`{ code, message }`. The directory's codec had to look an error class up on
ldapjs's exports and validate what it found; here there is nothing to look up.
A refusal carrying NO numeric code is rebuilt as a plain `Error` on purpose, so
that `errorToStatus()` reaches the same conclusion it would have reached in
process: a non-status throw is a defect in this service, logged as one and
answered `UNKNOWN`.

### Three things stay in the front process

* **`prepareCall()`** — it reads the TRANSPORT, the peer address, the peer
  certificate and the Workload API's selectors, every one of which is a property
  of a connection this process accepted. What crosses is its ANSWER: a plain
  `caller` whose DNs `callerOf()` has already rendered with `dnRfc4514()`.
* **`recordCall()`** — it is called from the wrappers rather than from any
  handler, so it simply stays. Worth having on purpose rather than by accident:
  the counters behind `/admin/metrics` and the audit row would otherwise land in
  whichever worker answered, and `admin_stats.users` is one of the three stores
  that does not fan in.
* **The callback**, which writes to the connection.

### The five server streams are not dispatched, and that is a decision

All five are on the Workload API. Two things put them on the socket side of the
line `unbind` is on in `ldap/CLAUDE.md`:

* **A STREAM HERE IS A SUBSCRIPTION AND NOT A REQUEST.** It is opened once and
  held for the life of the process — this file's own *THE STREAMS STAY OPEN*
  says a real client treats it ending as a FAULT — and what feeds it is
  `pushOnRotation()`'s timer, not a caller. Moving it would mean a worker owning
  a stream whose file descriptor is here, every `push()` crossing the channel,
  and **a worker's death silently turning a live subscription into one that
  never updates again**: a client would go on holding an SVID it believes is
  being renewed. That is the LDAP connection's problem exactly, and the answer
  there was the same.
* **DISPATCHING ONLY THE FIRST MESSAGE WOULD BE WORSE THAN NOT DISPATCHING.**
  `pushOnRotation()` builds later messages with the same
  `buildX509SvidResponse()` the first one uses, so the front process must be
  able to build one anyway — and splitting them would put one response in two
  processes.

`bidiStream()` is unchanged for the same reason read the other way:
`AttestAgent` and `SyncAuthorizedEntries` are request/response in practice, but
the stream and its `data`/`end` events belong to the connection.

**WHAT THAT COSTS IS SMALL AND IS WORTH STATING.** The expensive thing on this
surface is minting an SVID, and a stream mints on rotation rather than per call.

### The channel had to learn to carry bytes

The request pool forked its workers with node's DEFAULT JSON serialization,
which was right for LDAP — attribute values are strings — and wrong here.
**`JSON.stringify(Buffer)` is `{"type":"Buffer","data":[…]}`**: six times the
bytes, and it arrives as a PLAIN OBJECT. A SPIFFE request and reply carry
X509-SVIDs, bundles, CSRs and private keys as protobuf `bytes`, so grpc-js would
have been handed a non-Buffer for a `bytes` field and the failure would have
landed inside protobuf serialization, naming a field, one process from the
cause.

It forks `serialization: 'advanced'` now — `common/worker_pool.js`'s argument
about a 32,000-byte signature, reaching the second pool — and it is a strict
superset for everything that channel already carried.

**`structuredClone()` IS NOT THAT CHANNEL, and assuming it was cost a test.**
That is the algorithm the documentation names, and it downgrades a `Buffer` to a
`Uint8Array` where node's IPC hands back a real Buffer. The first version of
`tests/spiffe_operations.js` modelled the channel with it and failed against a
service that was working. It forks an echo child now and asks.

### The worker table is filled only in a worker

Requiring `common/request_worker.ts` pulls `common/service_state.ts` in at
module scope. Registering from the front process is therefore a table nothing
there will ever read, bought with a load of the store, the keys, the minted rows
and coordination — so `registerWorkerMethod()` returns early unless
`STS_REQUEST_WORKER` is set.

**IT WAS UNCONDITIONAL FOR TEN MINUTES AND `tests/spiffe_pki.js` WENT RED IN THE
SUITE WHILE PASSING ALONE.** `run.js` runs every file in one process, so pulling
that module in at a new point in the load order changed what a later file saw of
the certificate hierarchy — the process-wide-state hazard `tests/CLAUDE.md`
warns about, arriving from the one direction nobody watches: a require added for
a feature that is off. `ldap/ldap_server.js` was given the same gate in the same
change.

### What is asserted

`tests/spiffe_operations.js` is the in-process half — the codec both ways, a
real throw carrying its status, the caller reaching the handler, the byte
channel driven through a real fork, and the stream exclusion read off the loaded
protos rather than written down. Eight mutants, all caught; **two survived the
first round and both were the fixture** — the test was building the request
shape itself, so a codec that sent `caller: null` passed, and it was rebuilding
a result by hand, so a worker that dropped the status code passed. It drives
`methodRequest()` and `performMethod()` now.

Driven over real gRPC on 2026-09-12 with two workers: `FetchJWTSVID` and
`ValidateJWTSVID` answered by two different workers, all six Server API probes
answered by workers, an 841-byte DER bundle and a 2,912-byte certificate
crossing intact, `NOT_FOUND` arriving as code 5 — and `FetchX509SVID` never
leaving the front process.

**The end-to-end claim is still this directory's standing obligation** and is
unchanged by any of it: what a handler ANSWERS is not asserted here, only that
the answer is the same through the codec.

## ONE AUTHORITY PER REALM FOR THE CLUSTER (2026-09-14, #46)

`spiffe.authority-agreement`. The X.509 authority is the realm's SPIFFE Issuing
CA, which `common/pki.js` now builds once for the cluster and every node adopts
from the store — so `spiffe_auth.ts` on B verifies an X509-SVID A issued against
the same CA, and the comment in `buildTrustMaterial()` that the row "is
replicated by the same mechanism" holds across containers rather than within
one. The JWT authority, and the self-signed X.509 fallback of a realm with no
hierarchy, raced on first use: each node generated one and the later minted
write won, and a JWT-SVID minted by the loser in between was refused everywhere.
`establishOnce()` makes them once where the store arbitrates: claim
`spiffe.authority` per realm and kind, sync, make only if still missing, commit
(`flushMinted()`) before releasing; a node that finds the claim held syncs until
the authority arrives. A store that cannot be asked, or a claim held past two
minutes, makes nothing (`STS-SPIFFE-0076`). **Not covered: two ROTATIONS at
once on two nodes** — `rotateJwtAuthority()` reads, prepends and writes back,
and the later write wins; a rotation is an operator act and the barrier
serialises a sequential pair. `tests/cluster_key_pki_agreement.js` section 13
pins the claim (and its control); the live probe did not discriminate — the
control converged too, through replication, before anything was minted.

## A JOIN TOKEN IS SPENT ONCE ACROSS NODES (2026-09-14, #46)

`joinTokens` replicates, and the token was deleted from it at the SUCCESSFUL
attestation — so two AttestAgent calls with one token at two nodes inside the
change log's window both attested, two agents from a single-use credential.
Wherever the token is checked (`auth.authRequired()`, which is
`mode.gatesSpireServerApi()` and answers true in both modes) it is CLAIMED once
every check that refuses without side effects has passed and before the CSR is
signed; a
claim another call holds is `STS-SPIFFE-0055`, the spent-token refusal it
always was, a store that cannot be asked is `UNAVAILABLE` (`STS-SPIFFE-0075`),
and an attestation that throws after the claim (the CSR, a ban recorded
between) gives it back. (This read "Development mode checks no join token and
claims none"; the predicate has never distinguished the modes.)

## THE SPIRE SERVER API ASKS THE ACCESS POLICY, AFTER SPIRE'S OWN TABLE (2026-09-06)

In `spiffe_grpc.ts`'s `prepareCall()`, as `auth.authorize(caller, method) ||
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

## A PRESENTED X509-SVID IS LOOKED UP IN THE REVOCATION REGISTER (2026-09-12)

`verifyPresentedCertificate()` asks `common/revocation_status.js`'s SYNCHRONOUS
door once the signature and the trust domain have passed: the SVID's serial at
this realm's SPIFFE Issuing CA, that CA's at the realm Intermediate, and the
Intermediate's at the Root — so revoking the SPIFFE Issuing CA on `/admin/pki`
refuses every SVID under it at the SPIRE Server API, with `STS-PKI-0118` on the
refusal's audit row. **The register only, whatever `pki.revocationCheck` says**:
this runs inside a gRPC handler that cannot wait on a fetch, and a FEDERATED
SVID has no revocation mechanism but its bundle, which `authorityCertificates()`
already honours — so a federated one is answered `not-consulted` and never
refused on it. **An SVID is minted by `issueUnder()`, which records nothing**, so
revoking one individually means naming its serial by hand; revoking an authority
is the ordinary case. `common/CLAUDE.md` 3ad argues the check.

## THE 2026-09-12 AUDIT OF HARD-CODED VALUES, AND WHAT IT CHANGED HERE

An audit for literals that decided something went through this directory. Most
of what it found became a setting; four were defects in every mode and were
fixed unconditionally; three became mode-dependent through `common/mode.js`'s
predicates. `tests/ssf_spiffe_scim_hardening.js` holds all of it, twelve
mutants caught across the three directories it covers.

### Federated bundles are a realm's own, and none may shadow a served domain

`spiffe_ca.ts`'s federated store was `realms.sharedMap(... scope: 'shared')`,
argued as *SPIFFE is one trust domain for the whole service*. That stopped
being true when each realm got a trust domain, and the store was left behind.
**The consequence was a realm boundary one API call wide**: realm `acme` could
register a bundle NAMED `example.org` — the default realm's domain — because
the "not your own domain" check compared against the CALLING realm only;
`spiffe_auth.ts`'s `authorityCertificates()` then offered that bundle's anchors
in every realm, and `verifyPresentedCertificate()` matches a signer to a trust
domain by the LABEL the bundle was stored under — so a certificate acme's
operator minted for `spiffe://example.org/admin` authenticated on the default
realm's SPIRE Server API. And `spiffe_workload.ts` keyed FetchX509Bundles by
trust domain, so the federated entry OVERWROTE the realm's own bundle.

**Three halves, and each is needed.** The store is `realms.map()`. A bundle may
not be registered under ANY trust domain this process serves
(`servedTrustDomains()`, every realm's, SPIFFE on or off). And every reader —
`federatedBundles()`, `federatedBundle()`, `federatedX509BundleDer()`,
`jwkSetFor()` — ignores a row named after a served domain, which is what
protects a row an older build persisted; the two Workload API bundle maps also
write the realm's own key LAST. A DELETE of such a name is never refused.

**What it costs**: one realm of this service can no longer be told to trust
another by federating with its bundle. Two realms here share a Root and a
process, and the only thing such a federation could add is a way round the
boundary the Intermediate draws.

### A realm is created without TCP gRPC listeners or administrators

`realms.js` seeded only the socket paths, so a realm inherited 8092, 8181 and
`0.0.0.0` — addresses the default realm already holds — and turning its SPIFFE
on produced two refused binds every time. It now also seeds
`spiffe.workloadPort` and `spiffe.serverPort` to **0** and `spiffe.adminIds` to
**empty**. Distinct ports were rejected (this file argues a realm is an ADDRESS
with the ports unchanged, and no port that file could pick is known to be
free); an address cannot be chosen automatically because nothing knows which
addresses the host has. So a realm turned on gets its two Unix sockets, and the
SPIRE Server API — the network-reachable surface that mints credentials — is
opened on TCP only by somebody setting `spiffe.grpcHost` and the two ports on
the realm. The inherited admin ids named SPIFFE IDs in another trust domain;
nothing in the realm could verify them, so they granted nothing and published
administrators of nothing.

### Mode-dependent, through the predicate that names the question

* **`registry.seed()` asks `mode.seedsDemoData()`** — the three sample entries,
  one selecting `unix:uid:1000`, are three identities nobody configured.
* **`entitledEntries()` asks `mode.autoCreates()` AS WELL AS
  `spiffe.autoCreateEntries`** — in product the setting cannot invent
  `spiffe://<domain>/workload` for whoever reaches the socket, and the refusal
  says which of the two decided.

### Defects fixed in every mode

* **The rotation period** was `max(30, spiffe.svidTtl / 2)` while an entry's own
  `x509SvidTtl` wins at the mint. It is half the SHORTEST lifetime the last
  response actually carried (read off the minted certificates, which are clamped
  to their issuer), re-armed after every send, with the 30-second floor gone —
  below a minute it made the period longer than the lifetime.
* **`mintX509Svid()` read `spiffe.x509KeyType` in the AMBIENT realm** while
  minting for `opts.realm`; it reads the target realm's, and the `'ec-p256'`
  literal behind it — a second default beside config.js's — is gone.
  `downstreamCa()` read `spiffe.caTtl` the same way and was fixed with it.
* **Socket permissions.** The SPIRE Server API socket is the trusted `local`
  entity and nothing had set its mode. A directory created for it is 0700 and
  the socket is chmod-ed 0600 once bound (connecting needs write on the socket,
  so 0600 is this uid alone); a directory created for the Workload API socket
  is 0755 — reachable, as its specification needs, and never writable by
  others, since a writable directory lets anybody replace the socket. A
  directory that already existed is warned about and never chmod-ed. There is
  a window between bind and chmod in which the socket has the umask's mode; the
  0700 directory is what closes it when this service created the directory.
* **CreateJoinToken's cap evicted a live token** — the 257th silently
  invalidated one already handed to an agent. Expired tokens are swept first,
  a re-set of the same value does not count, and at the cap the NEW request is
  refused with RESOURCE_EXHAUSTED.

### New settings, each defaulting to the literal it replaced

`spiffe.caSubject` (`CN=sts SPIFFE {kind} ({trustDomain}),O=sts`, the
self-signed fallback CA and every downstream CA), `spiffe.retainedAuthorities`
(4, min 2 — `MAX_RETAINED_AUTHORITIES` is a getter over it so the console's
report follows), `spiffe.agentSvidTtl` (0, meaning `spiffe.svidTtl`),
`spiffe.joinTokenTtl` (600), `spiffe.maxJoinTokens` (256, per realm),
`spiffe.maxPageSize` (1000) and `spiffe.maxRecordedConnections` (512,
`perProcess` — the same number for every realm's partition, which a realm must
not resize for the others).

### The connections an X509-SVID was recorded for are the LISTENER's realm's (2026-09-12)

`spiffe_auth.ts` remembers each accepted mutual-TLS connection so that an
X509-SVID is ONE authentication per connection. That register was
`realms.sharedMap(… scope: 'shared')` — right while there was one pair of
sockets, and a leak once each realm had its own: one realm's connections counted
against, and evicted, another's from one cap, and every realm's keys sat in one
row set. It is `realms.map({ persist: 'spiffe.recordedConnections' })` now.

**THE REALM OF A gRPC CONNECTION IS THE LISTENER IT WAS ACCEPTED ON**, and that
is the only answer available: the path is the method name and the caller sends
nothing that names a realm. `handlersInRealm()` enters that listener's realm
around every handler — the default realm's four sockets are started through the
same `startRealm('')` — and `recordCaller()` runs inside `prepareCall()`, which
is inside the handler and stays in the front process, so the ambient realm there
is the socket's. A connection key (thumbprint and peer address) is one connection
to one socket, so no entry could ever have been legitimately shared.
`tests/realm_isolation.js` records a caller in a realm, in a child process, and
reads the partition back.

**Left alone and said so**: the `x-sts-workload-selector` metadata key —
renaming it breaks every client that sends it.
