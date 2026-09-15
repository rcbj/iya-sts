# oauth-oidc/

A full OAuth 2.0 authorization server and OpenID Connect provider, plus the four
libraries that decide things on its behalf.

| File | What it is |
|---|---|
| `oauth2.js` | Every endpoint. The only module here that touches `res`. |
| `oauth2_bcp.js` | RFC 9700, the Security BCP, as a table of requirements with a check citing each. A MODE. |
| `client_auth.js` | All six token-endpoint authentication methods. The mechanics half of section 2.5. |
| `dpop.js` | RFC 9449, and `presentedAccessToken()` — the Bearer-or-DPoP check four protected endpoints share. |
| `mtls.js` | RFC 8705 certificate-bound tokens — the other half of RFC 9700 section 2.2 — and, since 2026-09-13, the POLICY RFC 8705's two sections share: a declared certificate method or `tls_client_certificate_bound_access_tokens` held to in every mode, and section 7.1's refresh rule. See 3an. |
| `assertion_grant.js` | **RFC 7521 and RFC 7523, both halves.** The JWT bearer AUTHORIZATION grant (§2.1), and the assertion FORMAT `client_auth.js` takes its JWKS reading and its JWE unwrap from. |
| `saml_assertion_grant.js` | **RFC 7521 and RFC 7522, both halves.** The SAML 2.0 bearer AUTHORIZATION grant (§2.1) and CLIENT AUTHENTICATION by the same document (§2.2), in ONE `verify()`. A SEPARATE implementation from `assertion_grant.js` and not that one with a format flag — see 3z. |
| `authorization_servers.js` | Makes one process BE several authorization servers, selected by a path component. |
| `oauth21.js` | **OAuth 2.1 (draft-ietf-oauth-v2-1-16), as a MODE that turns RFC 9700 mode on** — the difference between the two, as a table of requirements with a decision citing each. See 3ah. |
| `introspection_jwt.js` | **RFC 9701 (2026-09-13).** Whether an introspection request asked for a JWT, what the resource server registered (section 6's defaults applied), and the signed — optionally encrypted — `token-introspection+jwt` response. See 3ai. |
| `software_statement.js` | **RFC 7591 section 2.3 (2026-09-13).** Whether a software statement is trusted, what it fixes in a registration, the RFC 7592 update binding, and issuing one as this realm. See 3aj. |
| `request_object.js` | **RFC 9101, JAR (2026-09-13).** Resolves an authorization request's `request` or `request_uri` — fetched only from a registered address — decrypts, verifies and checks the object, and hands the endpoint the parameters that replace the query's. See 3ak. |
| `authorization_details.js` | **RFC 9396, RAR (2026-09-13).** Parses and checks `authorization_details` against the types resource applications DECLARE, the section 6 subset rule, the resource a set of details addresses, and the one-time consent. See 3am. |
| `par.js` | **RFC 9126, PAR (2026-09-13).** The store of pushed authorization requests: the `request_uri`, bound to its client and authorization server, read without spending, spent when a response is issued, expired, listed and deleted. `oauth2.js` answers `POST /oauth2/par`. See 3al. |
| `oauth2_monitor.js` | **The counters behind `/admin/oauth2/monitor` (2026-09-13)**, in sections; pushed authorization requests are the first. |
| `oauth2_monitor_console.js` | **The view and action model of that page (2026-09-13)** — `monitorView()` and `monitorAction()` (`delete-pushed-request`), no route, no `res`, no markup; both doors render the same call (rule 7). `gnap/gnap_console.js`'s arrangement, and one of the files `tests/admin_actions_layer.js` allows to require `admin-core/admin_views.js`. |
| `oauth2_monitor_admin.js` | **THE ONE FILE HERE BESIDE `oauth2.js` THAT REGISTERS ROUTES**: `GET` and `POST /admin/oauth2/monitor`, in the console's shell. Required at 18f in `common/protocol_stack.js`, never from `oauth2.js`, which would drag the console in front of the authorization server. |
| `oauth2_monitor_api.js` | `GET /admin-api/oauth2/monitor` and `POST /admin-api/oauth2/monitor/{action}`, `ROUTES` spread into `mgmt-api/admin_api.js` beside ACME's; requires its model lazily. Codes `STS-ADMIN-0700..0705` and `STS-API-0100..0102`; `tests/vendored/sts_oauth2_monitor.js` drives both doors. |
| `protected_resource_metadata.js` | **RFC 9728, CONSUMED (2026-09-13).** Reads a protected resource's metadata document — pasted, uploaded or fetched from an administrator's URL — checks every section 2 member and section 3.3, compares `authorization_servers` with the realm's issuers, and proposes the application `/admin/applications/new` creates. The fetch takes `federation_http.js`'s policy and, in product mode, resolves once, refuses an internal address and pins the connection (`mode.dialsInternalAddresses()`); section 3.3 and a non-https `resource` are refused in product and warned in development (`mode.acceptsNonconformingResourceMetadata()`); malformed is refused in both. `signed_metadata` is decoded, never verified or applied. Its file header argues each decision. |
| `jwt_access_token.js` | **RFC 9068, both halves (2026-09-13).** The `at+jwt` header, the issuer and default audience the minter uses and every resource server here checks, and the audience-and-scope plan behind section 3's refusals. In every mode — see 3ah. |

**Everything but `oauth2.js` — and, since 2026-09-13, the console page
`oauth2_monitor_admin.js`, required at 18f rather than from here — registers
nothing.** They are libraries in the sense
rule 3 of the root `CLAUDE.md` means: they require only `../common` and each
other, so they cannot join a cycle and their position in the require order is not
a position at all. The split throughout is the same one: **a library decides and
`oauth2.js` answers.** What a refusal LOOKS like is protocol knowledge and stays
in the one module that has a response object.

`dpop.js` is where `presentedAccessToken()` lives rather than
`../oid4vc/vc_issuer.js`, where it was written, because the fourth caller is in
`oauth2.js` — which `vc_issuer.js` cannot be required from without building a
cycle or moving OID4VCI ahead of OAuth2 in the route order.

Two ordering facts about this directory are in the root `CLAUDE.md` because they
are facts about `server.js`: `ws-federation/wsfed.js` must be required AFTER
`oauth2.js`, and so must `admin-ui/admin.js`.

---

3f. **`oauth2_bcp.js` is a library like `dpop.js`, and it is a MODE rather than a
   change of behaviour.** It holds this service's model of RFC 9700 (the OAuth 2.0
   Security Best Current Practice) — the whole of that BCP's section 2, as a table
   of requirements with a check citing each by id. It registers nothing and
   requires `crypto`, `helpers.js`, `config.js`, `realms.js`, `applications.js`,
   `client_auth.js`, `validation.js` and `oauth21.js` — this sentence named only
   the first three until 2026-09-13, when a reviewer found it had been out of
   date for weeks — none of which requires it back, so it cannot join a cycle
   and its position in the require order does not matter. **`common/cors.js`
   requires it too** (it was `app.js` until 2026-09-13, when CORS became an
   allowlist), for one decision (section 2.6's "no CORS at the authorization
   endpoint"), which is safe for exactly that reason and is the only middleware
   this mode touches. Six things in it are load-bearing:

   **The flag is the whole contract, and it is RESTART-ONLY.** `oauth2.rfc9700`
   is OFF by default and every entry point in the module returns "no opinion"
   while it is, so the service behaves EXACTLY as it did before the file
   existed. That is not timidity: every existing caller of this mock uses an
   unregistered `redirect_uri`, no PKCE or the implicit grant, and a client is
   exercised by both answers — one that has only met a permissive server has
   never run its own refusal paths, and one that has only met a strict server
   cannot reproduce the behaviour it is trying to detect. It stopped being a
   runtime setting the moment it grew a consequence that happens before the
   service is listening: `global.https` derives its default from it, so it binds
   the main port as HTTPS. A flag that was runtime for its checks and
   restart-only for its socket is the silent disagreement the config.js header
   warns about — /admin/oauth2 would report the mode as on while every
   authorization response still went out over plain HTTP.

   **RESTART-ONLY FOR THE PROCESS; A TRUST REALM MAY CARRY IT.** That is the
   whole of the `realmRuntime` marker, and `oauth2.rfc9700` is the only row in
   `config.js` that has it. The paragraph above is an argument about a BOUND
   SOCKET, and a realm has none — it answers on the port this process already
   opened, in the scheme that port was opened in — so the reason does not reach
   it, and `enabled()` here reads the setting per request through the realm
   layer exactly as every runtime row is read. One process therefore serves both
   passes: permissive at `/oauth2/authorize`, compliant at
   `/realm/<id>/oauth2/authorize`, with their own issuers, keys, codes and
   tokens. NOTHING IN THIS MODULE WAS EDITED FOR THAT — it is `config.value()`
   consulting the ambient realm, which is the property `common/CLAUDE.md` argues
   the whole realm design rests on.

   What a realm does not bring is a SCHEME, and `mainPortIsTls()` is where that
   shows: it reads `global.https`, which is a property of the process. A
   compliant realm on a plain-HTTP service enforces every check in
   `REQUIREMENTS` and still publishes `http://` endpoints — the combination
   `global.https` exists to make settable both ways — and it is PUBLISHED rather
   than hidden, because those four deployment rows come back `no` instead of
   `deployment` and `GET /oauth2/rfc9700` names the scheme. A stack that wants
   the compliant pass over HTTPS turns `global.https` on for the whole process
   and leaves the mode to the realm.

   **It decides; `oauth2.js` answers.** This module never touches `res`. What a
   refusal LOOKS like is protocol knowledge and stays there — the same split
   `authn.js` has — and the order is load-bearing rather than stylistic: the
   `redirect_uri` is matched FIRST and a failure is answered as a 400 on this
   service, because reporting `error=invalid_request` by redirecting to an
   unvalidated URI is still the browser being forwarded to an arbitrary URI, and
   an attacker does not mind which parameters ride along. Everything after that
   check may be reported to the client.

   **THREE THINGS OUTSIDE THE AUTHORIZATION ENDPOINT, and each is at a funnel
   rather than a call site.** Refresh token lineage is recorded inside
   `refreshToken()` in `oauth2.js` — the one function that mints one, so no
   grant can issue a refresh token outside its family; the sender-constraining
   note is inside `tokenSet()`, the one place a grant mints a token set; and the
   client-authentication and grant-type checks are ABOVE the grant switch at the
   token endpoint, because a client that cannot authenticate has not
   authenticated whichever grant it was about to ask for. Do not move any of
   them into a branch — five branches means a sixth added later with none, which
   is the same reasoning that keeps `signJwt()` the single counter.

   **A REFRESH TOKEN CARRIES ITS RESOURCES, and forgetting that was a hole.**
   RFC 8707 narrows an access token's audience; the refresh token has to carry
   the same list or the grant WIDENS ITSELF BY BEING RENEWED — the refreshed
   access token would get this service's default audience, which is broader than
   what was authorized. `refreshToken()` records `resources`, the refresh grant
   reads them back for the new audience, and a refresh naming one the grant does
   not carry is `invalid_target`. The same shape as the scope check one field
   over.

   **THE IDLE TIMEOUT IS ON THE FAMILY AND REFUSES RATHER THAN REVOKING.**
   `lastUsedAt` lives on the family and is touched at `noteRefreshRotated()` —
   at the SUCCESSFUL redemption, so a run of refused attempts cannot keep a
   chain alive. It refuses without revoking the family because an idle chain is
   a client that went away and a replayed one is a chain that was copied;
   collapsing the two would make the replay refusal, which says something
   serious, indistinguishable from an afternoon off.

   **REVOCATION IS STILL `stats.revoke()` AND THIS MODULE NEVER CALLS IT.**
   `checkRefreshRequest()` returns the jtis a replay should kill and `oauth2.js`
   revokes them, which keeps both rules intact at once: the one-store rule (the
   revocation set `/oauth2/revoke` and the console write to is the only one), and
   this module's own — it decides, the protocol acts. A rotated token is revoked
   through the same call, which is why a retired refresh token also reports
   inactive at `/oauth2/introspect` rather than merely failing to refresh.

   **The transaction check runs where the values are SPENT.** An authorization
   request runs through `/oauth2/authorize` twice — once before the sign-in
   screen and once on the way back with a session — so a reuse check at the top
   of that endpoint refuses every request in the service for reusing its own
   values between its own two passes. It is called from
   `issueAuthorizationResponse()` immediately before a code is minted, and the
   token endpoint marks the transaction finished when the code is redeemed. A
   value presented again BEFORE that is a reloaded tab, not a second
   transaction, and refusing it is how a check like this gets turned off.

   **What the mode refuses, the metadata stops advertising**, and it happens in
   `asMetadata()` for the reason the two discovery documents are built from one
   object at all: narrowing one of them would produce exactly the drift that
   arrangement exists to prevent.

   **A REFUSAL AT AN ENDPOINT NEEDS THE MATCHING REFUSAL AT REGISTRATION.**
   `checkClientRegistration()` refuses metadata the other endpoints would refuse
   in use — the password grant, the implicit grant, a response type naming
   `token`, an `http` redirect URI off the loopback — because a registration is
   a document the client KEEPS and acts on, and recording a permission this
   server will always refuse is the discovery document's promise broken in the
   other direction. It refuses rather than silently returning different
   metadata, which RFC 7591 also permits: a client that registered for
   `password` and got a registration quietly without it would have to diff two
   documents to notice. **When a new refusal is added to an endpoint, look for
   the registration member that would have recorded it.**

   **ONE DECISION ABOUT FORWARDED HEADERS, SHARED.** `helpers.forwardedFrom()`
   decides whether `X-Forwarded-Proto`/`X-Forwarded-Host` are believed, and both
   `baseUrlOf()` and `dpop.js`'s `htuOf()` go through it. They used to disagree
   — dpop believed them unconditionally and baseUrlOf ignored them — and each
   answer was wrong for the deployment the other was written for: behind a proxy
   the metadata published the last hop's URLs, and without one a client could
   choose the `htu` its own proof was checked against, which unbinds the proof.
   `global.trustProxy` is OFF by default and the htu refusal NAMES it. Do not
   let a third function make this decision a third way.

   **NO CLIENT CERTIFICATE IS EVER READ FROM A HEADER.** `X-Client-Cert` and its
   dozen vendor spellings are listed on `/tls/forwarded` and read by nothing:
   a certificate in a header is one anybody can forge, so RFC 8705 binding and
   mTLS client authentication both take it off the TLS handshake. The cost —
   a proxy terminating mTLS cannot pass the certificate through — is stated
   rather than hidden, and the headers a request carried are SHOWN so that
   ignoring them is visible rather than silent.

   **RESOURCE INDICATORS AND THE AUDIENCE CHECK ARE FEATURES, NOT MODE
   BEHAVIOUR.** RFC 8707 `resource` is honoured in both modes and the protected
   endpoints refuse a token issued for another audience in both, because a
   request that sends no `resource` is unaffected either way — the flag contract
   ("mode off changes nothing") is about existing callers and no existing caller
   sends it. Two details in the check are easy to get wrong: it applies only to
   a token this service VERIFIED (a foreign token's `aud` is a string nobody can
   check), and ~~it matches on the PATH rather than the whole URL, because every
   token carries `<base>/resource` where the base is whatever URL minted it — a
   whole-URL comparison refuses a token minted at localhost and presented at
   127.0.0.1, while a token narrowed to somebody else always has a different
   path~~ — **REVERSED 2026-09-13 (3ah): it compares the WHOLE URL.** The path
   test was an `endsWith('/resource')`, which accepted
   `https://api.partner.example/resource` — somebody else's server, narrowed
   to on purpose — and RFC 9068 section 4 does not permit the localhost/127.0.0.1
   reading it was written for: an identifier the resource server does not
   expect is not one it expects. `global.publicBaseUrl` is the answer for a
   service reached under several names.

   **`resource` IS READ FOR EVERY GRANT, and it was read for two until
   2026-08-26.** Section 2 puts the parameter on *a token request* — the grant
   types RFC 6749 defines and the extensions built on them, not a chosen pair.
   Only `authorization_code` and `refresh_token` parsed it, because only they
   have something to NARROW, and the other four IGNORED IT SILENTLY: a
   `client_credentials` request asking for `https://apigw1.example.com` got
   `<base>/resource` and no error, so the restriction the client believed it had
   was never there. It is parsed ONCE now, above every grant in
   `tokenEndpoint()`, for the reason the DPoP check above it is where it is — a
   malformed `resource` is malformed whatever is being asked for. The two
   narrowing RULES stay per grant, because they are the half that depends on
   what came before; the four direct grants have no earlier decision for a rule
   to be about, and inventing one would refuse the only request they can make.

   **THE REPETITION WAS A SECOND HOLE UNDER THE FIRST.** `helpers.parseBody()`
   builds a plain object, so `resource=a&resource=b` arrived as `b` and
   `parseResourceIndicators()` — written to accept an array since the day it was
   added — could never be handed one. `bodyValues()` in `helpers.js` reads the
   repetition from the raw body, and `parseBody()` is deliberately NOT changed:
   sixty-odd call sites across fourteen modules read that object with
   `String(body.x)`. `admin-ui/admin.js`'s `listField()` is the same function
   written first, for the console's checkbox columns; the two are deliberately
   identical in shape so that folding them is a one-line delegation, which has
   to happen in THAT file because it requires this one (rule 5).

   **AND THE TOKEN EXCHANGE HAD BOTH BUGS AT ONCE.** `body.audience ||
   body.resource` discarded the resource whenever both were sent — RFC 8693
   section 2.1 says outright that they MAY be used together — and never
   validated it, so a fragment or an array went straight into `aud`. They are
   unioned now, with the resources read through the shared parse. `audience` is
   NOT put through it: section 2.1 calls it a *logical name*, which is not
   required to be a URI. Audiences come FIRST in the union, and that ordering is
   the one compatibility decision here rather than a reading of the RFC — order
   means nothing in an `aud` array, but the delegation act files an exchange
   against ONE target and `audience` winning is what it did before.

   **AND A SCOPE THAT NAMES ANOTHER APPLICATION IS AN AUDIENCE TOO — added
   2026-08-26, and it is the mechanism clients ACTUALLY use.** RFC 8707 above is
   how a client SHOULD say which resource server a token is for; a scope list
   carrying the API's name (`scope=openid email profile apigw1`, no `resource`
   parameter anywhere) is how every real deployment of the pattern does it. So
   `audienceScopes()` in `oauth2.js` reads one: a scope value that is the
   `oauthClientId` of ANOTHER application in the registry becomes the `aud` and
   comes off the scope claim, and everything else is untouched. Four rules and
   each has a reason written above the function — the match is against
   `oauthClientId` and not the audience or the entry's `cn`; the audience is the
   scope value VERBATIM rather than that application's `oauthAudience`; a
   spec-defined scope is never an audience whatever the registry says (nothing
   stops somebody registering a client called `profile`); and the client's own
   client_id is skipped.

   **TWO CONSEQUENCES ARE THE INTERESTING PART, AND BOTH WERE FOUND BY RUNNING
   IT.** The refresh token keeps the WHOLE scope while the access token loses
   the value that became its audience — the one place the two halves of a grant
   deliberately disagree, because section 2.2.2 binds a refresh token to what
   was AUTHORIZED and `oauth2_bcp.js`'s `scope-not-widened` compares a refresh
   request against it, so stripping it there refuses a client that refreshes
   with the scope list it originally sent. **Since 2026-09-13 a refresh also
   HANDS ON the grant it was given rather than the one it asked for** — the
   refresh branch passes `grantScope`/`grantResources` so the ROTATED refresh
   token carries what the presented one carried (RFC 6749 section 6, OAuth 2.1
   section 4.3.3), in both modes; before that, one narrowing refresh shrank the
   grant for good. ~~And an `openid` token gets
   the default audience APPENDED beside the derived one
   (`withOwnResource()`), because `audienceRefusal()` in `dpop.js` refuses a
   token addressed elsewhere and `/oauth2/userinfo` is one of the endpoints it
   guards: without it, the exact request this feature was written for produced a
   token that could not call UserInfo.~~ **REVERSED 2026-09-13 AT RCBJ'S CHOICE
   (3ah): a token for an API is for the API ALONE**, and `openid`, `profile`,
   `email`, `address`, `phone` and `offline_access` are left off its scope claim
   and off the response's `scope` member. RFC 9068 section 2.2.3 says every scope
   on the token MUST have meaning for the resources in its `aud`, and `apigw1`
   handed `openid profile` cannot tell which are its own. The OIDC scopes stay
   GRANTED — the ID Token is minted and the refresh token keeps the whole scope
   — and a client that wants UserInfo asks for a token without the API in it.
   That is Microsoft Entra ID's arrangement, which this feature already copies,
   and the same now holds for RFC 8707's `resource`, which never had the append.

   **THE REPLAY RELAXATION IS THE ONE THING THE TWO MODES ANSWER DIFFERENTLY
   ABOUT A CODE.** `redeemedCodes` in `oauth2.js` answers an IDENTICAL repeat
   with the tokens it already bought, for the reason written where it is
   declared. RFC 9700 section 4.5 says a real server refuses that, so
   `checkCodeReplay()` does — and revokes the access, refresh and ID Tokens that
   code bought (RFC 6749 section 10.5), through `stats.revoke()` called by
   `oauth2.js`, never by this module. It sits BELOW the two refusals that are
   more specific — a repeat that differs, and a code whose lifetime ran out —
   because those are already refusals in both modes and each deserves its own
   sentence.

   **TWO REQUIREMENTS ARE IN THE TABLE AS `enforced: 'no'` BECAUSE THEY ARE THE
   CLIENT'S**, not because they were skipped: the client must validate the ID
   Token's nonce and must not use a token before that succeeds. Nothing this
   server observes separates a client that checks from one that does not. What
   it can do instead is `oauth2.breakIdTokenNonce` — a deliberately wrong nonce,
   off by default, NOT part of this mode (it is useful in either), reported on
   `GET /oauth2/rfc9700` and logged on every token it spoils. That is the same
   device as `/spnego`'s three knobs and the reserved password `invalid`: a
   reachable negative. Do not fold it into the mode — a compliance flag that
   also breaks tokens is a flag nobody will turn on.

   **THE TLS REQUIREMENT IS NOT A CHECK AND MUST NOT BE MADE ONE.** "An
   authorization response MUST NOT be sent over an unencrypted connection"
   cannot be refused per request — by the time anything here runs the request
   has already arrived, and refusing it would report the problem down the same
   channel. It is a property of the SOCKET, so `global.https` settles it at
   `listen()` in `server.js`, using `tls_server.js`'s ONE per-start certificate
   rather than a second pair (see rule 6: that is the same reasoning that put
   LDAPS 636 on it). The row in `REQUIREMENTS` therefore has FUNCTIONS for
   `enforced` and `note` — the only row that does — and `state()` calls them, so
   the table stays the single source rather than half of that row's meaning
   moving into the view. It reports `deployment` when the port is TLS and `no`
   with the reason when somebody has set `global.https` false to run the checks
   over plain http, which is a case that must stay reachable: a client that
   cannot trust a certificate regenerated every start should still be able to
   exercise the rest. `GET /oauth2/rfc9700` publishes every row with `enforced`
   as yes / detected / always / deployment / no, and a compliance mode that
   quietly skipped a requirement it advertises would be the most misleading
   thing in this repository. New requirements are rows in `REQUIREMENTS` and the
   checks cite them by id; do not add a check with no row.

   **The SCHEME is derived and nothing pins it.** `baseUrlOf()` builds every URL
   from `req.protocol` and the Host header, so an https.Server moves the RFC
   8414 document, the OpenID Provider Configuration, the OID4VCI and OID4VP
   metadata, the federation metadata, the DID document and the `iss` of every
   token together, with no module told about any of it. Do not "fix" that by
   hardcoding a scheme anywhere — it would be wrong on the default plain
   listener. The ONE exception is a PINNED `oauth2.issuer`: `issuerOf()` in
   `oauth2.js` upgrades an `http://` pin to `https://` when the port is TLS and
   logs it, because a client MUST reject a document whose issuer is not the
   identifier it fetched from, and that failure names the issuer rather than the
   scheme. Pinning a different HOST still produces the mismatch it exists for.


3ah. **`oauth21.js` is OAuth 2.1 as a MODE, and it is a mode OF ITS OWN rather
   than RFC 9700 mode renamed (2026-09-13).** It follows
   draft-ietf-oauth-v2-1-16 — an Internet-Draft, which every row and
   `GET /oauth2/oauth21` say by revision — and it is a LEAF: `helpers.js` and
   `config.js`, nothing else, with every record it decides about PASSED IN.
   `oauth2_bcp.js` and `oauth2.js` require it. It decides; `oauth2.js` answers,
   which is 3f's split.

   **`oauth2.oauth21` IMPLIES `oauth2.rfc9700`.** `oauth2_bcp.js`'s `enabled()`
   answers true for either, because OAuth 2.1 is OAuth 2.0 with the best current
   practices applied and every row in that file's table is one of them — so a
   2.1 realm gets every RFC 9700 check once, and this file holds only the
   difference. `state()` over there carries `enabled_by`, or a realm carrying
   only this flag would read on `/oauth2/rfc9700` as enforcing with
   `oauth2.rfc9700: false` beside it. **`global.https` derives from both**
   (through `processValue()`, so a realm moves no socket), and so do both
   compose healthchecks.

   **THE DIFFERENCE HAS TWO HALVES AND THE LOOSER ONE IS WHY IT EXISTS.** RFC
   9700 mode requires `redirect_uri` at the token endpoint (RFC 6749 section
   4.1.3, `STS-OAUTH-0147`) and at the authorization endpoint; OAuth 2.1 section
   10.2 removed the first and section 4.1.1 makes the second optional when one
   URI is registered. So `checkTokenRequest()` asks
   `oauth21.tokenRedirectUriRequired()` and the authorization endpoint defaults
   a missing `redirect_uri` to the one registered — **checked against the
   redirect allowlist first**, because it comes off an entry `ldapmodify`
   reaches. A sent `redirect_uri` is still compared in every mode. **The one
   code that still needs it is a code issued under the nonce exemption**, which
   has no PKCE, and the record carries `pkce_exempt` for exactly that.

   **THE STRICTER HALF**, each a row with a code in the reserved
   `STS-OAUTH-0270..0299` block:

   * **PKCE for every client** bar a confidential one WITH A CREDENTIAL ON FILE
     asking for `openid` with a `nonce` (section 7.5.1.1) — `bcp.credentialOnFile()`
     is that test, and it replaced two inline copies of one expression in
     `oauth2_bcp.js`. `code_challenge_method` is read RAW, because the code
     record stores `|| 'plain'`.
   * **A client that registered its own redirect URI** (section 2.3.1).
     `registeredUrisFor()` reads no fallback to `oauth2.redirectUris` in this
     mode, and `checkClientIdPresent()` runs FIRST so a missing `client_id` is
     not reported as an unregistered client.
   * **A token request naming a client that declares nothing** — refused BEFORE
     `applications.seen()`, so the refusal does not create the entry.
     `clientConfigOf().declared` is the predicate, and it is *anything a
     sighting never writes*, because every client_id that ever reached an
     endpoint has an entry. Exempt, and published as exempt: the pre-authorized
     code grant and the assertion grants with no client.
   * **A presented credential must verify; one method per request; client
     credentials only for an authenticated client.** RFC 9700 mode lets a secret
     from a public, unknown or empty confidential client through; section 3.2.2
     does not. `tokenClientDeclarationRefusal()` and
     `tokenClientAuthenticationRefusal()` are TWO functions because the endpoint
     asks them either side of the credential being observed.
   * **A JWT client assertion's `aud` is the issuer as its SOLE value**
     (draft-ietf-oauth-rfc7523bis-11). The signature is verified against the
     lenient list and `client_auth.js` then refuses by name, so the refusal is
     about the audience. **`verifiedOnce()`'s key carries the policy**, so the
     token endpoint's two questions about one document cannot have the first
     answer decide the second — they share one audience list and one flag, and a
     mismatch would re-verify and meet its own replay rather than be silently
     cached. The grant (6923) keeps the lenient list; rfc7523bis allows the
     token endpoint there.
   * **No SAML client authentication**, dropped from the metadata and refused at
     registration too (3f's mirror rule). The RFC 7522 GRANT is untouched.
   * **No repeated parameters, a ten-minute code, `error_description`'s
     grammar.** The last is applied in one wrapper — `oauth2.js`'s local
     `oauthError()` over the helper — and in `redirectBack()`/`redirectTarget()`.

   **THREE CHANGES CAME WITH IT AND ARE IN EVERY MODE**, because they are fixes:
   private-use redirect URIs accepted and a scheme with no period refused
   (`common/validation.js`'s `redirectUriProblem()`, an ALLOWLIST where `uri` is
   a blocklist — see `common/CLAUDE.md`); a refresh token rotated from a narrowed
   refresh keeping the presented grant (the paragraph at 3f above); and a client
   secret that FAILS being rate limited, per realm and per client AND address,
   wherever a secret is checked. `/oauth2/logout` considers a private-use
   `post_logout_redirect_uri` only in RFC 9700 or 2.1 mode, and believes one only
   off the client's own list (`STS-OAUTH-0290`).

   **NOT DONE, AND WRITTEN DOWN**: the debugger's client side;
   introspection and revocation still authenticate no client; and product mode
   still checks an OAuth `redirect_uri` only when one of the two modes is on.
   `tests/oauth21_mode.js` and `tests/redirect_uri_schemes.js` are the
   in-process half, mutation-tested against twenty mutants.

3i. **`client_auth.js` verifies all six token-endpoint methods, and it is the
   PROTOCOL half of section 2.5.** `oauth2_bcp.js` decides whether a client has
   to authenticate at all (the policy); this decides whether what arrived proves
   it (the mechanics). It registers nothing and requires `helpers.js`,
   `config.js` and `mtls.js`, so it cannot join a cycle. Four things:

   **NOTHING FALLS THROUGH UNCHECKED ANY MORE.** `private_key_jwt` and
   `client_secret_jwt` used to be advertised and ACCEPTED without an assertion
   being looked at — worse than not offering them, because a client author came
   away believing a check had happened. A method this file cannot verify is now
   REFUSED, and `token_endpoint_auth_methods_supported` is built from
   `METHODS` so the metadata cannot advertise one that would not be.

   **THE METHOD DECIDES THE ALGORITHM FAMILY, NOT THE HEADER.** An assertion
   nominating `HS256` for `private_key_jwt` is refused rather than verified —
   verifying it would use the client's PUBLIC key as an HMAC secret, which is
   the classic JWT forgery and one anybody can perform.

   **THE UNVERIFIED `sub` SELECTS, IT DOES NOT ESTABLISH.** OIDC Core section 9
   lets a `private_key_jwt` request omit `client_id`, so `clientFrom()` reads
   the assertion's `sub` unverified — safe for exactly one purpose, choosing
   which registered client to check AGAINST, because the assertion is then
   verified against that client's keys with `iss` and `sub` required to match.
   Do not read anything else out of an unverified assertion.

   **`jwks_uri` IS RECORDED AND NEVER FOLLOWED**, which is the same refusal
   `wsfed.js` gives `wreqptr`: fetching a URL somebody registered in order to
   verify a credential is a server-side request forgery with a citation
   attached. Holding that position in one file and not the other would be no
   position at all.

   **THREE SOURCES OF KEY SINCE 2026-09-10, AND THEY ARE ORed.** What the client
   REGISTERED (`oauthJwks`), what this service ISSUED it from its own
   certificate authority (`oauthAssertionJwks`), and an `x5c` the assertion
   carries — the last used only after `common/pki.js` has shown it chains to
   this realm's Root. **Two attributes and not one**: the issue path must not
   overwrite keys a client registered, and a client holding both was given both
   deliberately.

   **A CLIENT ASSERTION IS VERIFIED ONCE PER REQUEST (2026-09-13)**, and that
   was a live bug rather than a tidiness. The token endpoint asks this file
   twice about one request — `oauth2_bcp.js`'s `checkClientAuthentication()` in
   RFC 9700 mode, then `observeClientAuthentication()` in every mode — and each
   used to spend the `jti`, so the second met a replay of the request's own
   document: the client was OBSERVED as unauthenticated, a role requiring
   `ALL_AUTHENTICATED_APPLICATIONS` refused it, and product mode's
   `requiresClientSecret()` would have refused it `invalid_client`.
   `verifiedOnce()` keeps the promise for a document on the request object under
   a Symbol, keyed by method, client, type and the document itself.
   `tests/vendored/sts_jwt_bearer_grant.js` section 14 is the over-HTTP proof and
   was mutation-tested by removing it.

   **AND AN ASSERTION MAY ARRIVE ENCRYPTED**, which is RFC 7523 section 3 claim
   10 and reaches BOTH parameters. It is unwrapped by
   `assertion_grant.unwrapAssertion()` — one function for both halves of the
   profile — with the client secret passed for the symmetric algorithms, because
   a `client_secret_jwt` client's only shared key IS its secret. A plain
   three-part JWS comes back untouched, so every client that authenticated with
   one before this existed is on exactly the path it was.


3h. **`mtls.js` is a library like `dpop.js`, and it is the OTHER half of RFC
   9700 section 2.2.** `dpop.js` binds a token to a KEY proved per request;
   this binds it to the CLIENT CERTIFICATE the TLS connection was made with (RFC
   8705 section 3). It registers nothing and requires only `helpers.js` and
   `config.js`, so it cannot join a cycle. Five things are load-bearing:

   **`dpop.js` REQUIRES IT, and that is where the resource-server check goes.**
   `presentedAccessToken()` there is the single check `/oauth2/userinfo` and the
   three credential endpoints share — the same reasoning that put that function
   in `dpop.js` rather than in `vc_issuer.js`. A second check beside it would be
   a fourth caller nobody updated.

   **The thumbprint is of the DER**, base64url, unpadded — not the PEM, not the
   public key, not hex. Every other spelling looks right in a log and matches
   nothing, so `thumbprintOf()` is the only place it is computed and both ends
   of the comparison go through it.

   **An UNVERIFIED certificate still binds.** `server.js` sets
   `rejectUnauthorized: false` on the main listener, and that is not a hole: RFC
   8705 section 3 binds to the CERTIFICATE and permits a self-signed one
   explicitly — the proof is that the same key completed this handshake, not
   that a CA vouched for it. Requiring verification would make the feature
   unreachable, since `/tls/trust` starts empty by design.

   **A REVOKED certificate is NOT verified, since 2026-09-12**, and it still
   binds. `peerVerified()` reads `req.certificateRevocation` — which
   `common/app.js` computes before any route through
   `common/revocation_status.js` — and answers `verified: false` with
   `CERT_REVOKED` (or `REVOCATION_STATUS_UNKNOWN` under hard-fail) for a chain
   the policy refused, so every caller resolving a certificate to an identity
   refuses it. `client_auth.js`'s `verifyCertificate()` refuses the same
   verdict for both RFC 8705 section 2 methods, BEFORE the subject or thumbprint
   match — a revoked certificate is a client secret its issuer withdrew. RFC
   8705 section 3 BINDING is deliberately untouched: it authenticates nobody.

   **The confirmation is MERGED with the DPoP one, never replaces it.** A client
   that presented a certificate AND sent a proof demonstrated both, and a token
   recording one would discard a check somebody performed. The REFRESH token is
   bound too — otherwise the long-lived half of the grant stays a bearer
   credential that mints bound tokens for whoever holds it, which is worse than
   not binding at all because the `cnf` on what it mints implies a guarantee
   nobody checked.

   **RFC 8705 SECTION 2 AND THE REST OF SECTION 3 ARE 3an.** This paragraph
   and the ones above it are the binding as it stood before 2026-09-13, and they
   still hold; 3an is what was added to them.

   **The request reaches `accessToken()` through ONE funnel.** The token
   endpoint's `issue()` adds `request: req` to every grant's options, so six
   call sites did not have to remember it — five that would and a sixth added
   later that would not, the reasoning that keeps `signJwt()` the single counter.
   Only available where the main port is TLS, and
   `tls_client_certificate_bound_access_tokens` is advertised only there: a
   client reads a metadata member as a promise.


3an. **RFC 8705, BOTH HALVES, AND THE CLIENT CERTIFICATE MAPPED TO AN
   APPLICATION (2026-09-13).** 3h and 3i are what existed: a binding that bound
   whatever certificate arrived, and a `tls_client_auth` that compared a
   registered DN to the subject by exact string and logged that no chain was
   checked. rcbj asked for both use cases, reusing the certificate-to-identity
   mapping a person's TLS client certificate signs them in by, and chose
   **implicit AND explicit matching**, a **door on the application's Credentials
   section**, **declared refusals in every mode** and **in-process tests**.

   **`tls_client_auth` HAS TWO MAPPINGS AND BOTH NEED A VERIFIED CHAIN.**
   `client_auth.js`'s `verifyCertificate()` asks `mtls.peerVerified()` first —
   the listener's chain, revocation and `tls_client_certificates.js`'s identity
   gate in one answer — and refuses anything unverified (`STS-OAUTH-0480`) or
   issued here and not an identity (`0481`). Then: a certificate the gate names
   as issued to an APPLICATION must be THIS client's (`0484` otherwise, whatever
   subject it registered — section 7.4) and still on its record
   (`tls_client_certificates.stillHeld()`, `0483`); anything else is matched
   against the ONE registered subject parameter by
   `common/certificate_subject.js` (`0485`, `0486` with none, `0482` for two an
   `ldapmodify` left). The five parameters live in five attributes, at most one
   set (`applications.mtlsAttributeProblem()` / `mtlsMetadataProblem()`,
   `STS-REG-0130..0136`), and RFC 7591 registration writes and clears them.
   **At most one, not exactly one**, because none is the implicit mapping.
   `credentialOnFile()` answers true for both certificate methods, so a declared
   certificate client is never waved through as half-configured.

   **`self_signed_tls_client_auth` READS THE RFC's `jwks` NOW** — a key's
   `x5c[0]` — beside the thumbprint attribute this service invented first.

   **THE DECLARATION IS HELD TO IN EVERY MODE** — `mtls.declaredRefusal()`, asked
   at the token endpoint after the observation and at `/oauth2/par`: a declared
   certificate method that did not authenticate is 401 `invalid_client` with the
   verifier's own code (`0488` when there is none), and
   `tls_client_certificate_bound_access_tokens` with no certificate is 400
   `invalid_request` (`0487`). The standing rule mode-gates refusals; these two
   are refusals the CLIENT asked for. Registration refuses the flag where the
   main port is not TLS (`STS-REG-0133`, 3f's mirror). Introspection and
   revocation do not ask it.

   **SECTION 7.1 AT THE REFRESH GRANT.** `mtls.refreshBindingApplies()` skips the
   refresh token's `x5t#S256` comparison only for a client that authenticated BY
   CERTIFICATE on this request AND is the token's own `client_id` — the check
   RFC 6749 puts on a refresh is RFC 9700 mode's here, so without the second half
   a certificate client could redeem another client's bound refresh token. The
   new tokens bind to the new certificate. A public client's refresh token keeps
   the check (section 4).

   **`/admin-api` AND THE EMBEDDED DEBUGGER CHECK THE BINDING** (`STS-API-0110`,
   `STS-DBG-0030`), where they verified signature, type, issuer and audience and
   never `cnf`. UserInfo, the credential endpoints, SCIM and SSF already did,
   through `dpop.presentedAccessToken()`.

   **NOT DONE**: `mtls_endpoint_aliases`; a certificate from a proxy header (3f);
   the debugger listener does not ask for a client certificate, so a bound token
   is refused there rather than usable. `tests/rfc8705_mtls.js` holds it — 72
   assertions over real handshakes, 27 mutants all caught.

3j. **`authorization_servers.js` makes one process BE several authorization
   servers, and the document is the server rather than a description of one.**
   The path component both discovery shapes carry selects one; its endpoints
   live under that name (`/{id}/oauth2/…`, registered in one block in
   `oauth2.js` so the prefixed set cannot drift from the unprefixed one); and
   the capabilities in its document DRIVE those endpoints. A library requiring
   only `helpers.js`. Nine things:

   **EVERY AUTHORIZATION SERVER STARTS EQUAL, and every name is one.** An
   unconfigured profile has the defaults `asMetadata()` builds, and a name
   nobody has configured is CREATED on first sight — by an endpoint or by a
   metadata fetch, since reading the document is accessing the server. It is
   marked `autoCreated` so the console can tell the two apart. Bounded at
   `oauth2.maxAuthorizationServerProfiles` (200, `MAX_PROFILES` until
   2026-09-12), past which a name is still SERVED with the defaults and
   simply not recorded: the id comes off a URL path, so any caller can invent
   one, and a load generator must not take the feature away from the names that
   matter.

   **`capabilitiesOf()` IS READ BY BOTH THE DOCUMENT AND THE ENDPOINTS.** That
   is the whole of how they are kept in step — there is no second table of what
   `tenant1` does that could disagree with what `tenant1` advertises. An
   enforceable member is marked `enforces` on its catalogue row; anything else
   is published and not read.

   **A REMOVED MEMBER MEANS THE CHECK DOES NOT RUN**, and that is the honest
   reading rather than a gap: a client cannot learn from an absent
   `code_challenge_methods_supported` that PKCE is unavailable, so a server that
   refused every method on the strength of having removed the member would be
   enforcing something it never said. `capabilityList()` returns null for it and
   every caller distinguishes null from an empty list.

   **A CREDENTIAL DOES NOT CROSS BETWEEN THEM.** The authorization code carries
   `authorization_server` and the token endpoint refuses one issued by another.
   They publish different capabilities and are presented to a client as separate
   servers; one process serving several must not let a credential leak between
   them.

   **`asBaseOf(req)` IS WHAT EVERY ISSUER AND AUDIENCE IS BUILT FROM.** A named
   authorization server is its own issuer, so its tokens' `iss`, their `aud`,
   and the RFC 9207 `iss` on its authorization responses all carry its path —
   and its document says the same, which is what a conforming client checks.
   **The sign-in return URL has to carry it too**: `returnTo` was hard-coded to
   `/oauth2/authorize`, which sent every named server's SECOND pass — the one
   that issues the code — to the default server, and the code came out belonging
   to somebody else with nothing on the way through looking wrong.

   And five things from before:

   **A CATALOGUE, NOT A SCHEMA.** Any member is settable, including one this
   service has never heard of, because publishing something a client did not
   expect is half the point of a mock. That is the deliberate OPPOSITE of
   `applications.js`, which refuses an attribute outside its table — that table
   is a published contract about what an entry carries, and this is a way to lie
   on purpose. Do not add validation here.

   **THE PROFILE IS APPLIED TWICE, and it has to be.** `asMetadata()` applies it,
   and then `oidcMetadata()`'s `Object.assign` overwrites every member OpenID
   Connect Discovery adds — so it is applied again at the end of that function.
   A profile that set `userinfo_endpoint` would otherwise work in the RFC 8414
   document and do nothing in the OIDC one.

   **IT IS APPLIED LAST, AFTER `bcp.applyToMetadata()`.** A profile is somebody
   saying "publish this", and a mode quietly winning would make the control
   appear not to work. A profile re-advertising the implicit grant the mode
   refuses is a document that lies about this server, which is the case the
   drift report exists for.

   **DRIFT MEANS SOMETHING NARROWER NOW.** It used to be "this document lies
   about this service", which cannot happen for an enforced member any more —
   the document IS the behaviour. `driftOf()` therefore SKIPS a member with an
   `enforces` row and reports the rest: what this service cannot honour however
   it is set. Those stay publishable, because a misconfigured document is a
   client error path worth running, and they stay reported.

   **AN UNCONFIGURED PATH IS NOT AN ERROR.** It publishes the ordinary document
   with the issuer taken from the path, which is what this service has always
   done — so adding this feature changed nothing for any existing caller, and a
   deleted profile leaves its URLs answering.


---

3x. **`assertion_grant.js` holds RFC 7521 and RFC 7523 in one file, and the
   dependency runs ONE WAY.** It is a library like `dpop.js`: it registers no
   route, so its position in the require order is not a position, and it
   requires `helpers.js`, `config.js`, `applications.js`, `common/crypto.js`,
   `common/pki.js` and `common/realms.js` — none of which requires it back.

   **ONE FILE BECAUSE RFC 7521 HAS NO WIRE FORMAT.** It is a framework: two
   request parameters, an error vocabulary and a list of checks. RFC 7523 is the
   only profile of it anybody uses, so everything 7521 asks for is implemented
   THROUGH 7523 and neither is testable without the other. A reader looking for
   "the RFC 7521 code" finds nothing else, and `tests/CLAUDE.md` says the same
   thing where it would otherwise look like a coverage gap.

   **TWO USES OF ONE FORMAT, AND THEY ARE NOT THE SAME FEATURE.** Section 2.2 is
   CLIENT AUTHENTICATION — `client_assertion`, the assertion says who is
   CALLING, `client_auth.js` has done it since 2026-08-26. Section 2.1 is an
   AUTHORIZATION GRANT — `assertion`, the assertion says who the token is FOR.
   They share a format, a claim set and — since 2026-09-13 — one
   used-assertion history, and nothing else: in the
   first the `sub` MUST be the client, and in the second the `sub` is a PERSON
   and being the client is the degenerate case. **Reading one file and
   concluding the other is covered is exactly the mistake this service had
   made**: the metadata named RFC 7523, section 2.2 was complete, and section
   2.1 did not exist.

   **`client_auth.js` REQUIRES THIS AND NEVER THE REVERSE.** Section 2.2 needs
   the assertion FORMAT and this file owns it — `keysFrom()`, `unwrapAssertion()`
   and `keyFromChain()` are all reached from there — and section 2.1 needs
   nothing at all from client authentication, because an assertion grant may
   arrive from a public client with no credential. A second copy of the JWKS
   reader would have been a second answer to *which of this party's keys may
   sign*, which is the shape of duplication `crypto.js` was written to end one
   layer down.

   ~~**A SECOND REPLAY CACHE BESIDE `client_auth.js`'s, DELIBERATELY.**~~ —
   **REVERSED 2026-09-13, AT THE OWNER'S ASK: ONE HISTORY, AND AN ASSERTION IS
   ACCEPTED ONCE EVER.** It read: *a document used to authenticate a client and
   a document used to authorize an issuance are two different credentials, they
   are keyed differently (by client, and by issuer), and sharing one cache would
   mean an assertion presented as a client credential silently spending the jti
   of an authorization grant from the same party.* The argument did not survive
   the rule it was for. A `jti` is the ISSUER's name for ONE document (RFC 7519
   section 4.1.7), and a client assertion's issuer IS the client — so keying
   both uses by issuer and `jti` spends exactly one document, and the case the
   old paragraph feared is one issuer reusing a `jti` across two documents,
   which is already a broken issuer. The case it PERMITTED was one JWT spent as
   a client credential and then again as a grant, which is a JWT used twice.

   `common/used_assertions.js` is the history, and three things came with it
   that each of the old caches lacked: it **persists in every store with one, in
   both modes** (the key that verifies an assertion is the client's and survives
   a restart, so forgetting at a restart was a replay), it is **claimed
   atomically on postgres** (a journalled cache converged, so a second worker
   accepted a replay for up to `persistence.pollInterval`), and an assertion is
   **spent only when tokens are issued** — reserved while its token request is
   answered, confirmed on a 2xx and released otherwise, through the response's
   own `finish`, which is why both grant branches in `oauth2.js` and
   `client_auth.verify()` pass the request down. The claim is the LAST check of
   the document in every verifier, so a refusal for any other reason is not
   also a use.

   **`jti` IS REQUIRED WHERE THE RFC SAYS OPTIONAL**, and that is §3's own last
   paragraph read literally: it says an authorization server MAY reject a reused
   JWT, and an assertion with no `jti` cannot be REMEMBERED — so accepting one
   means accepting a bearer credential this service has no way to spend. It is
   the same decision section 2.2 already made, stated at the refusal rather than
   left to be discovered.

   **THE ISSUER MUST BE DECLARED, AND THAT IS FEDERATION'S ARGUMENT WORD FOR
   WORD.** An assertion grant has no browser, no password and no consent step
   anywhere in it, so the signature is the entire security of the grant and
   there is **no permissive answer available**: "accept any signed assertion"
   means anybody who can reach this port getting an access token as anybody.
   `oauth2.jwtBearerRequireRegisteredIssuer` is therefore ON by default, and
   federation's refusal and this one are the only two here that are. **What is
   still permissive is everything around it** — the `sub` need not be anybody
   this service has heard of, and the scope is checked against nothing — which
   is the distinction `kerberos/CLAUDE.md` draws about SPNEGO.

   **THERE ARE TWO KINDS OF ISSUER SINCE 2026-09-11, AND THE SECOND HAS A RULE
   THE FIRST DOES NOT.** An APPLICATION that declares `oauthAssertionIssuer` is
   an operator saying *this party may speak about people*, so its assertion may
   name any `sub` and always could. A PERSON may hold a signing key pair now —
   `common/person_assertions.js` (rule 3ab) is the register, `stsAssertion*` on
   their own entry — and **a person may only assert about themselves**: `iss`
   and `sub` must name the same person, and one naming anybody else is refused
   by name. Without the rule, everybody ever issued a key on `/admin/pki` can
   obtain a token as anybody in the realm, with the signature verifying and the
   claims well formed while they do it. **The check is made TWICE**, for the key
   on the entry and for a certificate presented in an `x5c` that this service
   can see it issued to a person — that second path does not consult the
   registry at all, which is the point of it, so `common/pki.js` puts the answer
   in the certificate as a `urn:sts:person:<name>` subjectAltName. That
   file argues the whole thing; what belongs here is that `keysForParty()` is
   told which KIND of party it is reading rather than trying every attribute
   name it knows, because the store is schemaless and a function that read both
   lists off whatever it was handed would accept an `oauthAssertionJwks`
   somebody had put on a person.

   **THE SIGNATURE IS VERIFIED BEFORE ANY CLAIM IS BELIEVED**, which is not the
   order RFC 7521 section 5.2 lists its checks in and is the order they have to
   run in. The unverified `iss` is used ONLY to find candidate keys and decides
   nothing; every check below it runs on claims a signature has already vouched
   for. Do not read anything else out of an unverified assertion — the same rule
   `client_auth.js` states about the unverified `sub`.

   **A REGISTERED KEY'S CERTIFICATE IS CHECKED FOR REVOCATION ONCE IT HAS
   VERIFIED THE ASSERTION (2026-09-12)** — here, in `client_auth.js` and in 3z's
   file alike: the `x5c` of the JWK that verified (or the RFC 7522 certificate) goes
   to `common/revocation_status.js`'s `registeredVerdictFor()` before any claim is
   believed and before the jti is spent, and a revoked one is `STS-PKI-0129` with
   the protocol's own error. A JWK with no `x5c` is a bare key: nothing is looked
   up and `keyRevocation.bare` says so rather than calling it good.

   **AN `x5c` IS CHECKED RATHER THAN READ.** Taking a public key out of one and
   verifying with it would be verifying a signature against a key the signature
   came with, which proves nothing at all — so it is used only after
   `common/pki.js` has shown the chain reaches this realm's own Root. That is
   what makes the certificate authority worth having: a party issued a key pair
   can present its certificate instead of registering a JWKS.

   **AND EVERY SIGNER CERTIFICATE'S WHOLE CHAIN IS VALIDATED WHERE THE SIGNATURE
   IS (2026-09-13)**, in this file, in `client_auth.js` and in 3z's file, in
   both modes. Two holes closed together. The `x5c` header's path check
   (`pki.verifyLeaf()`) walked signatures and never asked who was ENTITLED to
   sign each link, so any issued leaf — a person's from `/portal/signing-key`
   included — could sign a certificate of its own, present it under itself, and
   assert about anybody; it now refuses a non-CA issuer (`STS-PKI-0158`) and a
   CA as the signer (`0159`), and `keyFromChain()` keeps those two codes rather
   than calling the path one that "does not chain here". And a REGISTERED key's
   certificate had its chain checked when it was registered and never again; now
   `pki.verifySignerChain()` runs after the signature verifies and BEFORE the
   revocation check, on the key that verified: the certificate must hold that
   key (RFC 7517 section 4.7, `0160`), and the path must be valid at that moment
   and end in this realm or at a self-signed root registered with it (`0156`,
   `0157`). `common/CLAUDE.md` 3w argues the three anchors. **A bare key is not
   asked** — there is no certificate — and the verdict's `keyChain` is null for
   it. The chain check passes `revocation: false` to `verifyLeaf()` so that a
   revoked registered certificate is still reported by the registered door as
   `STS-PKI-0129`.

   **THE SCOPE IS NARROWED AND NEVER WIDENED** (RFC 7521 section 4.1). An
   assertion naming a `scope` is the issuer saying what this grant is for; where
   it names none, the request decides. A `cnf` is CARRIED AND REPORTED and never
   enforced, which is the position this service already takes on OIDC Core
   5.5's `essential`: enforcing it means demanding a proof this grant has no
   parameter to carry.

   **`PROTOCOL_CLAIMS` IS TWELVE NAMES AND IT IS A LIST RATHER THAN A
   BEHAVIOUR.** What an assertion carries beyond the profile's own claims is
   copied onto the issued token (§3 claim 8) and the twelve are stripped first —
   an `exp` copied off an assertion would be a token lifetime chosen by whoever
   signed it. `accessToken()` puts them UNDER the protocol's own claims and OVER
   the console's configured ones: the protocol always wins, and an assertion is
   a statement about THIS issuance where the console's is a service-wide
   default.

3z. **`saml_assertion_grant.js` IS RFC 7522, AND IT IS A SECOND IMPLEMENTATION
   RATHER THAN A FORMAT FLAG ON 3x.** A library like that one: it registers no
   route, requires `helpers.js`, `config.js`, `applications.js`,
   `common/crypto.js` and `common/realms.js`, and none of them requires it back.
   **It does NOT require `assertion_grant.js` and must not** — a require between
   the two would be the first step towards the flag this rule refuses, and
   `tests/saml_assertion_grant.js` asserts its absence out of the source.

   **THE ARGUMENT IS `saml/CLAUDE.md`'s ABOUT SAML 2.0 AND SAML 1.1, MADE AGAIN
   FOR A DIFFERENT PAIR.** RFC 7521 is a framework and RFC 7522 and RFC 7523 are
   two profiles of it: the framework is shared and nothing else is. RFC 7523's
   assertion is three base64url parts and a claim set; RFC 7522's is an XML
   document with an enveloped XML Signature, a `<Conditions>` element, a
   `<SubjectConfirmation>` and a `Recipient` attribute that has **no JWT
   equivalent at all** — and there is no element in RFC 7522 corresponding to
   `jti`. A shared implementation would be a `switch` in every check.

   **WHAT IS CITED RATHER THAN REPEATED.** The replay rule, the scope
   narrowing, the signature-before-any-element ordering and the claim-8
   treatment of extra statements are 3x's arguments and that file cites them.
   **One thing is repeated in full and deliberately**: the registered-issuer
   refusal, because it is the one thing there that refuses by default and a
   reader arriving at that file first must not have to go and find it.

   **ACCEPTING AN RFC 7522 ASSERTION FROM AN `<Issuer>` NOBODY DECLARED IS
   REFUSED — the THIRD refusal that defaults to ON, and it is a SEPARATE
   declaration from 3x's**: `oauthSamlAssertionIssuer` rather than
   `oauthAssertionIssuer`, because being trusted to assert in one document
   format is not being trusted to assert in the other, and an operator who
   wrote one attribute must not accidentally have written two.

   **ITS TWO SECTIONS ARE ONE `verify()` WHERE 3x's ARE TWO FILES**, which is
   the opposite arrangement and is not an inconsistency. In RFC 7523 the halves
   diverge at the KEY — a client secret may verify a client assertion and
   nothing may verify a grant that way — and in RFC 7522 there is no symmetric
   option at all, because XML Signature over a shared secret is not something
   any SAML implementation emits. So the only difference between the two
   sections here is what the `<Subject>` has to be (item 3B), and that is one
   `if`.

   **THE KEY PAIRS ARE SEPARATE FROM RFC 7523's, PER APPLICATION, AND THAT IS
   THE DESIGN THIS FILE EXISTS TO ENFORCE.** `common/applications.js` declares
   two attribute sets that SHARE NO NAME — `oauthAssertion*` and
   `oauthSamlAssertion*` — and no code path crosses them. `common/pki.js`
   issues into one or the other by `purpose`, and `/admin/pki` writes seven
   attributes for the JWT profile and six for the SAML one (no JWKS: SAML has
   none, and what a party registers for that profile IS a certificate).

   **SO A BARE CERTIFICATE PATH IS NOT ENOUGH HERE, AND THIS IS THE ONE PLACE
   THIS SERVICE IS STRICTER FOR RFC 7522 THAN FOR RFC 7523.** 3x accepts a key
   out of an `x5c` once the chain reaches this realm's Root, and that is sound
   for a JWT: the chain is evidence this service issued the key. It would not be
   sound here, because it is evidence about the REALM and not about the
   APPLICATION — an application's RFC 7523 leaf, pasted into a SAML assertion's
   `<ds:KeyInfo>`, would chain perfectly and sign. That is exactly the crossing
   the two attribute sets exist to prevent. So **a SAML assertion is verified
   ONLY against a certificate registered against the asserting party under the
   RFC 7522 attributes**; a `<ds:KeyInfo>` certificate narrows that set and is
   never a key in its own right, and one matching none of it is refused by name.
   Nothing is lost: 3x's chain path exists because a JWKS is the thing a client
   registers and a certificate is the awkward case, and here the thing
   registered IS a certificate.

   **THE REGISTERED CERTIFICATE'S OWN CHAIN IS VALIDATED AT EVERY USE
   (2026-09-13)** — `pki.verifySignerChain()`, after the XML Signature verifies
   and before revocation, which is 3x's paragraph for this profile. Being
   registered is what makes a certificate a CANDIDATE; its chain holding is what
   makes the signature count. An issued or uploaded certificate brings its
   stored chain; one registered BY VALUE on
   `oauthSamlAssertionSigningCertificate` offers the other PEM blocks in the
   same value as candidate issuers (`siblings` on the candidate), because that
   one attribute is the only place its issuers can be registered — a
   CA-issued certificate there with nothing beside it is refused as incomplete,
   and a self-signed one is pinned. The verdict carries `certificateChain`.

   **THE THREE ITEMS OF SECTION 3 WHOSE LENIENT READING IS THE USUAL BUG**, all
   three asserted in `tests/saml_assertion_grant.js` because each of them looks
   like a refusal that is simply missing:

   * **item 4** — the expiry may be on the `<Conditions>` OR on a
     `<SubjectConfirmationData>`, and EITHER satisfies it. Half the
     implementations in the world require the first.
   * **item 6** — an expired `<SubjectConfirmation>` is DISCARDED and the others
     still considered ("MUST reject the `<SubjectConfirmation>` (but MAY still
     use the rest of the Assertion)"), where an expired `<Conditions>` makes the
     whole assertion invalid. Nearly every implementation collapses the two.
   * **item 11** — an unrecognised `<Condition>` makes the assertion **Invalid**
     per SAML core section 2.5.1 rather than being ignored, which is the
     opposite of what every other XML reader does with an element it does not
     know.

   **`saml2_bearer` IS THIS SERVICE'S OWN NAME AND NOT A REGISTERED ONE.** The
   IANA "OAuth Token Endpoint Authentication Methods" registry holds seven
   values and RFC 7522 registers none: it defines a `client_assertion_type` and
   stops. So a deployment offering the feature has no registered word for it.
   The invention is PUBLISHED rather than documented — it is in
   `token_endpoint_auth_methods_supported` like every other method — and
   nothing on the wire is invented: the `client_assertion_type` is RFC 7522's
   URN exactly.

   **`PROTOCOL_ATTRIBUTES` IS ONE NAME WHERE 3x's LIST IS TWELVE**, and the
   difference is a fact about the two formats rather than an omission: a SAML
   assertion keeps its protocol furniture in ELEMENTS, so there is nothing in
   the `<AttributeStatement>` to strip but the `scope` this service reads as a
   constraint. A single-valued SAML attribute becomes a string on the token and
   a multi-valued one stays a list — `"department": ["engineering"]` in a token
   reads as a bug to every relying party that meets it.

3ah. **`jwt_access_token.js` IS RFC 9068, AND EVERY ACCESS TOKEN HERE IS A JWT
   ACCESS TOKEN BY THAT PROFILE (2026-09-13).** Every access token was a JWT
   from the first day, and none was one RFC 9068 recognised: its header said
   `typ: "JWT"` exactly as the ID Token's did, so a resource server following
   section 4 refused every one at step one, and one that did not could be handed
   an ID Token signed by the same key and take it for an access token. A library
   (rule 3): it registers nothing and requires `common/` modules and
   `authorization_servers.js` (for `ID_SHAPE`), none of which requires it back.

   **IN EVERY MODE, AND THAT WAS ASKED.** rcbj chose *"RFC 9068 checks in every
   mode"* over gating the refusals on `oauth2.rfc9700`, which is the opposite of
   this repository's standing rule for refusals and is a decision rather than an
   oversight: the profile is what the token IS, and a token some resource
   servers could validate depending on a restart-only flag would be two formats
   under one name.

   **ONE LIBRARY FOR BOTH HALVES, BECAUSE EACH FACT HAS TWO READERS.** The
   minter (`oauth2.js`) and the resource servers (`dpop.js`'s
   `presentedAccessToken()` — UserInfo, the three credential endpoints, SCIM
   and SSF through it — `mgmt-api/admin_api.js`'s gate, and the embedded
   debugger's) must agree on the header, the issuer and the default audience.
   **`issuerOf()` MOVED HERE as `issuerFor()`** for that reason: `dpop.js`
   cannot require `oauth2.js`, and a second copy of "what is this service's
   issuer" is the fact a check like this must not have two of. `oauth2.js`'s
   `issuerOf()` is kept, by name, as a one-line call.

   **WHAT IS ISSUED.** `accessToken()` signs with `header()` — `signJwt()`
   forwards `opts.header` since this change, and still signs the refresh token
   with `typ: "JWT"`. The seven REQUIRED claims were always present; `scope` is
   OMITTED when nothing was granted rather than `""`; `preferred_username`
   carries the person's name beside `username` (section 2.2.2's registered
   name; `username` stays because the token registry, SCIM and the audit log
   read it), and not on a client_credentials token; `auth_time`, `amr` and `acr`
   ride where an authentication event is behind the grant (section 2.2.1). The
   `typ: 'Bearer'` CLAIM is kept: it is this service's own, older than the
   header, and four readers still use it.

   **WHAT A RESOURCE SERVER CHECKS** — `resourceServerRefusal()`, in section
   4's order, for a token this service VERIFIED:

   | Step | Refusal |
   |---|---|
   | 1, the header `typ` is `at+jwt` (RFC 7515's case and `application/` rules) | `STS-OAUTH-0247` |
   | 3, `iss` is an issuer this service publishes AT THE REQUEST'S ADDRESS — the default authorization server or a named one under it | `STS-OAUTH-0248` |
   | 4, `aud` contains `<base>/resource` or `<base>/<id>/resource`, compared WHOLE | `STS-OAUTH-0114` |

   `/admin-api` asks the first two itself (`STS-API-0082`, `STS-API-0083`)
   against the addresses its audiences name, because its audience is its own.
   **THE RESOURCE SERVERS HERE TRUST SEVERAL ISSUERS** — every authorization
   server this process publishes at that address — which RFC 9068 permits and
   which the named authorization servers need. **AND AN ADDRESS IS PART OF AN
   ISSUER**: a token minted at `localhost` is refused at `127.0.0.1`. That
   reversed the path-only audience match (see 3f), and `global.publicBaseUrl`
   is the answer for a service reached under several names. A token minted
   before `at+jwt` is refused once presented; access tokens live an hour.

   **WHAT A TOKEN MAY BE ADDRESSED TO — `audiencePlan()`, one decision behind
   `accessTokenPlan()` in `oauth2.js`**, which classifies each scope value
   (an application's client_id, a delegated permission, an OIDC scope, or
   anything else) because only that module knows the registry:

   * **scopes naming two APIs** — section 3's "SHOULD reject with
     invalid_scope": `STS-OAUTH-0244`;
   * **a scope naming an API the request did not address** (`resource=A` and a
     scope naming B) — section 2.2.3's MUST, as a refusal: `invalid_scope`,
     `STS-OAUTH-0245`;
   * **several resources and a scope tied to none of them** — section 3's
     "MUST NOT issue ... ambiguous": `invalid_target`, `STS-OAUTH-0246`. A
     delegated permission is tied to its API (and keeps its WHOLE identifier on
     a multi-audience token, the one spelling that names its API), an OIDC
     scope to this service's own resource server, and an ordinary scope to
     nothing in particular;
   * **and the rewrite, rcbj's choice over refusing**: a token for an API is for
     the API alone and carries no OIDC scope — see 3f's reversed paragraph.

   **FOUR PLACES ASK THE PLAN, and two are where a client can still be told**:
   the authorization endpoint before a code is minted (a redirected error) and
   the token endpoint above the grant switch, before a code is redeemed or a
   refresh token rotated. `tokenSet()` asks again as the BACKSTOP — a refresh
   token minted before the rule, which would otherwise issue an ambiguous token
   because its grant is old — and throws `AccessTokenRefused`, answered by
   `tokenEndpoint()` beside `IssuanceRefused`. The implicit and hybrid token is
   minted from the authorization endpoint's plan. The token exchange is left
   to the backstop: its audience is assembled inside its branch and nothing it
   does before issuing can be spent.

   **WHAT IS NOT DONE, SAID RATHER THAN LEFT:** access tokens are not
   ENCRYPTED (section 6 names it as one privacy measure; optional); `roles` and
   `entitlements` (section 2.2.3.1) are not emitted, and the groups claim takes
   its name from `groups.claimName`, `groups` by default; a foreign token at the
   OID4VCI credential endpoints is still accepted unverified, by design; and the
   introspection and token-exchange readers of a token this service issued do
   not ask section 4, which is a resource server's list.
   `tests/rfc9068_access_tokens.js` holds the library, the plan and the
   endpoints in a child process.

3ai. **`introspection_jwt.js` IS RFC 9701, AND IT CHANGED WHO MAY CALL
   `/oauth2/introspect` (2026-09-13).** A library (rule 3): it registers
   nothing and requires `helpers.js`, `common/crypto.js`,
   `common/applications.js` and `error_codes.js`, none of which requires it
   back. `introspectEndpoint()` in `oauth2.js` answers; this decides. Three
   decisions were asked of rcbj before it was built and each took the
   recommended answer, and they are the design:

   | Asked | Chosen |
   |---|---|
   | Who must authenticate | A JWT request in EVERY mode; a JSON request in PRODUCT mode only (`mode.opensIntrospection()`) |
   | Where the three client metadata members live | Application attributes (`oauthIntrospection*`), written by RFC 7591 registration and editable on the console and `/admin-api` |
   | Tests | In process, `tests/rfc9701_introspection.js` |

   **THE JWT REQUEST AUTHENTICATES IN EVERY MODE, AGAINST THIS REPOSITORY'S
   STANDING RULE, AND THE REASON IS THE `aud`.** Section 5 says the response's
   `aud` identifies the resource server receiving it, and an unauthenticated
   caller has no identity to put there — so a JWT to an anonymous caller would
   be a signed statement addressed to nobody, which is not a permissive version
   of the feature but the absence of it. It is refused **400 `invalid_client`**,
   section 5's own status, not RFC 6749's 401. The JSON path is the mode-gated
   one and answers RFC 7662 section 2.3's 401 in product, with the Basic
   challenge. `respond()` takes the `aud` from the authenticated client and has
   nowhere else to get one, so the ordering is structural.

   **ONE AUTHENTICATION, THE TOKEN ENDPOINT'S.** `bcp.observeClientAuthentication()`
   — all six methods, the used-assertion history, certificate revocation — with
   assertion audiences of this endpoint, the token endpoint, the issuer and the
   base, and the same secret rate-limit bucket (`STS-OAUTH-0284`), so a secret
   throttled at one endpoint cannot be guessed at the other. A credential sent
   where none is required is NOT checked, which is what development did before.
   `introspection_endpoint_auth_methods_supported` is `clientAuth.METHODS` now,
   filtered as the token endpoint's is; it named three while nothing
   authenticated a caller there at all.

   **WHAT MAKES IT NOT A TOKEN** (section 8.1): `typ: token-introspection+jwt`,
   which no resource server here accepts; no top-level `sub` or `exp`; the
   RFC 7662 members nested under `token_introspection`; and it is signed
   through `helpers.signJwtAsAsync()` rather than `signJwt()`, so it never
   enters the token registry — `/admin/tokens` lists credentials. An inactive
   token's claim is `{ "active": false }` REBUILT by `claimsFor()`, so a member
   that leaked into the caller's object cannot become a signed statement.

   **A JWT ONLY WHERE THE MEDIA TYPE IS NAMED.** `wantsJwt()` parses the Accept
   header with q-values rather than using `req.accepts()`, which answers "which
   would you send" — the wrong question once a wildcard is involved. No
   header, `*/*`, `application/*` and `application/json` all get the JSON every
   pre-RFC 9701 client got; a tie between the named JWT and JSON goes to the
   JWT. `Vary: Accept` is set on every answer.

   **REFUSED, NEVER DOWNGRADED.** `applications.introspectionResponseProblem()`
   is the one check — at registration and RFC 7592 update (`STS-REG-0072`,
   `invalid_client_metadata`), on the console and `/admin-api`
   (`STS-REG-0073`), and again by `protectionFor()` when answering, for a value
   an `ldapmodify` wrote (`STS-OAUTH-0293`, 500 with the reason). The lists are
   `common/crypto.js`'s: every JWS algorithm, HMAC keyed by the client secret,
   never `none` (section 5's "MUST be cryptographically secured"); the
   ASYMMETRIC JWE list only, to the client's inline `jwks`, never a `jwks_uri`.
   An `enc` with no `alg` is refused at every write and, left behind by a clear,
   fails the response rather than sending it unencrypted. **An RFC 7592 update
   that omits a member CLEARS it** — unlike the older members — because the
   update replaces the registration and a stale encryption key is a response
   the client can no longer read.

   **`recipientEncryptionKey()` MOVED HERE** as `recipientKey(registered, alg,
   member)`: the UserInfo response calls it with its own member name, so its
   refusal sentences are unchanged, and the one reading of "which of this
   client's keys may be encrypted to" now reads a JWKS held as text (the
   attribute) as well as an object (a registration document).

   **THREE MORE THINGS LANDED THE SAME DAY, EACH A GAP THE FIRST PASS HAD
   STATED.** Two decisions were asked of rcbj for the first and both took the
   recommended answer:

   * **SECTION 5's "NOT INTENDED FOR THE RESOURCE SERVER" IS ENFORCED** —
     `intendedFor()` — for EVERY caller that authenticated: a JWT request in
     every mode and a JSON request in product mode, because one caller getting
     two different answers about one token by changing its Accept header would
     be two endpoints under one path. A token is intended for the caller when
     it is the caller's OWN (its `client_id` claim), when an `aud` value is this
     service's default resource indicator (any caller may ask about a token
     that named no resource server — which keeps every existing deployment
     working), or when an `aud` value names the caller's entry by
     `oauthClientId`, `oauthAudience` or `oauthPermissionBaseUri` (normalised
     both sides; a resource written without its trailing slash is the same
     base). **A refresh token is its client's alone**, whatever its `aud`.
     Anything else is answered `{active:false}` — the invalid token's answer,
     so "not yours" and "not a token" cannot be told apart. An anonymous
     development JSON caller is not restricted: there is nobody to compare the
     token with.
   * **A NAMED AUTHORIZATION SERVER'S PROFILE NARROWS INTROSPECTION** — four
     catalogue rows in `authorization_servers.js` marked `enforces`:
     `introspection_endpoint_auth_methods_supported` refuses a client whose
     declared method is not listed before its credential is read
     (`STS-OAUTH-0295`, 400 for a JWT request and 401 for JSON), and the three
     RFC 9701 lists refuse a registration — or section 6's RS256 default,
     named as the default — that the server does not publish
     (`protectionFor(client, advertised)`, `notAdvertised`, `STS-OAUTH-0296`,
     400 `invalid_client`). That is the client's refusal and not the 500 an
     unhonourable registration gets: the registration is fine and this server
     does not offer it. A removed member means the check does not run.
   * **OAUTH 2.1 SECTION 2.4 IS ASKED AT INTROSPECTION** —
     `oauth21.multipleMethodsRefusal()` before anything is verified, for JSON
     and JWT requests alike, because two credentials on one request is
     malformed whichever would have been read (`STS-OAUTH-0281`).

   `/admin/crypto-metadata` lists the JWT introspection response's signing and
   encryption algorithms, read off this library, and
   `tests/vendored/admin_api.js` holds both against the RFC 8414 document.

   **WHAT IS STILL NOT DONE:** section 9's legal basis for releasing token data
   is the deployment's to establish and nothing here can decide it.
   `oauth2.introspectionCertificateHeader` is the twelfth `x5c`/`x5u` use case.

3aj. **`software_statement.js` IS RFC 7591 SECTION 2.3, AND A TRUSTED STATEMENT
   IS THE SECOND DOOR THROUGH A CLOSED REGISTRATION ENDPOINT (2026-09-13).** A
   library (rule 3): it requires `assertion_grant.js` (for `keysForParty()` and
   `keyFromChain()`, exported for it), `jwt_access_token.js` (the issuer) and
   `common/` modules, none of which requires it back; `oauth2.js`,
   `admin-core/admin_actions.js` and `admin-core/admin_views.js` require it. Four
   decisions were asked of rcbj and each took the recommended answer:

   | Asked | Chosen |
   |---|---|
   | Who may sign a statement | An application declaring the `iss` in `oauthSoftwareStatementIssuer` (a SEPARATE declaration from `oauthAssertionIssuer`, for 3z's reason), with its keys — plus this realm itself |
   | An untrusted or invalid statement | Refused in EVERY mode; `oauth2.softwareStatementRequireTrustedIssuer` turns off the issuer refusal only |
   | Product mode, registration closed | A trusted statement opens it, behind `oauth2.softwareStatementOpensRegistration` (on) |
   | Issuing | From the application's page and `POST /admin-api/applications/issue-software-statement`, signed by the realm |

   **THE STATEMENT IS RESOLVED BEFORE ANY OTHER CHECK OF THE METADATA**, in the
   POST and in RFC 7592's PUT, because a trusted one decides what the metadata IS
   (section 3.1.1's precedence) — so the address check, RFC 9701's algorithm
   check and 3f's registration mirror all run on the MERGED document, and a
   statement cannot fix what the JSON could not. An untrusted statement accepted
   with the refusal off merges the other way round and never opens a closed
   endpoint. The statement string is kept in the registration verbatim, which is
   what section 3.2.1's echo and RFC 7592's read hand back.

   **THIS REALM'S OWN STATEMENTS ARE RECOGNISED BY THREE THINGS TOGETHER**: an
   `iss` this process publishes at the request's address
   (`isHostedIssuer()`), `typ: software-statement+jwt`, and this realm's key.
   **The type is the one that matters**: every other JWT this realm signs —
   an ID Token, an access token — verifies under the same key and names the same
   issuer, and without it its `sub`, `aud` and `name` would register as client
   metadata. A hosted `iss` without the type is refused `STS-OAUTH-0305` and is
   never looked up as a declared issuer. **An address is part of that issuer**
   (3ah): a statement issued at one host name is refused at another, and
   `global.publicBaseUrl` is the answer.

   **A DECLARED PUBLISHER'S `x5c` MUST HAVE BEEN ISSUED TO THAT PUBLISHER.**
   `keyFromChain()` reads `urn:sts:application:` off the leaf; a chain to this
   realm issued to anybody else is `STS-OAUTH-0306`, because a realm certificate
   proves who it was issued to and a person's leaf is not a publisher. The
   registered key's chain and revocation are checked after it verifies, 3x's
   order.

   **THE UPDATE BINDING (`updateProblem()`) IS THE ONE RULE THE POST DOES NOT
   HAVE.** A client admitted ONLY because a trusted statement fixed its
   metadata — `registrationOpen()` false — must present a trusted statement from
   the SAME issuer with every PUT, or it could replace the `redirect_uris` the
   publisher fixed with whatever a registration access token holder likes. The
   facts it reads are three `appSoftwareStatement*` attributes
   `applications.applyRegistrationFields()` writes from what `resolve()` VERIFIED —
   never from the document — and clears on an update without a statement and on
   delete.

   **WHAT IS NOT CHECKED, AND SAYS SO** in the module header: `jti` is not spent
   (section 2.3 expects every copy of the software to present one statement),
   `exp` is not required (only `iss` is), HMAC is refused rather than supported
   (no key is shared with a publisher, and the registering client has no secret
   yet), a JWE is refused, and a publisher's `jwks_uri` is not fetched. **An
   initial access token (section 3) is still not issued** — a trusted statement
   is this service's answer to a closed endpoint instead.

   **`issue()` WRITES `oauthIssuedSoftwareStatement`** — not sensitive, because a
   statement ships with the software — and takes the base URL from the ACTION's
   context, never the body, since the `iss` it signs is the one a registration
   must match. With no base and no `oauth2.issuer` pin it refuses
   (`STS-ADMIN-0650`) rather than signing an empty `iss`. It is signed through
   `signJwtAs()` rather than `signJwt()`, so it never enters the token registry,
   and names no certificate header (a statement is verified only here).

   `tests/software_statement.js` holds it end to end in a child process, and was
   mutation-tested against the precedence, the type check and the update binding
   — the type mutant SURVIVED the first version, because the token-shaped
   fixture carried an `aud` and the audience check refused it first.
   **Not driven by any over-HTTP job yet**: the console section and the API
   operation are reached by the owned jobs' generic walks, not by a job about
   statements.

3ak. **`request_object.js` IS RFC 9101, AND A JWT-SECURED REQUEST IS RESOLVED
   BEFORE THE AUTHORIZATION ENDPOINT READS ANYTHING (2026-09-13).** A library
   (rule 3): it requires `common/` modules and `assertion_grant.js` (for
   `keysForParty()`), none of which requires it back; `par.js` is required
   LAZILY, because it requires this file for `verifyObject()`. Four decisions
   were asked of rcbj, each taking the recommended answer, and then *"all
   optional spec features should be implemented"*:

   | Asked | Chosen |
   |---|---|
   | Which `request_uri` may be fetched | Only one the client registered in `request_uris` (`require_request_uri_registration: true`); https only in product; no redirects, a timeout, a size cap, the media type checked in product |
   | `alg: none` | Accepted in development unless a signed object is required; refused in product (`mode.acceptsUnsignedRequestObjects()`) |
   | `typ` | Only a JWT typed as something ELSE is refused (section 10.8); `oauth2.requireRequestObjectType` requires `oauth-authz-req+jwt` |
   | Encryption | A per-realm RSA and EC key published with `use: "enc"` (`common/CLAUDE.md`), plus the symmetric algorithms keyed by the client secret |

   **THE OBJECT REPLACES `req.query`, SO EVERY CHECK RUNS ON WHAT WAS SIGNED.**
   `oauth2.js`'s `authorizeEndpoint()` is now the route handler: a request with
   no `request`/`request_uri` and no signing requirement takes the synchronous
   path to `authorizeRequest()` unchanged; anything else is resolved first, a
   refusal answered 400 on this server (never redirected — the redirect URI is
   inside the object not yet believed), and on success `req.query` is REDEFINED
   as the object's parameters and `req.stsJar` records `{outer, source, alg,
   encrypted, pushed}`. Section 6.3's assembly is `parametersFrom()`: the
   object's members only, JWT claims and nested `request`/`request_uri`
   dropped, the query's `client_id` required and identical to any in the object.

   **THE ROUND TRIP CARRIES THE OBJECT, NOT ITS PARAMETERS.** The sign-in and
   consent hops return through `authorizationReturnQuery()`: for a JAR request
   that is `client_id` plus `request` or `request_uri` as they arrived, so the
   second pass verifies the object again rather than trusting resolved
   parameters put back in a URL. `prompt` cannot be dropped from a signed
   object, so `jar_prompt_honoured=1` tells the second pass the first honoured
   it — without it `prompt=login` asks for ever. The consequence is that a
   `request_uri` is fetched twice per flow unless `oauth2.requestUriCacheS` is
   set, and a PAR URN resolves twice (`par.js` spends it at issuance).

   **THE ORDER OF REFUSALS, EACH WITH ITS CODE (`STS-OAUTH-0340..0373`)**: the
   shape (none required 0340, both or repeated 0341, a profile's
   `request_parameter_supported`/`request_uri_parameter_supported` false 0342 /
   0343 — a PAR URN is exempt from 0343, RFC 9126 section 5 — no `client_id`
   0344); for a reference, registered 0345, still a usable address 0346, the
   fetch 0347 and media type 0348, the fragment digest 0349; decryption (plain
   where encryption is registered and the registered pair 0350, the profile's
   lists 0351, the key or secret 0352, the unwrap 0353, not a nested JWS 0354);
   the JWS (header 0355, `typ` 0356/0368, unsigned refused 0357 — BEFORE the
   algorithm lists, so a required signature is named as the reason — the
   registered algorithm 0358, the profile's list 0359, an unknown algorithm
   0360, no key 0361, a `kid` naming no key 0370, the signature 0362, the
   certificate chain 0363 and revocation `STS-PKI-0129`, unsigned claims 0364);
   then the claims (`iss`/`aud` required 0369, `iss` 0365, `aud` 0366,
   `client_id` 0367, a duplicated `response_type` 0371). A PAR URN with no
   `par.js` is 0372; a throw is 0373.

   **THE SYMMETRIC KEY IS OPENID CONNECT CORE 10.2's**: the leftmost octets of
   SHA-256/384/512 of the client secret, as many as the algorithm (or, for
   `dir`, the content encryption) needs; PBES2 is handed the secret itself.
   `common/crypto.js` takes a key of exactly the right size and derives
   nothing, so `symmetricKeyFor()` is where it happens.

   **WHAT A PROFILE NARROWS**: the six catalogue rows in
   `authorization_servers.js` marked `enforces` — the two booleans, the
   requirement, and the three algorithm lists — through
   `authorizationProfileOf(req)`. **THE REGISTRY**: five attributes
   (`oauthRequestUri`, `oauthRequestObjectSigningAlg`,
   `oauthRequestObjectEncryptionAlg`, `oauthRequestObjectEncryptionEnc`,
   `oauthRequireSignedRequestObject`) written by RFC 7591 and editable on the
   console and `/admin-api`, all checked by `applications.requestObjectMetadataProblem()`
   (`STS-REG-0100`) and `requestObjectAttributeProblem()` (`STS-REG-0101`).

   **NOT DONE**: a request object's `jti` is not remembered (RFC 9101 does not
   ask, and the endpoint's two passes would meet their own replay); the product
   media-type refusal (0348) is not reached by any test, because product also
   refuses the plain-http `request_uri` a loopback test server can offer.
   `tests/rfc9101_request_objects.js` holds the rest.

3al. **`par.js` IS RFC 9126, AND A PUSHED REQUEST IS VALIDATED BY THE
   AUTHORIZATION ENDPOINT'S OWN CHECKS (2026-09-13).** Two libraries (rule 3):
   `par.js` holds a pushed request behind its `request_uri` and
   `oauth2_monitor.js` counts what happens to it; both require only `common/`
   modules and each other, and nothing requires them back. The endpoint,
   `parEndpoint()`, is `oauth2.js`'s, for 3f's split. Four decisions were asked
   of rcbj and each took the recommended answer (the third with a change of
   shape):

   | Asked | Chosen |
   |---|---|
   | When a client must authenticate at `/oauth2/par` | Exactly as at the token endpoint — enforced in RFC 9700, OAuth 2.1 and product mode, observed in development. Section 2.4's relaxation counts only a VERIFIED credential, in every mode |
   | When a `request_uri` is spent | When an authorization response is issued on it — it is read before the sign-in screen and again after, which section 4's "MAY allow for duplicate requests" covers |
   | A console page and an API | An OAuth monitoring page, `/admin/oauth2/monitor`, with PAR as its first SECTION, and `/admin-api/oauth2/monitor` |
   | Tests | In process (`tests/par.js`) plus an owned over-HTTP job for the page and the API |

   **THE VALIDATION IS NOT WRITTEN TWICE.** Section 2.1 says a push is validated
   "as it would an authorization request sent to the authorization endpoint", so
   the request-level half of `authorizeRequest()` — the shape, OAuth 2.1's client
   and default `redirect_uri`, the redirect URI, the response type, mode and PKCE
   method this authorization server advertises, and RFC 9700 mode's list — moved,
   unchanged and in its order, into `vetAuthorizationRequest(req, options)`. It
   DECIDES and answers whether a refusal may be redirected; `authorizeRequest()`
   answers as it did (a 400 or `fail()`), and `parRequest()` answers every refusal
   as section 2.3's JSON. The five parsers `issueAuthorizationResponse()` asks
   before minting (`authorization_details`, `resource`, the delegated permission,
   RFC 9068's audience plan, `claims`) are asked at the push too, so a request
   that could never be answered is refused while the client can still be told.
   **The authorization endpoint validates the pushed parameters AGAIN** when the
   `request_uri` is used — section 4 permits omitting that and section 7.4 argues
   against it, and here it is free, because the resolved parameters replace the
   query and run through the same function.

   **JAR RESOLVES THE URN; PAR NEVER SEES THE AUTHORIZATION ENDPOINT'S QUERY.**
   `request_object.js`'s `resolve()` hands a `request_uri` in the
   `urn:ietf:params:oauth:request_uri:` namespace to `par.resolve()` (lazily
   required, so there is no cycle) and never fetches one; the parameters it
   answers REPLACE the query, and `req.stsJar` carries `source: 'par'` and
   `pushed` — the facts of the back-channel request the authorization endpoint
   cannot recompute. The round trip through sign-in and consent carries the
   `request_uri`, never the pushed parameters, so they do not cross the browser
   on the second pass either. **A pushed `request` object is verified at push time
   by `request_object.verifyObject()`** and kept as the parameters it verified to;
   `par.resolve()` never hands back a JWT. Section 5's "usable ... regardless of
   other authorization server metadata" is why a URN skips a profile's
   `request_uri_parameter_supported: false`.

   **CLIENT AUTHENTICATION IS THE TOKEN ENDPOINT'S SEQUENCE, CALLED IN THE SAME
   ORDER** — the advertised methods, `bcp.checkClientAuthentication()`, OAuth 2.1's
   declaration refusal (as for `authorization_code`), the observation, OAuth 2.1's
   presented-credential refusal, product mode's public client, and the secret
   rate-limit bucket — with section 2's audiences: the issuer, the token endpoint
   and the PAR endpoint. The decisions are the libraries'; what `parRequest()`
   repeats is the call order, which is stated rather than hidden.

   **WHAT A PUSHED REQUEST CARRIES**: the validated parameters with the client's
   credential and this service's own round-trip markers (`authn_error`,
   `consent_error`, `jar_prompt_honoured`) STRIPPED — a push must not be able to
   pre-load an answer only the sign-in or consent screen may give — plus
   `clientAuthenticated`, `method`, `source`, the object's `alg`, the DPoP key a
   proof at the push bound the code to (RFC 9449 section 10.1, written into the
   parameters as `dpop_jkt` so the code record needs nothing new), and whether
   section 2.4 let its redirect URI through.

   **THE REQUEST_URI**: 256 bits of CSPRNG output (section 7.1), bound to the
   client (`STS-OAUTH-0413`) and to the authorization server it was pushed at
   (`0414`, 3j's "a credential does not cross between them"), per realm and
   persisted like `authzCodes` so a push answered by one process and a browser
   arriving at another is the ordinary case in dispatch mode. **Spent** in
   `issueAuthorizationResponse()` below every refusal and above the minting, so a
   request refused for its audience or role has not thrown its `request_uri` away,
   and kept marked until it would have expired so a replay is told "already used"
   (`0412`) rather than "unknown" (`0410`). **A full store refuses (503) rather
   than forgetting a live one**, the used-assertion history's rule.

   **TWO POLICIES ARE ASKED BEFORE A REQUEST IS VETTED** —
   `pushedRequestPolicyRefusal()`: PAR required by the setting, the client's
   `require_pushed_authorization_requests` or the selected authorization server's
   profile (`0419`, a 400 on this server — the redirect URI of a request that
   should never have been sent this way is not trusted with an error), and a
   `request_uri` pushed as plain parameters while a signed request object is now
   required (`0426`, section 7.4). **Section 2.4's relaxation is asked again**
   (`pushedRedirectRelaxed()`): it holds only if the push used it on a verified
   credential AND the setting still says so.

   **WHAT IS NOT DONE, SAID**: the debugger's client side; RFC 8705's
   `mtls_endpoint_aliases` (this service publishes none for any endpoint); and
   the section 2.4 relaxation has no prefix or query-only restriction beyond the
   URI's shape. `tests/par.js` holds the library, the registry check and the
   endpoints in a child process; its mutation record is in its header.

3am. **`authorization_details.js` IS RFC 9396, AND A TYPE BELONGS TO THE
   RESOURCE THAT DECLARES IT (2026-09-13).** A library (rule 3): it requires
   `common/` modules only; `oauth2.js` and `consent_screen.js` require it.
   OpenID4VCI's `openid_credential` was the only type before, hard-coded in
   `parseAuthorizationDetails()`; it is now the BUILT-IN type, its checks
   handed to `parse()` as `builtIn` (`vciAuthorizationDetail()`). Four
   decisions were asked of rcbj, each taking the recommended answer:

   | Asked | Chosen |
   |---|---|
   | Where a type is defined | On the resource application: `oauthAuthorizationDetailsType`, a name or a JSON definition with `description`, `locations` and a JSON `schema`; the realm's list is the union plus `openid_credential` |
   | An unknown or non-conforming detail | Refused `invalid_authorization_details` in every mode (section 5) |
   | The audience | The type's resource — the detail's `locations` (which that resource must declare), else its primary identifier; one resource per token |
   | Consent | Every detail drawn, asked EVERY time, Allow spent once |

   **THE DEFINITION'S GRAMMAR IS `common/applications.js`'s**
   (`authorizationDetailsTypeOf()`), for the introspection check's reason: the
   module that owns an attribute owns what a value may be, and every write door
   (`STS-REG-0112`) and this library read the same parse. Schemas compile with
   Ajv 2020, not strict — a schema is somebody else's document — and a
   definition is cached by its value, so an edit is a new entry. An unusable
   value an `ldapmodify` left is skipped with `STS-OAUTH-0461`; one type
   declared twice belongs to the first application in identifier order
   (`STS-OAUTH-0462`).

   **THE REFUSAL ORDER, `STS-OAUTH-0450..0460`**: the array (not JSON, not an
   array, over `oauth2.authorizationDetailsMaxEntries` — 0450), an entry (not
   an object, no string `type` — 0451), a common data field's shape (0452),
   whether anything understands the type (0453 — before the lists, so an
   unknown type is called unknown), the client's `authorization_details_types`
   (0454), the named authorization server's
   `authorization_details_types_supported` (0455, a catalogue row with
   `enforces`), the built-in checks (0153), the schema (0456), and a location
   the resource does not answer to (0457). A token request's details not
   covered by the grant are 0458. `parseAuthorizationDetails(raw, {clientId,
   req})` marks each with its code, and the PAR endpoint reads it too.

   **THE AUDIENCE IS ONE MORE INPUT TO RFC 9068's PLAN.** `audienceFor()`
   answers `{resources, audiences, identifiers}` and
   `jwt_access_token.audiencePlan()` takes it as `details`: two resources
   refused (0459), a scope or `resource` naming an identifier the details'
   resource does not answer to refused (0460, `invalid_scope` /
   `invalid_target`), and several audiences of ONE resource are not "several
   resources", so an ordinary scope is not ambiguous. `accessTokenPlan()` has a
   fifth argument and every caller passes the details it has — the
   authorization endpoint, the token endpoint's early plan, `tokenSet()`'s
   backstop and the PAR endpoint.

   **SECTION 6 IS A SUBSET RULE, AND THE REFRESH TOKEN KEEPS THE WHOLE GRANT.**
   `covers()`: the same type, every common array of the request a subset of the
   grant's (absent means "as granted"), every other member identical, members
   only the grant has ignored — which is what lets an ENRICHED
   `openid_credential` cover the plain request, and `narrow()` hands back the
   enriched one. The code and refresh grants narrow the ACCESS token and pass
   `grantAuthorizationDetails`, which `tokenSet()` puts on the rotated refresh
   token beside `grantScope`/`grantResources`. The direct grants and the token
   exchange are granted what they ask for. `grantIdentifiers()` enriches
   `openid_credential` only.

   **CONSENT ASKS EVERY TIME, AND THE ANSWER CANNOT BE FORGED.** The
   authorization endpoint's consent block parses the details; where one is of a
   declared type and the audience plan would not refuse it, it is outstanding
   unless `consumeConsented(username, client_id, digest)` finds an Allow — a
   persisted `realms.map` entry the consent POST writes
   (`noteConsented()`) and this pass SPENDS. The digest is a SHA-256 of the
   canonical array, so an Allow for 12.50 is not one for 13.00, and a query
   marker a client could add itself was refused as the mechanism. Scopes are
   recorded as before; details never are. `openid_credential` keeps the scope
   rules, which is what every OpenID4VCI wallet already meets. `prompt=none`
   answers `consent_required`.

   **THE REST**: the claim in the access token and the token response (as
   before), `authorization_details` in introspection (section 9.2), both
   discovery documents' list per realm, a client's registered
   `authorization_details_types` at RFC 7591/7592 (`STS-REG-0110`, cleared by
   an update that omits it) and on the console (`STS-REG-0111`), and the RFC
   9728 import proposing a resource's `authorization_details_types_supported`
   as its declared types.

   **NOT DONE**: section 7's enrichment for declared types — nothing here knows
   what a resource server would add — and no resource server HERE reads a
   declared type's details. `tests/rfc9396_authorization_details.js` holds the
   rest.

3an. **`step_up.js` IS RFC 9470, AND A SESSION IS NO LONGER AN ANSWER TO A
   REQUEST IT DOES NOT MEET (2026-09-13).** Asked for as *a couple of new query
   parameters on the authorization endpoint*; `acr_values` and `max_age` were
   already accepted and access tokens already carried `acr` and `auth_time`
   (3ah). What was missing was everything the RFC says about them: the
   authorization endpoint answered from ANY session, so a step-up request on a
   password session got the password session's token back; nothing refused
   `unmet_authentication_requirements`; introspection carried neither claim; and
   no resource server here sent the challenge. A library (rule 3): it requires
   `common/` modules and `oauth2_monitor.js`; `oauth2.js`, `dpop.js` and the
   monitor's view require it. Four decisions were asked of rcbj:

   | Asked | Chosen |
   |---|---|
   | Who sends section 3's challenge | Both: a resource APPLICATION's `oauthStepUpAcrValues` / `oauthStepUpMaxAge`, enforced by the stand-in resource `/oauth2/step-up/resource/{application}`, and this service's own resource server through `dpop.presentedAccessToken()` |
   | An `acr_values` nothing can meet | Refused `unmet_authentication_requirements` in EVERY mode |
   | Ordering, and the token's `acr` | `0` < `1` < `mfa`; the most preferred REQUESTED value met |
   | Monitoring and tests | A second section on `/admin/oauth2/monitor`, in-process tests |

   **THE FIRST ANSWER WAS REFINED WHILE BUILDING, AND SAYS SO.** The question
   described the application requirement as enforced in `presentedAccessToken()`.
   It cannot be reached there: those endpoints are this service's resource server
   and RFC 9068 section 4 refuses a token addressed to an API before any step-up
   question. So an application's requirement is enforced by the stand-in
   resource (which passes `presentedAccessToken()` an `audience` predicate —
   `jwt_access_token.resourceServerRefusal()`'s new fourth argument replaces step
   4 and nothing else — `requireVerified`, and the requirement), and the own
   resource server's requirement is two settings, `oauth2.stepUpAcrValues` and
   `oauth2.stepUpMaxAgeS` (`-1` is off, because `0` is a real requirement).

   **THE AUTHORIZATION ENDPOINT, IN ORDER** (`authorizeRequest()`, above the
   session branch): with a session and a requirement, `assessSession()`; met →
   issue with `issuedAcr` (a new last argument to `issueAuthorizationResponse()`,
   which the code, the ID Token and the access token carry); not met under
   `prompt=none` → `login_required` (`STS-OAUTH-0502`); not met on the RETURN
   from a sign-in → `unmet_authentication_requirements` (0500 for acr, 0501 for
   an age still unmet); not met otherwise → the sign-in screen, as if there were
   no session. `forceMfa` is `demandsSecondFactor()` now — every value the screen
   can PRODUCE needs two — where a regex found `mfa` inside any word, so `mfa 1`
   no longer forces a second factor (it accepts one). **`authn.js` reads
   `record.forceMfa` as a demand for the second factor**, `forcePasswordless`'s
   reason: the hidden `use_webauthn` was a suggestion a hand-made POST could drop.
   An unusable acr value (a quote, a backslash — it is repeated in a
   quoted-string) is `invalid_request` in `vetAuthorizationRequest()`, 0509, so
   a push is refused for it too.

   **ONE ATTEMPT, BY A MARKER A CLIENT CAN FORGE — AND WHY THAT IS BOUNDED.**
   `authorizationReturnQuery()` puts `step_up_honoured=1` on the return address of
   any request carrying a requirement (beside the object for JAR, as
   `jar_prompt_honoured` rides); `PAR_PRIVATE_FIELDS` strips it from a push. With
   it, an unmet requirement is refused instead of looping (anonymous sign-in
   against `acr_values=1`, `max_age=0`, a URN nobody produces). A client adding it
   to its first request gains nothing: an unmet acr is still refused, and max_age
   is held to `authn.pendingTtlS` rather than waived — and the token's `auth_time`
   is true either way, which is what the resource server checks.

   **WHAT MEETS WHAT.** Ordered levels; `hwk`/`phr`/`phrh` (RFC 8176 METHOD
   names, accepted in `acr_values` before this and not published) met by two
   factors whose `amr` names `hwk` — not by a one-time code; anything else only by
   that exact `acr`, which is why an unknown value still gets one sign-in (a
   federation partner may report it). A token with no `auth_time` does not meet a
   `max_age`, and no clock skew is allowed on the age.

   **THE REST**: `acr_values_supported` (0, 1, mfa) in `asMetadata()` and so both
   discovery documents; `acr` and `auth_time` in `introspectionOf()`; the
   challenge (`challengeHeader()`) under the scheme the token was presented with,
   carrying both auth-params when both are required; codes 0500..0509 and
   `STS-REG-0140`/`0141` for the attributes' grammar (owned by `applications.js`,
   `stepUpAttributeProblem()` / `stepUpRequirementOf()`, the acr pattern repeated
   and held equal by the test); `applications.audienceNamesEntry()` shared with
   RFC 9701's `intendedFor()`; eight events counted per client.

   **NOT DONE**: the device and token-exchange grants take no `acr_values`;
   GNAP's interaction does not read a requirement; a JAR round trip was not
   driven by a test with a requirement inside the object.
   `tests/rfc9470_step_up.js` holds the library, the registry and the endpoints
   in a child process; `tests/vendored/sts_step_up.js` the page, the API and the
   flow over HTTP.

## EVERY REFRESH TOKEN IS ENCRYPTED TO ITS OWN REALM (2026-09-12)

`refresh_token_crypto.js` is a library (rule 3) and `refreshToken()` is the one
place it seals. A refresh token is a **nested JWT**: the JWS this file always
minted, encrypted as a compact JWE with `cty: "JWT"` to the realm's own keys.
Three decisions, each asked of the user before it was built:

* **SIGNED, THEN ENCRYPTED.** `open()` hands back the same JWS the refresh grant
  always verified, so the signature, `exp`, revocation, RFC 9700 rotation, the
  DPoP and certificate bindings and the client check are untouched, and
  `signJwt()` still records the jti before anything is sealed.
* **AN UNENCRYPTED REFRESH TOKEN IS REFUSED** — `invalid_grant` at the grant
  (`STS-OAUTH-0237`), `active: false` at introspection. A client holding one
  from before the change signs in again.
* **EVERY JWE ALGORITHM `common/crypto.js` IMPLEMENTS**, chosen by
  `oauth2.refreshTokenEncryptionAlg` / `…Enc`. Each realm holds an RSA pair, an
  EC pair and a 64-byte secret (`helpers.js`'s makeRefreshTokenEncryptionKeys())
  and `open()` picks the key off the token's own header, so changing the setting
  strands nothing. The symmetric algorithms get an HKDF-derived key per
  (alg, enc) — `info` names the pair, because HKDF at 16 bytes is the prefix of
  HKDF at 32 under the same info.

**A REFRESHED ID TOKEN KEEPS THE ORIGINAL `auth_time`, `amr` AND `acr`
(2026-09-12).** OpenID Connect Core section 12.2 says an ID Token from a refresh
response describes the original authentication. The refresh grant minted it with
`auth_time` = now and no `amr` or `acr`, because nothing carried them — so a
relying party renewing a session was told somebody had just authenticated, by no
method. `refreshToken()` now puts the three inside the (encrypted) refresh token
and the grant hands them back to `issue()`. It was found by this service's own
console, which checks exactly that when it renews (`common/oidc_rp.js`'s
`checkRenewedClaims()`), and `tests/vendored/sts_hosted_surface_renewal.js`
goes red without it.

**EVERY READER OPENS FIRST, AND THERE ARE SIX**: the refresh grant,
introspection, revocation, token exchange's `subject_token`, `jtiOf()` and the
code-replay jti reader — plus `admin-core/admin_actions.js`'s `jtiFrom()`, so a
pasted refresh token can still be revoked on the console. **A new reader of a
refresh token must go through `refresh_token_crypto.open()`**; a `split('.')[1]`
on one reads the JWE's encrypted key and throws somewhere unhelpful.

**THE KEYS ARE NEVER PUBLISHED AND ARE NOT PKI LEAVES**: nobody but this service
encrypts to or decrypts with them. They travel with the key set exactly as the
OpenID4VCI request-encryption key does — sealed in `sts_keys` in product mode,
shared over the request pool's key channel, counted by `keystore.enriches()`,
backfilled into a set written before them, private halves and the secret behind
getters — and they rotate with the set. A token minted in one realm does not open
in another. `tests/refresh_token_encryption.js` pins it; the parent project's
`oauth2_sts_endpoints.js` and `sts_dpop.js` stopped decoding the refresh token
the same day and read it at introspection instead.

## `signed_metadata` is signed once a minute, not once a request

`signedMetadata()` in `oauth2.js` caches, and both discovery documents go
through it — the RFC 8414 one and the OpenID Provider Configuration. Discovery
is the most-fetched endpoint here (every client reads it first) and signing it
per request made it the slowest read-only endpoint in the service by a factor
of five; caching took it from 762 to 8,006 requests a second.

**It is the one artifact here where re-signing per request buys nothing.** RFC
8414 section 2.1 describes `signed_metadata` as something the issuer PUBLISHES:
no nonce, no `jti`, nothing bound to the caller, so two clients a second apart
are entitled to byte-identical documents. Everything that can vary — the base
URL the request arrived on, the authorization-server profile it selected, any
setting changed at runtime through `/admin/oauth2` — varies the METADATA, and
**the metadata is the cache key**, so runtime settability is untouched: a
document differing by one member is a different key and is signed afresh.

The entry is held for a minute against a token that lives an hour, and that gap
is the point — a caller must never be handed a signature about to expire. The
map is capped because the key includes a base URL that comes off the Host
header. **Both are settings since 2026-09-12** — `oauth2.signedMetadataCacheS`
(ceiling 1800, half the signature's hour, which is that rule written into the
row) and `oauth2.maxSignedMetadataEntries` — and so is the ALGORITHM,
`oauth2.signedMetadataAlgorithm`, which is part of the cache key: the same
claims signed RS256 and then ES256 are two artefacts. `signPublishedDocument()`
is the signer, and the OID4VCI issuer metadata's `signed_metadata` calls it
rather than keeping a copy.

## The three lifetimes and the skew are SETTINGS now, and one default changed

`ACCESS_TOKEN_TTL` (an hour), `REFRESH_TOKEN_TTL` (thirty days) and the ID
Token's reuse of the first were module-level `const`s in `oauth2.js` until
2026-08-24. They are four `config.js` rows read through four one-line functions
— `accessTokenTtl()`, `idTokenTtl()`, `refreshTokenTtl()`, `tokenClockSkew()` —
and `/admin/token-lifetimes` is the console page over them. Five things about
that, and the first is the one to read before upgrading anything that points at
this service.

* **THE REFRESH DEFAULT IS TWENTY-FOUR HOURS AND WAS THIRTY DAYS.** A client
  holding a refresh token across a long test run now meets an ordinary
  `invalid_grant` where it did not, and `oauth2.refreshTokenTtlS: 2592000` is
  exactly the old behaviour. Every sentence in this repository that asserted
  "thirty days" about a refresh token was CHANGED rather than left to be
  discovered — `oauth2_bcp.js`'s requirement table and its section 2.2.2 header,
  `oauth2.js`'s rotation comment, `config.js`'s `refreshIdleSeconds` row and
  README.md. A default that moves while five documents still name the old number
  is worse than either number.
* **THE ACCESS TOKEN AND THE ID TOKEN NO LONGER SHARE A NUMBER.** They shared a
  constant because an hour suited both, which is not the same as their being one
  setting: an ID Token is consumed once at sign-in by the client and an access
  token is presented to a resource server, and a client that treats the ID Token
  as a session is a defect this mock should be able to produce on demand. Give
  the two different lifetimes and watch which one the client notices.
* **A `const` WOULD HAVE BEEN THE BUG.** This is `common/CLAUDE.md`'s rule read
  literally — a runtime setting must be READ WHERE IT IS USED — and these are
  the settings where it bites hardest, because "make it a minute so I can watch
  my client refresh" is why somebody points a client at a mock at all. A value
  captured at require time is the one thing a runtime override cannot change, and
  it fails in the direction that looks like the console is broken.
* **THE GRANULARITY IS THIRTY SECONDS AND THE FLOOR IS ONE STEP**, declared as
  `min`/`max`/`step` on the row rather than checked at a call site — see
  `common/CLAUDE.md`, since the `int` type grew those for these four. It is a
  decision about what the settings are FOR: below half a minute a token expires
  between the response being written and the client reading it, and the client
  author debugs their own code for an hour. `max` is thirty days on all three
  because a ceiling that made the OLD default unreachable would be a setting
  that cannot be put back the way it was.
* **`oauth2_bcp.js`'s FAMILY WINDOW FOLLOWS THE SETTING.** `REFRESH_TTL_MS` was
  a fixed thirty days with a comment saying it matched `REFRESH_TOKEN_TTL`; it
  is `refreshFamilyWindowMs()` now, because a fixed number would have been a
  comment claiming a match nothing kept. It has a FLOOR OF ONE HOUR: the window
  is granted when a token is minted, so raising the lifetime afterwards could
  otherwise leave a family forgotten while its tokens are still presentable —
  a check silently not made rather than a false refusal, which is the safe
  direction and still not one to arrive at by accident.

## `oauth2.clockSkewS` is applied at EVERY read-back, and that is the whole point

The allowance passed to `jwt.verify()` as `clockTolerance` wherever this service
reads back a token it signed. **Six places take it and a seventh is not in this
directory**: `tokenFailure()`, the refresh grant, token exchange,
`/oauth2/introspect`, `/oauth2/revoke`, `dpop.js`'s `presentedAccessToken()` —
the check the four protected endpoints share — and `common/admin_stats.js`'s
`tokenStateOf()`, which is what every console screen reports state from.

**A verify that did not take it would be a second, stricter opinion about what
"expired" means, reachable only through whichever endpoint forgot.** The symptom
is a token that introspects active and is refused at the refresh grant thirty
seconds before it should be, which reads as a client bug from every side. That
is also why the console reads the same setting: a page saying "valid" about a
token `/oauth2/introspect` calls inactive is worse than a page with no state
column, because it is believed.

**It is NOT `oauth2.clientAssertionSkewS` and must not be merged with it.** That
one is how far out a CLIENT'S assertion may be under RFC 7523 — somebody else's
clock, on a credential this service did not mint. This one is how far out THIS
service's clock may be when reading its own. They move for different reasons,
and a deployment wanting a strict assertion check and a forgiving expiry reading
has to be able to say so. Capped at 300, which is what `krb5.clockSkew` allows,
because a window wider than that has stopped being a tolerance.

**`dpop.js` requires `config.js` for it and is still a leaf** — that module
requires nothing from this repository, so the no-cycle property rule 3 asserts
about `dpop.js` is unchanged.

## THE USERINFO ENDPOINT HAS FOUR LAYERS AND A CLIENT CONTROLS ONE OF THEM

Since 2026-08-26. It was `sub` plus whatever section 5.4's scope asked for, and a
reader who still has that picture has the one this endpoint had before either of
the two things below existed.

**A CUSTOM CLAIM SET OF ITS OWN — `/admin/userinfo-claims`.** The fifth set in
`admin_stats.js`, configured exactly like the four beside it: typed claims,
ticked LDAP attribute types read off `ou=users`, and the groups claim. What
makes it worth having SEPARATELY from the ID Token's set rather than being one
list under two names is the one property no issued artefact has — **this
response is built on every call**, so a claim added there reaches a client that
signed in an hour ago and has done nothing since, where a claim added to the ID
Token set is invisible until the next sign-in. That is the difference the
console page is built around and the reason it is the one claims page with no
"nothing already issued changes" warning on it.

It carries `kind: 'userinfo'` rather than `kind: 'jwt'`, and `kind` answers
exactly one question — which page and which `/admin-api` resource carries the
set. `'jwt'` would have put it on `/admin/claims` automatically, which is the
accident `JWT_CLAIM_SET_IDS` being derived exists to prevent in the other
direction. **`SAML_CLAIM_SET_IDS` had to stop being `kind !== 'jwt'` in the same
change**: a list derived by exclusion is derived from what existed when it was
written, and that spelling would have swept the new set onto
`/admin/saml-attributes` with nothing failing anywhere.

**THE `claims` REQUEST PARAMETER — OpenID Connect Core section 5.5**, and
`claims_parameter_supported` says `true` where it said `false`. A client names
individual claims in the `userinfo` (or `id_token`) member; this server parses
it, **refuses a malformed one at the AUTHORIZATION endpoint** with
`invalid_request` — the last point at which the client is still being talked to,
the same reasoning that puts RFC 8707's `resource` refusal there — carries it on
the authorization code and **inside the access token** as the `claims` claim, and
answers it by resolving each name against the LDAP attribute catalogue.

Riding in the token is the same decision `authorization_details` records and for
the same reason: the UserInfo endpoint sees the token and nothing else — no
code, no session, no request record — so a side table keyed by `jti` would have
to be swept and would not survive a refresh. `claims` is on
`RESERVED_JWT_CLAIMS` so that no web form can decide what a request asked for,
and the refresh grant carries it forward so that a renewal cannot narrow the
grant any more than it can widen it.

**THE FOUR LAYERS, LATER WINNING**, written out at the merge in `oauth2.js`
because that is where somebody debugging an unexpected member is looking:

1. the configured `userinfo` set — what everybody gets;
2. section 5.4's scope-driven claims (`profile`, `email`);
3. section 5.5's individually requested claims, read off `ou=users`;
4. `sub`, assigned last and unconditionally (5.3.2 — a client MUST check it
   against the ID Token's).

**Layer 3 beating layer 2 is the one choice here that is not obvious.** A scope
asks for a CATEGORY and a claims request names a CLAIM, so answering
`{"email":null}` with the invented persona value while the entry holds a real
`mail` would defeat the only reason the feature is worth having. Nothing in
layer 3 can reach a structural claim, and that is by construction rather than by
a guard: every name it resolves comes from the attribute catalogue or from
`PERSONA_CLAIMS`, and no member of either is `iss`, `sub`, `aud`, `exp` or
`nonce`.

**`essential`, `value` and `values` are CARRIED AND NOT ENFORCED**, which is the
honest reading of section 5.5.1 rather than a shortfall. That section says a
server MUST NOT return an error because a requested claim is unavailable, so an
essential claim this service cannot produce is absent and logged at warn level.
`value` and `values` could be satisfied by echoing the asked-for value back and
deliberately are not: everything this service says about a person comes from the
directory or from the invented persona, and a UserInfo response that agreed with
whatever a client asked it to assert would be the one surface here that cannot
be used to test anything. The mismatch is reported instead.

**NON-SPEC: the endpoint also takes a claims request on the request itself.**
Section 5.3.1 defines no request parameters at all. `?claims={json}` and a
repeated `?claim=name` are accepted anyway, on GET and on a form-encoded POST,
because exercising section 5.5 through the specified route means running a whole
authorization flow per variation and a mock nobody can poke is a mock nobody
uses. It is a **union** with what the access token carries and can never take a
claim away from it — what the client was authorized for is what the token says —
and a malformed one is refused `invalid_request` rather than ignored, because
ignoring a debugging parameter that was typed wrong produces exactly the
response a parameter that was never sent produces.

**`claims_supported` was NOT extended to cover any of it, and the absence is the
answer.** That member lists what the protocol itself puts in an ID Token. It
cannot honestly list what `/admin/userinfo-claims` has been configured to add
nor the whole attribute catalogue section 5.5 can reach, because this document
is fetched and cached by clients and both of those change at runtime from a
console page — a list that tracked them would be stale in every cache the moment
somebody ticked a box. `GET /admin-api/userinfo-claims` is the live answer and
names every claim a request may ask for.

---

## `/oauth2/autopost.js` IS ONE OF THE SCRIPTED PAGES

`response_mode=form_post` is answered with a self-submitting form whose script
is `/oauth2/autopost.js` — one entry in the root `CLAUDE.md`'s inventory of
pages that relax `script-src`. The argument for it is made in `oauth2.js`, above
`AUTOPOST_SCRIPT`, and is not repeated here.

---

## What this half deliberately does not do

* **It is permissive on purpose, and it can be told not to be.** Everything in this
  list is the default; `oauth2.rfc9700` turns the OAuth 2.0 / OIDC authorization
  flow into an RFC 9700-conforming one (see rule 3f and `oauth2_bcp.js`) and, with
  it, **turns the main port into an HTTPS listener** on the certificate 8443, 9443
  and LDAPS 636 already share — so there is then no plain listener in this process
  and `/tls/trust` has to be bootstrapped with verification off. The flag is OFF by
  default, changes nothing until it is set, and is RESTART-ONLY because of that
  socket. What it does and does not enforce is published at `GET /oauth2/rfc9700`
  rather than left to be read out of the code. Nothing else here has such a mode.
* **It checks ONE credential, and only in RFC 9700 mode: a registered client's
  secret** — at the token endpoint. `/oauth2/introspect` is the other place a
  client authenticates, and it is not this mode's: an RFC 9701 JWT request
  authenticates in every mode and a JSON one in product mode (3ai). Section 2.5 conditions its requirement on a process for issuing
  credentials existing, and `POST /oauth2/register` is one — so a client that
  registered HERE as confidential must present the `client_secret` this service
  minted for it at the token endpoint. Nothing else changes: a `client_id` this
  service never registered has no credential on file and is untouched, a
  registered public client has nothing to authenticate with, and a client
  declaring `private_key_jwt` is ACCEPTED AND NOT VERIFIED (reported as such,
  because an unverified assertion that is accepted looks exactly like a verified
  one from the client's side). **No end user's password is checked in that mode
  or any other IN DEVELOPMENT**, which is the next bullet and is not affected
  by this one. Product mode (`global.mode`) is a different axis from RFC 9700
  mode and does check it — at the sign-in screen and, since 2026-09-12, at the
  password grant; see the sweep section at the end of this file.
* **It does not verify access tokens it did not issue — except at UserInfo.**
  OID4VCI lets the authorization server be somebody else, so at the three
  credential endpoints a foreign token is accepted as-is. The consequence for DPoP
  is stated in `presentedAccessToken()` (in `dpop.js`, shared by all four
  protected endpoints): for such a token, `cnf.jkt` is a claim anyone could have
  written, and the binding is real only for tokens this service issued.
  `/oauth2/userinfo` is the exception and is meant to be — it answers "who did YOU
  authenticate", so it checks the signature, the `typ`, revocation and the
  `openid` scope, and refuses anything else rather than inventing a profile.
  **Every token it DID issue meets RFC 9068 section 4 at every one of the
  protected endpoints since 2026-09-13** — header `at+jwt`, an issuer this
  service publishes at the request's address, and this resource server in `aud`
  (3ah). A foreign token at the credential endpoints still does not, and cannot:
  its header, issuer and audience are strings this service has no configuration
  to judge.
* **There is no "DPoP required" mode.** Nonce mode makes proofs fresher, not
  mandatory; a request with no `DPoP` header is a Bearer request and is answered as
  one, so turning nonce mode on cannot break the Bearer clients this service also
  exists to exercise.

---

## RFC 8693 IS TWO MECHANISMS, AND THE TOKEN ENDPOINT RECORDS THEM AS TWO

Section 1.1 is explicit that impersonation and delegation are different things,
and `/admin/delegation` is where the difference is visible:

* **no `actor_token` — IMPERSONATION.** What comes back is a token for the
  subject with nothing on it about who exchanged it. The resource server cannot
  tell, and neither can anybody reading the token later, which makes that page
  the only place the fact will ever exist.
* **an `actor_token` — DELEGATION (§4.1).** What comes back carries `act` naming
  the actor, and `act` NESTS: a second hop appears underneath the first rather
  than replacing it.

The act is recorded through `../common/delegation.js` (rule 3l) AFTER `issue()`,
so the row can name the token that came out. Two details are worth keeping if it
is reworked. The `jti` is read back off the signed access token with
`jsonFromB64u()` — the same reader the `actor_token` is decoded with twelve lines
above — rather than by changing the return type of the one helper every grant
here mints through. And the INTERMEDIARY of the chain is deliberately both an
identity and an application: the client performing the exchange is the
application, always, and the actor named in the `actor_token` is the identity,
which only a delegation has. An impersonation therefore draws a chain whose
middle is an application and nobody, which is exactly what happened.

**THE TARGET IS RESOLVED THROUGH THE APPLICATIONS REGISTRY, and it is the one
place in this service that reads `oauthAudience`.** An `audience` names a
RESOURCE — `https://esb1.example.com` — and that registry is keyed by the
identifier an application PRESENTS, which for an OAuth client is its client_id.
Filing the act under the raw audience therefore draws a box on
`/admin/delegation/map` that nothing else in the picture mentions, and a
two-hop chain through a middle tier comes out as two unconnected halves: the URL
the first hop reached and the client_id the second hop exchanged AS are one
application under two names. So `applications.forAudience()` is asked first and
the application's own identifier is what the row carries, with the audience that
was actually requested kept in the sentence beside it — the raw string is a fact
about the request and must not be lost to a resolution. **Nothing is refused:**
an audience nobody has registered resolves to null and is recorded verbatim,
exactly as it was before this existed.

**Nothing authorizes either of them here**, and the row says so where a Kerberos
row names an attribute. `may_act` is the claim a real deployment would use for
it; this service neither issues nor reads one.

**AN EXCHANGE MAY ASK FOR A REFRESH TOKEN SINCE 2026-09-01, AND THAT REVERSED A
SENTENCE THIS FILE AND README.md BOTH USED TO STATE FLATLY.** The old one was
that an exchanged token carries no refresh token because there is no end-user
session behind it to refresh against — which is true and is not the argument.
RFC 8693 section 2.2.1 makes `refresh_token` an OPTIONAL member and says when it
is worth issuing: "in cases where the client of the token exchange needs the
ability to access a resource even when the original credential is no longer
valid", the user-not-present case where there is no session BY DESIGN. So the
absence of a session was the reason to have one, read backwards.

Three things about how it is done are the parts worth keeping:

* **It is asked for, not assumed — and what the ask BUYS is configured.**
  `requested_token_type` is section 2.1's parameter for exactly this, and the
  branch reads it and nothing else about the request: the URN
  `urn:ietf:params:oauth:token-type:refresh_token` is the ask and every other
  value, including none, is not. What that ask then produces is
  `oauth2.tokenExchangeRefreshToken`, which is THREE WORDS AND NOT A FLAG:
  `never` refuses the ask (silently — an exchange that asked and did not get one
  is still well-formed, and the refusal is a log line naming the setting rather
  than an error), `when-requested` honours it and is the default, `always` hands
  one to an exchange that never mentioned the parameter. A bool could not have
  said this: `false` would have had to mean `never`, leaving `true` meaning
  either of the other two with no way to reach the third — and `always` is the
  side the interesting client bug is on, because a credential arrives that the
  client did not ask for and must not leak. The default keeps the change
  invisible to every existing caller, `tests/vendored/oauth2_sts_endpoints.js`
  among them.
* **It is read on the CLIENT PERFORMING THE EXCHANGE**, through
  `applications.settingFor()` — the same call every other per-client OAuth
  override goes through, so `oauthTokenExchangeRefreshToken` on that entry wins
  over the service-wide value. The client and not the audience, for two reasons
  that point the same way: the refresh token is HANDED to the client, so it is
  that party's credential to hold, revoke and redeem; and in the interesting
  case the subject the exchange is *about* has no entry in the registry at all,
  the whole point of an exchange being a subject_token from somewhere else.
  **That attribute is the first in this service's application schema that is
  scoped to a protocol family** — it applies to OAuth 2.0 and OpenID Connect and
  both write doors refuse it elsewhere; `common/CLAUDE.md`'s rule 3g argues the
  mechanism, and the reason it is worth refusing rather than leaving inert is
  that a value here is a policy about the TOKEN ENDPOINT, and an entry no token
  request can ever name would carry it looking as though it were in force.
* **An unrecognised value falls to `when-requested` and not to `always`.**
  `settingFor()` warns naming the entry and hands back the service-wide value,
  and the branch then compares that against the three words — so a fourth word
  behaves as the middle one. That is the safe end of the range to fall off: the
  client gets what it asked for and nothing it did not.
* **`withRefresh` and `resources` are the WHOLE of it.** The token is minted by
  `refreshToken()` through `tokenSet()`, the same path every other grant takes,
  so "an ordinary refresh token of this service" is true by construction rather
  than by six properties having been remembered separately — the `typ`, the jti
  in the one revocation set, `oauth2.refreshTokenTtlS`, the RFC 9700 family
  bookkeeping and rotation, and the DPoP and certificate confirmations. An
  exchange made with a proof mints a BOUND refresh token, which is the whole of
  RFC 9449 section 5 on the long-lived half of a grant. `resources` is passed
  because it is what the refresh grant compares a renewal against: an exchange
  addressed to one audience must not be renewable into a token carrying this
  service's default, since a grant cannot widen itself by being renewed and an
  exchange is a grant like the rest.
* **`issued_token_type` still says `access_token`, and that is a decision.**
  Section 2.2.1 defines that member as describing the token in `access_token`,
  and an access token is what this response's `access_token` holds however the
  request was written. The other available reading — hand the client a refresh
  token IN `access_token` and name it there, which the section's "historical
  reasons" note permits — was refused: a client would then hold a `typ:
  'Refresh'` JWT under the name every other grant here uses for the credential
  a resource server is presented with, and this service's own protected
  endpoints would refuse it. Both halves of the grant come back where a client
  already knows to look for them.

The delegation act names the refresh token in `produced` beside the access token
and the ID token, for the id_token's reason and a stronger one: it is the half
that OUTLIVES the exchange, and an act that did not mention it would describe a
delegation as having produced a credential good for an hour when what it
produced is one good for a day and renewable.

---

3n. **`frontchannel_logout.js` is a library (rule 3) and it exists because THREE
   sign-outs have to fan out identically.** It registers no route, so its place
   in the require order does not matter, and it requires `helpers.js`,
   `config.js`, `app.js` and `applications.js` — none of which requires it back.

   It holds four things: which clients a session signed into
   (`noteClient()`, written on the session at `issueAuthorizationResponse()`, the
   one point where both the client and the session are in scope), the
   notification URLs (`notificationsFor()`), the CSP the iframes need
   (`contentSecurityPolicyFor()`), and the block of HTML (`render()`).

   **It is a file of its own rather than code in `oauth2.js` for one reason:**
   `/oauth2/logout`, the protocol-independent `/logout` and the console all have
   to render the SAME fan-out, and `logout/logout.js` reaching into `oauth2.js`
   for it would be a require this file makes unnecessary — `oauth2.js` requires
   THIS, so the other direction would be a cycle.

   **`sid` REVERSED A DOCUMENTED DECISION AND THE REVERSAL IS THE INTERESTING
   PART.** `admin_stats.js` used to say, in as many words, that no token this
   service issues carries a session identifier and that inventing one to make a
   console page easier would change what every client receives. That was right,
   and the reasoning is kept: **a claim is added because a SPECIFICATION needs
   it, not because something here would find it convenient.** Front-Channel
   Logout section 3 is that specification — an RP holding two sessions in one
   browser cannot tell which ended without `sid`. So the ID Token carries it when
   it was issued ON a session, and `oauth2.frontchannelLogout` turns the claim,
   the two metadata members and the fan-out off together, in one place. Three
   switches would let somebody advertise a capability whose claim is off, which
   is a discovery document that lies.

   **THE IFRAMES ARE THE SIXTH CSP RELAXATION AND THE NARROWEST.** `frame-src`
   falls back from `default-src 'none'`, so an iframe to another origin is
   blocked — correct everywhere else here. The sign-out page relaxes it to THE
   ORIGINS IT IS ACTUALLY LOADING, enumerated from the URIs, rather than to `*`.
   It goes through `app.contentSecurityPolicy()` like every other relaxation, so
   `frame-ancestors` and `base-uri` cannot be dropped by it. A URI this runtime
   cannot parse is left OUT of the policy rather than widening it: the iframe
   then does not load, which is the safe direction, and the row beside it still
   shows the URL.

   **EVERY URL IS PRINTED AS A LINK BESIDE ITS IFRAME**, because section 5 says
   the provider cannot know whether a notification succeeded. A dead relying
   party, a certificate the browser will not accept and a mistyped URI all look
   exactly like success; the link is the only thing that turns "nothing
   happened" into something a person can click. Same decision `wsfed.js` made
   about its cleanup pings.

   **`/oauth2/logout` CAN NOW ANSWER WITH A PAGE INSTEAD OF A REDIRECT**, and
   only when there is a fan-out to perform: a 302 to `post_logout_redirect_uri`
   abandons the document before any iframe loads. **Where no client on the
   session registered a logout URI — every deployment that has not asked for
   this — the redirect happens exactly as it always did.** The behaviour of an
   existing caller must not turn on a feature it never opted into.

   **BACK-CHANNEL LOGOUT IS A DIFFERENT SPECIFICATION AND IS NOT IMPLEMENTED.**
   It is a signed Logout Token POSTed server-to-server, which needs this service
   to reach the RP's network rather than the browser's. `backchannel_logout_supported`
   stays `false`; advertising it because front-channel arrived would be the
   overstatement that document exists not to make.

   `outstandingCodesFor()` / `dropCode()` are exported from `oauth2.js` for the
   same feature and are FUNCTIONS rather than the `authzCodes` Map, for the
   reason `registeredClients` is no longer exported: a caller holding the Map
   would be a second place that decides what a code is, and would miss
   `redeemedCodes` beside it — so a signed-out code would still answer a REPEAT
   of the token request with the tokens it already got, and a sign-out that hands
   back a token set is not a sign-out.

---

## A scope may name a PERMISSION, not just an application, and the token says both halves

Added 2026-09-01. `audienceScopes()` already turned a scope value that is
another application's `client_id` into the access token's `aud` — the rule
`scope-named-audience` describes, one section up. This is that rule one step
more precise, and it is the OAuth half of the delegated-permission register in
`common/app_permissions.js`.

A **resource** application exposes an API: a base URI
(`oauthPermissionBaseUri`) and a list of permission names (`oauthPermission`),
joined into an identifier — `https://example.com/` and `write` make
`https://example.com/write`. A client sends that whole string as an ordinary
scope, and:

```
scope=openid https://example.com/write https://example.com/read
   ->   "aud":   "https://example.com/"
        "scope": "openid read write"
```

**THE BASE URI IS THE AUDIENCE AND THE NAME IS THE SCOPE**, which is Microsoft
Entra ID's behaviour exactly and is what a resource server wants: check `aud`
once, then read bare permission names.

**IT IS THE ONE EXCEPTION TO "THE AUDIENCE IS THE SCOPE VALUE VERBATIM"**, and
that rule's own header is where the difference is argued. A permission is a
COMPOSITE identifier this service composed out of two facts on an entry, so
taking the whole string as the audience would address the token to a PERMISSION
rather than to the API — and nothing would ever be able to check that `aud`
against anything, because no application answers to `https://example.com/write`.

**THE PERMISSION LOOKUP IS TRIED BEFORE THE CLIENT_ID ONE**, because it is the
more specific of the two: a permission identifier is a whole URI with a name on
the end and a `client_id` is a bare word, so they cannot collide in practice —
and where a registration ever managed to make them collide, the permission is
what a client that wrote a URI meant.

**THE MATCH IS EXACT AGAINST THE COMPOSED IDENTIFIER, NEVER A PREFIX TEST ON
THE BASE.** A prefix test would match `https://example.com/anything` against a
registered base whether or not that permission was ever defined — which is
precisely the case this feature exists to distinguish, and it would let any
client address a token to anybody's API by inventing a word after their base
URI. A scope naming no defined permission is an ordinary scope and is granted as
everything else here is.

### `permissionRefusal()` — the one refusal, and where it is made

**IT IS NOT PART OF RFC 9700 MODE AND MUST NEVER BE FOLDED INTO IT.** Every
check in `oauth2_bcp.js` cites a section of a published Best Current Practice; a
delegated permission cites nothing, because no RFC says an authorization server
must have one. It is a product's design rather than a standard, and putting it
behind `oauth2.rfc9700` would make `GET /oauth2/rfc9700` advertise a requirement
no document contains. It has a setting of its own —
`oauth2.delegatedPermissionsEnforced`, off by default, runtime, and settable on
a realm.

**IT IS SEPARATE FROM `audienceScopes()` FOR THE REASON THAT KEEPS `bcp.js` OUT
OF THE MINTING PATH.** That function TRANSLATES and is called from six grants; a
translation that also decided policy would make the decision six times, and one
of them would eventually get it wrong.

**IT IS CALLED IN THE TWO PLACES A CLIENT ASKS.** The AUTHORIZATION endpoint,
beside the `resource` and `claims` refusals and for their stated reason — it is
the last point at which the client is still being talked to — answering
`invalid_scope`, which is RFC 6749 section 4.1.2.1's own code for a scope that
exceeds what this client may have, so no code had to be invented. And the TOKEN
endpoint, once above the grant switch beside `parseResourceIndicators()`, for
the grants that never pass through the authorization endpoint: client
credentials, the password grant, the token exchange, and a refresh naming a
scope explicitly.

**A GRANT ALREADY ISSUED IS NEVER RE-JUDGED**, which is why the token endpoint
reads `body.scope` and nothing else. An authorization code carries what was
authorized and was judged at the authorization endpoint; a refresh with no
`scope` carries its grant's. That is the same rule federation follows about not
re-checking a person after the session exists, and it is what makes the setting
safe to turn on while something is running.

### The token endpoint now records `oauthScope`, and that is not cosmetic

`seen()` at the token endpoint writes the scope the request carried, where it
carries one. Until 2026-09-01 only the authorization endpoint did — so for the
three grants that never go near it (client credentials, the password grant, the
pre-authorized code grant) `oauthScope` on the client's entry stayed empty
however often it asked. The visible symptom was on `/admin/delegation`, whose
`asked for` column reads that attribute: a client spending a permission every
minute was reported as never having asked for it. It is CONDITIONAL on the body
carrying a scope, because an `authorization_code` redemption does not (the grant
does) and writing an empty value would record that the client asked for nothing.

## `consent_screen.js`: the screen, and why it is not in `oauth2.js`

Rule 4c. `/oauth2/consent` is the one thing between a signed-in person and an
issued credential since 2026-09-01, and it is a module of its own for the reason
`authn/authn.js` is: **the authorization endpoint hands a browser to a screen
somebody else owns and takes it back afterwards**, and the thing that owns the
screen must not have to know what OAuth is.

**IT IS REQUIRED AFTER `authn.js` AND BEFORE `oauth2.js`, and both halves are
dependencies.** AFTER, because it reads that module's session — to check that
the person answering is the person the question was asked of — and draws with
its stylesheet, so that two screens a person meets seconds apart in one flow
look like one service. BEFORE, because the authorization endpoint calls
`beginConsent()`. The dependency is one-way in exactly the way
`beginAuthentication()`'s is: this module knows nothing about OAuth beyond a
`returnTo` it is handed and a `consent_error` it hands back.

**THE SCREEN HOLDS THE PENDING RECORDS AND THE REGISTER HOLDS NONE.**
`common/consent.js` is the model — the value's grammar, what "outstanding"
means, the global override, the register both console halves are read from — and
it holds no store at all, because both halves of what it knows are attributes in
the directory. This file holds the one thing that IS state: a `realms.map()` of
consents in flight. That split is `app_permissions.js` / `admin-ui/admin.js`'s
and `delegation.js` / `delegation_map.js`'s, made a third time.

### Where the check sits in `authorizeEndpoint()`, and why

**Inside the branch that has a session, above `issueAuthorizationResponse()`.**
Everything above that line is about the REQUEST; this is the only check in that
endpoint that is about who is answering it, and there is no person until there
is a session.

**`consent_error` is read beside `authn_error`, one line below it, and the
reason it must be THERE rather than lower is the opposite of the sign-in
screen's.** A refused sign-in leaves no session, so the session branch would
draw the login screen again — a loop with a form in it. A refused CONSENT leaves
the session STANDING, so the session branch would find it, ask
`consent.outstanding()` again and send the person straight back to the screen
they just said no on. Same loop, one door along, and the only way out would be
closing the tab.

**The `returnTo` is built exactly as the sign-in hop's is, with `prompt`
dropped** — it has been honoured by the time they come back, and leaving
`prompt=consent` on would ask again for ever. Everything else goes back
untouched, because the second pass has to be the request the client actually
made: PKCE, the nonce, `claims` and `authorization_details` are all read on it.

**THE APPLICATION IS RECORDED ON THIS PATH TOO, with `counts: false`.**
`issueAuthorizationResponse()` is where a client_id is normally written into
`ou=applications` and it is not reached here, so without it an application whose
very first request meets the screen has no entry — the screen shows a bare
client_id where a name belongs, and `/admin/consent` cannot offer it in the list
of applications a scope can be consented for. An operator wanting to pre-consent
a new client would have had to sign in to it first and agree to everything by
hand. `counts: false` is what keeps it honest: being ASKED is not an
authentication, and the call in `issueAuthorizationResponse()` still counts
once.

### What the screen refuses, and the one that matters

Three checks, and only one of them is obvious. The record must EXIST and not
have expired (ten minutes, `authn.js`'s window, because they are two halves of
one interrupted request). The answer must be a POST — a GET that recorded
consent would be consent that anything prefetching a link could give. And **the
session presenting the answer must belong to the person the question was asked
of**: that is the one failure at this door that would write something UNTRUE
into the directory rather than merely letting something through, because the
answer would be filed against whoever happened to be signed in.

Every one of those refusals leaves the pending record ALONE. A screen that spent
itself on a refusal would turn each of them into a denial of service against the
person it was asked of.

### Two things it deliberately is not

**IT IS NOT A SIXTH SCRIPTED PAGE.** `app.js` sets `script-src 'none'` for the
whole service and this repository's rule is that a page wanting a script must
argue it CANNOT work without one. This one plainly can: it is two buttons in a
form. There is no `contentSecurityPolicy()` override anywhere in the file.

**IT IS NOT A REFUSAL, WHICH IS WHY THE SETTING IS ON BY DEFAULT.** Every other
policy here is off because a refusal that cannot be turned off removes a test
case; consent adds one. `oauth2.consentRequired` off means exactly what this
service did before the screen existed — nothing asked and nothing recorded — and
it is NOT "everybody consented", because no agreement is written down and
turning it back on asks again.

It is not a refusal and that is why: it is the screen every real authorization
server draws on a first sign-in, and a client that has never met one has never
run the code that survives it. It still checks nothing — the person has already
been let in under any name they typed.

**THE TOKEN ENDPOINT ASKS NOBODY ANYTHING.** A grant already issued is never
re-judged, the same rule delegated permissions follow and federation follows
about not re-checking a person once the session exists — so a refresh of a code
obtained before the setting was turned on still works, and revoking a consent
does not touch a token already minted.

## The UserInfo endpoint's two halves have no test in either repository

**By the root `CLAUDE.md`'s rule they belong in the PARENT suite** — every one of the
assertions below can be made by driving the running service over HTTP, so
nothing about them justifies a directory here. What a test would have to cover
is almost entirely the CLAIMS REQUEST, because the configured `userinfo` set is
the four claim sets' behaviour on a fifth set and the one thing about it that is
its own is worth one assertion: a claim added to it reaches a client that
already holds its token, with no new sign-in. The rest is OIDC Core section 5.5,
and it is mostly negatives: a `claims` parameter that is not JSON, is not an
object, whose `userinfo` member is a string or a number, whose individual claim
request is a number, whose `essential` is not a boolean, whose `values` is not a
non-empty array, or that names more claims than the cap — each refused at the
AUTHORIZATION endpoint with `invalid_request` and the reason, which is where the
client can still be told; an unknown TOP-LEVEL member ignored rather than
refused, and named in the reply; a name nothing can resolve simply absent and
never an error; an `essential` one absent too; a `value` that does not match
answered with the value HELD. Beside those, the properties that only a test can
pin down: that the parsed request rides in the access token and survives a
REFRESH, that the ID Token honours the `id_token` member and the UserInfo
response the `userinfo` one, that `address` returns the whole Address Claim
where `address.locality` returns one member, that `family_name#ja-Kana-JP` comes
back under exactly that name, that a requested claim beats the scope-driven one
and `sub` beats everything, that the federation release policy filters a
requested claim exactly as it filters a configured one, and that the non-spec
request-level parameter is a UNION with the token's own request and can never
take a claim away from it.


## `observeClientAuthentication()` — A FACT, WHERE `checkClientAuthentication()` IS A POLICY (2026-09-05)

`oauth2_bcp.js` has two functions about client authentication now and they
answer different questions:

| | Question | Refuses? | Mode-gated? |
|---|---|---|---|
| `checkClientAuthentication()` | was this client REQUIRED to authenticate, and did it | yes, `invalid_client` | yes — a no-op while `oauth2.rfc9700` is off |
| `observeClientAuthentication()` | did this client, on this request, present a credential that VERIFIED | **never** | **no** |

**The second exists because the role gate asks a question RFC 9700 mode does
not.** `ALL_AUTHENTICATED_APPLICATIONS` and
`ALL_UNAUTHENTICATED_APPLICATIONS` are about what the client IS, and that is
true whether or not this service has been asked to enforce the BCP. A mock with
`oauth2.rfc9700` off still knows perfectly well that a client sent a matching
secret; refusing to notice would make both roles unusable in the default
configuration — which is the configuration almost everything here runs in.
`tests/vendored/sts_roles_builtin.js` asserts the mode is OFF before it asserts
anything else in that section, so the claim is about observation and not about
enforcement.

**It keeps four "no" answers apart** — no entry here, a PUBLIC client, a
confidential client with nothing on file to check against, and a credential
that did not verify. Only the last is a failure; the second is what
`ALL_UNAUTHENTICATED_APPLICATIONS` is actually about. That is why the function
has no `ok` field at all: an `ok` would invite a caller to treat a public client
as a problem.

**It is not free.** For a confidential client it performs the same verification
the policy function performs, so a token request from one now does that work
whether or not the mode is on. That is affordable — one signature check on a
request about to mint several — and the alternative was a third state, "we did
not look", that every caller would have had to decide what to do about.

## `issuanceSubjectOf()` HELD TWO CONSTANTS DRESSED AS FACTS

Until 2026-09-05 it returned `authenticated: true` for both kinds of party.
Three of the six built-in roles are about that difference, so while it said
`true` twice, a policy could name them and nothing arriving at the token
endpoint could hold or fail to hold them.

The two kinds take their answer from different places and that is the shape of
the fix:

* **A user's** belongs to the session the authorization happened on, and the
  session is not here — so the authorization code carries
  `session_authenticated`, and a refresh reads it back off the token registry
  by jti. A grant with no session behind it (the password grant, a token
  exchange) HAS authenticated somebody by presenting a credential at this
  endpoint, so `true` is honest there and stays.
* **An application's** belongs to this request, and is the observation above.
  **A missing observation is `false`**, which is the one place in that function
  that fails closed: the permissive reading would hand
  `ALL_AUTHENTICATED_APPLICATIONS` to every public client in the service.
  Nothing is refused by that alone — an application requiring `EVERYBODY` is
  unaffected, which is every application that has not been told otherwise.

The observation is injected by the `issue()` closure at the token endpoint
rather than passed by each grant, for the reason that closure already gives
about the client certificate: every grant mints through it, so a seventh added
later inherits the decision without its author having to know it exists.

## THERE ARE EXACTLY TWO PLACES THIS MODULE HANDS BACK SEVERAL CREDENTIALS AT ONCE, AND BOTH NOW SAY SO (2026-09-05)

`/admin/tokens` lists one row per REPLY rather than one per credential, and what
makes that possible is a `set_id` minted here and carried into the token registry
through `issuanceContext()`. **`common/CLAUDE.md` argues why it is stated rather
than derived**; this is about the two call sites, because getting the list of
them wrong is the way this feature breaks quietly.

| Where | What it hands back | Why it is not the other one |
|---|---|---|
| `tokenSet()` | access token, refresh token, ID Token | every grant that issues a token set goes through it — the same property that already makes it the one place the RFC 9700 binding note is written |
| `issueAuthorizationResponse()` | access token and ID Token, in one fragment | **implicit and hybrid never go through `tokenSet()` at all.** They mint on the spot |

That second row is the same trap the audience derivation fell into and is fixed
beside it: `audienceScopes()` is read in both places for exactly this reason, and
a set id in only one of them would have drawn the identical pair as one row from
the token endpoint and two from the authorization endpoint.

**`tokenSet()` REPLACES its parameter object rather than mutating it.** `issue()`
hands the same object to `checkIssuance()` and to the audit, and a set id
appearing in a record nobody minted is worse than none at all. A copy, so the
twenty-odd reads of `opts` below it are untouched.

**A REFRESH GETS A NEW SET.** This function is entered once per response, so the
second generation of a grant is a set of its own with its own issued instant and
its own expiries. What joins the generations is `parent_refresh_jti`, which is a
different relation and is already drawn as one at `/admin/tokens/credential`.

**The id is minted even when the response carries one credential or none.** A
`response_type=code` response records nothing, so the id costs a random string; a
conditional would be a second rule about when a set exists, and the one rule — a
set is a response — is what makes "a set of one" mean the same thing on every row
of that table.

## THE 2026-09-12 HARD-CODED-VALUE SWEEP, AND WHAT IN IT IS MORE THAN A NUMBER

An audit for literals product mode shipped unchanged. Most of what it found
became a `config.js` row whose `dflt` is the literal, read per use — the
authorization code's life (`oauth2.authorizationCodeTtlS`, which
`oauth2_bcp.js`'s transaction window now READS rather than a comment claiming
twice it), the DPoP windows, the caps, the Basic realm, the registration shapes.
Those need no argument beyond `common/CLAUDE.md`'s. Six things do, and
`tests/oauth_oid4vc_hardcoded.js` pins every one.

**THE PASSWORD GRANT VERIFIES THE PASSWORD.** It refused the literal `invalid`
and accepted everything else in BOTH modes, so a product deployment that checked
a password at every other door issued tokens to anybody naming a person at the
token endpoint. It goes through `credentials.verifyAsync()` now — which refuses
`invalid` in both modes and says yes to everything else in development, so
development is unchanged by construction rather than by a branch. In product it
is also rate-limited in the sign-in screen's bucket, and **a person holding a
second factor is refused**, because RFC 6749 section 4.3 has nowhere to carry
one and issuing would make `mfaRequired` mean nothing at the one endpoint nobody
looks at. Every refusal is the one protocol answer; the reason goes to the log.

**THE ID TOKEN AND USERINFO FILL PROFILE CLAIMS FROM THE DIRECTORY WHERE NOTHING
IS INVENTED.** `helpers.userFor()` stopped inventing `name`, `given_name`,
`family_name`, `email` and `email_verified` in product mode.
`personFromDirectory()` fills the first four from `cn`, `givenName`, `sn` and
`mail` through `claimAttributes.requestedClaimsFor()` — the catalogue every claim
set already uses, so there is one answer to which attribute is a family name —
and **never sets `email_verified`**, because no directory attribute says a
mailbox was verified. `definedOnly()` keeps an absent claim ABSENT: an
`undefined` member in a payload is dropped by JSON, but `Object.assign` copies it
first and would erase a configured claim of the same name. `sub` is NOT touched
and is worth knowing about: it is derived from the username, so an account
deleted and re-created under the same name is the same subject everywhere.

**THE THREE ASSERTION REPLAY CACHES REFUSE WHEN FULL; THEY NO LONGER FORGET.**
(They are ONE history since 2026-09-13 — `common/used_assertions.js` — and the
rule below moved into it unchanged, as one count per realm rather than three.)
`client_auth.js`, `assertion_grant.js` and `saml_assertion_grant.js` each
dropped their oldest entry at a thousand whether or not it had expired — "a
forgotten jti is a check not made", which is the right trade for a cache that
guards against a client bug and the wrong one for a cache that guards against a
CAPTURED CREDENTIAL. The cap is `oauth2.assertionReplayCacheSize`, expired
entries are swept first, and a cache full of live ones refuses the next
assertion. `oauth2_bcp.js`'s refresh bookkeeping could not take that rule word
for word — it runs after a token is signed, and refusing to issue would turn a
busy service into one that signs nobody in — so it forgets expired, then ROTATED
(already revoked), then only as a last resort a live record, with a warning. Its
header states the trade.

**CLIENT ASSERTIONS, AND THE GRANT'S `iat` HOLE.** RFC 7523 section 3 claim 4
makes `exp` REQUIRED, and a client assertion without one was accepted with its
jti remembered for sixty seconds while the assertion itself never expired. In
product it is refused and `oauth2.jwtBearerMaxLifetimeS` caps a client
assertion's lifetime too; development keeps both permissive (the parent suite
signs post-quantum client assertions for an hour) and now remembers a no-`exp`
jti for the ceiling rather than a minute. The GRANT had the ceiling in both
modes and skipped it for an assertion with no `iat` — so leaving out an optional
claim was the way round it. It measures from now in that case, in every mode,
and so does the SAML profile for an assertion with no `IssueInstant`.

**`POST /dpop/nonce-mode` IS PER REALM AND A TEST CONTROL.** It flipped one
`realms.sharedMap` row for the process, so a realm turning nonces on turned them
on everywhere, and it answered anybody. The state is `oauth2.dpopNonceRequired`
now — per realm by construction, replicated like any setting, and changeable
through `/admin/oauth2` and `/admin-api/config/set` behind a credential — the
endpoint writes it in development and `mode.opensTestControls()` refuses it in
product. Writing the value the setting would have anyway CLEARS the override,
so a test that turns nonces on and off leaves no `source: override` row behind.

**RFC 7591 REGISTRATION IS CLOSED IN PRODUCT** unless `oauth2.openRegistration`
is on, and `registrationOpen()` is read by the endpoint AND the metadata so that
`registration_endpoint` is not advertised where it refuses. The RFC 7592
management calls compare the registration access token in constant time and
never match an empty one — in every mode, because a read hands back the client
secret.

**WHAT DID NOT CHANGE, AND SAYS SO.** `urn:sts:client:` (the RFC 9700
client subject) and the `urn:sts:application:` / `urn:sts:person:`
certificate SANs are identifiers already inside issued tokens and certificates;
renaming them is a migration, not a setting.


## 3z, CONTINUED: A PERSON AS AN RFC 7522 ISSUER (2026-09-13)

`saml_assertion_grant.js` answered only for applications: `issuerEntry()` read
`oauthSamlAssertionIssuer` and an application's own identifier. It asks
`person_assertions.issuerFor(iss, 'saml')` now, **after every application
declaration and before an application's own identifier** — `assertion_grant.js`'s
order, for its reason. A person is an issuer here only while they hold an RFC 7522
key pair (`stsSamlAssertion*`); what comes back carries `kind: 'person'` and the
person's certificate **mapped into the section 2.2 shape** `certificatesForParty()`
already reads (`oauthSamlAssertionCertificate` + chain), so the reader that refuses
to cross into the RFC 7523 set is the one reading it and a person's JWT key cannot
sign a SAML assertion. A person has no registered-by-value certificate.

**Below the signature, a `<Subject>` that is not that person is refused
`STS-OAUTH-0242`** — `subjectIsSelf(record, subject, 'saml')`, the username or the
SAML declaration. The verdict carries `issuerKind` and `person` like the JWT
grant's, and `oauth2.js` writes the authentication note and the delegation row as
*a person presenting themselves* rather than as a third party vouching.
`tests/person_credentials.js` holds it in process and
`tests/vendored/sts_user_credentials.js` at `/oauth2/token`.

## A PERSON'S `sub` IS THEIR ENTRY'S, AND A GRANT WITH NO BROWSER STILL NEEDS ONE (2026-09-14)

Every token issued to a person carries `sub = urn:uuid:<entryUUID>` now (it was
`urn:sts:user:<username>`); `authn/CLAUDE.md`, *What an authenticated identity is here*,
carries the design and `ldap/CLAUDE.md` the directory half. Three things in this directory
changed with it:

* **The password grant and both assertion grants record the authentication FIRST** — which
  is what makes the directory create the entry — and then ask for the person through
  `provisionedPerson()`. Where the directory still holds nobody (`ldap.autocreateUsers`
  off, the person never provisioned) they refuse `invalid_grant` (`STS-OAUTH-0510`) rather
  than minting an empty `sub`. A process with no directory refuses nothing.
* **A refresh follows the token's SUBJECT, not the username beside it**
  (`refreshedPerson()`): a person renamed since the grant is found under the new name and
  keeps their `sub`; one deleted since — or deleted and re-created under the same name,
  which is a different subject — is refused `invalid_grant` (`STS-OAUTH-0511`). A refresh
  token whose subject is not a person's is minted as it always was.
* **UserInfo reads the person under the name their subject names now**, so a renamed
  person is answered with their own entry. A person's RFC 7523 self-assertion may carry
  their own `urn:uuid:` as `sub` (`person_assertions.subjectIsSelf()`), and GNAP reads
  either subject form through `helpers.nameForSubject()`.

`tests/stable_subject.js` section D drives all three over HTTP.

## SEVERAL NODES: EVERY OAUTH SINGLE-USE VALUE IS SPENT THROUGH A CLAIM (2026-09-14, #46)

Issue #46 section 2's OAuth items. Each was a read, then a write, on a store that reaches
the other nodes a moment later — and in every case but DPoP, an `await` sat between the
read and the write inside ONE process as well, so two concurrent requests to one node
could already both win. Each is now spent through `cluster/cluster_claims.js`
(`cluster/CLAUDE.md`): one `INSERT … ON CONFLICT` on postgres, this process's memory
otherwise. The capability rows `oauth.codes-once`, `oauth.refresh-rotation` and
`oauth.dpop-jti` are provided by `oauth2.js`, `oauth2_bcp.js` and `dpop.js`.

| Value | Scope | Where it is spent | The loser |
|---|---|---|---|
| authorization code | `oauth.code` | `tokenGrant()`, below every check and above the mint; bound to the response | waits (≤5s, catching up through `cluster_barrier.syncShared()`) for the winner's `redeemedCodes` record, then goes down `replayOrRefuseRedemption()` — the same token set outside RFC 9700 mode, refusal and revocation inside it; no record in time is `STS-OAUTH-0512` |
| PAR `request_uri` | `oauth.par` | `issueAuthorizationResponse()`, where `par.spend()` was; bound to the response | `invalid_request_uri` 400, `STS-OAUTH-0514` |
| rotated refresh token (RFC 9700 / 2.1 mode) | `oauth.refresh` | `bcp.spendRefreshToken()`, just before the mint; bound to the response | a replay: family revoked by id and by the members known, `STS-OAUTH-0516` |
| a revoked family | `oauth.refresh-family-revoked` | `bcp.revokeFamily()`, on every replay (local or claimed) | any member presented later, including one no node listed, `STS-OAUTH-0517` |
| DPoP proof `jti` | `oauth.dpop-jti` | reserved on arrival by `dpop.proofClaims()`; kept by `verifyProof()` on acceptance, released otherwise | `invalid_dpop_proof`, `STS-OAUTH-0519` |
| hosted-surface renewal | `oidc_rp.renewal` | `common/oidc_rp.js` `renewOnce()` | does not redeem; waits for the winner's tokens on the session |

**AND TWO STORES LEAVE A TOMBSTONE (#46 section 3).** `oauth2.authzCodes` and
`oauth2_bcp.refreshTokens` are declared `tombstone: true`, so a code or a refresh
token record another node deleted is not written back by a node holding an
older copy; `refreshTokens` also declares a `mergeRow` that keeps `rotated`
moving forward only, because a record written back unrotated makes the replay it
marks undetectable. `persistence/CLAUDE.md`, *Several nodes writing one row*.

A store that cannot be asked refuses in every row (`STS-OAUTH-0513`, `-0515`, `-0518`,
`-0520`; the renewal logs `STS-AUTHN-0190` and does not renew). A single-use value this
service cannot prove unspent is not one it may accept.

**The refresh family changed shape, for three reasons that are each a lost update.**
(1) A child whose parent this node had not heard of started a family of its own and split
the chain — so the family id now travels IN the refresh token (`refresh_family`, RFC 9700
mode only, inside the JWE) and `familyForIssuance()` prefers it. (2) `members.push()` on a
row written whole lost a child when two nodes added one each — so no `members` array is
written; `membersOf()` derives the list from each token's own `refreshTokens` record (one
key per jti, which two nodes cannot overwrite), and still reads an array on a restored row.
(3) A replay revoked the members one node knew, and a child minted elsewhere in the same
instant was in nobody's list — so the family is also revoked BY ID, and the claim is asked
before a refresh is spent. That member is refused at its first use rather than at the
replay; it still introspects as active until then, which is the one thing the by-id mark
does not reach.

**Why DPoP is claimed on ARRIVAL and not in `verifyProof()`.** The verifier is synchronous
and `presentedAccessToken()` has synchronous callers in three other families (the
credential endpoints, SCIM, Shared Signals) besides UserInfo; an async verifier would be a
change to every one, and a caller that forgot the `await` would be a resource server that
checks nothing. So `oauth2.js` registers `dpop.proofClaims()` with `app.use()` above its
first route — above every route that reads a proof, since nothing required before it
does — and that middleware reserves the proof's unverified `jti`. `verifyProof()` refuses a
refused reservation at the place the local replay check already sits (so every earlier
check keeps its own code, and a same-process replay keeps `STS-OAUTH-0110`) and keeps the
reservation only when it accepts: `seenJtis`' rule, that only an accepted proof is
remembered, is unchanged. **A caller of `verifyProof()` must pass `req`** for the
cross-node half; one that does not gets the local check only. **The server nonce needs
nothing**: `issuedNonces` is persisted, a nonce is not single use, the response carrying
one is held by the barrier until it commits, and the retry passes the barrier's catch-up
on whichever node it reaches.

**What is still open.** The code loser's wait is bounded: a winner whose commit takes
longer than five seconds has bought tokens the loser could not find to revoke (it is
refused all the same). The OID4VCI pre-authorized code grant in `tokenGrant()` is the
`oid4vc` family's (`oid4vc.once`), not this one. `tests/oauth_cluster_once.js` holds
all of it in process — including a control store that answers every claim "yes", under
which two concurrent redemptions of one code are both issued, and which fails six of its
assertions.
