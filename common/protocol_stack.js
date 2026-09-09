'use strict';
//
// File: protocol_stack.js
//
// ---------------------------------------------------------------------------
// THE REQUIRE ORDER, WHICH IS THE ROUTE ORDER, IN ONE PLACE.
//
// Rule 1 in the root CLAUDE.md: requiring a module registers its endpoints, so
// **the require order in this file IS the order the router matches in**. That
// sequence lived in `server.js` until 2026-09-07 and it moved here for one
// reason: it now has TWO readers.
//
// `server.js` is the front process — it loads this, then binds the sockets.
// `common/request_worker.js` is a worker — it loads THIS SAME FILE and binds
// none of them. **A second copy of the order would be a second answer to
// "which handler wins",** and the two processes would disagree about it in
// exactly the cases that are hardest to see: a route registered before a
// middleware in one and after it in the other.
//
// So there is one copy, and it is this. Every constraint on the order is
// argued where the module lives; the table in the root CLAUDE.md is the index.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE DOES NOT DO IS BIND ANYTHING.
//
// Four of these modules own listeners — the two Kerberos ones, the LDAP
// directory and the TLS endpoints — plus SPIFFE's four sockets. Requiring them
// registers their HTTP views and NOTHING ELSE; `listen()` is called by
// `server.js` and by nothing here. That separation already existed and is what
// makes a worker possible at all: a worker loads every route and owns no port,
// so N of them can run beside one front process without a single conflict.
//
// The five modules that bind are returned rather than merely required, because
// `server.js` needs the handles to start and to report them.
// ---------------------------------------------------------------------------

// Which LDAP attributes the four claim sets carry. A LIBRARY — it registers no
// route, so this line adds nothing to /admin/sts-metadata and its position in
// the route order is not a position at all. It is required HERE, ahead of the
// modules that issue, because requiring it is what fills admin_stats.js's
// attribute-resolver slot, and an empty slot means tokens issued without their
// configured attributes. admin.js requires it too, which would be enough today
// by accident; this line is what makes it true on purpose, and what keeps it
// true for a process that loads the protocol modules without the console.
require('./claim_attributes');

// The groups claim: for anybody who is a member of a group in the embedded
// directory, a claim naming those groups in every access token, ID Token and
// both SAML assertions. A LIBRARY too, required HERE for exactly the reason the
// line above is: requiring it is what fills admin_stats.js's group-resolver
// slot, and an empty slot means tokens issued without the claim with nothing
// looking wrong. It must come before the modules that issue; the directory it
// reads arrives later, through its own slot, and until then it simply reports
// that no directory is loaded.
require('./group_claims');

// The front door: GET / and the one image on it. It is first among the modules
// that register routes, and the position is a preference rather than a
// dependency — it requires nothing but the app, registers two EXACT paths that
// nothing else here could shadow, and being first is what puts the page a
// person meets first at the top of the list on /admin/sts-metadata. Before this
// module existed the root of this service was an unrouted path, so the answer
// to the one URL somebody types first was Express's `Cannot GET /`.
require('../home/home');

// The authentication service: the sign-in screen every protocol here sends a
// person to, and the session store it fills. FIRST of the modules that use it,
// because require order is route order on the /admin/sts-metadata page and the
// thing that authenticates should be listed before the protocols that lean on
// it.
require('../authn/authn');
// WS-Trust 1.0-1.4. **IT MOVED BELOW authn.js ON 2026-09-05 AND THE ORDER IS
// NOW A DEPENDENCY** where it had been no constraint at all. Issuing a token or
// an assertion here starts a tracked sign-on session — see ws-trust/CLAUDE.md
// for why an issued credential implies one — and it does that by calling
// `authn.startSession()` directly, without a screen, exactly as
// federation/federation_sp.js does and for the same reason: the caller
// presented a credential of its own (a UsernameToken) rather than being sent
// somewhere to type one. Requiring it from ABOVE authn.js would have dragged
// every /authn route to the front of the router (rule 1), which is why this
// line moved rather than a require being added where it stood.
require('../ws-trust/wstrust');
// THE USER PORTAL. **After `authn`**, whose session store every authenticated
// route on it reads — a dependency of the same kind `saml2_sso.js` and
// `consent_screen.js` have, and one-way in the same way: `authn.js` knows
// nothing about the portal. It registers its own routes under /portal, which
// nothing else here could shadow.
//
// **AND AFTER `oauth-oidc/oauth2.js` IN EFFECT SINCE 2026-09-06**, though not
// as an ordering constraint: this portal is an OpenID Connect RELYING PARTY of
// this service's own authorization server (`common/oidc_rp.js`), so it needs
// `/oauth2/authorize` and `/oauth2/token` to be REGISTERED rather than
// required — and they are, at 9, four lines above. A process that loaded this
// module without them would have a portal whose sign-in redirects to a 404.
// `oidc_rp.js` itself is a LIBRARY (rule 3): it registers nothing, the two
// callbacks are registered by the two surfaces, and it requires `tls_server`
// LAZILY inside the one function that dials the back channel — a require at
// its top would drag three /tls routes here.
require('../portal/portal');
// The consent screen. It must come AFTER authn.js and BEFORE oauth2.js, and
// both halves are dependencies rather than preferences. AFTER, because it reads
// that module's session to check that the person answering is the person the
// question was asked of, and draws with that module's stylesheet so the two
// screens a person meets seconds apart in one flow look like one service.
// BEFORE, because the authorization endpoint calls beginConsent() and takes the
// browser back afterwards — exactly the arrangement it already has with
// beginAuthentication(), and the dependency is one-way in the same way: this
// module knows nothing about OAuth beyond a `returnTo` it is handed and a
// `consent_error` it hands back.
require('../oauth-oidc/consent_screen');
require('../oauth-oidc/oauth2');
// WS-Federation's passive requestor profile. It must come AFTER authn.js and the
// order is a dependency and not a preference: it signs users in to the session
// that service owns (startSession/sessionOf), so that single sign-on works across
// the two protocols. The dependency is one-way — authn.js knows nothing about
// this module — which is what keeps it out of the cycles the split exists to
// avoid.
require('../ws-federation/wsfed');
// SAML 2.0 Web Browser SSO — the profile this service spent years documenting
// the absence of. It must come AFTER authn.js for the reason wsfed.js must, and
// it is a stronger dependency here rather than a weaker one: this module has NO
// sign-in screen of its own at all and reaches that service's through
// beginAuthentication(). It has no constraint against wsfed.js in either
// direction — the two share the session and know nothing about each other — and
// it sits here so that the two browser SSO profiles read together in the route
// order and on /admin/sts-metadata.
require('../saml/saml2_sso');
// SAML 1.1's two browser profiles, and the SAML responder behind one of them.
// TWO constraints, and the second is the interesting one. It must come AFTER
// authn.js for the same reason saml2_sso.js must — no sign-in screen of its own,
// and beginAuthentication() is how it reaches one. And it must come AFTER
// saml/saml2_sso.js, because it takes that module's slugOf(): the slug is a
// HANDLE FOR AN APPLICATION shared by both profiles and by the console, and two
// spellings of it would make /saml2/metadata/app-1a2b3c and
// /saml11/metadata/app-9f8e7d name one entry in one directory. That require is
// in the ordinary direction and closes no cycle. Nothing else passes between
// them; the two profiles share a registry and a session and know nothing else
// about each other.
require('../saml/saml11_sso');
// FEDERATION, and it is the one module here that consumes rather than issues.
// ONE constraint, and it is the strongest of the three sign-in dependencies:
// it must come AFTER authn/authn.js, because it has no sign-in screen of its
// own AND it does not go through beginAuthentication() either — a federated
// sign-in ends by calling startSession() directly, since the person has already
// authenticated somewhere else and there is no screen to show them.
//
// No constraint against the four protocol modules above it in either direction.
// They know nothing about federation and federation knows nothing about them:
// what joins the two halves is the SESSION, which is authn.js's, so a federated
// identity satisfies an OAuth 2.0 authorization request, a WS-Federation
// sign-in or a SAML AuthnRequest without any of those modules being told this
// one exists. That is the whole design and it is why this require can sit
// anywhere below line 137.
//
// It is placed HERE, after the four browser SSO profiles, so that the route
// order and /admin/sts-metadata read in the order somebody thinks about them:
// what this service ISSUES, and then what it CONSUMES.
//
// Only federation_sp.js is required. `federation.js`, `federation_map.js` and
// `federation_http.js` are libraries (rule 3) — they register nothing, so their
// position is not a position — and each is required by whoever needs it:
// admin_stats.js and authn.js reach the register directly, and ldap_server.js
// fills its directory slot at its own require time.
require('../federation/federation_sp');
require('../oid4vc/vc_offers');
require('../oid4vc/vc_did');
require('../oid4vc/vc_issuer');
require('../oid4vc/vc_verifier');
// The Kerberos KDC. Requiring it registers /KdcProxy and /krb5/principals like
// every other module here — but NOT the raw TCP/UDP listeners on port 88, which
// are started by krb5.listen() below. Binding a privileged port can fail, and a
// require that throws takes the whole service down; a route cannot.
const krb5 = require('../kerberos/krb5_kdc');
// The Kerberos-protected service. Like the KDC it registers its HTTP view at
// require time and starts its socket from listen(), for the same reason.
const krb5Service = require('../kerberos/krb5_service');
// The same acceptor over HTTP: SPNEGO. It must come AFTER krb5_service.js and
// the order is a dependency rather than a preference — it calls that module's
// accept() for every Kerberos check and adds none of its own. Unlike the two
// above it starts nothing: it is HTTP all the way down, so requiring it is the
// whole of its installation.
require('../kerberos/spnego');
// ---------------------------------------------------------------------------
// AND THE SAME HANDSHAKE AS A SIGN-IN: /authn/spnego, which turns a Kerberos
// ticket into the browser session every protocol family here reads.
//
// TWO constraints, and both are dependencies rather than preferences. It must
// come AFTER `spnego.js`, whose page shell and check table it draws with and
// whose `spnego_exchange.js` performs the negotiation; and it must come AFTER
// `authn/authn.js`, which is at #8, because it calls that module's
// `startSession()` and reads its pending records. The second is why the
// endpoint is HERE and not over there: `authn.js` is required before
// `oauth2.js`, which reads the session it owns, so a require in the other
// direction would drag the KDC's routes to the front of the router and close a
// cycle besides. What `authn.js` needs to know about this door is a path it
// declares itself and one setting they both read — no inverted hook, and its
// own header says why one would have been the wrong answer.
//
// It starts nothing, exactly as `spnego.js` starts nothing.
// ---------------------------------------------------------------------------
require('../kerberos/spnego_authn');
// The admin console. It must come AFTER oauth2.js and, like wsfed.js, the order is a
// dependency rather than a preference: its metrics page reports the browser sign-on
// sessions oauth2.js owns, read through the `sessions` map that module exports. The
// dependency is one way — oauth2.js knows nothing about the console — so it is not a
// cycle. What holds the STATE it renders is admin_stats.js, which registers no route
// and is required by app.js, so the counting is already running by the time this
// line is reached.
require('../admin-ui/admin');
// The management API: everything that console shows and everything it can
// change, at /admin-api, over JSON. It must come AFTER admin.js and the order is
// a dependency rather than a preference — it requires that module for the four
// action functions and the per-page JSON views, and calls nothing else, which is
// what makes it incapable of holding a second opinion about what a revocation
// means. Its OpenAPI document is built from its own route table (admin_api.js ->
// admin_api_spec.js), so an operation cannot be undocumented.
require('../mgmt-api/admin_api');
// 19a. THE API EXPLORER, which is a page of the CONSOLE and not of that API.
//
// It was `GET /admin-api/docs` until 2026-09-09, when that API began requiring
// an access token — and a browser navigating to a URL carries none, so the one
// page in this service written to be opened in a browser had become the one
// page a browser could not open. It is `/admin/api-explorer` now, behind the
// console's session and roles.
//
// AFTER BOTH of the modules above and for two different reasons: it requires
// `admin.js` (18) for the shell and the gate, and `admin_api.js` (19) for the
// route table its OpenAPI document is built from. Both are plain requires in
// the ordinary direction — neither of those files knows this one exists, so
// there is no cycle to close and no route to move. It is a file of its own for
// `crypto_metadata.js`'s reason: putting it in `admin.js` would mean that
// module requiring the management API, which would drag every `/admin-api`
// route ahead of the console's own.
require('../admin-ui/api_explorer');
// The TLS / mutual-TLS endpoint. Third in the family of modules whose real
// surface is a SOCKET rather than a route: it registers its plain-HTTP views
// (/tls, /tls/server-certificate, /tls/trust) at require time and starts two
// HTTPS listeners from listen() below, for the same reason the KDC and the
// directory do — a bind can fail, and a require that throws takes the whole
// service down where a route cannot.
//
// Its position used to be free. It is not any more: ldap_server.js below serves
// this module's server certificate on 636, so it requires this file — and node
// would load it here whatever this line said. Saying it explicitly is what
// keeps "the order in this file is the route order" true.
const tlsServer = require('../tls/tls_server');
// ---------------------------------------------------------------------------
// GET /admin/crypto-metadata — the console's report on what this service does
// with cryptography, for every identity service it advertises.
//
// ITS POSITION IS A DEPENDENCY AND NOT A PREFERENCE, and it is an unusual one:
// this module reads an algorithm table out of eleven other modules, and
// requiring one of them that this file has not yet loaded would REGISTER ITS
// ROUTES HERE (rule 1). Here, everything it reaches for is already loaded, so
// every one of its requires is a cache hit that registers nothing and moves
// nothing:
//
//   after ./admin-ui/admin        for the console SHELL and its gate — express
//                                 applies middleware only to routes added after
//                                 it, so this page is behind the sign-on and
//                                 the two roles by construction
//   after ./oauth-oidc/oauth2     the ID Token and UserInfo signing lists, and
//                                 dpop.js's DPoP filter over the shared table
//   after ./authn/authn           webauthn.js's COSE tables
//   after ./kerberos/krb5_kdc     the encryption type codec
//   after ./tls/tls_server        the server certificate — THE ONE THAT DECIDES
//                                 THIS LINE'S PLACE. Every other dependency is
//                                 satisfied several requires earlier; this is
//                                 the last of them, which is why the module
//                                 sits immediately below that one.
//
// It fills admin.js's setCryptoReporter() so that GET /admin-api/crypto can
// mirror the page without the management API requiring this file — a require in
// that direction would drag this page's route and tls_server's three ahead of
// the management API's own. And ./sts_metadata.js, last in this file, hands it
// the protocol family list so that the two pages' idea of what this service
// advertises is checked rather than agreed by hand.
// ---------------------------------------------------------------------------
require('../admin-ui/crypto_metadata');
// The embedded LDAPv3 directory (RFC 4511), built on the node-ldapjs submodule.
// Like the two Kerberos modules it registers its HTTP views at require time
// (/ldap, /admin/ldap/directory) and starts its TCP listener from listen() below, for
// the same reason: binding port 389 is privileged and can fail, and a require
// that throws takes the whole service down where a route cannot.
//
// It must come AFTER admin.js, and that is a dependency rather than a
// preference: it installs itself as admin_stats.js's user observer, which is how
// an entry appears under ou=users for anybody who authenticates through ANY
// protocol here. Requiring it earlier would work too — nothing authenticates
// during require — but keeping it beside the console is what makes the pairing
// visible to the next reader.
//
// It must also come after ./tls_server below, and THAT one is not optional: its
// LDAPS listener on 636 serves the certificate and key that module generates,
// so requiring it first is what makes the route order in this file the real one
// rather than a fiction node quietly corrects.
const ldapServer = require('../ldap/ldap_server');
// SCIM 2.0 (RFC 7642, 7643, 7644) — the fifteenth family, and the one whose
// whole purpose is to WRITE. It provisions into the directory above, entry for
// entry, with no store of its own: a POST /scim/v2/Users and an ldapadd write
// the same entry, so a person provisioned over SCIM appears on /admin/users,
// carries the credential-claim attributes /admin/vc selects, and lands in
// whatever group a client puts them in.
//
// It must come AFTER ./ldap_server, and that is a dependency rather than a
// preference: it requires that module for the twelve functions that make
// ou=users and ou=groups a store, and requiring it any earlier would pull every
// /ldap route into the express router at that point. It is NOT one of that
// file's five inverted hooks — there is no cycle and no route moves, which is
// rule 3e's test, and this proposal fails it both ways round, so it is a plain
// require.
//
// Unlike the four modules above it, it starts nothing: it is HTTP all the way
// down, so requiring it is the whole of its installation.
require('../scim/scim');
// SPIFFE — the sixteenth family, and the third module here whose own listeners
// are started from listen() below rather than at require time.
//
// Three server-side surfaces: the BUNDLE ENDPOINT (plain HTTPS, registered by
// requiring this), the WORKLOAD API and the SPIRE SERVER API (both gRPC, on a
// Unix socket and a TCP port each). The gRPC listeners are invisible to
// /admin/sts-metadata for the same reason the KDC's, the directory's and the
// TLS endpoint's sockets are, so they are described by hand there.
//
// It must come AFTER ./ldap_server, and it is a dependency rather than a
// preference: the SPIFFE registry's store is the directory under ou=spiffe, and
// that module fills spiffe_registry.js's setDirectory() slot at ITS require
// time. Requiring this any earlier would leave the registry with no store at
// the moment the seed entries are written.
//
// The 8443/9443/636/8081 certificate is NOT shared with this. A SPIFFE trust
// domain is its own PKI — the CA here signs identities in one trust domain and
// the TLS certificate identifies a host — and one process holding two of them
// is correct rather than wasteful. See spiffe_ca.js.
const spiffeServer = require('../spiffe/spiffe_server');
// ---------------------------------------------------------------------------
// SHARED SIGNALS — THE SEVENTEENTH FAMILY, AND THE FIRST ONE THAT TALKS BACK.
//
// Every other module above answers a request. This one AGREES A STREAM and
// then delivers a Security Event Token to somebody who asked in advance to be
// told — which is why it is the only protocol module here that makes an
// outbound request, and only the second module in the repository that does
// (`federation/federation_http.js` is the first, and `ssf/ssf_http.js` argues
// its own case rather than citing that one, because RFC 8935 push IS the
// receiver telling the transmitter where to post).
//
// **AFTER `admin-ui/admin.js`, and that is the constraint that decides the
// line.** It fills that module's eighth slot — the reader and the four actions
// behind `/admin/ssf` and `/admin-api/ssf` — and it requires it for the page
// shell and the gate, exactly as `sts_metadata.js` and `crypto_metadata.js`
// do. Rule 3e's test was applied both ways round: a require from `admin.js` to
// here CLOSES A CYCLE, and a require from `mgmt-api/admin_api.js` to here
// would MOVE ROUTES — every /ssf endpoint and the well-known document ahead of
// the management API's own and of ldap, scim and spiffe. So a slot, not an
// indirection added by analogy.
//
// It starts nothing: it is HTTP all the way down, so requiring it is the whole
// of its installation. It registers no listener and holds no socket, and its
// streams are in memory and die with the process — which persistence/CLAUDE.md
// decides: the signing key is regenerated on every start, so a restored queue
// would be tokens nothing can verify.
require('../ssf/ssf');
// ---------------------------------------------------------------------------
// THE PROTOCOL-INDEPENDENT LOGOUT — SECOND TO LAST, AND THE POSITION IS THE
// WHOLE OF ITS ARGUMENT.
//
// `GET|POST /logout` lists everything this service is still holding for one
// identity — across the session store, the token registry, the authorization
// codes, the pre-authorized codes, the directory's bound connections and the
// Kerberos principal database — and ends what is asked for. So it READS NINE
// MODULES, and it must come after every one of them.
//
// It is a plain require of each rather than nine inverted hooks, and rule 3e's
// test is why: a slot is what you reach for when a require would close a cycle
// or move a route, and neither applies here. Every module it requires has
// already been loaded by the lines above, so each require is a cache hit that
// registers nothing and moves nothing; and nothing in this service requires
// that module back, so there is no cycle to close.
//
// It is NOT last. `sts_metadata.js` is, for everybody, because it reads the
// router to list what everything else registered — and a logout endpoint
// missing from that list would be the exact drift that page exists to catch.
// ---------------------------------------------------------------------------
// 23c. XACML 3.0 — the PDP, the policy repository and the embedded PEP.
//
// AFTER `ldap/ldap_server` (21), which fills two slots it owns: the policy
// repository's directory functions and the PIP's entry lookup. The store IS
// ou=policies, so this module has nothing to load and nothing to hold.
//
// It does NOT go through a slot on admin.js, because it has no console page
// yet — that is phase three, and when it lands the require stays here and a
// slot appears, for the reason SSF's does at 23b: a require from
// mgmt-api/admin_api.js (19) to this module would drag every /xacml route
// ahead of the management API's own.
//
// It starts nothing and holds no socket.
require('../xacml/xacml');

require('../logout/logout');
require('../sts_metadata');

module.exports = {
  krb5: krb5,
  krb5Service: krb5Service,
  tlsServer: tlsServer,
  ldapServer: ldapServer,
  spiffeServer: spiffeServer
};
