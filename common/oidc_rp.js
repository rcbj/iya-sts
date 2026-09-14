'use strict';
//
// File: oidc_rp.js
//
// ===========================================================================
// THIS SERVICE'S OWN HOSTED SURFACES, AS RELYING PARTIES OF ITS OWN
// AUTHORIZATION SERVER (2026-09-06).
//
// `/admin` and `/portal` used to authenticate by REDIRECTING STRAIGHT TO THE
// SIGN-IN SCREEN: `authn.beginAuthentication()` stashed the interrupted
// request, the screen took a name, and the session it minted was the one those
// surfaces then read. That worked, and what was wrong with it is that **this
// service's own two applications were the only applications in the process that
// did not use the protocol this service exists to demonstrate.** An OpenID
// Connect relying party does not read the provider's session store — it has no
// access to one. It sends the person to the authorization endpoint, gets a code
// back at a registered redirect URI, redeems it with a client credential,
// verifies an ID Token and establishes a session of its OWN.
//
// So they do that now, and this module is the client.
//
//   GET /admin                                     no console session
//     -> 302 /oauth2/authorize?client_id=sts-admin-console
//                             &redirect_uri=<base>/admin/callback
//                             &response_type=code&scope=openid profile email
//                             &state=…&nonce=…&code_challenge=…&method=S256
//        the AS finds no SIGN-ON session and redirects to /authn/login;
//        the person signs in; the AS comes back to its own /oauth2/authorize
//     -> 302 <base>/admin/callback?code=…&state=…
//        POST /oauth2/token   Authorization: Basic <client_id:secret>
//                             grant_type=authorization_code&code_verifier=…
//        verify the ID Token against /oauth2/jwks
//     -> 302 wherever the person was going
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3): IT REGISTERS NOTHING.
//
// The two callback routes are registered by the two surfaces —
// `/admin/callback` in `admin-ui/admin.js` and `/portal/callback` in
// `portal/portal.js` — and that is deliberate rather than tidy. A route
// registered HERE would land wherever this file was first required, which is a
// position decided by whoever edits an import list; a route registered there
// lands where that surface's other routes are, which is what
// `/admin/sts-metadata` walks and what the console's gate applies to. It also
// keeps the one exemption that gate needs (its own callback) in the file that
// has the gate in it.
//
// It requires `authn.js`, which is loaded at 8 — long before either surface —
// so requiring it here is a cache hit and cannot move a route.
//
// **AND IT REQUIRES `tls/tls_server.js` LAZILY, INSIDE THE ONE FUNCTION THAT
// NEEDS IT.** That module is at 20 and registers three routes; a require at the
// top of this file would drag them ahead of `/admin`'s own, of `/admin-api`'s,
// and of ldap, scim and spiffe (rule 1). The precedent is `xacml_admin.js`,
// which requires `xacml.js` back the same way and for the same reason. By the
// time anybody signs in, every module is loaded and the require is a cache hit.
//
// ---------------------------------------------------------------------------
// THE BACK CHANNEL IS A REAL HTTP REQUEST, AND IT IS THE FOURTH OUTBOUND ONE.
//
// This repository has three (federation's, SSF's push, and XACML's nudge) and
// each argues its own case rather than citing the others. This is the fourth
// and it is the narrowest of the four, because of who it dials: **itself, at a
// loopback address it computes, on a port it is listening on.** Nothing about
// it is influenced by a caller. `DIALLABLE` in `federation_http.js` exists to
// stop a URL from a request becoming a URL this service fetches; here there is
// no URL at all — the address is `helpers.loopbackHost()` and `helpers.PORT`,
// and the paths are this service's own, three constants below.
//
// **IT IS AN HTTP REQUEST RATHER THAN A FUNCTION CALL ON PURPOSE.** Redeeming
// the code in process would be a client that skips client authentication, skips
// PKCE verification, writes no audit row at the token endpoint, mints nothing
// on `/admin/tokens` and proves nothing about the flow. The whole value of
// moving these surfaces onto the code flow is that the flow is REALLY RUN, and
// a back channel that was a function call would be the half of it that only
// looked run.
//
// Four things bound it, and each is `federation_http.js`'s rule made again:
//
//   * **THE HOST HEADER IS THE BROWSER'S, THE ADDRESS IS LOOPBACK.** The
//     connection goes to the loopback address of the interface this service
//     LISTENS on — `helpers.loopbackHost()`, which is 127.0.0.1 for a wildcard
//     bind, ::1 for an IPv6 one, and the address itself where `global.host`
//     names one — because that is reachable from inside this process whatever
//     DNS says outside it. It was the literal `127.0.0.1` until 2026-09-12,
//     which reaches nothing when the listener is bound to one interface
//     address or to IPv6 only. The `Host` header carries the name
//     the BROWSER used, because `issuerOf()` builds the `iss` claim from the
//     request when `oauth2.issuer` is not pinned. Dial loopback and say
//     loopback, and the ID Token comes back issued by `https://127.0.0.1:8081`
//     — which is not the issuer the authorization endpoint advertised to the
//     browser, so the RP would have to accept an issuer it should refuse.
//   * **TLS IS VERIFIED AGAINST THIS SERVICE'S OWN CERTIFICATE**, passed as the
//     trust anchor. The certificate is self-signed and generated at start, so
//     it IS its own root; what is skipped is the HOSTNAME check, because the
//     certificate names the service and the connection names the loopback
//     interface. Skipping the hostname while pinning the key is the stronger
//     half of the two — it is the same argument `federation/CLAUDE.md` makes
//     about a pinned partner certificate.
//   * **NO REDIRECT IS FOLLOWED.** A 302 from the token endpoint would hand the
//     Basic credential in the `Authorization` header to whatever `Location`
//     said. This service's token endpoint does not redirect; the rule is here
//     because the day it does is the day nobody remembers this.
//   * **THE BODY IS CAPPED AND THE REQUEST IS TIMED OUT**, because a browser is
//     waiting on the far end of it.
//
// ---------------------------------------------------------------------------
// WHAT IT DELIBERATELY DOES NOT DO.
//
//   * **No discovery document is fetched.** An RP normally learns the endpoints
//     from `/.well-known/openid-configuration`, and this one already knows
//     them: it is inside the service that serves them. Fetching it would mean
//     reading back three paths this file could not be wrong about, and then
//     REBASING every absolute URL in it onto the loopback address — because
//     that document advertises the address a BROWSER uses. That is more moving
//     parts for no check.
//   * **It presents the access token to nobody.** These surfaces read the
//     directory directly; there is no resource server to present one to.
//
// **TWO BULLETS HERE SAID "NO REFRESH TOKEN IS KEPT" AND "THE ACCESS TOKEN IS
// DISCARDED TOO" UNTIL 2026-09-12, AND THE FIRST WAS THE DEFECT.** Its argument
// was that a refresh token would be this service refreshing a session nobody is
// using, kept in a store that is the wrong one. What it cost is the thing a
// relying party exists to avoid: an operator working in the console was sent
// back through the sign-in screen, off the page they were on, the moment the
// hour ran out. Both halves of the argument are answered in section 4 below —
// a renewal happens only on a request somebody made, so nothing is refreshed
// for nobody, and the tokens live on the relying-party session itself, which
// is the store the session already is rather than a second one.
// ===========================================================================

const https = require('https');
const http = require('http');
const nodeCrypto = require('crypto');

const helpers = require('./helpers');
const { log, PORT, baseUrlOf } = helpers;
const config = require('./config');
// Whether a redirect URI a request's address produced may be written onto one
// of these two entries — see `ensureRedirectUri()`. A LEAF (rule 3): it
// requires only `config`.
const mode = require('./mode');
const realms = require('./realms');
const applications = require('./applications');
const stsCrypto = require('./crypto');
const audit = require('./audit');
const authn = require('../authn/authn');
// The error codes (common/error_codes.js). Every refusal below answers
// `{ ok: false, why }` to the console or the portal, which draws the page — so
// the code rides on that answer non-enumerably (`codeOf()` reads it) AND is
// marked on the response where this file holds one, so the call-log row
// carries the specific reason whichever of the two callers forgets.
const errorCodes = require('./error_codes');

function coded(code, answer, res) {
  log.debug("Entering coded().");
  if (res) {
    errorCodes.mark(res, code);
  }
  log.debug("Leaving coded().");
  return errorCodes.mark(answer, code);
}

// ---------------------------------------------------------------------------
// THE TWO SURFACES.
//
// `clientId` is the identifier of the entry `applications.js` seeds under
// `ou=applications` — this file does not create it and must not: that container
// IS the registry, and a client this module invented would be a second answer
// to what a client is. If the entry is gone, the flow REFUSES and says so,
// which is what makes "an operator who deleted one of these meant it" a
// sentence with an observable consequence.
//
// `cookie` is the surface's own session cookie and is never `authn.js`'s. Two
// surfaces, two cookies: signing in to the portal does not sign anybody in to
// the console, which is what makes them two applications rather than one
// wearing two paths.
//
// **A SURFACE HAS TWO REALMS AND THEY ARE NOT THE SAME QUESTION (2026-09-11).**
// It had one — `realm`, meaning both — and that one answer is what stopped
// these two surfaces from sharing a sign-on session anywhere but the default
// realm.
//
// `flowRealm` is where the AUTHORIZATION CODE FLOW runs: which
// `/oauth2/authorize` the browser is sent to, which `/oauth2/token` the code is
// redeemed at, and therefore **which realm's sign-on session the authorization
// endpoint is able to answer out of**. It is `ambient` for both, because that
// is the whole of single sign-on between them: a person who signed in at
// `/realm/acme/portal` and then opens `/realm/acme/admin` is answered out of
// the session they already have, and the sign-in screen is never reached. The
// console's used to be `default` wherever it was reached, which meant the two
// surfaces authenticated against two different partitions of `authn.js`'s
// session store and neither endpoint could see the other's — two sign-ins, in
// both directions, for one person in one browser.
//
// `sessionRealm` is where the surface's OWN session lives, and the console's is
// still `default` whatever realm it was reached in. That is what `admin.js`
// calls "sign in once, in one realm, read every realm": one console session,
// found by the gate from every realm, with the ROLE checked against the default
// realm's `ou=groups` — so who may administer this service is still decided in
// one place and a realm nobody could create cannot make anybody an
// administrator. Moving it to the ambient realm would have bought cross-surface
// single sign-on by taking the realm switcher away.
//
// The consequence is the one thing worth knowing before reading further: **a
// console session's PARENT lives in a different realm's partition from the
// session itself**, whenever the console is reached in a realm. `authn.js`
// carries `derivedFromRealm` for exactly that, and the cascade that ends a
// derived session with its sign-on session reaches across.
// ---------------------------------------------------------------------------
const SURFACES = {
  admin: {
    id: 'admin',
    clientId: 'sts-admin-console',
    label: 'Admin console',
    callbackPath: '/admin/callback',
    cookie: 'sts_admin',
    flowRealm: 'ambient',
    sessionRealm: 'default',
    scopes: ['openid', 'profile', 'email']
  },
  portal: {
    id: 'portal',
    clientId: 'sts-user-portal',
    label: 'User portal',
    callbackPath: '/portal/callback',
    cookie: 'sts_portal',
    flowRealm: 'ambient',
    sessionRealm: 'ambient',
    scopes: ['openid', 'profile', 'email']
  },
  // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13), and the first surface that is
  // NOT ON THIS SERVICE'S ORIGIN: it is served by `debugger/debugger_server.js`
  // on a listener of its own. Two things follow and both are options rather
  // than fields, because they are addresses a REQUEST decides:
  //
  //   * the redirect URI is on the debugger's origin and the authorization
  //     endpoint is on the main port's, so `beginSignIn()` and
  //     `handleCallback()` take `callbackBase` and `authorizationBase` where
  //     the other two surfaces use one base for both;
  //   * the back channel's Host header is the AUTHORIZATION base's, because
  //     that is the issuer the browser was sent to.
  //
  // Both realms are the default realm's: the listener has no realm prefix, and
  // the roster that decides who may use the debugger is the default realm's.
  //
  // THE FOURTH SCOPE IS THE DEBUGGER API'S PERMISSION, written out here for
  // the reason `applications.js` writes it out — this library is read by every
  // hosted surface and must not depend on a feature directory — and compared
  // with `debugger/debugger_access.js` by `tests/debugger_access.js`. The
  // authorization server takes it off the grant for anybody who is not a
  // console administrator, and the debugger's gate reports that.
  debugger: {
    id: 'debugger',
    clientId: 'sts-debugger-ui',
    label: 'Protocol debugger',
    callbackPath: '/_sts/callback',
    cookie: 'sts_debugger',
    flowRealm: 'default',
    sessionRealm: 'default',
    scopes: ['openid', 'profile', 'email', 'urn:sts:debugger-api:debugger']
  }
};

// The paths this client knows because it is inside the server that serves them.
// See "no discovery document is fetched" above.
const AUTHORIZE_PATH = '/oauth2/authorize';
const TOKEN_PATH = '/oauth2/token';
const JWKS_PATH = '/oauth2/jwks';

// A flow in progress, per realm, keyed by `state`. `federation_sp.js`'s
// decision 3 exactly: the partner — here, the browser — carries an opaque
// handle and every fact about the request stays on this side. The `returnTo` in
// particular must never ride in a parameter, because a return address a caller
// can write is an open redirect operated by whoever can forge a state.
const flows = realms.map({ persist: 'oidc_rp.flows' });
// In flight at once, per realm rather than per process, for the reason
// `federation_sp.js` gives about a shared cap: one realm's flood would
// otherwise evict another realm's in-flight sign-ins. `oidcRp.maxFlows` since
// 2026-09-12; this is its default.
const MAX_FLOWS = 200;
// How long somebody has to get through the sign-in screen. It is the
// pending-authentication record's own lifetime over in `authn.js`, and the two
// are deliberately the same: a flow that outlived the screen it is waiting on
// would be a state this service accepts and an authorization endpoint that no
// longer has anything to answer with.
//
// **THEY WERE "THE SAME" AS TWO LITERALS UNTIL 2026-09-12**, which is the one
// way that sentence can quietly stop being true. Both read `authn.pendingTtlS`
// now, so they cannot differ.
const FLOW_TTL_MS = 10 * 60 * 1000;
// The back channel's bounds. Both are `federation_http.js`'s and are set to the
// same values for the same reasons. The timeout is `oidcRp.backChannelTimeoutS`
// since 2026-09-12; the body cap is not a deployment decision.
const BACK_CHANNEL_TIMEOUT_MS = 10 * 1000;
const MAX_BODY_BYTES = 256 * 1024;
// How many redirect URIs the two entries may carry before learning stops —
// `oidcRp.maxRedirectUris`. See `ensureRedirectUri()`.
const MAX_REDIRECT_URIS = 20;

// A positive-integer setting, or its default where the store holds none.
function positiveSetting(key, fallback) {
  log.debug("Entering positiveSetting().");
  const n = Number(config.value(key));
  log.debug("Leaving positiveSetting().");
  return isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function maxFlows() {
  log.debug("Entering maxFlows().");
  log.debug("Leaving maxFlows().");
  return positiveSetting('oidcRp.maxFlows', MAX_FLOWS);
}

function flowTtlMs() {
  log.debug("Entering flowTtlMs().");
  log.debug("Leaving flowTtlMs().");
  return positiveSetting('authn.pendingTtlS', FLOW_TTL_MS / 1000) * 1000;
}

function backChannelTimeoutMs() {
  log.debug("Entering backChannelTimeoutMs().");
  log.debug("Leaving backChannelTimeoutMs().");
  return positiveSetting('oidcRp.backChannelTimeoutS',
                         BACK_CHANNEL_TIMEOUT_MS / 1000) * 1000;
}

function maxRedirectUris() {
  log.debug("Entering maxRedirectUris().");
  log.debug("Leaving maxRedirectUris().");
  return positiveSetting('oidcRp.maxRedirectUris', MAX_REDIRECT_URIS);
}

// ---------------------------------------------------------------------------
// The surface, by id. A caller naming one that does not exist is a bug in this
// repository rather than anything a request can cause, so it throws rather than
// answering null: a null here would produce a sign-in that redirects to
// `undefined`.
// ---------------------------------------------------------------------------
function surfaceOf(id) {
  log.debug("Entering surfaceOf().");
  const surface = SURFACES[String(id)];
  if (!surface) {
    throw new Error('oidc_rp: there is no surface called "' + id + '". The ' +
                    'surfaces are ' + Object.keys(SURFACES).join(', ') + '.');
  }
  log.debug("Leaving surfaceOf().");
  return surface;
}

// Run `fn` in the realm this surface's CODE FLOW belongs to — the authorization
// request, the token request, the JWKS fetch and the flow record that joins
// them. Both surfaces answer `ambient` today; the branch stays because the
// field is what makes the decision readable, and a surface added later may want
// the other answer.
function inFlowRealm(surface, fn) {
  log.debug("Entering inFlowRealm().");
  if (surface.flowRealm === 'default') {
    log.debug("Leaving inFlowRealm().");
    return realms.run(realms.DEFAULT_REALM, fn);
  }
  log.debug("Leaving inFlowRealm().");
  return fn();
}

// Run `fn` in the realm this surface's OWN SESSION belongs to. The console's is
// always the default realm, so that one console session is found by the gate
// from every realm; the portal's is the realm it was reached in, because a
// person in `acme` is a different person from the one in the default realm.
function inSessionRealm(surface, fn) {
  log.debug("Entering inSessionRealm().");
  if (surface.sessionRealm === 'default') {
    log.debug("Leaving inSessionRealm().");
    return realms.run(realms.DEFAULT_REALM, fn);
  }
  log.debug("Leaving inSessionRealm().");
  return fn();
}

// The id of that realm, for the readers that take one rather than running in
// it.
function sessionRealmIdOf(surface) {
  log.debug("Entering sessionRealmIdOf().");
  log.debug("Leaving sessionRealmIdOf().");
  return surface.sessionRealm === 'default' ? realms.DEFAULT_ID :
         realms.currentId();
}

// ---------------------------------------------------------------------------
// THE ADDRESSES.
//
// `publicBaseOf()` is what the BROWSER is sent to and what goes in the redirect
// URI. `loopbackOrigin()` is where this process dials itself. They are
// different strings on purpose and the difference is the whole of the back
// channel's design — see the header.
// ---------------------------------------------------------------------------
function publicBaseOf(req) {
  log.debug("Entering publicBaseOf().");
  log.debug("Leaving publicBaseOf().");
  return baseUrlOf(req);
}

function loopbackOrigin() {
  log.debug("Entering loopbackOrigin().");
  const scheme = config.value('global.https') ? 'https' : 'http';
  log.debug("Leaving loopbackOrigin().");
  // An ADDRESS rather than `localhost`, which resolves to ::1 first on some
  // hosts while this service binds 0.0.0.0 — a connection refused on a name
  // that pings, which is among the least obvious failures available. Which
  // address is `helpers.loopbackHost()`'s answer about the interface this
  // service is bound to; `hostForUrl()` brackets it when it is IPv6.
  return scheme + '://' + helpers.hostForUrl(helpers.loopbackHost()) + ':' +
         PORT;
}

// The Host header the loopback request carries: the authority the browser used,
// so that `issuerOf()` builds the issuer the browser was told about. It is
// taken from the public base rather than from `req.headers.host` directly
// because the public base has already been through `forwardedFrom()`, which is
// where `global.trustProxy` is honoured.
function hostHeaderFrom(publicBase) {
  log.debug("Entering hostHeaderFrom().");
  log.debug("Leaving hostHeaderFrom().");
  return String(publicBase).replace(/^https?:\/\//i, '').split('/')[0];
}

// ---------------------------------------------------------------------------
// THE CLIENT'S OWN REGISTRATION, READ FROM THE REGISTRY AT THE MOMENT IT IS
// USED.
//
// Not cached, and that is the same rule `/admin/xacml`'s repository reads and
// `federation.js`'s register reads: there are four doors onto this entry — the
// console, the management API, an `ldapmodify` and RFC 7591's
// `PUT /oauth2/register/{id}` — and a copy held here would be the one that is
// wrong exactly when somebody has just edited it.
// ---------------------------------------------------------------------------
// The members are RFC 7591's own spellings — `client_secret`, `redirect_uris`,
// `token_endpoint_auth_method` — because that is what `clientConfigOf()`
// answers with: the registry speaks the registration document's vocabulary and
// this client reads it rather than a camelCase copy of it.
function clientOf(surface) {
  log.debug('Entering clientOf(). clientId=' + surface.clientId);
  const entry = applications.clientConfigOf(surface.clientId);
  if (!entry || !entry.registered) {
    log.debug('Leaving clientOf(). It is not registered.');
    return coded('STS-AUTHN-0112', { ok: false,
             why: 'the application "' + surface.clientId + '" is not in this ' +
                  'realm\'s registry. It is seeded at startup ' +
                  '(applications.seedInternal) and something has deleted it, ' +
                  'or seeding is off. Recreate it on /admin/applications, or ' +
                  'restart this service.' });
  }
  if (!entry.client_secret) {
    log.debug('Leaving clientOf(). It has no secret.');
    return coded('STS-AUTHN-0113', { ok: false,
             why: 'the application "' + surface.clientId + '" carries no ' +
                  'oauthClientSecret, so this surface cannot authenticate at ' +
                  'the token endpoint. The secret is minted at startup; an ' +
                  'entry without one has had it removed.' });
  }
  log.debug('Leaving clientOf(). Registered.');
  return { ok: true, client: entry };
}

// ---------------------------------------------------------------------------
// THE REDIRECT URI THE ENTRY LEARNS — IN DEVELOPMENT, FROM AN ADDRESS NOBODY
// PINNED.
//
// The seeded entry carries a callback built before any request exists. The
// BROWSER reaches this service at whatever address it was given — a container
// name, a proxy's hostname, an IP — and RFC 9700 mode matches `redirect_uri`
// by exact string, so the address actually in use has to be ON the entry or
// the first sign-in in that mode is refused by this service against itself.
//
// So in DEVELOPMENT the entry LEARNS it: the first flow through a given base
// adds that base's callback to `oauthRedirectUri`, which is multi-valued
// precisely so a client can have several. It is added and never replaced — a
// deployment reached at two names has two, both legitimate — and it is written
// through `applications.updateApplication()` like every other change to an
// entry, so it is audited and an operator can take it off again.
//
// ---------------------------------------------------------------------------
// **THIS COMMENT SAID LEARNING WAS "NOT A URL FROM A REQUEST BEING TRUSTED",
// AND IT WAS (corrected 2026-09-12).** It argued that a `Host` header a caller
// invented reaches `baseUrlOf()` only when `global.trustProxy` is on. That is
// false: `helpers.forwardedFrom()` reads the forwarded headers only with that
// setting on and reads the request's own `Host` header ALWAYS — so an
// anonymous `GET /admin` carrying `Host: evil.example` wrote
// `https://evil.example/admin/callback` PERMANENTLY onto `sts-admin-console`,
// with nothing typed and nobody signed in. A registered redirect URI is the
// thing an authorization server hands a code to; planting one is the first
// half of stealing the console's.
//
// **THREE ANSWERS NOW, AND THE MODE ASKS `acceptsUnregisteredAddresses()`**,
// which is the question exactly — may a response go to an address the request
// named and no registration did:
//
//   * `global.publicBaseUrl` SET → the base is pinned, whatever Host a request
//     carried, and NOTHING IS LEARNT. The callback is the pinned one; an entry
//     that does not carry it is used anyway in development and refused in
//     product, where the entry is a statement about the deployment.
//   * not set, DEVELOPMENT → learnt as before, up to `oidcRp.maxRedirectUris`
//     values on the entry. The cap is what keeps a service reached under many
//     names — or asked with many invented Host headers — from growing an entry
//     without bound; past it the flow still runs and nothing is written.
//   * not set, PRODUCT → nothing is written, and a flow at an address the entry
//     does not carry is REFUSED before a browser is sent anywhere, with a
//     sentence naming `global.publicBaseUrl` and the entry.
//
// It answers `{ ok, why }` and `beginSignIn()` refuses on `ok: false`. A write
// the registry refuses is still only a warning, as it always was.
// ---------------------------------------------------------------------------
function ensureRedirectUri(surface, client, uri) {
  log.debug('Entering ensureRedirectUri(). uri=' + uri);
  const held = [].concat(client.redirect_uris || []);
  if (held.indexOf(uri) >= 0) {
    log.debug('Leaving ensureRedirectUri(). Already registered.');
    return { ok: true, learnt: false };
  }
  const pinned = !!helpers.pinnedBaseUrl();
  // -------------------------------------------------------------------------
  // AN ADDRESS DEVELOPMENT LEARNT IS NOT A REGISTERED ONE (2026-09-12).
  // `client.redirect_uris` comes from `applications.clientConfigOf()`, which
  // asks `returnAddressesOf()` — so in product a callback this function taught
  // the entry while the realm was in development is not in `held` above, it is
  // in `unconfirmed_redirect_uris`, still marked OBSERVED. It is refused like
  // any unregistered address, with a sentence that says it IS on the entry and
  // how to confirm it rather than one sending the operator to add a value they
  // can already see there.
  // -------------------------------------------------------------------------
  if (!mode.acceptsUnregisteredAddresses() &&
      [].concat(client.unconfirmed_redirect_uris || []).indexOf(uri) >= 0) {
    const why = uri + ' is on the oauthRedirectUri of "' + surface.clientId +
                '", but this service LEARNT it from a request while the ' +
                'realm was in development mode and nobody has confirmed it, ' +
                'so in product mode it is not a registered redirect URI. ' +
                'Confirm it on that application\'s page under ' +
                '/admin/applications, or with POST ' +
                '/admin-api/applications/confirm-address, if people really ' +
                'reach this service at that address.';
    log.warn('oidc_rp: the ' + surface.label + ' refused to start a sign-in. ' +
             why);
    log.debug('Leaving ensureRedirectUri(). Refused: still marked observed.');
    return coded('STS-REG-0049', { ok: false, why: why });
  }
  if (!mode.acceptsUnregisteredAddresses()) {
    const why = 'this service is being reached at an address that is not a ' +
                'redirect URI of "' + surface.clientId + '" (' + uri + '), ' +
                'and in product mode that entry is not taught new addresses ' +
                'by the requests that arrive at them — an invented Host ' +
                'header would otherwise plant a callback on this service\'s ' +
                'own client. ' +
                (pinned
                  ? 'global.publicBaseUrl is set, so add ' + uri + ' to that ' +
                    'entry\'s oauthRedirectUri on /admin/applications or ' +
                    'through POST /admin-api/applications/add.'
                  : 'Set global.publicBaseUrl to the address people reach ' +
                    'this service at, and register ' +
                    'its ' + surface.callbackPath +
                    ' on that entry\'s oauthRedirectUri.');
    log.warn('oidc_rp: the ' + surface.label + ' refused to start a sign-in. ' +
             why);
    log.debug('Leaving ensureRedirectUri(). Refused in product mode.');
    return coded('STS-AUTHN-0114', { ok: false, why: why });
  }
  if (pinned) {
    log.info('oidc_rp: "' + surface.clientId + '" does not carry the pinned ' +
             'callback ' + uri + '. It is used without being written, ' +
             'because global.publicBaseUrl is set and a pinned address is ' +
             'never learnt; register it on the entry if oauth2.rfc9700 is ' +
             'on, where a redirect URI is matched by exact string.');
    log.debug('Leaving ensureRedirectUri(). Pinned; not learnt.');
    return { ok: true, learnt: false };
  }
  const cap = maxRedirectUris();
  if (held.length >= cap) {
    log.warn('oidc_rp: "' + surface.clientId + '" already carries ' +
             held.length + ' redirect URI(s), the most ' +
             'oidcRp.maxRedirectUris allows ' +
             '(' + cap + '), so ' + uri + ' was NOT added. The ' +
             'sign-in goes ahead; it will be refused only where ' +
             'oauth2.rfc9700 matches redirect URIs by exact string. Set ' +
             'global.publicBaseUrl rather than raising the cap.');
    log.debug('Leaving ensureRedirectUri(). At the cap.');
    return { ok: true, learnt: false, capped: true };
  }
  // -------------------------------------------------------------------------
  // **THIS CALL NEVER WORKED UNTIL 2026-09-12, AND THE LOG SAID "no reason
  // given".** It passed ONE object — `{ application, action, attribute, … }` —
  // to a function whose signature is `(identifier, change)` with the verb in
  // `change.mode`, so the registry looked up an application called
  // "[object Object]", refused, and this function read `answer.error` where
  // the refusal is `answer.errors`. So the entry had never learnt anything:
  // the documented behaviour above, and the self-refusal in RFC 9700 mode it
  // exists to prevent, were both a comment. Found by the test written for the
  // Host-header finding, which asserted a learnt address and got none.
  // -------------------------------------------------------------------------
  const answer = applications.updateApplication(surface.clientId, {
    attribute: 'oauthRedirectUri',
    mode: 'add',
    value: uri,
    // A SIGHTING WEARING AN UPDATE'S SHAPE (2026-09-12): the address came off
    // a request's Host header, so it is marked OBSERVED on the entry and a
    // realm later switched to product does not believe it until somebody
    // confirms it. Without the flag this call would be an operator's explicit
    // registration, which is exactly what it is not.
    observed: true,
    actor: 'the ' + surface.label
  });
  if (!answer || answer.ok === false) {
    log.warn(errorCodes.tag('STS-AUTHN-0115') +
             'oidc_rp: ' + uri + ' could not be added to "' + surface.clientId +
             '" (' + ((answer && (answer.errors || []).join(' ')) ||
                      'no reason given') + '). The ' +
             'sign-in will still work unless oauth2.rfc9700 is on, where the ' +
             'redirect URI is matched by exact string.');
    log.debug('Leaving ensureRedirectUri(). The write was refused.');
    return { ok: true, learnt: false };
  }
  log.info('oidc_rp: "' + surface.clientId + '" learnt the redirect URI ' +
           uri +
           '. This service is being reached at an address the seeded entry ' +
           'did not name, which is the ordinary case behind a proxy or in a ' +
           'container. It is ADDED rather than replacing what was there. ' +
           'Development mode only; set global.publicBaseUrl to stop it.');
  log.debug('Leaving ensureRedirectUri(). Added.');
  return { ok: true, learnt: true };
}

// ---------------------------------------------------------------------------
// PKCE. RFC 7636, S256, always — there is no setting to turn it off, which is
// `federation_sp.js`'s position on the same question: the one thing worse than
// not sending PKCE is a flag that stops.
// ---------------------------------------------------------------------------
function pkcePair() {
  log.debug("Entering pkcePair().");
  const verifier = nodeCrypto.randomBytes(32).toString('base64url');
  const challenge = nodeCrypto.createHash('sha256')
                              .update(verifier)
                              .digest('base64url');
  log.debug("Leaving pkcePair().");
  return { verifier: verifier, challenge: challenge };
}

// ---------------------------------------------------------------------------
// WHERE THE BROWSER GOES AFTERWARDS, checked the way `beginAuthentication()`
// checks its own AND stored server-side. Both, because they fail differently:
// the check catches a caller's bug and the storage catches an attacker.
// ---------------------------------------------------------------------------
function safeReturnTo(value, fallback) {
  log.debug("Entering safeReturnTo().");
  const wanted = String(value || '');
  // A single-slash-rooted path with no whitespace and no scheme. `//host` is
  // refused rather than corrected, because it is the shape an open redirect
  // takes and correcting it would teach a caller that it works.
  if (/^\/(?!\/)[^\s]*$/.test(wanted)) {
    log.debug("Leaving safeReturnTo().");
    return wanted;
  }
  log.debug("Leaving safeReturnTo().");
  return fallback;
}

// ---------------------------------------------------------------------------
// AND IT COMES BACK INTO THE REALM IT LEFT FROM (2026-09-11).
//
// A `Location` header is not markup, so `app.js`'s HTML rewrite — which is what
// carries the console's several hundred hand-written links into a realm — never
// sees it. Two callers pass a return address and they were paying that
// differently by accident: the console passes `req.originalUrl`, which still
// carries the prefix, and the portal passes the CONSTANT `/portal`. So a person
// signing in at `/realm/acme/portal` completed the flow in acme, was handed a
// session in acme, and was then redirected to the DEFAULT realm's portal —
// which correctly has no session for them, and asks them to sign in again. The
// symptom is a sign-in that works and then immediately asks again, with nothing
// in the flow having failed.
//
// It is fixed HERE rather than at the seven `requireSignIn()` call sites,
// because a prefix somebody has to remember to add is a prefix that will be
// missing from the eighth. It is IDEMPOTENT for the same reason — the console's
// address already carries the prefix, and a caller should not have to know
// which kind it is holding.
//
// The default realm's prefix is empty, so this is inert there: the bytes of
// every redirect in a service with no realms defined are untouched.
// ---------------------------------------------------------------------------
function inThisRealm(path) {
  log.debug("Entering inThisRealm().");
  const prefix = realms.currentPrefix();
  if (!prefix) {
    log.debug("Leaving inThisRealm().");
    return path;
  }
  if (path === prefix || path.indexOf(prefix + '/') === 0) {
    log.debug("Leaving inThisRealm().");
    return path;
  }
  log.debug("Leaving inThisRealm().");
  return prefix + path;
}

// ---------------------------------------------------------------------------
// THE BACK CHANNEL.
//
// One function for both calls it makes, because they differ only in the method
// and the body. Everything the header promises is here.
// ---------------------------------------------------------------------------
function backChannel(options) {
  log.debug('Entering backChannel(). ' + options.method + ' ' + options.path);
  log.debug("Leaving backChannel().");
  return new Promise(function (resolve) {
    const useHttps = config.value('global.https');
    // THE LAZY REQUIRE. See the header: at the top of this file it would move
    // three routes; here every module is loaded and it is a cache hit.
    let anchor = null;
    if (useHttps) {
      try {
        // **THE ANCHOR AND NOT THE CERTIFICATE.** Since 2026-09-11 this
        // listener's certificate is a LEAF of this service's own Root, so
        // pinning it puts a certified certificate in a truststore and no
        // path terminates there — `unable to get local issuer certificate`,
        // reported by the console as *Signing in did not complete*, which is
        // this flow correctly describing a token request that never got a
        // connection. `trustAnchorPems()` answers the Root while there is
        // one and the self-signed certificate while there is not, so this
        // call site does not have to know which.
        anchor =
            require('../tls/tls_server').serverCertificate().trustAnchorPem;
      } catch (e) {
        log.debug('Leaving backChannel(). No server certificate: ' + e.message);
        resolve(coded('STS-AUTHN-0116', { ok: false,
                  why: 'this service could not read its own TLS certificate ' +
                       'to verify the loopback connection ' +
                       'against: ' + e.message }));
        return;
      }
    }
    const body = options.body || '';
    const headers = Object.assign({
      host: options.host,
      accept: 'application/json',
      'content-length': Buffer.byteLength(body)
    }, options.headers || {});

    // -----------------------------------------------------------------------
    // THE BACK CHANNEL HAS TO COME BACK TO THE PROCESS THAT MINTED THE CODE
    // (2026-09-07).
    //
    // This is a SERVER-TO-SERVER request and it carries no cookies, which is
    // correct — it is not the browser and it must not present the browser's
    // credentials. With request dispatching on, that made it the one hop in
    // either hosted surface that could not work: the authorization code was
    // minted in the worker that ran `/oauth2/authorize`, this request goes out
    // to the front process with nothing to route it by, and the front process
    // sends it to whichever worker is least loaded — which does not have the
    // code. The symptom is `/admin/callback` answering 400 on a flow where
    // every earlier hop was correct.
    //
    // So it names the worker it is running in. The value is the pool's routing
    // cookie and NOT a credential — it selects which of N identical processes
    // answers, and nothing is authorized by it; the front process would
    // otherwise have chosen by load. See common/request_pool.js.
    //
    // In the front process, and in any process with no pool, the variable is
    // unset and no header is added — so this is inert everywhere dispatching
    // is not in use.
    // -----------------------------------------------------------------------
    //
    // **AND IN A HOSTED-SURFACE WORKER ITS OWN PID IS THE WRONG ANSWER
    // (2026-09-13).** With `workers.surfaceCount` set, this callback runs in a
    // worker of the SECOND pool and the code is in a worker of the first, so
    // naming itself names no protocol worker at all and the token request is
    // routed by load. The front process knows which protocol worker holds this
    // browser and says so on the request (`request_pool.js`'s
    // PROTOCOL_WORKER_HEADER); `request_worker.js` puts it on `req`, and the
    // caller passes `req` as `options.from`. No hint — a browser the protocol
    // pool holds nothing for — means no cookie, which is the load-routed
    // request this was before 2026-09-07 and is still correct under
    // `workers.readYourWrite`, which a surface pool cannot start without.
    if (process.env.STS_REQUEST_WORKER) {
      const inSurfacePool =
        process.env.STS_REQUEST_WORKER_POOL === 'surfaces';
      const target = inSurfacePool
        ? (Number(options.from && options.from.stsProtocolWorker) || 0)
        : process.pid;
      if (target) {
        const pin = 'sts_pool=' + target;
        headers.cookie = headers.cookie ? (headers.cookie + '; ' + pin) : pin;
      }
    } else if (options.poolPin &&
               /^[0-9]{1,10}$/.test(String(options.poolPin))) {
      // THE SAME PIN FROM THE FRONT PROCESS (2026-09-13), for a surface that
      // is served there rather than by a worker — the embedded debugger. Its
      // browser holds the pool's routing cookie from the authorization
      // endpoint on the main port (a cookie is scoped to a host, not a port),
      // and that names the worker the code was minted in. Digits only: it
      // selects a process and authorizes nothing.
      const pin = 'sts_pool=' + String(options.poolPin);
      headers.cookie = headers.cookie ? (headers.cookie + '; ' + pin) : pin;
    }
    if (body) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
    }
    const request = (useHttps ? https : http).request({
      // THE INTERFACE THIS SERVICE LISTENS ON — see the header. Node takes an
      // IPv6 literal here without brackets, which is why this is
      // `loopbackHost()` and not `hostForUrl()`.
      host: helpers.loopbackHost(),
      port: PORT,
      method: options.method,
      path: options.path,
      headers: headers,
      // THE PIN. Our own certificate as the trust anchor — it is self-signed,
      // so it is its own root — and the hostname check skipped, because the
      // certificate names this service and the connection names the loopback
      // interface. Pinning the key is the stronger half of the two.
      ca: anchor ? [anchor] : undefined,
      checkServerIdentity: useHttps ? function () { return undefined; } :
                           undefined
    }, function (response) {
      // NO REDIRECT IS FOLLOWED. See the header: a 302 here would hand the
      // Basic credential to whatever Location said.
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        resolve(coded('STS-AUTHN-0117', { ok: false,
                  why: 'the token endpoint answered ' + response.statusCode +
                       ' with a redirect, which this client does not follow ' +
                       '— a redirect from a credentialed request is how the ' +
                       'credential ends up somewhere else' }));
        return;
      }
      let text = '';
      let over = false;
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        if (over) {
          return;
        }
        text += chunk;
        if (text.length > MAX_BODY_BYTES) {
          over = true;
          request.destroy();
        }
      });
      response.on('end', function () {
        if (over) {
          resolve(coded('STS-AUTHN-0118', { ok: false, why: 'the answer was ' +
              'larger than ' +
                                    MAX_BODY_BYTES + ' bytes' }));
          return;
        }
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in backChannel(): " +
                    ((e && e.message) || e));
          // Not JSON; the raw text is what gets reported, because an HTML error
          // page from a door that answers JSON is the interesting case.
          json = null;
        }
        log.debug('Leaving backChannel(). status=' + response.statusCode);
        resolve({ ok: true, status: response.statusCode, json: json,
                  text: text.slice(0, 2000) });
      });
    });
    const timeoutMs = backChannelTimeoutMs();
    request.setTimeout(timeoutMs, function () {
      request.destroy();
      resolve(coded('STS-AUTHN-0119', { ok: false,
                why: 'this service did not answer its own ' + options.path +
                     ' within ' + (timeoutMs / 1000) + 's ' +
                     '(oidcRp.backChannelTimeoutS)' }));
    });
    request.on('error', function (e) {
      log.debug('Leaving backChannel(). error=' + e.message);
      resolve(coded('STS-AUTHN-0120', { ok: false,
                why: 'the loopback request to ' + options.path + ' failed: ' +
                     e.message }));
    });
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

// ---------------------------------------------------------------------------
// THE ID TOKEN.
//
// Verified against the JWKS this service publishes, fetched over the same
// loopback channel — NOT against the key material in this process, which would
// prove nothing about what was actually served. `federation_sp.js`'s
// `verifyForeignJwt()` is the model and two of its rules are copied here
// deliberately rather than referenced: `alg: none` is refused BY NAME, because
// it is an attack with a name; and the algorithm family comes from the KEY
// rather than from the token, which is the classic JWT forgery.
// ---------------------------------------------------------------------------
function jsonFromB64u(part) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(Buffer.from(String(part), 'base64url').toString('utf8'));
}

function verifyIdToken(token, keys, expected) {
  log.debug('Entering verifyIdToken().');
  let header = null;
  try {
    header = jsonFromB64u(String(token).split('.')[0]);
  } catch (e) {
    log.debug('Leaving verifyIdToken(). The header will not decode.');
    return coded('STS-AUTHN-0129', { ok: false, why: 'its header is not ' +
                                                     'base64url ' +
                                                     'JSON: ' + e.message });
  }
  if (!header || !header.alg) {
    log.debug("Leaving verifyIdToken().");
    return coded('STS-AUTHN-0130', { ok: false, why: 'it has no alg in its ' +
                                                     'header' });
  }
  if (String(header.alg).toLowerCase() === 'none') {
    log.debug("Leaving verifyIdToken().");
    return coded('STS-AUTHN-0131', { ok: false,
             why: 'its header says alg=none, which is an unsigned token ' +
                  'presented as a signed one' });
  }
  const kid = header.kid || '';
  const candidates = keys.filter(function (key) {
    if (kid && key.kid) {
      return key.kid === kid;
    }
    return true;
  });
  if (!candidates.length) {
    log.debug("Leaving verifyIdToken().");
    return coded('STS-AUTHN-0132', { ok: false,
             why: kid
               ? 'its header names kid "' + kid + '" and ' + JWKS_PATH +
                 ' publishes no such key'
               : 'this service publishes no keys at ' + JWKS_PATH });
  }
  let lastWhy = '';
  for (let i = 0; i < candidates.length; i++) {
    let key = null;
    try {
      key = nodeCrypto.createPublicKey({ key: candidates[i], format: 'jwk' });
    } catch (e) {
      lastWhy = 'a published key could not be read: ' + e.message;
      continue;
    }
    try {
      const payload = stsCrypto.verifyJws(String(token), key, {
        algorithms: candidates[i].kty === 'EC'
          ? ['ES256', 'ES384', 'ES512']
          : ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
        clockTolerance: config.value('oauth2.clockSkewS'),
        issuer: expected.issuer,
        audience: expected.audience
      });
      // THE NONCE, which is OpenID Connect Core section 3.1.3.7 step 11 and is
      // the check that makes this an authentication rather than a token
      // handover. `oauth2_bcp.js` records it as unenforceable on the ISSUING
      // side because nothing there can observe a client doing it; here this
      // service IS the client, so it does it.
      //
      // `expected.nonce === null` is a RENEWAL (2026-09-12): OpenID Connect
      // Core section 12.2 says an ID Token from a refresh response SHOULD NOT
      // carry a nonce, because no authorization request sent one — so there is
      // nothing to compare, and what binds that token to this session instead
      // is `checkRenewedClaims()`: the same issuer, the same subject and the
      // same authentication time.
      if (expected.nonce !== null &&
          String(payload.nonce || '') !== String(expected.nonce)) {
        log.debug('Leaving verifyIdToken(). The nonce does not match.');
        return coded('STS-AUTHN-0134', { ok: false,
                 why: 'its nonce is not the one this sign-in sent, which is ' +
                      'what OpenID Connect Core section 3.1.3.7 step 11 is ' +
                      'for: the token is genuine and belongs to a different ' +
                      'request' });
      }
      log.debug('Leaving verifyIdToken(). Verified.');
      return { ok: true, claims: payload };
    } catch (e) {
      lastWhy = e.message;
    }
  }
  log.debug('Leaving verifyIdToken(). Nothing verified it: ' + lastWhy);
  return coded('STS-AUTHN-0133', { ok: false, why: lastWhy || 'no published ' +
      'key verified it' });
}

// ---------------------------------------------------------------------------
// CLIENT AUTHENTICATION AT THE TOKEN ENDPOINT, for both grants this client
// makes — the code redemption and the renewal. `client_secret_basic` is what
// the entry's own `token_endpoint_auth_method` says, read off the registration
// rather than assumed, so an operator who changes it there gets a client that
// says so rather than one that silently keeps using Basic. Adds the POST
// members to `form` where the method puts the secret in the body, and answers
// the headers to send.
// ---------------------------------------------------------------------------
function clientAuthentication(surface, client, form) {
  log.debug("Entering clientAuthentication().");
  const method = String(client.token_endpoint_auth_method ||
                        'client_secret_basic');
  const headers = {};
  if (method === 'client_secret_post') {
    form.set('client_id', surface.clientId);
    form.set('client_secret', client.client_secret);
  } else {
    headers.authorization = 'Basic ' + Buffer.from(
      encodeURIComponent(surface.clientId) + ':' +
      encodeURIComponent(client.client_secret)).toString('base64');
  }
  log.debug("Leaving clientAuthentication(). method=" + method);
  return headers;
}

// ---------------------------------------------------------------------------
// WHAT THIS RELYING PARTY KEEPS OF A TOKEN RESPONSE (2026-09-12).
//
// The three tokens, the instants the access token and the ID Token run out,
// and — from the ID Token, which is the only one this client can read — the
// issuer, subject and authentication time a renewed ID Token must repeat.
// `flowRealm` and `host` are how a renewal reaches the SAME authorization
// server later: the realm whose token endpoint issued the refresh token (a
// refresh token is encrypted to that realm's keys and opens nowhere else) and
// the Host header the issuer was built from, so a renewal made while the
// browser is reading another realm, or reached this service under another
// name, still gets an ID Token from the issuer it started with.
//
// A token response WITHOUT a refresh token — the entry's grant types no longer
// include `refresh_token` — keeps the rest, and a session holding no refresh
// token is not renewed: it ends with its sign-on session, exactly as every
// console session did before renewal existed.
// ---------------------------------------------------------------------------
function tokensFrom(json, claims, flowRealmId, host, previous) {
  log.debug("Entering tokensFrom().");
  const now = Date.now();
  const kept = previous || {};
  const expiresIn = Number(json.expires_in);
  const tokens = {
    accessToken: String(json.access_token || ''),
    tokenType: String(json.token_type || 'Bearer'),
    scope: String(json.scope || kept.scope || ''),
    accessExpiresAt: isFinite(expiresIn) && expiresIn > 0
      ? now + expiresIn * 1000
      : (Number(claims && claims.exp) || 0) * 1000,
    // A renewal that came back with no NEW refresh token keeps using the one
    // it has: RFC 6749 section 6 makes a new one optional, and outside RFC
    // 9700 mode the old one is still good.
    refreshToken: String(json.refresh_token || kept.refreshToken || ''),
    idToken: String(json.id_token || kept.idToken || ''),
    // A renewal answered with NO ID Token (section 12.2 makes it optional)
    // leaves the access token's expiry as the only clock: keeping the old ID
    // Token's would make a renewal due on every request for ever.
    idTokenExpiresAt: claims && claims.exp ? Number(claims.exp) * 1000 : 0,
    issuer: String((claims && claims.iss) || kept.issuer || ''),
    sub: String((claims && claims.sub) || kept.sub || ''),
    authTime: Number(kept.authTime || (claims && claims.auth_time)) || 0,
    flowRealm: String(flowRealmId || kept.flowRealm || realms.DEFAULT_ID),
    host: String(host || kept.host || '')
  };
  log.debug("Leaving tokensFrom().");
  return tokens;
}

// ---------------------------------------------------------------------------
// A RENEWED ID TOKEN MUST DESCRIBE THE SAME SIGN-IN (OpenID Connect Core
// section 12.2): the same `iss`, the same `sub`, and where both carry one, the
// same `auth_time`. The signature, the audience and the expiry are
// `verifyIdToken()`'s; these three are what make it THIS session's token
// rather than a genuine token about somebody else. Pure, and exported for
// `tests/oidc_rp_renewal.js`, because the case worth asserting — an
// authorization server answering a refresh with a different person — is one
// this service will not produce on demand.
// ---------------------------------------------------------------------------
function checkRenewedClaims(previous, claims) {
  log.debug("Entering checkRenewedClaims().");
  const was = previous || {};
  const now = claims || {};
  if (was.issuer && String(now.iss || '') !== was.issuer) {
    log.debug("Leaving checkRenewedClaims(). The issuer moved.");
    return { ok: false, why: 'the renewed ID Token was issued by "' +
             String(now.iss || '') + '", and the sign-in\'s by "' + was.issuer +
             '"' };
  }
  if (was.sub && String(now.sub || '') !== was.sub) {
    log.debug("Leaving checkRenewedClaims(). The subject moved.");
    return { ok: false, why: 'the renewed ID Token names subject "' +
             String(now.sub || '') + '", and the sign-in named "' + was.sub +
             '"' };
  }
  if (was.authTime && now.auth_time !== undefined &&
      Number(now.auth_time) !== Number(was.authTime)) {
    log.debug("Leaving checkRenewedClaims(). The authentication time moved.");
    return { ok: false, why: 'the renewed ID Token says the person ' +
             'authenticated ' +
             'at ' + Number(now.auth_time) + ', and the sign-in said ' +
             Number(was.authTime) + ' — a refresh is not an authentication' };
  }
  log.debug("Leaving checkRenewedClaims(). The same sign-in.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// 1. BEGIN. Where an unauthenticated request to a hosted surface goes.
//
// It answers by SENDING a redirect, and returns whether it did — a caller that
// gets `false` has already had a refusal drawn for it and must not write to the
// response again.
// ---------------------------------------------------------------------------
function beginSignIn(req, res, surfaceId, options) {
  log.debug('Entering beginSignIn(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const opts = options || {};
  log.debug("Leaving beginSignIn().");
  return inFlowRealm(surface, function () {
    const found = clientOf(surface);
    if (!found.ok) {
      log.error(errorCodes.tag(errorCodes.codeOf(found) || 'STS-AUTHN-0112') +
                'oidc_rp: the ' + surface.label + ' cannot start a sign-in. ' +
                found.why);
      log.debug('Leaving beginSignIn(). There is no client.');
      return coded(errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                   { ok: false, why: found.why, reason: 'no-client' }, res);
    }
    const publicBase = opts.callbackBase || publicBaseOf(req);
    const redirectUri = publicBase + surface.callbackPath;
    const registered = ensureRedirectUri(surface, found.client, redirectUri);
    if (!registered.ok) {
      log.debug('Leaving beginSignIn(). The address is not registered.');
      return coded(errorCodes.codeOf(registered) || 'STS-AUTHN-0114',
                   { ok: false, why: registered.why,
                     reason: 'unregistered-address' }, res);
    }

    const store = flows;
    const cap = maxFlows();
    if (store.size >= cap) {
      // The oldest goes, exactly as `federation_sp.js` does it: the cap bounds
      // memory and the eviction has to fall on the flow least likely to still
      // be wanted.
      let oldestKey = null;
      let oldestAt = Infinity;
      store.forEach(function (held, key) {
        if (held.startedAt < oldestAt) {
          oldestAt = held.startedAt;
          oldestKey = key;
        }
      });
      if (oldestKey) {
        log.warn('oidc_rp: ' + cap + ' sign-ins are in flight in this realm, ' +
                 'so the oldest is being dropped. Somebody who was part way ' +
                 'through will be sent round again.');
        store.delete(oldestKey);
      }
    }

    const pkce = pkcePair();
    const state = nodeCrypto.randomBytes(24).toString('base64url');
    const nonce = nodeCrypto.randomBytes(24).toString('base64url');
    store.set(state, {
      surface: surface.id,
      nonce: nonce,
      verifier: pkce.verifier,
      redirectUri: redirectUri,
      issuer: null,
      returnTo: inThisRealm(safeReturnTo(opts.returnTo, opts.fallback || '/')),
      startedAt: Date.now()
    });

    const query = new URLSearchParams({
      response_type: 'code',
      client_id: surface.clientId,
      redirect_uri: redirectUri,
      scope: surface.scopes.join(' '),
      state: state,
      nonce: nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256'
    });
    // `prompt=login` where the caller asked for a fresh authentication. Nothing
    // does today; it is threaded because the alternative is a caller reaching
    // into the URL, and a sign-in that must be re-done is a real thing to want.
    if (opts.prompt) {
      query.set('prompt', String(opts.prompt));
    }
    const to = (opts.authorizationBase || publicBase) + AUTHORIZE_PATH + '?' +
               query.toString();
    log.info('oidc_rp: sending a browser to the authorization endpoint for the ' +
             surface.label + ' (client_id ' + surface.clientId + ', state ' +
             state + '). It comes back to ' + redirectUri + '.');
    // 303 rather than 302: this is reached from a GET today and from a POST the
    // moment somebody adds a form that needs a session, and a 302 leaves the
    // method up to the browser.
    res.status(303).set('Location', to).end();
    log.debug('Leaving beginSignIn(). Redirected.');
    return { ok: true, state: state };
  });
}

// ---------------------------------------------------------------------------
// 2. THE CALLBACK. Where the browser comes back with a code.
//
// Every refusal here is REPORTED and never redirected, which is
// `federation_sp.js`'s decision 6 and its reason applies unchanged: the
// person's sign-in has already succeeded at the authorization endpoint, so the
// only interesting question is what THIS side disliked about the answer — and
// that is unanswerable from a redirect that has thrown the detail away.
//
// It returns `{ ok, session, returnTo, why }`. The caller draws its own
// refusal, because the console's shell and the portal's are different
// applications and a page drawn here would belong to neither.
// ---------------------------------------------------------------------------
async function handleCallback(req, res, surfaceId, options) {
  log.debug('Entering handleCallback(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const opts = options || {};
  const query = req.query || {};

  // THE AUTHORIZATION SERVER'S OWN REFUSAL, first: `error` beats everything
  // below it, and reporting "no such state" for a request that carries a
  // perfectly good `error=access_denied` would send somebody to debug the
  // wrong half.
  if (query.error) {
    const why = 'the authorization endpoint refused the request: ' +
                String(query.error) +
                (query.error_description ?
                 ' — ' + String(query.error_description) : '');
    log.info('oidc_rp: the ' + surface.label + ' sign-in was refused. ' + why);
    log.debug('Leaving handleCallback(). The AS refused.');
    return coded('STS-AUTHN-0121', { ok: false, why: why, refusedByAs: true },
                 res);
  }

  const state = String(query.state || '');
  const code = String(query.code || '');
  if (!state || !code) {
    log.debug('Leaving handleCallback(). No code or no state.');
    return coded('STS-AUTHN-0122', { ok: false,
             why: 'the callback carried no ' + (state ? 'code' : 'state') +
                  '. It is reached by the authorization endpoint sending a ' +
                  'browser here and not by being opened directly.' }, res);
  }

  log.debug("Leaving handleCallback().");
  return inFlowRealm(surface, async function () {
    const flow = flows.get(state);
    // SPENT ON SIGHT, whatever happens next. A state is single use: the second
    // presentation of one is either a browser reloading a page it should not
    // reload or somebody replaying a code, and both must fail. Deleting before
    // the work rather than after it is what makes that true even where the work
    // throws.
    flows.delete(state);
    if (!flow) {
      log.debug('Leaving handleCallback(). No such flow.');
      return coded('STS-AUTHN-0123', { ok: false,
               why: 'this sign-in is not one this service started, or it has ' +
                    'already been completed, or it took longer than ' +
                    Math.round(flowTtlMs() / 1000) + ' seconds. Start again.' },
                   res);
    }
    if (flow.surface !== surface.id) {
      // The state belongs to the OTHER surface. Refused rather than honoured,
      // because a code redeemed at the wrong callback would put a portal
      // session behind the console's cookie or the other way round.
      log.warn('oidc_rp: a ' + flow.surface + ' state was presented at the ' +
               surface.id + ' callback. Refused.');
      return coded('STS-AUTHN-0124',
                   { ok: false, why: 'this sign-in belongs to a different ' +
                                     'surface' }, res);
    }
    const ttlMs = flowTtlMs();
    if (Date.now() - flow.startedAt > ttlMs) {
      log.debug('Leaving handleCallback(). The flow expired.');
      return coded('STS-AUTHN-0125', { ok: false,
               why: 'this sign-in took longer than ' +
                    Math.round(ttlMs / 1000) +
                    ' seconds (authn.pendingTtlS) and has expired. Start again.' }, res);
    }

    const found = clientOf(surface);
    if (!found.ok) {
      return coded(errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                   { ok: false, why: found.why }, res);
    }
    const client = found.client;
    // The authorization server's base, which is the request's own for the
    // console and the portal and the main port's for the debugger — see the
    // surface table.
    const publicBase = opts.authorizationBase || publicBaseOf(req);
    const host = hostHeaderFrom(publicBase);

    // ---------------------------------------------------------------------
    // THE TOKEN REQUEST. Client authentication is `client_secret_basic`, which
    // is what the entry's own `token_endpoint_auth_method` says — read off the
    // registration rather than assumed, so an operator who changes it there
    // gets a client that says so rather than one that silently keeps using
    // Basic.
    // ---------------------------------------------------------------------
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: flow.redirectUri,
      code_verifier: flow.verifier
    });
    const headers = clientAuthentication(surface, client, form);
    const tokenAnswer = await backChannel({
      method: 'POST',
      path: realms.currentPrefix() + TOKEN_PATH,
      host: host,
      headers: headers,
      body: form.toString(),
      poolPin: opts.poolPin,
      // Which protocol worker redeems it when there are two pools; see
      // backChannel().
      from: req
    });
    if (!tokenAnswer.ok) {
      log.error(errorCodes.tag(errorCodes.codeOf(tokenAnswer) ||
                               'STS-AUTHN-0120') +
                'oidc_rp: the ' + surface.label +
                ' could not redeem its code. ' +
                tokenAnswer.why);
      return coded(errorCodes.codeOf(tokenAnswer) || 'STS-AUTHN-0120',
                   { ok: false, why: tokenAnswer.why }, res);
    }
    if (tokenAnswer.status !== 200 || !tokenAnswer.json) {
      const detail = (tokenAnswer.json && tokenAnswer.json.error)
        ? tokenAnswer.json.error +
          (tokenAnswer.json.error_description
            ? ' — ' + tokenAnswer.json.error_description : '')
        : tokenAnswer.text;
      return coded('STS-AUTHN-0126', { ok: false,
               why: 'the token endpoint answered ' + tokenAnswer.status + ': ' +
                    detail }, res);
    }
    const idToken = String(tokenAnswer.json.id_token || '');
    if (!idToken) {
      // The one refusal here that is about OIDC rather than OAuth: an access
      // token alone says a client was AUTHORIZED and not that anybody signed
      // in, which is the distinction `federation_sp.js` warns about on every
      // OAuth-shaped federated sign-in. Signing somebody in on it would be
      // signing in as nobody.
      return coded('STS-AUTHN-0127', { ok: false,
               why: 'the token response carried no id_token, so nothing in ' +
                    'it says who signed in. An access token means a client ' +
                    'was authorized, not that a person authenticated.' }, res);
    }

    // ---------------------------------------------------------------------
    // THE KEYS, FETCHED. See verifyIdToken()'s header for why they are fetched
    // rather than read out of this process.
    // ---------------------------------------------------------------------
    const jwksAnswer = await backChannel({
      method: 'GET',
      path: realms.currentPrefix() + JWKS_PATH,
      host: host,
      poolPin: opts.poolPin,
      from: req
    });
    if (!jwksAnswer.ok || jwksAnswer.status !== 200 || !jwksAnswer.json) {
      return coded('STS-AUTHN-0128', { ok: false,
               why: 'this service\'s own JWKS at ' + JWKS_PATH +
                    ' could not be read: ' +
                    (jwksAnswer.why || ('it answered ' + jwksAnswer.status)) },
                   res);
    }
    const keys = Array.isArray(jwksAnswer.json.keys) ? jwksAnswer.json.keys :
                 [];

    const verified = verifyIdToken(idToken, keys, {
      // The issuer the AUTHORIZATION endpoint would have advertised, which is
      // why the loopback request carries the browser's Host header — see the
      // header of this file.
      issuer: undefined,
      audience: surface.clientId,
      nonce: flow.nonce
    });
    if (!verified.ok) {
      const idTokenCode = errorCodes.codeOf(verified) || 'STS-AUTHN-0133';
      log.error(errorCodes.tag(idTokenCode) +
                'oidc_rp: the ' + surface.label + ' refused the ID Token it ' +
                'was issued. ' + verified.why);
      audit.audit({
        action: 'session.refused',
        errorCode: idTokenCode,
        actor: '',
        protocol: 'OAuth 2.0 / OIDC',
        channel: 'http',
        target: surface.clientId,
        outcome: 'refused',
        summary: 'the ' + surface.label + ' refused an ID Token from this ' +
                 'service: ' + verified.why,
        detail: { surface: surface.id, client_id: surface.clientId,
                  why: verified.why }
      });
      return coded(idTokenCode, { ok: false,
               why: 'the ID Token this service issued did not verify: ' +
                    verified.why }, res);
    }

    const claims = verified.claims || {};
    const username = String(claims.preferred_username || claims.sub || '');
    if (!username) {
      return coded('STS-AUTHN-0135', { ok: false,
               why: 'the ID Token names nobody: it carries neither ' +
                    'preferred_username nor sub' }, res);
    }

    // ---------------------------------------------------------------------
    // AND THE SESSION, WHICH IS NOT ALWAYS IN THE REALM THE FLOW JUST RAN IN.
    //
    // The flow ran in the AMBIENT realm — that is what made the sign-on session
    // it was answered out of the same one the other surface reached — and the
    // console's own session lives in the DEFAULT realm's partition wherever it
    // was reached, because that is what lets one console session read every
    // realm. So the two are stated separately rather than both being "here":
    // `parentRealm` says where the sign-on session named by `sid` lives, and
    // `inSessionRealm()` says where this session is created.
    //
    // `sid` is what joins them — see startRelyingPartySession(), where the
    // cascade that ends a derived session with its sign-on session is argued
    // and where the parent is now looked up in the realm named here rather than
    // assumed to be in its own.
    // ---------------------------------------------------------------------
    const parentRealm = realms.currentId();
    // THE TOKENS, KEPT (2026-09-12), and the window they may be renewed in:
    // the refresh token's lifetime from now, which is what the authorization
    // server states for THIS client — the service-wide
    // `oauth2.refreshTokenTtlS` or the entry's own `oauthRefreshTokenTtlS`. It
    // is read off this client's own registry entry, the same entry its secret
    // came from two steps up, rather than decoded out of the refresh token,
    // which is encrypted to the authorization server and is nothing this
    // client can or should read. See renewIfDue().
    const tokens = tokensFrom(tokenAnswer.json, claims, parentRealm, host,
                              null);
    const refreshTtlS = Number(applications.settingFor(surface.clientId,
                                                       'oauth2.refreshTokenTtlS',
                                                       config));
    const renewableUntil = tokens.refreshToken && isFinite(refreshTtlS) &&
                           refreshTtlS > 0
      ? Date.now() + refreshTtlS * 1000 : 0;
    const session = inSessionRealm(surface, function () {
      return authn.startRelyingPartySession({
      res: res,
      username: username,
      claims: claims,
      // THE SURFACE, as the protocol this session came through — which is what
      // `/admin/sessions` draws in its Protocol column and what the old
      // arrangement passed to `beginAuthentication()`. The SIGN-ON session
      // beside it says `OAuth 2.0 / OIDC`, correctly: it was created by an
      // authorization request. Two rows, two true answers.
      via: surface.label,
      parent: String(claims.sid || ''),
      surface: surface.id,
      label: surface.label,
      clientId: surface.clientId,
      cookie: surface.cookie,
      // WHERE THE PARENT LIVES. Absent means "the same realm as this session",
      // which is what every session made before 2026-09-11 meant and what the
      // portal still means; the console says `acme` while being created in the
      // default realm's partition.
      parentRealm: parentRealm,
      tokens: tokens,
      renewableUntil: renewableUntil
      });
    });
    log.info('oidc_rp: ' + username + ' completed the authorization code ' +
             'flow for ' +
             'the ' + surface.label + ' and holds session ' + session.id +
             '. The ID Token verified against ' + JWKS_PATH + '.');
    log.debug('Leaving handleCallback(). Signed in.');
    return { ok: true, session: session, returnTo: flow.returnTo,
             username: username };
  });
}

// ---------------------------------------------------------------------------
// 3. THE READER. What a hosted surface asks on every request.
// ---------------------------------------------------------------------------
function sessionFor(req, surfaceId) {
  log.debug("Entering sessionFor().");
  const surface = surfaceOf(surfaceId);
  log.debug("Leaving sessionFor().");
  return authn.relyingPartySessionOf(req, surface.cookie,
                                     sessionRealmIdOf(surface));
}

// ---------------------------------------------------------------------------
// 4. RENEWAL — THE SAME SESSION, NEW TOKENS (2026-09-12).
//
// **WHAT WAS WRONG IS WHAT A PERSON SAW.** A console session expired an hour
// after the sign-in, together with its ID Token and access token, and the next
// click sent the operator back through the sign-in screen — off the page they
// were on, and with any form they had open refused for want of a session. A
// real relying party does not do that: it holds a refresh token, and when its
// tokens run out it asks the token endpoint for new ones and carries on. This
// one was issued a refresh token on every sign-in (the entry's grant types
// have always included `refresh_token`) and threw it away.
//
// So now:
//
//   * the tokens are KEPT on the relying-party session (`tokensFrom()`,
//     `authn.startRelyingPartySession()`);
//   * every request to the surface passes through `renewal()` BEFORE the
//     surface's own gate, and `renewIfDue()` asks one question — do this
//     session's tokens run out within `oidcRp.renewBeforeExpiryS`? — and where
//     they do, redeems the refresh token over the same loopback back channel
//     the sign-in used, verifies the new ID Token, and writes the new tokens
//     onto THE SAME SESSION (`authn.renewRelyingPartySession()`);
//   * and the request goes on to the page it asked for. Same session id, same
//     cookie, same CSRF token on every form already open: nothing about the
//     browser changes, which is what "stay signed in on the page I was on"
//     means.
//
// **IT IS NOT A SIGN-IN AND CREATES NO SESSION.** No authentication is
// recorded, no `session.start` row is written, no CAEP event is sent, and the
// sign-on session the relying-party session descends from is not touched:
// `session.renew` is the one audit row, and it says the session is unchanged.
//
// **THE WINDOW IS BOUNDED.** A session may renew until the refresh token it
// was issued at sign-in would have expired (`renewableUntil`) and never past
// it — renewing does not extend the window, so a console somebody keeps using
// still signs them out after `oauth2.refreshTokenTtlS` (twenty-four hours by
// default, and the client's own `oauthRefreshTokenTtlS` where one is set).
//
// **THE SIGN-ON SESSION'S LIFETIME NO LONGER ENDS IT; A SIGN-OUT STILL DOES.**
// `dropSession()`'s cascade ends every relying-party session derived from a
// sign-on session that is ended — by any sign-out door, by a Revoke on
// `/admin/sessions`, by a global logout — exactly as before. What changed is
// the case where the sign-on session simply RAN OUT: a session that can renew
// carries on, and `authn.relyingPartySessionOf()` tells the two cases apart by
// the clock (see there).
//
// **A RENEWAL THAT FAILS ENDS THE SESSION**, and the gate then does what it
// always did for a request with no session: a GET is sent through the
// authorization code flow and comes back to the page it asked for. A refused
// refresh token, a renewed ID Token about a different sign-in, a client entry
// that has gone — each is an audit row coded `session.renew` refused and a
// `session.end` beside it. What it never does is let a request through on
// tokens that have run out and could not be renewed.
//
// **ONE RENEWAL AT A TIME PER SESSION.** A page's several requests arriving
// together would otherwise each redeem the refresh token — and in RFC 9700
// mode a refresh token is rotated on use, so the second redemption is a
// REPLAY, and a replay revokes the whole family. `renewing` holds the promise
// for the length of one round trip and every concurrent caller waits on it.
// ---------------------------------------------------------------------------
const RENEW_BEFORE_EXPIRY_S = 60;
// Keyed by the realm the session lives in and the session id. Process-wide
// rather than `realms.map()` because it is keyed BY realm already and holds a
// promise for one back-channel round trip: nothing to persist, and nothing
// another process could use — a console or portal request holds affinity to
// one request worker.
const renewing = new Map();

// `oidcRp.renewBeforeExpiryS`, where ZERO is legal and means "only once they
// have run out" — so not `Number(x || n)`.
function renewBeforeExpiryMs() {
  log.debug("Entering renewBeforeExpiryMs().");
  const n = Number(config.value('oidcRp.renewBeforeExpiryS'));
  log.debug("Leaving renewBeforeExpiryMs().");
  return (isFinite(n) && n >= 0 ? Math.floor(n) : RENEW_BEFORE_EXPIRY_S) * 1000;
}

// Ending a session whose tokens could not be renewed: the refused
// `session.renew` row, the log line, the session ended through `dropSession()`
// like every other, and the surface's cookie cleared. In the SESSION's realm,
// so both rows land in the audit log the `session.start` for it is in.
function renewalFailed(surface, session, sessionRealmId, res, code, why) {
  log.debug("Entering renewalFailed(). code=" + code);
  log.warn(errorCodes.tag(code) + 'oidc_rp: the ' + surface.label + ' could ' +
           'not renew the tokens of session ' + session.id + ' for ' +
           session.user.username + ', so the session is ended and the next ' +
           'page runs the authorization code flow again. ' + why);
  realms.run(realms.get(sessionRealmId), function () {
    // The code is the caller's, one of STS-AUTHN-0136 to STS-AUTHN-0141 or the
    // back channel's own (STS-AUTHN-0112, -0120, -0128, -0133).
    audit.audit({
      action: 'session.renew',
      outcome: 'refused',
      errorCode: code,
      actor: session.user.username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: session.id,
      summary: 'the ' + surface.label + ' could not renew the tokens of ' +
               session.user.username + '\'s session ' + session.id + ': ' + why,
      detail: { sessionId: session.id, surface: surface.id,
                client_id: surface.clientId, why: why }
    });
    // `via` deliberately names neither "admin" nor "console": dropSession()
    // reads those words as an ADMINISTRATOR ending somebody's session and says
    // so in the CAEP event, and nobody did.
    authn.endSessionById(session.id, 'a token renewal that did not complete');
  });
  if (res && !res.headersSent) {
    authn.clearSessionCookie(res, surface.cookie);
  }
  log.debug("Leaving renewalFailed().");
  return { renewed: false, ended: true, why: why };
}

// The round trip. Runs in the realm the sign-in's code flow ran in, because
// that realm's token endpoint issued the refresh token and its keys are the
// only ones that open it.
async function renewNow(req, res, surface, session, sessionRealmId) {
  log.debug("Entering renewNow(). session=" + session.id);
  const tokens = session.rpTokens;
  const found = clientOf(surface);
  if (!found.ok) {
    log.debug("Leaving renewNow(). There is no client.");
    return renewalFailed(surface, session, sessionRealmId, res,
                         errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                         found.why);
  }
  const host = tokens.host || hostHeaderFrom(publicBaseOf(req));
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: tokens.refreshToken
  });
  const headers = clientAuthentication(surface, found.client, form);
  const tokenAnswer = await backChannel({
    method: 'POST',
    path: realms.currentPrefix() + TOKEN_PATH,
    host: host,
    headers: headers,
    body: form.toString(),
    from: req
  });
  if (!tokenAnswer.ok) {
    log.debug("Leaving renewNow(). The back channel failed.");
    return renewalFailed(surface, session, sessionRealmId, res,
                         errorCodes.codeOf(tokenAnswer) || 'STS-AUTHN-0120',
                         tokenAnswer.why);
  }
  if (tokenAnswer.status !== 200 || !tokenAnswer.json ||
      !tokenAnswer.json.access_token) {
    const detail = (tokenAnswer.json && tokenAnswer.json.error)
      ? tokenAnswer.json.error +
        (tokenAnswer.json.error_description
          ? ' — ' + tokenAnswer.json.error_description : '')
      : tokenAnswer.text;
    log.debug("Leaving renewNow(). The token endpoint refused.");
    return renewalFailed(surface, session, sessionRealmId, res,
                         'STS-AUTHN-0137',
                         'the token endpoint answered the refresh token grant ' +
                         tokenAnswer.status + ': ' + detail);
  }
  let claims = null;
  const idToken = String(tokenAnswer.json.id_token || '');
  if (idToken) {
    const jwksAnswer = await backChannel({
      method: 'GET',
      path: realms.currentPrefix() + JWKS_PATH,
      host: host,
      from: req
    });
    if (!jwksAnswer.ok || jwksAnswer.status !== 200 || !jwksAnswer.json) {
      log.debug("Leaving renewNow(). The JWKS could not be read.");
      return renewalFailed(surface, session, sessionRealmId, res,
                           'STS-AUTHN-0128',
                           'this service\'s own JWKS at ' + JWKS_PATH +
                           ' could not be read: ' +
                           (jwksAnswer.why ||
                            ('it answered ' + jwksAnswer.status)));
    }
    const keys = Array.isArray(jwksAnswer.json.keys) ? jwksAnswer.json.keys :
                 [];
    const verified = verifyIdToken(idToken, keys, {
      issuer: undefined,
      audience: surface.clientId,
      nonce: null
    });
    if (!verified.ok) {
      log.debug("Leaving renewNow(). The renewed ID Token did not verify.");
      return renewalFailed(surface, session, sessionRealmId, res,
                           errorCodes.codeOf(verified) || 'STS-AUTHN-0133',
                           'the renewed ID Token did not verify: ' +
                           verified.why);
    }
    const same = checkRenewedClaims(tokens, verified.claims);
    if (!same.ok) {
      log.debug("Leaving renewNow(). The renewed ID Token is about another " +
                "sign-in.");
      return renewalFailed(surface, session, sessionRealmId, res,
                           'STS-AUTHN-0138',
                           same.why);
    }
    claims = verified.claims;
  }
  const renewedTokens = tokensFrom(tokenAnswer.json, claims, tokens.flowRealm,
                                   tokens.host, tokens);
  const renewed = realms.run(realms.get(sessionRealmId), function () {
    return authn.renewRelyingPartySession({ realmId: sessionRealmId,
                                            id: session.id,
                                            tokens: renewedTokens });
  });
  log.debug("Leaving renewNow(). " + (renewed ? "Renewed." : "The session " +
      "had gone."));
  return renewed ? { renewed: true, session: renewed }
                 : { renewed: false, why: 'the session ended while it was ' +
                                          'renewed' };
}

// Is this session's renewal due, and may it happen? Answers what to do rather
// than doing it, so the one decision is readable in one place:
//   `none`   — nothing to do (no tokens, or not due yet)
//   `renew`  — redeem the refresh token now
//   `end`    — the tokens have run out and cannot be renewed
function renewalDecision(session, nowMs, marginMs) {
  log.debug("Entering renewalDecision().");
  const tokens = session && session.rpTokens;
  const expireAt = authn.tokensExpireAt(tokens);
  if (!expireAt || nowMs < expireAt - marginMs) {
    log.debug("Leaving renewalDecision(). Not due.");
    return { action: 'none' };
  }
  const windowOpen = tokens.refreshToken &&
    (!session.rpRenewableUntil || nowMs < Number(session.rpRenewableUntil));
  if (windowOpen) {
    log.debug("Leaving renewalDecision(). Due.");
    return { action: 'renew' };
  }
  if (nowMs < expireAt) {
    // Inside the lead time with nothing to renew with: the tokens are still
    // good, so they are left to run out rather than the session being ended
    // early.
    log.debug("Leaving renewalDecision(). Due, not renewable, not yet run " +
              "out.");
    return { action: 'none' };
  }
  log.debug("Leaving renewalDecision(). Run out and not renewable.");
  return tokens.refreshToken
    ? { action: 'end', code: 'STS-AUTHN-0141',
        why: 'its tokens have run out and the window it could renew them in ' +
             '(the refresh token\'s lifetime from the sign-in, ' +
             'oauth2.refreshTokenTtlS) has closed' }
    : { action: 'end', code: 'STS-AUTHN-0136',
        why: 'its tokens have run out and the sign-in was issued no refresh ' +
             'token to renew them with — the client entry does not allow the ' +
             'refresh_token grant' };
}

async function renewIfDue(req, res, surfaceId) {
  log.debug('Entering renewIfDue(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const session = sessionFor(req, surfaceId);
  if (!session || !session.rpTokens) {
    log.debug("Leaving renewIfDue(). No session holding tokens.");
    return { renewed: false };
  }
  const sessionRealmId = sessionRealmIdOf(surface);
  const flowRealm = realms.get(session.rpTokens.flowRealm);
  if (!flowRealm) {
    log.debug("Leaving renewIfDue(). The realm the sign-in ran in is gone.");
    return renewalFailed(surface, session, sessionRealmId, res,
                         'STS-AUTHN-0139',
                         'the trust realm "' + session.rpTokens.flowRealm +
                         '" ' +
                         'the sign-in ran in no longer exists, so there is ' +
                         'no token endpoint that can open its refresh token');
  }
  const decision = renewalDecision(session, Date.now(),
                                   realms.run(flowRealm, renewBeforeExpiryMs));
  if (decision.action === 'none') {
    log.debug("Leaving renewIfDue(). Nothing to do.");
    return { renewed: false };
  }
  if (decision.action === 'end') {
    log.debug("Leaving renewIfDue(). Ended.");
    return renewalFailed(surface, session, sessionRealmId, res, decision.code,
                         decision.why);
  }
  const key = sessionRealmId + ' ' + session.id;
  if (renewing.has(key)) {
    log.debug("Leaving renewIfDue(). Waiting on the renewal already in " +
              "flight.");
    return renewing.get(key);
  }
  const work = realms.run(flowRealm, function () {
    return renewNow(req, res, surface, session, sessionRealmId);
  });
  renewing.set(key, work);
  try {
    const answer = await work;
    log.debug("Leaving renewIfDue().");
    return answer;
  } finally {
    renewing.delete(key);
  }
}

// The middleware each surface registers ABOVE its own gate and routes (rule 1:
// middleware applies only to routes added after it). It never answers the
// request itself — a renewal that ended the session leaves the gate to send
// the browser through the code flow, which is the one place that decision is
// made — and a renewal that throws is logged and the request goes on, because
// the session it was renewing is still what the gate reads.
function renewal(surfaceId) {
  log.debug("Entering renewal(). surface=" + surfaceId);
  surfaceOf(surfaceId);
  log.debug("Leaving renewal().");
  return function renewTokensIfDue(req, res, next) {
    renewIfDue(req, res, surfaceId).then(function () {
      next();
    }, function (e) {
      log.error(errorCodes.tag('STS-AUTHN-0140') + 'oidc_rp: renewing the ' +
                surfaceId + ' session\'s tokens threw, and the request goes ' +
                'on without them: ' + ((e && e.stack) || e));
      next();
    });
  };
}

// Ending one. The surface's own cookie is cleared and the session goes through
// `dropSession()` like every other, so the audit row and the CAEP event are the
// ones every sign-out writes.
function endSessionFor(req, res, surfaceId, via) {
  log.debug('Entering endSessionFor(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const session = sessionFor(req, surfaceId);
  if (session) {
    inSessionRealm(surface, function () {
      authn.endSessionById(session.id, via || 'the ' + surface.label);
    });
  }
  authn.clearSessionCookie(res, surface.cookie);
  log.debug('Leaving endSessionFor(). ' + (session ? 'Ended.' : 'Nothing to ' +
      'end.'));
  return !!session;
}

module.exports = {
  SURFACES: SURFACES,
  surfaceOf: surfaceOf,
  beginSignIn: beginSignIn,
  handleCallback: handleCallback,
  sessionFor: sessionFor,
  endSessionFor: endSessionFor,
  // THE RENEWAL (2026-09-12): the middleware both surfaces register above
  // their routes, the function it calls, and — for `tests/oidc_rp_renewal.js`
  // — the two pure decisions no request can be made to exercise on demand.
  renewal: renewal,
  renewIfDue: renewIfDue,
  renewalDecision: renewalDecision,
  checkRenewedClaims: checkRenewedClaims,
  tokensFrom: tokensFrom,
  // For the two surfaces' own metadata pages and for the tests: which client a
  // surface is, so that nothing has to write the identifier down twice.
  clientIdFor: function (surfaceId) {
    log.debug("Entering clientIdFor().");
    log.debug("Leaving clientIdFor().");
    return surfaceOf(surfaceId).clientId;
  },
  cookieFor: function (surfaceId) {
    log.debug("Entering cookieFor().");
    log.debug("Leaving cookieFor().");
    return surfaceOf(surfaceId).cookie;
  },
  // For `tests/oidc_rp_addresses.js` (2026-09-12): the address rule and the
  // loopback origin are the two halves of this file no request can see
  // directly — one decides what is written onto an entry, the other where a
  // socket is opened.
  ensureRedirectUri: ensureRedirectUri,
  loopbackOrigin: loopbackOrigin,
  flowTtlMs: flowTtlMs
};
