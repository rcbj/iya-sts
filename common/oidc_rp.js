'use strict';
//
// File: oidc_rp.js
//
// ===========================================================================
// THIS SERVICE'S OWN HOSTED SURFACES, AS RELYING PARTIES OF ITS OWN
// AUTHORIZATION SERVER (2026-09-06).
//
// `/admin` and `/portal` used to authenticate by REDIRECTING STRAIGHT TO THE
// SIGN-IN SCREEN: `authn.beginAuthentication()` stashed the interrupted request,
// the screen took a name, and the session it minted was the one those surfaces
// then read. That worked, and what was wrong with it is that **this service's
// own two applications were the only applications in the process that did not
// use the protocol this service exists to demonstrate.** An OpenID Connect
// relying party does not read the provider's session store — it has no access
// to one. It sends the person to the authorization endpoint, gets a code back
// at a registered redirect URI, redeems it with a client credential, verifies
// an ID Token and establishes a session of its OWN.
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
// The two callback routes are registered by the two surfaces — `/admin/callback`
// in `admin-ui/admin.js` and `/portal/callback` in `portal/portal.js` — and that
// is deliberate rather than tidy. A route registered HERE would land wherever
// this file was first required, which is a position decided by whoever edits an
// import list; a route registered there lands where that surface's other routes
// are, which is what `/admin/sts-metadata` walks and what the console's gate
// applies to. It also keeps the one exemption that gate needs (its own callback)
// in the file that has the gate in it.
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
// no URL at all — the address is `127.0.0.1` and `helpers.PORT`, and the paths
// are this service's own, three constants below.
//
// **IT IS AN HTTP REQUEST RATHER THAN A FUNCTION CALL ON PURPOSE.** Redeeming
// the code in process would be a client that skips client authentication, skips
// PKCE verification, writes no audit row at the token endpoint, mints nothing on
// `/admin/tokens` and proves nothing about the flow. The whole value of moving
// these surfaces onto the code flow is that the flow is REALLY RUN, and a
// back channel that was a function call would be the half of it that only looked
// run.
//
// Four things bound it, and each is `federation_http.js`'s rule made again:
//
//   * **THE HOST HEADER IS THE BROWSER'S, THE ADDRESS IS LOOPBACK.** The
//     connection goes to 127.0.0.1 because that is reachable from inside this
//     process whatever DNS says outside it; the `Host` header carries the name
//     the BROWSER used, because `issuerOf()` builds the `iss` claim from the
//     request when `oauth2.issuer` is not pinned. Dial loopback and say
//     loopback, and the ID Token comes back issued by `https://127.0.0.1:8081`
//     — which is not the issuer the authorization endpoint advertised to the
//     browser, so the RP would have to accept an issuer it should refuse.
//   * **TLS IS VERIFIED AGAINST THIS SERVICE'S OWN CERTIFICATE**, passed as the
//     trust anchor. The certificate is self-signed and generated at start, so it
//     IS its own root; what is skipped is the HOSTNAME check, because the
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
//     from `/.well-known/openid-configuration`, and this one already knows them:
//     it is inside the service that serves them. Fetching it would mean reading
//     back three paths this file could not be wrong about, and then REBASING
//     every absolute URL in it onto the loopback address — because that document
//     advertises the address a BROWSER uses. That is more moving parts for no
//     check.
//   * **No refresh token is kept.** The tokens buy exactly one thing here: an ID
//     Token that says who signed in. Keeping a refresh token would mean this
//     service holding a credential for itself, refreshing a session nobody is
//     using, and having somewhere to keep it — which is a store, and the wrong
//     one.
//   * **The access token is discarded too.** These surfaces read the directory
//     directly; there is no resource server to present one to. It is still
//     ISSUED, and appears on `/admin/tokens` like any other, because that is
//     what the authorization code grant does.
// ===========================================================================

const https = require('https');
const http = require('http');
const nodeCrypto = require('crypto');

const helpers = require('./helpers');
const { log, PORT, baseUrlOf } = helpers;
const config = require('./config');
const realms = require('./realms');
const applications = require('./applications');
const stsCrypto = require('./crypto');
const audit = require('./audit');
const authn = require('../authn/authn');

// ---------------------------------------------------------------------------
// THE TWO SURFACES.
//
// `clientId` is the identifier of the entry `applications.js` seeds under
// `ou=applications` — this file does not create it and must not: that container
// IS the registry, and a client this module invented would be a second answer
// to what a client is. If the entry is gone, the flow REFUSES and says so, which
// is what makes "an operator who deleted one of these meant it" a sentence with
// an observable consequence.
//
// `cookie` is the surface's own session cookie and is never `authn.js`'s. Two
// surfaces, two cookies: signing in to the portal does not sign anybody in to
// the console, which is what makes them two applications rather than one wearing
// two paths.
//
// `realm` is which realm the flow runs in, and the two answers differ for the
// reason `applications.js`'s `realmScope` rows argue: the console's gate accepts
// the DEFAULT realm's session in every realm, so its flow runs there; the portal
// reads the ambient realm's session, so its flow runs wherever it was reached.
// ---------------------------------------------------------------------------
const SURFACES = {
  admin: {
    id: 'admin',
    clientId: 'sts-admin-console',
    label: 'Admin console',
    callbackPath: '/admin/callback',
    cookie: 'sts_mock_admin',
    realm: 'default',
    scopes: ['openid', 'profile', 'email']
  },
  portal: {
    id: 'portal',
    clientId: 'sts-user-portal',
    label: 'User portal',
    callbackPath: '/portal/callback',
    cookie: 'sts_mock_portal',
    realm: 'ambient',
    scopes: ['openid', 'profile', 'email']
  }
};

// The paths this client knows because it is inside the server that serves them.
// See "no discovery document is fetched" above.
const AUTHORIZE_PATH = '/oauth2/authorize';
const TOKEN_PATH = '/oauth2/token';
const JWKS_PATH = '/oauth2/jwks';

// A flow in progress, per realm, keyed by `state`. `federation_sp.js`'s decision
// 3 exactly: the partner — here, the browser — carries an opaque handle and
// every fact about the request stays on this side. The `returnTo` in particular
// must never ride in a parameter, because a return address a caller can write is
// an open redirect operated by whoever can forge a state.
const flows = realms.map({ persist: 'oidc_rp.flows' });
// In flight at once, per realm rather than per process, for the reason
// `federation_sp.js` gives about a shared cap: one realm's flood would otherwise
// evict another realm's in-flight sign-ins.
const MAX_FLOWS = 200;
// How long somebody has to get through the sign-in screen. Ten minutes is the
// pending-authentication record's own lifetime over in `authn.js`, and the two
// are deliberately the same: a flow that outlived the screen it is waiting on
// would be a state this service accepts and an authorization endpoint that no
// longer has anything to answer with.
const FLOW_TTL_MS = 10 * 60 * 1000;
// The back channel's bounds. Both are `federation_http.js`'s and are set to the
// same values for the same reasons.
const BACK_CHANNEL_TIMEOUT_MS = 10 * 1000;
const MAX_BODY_BYTES = 256 * 1024;

// ---------------------------------------------------------------------------
// The surface, by id. A caller naming one that does not exist is a bug in this
// repository rather than anything a request can cause, so it throws rather than
// answering null: a null here would produce a sign-in that redirects to
// `undefined`.
// ---------------------------------------------------------------------------
function surfaceOf(id) {
  const surface = SURFACES[String(id)];
  if (!surface) {
    throw new Error('oidc_rp: there is no surface called "' + id + '". The ' +
                    'surfaces are ' + Object.keys(SURFACES).join(', ') + '.');
  }
  return surface;
}

// Run `fn` in the realm this surface's flow belongs to. The console's is always
// the default realm — its gate accepts that realm's session and no other, so a
// flow run in `acme` would mint a session the gate then refuses, which reads as
// a sign-in that silently did nothing.
function inRealmFor(surface, fn) {
  if (surface.realm === 'default') {
    return realms.run(realms.DEFAULT_REALM, fn);
  }
  return fn();
}

// ---------------------------------------------------------------------------
// THE ADDRESSES.
//
// `publicBaseOf()` is what the BROWSER is sent to and what goes in the redirect
// URI. `loopbackOrigin()` is where this process dials itself. They are different
// strings on purpose and the difference is the whole of the back channel's
// design — see the header.
// ---------------------------------------------------------------------------
function publicBaseOf(req) {
  return baseUrlOf(req);
}

function loopbackOrigin() {
  const scheme = config.value('global.https') ? 'https' : 'http';
  // 127.0.0.1 rather than `localhost`, which resolves to ::1 first on some
  // hosts while this service binds 0.0.0.0 — a connection refused on a name
  // that pings, which is among the least obvious failures available.
  return scheme + '://127.0.0.1:' + PORT;
}

// The Host header the loopback request carries: the authority the browser used,
// so that `issuerOf()` builds the issuer the browser was told about. It is taken
// from the public base rather than from `req.headers.host` directly because the
// public base has already been through `forwardedFrom()`, which is where
// `global.trustProxy` is honoured.
function hostHeaderFrom(publicBase) {
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
    return { ok: false,
             why: 'the application "' + surface.clientId + '" is not in this ' +
                  'realm\'s registry. It is seeded at startup ' +
                  '(applications.seedInternal) and something has deleted it, ' +
                  'or seeding is off. Recreate it on /admin/applications, or ' +
                  'restart this service.' };
  }
  if (!entry.client_secret) {
    log.debug('Leaving clientOf(). It has no secret.');
    return { ok: false,
             why: 'the application "' + surface.clientId + '" carries no ' +
                  'oauthClientSecret, so this surface cannot authenticate at ' +
                  'the token endpoint. The secret is minted at startup; an ' +
                  'entry without one has had it removed.' };
  }
  log.debug('Leaving clientOf(). Registered.');
  return { ok: true, client: entry };
}

// ---------------------------------------------------------------------------
// THE REDIRECT URI THE ENTRY LEARNS.
//
// The seeded entry carries `http(s)://localhost:<port>/admin/callback`, because
// it is written before any request exists and `localhost` is the only address
// this service can name without one. The BROWSER reaches this service at
// whatever address it was given — a container name, a proxy's hostname, an IP —
// and RFC 9700 mode matches `redirect_uri` by exact string, so the address
// actually in use has to be ON the entry or the first sign-in in that mode is
// refused by this service against itself.
//
// So the entry LEARNS it: the first flow through a given base adds that base's
// callback to `oauthRedirectUri`, which is multi-valued precisely so a client
// can have several. It is added and never replaced — a deployment reached at two
// names has two, both legitimate — and it is written through
// `applications.updateApplication()` like every other change to an entry, so it
// is audited and an operator can take it off again.
//
// **IT IS NOT A URL FROM A REQUEST BEING TRUSTED.** What is written is this
// service's OWN base, as `baseUrlOf()` computes it, with a path constant from
// the table above appended — the same string this module is about to send as
// `redirect_uri` and the same one the browser will come back to. A `Host` header
// a caller invented reaches `baseUrlOf()` only when `global.trustProxy` is on,
// which is the setting that already says this service believes what a proxy in
// front of it says.
// ---------------------------------------------------------------------------
function ensureRedirectUri(surface, client, uri) {
  log.debug('Entering ensureRedirectUri(). uri=' + uri);
  const held = [].concat(client.redirect_uris || []);
  if (held.indexOf(uri) >= 0) {
    log.debug('Leaving ensureRedirectUri(). Already registered.');
    return true;
  }
  const answer = applications.updateApplication({
    application: surface.clientId,
    action: 'add',
    attribute: 'oauthRedirectUri',
    value: uri,
    actor: 'the ' + surface.label,
    note: 'the address this service is being reached at'
  });
  if (!answer || answer.ok === false) {
    log.warn('oidc_rp: ' + uri + ' could not be added to "' + surface.clientId +
             '" (' + ((answer && answer.error) || 'no reason given') + '). The ' +
             'sign-in will still work unless oauth2.rfc9700 is on, where the ' +
             'redirect URI is matched by exact string.');
    log.debug('Leaving ensureRedirectUri(). The write was refused.');
    return false;
  }
  log.info('oidc_rp: "' + surface.clientId + '" learnt the redirect URI ' + uri +
           '. This service is being reached at an address the seeded entry did ' +
           'not name, which is the ordinary case behind a proxy or in a ' +
           'container. It is ADDED rather than replacing what was there.');
  log.debug('Leaving ensureRedirectUri(). Added.');
  return true;
}

// ---------------------------------------------------------------------------
// PKCE. RFC 7636, S256, always — there is no setting to turn it off, which is
// `federation_sp.js`'s position on the same question: the one thing worse than
// not sending PKCE is a flag that stops.
// ---------------------------------------------------------------------------
function pkcePair() {
  const verifier = nodeCrypto.randomBytes(32).toString('base64url');
  const challenge = nodeCrypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier: verifier, challenge: challenge };
}

// ---------------------------------------------------------------------------
// WHERE THE BROWSER GOES AFTERWARDS, checked the way `beginAuthentication()`
// checks its own AND stored server-side. Both, because they fail differently:
// the check catches a caller's bug and the storage catches an attacker.
// ---------------------------------------------------------------------------
function safeReturnTo(value, fallback) {
  const wanted = String(value || '');
  // A single-slash-rooted path with no whitespace and no scheme. `//host` is
  // refused rather than corrected, because it is the shape an open redirect
  // takes and correcting it would teach a caller that it works.
  if (/^\/(?!\/)[^\s]*$/.test(wanted)) {
    return wanted;
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// THE BACK CHANNEL.
//
// One function for both calls it makes, because they differ only in the method
// and the body. Everything the header promises is here.
// ---------------------------------------------------------------------------
function backChannel(options) {
  log.debug('Entering backChannel(). ' + options.method + ' ' + options.path);
  return new Promise(function (resolve) {
    const useHttps = config.value('global.https');
    // THE LAZY REQUIRE. See the header: at the top of this file it would move
    // three routes; here every module is loaded and it is a cache hit.
    let anchor = null;
    if (useHttps) {
      try {
        anchor = require('../tls/tls_server').serverCertificate().certPem;
      } catch (e) {
        log.debug('Leaving backChannel(). No server certificate: ' + e.message);
        resolve({ ok: false,
                  why: 'this service could not read its own TLS certificate to ' +
                       'verify the loopback connection against: ' + e.message });
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
    if (process.env.STS_REQUEST_WORKER) {
      const pin = 'sts_pool=' + process.pid;
      headers.cookie = headers.cookie ? (headers.cookie + '; ' + pin) : pin;
    }
    if (body) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
    }
    const request = (useHttps ? https : http).request({
      host: '127.0.0.1',
      port: PORT,
      method: options.method,
      path: options.path,
      headers: headers,
      // THE PIN. Our own certificate as the trust anchor — it is self-signed, so
      // it is its own root — and the hostname check skipped, because the
      // certificate names this service and the connection names the loopback
      // interface. Pinning the key is the stronger half of the two.
      ca: anchor ? [anchor] : undefined,
      checkServerIdentity: useHttps ? function () { return undefined; } : undefined
    }, function (response) {
      // NO REDIRECT IS FOLLOWED. See the header: a 302 here would hand the
      // Basic credential to whatever Location said.
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        resolve({ ok: false,
                  why: 'the token endpoint answered ' + response.statusCode +
                       ' with a redirect, which this client does not follow — ' +
                       'a redirect from a credentialed request is how the ' +
                       'credential ends up somewhere else' });
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
          resolve({ ok: false, why: 'the answer was larger than ' +
                                    MAX_BODY_BYTES + ' bytes' });
          return;
        }
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          // Not JSON; the raw text is what gets reported, because an HTML error
          // page from a door that answers JSON is the interesting case.
          json = null;
        }
        log.debug('Leaving backChannel(). status=' + response.statusCode);
        resolve({ ok: true, status: response.statusCode, json: json,
                  text: text.slice(0, 2000) });
      });
    });
    request.setTimeout(BACK_CHANNEL_TIMEOUT_MS, function () {
      request.destroy();
      resolve({ ok: false,
                why: 'this service did not answer its own ' + options.path +
                     ' within ' + (BACK_CHANNEL_TIMEOUT_MS / 1000) + 's' });
    });
    request.on('error', function (e) {
      log.debug('Leaving backChannel(). error=' + e.message);
      resolve({ ok: false,
                why: 'the loopback request to ' + options.path + ' failed: ' +
                     e.message });
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
  return JSON.parse(Buffer.from(String(part), 'base64url').toString('utf8'));
}

function verifyIdToken(token, keys, expected) {
  log.debug('Entering verifyIdToken().');
  let header = null;
  try {
    header = jsonFromB64u(String(token).split('.')[0]);
  } catch (e) {
    log.debug('Leaving verifyIdToken(). The header will not decode.');
    return { ok: false, why: 'its header is not base64url JSON: ' + e.message };
  }
  if (!header || !header.alg) {
    return { ok: false, why: 'it has no alg in its header' };
  }
  if (String(header.alg).toLowerCase() === 'none') {
    return { ok: false,
             why: 'its header says alg=none, which is an unsigned token ' +
                  'presented as a signed one' };
  }
  const kid = header.kid || '';
  const candidates = keys.filter(function (key) {
    if (kid && key.kid) {
      return key.kid === kid;
    }
    return true;
  });
  if (!candidates.length) {
    return { ok: false,
             why: kid
               ? 'its header names kid "' + kid + '" and ' + JWKS_PATH +
                 ' publishes no such key'
               : 'this service publishes no keys at ' + JWKS_PATH };
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
      if (String(payload.nonce || '') !== String(expected.nonce)) {
        log.debug('Leaving verifyIdToken(). The nonce does not match.');
        return { ok: false,
                 why: 'its nonce is not the one this sign-in sent, which is ' +
                      'what OpenID Connect Core section 3.1.3.7 step 11 is ' +
                      'for: the token is genuine and belongs to a different ' +
                      'request' };
      }
      log.debug('Leaving verifyIdToken(). Verified.');
      return { ok: true, claims: payload };
    } catch (e) {
      lastWhy = e.message;
    }
  }
  log.debug('Leaving verifyIdToken(). Nothing verified it: ' + lastWhy);
  return { ok: false, why: lastWhy || 'no published key verified it' };
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
  return inRealmFor(surface, function () {
    const found = clientOf(surface);
    if (!found.ok) {
      log.error('oidc_rp: the ' + surface.label + ' cannot start a sign-in. ' +
                found.why);
      log.debug('Leaving beginSignIn(). There is no client.');
      return { ok: false, why: found.why };
    }
    const publicBase = publicBaseOf(req);
    const redirectUri = publicBase + surface.callbackPath;
    ensureRedirectUri(surface, found.client, redirectUri);

    const store = flows;
    if (store.size >= MAX_FLOWS) {
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
        log.warn('oidc_rp: ' + MAX_FLOWS + ' sign-ins are in flight in this ' +
                 'realm, so the oldest is being dropped. Somebody who was part ' +
                 'way through will be sent round again.');
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
      returnTo: safeReturnTo(opts.returnTo, opts.fallback || '/'),
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
    const to = publicBase + AUTHORIZE_PATH + '?' + query.toString();
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
// `federation_sp.js`'s decision 6 and its reason applies unchanged: the person's
// sign-in has already succeeded at the authorization endpoint, so the only
// interesting question is what THIS side disliked about the answer — and that is
// unanswerable from a redirect that has thrown the detail away.
//
// It returns `{ ok, session, returnTo, why }`. The caller draws its own refusal,
// because the console's shell and the portal's are different applications and a
// page drawn here would belong to neither.
// ---------------------------------------------------------------------------
async function handleCallback(req, res, surfaceId) {
  log.debug('Entering handleCallback(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const query = req.query || {};

  // THE AUTHORIZATION SERVER'S OWN REFUSAL, first: `error` beats everything
  // below it, and reporting "no such state" for a request that carries a
  // perfectly good `error=access_denied` would send somebody to debug the
  // wrong half.
  if (query.error) {
    const why = 'the authorization endpoint refused the request: ' +
                String(query.error) +
                (query.error_description ? ' — ' + String(query.error_description) : '');
    log.info('oidc_rp: the ' + surface.label + ' sign-in was refused. ' + why);
    log.debug('Leaving handleCallback(). The AS refused.');
    return { ok: false, why: why, refusedByAs: true };
  }

  const state = String(query.state || '');
  const code = String(query.code || '');
  if (!state || !code) {
    log.debug('Leaving handleCallback(). No code or no state.');
    return { ok: false,
             why: 'the callback carried no ' + (state ? 'code' : 'state') +
                  '. It is reached by the authorization endpoint sending a ' +
                  'browser here and not by being opened directly.' };
  }

  return inRealmFor(surface, async function () {
    const flow = flows.get(state);
    // SPENT ON SIGHT, whatever happens next. A state is single use: the second
    // presentation of one is either a browser reloading a page it should not
    // reload or somebody replaying a code, and both must fail. Deleting before
    // the work rather than after it is what makes that true even where the work
    // throws.
    flows.delete(state);
    if (!flow) {
      log.debug('Leaving handleCallback(). No such flow.');
      return { ok: false,
               why: 'this sign-in is not one this service started, or it has ' +
                    'already been completed, or it took longer than ' +
                    (FLOW_TTL_MS / 60000) + ' minutes. Start again.' };
    }
    if (flow.surface !== surface.id) {
      // The state belongs to the OTHER surface. Refused rather than honoured,
      // because a code redeemed at the wrong callback would put a portal
      // session behind the console's cookie or the other way round.
      log.warn('oidc_rp: a ' + flow.surface + ' state was presented at the ' +
               surface.id + ' callback. Refused.');
      return { ok: false, why: 'this sign-in belongs to a different surface' };
    }
    if (Date.now() - flow.startedAt > FLOW_TTL_MS) {
      log.debug('Leaving handleCallback(). The flow expired.');
      return { ok: false,
               why: 'this sign-in took longer than ' + (FLOW_TTL_MS / 60000) +
                    ' minutes and has expired. Start again.' };
    }

    const found = clientOf(surface);
    if (!found.ok) {
      return { ok: false, why: found.why };
    }
    const client = found.client;
    const publicBase = publicBaseOf(req);
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
    const method = String(client.token_endpoint_auth_method || 'client_secret_basic');
    const headers = {};
    if (method === 'client_secret_post') {
      form.set('client_id', surface.clientId);
      form.set('client_secret', client.client_secret);
    } else {
      headers.authorization = 'Basic ' + Buffer.from(
        encodeURIComponent(surface.clientId) + ':' +
        encodeURIComponent(client.client_secret)).toString('base64');
    }
    const tokenAnswer = await backChannel({
      method: 'POST',
      path: realms.currentPrefix() + TOKEN_PATH,
      host: host,
      headers: headers,
      body: form.toString()
    });
    if (!tokenAnswer.ok) {
      log.error('oidc_rp: the ' + surface.label + ' could not redeem its code. ' +
                tokenAnswer.why);
      return { ok: false, why: tokenAnswer.why };
    }
    if (tokenAnswer.status !== 200 || !tokenAnswer.json) {
      const detail = (tokenAnswer.json && tokenAnswer.json.error)
        ? tokenAnswer.json.error +
          (tokenAnswer.json.error_description
            ? ' — ' + tokenAnswer.json.error_description : '')
        : tokenAnswer.text;
      return { ok: false,
               why: 'the token endpoint answered ' + tokenAnswer.status + ': ' +
                    detail };
    }
    const idToken = String(tokenAnswer.json.id_token || '');
    if (!idToken) {
      // The one refusal here that is about OIDC rather than OAuth: an access
      // token alone says a client was AUTHORIZED and not that anybody signed
      // in, which is the distinction `federation_sp.js` warns about on every
      // OAuth-shaped federated sign-in. Signing somebody in on it would be
      // signing in as nobody.
      return { ok: false,
               why: 'the token response carried no id_token, so nothing in it ' +
                    'says who signed in. An access token means a client was ' +
                    'authorized, not that a person authenticated.' };
    }

    // ---------------------------------------------------------------------
    // THE KEYS, FETCHED. See verifyIdToken()'s header for why they are fetched
    // rather than read out of this process.
    // ---------------------------------------------------------------------
    const jwksAnswer = await backChannel({
      method: 'GET',
      path: realms.currentPrefix() + JWKS_PATH,
      host: host
    });
    if (!jwksAnswer.ok || jwksAnswer.status !== 200 || !jwksAnswer.json) {
      return { ok: false,
               why: 'this service\'s own JWKS at ' + JWKS_PATH +
                    ' could not be read: ' +
                    (jwksAnswer.why || ('it answered ' + jwksAnswer.status)) };
    }
    const keys = Array.isArray(jwksAnswer.json.keys) ? jwksAnswer.json.keys : [];

    const verified = verifyIdToken(idToken, keys, {
      // The issuer the AUTHORIZATION endpoint would have advertised, which is
      // why the loopback request carries the browser's Host header — see the
      // header of this file.
      issuer: undefined,
      audience: surface.clientId,
      nonce: flow.nonce
    });
    if (!verified.ok) {
      log.error('oidc_rp: the ' + surface.label + ' refused the ID Token it ' +
                'was issued. ' + verified.why);
      audit.audit({
        action: 'session.refused',
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
      return { ok: false,
               why: 'the ID Token this service issued did not verify: ' +
                    verified.why };
    }

    const claims = verified.claims || {};
    const username = String(claims.preferred_username || claims.sub || '');
    if (!username) {
      return { ok: false,
               why: 'the ID Token names nobody: it carries neither ' +
                    'preferred_username nor sub' };
    }

    // ---------------------------------------------------------------------
    // AND THE SESSION. `sid` is what joins it to the sign-on session the
    // authorization endpoint answered out of — see startRelyingPartySession(),
    // where the cascade that ends one with the other is argued.
    // ---------------------------------------------------------------------
    const session = authn.startRelyingPartySession({
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
      cookie: surface.cookie
    });
    log.info('oidc_rp: ' + username + ' completed the authorization code flow ' +
             'for the ' + surface.label + ' and holds session ' + session.id +
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
  const surface = surfaceOf(surfaceId);
  return authn.relyingPartySessionOf(
    req, surface.cookie,
    surface.realm === 'default' ? realms.DEFAULT_ID : undefined);
}

// Ending one. The surface's own cookie is cleared and the session goes through
// `dropSession()` like every other, so the audit row and the CAEP event are the
// ones every sign-out writes.
function endSessionFor(req, res, surfaceId, via) {
  log.debug('Entering endSessionFor(). surface=' + surfaceId);
  const surface = surfaceOf(surfaceId);
  const session = sessionFor(req, surfaceId);
  if (session) {
    inRealmFor(surface, function () {
      authn.endSessionById(session.id, via || 'the ' + surface.label);
    });
  }
  authn.clearSessionCookie(res, surface.cookie);
  log.debug('Leaving endSessionFor(). ' + (session ? 'Ended.' : 'Nothing to end.'));
  return !!session;
}

module.exports = {
  SURFACES: SURFACES,
  surfaceOf: surfaceOf,
  beginSignIn: beginSignIn,
  handleCallback: handleCallback,
  sessionFor: sessionFor,
  endSessionFor: endSessionFor,
  // For the two surfaces' own metadata pages and for the tests: which client a
  // surface is, so that nothing has to write the identifier down twice.
  clientIdFor: function (surfaceId) { return surfaceOf(surfaceId).clientId; },
  cookieFor: function (surfaceId) { return surfaceOf(surfaceId).cookie; }
};
