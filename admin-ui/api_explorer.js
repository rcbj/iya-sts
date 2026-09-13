'use strict';
//
// File: api_explorer.js
//
// ---------------------------------------------------------------------------
// THE API EXPLORER, AS A PAGE OF THE ADMIN CONSOLE (2026-09-09).
//
// Three routes under `/admin/api-explorer`: the page, the OpenAPI document it
// reads, and the browser script that renders it. All three sit BELOW the
// console's gate — a sign-on session and one of the two roles — because they
// are registered after `admin.js` in the require order and that gate is an
// `app.use('/admin', ...)`.
//
// ---------------------------------------------------------------------------
// WHY IT MOVED, WHICH IS THE WHOLE REASON THIS FILE EXISTS.
//
// It was `GET /admin-api/docs`, hanging off the management API it documents,
// and that was right for as long as that API was open to anybody. On
// 2026-09-09 it stopped being: `/admin-api` requires an OAuth 2.0 access token
// now, and a browser navigating to a URL carries none. So the one page in this
// service whose entire purpose is to be opened in a browser became the one page
// a browser could not open — the console linked to it and the link answered
// 401, which is a console pointing at something a reader cannot have.
//
// The move is a STRONGER gate rather than a weaker one. Before: no credential
// at all. Now: a sign-on session, plus Admin Read or Admin Write, plus — for
// every call the page makes — an access token carrying only what those roles
// grant.
//
// ---------------------------------------------------------------------------
// THE TOKEN THIS PAGE IS GIVEN, AND THE LINE IT MUST NOT CROSS.
//
// The explorer's whole value is the Try it button, and Try it calls
// `/admin-api`, which requires a token. So this page mints one — through
// `oauth2.accessToken()`, the same function the token endpoint calls, so there
// is one place in this service where an access token is built — carrying the
// scopes the reader's OWN console roles grant and no others: `admin:read` for
// Admin Read, `admin:write` for Admin Write.
//
// **IT IS NOT A BYPASS AND MUST NEVER BECOME ONE.** The API still checks the
// token on every call, against the same XACML document that decides every other
// access here. A reader holding Admin Read gets a token that reads, presses Try
// it on a POST, and is refused 403 by the policy — which is the correct answer
// and the one they would get from a terminal. What the console removes is the
// step where a person copies a credential out of a shell and into a form; it
// removes no check.
//
// **MINTED IN THE DEFAULT REALM, WHEREVER THIS PAGE IS READ.** `admin_api.js`
// verifies against the DEFAULT realm's key and computes the audience outside
// any realm, because that credential is service-wide — a per-realm signing key
// for it would let anybody who can create a realm mint that realm's
// administrator token. A page that minted with the ambient realm's key would
// produce a token its own API refuses, inside every realm but one. That is the
// same rule the console's two roles already follow and the reason both halves
// are written down in both files.
//
// ---------------------------------------------------------------------------
// THE DOCUMENT IS SERVED FROM HERE RATHER THAN FETCHED FROM `/admin-api`.
//
// `/admin-api/openapi.json` is behind the token gate like everything else on
// that path, and the page's first act is to fetch its document — which would
// mean the explorer needing its token before it could draw anything at all, and
// a page that fails to render when a credential is missing rather than
// rendering and saying so. Serving the document on the console's own path lets
// it arrive on the session this page was already drawn with. It is BUILT by
// `admin_api_spec.buildSpec()` from `admin_api.js`'s own route table, so it is
// the same document by construction rather than by intention.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, AND WHY IT IS NOT IN `admin.js`.
//
// 19a — after `mgmt-api/admin_api` (19), which it requires for the route table
// the document is built from, and after `admin-ui/admin` (18), whose shell and
// gate it draws in. Both are plain requires in the ordinary direction and
// neither closes a cycle: `admin.js` does not know this file exists beyond a
// row in its `SECTIONS`, and `admin_api.js` does not require it at all.
//
// It is a file of its own rather than more of `admin.js` for the reason
// `crypto_metadata.js` is: `admin.js` is required at 18 and this needs the
// management API's table, so a require the other way round would drag every
// `/admin-api` route ahead of the console's own.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, baseUrlOf } = require('../common/helpers');
// The error codes (common/error_codes.js), a leaf: requiring it moves nothing.
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
const admin = require('./admin');
// `gateStateFor()` moved to the read layer on 2026-09-12 with the other
// thirty-seven pure answers — see admin-core/admin_views.js. This page asks
// it which roles the reader holds, so the token it mints carries those
// scopes and no others.
const adminViews = require('../admin-core/admin_views');
const adminApi = require('../mgmt-api/admin_api');
const spec = require('../mgmt-api/admin_api_spec');
const docs = require('../mgmt-api/admin_api_docs');
const oauth2 = require('../oauth-oidc/oauth2');
const version = require('../common/version');

const PATH = '/admin/api-explorer';
const VERSION = version.load().version;

// ---------------------------------------------------------------------------
// THE SCOPES THIS READER'S ROLES GRANT, and the mapping is deliberately the
// same one `admin_api.js`'s gate makes in the other direction: a GET wants
// ADMIN_READ, anything else wants ADMIN_WRITE, and those two roles are what
// `admin:read` and `admin:write` become. So the token a reader is handed can
// do exactly the operations the console would let them press a button for.
// ---------------------------------------------------------------------------
function scopesFor(gate) {
  const scopes = [];
  if (gate.read) {
    scopes.push('admin:read');
  }
  if (gate.write) {
    scopes.push('admin:write');
  }
  return scopes.join(' ');
}

// The audience `/admin-api` answers to, computed the way that file computes it:
// outside any realm, because the credential is service-wide.
function audienceFor(req) {
  return realms.run(realms.get(realms.DEFAULT_ID), function () {
    return baseUrlOf(req);
  }) + adminApi.BASE;
}

// A token for the person reading this page, or '' if one cannot be made.
function tokenFor(req, gate) {
  log.debug("Entering tokenFor().");
  const scope = scopesFor(gate);
  if (!scope) {
    // NOT AN ERROR AND NOT A REFUSAL. Somebody can be through the console's
    // gate holding neither role only in states the gate itself allows — the
    // empty roster with `admin.openWhenEmpty` off is drawn a refusal page, and
    // a build with no directory can hold no role at all — and there is then no
    // honest scope to put in a token. The page draws and says Try it will be
    // refused, which is true. (This read `admin.authRequired` until that
    // setting was removed on 2026-09-06; the gate is unconditional now.)
    log.debug("Leaving tokenFor(). No role, so no scope.");
    return '';
  }
  try {
    // IN THE DEFAULT REALM, for the reason in this file's header: the gate
    // verifies with that realm's key wherever it is reached.
    const token = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return oauth2.accessToken(baseUrlOf(req), {
        audience: audienceFor(req),
        client_id: 'sts-admin-console',
        scope: scope,
        username: gate.username || 'admin-console',
        sub: gate.username || 'admin-console'
      });
    });
    log.debug("Leaving tokenFor(). Minted a token with scope " + scope + ".");
    return token;
  } catch (e) {
    // SWALLOWED WITH A REASON: the explorer is useful without a token — every
    // operation is still described and the curl line is still shown — and a
    // console page that 500s because a credential could not be minted would be
    // a worse answer than one that renders and says so.
    log.error(errorCodes.tag('STS-ADMIN-0597') +
              'api-explorer: an access token could not be minted for ' +
              (gate.username || 'this session') + ': ' + e.message +
              '. The page will draw and Try it will be refused.');
    log.debug("Leaving tokenFor(). It failed.");
    return '';
  }
}

// What `?format=json` and the mirroring operation answer. NOT the whole OpenAPI
// document: that is what the route below serves, and repeating it here would be
// a second copy of a large thing in a reply whose subject is the PAGE.
function explorerJson(req) {
  const gate = adminViews.gateStateFor(req);
  const document = spec.buildSpec(adminApi.ROUTES, adminApi.specOptions(req));
  const paths = Object.keys(document.paths || {});
  let operations = 0;
  paths.forEach(function (one) {
    operations += Object.keys(document.paths[one] || {}).length;
  });
  return {
    page: PATH,
    api: adminApi.BASE,
    document: PATH + '/openapi.json',
    version: VERSION,
    paths: paths.length,
    operations: operations,
    // WHAT A READER OF THIS PAGE MAY ACTUALLY DO, which is the one thing here
    // that is about the caller rather than about the document — and it is
    // EMPTY when this is reached through `/admin-api/api-explorer`, because
    // there is no console session on such a request. That is honest rather
    // than a gap: reporting a token's own scopes back to the caller that just
    // sent them would be telling somebody what they had said.
    scope: scopesFor(gate),
    audience: audienceFor(req),
    // The token is NOT in this reply. It is a credential, and `?format=json` is
    // the shape a script reads — a page handing one to a browser it has already
    // authenticated is a different act from an API handing one to whoever asked.
    tokenInReply: false
  };
}

// ---------------------------------------------------------------------------
// THE PAGE.
// ---------------------------------------------------------------------------
app.get(PATH, function (req, res) {
  log.debug("Entering the API explorer console page.");
  // THE ONE CLAUSE THIS PAGE RELAXES, and it is the same shape every other
  // scripted page in this service uses: `script-src 'self'` naming one
  // resource, never `'unsafe-inline'`, through `app.contentSecurityPolicy()` so
  // that `frame-ancestors` and `base-uri` are re-added whatever is asked for.
  // `connect-src 'self'` is the second, and it is what lets the page call the
  // API it documents and nothing else.
  res.set('Content-Security-Policy', app.contentSecurityPolicy({
    'script-src': "'self'",
    'connect-src': "'self'"
  }));
  const gate = adminViews.gateStateFor(req);
  const token = tokenFor(req, gate);
  const prefix = realms.currentPrefix() || '';
  const inner = docs.consoleBody({
    // ---------------------------------------------------------------------
    // ONE OF THESE CARRIES THE REALM PREFIX AND THE OTHER MUST NOT, and the
    // asymmetry is `app.js`'s rewrite rather than an inconsistency here.
    //
    // That middleware rewrites every root-relative `href`, `action` and `src`
    // in an HTML response to carry the current realm's prefix — which is what
    // makes this whole console realm-correct without a line of its markup
    // being edited. So `scriptUrl` goes in BARE: it becomes a `src`, and
    // prefixing it here as well would produce `/realm/acme/realm/acme/...`
    // and a page whose script 404s in every realm but the default.
    //
    // `specUrl` becomes a DATA ATTRIBUTE, which that rewrite does not touch —
    // it is not markup a browser resolves, it is a string a script reads — so
    // it carries the prefix explicitly. That is the same split the page had
    // when it lived at `/admin-api/docs`, and it is worth restating because
    // getting it backwards fails in exactly one realm out of two.
    // ---------------------------------------------------------------------
    specUrl: prefix + PATH + '/openapi.json',
    scriptUrl: PATH + '/explorer.js',
    version: VERSION,
    // THE EXPLORER PREPENDS THIS TO EVERY REQUEST IT MAKES. The paths in the
    // document are the paths the routes are REGISTERED at and no route in this
    // service carries a realm, so without it Try it inside a realm would call
    // the default realm's API — the call would succeed and it would have
    // changed the wrong service.
    realmPrefix: prefix,
    token: token,
    who: gate.username || '',
    scope: scopesFor(gate)
  });
  admin.respond(req, res, explorerJson(req), 'API explorer', PATH, inner);
  log.debug("Leaving the API explorer console page.");
});

// ---------------------------------------------------------------------------
// THE DOCUMENT, on the console's own path so that it arrives on this session.
// ---------------------------------------------------------------------------
app.get(PATH + '/openapi.json', function (req, res) {
  log.debug("Entering the API explorer's OpenAPI document.");
  // THE OPTIONS COME FROM `admin_api.js` rather than being assembled here.
  // This page serves a SECOND copy of that API's document — on the console's
  // own path, so that it arrives on the session the page was drawn with — and
  // two copies built from two sets of facts is two documents. The one that
  // used to be missing from both is the gate's state.
  res.set('Cache-Control', 'no-store').type('application/json')
     .send(JSON.stringify(spec.buildSpec(adminApi.ROUTES,
                                         adminApi.specOptions(req)), null, 2));
  log.debug("Leaving the API explorer's OpenAPI document.");
});

// ---------------------------------------------------------------------------
// THE SCRIPT. A separate resource rather than an inline block precisely so that
// `'self'` suffices — `'unsafe-inline'` would be the clause that mattered, and
// this page never needs it.
// ---------------------------------------------------------------------------
app.get(PATH + '/explorer.js', function (req, res) {
  log.debug("Entering the API explorer script endpoint.");
  res.set('Content-Security-Policy', app.contentSecurityPolicy({
    'script-src': "'self'",
    'connect-src': "'self'"
  }));
  res.type('application/javascript').set('Cache-Control', 'no-store')
     .send(docs.SCRIPT);
  log.debug("Leaving the API explorer script endpoint.");
});

log.info('The API explorer is at ' + PATH + ': every operation of ' +
         adminApi.BASE + ', with a form that calls it. It moved off that API ' +
         'on 2026-09-09, when that API began requiring an access token a ' +
         'browser has no way to carry — so it is behind the console\'s own ' +
         'session and roles now, and the calls it makes use a token minted ' +
         'for the reader carrying exactly what their roles grant.');

module.exports = {
  PATH: PATH,
  explorerJson: explorerJson
};
