// @ts-check
'use strict';
//
// File: app.js
//
// ---------------------------------------------------------------------------
// The express application and everything that must be in place BEFORE a single
// route is registered: the security headers, the Private Network Access answer,
// CORS, the body parser and the call log.
//
// It is a module of its own, and the reason is the registration order. Each
// protocol module registers its endpoints as a side effect of being required
// (`const app = require('./app')` then `app.get(...)` at its top level), which
// keeps every handler exactly where it was written instead of wrapped in a
// register() function and re-indented. Express applies middleware in the order
// it was added and only to routes added AFTER it, so the middleware has to be
// installed by the time any protocol module is loaded — i.e. here, in the
// module they all require, rather than in server.js, which requires them.
//
// The consequence to remember when adding a module: `common/protocol_stack.js`
// (which server.js and every request worker load) requires the protocol
// modules in a deliberate order, and that order is the route order.
// Nothing here has overlapping paths, so it does not currently matter — but a
// new module that registers a wildcard would matter a great deal.
// ---------------------------------------------------------------------------

const express = require('express');
const bodyParser = require('body-parser');
const helpers = require('./helpers');
const { log, headersOf, bodyOf } = helpers;
// TRUST REALMS. Required here rather than anywhere else because the realm has
// to be established BEFORE any other middleware runs — the call log records the
// realm's statistics, the audit log records the realm's rows, and the CORS
// decision reads the realm's applications and asks oauth2_bcp.js which path is
// an authorization endpoint — both questions with a different answer in each
// realm. It requires config.js and the error-code table and nothing else here,
// so it cannot join a cycle; helpers.js above has already pulled it in anyway.
const realms = require('./realms');
// The service's own record of what it has done. Required HERE, and the position
// is load-bearing twice over: the call log below is where the per-endpoint
// statistics are collected, so this is a real dependency — and because every
// protocol module requires this file, requiring it here means admin_stats.js
// has installed its JWT recorder into helpers.js before any route exists and
// therefore before any token can be minted. See the comment on setJwtRecorder
// in helpers.js for why that installation is a hook rather than a require in
// the other direction.
const stats = require('./admin_stats');
// THE CORS ALLOWLIST. A library (rule 3) registering no route; it requires the
// application registry, which `admin_stats.js` on the line above has just
// loaded, and `oauth2_bcp.js` for RFC 9700 section 2.6 — neither of which
// requires this file — so the require closes no cycle and moves no route.
// Below the realm module because the registry it reads is the ambient realm's.
const corsPolicy = require('./cors');
// The service's account of WHAT HAPPENED, as against how much of it. Required
// here for the same reason admin_stats.js is and with the same consequence: the
// call log below is the single place every answered request passes through, so
// one call there covers three of the audit categories — the admin console,
// the management API and every protocol endpoint — instead of a recording site
// in each of forty route handlers, thirty-seven of which would never be added.
// It is a library like admin_stats.js (it registers no route) and it requires
// only helpers, config, realms, the error-code table and the replication
// fan-in — none of which requires it back — which is what keeps it out of the
// cycles rule 2 exists to avoid.
const audit = require('./audit');
// Where a signed token's `x5u` points. A library (rule 3) that `helpers.js`
// has already loaded, so this is a cache hit; the middleware below is its one
// use here.
const certificateHeader = require('./jose_certificate_header');

// The input guard. A LEAF (rule 3) — it registers no route of its own and
// requires only `config`, the error-code table and npm packages (bunyan, zod,
// xmldom), so requiring it here closes no cycle and moves nothing in the route
// order. `common/validation.js` is where every decision about what a value
// from outside may be is argued.
const validation = require('./validation');
// The request worker pool. A LIBRARY as far as rule 1 goes — it registers no
// route, and at load it requires only `config`, `keystore`, the error-code
// table, `client_address` and node builtins (the modules that register routes
// only lazily, inside functions), so it can neither join a cycle nor move a
// route. Its middleware is installed below the realm one.
const requestPool = require('./request_pool');
// THE CLUSTER BARRIER (2026-09-14, #46). A LIBRARY with a middleware, and a
// LEAF as far as the require order goes: it requires config, the error-code
// table and the capability table at load, and `persistence.js` only inside a
// request. Installed directly below the pool's middleware — see there.
const clusterBarrier = require('../cluster/cluster_barrier');
// --- express app -----------------------------------------------------------
const app = express();

// ---------------------------------------------------------------------------
// THE TRUST REALM. FIRST OF ALL, AND NOTHING MAY BE REGISTERED ABOVE IT.
//
// A trust realm is a whole logical copy of this service, reached on the same
// sockets and told apart by a segment at the front of the path — see
// realms.js, which argues the whole design. This middleware is the only place
// in this service that knows that, and what it does is three things:
//
//   1. STRIPS THE PREFIX. `/realm/acme/oauth2/token` becomes `/oauth2/token`
//      before the router ever sees it, so every one of this service's route
//      registrations matches unchanged. That is the trick the whole feature
//      rests on: no protocol module has a realm-aware path, because no
//      protocol module has a realm-aware anything.
//
//   2. ENTERS THE REALM, for the request and for everything it awaits. Every
//      `config.value()` below this line answers the realm's value, every store
//      declared with realms.map() reads the realm's partition, and every
//      signature is made with the realm's key. Ambient rather than threaded —
//      realms.js says why, at length, and the short version is that the
//      alternative is several hundred call sites that each silently work when
//      the argument is dropped.
//
//   3. PUTS THE PREFIX BACK ON THE WAY OUT, in the two places a path leaves
//      this service without going through baseUrlOf(): a redirect target and a
//      root-relative link in an HTML page. See below — each is argued where it
//      is done.
//
// **ALL THREE ARE NO-OPS IN THE DEFAULT REALM**, which is the contract
// realms.js opens with: `currentPrefix()` is the empty string there,
// `matchPath()` answers null when no realm is defined, and the two wrappers
// below return before touching anything. A service with no realms defined does
// not merely behave as it did — it runs the same code it did, with two
// comparisons added.
// ---------------------------------------------------------------------------
//
// **IT IS A NAMED FUNCTION BECAUSE `request_pool.js` ASKS IT AGAIN
// (2026-09-15).** A request the front process answers itself waits for other
// processes' writes before it is routed — and a realm another process created a
// moment ago is one of those writes. This middleware runs BEFORE that wait, so
// such a request found no realm, kept its `/realm/<id>` prefix, and reached the
// router as a path nothing registers: `sts_admin_api_operations` got
// `Cannot POST /realm/adminapi-…/admin-api/tls/trust/…` 270ms after creating
// the realm on a worker, in `dispatch` mode only. The pool is handed this
// function and applies it once more after catching up, to a request it had not
// placed in a realm. It wraps `res.location` and `res.send` only on a match, so
// asking twice cannot wrap them twice.
function enterRealm(req, res, next) {
  log.debug("Entering enterRealm().");
  const pathname = String(req.url || '').split('?')[0];
  const match = realms.matchPath(pathname);

  // Not in a realm — including a path that opens with the realm SEGMENT and an
  // id nobody defined. That case deliberately falls through to Express's own
  // 404 rather than being refused here: `Cannot GET /realm/nope/oauth2/token`
  // is how this repository's own tests/vendored/sts_metadata.js tells an
  // unrouted path from an endpoint legitimately answering 404, and a friendlier
  // refusal for unknown realms would break that distinction for every path
  // under the segment. `GET /realms` is where somebody finds out what the
  // realms are.
  //
  // ---------------------------------------------------------------------
  // **UNLESS ANOTHER NODE HAS JUST DEFINED IT (2026-09-14, #46).** This
  // middleware runs before the cluster barrier — nothing may be registered
  // above it — so on an active-active node a realm created on the other node
  // a moment ago was not here yet when its first request was matched, and
  // `/realm/<new>/admin-api/status` answered Express's 404 two times in six.
  // So when the node is active-active and the path names a realm id this
  // process does not hold, the barrier is run HERE, and the path matched
  // again. A realm that still does not exist falls through exactly as before,
  // to the same `Cannot GET` body. The barrier middleware below is told, so
  // one request catches up once.
  // ---------------------------------------------------------------------
  if (!match && clusterBarrier.isActive() &&
      realms.unknownRealmPath(pathname)) {
    clusterBarrier.syncShared().then(function (answer) {
      clusterBarrier.markSynced(req, answer);
      const again = realms.matchPath(pathname);
      if (!again) {
        log.debug("Leaving enterRealm(). Still in no realm.");
        next();
        return;
      }
      log.debug("Leaving enterRealm(). The realm arrived.");
      enterMatchedRealm(req, res, next, again);
    });
    log.debug("Leaving enterRealm(). Catching up first.");
    return;
  }
  if (!match) {
    log.debug("Leaving enterRealm(). Not in a realm.");
    next();
    return;
  }
  log.debug("Leaving enterRealm().");
  enterMatchedRealm(req, res, next, match);
}

// The realm middleware's work once a path has matched a realm.
function enterMatchedRealm(req, res, next, match) {
  log.debug("Entering enterMatchedRealm().");
  const query = String(req.url || '').slice(String(req.url || '').split(
      '?')[0].length);
  // `req.originalUrl` is left ALONE and that is deliberate twice over: the call
  // log and the audit log record what was asked for rather than what the router
  // was shown, and Express's 404 body — the one the test above reads — is built
  // from it, so an unrouted path inside a realm still names the realm.
  req.url = match.rest + query;
  req.realm = match.realm;

  // ---------------------------------------------------------------------
  // A REDIRECT TARGET. `res.redirect('/authn/login?...')` is how six modules
  // here send a browser to the sign-in screen, and the string is written the
  // way the route is registered — without a realm, because no route here has
  // one. Left alone it would send somebody signing in to realm `acme` to the
  // DEFAULT realm's login screen, they would sign in there, and the flow would
  // come back to a realm that had never heard of them. The symptom is an
  // authorization request that loops.
  //
  // Only a ROOT-RELATIVE target is touched. An absolute one names a host —
  // a client's redirect_uri, a wallet — and this service is not entitled to
  // put its own realm segment into somebody else's URL. `res.location()` is
  // wrapped as well as `res.redirect()` because the latter calls the former,
  // and because three places here set a Location header without redirecting.
  // ---------------------------------------------------------------------
  const location = res.location;
  res.location = function (url) {
    log.debug("Entering location().");
    log.debug("Leaving location().");
    return location.call(res, realms.href(url));
  };

  // ---------------------------------------------------------------------
  // A ROOT-RELATIVE LINK IN AN HTML PAGE.
  //
  // The console draws several hundred hrefs, every one of them written as the
  // path the route is registered at. The login screen posts to /authn/login.
  // The four autopost pages load /oauth2/autopost.js and its siblings. None of
  // them can know about a realm, and threading one through every one of them
  // is the several-hundred-call-sites problem this whole design exists to
  // avoid — with the extra property that a missed one is a link that silently
  // leaves the realm rather than a link that breaks.
  //
  // So it is done ONCE, here, on the way out. Three attributes and nothing
  // else — href, action and src — and only where the value starts with a
  // single `/`, which is what makes `//cdn.example` and `https://…` and every
  // relative path untouched. It runs on `text/html` responses only, so no JSON
  // body, no XML assertion, no JWT and no script is rewritten; and it runs in
  // a non-default realm only, so the default realm's bytes are not merely
  // unchanged but untouched.
  //
  // THE HONEST LIMITATION, said here rather than discovered later: a URL this
  // service builds inside a SCRIPT or a JSON island in an HTML page is not
  // rewritten. There is one such page — /admin/api-explorer, whose explorer
  // builds request URLs in JavaScript — and it is handled in
  // mgmt-api/admin_api_explorer.js by being given the prefix as a value rather
  // than by having its markup rewritten. Another page that builds URLs in a
  // script would need the same treatment and would not get it for free.
  // (It was /admin-api/docs
  // until 2026-09-09; the page moved into the console, the limitation did
  // not move with it.)
  // ---------------------------------------------------------------------
  const send = res.send;
  res.send = function (body) {
    log.debug("Entering send().");
    const type = String(res.get('Content-Type') || '');
    if (typeof body === 'string' && /html/i.test(type)) {
      arguments[0] = withRealmLinks(body, realms.currentPrefix());
    }
    log.debug("Leaving send().");
    return send.apply(res, arguments);
  };

  log.debug("Leaving enterMatchedRealm(). In realm " + match.realm.id + ".");
  realms.run(match.realm, next);
}

app.use(enterRealm);

// ---------------------------------------------------------------------------
// THE AMBIENT REQUEST, for the one thing a signer needs a request for and
// cannot be handed one: the ORIGIN of the `x5u` address a signed token carries
// (common/jose_certificate_header.js, 2026-09-13). Entered for the life of the
// request exactly as the realm above is, and for the realm's reason — the
// alternative is a request threaded through a dozen signers to build one URL.
// It is BELOW the realm middleware, which nothing may be registered above.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  log.debug("Entering the ambient-request middleware.");
  log.debug("Leaving the ambient-request middleware.");
  return certificateHeader.enterRequest(req, next);
});

// The rewrite itself. A function rather than an inline regex so that the ONE
// pattern that decides what a link is has one home and one test: `="/` and not
// `="//`, which is a protocol-relative URL to another host.
function withRealmLinks(html, prefix) {
  log.debug("Entering withRealmLinks().");
  if (!prefix) {
    log.debug("Leaving withRealmLinks().");
    return html;
  }
  log.debug("Leaving withRealmLinks().");
  return html.replace(/\b(href|action|src)="\/(?!\/)/g, '$1="' + prefix + '/');
}

// WHICH REALM IDS ARE ALREADY SPOKEN FOR — the first path segment of every
// route registered against this app. Installed as a FUNCTION because this file
// is loaded before a single route exists (it has to be: middleware applies only
// to routes added after it), so the answer is only complete at the moment a
// realm is being created, which is when this is called. See realms.js's
// reserve().
realms.reserve(function () {
  const router = app._router || app.router;
  const stack = (router && router.stack) || [];
  const seen = {};
  stack.forEach(function (layer) {
    const path = layer.route && layer.route.path;
    if (!path) {
      return;
    }
    (Array.isArray(path) ? path : [path]).forEach(function (one) {
      const first = String(one).split('/')[1];
      if (first && /^[a-z0-9-]+$/i.test(first)) {
        seen[first.toLowerCase()] = true;
      }
    });
  });
  return Object.keys(seen);
});

// ---------------------------------------------------------------------------
// AND HERE THE FRONT PROCESS STOPS HANDLING THE REQUEST AND STARTS PROXYING IT.
//
// `request_pool.js` argues the whole arrangement; this is where it is
// installed, and the POSITION belongs in this file because two things pin it,
// from opposite sides.
//
// **BELOW THE REALM MIDDLEWARE**, because that one decides which realm a
// request is in and must go on doing so here — the call log, the audit row and
// the flush-time check below all read `req.realm`. What the worker is sent is
// `req.originalUrl`, which still carries the `/realm/<id>` prefix, so the
// worker derives the same realm by the same rule rather than being told it.
//
// **ABOVE THE BODY PARSERS**, and that one is not a preference: `bodyParser`
// CONSUMES the request stream. Installed after it, this middleware would pipe
// an already-drained `req` to the worker and every POST in the service would
// arrive there with an empty body — a failure that would look like a
// validation bug in whichever handler happened to notice first.
//
// So everything between here and the routes runs IN THE WORKER for a
// dispatched request: the private-network preflight, CORS, the security
// headers, the body parsers, the call log and the validation guard. That is
// the point rather than a side effect — the front process is meant to be doing
// request/response I/O and nothing else.
//
// **THE ANSWER IS PIPED, WHICH IS WHY `res.send()`'s OVERRIDE BELOW DOES NOT
// FIRE TWICE.** That override rewrites root-relative links and re-checks the
// CSP; the proxy writes the worker's bytes through `res.write()`/`res.end()`
// and never calls `res.send()`, so a body the worker has already rewritten is
// not rewritten again. The flush-time CSP check still runs here over the header
// the worker set, which is defence in depth rather than duplication.
//
// With `workers.dispatch` empty — the default — this calls next() for
// everything and the service behaves exactly as it did.
// ---------------------------------------------------------------------------
app.use(requestPool.middleware({ enterRealm: enterRealm }));

// ---------------------------------------------------------------------------
// AND DIRECTLY BELOW IT, THE CLUSTER BARRIER (2026-09-14, #46).
//
// Below the pool's middleware so that it runs in the process that SERVES the
// request — a worker, or this process for a request it keeps — and never in a
// front process that only proxies. Above everything else, because every
// middleware below here may read a store: the arrival session, the CSRF check,
// the rate limiter. It does nothing unless the node is active-active.
// cluster/cluster_barrier.js argues both of its rules.
// ---------------------------------------------------------------------------
app.use(clusterBarrier.middleware());

// ---------------------------------------------------------------------------
// AND THE REQUEST'S REALM'S KEY SET, MADE OFF THE EVENT LOOP BEFORE A HANDLER
// READS IT (2026-09-14, #46).
//
// A realm this process holds no keys for — one created at runtime, here or on
// another node — used to have them generated inside the first handler that
// read `STS`: four RSA generations, ~470ms of a stopped process. A burst of
// such requests, or one list of such realms, stopped a cluster node past its
// membership lifetime and it exited. `helpers.prepareKeySet()` argues it.
//
// BELOW THE BARRIER, so a set another node already wrote has been adopted and
// there is nothing to make; in the process that SERVES the request, for the
// barrier's reason. After the first request a realm's keys are held, so this
// is one map lookup — the reason it is a bare callback and logs nothing (a
// hot path: an Entering/Leaving pair on every request would drown the log).
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  helpers.prepareKeySet(realms.currentId()).then(function () {
    next();
  });
});

// Chrome Private Network Access: when a PUBLIC page calls a LOCAL (loopback)
// server — which is exactly the live-site test setup, an HTTPS page on
// idptools.com calling this mock on localhost:8081 — Chrome may send a
// CORS preflight carrying Access-Control-Request-Private-Network and require
// this header on the response. Answer it so the call isn't blocked. Registered
// BEFORE the CORS preflight so the header is set before the preflight
// response is sent; a no-op for the containerized suite (both sides on the
// same bridge network).
app.use(function (req, res, next) {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

// The response hardening that actually applies to this service.
//
// Almost everything here answers `application/json`, and the values in those
// responses are echoed from what a caller sent — an error_description quoting a
// bad grant_type, a client name from a registration request. Escaping that
// content is NOT the control: JSON.stringify already encodes it unambiguously,
// and running an HTML sanitizer over it would corrupt legitimate values while
// protecting nothing (a JSON string is not markup). The way such a body turns
// into script is a browser deciding to treat it as HTML anyway, so the control
// is to forbid that decision:
//
//   X-Content-Type-Options: nosniff   honour the declared Content-Type, never
//                                     sniff a JSON body as text/html
//   Content-Security-Policy           no script runs even if some response were
//                                     rendered as a document after all
//   X-Frame-Options: DENY             no framing of the login screen the
//                                     authorization endpoint serves
//
// The HTML this service does emit (the login screen, the console, the portal,
// the credential-offer and verifier pages) builds its markup from server-side
// values, and where a caller-supplied value appears in it, it is escaped at
// that point with xmlEscape().
//
// The policy is as tight as these pages allow, and it is worth saying what each
// clause is for, because a stricter-looking one would break them:
//   script-src 'none'   the pages under it contain no <script> at all, inline
//                       or external — so this is the clause that makes the
//                       whole family of js/reflected-xss reports moot rather
//                       than merely unlikely: a JSON body rendered as a
//                       document still runs nothing. The few pages that need
//                       one name a single 'self' resource through
//                       contentSecurityPolicy() below (the root CLAUDE.md
//                       lists them).
//   style-src           many pages carry an inline <style> block, so
//                       'unsafe-inline' is required; extracting them to files
//                       would buy nothing here since no untrusted value reaches
//                       a style.
//   img-src data:       the QR pages (the Credential Offer, the verifier's
//                       request, the authenticator-app setup) embed the code as
//                       a data: URI produced by the qrcode library server-side.
//
// NOT present, and it must not be added back: **form-action**. It looks
// obviously right here — the only form posts to /authn/login, which is
// same-origin — but Chrome enforces form-action against the whole REDIRECT
// CHAIN that follows a submission, not just its immediate target. This is an
// authorization server: signing in POSTs the login form and the response is a
// 302 to the client's redirect_uri, which is by definition another origin.
// `form-action 'self'` therefore blocks the browser from ever reaching the
// client, and the symptom is remote from the cause — the sign-in appears to
// succeed and the wallet simply never comes back. It cost a full SD-JWT VC
// issuance run to find, and the parent project's tests/sd_jwt_vc_issuance.js
// is what catches it (H.1 signs in here). Enumerating allowed redirect origins
// is not a fix either: in development mode this service accepts arbitrary
// redirect_uris on purpose.
const CSP_DIRECTIVES = {
  'default-src': "'none'",
  'script-src': "'none'",
  'style-src': "'unsafe-inline'",
  'img-src': "'self' data:",
  'base-uri': "'none'",
  'frame-ancestors': "'none'"
};

// ---------------------------------------------------------------------------
// THE CLAUSES NO PAGE MAY DROP — RFC 9700 section 4.14, clickjacking.
//
// A page framed invisibly over another one collects a click the person meant
// for something else, and on a sign-in screen or an authorization page that
// click IS the decision. `frame-ancestors 'none'` is what prevents it —
// X-Frame-Options is set beside it for the browsers that still read it, but
// that header is obsolete and the CSP directive is the one that governs.
//
// **`frame-ancestors` HAS NO FALLBACK.** `default-src` covers most fetch
// directives and not this one, so a page that sets `Content-Security-Policy:
// default-src 'none'` and nothing else is framable as far as CSP is concerned.
// That is the trap this list exists to close: several routes here relax the
// policy — most so they can load a named script — each by SETTING THE WHOLE
// HEADER, and any of them could have left this clause out without anything
// failing — the page works, the script runs, and the protection is quietly
// gone.
//
// So a relaxation goes through `contentSecurityPolicy()` below, which starts
// from the base and re-adds the framing clauses whatever the caller asked for.
// A caller CANNOT turn them off, which is deliberate: there is no page in an
// authorization server that should be framable, and a mock that let one be
// would be teaching the opposite of what section 4.14 is for.
// ---------------------------------------------------------------------------
const UNDROPPABLE = ['frame-ancestors', 'base-uri'];

function contentSecurityPolicy(overrides) {
  log.debug("Entering contentSecurityPolicy().");
  const merged = Object.assign({}, CSP_DIRECTIVES, overrides || {});
  UNDROPPABLE.forEach(function (name) {
    merged[name] = CSP_DIRECTIVES[name];
  });
  log.debug("Leaving contentSecurityPolicy().");
  return Object.keys(merged).filter(function (name) {
    return merged[name] !== null && merged[name] !== undefined;
  }).map(function (name) {
    return name + ' ' + merged[name];
  }).join('; ');
}

const CONTENT_SECURITY_POLICY = contentSecurityPolicy({});

app.use(function (req, res, next) {
  log.debug("Entering the security-headers middleware.");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // ---------------------------------------------------------------------
  // NO RESPONSE LEAVES THIS SERVICE WITHOUT `frame-ancestors`, INCLUDING THE
  // ONES THIS SERVICE DID NOT WRITE.
  //
  // Setting the header above is not enough, and the gap is one nothing in this
  // repository could have shown: **Express's own 404 handler replaces the
  // Content-Security-Policy with `default-src 'none'`** on its way out.
  // `frame-ancestors` has no fallback from `default-src`, so every unrouted
  // path — every typo, every probe, and every error page a framework generates
  // — came back framable as far as CSP was concerned, protected only by the
  // obsolete X-Frame-Options. RFC 9700 section 4.14 names error pages
  // specifically, and this is why.
  //
  // So the header is re-checked at the moment it is flushed. The test is
  // deliberately "does it still carry the clause" rather than "is it still the
  // value I set": several routes here legitimately relax the policy, and
  // every one of them goes through contentSecurityPolicy(), which cannot drop
  // the framing clauses, or (mgmt-api/admin_api_docs.ts, a leaf) writes them
  // out itself — so a policy without them was set by something that is not
  // us, and the base policy is put back.
  //
  // Wrapping writeHead rather than adding a final 404 handler is deliberate
  // too. A handler would have to reproduce Express's body byte for byte:
  // `Cannot GET /path` is how this repository's own
  // tests/vendored/sts_metadata.js tells an unrouted path from an endpoint
  // legitimately answering 404, and a prettier 404 here would silently break
  // that distinction.
  // ---------------------------------------------------------------------
  const writeHead = res.writeHead;
  res.writeHead = function () {
    log.debug("Entering writeHead().");
    const current = String(res.getHeader('Content-Security-Policy') || '');
    if (current.indexOf('frame-ancestors') < 0) {
      res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
      res.setHeader('X-Frame-Options', 'DENY');
    }
    log.debug("Leaving writeHead().");
    return writeHead.apply(res, arguments);
  };
  log.debug("Leaving the security-headers middleware.");
  next();
});

// ---------------------------------------------------------------------------
// CORS: AN ALLOWLIST ON EVERY PATH (2026-09-13), DECIDED IN `common/cors.js`.
//
// This was `origin: '*'` everywhere, with `/oauth2/authorize` carved out in
// RFC 9700 mode. It is now the origins this service calls its own plus the
// ones applications list in `appCorsOrigin` — per client where a request
// names one, across the realm where it names none — and that module's header
// argues every part of it. This file only installs it, in two places:
//
//   * `cors.preflight()` HERE, for every OPTIONS request, and again as the
//     `app.options('*')` route `/admin/sts-metadata` lists (GNAP's discovery is
//     an OPTIONS request that must reach its route — see that module);
//   * `cors.response()` BELOW THE BODY PARSERS, for everything else, because a
//     `client_id` is usually in the body and nothing has read it up here.
//
// A preflight has no body, which is why it can be answered above them.
// ---------------------------------------------------------------------------
app.use(corsPolicy.preflight());

app.options('*', corsPolicy.preflight());

// ---------------------------------------------------------------------------
// BINARY BODIES FIRST, AND THE TEXT PARSER BELOW TAKES EVERYTHING ELSE.
//
// **THIS ORDER IS A FIX RATHER THAN A TIDY-UP (2026-09-05).** The text parser
// below claims EVERY content type — `type: () => true` — which is right for a
// service whose bodies are SOAP, form encodings, JSON and XML, and silently
// wrong for the one endpoint here whose body is neither text nor meant to be:
// `POST /KdcProxy`, MS-KKDCP's KDC-PROXY-MESSAGE, which is DER.
//
// What that cost was total and invisible: a DER body decoded as UTF-8 is
// CORRUPTED — every byte outside ASCII becomes U+FFFD and no length prefix
// survives — and it arrives at the handler as a `string`, so
// `prim.toBytes()` throws `expected bytes, got string` and the endpoint
// answers `400 the KDC-PROXY-MESSAGE does not decode`. **MS-KKDCP has
// therefore never worked**, while `/admin/sts-metadata` advertised it and
// `krb5_kdc.js` carried a complete and correct implementation behind it. No
// test drove it, which is how it survived: the Kerberos jobs in this suite talk
// to the KDC on raw TCP 88, where there is no body parser.
//
// `application/kerberos` is what MS-KKDCP section 2.1 specifies and what the
// endpoint answers with; `application/octet-stream` is beside it because a
// caller that sends the bytes without knowing the specific type should not be
// handed a corrupted body either. Anything else still reaches the text parser
// exactly as before, so no other endpoint in this service changes.
//
// **`application/ocsp-request` JOINED THEM ON 2026-09-11 AND IT IS THE SAME
// DEFECT A SECOND TIME.** The OCSP responder at `/pki/ocsp/{scope}/{ca}` takes
// a DER body, and without a row here it met the TEXT parser below — which
// takes EVERY content type. Two things went wrong at once and only the second
// is the one anybody would have predicted:
//
//   * **the request HUNG.** The handler read the body off the stream, and by
//     the time it ran the text parser had already drained it — so `end` never
//     fired again and nothing ever answered. Every POST to that endpoint
//     timed out with no error anywhere: `curl` reported `000`, the access log
//     recorded nothing, and the service went on answering everything else in
//     milliseconds.
//   * **and the bytes would have been CORRUPTED even once it answered**,
//     because the text parser decodes as UTF-8 and DER is not text. That is
//     the failure the Kerberos row above was added for, and the comment there
//     spells it out.
//
// The handler reads `req.body` now, like every other endpoint here.
// **`application/pkcs10` JOINED THEM ON 2026-09-13, FOR EST.** An EST body is
// base64 text rather than DER (RFC 8951), so the text parser would not corrupt
// it — but it would strip a byte-order mark and replace an invalid byte with
// U+FFFD before `est/est.ts` could refuse the body for containing one, which
// turns a malformed request into a different malformed request. Taken raw, the
// bytes EST checks are the bytes the client sent.
// **`application/x-pki-message` JOINED THEM THE SAME DAY, FOR SCEP.** A
// PKIOperation POST (RFC 8894 section 4.3) is a binary CMS SignedData, which
// is the OCSP case exactly: the text parser would drain the stream and decode
// DER as UTF-8, so `scep/scep.ts` would verify a signature over bytes the
// client never signed and refuse every correct request as badMessageCheck.
app.use(bodyParser.raw({
  type: ['application/kerberos', 'application/octet-stream',
         'application/ocsp-request', 'application/pkcs10',
         'application/x-pki-message'],
  limit: '5mb'
}));

// Accept any content-type as raw text (SOAP arrives as text/xml or
// application/soap+xml). It runs AFTER the raw parser above, and body-parser
// leaves a body alone once one of them has taken it.
//
// **THE BYTES ARE KEPT BESIDE THE STRING (2026-09-12), FOR ONE READER: GNAP.**
// RFC 9635 section 7.3.1 makes a client sign a `Content-Digest` (RFC 9530) of
// the request content, and section 7.3.3's detached JWS signs a SHA-256 of it —
// both over the BYTES ON THE WIRE. `req.body` is those bytes decoded as UTF-8,
// and a decode is not reversible in general: body-parser strips a byte-order
// mark and turns an invalid sequence into U+FFFD, so re-encoding the string
// would compare a digest over something the client never sent, and a correct
// client would be refused for it.
//
// `verify` is body-parser's hook for exactly this — it is called with the
// buffer BEFORE the decode (body-parser 2.x, lib/read.js) — and it only
// ASSIGNS, so it cannot refuse a body and cannot change what any other endpoint
// here sees. One caveat is inherent rather than fixable here: with a
// `Content-Encoding` the stream is inflated first, so the buffer is the decoded
// content, which is also what RFC 9530's `Content-Digest` is defined over.
app.use(bodyParser.text({
  type: function () {
    log.debug("Entering type().");
    log.debug("Leaving type().");
    return true;
  },
  limit: '5mb',
  verify: function (req, res, buffer) {
    log.debug("Entering verify().");
    req.rawBody = buffer;
    log.debug("Leaving verify().");
  }
}));

// The CORS decision for every request that is not OPTIONS, now that a body has
// been read. See `common/cors.js`; it refuses nothing, it decides a header.
app.use(corsPolicy.response());

// ---------------------------------------------------------------------------
// A BODY THE PARSERS ABOVE REFUSED, WRITTEN DOWN — AND NOTHING ELSE ABOUT IT.
//
// A body too large, in a charset or content encoding body-parser does not
// read, or cut off before its Content-Length arrived is refused by the parser
// with `next(err)`, and Express's final handler answers it. That refusal
// reaches NO RECORD: the call log below is registered after the parsers (it has
// to be — see its own comment), so an error raised here skips it along with
// every other ordinary middleware, and a 413 or a 415 left no audit row at all.
//
// So this one error middleware writes the failure row itself, with the code for
// the condition, and hands the error straight on. It changes nothing a client
// receives — the same error reaches the same final handler — and it cannot
// throw, because audit.failure() cannot. The target is the PATH only: a query
// string on this service carries codes and hints the audit log redacts.
// ---------------------------------------------------------------------------
app.use(function (err, req, res, next) {
  const type = String((err && err.type) || '');
  let code = 'STS-HTTP-0014';
  if (type === 'entity.too.large') {
    code = 'STS-HTTP-0004';
  } else if (type === 'charset.unsupported' ||
             type === 'encoding.unsupported') {
    code = 'STS-HTTP-0012';
  } else if (type === 'request.aborted' || type === 'request.size.invalid') {
    code = 'STS-HTTP-0013';
  }
  audit.failure(code, {
    protocol: 'HTTP', channel: 'http',
    target: String(req.originalUrl || req.url || '').split('?')[0],
    summary: 'The request body of ' + req.method + ' was refused before any ' +
             'endpoint saw it (' + (type || 'unclassified') + ', HTTP ' +
             ((err && (err.status || err.statusCode)) || 500) + ').',
    outcome: (err && (err.status || err.statusCode) >= 500) ? 'error' :
              'refused'
  });
  next(err);
});

// ---------------------------------------------------------------------------
// Record every call into every endpoint: the path, the request (headers and
// body), the response (headers, body and status), and how long it took.
//
// Registered AFTER the body parser on purpose: before that runs req.body is
// undefined, and every request would be recorded as empty.
//
// res.send / res.json / res.end are wrapped rather than hooked on 'finish',
// because by the time the response has been flushed the body is gone. Two
// entries are written per call — one when the request arrives, one when the
// answer goes out — so a request that never gets answered is still visible.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  log.debug("Entering the call-log middleware.");
  const started = Date.now();
  const request = {
    path: req.originalUrl,
    method: req.method,
    query: req.query,
    headers: headersOf(req.headers),
    body: bodyOf(req.body)
  };
  log.debug({ request: request },
            'Request: ' + req.method + ' ' + req.originalUrl);

  let responseBody = '';
  const send = res.send;
  const json = res.json;
  const end = res.end;
  res.send = function (body) {
    log.debug("Entering send().");
    responseBody = bodyOf(body);
    log.debug("Leaving send().");
    return send.apply(res, arguments);
  };
  res.json = function (body) {
    log.debug("Entering json().");
    responseBody = bodyOf(body);
    log.debug("Leaving json().");
    return json.apply(res, arguments);
  };
  // ---------------------------------------------------------------------
  // THE CALL IS RECORDED WHEN THE ANSWER IS HANDED OVER, NOT WHEN IT HAS GONE
  // (2026-09-14, #46). It was recorded from `finish`, and with a cluster that
  // is too late in one precise way: the barrier holds a writing response until
  // its writes have committed (cluster/cluster_barrier.js, rule 2), and a row
  // recorded after the response left was never one of them. A refused
  // `POST /healthcheck` on node A answered 404 and its audit row was committed
  // a moment later — after the client had already asked node B for the audit
  // log, which did not list it (the `admin_api` job, in the suite's `cluster`
  // mode). Recorded here, in `end()`, the row is in the journal when the
  // barrier decides, so a request that wrote anyway carries its row in the
  // commit it was already waiting for, and a REFUSAL — the row somebody opens
  // the audit log to find — is held for its row's commit even when it wrote
  // nothing else. What the barrier does with it is argued there.
  //
  // Everything the old comment said about the timing still holds: the status
  // is set before `end()`, `req.route` holds the matched pattern, and the
  // elapsed time is taken here. `finish` records a call that somehow reached
  // it without `end()` passing through here, and logs the response as before.
  // ---------------------------------------------------------------------
  let recorded = false;
  const recordTheCall = realms.bind(req.realm, function () {
    // Counted when the answer goes out rather than at the top of the
    // middleware because the two things worth counting — the status code and
    // how long it took — do not exist before. `req.route` is set by Express
    // when it dispatches into a route, so by now it holds the PATTERN that
    // matched ("/oauth2/register/:client_id") rather than the URL that was
    // requested; the metrics table is keyed on it so that one row means one
    // endpoint instead of one row per client id. A request that matched
    // nothing has no pattern, which is what `matched` records: those are 404s,
    // and they are the ones the table's cap collapses when a scanner starts
    // inventing paths.
    if (recorded) {
      return null;
    }
    recorded = true;
    const matchedPath = (req.route && req.route.path) || '';
    stats.recordCall({
      method: req.method,
      path: matchedPath || String(req.originalUrl || '/').split('?')[0],
      matched: !!matchedPath,
      status: res.statusCode,
      durationMs: Date.now() - started
    });
    // The same event, as one ROW rather than as a number that went up. `req`
    // is live, which is what lets audit.js resolve the signed-in user without
    // that having to be threaded through every handler.
    //
    // Nothing out of the request or response BODY is recorded, deliberately:
    // those carry passwords, bearer tokens and assertions on this service, and
    // the debug log above is where a person who wants them looks. The one field
    // read out of an admin body is `action`, by name — see audit.js.
    return audit.recordHttp(req, res, {
      route: matchedPath,
      matched: !!matchedPath,
      durationMs: Date.now() - started
    });
  });

  res.end = function (chunk) {
    log.debug("Entering end().");
    if (!responseBody && chunk) {
      responseBody = bodyOf(Buffer.isBuffer(chunk) ?
                            chunk.toString('utf8') : chunk);
    }
    if (!recorded) {
      clusterBarrier.callLogStarts(res);
      const row = recordTheCall();
      clusterBarrier.callLogRecorded(res, !!(row && row.errorCode));
    }
    log.debug("Leaving end().");
    return end.apply(res, arguments);
  };

  // ---------------------------------------------------------------------
  // THE REALM IS RE-ENTERED, EXPLICITLY, AND IT IS NOT BELT AND BRACES.
  //
  // A `finish` listener runs in the async context of whatever EMITTED the
  // event — not the one it was added in. The realm middleware's
  // AsyncLocalStorage therefore may or may not still be entered by the time
  // it fires, depending on whether the response was flushed synchronously or
  // from a socket write callback, and a row recorded there would land in
  // whichever realm the process happened to be in. `recordTheCall` is bound
  // to `req.realm` for that reason, and so is `end()`'s call of it: a handler
  // may answer from a callback outside the realm's context too.
  // ---------------------------------------------------------------------
  res.on('finish', realms.bind(req.realm, function () {
    recordTheCall();
    log.debug({ response: { path: req.originalUrl,
                            method: req.method,
                            status: res.statusCode,
                            durationMs: Date.now() - started,
                            headers: headersOf(res.getHeaders()),
                            body: responseBody } },
              'Response: ' + res.statusCode + ' ' + req.method + ' ' +
              req.originalUrl +
              ' in ' + (Date.now() - started) + 'ms');
  }));
  log.debug("Leaving the call-log middleware. The call will be recorded " +
            "when the answer is handed over.");
  next();
});

// ---------------------------------------------------------------------------
// THE VALIDATION GUARD, AND WHY IT IS HERE RATHER THAN THREE MIDDLEWARES UP.
//
// It refuses the two things no caller of any protocol this service speaks ever
// sends: a parameter NAMED `__proto__`/`constructor`/`prototype`, and a control
// character in a query-string value. Everything else about input validation is
// per endpoint and lives in the schema that endpoint declares —
// `common/validation.js` argues the split, and in particular argues why a
// REPEATED parameter is deliberately NOT refused here.
//
// **AFTER THE CALL LOG ON PURPOSE.** A refusal is exactly the request an
// operator wants to find afterwards, and the middleware above is what puts a
// request in `/admin/audit`. Registered ahead of it, every refusal this makes
// would be invisible — which is the same argument `common/websecurity.ts` makes
// about a rate-limit lockout nobody can see being a support call with no
// evidence in it.
//
// It is BELOW the security-headers middleware too, so a refusal still carries
// the CSP and `X-Content-Type-Options` every other response does.
// ---------------------------------------------------------------------------
app.use(validation.guard());

// ---------------------------------------------------------------------------
// THE REVOCATION STATUS OF A PRESENTED CLIENT CERTIFICATE (2026-09-12).
//
// The doors on this port that accept a certificate — `mtls.peerVerified()`,
// SCIM's client-certificate scheme and RFC 8705 client authentication — are
// synchronous, and a certificate from a foreign authority may need its CRL
// fetched. So the verdict is computed ONCE here, before any route, onto
// `req.certificateRevocation`, and those doors read it. **It refuses nothing
// itself**: a request that reaches no door reading it is unaffected, which is
// what keeps the refusal at the point the certificate is USED.
//
// **BELOW `requestPool.middleware()` ON PURPOSE**, so a dispatched request is
// checked in the worker that evaluates its certificate, where the register is
// visible because it is a `pki:` row every process holds. A plain-HTTP request
// and one that presented nothing pass straight through.
//
// The module is required LAZILY: it requires `common/pki.js`, and this file is
// at position 2 of the require order, above everything that module is built
// on. By the time a request arrives every one of those is loaded.
// `common/revocation_status.js` argues the rest.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  const socket = req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    next();
    return;
  }
  require('./revocation_status').annotateRequest(req).then(function () {
    next();
  }, function (e) {
    // `annotateRequest()` never rejects; a rejection here is a defect in it,
    // and a request must not hang for one. Nothing was annotated, which every
    // door reads as "not consulted".
    log.warn('app: the revocation annotation rejected and was skipped: ' +
             e.message);
    next();
  });
});

app.get('/healthcheck', function (req, res) {
  log.debug("Entering the healthcheck endpoint.");
  res.status(200).json({ message: 'Success' });
  log.debug("Leaving the healthcheck endpoint.");
});

// The app, with four members hung off it. One `Object.assign` rather than an
// assignment followed by four more (#50, 2026-09-16): the same object either
// way, and the type checker accepts only this form.
module.exports = Object.assign(app, {
  // The policy builder, for the routes that relax it. Exported off the app
  // object rather than as a second module because every one of them already
  // requires this file — and because a relaxation belongs beside the policy
  // it relaxes, where the next reader will find both.
  contentSecurityPolicy: contentSecurityPolicy,
  CONTENT_SECURITY_POLICY: CONTENT_SECURITY_POLICY,
  // For the one page that builds URLs in a script and therefore cannot have
  // its markup rewritten. See the comment on res.send above.
  withRealmLinks: withRealmLinks,
  // For tests/front_process_realm_arrival.js, which drives it beside the
  // request pool's second ask; nothing in the service calls it off the
  // export.
  enterRealm: enterRealm
});
