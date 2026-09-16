'use strict';
//
// File: debugger_server.ts
//
// ===========================================================================
// THE EMBEDDED IDENTITY PROTOCOL DEBUGGER: ITS LISTENER, ITS SIGN-IN AND ITS
// GATE (2026-09-13).
//
// rcbj asked for the parent project's debugger — its browser client and its
// api — to be a feature of this service, in this container, signed in to
// through this service's own authorization server like `/admin` and
// `/portal`, with its api behind an access token carrying a permission only a
// console administrator is issued. Eight decisions were put to him before
// anything was written and each took the recommended answer; they are the
// design and `debugger/CLAUDE.md` argues them. The four that shape this file:
//
//   1. **A LISTENER OF ITS OWN, ON AN ORIGIN OF ITS OWN** (`debugger.port`).
//      The debugger's pages carry inline scripts on nearly every control and
//      render tokens and assertions from any identity provider. On the
//      console's origin a flaw in either would be a script that can drive the
//      console with an administrator's cookies; on an origin of its own it is
//      a script that can drive the debugger. It also keeps every page's
//      root-relative `/js` and `/css` working unedited.
//   2. **THE API IS A FORKED CHILD** on a unix socket
//      (`debugger_api_process.ts`), and this file forwards `/api/*` to it with
//      the prefix stripped. Nothing of the debugger is ever required here.
//   3. **THE GATE IS ALWAYS ON.** There is no setting and no mode that opens
//      it, because the api dials whatever its caller names.
//   4. **PEOPLE ONLY, CONSOLE ADMINISTRATORS ONLY** — `debugger_access.ts`.
//
// ---------------------------------------------------------------------------
// WHAT A REQUEST MEETS, IN ORDER.
//
//   * the security headers — `frame-ancestors 'none'` and the rest, with a
//     script policy that allows the debugger's own inline scripts ON THIS
//     ORIGIN ONLY (`app.js`'s `script-src 'none'` is the main port's, and
//     this listener is not the main port);
//   * `GET /_sts/callback`, where this service's authorization endpoint sends
//     a browser back with a code — ungated, because a person arriving there has
//     no session yet by definition, exactly as `/admin/callback` is;
//   * FOUR LANDING PATHS, ungated, where a flow the debugger STARTED comes
//     back: `/callback` (an OAuth 2.0 authorization response), and at the api
//     `/samlacs`, `/samlslo`, `/wsfed` (a SAML or WS-Federation response
//     POSTed by an identity provider) and `POST /ssf/receiver/{id}` (a Shared
//     Signals push). The first three are cross-site form POSTs, which a
//     `SameSite=Lax` cookie is not sent on, so gated they could only ever be
//     refused — and none of them dials anything a request names: they stash
//     what arrived and redirect to a gated page, or append to an inbox an
//     authenticated call created. The move is the one this service's own
//     `/admin/signals/receive` exemption makes, and it passes the same test:
//     the check moved (to the gated page that reads what was stashed) rather
//     than went away;
//   * THE GATE: a bearer token, or this surface's relying-party session and
//     the access token it holds. Either is verified here — signature, `typ`,
//     issuer, audience, the permission, and whether the subject is STILL a
//     console administrator;
//   * `/api/*` forwarded, `/_sts/*` this surface's own account and sign-out
//     pages, and everything else the debugger's built static site.
//
// A browser with no session is sent through the authorization code flow and
// comes back to the page it asked for; an API caller with none gets 401. A
// signed-in person who is not an administrator gets a page saying so — the
// authorization server will have left the permission off their token, and
// that is the one refusal here a person meets in the ordinary course.
//
// ---------------------------------------------------------------------------
// WHAT IS NOT ON `/admin/sts-metadata`'S ROUTE WALK, AND WHY THAT IS STATED.
//
// Everything above is registered on THIS listener's express app and not on
// `common/app.js`'s, so the page built by walking that router cannot see it —
// the same blind spot the KDC's and the directory's sockets are. It is
// described by hand there, and `/admin/debugger` reports whether the listener
// bound and what the api process is doing.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DebuggerServer` takes the modules it uses through its constructor
// (`DebuggerServerDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `DebuggerServer` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the
// transitional code calls at load where the first route used to be
// registered, so rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import fs = require('fs');
import http = require('http');
import https = require('https');
import path = require('path');
import express = require('express');
import helpers = require('../common/helpers');
const { log, PORT } = helpers;
import config = require('../common/config');
import mode = require('../common/mode');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
// The PROXY protocol v2 reader (2026-09-14, #46), a LIBRARY, installed in
// listen() like every TCP listener's.
import proxyProtocol = require('../common/proxy_protocol');
import audit = require('../common/audit');
import websecurity = require('../common/websecurity');
import oidcRp = require('../common/oidc_rp');
import authn = require('../authn/authn');
import jwtAccessToken = require('../oauth-oidc/jwt_access_token');
// RFC 8705 section 3.1's resource-server check (2026-09-13); a library.
import mtls = require('../oauth-oidc/mtls');
// RFC 9449's binding check, and #34's two settings (2026-09-15). Both are
// libraries this process has already loaded through oauth2.js.
import dpop = require('../oauth-oidc/dpop');
import senderConstraints = require('../oauth-oidc/sender_constraints');
import tlsServer = require('../tls/tls_server');
import access = require('./debugger_access');
import apiProcess = require('./debugger_api_process');

const PACKAGE_ROOT = path.join(__dirname, '..');
const SURFACE = 'debugger';
const OWN_PREFIX = '/_sts';
const CALLBACK_PATH = OWN_PREFIX + '/callback';
const SIGNOUT_PATH = OWN_PREFIX + '/signout';
const ACCOUNT_PATH = OWN_PREFIX + '/';
const API_PREFIX = '/api';
// The literal the debugger's embedded build puts where this service's own
// base URL goes (`client/src/env/embedded.js` over there), replaced when a
// page or a bundle is served.
const STS_URL_PLACEHOLDER = '__STS_EMBED_STS_URL__';

// ---------------------------------------------------------------------------
// THE PATHS A FLOW THE DEBUGGER STARTED LANDS ON — see the header. Matched on
// the path with the api prefix stripped, method and all, so a GET of an inbox
// or a DELETE of one is gated like everything else.
// ---------------------------------------------------------------------------
const UI_LANDINGS = ['/callback'];
const API_LANDINGS = [
  { methods: ['GET', 'POST'], pattern: /^\/samlacs\/?$/ },
  { methods: ['GET', 'POST'], pattern: /^\/samlslo\/?$/ },
  { methods: ['GET', 'POST'], pattern: /^\/wsfed\/?$/ },
  { methods: ['POST'], pattern: /^\/ssf\/receiver\/[A-Za-z0-9_-]{1,128}\/?$/ }
];

// Hop-by-hop headers, which a proxy does not forward (RFC 9110 section 7.6.1).
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate',
                    'proxy-authorization', 'te', 'trailer',
                    'transfer-encoding', 'upgrade', 'proxy-connection'];

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.webp': 'image/webp', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml', '.pem': 'application/x-pem-file',
  '.webmanifest': 'application/manifest+json', '.map': 'application/json'
};
// The files whose text carries the placeholder and is rewritten on the way
// out. Everything else is sent as the bytes on disk.
const SUBSTITUTED = ['.html', '.js'];

let listening = false;
let boundPort = null;
let listenError = '';
let started = false;
let startProblem = '';
let server = null;

// What `DebuggerServer` needs from the rest of the service: the modules this
// file used to reach for itself, passed in so that the composition root can
// build one and a test can build one with stubs.
interface DebuggerServerDeps {
  fs: typeof fs;
  http: typeof http;
  https: typeof https;
  path: typeof path;
  express: typeof express;
  helpers: typeof helpers;
  log: typeof log;
  PORT: typeof PORT;
  config: typeof config;
  mode: typeof mode;
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  proxyProtocol: typeof proxyProtocol;
  websecurity: typeof websecurity;
  oidcRp: typeof oidcRp;
  authn: typeof authn;
  jwtAccessToken: typeof jwtAccessToken;
  mtls: typeof mtls;
  dpop: typeof dpop;
  senderConstraints: typeof senderConstraints;
  tlsServer: typeof tlsServer;
  access: typeof access;
  apiProcess: typeof apiProcess;
}

type RouteApp = typeof app;

class DebuggerServer {
  constructor(private readonly deps: DebuggerServerDeps) {
    deps.log.debug("Entering DebuggerServer.constructor().");
    deps.log.debug("Leaving DebuggerServer.constructor().");
  }

  esc(text) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.esc().");
    log.debug("Leaving DebuggerServer.esc().");
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  uiDirectory() {
    const { log, config, path } = this.deps;
    log.debug("Entering DebuggerServer.uiDirectory().");
    const raw = String(config.value('debugger.uiDirectory') || '').trim();
    log.debug("Leaving DebuggerServer.uiDirectory().");
    return path.isAbsolute(raw) ? raw : path.join(PACKAGE_ROOT, raw);
  }

  scheme() {
    const { log, config } = this.deps;
    log.debug("Entering DebuggerServer.scheme().");
    log.debug("Leaving DebuggerServer.scheme().");
    return config.value('global.https') ? 'https' : 'http';
  }

  // The Host a request arrived with, refused when it is not a plain authority —
  // it goes into a redirect and into a page, so it may not carry anything else.
  hostHeaderOf(req) {
    const { log, config } = this.deps;
    log.debug("Entering DebuggerServer.hostHeaderOf().");
    const host = String((req.headers && req.headers.host) || '').trim();
    if (/^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/.test(host) ||
        /^\[[0-9A-Fa-f:.]{2,45}\](:[0-9]{1,5})?$/.test(host)) {
      log.debug("Leaving DebuggerServer.hostHeaderOf().");
      return host;
    }
    log.debug("Leaving DebuggerServer.hostHeaderOf(). Not a plain authority.");
    return 'localhost:' + config.value('debugger.port');
  }

  // The debugger's own origin as the browser reached it, or the pinned one.
  debuggerBaseOf(req) {
    const { log, config } = this.deps;
    log.debug("Entering DebuggerServer.debuggerBaseOf().");
    const pinned = String(config.value('debugger.publicBaseUrl') || '').trim()
      .replace(/\/+$/, '');
    log.debug("Leaving DebuggerServer.debuggerBaseOf().");
    return pinned || (this.scheme() + '://' + this.hostHeaderOf(req));
  }

  // THE AUTHORIZATION SERVER'S BASE, from a request to the debugger. Pinned
  // where `global.publicBaseUrl` is; otherwise the SAME HOST the browser used,
  // on the main port — which is what makes the sign-on session cookie the
  // browser gets there one this listener is also sent (a cookie is scoped to a
  // host and not to a port).
  authorizationBaseOf(req) {
    const { log, helpers, PORT } = this.deps;
    log.debug("Entering DebuggerServer.authorizationBaseOf().");
    const pinned = helpers.pinnedBaseUrl();
    if (pinned) {
      log.debug("Leaving DebuggerServer.authorizationBaseOf(). Pinned.");
      return pinned;
    }
    const host = this.hostHeaderOf(req).replace(/:[0-9]{1,5}$/, '');
    log.debug("Leaving DebuggerServer.authorizationBaseOf().");
    return this.scheme() + '://' + host + ':' + PORT;
  }

  wantsJson(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.wantsJson().");
    const accept = String(req.headers.accept || '');
    const api = req.path === API_PREFIX ||
                req.path.indexOf(API_PREFIX + '/') ===
                                           0;
    log.debug("Leaving DebuggerServer.wantsJson().");
    return api || (accept.indexOf('application/json') >= 0 &&
                   accept.indexOf('text/html') < 0);
  }

  // A page of this surface's own — the account page, a refusal — in plain
  // markup with no script, on the debugger's origin.
  sendPage(res, status, title, inner) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.sendPage().");
    res.status(status).set('Content-Type', 'text/html; charset=utf-8')
       .set('Cache-Control', 'no-store')
       .send('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
             '<meta name="viewport" ' +
             'content="width=device-width,initial-scale=1">' +
             '<title>' + this.esc(title) + '</title><style>' +
             'body{font-family:system-ui,sans-serif;max-width:46rem;' +
             'margin:2rem auto;padding:0 1rem;line-height:1.5;color:#222}' +
             'code{background:#f3f3f3;padding:0 .25em}' +
             '.muted{color:#666}.btn{display:inline-block;padding:.4em .9em;' +
             'border:1px solid #888;border-radius:4px;background:#f7f7f7;' +
             'color:#222;text-decoration:none;cursor:pointer;font:inherit}' +
             '</style></head><body><h1>' + this.esc(title) + '</h1>' + inner +
             '</body></html>');
    log.debug("Leaving DebuggerServer.sendPage().");
  }

  // error-code: none — the definition of this helper, not a call to it
  refuse(req, res, status, code, error, why, challenge?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DebuggerServer.refuse(). code=" + code);
    errorCodes.mark(res, code);
    if (challenge) {
      res.set('WWW-Authenticate', challenge);
    }
    if (this.wantsJson(req)) {
      res.status(status).set('Cache-Control', 'no-store')
         .json({ error: error, error_description: why });
    } else {
      this.sendPage(res, status, status === 403 ? 'Not permitted' : 'Refused',
                    '<p>' + this.esc(why) + '</p><p><a class="btn" href="' +
                    this.esc(ACCOUNT_PATH) + '">Your debugger session</a></p>');
    }
    log.debug("Leaving DebuggerServer.refuse().");
  }

  // ---------------------------------------------------------------------------
  // THE TOKEN, VERIFIED. RFC 9068 section 4's order, as `/admin-api`'s gate
  // makes it: the signature against the DEFAULT realm's key (the debugger's
  // permission exists there only), the expiry, the `typ`, the issuer, the
  // audience, then the permission and the subject.
  //
  // Answers `{ ok, claims, username }` or `{ ok: false, status, code, error,
  // why }`.
  // ---------------------------------------------------------------------------
  // `opts.presented` is true when the token came in on THIS request's
  // Authorization header, and false when it is the one held inside the relying
  // party's own session (#34, 2026-09-15). The difference decides the sender
  // constraints below: a token nobody sent cannot prove possession of anything
  // on a request it was not part of, and requiring it to would turn the two new
  // settings into "the debugger's sign-in stops working", which is not what
  // either of them says. `opts.scheme` is how a presented one was sent.
  verifyAccessToken(token, req, opts?) {
    const { log, realms, helpers, stsCrypto, jwtAccessToken, access, mtls, dpop,
            senderConstraints } = this.deps;
    log.debug("Entering DebuggerServer.verifyAccessToken().");
    const o = opts || {};
    let claims = null;
    try {
      const certPem = realms.run(realms.get(realms.DEFAULT_ID), function () {
        return helpers.STS.certPem;
      });
      claims = stsCrypto.verifyJws(String(token), certPem);
    } catch (e) {
      log.debug("Caught in DebuggerServer.verifyAccessToken(): " +
                ((e && e.message) || e));
      claims = null;
    }
    if (!claims) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Did not verify.");
      return { ok: false, status: 401, code: 'STS-DBG-0003',
               error: 'invalid_token',
               why: 'That access token was not issued by this service, or ' +
                    'its signature does not verify.' };
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Expired.");
      return { ok: false, status: 401, code: 'STS-DBG-0004',
               error: 'invalid_token',
               why: 'That access token expired at ' +
                    new Date(Number(claims.exp) * 1000).toISOString() + '.' };
    }
    const typ = jwtAccessToken.typOf(token);
    if (!jwtAccessToken.isAccessTokenType(typ)) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Not an access " +
                "token.");
      return { ok: false, status: 401, code: 'STS-DBG-0005',
               error: 'invalid_token',
               why: 'RFC 9068 section 4: a JWT access token\'s typ is ' +
                    '"at+jwt", ' +
                    'and this one\'s is ' + (typ ? '"' + typ + '"' : 'absent') +
                    '. An ID Token is not an access token.' };
    }
    const bases = [this.authorizationBaseOf(req)];
    const pinned = helpers.pinnedBaseUrl();
    if (pinned && bases.indexOf(pinned) < 0) {
      bases.push(pinned);
    }
    const issuerOk = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return bases.some(function (base) {
        return jwtAccessToken.isHostedIssuer(claims.iss, base);
      });
    });
    if (!issuerOk) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Wrong issuer.");
      return { ok: false, status: 401, code: 'STS-DBG-0006',
               error: 'invalid_token',
               why: 'That access token names the issuer ' +
                    JSON.stringify(claims.iss || null) + ', and the debugger ' +
                    'accepts tokens from this service\'s default ' +
                    'authorization server at ' + bases.join(' or ') + '.' };
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud.map(String)
      : (claims.aud === undefined || claims.aud === null
        ? [] : [String(claims.aud)]);
    if (audiences.indexOf(access.PERMISSION_BASE) < 0) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Wrong audience.");
      return { ok: false, status: 403, code: 'STS-DBG-0007',
               error: 'insufficient_scope',
               why: 'That access token is addressed to ' +
                    JSON.stringify(claims.aud || null) + ' and not to the ' +
                    'debugger api (' + access.PERMISSION_BASE + '). Ask for ' +
                    'the scope ' + access.PERMISSION_ID + '.' };
    }
    // RFC 8705 SECTION 3.1 (2026-09-13): a certificate-bound token only on a
    // connection made with its certificate, as at `/admin-api`. This listener
    // asks for a certificate and requires none (since #34, 2026-09-15), and a
    // bound token presented without its certificate is refused rather than
    // accepted as a bearer token — which is what the binding exists to prevent.
    const certificateProblem = mtls.checkBinding(claims, req, true);
    if (certificateProblem) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). The certificate " +
                "binding failed.");
      return { ok: false, status: 401, code: 'STS-DBG-0030',
               error: 'invalid_token', why: certificateProblem.description };
    }
    // RFC 9449 SECTION 7 AND #34's TWO SETTINGS (2026-09-15), for a token this
    // request PRESENTED. The binding check above was written for RFC 8705 and
    // the DPoP one was never written, so a bound token was accepted here as a
    // bearer token — the same hole `/admin-api` carried, closed the same way.
    if (o.presented) {
      const boundJkt = dpop.jktOf(claims);
      let proofOk = false;
      if (boundJkt) {
        if (String(o.scheme || '') !== 'dpop') {
          log.debug("Leaving DebuggerServer.verifyAccessToken(). Bound, " +
                    "presented as Bearer.");
          return { ok: false, status: 401, code: 'STS-DBG-0031',
                   error: 'invalid_token',
                   why:
                     'That access token is DPoP-bound (it carries cnf.jkt), ' +
                        'so it must be sent as "Authorization: DPoP <token>" ' +
                        'with a DPoP proof rather than as a Bearer token.' };
        }
        const checked = dpop.verifyProof(req.headers['dpop'], {
          htm: req.method, htu: dpop.htuOf(req), accessToken: String(token),
          expectedJkt: boundJkt, req: req
        });
        if (!checked.ok) {
          log.debug("Leaving DebuggerServer.verifyAccessToken(). The DPoP " +
                    "proof failed.");
          return { ok: false, status: 401,
                   code: checked.errorCode || 'STS-DBG-0032',
                   error: 'invalid_dpop_proof', why: checked.description };
        }
        proofOk = true;
      }
      const required = senderConstraints.accessTokenRefusal({
        where: 'the debugger api',
        boundJkt: boundJkt,
        proofOk: proofOk,
        boundThumbprint: mtls.boundThumbprintOf(claims),
        certificate: !!mtls.peerCertificate(req),
        certificateMatches: !!mtls.boundThumbprintOf(claims) &&
                            mtls.peerVerified(req) &&
                            mtls.presentedThumbprint(req) ===
                              mtls.boundThumbprintOf(claims),
        mtlsAvailable: mtls.available()
      });
      if (required) {
        log.debug("Leaving DebuggerServer.verifyAccessToken(). A required " +
                  "sender constraint was not met.");
        // error-code: none — `code` IS the code, one of STS-OAUTH-0527 to 0531,
        // and the gate's refuse() marks whatever this verdict carries.
        return { ok: false, status: 401, code: required.errorCode,
                 error: required.error, why: required.description };
      }
    }
    const scopes = String(claims.scope || '').split(/\s+/);
    if (scopes.indexOf(access.PERMISSION_NAME) < 0) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). No permission.");
      return { ok: false, status: 403, code: 'STS-DBG-0008',
               error: 'insufficient_scope',
               why: 'That access token does not carry the debugger ' +
                    'permission. It is issued to console administrators ' +
                    'only, so the authorization server leaves it off for ' +
                    'anybody else.' };
    }
    const username = String(claims.username || claims.preferred_username ||
                            claims.sub || '');
    const answer = access.isAdministrator({ kind: 'user', name: username,
                                            authenticated: true,
                                            path: req.originalUrl });
    if (!answer.allowed) {
      log.debug("Leaving DebuggerServer.verifyAccessToken(). Not an " +
                "administrator now.");
      return { ok: false, status: 403, code: answer.code || 'STS-DBG-0009',
               error: 'access_denied', why: answer.why + '.' };
    }
    log.debug("Leaving DebuggerServer.verifyAccessToken(). Accepted.");
    return { ok: true, claims: claims, username: username };
  }

  // BOTH SCHEMES SINCE #34 (2026-09-15), for `/admin-api`'s reason: a
  // DPoP-bound token sent the way RFC 9449 says to send it counted as no token
  // at all here, and the client doing the stricter thing got the least helpful
  // answer.
  bearerOf(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.bearerOf().");
    log.debug("Leaving DebuggerServer.bearerOf().");
    return this.presentedTokenOf(req).token;
  }

  presentedTokenOf(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.presentedTokenOf().");
    const header = String(req.headers.authorization || '');
    const match = /^(Bearer|DPoP)\s+([A-Za-z0-9._~+/=-]+)\s*$/i.exec(header);
    if (!match) {
      log.debug("Leaving DebuggerServer.presentedTokenOf(). Nothing " +
                "presented.");
      return { token: '', scheme: '' };
    }
    log.debug("Leaving DebuggerServer.presentedTokenOf(). " + match[1]);
    return { token: match[2], scheme: match[1].toLowerCase() };
  }

  isLanding(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.isLanding().");
    if (UI_LANDINGS.indexOf(req.path) >= 0) {
      log.debug("Leaving DebuggerServer.isLanding(). A UI landing.");
      return true;
    }
    if (req.path.indexOf(API_PREFIX + '/') !== 0) {
      log.debug("Leaving DebuggerServer.isLanding(). Not the api.");
      return false;
    }
    const rest = req.path.slice(API_PREFIX.length);
    const hit = API_LANDINGS.some(function (one) {
      return one.methods.indexOf(req.method) >= 0 && one.pattern.test(rest);
    });
    log.debug("Leaving DebuggerServer.isLanding(). " + hit);
    return hit;
  }

  // ---------------------------------------------------------------------------
  // THE OAUTH 2.0 LANDING, ported from the debugger's own `client/server.js`
  // with its one property kept: the destination is built from this listener's
  // own base and NOTHING read out of the request decides it (RFC 9700 sections
  // 4.1.1 and 4.10), so it cannot be an open redirector. 303 for both methods.
  // A form_post response is handed on in the FRAGMENT, as the original does.
  // ---------------------------------------------------------------------------
  landingTarget(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.landingTarget().");
    log.debug("Leaving DebuggerServer.landingTarget().");
    return this.debuggerBaseOf(req) + '/oauth2_oidc_2.html';
  }

  // ---------------------------------------------------------------------------
  // THIS SURFACE'S OWN ACCOUNT PAGE AND SIGN-OUT.
  // ---------------------------------------------------------------------------
  signOutForm(session) {
    const { log, websecurity } = this.deps;
    log.debug("Entering DebuggerServer.signOutForm().");
    log.debug("Leaving DebuggerServer.signOutForm().");
    return '<form method="post" action="' + this.esc(SIGNOUT_PATH) + '">' +
           websecurity.field(session ? session.id : '') +
           '<button class="btn" type="submit">Sign out</button></form>';
  }

  // Hand the api child the anchor this service presents NOW, if it differs from
  // the one it was started with — see `debugger_api_process.ts`'s
  // updateAnchor(). A replacement answers this call with the not-ready 502
  // below rather than forwarding it to a child that is exiting.
  checkAnchor() {
    const { log, config, tlsServer, apiProcess } = this.deps;
    log.debug("Entering DebuggerServer.checkAnchor().");
    const now = Date.now();
    if (!config.value('global.https') ||
        now - anchorCheckedAt < ANCHOR_CHECK_MS) {
      log.debug("Leaving DebuggerServer.checkAnchor(). Not due.");
      return false;
    }
    anchorCheckedAt = now;
    let pem = '';
    try {
      const material = tlsServer.serverCertificate();
      pem = material.trustAnchorPem || '';
    } catch (e) {
      log.debug("Caught in DebuggerServer.checkAnchor(): " +
                ((e && e.message) || e));
      pem = '';
    }
    log.debug("Leaving DebuggerServer.checkAnchor().");
    return apiProcess.updateAnchor(pem);
  }

  forward(req, res) {
    const { log, apiProcess, config, http, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering DebuggerServer.forward(). " + req.method + " " +
              req.originalUrl);
    this.checkAnchor();
    if (!apiProcess.ready()) {
      const status = apiProcess.status();
      this.refuse(req, res, 502, 'STS-DBG-0010', 'api_unavailable',
                  'The debugger api is ' + status.state + '. ' +
                  (status.lastError ? 'Last failure: ' + status.lastError :
                   ''));
      log.debug("Leaving DebuggerServer.forward(). Not ready.");
      return;
    }
    const max = Number(config.value('debugger.maxRequestBytes'));
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > max) {
      this.refuse(req, res, 413, 'STS-DBG-0012', 'request_too_large',
                  'That request body is ' + declared +
                  ' bytes and the debugger ' +
                  'forwards at most ' + max + ' (debugger.maxRequestBytes).');
      log.debug("Leaving DebuggerServer.forward(). Too large.");
      return;
    }
    const original = String(req.originalUrl || '/');
    const stripped = original.slice(API_PREFIX.length) || '/';
    const target = stripped.charAt(0) === '/' ? stripped : '/' + stripped;
    const headers = {};
    Object.keys(req.headers).forEach(function (name) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.indexOf(lower) >= 0 || lower === 'cookie' ||
          lower === 'authorization' || lower.indexOf('x-forwarded-') === 0) {
        return;
      }
      headers[name] = req.headers[name];
    });
    const base = this.debuggerBaseOf(req);
    headers['x-forwarded-proto'] = base.split('://')[0];
    headers['x-forwarded-host'] = base.split('://')[1];
    headers['x-forwarded-prefix'] = API_PREFIX;
    headers['x-forwarded-for'] = String((req.socket &&
                                         req.socket.remoteAddress) || '');
    const upstream = http.request({
      socketPath: apiProcess.socketPath(),
      method: req.method,
      path: target,
      headers: headers
    }, function (answer) {
      const out = {};
      const childOrigin = String(apiProcess.status().uiUrl || '');
      Object.keys(answer.headers).forEach(function (name) {
        const lower = name.toLowerCase();
        if (HOP_BY_HOP.indexOf(lower) >= 0 || lower === 'set-cookie' ||
            lower === 'access-control-allow-origin' ||
            lower === 'access-control-allow-credentials') {
          return;
        }
        let value = answer.headers[name];
        if (lower === 'location' && childOrigin &&
            String(value).indexOf(childOrigin) === 0) {
          value = base + String(value).slice(childOrigin.length);
        }
        out[name] = value;
      });
      res.writeHead(answer.statusCode || 502, out);
      answer.pipe(res);
    });
    const timeoutMs = Number(config.value('debugger.proxyTimeoutS')) * 1000;
    upstream.setTimeout(timeoutMs, function () {
      upstream.destroy(new Error('timed out after ' + (timeoutMs / 1000) +
                                 's (debugger.proxyTimeoutS)'));
    });
    upstream.on('error', function (err) {
      log.warn(errorCodes.tag('STS-DBG-0011') + 'debugger: forwarding ' +
               req.method + ' ' + target + ' to the api failed: ' +
               err.message);
      if (!res.headersSent) {
        const timedOut = /timed out/.test(err.message);
        self.refuse(req, res, timedOut ? 504 : 502, 'STS-DBG-0011',
                    'api_unavailable',
                    'The debugger api did not answer: ' + err.message);
      } else {
        res.destroy();
      }
    });
    let seen = 0;
    req.on('data', function (chunk) {
      seen += chunk.length;
      if (seen > max) {
        upstream.destroy(new Error('the request body passed ' + max +
                                   ' bytes (debugger.maxRequestBytes)'));
        req.destroy();
      }
    });
    res.on('close', function () {
      if (!res.writableFinished) {
        upstream.destroy();
      }
    });
    req.pipe(upstream);
    log.debug("Leaving DebuggerServer.forward().");
  }

  servedText(file, stat, stsUrl) {
    const { log, fs } = this.deps;
    log.debug("Entering DebuggerServer.servedText().");
    const key = file + '\n' + stat.mtimeMs + '\n' + stsUrl;
    if (substitutedCache.has(key)) {
      log.debug("Leaving DebuggerServer.servedText(). Cached.");
      return substitutedCache.get(key);
    }
    const text = fs.readFileSync(file, 'utf8').split(STS_URL_PLACEHOLDER)
      .join(stsUrl);
    if (substitutedCache.size >= SUBSTITUTED_CACHE_MAX) {
      substitutedCache.delete(substitutedCache.keys().next().value);
    }
    substitutedCache.set(key, text);
    log.debug("Leaving DebuggerServer.servedText().");
    return text;
  }

  // ===========================================================================
  // LISTEN — from `server.js`'s `listen()`, never at require time, because
  // binding a port can fail and a require that throws takes the service down.
  // A failure is RECORDED and shown on /admin/debugger.
  // ===========================================================================
  listen() {
    const { log, mode, config, fs, path, apiProcess, errorCodes, https,
            tlsServer, http, proxyProtocol, helpers } = this.deps;
    log.debug("Entering DebuggerServer.listen().");
    if (!mode.embedsProtocolDebugger()) {
      startProblem = 'debugger.enabled is ' +
                     String(config.value('debugger.enabled')) +
                     ' and this service is in ' + mode.current() +
                     ' mode, so the debugger is not embedded';
      log.debug("Leaving DebuggerServer.listen(). Not embedded.");
      return { whenReady: Promise.resolve({ port: null, why: startProblem }) };
    }
    const uiProblem = fs.existsSync(path.join(this.uiDirectory(), 'index.html'))
      ? '' : 'the debugger UI is not installed: ' +
             path.join(this.uiDirectory(), 'index.html') + ' does not exist ' +
             '(debugger.uiDirectory)';
    const problem = uiProblem || apiProcess.installedProblem();
    if (problem) {
      startProblem = problem;
      log.error(errorCodes.tag('STS-DBG-0015') + 'debugger: not started — ' +
                problem + '. Everything else this service does is unaffected.');
      log.debug("Leaving DebuggerServer.listen(). Not installed.");
      return { whenReady: Promise.resolve({ port: null, why: problem }) };
    }
    started = true;
    const port = Number(config.value('debugger.port'));
    const useHttps = !!config.value('global.https');
    server = useHttps
      // IT ASKS FOR A CLIENT CERTIFICATE SINCE #34 (2026-09-15), AND REQUIRES
      // NONE. `requestCert` with `rejectUnauthorized: false` is exactly what
      // the main port does: the handshake succeeds either way, and what a
      // certificate is worth is decided per request against the truststore. It
      // was added because `oauth2.accessTokenRequireMtls` covers this listener,
      // and a listener that never asks makes a certificate-bound token
      // impossible to present here rather than merely unusual — which would
      // have been an exemption dressed up as a refusal.
      ? https.createServer(Object.assign({},
                                         tlsServer.clientTruststoreOptions(),
                                         { requestCert: true,
                                           rejectUnauthorized: false }), app)
      : http.createServer(app);
    if (useHttps) {
      // REGISTERED so that a certificate this service replaces at runtime —
      // `build-root` on /admin/pki — is presented here too, the way the main
      // port's is. It also keeps the anchors this listener verifies a client
      // certificate against current, now that it asks for one (#34).
      tlsServer.trustClientCertificatesOn(server, 'the protocol debugger (' +
                                                  port + ')');
    }
    // Before TLS, like the main port's — see common/proxy_protocol.ts.
    proxyProtocol.install(server, {
      label: 'the protocol debugger (' + port + ')', channel: 'http' });
    const whenReady = new Promise<{ port: number }>(function (resolve,
                                                              reject) {
      server.once('error', function (err) {
        listenError = err.message;
        log.error(errorCodes.tag('STS-DBG-0016') + 'debugger: the listener ' +
                  'could not bind port ' + port + ': ' + err.message);
        reject(err);
      });
      server.listen(port, helpers.listenHost(), function () {
        listening = true;
        boundPort = server.address().port;
        resolve({ port: boundPort });
      });
    }).then(function (ready) {
      const tls = useHttps ? tlsServer.serverCertificate() : null;
      return apiProcess.start({
        uiUrl: String(config.value('debugger.publicBaseUrl') || '').trim()
                 .replace(/\/+$/, '') ||
               (useHttps ? 'https' : 'http') + '://localhost:' + ready.port,
        anchorPem: tls ? (tls.trustAnchorPem || tls.certPem) : ''
      }).then(function () {
        return ready;
      });
    });
    log.debug("Leaving DebuggerServer.listen().");
    return { whenReady: whenReady, server: server };
  }

  close() {
    const { log, apiProcess } = this.deps;
    log.debug("Entering DebuggerServer.close().");
    const closing = server;
    server = null;
    log.debug("Leaving DebuggerServer.close().");
    return Promise.all([
      apiProcess.stop(),
      new Promise<void>(function (resolve) {
        if (!closing) {
          resolve();
          return;
        }
        closing.close(function () {
          resolve();
        });
        if (typeof closing.closeAllConnections === 'function') {
          closing.closeAllConnections();
        }
      })
    ]);
  }

  // What `/admin/debugger` and `GET /admin-api/debugger` draw.
  status(): Record<string, any> {
    const { log, mode, config, access, apiProcess } = this.deps;
    log.debug("Entering DebuggerServer.status().");
    log.debug("Leaving DebuggerServer.status().");
    return {
      embedded: mode.embedsProtocolDebugger(),
      setting: String(config.value('debugger.enabled')),
      mode: mode.current(),
      started: started,
      startProblem: startProblem || null,
      listening: listening,
      port: boundPort || Number(config.value('debugger.port')),
      listenError: listenError || null,
      scheme: this.scheme(),
      publicBaseUrl: String(config.value('debugger.publicBaseUrl') || '') ||
                     null,
      uiDirectory: this.uiDirectory(),
      clientId: access.UI_CLIENT_ID,
      resource: access.API_IDENTIFIER,
      permission: access.PERMISSION_ID,
      audience: access.PERMISSION_BASE,
      api: apiProcess.status()
    };
  }

  // THE ROUTES, registered where they always were: the transitional
  // code below calls this at load, at the point the first of them
  // used to be registered, so the route order is unchanged (rule 1).
  registerRoutes(app: RouteApp): void {
    const { log, realms, dpop, authn, oidcRp, errorCodes, express, access,
            apiProcess, websecurity, config, tlsServer, path, fs } = this.deps;
    const self = this;
    log.debug("Entering DebuggerServer.registerRoutes().");
    app.disable('x-powered-by');

    // Every request here is in the DEFAULT realm: this listener has no realm
    // prefix, and everything it reads — the client entry, the sessions, the
    // roster, the signing key — is the default realm's.
    app.use(function inDefaultRealm(req, res, next) {
      realms.run(realms.get(realms.DEFAULT_ID), next);
    });

    // THE CROSS-NODE `jti` RESERVATION FOR A DPoP PROOF (#34, 2026-09-15), the
    // same middleware `oauth2.js` registers above every route on the main app.
    // It reserves the proof's `jti` on arrival and gives it back unless the
    // proof was accepted, so a proof replayed against a second node is refused
    // there too. Below `inDefaultRealm` because the reservation is per realm
    // and this listener's realm is the default one; above the gate, which is
    // what verifies the proof.
    app.use(dpop.proofClaims());

    // THE HEADERS. `frame-ancestors 'none'` for RFC 9700 section 4.14, which is
    // the one CSP clause no page here may drop. The script policy allows the
    // debugger's inline scripts because its pages cannot work without them, and
    // that is tolerable ONLY because this is not the console's origin. It may
    // fetch and post to anything, because reaching another party's endpoints
    // from the browser is what several of its workflows are.
    app.use(function securityHeaders(req, res, next) {
      res.set('Content-Security-Policy',
              "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
              "style-src 'self' 'unsafe-inline'; img-src 'self' data: https: " +
              "http:; font-src 'self' data:; connect-src 'self' https: " +
              "http:; form-action 'self' https: http:; frame-src 'self' " +
              "https: http:; object-src 'none'; base-uri 'self'; " +
              "frame-ancestors 'none'");
      res.set('X-Frame-Options', 'DENY');
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('Referrer-Policy', 'no-referrer');
      next();
    });

    // -------------------------------------------------------------------------
    // THE CALLBACK OF THIS SURFACE'S OWN SIGN-IN.
    // -------------------------------------------------------------------------
    app.get(CALLBACK_PATH, function (req, res) {
      log.debug("Entering GET " + CALLBACK_PATH + ".");
      const pin = authn.cookiesOf(req).sts_pool || '';
      oidcRp.handleCallback(req, res, SURFACE, {
        authorizationBase: self.authorizationBaseOf(req),
        poolPin: pin
      }).then(function (answer) {
        if (res.headersSent) {
          log.debug("Leaving GET " + CALLBACK_PATH + ". Already answered.");
          return;
        }
        if (!answer || !answer.ok) {
          errorCodes.mark(res, errorCodes.codeOf(answer) || 'STS-DBG-0018');
          self.sendPage(res, 400, 'Signing in did not complete',
                        '<p>' +
                        self.esc((answer && answer.why) || 'no reason given') +
                        '</p><p><a class="btn" href="/">Start again</a></p>');
          log.debug("Leaving GET " + CALLBACK_PATH + ". Refused.");
          return;
        }
        res.redirect(303, answer.returnTo || '/');
        log.debug("Leaving GET " + CALLBACK_PATH + ". Signed in.");
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-DBG-0018') + 'debugger: the sign-in ' +
                  'callback threw: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-DBG-0018');
          self.sendPage(res, 500, 'Signing in did not complete',
                        '<p>The sign-in callback failed on this service.</p>');
        }
      });
    });

    app.get('/callback', function (req, res) {
      log.debug("Entering GET /callback.");
      const query = String(req.originalUrl || '').split('?')[1] || '';
      res.redirect(303, self.landingTarget(req) + (query ? '?' + query : ''));
      log.debug("Leaving GET /callback.");
    });

    app.post('/callback',
             express.urlencoded({ extended: false, limit: '64kb' }),
             function (req, res) {
      log.debug("Entering POST /callback.");
      const body = req.body || {};
      const fragment = Object.keys(body).map(function (key) {
        return encodeURIComponent(key) + '=' + encodeURIComponent(body[key]);
      }).join('&');
      res.redirect(303,
                   self.landingTarget(req) + (fragment ? '#' + fragment : ''));
      log.debug("Leaving POST /callback.");
    });

    // -------------------------------------------------------------------------
    // THE GATE.
    // -------------------------------------------------------------------------
    app.use(oidcRp.renewal(SURFACE));

    app.use(function gate(req, res, next) {
      log.debug("Entering the debugger gate. " + req.method + " " + req.path);
      if (req.path === CALLBACK_PATH || self.isLanding(req)) {
        log.debug("Leaving the debugger gate. A landing path is not gated.");
        next();
        return;
      }
      const presentation = self.presentedTokenOf(req);
      const presented = presentation.token;
      if (presented) {
        const verdict = self.verifyAccessToken(presented, req,
                                               { presented: true,
                                                 scheme: presentation.scheme });
        if (!verdict.ok) {
          // error-code: none — refuse() marks verdict.code, the STS-DBG code
          // verifyAccessToken() chose for this failure.
          self.refuse(req, res, verdict.status, verdict.code, verdict.error,
                      verdict.why,
                      'Bearer error="' + verdict.error + '", scope="' +
                      access.PERMISSION_ID + '"');
          log.debug("Leaving the debugger gate. Bearer refused.");
          return;
        }
        req.debuggerUser = verdict.username;
        req.debuggerSession = null;
        log.debug("Leaving the debugger gate. Bearer accepted.");
        next();
        return;
      }
      const session = oidcRp.sessionFor(req, SURFACE);
      if (!session) {
        if (!self.wantsJson(req) &&
            (req.method === 'GET' || req.method === 'HEAD')) {
          const begun = oidcRp.beginSignIn(req, res, SURFACE, {
            returnTo: req.originalUrl,
            fallback: '/',
            callbackBase: self.debuggerBaseOf(req),
            authorizationBase: self.authorizationBaseOf(req)
          });
          if (begun && begun.ok === false && !res.headersSent) {
            errorCodes.mark(res, errorCodes.codeOf(begun) || 'STS-DBG-0017');
            self.sendPage(res, begun.reason === 'no-client' ? 500 : 403,
                          'The debugger cannot sign you in',
                          '<p>' + self.esc(begun.why) + '</p>');
          }
          log.debug("Leaving the debugger gate. Sent to sign in.");
          return;
        }
        self.refuse(req, res, 401, 'STS-DBG-0002', 'unauthorized',
                    'The debugger needs a signed-in console administrator: ' +
                    'open it in a browser, or send an access token carrying ' +
                    access.PERMISSION_ID + ' as Authorization: Bearer.',
                    'Bearer scope="' + access.PERMISSION_ID + '"');
        log.debug("Leaving the debugger gate. No session.");
        return;
      }
      const tokens = session.rpTokens || {};
      const verdict = self.verifyAccessToken(tokens.accessToken || '', req);
      if (!verdict.ok) {
        // THE AUDIENCE IS ONE OF THEM. The session's token was asked for with
        // the permission, so a token addressed anywhere else is the
        // authorization server having taken the permission off (and with it the
        // only audience the request named) — the same answer as a missing
        // scope.
        if (verdict.code === 'STS-DBG-0007' ||
            verdict.code === 'STS-DBG-0008' ||
            verdict.code === 'STS-DBG-0009' ||
            verdict.code === 'STS-DBG-0024') {
          // SIGNED IN AND NOT AN ADMINISTRATOR: the one refusal a person meets
          // here in the ordinary course, drawn as a page that says who they are
          // and how to leave rather than as a token error.
          //
          // THE TOKEN'S FAILURE IS NOT THE REASON, so the person is asked about
          // directly. A permission taken off at issuance changes the token's
          // audience first, so what verifyAccessToken() reports is "wrong
          // audience" (0007) whether the cause was an empty roster (0024) or a
          // person holding no role (0009) — and those two need different pages.
          const reason = access.isAdministrator({
            kind: 'user', name: session.user.username, authenticated: true,
            path: req.originalUrl });
          const why = reason.allowed ? verdict : reason;
          errorCodes.mark(res, why.code || verdict.code);
          if (self.wantsJson(req)) {
            // error-code: none — marked two lines up with the reason's code.
            res.status(403).set('Cache-Control', 'no-store')
               .json({ error: 'access_denied', error_description: why.why });
          } else {
            // error-code: none — marked above with verdict.code.
            self.sendPage(res, 403, 'The debugger is for administrators',
                          (why.code === 'STS-DBG-0024'
                            ? '<p><strong>Nobody is an administrator ' +
                              'yet.</strong> While neither console role ' +
                              'group has a member the admin console opens to ' +
                              'everybody so that the first role can be ' +
                              'granted; the debugger does not. Grant ' +
                              'somebody Admin Read or Admin Write on ' +
                              '<code>/admin/rbac</code>, then sign in ' +
                              'again.</p>'
                            : '') +
                          '<p>You are signed in as <code>' +
                          self.esc(session.user.username) +
                          '</code>. The identity ' +
                          'protocol debugger is available to console ' +
                          'administrators — members of the ' +
                          'Admin Read or Admin Write group — ' +
                          (reason.allowed
                            ? 'and this account IS one now, but its token ' +
                              'was issued before it ' +
                              'was, without the debugger ' +
                              'permission. Sign out and sign in again.</p>'
                            : 'and this account is neither, so the ' +
                              'authorization server issued its token without ' +
                              'the debugger permission.</p>') +
                          '<p class="muted">' + self.esc(why.why) + '</p>' +
                          self.signOutForm(session));
          }
          log.debug("Leaving the debugger gate. Not an administrator.");
          return;
        }
        // error-code: none — refuse() marks verdict.code, from
        // verifyAccessToken().
        self.refuse(req, res, verdict.status, verdict.code, verdict.error,
                    verdict.why);
        log.debug("Leaving the debugger gate. The session's token refused.");
        return;
      }
      req.debuggerUser = verdict.username;
      req.debuggerSession = session;
      req.debuggerToken = tokens.accessToken;
      log.debug("Leaving the debugger gate. Session accepted.");
      next();
    });

    app.get(ACCOUNT_PATH, function (req, res) {
      log.debug("Entering GET " + ACCOUNT_PATH + ".");
      const session = req.debuggerSession;
      const status = apiProcess.status();
      self.sendPage(res, 200, 'Identity protocol debugger',
        '<p>Signed in as <code>' + self.esc(req.debuggerUser) +
        '</code> through this service\'s authorization server, as the client ' +
        '<code>' + self.esc(access.UI_CLIENT_ID) + '</code>. The api at ' +
        '<code>/api</code> is reached with an access token carrying ' +
        '<code>' + self.esc(access.PERMISSION_ID) +
        '</code>, which is issued to ' +
        'console administrators only.</p>' +
        '<p>The api process is <strong>' + self.esc(status.state) +
        '</strong>' +
        (status.allowList
          ? ', allowed to dial ' +
            self.esc(String(status.allowedRanges.length)) +
            ' address range(s) — this service\'s own and ' +
            '<code>debugger.allowedDestinations</code>.'
          : ', with no allow-list (development mode).') + '</p>' +
        '<p><a class="btn" href="/">Open the debugger</a></p>' +
        (session ? self.signOutForm(session) :
         '<p class="muted">This request ' +
          'presented a bearer token, so there is no session to sign out ' +
          'of.</p>'));
      log.debug("Leaving GET " + ACCOUNT_PATH + ".");
    });

    app.post(SIGNOUT_PATH,
             express.urlencoded({ extended: false, limit: '8kb' }),
             function (req, res) {
      log.debug("Entering POST " + SIGNOUT_PATH + ".");
      const session = req.debuggerSession;
      const csrf = websecurity.checkCsrf(session ? session.id : '', req.body);
      if (!session || !csrf.ok) {
        self.refuse(req, res, 403, 'STS-DBG-0021', 'csrf',
                    'That sign-out did not come ' +
                    'from a page this debugger drew. ' +
                    ((csrf && csrf.detail) || ''));
        log.debug("Leaving POST " + SIGNOUT_PATH + ". Refused.");
        return;
      }
      const parent = String(session.derivedFrom || '');
      const username = session.user.username;
      oidcRp.endSessionFor(req, res, SURFACE,
                           'the Sign out button on the protocol debugger');
      const signOnEnded = parent
        ? !!authn.endSessionById(parent, 'the Sign out button on the ' +
                                         'protocol debugger')
        : false;
      if (signOnEnded) {
        authn.clearSessionCookie(res);
      }
      log.info('debugger: ' + username + ' signed out' +
               (signOnEnded ? ', with the sign-on session behind it.' : '.'));
      self.sendPage(res, 200, 'Signed out',
                    '<p>You are signed out of the debugger' +
                    (signOnEnded ?
                     ', and of the sign-on session it was built on' : '') +
                    '.</p><p><a class="btn" href="/">Sign in again</a></p>');
      log.debug("Leaving POST " + SIGNOUT_PATH + ".");
    });

    // The certificate this listener presents, which the debugger's TLS pages
    // fetch from the origin they were served by.
    app.get('/tls/server-certificate', function (req, res) {
      log.debug("Entering GET /tls/server-certificate.");
      if (!config.value('global.https')) {
        errorCodes.mark(res, 'STS-DBG-0019');
        res.status(404).json({ error: 'This listener is not serving TLS, so ' +
                                      'it has no certificate to publish.',
                               code: 'ENOTLS' });
        log.debug("Leaving GET /tls/server-certificate. Plain.");
        return;
      }
      const material = tlsServer.serverCertificate();
      res.set('Content-Type', 'application/x-pem-file')
         .set('Cache-Control', 'no-store')
         .send([material.certPem].concat(material.chainPem || []).join(''));
      log.debug("Leaving GET /tls/server-certificate.");
    });

    app.use(API_PREFIX, this.forward.bind(this));

    app.use(function staticSite(req, res) {
      log.debug("Entering staticSite(). " + req.path);
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        errorCodes.mark(res, 'STS-DBG-0022');
        res.status(405).set('Allow', 'GET, HEAD').type('text/plain')
           .send('The debugger\'s pages are read with GET.\n');
        log.debug("Leaving staticSite(). Method.");
        return;
      }
      const root = self.uiDirectory();
      let wanted = '/';
      try {
        wanted = decodeURIComponent(req.path);
      } catch (e) {
        log.debug("Caught in staticSite(): " + ((e && e.message) || e));
        wanted = '';
      }
      if (wanted.slice(-1) === '/') {
        wanted += 'index.html';
      }
      const file = path.resolve(root, '.' + wanted);
      let stat = null;
      if (wanted && wanted.indexOf('\0') < 0 &&
          (file === root || file.indexOf(root + path.sep) === 0)) {
        try {
          stat = fs.statSync(file);
        } catch (e) {
          log.debug("Caught in staticSite(): " + ((e && e.message) || e));
          stat = null;
        }
      }
      if (!stat || !stat.isFile()) {
        errorCodes.mark(res, 'STS-DBG-0019');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('The debugger has no page at ' + req.path + '.\n');
        log.debug("Leaving staticSite(). Not found.");
        return;
      }
      const ext = path.extname(file).toLowerCase();
      res.set('Content-Type', CONTENT_TYPES[ext] || 'application/octet-stream');
      res.set('Cache-Control', 'no-cache');
      if (SUBSTITUTED.indexOf(ext) >= 0) {
        res.send(self.servedText(file, stat, self.authorizationBaseOf(req)));
        log.debug("Leaving staticSite(). Substituted.");
        return;
      }
      res.set('Content-Length', String(stat.size));
      if (req.method === 'HEAD') {
        res.end();
      } else {
        fs.createReadStream(file).pipe(res);
      }
      log.debug("Leaving staticSite(). Sent.");
    });
    log.debug("Leaving DebuggerServer.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const debuggerServer = new DebuggerServer({
  fs: fs,
  http: http,
  https: https,
  path: path,
  express: express,
  helpers: helpers,
  log: log,
  PORT: PORT,
  config: config,
  mode: mode,
  realms: realms,
  stsCrypto: stsCrypto,
  errorCodes: errorCodes,
  proxyProtocol: proxyProtocol,
  websecurity: websecurity,
  oidcRp: oidcRp,
  authn: authn,
  jwtAccessToken: jwtAccessToken,
  mtls: mtls,
  dpop: dpop,
  senderConstraints: senderConstraints,
  tlsServer: tlsServer,
  access: access,
  apiProcess: apiProcess
});

// ===========================================================================
// THE APP.
// ===========================================================================
const app = express();

debuggerServer.registerRoutes(app);

// ---------------------------------------------------------------------------
// THE API, FORWARDED.
//
// Bytes in and bytes out: no body parser runs on this path, so the api sees
// exactly what the browser sent. The COOKIE and AUTHORIZATION headers are
// dropped — the child needs neither and must not hold an administrator's
// session or token — and `X-Forwarded-Proto`, `-Host` and `-Prefix` say where
// the browser was, which the api uses where it builds an address for one.
// A `Location` naming the child's configured origin is rewritten to the one
// this request arrived at, so a SAML or WS-Federation landing redirects to
// the host the browser is actually using.
// ---------------------------------------------------------------------------
// How often a forwarded call may ask whether this service's trust anchor has
// moved. `serverCertificate()` verifies the chain it answers about, so asking
// on every call would put that work on the hot path for a change an operator
// makes a few times in a deployment's life.
const ANCHOR_CHECK_MS = 5000;
let anchorCheckedAt = 0;

// ---------------------------------------------------------------------------
// THE STATIC SITE.
// ---------------------------------------------------------------------------
const substitutedCache = new Map();
const SUBSTITUTED_CACHE_MAX = 400;

export = {
  DebuggerServer: DebuggerServer,
  listen: debuggerServer.listen.bind(debuggerServer) as
    DebuggerServer['listen'],
  close: debuggerServer.close.bind(debuggerServer) as DebuggerServer['close'],
  status: debuggerServer.status.bind(debuggerServer) as
    DebuggerServer['status'],
  // For tests/debugger_server.js, which drives the app in process.
  app: app,
  verifyAccessToken: debuggerServer.verifyAccessToken.bind(debuggerServer) as
    DebuggerServer['verifyAccessToken'],
  checkAnchor: debuggerServer.checkAnchor.bind(debuggerServer) as
    DebuggerServer['checkAnchor'],
  isLanding: debuggerServer.isLanding.bind(debuggerServer) as
    DebuggerServer['isLanding'],
  authorizationBaseOf:
    debuggerServer.authorizationBaseOf.bind(debuggerServer) as
      DebuggerServer['authorizationBaseOf'],
  debuggerBaseOf: debuggerServer.debuggerBaseOf.bind(debuggerServer) as
    DebuggerServer['debuggerBaseOf'],
  STS_URL_PLACEHOLDER: STS_URL_PLACEHOLDER
};
