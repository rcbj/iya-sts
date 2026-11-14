// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// `/portal`, and usable by console administrators only. Eight decisions
// were put to him before anything was written and each took the recommended
// answer; they are the design and `debugger/CLAUDE.md` argues them. The
// four that shape this file:
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
//   * THE GATE: this surface's relying-party session, named by its cookie,
//     and whether the person it belongs to is STILL a console administrator —
//     asked on every request. NOTHING ELSE the request carries is read: since
//     #1717 (2026-11-13) there is no access-token path, because the debugger
//     sends `Authorization` (and `DPoP`) to its own api as the work it does —
//     a UserInfo Bearer token, introspection's Basic credentials, SCIM's and
//     GNAP's own — and a gate that read that header as its credential refused
//     the debugger's own calls, and the forwarder then stripped it;
//   * `/api/*` forwarded, `/_sts/*` this surface's own account and sign-out
//     pages, and everything else the debugger's built static site.
//
// A browser with no session is sent through the authorization code flow — as
// a CONFIDENTIAL client, `private_key_jwt`, whose tokens never leave this
// process — and comes back to the page it asked for; a call with none gets
// 401. A signed-in person who is not an administrator gets a page saying so,
// which is the one refusal here a person meets in the ordinary course.
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
// (`DebuggerServerDeps`). Since #50's R2 the composition root builds the
// instance; the module's old names are FACADES forwarding to it, for the
// callers that are not converted, and a process without the root builds a
// default at load.
// `DebuggerServer` is exported beside them for that root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, on this listener's
// own app, which `DebuggerServer.wire()` calls when the instance is installed
// — standalone, at load, where the first route used to be registered — so
// rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import fs = require('fs');
import http = require('http');
import http2 = require('http2');
import https = require('https');
import path = require('path');
import express = require('express');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log, PORT } = helpers;
import config = require('../common/config');
import mode = require('../common/mode');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
// The PROXY protocol v2 reader (2026-09-14, #46), a LIBRARY, installed in
// listen() like every TCP listener's.
import proxyProtocol = require('../common/proxy_protocol');
import Http2Framing = require('../common/http2_framing');
import Http2Express = require('../common/http2_express');
import ConnectRefusal = require('../common/connect_refusal');
import ParserRefusal = require('../common/parser_refusal');
import AlertClose = require('../tls/alert_close');
import audit = require('../common/audit');
import websecurity = require('../common/websecurity');
import oidcRp = require('../common/oidc_rp');
import authn = require('../authn/authn');
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
/**
 * The literal the debugger's embedded build carries where this service's
 * base URL goes, replaced in served HTML and JavaScript.
 */
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
  errorCodes: typeof errorCodes;
  proxyProtocol: typeof proxyProtocol;
  websecurity: typeof websecurity;
  oidcRp: typeof oidcRp;
  authn: typeof authn;
  tlsServer: typeof tlsServer;
  access: typeof access;
  apiProcess: typeof apiProcess;
}

type RouteApp = typeof app;

/**
 * The embedded identity protocol debugger's listener, sign-in and gate.
 *
 * It serves the debugger's static UI and forwards `/api` to the api child
 * process on an express app and port of its own. Every request but the
 * landing paths needs this surface's sign-in session, for a person who is a
 * console administrator; nothing else the request carries is read.
 */
class DebuggerServer {
  /**
   * Builds the server over the given modules.
   *
   * @param deps - the node and express modules and the service modules the
   *   listener reads
   */
  constructor(private readonly deps: DebuggerServerDeps) {
    deps.log.debug("Entering DebuggerServer.constructor().");
    deps.log.debug("Leaving DebuggerServer.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the load-time default instance is built from.
   *
   * @returns the real modules
   */
  static defaultDeps(): DebuggerServerDeps {
    helpers.log.debug("Entering DebuggerServer.defaultDeps().");
    helpers.log.debug("Leaving DebuggerServer.defaultDeps().");
    return {
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
      errorCodes: errorCodes,
      proxyProtocol: proxyProtocol,
      websecurity: websecurity,
      oidcRp: oidcRp,
      authn: authn,
      tlsServer: tlsServer,
      access: access,
      apiProcess: apiProcess
    };
  }

  // What loading this module did with its instance before #50's R2, now
  // done by the slot for whichever instance is installed: the listener's
  // own app (below) gets its routes.
  /**
   * Registers the installed instance's routes on the listener's own app.
   *
   * @param instance - the installed instance
   */
  static wire(instance: DebuggerServer): void {
    helpers.log.debug("Entering DebuggerServer.wire().");
    instance.registerRoutes(app);
    helpers.log.debug("Leaving DebuggerServer.wire().");
  }

  /**
   * Escapes text for HTML.
   *
   * @param text - the text; null and undefined become empty
   * @returns the escaped text
   */
  esc(text) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.esc().");
    log.debug("Leaving DebuggerServer.esc().");
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Returns the directory of the debugger's static UI,
   * `debugger.uiDirectory`, resolved against the package root.
   *
   * @returns the absolute path
   */
  uiDirectory() {
    const { log, config, path } = this.deps;
    log.debug("Entering DebuggerServer.uiDirectory().");
    const raw = String(config.value('debugger.uiDirectory') || '').trim();
    log.debug("Leaving DebuggerServer.uiDirectory().");
    return path.isAbsolute(raw) ? raw : path.join(PACKAGE_ROOT, raw);
  }

  /**
   * Returns the listener's scheme, https when `global.https` is set.
   *
   * @returns `https` or `http`
   */
  scheme() {
    const { log, config } = this.deps;
    log.debug("Entering DebuggerServer.scheme().");
    log.debug("Leaving DebuggerServer.scheme().");
    return config.value('global.https') ? 'https' : 'http';
  }

  // The Host a request arrived with, refused when it is not a plain authority —
  // it goes into a redirect and into a page, so it may not carry anything else.
  /**
   * Returns the request's Host header when it is a plain authority, and
   * `localhost:<debugger.port>` otherwise.
   *
   * @param req - the express request
   * @returns the host and optional port
   */
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
  /**
   * Returns the debugger's own origin: `debugger.publicBaseUrl` when set,
   * otherwise as the browser reached it.
   *
   * @param req - the express request
   * @returns the base URL, with no trailing slash
   */
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
  /**
   * Returns the authorization server's base for a request to the debugger:
   * the pinned public base URL, or the same host on the main port.
   *
   * @param req - the express request
   * @returns the base URL
   */
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

  /**
   * Says whether a refusal should be answered in JSON: always under `/api`,
   * and otherwise when the client accepts JSON and not HTML.
   *
   * @param req - the express request
   * @returns true for JSON
   */
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
  /**
   * Sends one of this surface's own script-free pages, `no-store`.
   *
   * @param res - the express response
   * @param status - the HTTP status
   * @param title - the page title, escaped here
   * @param inner - the body, as HTML
   */
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

  /**
   * Answers a refusal, marked with its error code, as JSON or as a page.
   *
   * @param req - the express request
   * @param res - the express response
   * @param status - the HTTP status
   * @param code - the STS error code to record
   * @param error - the OAuth-style error value
   * @param why - the sentence for the caller
   * @param challenge - optional; a WWW-Authenticate value
   */
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
  // THE SESSION'S VERDICT (#1717, 2026-11-13). The relying-party session is
  // the credential, and `oidc_rp.ts` has already decided it is current —
  // signed in, unexpired, its sign-on session still there (`renewal()`). What
  // is left is who it belongs to, asked AGAIN on every request so a console
  // role revoked after the person signed in stops working now rather than
  // when the session runs out. The access token the session holds is not
  // consulted: it is this client's own, the debugger's api never sees it, and
  // there is no separate api for it to be addressed to any more.
  // ---------------------------------------------------------------------------
  /**
   * Decides whether a relying-party session's person may use the debugger
   * now.
   *
   * @param session - the relying-party session
   * @param req - the express request
   * @returns `{ ok: true, username }` or `{ ok: false, status, code, error,
   *   why }`
   */
  sessionVerdict(session, req) {
    const { log, access } = this.deps;
    log.debug("Entering DebuggerServer.sessionVerdict().");
    const username = String((session && session.user &&
                             session.user.username) || '');
    const answer = access.isAdministrator({ kind: 'user', name: username,
                                            authenticated: true,
                                            sessionId: session && session.id,
                                            path: req.originalUrl });
    if (!answer.allowed) {
      log.debug("Leaving DebuggerServer.sessionVerdict(). Not an " +
                "administrator.");
      return { ok: false, status: 403, code: answer.code || 'STS-DBG-0009',
               error: 'access_denied', why: answer.why + '.' };
    }
    log.debug("Leaving DebuggerServer.sessionVerdict(). Allowed.");
    return { ok: true, username: username };
  }

  /**
   * Says whether a request is to one of the landing paths a flow the
   * debugger started returns to, which the gate lets through.
   *
   * @param req - the express request
   * @returns true for a landing path and method
   */
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
  /**
   * Returns where the OAuth 2.0 landing sends the browser, built from this
   * listener's own base and nothing read from the request.
   *
   * @param req - the express request
   * @returns the URL of the debugger's OAuth page
   */
  landingTarget(req) {
    const { log } = this.deps;
    log.debug("Entering DebuggerServer.landingTarget().");
    log.debug("Leaving DebuggerServer.landingTarget().");
    return this.debuggerBaseOf(req) + '/oauth2_oidc_2.html';
  }

  // ---------------------------------------------------------------------------
  // THIS SURFACE'S OWN ACCOUNT PAGE AND SIGN-OUT.
  // ---------------------------------------------------------------------------
  /**
   * Draws the sign-out form, with its CSRF field.
   *
   * @param session - the relying-party session, or null
   * @returns the HTML form
   */
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
  /**
   * Hands the api child the trust anchor this service presents now, if it
   * changed, at most once every few seconds.
   *
   * @returns true when the child is being replaced
   */
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

  /**
   * Forwards an `/api` request to the api child over its unix socket.
   *
   * Hop-by-hop headers and cookies are not forwarded — `Authorization` and
   * `DPoP` are, untouched, because they are the debugger's own (#1717); the
   * body is bounded by `debugger.maxRequestBytes` and the call by
   * `debugger.proxyTimeoutS`. A child that is not ready is answered 502.
   * @param req - the express request
   * @param res - the express response
   */
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
    // THE HOST IS THE AUTHORITY (#407; RFC 9113 section 8.3.1), asked again
    // here rather than trusted from the app's `init`, because the api
    // process believes the `host` this one forwards.
    const asked = Object.assign({}, req.headers);
    if (Http2Express.hostProblem(asked)) {
      this.refuse(req, res, 400, 'STS-HTTP-0024', 'invalid_request',
                  'The request\'s :authority and Host name different hosts ' +
                  '(RFC 9113 section 8.3.1).');
      log.debug("Leaving DebuggerServer.forward(). Host mismatch.");
      return;
    }
    const original = String(req.originalUrl || '/');
    const stripped = original.slice(API_PREFIX.length) || '/';
    const target = stripped.charAt(0) === '/' ? stripped : '/' + stripped;
    const headers = {};
    Object.keys(asked).forEach(function (name) {
      const lower = name.toLowerCase();
      // An HTTP/2 request's pseudo-headers (`:path` and the rest, #407) are
      // no HTTP/1.1 field name: node's client throws on one; `:authority`
      // is in `host` by now.
      // `Authorization` and `DPoP` GO THROUGH (#1717): the debugger sends
      // them to its api as the request it is debugging — a UserInfo Bearer
      // token, introspection's Basic credentials, SCIM's and GNAP's own.
      // The cookie does not: it carries this service's sessions, which the
      // api must never hold.
      if (HOP_BY_HOP.indexOf(lower) >= 0 || lower === 'cookie' ||
          lower.indexOf('x-forwarded-') === 0 || lower.charAt(0) === ':') {
        return;
      }
      headers[name] = asked[name];
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

  /**
   * Returns a static HTML or JavaScript file with the placeholder replaced
   * by this service's URL, cached by file, modification time and URL.
   *
   * @param file - the file path
   * @param stat - the file's stat
   * @param stsUrl - the value for the placeholder
   * @returns the text
   */
  servedText(file, stat, stsUrl) {
    const { log, fs } = this.deps;
    log.debug("Entering DebuggerServer.servedText().");
    const key = file + '\n' + stat.mtimeMs + '\n' + stsUrl;
    if (substitutedCache.has(key)) {
      substitutedCount.hit();
      log.debug("Leaving DebuggerServer.servedText(). Cached.");
      return substitutedCache.get(key);
    }
    substitutedCount.miss();
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
  /**
   * Binds the debugger's listener and then starts the api child; called from
   * server.js's listen(), never at require time.
   *
   * When the debugger is not embedded or not installed nothing is bound and
   * the reason is recorded. A failure to bind is recorded and rejects
   * `whenReady`.
   * @returns `{ whenReady, server? }`, where whenReady resolves to the bound
   *   port
   */
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
      //
      // Its own pair since #423 (debugger.disableOptionalClientCertificate,
      // debugger.requireClientCertificate), and the listeners' TLS policy.
      //
      // HTTP/2 beside HTTP/1.1 since #407, as on the main port: offered
      // unless listenerDebugger.http2 or http.http2 says not, which
      // tls_server.js applies to the server's ALPN offer.
      ? http2.createSecureServer(Object.assign({ allowHTTP1: true },
          tlsServer.clientTruststoreOptions(tlsServer.policyFor('debugger')),
          tlsServer.clientAuthOptions(
            tlsServer.policyFor('debugger').clientAuth)), app)
      // `clientTruststoreOptions()` carries `tls_server.js`'s
      // protocolOptions() — the floor, the ciphers, the groups and the
      // signature algorithms — so this listener is held to the main port's
      // policy from its first handshake (#212's tlsfuzzer run drives it).
      : http.createServer(app);
    if (useHttps) {
      // REGISTERED so that a certificate this service replaces at runtime —
      // `build-root` on /admin/pki — is presented here too, the way the main
      // port's is. It also keeps the anchors this listener verifies a client
      // certificate against current, now that it asks for one (#34).
      tlsServer.trustClientCertificatesOn(server, 'the protocol debugger (' +
                                                  port + ')', undefined,
                                          { kind: 'debugger' });
      // Under paranoid PKI mode it holds a client certificate as the main port
      // does, with revocation, and `app`'s first middleware waits (#1360).
      tlsServer.holdConnectionsOn(server, 'the protocol debugger (' + port +
                                          ')');
      // NO shared session-ticket key (tls/session_tickets.ts): this
      // listener asks for a client certificate, and a session resumed on
      // another node has no remembered chain there — server.js says why.
    }
    // ITS OWN CONNECTION POOLING (#429): listenerDebugger.keepAliveTimeoutS
    // and the rest, inheriting http.*, over https or http alike.
    tlsServer.registerHttpListener(server, 'debugger');
    // An HTTP/2 body with no length is still a body (common/http2_framing.ts).
    server.prependListener('request', Http2Framing.markFramedBody);
    // A CONNECT is answered 501, as on the main port (#1304).
    ConnectRefusal.install(server, 'the protocol debugger (' + port + ')');
    ParserRefusal.install(server, 'the protocol debugger (' + port + ')');
    // A connection that fails at the TLS layer keeps its alert, as on the
    // main port (tls/alert_close.ts; a no-op over plain HTTP).
    AlertClose.install(server, 'the protocol debugger (' + port + ')');
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

  /**
   * Stops the api child and closes the listener.
   *
   * @returns a promise settled when both have gone
   */
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
  /**
   * Reports what the listener and the api process are doing, for
   * `/admin/debugger` and `GET /admin-api/debugger`.
   *
   * @returns the status
   */
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
      api: apiProcess.status()
    };
  }

  // THE ROUTES, registered where they always were: `wire()` calls this on
  // the listener's own app when the instance is installed (standalone, at
  // load, at the point the first of them used to be registered), so the
  // route order is unchanged (rule 1).
  /**
   * Registers the listener's middleware and routes: the default realm, the
   * gate, the sign-in and sign-out, the `/api` forward
   * and the static UI.
   *
   * @param app - the listener's own express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, realms, authn, oidcRp, errorCodes, express, access,
            apiProcess, websecurity, config, tlsServer, path, fs } = this.deps;
    const self = this;
    log.debug("Entering DebuggerServer.registerRoutes().");
    app.disable('x-powered-by');

    // Every request here is in the DEFAULT realm: this listener has no realm
    // prefix, and everything it reads — the client entry, the sessions, the
    // roster, the signing key — is the default realm's.
    // An HTTP parser reads past a socket's pause, so a request waits here for
    // what `holdConnectionsOn()` is still asking of its certificate (#1360).
    app.use(function settledCertificate(req, res, next) {
      require('../tls/tls_server').settledRequest(req).then(function () {
        next();
      }, next);
    });
    app.use(function inDefaultRealm(req, res, next) {
      realms.run(realms.get(realms.DEFAULT_ID), next);
    });
    // A cookie is scoped to a host and not a port, so this listener reads the
    // main port's by the same wire names (#1441).
    app.use(require('../common/cookie_wire').middleware());

    // NO DPoP `jti` RESERVATION HERE (#1717, 2026-11-13). `dpop.proofClaims()`
    // was registered on this app for the gate's access-token path (#34), and
    // it reserved the `jti` of every DPoP proof arriving — including the
    // proofs the DEBUGGER sends through its api to the server it is testing,
    // which is very often this service. That server then saw its own proof as
    // a replay. The gate reads no token now, so it verifies no proof and
    // reserves none.

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
      // NOT `Authorization`, NOT `DPoP`, NOT a client certificate (#1717):
      // those belong to the debugger's own calls and pass through untouched.
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
          // A promise under FAPI 1.0 Advanced (#139); a value otherwise.
          const refusedIfSo = function (answer: any): void {
            log.debug("Entering refusedIfSo().");
            if (answer && answer.ok === false && !res.headersSent) {
              errorCodes.mark(res, errorCodes.codeOf(answer) ||
                                   'STS-DBG-0017');
              self.sendPage(res, answer.reason === 'no-client' ? 500 : 403,
                            'The debugger cannot sign you in',
                            '<p>' + self.esc(answer.why) + '</p>');
            }
            log.debug("Leaving refusedIfSo().");
          };
          if (begun && typeof begun.then === 'function') {
            begun.then(refusedIfSo);
          } else {
            refusedIfSo(begun);
          }
          log.debug("Leaving the debugger gate. Sent to sign in.");
          return;
        }
        // NO `WWW-Authenticate`: there is no scheme a caller could answer
        // with, only a browser sign-in, and the header would name one.
        self.refuse(req, res, 401, 'STS-DBG-0002', 'unauthorized',
                    'The debugger needs a signed-in console administrator: ' +
                    'open it in a browser and sign in. It accepts no access ' +
                    'token, and the Authorization header is passed to the ' +
                    'debugger\'s api as part of the call rather than read.');
        log.debug("Leaving the debugger gate. No session.");
        return;
      }
      const verdict = self.sessionVerdict(session, req);
      if (!verdict.ok) {
        // SIGNED IN AND NOT AN ADMINISTRATOR: the one refusal a person meets
        // here in the ordinary course, drawn as a page that says who they are
        // and how to leave rather than as an error.
        errorCodes.mark(res, verdict.code);
        if (self.wantsJson(req)) {
          // error-code: none — marked two lines up with the verdict's code.
          res.status(403).set('Cache-Control', 'no-store')
             .json({ error: 'access_denied', error_description: verdict.why });
        } else {
          // error-code: none — marked above with verdict.code.
          self.sendPage(res, 403, 'The debugger is for administrators',
                        (verdict.code === 'STS-DBG-0024'
                          ? '<p><strong>Nobody is an administrator ' +
                            'yet.</strong> While neither console role ' +
                            'group has a member the admin console opens to ' +
                            'everybody so that the first role can be ' +
                            'granted; the debugger does not. Grant ' +
                            'somebody Admin Read or Admin Write on ' +
                            '<code>/admin/rbac</code>, then sign in ' +
                            'again.</p>'
                          : '') +
                        (verdict.code === 'STS-DBG-0033'
                          ? '<p><strong>The console has not been claimed ' +
                            'yet.</strong> This is the bootstrap ' +
                            'administrator, and in product mode its roles ' +
                            'open the admin console alone, from a ' +
                            'password sign-in, until it has signed in to ' +
                            '<code>/admin</code> with its password once. ' +
                            'Do that, then sign in here again.</p>'
                          : '') +
                        '<p>You are signed in as <code>' +
                        self.esc(session.user.username) +
                        '</code>. The identity ' +
                        'protocol debugger is available to console ' +
                        'administrators — members of the ' +
                        'Admin Read or Admin Write group — and this account ' +
                        'is not one now.</p>' +
                        '<p class="muted">' + self.esc(verdict.why) + '</p>' +
                        self.signOutForm(session));
        }
        log.debug("Leaving the debugger gate. Not an administrator.");
        return;
      }
      req.debuggerUser = verdict.username;
      req.debuggerSession = session;
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
        '<code>' + self.esc(access.UI_CLIENT_ID) + '</code>, a confidential ' +
        'client whose tokens stay on this service. This session is what ' +
        'admits you to the debugger and its api at <code>/api</code>, for ' +
        'as long as you are a console administrator; nothing the debugger ' +
        'sends to its api is read on the way.</p>' +
        '<p>The api process is <strong>' + self.esc(status.state) +
        '</strong>' +
        (status.allowList
          ? ', allowed to dial ' +
            self.esc(String(status.allowedRanges.length)) +
            ' address range(s) — this service\'s own and ' +
            '<code>debugger.allowedDestinations</code>.'
          : ', with no allow-list (development mode).') + '</p>' +
        '<p><a class="btn" href="/">Open the debugger</a></p>' +
        self.signOutForm(session));
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
                           'the Sign out button on the protocol debugger',
                           'user');
      const signOnEnded = parent
        ? !!authn.endSessionById(parent, 'the Sign out button on the ' +
                                         'protocol debugger', 'user')
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

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DebuggerServer>(
  'debugger/debugger_server',
  () => new DebuggerServer(DebuggerServer.defaultDeps()),
  DebuggerServer.wire,
  helpers.log);

// ===========================================================================
// THE APP.
// ===========================================================================
/**
 * The debugger listener's own express app, not the shared one.
 */
// Adapted for HTTP/2 as the shared one is (#407, common/http2_express.ts):
// plain express throws on the first HTTP/2 request.
const app = Http2Express.adapt(express());

// The routes go on it in `DebuggerServer.wire()`, when the instance is
// installed (#50, R2) — this app is the listener's own, not the shared one,
// so nothing else's order depends on when.

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

// Described to `/admin/caches` (#74, rule 3ap). An entry is current while the
// file on disk still has the modification time it was read at; an older
// version stays until it is pushed out, and is counted as expired.
const substitutedCount = cacheRegistry.register({
  name: 'debugger.static-files',
  title: 'Embedded debugger static files',
  description: 'The embedded debugger\'s client files with this service\'s ' +
    'address substituted in, kept per file version and address so the ' +
    'debugger listener does not rewrite a file on every request.',
  owner: 'debugger/debugger_server.ts',
  scope: 'process',
  maxEntries: function (): number {
    return SUBSTITUTED_CACHE_MAX;
  },
  bound: 'Enforced: 400 files, the oldest dropped and read again when next ' +
    'served.',
  lifetime: function (): string {
    return 'Until the file changes on disk (a new modification time is a ' +
      'new entry); the oldest goes first when full.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    substitutedCache.forEach(function (text: string, key: string): void {
      const parts = key.split('\n');
      let current = false;
      try {
        current = String(fs.statSync(parts[0]).mtimeMs) === parts[1];
      } catch (e) {
        helpers.log.debug("Caught in the debugger.static-files entries(): " +
                          ((e && e.message) || e));
        current = false;
      }
      out.push({ key: path.basename(parts[0]) + ' for ' + parts[2],
                 validUntil: null, valid: current,
                 basis: 'file modification time' });
    });
    return out;
  }
});

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The embedded identity protocol debugger: its listener, its sign-in and its
 * gate.
 *
 * The functions forward to the DebuggerServer instance the composition root
 * installs.
 * @namespace
 */
export = {
  DebuggerServer: DebuggerServer,
  /** Installs the instance the composition root built. */
  installInstance: (instance: DebuggerServer): void => slot.install(instance),
  /** Says where the installed instance came from. */
  instanceOrigin: (): string => slot.origin(),
  listen: slot.forward('listen'),
  close: slot.forward('close'),
  status: slot.forward('status'),
  // For tests/debugger_server.js, which drives the app in process.
  app: app,
  sessionVerdict: slot.forward('sessionVerdict'),
  checkAnchor: slot.forward('checkAnchor'),
  isLanding: slot.forward('isLanding'),
  authorizationBaseOf: slot.forward('authorizationBaseOf'),
  debuggerBaseOf: slot.forward('debuggerBaseOf'),
  STS_URL_PLACEHOLDER: STS_URL_PLACEHOLDER
};
