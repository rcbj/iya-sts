#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/companion.js
//
// ===========================================================================
// iya-sts-companion — THE CLICK-THROUGH DEMONSTRATIONS, OUTSIDE THE SERVICE
// (#594, phase 3 of #591).
//
// rcbj's decision 1 on #591: the demonstrations a PERSON clicks through —
// and the embedded debugger points a person at — move into a
// development-only companion container, like the test peer (#586) but for
// people rather than jobs, and the service ships none of them.
// `companion/CLAUDE.md` argues the design; this file is the shell every
// demonstration is mounted on:
//
//   GET  /                 the start page: every demonstration's links
//   GET  /companion.css    the one stylesheet
//   GET  /healthz          JSON: up, and whether the service answered
//   ...                    each demonstration's own routes (`DEMOS`)
//
// **A DEMONSTRATION IS A MODULE WITH `describe()` AND `mount(router)`.** The
// OpenID4VC issuer and verifier are the first (`demo_oid4vc.js`); the
// Kerberos and SPNEGO demonstration (#595, `demo_kerberos.js`) is the
// second, and the one with a socket of its own — the protected TCP service —
// which a demonstration's optional `listen()` starts, called from `listen()`
// here once the pages listen, as the service starts its own sockets: a bind
// can fail, and a require must not.
//
// **SESSIONS.** A browser gets one cookie, `companion_sid` (HttpOnly,
// SameSite=Lax), naming a session in memory: its CSRF token and what it
// started. The store is bounded (`MAX_SESSIONS`, the oldest evicted on an
// insert) and a session past `SESSION_TTL_MS` is never answered — checked
// where it is read, so nothing here runs on a timer.
//
// **EVERY POST IS BOUND**: its form's `csrf` must be the session's token,
// and an `Origin` it carries must be the companion's own.
// ===========================================================================

const http = require("http");
const nodeCrypto = require("crypto");
const util = require("./companion_util.js");
const { StsClient } = require("./sts_client.js");
const { Oid4vcDemo } = require("./demo_oid4vc.js");
const { KerberosDemo } = require("./demo_kerberos.js");

const log = util.logger("iya-sts-companion");

const MAX_SESSIONS = 2000;
const SESSION_TTL_MS = 60 * 60 * 1000;
const COOKIE = "companion_sid";

/**
 * The configuration, from the environment.
 *
 * @param {object} env - the environment
 * @returns {object} the settings
 */
function settingsFrom(env) {
  log.debug("Entering settingsFrom().");
  const port = Number(env.COMPANION_PORT || 9700);
  const stsPublicUrl = String(env.COMPANION_STS_PUBLIC_URL ||
                              env.COMPANION_STS_URL ||
                              "https://localhost:8081");
  const out = {
    port: port,
    publicUrl: String(env.COMPANION_PUBLIC_URL ||
                      "http://localhost:" + port).replace(/\/+$/, ""),
    stsUrl: String(env.COMPANION_STS_URL || stsPublicUrl),
    stsPublicUrl: stsPublicUrl,
    caFile: String(env.COMPANION_STS_CA_FILE || ""),
    insecure: String(env.COMPANION_STS_TLS_INSECURE || "") === "true",
    clientId: String(env.COMPANION_CLIENT_ID || ""),
    clientSecret: String(env.COMPANION_CLIENT_SECRET || ""),
    bootstrapSecret: String(env.COMPANION_BOOTSTRAP_SECRET || ""),
    walletUrl: String(env.COMPANION_WALLET_URL || ""),
    // #595: the Kerberos demonstration's principal ('' is HTTP/<the public
    // URL's host>), its TCP socket ('off' for none) and where its keytab is
    // written ('' is a fresh directory under the system's temporary one).
    krb5Spn: String(env.COMPANION_KRB5_SPN || ""),
    krb5ServicePort: String(env.COMPANION_KRB5_SERVICE_PORT || "") === "off"
      ? null : Number(env.COMPANION_KRB5_SERVICE_PORT || 8888),
    krb5KeytabDir: String(env.COMPANION_KRB5_KEYTAB_DIR || "")
  };
  log.debug("Leaving settingsFrom().");
  return out;
}

/**
 * The bounded session store.
 */
class Sessions {
  constructor() {
    log.debug("Entering Sessions.constructor().");
    this.map = new Map();
    log.debug("Leaving Sessions.constructor().");
  }

  /**
   * The session a request's cookie names, or a new one.
   *
   * @param {object} req - the request
   * @returns {object} `{ session, fresh }`
   */
  of(req) {
    log.debug("Entering Sessions.of().");
    const sid = util.cookiesOf(req)[COOKIE] || "";
    const found = sid ? this.map.get(sid) : null;
    if (found && found.expires > Date.now()) {
      log.debug("Leaving Sessions.of(). Known.");
      return { session: found, fresh: false };
    }
    if (found) {
      this.map.delete(sid);
    }
    while (this.map.size >= MAX_SESSIONS) {
      this.map.delete(this.map.keys().next().value);
    }
    const session = { id: nodeCrypto.randomBytes(24).toString("base64url"),
                      csrf: nodeCrypto.randomBytes(24).toString("base64url"),
                      expires: Date.now() + SESSION_TTL_MS,
                      verifications: [] };
    this.map.set(session.id, session);
    log.debug("Leaving Sessions.of(). New.");
    return { session: session, fresh: true };
  }
}

/**
 * The companion: its settings, its demonstrations and its listener.
 */
class Companion {
  /**
   * @param {object} settings - `settingsFrom()`'s answer
   * @param {object} [deps] - `sts`, a stand-in for the service's client;
   *   `gss`, a stand-in for the Kerberos acceptor
   */
  constructor(settings, deps) {
    log.debug("Entering Companion.constructor().");
    this.settings = settings;
    this.sessions = new Sessions();
    this.routes = { GET: new Map(), POST: new Map() };
    const oid4vc = new Oid4vcDemo({ sessions: this.sessions,
                                    publicUrl: settings.publicUrl,
                                    walletUrl: settings.walletUrl,
                                    sts: null });
    this.sts = (deps && deps.sts) || new StsClient({
      stsUrl: settings.stsUrl, stsPublicUrl: settings.stsPublicUrl,
      caFile: settings.caFile, insecure: settings.insecure,
      clientId: settings.clientId, clientSecret: settings.clientSecret,
      bootstrapSecret: settings.bootstrapSecret,
      redirectUris: [oid4vc.completionUrl()] });
    oid4vc.sts = this.sts;
    const kerberos = new KerberosDemo({
      sts: this.sts, publicUrl: settings.publicUrl, spn: settings.krb5Spn,
      servicePort: settings.krb5ServicePort === undefined
        ? null : settings.krb5ServicePort,
      keytabDir: settings.krb5KeytabDir, gss: deps && deps.gss });
    // THE DEMONSTRATIONS.
    this.demos = [oid4vc, kerberos];
    const router = {
      get: (path, handler) => {
        this.routes.GET.set(path, handler);
      },
      post: (path, handler) => {
        this.routes.POST.set(path, handler);
      }
    };
    this.demos.forEach(function (demo) {
      demo.mount(router);
    });
    log.debug("Leaving Companion.constructor().");
  }

  /**
   * The start page.
   *
   * @param {object} res - the response
   */
  index(res) {
    log.debug("Entering Companion.index().");
    const cards = this.demos.map(function (demo) {
      const d = demo.describe();
      return "<div class=\"card\" id=\"demo-" + util.esc(d.id) + "\"><h2>" +
        util.esc(d.title) + "</h2><ul>" + d.links.map(function (link) {
          return "<li><a href=\"" + util.esc(link.href) + "\">" +
                 util.esc(link.text) + "</a></li>";
        }).join("") + "</ul></div>";
    }).join("");
    util.sendHtml(res, 200, util.page("iya-sts companion",
      "<div class=\"card\"><h1>iya-sts companion</h1><p class=\"sub\">" +
      "Demonstrations of <code>" + util.esc(this.sts.publicBase) +
      "</code>, played by a separate party.</p></div>" + cards));
    log.debug("Leaving Companion.index().");
  }

  /**
   * Whether a POST is bound to its session: the form's token, and the
   * Origin when one is sent.
   *
   * @param {object} req - the request
   * @param {object} ctx - its context, the form read
   * @returns {string} '' when bound, else why not
   */
  unbound(req, ctx) {
    log.debug("Entering Companion.unbound().");
    const origin = String(req.headers.origin || "");
    if (origin && origin !== new URL(this.settings.publicUrl).origin) {
      log.debug("Leaving Companion.unbound(). Origin.");
      return "This form was sent from another site (" + origin + ").";
    }
    const presented = Buffer.from(String((ctx.form || {}).csrf || ""));
    const expected = Buffer.from(ctx.session.csrf);
    if (ctx.fresh || presented.length !== expected.length ||
        !nodeCrypto.timingSafeEqual(presented, expected)) {
      log.debug("Leaving Companion.unbound(). Token.");
      return "This form is not this browser's. Load the page again.";
    }
    log.debug("Leaving Companion.unbound(). Bound.");
    return "";
  }

  /**
   * Answers one request.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   */
  async handle(req, res) {
    log.debug("Entering Companion.handle(). " + req.method + " " +
              String(req.url).replace(/\?.*$/, ""));
    const url = new URL(req.url, "http://companion.invalid");
    const found = this.sessions.of(req);
    if (found.fresh) {
      res.setHeader("Set-Cookie", COOKIE + "=" + found.session.id +
                    "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" +
                    Math.floor(SESSION_TTL_MS / 1000) +
                    (this.settings.publicUrl.indexOf("https:") === 0
                      ? "; Secure" : ""));
    }
    const ctx = { query: url.searchParams, session: found.session,
                  fresh: found.fresh, form: null };
    try {
      if (req.method === "GET" && url.pathname === "/") {
        this.index(res);
      } else if (req.method === "GET" && url.pathname === "/companion.css") {
        res.writeHead(200, { "Content-Type": "text/css; charset=utf-8",
                             "Cache-Control": "max-age=300" });
        res.end(util.CSS);
      } else if (req.method === "GET" && url.pathname === "/healthz") {
        util.sendJson(res, 200, { ok: true, sts: this.sts.publicBase,
                                  demos: this.demos.map(function (d) {
                                    return d.describe().id;
                                  }) });
      } else if (this.routes[req.method] &&
                 this.routes[req.method].has(url.pathname)) {
        if (req.method === "POST") {
          ctx.form = util.formOf(await util.readBody(req));
          const why = this.unbound(req, ctx);
          if (why) {
            util.sendError(res, 403, "Refused", why);
            log.debug("Leaving Companion.handle(). Unbound.");
            return;
          }
        }
        await this.routes[req.method].get(url.pathname)(req, res, ctx);
      } else {
        util.sendError(res, 404, "Not here", "The companion has no page at " +
                       url.pathname + ".");
      }
    } catch (e) {
      log.debug("Caught in Companion.handle(): " + ((e && e.message) || e));
      log.error("companion: " + req.method + " " + url.pathname +
                " failed: " + ((e && e.stack) || e));
      if (!res.headersSent) {
        util.sendError(res, 502, "The service did not answer",
                       String((e && e.message) || e));
      }
    }
    log.debug("Leaving Companion.handle().");
  }

  /**
   * Starts the listener, then every demonstration's own sockets.
   *
   * @returns {Promise<object>} the http server, listening; `sockets` on it
   *   holds what the demonstrations started
   */
  listen() {
    log.debug("Entering Companion.listen().");
    const server = http.createServer((req, res) => {
      this.handle(req, res);
    });
    log.debug("Leaving Companion.listen().");
    return new Promise((resolve, reject) => {
      server.on("error", reject);
      server.listen(this.settings.port, () => {
        log.info("companion: listening on " + server.address().port +
                 " as " + this.settings.publicUrl + ", in front of " +
                 this.sts.publicBase);
        resolve(server);
      });
    }).then((server) => {
      // A demonstration's socket: a failed bind is the demonstration's to
      // record and show, never the companion's to die of.
      return Promise.all(this.demos.map(function (demo) {
        return typeof demo.listen === "function" ? demo.listen() : null;
      })).then(function (sockets) {
        server.sockets = sockets.filter(Boolean);
        server.on("close", function () {
          server.sockets.forEach(function (one) {
            one.close();
          });
        });
        return server;
      });
    });
  }
}

module.exports = { Companion: Companion, Sessions: Sessions,
                   settingsFrom: settingsFrom };

if (require.main === module) {
  new Companion(settingsFrom(process.env)).listen().catch(function (e) {
    log.debug("Caught in the companion's start: " + ((e && e.message) || e));
    log.error("companion: could not listen: " + ((e && e.message) || e));
    process.exitCode = 1;
  });
}
