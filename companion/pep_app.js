#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/pep_app.js
//
// ===========================================================================
// THE APPLICATION THE REMOTE XACML PEP PROTECTS (#1760, decision D9).
//
// The remote PEP container (`xacml-pep/`, `rust/bins/xacml-pep`) can stand
// in front of an application as a reverse proxy: it authenticates a request
// by the route's mechanism, asks its own XACML engine, and forwards what is
// allowed to ONE upstream fixed in its configuration. This module is that
// upstream for the protocol job (`tests/protocol/sts_xacml_remote_pep.js`)
// and for a person trying the feature on a laptop: a small application
// under `/pep-app` that ECHOES what reached it, so a test can see what the
// proxy forwarded, and what it stripped.
//
//   GET  /pep-app/_hits          how many requests reached each path here
//                                (not counted itself). The job reads it
//                                DIRECTLY, never through the proxy, to
//                                prove an unrouted or refused request never
//                                reached the application.
//   *    /pep-app/public[/...]   page "public"
//   GET  /pep-app/public/hop     page "hop": answers a hop-by-hop header
//                                (`Connection: x-upstream-secret` naming
//                                `X-Upstream-Secret`) beside an end-to-end
//                                one (`X-Upstream-Visible`), so the job can
//                                assert the proxy drops the first and keeps
//                                the second (RFC 9110 section 7.6.1)
//   *    /pep-app/protected[/...] page "protected"
//   GET  /pep-app/api/items      page "items"
//   POST /pep-app/api/items      page "item-created" (201), with the body's
//                                length and SHA-256
//   GET  /pep-app/slow?ms=<n>    page "slow", answered after n ms, at most
//                                30 s: the proxy's upstream timeout (504)
//   POST /pep-app/saml/acs       page "saml-acs": the application's SAML
//                                ACS (D11's `saml` mode), which checks the
//                                SAMLResponse and opens a session behind
//                                `pep_app_saml` (`pep_app_identity.js`)
//   POST /pep-app/saml/_setup    what the ACS and the JWT check trust; not
//                                counted
//   GET  /pep-app/whoami[/...]   page "whoami" (2026-11-16): beside the
//                                echo, `whoami` — the identity headers the
//                                proxy forwarded (X-Remote-User, X-Iya-*)
//                                and the listener the request came through,
//                                read off the proxy's X-Forwarded-Host and
//                                X-Forwarded-Proto: what
//                                sts_xacml_pep_proxy_cluster.js asserts of a
//                                route served on a listener of its own
//   *    /pep-app/...            page "other"
//
// Every echo also carries `jwt` ({ header, payload, verified, expired, why })
// when `Authorization` is a Bearer JWT, and `saml` ({ nameId, attributes,
// issuer, sessionIndex }) when the request's `pep_app_saml` cookie names a
// live ACS session.
//
// Every page answers the same JSON:
//
//   { app: "pep-app", page, method, path, query, headers, hit,
//     body: { length, sha256 } }        (body: only when one was sent)
//
// `path` is the RAW request target's path as it arrived, not normalised,
// so a dot segment the proxy forwarded would show; `headers` is every
// header node received, names lower-cased (node's own `req.headers`), so
// the identity headers the proxy adds and the `Authorization` it must
// strip are read off it.
//
// **DISPATCHED BEFORE THE COMPANION'S SESSION AND CSRF CHECK**, like
// `/social`: the proxy, not a browser, sends these requests, carrying no
// companion session, and a `Set-Cookie: companion_sid` on every answer
// would be one more header the job has to explain. `companion.js` hands
// any path under `/pep-app` here first.
//
// **NOTHING HERE IS AUTHORIZATION.** It trusts every header it is sent,
// because deciding is the proxy's job and echoing is this one's. Nothing
// on a timer: the counter is capped on insert and the slow page's delay is
// one request's.
// ===========================================================================

const crypto = require("crypto");
const util = require("./companion_util.js");
const { PepAppIdentity } = require("./pep_app_identity.js");

const log = util.logger("iya-sts-companion-pep-app");

const PREFIX = "/pep-app";
// The slow page's bound: well past any upstream timeout a test sets, and
// short enough that a client that never gives up costs one socket for half
// a minute at most.
const SLOW_MAX_MS = 30000;
// What a body may be. The proxy's own `maxBodyBytes` defaults to 1 MiB; a
// body the proxy let through and this refused would be a 413 nobody could
// tell from the proxy's.
const BODY_MAX_BYTES = 8 * 1024 * 1024;
// Distinct paths counted. A path past the cap evicts the oldest.
const HITS_CAP = 2000;

/**
 * The raw path of a request target: everything before `?`, as sent.
 *
 * @param {string} target - `req.url`
 * @returns {string} the path
 */
function rawPathOf(target) {
  log.debug("Entering rawPathOf().");
  const text = String(target || "");
  const at = text.indexOf("?");
  log.debug("Leaving rawPathOf().");
  return at < 0 ? text : text.slice(0, at);
}

/**
 * Whether a raw path is this application's.
 *
 * @param {string} target - `req.url`
 * @returns {boolean} whether it is under `/pep-app`
 */
function owns(target) {
  log.debug("Entering owns().");
  const p = rawPathOf(target);
  log.debug("Leaving owns().");
  return p === PREFIX || p.indexOf(PREFIX + "/") === 0;
}

/**
 * A query string as an object: a name sent once is a string, a name sent
 * more than once an array of its values in order.
 *
 * @param {string} target - `req.url`
 * @returns {object} the query
 */
function queryOf(target) {
  log.debug("Entering queryOf().");
  const text = String(target || "");
  const at = text.indexOf("?");
  const out = {};
  if (at >= 0) {
    new URLSearchParams(text.slice(at + 1)).forEach(function (value, name) {
      if (!Object.prototype.hasOwnProperty.call(out, name)) {
        out[name] = value;
      } else if (Array.isArray(out[name])) {
        out[name].push(value);
      } else {
        out[name] = [out[name], value];
      }
    });
  }
  log.debug("Leaving queryOf().");
  return out;
}

/**
 * A request body, whole, at most `BODY_MAX_BYTES`.
 *
 * @param {object} req - the request
 * @returns {Promise<Buffer|null>} the bytes, or null when over the bound
 */
function bodyOf(req) {
  log.debug("Entering bodyOf().");
  log.debug("Leaving bodyOf().");
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    let over = false;
    req.on("data", function (chunk) {
      size += chunk.length;
      if (size > BODY_MAX_BYTES) {
        over = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", function () {
      resolve(over ? null : Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

/**
 * The application.
 */
class PepApp {
  /**
   * @param {object} [opts] - `caFile`, `insecure`: how the identity half
   *   dials the service for its metadata and JWKS
   */
  constructor(opts) {
    log.debug("Entering PepApp.constructor().");
    this.identity = new PepAppIdentity(opts);
    // path -> count, in insertion order for the cap.
    this.hits = new Map();
    this.total = 0;
    log.debug("Leaving PepApp.constructor().");
  }

  /**
   * For the companion's start page.
   *
   * @returns {object} `{ id, title, links }`
   */
  describe() {
    log.debug("Entering PepApp.describe().");
    log.debug("Leaving PepApp.describe().");
    return {
      id: "pep-app",
      title: "The application the remote XACML PEP protects (#1760)",
      links: [
        { href: PREFIX + "/public", text: "A public page (JSON echo)" },
        { href: PREFIX + "/protected", text: "A protected page (JSON echo)" },
        { href: PREFIX + "/_hits", text: "What reached it" }
      ]
    };
  }

  /**
   * Nothing to mount on the exact-path router: `handle()` is dispatched by
   * prefix, before the session.
   *
   * @param {object} router - the companion's router
   */
  mount(router) {
    log.debug("Entering PepApp.mount().");
    log.info("pep-app: the remote PEP's upstream application is served " +
             "under " + PREFIX + " (" + (router ? "mounted" : "no router") +
             ").");
    log.debug("Leaving PepApp.mount().");
  }

  /**
   * Counts one request to a path.
   *
   * @param {string} p - the raw path
   * @returns {number} that path's count now
   */
  count(p) {
    log.debug("Entering PepApp.count().");
    if (!this.hits.has(p)) {
      while (this.hits.size >= HITS_CAP) {
        this.hits.delete(this.hits.keys().next().value);
      }
      this.hits.set(p, 0);
    }
    const n = this.hits.get(p) + 1;
    this.hits.set(p, n);
    this.total += 1;
    log.debug("Leaving PepApp.count(). " + n);
    return n;
  }

  /**
   * Who the proxy said the caller is, and which of its listeners the
   * request came through: the identity headers it forwarded, and the host,
   * port and scheme of X-Forwarded-Host and X-Forwarded-Proto, which are
   * the proxy's own and never the client's.
   *
   * @param {object} headers - the request's headers, names lower-cased
   * @returns {object} `{ user, subject, email, groups, mechanism, via }`
   */
  static whoami(headers) {
    log.debug("Entering PepApp.whoami().");
    const h = headers || {};
    const host = String(h["x-forwarded-host"] || "");
    const m = /^(.*?)(?::(\d+))?$/.exec(host) || [];
    const proto = String(h["x-forwarded-proto"] || "");
    const out = {
      user: String(h["x-remote-user"] || ""),
      subject: String(h["x-iya-user"] || ""),
      email: String(h["x-iya-email"] || ""),
      groups: String(h["x-iya-groups"] || ""),
      mechanism: String(h["x-iya-auth"] || h["x-remote-auth"] || ""),
      via: { host: m[1] || "", proto: proto,
             port: m[2] ? Number(m[2]) : (proto === "https" ? 443
                                          : (proto === "http" ? 80 : 0)) }
    };
    log.debug("Leaving PepApp.whoami().");
    return out;
  }

  /**
   * Which page a raw path is.
   *
   * @param {string} method - the method
   * @param {string} p - the raw path
   * @returns {string} the page's name
   */
  pageOf(method, p) {
    log.debug("Entering PepApp.pageOf().");
    const under = function (prefix) {
      log.debug("Entering under().");
      log.debug("Leaving under().");
      return p === prefix || p.indexOf(prefix + "/") === 0;
    };
    let page = "other";
    if (p === PREFIX + "/public/hop") {
      page = "hop";
    } else if (under(PREFIX + "/public")) {
      page = "public";
    } else if (under(PREFIX + "/protected")) {
      page = "protected";
    } else if (p === PREFIX + "/api/items") {
      page = method === "POST" ? "item-created" : "items";
    } else if (under(PREFIX + "/whoami")) {
      page = "whoami";
    } else if (p === PREFIX + "/slow") {
      page = "slow";
    } else if (p === PREFIX + "/saml/acs" && method === "POST") {
      page = "saml-acs";
    }
    log.debug("Leaving PepApp.pageOf(). " + page);
    return page;
  }

  /**
   * Answers one request under `/pep-app`.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   */
  async handle(req, res) {
    log.debug("Entering PepApp.handle().");
    const p = rawPathOf(req.url);
    if (p === PREFIX + "/_hits") {
      util.sendJson(res, 200, { app: "pep-app", total: this.total,
                                byPath: Object.fromEntries(this.hits) });
      log.debug("Leaving PepApp.handle(). Hits.");
      return;
    }
    if (p === PREFIX + "/saml/_setup" && req.method === "POST") {
      // What the ACS and the JWT check trust; not counted, never proxied.
      const raw = await bodyOf(req);
      let asked = {};
      try {
        asked = JSON.parse((raw || Buffer.alloc(0)).toString("utf8") || "{}");
      } catch (e) {
        log.debug("Caught in PepApp.handle(): " + ((e && e.message) || e));
        util.sendJson(res, 400, { ok: false, why: "the body is not JSON" });
        log.debug("Leaving PepApp.handle(). Setup not JSON.");
        return;
      }
      try {
        util.sendJson(res, 200, await this.identity.setup(asked));
      } catch (e) {
        log.debug("Caught in PepApp.handle(): " + ((e && e.message) || e));
        util.sendJson(res, 502, { ok: false,
                                  why: String((e && e.message) || e) });
      }
      log.debug("Leaving PepApp.handle(). Setup.");
      return;
    }
    const hit = this.count(p);
    const method = String(req.method || "GET");
    const page = this.pageOf(method, p);
    const query = queryOf(req.url);
    const bytes = await bodyOf(req);
    log.info("pep-app: " + method + " " + p + " (page " + page + ", hit " +
             hit + ", from " + String(req.socket.remoteAddress || "?") +
             (req.headers.authorization ? ", WITH an Authorization header"
                                        : "") + ")");
    if (bytes === null) {
      util.sendJson(res, 413, { app: "pep-app", page: page,
                                error: "the body is over " + BODY_MAX_BYTES +
                                       " bytes" });
      log.debug("Leaving PepApp.handle(). Too large.");
      return;
    }
    const echo = { app: "pep-app", page: page, method: method, path: p,
                   query: query, headers: req.headers, hit: hit };
    const sent = bytes.length > 0 || method === "POST" || method === "PUT" ||
                 method === "PATCH";
    if (sent) {
      echo.body = { length: bytes.length,
                    sha256: crypto.createHash("sha256").update(bytes)
                      .digest("hex") };
    }
    if (page === "whoami") {
      echo.whoami = PepApp.whoami(req.headers);
    }
    if (page === "slow") {
      const asked = Number(query.ms);
      const ms = Number.isFinite(asked) && asked > 0
        ? Math.min(asked, SLOW_MAX_MS) : 0;
      echo.waitedMs = ms;
      // ONE REQUEST'S DELAY, not a periodic timer.
      await new Promise(function (resolve) {
        setTimeout(resolve, ms);
      });
      if (res.destroyed || res.writableEnded) {
        log.debug("Leaving PepApp.handle(). The caller left.");
        return;
      }
    }
    // THE IDENTITY THE PROXY FORWARDED (D11): a Bearer JWT decoded and
    // checked, and the SAML session the ACS opened, when there is one.
    let status = page === "item-created" ? 201 : 200;
    const headers = { "Content-Type": "application/json",
                      "Cache-Control": "no-store",
                      "X-Content-Type-Options": "nosniff",
                      "X-Pep-App-Page": page };
    const jwt = await this.identity.bearerJwt(req.headers.authorization);
    if (jwt) {
      echo.jwt = jwt;
    }
    if (page === "saml-acs") {
      const accepted = this.identity.acs(bytes);
      status = accepted.status;
      echo.ok = accepted.status === 200;
      if (accepted.saml) {
        echo.saml = accepted.saml;
        headers["Set-Cookie"] = accepted.cookie;
      } else {
        echo.why = accepted.why;
      }
    } else {
      const saml = this.identity.sessionOf(req);
      if (saml) {
        echo.saml = saml;
      }
    }
    if (page === "hop") {
      // A HOP-BY-HOP HEADER, NAMED BY `Connection`. A proxy that forwards a
      // response must remove `Connection` and every header it names (RFC
      // 9110 section 7.6.1); `X-Upstream-Visible` is end-to-end and stays.
      headers.Connection = "x-upstream-secret";
      headers["X-Upstream-Secret"] = "only-for-the-next-hop";
      headers["X-Upstream-Visible"] = "end-to-end";
      headers["Keep-Alive"] = "timeout=5";
    }
    const text = JSON.stringify(echo);
    headers["Content-Length"] = Buffer.byteLength(text);
    res.writeHead(status, headers);
    res.end(method === "HEAD" ? undefined : text);
    log.debug("Leaving PepApp.handle(). " + status);
  }
}

module.exports = { PepApp: PepApp, owns: owns, rawPathOf: rawPathOf,
                   SLOW_MAX_MS: SLOW_MAX_MS };
