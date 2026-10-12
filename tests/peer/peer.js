#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer.js
//
// ===========================================================================
// sts-test-peer — THE FAR PARTY THE PROTOCOL JOBS TALK TO (#586).
//
// rcbj's decision of 2026-10-12 (#585): every demo and mock endpoint of the
// service is served in development realms only. The product-mode protocol
// jobs used several of them as the OTHER END of a protocol — a service
// provider, a relying party, a resource server, a receiver — and this is
// what replaces them: ONE separate component on the test stack, one image,
// one port, one JSON readback (rcbj, #586), that plays each of those parties
// over the real protocol, as an outside party would, and is believed by the
// service only because a job registered it as an ordinary application.
//
//   role                         replaces                       module
//   SAML 2.0 SP (POST, Artifact) /saml2/sp                      peer_saml.js
//   SAML 1.1 RP (POST, Artifact) /saml11/rp                     peer_saml.js
//   WS-Federation passive RP     /wsfed/rp                      peer_saml.js
//   RFC 9470 resource server     /oauth2/step-up/resource/{a}   peer_stepup.js
//   GNAP resource server         /gnap/rs/resource, /spend      peer_gnap.js
//   SSF receiver (push)          /ssf/receive                   peer_ssf.js
//   OP Commands relying party    /oauth2/commands/mock-rp       peer_commands.js
//
// ---------------------------------------------------------------------------
// TENANTS. A job starts from a known state (#586): it creates a realm,
// configures a TENANT here for it — `PUT /peer/tenants/{id}` with the
// realm's base URL and the anchors to trust the service's TLS with — and
// registers what the answer describes (the tenant's entityID, return
// addresses, signing certificate, GNAP key, push URL, command endpoint) as
// an application in that realm through `/admin-api`.
// `tests/vendored/test_peer.js` is the jobs' side of that. Every key a tenant uses is made when it is first
// configured, and kept across a reconfiguration so a registration stays
// true.
//
// THE READBACK. Every role records what arrived and what it made of it on
// the tenant; `GET /peer/tenants/{id}/received?role=…&since=…` answers the
// records after a sequence number, so a job asserts on what reached the
// peer rather than on a page the service drew.
//
// ONE PORT, TWO SCHEMES. The listener reads the first byte of a connection:
// a TLS handshake record (0x16) goes to the HTTPS server, anything else to
// the plain one. Plain HTTP serves the browser-facing roles and the
// readback; TLS serves the SSF push (product mode pushes only over verified
// TLS, #171) and asks for — never requires — a client certificate, for
// GNAP's mutual-TLS proof. The TLS certificate is under a CA made at start,
// whose certificate is written to the directory the stack shares with the
// service (`TEST_PEER_CA_DIR`, `/run/sts-test/test-peer` by default), so a
// realm can be told to trust it (`ssf.pushCaFile`).
//
// NOTHING IN THIS DIRECTORY IS A KEY. tests/CLAUDE.md, *THE TEST PEER*,
// argues the rest.
// ===========================================================================

const fs = require("fs");
const http = require("http");
const https = require("https");
const net = require("net");
const path = require("path");
const util = require("./peer_util.js");
const pki = require("./peer_pki.js");
const saml = require("./peer_saml.js");
const stepUp = require("./peer_stepup.js");
const gnap = require("./peer_gnap.js");
const ssf = require("./peer_ssf.js");
const commands = require("./peer_commands.js");

const log = util.logger("sts-test-peer");

const MAX_TENANTS = 500;
const MAX_EVENTS = 2000;
const ROLES = ["saml2", "saml11", "wsfed", "step-up", "gnap", "ssf",
               "commands"];

// ---------------------------------------------------------------------------
// TENANTS.
// ---------------------------------------------------------------------------
function makeTenant(state, id) {
  log.debug("Entering makeTenant(). " + id);
  const tenant = {
    id: id,
    created: new Date().toISOString(),
    pending: new Map(),
    events: [],
    seq: 0,
    record: function (role, event) {
      log.debug("Entering record(). " + role);
      tenant.seq += 1;
      const row = Object.assign({ seq: tenant.seq, role: role,
                                  at: new Date().toISOString() }, event);
      tenant.events.push(row);
      if (tenant.events.length > MAX_EVENTS) {
        tenant.events.shift();
      }
      log.info("peer: " + id + " " + role + " #" + row.seq + " ok=" +
               row.ok + (row.ok ? "" : " — " + (row.why || row.error ||
                 row.description || (row.problems || []).join("; "))));
      log.debug("Leaving record().");
    }
  };
  if (state.tenants.size >= MAX_TENANTS) {
    state.tenants.delete(state.tenants.keys().next().value);
  }
  state.tenants.set(id, tenant);
  log.debug("Leaving makeTenant().");
  return tenant;
}

// What a job registers, and where each role is reached.
function viewOf(state, tenant) {
  log.debug("Entering viewOf().");
  const plain = state.plainBase + "/t/" + encodeURIComponent(tenant.id);
  const secure = state.secureBase + "/t/" + encodeURIComponent(tenant.id);
  log.debug("Leaving viewOf().");
  return {
    tenant: tenant.id,
    realmBase: tenant.realmBase,
    urls: tenant.urls,
    saml: { entityId: tenant.saml.entityId,
            certPem: tenant.signing.certPem,
            certB64: tenant.signing.certB64 },
    wsfed: { realm: tenant.wsfed.realm || null },
    stepUp: { base: plain + "/step-up/",
              resources: tenant.stepUp.resources || {} },
    gnap: { type: tenant.gnap.type, actions: gnap.ACTIONS,
            key: tenant.gnap.key.keyObject,
            rsUri: plain + "/gnap",
            resource: plain + "/gnap/resource",
            spend: plain + "/gnap/spend",
            resourceTls: secure + "/gnap/resource" },
    ssf: { pushUrl: secure + "/ssf/push",
           audience: tenant.ssf.audience || null },
    commands: { endpoint: secure + "/commands" },
    caPem: state.ca.certPem,
    caFile: state.caFile
  };
}

// PUT /peer/tenants/{id}.
function configureTenant(state, id, asked) {
  log.debug("Entering configureTenant(). " + id);
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(id)) {
    log.debug("Leaving configureTenant(). Bad id.");
    return { status: 400, body: { ok: false, error: "a tenant id is 1 to " +
      "80 of A-Z a-z 0-9 . _ -" } };
  }
  const body = asked || {};
  let base;
  try {
    base = new URL(String(body.realmBase || ""));
  } catch (e) {
    log.debug("Caught in configureTenant(): " + ((e && e.message) || e));
    // Refused below, with the reason.
    base = null;
  }
  if (!base || !/^https?:$/.test(base.protocol)) {
    log.debug("Leaving configureTenant(). No realm.");
    return { status: 400, body: { ok: false, error: "realmBase must be the " +
      "realm's absolute http(s) base URL" } };
  }
  const tenant = state.tenants.get(id) || makeTenant(state, id);
  tenant.realmBase = String(body.realmBase).replace(/\/+$/, "");
  tenant.serviceCaPem = String(body.serviceCaPem || tenant.serviceCaPem ||
                               "");
  tenant.signing = tenant.signing ||
    pki.signingCertificate("sts-test-peer " + id);
  const plain = state.plainBase + "/t/" + encodeURIComponent(id);
  tenant.urls = {
    saml2Login: plain + "/saml2/login",
    saml2Acs: plain + "/saml2/acs",
    saml11Acs: plain + "/saml11/acs",
    wsfedReply: plain + "/wsfed"
  };
  const samlAsked = body.saml || {};
  tenant.saml = { entityId: String(samlAsked.entityId ||
    (tenant.saml && tenant.saml.entityId) || plain + "/saml") };
  tenant.wsfed = { realm: String((body.wsfed || {}).realm ||
                                 (tenant.wsfed && tenant.wsfed.realm) || "") };
  if (body.stepUp || !tenant.stepUp) {
    tenant.stepUp = { resources: (body.stepUp || {}).resources || {} };
  }
  gnap.configure(tenant, body.gnap);
  if (body.ssf || !tenant.ssf) {
    ssf.configure(tenant, body.ssf);
  }
  commands.configure(tenant);
  tenant.metadataCache = {};
  log.info("peer: tenant " + id + " configured for " + tenant.realmBase);
  log.debug("Leaving configureTenant().");
  return { status: 200, body: Object.assign({ ok: true },
                                            viewOf(state, tenant)) };
}

// GET /peer/tenants/{id}/received.
function received(tenant, query) {
  log.debug("Entering received().");
  const role = query.get("role");
  const since = Number(query.get("since") || 0);
  const events = tenant.events.filter(function (row) {
    return row.seq > since && (!role || row.role === role);
  });
  log.debug("Leaving received(). " + events.length);
  return { status: 200, body: { tenant: tenant.id, last: tenant.seq,
                                events: events } };
}

// ---------------------------------------------------------------------------
// ROUTING. One function, a table of patterns: there are a dozen paths and no
// framework is worth its weight for them.
// ---------------------------------------------------------------------------
async function route(state, request) {
  log.debug("Entering route(). " + request.method + " " + request.path);
  const p = request.path;
  if (p === "/health" && request.method === "GET") {
    log.debug("Leaving route(). Health.");
    return { status: 200, body: { ok: true,
                                  tenants: state.tenants.size } };
  }
  if (p === "/peer/info" && request.method === "GET") {
    log.debug("Leaving route(). Info.");
    return { status: 200, body: { ok: true, plainBase: state.plainBase,
                                  secureBase: state.secureBase,
                                  caPem: state.ca.certPem,
                                  caFile: state.caFile, roles: ROLES } };
  }
  let m = /^\/peer\/tenants\/([^/]+)(\/received)?$/.exec(p);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (!m[2] && (request.method === "PUT" || request.method === "POST")) {
      let asked;
      try {
        asked = JSON.parse(request.body.toString("utf8") || "{}");
      } catch (e) {
        log.debug("Caught in route(): " + ((e && e.message) || e));
        // Said to the job, which sent it.
        log.debug("Leaving route(). Bad JSON.");
        return { status: 400, body: { ok: false, error: "the body is not " +
                                      "JSON: " + e.message } };
      }
      log.debug("Leaving route(). Configure.");
      return configureTenant(state, id, asked);
    }
    const tenant = state.tenants.get(id);
    if (!tenant) {
      log.debug("Leaving route(). No tenant.");
      return { status: 404, body: { ok: false, error: "no tenant " + id } };
    }
    if (request.method === "GET") {
      log.debug("Leaving route(). Tenant read.");
      return m[2] ? received(tenant, request.query)
                  : { status: 200, body: viewOf(state, tenant) };
    }
  }
  m = /^\/t\/([^/]+)\/(.+)$/.exec(p);
  if (m) {
    const tenant = state.tenants.get(decodeURIComponent(m[1]));
    if (!tenant) {
      log.debug("Leaving route(). No tenant.");
      return { status: 404, body: { ok: false, error: "no tenant " +
                                    decodeURIComponent(m[1]) } };
    }
    const rest = m[2];
    const form = /x-www-form-urlencoded/i.test(
      request.headers["content-type"] || "") ? util.formOf(request.body) : {};
    if (rest === "saml2/login" && request.method === "GET") {
      log.debug("Leaving route(). SAML 2.0 login.");
      return saml.saml2Login(tenant, request.query);
    }
    if (rest === "saml2/acs") {
      log.debug("Leaving route(). SAML 2.0 ACS.");
      return saml.saml2Acs(tenant, request.method, request.query, form);
    }
    if (rest === "saml11/acs") {
      log.debug("Leaving route(). SAML 1.1 ACS.");
      return saml.saml11Acs(tenant, request.method, request.query, form);
    }
    if (rest === "wsfed" && request.method === "POST") {
      log.debug("Leaving route(). WS-Federation.");
      return saml.wsfedReply(tenant, form);
    }
    const su = /^step-up\/([^/]+)$/.exec(rest);
    if (su) {
      log.debug("Leaving route(). Step-up.");
      return stepUp.resource(tenant, decodeURIComponent(su[1]),
                             request.headers.authorization);
    }
    if (rest === "gnap/resource" &&
        (request.method === "GET" || request.method === "POST")) {
      log.debug("Leaving route(). GNAP resource.");
      return gnap.resource(tenant, request);
    }
    if (rest === "gnap/spend" && request.method === "POST") {
      log.debug("Leaving route(). GNAP spend.");
      return gnap.spend(tenant, request);
    }
    if (rest === "ssf/push" && request.method === "POST") {
      log.debug("Leaving route(). SSF push.");
      return ssf.push(tenant, request);
    }
    if (rest === "commands" && request.method === "POST") {
      log.debug("Leaving route(). OP command.");
      return commands.command(tenant, request);
    }
    if (rest === "commands" && request.method === "GET") {
      log.debug("Leaving route(). OP command accounts.");
      return commands.accounts(tenant, request.query);
    }
  }
  log.debug("Leaving route(). Not found.");
  return { status: 404, body: { ok: false, error: "no route " +
                                request.method + " " + p } };
}

// Which role a path belongs to, for recording a failure that escaped it.
function roleOf(p) {
  log.debug("Entering roleOf().");
  const m = /^\/t\/[^/]+\/(saml2|saml11|wsfed|step-up|gnap|ssf|commands)\b/
    .exec(p);
  log.debug("Leaving roleOf().");
  return m ? m[1] : null;
}

function handler(state) {
  log.debug("Entering handler().");
  log.debug("Leaving handler().");
  return function (req, res) {
    const tls = !!req.socket.encrypted;
    const host = req.headers.host || "localhost";
    const scheme = tls ? "https" : "http";
    const url = new URL(req.url, scheme + "://" + host);
    util.readBody(req).then(function (body) {
      let peerCertificate = null;
      if (tls) {
        const presented = req.socket.getPeerCertificate();
        peerCertificate = presented && presented.raw ? presented.raw : null;
      }
      const request = { method: req.method, path: url.pathname,
                        query: url.searchParams, headers: req.headers,
                        body: body, targetUri: scheme + "://" + host +
                                               req.url,
                        tls: tls, peerCertificate: peerCertificate };
      return route(state, request).catch(function (e) {
        log.debug("Caught in handler(): " + ((e && e.message) || e));
        // A role that could not finish — the service unreachable, a
        // document that would not parse — is RECORDED as that role's
        // failure, so the readback says why, and answered 502.
        const role = roleOf(url.pathname);
        const tenantId = (/^\/t\/([^/]+)\//.exec(url.pathname) || [])[1];
        const tenant = tenantId
          ? state.tenants.get(decodeURIComponent(tenantId)) : null;
        if (tenant && role) {
          tenant.record(role, { ok: false, path: url.pathname,
                                error: e.message });
        }
        log.warn("peer: " + req.method + " " + url.pathname + " failed: " +
                 e.message);
        return { status: 502, body: { ok: false, error: e.message } };
      });
    }).then(function (answer) {
      if (answer.status === 302 || answer.status === 303) {
        util.send(res, answer.status, null, { Location: answer.location });
        return;
      }
      util.send(res, answer.status, answer.body, answer.headers);
    }).catch(function (e) {
      log.debug("Caught in handler(): " + ((e && e.message) || e));
      // The body could not be read, or the answer not written: the
      // connection is what failed, and there is nobody left to tell.
      log.warn("peer: " + req.method + " " + req.url + " could not be " +
               "answered: " + e.message);
      if (!res.headersSent) {
        util.send(res, 400, { ok: false, error: e.message });
      }
    });
  };
}

// ---------------------------------------------------------------------------
// START. `options` (for the in-process test): { port, host, names, caDir }.
// Answers `{ port, close(), state }` once listening.
// ---------------------------------------------------------------------------
function start(options) {
  log.debug("Entering start().");
  const opts = options || {};
  const port = opts.port !== undefined ? Number(opts.port)
    : Number(process.env.TEST_PEER_PORT || 9600);
  const publicHost = opts.host || process.env.TEST_PEER_PUBLIC_HOST ||
                     "test-peer";
  const names = opts.names || String(process.env.TEST_PEER_NAMES ||
    publicHost + ",localhost,127.0.0.1").split(",").map(function (one) {
      return one.trim();
    }).filter(Boolean);
  const caDir = opts.caDir !== undefined ? opts.caDir
    : (process.env.TEST_PEER_CA_DIR || "/run/sts-test/test-peer");
  const ca = pki.makeCa();
  const listener = pki.listenerCertificate(ca, names);
  const state = { tenants: new Map(), ca: ca, caFile: null };
  if (caDir) {
    try {
      fs.mkdirSync(caDir, { recursive: true });
      state.caFile = path.join(caDir, "ca.crt");
      fs.writeFileSync(state.caFile, ca.certPem, { mode: 0o644 });
    } catch (e) {
      log.debug("Caught in start(): " + ((e && e.message) || e));
      // Not fatal: every role but the SSF push works without it, and a job
      // that needs it is told by `/peer/info` that there is no file.
      log.warn("peer: the CA certificate could not be written to " + caDir +
               ": " + e.message);
      state.caFile = null;
    }
  }
  const plain = http.createServer(handler(state));
  const secure = https.createServer({ key: listener.key,
                                      cert: listener.cert,
                                      requestCert: true,
                                      rejectUnauthorized: false },
                                    handler(state));
  const front = net.createServer(function (socket) {
    socket.on("error", function (e) {
      log.debug("peer: a connection failed: " + e.message);
    });
    socket.once("data", function (first) {
      socket.pause();
      socket.unshift(first);
      (first[0] === 0x16 ? secure : plain).emit("connection", socket);
      process.nextTick(function () {
        socket.resume();
      });
    });
  });
  log.debug("Leaving start().");
  return new Promise(function (resolve, reject) {
    front.on("error", reject);
    front.listen(port, function () {
      const bound = front.address().port;
      state.plainBase = "http://" + publicHost + ":" + bound;
      state.secureBase = "https://" + publicHost + ":" + bound;
      log.info("sts-test-peer listening on " + bound + " (http and https), " +
               "as " + publicHost + "; CA certificate " +
               (state.caFile || "(not written)"));
      resolve({
        port: bound,
        state: state,
        close: function () {
          log.debug("Entering close().");
          log.debug("Leaving close().");
          return new Promise(function (done) {
            front.close(function () {
              done();
            });
            // The connections were handed to these two, which the front
            // listener's close() does not reach.
            plain.closeAllConnections();
            secure.closeAllConnections();
          });
        }
      });
    });
  });
}

module.exports = { start: start, route: route };

if (require.main === module) {
  start().catch(function (e) {
    log.error("sts-test-peer could not start: " + e.message);
    process.exit(1);
  });
}
