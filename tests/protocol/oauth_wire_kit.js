// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: oauth_wire_kit.js
//
// ===========================================================================
// THE PLUMBING OF THE D12 OAUTH JOBS (#444, phase 5) — A HELPER, NOT A JOB.
//
// `sts_par.js`, `sts_rfc9101_request_objects.js`,
// `sts_rfc9101_request_object_jti.js`, `sts_rfc9701_introspection.js`,
// `sts_sender_constraints.js` and `sts_oidc_registration.js` carry the
// in-process files of the same names over the wire, and every one of them
// needs the same few things: a throwaway realm per mode, applications and a
// person written through `/admin-api`, a browser that keeps cookies and
// follows nothing, the sign-in screen walked through `authn_signin.js`, JWS
// signed by THIS FILE's own code (the service checking a JWT with the
// implementation that made it would prove only that it agrees with itself),
// DPoP proofs, a listener the service dials for a client's keys or request
// objects, and a code read off `/admin-api/audit` (a code is recorded, never
// sent). They live here once rather than six times.
//
// `kit(name)` answers an object bound to one job: its logger, its STAMP and
// its check counter. Every realm a job makes goes through `realm()`, whose id
// carries the STAMP, so `removeRealms()` — which does anything only when
// STS_TEST_REMOVE_REALMS=1, a private probe's switch — finds them all
// (tests/CLAUDE.md, *No job removes a realm*).
//
// OWNED HERE (MANIFEST.js's LOCAL_HELPERS).
// ===========================================================================

const assert = require("assert");
const http = require("http");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");

const bunyan = require("bunyan");

function kit(name) {
  const log = bunyan.createLogger({ name: name,
    level: process.env.LOG_LEVEL || "info" });
  log.debug("Entering kit(). " + name);
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  const base = String(process.env.OID4VCI_ISSUER_URL ||
                      stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
  const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
    .slice(-10);
  // The address the SERVICE reaches this process at, for a listener it
  // dials (a client's jwks_uri or request_uri).
  const HOST = process.env.OUTBOUND_TEST_HOST ||
               process.env.GNAP_PUSH_HOST || "127.0.0.1";
  let checks = 0;

  function check(what, fn) {
    log.debug("Entering check().");
    fn();
    checks += 1;
    log.info("  [ok] " + what);
    log.debug("Leaving check().");
  }

  function count() {
    log.debug("Entering count().");
    log.debug("Leaving count().");
    return checks;
  }

  function sleep(ms) {
    log.debug("Entering sleep().");
    log.debug("Leaving sleep().");
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function rb(id) {
    log.debug("Entering rb().");
    log.debug("Leaving rb().");
    return id ? base + "/realm/" + id : base;
  }

  // ONE REQUEST. `o.json` is sent as JSON, `o.form` as a form (an object, or
  // a string sent as written so that a repeated parameter can be), `o.raw`
  // as given; `o.jar` is a cookie jar kept across calls. Never follows.
  async function send(url, o) {
    log.debug("Entering send(). " + ((o && o.method) || "GET") + " " + url);
    const opts = o || {};
    const headers = Object.assign({}, opts.headers || {});
    let body;
    if (opts.json !== undefined) {
      headers["Content-Type"] = headers["Content-Type"] ||
                                "application/json";
      body = JSON.stringify(opts.json);
    } else if (opts.form !== undefined) {
      headers["Content-Type"] = headers["Content-Type"] ||
                                "application/x-www-form-urlencoded";
      body = typeof opts.form === "string" ? opts.form
        : new URLSearchParams(clean(opts.form)).toString();
    } else if (opts.raw !== undefined) {
      body = opts.raw;
    }
    if (opts.jar) {
      const cookie = Object.keys(opts.jar).map(function (k) {
        return k + "=" + opts.jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
    }
    const method = opts.method || (body !== undefined ? "POST" : "GET");
    const r = await fetch(url, { method: method, redirect: "manual",
                                 headers: headers, body: body });
    if (opts.jar) {
      keep(opts.jar, r.headers.getSetCookie ? r.headers.getSetCookie() : []);
    }
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in send(): " + ((e && e.message) || e));
      // Not JSON: a page, a JWT or nothing; the caller reads `text`.
      json = null;
    }
    log.debug("Leaving send(). status=" + r.status);
    return { status: r.status, json: json, text: text, headers: r.headers,
             location: r.headers.get("location") || "" };
  }

  // Drops the members a form must not carry (undefined), so a caller can
  // write `{ redirect_uri: undefined }` for "no redirect_uri".
  function clean(o) {
    log.debug("Entering clean().");
    const out = {};
    Object.keys(o).forEach(function (k) {
      if (o[k] !== undefined && o[k] !== null) {
        out[k] = o[k];
      }
    });
    log.debug("Leaving clean().");
    return out;
  }

  function keep(jar, lines) {
    log.debug("Entering keep().");
    (lines || []).forEach(function (line) {
      const pair = String(line).split(";")[0];
      const at = pair.indexOf("=");
      if (at <= 0) {
        return;
      }
      const value = pair.slice(at + 1);
      if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(line))) {
        delete jar[pair.slice(0, at)];
      } else {
        jar[pair.slice(0, at)] = value;
      }
    });
    log.debug("Leaving keep().");
  }

  function shown(r) {
    log.debug("Entering shown().");
    log.debug("Leaving shown().");
    return r.status + " " + (r.location || "") + " " +
      String(r.text || "").replace(/<style[\s\S]*?<\/style>/, "")
        .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").slice(0, 400);
  }

  async function ok(url, body, what) {
    log.debug("Entering ok().");
    const r = await send(url, { json: body || {} });
    assert.ok(r.status === 200 && r.json && r.json.ok !== false,
              (what || url) + ": " + r.status + " " + r.text.slice(0, 400));
    log.debug("Leaving ok().");
    return r.json;
  }

  // A THROWAWAY REALM: its id carries the STAMP; `mode` is development or
  // product, written as an override at creation; risk scoring and consent
  // are off, so a sign-in is a sign-in and nothing else (each job turns
  // either back on where it is the thing under test).
  async function realm(prefix, mode, overrides) {
    log.debug("Entering realm(). " + prefix);
    const id = (prefix + "-" + STAMP).slice(0, 40);
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: prefix + " " + STAMP,
      overrides: Object.assign({ "global.mode": mode || "development" },
                               overrides || {}) },
      "created the realm " + id);
    await set(id, "risk.assessSignIns", false);
    await set(id, "oauth2.consentRequired", false);
    log.debug("Leaving realm(). " + id);
    return id;
  }

  // A realm's setting, through the root API's realms/set (a realms.* key
  // posted to a realm's own config/set lands on the process).
  function set(id, key, value) {
    log.debug("Entering set(). " + key + "=" + value);
    log.debug("Leaving set().");
    return ok(base + "/admin-api/realms/set", { id: id, key: key,
      value: typeof value === "string" ? value : JSON.stringify(value) },
      "set " + key + " on " + id);
  }

  // A realm's override taken off again, so the realm reads the process's.
  function unset(id, key) {
    log.debug("Entering unset(). " + key);
    log.debug("Leaving unset().");
    return ok(base + "/admin-api/realms/unset", { id: id, key: key },
              "unset " + key + " on " + id);
  }

  // A code's count before and after `act()`: answers `{ answer, rose }`,
  // `rose` the number of new rows (waited for briefly).
  async function coded(id, code, act) {
    log.debug("Entering coded(). " + code);
    const before = await codeCount(id, code);
    const answer = await act();
    const after = await codeAfter(id, code, before);
    log.debug("Leaving coded(). " + (after - before));
    return { answer: answer, rose: after - before };
  }

  // A PROCESS-WIDE setting (an `exclusive` job's), put back with reset.
  function setProcess(key, value) {
    log.debug("Entering setProcess(). " + key);
    log.debug("Leaving setProcess().");
    return ok(base + "/admin-api/config/set", { key: key,
      value: typeof value === "string" ? value : JSON.stringify(value) },
      "set " + key + " on the process");
  }

  function resetProcess(key) {
    log.debug("Entering resetProcess(). " + key);
    log.debug("Leaving resetProcess().");
    return ok(base + "/admin-api/config/reset", { key: key },
              "reset " + key + " on the process");
  }

  async function app(id, identifier, fields, extra) {
    log.debug("Entering app(). " + identifier);
    const answer = await ok(rb(id) + "/admin-api/applications/create",
      Object.assign({ identifier: identifier, name: identifier,
                      protocols: ["oauth2", "oidc"], fields: fields }, extra),
      id + ": created " + identifier);
    log.debug("Leaving app().");
    return answer;
  }

  function appSet(id, identifier, attribute, value) {
    log.debug("Entering appSet(). " + attribute);
    log.debug("Leaving appSet().");
    return send(rb(id) + "/admin-api/applications/set", { json: {
      application: identifier, attribute: attribute, value: value } });
  }

  function person(id, username, password) {
    log.debug("Entering person().");
    log.debug("Leaving person().");
    return registry.ensurePerson(rb(id), username, password);
  }

  // A BROWSER: a cookie jar, and redirects left to the caller.
  function browser() {
    log.debug("Entering browser().");
    const jar = {};
    const self = {
      jar: jar,
      go: function (url, o) {
        log.debug("Entering go().");
        log.debug("Leaving go().");
        const absolute = /^https?:\/\//i.test(url) ? url : base + url;
        return send(absolute, Object.assign({ jar: jar }, o || {}));
      }
    };
    log.debug("Leaving browser().");
    return self;
  }

  function toSignIn(r) {
    log.debug("Entering toSignIn().");
    log.debug("Leaving toSignIn().");
    return (r.status === 302 || r.status === 303) &&
      /\/authn\/login/.test(r.location);
  }

  // THE SIGN-IN SCREEN, AS ITS PAGE WALKS IT, then the redirects up to the
  // first that leaves this service (or a page it answers).
  async function signIn(id, b, first, username, password) {
    log.debug("Entering signIn().");
    if (!toSignIn(first)) {
      log.debug("Leaving signIn(). Not sent to sign in.");
      return first;
    }
    let r = await authnSignin.signInWithJar(rb(id), first.location,
      { action: "login", username: username, password: password }, b.jar);
    for (let hops = 0; hops < 8 && (r.status === 302 || r.status === 303) &&
         (/^\//.test(r.location) ||
          String(r.location).indexOf(base) === 0); hops++) {
      r = await b.go(r.location);
    }
    log.debug("Leaving signIn(). " + r.status);
    return r;
  }

  // The authorization response's parameters, where it went to `target`.
  function answerAt(r, target) {
    log.debug("Entering answerAt().");
    const loc = String((r && r.location) || "");
    if (!r || (r.status !== 302 && r.status !== 303) ||
        loc.indexOf(target) !== 0) {
      log.debug("Leaving answerAt(). Not there.");
      return null;
    }
    const u = new URL(loc);
    const out = new URLSearchParams(u.search);
    new URLSearchParams(u.hash.replace(/^#/, "")).forEach(function (v, k) {
      out.set(k, v);
    });
    log.debug("Leaving answerAt().");
    return out;
  }

  function basic(clientId, secret) {
    log.debug("Entering basic().");
    log.debug("Leaving basic().");
    return "Basic " + Buffer.from(encodeURIComponent(clientId) + ":" +
                                  encodeURIComponent(secret))
      .toString("base64");
  }

  // ------------------------------------------------------------------ JOSE
  function b64u(value) {
    log.debug("Entering b64u().");
    log.debug("Leaving b64u().");
    return Buffer.from(Buffer.isBuffer(value) ? value :
      (typeof value === "string" ? value : JSON.stringify(value)))
      .toString("base64url");
  }

  function keyPair(alg, kid) {
    log.debug("Entering keyPair(). " + alg);
    let pair;
    if (/^ES256/.test(alg)) {
      pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    } else if (/^ES384/.test(alg)) {
      pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
    } else {
      pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    }
    const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
      { kid: kid, use: "sig", alg: alg });
    log.debug("Leaving keyPair().");
    return { privateKey: pair.privateKey, publicKey: pair.publicKey,
             jwk: jwk, kid: kid, alg: alg };
  }

  // A JWS in compact form. `key` is a keyPair(), or for HS* a string secret;
  // `alg: none` signs nothing.
  function jws(alg, header, claims, key) {
    log.debug("Entering jws(). " + alg);
    const input = b64u(Object.assign({ alg: alg }, header || {})) + "." +
                  b64u(claims);
    let sig = "";
    if (alg === "none") {
      sig = "";
    } else if (/^HS/.test(alg)) {
      sig = nodeCrypto.createHmac("sha" + alg.slice(2), key)
        .update(input).digest("base64url");
    } else if (/^ES/.test(alg)) {
      sig = nodeCrypto.sign("sha" + alg.slice(2), Buffer.from(input),
        { key: key.privateKey, dsaEncoding: "ieee-p1363" })
        .toString("base64url");
    } else if (/^PS/.test(alg)) {
      sig = nodeCrypto.sign("sha" + alg.slice(2), Buffer.from(input),
        { key: key.privateKey,
          padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: Number(alg.slice(2)) / 8 }).toString("base64url");
    } else {
      sig = nodeCrypto.sign("sha" + alg.slice(2), Buffer.from(input),
        key.privateKey).toString("base64url");
    }
    log.debug("Leaving jws().");
    return input + "." + sig;
  }

  function decode(token) {
    log.debug("Entering decode().");
    const parts = String(token || "").split(".");
    let out = null;
    try {
      out = { header: JSON.parse(Buffer.from(parts[0], "base64url")),
              payload: JSON.parse(Buffer.from(parts[1], "base64url")),
              parts: parts };
    } catch (e) {
      log.debug("Caught in decode(): " + ((e && e.message) || e));
      // Not a JWS; the caller asserts on the null.
      out = null;
    }
    log.debug("Leaving decode().");
    return out;
  }

  function thumbprint(jwk) {
    log.debug("Entering thumbprint().");
    const members = jwk.kty === "EC"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : { e: jwk.e, kty: jwk.kty, n: jwk.n };
    log.debug("Leaving thumbprint().");
    return nodeCrypto.createHash("sha256").update(JSON.stringify(members))
      .digest("base64url");
  }

  // An RFC 9449 proof by `key` (a keyPair('ES256')) for `htm` `htu`.
  function dpop(key, htm, htu, extra) {
    log.debug("Entering dpop().");
    const pub = Object.assign({}, key.jwk);
    delete pub.kid;
    delete pub.use;
    delete pub.alg;
    log.debug("Leaving dpop().");
    return jws("ES256", { typ: "dpop+jwt", jwk: pub },
      Object.assign({ jti: nodeCrypto.randomBytes(12).toString("hex"),
                      htm: htm, htu: htu,
                      iat: Math.floor(Date.now() / 1000) }, extra || {}),
      key);
  }

  function pkce() {
    log.debug("Entering pkce().");
    const verifier = nodeCrypto.randomBytes(32).toString("base64url");
    log.debug("Leaving pkce().");
    return { verifier: verifier,
             challenge: nodeCrypto.createHash("sha256").update(verifier)
               .digest("base64url") };
  }

  function rand(n) {
    log.debug("Entering rand().");
    log.debug("Leaving rand().");
    return nodeCrypto.randomBytes(n || 6).toString("hex");
  }

  // ----------------------------------------------------------------- AUDIT
  async function codeCount(id, code) {
    log.debug("Entering codeCount(). " + code);
    const r = await send(rb(id) + "/admin-api/audit?per=500&code=" +
                         encodeURIComponent(code));
    log.debug("Leaving codeCount().");
    return Number((r.json && r.json.matched) || 0);
  }

  // Waits (briefly) for the count of `code` in a realm to pass `above`.
  async function codeAfter(id, code, above) {
    log.debug("Entering codeAfter(). " + code);
    let n = await codeCount(id, code);
    for (let i = 0; i < 20 && n <= above; i += 1) {
      await sleep(150);
      n = await codeCount(id, code);
    }
    log.debug("Leaving codeAfter(). " + n);
    return n;
  }

  // ------------------------------------------------------------- LISTENER
  // A listener the service dials, on every interface; `routes` maps a path
  // to `function (req, res)`; every path asked for is in `hits`.
  async function listener(routes) {
    log.debug("Entering listener().");
    const hits = [];
    const server = http.createServer(function (req, res) {
      const path = String(req.url || "").split("?")[0];
      hits.push(path);
      const route = routes[path];
      if (route) {
        route(req, res);
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise(function (resolve) {
      server.listen(0, "0.0.0.0", resolve);
    });
    const origin = "http://" + HOST + ":" + server.address().port;
    log.debug("Leaving listener(). " + origin);
    return { origin: origin, hits: hits, routes: routes,
             close: function () {
               server.close();
             } };
  }

  // REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
  // would otherwise fill its directory) every realm this run made — each id
  // carries the run's STAMP — is removed at the end, pass or fail. A suite
  // run leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
  async function removeRealms() {
    log.debug("Entering removeRealms().");
    if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
      log.debug("Leaving removeRealms(). Not asked to.");
      return;
    }
    const listed = await send(base + "/admin-api/realms?per=500");
    const mine = ((listed.json && listed.json.realms) || []).filter(
      function (one) {
        return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
      });
    for (const one of mine) {
      const r = await send(base + "/admin-api/realms/remove",
                           { json: { id: one.id } });
      log.info("removed the realm " + one.id + " (" + r.status + ")");
    }
    log.debug("Leaving removeRealms().");
  }

  // THE JOB'S MAIN: runs `test`, removes the realms if asked, holds the
  // floor, and exits non-zero on any failure.
  function main(test, floor) {
    log.debug("Entering main().");
    (async function () {
      let failure = null;
      try {
        await test();
      } catch (e) {
        log.debug("Caught in main(): " + ((e && e.message) || e));
        // Reported below, after the realms are removed.
        failure = e;
      }
      try {
        await removeRealms();
      } catch (e) {
        log.debug("Caught in main(), removing realms: " +
                  ((e && e.message) || e));
        // A removal that fails changes no verdict; it is logged.
        log.warn("could not remove the realms: " + e.message);
      }
      if (!failure && checks < (floor || 1)) {
        failure = new Error("only " + checks + " checks ran (floor " +
                            floor + "); a section has stopped being called.");
      }
      if (failure) {
        log.error(failure.stack || failure.message);
        process.exit(1);
      }
      log.info(checks + " check(s) passed.");
      log.info("Test completed successfully.");
      process.exit(0);
    })();
    log.debug("Leaving main().");
  }

  log.debug("Leaving kit().");
  return { log: log, base: base, STAMP: STAMP, HOST: HOST, check: check,
           count: count, sleep: sleep, rb: rb, send: send, ok: ok,
           shown: shown, realm: realm, set: set, unset: unset,
           coded: coded, setProcess: setProcess,
           resetProcess: resetProcess, app: app, appSet: appSet,
           person: person, browser: browser, toSignIn: toSignIn,
           signIn: signIn, answerAt: answerAt, basic: basic, b64u: b64u,
           keyPair: keyPair, jws: jws, decode: decode,
           thumbprint: thumbprint, dpop: dpop, pkce: pkce, rand: rand,
           codeCount: codeCount, codeAfter: codeAfter, listener: listener,
           removeRealms: removeRealms, main: main };
}

module.exports = { kit: kit };
