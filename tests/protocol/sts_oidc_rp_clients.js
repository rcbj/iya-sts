// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidc_rp_clients.js
//
// ---------------------------------------------------------------------------
// THE SERVICE'S OWN SURFACES AS CLIENTS: NOTHING A REQUEST'S Host WRITES
// ONTO THEIR ENTRIES, AND THE DPoP PROOF THEIR TOKENS ARE BOUND WITH, OVER
// THE WIRE.
//
// D12 (#444): carries over `tests/oidc_rp_addresses.js` (2026-09-12) and
// `tests/oidc_rp_dpop.js` (#34). Both were written when `/admin` and
// `/portal` were OpenID Connect relying parties run by this process
// (`common/oidc_rp.ts`); since #446 and #568 they are static applications
// signing in IN THE BROWSER as public clients, and `oidc_rp.ts` serves only
// the embedded debugger, on a listener of its own. So what a client can
// still observe is asked here, in a development and a product realm:
//
//   A. AN INVENTED Host WRITES NOTHING: anonymous requests to the console's,
//      the portal's and the reports application's shells and callbacks,
//      each carrying `Host: evil.example` and `X-Forwarded-Host:
//      evil.example`, leave `sts-admin-console`, `sts-user-portal` and
//      `sts-report` with exactly the redirect URIs they were seeded with —
//      in either mode — and no seeded address names the invented host.
//   B. THE PROOF THE TOKENS ARE BOUND WITH, through the SERVER's verifier
//      at `/oauth2/token` (oidc_rp_dpop.js section 2): a proof made for
//      this token endpoint is accepted and binds the token to its key
//      (`token_type` DPoP, `cnf.jkt` the key's thumbprint); the same proof
//      presented again is a replay and refused; a fresh proof from the same
//      key is accepted (a renewal months later); a proof made for another
//      URL is refused naming htu (STS-OAUTH-0106) and one made for another
//      method naming htm (STS-OAUTH-0105); a proof carrying a private
//      member in its jwk is refused.
//
// NOT carried, and why: oidc_rp_addresses B, C and D — the pinned base,
// development's learning up to `oidcRp.maxRedirectUris`, the back channel's
// loopback origin and the flow lifetime — are `oidc_rp.ts`'s, which now
// serves only the embedded debugger, a listener no stack publishes for a
// client (class (d)); oidc_rp_dpop sections 1, 3 and 4 (the relying party's
// own key and proof-building — the console's proof is made by its browser
// bundle now — and a proof verified in two realms, which no request can
// make, since a proof's htu names the realm) are class (d).
//
// OWNED HERE (local: true): this repository's own clients and token
// endpoint.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_oidc_rp_clients",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const DEV = "orp-d-" + STAMP;
const PROD = "orp-p-" + STAMP;
const SECRET = "orp-secret-" + nodeCrypto.randomBytes(16).toString("hex");
const CLIENTS = ["sts-admin-console", "sts-user-portal", "sts-report"];
const FLOOR = 13;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function rb(realm) {
  log.debug("Entering rb().");
  log.debug("Leaving rb().");
  return base + "/realm/" + realm;
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
                               headers: headers || {}, body: body });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, JSON.stringify(payload),
                       { "Content-Type": "application/json" });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

// A GET carrying a Host header of the caller's choosing, which `fetch`
// will not send: the https module, to the service's own address.
function forged(path) {
  log.debug("Entering forged(). " + path);
  const u = new URL(base);
  log.debug("Leaving forged().");
  return new Promise(function (resolve) {
    const req = https.request({ host: u.hostname,
      port: Number(u.port || 443), path: path, method: "GET",
      servername: u.hostname,
      headers: { Host: "evil.example", "X-Forwarded-Host": "evil.example",
                 "X-Forwarded-Proto": "https",
                 Accept: "text/html" } }, function (res) {
      res.resume();
      res.on("end", function () {
        resolve({ status: res.statusCode, location:
                    String(res.headers.location || "") });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in forged(): " + ((e && e.message) || e));
      // A refused connection is an answer too: nothing was written by it.
      resolve({ status: 0, location: "", error: String(e.message || e) });
    });
    req.end();
  });
}

async function redirectsOf(realm, id) {
  log.debug("Entering redirectsOf(). " + id);
  const r = await call("GET", rb(realm) + "/admin-api/applications?" +
                       "application=" + id);
  // `?application=` answers the one application's view at the top level.
  const attributes = (r.json && r.json.attributes) || {};
  log.debug("Leaving redirectsOf().");
  return (attributes.oauthRedirectUri || []).slice().sort();
}

async function hostSection(realm, mode) {
  log.debug("Entering hostSection(). " + realm);
  log.info("=== A. an invented Host writes nothing (" + mode + ") ===");
  const paths = ["/admin", "/admin/callback?code=x&state=y", "/portal",
                 "/portal/callback?code=x&state=y", "/report",
                 "/report/callback?code=x&state=y"];
  const sweep = async function () {
    const answers = [];
    for (const p of paths) {
      answers.push(await forged("/realm/" + realm + p));
    }
    return answers;
  };
  const read = async function () {
    const out = {};
    for (const id of CLIENTS) {
      out[id] = await redirectsOf(realm, id);
    }
    return out;
  };
  // FIRST, before any honest request has reached the realm's surfaces: a
  // seed made lazily from the first request's Host would be made HERE.
  const answers = await sweep();
  const first = await read();
  check("A. (" + mode + ") the shells and callbacks answer a request with " +
        "an invented Host without sending the browser to it", function () {
    answers.forEach(function (a, i) {
      assert.ok(a.status > 0 && a.status < 500, paths[i] + ": " +
                JSON.stringify(a));
      assert.ok(a.location.indexOf("evil.example") < 0, paths[i] + ": " +
                a.location);
    });
  });
  check("A. (" + mode + ") and the three surfaces' clients carry redirect " +
        "URIs on this service's own address only — none learnt from the " +
        "invented Host", function () {
    CLIENTS.forEach(function (id) {
      assert.ok(first[id].length >= 1, id + ": " + JSON.stringify(first[id]));
      first[id].forEach(function (uri) {
        assert.ok(uri.indexOf(rb(realm) + "/") === 0, id + ": " + uri);
      });
    });
  });
  await call("GET", rb(realm) + "/admin", undefined, { Accept: "text/html" });
  await sweep();
  const after = await read();
  check("A. (" + mode + ") an honest request and a second forged sweep " +
        "change NOTHING on the three client entries — the assertion the " +
        "in-process file was for", function () {
    CLIENTS.forEach(function (id) {
      assert.deepStrictEqual(after[id], first[id], id);
    });
  });
  log.debug("Leaving hostSection().");
}

// A DPoP proof (RFC 9449) signed with `key`, for `htm` and `htu`.
function proof(key, htm, htu, extra) {
  log.debug("Entering proof().");
  const jwk = key.publicKey.export({ format: "jwk" });
  const header = { typ: "dpop+jwt", alg: "ES256",
    jwk: Object.assign({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
                       (extra && extra.jwk) || {}) };
  const claims = { jti: nodeCrypto.randomBytes(16).toString("base64url"),
                   htm: htm, htu: htu, iat: Math.floor(Date.now() / 1000) };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving proof().");
  return input + "." + sig.toString("base64url");
}

function thumbprint(key) {
  log.debug("Entering thumbprint().");
  const jwk = key.publicKey.export({ format: "jwk" });
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x,
                                     y: jwk.y });
  log.debug("Leaving thumbprint().");
  return nodeCrypto.createHash("sha256").update(canonical)
    .digest("base64url");
}

function tokenWith(dpop) {
  log.debug("Entering tokenWith().");
  log.debug("Leaving tokenWith().");
  return call("POST", rb(DEV) + "/oauth2/token", new URLSearchParams({
    grant_type: "client_credentials", client_id: "orp-client",
    client_secret: SECRET }).toString(),
    { "Content-Type": "application/x-www-form-urlencoded", DPoP: dpop });
}

// The newest refused call at the token endpoint: its code.
async function lastCode() {
  log.debug("Entering lastCode().");
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", rb(DEV) + "/admin-api/audit?per=20&action=" +
                         "protocol.call");
    const rows = ((r.json && (r.json.events || r.json.rows)) || [])
      .filter(function (row) {
        return /\/oauth2\/token$/.test(String(row.target || "")) &&
               row.outcome !== "success";
      });
    if (rows.length && rows[0].errorCode) {
      log.debug("Leaving lastCode(). " + rows[0].errorCode);
      return String(rows[0].errorCode);
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  log.debug("Leaving lastCode(). none");
  return "";
}

async function dpopSection() {
  log.debug("Entering dpopSection().");
  log.info("=== B. the proof, through the server's own verifier ===");
  await ok(rb(DEV) + "/admin-api/applications/create", {
    identifier: "orp-client", name: "orp-client", protocols: ["oauth2"],
    fields: { oauthClientId: ["orp-client"], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"] } },
    "created the client");
  const key = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const htu = rb(DEV) + "/oauth2/token";
  const first = proof(key, "POST", htu);
  let r = await tokenWith(first);
  check("B. a proof made for this token endpoint verifies where every " +
        "client's proof is checked, and binds the token to its key",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.token_type, "DPoP");
    const claims = JSON.parse(Buffer.from(r.json.access_token.split(".")[1],
                                          "base64url").toString("utf8"));
    assert.strictEqual(claims.cnf && claims.cnf.jkt, thumbprint(key));
  });
  r = await tokenWith(first);
  check("B. presenting the SAME proof twice is a replay, refused",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_dpop_proof");
  });
  r = await tokenWith(proof(key, "POST", htu));
  check("B. while a new proof from the same key is accepted — what a " +
        "renewal makes, months after the sign-in", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await tokenWith(proof(key, "POST", rb(DEV) + "/oauth2/elsewhere"));
  const htuCode = await lastCode();
  check("B. a proof made for another URL is refused, naming htu " +
        "(STS-OAUTH-0106)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_dpop_proof");
    assert.strictEqual(htuCode, "STS-OAUTH-0106");
  });
  r = await tokenWith(proof(key, "GET", htu));
  const htmCode = await lastCode();
  check("B. and one made for another method, naming htm (STS-OAUTH-0105)",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_dpop_proof");
    assert.strictEqual(htmCode, "STS-OAUTH-0105");
  });
  const priv = key.privateKey.export({ format: "jwk" });
  r = await tokenWith(proof(key, "POST", htu, { jwk: { d: priv.d } }));
  check("B. a proof whose jwk carries a private member is refused — the " +
        "PUBLIC members only go in the header", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_dpop_proof");
  });
  check("B. and no refusal names a code", function () {
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text));
  });
  log.debug("Leaving dpopSection().");
}

async function test() {
  log.debug("Entering test().");
  for (const id of [DEV, PROD]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Own clients " + STAMP },
      "created the realm " + id);
  }
  await setting(DEV, "global.mode", "development");
  await setting(PROD, "global.mode", "product");
  await hostSection(DEV, "development");
  await hostSection(PROD, "product");
  await dpopSection();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made is removed
// at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [DEV, PROD]) {
    const r = await call("POST", base + "/admin-api/realms/remove",
                         JSON.stringify({ id: id }),
                         { "Content-Type": "application/json" });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
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
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A removal that fails is logged; the job's verdict is the test's.
    log.warn("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
  process.exit(0);
}

main();
