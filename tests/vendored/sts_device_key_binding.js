"use strict";
//
// File: sts_device_key_binding.js
//
// ---------------------------------------------------------------------------
// RFC 8628 DEVICE AUTHORIZATION AND OPENID CONNECT KEY BINDING (#150,
// 2026-09-26), over HTTP, in a throwaway realm.
//
//   1. DISCOVERY: the device authorization endpoint and grant, bound_key,
//      and ML-DSA among the DPoP algorithms.
//   2. THE DEVICE FLOW: codes with a DPoP proof; authorization_pending, then
//      slow_down; the person finds the code on /portal/device (a wrong one
//      is refused) and approves it.
//   3. KEY BINDING at the device_code grant: no c_s256 is refused; the right
//      one gets a DPoP-bound token and an ID Token with cnf.jwk and
//      typ dpop+id_token; a second redemption is refused.
//   4. REFRESH: another key is refused, the same key re-binds.
//   5. SECTION 7: the bound ID Token as a token exchange subject_token
//      without a proof from its key is refused.
//   6. THE AUTHORIZATION REQUEST: bound_key without dpop_jkt is refused; with
//      an ML-DSA-44 key the code flow issues an ID Token bound to an AKP key.
//
// OWNED HERE (local: true): this repository's authorization server, portal
// and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_device_key_binding",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "kb-" + TAG;
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const PERSON = names.usernameFor("kb-person");
const PASSWORD = "Kb-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const RP_REDIRECT = "https://rp.keybinding.example/cb";
const TOKEN = base + "/oauth2/token";
const DEVICE = base + "/oauth2/device_authorization";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// Follows redirects inside this service, signing the person in on the
// realm's screen and allowing a consent screen, until the answer leaves the
// service or is a page.
async function follow(who, first) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 20; i++) {
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = PERSON;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await hop(who, "POST", base + "/authn/login", { form: fields });
      continue;
    }
    if (r.status === 200 && /id="consent-allow"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      r = await hop(who, "POST", base + "/oauth2/consent", { form: fields });
      continue;
    }
    if (!(r.status === 302 || r.status === 303) ||
        r.location.indexOf(root + "/") !== 0) {
      break;
    }
    r = await hop(who, "GET", r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function authorizeUrl(client, extra) {
  log.debug("Entering authorizeUrl().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const q = new URLSearchParams(Object.assign({
    response_type: "code", client_id: client.client_id,
    redirect_uri: RP_REDIRECT, scope: "openid", state: "s-" + TAG,
    nonce: "n-" + TAG, code_challenge: crypto.createHash("sha256")
      .update(verifier).digest("base64url"),
    code_challenge_method: "S256" }, extra || {}));
  log.debug("Leaving authorizeUrl().");
  return { url: base + "/oauth2/authorize?" + q.toString(),
           verifier: verifier };
}

function sha256(text) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return crypto.createHash("sha256").update(String(text), "ascii")
    .digest("base64url");
}

// A DPoP key: ES256 or one of the three ML-DSA algorithms (kty AKP).
function newKey(alg) {
  log.debug("Entering newKey(). " + alg);
  const pq = /^ML-DSA-/.test(alg);
  const pair = pq ? crypto.generateKeyPairSync(alg.toLowerCase())
    : crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const j = pair.publicKey.export({ format: "jwk" });
  const jwk = pq ? { kty: "AKP", alg: alg, pub: j.pub }
    : { kty: "EC", crv: j.crv, x: j.x, y: j.y };
  const canonical = pq
    ? JSON.stringify({ alg: jwk.alg, kty: jwk.kty, pub: jwk.pub })
    : JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  log.debug("Leaving newKey().");
  return { alg: alg, pq: pq, privateKey: pair.privateKey, jwk: jwk,
           jkt: crypto.createHash("sha256").update(canonical, "utf8")
             .digest("base64url") };
}

function proof(key, htu, extra) {
  log.debug("Entering proof().");
  const header = { typ: "dpop+jwt", alg: key.alg, jwk: key.jwk };
  const payload = Object.assign({ jti: crypto.randomBytes(16)
    .toString("base64url"), htm: "POST", htu: htu,
    iat: Math.floor(Date.now() / 1000) }, extra || {});
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = key.pq
    ? crypto.sign(null, Buffer.from(input, "ascii"), key.privateKey)
    : crypto.sign("sha256", Buffer.from(input, "ascii"),
                  { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving proof().");
  return input + "." + signature.toString("base64url");
}

function headerOf(jwt) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[0], "base64url")
    .toString("utf8"));
}

async function register(extra) {
  log.debug("Entering register().");
  const r = await hop(null, "POST", base + "/oauth2/register", { json:
    Object.assign({ redirect_uris: [RP_REDIRECT],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code", "refresh_token", DEVICE_GRANT,
                    EXCHANGE_GRANT],
      response_types: ["code"], scope: "openid offline_access bound_key",
      client_name: "Device " + TAG }, extra || {}) });
  assert.strictEqual(r.status, 201, "registration: " + r.text.slice(0, 300));
  log.debug("Leaving register().");
  return r.json;
}

function form(client, fields) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return Object.assign({ client_id: client.client_id,
                         client_secret: client.client_secret }, fields);
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Key Binding " + TAG },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await ok(api + "/config/set", { key: "oauth2.deviceAuthorization",
                                  value: true }, "turned the device flow on");
  await ok(api + "/config/set", { key: "oauth2.deviceCodeIntervalS",
                                  value: 1 }, "shortened the interval");
  await registry.ensurePerson(base, PERSON, PASSWORD);

  log.info("=== 1. discovery ===");
  const as = (await hop(null, "GET", base +
                        "/.well-known/oauth-authorization-server")).json;
  check("the device endpoint and grant, bound_key and ML-DSA DPoP keys are " +
        "published", function () {
    assert.strictEqual(as.device_authorization_endpoint, DEVICE);
    assert.ok(as.grant_types_supported.indexOf(DEVICE_GRANT) >= 0);
    assert.ok(as.scopes_supported.indexOf("bound_key") >= 0);
    ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"].forEach(function (alg) {
      assert.ok(as.dpop_signing_alg_values_supported.indexOf(alg) >= 0, alg);
    });
    assert.ok(as.dpop_signing_alg_values_supported
      .indexOf("SLH-DSA-SHA2-128s") < 0);
  });

  log.info("=== 2. the device flow ===");
  const client = await register();
  const key = newKey("ES256");
  const started = await hop(null, "POST", DEVICE, {
    form: form(client, { scope: "openid offline_access bound_key" }),
    headers: { DPoP: proof(key, DEVICE) } });
  const codes = started.json || {};
  const pending = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: DEVICE_GRANT, device_code: codes.device_code }) });
  const slow = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: DEVICE_GRANT, device_code: codes.device_code }) });
  check("codes are issued; polling answers authorization_pending, then " +
        "slow_down", function () {
    assert.strictEqual(started.status, 200, started.text.slice(0, 300));
    assert.ok(/^[A-Z]{4}-[A-Z]{4}$/.test(codes.user_code), codes.user_code);
    assert.strictEqual(codes.verification_uri, base + "/portal/device");
    assert.ok(codes.verification_uri_complete.indexOf("user_code=" +
      codes.user_code.replace("-", "")) > 0);
    assert.strictEqual(pending.json.error, "authorization_pending",
                       pending.text.slice(0, 200));
    assert.strictEqual(slow.json.error, "slow_down", slow.text.slice(0, 200));
  });

  const browser = jar();
  await follow(browser, await hop(browser, "GET", base + "/portal/device"));
  const wrong = await hop(browser, "GET", base +
                          "/portal/device?user_code=ZZZZ-ZZZZ");
  const found = await follow(browser, await hop(browser, "GET",
    codes.verification_uri_complete));
  check("a wrong code finds nothing; the right one shows the client and " +
        "scopes before anything is approved", function () {
    assert.strictEqual(wrong.status, 404, wrong.text.slice(0, 200));
    assert.strictEqual(found.status, 200, found.text.slice(0, 300));
    assert.ok(/id="device-request"/.test(found.text));
    assert.ok(found.text.indexOf("Device " + TAG) >= 0);
    assert.ok(found.text.indexOf("bound_key") >= 0);
  });
  const approved = await hop(browser, "POST", base + "/portal/device", {
    form: { action: "approve", user_code: codes.user_code,
            csrf_token: csrfOf(found.text) } });
  check("the person approves", function () {
    assert.strictEqual(approved.status, 303, approved.text.slice(0, 300));
  });

  log.info("=== 3. Key Binding at the device_code grant ===");
  const noHash = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: DEVICE_GRANT, device_code: codes.device_code }),
    headers: { DPoP: proof(key, TOKEN) } });
  const issued = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: DEVICE_GRANT, device_code: codes.device_code }),
    headers: { DPoP: proof(key, TOKEN,
                           { c_s256: sha256(codes.device_code) }) } });
  const twice = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: DEVICE_GRANT, device_code: codes.device_code }),
    headers: { DPoP: proof(key, TOKEN,
                           { c_s256: sha256(codes.device_code) }) } });
  const idToken = (issued.json || {}).id_token;
  check("no c_s256 is refused; the right one gets a bound ID Token, once",
        function () {
    assert.strictEqual(noHash.json.error, "invalid_dpop_proof",
                       noHash.text.slice(0, 200));
    assert.strictEqual(issued.status, 200, issued.text.slice(0, 300));
    assert.strictEqual(issued.json.token_type, "DPoP");
    assert.strictEqual(headerOf(idToken).typ, "dpop+id_token");
    assert.deepStrictEqual(payloadOf(idToken).cnf.jwk, key.jwk);
    assert.strictEqual(payloadOf(issued.json.access_token).cnf.jkt, key.jkt);
    assert.strictEqual(twice.json.error, "invalid_grant");
  });

  log.info("=== 4. refresh ===");
  const other = newKey("ES256");
  const stolen = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: "refresh_token", refresh_token: issued.json.refresh_token }),
    headers: { DPoP: proof(other, TOKEN) } });
  const renewed = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: "refresh_token", refresh_token: issued.json.refresh_token }),
    headers: { DPoP: proof(key, TOKEN) } });
  check("a refresh with another key is refused; the same key re-binds",
        function () {
    assert.strictEqual(stolen.json.error, "invalid_dpop_proof",
                       stolen.text.slice(0, 200));
    assert.strictEqual(renewed.status, 200, renewed.text.slice(0, 300));
    assert.deepStrictEqual(payloadOf(renewed.json.id_token).cnf.jwk,
                           key.jwk);
  });

  log.info("=== 5. section 7: a bound ID Token presented ===");
  const bare = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: EXCHANGE_GRANT, subject_token: idToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token" }) });
  const proved = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: EXCHANGE_GRANT, subject_token: idToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token" }),
    headers: { DPoP: proof(key, TOKEN) } });
  check("without a proof from its key it is refused; with one it is not " +
        "refused for the key", function () {
    assert.strictEqual(bare.json.error, "invalid_dpop_proof",
                       bare.text.slice(0, 200));
    assert.ok(!proved.json || proved.json.error !== "invalid_dpop_proof",
              proved.text.slice(0, 200));
  });

  log.info("=== 6. the authorization request, and ML-DSA ===");
  const naked = authorizeUrl(client, { scope: "openid bound_key" });
  const refused = await follow(browser, await hop(browser, "GET",
                                                   naked.url));
  const pq = newKey("ML-DSA-44");
  const asked = authorizeUrl(client, { scope: "openid bound_key",
                                       dpop_jkt: pq.jkt });
  const landed = await follow(browser, await hop(browser, "GET", asked.url));
  const code = new URL(landed.location || RP_REDIRECT).searchParams
    .get("code");
  const pqIssued = await hop(null, "POST", TOKEN, { form: form(client, {
    grant_type: "authorization_code", code: code, redirect_uri: RP_REDIRECT,
    code_verifier: asked.verifier }),
    headers: { DPoP: proof(pq, TOKEN, { c_s256: sha256(code) }) } });
  check("bound_key without dpop_jkt is refused; an ML-DSA-44 key binds the " +
        "ID Token", function () {
    assert.ok(/[?&]error=invalid_request/.test(refused.location),
              refused.status + " " + refused.location);
    assert.ok(code, landed.status + " " + landed.location);
    assert.strictEqual(pqIssued.status, 200, pqIssued.text.slice(0, 300));
    assert.deepStrictEqual(payloadOf(pqIssued.json.id_token).cnf.jwk,
                           pq.jwk);
    assert.strictEqual(payloadOf(pqIssued.json.access_token).cnf.jkt,
                       pq.jkt);
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("RFC 8628 device authorization and OpenID Connect Key " +
    "Binding (#150), over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
