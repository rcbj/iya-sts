"use strict";
//
// File: sts_fapi2_message_signing.js
//
// ---------------------------------------------------------------------------
// FAPI 2.0 MESSAGE SIGNING, OVER THE WIRE (#141, 2026-09-22).
//
// A throwaway realm (left behind) carrying `oauth2.fapi=2-message-signing` —
// the Security Profile and all three of Message Signing's components:
//
//   a. GET /oauth2/fapi lists the 2.0 table and Message Signing's rows.
//   b. DISCOVERY: JARM's response modes only, a signed request object and
//      PAR required.
//   c. THE PUSH: plain parameters, a signed object asking for no JARM mode,
//      and one with no nbf — each refused.
//   d. THE FLOW: a signed request object pushed, the person signs in, and the
//      response is a JARM JWT, signed PS256 and verified here; a DPoP-bound
//      token follows.
//   e. INTROSPECTION as RFC 9701: a signed JWT response, verified here.
//   f. THE PORTAL signs its person in under the profile (signed push, JARM).
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_fapi2_message_signing",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fapims-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.fapims.example.test/cb";
const PASSWORD = "fapi-Msg-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("fapims-alice");
const SCOPE = "openid profile email";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// One browser, with a cookie jar.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
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

function decode(jwt) {
  log.debug("Entering decode().");
  const parts = String(jwt).split(".");
  log.debug("Leaving decode().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url")
                                .toString("utf8")),
           claims: JSON.parse(Buffer.from(parts[1], "base64url")
                                .toString("utf8")) };
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// Where a redirect to REDIRECT put its parameters, or null.
function atClient(r) {
  log.debug("Entering atClient().");
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(REDIRECT) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  log.debug("Leaving atClient().");
  return url.searchParams;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200, "the sign-in screen: " + page.status +
                     " " + page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  log.debug("Leaving signIn().");
  return posted;
}

// Follows redirects inside this service, signing in when asked, until the
// answer leaves it or is a page. `onConsent` answers a consent screen.
async function follow(b, first, who, onConsent) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 12; i++) {
    if (!(r.status === 302 || r.status === 303)) {
      break;
    }
    const where = absolute(r.location);
    if (where.indexOf(base) !== 0) {
      break;
    }
    if (/\/authn\/login\?authn=/.test(where) && who) {
      const signed = await signIn(b, where, who);
      r = signed;
      continue;
    }
    r = await b.go("GET", where);
    if (r.status === 200 && /id="consent-allow"/.test(r.text) && onConsent) {
      onConsent.shown += 1;
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      r = await b.go("POST", R + "/oauth2/consent", form(fields));
    }
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

// An EC P-256 key the client proves possession of, and its public JWK.
function clientKey(kid) {
  log.debug("Entering clientKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "ES256";
  log.debug("Leaving clientKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

// RFC 7523 section 3's client assertion, signed ES256.
function assertion(clientId, key, aud) {
  log.debug("Entering assertion().");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key.jwk.kid };
  const claims = { iss: clientId, sub: clientId, aud: aud,
                   jti: nodeCrypto.randomBytes(12).toString("base64url"),
                   iat: now, exp: now + 60 };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(claims))
                  .toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving assertion().");
  return input + "." + sig.toString("base64url");
}

// The parameters a redirect to REDIRECT carried, query or fragment.
function paramsAt(r) {
  log.debug("Entering paramsAt().");
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(REDIRECT) !== 0) {
    log.debug("Leaving paramsAt(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  log.debug("Leaving paramsAt().");
  return url.hash ? new URLSearchParams(url.hash.slice(1)) : url.searchParams;
}

// Sign a JWT with the client's EC key (ES256).
function signEs256(header, claims, key) {
  log.debug("Entering signEs256().");
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving signEs256().");
  return input + "." + sig.toString("base64url");
}

// A JWS this realm signed, verified against its JWKS by kid; the claims.
function verifyWithJwks(jwt, jwks) {
  log.debug("Entering verifyWithJwks().");
  const parts = String(jwt).split(".");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const jwk = jwks.keys.filter(function (k) {
    return k.kid === header.kid;
  })[0];
  assert.ok(jwk, "no JWKS key " + header.kid);
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const data = Buffer.from(parts[0] + "." + parts[1]);
  const sig = Buffer.from(parts[2], "base64url");
  let ok = false;
  if (header.alg === "PS256") {
    ok = nodeCrypto.verify("sha256", data, { key: key,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32 }, sig);
  } else if (header.alg === "ES256") {
    ok = nodeCrypto.verify("sha256", data, { key: key,
                                             dsaEncoding: "ieee-p1363" }, sig);
  } else if (header.alg === "RS256") {
    ok = nodeCrypto.verify("sha256", data, key, sig);
  }
  assert.ok(ok, "the " + header.alg + " signature does not verify");
  log.debug("Leaving verifyWithJwks().");
  return { header: header,
           claims: JSON.parse(Buffer.from(parts[1], "base64url").toString()) };
}

function halfHash(value) {
  log.debug("Entering halfHash().");
  const digest = nodeCrypto.createHash("sha256").update(String(value), "ascii")
    .digest();
  log.debug("Leaving halfHash().");
  return digest.subarray(0, 16).toString("base64url");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving FAPI 2.0 Message Signing at " + base + R);

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI MS " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.fapi",
                                       value: "2-message-signing" },
           "put the realm in FAPI 2.0 Message Signing");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "FAPI MS " + ALICE, givenName: "FAPI", sn: ALICE,
                  mail: ALICE + "@fapims.test" } }, "created " + ALICE);

  log.info("=== a. the report ===");
  let r = await send(base + R + "/oauth2/fapi");
  check("GET /oauth2/fapi lists the 2.0 table and Message Signing's rows",
        function () {
    assert.strictEqual(r.body.profile, "2-message-signing",
                       r.raw.slice(0, 200));
    const ids = r.body.requirements.map(function (row) {
      return row.id;
    });
    ["no-rotation", "par-required", "signed-request-at-par",
     "jarm-required", "signed-introspection"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, id);
    });
  });

  log.info("=== b. discovery ===");
  r = await send(base + R + "/.well-known/openid-configuration");
  const disco = r.body;
  const issuer = disco.issuer;
  check("discovery: JARM's modes only, a signed request object and PAR " +
        "required", function () {
    assert.deepStrictEqual(disco.response_modes_supported.slice().sort(),
                           ["form_post.jwt", "fragment.jwt", "jwt",
                            "query.jwt"]);
    assert.strictEqual(disco.require_signed_request_object, true);
    assert.strictEqual(disco.require_pushed_authorization_requests, true);
  });
  const jwks = (await send(base + R + "/oauth2/jwks")).body;

  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = pair.publicKey.export({ format: "jwk" });
  pub.kid = "ms-" + STAMP;
  pub.use = "sig";
  pub.alg = "ES256";
  r = await postJson(base + R + "/oauth2/register", {
    redirect_uris: [REDIRECT], token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    request_object_signing_alg: "ES256", jwks: { keys: [pub] },
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"], scope: SCOPE });
  assert.strictEqual(r.status, 201, "registration: " + r.raw.slice(0, 400));
  const client = r.body;
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: client.client_id, scope: one },
             "consented " + one + " for everybody");
  }
  const clientAuth = function (audience) {
    const now = Math.floor(Date.now() / 1000);
    return { client_id: client.client_id,
             client_assertion_type:
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
             client_assertion: signEs256({ alg: "ES256", typ: "JWT",
                                           kid: pub.kid },
               { iss: client.client_id, sub: client.client_id,
                 aud: audience || issuer,
                 jti: nodeCrypto.randomBytes(12).toString("base64url"),
                 iat: now, exp: now + 60 }, pair.privateKey) };
  };
  const requestObject = function (params, overrides) {
    const now = Math.floor(Date.now() / 1000);
    const claims = Object.assign({ iss: client.client_id, aud: issuer,
      client_id: client.client_id, nbf: now, exp: now + 300, iat: now,
      jti: nodeCrypto.randomBytes(12).toString("base64url") }, params);
    Object.keys(overrides || {}).forEach(function (name) {
      if (overrides[name] === undefined) {
        delete claims[name];
      } else {
        claims[name] = overrides[name];
      }
    });
    return signEs256({ alg: "ES256", typ: "oauth-authz-req+jwt",
                       kid: pub.kid }, claims, pair.privateKey);
  };
  const parUrl = base + R + "/oauth2/par";
  const push = function (fields) {
    return send(parUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form(Object.assign(clientAuth(), fields)) });
  };
  const p = pkce();
  const params = { response_type: "code", response_mode: "jwt",
    redirect_uri: REDIRECT, scope: SCOPE, state: "st-" + STAMP,
    code_challenge: p.challenge, code_challenge_method: "S256" };

  log.info("=== c. the push ===");
  r = await push(params);
  check("a push of plain parameters is refused (5.3.2 item 1)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });
  r = await push({ request: requestObject(params,
                                          { response_mode: undefined }) });
  check("a signed object asking for no JARM mode is refused (5.4.2 item 1)",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(/JWT-secured|JARM/.test(r.raw), r.raw.slice(0, 300));
  });
  r = await push({ request: requestObject(params, { nbf: undefined }) });
  check("a signed object with no nbf is refused (5.3.2 item 3)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  log.info("=== d. the flow ===");
  r = await push({ request: requestObject(params) });
  check("a signed request object is pushed", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
  });
  const alice = browser("alice");
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id, request_uri: r.body.request_uri })),
    ALICE, { shown: 0 });
  const back = paramsAt(r);
  let claims = null;
  check("the response is a JARM JWT signed PS256, verified here, carrying " +
        "iss inside it (5.4.2)", function () {
    assert.ok(back && back.get("response") && !back.get("iss"),
              r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
    const opened = verifyWithJwks(back.get("response"), jwks);
    assert.strictEqual(opened.header.alg, "PS256");
    claims = opened.claims;
    assert.strictEqual(claims.iss, issuer);
    assert.strictEqual(claims.aud, client.client_id);
    assert.ok(claims.code);
  });
  const dpopKey = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const tokenUrl = base + R + "/oauth2/token";
  const proof = signEs256({ typ: "dpop+jwt", alg: "ES256",
                            jwk: dpopKey.publicKey.export({ format: "jwk" }) },
    { jti: nodeCrypto.randomBytes(12).toString("base64url"), htm: "POST",
      htu: tokenUrl, iat: Math.floor(Date.now() / 1000) },
    dpopKey.privateKey);
  const t = await send(tokenUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               DPoP: proof },
    body: form(Object.assign(clientAuth(), { grant_type: "authorization_code",
      code: claims.code, redirect_uri: REDIRECT,
      code_verifier: p.verifier })) });
  check("the code is redeemed for a DPoP-bound token", function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 400));
    assert.strictEqual(t.body.token_type, "DPoP");
  });

  log.info("=== e. introspection ===");
  const introspect = await send(base + R + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/token-introspection+jwt" },
    body: form(Object.assign(clientAuth(),
                             { token: t.body.access_token })) });
  check("an RFC 9701 introspection response is a JWT signed PS256 that " +
        "verifies here (5.5)", function () {
    assert.strictEqual(introspect.status, 200, introspect.raw.slice(0, 300));
    const opened = verifyWithJwks(introspect.raw.trim(), jwks);
    assert.strictEqual(opened.header.alg, "PS256");
    assert.strictEqual(opened.header.typ, "token-introspection+jwt");
    assert.strictEqual(opened.claims.token_introspection.active, true);
  });

  log.info("=== f. the portal ===");
  const portal = browser("portal");
  r = await follow(portal, await portal.go("GET", R + "/portal"), ALICE,
                   { shown: 0 });
  check("the portal signs its person in under the profile — a signed " +
        "request pushed, a JARM response verified", function () {
    assert.ok(r.status === 200 || (r.status === 302 &&
              /\/portal/.test(r.location)),
              r.status + " " + r.location + " " + r.text.slice(0, 400));
    assert.ok(!/cannot sign/i.test(r.text), r.text.slice(0, 400));
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fapi2_message_signing")
  .description("FAPI 2.0 Message Signing over the wire (#141).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
