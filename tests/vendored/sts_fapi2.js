"use strict";
//
// File: sts_fapi2.js
//
// ---------------------------------------------------------------------------
// THE FAPI 2.0 SECURITY PROFILE, OVER THE WIRE (#140, 2026-09-22).
//
// A throwaway realm (left behind) carrying `oauth2.fapi=2-security`:
//
//   a. GET /oauth2/fapi reports FAPI 2.0 with its own table.
//   b. DISCOVERY: code alone, PAR required, PS256/ES256/EdDSA, and no public
//      or secret client method.
//   c. REGISTRATION refuses a public client, client_secret_jwt, code
//      id_token and RS256, and takes private_key_jwt on ES256.
//   d. PAR: an authorization request not pushed, a push without client
//      authentication, without PKCE and without redirect_uri, a client
//      assertion with an array aud and one dated two minutes ahead — all
//      refused.
//   e. THE FLOW: pushed, signed in (the ordinary consent rules — a global
//      consent counts under 2.0), a code for 60 seconds at most, an unbound
//      token refused and a DPoP-bound one issued PS256.
//   f. NO ROTATION: the refresh token is redeemed twice.
//   g. THE PORTAL signs its person in under FAPI 2.0 (PAR, code, DPoP).
//   h. TLS: BCP 195 — TLS 1.3 preferred, TLS 1.2 only with an ECDHE AES-GCM
//      suite, a CBC suite refused.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const tls = require("tls");
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
var log = bunyan.createLogger({ name: "sts_fapi2",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fapi2-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.fapi2.example.test/cb";
const PASSWORD = "fapi-Two-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("fapi2-alice");
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

// A TLS handshake with the main port, as `options` asks. Resolves with the
// protocol and cipher, or the error.
function handshake(options) {
  log.debug("Entering handshake().");
  const url = new URL(base);
  return new Promise(function (resolve) {
    const socket = tls.connect(Object.assign({
      host: url.hostname, port: Number(url.port || 443),
      servername: url.hostname, rejectUnauthorized: false
    }, options), function () {
      const answer = { ok: true, protocol: socket.getProtocol(),
                       cipher: socket.getCipher().name };
      socket.end();
      log.debug("Leaving handshake(). " + answer.protocol);
      resolve(answer);
    });
    socket.on("error", function (e) {
      log.debug("Leaving handshake(). " + e.message);
      resolve({ ok: false, error: e.message });
    });
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the FAPI 2.0 Security Profile at " + base + R);

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI 2.0 " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.fapi",
                                       value: "2-security" },
           "put the realm in the FAPI 2.0 Security Profile");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "FAPI2 " + ALICE, givenName: "FAPI", sn: ALICE,
                  mail: ALICE + "@fapi2.test" } }, "created " + ALICE);

  log.info("=== a. the report ===");
  let r = await send(base + R + "/oauth2/fapi");
  check("GET /oauth2/fapi reports FAPI 2.0 with its own table", function () {
    assert.strictEqual(r.body.profile, "2-security", r.raw.slice(0, 200));
    assert.ok(r.body.requirements.every(function (row) {
      return /^FAPI 2.0 /.test(row.section);
    }));
    assert.strictEqual(r.body.access_token_signing_alg, "PS256");
  });

  log.info("=== b. discovery ===");
  r = await send(base + R + "/.well-known/openid-configuration");
  const disco = r.body;
  const issuer = disco.issuer;
  check("discovery: code alone, PAR required, PS256/ES256/EdDSA, no public " +
        "or secret client method", function () {
    assert.deepStrictEqual(disco.response_types_supported, ["code"]);
    assert.strictEqual(disco.require_pushed_authorization_requests, true);
    disco.id_token_signing_alg_values_supported.forEach(function (alg) {
      assert.ok(["PS256", "ES256", "EdDSA"].indexOf(alg) >= 0, alg);
    });
    ["none", "client_secret_basic", "client_secret_post",
     "client_secret_jwt"].forEach(function (method) {
      assert.ok(disco.token_endpoint_auth_methods_supported
        .indexOf(method) < 0, method);
    });
  });
  const jwks = (await send(base + R + "/oauth2/jwks")).body;

  log.info("=== c. registration ===");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = pair.publicKey.export({ format: "jwk" });
  pub.kid = "f2-" + STAMP;
  pub.use = "sig";
  pub.alg = "ES256";
  const metadata = { redirect_uris: [REDIRECT],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks: { keys: [pub] },
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"], scope: SCOPE };
  const refusedRegistration = async function (overrides, what) {
    const answer = await postJson(base + R + "/oauth2/register",
                                  Object.assign({}, metadata, overrides));
    check(what, function () {
      assert.strictEqual(answer.status, 400, answer.raw.slice(0, 300));
    });
  };
  await refusedRegistration({ token_endpoint_auth_method: "none" },
                            "a public client is refused (5.3.2.1 item 3)");
  await refusedRegistration({ token_endpoint_auth_method: "client_secret_jwt" },
                            "client_secret_jwt is refused (item 6)");
  await refusedRegistration({ response_types: ["code id_token"] },
                            "code id_token is refused (5.3.2.2 item 1)");
  await refusedRegistration({ id_token_signed_response_alg: "RS256" },
                            "RS256 is refused (5.4.1)");
  r = await postJson(base + R + "/oauth2/register", metadata);
  check("a private_key_jwt client on ES256 is registered", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 400));
  });
  const client = r.body;
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: client.client_id, scope: one },
             "consented " + one + " for everybody");
  }
  const assertion = function (overrides) {
    const now = Math.floor(Date.now() / 1000);
    return signEs256({ alg: "ES256", typ: "JWT", kid: pub.kid },
      Object.assign({ iss: client.client_id, sub: client.client_id,
        aud: issuer, jti: nodeCrypto.randomBytes(12).toString("base64url"),
        iat: now, exp: now + 60 }, overrides || {}), pair.privateKey);
  };
  const clientAuth = function (overrides) {
    return { client_id: client.client_id,
             client_assertion_type:
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
             client_assertion: assertion(overrides) };
  };
  const dpopKey = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const dpopProof = function (url) {
    const jwk = dpopKey.publicKey.export({ format: "jwk" });
    return signEs256({ typ: "dpop+jwt", alg: "ES256", jwk: jwk },
      { jti: nodeCrypto.randomBytes(12).toString("base64url"), htm: "POST",
        htu: url, iat: Math.floor(Date.now() / 1000) }, dpopKey.privateKey);
  };
  const tokenUrl = base + R + "/oauth2/token";
  const token = function (fields, proof) {
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (proof) {
      headers.DPoP = dpopProof(tokenUrl);
    }
    return send(tokenUrl, { method: "POST", headers: headers,
      body: form(Object.assign(clientAuth(), fields)) });
  };
  const parUrl = base + R + "/oauth2/par";
  const push = function (params, auth) {
    return send(parUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form(Object.assign(auth === undefined ? clientAuth() : auth,
                               params)) });
  };

  log.info("=== d. PAR ===");
  const alice = browser("alice");
  const p = pkce();
  const params = { response_type: "code", redirect_uri: REDIRECT,
    scope: SCOPE, state: "st-" + STAMP, code_challenge: p.challenge,
    code_challenge_method: "S256" };
  r = await alice.go("GET", R + "/oauth2/authorize?" + form(Object.assign(
    { client_id: client.client_id }, params)));
  check("an authorization request that was not pushed is refused (5.3.2.2 " +
        "item 3)", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
  });
  r = await push(params, { client_id: client.client_id });
  check("a push without client authentication is refused (item 4)",
        function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
  });
  r = await push(Object.assign({}, params, { code_challenge: "",
                                             code_challenge_method: "" }));
  check("a push without PKCE is refused (item 5)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });
  r = await push(Object.assign({}, params, { redirect_uri: "" }));
  check("a push without redirect_uri is refused (item 6)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });
  r = await push(params, clientAuth({ aud: [issuer] }));
  check("a client assertion whose aud is an array is refused (5.3.2.1 " +
        "item 8)", function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
  });
  r = await push(params, clientAuth({ iat: Math.floor(Date.now() / 1000) +
                                            120 }));
  check("a client assertion dated two minutes ahead is refused (item 13)",
        function () {
    assert.ok(r.status === 400 || r.status === 401, r.raw.slice(0, 300));
  });

  log.info("=== e. the flow ===");
  r = await push(params);
  check("a pushed request is accepted, its request_uri under 600 seconds",
        function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
    assert.ok(r.body.expires_in < 600, String(r.body.expires_in));
  });
  const consent = { shown: 0 };
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id, request_uri: r.body.request_uri })),
    ALICE, consent);
  const back = paramsAt(r);
  check("the code comes back with iss, and the global consent counted (the " +
        "ordinary rules under 2.0)", function () {
    assert.ok(back && back.get("code"), r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
    assert.strictEqual(back.get("iss"), issuer);
    assert.strictEqual(consent.shown, 0, "consent screens: " + consent.shown);
  });
  const code = back.get("code");
  let t = await token({ grant_type: "authorization_code", code: code,
                        redirect_uri: REDIRECT, code_verifier: p.verifier });
  check("a token request with no binding is refused (5.3.2.1 item 4)",
        function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
  });
  t = await token({ grant_type: "authorization_code", code: code,
                    redirect_uri: REDIRECT, code_verifier: p.verifier }, true);
  check("with DPoP it is issued, signed PS256", function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 400));
    assert.strictEqual(t.body.token_type, "DPoP");
    assert.strictEqual(verifyWithJwks(t.body.access_token, jwks).header.alg,
                       "PS256");
    assert.ok(t.body.refresh_token, "no refresh token");
  });

  log.info("=== f. no rotation ===");
  const refresh = t.body.refresh_token;
  const first = await token({ grant_type: "refresh_token",
                              refresh_token: refresh }, true);
  const second = await token({ grant_type: "refresh_token",
                               refresh_token: refresh }, true);
  check("the refresh token is not rotated: it is redeemed twice (5.3.2.1 " +
        "item 9)", function () {
    assert.strictEqual(first.status, 200, first.raw.slice(0, 300));
    assert.strictEqual(second.status, 200, second.raw.slice(0, 300));
  });

  log.info("=== g. the portal ===");
  const portal = browser("portal");
  r = await follow(portal, await portal.go("GET", R + "/portal"), ALICE,
                   { shown: 0 });
  check("the portal signs its person in under FAPI 2.0 — pushed, code, " +
        "DPoP-bound", function () {
    assert.ok(r.status === 200 || (r.status === 302 &&
              /\/portal/.test(r.location)),
              r.status + " " + r.location + " " + r.text.slice(0, 400));
    assert.ok(!/cannot sign/i.test(r.text), r.text.slice(0, 400));
  });

  log.info("=== h. TLS ===");
  if (/^https:/.test(base)) {
    const preferred = await handshake({});
    check("TLS 1.3 is what a modern client gets", function () {
      assert.strictEqual(preferred.protocol, "TLSv1.3",
                         JSON.stringify(preferred));
    });
    const gcm = await handshake({ maxVersion: "TLSv1.2",
      ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256" });
    check("TLS 1.2 is accepted with an ECDHE AES-GCM suite (BCP 195)",
          function () {
      assert.ok(gcm.ok && gcm.protocol === "TLSv1.2", JSON.stringify(gcm));
    });
    const cbc = await handshake({ maxVersion: "TLSv1.2",
      ciphers: "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:AES128-SHA" });
    check("and refused with a CBC suite BCP 195 does not recommend",
          function () {
      assert.strictEqual(cbc.ok, false, JSON.stringify(cbc));
    });
  } else {
    log.info("  (the service is plain HTTP here; TLS is not checked)");
  }

  assert.ok(checks >= 18, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fapi2")
  .description("The FAPI 2.0 Security Profile over the wire (#140).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
