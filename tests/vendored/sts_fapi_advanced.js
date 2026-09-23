"use strict";
//
// File: sts_fapi_advanced.js
//
// ---------------------------------------------------------------------------
// FAPI 1.0 PART 2 ADVANCED AND JARM, OVER THE WIRE (#139, #143, 2026-09-22).
//
// A throwaway realm (left behind) carrying `oauth2.fapi=1-advanced`, with
// dynamic registration opened:
//
//   a. GET /oauth2/fapi reports Advanced over Baseline, PS256 for access
//      tokens.
//   b. DISCOVERY: the two response types, PS256/ES256 lists, no RSA1_5, the
//      JARM modes and members, a signed request object required, and
//      mtls_endpoint_aliases where the port is TLS.
//   c. REGISTRATION refuses client_secret_jwt, a public client, a response
//      type carrying a token and an RS256 ID Token, and takes a
//      private_key_jwt client on ES256.
//   d. THE REQUEST OBJECT: a plain request, one with no nbf, one with a
//      foreign aud and one living too long are refused; a push without PKCE
//      is refused.
//   e. PAR + JARM: a signed request pushed, the person signs in and
//      consents, and the response comes back as a JWT verified here against
//      the realm's JWKS (PS256), carrying code, state, iss, aud and exp.
//   f. THE TOKEN ENDPOINT refuses an unbound token and issues a DPoP-bound
//      one, the access token and ID Token signed PS256.
//   g. HYBRID: code id_token by value, with no PKCE, answered in the
//      fragment with an ID Token carrying c_hash and s_hash.
//   h. oauth2.fapiRequireMtls: a DPoP-only token request is refused.
//   i. THE HOSTED SURFACES: the portal signs its person in under Advanced —
//      signed request, PAR, JARM — and, with oauth2.fapiRequireMtls on, over
//      a loopback that presents its CA-issued client certificate.
//   j. JARM outside FAPI: a named server with fapi=off answers query.jwt and
//      refuses query.jwt carrying an id_token in clear.
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
var log = bunyan.createLogger({ name: "sts_fapi_advanced",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fapiadv-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.fapiadv.example.test/cb";
const PASSWORD = "fapi-Advanced-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("fapiadv-alice");
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
  log.info("Driving FAPI 1.0 Advanced at " + base + R);

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI Advanced " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.fapi",
                                       value: "1-advanced" },
           "put the realm in FAPI 1.0 Advanced");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "FAPI " + ALICE, givenName: "FAPI", sn: ALICE,
                  mail: ALICE + "@fapiadv.test" } }, "created " + ALICE);

  log.info("=== a. the report ===");
  let r = await send(base + R + "/oauth2/fapi");
  check("GET /oauth2/fapi reports Advanced over Baseline and PS256 access " +
        "tokens", function () {
    assert.strictEqual(r.body.profile, "1-advanced", r.raw.slice(0, 200));
    assert.strictEqual(r.body.access_token_signing_alg, "PS256");
    const ids = r.body.requirements.map(function (row) {
      return row.id;
    });
    ["signed-request-object", "response-type", "sender-constrained",
     "request-object-lifetime", "algorithms", "confidential-client-auth"]
      .forEach(function (id) {
        assert.ok(ids.indexOf(id) >= 0, id);
      });
  });

  log.info("=== b. discovery ===");
  r = await send(base + R + "/.well-known/openid-configuration");
  const disco = r.body;
  const issuer = disco.issuer;
  check("discovery narrows to Advanced: two response types, PS256/ES256, " +
        "no RSA1_5, JARM, a signed request object", function () {
    assert.deepStrictEqual(disco.response_types_supported.slice().sort(),
                           ["code", "code id_token"]);
    ["id_token_signing_alg_values_supported",
     "request_object_signing_alg_values_supported",
     "authorization_signing_alg_values_supported",
     "token_endpoint_auth_signing_alg_values_supported"]
      .forEach(function (name) {
        assert.deepStrictEqual(disco[name], ["PS256", "ES256"], name);
      });
    assert.ok((disco.request_object_encryption_alg_values_supported || [])
      .indexOf("RSA1_5") < 0);
    ["jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]
      .forEach(function (mode) {
        assert.ok(disco.response_modes_supported.indexOf(mode) >= 0, mode);
      });
    assert.strictEqual(disco.require_signed_request_object, true);
    assert.ok(disco.token_endpoint_auth_methods_supported
      .indexOf("client_secret_jwt") < 0);
  });
  const tls = /^https:/.test(base);
  check("mtls_endpoint_aliases is published " + (tls ? "(the port is TLS)"
                                                     : "only over TLS"),
        function () {
    if (tls) {
      assert.strictEqual(disco.mtls_endpoint_aliases.token_endpoint,
                         disco.token_endpoint);
      assert.strictEqual(disco.mtls_endpoint_aliases.userinfo_endpoint,
                         disco.userinfo_endpoint);
    } else {
      assert.strictEqual(disco.mtls_endpoint_aliases, undefined);
    }
  });
  const jwks = (await send(base + R + "/oauth2/jwks")).body;

  log.info("=== c. registration ===");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = pair.publicKey.export({ format: "jwk" });
  pub.kid = "adv-" + STAMP;
  pub.use = "sig";
  pub.alg = "ES256";
  const metadata = { redirect_uris: [REDIRECT],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    request_object_signing_alg: "ES256",
    jwks: { keys: [pub] },
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code", "code id_token"], scope: SCOPE };
  const refusedRegistration = async function (overrides, what) {
    const answer = await postJson(base + R + "/oauth2/register",
                                  Object.assign({}, metadata, overrides));
    check(what, function () {
      assert.strictEqual(answer.status, 400, answer.raw.slice(0, 300));
    });
  };
  await refusedRegistration({ token_endpoint_auth_method: "client_secret_jwt" },
                            "client_secret_jwt is refused (item 14)");
  await refusedRegistration({ token_endpoint_auth_method: "none" },
                            "a public client is refused (item 16)");
  await refusedRegistration({ response_types: ["code token"] },
                            "a response type carrying a token is refused");
  await refusedRegistration({ id_token_signed_response_alg: "RS256" },
                            "an RS256 ID Token is refused (8.6)");
  r = await postJson(base + R + "/oauth2/register", metadata);
  check("a private_key_jwt client on ES256 is registered", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 400));
  });
  const client = r.body;
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: client.client_id, scope: one },
             "consented " + one + " (Advanced asks the person anyway)");
  }
  const assertion = function () {
    const now = Math.floor(Date.now() / 1000);
    return signEs256({ alg: "ES256", typ: "JWT", kid: pub.kid },
      { iss: client.client_id, sub: client.client_id, aud: issuer,
        jti: nodeCrypto.randomBytes(12).toString("base64url"),
        iat: now, exp: now + 60 }, pair.privateKey);
  };
  const clientAuth = function () {
    return { client_id: client.client_id,
             client_assertion_type:
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
             client_assertion: assertion() };
  };
  const requestObject = function (params, overrides) {
    const now = Math.floor(Date.now() / 1000);
    return signEs256({ alg: "ES256", typ: "oauth-authz-req+jwt",
                       kid: pub.kid },
      Object.assign({ iss: client.client_id, aud: issuer,
                      client_id: client.client_id, nbf: now,
                      exp: now + 300, iat: now,
                      jti: nodeCrypto.randomBytes(12).toString("base64url") },
                    params, overrides || {}), pair.privateKey);
  };
  const dpopKey = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const dpopProof = function (url) {
    const jwk = dpopKey.publicKey.export({ format: "jwk" });
    return signEs256({ typ: "dpop+jwt", alg: "ES256", jwk: jwk },
      { jti: nodeCrypto.randomBytes(12).toString("base64url"), htm: "POST",
        htu: url, iat: Math.floor(Date.now() / 1000) }, dpopKey.privateKey);
  };
  const tokenUrl = base + R + "/oauth2/token";
  const token = function (bodyFields, proof) {
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (proof) {
      headers.DPoP = dpopProof(tokenUrl);
    }
    return send(tokenUrl, { method: "POST", headers: headers,
      body: form(Object.assign(clientAuth(), bodyFields)) });
  };

  log.info("=== d. the request object ===");
  const alice = browser("alice");
  const p = pkce();
  const params = { response_type: "code", response_mode: "jwt",
    client_id: client.client_id, redirect_uri: REDIRECT, scope: SCOPE,
    state: "st-" + STAMP, nonce: "n-" + STAMP, code_challenge: p.challenge,
    code_challenge_method: "S256" };
  r = await alice.go("GET", R + "/oauth2/authorize?" + form(params));
  check("a plain request, with no request object, is refused (item 1)",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
  });
  const byValue = async function (overrides) {
    return alice.go("GET", R + "/oauth2/authorize?" + form({
      client_id: client.client_id,
      request: requestObject(params, overrides) }));
  };
  r = await byValue({ nbf: undefined });
  check("a request object with no nbf is refused (item 17)", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 200));
    assert.ok(/nbf/.test(r.text), r.text.slice(0, 300));
  });
  r = await byValue({ aud: "https://elsewhere.example" });
  check("a request object addressed elsewhere is refused (item 15)",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 200));
  });
  const now0 = Math.floor(Date.now() / 1000);
  r = await byValue({ nbf: now0, exp: now0 + 3700 });
  check("a request object living over 60 minutes is refused (item 13)",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 200));
  });
  const parUrl = base + R + "/oauth2/par";
  r = await send(parUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(Object.assign(clientAuth(), { request: requestObject(params,
      { code_challenge: undefined, code_challenge_method: undefined }) })) });
  check("a push without PKCE is refused (item 18)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  log.info("=== e. PAR and JARM ===");
  r = await send(parUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(Object.assign(clientAuth(),
                             { request: requestObject(params) })) });
  check("a signed request object is pushed", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
  });
  const consent = { shown: 0 };
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id, request_uri: r.body.request_uri })),
    ALICE, consent);
  let back = paramsAt(r);
  let jarmClaims = null;
  check("the response is ONE parameter, a JWT signed PS256 that verifies " +
        "against the realm's JWKS and carries code, state, iss, aud and exp",
        function () {
    assert.ok(back && back.get("response") && !back.get("code"),
              r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
    const opened = verifyWithJwks(back.get("response"), jwks);
    assert.strictEqual(opened.header.alg, "PS256");
    jarmClaims = opened.claims;
    assert.strictEqual(jarmClaims.iss, issuer);
    assert.strictEqual(jarmClaims.aud, client.client_id);
    assert.strictEqual(jarmClaims.state, params.state);
    assert.ok(jarmClaims.code);
    assert.ok(jarmClaims.exp > Math.floor(Date.now() / 1000));
    assert.strictEqual(consent.shown, 1, "consent screens: " + consent.shown);
  });

  log.info("=== f. the token endpoint ===");
  let t = await token({ grant_type: "authorization_code",
                        code: jarmClaims.code, redirect_uri: REDIRECT,
                        code_verifier: p.verifier });
  check("a token request with no DPoP proof and no certificate is refused " +
        "(item 5)", function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_request");
  });
  t = await token({ grant_type: "authorization_code", code: jarmClaims.code,
                    redirect_uri: REDIRECT, code_verifier: p.verifier }, true);
  check("with a DPoP proof it is issued: a DPoP-bound access token and an " +
        "ID Token, both signed PS256", function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 400));
    assert.strictEqual(t.body.token_type, "DPoP");
    const at = verifyWithJwks(t.body.access_token, jwks);
    assert.strictEqual(at.header.alg, "PS256");
    assert.ok(at.claims.cnf && at.claims.cnf.jkt);
    assert.strictEqual(verifyWithJwks(t.body.id_token, jwks).header.alg,
                       "PS256");
  });

  log.info("=== g. the hybrid flow ===");
  const hybrid = { response_type: "code id_token",
    client_id: client.client_id, redirect_uri: REDIRECT, scope: SCOPE,
    state: "hy-" + STAMP, nonce: "hn-" + STAMP };
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id, request: requestObject(hybrid) })),
    ALICE, consent);
  back = paramsAt(r);
  check("code id_token by value, with no PKCE, answers in the fragment with " +
        "an ID Token carrying c_hash and s_hash (5.2.2.1)", function () {
    assert.ok(back && back.get("code") && back.get("id_token"),
              r.status + " " + r.location);
    const idt = verifyWithJwks(back.get("id_token"), jwks);
    assert.strictEqual(idt.claims.c_hash, halfHash(back.get("code")));
    assert.strictEqual(idt.claims.s_hash, halfHash(hybrid.state));
  });

  log.info("=== h. oauth2.fapiRequireMtls ===");
  await ok(realmApi + "/config/set", { key: "oauth2.fapiRequireMtls",
                                       value: true }, "required mTLS");
  t = await token({ grant_type: "client_credentials" }, true);
  check("a DPoP-bound request with no client certificate is refused",
        function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
  });

  log.info("=== i. the hosted surfaces ===");
  const portal = browser("portal");
  const portalConsent = { shown: 0 };
  r = await follow(portal, await portal.go("GET", R + "/portal"), ALICE,
                   portalConsent);
  check("the portal signs its person in under Advanced with mTLS required: " +
        "a signed request pushed, a JARM response, a certificate-bound token",
        function () {
    assert.ok(r.status === 200 || (r.status === 302 &&
              /\/portal/.test(r.location)),
              r.status + " " + r.location + " " + r.text.slice(0, 400));
    assert.ok(!/cannot sign/i.test(r.text), r.text.slice(0, 400));
  });
  await ok(realmApi + "/config/set", { key: "oauth2.fapiRequireMtls",
                                       value: false }, "mTLS back to optional");

  log.info("=== j. JARM outside FAPI ===");
  await ok(realmApi + "/authorization-servers/create",
           { id: "open", label: "Not FAPI" }, "created a named server");
  await ok(realmApi + "/authorization-servers/set",
           { id: "open", member: "fapi", value: "off" },
           "opted it out of the realm's profile");
  const openMeta = (await send(base + R +
    "/.well-known/oauth-authorization-server/open")).body;
  const q = pkce();
  r = await follow(alice, await alice.go("GET", R + "/open/oauth2/authorize?" +
    form({ response_type: "code", response_mode: "query.jwt",
           client_id: client.client_id, redirect_uri: REDIRECT, scope: SCOPE,
           state: "oj-" + STAMP, nonce: "on-" + STAMP,
           code_challenge: q.challenge, code_challenge_method: "S256" })),
    ALICE, consent);
  back = paramsAt(r);
  check("a named server outside FAPI answers query.jwt with a JWT in the " +
        "query", function () {
    assert.ok(back && back.get("response"), r.status + " " + r.location +
              " " + String(r.text).slice(0, 300));
    const opened = verifyWithJwks(back.get("response"), jwks);
    assert.strictEqual(opened.claims.state, "oj-" + STAMP);
    assert.strictEqual(opened.claims.iss, openMeta.issuer);
  });
  r = await follow(alice, await alice.go("GET", R + "/open/oauth2/authorize?" +
    form({ response_type: "code id_token", response_mode: "query.jwt",
           client_id: client.client_id, redirect_uri: REDIRECT, scope: SCOPE,
           state: "oq-" + STAMP, nonce: "oqn-" + STAMP })), ALICE, consent);
  back = paramsAt(r);
  check("and refuses query.jwt carrying an id_token in clear (JARM 2.3.1), " +
        "itself as a JWT", function () {
    assert.ok(back && back.get("response"), r.status + " " + r.location);
    const opened = verifyWithJwks(back.get("response"), jwks);
    assert.strictEqual(opened.claims.error, "invalid_request");
  });

  assert.ok(checks >= 20, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fapi_advanced")
  .description("FAPI 1.0 Part 2 Advanced and JARM over the wire (#139, #143).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
