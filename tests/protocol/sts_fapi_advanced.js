// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   i. THE HOSTED SURFACES: the static portal (#568) signs its person in
//      under Advanced as its runtime does — the public client
//      sts-user-portal, PKCE, a DPoP-bound token — with
//      oauth2.fapiRequireMtls on. Until #568 this process signed in for it,
//      with a signed request, PAR, JARM and a CA-issued certificate.
//   j. JARM outside FAPI: a named server with fapi=off answers query.jwt and
//      refuses query.jwt carrying an id_token in clear.
//   k. D12 (#444), `tests/fapi_advanced_units.js` over the wire: by-value
//      refusals of code without JARM (invalid_request), no scope
//      (invalid_scope), a token response type, plain PKCE, no nonce, no exp
//      and an nbf over an hour old; id_token code with an aud array taken;
//      ES512 for JARM, RSA1_5, a none JARM alg and an enc without an alg
//      refused at registration; an RS256 client assertion refused and PS256
//      taken; oauth2.accessTokenSigningAlg ES256 holding and RS256 replaced
//      by PS256; a named server's HS256 refused; an encrypted JARM response
//      opened here (RSA-OAEP-256) to a PS256 JWT; and every code of a-k off
//      the audit log (ADV_CODES). Not carried (class (d)): signJwt() and
//      verifyOwnJws() as functions (B), jarm.transportOf() and the metadata
//      filter as functions, the requirement table as data, a registered
//      RS256 JARM alg under Advanced (registration refuses it first, so
//      STS-OAUTH-0588 is unreachable), and a named server's own EdDSA
//      access tokens (EdDSA signing is off by default, #1292).
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const portalSignin = require("./portal_signin.js");

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
    // The jar, for the sign-in over /authn-api (#571).
    jar: jar,
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
      !urls.isAt(r.location, REDIRECT)) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  log.debug("Leaving atClient().");
  return url.searchParams;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  // THE SCREEN OVER `/authn-api` (#571), through the one helper, with this
  // browser's jar: the answer is read as the form's 303 was.
  const posted = await authnSignin.signInWithJar(base + R, location,
    { action: "login", username: who, password: PASSWORD }, b.jar);
  assert.ok(posted.answer.view, "the sign-in screen: " +
            posted.answer.status + " " + JSON.stringify(posted.answer.json));
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
    if (!urls.isUnder(where, base)) {
      break;
    }
    if (/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(where) && who) {
      const signed = await signIn(b, where, who);
      r = signed;
      continue;
    }
    // THE CONSENT SCREEN IS A PAGE OF THE SIGN-IN SURFACE SINCE #576: its
    // view and its answer are `/authn-api/consent`'s, through the one
    // helper, with this browser's jar; the answer is read as the form's 303.
    if (authnSignin.isConsent(where) && onConsent) {
      onConsent.shown += 1;
      r = await authnSignin.consentWithJar(where, "allow", b.jar);
      continue;
    }
    r = await b.go("GET", where);
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
      !urls.isAt(r.location, REDIRECT)) {
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

// THE STATIC PORTAL'S SIGN-IN (#568): in the browser, as the public client
// `sts-user-portal` with PKCE and a DPoP-bound token — the one public client
// besides the console a FAPI profile lets through (`fapi.js`
// PUBLIC_CLIENT_EXEMPT) — driven the way its runtime drives it, then the
// account API asked who it is. Answers `{ problem, me }`.
async function portalSignsIn(who, password) {
  log.debug("Entering portalSignsIn().");
  let problem = "";
  let me = null;
  try {
    const portal = await portalSignin.signInToThePortal(absolute(R), who,
      null, { password: password });
    me = await portal.api("GET", "/account-api/me");
  } catch (e) {
    log.debug("Caught in portalSignsIn(): " + ((e && e.message) || e));
    problem = String((e && e.message) || e);
  }
  log.debug("Leaving portalSignsIn().");
  return { problem: problem, me: me };
}

// The codes section k reads off the audit log, as the wire records them.
// Where the units file asked fapi.js alone it named other codes for seven of
// these — 0783 (no JARM), 0784 (no scope), 0582 (a token response type),
// 0575 (nonce), 0586 (an RS256 assertion), 0585 (aud) and 0580 (a secret
// method) — because a request meets the general gates (advertised modes and
// types, the request object, client authentication) first.
const ADV_CODES = [
  // c: client_secret_jwt, a public client, code token, an RS256 ID Token
  "STS-REG-0167", "STS-REG-0174", "STS-REG-0183", "STS-REG-0177",
  // d: a plain request, nbf, aud, the lifetime, a push without PKCE
  "STS-OAUTH-0340", "STS-OAUTH-0584", "STS-OAUTH-0366", "STS-OAUTH-0573",
  // f, h, j: unbound, mTLS required, query.jwt with an id_token in clear
  "STS-OAUTH-0583", "STS-OAUTH-0598", "STS-OAUTH-0587",
  // k: no JARM mode, no scope, a token response type, plain PKCE, no nonce
  "STS-OAUTH-0164", "STS-OAUTH-0560", "STS-OAUTH-0163", "STS-OAUTH-0165",
  "STS-OAUTH-0562",
  // k: RSA1_5, JARM's grammar, an RS256 assertion, the named server's alg
  "STS-REG-0164", "STS-REG-0179", "STS-OAUTH-0570", "STS-ADMIN-0799"
];

// How many rows of this realm's audit log carry `code`, waited for briefly.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await send(realmApi + "/audit?per=500&code=" +
                         encodeURIComponent(code));
    n = Number((r.body && r.body.matched) || 0);
    if (n > 0) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
}

// Opens a compact JWE (RSA-OAEP-256 or RSA-OAEP; A128CBC-HS256 or A*GCM)
// with `privateKey`; the plaintext as a string. An independent
// implementation of RFC 7516 section 5.2 and RFC 7518 section 5.2.2.1.
function openJwe(compact, privateKey) {
  log.debug("Entering openJwe().");
  const parts = String(compact).split(".");
  if (parts.length !== 5) {
    log.debug("Leaving openJwe(). Not a JWE.");
    throw new Error("not a compact JWE: " + parts.length + " parts");
  }
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const cek = nodeCrypto.privateDecrypt({ key: privateKey,
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: header.alg === "RSA-OAEP-256" ? "sha256" : "sha1" },
    Buffer.from(parts[1], "base64url"));
  const iv = Buffer.from(parts[2], "base64url");
  const ciphertext = Buffer.from(parts[3], "base64url");
  const tag = Buffer.from(parts[4], "base64url");
  const aad = Buffer.from(parts[0], "ascii");
  let plain = null;
  if (/^A(128|192|256)GCM$/.test(header.enc)) {
    const d = nodeCrypto.createDecipheriv("aes-" + (cek.length * 8) + "-gcm",
                                          cek, iv);
    d.setAAD(aad);
    d.setAuthTag(tag);
    plain = Buffer.concat([d.update(ciphertext), d.final()]);
  } else {
    const half = cek.length / 2;
    const macKey = cek.subarray(0, half);
    const encKey = cek.subarray(half);
    const al = Buffer.alloc(8);
    al.writeBigUInt64BE(BigInt(aad.length * 8));
    const hash = { 16: "sha256", 24: "sha384", 32: "sha512" }[half];
    const mac = nodeCrypto.createHmac(hash, macKey)
      .update(Buffer.concat([aad, iv, ciphertext, al])).digest()
      .subarray(0, half);
    if (!nodeCrypto.timingSafeEqual(mac, tag)) {
      log.debug("Leaving openJwe(). Bad tag.");
      throw new Error("the JWE's authentication tag does not verify");
    }
    const d = nodeCrypto.createDecipheriv("aes-" + (half * 8) + "-cbc",
                                          encKey, iv);
    plain = Buffer.concat([d.update(ciphertext), d.final()]);
  }
  log.debug("Leaving openJwe().");
  return plain.toString("utf8");
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
  // That refusal SPENT the code: a code is presented once, whatever the
  // outcome (RFC 6749 section 4.1.2, #424). The bound request needs a
  // fresh one, pushed and authorized again.
  r = await send(parUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(Object.assign(clientAuth(),
                             { request: requestObject(params) })) });
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id, request_uri: r.body.request_uri })),
    ALICE, { shown: 0 });
  back = paramsAt(r);
  const fresh = back && back.get("response")
    ? verifyWithJwks(back.get("response"), jwks).claims.code : "";
  check("a fresh authorization gives another code", function () {
    assert.ok(fresh && fresh !== jarmClaims.code,
              r.status + " " + r.location);
  });
  t = await token({ grant_type: "authorization_code", code: fresh,
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
  const signedIn = await portalSignsIn(ALICE, PASSWORD);
  check("the portal signs its person in under Advanced with mTLS required, " +
        "as its static runtime does — and its account API answers them",
        function () {
    assert.strictEqual(signedIn.problem, "", signedIn.problem.slice(0, 600));
    assert.ok(signedIn.me && signedIn.me.status === 200 &&
              signedIn.me.json.user.username === ALICE,
              signedIn.me ? signedIn.me.text.slice(0, 300) : "no answer");
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

  log.info("=== k. the profile's rules, as fapi_advanced_units.js held " +
           "them ===");
  // EVERY REQUEST BELOW CARRIES FRESH state AND nonce VALUES: RFC 9700 mode
  // (which the profile implies) refuses one already used in this realm.
  let kn = 0;
  const freshly = function (extra) {
    kn += 1;
    return Object.assign({}, hybrid, { state: "k" + kn + "-" + STAMP,
                                       nonce: "kn" + kn + "-" + STAMP },
                         extra || {});
  };
  const refusedByValue = async function (claims, what, error) {
    const answer = await alice.go("GET", R + "/oauth2/authorize?" + form({
      client_id: client.client_id, request: requestObject(claims) }));
    const at = paramsAt(answer);
    check(what, function () {
      assert.ok(error === 400 ? answer.status === 400
                              : at && at.get("error") === error,
                answer.status + " " + answer.location + " " +
                String(answer.text).slice(0, 200));
    });
    return answer;
  };
  await refusedByValue(freshly({ response_type: "code",
                                 response_mode: "query" }),
                       "k/A. code without JARM is refused invalid_request " +
                       "(Part 2 5.2.2 item 2, #187)", "invalid_request");
  await refusedByValue(freshly({ scope: "" }),
                       "k/A. a request naming no scope is refused " +
                       "invalid_scope rather than given a default (#187)",
                       "invalid_scope");
  await refusedByValue(freshly({ response_type: "code id_token token" }),
                       "k/A. a response type carrying a token is refused " +
                       "unsupported_response_type",
                       "unsupported_response_type");
  await refusedByValue(freshly({ code_challenge: q.challenge + "x",
                                 code_challenge_method: "plain" }),
                       "k/A. a challenge that is sent is held to S256",
                       "invalid_request");
  await refusedByValue(freshly({ nonce: undefined }),
                       "k/A. Baseline's nonce rule still applies",
                       "invalid_request");
  const nowK = Math.floor(Date.now() / 1000);
  await refusedByValue(Object.assign(freshly(), { exp: undefined }),
                       "k/A. a request object with no exp is refused " +
                       "(item 13), on this server's own page", 400);
  await refusedByValue(freshly({ nbf: nowK - 3601, exp: nowK + 60 }),
                       "k/A. one whose nbf is over 60 minutes old is " +
                       "refused", 400);
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: client.client_id,
           request: requestObject(freshly({ response_type: "id_token code" }),
                                  { aud: ["https://other.example",
                                          issuer] }) })), ALICE, consent);
  back = paramsAt(r);
  check("k/A. id_token code (either order) with an aud array holding the " +
        "issuer is answered with a code and an ID Token", function () {
    assert.ok(back && back.get("code") && back.get("id_token"),
              r.status + " " + r.location);
  });

  // REGISTRATION: the algorithms Advanced refuses, and JARM's grammar.
  await refusedRegistration({ authorization_signed_response_alg: "ES512" },
                            "k/A. an ES512 JARM response is refused (8.6)");
  await refusedRegistration({ id_token_encrypted_response_alg: "RSA1_5" },
                            "k/A. RSA1_5 is refused (8.6.1)");
  await refusedRegistration({ authorization_signed_response_alg: "none" },
                            "k/C. none is not a JARM algorithm (section 3)");
  await refusedRegistration({ authorization_encrypted_response_enc:
                                "A256GCM" },
                            "k/C. a JARM enc without an alg is refused");

  // AN RS256 CLIENT ASSERTION (8.6): a client whose key is RSA, signing
  // RS256 where the profile allows PS256.
  const rsaPair = nodeCrypto.generateKeyPairSync("rsa",
                                                 { modulusLength: 2048 });
  const rsaPub = rsaPair.publicKey.export({ format: "jwk" });
  rsaPub.kid = "adv-rsa-" + STAMP;
  rsaPub.use = "sig";
  r = await postJson(base + R + "/oauth2/register", Object.assign({},
    metadata, { token_endpoint_auth_signing_alg: "PS256",
                request_object_signing_alg: "PS256",
                grant_types: ["client_credentials"], response_types: [],
                jwks: { keys: [rsaPub] } }));
  const rsaClient = r.body || {};
  const rsaAssertion = function (alg) {
    const now = Math.floor(Date.now() / 1000);
    const input = Buffer.from(JSON.stringify({ alg: alg, typ: "JWT",
                                               kid: rsaPub.kid }))
      .toString("base64url") + "." +
      Buffer.from(JSON.stringify({ iss: rsaClient.client_id,
        sub: rsaClient.client_id, aud: issuer,
        jti: nodeCrypto.randomBytes(12).toString("base64url"), iat: now,
        exp: now + 60 })).toString("base64url");
    const options = alg === "PS256"
      ? { key: rsaPair.privateKey,
          padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32 }
      : rsaPair.privateKey;
    return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                         options).toString("base64url");
  };
  const rsaToken = function (alg) {
    return send(tokenUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded",
                 DPoP: dpopProof(tokenUrl) },
      body: form({ grant_type: "client_credentials",
                   client_id: rsaClient.client_id,
                   client_assertion_type:
                     "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                   client_assertion: rsaAssertion(alg) }) });
  };
  const rsByRs = await rsaToken("RS256");
  const rsByPs = await rsaToken("PS256");
  check("k/A. a client assertion signed RS256 is refused invalid_client, " +
        "and the same client's PS256 one is taken (8.6)", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
    assert.strictEqual(rsByRs.status, 401, rsByRs.raw.slice(0, 300));
    assert.strictEqual(rsByRs.body.error, "invalid_client");
    assert.strictEqual(rsByPs.status, 200, rsByPs.raw.slice(0, 300));
  });

  // D. THE ACCESS-TOKEN ALGORITHM: the setting holds where the profile
  // allows it, is replaced by PS256 where it does not, and a named server's
  // member refuses one it cannot use.
  await ok(realmApi + "/config/set", { key: "oauth2.accessTokenSigningAlg",
                                       value: "ES256" },
           "chose ES256 for access tokens");
  const byEs = await rsaToken("PS256");
  await ok(realmApi + "/config/set", { key: "oauth2.accessTokenSigningAlg",
                                       value: "RS256" },
           "chose RS256 for access tokens");
  const byRs = await rsaToken("PS256");
  await ok(realmApi + "/config/reset",
           { key: "oauth2.accessTokenSigningAlg" }, "put the choice back");
  check("k/D. oauth2.accessTokenSigningAlg ES256 holds under Advanced; RS256 " +
        "is replaced by PS256", function () {
    assert.strictEqual(byEs.status, 200, byEs.raw.slice(0, 300));
    assert.strictEqual(verifyWithJwks(byEs.body.access_token, jwks)
                         .header.alg, "ES256");
    assert.strictEqual(byRs.status, 200, byRs.raw.slice(0, 300));
    assert.strictEqual(verifyWithJwks(byRs.body.access_token, jwks)
                         .header.alg, "PS256");
  });
  r = await postJson(realmApi + "/authorization-servers/set",
                     { id: "open", member: "access_token_signing_alg",
                       value: "HS256" });
  check("k/D. a named server's access_token_signing_alg refuses HS256",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  // C. AN ENCRYPTED JARM RESPONSE: a client registering an encryption key
  // and RSA-OAEP-256 gets a JWE that opens, with its own key, to the
  // response signed PS256.
  const encPair = nodeCrypto.generateKeyPairSync("rsa",
                                                 { modulusLength: 2048 });
  const encPub = encPair.publicKey.export({ format: "jwk" });
  encPub.kid = "adv-enc-" + STAMP;
  encPub.use = "enc";
  encPub.alg = "RSA-OAEP-256";
  r = await postJson(base + R + "/oauth2/register", Object.assign({},
    metadata, { authorization_encrypted_response_alg: "RSA-OAEP-256",
                jwks: { keys: [pub, encPub] } }));
  const encClient = r.body || {};
  check("k/C. a client registering RSA-OAEP-256 for its JARM responses is " +
        "registered", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
  });
  const encObject = function (claims) {
    const now = Math.floor(Date.now() / 1000);
    return signEs256({ alg: "ES256", typ: "oauth-authz-req+jwt",
                       kid: pub.kid },
      Object.assign({ iss: encClient.client_id, aud: issuer,
                      client_id: encClient.client_id, nbf: now,
                      exp: now + 300, iat: now,
                      jti: nodeCrypto.randomBytes(12).toString("base64url") },
                    claims), pair.privateKey);
  };
  const encNow = Math.floor(Date.now() / 1000);
  const encAuth = { client_id: encClient.client_id,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: signEs256({ alg: "ES256", typ: "JWT", kid: pub.kid },
      { iss: encClient.client_id, sub: encClient.client_id, aud: issuer,
        jti: nodeCrypto.randomBytes(12).toString("base64url"), iat: encNow,
        exp: encNow + 60 }, pair.privateKey) };
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: encClient.client_id, scope: one },
             "consented " + one);
  }
  const ep = pkce();
  r = await send(parUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(Object.assign(encAuth, { request: encObject(Object.assign({},
      params, { client_id: encClient.client_id, state: "enc-" + STAMP,
                nonce: "encn-" + STAMP, code_challenge: ep.challenge })) })) });
  const pushedEnc = r;
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: encClient.client_id,
           request_uri: (pushedEnc.body || {}).request_uri })),
    ALICE, consent);
  back = paramsAt(r);
  const jwe = String((back && back.get("response")) || "");
  let inner = null;
  let opened = null;
  try {
    inner = openJwe(jwe, encPair.privateKey);
    opened = verifyWithJwks(inner, jwks);
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // Reported by the check below with what came back.
    inner = "error: " + ((e && e.message) || e);
  }
  check("k/C. its response is a five-part JWE that opens with its key to a " +
        "JARM response signed PS256, carrying the code and state",
        function () {
    assert.strictEqual(pushedEnc.status, 201, pushedEnc.raw.slice(0, 300));
    assert.strictEqual(jwe.split(".").length, 5, r.status + " " +
                       String(r.location).slice(0, 200));
    assert.ok(opened, String(inner).slice(0, 200));
    assert.strictEqual(opened.header.alg, "PS256");
    assert.strictEqual(opened.claims.state, "enc-" + STAMP);
    assert.ok(opened.claims.code);
  });

  // THE CODES, read off the realm's audit log; a code is never sent.
  const advCodes = {};
  for (const code of ADV_CODES) {
    advCodes[code] = await codeCount(code);
  }
  check("k. the refusals are recorded under their codes (" +
        ADV_CODES.join(", ") + ")", function () {
    Object.keys(advCodes).forEach(function (code) {
      assert.ok(advCodes[code] >= 1, JSON.stringify(advCodes));
    });
  });

  assert.ok(checks >= 40, "only " + checks + " checks ran; a section has " +
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
