// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_assertion_grant_rules.js
//
// ---------------------------------------------------------------------------
// RFC 7521, RFC 7522 AND RFC 7523: WHAT THE IN-PROCESS FILES HELD, ASKED OF
// A RUNNING TOKEN ENDPOINT.
//
// D12 (#444): carries over the part a client can see of
//
//   * `tests/assertion_grant.js` — THE ENCRYPTION MATRIX at the token
//     endpoint rather than as a crypto.js round trip: every content
//     encryption algorithm under RSA-OAEP-256 and under ECDH-ES, and every
//     key management family once (RSA-OAEP, the ECDH-ES key wraps, AES key
//     wrap and AES-GCM key wrap under the client's secret, `dir`, PBES2),
//     each JWE built HERE with node's own crypto so that a wrap and an
//     unwrap cannot agree by sharing code; a nested JWT declaring a `cty`
//     that is not JWT, a protected header that is not JSON (STS-OAUTH-0029),
//     an algorithm this realm holds no key for (STS-OAUTH-0030), RSA1_5 by
//     name, the PBES2 ceiling and the realm's PBES2 floor; and the protocol
//     claims (`client_id`, `azp`, `cnf`, `exp`) never copied from an
//     assertion onto the token while a statement (`department`) is;
//   * `tests/assertion_grant_unknown_subject.js` — in PRODUCT a valid JWT
//     and a valid SAML 2.0 assertion about nobody the directory holds are
//     refused `invalid_grant`, STS-OAUTH-0510, and nobody is created;
//   * `tests/used_assertions.js` — a client assertion spent at the token
//     endpoint is a replay the next time, recorded STS-OAUTH-0012;
//   * `tests/rfc7523_person_issuer.js` — a person's several key pairs held
//     to the realm's `pki.personSigningKeyMax` (STS-PKI-0223), a label that
//     is not a short name refused (STS-PKI-0225), and a revocation that
//     names another person's kid refused (STS-PKI-0224).
//
// NOT carried, and why: the crypto tables as tables, the PBES2 vector and
// the "derived off the event loop" claim (library, class (d)); the one
// JWKS reader for both halves (a property of the modules); the
// used-assertion history's store, restart, cap and postgres statement
// (STS-STORE-0044..0048, STS-OAUTH-0243: a failing store, class (d)); the
// person key pair's sealing and a certificate issued to a person since
// deleted (no door produces either). What `sts_jwt_bearer_grant.js` and
// `sts_saml2_bearer_grant.js` already hold (RSA-OAEP-256 + A256GCM, an
// unsigned plaintext, one history across the grant and client
// authentication, a person about somebody else) is not repeated.
//
// OWNED HERE (local: true). Its realm is left standing unless
// STS_TEST_REMOVE_REALMS=1.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const saml = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_assertion_grant_rules",
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
const REALM = "agr-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const TOKEN = RB + "/oauth2/token";
const CLIENT = "agr-client";
// EXACTLY 32 ASCII characters: an A256KW, A256GCMKW or `dir` + A256GCM
// assertion is encrypted under the UTF-8 octets of the client's secret
// (OpenID Connect Core section 16.19), so the secret is the key.
const SECRET = ("agr" + STAMP + "0123456789abcdefghijklmnopqrstuvwxyz")
  .slice(0, 32);
const JWT_ISS = "https://agr-jwt.example/" + STAMP;
const SAML_ISS = "https://agr-saml.example/" + STAMP;
const JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const SAML_GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";
const PERSON = "agr-alice-" + STAMP;
const BOB = "agr-bob-" + STAMP;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
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
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body || {}, raw: raw };
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

function setting(key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key + " on the realm");
}

function tokenRequest(form) {
  log.debug("Entering tokenRequest().");
  log.debug("Leaving tokenRequest().");
  return send(TOKEN, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString() });
}

function grant(assertion, extra) {
  log.debug("Entering grant().");
  log.debug("Leaving grant().");
  return tokenRequest(Object.assign({ grant_type: JWT_GRANT,
    assertion: assertion, client_id: CLIENT, client_secret: SECRET },
  extra || {}));
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

// Counted before and after, so each refusal is its own row: the realm's
// audit log is read until the count has risen, or two seconds have passed.
async function codeRose(code, before) {
  log.debug("Entering codeRose(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 20 && n <= before; i += 1) {
    await sleep(100);
    n = await codeCount(code);
  }
  log.debug("Leaving codeRose(). " + n);
  return n > before;
}

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function b64uJson(o) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return b64u(Buffer.from(JSON.stringify(o), "utf8"));
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

function jti() {
  log.debug("Entering jti().");
  log.debug("Leaving jti().");
  return "agr-" + nodeCrypto.randomBytes(9).toString("hex");
}

function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

function signRs256(header, claims, key) {
  log.debug("Entering signRs256().");
  const input = b64uJson(header) + "." + b64uJson(claims);
  log.debug("Leaving signRs256().");
  return input + "." + b64u(nodeCrypto.sign("sha256", Buffer.from(input),
                                             key));
}

// ---------------------------------------------------------------------------
// A JWE, WRITTEN OUT WITH NODE'S CRYPTO (RFC 7516, RFC 7518). Nothing here
// is the service's: a key wrap this file performed and the service unwraps
// is two implementations agreeing, which is the claim.
// ---------------------------------------------------------------------------
const ENC_BYTES = { "A128GCM": 16, "A192GCM": 24, "A256GCM": 32,
                    "A128CBC-HS256": 32, "A192CBC-HS384": 48,
                    "A256CBC-HS512": 64 };
const CBC_HASH = { "A128CBC-HS256": "sha256", "A192CBC-HS384": "sha384",
                   "A256CBC-HS512": "sha512" };

function contentEncrypt(enc, cek, protectedB64, plaintext) {
  log.debug("Entering contentEncrypt(). " + enc);
  const aad = Buffer.from(protectedB64, "ascii");
  if (/GCM$/.test(enc)) {
    const iv = nodeCrypto.randomBytes(12);
    const c = nodeCrypto.createCipheriv("aes-" + (cek.length * 8) + "-gcm",
                                        cek, iv);
    c.setAAD(aad);
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    log.debug("Leaving contentEncrypt().");
    return { iv: iv, ct: ct, tag: c.getAuthTag() };
  }
  // RFC 7518 section 5.2: MAC_KEY || ENC_KEY, AES-CBC, then HMAC over
  // AAD || IV || ciphertext || AL, truncated to half.
  const half = cek.length / 2;
  const macKey = cek.subarray(0, half);
  const encKey = cek.subarray(half);
  const iv = nodeCrypto.randomBytes(16);
  const c = nodeCrypto.createCipheriv("aes-" + (encKey.length * 8) + "-cbc",
                                      encKey, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length * 8));
  const mac = nodeCrypto.createHmac(CBC_HASH[enc], macKey)
    .update(Buffer.concat([aad, iv, ct, al])).digest();
  log.debug("Leaving contentEncrypt().");
  return { iv: iv, ct: ct, tag: mac.subarray(0, half) };
}

function lengthPrefixed(buf) {
  log.debug("Entering lengthPrefixed().");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  log.debug("Leaving lengthPrefixed().");
  return Buffer.concat([len, buf]);
}

// RFC 7518 section 4.6.2: the Concat KDF of NIST SP 800-56A, SHA-256.
function concatKdf(z, algorithmId, keyBits) {
  log.debug("Entering concatKdf().");
  const pub = Buffer.alloc(4);
  pub.writeUInt32BE(keyBits);
  const other = Buffer.concat([
    lengthPrefixed(Buffer.from(algorithmId, "ascii")),
    lengthPrefixed(Buffer.alloc(0)), lengthPrefixed(Buffer.alloc(0)), pub]);
  const out = [];
  const reps = Math.ceil(keyBits / 256);
  for (let i = 1; i <= reps; i += 1) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(i);
    out.push(nodeCrypto.createHash("sha256")
      .update(Buffer.concat([counter, z, other])).digest());
  }
  log.debug("Leaving concatKdf().");
  return Buffer.concat(out).subarray(0, keyBits / 8);
}

function aesKw(kek, cek) {
  log.debug("Entering aesKw().");
  const c = nodeCrypto.createCipheriv("id-aes" + (kek.length * 8) + "-wrap",
    kek, Buffer.from("A6A6A6A6A6A6A6A6", "hex"));
  log.debug("Leaving aesKw().");
  return Buffer.concat([c.update(cek), c.final()]);
}

// `o`: { alg, enc, rsa (a KeyObject), ec ({ jwk }), secret, p2c, cty,
// header (extra members), plaintext }.
function jwe(o) {
  log.debug("Entering jwe(). " + o.alg + " " + o.enc);
  const header = Object.assign({ alg: o.alg, enc: o.enc, typ: "JWT",
                                 cty: o.cty === undefined ? "JWT" : o.cty },
                               o.header || {});
  if (header.cty === null) {
    delete header.cty;
  }
  let cek = nodeCrypto.randomBytes(ENC_BYTES[o.enc]);
  let encryptedKey = Buffer.alloc(0);
  if (/^RSA-OAEP/.test(o.alg)) {
    encryptedKey = nodeCrypto.publicEncrypt({ key: o.rsa,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: o.alg === "RSA-OAEP-256" ? "sha256" : "sha1" }, cek);
  } else if (/^ECDH-ES/.test(o.alg)) {
    const eph = nodeCrypto.generateKeyPairSync("ec",
                                               { namedCurve: "prime256v1" });
    const epk = eph.publicKey.export({ format: "jwk" });
    header.epk = { kty: "EC", crv: epk.crv, x: epk.x, y: epk.y };
    if (o.ec.jwk.kid) {
      header.kid = o.ec.jwk.kid;
    }
    const z = nodeCrypto.diffieHellman({ privateKey: eph.privateKey,
      publicKey: nodeCrypto.createPublicKey({ key: o.ec.jwk,
                                              format: "jwk" }) });
    if (o.alg === "ECDH-ES") {
      cek = concatKdf(z, o.enc, ENC_BYTES[o.enc] * 8);
    } else {
      const bits = Number(o.alg.match(/A(\d+)KW$/)[1]);
      encryptedKey = aesKw(concatKdf(z, o.alg, bits), cek);
    }
  } else if (/^A\d+KW$/.test(o.alg)) {
    encryptedKey = aesKw(Buffer.from(o.secret, "utf8"), cek);
  } else if (/^A\d+GCMKW$/.test(o.alg)) {
    const kek = Buffer.from(o.secret, "utf8");
    const iv = nodeCrypto.randomBytes(12);
    const c = nodeCrypto.createCipheriv("aes-" + (kek.length * 8) + "-gcm",
                                        kek, iv);
    encryptedKey = Buffer.concat([c.update(cek), c.final()]);
    header.iv = b64u(iv);
    header.tag = b64u(c.getAuthTag());
  } else if (o.alg === "dir") {
    cek = Buffer.from(o.secret, "utf8");
  } else if (/^PBES2/.test(o.alg)) {
    const p2s = nodeCrypto.randomBytes(16);
    header.p2s = b64u(p2s);
    header.p2c = o.p2c;
    if (o.p2c <= 100000) {
      const salt = Buffer.concat([Buffer.from(o.alg, "utf8"), Buffer.alloc(1),
                                  p2s]);
      const kek = nodeCrypto.pbkdf2Sync(Buffer.from(o.secret, "utf8"), salt,
                                        o.p2c, 16, "sha256");
      encryptedKey = aesKw(kek, cek);
    } else {
      // A count this file will not derive: the service must refuse the
      // header before it derives anything, so the key is noise.
      encryptedKey = nodeCrypto.randomBytes(24);
    }
  } else {
    // RSA1_5 and the families this file never builds: noise, refused on
    // the header.
    encryptedKey = nodeCrypto.randomBytes(256);
  }
  const protectedB64 = b64uJson(header);
  const sealed = contentEncrypt(o.enc, cek, protectedB64,
                                Buffer.from(o.plaintext, "utf8"));
  log.debug("Leaving jwe().");
  return [protectedB64, b64u(encryptedKey), b64u(sealed.iv),
          b64u(sealed.ct), b64u(sealed.tag)].join(".");
}

async function setup() {
  log.debug("Entering setup().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Assertion grant rules " + STAMP },
    "created the realm");
  await setting("global.mode", "development");
  await ok(API + "/pki/build", { organisation: "Assertion Grant Rules",
                                 country: "US" },
           "built a certificate authority");
  for (const who of [PERSON, BOB]) {
    await ok(API + "/users/create", { username: who, invent: false,
      attributes: { cn: who, givenName: "Assertion", sn: who,
                    mail: who + "@" + REALM + ".example.net" } },
      "created " + who);
  }
  const jwtKey = nodeCrypto.generateKeyPairSync("rsa",
                                                { modulusLength: 2048 });
  const jwk = Object.assign(jwtKey.publicKey.export({ format: "jwk" }),
                            { kid: "agr-1", alg: "RS256", use: "sig" });
  await ok(API + "/applications/create", { identifier: CLIENT,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: [JWT_GRANT, SAML_GRANT, "client_credentials"],
              oauthAllowedScope: ["openid", "profile"],
              oauthAssertionIssuer: [JWT_ISS],
              oauthAssertionJwks: JSON.stringify({ keys: [jwk] }),
              oauthSamlAssertionIssuer: [SAML_ISS] } },
    "registered the asserting client");
  await ok(API + "/pki/issue", { identifier: CLIENT, purpose: "saml" },
           "issued the client an RFC 7522 key pair");
  const view = await send(API + "/applications?application=" +
                          encodeURIComponent(CLIENT));
  const fields = ((view.body.application || view.body).fields) || {};
  const samlKey = (await ok(API + "/applications/reveal-secret",
    { application: CLIENT, secret: "oauthSamlAssertionPrivateKey" },
    "revealed the RFC 7522 private key")).value;
  const keys = (await send(RB + "/oauth2/jwks")).body.keys || [];
  // THE KEYS AN ASSERTION IS ENCRYPTED TO ARE THE REALM'S JOSE SIGNING
  // KEYS, as published (`use: sig`): `assertion_grant.js` decrypts with
  // `ownRsaDecryptionKeys('jose')` and the realm's EC keys, and the two
  // `use: enc` keys this JWKS also carries (`sts-ro-*`) are the request
  // object's, which this grant does not try. Pinned as observed (notes).
  const rsaEnc = keys.filter(function (k) {
    return k.kty === "RSA" && !/^sts-ro-/.test(String(k.kid));
  })[0];
  const ecEnc = keys.filter(function (k) {
    return k.kty === "EC" && k.crv === "P-256" &&
           !/^sts-ro-/.test(String(k.kid));
  })[0];
  assert.ok(rsaEnc && ecEnc, "the realm's JWKS names no RSA and P-256 " +
            "encryption keys: " + JSON.stringify(keys.map(function (k) {
              return [k.kty, k.crv, k.use, k.kid];
            })));
  log.debug("Leaving setup().");
  return { jwtKey: jwtKey.privateKey, kid: jwk.kid, samlKey: samlKey,
           samlCert: fields.oauthSamlAssertionCertificate,
           rsa: nodeCrypto.createPublicKey({ key: rsaEnc, format: "jwk" }),
           ec: { jwk: ecEnc } };
}

function innerFor(k, sub, extra) {
  log.debug("Entering innerFor().");
  log.debug("Leaving innerFor().");
  return signRs256({ alg: "RS256", typ: "JWT", kid: k.kid },
    Object.assign({ iss: JWT_ISS, sub: sub || PERSON, aud: TOKEN, iat: now(),
                    exp: now() + 120, jti: jti() }, extra || {}), k.jwtKey);
}

async function matrix(k) {
  log.debug("Entering matrix().");
  log.info("=== A. the encryption matrix, at the token endpoint ===");
  const encs = Object.keys(ENC_BYTES);
  const cases = [];
  encs.forEach(function (enc) {
    cases.push({ alg: "RSA-OAEP-256", enc: enc });
    cases.push({ alg: "ECDH-ES", enc: enc });
  });
  ["RSA-OAEP", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
   "A256KW", "A256GCMKW", "dir"].forEach(function (alg) {
    cases.push({ alg: alg, enc: "A256GCM" });
  });
  cases.push({ alg: "PBES2-HS256+A128KW", enc: "A128CBC-HS256", p2c: 1000 });
  const failures = [];
  for (const c of cases) {
    const r = await grant(jwe(Object.assign({ rsa: k.rsa, ec: k.ec,
      secret: SECRET, plaintext: innerFor(k) }, c)));
    if (r.status !== 200 || !r.body.access_token) {
      failures.push(c.alg + "/" + c.enc + " -> " + r.status + " " +
                    String(r.raw).slice(0, 200));
    }
  }
  check("A1. an assertion encrypted with each of the six content " +
        "encryption algorithms under RSA-OAEP-256 and under ECDH-ES, and " +
        "with RSA-OAEP, the three ECDH-ES key wraps, A256KW and A256GCMKW " +
        "under the client's secret, dir, and PBES2 — " + cases.length +
        " JWEs built with node's crypto — is decrypted and a token issued",
        function () {
          assert.deepStrictEqual(failures, []);
        });

  const cty = await grant(jwe({ alg: "RSA-OAEP-256", enc: "A256GCM",
    rsa: k.rsa, cty: "application/json", plaintext: innerFor(k) }));
  check("A2. a nested JWT declaring a cty that is not JWT is refused " +
        "invalid_grant, saying so", function () {
          assert.strictEqual(cty.status, 400, cty.raw.slice(0, 300));
          assert.strictEqual(cty.body.error, "invalid_grant");
          assert.ok(/cty/.test(cty.body.error_description),
                    cty.raw.slice(0, 300));
        });

  let before = await codeCount("STS-OAUTH-0029");
  const garbled = await grant("bm90IGpzb24." + b64u("x") + "." + b64u("y") +
                              "." + b64u("z") + "." + b64u("t"));
  const garbledRow = await codeRose("STS-OAUTH-0029", before);
  check("A3. five parts whose protected header is not JSON are refused " +
        "invalid_grant, recorded STS-OAUTH-0029 and no code sent",
        function () {
          assert.strictEqual(garbled.status, 400, garbled.raw.slice(0, 300));
          assert.strictEqual(garbled.body.error, "invalid_grant");
          assert.ok(garbledRow, "no new STS-OAUTH-0029 row");
          assert.ok(!/STS-[A-Z]+-\d{4}/.test(garbled.raw), garbled.raw);
        });

  before = await codeCount("STS-OAUTH-0030");
  const kem = await grant(jwe({ alg: "ML-KEM-768", enc: "A256GCM",
                                plaintext: innerFor(k) }));
  const kemRow = await codeRose("STS-OAUTH-0030", before);
  check("A4. an ML-KEM-768 assertion, to a realm that holds no ML-KEM key " +
        "(an administrator's opt-in), is refused naming /oauth2/jwks, " +
        "recorded STS-OAUTH-0030", function () {
          assert.strictEqual(kem.status, 400, kem.raw.slice(0, 300));
          assert.ok(/no key|oauth2\/jwks/.test(kem.body.error_description),
                    kem.raw.slice(0, 300));
          assert.ok(kemRow, "no new STS-OAUTH-0030 row");
        });

  const rsa15 = await grant(jwe({ alg: "RSA1_5", enc: "A256GCM",
                                  plaintext: innerFor(k) }));
  check("A5. RSA1_5 is refused invalid_grant, by name", function () {
    assert.strictEqual(rsa15.status, 400, rsa15.raw.slice(0, 300));
    assert.ok(/RSA1_5/.test(rsa15.body.error_description),
              rsa15.raw.slice(0, 300));
  });

  const huge = await grant(jwe({ alg: "PBES2-HS256+A128KW", enc: "A256GCM",
    secret: SECRET, p2c: 2000000000, plaintext: innerFor(k) }));
  check("A6. a PBES2 assertion asking for two billion iterations is " +
        "refused before anything is derived: at most 1000000", function () {
          assert.strictEqual(huge.status, 400, huge.raw.slice(0, 300));
          assert.ok(/at most 1000000/.test(huge.body.error_description),
                    huge.raw.slice(0, 300));
        });
  log.debug("Leaving matrix().");
}

async function floorAndClaims(k) {
  log.debug("Entering floorAndClaims().");
  log.info("=== B. the PBES2 floor and the claims an assertion may carry ===");
  await setting("security.pbes2MinIterations", 5000);
  const low = await grant(jwe({ alg: "PBES2-HS256+A128KW", enc: "A256GCM",
    secret: SECRET, p2c: 1000, plaintext: innerFor(k) }));
  const enough = await grant(jwe({ alg: "PBES2-HS256+A128KW",
    enc: "A256GCM", secret: SECRET, p2c: 5000, plaintext: innerFor(k) }));
  check("B1. with the realm's security.pbes2MinIterations at 5000, a PBES2 " +
        "assertion at 1000 iterations is refused naming the floor, and one " +
        "at 5000 is issued", function () {
          assert.strictEqual(low.status, 400, low.raw.slice(0, 300));
          assert.ok(/at least 5000/.test(low.body.error_description),
                    low.raw.slice(0, 300));
          assert.strictEqual(enough.status, 200, enough.raw.slice(0, 300));
        });

  const spoofed = await grant(innerFor(k, PERSON, {
    department: "engineering", client_id: "agr-spoof", azp: "agr-spoof",
    cnf: { jkt: "agr-spoofed-thumbprint" } }));
  check("B2. a statement in an assertion (department) is carried onto the " +
        "access token, while its client_id, azp and cnf are not: the token " +
        "names the client that asked and is bound to nothing", function () {
          assert.strictEqual(spoofed.status, 200, spoofed.raw.slice(0, 300));
          const claims = claimsOf(spoofed.body.access_token);
          assert.strictEqual(claims.department, "engineering",
                             JSON.stringify(claims));
          assert.strictEqual(claims.client_id, CLIENT, JSON.stringify(claims));
          assert.notStrictEqual(claims.azp, "agr-spoof");
          assert.ok(!claims.cnf, JSON.stringify(claims.cnf));
        });

  const assertionExp = now() + 250;
  const longLived = await grant(innerFor(k, PERSON, { exp: assertionExp }));
  check("B3. an assertion's own exp is not the token's lifetime: the token " +
        "lives for its own expires_in", function () {
    assert.strictEqual(longLived.status, 200, longLived.raw.slice(0, 300));
    const claims = claimsOf(longLived.body.access_token);
    assert.notStrictEqual(claims.exp, assertionExp);
    assert.ok(Math.abs(claims.exp - claims.iat -
                       Number(longLived.body.expires_in)) <= 2,
              JSON.stringify([claims.iat, claims.exp,
                              longLived.body.expires_in]));
  });
  log.debug("Leaving floorAndClaims().");
}

async function personKeys() {
  log.debug("Entering personKeys().");
  log.info("=== C. a person's key pairs, held to the realm's cap ===");
  await setting("pki.personSigningKeyMax", 2);
  const first = await ok(API + "/pki/issue", { identifier: PERSON,
    target: "person" }, "issued the person a key pair");
  await ok(API + "/pki/issue", { identifier: PERSON, target: "person",
    label: "second" }, "issued the person a second key pair");
  let before = await codeCount("STS-PKI-0223");
  const third = await postJson(API + "/pki/issue", { identifier: PERSON,
    target: "person", label: "third" });
  const thirdRow = await codeRose("STS-PKI-0223", before);
  check("C1. at pki.personSigningKeyMax (2) valid key pairs a third is " +
        "refused rather than an older one revoked, recorded STS-PKI-0223",
        function () {
          assert.ok(third.status >= 400 || third.body.ok === false,
                    third.raw.slice(0, 300));
          assert.ok(thirdRow, "no new STS-PKI-0223 row");
        });
  before = await codeCount("STS-PKI-0225");
  const badLabel = await postJson(API + "/pki/issue", { identifier: BOB,
    target: "person", label: "<script>" });
  const labelRow = await codeRose("STS-PKI-0225", before);
  check("C2. a label that is not a short name is refused, STS-PKI-0225",
        function () {
          assert.ok(badLabel.status >= 400 || badLabel.body.ok === false,
                    badLabel.raw.slice(0, 300));
          assert.ok(labelRow, "no new STS-PKI-0225 row");
        });
  before = await codeCount("STS-PKI-0224");
  const notMine = await postJson(API + "/pki/revoke", { identifier: BOB,
    target: "person", handle: first.kid, reason: "keyCompromise" });
  const notMineRow = await codeRose("STS-PKI-0224", before);
  check("C3. a revocation naming one person's kid against another is " +
        "looked up among THAT person's key pairs and refused, STS-PKI-0224",
        function () {
          assert.ok(notMine.status >= 400 || notMine.body.ok === false,
                    notMine.raw.slice(0, 300));
          assert.ok(notMineRow, "no new STS-PKI-0224 row");
        });
  const revoked = await ok(API + "/pki/revoke", { identifier: PERSON,
    target: "person", handle: first.kid, reason: "keyCompromise" },
    "revoked the person's first key pair");
  const room = await postJson(API + "/pki/issue", { identifier: PERSON,
    target: "person", label: "third" });
  check("C4. revoking one makes room under the cap: only valid key pairs " +
        "count", function () {
          assert.strictEqual(revoked.onList, true, JSON.stringify(revoked));
          assert.strictEqual(room.status, 200, room.raw.slice(0, 300));
        });
  log.debug("Leaving personKeys().");
}

async function product(k) {
  log.debug("Entering product().");
  log.info("=== D. product: nobody, and a replayed client assertion ===");
  await setting("global.mode", "product");
  const nobodyJwt = "agr-nobody-jwt-" + STAMP;
  const nobodySaml = "agr-nobody-saml-" + STAMP;
  const known = await grant(innerFor(k, PERSON));
  let before = await codeCount("STS-OAUTH-0510");
  const jwtNobody = await grant(innerFor(k, nobodyJwt));
  const jwtRow = await codeRose("STS-OAUTH-0510", before);
  check("D1. PRODUCT, RFC 7523: an assertion naming a person the directory " +
        "holds is issued a token, and the same naming nobody is refused " +
        "invalid_grant, recorded STS-OAUTH-0510", function () {
          assert.strictEqual(known.status, 200, known.raw.slice(0, 300));
          assert.strictEqual(jwtNobody.status, 400,
                             jwtNobody.raw.slice(0, 300));
          assert.strictEqual(jwtNobody.body.error, "invalid_grant");
          assert.ok(/no directory entry/i.test(
            jwtNobody.body.error_description), jwtNobody.raw.slice(0, 300));
          assert.ok(jwtRow, "no new STS-OAUTH-0510 row");
        });
  const samlFor = function (sub) {
    log.debug("Entering samlFor().");
    const doc = saml.buildAssertion({ issuer: SAML_ISS, subject: sub,
                                      audience: TOKEN, recipient: TOKEN });
    log.debug("Leaving samlFor().");
    return saml.b64u(saml.sign(doc, k.samlKey, k.samlCert, {}));
  };
  const samlKnown = await grant(samlFor(PERSON), { grant_type: SAML_GRANT });
  before = await codeCount("STS-OAUTH-0510");
  const samlNobody = await grant(samlFor(nobodySaml),
                                 { grant_type: SAML_GRANT });
  const samlRow = await codeRose("STS-OAUTH-0510", before);
  check("D2. PRODUCT, RFC 7522: the same for a SAML 2.0 assertion",
        function () {
          assert.strictEqual(samlKnown.status, 200,
                             samlKnown.raw.slice(0, 300));
          assert.strictEqual(samlNobody.status, 400,
                             samlNobody.raw.slice(0, 300));
          assert.strictEqual(samlNobody.body.error, "invalid_grant");
          assert.ok(samlRow, "no new STS-OAUTH-0510 row");
        });
  const lookups = [];
  for (const who of [nobodyJwt, nobodySaml]) {
    const r = await send(API + "/users?user=" + encodeURIComponent(who));
    lookups.push(r.body && r.body.subject ? who + " " + r.body.subject : "");
  }
  const control = await send(API + "/users?user=" +
                             encodeURIComponent(PERSON));
  check("D3. and the directory still holds nobody by either name, where " +
        "the same lookup finds the person who exists", function () {
          assert.ok(/^urn:uuid:/.test(String(control.body.subject)),
                    control.raw.slice(0, 200));
          assert.deepStrictEqual(lookups.filter(Boolean), []);
        });

  const HS = "agr-hs-" + STAMP;
  const hsSecret = "agr-client-assertion-secret-" + STAMP + "-0123456789";
  await ok(API + "/applications/create", { identifier: HS,
    protocols: ["oauth2"],
    fields: { oauthClientId: [HS], oauthClientSecret: hsSecret,
              oauthTokenEndpointAuthMethod: "client_secret_jwt",
              oauthGrantType: ["client_credentials"] } },
    "registered a client_secret_jwt client");
  const head = b64uJson({ alg: "HS256", typ: "JWT" });
  const body = b64uJson({ iss: HS, sub: HS, aud: TOKEN, iat: now(),
                          exp: now() + 60, jti: jti() });
  const assertion = head + "." + body + "." + b64u(nodeCrypto
    .createHmac("sha256", hsSecret).update(head + "." + body).digest());
  const form = { grant_type: "client_credentials", client_id: HS,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion };
  const firstUse = await tokenRequest(form);
  before = await codeCount("STS-OAUTH-0012");
  const replay = await tokenRequest(form);
  const replayRow = await codeRose("STS-OAUTH-0012", before);
  check("D4. PRODUCT: a client assertion spent at the token endpoint " +
        "authenticates once; the same assertion on another request is " +
        "refused invalid_client, recorded STS-OAUTH-0012, the refusal " +
        "naming what it was spent as", function () {
          assert.strictEqual(firstUse.status, 200,
                             firstUse.raw.slice(0, 300));
          assert.strictEqual(replay.status, 401, replay.raw.slice(0, 300));
          assert.strictEqual(replay.body.error, "invalid_client");
          assert.ok(/client assertion/.test(replay.body.error_description),
                    replay.raw.slice(0, 300));
          assert.ok(replayRow, "no new STS-OAUTH-0012 row");
        });
  log.debug("Leaving product().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + RB);
  const k = await setup();
  await matrix(k);
  await floorAndClaims(k);
  await personKeys();
  await product(k);
  assert.ok(checks >= 17, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const listed = await send(base + "/admin-api/realms?per=500");
  const mine = ((listed.body && listed.body.realms) || []).filter(
    function (one) {
      return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
    });
  for (const one of mine) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: one.id });
    log.info("removed the realm " + one.id + " (" + r.status + ")");
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
    log.warn("could not remove this run's realms: " + e.message);
  }
  if (failure) {
    log.error("Test failed: " + (failure.stack || failure));
    log.debug("Leaving main().");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
