// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_encryption_codes.js
//
// ===========================================================================
// A PARTNER'S ENCRYPTED ASSERTION OR ID TOKEN, EVERY REFUSAL BY ITS CODE, IN
// BOTH MODES, OVER THE WIRE (#168; #444 D12, phase 7).
//
// `tests/federation_encryption.js` pins `federation_encryption.ts` and
// `crypto.js` at the function, reading codes off the audit ring;
// `sts_federation_encryption.js` (vendored) drives the sign-ins over HTTP
// with an independent encryptor and reads the pages, not the codes. This
// job carries the codes over the wire in a development AND a product realm
// of one service, against partners written HERE — this file's own XML
// Encryption and JWE (node's crypto and string concatenation, the vendored
// job's construction), so nothing is dialled:
//
//   0. product refuses plaintext SAML 2.0 and a signed-only ID Token by
//      form_post (STS-FED-0140) where development accepts them, and a
//      relationship with no key is not ready in product only;
//   3. the four fields: aes256-cbc, rsa-1_5, RSA1_5 and A128CBC-HS256
//      refused in every mode (STS-FED-0139); a key management the key
//      cannot do, a field on SAML 1.1 and a post-quantum key type for XML
//      (STS-FED-0143); the stored key itself, which is not a field the
//      operation accepts (STS-API-0009; in process STS-FED-0067); a new key
//      type issuing a key of that type, its default key management, the old
//      key kept in its grace;
//   4. decryption: rsa-oaep with aes256-gcm signs in; aes256-cbc, rsa-1_5
//      and rsa-oaep-mgf1p announced on a real ciphertext (STS-FED-0139); a
//      wrong key and an altered ciphertext, which read the same
//      (STS-FED-0138);
//   5. the JWE ID Token: ECDH-ES / A256GCM signs in; A128CBC-HS256 and
//      RSA1_5 (0139); another key under our kid (0138); a kid naming no key
//      held (0137); nothing signed inside (0141);
//   6. rotation: the replaced key decrypts in its grace; two rotations old
//      under a short grace decrypts nothing (0138); SAML 1.1 has no key to
//      rotate (0144).
//
// ENVIRONMENT: the product realm's keys are SEALED, so the process must hold
// a key-encryption key and persist keys — every stack's product and store
// modes do. A memory-store development process holds none, and there a
// product realm's relationship gets no key at all (rotate-key answers
// STS-FED-0142): a private probe needs a KEK file, STS_KEYS_SOURCE=persisted
// and a store (STS_PERSISTENCE_MODE=ldif).
//
// NOT HERE: `crypto.js`'s allow-list refusing before any key operation with
// no key given (STS-KEYS-0071 — no request reaches the library without a
// relationship's key), and the sealed-in-product claim about the stored key
// (no view shows a private half to compare; the vendored job holds that the
// view carries none).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const xmldsig = require("./saml_xmldsig.js");
const K = require("./oauth_wire_kit.js").kit(
  "sts_federation_encryption_codes");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const ISSUER = "urn:test:fec-partner:" + K.STAMP;
const SUBJECT = "fec-subject-" + K.STAMP;
const OIDC_ISSUER = "https://fec-oidc-" + K.STAMP + ".invalid";
const CLIENT = "fec-client-" + K.STAMP;

function el(name, attrs, inner) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return "<" + name + (attrs || "") + ">" + (inner || "") + "</" + name + ">";
}

// XML ENCRYPTION, WRITTEN HERE (rsa transports only: the EC path is the
// vendored job's). `o.cipher` aes256-gcm | aes256-cbc; `o.transport`
// rsa-oaep (SHA-256, MGF1-SHA-256) | rsa-oaep-mgf1p | rsa-1_5;
// `o.alter` flips a byte of the ciphertext after it is made.
function encryptXml(xml, certPem, o) {
  log.debug("Entering encryptXml(). " + o.cipher + " " + o.transport);
  const recipient = new nodeCrypto.X509Certificate(certPem).publicKey;
  const gcm = /gcm$/.test(o.cipher);
  const key = nodeCrypto.randomBytes(32);
  const iv = nodeCrypto.randomBytes(gcm ? 12 : 16);
  const cipher = nodeCrypto.createCipheriv(gcm ? "aes-256-gcm"
                                               : "aes-256-cbc", key, iv);
  const body = Buffer.concat([iv, cipher.update(Buffer.from(xml, "utf8")),
                              cipher.final(),
                              gcm ? cipher.getAuthTag() : Buffer.alloc(0)]);
  if (o.alter) {
    body[body.length - 20] ^= 0x55;
  }
  let wrapped;
  let method;
  if (o.transport === "rsa-1_5") {
    wrapped = nodeCrypto.publicEncrypt({ key: recipient,
      padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, key);
    method = el("xenc:EncryptionMethod", " Algorithm=\"" + XENC +
                "rsa-1_5\"");
  } else {
    const sha256 = o.transport === "rsa-oaep";
    wrapped = nodeCrypto.publicEncrypt({ key: recipient,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: sha256 ? "sha256" : "sha1" }, key);
    method = sha256
      ? el("xenc:EncryptionMethod", " Algorithm=\"" + XENC11 + "rsa-oaep\"",
           el("ds:DigestMethod", " Algorithm=\"" + XENC + "sha256\"") +
           el("xenc11:MGF", " xmlns:xenc11=\"" + XENC11 +
              "\" Algorithm=\"" + XENC11 + "mgf1sha256\""))
      : el("xenc:EncryptionMethod", " Algorithm=\"" + XENC +
           "rsa-oaep-mgf1p\"",
           el("ds:DigestMethod", " Algorithm=\"" + DS + "sha1\""));
  }
  const keyXml = el("xenc:EncryptedKey", "", method +
    el("xenc:CipherData", "",
       el("xenc:CipherValue", "", wrapped.toString("base64"))));
  const data = el("xenc:EncryptedData", " xmlns:xenc=\"" + XENC +
                  "\" Type=\"" + XENC + "Element\"",
    el("xenc:EncryptionMethod", " Algorithm=\"" + (gcm ? XENC11 : XENC) +
       o.cipher + "\"") +
    el("ds:KeyInfo", " xmlns:ds=\"" + DS + "\"", keyXml) +
    el("xenc:CipherData", "",
       el("xenc:CipherValue", "", body.toString("base64"))));
  log.debug("Leaving encryptXml().");
  return el("saml:EncryptedAssertion", " xmlns:saml=\"" + SAML + "\"", data);
}

// JWE, WRITTEN HERE: ECDH-ES direct with A256GCM (RFC 7518 section 4.6);
// `headerExtra` announces another alg or enc on a real JWE.
function jweTo(jwk, plaintext, headerExtra) {
  log.debug("Entering jweTo().");
  const recipient = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const ephemeral = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" });
  const epk = ephemeral.publicKey.export({ format: "jwk" });
  const header = Object.assign({ alg: "ECDH-ES", enc: "A256GCM", cty: "JWT",
    kid: jwk.kid, epk: { kty: "EC", crv: "P-256", x: epk.x, y: epk.y } },
  headerExtra || {});
  const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                       publicKey: recipient });
  const u32 = function (n) {
    log.debug("Entering u32().");
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug("Leaving u32().");
    return b;
  };
  const algId = Buffer.from("A256GCM", "utf8");
  const cek = nodeCrypto.createHash("sha256").update(Buffer.concat([
    u32(1), z, u32(algId.length), algId, u32(0), u32(0), u32(256)]))
    .digest();
  const protectedHeader = Buffer.from(JSON.stringify(header))
    .toString("base64url");
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  c.setAAD(Buffer.from(protectedHeader, "ascii"));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")),
                            c.final()]);
  log.debug("Leaving jweTo().");
  return [protectedHeader, "", iv.toString("base64url"),
          ct.toString("base64url"), c.getAuthTag().toString("base64url")]
    .join(".");
}

function pemOf(der) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return "-----BEGIN CERTIFICATE-----\n" +
    (String(der).match(/.{1,64}/g) || []).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

function tag(w, what) {
  log.debug("Entering tag().");
  log.debug("Leaving tag().");
  return "[" + w.mode + "] " + what;
}

function api(w, path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(w.SP) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

async function relationship(w, id, protocol, peer, settings) {
  log.debug("Entering relationship(). " + id);
  await K.ok(K.rb(w.SP) + "/admin-api/federation/create", { id: id,
    role: "service-provider", protocol: protocol, peer: peer },
  "created " + id);
  for (const field of Object.keys(settings || {})) {
    await K.ok(K.rb(w.SP) + "/admin-api/federation/set", { id: id,
      field: field, value: settings[field] }, "set " + field + " on " + id);
  }
  log.debug("Leaving relationship().");
}

async function viewOf(w, id) {
  log.debug("Entering viewOf(). " + id);
  const r = await api(w, "/federation?relationship=" + id);
  log.debug("Leaving viewOf().");
  return r.json || {};
}

async function encryptionCert(w, id) {
  log.debug("Entering encryptionCert(). " + id);
  const r = await K.send(K.rb(w.SP) + "/federation/metadata/" + id);
  const desc = (/<md:KeyDescriptor use="encryption">[\s\S]*?<\/md:KeyDescriptor>/
    .exec(r.text) || [])[0] || "";
  const der = ((/X509Certificate>([^<]+)</.exec(desc) || [])[1] || "")
    .replace(/\s+/g, "");
  log.debug("Leaving encryptionCert().");
  return der ? pemOf(der) : "";
}

async function world(mode) {
  log.debug("Entering world(). " + mode);
  const w = { mode: mode, product: mode === "product" };
  w.SP = await K.realm("fec-" + mode.slice(0, 1), mode);
  w.person = "fec-" + mode.slice(0, 1) + "-" + K.rand(3);
  await K.ok(K.rb(w.SP) + "/admin-api/users/create", { username: w.person,
    invent: false, credential: "none", attributes: {
      cn: "Enc " + w.person, givenName: "Enc", sn: w.person,
      mail: w.person + "@" + w.SP + ".example.net" } }, "created the person");
  w.signer = await S.credential("fec partner " + K.STAMP);
  w.stranger = await S.credential("fec stranger " + K.STAMP);
  w.oidcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = Object.assign(w.oidcKey.publicKey.export({ format: "jwk" }),
                            { kid: "fec-sig", alg: "RS256", use: "sig" });
  await relationship(w, "fec-saml", "saml2", ISSUER, {
    fedSsoUrl: "https://fec-" + K.STAMP + ".invalid/sso",
    fedSigningCertificate: S.b64cert(w.signer.certificatePem),
    fedAllowUnsolicited: "TRUE", fedSubjectPolicy: "pre-linked" });
  await relationship(w, "fec-oidc", "oidc", OIDC_ISSUER, {
    fedSsoUrl: OIDC_ISSUER + "/authorize", fedClientId: CLIENT,
    fedResponseType: "id_token", fedScope: "openid",
    fedJwks: JSON.stringify({ keys: [jwk] }),
    fedSubjectPolicy: "pre-linked" });
  await relationship(w, "fec-saml11", "saml11", "urn:test:fec-11:" +
                     K.STAMP, { fedSsoUrl: "https://fec11-" + K.STAMP +
                                           ".invalid/" });
  await relationship(w, "fec-wsfed", "wsfed", "urn:test:fec-ws:" + K.STAMP,
                     { fedSsoUrl: "https://fecws-" + K.STAMP +
                                  ".invalid/" });
  for (const id of ["fec-saml", "fec-oidc"]) {
    await K.ok(K.rb(w.SP) + "/admin-api/federation/enable", { id: id },
               "enabled " + id);
  }
  await K.ok(K.rb(w.SP) + "/admin-api/users/federation-link", {
    user: w.person, relationship: "fec-saml", subject: SUBJECT }, "linked");
  await K.ok(K.rb(w.SP) + "/admin-api/users/federation-link", {
    user: w.person, relationship: "fec-oidc", subject: SUBJECT }, "linked");
  const view = await viewOf(w, "fec-saml");
  w.acs = view.endpoints.assertionConsumerService;
  w.oidcAcs = (await viewOf(w, "fec-oidc")).endpoints
    .assertionConsumerService;
  w.cert = await encryptionCert(w, "fec-saml");
  const keys = await K.send(K.rb(w.SP) + "/federation/jwks/fec-oidc");
  w.encJwk = ((keys.json || {}).keys || [])[0] || {};
  log.debug("Leaving world().");
  return w;
}

function assertionFor(w) {
  log.debug("Entering assertionFor().");
  const built = xmldsig.buildAssertion({ issuer: ISSUER, subject: SUBJECT,
    audience: w.acs, recipient: w.acs, authnStatement: true });
  log.debug("Leaving assertionFor().");
  return xmldsig.sign(built, w.signer.privateKeyPem, "");
}

function responseOf(inner) {
  log.debug("Entering responseOf().");
  log.debug("Leaving responseOf().");
  return Buffer.from("<samlp:Response xmlns:samlp=\"" + SAMLP + "\" ID=\"" +
    xmldsig.id() + "\" IssueInstant=\"" + xmldsig.iso(0) +
    "\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"" + SAML + "\">" + ISSUER +
    "</saml:Issuer><samlp:Status><samlp:StatusCode " +
    "Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">" +
    "</samlp:StatusCode></samlp:Status>" + inner + "</samlp:Response>",
  "utf8").toString("base64");
}

// A SAML sign-in at the relationship's ACS with `inner` as the assertion
// (encrypted or not); `code` is read off the audit log around it.
async function samlPost(w, inner, code) {
  log.debug("Entering samlPost().");
  const act = function () {
    return K.send(w.acs, { form: { SAMLResponse: responseOf(inner) } });
  };
  const got = code ? await K.coded(w.SP, code, act)
                   : { answer: await act(), rose: 0 };
  log.debug("Leaving samlPost(). " + got.answer.status);
  return got;
}

function startsSession(r) {
  log.debug("Entering startsSession().");
  log.debug("Leaving startsSession().");
  return (r.status === 302 || r.status === 303 || r.status === 200) &&
    (r.headers.getSetCookie ? r.headers.getSetCookie() : []).some(
      function (c) {
        // `__Host-sts_session` in product, `sts_session` in development.
        return /^(?:__Host-)?sts_session=[^;]+/.test(c);
      });
}

async function oidcPost(w, wrap, code) {
  log.debug("Entering oidcPost().");
  const b = K.browser();
  const begun = await b.go(K.rb(w.SP) + "/federation/login/fec-oidc");
  const asked = new URL(begun.location);
  const now = Math.floor(Date.now() / 1000);
  const input = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT",
    kid: "fec-sig" })).toString("base64url") + "." +
    Buffer.from(JSON.stringify({ iss: OIDC_ISSUER, aud: CLIENT,
      sub: SUBJECT, iat: now, exp: now + 300,
      nonce: asked.searchParams.get("nonce") })).toString("base64url");
  const signed = input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
    w.oidcKey.privateKey).toString("base64url");
  const act = function () {
    return b.go(w.oidcAcs, { form: { id_token: wrap(signed),
                                     state: asked.searchParams.get("state") } });
  };
  const got = code ? await K.coded(w.SP, code, act)
                   : { answer: await act(), rose: 0 };
  log.debug("Leaving oidcPost(). " + got.answer.status);
  return got;
}

// ------------------------------------------------------------------- 0
async function plaintext(w) {
  log.debug("Entering plaintext().");
  log.info("=== 0. [" + w.mode + "] plaintext ===");
  let got = await samlPost(w, assertionFor(w), w.product ? "STS-FED-0140"
                                                         : null);
  K.check(tag(w, "0a. a plaintext SAML 2.0 assertion is " + (w.product
    ? "REFUSED in product (401, STS-FED-0140)" : "accepted in development")),
  function () {
    if (w.product) {
      assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
      assert.ok(got.rose >= 1);
    } else {
      assert.ok(startsSession(got.answer), K.shown(got.answer));
    }
  });
  got = await oidcPost(w, function (s) {
    return s;
  }, w.product ? "STS-FED-0140" : null);
  K.check(tag(w, "0b. a signed-only ID Token by form_post is " + (w.product
    ? "REFUSED in product (401, STS-FED-0140)" : "accepted in development")),
  function () {
    if (w.product) {
      assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
      assert.ok(got.rose >= 1);
    } else {
      assert.ok(got.answer.status < 400, K.shown(got.answer));
    }
  });
  await relationship(w, "fec-bare", "saml2", "urn:test:fec-bare:" + K.STAMP,
                     {});
  const bare = await viewOf(w, "fec-bare");
  K.check(tag(w, "0c. a relationship's readiness never names the key in " +
          "development, which accepts plaintext"), function () {
    assert.ok(Array.isArray(bare.missing), JSON.stringify(bare).slice(0,
                                                                    200));
    const needsKey = (bare.missing || []).some(function (m) {
      return /fedEncryptionKey/.test(String(m));
    });
    assert.ok(!needsKey || w.product, JSON.stringify(bare.missing));
  });
  log.debug("Leaving plaintext().");
}

// ------------------------------------------------------------------- 3
async function fields(w) {
  log.debug("Entering fields().");
  log.info("=== 3. [" + w.mode + "] the encryption fields ===");
  const refusals = [
    ["fec-saml", "fedContentEncryptionAlgorithm", "aes256-cbc",
     "STS-FED-0139"],
    ["fec-saml", "fedKeyManagementAlgorithm", "rsa-1_5", "STS-FED-0139"],
    ["fec-oidc", "fedKeyManagementAlgorithm", "RSA1_5", "STS-FED-0139"],
    ["fec-oidc", "fedContentEncryptionAlgorithm", "A128CBC-HS256",
     "STS-FED-0139"],
    ["fec-saml", "fedKeyManagementAlgorithm", "ecdh-es", "STS-FED-0143"],
    ["fec-saml", "fedKeyManagementAlgorithm", "RSA-OAEP-256",
     "STS-FED-0143"],
    ["fec-saml11", "fedEncryptionKeyType", "rsa-3072", "STS-FED-0143"],
    ["fec-saml", "fedEncryptionKeyType", "x-wing", "STS-FED-0143"],
    // WIRE DIFFERS: the in-process act meets federation.update()'s "not
    // editable" (STS-FED-0067); over /admin-api the operation's request
    // model names the 68 fields it accepts and refuses first.
    ["fec-saml", "fedEncryptionKey", "{}", "STS-API-0009"]
  ];
  for (const one of refusals) {
    const got = await K.coded(w.SP, one[3], function () {
      return api(w, "/federation/set", { id: one[0], field: one[1],
                                         value: one[2] });
    });
    K.check(tag(w, "3a. " + one[1] + "=" + one[2] + " on " + one[0] +
            " is refused (" + one[3] + "), no code in the answer"),
    function () {
      assert.strictEqual(got.answer.status, 400, got.answer.text.slice(0,
                                                                       200));
      assert.ok(got.rose >= 1, "no " + one[3] + " row");
      assert.ok(got.answer.text.indexOf(one[3]) < 0);
    });
  }
  const typed = await api(w, "/federation/set", { id: "fec-wsfed",
    field: "fedEncryptionKeyType", value: "ec-p256" });
  const ws = await viewOf(w, "fec-wsfed");
  const enc = ws.encryption || {};
  K.check(tag(w, "3b. a new key type issues a key of that type at once, " +
          "takes its default key management, and keeps the old key in its " +
          "grace"), function () {
    assert.strictEqual(typed.status, 200, typed.text.slice(0, 200));
    assert.strictEqual((enc.keys || []).length, 2, JSON.stringify(enc)
      .slice(0, 400));
    assert.ok(/ec-p256/.test(JSON.stringify(enc.keys[0]) +
                             JSON.stringify(enc.current || {})),
              JSON.stringify(enc).slice(0, 400));
    assert.ok(/"fedKeyManagementAlgorithm":\s*"ecdh-es"/.test(
      JSON.stringify(ws)), JSON.stringify(ws.fields || {}).slice(0, 300));
  });
  log.debug("Leaving fields().");
}

// ------------------------------------------------------------------- 4
async function decryption(w) {
  log.debug("Entering decryption().");
  log.info("=== 4. [" + w.mode + "] XML decryption ===");
  const good = await samlPost(w, encryptXml(assertionFor(w), w.cert,
    { cipher: "aes256-gcm", transport: "rsa-oaep" }));
  K.check(tag(w, "4a. rsa-oaep (SHA-256, MGF1-SHA-256) with aes256-gcm " +
          "signs in"), function () {
    assert.ok(startsSession(good.answer), K.shown(good.answer));
  });
  for (const [cipher, transport] of [["aes256-cbc", "rsa-oaep"],
                                     ["aes256-gcm", "rsa-1_5"],
                                     ["aes256-gcm", "rsa-oaep-mgf1p"]]) {
    const got = await samlPost(w, encryptXml(assertionFor(w), w.cert,
      { cipher: cipher, transport: transport }), "STS-FED-0139");
    K.check(tag(w, "4b. " + cipher + " / " + transport + " on a real " +
            "ciphertext is refused 401 (STS-FED-0139), no session"),
    function () {
      assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
      assert.ok(got.rose >= 1);
      assert.ok(!startsSession(got.answer));
    });
  }
  const wrong = await samlPost(w, encryptXml(assertionFor(w),
    w.stranger.certificatePem, { cipher: "aes256-gcm",
                                 transport: "rsa-oaep" }), "STS-FED-0138");
  const altered = await samlPost(w, encryptXml(assertionFor(w), w.cert,
    { cipher: "aes256-gcm", transport: "rsa-oaep", alter: true }),
  "STS-FED-0138");
  const strip = function (t) {
    log.debug("Entering strip().");
    log.debug("Leaving strip().");
    return String(t).replace(/<[^>]*>/g, " ").replace(/\d{6,}/g, "#")
      .replace(/\s+/g, " ");
  };
  K.check(tag(w, "4c. a wrong key and an altered ciphertext are each " +
          "refused 401 (STS-FED-0138) and read the same"), function () {
    assert.strictEqual(wrong.answer.status, 401, K.shown(wrong.answer));
    assert.strictEqual(altered.answer.status, 401, K.shown(altered.answer));
    assert.ok(wrong.rose >= 1 && altered.rose >= 1);
    assert.strictEqual(strip(wrong.answer.text).length > 0, true);
    assert.ok(/could not be decrypted/.test(wrong.answer.text) &&
              /could not be decrypted/.test(altered.answer.text));
  });
  log.debug("Leaving decryption().");
}

// ------------------------------------------------------------------- 5
async function jwe(w) {
  log.debug("Entering jwe().");
  log.info("=== 5. [" + w.mode + "] an encrypted ID Token ===");
  let got = await oidcPost(w, function (s) {
    return jweTo(w.encJwk, s);
  });
  K.check(tag(w, "5a. an ID Token signed then encrypted (ECDH-ES, A256GCM) " +
          "to the published key signs in"), function () {
    assert.ok(w.encJwk.kid && w.encJwk.kty === "EC" && !w.encJwk.d,
              JSON.stringify(w.encJwk));
    assert.ok(got.answer.status < 400, K.shown(got.answer));
  });
  for (const extra of [{ enc: "A128CBC-HS256" }, { alg: "RSA1_5" }]) {
    got = await oidcPost(w, function (s) {
      return jweTo(w.encJwk, s, extra);
    }, "STS-FED-0139");
    K.check(tag(w, "5b. " + (extra.enc || extra.alg) + " is refused 401 " +
            "(STS-FED-0139)"), function () {
      assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
      assert.ok(got.rose >= 1);
    });
  }
  const stranger = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
  got = await oidcPost(w, function (s) {
    return jweTo(Object.assign({}, stranger, { kid: w.encJwk.kid }), s);
  }, "STS-FED-0138");
  K.check(tag(w, "5c. a JWE to another key under our kid is refused 401 " +
          "(STS-FED-0138)"), function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  got = await oidcPost(w, function (s) {
    return jweTo(Object.assign({}, w.encJwk), s, { kid: "no-such-kid" });
  }, "STS-FED-0137");
  K.check(tag(w, "5d. a kid naming no key held is STS-FED-0137"),
          function () {
            assert.ok(got.answer.status >= 400, K.shown(got.answer));
            assert.ok(got.rose >= 1);
          });
  got = await oidcPost(w, function () {
    return jweTo(w.encJwk, "{\"sub\":\"" + SUBJECT + "\"}");
  }, "STS-FED-0141");
  K.check(tag(w, "5e. a JWE with nothing signed inside is refused 401 " +
          "(STS-FED-0141)"), function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  log.debug("Leaving jwe().");
}

// ------------------------------------------------------------------- 6
async function rotation(w) {
  log.debug("Entering rotation().");
  log.info("=== 6. [" + w.mode + "] rotation ===");
  const first = w.cert;
  const rotated = await api(w, "/federation/rotate-key", { id: "fec-saml" });
  const second = await encryptionCert(w, "fec-saml");
  const toKey = function (certPem, code) {
    log.debug("Entering toKey().");
    log.debug("Leaving toKey().");
    return samlPost(w, encryptXml(assertionFor(w), certPem,
      { cipher: "aes256-gcm", transport: "rsa-oaep" }), code);
  };
  const inGrace = await toKey(first);
  const fresh = await toKey(second);
  K.check(tag(w, "6a. a rotation publishes a new key, which decrypts, and " +
          "the key it replaced still decrypts in its grace"), function () {
    assert.strictEqual(rotated.status, 200, rotated.text.slice(0, 200));
    assert.notStrictEqual(second, first);
    assert.ok(startsSession(fresh.answer), K.shown(fresh.answer));
    assert.ok(startsSession(inGrace.answer), K.shown(inGrace.answer));
  });
  await K.set(w.SP, "federation.encryptionKeyGraceS", 2);
  await api(w, "/federation/rotate-key", { id: "fec-saml" });
  const old = await toKey(first, "STS-FED-0138");
  K.check(tag(w, "6b. a key two rotations old decrypts nothing (401, " +
          "STS-FED-0138)"), function () {
    assert.strictEqual(old.answer.status, 401, K.shown(old.answer));
    assert.ok(old.rose >= 1);
  });
  await K.sleep(3000);
  const past = await toKey(second);
  K.check(tag(w, "6c. past its grace the replaced key decrypts nothing, " +
          "before any job has run"), function () {
    assert.strictEqual(past.answer.status >= 400, true, K.shown(past.answer));
    assert.ok(!startsSession(past.answer));
  });
  await K.unset(w.SP, "federation.encryptionKeyGraceS");
  const refused = await K.coded(w.SP, "STS-FED-0144", function () {
    return api(w, "/federation/rotate-key", { id: "fec-saml11" });
  });
  K.check(tag(w, "6d. SAML 1.1 has no key to rotate (400, STS-FED-0144)"),
          function () {
            assert.strictEqual(refused.answer.status, 400,
                               refused.answer.text.slice(0, 200));
            assert.ok(refused.rose >= 1);
          });
  w.cert = await encryptionCert(w, "fec-saml");
  log.debug("Leaving rotation().");
}

async function test() {
  log.debug("Entering test().");
  for (const mode of ["development", "product"]) {
    const w = await world(mode);
    await plaintext(w);
    await fields(w);
    await decryption(w);
    await jwe(w);
    await rotation(w);
  }
  log.debug("Leaving test().");
}

K.main(test, 56);
