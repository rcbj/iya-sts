"use strict";
//
// File: sts_gnap_rs.js
//
// ---------------------------------------------------------------------------
// GNAP RESOURCE SERVER CONNECTIONS (RFC 9767) AGAINST A RUNNING SERVICE: THE
// FIVE TOKEN FORMATS, CHECKED BY CODE THAT IS NOT THE SERVICE'S; INTROSPECTION,
// ACTIVE AND EVERY WAY OF BEING INACTIVE; RESOURCE SET REGISTRATION; TOKEN
// DERIVATION; AND A KEY PROVED BY MUTUAL TLS.
//
// `sts_gnap_core.js` drives the client instance's half of RFC 9635. This is the
// other party: a resource server with a key of its own, registered on an
// application entry the way an operator would register one, which registers a
// resource set, receives tokens issued for it, introspects them, and derives a
// downstream token from one.
//
// **EACH FORMAT IS CHECKED BY THIS FILE, NOT BY ASKING THE SERVICE.** Asking
// introspection whether a token is good proves the authorization server agrees
// with itself. So:
//
//   jwt-signed     the JWS verified against /oauth2/jwks with node's crypto, and
//                  `cnf.jkt` recomputed from the client's JWK by RFC 7638
//   jwt-encrypted  the JWE opened with THIS FILE'S private key (RSA-OAEP-256 +
//                  A256GCM, written out here), then the inner JWS as above
//   macaroon       the V2 binary format decoded here and the HMAC-SHA256 chain
//                  recomputed from the root key on the resource server's entry
//   biscuit        the protobuf walked here and the authority block's Ed25519
//                  signature verified against the published root key, and the
//                  proof's next secret shown to be the next key's private half
//   zcap           the realm's default suite, eddsa-jcs-2022 (#43): the
//                  verification method resolved through the published
//                  controller document to a Multikey that is the published
//                  Ed25519 key, then the Data Integrity proof verified HERE —
//                  RFC 8785 written out below, SHA-256 of the proof
//                  configuration and of the capability, and node's Ed25519.
//                  Until 2026-09-22 the proof was Ed25519Signature2020, which
//                  needs RDF dataset canonicalization this file does not
//                  carry, so its signature was the service's word; with a
//                  JCS suite none of the five formats is.
//
// Everything runs in a THROWAWAY TRUST REALM that is left behind.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_rs",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnaprs").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: "gnap-rs-Passw0rd!-" + String(Date.now()).slice(-6),
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-rs-owner");
const FORMATS = ["jwt-signed", "jwt-encrypted", "macaroon", "biscuit", "zcap"];

// ---------------------------------------------------------------------------
// INDEPENDENT VERIFIERS.
// ---------------------------------------------------------------------------
function b64json(segment) {
  log.debug("Entering b64json().");
  log.debug("Leaving b64json().");
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

function verifyJws(compact, jwks) {
  log.debug("Entering verifyJws().");
  const parts = String(compact).split(".");
  assert.strictEqual(parts.length, 3, "a JWS compact serialization has three " +
                                      "parts");
  const header = b64json(parts[0]);
  const jwk =
      jwks.keys.filter(function (k) { return k.kid === header.kid; })[0];
  assert.ok(jwk, "the JWS kid " + header.kid + " is in the published JWKS");
  const hash = "sha" + String(header.alg).slice(2);
  const signed = Buffer.from(parts[0] + "." + parts[1]);
  const signature = Buffer.from(parts[2], "base64url");
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  let good;
  if (/^PS/.test(header.alg)) {
    good = nodeCrypto.verify(hash, signed,
                             { key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                                             saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  } else if (/^ES/.test(header.alg)) {
    good = nodeCrypto.verify(hash, signed,
                             { key: key, dsaEncoding: "ieee-p1363" },
                             signature);
  } else {
    good = nodeCrypto.verify(hash, signed, key, signature);
  }
  assert.ok(good,
            "the JWS signature verifies against the JWKS (" + header.alg + ")");
  log.debug("Leaving verifyJws().");
  return { header: header, claims: b64json(parts[1]) };
}

// RFC 7638: the required members in lexicographic order, no whitespace.
function jwkThumbprint(jwk) {
  log.debug("Entering jwkThumbprint().");
  const members = { EC: ["crv", "kty", "x", "y"], RSA: ["e", "kty", "n"],
                    OKP: ["crv", "kty", "x"] }[jwk.kty];
  const canonical = "{" +
                    members.map(function (m) {
                      return JSON.stringify(m) + ":" + JSON.stringify(jwk[m]);
                    })
    .join(",") + "}";
  log.debug("Leaving jwkThumbprint().");
  return gnap.b64u(gnap.sha("sha256", Buffer.from(canonical)));
}

// RFC 7516 compact, RSA-OAEP-256 key wrap, AES-GCM content encryption.
function openJwe(compact, privateKey) {
  log.debug("Entering openJwe().");
  const parts = String(compact).split(".");
  assert.strictEqual(parts.length, 5, "a JWE compact serialization has five " +
                                      "parts");
  const header = b64json(parts[0]);
  assert.strictEqual(header.alg, "RSA-OAEP-256", "encrypted to the resource " +
                                                 "server's RSA key");
  const cek = nodeCrypto.privateDecrypt({ key: privateKey, oaepHash: "sha256",
                                         padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING },
                                       Buffer.from(parts[1], "base64url"));
  const bits = { A128GCM: 128, A192GCM: 192, A256GCM: 256 }[header.enc];
  assert.ok(bits, "a GCM content encryption: " + header.enc);
  const decipher = nodeCrypto.createDecipheriv("aes-" + bits + "-gcm", cek,
                                               Buffer.from(parts[2],
                                                           "base64url"));
  decipher.setAAD(Buffer.from(parts[0], "ascii"));
  decipher.setAuthTag(Buffer.from(parts[4], "base64url"));
  const plain = Buffer.concat([decipher.update(Buffer.from(parts[3],
                                                           "base64url")),
                               decipher.final()]);
  log.debug("Leaving openJwe().");
  return { header: header, plaintext: plain.toString("utf8") };
}

function uvarint(buf, at) {
  log.debug("Entering uvarint().");
  let value = 0;
  let shift = 0;
  let i = at;
  let byte;
  do {
    byte = buf[i++];
    value += (byte & 0x7f) * Math.pow(2, shift);
    shift += 7;
  } while (byte & 0x80);
  log.debug("Leaving uvarint().");
  return { value: value, next: i };
}

// libmacaroons' V2 binary format: a version byte, then fields of
// (type varint, length varint, bytes) with an EOS field (type 0, no length)
// closing the header, each caveat and the caveat list.
function decodeMacaroonV2(bytes) {
  log.debug("Entering decodeMacaroonV2().");
  assert.strictEqual(bytes[0], 2,
                     "a V2 macaroon starts with the version byte 2");
  let i = 1;
  function field() {
    log.debug("Entering field().");
    const type = uvarint(bytes, i);
    i = type.next;
    if (type.value === 0) {
      log.debug("Leaving field().");
      return { type: 0 };
    }
    const length = uvarint(bytes, i);
    const data = bytes.slice(length.next, length.next + length.value);
    i = length.next + length.value;
    log.debug("Leaving field().");
    return { type: type.value, data: data };
  }
  const out = { location: null, identifier: null, caveats: [],
                signature: null };
  let f = field();
  while (f.type !== 0) {
    if (f.type === 1) { out.location = f.data.toString("utf8"); }
    if (f.type === 2) { out.identifier = f.data; }
    f = field();
  }
  for (;;) {
    f = field();
    if (f.type === 0) {
      break;
    }
    const caveat = { identifier: null, vid: null };
    while (f.type !== 0) {
      if (f.type === 2) { caveat.identifier = f.data; }
      if (f.type === 4) { caveat.vid = f.data; }
      f = field();
    }
    out.caveats.push(caveat);
  }
  f = field();
  assert.strictEqual(f.type, 6, "the signature field follows the caveats");
  out.signature = f.data;
  log.debug("Leaving decodeMacaroonV2().");
  return out;
}

function hmac(key, data) {
  log.debug("Entering hmac().");
  log.debug("Leaving hmac().");
  return nodeCrypto.createHmac("sha256", key).update(data).digest();
}

// The libmacaroons chain: the root key is first turned into a signing key with
// the fixed generator string, then each first-party caveat re-keys the MAC.
function macaroonSignature(rootKey, decoded) {
  log.debug("Entering macaroonSignature().");
  let sig = hmac(hmac(Buffer.from("macaroons-key-generator"), rootKey),
                 decoded.identifier);
  decoded.caveats.forEach(function (caveat) {
    assert.ok(!caveat.vid, "only first-party caveats are minted");
    sig = hmac(sig, caveat.identifier);
  });
  log.debug("Leaving macaroonSignature().");
  return sig;
}

// A protobuf message as [fieldNumber, bytes|varint] pairs.
function protoFields(buf) {
  log.debug("Entering protoFields().");
  const out = [];
  let i = 0;
  while (i < buf.length) {
    const key = uvarint(buf, i);
    i = key.next;
    const number = Math.floor(key.value / 8);
    const wire = key.value & 7;
    if (wire === 2) {
      const length = uvarint(buf, i);
      out.push([number, buf.slice(length.next, length.next + length.value)]);
      i = length.next + length.value;
    } else if (wire === 0) {
      const v = uvarint(buf, i);
      out.push([number, v.value]);
      i = v.next;
    } else {
      throw new Error("unexpected protobuf wire type " + wire);
    }
  }
  log.debug("Leaving protoFields().");
  return out;
}

function protoOne(fields, number) {
  log.debug("Entering protoOne().");
  const hit = fields.filter(function (f) { return f[0] === number; })[0];
  log.debug("Leaving protoOne().");
  return hit ? hit[1] : undefined;
}

function ed25519PublicFromRaw(raw) {
  log.debug("Entering ed25519PublicFromRaw().");
  log.debug("Leaving ed25519PublicFromRaw().");
  return nodeCrypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519",
                                             x: gnap.b64u(raw) },
                                      format: "jwk" });
}

// Biscuit: Biscuit{authority=2 SignedBlock, proof=4}; SignedBlock{block=1,
// nextKey=2 PublicKey{algorithm=1, key=2}, signature=3}; Proof{nextSecret=1}.
// The authority signature covers block || algorithm (u32 LE) || nextKey.key.
function verifyBiscuit(value, rootRaw) {
  log.debug("Entering verifyBiscuit().");
  const top = protoFields(Buffer.from(value, "base64url"));
  const authority = protoFields(protoOne(top, 2));
  const block = protoOne(authority, 1);
  const nextKey = protoFields(protoOne(authority, 2));
  const algorithm = protoOne(nextKey, 1) || 0;
  const nextPublic = protoOne(nextKey, 2);
  const signature = protoOne(authority, 3);
  const le = Buffer.alloc(4);
  le.writeUInt32LE(algorithm);
  const good = nodeCrypto.verify(null, Buffer.concat([block, le, nextPublic]),
                                 ed25519PublicFromRaw(rootRaw),
                                 signature);
  const proof = protoFields(protoOne(top, 4));
  const nextSecret = protoOne(proof, 1);
  let proofMatches = false;
  if (nextSecret) {
    const derived = nodeCrypto.createPrivateKey({ key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"), nextSecret]),
                                                  format: "der",
                                                  type: "pkcs8" });
    const pub = nodeCrypto.createPublicKey(derived).export({ format: "jwk" }).x;
    proofMatches = pub === gnap.b64u(nextPublic);
  }
  log.debug("Leaving verifyBiscuit().");
  return { signatureVerifies: good, proofMatches: proofMatches,
           algorithm: algorithm, block: block,
           blocks: top.filter(function (f) { return f[0] === 3; }).length };
}

// RFC 8785, the JSON Canonicalization Scheme: members sorted by UTF-16 code
// unit (what Array.prototype.sort() compares), every primitive as
// JSON.stringify() writes it — the RFC adopts ECMAScript's serialisation of
// strings and numbers.
function jcs(value) {
  log.debug("Entering jcs().");
  let out;
  if (value === null || typeof value !== "object") {
    out = JSON.stringify(value);
  } else if (Array.isArray(value)) {
    out = "[" + value.map(jcs).join(",") + "]";
  } else {
    out = "{" + Object.keys(value).sort().map(function (k) {
      return JSON.stringify(k) + ":" + jcs(value[k]);
    }).join(",") + "}";
  }
  log.debug("Leaving jcs().");
  return out;
}

// W3C Data Integrity EdDSA Cryptosuites v1.0, section 3.3.2 (eddsa-jcs-2022):
// the proof's @context is the document's, hashData is SHA-256(JCS(proof
// configuration)) || SHA-256(JCS(document without proof)), and the proof
// value is a base58-btc Ed25519 signature over it.
function verifyEddsaJcs(cap, publicRaw) {
  log.debug("Entering verifyEddsaJcs().");
  const proof = cap.proof;
  const unsecured = Object.assign({}, cap);
  delete unsecured.proof;
  const config = Object.assign({}, proof);
  delete config.proofValue;
  assert.strictEqual(jcs(config["@context"]), jcs(cap["@context"]),
                     "the proof carries the capability's @context");
  const sha = function (text) {
    return nodeCrypto.createHash("sha256").update(text, "utf8").digest();
  };
  const hashData = Buffer.concat([sha(jcs(config)), sha(jcs(unsecured))]);
  assert.ok(/^z/.test(proof.proofValue), "a base58-btc proof value");
  const signature = base58btc(String(proof.proofValue).slice(1));
  assert.strictEqual(signature.length, 64, "a 64-byte Ed25519 signature");
  const key = nodeCrypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: gnap.b64u(publicRaw) },
    format: "jwk" });
  const good = nodeCrypto.verify(null, hashData, key, signature);
  log.debug("Leaving verifyEddsaJcs(). " + good);
  return good;
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btc(text) {
  log.debug("Entering base58btc().");
  let n = 0n;
  for (const c of text) {
    const i = BASE58.indexOf(c);
    assert.ok(i >= 0, "a base58btc character");
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) { hex = "0" + hex; }
  let bytes = Buffer.from(hex, "hex");
  let zeros = 0;
  while (text[zeros] === "1") { zeros++; }
  log.debug("Leaving base58btc().");
  return Buffer.concat([Buffer.alloc(zeros), bytes]);
}

// ---------------------------------------------------------------------------
// A RESOURCE SERVER CALL: a signed POST from the RS's own key.
// ---------------------------------------------------------------------------
function introspect(rs, token, extra) {
  log.debug("Entering introspect().");
  log.debug("Leaving introspect().");
  return rs.send("POST", h.realmBase + "/gnap/introspect", {
    json: Object.assign({ access_token: token,
                          resource_server: { key: rs.keyObject() } },
                        extra || {}) });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving RFC 9767 at " + h.realmBase);

  // =========================================================================
  // 0. THE REALM, A RESOURCE OWNER, A RESOURCE SERVER REGISTERED BY HAND.
  // =========================================================================
  log.info("=== 0. the realm and a registered resource server ===");
  await h.createRealm("GNAP resource servers");
  await h.setting("gnap.continueWaitS", 0);
  await h.ensurePerson(OWNER);
  const rsKey = new gnap.Client({ key: gnap.newKey("ES256") });
  const rsJwe = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsJweJwk = Object.assign(rsJwe.publicKey.export({ format: "jwk" }),
                                 { alg: "RSA-OAEP-256", use: "enc" });
  const RS_ID = "gnap-rs-" + h.realm;
  const RS_URI = "https://rs.gnap.test/api";
  await h.ok(h.realmApi + "/applications/create", {
    identifier: RS_ID, kind: "gnap-resource-server", protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(rsKey.keyObject()),
              gnapJweKey: JSON.stringify(rsJweJwk),
              gnapResourceServerUri: RS_URI } }, "registered the resource " +
                                                 "server");
  const client = new gnap.Client({ key: gnap.newKey("ES256") });

  // =========================================================================
  // 1. RESOURCE SET REGISTRATION (RFC 9767 section 3.4).
  // =========================================================================
  log.info("=== 1. resource set registration ===");
  const references = {};
  for (const format of FORMATS) {
    const r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
      access: [{ type: "https://rs.gnap.test/photos", actions: ["read"],
                 locations: [RS_URI] }],
      resource_server: { key: rsKey.keyObject() }, token_formats_supported: [
        format] } });
    check("registering a resource set that only accepts " + format + " " +
        "answers a reference", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.ok(r.json.resource_reference, r.text);
      assert.strictEqual(r.json.introspection_endpoint,
                         h.realmBase + "/gnap/introspect");
    });
    references[format] = r.json.resource_reference;
  }
  let r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: [{ type: "https://rs.gnap.test/photos", actions: ["read"],
               locations: [RS_URI] }],
    resource_server: { key: rsKey.keyObject() }, token_formats_supported: [
      "macaroon"] } });
  check("the same set registered again answers the SAME reference (section 3.4)", function () {
    assert.strictEqual(r.json.resource_reference, references.macaroon);
  });
  check("five formats gave five different references", function () {
    assert.strictEqual(new Set(Object.values(references)).size, 5);
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: ["x"], resource_server: { key: rsKey.keyObject() },
    token_formats_supported: ["paseto"] } });
  check("a set whose only token format this AS does not issue is " +
        "invalid_request", function () {
    h.refused(r, "invalid_request", "an unsupported format");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: [], resource_server: { key: rsKey.keyObject() } } });
  check("an empty access list is invalid_request", function () {
    h.refused(r, "invalid_request", "no access");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource",
                       { json: { access: ["x"] } });
  check("a registration naming no resource server is invalid_resource_server " +
        "(section 3.2)", function () {
    h.refused(r, "invalid_resource_server", "no resource_server");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: ["x"], resource_server: { key: rsKey.keyObject() } },
                                                                 sign: false });
  check("an unsigned registration is refused as the resource server's failure",
        function () {
    h.refused(r, "invalid_resource_server", "an unsigned registration");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: ["x"], resource_server: { key: rsKey.keyObject() },
    token_introspection_required: "yes" } });
  check("a non-boolean token_introspection_required fails the JSON Schema",
        function () {
    h.refused(r, "invalid_request", "a string where a boolean belongs");
  });

  const entry = await h.apiGet(h.realmApi + "/applications?application=" +
                               encodeURIComponent(RS_ID));
  let macaroonRoot;
  check("registration wrote the macaroon root key onto the resource server's " +
        "own entry", function () {
    const values = entry.body.attributes.gnapMacaroonKey ||
                   entry.body.attributes.gnapmacaroonkey;
    assert.ok(values && values[0],
              JSON.stringify(Object.keys(entry.body.attributes)));
    macaroonRoot = Buffer.from(values[0], "base64url");
    assert.strictEqual(macaroonRoot.length, 32);
  });

  // =========================================================================
  // 2. FIVE FORMATS, EACH CHECKED BY THIS FILE (the header says how).
  // =========================================================================
  log.info("=== 2. the five token formats ===");
  const jwks = await (await fetch(h.realmBase + "/oauth2/jwks")).json();
  const material = (await gnap.rawRequest("GET", h.realmBase + "/gnap/keys",
                                          {})).json;
  const controllerDoc = await gnap.rawRequest("GET",
                                              h.realmBase +
                                              "/gnap/zcap/controller", {});
  check("the verification material and the controller document are published " +
        "no-store", function () {
    assert.ok(material && material.biscuit && material.zcap,
              JSON.stringify(material));
    assert.strictEqual(controllerDoc.status, 200, controllerDoc.text);
    assert.strictEqual(controllerDoc.headers["cache-control"], "no-store");
  });
  const rootRaw = Buffer.from(String(material.biscuit.root_public_key).replace(
      /^ed25519\//, ""), "hex");
  const clientJkt = jwkThumbprint(client.key.publicJwk);
  const issued = {};
  for (const format of FORMATS) {
    const done = await h.redirectGrant(client, OWNER,
                                       { access_token: {
                                         access: [references[format]] } });
    const token = done.released.access_token;
    issued[format] = token.value;
    r = await introspect(rsKey, token.value);
    check(format + ": introspection by its resource server is active with " +
                   "the section 2.1 model", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.active, true, r.text);
      assert.strictEqual(r.json.format, format);
      assert.strictEqual(r.json.aud, RS_ID);
      assert.strictEqual(r.json.iss, h.GRANT);
      assert.ok(r.json.key && r.json.key.jwk,
                "a bound token's key is returned");
      assert.deepStrictEqual(r.json.access, [references[format]]);
    });
    if (format === "jwt-signed") {
      check("jwt-signed: the JWS verifies against /oauth2/jwks here, and " +
            "cnf.jkt is the client's RFC 7638 thumbprint computed " +
            "here", function () {
              const v = verifyJws(token.value, jwks);
              assert.strictEqual(v.claims.typ, "GNAP");
              assert.strictEqual(v.claims.aud, RS_ID);
              assert.deepStrictEqual(v.claims.cnf, { jkt: clientJkt });
              assert.ok(v.claims.exp > v.claims.iat);
            });
    } else if (format === "jwt-encrypted") {
      check("jwt-encrypted: this file's RSA private key opens the JWE, and " +
            "the JWS inside verifies", function () {
        const opened = openJwe(token.value, rsJwe.privateKey);
        assert.strictEqual(opened.header.cty, "JWT");
        const v = verifyJws(opened.plaintext, jwks);
        assert.strictEqual(v.claims.aud, RS_ID);
        assert.deepStrictEqual(v.claims.cnf, { jkt: clientJkt });
      });
      check("jwt-encrypted: a different RSA key cannot open it", function () {
        const other = nodeCrypto.generateKeyPairSync("rsa",
                                                     { modulusLength: 2048 });
        assert.throws(function () { openJwe(token.value, other.privateKey); });
      });
    } else if (format === "macaroon") {
      check("macaroon: the V2 binary decodes here and the HMAC chain " +
            "recomputed from the root key on the entry equals the " +
            "signature", function () {
              const decoded = decodeMacaroonV2(Buffer.from(token.value,
                                                           "base64url"));
              assert.ok(decoded.caveats.length >= 5, "caveats carry the model");
              const caveats = decoded.caveats.map(
                  function (c) { return c.identifier.toString("utf8"); });
              assert.ok(caveats.indexOf("gnap:aud=" + RS_ID) >= 0,
                        caveats.join(" " +
                  "| "));
              assert.ok(caveats.indexOf("gnap:cnf=jkt:" + clientJkt) >= 0,
                        caveats.join(" " +
                  "| "));
              assert.ok(macaroonSignature(macaroonRoot, decoded).equals(
                  decoded.signature),
                        "the recomputed MAC matches");
              assert.ok(!macaroonSignature(nodeCrypto.randomBytes(32),
                                           decoded).equals(decoded.signature),
                        "and a different root key does not");
            });
      check("macaroon: appending a caveat without re-keying breaks the chain " +
            "(the attenuation rule)", function () {
        const decoded = decodeMacaroonV2(Buffer.from(token.value, "base64url"));
        decoded.caveats.push({ identifier: Buffer.from("gnap:label=forged"),
                               vid: null });
        assert.ok(!macaroonSignature(macaroonRoot, decoded).equals(
            decoded.signature));
      });
    } else if (format === "biscuit") {
      check("biscuit: the authority block's Ed25519 signature verifies here " +
            "against the published root key, and the proof's next secret is " +
            "the next key's private half", function () {
              const v = verifyBiscuit(token.value, rootRaw);
              assert.ok(v.signatureVerifies, "the authority signature");
              assert.ok(v.proofMatches, "the sealed-or-open proof");
              assert.ok(v.block.toString("latin1").indexOf(clientJkt) >= 0,
                        "the " +
                  "block carries the binding");
              const wrong = verifyBiscuit(token.value,
                                          nodeCrypto.randomBytes(32));
              assert.ok(!wrong.signatureVerifies, "a different root key does " +
                                                  "not verify");
            });
    } else if (format === "zcap") {
      check("zcap: an eddsa-jcs-2022 Data Integrity proof whose verification " +
            "method resolves through the published controller document to " +
            "the published Ed25519 key, and whose signature verifies HERE " +
            "over RFC 8785", function () {
              const cap = JSON.parse(Buffer.from(token.value, "base64url")
                                           .toString("utf8"));
              assert.ok(cap.proof && !Array.isArray(cap.proof),
                        "exactly one proof");
              const proof = cap.proof;
              assert.strictEqual(material.zcap.cryptosuite, "eddsa-jcs-2022",
                                 "/gnap/keys names the realm's suite");
              assert.strictEqual(proof.type, "DataIntegrityProof");
              assert.strictEqual(proof.cryptosuite, "eddsa-jcs-2022");
              assert.strictEqual(proof.proofPurpose, "capabilityDelegation");
              assert.deepStrictEqual(proof.capabilityChain,
                                     [cap.parentCapability],
                                     "a one-link chain from the root");
              assert.deepStrictEqual(cap["@context"].slice(0, 2),
                                     ["https://w3id.org/zcap/v1",
                                      "https://w3id.org/security/" +
                                      "data-integrity/v2"],
                                     "ZCAP-LD v0.4's context order");
              assert.deepStrictEqual(controllerDoc.json["@context"],
                                     ["https://www.w3.org/ns/cid/v1"],
                                     "a Controlled Identifiers v1.0 document");
              const methods = [].concat(controllerDoc.json.verificationMethod ||
                                        [],
                                        controllerDoc.json.assertionMethod ||
                                        [],
                                        controllerDoc.json.capabilityInvocation || [],
                                        controllerDoc.json.capabilityDelegation || []);
              const method = methods.filter(function (m) {
                return m && typeof m === "object" &&
                       m.id === proof.verificationMethod;
              })[0];
              assert.ok(method,
                        "the controller document names " +
                        proof.verificationMethod);
              assert.strictEqual(method.type, "Multikey");
              assert.ok((controllerDoc.json.capabilityDelegation || [])
                          .indexOf(proof.verificationMethod) >= 0,
                        "the key is authorized for capabilityDelegation");
              const multikey =
                  base58btc(String(method.publicKeyMultibase).slice(1));
              assert.strictEqual(multikey.slice(0, 2).toString("hex"), "ed01",
                                 "an " +
                  "Ed25519 multikey");
              assert.strictEqual(gnap.b64u(multikey.slice(2)),
                                 material.biscuit.jwk.x,
                                 "the same key /gnap/keys publishes");
              assert.ok(verifyEddsaJcs(cap, multikey.slice(2)),
                        "the Ed25519 signature over the JCS hash data " +
                        "verifies");
              const touched = JSON.parse(JSON.stringify(cap));
              touched.gnapLabel = String(touched.gnapLabel || "") + "!";
              assert.ok(!verifyEddsaJcs(touched, multikey.slice(2)),
                        "and a changed member does not");
            });
    }
    r = await client.send("GET", h.RS, { token: token.value });
    check(format + ": a token issued for one resource server is refused at " +
                   "another (the demonstration RS)",
          function () {
            assert.strictEqual(r.status, 401, r.text);
          });
  }

  // =========================================================================
  // 2b. EVERY FORMAT THROUGH THE WHOLE LIFECYCLE AT A RESOURCE SERVER.
  //
  // Section 2 proves each format is minted correctly; it presents four of the
  // five only where they are REFUSED. So each format is also ACCEPTED here, by
  // the demonstration resource server — whose format-specific check (audience,
  // key binding, access) runs only on this path — then narrowed, rotated,
  // revoked and allowed to expire, because rotation and modification RE-MINT in
  // the token's own format. A token asked for with no resource server named is
  // audienced to the demonstration RS, and `jwt-encrypted` is then encrypted to
  // this authorization server (dir), which is its other mode.
  // =========================================================================
  log.info("=== 2b. each format accepted, narrowed, rotated, revoked and " +
           "expired ===");
  const thief = new gnap.Client({ key: gnap.newKey("ES256") });
  for (const format of FORMATS) {
    await h.setting("gnap.accessTokenFormat", format);
    const life = await h.redirectGrant(client, OWNER);
    const first = life.released.access_token;
    r = await client.send("GET", h.RS, { token: first.value });
    check(format + ": the demonstration RS ACCEPTS it for read, and says " +
                   "which format it judged", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.format, format);
      assert.strictEqual(r.json.method, "httpsig");
      assert.deepStrictEqual(r.json.token.cnf, { jkt: clientJkt });
    });
    if (format === "jwt-encrypted") {
      check("jwt-encrypted: with no resource server key it is encrypted to " +
            "this authorization server (dir)",
            function () {
              const header = JSON.parse(Buffer.from(first.value.split(".")[0],
                                                    "base64url")
                                              .toString("utf8"));
              assert.strictEqual(header.alg, "dir", JSON.stringify(header));
            });
    }
    r = await client.send("POST", h.RS,
                          { token: first.value, json: { write: format } });
    check(format + ": and for write, which the grant also carries",
          function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.action, "write");
    });
    r = await thief.send("GET", h.RS, { token: first.value });
    check(format + ": the same value proved by another key is refused (401)",
          function () {
      assert.strictEqual(r.status, 401, r.text);
    });
    r = await client.send("GET", h.RS, { token: first.value, sign: false });
    check(format + ": the bound value with no proof is refused (401)",
          function () {
      assert.strictEqual(r.status, 401, r.text);
    });

    r = await client.send("PATCH", life.released.continue.uri, {
      token: life.released.continue.access_token.value,
      json: { access_token: { access: [{ type: h.DEMO,
                                         actions: ["read"] }] } } });
    check(format + ": modifying the grant to read only issues a new token",
          function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.notStrictEqual(r.json.access_token.value, first.value);
    });
    const narrowed = r.json.access_token;
    r = await client.send("GET", h.RS, { token: narrowed.value });
    check(format + ": the narrowed token is re-minted in the same format and " +
                   "reads", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.format, format);
    });
    r = await client.send("POST", h.RS,
                          { token: narrowed.value, json: { write: format } });
    check(format + ": and may not write — 403 insufficient_scope, decided on " +
                   "the format's own access", function () {
      assert.strictEqual(r.status, 403, r.text);
      assert.strictEqual(r.json.error, "insufficient_scope");
    });
    r = await client.send("GET", h.RS, { token: first.value });
    check(format + ": the token from before the modification no longer works",
          function () {
      assert.strictEqual(r.status, 401, r.text);
    });

    r = await client.send("POST", narrowed.manage.uri,
                          { token: narrowed.manage.access_token.value });
    check(format + ": rotating it answers a new value in the same format",
          function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.notStrictEqual(r.json.access_token.value, narrowed.value);
    });
    const rotated = r.json.access_token;
    r = await client.send("GET", h.RS, { token: rotated.value });
    check(format + ": the rotated value is accepted, as " + format,
          function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.format, format);
    });
    r = await client.send("GET", h.RS, { token: narrowed.value });
    check(format + ": and the value it replaced is refused", function () {
      assert.strictEqual(r.status, 401, r.text);
    });
    r = await client.send("DELETE", rotated.manage.uri,
                          { token: rotated.manage.access_token.value });
    assert.strictEqual(r.status, 204, r.text);
    r = await client.send("GET", h.RS, { token: rotated.value });
    check(format + ": revoked at its manage URI, it is refused at the RS",
          function () {
      assert.strictEqual(r.status, 401, r.text);
    });

    const carried = await h.redirectGrant(client, OWNER,
      { access_token: { access: h.readAccess(), flags: ["bearer"] } });
    r = await gnap.rawRequest("GET", h.RS,
                              { Authorization: "Bearer " +
                                               carried.released.access_token.value });
    check(format + ": a BEARER token in this format works with the Bearer " +
                   "scheme and no proof", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.format, format);
      assert.strictEqual(r.json.token.cnf, null);
    });

    await h.setting("gnap.accessTokenLifetimeS", 1);
    const brief = await h.redirectGrant(client, OWNER);
    await h.ok(h.realmApi + "/config/reset",
               { key: "gnap.accessTokenLifetimeS" }, "reset " +
        "the lifetime");
    await new Promise(function (resolve) { setTimeout(resolve, 2100); });
    r = await client.send("GET", h.RS,
                          { token: brief.released.access_token.value });
    check(format + ": a token past its one-second lifetime is refused",
          function () {
      assert.strictEqual(r.status, 401, r.text);
    });
  }
  await h.ok(h.realmApi + "/config/reset", { key: "gnap.accessTokenFormat" },
             "reset " +
      "the format");

  // =========================================================================
  // 3. INTROSPECTION: EVERY WAY OF BEING INACTIVE (RFC 9767 section 3.3).
  // =========================================================================
  log.info("=== 3. introspection answers inactive ===");
  const stranger = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await introspect(stranger, issued["jwt-signed"]);
  check("another resource server introspecting the token is told only " +
        "active: false", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(r.json, { active: false });
  });
  r = await introspect(rsKey, issued["jwt-signed"], { proof: "mtls" });
  check("naming a proof method the token is not bound with is active: false",
        function () {
    assert.deepStrictEqual(r.json, { active: false });
  });
  r = await introspect(rsKey, issued["jwt-signed"], { proof: "httpsig" });
  check("…and naming the method it IS bound with is active", function () {
    assert.strictEqual(r.json.active, true, r.text);
  });
  r = await introspect(rsKey, issued["jwt-signed"],
                       { access: ["something-else"] });
  check("asking about access the token does not carry is active: false",
        function () {
    assert.deepStrictEqual(r.json, { active: false });
  });
  r = await introspect(rsKey, "not-a-token-this-as-issued");
  check("a value this AS never issued is active: false", function () {
    assert.deepStrictEqual(r.json, { active: false });
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/introspect", { json: {
    access_token: issued.macaroon,
    resource_server: { key: rsKey.keyObject() } }, sign: false });
  check("an unsigned introspection call is invalid_resource_server",
        function () {
    h.refused(r, "invalid_resource_server", "an unsigned introspection");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/introspect", { json: {
    resource_server: { key: rsKey.keyObject() } } });
  check("an introspection call with no access_token is invalid_request",
        function () {
    h.refused(r, "invalid_request", "no access_token");
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/introspect", { json: {
    access_token: 7, resource_server: { key: rsKey.keyObject() } } });
  check("an access_token that is not a string fails the JSON Schema",
        function () {
    h.refused(r, "invalid_request", "a numeric access_token");
  });

  // =========================================================================
  // 4. TOKEN DERIVATION (RFC 9767 section 4).
  // =========================================================================
  log.info("=== 4. token derivation ===");
  const upstream = await h.redirectGrant(client, OWNER,
                                         { access_token: {
                                           access: [
                                             references["jwt-signed"]] } });
  const upstreamValue = upstream.released.access_token.value;
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: upstreamValue,
    access_token: { access: [references["jwt-signed"]] } } });
  check("the resource server derives a token from the one it was handed, " +
        "with no interaction", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value, r.text);
    assert.ok(!r.json.interact);
    assert.notStrictEqual(r.json.access_token.value, upstreamValue);
  });
  const derived = r.json.access_token.value;
  r = await introspect(rsKey, derived);
  check("the derived token names the resource server as its client and the " +
        "same resource owner", function () {
    assert.strictEqual(r.json.active, true, r.text);
    assert.strictEqual(r.json.instance_id, RS_ID);
    // A person's subject is `urn:uuid:<entryUUID>` since 2026-09-14.
    assert.ok(/gnap-rs-owner|^urn:uuid:[0-9a-f-]{36}$/.test(String(r.json.sub)),
              String(r.json.sub));
  });
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: upstreamValue,
    access_token: { access: [references["jwt-signed"],
                             { type: "https://rs.gnap.test/admin",
                               actions: ["delete"] }] } } });
  check("deriving MORE access than the existing token carries is request_denied", function () {
    h.refused(r, "request_denied", "a widening derivation");
  });
  r = await stranger.send("POST", h.GRANT, { json: {
    client: { key: stranger.keyObject() }, existing_access_token: upstreamValue,
    access_token: { access: [references["jwt-signed"]] } } });
  check("a resource server the token was not issued for cannot derive from it",
        function () {
    h.refused(r, "request_denied", "a derivation by another resource server");
  });
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: "never-issued",
    access_token: { access: [references["jwt-signed"]] } } });
  check("deriving from a token that is not active is invalid_request",
        function () {
    h.refused(r, "invalid_request", "an inactive existing token");
  });
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: 42,
    access_token: { access: [references["jwt-signed"]] } } });
  check("an existing_access_token that is not a string fails the JSON Schema",
        function () {
    h.refused(r, "invalid_request", "a numeric existing_access_token");
  });
  await h.setting("gnap.tokenDerivation", false);
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: upstreamValue,
    access_token: { access: [references["jwt-signed"]] } } });
  check("with gnap.tokenDerivation off a derivation is request_denied",
        function () {
    h.refused(r, "request_denied", "derivation switched off");
  });
  await h.setting("gnap.tokenDerivation", true);

  // =========================================================================
  // 5. REVOCATION REACHES INTROSPECTION.
  // =========================================================================
  log.info("=== 5. revoked tokens ===");
  const manage = upstream.released.access_token.manage;
  r = await client.send("DELETE", manage.uri,
                        { token: manage.access_token.value });
  check("the client revokes its token at the manage URI", function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  r = await introspect(rsKey, upstreamValue);
  check("…and the resource server's introspection now says active: false",
        function () {
    assert.deepStrictEqual(r.json, { active: false });
  });
  r = await rsKey.send("POST", h.GRANT, { json: {
    client: { key: rsKey.keyObject() }, existing_access_token: upstreamValue,
    access_token: { access: [references["jwt-signed"]] } } });
  check("…and it can no longer derive a token", function () {
    h.refused(r, "invalid_request", "a derivation from a revoked token");
  });

  // =========================================================================
  // 6. MUTUAL TLS (RFC 9635 section 7.3.2), with a self-signed certificate.
  // =========================================================================
  log.info("=== 6. mutual TLS ===");
  const forge = require("node-forge");
  const pair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600000);
  cert.setSubject([{ name: "commonName", value: "gnap-mtls-client" }]);
  cert.setIssuer([{ name: "commonName", value: "gnap-mtls-client" }]);
  cert.sign(pair.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(pair.privateKey);
  const certDer = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(
      cert)).getBytes(), "binary");
  const mtlsClient = new gnap.Client({ key: { alg: "RS256" }, proof: "mtls",
    tls: { cert: certPem, key: keyPem, certDer: certDer,
           rejectUnauthorized: false } });
  const mtlsFlow = await h.redirectGrant(mtlsClient, OWNER);
  r = await mtlsClient.send("GET", h.RS,
                            { token: mtlsFlow.released.access_token.value });
  check("a certificate key proved by mutual TLS obtains a token and presents " +
        "it at the RS", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.method, "mtls");
  });
  r = await gnap.rawRequest("GET", h.RS,
                            { Authorization: "GNAP " +
                                             mtlsFlow.released.access_token.value });
  check("the same token on a connection with no client certificate is refused",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  const otherPair = forge.pki.rsa.generateKeyPair(2048);
  const otherCert = forge.pki.createCertificate();
  otherCert.publicKey = otherPair.publicKey;
  otherCert.serialNumber = "02" + nodeCrypto.randomBytes(8).toString("hex");
  otherCert.validity.notBefore = new Date(Date.now() - 60000);
  otherCert.validity.notAfter = new Date(Date.now() + 3600000);
  otherCert.setSubject([{ name: "commonName", value: "gnap-mtls-thief" }]);
  otherCert.setIssuer([{ name: "commonName", value: "gnap-mtls-thief" }]);
  otherCert.sign(otherPair.privateKey, forge.md.sha256.create());
  r = await gnap.rawRequest("GET", h.RS,
    { Authorization: "GNAP " + mtlsFlow.released.access_token.value },
    null, { cert: forge.pki.certificateToPem(otherCert),
            key: forge.pki.privateKeyToPem(otherPair.privateKey),
            rejectUnauthorized: false });
  check("…and on a connection presenting a DIFFERENT certificate", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await gnap.rawRequest("POST", h.GRANT,
                            { "Content-Type": "application/json" },
                            Buffer.from(JSON.stringify(
                                h.grantBody(mtlsClient))));
  check("a grant request naming a certificate key proved by mtls, on a " +
        "connection with no certificate, is invalid_client", function () {
    h.refused(r, "invalid_client", "an mtls key with no client certificate");
  });

  // =========================================================================
  // 7. THE RESOURCE SERVER DISCOVERY DOCUMENT FOLLOWS THE SETTINGS.
  // =========================================================================
  log.info("=== 7. discovery follows the settings ===");
  await h.setting("gnap.introspection", false);
  r = await gnap.rawRequest("GET", h.realmBase + "/.well-known/gnap-as-rs", {});
  const offDoc = r.json;
  r = await introspect(rsKey, issued.biscuit);
  check("with gnap.introspection off the document drops the endpoint and the " +
        "endpoint refuses", function () {
    assert.strictEqual(offDoc.introspection_endpoint, undefined,
                       JSON.stringify(offDoc));
    assert.strictEqual(r.status, 404, r.text);
  });
  await h.setting("gnap.introspection", true);
  await h.setting("gnap.resourceRegistration", false);
  r = await rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
    access: ["x"], resource_server: { key: rsKey.keyObject() } } });
  check("with gnap.resourceRegistration off registration answers 404",
        function () {
    assert.strictEqual(r.status, 404, r.text);
  });
  await h.setting("gnap.resourceRegistration", true);

  assert.ok(h.checks >= 100, "only " + h.checks + " checks ran; a section " +
                                                  "has stopped being called.");
  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_rs")
  .description("GNAP resource server connections (RFC 9767): the five token " +
    "formats verified by this file's own code, introspection active and " +
    "inactive, resource set registration, token derivation, revocation " +
    "reaching introspection, and a key proved by mutual TLS.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
