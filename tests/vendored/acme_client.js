"use strict";
//
// File: acme_client.js
//
// ===========================================================================
// AN ACME CLIENT WRITTEN FROM RFC 8555, RFC 9773 AND RFC 7638, WITH NOTHING
// FROM acme/ (2026-09-13).
//
// `tests/vendored/sts_acme_enrollment.js` and the in-process
// `tests/acme_protocol.js` drive the service's ACME server with this module,
// and the worth of both rests on it being a SECOND READING of the RFCs rather
// than the server's own envelope code called from a test: a JWS the server's
// codec builds and the server's codec accepts proves only that one
// implementation agrees with itself.
//
// So it requires nothing from `acme/`, `common/cert_enrollment.js` or any other
// server module. The JWS (flattened JSON serialization, RS256 / PS256 / ES256 /
// ES384 / EdDSA), the RFC 7638 thumbprint, the External Account Binding MAC,
// nonce handling with the one badNonce retry section 6.5 invites, the key
// change's nested JWS and RFC 9773's certificate identifier are written out
// here over node's own `crypto`. The PKCS#10 requests are built with the parent
// project's vendored `x509.js` and `key_material.js` — the independent PKI code
// `sts_user_credentials.js` builds its certificates with — and certificates are
// read with `pkijs`, a library, never the server's reader.
// ===========================================================================

const nodeCrypto = require("crypto");
const path = require("path");

let log = null;
try {
  log = require("bunyan").createLogger({ name: "acme_client",
    level: process.env.LOG_LEVEL || "info" });
} catch (e) {
  // No bunyan (a hand run outside the suite): a console-backed logger of the
  // same shape, so the Entering/Leaving lines still have somewhere to go.
  log = { debug: function () {}, info: console.log, warn: console.warn,
          error: console.error };
  log.debug("Caught loading bunyan: " + ((e && e.message) || e));
}

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");

function vendored(name) {
  log.debug("Entering vendored(). name=" + name);
  log.debug("Leaving vendored().");
  return require(path.join(REPO, "common", "vendored", name));
}

// ---------------------------------------------------------------------------
// BYTES.
// ---------------------------------------------------------------------------
function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString("base64url");
}

function b64uJson(value) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return b64u(Buffer.from(JSON.stringify(value), "utf8"));
}

function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  const match = /-----BEGIN [A-Z ]+-----([\s\S]*?)-----END [A-Z ]+-----/
    .exec(String(pem || ""));
  log.debug("Leaving pemToDer().");
  return match ? Buffer.from(match[1].replace(/\s+/g, ""), "base64") : null;
}

function splitPemChain(text) {
  log.debug("Entering splitPemChain().");
  const out = String(text || "").match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving splitPemChain(). " + out.length + ".");
  return out.map(function (one) { return one + "\n"; });
}

// ---------------------------------------------------------------------------
// ACCOUNT KEYS AND RFC 7638.
// ---------------------------------------------------------------------------
const MEMBERS = { RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"],
                  OKP: ["crv", "kty", "x"] };

function publicJwkOf(publicKey) {
  log.debug("Entering publicJwkOf().");
  const full = publicKey.export({ format: "jwk" });
  const out = {};
  (MEMBERS[full.kty] || []).forEach(function (name) {
    out[name] = full[name];
  });
  log.debug("Leaving publicJwkOf().");
  return out;
}

function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  const members = MEMBERS[jwk.kty];
  const canonical = "{" + members.map(function (name) {
    return JSON.stringify(name) + ":" + JSON.stringify(jwk[name]);
  }).join(",") + "}";
  log.debug("Leaving thumbprint().");
  return nodeCrypto.createHash("sha256").update(canonical, "utf8")
    .digest("base64url");
}

// alg is the JWS algorithm the key will sign with.
function generateAccountKey(alg, options) {
  log.debug("Entering generateAccountKey(). alg=" + alg);
  const opts = options || {};
  let pair = null;
  if (/^(RS|PS)/.test(alg)) {
    pair = nodeCrypto.generateKeyPairSync("rsa",
      { modulusLength: opts.bits || 2048 });
  } else if (alg === "ES256") {
    pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  } else if (alg === "ES384") {
    pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  } else if (alg === "EdDSA") {
    pair = nodeCrypto.generateKeyPairSync("ed25519");
  } else {
    log.debug("Leaving generateAccountKey(). Unknown.");
    throw new Error("acme_client: no key generator for " + alg);
  }
  const jwk = publicJwkOf(pair.publicKey);
  log.debug("Leaving generateAccountKey().");
  return { alg: alg, privateKey: pair.privateKey, publicKey: pair.publicKey,
           jwk: jwk, thumbprint: thumbprint(jwk) };
}

// An account key made from a key pair something else generated (a CSR's key,
// for revocation by the certificate key).
function accountKeyFromPem(alg, privatePem) {
  log.debug("Entering accountKeyFromPem().");
  const privateKey = nodeCrypto.createPrivateKey(privatePem);
  const publicKey = nodeCrypto.createPublicKey(privateKey);
  const jwk = publicJwkOf(publicKey);
  log.debug("Leaving accountKeyFromPem().");
  return { alg: alg, privateKey: privateKey, publicKey: publicKey, jwk: jwk,
           thumbprint: thumbprint(jwk) };
}

// ---------------------------------------------------------------------------
// THE FLATTENED JWS (RFC 7515 section 7.2.2), SIGNED HERE.
// ---------------------------------------------------------------------------
const HASH = { "256": "sha256", "384": "sha384", "512": "sha512" };

function signBytes(key, input) {
  log.debug("Entering signBytes(). alg=" + key.alg);
  const alg = key.alg;
  let signature = null;
  if (alg === "EdDSA") {
    signature = nodeCrypto.sign(null, input, key.privateKey);
  } else if (/^RS/.test(alg)) {
    signature = nodeCrypto.sign(HASH[alg.slice(2)], input, key.privateKey);
  } else if (/^PS/.test(alg)) {
    signature = nodeCrypto.sign(HASH[alg.slice(2)], input, {
      key: key.privateKey, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: Number(alg.slice(2)) / 8 });
  } else if (/^ES/.test(alg)) {
    signature = nodeCrypto.sign(HASH[alg.slice(2)], input,
      { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  } else {
    log.debug("Leaving signBytes(). Unknown.");
    throw new Error("acme_client: cannot sign " + alg);
  }
  log.debug("Leaving signBytes().");
  return signature;
}

// payload: an object (JSON), null (POST-as-GET, the empty string) or
// { raw: '<already base64url>' } for a test that needs exact bytes.
function flattened(key, header, payload) {
  log.debug("Entering flattened().");
  const protectedB64 = b64uJson(header);
  let payloadB64 = "";
  if (payload && payload.raw !== undefined) {
    payloadB64 = String(payload.raw);
  } else if (payload !== null && payload !== undefined) {
    payloadB64 = b64uJson(payload);
  }
  const signature = signBytes(key, Buffer.from(protectedB64 + "." +
                                               payloadB64, "ascii"));
  log.debug("Leaving flattened().");
  return { protected: protectedB64, payload: payloadB64,
           signature: b64u(signature) };
}

// RFC 8555 section 7.3.4: HS256 over the account's JWK.
function externalAccountBinding(eab, accountJwk, url) {
  log.debug("Entering externalAccountBinding().");
  const alg = eab.alg || "HS256";
  const header = Object.assign({ alg: alg, kid: eab.kid, url: url },
                               eab.extraHeader || {});
  const protectedB64 = b64uJson(header);
  const payloadB64 = b64uJson(eab.jwk || accountJwk);
  const mac = nodeCrypto.createHmac(HASH[alg.slice(2)],
                                    Buffer.from(eab.hmacKey, "base64url"))
    .update(protectedB64 + "." + payloadB64, "ascii").digest();
  log.debug("Leaving externalAccountBinding().");
  return { protected: protectedB64, payload: payloadB64, signature: b64u(mac) };
}

// ---------------------------------------------------------------------------
// THE CLIENT.
// ---------------------------------------------------------------------------
class AcmeClient {
  constructor(directoryUrl) {
    log.debug("Entering AcmeClient.constructor().");
    this.directoryUrl = directoryUrl;
    this.dir = null;
    this.nonce = null;
    this.badNonceRetries = 0;
    log.debug("Leaving AcmeClient.constructor().");
  }

  async directory() {
    log.debug("Entering AcmeClient.directory().");
    const r = await fetch(this.directoryUrl);
    const text = await r.text();
    this.remember(r);
    let body = null;
    try {
      body = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in AcmeClient.directory(): " + ((e && e.message) || e));
      body = null;
    }
    if (r.status === 200) {
      this.dir = body;
    }
    log.debug("Leaving AcmeClient.directory().");
    return { status: r.status, body: body, headers: r.headers };
  }

  remember(response) {
    log.debug("Entering AcmeClient.remember().");
    const nonce = response.headers.get("replay-nonce");
    if (nonce) {
      this.nonce = nonce;
    }
    log.debug("Leaving AcmeClient.remember().");
  }

  async freshNonce() {
    log.debug("Entering AcmeClient.freshNonce().");
    const r = await fetch(this.dir.newNonce, { method: "HEAD" });
    this.remember(r);
    log.debug("Leaving AcmeClient.freshNonce().");
    return r.headers.get("replay-nonce");
  }

  async takeNonce() {
    log.debug("Entering AcmeClient.takeNonce().");
    let nonce = this.nonce;
    this.nonce = null;
    if (!nonce) {
      nonce = await this.freshNonce();
      this.nonce = null;
    }
    log.debug("Leaving AcmeClient.takeNonce().");
    return nonce;
  }

  // One signed POST.
  //   opts.key           the signing key ({ alg, privateKey, jwk })
  //   opts.kid           the account URL, or
  //   opts.jwk           true to carry the key in the header
  //   opts.nonce         a nonce to use instead of taking one (no retry)
  //   opts.url           the header's url, when a test lies about it
  //   opts.header        extra protected-header members
  //   opts.contentType   instead of application/jose+json
  //   opts.body          a raw body string instead of the signed JWS
  //   opts.mutate        function(flattenedObject) -> object, before sending
  //   opts.noRetry       no badNonce retry
  async post(url, payload, opts) {
    log.debug("Entering AcmeClient.post(). url=" + url);
    const o = opts || {};
    const nonce = o.nonce !== undefined ? o.nonce : await this.takeNonce();
    const header = Object.assign({ alg: o.key ? o.key.alg : "RS256" },
                                 nonce === null ? {} : { nonce: nonce },
                                 { url: o.url || url });
    if (o.jwk) {
      header.jwk = o.key.jwk;
    }
    if (o.kid) {
      header.kid = o.kid;
    }
    Object.assign(header, o.header || {});
    let body = o.body;
    if (body === undefined) {
      let jws = flattened(o.key, header, payload);
      if (o.mutate) {
        jws = o.mutate(jws);
      }
      body = JSON.stringify(jws);
    }
    const r = await fetch(url, { method: "POST", body: body,
      headers: { "Content-Type": o.contentType || "application/jose+json" } });
    this.remember(r);
    const text = await r.text();
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in AcmeClient.post(): " + ((e && e.message) || e));
      parsed = null;
    }
    const out = { status: r.status, headers: r.headers, text: text,
                  body: parsed, location: r.headers.get("location"),
                  type: r.headers.get("content-type") || "" };
    if (r.status === 400 && parsed &&
        parsed.type === "urn:ietf:params:acme:error:badNonce" &&
        o.nonce === undefined && !o.noRetry) {
      // Section 6.5: the refusal carries a fresh nonce, and a client retries
      // once with it. A second badNonce is a real problem and is returned.
      this.badNonceRetries += 1;
      log.debug("Leaving AcmeClient.post(). Retrying after badNonce.");
      return this.post(url, payload, Object.assign({}, o, { noRetry: true }));
    }
    log.debug("Leaving AcmeClient.post(). status=" + r.status);
    return out;
  }

  // Section 7.3 and 7.3.4.
  async newAccount(key, eab, extra) {
    log.debug("Entering AcmeClient.newAccount().");
    const payload = Object.assign({ termsOfServiceAgreed: true },
                                  extra || {});
    if (eab) {
      payload.externalAccountBinding = externalAccountBinding(
        eab, key.jwk, eab.url || this.dir.newAccount);
    }
    const r = await this.post(this.dir.newAccount, payload,
                              { key: key, jwk: true });
    log.debug("Leaving AcmeClient.newAccount(). status=" + r.status);
    return r;
  }

  async postAsGet(url, key, kid, opts) {
    log.debug("Entering AcmeClient.postAsGet().");
    log.debug("Leaving AcmeClient.postAsGet().");
    return this.post(url, null, Object.assign({ key: key, kid: kid },
                                              opts || {}));
  }

  async newOrder(key, kid, identifiers, extra) {
    log.debug("Entering AcmeClient.newOrder().");
    log.debug("Leaving AcmeClient.newOrder().");
    return this.post(this.dir.newOrder,
                     Object.assign({ identifiers: identifiers }, extra || {}),
                     { key: key, kid: kid });
  }

  async finalize(key, kid, finalizeUrl, csrDer) {
    log.debug("Entering AcmeClient.finalize().");
    log.debug("Leaving AcmeClient.finalize().");
    return this.post(finalizeUrl, { csr: b64u(csrDer) },
                     { key: key, kid: kid });
  }

  // Section 7.6, by the account (kid) or by the certificate's key (jwk).
  async revoke(key, kid, certificateDer, reason) {
    log.debug("Entering AcmeClient.revoke().");
    const payload = { certificate: b64u(certificateDer) };
    if (reason !== undefined) {
      payload.reason = reason;
    }
    log.debug("Leaving AcmeClient.revoke().");
    return this.post(this.dir.revokeCert, payload,
                     kid ? { key: key, kid: kid } : { key: key, jwk: true });
  }

  // Section 7.3.5: the inner JWS signed by the NEW key, carried as the payload
  // of an outer JWS signed by the OLD one.
  async keyChange(oldKey, kid, newKey, overrides) {
    log.debug("Entering AcmeClient.keyChange().");
    const o = overrides || {};
    const innerHeader = Object.assign({ alg: newKey.alg, jwk: newKey.jwk,
                                        url: o.innerUrl || this.dir.keyChange },
                                      o.innerHeader || {});
    const inner = flattened(newKey, innerHeader, {
      account: o.account || kid, oldKey: o.oldKey || oldKey.jwk });
    log.debug("Leaving AcmeClient.keyChange().");
    return this.post(this.dir.keyChange, inner, { key: oldKey, kid: kid });
  }
}

// ---------------------------------------------------------------------------
// CERTIFICATES, READ WITH pkijs, AND RFC 9773's IDENTIFIER.
// ---------------------------------------------------------------------------
function readCertificate(pemOrDer) {
  log.debug("Entering readCertificate().");
  const asn1js = require("asn1js");
  const pkijs = require("pkijs");
  const der = Buffer.isBuffer(pemOrDer) ? pemOrDer : pemToDer(pemOrDer);
  const parsed = asn1js.fromBER(der.buffer.slice(der.byteOffset,
                                                 der.byteOffset +
                                                 der.byteLength));
  const cert = new pkijs.Certificate({ schema: parsed.result });
  let aki = null;
  const sans = [];
  (cert.extensions || []).forEach(function (extension) {
    if (extension.extnID === "2.5.29.35" && extension.parsedValue &&
        extension.parsedValue.keyIdentifier) {
      aki = Buffer.from(extension.parsedValue.keyIdentifier.valueBlock
                        .valueHexView);
    }
    if (extension.extnID === "2.5.29.17" && extension.parsedValue) {
      (extension.parsedValue.altNames || []).forEach(function (name) {
        if (name.type === 1 || name.type === 2 || name.type === 6) {
          sans.push({ type: name.type, value: String(name.value) });
        } else if (name.type === 7) {
          sans.push({ type: 7, value: Buffer.from(name.value.valueBlock
                                                  .valueHexView) });
        } else {
          sans.push({ type: name.type, value: name.value });
        }
      });
    }
  });
  log.debug("Leaving readCertificate().");
  return { der: der, cert: cert, aki: aki, sans: sans,
           serialBytes: Buffer.from(cert.serialNumber.valueBlock
                                    .valueHexView) };
}

// base64url(AKI keyIdentifier) "." base64url(serial INTEGER content octets).
function certIdOf(pem) {
  log.debug("Entering certIdOf().");
  const read = readCertificate(pem);
  log.debug("Leaving certIdOf().");
  return b64u(read.aki) + "." + b64u(read.serialBytes);
}

// The UPN otherName's UTF8String out of the certificate's DER, searched for
// after its OID so no general-name decoder of the server's is involved.
function upnOf(pem) {
  log.debug("Entering upnOf().");
  const der = Buffer.isBuffer(pem) ? pem : pemToDer(pem);
  // 1.3.6.1.4.1.311.20.2.3
  const oid = Buffer.from("060a2b060104018237140203", "hex");
  const at = der.indexOf(oid);
  if (at < 0) {
    log.debug("Leaving upnOf(). None.");
    return null;
  }
  // [0] EXPLICIT { UTF8String }: a0 len 0c len value
  let i = at + oid.length;
  if (der[i] !== 0xa0) {
    log.debug("Leaving upnOf(). Unexpected shape.");
    return null;
  }
  i += 2;
  if (der[i] !== 0x0c) {
    log.debug("Leaving upnOf(). Not a UTF8String.");
    return null;
  }
  const length = der[i + 1];
  log.debug("Leaving upnOf().");
  return der.slice(i + 2, i + 2 + length).toString("utf8");
}

// ---------------------------------------------------------------------------
// PKCS#10, WITH THE VENDORED ENCODER.
//   spec.keyAlg   a key_material id: rsa-2048, ec-p256, ed25519, …
//   spec.cn       the subject common name
//   spec.sans     [{ kind: 'dns'|'ip'|'email'|'uri'|'upn', value }]
// ---------------------------------------------------------------------------
async function buildCsr(spec) {
  log.debug("Entering buildCsr(). keyAlg=" + spec.keyAlg);
  const keys = vendored("key_material.js");
  const x509 = vendored("x509.js");
  const pair = await keys.generateKeyPair(spec.keyAlg || "ec-p256");
  const request = await x509.certificationRequest({
    subject: [{ name: "CN", value: spec.cn || "acme-client" }],
    publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem,
    subjectAltName: spec.sans || []
  });
  log.debug("Leaving buildCsr().");
  return { der: Buffer.from(request.der), privatePem: pair.privatePem,
           publicPem: pair.publicPem };
}

// A CSR whose signature no longer verifies: one bit of the signature flipped.
function corruptSignature(der) {
  log.debug("Entering corruptSignature().");
  const out = Buffer.from(der);
  out[out.length - 5] ^= 0x01;
  log.debug("Leaving corruptSignature().");
  return out;
}

// A CSR carrying an ML-KEM public key, which can make no proof of possession:
// a signed request whose SubjectPublicKeyInfo is swapped for the KEM key's. The
// signature is the original key's and does not matter — a server must refuse
// the KEY before it looks at the signature.
async function csrWithKemKey(spec) {
  log.debug("Entering csrWithKemKey().");
  const asn1js = require("asn1js");
  const pkijs = require("pkijs");
  const keys = vendored("key_material.js");
  const csr = await buildCsr(spec);
  const kem = await keys.generateKeyPair("ml-kem-768");
  const parsed = asn1js.fromBER(csr.der.buffer.slice(csr.der.byteOffset,
    csr.der.byteOffset + csr.der.byteLength));
  const request = new pkijs.CertificationRequest({ schema: parsed.result });
  const spki = pemToDer(kem.publicPem);
  request.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({
    schema: asn1js.fromBER(spki.buffer.slice(spki.byteOffset,
                                             spki.byteOffset +
                                             spki.byteLength)).result });
  const der = Buffer.from(request.toSchema(true).toBER(false));
  log.debug("Leaving csrWithKemKey().");
  return { der: der };
}

module.exports = {
  AcmeClient: AcmeClient,
  b64u: b64u,
  b64uJson: b64uJson,
  pemToDer: pemToDer,
  splitPemChain: splitPemChain,
  thumbprint: thumbprint,
  publicJwkOf: publicJwkOf,
  generateAccountKey: generateAccountKey,
  accountKeyFromPem: accountKeyFromPem,
  flattened: flattened,
  externalAccountBinding: externalAccountBinding,
  readCertificate: readCertificate,
  certIdOf: certIdOf,
  upnOf: upnOf,
  buildCsr: buildCsr,
  corruptSignature: corruptSignature,
  csrWithKemKey: csrWithKemKey
};
