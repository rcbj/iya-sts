"use strict";
//
// File: gnap_client.js
//
// ---------------------------------------------------------------------------
// A GNAP CLIENT INSTANCE AND RESOURCE SERVER, WRITTEN FOR THE TESTS AND SHARING
// NO CODE WITH `gnap/`.
//
// The GNAP jobs assert what mock-sts does over the wire, and the one property
// that makes such a job worth running is that the two ends of the exchange are
// INDEPENDENT implementations: a signature base built by the same function on
// both sides verifies perfectly and interoperates with nobody
// (`tests/vendored/sts_dpop.js` makes this argument and writes its own DPoP
// client for it). So this file builds RFC 9421 signature bases, RFC 9530
// digests, RFC 8941 serialisations, detached and attached JWS proofs and the
// RFC 9635 section 4.2.3 interaction hash from the RFCs, with node's crypto and
// nothing from the service's tree. Its only requires are node built-ins.
//
// It is a LOCAL HELPER (tests/vendored/MANIFEST.js), owned here: there is no
// copy in the parent project to sync from.
// ---------------------------------------------------------------------------

const nodeCrypto = require("crypto");
const https = require("https");
const http = require("http");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'gnap_client',
  level: process.env.LOG_LEVEL || 'info' });

function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString("base64url");
}

function sha(name, bytes) {
  log.debug("Entering sha().");
  log.debug("Leaving sha().");
  return nodeCrypto.createHash(name).update(bytes).digest();
}

// RFC 8941 section 4.1.6: a String.
function sfString(value) {
  log.debug("Entering sfString().");
  log.debug("Leaving sfString().");
  return "\"" + String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") +
         "\"";
}

// RFC 9530 section 2: `sha-256=:<base64>:`.
function contentDigest(body, alg) {
  log.debug("Entering contentDigest().");
  const name = alg || "sha-256";
  const node = name === "sha-512" ? "sha512" : "sha256";
  log.debug("Leaving contentDigest().");
  return name + "=:" + sha(node, Buffer.from(body)).toString("base64") + ":";
}

// ---------------------------------------------------------------------------
// KEYS. A JWK private key with `alg` and `kid`, as RFC 9635 section 7.1 wants.
// ---------------------------------------------------------------------------
function newKey(alg, kid) {
  log.debug("Entering newKey().");
  let pair;
  if (alg === "ES256") {
    pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  } else if (alg === "ES384") {
    pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  } else if (alg === "EdDSA") {
    pair = nodeCrypto.generateKeyPairSync("ed25519");
  } else {
    pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  }
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  publicJwk.alg = alg;
  publicJwk.kid = kid || ("k-" + nodeCrypto.randomBytes(6).toString("hex"));
  log.debug("Leaving newKey().");
  return { alg: alg, kid: publicJwk.kid, privateKey: pair.privateKey,
           publicKey: pair.publicKey,
           publicJwk: publicJwk };
}

// A shared secret for a key reference (section 7.1.1).
function secretKey(reference, secret, alg) {
  log.debug("Entering secretKey().");
  log.debug("Leaving secretKey().");
  return { alg: alg || "HS256", kid: reference, secret: Buffer.from(secret),
           reference: reference };
}

// JWS algorithm -> the bytes of a signature (RFC 7518, and RFC 9421 section
// 3.3.7).
function signBytes(key, data) {
  log.debug("Entering signBytes().");
  const bytes = Buffer.from(data);
  const alg = key.alg;
  if (/^HS/.test(alg)) {
    log.debug("Leaving signBytes().");
    return nodeCrypto.createHmac("sha" + alg.slice(2), key.secret)
                     .update(bytes)
                     .digest();
  }
  if (alg === "EdDSA") {
    log.debug("Leaving signBytes().");
    return nodeCrypto.sign(null, bytes, key.privateKey);
  }
  const hash = "sha" + alg.slice(2);
  if (/^ES/.test(alg)) {
    log.debug("Leaving signBytes().");
    return nodeCrypto.sign(hash, bytes,
                           { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  }
  if (/^PS/.test(alg)) {
    log.debug("Leaving signBytes().");
    return nodeCrypto.sign(hash, bytes, { key: key.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST });
  }
  log.debug("Leaving signBytes().");
  return nodeCrypto.sign(hash, bytes, key.privateKey);
}

// ---------------------------------------------------------------------------
// RFC 9421: the signature base and the two header fields.
//
// `components` are identifier STRINGS as they appear in Signature-Input:
// `"@method"`, `"content-digest"`, `"signature";key="old"`.
// ---------------------------------------------------------------------------
function componentValue(identifier, message) {
  log.debug("Entering componentValue().");
  const match = identifier.match(/^"([^"]+)"(.*)$/);
  const name = match[1];
  const params = match[2];
  if (name === "@method") {
    log.debug("Leaving componentValue().");
    return message.method.toUpperCase();
  }
  if (name === "@target-uri") {
    log.debug("Leaving componentValue().");
    return message.url;
  }
  if (name === "@authority") {
    log.debug("Leaving componentValue().");
    return new URL(message.url).host.toLowerCase();
  }
  const header = message.headers[name] !== undefined ? message.headers[name]
    : message.headers[Object.keys(message.headers).filter(function (k) {
      return k.toLowerCase() === name;
    })[0]];
  const keyParam = params.match(/;key="([^"]+)"/);
  if (keyParam) {
    // A dictionary member, re-serialised (RFC 9421 section 2.1.2). The two
    // dictionaries this client ever covers by key are its own Signature and
    // Signature-Input, whose members it wrote as `label=value` separated by
    // ", " — so splitting on the label is exact for them.
    const wanted = keyParam[1];
    const members = splitDictionary(String(header));
    log.debug("Leaving componentValue().");
    return members[wanted];
  }
  log.debug("Leaving componentValue().");
  return String(header).trim();
}

// Split `a=(...);x=1, b=:...:` into members, respecting parentheses and quotes.
function splitDictionary(text) {
  log.debug("Entering splitDictionary().");
  const out = {};
  let depth = 0;
  let quoted = false;
  let start = 0;
  const push = function (piece) {
    log.debug("Entering push().");
    const trimmed = piece.trim();
    const eq = trimmed.indexOf("=");
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
    log.debug("Leaving push().");
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\"" && text[i - 1] !== "\\") {
      quoted = !quoted;
    } else if (!quoted && c === "(") {
      depth++;
    } else if (!quoted && c === ")") {
      depth--;
    } else if (!quoted && depth === 0 && c === ",") {
      push(text.slice(start, i));
      start = i + 1;
    }
  }
  push(text.slice(start));
  log.debug("Leaving splitDictionary().");
  return out;
}

function signatureParams(components, params) {
  log.debug("Entering signatureParams().");
  let out = "(" + components.join(" ") + ")";
  ["created", "expires", "nonce", "keyid", "tag", "alg"].forEach(
      function (name) {
    if (params[name] === undefined) {
      return;
    }
    out += ";" + name + "=" +
           (typeof params[name] === "number" ? String(params[name])
                                                                 : sfString(
                                                                     params[name]));
  });
  log.debug("Leaving signatureParams().");
  return out;
}

function signatureBase(components, message, params) {
  log.debug("Entering signatureBase().");
  const lines = components.map(function (identifier) {
    return identifier + ": " + componentValue(identifier, message);
  });
  const serialised = signatureParams(components, params);
  lines.push("\"@signature-params\": " + serialised);
  log.debug("Leaving signatureBase().");
  return { base: lines.join("\n"), serialised: serialised };
}

// Adds one signature to `message.headers`, appending to existing dictionaries.
function httpsign(message, key, opts) {
  log.debug("Entering httpsign().");
  const options = opts || {};
  const label = options.label || "sig1";
  const components = ["\"@method\"", "\"@target-uri\""];
  if (message.body && message.body.length) {
    components.push("\"content-digest\"");
  }
  if (message.headers.Authorization) {
    components.push("\"authorization\"");
  }
  (options.extraComponents || []).forEach(function (one) {
    components.push(one);
  });
  const params = {
    created: options.created !== undefined ? options.created :
             Math.floor(Date.now() / 1000),
    nonce: options.nonce === null ? undefined :
           (options.nonce || b64u(nodeCrypto.randomBytes(9))),
    keyid: options.keyid !== undefined ? options.keyid : key.kid,
    tag: options.tag === null ? undefined : (options.tag || "gnap")
  };
  if (options.alg) {
    params.alg = options.alg;
  }
  const built = signatureBase(components, message, params);
  const signature = signBytes(key, built.base);
  const input = label + "=" + built.serialised;
  const value = label + "=:" + signature.toString("base64") + ":";
  message.headers["Signature-Input"] = message.headers["Signature-Input"]
    ? message.headers["Signature-Input"] + ", " + input : input;
  message.headers.Signature = message.headers.Signature
    ? message.headers.Signature + ", " + value : value;
  log.debug("Leaving httpsign().");
  return { label: label, base: built.base };
}

// ---------------------------------------------------------------------------
// RFC 9635 sections 7.3.3 and 7.3.4: JWS proofs.
// ---------------------------------------------------------------------------
function jwsCompact(header, payloadBytes, key) {
  log.debug("Entering jwsCompact().");
  const h = b64u(Buffer.from(JSON.stringify(header)));
  const p = b64u(payloadBytes);
  const signature = signBytes(key, h + "." + p);
  log.debug("Leaving jwsCompact().");
  return h + "." + p + "." + b64u(signature);
}

function jwsHeader(message, key, typ, token, created) {
  log.debug("Entering jwsHeader().");
  const header = { alg: key.alg, kid: key.kid, typ: typ,
                   htm: message.method.toUpperCase(),
                   uri: message.url, created: created ||
                                              Math.floor(Date.now() / 1000) };
  if (token) {
    header.ath = b64u(sha("sha256", Buffer.from(token, "ascii")));
  }
  log.debug("Leaving jwsHeader().");
  return header;
}

// The detached JWS: payload = the SHA-256 digest of the content (the RFC's
// example form, whose middle segment is base64url(digest)), empty without one.
function jwsd(message, key, token, typ) {
  log.debug("Entering jwsd().");
  const body = message.body && message.body.length ?
               sha("sha256", message.body) : Buffer.alloc(0);
  log.debug("Leaving jwsd().");
  return jwsCompact(jwsHeader(message, key, typ || "gnap-binding-jwsd", token),
                    body, key);
}

// RFC 9635 section 4.2.3.
function interactionHash(clientNonce, serverNonce, interactRef, grantEndpoint,
                         method) {
  log.debug("Entering interactionHash().");
  const name = { "sha-256": "sha256", "sha-512": "sha512",
                 "sha3-512": "sha3-512" }[method || "sha-256"];
  log.debug("Leaving interactionHash().");
  return b64u(sha(name,
                  Buffer.from([clientNonce, serverNonce, interactRef,
                               grantEndpoint].join("\n"),
                                    "ascii")));
}

// ---------------------------------------------------------------------------
// HTTP. `https.request` rather than fetch, because MTLS needs a client
// certificate on the connection and the proofs need the exact body bytes.
// ---------------------------------------------------------------------------
function rawRequest(method, url, headers, body, tlsOptions) {
  log.debug("Entering rawRequest().");
  log.debug("Leaving rawRequest().");
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === "http:" ? http : https;
    const options = Object.assign({ method: method, hostname: u.hostname,
                                    port: u.port,
                                    path: u.pathname +
                                          u.search, headers: headers },
                                  tlsOptions || {});
    if (tlsOptions && (tlsOptions.cert || tlsOptions.key)) {
      options.agent = false;
    }
    const req = mod.request(options, function (res) {
      const chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch (e) {
          log.debug("Caught in a callback in rawRequest(): " +
                    ((e && e.message) || e));
          // Not JSON: an HTML page or an empty 204. `text` carries it.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  json: json });
      });
    });
    req.on("error", reject);
    if (body && body.length) {
      req.write(body);
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// A KEY IS PROVISIONED BEFORE IT IS FIRST PRESENTED (2026-09-18).
//
// In development mode this service registers a GNAP key the first time a
// request presents it by value; in PRODUCT mode an unregistered key is
// refused `invalid_client` (RFC 9635 section 2.3.3), which is what a real
// deployment does. So the harness installs a REGISTRAR — gnap_flow.js writes
// the key onto an application entry through /admin-api — and a client calls
// it once, before the first request that carries its own key by value (as
// `client.key` or, RFC 9767, `resource_server.key`). It runs in both modes:
// a job that worked only because the service made its clients up would be
// testing the making-up (sts_consent.js's argument).
// ---------------------------------------------------------------------------
let registrar = null;

function setRegistrar(fn) {
  log.debug("Entering setRegistrar().");
  registrar = fn;
  log.debug("Leaving setRegistrar().");
}

// The key object a request body carries by value, or null.
function presentedKey(json) {
  log.debug("Entering presentedKey().");
  if (!json || typeof json !== "object") {
    log.debug("Leaving presentedKey().");
    return null;
  }
  const holders = [json.client, json.resource_server];
  for (const holder of holders) {
    if (holder && typeof holder === "object" && holder.key &&
        typeof holder.key === "object") {
      log.debug("Leaving presentedKey(). Found.");
      return holder.key;
    }
  }
  log.debug("Leaving presentedKey().");
  return null;
}

// ---------------------------------------------------------------------------
// A CLIENT INSTANCE. `proof` is httpsig | jwsd | jws | mtls. `send()` builds
// the message, proves the key, and returns the parsed response.
//
// `opts.mutate(message)` runs AFTER the proof, so a test can tamper with what
// was signed; `opts.sign` false sends no proof at all.
// ---------------------------------------------------------------------------
function Client(options) {
  log.debug("Entering Client().");
  this.key = options.key;
  this.proof = options.proof || "httpsig";
  this.tls = options.tls || null;
  log.debug("Leaving Client().");
}

Client.prototype.keyObject = function () {
  log.debug("Entering keyObject().");
  if (this.key.reference) {
    log.debug("Leaving keyObject().");
    return this.key.reference;
  }
  const out = { proof: this.proof };
  if (this.proof === "mtls" && this.tls && this.tls.certDer) {
    out.cert = this.tls.certDer.toString("base64");
  } else {
    out.jwk = this.key.publicJwk;
  }
  log.debug("Leaving keyObject().");
  return out;
};

Client.prototype.send = async function (method, url, opts) {
  log.debug("Entering send().");
  const options = opts || {};
  if (registrar && !this.registered && options.provision !== false &&
      String(method).toUpperCase() === "POST" &&
      presentedKey(options.json)) {
    // Marked first, so a registrar that itself sends cannot recurse.
    this.registered = true;
    await registrar(this, url, presentedKey(options.json));
  }
  const headers = Object.assign({}, options.headers || {});
  let body = Buffer.alloc(0);
  if (options.json !== undefined) {
    body = Buffer.from(typeof options.json === "string" ? options.json :
                       JSON.stringify(options.json));
  }
  const message = { method: method, url: url, headers: headers, body: body };
  if (options.token) {
    headers.Authorization = (options.scheme || "GNAP") + " " + options.token;
  }
  const proof = options.proof || this.proof;
  if (options.sign !== false) {
    if (proof === "httpsig") {
      if (body.length) {
        headers["Content-Type"] = "application/json";
        headers["Content-Digest"] = contentDigest(body, options.digestAlg);
      }
      httpsign(message, this.key, options.httpsig || {});
      if (options.rotateTo) {
        // Section 7.3.1.1: the new key signs over the old signature.
        httpsign(message, options.rotateTo.key,
                 { label: "new-key", tag: "gnap-rotate",
          extraComponents: ["\"signature\";key=\"sig1\"",
                            "\"signature-input\";key=\"sig1\""] });
      }
    } else if (proof === "jwsd") {
      if (body.length) {
        headers["Content-Type"] = "application/json";
      }
      if (options.rotateTo) {
        const inner = jwsd(message, this.key, options.token,
                           "gnap-binding-rotation-jwsd");
        headers["Detached-JWS"] = jwsCompact(jwsHeader(message,
          options.rotateTo.key,
          "gnap-binding-jwsd", options.token), Buffer.from(inner,
                                                           "ascii"),
                                             options.rotateTo.key);
      } else {
        headers["Detached-JWS"] = jwsd(message, this.key, options.token,
                                       options.jwsTyp);
      }
    } else if (proof === "jws") {
      if (body.length) {
        const typ = options.rotateTo ? "gnap-binding-rotation-jws" :
                    (options.jwsTyp || "gnap-binding-jws");
        let compact = jwsCompact(jwsHeader(message, this.key, typ,
                                           options.token), body, this.key);
        if (options.rotateTo) {
          compact = jwsCompact(jwsHeader(message, options.rotateTo.key,
                                         "gnap-binding-jws",
                                         options.token), Buffer.from(compact,
                                                                     "ascii"),
                               options.rotateTo.key);
        }
        body = Buffer.from(compact, "ascii");
        headers["Content-Type"] = "application/jose";
      } else {
        headers["Detached-JWS"] = jwsd(message, this.key, options.token,
                                       "gnap-binding-jws");
      }
    }
  } else if (body.length) {
    headers["Content-Type"] = "application/json";
  }
  if (options.mutate) {
    const mutated = options.mutate({ headers: headers, body: body });
    if (mutated && mutated.body) {
      body = mutated.body;
    }
  }
  if (body.length) {
    headers["Content-Length"] = String(body.length);
  }
  log.debug("Leaving send().");
  return rawRequest(method, url, headers, body,
                    proof === "mtls" ? this.tls : null);
};

module.exports = {
  setRegistrar: setRegistrar,
  b64u: b64u,
  sha: sha,
  sfString: sfString,
  contentDigest: contentDigest,
  newKey: newKey,
  secretKey: secretKey,
  signBytes: signBytes,
  signatureBase: signatureBase,
  httpsign: httpsign,
  jwsCompact: jwsCompact,
  jwsd: jwsd,
  interactionHash: interactionHash,
  rawRequest: rawRequest,
  Client: Client
};
