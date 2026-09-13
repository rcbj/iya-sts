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

function b64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function sha(name, bytes) {
  return nodeCrypto.createHash(name).update(bytes).digest();
}

// RFC 8941 section 4.1.6: a String.
function sfString(value) {
  return "\"" + String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

// RFC 9530 section 2: `sha-256=:<base64>:`.
function contentDigest(body, alg) {
  const name = alg || "sha-256";
  const node = name === "sha-512" ? "sha512" : "sha256";
  return name + "=:" + sha(node, Buffer.from(body)).toString("base64") + ":";
}

// ---------------------------------------------------------------------------
// KEYS. A JWK private key with `alg` and `kid`, as RFC 9635 section 7.1 wants.
// ---------------------------------------------------------------------------
function newKey(alg, kid) {
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
  return { alg: alg, kid: publicJwk.kid, privateKey: pair.privateKey, publicKey: pair.publicKey,
           publicJwk: publicJwk };
}

// A shared secret for a key reference (section 7.1.1).
function secretKey(reference, secret, alg) {
  return { alg: alg || "HS256", kid: reference, secret: Buffer.from(secret), reference: reference };
}

// JWS algorithm -> the bytes of a signature (RFC 7518, and RFC 9421 section 3.3.7).
function signBytes(key, data) {
  const bytes = Buffer.from(data);
  const alg = key.alg;
  if (/^HS/.test(alg)) {
    return nodeCrypto.createHmac("sha" + alg.slice(2), key.secret).update(bytes).digest();
  }
  if (alg === "EdDSA") {
    return nodeCrypto.sign(null, bytes, key.privateKey);
  }
  const hash = "sha" + alg.slice(2);
  if (/^ES/.test(alg)) {
    return nodeCrypto.sign(hash, bytes, { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  }
  if (/^PS/.test(alg)) {
    return nodeCrypto.sign(hash, bytes, { key: key.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST });
  }
  return nodeCrypto.sign(hash, bytes, key.privateKey);
}

// ---------------------------------------------------------------------------
// RFC 9421: the signature base and the two header fields.
//
// `components` are identifier STRINGS as they appear in Signature-Input:
// `"@method"`, `"content-digest"`, `"signature";key="old"`.
// ---------------------------------------------------------------------------
function componentValue(identifier, message) {
  const match = identifier.match(/^"([^"]+)"(.*)$/);
  const name = match[1];
  const params = match[2];
  if (name === "@method") {
    return message.method.toUpperCase();
  }
  if (name === "@target-uri") {
    return message.url;
  }
  if (name === "@authority") {
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
    return members[wanted];
  }
  return String(header).trim();
}

// Split `a=(...);x=1, b=:...:` into members, respecting parentheses and quotes.
function splitDictionary(text) {
  const out = {};
  let depth = 0;
  let quoted = false;
  let start = 0;
  const push = function (piece) {
    const trimmed = piece.trim();
    const eq = trimmed.indexOf("=");
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
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
  return out;
}

function signatureParams(components, params) {
  let out = "(" + components.join(" ") + ")";
  ["created", "expires", "nonce", "keyid", "tag", "alg"].forEach(function (name) {
    if (params[name] === undefined) {
      return;
    }
    out += ";" + name + "=" + (typeof params[name] === "number" ? String(params[name])
                                                                 : sfString(params[name]));
  });
  return out;
}

function signatureBase(components, message, params) {
  const lines = components.map(function (identifier) {
    return identifier + ": " + componentValue(identifier, message);
  });
  const serialised = signatureParams(components, params);
  lines.push("\"@signature-params\": " + serialised);
  return { base: lines.join("\n"), serialised: serialised };
}

// Adds one signature to `message.headers`, appending to existing dictionaries.
function httpsign(message, key, opts) {
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
    created: options.created !== undefined ? options.created : Math.floor(Date.now() / 1000),
    nonce: options.nonce === null ? undefined : (options.nonce || b64u(nodeCrypto.randomBytes(9))),
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
  return { label: label, base: built.base };
}

// ---------------------------------------------------------------------------
// RFC 9635 sections 7.3.3 and 7.3.4: JWS proofs.
// ---------------------------------------------------------------------------
function jwsCompact(header, payloadBytes, key) {
  const h = b64u(Buffer.from(JSON.stringify(header)));
  const p = b64u(payloadBytes);
  const signature = signBytes(key, h + "." + p);
  return h + "." + p + "." + b64u(signature);
}

function jwsHeader(message, key, typ, token, created) {
  const header = { alg: key.alg, kid: key.kid, typ: typ, htm: message.method.toUpperCase(),
                   uri: message.url, created: created || Math.floor(Date.now() / 1000) };
  if (token) {
    header.ath = b64u(sha("sha256", Buffer.from(token, "ascii")));
  }
  return header;
}

// The detached JWS: payload = the SHA-256 digest of the content (the RFC's
// example form, whose middle segment is base64url(digest)), empty without one.
function jwsd(message, key, token, typ) {
  const body = message.body && message.body.length ? sha("sha256", message.body) : Buffer.alloc(0);
  return jwsCompact(jwsHeader(message, key, typ || "gnap-binding-jwsd", token), body, key);
}

// RFC 9635 section 4.2.3.
function interactionHash(clientNonce, serverNonce, interactRef, grantEndpoint, method) {
  const name = { "sha-256": "sha256", "sha-512": "sha512", "sha3-512": "sha3-512" }[method || "sha-256"];
  return b64u(sha(name, Buffer.from([clientNonce, serverNonce, interactRef, grantEndpoint].join("\n"),
                                    "ascii")));
}

// ---------------------------------------------------------------------------
// HTTP. `https.request` rather than fetch, because MTLS needs a client
// certificate on the connection and the proofs need the exact body bytes.
// ---------------------------------------------------------------------------
function rawRequest(method, url, headers, body, tlsOptions) {
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === "http:" ? http : https;
    const options = Object.assign({ method: method, hostname: u.hostname, port: u.port,
                                    path: u.pathname + u.search, headers: headers }, tlsOptions || {});
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
          // Not JSON: an HTML page or an empty 204. `text` carries it.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: text, json: json });
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
// A CLIENT INSTANCE. `proof` is httpsig | jwsd | jws | mtls. `send()` builds
// the message, proves the key, and returns the parsed response.
//
// `opts.mutate(message)` runs AFTER the proof, so a test can tamper with what
// was signed; `opts.sign` false sends no proof at all.
// ---------------------------------------------------------------------------
function Client(options) {
  this.key = options.key;
  this.proof = options.proof || "httpsig";
  this.tls = options.tls || null;
}

Client.prototype.keyObject = function () {
  if (this.key.reference) {
    return this.key.reference;
  }
  const out = { proof: this.proof };
  if (this.proof === "mtls" && this.tls && this.tls.certDer) {
    out.cert = this.tls.certDer.toString("base64");
  } else {
    out.jwk = this.key.publicJwk;
  }
  return out;
};

Client.prototype.send = async function (method, url, opts) {
  const options = opts || {};
  const headers = Object.assign({}, options.headers || {});
  let body = Buffer.alloc(0);
  if (options.json !== undefined) {
    body = Buffer.from(typeof options.json === "string" ? options.json : JSON.stringify(options.json));
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
        httpsign(message, options.rotateTo.key, { label: "new-key", tag: "gnap-rotate",
          extraComponents: ["\"signature\";key=\"sig1\"", "\"signature-input\";key=\"sig1\""] });
      }
    } else if (proof === "jwsd") {
      if (body.length) {
        headers["Content-Type"] = "application/json";
      }
      if (options.rotateTo) {
        const inner = jwsd(message, this.key, options.token, "gnap-binding-rotation-jwsd");
        headers["Detached-JWS"] = jwsCompact(jwsHeader(message, options.rotateTo.key,
          "gnap-binding-jwsd", options.token), Buffer.from(inner, "ascii"), options.rotateTo.key);
      } else {
        headers["Detached-JWS"] = jwsd(message, this.key, options.token, options.jwsTyp);
      }
    } else if (proof === "jws") {
      if (body.length) {
        const typ = options.rotateTo ? "gnap-binding-rotation-jws" : (options.jwsTyp || "gnap-binding-jws");
        let compact = jwsCompact(jwsHeader(message, this.key, typ, options.token), body, this.key);
        if (options.rotateTo) {
          compact = jwsCompact(jwsHeader(message, options.rotateTo.key, "gnap-binding-jws",
                                         options.token), Buffer.from(compact, "ascii"),
                               options.rotateTo.key);
        }
        body = Buffer.from(compact, "ascii");
        headers["Content-Type"] = "application/jose";
      } else {
        headers["Detached-JWS"] = jwsd(message, this.key, options.token, "gnap-binding-jws");
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
  return rawRequest(method, url, headers, body, proof === "mtls" ? this.tls : null);
};

module.exports = {
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
