// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_jwt.js
//
// ===========================================================================
// A COMPACT JWS, VERIFIED AGAINST A PUBLISHED KEY SET (#586): what the
// RFC 9470 resource server checks an RFC 9068 access token with, and what the
// SSF receiver checks a Security Event Token with. Node's crypto; the keys
// come from the issuer's own published JWKS, fetched over TLS the peer
// verifies, cached, and fetched again once when a `kid` is not in the cache
// (a key the issuer rolled since).
// ===========================================================================

const nodeCrypto = require("crypto");
const util = require("./peer_util.js");

const log = util.logger("peer_jwt");

// The three parts of a compact JWS, decoded. Throws on anything else.
function decode(compact) {
  log.debug("Entering decode().");
  const parts = String(compact || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving decode(). Not three parts.");
    throw new Error("not a compact JWS (" + parts.length + " part(s))");
  }
  const out = {
    header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
    signingInput: parts[0] + "." + parts[1],
    signature: Buffer.from(parts[2], "base64url")
  };
  log.debug("Leaving decode().");
  return out;
}

// Whether `signature` over `data` verifies under the JWK for JWS `alg`.
// Shared with the GNAP role, whose proofs name JWS algorithms too.
function verifyBytes(alg, jwk, data, signature) {
  log.debug("Entering verifyBytes(). " + alg);
  const material = Object.assign({}, jwk);
  // node's JWK import wants the key members only.
  ["alg", "kid", "use", "key_ops", "x5c", "x5t", "x5t#S256"].forEach(
    function (name) {
      delete material[name];
    });
  const key = nodeCrypto.createPublicKey({ key: material, format: "jwk" });
  const bytes = Buffer.from(data);
  const m = /^(RS|PS|ES)(256|384|512)$/.exec(String(alg));
  let ok;
  if (alg === "EdDSA" || alg === "Ed25519") {
    ok = nodeCrypto.verify(null, bytes, key, signature);
  } else if (alg === "ES256K") {
    ok = nodeCrypto.verify("sha256", bytes,
                           { key: key, dsaEncoding: "ieee-p1363" },
                           signature);
  } else if (m && m[1] === "ES") {
    ok = nodeCrypto.verify("sha" + m[2], bytes,
                           { key: key, dsaEncoding: "ieee-p1363" },
                           signature);
  } else if (m && m[1] === "PS") {
    ok = nodeCrypto.verify("sha" + m[2], bytes, {
      key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  } else if (m && m[1] === "RS") {
    ok = nodeCrypto.verify("sha" + m[2], bytes, key, signature);
  } else {
    log.debug("Leaving verifyBytes(). Unsupported.");
    throw new Error("the algorithm " + alg + " is not one this peer " +
                    "verifies");
  }
  log.debug("Leaving verifyBytes(). " + ok);
  return ok;
}

// A key set, from `jwksUri`, cached on `cache` (an object the caller owns).
async function keysOf(cache, jwksUri, ca, fresh) {
  log.debug("Entering keysOf(). " + jwksUri);
  if (!fresh && cache[jwksUri]) {
    log.debug("Leaving keysOf(). Cached.");
    return cache[jwksUri];
  }
  const r = await util.outbound("GET", jwksUri, { ca: ca });
  if (r.status !== 200 || !r.json || !Array.isArray(r.json.keys)) {
    log.debug("Leaving keysOf(). " + r.status);
    throw new Error("the key set at " + jwksUri + " answered " + r.status);
  }
  cache[jwksUri] = r.json.keys;
  log.debug("Leaving keysOf(). " + r.json.keys.length);
  return r.json.keys;
}

// The key a header names: by `kid` when it has one, else every key of the
// algorithm's type. Re-fetches once on a miss.
async function verify(cache, jwksUri, ca, decoded) {
  log.debug("Entering verify().");
  const header = decoded.header;
  const kty = /^ES/.test(header.alg) ? "EC"
    : (header.alg === "EdDSA" ? "OKP" : "RSA");
  const pick = function (keys) {
    log.debug("Entering pick().");
    log.debug("Leaving pick().");
    return keys.filter(function (k) {
      return header.kid ? k.kid === header.kid : k.kty === kty;
    });
  };
  let candidates = pick(await keysOf(cache, jwksUri, ca, false));
  if (!candidates.length) {
    candidates = pick(await keysOf(cache, jwksUri, ca, true));
  }
  if (!candidates.length) {
    log.debug("Leaving verify(). No key.");
    return { ok: false, why: "no key in " + jwksUri + " has the kid " +
             header.kid };
  }
  let why = "the signature does not verify under " + candidates.length +
            " key(s) of " + jwksUri;
  for (const jwk of candidates) {
    try {
      if (verifyBytes(header.alg, jwk, decoded.signingInput,
                      decoded.signature)) {
        log.debug("Leaving verify(). Verified.");
        return { ok: true, why: "", kid: jwk.kid || null };
      }
    } catch (e) {
      log.debug("Caught in verify(): " + ((e && e.message) || e));
      // An unusable key or algorithm: the next candidate, and the reason
      // if none verifies.
      why = e.message;
    }
  }
  log.debug("Leaving verify(). Did not verify.");
  return { ok: false, why: why };
}

module.exports = { decode: decode, verify: verify, verifyBytes: verifyBytes };
