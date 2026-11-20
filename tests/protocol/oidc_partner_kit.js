// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: oidc_partner_kit.js
//
// ===========================================================================
// A STAND-IN OPENID PROVIDER ON THE RUNNER, WHICH THE SERVICE DIALS AS A
// FEDERATION PARTNER (#444 D12, phase 7) — A HELPER, NOT A JOB.
//
// The in-process federation files (`federation_oidc_rp.js`,
// `federation_fapi_client.js`, `federation_signout.js`,
// `federation_consumer_providers.js`) each write a small OpenID Provider in
// their child process whose answers a case chooses. Over the wire the same
// partner runs in the JOB's process, on every interface, and the service
// reaches it at OUTBOUND_TEST_HOST (`test-peer` on a probe started with
// `--add-host test-peer:host-gateway`), in a DEVELOPMENT realm with
// `federation.outboundAllowHttp` on — a realm setting, so no process-wide
// switch is turned (and, for the https listener, the realm's
// `federation.outboundSkipTlsVerification`).
//
// `partner(K)` answers `{ op, base, tlsBase, mtlsBase, sign, jwk, close }`:
//   * `op.scenario` is what the next answers are made of (`issuer`, `base`,
//     `discovery`, `backClaims()`, `userinfo`, `tokenType`, `rt`, `demand`,
//     `parNonce`, `parNonceAlways`, `parRefuse`, `bindMtls`,
//     `webfingerIssuer`, `tokenRefuse`, `extraKeys`);
//   * `op.calls` lists every request (`path`, `body`, `auth`, `dpop`,
//     `cert`, `query`), cleared by the case that reads it;
//   * `op.byToken[rt]` answers a refresh of `rt` (`claims()`, `refuse`,
//     `tokenType`);
//   * `op.registered` / `op.registrations` record RFC 7591 registrations,
//     each answered a client_id `dyn-N` and a secret holding what
//     form-encoding changes (`dyn %+:<é/secret-N`).
// Every ID Token is RS256 under `kid` `opk-1`, the key served at
// `{base}jwks`; `sign(claims, header)` signs anything else a case needs.
//
// OWNED HERE (MANIFEST.js's LOCAL_HELPERS).
// ===========================================================================

const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const outboundCa = require("./outbound_test_ca.js");
const serviceTrust = require("../tools/service_trust.js");

const log = require("bunyan").createLogger({ name: "oidc_partner_kit",
  level: process.env.LOG_LEVEL || "info" });

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === "string" ? value
                                               : JSON.stringify(value))
    .toString("base64url");
}

// The left half of a SHA-256, base64url: c_hash, at_hash, s_hash.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const digest = nodeCrypto.createHash("sha256").update(String(value))
    .digest();
  log.debug("Leaving halfHash().");
  return digest.subarray(0, digest.length / 2).toString("base64url");
}

// A JWT's header and claims, unverified; null for anything else.
function jwtParts(token) {
  log.debug("Entering jwtParts().");
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving jwtParts(). Not three parts.");
    return null;
  }
  try {
    const out = {
      header: JSON.parse(Buffer.from(parts[0], "base64url").toString()),
      claims: JSON.parse(Buffer.from(parts[1], "base64url").toString())
    };
    log.debug("Leaving jwtParts().");
    return out;
  } catch (e) {
    log.debug("Caught in jwtParts(): " + ((e && e.message) || e));
    // Not a JWT the partner can read: answered as none, which every check
    // reading it treats as missing.
    log.debug("Leaving jwtParts(). Unreadable.");
    return null;
  }
}

async function partner(K, o) {
  log.debug("Entering partner().");
  const opts = o || {};
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = pair.publicKey.export({ format: "jwk" });
  jwk.kid = "opk-1";
  jwk.use = "sig";
  jwk.alg = "RS256";
  const op = { calls: [], scenario: {}, byToken: {}, bound: {}, jtis: [],
               sub: opts.sub || "opk-person",
               registrations: 0, registered: null };
  const sign = function (claims, header) {
    log.debug("Entering sign().");
    const input = b64u(Object.assign({ alg: "RS256", kid: "opk-1",
                                       typ: "JWT" }, header || {})) + "." +
                  b64u(claims);
    log.debug("Leaving sign().");
    return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                         pair.privateKey)
      .toString("base64url");
  };
  // The partner's one request handler, over plain http, TLS and mutual TLS.
  // No Entering/Leaving pair: the answer is made in the "end" callback, and
  // each request is in `op.calls`, which is the record a case reads.
  const handle = function (req, res) {
    let body = "";
    req.on("data", function (c) {
      body += c;
    });
    req.on("end", function () {
      const url = new URL(req.url, "http://x");
      const peer = req.socket &&
        typeof req.socket.getPeerCertificate === "function"
        ? req.socket.getPeerCertificate() : null;
      const cert = peer && peer.raw
        ? nodeCrypto.createHash("sha256").update(peer.raw)
            .digest("base64url") : "";
      op.calls.push({ path: url.pathname, query: url.search, body: body,
                      auth: String(req.headers.authorization || ""),
                      dpop: String(req.headers.dpop || ""), cert: cert,
                      headers: req.headers });
      const form = new URLSearchParams(body);
      ["client_assertion", "request"].forEach(function (name) {
        const sent = jwtParts(form.get(name));
        if (sent) {
          op.jtis.push({ path: url.pathname, kind: name,
                         jti: String(sent.claims.jti || "") });
        }
      });
      const s = op.scenario;
      const demand = s.demand;
      const proof = (jwtParts(req.headers.dpop) || { claims: {} }).claims;
      const proofNonce = String(proof.nonce || "");
      const sentRt = form.get("refresh_token");
      const asDemanded = demand &&
        (/\/par$/.test(url.pathname) ||
         (/\/token$/.test(url.pathname) &&
          (!sentRt || sentRt === demand.rt)));
      if (asDemanded && proofNonce !== demand.as) {
        res.writeHead(400, { "Content-Type": "application/json",
                             "DPoP-Nonce": demand.as });
        res.end(JSON.stringify({ error: "use_dpop_nonce" }));
        return;
      }
      const presentedAt = String(req.headers.authorization || "")
        .replace(/^(Bearer|DPoP) /, "");
      if (demand && /\/userinfo$/.test(url.pathname) &&
          (presentedAt === "at-back" ||
           presentedAt === "at-" + demand.rt) &&
          proofNonce !== demand.rs) {
        res.writeHead(401, {
          "WWW-Authenticate": "dPoP error=\"use_dpop_nonce\", " +
            "error_description=\"Resource server requires nonce in DPoP " +
            "proof\"",
          "DPoP-Nonce": demand.rs });
        res.end();
        return;
      }
      // A hot path for the same reason as `handle`'s.
      const send = function (status, json, type) {
        res.writeHead(status, { "Content-Type": type || "application/json",
                                "Cache-Control": "no-store" });
        res.end(typeof json === "string" ? json : JSON.stringify(json));
      };
      if (typeof opts.route === "function" &&
          opts.route(url, req, res, body, op)) {
        return;
      }
      if (/openid-configuration$/.test(url.pathname)) {
        const issuer = s.issuer || base;
        const at = s.base || base;
        send(200, Object.assign({ issuer: issuer,
          registration_endpoint: at + "register",
          authorization_endpoint: at + "disco-authorize",
          token_endpoint: at + "token", jwks_uri: at + "jwks",
          userinfo_endpoint: at + "userinfo" }, s.discovery || {}));
        return;
      }
      if (url.pathname === "/.well-known/webfinger") {
        op.webfinger = url.searchParams.get("resource");
        send(200, { subject: op.webfinger, links: [
          { rel: "http://openid.net/specs/connect/1.0/issuer",
            href: s.webfingerIssuer } ] });
        return;
      }
      if (/\/register$/.test(url.pathname)) {
        let asked = {};
        try {
          asked = JSON.parse(body || "{}");
        } catch (e) {
          log.debug("Caught in the partner's register: " +
                    ((e && e.message) || e));
          // A registration that is not JSON is recorded as empty; the case
          // reading it fails on what is missing.
          asked = {};
        }
        op.registered = asked;
        op.registrations += 1;
        send(201, Object.assign({}, asked,
          { client_id: "dyn-" + op.registrations,
            client_secret: "dyn %+:<é/secret-" + op.registrations }));
        return;
      }
      if (/\/jwks$/.test(url.pathname)) {
        send(200, { keys: [jwk].concat(s.extraKeys || []) });
        return;
      }
      if (/\/par$/.test(url.pathname)) {
        op.par = form;
        const posts = op.calls.filter(function (c) {
          return /\/par$/.test(c.path);
        }).length;
        if (s.parNonceAlways) {
          res.writeHead(400, { "Content-Type": "application/json",
                               "DPoP-Nonce": "n-again-" + posts });
          res.end(JSON.stringify({ error: "use_dpop_nonce" }));
          return;
        }
        if (s.parNonce && posts === 1) {
          res.writeHead(400, { "Content-Type": "application/json",
                               "DPoP-Nonce": String(s.parNonce) });
          res.end(JSON.stringify({ error: "use_dpop_nonce" }));
          return;
        }
        if (s.parRefuse) {
          send(400, { error: "invalid_request" });
          return;
        }
        send(200, { request_uri: (s.base || base) + "pushed",
                    expires_in: 90 });
        return;
      }
      if (/\/token$/.test(url.pathname)) {
        const boundType = req.headers.dpop ? "DPoP" : "Bearer";
        if (/grant_type=refresh_token/.test(body)) {
          const how = op.byToken[sentRt] || {};
          if (how.refuse) {
            send(400, { error: "invalid_grant" });
            return;
          }
          send(200, { access_token: "at-" + sentRt,
                      token_type: how.tokenType || boundType,
                      refresh_token: sentRt,
                      id_token: sign(how.claims()) });
          return;
        }
        let issued = "at-back";
        if (s.bindMtls && cert) {
          op.boundCount = (op.boundCount || 0) + 1;
          issued = "at-mtls-" + op.boundCount;
          op.bound[issued] = cert;
        }
        if (s.tokenRefuse) {
          send(400, { error: "invalid_grant" });
          return;
        }
        const answer = { access_token: issued,
                         token_type: s.tokenType || boundType,
                         refresh_token: s.rt || "rt-none",
                         expires_in: 300 };
        if (s.backClaims) {
          answer.id_token = sign(s.backClaims());
        }
        send(200, answer);
        return;
      }
      if (/\/userinfo$/.test(url.pathname)) {
        op.bearer = String(req.headers.authorization || "");
        const presented = op.bearer.replace(/^(Bearer|DPoP) /, "");
        if (op.bound[presented] !== undefined &&
            op.bound[presented] !== cert) {
          op.boundRefused = (op.boundRefused || 0) + 1;
          send(401, { error: "invalid_token" });
          return;
        }
        if (op.bound[presented] !== undefined) {
          op.boundAnswered = (op.boundAnswered || 0) + 1;
        }
        send(200, Object.assign({ sub: s.sub || op.sub },
                                s.userinfo || {}));
        return;
      }
      send(404, { error: "not_found" });
    });
  };
  const plain = http.createServer(handle);
  await new Promise(function (resolve) {
    plain.listen(0, "0.0.0.0", resolve);
  });
  const base = "http://" + K.HOST + ":" + plain.address().port + "/op/";
  // THE SAME PARTNER OVER TLS (WebFinger is https only) and over mutual TLS
  // (a FAPI 1.0 Advanced partner's token and UserInfo endpoints): a
  // self-signed certificate for the host the service dials, which the
  // realm's federation.outboundSkipTlsVerification lets through.
  const leaf = await outboundCa.selfSignedCertificate(K.HOST);
  const tls = https.createServer({ key: leaf.key, cert: leaf.cert }, handle);
  await new Promise(function (resolve) {
    tls.listen(0, "0.0.0.0", resolve);
  });
  // THE MUTUAL-TLS PARTNER VERIFIES THE CERTIFICATE IT IS SHOWN, as a FAPI
  // 1.0 Advanced authorization server does (RFC 8705 section 2): the
  // relationship's client certificate is issued under the service Root and
  // presented with its chain (federation_client_certificate.ts), so the
  // Root fetched from `/pki/ca/service/root.cer` is the whole truststore,
  // and a handshake without a certificate, or with anybody else's, is
  // refused before a request is read. Every case dialling `mtlsBase`
  // presents one (sts_federation_fapi_client.js).
  const mtls = https.createServer({ key: leaf.key, cert: leaf.cert,
    requestCert: true, ca: [await serviceTrust.serviceRoot(K.base)] },
    handle);
  await new Promise(function (resolve) {
    mtls.listen(0, "0.0.0.0", resolve);
  });
  log.debug("Leaving partner(). " + base);
  return {
    op: op, base: base, jwk: jwk, sign: sign,
    privateKey: pair.privateKey,
    tlsHost: K.HOST + ":" + tls.address().port,
    tlsBase: "https://" + K.HOST + ":" + tls.address().port + "/op/",
    mtlsBase: "https://" + K.HOST + ":" + mtls.address().port + "/op/",
    close: function () {
      log.debug("Entering close().");
      plain.close();
      tls.close();
      mtls.close();
      log.debug("Leaving close().");
    }
  };
}

module.exports = { partner: partner, b64u: b64u, halfHash: halfHash,
                   jwtParts: jwtParts };
