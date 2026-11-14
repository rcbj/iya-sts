// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_gnap.js
//
// ===========================================================================
// A GNAP RESOURCE SERVER (RFC 9635 section 7, RFC 9767) (#586), in place of
// the service's demonstration resource server at `/gnap/rs/resource` and
// `/gnap/rs/spend`, which #593 deleted.
//
//   GET  /t/{tenant}/gnap/resource   needs `read` on the tenant's type
//   POST /t/{tenant}/gnap/resource   needs `write`
//   POST /t/{tenant}/gnap/spend      needs `spend`, and is held to the
//                                    right's limits
//
// **IT KNOWS NOTHING THE SERVICE DID NOT TELL IT OVER RFC 9767.** Each tenant
// has a key of its own (ES256, made when the tenant is configured), which a
// job registers on a GNAP resource-server application (`gnapKey`, with this
// tenant's `gnapResourceServerUri`) and declares the tenant's access type on
// (`set-access-type`) — so a right of that type naming no location is
// audienced to this resource server, which is how the service addresses a
// token to an API it catalogues. Every presented token is then INTROSPECTED
// at the realm's `/gnap/introspect` (section 3.3), signed by that key; the
// answer says whether it is active, its access, its key and proofing method,
// its format and the grant its limits count against. Nothing is decoded
// locally: four of the five formats are opaque to a resource server
// without the AS's keys, and introspection is the one path that works for
// all of them.
//
// **THE KEY PROOF IS CHECKED HERE, AGAINST THE KEY INTROSPECTION NAMES**
// (section 7.2): an HTTP message signature (RFC 9421, with the RFC 9530
// digest), a detached or attached JWS (sections 7.3.3, 7.3.4), or the
// client certificate on a mutual-TLS connection (7.3.2) — which the peer's
// TLS listener asks for and does not require. A bearer token (`flags`
// carrying `bearer`) is accepted with the Bearer scheme and no proof, and
// refused with the GNAP scheme; a bound one the other way round.
//
// **THE LIMITS (#432 phase 5) ARE KEPT HERE**, per grant and right, as a
// resource server keeps them (rcbj's decision 2 on #432): `amount` (a
// decimal string), `currency`, `count` and `receiver`. A right whose limits
// name an `interval` or a `window` is REFUSED rather than counted wrongly —
// the peer does not keep periods. A failed operation (`simulateFailure`) is
// refunded, which is the service's reference behaviour.
// ===========================================================================

const nodeCrypto = require("crypto");
const util = require("./peer_util.js");
const jwt = require("./peer_jwt.js");

const log = util.logger("peer_gnap");

const DEFAULT_TYPE = "urn:iya-sts:test-peer:resource";
const ACTIONS = ["read", "write", "delete", "spend"];
const FRESH_S = 300;
// Six decimal places: enough for any currency's minor unit.
const SCALE = 1000000n;

// ---------------------------------------------------------------------------
// THE TENANT'S KEY, and its key object as a request carries it by value.
// ---------------------------------------------------------------------------
function makeKey() {
  log.debug("Entering makeKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  publicJwk.alg = "ES256";
  publicJwk.kid = "peer-rs-" + nodeCrypto.randomBytes(6).toString("hex");
  log.debug("Leaving makeKey().");
  return { alg: "ES256", kid: publicJwk.kid, privateKey: pair.privateKey,
           publicJwk: publicJwk,
           keyObject: { proof: "httpsig", jwk: publicJwk } };
}

// RFC 7638: the members a key type requires, in lexicographic order.
function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  const members = { EC: ["crv", "kty", "x", "y"], RSA: ["e", "kty", "n"],
                    OKP: ["crv", "kty", "x"] }[jwk.kty] || [];
  const canonical = {};
  members.forEach(function (name) {
    canonical[name] = jwk[name];
  });
  log.debug("Leaving thumbprint().");
  return util.b64u(util.sha("sha256",
                            Buffer.from(JSON.stringify(canonical))));
}

// ---------------------------------------------------------------------------
// RFC 9421 AND RFC 9530, both directions.
// ---------------------------------------------------------------------------
function contentDigest(body) {
  log.debug("Entering contentDigest().");
  log.debug("Leaving contentDigest().");
  return "sha-256=:" + util.sha("sha256", body).toString("base64") + ":";
}

// A structured-field dictionary split into its members, respecting
// parentheses and quoted strings (RFC 8941 section 3.2).
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
    if (eq > 0) {
      out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
    }
    log.debug("Leaving push().");
  };
  const s = String(text || "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\"" && s[i - 1] !== "\\") {
      quoted = !quoted;
    } else if (!quoted && c === "(") {
      depth++;
    } else if (!quoted && c === ")") {
      depth--;
    } else if (!quoted && depth === 0 && c === ",") {
      push(s.slice(start, i));
      start = i + 1;
    }
  }
  push(s.slice(start));
  log.debug("Leaving splitDictionary().");
  return out;
}

function signBytes(key, data) {
  log.debug("Entering signBytes().");
  log.debug("Leaving signBytes().");
  return nodeCrypto.sign("sha256", Buffer.from(data),
                         { key: key.privateKey, dsaEncoding: "ieee-p1363" });
}

// The peer's own signature on a request it sends the authorization server:
// @method, @target-uri and the content digest, tagged `gnap`.
function signRequest(key, method, url, headers, body) {
  log.debug("Entering signRequest(). " + method + " " + url);
  headers["Content-Digest"] = contentDigest(body);
  const params = "(\"@method\" \"@target-uri\" \"content-digest\")" +
    ";created=" + Math.floor(Date.now() / 1000) +
    ";nonce=\"" + util.b64u(nodeCrypto.randomBytes(9)) + "\"" +
    ";keyid=\"" + key.kid + "\";tag=\"gnap\"";
  const base = "\"@method\": " + method.toUpperCase() + "\n" +
               "\"@target-uri\": " + url + "\n" +
               "\"content-digest\": " + headers["Content-Digest"] + "\n" +
               "\"@signature-params\": " + params;
  headers["Signature-Input"] = "sig1=" + params;
  headers.Signature = "sig1=:" + signBytes(key, base).toString("base64") +
                      ":";
  log.debug("Leaving signRequest().");
}

// A JSON request to the authorization server, signed by the tenant's key.
async function asCall(tenant, url, json) {
  log.debug("Entering asCall(). " + url);
  const body = Buffer.from(JSON.stringify(json));
  const headers = { "Content-Type": "application/json" };
  signRequest(tenant.gnap.key, "POST", url, headers, body);
  const r = await util.outbound("POST", url, { ca: tenant.serviceCaPem,
                                               headers: headers,
                                               body: body });
  log.debug("Leaving asCall(). " + r.status);
  return r;
}

// The value of one covered component of an incoming request.
function componentOf(name, request) {
  log.debug("Entering componentOf(). " + name);
  if (name === "@method") {
    log.debug("Leaving componentOf().");
    return request.method.toUpperCase();
  }
  if (name === "@target-uri") {
    log.debug("Leaving componentOf().");
    return request.targetUri;
  }
  if (name === "@authority") {
    log.debug("Leaving componentOf().");
    return new URL(request.targetUri).host.toLowerCase();
  }
  const value = request.headers[name];
  log.debug("Leaving componentOf().");
  return value === undefined ? null : String(value).trim();
}

// `''` when the request's HTTP message signature verifies under `jwk`,
// covering what section 7.3.1 requires; else why not.
function httpsigProblem(tenant, request, jwk) {
  log.debug("Entering httpsigProblem().");
  const inputs = splitDictionary(request.headers["signature-input"]);
  const values = splitDictionary(request.headers.signature);
  const labels = Object.keys(inputs);
  const label = labels.filter(function (one) {
    return /;tag="gnap"/.test(inputs[one]);
  })[0] || labels[0];
  if (!label || !values[label]) {
    log.debug("Leaving httpsigProblem(). Unsigned.");
    return "there is no HTTP message signature";
  }
  const inner = inputs[label];
  const list = /^\(([^)]*)\)/.exec(inner);
  const components = list
    ? (list[1].match(/"[^"]*"/g) || []).map(function (one) {
      return one.slice(1, -1);
    }) : [];
  const needed = ["@method", "@target-uri"];
  if (request.headers.authorization) {
    needed.push("authorization");
  }
  if (request.body.length) {
    needed.push("content-digest");
  }
  const missing = needed.filter(function (one) {
    return components.indexOf(one) < 0;
  });
  if (missing.length) {
    log.debug("Leaving httpsigProblem(). Uncovered.");
    return "the signature does not cover " + missing.join(", ") +
           " (RFC 9635 section 7.3.1)";
  }
  if (request.body.length &&
      request.headers["content-digest"] !== contentDigest(request.body)) {
    const sha512 = "sha-512=:" + util.sha("sha512", request.body)
      .toString("base64") + ":";
    if (request.headers["content-digest"] !== sha512) {
      log.debug("Leaving httpsigProblem(). Digest.");
      return "the Content-Digest does not match the body";
    }
  }
  const created = Number((/;created=(\d+)/.exec(inner) || [])[1]);
  const now = Math.floor(Date.now() / 1000);
  if (!created || Math.abs(now - created) > FRESH_S) {
    log.debug("Leaving httpsigProblem(). Stale.");
    return "the signature's created time is missing or not fresh";
  }
  const nonce = (/;nonce="([^"]*)"/.exec(inner) || [])[1];
  if (nonce) {
    if (tenant.gnap.nonces.has(nonce)) {
      log.debug("Leaving httpsigProblem(). Replayed.");
      return "the signature's nonce was used before";
    }
    tenant.gnap.nonces.add(nonce);
    if (tenant.gnap.nonces.size > 5000) {
      tenant.gnap.nonces.delete(tenant.gnap.nonces.values().next().value);
    }
  }
  const lines = [];
  for (const name of components) {
    const value = componentOf(name, request);
    if (value === null) {
      log.debug("Leaving httpsigProblem(). Absent component.");
      return "the covered component " + name + " is not in the request";
    }
    lines.push("\"" + name + "\": " + value);
  }
  lines.push("\"@signature-params\": " + inner);
  const signature = Buffer.from(values[label].replace(/^:|:$/g, ""),
                                "base64");
  let ok = false;
  try {
    ok = jwt.verifyBytes(jwk.alg || "ES256", jwk, lines.join("\n"),
                         signature);
  } catch (e) {
    log.debug("Caught in httpsigProblem(): " + ((e && e.message) || e));
    // An unusable key or algorithm is a signature that does not verify.
    ok = false;
  }
  log.debug("Leaving httpsigProblem(). ok=" + ok);
  return ok ? "" : "the HTTP message signature does not verify under the " +
                   "token's key";
}

// `''` when a JWS proof (detached, or attached as the body) verifies under
// `jwk`; else why not. Answers the body a JWS carried in `out.payload`.
function jwsProblem(request, jwk, token, attached, out) {
  log.debug("Entering jwsProblem(). attached=" + attached);
  const compact = attached ? request.body.toString("utf8")
                           : String(request.headers["detached-jws"] || "");
  const parts = compact.split(".");
  if (parts.length !== 3) {
    log.debug("Leaving jwsProblem(). Absent.");
    return attached ? "the body is not a compact JWS"
                    : "there is no Detached-JWS header";
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch (e) {
    log.debug("Caught in jwsProblem(): " + ((e && e.message) || e));
    // A header that is not JSON is not a proof.
    log.debug("Leaving jwsProblem(). Unreadable header.");
    return "the JWS header is not JSON";
  }
  if (!/^gnap-binding-jwsd?$/.test(String(header.typ || ""))) {
    log.debug("Leaving jwsProblem(). typ.");
    return "the JWS typ is " + header.typ;
  }
  if (String(header.htm || "").toUpperCase() !==
      request.method.toUpperCase() || header.uri !== request.targetUri) {
    log.debug("Leaving jwsProblem(). htm/uri.");
    return "the JWS names " + header.htm + " " + header.uri + ", not this " +
           "request";
  }
  if (token && header.ath !== util.b64u(util.sha("sha256",
                                                 Buffer.from(token)))) {
    log.debug("Leaving jwsProblem(). ath.");
    return "the JWS ath is not the hash of the presented token";
  }
  const now = Math.floor(Date.now() / 1000);
  if (!header.created || Math.abs(now - Number(header.created)) > FRESH_S) {
    log.debug("Leaving jwsProblem(). Stale.");
    return "the JWS created time is missing or not fresh";
  }
  if (!attached) {
    const expected = request.body.length
      ? util.b64u(util.sha("sha256", request.body)) : "";
    if (parts[1] !== expected) {
      log.debug("Leaving jwsProblem(). Payload.");
      return "the detached JWS payload is not the hash of the body";
    }
  } else {
    out.payload = Buffer.from(parts[1], "base64url");
  }
  let ok = false;
  try {
    ok = jwt.verifyBytes(header.alg, jwk, parts[0] + "." + parts[1],
                         Buffer.from(parts[2], "base64url"));
  } catch (e) {
    log.debug("Caught in jwsProblem(): " + ((e && e.message) || e));
    // An unusable key or algorithm is a proof that does not verify.
    ok = false;
  }
  log.debug("Leaving jwsProblem(). ok=" + ok);
  return ok ? "" : "the JWS does not verify under the token's key";
}

// `''` when the connection presented the certificate the token's key names.
function mtlsProblem(request, key) {
  log.debug("Entering mtlsProblem().");
  const presented = request.peerCertificate;
  if (!presented) {
    log.debug("Leaving mtlsProblem(). None.");
    return "the connection presented no client certificate";
  }
  const wanted = String(key.cert || "")
    .replace(/-----[^-]+-----|\s+/g, "");
  log.debug("Leaving mtlsProblem().");
  return presented.toString("base64") === wanted ? ""
    : "the connection's client certificate is not the token's";
}

// ---------------------------------------------------------------------------
// DECIMALS, for the limits: a non-negative decimal string (or number) as a
// BigInt of millionths, and back.
// ---------------------------------------------------------------------------
function toUnits(value) {
  log.debug("Entering toUnits().");
  const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(String(value).trim());
  if (!m) {
    log.debug("Leaving toUnits(). Not a decimal.");
    return null;
  }
  const fraction = (m[2] || "").padEnd(6, "0");
  log.debug("Leaving toUnits().");
  return BigInt(m[1]) * SCALE + BigInt(fraction);
}

function fromUnits(units) {
  log.debug("Entering fromUnits().");
  const whole = units / SCALE;
  const fraction = (units % SCALE).toString().padStart(6, "0")
    .replace(/0+$/, "");
  log.debug("Leaving fromUnits().");
  return whole.toString() + (fraction ? "." + fraction : "");
}

// ---------------------------------------------------------------------------
// THE RESOURCE SERVER.
// ---------------------------------------------------------------------------

// The access string the RS-first challenge offers (section 9.1): a resource
// set registered at the realm's `/gnap/resource` (RFC 9767 section 3.4) for
// every action of the tenant's type, made once — or, where registration is
// refused, the type itself.
async function referenceOf(tenant) {
  log.debug("Entering referenceOf().");
  if (tenant.gnap.reference !== undefined) {
    log.debug("Leaving referenceOf(). Cached.");
    return tenant.gnap.reference || tenant.gnap.type;
  }
  tenant.gnap.reference = "";
  try {
    const r = await asCall(tenant, tenant.gnap.registrationEndpoint, {
      access: [{ type: tenant.gnap.type, actions: ACTIONS }],
      resource_server: { key: tenant.gnap.key.keyObject } });
    if (r.status === 200 && r.json && r.json.resource_reference) {
      tenant.gnap.reference = r.json.resource_reference;
    } else {
      log.info("peer: resource registration answered " + r.status + " " +
               r.text.slice(0, 300) + "; the challenge offers the type");
    }
  } catch (e) {
    log.debug("Caught in referenceOf(): " + ((e && e.message) || e));
    // The challenge still works with the type; said, and carried on.
    log.info("peer: resource registration failed: " + e.message);
  }
  log.debug("Leaving referenceOf().");
  return tenant.gnap.reference || tenant.gnap.type;
}

async function challengeOf(tenant, request, error) {
  log.debug("Entering challengeOf().");
  const access = await referenceOf(tenant);
  log.debug("Leaving challengeOf().");
  return "GNAP as_uri=\"" + tenant.gnap.grantEndpoint + "\", access=\"" +
    access + "\", referrer=\"" + request.targetUri.split("?")[0] + "\"" +
    (error ? ", error=\"" + error + "\"" : "");
}

// A refusal, recorded. With no `extra` at all it is the RS-FIRST challenge
// of section 9.1 — no token was presented, so there is no error to name in
// WWW-Authenticate; every other refusal names its error there.
async function refuse(tenant, request, status, error, why, extra) {
  log.debug("Entering refuse(). " + status + " " + error);
  tenant.record("gnap", Object.assign({ ok: false, path: request.path,
                                        status: status, error: error,
                                        why: why }, extra || {}));
  const challenge = await challengeOf(tenant, request,
                                      extra === undefined ? null : error);
  log.debug("Leaving refuse().");
  return { status: status, headers: { "WWW-Authenticate": challenge },
           body: Object.assign({ error: error, error_description: why },
                               (extra && extra.refunded !== undefined)
                                 ? { refunded: extra.refunded } : {}) };
}

// Whether `rights` grant `action` on the tenant's type.
function covering(tenant, rights, action) {
  log.debug("Entering covering(). " + action);
  const out = (rights || []).filter(function (right) {
    if (typeof right === "string") {
      return right === tenant.gnap.reference;
    }
    return right && right.type === tenant.gnap.type &&
      (!Array.isArray(right.actions) || right.actions.indexOf(action) >= 0);
  });
  log.debug("Leaving covering(). " + out.length);
  return out;
}

// The token, introspected and its proof checked. `{ ok, … }` or a refusal
// to hand back as is.
async function judge(tenant, request) {
  log.debug("Entering judge().");
  const m = /^(GNAP|Bearer)\s+(\S+)$/i.exec(
    String(request.headers.authorization || "").trim());
  if (!m) {
    log.debug("Leaving judge(). No token.");
    return { refusal: await refuse(tenant, request, 401, "invalid_token",
      "This resource needs a GNAP access token; ask the authorization " +
      "server named in WWW-Authenticate.") };
  }
  const scheme = m[1].toLowerCase() === "gnap" ? "GNAP" : "Bearer";
  const token = m[2];
  const r = await asCall(tenant, tenant.gnap.introspectionEndpoint, {
    access_token: token,
    resource_server: { key: tenant.gnap.key.keyObject } });
  if (r.status !== 200 || !r.json) {
    log.debug("Leaving judge(). Introspection failed.");
    return { refusal: await refuse(tenant, request, 401, "invalid_token",
      "introspection at " + tenant.gnap.introspectionEndpoint +
      " answered " + r.status + " " + r.text.slice(0, 300), {}) };
  }
  const intro = r.json;
  if (intro.active !== true) {
    log.debug("Leaving judge(). Inactive.");
    return { refusal: await refuse(tenant, request, 401, "invalid_token",
      "the authorization server says the token is not active for this " +
      "resource server", { active: false }) };
  }
  const bearer = (intro.flags || []).indexOf("bearer") >= 0;
  let method;
  let problem = "";
  const carried = {};
  if (bearer) {
    method = "bearer";
    if (scheme !== "Bearer") {
      problem = "a bearer token is presented with the Bearer scheme (RFC " +
                "9635 section 7.2 names RFC 6750)";
    }
  } else if (scheme !== "GNAP") {
    problem = "a bound token is presented with the GNAP scheme and a key " +
              "proof";
  } else {
    const key = intro.key;
    if (!key || typeof key !== "object") {
      problem = "the token's key is a reference this resource server " +
                "cannot prove against";
    } else {
      method = typeof key.proof === "string" ? key.proof
        : ((key.proof && key.proof.method) || "httpsig");
      if (method === "httpsig") {
        problem = httpsigProblem(tenant, request, key.jwk || {});
      } else if (method === "jwsd") {
        problem = jwsProblem(request, key.jwk || {}, token, false, carried);
      } else if (method === "jws") {
        problem = jwsProblem(request, key.jwk || {}, token,
                             request.body.length > 0, carried);
      } else if (method === "mtls") {
        problem = mtlsProblem(request, key);
      } else {
        problem = "the proofing method " + method + " is not one this " +
                  "resource server checks";
      }
    }
  }
  if (problem) {
    log.debug("Leaving judge(). Proof: " + problem);
    return { refusal: await refuse(tenant, request, 401, "invalid_token",
                                   problem, { method: method || null }) };
  }
  let cnf = null;
  if (!bearer && intro.key && typeof intro.key === "object") {
    if (intro.key.jwk) {
      cnf = { jkt: thumbprint(intro.key.jwk) };
    } else if (intro.key.cert) {
      const der = Buffer.from(String(intro.key.cert)
        .replace(/-----[^-]+-----|\s+/g, ""), "base64");
      cnf = { "x5t#S256": util.b64u(util.sha("sha256", der)) };
    }
  }
  log.debug("Leaving judge(). Accepted.");
  return {
    ok: true, method: method, format: intro.format || null,
    payload: carried.payload || null,
    intro: intro,
    model: { access: intro.access || [], sub: intro.sub || null,
             aud: intro.aud || null, iss: intro.iss || null,
             grant_id: intro.grant_id || null, flags: intro.flags || [],
             exp: intro.exp || null, iat: intro.iat || null,
             instance_id: intro.instance_id || null,
             label: intro.label || null, act: intro.act || null,
             cnf: cnf }
  };
}

// GET|POST /t/{tenant}/gnap/resource.
async function resource(tenant, request) {
  log.debug("Entering resource(). " + request.method);
  const judged = await judge(tenant, request);
  if (!judged.ok) {
    log.debug("Leaving resource(). Refused.");
    return judged.refusal;
  }
  const action = request.method === "GET" ? "read" : "write";
  if (!covering(tenant, judged.model.access, action).length) {
    log.debug("Leaving resource(). Not covered.");
    return refuse(tenant, request, 403, "insufficient_scope",
                  "The token does not grant " + action + " on " +
                  tenant.gnap.type + ".", { method: judged.method });
  }
  tenant.record("gnap", { ok: true, path: request.path, status: 200,
                          action: action, method: judged.method,
                          format: judged.format,
                          grant_id: judged.model.grant_id });
  log.debug("Leaving resource(). Allowed.");
  return { status: 200, body: { ok: true, action: action,
                                format: judged.format,
                                method: judged.method,
                                token: judged.model } };
}

// The spend body: from the JSON body, or the attached JWS's payload.
function operationOf(request, judged) {
  log.debug("Entering operationOf().");
  const bytes = judged.payload || request.body;
  if (!bytes.length) {
    log.debug("Leaving operationOf(). Empty.");
    return {};
  }
  const parsed = JSON.parse(bytes.toString("utf8"));
  log.debug("Leaving operationOf().");
  return parsed && typeof parsed === "object" ? parsed : {};
}

// What a right's limits make of one more operation: `{ ok, why }`, and the
// totals it would leave. Nothing is written here.
function trySpend(tenant, grant, right, op) {
  log.debug("Entering trySpend().");
  const limits = right.limits || {};
  if (limits.interval !== undefined || limits.window !== undefined) {
    log.debug("Leaving trySpend(). Periods.");
    return { ok: false, why: "the right's limits name an interval or a " +
             "window, which this resource server does not keep" };
  }
  if (limits.receiver !== undefined) {
    const allowed = [].concat(limits.receiver);
    if (allowed.indexOf(op.receiver) < 0) {
      log.debug("Leaving trySpend(). Receiver.");
      return { ok: false, why: "the receiver " + op.receiver + " is not " +
               "one the right allows (" + allowed.join(", ") + ")" };
    }
  }
  if (limits.currency !== undefined && op.currency !== limits.currency) {
    log.debug("Leaving trySpend(). Currency.");
    return { ok: false, why: "the operation is in " + op.currency +
             "; the right allows " + limits.currency + " only" };
  }
  const key = grant + "|" + right.type + "|" + (right.identifier || "");
  const was = tenant.gnap.totals.get(key) || { amount: 0n, count: 0 };
  const next = { amount: was.amount + (op.units || 0n),
                 count: was.count + 1 };
  if (limits.count !== undefined && next.count > Number(limits.count)) {
    log.debug("Leaving trySpend(). Count.");
    return { ok: false, why: "the right allows " + limits.count +
             " operation(s), and " + was.count + " were made" };
  }
  if (limits.amount !== undefined) {
    const ceiling = toUnits(limits.amount);
    if (ceiling === null || next.amount > ceiling) {
      log.debug("Leaving trySpend(). Amount.");
      return { ok: false, why: "the right allows " + limits.amount +
               " in all, and " + fromUnits(was.amount) + " was spent" };
    }
  }
  log.debug("Leaving trySpend(). Fits.");
  return { ok: true, key: key, was: was, next: next, limits: limits };
}

// POST /t/{tenant}/gnap/spend.
async function spend(tenant, request) {
  log.debug("Entering spend().");
  const judged = await judge(tenant, request);
  if (!judged.ok) {
    log.debug("Leaving spend(). Refused.");
    return judged.refusal;
  }
  let op;
  try {
    op = operationOf(request, judged);
  } catch (e) {
    log.debug("Caught in spend(): " + ((e && e.message) || e));
    // An unreadable operation is the client's error, said as one.
    log.debug("Leaving spend(). Unreadable.");
    return refuse(tenant, request, 400, "invalid_request",
                  "The operation is not JSON: " + e.message,
                  { method: judged.method });
  }
  op.units = op.amount === undefined ? 0n : toUnits(op.amount);
  if (op.units === null) {
    log.debug("Leaving spend(). Bad amount.");
    return refuse(tenant, request, 400, "invalid_request",
                  "The amount \"" + op.amount + "\" is not a non-negative " +
                  "decimal.", { method: judged.method });
  }
  const rights = covering(tenant, judged.model.access, "spend")
    .filter(function (one) {
      return typeof one === "object";
    });
  if (!rights.length) {
    log.debug("Leaving spend(). Not covered.");
    return refuse(tenant, request, 403, "insufficient_scope",
                  "The token does not grant spend on " + tenant.gnap.type +
                  ".", { method: judged.method });
  }
  const grant = judged.model.grant_id || "";
  const limited = rights.filter(function (one) {
    return one.limits !== undefined;
  });
  let spent = null;
  if (limited.length === rights.length) {
    let why = "";
    for (const right of limited) {
      const tried = trySpend(tenant, grant, right, op);
      if (tried.ok) {
        spent = tried;
        break;
      }
      why = why || tried.why;
    }
    if (!spent) {
      log.debug("Leaving spend(). Over a limit.");
      return refuse(tenant, request, 403, "insufficient_scope",
                    "The operation is outside the right's limits: " + why +
                    ".", { method: judged.method });
    }
    tenant.gnap.totals.set(spent.key, spent.next);
  }
  if (op.simulateFailure === true || op.simulateFailure === "true") {
    if (spent) {
      tenant.gnap.totals.set(spent.key, spent.was);
    }
    log.debug("Leaving spend(). Failed and refunded.");
    return refuse(tenant, request, 502, "operation_failed",
                  "The operation failed after its spend was counted" +
                  (spent ? "; the spend was refunded." : "."),
                  { method: judged.method, refunded: !!spent });
  }
  const body = { ok: true, action: "spend", format: judged.format,
                 method: judged.method, grant_id: grant,
                 limited: !!spent };
  if (spent) {
    body.totals = { amount: fromUnits(spent.next.amount),
                    count: spent.next.count };
    body.remaining = {};
    if (spent.limits.amount !== undefined) {
      body.remaining.amount = fromUnits(toUnits(spent.limits.amount) -
                                        spent.next.amount);
    }
    if (spent.limits.count !== undefined) {
      body.remaining.count = Number(spent.limits.count) - spent.next.count;
    }
  }
  tenant.record("gnap", { ok: true, path: request.path, status: 200,
                          action: "spend", method: judged.method,
                          grant_id: grant, totals: body.totals || null });
  log.debug("Leaving spend(). Spent.");
  return { status: 200, body: body };
}

// A tenant's GNAP state, from what the job configured.
function configure(tenant, asked) {
  log.debug("Entering configure().");
  const given = asked || {};
  const previous = tenant.gnap || {};
  tenant.gnap = {
    key: previous.key || makeKey(),
    type: String(given.type || previous.type || DEFAULT_TYPE),
    grantEndpoint: String(given.grantEndpoint || tenant.realmBase + "/gnap"),
    introspectionEndpoint: tenant.realmBase + "/gnap/introspect",
    registrationEndpoint: tenant.realmBase + "/gnap/resource",
    reference: previous.reference,
    nonces: previous.nonces || new Set(),
    totals: previous.totals || new Map()
  };
  log.debug("Leaving configure().");
}

module.exports = {
  DEFAULT_TYPE: DEFAULT_TYPE,
  ACTIONS: ACTIONS,
  configure: configure,
  resource: resource,
  spend: spend,
  // For the in-process test.
  thumbprint: thumbprint,
  toUnits: toUnits,
  fromUnits: fromUnits,
  httpsigProblem: httpsigProblem
};
