// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_cluster_single_use.js
//
// ---------------------------------------------------------------------------
// A SINGLE-USE VALUE IS SPENT ONCE ON EVERY NODE, NOT ONCE PER NODE (#46
// section 2), ASKED OVER THE WIRE.
//
// D12 (#444): carries over tests/oauth_cluster_once.js's endpoint claims,
// and the shape of tests/cluster_single_use_protocols.js's and
// tests/cluster_single_use_credentials.js's: a value spent at one node and
// presented again at another. The nodes are STS_TEST_NODE_URLS
// (comma-separated base URLs, one per node, each reaching that node alone,
// with `global.publicBaseUrl` the same on all of them); unset, both "nodes"
// are the job's own base, which in the `cluster` mode is the balancer with
// a new connection per request, and on one node is that node twice. In a
// throwaway realm, every value spent at NODE A and presented at NODE B:
//
//   a. an authorization code: redeemed at A, the replay at B refused
//      `invalid_grant`; and the same code sent to A and B AT ONCE never
//      issues two different token sets;
//   b. in RFC 9700 mode (a second realm), the code's replay at B also
//      revokes the refresh token A issued for it (RFC 9700 4.14.2);
//   c. one refresh token sent to A and B at once in RFC 9700 mode: one 200
//      and one `invalid_grant` (STS-OAUTH-0516 on the realm's audit), and
//      the winner's new refresh token refused afterwards, its family
//      revoked (STS-OAUTH-0517);
//   d. a PAR request_uri whose authorization completed at A is refused at
//      B's authorization endpoint (it is spent when the code is issued: a
//      second visit before that starts a sign-in again);
//   e. a DPoP proof accepted at A's token endpoint is refused at B's for
//      the replay, and a fresh proof is accepted there. Both are sent with
//      the Host the proof's `htu` names, as a balancer passes it: a node
//      checks `htu` against the URL the request was made to;
//   f. (tests/cluster_single_use_credentials.js) the TOTP code that
//      confirmed an enrolment at A's portal is refused as a replay ("already
//      been used") at B's sign-in.
//
// What stays in process (class (d)): the claim store answering on a later
// tick so two calls REALLY interleave, a stale copy written back, and a
// store that cannot be asked failing closed (STS-OAUTH-0518) — a race a job
// wins only sometimes, and a fault no running service can be told to have;
// the hosted surfaces' renewal claimed elsewhere; and, of the other two
// files, what is not above: the SAML artifacts, the OpenID4VCI and GNAP
// values, the Kerberos Authenticator, recovery codes, links, EAB keys and
// SCEP challenges are spent through the same `cluster_claims.js` door as
// the six above, with the stale-copy and fail-closed halves in process; and
// the bootstrap of two cold-starting nodes is a start-up race.
//
// Its realms are removed at the end only under STS_TEST_REMOVE_REALMS=1
// (a hand run on a shared probe); the suite leaves them standing.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const portal = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_cluster_single_use",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const NODES = String(process.env.STS_TEST_NODE_URLS || "").split(",")
  .map(function (one) {
    return one.trim().replace(/\/+$/, "");
  }).filter(Boolean);
const NODE_A = NODES[0] || base;
const NODE_B = NODES[1] || NODES[0] || base;
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                       .slice(0, 31);
}
const PLAIN = realmId("once-");
const BCP = realmId("oncebcp-");
const PERSON = ("once" + STAMP).toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 30);
const PASSWORD = "Once-Only-" + String(Date.now()).slice(-8) + "-Pw!x";
const PUBLIC = "once-public-" + STAMP.toLowerCase();
const CONFIDENTIAL = "once-conf-" + STAMP.toLowerCase();
const SECRET = "once-secret-" + nodeCrypto.randomBytes(12).toString("hex");
const REDIRECT = "https://once.example.net/cb";

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

function form(fields) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(fields).toString();
}

async function api(method, url, payload) {
  log.debug("Entering api(). " + method + " " + url);
  const r = await fetch(url, {
    method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function ok(method, url, payload, what) {
  log.debug("Entering ok().");
  const r = await api(method, url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            what + ": " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A token request at `node` in `realm`, optionally with a DPoP proof.
async function token(node, realm, fields, extraHeaders) {
  log.debug("Entering token(). " + node);
  const r = await fetch(node + "/realm/" + realm + "/oauth2/token", {
    method: "POST",
    headers: Object.assign({
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json" }, extraHeaders || {}),
    body: form(fields) });
  const raw = await r.text();
  let body = {};
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in token(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = {};
  }
  log.debug("Leaving token(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api("GET", base + "/realm/" + realm +
                      "/admin-api/audit?per=500&code=" +
                      encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function sawCode(realm, code, before) {
  log.debug("Entering sawCode(). " + code);
  for (let i = 0; i < 30; i += 1) {
    if (await codeCount(realm, code) > before) {
      log.debug("Leaving sawCode(). Seen.");
      return true;
    }
    await sleep(200);
  }
  log.debug("Leaving sawCode(). Not seen.");
  return false;
}

// One browser: a cookie jar, redirects left to the caller, every request
// to `node`.
function browser(node) {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, url, body) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body) {
        headers["content-type"] = "application/x-www-form-urlencoded";
      }
      const absolute = /^https?:\/\//i.test(url) ? url : node + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at > 0) {
          jar[pair.slice(0, at)] = pair.slice(at + 1);
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

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: nodeCrypto.createHash("sha256")
    .update(verifier).digest("base64url") };
}

// THE PERSON SIGNS IN AT `node` AND THE BROWSER FOLLOWS THE FLOW TO THE
// CLIENT. `authorize` is the query of the authorization request.
async function codeVia(node, realm, authorize) {
  log.debug("Entering codeVia().");
  const b = browser(node);
  let r = await b.go("GET", "/realm/" + realm + "/oauth2/authorize?" +
                     form(authorize));
  assert.ok((r.status === 302 || r.status === 303) &&
            /\/authn\/login/.test(r.location),
            "the authorization endpoint should send the browser to sign " +
            "in; it answered " + r.status + " " + r.location + " " +
            r.text.slice(0, 300));
  r = await authnSignin.signInWithJar(node + "/realm/" + realm, r.location,
    { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  for (let hops = 0; hops < 8 && (r.status === 302 || r.status === 303) &&
       !urls.isAt(r.location, REDIRECT); hops++) {
    if (authnSignin.isConsent(r.location)) {
      // offline_access asks the person; the screen is answered "allow".
      r = await authnSignin.consentWithJar(new URL(r.location, node)
        .toString(), "allow", b.jar);
    } else {
      r = await b.go("GET", r.location);
    }
  }
  assert.ok(urls.isAt(r.location, REDIRECT),
            "the flow should end at the client; it answered " + r.status +
            " " + r.location + " " + String(r.text).slice(0, 300));
  const code = new URL(r.location).searchParams.get("code");
  assert.ok(code, "no code at the client: " + r.location);
  log.debug("Leaving codeVia().");
  return code;
}

async function freshCode(realm) {
  log.debug("Entering freshCode().");
  const p = pkce();
  const code = await codeVia(NODE_A, realm, {
    response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
    scope: "openid offline_access", state: "s-" + STAMP,
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex"),
    code_challenge: p.challenge, code_challenge_method: "S256" });
  log.debug("Leaving freshCode().");
  return { code: code, verifier: p.verifier };
}

function redeem(node, realm, got) {
  log.debug("Entering redeem().");
  log.debug("Leaving redeem().");
  return token(node, realm, { grant_type: "authorization_code",
    code: got.code, redirect_uri: REDIRECT, client_id: PUBLIC,
    code_verifier: got.verifier });
}

function refresh(node, realm, refreshToken) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return token(node, realm, { grant_type: "refresh_token",
    refresh_token: refreshToken, client_id: PUBLIC });
}

// A token request at `node` carrying the Host the proof names, as a
// balancer in front of both nodes passes it: DPoP's htu is the URL the
// request was MADE to, so a proof is only replayable at another node that
// is reached by the same name.
function tokenAs(node, hostName, realm, fields, proof) {
  log.debug("Entering tokenAs(). " + node);
  const target = new URL(node);
  const body = form(fields);
  log.debug("Leaving tokenAs().");
  return new Promise(function (resolve, reject) {
    const req = require("https").request({
      method: "POST", hostname: target.hostname, port: target.port,
      path: "/realm/" + realm + "/oauth2/token", agent: false,
      headers: { host: hostName, DPoP: proof, accept: "application/json",
                 "content-type": "application/x-www-form-urlencoded",
                 "content-length": Buffer.byteLength(body) }
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = {};
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in tokenAs(): " + ((e && e.message) || e));
          // Not JSON; the caller reads `raw`.
          json = {};
        }
        resolve({ status: res.statusCode, body: json, raw: raw });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

// An RFC 9449 proof for `url`, signed with `key`.
function dpopProof(key, url) {
  log.debug("Entering dpopProof().");
  const jwk = nodeCrypto.createPublicKey(key).export({ format: "jwk" });
  const enc = function (o) {
    return Buffer.from(JSON.stringify(o)).toString("base64url");
  };
  const input = enc({ typ: "dpop+jwt", alg: "ES256",
                      jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x,
                             y: jwk.y } }) + "." +
    enc({ jti: nodeCrypto.randomBytes(16).toString("base64url"),
          htm: "POST", htu: url, iat: Math.floor(Date.now() / 1000) });
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
                              { key: key, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving dpopProof().");
  return input + "." + sig.toString("base64url");
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two throwaway realms " + PLAIN + " and " + BCP +
           "; node A " + NODE_A + ", node B " + NODE_B + " ===");
  for (const realm of [PLAIN, BCP]) {
    await ok("POST", base + "/admin-api/realms/create",
             { id: realm, domain: realm + ".example.net",
               name: "Spent once " + STAMP }, "created " + realm);
    const apiBase = base + "/realm/" + realm + "/admin-api";
    await ok("POST", apiBase + "/config/set",
             { key: "global.mode", value: "development" },
             "development mode in " + realm);
    await ok("POST", apiBase + "/config/set",
             { key: "risk.assessSignIns", value: false },
             "risk scoring off in " + realm);
    await ok("POST", apiBase + "/users/create", {
      username: PERSON, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { givenName: "Once", sn: PERSON,
                    mail: PERSON + "@" + realm + ".example.net" } },
      "created the person in " + realm);
    await ok("POST", apiBase + "/applications/create", {
      identifier: PUBLIC, name: PUBLIC, protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: PUBLIC, oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: "none",
                oauthGrantType: ["authorization_code", "refresh_token"] } },
      "created the public client in " + realm);
    await ok("POST", apiBase + "/applications/create", {
      identifier: CONFIDENTIAL, name: CONFIDENTIAL,
      protocols: ["oauth2"],
      fields: { oauthClientId: CONFIDENTIAL, oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post",
                oauthGrantType: ["client_credentials"],
                oauthRedirectUri: [REDIRECT] } },
      "created the confidential client in " + realm);
  }
  await ok("POST", base + "/realm/" + BCP + "/admin-api/config/set",
           { key: "oauth2.rfc9700", value: true }, "RFC 9700 mode in " + BCP);
  log.debug("Leaving setUp().");
}

async function codes() {
  log.debug("Entering codes().");
  log.info("=== a. an authorization code ===");
  const one = await freshCode(PLAIN);
  const first = await redeem(NODE_A, PLAIN, one);
  const replay = await redeem(NODE_B, PLAIN, one);
  check("a. a code redeemed at node A is refused at node B (invalid_grant)",
        function () {
    assert.strictEqual(first.status, 200, first.raw.slice(0, 300));
    assert.strictEqual(replay.status, 400, replay.raw.slice(0, 300));
    assert.strictEqual(replay.body.error, "invalid_grant", replay.raw);
  });
  const two = await freshCode(PLAIN);
  const both = await Promise.all([redeem(NODE_A, PLAIN, two),
                                  redeem(NODE_B, PLAIN, two)]);
  check("a. one code sent to A and B at once never issues two different " +
        "token sets", function () {
    const issued = both.filter(function (r) {
      return r.status === 200;
    });
    assert.ok(issued.length >= 1, JSON.stringify(both.map(function (r) {
      return r.status + " " + r.raw.slice(0, 120);
    })));
    if (issued.length === 2) {
      assert.strictEqual(issued[0].body.access_token,
                         issued[1].body.access_token,
                         "two different token sets for one code");
    }
  });

  log.info("=== b. the code replayed in RFC 9700 mode ===");
  const three = await freshCode(BCP);
  const won = await redeem(NODE_A, BCP, three);
  assert.strictEqual(won.status, 200, won.raw.slice(0, 300));
  assert.ok(won.body.refresh_token, "no refresh token for offline_access: " +
            won.raw.slice(0, 300));
  const again = await redeem(NODE_B, BCP, three);
  let after = null;
  for (let i = 0; i < 20; i += 1) {
    after = await refresh(NODE_A, BCP, won.body.refresh_token);
    if (after.status !== 200) {
      break;
    }
    // A refresh that succeeded rotated the token; keep the newest.
    won.body.refresh_token = after.body.refresh_token ||
      won.body.refresh_token;
    await sleep(250);
  }
  check("b. in RFC 9700 mode the replay at B is refused, and the refresh " +
        "token A issued for the code is revoked", function () {
    assert.strictEqual(again.status, 400, again.raw.slice(0, 300));
    assert.strictEqual(after.status, 400, after.raw.slice(0, 300));
    assert.strictEqual(after.body.error, "invalid_grant", after.raw);
  });
  log.debug("Leaving codes().");
}

async function refreshes() {
  log.debug("Entering refreshes().");
  log.info("=== c. one refresh token at A and B at once ===");
  const got = await freshCode(BCP);
  const issued = await redeem(NODE_A, BCP, got);
  assert.strictEqual(issued.status, 200, issued.raw.slice(0, 300));
  const before516 = await codeCount(BCP, "STS-OAUTH-0516");
  const before517 = await codeCount(BCP, "STS-OAUTH-0517");
  const pair = await Promise.all([
    refresh(NODE_A, BCP, issued.body.refresh_token),
    refresh(NODE_B, BCP, issued.body.refresh_token)]);
  const winner = pair.filter(function (r) {
    return r.status === 200;
  })[0];
  const loser = pair.filter(function (r) {
    return r.status !== 200;
  })[0];
  check("c. one 200 and one invalid_grant", function () {
    assert.ok(winner && loser, JSON.stringify(pair.map(function (r) {
      return r.status + " " + r.raw.slice(0, 120);
    })));
    assert.strictEqual(loser.body.error, "invalid_grant", loser.raw);
  });
  const saw516 = await sawCode(BCP, "STS-OAUTH-0516", before516);
  check("c. the second redemption is a replay (STS-OAUTH-0516)", function () {
    assert.ok(saw516, "no STS-OAUTH-0516 row");
  });
  let late = null;
  for (let i = 0; i < 20; i += 1) {
    late = await refresh(NODE_B, BCP, winner.body.refresh_token);
    if (late.status !== 200) {
      break;
    }
    await sleep(250);
  }
  const saw517 = await sawCode(BCP, "STS-OAUTH-0517", before517);
  check("c. the winner's new refresh token is refused afterwards, its " +
        "family revoked (STS-OAUTH-0517)", function () {
    assert.strictEqual(late.status, 400, late.raw.slice(0, 300));
    assert.ok(saw517, "no STS-OAUTH-0517 row");
  });
  log.debug("Leaving refreshes().");
}

async function pushed() {
  log.debug("Entering pushed().");
  log.info("=== d. a PAR request_uri ===");
  const p = pkce();
  const par = await fetch(NODE_A + "/realm/" + PLAIN + "/oauth2/par", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ response_type: "code", client_id: PUBLIC,
                 redirect_uri: REDIRECT, scope: "openid",
                 state: "par-" + STAMP, code_challenge: p.challenge,
                 code_challenge_method: "S256" }) });
  const parBody = await par.json();
  assert.strictEqual(par.status, 201, JSON.stringify(parBody));
  const code = await codeVia(NODE_A, PLAIN,
                             { client_id: PUBLIC,
                               request_uri: parBody.request_uri });
  const atB = await browser(NODE_B).go("GET", "/realm/" + PLAIN +
    "/oauth2/authorize?" + form({ client_id: PUBLIC,
                                  request_uri: parBody.request_uri }));
  check("d. a request_uri whose authorization A completed (a code was " +
        "issued) is refused at B: no sign-in is started for it",
        function () {
    assert.ok(code, "no code from the pushed request at A");
    assert.ok(!/\/authn\/login/.test(atB.location),
              "B started a sign-in for a spent request_uri: " + atB.location);
    assert.ok(/invalid_request_uri|invalid_request/.test(atB.location +
              atB.text), atB.status + " " + atB.location + " " +
              atB.text.slice(0, 300));
  });
  log.debug("Leaving pushed().");
}

async function proofs() {
  log.debug("Entering proofs().");
  log.info("=== e. a DPoP proof ===");
  const meta = await api("GET", NODE_A + "/realm/" + PLAIN +
                         "/.well-known/oauth-authorization-server");
  const endpoint = meta.body.token_endpoint;
  const key = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey;
  const proof = dpopProof(key, endpoint);
  const fields = { grant_type: "client_credentials", client_id: CONFIDENTIAL,
                   client_secret: SECRET };
  const hostName = new URL(endpoint).host;
  const atA = await tokenAs(NODE_A, hostName, PLAIN, fields, proof);
  const atB = await tokenAs(NODE_B, hostName, PLAIN, fields, proof);
  const fresh = await tokenAs(NODE_B, hostName, PLAIN, fields,
                              dpopProof(key, endpoint));
  check("e. a DPoP proof accepted at A is refused at B, and a fresh proof " +
        "is accepted there", function () {
    assert.strictEqual(atA.status, 200, atA.raw.slice(0, 300));
    assert.strictEqual(String(atA.body.token_type).toLowerCase(), "dpop",
                       atA.raw.slice(0, 300));
    assert.strictEqual(atB.status, 400, atB.raw.slice(0, 300));
    assert.ok(/invalid_dpop_proof|use_dpop_nonce/.test(atB.body.error),
              atB.raw.slice(0, 300));
    // Refused for the replay, not for the address it names.
    assert.ok(!/was made for/.test(String(atB.body.error_description)),
              atB.raw.slice(0, 300));
    assert.strictEqual(fresh.status, 200, fresh.raw.slice(0, 300));
  });
  log.debug("Leaving proofs().");
}

// RFC 6238's code, for section f.
function totpCode(secret, atMs) {
  log.debug("Entering totpCode().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of String(secret).replace(/[\s=]/g, "").toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const key = Buffer.from(bits.match(/.{8}/g).map(function (b) {
    return parseInt(b, 2);
  }));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(Math.floor(atMs / 30000)));
  const digest = nodeCrypto.createHmac("sha1", key).update(message).digest();
  const at = digest[digest.length - 1] & 0x0f;
  const value = ((digest[at] & 0x7f) << 24) | (digest[at + 1] << 16) |
                (digest[at + 2] << 8) | digest[at + 3];
  log.debug("Leaving totpCode().");
  return String(value % 1000000).padStart(6, "0");
}

async function secondFactors() {
  log.debug("Entering secondFactors().");
  log.info("=== f. a TOTP code ===");
  const who = ("totp" + STAMP).toLowerCase().replace(/[^a-z0-9]/g, "")
    .slice(0, 30);
  await ok("POST", base + "/realm/" + PLAIN + "/admin-api/users/create", {
    username: who, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { givenName: "Totp", sn: who,
                  mail: who + "@" + PLAIN + ".example.net" } },
    "created the TOTP person");
  const b = await portal.signInToThePortal(NODE_A + "/realm/" + PLAIN, who,
                                           null, { password: PASSWORD });
  const started = await b.act("/portal/mfa", { action: "start" });
  assert.strictEqual(started.status, 200, String(started.text).slice(0, 300));
  const view = await b.page("/portal/mfa");
  const secret = (view.json && view.json.setup &&
                  view.json.setup.grouped) || "";
  assert.ok(secret, "no secret on the setup view: " +
            JSON.stringify(view.json).slice(0, 300));
  const code = totpCode(secret, Date.now());
  const confirmed = await b.act("/portal/mfa",
                                { action: "confirm", code: code });
  assert.strictEqual(confirmed.status, 200,
                     String(confirmed.text).slice(0, 300));
  // The same code, at node B's sign-in, inside its thirty seconds.
  const nb = browser(NODE_B);
  const p = pkce();
  const r = await nb.go("GET", "/realm/" + PLAIN + "/oauth2/authorize?" +
    form({ response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
           scope: "openid", state: "t-" + STAMP,
           code_challenge: p.challenge, code_challenge_method: "S256" }));
  const cookie = function () {
    return Object.keys(nb.jar).map(function (k) {
      return k + "=" + nb.jar[k];
    }).join("; ");
  };
  const answer = await authnSignin.submit(NODE_B + "/realm/" + PLAIN,
    new URL(r.location, NODE_B).toString(),
    { action: "login", username: who, password: PASSWORD },
    { cookie: cookie() });
  (answer.setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at > 0) {
      nb.jar[pair.slice(0, at)] = pair.slice(at + 1);
    }
  });
  const shown = await authnSignin.asFormAnswer(answer, function (m, u) {
    return nb.go(m, new URL(u, NODE_B).toString());
  });
  assert.ok(shown.step && shown.step.view && shown.step.view.page === "totp",
            "node B's sign-in did not ask for the code: " + shown.status +
            " " + String(shown.text).slice(0, 300));
  const replay = await authnSignin.stepAct(shown.step, "totp",
                                           { code: code },
                                           { cookie: cookie() });
  check("f. the TOTP code that confirmed the enrolment at A is refused as a " +
        "replay at B's sign-in", function () {
    assert.ok(String(shown.step.base).indexOf(NODE_B) === 0 ||
              NODE_A === NODE_B, "the step was not node B's: " +
              shown.step.base);
    assert.strictEqual(replay.status, 400, replay.status + " " +
                       String(replay.text).slice(0, 300));
    assert.ok(/already been used/.test((replay.errors || []).join(" ") +
              String(replay.text)), JSON.stringify(replay.errors));
  });
  log.debug("Leaving secondFactors().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await codes();
  await refreshes();
  await pushed();
  await proofs();
  await secondFactors();
  log.info("sts_cluster_single_use: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

// THE REALMS THIS JOB MADE, REMOVED AT ITS END ONLY WHEN ASKED
// (STS_TEST_REMOVE_REALMS=1, a hand run against a probe that many jobs
// share and whose directory would otherwise fill). The suite does not ask:
// no job removes a realm on a shared run (tests/CLAUDE.md).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked.");
    return;
  }
  for (const id of [PLAIN, BCP]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm left behind is litter, not a failure of what was tested.
      log.warn("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().finally(removeRealms).then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_cluster_single_use FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
