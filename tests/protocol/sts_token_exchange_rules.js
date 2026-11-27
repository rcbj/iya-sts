// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_token_exchange_rules.js
//
// ---------------------------------------------------------------------------
// RFC 8693 TOKEN EXCHANGE: WHAT IS VERIFIED, WHAT TYPE A TOKEN IS, AND WHO
// MAY ACT FOR WHOM — IN BOTH MODES, WITH THE CODES OFF THE AUDIT LOG.
//
// D12 (#444): carries over the part a client can see of
//
//   * `tests/token_exchange_product.js` — PRODUCT exchanges only a token it
//     can verify: an unsigned or foreign-signed subject_token naming
//     somebody else is refused STS-OAUTH-0555, a revoked one STS-OAUTH-0557,
//     a forged actor_token STS-OAUTH-0556, a verified actor named in `act`;
//     DEVELOPMENT still exchanges the forged token. And the issuance
//     policy's answers at the endpoint, by code: no relationship
//     (invalid_target, 0619), impersonation asked of an actor allowing
//     delegation only (0790), an unusable exchange_semantics (0795), a
//     protected subject (0618), an unregistered audience (0793 or 0986), two
//     audiences (0792), no audience by an actor that is not S (0794), a
//     wider scope (0621); and #471's `act`: the client named
//     `urn:sts:client:<id>` in product, every entry carrying the token's
//     `iss`;
//   * `tests/token_exchange_declared_type.js` — a subject_token or
//     actor_token is the type it was declared as, STS-OAUTH-0628, in both
//     modes (an ID Token as an access token, an access token as an ID Token,
//     a refresh token as an access token, an ID Token as the actor), and a
//     token from anywhere still read unverified in development, held to
//     #550's rule that an actor_token is the exchanging client's own;
//   * `tests/token_exchange_jti.js` — its wire half: an exchange with no
//     `openid` answers no ID Token, one with it answers one, and the
//     delegation act names the exchanged access token's jti.
//
// NOT carried, and why: STS-OAUTH-0182 itself — it was only ever a log line
// at ERROR, never an audit row or an answer (class (d)); the development
// mode's "WOULD HAVE BEEN REFUSED" rows, which `sts_delegation_policy.js`
// holds in whatever mode the stack runs; and may_act (0620), `act` nesting
// and RFC 9700 mode's namings (#471 part 9), which that job and
// `sts_token_exchange_chain_*.js` hold.
//
// OWNED HERE (local: true). Its realm is left standing unless
// STS_TEST_REMOVE_REALMS=1.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_token_exchange_rules",
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
const REALM = "txr-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const TOKEN = RB + "/oauth2/token";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const T = "urn:ietf:params:oauth:token-type:";
const ALICE = "txr-alice-" + STAMP;
const BOB = "txr-bob-" + STAMP;
const CLIENT = "txr-client";
const FRONT = "txr-front";
const BACK = "txr-back";
const IMP = "txr-imp";
const BACK_AUD = "https://txr-back-" + STAMP + ".example";
const secretOf = function (id) {
  log.debug("Entering secretOf().");
  log.debug("Leaving secretOf().");
  return id + "-secret-0123456789abcdef0123";
};

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

// A form, a value that is an array sent as the parameter repeated.
function form(url, fields) {
  log.debug("Entering form().");
  const params = new URLSearchParams();
  Object.keys(fields).forEach(function (k) {
    [].concat(fields[k]).forEach(function (v) {
      params.append(k, v);
    });
  });
  log.debug("Leaving form().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString() });
}

function as(id) {
  log.debug("Entering as().");
  log.debug("Leaving as().");
  return { client_id: id, client_secret: secretOf(id) };
}

function exchange(actor, subject, type, extra) {
  log.debug("Entering exchange().");
  log.debug("Leaving exchange().");
  return form(TOKEN, Object.assign({ grant_type: EXCHANGE,
    subject_token: subject, subject_token_type: T + (type || "access_token") },
  as(actor), extra || {}));
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

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

// A refusal with its OAuth error, nothing issued, no code in the answer,
// and `code` (one of several, where the wire may record either) on the
// realm's audit log. Answers "" when it holds, else what went wrong.
async function refusedWith(label, attempt, error, codes, says) {
  log.debug("Entering refusedWith(). " + label);
  const list = [].concat(codes);
  const before = {};
  for (const c of list) {
    before[c] = await codeCount(c);
  }
  const r = await attempt();
  let rose = false;
  for (const c of list) {
    rose = rose || await codeRose(c, before[c]);
  }
  const fine = r.status === 400 && r.body.error === error &&
               !r.body.access_token && rose &&
               !/STS-[A-Z]+-\d{4}/.test(r.raw) &&
               (!says || String(r.body.error_description).indexOf(says) >=
                0);
  log.debug("Leaving refusedWith().");
  return fine ? "" : label + ": " + r.status + " " + r.raw.slice(0, 250) +
                     " (code " + list.join("|") + " rose=" + rose + ")";
}

function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

function b64uJson(o) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
}

async function setup() {
  log.debug("Entering setup().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Token exchange rules " + STAMP },
    "created the realm");
  await setting("global.mode", "development");
  for (const who of [ALICE, BOB]) {
    await ok(API + "/users/create", { username: who, invent: false,
      attributes: { cn: who, givenName: "Exchange", sn: who,
                    mail: who + "@" + REALM + ".example.net" } },
      "created " + who);
  }
  const app = async function (id, fields) {
    log.debug("Entering app(). " + id);
    await ok(API + "/applications/create", { identifier: id,
      protocols: ["oauth2", "oidc"],
      fields: Object.assign({ oauthClientId: [id],
        oauthClientSecret: secretOf(id),
        oauthTokenEndpointAuthMethod: "client_secret_post",
        oauthGrantType: ["password", "client_credentials", "refresh_token",
                         EXCHANGE],
        oauthAllowedScope: ["openid", "profile", "offline_access", "api",
                            "wider"] }, fields || {}) },
      "registered " + id);
    log.debug("Leaving app().");
  };
  await app(CLIENT);
  await app(BACK, { oauthAudience: [BACK_AUD] });
  await app(FRONT, { appAllowedToDelegateTo: [BACK] });
  await app(IMP, { appAllowedToDelegateTo: [BACK],
                   appDelegationSemantics: ["delegation", "impersonation"] });
  log.debug("Leaving setup().");
}

async function password(client, who, scope) {
  log.debug("Entering password().");
  const r = await form(TOKEN, Object.assign({ grant_type: "password",
    username: who, password: "anything", scope: scope }, as(client)));
  assert.strictEqual(r.status, 200, "the password grant for " + who +
                     ": " + r.raw.slice(0, 300));
  log.debug("Leaving password().");
  return r.body;
}

async function clientToken(client) {
  log.debug("Entering clientToken().");
  const r = await form(TOKEN, Object.assign(
    { grant_type: "client_credentials" }, as(client)));
  assert.strictEqual(r.status, 200, "client_credentials for " + client +
                     ": " + r.raw.slice(0, 300));
  log.debug("Leaving clientToken().");
  return r.body.access_token;
}

// ---------------------------------------------------------------------------
async function declaredTypes(tokens) {
  log.debug("Entering declaredTypes().");
  log.info("=== T. a token is the type it was declared as ===");
  const problems = [];
  const accepted = async function (label, attempt) {
    log.debug("Entering accepted().");
    const r = await attempt();
    if (r.status !== 200 || !r.body.access_token) {
      problems.push(label + ": " + r.status + " " + r.raw.slice(0, 200));
    }
    log.debug("Leaving accepted().");
  };
  const C = "STS-OAUTH-0628";
  const access = tokens.access;
  const idToken = tokens.idToken;
  const refresh = tokens.refresh;
  const unsigned = b64uJson({ alg: "none", typ: "JWT" }) + "." +
    b64uJson({ sub: "txr-somebody", iat: Math.floor(Date.now() / 1000) }) +
    ".";
  const ownCc = await clientToken(CLIENT);
  await accepted("D1 access as access_token", function () {
    return exchange(CLIENT, access, "access_token");
  });
  problems.push(await refusedWith("D2 ID Token as access_token", function () {
    return exchange(CLIENT, idToken, "access_token");
  }, "invalid_request", C, "is an ID Token"));
  problems.push(await refusedWith("D3 access token as id_token", function () {
    return exchange(CLIENT, access, "id_token");
  }, "invalid_request", C, "is an access token"));
  await accepted("D4 ID Token as id_token", function () {
    return exchange(CLIENT, idToken, "id_token");
  });
  await accepted("D5 ours as jwt", function () {
    return exchange(CLIENT, idToken, "jwt");
  });
  problems.push(await refusedWith("D6 refresh token as access_token",
    function () {
      return exchange(CLIENT, refresh, "access_token");
    }, "invalid_request", C, "is a refresh token"));
  await accepted("D7 a token from anywhere, read unverified", function () {
    return exchange(CLIENT, unsigned, "access_token");
  });
  await accepted("D8 our access token as the actor", function () {
    return exchange(CLIENT, access, "access_token",
      { actor_token: ownCc, actor_token_type: T + "access_token" });
  });
  problems.push(await refusedWith("D9 our ID Token as the actor declared " +
    "access_token", function () {
    return exchange(CLIENT, access, "access_token",
      { actor_token: idToken, actor_token_type: T + "access_token" });
  }, "invalid_request", C, "actor_token was declared"));
  const unsignedOwn = b64uJson({ alg: "none", typ: "JWT" }) + "." +
    b64uJson({ sub: "txr-somebody", client_id: CLIENT, aud: CLIENT,
               iat: Math.floor(Date.now() / 1000) }) + ".";
  await accepted("D10 an unverified actor naming this client", function () {
    return exchange(CLIENT, access, "access_token",
      { actor_token: unsignedOwn, actor_token_type: T + "access_token" });
  });
  const unbound = await exchange(CLIENT, access, "access_token",
    { actor_token: unsigned, actor_token_type: T + "access_token" });
  check("T1. DEVELOPMENT: an access token, an ID Token as id_token and any " +
        "token of ours as jwt are exchanged; an ID Token as an access " +
        "token, an access token as an ID Token, a refresh token as an " +
        "access token and an ID Token as the actor are refused " +
        "invalid_request naming what they are, each recorded STS-OAUTH-0628; " +
        "a token from anywhere is still read unverified", function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
        });
  check("T2. DEVELOPMENT (#550): an unverified actor_token naming no " +
        "client is refused all the same", function () {
          assert.strictEqual(unbound.status, 400, unbound.raw.slice(0, 300));
          assert.ok(/not issued to this client/.test(
            unbound.body.error_description), unbound.raw.slice(0, 300));
        });
  log.debug("Leaving declaredTypes().");
}

async function declaredTypesProduct(tokens) {
  log.debug("Entering declaredTypesProduct().");
  const C = "STS-OAUTH-0628";
  const problems = [];
  const own = await clientToken(CLIENT);
  const p1 = await exchange(CLIENT, own, "access_token");
  if (p1.status !== 200) {
    problems.push("P1 own access token: " + p1.status + " " +
                  p1.raw.slice(0, 200));
  }
  problems.push(await refusedWith("P2 ID Token as access_token", function () {
    return exchange(CLIENT, tokens.idToken, "access_token");
  }, "invalid_request", C, "is an ID Token"));
  problems.push(await refusedWith("P3 access token as id_token", function () {
    return exchange(CLIENT, own, "id_token");
  }, "invalid_request", C, "is an access token"));
  problems.push(await refusedWith("P4 ID Token as the actor", function () {
    return exchange(CLIENT, own, "access_token",
      { actor_token: tokens.idToken, actor_token_type: T + "access_token" });
  }, "invalid_request", C, "actor_token was declared"));
  check("T3. PRODUCT: the client's own token is exchanged, and the same " +
        "three type refusals hold, each STS-OAUTH-0628", function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
        });
  log.debug("Leaving declaredTypesProduct().");
}

async function produced(tokens) {
  log.debug("Entering produced().");
  log.info("=== J. what an exchange produced, and the act naming it ===");
  const plain = await exchange(CLIENT, tokens.access, "access_token",
                               { scope: "api" });
  const withId = await exchange(CLIENT, tokens.access, "access_token",
                                { scope: "openid api" });
  check("J1. an exchange with no openid answers 200 and no ID Token; with " +
        "openid it answers one", function () {
          assert.strictEqual(plain.status, 200, plain.raw.slice(0, 300));
          assert.ok(plain.body.access_token && !plain.body.id_token,
                    Object.keys(plain.body).join(","));
          assert.strictEqual(withId.status, 200, withId.raw.slice(0, 300));
          assert.ok(withId.body.id_token, Object.keys(withId.body).join(","));
        });
  const jti = claimsOf(plain.body.access_token).jti;
  let found = [];
  for (let i = 0; i < 20 && !found.length; i += 1) {
    const reg = await send(API + "/delegation?per=200&q=" +
                           encodeURIComponent(ALICE));
    found = (reg.body.acts || []).filter(function (row) {
      return (row.produced || []).some(function (one) {
        return one.kind === "access_token" && one.identifier === jti;
      });
    });
    if (!found.length) {
      await sleep(150);
    }
  }
  check("J2. the delegation register holds exactly one act naming the " +
        "exchanged access token's jti, and no ID Token it never issued",
        function () {
          assert.strictEqual(found.length, 1, "acts naming " + jti + ": " +
                             found.length);
          assert.ok(!(found[0].produced || []).some(function (one) {
            return one.kind === "id_token";
          }), JSON.stringify(found[0].produced));
        });
  log.debug("Leaving produced().");
}

async function verification(tokens) {
  log.debug("Entering verification().");
  log.info("=== X. product exchanges only what it can verify ===");
  const own = await clientToken(CLIENT);
  const control = await exchange(CLIENT, tokens.access, "access_token");
  check("X1. PRODUCT: a subject_token this realm signed is exchanged — the " +
        "control", function () {
          assert.strictEqual(control.status, 200, control.raw.slice(0, 300));
        });
  const forged = { iss: RB, sub: "urn:uuid:00000000-0000-4000-8000-" +
                   "00000000a11c", username: "txr-admin", scope: "openid",
                   iat: Math.floor(Date.now() / 1000),
                   exp: Math.floor(Date.now() / 1000) + 600,
                   jti: "txr-forged-" +
                        nodeCrypto.randomBytes(6).toString("hex") };
  const unsigned = b64uJson({ alg: "none", typ: "JWT" }) + "." +
                   b64uJson(forged) + ".";
  const stranger = nodeCrypto.generateKeyPairSync("rsa",
                                                  { modulusLength: 2048 });
  const input = b64uJson({ alg: "RS256", typ: "JWT" }) + "." +
                b64uJson(forged);
  const foreign = input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                                stranger.privateKey)
    .toString("base64url");
  const problems = [];
  problems.push(await refusedWith("X2 alg none", function () {
    return exchange(CLIENT, unsigned, "access_token");
  }, "invalid_request", "STS-OAUTH-0555"));
  problems.push(await refusedWith("X3 a foreign key", function () {
    return exchange(CLIENT, foreign, "access_token");
  }, "invalid_request", "STS-OAUTH-0555"));
  const revoked = tokens.toRevoke;
  const rv = await form(RB + "/oauth2/revoke", Object.assign({
    token: revoked.access_token, token_type_hint: "access_token" },
  as(CLIENT)));
  assert.strictEqual(rv.status, 200, "the revocation: " + rv.raw);
  problems.push(await refusedWith("X4 revoked", function () {
    return exchange(CLIENT, revoked.access_token, "access_token");
  }, "invalid_request", "STS-OAUTH-0557"));
  const forgedActor = b64uJson({ alg: "none", typ: "JWT" }) + "." +
    b64uJson({ sub: "txr-actor", client_id: CLIENT, aud: CLIENT,
               iat: Math.floor(Date.now() / 1000) }) + ".";
  problems.push(await refusedWith("X5 a forged actor_token", function () {
    return exchange(CLIENT, tokens.access, "access_token",
      { actor_token: forgedActor, actor_token_type: T + "access_token" });
  }, "invalid_request", "STS-OAUTH-0556"));
  const withActor = await exchange(CLIENT, own, "access_token",
    { actor_token: own, actor_token_type: T + "access_token" });
  check("X2. PRODUCT: an unsigned or foreign-signed subject_token naming " +
        "somebody else is refused STS-OAUTH-0555, a revoked one " +
        "STS-OAUTH-0557, a forged actor_token STS-OAUTH-0556", function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
        });
  check("X3. PRODUCT: with a VERIFIED actor_token the exchange succeeds — " +
        "the actor IS the subject, a self exchange, so no `act` (#186)",
        function () {
          assert.strictEqual(withActor.status, 200,
                             withActor.raw.slice(0, 300));
          assert.ok(!claimsOf(withActor.body.access_token).act,
                    JSON.stringify(claimsOf(withActor.body.access_token)));
        });
  log.debug("Leaving verification().");
  return { unsigned: unsigned, forged: forged };
}

async function policy(tokens) {
  log.debug("Entering policy().");
  log.info("=== Y. who may act for whom, product, by code ===");
  const forFront = tokens.aliceForFront;
  const r = await exchange(FRONT, forFront, "access_token",
                           { audience: BACK_AUD });
  check("Y1. PRODUCT: a delegation by S to the R it delegates to is " +
        "issued for R, `act` naming the client urn:sts:client:" + FRONT +
        " with the token's own iss (#471)", function () {
          assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
          const c = claimsOf(r.body.access_token);
          assert.ok(c.act, JSON.stringify(c));
          assert.strictEqual(c.act.sub, "urn:sts:client:" + FRONT);
          assert.strictEqual(c.act.iss, c.iss);
          assert.ok(urls.holds(c.aud, BACK_AUD),
                    JSON.stringify(c.aud));
        });
  const problems = [];
  const forClient = tokens.aliceForClient;
  problems.push(await refusedWith("0619 no relationship", function () {
    return exchange(CLIENT, forClient, "access_token",
                    { audience: BACK_AUD });
  }, "invalid_target", "STS-OAUTH-0619"));
  problems.push(await refusedWith("0790 impersonation, delegation only",
    function () {
      return exchange(FRONT, forFront, "access_token",
        { audience: BACK_AUD, exchange_semantics: "impersonation" });
    }, "invalid_request", "STS-OAUTH-0790"));
  problems.push(await refusedWith("0795 sideways", function () {
    return exchange(FRONT, forFront, "access_token",
      { audience: BACK_AUD, exchange_semantics: "sideways" });
  }, "invalid_request", "STS-OAUTH-0795"));
  problems.push(await refusedWith("0793 unregistered audience", function () {
    return exchange(FRONT, forFront, "access_token",
      { audience: "https://nobody-" + STAMP + ".example" });
  }, "invalid_target", ["STS-OAUTH-0793", "STS-OAUTH-0986"]));
  problems.push(await refusedWith("0792 two audiences", function () {
    return exchange(FRONT, forFront, "access_token",
      { audience: [BACK_AUD, "https://txr-other-" + STAMP + ".example"] });
  }, "invalid_target", ["STS-OAUTH-0792", "STS-OAUTH-0986",
                        "STS-OAUTH-0793"]));
  problems.push(await refusedWith("0794 no audience, actor not S",
    function () {
      return exchange(BACK, forFront, "access_token");
    }, "invalid_target", "STS-OAUTH-0794"));
  problems.push(await refusedWith("0621 a wider scope", function () {
    return exchange(FRONT, forFront, "access_token",
                    { audience: BACK_AUD, scope: "api wider" });
  }, "invalid_scope", "STS-OAUTH-0621"));
  const forImp = tokens.aliceForImp;
  const imp = await exchange(IMP, forImp, "access_token",
    { audience: BACK_AUD, exchange_semantics: "impersonation" });
  await ok(API + "/users/set-not-delegated", { user: BOB, value: true },
           "set stsNotDelegated on " + BOB);
  const forBob = tokens.bobForFront;
  problems.push(await refusedWith("0618 a protected subject", function () {
    return exchange(FRONT, forBob, "access_token", { audience: BACK_AUD });
  }, "invalid_request", "STS-OAUTH-0618"));
  check("Y2. PRODUCT, each refusal by its OAuth error and its code off the " +
        "audit log: no relationship (invalid_target, 0619), impersonation " +
        "of an actor allowing delegation only (0790), an unusable " +
        "exchange_semantics (0795), an unregistered audience (0793/0986), " +
        "two audiences (0792), no audience by an actor that is not S " +
        "(0794), a wider scope (0621), a protected subject (0618)",
        function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
        });
  check("Y3. PRODUCT: impersonation by an actor allowing it is issued, " +
        "with no `act`", function () {
          assert.strictEqual(imp.status, 200, imp.raw.slice(0, 300));
          assert.ok(!claimsOf(imp.body.access_token).act,
                    JSON.stringify(claimsOf(imp.body.access_token).act));
        });
  log.debug("Leaving policy().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + RB);
  await setup();
  const alice = await password(CLIENT, ALICE,
                               "openid profile offline_access api");
  const tokens = { access: alice.access_token, idToken: alice.id_token,
                   refresh: alice.refresh_token,
                   bobForFront: (await password(FRONT, BOB, "api"))
                     .access_token };
  assert.ok(tokens.access && tokens.idToken && tokens.refresh,
            "the password grant issued no access, ID or refresh token");
  await declaredTypes(tokens);
  await produced(tokens);
  // The forged token is exchanged in development — it is what a client
  // under test uses — and says whose it claimed to be.
  const forgedSub = "urn:uuid:00000000-0000-4000-8000-00000000d0e1";
  const devForged = await exchange(CLIENT, b64uJson({ alg: "none",
    typ: "JWT" }) + "." + b64uJson({ sub: forgedSub, username: "txr-admin",
    iat: Math.floor(Date.now() / 1000) }) + ".", "access_token");
  check("X0. DEVELOPMENT: an unsigned subject_token is still exchanged, and " +
        "the token says whose it claimed to be", function () {
          assert.strictEqual(devForged.status, 200,
                             devForged.raw.slice(0, 300));
          const c = claimsOf(devForged.body.access_token);
          assert.ok(c.sub === forgedSub || c.username === "txr-admin",
                    JSON.stringify(c));
        });
  // Product checks every password, so every person-bearing token the
  // product sections present is minted while the realm is in development.
  tokens.toRevoke = await password(CLIENT, ALICE, "api");
  tokens.aliceForFront = (await password(FRONT, ALICE, "api")).access_token;
  tokens.aliceForClient = (await password(CLIENT, ALICE, "api"))
    .access_token;
  tokens.aliceForImp = (await password(IMP, ALICE, "api")).access_token;
  await setting("global.mode", "product");
  await declaredTypesProduct(tokens);
  await verification(tokens);
  await policy(tokens);
  assert.ok(checks >= 12, "only " + checks + " checks ran");
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
