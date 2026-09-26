"use strict";
//
// File: sts_caep_oauth_grants.js
//
// ---------------------------------------------------------------------------
// AN OAUTH GRANT REVOKED IS CAEP's session-revoked, AND THREE MORE DOORS ARE
// SINGLE SIGN-ON (#239, #240, 2026-09-26), over the wire.
//
// In a throwaway realm it leaves behind, with CIBA and refresh-token rotation
// on and a poll stream that takes session-revoked, session-presented and
// risk-level-change about everybody:
//
//   a. a client revoking its refresh token at /oauth2/revoke sends ONE
//      session-revoked whose session is `oauth-grant:<id>`, about the person,
//      initiating_entity `user` — one for the grant, not one per token;
//   b. a rotated refresh token REPLAYED sends risk-level-change (SESSION,
//      HIGH, refresh-token-replay) and session-revoked, both `policy`, about
//      the same grant;
//   c. /admin-api/tokens revoking everything a person holds sends
//      session-revoked `admin` for the grant still live;
//   d. a CIBA approval on /portal/ciba is a session-presented naming CIBA,
//      and its tokens are issued ON the approving sign-on session — listed
//      under it, and their refresh token inactive once that session ends;
//   e. in product mode, a pre-authorized (cross-device) OpenID4VCI offer
//      made for the signed-in person is a session-presented naming
//      OpenID4VCI (development mints that offer for a fixed test person and
//      reads no session, so there is nothing to present).
//
// OWNED HERE (local: true): this repository's own transmitter.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_caep_oauth_grants",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("caep239-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const base = root + R;
const api = base + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const POLL = "urn:ietf:rfc:8936";
const CIBA = "urn:openid:params:grant-type:ciba";
const SECRET = "caep-239-" + nodeCrypto.randomBytes(9).toString("hex");
const CLIENT = "caep239-rp-" + STAMP.toLowerCase();
const REDIRECT = "https://rp.caep239.example.test/cb";
const PASSWORD = "Caep-239-" + nodeCrypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const ALICE = names.usernameFor("c239-alice");
// A desktop browser's User-Agent, with this job's name on the end: product
// mode scores an automated client's first sign-in as a risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_caep_oauth_grants/1.0 (" + STAMP + ")";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function postForm(url, fields) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(fields) });
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

// One browser, with a cookie jar.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(path) ? path : root + path;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Max-Age=0/i.test(String(one)) ||
            /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      const location = r.headers.get("location") || "";
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, text: text,
               location: location ? new URL(location, url).toString() : "" };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

// Follows redirects from `path`, signing in with the password where the
// sign-in screen appears, until a page answers 200 or a redirect leaves for
// `stopAt`.
async function follow(b, path, stopAt) {
  log.debug("Entering follow(). " + path);
  let r = await b.go("GET", path);
  for (let n = 0; n < 16; n += 1) {
    if (stopAt && r.location.indexOf(stopAt) === 0) {
      break;
    }
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = ALICE;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
      continue;
    }
    if (r.status !== 302 && r.status !== 303) {
      break;
    }
    r = await b.go("GET", r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

// A code flow for CLIENT in browser `b`, redeemed: the token response.
async function codeGrant(b) {
  log.debug("Entering codeGrant().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const params = { response_type: "code", client_id: CLIENT,
    redirect_uri: REDIRECT, scope: "openid profile", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"), code_challenge_method: "S256" };
  const r = await follow(b, R + "/oauth2/authorize?" + form(params),
                         REDIRECT);
  const code = r.location.indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "the code flow reaches the client: " + r.status + " " +
            r.location + " " + r.text.slice(0, 300));
  const redeemed = await postForm(base + "/oauth2/token", {
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT,
    client_id: CLIENT, client_secret: SECRET, code_verifier: verifier });
  assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
  assert.ok(redeemed.body.refresh_token, "a refresh token: " +
            redeemed.raw.slice(0, 300));
  log.debug("Leaving codeGrant().");
  return redeemed.body;
}

function refresh(token) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return postForm(base + "/oauth2/token", { grant_type: "refresh_token",
    refresh_token: token, client_id: CLIENT, client_secret: SECRET });
}

async function tokenFor(scope) {
  log.debug("Entering tokenFor().");
  const r = await postForm(base + "/oauth2/token", {
    grant_type: "client_credentials", client_id: CLIENT,
    client_secret: SECRET, scope: scope });
  assert.ok(r.body && r.body.access_token,
            "a token for " + scope + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

function decode(token) {
  log.debug("Entering decode().");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

// Every SET waiting on the stream, decoded and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(base + "/ssf/poll", { method: "POST", headers: auth,
    body: JSON.stringify({ stream_id: streamId, returnImmediately: true,
                           maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(base + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: streamId, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// Everything that arrived, kept across waits so a later check can count.
const SEEN = [];

// Waits for every predicate in `wanted` to be met by a SET that arrived
// since `from` (an index into SEEN). Delivery is on a promise after the act
// answers, so a first poll may be early.
async function waitFor(token, streamId, what, wanted, from) {
  log.debug("Entering waitFor(). " + what);
  const start = from || 0;
  let hits = [];
  for (let i = 0; i < 24; i++) {
    (await drain(token, streamId)).forEach(function (one) {
      SEEN.push(one);
    });
    const fresh = SEEN.slice(start);
    hits = wanted.map(function (predicate) {
      return fresh.filter(predicate)[0] || null;
    });
    if (hits.every(Boolean)) {
      break;
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor().");
  return hits;
}

function eventOf(set, type) {
  log.debug("Entering eventOf().");
  log.debug("Leaving eventOf().");
  return ((set && set.events) || {})[CAEP + type] || null;
}

function sessionIdOf(set) {
  log.debug("Entering sessionIdOf().");
  const sub = set && set.sub_id;
  log.debug("Leaving sessionIdOf().");
  return sub && sub.format === "complex" && sub.session
    ? String(sub.session.id || "") : "";
}

function grantRevoked(entity, notIn) {
  log.debug("Entering grantRevoked().");
  log.debug("Leaving grantRevoked().");
  return function (set) {
    const ev = eventOf(set, "session-revoked");
    const id = sessionIdOf(set);
    return !!ev && id.indexOf("oauth-grant:") === 0 &&
           (!entity || ev.initiating_entity === entity) &&
           (!notIn || notIn.indexOf(id) < 0);
  };
}

function presentedVia(word) {
  log.debug("Entering presentedVia().");
  log.debug("Leaving presentedVia().");
  return function (set) {
    const ev = eventOf(set, "session-presented");
    return !!ev && JSON.stringify(ev).indexOf(word) >= 0;
  };
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + ") ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "CAEP 239 " + STAMP },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.ciba", value: true },
           "turned CIBA on in the realm");
  await ok(api + "/config/set", { key: "oauth2.refreshTokenRotation",
                                  value: true },
           "turned refresh-token rotation on in the realm");
  await ok(api + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT,
    protocols: ["oauth2", "oidc", "ssf"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid", "profile", "ssf:read",
                                  "ssf:write"],
              oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code", "refresh_token",
                               "client_credentials", CIBA],
              oauthResponseType: ["code"],
              oauthBackchannelTokenDeliveryMode: "poll" } },
    "created the client and receiver");
  for (const one of ["openid", "profile"]) {
    await ok(api + "/consent/grant-global-consent",
             { client: CLIENT, scope: one }, "consented " + one);
  }
  await ok(api + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "CAEP " + ALICE, givenName: "CAEP", sn: "Grants",
                  mail: ALICE + "@caep239.test" } }, "created " + ALICE);
  const token = await tokenFor("ssf:read ssf:write");
  const created = await send(base + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: [CAEP + "session-revoked",
                         CAEP + "session-presented",
                         CAEP + "risk-level-change"] }) });
  check("a poll stream takes session-revoked, session-presented and " +
        "risk-level-change", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
    const delivered = created.body.events_delivered || [];
    [CAEP + "session-revoked", CAEP + "session-presented",
     CAEP + "risk-level-change"].forEach(function (one) {
      assert.ok(delivered.indexOf(one) >= 0, JSON.stringify(delivered));
    });
  });
  const streamId = created.body.stream_id;
  const announced = [];

  log.info("=== a. /oauth2/revoke of the refresh token ===");
  const b = browser();
  const first = await codeGrant(b);
  let mark = SEEN.length;
  const revoked = await postForm(base + "/oauth2/revoke", {
    token: first.refresh_token, token_type_hint: "refresh_token",
    client_id: CLIENT, client_secret: SECRET });
  check("the refresh token is revoked", function () {
    assert.strictEqual(revoked.status, 200, revoked.raw.slice(0, 300));
  });
  let hits = await waitFor(token, streamId, "the grant revoked",
                           [grantRevoked("user")], mark);
  check("session-revoked names the grant as oauth-grant:<id>, about the " +
        "person, initiating_entity user", function () {
    assert.ok(hits[0], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
    const sub = hits[0].sub_id;
    assert.strictEqual(sub.user.format, "iss_sub", JSON.stringify(sub));
    assert.ok(/^urn:uuid:/.test(String(sub.user.sub)), JSON.stringify(sub));
  });
  announced.push(sessionIdOf(hits[0]));
  await new Promise(function (r) { setTimeout(r, 1500); });
  (await drain(token, streamId)).forEach(function (one) {
    SEEN.push(one);
  });
  check("ONE event for the grant, though the revocation took its refresh " +
        "token and the access token minted beside it", function () {
    const same = SEEN.slice(mark).filter(function (set) {
      return !!eventOf(set, "session-revoked") &&
             sessionIdOf(set) === announced[0];
    });
    assert.strictEqual(same.length, 1, JSON.stringify(same).slice(0, 800));
  });

  log.info("=== b. a rotated refresh token, replayed ===");
  const second = await codeGrant(b);
  const rotated = await refresh(second.refresh_token);
  check("the refresh rotates the token", function () {
    assert.strictEqual(rotated.status, 200, rotated.raw.slice(0, 300));
    assert.ok(rotated.body.refresh_token &&
              rotated.body.refresh_token !== second.refresh_token);
  });
  mark = SEEN.length;
  const replayed = await refresh(second.refresh_token);
  check("the replay is refused", function () {
    assert.strictEqual(replayed.status, 400, replayed.raw.slice(0, 300));
    assert.strictEqual(replayed.body.error, "invalid_grant");
  });
  hits = await waitFor(token, streamId, "the replay", [
    function (set) {
      const ev = eventOf(set, "risk-level-change");
      return !!ev && ev.current_level === "HIGH" &&
             ev.principal === "SESSION" &&
             ev.risk_reason === "refresh-token-replay" &&
             sessionIdOf(set).indexOf("oauth-grant:") === 0;
    },
    grantRevoked("policy", announced)
  ], mark);
  check("risk-level-change (SESSION, HIGH, refresh-token-replay) about the " +
        "grant", function () {
    assert.ok(hits[0], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
    assert.strictEqual(eventOf(hits[0], "risk-level-change")
      .initiating_entity, "policy");
  });
  check("and session-revoked about the same grant, initiating_entity " +
        "policy", function () {
    assert.ok(hits[1], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
    assert.strictEqual(sessionIdOf(hits[0]), sessionIdOf(hits[1]));
  });
  announced.push(sessionIdOf(hits[1]));

  log.info("=== c. /admin-api/tokens revokes everything the person holds ===");
  await codeGrant(b);
  mark = SEEN.length;
  await ok(api + "/tokens/revoke-user", { user: ALICE },
           "revoked everything " + ALICE + " holds");
  hits = await waitFor(token, streamId, "the admin revocation",
                       [grantRevoked("admin", announced)], mark);
  check("session-revoked for the grant still live, initiating_entity admin",
        function () {
    assert.ok(hits[0], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
  });

  log.info("=== d. CIBA: the approval, and the session the tokens rest on " +
           "===");
  const asked = await postForm(base + "/oauth2/bc-authorize", {
    client_id: CLIENT, client_secret: SECRET, scope: "openid",
    login_hint: ALICE });
  const reqId = asked.body && asked.body.auth_req_id;
  check("the backchannel request is acknowledged", function () {
    assert.strictEqual(asked.status, 200, asked.raw.slice(0, 300));
  });
  const page = await follow(b, R + "/portal/ciba");
  const csrf = (/name="csrf_token" value="([^"]+)"/.exec(page.text) ||
                [])[1] || "";
  mark = SEEN.length;
  const approved = await b.go("POST", R + "/portal/ciba", form({
    action: "approve", id: reqId, csrf_token: csrf }));
  check("the person approves on /portal/ciba", function () {
    assert.strictEqual(approved.status, 303, approved.text.slice(0, 300));
  });
  hits = await waitFor(token, streamId, "the CIBA presentation",
                       [presentedVia("CIBA")], mark);
  check("the approval is session-presented, naming CIBA", function () {
    assert.ok(hits[0], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
  });
  const cibaTokens = await postForm(base + "/oauth2/token", {
    grant_type: CIBA, auth_req_id: reqId, client_id: CLIENT,
    client_secret: SECRET });
  check("the CIBA tokens are issued, with a refresh token", function () {
    assert.strictEqual(cibaTokens.status, 200, cibaTokens.raw.slice(0, 300));
    assert.ok(cibaTokens.body.refresh_token, cibaTokens.raw.slice(0, 300));
  });
  const sessions = await send(api + "/sessions?q=" +
                              encodeURIComponent(ALICE));
  const rows = ((sessions.body && (sessions.body.rows ||
                                   sessions.body.sessions)) || [])
    .filter(function (row) {
      return String(row.id || "").indexOf("session:") === 0;
    });
  check("the person's sign-on session is listed", function () {
    assert.ok(rows.length >= 1, sessions.raw.slice(0, 800));
  });
  const sessionId = String(rows[0].sessionId ||
                           String(rows[0].id).slice("session:".length));
  const under = await send(api + "/tokens?session=" +
                           encodeURIComponent(sessionId));
  check("the CIBA tokens are listed UNDER that sign-on session", function () {
    assert.strictEqual(under.status, 200, under.raw.slice(0, 300));
    assert.ok(/ciba/i.test(under.raw), under.raw.slice(0, 1200));
  });

  if (product) {
    log.info("=== e. a pre-authorized OpenID4VCI offer (product) ===");
    mark = SEEN.length;
    const offered = await b.go("GET", R + "/issuer/offer?mode=cross-device");
    check("the cross-device offer is made for the signed-in person",
          function () {
      assert.strictEqual(offered.status, 200, offered.text.slice(0, 300));
    });
    hits = await waitFor(token, streamId, "the offer's presentation",
                         [presentedVia("OpenID4VCI")], mark);
    check("the offer is session-presented, naming OpenID4VCI", function () {
      assert.ok(hits[0], JSON.stringify(SEEN.slice(mark)).slice(0, 1500));
    });
  } else {
    log.info("=== e. skipped: development mints the pre-authorized offer " +
             "for a fixed test person and reads no session ===");
  }

  log.info("=== d, continued. the approving session ends ===");
  await ok(api + "/sessions/revoke", { key: rows[0].key,
    select: rows[0].id }, "ended the sign-on session");
  const introspected = await postForm(base + "/oauth2/introspect", {
    token: cibaTokens.body.refresh_token, client_id: CLIENT,
    client_secret: SECRET });
  check("the CIBA refresh token is inactive once the session it was " +
        "approved on has ended", function () {
    assert.strictEqual(introspected.status, 200,
                       introspected.raw.slice(0, 300));
    assert.strictEqual(introspected.body.active, false,
                       introspected.raw.slice(0, 300));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_caep_oauth_grants FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
