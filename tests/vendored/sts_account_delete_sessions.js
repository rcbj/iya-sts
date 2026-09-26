"use strict";
//
// File: sts_account_delete_sessions.js
//
// ---------------------------------------------------------------------------
// A DELETED PERSON'S SESSION ENDS WITH THEM, OVER THE WIRE (#241, 2026-09-26).
//
// Until #241 a person deleted over SCIM (or LDAP) was sent RISC
// account-purged and nothing else: their browser session kept signing in to
// every relying party until it ran out, and no CAEP session-revoked went at
// delete time. In a throwaway realm it leaves behind, with a poll stream that
// takes session-revoked and account-purged about everybody:
//
//   a. a person signs in through the code flow, and a second authorization
//      request is answered from the session (single sign-on — the control);
//   b. SCIM DELETE of the person answers 204;
//   c. the SAME browser's next authorization request is sent to the sign-in
//      screen: the session cookie no longer signs in;
//   d. the stream holds session-revoked about the person, initiated by an
//      ADMINISTRATOR (#242), and account-purged.
//
// The back-channel Logout Token is not observed here — the suite has no
// relying party the service can reach — and is held in process by
// tests/account_delete.js (A6).
//
// OWNED HERE (local: true): this repository's directory, sessions and
// transmitter.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_account_delete_sessions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("del241-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "del-241-" + String(Date.now()).slice(-8);
const RECEIVER = "del241-rx-" + STAMP.toLowerCase();
const RP = "https://rp.del241.example.test";
const REDIRECT = RP + "/cb";
const PASSWORD = "Del-241-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("d241-alice");
// A desktop Chrome string with this job's name on the end: isbot reads a bare
// job name as an automated client, and product mode refuses a first sign-in
// from one on risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like " +
  "Gecko) Chrome/140.0.0.0 Safari/537.36 sts_account_delete_sessions/1.0 (" +
  STAMP + ")";

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

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
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
function browser(name) {
  log.debug("Entering browser(). " + name);
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
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, headers: r.headers };
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

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// Where a redirect to REDIRECT put its parameters: `{ where, params }`, or
// null when it went anywhere else.
function atClient(r, redirect) {
  log.debug("Entering atClient().");
  const target = redirect || REDIRECT;
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(target) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  const fragment = url.hash ? new URLSearchParams(url.hash.slice(1)) : null;
  log.debug("Leaving atClient().");
  return fragment && Array.from(fragment.keys()).length
    ? { where: "fragment", params: fragment }
    : { where: "query", params: url.searchParams };
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200, "the sign-in screen: " + page.status +
                     " " + page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  log.debug("Leaving signIn().");
  return posted;
}

// An authorization request; follows a sign-in when there is no session.
async function authorize(b, params, who) {
  log.debug("Entering authorize().");
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login\?authn=/.test(r.location) && who) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function tokenFor(scope) {
  log.debug("Entering tokenFor().");
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: RECEIVER,
                 client_secret: SECRET, scope: scope }) });
  assert.ok(r.body && r.body.access_token,
            "a token for " + scope + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

// Every SET waiting on the stream, decoded, and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(realmBase + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: streamId,
      returnImmediately: true, maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(realmBase + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: streamId, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// Waits for the stream to hold a SET the predicate accepts. Delivery is on a
// promise after the write answers, so a first poll may be early.
async function waitFor(token, streamId, what, predicate) {
  log.debug("Entering waitFor(). " + what);
  const seen = [];
  for (let i = 0; i < 20; i++) {
    const sets = await drain(token, streamId);
    sets.forEach(function (one) {
      seen.push(one);
    });
    const hit = seen.filter(predicate)[0];
    if (hit) {
      log.debug("Leaving waitFor(). Found.");
      return { hit: hit, seen: seen };
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return { hit: null, seen: seen };
}

function eventOf(set, type) {
  log.debug("Entering eventOf().");
  log.debug("Leaving eventOf().");
  return ((set && set.events) || {})[CAEP + type] || null;
}

// Whether a SET's subject is this person: `iss_sub` naming their `sub`, which
// is `urn:uuid:<entryUUID>` — and a SCIM id is that entryUUID.
const SUBJECTS = {};
function aboutUser(set, username) {
  log.debug("Entering aboutUser().");
  const sub = set && set.sub_id;
  const user = sub && (sub.format === "complex" ? sub.user : sub);
  log.debug("Leaving aboutUser().");
  return !!user && user.format === "iss_sub" && !!SUBJECTS[username] &&
         String(user.sub) === SUBJECTS[username];
}

// A person's SCIM id, which is their entry's entryUUID.
async function scimIdOf(scimAuth, username) {
  log.debug("Entering scimIdOf().");
  const listed = await send(realmBase + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + username + "\""),
    { headers: scimAuth });
  const id = listed.body && listed.body.Resources &&
             listed.body.Resources[0] && listed.body.Resources[0].id;
  assert.ok(id, "SCIM finds " + username + ": " + listed.status + " " +
            listed.raw.slice(0, 300));
  log.debug("Leaving scimIdOf().");
  return String(id);
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and a poll stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Delete 241 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    // The Shared Signals and SCIM scopes are issued only to a client that
    // declares them (#110).
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid", "profile", "ssf:read",
                                  "ssf:write", "scim:read", "scim:write"],
              oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code", "client_credentials"],
              oauthResponseType: ["code"] } },
    "created the receiver's application");
  for (const one of ["openid", "profile"]) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: RECEIVER, scope: one }, "consented " + one);
  }
  const token = await tokenFor("ssf:read ssf:write");
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: [CAEP + "session-revoked",
                         RISC + "account-purged"] }) });
  check("a poll stream takes session-revoked and account-purged",
    function () {
      assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
      const delivered = created.body.events_delivered || [];
      assert.ok(delivered.indexOf(CAEP + "session-revoked") >= 0 &&
                delivered.indexOf(RISC + "account-purged") >= 0,
                JSON.stringify(delivered));
    });
  const streamId = created.body.stream_id;

  await ok(realmApi + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Delete " + ALICE, givenName: "Delete", sn: "Me",
                  mail: ALICE + "@del241.test" } }, "created " + ALICE);
  const scimToken = await tokenFor("scim:read scim:write");
  const scimAuth = { Authorization: "Bearer " + scimToken };
  const scimId = await scimIdOf(scimAuth, ALICE);
  SUBJECTS[ALICE] = "urn:uuid:" + scimId;

  log.info("=== a. a sign-in, and single sign-on on it (the control) ===");
  const b = browser("alice");
  const challenge = nodeCrypto.createHash("sha256").update("v".repeat(43))
    .digest("base64url");
  const params = function () {
    return { response_type: "code", client_id: RECEIVER,
      redirect_uri: REDIRECT, scope: "openid profile", state: "st",
      nonce: "n-" + nodeCrypto.randomBytes(4).toString("hex"),
      code_challenge: challenge, code_challenge_method: "S256" };
  };
  let r = await authorize(b, params(), ALICE);
  check("the sign-in reaches the client with a code", function () {
    const at = atClient(r);
    assert.ok(at && at.params.get("code"), r.status + " " + r.location);
  });
  r = await b.go("GET", R + "/oauth2/authorize?" + form(params()));
  check("a second authorization request is answered from the session, " +
        "with no screen — single sign-on, before the delete", function () {
    const at = atClient(r);
    assert.ok(at && at.params.get("code"), r.status + " " + r.location);
  });

  log.info("=== b. SCIM DELETE ===");
  const deleted = await send(realmBase + "/scim/v2/Users/" + scimId,
                             { method: "DELETE", headers: scimAuth });
  check("SCIM DELETE answers 204", function () {
    assert.strictEqual(deleted.status, 204, deleted.raw.slice(0, 300));
  });

  log.info("=== c. the old session cookie no longer signs in ===");
  let refused = null;
  for (let i = 0; i < 20 && !refused; i++) {
    const again = await b.go("GET", R + "/oauth2/authorize?" + form(params()));
    if ((again.status === 302 || again.status === 303) &&
        /\/authn\/login\?authn=/.test(again.location)) {
      refused = again;
    } else {
      await new Promise(function (res) { setTimeout(res, 250); });
    }
  }
  check("the same browser is sent to the sign-in screen: the deleted " +
        "person's session is over", function () {
    assert.ok(refused, "the session was still honoured after the delete");
  });

  log.info("=== d. what the stream was told ===");
  let found = await waitFor(token, streamId, "session-revoked",
    function (set) {
      return !!eventOf(set, "session-revoked") && aboutUser(set, ALICE);
    });
  check("session-revoked about the deleted person, initiated by an " +
        "ADMINISTRATOR", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    assert.strictEqual(eventOf(found.hit, "session-revoked")
      .initiating_entity, "admin");
  });
  const seen = found.seen;
  found = await waitFor(token, streamId, "account-purged", function (set) {
    return !!((set && set.events) || {})[RISC + "account-purged"];
  });
  check("and account-purged", function () {
    assert.ok(found.hit || seen.some(function (set) {
      return !!((set && set.events) || {})[RISC + "account-purged"];
    }), JSON.stringify(found.seen.concat(seen)).slice(0, 1200));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_account_delete_sessions FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
