"use strict";
//
// File: sts_caep_credential_changes.js
//
// ---------------------------------------------------------------------------
// CAEP FROM EVERY DOOR, OVER THE WIRE (#145, 2026-09-22).
//
// In a throwaway realm it leaves behind, with a poll stream that takes every
// CAEP type and covers everybody (an empty subject list, which
// `ssf.defaultSubjects` makes ALL):
//
//   a. a person created with a password sends credential-change (password,
//      create, admin);
//   b. a sign-in with a known User-Agent sends session-established whose
//      fp_ua is the base64url SHA-256 of that header — a fingerprint, not the
//      header — and leaves the person holding live tokens;
//   c. a SCIM change to their family name sends token-claims-change carrying
//      family_name and its new value, about the PERSON (iss_sub);
//   d. adding them to a group sends token-claims-change carrying the groups
//      claim as the whole new list;
//   e. the same change for a person who holds nothing live sends nothing;
//   f. a signing key pair issued to them on /admin-api/pki sends
//      credential-change x509 with x509_issuer and x509_serial, the serial
//      the one the issue answered with.
//
// OWNED HERE (local: true): this repository's own transmitter.
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
var log = bunyan.createLogger({ name: "sts_caep_credential_changes",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("caep145-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "caep-145-" + String(Date.now()).slice(-8);
const RECEIVER = "caep145-rx-" + STAMP.toLowerCase();
const RP = "https://rp.caep145.example.test";
const REDIRECT = RP + "/cb";
const PASSWORD = "Caep-145-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("c145-alice");
const BOB = names.usernameFor("c145-bob");
const GROUP = "c145-group-" + STAMP.toLowerCase();
const AGENT = "sts_caep_credential_changes/1.0 (" + STAMP + ")";

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
    domain: REALM + ".example.net", name: "CAEP 145 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    // The Shared Signals and SCIM scopes are issued only to a client that
    // declares them (#110), and in product a declared list is the whole of
    // what the client may be issued.
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
      events_requested: [CAEP + "credential-change",
                         CAEP + "token-claims-change",
                         CAEP + "session-established"] }) });
  check("a poll stream takes credential-change, token-claims-change and " +
        "session-established", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
    const delivered = created.body.events_delivered || [];
    assert.ok(delivered.indexOf(CAEP + "token-claims-change") >= 0 &&
              delivered.indexOf(CAEP + "credential-change") >= 0,
              JSON.stringify(delivered));
  });
  const streamId = created.body.stream_id;

  log.info("=== a. a person created with a password ===");
  for (const who of [ALICE, BOB]) {
    await ok(realmApi + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "CAEP " + who, givenName: "CAEP", sn: "Before",
                    mail: who + "@caep145.test" } }, "created " + who);
  }
  const scimToken = await tokenFor("scim:read scim:write");
  const scimAuth = { Authorization: "Bearer " + scimToken };
  for (const who of [ALICE, BOB]) {
    SUBJECTS[who] = "urn:uuid:" + await scimIdOf(scimAuth, who);
  }
  let found = await waitFor(token, streamId, "password create",
    function (set) {
      const ev = eventOf(set, "credential-change");
      return !!ev && ev.credential_type === "password" &&
             ev.change_type === "create" && aboutUser(set, ALICE);
    });
  check("credential-change: password, create, initiated by admin",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      assert.strictEqual(eventOf(found.hit, "credential-change")
        .initiating_entity, "admin");
    });

  log.info("=== b. a sign-in with a known User-Agent ===");
  const b = browser("alice");
  const params = { response_type: "code", client_id: RECEIVER,
    redirect_uri: REDIRECT, scope: "openid profile", state: "st",
    nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" };
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  const page = await b.go("GET", r.location);
  const fields = hiddenFields(page.text);
  fields.username = ALICE;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  r = await b.go("GET", posted.location);
  const code = r.location ? new URL(r.location).searchParams.get("code") : "";
  check("the sign-in reaches the client with a code", function () {
    assert.ok(code, r.status + " " + r.location);
  });
  const redeemed = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, client_id: RECEIVER,
                 client_secret: SECRET, code_verifier: "v".repeat(43) }) });
  check("and the code is redeemed: alice holds live tokens", function () {
    assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
  });
  const fingerprint = nodeCrypto.createHash("sha256").update(AGENT, "utf8")
    .digest("base64url");
  found = await waitFor(token, streamId, "session-established",
    function (set) {
      return !!eventOf(set, "session-established") && aboutUser(set, ALICE);
    });
  check("session-established carries fp_ua, the SHA-256 of the " +
        "User-Agent, not the header", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    const ev = eventOf(found.hit, "session-established");
    assert.strictEqual(ev.fp_ua, fingerprint, JSON.stringify(ev));
  });

  log.info("=== c. a SCIM change to the family name ===");
  const scimId = SUBJECTS[ALICE].slice("urn:uuid:".length);
  const patched = await send(realmBase + "/scim/v2/Users/" + scimId, {
    method: "PATCH", headers: Object.assign({ "Content-Type":
      "application/scim+json" }, scimAuth),
    body: JSON.stringify({ schemas:
      ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "name.familyName",
                     value: "After" }] }) });
  check("the PATCH is applied", function () {
    assert.ok(patched.status === 200 || patched.status === 204,
              patched.status + " " + patched.raw.slice(0, 300));
  });
  found = await waitFor(token, streamId, "family_name change",
    function (set) {
      const ev = eventOf(set, "token-claims-change");
      return !!ev && ev.claims && ev.claims.family_name === "After";
    });
  check("token-claims-change carries family_name with its new value, " +
        "about the person", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    assert.ok(aboutUser(found.hit, ALICE), JSON.stringify(found.hit.sub_id));
  });

  log.info("=== d. a group joined ===");
  await ok(realmApi + "/groups/create", { group: GROUP }, "created a group");
  await ok(realmApi + "/groups/add-member", { group: GROUP, member: ALICE },
           "added alice to it");
  found = await waitFor(token, streamId, "groups change", function (set) {
    const ev = eventOf(set, "token-claims-change");
    return !!ev && ev.claims && Object.keys(ev.claims).some(function (k) {
      return Array.isArray(ev.claims[k]) &&
             ev.claims[k].join(" ").indexOf(GROUP) >= 0;
    });
  });
  check("token-claims-change carries the groups claim as the whole new " +
        "list", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });

  log.info("=== e. nothing live, nothing sent ===");
  await ok(realmApi + "/groups/add-member", { group: GROUP, member: BOB },
           "added bob, who holds nothing live");
  found = await waitFor(token, streamId, "bob's change", function (set) {
    return !!eventOf(set, "token-claims-change") && aboutUser(set, BOB);
  });
  check("no token-claims-change is sent about a person with no live " +
        "tokens", function () {
    assert.strictEqual(found.hit, null, JSON.stringify(found.hit));
  });

  log.info("=== f. a signing key pair issued on /admin-api/pki ===");
  const issued = await postJson(realmApi + "/pki/issue", { target: "person",
    identifier: ALICE });
  const serial = String((issued.body && (issued.body.serialHex ||
    (issued.body.issued && issued.body.issued.serialHex) ||
    (issued.body.record && issued.body.record.serialHex))) || "")
    .toLowerCase();
  check("a key pair is issued to alice", function () {
    assert.strictEqual(issued.status, 200, issued.raw.slice(0, 400));
  });
  found = await waitFor(token, streamId, "x509 create", function (set) {
    const ev = eventOf(set, "credential-change");
    return !!ev && ev.credential_type === "x509" && aboutUser(set, ALICE);
  });
  check("credential-change x509 names the certificate by issuer and serial",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = eventOf(found.hit, "credential-change");
      assert.ok(/CN=/.test(String(ev.x509_issuer)), JSON.stringify(ev));
      assert.ok(/^[0-9a-f]+$/.test(String(ev.x509_serial)),
                JSON.stringify(ev));
      if (serial) {
        assert.strictEqual(ev.x509_serial.replace(/^0+/, ""),
                           serial.replace(/^0+/, ""));
      }
    });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_caep_credential_changes FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
