"use strict";
//
// File: sts_second_factor_doors.js
//
// ---------------------------------------------------------------------------
// THE FIVE PASSWORD-ONLY DOORS AND APP PASSWORDS, OVER THE WIRE (#101,
// 2026-09-22).
//
// In a throwaway trust realm it leaves behind (tests/CLAUDE.md), with a poll
// stream that takes CAEP credential-change:
//
//   0. a person makes an APP PASSWORD on /portal/app-passwords after signing
//      in: a real form with a real submit button and no script, the password
//      shown once on the 200, `Cache-Control: no-store`;
//   1. a second factor is then REQUIRED of them (/admin-api/users/
//      require-mfa), and at each of the five doors — an LDAPS simple bind, a
//      WS-Security UsernameToken, SCIM Basic, SSF Basic and EST Basic — in
//      PRODUCT mode their own right password is refused with EXACTLY the
//      answer a wrong password gets, while in DEVELOPMENT it is accepted as
//      every password is; the app password is accepted at every door it
//      names in both modes; and a person with no second factor is accepted
//      with their password in both;
//   2. in product, the app password is refused at the sign-in screen, and an
//      app password is refused at a door outside its scope;
//      (and GET /admin-api/users/app-passwords records its last use, pages
//      the list and carries no hash);
//   3. an administrator makes one through /admin-api (answered once),
//      scoped to one door, which a password reset leaves working, and
//      revokes it — each a CAEP credential-change on the stream;
//   4. a disabled account is refused its app password, in both modes;
//   5. `authn.passwordAloneDoors` admits the doors it lists, and only them;
//   6. the person revokes theirs on the portal — a credential-change
//      initiated by the user — and cannot revoke an id they do not hold.
//
// LDAP is reached on the service's host at 636, or where STS_LDAPS_PORT /
// STS_LDAPS_URL say (sts_ldaps.js's convention).
//
// OWNED HERE (local: true): this repository's own doors, portal and API.
// ---------------------------------------------------------------------------
const assert = require("assert");
const ldapjs = require("ldapjs");
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
var log = bunyan.createLogger({ name: "sts_second_factor_doors",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

const STAMP = names.runStamp();
const REALM = ("sfd101-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "sfd-101-" + String(Date.now()).slice(-8) + "-secret";
const RECEIVER = "sfd101-rx-" + STAMP.toLowerCase();
const APPLIES_TO = "https://wstrust.sfd101.example.test/" + STAMP;
const PASSWORD = "Sfd-101-Passw0rd!-" + String(Date.now()).slice(-6);
const WRONG = PASSWORD + "-not-it";
const ALICE = names.usernameFor("sfd-alice");     // portal-made app password
const BOB = names.usernameFor("sfd-bob");         // API-made, scim only
const CAROL = names.usernameFor("sfd-carol");     // no second factor
const DOORS = ["ldap", "wstrust", "scim", "ssf", "est"];

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
    // Not JSON — a page or a SOAP envelope; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
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

// Put a setting back: reset, never a write of the old value (tests/CLAUDE.md).
async function resetSetting(key) {
  log.debug("Entering resetSetting(). " + key);
  try {
    await postJson(realmApi + "/config/reset", { key: key });
  } catch (e) {
    log.warn("could not reset " + key + ": " + ((e && e.message) || e));
  }
  log.debug("Leaving resetSetting().");
}

// ---------------------------------------------------------------------------
// ONE BROWSER, with a cookie jar and manual redirects.
// ---------------------------------------------------------------------------
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
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

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// Signs `who` in to a portal page, following the code flow: the page, the
// authorization endpoint, the sign-in screen, the callback, the page again.
// Answers the browser and the page's final 200.
async function portalSignIn(who, path) {
  log.debug("Entering portalSignIn(). " + who);
  const b = browser(who);
  let r = await b.go("GET", path);
  for (let hop = 0; hop < 12 && r.status !== 200; hop++) {
    assert.ok(r.status === 302 || r.status === 303,
      "signing in to " + path + " stopped at " + r.status + " " +
      r.text.slice(0, 300));
    r = await b.go("GET", r.location);
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = who;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
    }
  }
  assert.strictEqual(r.status, 200, "the signed-in page: " + r.status);
  log.debug("Leaving portalSignIn().");
  return { b: b, page: r };
}

// ---------------------------------------------------------------------------
// THE FIVE DOORS. Each answers a comparable `{ accepted, answer }`: `answer`
// is what a client sees, normalised only of what differs between two
// identical refusals (a SOAP message id, a timestamp), so that "the same
// answer as a wrong password" is a string comparison.
// ---------------------------------------------------------------------------
function basic(user, password) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(user + ":" + password).toString("base64");
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + new URL(base).hostname + ":" +
     (process.env.STS_LDAPS_PORT || 636));
}

function personDn(who) {
  log.debug("Entering personDn().");
  log.debug("Leaving personDn().");
  return "uid=" + who + ",ou=users," + DOMAIN.split(".").map(function (one) {
    return "dc=" + one;
  }).join(",");
}

function ldapBind(who, password) {
  log.debug("Entering ldapBind(). " + who);
  return new Promise(function (resolve) {
    const url = ldapsUrl();
    const client = ldapjs.createClient({
      url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
      tlsOptions: { servername: new URL(url).hostname,
                    rejectUnauthorized:
                      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" }
    });
    client.on("error", function (e) {
      // ldapjs also emits on the client; the bind's callback reports it.
      log.debug("The LDAP client emitted an error: " + e.message);
    });
    client.bind(personDn(who), password, function (e) {
      const out = e ? { accepted: false, answer: "ldap " + e.code + " " +
                        String(e.name) }
                    : { accepted: true, answer: "ldap 0" };
      try {
        client.unbind(function () {
          client.destroy();
        });
      } catch (x) {
        // An unbind on a connection the server already closed.
        log.debug("Caught in ldapBind(): " + ((x && x.message) || x));
      }
      log.debug("Leaving ldapBind(). " + out.answer);
      resolve(out);
    });
  });
}

async function wsTrust(who, password) {
  log.debug("Entering wsTrust(). " + who);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + who + '</wsse:Username>' +
    '<wsse:Password>' + password +
    '</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    APPLIES_TO + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const r = await send(realmBase + "/sts", { method: "POST",
    headers: { "Content-Type": "application/soap+xml" }, body: rst });
  const accepted = r.status === 200 && /Assertion/.test(r.raw);
  log.debug("Leaving wsTrust(). " + r.status);
  return { accepted: accepted,
           answer: r.status + " " + String(r.raw)
             .replace(/(uuid|urn:uuid):[0-9a-f-]+/gi, "ID")
             .replace(/_[0-9a-f]{16,}/gi, "ID")
             .replace(/\d{4}-\d\d-\d\dT[\d:.]+Z/g, "TIME") };
}

async function scim(who, password) {
  log.debug("Entering scim(). " + who);
  const r = await send(realmBase + "/scim/v2/Users?count=1",
    { headers: { Authorization: basic(who, password),
                 Accept: "application/scim+json" } });
  log.debug("Leaving scim(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

async function ssf(who, password) {
  log.debug("Entering ssf(). " + who);
  const r = await send(realmBase + "/ssf/stream",
    { headers: { Authorization: basic(who, password) } });
  log.debug("Leaving ssf(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

// A body that is not a certificate request: an authenticated caller is
// answered 400 about the body, an unauthenticated one 401 before it is read.
async function est(who, password) {
  log.debug("Entering est(). " + who);
  const r = await send(realmBase + "/.well-known/est/simpleenroll", {
    method: "POST", headers: { Authorization: basic(who, password),
                               "Content-Type": "application/pkcs10" },
    body: "not-a-certificate-request" });
  log.debug("Leaving est(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

const DOOR = { ldap: ldapBind, wstrust: wsTrust, scim: scim, ssf: ssf,
               est: est };

// ---------------------------------------------------------------------------
// THE STREAM, for the credential-change events.
// ---------------------------------------------------------------------------
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

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(realmBase + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: streamId,
      returnImmediately: true, maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = (r.body && r.body.sets) || {};
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

const SEEN = [];
async function waitForChange(token, streamId, friendlyName, changeType) {
  log.debug("Entering waitForChange(). " + friendlyName + " " + changeType);
  const matches = function (set) {
    const ev = ((set && set.events) || {})[CAEP + "credential-change"];
    return !!ev && ev.friendly_name === friendlyName &&
           ev.change_type === changeType && ev.credential_type === "password";
  };
  for (let i = 0; i < 24; i++) {
    (await drain(token, streamId)).forEach(function (one) {
      SEEN.push(one);
    });
    const hit = SEEN.filter(matches)[0];
    if (hit) {
      log.debug("Leaving waitForChange(). Found.");
      return hit.events[CAEP + "credential-change"];
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitForChange(). Not found.");
  return null;
}

// ---------------------------------------------------------------------------
// THE ASSERTIONS ABOUT ONE DOOR.
// ---------------------------------------------------------------------------
async function refusedLikeWrong(door, who) {
  log.debug("Entering refusedLikeWrong(). " + door + " " + who);
  const right = await DOOR[door](who, PASSWORD);
  const wrong = await DOOR[door](who, WRONG);
  check(door + ": " + who + "'s RIGHT password is refused, with exactly the " +
        "answer a wrong password gets", function () {
    assert.ok(!right.accepted, "accepted: " + right.answer.slice(0, 300));
    assert.ok(!wrong.accepted, "a wrong password was accepted: " +
              wrong.answer.slice(0, 300));
    assert.strictEqual(right.answer, wrong.answer,
      "the refusal is distinguishable from a wrong password, which makes " +
      "it a password oracle");
  });
  log.debug("Leaving refusedLikeWrong().");
}

async function accepted(door, who, password, what) {
  log.debug("Entering accepted(). " + door + " " + who);
  const r = await DOOR[door](who, password);
  check(door + ": " + what, function () {
    assert.ok(r.accepted, r.answer.slice(0, 400));
  });
  log.debug("Leaving accepted().");
}

async function refused(door, who, password, what) {
  log.debug("Entering refused(). " + door + " " + who);
  const r = await DOOR[door](who, password);
  check(door + ": " + what, function () {
    assert.ok(!r.accepted, r.answer.slice(0, 400));
  });
  log.debug("Leaving refused().");
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(base + "/admin-api");
  log.info("Driving " + base + " (" + (product ? "product" :
           "development") + " mode) in the trust realm \"" + REALM + "\".");

  // -------------------------------------------------------------------------
  log.info("=== setup: the realm, the stream, the people ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Second-factor doors " + STAMP }, "created the realm");
  // This job refuses many binds and enrollments on purpose, from one address.
  await ok(realmApi + "/config/set", { key: "est.attemptsPerAddress",
                                       value: 100000 }, "raised EST's limit");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the stream's receiver");
  await ok(realmApi + "/applications/create", { identifier: APPLIES_TO,
    name: "sfd101 relying party", protocols: ["wstrust"],
    fields: { wstrustAppliesTo: [APPLIES_TO] } },
    "registered the WS-Trust relying party");
  const token = await tokenFor("ssf:read ssf:write");
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: [CAEP + "credential-change"] }) });
  assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
  const streamId = created.body.stream_id;
  for (const who of [ALICE, BOB, CAROL]) {
    await ok(realmApi + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "SFD " + who, givenName: "SFD", sn: who,
                    mail: who + "@sfd101.test" } }, "created " + who);
  }

  // -------------------------------------------------------------------------
  log.info("=== 0. the portal: a person makes an app password ===");
  const PAGE = R + "/portal/app-passwords";
  const signed = await portalSignIn(ALICE, PAGE);
  const b = signed.b;
  check("/portal/app-passwords draws a form with a REAL submit button and " +
        "no script", function () {
    assert.ok(/<button type="submit">Make an app password<\/button>/
      .test(signed.page.text), signed.page.text.slice(0, 600));
    assert.ok(!/<script/i.test(signed.page.text),
              "the page carries a script");
    DOORS.forEach(function (door) {
      assert.ok(signed.page.text.indexOf('name="door_' + door + '"') >= 0,
                "no checkbox for " + door);
    });
  });
  const madeName = "portal client " + STAMP;
  const made = await b.go("POST", PAGE, form({ action: "create",
    name: madeName, door_ldap: "on", door_wstrust: "on", door_scim: "on",
    door_ssf: "on", door_est: "on", csrf_token: csrfOf(signed.page.text) }));
  const shown = (made.text.match(
    /<code class="app-password">([A-Z2-7-]+)<\/code>/) || [])[1] || "";
  check("making one answers 200 with the password ONCE, not in a redirect, " +
        "no-store", function () {
    assert.strictEqual(made.status, 200, made.text.slice(0, 400));
    assert.ok(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/.test(shown),
              "no app password on the page: " + made.text.slice(0, 800));
    assert.ok(/no-store/.test(String(made.headers.get("cache-control"))));
  });
  const again = await b.go("GET", PAGE);
  check("the list shows it by name and id, and never the password again",
        function () {
    assert.ok(again.text.indexOf(madeName) >= 0);
    assert.ok(again.text.indexOf(shown.slice(0, 4)) >= 0);
    assert.ok(again.text.indexOf(shown) < 0,
              "the password is on the page a second time");
  });
  let ev = await waitForChange(token, streamId, madeName, "create");
  check("CAEP credential-change (password, create) went out, initiated by " +
        "the user", function () {
    assert.ok(ev, JSON.stringify(SEEN).slice(0, 800));
    assert.strictEqual(ev.initiating_entity, "user");
  });

  // -------------------------------------------------------------------------
  log.info("=== 1. a second factor is required: the five doors ===");
  await ok(realmApi + "/users/require-mfa", { user: ALICE },
           "required a second factor of " + ALICE);
  for (const door of DOORS) {
    if (product) {
      await refusedLikeWrong(door, ALICE);
    } else {
      await accepted(door, ALICE, PASSWORD, "DEVELOPMENT accepts " + ALICE +
                     "'s own password, as it accepts every password");
    }
    await accepted(door, ALICE, shown, "the app password is accepted");
    await accepted(door, CAROL, PASSWORD, "a person with no second factor " +
                   "is accepted with their password");
  }
  const doors = await send(realmApi + "/users/app-passwords?user=" +
                           encodeURIComponent(ALICE));
  check("GET /admin-api/users/app-passwords says which doors refuse the " +
        "password, and (in product) records the last use", function () {
    assert.strictEqual(doors.status, 200, doors.raw.slice(0, 300));
    assert.deepStrictEqual(doors.body.passwordOnlyDoors.refused,
                           product ? DOORS : []);
    // Development checks no password, so it never gets as far as asking
    // which app password was presented; product records the use.
    assert.ok(!product || doors.body.passwords[0].lastUsedAt > 0,
              JSON.stringify(doors.body.passwords));
    assert.ok(doors.raw.indexOf("$scrypt$") < 0 &&
              doors.raw.indexOf(shown) < 0, "a hash or the password leaked");
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. never at the sign-in screen ===");
  if (product) {
    const s = browser("app-at-login");
    let r = await s.go("GET", R + "/portal");
    for (let hop = 0; hop < 6 && !/name="authn_id"/.test(r.text); hop++) {
      r = await s.go("GET", r.location);
    }
    const fields = hiddenFields(r.text);
    fields.username = ALICE;
    fields.password = shown;
    fields.action = "login";
    const posted = await s.go("POST", R + "/authn/login", form(fields));
    check("the app password is REFUSED at the sign-in screen", function () {
      assert.strictEqual(posted.status, 200,
                         "the screen let it through: " + posted.location);
      assert.ok(/Authentication failed/.test(posted.text),
                posted.text.slice(0, 400));
    });
  } else {
    log.info("  (development checks no password at the sign-in screen)");
  }

  // -------------------------------------------------------------------------
  log.info("=== 3. an administrator's app password, scoped to SCIM ===");
  await ok(realmApi + "/users/require-mfa", { user: BOB },
           "required a second factor of " + BOB);
  const bobName = "scim job " + STAMP;
  const byApi = await ok(realmApi + "/users/create-app-password",
    { user: BOB, name: bobName, doors: ["scim"] }, "made BOB's");
  check("POST /admin-api/users/create-app-password answers it once, scoped",
        function () {
    assert.ok(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/.test(byApi.appPassword),
              JSON.stringify(byApi));
    assert.deepStrictEqual(byApi.doors, ["scim"]);
  });
  ev = await waitForChange(token, streamId, bobName, "create");
  check("and says so: credential-change (password, create), by the admin",
        function () {
    assert.ok(ev, JSON.stringify(SEEN).slice(0, 800));
    assert.strictEqual(ev.initiating_entity, "admin");
  });
  await accepted("scim", BOB, byApi.appPassword, "BOB's app password");
  if (product) {
    await refused("ssf", BOB, byApi.appPassword, "but NOT at a door " +
                  "outside its scope");
  }
  const reset = await ok(realmApi + "/users/reset-password", { user: BOB },
                         "reset BOB's password");
  check("(the reset answered a new password)", function () {
    assert.ok(reset.password);
  });
  await accepted("scim", BOB, byApi.appPassword,
                 "a password reset leaves the app password working");
  const listed = await send(realmApi + "/users/app-passwords?per=1&user=" +
                            encodeURIComponent(BOB));
  check("the list pages (`per`, `page`)", function () {
    assert.strictEqual(listed.body.total, 1);
    assert.strictEqual(listed.body.perPage, 1);
  });
  await ok(realmApi + "/users/revoke-app-password",
           { user: BOB, id: byApi.id }, "revoked BOB's");
  ev = await waitForChange(token, streamId, bobName, "revoke");
  check("a revoke says so: credential-change (password, revoke)",
        function () {
    assert.ok(ev, JSON.stringify(SEEN).slice(0, 800));
  });
  if (product) {
    await refused("scim", BOB, byApi.appPassword, "and a revoked app " +
                  "password is refused");
  }

  // -------------------------------------------------------------------------
  log.info("=== 4. a disabled account ===");
  const carolName = "disabled check " + STAMP;
  const carols = await ok(realmApi + "/users/create-app-password",
    { user: CAROL, name: carolName, doors: ["scim"] }, "made CAROL's");
  await ok(realmApi + "/users/disable", { user: CAROL }, "disabled CAROL");
  await refused("scim", CAROL, carols.appPassword, "a disabled account is " +
                "refused its app password, in every mode");
  await ok(realmApi + "/users/enable", { user: CAROL }, "enabled CAROL");
  await accepted("scim", CAROL, carols.appPassword, "and enabled, it works " +
                 "again");

  // -------------------------------------------------------------------------
  log.info("=== 5. authn.passwordAloneDoors ===");
  if (product) {
    await ok(realmApi + "/config/set", { key: "authn.passwordAloneDoors",
                                         value: "scim" }, "listed scim");
    try {
      await accepted("scim", ALICE, PASSWORD, "a listed door accepts the " +
                     "password alone");
      await refusedLikeWrong("ssf", ALICE);
    } finally {
      await resetSetting("authn.passwordAloneDoors");
    }
  }

  // -------------------------------------------------------------------------
  log.info("=== 6. the person revokes theirs on the portal ===");
  const fresh = await portalSignIn(CAROL, PAGE);
  check("(a person with no second factor can reach the page too)",
        function () {
    assert.ok(/Make an app password/.test(fresh.page.text));
  });
  const listPage = await b.go("GET", PAGE);
  const revoke = await b.go("POST", PAGE, form({ action: "revoke",
    id: shown.slice(0, 4), csrf_token: csrfOf(listPage.text) }));
  check("revoking on the portal redirects back with done=", function () {
    assert.strictEqual(revoke.status, 303, revoke.text.slice(0, 300));
  });
  ev = await waitForChange(token, streamId, madeName, "revoke");
  check("and says so over CAEP, initiated by the user", function () {
    assert.ok(ev, JSON.stringify(SEEN).slice(0, 800));
    assert.strictEqual(ev.initiating_entity, "user");
  });
  if (product) {
    await refused("scim", ALICE, shown, "the revoked app password is refused");
  }
  const notMine = await fresh.b.go("POST", PAGE, form({ action: "revoke",
    id: "ABCD", csrf_token: csrfOf(fresh.page.text) }));
  check("revoking an id the person does not hold is a 404, never an oracle",
        function () {
    assert.strictEqual(notMine.status, 404);
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_second_factor_doors FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
