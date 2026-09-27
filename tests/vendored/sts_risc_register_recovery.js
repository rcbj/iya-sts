"use strict";
//
// File: sts_risc_register_recovery.js
//
// ---------------------------------------------------------------------------
// RISC: THE HOLDER'S OPT STATE, IDENTIFIERS AS SETS, AND RECOVERY, OVER THE
// WIRE (#233, #234, #235, 2026-09-26).
//
// In a throwaway realm it leaves behind, with a poll stream taking every RISC
// type and covering everybody:
//
//   1. #233 — an administrator's register reset and clear never move the
//      account holder's section 2.8 choice: a pending opt-out survives both
//      and still becomes effective on the risc.opt-out-effective job; an
//      effective one survives both too.
//   2. #234 — every value of `mail`, `telephoneNumber` and `mobile` compared
//      as a set, written over SCIM: a SECOND address changed and a `mobile`
//      changed beside a `telephoneNumber` are each identifier-changed; an
//      address REMOVED is identifier-changed with no `new-value`; and a new
//      account given that removed address is identifier-recycled.
//   3. #235 — a first address set by an administrator is
//      recovery-information-changed; a changed one is identifier-changed AND
//      recovery-information-changed; an activation link for somebody who
//      exists is recovery-activated and account-credential-change-required;
//      and a recovery code spent at sign-in is recovery-information-changed
//      and recovery-activated.
//
// The recovery code spent on /portal/forgot-password and the portal's
// verification link are in process (`tests/mail.js` 15f,
// `tests/risc_identifiers_recovery.js` B3 and B6): both need a mail catcher
// this job does not.
//
// OWNED HERE (local: true): this repository's own transmitter, portal and
// sign-in.
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
var log = bunyan.createLogger({ name: "sts_risc_register_recovery",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("risc233-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "risc-233-" + String(Date.now()).slice(-8);
const RECEIVER = "risc233-rx-" + STAMP.toLowerCase();
const PASSWORD = "Risc-233-Passw0rd!-" + String(Date.now()).slice(-6);
const EVE = names.usernameFor("r233-eve");
const SID = names.usernameFor("r233-sid");
const TIM = names.usernameFor("r233-tim");
const UMA = names.usernameFor("r233-uma");
const VIC = names.usernameFor("r233-vic");
const WYN = names.usernameFor("r233-wyn");
const DOMAIN = "risc233-" + STAMP.toLowerCase() + ".test";
// A desktop Chrome string, with this job's own name on the end: isbot reads
// the bare name as an automated client, and product mode refuses a first
// sign-in from one on risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like " +
  "Gecko) Chrome/140.0.0.0 Safari/537.36 sts_risc_register_recovery/1.0";

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
// Everything drained and not yet matched. A drain acknowledges every SET it
// reads, so events that arrive together (a reset link sends three) must be
// kept for the waits that follow, and a matched one is taken out so that two
// waits for the same type find two events.
const POOL = [];
async function waitFor(token, streamId, what, predicate, tries) {
  log.debug("Entering waitFor(). " + what);
  for (let i = 0; i < (tries || 20); i++) {
    (await drain(token, streamId)).forEach(function (one) {
      POOL.push(one);
    });
    const at = POOL.findIndex(predicate);
    if (at >= 0) {
      const hit = POOL.splice(at, 1)[0];
      log.debug("Leaving waitFor(). Found.");
      return { hit: hit, seen: POOL.slice() };
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return { hit: null, seen: POOL.slice() };
}

function riscEvent(set, type) {
  log.debug("Entering riscEvent().");
  log.debug("Leaving riscEvent().");
  return ((set && set.events) || {})[RISC + type] || null;
}

function userOf(set) {
  log.debug("Entering userOf().");
  const sub = set && set.sub_id;
  log.debug("Leaving userOf().");
  return sub && sub.format === "complex" ? sub.user : sub;
}

async function signInToPortal(who) {
  log.debug("Entering signInToPortal().");
  const b = browser(who);
  let r = await b.go("GET", R + "/portal");
  for (let i = 0; i < 8 && (r.status === 302 || r.status === 303); i++) {
    if (/\/authn\/login\?authn=/.test(r.location)) {
      const page = await b.go("GET", r.location);
      const fields = hiddenFields(page.text);
      fields.username = who;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
      continue;
    }
    r = await b.go("GET", r.location);
  }
  assert.strictEqual(r.status, 200, "the portal after sign-in: " + r.status +
                     " " + r.location + " " + String(r.text).slice(0, 300));
  log.debug("Leaving signInToPortal().");
  return b;
}

// POST one opt-out move from the page's own form (and its CSRF token).
async function move(b, which) {
  log.debug("Entering move(). " + which);
  const page = await b.go("GET", R + "/portal/signals");
  const csrf = (String(page.text)
    .match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
  const r = await b.go("POST", R + "/portal/signals",
                       form({ move: which, csrf_token: csrf }));
  log.debug("Leaving move(). " + r.status);
  return r;
}

// ---------------------------------------------------------------------------
// THE JOB'S OWN RFC 6238, for `sts_portal_backup_codes.js`'s reason: a
// recovery code is reached from the one-time code screen, and only a person
// with an enrolled authenticator is sent there. Scaffolding, not a subject:
// `sts_portal_totp.js` holds the arithmetic to the RFC's vectors.
// ---------------------------------------------------------------------------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    const index = B32.indexOf(cleaned[i]);
    assert.ok(index >= 0, "the secret shown is not base32: " + cleaned[i]);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

function totpFor(secret) {
  log.debug("Entering totpFor().");
  const counter = Math.floor(Date.now() / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac("sha1", base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving totpFor().");
  return String(binary % 1000000).padStart(6, "0");
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// An authenticator app enrolled on the portal, then a set of recovery codes
// generated and confirmed. Answers the codes as the page printed them.
async function enrolAndGenerate(b) {
  log.debug("Entering enrolAndGenerate().");
  let page = await b.go("GET", R + "/portal/mfa");
  await b.go("POST", R + "/portal/mfa",
             form({ action: "start", csrf_token: csrfOf(page.text) }));
  page = await b.go("GET", R + "/portal/mfa");
  const secret = ((String(page.text)
    .match(/<th>Secret<\/th><td><code>([^<]+)<\/code>/) || [])[1] || "")
    .replace(/\s+/g, "");
  assert.ok(secret, "no shared secret on /portal/mfa: " +
            String(page.text).slice(0, 400));
  await b.go("POST", R + "/portal/mfa",
    form({ action: "confirm", code: totpFor(secret),
           csrf_token: csrfOf(page.text) }));
  page = await b.go("GET", R + "/portal/mfa");
  const shown = await b.go("POST", R + "/portal/mfa",
    form({ action: "generate-codes", csrf_token: csrfOf(page.text) }));
  const list = String(shown.text).match(/<ul class="codes">([\s\S]*?)<\/ul>/);
  const codes = [];
  const re = /<code(?: class="[^"]*")?>([^<]+)<\/code>/g;
  let m;
  while (list && (m = re.exec(list[1])) !== null) {
    codes.push(m[1]);
  }
  assert.ok(codes.length >= 2, "no recovery codes were shown: " +
            String(shown.text).slice(0, 400));
  const handle = (String(shown.text)
    .match(/name="handle" value="([^"]+)"/) || [])[1];
  const confirmed = await b.go("POST", R + "/portal/mfa",
    form({ action: "confirm-codes", handle: handle,
           csrf_token: csrfOf(shown.text) }));
  assert.ok(confirmed.status === 303 || confirmed.status === 200,
            "confirming the codes answered " + confirmed.status);
  log.debug("Leaving enrolAndGenerate().");
  return codes;
}

// Sign in to the portal with the password and then a RECOVERY CODE, through
// the link the one-time code screen offers.
async function signInWithRecoveryCode(who, code) {
  log.debug("Entering signInWithRecoveryCode().");
  const b = browser(who);
  let r = await b.go("GET", R + "/portal");
  let spent = false;
  for (let i = 0; i < 10 && (r.status === 302 || r.status === 303); i++) {
    if (/\/authn\/login\?authn=/.test(r.location)) {
      const page = await b.go("GET", r.location);
      const fields = hiddenFields(page.text);
      fields.username = who;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
      if (r.status === 200) {
        const link = (String(r.text)
          .match(/href="([^"]*\/authn\/backup-code\?mfa=[^"]+)"/) || [])[1];
        assert.ok(link, "the one-time code screen offers no recovery code " +
                  "link: " + String(r.text).slice(0, 400));
        const screen = await b.go("GET", link.replace(/&amp;/g, "&"));
        const mfaId = (String(screen.text)
          .match(/name="mfa_id" value="([^"]+)"/) || [])[1];
        const action = (String(screen.text)
          .match(/<form[^>]*action="([^"]*backup-code[^"]*)"/) || [])[1] ||
          R + "/authn/backup-code";
        r = await b.go("POST", action.replace(/&amp;/g, "&"),
                       form({ mfa_id: mfaId, code: code }));
        spent = r.status === 302 || r.status === 303;
      }
      continue;
    }
    r = await b.go("GET", r.location);
  }
  log.debug("Leaving signInWithRecoveryCode().");
  return { spent: spent, status: r.status };
}

async function riscRow(who) {
  log.debug("Entering riscRow().");
  const r = await send(realmApi + "/risc");
  const row = ((r.body && r.body.accounts) || []).filter(function (one) {
    return one.accountId === who;
  })[0] || null;
  log.debug("Leaving riscRow().");
  return row;
}

function subjectValue(set) {
  log.debug("Entering subjectValue().");
  const user = userOf(set) || {};
  log.debug("Leaving subjectValue().");
  return user.email || user.phone_number || "";
}

function has(type) {
  log.debug("Entering has(). " + type);
  log.debug("Leaving has().");
  return function (set) {
    return !!riscEvent(set, type);
  };
}

function about(type, value) {
  log.debug("Entering about(). " + type);
  log.debug("Leaving about().");
  return function (set) {
    return !!riscEvent(set, type) && subjectValue(set) === value;
  };
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and a poll stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "RISC 233 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write", "scim:read",
                                  "scim:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  const token = await tokenFor("ssf:read ssf:write");
  const types = ["account-credential-change-required", "recovery-activated",
    "recovery-information-changed", "identifier-changed",
    "identifier-recycled", "opt-out-initiated", "opt-out-cancelled",
    "opt-out-effective", "opt-in"].map(function (t) { return RISC + t; });
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
                           events_requested: types }) });
  check("a poll stream takes the RISC types under test", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
  });
  const streamId = created.body.stream_id;
  for (const who of [EVE, SID, TIM, VIC, WYN]) {
    const attributes = { cn: "RISC " + who, givenName: "RISC", sn: who };
    if (who !== TIM) {
      attributes.mail = who + "@" + DOMAIN;
    }
    await ok(realmApi + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD, attributes: attributes },
      "created " + who);
  }
  await drain(token, streamId);
  POOL.length = 0;

  // -----------------------------------------------------------------------
  log.info("=== 1. #233: reset and clear keep the holder's choice ===");
  // -----------------------------------------------------------------------
  const b = await signInToPortal(EVE);
  let r = await move(b, "optOutInitiated");
  let found = await waitFor(token, streamId, "initiated",
                            has("opt-out-initiated"));
  check("eve opts out: opt-out-initiated", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  await ok(realmApi + "/risc/reset-account", { account_id: EVE },
           "reset eve's RISC row");
  let row = await riscRow(EVE);
  check("a reset keeps opt-out-initiated (RISC section 2.8: the holder's " +
        "choice)", function () {
    assert.ok(row, "eve has no row");
    assert.strictEqual(row.optOut, "opt-out-initiated", JSON.stringify(row));
  });
  await ok(realmApi + "/risc/clear", {}, "cleared the register");
  row = await riscRow(EVE);
  check("a clear keeps the row, blank, with opt-out-initiated", function () {
    assert.ok(row, "eve's row was dropped");
    assert.strictEqual(row.optOut, "opt-out-initiated", JSON.stringify(row));
    assert.strictEqual(row.total, 0, JSON.stringify(row));
  });
  check("and nothing was sent to say the state moved", function () {
    assert.ok(!POOL.some(function (set) {
      return !!riscEvent(set, "opt-in") ||
             !!riscEvent(set, "opt-out-cancelled");
    }), JSON.stringify(POOL).slice(0, 600));
  });
  await ok(realmApi + "/config/set", { key: "risc.optOutDelayHours",
                                       value: 0 }, "set the delay to 0");
  const queued = await postJson(realmApi + "/scheduler/run",
                                { job: "risc.opt-out-effective" });
  check("the risc.opt-out-effective job is queued (202)", function () {
    assert.strictEqual(queued.status, 202, queued.raw.slice(0, 300));
  });
  found = await waitFor(token, streamId, "effective",
                        has("opt-out-effective"), 120);
  check("the pending opt-out STILL becomes effective on schedule after the " +
        "reset and the clear", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  await ok(realmApi + "/config/reset", { key: "risc.optOutDelayHours" },
           "put the delay back");
  await ok(realmApi + "/risc/reset-account", { account_id: EVE },
           "reset eve's row again");
  await ok(realmApi + "/risc/clear", {}, "cleared the register again");
  row = await riscRow(EVE);
  check("an EFFECTIVE opt-out survives a reset and a clear too", function () {
    assert.ok(row, "eve's row was dropped");
    assert.strictEqual(row.optOut, "opt-out", JSON.stringify(row));
  });
  r = await move(b, "optIn");
  found = await waitFor(token, streamId, "opt-in", has("opt-in"));
  check("and only the holder brings it back: opt-in", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });

  // -----------------------------------------------------------------------
  log.info("=== 2. #234: every value, as a set, over SCIM ===");
  // -----------------------------------------------------------------------
  const scimToken = await tokenFor("scim:read scim:write");
  const scimAuth = { Authorization: "Bearer " + scimToken };
  const scimJson = Object.assign({ "Content-Type": "application/scim+json" },
                                 scimAuth);
  const listed = await send(realmBase + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + SID + "\""), { headers: scimAuth });
  const sidId = listed.body && listed.body.Resources &&
                listed.body.Resources[0] && listed.body.Resources[0].id;
  const first = SID + "@" + DOMAIN;
  const second = "second-" + SID + "@" + DOMAIN;
  const third = "third-" + SID + "@" + DOMAIN;
  const patch = function (emails, phones) {
    return send(realmBase + "/scim/v2/Users/" + sidId, { method: "PATCH",
      headers: scimJson, body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          { op: "replace", path: "emails", value: emails.map(function (v) {
            return { value: v, type: "work" };
          }) },
          { op: "replace", path: "phoneNumbers", value: phones }] }) });
  };
  r = await patch([first, second],
                  [{ value: "+15552330100", type: "work" },
                   { value: "+15552330111", type: "mobile" }]);
  check("sid is given a second address, a telephoneNumber and a mobile",
    function () {
      assert.ok(r.status === 200 || r.status === 204,
                r.status + " " + r.raw.slice(0, 300));
    });
  await drain(token, streamId);
  POOL.length = 0;
  r = await patch([first, third],
                  [{ value: "+15552330100", type: "work" },
                   { value: "+15552330122", type: "mobile" }]);
  found = await waitFor(token, streamId, "second address changed",
                        about("identifier-changed", second));
  check("the SECOND address changed is identifier-changed, from it to the " +
        "new one", function () {
    assert.ok(r.status === 200 || r.status === 204, r.raw.slice(0, 300));
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
    assert.strictEqual(riscEvent(found.hit, "identifier-changed")["new-value"],
                       third);
  });
  found = await waitFor(token, streamId, "mobile changed",
                        about("identifier-changed", "+15552330111"));
  check("a mobile changed beside a telephoneNumber is identifier-changed",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
      assert.strictEqual(
        riscEvent(found.hit, "identifier-changed")["new-value"],
        "+15552330122");
    });
  check("and the first address, unchanged, is no event", function () {
    assert.ok(!POOL.some(about("identifier-changed", first)),
              JSON.stringify(POOL).slice(0, 600));
  });
  r = await patch([first], [{ value: "+15552330100", type: "work" },
                            { value: "+15552330122", type: "mobile" }]);
  found = await waitFor(token, streamId, "address removed",
                        about("identifier-changed", third));
  check("an address REMOVED is identifier-changed with no new-value",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
      assert.ok(!("new-value" in riscEvent(found.hit, "identifier-changed")),
                JSON.stringify(riscEvent(found.hit, "identifier-changed")));
    });
  await ok(realmApi + "/users/create", { username: UMA, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "RISC " + UMA, givenName: "RISC", sn: UMA,
                  mail: third } }, "created uma with the removed address");
  found = await waitFor(token, streamId, "recycled",
                        about("identifier-recycled", third));
  check("so a new account given the removed address is identifier-recycled " +
        "(RISC section 2.6)", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });

  // -----------------------------------------------------------------------
  log.info("=== 3. #235: recovery information and recovery activated ===");
  // -----------------------------------------------------------------------
  await drain(token, streamId);
  POOL.length = 0;
  const timAddress = TIM + "@" + DOMAIN;
  await ok(realmApi + "/users/set-mail", { user: TIM, mail: timAddress },
           "gave tim his first address");
  found = await waitFor(token, streamId, "first address",
                        has("recovery-information-changed"));
  check("a first address is recovery-information-changed", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  check("and not identifier-changed: there was no old value", function () {
    assert.ok(!POOL.some(has("identifier-changed")),
              JSON.stringify(POOL).slice(0, 600));
  });
  const timNew = "new-" + timAddress;
  await ok(realmApi + "/users/set-mail", { user: TIM, mail: timNew },
           "changed tim's address");
  found = await waitFor(token, streamId, "changed address",
                        about("identifier-changed", timAddress));
  const recovery = await waitFor(token, streamId, "recovery after change",
                                 has("recovery-information-changed"));
  check("a changed address is identifier-changed AND " +
        "recovery-information-changed", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
    assert.ok(recovery.hit, JSON.stringify(recovery.seen).slice(0, 800));
  });

  await drain(token, streamId);
  POOL.length = 0;
  await ok(realmApi + "/users/issue-activation", { user: VIC },
           "issued vic an activation link");
  for (const one of ["recovery-activated",
                     "account-credential-change-required"]) {
    found = await waitFor(token, streamId, one, has(one));
    check("an activation link for somebody who exists is " + one,
      function () {
        assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
      });
  }

  const w = await signInToPortal(WYN);
  const codes = await enrolAndGenerate(w);
  await drain(token, streamId);
  POOL.length = 0;
  const signed = await signInWithRecoveryCode(WYN, codes[0]);
  check("wyn signs in with a recovery code", function () {
    assert.ok(signed.spent, JSON.stringify(signed));
  });
  for (const one of ["recovery-information-changed", "recovery-activated"]) {
    found = await waitFor(token, streamId, one, has(one));
    check("a recovery code spent at sign-in is " + one, function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
    });
  }

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_risc_register_recovery FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
