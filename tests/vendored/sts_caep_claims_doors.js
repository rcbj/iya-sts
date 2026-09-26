"use strict";
//
// File: sts_caep_claims_doors.js
//
// ---------------------------------------------------------------------------
// CAEP FROM THE DOORS THAT ARE NOT A DIRECTORY ATTRIBUTE, OVER THE WIRE
// (#238, #243, 2026-09-26).
//
// In a throwaway realm it leaves behind, with a poll stream that takes
// token-claims-change and assurance-level-change and covers everybody, a
// person who signed in and holds live tokens is sent:
//
//   a. token-claims-change carrying the roles claim when a role is given to
//      them on /admin-api/roles;
//   b. token-claims-change carrying the groups claim AND the roles claim
//      when they join a group a role names;
//   c. token-claims-change carrying verified_claims (no evidence) and
//      assurance-level-change in NIST-IAL at IAL2 when an nist_800_63A
//      verification is recorded for them;
//   d. token-claims-change carrying email and email_verified when SCIM
//      writes them an address (a trusted source, so it is verified);
//   e. token-claims-change carrying a custom claim with its value when the
//      access-token claim set gains it — the fan-out to every holder;
//
// and GET /ssf says that a tightened authentication policy sends nothing
// (#243's documented limitation).
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
var log = bunyan.createLogger({ name: "sts_caep_claims_doors",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("caep238-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "caep-238-" + String(Date.now()).slice(-8);
const RECEIVER = "caep238-rx-" + STAMP.toLowerCase();
const RP = "https://rp.caep238.example.test";
const REDIRECT = RP + "/cb";
const PASSWORD = "Caep-238-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("c238-alice");
const GROUP = "c238-group-" + STAMP.toLowerCase();
const ROLE = "c238-role-" + STAMP.toLowerCase();
const GROUP_ROLE = "c238-grole-" + STAMP.toLowerCase();
// A desktop Chrome string, with this job's own name on the end so the
// fingerprint it hashes is still its own: isbot reads the bare name as
// an automated client, and product mode refuses a first sign-in from
// one on risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like " +
  "Gecko) Chrome/140.0.0.0 Safari/537.36 sts_caep_claims_doors/1.0 (" +
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
    domain: REALM + ".example.net", name: "CAEP 238 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
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
      events_requested: [CAEP + "token-claims-change",
                         CAEP + "assurance-level-change"] }) });
  check("a poll stream takes token-claims-change and " +
        "assurance-level-change", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
    const delivered = created.body.events_delivered || [];
    assert.ok(delivered.indexOf(CAEP + "token-claims-change") >= 0 &&
              delivered.indexOf(CAEP + "assurance-level-change") >= 0,
              JSON.stringify(delivered));
  });
  const streamId = created.body.stream_id;

  log.info("=== a person with no address, signed in, holding tokens ===");
  await ok(realmApi + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "CAEP " + ALICE, givenName: "Caep", sn: "Doors" } },
    "created " + ALICE);
  const scimToken = await tokenFor("scim:read scim:write");
  const scimAuth = { Authorization: "Bearer " + scimToken };
  SUBJECTS[ALICE] = "urn:uuid:" + await scimIdOf(scimAuth, ALICE);
  const b = browser("alice");
  const params = { response_type: "code", client_id: RECEIVER,
    redirect_uri: REDIRECT, scope: "openid profile", state: "st",
    nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" };
  let r = await authorize(b, params, ALICE);
  const code = r.location ? new URL(absolute(r.location)).searchParams
    .get("code") : "";
  check("the sign-in reaches the client with a code", function () {
    assert.ok(code, r.status + " " + r.location);
  });
  const redeemed = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, client_id: RECEIVER,
                 client_secret: SECRET, code_verifier: "v".repeat(43) }) });
  check("and the code is redeemed: the person holds live tokens",
    function () {
      assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
    });
  await drain(token, streamId);

  const claimsAbout = function (set) {
    const ev = eventOf(set, "token-claims-change");
    return ev && aboutUser(set, ALICE) ? (ev.claims || {}) : null;
  };

  log.info("=== a. a role given ===");
  await ok(realmApi + "/roles/create-role", { role: ROLE },
           "created a role");
  await ok(realmApi + "/roles/add-member", { role: ROLE, kind: "user",
                                             member: ALICE },
           "gave it to the person");
  let found = await waitFor(token, streamId, "roles claim", function (set) {
    const claims = claimsAbout(set);
    return !!claims && Array.isArray(claims.roles) &&
           claims.roles.indexOf(ROLE) >= 0;
  });
  check("token-claims-change carries the roles claim, about the person",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    });

  log.info("=== b. a group a role names ===");
  await ok(realmApi + "/groups/create", { group: GROUP }, "created a group");
  await ok(realmApi + "/roles/create-role", { role: GROUP_ROLE },
           "created a second role");
  await ok(realmApi + "/roles/add-member", { role: GROUP_ROLE, kind: "group",
                                             member: GROUP },
           "gave it to the group");
  await ok(realmApi + "/groups/add-member", { group: GROUP, member: ALICE },
           "added the person to the group");
  found = await waitFor(token, streamId, "groups and roles", function (set) {
    const claims = claimsAbout(set);
    return !!claims && Array.isArray(claims.roles) &&
           claims.roles.indexOf(GROUP_ROLE) >= 0 &&
           Object.keys(claims).some(function (k) {
             return k !== "roles" && Array.isArray(claims[k]) &&
                    claims[k].join(" ").indexOf(GROUP) >= 0;
           });
  });
  check("joining it moves the groups claim and the roles claim together",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    });

  log.info("=== c. an identity verification recorded ===");
  await ok(realmApi + "/config/set", { key: "oauth2.idaTrustFrameworks",
                                       value: "nist_800_63A" },
           "allowed the nist_800_63A framework");
  await ok(realmApi + "/users/record-verification", { user: ALICE,
    verification: { trust_framework: "nist_800_63A",
                    assurance_level: "IAL2",
                    evidence: [{ type: "document",
                      check_details: [{ check_method: "vpip" }],
                      document_details: { type: "passport",
                                          document_number: "X238" } }] },
    claims: ["given_name"] }, "recorded a verification");
  found = await waitFor(token, streamId, "verified_claims", function (set) {
    const claims = claimsAbout(set);
    return !!claims && Array.isArray(claims.verified_claims);
  });
  check("token-claims-change carries verified_claims: framework, level " +
        "and the claim, and never the evidence", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    const vc = claimsAbout(found.hit).verified_claims[0];
    assert.strictEqual(vc.verification.trust_framework, "nist_800_63A");
    assert.strictEqual(vc.verification.assurance_level, "IAL2");
    assert.strictEqual(vc.claims.given_name, "Caep");
    assert.ok(JSON.stringify(found.hit).indexOf("X238") < 0,
              "the document number is not in the SET");
  });
  found = await waitFor(token, streamId, "assurance level", function (set) {
    const ev = eventOf(set, "assurance-level-change");
    return !!ev && aboutUser(set, ALICE);
  });
  check("assurance-level-change: NIST-IAL, IAL2, about the person",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = eventOf(found.hit, "assurance-level-change");
      assert.strictEqual(ev.namespace, "NIST-IAL", JSON.stringify(ev));
      assert.strictEqual(ev.current_level, "IAL2", JSON.stringify(ev));
      assert.ok(!("previous_level" in ev),
                "no previous level from another namespace: " +
                JSON.stringify(ev));
    });

  log.info("=== d. an address written by SCIM ===");
  const scimId = SUBJECTS[ALICE].slice("urn:uuid:".length);
  const patched = await send(realmBase + "/scim/v2/Users/" + scimId, {
    method: "PATCH", headers: Object.assign({ "Content-Type":
      "application/scim+json" }, scimAuth),
    body: JSON.stringify({ schemas:
      ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "add", path: "emails",
                     value: [{ value: ALICE + "@caep238.test",
                               primary: true }] }] }) });
  check("the PATCH is applied", function () {
    assert.ok(patched.status === 200 || patched.status === 204,
              patched.status + " " + patched.raw.slice(0, 300));
  });
  found = await waitFor(token, streamId, "email_verified", function (set) {
    const claims = claimsAbout(set);
    return !!claims && claims.email_verified === true;
  });
  check("token-claims-change carries email_verified with the address",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      assert.strictEqual(claimsAbout(found.hit).email,
                         ALICE + "@caep238.test");
    });

  log.info("=== e. the access-token claim set gains a claim ===");
  await ok(realmApi + "/claims/add", { set: "access_token",
    name: "c238_dept", value: "${username}-dept" }, "added a custom claim");
  found = await waitFor(token, streamId, "custom claim", function (set) {
    const claims = claimsAbout(set);
    return !!claims && claims.c238_dept === ALICE + "-dept";
  });
  check("token-claims-change fans out the new claim with its value",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    });

  log.info("=== f. GET /ssf states the tightened-policy limitation ===");
  const page = await send(realmBase + "/ssf", {});
  check("GET /ssf says a tightened authentication policy sends nothing",
    function () {
      assert.strictEqual(page.status, 200, page.raw.slice(0, 300));
      assert.ok(/authentication policy is\s+TIGHTENED/.test(page.raw),
                page.raw.slice(0, 600));
    });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_caep_claims_doors FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
