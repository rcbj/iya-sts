// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_stable_subject.js
//
// ---------------------------------------------------------------------------
// A PERSON'S `sub` IS THEIR ENTRY'S `entryUUID`, A SCIM ID IS TOO, AND A
// SIGN-IN FOR SOMEBODY WITH NO ENTRY IS REFUSED AND ANSWERED, OVER THE WIRE
// (2026-09-14; #62 P0).
//
// D12 (#444): carries over `tests/stable_subject.js` and
// `tests/authn_session_refusals.js`. In a DEVELOPMENT realm of its own
// (development is where the LDAP socket takes an anonymous write, which is
// the door a rename and a delete come through), over the LDAP socket, the
// token endpoint, `/scim/v2`, WS-Trust and the sign-in screen:
//
//   A. THE DIRECTORY: an entry a door created has a random (version 4)
//      `entryUUID`; a search returns it only when asked for by name (RFC
//      4512's operational attributes); an LDAP add or modify naming it is
//      refused (STS-LDAP-0076) and the value kept, while a modify of
//      anything else keeps it; a RENAME (modifyDN, deleteOldRdn) keeps it
//      and removes the old uid; a person deleted and re-created under the
//      same name gets a NEW one.
//   D. THE TOKEN ENDPOINT: the ID Token's and access token's `sub` are
//      `urn:uuid:<entryUUID>`; a refresh after a rename keeps the same
//      `sub`; once the person is deleted and somebody re-created under the
//      old name, the refresh is refused invalid_grant; with
//      `ldap.autocreateUsers` off a password grant for somebody with no
//      entry is refused invalid_grant and creates no entry, and so is a
//      WS-Trust JWT request (STS-WSTRUST-0017).
//   E. SCIM: a user's `id` is the entryUUID; a group created with a member
//      given by id stores the member's DN.
//   S. A REFUSED SESSION IS ANSWERED (authn_session_refusals A): with
//      autocreate off, a password sign-in for somebody with no entry is
//      answered with the sign-in screen again (`next: refused`, STS-AUTHN-
//      0180 on the audit log), the SAME pending sign-in is drawn, and a
//      person who has an entry signs in from it and comes back with a code.
//
// NOT carried, and why: A1 and A11–A20 (a seeded entry's name-based UUID
// across two processes, replicated rows, create races, aliases), B (the
// resolver functions), C1, C4, C5 and D6 call the store and the session
// layer directly (class (d)); F (a federation partner's `urn:uuid:`
// subject) is phase 7's; authn_session_refusals B (`refusedWith` on a
// caller's detail object) and C (the event's address, User-Agent and
// credential fingerprints, the risk assessment) are fields of the session
// record that no answer states (class (d)).
//
// OWNED HERE (local: true): this repository's own directory, token endpoint,
// SCIM service and sign-in.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_stable_subject",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
// A password this process made: product checks it.
const PASSWORD = "Stable-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_stable_subject/1.0 (" + STAMP + ")";

let checks = 0;
const failures = [];

// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()`, which throws.
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  [ok] " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  [FAILED] " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function expect(condition, message) {
  log.debug("Entering expect().");
  if (!condition) {
    log.debug("Leaving expect(). Refused.");
    throw new Error(String(message));
  }
  log.debug("Leaving expect().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
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
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "", headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

// The management API of a realm (`realm` null: the root's). The run's admin
// token is attached by the preload (`tools/attach-admin-token.js`).
function api(realm, method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const url = (realm ? realmBase(realm) : base) + "/admin-api" + p;
  log.debug("Leaving api().");
  if (method === "GET") {
    return send(url);
  }
  return postJson(url, payload);
}

async function apiOk(realm, p, payload, what) {
  log.debug("Entering apiOk(). " + p);
  const r = await api(realm, "POST", p, payload);
  must(r.status === 200 && r.body && r.body.ok !== false,
       (what || p) + " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.body;
}

const MADE = [];
async function makeRealm(stem, mode) {
  log.debug("Entering makeRealm(). " + stem);
  const id = (stem + "-" + STAMP).slice(0, 31);
  await apiOk(null, "/realms/create", { id: id, domain: id + ".example.net",
    name: stem + " " + STAMP }, "created the realm " + id);
  MADE.push(id);
  await apiOk(null, "/realms/set", { id: id, key: "global.mode",
    value: mode }, "set " + id + " to " + mode);
  log.debug("Leaving makeRealm(). " + id);
  return id;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return apiOk(null, "/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

async function createPerson(realm, username, extra) {
  log.debug("Entering createPerson(). " + username);
  const body = await apiOk(realm, "/users/create", Object.assign({
    username: username, invent: false,
    attributes: { cn: "Probe " + username, givenName: "Probe",
                  sn: username, mail: username + "@" + realm + ".example" },
    credential: "password", password: PASSWORD }, extra || {}),
  "created " + username);
  log.debug("Leaving createPerson().");
  return body;
}

// How many of a realm's audit rows carry `code`.
async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api(realm, "GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const b = r.body && typeof r.body === "object" ? r.body : {};
  const rows = b.rows || b.events || [];
  const n = typeof b.matched === "number" ? b.matched : rows.length;
  log.debug("Leaving codeCount(). " + n);
  return n;
}

// Whether a new row with `code` arrived since `before`: the row is written
// as the response finishes, so the read after it may need a moment.
async function newRowWith(realm, code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = await codeCount(realm, code);
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// A browser: a cookie jar (a plain object, which `authn_signin.js` writes
// back into) and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function cookieOf() {
      log.debug("Entering cookieOf().");
      log.debug("Leaving cookieOf().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    go: async function go(method, url, body, extra) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = Object.assign({ "User-Agent": AGENT }, extra || {});
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
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
               text: text, url: absolute };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location);
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token || "").split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1] || "", "base64url")
    .toString("utf8") || "{}");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made is removed
// at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
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
    // A failed removal leaves a realm on a private probe; it is not the
    // job's verdict.
    log.warn("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("Test failed: " + ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  if (failures.length) {
    log.error(failures.length + " check(s) FAILED:\n  " +
              failures.join("\n  "));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}


const ldapjs = require("ldapjs");

const CLIENT = "ss-client-" + STAMP;
const SECRET = "ss-secret-" + nodeCrypto.randomBytes(12).toString("hex");
const SCIM_CLIENT = "ss-scim-" + STAMP;
const APP = "ss-app-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".ss.example/cb";
const V4 = new RegExp("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]" +
                      "[0-9a-f]{3}-[0-9a-f]{12}$");
let REALM = "";
let USERS_DN = "";

function ldapClient() {
  log.debug("Entering ldapClient().");
  const host = new URL(base).hostname;
  const client = ldapjs.createClient({
    url: "ldap://" + host + ":" + (process.env.STS_LDAP_PORT || 389),
    reconnect: false, timeout: 20000, connectTimeout: 15000 });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back; the operation in
    // flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving ldapClient().");
  return client;
}

function settle(fn) {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    fn(function (e) {
      resolve({ code: e ? e.code : 0,
                message: e ? String(e.lde_message || e.message || "") : "" });
    });
  });
}

// One entry by DN: `{ code, entry }`, the entry's attributes by name.
function read(client, dn, attributes) {
  log.debug("Entering read(). " + dn);
  return new Promise(function (resolve) {
    client.search(dn, { scope: "base", attributes: attributes || [] },
      function (e, res) {
        if (e) {
          log.debug("Leaving read(). " + e.message);
          resolve({ code: e.code || -1, entry: null });
          return;
        }
        let entry = null;
        res.on("searchEntry", function (one) {
          entry = {};
          (one.pojo ? one.pojo.attributes : one.attributes)
            .forEach(function (a) {
              entry[String(a.type).toLowerCase()] = a.values || a.vals;
            });
        });
        res.on("error", function (err) {
          log.debug("Leaving read(). " + err.message);
          resolve({ code: err.code || -1, entry: null });
        });
        res.on("end", function (done) {
          log.debug("Leaving read().");
          resolve({ code: done ? done.status : 0, entry: entry });
        });
      });
  });
}

function uuidOf(r) {
  log.debug("Entering uuidOf().");
  log.debug("Leaving uuidOf().");
  return r && r.entry && r.entry.entryuuid ? String(r.entry.entryuuid[0])
    : "";
}

function token(fields) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(realmBase(REALM) + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(Object.assign({ client_id: CLIENT, client_secret: SECRET },
                             fields)) });
}

function rst(who) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
    "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/" +
    "oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header>" +
    "<wsse:Security><wsse:UsernameToken><wsse:Username>" + who +
    "</wsse:Username><wsse:Password>x</wsse:Password>" +
    "</wsse:UsernameToken></wsse:Security></s:Header><s:Body>" +
    "<wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/" +
    "ws-sx/ws-trust/200512\"><wst:RequestType>http://docs.oasis-open.org/" +
    "ws-sx/ws-trust/200512/Issue</wst:RequestType><wst:TokenType>" +
    "urn:ietf:params:oauth:token-type:jwt</wst:TokenType>" +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
}

async function directory(client) {
  log.debug("Entering directory().");
  log.info("=== A. the directory ===");
  const bob = names.usernameFor("ssb");
  await createPerson(REALM, bob);
  const bobDn = "uid=" + bob + "," + USERS_DN;
  const plain = await read(client, bobDn);
  const asked = await read(client, bobDn, ["entryUUID", "uid"]);
  const bobUuid = uuidOf(asked);
  await check("A2. an entry a door created has a random (version 4) " +
              "entryUUID", async function () {
    expect(V4.test(bobUuid), JSON.stringify(asked));
  });
  await check("A7. a search returns entryUUID only when asked for by name",
              async function () {
    expect(plain.entry && !plain.entry.entryuuid, JSON.stringify(plain));
  });
  const beforeCode = await codeCount(REALM, "STS-LDAP-0076");
  const forged = await settle(function (done) {
    client.add("uid=ss-forged-" + STAMP + "," + USERS_DN, {
      objectClass: ["inetOrgPerson"], uid: "ss-forged-" + STAMP,
      cn: "Forged", sn: "Forged", entryUUID: bobUuid }, done);
  });
  const addCoded = await newRowWith(REALM, "STS-LDAP-0076", beforeCode);
  await check("A4. an LDAP add naming entryUUID is refused (STS-LDAP-0076)",
              async function () {
    expect(forged.code !== 0, JSON.stringify(forged));
    expect(addCoded, "no STS-LDAP-0076 row");
  });
  const replaced = await settle(function (done) {
    client.modify(bobDn, new ldapjs.Change({ operation: "replace",
      modification: new ldapjs.Attribute({ type: "entryUUID",
        values: ["00000000-0000-4000-8000-000000000000"] }) }), done);
  });
  const afterReplace = uuidOf(await read(client, bobDn, ["entryUUID"]));
  await check("A5. a modify naming it is refused, leaving the value",
              async function () {
    expect(replaced.code !== 0 && afterReplace === bobUuid,
           JSON.stringify(replaced) + " " + afterReplace);
  });
  const titled = await settle(function (done) {
    client.modify(bobDn, new ldapjs.Change({ operation: "replace",
      modification: new ldapjs.Attribute({ type: "title",
        values: ["Foreman"] }) }), done);
  });
  const afterTitle = uuidOf(await read(client, bobDn, ["entryUUID"]));
  await check("A6. a modify of anything else keeps it", async function () {
    expect(titled.code === 0 && afterTitle === bobUuid,
           JSON.stringify(titled) + " " + afterTitle);
  });
  const robert = bob + "-r";
  const renamed = await settle(function (done) {
    client.modifyDN(bobDn, "uid=" + robert + "," + USERS_DN, done);
  });
  const robertEntry = await read(client, "uid=" + robert + "," + USERS_DN,
                                 ["entryUUID", "uid"]);
  await check("A8. a RENAME keeps the entryUUID", async function () {
    expect(renamed.code === 0 && uuidOf(robertEntry) === bobUuid,
           JSON.stringify(renamed) + " " + JSON.stringify(robertEntry));
  });
  await check("A9. and deleteOldRdn removes the old uid", async function () {
    const uids = (robertEntry.entry && robertEntry.entry.uid) || [];
    expect(uids.indexOf(bob) < 0 && uids.indexOf(robert) >= 0,
           JSON.stringify(uids));
  });
  const carol = names.usernameFor("ssc");
  await createPerson(REALM, carol);
  const carolDn = "uid=" + carol + "," + USERS_DN;
  const carolUuid = uuidOf(await read(client, carolDn, ["entryUUID"]));
  const gone = await settle(function (done) {
    client.del(carolDn, done);
  });
  await createPerson(REALM, carol);
  const again = uuidOf(await read(client, carolDn, ["entryUUID"]));
  await check("A10. a person deleted and re-created under the same name is " +
              "a NEW entryUUID", async function () {
    expect(gone.code === 0 && V4.test(again) && again !== carolUuid,
           JSON.stringify(gone) + " " + carolUuid + " -> " + again);
  });
  log.debug("Leaving directory().");
}

async function tokens(client) {
  log.debug("Entering tokens().");
  log.info("=== D. the token endpoint ===");
  const frank = names.usernameFor("ssf");
  await createPerson(REALM, frank);
  const frankDn = "uid=" + frank + "," + USERS_DN;
  const frankUuid = uuidOf(await read(client, frankDn, ["entryUUID"]));
  const grant = function () {
    return token({ grant_type: "password", username: frank,
                   password: PASSWORD, scope: "openid offline_access" });
  };
  const first = await grant();
  const second = await grant();
  const idt = decode(first.body && first.body.id_token);
  const at = decode(first.body && first.body.access_token);
  await check("D1. the ID Token and the access token carry sub = " +
              "urn:uuid:<entryUUID>", async function () {
    expect(first.status === 200, first.status + " " + first.raw
      .slice(0, 300));
    expect(idt.sub === "urn:uuid:" + frankUuid &&
           at.sub === "urn:uuid:" + frankUuid,
           frankUuid + " " + idt.sub + " " + at.sub);
  });
  must(first.body && first.body.refresh_token && second.body &&
       second.body.refresh_token, "two refresh tokens: " +
       first.raw.slice(0, 300));
  const francis = frank + "-r";
  const renamed = await settle(function (done) {
    client.modifyDN(frankDn, "uid=" + francis + "," + USERS_DN, done);
  });
  must(renamed.code === 0, "the rename: " + JSON.stringify(renamed));
  const r3 = await token({ grant_type: "refresh_token",
                           refresh_token: first.body.refresh_token });
  await check("D3. a refresh after a RENAME is issued with the SAME sub",
              async function () {
    expect(r3.status === 200 && decode(r3.body.access_token).sub ===
           "urn:uuid:" + frankUuid, r3.status + " " + r3.raw.slice(0, 300));
  });
  const deleted = await settle(function (done) {
    client.del("uid=" + francis + "," + USERS_DN, done);
  });
  must(deleted.code === 0, "the delete: " + JSON.stringify(deleted));
  await createPerson(REALM, frank);
  const r4 = await token({ grant_type: "refresh_token",
                           refresh_token: second.body.refresh_token });
  await check("D4. once the person is DELETED and somebody RE-CREATED under " +
              "the old name, the refresh is refused invalid_grant",
              async function () {
    expect(r4.status === 400 && r4.body && r4.body.error === "invalid_grant",
           r4.status + " " + r4.raw.slice(0, 300));
  });

  await setting(REALM, "ldap.autocreateUsers", "false");
  const george = names.usernameFor("ssg");
  const r5 = await token({ grant_type: "password", username: george,
                           password: PASSWORD });
  const georgeEntry = await read(client, "uid=" + george + "," + USERS_DN);
  await check("D5. with autocreate off, a password grant for somebody with " +
              "no entry is refused invalid_grant and creates no entry",
              async function () {
    expect(r5.status === 400 && r5.body && r5.body.error === "invalid_grant",
           r5.status + " " + r5.raw.slice(0, 300));
    expect(!georgeEntry.entry, JSON.stringify(georgeEntry));
  });
  const before = await codeCount(REALM, "STS-WSTRUST-0017");
  const ws = await send(realmBase(REALM) + "/sts", { method: "POST",
    headers: { "Content-Type": "application/soap+xml" },
    body: rst(names.usernameFor("ssn")) });
  const wsCoded = await newRowWith(REALM, "STS-WSTRUST-0017", before);
  await check("D5b. a WS-Trust JWT request for somebody with no entry is " +
              "refused, issuing nothing (STS-WSTRUST-0017)",
              async function () {
    expect(ws.status >= 400 && !/BinarySecurityToken/.test(ws.raw),
           ws.status + " " + ws.raw.slice(0, 300));
    expect(wsCoded, "no STS-WSTRUST-0017 row");
  });
  log.debug("Leaving tokens().");
}

async function scim(client) {
  log.debug("Entering scim().");
  log.info("=== E. SCIM ===");
  const t = await send(realmBase(REALM) + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: SCIM_CLIENT,
                 client_secret: SECRET, scope: "scim:read scim:write" }) });
  must(t.body && t.body.access_token, "a SCIM token: " + t.raw.slice(0, 300));
  const auth = { Authorization: "Bearer " + t.body.access_token };
  const ivy = names.usernameFor("ssi");
  await createPerson(REALM, ivy);
  const ivyUuid = uuidOf(await read(client, "uid=" + ivy + "," + USERS_DN,
                                    ["entryUUID"]));
  const listed = await send(realmBase(REALM) + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + ivy + "\""), { headers: auth });
  const id = listed.body && listed.body.Resources &&
    listed.body.Resources[0] && listed.body.Resources[0].id;
  await check("E1. a SCIM user's id is the entry's entryUUID",
              async function () {
    expect(id && id === ivyUuid, listed.status + " " + id + " " + ivyUuid);
  });
  const group = "ss-scim-g-" + STAMP;
  const made = await send(realmBase(REALM) + "/scim/v2/Groups", {
    method: "POST", headers: Object.assign({ "Content-Type":
      "application/scim+json" }, auth),
    body: JSON.stringify({ schemas: [
      "urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: group,
      members: [{ value: id }] }) });
  const groupEntry = await read(client, "cn=" + group + ",ou=groups," +
    USERS_DN.replace(/^ou=users,/, ""), ["member"]);
  await check("E3. a group created with a member given by id stores the " +
              "member's DN", async function () {
    expect(made.status === 201, made.status + " " + made.raw.slice(0, 300));
    const members = ((groupEntry.entry && groupEntry.entry.member) || [])
      .map(function (m) {
        return String(m).toLowerCase();
      });
    expect(members.indexOf(("uid=" + ivy + "," + USERS_DN).toLowerCase()) >=
           0, JSON.stringify(groupEntry));
  });
  log.debug("Leaving scim().");
}

async function refusedSession() {
  log.debug("Entering refusedSession().");
  log.info("=== S. a refused session is answered ===");
  const ghost = names.usernameFor("ssghost");
  const real = names.usernameFor("ssreal");
  await setting(REALM, "ldap.autocreateUsers", "true");
  await createPerson(REALM, real);
  await setting(REALM, "ldap.autocreateUsers", "false");
  const b = browser();
  const p = pkce();
  const start = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form({ client_id: APP, response_type: "code", redirect_uri: REDIRECT,
           scope: "openid", state: "s", nonce: "n" + STAMP,
           code_challenge: p.challenge, code_challenge_method: "S256" }));
  must(sentToSignIn(start), "no screen: " + start.status + " " +
       start.location);
  const at = new URL(start.location, realmBase(REALM) + "/").toString();
  const before = await codeCount(REALM, "STS-AUTHN-0180");
  const refused = await authnSignin.signInWithJar(realmBase(REALM), at,
    { action: "login", username: ghost, password: PASSWORD }, b.jar,
    { headers: { "User-Agent": AGENT } });
  const coded = await newRowWith(REALM, "STS-AUTHN-0180", before);
  await check("S-A1. a session refused at the password door (no directory " +
              "entry, STS-AUTHN-0180) is answered with the screen again " +
              "(next: refused), not a redirect back to the caller",
              async function () {
    expect(refused.answer.next === "refused" && !refused.location,
           refused.status + " " + refused.answer.next + " " +
           JSON.stringify(refused.answer.errors));
    expect(new RegExp("Authentication failed for " + ghost)
      .test((refused.answer.errors || []).join(" ")),
           JSON.stringify(refused.answer.errors));
    expect(coded, "no STS-AUTHN-0180 row");
  });
  const redrawn = await authnSignin.screen(realmBase(REALM), at,
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  await check("S-A3. the screen is drawn for the SAME pending sign-in",
              async function () {
    expect(redrawn.status === 200 && !!redrawn.view &&
           redrawn.id === authnSignin.pendingIdOf(at),
           redrawn.status + " " + redrawn.id + " " +
           authnSignin.pendingIdOf(at));
  });
  const after = await authnSignin.signInWithJar(realmBase(REALM), at,
    { action: "login", username: real, password: PASSWORD }, b.jar,
    { ignoreOffer: true, headers: { "User-Agent": AGENT } });
  let landed = null;
  if (after.status === 303 && after.location) {
    landed = await b.go("GET", new URL(after.location,
                                       realmBase(REALM) + "/").toString());
  }
  await check("S-A4. and a person with an entry signs in from it and comes " +
              "back with a code — the pending sign-in was put back",
              async function () {
    expect(landed && urls.isAt(landed.location, REDIRECT) &&
           /[?&]code=/.test(landed.location),
           after.status + " " + after.location + " " +
           (landed ? landed.status + " " + landed.location : ""));
  });
  log.debug("Leaving refusedSession().");
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("ssub", "development");
  USERS_DN = "ou=users,dc=" + REALM + ",dc=example,dc=net";
  await apiOk(REALM, "/applications/create", { identifier: CLIENT,
    name: CLIENT, protocols: ["oauth2"], kind: "oauth2-client",
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid", "offline_access"],
              oauthGrantType: ["password", "refresh_token"] } },
  "the password-grant client");
  await apiOk(REALM, "/applications/create", { identifier: SCIM_CLIENT,
    name: SCIM_CLIENT, protocols: ["oauth2"], kind: "oauth2-client",
    fields: { oauthClientId: [SCIM_CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["scim:read", "scim:write"],
              oauthGrantType: ["client_credentials"] } }, "the SCIM client");
  await apiOk(REALM, "/applications/create", { identifier: APP, name: APP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none" } }, "the browser client");
  await apiOk(REALM, "/consent/grant-global-consent",
              { client: APP, scope: "openid" }, "consented openid");
  for (const one of ["openid", "offline_access"]) {
    await apiOk(REALM, "/consent/grant-global-consent",
                { client: CLIENT, scope: one }, "consented " + one);
  }
  const client = ldapClient();
  try {
    await directory(client);
    await tokens(client);
    await scim(client);
  } finally {
    client.unbind(function () {
      log.debug("The LDAP client unbound.");
    });
  }
  await refusedSession();
  log.debug("Leaving test().");
}

main();
