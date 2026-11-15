// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_security_admin.js
//
// ===========================================================================
// THE SECURITY ADMINISTRATOR (#645, 2026-11-02), OVER HTTP.
//
// rcbj: "only a security administrator can modify policy object". Two people
// sign in to the console as the console signs in — one granted Admin Write,
// one granted only Security Administrator — and drive `/admin-api` with the
// tokens the console would hold:
//
//   1. Admin Write is refused a Directory → Policies save, 403, in words
//      naming the role (STS-API-0138, recorded and never sent).
//   2. Admin Write is refused granting the Security Administrator's role.
//   3. The Security Administrator is NOT refused that save on the role's
//      grounds, and `/admin-api/me` says `security` and not `write`.
//   4. The Security Administrator is refused an ordinary write (a person
//      created): the role implies read and not write.
//   5. Admin Write still saves an application's other fields: a grid Save
//      posting the policy reference unchanged is not a security change.
//
// IN A THROWAWAY REALM SINCE D12 (#444): it ran against the DEFAULT realm's
// roster, which a job on a shared service may not write; the realm's own
// console is claimed first (its bootstrap administrator signing in through
// the console's client), because until then development's window hands
// every signed-in person read and write and the two people could not be
// told apart.
//
// D12 also carries over what tests/security_admin.js holds that a client
// sees:
//
//   6. C1: before the claim, the realm's open window hands a person holding
//      no role read and write, and not security;
//   7. the classifier's kinds (B), each by what Admin Write is let do and
//      refused (403, STS-API-0138 on the realm's audit): a policy save and a
//      reset; a grant and a revoke of the role, and its member in
//      SECURITY_ADMIN or its group (any case), against another role and
//      group; a group, an application, a grid Save, an LDIF import and a
//      create naming a policy, against posting the reference unchanged,
//      `default` where none is named, and an empty field; and a GET;
//   8. C5: the realm's bootstrap administrator is not seeded into the role;
//   9. D: the holder's token carries admin:security and SECURITY_ADMIN, and
//      Admin Write's carries neither.
//
// What stays in process (its D12 note): the role tables as modules answer
// them and the classifier's own hooks.
// `local: true`: the role and the gate are ours.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const crypto = require("crypto");
const { usernameFor, runStamp } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const authnSignin = require("./authn_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_security_admin",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The throwaway realm every write lands in, and its own console.
const STAMP = runStamp();
const REALM = ("seca-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
let realmBase = "";
// The two people, named for what they hold, and one holding nothing.
const WRITER = usernameFor("sec-writer");
const OFFICER = usernameFor("sec-officer");
const VISITOR = usernameFor("sec-visitor");
// The policy kind every service has, and its save action.
const SAVE = "/admin-api/policies/save-password-policy";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// THE HARNESS'S OWN TOKEN, which `tests/tools/attach-admin-token.js` adds to
// a bare /admin-api call and which carries admin:security as seeded.
async function asHarness(method, path, payload) {
  log.debug("Entering asHarness(). " + method + " " + path);
  const init = { method: method };
  if (payload !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(realmBase + path, init);
  const text = await r.text();
  log.debug("Leaving asHarness(). " + r.status);
  return { status: r.status, text: text };
}

function errorsOf(reply) {
  log.debug("Entering errorsOf().");
  const json = (reply && reply.json) || {};
  log.debug("Leaving errorsOf().");
  return JSON.stringify(json.errors || json.error || reply.text || "");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// The realm's audit rows of one code: a code is recorded, never sent.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await asHarness("GET", "/admin-api/audit?per=1&code=" +
                            encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number(JSON.parse(r.text).matched || 0);
}

// What Admin Write's client answers an act, and how far STS-API-0138's
// count grew with it.
async function asWriter(writer, method, path, payload) {
  log.debug("Entering asWriter(). " + path);
  const before = await codeCount("STS-API-0138");
  const reply = await writer.api(method, path, payload);
  let now = before;
  for (let i = 0; i < 10 && now <= before && reply.status === 403; i += 1) {
    now = await codeCount("STS-API-0138");
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving asWriter(). " + reply.status);
  return { reply: reply, grew: now - before };
}

function refusedToWrite(got, what) {
  log.debug("Entering refusedToWrite().");
  check("7. Admin Write is refused " + what + ", 403, recorded as " +
        "STS-API-0138", function () {
    assert.strictEqual(got.reply.status, 403, "it answered " +
      got.reply.status + " " + String(got.reply.text).slice(0, 300));
    assert.ok(/Security Administrator/.test(errorsOf(got.reply)),
              errorsOf(got.reply));
    assert.ok(got.grew >= 1, "STS-API-0138 rows grew by " + got.grew);
  });
  log.debug("Leaving refusedToWrite().");
}

function letWrite(got, what) {
  log.debug("Entering letWrite().");
  check("7. Admin Write is let " + what + ": not a security change",
        function () {
    assert.ok(got.reply.status !== 403 && got.reply.status !== 401,
      "it answered " + got.reply.status + " " +
      String(got.reply.text).slice(0, 300));
    assert.strictEqual(got.grew, 0);
  });
  log.debug("Leaving letWrite().");
}

// THE REALM'S CONSOLE CLAIMED, as development claims it: the bootstrap
// administrator signs in through the console's own client.
async function claimConsole() {
  log.debug("Entering claimConsole().");
  const cookies = consoleSignIn.jar();
  const hop = async function (url) {
    const r = await fetch(new URL(url, realmBase).toString(),
      { redirect: "manual", headers: { cookie: cookies.header() } });
    cookies.keep(r);
    return r;
  };
  await hop(realmBase + "/admin");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const authorize = realmBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: realmBase + "/admin/callback", scope: "openid admin:read",
    state: "claim-" + STAMP, code_challenge_method: "S256",
    code_challenge: crypto.createHash("sha256").update(verifier)
      .digest("base64url"), resource: realmBase + "/admin-api" }).toString();
  const toScreen = await hop(authorize);
  const where = new URL(toScreen.headers.get("location") || "", realmBase)
    .toString();
  const newPassword = "Claimed-Console-" + STAMP + "-9!";
  let answered = await authnSignin.signIn(realmBase, where,
    { action: "login", username: "admin", password: "anything-at-all" },
    { cookie: cookies.header() });
  cookies.keep(answered);
  for (let step = 0; step < 2 && answered.next === "password-change";
       step += 1) {
    answered = await authnSignin.changePassword(realmBase, answered.location,
      { new_password: newPassword, confirm_password: newPassword },
      { cookie: cookies.header() });
    cookies.keep(answered);
    answered = await authnSignin.ignoreOffer(realmBase, answered);
    cookies.keep(answered);
  }
  let at = await hop(answered.location || authorize);
  for (let i = 0; i < 5 && (at.status === 302 || at.status === 303) &&
       !/\/admin\/callback\?/.test(at.headers.get("location") || ""); i++) {
    at = await hop(at.headers.get("location"));
  }
  const roster = JSON.parse((await asHarness("GET", "/admin-api/rbac")).text);
  assert.ok(roster.bootstrap.claimedAt, "signing in as admin did not claim " +
            "the realm's console: " + JSON.stringify(roster.bootstrap));
  log.debug("Leaving claimConsole().");
  return roster;
}

async function theKinds(writer) {
  log.debug("Entering theKinds().");
  log.info("=== 7. what is a security change, by what Admin Write may do ===");
  const plainPolicy = JSON.parse((await asHarness("GET",
    "/admin-api/policies")).text).password;
  const passwordFields = Object.assign({}, plainPolicy.defaults || {});
  const harnessSave = await asHarness("POST",
    "/admin-api/policies/save-password-policy",
    Object.assign({}, passwordFields, { profile: "strict",
                                        precedence: 10 }));
  assert.strictEqual(harnessSave.status, 200, "precondition: a named " +
    "password policy answered " + harnessSave.status + " " +
    harnessSave.text.slice(0, 300));
  const group = "sec-group-" + STAMP.toLowerCase();
  await asHarness("POST", "/admin-api/groups/create", { group: group });
  await asHarness("POST", "/admin-api/groups/set-policy", { group: group,
    attribute: "stsPasswordPolicy", policy: "strict" });
  const app = "sec-app";
  const plainApp = "sec-plain";
  for (const id of [app, plainApp]) {
    await asHarness("POST", "/admin-api/applications/create", {
      identifier: id, kind: "oauth2-client", name: id, protocols: ["oauth2"],
      fields: { oauthClientId: [id],
                oauthRedirectUri: ["https://" + id + ".example.net/cb"] } });
  }
  await asHarness("POST", "/admin-api/applications/set", { application: app,
    attribute: "appPasswordPolicy", value: "strict" });

  refusedToWrite(await asWriter(writer, "POST",
    "/admin-api/policies/reset-password-policy", { profile: "strict" }),
    "a policy reset");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/rbac/revoke",
    { username: OFFICER, role: "security" }), "a revoke of the role");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/roles/add-member",
    { role: "SECURITY_ADMIN", kind: "application", member: plainApp }),
    "a member added to SECURITY_ADMIN");
  letWrite(await asWriter(writer, "POST", "/admin-api/roles/add-member",
    { role: "DEVICE_COMPLIANCE", kind: "application", member: plainApp }),
    "a member added to another role");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/groups/add-member",
    { group: "Security-Admin", member: VISITOR }),
    "a member added to the role's group, in any case");
  letWrite(await asWriter(writer, "POST", "/admin-api/groups/add-member",
    { group: group, member: VISITOR }), "a member added to another group");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/groups/set-policy",
    { group: group, attribute: "stsPasswordPolicy", policy: "default" }),
    "a group naming another password policy");
  letWrite(await asWriter(writer, "POST", "/admin-api/groups/set-policy",
    { group: group, attribute: "stsPasswordPolicy", policy: "STRICT" }),
    "a group naming the one it names already");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/applications/set",
    { application: app, attribute: "appPasswordPolicy", value: "default" }),
    "an application naming another password policy");
  letWrite(await asWriter(writer, "POST", "/admin-api/applications/set",
    { application: plainApp, attribute: "appPasswordPolicy",
      value: "default" }), "`default` where none is named");
  letWrite(await asWriter(writer, "POST",
    "/admin-api/applications/update-fields",
    { application: app, fields: { appPasswordPolicy: "strict",
      appHomePageUrl: "https://sec-app.example.net/" } }),
    "a grid Save posting the reference unchanged");
  refusedToWrite(await asWriter(writer, "POST",
    "/admin-api/applications/update-fields",
    { application: app, fields: { appPasswordPolicy: "" } }),
    "a grid Save clearing the reference");
  const ldif = function (id, extra) {
    return "dn: cn=" + id + ",ou=applications,dc=" + REALM +
           ",dc=example,dc=net\nobjectClass: top\nobjectClass: " +
           "applicationProcess\nobjectClass: stsApplication\ncn: " + id +
           "\nappIdentifier: " + id + "\n" + (extra || "");
  };
  refusedToWrite(await asWriter(writer, "POST",
    "/admin-api/applications/import-ldif",
    { ldif: ldif("sec-ldif-a", "appPasswordPolicy: strict\n") }),
    "an LDIF file naming a policy");
  letWrite(await asWriter(writer, "POST", "/admin-api/applications/import-ldif",
    { ldif: ldif("sec-ldif-b", "") }), "an LDIF file naming none");
  refusedToWrite(await asWriter(writer, "POST", "/admin-api/users/create",
    { username: usernameFor("sec-named"), invent: false,
      attributes: { cn: "Named", sn: "Named", givenName: "Sec",
                    stsServiceAccountPolicy: "strict" } }),
    "a create naming a policy");
  letWrite(await asWriter(writer, "POST", "/admin-api/users/create",
    { username: usernameFor("sec-unnamed"), invent: false,
      attributes: { cn: "Unnamed", sn: "Unnamed", givenName: "Sec" } }),
    "a create naming none");
  letWrite(await asWriter(writer, "GET", "/admin-api/policies"),
           "a GET of the policies");
  log.debug("Leaving theKinds().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the Security Administrator at " + base + ".");
  const made = await fetch(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "Security administrator " + STAMP }) });
  assert.strictEqual(made.status, 200, "creating the realm answered " +
                     made.status + " " + (await made.text()).slice(0, 300));
  realmBase = base + "/realm/" + REALM;

  log.info("=== 6. the open window, before the claim ===");
  const visitor = await consoleSignIn.signInToTheConsole(realmBase, VISITOR,
                                                         log);
  const open = await visitor.api("GET", "/admin-api/me");
  check("6. a trust realm's open window hands a person holding no role " +
        "read and write, and not security", function () {
    assert.strictEqual(open.status, 200, "it answered " + open.status);
    assert.ok(open.json.read === true && open.json.write === true &&
              open.json.security === false, JSON.stringify(open.json));
  });
  const claimed = await claimConsole();
  check("8. the realm's bootstrap administrator is not seeded into the " +
        "Security Administrator's role", function () {
    const rows = (claimed.grants || []).filter(function (row) {
      return JSON.stringify(row).indexOf('"admin"') >= 0 ||
             row.username === "admin" || row.name === "admin";
    });
    assert.ok(rows.length >= 1, JSON.stringify(claimed.grants).slice(0, 400));
    assert.ok(!/security/i.test(JSON.stringify(rows)),
              JSON.stringify(rows));
  });

  const writer = await consoleSignIn.signInToTheConsole(realmBase, WRITER,
                                                        log,
                                                        { grant: "write" });
  // ONLY the Security Administrator's role: not Admin Write.
  await consoleSignIn.ensureConsoleAccount(realmBase, OFFICER,
                                           log.info.bind(log));
  const granted = await asHarness("POST", "/admin-api/rbac/grant",
                                  { username: OFFICER, role: "security" });
  assert.strictEqual(granted.status, 200,
    "precondition: granting the Security Administrator's role answered " +
    granted.status + " " + granted.text.slice(0, 300));
  const officer = await consoleSignIn.signInToTheConsole(realmBase, OFFICER,
                                                         log);

  const current = await writer.api("GET", "/admin-api/policies");
  assert.strictEqual(current.status, 200, "precondition: GET " +
    "/admin-api/policies answered " + current.status);

  const refused = await writer.api("POST", SAVE, {});
  check("1. Admin Write is refused a Directory → Policies save, 403, in " +
        "words naming the Security Administrator", function () {
    assert.strictEqual(refused.status, 403, "it answered " + refused.status +
                       " " + String(refused.text).slice(0, 300));
    assert.ok(/Security Administrator/.test(errorsOf(refused)),
      "the refusal does not name the role: " + errorsOf(refused));
    assert.ok(!/STS-API-0138/.test(String(refused.text)),
      "the error code was SENT, and a code is recorded, never sent");
  });

  const grant = await writer.api("POST", "/admin-api/rbac/grant",
                                 { username: WRITER, role: "security" });
  check("2. Admin Write is refused granting itself the Security " +
        "Administrator's role", function () {
    assert.strictEqual(grant.status, 403, "it answered " + grant.status +
                       " " + String(grant.text).slice(0, 300));
  });

  const me = await officer.api("GET", "/admin-api/me");
  check("3a. /admin-api/me says the Security Administrator holds security " +
        "and read, and not write", function () {
    assert.strictEqual(me.status, 200, "it answered " + me.status);
    assert.ok(me.json.security === true && me.json.read === true &&
              me.json.write === false,
      "it said " + JSON.stringify({ security: me.json.security,
                                    read: me.json.read,
                                    write: me.json.write,
                                    roles: me.json.roles,
                                    scopes: me.json.scopes }));
  });
  check("9. the holder's token carries admin:security and SECURITY_ADMIN, " +
        "and Admin Write's carries neither", function () {
    assert.ok((me.json.scopes || []).indexOf("admin:security") >= 0 &&
              (me.json.roles || []).indexOf("SECURITY_ADMIN") >= 0,
              JSON.stringify({ scopes: me.json.scopes,
                               roles: me.json.roles }));
  });
  const writerMe = await writer.api("GET", "/admin-api/me");
  check("9. and Admin Write's /admin-api/me holds neither", function () {
    assert.ok((writerMe.json.scopes || []).indexOf("admin:security") < 0 &&
              (writerMe.json.roles || []).indexOf("SECURITY_ADMIN") < 0,
              JSON.stringify({ scopes: writerMe.json.scopes,
                               roles: writerMe.json.roles }));
  });
  const saved = await officer.api("POST", SAVE, {});
  check("3b. the Security Administrator's save is not refused on the " +
        "role's grounds", function () {
    assert.ok(saved.status !== 401 && saved.status !== 403,
      "it answered " + saved.status + " " + String(saved.text).slice(0, 300));
  });

  const created = await officer.api("POST", "/admin-api/users/create",
    { username: usernameFor("sec-nobody"), invent: "no" });
  check("4. the Security Administrator is refused an ordinary write: the " +
        "role implies read and not write", function () {
    assert.strictEqual(created.status, 403, "it answered " + created.status +
                       " " + String(created.text).slice(0, 300));
  });

  const reset = await writer.api("POST", "/admin-api/users/reset-password",
                                 { user: OFFICER });
  check("5. Admin Write is refused acting on a holder's account", function () {
    assert.strictEqual(reset.status, 403, "it answered " + reset.status +
                       " " + String(reset.text).slice(0, 300));
    assert.ok(/Security Administrator/.test(errorsOf(reset)),
      "the refusal does not name the role: " + errorsOf(reset));
  });

  await theKinds(writer);

  // TIDY: the role taken back, through the harness's token.
  const revoked = await asHarness("POST", "/admin-api/rbac/revoke",
                                  { username: OFFICER, role: "security" });
  assert.strictEqual(revoked.status, 200, "revoking the role answered " +
                     revoked.status + " " + revoked.text.slice(0, 200));

  assert.ok(checks >= 6, "only " + checks + " checks ran: a section " +
            "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_security_admin")
  .description("Drive the Security Administrator (#645): Admin Write " +
      "refused a policy save, a grant of the role and a holder's account; " +
      "the Security Administrator let through to the save and refused an " +
      "ordinary write.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
