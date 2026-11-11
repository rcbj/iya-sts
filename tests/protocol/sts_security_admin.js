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
// What is in process — the classifier, the roster, held ∩ carried — is
// `tests/security_admin.js`. `local: true`: the role and the gate are ours.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

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

// The two people, named for what they hold.
const WRITER = usernameFor("sec-writer");
const OFFICER = usernameFor("sec-officer");
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
  const r = await fetch(base + path, init);
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

async function test() {
  log.debug("Entering test().");
  log.info("Driving the Security Administrator at " + base + ".");

  const writer = await consoleSignIn.signInToTheConsole(base, WRITER, log,
                                                        { grant: "write" });
  // ONLY the Security Administrator's role: not Admin Write.
  await consoleSignIn.ensureConsoleAccount(base, OFFICER, log.info.bind(log));
  const granted = await asHarness("POST", "/admin-api/rbac/grant",
                                  { username: OFFICER, role: "security" });
  assert.strictEqual(granted.status, 200,
    "precondition: granting the Security Administrator's role answered " +
    granted.status + " " + granted.text.slice(0, 300));
  const officer = await consoleSignIn.signInToTheConsole(base, OFFICER, log);

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
