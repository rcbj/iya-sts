// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ldap_rules.js
//
// ---------------------------------------------------------------------------
// THE DIRECTORY'S BIND, READ AND WRITE RULES, ASKED OVER ITS OWN SOCKETS
// (D12, #444).
//
// `ldap/ldap_server.js` decides who may bind, what a connection may read and
// what it may write, and until this job every refusal it records was held only
// in process, through `performOperation()`. That function is the handler the
// socket runs, so the in-process files are right about Node; they say nothing
// about a runtime that replaces it. This asks the same questions of a RUNNING
// service on 389 and 636, the way a directory client does, and reads each
// refusal's code back off `GET /admin-api/audit` — a code is never sent.
//
// **TWO THROWAWAY REALMS, ONE IN EACH MODE.** An LDAP operation runs in the
// realm its DN names, and a realm's `global.mode` is its own, so both modes
// are asserted whichever mode the stack runs in. The product realm also turns
// on `authn.allowOptionalSecondFactor`, as `directory_read_security.js` does:
// a product realm otherwise requires a second factor of everybody, and an
// LDAP simple bind cannot ask for one (STS-AUTHN-0213).
//
// D12 (#444) — what it carries over, by section:
//
//   1. BINDS (tests/directory_read_security.js 1): a password on the plain
//      listener is 13 before it is read (STS-LDAP-0071), a DN with no
//      password 53 (STS-LDAP-0072), the right password over LDAPS binds.
//   2. FAILED BINDS ARE RATE LIMITED (directory_read_security.js 2): per DN,
//      the correct password once the DN is over its limit is 53
//      (STS-LDAP-0073); per address, a success in between resets nothing.
//   3. A READ REQUIRES A BIND (directory_read_security.js 3): an unbound
//      search, compare and search of a DN that does not exist are each 50
//      (STS-LDAP-0074); the root DSE answers.
//   4. CREDENTIALS ARE WITHHELD (directory_read_security.js 4): not returned
//      when asked for by name, invisible to a presence and a substring
//      filter, a compare of one's own userPassword 50 (STS-LDAP-0075), and an
//      administrator is not excepted.
//   5. OPERATIONAL ATTRIBUTES (directory_read_security.js 5): createTimestamp
//      on a modify and modifyTimestamp on an add are 19 (STS-LDAP-0076), an
//      administrator included.
//   6. WHAT A BOUND PERSON SEES (tests/directory_read_authorization.js): the
//      codes `sts_ldap_read_authorization.js` does not read — another
//      person's entry and a compare on it 32 (STS-LDAP-0013), a compare of an
//      unlisted attribute 50 (STS-LDAP-0099), an application's DN binding 49
//      (STS-LDAP-0100) — the member list behind `ldap.groupMembersReadable`,
//      and the audit row counting what a search withheld.
//   7. WHO MAY WRITE (tests/directory_write_authorization.js): an anonymous
//      modify 50 (STS-LDAP-0052); a person on another's entry, an add, a
//      delete and a rename 50 (STS-LDAP-0053); memberOf on one's own entry,
//      a modify mixing in an unlisted attribute (atomically) and an
//      attribute `ldap.selfWritableAttributes` stopped naming 50
//      (STS-LDAP-0054); one's own allowlisted attributes written; a password
//      over LDAP refused by default, a weak one 19 once allowed, a strong one
//      binding afterwards; the realm's Admin Write adding, modifying and
//      deleting; and a namesake in another realm writing nothing.
//   8. A REFUSAL'S TEXT REACHES THE CLIENT (tests/ldap_diagnostic_message.js):
//      the diagnosticMessage of a credential write names the attribute and
//      the page to use (STS-LDAP-0111).
//   9. FILTERS MATCH BY EACH ATTRIBUTE'S RULE (tests/ldap_filter_matching.js
//      B): a person added over LDAP with a mixed-case uid and mail is found
//      in another case by equality and substring, and `memberUid`, an exact
//      attribute, is not.
//  10. AN LDAP ADD REGISTERS AN APPLICATION
//      (tests/ldap_application_registration.js): an administrator's add is
//      stamped `ldap:<their DN>`, an author's value is kept, an entry below
//      an application and a modify are not stamped, an unbound add in
//      development is `ldap`; and product serves the LDAP-added application
//      over WS-Trust where the seen-only one is wst:InvalidScope
//      (STS-WSTRUST-0030).
//  11. DEVELOPMENT REFUSES NONE OF IT.
//
// What stays in process (class d): the dispatched-operation codec carrying
// the client's address (directory_read_security.js 6), a second client
// address for the per-address bucket (every connection from one runner has
// one), and the Kerberos key register being told of a password written over
// LDAP (directory_write_authorization.js 4b's spy).
//
// OWNED HERE (local: true): this repository's own directory and sockets. It
// needs LDAP and LDAPS reachable — STS_LDAP_URL / STS_LDAPS_URL where the
// launcher sets them, otherwise the service's host on STS_LDAP_PORT (389) and
// STS_LDAPS_PORT (636). The realms are left behind.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // No appconfig file: the log level falls back to info, and the reason is
  // reported once the logger exists.
  appconfigProblem = e.message;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ldap_rules",
  level: appconfig.logLevel || appconfig.LOG_LEVEL ||
         process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("No appconfig file was read: " + appconfigProblem);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-12);
const PROD = "lrp" + STAMP;
const DEV = "lrd" + STAMP;
const PERSON = "lr-person-" + STAMP;
const OTHER = "lr-other-" + STAMP;
const ADMIN = "lr-admin-" + STAMP;
const IN_GROUP = "lr-in-" + STAMP;
const PHONE = "+1 555 0100";
const PASSWORD = "Lr-" + crypto.randomBytes(9).toString("base64url") +
                 "-Correct.Horse-42";
const FLOOR_PRODUCT = 60;

// REMOVAL IS OPT-IN (STS_TEST_REMOVE_REALMS=1). tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, where what a job leaves is
// there to be read afterwards; a hand run against a private service sets the
// variable, and the realms this job made are removed at its end, pass or
// fail, so a long series of runs does not fill the directory's ceiling.
const MADE_REALMS = [];

async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE_REALMS) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("  (removed the realm " + id + ": " + r.status + ")");
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm that cannot be removed is left, as a shared run leaves it.
    }
  }
  log.debug("Leaving removeRealms().");
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
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

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
}

function ldapUrl() {
  log.debug("Entering ldapUrl().");
  log.debug("Leaving ldapUrl().");
  return process.env.STS_LDAP_URL ||
    ("ldap://" + hostOf(base) + ":" + (process.env.STS_LDAP_PORT || 389));
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// The audit rows of `realm` carrying `code`, newest first.
async function codeRows(realm, code) {
  log.debug("Entering codeRows(). " + realm + " " + code);
  const r = await call("GET", realmBase(realm) +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status + " " +
                     r.text.slice(0, 300));
  log.debug("Leaving codeRows().");
  return (r.json && r.json.events) || [];
}

// How many rows of `code` name `target` (lower-cased DN), so a check can ask
// for one MORE than there were before its operation.
async function codeCount(realm, code, target) {
  log.debug("Entering codeCount().");
  const rows = await codeRows(realm, code);
  const want = target === undefined ? null : lower(target);
  log.debug("Leaving codeCount().");
  return rows.filter(function (row) {
    return want === null || lower(row.target) === want;
  }).length;
}

// The audit row is written as the operation answers; a moment's grace for a
// cluster node behind is all it needs.
async function recorded(realm, code, target, before) {
  log.debug("Entering recorded(). " + code);
  let now = before;
  for (let i = 0; i < 25 && now <= before; i += 1) {
    now = await codeCount(realm, code, target);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving recorded(). " + before + " -> " + now);
  return now > before;
}

// Run `operation` and assert it was refused with `status` and that a row with
// `code` naming `target` was added to `realm`'s audit log.
async function refusedWith(realm, code, target, status, what, operation) {
  log.debug("Entering refusedWith(). " + what);
  const before = await codeCount(realm, code, target);
  const answer = await operation();
  const seen = await recorded(realm, code, target, before);
  check(what + " — " + status + ", recorded " + code, function () {
    assert.strictEqual(answer.code, status, what + " answered " +
                       answer.code + " " + (answer.message || ""));
    assert.ok(seen, "no new " + code + " row naming " + target + " in " +
              realm + "'s audit log");
  });
  log.debug("Leaving refusedWith().");
  return answer;
}

function connect(url) {
  log.debug("Entering connect(). " + url);
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    // Verified, with the trust this runner has for the service (the
    // launcher's NODE_EXTRA_CA_CERTS), as sts_ldaps.js does.
    tlsOptions: { rejectUnauthorized: true, servername: hostOf(url) }
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back, and an unhandled
    // 'error' is a process-level throw. The operation in flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

function settle(fn) {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    fn(function (e, extra) {
      resolve({ code: e ? e.code : 0, message: e ? String(e.message) : "",
                diagnostic: e ? String(e.diagnosticMessage || "") : "",
                extra: extra });
    });
  });
}

function bind(client, dn, password) {
  log.debug("Entering bind(). " + dn);
  log.debug("Leaving bind().");
  return settle(function (done) {
    client.bind(dn, password, done);
  });
}

function compare(client, dn, attribute, value) {
  log.debug("Entering compare().");
  log.debug("Leaving compare().");
  return settle(function (done) {
    client.compare(dn, attribute, value, function (e, matched) {
      done(e, !!matched);
    });
  });
}

function change(operation, type, values) {
  log.debug("Entering change().");
  log.debug("Leaving change().");
  return new ldapjs.Change({ operation: operation,
    modification: new ldapjs.Attribute({ type: type,
                                         values: [].concat(values) }) });
}

function modify(client, dn, changes) {
  log.debug("Entering modify(). " + dn);
  log.debug("Leaving modify().");
  return settle(function (done) {
    client.modify(dn, changes.map(function (c) {
      return change(c[0], c[1], c[2]);
    }), done);
  });
}

function add(client, dn, attributes) {
  log.debug("Entering add(). " + dn);
  log.debug("Leaving add().");
  return settle(function (done) {
    client.add(dn, attributes, done);
  });
}

function del(client, dn) {
  log.debug("Entering del(). " + dn);
  log.debug("Leaving del().");
  return settle(function (done) {
    client.del(dn, done);
  });
}

function rename(client, dn, newDn) {
  log.debug("Entering rename(). " + dn);
  log.debug("Leaving rename().");
  return settle(function (done) {
    client.modifyDN(dn, newDn, done);
  });
}

// A search that settles either way: ldapjs emits `error` and NEVER `end` for
// a refused search, and a deadline stops a silent server hanging the job.
function search(client, dn, options) {
  log.debug("Entering search(). " + dn);
  log.debug("Leaving search().");
  return new Promise(function (resolve) {
    const entries = [];
    let settled = false;
    const done = function (outcome) {
      log.debug("Entering done().");
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve(outcome);
      }
      log.debug("Leaving done().");
    };
    const deadline = setTimeout(function () {
      done({ code: -1, entries: [] });
    }, 20000);
    client.search(dn, Object.assign({ filter: "(objectClass=*)",
                                      scope: "sub" }, options || {}),
                  function (e, res) {
      if (e) {
        done({ code: e.code, message: e.message, entries: [] });
        return;
      }
      res.on("searchEntry", function (entry) {
        const pojo = entry.pojo || entry;
        entries.push({ dn: lower(pojo.objectName),
                       attributes: pojo.attributes || [] });
      });
      res.on("error", function (err) {
        done({ code: err.code, message: err.message, entries: entries });
      });
      res.on("end", function (result) {
        done({ code: result ? result.status : 0, entries: entries });
      });
    });
  });
}

function unbind(client) {
  log.debug("Entering unbind().");
  log.debug("Leaving unbind().");
  return new Promise(function (resolve) {
    try {
      client.unbind(function () {
        resolve(true);
      });
    } catch (e) {
      log.debug("Caught in unbind(): " + ((e && e.message) || e));
      // A connection the server already closed cannot be unbound, and that
      // is not what any check here is about.
      resolve(false);
    }
  });
}

// A connection bound as `dn`, asserted to have bound.
async function boundAs(dn, password, url) {
  log.debug("Entering boundAs(). " + dn);
  const client = connect(url || ldapsUrl());
  const r = await bind(client, dn, password);
  assert.strictEqual(r.code, 0, "binding as " + dn + " answered " + r.code +
                     " " + r.message);
  log.debug("Leaving boundAs().");
  return client;
}

// One operation on a connection of its own: connect, maybe bind, act, leave.
async function once(dn, password, fn, url) {
  log.debug("Entering once().");
  const client = connect(url || ldapsUrl());
  try {
    if (dn !== null) {
      const r = await bind(client, dn, password);
      assert.strictEqual(r.code, 0, "binding as " + dn + " answered " +
                         r.code + " " + r.message);
    }
    const answer = await fn(client);
    log.debug("Leaving once().");
    return answer;
  } finally {
    await unbind(client);
  }
}

function lower(dn) {
  log.debug("Entering lower().");
  log.debug("Leaving lower().");
  return String(dn || "").toLowerCase().replace(/,\s+/g, ",");
}

function entryFor(result, dn) {
  log.debug("Entering entryFor().");
  log.debug("Leaving entryFor().");
  return (result.entries || []).filter(function (entry) {
    return entry.dn === lower(dn);
  })[0] || null;
}

function namesOf(entry) {
  log.debug("Entering namesOf().");
  log.debug("Leaving namesOf().");
  return ((entry && entry.attributes) || []).map(function (a) {
    return String(a.type || "").toLowerCase();
  });
}

function valuesOf(entry, name) {
  log.debug("Entering valuesOf().");
  const hit = ((entry && entry.attributes) || []).filter(function (a) {
    return String(a.type || "").toLowerCase() === name.toLowerCase();
  })[0];
  log.debug("Leaving valuesOf().");
  return hit ? [].concat(hit.values || []).map(String) : [];
}

function dnsOf(result) {
  log.debug("Entering dnsOf().");
  log.debug("Leaving dnsOf().");
  return (result.entries || []).map(function (entry) {
    return entry.dn;
  });
}

async function setRealm(realm, key, value) {
  log.debug("Entering setRealm(). " + key);
  await ok(realmBase(realm) + "/admin-api/config/set",
           { key: key, value: value }, "set " + key + " in " + realm);
  log.debug("Leaving setRealm().");
}

async function resetRealm(realm, key) {
  log.debug("Entering resetRealm(). " + key);
  const r = await call("POST", realmBase(realm) + "/admin-api/config/reset",
                       { key: key });
  log.debug("Leaving resetRealm(). " + r.status);
}

// The realm, its people, a group and an application; ADMIN holds Admin Write
// on the realm's own roster.
async function setUp(realm, mode) {
  log.debug("Entering setUp(). " + realm);
  await ok(base + "/admin-api/realms/create",
           { id: realm, domain: realm + ".example.net",
             name: "D12 LDAP rules " + mode,
             overrides: { "global.mode": mode } },
           "created the " + mode + " realm " + realm);
  MADE_REALMS.push(realm);
  if (mode === "product") {
    await setRealm(realm, "authn.allowOptionalSecondFactor", "true");
  }
  const api = realmBase(realm) + "/admin-api";
  const dns = { realm: realm };
  for (const who of [PERSON, OTHER, ADMIN]) {
    const made = await ok(api + "/users/create", {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "LR " + who, givenName: "LR", sn: who,
                    mail: who + "@lr.test", telephoneNumber: PHONE } },
      "created " + who + " in " + realm);
    dns[who] = String(made.dn);
  }
  const where = await call("GET", api + "/groups");
  assert.ok(where.status === 200 && where.json && where.json.usersDn,
            "GET " + api + "/groups should name the containers: " +
            where.status + " " + where.text.slice(0, 300));
  dns.users = String(where.json.usersDn);
  dns.groups = String(where.json.groupsDn);
  dns.base = String(where.json.baseDn);
  dns.applications = "ou=applications," + dns.base;
  dns.missing = "uid=lr-nobody-" + STAMP + "," + dns.users;
  await ok(api + "/groups/create", { group: IN_GROUP }, "created the group");
  await ok(api + "/groups/add-member", { group: IN_GROUP, member: PERSON },
           "put the person in it");
  await ok(api + "/groups/add-member", { group: IN_GROUP, member: OTHER },
           "and the other person");
  dns.inGroup = "cn=" + IN_GROUP + "," + dns.groups;
  await ok(api + "/rbac/grant", { username: ADMIN, role: "write" },
           "granted " + ADMIN + " Admin Write on " + realm + "'s roster");
  log.debug("Leaving setUp().");
  return dns;
}

// ---------------------------------------------------------------------------
async function binds(dns) {
  log.debug("Entering binds().");
  log.info("=== 1. PRODUCT: the bind ===");
  await refusedWith(dns.realm, "STS-LDAP-0071", dns[PERSON], 13,
    "PRODUCT: the CORRECT password on the plain listener is refused before " +
    "it is read", function () {
      return once(null, null, function (c) {
        return bind(c, dns[PERSON], PASSWORD);
      }, ldapUrl());
    });
  await refusedWith(dns.realm, "STS-LDAP-0072", dns[PERSON], 53,
    "PRODUCT: a DN with an empty password (an unauthenticated bind)",
    function () {
      return once(null, null, function (c) {
        return bind(c, dns[PERSON], "");
      });
    });
  const good = await once(null, null, function (c) {
    return bind(c, dns[PERSON], PASSWORD);
  });
  check("PRODUCT: the correct password over LDAPS binds", function () {
    assert.strictEqual(good.code, 0, good.message);
  });
  log.debug("Leaving binds().");
}

// Whether a CORRECT bind as `dn` is let through with the realm's per-address
// limit at `limit`. Reading the buckets counts nothing, and a success is not
// a failure, so this asks how full the address bucket is without filling it.
async function allowedAt(dns, dn, limit) {
  log.debug("Entering allowedAt(). " + limit);
  await setRealm(dns.realm, "security.rateLimitPerAddress", String(limit));
  const r = await once(null, null, function (c) {
    return bind(c, dn, PASSWORD);
  });
  log.debug("Leaving allowedAt(). " + r.code);
  return r.code === 0;
}

// The smallest per-address limit that still lets this runner's address bind:
// one more than the failures already in its bucket. The bucket is the
// process's, keyed by the door and the address and shared by every realm,
// so whatever failed from this address in the window is in it.
async function addressThreshold(dns, dn) {
  log.debug("Entering addressThreshold().");
  let low = 1;
  let high = 1000;
  if (!(await allowedAt(dns, dn, high))) {
    log.debug("Leaving addressThreshold(). Full even at 1000.");
    return null;
  }
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (await allowedAt(dns, dn, mid)) {
      high = mid;
    } else {
      low = mid + 1;
    }
  }
  log.debug("Leaving addressThreshold(). " + low);
  return low;
}

// Two failures, a success, a third failure, then the correct password:
// refused, because a success resets the DN's bucket and NEVER the
// address's. Answers the five codes, or null when the bucket's window ran
// out underneath (it restarts at one), which the caller retries.
async function addressRound(dns) {
  log.debug("Entering addressRound().");
  const threshold = await addressThreshold(dns, dns[PERSON]);
  assert.ok(threshold, "the address bucket is full even at a limit of 1000");
  await setRealm(dns.realm, "security.rateLimitPerAddress",
                 String(threshold + 2));
  const codes = [];
  for (const attempt of [[dns[ADMIN], "not-their-password-1"],
                         [dns[ADMIN], "not-their-password-2"],
                         [dns[PERSON], PASSWORD],
                         [dns[ADMIN], "not-their-password-3"]]) {
    const r = await once(null, null, function (c) {
      return bind(c, attempt[0], attempt[1]);
    });
    codes.push(r.code);
  }
  const before = await codeCount(dns.realm, "STS-LDAP-0073", dns[PERSON]);
  const last = await once(null, null, function (c) {
    return bind(c, dns[PERSON], PASSWORD);
  });
  codes.push(last.code);
  const seen = await recorded(dns.realm, "STS-LDAP-0073", dns[PERSON],
                              before);
  log.debug("Leaving addressRound(). " + codes.join(","));
  return { codes: codes, recorded: seen };
}

async function rateLimits(dns) {
  log.debug("Entering rateLimits().");
  log.info("=== 2. PRODUCT: failed binds are rate limited ===");
  await setRealm(dns.realm, "security.rateLimitPerIdentity", "3");
  try {
    for (let i = 0; i < 3; i += 1) {
      const wrong = await once(null, null, function (c) {
        return bind(c, dns[OTHER], PASSWORD + "-wrong-" + i);
      });
      check("PRODUCT: wrong password " + (i + 1) + " of 3 is 49", function () {
        assert.strictEqual(wrong.code, 49, wrong.message);
      });
    }
    await refusedWith(dns.realm, "STS-LDAP-0073", dns[OTHER], 53,
      "PRODUCT: the CORRECT password once the DN is over its limit",
      function () {
        return once(null, null, function (c) {
          return bind(c, dns[OTHER], PASSWORD);
        });
      });
  } finally {
    await resetRealm(dns.realm, "security.rateLimitPerIdentity");
  }
  // THE ADDRESS BUCKET: every connection this runner makes comes from one
  // address, so this asks the half that needs only one — a success between
  // failures resets nothing. A second address is in process only. The
  // limit is set just above what the bucket already holds (found without
  // counting anything), so the third failure is the one that fills it.
  let round = null;
  try {
    for (let i = 0; i < 3; i += 1) {
      round = await addressRound(dns);
      if (round.codes[4] === 53) {
        break;
      }
      log.info("  (the address bucket's window ran out mid-round; again)");
    }
  } finally {
    await resetRealm(dns.realm, "security.rateLimitPerAddress");
  }
  check("PRODUCT: two failures, a SUCCESS and a third failure answer 49, " +
        "49, 0, 49", function () {
    assert.deepStrictEqual(round.codes.slice(0, 4), [49, 49, 0, 49]);
  });
  check("PRODUCT: and then the correct password is refused 53, recorded " +
        "STS-LDAP-0073 — the success did not reset the address", function () {
    assert.strictEqual(round.codes[4], 53, JSON.stringify(round.codes));
    assert.ok(round.recorded, "no STS-LDAP-0073 row");
  });
  log.debug("Leaving rateLimits().");
}

async function unboundReads(dns) {
  log.debug("Entering unboundReads().");
  log.info("=== 3. PRODUCT: a read requires a bind ===");
  await refusedWith(dns.realm, "STS-LDAP-0074", dns.users, 50,
    "PRODUCT: an unbound search", function () {
      return once(null, null, function (c) {
        return search(c, dns.users, {});
      });
    });
  await refusedWith(dns.realm, "STS-LDAP-0074", dns[PERSON], 50,
    "PRODUCT: an unbound compare", function () {
      return once(null, null, function (c) {
        return compare(c, dns[PERSON], "mail", "x");
      });
    });
  await refusedWith(dns.realm, "STS-LDAP-0074", dns.missing, 50,
    "PRODUCT: an unbound search of a DN that does not exist, the same way",
    function () {
      return once(null, null, function (c) {
        return search(c, dns.missing, { scope: "base" });
      });
    });
  const rootDse = await once(null, null, function (c) {
    return search(c, "", { scope: "base" });
  });
  check("PRODUCT: the root DSE still answers before a bind", function () {
    assert.ok(rootDse.code === 0 && rootDse.entries.length === 1,
              JSON.stringify(rootDse).slice(0, 300));
  });
  log.debug("Leaving unboundReads().");
}

async function credentialsWithheld(dns) {
  log.debug("Entering credentialsWithheld().");
  log.info("=== 4. PRODUCT: credentials are withheld ===");
  const client = await boundAs(dns[PERSON], PASSWORD);
  try {
    const asked = await search(client, dns[PERSON], { scope: "base",
      attributes: ["userPassword", "pwdHistory", "*"] });
    const held = namesOf(entryFor(asked, dns[PERSON]));
    check("PRODUCT: userPassword and pwdHistory are not returned even when " +
          "asked for by name", function () {
      assert.ok(asked.code === 0 && held.length > 0 &&
                held.indexOf("userpassword") === -1 &&
                held.indexOf("pwdhistory") === -1, held.join(", "));
      assert.ok(held.indexOf("uid") !== -1, held.join(", "));
    });
    const presence = await search(client, dns.users,
                                  { filter: "(userPassword=*)" });
    check("PRODUCT: (userPassword=*) matches nobody", function () {
      assert.ok(presence.code === 0 && presence.entries.length === 0,
                dnsOf(presence).join(", "));
    });
    const substring = await search(client, dns.users,
      { filter: "(&(uid=" + PERSON + ")(userPassword=$scrypt*))" });
    check("PRODUCT: nor does a substring filter, the one-character oracle",
          function () {
      assert.ok(substring.code === 0 && substring.entries.length === 0,
                dnsOf(substring).join(", "));
    });
    await refusedWith(dns.realm, "STS-LDAP-0075", dns[PERSON], 50,
      "PRODUCT: a compare against their OWN userPassword", function () {
        return compare(client, dns[PERSON], "userPassword", PASSWORD);
      });
    const ordinary = await compare(client, dns[PERSON], "uid", PERSON);
    check("PRODUCT: a compare against an ordinary attribute still answers",
          function () {
      assert.ok(ordinary.code === 0 && ordinary.extra === true,
                JSON.stringify(ordinary));
    });
  } finally {
    await unbind(client);
  }
  const adminRead = await once(dns[ADMIN], PASSWORD, function (c) {
    return search(c, dns[PERSON], { scope: "base",
                                    attributes: ["*", "userPassword"] });
  });
  check("PRODUCT: an administrator is not excepted: no userPassword",
        function () {
    const held = namesOf(entryFor(adminRead, dns[PERSON]));
    assert.ok(adminRead.code === 0 && held.length > 0 &&
              held.indexOf("userpassword") === -1, held.join(", "));
  });
  log.debug("Leaving credentialsWithheld().");
}

async function operationalAttributes(dns) {
  log.debug("Entering operationalAttributes().");
  log.info("=== 5. PRODUCT: operational attributes are the directory's ===");
  await refusedWith(dns.realm, "STS-LDAP-0076", dns[OTHER], 19,
    "PRODUCT: an administrator writing createTimestamp", function () {
      return once(dns[ADMIN], PASSWORD, function (c) {
        return modify(c, dns[OTHER],
                      [["replace", "createTimestamp", "19700101000000Z"]]);
      });
    });
  const addDn = "uid=lr-stamp-" + STAMP + "," + dns.users;
  await refusedWith(dns.realm, "STS-LDAP-0076", addDn, 19,
    "PRODUCT: an add carrying modifyTimestamp", function () {
      return once(dns[ADMIN], PASSWORD, function (c) {
        return add(c, addDn, { objectClass: ["top", "person"], sn: "x",
                               cn: "x", modifyTimestamp: "19700101000000Z" });
      });
    });
  log.debug("Leaving operationalAttributes().");
}

async function boundReads(dns) {
  log.debug("Entering boundReads().");
  log.info("=== 6. PRODUCT: what a bound person may see ===");
  const client = await boundAs(dns[PERSON], PASSWORD);
  try {
    await refusedWith(dns.realm, "STS-LDAP-0013", dns[OTHER], 32,
      "PRODUCT: a base search of another person", function () {
        return search(client, dns[OTHER], { scope: "base" });
      });
    await refusedWith(dns.realm, "STS-LDAP-0013", dns.missing, 32,
      "PRODUCT: a base search of a DN that does not exist — the same answer",
      function () {
        return search(client, dns.missing, { scope: "base" });
      });
    await refusedWith(dns.realm, "STS-LDAP-0013", dns[OTHER], 32,
      "PRODUCT: a compare on another person", function () {
        return compare(client, dns[OTHER], "mail", OTHER + "@lr.test");
      });
    const groupBefore = await search(client, dns.inGroup, { scope: "base" });
    check("PRODUCT: their own group shows no member list by default",
          function () {
      assert.ok(groupBefore.code === 0 &&
                namesOf(entryFor(groupBefore, dns.inGroup))
                  .indexOf("member") === -1,
                JSON.stringify(groupBefore).slice(0, 400));
    });
    const apps = await search(client, dns.applications, {});
    check("PRODUCT: ou=applications shows only itself", function () {
      assert.ok(apps.code === 0 &&
                dnsOf(apps).join("|") === lower(dns.applications),
                dnsOf(apps).join(", "));
    });
  } finally {
    await unbind(client);
  }
  const audit = await call("GET", realmBase(dns.realm) +
    "/admin-api/audit?per=50&action=directory.search");
  const withheld = ((audit.json && audit.json.events) || []).filter(
    function (row) {
      return lower(row.target) === lower(dns.applications);
    })[0];
  check("PRODUCT: the search's audit row counts what it withheld",
        function () {
    assert.ok(withheld && withheld.detail &&
              withheld.detail.withheldEntries >= 1,
              JSON.stringify(withheld && withheld.detail));
  });

  await setRealm(dns.realm, "ldap.directoryReadableAttributes",
                 "objectClass,cn,uid,mail");
  await setRealm(dns.realm, "ldap.groupMembersReadable", "true");
  try {
    const widened = await boundAs(dns[PERSON], PASSWORD);
    try {
      let mail = { code: -1 };
      for (let i = 0; i < 40 && mail.code !== 0; i += 1) {
        mail = await compare(widened, dns[OTHER], "mail",
                             OTHER + "@lr.test");
        if (mail.code !== 0) {
          await sleep(250);
        }
      }
      check("PRODUCT: widened, a compare of a listed attribute answers",
            function () {
        assert.ok(mail.code === 0 && mail.extra === true,
                  JSON.stringify(mail));
      });
      await refusedWith(dns.realm, "STS-LDAP-0099", dns[OTHER], 50,
        "PRODUCT: a compare of an unlisted attribute the entry holds",
        function () {
          return compare(widened, dns[OTHER], "telephoneNumber", PHONE);
        });
      await refusedWith(dns.realm, "STS-LDAP-0099", dns[OTHER], 50,
        "PRODUCT: and of one it does not hold, the same way", function () {
          return compare(widened, dns[OTHER], "title", "x");
        });
      const members = await search(widened, dns.inGroup, { scope: "base" });
      check("PRODUCT: ldap.groupMembersReadable turns the member list on",
            function () {
        assert.ok(members.code === 0 &&
                  namesOf(entryFor(members, dns.inGroup))
                    .indexOf("member") !== -1,
                  JSON.stringify(members).slice(0, 400));
      });
    } finally {
      await unbind(widened);
    }
  } finally {
    await resetRealm(dns.realm, "ldap.directoryReadableAttributes");
    await resetRealm(dns.realm, "ldap.groupMembersReadable");
  }
  log.debug("Leaving boundReads().");
}

async function writes(dns) {
  log.debug("Entering writes().");
  log.info("=== 7. PRODUCT: who may write ===");
  await refusedWith(dns.realm, "STS-LDAP-0052", dns[PERSON], 50,
    "PRODUCT: an anonymous connection may not modify even an allowlisted " +
    "attribute", function () {
      return once(null, null, function (c) {
        return modify(c, dns[PERSON], [["replace", "telephoneNumber", "1"]]);
      });
    });
  const person = await boundAs(dns[PERSON], PASSWORD);
  const admin = await boundAs(dns[ADMIN], PASSWORD);
  try {
    await refusedWith(dns.realm, "STS-LDAP-0053", dns[OTHER], 50,
      "PRODUCT: a person modifying somebody else's entry", function () {
        return modify(person, dns[OTHER],
                      [["replace", "telephoneNumber", "3"]]);
      });
    await refusedWith(dns.realm, "STS-LDAP-0054",
      dns[PERSON], 50, "PRODUCT: a person writing memberOf on their own entry",
      function () {
        return modify(person, dns[PERSON],
          [["add", "memberOf", "cn=admin-write," + dns.groups]]);
      });
    const afterEscalation = await search(admin, dns[PERSON],
                                         { scope: "base" });
    check("PRODUCT: and no memberOf value landed on the entry", function () {
      assert.deepStrictEqual(valuesOf(entryFor(afterEscalation, dns[PERSON]),
                                      "memberOf"), []);
    });
    const own = await modify(person, dns[PERSON],
      [["replace", "telephoneNumber", "+1 555 0101"],
       ["replace", "displayName", "Probe"]]);
    const stored = await search(admin, dns[PERSON], { scope: "base" });
    check("PRODUCT: a person may change allowlisted attributes on their own " +
          "entry, and the value is stored", function () {
      assert.strictEqual(own.code, 0, own.message);
      assert.deepStrictEqual(valuesOf(entryFor(stored, dns[PERSON]),
                                      "telephoneNumber"), ["+1 555 0101"]);
    });
    await refusedWith(dns.realm, "STS-LDAP-0054", dns[PERSON], 50,
      "PRODUCT: a modify mixing an allowlisted attribute with mail",
      function () {
        return modify(person, dns[PERSON],
          [["replace", "telephoneNumber", "+1 555 0199"],
           ["replace", "mail", "me@lr.test"]]);
      });
    const atomic = await search(admin, dns[PERSON], { scope: "base" });
    check("PRODUCT: and it is atomic: the allowlisted half was not applied",
          function () {
      assert.deepStrictEqual(valuesOf(entryFor(atomic, dns[PERSON]),
                                      "telephoneNumber"), ["+1 555 0101"]);
    });
    await setRealm(dns.realm, "ldap.selfWritableAttributes", "mail");
    try {
      let widened = { code: -1 };
      for (let i = 0; i < 40 && widened.code !== 0; i += 1) {
        widened = await modify(person, dns[PERSON],
                               [["replace", "MAIL", "me@lr.test"]]);
        if (widened.code !== 0) {
          await sleep(250);
        }
      }
      check("PRODUCT: the list is the setting, matched case-insensitively: " +
            "naming mail lets MAIL through", function () {
        assert.strictEqual(widened.code, 0, widened.message);
      });
      await refusedWith(dns.realm, "STS-LDAP-0054", dns[PERSON], 50,
        "PRODUCT: and an attribute the edited list no longer names",
        function () {
          return modify(person, dns[PERSON],
                        [["replace", "telephoneNumber", "2"]]);
        });
    } finally {
      await resetRealm(dns.realm, "ldap.selfWritableAttributes");
    }
    const newDn = "uid=lr-new-" + STAMP + "," + dns.users;
    await refusedWith(dns.realm, "STS-LDAP-0053", newDn, 50,
      "PRODUCT: a person adding an entry", function () {
        return add(person, newDn, { objectClass: ["top", "person"],
                                    sn: "x", cn: "x" });
      });
    await refusedWith(dns.realm, "STS-LDAP-0053", dns[PERSON], 50,
      "PRODUCT: a person deleting their own entry", function () {
        return del(person, dns[PERSON]);
      });
    await refusedWith(dns.realm, "STS-LDAP-0053", dns[PERSON], 50,
      "PRODUCT: a person renaming their own entry", function () {
        return rename(person, dns[PERSON],
                      "uid=lr-renamed-" + STAMP + "," + dns.users);
      });
    const still = await search(admin, dns[PERSON], { scope: "base" });
    check("PRODUCT: and their entry is still where it was", function () {
      assert.ok(entryFor(still, dns[PERSON]), dnsOf(still).join(", "));
    });

    const byDefault = await modify(person, dns[PERSON],
      [["replace", "userPassword", "A-long-passphrase-9-Zz!"]]);
    check("PRODUCT: by default a person may not set their password over " +
          "LDAP (50)", function () {
      assert.strictEqual(byDefault.code, 50, byDefault.message);
    });
    await setRealm(dns.realm, "ldap.selfWritableAttributes",
                   "userPassword,mail");
    const NEW_PASSWORD = "Self-Service-Passw0rd!" + STAMP;
    try {
      let weak = { code: -1 };
      for (let i = 0; i < 40 && weak.code === 50; i += 1) {
        weak = await modify(person, dns[PERSON],
                            [["replace", "userPassword", "short"]]);
        if (weak.code === 50) {
          await sleep(250);
        }
      }
      if (weak.code === -1) {
        weak = await modify(person, dns[PERSON],
                            [["replace", "userPassword", "short"]]);
      }
      check("PRODUCT: allowed, a password that breaks the policy is a " +
            "constraint violation (19), not an authorization refusal",
            function () {
        assert.strictEqual(weak.code, 19, weak.message);
      });
      const strong = await modify(person, dns[PERSON],
        [["replace", "userPassword", NEW_PASSWORD]]);
      check("PRODUCT: and a strong one is written", function () {
        assert.strictEqual(strong.code, 0, strong.message);
      });
    } finally {
      await resetRealm(dns.realm, "ldap.selfWritableAttributes");
    }
    const rebound = await once(null, null, function (c) {
      return bind(c, dns[PERSON], NEW_PASSWORD);
    });
    const oldOne = await once(null, null, function (c) {
      return bind(c, dns[PERSON], PASSWORD);
    });
    check("PRODUCT: the new password binds and the old one no longer does",
          function () {
      assert.strictEqual(rebound.code, 0, rebound.message);
      assert.strictEqual(oldOne.code, 49, oldOne.message);
    });
    dns.personPassword = NEW_PASSWORD;

    const adminModify = await modify(admin, dns[OTHER],
      [["replace", "mail", "set@lr.test"]]);
    const adminAdd = await add(admin, newDn,
      { objectClass: ["top", "person", "inetOrgPerson"], sn: "x", cn: "x",
        givenName: "x", mail: "lr-new-" + STAMP + "@lr.test" });
    const adminDelete = await del(admin, newDn);
    check("PRODUCT: the realm's Admin Write modifies, adds and deletes",
          function () {
      assert.deepStrictEqual([adminModify.code, adminAdd.code,
                              adminDelete.code], [0, 0, 0],
                             [adminModify, adminAdd, adminDelete].map(
                               function (r) {
                                 return r.code + " " + r.message;
                               }).join(" / "));
    });
  } finally {
    await unbind(person);
    await unbind(admin);
  }
  log.debug("Leaving writes().");
}

// A person in the OTHER realm bearing the administrator's name is nobody in
// this one.
async function namesake(prodDns, devDns) {
  log.debug("Entering namesake().");
  const foreign = devDns[ADMIN];
  check("precondition: the development realm holds an entry with the " +
        "administrator's name", function () {
    assert.ok(lower(foreign) !== lower(prodDns[ADMIN]) &&
              lower(foreign).indexOf(DEV) !== -1, foreign);
  });
  await refusedWith(prodDns.realm, "STS-LDAP-0053", prodDns[OTHER], 50,
    "PRODUCT: a DN in another realm bearing an administrator's name writes " +
    "nothing", function () {
      return once(foreign, "anything-at-all", function (c) {
        return modify(c, prodDns[OTHER], [["replace", "mail", "z@lr.test"]]);
      });
    });
  log.debug("Leaving namesake().");
}

async function diagnosticMessage(dns) {
  log.debug("Entering diagnosticMessage().");
  log.info("=== 8. a refusal's text reaches the client ===");
  const answer = await refusedWith(dns.realm, "STS-LDAP-0111", dns[PERSON],
    53, "the realm's administrator writing stsTotpCredential on somebody's " +
    "entry", function () {
      return once(dns[ADMIN], PASSWORD, function (c) {
        return modify(c, dns[PERSON],
                      [["replace", "stsTotpCredential", "{}"]]);
      });
    });
  check("and its diagnosticMessage names the attribute and the door that " +
        "writes it, /portal/mfa", function () {
    // The server names the attribute lower-cased, as it matches it.
    assert.ok(answer.diagnostic.toLowerCase()
                .indexOf("ststotpcredential") >= 0 &&
              answer.diagnostic.indexOf("/portal/mfa") >= 0,
              JSON.stringify(answer));
  });
  log.debug("Leaving diagnosticMessage().");
}

async function filterMatching(dns, password) {
  log.debug("Entering filterMatching().");
  log.info("=== 9. " + dns.realm + ": filters match by each attribute's " +
           "rule ===");
  const uid = "LR-Mixed-" + STAMP.toUpperCase();
  const dn = "uid=" + uid + "," + dns.users;
  const mail = "LR.Mixed." + STAMP + "@LR.Example";
  const group = "cn=lr-uids-" + STAMP + "," + dns.groups;
  const admin = await boundAs(dns[ADMIN], password);
  try {
    const made = await add(admin, dn, {
      objectClass: ["top", "person", "inetOrgPerson"], uid: uid, sn: "M",
      cn: "LR Mixed", givenName: "LR", mail: mail });
    const gmade = await add(admin, group, {
      objectClass: ["top", "posixGroup"], cn: "lr-uids-" + STAMP,
      gidNumber: "7001", memberUid: uid });
    check(dns.realm + ": a person and a posixGroup added over LDAP",
          function () {
      assert.deepStrictEqual([made.code, gmade.code], [0, 0],
                             made.code + " " + made.message + " / " +
                             gmade.code + " " + gmade.message);
    });
    const tries = [
      ["(uid=" + uid.toLowerCase() + ")", true, "uid equality, lower case"],
      ["(uid=" + uid.toUpperCase() + ")", true, "uid equality, upper case"],
      ["(uid=lr-mixed-*)", true, "uid initial substring, another case"],
      ["(uid=*-MIXED-*)", true, "uid any substring"],
      ["(mail=" + mail.toUpperCase() + ")", true, "mail equality"],
      ["(mail=*@lr.example)", true, "mail final substring"],
      ["(&(uid=" + uid.toLowerCase() + ")(!(cn=nobody)))", true,
       "AND and NOT compose"],
      ["(|(uid=nobody)(cn=lr mixed))", true, "OR, and cn ignores case"]
    ];
    for (const one of tries) {
      const r = await search(admin, dns.users, { filter: one[0] });
      check(dns.realm + ": " + one[2] + " " + one[0] + " finds the person",
            function () {
        assert.ok(r.code === 0 && !!entryFor(r, dn) === one[1],
                  r.code + " " + dnsOf(r).join(", "));
      });
    }
    const exact = await search(admin, dns.groups,
      { filter: "(memberUid=" + uid.toLowerCase() + ")" });
    const asStored = await search(admin, dns.groups,
      { filter: "(memberUid=" + uid + ")" });
    check(dns.realm + ": memberUid is exact — another case finds nothing, " +
          "the stored case finds the group", function () {
      assert.ok(exact.code === 0 && !entryFor(exact, group),
                dnsOf(exact).join(", "));
      assert.ok(asStored.code === 0 && !!entryFor(asStored, group),
                dnsOf(asStored).join(", "));
    });
  } finally {
    await unbind(admin);
  }
  log.debug("Leaving filterMatching().");
}

// Read an application's appRegisteredBy over LDAP as the realm's
// administrator: '' when it carries none, null when it is not there.
async function registeredBy(dns, password, dn) {
  log.debug("Entering registeredBy().");
  const r = await once(dns[ADMIN], password, function (c) {
    return search(c, dn, { scope: "base", attributes: ["*"] });
  });
  const entry = entryFor(r, dn);
  log.debug("Leaving registeredBy().");
  return entry ? valuesOf(entry, "appRegisteredBy").join(",") : null;
}

function wsTrustRst(username, password, appliesTo) {
  log.debug("Entering wsTrustRst().");
  log.debug("Leaving wsTrustRst().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + username + '</wsse:Username>' +
    '<wsse:Password>' + password +
    '</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    appliesTo +
    '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
}

async function wsTrust(realm, username, password, appliesTo) {
  log.debug("Entering wsTrust(). " + appliesTo);
  const r = await fetch(realmBase(realm) + "/sts", { method: "POST",
    headers: { "content-type": "application/soap+xml" },
    body: wsTrustRst(username, password, appliesTo) });
  const text = await r.text();
  log.debug("Leaving wsTrust(). " + r.status);
  return { status: r.status, text: text };
}

async function applicationRegistration(prod, dev) {
  log.debug("Entering applicationRegistration().");
  log.info("=== 10. an LDAP add registers an application ===");
  const added = {};
  for (const dns of [prod, dev]) {
    const mode = dns === prod ? "PRODUCT" : "development";
    const password = dns === prod ? PASSWORD : "anything";
    const id = "https://lr-added-" + dns.realm + ".example";
    const dn = "cn=lr-added-" + STAMP + "," + dns.applications;
    const authored = "https://lr-authored-" + dns.realm + ".example";
    const authoredDn = "cn=lr-authored-" + STAMP + "," + dns.applications;
    const belowDn = "cn=lr-below," + dn;
    const results = await once(dns[ADMIN], password, async function (c) {
      return [
        await add(c, dn, { objectClass: ["top", "applicationProcess"],
                           cn: "lr-added-" + STAMP, appIdentifier: id }),
        await add(c, authoredDn, { objectClass: ["top", "applicationProcess"],
                                   cn: "lr-authored-" + STAMP,
                                   appIdentifier: authored,
                                   appRegisteredBy: "administrator" }),
        await add(c, belowDn, { objectClass: ["top"], cn: "lr-below" })
      ];
    });
    check(mode + ": three adds under ou=applications answer 0", function () {
      assert.deepStrictEqual(results.map(function (r) {
        return r.code;
      }), [0, 0, 0], results.map(function (r) {
        return r.code + " " + r.message;
      }).join(" / "));
    });
    const by = await registeredBy(dns, password, dn);
    check(mode + ": an application added over LDAP by an administrator is " +
          "registered as ldap:<their DN>", function () {
      assert.strictEqual(lower(by), "ldap:" + lower(dns[ADMIN]));
    });
    const kept = await registeredBy(dns, password, authoredDn);
    check(mode + ": an add carrying appRegisteredBy keeps the author's value",
          function () {
      assert.strictEqual(kept, "administrator");
    });
    const below = await registeredBy(dns, password, belowDn);
    check(mode + ": an entry below an application is not stamped",
          function () {
      assert.strictEqual(below, "");
    });
    added[dns.realm] = id;
  }
  const anonId = "https://lr-anon-" + dev.realm + ".example";
  const anonDn = "cn=lr-anon-" + STAMP + "," + dev.applications;
  const anon = await once(null, null, function (c) {
    return add(c, anonDn, { objectClass: ["top", "applicationProcess"],
                            cn: "lr-anon-" + STAMP, appIdentifier: anonId });
  });
  const anonBy = await registeredBy(dev, "anything", anonDn);
  check("development: an unbound add is registered as ldap", function () {
    assert.strictEqual(anon.code, 0, anon.message);
    assert.strictEqual(anonBy, "ldap");
  });

  // A SIGHTING: a development realm files an AppliesTo it was asked for, and
  // the realm is then switched to product — the entry is still unregistered,
  // even after an administrator's LDAP modify.
  const seen = "https://lr-seen-" + STAMP + ".example";
  const realm = "lrs" + STAMP;
  await ok(base + "/admin-api/realms/create",
           { id: realm, domain: realm + ".example.net",
             name: "D12 LDAP sighting" }, "created " + realm);
  MADE_REALMS.push(realm);
  const api = realmBase(realm) + "/admin-api";
  const adminMade = await ok(api + "/users/create", {
    username: ADMIN, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "LR admin", givenName: "LR", sn: ADMIN,
                  mail: ADMIN + "@lr.test" } }, "created the administrator");
  await ok(api + "/rbac/grant", { username: ADMIN, role: "write" },
           "granted Admin Write in " + realm);
  const sighted = await wsTrust(realm, ADMIN, PASSWORD, seen);
  check("development: a WS-Trust Issue for an unknown AppliesTo issues and " +
        "files it", function () {
    assert.strictEqual(sighted.status, 200, sighted.text.slice(0, 300));
  });
  const listed = await call("GET", api + "/applications?per=300");
  const view = ((listed.json && (listed.json.applications ||
                                 listed.json.rows)) || []).filter(
    function (a) {
      return a.identifier === seen || a.appIdentifier === seen;
    })[0];
  check("precondition: the sighting is filed, unregistered", function () {
    assert.ok(view && view.dn && !view.registeredBy,
              JSON.stringify(view || listed.text.slice(0, 400)));
  });
  const sightDns = { realm: realm, applications: "" };
  sightDns[ADMIN] = String(adminMade.dn);
  const modified = await once(sightDns[ADMIN], PASSWORD, function (c) {
    return modify(c, view.dn, [["replace", "appName", "modified over LDAP"]]);
  });
  const stillUnregistered = await registeredBy(sightDns, PASSWORD, view.dn);
  check("development: an LDAP modify of the seen-only entry does not " +
        "register it", function () {
    assert.strictEqual(modified.code, 0, modified.message);
    assert.strictEqual(stillUnregistered, "");
  });
  await setRealm(realm, "global.mode", "product");
  await setRealm(realm, "authn.allowOptionalSecondFactor", "true");
  const before = await codeCount(realm, "STS-WSTRUST-0030");
  const refusedSeen = await wsTrust(realm, ADMIN, PASSWORD, seen);
  const seenRecorded = await recorded(realm, "STS-WSTRUST-0030", undefined,
                                      before);
  check("PRODUCT: the seen-only application, modified over LDAP, is " +
        "wst:InvalidScope (STS-WSTRUST-0030)", function () {
    assert.ok(refusedSeen.status === 500 &&
              /InvalidScope/.test(refusedSeen.text),
              refusedSeen.status + " " + refusedSeen.text.slice(0, 400));
    assert.ok(seenRecorded, "no STS-WSTRUST-0030 row in " + realm);
  });
  const servedProd = await wsTrust(prod.realm, ADMIN, PASSWORD,
                                   added[prod.realm]);
  check("PRODUCT: a WS-Trust Issue for the LDAP-added application is issued",
        function () {
    assert.ok(servedProd.status === 200 &&
              /Assertion/.test(servedProd.text),
              servedProd.status + " " + servedProd.text.slice(0, 400));
  });
  log.debug("Leaving applicationRegistration().");
}

async function development(dns) {
  log.debug("Entering development().");
  log.info("=== 11. development refuses none of it ===");
  const anonymous = await once(null, null, function (c) {
    return modify(c, dns[OTHER], [["replace", "mail", "dev@lr.test"]]);
  });
  check("development: an anonymous connection may modify somebody else's " +
        "entry", function () {
    assert.strictEqual(anonymous.code, 0, anonymous.message);
  });
  const plain = await once(null, null, function (c) {
    return bind(c, dns[PERSON], "wrong-and-plain");
  }, ldapUrl());
  check("development: any password on the plain listener binds", function () {
    assert.strictEqual(plain.code, 0, plain.message);
  });
  const read = await once(null, null, function (c) {
    return search(c, dns.users, { filter: "(userPassword=*)",
                                  attributes: ["userPassword"] });
  });
  check("development: an unbound search may filter on and read " +
        "userPassword — which is what makes the product zero a refusal",
        function () {
    assert.ok(read.code === 0 && read.entries.length >= 1 &&
              namesOf(read.entries[0]).indexOf("userpassword") !== -1,
              JSON.stringify(read).slice(0, 300));
  });
  const other = await once(dns[PERSON], "anything", function (c) {
    return search(c, dns[OTHER], { scope: "base" });
  });
  check("development: a person reads another person", function () {
    assert.ok(other.code === 0 && entryFor(other, dns[OTHER]),
              JSON.stringify(other).slice(0, 300));
  });
  log.debug("Leaving development().");
}

async function test() {
  log.debug("Entering test().");
  log.info("LDAPS at " + ldapsUrl() + ", LDAP at " + ldapUrl() + "; realms " +
           PROD + " (product) and " + DEV + " (development), left behind.");
  const prod = await setUp(PROD, "product");
  const dev = await setUp(DEV, "development");
  await binds(prod);
  await rateLimits(prod);
  await unboundReads(prod);
  await credentialsWithheld(prod);
  await operationalAttributes(prod);
  await boundReads(prod);
  const appBind = await once(null, null, async function (c) {
    const apiApps = await call("GET", realmBase(PROD) +
                               "/admin-api/applications?per=300");
    const any = ((apiApps.json && (apiApps.json.applications ||
                                   apiApps.json.rows)) || []).filter(
      function (a) {
        return a.dn && lower(a.dn).indexOf(lower(prod.applications)) !== -1;
      })[0];
    assert.ok(any, "no application with a DN in " + PROD + ": " +
              apiApps.text.slice(0, 300));
    prod.appDn = any.dn;
    const before = await codeCount(PROD, "STS-LDAP-0100", any.dn);
    const r = await bind(c, any.dn, PASSWORD);
    r.recorded = await recorded(PROD, "STS-LDAP-0100", any.dn, before);
    return r;
  });
  check("PRODUCT: a bind as an application's DN is 49, recorded " +
        "STS-LDAP-0100", function () {
    assert.strictEqual(appBind.code, 49, appBind.message);
    assert.ok(appBind.recorded, "no STS-LDAP-0100 row for " + prod.appDn);
  });
  await writes(prod);
  await namesake(prod, dev);
  await diagnosticMessage(prod);
  await filterMatching(prod, PASSWORD);
  await filterMatching(dev, "anything");
  await applicationRegistration(prod, dev);
  await development(dev);
  // A FLOOR on the count: a section that stops running must fail the job.
  assert.ok(checks >= FLOOR_PRODUCT,
    "only " + checks + " checks ran; a section stopped running.");
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "ignored; kept for a uniform CLI across the suite"));
program.parse(process.argv);

test().then(async function () {
  await removeRealms();
  log.info("Test completed successfully.");
}).catch(async function (e) {
  log.error(e.stack || e.message);
  await removeRealms();
  process.exit(1);
});
