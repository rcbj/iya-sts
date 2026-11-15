// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_config_dump.js
//
// ---------------------------------------------------------------------------
// THE CONFIGURATION DUMP OVER HTTP. A planted secret, global and in a realm,
// must not come back from `GET /admin-api/config-dump`; the parameters round
// it must, each with its value and source. The masking's rules are
// tests/config_dump.js's.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_config_dump",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("cfgdump-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const KEY = "scim.digestPassword";
const GLOBAL_CANARY = "cfgdump-global-" + STAMP;
const REALM_CANARY = "cfgdump-realm-" + STAMP;

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text };
}

async function must(url, body) {
  log.debug("Entering must().");
  const r = await call("POST", url, body);
  assert.strictEqual(r.status, 200, url + ": " + r.text);
  log.debug("Leaving must().");
}

function rowOf(rows, key) {
  log.debug("Entering rowOf().");
  log.debug("Leaving rowOf().");
  return rows.filter(function (row) {
    return row.key === key;
  })[0];
}

// THE MASKING RULES OF tests/config_dump.js, in this job's realm (D12).
async function realmMasking(inRealm) {
  log.debug("Entering realmMasking().");
  const writes = {
    "krb5.serviceSalt": "salt-" + REALM_CANARY,
    "mail.smtpPasswordRef": "secret/data/smtp-" + STAMP,
    "spiffe.k8sTokenFile": "/var/run/k8s/token-" + STAMP,
    "branding.displayName": "postgres://sts:url-" + REALM_CANARY +
                            "@db:5432/sts",
    "totp.issuer": "Bearer hdr-" + REALM_CANARY,
    "webauthn.rpName": "Endpoint=sb://x;AccessKey=cs-" + REALM_CANARY
  };
  for (const key of Object.keys(writes)) {
    await must(inRealm + "/admin-api/config/set",
               { key: key, value: writes[key] });
  }
  const answer = await call("GET", inRealm + "/admin-api/config-dump");
  assert.strictEqual(answer.status, 200, answer.text);
  assert.ok(answer.text.indexOf(REALM_CANARY) < 0,
            "no realm canary in the realm's dump: " +
            answer.text.slice(0, 200));
  const dump = JSON.parse(answer.text);
  const mask = dump.masking.mask;
  const salt = rowOf(dump.settings, "krb5.serviceSalt");
  assert.strictEqual(salt.value, mask, "a secret-named value is masked");
  assert.strictEqual(salt.masked, true, "and the row says so");
  assert.strictEqual(salt.description, undefined,
                     "a dump row carries no prose");
  log.info("  [ok] a value whose name reads as a secret is masked by name");
  assert.strictEqual(rowOf(dump.settings, "mail.smtpPasswordRef").value,
                     writes["mail.smtpPasswordRef"]);
  assert.strictEqual(rowOf(dump.settings, "spiffe.k8sTokenFile").value,
                     writes["spiffe.k8sTokenFile"]);
  log.info("  [ok] a reference and a file name are shown as written");
  assert.strictEqual(rowOf(dump.settings, "branding.displayName").value,
                     "postgres://sts:" + mask + "@db:5432/sts");
  assert.strictEqual(rowOf(dump.settings, "totp.issuer").value,
                     "Bearer " + mask);
  assert.strictEqual(rowOf(dump.settings, "webauthn.rpName").value,
                     "Endpoint=sb://x;AccessKey=" + mask);
  log.info("  [ok] a URL's password, a header and a connection string's " +
           "key are masked in place, the rest standing");
  assert.strictEqual(typeof rowOf(dump.settings, "global.port").value,
                     "number");
  assert.ok(Array.isArray(rowOf(dump.settings, "gnap.tokenFormats").value));
  log.info("  [ok] a number and a list are shown");

  const table = await call("GET", inRealm + "/admin-api/config");
  assert.strictEqual(table.status, 200, table.text);
  assert.ok(table.text.indexOf(REALM_CANARY) < 0, "the table masks them");
  const rows = JSON.parse(table.text).groups.reduce(function (all, group) {
    return all.concat(group.settings);
  }, []);
  const tableSalt = rowOf(rows, "krb5.serviceSalt");
  assert.strictEqual(tableSalt.value, mask);
  assert.strictEqual(tableSalt.text, mask);
  assert.strictEqual(tableSalt.masked, true);
  assert.ok(typeof tableSalt.description === "string" &&
            tableSalt.description.length > 0, "the table keeps the prose");
  log.info("  [ok] the settings table masks the value and the copy a form " +
           "is drawn from, and keeps the rest of the row");

  const echoed = await call("POST", inRealm + "/admin-api/config/set",
    { key: "branding.displayName",
      value: "postgres://sts:" + mask + "@db:5432/sts" });
  assert.strictEqual(echoed.status, 200, echoed.text);
  assert.ok(/unchanged: the value posted was its mask/
    .test(JSON.parse(echoed.text).message), echoed.text.slice(0, 300));
  const again = JSON.parse((await call("GET", inRealm +
    "/admin-api/config-dump")).text);
  assert.strictEqual(rowOf(again.settings, "branding.displayName").value,
                     "postgres://sts:" + mask + "@db:5432/sts");
  log.info("  [ok] a partly masked value posted back keeps what is held");

  const audited = await call("GET", inRealm + "/admin-api/audit?per=20&" +
                             "action=admin.config-dump");
  const rowsRead = JSON.parse(audited.text).events || [];
  assert.ok(rowsRead.length >= 2, "the reads are audited");
  const read = rowsRead[0];
  assert.strictEqual(read.target, REALM);
  assert.ok(read.actor && read.actor.length > 0, "with who asked");
  assert.strictEqual(read.detail.scope, "realm");
  assert.strictEqual(read.detail.realms, 0);
  assert.ok(read.detail.maskedValues > 0, "and the masked count");
  assert.ok(JSON.stringify(rowsRead).indexOf(REALM_CANARY) < 0,
            "and the audit rows carry no value");
  log.info("  [ok] the read is audited with who asked and the count, and " +
           "no value");
  for (const key of Object.keys(writes)) {
    await must(inRealm + "/admin-api/config/reset", { key: key });
  }
  log.debug("Leaving realmMasking().");
}

async function test() {
  log.debug("Entering test().");
  const inRealm = base + "/realm/" + REALM;
  const before = JSON.parse((await call("GET", base + "/admin-api/config"))
    .text).groups.reduce(function (all, group) {
    return all.concat(group.settings);
  }, []);
  await must(base + "/admin-api/realms/create", { id: REALM });
  await must(base + "/admin-api/config/set",
             { key: KEY, value: GLOBAL_CANARY });
  try {
    await must(inRealm + "/admin-api/config/set",
               { key: KEY, value: REALM_CANARY });

    const table = await call("GET", base + "/admin-api/config");
    assert.strictEqual(table.status, 200, table.text);
    assert.ok(table.text.indexOf(GLOBAL_CANARY) < 0,
              "GET /admin-api/config masks a secret");
    const page = await call("GET", base + "/admin-api/scim");
    assert.ok(page.text.indexOf(GLOBAL_CANARY) < 0,
              "a page's settings block masks it too");
    // A form posts back the mask it was drawn with; the secret stands.
    await must(base + "/admin-api/config/set-many", { [KEY]: "********" });
    const set = await call("POST", base + "/admin-api/config/set",
                           { key: KEY, value: "********" });
    assert.ok(set.text.indexOf(GLOBAL_CANARY) < 0, "a set's answer masks it");
    const kept = await call("POST", inRealm + "/admin-api/config/set",
                            { key: KEY, value: REALM_CANARY });
    assert.ok(kept.text.indexOf(REALM_CANARY) < 0,
              "and so does an answer naming the value just set");

    const listed = await call("GET", base + "/admin-api/realms");
    assert.strictEqual(listed.status, 200, listed.text);
    assert.ok(listed.text.indexOf(REALM_CANARY) < 0,
              "GET /admin-api/realms masks a realm's secret");
    const mode = await call("GET", base + "/admin-api/mode");
    assert.strictEqual(mode.status, 200, mode.text);
    const krbtgt = JSON.parse(mode.text).developmentOnlySettings
      .filter(function (row) {
        return row.key === "krb5.krbtgtPassword";
      })[0];
    assert.ok(krbtgt, "GET /admin-api/mode lists the krbtgt password");
    assert.strictEqual(krbtgt.value, "********", "and masks its value");
    assert.strictEqual(krbtgt.default, "********", "its default");
    assert.strictEqual(krbtgt.inForce, "********", "and what is in force");

    const answer = await call("GET", base + "/admin-api/config-dump");
    assert.strictEqual(answer.status, 200, answer.text);
    assert.ok(answer.text.indexOf(GLOBAL_CANARY) < 0, "the global secret");
    assert.ok(answer.text.indexOf(REALM_CANARY) < 0, "the realm's secret");
    const dump = JSON.parse(answer.text);
    assert.strictEqual(dump.format, "iya-sts-config-dump/1");
    assert.strictEqual(dump.scope, "service");
    assert.strictEqual(dump.settings.length, before.length,
                       "every parameter is in the dump");
    assert.ok(dump.masking.maskedValues > 0, "the count is reported");
    const secret = rowOf(dump.settings, KEY);
    assert.strictEqual(secret.value, dump.masking.mask);
    assert.strictEqual(secret.masked, true);
    assert.strictEqual(typeof rowOf(dump.settings, "global.port").value,
                       "number", "an ordinary parameter is shown");
    const realm = dump.realms.filter(function (one) {
      return one.id === REALM;
    })[0];
    assert.ok(realm, "the realm is listed");
    assert.strictEqual(rowOf(realm.settings, KEY).value, dump.masking.mask);

    const own = await call("GET", inRealm + "/admin-api/config-dump");
    assert.strictEqual(own.status, 200, own.text);
    assert.ok(own.text.indexOf(REALM_CANARY) < 0, "the realm's own read");
    const confined = JSON.parse(own.text);
    assert.strictEqual(confined.scope, "realm");
    assert.strictEqual(confined.realm, REALM);
    assert.strictEqual(confined.realms.length, 0);
    assert.strictEqual(rowOf(confined.settings, KEY).source, "realm");
    await realmMasking(inRealm);
  } finally {
    // RESET rather than set back: a value set back is still a runtime
    // override, and later jobs assert that none is in force.
    await must(base + "/admin-api/config/reset", { key: KEY });
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_config_dump")
  .description("The configuration dump shows every parameter and no secret.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
