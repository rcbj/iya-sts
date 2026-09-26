"use strict";
//
// File: sts_devices.js
//
// ---------------------------------------------------------------------------
// THE DEVICE REGISTER THROUGH THE MANAGEMENT API (#164 phase 1, #218,
// 2026-09-26), over HTTP, in a throwaway realm.
//
//   1. An administrator registers a PERSON's device with a JWK, and an
//      APPLICATION's device — decision 5's two kinds of owner.
//   2. The lists: filtered by owner kind and key kind, paged (a page past the
//      end is clamped), and one device by id — `found: false` for an id the
//      realm does not hold.
//   3. Edits: the label and platform, a second key, a key another device
//      holds refused, a private JWK refused, a key removed.
//   4. The refusals: an unknown action in the sentence the parity jobs read,
//      an unknown owner, and a person at `devices.maxPerPerson` (the
//      setting moved there from `oauth2.maxDevicesPerPerson` in #218).
//   5. The three other views: Monitoring → Devices' counts and timeline,
//      Device registration's methods and settings, and the entries as the
//      directory holds them — the Native SSO hash never among them.
//   6. Removal, counted as an event.
//
// OWNED HERE (local: true): this repository's register and management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_devices",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("dev-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                            .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const OWNER = names.usernameFor("dev-owner");
const PASSWORD = "Dev-owner-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const HOST = "dev-host-" + STAMP.toLowerCase().replace(/[^a-z0-9-]/g, "");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function hop(method, url, json) {
  log.debug("Entering hop(). " + method + " " + url);
  const headers = {};
  let body;
  if (json !== undefined) {
    body = JSON.stringify(json);
    headers["content-type"] = "application/json";
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const text = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    parsed = null;
  }
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: parsed };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop("POST", url, payload || {});
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await hop("POST", url, payload || {});
  assert.ok(r.status === 400 && r.json && r.json.ok === false &&
            (r.json.errors || []).length,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving refused().");
  return r.json.errors.join(" ");
}

async function read(path) {
  log.debug("Entering read(). " + path);
  const r = await hop("GET", api + path);
  assert.strictEqual(r.status, 200, "GET " + path + " answered " + r.status +
                     " " + r.text.slice(0, 300));
  log.debug("Leaving read().");
  return r.json;
}

function publicJwk() {
  log.debug("Entering publicJwk().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving publicJwk().");
  return { pub: pair.publicKey.export({ format: "jwk" }),
           priv: pair.privateKey.export({ format: "jwk" }) };
}

function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  const canonical = '{"crv":' + JSON.stringify(jwk.crv) + ',"kty":' +
    JSON.stringify(jwk.kty) + ',"x":' + JSON.stringify(jwk.x) + ',"y":' +
    JSON.stringify(jwk.y) + "}";
  log.debug("Leaving thumbprint().");
  return crypto.createHash("sha256").update(canonical).digest("base64url");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Devices " + STAMP },
    "created the realm");
  await registry.provision(base, {
    identifier: HOST, name: "Device job host", protocols: ["oauth2"],
    fields: { oauthClientId: HOST },
    why: "the application sts_devices.js registers a device for"
  });
  await registry.ensurePerson(base, OWNER, PASSWORD);

  log.info("=== 1. registration, by an administrator ===");
  const key = publicJwk();
  const laptop = await ok(api + "/devices/create", { owner: OWNER,
    label: "Owner laptop", platform: "macos", keyKind: "jwk",
    key: key.pub }, "registered a person's device");
  const host = await ok(api + "/devices/create", { owner: HOST,
    ownerKind: "application", label: "Build host", platform: "linux",
    applications: [HOST] }, "registered an application's device");
  check("a person's device and an application's, one owner each",
        function () {
    assert.strictEqual(laptop.device.ownerKind, "person");
    assert.strictEqual(laptop.device.ownerName, OWNER);
    assert.strictEqual(laptop.device.enrolment.method, "admin");
    assert.strictEqual(laptop.device.keys.length, 1);
    assert.strictEqual(laptop.device.keys[0].thumbprint,
                       thumbprint(key.pub));
    assert.strictEqual(laptop.device.keys[0].proof, "admin");
    assert.strictEqual(laptop.device.attestation.level, "self-asserted");
    assert.strictEqual(host.device.ownerKind, "application");
    assert.strictEqual(host.device.ownerName, HOST);
    assert.deepStrictEqual(host.device.applicationNames, [HOST]);
    assert.ok(/,ou=devices,/.test(host.device.dn), host.device.dn);
  });

  log.info("=== 2. the lists ===");
  const all = await read("/devices");
  const apps = await read("/devices?ownerKind=application");
  const jwks = await read("/devices?keyKind=jwk");
  check("the list, filtered by owner kind and by key kind", function () {
    assert.strictEqual(all.total, 2, JSON.stringify(all).slice(0, 300));
    assert.strictEqual(apps.matched, 1);
    assert.strictEqual(apps.devices[0].id, host.device.id);
    assert.strictEqual(jwks.matched, 1);
    assert.strictEqual(jwks.devices[0].id, laptop.device.id);
    assert.ok(all.devices.every(function (d) {
      return d.secretHash === undefined && d.session === undefined;
    }));
  });
  const paged = await read("/devices?per=1&page=99");
  check("paged, and a page past the end is clamped", function () {
    assert.strictEqual(paged.perPage, 1);
    assert.strictEqual(paged.pages, 2);
    assert.strictEqual(paged.page, 2);
    assert.strictEqual(paged.devices.length, 1);
    assert.strictEqual(paged.devicesPaging.total, 2);
  });
  const one = await read("/devices?device=" + laptop.device.id);
  const none = await read("/devices?device=no-such-device");
  check("one device by id, and an unknown id is an answer", function () {
    assert.strictEqual(one.found, true);
    assert.strictEqual(one.device.label, "Owner laptop");
    assert.strictEqual(none.found, false);
  });

  log.info("=== 3. edits ===");
  await ok(api + "/devices/update", { id: laptop.device.id,
    label: "Owner's laptop", platform: "windows" }, "saved the label");
  const second = publicJwk();
  const added = await ok(api + "/devices/add-key", { id: laptop.device.id,
    kind: "jwk", value: second.pub, label: "second" }, "added a key");
  const taken = await refused(api + "/devices/add-key", {
    id: host.device.id, kind: "jwk", value: second.pub },
    "a key another device holds");
  const secret = await refused(api + "/devices/add-key", {
    id: host.device.id, kind: "jwk", value: publicJwk().priv },
    "a private JWK");
  let edited = await read("/devices?device=" + laptop.device.id);
  check("the label and platform saved, a second key, and a key another " +
        "device holds or a private one refused", function () {
    assert.strictEqual(edited.device.label, "Owner's laptop");
    assert.strictEqual(edited.device.platform, "windows");
    assert.strictEqual(edited.device.keys.length, 2);
    assert.ok(/already registered to device/.test(taken), taken);
    assert.ok(/PUBLIC/.test(secret), secret);
  });
  await ok(api + "/devices/remove-key", { id: laptop.device.id,
    key: added.key }, "removed the key");
  edited = await read("/devices?device=" + laptop.device.id);
  check("a key removed by its id", function () {
    assert.strictEqual(edited.device.keys.length, 1);
  });

  log.info("=== 4. the refusals ===");
  const unknown = await refused(api + "/devices/no-such-action", {},
                                "an unknown action");
  const nobody = await refused(api + "/devices/create", {
    owner: "nobody-" + STAMP }, "an owner the directory does not hold");
  await ok(api + "/config/set", { key: "devices.maxPerPerson", value: 1 },
           "set this realm's devices.maxPerPerson to 1");
  const full = await refused(api + "/devices/create", { owner: OWNER,
    label: "one too many" }, "a person at devices.maxPerPerson");
  await ok(api + "/config/reset", { key: "devices.maxPerPerson" },
           "put devices.maxPerPerson back");
  check("an unknown action names the five; an unknown owner; a person at " +
        "the bound — and nothing was evicted", function () {
    assert.strictEqual(unknown, 'Unknown action "no-such-action". The five ' +
                       "are: create, update, remove, add-key and " +
                       "remove-key.");
    assert.ok(/There is no person/.test(nobody), nobody);
    assert.ok(/devices\.maxPerPerson/.test(full), full);
  });
  const still = await read("/devices?owner=" + encodeURIComponent(OWNER));
  check("the person's one device is still there", function () {
    assert.strictEqual(still.matched, 1);
  });

  log.info("=== 5. the other three views ===");
  const monitor = await read("/devices/monitor?days=7");
  check("Monitoring → Devices counts by owner kind, key kind and " +
        "attestation, and today's events", function () {
    const c = monitor.counts;
    assert.strictEqual(c.total, 2, JSON.stringify(c));
    assert.strictEqual(c.byOwnerKind.person, 1);
    assert.strictEqual(c.byOwnerKind.application, 1);
    assert.strictEqual(c.byKeyKind.jwk, 1);
    assert.strictEqual(c.byAttestation["self-asserted"], 2);
    assert.strictEqual(c.byEnrolment.admin, 2);
    assert.strictEqual(c.nativeSso.none, 2);
    assert.strictEqual(monitor.timeline.rows.length, 7);
    assert.strictEqual(monitor.timeline.totals.created, 2);
    assert.strictEqual(monitor.timeline.rows[6].created, 2);
  });
  const registration = await read("/device-registration");
  check("Device registration: the methods, which are built, and the " +
        "settings", function () {
    const methods = registration.enrolment.map(function (m) {
      return m.method + ":" + m.built;
    });
    assert.deepStrictEqual(methods, ["native-sso:true", "admin:true",
                                     "portal:false", "est:false",
                                     "scep:false"]);
    const keys = JSON.stringify(registration.settings);
    assert.ok(keys.indexOf("devices.maxPerPerson") >= 0, keys.slice(0, 300));
    assert.ok(keys.indexOf("oauth2.maxDevicesPerPerson") < 0);
  });
  const entries = await read("/ldap/devices");
  check("the entries as the directory holds them, with the schema",
        function () {
    assert.strictEqual(entries.count, 2);
    assert.ok(entries.schema.attributes.some(function (a) {
      return a.name === "stsDeviceKey";
    }));
    const laptopEntry = entries.entries.filter(function (e) {
      return (e.attributes.cn || [])[0] === laptop.device.id;
    })[0];
    assert.ok(laptopEntry, JSON.stringify(entries.entries).slice(0, 300));
    assert.strictEqual(laptopEntry.attributes.stsDeviceOwnerKind[0],
                       "person");
    assert.strictEqual(laptopEntry.attributes.stsDeviceKey.length, 1);
  });

  log.info("=== 6. removal ===");
  await ok(api + "/devices/remove", { id: host.device.id },
           "removed the application's device");
  const after = await read("/devices");
  const counted = await read("/devices/monitor");
  check("removed, and counted as an event", function () {
    assert.strictEqual(after.total, 1);
    assert.strictEqual(counted.timeline.totals.removed, 1);
    assert.strictEqual(counted.counts.byOwnerKind.application, 0);
  });

  assert.ok(checks >= 12, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The device register (#164, #218) through the management " +
    "API: person- and application-owned devices, keys, the lists, the " +
    "bounds, the monitoring counts and the directory's view.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
