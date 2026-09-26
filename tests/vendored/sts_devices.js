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
// AND #164 PHASE 2 (2026-09-26): ENROLMENT AND RECOGNITION.
//
//   7. The person's portal JSON doors: a challenge, a device-key-proof+jwt
//      over it registering a device (portal, self-asserted in development),
//      the challenge refused a second time, a body that is not JSON refused,
//      and the page offering both ways.
//   8. EST's device profile: /.well-known/est/device/simpleenroll issues a
//      certificate to a NEW device owned by the person, naming only
//      urn:sts:device:<id>, kept on the device as an x509 key.
//   9. Recognition at the token endpoint: a DPoP proof by a registered jwk
//      key and the EST device certificate over mutual TLS (RFC 8705) are
//      each counted as a recognition by that key on Monitoring → Devices.
//  10. Product mode on this realm refuses an unattested key proof
//      (STS-DEVICE-0024).
//
// AND #164 PHASES 3 AND 4 (2026-09-26): COMPLIANCE, THE MDM FEED, CAEP AND
// RISC.
//
//  11. The MDM feed: device:compliance is issued only to a client that
//      declares it; POST /admin-api/device-compliance applies a batch by key
//      thumbprint and by certificate and refuses an unknown device alone;
//      the job's own admin:write token is refused there; and CAEP
//      device-compliance-change arrives on a POLL stream (every SET drained
//      is pooled, because a poll acknowledges what it reads), its subject
//      the device and its owner.
//  12. The test control: it answers in development and product refuses it.
//  13. A device marked compromised: its EST certificate appears on the
//      realm's EST CRL, RISC credential-compromise and sessions-revoked
//      arrive naming the account and the device, and CAEP risk-level-change
//      to HIGH.
//
// AND #164 PHASES 5 AND 6 (2026-09-26): RISK, POLICY, ACR AND CLAIMS.
//
//  14. A client_credentials token bound by DPoP to the application's own
//      device key carries device_id, and its one cnf.jkt is that key's
//      thumbprint; an unbound one carries none; introspection repeats it;
//      discovery lists device_id and urn:sts:acr:compliant-device.
//  15. devices.requireCompliantDevice on in the realm: the same request
//      from a not-compliant device is refused, from a compliant one issued.
//  16. acr_values=urn:sts:acr:compliant-device on a session with no device:
//      one sign-in again, then unmet_authentication_requirements.
//  17. A device owner signing in with none of their devices is assessed
//      unregistered-device, and Monitoring → Risk lists the five device
//      signals.
//
// OWNED HERE (local: true): this repository's register and management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const path = require("path");
const est = require("./est_client.js");
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
const R = "/realm/" + REALM;
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));

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

// ---------------------------------------------------------------------------
// #164 PHASE 2: A BROWSER FOR THE PORTAL, A KEY PROOF AND A DPoP PROOF.
// ---------------------------------------------------------------------------
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, where, body, type) {
      log.debug("Entering go(). " + method + " " + where);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = type || "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(where) ? where : root + where;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
        .forEach(function (one) {
          const pair = String(one).split(";")[0];
          const at = pair.indexOf("=");
          if (at <= 0) {
            return;
          }
          const value = pair.slice(at + 1);
          if (value === "") {
            delete jar[pair.slice(0, at)];
          } else {
            jar[pair.slice(0, at)] = value;
          }
        });
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in go(): " + ((e && e.message) || e));
        json = null;
      }
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, json: json };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
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

// Signs in to this realm's portal through its code flow, landing on `where`.
async function portalSignIn(who, where) {
  log.debug("Entering portalSignIn(). " + who);
  const b = browser();
  let r = await b.go("GET", where);
  for (let hop = 0; hop < 12 && r.status !== 200; hop++) {
    assert.ok(r.status === 302 || r.status === 303,
      "signing in to " + where + " stopped at " + r.status + " " +
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
  assert.strictEqual(r.status, 200, "the signed-in page: " + r.status + " " +
                     r.text.slice(0, 300));
  log.debug("Leaving portalSignIn().");
  return { browser: b, page: r };
}

// A compact ES256 JWS, built by hand.
function es256(header, payload, privateKey) {
  log.debug("Entering es256().");
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.sign("sha256", Buffer.from(input), {
    key: privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving es256().");
  return input + "." + sig.toString("base64url");
}

function keyProof(pair, challenge, audience) {
  log.debug("Entering keyProof().");
  log.debug("Leaving keyProof().");
  return es256({ alg: "ES256", typ: "device-key-proof+jwt",
                 jwk: pair.publicKey.export({ format: "jwk" }) },
               { nonce: challenge, aud: audience,
                 iat: Math.floor(Date.now() / 1000) }, pair.privateKey);
}

function dpopProof(pair, url) {
  log.debug("Entering dpopProof().");
  log.debug("Leaving dpopProof().");
  return es256({ alg: "ES256", typ: "dpop+jwt",
                 jwk: pair.publicKey.export({ format: "jwk" }) },
               { jti: crypto.randomBytes(12).toString("base64url"),
                 htm: "POST", htu: url,
                 iat: Math.floor(Date.now() / 1000) }, pair.privateKey);
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
  check("an unknown action names the seven; an unknown owner; a person at " +
        "the bound — and nothing was evicted", function () {
    assert.strictEqual(unknown, 'Unknown action "no-such-action". The ' +
                       "seven are: create, update, remove, add-key, " +
                       "remove-key, set-compliance and set-status.");
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
                                     "portal:true", "est:true",
                                     "scep:true"]);
    assert.ok(registration.recognition.every(function (r) {
      return r.built;
    }), JSON.stringify(registration.recognition));
    assert.strictEqual(registration.unattestedKeys.accepted, true);
    assert.ok(registration.trustAnchors.some(function (a) {
      return a.kind === "android-key-attestation" && a.source === "shipped" &&
             a.shipped.length >= 1;
    }), JSON.stringify(registration.trustAnchors).slice(0, 400));
    assert.strictEqual(registration.challenges.store, "devices.challenges");
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


  log.info("=== 7. the portal's JSON doors: a key proof ===");
  const signed = await portalSignIn(OWNER, R + "/portal/devices");
  const b = signed.browser;
  check("the page offers a key proof and a linked security key", function () {
    assert.ok(/Register a device by proving its key/.test(signed.page.text),
              signed.page.text.slice(0, 300));
    assert.ok(/Link a security key built into a device/
      .test(signed.page.text));
  });
  const notJson = await b.go("POST", R + "/portal/devices/challenge",
                             form({ purpose: "key" }));
  const issued = await b.go("POST", R + "/portal/devices/challenge",
                            JSON.stringify({ purpose: "key" }),
                            "application/json");
  check("a challenge, bound to the portal session; a form body refused",
        function () {
    assert.strictEqual(notJson.status, 415, notJson.text.slice(0, 200));
    assert.strictEqual(issued.status, 200, issued.text.slice(0, 300));
    assert.strictEqual(issued.json.typ, "device-key-proof+jwt");
    assert.ok(/\/portal\/devices$/.test(issued.json.audience),
              issued.json.audience);
  });
  const phone = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const proved = await b.go("POST", R + "/portal/devices/proof",
    JSON.stringify({ challenge: issued.json.challenge,
                     proof: keyProof(phone, issued.json.challenge,
                                     issued.json.audience),
                     label: "Owner phone", platform: "android" }),
    "application/json");
  const replayed = await b.go("POST", R + "/portal/devices/proof",
    JSON.stringify({ challenge: issued.json.challenge,
                     proof: keyProof(phone, issued.json.challenge,
                                     issued.json.audience) }),
    "application/json");
  check("the proof registers a device, portal-enrolled and self-asserted; " +
        "the challenge is answered once", function () {
    assert.strictEqual(proved.status, 201, proved.text.slice(0, 400));
    const d = proved.json.device;
    assert.strictEqual(d.enrolment.method, "portal");
    assert.strictEqual(d.label, "Owner phone");
    assert.strictEqual(d.keys[0].kind, "jwk");
    assert.strictEqual(d.keys[0].proof, "jwk-proof");
    assert.strictEqual(d.keys[0].attestation.level, "self-asserted");
    assert.strictEqual(d.keys[0].thumbprint,
                       thumbprint(phone.publicKey.export({ format: "jwk" })));
    assert.strictEqual(replayed.status, 400, replayed.text.slice(0, 200));
  });

  log.info("=== 8. EST: the device profile ===");
  const deviceKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const csr = await x509.certificationRequest({ subject: "CN=a device",
    publicKeyPem: deviceKey.publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: deviceKey.privateKey.export({ type: "pkcs8",
                                                 format: "pem" }),
    subjectAltName: [] });
  const enrolled = await est.send({ method: "POST",
    url: base + "/.well-known/est/device/simpleenroll",
    body: est.requestBody(Buffer.from(csr.der)),
    headers: { "Content-Type": "application/pkcs10" },
    basic: [OWNER, PASSWORD] });
  assert.strictEqual(enrolled.status, 200, "EST device enrolment answered " +
                     enrolled.status + " " + String(enrolled.body)
                       .slice(0, 300));
  const certificate = new crypto.X509Certificate(est.parseCertsOnly(
    est.base64Body(enrolled.body)).certificates[0]);
  const deviceId = String(certificate.subjectAltName)
    .replace(/^URI:urn:sts:device:/, "");
  const estDevice = await read("/devices?device=" + deviceId);
  check("a certificate naming only urn:sts:device:<id>, issued to a NEW " +
        "device the person owns, kept on it as an x509 key", function () {
    assert.ok(/^URI:urn:sts:device:[0-9a-f-]{36}$/
      .test(certificate.subjectAltName), certificate.subjectAltName);
    assert.strictEqual(estDevice.found, true);
    assert.strictEqual(estDevice.device.ownerName, OWNER);
    assert.strictEqual(estDevice.device.enrolment.method, "est");
    assert.strictEqual(estDevice.device.keys[0].kind, "x509");
    assert.strictEqual(estDevice.device.keys[0].proof, "est");
  });

  log.info("=== 9. recognition at the token endpoint ===");
  const token = base + "/oauth2/token";
  const dpopKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const dpopDevice = await ok(api + "/devices/create", { owner: HOST,
    ownerKind: "application", label: "DPoP device", keyKind: "jwk",
    key: dpopKey.publicKey.export({ format: "jwk" }) },
    "registered a device holding the DPoP key");
  const before = (await read("/devices/monitor")).activity.recognitions;
  const bound = await fetch(token, { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: dpopProof(dpopKey, token) },
    body: form({ grant_type: "client_credentials", client_id: HOST }) });
  const boundText = await bound.text();
  const mutual = await est.send({ method: "POST", url: token,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: HOST }),
    key: deviceKey.privateKey.export({ type: "pkcs8", format: "pem" }),
    cert: certificate.toString() });
  const afterCount = (await read("/devices/monitor")).activity.recognitions;
  check("a DPoP proof by a registered key, and the EST device certificate " +
        "over mutual TLS, each recognise their device", function () {
    assert.strictEqual(bound.status, 200, boundText.slice(0, 300));
    assert.strictEqual(mutual.status, 200, String(mutual.body)
      .slice(0, 300));
    assert.ok(afterCount.jwk > before.jwk, JSON.stringify([before,
                                                           afterCount]));
    assert.ok(afterCount.x509 > before.x509, JSON.stringify([before,
                                                             afterCount]));
  });

  log.info("=== 10. product mode refuses an unattested key ===");
  await ok(api + "/config/set", { key: "global.mode", value: "product" },
           "put this realm in product mode");
  let productRefusal = null;
  try {
    const again = await b.go("POST", R + "/portal/devices/challenge",
                             JSON.stringify({}), "application/json");
    productRefusal = again.status === 200
      ? await b.go("POST", R + "/portal/devices/proof",
          JSON.stringify({ challenge: again.json.challenge,
            proof: keyProof(crypto.generateKeyPairSync("ec",
              { namedCurve: "P-256" }), again.json.challenge,
                            again.json.audience) }), "application/json")
      : again;
  } finally {
    await ok(api + "/config/reset", { key: "global.mode" },
             "put this realm back in development mode");
  }
  check("product refuses a key proof with no attestation", function () {
    assert.strictEqual(productRefusal.status, 400,
                       productRefusal.text.slice(0, 300));
    assert.ok(/attestation/.test(productRefusal.json.error_description),
              productRefusal.text.slice(0, 300));
  });

  log.info("=== 11. the MDM feed, under device:compliance ===");
  const SECRET = "dev-feed-" + crypto.randomBytes(9).toString("base64url");
  const RX = "dev-rx-" + STAMP.toLowerCase().replace(/[^a-z0-9-]/g, "");
  const MDM = "dev-mdm-" + STAMP.toLowerCase().replace(/[^a-z0-9-]/g, "");
  const NOT_MDM = "dev-notmdm-" + STAMP.toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
  const client = function (identifier, protocols, scopes) {
    log.debug("Entering client().");
    log.debug("Leaving client().");
    return { identifier: identifier, kind: "oauth2-client", name: identifier,
             protocols: protocols,
             fields: { oauthClientId: [identifier],
                       oauthAllowedScope: scopes,
                       oauthClientSecret: SECRET,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } };
  };
  await ok(api + "/applications/create",
           client(RX, ["oauth2", "ssf"], ["ssf:read", "ssf:write"]),
           "registered a Shared Signals receiver");
  await ok(api + "/applications/create",
           client(MDM, ["oauth2"], ["device:compliance"]),
           "registered an MDM feed that declares device:compliance");
  await ok(api + "/applications/create",
           client(NOT_MDM, ["oauth2"], ["openid"]),
           "registered a client that does not declare it");
  const tokenOf = async function (identifier, scope, resource) {
    log.debug("Entering tokenOf(). " + identifier);
    const r = await fetch(base + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form(Object.assign({ grant_type: "client_credentials",
        client_id: identifier, client_secret: SECRET, scope: scope },
        resource ? { resource: resource } : {})) });
    const json = await r.json();
    log.debug("Leaving tokenOf(). " + r.status);
    return { status: r.status, json: json };
  };
  const rxToken = (await tokenOf(RX, "ssf:read ssf:write")).json.access_token;
  assert.ok(rxToken, "a Shared Signals token for the receiver");
  const ssf = async function (method, where, body) {
    log.debug("Entering ssf(). " + where);
    const r = await fetch(base + where, { method: method,
      headers: { "Content-Type": "application/json",
                 Authorization: "Bearer " + rxToken },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in ssf(): " + ((e && e.message) || e));
      json = null;
    }
    log.debug("Leaving ssf(). " + r.status);
    return { status: r.status, json: json, text: text };
  };
  const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
  const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
  const made = await ssf("POST", "/ssf/stream", {
    delivery: { method: "urn:ietf:rfc:8936" },
    events_requested: [CAEP + "device-compliance-change",
                       CAEP + "risk-level-change", CAEP + "credential-change",
                       RISC + "credential-compromise",
                       RISC + "sessions-revoked"] });
  assert.ok(made.status === 200 || made.status === 201,
            "a poll stream: " + made.status + " " + made.text.slice(0, 300));
  const streamId = made.json.stream_id;
  // A poll ACKs what it reads, so every SET drained is POOLED here and each
  // check reads the pool rather than one poll's answer.
  const pool = [];
  const drain = async function () {
    log.debug("Entering drain().");
    await new Promise(function (resolve) {
      setTimeout(resolve, 400);
    });
    for (let round = 0; round < 10; round += 1) {
      const r = await ssf("POST", "/ssf/poll", { stream_id: streamId,
        returnImmediately: true, maxEvents: 100 });
      assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
      const sets = r.json.sets || {};
      const jtis = Object.keys(sets);
      jtis.forEach(function (jti) {
        pool.push(JSON.parse(Buffer.from(sets[jti].split(".")[1],
                                         "base64url").toString("utf8")));
      });
      if (jtis.length) {
        await ssf("POST", "/ssf/poll", { stream_id: streamId, ack: jtis,
                                         returnImmediately: true,
                                         maxEvents: 0 });
      }
      if (!r.json.moreAvailable) {
        break;
      }
    }
    log.debug("Leaving drain(). " + pool.length);
    return pool;
  };
  const about = function (uri, deviceId) {
    log.debug("Entering about().");
    log.debug("Leaving about().");
    return pool.filter(function (set) {
      return set.events && set.events[uri] && set.sub_id &&
             set.sub_id.device && set.sub_id.device.sub === deviceId;
    });
  };
  const notDeclared = await tokenOf(NOT_MDM, "device:compliance", api);
  const feedGrant = await tokenOf(MDM, "device:compliance", api);
  check("device:compliance is issued only to a client that declares it",
        function () {
    assert.strictEqual(notDeclared.status, 400,
                       JSON.stringify(notDeclared.json));
    assert.strictEqual(notDeclared.json.error, "invalid_scope");
    assert.strictEqual(feedGrant.status, 200, JSON.stringify(feedGrant.json));
    assert.strictEqual(feedGrant.json.scope, "device:compliance");
  });
  const feed = async function (token, payload) {
    log.debug("Entering feed().");
    const headers = { "Content-Type": "application/json" };
    if (token) {
      headers.Authorization = "Bearer " + token;
    }
    const r = await fetch(api + "/device-compliance", { method: "POST",
      headers: headers, body: JSON.stringify(payload) });
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in feed(): " + ((e && e.message) || e));
      json = null;
    }
    log.debug("Leaving feed(). " + r.status);
    return { status: r.status, json: json, text: text };
  };
  // The job's own admin token (attached by the launcher's preload) carries
  // admin:write and NOT device:compliance.
  const asAdmin = await hop("POST", api + "/device-compliance", {
    id: laptop.device.id, status: "compliant" });
  await drain();
  const reported = await feed(feedGrant.json.access_token, { reports: [
    { thumbprint: thumbprint(key.pub), keyKind: "jwk", status: "compliant",
      reason: "sts_devices MDM feed" },
    { certificate: certificate.toString(), status: "not-compliant" },
    { id: "no-such-device", status: "compliant" }] });
  await drain();
  const feedSets = about(CAEP + "device-compliance-change", laptop.device.id);
  check("the feed applies a batch by key thumbprint and by certificate, " +
        "refuses an unknown device alone, and an admin:write token is " +
        "refused there", function () {
    assert.strictEqual(asAdmin.status, 403, asAdmin.text.slice(0, 300));
    assert.strictEqual(reported.status, 200, reported.text.slice(0, 400));
    assert.strictEqual(reported.json.applied, 2);
    assert.strictEqual(reported.json.refused, 1);
    assert.strictEqual(reported.json.results[0].id, laptop.device.id);
    assert.strictEqual(reported.json.results[1].id, deviceId);
  });
  check("device-compliance-change arrives on the poll stream: the device " +
        "and its owner as a complex subject, initiated by a system",
        function () {
    assert.strictEqual(feedSets.length, 1, JSON.stringify(pool)
      .slice(0, 600));
    const e = feedSets[0].events[CAEP + "device-compliance-change"];
    assert.strictEqual(e.previous_status, "not-compliant");
    assert.strictEqual(e.current_status, "compliant");
    assert.strictEqual(e.initiating_entity, "system");
    assert.strictEqual(e.reason_admin.en, "sts_devices MDM feed");
    assert.strictEqual(feedSets[0].sub_id.format, "complex");
    assert.strictEqual(feedSets[0].sub_id.device.format, "iss_sub");
    assert.ok(feedSets[0].sub_id.user, JSON.stringify(feedSets[0].sub_id));
  });
  const shown = await read("/devices?device=" + laptop.device.id);
  check("recorded with source mdm and the feed's client as the actor",
        function () {
    assert.strictEqual(shown.device.compliance, "compliant");
    assert.strictEqual(shown.device.complianceChange.source, "mdm");
    assert.strictEqual(shown.device.complianceChange.actor, MDM);
  });

  log.info("=== 12. the test control ===");
  const control = await hop("POST", base + "/devices/test/compliance", {
    id: laptop.device.id, status: "not-compliant" });
  check("development's test control sets compliance with no credential",
        function () {
    assert.strictEqual(control.status, 200, control.text.slice(0, 300));
    assert.strictEqual(control.json.applied, 1);
  });
  await ok(api + "/config/set", { key: "global.mode", value: "product" },
           "put this realm in product mode");
  let productControl = null;
  try {
    productControl = await hop("POST", base + "/devices/test/compliance", {
      id: laptop.device.id, status: "compliant" });
  } finally {
    await ok(api + "/config/reset", { key: "global.mode" },
             "put this realm back in development mode");
  }
  check("product refuses the test control", function () {
    assert.strictEqual(productControl.status, 403,
                       productControl.text.slice(0, 300));
  });

  log.info("=== 13. a compromised device ===");
  const serial = estDevice.device.keys[0].material.serial;
  const crlOf = async function () {
    log.debug("Entering crlOf().");
    const r = await est.send({ method: "GET",
                               url: base + "/pki/crl/" + REALM + "/est" });
    assert.strictEqual(r.status, 200, "the EST CRL: " + r.status);
    log.debug("Leaving crlOf().");
    return est.crlSerials(r.body).map(function (s) {
      return String(s).toLowerCase().replace(/^0+/, "");
    });
  };
  const crlBefore = await crlOf();
  const compromised = await ok(api + "/devices/set-status", {
    id: deviceId, status: "compromised", reason: "reported stolen" },
    "marked the EST device compromised");
  await drain();
  const crlAfter = await crlOf();
  const bare = String(serial).toLowerCase().replace(/^0+/, "");
  check("its EST certificate is on the CRL now, and was not before",
        function () {
    assert.strictEqual(compromised.certificatesRevoked, 1,
                       JSON.stringify(compromised));
    assert.ok(crlBefore.indexOf(bare) < 0, crlBefore.join(","));
    assert.ok(crlAfter.indexOf(bare) >= 0, crlAfter.join(","));
  });
  const compromise = about(RISC + "credential-compromise", deviceId);
  const plural = about(RISC + "sessions-revoked", deviceId);
  const risky = about(CAEP + "risk-level-change", deviceId);
  check("RISC credential-compromise (x509) and sessions-revoked, naming the " +
        "account and the device, and CAEP risk-level-change to HIGH",
        function () {
    assert.strictEqual(compromise.length, 1, JSON.stringify(pool)
      .slice(0, 600));
    assert.strictEqual(compromise[0].events[RISC + "credential-compromise"]
      .credential_type, "x509");
    assert.ok(compromise[0].sub_id.user, JSON.stringify(compromise[0]));
    assert.strictEqual(plural.length, 1);
    assert.strictEqual(risky.length, 1);
    const r = risky[0].events[CAEP + "risk-level-change"];
    assert.strictEqual(r.principal, "DEVICE");
    assert.strictEqual(r.current_level, "HIGH");
  });
  const afterCompromise = await read("/devices?device=" + deviceId);
  check("it stays in the register, marked compromised, risk HIGH",
        function () {
    assert.strictEqual(afterCompromise.device.status, "compromised");
    assert.strictEqual(afterCompromise.device.riskLevel, "HIGH");
  });

  log.info("=== 14. device_id and cnf in the tokens (phase 6) ===");
  const dpopJkt = thumbprint(dpopKey.publicKey.export({ format: "jwk" }));
  const boundAgain = await fetch(token, { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: dpopProof(dpopKey, token) },
    body: form({ grant_type: "client_credentials", client_id: HOST }) });
  const boundJson = await boundAgain.json();
  const boundClaims = boundJson.access_token
    ? JSON.parse(Buffer.from(String(boundJson.access_token).split(".")[1],
                             "base64url").toString("utf8")) : {};
  check("a token bound by DPoP to the application's own device key names " +
        "the device (device_id), and its one cnf names the same key by its " +
        "thumbprint", function () {
    assert.strictEqual(boundAgain.status, 200, JSON.stringify(boundJson));
    assert.strictEqual(boundClaims.device_id, dpopDevice.device.id,
                       JSON.stringify(boundClaims));
    assert.deepStrictEqual(boundClaims.cnf, { jkt: dpopJkt });
    assert.strictEqual(boundJson.token_type, "DPoP");
  });
  const unbound = await fetch(token, { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: HOST }) });
  const unboundJson = await unbound.json();
  const unboundClaims = unboundJson.access_token
    ? JSON.parse(Buffer.from(String(unboundJson.access_token).split(".")[1],
                             "base64url").toString("utf8")) : {};
  const introspected = await fetch(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ token: boundJson.access_token, client_id: MDM,
                 client_secret: SECRET }) });
  const introspection = await introspected.json();
  const discovery = await hop("GET", base +
                              "/.well-known/openid-configuration");
  check("no device, no device_id; introspection repeats it; discovery " +
        "lists device_id and the compliant-device acr", function () {
    assert.strictEqual(unbound.status, 200, JSON.stringify(unboundJson));
    assert.strictEqual(unboundClaims.device_id, undefined);
    assert.strictEqual(introspected.status, 200,
                       JSON.stringify(introspection));
    assert.strictEqual(introspection.active, true);
    assert.strictEqual(introspection.device_id, dpopDevice.device.id);
    assert.ok(discovery.json.claims_supported.indexOf("device_id") >= 0);
    assert.ok(discovery.json.acr_values_supported
      .indexOf("urn:sts:acr:compliant-device") >= 0,
              JSON.stringify(discovery.json.acr_values_supported));
  });

  log.info("=== 15. the compliant-device rule, on in this realm ===");
  await ok(api + "/config/set", { key: "devices.requireCompliantDevice",
                                  value: true },
           "required a compliant registered device in this realm");
  let refusedBound = null;
  let issuedBound = null;
  let issuedJson = null;
  try {
    await ok(api + "/devices/set-compliance", { id: dpopDevice.device.id,
      status: "not-compliant", reason: "sts_devices rule check" },
      "reported the DPoP device not compliant");
    refusedBound = await fetch(token, { method: "POST", headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: dpopProof(dpopKey, token) },
      body: form({ grant_type: "client_credentials", client_id: HOST }) });
    await refusedBound.text();
    await ok(api + "/devices/set-compliance", { id: dpopDevice.device.id,
      status: "compliant", reason: "sts_devices rule check" },
      "reported the DPoP device compliant");
    issuedBound = await fetch(token, { method: "POST", headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: dpopProof(dpopKey, token) },
      body: form({ grant_type: "client_credentials", client_id: HOST }) });
    issuedJson = await issuedBound.json();
  } finally {
    await ok(api + "/config/reset", { key: "devices.requireCompliantDevice" },
             "put devices.requireCompliantDevice back");
  }
  check("with devices.requireCompliantDevice on, a token from a " +
        "not-compliant device is refused and one from a compliant device " +
        "issued", function () {
    assert.ok(refusedBound.status >= 400, "refused: " + refusedBound.status);
    assert.strictEqual(issuedBound.status, 200, JSON.stringify(issuedJson));
  });

  log.info("=== 16. acr_values=urn:sts:acr:compliant-device ===");
  const ACR = "dev-acr-" + STAMP.toLowerCase().replace(/[^a-z0-9-]/g, "");
  const REDIRECT = "https://" + ACR + ".example/cb";
  await ok(api + "/applications/create", {
    identifier: ACR, kind: "oauth2-client", name: ACR,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [ACR], oauthClientSecret: SECRET,
              oauthRedirectUri: [REDIRECT],
              oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "registered a relying party for the acr check");
  const authorizePath = function (extra) {
    log.debug("Entering authorizePath().");
    const verifier = crypto.randomBytes(32).toString("base64url");
    log.debug("Leaving authorizePath().");
    return R + "/oauth2/authorize?" + form(Object.assign({
      response_type: "code", client_id: ACR, redirect_uri: REDIRECT,
      scope: "openid", state: "st-" + STAMP,
      nonce: "n-" + crypto.randomBytes(4).toString("hex"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }, extra || {}));
  };
  const signInAt = async function (rb, location) {
    log.debug("Entering signInAt().");
    const page = await rb.go("GET", location);
    assert.strictEqual(page.status, 200, "the sign-in screen: " +
                       page.status + " " + page.text.slice(0, 300));
    const fields = hiddenFields(page.text);
    fields.username = OWNER;
    fields.password = PASSWORD;
    fields.action = "login";
    const posted = await rb.go("POST", R + "/authn/login", form(fields));
    log.debug("Leaving signInAt(). " + posted.status);
    return posted.location;
  };
  // A first sign-in makes a session (what the browser lands on next — a
  // consent screen or a code — is not this section's business); the second
  // request is answered from that session.
  const rp = browser();
  let hopped = await rp.go("GET", authorizePath());
  const firstBack = await signInAt(rp, hopped.location);
  hopped = await rp.go("GET", authorizePath({
    acr_values: "urn:sts:acr:compliant-device" }));
  const sentBack = /\/authn\/login\?authn=/.test(hopped.location);
  const back = sentBack ? await signInAt(rp, hopped.location) : "";
  hopped = back ? await rp.go("GET", back) : hopped;
  const answered = hopped.location.indexOf(REDIRECT) === 0
    ? new URL(hopped.location).searchParams : null;
  check("a session with no compliant device is sent to sign in again, and " +
        "then refused unmet_authentication_requirements", function () {
    assert.ok(firstBack, "the first sign-in returned to the request");
    assert.ok(sentBack, "sent to sign in again: " + hopped.location);
    assert.ok(/[?&]step_up_honoured=1(&|$)/.test(back), back);
    assert.ok(answered, hopped.status + " " + hopped.location);
    assert.strictEqual(answered.get("error"),
                       "unmet_authentication_requirements", hopped.location);
    assert.strictEqual(answered.get("code"), null);
  });

  log.info("=== 17. a risk assessment shows the device signal ===");
  await ok(api + "/config/set", { key: "risk.minimumHistory", value: 1 },
           "scored this realm's people from their second sign-in");
  await ok(api + "/config/set", { key: "risk.signalFactors",
                                  value: "unregistered-device=1" },
           "kept unregistered-device from moving a score here");
  let riskView = null;
  try {
    await portalSignIn(OWNER, R + "/portal/devices");
    await portalSignIn(OWNER, R + "/portal/devices");
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
    riskView = await read("/risk");
  } finally {
    await ok(api + "/config/reset", { key: "risk.minimumHistory" },
             "put risk.minimumHistory back");
    await ok(api + "/config/reset", { key: "risk.signalFactors" },
             "put risk.signalFactors back");
  }
  check("an owner of registered devices signing in with none of them is " +
        "assessed unregistered-device, and the page lists the five device " +
        "signals", function () {
    const rows = (riskView.assessments && riskView.assessments.rows) || [];
    assert.ok(rows.some(function (a) {
      return (a.signals || []).some(function (x) {
        return x.signal === "unregistered-device";
      });
    }), JSON.stringify(rows.map(function (a) {
      return (a.signals || []).map(function (x) {
        return x.signal;
      });
    })));
    const listed = (riskView.signals || []).map(function (x) {
      return x.signal;
    });
    ["compromised-device", "non-compliant-device", "unregistered-device",
     "compliant-attested-device", "compliant-device"]
      .forEach(function (one) {
        assert.ok(listed.indexOf(one) >= 0, one + ": " + listed.join(","));
      });
  });

  assert.ok(checks >= 32, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The device register (#164, #218) through the management " +
    "API: person- and application-owned devices, keys, the lists, the " +
    "bounds, the monitoring counts and the directory's view; and #164 " +
    "phase 2's enrolment (the portal's key proof, EST's device profile) " +
    "and recognition at the token endpoint (DPoP, mutual TLS); and phases " +
    "3 and 4: the MDM feed under device:compliance, the test control, and " +
    "the CAEP and RISC events a compliance change and a compromise send; " +
    "and phases 5 and 6: device_id and cnf, the compliant-device rule, " +
    "the compliant-device acr and the device risk signals.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
