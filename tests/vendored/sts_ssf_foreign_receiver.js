"use strict";
//
// File: sts_ssf_foreign_receiver.js
//
// ---------------------------------------------------------------------------
// THIS REALM AS THE RECEIVER OF A FOREIGN SSF TRANSMITTER (#153,
// 2026-09-26), over HTTP. Two throwaway realms: A is the "foreign" identity
// service — this service's own transmitter, in a realm of its own — and B
// receives from it.
//
//   1. B registers A by its issuer (discovery through the inserted-path
//      well-known form, A's jwks_uri) and creates a poll stream there with
//      client credentials A issued.
//   2. Verification: B asks, A sends, B's poll records it.
//   3. A disables its person (RISC account-disabled, subject iss_sub); B's
//      poll maps the subject through B's federation link and disables B's
//      person — and A's account-enabled enables them again.
//   4. Push: a second stream, pushed by A to /ssf/transmitters/{id}/push,
//      disables another linked person.
//
// OWNED HERE (local: true): this repository's transmitter, receiver and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const tls = require("tls");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const facts = require("./service_facts.js");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_foreign_receiver",
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
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 10);
const REALM_A = "sfa-" + TAG;
const REALM_B = "sfb-" + TAG;
const baseA = root + "/realm/" + REALM_A;
const baseB = root + "/realm/" + REALM_B;
const apiA = baseA + "/admin-api";
const apiB = baseB + "/admin-api";
const SECRET = "sfr-" + crypto.randomBytes(9).toString("base64url");
const CLIENT = "realm-b-receiver";
const REL = "partner-a";
const PASSWORD = "Sf-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const A1 = names.usernameFor("sf-a1");
const B1 = names.usernameFor("sf-b1");
const A2 = names.usernameFor("sf-a2");
const B2 = names.usernameFor("sf-b2");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
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

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// Follows redirects inside this service, signing the person in on the
// realm's screen and allowing a consent screen, until the answer leaves the
// service or is a page.
function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function subjectOf(api, username) {
  log.debug("Entering subjectOf().");
  const r = await hop(null, "GET", api + "/users?user=" +
                      encodeURIComponent(username));
  assert.ok(r.json && r.json.subject, "the subject of " + username + ": " +
            r.text.slice(0, 300));
  log.debug("Leaving subjectOf().");
  return r.json.subject;
}

async function reportB() {
  log.debug("Entering reportB().");
  const r = await hop(null, "GET", apiB + "/ssf/transmitters");
  log.debug("Leaving reportB().");
  return r.json;
}

// Polls B's view until `until` holds; `poll` asks B to poll A first.
async function waitFor(what, until, poll) {
  log.debug("Entering waitFor(). " + what);
  let last = null;
  for (let i = 0; i < 40; i++) {
    if (poll) {
      await hop(null, "POST", apiB + "/ssf/transmitters/poll-now",
                { json: { id: poll } });
    }
    last = await reportB();
    if (last && until(last)) {
      log.debug("Leaving waitFor().");
      return last;
    }
    await sleep(500);
  }
  log.debug("Leaving waitFor(). Gave up.");
  throw new Error("waited for " + what + ": " +
                  JSON.stringify(last).slice(0, 2000));
}

function locked(report, username) {
  log.debug("Entering locked().");
  log.debug("Leaving locked().");
  return (report.locks || []).some(function (l) {
    return l.username === username;
  });
}

// BOTH REALMS MUST TRUST THIS SERVICE, because each dials the other's own
// address, whose certificate is issued under a Root made at start that the
// service's outbound client does not know. As sts_claims_aggregation.js does:
// the Root is read off the handshake, published in the directory shared with
// the service (a file of this job's own), and named as each realm's
// federation.outboundCaFile and A's ssf.pushCaFile, which product honours
// (#171). With no shared directory a development service is told to skip
// verification in the two realms alone; product refuses that (#104), and the
// job says why.
async function trustThisService(product) {
  log.debug("Entering trustThisService().");
  const where = testCa.caLocation();
  if (where) {
    const target = new URL(root);
    const rootPem = await new Promise(function (resolve, reject) {
      const socket = tls.connect({ host: target.hostname,
        port: Number(target.port || 443), servername: target.hostname,
        rejectUnauthorized: false }, function () {
          let cert = socket.getPeerCertificate(true);
          while (cert && cert.issuerCertificate &&
                 cert.issuerCertificate !== cert &&
                 cert.issuerCertificate.fingerprint256 !==
                   cert.fingerprint256) {
            cert = cert.issuerCertificate;
          }
          socket.end();
          resolve("-----BEGIN CERTIFICATE-----\n" +
            cert.raw.toString("base64").match(/.{1,64}/g).join("\n") +
            "\n-----END CERTIFICATE-----\n");
        });
      socket.on("error", reject);
    });
    const name = "ssf-foreign-receiver-root-" + TAG + ".crt";
    const served = path.join(path.dirname(where.serviceFile), name);
    fs.mkdirSync(where.dir, { recursive: true });
    fs.writeFileSync(path.join(where.dir, name), rootPem, { mode: 0o644 });
    for (const api of [apiA, apiB]) {
      await ok(api + "/config/set", { key: "federation.outboundCaFile",
        value: served }, "named this service's Root as the outbound CA");
    }
    await ok(apiA + "/config/set", { key: "ssf.pushCaFile", value: served },
             "named this service's Root as A's push CA");
    log.debug("Leaving trustThisService(). CA file.");
    return;
  }
  assert.ok(!product, testCa.skipReason());
  for (const api of [apiA, apiB]) {
    await ok(api + "/config/set", {
      key: "federation.outboundSkipTlsVerification", value: true },
      "trusted this run's certificate");
  }
  await ok(apiA + "/config/set", { key: "ssf.pushSkipTlsVerification",
    value: true }, "let A's push trust this run's certificate");
  log.debug("Leaving trustThisService(). Verification skipped.");
}

async function test() {
  log.debug("Entering test().");
  // PRODUCT NEVER DIALS AN ADDRESS INSIDE ITS OWN NETWORK
  // (`mode.dialsInternalAddresses()`, federation_http.ts), and every part of
  // this job is realm B reading realm A's configuration and A pushing to B on
  // this one service's own address. So the job runs in development and says
  // why it does not in product, as sts_ciba.js's section 6 does.
  const product = await facts.isProduct(root + "/admin-api");
  if (product) {
    log.info("[skip] product mode will not dial this service's own " +
             "address, which is internal; the foreign receiver runs in " +
             "development.");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Product.");
    return;
  }
  log.info("=== 0. realm A (the transmitter) and realm B (the receiver) ===");
  for (const id of [REALM_A, REALM_B]) {
    await ok(root + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "SSF foreign " + id },
      "created realm " + id);
  }
  // Each dials the other's own address, whose certificate is this run's.
  await trustThisService(product);
  await ok(apiA + "/config/set", { key: "ssf.pushDelivery", value: true },
           "let A push");
  // A's address, pinned, as a deployed transmitter's is: a SET it builds
  // with no request in hand (an emitted event) otherwise names its subject
  // under the listener's address and its token under the request's, and
  // B rightly maps a subject only under the issuer it federates with.
  await ok(apiA + "/config/set", { key: "global.publicBaseUrl",
    value: root }, "pinned A's address");
  await ok(apiB + "/config/set", { key: "ssf.actOnSignalsInDevelopment",
    value: true }, "let B act in development");
  await ok(apiA + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [CLIENT],
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "registered B's client at A");
  for (const [realm, who] of [[baseA, A1], [baseB, B1], [baseA, A2],
                              [baseB, B2]]) {
    await registry.ensurePerson(realm, who, PASSWORD);
  }
  const conf = (await hop(null, "GET", root +
    "/.well-known/ssf-configuration/realm/" + REALM_A)).json;
  const ISS = conf.issuer;
  const made = await hop(null, "POST", apiB + "/federation/create", {
    json: { id: REL, role: "service-provider", protocol: "oidc",
            peer: ISS } });
  assert.ok(made.json && made.json.ok, "the relationship: " +
            made.text.slice(0, 300));
  for (const [a, b] of [[A1, B1], [A2, B2]]) {
    await ok(apiB + "/users/federation-link", { user: b, relationship: REL,
      subject: await subjectOf(apiA, a) }, "linked " + b + " to " + a);
  }

  log.info("=== 1. registration and a poll stream ===");
  const tokenEndpoint = baseA + "/oauth2/token";
  const added = await hop(null, "POST", apiB + "/ssf/transmitters/add", {
    json: { id: "a-poll", issuer: ISS, federationId: REL, delivery: "poll",
            tokenEndpoint: tokenEndpoint, clientId: CLIENT,
            clientSecret: SECRET } });
  const stream = await hop(null, "POST",
                           apiB + "/ssf/transmitters/create-stream",
                           { json: { id: "a-poll" } });
  check("B registers A by its issuer and creates a poll stream there",
        function () {
    assert.strictEqual(added.status, 200, added.text.slice(0, 400));
    assert.strictEqual(added.json.transmitter.config.issuer, ISS);
    assert.strictEqual(stream.status, 200, stream.text.slice(0, 400));
    assert.ok(stream.json.transmitter.streamId);
    assert.ok(stream.json.transmitter.pollEndpoint);
  });

  log.info("=== 2. verification ===");
  await ok(apiB + "/ssf/transmitters/verify", { id: "a-poll" },
           "asked for verification");
  await waitFor("the verification event", function (r) {
    return r.transmitters.some(function (t) {
      return t.id === "a-poll" && t.verifiedAt;
    });
  }, "a-poll");
  check("the verification A sent is received, verified and matched",
        function () {
    assert.ok(true);
  });

  log.info("=== 3. account-disabled and account-enabled, by poll ===");
  await ok(apiA + "/risc/emit", { type: "account-disabled", account_id: A1,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-disabled");
  const disabled = await waitFor("B1 disabled", function (r) {
    return locked(r, B1);
  }, "a-poll");
  check("A's account-disabled, mapped through B's link, disables B's person",
        function () {
    const row = disabled.received.filter(function (x) {
      return x.person === B1 && x.verified;
    })[0];
    assert.ok(row, JSON.stringify(disabled.received).slice(0, 800));
  });
  await ok(apiA + "/risc/emit", { type: "account-enabled", account_id: A1,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-enabled");
  await waitFor("B1 enabled", function (r) {
    return !locked(r, B1);
  }, "a-poll");
  check("A's account-enabled enables them again", function () {
    assert.ok(true);
  });

  log.info("=== 4. push ===");
  const pushAdded = await hop(null, "POST", apiB + "/ssf/transmitters/add", {
    json: { id: "a-push", issuer: ISS, federationId: REL, delivery: "push",
            tokenEndpoint: tokenEndpoint, clientId: CLIENT,
            clientSecret: SECRET } });
  const pushStream = await hop(null, "POST",
    apiB + "/ssf/transmitters/create-stream", { json: { id: "a-push" } });
  check("a push stream is created with B's endpoint", function () {
    assert.strictEqual(pushAdded.status, 200, pushAdded.text.slice(0, 300));
    assert.strictEqual(pushStream.status, 200,
                       pushStream.text.slice(0, 300));
    assert.ok(pushStream.json.transmitter.pushEndpointSet);
  });
  await ok(apiA + "/risc/emit", { type: "account-disabled", account_id: A2,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-disabled (A2)");
  const pushed = await waitFor("B2 disabled by a push", function (r) {
    return r.received.some(function (x) {
      return x.transmitter === "a-push" && x.person === B2 && x.verified;
    });
  });
  check("A pushes to B, and B acts on it", function () {
    assert.ok(locked(pushed, B2), JSON.stringify(pushed.locks));
  });

  const bad = await hop(null, "POST", baseB + "/ssf/transmitters/a-push/push",
    { headers: { Authorization: "Bearer not-it",
                 "Content-Type": "application/secevent+jwt" } });
  check("the push endpoint refuses an Authorization header it did not give",
        function () {
    assert.strictEqual(bad.status, 401, bad.text.slice(0, 200));
  });

  assert.ok(checks >= 7, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("SSF: a realm receiving from a foreign transmitter (#153), " +
    "over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
