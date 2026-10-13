// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_foreign_receiver.js
//
// ---------------------------------------------------------------------------
// A FEDERATION PARTNER'S SHARED SIGNALS (#153, #373, #374), over HTTP. Two
// throwaway realms: A is the partner identity service — this service's own
// transmitter, in a realm of its own — and B receives from it through
// federation relationships.
//
//   1. B's relationship with A, its signals turned on with client
//      credentials A issued: the configuration discovered from fedPeer
//      (the inserted-path well-known form, A's jwks_uri) and a poll stream
//      created there.
//   2. Verification: B asks, A sends, B's poll records it.
//   3. A disables its person (RISC account-disabled, subject iss_sub): B's
//      poll maps the subject through B's federation link and BLOCKS that
//      partner's sign-ins of B's person — the account stays enabled — and
//      A's account-enabled lifts the block.
//   4. A signals-only (`ssf`) relationship with the same partner (#374): the
//      same event names the person through an administrator's link, and is
//      recorded and does nothing.
//   5. Push: a second relationship pushed by A to /federation/signals/{id}
//      blocks another linked person; a header B did not give is refused.
//
// OWNED HERE (local: true): this repository's transmitter, receiver and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const fs = require("fs");
const path = require("path");
const tls = require("tls");
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
const REL_PUSH = "partner-a-push";
const REL_ONLY = "partner-a-signals";
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

// Polls B's view until `until` holds; `poll` names the relationships B
// polls A through first.
async function waitFor(what, until, poll) {
  log.debug("Entering waitFor(). " + what);
  let last = null;
  for (let i = 0; i < 40; i++) {
    for (const id of [].concat(poll || [])) {
      await hop(null, "POST", apiB + "/federation/signals-poll-now",
                { json: { id: id } });
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

function blocked(report, relationship, username) {
  log.debug("Entering blocked().");
  log.debug("Leaving blocked().");
  return (report.blocks || []).some(function (b) {
    return b.relationship === relationship && b.username === username;
  });
}

function locked(report, username) {
  log.debug("Entering locked().");
  log.debug("Leaving locked().");
  return (report.locks || []).some(function (l) {
    return l.username === username;
  });
}

// A relationship of B's with A, its signals on with A's client credentials.
async function relationship(id, protocol, delivery) {
  log.debug("Entering relationship(). " + id);
  const made = await hop(null, "POST", apiB + "/federation/create", {
    json: { id: id, role: "service-provider", protocol: protocol,
            peer: ISSUER } });
  assert.ok(made.json && made.json.ok, "the relationship " + id + ": " +
            made.text.slice(0, 300));
  const fields = [["fedSignalsTokenUrl", baseA + "/oauth2/token"],
                  ["fedSignalsClientId", CLIENT],
                  ["fedSignalsClientSecret", SECRET],
                  ["fedSignalsDelivery", delivery]];
  if (protocol !== "ssf") {
    fields.push(["fedSignalsEnabled", "TRUE"]);
  }
  for (const [field, value] of fields) {
    await ok(apiB + "/federation/set", { id: id, field: field, value: value },
             "set " + field + " on " + id);
  }
  await ok(apiB + "/federation/enable", { id: id }, "enabled " + id);
  log.debug("Leaving relationship().");
}

let ISSUER = "";

// THIS SERVICE'S ROOT AS EACH REALM'S OUTBOUND CA (2026-09-27). The two
// realms dial each other at this service's own address, whose certificate is
// this run's own. Product mode refuses to skip verifying it (#171), so the
// service's Root is published in the shared test-CA directory and named as
// both realms' federation and push CA — sts_provider_commands.js's
// arrangement. Without that directory (an AWS target, a hand run) only
// development may skip verification.
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
    const name = "ssf-foreign-root-" + TAG + ".crt";
    fs.mkdirSync(where.dir, { recursive: true });
    fs.writeFileSync(path.join(where.dir, name), rootPem, { mode: 0o644 });
    const file = path.join(path.dirname(where.serviceFile), name);
    for (const api of [apiA, apiB]) {
      for (const key of ["federation.outboundCaFile", "ssf.pushCaFile"]) {
        await ok(api + "/config/set", { key: key, value: file },
                 "named this service's Root as " + key);
      }
    }
    log.debug("Leaving trustThisService(). CA file.");
    return;
  }
  assert.ok(!product, testCa.skipReason());
  for (const api of [apiA, apiB]) {
    await ok(api + "/config/set", {
      key: "federation.outboundSkipTlsVerification", value: true },
      "trusted this run's certificate");
  }
  log.debug("Leaving trustThisService(). Verification skipped.");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. realm A (the transmitter) and realm B (the receiver) ===");
  for (const id of [REALM_A, REALM_B]) {
    // In development mode, said rather than inherited (2026-09-27): the two
    // realms dial each other at this service's own name, a private address,
    // which product mode never dials.
    await ok(root + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "SSF foreign " + id,
      overrides: { "global.mode": "development" } },
      "created realm " + id);
  }
  // Each dials the other's own address, whose certificate is this run's.
  await trustThisService(false);
  await ok(apiA + "/config/set", { key: "ssf.pushDelivery", value: true },
           "let A push");
  // trustThisService() named the Root as ssf.pushCaFile where it could;
  // without that directory development skips verification instead (product
  // refuses the skip, #171).
  if (!testCa.caLocation()) {
    await ok(apiA + "/config/set", { key: "ssf.pushSkipTlsVerification",
      value: true }, "let A's push trust this run's certificate");
  }
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
  ISSUER = conf.issuer;
  await relationship(REL, "oidc", "poll");
  await relationship(REL_ONLY, "ssf", "poll");
  await ok(apiB + "/users/federation-link", { user: B1, relationship: REL,
    subject: await subjectOf(apiA, A1) }, "linked " + B1 + " to " + A1);
  // A signals-only partner's people are linked by an administrator, under
  // the iss its iss_sub subjects carry (#374).
  await ok(apiB + "/users/federation-link", { user: B1,
    relationship: REL_ONLY, issuer: ISSUER,
    subject: await subjectOf(apiA, A1) }, "linked " + B1 + " for " +
    REL_ONLY);

  log.info("=== 1. discovery and a poll stream ===");
  const stream = await hop(null, "POST",
                           apiB + "/federation/signals-create-stream",
                           { json: { id: REL } });
  const only = await hop(null, "POST",
                         apiB + "/federation/signals-create-stream",
                         { json: { id: REL_ONLY } });
  check("B discovers A from the relationship's fedPeer and creates a poll " +
        "stream there", function () {
    assert.strictEqual(stream.status, 200, stream.text.slice(0, 400));
    assert.strictEqual(stream.json.signals.config.issuer, ISSUER);
    assert.ok(stream.json.signals.streamId);
    assert.ok(stream.json.signals.pollEndpoint);
    assert.strictEqual(only.status, 200, only.text.slice(0, 400));
    assert.strictEqual(only.json.signals.kind, "signals-only");
  });

  log.info("=== 2. verification ===");
  await ok(apiB + "/federation/signals-verify", { id: REL },
           "asked for verification");
  await waitFor("the verification event", function (r) {
    return r.relationships.some(function (t) {
      return t.relationship === REL && t.verifiedAt;
    });
  }, REL);
  check("the verification A sent is received, verified and matched",
        function () {
    assert.ok(true);
  });

  log.info("=== 3. account-disabled and account-enabled, by poll ===");
  await ok(apiA + "/risc/emit", { type: "account-disabled", account_id: A1,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-disabled");
  const disabled = await waitFor("B1 blocked through " + REL, function (r) {
    return blocked(r, REL, B1);
  }, [REL, REL_ONLY]);
  check("A's account-disabled, mapped through B's link, blocks A's " +
        "sign-ins of B's person and leaves the account enabled",
        function () {
    const row = disabled.received.filter(function (x) {
      return x.relationship === REL && x.person === B1 && x.verified;
    })[0];
    assert.ok(row, JSON.stringify(disabled.received).slice(0, 800));
    assert.ok(!locked(disabled, B1), JSON.stringify(disabled.locks));
  });

  log.info("=== 4. the same event, from a signals-only relationship ===");
  const recorded = await waitFor("the event through " + REL_ONLY,
    function (r) {
      return r.received.some(function (x) {
        return x.relationship === REL_ONLY && x.person === B1 &&
               x.verified && (x.events || []).some(function (e) {
                 return /account-disabled$/.test(e);
               });
      });
    }, REL_ONLY);
  check("a signals-only partner's account-disabled names the person and " +
        "is recorded, and does nothing (#374)", function () {
    const row = recorded.received.filter(function (x) {
      return x.relationship === REL_ONLY && x.person === B1;
    })[0];
    assert.ok(!(row.reactions || []).some(function (x) {
      return x.done;
    }), JSON.stringify(row));
    assert.ok(!blocked(recorded, REL_ONLY, B1));
  });

  await ok(apiA + "/risc/emit", { type: "account-enabled", account_id: A1,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-enabled");
  await waitFor("B1 unblocked", function (r) {
    return !blocked(r, REL, B1);
  }, REL);
  check("A's account-enabled lifts the block", function () {
    assert.ok(true);
  });

  log.info("=== 5. push ===");
  await relationship(REL_PUSH, "oidc", "push");
  await ok(apiB + "/users/federation-link", { user: B2,
    relationship: REL_PUSH, subject: await subjectOf(apiA, A2) },
    "linked " + B2 + " to " + A2);
  const pushStream = await hop(null, "POST",
    apiB + "/federation/signals-create-stream", { json: { id: REL_PUSH } });
  check("a push stream is created with B's endpoint", function () {
    assert.strictEqual(pushStream.status, 200,
                       pushStream.text.slice(0, 300));
    assert.ok(pushStream.json.signals.pushEndpointSet);
  });
  await ok(apiA + "/risc/emit", { type: "account-disabled", account_id: A2,
    reason_admin: "sts_ssf_foreign_receiver" }, "A: account-disabled (A2)");
  const pushed = await waitFor("B2 blocked by a push", function (r) {
    return r.received.some(function (x) {
      return x.relationship === REL_PUSH && x.person === B2 && x.verified;
    });
  });
  check("A pushes to B, and B acts on it", function () {
    assert.ok(blocked(pushed, REL_PUSH, B2), JSON.stringify(pushed.blocks));
  });

  const bad = await hop(null, "POST", baseB + "/federation/signals/" +
    REL_PUSH, { headers: { Authorization: "Bearer not-it",
                           "Content-Type": "application/secevent+jwt" } });
  check("the push endpoint refuses an Authorization header it did not give",
        function () {
    assert.strictEqual(bad.status, 401, bad.text.slice(0, 200));
  });

  assert.ok(checks >= 8, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("SSF: a realm receiving its federation partners' Shared " +
    "Signals (#153, #373, #374), over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
