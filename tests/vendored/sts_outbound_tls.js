"use strict";
//
// File: sts_outbound_tls.js
//
// ---------------------------------------------------------------------------
// PRODUCT MODE SENDS NOTHING OVER TLS IT DID NOT VERIFY (#171, 2026-09-23),
// DRIVEN OVER HTTP.
//
// GNAP's push finish, SSF push delivery, federation's back channels and the
// XACML PEP nudge each had one `…AllowInsecure` switch that allowed plain http
// AND turned certificate verification off, and product mode honoured it. Each
// is three settings now — `…AllowHttp`, `…SkipTlsVerification` (development
// only) and `…CaFile` — and this job asserts over HTTP what a running service
// does with them, in two throwaway trust realms it leaves behind, one
// development and one product, so it asserts both halves whatever mode the
// service itself was started in:
//
//   0. A realm create that names product mode and a skip in ONE body is
//      refused (STS-CORE-0103), and nothing is created.
//   1. THE WRITE DOORS. In the product realm a write of any of the five
//      development-only settings (the four skips and SPIRE's kubelet skip) to
//      true is refused — through `config/set`, through `config/set-many`
//      (nothing written), and through `realms/set` from the default realm —
//      and false is accepted. The development realm accepts true. A removed
//      key is refused naming what replaced it.
//   2. SSF PUSH, END TO END, to listeners this job runs. In the development
//      realm a stream to a SELF-SIGNED listener delivers with
//      `ssf.pushSkipTlsVerification` on. The realm is then switched to product
//      with the skip still stored: the view reports it not in force, and the
//      next push is NOT delivered and is dead-lettered. A listener certified
//      by a CA this job makes at run time, named in `ssf.pushCaFile`, IS
//      delivered to in product — or, with no directory shared with the
//      service to put that CA's certificate in, is SKIPPED and says so. Plain http: a stream to an http endpoint is refused at
//      creation in product whatever `ssf.pushAllowHttp` says.
//   3. FEDERATION'S POLICY, through the RFC 9728 import, which borrows it: a
//      self-signed https document loads in development with
//      `federation.outboundSkipTlsVerification` on and is refused without
//      it; a plain-http URL is refused in product whatever
//      `federation.outboundAllowHttp` says.
//   4. XACML: `GET /admin-api/xacml/peps` reports the nudge's transport as it
//      is IN FORCE — a skip stored in a product realm reads false.
//
// GNAP's push over a CA file is `sts_gnap_core.js` section 6. What cannot be
// reached over HTTP — a federation partner's TLS in product (the internal
// address rule refuses this job's listener first), the loopback rules, the
// removed key in the environment — is `tests/outbound_tls.js`.
//
// THE LISTENERS run in this job, on OUTBOUND_TEST_HOST (or GNAP_PUSH_HOST, the
// name the service reaches this runner by), and the shared directory the CA
// certificate is written to is `outbound_test_ca.js`'s.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const http = require("http");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
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
var log = bunyan.createLogger({ name: "sts_outbound_tls",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const DEV = usernameFor("otlsdev").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const PROD = usernameFor("otlsprod").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const PUSH = "urn:ietf:rfc:8935";
const VERIFICATION =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
const SECRET = "otls-" + String(Date.now()).slice(-8);
const SKIPS = ["gnap.pushSkipTlsVerification", "ssf.pushSkipTlsVerification",
               "federation.outboundSkipTlsVerification",
               "xacml.pepNotifySkipTlsVerification",
               "spiffe.k8sSkipKubeletVerification"];

let checks = 0;
// Checks a section skipped for want of a directory shared with the service.
let skipped = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method,
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call().");
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

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase(realm) + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + realm);
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// A listener on every interface, recording each request it answers.
async function listener(credential, answer) {
  log.debug("Entering listener().");
  const seen = [];
  const handler = function (req, res) {
    let text = "";
    req.on("data", function (c) { text += c; });
    req.on("end", function () {
      seen.push({ method: req.method, url: req.url, body: text });
      const body = typeof answer === "function" ? answer(req) : "";
      res.writeHead(body ? 200 : 202,
                    body ? { "Content-Type": "application/json" } : {});
      res.end(body);
    });
  };
  const server = credential
    ? https.createServer({ key: credential.key, cert: credential.cert },
                         handler)
    : http.createServer(handler);
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  const url = (credential ? "https" : "http") + "://" +
              (HOST.indexOf(":") >= 0 ? "[" + HOST + "]" : HOST) + ":" +
              server.address().port;
  log.debug("Leaving listener(). " + url);
  return { server: server, seen: seen, url: url };
}

async function until(what, fn, ms) {
  log.debug("Entering until().");
  const deadline = Date.now() + (ms || 15000);
  while (Date.now() < deadline) {
    if (await fn()) {
      log.debug("Leaving until(). Yes.");
      return true;
    }
    await sleep(250);
  }
  log.debug("Leaving until(). Timed out waiting for " + what + ".");
  return false;
}

async function tokenFor(realm, identifier) {
  log.debug("Entering tokenFor().");
  const r = await fetch(realmBase(realm) + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" +
          encodeURIComponent(identifier) + "&client_secret=" +
          encodeURIComponent(SECRET) + "&scope=" +
          encodeURIComponent("ssf:read ssf:write") });
  const json = await r.json();
  assert.ok(json.access_token,
            "a token for " + identifier + ": " + JSON.stringify(json));
  log.debug("Leaving tokenFor().");
  return json.access_token;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the outbound transport policy at " + base + "; this " +
           "job's listeners are on " + HOST);

  // =========================================================================
  // 0. THE REALMS.
  // =========================================================================
  log.info("=== 0. two realms, one each way ===");
  let r = await call("POST", base + "/admin-api/realms/create",
                     { id: PROD, domain: PROD + ".example.net",
                       name: "outbound TLS (refused)",
                       overrides: { "global.mode": "product",
                                    "ssf.pushSkipTlsVerification": "true" } });
  check("a realm create naming product mode and a TLS-verification skip in " +
        "one body is refused (STS-CORE-0103)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/product mode/.test(r.text), r.text.slice(0, 300));
  });
  r = await call("GET", base + "/admin-api/realms");
  check("and no realm was created", function () {
    assert.ok(r.text.indexOf('"' + PROD + '"') < 0, "found " + PROD);
  });
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "outbound TLS " +
             "(product)", overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net", name: "outbound TLS " +
             "(development)", overrides: { "global.mode": "development" } },
           "created the development realm");

  // =========================================================================
  // 1. THE WRITE DOORS.
  // =========================================================================
  log.info("=== 1. a skip cannot be turned on in product ===");
  for (const key of SKIPS) {
    r = await call("POST", realmBase(PROD) + "/admin-api/config/set",
                   { key: key, value: true });
    check("config/set " + key + "=true is refused in the product realm",
          function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.ok(/product mode/.test(r.text) && r.text.indexOf(key) >= 0,
                r.text.slice(0, 300));
    });
    r = await call("POST", base + "/admin-api/realms/set",
                   { id: PROD, key: key, value: "true" });
    check("realms/set of it from the default realm is refused too, asked in " +
          "the product realm", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
    await setting(PROD, key, false);
    await setting(DEV, key, true);
  }
  check("false is accepted in the product realm, and true in the " +
        "development one (every call above answered 200)", function () {
    assert.ok(true);
  });
  const body = { "ssf.pushCaFile": "/nonexistent-but-harmless.crt",
                 "ssf.pushSkipTlsVerification": "true" };
  r = await call("POST", realmBase(PROD) + "/admin-api/config/set-many",
                 body);
  check("a set-many carrying a skip is refused WHOLE in product", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  r = await call("GET", realmBase(PROD) + "/admin-api/config");
  check("and wrote nothing — the CA file beside it was not set", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.ok(r.text.indexOf("/nonexistent-but-harmless.crt") < 0,
              "the CA file was written by a refused section");
  });
  r = await call("POST", realmBase(DEV) + "/admin-api/config/set",
                 { key: "ssf.pushAllowInsecure", value: true });
  check("a removed key is refused, naming what replaced it", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/ssf\.pushAllowHttp/.test(r.text) &&
              /ssf\.pushSkipTlsVerification/.test(r.text),
              r.text.slice(0, 300));
  });

  // =========================================================================
  // 2. SSF PUSH, END TO END.
  // =========================================================================
  log.info("=== 2. SSF push to listeners this job runs ===");
  // A CA made now, for this run only (no key material is committed), and a
  // listener it certified; its certificate reaches the service through the
  // shared directory, or the section that needs it is skipped.
  const ca = await testCa.makeCa();
  const caFile = testCa.publishCa(ca);
  const selfSigned = await listener(await testCa.selfSignedCertificate(HOST));
  const certified = await listener(await testCa.listenerCertificate(ca,
                                                                    HOST));
  const APP = "otls-ssf-" + DEV;
  await ok(realmBase(DEV) + "/admin-api/applications/create",
           { identifier: APP, kind: "oauth2-client", name: APP,
             protocols: ["oauth2", "ssf"],
             fields: { oauthClientId: [APP],
                       oauthAllowedScope: ["ssf:read", "ssf:write"],
                       oauthClientSecret: SECRET,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created the SSF receiver application");
  const create = async function (token, url) {
    log.debug("Entering create().");
    log.debug("Leaving create().");
    return call("POST", realmBase(DEV) + "/ssf/stream",
                { delivery: { method: PUSH, endpoint_url: url },
                  events_requested: [VERIFICATION] },
                { Authorization: "Bearer " + token });
  };
  const verify = async function (token, id) {
    log.debug("Entering verify().");
    log.debug("Leaving verify().");
    return call("POST", realmBase(DEV) + "/ssf/verify",
                { stream_id: id, state: "otls-" + Date.now() },
                { Authorization: "Bearer " + token });
  };
  let token = await tokenFor(DEV, APP);
  r = await create(token, selfSigned.url + "/events");
  check("development: a push stream to a self-signed https listener is " +
        "created", function () {
    assert.ok(r.status === 200 || r.status === 201, r.text.slice(0, 300));
  });
  const untrustedStream = r.json.stream_id;
  r = await verify(token, untrustedStream);
  const arrived = await until("the push to the self-signed listener",
                              async function () {
                                return selfSigned.seen.length > 0;
                              });
  check("development: with ssf.pushSkipTlsVerification on, the verification " +
        "event reaches the self-signed listener", function () {
    assert.ok(arrived, "nothing arrived; verify answered " + r.status +
              " " + r.text.slice(0, 200));
  });

  await setting(DEV, "global.mode", "product");
  r = await call("GET", realmBase(DEV) + "/admin-api/xacml/peps");
  check("product: the XACML view reports the stored nudge skip as NOT in " +
        "force", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    const t = r.json.notify && r.json.notify.transport;
    assert.ok(t && t.skipTlsVerificationSet === true &&
              t.skipTlsVerification === false, JSON.stringify(t));
  });
  token = await tokenFor(DEV, APP);
  const before = selfSigned.seen.length;
  r = await verify(token, untrustedStream);
  await sleep(3000);
  check("product: the same push is NOT delivered, though the skip is still " +
        "stored", function () {
    assert.strictEqual(selfSigned.seen.length, before,
                       "the self-signed listener was reached in product");
  });
  const dead = await until("the refused push to be dead-lettered",
                           async function () {
    const d = await call("GET", realmBase(DEV) +
                         "/admin-api/ssf/dead-letters?dlstream=" +
                         encodeURIComponent(untrustedStream));
    return d.status === 200 && /STS-SSF-0044|certificate/i.test(d.text);
  });
  check("and it is dead-lettered with a certificate failure", function () {
    assert.ok(dead, "no dead letter naming the certificate");
  });

  if (!caFile) {
    skipped += 2;
    log.info("[skip] the CA-file delivery in product: " + testCa.skipReason());
  } else {
    await setting(DEV, "ssf.pushCaFile", caFile);
    r = await create(token, certified.url + "/events");
    check("product: a stream to a listener this job's CA certified is " +
          "created", function () {
      assert.ok(r.status === 200 || r.status === 201, r.text.slice(0, 300));
    });
    const trustedStream = r.json.stream_id;
    await verify(token, trustedStream);
    const reached = await until("the push to the certified listener",
                                async function () {
                                  return certified.seen.length > 0;
                                });
    check("product: with ssf.pushCaFile naming that CA, the push is " +
          "delivered with verification on", function () {
      assert.ok(reached, "nothing arrived at " + certified.url);
    });
  }

  await setting(DEV, "ssf.pushAllowHttp", true);
  r = await create(token, "http://" + HOST + ":9/events");
  check("product: a push stream to a plain-http endpoint is refused " +
        "whatever ssf.pushAllowHttp says", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/product mode/.test(r.text), r.text.slice(0, 300));
  });
  await setting(DEV, "global.mode", "development");
  r = await create(token, "http://" + HOST + ":9/events");
  check("development: the same stream is created with it on", function () {
    assert.ok(r.status === 200 || r.status === 201, r.text.slice(0, 300));
  });

  // =========================================================================
  // 3. FEDERATION'S POLICY, THROUGH THE RFC 9728 IMPORT.
  // =========================================================================
  log.info("=== 3. the RFC 9728 import borrows federation's policy ===");
  const document = function () {
    return JSON.stringify({ resource: "https://api.otls.example",
                            authorization_servers: [realmBase(DEV)] });
  };
  const prm = await listener(await testCa.selfSignedCertificate(HOST),
                             document);
  await setting(DEV, "federation.outboundSkipTlsVerification", false);
  r = await call("POST", realmBase(DEV) +
                 "/admin-api/applications/load-resource-metadata",
                 { url: prm.url + "/.well-known/oauth-protected-resource" });
  check("development: a self-signed document is refused while " +
        "federation.outboundSkipTlsVerification is off", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  await setting(DEV, "federation.outboundSkipTlsVerification", true);
  r = await call("POST", realmBase(DEV) +
                 "/admin-api/applications/load-resource-metadata",
                 { url: prm.url + "/.well-known/oauth-protected-resource" });
  check("development: and loaded with it on", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  await setting(PROD, "federation.outboundAllowHttp", true);
  r = await call("POST", realmBase(PROD) +
                 "/admin-api/applications/load-resource-metadata",
                 { url: "http://" + HOST +
                        ":9/.well-known/oauth-protected-resource" });
  check("product: a plain-http document URL is refused whatever " +
        "federation.outboundAllowHttp says", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/product mode/.test(r.text), r.text.slice(0, 300));
  });

  [selfSigned, certified, prm].forEach(function (one) {
    one.server.close();
  });
  assert.ok(checks + skipped >= 25, "only " + checks + " checks ran and " +
            skipped + " were skipped; a section has stopped being called.");
  log.info(checks + " check(s) passed, " + skipped + " skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_outbound_tls")
  .description("#171: in product mode no outbound request goes over TLS " +
    "without verifying the peer, a skip cannot be written, a private CA is " +
    "reached through a CA file, and plain http is refused.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
