// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_client_certificate.js
//
// ---------------------------------------------------------------------------
// A SHARED SIGNALS RECEIVER AUTHENTICATED BY ITS TLS CLIENT CERTIFICATE,
// OVER THE WIRE (#1049, part of #520).
//
// Every certificate here is one a realm issued to an application through its
// Credentials door, presented on the main port (which asks every connection
// for one and requires none) with no Authorization header. In a throwaway
// realm, and a second one for the realm boundary, both left behind:
//
//   1. The transmitter configuration lists urn:ietf:rfc:8705 in
//      `authorization_schemes`.
//   2. An application declaring `ssf.manage` and a member of SSF_MANAGE
//      creates a poll stream with its certificate alone, reads it back, finds
//      it in its list and polls it.
//   3. The stream is the application's: another client's token answers 404
//      for it and does not list it; that client's own stream answers 404 to
//      the certificate; and a token presented ON the certificate's
//      connection is the token's client, not the application.
//   4. An application declaring only `ssf.read` and in SSF_READ lists its
//      streams with its certificate and is refused a create, 403 naming
//      `ssf.manage`.
//   5. An application certificate from the SECOND realm's authority is
//      refused at the first, 401 saying which realm issued it.
//   6. Revoked, the first application's certificate is refused (401); a new
//      certificate issued to the same application reaches the same stream.
//   7. Nothing presented at all is still a 401: the control.
//
// The in-process half, every branch with the gate's answers given, is
// `tests/ssf_client_certificate.js`.
//
// **NOTHING HERE IS COMMITTED KEY MATERIAL.** Every certificate comes from a
// realm's own authority at run time.
//
// OWNED HERE (local: true): this repository's own transmitter.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const ssfRoles = require("./ssf_roles.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_client_certificate",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("ssfcert").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const OTHER_REALM = usernameFor("ssfcertb").replace(/[^a-z0-9-]/g, "")
  .slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const otherApi = base + "/realm/" + OTHER_REALM + "/admin-api";
const POLL = "urn:ietf:rfc:8936";
const VERIFICATION =
  "https://schemas.openid.net/secevent/ssf/event-type/verification";
const SECRET = "ssf-cert-" + String(Date.now()).slice(-8);
const FILE_PASSWORD = "correct horse battery staple";
const WRITER = "ssfcert-writer-" + REALM;
const READER = "ssfcert-reader-" + REALM;
const CLIENT = "ssfcert-client-" + REALM;
const FOREIGN = "ssfcert-foreign-" + REALM;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The management API and the token endpoint: fetch, no certificate.
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
  return { status: r.status, json: json, text: text, headers: r.headers };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// A request to the transmitter over its own connection, with `tls` (the
// certificate and key) when given, and `token` as a Bearer when given.
async function ssf(method, path, body, tls, token) {
  log.debug("Entering ssf().");
  const bytes = body === undefined ? Buffer.alloc(0)
    : Buffer.from(JSON.stringify(body));
  const headers = { "Content-Type": "application/json",
                    "Content-Length": String(bytes.length) };
  if (token) {
    headers.Authorization = "Bearer " + token;
  }
  const r = await gnap.rawRequest(method, realmBase + path, headers, bytes,
    Object.assign({ rejectUnauthorized: false },
                  tls ? { cert: tls.cert, key: tls.key } : {}));
  log.debug("Leaving ssf(). " + r.status);
  return r;
}

function application(identifier, scopes, extra) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: ["oauth2", "ssf"],
           fields: Object.assign({ oauthClientId: [identifier],
                                   oauthAllowedScope: scopes }, extra || {}) };
}

// A TLS client certificate from a realm's authority, through the
// application's Credentials door: `{ tls, serialHex }`.
async function issueTo(api, identifier, label) {
  log.debug("Entering issueTo().");
  const body = await ok(api + "/applications/issue-tls-client-certificate",
                        { application: identifier, password: FILE_PASSWORD,
                          keyAlg: "ec-p256", label: label },
                        "issued " + identifier + " a TLS client certificate");
  const key = nodeCrypto.createPrivateKey({ key: body.files.key.text,
                                            format: "pem",
                                            passphrase: FILE_PASSWORD })
    .export({ type: "pkcs8", format: "pem" });
  log.debug("Leaving issueTo().");
  return { tls: { cert: body.files.chain.text, key: key },
           serialHex: body.certificate.serialHex };
}

async function token(identifier, scope) {
  log.debug("Entering token().");
  const r = await call("POST", realmBase + "/oauth2/token",
    "grant_type=client_credentials&client_id=" +
    encodeURIComponent(identifier) + "&client_secret=" +
    encodeURIComponent(SECRET) + "&scope=" + encodeURIComponent(scope),
    { "Content-Type": "application/x-www-form-urlencoded" });
  assert.strictEqual(r.status, 200, "token for " + identifier + ": " +
                     r.text.slice(0, 400));
  log.debug("Leaving token().");
  return r.json.access_token;
}

function ids(r) {
  log.debug("Entering ids().");
  const list = Array.isArray(r.json) ? r.json
    : (r.json && r.json.stream_id ? [r.json] : []);
  log.debug("Leaving ids().");
  return list.map(function (one) {
    return one.stream_id;
  });
}

const STREAM = { delivery: { method: POLL },
                 events_requested: [VERIFICATION] };

async function test() {
  log.debug("Entering test().");
  log.info("Driving Shared Signals with TLS client certificates at " +
           realmBase);

  // =========================================================================
  // 0. TWO REALMS, THEIR AUTHORITIES, THE APPLICATIONS AND THEIR ROLES.
  // =========================================================================
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "SSF certificates" },
           "created the realm");
  await ok(base + "/admin-api/realms/create", { id: OTHER_REALM,
    domain: OTHER_REALM + ".example.net", name: "SSF certificates B" },
           "created the second realm");
  await ok(realmApi + "/pki/build", { organisation: "Ssfcert",
                                      country: "US" },
           "built the realm's certificate authority");
  await ok(otherApi + "/pki/build", { organisation: "Ssfcertb",
                                      country: "US" },
           "built the second realm's certificate authority");
  await ok(realmApi + "/applications/create",
           application(WRITER, ["ssf.manage"]), "created the writer");
  await ok(realmApi + "/applications/create",
           application(READER, ["ssf.read"]), "created the reader");
  await ok(realmApi + "/applications/create",
           application(CLIENT, ["ssf.manage"],
                       { oauthClientSecret: SECRET,
                         oauthGrantType: ["client_credentials"],
                         oauthTokenEndpointAuthMethod:
                           "client_secret_post" }),
           "created the token client");
  await ok(otherApi + "/applications/create",
           application(FOREIGN, ["ssf.manage"]),
           "created the second realm's application");
  const post = ssfRoles.callPost(call);
  await ssfRoles.mapApplication(post, realmApi, WRITER, "ssf.manage");
  await ssfRoles.mapApplication(post, realmApi, READER, "ssf.read");
  await ssfRoles.mapApplication(post, realmApi, CLIENT, "ssf.manage");
  await ssfRoles.mapApplication(post, otherApi, FOREIGN, "ssf.manage");
  const writer = await issueTo(realmApi, WRITER, "first");
  const reader = await issueTo(realmApi, READER, "reader");
  const foreign = await issueTo(otherApi, FOREIGN, "foreign");

  log.info("=== 1. the published scheme ===");
  let r = await ssf("GET", "/.well-known/ssf-configuration");
  check("authorization_schemes lists urn:ietf:rfc:8705", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok((r.json.authorization_schemes || []).some(function (one) {
      return one.spec_urn === "urn:ietf:rfc:8705";
    }), JSON.stringify(r.json.authorization_schemes));
  });

  log.info("=== 2. the certificate alone drives a stream ===");
  r = await ssf("POST", "/ssf/stream", STREAM, writer.tls);
  check("the writer's certificate creates a poll stream (201)", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 400));
    assert.ok(r.json && r.json.stream_id, r.text);
  });
  const stream = r.json.stream_id;
  const q = "/ssf/stream?stream_id=" + encodeURIComponent(stream);
  r = await ssf("GET", q, undefined, writer.tls);
  check("and reads it back", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.stream_id, stream, r.text);
  });
  r = await ssf("GET", "/ssf/stream", undefined, writer.tls);
  check("and finds it in its own list", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(ids(r).indexOf(stream) >= 0, r.text.slice(0, 400));
  });
  r = await ssf("POST", "/ssf/poll", { stream_id: stream,
    returnImmediately: true, maxEvents: 10 }, writer.tls);
  check("and polls it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(r.json && r.json.sets && typeof r.json.sets === "object",
              r.text.slice(0, 400));
  });

  log.info("=== 3. the stream is the application's ===");
  const clientToken = await token(CLIENT, "ssf.manage");
  r = await ssf("GET", q, undefined, null, clientToken);
  check("another client's token gets 404 for the certificate's stream",
        function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 400));
  });
  r = await ssf("GET", "/ssf/stream", undefined, null, clientToken);
  check("and does not list it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(ids(r).indexOf(stream) < 0, r.text.slice(0, 400));
  });
  r = await ssf("POST", "/ssf/stream", STREAM, null, clientToken);
  check("that client creates a stream of its own", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 400));
  });
  const theirs = r.json.stream_id;
  r = await ssf("GET", "/ssf/stream?stream_id=" + encodeURIComponent(theirs),
                undefined, writer.tls);
  check("which the writer's certificate gets 404 for", function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 400));
  });
  r = await ssf("GET", q, undefined, writer.tls, clientToken);
  check("a token on the certificate's connection is the token's client: " +
        "404 for the certificate's stream", function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 400));
  });

  log.info("=== 4. the reader reads and does not write ===");
  r = await ssf("GET", "/ssf/stream", undefined, reader.tls);
  check("the reader's certificate lists its streams (200)", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
  });
  r = await ssf("POST", "/ssf/stream", STREAM, reader.tls);
  check("and is refused a create, 403 naming ssf.manage", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 400));
    assert.strictEqual(r.json && r.json.err, "access_denied", r.text);
    assert.ok(/ssf\.manage/.test(r.text), r.text.slice(0, 400));
  });

  log.info("=== 5. the realm boundary ===");
  r = await ssf("GET", "/ssf/stream", undefined, foreign.tls);
  check("the second realm's application certificate is refused here, " +
        "401 naming its realm", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 400));
    assert.ok(r.text.indexOf(OTHER_REALM) >= 0, r.text.slice(0, 400));
  });

  log.info("=== 6. revocation, and the next certificate ===");
  await ok(realmApi + "/applications/revoke-tls-client-certificate",
           { application: WRITER, serialHex: writer.serialHex,
             reason: "keyCompromise" },
           "revoked the writer's certificate");
  r = await ssf("GET", q, undefined, writer.tls);
  check("the revoked certificate is refused (401)", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 400));
  });
  const next = await issueTo(realmApi, WRITER, "second");
  r = await ssf("GET", q, undefined, next.tls);
  check("a new certificate issued to the same application reaches the " +
        "same stream", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.stream_id, stream, r.text);
  });

  log.info("=== 7. the control ===");
  r = await ssf("GET", "/ssf/stream", undefined, null);
  check("nothing presented is still a 401", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 400));
  });

  assert.ok(checks >= 17, "only " + checks + " of 17 checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_ssf_client_certificate")
  .description("Shared Signals: a receiver authenticated by its TLS client " +
    "certificate, as its application (#1049).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
