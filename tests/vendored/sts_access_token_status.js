// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_access_token_status.js
//
// ---------------------------------------------------------------------------
// THE ACCESS-TOKEN STATUS LIST AGAINST A RUNNING SERVICE, FROM OAUTH'S SIDE
// (#432 phase 2; rcbj's decision 4: one list per realm for OAuth's RFC 9068
// access tokens and GNAP's JWT formats). `sts_gnap_rs.js` section 8 holds the
// GNAP half.
//
// A resource server that checks an RFC 9068 access token ON ITS OWN — the JWS
// against /oauth2/jwks, then the claims — could not see a revocation before
// this: only introspection could. What is held here, by THIS FILE'S code and
// not by asking the service:
//
//   1. the authorization server metadata names the aggregation
//      (`status_list_aggregation_endpoint`, draft-ietf-oauth-status-list
//      section 9.1), and the aggregation names the one list;
//   2. a client_credentials token carries `status.status_list` naming it;
//   3. the list is fetched from the token's `uri`, its JWS verified against
//      the JWKS here, `typ`, `sub` and `exp` checked as section 8.3 asks, the
//      ZLIB list inflated here and the token's bit read here (index 0 in the
//      least significant bit, section 4.1): 0;
//   4. after RFC 7009 revocation the bit is 1;
//   5. the CWT form answers by Accept, a historical request answers 501, and
//      the list's Cache-Control is the ttl it carries.
//
// `local: true`, on `tests/CLAUDE.md`'s second question: it is asserted over
// HTTP against a running service, so it is written here (rcbj, 2026-09-21).
// It works in a throwaway trust realm, which it leaves standing.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_access_token_status",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("atstatus").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const api = base + "/admin-api";
const realmApi = realmBase + "/admin-api";
const CLIENT = "ats-client-" + String(Date.now()).slice(-6);
// Long enough for HS256, which product mode holds a secret to (#202).
const SECRET = "ats-secret-" + String(Date.now()).slice(-8) +
  "-0123456789abcdef0123456789abcdef";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const buffer = Buffer.from(await r.arrayBuffer());
  const text = buffer.toString("utf8");
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON: a JWT, a CWT or a page; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving send().");
  return { status: r.status, headers: r.headers, text: text, json: json,
           buffer: buffer };
}

async function apiOk(url, body, what) {
  log.debug("Entering apiOk().");
  const r = await send(url, { method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify(body) });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + url + " answered " + r.status + " " +
            r.text.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.json;
}

function b64json(segment) {
  log.debug("Entering b64json().");
  log.debug("Leaving b64json().");
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

// RS256 / PS256 / ES256 over the published JWKS, with node's crypto.
function verifyJws(compact, jwks) {
  log.debug("Entering verifyJws().");
  const parts = String(compact).split(".");
  assert.strictEqual(parts.length, 3, "a JWS has three parts");
  const header = b64json(parts[0]);
  const jwk = jwks.keys.filter(function (k) {
    return k.kid === header.kid;
  })[0];
  assert.ok(jwk, "the JWS kid " + header.kid + " is in the published JWKS");
  const hash = "sha" + String(header.alg).slice(2);
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const signed = Buffer.from(parts[0] + "." + parts[1]);
  const signature = Buffer.from(parts[2], "base64url");
  let good;
  if (/^PS/.test(header.alg)) {
    good = nodeCrypto.verify(hash, signed, {
      key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  } else if (/^ES/.test(header.alg)) {
    good = nodeCrypto.verify(hash, signed,
                             { key: key, dsaEncoding: "ieee-p1363" },
                             signature);
  } else {
    good = nodeCrypto.verify(hash, signed, key, signature);
  }
  assert.ok(good, "the JWS verifies against the JWKS (" + header.alg + ")");
  log.debug("Leaving verifyJws().");
  return { header: header, claims: b64json(parts[1]) };
}

// The token's bit, after section 8.3's checks on the list itself.
async function statusBit(ref, jwks) {
  log.debug("Entering statusBit().");
  const r = await send(ref.uri);
  assert.strictEqual(r.status, 200, "the status list answers: " + r.text);
  const v = verifyJws(r.text, jwks);
  assert.strictEqual(v.header.typ, "statuslist+jwt", "section 5.1's typ");
  assert.strictEqual(v.claims.sub, ref.uri, "sub is the uri the token names");
  assert.ok(v.claims.exp > Date.now() / 1000, "the list has not expired");
  const bits = v.claims.status_list.bits;
  const bytes = zlib.inflateSync(Buffer.from(v.claims.status_list.lst,
                                             "base64url"));
  const perByte = 8 / bits;
  const byte = bytes[Math.floor(ref.idx / perByte)];
  assert.ok(byte !== undefined, "the index is inside the list");
  log.debug("Leaving statusBit().");
  return (byte >> ((ref.idx % perByte) * bits)) & ((1 << bits) - 1);
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the access-token status list at " + realmBase);

  // ===========================================================================
  // 0. A REALM AND A CONFIDENTIAL CLIENT.
  // ===========================================================================
  await apiOk(api + "/realms/create", { id: REALM,
                                        domain: REALM + ".example.net",
                                        name: "Access-token status" },
              "created the realm");
  await apiOk(realmApi + "/applications/create", {
    identifier: CLIENT, kind: "oauth2-client", name: CLIENT,
    protocols: ["oauth2"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "registered the client");
  const jwks = (await send(realmBase + "/oauth2/jwks")).json;

  // ===========================================================================
  // 1. WHERE A RESOURCE SERVER FINDS IT.
  // ===========================================================================
  let r = await send(realmBase + "/.well-known/oauth-authorization-server");
  const aggregation = r.json && r.json.status_list_aggregation_endpoint;
  check("the authorization server metadata names " +
        "status_list_aggregation_endpoint (section 9.1)", function () {
    assert.strictEqual(aggregation, realmBase + "/status-lists",
                       r.text.slice(0, 300));
  });
  r = await send(aggregation);
  const listUri = realmBase + "/status-lists/access-tokens";
  check("the aggregation names the realm's one list", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(r.json.status_lists, [listUri]);
  });

  // ===========================================================================
  // 2–4. A TOKEN, ITS BIT, AND ITS REVOCATION.
  // ===========================================================================
  const form = new URLSearchParams({ grant_type: "client_credentials",
                                     client_id: CLIENT,
                                     client_secret: SECRET }).toString();
  r = await send(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form });
  assert.strictEqual(r.status, 200, "a token: " + r.text);
  const token = r.json.access_token;
  const claims = verifyJws(token, jwks).claims;
  const ref = (claims.status || {}).status_list || {};
  check("an RFC 9068 access token carries status.status_list naming the " +
        "realm's list (section 6.1)", function () {
    assert.strictEqual(ref.uri, listUri, JSON.stringify(claims.status));
    assert.ok(Number.isInteger(ref.idx) && ref.idx >= 0,
              JSON.stringify(claims.status));
  });
  const before = await statusBit(ref, jwks);
  check("its bit, read from the list this file verified, is 0", function () {
    assert.strictEqual(before, 0);
  });
  r = await send(realmBase + "/oauth2/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: token, client_id: CLIENT,
                                client_secret: SECRET }).toString() });
  assert.strictEqual(r.status, 200, "RFC 7009 revocation: " + r.text);
  // A revocation reaches another worker or node by replication: asked again
  // until it shows, within a bound.
  let after = await statusBit(ref, jwks);
  const deadline = Date.now() + 15000;
  while (after !== 1 && Date.now() < deadline) {
    await new Promise(function (resolve) { setTimeout(resolve, 250); });
    after = await statusBit(ref, jwks);
  }
  check("after /oauth2/revoke the bit is 1 — a resource server checking on " +
        "its own refuses the token", function () {
    assert.strictEqual(after, 1);
  });

  // ===========================================================================
  // 5. THE OTHER FORMS.
  // ===========================================================================
  r = await send(listUri, { headers: {
    Accept: "application/statuslist+cwt" } });
  check("Accept: application/statuslist+cwt answers a COSE_Sign1 (tag 18)",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/^application\/statuslist\+cwt/
      .test(String(r.headers.get("content-type"))));
    assert.strictEqual(r.buffer[0], 0xd2, "CBOR tag 18 first");
  });
  r = await send(listUri);
  const ttl = b64json(r.text.split(".")[1]).ttl;
  check("Cache-Control is max-age equal to the ttl the list carries",
        function () {
    assert.ok(ttl > 0, String(ttl));
    assert.strictEqual(r.headers.get("cache-control"), "max-age=" + ttl);
  });
  r = await send(listUri + "?time=1700000000");
  check("a historical list answers 501 (section 8.4)", function () {
    assert.strictEqual(r.status, 501, r.text);
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
                         "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_access_token_status")
  .description("The access-token status list from OAuth's side: an RFC 9068 " +
    "token's status claim, the list verified and read by this file, and the " +
    "bit set by RFC 7009 revocation.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
