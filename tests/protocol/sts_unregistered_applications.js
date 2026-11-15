// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_unregistered_applications.js
//
// ---------------------------------------------------------------------------
// IN PRODUCT, AN APPLICATION NOBODY REGISTERED GETS NOTHING, OVER THE WIRE
// (#496).
//
// D12 (#444): carries over tests/unregistered_applications.js in one
// throwaway realm that starts in development and is switched to product
// half way, so that an application development only SAW (a sighting, no
// `appRegisteredBy`) is there to be refused:
//
//   U6/O1/S1/S4/U7, development: an unregistered OAuth client, SAML 2.0
//      service provider, SAML 1.1 relying party, WS-Federation relying party
//      and WS-Trust AppliesTo are each answered, and the sighting files the
//      application unregistered;
//   U2, product: a WS-Trust Issue for an AppliesTo nobody registered or only
//      seen is wst:InvalidScope (STS-WSTRUST-0030); none is
//      wst:InvalidRequest (STS-WSTRUST-0031); a registered one is issued;
//   U4: a refusal records nothing — no application entry for the AppliesTo;
//   U7, product: a wsignin1.0 for an unregistered or seen-only wtrealm is a
//      404 (STS-WSFED-0021) before the sign-in screen; a registered one
//      reaches the screen;
//   O1, product: an authorization request naming an unregistered or a
//      seen-only client_id is a 400 that is not redirected (STS-OAUTH-0947),
//      and one naming none too (STS-OAUTH-0948); a registered one reaches
//      the screen;
//   O2, product: a token request from a seen-only client is 401
//      invalid_client (STS-OAUTH-0949);
//   S1, product: an AuthnRequest from an unregistered or seen-only Issuer is
//      a 403 page (STS-SAML-0103); a registered one passes that check and
//      is refused only for being unsigned (STS-SAML-0063);
//   S3, product: the per-SP metadata path of a seen-only service provider
//      is a 404 (STS-SAML-0082);
//   S4, product: a SAML 1.1 browser flow for a seen-only relying party is a
//      403 page (STS-SAML-0105).
//
// What stays in process (its D12 note): the mode predicate's own table
// (U1), Validate and Cancel (U5), the delegation policy's resolution (O3),
// a request-started Metadata Query lookup (S5, `sts_saml_unregistered.js`
// holds the over-the-wire half) and GNAP's proved key (G1, phase 8's GNAP
// jobs carry the key proofs it needs).
//
// The realm is removed at the end ONLY when STS_TEST_REMOVE_REALMS is "1":
// a private probe shared by many jobs fills its directory otherwise, and
// the suite's own rule (tests/CLAUDE.md, *No job removes a realm*) keeps it.
//
// OWNED HERE (local: true): this repository's own registry and protocols.
// ---------------------------------------------------------------------------

const assert = require("assert");
const zlib = require("zlib");
const crypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_unregistered_applications",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("unr-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const PERSON = "unr-person";
const PASSWORD = "Unr-Person-Pa55word!x";
const SEEN = {
  client: "unr-seen-client",
  sp: "https://unr-seen-sp.example",
  rp11: "urn:unr-seen-rp11",
  wsfed: "https://unr-seen-rp.example/",
  wstrust: "https://unr-seen-wst.example/"
};
const NEVER = {
  client: "unr-never-client",
  sp: "https://unr-never-sp.example",
  wsfed: "https://unr-never-rp.example/",
  wstrust: "https://unr-never-wst.example/"
};
const REGISTERED = {
  client: "unr-reg-client",
  sp: "https://unr-reg-sp.example",
  wsfed: "https://unr-reg-rp.example/",
  wstrust: "https://unr-reg-wst.example/"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
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

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page, a SOAP envelope or nothing; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=1&code=" + encodeURIComponent(code));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving codeCount().");
  return Number(r.body.matched || 0);
}

// Runs `act` and answers it with how far the code's count on the realm's
// audit grew: a code is recorded, never sent.
async function coded(code, act) {
  log.debug("Entering coded(). " + code);
  const before = await codeCount(code);
  const answer = await act();
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving coded(). " + before + " -> " + now);
  return { answer: answer, grew: now - before };
}

async function application(identifier) {
  log.debug("Entering application(). " + identifier);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(identifier));
  log.debug("Leaving application().");
  return r.status === 200 && r.body && r.body.found ? r.body : null;
}

// The sign-in screen's address; product moves the step's id into the
// fragment (#1454).
function toScreen(reply) {
  log.debug("Entering toScreen().");
  log.debug("Leaving toScreen().");
  return (reply.status === 302 || reply.status === 303) &&
         /\/authn\/login\?(.*[&#])?authn=/.test(reply.location);
}

function authorize(clientId) {
  log.debug("Entering authorize(). " + clientId);
  // PKCE, which product's RFC 9700 mode requires of every client
  // (STS-OAUTH-0127 without it).
  const verifier = crypto.randomBytes(32).toString("base64url");
  const query = { response_type: "code", scope: "openid", state: "s",
                  redirect_uri: "https://" + String(clientId || "none") +
                                ".example/cb",
                  code_challenge_method: "S256",
                  code_challenge: crypto.createHash("sha256")
                    .update(verifier).digest("base64url") };
  if (clientId) {
    query.client_id = clientId;
  }
  log.debug("Leaving authorize().");
  return send(RB + "/oauth2/authorize?" + new URLSearchParams(query)
    .toString());
}

function wsfed(wtrealm) {
  log.debug("Entering wsfed(). " + wtrealm);
  log.debug("Leaving wsfed().");
  return send(RB + "/wsfed?" + new URLSearchParams({ wa: "wsignin1.0",
    wtrealm: wtrealm, wreply: wtrealm }).toString());
}

// An AuthnRequest over the HTTP-Redirect binding: deflated, base64.
function saml2(issuer) {
  log.debug("Entering saml2(). " + issuer);
  const xml = '<samlp:AuthnRequest ' +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_' +
    crypto.randomBytes(12).toString("hex") + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString().replace(/\.\d+Z$/, "Z") +
    '" AssertionConsumerServiceURL="' + issuer + '/acs"><saml:Issuer>' +
    issuer + '</saml:Issuer></samlp:AuthnRequest>';
  const request = zlib.deflateRawSync(Buffer.from(xml)).toString("base64");
  log.debug("Leaving saml2().");
  return send(RB + "/saml2/sso?" + new URLSearchParams({
    SAMLRequest: request }).toString());
}

function saml11(providerId) {
  log.debug("Entering saml11(). " + providerId);
  log.debug("Leaving saml11().");
  return send(RB + "/saml11/sso?" + new URLSearchParams({
    providerId: providerId,
    shire: "https://" + providerId.replace(/^urn:/, "") + ".example/acs",
    target: "t" }).toString());
}

function wsTrust(appliesTo) {
  log.debug("Entering wsTrust(). " + appliesTo);
  const applies = appliesTo === null ? "" :
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<wsa:Address>' + appliesTo + '</wsa:Address></wsa:EndpointReference>' +
    '</wsp:AppliesTo>';
  const envelope = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + PERSON + '</wsse:Username>' +
    '<wsse:Password>' + PASSWORD + '</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></soap:Header><soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
    'Issue</wst:RequestType>' + applies +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  log.debug("Leaving wsTrust().");
  return send(RB + "/sts", { method: "POST",
    headers: { "Content-Type": "application/soap+xml" }, body: envelope });
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Unregistered " + STAMP },
    "created the realm");
  await ok(API + "/users/create", { username: PERSON, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Unr Person", givenName: "Unr", sn: "Person",
                  mail: PERSON + "@unr.example.net" } }, "created the person");
  const register = function (id, protocols, fields) {
    return ok(API + "/applications/create", { identifier: id, name: id,
      protocols: protocols, fields: fields }, "registered " + id);
  };
  await register(REGISTERED.client, ["oauth2", "oidc"], {
    oauthClientId: [REGISTERED.client],
    oauthRedirectUri: ["https://" + REGISTERED.client + ".example/cb"] });
  await register(REGISTERED.sp, ["saml2"], {
    samlEntityId: [REGISTERED.sp],
    samlAssertionConsumerService: [REGISTERED.sp + "/acs"] });
  await register(REGISTERED.wsfed, ["wsfed"], {
    wsfedRealm: [REGISTERED.wsfed], wsfedReplyUrl: [REGISTERED.wsfed] });
  await register(REGISTERED.wstrust, ["wstrust"], {
    wstrustAppliesTo: [REGISTERED.wstrust] });
  log.debug("Leaving setUp().");
}

async function development() {
  log.debug("Entering development().");
  log.info("=== U6. development answers, and files what it sees ===");
  const answered = [
    ["an OAuth client", await authorize(SEEN.client)],
    ["a SAML 2.0 service provider", await saml2(SEEN.sp)],
    ["a SAML 1.1 relying party", await saml11(SEEN.rp11)],
    ["a WS-Federation relying party", await wsfed(SEEN.wsfed)]];
  answered.forEach(function (pair) {
    check("DEVELOPMENT: " + pair[0] + " nobody registered reaches the " +
          "sign-in screen", function () {
      assert.ok(toScreen(pair[1]), pair[1].status + " " + pair[1].location);
    });
  });
  const minted = await send(RB + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: SEEN.client, client_secret: "x" }).toString() });
  check("DEVELOPMENT: the token endpoint issues to it too", function () {
    assert.strictEqual(minted.status, 200, minted.raw.slice(0, 300));
  });
  const issued = await wsTrust(SEEN.wstrust);
  check("DEVELOPMENT: a WS-Trust Issue for an unregistered AppliesTo is " +
        "issued", function () {
    assert.strictEqual(issued.status, 200, issued.raw.slice(0, 300));
    assert.ok(/Assertion/.test(issued.raw));
  });
  const none = await wsTrust(null);
  check("DEVELOPMENT: and so is one with no AppliesTo", function () {
    assert.strictEqual(none.status, 200, none.raw.slice(0, 300));
  });
  for (const id of [SEEN.client, SEEN.sp, SEEN.rp11, SEEN.wstrust]) {
    const app = await application(id);
    check("DEVELOPMENT: the sighting files " + id + ", unregistered",
          function () {
      assert.ok(app, "no entry for " + id);
      assert.ok(!app.registeredBy, JSON.stringify(app.registeredBy));
    });
  }
  log.debug("Leaving development().");
}

async function product() {
  log.debug("Entering product().");
  await ok(API + "/config/set", { key: "global.mode", value: "product" },
           "switched the realm to product");
  await ok(API + "/config/set", { key: "authn.allowOptionalSecondFactor",
                                  value: "true" },
           "let a password alone sign in");

  log.info("=== U2. WS-Trust, product ===");
  for (const pair of [["nobody registered", NEVER.wstrust],
                      ["only seen", SEEN.wstrust]]) {
    const got = await coded("STS-WSTRUST-0030", function () {
      return wsTrust(pair[1]);
    });
    check("PRODUCT: an AppliesTo " + pair[0] + " is wst:InvalidScope, " +
          "recorded as STS-WSTRUST-0030", function () {
      assert.strictEqual(got.answer.status, 500, got.answer.raw
        .slice(0, 300));
      assert.ok(/InvalidScope/.test(got.answer.raw));
      assert.strictEqual(got.grew, 1);
      assert.ok(got.answer.raw.indexOf("STS-") < 0, "a code was sent");
    });
  }
  const none = await coded("STS-WSTRUST-0031", function () {
    return wsTrust(null);
  });
  check("PRODUCT: no AppliesTo is wst:InvalidRequest, recorded as " +
        "STS-WSTRUST-0031", function () {
    assert.strictEqual(none.answer.status, 500, none.answer.raw.slice(0, 300));
    assert.ok(/InvalidRequest/.test(none.answer.raw));
    assert.strictEqual(none.grew, 1);
  });
  const registered = await wsTrust(REGISTERED.wstrust);
  check("PRODUCT: a registered AppliesTo is issued", function () {
    assert.strictEqual(registered.status, 200, registered.raw.slice(0, 300));
    assert.ok(/Assertion/.test(registered.raw));
  });
  const nothing = await application(NEVER.wstrust);
  check("U4. PRODUCT: a refusal records nothing: no entry for the AppliesTo",
        function () {
    assert.strictEqual(nothing, null);
  });

  log.info("=== U7. WS-Federation, product ===");
  for (const pair of [["nobody registered", NEVER.wsfed],
                      ["only seen", SEEN.wsfed]]) {
    const got = await coded("STS-WSFED-0021", function () {
      return wsfed(pair[1]);
    });
    check("PRODUCT: a wsignin1.0 for a wtrealm " + pair[0] + " is a 404 " +
          "before the sign-in screen, recorded as STS-WSFED-0021",
          function () {
      assert.strictEqual(got.answer.status, 404, got.answer.raw
        .slice(0, 300));
      assert.strictEqual(got.grew, 1);
    });
  }
  const wsfedOk = await wsfed(REGISTERED.wsfed);
  check("PRODUCT: a registered wtrealm reaches the sign-in screen",
        function () {
    assert.ok(toScreen(wsfedOk), wsfedOk.status + " " + wsfedOk.location);
  });

  log.info("=== O1, O2. OAuth, product ===");
  for (const pair of [["nobody registered", NEVER.client,
                       "STS-OAUTH-0947"],
                      ["only seen", SEEN.client, "STS-OAUTH-0947"],
                      ["none", "", "STS-OAUTH-0948"]]) {
    const got = await coded(pair[2], function () {
      return authorize(pair[1]);
    });
    check("PRODUCT: an authorization request naming " + pair[0] + " is a " +
          "400 that is not redirected, recorded as " + pair[2], function () {
      assert.strictEqual(got.answer.status, 400, got.answer.raw
        .slice(0, 300));
      assert.strictEqual(got.answer.location, "");
      assert.strictEqual(got.grew, 1);
    });
  }
  const oauthOk = await authorize(REGISTERED.client);
  check("PRODUCT: a registered client reaches the sign-in screen",
        function () {
    assert.ok(toScreen(oauthOk), oauthOk.status + " " + oauthOk.location +
              " " + oauthOk.raw.slice(0, 600));
  });
  const token = await coded("STS-OAUTH-0949", function () {
    return send(RB + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: SEEN.client, client_secret: "x" }).toString() });
  });
  check("PRODUCT: a token request from a seen-only client is 401 " +
        "invalid_client, recorded as STS-OAUTH-0949", function () {
    assert.strictEqual(token.answer.status, 401, token.answer.raw
      .slice(0, 300));
    assert.strictEqual(token.answer.body.error, "invalid_client");
    assert.strictEqual(token.grew, 1);
  });

  log.info("=== S1, S3, S4. SAML, product ===");
  for (const pair of [["nobody registered", NEVER.sp],
                      ["only seen", SEEN.sp]]) {
    const got = await coded("STS-SAML-0103", function () {
      return saml2(pair[1]);
    });
    check("PRODUCT: an AuthnRequest from an Issuer " + pair[0] + " is a " +
          "403 page, recorded as STS-SAML-0103", function () {
      assert.strictEqual(got.answer.status, 403, got.answer.raw
        .slice(0, 300));
      assert.strictEqual(got.grew, 1);
    });
  }
  // OBSERVED: product also requires a signed AuthnRequest (#37), so a
  // registered service provider's UNSIGNED request passes the registration
  // check and is then refused for its signature, STS-SAML-0063, not 0103.
  const before0103 = await codeCount("STS-SAML-0103");
  const samlOk = await coded("STS-SAML-0063", function () {
    return saml2(REGISTERED.sp);
  });
  const after0103 = await codeCount("STS-SAML-0103");
  check("PRODUCT: a registered service provider passes the registration " +
        "check, and its unsigned request is refused for that alone " +
        "(STS-SAML-0063)", function () {
    assert.strictEqual(samlOk.answer.status, 403);
    // The call's row and the refusal's own row each carry it.
    assert.ok(samlOk.grew >= 1, "STS-SAML-0063 rows grew by " + samlOk.grew);
    assert.strictEqual(after0103, before0103);
  });
  const metadata = await coded("STS-SAML-0082", function () {
    return send(RB + "/saml2/metadata/" + encodeURIComponent(SEEN.sp));
  });
  check("PRODUCT: a seen-only service provider's metadata path is a 404, " +
        "recorded as STS-SAML-0082", function () {
    assert.strictEqual(metadata.answer.status, 404);
    assert.strictEqual(metadata.grew, 1);
  });
  const rp11 = await coded("STS-SAML-0105", function () {
    return saml11(SEEN.rp11);
  });
  check("PRODUCT: a SAML 1.1 browser flow for a seen-only relying party is " +
        "a 403 page, recorded as STS-SAML-0105", function () {
    assert.strictEqual(rp11.answer.status, 403, rp11.answer.raw
      .slice(0, 300));
    assert.strictEqual(rp11.grew, 1);
  });
  log.debug("Leaving product().");
}

// Opt-in: see the header.
async function removeRealm() {
  log.debug("Entering removeRealm().");
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: REALM });
    log.info("Removed the realm " + REALM + ": " + r.status);
  }
  log.debug("Leaving removeRealm().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await setUp();
    await development();
    await product();
  } finally {
    await removeRealm();
  }
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_unregistered_applications FAILED: " +
            ((e && e.stack) || e));
  process.exit(1);
});
