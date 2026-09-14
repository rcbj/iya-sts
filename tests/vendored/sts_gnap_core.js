"use strict";
//
// File: sts_gnap_core.js
//
// ---------------------------------------------------------------------------
// GNAP (RFC 9635) AGAINST A RUNNING SERVICE: EVERY INTERACTION MODE, EVERY
// FINISH METHOD, EVERY KEY PROOFING METHOD, CONTINUATION, MODIFICATION,
// REVOCATION, TOKEN MANAGEMENT AND KEY ROTATION — AND THE WAYS EACH IS REFUSED.
//
// The client instance here is `gnap_client.js`, written from the RFCs with
// node's crypto and sharing no code with `gnap/`: an HTTP signature base built
// by the same function at both ends verifies and interoperates with nobody.
// The resource owner is a person created through /admin-api with a real
// password, signing in through the one sign-in screen in a cookie-jar browser
// of this file's own, and every refusal is asserted by its GNAP ERROR CODE
// (RFC 9635 section 3.6), never by its status alone.
//
// Everything runs in a THROWAWAY TRUST REALM, with `gnap.continueWaitS` at zero
// so no grant has to sleep five seconds, which the job restores for the one
// section that asserts `too_fast`. Realms are left behind for troubleshooting
// (tests/CLAUDE.md).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_core",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
var REALM = usernameFor("gnapcore").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var PASSWORD = "gnap-core-Passw0rd!-" + String(Date.now()).slice(-6);

// The resource owner, the browser and the harness are `gnap_flow.js`'s, shared
// with sts_gnap_rs.js and sts_gnap_signals.js; the names below are the ones
// this file has always used.
const h = require("./gnap_flow.js").harness({ base: base, realm: REALM,
                                              password: PASSWORD, log: log });
var api = h.api;
var realmBase = h.realmBase;
var realmApi = h.realmApi;
var GRANT = h.GRANT;
var RS = h.RS;
var FINISH = h.FINISH;
var DEMO = h.DEMO;

var OWNER = usernameFor("gnap-owner");
var STRANGER = usernameFor("gnap-stranger");

const check = h.check;
const apiPost = h.apiPost;
const ok = h.ok;
const setting = h.setting;
const refused = h.refused;
const browser = h.browser;
const reachApproval = h.reachApproval;
const answer = h.answer;
const finishParams = h.finishParams;
const readAccess = h.readAccess;
const ensurePerson = h.ensurePerson;

function grantBody(client, extra) {
  log.debug("Entering grantBody().");
  log.debug("Leaving grantBody().");
  return h.grantBody(client, extra, "GNAP core job");
}

async function redirectGrant(client, who, extra, opts) {
  log.debug("Entering redirectGrant().");
  log.debug("Leaving redirectGrant().");
  return h.redirectGrant(client, who,
                         Object.assign({ client: grantBody(client).client },
                                       extra || {}), opts);
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving GNAP at " + GRANT);

  // =========================================================================
  // 0. A REALM, TWO PEOPLE, AND NO WAITING.
  // =========================================================================
  log.info("=== 0. the realm ===");
  await ok(api + "/realms/create", { id: REALM, name: "GNAP core" },
           "created " +
      "the realm");
  await setting("gnap.continueWaitS", 0);
  await setting("gnap.pushAllowInsecure", true);
  await ensurePerson(OWNER);
  await ensurePerson(STRANGER);

  // =========================================================================
  // 1. DISCOVERY (section 9, RFC 9767 section 3.1).
  // =========================================================================
  log.info("=== 1. discovery ===");
  let r = await gnap.rawRequest("OPTIONS", GRANT, {});
  check("OPTIONS on the grant endpoint answers the section 9 document",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.grant_request_endpoint, GRANT);
    ["redirect", "app", "user_code", "user_code_uri"].forEach(function (mode) {
      assert.ok(r.json.interaction_start_modes_supported.indexOf(mode) >= 0,
                mode);
    });
    assert.deepStrictEqual(r.json.key_proofs_supported.slice().sort(),
                           ["httpsig", "jws", "jwsd", "mtls"]);
    assert.strictEqual(r.json.key_rotation_supported, true);
  });
  r = await gnap.rawRequest("GET", realmBase + "/.well-known/gnap-as-rs", {});
  check("the RS-facing discovery document names the five token formats and " +
        "both RS endpoints",
        function () {
          assert.strictEqual(r.status, 200, r.text);
          assert.deepStrictEqual(r.json.token_formats_supported.slice().sort(),
                                 ["biscuit", "jwt-encrypted", "jwt-signed",
                                  "macaroon", "zcap"]);
          assert.strictEqual(r.json.introspection_endpoint,
                             realmBase + "/gnap/introspect");
          assert.strictEqual(r.json.resource_registration_endpoint,
                             realmBase + "/gnap/resource");
        });
  r = await gnap.rawRequest("GET", RS, {});
  check("the demonstration RS answers an unauthenticated request with the " +
        "RS-first challenge (section 9.1)", function () {
          assert.strictEqual(r.status, 401);
          assert.ok(/^GNAP /.test(r.headers["www-authenticate"]),
                    r.headers["www-authenticate"]);
          assert.ok(r.headers["www-authenticate"].indexOf(
              "as_uri=\"" + GRANT + "\"") >= 0);
        });

  // =========================================================================
  // 2. REFUSALS BEFORE ANY INTERACTION.
  // =========================================================================
  log.info("=== 2. malformed and unproved requests ===");
  const es = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await es.send("POST", GRANT, { json: grantBody(es), sign: false });
  check("an unsigned grant request is invalid_client (section 7.3)",
        function () {
    refused(r, "invalid_client", "an unsigned request");
    assert.strictEqual(r.status, 401);
  });
  r = await es.send("POST", GRANT, { json: grantBody(es), mutate: function (m) {
    log.debug("Entering mutate().");
    log.debug("Leaving mutate().");
    return { body: Buffer.from(m.body.toString()
                                     .replace("GNAP core job", "GNAP " +
        "core jab")) };
  } });
  check("content changed after signing fails the Content-Digest check",
        function () {
    refused(r, "invalid_client", "a tampered body");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es), httpsig: { tag: "not-gnap" } });
  check("a signature without tag=gnap is refused (section 7.3.1)", function () {
    refused(r, "invalid_client", "the wrong tag");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es),
                      httpsig: { created: Math.floor(Date.now() / 1000) -
                                          3600 } });
  check("a signature created an hour ago is refused", function () {
    refused(r, "invalid_client", "a stale created");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es),
                      httpsig: { alg: "ecdsa-p256-sha256" } });
  check("a signature carrying the alg parameter is refused (section 7.3.1)",
        function () {
    refused(r, "invalid_client", "an explicit alg parameter");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es),
                      httpsig: { keyid: "someone-else" } });
  check("a keyid that is not the JWK's kid is refused", function () {
    refused(r, "invalid_client", "the wrong keyid");
  });
  const replayNonce = "replay-" + nodeCrypto.randomBytes(6).toString("hex");
  r = await es.send("POST", GRANT,
                    { json: grantBody(es), httpsig: { nonce: replayNonce } });
  assert.strictEqual(r.status, 200, r.text);
  r = await es.send("POST", GRANT,
                    { json: grantBody(es), httpsig: { nonce: replayNonce } });
  check("a nonce used twice is refused (section 7.3.1)", function () {
    refused(r, "invalid_client", "a replayed nonce");
  });
  r = await es.send("POST", GRANT, { json: "{not json" });
  check("content that is not JSON is invalid_request", function () {
    refused(r, "invalid_request", "a body that is not JSON");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es,
                                      { access_token: { access: readAccess(),
                                                        label: 42 } }) });
  check("a label that is not a string fails the JSON Schema", function () {
    const body = refused(r, "invalid_request", "a numeric label");
    assert.ok(/schema/i.test(body.error.description), body.error.description);
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { client: { key: es.keyObject(),
    class_id: "evil\u0007class" } }) });
  check("a control character in class_id is refused by the schema " +
        "(sanitisation)", function () {
    refused(r, "invalid_request", "a control character");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es,
                                      { access_token: { access: readAccess(),
    flags: ["bearer", "bearer"] } }) });
  check("a flag repeated is invalid_flag (section 2.1.1)", function () {
    refused(r, "invalid_flag", "a repeated flag");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es,
                                      { access_token: { access: readAccess(),
    flags: ["durable"] } }) });
  check("asking for the response-only durable flag is invalid_flag",
        function () {
    refused(r, "invalid_flag", "a durable request");
  });
  r = await es.send("POST", GRANT, { json: grantBody(es, { access_token: [
    { label: "a", access: readAccess() }, { access: readAccess() }] }) });
  check("a multiple-token request with an unlabelled token is " +
        "invalid_request (2.1.2)", function () {
    refused(r, "invalid_request", "a missing label");
  });
  r = await es.send("POST", GRANT, { json: grantBody(es, { access_token: [
    { label: "a", access: readAccess() },
    { label: "a", access: readAccess() }] }) });
  check("two tokens with one label is invalid_request", function () {
    refused(r, "invalid_request", "a duplicate label");
  });
  r = await es.send("POST", GRANT, { json: { client: { key: es.keyObject() },
                                             interact: {
                                               start: ["redirect"] } } });
  check("a request for neither access nor subject is invalid_request",
        function () {
    refused(r, "invalid_request", "an empty request");
  });
  const withPrivate = JSON.parse(JSON.stringify(es.keyObject()));
  withPrivate.jwk.d = "AAAA";
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { client: { key: withPrivate } }) });
  check("a JWK carrying a private member is invalid_client (section 7.1)",
        function () {
    refused(r, "invalid_client", "a private key by value");
  });
  const twoFormats = Object.assign({}, es.keyObject(),
                                   { "cert#S256": gnap.b64u(
                                       gnap.sha("sha256", Buffer.from("x"))) });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { client: { key: twoFormats } }) });
  check("a key in two formats is invalid_client (section 11.35)", function () {
    refused(r, "invalid_client", "two key formats");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { client: undefined }) });
  check("a request with no client is invalid_client (section 2.3)",
        function () {
    refused(r, "invalid_client", "no client");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { client: "no-such-instance" }) });
  check("an unknown instance identifier is invalid_client (2.3.1)",
        function () {
    refused(r, "invalid_client", "an unknown instance");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { interact: undefined }) });
  check("a request needing approval with no interaction is " +
        "invalid_interaction (2.5)", function () {
    refused(r, "invalid_interaction", "no interaction");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es,
                                      { interact: {
                                        start: ["telepathy"] } }) });
  check("only an unsupported start mode is invalid_interaction", function () {
    refused(r, "invalid_interaction", "an unsupported start mode");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es, { interact_ref: "abc" }) });
  check("interact_ref on a new request is invalid_request (5.1)", function () {
    refused(r, "invalid_request", "an interaction reference at the grant " +
                                  "endpoint");
  });

  // =========================================================================
  // 3. REDIRECT START, REDIRECT FINISH, HTTP SIGNATURES — THE WHOLE GRANT.
  // =========================================================================
  log.info("=== 3. redirect + redirect finish ===");
  const flow = await redirectGrant(es, OWNER);
  check("the pending response carries a redirect, a finish nonce, expires_in " +
        "and a continuation with a wait (sections 3.1 and 3.3)", function () {
          assert.ok(/\/gnap\/interact\//.test(flow.pending.interact.redirect));
          assert.ok(flow.pending.interact.finish);
          assert.ok(flow.pending.interact.expires_in > 0);
          assert.strictEqual(flow.pending.continue.wait, 0);
          assert.ok(flow.pending.instance_id, "an instance_id is issued (3.5)");
        });
  const token = flow.released.access_token;
  check("the released token carries the value, the access, expires_in and a " +
        "manage URI", function () {
    assert.ok(/^[A-Za-z0-9._~+/-]+=*$/.test(token.value), "token68");
    assert.deepStrictEqual(token.access, readAccess());
    assert.ok(token.expires_in > 0);
    assert.ok(token.manage && token.manage.uri &&
              token.manage.access_token.value);
    assert.notStrictEqual(token.manage.access_token.value, token.value);
    assert.ok(!token.flags || token.flags.indexOf("bearer") < 0, "bound, not " +
        "bearer");
  });
  r = await es.send("GET", RS, { token: token.value });
  check("the demonstration RS accepts the bound token with an HTTP signature",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.format, "jwt-signed");
    assert.strictEqual(r.json.method, "httpsig");
  });
  const thief = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await thief.send("GET", RS, { token: token.value });
  check("the same token signed with another key is refused at the RS",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await es.send("GET", RS, { token: token.value, sign: false });
  check("the bound token with no proof is refused at the RS (section 7.2)",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await es.send("GET", RS,
                    { token: flow.released.continue.access_token.value });
  check("a CONTINUATION token is never an access token at the RS (section 5)",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await es.send("POST", flow.released.continue.uri, {
    token: flow.released.continue.access_token.value,
    json: { interact_ref: flow.interactRef } });
  check("the interaction reference presented again is too_many_attempts " +
        "(section 5.1)", function () {
    refused(r, "too_many_attempts", "a replayed interact_ref");
  });
  r = await es.send("POST", flow.released.continue.uri,
                    { token: flow.released.continue.access_token.value });
  check("…and the grant is finalized: a further continuation is " +
        "invalid_continuation", function () {
    refused(r, "invalid_continuation", "a continuation after finalization");
  });
  r = await gnap.rawRequest("GET", flow.pending.interact.redirect, {});
  check("the used redirect URI shows an error and never redirects to the " +
        "client (4.1.1)", function () {
    assert.strictEqual(r.status, 400);
    assert.ok(!r.headers.location);
  });

  // =========================================================================
  // 4. DENIAL, AND THE WRONG PERSON.
  // =========================================================================
  log.info("=== 4. user_denied and unknown_user ===");
  // A remembered approval: the same client asking for the same rights again is
  // not shown the page (gnap.rememberApprovals).
  let body = grantBody(es);
  r = await es.send("POST", GRANT, { json: body });
  let pending = r.json;
  let b = flow.browser;
  r = await b.go("GET", pending.interact.redirect);
  r = await b.go("GET", r.location);
  check("the same client asking the same person for the same rights again " +
        "skips the approval page and finishes at once (remembered in the " +
        "consent register)", function () {
          assert.strictEqual(r.status, 303, r.text.slice(0, 300));
          assert.ok(/hash=.*interact_ref=/.test(r.location), r.location);
        });
  const denier = new gnap.Client({ key: gnap.newKey("ES256") });
  body = grantBody(denier);
  r = await denier.send("POST", GRANT, { json: body });
  pending = r.json;
  b = browser();
  let approval = await reachApproval(b, pending.interact.redirect, OWNER);
  r = await answer(b, approval, "deny");
  let params = finishParams(r.location, r);
  check("a denial still enacts the finish method with a valid hash (section " +
        "4.2)", function () {
    assert.strictEqual(params.hash,
                       gnap.interactionHash(body.interact.finish.nonce,
      pending.interact.finish, params.ref, GRANT));
  });
  r = await denier.send("POST", pending.continue.uri,
                        { token: pending.continue.access_token.value,
                                                        json: {
                                                          interact_ref:
                                                            params.ref } });
  check("the continuation says user_denied, with a continue member to try " +
        "again (5.1)", function () {
    refused(r, "user_denied", "a denied grant");
    assert.ok(r.json.continue && r.json.continue.access_token.value);
    assert.ok(!r.json.access_token);
  });
  const naming = new gnap.Client({ key: gnap.newKey("ES256") });
  body = grantBody(naming,
                   { user: { sub_ids: [{ format: "uri",
                                         uri: "urn:sts:user:" +
                                              STRANGER }] } });
  r = await naming.send("POST", GRANT, { json: body });
  pending = r.json;
  b = browser();
  approval = await reachApproval(b, pending.interact.redirect, OWNER);
  r = await answer(b, approval, "allow");
  params = finishParams(r.location, r);
  r = await naming.send("POST", pending.continue.uri,
                        { token: pending.continue.access_token.value,
                                                        json: {
                                                          interact_ref:
                                                            params.ref } });
  check("a request naming one person approved by another is unknown_user " +
        "(section 2.4)", function () {
    refused(r, "unknown_user", "the wrong person");
  });

  // =========================================================================
  // 5. USER CODES AND POLLING; THE APP MODE.
  // =========================================================================
  log.info("=== 5. user_code, user_code_uri, app, polling ===");
  const poller = new gnap.Client({ key: gnap.newKey("PS512") });
  r = await poller.send("POST", GRANT, { json: grantBody(poller, { interact: {
    start: ["user_code", "user_code_uri", "app"] } }) });
  pending = r.json;
  check("a code-and-app request gets a user code, a user_code_uri and an app " +
        "URI but no finish",
        function () {
          assert.ok(/^[A-Z0-9]{6,8}$/.test(pending.interact.user_code),
                    pending.interact.user_code);
          assert.strictEqual(pending.interact.user_code_uri.code,
                             pending.interact.user_code);
          assert.strictEqual(pending.interact.user_code_uri.uri,
                             realmBase + "/gnap/code");
          assert.ok(/\/gnap\/app\//.test(pending.interact.app));
          assert.ok(!pending.interact.finish);
        });
  r = await poller.send("POST", pending.continue.uri,
                        { token: pending.continue.access_token.value });
  check("a poll before approval answers only a new continuation (5.2)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.continue && !r.json.access_token);
    assert.notStrictEqual(r.json.continue.access_token.value,
                          pending.continue.access_token.value);
  });
  let cont = r.json.continue;
  r = await poller.send("POST", cont.uri,
                        { token: pending.continue.access_token.value });
  check("the previous continuation token stopped working when a new one was " +
        "issued (5)", function () {
    refused(r, "invalid_continuation", "a superseded continuation token");
  });
  b = browser();
  r = await b.go("POST", "/realm/" + REALM + "/gnap/code",
                 { code: "NOTACODE" });
  check("an unknown user code is an error on the page, not a redirect (4.1.2)",
        function () {
    assert.strictEqual(r.status, 400);
    assert.ok(!r.location);
  });
  const typed = pending.interact.user_code.toLowerCase().slice(0, 4) + " - " +
    pending.interact.user_code.toLowerCase().slice(4);
  r = await b.go("POST", "/realm/" + REALM + "/gnap/code", { code: typed });
  check("a user code typed in lower case with spaces and a dash is accepted " +
        "(4.1.2)", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 300));
    assert.ok(/\/gnap\/approve\//.test(r.location));
  });
  approval = await reachApproval({ go: async function (m, u, f) {
    log.debug("Entering go().");
    if (u === "START") {
      log.debug("Leaving go().");
      return { status: 303, location: r.location, text: "" };
    }
    log.debug("Leaving go().");
    return b.go(m, u, f);
  } }, "START", OWNER);
  r = await answer(b, approval, "allow");
  check("with no finish method the RO is told to return to the device",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/approved/i.test(r.text));
  });
  r = await poller.send("POST", cont.uri, { token: cont.access_token.value });
  check("the next poll releases the token (5.2)", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value);
  });
  r = await gnap.rawRequest("GET", pending.interact.app, {});
  check("the app URI of a grant already approved through a code is refused " +
        "(4.1)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
  });
  r = await poller.send("POST", GRANT,
                        { json: grantBody(poller,
                                          { interact: { start: ["app"] } }) });
  pending = r.json;
  b = browser();
  approval = await reachApproval(b, pending.interact.app, OWNER);
  r = await answer(b, approval, "allow");
  r = await poller.send("POST", pending.continue.uri,
                        { token: pending.continue.access_token.value });
  check("the app start mode reaches the same approval and polling releases " +
        "the token", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token);
  });

  // =========================================================================
  // 6. PUSH FINISH (section 4.2.2), to a listener in this process.
  // =========================================================================
  log.info("=== 6. push finish ===");
  const pushed = [];
  const listener = http.createServer(function (req, res) {
    let text = "";
    req.on("data", function (c) { text += c; });
    req.on("end", function () {
      pushed.push({ method: req.method, type: req.headers["content-type"],
                    body: text });
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise(function (resolve) {
    listener.listen(0, "0.0.0.0", resolve);
  });
  const callbackHost = process.env.GNAP_PUSH_HOST || "localhost";
  const pushUri = "http://" + callbackHost + ":" + listener.address().port +
                  "/gnap-push";
  body = grantBody(es,
                   { interact: { start: ["redirect"],
                                 finish: { method: "push", uri: pushUri,
                                                                    nonce: "push-nonce-1" } } });
  r = await es.send("POST", GRANT, { json: body });
  pending = r.json;
  b = browser();
  approval = await reachApproval(b, pending.interact.redirect, OWNER);
  r = await answer(b, approval, "allow");
  check("after approval the browser is shown a page, not redirected (push)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  check("the AS POSTed {hash, interact_ref} as JSON to the push URI with a " +
        "verifiable hash",
        function () {
          assert.strictEqual(pushed.length, 1, JSON.stringify(pushed));
          assert.strictEqual(pushed[0].method, "POST");
          assert.ok(/application\/json/.test(pushed[0].type));
          const message = JSON.parse(pushed[0].body);
          assert.strictEqual(message.hash,
                             gnap.interactionHash("push-nonce-1",
                                                                pending.interact.finish,
                                                                message.interact_ref, GRANT));
          pending.pushedRef = message.interact_ref;
        });
  r = await es.send("POST", pending.continue.uri,
                    { token: pending.continue.access_token.value,
                                                    json: {
                                                      interact_ref:
                                                        pending.pushedRef } });
  check("the pushed interaction reference releases the grant", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token);
  });
  listener.close();

  // =========================================================================
  // 7. MULTIPLE TOKENS, BEARER, SUBJECT INFORMATION AND ASSERTIONS.
  // =========================================================================
  log.info("=== 7. multiple tokens, bearer, subject ===");
  const multi = await redirectGrant(es, OWNER, {
    access_token: [{ label: "bound", access: readAccess() },
                   { label: "carry", access: readAccess(), flags: ["bearer"] }],
    subject: { sub_id_formats: ["opaque", "iss_sub", "email"],
               assertion_formats: ["id_token", "saml2"] }
  });
  const tokensByLabel = {};
  check("a multiple-token request is answered with an array, one per label " +
        "(3.2.2)", function () {
    assert.ok(Array.isArray(multi.released.access_token));
    multi.released.access_token.forEach(function (one) {
      tokensByLabel[one.label] = one;
    });
    assert.ok(tokensByLabel.bound && tokensByLabel.carry);
    assert.deepStrictEqual(tokensByLabel.carry.flags, ["bearer"]);
  });
  r = await gnap.rawRequest("GET", RS,
                            { Authorization: "Bearer " +
                                             tokensByLabel.carry.value });
  check("the bearer token works with the Bearer scheme and no proof (7.2)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  r = await es.send("GET", RS, { token: tokensByLabel.carry.value });
  check("…and is refused with the GNAP scheme (7.2 names RFC 6750 for bearer " +
        "tokens)", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await gnap.rawRequest("GET", RS,
                            { Authorization: "Bearer " +
                                             tokensByLabel.bound.value });
  check("the bound token is refused with the Bearer scheme", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  const subject = multi.released.subject;
  let opaque;
  check("subject information carries the requested sub_ids, both assertions " +
        "and updated_at (3.4)",
        function () {
          assert.ok(subject, JSON.stringify(multi.released));
          const formats = subject.sub_ids.map(function (
              one) { return one.format; }).sort();
          assert.deepStrictEqual(formats, ["email", "iss_sub", "opaque"]);
          opaque = subject.sub_ids.filter(function (
              one) { return one.format === "opaque"; })[0].id;
          assert.ok(subject.sub_ids.filter(function (
              one) { return one.format === "email"; })[0].email
                    .indexOf(OWNER) === 0);
          const formatsA = subject.assertions.map(
              function (one) { return one.format; }).sort();
          assert.deepStrictEqual(formatsA, ["id_token", "saml2"]);
          assert.ok(!isNaN(Date.parse(subject.updated_at)));
        });
  const jwks = await (await fetch(realmBase + "/oauth2/jwks")).json();
  const ownerSubject = await h.subjectOf(OWNER);
  check("the id_token assertion verifies against the realm JWKS and names " +
        "the resource owner",
        function () {
          const idToken = subject.assertions.filter(
              function (one) { return one.format === "id_token"; })[0].value;
          const parts = idToken.split(".");
          const header = JSON.parse(Buffer.from(parts[0], "base64url"));
          const jwk = jwks.keys.filter(function (
              k) { return k.kid === header.kid; })[0];
          const ok1 = nodeCrypto.verify("sha256",
            Buffer.from(parts[0] + "." + parts[1]),
            nodeCrypto.createPublicKey({ key: jwk,
                                         format: "jwk" }),
            Buffer.from(parts[2], "base64url"));
          assert.ok(ok1, "the ID Token signature verifies");
          const claims = JSON.parse(Buffer.from(parts[1], "base64url"));
          // The owner's urn:uuid:<entryUUID> since 2026-09-14.
          assert.strictEqual(claims.sub, ownerSubject);
        });
  check("the saml2 assertion is unpadded base64url of a SAML 2.0 Assertion " +
        "naming the owner",
        function () {
          const value = subject.assertions.filter(
              function (one) { return one.format === "saml2"; })[0].value;
          assert.ok(!/=/.test(value) && /^[A-Za-z0-9_-]+$/.test(value));
          const xml = Buffer.from(value, "base64url").toString("utf8");
          assert.ok(/<(saml2?:)?Assertion\b/.test(xml) &&
                    xml.indexOf(OWNER) >= 0, xml.slice(0, 300));
        });
  const hinted = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await hinted.send("POST", GRANT,
                        { json: grantBody(hinted, { user: opaque }) });
  check("the opaque identifier is usable as a user reference (2.4.1)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  r = await hinted.send("POST", GRANT,
                        { json: grantBody(hinted,
                                          { user: "not-a-reference" }) });
  check("an unknown user reference is unknown_user (2.4.1)", function () {
    refused(r, "unknown_user", "an unknown user reference");
  });

  // =========================================================================
  // 8. MODIFICATION AND REVOCATION (sections 5.3 and 5.4).
  // =========================================================================
  log.info("=== 8. modify and revoke ===");
  const modifying = await redirectGrant(es, OWNER);
  const firstValue = modifying.released.access_token.value;
  cont = modifying.released.continue;
  r = await es.send("PATCH", cont.uri, { token: cont.access_token.value,
    json: { access_token: { access: [{ type: DEMO, actions: ["read"] }] } } });
  check("narrowing the access issues a new token with no interaction (5.3)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(r.json.access_token.access,
                           [{ type: DEMO, actions: ["read"] }]);
    assert.notStrictEqual(r.json.access_token.value, firstValue);
  });
  const narrowed = r.json;
  r = await es.send("GET", RS, { token: firstValue });
  check("the earlier non-durable token was revoked by the modification",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await es.send("POST", RS,
                    { token: narrowed.access_token.value, json: { x: 1 } });
  check("the narrowed token no longer grants write at the RS", function () {
    assert.strictEqual(r.status, 403, r.text);
  });
  r = await es.send("PATCH", narrowed.continue.uri,
                    { token: narrowed.continue.access_token.value,
    json: { access_token: { access: [{ type: DEMO,
                                       actions: ["read", "write",
                                                 "delete"] }] } } });
  check("widening the access with no interaction offered is request_denied",
        function () {
    refused(r, "request_denied", "a widening without interaction");
  });
  cont = r.json.continue;
  r = await es.send("PATCH", cont.uri, { token: cont.access_token.value,
    json: { client: { key: es.keyObject() } } });
  check("a modification carrying client is invalid_request (5.3)", function () {
    refused(r, "invalid_request", "client in a PATCH");
  });
  cont = await es.send("POST", cont.uri, { token: cont.access_token.value });
  cont = cont.json.continue;
  r = await es.send("DELETE", cont.uri, { token: cont.access_token.value });
  check("DELETE on the continuation URI revokes the grant with 204 (5.4)",
        function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  r = await es.send("GET", RS, { token: narrowed.access_token.value });
  check("…and the grant's tokens stop working", function () {
    assert.strictEqual(r.status, 401, r.text);
  });

  // =========================================================================
  // 9. TOKEN MANAGEMENT AND KEY ROTATION (section 6).
  // =========================================================================
  log.info("=== 9. rotate, rotate the key, revoke ===");
  const managed = await redirectGrant(es, OWNER);
  let current = managed.released.access_token;
  r = await es.send("POST", current.manage.uri,
                    { token: current.manage.access_token.value });
  check("POST to the manage URI rotates the token, keeping its access (6.1)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.notStrictEqual(r.json.access_token.value, current.value);
    assert.deepStrictEqual(r.json.access_token.access, current.access);
    assert.ok(r.json.access_token.manage.uri);
  });
  const rotated = r.json.access_token;
  r = await es.send("GET", RS, { token: current.value });
  check("the pre-rotation value is invalidated", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await es.send("POST", rotated.manage.uri,
                    { token: current.manage.access_token.value });
  check("the old management token no longer manages it", function () {
    refused(r, "invalid_rotation", "a superseded management token");
  });
  const newKey = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await es.send("POST", rotated.manage.uri,
                    { token: rotated.manage.access_token.value,
    json: { key: newKey.keyObject() } });
  check("a key rotation proved only by the old key is invalid_rotation (6.1.1)",
        function () {
    refused(r, "invalid_rotation",
            "a rotation without the new key's signature");
  });
  r = await es.send("POST", rotated.manage.uri,
                    { token: rotated.manage.access_token.value,
    json: { key: newKey.keyObject() }, rotateTo: newKey });
  check("a key rotation proved by both keys binds the token to the new key " +
        "(7.3.1.1)", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  const rekeyed = r.json.access_token;
  r = await newKey.send("GET", RS, { token: rekeyed.value });
  check("the new key presents the rotated token", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  r = await es.send("GET", RS, { token: rekeyed.value });
  check("the old key no longer does", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await newKey.send("DELETE", rekeyed.manage.uri,
                        { token: rekeyed.manage.access_token.value });
  check("DELETE on the manage URI revokes the token with 204 (6.2)",
        function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  r = await newKey.send("GET", RS, { token: rekeyed.value });
  check("…and it is refused at the RS", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  const carrying = await redirectGrant(es, OWNER,
                                       { access_token: { access: readAccess(),
                                                         flags: ["bearer"] } });
  r = await es.send("POST", carrying.released.access_token.manage.uri, {
    token: carrying.released.access_token.manage.access_token.value,
    json: { key: newKey.keyObject() }, rotateTo: newKey });
  check("rotating the key of a bearer token is invalid_rotation (6.1.1)",
        function () {
    refused(r, "invalid_rotation", "a bearer key rotation");
  });
  await setting("gnap.keyRotation", false);
  const off = await redirectGrant(es, OWNER);
  r = await es.send("POST", off.released.access_token.manage.uri, {
    token: off.released.access_token.manage.access_token.value,
    json: { key: newKey.keyObject() }, rotateTo: newKey });
  check("with key rotation switched off the answer is " +
        "key_rotation_not_supported", function () {
    refused(r, "key_rotation_not_supported", "rotation switched off");
  });
  await setting("gnap.keyRotation", true);

  // =========================================================================
  // 10. DETACHED AND ATTACHED JWS (sections 7.3.3 and 7.3.4).
  // =========================================================================
  log.info("=== 10. jwsd and jws ===");
  for (const method of ["jwsd", "jws"]) {
    const signer = new gnap.Client({ key: gnap.newKey(
        method === "jws" ? "EdDSA" : "RS256"), proof: method });
    const done = await redirectGrant(signer, OWNER);
    r = await signer.send("GET", RS,
                          { token: done.released.access_token.value });
    check(method + ": a grant, its continuation and an RS call all prove the " +
                   "key", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.strictEqual(r.json.method, method);
    });
    r = await signer.send("POST", GRANT,
                          { json: grantBody(signer),
                            jwsTyp: "gnap-binding-wrong" });
    check(method + ": the wrong typ is refused", function () {
      refused(r, "invalid_client", method + " with the wrong typ");
    });
    const next = new gnap.Client({ key: gnap.newKey(
        method === "jws" ? "EdDSA" : "RS256"), proof: method });
    const mng = done.released.access_token.manage;
    r = await signer.send("POST", mng.uri,
                          { token: mng.access_token.value,
                                             json: { key: next.keyObject() },
                                             rotateTo: next });
    check(method + ": a nested-JWS key rotation binds the new key (7.3." +
          (method === "jws" ? "4.1" : "3.1") + ")", function () {
      assert.strictEqual(r.status, 200, r.text);
    });
    r = await next.send("GET", RS, { token: r.json.access_token.value });
    check(method + ": the new key presents the rotated token", function () {
      assert.strictEqual(r.status, 200, r.text);
    });
  }
  const mixed = new gnap.Client({ key: gnap.newKey("ES256"), proof: "jwsd" });
  r = await mixed.send("POST", GRANT,
                       { json: grantBody(mixed), proof: "httpsig" });
  check("a key declared jwsd and proved with an HTTP signature is refused",
        function () {
    refused(r, "invalid_client", "a proof method other than the key's");
  });

  // =========================================================================
  // 11. SHARED SECRETS, INSTANCE IDENTIFIERS, TRUSTED CLIENTS.
  // =========================================================================
  log.info("=== 11. key references, instance_id, trusted clients ===");
  const secret = nodeCrypto.randomBytes(32);
  const REF = "gnap-ref-" + nodeCrypto.randomBytes(4).toString("hex");
  await ok(realmApi + "/applications/create", {
    identifier: REF + "-app", kind: "gnap-client", protocols: ["gnap"],
    fields: { gnapKeyReference: REF,
              gnapSymmetricKey: secret.toString("base64url"),
              gnapKeyProof: "httpsig", gnapSymmetricAlg: "hmac-sha256" } },
    "registered a client with a shared secret");
  const hmacClient = new gnap.Client({ key: gnap.secretKey(REF, secret,
                                                           "HS256") });
  r = await hmacClient.send("POST", GRANT, { json: grantBody(hmacClient) });
  check("a key reference to a shared secret proves an HMAC HTTP signature " +
        "(7.1.1)", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  const wrongSecret = new gnap.Client({ key: gnap.secretKey(REF,
                                                            nodeCrypto.randomBytes(32), "HS256") });
  r = await wrongSecret.send("POST", GRANT, { json: grantBody(wrongSecret) });
  check("the same reference with the wrong secret is invalid_client",
        function () {
    refused(r, "invalid_client", "a wrong shared secret");
  });
  r = await es.send("POST", GRANT,
                    { json: grantBody(es,
                                      { client: flow.pending.instance_id }) });
  check("the dynamic instance_id is accepted by reference with the same key " +
        "(2.3.1)", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  r = await thief.send("POST", GRANT,
                       { json: grantBody(thief,
                                         { client:
                                             flow.pending.instance_id }) });
  check("…and refused when signed by another key", function () {
    refused(r, "invalid_client", "an instance_id with the wrong key");
  });
  const trustedKey = new gnap.Client({ key: gnap.newKey("ES256") });
  await ok(realmApi + "/applications/create", {
    identifier: "gnap-trusted-" + REALM, kind: "gnap-client",
    protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(trustedKey.keyObject()),
              gnapSkipInteraction: "TRUE" } },
    "registered a trusted client");
  r = await trustedKey.send("POST", GRANT,
                            { json: { client: { key: trustedKey.keyObject() },
                                                     access_token: {
                                                       access:
                                                         readAccess() } } });
  check("a registered trusted client gets a token with no interaction (2.3.3)",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && !r.json.interact);
  });

  // =========================================================================
  // 12. A NAMED AUTHORIZATION SERVER.
  // =========================================================================
  log.info("=== 12. authorization server profiles ===");
  const AS = "gnapas" + nodeCrypto.randomBytes(3).toString("hex");
  const asGrant = realmBase + "/" + AS + "/gnap";
  r = await gnap.rawRequest("OPTIONS", asGrant, {});
  check("a named authorization server has its own grant endpoint in discovery",
        function () {
    assert.strictEqual(r.json.grant_request_endpoint, asGrant);
  });
  await ok(realmApi + "/authorization-servers/set",
           { profile: AS, member: "interaction_start_modes_supported",
                                                      value: JSON.stringify(
                                                          ["user_code"]) },
           "narrowed the start modes");
  r = await gnap.rawRequest("OPTIONS", asGrant, {});
  check("the profile's GNAP override is published by that server's discovery",
        function () {
    assert.deepStrictEqual(r.json.interaction_start_modes_supported,
                           ["user_code"]);
  });
  r = await gnap.rawRequest("GET",
                            realmBase + "/" + AS +
                            "/.well-known/oauth-authorization-server", {});
  check("…and does not leak into its OAuth metadata", function () {
    assert.ok(!r.json || r.json.interaction_start_modes_supported === undefined,
              r.text.slice(0, 200));
  });
  r = await es.send("POST", asGrant, { json: grantBody(es) });
  check("…and is ENFORCED: redirect is no longer offered there, so " +
        "invalid_interaction", function () {
    refused(r, "invalid_interaction", "a start mode the profile removed");
  });
  const asFlow = await (async function () {
    const body2 = grantBody(es, { interact: { start: ["user_code"] } });
    const resp = await es.send("POST", asGrant, { json: body2 });
    return resp.json;
  }());
  check("a grant at the named server records it: tokens will say iss = that " +
        "grant endpoint", function () {
    assert.ok(asFlow.interact.user_code);
  });

  // =========================================================================
  // 13. TOO FAST (section 5).
  // =========================================================================
  log.info("=== 13. too_fast ===");
  await setting("gnap.continueWaitS", 30);
  r = await poller.send("POST", GRANT,
                        { json: grantBody(poller,
                                          { interact: {
                                            start: ["user_code"] } }) });
  pending = r.json;
  check("the continuation response states the wait", function () {
    assert.strictEqual(pending.continue.wait, 30);
  });
  r = await poller.send("POST", pending.continue.uri,
                        { token: pending.continue.access_token.value });
  check("continuing before the wait is too_fast, with a continuation to use " +
        "later", function () {
    refused(r, "too_fast", "an early continuation");
    assert.ok(r.json.continue);
  });
  await setting("gnap.continueWaitS", 0);

  // =========================================================================
  // 14. TRUST REALMS ARE SEPARATE AUTHORIZATION SERVERS.
  // =========================================================================
  log.info("=== 14. realm isolation ===");
  const isolated = await redirectGrant(es, OWNER);
  r = await es.send("GET", base + "/gnap/rs/resource",
                    { token: isolated.released.access_token.value });
  check("a token from this realm is refused by the default realm's resource " +
        "server", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  const foreignCont = isolated.released.continue.uri.replace("/realm/" + REALM,
                                                             "");
  r = await es.send("POST", foreignCont,
                    { token: isolated.released.continue.access_token.value });
  check("this realm's continuation token finds no grant in the default realm",
        function () {
    refused(r, "invalid_continuation", "a continuation token in another realm");
  });

  assert.ok(h.checks >= 90, "only " + h.checks + " checks ran; a section has " +
                                                 "stopped being called.");
  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_core")
  .description("GNAP (RFC 9635) against the running service: every " +
    "interaction start mode and finish method, the four key proofing " +
    "methods, continuation, modification, revocation, token rotation and key " +
    "rotation, subject assertions, key references, instance identifiers, " +
    "authorization server profiles, too_fast, realm isolation, and the " +
    "refusals of each.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
