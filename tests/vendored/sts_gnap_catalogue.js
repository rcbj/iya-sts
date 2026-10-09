// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_catalogue.js
//
// ---------------------------------------------------------------------------
// ONE ACCESS-TYPE CATALOGUE FOR GNAP AND RFC 9396, AND EACH GNAP ACCESS RIGHT
// A QUESTION TO THE ISSUANCE POLICY, OVER HTTP (#432 PHASES 4 AND 3), in
// whichever mode the service is in.
//
//   0. THE CATALOGUE through the management API: `set-access-type` on two
//      resource servers (a payment type with values, a limits schema,
//      `bearer: false`, `maxLifetimeS` and `introspectionClaims`; a refund
//      type `derivableFrom` it; another resource server's type), read back
//      off the entry; a definition that does not read refused.
//   1. A DECLARED TYPE ACCEPTED: a grant for it, the token capped at the
//      type's lifetime and audienced to the type's owner.
//   2. INTROSPECTION PER RESOURCE SERVER: each sees its own type's rights
//      only, and the person's `email` its type declares.
//   3. THE CATALOGUE'S REFUSALS: a bearer token for the payment type
//      (request_denied), an action it does not list, limits its schema
//      refuses and limits on a type that declares none (invalid_request).
//   4. AN UNDECLARED TYPE: refused request_denied in product, granted in
//      development.
//   5. DERIVATION INTO A `derivableFrom` TYPE (RFC 9767 section 4): the
//      payment resource server derives a refund right for the downstream
//      one; a type that is not derivable is refused.
//   6. RFC 9396 READS THE SAME CATALOGUE: at `/oauth2/token`, a detail of the
//      payment type in a bearer token refused, an action the type does not
//      list refused, the quota type's lifetime capping the token, and the
//      owning resource server's RFC 9701 introspection.
//   7. A NARROWED RIGHT: a realm's own issuance policy (imported as ALFA)
//      takes `refund` off the payment type; the approval page says what was
//      narrowed and the token carries the rest.
//   8. A TYPE'S acr HOLDS FOR RFC 9396 TOO (#432 phase 6): an authorization
//      code flow for a type needing acr 1 granted on a password session,
//      the ID Token's acr the one met; a type needing mfa sending the same
//      session to sign in again, and refused
//      unmet_authentication_requirements on the way back; client
//      credentials refused a type needing any acr. And LIMITS ON A DETAIL
//      (#432 phase 5): the consent screen drawing a limit as a control and
//      refusing a raised one, the access token carrying the lowered value
//      and a grant_id (read off the token by this job), a refresh keeping
//      the same grant_id, introspection returning it, and a detail with no
//      limits carrying none.
//
// The in-process half, with each built-in rule in both modes, is
// `tests/gnap_catalogue.js`. Everything runs in a THROWAWAY TRUST REALM that
// is left behind.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");
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
var log = bunyan.createLogger({ name: "sts_gnap_catalogue",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const PASSWORD = "gnap-cat-Passw0rd!-" + String(Date.now()).slice(-6);
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnapcat").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: PASSWORD,
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-cat-owner");
const PAY = "cat-payment";
const REFUND = "cat-refund";
const OTHER = "cat-other";
const QUOTA = "cat-quota";
const PAY_URI = "https://pay.cat.test/api";
const OTHER_URI = "https://other.cat.test/api";

// THE NARROWING POLICY (section 7), as ALFA this service's own emitter wrote
// for the same model (`xacml/xacml_alfa.ts`): one Permit rule targeted at
// `issue-gnap-right` for the payment type carrying the gnap-right obligation
// (verdict narrow, drop the action `refund`), and a catch-all Permit so every
// other question in this throwaway realm is answered by the built-in rules
// beside it (a Permit with no obligation says nothing about a right).
function narrowingAlfa(type) {
  log.debug("Entering narrowingAlfa().");
  log.debug("Leaving narrowingAlfa().");
  return "namespace stsMock {\n" +
    "    attribute actionId {\n        category = actionCat\n" +
    "        id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"\n" +
    "        type = string\n    }\n" +
    "    attribute resourceId {\n        category = resourceCat\n" +
    "        id = \"urn:oasis:names:tc:xacml:1.0:resource:resource-id\"\n" +
    "        type = string\n    }\n\n" +
    "    policy gnapNarrow {\n" +
    "        id = \"urn:sts:test:gnap-narrow\"\n" +
    "        version = \"1.0\"\n" +
    "        description = \"A realm issuance policy that narrows the " +
    "payment type\"\n" +
    "        apply orderedDenyOverrides\n" +
    "        rule narrowPayment {\n            permit\n" +
    "            target clause actionId == \"issue-gnap-right\"\n" +
    "            target clause resourceId == \"" + type + "\"\n" +
    "            on permit {\n" +
    "                obligation \"urn:sts:xacml:obligation:gnap-right\" {\n" +
    "                    \"urn:sts:xacml:gnap-right-verdict\" = \"narrow\"\n" +
    "                    \"urn:sts:xacml:gnap-right-drop-action\" = " +
    "\"refund\"\n" +
    "                }\n            }\n        }\n" +
    "        rule everythingElse {\n            permit\n        }\n" +
    "    }\n}\n";
}

function claimsOf(value) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(value).split(".")[1], "base64url")
                          .toString("utf8"));
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the access-type catalogue at " + h.realmBase);
  const PRODUCT = await registry.isProduct(base);
  log.info("The service is in " + (PRODUCT ? "product" : "development") +
           " mode.");
  await h.createRealm("GNAP access-type catalogue");
  await h.setting("gnap.continueWaitS", 0);
  await h.ensurePerson(OWNER);

  // =========================================================================
  // 0. THE CATALOGUE, THROUGH /admin-api.
  // =========================================================================
  log.info("=== 0. the catalogue ===");
  const id = function (name) {
    log.debug("Entering id().");
    log.debug("Leaving id().");
    return name + "-" + h.realm;
  };
  const RS = id("cat-pay-rs");
  const RS2 = id("cat-other-rs");
  const keys = {};
  const register = async function (identifier, uri, fields) {
    log.debug("Entering register().");
    keys[identifier] = new gnap.Client({ key: gnap.newKey("ES256") });
    await h.ok(h.realmApi + "/applications/create", {
      identifier: identifier, kind: "gnap-resource-server",
      protocols: ["gnap", "oauth2"],
      fields: Object.assign({ gnapKey: JSON.stringify(
        keys[identifier].keyObject()), gnapResourceServerUri: uri },
                            fields || {}) },
               "registered " + identifier);
    log.debug("Leaving register().");
  };
  const rsSecret = "cat-rs-" + nodeCrypto.randomBytes(18).toString("base64url");
  await register(RS2, OTHER_URI);
  await register(RS, PAY_URI, { appAllowedToDelegateTo: [RS2],
                                oauthClientId: [RS], oauthClientSecret: rsSecret,
                                oauthTokenEndpointAuthMethod:
                                  "client_secret_post" });
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS, type: PAY, description: "Initiate and track a payment",
    actions: ["initiate", "status", "refund"],
    requiredMembers: ["actions"],
    bearer: false, maxLifetimeS: 120, introspectionClaims: ["email"],
    limits: { type: "object",
              // #432 phase 5: an amount is in a currency, beside it.
              properties: { amount: { type: "number", minimum: 0 },
                            currency: { type: "string" } },
              required: ["amount"], additionalProperties: false } },
             "declared the payment type");
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS, type: QUOTA, maxLifetimeS: 90 },
             "declared the quota type");
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS2, type: REFUND, actions: "issue\nstatus",
    derivableFrom: [PAY] }, "declared the refund type");
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS2, type: OTHER, introspectionClaims: ["email"] },
             "declared the other type");
  let r = await h.apiGet(h.realmApi + "/applications?application=" +
                         encodeURIComponent(RS));
  check("0a. the definitions are on the entry, read back by the API",
        function () {
    const values = [].concat((r.body.attributes || {})
      .oauthAuthorizationDetailsType || []);
    const pay = values.map(function (one) {
      return JSON.parse(one);
    }).filter(function (one) { return one.type === PAY; })[0];
    assert.ok(pay, String(r.raw).slice(0, 400));
    assert.strictEqual(pay.bearer, false);
    assert.strictEqual(pay.maxLifetimeS, 120);
  });
  const refusedSet = await h.apiPost(h.realmApi +
                                     "/applications/set-access-type", {
    application: RS, type: "cat-broken", limits: { anyOf: [] } });
  check("0b. a definition outside the grammar is refused, with the reason",
        function () {
    assert.strictEqual(refusedSet.status, 400, refusedSet.raw);
    assert.ok(/anyOf/.test(refusedSet.raw), refusedSet.raw);
  });

  // =========================================================================
  // 1. A DECLARED TYPE ACCEPTED.
  // =========================================================================
  log.info("=== 1. a declared type ===");
  const client = new gnap.Client({ key: gnap.newKey("ES256") });
  const payRight = { type: PAY, actions: ["status", "initiate"],
                     limits: { amount: 25, currency: "EUR" } };
  const both = await h.redirectGrant(client, OWNER, {
    access_token: { access: [payRight, { type: OTHER }] } });
  const token = both.released.access_token;
  check("1a. a grant of the declared types is released", function () {
    assert.ok(token && token.value, JSON.stringify(both.released));
  });
  check("1b. the token lives no longer than the payment type's " +
        "maxLifetimeS", function () {
    assert.ok(Number(token.expires_in) <= 120, String(token.expires_in));
  });
  check("1c. it is audienced to each type's owning resource server", function () {
    const aud = [].concat(claimsOf(token.value).aud || []);
    assert.ok(aud.indexOf(RS) >= 0 && aud.indexOf(RS2) >= 0,
              JSON.stringify(aud));
  });

  // =========================================================================
  // 2. INTROSPECTION, PER RESOURCE SERVER.
  // =========================================================================
  log.info("=== 2. introspection per resource server ===");
  const introspect = function (who, value) {
    log.debug("Entering introspect().");
    log.debug("Leaving introspect().");
    return keys[who].send("POST", h.realmBase + "/gnap/introspect", { json: {
      access_token: value, resource_server: { key: keys[who].keyObject() } } });
  };
  r = await introspect(RS, token.value);
  check("2a. the payment resource server sees its own type only, and the " +
        "person's email", function () {
    assert.strictEqual(r.json.active, true, r.text);
    const types = (r.json.access || []).map(function (one) {
      return one.type;
    });
    assert.deepStrictEqual(types, [PAY], r.text);
    assert.strictEqual(r.json.email, OWNER + "@gnap.test", r.text);
  });
  r = await introspect(RS2, token.value);
  check("2b. the other resource server sees its own type only", function () {
    assert.strictEqual(r.json.active, true, r.text);
    const types = (r.json.access || []).map(function (one) {
      return one.type;
    });
    assert.deepStrictEqual(types, [OTHER], r.text);
  });

  // =========================================================================
  // 3. THE CATALOGUE'S REFUSALS.
  // =========================================================================
  log.info("=== 3. the catalogue's refusals ===");
  const ask = function (access, flags) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return client.send("POST", h.GRANT, { json: h.grantBody(client, {
      access_token: Object.assign({ access: access },
                                  flags ? { flags: flags } : {}) }) });
  };
  r = await ask([payRight], ["bearer"]);
  check("3a. a bearer token for a type declaring bearer: false", function () {
    h.refused(r, "request_denied", "a bearer payment token");
  });
  r = await ask([{ type: PAY, actions: ["delete"] }]);
  check("3b. an action the type does not list", function () {
    h.refused(r, "invalid_request", "an undeclared action");
  });
  r = await ask([{ type: PAY, actions: ["status"],
                   limits: { amount: -5 } }]);
  check("3c. limits the type's limits schema refuses", function () {
    h.refused(r, "invalid_request", "a negative amount");
  });
  r = await ask([{ type: OTHER, limits: { amount: 1 } }]);
  check("3d. limits on a type that declares no limits schema", function () {
    h.refused(r, "invalid_request", "limits on the other type");
  });

  // =========================================================================
  // 4. AN UNDECLARED TYPE.
  // =========================================================================
  log.info("=== 4. an undeclared type ===");
  r = await ask([{ type: "cat-nobody-declares-this", actions: ["read"] }]);
  if (PRODUCT) {
    check("4. product: an undeclared type is refused", function () {
      h.refused(r, "request_denied", "an undeclared type");
    });
  } else {
    check("4. development: an undeclared type is granted as asked",
          function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.ok(r.json.interact, r.text);
    });
  }

  // =========================================================================
  // 5. DERIVATION INTO A derivableFrom TYPE.
  // =========================================================================
  log.info("=== 5. derivation ===");
  const payOnly = await h.redirectGrant(client, OWNER, {
    access_token: { access: [payRight] } });
  const original = payOnly.released.access_token.value;
  const derive = function (access) {
    log.debug("Entering derive().");
    log.debug("Leaving derive().");
    return keys[RS].send("POST", h.GRANT, { json: {
      client: { key: keys[RS].keyObject() },
      existing_access_token: original,
      access_token: { access: access } } });
  };
  r = await derive([{ type: REFUND, actions: ["issue"] }]);
  check("5a. the payment resource server derives a refund right — a type " +
        "declared derivable from the payment type — for its owner",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    const claims = claimsOf(r.json.access_token.value);
    assert.deepStrictEqual([].concat(claims.aud), [RS2],
                           JSON.stringify(claims));
    // #526: the act chain follows RFC 8693's rules — the deriving resource
    // server as a client of the grant endpoint, the original client at the
    // foot, each entry naming its issuer.
    assert.ok(claims.act && typeof claims.act === "object",
              JSON.stringify(claims));
    assert.strictEqual(claims.act.sub, "urn:sts:client:" + RS,
                       JSON.stringify(claims.act));
    assert.ok(/\/gnap$/.test(String(claims.act.iss)),
              JSON.stringify(claims.act));
    // Every entry carries the GNAP authorization server's issuer, the
    // token's own `iss`, and the foot names the client the original token
    // was issued to — exactly, read off that token's own `client_id`.
    assert.strictEqual(claims.act.iss, claims.iss,
                       "each entry's iss is the token's own: " +
                       JSON.stringify(claims));
    assert.ok(claims.act.act &&
              claims.act.act.sub === "urn:sts:client:" +
                claimsOf(original).client_id &&
              claims.act.act.iss === claims.iss &&
              claims.act.act.act === undefined,
              "the original client at the foot: " +
              JSON.stringify(claims.act));
    assert.strictEqual(claims.access[0].type, REFUND);
  });
  r = await derive([{ type: OTHER }]);
  check("5b. a type that declares nothing derivable is refused", function () {
    h.refused(r, "request_denied", "a non-derivable type");
  });

  // =========================================================================
  // 6. RFC 9396 READS THE SAME CATALOGUE.
  // =========================================================================
  log.info("=== 6. RFC 9396 ===");
  const OAUTH = id("cat-oauth");
  const oauthSecret = "cat-oauth-" +
                      nodeCrypto.randomBytes(18).toString("base64url");
  await h.ok(h.realmApi + "/applications/create", {
    identifier: OAUTH, kind: "oauth2-client", protocols: ["oauth2"],
    fields: { oauthClientId: [OAUTH], oauthClientSecret: oauthSecret,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"] } },
             "registered the OAuth client");
  const tokenRequest = async function (details) {
    log.debug("Entering tokenRequest().");
    const res = await fetch(h.realmBase + "/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: OAUTH, client_secret: oauthSecret,
        authorization_details: JSON.stringify(details) }).toString() });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in tokenRequest(): " + ((e && e.message) || e));
      // Not JSON: the assertion prints the text.
      json = null;
    }
    log.debug("Leaving tokenRequest().");
    return { status: res.status, json: json, text: text };
  };
  r = await tokenRequest([{ type: PAY, actions: ["status"] }]);
  check("6a. a detail of a type refusing bearer, in a bearer token, is " +
        "invalid_authorization_details", function () {
    assert.strictEqual(r.status, 400, r.text);
    assert.strictEqual(r.json.error, "invalid_authorization_details", r.text);
  });
  r = await tokenRequest([{ type: REFUND, actions: ["delete"] }]);
  check("6b. an action the type does not list is " +
        "invalid_authorization_details", function () {
    assert.strictEqual(r.status, 400, r.text);
    assert.strictEqual(r.json.error, "invalid_authorization_details", r.text);
  });
  r = await tokenRequest([{ type: QUOTA }]);
  check("6c. the quota type's maxLifetimeS caps the access token",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(Number(r.json.expires_in) <= 90, r.text);
  });
  const quotaToken = r.json && r.json.access_token;
  r = await fetch(h.realmBase + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/token-introspection+jwt" },
    body: new URLSearchParams({ token: String(quotaToken || ""),
                                client_id: RS,
                                client_secret: rsSecret }).toString() });
  const introspected = await r.text();
  check("6d. the owning resource server's RFC 9701 introspection carries " +
        "its own type's details", function () {
    assert.strictEqual(r.status, 200, introspected);
    const answer = claimsOf(introspected).token_introspection || {};
    assert.strictEqual(answer.active, true, JSON.stringify(answer));
    assert.deepStrictEqual((answer.authorization_details || [])
      .map(function (one) { return one.type; }), [QUOTA],
                           JSON.stringify(answer));
  });

  // =========================================================================
  // 7. A NARROWED RIGHT, BY THE REALM'S OWN POLICY.
  // =========================================================================
  log.info("=== 7. a narrowed right ===");
  await h.ok(h.realmApi + "/xacml/import-alfa", {
    name: "cat-narrow", alfa: narrowingAlfa(PAY) },
             "imported the narrowing policy");
  await h.setting("xacml.issuancePolicy", "cat-narrow");
  const fresh = new gnap.Client({ key: gnap.newKey("ES256") });
  const body = h.grantBody(fresh, { access_token: { access: [
    { type: PAY, actions: ["status", "refund"],
      limits: { amount: 3, currency: "EUR" } }] } });
  r = await fresh.send("POST", h.GRANT, { json: body });
  check("7a. the grant request is accepted", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  const pending = r.json;
  const b = h.browser();
  const approval = await h.reachApproval(b, pending.interact.redirect, OWNER);
  check("7b. the approval page says what the policy narrowed", function () {
    assert.ok(/narrowed what the application asked for/.test(
      approval.page.text), approval.page.text.slice(0, 600));
    assert.ok(/actions refund/.test(approval.page.text),
              approval.page.text.slice(0, 600));
  });
  r = await h.answer(b, approval, "allow");
  const finished = h.finishParams(r.location, r);
  r = await fresh.send("POST", pending.continue.uri, {
    token: pending.continue.access_token.value,
    json: { interact_ref: finished.ref } });
  check("7c. the token carries the right without the narrowed action",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    const access = r.json.access_token.access;
    assert.deepStrictEqual(access[0].actions, ["status"], r.text);
  });
  await h.setting("xacml.issuancePolicy", "role-issuance");

  // =========================================================================
  // 8. A TYPE'S acr AT THE OAUTH AUTHORIZATION ENDPOINT (#432 phase 6).
  // =========================================================================
  log.info("=== 8. a type's acr for RFC 9396 ===");
  const ONE = "cat-acr-one";
  const STRONG = "cat-acr-mfa";
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS2, type: ONE, acr: "1" }, "declared the acr-1 type");
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS2, type: STRONG, acr: "mfa" }, "declared the mfa type");
  const RP = id("cat-rp");
  const RP_REDIRECT = "https://rp.cat.test/cb";
  const rpSecret = "cat-rp-" + nodeCrypto.randomBytes(18).toString("base64url");
  await h.ok(h.realmApi + "/applications/create", {
    // OpenID Connect too: the flow asks `openid`, and product refuses
    // issuance through a protocol family the application does not declare.
    identifier: RP, kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [RP], oauthClientSecret: rpSecret,
              oauthRedirectUri: [RP_REDIRECT],
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["authorization_code", "client_credentials",
                               "refresh_token"] } },
             "registered the relying party");
  const rp = h.browser();
  const authorizeUrl = function (details, extra) {
    log.debug("Entering authorizeUrl().");
    log.debug("Leaving authorizeUrl().");
    return h.realmBase + "/oauth2/authorize?" + new URLSearchParams(
      Object.assign({ response_type: "code", client_id: RP,
                      redirect_uri: RP_REDIRECT, scope: "openid",
                      state: "s-" + nodeCrypto.randomBytes(4).toString("hex"),
                      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSs" +
                                      "tw-cM",
                      code_challenge_method: "S256",
                      authorization_details: JSON.stringify(details) },
                    extra || {})).toString();
  };
  // Sign-in and consent until the relying party's redirect URI, or the first
  // page that is neither.
  // `lowering`, where given, is added to the consent form's Allow — the
  // limit controls a person changed (#432 phase 5).
  const follow = async function (first, lowering) {
    log.debug("Entering follow().");
    let res = first;
    for (let hop = 0; hop < 14; hop++) {
      if (res.status === 302 || res.status === 303) {
        if (res.location.indexOf(RP_REDIRECT) === 0) {
          break;
        }
        res = await rp.go("GET", res.location);
        continue;
      }
      const authnId = (res.text.match(/name="authn_id" value="([^"]+)"/) ||
                       [])[1];
      if (res.status === 200 && authnId) {
        res = await rp.go("POST", "/realm/" + h.realm + "/authn/login",
                          { authn_id: authnId, username: OWNER,
                            password: PASSWORD, action: "login",
                            csrf_token: h.csrfOf(res.text) });
        continue;
      }
      const consentAction = (res.text.match(
        /<form method="post" action="([^"]*oauth2\/consent[^"]*)"/) || [])[1];
      if (res.status === 200 && consentAction) {
        const form = {};
        (res.text.match(/<input type="hidden"[^>]*>/g) || [])
          .forEach(function (tag) {
            const name = /name="([^"]+)"/.exec(tag);
            const value = /value="([^"]*)"/.exec(tag);
            if (name) {
              form[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
            }
          });
        form.action = "allow";
        Object.assign(form, lowering || {});
        res = await rp.go("POST", consentAction.replace(/&amp;/g, "&"), form);
        continue;
      }
      break;
    }
    log.debug("Leaving follow().");
    return res;
  };
  r = await follow(await rp.go("GET", authorizeUrl([{ type: ONE }])));
  const issuedCode = new URL(r.location || "https://x/").searchParams
    .get("code");
  check("8a. a type needing acr 1 is authorized on a password session",
        function () {
    assert.ok(issuedCode, r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
  });
  r = await fetch(h.realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: String(issuedCode || ""), redirect_uri: RP_REDIRECT,
      client_id: RP, client_secret: rpSecret,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" })
      .toString() });
  const issuedText = await r.text();
  check("8b. the ID Token carries the acr the session met", function () {
    assert.strictEqual(r.status, 200, issuedText);
    assert.strictEqual(claimsOf(JSON.parse(issuedText).id_token).acr, "1",
                       issuedText);
  });
  r = await rp.go("GET", authorizeUrl([{ type: ONE }, { type: STRONG }]));
  check("8c. a second type needing mfa sends the same session to sign in " +
        "again: every type's acr is required", function () {
    assert.ok((r.status === 302 || r.status === 303) &&
              /\/authn\/login/.test(r.location), r.status + " " + r.location);
  });
  r = await rp.go("GET", authorizeUrl([{ type: STRONG }],
                                      { acr_values: "1",
                                        step_up_honoured: "1" }));
  check("8d. back still short of it: unmet_authentication_requirements, " +
        "with acr_values met", function () {
    assert.ok(/error=unmet_authentication_requirements/.test(r.location),
              r.status + " " + r.location);
  });
  r = await fetch(h.realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: RP, client_secret: rpSecret,
      authorization_details: JSON.stringify([{ type: ONE }]) }).toString() });
  const ccText = await r.text();
  check("8e. client credentials meet no type's acr", function () {
    assert.strictEqual(r.status, 400, ccText);
    assert.strictEqual(JSON.parse(ccText).error,
                       "invalid_authorization_details", ccText);
  });

  // =========================================================================
  // 8f–8k. LIMITS ON AN RFC 9396 DETAIL (#432 phase 5): lowered on the
  // consent screen, a raise refused there, and the access token carrying
  // the lowered values with a grant_id that every refresh keeps and
  // introspection returns — the key a resource server counts under.
  // =========================================================================
  log.info("=== 8f. limits on an RFC 9396 detail ===");
  const LIMITED = "cat-limited";
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS2, type: LIMITED, actions: ["spend"],
    limits: JSON.stringify({ type: "object",
      properties: { amount: { type: "string" },
                    currency: { type: "string" },
                    count: { type: "integer", minimum: 0 } },
      additionalProperties: false }) }, "declared the limited type");
  const asked = [{ type: LIMITED, actions: ["spend"],
                   limits: { amount: "50", currency: "EUR", count: 3 } }];
  // A FRESH PKCE pair per authorization: RFC 9700 mode (product) refuses a
  // code_challenge reused after its code was redeemed, and 8a's is.
  const pkce = function () {
    log.debug("Entering pkce().");
    const verifier = nodeCrypto.randomBytes(32).toString("base64url");
    log.debug("Leaving pkce().");
    return { verifier: verifier,
             challenge: nodeCrypto.createHash("sha256").update(verifier)
               .digest("base64url") };
  };
  const pkceExtra = function (pair) {
    log.debug("Entering pkceExtra().");
    log.debug("Leaving pkceExtra().");
    return { code_challenge: pair.challenge };
  };
  const refusedPair = pkce();
  const consentPage = await follow(await rp.go("GET",
    authorizeUrl(asked, pkceExtra(refusedPair))), { "lim_t0r0_amount": "80" });
  check("8f. the consent screen refuses a RAISED limit", function () {
    assert.strictEqual(consentPage.status, 400,
                       String(consentPage.text).slice(0, 300));
    assert.ok(/lowered/.test(consentPage.text),
              String(consentPage.text).slice(0, 400));
  });
  // Drawn: the screen shows the limit as a control holding the asked value.
  const limitedPair = pkce();
  const drawn = await rp.go("GET", authorizeUrl(asked,
                                                pkceExtra(limitedPair)));
  const drawnPage = drawn.status === 302 || drawn.status === 303
    ? await rp.go("GET", drawn.location) : drawn;
  check("8g. the consent screen draws the limit as a control", function () {
    assert.ok(/name="lim_t0r0_amount" value="50"/.test(drawnPage.text),
              String(drawnPage.text).slice(0, 800));
  });
  r = await follow(drawnPage, { "lim_t0r0_amount": "20" });
  const limitedCode = new URL(r.location || "https://x/").searchParams
    .get("code");
  const redeem = function (form) {
    log.debug("Entering redeem().");
    log.debug("Leaving redeem().");
    return fetch(h.realmBase + "/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(Object.assign({ client_id: RP,
        client_secret: rpSecret }, form)).toString() });
  };
  r = await redeem({ grant_type: "authorization_code",
    code: String(limitedCode || ""), redirect_uri: RP_REDIRECT,
    code_verifier: limitedPair.verifier });
  const limitedText = await r.text();
  let limitedAccess = null;
  check("8h. the access token carries the LOWERED limit and a grant_id, " +
        "read off the token by this job", function () {
    assert.strictEqual(r.status, 200, limitedText);
    limitedAccess = claimsOf(JSON.parse(limitedText).access_token);
    assert.deepStrictEqual(limitedAccess.authorization_details[0].limits,
                           { amount: "20", currency: "EUR", count: 3 },
                           JSON.stringify(limitedAccess));
    assert.ok(typeof limitedAccess.grant_id === "string" &&
              limitedAccess.grant_id, JSON.stringify(limitedAccess));
  });
  const refreshToken = JSON.parse(limitedText).refresh_token;
  r = await redeem({ grant_type: "refresh_token",
                     refresh_token: String(refreshToken || "") });
  const refreshedText = await r.text();
  check("8i. a refreshed token keeps the SAME grant_id and the lowered limit",
        function () {
    assert.strictEqual(r.status, 200, refreshedText);
    const renewed = claimsOf(JSON.parse(refreshedText).access_token);
    assert.strictEqual(renewed.grant_id, limitedAccess.grant_id,
                       refreshedText);
    assert.strictEqual(renewed.authorization_details[0].limits.amount, "20",
                       refreshedText);
  });
  r = await fetch(h.realmBase + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: RP, client_secret: rpSecret,
      token: JSON.parse(limitedText).access_token }).toString() });
  const limitedIntrospection = await r.text();
  check("8j. introspection returns the grant_id", function () {
    assert.strictEqual(r.status, 200, limitedIntrospection);
    assert.strictEqual(JSON.parse(limitedIntrospection).grant_id,
                       limitedAccess.grant_id, limitedIntrospection);
  });
  const plainPair = pkce();
  r = await follow(await rp.go("GET", authorizeUrl([{ type: ONE }],
                                                   pkceExtra(plainPair))));
  const plainCode = new URL(r.location || "https://x/").searchParams
    .get("code");
  r = await redeem({ grant_type: "authorization_code",
    code: String(plainCode || ""), redirect_uri: RP_REDIRECT,
    code_verifier: plainPair.verifier });
  const plainText = await r.text();
  check("8k. details without limits carry no grant_id", function () {
    assert.strictEqual(r.status, 200, plainText);
    assert.strictEqual(claimsOf(JSON.parse(plainText).access_token).grant_id,
                       undefined, plainText);
  });

  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_catalogue")
  .description("The access-type catalogue GNAP and RFC 9396 share, and each " +
    "GNAP access right a question to the issuance policy (#432 phases 3 " +
    "and 4), in whichever mode the service is in.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
