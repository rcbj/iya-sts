// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9396_authorization_details.js
//
// ===========================================================================
// RFC 9396 RICH AUTHORIZATION REQUESTS, EVERY FEATURE A CLIENT SEES,
// POSITIVE AND NEGATIVE, OVER THE WIRE (D12, #444).
//
// Carries the child-process half of `tests/rfc9396_authorization_details.js`
// onto a running service, in a throwaway development realm with consent ON,
// every refusal's code read off `/admin-api/audit`:
//
//   a. METADATA: `authorization_details_types_supported` is openid_credential
//      and every type the realm's applications declare, sorted; another
//      realm does not support them;
//   b. THE WHOLE FLOW: the consent screen draws the type, the resource's
//      description, the amount, the location and the resource; Allow gives a
//      code; the token response and the access token carry the details, the
//      token addressed to the detail's location; introspection returns them;
//   c. SECTION 6 AT THE TOKEN ENDPOINT: a refresh narrowed to a subset, the
//      rotated refresh token keeping the whole grant, a widening and a
//      different amount refused (STS-OAUTH-0458), no details carrying the
//      grant's; consent asked again for the same details; a code redeemed
//      with a subset and refused with more;
//   d. CONSENT: Deny is access_denied, prompt=none is consent_required;
//   e. THE REFUSALS (an unknown type and two resource servers never reach
//      the consent screen): an unknown type (0453), a schema failure
//      (0456), a location the resource does not answer to (0457), two resource servers (0459), a
//      resource or a scope of another API (0460), a type outside the
//      client's registered types (0454), unreadable JSON (0450), an entry
//      that is not an object (0451) and a common field of the wrong shape
//      (0452), a named authorization server's narrower list and its document
//      (0455); a type two applications declare belonging to the first, and a
//      resource the details' resource answers to becoming the audience;
//   f. DIRECT GRANTS: client_credentials with details granted and four
//      refusals; details inside an RFC 9101 request object; an RFC 9126 push
//      refused at the push;
//   g. openid_credential not forced through consent and given its
//      credential_identifiers;
//   h. REGISTRATION AND THE CONSOLE'S WRITES: RFC 7591/7592 read-back and a
//      non-array refused; a definition whose schema does not compile and a
//      type name with a space refused on the application; a type added
//      supported at once;
//   i. A TYPE'S acr (#432 phase 6): granted on a password session with the
//      ID Token's acr, every type's acr required, refused
//      unmet_authentication_requirements on the way back, and a grant with
//      nobody behind it refused (STS-OAUTH-0937).
//
// NOT CARRIED (class (d)): the type registry, the parser, `covers()`,
// `narrow()`, the consent digest and `audiencePlan()` as library calls,
// whose outcomes sections b-f assert at the endpoints; and the RFC 9728
// import's proposal (`planFor()`), which the protected-resource-metadata
// import job reaches.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit(
  "sts_rfc9396_authorization_details");
const log = K.log;

const SECRET = "r96-client-secret-" + K.rand(10);
const PASSWORD = "R96-" + K.rand(6) + "-password!";
const REDIRECT = "https://rp.r96.example/cb";
const BASIC = K.basic("r96", SECRET);
const LIMITED = K.basic("r96-limited", SECRET);
const PAY = "https://pay.bank.r96.example/";
const PAYMENT = {
  type: "payment_initiation",
  description: "Initiate a payment from your account",
  locations: [PAY],
  schema: { type: "object", required: ["instructedAmount"],
            properties: { instructedAmount: { type: "object",
              required: ["currency", "amount"],
              properties: { currency: { type: "string" },
                            amount: { type: "string" } } } } }
};

let ID = "";
let USER = "";

function payment(amount, extra) {
  log.debug("Entering payment().");
  log.debug("Leaving payment().");
  return Object.assign({ type: "payment_initiation", locations: [PAY],
    actions: ["initiate", "status"],
    instructedAmount: { currency: "EUR", amount: amount } }, extra || {});
}

function absolute(where) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:/.test(where) ? where : K.base + where;
}

// The authorization request on browser `b`, through sign-in and consent,
// up to the client's redirect_uri; consent answered with `decision`.
async function drive(b, query, decision, prefix) {
  log.debug("Entering drive().");
  const url = K.rb(ID) + (prefix || "") + "/oauth2/authorize?" +
    new URLSearchParams(Object.assign({ response_type: "code",
      client_id: "r96", redirect_uri: REDIRECT, scope: "openid",
      state: "st-" + K.rand(4) }, query));
  let r = await b.go(url);
  const pages = { consent: null, consentCount: 0, signIns: 0 };
  for (let hop = 0; hop < 12; hop++) {
    if (r.status !== 302 && r.status !== 303) {
      break;
    }
    const where = absolute(r.location);
    if (urls.isAt(where, REDIRECT)) {
      break;
    }
    if (/\/authn\/login/.test(where)) {
      pages.signIns += 1;
      r = await authnSignin.signInWithJar(K.rb(ID), where,
        { action: "login", username: USER, password: PASSWORD }, b.jar);
      continue;
    }
    if (authnSignin.isConsent(where)) {
      pages.consentCount += 1;
      const answered = await authnSignin.consentWithJar(where,
        decision === "deny" ? "deny" : "allow", b.jar);
      pages.consent = answered.opened;
      r = answered;
      continue;
    }
    r = await b.go(where);
  }
  const location = String(r.location || "");
  const params = urls.isAt(location, REDIRECT)
    ? K.answerAt({ status: 302, location: location }, REDIRECT)
    : new URLSearchParams();
  log.debug("Leaving drive().");
  return { r: r, location: location, query: params, pages: pages };
}

function token(form, auth) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(ID) + "/oauth2/token", { form: form,
    headers: { authorization: auth || BASIC } });
}

async function redeemed(flow, extra) {
  log.debug("Entering redeemed().");
  const r = await token(Object.assign({ grant_type: "authorization_code",
    code: flow.query.get("code"), redirect_uri: REDIRECT }, extra || {}));
  log.debug("Leaving redeemed().");
  return r;
}

// A refusal at the authorization endpoint: its error at the redirect URI,
// its description, `code` recorded, and — where `noConsent` says so — the
// consent screen never drawn.
async function refusedAt(b, what, query, error, pattern, code, opts) {
  log.debug("Entering refusedAt(). " + what);
  const o = opts || {};
  let flow = null;
  const out = await K.coded(ID, code, async function () {
    flow = await drive(b, Object.assign(o.client
      ? { client_id: o.client } : {}, query), "allow", o.prefix);
    return flow;
  });
  K.check(what + " (" + code + ")", function () {
    assert.strictEqual(flow.query.get("error"), error,
                       flow.location + " " + K.shown(flow.r));
    if (pattern) {
      assert.ok(pattern.test(flow.query.get("error_description") || ""),
                flow.query.get("error_description"));
    }
    if (o.noConsent === true) {
      assert.strictEqual(flow.pages.consentCount, 0);
    }
    assert.ok(out.rose >= 1, code + " was not recorded");
  });
  log.debug("Leaving refusedAt().");
  return flow;
}

async function setUp() {
  log.debug("Entering setUp().");
  ID = await K.realm("r96", "development");
  await K.set(ID, "oauth2.consentRequired", true);
  USER = "r96-alice-" + K.STAMP;
  await K.person(ID, USER, PASSWORD);
  await K.app(ID, "r96-bank", { oauthClientId: ["r96-bank"],
    oauthPermissionBaseUri: "https://bank.r96.example/",
    oauthPermission: ["read"],
    oauthAudience: ["https://api.bank.r96.example"],
    oauthAuthorizationDetailsType: [JSON.stringify(PAYMENT),
                                    "account_information"] },
    { protocols: ["oauth2"] });
  await K.app(ID, "r96-shop", { oauthClientId: ["r96-shop"],
    oauthPermissionBaseUri: "https://shop.r96.example/",
    oauthPermission: ["orders"],
    oauthAuthorizationDetailsType: ["order_access"] },
    { protocols: ["oauth2"] });
  await K.app(ID, "r96-zdup", { oauthClientId: ["r96-zdup"],
    oauthAuthorizationDetailsType: ["account_information"] },
    { protocols: ["oauth2"] });
  const client = { oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthGrantType: ["authorization_code", "refresh_token",
                     "client_credentials"] };
  await K.app(ID, "r96", Object.assign({ oauthClientId: ["r96"] }, client));
  await K.app(ID, "r96-limited", Object.assign({
    oauthClientId: ["r96-limited"],
    oauthAuthorizationDetailsTypes: ["account_information"] }, client));
  log.debug("Leaving setUp().");
}

async function metadata() {
  log.debug("Entering metadata().");
  log.info("=== a. metadata ===");
  const meta = (await K.send(K.rb(ID) +
                             "/.well-known/openid-configuration")).json;
  const types = meta.authorization_details_types_supported || [];
  K.check("a1. authorization_details_types_supported is openid_credential " +
          "and every declared type, sorted", function () {
    assert.deepStrictEqual(types.filter(function (one) {
      return /^(openid_credential|payment_initiation|account_information|order_access)$/
        .test(one);
    }), ["account_information", "openid_credential", "order_access",
         "payment_initiation"]);
    assert.deepStrictEqual(types, types.slice(0).sort());
  });
  const other = await K.realm("r96o", "development");
  const otherMeta = (await K.send(K.rb(other) +
                                  "/.well-known/openid-configuration")).json;
  K.check("a2. another realm does not support this realm's declared types",
          function () {
    const listed = otherMeta.authorization_details_types_supported || [];
    assert.ok(listed.indexOf("payment_initiation") < 0, listed.join());
    assert.ok(listed.indexOf("openid_credential") >= 0, listed.join());
  });
  log.debug("Leaving metadata().");
}

async function theFlow(b) {
  log.debug("Entering theFlow().");
  log.info("=== b. the whole flow ===");
  const firstDetails = [payment("12.50")];
  const flow = await drive(b, {
    authorization_details: JSON.stringify(firstDetails) });
  const shown = flow.pages.consent ? JSON.stringify(flow.pages.consent.view)
    : "";
  K.check("b1. section 11.2: the consent screen draws the detail — type, " +
          "the resource's description, the amount, the location and the " +
          "resource", function () {
    assert.strictEqual(flow.pages.consentCount, 1, flow.location);
    assert.ok(/payment_initiation/.test(shown), shown.slice(0, 400));
    assert.ok(/Initiate a payment from your account/.test(shown));
    assert.ok(/12\.50/.test(shown));
    assert.ok(/pay\.bank\.r96\.example/.test(shown));
    assert.ok(/r96-bank/.test(shown), shown.slice(0, 600));
  });
  K.check("b2. Allow leads to a code", function () {
    assert.ok(flow.query.get("code"), flow.location);
  });
  const r = await redeemed(flow);
  const at = K.decode(r.json.access_token).payload;
  K.check("b3. section 7: the token response carries authorization_details",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.authorization_details[0].instructedAmount
                         .amount, "12.50");
  });
  K.check("b4. section 9.1: the access token carries the claim, addressed " +
          "to the detail's location", function () {
    assert.strictEqual(at.authorization_details[0].type,
                       "payment_initiation");
    assert.strictEqual(at.aud, PAY);
  });
  const intro = await K.send(K.rb(ID) + "/oauth2/introspect", {
    form: { token: r.json.access_token },
    headers: { authorization: BASIC } });
  K.check("b5. section 9.2: introspection returns authorization_details",
          function () {
    assert.strictEqual(intro.json.active, true, K.shown(intro));
    assert.strictEqual(intro.json.authorization_details[0].actions.length,
                       2);
  });
  log.debug("Leaving theFlow().");
  return { firstDetails: firstDetails, refresh: r.json.refresh_token };
}

async function sectionSix(b, held) {
  log.debug("Entering sectionSix().");
  log.info("=== c. section 6 at the token endpoint ===");
  const actionsOf = function (r) {
    return K.decode(r.json.access_token).payload.authorization_details[0]
      .actions;
  };
  let r = await token({ grant_type: "refresh_token",
    refresh_token: held.refresh, authorization_details:
      JSON.stringify([payment("12.50", { actions: ["status"] })]) });
  K.check("c1. a refresh narrows the details to a subset", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.deepStrictEqual(actionsOf(r), ["status"]);
  });
  r = await token({ grant_type: "refresh_token",
    refresh_token: r.json.refresh_token,
    authorization_details: JSON.stringify(held.firstDetails) });
  K.check("c2. and the rotated refresh token kept the WHOLE grant",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(actionsOf(r).length, 2);
  });
  const rotated = r.json.refresh_token;
  const wider = await K.coded(ID, "STS-OAUTH-0458", function () {
    return token({ grant_type: "refresh_token", refresh_token: rotated,
      authorization_details: JSON.stringify([payment("12.50",
        { actions: ["initiate", "refund"] })]) });
  });
  K.check("c3. a refresh asking for an action the grant lacks is refused " +
          "(STS-OAUTH-0458)", function () {
    assert.strictEqual(wider.answer.status, 400, K.shown(wider.answer));
    assert.strictEqual(wider.answer.json.error,
                       "invalid_authorization_details");
    assert.ok(/not covered/.test(wider.answer.json.error_description));
    assert.ok(wider.rose >= 1);
  });
  r = await token({ grant_type: "refresh_token", refresh_token: rotated,
    authorization_details: JSON.stringify([payment("99.00")]) });
  K.check("c4. a refresh asking for a different amount is refused",
          function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_authorization_details");
  });
  r = await token({ grant_type: "refresh_token", refresh_token: rotated });
  K.check("c5. a refresh naming no details carries the grant's",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(K.decode(r.json.access_token).payload
      .authorization_details[0].instructedAmount.amount, "12.50");
  });
  let flow = await drive(b, { authorization_details:
    JSON.stringify(held.firstDetails) });
  K.check("c6. the same details again, same person and client: consent is " +
          "asked AGAIN", function () {
    assert.strictEqual(flow.pages.consentCount, 1);
    assert.ok(flow.query.get("code"), flow.location);
  });
  r = await redeemed(flow, { authorization_details:
    JSON.stringify([payment("12.50", { actions: ["initiate"] })]) });
  K.check("c7. a code redeemed with a subset of its details", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.deepStrictEqual(actionsOf(r), ["initiate"]);
  });
  r = await token({ grant_type: "refresh_token",
    refresh_token: r.json.refresh_token,
    authorization_details: JSON.stringify(held.firstDetails) });
  K.check("c8. and its refresh token still carries the whole grant",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });
  flow = await drive(b, { authorization_details:
    JSON.stringify(held.firstDetails) });
  r = await redeemed(flow, { authorization_details:
    JSON.stringify([payment("13.00")]) });
  K.check("c9. a code redeemed with details it did not authorize is " +
          "refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_authorization_details");
  });

  log.info("=== d. consent ===");
  flow = await drive(b, { authorization_details:
    JSON.stringify(held.firstDetails) }, "deny");
  K.check("d1. Deny on details answers access_denied", function () {
    assert.strictEqual(flow.query.get("error"), "access_denied",
                       flow.location);
  });
  const none = await b.go(K.rb(ID) + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: "r96",
      redirect_uri: REDIRECT, scope: "openid", state: "pn",
      authorization_details: JSON.stringify(held.firstDetails),
      prompt: "none" }));
  K.check("d2. prompt=none with details answers consent_required, naming " +
          "the details", function () {
    assert.ok(/error=consent_required/.test(none.location), none.location);
    assert.ok(/authorization_details/.test(decodeURIComponent(
      none.location)), none.location);
  });
  log.debug("Leaving sectionSix().");
}

async function refusals(b) {
  log.debug("Entering refusals().");
  log.info("=== e. refusals ===");
  await refusedAt(b, "e1. an unknown type is refused, and never asked about",
    { authorization_details: "[{\"type\":\"not_declared_anywhere\"}]" },
    "invalid_authorization_details", /no application in this realm declares/,
    "STS-OAUTH-0453", { noConsent: true });
  await refusedAt(b, "e2. section 5: a detail failing its type's schema is " +
    "refused", { authorization_details: JSON.stringify([{
      type: "payment_initiation", locations: [PAY] }]) },
    "invalid_authorization_details", /instructedAmount/, "STS-OAUTH-0456");
  await refusedAt(b, "e3. a location the resource does not declare is " +
    "refused", { authorization_details: JSON.stringify([payment("1",
      { locations: ["https://evil.r96.example/"] })]) },
    "invalid_authorization_details", /evil\.r96\.example/, "STS-OAUTH-0457");
  await refusedAt(b, "e4. RFC 9068: details of two resource servers are " +
    "refused, and never asked about", { authorization_details:
      JSON.stringify([payment("1"), { type: "order_access" }]) },
    "invalid_authorization_details", /more than one resource server/,
    "STS-OAUTH-0459", { noConsent: true });
  await refusedAt(b, "e5. a resource naming another API beside the details " +
    "is invalid_target", { authorization_details:
      JSON.stringify([payment("1")]), resource: "https://shop.r96.example/" },
    "invalid_target", /resource parameter/, "STS-OAUTH-0460");
  await refusedAt(b, "e6. a scope naming another API's permission beside " +
    "the details is invalid_scope", { authorization_details:
      JSON.stringify([payment("1")]),
      scope: "openid https://shop.r96.example/orders" },
    "invalid_scope", /another resource server/, "STS-OAUTH-0460");
  await refusedAt(b, "e7. section 10: a type outside the client's " +
    "registered types is refused", { authorization_details:
      JSON.stringify([payment("1")]) }, "invalid_authorization_details",
    /registered authorization_details_types/, "STS-OAUTH-0454",
    { client: "r96-limited" });
  await refusedAt(b, "e8. unreadable JSON is refused",
    { authorization_details: "[{\"type\":" }, "invalid_authorization_details",
    /not readable JSON/, "STS-OAUTH-0450");
  await refusedAt(b, "e9. an entry that is not an object is refused",
    { authorization_details: "[1]" }, "invalid_authorization_details", null,
    "STS-OAUTH-0451");
  await refusedAt(b, "e10. a common data field of the wrong shape is refused",
    { authorization_details: JSON.stringify([payment("1",
      { locations: "https://pay.bank.r96.example/" })]) },
    "invalid_authorization_details", /locations/, "STS-OAUTH-0452");

  let flow = await drive(b, { authorization_details: JSON.stringify([{
    type: "account_information", actions: ["list_accounts"] }]) });
  let r = await redeemed(flow);
  K.check("e11. a detail with no locations is addressed to its resource's " +
          "permission base, and a type two applications declare belongs to " +
          "the first", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(K.decode(r.json.access_token).payload.aud,
                       "https://bank.r96.example/");
  });
  flow = await drive(b, { authorization_details:
    JSON.stringify([payment("3")]),
    resource: "https://api.bank.r96.example" });
  r = await redeemed(flow);
  K.check("e12. a resource the details' resource answers to is accepted " +
          "and becomes the audience", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(K.decode(r.json.access_token).payload.aud,
                       "https://api.bank.r96.example");
  });
  await K.ok(K.rb(ID) + "/admin-api/authorization-servers/create",
             { id: "r96as", label: "Narrow types" }, "created r96as");
  await K.ok(K.rb(ID) + "/admin-api/authorization-servers/set",
             { id: "r96as", member: "authorization_details_types_supported",
               value: "[\"account_information\"]" }, "narrowed r96as");
  await refusedAt(b, "e13. a named authorization server publishing a " +
    "narrower list refuses a type outside it",
    { authorization_details: JSON.stringify([payment("1")]) },
    "invalid_authorization_details",
    /publishes authorization_details_types_supported/, "STS-OAUTH-0455",
    { prefix: "/r96as" });
  const narrowed = (await K.send(K.rb(ID) +
    "/.well-known/oauth-authorization-server/r96as")).json;
  K.check("e14. and its document says so", function () {
    assert.deepStrictEqual(narrowed.authorization_details_types_supported,
                           ["account_information"]);
  });
  log.debug("Leaving refusals().");
}

async function directGrants(b) {
  log.debug("Entering directGrants().");
  log.info("=== f. direct grants, request objects, pushed requests ===");
  let r = await token({ grant_type: "client_credentials", scope: "payments",
    authorization_details: JSON.stringify([payment("5")]) });
  K.check("f1. client_credentials with details: granted, carried and " +
          "addressed to the location", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    const cc = K.decode(r.json.access_token).payload;
    assert.strictEqual(cc.authorization_details[0].instructedAmount.amount,
                       "5");
    assert.strictEqual(cc.aud, PAY);
    assert.ok(Array.isArray(r.json.authorization_details));
  });
  const cases = [
    ["f2. the token endpoint refuses an unknown type",
     { authorization_details: "[{\"type\":\"not_declared_anywhere\"}]" },
     "invalid_authorization_details"],
    ["f3. and details of two APIs",
     { authorization_details: JSON.stringify([payment("5"),
                                              { type: "order_access" }]) },
     "invalid_authorization_details"],
    ["f4. and a resource naming another API",
     { authorization_details: JSON.stringify([payment("5")]),
       resource: "https://shop.r96.example/" }, "invalid_target"]];
  for (const one of cases) {
    r = await token(Object.assign({ grant_type: "client_credentials" },
                                  one[1]));
    K.check(one[0], function () {
      assert.strictEqual(r.status, 400, K.shown(r));
      assert.strictEqual(r.json.error, one[2]);
    });
  }
  r = await token({ grant_type: "client_credentials",
    authorization_details: JSON.stringify([payment("5")]) }, LIMITED);
  K.check("f5. and a type outside the client's registered types",
          function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_authorization_details");
  });
  const claims = { iss: "r96", aud: K.rb(ID), client_id: "r96",
    response_type: "code", redirect_uri: REDIRECT, scope: "openid",
    state: "jar", exp: Math.floor(Date.now() / 1000) + 300,
    authorization_details: [payment("7.00")] };
  const unsigned = K.jws("none", {}, claims);
  const flow = await (async function () {
    const first = await b.go(K.rb(ID) + "/oauth2/authorize?" +
      new URLSearchParams({ client_id: "r96", request: unsigned }));
    // drive() builds its own request; this one is the request object's,
    // so the consent screen is answered here.
    let resp = first;
    let consents = 0;
    for (let hop = 0; hop < 8 && (resp.status === 302 ||
         resp.status === 303); hop++) {
      const where = absolute(resp.location);
      if (urls.isAt(where, REDIRECT)) {
        break;
      }
      if (authnSignin.isConsent(where)) {
        consents += 1;
        resp = await authnSignin.consentWithJar(where, "allow", b.jar);
        continue;
      }
      resp = await b.go(where);
    }
    return { consents: consents, query: K.answerAt({ status: 302,
      location: String(resp.location || "") }, REDIRECT) ||
      new URLSearchParams(), location: resp.location };
  })();
  r = await redeemed(flow);
  K.check("f6. RFC 9101: details as a JSON array inside a request object " +
          "are consented and granted", function () {
    assert.strictEqual(flow.consents, 1, String(flow.location));
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(K.decode(r.json.access_token).payload
      .authorization_details[0].instructedAmount.amount, "7.00");
  });
  r = await K.send(K.rb(ID) + "/oauth2/par", { form: { client_id: "r96",
    response_type: "code", redirect_uri: REDIRECT, scope: "openid",
    authorization_details: "[{\"type\":\"nope_nope\"}]" },
    headers: { authorization: BASIC } });
  K.check("f7. RFC 9126: a pushed request with an unknown type is refused " +
          "at the push", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_authorization_details");
  });
  log.debug("Leaving directGrants().");
}

async function credentialType(b) {
  log.debug("Entering credentialType().");
  log.info("=== g. openid_credential ===");
  const flow = await drive(b, { authorization_details:
    "[{\"type\":\"openid_credential\"," +
    "\"credential_configuration_id\":\"IdentityCredential\"}]" });
  const r = await redeemed(flow);
  K.check("g1. openid_credential is not forced through consent and still " +
          "gets its credential_identifiers", function () {
    assert.strictEqual(flow.pages.consentCount, 0, flow.location);
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(Array.isArray(r.json.authorization_details[0]
      .credential_identifiers), K.shown(r));
  });
  const out = await K.coded(ID, "STS-OAUTH-0153", function () {
    return drive(b, { authorization_details:
      "[{\"type\":\"openid_credential\"," +
      "\"credential_configuration_id\":\"NoSuchCredential\"}]" });
  });
  K.check("g2. and one naming a credential configuration this issuer does " +
          "not offer is refused (STS-OAUTH-0153)", function () {
    assert.ok(out.answer.query.get("error"), out.answer.location);
    assert.ok(out.rose >= 1, "STS-OAUTH-0153 was not recorded");
  });
  log.debug("Leaving credentialType().");
}

async function registration() {
  log.debug("Entering registration().");
  log.info("=== h. registration and the console's writes ===");
  let r = await K.send(K.rb(ID) + "/oauth2/register", { json: {
    client_name: "r96 registered", redirect_uris: [REDIRECT],
    authorization_details_types: ["account_information"] } });
  const reg = r.json || {};
  const read = reg.client_id ? await K.send(K.rb(ID) + "/oauth2/register/" +
    reg.client_id, { headers: { authorization: "Bearer " +
      reg.registration_access_token } }) : { json: {} };
  const entry = await K.send(K.rb(ID) + "/admin-api/applications?" +
                             "application=" +
                             encodeURIComponent(reg.client_id || "x"));
  K.check("h1. RFC 7591 and 7592: authorization_details_types registered, " +
          "held and read back", function () {
    assert.ok(r.status === 201 || r.status === 200, K.shown(r));
    assert.deepStrictEqual(reg.authorization_details_types,
                           ["account_information"]);
    assert.deepStrictEqual(read.json.authorization_details_types,
                           ["account_information"]);
    assert.ok(JSON.stringify(entry.json && entry.json.fields)
      .indexOf("account_information") >= 0, K.shown(entry));
  });
  r = await K.send(K.rb(ID) + "/oauth2/register", { json: {
    client_name: "r96 bad", redirect_uris: [REDIRECT],
    authorization_details_types: "account_information" } });
  K.check("h2. a registration with a non-array authorization_details_types " +
          "is refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client_metadata");
  });
  r = await K.send(K.rb(ID) + "/admin-api/applications/add", { json: {
    application: "r96-bank", attribute: "oauthAuthorizationDetailsType",
    value: "{\"type\":\"x\",\"schema\":{\"type\":\"nope\"}}" } });
  K.check("h3. the console's write refuses a definition whose schema does " +
          "not compile", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(/does not compile/.test(r.text), r.text.slice(0, 300));
  });
  r = await K.send(K.rb(ID) + "/admin-api/applications/add", { json: {
    application: "r96", attribute: "oauthAuthorizationDetailsTypes",
    value: "has space" } });
  K.check("h4. and a client type name with a space", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  await K.ok(K.rb(ID) + "/admin-api/applications/add", {
    application: "r96-shop", attribute: "oauthAuthorizationDetailsType",
    value: "refund_request" }, "added refund_request");
  const meta = (await K.send(K.rb(ID) +
                             "/.well-known/openid-configuration")).json;
  K.check("h5. a type added on the console is supported at once",
          function () {
    assert.ok(meta.authorization_details_types_supported
      .indexOf("refund_request") >= 0);
  });
  log.debug("Leaving registration().");
}

async function typeAcr() {
  log.debug("Entering typeAcr().");
  log.info("=== i. a type's acr ===");
  for (const value of ["{\"type\":\"r96-one\",\"acr\":\"1\"}",
                       "{\"type\":\"r96-strong\",\"acr\":\"mfa\"}"]) {
    await K.ok(K.rb(ID) + "/admin-api/applications/add", {
      application: "r96-shop", attribute: "oauthAuthorizationDetailsType",
      value: value }, "added " + value);
  }
  const b = K.browser();
  const flow = await drive(b, { authorization_details:
    JSON.stringify([{ type: "r96-one" }]) });
  let r = await redeemed(flow);
  K.check("i1. a type needing acr 1 is granted on a password session, and " +
          "the ID Token carries the acr met", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(K.decode(r.json.id_token).payload.acr, "1");
  });
  r = await b.go(K.rb(ID) + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "r96", redirect_uri: REDIRECT,
    scope: "openid", state: "acr", authorization_details:
      JSON.stringify([{ type: "r96-one" }, { type: "r96-strong" }]) }));
  K.check("i2. a type needing mfa sends the same session to sign in again " +
          "— every type's acr is required, not any of them", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  r = await b.go(K.rb(ID) + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "r96", redirect_uri: REDIRECT,
    scope: "openid", state: "acr", acr_values: "1", step_up_honoured: "1",
    authorization_details: JSON.stringify([{ type: "r96-strong" }]) }));
  K.check("i3. back from that sign-in still short of it, refused " +
          "unmet_authentication_requirements — acr_values met does not " +
          "stand in for a type's acr", function () {
    assert.ok(/error=unmet_authentication_requirements/.test(r.location),
              K.shown(r));
  });
  const cc = await K.coded(ID, "STS-OAUTH-0937", function () {
    return token({ grant_type: "client_credentials", scope: "payments",
      authorization_details: JSON.stringify([{ type: "r96-one" }]) });
  });
  K.check("i4. a grant with no person behind it meets no type's acr " +
          "(STS-OAUTH-0937)", function () {
    assert.strictEqual(cc.answer.status, 400, K.shown(cc.answer));
    assert.strictEqual(cc.answer.json.error, "invalid_authorization_details");
    assert.ok(/authentication level 1/.test(
      cc.answer.json.error_description || ""), K.shown(cc.answer));
    assert.ok(cc.rose >= 1);
  });
  log.debug("Leaving typeAcr().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await metadata();
  const b = K.browser();
  const held = await theFlow(b);
  await sectionSix(b, held);
  await refusals(b);
  await directGrants(b);
  await credentialType(b);
  await registration();
  await typeAcr();
  log.debug("Leaving test().");
}

K.main(test, 50);
