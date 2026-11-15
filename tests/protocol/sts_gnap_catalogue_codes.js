// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_catalogue_codes.js
//
// ===========================================================================
// THE ACCESS-TYPE CATALOGUE'S REFUSALS AND EACH BUILT-IN RULE OF THE GNAP
// RIGHT, BY CODE, OVER THE WIRE (#444 D12 phase 8; #432 phases 3-5).
//
// `tests/gnap_catalogue.js` and `tests/gnap_limits_ownership.js` hold the
// catalogue's grammar, `conformanceRefusal()`, the issuance policy's
// built-in rules and `common/access_limits.ts` as functions, in a realm
// with the issuance PEP armed. `sts_gnap_catalogue.js` asks the same of the
// wire by the GNAP error each answers; this job adds the code each records
// on `/admin-api/audit`, in a PRODUCT realm with a client trusted to skip
// the page (so each answer is the policy's, not the person's):
//
//   R. the console's door: a definition that does not read and a type on no
//      application (STS-REG-0294), a type taken off that is not there
//      (STS-REG-0295), an owner lookup that is not an https template
//      (STS-REG-0334);
//   P. the rules: an uncatalogued type in product (STS-GNAP-0810, and none
//      in development where it is granted), a bearer token while the
//      client's entry forbids them (0111) and while gnap.bearerTokens is
//      off (0111), a bearer token for a type declaring bearer false (0811),
//      a protected scope the client does not declare (0719), a right
//      outside gnapAllowedAccess (0112), an action the type does not list
//      (0812), limits on a type with no limits schema (0813), limits its
//      schema refuses (0814), limits common/access_limits.ts cannot read
//      (0860), an identifier whose owner lookup cannot be answered (0863);
//      and the type's maxLifetimeS capping the token;
//   O. RFC 9396 reads the same catalogue at /oauth2/token: an action the
//      type does not list (STS-OAUTH-0456), limits on a type with none
//      (0876), limits its schema refuses (0877), limits that cannot be read
//      (0916).
//
// (d), with the reason: STS-GNAP-0870 to 0875 are `gnap/gnap_spend.ts`'s,
// the totals a RESOURCE SERVER keeps (#432 decision 2) — no route of this
// service spends through it since #593, and the test peer keeps its own;
// the catalogue's grammar table and `derivableBeyond()` are functions
// (derivation is `sts_gnap_catalogue.js` 5). Owed: 0817 (a realm policy
// narrowing a right to nothing), 0861 (an identifier a registered resource
// set gives another owner, refused by the policy rather than the page).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_catalogue_codes");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Cat-Passw0rd!-" + String(Date.now()).slice(-6);
const PAY = "gcc-pay";
const PLAIN = "gcc-plain";
const SHORT = "gcc-short";
const LOOKUP = "gcc-owned";

let realm = null;
let h = null;
let trusted = null;
let RS = "";

async function refused(code, what, access, opts) {
  log.debug("Entering refused(). " + code);
  const o = opts || {};
  const c = await K.coded(realm, code, function () {
    return G.direct(h, o.client || trusted, access, o.extra);
  });
  check(what + " (" + code + ")", function () {
    assert.strictEqual(c.answer.status, o.status || 400, c.answer.text);
    assert.strictEqual(G.errorOf(c.answer), o.error || "invalid_request",
                       c.answer.text);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving refused().");
  return c.answer;
}

async function door() {
  log.debug("Entering door().");
  log.info("=== R. the console's door ===");
  let c = await K.coded(realm, "STS-REG-0294", function () {
    return K.send(h.realmApi + "/applications/set-access-type", { json: {
      application: RS, type: "gcc-broken", limits: { anyOf: [] } } });
  });
  check("R1. a definition that does not read is refused (STS-REG-0294)",
        function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(realm, "STS-REG-0294", function () {
    return K.send(h.realmApi + "/applications/set-access-type", { json: {
      application: "gcc-nobody-" + K.STAMP, type: "gcc-x" } });
  });
  check("R2. a type declared on no application is refused (STS-REG-0294)",
        function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(realm, "STS-REG-0295", function () {
    return K.send(h.realmApi + "/applications/remove-access-type", { json: {
      application: RS, type: "gcc-never-declared" } });
  });
  check("R3. a type taken off that the application does not declare is " +
        "refused (STS-REG-0295)", function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(realm, "STS-REG-0334", function () {
    return K.appSet(realm, RS, "gnapOwnerLookupUri",
                    "http://lookup.gcc.test/owner?id={identifier}");
  });
  check("R4. an owner lookup that is not an https template with " +
        "{identifier} as a path segment is refused (STS-REG-0334)",
        function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  log.debug("Leaving door().");
}

async function rules() {
  log.debug("Entering rules().");
  log.info("=== P. the rules ===");
  let r = await G.direct(h, trusted, [{ type: PLAIN, actions: ["read"] }]);
  check("P0. a declared type is granted to the trusted client without " +
        "interaction", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value, r.text);
  });
  await refused("STS-GNAP-0810", "P1. product: a type no resource server " +
                "declares is refused request_denied",
                [{ type: "gcc-undeclared" }],
                { status: 403, error: "request_denied" });
  const bearerOff = G.client();
  await G.entry(h, "gcc-nobearer-" + K.STAMP, "gnap-client", bearerOff,
                { gnapSkipInteraction: "TRUE", gnapBearerTokens: "FALSE",
                  gnapFinishUri: [h.FINISH] });
  await refused("STS-GNAP-0111", "P2. a bearer token for a client whose " +
                "entry forbids them is refused", [{ type: PLAIN }],
                { client: bearerOff, error: "invalid_flag",
                  extra: { access_token: { access: [{ type: PLAIN }],
                                           flags: ["bearer"] } } });
  await K.set(realm, "gnap.bearerTokens", false);
  await refused("STS-GNAP-0111", "P3. and for any client while " +
                "gnap.bearerTokens is off", [{ type: PLAIN }],
                { error: "invalid_flag",
                  extra: { access_token: { access: [{ type: PLAIN }],
                                           flags: ["bearer"] } } });
  await K.unset(realm, "gnap.bearerTokens");
  await refused("STS-GNAP-0811", "P4. a bearer token carrying a type " +
                "declared bearer: false is refused", [{ type: PAY }],
                { status: 403, error: "request_denied",
                  extra: { access_token: { access: [{ type: PAY,
                    actions: ["status"] }], flags: ["bearer"] } } });
  await refused("STS-GNAP-0719", "P5. a protected scope (ssf.read) the " +
                "client does not declare is refused", ["ssf.read"],
                { status: 403, error: "request_denied" });
  const narrow = G.client();
  await G.entry(h, "gcc-narrow-" + K.STAMP, "gnap-client", narrow,
                { gnapSkipInteraction: "TRUE", gnapFinishUri: [h.FINISH],
                  gnapAllowedAccess: [SHORT] });
  await refused("STS-GNAP-0112", "P6. a right outside the client's " +
                "gnapAllowedAccess is refused", [{ type: PLAIN }],
                { client: narrow, status: 403, error: "request_denied" });
  await refused("STS-GNAP-0812", "P7. an action the type does not list " +
                "is refused", [{ type: PAY, actions: ["steal"] }]);
  await refused("STS-GNAP-0813", "P8. limits on a type that declares no " +
                "limits schema are refused",
                [{ type: PLAIN, limits: { amount: 1 } }]);
  await refused("STS-GNAP-0814", "P9. limits the type's schema refuses " +
                "are refused", [{ type: PAY, actions: ["status"],
                                  limits: { amount: -5 } }]);
  await refused("STS-GNAP-0860", "P10. limits common/access_limits.ts " +
                "cannot read (an amount in no currency) are refused",
                [{ type: PAY, actions: ["status"], limits: { amount: 5 } }]);
  r = await G.direct(h, trusted, [{ type: SHORT }]);
  check("P11. the type's maxLifetimeS caps the token's expires_in",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    const exp = Number(r.json.access_token.expires_in);
    assert.ok(exp > 0 && exp <= 90, r.text);
  });
  await refused("STS-GNAP-0863", "P12. an identifier whose resource " +
                "server's owner lookup cannot be answered is refused",
                [{ type: LOOKUP, identifier: "doc-1" }],
                { status: 403, error: "request_denied" });
  log.debug("Leaving rules().");
}

async function oauthHalf() {
  log.debug("Entering oauthHalf().");
  log.info("=== O. RFC 9396 reads the same catalogue ===");
  const ID = "gcc-oauth-" + K.STAMP;
  const SECRET = "gcc-" + nodeCrypto.randomBytes(18).toString("base64url");
  await K.app(realm, ID, { oauthClientId: [ID], oauthClientSecret: SECRET,
    oauthGrantType: ["client_credentials"],
    oauthTokenEndpointAuthMethod: "client_secret_post" },
    { protocols: ["oauth2"] });
  const ask = function (details) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return K.send(K.rb(realm) + "/oauth2/token", { form: {
      grant_type: "client_credentials", client_id: ID, client_secret: SECRET,
      authorization_details: JSON.stringify(details) } });
  };
  const cases = [
    ["STS-OAUTH-0456", "O1. an action the type does not list",
     [{ type: PAY, actions: ["steal"] }]],
    ["STS-OAUTH-0876", "O2. limits on a type with no limits schema",
     [{ type: PLAIN, limits: { amount: 1 } }]],
    ["STS-OAUTH-0877", "O3. limits the type's schema refuses",
     [{ type: PAY, actions: ["status"], limits: { amount: -5 } }]],
    ["STS-OAUTH-0916", "O4. limits that cannot be read",
     [{ type: PAY, actions: ["status"], limits: { amount: 5 } }]]
  ];
  for (const one of cases) {
    const c = await K.coded(realm, one[0], function () {
      return ask(one[2]);
    });
    check(one[1] + " is invalid_authorization_details at /oauth2/token (" +
          one[0] + ")", function () {
      assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
      assert.strictEqual(c.answer.json && c.answer.json.error,
                         "invalid_authorization_details", c.answer.text);
      assert.ok(c.rose >= 1, one[0] + " rose " + c.rose);
    });
  }
  log.debug("Leaving oauthHalf().");
}

async function development() {
  log.debug("Entering development().");
  log.info("=== P1b. development grants an uncatalogued type ===");
  const made = await G.gnapRealm("gccd", "development", {}, PASSWORD);
  const dh = made.h;
  const c = G.client();
  await G.entry(dh, "gcc-trusted-" + K.STAMP, "gnap-client", c,
                { gnapSkipInteraction: "TRUE", gnapFinishUri: [dh.FINISH] });
  await G.resourceServer(dh, "gcc-rs-" + K.STAMP, G.client(),
                         "https://gcc-rs.gnap.test/api",
                         [{ type: PLAIN }]);
  const n = await K.coded(made.id, "STS-GNAP-0810", function () {
    return G.direct(dh, c, [{ type: PLAIN },
                            { type: "gcc-undeclared" }]);
  });
  check("P1b. development: the same uncatalogued type is granted, and " +
        "STS-GNAP-0810 is not recorded", function () {
    assert.strictEqual(n.answer.status, 200, n.answer.text);
    assert.ok(n.answer.json.access_token, n.answer.text);
    assert.strictEqual(n.rose, 0);
  });
  log.debug("Leaving development().");
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gcc", "product", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  RS = "gcc-rs-" + K.STAMP;
  await G.resourceServer(h, RS, G.client(), "https://gcc-rs.gnap.test/api", [
    { type: PAY, actions: ["initiate", "status"], bearer: false,
      limits: { type: "object",
                properties: { amount: { type: "number", minimum: 0 },
                              currency: { type: "string" } },
                required: ["amount"], additionalProperties: false } },
    { type: PLAIN, actions: ["read"] },
    { type: SHORT, maxLifetimeS: 90 }]);
  const LRS = "gcc-lookup-" + K.STAMP;
  await G.entry(h, LRS, "gnap-resource-server", G.client(), {
    gnapResourceServerUri: "https://gcc-lookup.gnap.test/api",
    gnapOwnerLookupUri:
      "https://gcc-lookup.invalid/owners/{identifier}" });
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: LRS, type: LOOKUP }, "declared " + LOOKUP);
  trusted = G.client();
  await G.entry(h, "gcc-trusted-" + K.STAMP, "gnap-client", trusted,
                { gnapSkipInteraction: "TRUE", gnapFinishUri: [h.FINISH] });
  await door();
  await rules();
  await oauthHalf();
  await development();
  log.debug("Leaving test().");
}

K.main(test, 22);
