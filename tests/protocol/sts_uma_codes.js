// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_uma_codes.js
//
// ===========================================================================
// USER-MANAGED ACCESS 2.0, EACH REFUSAL BY ITS CODE, OVER THE WIRE (#444 D12
// phase 8; #1168, #1193, #1195).
//
// `tests/uma_protection.js`, `uma_grant.js` and `uma_admin.js` hold the
// protection API with real PATs, the grant's layers and the console's acts
// in process; `sts_uma.js` drives a running service by status and error.
// This job adds the code each refusal records on `/admin-api/audit`, in a
// development realm with `uma.enabled` on, the job as resource server (an
// application owning resources, its PAT by client credentials) and as
// client (the uma-ticket grant):
//
//   P. the protection API: no PAT (STS-UMA-0100), one that does not verify
//      (0101), a client-credentials token without uma_protection or the
//      /uma audience (0102, the check met first); a registration that is
//      not an object (0110), with no resource_scopes (0111), past
//      uma.maxResourceScopes (0112), an icon_uri that is not https (0113); a resource this
//      server did not register (0114); a method the endpoint does not take
//      (0115); past uma.maxResourcesPerOwner (0116); a permission request
//      that is not an object or array (0117), naming an unregistered
//      resource (0118) or scope (0119); a path naming no realm (0120);
//      uma.enabled off (0108);
//   G. the uma-ticket grant: an unknown ticket (STS-UMA-0201), a ticket
//      need_info rotated (0201), a ticket another client presented first
//      (0203),
//      a scope of none of the ticket's resources (0205), an RPT for upgrade
//      that is unknown (0204), an unknown persisted claims token (0206);
//   A. /admin-api/uma: an unknown act (STS-UMA-0501), an application the
//      realm does not hold (0502), a resource not registered (0504), an RPT
//      not live (0505), an owner act on an application that owns no
//      resources (0506).
//
// (d), with the reason: 0109 needs the protection API's resource object
// removed (no door removes the realm's sts-uma-protection-api); 0208,
// 0211-0214 are policies that do not evaluate or obligations, which the
// owner's document editor refuses first; 0104 (the token endpoint refuses
// uma_protection to a client not declared for UMA, 400, so no such PAT
// reaches the protection API — P4 runs only if one is issued). Owed: 0103
// (a PAT audienced to /uma without uma_protection), 0105-0107, 0202 (a ticket spent on an RPT:
// the claims interaction `sts_uma.js` walks).
//
// OWNED HERE (local: true): UMA is ours.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_uma_codes");

const log = K.log;
const check = K.check;
const GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket";

let realm = null;
const SECRETS = {};
let RS = "";
let PLAIN = "";
let CLIENT = "";
let CLIENT2 = "";

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    (verdict || function (r) {
      assert.ok(r.status >= 400, K.shown(r));
    })(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

function tokenAs(id, form) {
  log.debug("Entering tokenAs(). " + id);
  log.debug("Leaving tokenAs().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(id, SECRETS[id]) }, form: form });
}

function withPat(pat, method, path, payload) {
  log.debug("Entering withPat(). " + method + " " + path);
  const o = { method: method, headers: {} };
  if (pat) {
    o.headers.Authorization = "Bearer " + pat;
  }
  if (payload !== undefined) {
    if (typeof payload === "string") {
      o.raw = payload;
      o.headers["Content-Type"] = "application/json";
    } else {
      o.json = payload;
    }
  }
  log.debug("Leaving withPat().");
  return K.send(K.rb(realm) + path, o);
}

async function patOf(id) {
  log.debug("Entering patOf(). " + id);
  const r = await tokenAs(id, { grant_type: "client_credentials",
    scope: "uma_protection", resource: K.rb(realm) + "/uma" });
  assert.ok(r.status === 200 && r.json && r.json.access_token,
            "a PAT for " + id + ": " + K.shown(r));
  log.debug("Leaving patOf().");
  return r.json.access_token;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("umc", "development");
  await K.set(realm, "uma.enabled", true);
  RS = "umc-rs-" + K.STAMP;
  PLAIN = "umc-plain-" + K.STAMP;
  CLIENT = "umc-client-" + K.STAMP;
  CLIENT2 = "umc-client2-" + K.STAMP;
  for (const one of [[RS, ["client_credentials"]],
                     [PLAIN, ["client_credentials"]],
                     [CLIENT, [GRANT]], [CLIENT2, [GRANT]]]) {
    SECRETS[one[0]] = "umc-" + nodeCrypto.randomBytes(24)
      .toString("base64url");
    await K.app(realm, one[0], { oauthClientId: [one[0]],
      oauthClientSecret: SECRETS[one[0]], oauthGrantType: one[1],
      oauthTokenEndpointAuthMethod: "client_secret_basic" },
      { protocols: ["oauth2"] });
  }
  await K.ok(api("/uma/enable-resource-server"), { application: RS },
             "made " + RS + " a resource server");
  await K.ok(api("/uma/set-owns-resources"), { application: RS,
                                               value: "TRUE" },
             "let " + RS + " own resources");
  log.debug("Leaving setUp().");
}

async function protection(pat) {
  log.debug("Entering protection().");
  log.info("=== P. the protection API ===");
  await coded("STS-UMA-0100", "P1. no PAT is refused", function () {
    return withPat(null, "GET", "/uma/rreg");
  });
  await coded("STS-UMA-0101", "P2. a PAT that does not verify is refused",
              function () {
    return withPat(pat.slice(0, -6) + "AAAAAA", "GET", "/uma/rreg");
  });
  const other = await tokenAs(RS, { grant_type: "client_credentials" });
  if (other.status === 200 && other.json && other.json.access_token) {
    // Asked with no resource, the token is not audienced to /uma, which
    // is the check met first (STS-UMA-0102).
    await coded("STS-UMA-0102", "P3. a token without uma_protection, not " +
                "audienced to /uma, is refused", function () {
      return withPat(other.json.access_token, "GET", "/uma/rreg");
    });
  }
  const plainPat = await tokenAs(PLAIN, { grant_type: "client_credentials",
    scope: "uma_protection", resource: K.rb(realm) + "/uma" });
  log.info("the PAT asked by a client not declared for UMA answered " +
           plainPat.status);
  if (plainPat.status === 200 && plainPat.json.access_token) {
    await coded("STS-UMA-0104", "P4. a PAT from a client not declared for " +
                "UMA is refused", function () {
      return withPat(plainPat.json.access_token, "GET", "/uma/rreg");
    });
  }
  await coded("STS-UMA-0110", "P5. a registration that is not a JSON " +
              "object is refused", function () {
    return withPat(pat, "POST", "/uma/rreg", "[1]");
  });
  await coded("STS-UMA-0111", "P6. a registration with no resource_scopes " +
              "is refused", function () {
    return withPat(pat, "POST", "/uma/rreg", { name: "no scopes" });
  });
  await K.set(realm, "uma.maxResourceScopes", 2);
  await coded("STS-UMA-0112", "P7. more resource_scopes than " +
              "uma.maxResourceScopes is refused", function () {
    return withPat(pat, "POST", "/uma/rreg",
                   { resource_scopes: ["a", "b", "c"] });
  });
  await K.unset(realm, "uma.maxResourceScopes");
  await coded("STS-UMA-0113", "P8. an icon_uri that is not https is " +
              "refused", function () {
    return withPat(pat, "POST", "/uma/rreg", { resource_scopes: ["read"],
      icon_uri: "http://umc.example/icon.png" });
  });
  const made = await withPat(pat, "POST", "/uma/rreg",
                             { resource_scopes: ["read", "write"],
                               name: "umc doc" });
  check("P9. a well-formed registration is 201 with an _id", function () {
    assert.strictEqual(made.status, 201, K.shown(made));
    assert.ok(made.json && made.json._id, made.text);
  });
  await coded("STS-UMA-0114", "P10. a resource this server did not " +
              "register is refused", function () {
    return withPat(pat, "GET", "/uma/rreg/umc-nothing-" + K.STAMP);
  });
  await coded("STS-UMA-0115", "P11. a method the endpoint does not take " +
              "is refused", function () {
    return withPat(pat, "PATCH", "/uma/rreg", { resource_scopes: ["x"] });
  });
  await K.set(realm, "uma.maxResourcesPerOwner", 1);
  await coded("STS-UMA-0116", "P12. a registration past " +
              "uma.maxResourcesPerOwner is refused", function () {
    return withPat(pat, "POST", "/uma/rreg", { resource_scopes: ["read"] });
  });
  await K.unset(realm, "uma.maxResourcesPerOwner");
  await coded("STS-UMA-0117", "P13. a permission request that is neither " +
              "an object nor an array of them is refused", function () {
    return withPat(pat, "POST", "/uma/perm", "\"text\"");
  });
  await coded("STS-UMA-0118", "P14. a permission request naming an " +
              "unregistered resource is refused", function () {
    return withPat(pat, "POST", "/uma/perm", [{ resource_id:
      "umc-nothing-" + K.STAMP, resource_scopes: ["read"] }]);
  });
  await coded("STS-UMA-0119", "P15. a permission request naming a scope " +
              "the resource was not registered with is refused", function () {
    return withPat(pat, "POST", "/uma/perm", [{ resource_id: made.json._id,
                                                resource_scopes: ["fly"] }]);
  });
  const c = await K.coded(null, "STS-UMA-0120", function () {
    return K.send(K.base + "/.well-known/uma2-configuration/realm/" +
                  "umc-nowhere-" + K.STAMP);
  });
  check("P16. a discovery path naming no realm is refused (STS-UMA-0120)",
        function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1, "STS-UMA-0120 rose " + c.rose);
  });
  log.debug("Leaving protection().");
  return made.json._id;
}

async function grant(pat, resource) {
  log.debug("Entering grant().");
  log.info("=== G. the uma-ticket grant ===");
  const ticketFor = async function (scopes) {
    log.debug("Entering ticketFor().");
    const r = await withPat(pat, "POST", "/uma/perm",
                            [{ resource_id: resource,
                               resource_scopes: scopes }]);
    assert.ok(r.status === 201 && r.json && r.json.ticket, K.shown(r));
    log.debug("Leaving ticketFor().");
    return r.json.ticket;
  };
  await coded("STS-UMA-0201", "G1. an unknown ticket is refused",
              function () {
    return tokenAs(CLIENT, { grant_type: GRANT,
                             ticket: "umc-no-such-ticket" });
  });
  const first = await ticketFor(["read"]);
  const once = await tokenAs(CLIENT, { grant_type: GRANT, ticket: first });
  log.info("the first presentation answered " + once.status + " " +
           String(once.json && once.json.error));
  const nextTicket = (once.json && once.json.ticket) || "";
  // The first presentation answered need_info with a new ticket, so the
  // first is ROTATED: STS-UMA-0201 (0202 is a ticket spent on an RPT).
  await coded("STS-UMA-0201", "G2. the ticket presented again after " +
              "need_info rotated it is refused", function () {
    return tokenAs(CLIENT, { grant_type: GRANT, ticket: first });
  });
  if (nextTicket) {
    await coded("STS-UMA-0203", "G3. a ticket presented by a client other " +
                "than the one that presented it first is refused",
                function () {
      return tokenAs(CLIENT2, { grant_type: GRANT, ticket: nextTicket });
    });
  }
  const scoped = await ticketFor(["read"]);
  await coded("STS-UMA-0205", "G4. a scope naming no scope of the " +
              "ticket's resources is refused", function () {
    return tokenAs(CLIENT, { grant_type: GRANT, ticket: scoped,
                             scope: "fly" });
  });
  const upgrade = await ticketFor(["read"]);
  await coded("STS-UMA-0204", "G5. an RPT for upgrade that is unknown is " +
              "refused", function () {
    return tokenAs(CLIENT, { grant_type: GRANT, ticket: upgrade,
                             rpt: "umc-no-such-rpt" });
  });
  const pctTicket = await ticketFor(["read"]);
  await coded("STS-UMA-0206", "G6. an unknown persisted claims token is " +
              "refused", function () {
    return tokenAs(CLIENT, { grant_type: GRANT, ticket: pctTicket,
                             pct: "umc-no-such-pct" });
  });
  log.debug("Leaving grant().");
}

async function admin(resource) {
  log.debug("Entering admin().");
  log.info("=== A. /admin-api/uma ===");
  await coded("STS-UMA-0501", "A1. an act the UMA page does not have is " +
              "refused", function () {
    return K.send(api("/uma/teleport"), { json: {} });
  });
  await coded("STS-UMA-0502", "A2. an application the realm does not hold " +
              "is refused", function () {
    return K.send(api("/uma/enable-resource-server"),
                  { json: { application: "umc-nobody-" + K.STAMP } });
  });
  await coded("STS-UMA-0504", "A3. a resource that is not registered is " +
              "refused", function () {
    return K.send(api("/uma/delete-resource"),
                  { json: { resource: "umc-nothing-" + K.STAMP } });
  });
  await coded("STS-UMA-0505", "A4. an RPT that is not live is refused",
              function () {
    return K.send(api("/uma/revoke-rpt"),
                  { json: { rpt: "umc-no-such-rpt" } });
  });
  await coded("STS-UMA-0506", "A5. an owner act on an application that " +
              "owns no resources is refused", function () {
    return K.send(api("/uma/owner-share"), { json: { owner: PLAIN,
      resource: resource, scope: ["read"], recipientKind: "realm" } });
  });
  log.debug("Leaving admin().");
}

async function off(pat) {
  log.debug("Entering off().");
  await K.set(realm, "uma.enabled", false);
  await coded("STS-UMA-0108", "P17. uma.enabled off: the routes answer " +
              "501", function () {
    return withPat(pat, "GET", "/uma/rreg");
  }, function (r) {
    assert.strictEqual(r.status, 501, K.shown(r));
  });
  await K.set(realm, "uma.enabled", true);
  log.debug("Leaving off().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  const pat = await patOf(RS);
  const resource = await protection(pat);
  await grant(pat, resource);
  await admin(resource);
  await off(pat);
  log.debug("Leaving test().");
}

K.main(test, 27);
