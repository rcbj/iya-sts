// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_issuance_refusal_reason.js
//
// ===========================================================================
// AN ISSUANCE DENY NAMES THE RULE KIND THAT MADE IT, OVER THE WIRE (#444 D12
// phase 8; 2026-11-10).
//
// `tests/issuance_refusal_reason.js` asks `XacmlRolePep.reasonFor()` in
// process. Its sentence reaches an operator as the `detail` of the
// `xacml.issuance.refused` audit row (STS-XACML-0039), so this job makes
// real refusals at `/oauth2/token` (a client_credentials grant, whose
// subject is the application, holding EVERYBODY) in a development realm
// and reads the rows back:
//
//   A. the realm's issuance policy overridden (`xacml.issuancePolicy`'s
//      entry, `role-issuance`) by one whose Deny carries an obligation: the
//      sentence says a rule other than the role requirement refused, names
//      the obligation and does not list the roles held;
//   B. the same Deny with no obligation: it points at /admin/xacml/decide;
//   C. the override deleted, the application requiring a role its client
//      does not hold: the role sentence, unchanged — answered as the token
//      endpoint's `error_description` (access_denied), where A's and B's
//      sentences are on the audit row only.
//
// OWNED HERE (local: true): the issuance PEP and its audit row are ours.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_issuance_refusal_reason");

const log = K.log;
const check = K.check;
const OBLIGATION = "urn:test:irr-obligation";
const SECRET = "irr-" + nodeCrypto.randomBytes(24).toString("base64url");

function override(withObligation) {
  log.debug("Entering override().");
  const rule = withObligation
    ? ["        rule refuse {",
       "            deny",
       "            on deny {",
       "                obligation \"" + OBLIGATION + "\" {",
       "                    \"urn:test:irr-note\" = \"refused\"",
       "                }",
       "            }",
       "        }"]
    : ["        rule refuse { deny }"];
  log.debug("Leaving override().");
  return ["namespace irr {",
          "    policy irrIssuance {",
          "        id = \"urn:test:irr-issuance\"",
          "        apply firstApplicable"].concat(rule)
    .concat(["    }", "}"]).join("\n");
}

let realm = null;
let CLIENT = "";

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

function token() {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(CLIENT, SECRET) },
    form: { grant_type: "client_credentials" } });
}

// The newest STS-XACML-0039 row's detail, after one refused grant.
async function refusedDetail(what) {
  log.debug("Entering refusedDetail().");
  const c = await K.coded(realm, "STS-XACML-0039", token);
  check(what + ": the token endpoint refuses and STS-XACML-0039 is " +
        "recorded", function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1, "rose " + c.rose + " " + K.shown(c.answer));
  });
  const r = await K.send(api("/audit?per=500&code=STS-XACML-0039"));
  const rows = (r.json && r.json.events) || [];
  const details = rows.map(function (one) {
    return typeof one.detail === "string" ? one.detail
      : JSON.stringify(one.detail || "") + " " + String(one.summary || "");
  }).filter(function (one) {
    return one.indexOf(CLIENT) >= 0;
  });
  log.debug("Leaving refusedDetail(). " + details.length);
  return { all: details, text: JSON.stringify(r.json || {}) };
}

async function test() {
  log.debug("Entering test().");
  realm = await K.realm("irr", "development");
  CLIENT = "irr-app-" + K.STAMP;
  await K.app(realm, CLIENT, { oauthClientId: [CLIENT],
    oauthClientSecret: SECRET, oauthGrantType: ["client_credentials"],
    oauthTokenEndpointAuthMethod: "client_secret_basic" },
    { protocols: ["oauth2"] });
  const fine = await token();
  check("A0. the built-in issuance policy issues to the application",
        function () {
    assert.strictEqual(fine.status, 200, K.shown(fine));
  });

  log.info("=== A. a held role and another rule's Deny ===");
  await K.ok(api("/xacml/import-alfa"), { name: "role-issuance",
    alfa: override(true) }, "overrode role-issuance with an obligation");
  const a = await refusedDetail("A1");
  const other = a.all.filter(function (one) {
    return one.indexOf(OBLIGATION) >= 0;
  })[0] || "";
  check("A2. the detail says a rule other than the role requirement " +
        "refused, names the obligation, and does not list the roles held",
        function () {
    assert.ok(/a rule other than the role requirement/.test(other),
              a.text.slice(0, 1500));
    assert.ok(/requires EVERYBODY, which "/.test(other), other);
    assert.ok(other.indexOf(" holds EVERYBODY,") < 0, other);
  });

  log.info("=== B. the same with no obligation ===");
  await K.ok(api("/xacml/import-alfa"), { name: "role-issuance",
    alfa: override(false) }, "overrode role-issuance with a bare Deny");
  const b = await refusedDetail("B1");
  const bare = b.all.filter(function (one) {
    return one.indexOf("/admin/xacml/decide") >= 0;
  })[0] || "";
  check("B2. with no obligation the detail points at /admin/xacml/decide",
        function () {
    assert.ok(/a rule other than the role requirement/.test(bare),
              b.text.slice(0, 1500));
    assert.ok(/carried no obligation naming the rule/.test(bare), bare);
  });

  log.info("=== C. a role the subject does not hold ===");
  await K.ok(api("/xacml/delete"), { name: "role-issuance" },
             "deleted the override");
  await K.ok(api("/roles/create-role"), { role: "irr-staff" },
             "created the role irr-staff");
  const narrowed = await K.send(api("/applications/add"), { json: {
    application: CLIENT, attribute: "appRequiredRole",
    value: "irr-staff" } });
  assert.strictEqual(narrowed.status, 200, K.shown(narrowed));
  const c = await token();
  const said = String((c.json && c.json.error_description) || "");
  check("C1. the token endpoint refuses the narrowed application",
        function () {
    assert.strictEqual(c.status, 400, K.shown(c));
    assert.strictEqual(c.json && c.json.error, "access_denied", K.shown(c));
  });
  check("C2. and the role sentence is unchanged where a required role is " +
        "missing: it names the role required and the roles held",
        function () {
    assert.ok(new RegExp("'" + CLIENT + "' requires irr-staff and '" +
                         CLIENT + "' holds EVERYBODY").test(said), said);
    assert.ok(!/a rule other than the role requirement/.test(said), said);
  });
  log.debug("Leaving test().");
}

K.main(test, 7);
