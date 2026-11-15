// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_access_policy.js
//
// ===========================================================================
// THE ACCESS-CONTROL POLICY DECIDES WHO REACHES THE GATED SURFACES, OVER THE
// WIRE (#444 D12 phase 8).
//
// `tests/access_policy.js` asks `common/access_gate.ts` in process: the
// built-in `access-control` document's ownership conjunct, its required-
// all conjunct, `xacml.enforceAccess`, and a fault refused in product.
// This job asks what a request can reach, in a development realm, as a
// person signed in to the static portal (a DPoP-bound `/account-api`
// token) and through `/admin-api`:
//
//   A. a person reaches their OWN account under the built-in policy;
//   O. the realm's override of `xacml.accessPolicy`'s entry denying the
//      portal resource refuses the same request (STS-XACML-0044 on the
//      realm's audit), and nothing else in the realm; the override
//      DISABLED stops that layer deciding (allowed), and deleted puts the
//      built-in back;
//   E. `xacml.enforceAccess` off in the realm: the overriding Deny is not
//      made, so the refusal above is the POLICY's and not an unreachable
//      gate;
//   M. `/admin-api/mode`'s `access-decisions-fail-closed` row: in force as
//      development's sentence in a development realm and product's in a
//      product realm, and a product realm's `xacml.enforceAccess` turned
//      off shown on the row by name.
//
// (d), with the reason: the ownership regression itself — a person
// reaching ANOTHER person's account, for manage-own and for read — and an
// unauthenticated session asking for its own name: `/account-api` takes the
// person from the token's subject and never from the request, so no
// request names an owner other than its own subject (`sts_account_api.js`
// holds that structural half). The console's required-all pairs
// (ADMIN_CONSOLE with ADMIN_READ) are the console's own token
// (`console_signin.js` jobs). A decider that throws or answers nothing is
// a process with the PEP half loaded, which no request makes.
//
// OWNED HERE (local: true): the access policy and the portal are ours.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_access_policy");
const portal = require("./portal_signin.js");

const log = K.log;
const check = K.check;
const PW = "Apol-" + nodeCrypto.randomBytes(9).toString("base64url") +
           "-Battery.42";
const OVERRIDE = [
  "namespace apol {",
  "    attribute res { category = resourceCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:resource:resource-id\"",
  "        type = string }",
  "    policy apolAccess {",
  "        id = \"urn:test:apol-access\"",
  "        apply firstApplicable",
  "        rule portalDenied { deny target clause res == \"user-portal\" }",
  "        rule rest { permit }",
  "    }",
  "}"
].join("\n");

let realm = null;
let person = null;

function api(id, path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(id) + "/admin-api" + path;
}

async function me(what, expected) {
  log.debug("Entering me(). " + what);
  const r = await person.api("GET", "/account-api/me");
  check(what, function () {
    assert.ok(expected ? r.status === 200 : r.status === 403,
              r.status + " " + String(r.text || "").slice(0, 300));
  });
  log.debug("Leaving me().");
  return r;
}

async function requirement(id) {
  log.debug("Entering requirement().");
  const r = await K.send(api(id, "/mode"));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving requirement().");
  return ((r.json && r.json.requirements) || []).filter(function (one) {
    return one.id === "access-decisions-fail-closed";
  })[0] || null;
}

async function overridden() {
  log.debug("Entering overridden().");
  log.info("=== O. the realm's override decides ===");
  await K.ok(api(realm, "/xacml/import-alfa"), { name: "access-control",
    alfa: OVERRIDE }, "the realm's access-control override");
  const c = await K.coded(realm, "STS-XACML-0044", function () {
    return person.api("GET", "/account-api/me");
  });
  check("O1. the override denying the portal refuses the person's own " +
        "account (STS-XACML-0044)", function () {
    assert.strictEqual(c.answer.status, 403, c.answer.status + " " +
                       String(c.answer.text || "").slice(0, 300));
    assert.ok(c.rose >= 1, "STS-XACML-0044 rose " + c.rose);
  });
  const listed = await K.send(api(realm, "/xacml/policies"));
  check("O2. and nothing else in the realm: its /admin-api still answers",
        function () {
    assert.strictEqual(listed.status, 200, K.shown(listed));
  });
  await K.ok(api(realm, "/xacml/disable"), { name: "access-control" },
             "disabled the override");
  await me("O3. the override DISABLED stops that layer deciding: the " +
           "account is reached", true);
  await K.ok(api(realm, "/xacml/enable"), { name: "access-control" },
             "enabled the override again");
  await me("O4. enabled again, refused again", false);
  log.debug("Leaving overridden().");
}

async function enforcementOff() {
  log.debug("Entering enforcementOff().");
  log.info("=== E. xacml.enforceAccess off ===");
  await K.set(realm, "xacml.enforceAccess", false);
  await me("E1. with enforcement off the override's Deny is not made — so " +
           "the refusal above is the policy's, not an unreachable gate",
           true);
  await K.unset(realm, "xacml.enforceAccess");
  await K.ok(api(realm, "/xacml/delete"), { name: "access-control" },
             "deleted the override");
  await me("E2. the override deleted, the built-in policy is back and the " +
           "person reaches their own account", true);
  log.debug("Leaving enforcementOff().");
}

async function modeRow() {
  log.debug("Entering modeRow().");
  log.info("=== M. /admin-api/mode ===");
  const dev = await requirement(realm);
  check("M1. the requirement is described, in force as development's " +
        "sentence in a development realm", function () {
    assert.ok(dev, "no access-decisions-fail-closed row");
    assert.strictEqual(dev.inForce, dev.development, JSON.stringify(dev));
  });
  const product = await K.realm("apolp", "product");
  const row = await requirement(product);
  check("M2. and as product's in a product realm, naming no switch while " +
        "none is off", function () {
    assert.strictEqual(row.inForce, row.product, JSON.stringify(row));
    assert.ok(JSON.stringify(row).indexOf("\"xacml.enforceAccess\"") < 0,
              JSON.stringify(row));
  });
  await K.set(product, "xacml.enforceAccess", false);
  const off = await requirement(product);
  check("M3. a switch turned off is shown on the row by name", function () {
    assert.ok(/xacml\.enforceAccess/.test(JSON.stringify(off).replace(
      row.product, "")), JSON.stringify(off));
  });
  await K.unset(product, "xacml.enforceAccess");
  log.debug("Leaving modeRow().");
}

async function test() {
  log.debug("Entering test().");
  realm = await K.realm("apol", "development");
  const username = ("apol" + K.STAMP).slice(0, 30);
  await K.ok(api(realm, "/users/create"), { username: username,
    invent: false, attributes: { cn: username, sn: username },
    credential: "password", password: PW }, "created " + username);
  person = await portal.signInToThePortal(K.rb(realm), username, log,
                                          { password: PW });
  await me("A1. a person signed in to the portal reaches their OWN account " +
           "under the built-in policy", true);
  await overridden();
  await enforcementOff();
  await modeRow();
  log.debug("Leaving test().");
}

K.main(test, 10);
