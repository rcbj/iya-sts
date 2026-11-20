// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_register.js
//
// ===========================================================================
// WHAT A WS-TRUST DELEGATION LEAVES IN THE REGISTERS, AND SAML 1.1 ON BEHALF
// OF SOMEBODY, OVER THE WIRE (#478, #479, #481; #444 D12, phase 7).
//
// The rest of `tests/wstrust_jwt_claims.js` (N), `tests/wstrust_fault_codes.js`
// (D) and `tests/wstrust_saml11.js` (T2), against a development realm D and
// a product realm P of the job's own. Every token presented is one the
// service issued over `/sts`: the front application's own (by its secret)
// as the requester, the person's (by her password) inside the element.
//
//   N. GET /admin-api/delegation, the act that produced the token:
//      N1 an ActAs act's note says the token names who acted (the
//      Delegation Restriction for an assertion, the nested `act` for a
//      JWT); N2 an OnBehalfOf act's note says the token adds nobody; N3 the
//      consumed token's note is VERIFIED in product and NOT verified in
//      development; N4 authorizedBy names the AppliesTo's application and
//      the token inside the element, never RFC 8693's "subject token".
//   D. GET /admin-api/users: a delegation the policy refused (a person set
//      not-delegated, STS-WSTRUST-0018) leaves its subject without the
//      delegated method; the requester is listed; an allowed delegation
//      records its subject as delegated, in product and in development.
//   T2. an OnBehalfOf SAML 1.1 assertion about the person carries the
//      AppliesTo application's SAML 1.1 attributes exactly as SAML 1.1 SSO
//      to that application does.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_wstrust_register");
const S = require("./saml_wire_kit.js").samlKit(K);
const W = require("./wstrust_wire_kit.js").wsKit(K);

const log = K.log;
const PASSWORD = "Wsr-Passw0rd!-" + K.rand(4);
const SECRET = "wsr-front-secret-" + K.rand(12);
const DELEGATED_METHOD = "OnBehalfOf / ActAs (delegated)";
const URL_OF = function (name) {
  log.debug("Entering URL_OF().");
  log.debug("Leaving URL_OF().");
  return "https://" + name + "-" + K.STAMP + ".example";
};
const BACK = URL_OF("wsr-back");
const FRONT = URL_OF("wsr-front");

async function api(id, path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.ok(K.rb(id) + "/admin-api" + path, body, path);
}

async function fixtures(id) {
  log.debug("Entering fixtures(). " + id);
  for (const who of ["wsr-alice", "wsr-carl", "wsr-dana", "wsr-erin"]) {
    await K.person(id, who, PASSWORD);
  }
  await api(id, "/users/set-not-delegated", { user: "wsr-carl",
                                              value: true });
  await api(id, "/groups/create", { group: "wsr-team" });
  await api(id, "/groups/add-member", { group: "wsr-team",
                                        member: "wsr-alice" });
  await api(id, "/saml-attributes/replace", { set: "saml11",
    claims: [{ name: "realm-flag", value: "on" }] });
  await api(id, "/applications/create", { identifier: "wsr-back",
    name: "wsr-back", protocols: ["wstrust", "saml11"],
    fields: { wstrustAppliesTo: [BACK], samlEntityId: [BACK],
              samlAssertionConsumerService: [BACK + "/shire"],
              appGroupsClaim: "TRUE" } });
  await api(id, "/applications/create", { identifier: "wsr-front",
    name: "wsr-front", protocols: ["wstrust", "oauth2"],
    fields: { oauthClientId: ["wsr-front"], oauthClientSecret: SECRET,
              wstrustAppliesTo: [FRONT], samlEntityId: FRONT,
              appAllowedToDelegateTo: ["wsr-back"],
              appDelegationSemantics: ["delegation", "impersonation"] } });
  log.debug("Leaving fixtures().");
}

function idOf(t) {
  log.debug("Entering idOf().");
  log.debug("Leaving idOf().");
  return t.jwt ? String((K.decode(t.jwt).payload || {}).jti || "")
    : ((/<saml:Assertion[^>]*\bID="([^"]+)"/.exec(t.inner) ||
        /AssertionID="([^"]+)"/.exec(t.inner) || [])[1] || "");
}

async function actFor(id, produced) {
  log.debug("Entering actFor().");
  let found = null;
  for (let i = 0; i < 20 && !found; i += 1) {
    const r = await K.send(K.rb(id) + "/admin-api/delegation?q=" +
                           "wsr-alice&per=200");
    found = ((r.json || {}).acts || []).filter(function (row) {
      return (row.produced || []).some(function (one) {
        return one.identifier === produced;
      });
    })[0] || null;
    if (!found) {
      await K.sleep(150);
    }
  }
  log.debug("Leaving actFor(). " + !!found);
  return found || {};
}

// ---------------------------------------------------------------------- N
async function register(id, product) {
  log.debug("Entering register(). " + id);
  const m = product ? "product" : "development";
  log.info("=== N. the register's rows, " + m + " ===");
  for (const [element, tokenType, note] of [
    ["ActAs", W.SAML2, /Delegation Restriction/],
    ["ActAs", W.JWT, /nested `act` claim/],
    ["OnBehalfOf", W.SAML2, /the assertion names the subject and adds nobody/],
    ["OnBehalfOf", W.JWT, /the JWT names the subject and adds nobody/]]) {
    const front = await W.issue(id, "wsr-front", SECRET, K.rb(id), W.SAML2);
    const alice = await W.issue(id, "wsr-alice", PASSWORD, FRONT, W.SAML2);
    const r = await W.post(id, { security: front.assertion, appliesTo: BACK,
      tokenType: tokenType, body: (element === "ActAs" ? W.actAs
                                                       : W.onBehalfOf)(
        alice.assertion) });
    const t = W.tokenOf(r, element + " " + tokenType);
    const act = await actFor(id, idOf(t));
    const label = m + ", " + element + ", " +
                  (tokenType === W.JWT ? "JWT" : "SAML");
    const consumed = String(((act.consumed || []).filter(function (c) {
      return c.kind === "delegated token";
    })[0] || {}).note || "");
    K.check("N3 (" + label + "). the consumed assertion's note says whether " +
            "it was verified", function () {
      assert.ok(product
        ? /VERIFIED against this realm's own signing certificate/
          .test(consumed)
        : /NOT verified/.test(consumed), consumed + " / " +
        JSON.stringify(act).slice(0, 400));
    });
    const tag = element === "ActAs" ? "<wst14:ActAs>" : "<wst:OnBehalfOf>";
    const said = String(act.authorizedBy || "");
    K.check("N4 (" + label + "). authorizedBy names the application the " +
            "AppliesTo names and the token inside " + tag, function () {
      assert.ok(said.indexOf('", the application the AppliesTo names (the ' +
                             "token inside " + tag + " was issued for ") > 0,
                said);
      assert.ok(said.indexOf("subject token") < 0, said);
    });
    K.check((element === "ActAs" ? "N1" : "N2") + " (" + label + "). the " +
            "act's note says what the token issued carries", function () {
      assert.ok(note.test(String(act.note || "")), String(act.note));
    });
  }
  log.debug("Leaving register().");
}

// ---------------------------------------------------------------------- D
async function delegatedRow(id, who) {
  log.debug("Entering delegatedRow(). " + who);
  const r = await K.send(K.rb(id) + "/admin-api/users?user=" +
                         encodeURIComponent(who));
  const text = JSON.stringify(r.json || {});
  log.debug("Leaving delegatedRow().");
  return { listed: text.indexOf(who) >= 0,
           delegated: text.indexOf(DELEGATED_METHOD) >= 0, text: text };
}

async function users(P, D) {
  log.debug("Entering users().");
  log.info("=== D. the delegated subject on /admin-api/users ===");
  const ask = async function (id, who, element) {
    log.debug("Entering ask().");
    const front = await W.issue(id, "wsr-front", SECRET, K.rb(id), W.SAML2);
    const inner = await W.issue(id, who, PASSWORD, FRONT, W.SAML2);
    log.debug("Leaving ask().");
    return W.post(id, { security: front.assertion, appliesTo: BACK,
      tokenType: W.SAML2, body: (element === "ActAs" ? W.actAs
                                                     : W.onBehalfOf)(
        inner.assertion) });
  };
  const c = await K.coded(P, "STS-WSTRUST-0018", function () {
    return ask(P, "wsr-carl", "ActAs");
  });
  const carl = await delegatedRow(P, "wsr-carl");
  K.check("D1. product: a delegation the policy refused (STS-WSTRUST-0018) " +
          "leaves its subject without the delegated method", function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
    assert.ok(!carl.delegated, carl.text.slice(0, 600));
  });
  const front = await delegatedRow(P, "wsr-front");
  K.check("D2. and the requester, who did authenticate, is listed",
          function () {
            assert.ok(front.listed, front.text.slice(0, 600));
          });
  const ok = await ask(P, "wsr-dana", "ActAs");
  let dana = await delegatedRow(P, "wsr-dana");
  for (let i = 0; i < 10 && !dana.delegated; i += 1) {
    await K.sleep(200);
    dana = await delegatedRow(P, "wsr-dana");
  }
  K.check("D3. product: an allowed delegation records its subject, as a " +
          "delegated subject", function () {
    assert.strictEqual(ok.status, 200, K.shown(ok));
    assert.ok(dana.delegated, dana.text.slice(0, 600));
  });
  const dev = await ask(D, "wsr-erin", "OnBehalfOf");
  let erin = await delegatedRow(D, "wsr-erin");
  for (let i = 0; i < 10 && !erin.delegated; i += 1) {
    await K.sleep(200);
    erin = await delegatedRow(D, "wsr-erin");
  }
  K.check("D4. development: an anonymous OnBehalfOf is issued, and its " +
          "subject recorded as delegated", function () {
    assert.strictEqual(dev.status, 200, K.shown(dev));
    assert.ok(erin.delegated, erin.text.slice(0, 600));
  });
  log.debug("Leaving users().");
}

// --------------------------------------------------------------------- T2
function attributes11(xml) {
  log.debug("Entering attributes11().");
  const out = {};
  const re = /<saml:Attribute AttributeName="([^"]+)" AttributeNamespace="([^"]+)">([\s\S]*?)<\/saml:Attribute>/g;
  let m = re.exec(String(xml || ""));
  while (m) {
    const values = [];
    m[3].replace(/<saml:AttributeValue[^>]*>([^<]*)</g, function (all, v) {
      values.push(v);
      return all;
    });
    out[m[2] + " " + m[1]] = values.sort();
    m = re.exec(String(xml || ""));
  }
  log.debug("Leaving attributes11(). " + Object.keys(out).length);
  return out;
}

async function saml11Attributes(id, product) {
  log.debug("Entering saml11Attributes().");
  const m = product ? "product" : "development";
  const b = K.browser();
  const sso = await S.drive(id, b, K.rb(id) + "/saml11/sso?" +
    new URLSearchParams({ providerId: "wsr-back", shire: BACK + "/shire",
                          TARGET: BACK + "/app" }).toString(),
  { username: "wsr-alice", password: PASSWORD });
  const viaSso = attributes11(S.messageOf(sso.final.text));
  const front = await W.issue(id, "wsr-front", SECRET, K.rb(id), W.SAML2);
  const alice = await W.issue(id, "wsr-alice", PASSWORD, FRONT, W.SAML2);
  const r = await W.post(id, { security: front.assertion, appliesTo: BACK,
    tokenType: W.SAML11, body: W.onBehalfOf(alice.assertion) });
  const viaTrust = attributes11(W.tokenOf(r, "the SAML 1.1 OnBehalfOf")
    .inner);
  K.check("T2 (" + m + "). an OnBehalfOf SAML 1.1 assertion about the " +
          "person carries the AppliesTo application's SAML 1.1 attributes " +
          "as SAML 1.1 SSO does: the groups and the realm's set, each " +
          "value for value", function () {
    assert.ok(Object.keys(viaSso).length > 0, K.shown(sso.final));
    assert.ok(Object.keys(viaSso).some(function (k) {
      return viaSso[k].indexOf("wsr-team") >= 0;
    }), JSON.stringify(viaSso));
    // The token carries the application's CONFIGURED attributes (the
    // groups, the realm's SAML 1.1 set); SSO adds the identity claims of
    // the profile on top. Each the token carries is the SSO's, value for
    // value.
    const keys = Object.keys(viaTrust);
    assert.ok(keys.some(function (k) {
      return viaTrust[k].indexOf("wsr-team") >= 0;
    }) && keys.some(function (k) {
      return / realm-flag$/.test(k) && viaTrust[k][0] === "on";
    }), JSON.stringify(viaTrust));
    keys.forEach(function (k) {
      assert.deepStrictEqual(viaTrust[k], viaSso[k], k);
    });
  });
  log.debug("Leaving saml11Attributes().");
}

async function test() {
  log.debug("Entering test().");
  const P = await K.realm("wsr-p", "product",
                          { "authn.allowOptionalSecondFactor": "true" });
  const D = await K.realm("wsr-d", "development");
  await fixtures(P);
  await fixtures(D);
  await register(D, false);
  await register(P, true);
  await users(P, D);
  await saml11Attributes(D, false);
  await saml11Attributes(P, true);
  log.debug("Leaving test().");
}

K.main(test, 30);
