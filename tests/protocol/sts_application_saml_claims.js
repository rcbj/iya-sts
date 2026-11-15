// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_saml_claims.js
//
// ===========================================================================
// WHAT AN APPLICATION'S OWN CLAIM SETTINGS PUT IN A REAL SAML ASSERTION, OVER
// THE WIRE (#444 D12, phase 7).
//
// `sts_application_claims.js` carries the OAuth halves of five in-process
// files out of real tokens and left the SAML halves to this phase. They are
// here, read out of assertions this job obtains from the realm's own SAML
// 2.0 identity provider (an AuthnRequest on the Redirect binding, a person
// signed in at the screen, the Response off the POST form) and its SAML
// 1.1 Browser/POST profile, the settings written through `/admin-api`:
//
//   C. application_claims.js C: an application's own SAML attribute row
//      wins by name for its audience — SAML 2.0 with its NameFormat, SAML
//      1.1 with its namespace — and another audience gets the realm's;
//   S. application_claim_selections.js C: a service provider's own
//      selection of directory attributes for SAML 2.0 replaces the realm's
//      for its audience, and another audience keeps the realm's;
//   D. custom_attribute_claims.js D: a realm's custom attributes (an
//      integer, a multi-valued string, a date) selected for SAML 2.0 are
//      carried as text, the multi-valued one as one attribute with a value
//      each.
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_application_saml_claims");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const SP = "https://asc-sp-" + K.STAMP + ".example.test/sp";
const SP_ACS = "https://asc-sp-" + K.STAMP + ".example.test/acs";
const OTHER = "https://asc-other-" + K.STAMP + ".example.test/sp";
const OTHER_ACS = "https://asc-other-" + K.STAMP + ".example.test/acs";
const PERSON = "asc-alice";
const PASSWORD = "Asc-Passw0rd!-" + K.rand(3);
let D = null;

function api(path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.ok(K.rb(D) + "/admin-api" + path, body, path);
}

// The attributes of an assertion: name to { format, namespace, values }.
function attributesOf(xml) {
  log.debug("Entering attributesOf().");
  const out = {};
  const re = /<(?:saml:)?Attribute\s([^>]*)>([\s\S]*?)<\/(?:saml:)?Attribute>/g;
  let m = re.exec(xml || "");
  while (m) {
    const name = (/(?:^|\s)(?:Name|AttributeName)="([^"]+)"/.exec(m[1]) ||
                  [])[1];
    const values = [...m[2].matchAll(
      /<(?:saml:)?AttributeValue[^>]*>([^<]*)</g)].map(function (v) {
      return v[1];
    });
    if (name) {
      out[name] = { format: (/NameFormat="([^"]+)"/.exec(m[1]) || [])[1],
                    namespace: (/AttributeNamespace="([^"]+)"/.exec(m[1]) ||
                                [])[1], values: values };
    }
    m = re.exec(xml || "");
  }
  log.debug("Leaving attributesOf().");
  return out;
}

async function saml2For(issuer, acs) {
  log.debug("Entering saml2For(). " + issuer);
  const built = S.authnRequestXml({ issuer: issuer, acs: acs });
  const got = await S.drive(D, K.browser(), S.redirect(K.rb(D) +
    "/saml2/sso", built.xml), { username: PERSON, password: PASSWORD });
  assert.ok(got.response, "no Response for " + issuer + ": " +
            K.shown(got.final));
  log.debug("Leaving saml2For().");
  return attributesOf(got.response.xml);
}

async function saml11For(provider, shire) {
  log.debug("Entering saml11For(). " + provider);
  const got = await S.drive(D, K.browser(), K.rb(D) + "/saml11/sso?" +
    new URLSearchParams({ providerId: provider, shire: shire,
                          TARGET: "https://asc.example.test/app" })
      .toString(), { username: PERSON, password: PASSWORD });
  const xml = S.messageOf(got.final.text) || "";
  assert.ok(xml, "no SAML 1.1 Response for " + provider + ": " +
            K.shown(got.final));
  log.debug("Leaving saml11For().");
  return attributesOf(xml);
}

async function setUp() {
  log.debug("Entering setUp().");
  D = await K.realm("asc", "development");
  for (const one of [
    { name: "costCentreCode", label: "Cost centre", syntax: "integer" },
    { name: "badgeIds", label: "Badges", syntax: "string",
      multiValued: true },
    { name: "hiredOn", label: "Hired on", syntax: "date" }]) {
    await api("/policies/define-person-attribute", one);
  }
  await api("/users/create", { username: PERSON, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Alice " + K.STAMP, givenName: "Alice", sn: "Person",
                  mail: PERSON + "@asc.example.test", costCentreCode: "42",
                  badgeIds: ["b-1", "b-2"], hiredOn: "20260131" } });
  for (const [id, acs] of [[SP, SP_ACS], [OTHER, OTHER_ACS]]) {
    await api("/applications/create", { identifier: id, name: id,
      protocols: ["saml2", "saml11"],
      fields: { samlEntityId: [id], samlAssertionConsumerService: [acs] } });
  }
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  log.info("=== C. an application's own SAML attribute rows ===");
  for (const set of ["saml2", "saml11"]) {
    await api("/saml-attributes/replace", { set: set,
      claims: [{ name: "tenant", value: "realm" }] });
  }
  await api("/applications/set-custom-claim", { application: SP,
    set: "saml2", name: "tenant", value: "sp",
    nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" });
  await api("/applications/set-custom-claim", { application: SP,
    set: "saml11", name: "tenant", value: "sp11",
    namespace: "urn:example:claims" });
  const sp2 = await saml2For(SP, SP_ACS);
  const other2 = await saml2For(OTHER, OTHER_ACS);
  K.check("C1. SAML 2.0: the service provider's attribute wins by name, " +
          "with its NameFormat; another audience gets the realm's",
  function () {
    assert.deepStrictEqual((sp2.tenant || {}).values, ["sp"],
                           JSON.stringify(sp2));
    assert.strictEqual(sp2.tenant.format,
                       "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
    assert.deepStrictEqual((other2.tenant || {}).values, ["realm"],
                           JSON.stringify(other2));
  });
  const sp11 = await saml11For(SP, SP_ACS);
  const other11 = await saml11For(OTHER, OTHER_ACS);
  K.check("C2. SAML 1.1: the same, with its namespace", function () {
    assert.deepStrictEqual((sp11.tenant || {}).values, ["sp11"],
                           JSON.stringify(sp11));
    assert.strictEqual(sp11.tenant.namespace, "urn:example:claims");
    assert.deepStrictEqual((other11.tenant || {}).values, ["realm"],
                           JSON.stringify(other11));
  });
  log.info("=== S, D. selections and custom attributes for SAML 2.0 ===");
  await api("/saml-attributes/attributes", { set: "saml2",
    attributes: ["mail",
    "costCentreCode", "badgeIds", "hiredOn"] });
  await api("/applications/set-claim-attributes", { application: SP,
    set: "saml2", attributes: ["givenName"] });
  const spSel = await saml2For(SP, SP_ACS);
  const otherSel = await saml2For(OTHER, OTHER_ACS);
  // The selection's attributes go by their claim names (`given_name`,
  // `email`) beside the identity attributes every assertion carries.
  K.check("S1. SAML 2.0: the service provider's selection replaces the " +
          "realm's by audience; another audience keeps the realm's",
  function () {
    assert.ok("given_name" in spSel, JSON.stringify(Object.keys(spSel)));
    assert.ok(!("email" in spSel) && !("costCentreCode" in spSel),
              JSON.stringify(Object.keys(spSel)));
    assert.ok("email" in otherSel && !("given_name" in otherSel),
              JSON.stringify(Object.keys(otherSel)));
  });
  K.check("D1. an assertion carries the realm's custom attributes as text, " +
          "the multi-valued one as one attribute with a value each",
  function () {
    assert.deepStrictEqual((otherSel.costCentreCode || {}).values, ["42"],
                           JSON.stringify(otherSel));
    assert.deepStrictEqual((otherSel.badgeIds || {}).values, ["b-1", "b-2"]);
    assert.deepStrictEqual((otherSel.hiredOn || {}).values, ["2026-01-31"]);
  });
  log.debug("Leaving test().");
}

K.main(test, 4);
