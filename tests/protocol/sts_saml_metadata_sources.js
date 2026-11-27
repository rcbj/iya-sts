// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_metadata_sources.js
//
// ===========================================================================
// WHERE A SERVICE PROVIDER'S METADATA COMES FROM AFTER IT IS CONSUMED: THE
// REFRESH, TRUST ANCHORS, AGGREGATES, MDQ (#37 follow-up, #112; #444 D12,
// phase 7).
//
// `tests/saml_metadata_lifecycle.js` serves documents from a local HTTP
// server in its own process. Here the server is THIS job's listener, which
// the service dials at OUTBOUND_TEST_HOST (`test-peer` on a private probe):
// a development realm with `federation.outboundAllowHttp` on (a REALM
// setting) fetches from it, and the refresher is run through
// `/admin-api/scheduler/run`.
//
//   R. a document with a URL and cacheDuration PT0S is consumed (the act's
//      fetch), shown STALE and refreshable, still WORKS (an AuthnRequest goes
//      on to the sign-in screen and dials nothing); one run of
//      `saml2.sp-metadata-refresh` fetches it again and consumes the new
//      document; a run whose fetch FAILS changes nothing on the entry and
//      the old document keeps working; an UPLOADED stale document is shown
//      stale, not refreshable, and works.
//   T. a realm trust anchor (`saml2.metadataTrustAnchors`): an unsigned
//      document, and one signed by another key, are refused (STS-SAML-0065);
//      one signed by the anchor is VERIFIED; an EntitiesDescriptor signed as
//      a whole by the anchor is consumed for its entity, a tampered one
//      refused, and an unsigned aggregate whose ENTITY is anchor-signed is
//      consumed.
//   M. the Metadata Query Protocol (`saml2.mdqBaseUrl`): `mdq-import` asks
//      `<base>/entities/<percent-encoded entityID>`, CREATES the entry and
//      consumes the answer; a 404 imports nothing and creates no entry.
//   F. product (#112): an operator's import with no anchor is refused
//      (STS-SAML-0084) and dials nothing; an anonymous AuthnRequest from an
//      unknown entityID with MDQ configured and no anchor asks the
//      responder NOTHING (STS-SAML-0080), and the entityID is listed refused
//      on GET /admin-api/saml2; with the anchor rule set aside
//      (`saml2.mdqImportWithoutAnchors`), a plain-http responder refused for
//      product mode and an https one at the runner's (private) address by
//      the outbound policy (STS-SAML-0079), neither dialled.
//
// NOT HERE: the refresher's own schedule (a clock), the claim two nodes
// race for (cluster), and STS-SAML-0081 (a product realm with an anchor
// whose responder ANSWERS unsigned or foreign-signed): product's outbound
// policy refuses every address a test listener can have — a private one —
// so no responder of a job's is ever dialled in product.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_saml_metadata_sources");
const S = require("./saml_wire_kit.js").samlKit(K);
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const xmldsig = require(path.join(REPO, "common", "crypto_impl",
                                  "xmldsig.js"));

const log = K.log;
const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
let D = null;
let T = null;
let P = null;
let L = null;
const SERVED = {};

function entity(entityId, o) {
  log.debug("Entering entity().");
  const opts = o || {};
  log.debug("Leaving entity().");
  return '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="_e' +
    K.rand(6) + '" entityID="' + entityId + '"' +
    (opts.cache ? ' cacheDuration="' + opts.cache + '"' : "") +
    '><md:SPSSODescriptor protocolSupportEnumeration="' + S.NS_SAMLP +
    '"><md:AssertionConsumerService Binding="' + S.BINDING_POST +
    '" Location="' + (opts.acs || "https://" + K.STAMP + ".md.example/acs") +
    '" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>';
}

function aggregate(inner) {
  log.debug("Entering aggregate().");
  log.debug("Leaving aggregate().");
  return '<md:EntitiesDescriptor xmlns:md="' + NS_MD + '" ID="_a' +
    K.rand(6) + '" Name="urn:agg:' + K.STAMP + '">' +
    inner.replace(/ xmlns:md="[^"]*"/, "") + "</md:EntitiesDescriptor>";
}

function signed(xml, cred) {
  log.debug("Entering signed().");
  log.debug("Leaving signed().");
  return xmldsig.signEnveloped(xml, { privateKeyPem: cred.privateKeyPem,
                                      certPem: cred.certificatePem,
                                      placement: "first" });
}

async function app(realm, identifier, fields) {
  log.debug("Entering app(). " + identifier);
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: identifier, name: identifier, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier] }, fields || {}) },
  "created " + identifier);
  log.debug("Leaving app().");
  return identifier;
}

async function fieldsOf(realm, identifier) {
  log.debug("Entering fieldsOf().");
  const r = await K.send(K.rb(realm) + "/admin-api/applications?" +
                         "application=" + encodeURIComponent(identifier));
  log.debug("Leaving fieldsOf().");
  return ((r.json || {}).attributes) || ((r.json || {}).fields) || {};
}

async function view(realm, identifier) {
  log.debug("Entering view().");
  const r = await K.send(K.rb(realm) + "/admin-api/saml2?sp=" +
                         encodeURIComponent(identifier));
  log.debug("Leaving view().");
  return JSON.stringify(r.json || {});
}

function acsOf(f) {
  log.debug("Entering acsOf().");
  log.debug("Leaving acsOf().");
  return [].concat(f.samlAssertionConsumerService || []).join(" ");
}

function hitsOf(p) {
  log.debug("Entering hitsOf().");
  log.debug("Leaving hitsOf().");
  return L.hits.filter(function (one) {
    return one === p;
  }).length;
}

function serve(p, status, body) {
  log.debug("Entering serve(). " + p);
  SERVED[p] = { status: status, body: body };
  L.routes[p] = function (req, res) {
    const one = SERVED[p];
    res.writeHead(one.status, { "Content-Type":
                                "application/samlmetadata+xml" });
    res.end(one.body || "");
  };
  log.debug("Leaving serve().");
}

function ssoUrl(realm, issuer, acs) {
  log.debug("Entering ssoUrl().");
  log.debug("Leaving ssoUrl().");
  return S.redirect(K.rb(realm) + "/saml2/sso", S.authnRequestXml({
    issuer: issuer, acs: acs, destination: K.rb(realm) + "/saml2/sso" })
    .xml);
}

async function runRefresher(realm) {
  log.debug("Entering runRefresher().");
  const r = await K.send(K.rb(realm) + "/admin-api/scheduler/run",
    { json: { job: "saml2.sp-metadata-refresh", realm: realm } });
  assert.ok((r.status === 200 || r.status === 202) && r.json && r.json.ok,
            "the refresher did not run: " + K.shown(r));
  log.debug("Leaving runRefresher().");
  return r;
}

// --------------------------------------------------------------------- R
async function refresh() {
  log.debug("Entering refresh().");
  log.info("=== R. a stale document and the refresher ===");
  const one = "https://one-" + K.STAMP + ".md.example/acs";
  const two = "https://two-" + K.STAMP + ".md.example/acs";
  const sp = "sms-refreshed-" + K.STAMP;
  const at = "/md/" + sp + ".xml";
  serve(at, 200, entity(sp, { acs: one, cache: "PT0S" }));
  await app(D, sp, { samlSpMetadataUrl: L.origin + at });
  const first = await K.send(K.rb(D) + "/admin-api/saml2/refresh-metadata",
                             { json: { sp: sp } });
  let f = await fieldsOf(D, sp);
  K.check("R1. the act fetches the first document and consumes it",
          function () {
            assert.strictEqual(first.status, 200, K.shown(first));
            assert.ok(urls.namesAddress(acsOf(f), one), acsOf(f));
          });
  let v = await view(D, sp);
  K.check("R2. with cacheDuration PT0S it is STALE at once, and refreshable " +
          "because the entry names a URL", function () {
    assert.ok(/stale/i.test(v), v.slice(0, 600));
    assert.ok(/refreshable"\s*:\s*true/.test(v), v.slice(0, 600));
  });
  const hits = hitsOf(at);
  const works = await K.send(ssoUrl(D, sp, one));
  K.check("R3. a stale document still WORKS, and answering dialled NOTHING",
          function () {
            assert.ok(K.toSignIn(works), K.shown(works));
            assert.strictEqual(hitsOf(at), hits);
          });
  serve(at, 200, entity(sp, { acs: two, cache: "PT0S" }));
  await runRefresher(D);
  for (let i = 0; i < 60 && !urls.namesAddress(acsOf(f), two); i += 1) {
    await K.sleep(500);
    f = await fieldsOf(D, sp);
  }
  K.check("R4. one run of saml2.sp-metadata-refresh REFRESHED it from the " +
          "URL", function () {
    assert.ok(urls.namesAddress(acsOf(f), two), acsOf(f));
    assert.ok(hitsOf(at) > hits);
  });
  serve(at, 500, "");
  const failedHits = hitsOf(at);
  await runRefresher(D);
  for (let i = 0; i < 60 && hitsOf(at) === failedHits; i += 1) {
    await K.sleep(500);
  }
  await K.sleep(500);
  f = await fieldsOf(D, sp);
  v = await view(D, sp);
  K.check("R5. a run whose fetch FAILS changes NOTHING on the entry, and " +
          "the view records the failure", function () {
    assert.ok(hitsOf(at) > failedHits, "the run never dialled");
    assert.ok(urls.namesAddress(acsOf(f), two), acsOf(f));
    assert.ok(/fail|500/i.test(v), v.slice(0, 800));
  });
  const still = await K.send(ssoUrl(D, sp, two));
  K.check("R6. the last good document KEEPS WORKING", function () {
    assert.ok(K.toSignIn(still), K.shown(still));
  });
  const up = "sms-uploaded-" + K.STAMP;
  await app(D, up);
  const consumed = await K.send(K.rb(D) + "/admin-api/saml2/upload-metadata",
    { json: { sp: up, document: entity(up, { acs: one, cache: "PT0S" }) } });
  v = await view(D, up);
  const upWorks = await K.send(ssoUrl(D, up, one));
  K.check("R7. an UPLOADED document with cacheDuration PT0S is shown STALE, " +
          "is not refreshable, and WORKS", function () {
    assert.strictEqual(consumed.status, 200, K.shown(consumed));
    assert.ok(/stale/i.test(v), v.slice(0, 600));
    assert.ok(!/refreshable"\s*:\s*true/.test(v), v.slice(0, 600));
    assert.ok(K.toSignIn(upWorks), K.shown(upWorks));
  });
  log.debug("Leaving refresh().");
}

// --------------------------------------------------------------------- T
async function anchors(anchor, stranger) {
  log.debug("Entering anchors().");
  log.info("=== T. a realm trust anchor, and aggregates ===");
  await K.set(T, "saml2.metadataTrustAnchors",
              S.b64cert(anchor.certificatePem));
  const upload = function (sp, doc) {
    log.debug("Entering upload().");
    log.debug("Leaving upload().");
    return K.send(K.rb(T) + "/admin-api/saml2/upload-metadata",
                  { json: { sp: sp, document: doc } });
  };
  const sp = await app(T, "sms-anchored-" + K.STAMP);
  for (const [label, doc] of [
    ["T1. an UNSIGNED document", entity(sp)],
    ["T2. one signed by another key", signed(entity(sp), stranger)]]) {
    const c = await K.coded(T, "STS-SAML-0065", function () {
      return upload(sp, doc);
    });
    K.check(label + " is refused with a realm anchor set, STS-SAML-0065",
            function () {
              assert.ok(c.answer.status >= 400, K.shown(c.answer));
              assert.ok(c.rose >= 1);
            });
  }
  const good = await upload(sp, signed(entity(sp), anchor));
  let f = await fieldsOf(T, sp);
  K.check("T3. one signed by the realm anchor is VERIFIED and consumed",
          function () {
            assert.strictEqual(good.status, 200, K.shown(good));
            assert.strictEqual([].concat(f.samlSpMetadataSignature).join(),
                               "verified");
          });
  const agg = await app(T, "sms-agg-" + K.STAMP);
  const aggAcs = "https://agg-" + K.STAMP + ".md.example/acs";
  const whole = signed(aggregate(entity(agg, { acs: aggAcs })), anchor);
  const tampered = await upload(agg, whole.replace(aggAcs,
    "https://evil-" + K.STAMP + ".md.example/acs"));
  K.check("T4. a tampered anchor-signed aggregate is refused", function () {
    assert.ok(tampered.status >= 400, K.shown(tampered));
  });
  const aggOk = await upload(agg, whole);
  f = await fieldsOf(T, agg);
  K.check("T5. an EntitiesDescriptor SIGNED AS A WHOLE by the anchor is " +
          "consumed for its entity", function () {
    assert.strictEqual(aggOk.status, 200, K.shown(aggOk));
    assert.ok(urls.namesAddress(acsOf(f), aggAcs), acsOf(f));
  });
  const inner = await app(T, "sms-inner-" + K.STAMP);
  const innerAcs = "https://inner-" + K.STAMP + ".md.example/acs";
  const innerOk = await upload(inner, aggregate(signed(entity(inner,
    { acs: innerAcs }), anchor)));
  f = await fieldsOf(T, inner);
  K.check("T6. an unsigned aggregate whose ENTITY is signed by the anchor " +
          "is consumed", function () {
    assert.strictEqual(innerOk.status, 200, K.shown(innerOk));
    assert.ok(urls.namesAddress(acsOf(f), innerAcs), acsOf(f));
  });
  log.debug("Leaving anchors().");
}

// --------------------------------------------------------------------- M
async function mdq() {
  log.debug("Entering mdq().");
  log.info("=== M. the Metadata Query Protocol ===");
  await K.set(D, "saml2.mdqBaseUrl", L.origin + "/mdq/");
  const name = "https://mdq-" + K.STAMP + ".md.example/saml";
  const at = "/mdq/entities/" + encodeURIComponent(name);
  const acs = "https://mdq-" + K.STAMP + ".md.example/acs";
  serve(at, 200, entity(name, { acs: acs }));
  const imported = await K.send(K.rb(D) + "/admin-api/saml2/mdq-import",
                                { json: { sp: name } });
  const f = await fieldsOf(D, name);
  K.check("M1. an import asks <base>/entities/<percent-encoded entityID>, " +
          "CREATES the entry and consumes the answer", function () {
    assert.strictEqual(imported.status, 200, K.shown(imported));
    assert.strictEqual(hitsOf(at), 1, JSON.stringify(L.hits.slice(-4)));
    assert.ok(urls.namesAddress(acsOf(f), acs), acsOf(f));
  });
  const ghost = "https://ghost-" + K.STAMP + ".md.example/saml";
  const ghostAt = "/mdq/entities/" + encodeURIComponent(ghost);
  serve(ghostAt, 404, "");
  const missing = await K.send(K.rb(D) + "/admin-api/saml2/mdq-import",
                               { json: { sp: ghost } });
  const after = await K.send(K.rb(D) + "/admin-api/applications?" +
                             "application=" + encodeURIComponent(ghost));
  K.check("M2. a 404 imports nothing and creates no entry", function () {
    assert.ok(missing.status >= 400, K.shown(missing));
    assert.strictEqual(hitsOf(ghostAt), 1);
    assert.ok(after.status === 404 || !(after.json || {}).application,
              K.shown(after));
  });
  log.debug("Leaving mdq().");
}

// --------------------------------------------------------------------- F
async function product() {
  log.debug("Entering product().");
  log.info("=== F. what an unknown service provider can cause (product) ===");
  await K.set(P, "saml2.mdqBaseUrl", L.origin + "/mdq/");
  const op = "https://op-" + K.STAMP + ".md.example/saml";
  const opAt = "/mdq/entities/" + encodeURIComponent(op);
  serve(opAt, 200, entity(op));
  const c = await K.coded(P, "STS-SAML-0084", function () {
    return K.send(K.rb(P) + "/admin-api/saml2/mdq-import",
                  { json: { sp: op } });
  });
  K.check("F1. PRODUCT, no anchor: an operator import is REFUSED, " +
          "STS-SAML-0084, and dials nothing", function () {
    assert.ok(c.answer.status >= 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
    assert.strictEqual(hitsOf(opAt), 0);
  });
  const stranger = "https://stranger-" + K.STAMP + ".md.example/saml";
  const strangerAt = "/mdq/entities/" + encodeURIComponent(stranger);
  serve(strangerAt, 200, entity(stranger));
  const r = await K.coded(P, "STS-SAML-0080", function () {
    return K.send(ssoUrl(P, stranger, undefined));
  });
  await K.sleep(1000);
  const listed = await K.send(K.rb(P) + "/admin-api/saml2");
  K.check("F2. PRODUCT, no anchor: an anonymous AuthnRequest from an unknown " +
          "entityID asks the MDQ responder NOTHING, STS-SAML-0080",
  function () {
    assert.ok(!K.toSignIn(r.answer), K.shown(r.answer));
    assert.strictEqual(hitsOf(strangerAt), 0);
    assert.ok(r.rose >= 1);
  });
  K.check("F3. and the entityID is listed as refused on GET " +
          "/admin-api/saml2, with no code in the answer", function () {
    const text = JSON.stringify(listed.json || {});
    assert.ok(urls.namesAddress(text, stranger), listed.text.slice(0, 600));
    const row = text.slice(text.indexOf(stranger) - 200,
                           text.indexOf(stranger) + 300);
    assert.ok(!/STS-SAML-0080/.test(row), row);
  });
  // saml_metadata_lifecycle 0079: with the anchor rule set aside
  // (`saml2.mdqImportWithoutAnchors`) only the transport is left to refuse.
  // A plain-http responder is refused for product mode whatever
  // federation.outboundAllowHttp says; an https one at the runner's (a
  // private) address is refused by the outbound policy, STS-SAML-0079 —
  // and neither is dialled.
  await K.set(P, "saml2.mdqImportWithoutAnchors", true);
  // federation.outboundAllowHttp on, as the in-process file has it: product
  // refuses plain http whatever it says.
  const allowed = await K.send(K.base + "/admin-api/realms/set", { json: {
    id: P, key: "federation.outboundAllowHttp", value: "true" } });
  const plain = await K.send(K.rb(P) + "/admin-api/saml2/mdq-import",
                             { json: { sp: op } });
  await K.set(P, "saml2.mdqBaseUrl", L.origin.replace(/^http:/, "https:") +
              "/mdq/");
  const policy = await K.coded(P, "STS-SAML-0079", function () {
    return K.send(K.rb(P) + "/admin-api/saml2/mdq-import",
                  { json: { sp: op } });
  });
  await K.unset(P, "saml2.mdqImportWithoutAnchors");
  if (allowed.status === 200) {
    await K.unset(P, "federation.outboundAllowHttp");
  }
  K.check("F4. PRODUCT, anchors set aside: a plain-http responder is " +
          "refused for product mode, and an https one at the runner's " +
          "address by the outbound policy (STS-SAML-0079); nothing is " +
          "dialled", function () {
    assert.ok(plain.status >= 400, K.shown(plain));
    assert.ok(allowed.status !== 200 || /product mode/.test(plain.text),
              plain.text.slice(0, 300));
    assert.ok(!/trust anchor/.test(plain.text));
    assert.ok(policy.answer.status >= 400, K.shown(policy.answer));
    assert.ok(policy.rose >= 1, "no STS-SAML-0079 row");
    assert.strictEqual(hitsOf(opAt), 0);
  });
  log.debug("Leaving product().");
}

async function test() {
  log.debug("Entering test().");
  L = await K.listener({});
  D = await K.realm("sms-d", "development",
                    { "federation.outboundAllowHttp": "true" });
  T = await K.realm("sms-t", "development");
  P = await K.realm("sms-p", "product");
  const anchor = await S.credential("sms-anchor");
  const stranger = await S.credential("sms-stranger");
  try {
    await refresh();
    await anchors(anchor, stranger);
    await mdq();
    await product();
  } finally {
    L.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 19);
