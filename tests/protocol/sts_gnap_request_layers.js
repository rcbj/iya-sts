// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_request_layers.js
//
// ===========================================================================
// WHICH LAYER REFUSES A GNAP DOCUMENT, OVER THE WIRE (#444 D12 phase 8).
//
// `tests/gnap_request.js` holds `validation.checkDocument()`'s bounds, the
// ajv schemas of `gnap/gnap_schemas.ts` and the RFC walker of
// `gnap/gnap_request.ts` as functions. Over HTTP all three answer 400
// invalid_request, so this job tells them apart by the code each records on
// `/admin-api/audit`:
//
//   B. the envelope: a body that is not an object (STS-GNAP-0052) at the
//      grant, continuation and introspection endpoints; a document nested
//      forty deep (STS-GNAP-0053, the bound, not the schema); a type error
//      (STS-GNAP-0061, the schema, not the walker);
//   A. the schemas, each by STS-GNAP-0061: a numeric label, a BEL in
//      class_id, a DEL in a display name, a display name of 100,000
//      characters, five thousand rights, a finish uri that is not a URI, an
//      access right with two hundred members, a numeric access_token at
//      introspection, a string token_introspection_required at
//      registration, a numeric interact.acr, a numeric interact_ref at a
//      continuation; and what passes: a data: logo, a string and an array
//      interact.acr with an unknown sibling;
//   C. the walker, by its own codes: interact_ref on a new request
//      (STS-GNAP-0054), two tokens with one label (0032), an unlabelled
//      token among several (0026), a hash_method outside the registry
//      (0050), a modification carrying client (0059), an email sub_id with
//      no email (0036) and an unknown format (0034), a key with no proof
//      method (0001 or 0002), a key with both jwk and cert#S256 (0007), a
//      JWK with no kid (0012), an unknown proof method (0001).
//
// (d), with the reason: section A's "schema published with an $id" and "an
// unknown schema name validates nothing" are the module's table; D's
// eap/forceKey/phishingClass split is the walker's return value (its
// outcome is `sts_gnap_interaction`'s step-up); the RFC 9635 4.2.3 hash
// examples and the RFC 7638 thumbprint are functions (every redirect dance
// in the GNAP jobs verifies a hash the service computed).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_request_layers");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Req-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gr-photos";

let realm = null;
let h = null;
let c = null;

function grant(extra) {
  log.debug("Entering grant().");
  const b = h.grantBody(c, { access_token: { access: [{ type: TYPE,
                                                       actions: ["read"] }] }
  });
  Object.keys(extra || {}).forEach(function (k) {
    b[k] = extra[k];
  });
  log.debug("Leaving grant().");
  return b;
}

// A document sent and refused by `code`: answers the response.
async function refusedBy(code, what, url, doc, opts) {
  log.debug("Entering refusedBy(). " + code);
  const o = opts || {};
  const sender = o.client || c;
  const coded = await K.coded(realm, code, function () {
    return sender.send(o.method || "POST", url || h.GRANT,
                       Object.assign({ json: doc }, o.send || {}));
  });
  check(what + " (" + code + ")", function () {
    assert.strictEqual(coded.answer.status, o.status || 400,
                       coded.answer.text);
    if (o.error !== null) {
      assert.strictEqual(G.errorOf(coded.answer), o.error ||
                         "invalid_request", coded.answer.text);
    }
    assert.strictEqual(coded.answer.headers["cache-control"], "no-store");
    assert.ok(coded.rose >= 1, code + " rose " + coded.rose);
  });
  log.debug("Leaving refusedBy().");
  return coded.answer;
}

async function accepted(what, doc) {
  log.debug("Entering accepted().");
  const r = await c.send("POST", h.GRANT, { json: doc });
  check(what, function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  log.debug("Leaving accepted().");
  return r;
}

function withKey(key) {
  log.debug("Entering withKey().");
  log.debug("Leaving withKey().");
  return { key: key, display: { name: "GNAP job",
                                uri: "https://client.gnap.test/" } };
}

async function envelope() {
  log.debug("Entering envelope().");
  log.info("=== B. the envelope ===");
  await refusedBy("STS-GNAP-0052", "B1. a grant request that is a JSON " +
                  "array is refused before any schema", h.GRANT, [grant()]);
  await refusedBy("STS-GNAP-0052", "B1b. and one that is a JSON string",
                  h.GRANT, "\"not an object\"");
  let deep = { v: 1 };
  for (let i = 0; i < 40; i += 1) {
    deep = { d: deep };
  }
  await refusedBy("STS-GNAP-0053", "B2. a document nested forty deep is " +
                  "refused by the bound, not the schema", h.GRANT,
                  grant({ access_token: { access: [{ type: TYPE,
                                                     deep: deep }] } }));
  const typed = await refusedBy("STS-GNAP-0061", "B3. a type error (a " +
                  "numeric label) is refused by the schema layer",
                  h.GRANT, grant({ access_token: { access: [TYPE],
                                                   label: 42 } }));
  check("B3b. and the description says it was the schema", function () {
    assert.ok(/schema/i.test(JSON.stringify(typed.json)), typed.text);
  });
  const rs = G.client();
  await refusedBy("STS-GNAP-0052", "B4. an introspection request that is " +
                  "an array", h.realmBase + "/gnap/introspect", [1],
                  { client: rs });
  log.debug("Leaving envelope().");
}

async function schemas() {
  log.debug("Entering schemas().");
  log.info("=== A. the schemas ===");
  const key = c.keyObject();
  await refusedBy("STS-GNAP-0061", "A1. a BEL in class_id is refused by " +
                  "the schema", h.GRANT, grant({ client: Object.assign(
                    withKey(key), { class_id: "bad\u0007class" }) }));
  await refusedBy("STS-GNAP-0061", "A2. DEL is a control character too",
                  h.GRANT, grant({ client: { key: key,
                                             display: { name: "x\u007fy" } }
                  }));
  await refusedBy("STS-GNAP-0061", "A3. a display name of 100,000 " +
                  "characters exceeds its maxLength", h.GRANT,
                  grant({ client: { key: key,
                                    display: { name: "x".repeat(100000) } }
                  }));
  await refusedBy("STS-GNAP-0061", "A4. five thousand access rights " +
                  "exceed the array bound", h.GRANT,
                  grant({ access_token: { access:
                    new Array(5000).fill(TYPE) } }));
  await refusedBy("STS-GNAP-0061", "A5. a finish uri that is not a URI " +
                  "fails format uri", h.GRANT,
                  grant({ interact: { start: ["redirect"],
                    finish: { method: "redirect", uri: "not a uri",
                              nonce: "n1" } } }));
  const wide = { type: TYPE };
  for (let i = 0; i < 200; i += 1) {
    wide["m" + i] = "v";
  }
  await refusedBy("STS-GNAP-0061", "A6. an access right with two hundred " +
                  "members exceeds maxProperties", h.GRANT,
                  grant({ access_token: { access: [wide] } }));
  await refusedBy("STS-GNAP-0061", "A7. a numeric interact.acr fails the " +
                  "schema", h.GRANT, grant({ interact: { start: ["redirect"],
                    acr: 7, finish: { method: "redirect", uri: h.FINISH,
                                      nonce: "n2" } } }));
  const rs = G.client();
  await refusedBy("STS-GNAP-0061", "A8. a numeric access_token fails the " +
                  "introspection schema", h.realmBase + "/gnap/introspect",
                  { access_token: 7, resource_server: { key:
                    rs.keyObject() } }, { client: rs });
  await refusedBy("STS-GNAP-0061", "A9. a string " +
                  "token_introspection_required fails the registration " +
                  "schema", h.realmBase + "/gnap/resource",
                  { access: [TYPE], resource_server: { key: rs.keyObject() },
                    token_introspection_required: "yes" }, { client: rs });
  await accepted("A10. a data: image logo is legitimate (RFC 9635 section " +
                 "2.3.2)", grant({ client: { key: key, display: {
                   name: "ok", logo_uri:
                     "data:image/png;base64,iVBORw0KGgo=" } } }));
  await accepted("A11. a string interact.acr passes the schema",
                 grant({ interact: { start: ["redirect"], acr: "phr",
                   finish: { method: "redirect", uri: h.FINISH,
                             nonce: "n3" } } }));
  await accepted("A12. an array interact.acr and an unknown sibling pass",
                 grant({ interact: { start: ["redirect"],
                   acr: ["phr", "phrh"], extension_member: true,
                   finish: { method: "redirect", uri: h.FINISH,
                             nonce: "n4" } } }));
  log.debug("Leaving schemas().");
}

async function walker() {
  log.debug("Entering walker().");
  log.info("=== C. the walker ===");
  const key = c.keyObject();
  await refusedBy("STS-GNAP-0054", "C1. interact_ref on a new request is " +
                  "refused (section 5.1)", h.GRANT,
                  grant({ interact_ref: "ref-1" }));
  await refusedBy("STS-GNAP-0032", "C2. two tokens with one label are " +
                  "refused", h.GRANT, grant({ access_token: [
                    { label: "a", access: [TYPE] },
                    { label: "a", access: [TYPE] }] }));
  await refusedBy("STS-GNAP-0026", "C3. an unlabelled token among several " +
                  "is refused (section 2.1.2)", h.GRANT,
                  grant({ access_token: [{ label: "a", access: [TYPE] },
                                         { access: [TYPE] }] }));
  await refusedBy("STS-GNAP-0050", "C4. a hash_method outside the Named " +
                  "Information registry is refused", h.GRANT,
                  grant({ interact: { start: ["redirect"],
                    finish: { method: "redirect", uri: h.FINISH,
                              nonce: "n5", hash_method: "md4" } } }));
  await refusedBy("STS-GNAP-0036", "C5. an email sub_id with no email is " +
                  "refused", h.GRANT, grant({ subject: {
                    sub_id_formats: ["opaque"] },
                    user: { sub_ids: [{ format: "email" }] } }));
  await refusedBy("STS-GNAP-0034", "C6. a sub_id of a format RFC 9493 does " +
                  "not define is refused", h.GRANT, grant({ subject: {
                    sub_id_formats: ["opaque"] },
                    user: { sub_ids: [{ format: "nonsense" }] } }));
  const noProof = Object.assign({}, key);
  delete noProof.proof;
  const r = await c.send("POST", h.GRANT, { json: grant({ client:
    withKey(noProof) }) });
  check("C7. a key with no proof method is refused invalid_request",
        function () {
    assert.ok(r.status === 400 || r.status === 401, r.text);
    assert.ok(/^invalid_/.test(G.errorOf(r)), r.text);
  });
  await refusedBy("STS-GNAP-0007", "C8. a key by value in both jwk and " +
                  "cert#S256 is refused 401 invalid_client (RFC 9635 " +
                  "section 11.35)", h.GRANT,
                  grant({ client: withKey(Object.assign({}, key,
                    { "cert#S256": "abc" })) }),
                  { status: 401, error: "invalid_client" });
  const noKid = JSON.parse(JSON.stringify(key));
  delete noKid.jwk.kid;
  await refusedBy("STS-GNAP-0012", "C9. a JWK with no kid is refused",
                  h.GRANT, grant({ client: withKey(noKid) }),
                  { status: 401, error: "invalid_client" });
  await refusedBy("STS-GNAP-0001", "C10. an unknown proof method is " +
                  "refused", h.GRANT, grant({ client: withKey(Object.assign(
                    {}, key, { proof: "telepathy" })) }),
                  { status: 401, error: "invalid_client" });

  // A pending grant, then its continuation and modification.
  const pending = await c.send("POST", h.GRANT, { json: grant() });
  assert.strictEqual(pending.status, 200, pending.text);
  const cont = pending.json.continue;
  await refusedBy("STS-GNAP-0061", "C11. a numeric interact_ref at a " +
                  "continuation fails its schema", cont.uri,
                  { interact_ref: 7 },
                  { send: { token: cont.access_token.value },
                    error: null });
  await refusedBy("STS-GNAP-0052", "C12. a continuation body that is an " +
                  "array", cont.uri, [1],
                  { send: { token: cont.access_token.value },
                    error: null });
  await refusedBy("STS-GNAP-0059", "C13. a modification (PATCH) carrying " +
                  "client is refused (section 5.3)", cont.uri,
                  { client: withKey(key) },
                  { method: "PATCH", send: { token: cont.access_token.value },
                    error: null });
  log.debug("Leaving walker().");
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("grl", "development", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  await G.resourceServer(h, "gr-rs-" + K.STAMP, G.client(),
                         "https://gr-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  c = G.client();
  await G.entry(h, "gr-client-" + K.STAMP, "gnap-client", c,
                { gnapFinishUri: [h.FINISH] });
  await envelope();
  await schemas();
  await walker();
  log.debug("Leaving test().");
}

K.main(test, 30);
