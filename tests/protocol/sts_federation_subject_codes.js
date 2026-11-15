// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_subject_codes.js
//
// ===========================================================================
// WHICH PEOPLE A FEDERATION PARTNER MAY ASSERT: THE REFUSALS THE VENDORED
// JOB DOES NOT REACH, BY CODE, OVER THE WIRE (#109, #701, #1497; #444 D12,
// phase 7).
//
// `tests/federation_subject_policy.js` drives a real federated sign-in in a
// child process per mode; `sts_federation_subject_policy.js` (vendored)
// drives most of it over HTTP. What neither carries over the wire is here,
// against an OpenID Connect partner written HERE (an ID Token by form_post
// under this job's key, the key pasted, so nothing is dialled and product's
// https-only back channel is not needed):
//
//   P. product: an enterprise partner that sends no givenName, sn or mail
//      sends its newcomer to /federation/profile, asked for exactly those
//      three (STS-FED-0188), and nobody is created until the form is
//      answered; the values given create the entry — a cn of the names, the
//      typed address unverified, nothing the form did not ask, one link —
//      and a returning person is not asked again;
//   Q. product: what the form refuses — a submission without the step's
//      token (STS-FED-0189, the handle spent), from a browser without the
//      step's cookie (STS-FED-0111), an empty value (STS-FED-0190, the
//      form again under a new handle), an address that is not one, and
//      five tries (STS-FED-0191) — each creating nobody (#729, the same
//      door a consumer newcomer meets);
//   B. product: a federated answer that arrives in another browser than the
//      one that began the sign-in is refused (401, STS-FED-0237);
//   L. a link already carried by one person refused on a second
//      (STS-FED-0107) in both modes;
//   A. product refuses setting any-existing (STS-FED-0095); a relationship
//      that carries it anyway — set while the realm was in development — is
//      refused at the sign-in (STS-FED-0094), writing nothing; development's
//      any-existing signs the name's person in and records the link.
//
// NOT HERE: 1m-0-iv's required attribute nobody can be asked for
// (STS-FED-0158 with STS-AUTHN-0180), which the in-process file makes by
// stubbing the person editor for one sign-in — no realm's attribute policy
// can require an attribute the editor refuses, so no request reaches it.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_federation_subject_codes");

const log = K.log;
const ISSUER = "https://fsc-partner-" + K.STAMP + ".invalid";
const CLIENT = "fsc-client-" + K.STAMP;
const REL = "fsc-oidc";
const KEY = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function b64uJson(value) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function idToken(claims) {
  log.debug("Entering idToken().");
  const input = b64uJson({ alg: "RS256", typ: "JWT", kid: "fsc-1" }) + "." +
                b64uJson(claims);
  log.debug("Leaving idToken().");
  return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                       KEY.privateKey).toString("base64url");
}

function viewOf(r) {
  log.debug("Entering viewOf().");
  const m = /data-sts-state="([^"]*)"/.exec(String((r && r.text) || ""));
  if (!m) {
    log.debug("Leaving viewOf(). None.");
    return null;
  }
  try {
    const out = JSON.parse(m[1].replace(/&quot;/g, "\"")
      .replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")).view;
    log.debug("Leaving viewOf().");
    return out;
  } catch (e) {
    log.debug("Caught in viewOf(): " + ((e && e.message) || e));
    // An unreadable state is reported as a view the assertion prints.
    log.debug("Leaving viewOf(). Unreadable.");
    return { kind: "unreadable" };
  }
}

async function makeRealm(prefix, mode) {
  log.debug("Entering makeRealm(). " + mode);
  const SP = await K.realm(prefix, mode);
  const jwk = Object.assign(KEY.publicKey.export({ format: "jwk" }),
                            { kid: "fsc-1", alg: "RS256", use: "sig" });
  await K.ok(K.rb(SP) + "/admin-api/federation/create", { id: REL,
    role: "service-provider", protocol: "oidc", peer: ISSUER },
  "created the relationship");
  const settings = { fedSsoUrl: ISSUER + "/authorize", fedClientId: CLIENT,
    fedResponseType: "id_token", fedScope: "openid",
    fedJwks: JSON.stringify({ keys: [jwk] }), fedAllowUnencrypted: "TRUE",
    fedUsernameSource: "preferred_username",
    fedSubjectPolicy: "jit-namespaced", fedAutocreateUsers: "TRUE" };
  for (const field of Object.keys(settings)) {
    await K.ok(K.rb(SP) + "/admin-api/federation/set", { id: REL,
      field: field, value: settings[field] }, "set " + field);
  }
  await K.ok(K.rb(SP) + "/admin-api/federation/enable", { id: REL },
             "enabled the relationship");
  const view = await K.send(K.rb(SP) + "/admin-api/federation?relationship=" +
                            REL);
  log.debug("Leaving makeRealm().");
  return { SP: SP, acs: view.json.endpoints.assertionConsumerService };
}

function setRel(w, field, value) {
  log.debug("Entering setRel(). " + field);
  log.debug("Leaving setRel().");
  return K.send(K.rb(w.SP) + "/admin-api/federation/set",
                { json: { id: REL, field: field, value: value } });
}

async function person(w, who) {
  log.debug("Entering person(). " + who);
  await K.ok(K.rb(w.SP) + "/admin-api/users/create", { username: who,
    invent: false, credential: "none", attributes: { cn: "Local " + who,
      givenName: "Local", sn: who, mail: "local-" + who + "@sp.example" } },
  "created " + who);
  log.debug("Leaving person().");
}

async function entry(w, who) {
  log.debug("Entering entry(). " + who);
  const r = await K.send(K.rb(w.SP) + "/admin-api/users?user=" +
                         encodeURIComponent(who));
  const ldap = (r.json && r.json.ldap) || {};
  log.debug("Leaving entry().");
  return { found: !!ldap.found, attrs: (ldap.entry || {}).attributes || {},
           json: r.json || {} };
}

function attr(e, name) {
  log.debug("Entering attr(). " + name);
  const v = e.attrs[name];
  log.debug("Leaving attr().");
  return v === undefined ? [] : [].concat(v);
}

// ONE SIGN-IN from the partner: `claims` beyond iss, aud, sub, iat, exp and
// the nonce; `o.otherBrowser` posts the answer from a browser that holds
// none of the cookies the beginning set.
async function signIn(w, sub, claims, o) {
  log.debug("Entering signIn(). " + sub);
  const opts = o || {};
  const b = K.browser();
  const begun = await b.go(K.rb(w.SP) + "/federation/login/" + REL);
  const asked = new URL(begun.location);
  const now = Math.floor(Date.now() / 1000);
  const token = idToken(Object.assign({ iss: ISSUER, aud: CLIENT, sub: sub,
    iat: now, exp: now + 300, nonce: asked.searchParams.get("nonce") },
  claims || {}));
  const poster = opts.otherBrowser ? K.browser() : b;
  let r = await poster.go(w.acs, { form: { id_token: token,
    state: asked.searchParams.get("state") } });
  let path = "";
  for (let i = 0; i < 8 && r.status >= 300 && r.status < 400 && r.location;
       i += 1) {
    const next = new URL(r.location, K.base);
    path = next.pathname;
    r = await poster.go(next.toString());
  }
  log.debug("Leaving signIn(). " + r.status);
  return { r: r, b: poster, path: path };
}

function namespaced(sub) {
  log.debug("Entering namespaced().");
  log.debug("Leaving namespaced().");
  return REL + "~sub-" + String(sub).replace(/^urn:uuid:/i, "")
    .toLowerCase();
}

// ------------------------------------------------------------------- P
async function profileForm(w) {
  log.debug("Entering profileForm().");
  log.info("=== P. product: the newcomer asked for what is missing ===");
  const sub = "urn:uuid:" + nodeCrypto.randomUUID();
  const name = namespaced(sub);
  const got = await K.coded(w.SP, "STS-FED-0188", function () {
    return signIn(w, sub, {});
  });
  const form = viewOf(got.answer.r);
  const names = form && Array.isArray(form.fields)
    ? form.fields.map(function (f) {
      return f.name;
    }).sort().join(",") : "";
  const before = await entry(w, name);
  K.check("P1. an enterprise partner that sends no givenName, sn or mail " +
          "sends its newcomer to /federation/profile, asked for exactly " +
          "those three (STS-FED-0188), and nobody is created yet",
  function () {
    assert.strictEqual(got.answer.r.status, 200, K.shown(got.answer.r));
    assert.ok(/\/federation\/profile\/fed-/.test(got.answer.path),
              got.answer.path);
    assert.ok(form && form.kind === "profile", JSON.stringify(form));
    assert.strictEqual(names, "givenName,mail,sn");
    assert.ok(got.rose >= 1);
    assert.ok(!before.found);
  });
  let done = await got.answer.b.go(K.rb(w.SP) + form.action, { form: {
    csrf: form.csrf, givenName: "Bare", sn: "Newcomer",
    mail: "bare@typed.example", title: "Smuggled" } });
  for (let i = 0; i < 8 && done.status >= 300 && done.status < 400 &&
       done.location; i += 1) {
    done = await got.answer.b.go(new URL(done.location, K.base).toString());
  }
  const made = await entry(w, name);
  K.check("P2. the values given finish the sign-in: the entry is created " +
          "and linked with them, a cn made of the names, the typed address " +
          "unverified, and nothing the form did not ask", function () {
    assert.strictEqual(done.status, 200, K.shown(done));
    assert.ok(made.found, "no entry " + name);
    assert.strictEqual(attr(made, "givenName")[0], "Bare");
    assert.strictEqual(attr(made, "sn")[0], "Newcomer");
    assert.strictEqual(attr(made, "mail")[0], "bare@typed.example");
    assert.ok(attr(made, "title").length === 0);
    assert.ok(attr(made, "cn").length > 0);
    assert.ok(!/"stsMailVerified":\s*\[?"TRUE"/i.test(
      JSON.stringify(made.attrs)), JSON.stringify(made.attrs).slice(0, 300));
    assert.strictEqual(((made.json || {}).federationLinks || []).length, 1);
  });
  const again = await K.coded(w.SP, "STS-FED-0188", function () {
    return signIn(w, sub, {});
  });
  K.check("P3. the same person signing in again is not asked", function () {
    assert.strictEqual(again.answer.r.status, 200, K.shown(again.answer.r));
    assert.ok(!/\/federation\/profile\//.test(again.answer.path));
    assert.strictEqual(again.rose, 0);
  });
  log.debug("Leaving profileForm().");
}

// ------------------------------------------------------------------- Q
// THE FORM'S REFUSALS (#729's decision 2, which consumer and enterprise
// newcomers share): the step's token, its browser, a value's shape, and
// five tries.
async function formRefusals(w) {
  log.debug("Entering formRefusals().");
  log.info("=== Q. product: what the profile form refuses ===");
  const open = async function (sub) {
    log.debug("Entering open().");
    const got = await signIn(w, sub, {});
    log.debug("Leaving open().");
    return { b: got.b, form: viewOf(got.r) || {} };
  };
  const post = function (b, form, fields) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return b.go(K.rb(w.SP) + form.action, { form: fields });
  };
  const sub = "urn:uuid:" + nodeCrypto.randomUUID();
  const name = namespaced(sub);
  let step = await open(sub);
  const forged = await K.coded(w.SP, "STS-FED-0189", function () {
    return post(step.b, step.form, { csrf: "not-the-token",
      givenName: "Nora", sn: "Surname", mail: "nora@typed.example" });
  });
  const replay = await post(step.b, step.form, { csrf: step.form.csrf,
    givenName: "Nora", sn: "Surname", mail: "nora@typed.example" });
  let e = await entry(w, name);
  K.check("Q1. a submission without the step's token is refused (403, " +
          "STS-FED-0189), the handle is spent, and nobody is created",
  function () {
    assert.strictEqual(forged.answer.status, 403, K.shown(forged.answer));
    assert.ok(forged.rose >= 1);
    assert.strictEqual(replay.status, 400, K.shown(replay));
    assert.ok(!e.found);
  });
  step = await open(sub);
  const elsewhere = await K.coded(w.SP, "STS-FED-0111", function () {
    return post(K.browser(), step.form, { csrf: step.form.csrf,
      givenName: "Nora", sn: "Surname", mail: "nora@typed.example" });
  });
  e = await entry(w, name);
  K.check("Q2. a submission from a browser without the step's cookie is " +
          "refused (403, STS-FED-0111)", function () {
    assert.strictEqual(elsewhere.answer.status, 403,
                       K.shown(elsewhere.answer));
    assert.ok(elsewhere.rose >= 1);
    assert.ok(!e.found);
  });
  step = await open(sub);
  const empty = await K.coded(w.SP, "STS-FED-0190", function () {
    return post(step.b, step.form, { csrf: step.form.csrf,
      givenName: "Nora", sn: "  ", mail: "nora@typed.example" });
  });
  const redrawn = viewOf(empty.answer) || {};
  K.check("Q3. an empty value draws the form again under a new handle and " +
          "creates nobody (400, STS-FED-0190)", function () {
    assert.strictEqual(empty.answer.status, 400, K.shown(empty.answer));
    assert.ok(empty.rose >= 1);
    assert.strictEqual(redrawn.kind, "profile");
    assert.ok(/required/.test(String(redrawn.problem)), redrawn.problem);
    assert.notStrictEqual(redrawn.action, step.form.action);
  });
  const bad = await post(step.b, redrawn, { csrf: redrawn.csrf,
    givenName: "Nora", sn: "Surname", mail: "not an address" });
  const again = viewOf(bad) || {};
  const done = await post(step.b, again, { csrf: again.csrf,
    givenName: "Nora", sn: "Surname", mail: "nora@typed.example" });
  e = await entry(w, name);
  K.check("Q4. an address is held to an address's shape (400, the form " +
          "again), and the next good answer creates the person", function () {
    assert.strictEqual(bad.status, 400, K.shown(bad));
    assert.strictEqual(again.kind, "profile");
    assert.ok(done.status < 400, K.shown(done));
    assert.ok(e.found);
    assert.strictEqual(attr(e, "mail")[0], "nora@typed.example");
  });
  const stubborn = "urn:uuid:" + nodeCrypto.randomUUID();
  step = await open(stubborn);
  let tries = step.form;
  let last = null;
  const five = await K.coded(w.SP, "STS-FED-0191", async function () {
    for (let i = 0; i < 5 && tries && tries.kind === "profile"; i += 1) {
      last = await post(step.b, tries, { csrf: tries.csrf, givenName: "",
                                         sn: "", mail: "" });
      tries = viewOf(last);
    }
    return last;
  });
  const none = await entry(w, namespaced(stubborn));
  K.check("Q5. five submissions without the values end the step and create " +
          "nobody (400, STS-FED-0191)", function () {
    assert.ok(last && last.status === 400, K.shown(last || {}));
    assert.ok(tries && tries.kind === "refused", JSON.stringify(tries));
    assert.ok(five.rose >= 1);
    assert.ok(!none.found);
  });
  log.debug("Leaving formRefusals().");
}

// ------------------------------------------------------------------- B
async function otherBrowser(w) {
  log.debug("Entering otherBrowser().");
  log.info("=== B. product: the answer in another browser ===");
  const sub = "urn:uuid:" + nodeCrypto.randomUUID();
  const got = await K.coded(w.SP, "STS-FED-0237", function () {
    return signIn(w, sub, { given_name: "W", family_name: "Anderer",
                            email: "w@partner.example" },
                  { otherBrowser: true });
  });
  const made = await entry(w, namespaced(sub));
  K.check("B1. a federated answer that arrives in another browser than " +
          "began the sign-in is refused (401, STS-FED-0237), creating nobody",
  function () {
    assert.strictEqual(got.answer.r.status, 401, K.shown(got.answer.r));
    assert.ok(got.rose >= 1);
    assert.ok(!made.found);
  });
  log.debug("Leaving otherBrowser().");
}

// ------------------------------------------------------------------- L
async function secondLink(w, mode) {
  log.debug("Entering secondLink().");
  log.info("=== L. [" + mode + "] one link, one person ===");
  const one = "fsc-one-" + K.rand(2);
  const two = "fsc-two-" + K.rand(2);
  await person(w, one);
  await person(w, two);
  const sub = "fsc-linked-" + K.rand(3);
  const first = await K.send(K.rb(w.SP) + "/admin-api/users/federation-link",
    { json: { user: one, relationship: REL, subject: sub } });
  const got = await K.coded(w.SP, "STS-FED-0107", function () {
    return K.send(K.rb(w.SP) + "/admin-api/users/federation-link",
      { json: { user: two, relationship: REL, subject: sub } });
  });
  K.check("[" + mode + "] L1. the same link on a SECOND person is refused " +
          "(400, STS-FED-0107), naming the first", function () {
    assert.strictEqual(first.status, 200, first.text.slice(0, 200));
    assert.strictEqual(got.answer.status, 400, got.answer.text.slice(0,
                                                                     200));
    assert.ok(/already carried by/.test(got.answer.text));
    assert.ok(got.rose >= 1);
  });
  log.debug("Leaving secondLink().");
}

// ------------------------------------------------------------------- A
async function anyExisting(dev, prod) {
  log.debug("Entering anyExisting().");
  log.info("=== A. any-existing ===");
  const hank = "fsc-hank-" + K.rand(2);
  await person(dev, hank);
  await K.ok(K.rb(dev.SP) + "/admin-api/federation/set", { id: REL,
    field: "fedSubjectPolicy", value: "any-existing" }, "any-existing");
  const signed = await signIn(dev, "fsc-hank-sub-" + K.rand(2),
    { preferred_username: hank, email: "hank@partner.example" });
  const e = await entry(dev, hank);
  K.check("[development] A1. any-existing signs the name's person in " +
          "directly and records the link", function () {
    assert.strictEqual(signed.r.status, 200, K.shown(signed.r));
    assert.strictEqual(((e.json || {}).federationLinks || []).length, 1,
                       JSON.stringify(e.json.federationLinks));
  });
  const refused = await K.coded(prod.SP, "STS-FED-0095", function () {
    return setRel(prod, "fedSubjectPolicy", "any-existing");
  });
  K.check("[product] A2. product refuses setting any-existing " +
          "(400, STS-FED-0095)", function () {
    assert.strictEqual(refused.answer.status, 400, refused.answer.text);
    assert.ok(refused.rose >= 1);
  });
  // A relationship that carries it anyway: written while the realm was in
  // development, then the realm put back in product.
  const ann = "fsc-ann-" + K.rand(2);
  await person(prod, ann);
  await K.set(prod.SP, "global.mode", "development");
  await K.ok(K.rb(prod.SP) + "/admin-api/federation/set", { id: REL,
    field: "fedSubjectPolicy", value: "any-existing" }, "any-existing");
  await K.set(prod.SP, "global.mode", "product");
  const got = await K.coded(prod.SP, "STS-FED-0094", function () {
    return signIn(prod, "fsc-ann-sub-" + K.rand(2),
      { preferred_username: ann, email: "ann@partner.example",
        given_name: "Ann", family_name: "Other" });
  });
  const after = await entry(prod, ann);
  K.check("[product] A3. a relationship that carries any-existing anyway is " +
          "refused at the sign-in (403, STS-FED-0094), writing nothing",
  function () {
    assert.strictEqual(got.answer.r.status, 403, K.shown(got.answer.r));
    assert.ok(got.rose >= 1);
    assert.deepStrictEqual(attr(after, "mail"),
                           ["local-" + ann + "@sp.example"]);
    assert.strictEqual(((after.json || {}).federationLinks || []).length, 0);
  });
  await K.ok(K.rb(prod.SP) + "/admin-api/federation/set", { id: REL,
    field: "fedSubjectPolicy", value: "jit-namespaced" }, "put back");
  log.debug("Leaving anyExisting().");
}

async function test() {
  log.debug("Entering test().");
  const dev = await makeRealm("fsc-d", "development");
  const prod = await makeRealm("fsc-p", "product");
  await profileForm(prod);
  await formRefusals(prod);
  await otherBrowser(prod);
  await secondLink(dev, "development");
  await secondLink(prod, "product");
  await anyExisting(dev, prod);
  log.debug("Leaving test().");
}

K.main(test, 14);
