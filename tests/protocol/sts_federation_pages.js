// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_pages.js
//
// ===========================================================================
// THE FEDERATION PAGES ARE A STATIC SURFACE'S SHELL; THE ASSERTION CONSUMER
// SERVICE'S ANSWERS ARE UNCHANGED (#580; #444 D12, phase 7).
//
// `tests/federation_pages.js` asks a child process's stack; this job asks a
// running service, in a development realm of its own with three
// relationships made through `/admin-api` (a disabled SAML partner, one the
// other way round, and an enabled half-configured OIDC partner). Each page
// is held to its STATUS and HEADERS, then to its body:
//
//   1. GET /federation: 200, no-store, the shell (its script, the
//      `<noscript>`, no server-drawn table) under a policy that runs the
//      script and keeps `frame-ancestors`, carrying the relationships in
//      each direction with their states, the endpoints and the base in
//      `data-sts-state`;
//   2. /federation/login/{id}'s refusals with the status each always had:
//      federation off (404), no such relationship (404), the other direction
//      (400), disabled (403, and `fedLastError` written), not fully
//      configured (409);
//   3. /federation/link/{handle} with no link waiting: 400, the shell;
//   4. the assertion consumer service is NOT converted: its refusal is drawn
//      by the server under `script-src 'none'`, with no state — the code's
//      sentence, the diagnostics with an incident ID — and its 404 for no
//      such relationship too, in French for a browser that asks;
//   5. /federation/pages.js is served as a script.
//
// NOT HERE: 6 and 7 (the renderers and the runtime drawing in a browser)
// are (d).
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_federation_pages");

const log = K.log;
let R = null;

function stateOf(text) {
  log.debug("Entering stateOf().");
  const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ""));
  log.debug("Leaving stateOf().");
  return m ? JSON.parse(m[1].replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"))
    : null;
}

function isShell(r) {
  log.debug("Entering isShell().");
  log.debug("Leaving isShell().");
  return /\/federation\/pages\.js/.test(r.text) && /<noscript>/.test(r.text) &&
    !/<table/.test(r.text);
}

function headersOk(r, status) {
  log.debug("Entering headersOk().");
  log.debug("Leaving headersOk().");
  return r.status === status &&
    /no-store/.test(String(r.headers.get("cache-control"))) &&
    /^text\/html/.test(String(r.headers.get("content-type")));
}

function policyOk(r) {
  log.debug("Entering policyOk().");
  const csp = String(r.headers.get("content-security-policy"));
  log.debug("Leaving policyOk().");
  return /script-src[^;]*'self'/.test(csp) && /frame-ancestors/.test(csp);
}

function rel(id, body) {
  log.debug("Entering rel().");
  log.debug("Leaving rel().");
  return K.ok(K.rb(R) + "/admin-api/federation/" + id, body, id);
}

async function test() {
  log.debug("Entering test().");
  R = await K.realm("fpg", "development");
  await K.set(R, "federation.enabled", true);
  const SP = "fp-sp-" + K.rand(3);
  const IDP = "fp-idp-" + K.rand(3);
  const HALF = "fp-half-" + K.rand(3);
  await rel("create", { id: SP, role: "service-provider", protocol: "saml2" });
  await rel("create", { id: IDP, role: "identity-provider",
                        protocol: "saml2" });
  await rel("create", { id: HALF, role: "service-provider",
                        protocol: "oidc" });
  await rel("enable", { id: HALF });
  const page = function (p, headers) {
    return K.send(K.rb(R) + p, { headers: headers || {} });
  };

  let r = await page("/federation");
  let state = stateOf(r.text);
  K.check("1a. GET /federation: 200, no-store, the shell under a policy " +
          "that runs its script and keeps frame-ancestors", function () {
    assert.ok(headersOk(r, 200) && isShell(r) && policyOk(r), K.shown(r));
  });
  K.check("1b. carrying the relationships in each direction, their states, " +
          "the endpoints and the base", function () {
    const v = (state || {}).view || {};
    const row = (v.consuming || []).filter(function (one) {
      return one.id === SP;
    })[0];
    const half = (v.consuming || []).filter(function (one) {
      return one.id === HALF;
    })[0];
    assert.strictEqual(v.kind, "index", JSON.stringify(state).slice(0, 400));
    assert.ok(row && row.state === "disabled", JSON.stringify(row));
    assert.ok(half && half.state === "incomplete" && half.missing.length > 0,
              JSON.stringify(half));
    assert.ok((v.asserting || []).some(function (one) {
      return one.id === IDP;
    }));
    assert.strictEqual(v.paths.acs, "/federation/acs");
    assert.strictEqual(v.base, K.rb(R));
  });
  await K.set(R, "federation.enabled", false);
  r = await page("/federation/login/" + SP);
  state = stateOf(r.text);
  K.check("2a. federation off: 404, the shell saying so", function () {
    assert.ok(headersOk(r, 404) && isShell(r) && policyOk(r), K.shown(r));
    assert.strictEqual(state.view.kind, "off");
  });
  await K.set(R, "federation.enabled", true);
  const nobody = "fp-nobody-" + K.rand(3);
  r = await page("/federation/login/" + nobody);
  state = stateOf(r.text);
  K.check("2b. no such relationship: 404, the shell naming it", function () {
    assert.ok(headersOk(r, 404) && isShell(r), K.shown(r));
    assert.strictEqual(state.view.kind, "noRelationship");
    assert.strictEqual(state.view.id, nobody);
  });
  r = await page("/federation/login/" + IDP);
  state = stateOf(r.text);
  K.check("2c. the other direction: 400, the shell with what and why",
          function () {
            assert.ok(headersOk(r, 400) && isShell(r), K.shown(r));
            assert.strictEqual(state.view.kind, "refused");
            assert.strictEqual(state.view.what,
                               "That relationship goes the other way");
          });
  r = await page("/federation/login/" + SP);
  state = stateOf(r.text);
  const recorded = await K.send(K.rb(R) + "/admin-api/federation?" +
                                "relationship=" + SP);
  K.check("2d. disabled: 403, the shell with the relationship, and " +
          "fedLastError written", function () {
    assert.ok(headersOk(r, 403) && isShell(r) && policyOk(r), K.shown(r));
    assert.strictEqual(state.view.what, "That relationship is disabled");
    assert.ok(/fedEnabled is FALSE/.test(state.view.why), state.view.why);
    assert.strictEqual(state.view.relationship, SP);
    assert.ok(/That relationship is disabled: /.test(recorded.text),
              recorded.text.slice(0, 300));
  });
  r = await page("/federation/login/" + HALF);
  state = stateOf(r.text);
  K.check("2e. not fully configured: 409, the shell", function () {
    assert.ok(headersOk(r, 409) && isShell(r), K.shown(r));
    assert.ok(/not fully configured/.test(state.view.what));
  });
  r = await page("/federation/link/fed-nothing" + K.rand(3));
  state = stateOf(r.text);
  K.check("3. no link waiting: 400, the shell", function () {
    assert.ok(headersOk(r, 400) && isShell(r) && policyOk(r), K.shown(r));
    assert.strictEqual(state.view.what, "There is no link waiting");
  });
  r = await page("/federation/acs/" + SP);
  K.check("4a. the assertion consumer service's refusal is drawn by the " +
          "server under script-src 'none', with no state", function () {
    assert.ok(r.status >= 400, K.shown(r));
    assert.strictEqual(stateOf(r.text), null);
    assert.ok(!isShell(r));
    assert.ok(/<h1>The federated sign-in was refused<\/h1>/.test(r.text));
    assert.ok(/script-src 'none'/.test(String(
      r.headers.get("content-security-policy"))));
    assert.ok(/<dt>Incident ID<\/dt>/.test(r.text));
  });
  r = await page("/federation/acs/" + nobody);
  const fr = await page("/federation/acs/" + nobody,
                        { "accept-language": "fr" });
  K.check("4b. its 404 for no such relationship, server-drawn, and in " +
          "French for a browser that asks", function () {
    assert.strictEqual(r.status, 404, K.shown(r));
    assert.ok(!isShell(r));
    assert.ok(fr.status >= 400 && /<html lang="fr"/.test(fr.text),
              K.shown(fr));
  });
  r = await page("/federation/pages.js");
  K.check("5. /federation/pages.js is served as a script", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/javascript/.test(String(r.headers.get("content-type"))));
  });
  log.debug("Leaving test().");
}

K.main(test, 11);
