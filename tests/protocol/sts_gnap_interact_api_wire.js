// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_interact_api_wire.js
//
// ===========================================================================
// GNAP'S INTERACTION PAGES AS A STATIC SURFACE OVER `/gnap-api`, OVER THE
// WIRE (#444 D12 phase 8; #578).
//
// `tests/gnap_interact_api.js` serves the whole stack in a child process
// and makes its waiting grants in the store; this job makes them as a
// client instance does, at `/gnap`, in a development realm, and asks:
//
//   1. the shell: `/gnap/code` answers the shell (the bundle, no form,
//      no-store) under a policy keeping frame-ancestors, script and API
//      from 'self' only, minting the arrival cookie; the bundle is served;
//   2. the index lists the four operations and what each mirrors;
//   3. the protocol's answers: a start link's 303 to the approval page,
//      once; spent or unknown, a 400 shell carrying the refusal with no
//      code in it; the page sends a browser with no session to sign in; a
//      cancelled sign-in enacts the redirect finish with the section 4.2.3
//      hash;
//   4. the view: with no session it sends the browser back to the page;
//      signed in, the page is the shell and the view facts with a csrf; a
//      person's own language as `{ value, populated }`, held to its model
//      (no STS-GNAP-0910 recorded);
//   5. the binding: an act needs JSON (415), an Origin of this service
//      (403) and the token (403), none carrying a code; a field the act
//      does not take, and a limit control it does not draw, refused;
//   6. the answer: Allow answers the finish URI with the hash; a second
//      answer refused with a problem view; Deny with no finish the done
//      view; a cancelled sign-in with no finish the shell carrying it;
//   7. the user code: its view's csrf, typed in either case with a dash,
//      spent once, bound as every act is;
//   8. the old form posts are gone (404).
//
// (d), with the reason: 2's equality with `interact.operations()` and 9
// (the compiled renderer drawing the view) are the module and the image's
// bundle; 6b's "only the right left ticked" is read here off the token the
// continuation releases rather than the store's decision.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_interact_api_wire");
const G = require("./gnap_wire_kit.js").gnapKit(K);
const gnap = require("./gnap_client.js");
const authnSignin = require("./authn_signin");

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Api-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gia-type";
const OTHER = "gia-other";

let realm = null;
let h = null;
let c = null;

function stateOf(text) {
  log.debug("Entering stateOf().");
  const m = /data-sts-state="([^"]*)"/.exec(String(text || ""));
  log.debug("Leaving stateOf().");
  return m ? JSON.parse(m[1].replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")) : null;
}

function isShell(r) {
  log.debug("Entering isShell().");
  log.debug("Leaving isShell().");
  return /<script[^>]+src="[^"]*interaction\.js"/.test(r.text) &&
         /<noscript>/.test(r.text) && !/<form/i.test(r.text);
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  log.debug("Leaving codeFree().");
  return !/STS-[A-Z]+-\d{4}/.test(String(text || ""));
}

// A waiting grant: `finish` false asks no finish method; `code` adds the
// user_code start mode.
async function waiting(finish, code) {
  log.debug("Entering waiting().");
  const nonce = "n-" + nodeCrypto.randomBytes(6).toString("hex");
  const interact = { start: code ? ["redirect", "user_code"]
                                 : ["redirect"] };
  if (finish !== false) {
    interact.finish = { method: "redirect", uri: h.FINISH, nonce: nonce };
  }
  const r = await c.send("POST", h.GRANT, { json: {
    access_token: { access: [{ type: TYPE, actions: ["read"] },
                             { type: OTHER, actions: ["read"] }] },
    client: { key: c.keyObject(), display: { name: "GIA client" } },
    interact: interact } });
  assert.strictEqual(r.status, 200, r.text);
  const start = r.json.interact.redirect;
  log.debug("Leaving waiting().");
  return { pending: r.json, start: start, nonce: nonce };
}

// The approval page a start link forwards to, and its /gnap-api view.
async function approveOf(one, jar) {
  log.debug("Entering approveOf().");
  const r = await K.send(one.start, { jar: jar });
  assert.strictEqual(r.status, 303, K.shown(r));
  const approve = h.absolute(r.location);
  log.debug("Leaving approveOf().");
  return { approve: approve, api: h.absolute(h.apiOf(r.location)),
           first: r };
}

// An act on /gnap-api, with this service's Origin and `csrf` unless told.
function act(jar, url, body, o) {
  log.debug("Entering act().");
  const opts = o || {};
  const headers = { accept: "application/json" };
  if (opts.origin !== null) {
    headers.origin = opts.origin || new URL(url).origin;
  }
  if (opts.csrf !== undefined) {
    headers["x-csrf-token"] = opts.csrf;
  }
  log.debug("Leaving act().");
  if (opts.form) {
    return K.send(url, { jar: jar, headers: headers, form: body });
  }
  return K.send(url, { jar: jar, headers: headers, json: body });
}

async function shell() {
  log.debug("Entering shell().");
  log.info("=== 1, 2. the shell and the index ===");
  const jar = {};
  let r = await K.send(h.realmBase + "/gnap/code", { jar: jar });
  const csp = String(r.headers.get("content-security-policy") || "");
  check("1a. /gnap/code answers the shell: the bundle, the notice and no " +
        "form, no-store", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(isShell(r) && !stateOf(r.text), r.text.slice(0, 400));
    assert.ok(/no-store/.test(String(r.headers.get("cache-control"))));
  });
  check("1b. its policy keeps frame-ancestors and allows script and API " +
        "from 'self' only", function () {
    assert.ok(/frame-ancestors 'none'/.test(csp), csp);
    assert.ok(/script-src 'self'(;|$)/.test(csp), csp);
    assert.ok(/connect-src 'self'/.test(csp), csp);
    assert.ok(!/unsafe-inline/.test(csp), csp);
  });
  check("1c. and it mints the arrival cookie for a browser without one",
        function () {
    assert.ok(jar.sts_session, JSON.stringify(Object.keys(jar)));
  });
  r = await K.send(h.realmBase + "/gnap/interaction.js");
  check("1d. the bundle is served, built", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/javascript/.test(String(r.headers.get("content-type"))));
    assert.ok(r.text.length > 1000 && r.text.indexOf("was not built") < 0);
  });
  r = await K.send(h.realmBase + "/gnap-api");
  const ops = (r.json && r.json.operations) || [];
  check("2. the index lists the four operations and what each mirrors",
        function () {
    ["GET /gnap/code", "POST /gnap/code", "GET /gnap/approve/{id}",
     "POST /gnap/approve/{id}"].forEach(function (m) {
      assert.strictEqual(ops.filter(function (op) {
        return op.mirrors === m;
      }).length, 1, m + " " + JSON.stringify(ops));
    });
  });
  log.debug("Leaving shell().");
  return jar;
}

async function protocolAnswers(person) {
  log.debug("Entering protocolAnswers().");
  log.info("=== 3, 4, 5, 6. the protocol's answers, the view, the act ===");
  const one = await waiting();
  const jar = {};
  const at = await approveOf(one, jar);
  check("3a. a start link answers its 303 to the approval page, no-store",
        function () {
    assert.ok(/\/gnap\/approve\//.test(at.approve), at.approve);
    assert.ok(/no-store/.test(String(at.first.headers.get(
      "cache-control"))));
  });
  let r = await K.send(one.start, { jar: jar });
  const spent = stateOf(r.text);
  check("3b. it works once: again, a 400 shell carrying the refusal and no " +
        "code", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(isShell(r) && spent && spent.view.kind === "problem",
              r.text.slice(0, 400));
    assert.ok(codeFree(r.text));
  });
  r = await K.send(h.realmBase + "/gnap/interact/nosuchlinkatall");
  check("3c. an unknown link is the same 400 page", function () {
    assert.strictEqual(r.status, 400);
    assert.strictEqual(stateOf(r.text).view.kind, "problem");
  });
  r = await K.send(at.approve, { jar: jar });
  check("3d. the approval page sends a browser with no session to the " +
        "sign-in screen", function () {
    assert.strictEqual(r.status, 303);
    assert.ok(/\/authn\/login/.test(r.location), r.location);
  });
  const signIn = r.location;

  // A cancelled sign-in on another grant.
  const cancelled = await waiting();
  const cAt = await approveOf(cancelled, {});
  r = await K.send(cAt.approve + "?authn_error=access_denied");
  const back = r.status === 303 ? new URL(r.location) : null;
  check("3e. a cancelled sign-in enacts the redirect finish with the " +
        "section 4.2.3 hash", function () {
    assert.ok(back, K.shown(r));
    assert.strictEqual(back.origin + back.pathname, h.FINISH);
    assert.strictEqual(back.searchParams.get("hash"),
                       gnap.interactionHash(cancelled.nonce,
                         cancelled.pending.interact.finish,
                         back.searchParams.get("interact_ref"), h.GRANT));
  });

  r = await K.send(at.api, { jar: jar });
  check("4a. with no session the view sends the browser back to the page",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.next, "page");
    assert.strictEqual(h.absolute(r.json.location), at.approve);
  });
  const cookie = Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
  const signedIn = await authnSignin.submit(h.realmBase, h.absolute(signIn),
    { action: "login", username: person, password: PASSWORD },
    { cookie: cookie });
  signedIn.setCookies.forEach(function (line) {
    const pair = String(line).split(";")[0];
    const name = pair.split("=")[0];
    jar[name] = pair.slice(name.length + 1);
  });
  check("4b. the sign-in returns to the approval page", function () {
    assert.strictEqual(signedIn.next, "redirect");
    assert.ok(signedIn.location.indexOf(new URL(at.approve).pathname) >= 0,
              signedIn.location);
  });
  r = await K.send(at.approve, { jar: jar });
  check("4c. signed in, the approval page is the shell, which fetches its " +
        "view", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(isShell(r) && !stateOf(r.text));
  });
  const lang = await K.send(h.realmApi + "/users/set-attribute", { json: {
    user: person, attribute: "preferredLanguage", value: "fr" } });
  assert.strictEqual(lang.status, 200, K.shown(lang));
  const gaps = await K.codeCount(realm, "STS-GNAP-0910");
  r = await K.send(at.api, { jar: jar });
  const view = r.json && r.json.view;
  const csrf = r.json && r.json.csrf;
  check("4d. the view is facts and no words, with its csrf", function () {
    assert.strictEqual(view.kind, "approve", r.text.slice(0, 400));
    assert.strictEqual(view.username, person);
    assert.deepStrictEqual(view.tokens[0].rights.map(function (x) {
      return x.field;
    }), ["t0r0", "t0r1"]);
    assert.strictEqual(view.tokens[0].rights[0].right.type, TYPE);
    assert.strictEqual(view.finish.method, "redirect");
    assert.ok(csrf);
    assert.ok(!/Allow access/.test(r.text));
  });
  const after = await K.codeCount(realm, "STS-GNAP-0910");
  check("4e. a person's own language is answered as { value, populated }, " +
        "and the answer is its model's (no STS-GNAP-0910)", function () {
    const own = r.json.preferredLanguage;
    assert.ok(own && own.value === "fr" &&
              typeof own.populated === "boolean", JSON.stringify(own));
    assert.strictEqual(after, gaps);
  });

  const refusals = [
    await act(jar, at.api, "action=allow", { form: true, csrf: csrf }),
    await act(jar, at.api, { action: "allow" }, { origin: null,
                                                  csrf: csrf }),
    await act(jar, at.api, { action: "allow" },
              { origin: "https://evil.example", csrf: csrf }),
    await act(jar, at.api, { action: "allow" }, { csrf: "nottoken" })];
  check("5a. an act needs JSON (415), an Origin of this service and the " +
        "token (403), and none of the refusals carries a code", function () {
    assert.deepStrictEqual(refusals.map(function (x) {
      return x.status;
    }), [415, 403, 403, 403]);
    refusals.forEach(function (x) {
      assert.ok(x.json && x.json.ok === false, x.text);
      assert.ok(codeFree(x.text), x.text);
    });
  });
  const unknownField = await act(jar, at.api, { action: "allow",
                                                extra: "x" }, { csrf: csrf });
  const limitControl = await act(jar, at.api, { action: "allow",
    lim_t0r0_amount: ["1", { x: 1 }] }, { csrf: csrf });
  check("5b. a field the act does not take, and a limit control it does " +
        "not draw, are refused", function () {
    assert.strictEqual(unknownField.status, 400, unknownField.text);
    assert.strictEqual(limitControl.status, 400, limitControl.text);
    assert.ok(codeFree(unknownField.text) && codeFree(limitControl.text));
  });

  r = await act(jar, at.api, { action: "allow", right: "t0r0" },
                { csrf: csrf });
  const to = r.json && r.json.location ? new URL(r.json.location) : null;
  check("6a. Allow answers the client's finish URI with the hash and " +
        "interact_ref section 4.2.3 defines", function () {
    assert.ok(to && r.json.next === "redirect", K.shown(r));
    assert.strictEqual(to.origin + to.pathname, h.FINISH);
    assert.strictEqual(to.searchParams.get("hash"),
                       gnap.interactionHash(one.nonce,
                         one.pending.interact.finish,
                         to.searchParams.get("interact_ref"), h.GRANT));
  });
  const released = await c.send("POST", one.pending.continue.uri, {
    token: one.pending.continue.access_token.value,
    json: { interact_ref: to.searchParams.get("interact_ref") } });
  check("6b. only the right left ticked is in the token", function () {
    assert.strictEqual(released.status, 200, released.text);
    assert.deepStrictEqual(released.json.access_token.access.map(
      function (x) {
        return x.type;
      }), [TYPE], released.text);
  });
  r = await act(jar, at.api, { action: "allow", right: "t0r0" },
                { csrf: csrf });
  check("6c. a second answer is refused, with a view the page draws",
        function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.view.kind, "problem");
    assert.ok(codeFree(r.text));
  });
  const quiet = await waiting(false);
  const qAt = await approveOf(quiet, jar);
  r = await K.send(qAt.api, { jar: jar });
  r = await act(jar, qAt.api, { action: "deny" }, { csrf: r.json.csrf });
  check("6d. Deny with no finish method answers the done view", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.next, "done");
    assert.strictEqual(r.json.view.kind, "done");
    assert.strictEqual(r.json.view.approved, false);
    assert.ok(!r.json.location);
  });
  const quietCancel = await waiting(false);
  const qcAt = await approveOf(quietCancel, {});
  r = await K.send(qcAt.approve + "?authn_error=access_denied");
  check("6e. a cancelled sign-in with no finish is the shell carrying the " +
        "done view", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(stateOf(r.text).view.kind, "done");
    assert.strictEqual(stateOf(r.text).view.approved, false);
  });
  log.debug("Leaving protocolAnswers().");
  return { jar: jar, approve: qcAt.approve };
}

async function userCode(codeJar, later) {
  log.debug("Entering userCode().");
  log.info("=== 7, 8. the user code and the old form posts ===");
  const one = await waiting(undefined, true);
  const code = String(one.pending.interact.user_code || "");
  assert.ok(code.length >= 6, JSON.stringify(one.pending.interact));
  let r = await K.send(h.realmBase + "/gnap-api/code", { jar: codeJar });
  const codeCsrf = r.json && r.json.csrf;
  check("7a. the code page's view carries its csrf", function () {
    assert.strictEqual(r.json.view.kind, "code", K.shown(r));
    assert.ok(codeCsrf);
  });
  const plain = code.replace(/-/g, "");
  const typed = plain.slice(0, 3).toLowerCase() + "-" + plain.slice(3);
  r = await act(codeJar, h.realmBase + "/gnap-api/code", { code: typed },
                { csrf: codeCsrf });
  check("7b. a code typed in either case, with a dash, names the approval " +
        "page", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.next, "page");
    assert.ok(/\/gnap\/approve\//.test(r.json.location), r.text);
  });
  r = await act(codeJar, h.realmBase + "/gnap-api/code", { code: code },
                { csrf: codeCsrf });
  check("7c. and it is spent: a second time it is refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(codeFree(r.text));
  });
  r = await act(codeJar, h.realmBase + "/gnap-api/code", { code: code });
  check("7d. the code act is bound as every act is", function () {
    assert.strictEqual(r.status, 403, K.shown(r));
  });
  const oldCode = await K.send(h.realmBase + "/gnap/code",
                               { form: "code=X", jar: codeJar });
  const oldApprove = await K.send(later.approve,
                                  { form: "action=allow", jar: later.jar });
  check("8. POST /gnap/code and POST /gnap/approve/{id} are gone",
        function () {
    assert.strictEqual(oldCode.status, 404);
    assert.strictEqual(oldApprove.status, 404);
  });
  log.debug("Leaving userCode().");
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gia", "development", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  const PERSON = "gia-alice-" + K.STAMP;
  await h.ensurePerson(PERSON);
  await G.resourceServer(h, "gia-rs-" + K.STAMP, G.client(),
                         "https://gia-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] },
                          { type: OTHER, actions: ["read"] }]);
  c = G.client();
  await G.entry(h, "gia-client-" + K.STAMP, "gnap-client", c,
                { gnapFinishUri: [h.FINISH] });
  const codeJar = await shell();
  const later = await protocolAnswers(PERSON);
  await userCode(codeJar, later);
  log.debug("Leaving test().");
}

K.main(test, 27);
