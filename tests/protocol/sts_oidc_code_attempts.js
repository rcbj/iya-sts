// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidc_code_attempts.js
//
// ---------------------------------------------------------------------------
// AN OIDC AUTHORIZATION-CODE SIGN-IN ON THE AUTHENTICATION ATTEMPTS TAB, OVER
// THE WIRE.
//
// D12 (#444): carries `tests/oidc_code_attempts.js`. The tab is the audit log,
// and the console draws it from `GET /admin-api/applications?application=`'s
// `authenticationEvents` (and the person's from `GET /admin-api/users?user=`),
// so this job asks those answers. In a throwaway realm:
//
//   1.–3. an application declared for the code flow (a public client) and a
//      person, signed in through `/oauth2/authorize` and the sign-in screen;
//      the application's attempts name the person, the client and the
//      method, and carry no password;
//   4.–6. `sts-admin-console`, the realm's seeded code-flow client, and the
//      same person signing in to it in a new browser; its attempts list them
//      and not the other application;
//   7. neither screen sign-in wrote `session.presented` (the return trip to
//      `/oauth2/authorize` is the sign-in's own);
//   8.–11. the first browser's single sign-on to the console, with no
//      screen, writes exactly one `session.presented` row naming the
//      console, `existing session` and the session, on the console's
//      attempts and on the person's;
//   12. a single sign-on through a CONSENT screen into a second application
//      writes one row, not one each way.
//
// NOT carried, and why: the tab's markup (the console renderer's HTML, the
// "No authentication attempt" sentence, the query links) is drawn in the
// browser from the same members asserted here — class (d).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_oidc_code_attempts");
const log = K.log;

const APP = "oca-app";
const APP2 = "oca-consent";
const CONSOLE = "sts-admin-console";
const REDIRECT = "https://rp.oca.example/cb";
const REDIRECT2 = "https://rp2.oca.example/cb";
const PERSON = "oca-user-" + K.STAMP;
const PASSWORD = "Oca-" + K.rand(9) + "-pw!";
const FLOOR = 12;

function check(what, fn) {
  K.check(what, fn);
}

function publicApp(id, redirect) {
  log.debug("Entering publicApp(). " + id);
  log.debug("Leaving publicApp().");
  return { oauthClientId: [id], oauthRedirectUri: [redirect],
           oauthGrantType: ["authorization_code"],
           oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
           oauthTokenEndpointAuthMethod: "none" };
}

// One authorization request; `screened` says whether the sign-in screen
// was met, `consented` whether the consent screen was.
async function authorize(realm, b, clientId, redirect, signIn) {
  log.debug("Entering authorize(). " + clientId);
  const v = nodeCrypto.randomBytes(32).toString("base64url");
  const q = { client_id: clientId, response_type: "code",
    redirect_uri: redirect, scope: "openid", state: "s-" + K.rand(3),
    nonce: "n-" + K.rand(3),
    code_challenge: nodeCrypto.createHash("sha256").update(v)
      .digest("base64url"),
    code_challenge_method: "S256" };
  let r = await b.go(K.rb(realm) + "/oauth2/authorize?" +
                     new URLSearchParams(q));
  const screened = K.toSignIn(r);
  if (screened && signIn) {
    // Not the kit's signIn(): the console's redirect is on this service's
    // own origin, and the kit follows every hop that stays here.
    r = await authnSignin.signInWithJar(K.rb(realm), r.location,
      { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  }
  let consented = false;
  for (let hops = 0; hops < 6; hops++) {
    const loc = /^https?:/.test(r.location) ? r.location
      : K.base + r.location;
    if (urls.isAt(loc, redirect)) {
      break;
    }
    if (authnSignin.isConsent(loc)) {
      consented = true;
      r = await authnSignin.consentWithJar(loc, "allow", b.jar);
    } else if ((r.status === 302 || r.status === 303) &&
               urls.isUnder(loc, K.base)) {
      r = await b.go(loc);
    } else {
      break;
    }
  }
  log.debug("Leaving authorize().");
  return { r: r, screened: screened, consented: consented,
           coded: /[?&]code=/.test(String(r.location)) &&
                  urls.isAt(r.location, redirect) };
}

async function attempts(realm, application) {
  log.debug("Entering attempts().");
  const r = await K.send(K.rb(realm) + "/admin-api/applications?" +
    new URLSearchParams({ application: application }));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving attempts().");
  return r.json;
}

async function presented(realm) {
  log.debug("Entering presented().");
  const r = await K.send(K.rb(realm) + "/admin-api/audit?" +
    new URLSearchParams({ action: "session.presented", per: "200" }));
  log.debug("Leaving presented().");
  return ((r.json && r.json.events) || []).filter(function (row) {
    return JSON.stringify(row).indexOf(PERSON) >= 0;
  });
}

function eventsBy(json, action) {
  log.debug("Entering eventsBy().");
  log.debug("Leaving eventsBy().");
  return ((json && json.authenticationEvents) || []).filter(function (row) {
    return row.action === action &&
      JSON.stringify(row).indexOf(PERSON) >= 0;
  });
}

async function test() {
  log.debug("Entering test().");
  const R = await K.realm("oca", "development");
  const made = await K.app(R, APP, publicApp(APP, REDIRECT));
  await K.person(R, PERSON, PASSWORD);
  check("1. an OIDC authorization-code application and a person are " +
        "created", function () {
    assert.ok(made && made.ok !== false, JSON.stringify(made));
  });

  const first = K.browser();
  const signed = await authorize(R, first, APP, REDIRECT, true);
  check("2. the person finishes the authorization-code sign-in",
        function () {
    assert.ok(signed.screened, "the sign-in screen was not met");
    assert.ok(signed.coded, K.shown(signed.r));
  });

  const appJson = await attempts(R, APP);
  const appEvents = eventsBy(appJson, "authentication");
  check("3. the application's authentication attempts name the person, " +
        "the client and the method, and no password", function () {
    assert.ok(appEvents.length >= 1,
              JSON.stringify(appJson.authenticationEvents).slice(0, 600));
    const d = appEvents[0].detail || {};
    assert.ok(d.application === APP || d.client_id === APP,
              JSON.stringify(d));
    assert.ok(d.method, JSON.stringify(d));
    assert.ok(JSON.stringify(appJson).indexOf(PASSWORD) < 0);
    assert.ok(JSON.stringify(appJson.authenticationEvents)
      .indexOf("\"" + CONSOLE + "\"") < 0);
  });

  const consoleJson = await attempts(R, CONSOLE);
  const f = consoleJson.fields || {};
  const consoleRedirect = [].concat(f.oauthRedirectUri || [])[0] || "";
  check("4. sts-admin-console is the realm's seeded authorization-code " +
        "client", function () {
    assert.ok([].concat(f.oauthGrantType || [])
      .indexOf("authorization_code") >= 0, JSON.stringify(f));
    const rt = [].concat(f.oauthResponseType || []);
    assert.ok(rt.length === 0 || rt.indexOf("code") >= 0);
    assert.ok(consoleRedirect, JSON.stringify(f));
  });

  const second = await authorize(R, K.browser(), CONSOLE, consoleRedirect,
                                 true);
  check("5. the same person signs in to sts-admin-console that way",
        function () {
    assert.ok(second.screened && second.coded, K.shown(second.r));
  });
  const consoleAfter = eventsBy(await attempts(R, CONSOLE),
                                "authentication");
  check("6. sts-admin-console's authentication attempts list that person, " +
        "for the console and not the other application", function () {
    assert.ok(consoleAfter.length >= 1);
    const d = consoleAfter[0].detail || {};
    assert.ok(d.application === CONSOLE || d.client_id === CONSOLE,
              JSON.stringify(d));
    assert.ok(d.method, JSON.stringify(d));
    assert.ok(d.application !== APP && d.client_id !== APP);
  });

  const beforeSso = await presented(R);
  check("7. neither screen sign-in wrote session.presented", function () {
    assert.strictEqual(beforeSso.length, 0, JSON.stringify(beforeSso));
  });

  const sso = await authorize(R, first, CONSOLE, consoleRedirect, false);
  check("8. the first browser reaches sts-admin-console on the session it " +
        "holds, with no sign-in screen", function () {
    assert.ok(!sso.screened && sso.coded, K.shown(sso.r));
  });
  const afterSso = await presented(R);
  check("9. that single sign-on wrote ONE session.presented row naming " +
        "sts-admin-console, the method and the session", function () {
    assert.strictEqual(afterSso.length, 1, JSON.stringify(afterSso));
    const d = afterSso[0].detail || {};
    assert.strictEqual(d.application, CONSOLE, JSON.stringify(d));
    assert.strictEqual(d.method, "existing session");
    assert.strictEqual(afterSso[0].protocol, "OAuth 2.0 / OIDC");
    assert.ok(d.sub && d.sessionId, JSON.stringify(d));
  });
  const ssoEvents = eventsBy(await attempts(R, CONSOLE),
                             "session.presented");
  check("10. sts-admin-console's attempts list the single sign-on",
        function () {
    assert.strictEqual(ssoEvents.length, 1);
    assert.strictEqual(ssoEvents[0].detail.method, "existing session");
  });
  const user = await K.send(K.rb(R) + "/admin-api/users?" +
                            new URLSearchParams({ user: PERSON }));
  const userEvents = ((user.json && user.json.authenticationEvents) || [])
    .filter(function (row) {
      return row.action === "session.presented";
    });
  check("11. the person's authentication attempts list the single sign-on " +
        "to sts-admin-console, with no password", function () {
    assert.strictEqual(userEvents.length, 1, K.shown(user));
    assert.strictEqual(userEvents[0].detail.application, CONSOLE);
    assert.ok(user.text.indexOf(PASSWORD) < 0);
  });

  await K.app(R, APP2, publicApp(APP2, REDIRECT2));
  await K.set(R, "oauth2.consentRequired", true);
  const before2 = (await presented(R)).length;
  const sso2 = await authorize(R, first, APP2, REDIRECT2, false);
  const after2 = await presented(R);
  check("12. a single sign-on through a consent screen writes one " +
        "session.presented row, not one each way", function () {
    assert.ok(!sso2.screened && sso2.consented && sso2.coded,
              JSON.stringify({ screened: sso2.screened,
                               consented: sso2.consented,
                               at: K.shown(sso2.r) }));
    assert.strictEqual(after2.length, before2 + 1);
    assert.strictEqual(after2.filter(function (row) {
      return (row.detail || {}).application === APP2;
    }).length, 1);
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
