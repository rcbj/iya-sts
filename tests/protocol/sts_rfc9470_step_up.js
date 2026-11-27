// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9470_step_up.js
//
// ===========================================================================
// RFC 9470 STEP-UP AUTHENTICATION: THE REFUSALS BY CODE, max_age, THE
// RETURN MARKER AND THIS SERVICE'S OWN RESOURCE SERVER (D12, #444).
//
// `sts_step_up.js` holds the end-to-end step-up against the test peer's
// resource server. This job carries what `tests/rfc9470_step_up.js` held in
// its child process and a client can still see with no peer, in a
// throwaway development realm, with a client of its own so the monitor's
// counters are EXACT, every code read off `/admin-api/audit`:
//
//   1. max_age: 3600 met by a fresh session with no sign-in; 0 sends the
//      session to sign in exactly once, the code comes back after it, and
//      the new ID Token's auth_time has moved;
//   2. A FORGED RETURN MARKER (`step_up_honoured=1` written by the client
//      itself): with max_age=0, a session that signed in inside the sign-in
//      window is answered rather than looped; with an unmeetable acr value
//      it is refused unmet_authentication_requirements at once
//      (STS-OAUTH-0500);
//   3. AN acr VALUE NO SIGN-IN HERE PRODUCES gets ONE sign-in and is then
//      refused unmet_authentication_requirements (STS-OAUTH-0500);
//   4. prompt=none with an unmet requirement is login_required
//      (STS-OAUTH-0502); an unusable acr value is invalid_request;
//   5. THIS SERVICE'S OWN RESOURCE SERVER, UserInfo: `oauth2.stepUpAcrValues`
//      set IN THE REALM challenges a one-factor token with section 3's
//      error and auth-param (STS-OAUTH-0503); `oauth2.stepUpMaxAgeS` a
//      token older than it (STS-OAUTH-0504); both taken off again;
//   6. MFA: an authenticator app enrolled on the portal with a code this job
//      computes; acr_values=mfa demands the second factor at the screen and
//      the token carries "mfa"; UserInfo, now requiring mfa, answers it; the
//      mfa session answers acr_values=1 with "1" in the token; a refresh
//      keeps the acr;
//   7. THE TWO WRITE DOORS: an acr value with a quote (STS-REG-0140) and a
//      negative max age (STS-REG-0141) refused on the application;
//   8. THE MONITOR: this client's eight counters, exactly.
//
// NOT CARRIED (class (d)): `step_up.ts`'s parse, ordering and aliases as a
// library, `audienceNamesEntry()`, the acr pattern held equal to the
// library's, a session older than the sign-in window (the window is the
// pending-authentication lifetime, minutes, not a clock a job can wait out,
// and it is what STS-OAUTH-0501 needs: a marker on a session older than it),
// and the sign-in POST dropping the screen's hidden second-factor field —
// the static screen has no hidden field since #571 and its act is driven
// by the view.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const portalSignin = require("./portal_signin.js");
const K = require("./oauth_wire_kit.js").kit("sts_rfc9470_step_up");
const log = K.log;

const SECRET = "su-secret-" + K.rand(10);
const PASSWORD = "Su-" + K.rand(6) + "-password!";
const REDIRECT = "https://su-client.example/cb";
const CLIENT = "su-client-" + K.STAMP;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    value = (value << 5) | B32.indexOf(cleaned[i]);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

// RFC 4226 section 5.3 over RFC 6238 section 4.2, this job's own.
function codeFor(secret, atMs) {
  log.debug("Entering codeFor().");
  const counter = Math.floor(Number(atMs || Date.now()) / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac("sha1", base32ToBytes(secret))
    .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving codeFor().");
  return String(binary % 1000000).padStart(6, "0");
}

function authorizeUrl(id, extra) {
  log.debug("Entering authorizeUrl().");
  const p = K.pkce();
  const url = K.rb(id) + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", client_id: CLIENT,
                    redirect_uri: REDIRECT, scope: "openid offline_access",
                    state: "su", nonce: "n-" + K.rand(4),
                    code_challenge: p.challenge,
                    code_challenge_method: "S256" }, extra || {}));
  log.debug("Leaving authorizeUrl().");
  return { url: url, verifier: p.verifier };
}

// The authorization endpoint on browser `b`; follows this service's own
// redirects except to the sign-in screen, which it reports.
async function ask(id, b, extra) {
  log.debug("Entering ask().");
  const asked = authorizeUrl(id, extra);
  let r = await b.go(asked.url);
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       !K.toSignIn(r) && (/^\//.test(r.location) ||
                          urls.isUnder(r.location, K.base)); hops++) {
    r = await b.go(r.location);
  }
  log.debug("Leaving ask(). " + r.status);
  return { r: r, verifier: asked.verifier,
           answer: K.answerAt(r, REDIRECT) };
}

async function redeem(id, code, verifier) {
  log.debug("Entering redeem().");
  const r = await K.send(K.rb(id) + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT,
    code_verifier: verifier, client_id: CLIENT, client_secret: SECRET } });
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving redeem().");
  return r.json;
}

// A full trip: the request, a sign-in if one is asked, the code redeemed.
async function trip(id, b, extra, user) {
  log.debug("Entering trip().");
  const first = await ask(id, b, extra);
  let r = first.r;
  let signedIn = false;
  if (K.toSignIn(r)) {
    signedIn = true;
    r = await K.signIn(id, b, r, user, PASSWORD);
  }
  const answer = K.answerAt(r, REDIRECT);
  const tokens = answer && answer.get("code")
    ? await redeem(id, answer.get("code"), first.verifier) : null;
  log.debug("Leaving trip().");
  return { first: first.r, r: r, answer: answer, tokens: tokens,
           signedIn: signedIn };
}

function userinfo(id, token) {
  log.debug("Entering userinfo().");
  log.debug("Leaving userinfo().");
  return K.send(K.rb(id) + "/oauth2/userinfo",
                { headers: { authorization: "Bearer " + token } });
}

async function counters(id) {
  log.debug("Entering counters().");
  for (let page = 1; page < 50; page++) {
    const r = await K.send(K.rb(id) + "/admin-api/oauth2/monitor?" +
                           "stepUpClientsPage=" + page);
    const section = ((r.json && r.json.sections) || []).filter(
      function (one) {
        return one.id === "stepup";
      })[0];
    assert.ok(section, K.shown(r));
    const row = section.clients.filter(function (one) {
      return one.client_id === CLIENT;
    })[0];
    if (row) {
      log.debug("Leaving counters().");
      return row.counters;
    }
    if (page >= ((section.clientsPaging || {}).pages || 1)) {
      break;
    }
  }
  log.debug("Leaving counters(). No row.");
  return {};
}

async function enrol(id, user) {
  log.debug("Entering enrol().");
  const portal = await portalSignin.signInToThePortal(K.rb(id), user, null,
                                                      { password: PASSWORD });
  let r = await portal.act("/portal/mfa", { action: "start" });
  assert.ok(r.status === 200 && r.json && r.json.ok, K.shown(r));
  const page = await portal.page("/portal/mfa");
  const secret = String(((page.json && page.json.setup) || {}).grouped || "")
    .replace(/\s+/g, "");
  assert.ok(secret.length >= 32, "no secret: " + page.text.slice(0, 300));
  const at = Date.now();
  r = await portal.act("/portal/mfa", { action: "confirm",
                                        code: codeFor(secret, at) });
  assert.ok(r.status === 200 && r.json && r.json.ok, K.shown(r));
  log.debug("Leaving enrol().");
  return { secret: secret, step: Math.floor(at / 30000) };
}

async function test() {
  log.debug("Entering test().");
  const id = await K.realm("su", "development");
  const user = "su-alice-" + K.STAMP;
  await K.person(id, user, PASSWORD);
  await K.app(id, CLIENT, { oauthClientId: [CLIENT],
    oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthRedirectUri: [REDIRECT],
    oauthAllowedScope: ["openid", "offline_access"],
    oauthGrantType: ["authorization_code", "refresh_token"] });
  const b = K.browser();

  log.info("=== 0. a one-factor session ===");
  const plain = await trip(id, b, {}, user);
  const firstAuth = K.decode(plain.tokens.id_token).payload.auth_time;
  K.check("0. (a control: a password sign-in issues a token with acr \"1\")",
          function () {
    assert.ok(plain.signedIn);
    assert.strictEqual(K.decode(plain.tokens.access_token).payload.acr, "1");
  });

  log.info("=== 1. max_age ===");
  const met = await trip(id, b, { max_age: "3600" }, user);
  K.check("1a. max_age=3600 is met by the session: no sign-in, a code",
          function () {
    assert.ok(!met.signedIn && met.tokens, K.shown(met.r));
  });
  await K.sleep(1100);
  const zero = await trip(id, b, { max_age: "0" }, user);
  K.check("1b. max_age=0 sends the session to sign in, once, and the code " +
          "comes back after it", function () {
    assert.ok(zero.signedIn, K.shown(zero.first));
    assert.ok(zero.tokens, K.shown(zero.r));
  });
  K.check("1c. and the new ID Token's auth_time has moved", function () {
    const later = K.decode(zero.tokens.id_token).payload.auth_time;
    assert.ok(later > firstAuth, firstAuth + " -> " + later);
  });

  log.info("=== 2. a forged return marker ===");
  // THE MARKER IS TRUSTED ONLY INSIDE THE SIGN-IN WINDOW: a session that
  // authenticated within it (1b, a second ago) meets max_age=0 when the
  // marker says the sign-in it was sent to happened. A session older than
  // the window would be refused STS-OAUTH-0501, and the window is minutes
  // (see the header), so what a client sees here is the answer.
  const forgedAge = await ask(id, b, { max_age: "0",
                                       step_up_honoured: "1" });
  K.check("2a. max_age=0 with step_up_honoured=1 on a session that signed in " +
          "inside the sign-in window is answered — the marker does not loop " +
          "it back to the screen", function () {
    assert.ok(!K.toSignIn(forgedAge.r), K.shown(forgedAge.r));
    assert.ok(forgedAge.answer && forgedAge.answer.get("code"),
              K.shown(forgedAge.r));
  });
  const forgedAcr = await K.coded(id, "STS-OAUTH-0500", function () {
    return ask(id, b, { acr_values: "urn:example:never",
                        step_up_honoured: "1" });
  });
  K.check("2b. an unmeetable acr value with a forged marker is refused " +
          "unmet_authentication_requirements at once (STS-OAUTH-0500)",
          function () {
    const a = forgedAcr.answer.answer;
    assert.ok(a, K.shown(forgedAcr.answer.r));
    assert.strictEqual(a.get("error"), "unmet_authentication_requirements");
    assert.ok(forgedAcr.rose >= 1);
  });

  log.info("=== 3. an acr value no sign-in here produces ===");
  const before0500 = await K.codeCount(id, "STS-OAUTH-0500");
  const never = await trip(id, b, { acr_values: "urn:example:never" }, user);
  const after0500 = await K.codeAfter(id, "STS-OAUTH-0500", before0500);
  K.check("3. it gets ONE sign-in and is then refused " +
          "unmet_authentication_requirements (STS-OAUTH-0500)", function () {
    assert.ok(never.signedIn, K.shown(never.first));
    assert.ok(never.answer, K.shown(never.r));
    assert.strictEqual(never.answer.get("error"),
                       "unmet_authentication_requirements");
    assert.ok(after0500 > before0500);
  });

  log.info("=== 4. prompt=none, and an unusable acr value ===");
  const none = await K.coded(id, "STS-OAUTH-0502", function () {
    return ask(id, b, { acr_values: "mfa", prompt: "none" });
  });
  K.check("4a. prompt=none with acr_values=mfa on a one-factor session is " +
          "login_required (STS-OAUTH-0502)", function () {
    assert.ok(none.answer.answer, K.shown(none.answer.r));
    assert.strictEqual(none.answer.answer.get("error"), "login_required");
    assert.ok(none.rose >= 1);
  });
  const quoted = await ask(id, b, { acr_values: "mfa a\"b" });
  K.check("4b. acr_values=mfa a\"b is invalid_request", function () {
    assert.ok(quoted.answer, K.shown(quoted.r));
    assert.strictEqual(quoted.answer.get("error"), "invalid_request");
  });

  log.info("=== 5. this service's own resource server ===");
  const oneFactor = plain.tokens.access_token;
  await K.set(id, "oauth2.stepUpAcrValues", "mfa");
  const challenged = await K.coded(id, "STS-OAUTH-0503", function () {
    return userinfo(id, oneFactor);
  });
  K.check("5a. with oauth2.stepUpAcrValues=mfa in the realm, UserInfo " +
          "challenges a one-factor token with section 3's error and " +
          "acr_values (STS-OAUTH-0503)", function () {
    const r = challenged.answer;
    assert.strictEqual(r.status, 401, K.shown(r));
    const header = String(r.headers.get("www-authenticate") || "");
    assert.ok(/error="insufficient_user_authentication"/.test(header),
              header);
    assert.ok(/acr_values="mfa"/.test(header), header);
    assert.ok(challenged.rose >= 1);
  });
  await K.unset(id, "oauth2.stepUpAcrValues");
  const freed = await userinfo(id, oneFactor);
  K.check("5b. taken off again, the same token is answered", function () {
    assert.strictEqual(freed.status, 200, K.shown(freed));
  });
  await K.set(id, "oauth2.stepUpMaxAgeS", 1);
  await K.sleep(2100);
  const aged = await K.coded(id, "STS-OAUTH-0504", function () {
    return userinfo(id, zero.tokens.access_token);
  });
  K.check("5c. with oauth2.stepUpMaxAgeS=1, a token whose authentication is " +
          "older is challenged with max_age (STS-OAUTH-0504)", function () {
    const r = aged.answer;
    assert.strictEqual(r.status, 401, K.shown(r));
    const header = String(r.headers.get("www-authenticate") || "");
    assert.ok(/insufficient_user_authentication/.test(header), header);
    assert.ok(/max_age="?1"?/.test(header), header);
    assert.ok(aged.rose >= 1);
  });
  await K.unset(id, "oauth2.stepUpMaxAgeS");

  log.info("=== 6. a second factor ===");
  const enrolled = await enrol(id, user);
  const up = await ask(id, b, { acr_values: "mfa" });
  K.check("6a. acr_values=mfa on the one-factor session goes to the sign-in " +
          "screen, not to the client", function () {
    assert.ok(K.toSignIn(up.r), K.shown(up.r));
  });
  while (Math.floor(Date.now() / 30000) <= enrolled.step) {
    await K.sleep(1000);
  }
  const authnSignin = require("./authn_signin");
  const answer = await authnSignin.signInWithJar(K.rb(id), up.r.location,
    { action: "login", username: user, password: PASSWORD }, b.jar);
  K.check("6b. the screen demands the second factor: the password is " +
          "answered with the code step", function () {
    assert.strictEqual(answer.answer.next, "mfa",
                       JSON.stringify(answer.answer.json).slice(0, 300));
    assert.ok(/\/authn\/totp/.test(String(answer.location || "")),
              answer.location);
  });
  const opened = await authnSignin.step(answer.location
    ? new URL(answer.location, K.base).toString() : "",
    { cookie: Object.keys(b.jar).map(function (k) {
      return k + "=" + b.jar[k];
    }).join("; ") });
  const coded = await authnSignin.stepAct(opened, "totp",
    { code: codeFor(enrolled.secret) },
    { cookie: Object.keys(b.jar).map(function (k) {
      return k + "=" + b.jar[k];
    }).join("; ") });
  (coded.setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    b.jar[pair.slice(0, at)] = pair.slice(at + 1);
  });
  let r = await b.go(new URL(coded.location, K.base).toString());
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       (/^\//.test(r.location) || urls.isUnder(r.location, K.base));
       hops++) {
    r = await b.go(r.location);
  }
  const back = K.answerAt(r, REDIRECT);
  K.check("6c. the code is accepted and the stepped-up session is issued a " +
          "code", function () {
    assert.ok(back && back.get("code"), K.shown(r) + " " +
              JSON.stringify(coded.json || {}).slice(0, 200));
  });
  const mfa = await redeem(id, back.get("code"), up.verifier);
  K.check("6d. the access token and the ID Token carry acr \"mfa\"",
          function () {
    assert.strictEqual(K.decode(mfa.access_token).payload.acr, "mfa");
    assert.strictEqual(K.decode(mfa.id_token).payload.acr, "mfa");
  });
  await K.set(id, "oauth2.stepUpAcrValues", "mfa");
  const answered = await userinfo(id, mfa.access_token);
  K.check("6e. UserInfo requiring mfa answers the stepped-up token",
          function () {
    assert.strictEqual(answered.status, 200, K.shown(answered));
  });
  await K.unset(id, "oauth2.stepUpAcrValues");
  const one = await trip(id, b, { acr_values: "1" }, user);
  K.check("6f. the mfa session answers acr_values=1 with no sign-in, and " +
          "the token carries the REQUESTED \"1\"", function () {
    assert.ok(!one.signedIn && one.tokens, K.shown(one.r));
    assert.strictEqual(K.decode(one.tokens.access_token).payload.acr, "1");
  });
  const refreshed = await K.send(K.rb(id) + "/oauth2/token", { form: {
    grant_type: "refresh_token", refresh_token: mfa.refresh_token,
    client_id: CLIENT, client_secret: SECRET } });
  K.check("6g. a refresh keeps the acr", function () {
    assert.strictEqual(refreshed.status, 200, K.shown(refreshed));
    assert.strictEqual(K.decode(refreshed.json.access_token).payload.acr,
                       "mfa");
  });

  log.info("=== 7. the write doors ===");
  const acrBad = await K.coded(id, "STS-REG-0140", function () {
    return K.appSet(id, CLIENT, "oauthStepUpAcrValues", "mfa a\"b");
  });
  const ageBad = await K.coded(id, "STS-REG-0141", function () {
    return K.appSet(id, CLIENT, "oauthStepUpMaxAge", "-5");
  });
  K.check("7a. an acr value with a quote is refused on the application " +
          "(STS-REG-0140)", function () {
    assert.strictEqual(acrBad.answer.status, 400, K.shown(acrBad.answer));
    assert.ok(acrBad.rose >= 1, "STS-REG-0140 was not recorded");
  });
  K.check("7b. a negative max age is refused (STS-REG-0141)", function () {
    assert.strictEqual(ageBad.answer.status, 400, K.shown(ageBad.answer));
    assert.ok(ageBad.rose >= 1, "STS-REG-0141 was not recorded");
  });

  log.info("=== 8. the monitor ===");
  const c = await counters(id);
  K.check("8. this client's eight counters, exactly: what this job caused",
          function () {
    // Met by the session: 1a and 6f; 1b, 2a and 6c met after a
    // sign-in; 6a and 3 sent to sign in again for acr; 1b for max_age; 2b
    // and 3 unmet; 4a login_required; 5a and 5c challenged at UserInfo; and
    // no request arrived with no session at all.
    assert.deepStrictEqual(c, { stepUpMetBySession: 2, stepUpSignIn: 0,
      stepUpReauthMaxAge: 1, stepUpReauthAcr: 2, stepUpMetAfterSignIn: 3,
      stepUpUnmet: 2, stepUpLoginRequired: 1, stepUpChallenged: 2 },
      JSON.stringify(c));
  });
  log.debug("Leaving test().");
}

K.main(test, 22);
