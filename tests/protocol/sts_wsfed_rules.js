// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wsfed_rules.js
//
// ===========================================================================
// WHAT WS-FEDERATION'S PASSIVE PROFILE ISSUES AND DEMANDS, OVER THE WIRE
// (#444 D12, phase 7).
//
// `tests/wsfed_saml2_token.js` and `tests/wsfed_wauth_step_up.js` drive the
// stack in a child process and read the session off `authn`'s module. Here
// the same requests go to a running service, in a development realm of the
// job's own (development accepts any password, which is what both files
// rely on), through `/realm/<id>/wsfed` with a cookie jar and the sign-in
// screen walked over `/authn-api`; what the session IS comes from the
// person's `/logout` inventory, the one model of a live session.
//
//   T. THE SAML 2.0 TOKEN NAMES ITS SESSION (#1243), asked for by a wreq
//      RST naming the type:
//      a. its SessionIndex is the session's id, not the assertion's ID;
//      b. a second token by single sign-on in that session carries the same
//         SessionIndex and AuthnInstant — the session's authentication time,
//         earlier than the token's IssueInstant;
//      c. a bearer SubjectConfirmationData: Recipient the wreply,
//         NotOnOrAfter the Conditions', no InResponseTo;
//      d. with saml.clockSkewS set the two expiries still agree;
//      e. another browser's sign-in carries another SessionIndex;
//      f. the default SAML 1.1 token's AuthenticationInstant is the
//         session's authentication time too.
//   S. `wauth` AS A STEP-UP (#36):
//      a. a password wauth on a one-factor session is answered at once;
//      b. a multi-factor wauth on it is sent to sign in again — the screen
//         demanding the second factor, the one-attempt marker on the return
//         — and a one-time code there yields multipleauthn; then the same
//         demand is met at once;
//      c. a hardware wauth on that two-factor session is sent to sign in
//         again, the screen demanding the KEY; a person with a second factor
//         and no key is told so (STS-AUTHN-0204), and the marker with no key
//         is refused (STS-WSFED-0009);
//      d. a marker forged onto a first request is refused (STS-WSFED-0010),
//         the shared error page with its diagnostics and no code, and in the
//         language asked for;
//      e. with no session the demand reaches the screen from the start;
//      f. an unknown wauth (STS-WSFED-0006), and two class URIs in one;
//      k/l. a phr / phrh wauth on a one-factor session is one step-up, the
//         key demanded; coming back without earning the class is refused
//         once (STS-WSFED-0030), the code not in the body;
//      m. a password wauth, no wauth, and a multi-factor wauth still issue
//         what they did before #737.
//
//      g. a real WebAuthn ceremony at the screen the key demand sends the
//         browser to (`passkey_wire_kit.js`'s software authenticator, the
//         screen's first use enrolling in development): a passwordless key
//         alone meets it (HardwareToken), a password and a key meets it
//         (multipleauthn), and the session meets it at once afterwards;
//      j. a person holding an authenticator app and a passkey enrolled
//         passwordless, signing in with a password under a key demand, is
//         sent to an ASSERTION of that passkey, never to an enrolment;
//      n. a passkey registration under phr earns nothing (STS-WSFED-0030);
//         an assertion with that key carries the phr URI on both token
//         types, and a later request that does not ask does not.
//
// NOT HERE: `step_up.screenDemandFor()` as a function (h, i), which is
// (d).
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_wsfed_rules");
// A method URI named in a page or a token, parsed rather than searched
// for as text (`url_match.js`).
const urls = require("./url_match.js");

const log = K.log;
const REALM_URI = "urn:wsfed-rules:" + K.STAMP;
const WREPLY = "https://rp.wsfed-rules.example/wsfed";
const SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";
const WREQ = '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open' +
  '.org/ws-sx/ws-trust/200512"><wst:TokenType>' + SAML2 +
  "</wst:TokenType></wst:RequestSecurityToken>";
const MFA = "http://schemas.microsoft.com/claims/multipleauthn";
const KEY = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
const PASSWORD = "urn:oasis:names:tc:SAML:1.0:am:password";
const PHR = "http://schemas.openid.net/pape/policies/2007/06/" +
            "phishing-resistant";
const PHRH = "http://schemas.openid.net/acr/2016/07/" +
             "phishing-resistant-hardware";
const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
            "PasswordProtectedTransport";

const UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const PK = require("./passkey_wire_kit.js").kit("sts_wsfed_rules",
                                                { log: K.log });
let D = null;

function signInUrl(extra) {
  log.debug("Entering signInUrl().");
  const o = Object.assign({}, extra || {});
  const saml2 = o.saml2;
  delete o.saml2;
  log.debug("Leaving signInUrl().");
  return K.rb(D) + "/wsfed?" + new URLSearchParams(Object.assign({
    wa: "wsignin1.0", wtrealm: REALM_URI, wctx: "ctx-1", wreply: WREPLY },
  saml2 ? { wreq: WREQ } : {}, o)).toString();
}

function wresultOf(r) {
  log.debug("Entering wresultOf().");
  const m = /name="wresult" value="([^"]*)"/.exec(r.text || "");
  log.debug("Leaving wresultOf().");
  return m ? m[1].replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&") : "";
}

function attrOf(xml, element, name) {
  log.debug("Entering attrOf().");
  const el = new RegExp("<(?:\\w+:)?" + element + "\\b[^>]*>").exec(xml);
  const a = el ? new RegExp("\\s" + name + "=\"([^\"]*)\"").exec(el[0])
               : null;
  log.debug("Leaving attrOf().");
  return a ? a[1] : undefined;
}

function cookieOf(b) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(b.jar).map(function (k) {
    return k + "=" + b.jar[k];
  }).join("; ");
}

function keepAll(b, lines) {
  log.debug("Entering keepAll().");
  (lines || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at > 0) {
      const value = pair.slice(at + 1);
      if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(line))) {
        delete b.jar[pair.slice(0, at)];
      } else {
        b.jar[pair.slice(0, at)] = value;
      }
    }
  });
  log.debug("Leaving keepAll().");
}

function toSignIn(r) {
  log.debug("Entering toSignIn().");
  log.debug("Leaving toSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login/.test(r.location);
}

// RFC 6238, HMAC-SHA-1, six digits, thirty seconds.
function totp(secret, offset) {
  log.debug("Entering totp().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of String(secret).replace(/[\s=]/g, "").toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) +
                                  (offset || 0)));
  const mac = nodeCrypto.createHmac("sha1", Buffer.from(bytes))
    .update(message).digest();
  const at = mac[mac.length - 1] & 0xf;
  const value = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
    (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totp().");
  return String(value % 1000000).padStart(6, "0");
}

// THE SIGN-IN SCREEN, WALKED: `first` sent the browser there. `o.code` a
// one-time code for the second-factor step; `o.enrol` enrols an
// authenticator app on the way (a required second factor). Answers the
// screen's view, the screen's answer, the address it sent the browser back
// to and the relying party's page there.
async function walk(b, first, username, o) {
  log.debug("Entering walk(). " + username);
  const opts = o || {};
  const rb = K.rb(D);
  const at = /^https?:/.test(first.location) ? first.location
                                             : K.base + first.location;
  const opened = await authnSignin.screen(rb, at, { cookie: cookieOf(b) });
  keepAll(b, opened.setCookies);
  let a = await authnSignin.submit(rb, at, { action: "login",
    username: username, password: opts.password || "anything" },
  { screen: opened, cookie: cookieOf(b) });
  keepAll(b, a.setCookies);
  let secret = "";
  let stepView = null;
  if (a.next === "mfa" && a.location) {
    const stepPage = await authnSignin.step(a.location,
                                            { cookie: cookieOf(b) });
    keepAll(b, stepPage.setCookies);
    stepView = stepPage.view;
    if (opts.enrol) {
      const begun = await authnSignin.stepAct(stepPage, "setup/totp", {});
      keepAll(b, begun.setCookies);
      const shown = await authnSignin.step(begun.location,
                                           { cookie: cookieOf(b) });
      keepAll(b, shown.setCookies);
      secret = ((shown.view.setup || {}).totp || {}).secret || "";
      a = await authnSignin.stepAct(shown, "setup/confirm",
                                    { code: totp(secret, 0) });
    } else if (opts.code) {
      a = await authnSignin.stepAct(stepPage, "totp",
                                    { code: opts.code() });
    }
    keepAll(b, a.setCookies);
  }
  let back = "";
  let final = null;
  if (a.next === "redirect" && a.location) {
    back = a.location;
    final = await b.go(back);
  }
  log.debug("Leaving walk(). " + a.next);
  return { view: opened.view || {}, answer: a, back: back, final: final,
           secret: secret, stepView: stepView };
}

// A token: straight through by single sign-on, or through the screen.
async function tokenFor(b, username, saml2) {
  log.debug("Entering tokenFor().");
  const first = await b.go(signInUrl({ saml2: saml2 }));
  if (first.status === 200) {
    log.debug("Leaving tokenFor(). By single sign-on.");
    return wresultOf(first);
  }
  const done = await walk(b, first, username);
  log.debug("Leaving tokenFor().");
  return wresultOf(done.final || { text: "" });
}

// The browser's live sign-on session, from its own /logout inventory.
async function sessionOf(b) {
  log.debug("Entering sessionOf().");
  const r = await b.go(K.rb(D) + "/logout",
                       { headers: { accept: "application/json" } });
  const family = ((r.json && r.json.families) || []).filter(function (f) {
    return f.id === "session";
  })[0] || { rows: [] };
  log.debug("Leaving sessionOf().");
  return family.rows[0] || null;
}

// --------------------------------------------------------------------- T
async function sessionToken() {
  log.debug("Entering sessionToken().");
  log.info("=== T. the SAML 2.0 token names its session (#1243) ===");
  const alice = K.browser();
  const one = await tokenFor(alice, "wr-alice", true);
  const session = await sessionOf(alice);
  K.check("Ta0. a wreq naming SAML 2.0 yields a SAML 2.0 assertion, and " +
          "the person holds a sign-on session", function () {
    assert.ok(/<(\w+:)?Assertion\b[^>]*urn:oasis:names:tc:SAML:2\.0:assertion/
      .test(one), one.slice(0, 300));
    assert.ok(session && session.sessionId, JSON.stringify(session));
  });
  const index1 = attrOf(one, "AuthnStatement", "SessionIndex");
  const id1 = attrOf(one, "Assertion", "ID");
  K.check("Ta1. SessionIndex is the session's id, not the assertion's ID",
          function () {
            assert.strictEqual(index1, session.sessionId);
            assert.notStrictEqual(index1, id1);
          });
  await K.sleep(1100);
  const two = await tokenFor(alice, "wr-alice", true);
  const authTime = new Date(session.startedAt).toISOString();
  K.check("Tb1. a second token in the same session names the same session",
          function () {
            assert.strictEqual(attrOf(two, "AuthnStatement",
                                      "SessionIndex"), index1);
            assert.notStrictEqual(attrOf(two, "Assertion", "ID"), id1);
          });
  K.check("Tb2. AuthnInstant is the session's authentication time on both, " +
          "earlier than the second token's IssueInstant", function () {
    const ai2 = attrOf(two, "AuthnStatement", "AuthnInstant");
    assert.strictEqual(Math.floor(Date.parse(ai2) / 1000),
                       Math.floor(Date.parse(authTime) / 1000),
                       ai2 + " vs " + authTime);
    assert.strictEqual(ai2, attrOf(one, "AuthnStatement", "AuthnInstant"));
    assert.ok(Date.parse(ai2) < Date.parse(attrOf(two, "Assertion",
                                                  "IssueInstant")));
  });
  K.check("Tc. a bearer SubjectConfirmationData: Recipient the wreply, " +
          "NotOnOrAfter the Conditions', no InResponseTo", function () {
    assert.ok(/<(\w+:)?SubjectConfirmationData\b/.test(one));
    assert.strictEqual(attrOf(one, "SubjectConfirmationData", "Recipient"),
                       WREPLY);
    assert.strictEqual(attrOf(one, "SubjectConfirmationData",
                              "NotOnOrAfter"),
                       attrOf(one, "Conditions", "NotOnOrAfter"));
    assert.strictEqual(attrOf(one, "SubjectConfirmationData",
                              "InResponseTo"), undefined);
  });
  await K.set(D, "saml.clockSkewS", 120);
  const skewed = await tokenFor(alice, "wr-alice", true);
  await K.unset(D, "saml.clockSkewS");
  K.check("Td. with saml.clockSkewS set, the two expiries still agree",
          function () {
            const e = attrOf(skewed, "SubjectConfirmationData",
                             "NotOnOrAfter");
            assert.ok(e && e === attrOf(skewed, "Conditions", "NotOnOrAfter"),
                      e);
          });
  const other = K.browser();
  const three = await tokenFor(other, "wr-alice", true);
  K.check("Te. another browser's sign-in carries another SessionIndex",
          function () {
            const i3 = attrOf(three, "AuthnStatement", "SessionIndex");
            assert.ok(i3 && i3 !== index1, i3);
          });
  const saml11 = await tokenFor(alice, "wr-alice", false);
  K.check("Tf. the default SAML 1.1 token's AuthenticationInstant is the " +
          "session's authentication time too", function () {
    const ai = attrOf(saml11, "AuthenticationStatement",
                      "AuthenticationInstant");
    assert.strictEqual(Math.floor(Date.parse(ai) / 1000),
                       Math.floor(Date.parse(authTime) / 1000),
                       ai + " vs " + authTime);
  });
  log.debug("Leaving sessionToken().");
}

// --------------------------------------------------------------------- S
function methodOf(text) {
  log.debug("Entering methodOf().");
  log.debug("Leaving methodOf().");
  return (/AuthenticationMethod="([^"]+)"/.exec(wresultOf({ text: text })) ||
          [])[1] || "";
}

function classRefOf(text) {
  log.debug("Entering classRefOf().");
  log.debug("Leaving classRefOf().");
  return (/<(?:\w+:)?AuthnContextClassRef>([^<]+)</.exec(
    wresultOf({ text: text })) || [])[1] || "";
}

async function coded(code, act) {
  log.debug("Entering coded(). " + code);
  log.debug("Leaving coded().");
  return K.coded(D, code, act);
}

async function stepUp() {
  log.debug("Entering stepUp().");
  log.info("=== S. wauth as a step-up (#36) ===");
  // A one-factor session first (wr-carol holds nothing yet), then her
  // authenticator app enrolled in another browser: the session stays the
  // one-factor one the in-process file's alice holds.
  const bob = K.browser();
  let first = await bob.go(signInUrl());
  K.check("Sa0. with no session, the sign-in screen", function () {
    assert.ok(toSignIn(first), first.status + " " + first.location);
  });
  let done = await walk(bob, first, "wr-carol");
  K.check("Sa0b. (a password sign-in answers the relying party)",
          function () {
            assert.ok(done.final && /wresult/.test(done.final.text));
          });
  await K.ok(K.rb(D) + "/admin-api/users/require-mfa", { user: "wr-carol" },
             "required a second factor of wr-carol");
  const alice = K.browser();
  done = await walk(alice, await alice.go(signInUrl()), "wr-carol",
                    { enrol: true });
  const secret = done.secret;
  await K.ok(K.rb(D) + "/admin-api/users/stop-requiring-mfa",
             { user: "wr-carol" }, "stopped requiring it");
  K.check("Sb0. (wr-carol enrols an authenticator app in another browser)",
          function () {
            assert.ok(secret, JSON.stringify(done.answer.json || {})
              .slice(0, 300));
          });
  let r = await bob.go(signInUrl({ wauth: PASSWORD }));
  K.check("Sa1. a password wauth on a one-factor session is answered at " +
          "once", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(methodOf(r.text), PASSWORD);
  });
  first = await bob.go(signInUrl({ wauth: MFA }));
  K.check("Sb1. a MULTI-FACTOR wauth on a one-factor session is sent to " +
          "sign in again, not refused", function () {
    assert.ok(toSignIn(first), K.shown(first));
  });
  done = await walk(bob, first, "wr-carol", { code: function () {
    return totp(secret, 1);
  } });
  K.check("Sb2. the return carries the one-attempt marker; the screen " +
          "demanded the second factor", function () {
    assert.ok(/step_up_honoured=1/.test(done.back), done.back);
    assert.strictEqual((done.view.demands || {}).mfa, true,
                       JSON.stringify(done.view.demands));
  });
  K.check("Sb3. a one-time code there answers with multipleauthn",
          function () {
            assert.ok(done.final && done.final.status === 200,
                      JSON.stringify(done.answer.json || {}).slice(0, 300));
            assert.strictEqual(methodOf(done.final.text), MFA);
          });
  r = await bob.go(signInUrl({ wauth: MFA }));
  K.check("Sb4. the same demand on the two-factor session is met at once",
          function () {
            assert.strictEqual(methodOf(r.text), MFA, K.shown(r));
          });
  first = await bob.go(signInUrl({ wauth: KEY }));
  K.check("Sc1. a HARDWARE wauth on a session that used a code and no key " +
          "is sent to sign in again", function () {
    assert.ok(toSignIn(first), K.shown(first));
  });
  const keyAt = K.base + first.location;
  const keyScreen = await authnSignin.screen(K.rb(D), keyAt,
                                             { cookie: cookieOf(bob) });
  K.check("Sc2. the screen demands the key and not two factors, both " +
          "lanes allowed", function () {
    const v = keyScreen.view || {};
    assert.strictEqual((v.demands || {}).key, true, JSON.stringify(v));
    assert.strictEqual((v.demands || {}).mfa, false);
    assert.strictEqual((v.keys || {}).mfaAllowed, true);
    assert.strictEqual((v.keys || {}).primaryAllowed, true);
  });
  const noKey = await coded("STS-AUTHN-0204", function () {
    return authnSignin.submit(K.rb(D), keyAt, { action: "login",
      username: "wr-carol", password: "anything" },
    { screen: keyScreen, cookie: cookieOf(bob) });
  });
  K.check("Sc3. a person holding a second factor and no key is told so, " +
          "STS-AUTHN-0204", function () {
    assert.ok(/This request needs a passkey/.test(
      JSON.stringify(noKey.answer.json || noKey.answer.text || "")),
    JSON.stringify(noKey.answer.json || {}).slice(0, 300));
    assert.ok(noKey.rose >= 1);
  });
  const forgedKey = await coded("STS-WSFED-0009", function () {
    return bob.go(signInUrl({ wauth: KEY, step_up_honoured: "1" }));
  });
  K.check("Sc4. back with the marker and still no key: refused, " +
          "STS-WSFED-0009", function () {
    assert.strictEqual(forgedKey.answer.status, 400);
    assert.ok(/No security key was used/.test(forgedKey.answer.text));
    assert.ok(forgedKey.rose >= 1);
  });
  const dave = K.browser();
  first = await dave.go(signInUrl());
  await walk(dave, first, "wr-dave");
  const forged = await coded("STS-WSFED-0010", function () {
    return dave.go(signInUrl({ wauth: MFA, step_up_honoured: "1" }));
  });
  const t = forged.answer.text;
  K.check("Sd1. a marker forged onto a first request: refused, " +
          "STS-WSFED-0010", function () {
    assert.strictEqual(forged.answer.status, 400);
    assert.ok(/Still one factor/.test(t));
    assert.ok(forged.rose >= 1);
  });
  K.check("Sd2. the refusal is the shared error page: the sentence, two " +
          "ways forward, the portal, an incident ID, the summary as data, " +
          "no key and no code", function () {
    assert.ok(/<div class="warn" role="alert">/.test(t));
    assert.ok(/only one factor was used/.test(t));
    assert.ok(/<h2>Two ways forward<\/h2>/.test(t));
    assert.ok(/href="[^"]*\/portal"/.test(t));
    assert.ok(/<dt>Incident ID<\/dt><dd><code>\d+<\/code>/.test(t));
    assert.ok(/<dt>Summary<\/dt><dd><code>Still one factor<\/code>/.test(t));
    assert.ok(/<dt>wtrealm<\/dt>/.test(t));
    assert.ok(t.indexOf("wsfedErrors.") < 0 && t.indexOf("STS-WSFED") < 0);
  });
  const fr = await dave.go(signInUrl({ wauth: MFA, step_up_honoured: "1" }),
    { headers: { "accept-language": "fr" } });
  K.check("Sd3. every word follows the language asked for; the English " +
          "summary stays as data", function () {
    assert.strictEqual(fr.status, 400);
    assert.ok(/<html lang="fr"/.test(fr.text));
    assert.ok(/un seul facteur a été utilisé/.test(fr.text));
    assert.ok(/Deux façons de continuer/.test(fr.text));
    assert.ok(/Still one factor/.test(fr.text));
  });
  const erin = K.browser();
  first = await erin.go(signInUrl({ wauth: MFA }));
  const page = await authnSignin.screen(K.rb(D), K.base + first.location,
                                        { cookie: cookieOf(erin) });
  K.check("Se. with no session the demand goes to the screen, which " +
          "demands the second factor from the start", function () {
    assert.ok(toSignIn(first));
    assert.strictEqual(((page.view || {}).demands || {}).mfa, true);
  });
  const unknown = await coded("STS-WSFED-0006", function () {
    return dave.go(signInUrl({ wauth: "urn:example:retina" }));
  });
  K.check("Sf1. an unknown wauth is refused, STS-WSFED-0006, the list " +
          "naming the hardware token", function () {
    assert.strictEqual(unknown.answer.status, 400);
    assert.ok(/not available/.test(unknown.answer.text));
    assert.ok(unknown.answer.text.indexOf(KEY) >= 0);
    assert.ok(unknown.rose >= 1);
  });
  const both = await coded("STS-WSFED-0006", function () {
    return dave.go(signInUrl({ wauth: PHR + " " + PHRH }));
  });
  K.check("Sk0. two class URIs in one wauth are one unknown value " +
          "(STS-WSFED-0006)", function () {
    assert.strictEqual(both.answer.status, 400);
    assert.ok(both.rose >= 1);
  });
  for (const [label, uri, hardware] of [["k", PHR, false],
                                        ["l", PHRH, true]]) {
    const start = await dave.go(signInUrl({ wauth: uri }));
    const s = await authnSignin.screen(K.rb(D), K.base + start.location,
                                       { cookie: cookieOf(dave) });
    K.check("S" + label + "1. a " + (hardware ? "phrh" : "phr") + " wauth " +
            "on a one-factor session is one step-up: the key demanded",
            function () {
              assert.ok(toSignIn(start), K.shown(start));
              assert.strictEqual(((s.view || {}).demands || {}).key, true,
                                 JSON.stringify((s.view || {}).demands));
            });
    const backAgain = await coded("STS-WSFED-0030", function () {
      return dave.go(signInUrl({ wauth: uri, step_up_honoured: "1" }));
    });
    K.check("S" + label + "2. coming back without earning the class is the " +
            "refusal page, once, STS-WSFED-0030, no code in the body",
            function () {
              const x = backAgain.answer;
              assert.strictEqual(x.status, 400, K.shown(x));
              assert.ok(/The class was not earned/.test(x.text));
              assert.strictEqual(/hardware-protected/.test(x.text), hardware);
              assert.ok(x.text.indexOf("STS-WSFED-0030") < 0);
              assert.ok(x.text.indexOf(uri) >= 0);
              assert.ok(!toSignIn(x));
              assert.ok(backAgain.rose >= 1);
            });
  }
  r = await dave.go(signInUrl({ wauth: PASSWORD, saml2: true }));
  K.check("Sm1. a password wauth still issues PasswordProtectedTransport, " +
          "neither EAP URI", function () {
    assert.strictEqual(classRefOf(r.text), PPT, K.shown(r));
    assert.ok(!urls.namesAddress(r.text, PHR) &&
              !urls.namesAddress(r.text, PHRH));
  });
  r = await dave.go(signInUrl({ saml2: true }));
  K.check("Sm2. a request with no wauth is unchanged", function () {
    assert.strictEqual(classRefOf(r.text), PPT);
  });
  r = await bob.go(signInUrl({ wauth: MFA, saml2: true }));
  K.check("Sm3. a multi-factor wauth still issues multipleauthn",
          function () {
            assert.strictEqual(classRefOf(r.text), MFA, K.shown(r));
            assert.ok(!urls.namesAddress(r.text, PHR));
          });
  r = await dave.go(signInUrl({ wauth: PASSWORD }));
  K.check("Sm4. the default SAML 1.1 token keeps am:password", function () {
    assert.strictEqual(methodOf(r.text), PASSWORD);
  });
  log.debug("Leaving stepUp().");
}

// ------------------------------------------------------------- G, J, N
// A REAL WebAuthn CEREMONY at the sign-in screen a key demand sends the
// browser to, with `passkey_wire_kit.js`'s software authenticator: the
// screen's first use in development enrols (create), a later sign-in
// asserts (get).
async function withKey(username, wauth, passwordless, auth, extra) {
  log.debug("Entering withKey(). " + username);
  const b = K.browser();
  const start = await b.go(signInUrl(Object.assign({ wauth: wauth },
                                                   extra || {})));
  if (!toSignIn(start)) {
    log.debug("Leaving withKey(). Not sent to sign in.");
    return { start: start, mode: "", answer: start, b: b };
  }
  const rb = K.rb(D);
  const at = /^https?:/.test(start.location) ? start.location
                                             : K.base + start.location;
  const opened = await authnSignin.screen(rb, at, { cookie: cookieOf(b) });
  keepAll(b, opened.setCookies);
  const a = await authnSignin.submit(rb, at, { action: "login",
    username: username, password: passwordless ? "" : "anything",
    webauthn_only: passwordless ? "1" : "" },
  { screen: opened, cookie: cookieOf(b) });
  keepAll(b, a.setCookies);
  if (!(a.next === "mfa" && a.location)) {
    log.debug("Leaving withKey(). No key step: " + a.next);
    return { start: start, mode: "", answer: { status: a.status,
      text: JSON.stringify(a.json || {}) }, b: b, submitted: a };
  }
  const step = await authnSignin.step(a.location, { cookie: cookieOf(b) });
  keepAll(b, step.setCookies);
  let mode = "";
  const ran = await authnSignin.passkeyStep(step, function (c) {
    mode = c.mode;
    return c.mode === "create"
      ? auth.register(c.challenge, (c.user || {}).id, c.rpId)
      : auth.assert(c.challenge, { rpId: c.rpId });
  }, { cookie: cookieOf(b) });
  keepAll(b, ran.setCookies);
  const answer = ran.next === "redirect" && ran.location
    ? await b.go(ran.location) : { status: ran.status,
                                   text: JSON.stringify(ran.json || {}) };
  log.debug("Leaving withKey(). " + mode);
  return { start: start, mode: mode, ran: ran, answer: answer, b: b,
           submitted: a, step: step };
}

function assertionSays(r, method) {
  log.debug("Entering assertionSays().");
  log.debug("Leaving assertionSays().");
  return r.status === 200 && /wresult/.test(r.text || "") &&
         String(r.text).indexOf(method) >= 0;
}

async function keys() {
  log.debug("Entering keys().");
  log.info("=== G, J, N. a real WebAuthn ceremony at the screen ===");
  const k1 = PK.authenticator();
  const g1 = await withKey("wr-passkey", KEY, true, k1);
  K.check("Sg1. a PASSWORDLESS security key — one factor, amr hwk — " +
          "meets a hardware wauth, and the assertion says HardwareToken",
  function () {
    assert.strictEqual(g1.mode, "create", K.shown(g1.answer));
    assert.ok(assertionSays(g1.answer, KEY), K.shown(g1.answer));
  });
  const k2 = PK.authenticator();
  const g2 = await withKey("wr-keypair", KEY, false, k2);
  K.check("Sg2. and so does a password AND a key — two factors, so the " +
          "assertion says multipleauthn", function () {
    assert.strictEqual(g2.mode, "create", K.shown(g2.answer));
    assert.ok(assertionSays(g2.answer, MFA), K.shown(g2.answer));
  });
  const g3 = await g2.b.go(signInUrl({ wauth: KEY }));
  K.check("Sg3. and the demand is met at once on that session afterwards",
          function () {
            assert.ok(assertionSays(g3, MFA), K.shown(g3));
          });
  // j: a person holding a second factor and a passkey enrolled
  // passwordless; a password sign-in under a key demand goes on to an
  // ASSERTION of that passkey and never to an enrolment (#898, #1135).
  const primary = "wr-primary";
  const kp = PK.authenticator();
  const made = await withKey(primary, KEY, true, kp);
  const portal = require("./portal_signin.js");
  const client = await portal.signInToThePortal(K.rb(D), primary, null,
    { cookie: cookieOf(made.b) });
  let r = await client.act("/portal/mfa", { action: "start" });
  const page = await client.page("/portal/mfa");
  const secret = String(((page.json && page.json.setup) || {}).grouped || "")
    .replace(/\s+/g, "");
  r = await client.act("/portal/mfa", { action: "confirm",
                                        code: totp(secret, 0) });
  K.check("Sj0. (wr-primary holds a passkey made passwordless and an " +
          "authenticator app)", function () {
    assert.strictEqual(made.mode, "create");
    assert.ok(r.status === 200 && r.json && r.json.ok, K.shown(r));
  });
  const dave = K.browser();
  const first = await dave.go(signInUrl({ wauth: KEY }));
  const rb = K.rb(D);
  const at = /^https?:/.test(first.location) ? first.location
                                             : K.base + first.location;
  const opened = await authnSignin.screen(rb, at, { cookie: cookieOf(dave) });
  keepAll(dave, opened.setCookies);
  const toKey = await authnSignin.submit(rb, at, { action: "login",
    username: primary, password: "anything" },
  { screen: opened, cookie: cookieOf(dave) });
  keepAll(dave, toKey.setCookies);
  const keyPage = toKey.next === "mfa"
    ? await authnSignin.step(toKey.location, { cookie: cookieOf(dave) })
    : {};
  const keyView = ((keyPage.view || {}).webauthn) || {};
  K.check("Sj1. a password sign-in by somebody holding a second factor and " +
          "a passkey enrolled passwordless goes on, under a key demand, to " +
          "an ASSERTION of that passkey, never to an enrolment", function () {
    assert.strictEqual(toKey.next, "mfa", JSON.stringify(toKey.json || {})
      .slice(0, 300));
    assert.strictEqual(toKey.step, "webauthn");
    assert.strictEqual(keyView.mode, "get", JSON.stringify(keyPage.view)
      .slice(0, 300));
  });
  // n: phr under a passkey.
  const kphr = PK.authenticator();
  const n1 = await coded("STS-WSFED-0030", function () {
    return withKey("wr-phr", PHR, true, kphr);
  });
  K.check("Sn1. a passkey registration under phr earns nothing: one trip, " +
          "then the class was not earned (400, STS-WSFED-0030), the code " +
          "not sent", function () {
    assert.strictEqual(n1.answer.mode, "create");
    assert.strictEqual(n1.answer.answer.status, 400,
                       K.shown(n1.answer.answer));
    assert.ok(/The class was not earned/.test(n1.answer.answer.text));
    assert.ok(n1.answer.answer.text.indexOf("STS-WSFED-0030") < 0);
    assert.ok(n1.rose >= 1);
  });
  const n2 = await withKey("wr-phr", PHR, true, kphr, { saml2: true });
  K.check("Sn2. an assertion with the same key earns phr, and the SAML 2.0 " +
          "class ref is that URI", function () {
    assert.strictEqual(n2.mode, "get", K.shown(n2.answer));
    assert.strictEqual(n2.answer.status, 200, K.shown(n2.answer));
    assert.strictEqual(classRefOf(n2.answer.text), PHR);
    assert.ok(!urls.namesAddress(n2.answer.text, PHRH));
  });
  const n3 = await n2.b.go(signInUrl({ wauth: PHR }));
  K.check("Sn3. the same session meets phr at once, and the SAML 1.1 " +
          "AuthenticationMethod is that URI", function () {
    assert.strictEqual(n3.status, 200, K.shown(n3));
    assert.strictEqual(methodOf(n3.text), PHR);
  });
  const n4 = await n2.b.go(signInUrl({ saml2: true }));
  K.check("Sn4. a request that does not ask keeps unspecified, even though " +
          "the session earned phr", function () {
    assert.strictEqual(n4.status, 200, K.shown(n4));
    assert.strictEqual(classRefOf(n4.text), UNSPECIFIED);
    assert.ok(!urls.namesAddress(n4.text, PHR) &&
              !urls.namesAddress(n4.text, PHRH));
  });
  log.debug("Leaving keys().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("wsr-d", "development");
  await K.ok(K.rb(D) + "/admin-api/applications/create", {
    identifier: REALM_URI, name: "wsfed rules", protocols: ["wsfed"],
    fields: { wsfedRealm: [REALM_URI], wsfedReplyUrl: [WREPLY] } },
  "created the relying party");
  for (const who of ["wr-alice", "wr-carol", "wr-dave", "wr-passkey",
                     "wr-keypair", "wr-primary", "wr-phr"]) {
    await K.person(D, who, "Wr-Passw0rd!-" + K.rand(3));
  }
  await sessionToken();
  await stepUp();
  await keys();
  log.debug("Leaving test().");
}

K.main(test, 43);
