// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9101_request_object_jti.js
//
// ---------------------------------------------------------------------------
// AN RFC 9101 REQUEST OBJECT'S `jti` IS ACCEPTED ONCE (#35), OVER THE WIRE.
//
// D12 (#444): carries over `tests/rfc9101_request_object_jti.js`'s child
// process (2a–2s) against a running service, in a development realm of its
// own, with a listener in this job serving an object by reference
// (OUTBOUND_TEST_HOST is the address the service reaches it at):
//
//   a. the passes before and after the sign-in screen are one use, and a
//      replay is refused invalid_request_object on this server before
//      anybody is asked to sign in;
//   b. a flow started before the spend is refused on its return;
//   c. a `login_required` error spends nothing;
//   d. no `jti` is never remembered; another client's `jti` is another
//      document; `oauth2.requestObjectJtiOnce` turns it off and on;
//   e. the consent screen is a third pass of the same use;
//   f. by reference, the same;
//   g. a pushed object is spent at the push, its URN still issues, and it
//      is refused at a second push and by value; an object spent at the
//      authorization endpoint is refused at the push;
//   h. `GET /admin-api/used-assertions` lists them as spent
//      `request-object` rows, and an object with no jti not at all.
//
// NOT CARRIED, and why: `onceOf()`, `lookUp()`, `spend()`,
// `used_assertions.peek()` and `claim()`'s `keepBelow` as functions (1a–1j)
// are library — (d); `keepBelow`'s effect is what a, b and f observe, since
// every redirect would otherwise release its claim. The RFC 7523 namespace
// shared with a client assertion is `sts_jwt_bearer_grant.js`'s family.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const K = require("./oauth_wire_kit.js")
  .kit("sts_rfc9101_request_object_jti");
const log = K.log;

const SECRET = "jti-client-secret-" + K.rand(16);
const REDIRECT = "https://rp.jti.example/cb";
const PERSON = "jti-alice-" + K.STAMP;
const PASSWORD = "Jti-" + K.rand(9) + "-pw!";
const EC = K.keyPair("ES256", "jti-ec");
const FLOOR = 21;

let D;
let ISS;
let L;
let served = "";
let counter = 0;

function check(what, fn) {
  K.check(what, fn);
}

function objectFor(clientId, extra) {
  log.debug("Entering objectFor().");
  counter += 1;
  const claims = Object.assign({ iss: clientId, aud: ISS,
    client_id: clientId, response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + counter, nonce: "n-" + K.rand(6),
    exp: Math.floor(Date.now() / 1000) + 300,
    jti: "jti-" + counter + "-" + K.STAMP + "-" + K.rand(4) },
    extra || {});
  Object.keys(claims).forEach(function (k) {
    if (claims[k] === null) {
      delete claims[k];
    }
  });
  log.debug("Leaving objectFor().");
  return { claims: claims, jwt: K.jws("ES256", { kid: "jti-ec",
    typ: "oauth-authz-req+jwt" }, claims, EC) };
}

async function authorize(query) {
  log.debug("Entering authorize().");
  const b = K.browser();
  const r = await b.go(K.rb(D) + "/oauth2/authorize?" +
                       new URLSearchParams(query).toString());
  r.b = b;
  log.debug("Leaving authorize().");
  return r;
}

function byValue(clientId, object, extra) {
  log.debug("Entering byValue().");
  log.debug("Leaving byValue().");
  return authorize(Object.assign({ client_id: clientId,
                                   request: object.jwt }, extra || {}));
}

function refusedAsUsed(r) {
  log.debug("Entering refusedAsUsed().");
  log.debug("Leaving refusedAsUsed().");
  return r.status === 400 && !!r.json &&
    r.json.error === "invalid_request_object" &&
    /used already/.test(r.json.error_description || "");
}

function codeAt(r, state) {
  log.debug("Entering codeAt().");
  const p = K.answerAt(r, REDIRECT);
  log.debug("Leaving codeAt().");
  return !!p && !!p.get("code") && (!state || p.get("state") === state);
}

// Signs in and answers the screen's own 303, NOT followed.
function held(first) {
  log.debug("Entering held().");
  log.debug("Leaving held().");
  return K.signIn(D, first.b, first, PERSON, PASSWORD, { follow: false });
}

async function resume(b, back) {
  log.debug("Entering resume().");
  let r = await b.go(back);
  for (let hops = 0; hops < 8 && (r.status === 302 || r.status === 303) &&
       (/^\//.test(r.location) || urls.isUnder(r.location, K.base));
       hops++) {
    r = await b.go(r.location);
  }
  log.debug("Leaving resume().");
  return r;
}

async function complete(first) {
  log.debug("Entering complete().");
  const back = await held(first);
  const r = back.location ? await resume(first.b, back.location) : back;
  log.debug("Leaving complete().");
  return r;
}

function push(object) {
  log.debug("Entering push().");
  log.debug("Leaving push().");
  return K.send(K.rb(D) + "/oauth2/par", {
    headers: { Authorization: K.basic("jti-a", SECRET) },
    form: { request: object.jwt } });
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("jti", "development",
                    { "federation.outboundAllowHttp": true });
  ISS = (await K.send(K.rb(D) + "/.well-known/oauth-authorization-server"))
    .json.issuer;
  await K.person(D, PERSON, PASSWORD);
  L = await K.listener({ "/ro/one": function (req, res) {
    res.writeHead(200, { "Content-Type": "application/oauth-authz-req+jwt" });
    res.end(served);
  } });
  try {
    for (const id of ["jti-a", "jti-b", "jti-consent"]) {
      await K.app(D, id, { oauthClientId: id, oauthClientSecret: SECRET,
        oauthRedirectUri: [REDIRECT],
        oauthTokenEndpointAuthMethod: "client_secret_basic",
        oauthRequestUri: [L.origin + "/ro/one"],
        oauthJwks: JSON.stringify({ keys: [EC.jwk] }) });
    }
    await sections();
  } finally {
    L.close();
  }
  log.debug("Leaving test().");
}

async function sections() {
  log.debug("Entering sections().");
  log.info("=== a. the passes are one use; a replay is refused ===");
  const one = objectFor("jti-a");
  let r = await byValue("jti-a", one);
  check("a1. an object with a jti reaches the sign-in screen", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  let final = await complete(r);
  check("a2. and its second pass, after the sign-in, issues a code: the " +
        "two passes are one use", function () {
    assert.ok(codeAt(final, one.claims.state), K.shown(final));
  });
  r = await byValue("jti-a", one);
  check("a3. the same object again is refused invalid_request_object " +
        "before the sign-in screen, on this server", function () {
    assert.ok(refusedAsUsed(r), K.shown(r));
    assert.ok(!K.toSignIn(r));
  });

  log.info("=== b. a flow started before the spend ===");
  const kept = objectFor("jti-a");
  const firstFlow = await byValue("jti-a", kept);
  const keptBack = await held(firstFlow);
  final = await complete(await byValue("jti-a", kept));
  check("b1. a second flow on one object issues first", function () {
    assert.ok(codeAt(final, kept.claims.state), K.shown(final));
  });
  r = await firstFlow.b.go(keptBack.location);
  check("b2. and the first flow, returning from its sign-in afterwards, is " +
        "refused on that pass", function () {
    assert.ok(refusedAsUsed(r), K.shown(r));
  });

  log.info("=== c. a refused request spends nothing ===");
  const silent = objectFor("jti-a", { prompt: "none" });
  r = await byValue("jti-a", silent);
  const again = await byValue("jti-a", silent);
  check("c1. prompt=none with no session is answered login_required",
        function () {
    assert.ok(/error=login_required/.test(r.location), K.shown(r));
  });
  check("c2. and the same object is not refused as used: an error " +
        "response spent nothing", function () {
    assert.ok(!refusedAsUsed(again), K.shown(again));
    assert.ok(/error=login_required/.test(again.location), K.shown(again));
  });

  log.info("=== d. no jti, another client, the switch ===");
  const bare = objectFor("jti-a", { jti: null });
  final = await complete(await byValue("jti-a", bare));
  const bareAgain = await complete(await byValue("jti-a", bare));
  check("d1. an object with no jti issues a code every time it is sent",
        function () {
    assert.ok(codeAt(final, bare.claims.state), K.shown(final));
    assert.ok(codeAt(bareAgain, bare.claims.state), K.shown(bareAgain));
  });
  const shared = objectFor("jti-a");
  final = await complete(await byValue("jti-a", shared));
  r = await byValue("jti-b", objectFor("jti-b", { jti: shared.claims.jti }));
  check("d2. another client's object with the same jti is another document",
        function () {
    assert.ok(codeAt(final, shared.claims.state), K.shown(final));
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  await K.set(D, "oauth2.requestObjectJtiOnce", false);
  try {
    final = await complete(await byValue("jti-a", shared));
  } finally {
    await K.unset(D, "oauth2.requestObjectJtiOnce");
  }
  check("d3. oauth2.requestObjectJtiOnce off: a spent object issues again",
        function () {
    assert.ok(codeAt(final, shared.claims.state), K.shown(final));
  });
  r = await byValue("jti-a", shared);
  check("d4. and on again, it is refused again", function () {
    assert.ok(refusedAsUsed(r), K.shown(r));
  });

  log.info("=== e. the consent screen is a third pass ===");
  await K.set(D, "oauth2.consentRequired", true);
  let consented;
  let replayed;
  const asked = objectFor("jti-consent", { scope: "openid email" });
  try {
    const first = await byValue("jti-consent", asked);
    const signedIn = await K.signIn(D, first.b, first, PERSON, PASSWORD);
    consented = signedIn.consent
      ? await K.consent(first.b, signedIn.consent) : signedIn;
    consented.where = signedIn.consent;
    replayed = await byValue("jti-consent", asked);
  } finally {
    await K.set(D, "oauth2.consentRequired", false);
  }
  check("e1. the passes before sign-in, after it and after the consent " +
        "screen are one use, and the last issues a code", function () {
    assert.ok(/\/oauth2\/consent/.test(consented.where || ""),
              consented.where);
    assert.ok(codeAt(consented, asked.claims.state), K.shown(consented));
  });
  check("e2. and the object is spent once the consent has issued",
        function () {
    assert.ok(refusedAsUsed(replayed), K.shown(replayed));
  });

  log.info("=== f. by reference ===");
  const referenced = objectFor("jti-a");
  served = referenced.jwt;
  const byRef = { client_id: "jti-a", request_uri: L.origin + "/ro/one" };
  final = await complete(await authorize(byRef));
  r = await authorize(byRef);
  check("f1. an object by reference issues a code", function () {
    assert.ok(codeAt(final, referenced.claims.state), K.shown(final));
  });
  check("f2. and the same request_uri, answering the same object, is " +
        "refused", function () {
    assert.ok(refusedAsUsed(r), K.shown(r));
  });

  log.info("=== g. a pushed object is spent at the push ===");
  const pushed = objectFor("jti-a");
  r = await push(pushed);
  check("g1. a pushed object with a jti is kept", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
  });
  const viaUrn = await authorize({ client_id: "jti-a",
                                   request_uri: r.json.request_uri });
  final = await complete(viaUrn);
  check("g2. its URN reaches the sign-in screen and issues a code: the URN " +
        "spends nothing again", function () {
    assert.ok(K.toSignIn(viaUrn), K.shown(viaUrn));
    assert.ok(codeAt(final, pushed.claims.state), K.shown(final));
  });
  r = await push(pushed);
  check("g3. the same object pushed again is refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_request_object");
    assert.ok(/used already/.test(r.json.error_description || ""));
  });
  r = await byValue("jti-a", pushed);
  check("g4. and so is the pushed object sent by value", function () {
    assert.ok(refusedAsUsed(r), K.shown(r));
  });
  const spentFirst = objectFor("jti-a");
  await complete(await byValue("jti-a", spentFirst));
  r = await push(spentFirst);
  check("g5. an object spent at the authorization endpoint is refused at " +
        "the push", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_request_object");
  });

  log.info("=== h. the history lists them ===");
  const listed = await K.send(K.rb(D) +
    "/admin-api/used-assertions?use=request-object&per=500");
  const rows = (listed.json && (listed.json.rows || listed.json.items ||
                                listed.json.assertions)) || [];
  const ids = rows.map(function (row) {
    return row.identifier;
  });
  check("h1. the used-assertion history lists each spent object as a " +
        "spent request-object row, and an object with no jti not at all",
        function () {
    assert.strictEqual(listed.status, 200, K.shown(listed));
    assert.ok(ids.indexOf(one.claims.jti) >= 0, JSON.stringify(
      Object.keys(listed.json || {})) + " " + JSON.stringify(rows[0]));
    assert.ok(ids.indexOf(pushed.claims.jti) >= 0);
    assert.ok(ids.indexOf(referenced.claims.jti) >= 0);
    assert.ok(rows.filter(function (row) {
      return ids.indexOf(row.identifier) >= 0 &&
             String(row.identifier).indexOf(K.STAMP) >= 0;
    }).every(function (row) {
      return row.state === "spent" && row.format === "jwt";
    }), JSON.stringify(rows.slice(0, 2)));
    assert.ok(!rows.some(function (row) {
      return row.identifier === undefined && row.state === "spent";
    }));
  });
  log.debug("Leaving sections().");
}

K.main(test, FLOOR);
