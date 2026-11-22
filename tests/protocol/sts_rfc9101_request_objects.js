// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9101_request_objects.js
//
// ---------------------------------------------------------------------------
// RFC 9101, JWT-SECURED AUTHORIZATION REQUESTS, AND OPENID CONNECT CORE
// SECTION 6's REQUEST OBJECT, OVER THE WIRE.
//
// D12 (#444): carries over `tests/rfc9101_request_objects.js` — its child
// process's sections 3a to 3ck and the realm's encryption keys (2l) —
// against a running service, in a development realm of its own (switched to
// product for the product rows and back), with a listener in this job
// playing the client's host, which the SERVICE dials (OUTBOUND_TEST_HOST, or
// GNAP_PUSH_HOST, is the address it reaches this process at):
//
//   a. a signed object by value to a code, the query's parameters ignored,
//      the sign-in screen's view naming the verified object, OIDC 6.1's
//      duplicated response_type;
//   b. ES256, RS256, PS256 and HS256 signed HERE, the kid rule, a foreign
//      key, a wrong secret, iss, aud (the issuer or the endpoint),
//      client_id, nested request/request_uri, exp, the registered
//      algorithm, a client with no key, an unknown algorithm, headers and
//      claims that are not JSON, something that is not a JWT;
//   c. unsigned objects: accepted in development, refused expired, where
//      `oauth2.requireSignedRequestObject` is on, and in product;
//   d. typ (section 10.8) and the two require settings;
//   e. require_signed_request_object from a client and a named server;
//   f. request_uri: fetched once, the round trip, unregistered and NEVER
//      dialled, application/jwt, another media type, 404, a redirect not
//      followed, oversize, a timeout, a hang-up in one sentence, the
//      fragment digest both ways, the cache counted by hits, product
//      refusing plain http before dialling and a private address
//      (STS-OAUTH-1004), both parameters, no client_id, a repeated one;
//   g. encryption by THIS FILE's own JWE (`oauth_wire_kit.js`):
//      RSA-OAEP-256, ECDH-ES, A256KW / A128GCMKW / dir under OIDC Core
//      10.2's derived key, the raw secret refused, a foreign kid, a key
//      that is not the client's, a non-JWS inside, a tampered JWE, a client
//      registered for encryption, another algorithm, another realm's key;
//   h. a named server's two booleans (a PAR URN exempt), its signing and
//      encryption lists, PAR's URN never matched or fetched;
//   i. `prompt=login` honoured once without a loop; the consent screen's
//      view naming the verified object;
//   j. both discovery documents, the requirement dropping `none`,
//      product's document never listing it, a named server's document,
//      RFC 7591 and 7592 with the five members and two refusals, the
//      console's three attribute refusals and one write, and
//      `/admin-api/crypto` (the crypto-metadata page) against the
//      metadata.
//
// NOT CARRIED, and why: the `typ` predicate, the fragment digest and the
// parameter assembly as functions (1a–1i), the registry's checker called
// directly (2a–2k) and the keystore's serialise/enriches (2m, 2n) are
// library — (d); what they decide is what the sections above observe. And
// owed: 3bb-ii and 3bb-iii, product accepting a SIGNED object by reference
// over https and refusing an UNSIGNED one — product dials no loopback,
// private or reserved address (ASVS 5.0.0 1.3.6), the in-process file
// stubbed `vetHost()` to reach its own loopback listener, and no host this
// job can stand up has a public address; 3bb-0's refusal of that address
// is asserted instead.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_rfc9101_request_objects");
const log = K.log;

const SECRET = "r91-client-secret-" + K.rand(16);
const REDIRECT = "https://rp.r91.example/cb";
const PERSON = "r91-alice-" + K.STAMP;
const PASSWORD = "R91-" + K.rand(9) + "-pw!";
const EC = K.keyPair("ES256", "r91-ec");
const RSA = K.keyPair("RS256", "r91-rsa");
const OTHER = K.keyPair("ES256", "r91-ec");
const FLOOR = 98;

let D;
let ISS;
let L;
const served = {};
const hits = {};

function check(what, fn) {
  K.check(what, fn);
}

function fields(id, extra) {
  log.debug("Entering fields(). " + id);
  const f = Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
    oauthRedirectUri: [REDIRECT],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthJwks: JSON.stringify({ keys: [EC.jwk, RSA.jwk] }) }, extra || {});
  Object.keys(f).forEach(function (k) {
    if (f[k] === null) {
      delete f[k];
    }
  });
  log.debug("Leaving fields().");
  return f;
}

function claimsFor(clientId, extra) {
  log.debug("Entering claimsFor().");
  const c = Object.assign({ iss: clientId, aud: ISS, client_id: clientId,
    response_type: "code", redirect_uri: REDIRECT, scope: "openid",
    state: "st-" + K.rand(6), nonce: "n-" + K.rand(6),
    exp: Math.floor(Date.now() / 1000) + 300 }, extra || {});
  Object.keys(c).forEach(function (k) {
    if (c[k] === undefined) {
      delete c[k];
    }
  });
  log.debug("Leaving claimsFor().");
  return c;
}

function good(clientId, extra, header) {
  log.debug("Entering good().");
  log.debug("Leaving good().");
  return K.jws("ES256", Object.assign({ typ: "oauth-authz-req+jwt",
    kid: "r91-ec" }, header || {}), claimsFor(clientId || "r91", extra), EC);
}

function unsigned(claims) {
  log.debug("Entering unsigned().");
  log.debug("Leaving unsigned().");
  return K.jws("none", {}, claims, null);
}

function authorize(query, prefix, b) {
  log.debug("Entering authorize().");
  log.debug("Leaving authorize().");
  return (b || K.browser()).go(K.rb(D) + (prefix || "") +
    "/oauth2/authorize?" + (typeof query === "string" ? query
      : new URLSearchParams(query).toString()));
}

function sent(compact, clientId, prefix) {
  log.debug("Entering sent().");
  log.debug("Leaving sent().");
  return authorize({ client_id: clientId || "r91", request: compact },
                   prefix);
}

function byRef(uri, clientId) {
  log.debug("Entering byRef().");
  log.debug("Leaving byRef().");
  return authorize({ client_id: clientId || "r91", request_uri: uri });
}

function refused(r, error, pattern) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return r.status === 400 && !!r.json && r.json.error === error &&
    (!pattern || pattern.test(r.json.error_description || ""));
}

function codeAt(r, state) {
  log.debug("Entering codeAt().");
  const p = K.answerAt(r, REDIRECT);
  log.debug("Leaving codeAt().");
  return !!p && !!p.get("code") && (!state || p.get("state") === state);
}

async function flow(first) {
  log.debug("Entering flow().");
  const b = first.b;
  const held = await K.signIn(D, b, first, PERSON, PASSWORD,
                              { follow: false });
  let final = held;
  for (let hops = 0; hops < 8 && (final.status === 302 ||
       final.status === 303) && (/^\//.test(final.location) ||
       urls.isUnder(final.location, K.base)); hops++) {
    final = await b.go(final.location);
  }
  log.debug("Leaving flow().");
  return { back: held.location || "", view: held.view, final: final };
}

// A browser's first request, the browser kept on the answer for flow().
async function start(query, prefix) {
  log.debug("Entering start().");
  const b = K.browser();
  const r = await authorize(query, prefix, b);
  r.b = b;
  log.debug("Leaving start().");
  return r;
}

async function clientHost() {
  log.debug("Entering clientHost().");
  const serve = function (type, name) {
    log.debug("Entering serve().");
    log.debug("Leaving serve().");
    return function (req, res) {
      hits[name] = (hits[name] || 0) + 1;
      res.writeHead(200, { "Content-Type": type });
      res.end(served[name]);
    };
  };
  const routes = {
    "/ro/good": serve("application/oauth-authz-req+jwt", "/ro/good"),
    "/ro/digest": serve("application/oauth-authz-req+jwt", "/ro/digest"),
    "/ro/jwt": serve("application/jwt", "/ro/jwt"),
    "/ro/plain": serve("text/plain", "/ro/plain"),
    "/ro/redirect": function (req, res) {
      res.writeHead(302, { Location: "/ro/good" });
      res.end();
    },
    "/ro/big": function (req, res) {
      res.writeHead(200, { "Content-Type": "application/jwt" });
      res.end("x".repeat(4096));
    },
    "/ro/slow": function () {
      // Never answers: the service's timeout is the thing under test.
    },
    "/ro/hangup": function (req) {
      req.socket.destroy();
    },
    "/ro/unregistered": function (req, res) {
      hits["/ro/unregistered"] = (hits["/ro/unregistered"] || 0) + 1;
      res.writeHead(200, { "Content-Type": "application/jwt" });
      res.end(good("r91"));
    }
  };
  const host = await K.listener(routes);
  log.debug("Leaving clientHost().");
  return host;
}

// OIDC Core section 10.2, computed HERE: the leftmost octets of the SHA-2
// of the client secret.
function secretKey(bytes) {
  log.debug("Entering secretKey().");
  const hash = bytes <= 32 ? "sha256" : bytes <= 48 ? "sha384" : "sha512";
  log.debug("Leaving secretKey().");
  return nodeCrypto.createHash(hash).update(SECRET).digest()
    .subarray(0, bytes);
}

function digestUri(content) {
  log.debug("Entering digestUri().");
  log.debug("Leaving digestUri().");
  return L.origin + "/ro/digest#" + nodeCrypto.createHash("sha256")
    .update(content).digest("base64url");
}

// --------------------------------------------------------------------- a
async function byValue() {
  log.debug("Entering byValue().");
  log.info("=== a. a signed object by value, all the way ===");
  const claims = claimsFor("r91");
  const object = K.jws("ES256", { typ: "oauth-authz-req+jwt",
                                  kid: "r91-ec" }, claims, EC);
  const r = await start({ client_id: "r91", request: object,
    redirect_uri: "https://evil.example/cb", scope: "profile",
    state: "query-state" });
  check("a1. a signed request object by value reaches the sign-in screen",
        function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  const f = await flow(r);
  check("a2. the return URL carries the request object again, not the " +
        "resolved or the query's parameters", function () {
    assert.ok(/request=/.test(f.back), f.back);
    assert.ok(!/evil\.example/.test(decodeURIComponent(f.back)), f.back);
    assert.ok(!/[?&]scope=/.test(f.back), f.back);
  });
  check("a3. the response goes to the OBJECT's redirect_uri with the " +
        "OBJECT's state (section 6.3)", function () {
    assert.ok(codeAt(f.final, claims.state), K.shown(f.final));
  });
  check("a4. section 11.1: the sign-in screen's view says the request was " +
        "a verified signed request object", function () {
    assert.ok(/signed request object \(ES256\)/.test(
      JSON.stringify(f.view || {})), JSON.stringify(f.view).slice(0, 300));
  });
  let x = await authorize({ client_id: "r91", request: object,
                            response_type: "token" });
  check("a5. OIDC 6.1: a response_type duplicated in the query must match",
        function () {
    assert.ok(refused(x, "invalid_request_object", /response_type/),
              K.shown(x));
  });
  x = await authorize({ client_id: "r91", request: object,
                        response_type: "code" });
  check("a6. and a matching duplicate is accepted", function () {
    assert.ok(K.toSignIn(x), K.shown(x));
  });
  log.debug("Leaving byValue().");
}

// --------------------------------------------------------------------- b
async function algorithms() {
  log.debug("Entering algorithms().");
  log.info("=== b. algorithms and claims ===");
  const accepted = [
    ["b1. RS256 with the registered RSA key",
     K.jws("RS256", { kid: "r91-rsa" }, claimsFor("r91"), RSA)],
    ["b2. PS256", K.jws("PS256", { kid: "r91-rsa" }, claimsFor("r91"), RSA)],
    ["b3. HS256 keyed by the client secret",
     K.jws("HS256", {}, claimsFor("r91"), SECRET)],
    ["b4. no kid: every registered key of the family is tried",
     K.jws("ES256", {}, claimsFor("r91"), EC)],
    ["b5. an aud naming the authorization endpoint is accepted",
     good("r91", { aud: ISS + "/oauth2/authorize" })],
    ["b6. a client registered for ES256 accepts ES256", good("r91-es256"),
     "r91-es256"]
  ];
  for (const one of accepted) {
    const r = await sent(one[1], one[2]);
    check(one[0], function () {
      assert.ok(K.toSignIn(r), K.shown(r));
    });
  }
  const now = Math.floor(Date.now() / 1000);
  const refusals = [
    ["b7. section 6.2: a kid naming no key of this client is refused",
     K.jws("ES256", { kid: "nobody" }, claimsFor("r91"), EC),
     /section 6\.2/],
    ["b8. a signature by another key is refused",
     K.jws("ES256", { kid: "r91-ec" }, claimsFor("r91"), OTHER),
     /did not verify/],
    ["b9. HS256 with the wrong secret is refused",
     K.jws("HS256", {}, claimsFor("r91"), "wrong-secret"), /did not verify/],
    ["b10. an iss that is not the client is refused",
     good("r91", { iss: "someone-else" }), /`iss`/],
    ["b11. an aud that is not this authorization server is refused",
     good("r91", { aud: "https://other-as.example" }), /`aud`/],
    ["b12. section 6.3: a client_id claim differing from the query is " +
     "refused", good("r91", { client_id: "r91-es256" }), /MUST be identical/],
    ["b13. section 4: a request_uri claim is refused, not dropped",
     good("r91", { request_uri: "urn:ietf:params:oauth:request_uri:n" }),
     /MUST NOT be included/],
    ["b14. and so is a request claim", good("r91", { request: "eyJ.n." }),
     /MUST NOT be included/],
    ["b15. an expired request object is refused",
     good("r91", { exp: now - 3600 }), /expired/],
    ["b16. a client registered for ES256 is refused an RS256 object",
     K.jws("RS256", { kid: "r91-rsa" }, claimsFor("r91-es256"), RSA),
     /registered request_object/, "r91-es256"],
    ["b17. a client with no registered key cannot send a signed object",
     K.jws("ES256", {}, claimsFor("r91-nokeys"), EC), /holds no key/,
     "r91-nokeys"],
    ["b18. a signing algorithm this service does not know is refused",
     K.b64u({ alg: "XS256" }) + "." + K.b64u(claimsFor("r91")) + ".c2ln",
     /XS256/],
    ["b19. a header that is not JSON is refused",
     Buffer.from("{not json").toString("base64url") + "." +
       K.b64u(claimsFor("r91")) + ".c2ln", null],
    ["b20. an unsigned object whose claims are not a JSON object is refused",
     K.b64u({ alg: "none" }) + "." +
       Buffer.from("[not an object").toString("base64url") + ".", null],
    ["b21. something that is not a JWT is refused",
     "not.a.jwt.at.all.really", null]
  ];
  for (const one of refusals) {
    const r = await sent(one[1], one[3]);
    check(one[0], function () {
      assert.ok(refused(r, "invalid_request_object", one[2]), K.shown(r));
    });
  }
  log.debug("Leaving algorithms().");
}

// ----------------------------------------------------------------- c, d, e
async function unsignedAndRequired() {
  log.debug("Entering unsignedAndRequired().");
  log.info("=== c. unsigned ===");
  const plain = unsigned(claimsFor("r91"));
  let r = await sent(plain);
  check("c1. development: an unsigned request object (OIDC 6.1) is " +
        "accepted", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  r = await sent(unsigned(claimsFor("r91", {
    exp: Math.floor(Date.now() / 1000) - 3600 })));
  check("c2. and refused when it is expired", function () {
    assert.ok(refused(r, "invalid_request_object", /expired/), K.shown(r));
  });
  await K.set(D, "oauth2.requireSignedRequestObject", true);
  let a;
  let b;
  let c;
  try {
    a = await sent(plain);
    b = await authorize({ client_id: "r91", response_type: "code",
                          redirect_uri: REDIRECT, scope: "openid" });
    c = await sent(good("r91"));
  } finally {
    await K.unset(D, "oauth2.requireSignedRequestObject");
  }
  check("c3. section 10.5: refused where a signed object is required",
        function () {
    assert.ok(refused(a, "invalid_request_object", /unsigned/), K.shown(a));
  });
  check("c4. and a plain request is refused by the setting, while a signed " +
        "object is accepted", function () {
    assert.ok(refused(b, "invalid_request", /requireSignedRequestObject/),
              K.shown(b));
    assert.ok(K.toSignIn(c), K.shown(c));
  });

  log.info("=== d. typ and the two require settings ===");
  r = await sent(good("r91", {}, { typ: "at+jwt" }));
  check("d1. section 10.8: typ at+jwt is refused", function () {
    assert.ok(refused(r, "invalid_request_object", /another kind of JWT/),
              K.shown(r));
  });
  r = await sent(K.jws("ES256", { kid: "r91-ec" }, claimsFor("r91"), EC));
  check("d2. no typ is accepted by default", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  await K.set(D, "oauth2.requireRequestObjectType", true);
  try {
    a = await sent(K.jws("ES256", { kid: "r91-ec", typ: "JWT" },
                         claimsFor("r91"), EC));
    b = await sent(K.jws("ES256", { kid: "r91-ec" }, claimsFor("r91"), EC));
    c = await sent(good("r91"));
  } finally {
    await K.unset(D, "oauth2.requireRequestObjectType");
  }
  check("d3. with the type required, typ JWT and no typ are refused, and " +
        "oauth-authz-req+jwt accepted", function () {
    assert.ok(refused(a, "invalid_request_object",
                      /requireRequestObjectType/), K.shown(a));
    assert.ok(refused(b, "invalid_request_object",
                      /requireRequestObjectType/), K.shown(b));
    assert.ok(K.toSignIn(c), K.shown(c));
  });
  const noIss = claimsFor("r91", { iss: undefined, aud: undefined });
  r = await sent(K.jws("ES256", { kid: "r91-ec" }, noIss, EC));
  check("d4. without iss and aud, accepted by default", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  await K.set(D, "oauth2.requireRequestObjectIssuerAudience", true);
  try {
    a = await sent(K.jws("ES256", { kid: "r91-ec" }, noIss, EC));
    c = await sent(good("r91"));
  } finally {
    await K.unset(D, "oauth2.requireRequestObjectIssuerAudience");
  }
  check("d5. with them required, refused, and an object carrying both " +
        "accepted", function () {
    assert.ok(refused(a, "invalid_request_object",
                      /requireRequestObjectIssuer/), K.shown(a));
    assert.ok(K.toSignIn(c), K.shown(c));
  });

  log.info("=== e. require_signed_request_object, client and profile ===");
  r = await authorize({ client_id: "r91-strict", response_type: "code",
                        redirect_uri: REDIRECT, scope: "openid" });
  check("e1. a client registered require_signed_request_object refuses a " +
        "plain request", function () {
    assert.ok(refused(r, "invalid_request", /this client/), K.shown(r));
  });
  r = await sent(unsigned(claimsFor("r91-strict")), "r91-strict");
  check("e2. and an unsigned object from it", function () {
    assert.ok(refused(r, "invalid_request_object", /unsigned/), K.shown(r));
  });
  r = await sent(good("r91-strict"), "r91-strict");
  check("e3. and accepts a signed one", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  r = await authorize({ client_id: "r91", response_type: "code",
                        redirect_uri: REDIRECT, scope: "openid" });
  check("e4. another client's plain request is unaffected", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  const api = K.rb(D) + "/admin-api/authorization-servers";
  await K.ok(api + "/create", { id: "r91as" }, "created r91as");
  await K.ok(api + "/set", { profile: "r91as",
    member: "require_signed_request_object", value: "true" },
    "required signed objects at r91as");
  r = await authorize({ client_id: "r91", response_type: "code",
                        redirect_uri: REDIRECT, scope: "openid" }, "/r91as");
  check("e5. a named authorization server publishing " +
        "require_signed_request_object refuses a plain request",
        function () {
    assert.ok(refused(r, "invalid_request", /authorization server/),
              K.shown(r));
  });
  log.debug("Leaving unsignedAndRequired().");
}

// --------------------------------------------------------------------- f
async function byReference() {
  log.debug("Entering byReference().");
  log.info("=== f. request_uri ===");
  served["/ro/good"] = good("r91");
  served["/ro/jwt"] = good("r91");
  served["/ro/plain"] = good("r91");
  hits["/ro/good"] = 0;
  let r = await start({ client_id: "r91", request_uri: L.origin +
                        "/ro/good" });
  check("f1. a registered request_uri is fetched once and accepted",
        function () {
    assert.ok(K.toSignIn(r), K.shown(r));
    assert.strictEqual(hits["/ro/good"], 1);
  });
  const f = await flow(r);
  check("f2. and the round trip carries the request_uri to a code",
        function () {
    assert.ok(/request_uri=/.test(f.back), f.back);
    assert.ok(codeAt(f.final), K.shown(f.final));
  });
  r = await byRef(L.origin + "/ro/unregistered");
  check("f3. an unregistered request_uri is refused and NEVER dialled",
        function () {
    assert.ok(refused(r, "invalid_request_uri", /not one client/),
              K.shown(r));
    assert.ok(!hits["/ro/unregistered"]);
  });
  r = await byRef(L.origin + "/ro/jwt");
  check("f4. application/jwt is accepted", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  r = await byRef(L.origin + "/ro/plain");
  check("f5. development: another media type is accepted", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  r = await byRef(L.origin + "/ro/missing");
  check("f6. a request_uri answering 404 is refused", function () {
    assert.ok(refused(r, "invalid_request_uri", /HTTP 404/), K.shown(r));
  });
  hits["/ro/good"] = 0;
  r = await byRef(L.origin + "/ro/redirect");
  check("f7. section 10.4: a redirect is not followed", function () {
    assert.ok(refused(r, "invalid_request_uri", /not followed/), K.shown(r));
    assert.ok(!hits["/ro/good"]);
  });
  await K.set(D, "oauth2.requestUriMaxBytes", 1024);
  try {
    r = await byRef(L.origin + "/ro/big");
  } finally {
    await K.unset(D, "oauth2.requestUriMaxBytes");
  }
  check("f8. a response over oauth2.requestUriMaxBytes is refused",
        function () {
    assert.ok(refused(r, "invalid_request_uri", /requestUriMaxBytes/),
              K.shown(r));
  });
  await K.set(D, "oauth2.requestUriTimeoutMs", 300);
  try {
    r = await byRef(L.origin + "/ro/slow");
  } finally {
    await K.unset(D, "oauth2.requestUriTimeoutMs");
  }
  check("f9. a request_uri that does not answer is given up on",
        function () {
    assert.ok(refused(r, "invalid_request_uri", /requestUriTimeoutMs/),
              K.shown(r));
  });
  r = await byRef(L.origin + "/ro/hangup");
  check("f10. a request_uri that hangs up is refused in one sentence, one " +
        "full stop at its end", function () {
    assert.ok(refused(r, "invalid_request_uri",
      /^the request_uri ['"]http[^'"]+\/ro\/hangup['"] could not be (fetched|read): [^.]+[^.]\.$/),
      K.shown(r));
    assert.ok(!/""|''|\.\.$/.test(r.json.error_description));
  });
  served["/ro/digest"] = good("r91");
  const fresh = digestUri(served["/ro/digest"]);
  let w = await K.send(K.rb(D) + "/admin-api/applications/add", { json: {
    application: "r91", attribute: "oauthRequestUri", value: fresh } });
  assert.strictEqual(w.status, 200, K.shown(w));
  r = await byRef(fresh);
  check("f11. OIDC 6.2: a request_uri whose fragment is the SHA-256 of its " +
        "content is accepted", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  served["/ro/digest"] = good("r91");
  r = await byRef(fresh);
  check("f12. and refused once the content changes under the fragment",
        function () {
    assert.ok(refused(r, "invalid_request_uri", /SHA-256 of a different/),
              K.shown(r));
  });
  hits["/ro/good"] = 0;
  await byRef(L.origin + "/ro/good");
  await byRef(L.origin + "/ro/good");
  check("f13. with no cache, each request fetches", function () {
    assert.strictEqual(hits["/ro/good"], 2);
  });
  await K.set(D, "oauth2.requestUriCacheS", 60);
  let one;
  let two;
  try {
    hits["/ro/good"] = 0;
    one = await byRef(L.origin + "/ro/good");
    two = await byRef(L.origin + "/ro/good");
  } finally {
    await K.unset(D, "oauth2.requestUriCacheS");
  }
  check("f14. OIDC 6.2: with oauth2.requestUriCacheS on, the content is " +
        "fetched once and reused", function () {
    assert.ok(K.toSignIn(one) && K.toSignIn(two), K.shown(two));
    assert.strictEqual(hits["/ro/good"], 1);
  });
  r = await authorize({ client_id: "r91", request: good("r91"),
                        request_uri: L.origin + "/ro/good" });
  check("f15. request and request_uri together are refused", function () {
    assert.ok(refused(r, "invalid_request", /both/), K.shown(r));
  });
  r = await authorize({ request: good("r91") });
  check("f16. section 5: a request object with no client_id query " +
        "parameter is refused", function () {
    assert.ok(refused(r, "invalid_request", /client_id/), K.shown(r));
  });
  r = await authorize("client_id=r91&request=" +
    encodeURIComponent(good("r91")) + "&request=" +
    encodeURIComponent(good("r91")));
  check("f17. a repeated request parameter is refused", function () {
    assert.ok(refused(r, "invalid_request", /repeats/), K.shown(r));
  });
  log.debug("Leaving byReference().");
}

// THE PRODUCT ROWS, with the development realm switched to product and
// back: 3ab, 3bb, 3bb-0 and 3ca-ii.
async function productRows() {
  log.debug("Entering productRows().");
  log.info("=== c/f/j. the product rows ===");
  const secure = "https://" + K.HOST + ":" + L.origin.split(":").pop() +
                 "/ro/signed";
  const w = await K.send(K.rb(D) + "/admin-api/applications/add", { json: {
    application: "r91", attribute: "oauthRequestUri", value: secure } });
  assert.strictEqual(w.status, 200, K.shown(w));
  await K.set(D, "global.mode", "product");
  let a;
  let b;
  let c;
  let meta;
  try {
    a = await sent(unsigned(claimsFor("r91")));
    hits["/ro/good"] = 0;
    b = await byRef(L.origin + "/ro/good");
    c = await K.coded(D, "STS-OAUTH-1004", function () {
      return byRef(secure);
    });
    meta = (await K.send(K.rb(D) + "/.well-known/openid-configuration"))
      .json || {};
  } finally {
    await K.set(D, "global.mode", "development");
  }
  check("c5. product: an unsigned request object is refused", function () {
    assert.ok(refused(a, "invalid_request_object", /product mode/),
              K.shown(a));
  });
  check("f18. product: a plain http request_uri is refused before it is " +
        "dialled", function () {
    assert.ok(refused(b, "invalid_request_uri", /https/), K.shown(b));
    assert.ok(!hits["/ro/good"]);
  });
  check("f19. product: a request_uri at a private address is not dialled, " +
        "and is refused invalid_request_uri (STS-OAUTH-1004)", function () {
    assert.ok(refused(c.answer, "invalid_request_uri",
                      /loopback, private, link-local or reserved/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  check("j1. product: the OpenID Provider Configuration's " +
        "request_object_signing_alg_values_supported lists ES256 and never " +
        "none", function () {
    const algs = meta.request_object_signing_alg_values_supported;
    assert.ok(Array.isArray(algs) && algs.indexOf("none") < 0 &&
              algs.indexOf("ES256") >= 0, JSON.stringify(algs));
  });
  log.debug("Leaving productRows().");
}

// --------------------------------------------------------------------- g
async function encryption(other) {
  log.debug("Entering encryption().");
  log.info("=== g. encryption ===");
  const jwks = (await K.send(K.rb(D) + "/oauth2/jwks")).json;
  const encRsa = jwks.keys.filter(function (k) {
    return k.use === "enc" && k.kty === "RSA";
  })[0];
  const encEc = jwks.keys.filter(function (k) {
    return k.use === "enc" && k.kty === "EC";
  })[0];
  check("g1. /oauth2/jwks publishes an RSA and an EC use-enc key, after " +
        "the signing keys, with no private member", function () {
    assert.ok(encRsa && encEc, JSON.stringify(jwks.keys.map(function (k) {
      return k.kid + ":" + k.use;
    })));
    assert.ok(/^sts-ro-rsa-/.test(encRsa.kid) && /^sts-ro-ec-/.test(
      encEc.kid));
    assert.strictEqual(jwks.keys[0].use, "sig");
    assert.ok(!encRsa.d && !encEc.d);
  });
  const rsaJwe = function (plaintext, jwk, extra) {
    log.debug("Entering rsaJwe().");
    log.debug("Leaving rsaJwe().");
    return K.jwe(plaintext, { alg: "RSA-OAEP-256", enc: "A128CBC-HS256",
      jwk: jwk, header: Object.assign({ cty: "JWT", kid: jwk.kid },
                                      extra || {}) });
  };
  const accepted = [
    ["g2. section 6.1: signed then encrypted with RSA-OAEP-256 by this " +
     "file's own JWE code", rsaJwe(good("r91"), encRsa)],
    ["g3. ECDH-ES to the published EC key",
     K.jwe(good("r91"), { alg: "ECDH-ES", enc: "A256GCM", jwk: encEc,
                          header: { cty: "JWT", kid: encEc.kid } })],
    ["g4. A256KW keyed by the SHA-256 of the client secret (OIDC Core 10.2)",
     K.jwe(good("r91"), { alg: "A256KW", enc: "A128CBC-HS256",
                          key: secretKey(32), header: { cty: "JWT" } })],
    ["g5. A128GCMKW keyed by its leftmost 128 bits",
     K.jwe(good("r91"), { alg: "A128GCMKW", enc: "A256GCM",
                          key: secretKey(16), header: { cty: "JWT" } })],
    ["g6. dir with A256CBC-HS512 keyed by the SHA-512 of the client secret",
     K.jwe(good("r91"), { alg: "dir", enc: "A256CBC-HS512",
                          key: secretKey(64), header: { cty: "JWT" } })]
  ];
  for (const one of accepted) {
    const r = await sent(one[1]);
    check(one[0], function () {
      assert.ok(K.toSignIn(r), K.shown(r));
    });
  }
  const broken = rsaJwe(good("r91"), encRsa).split(".");
  broken[3] = Buffer.from("tampered").toString("base64url");
  const refusals = [
    ["g7. the raw secret's own octets are not the key",
     K.jwe(good("r91"), { alg: "A256KW", enc: "A128CBC-HS256",
       key: Buffer.from(SECRET).subarray(0, 32), header: { cty: "JWT" } }),
     /could not be decrypted/],
    ["g8. a JWE naming a kid that is not this realm's key is refused",
     rsaJwe(good("r91"), Object.assign({}, encRsa, { kid: "elsewhere" })),
     /encrypted to the key/],
    ["g9. a JWE under a secret that is not the client's does not open",
     K.jwe(good("r91-nokeys"), { alg: "A256KW", enc: "A128CBC-HS256",
       key: nodeCrypto.randomBytes(32), header: { cty: "JWT" } }), null,
     "r91-nokeys"],
    ["g10. section 4: what is inside must be a signed JWT",
     rsaJwe("not a jws", encRsa), /not a JWS/],
    ["g11. a tampered JWE is refused", broken.join("."),
     /could not be decrypted/],
    ["g12. a client registered for encryption is refused a plain object",
     good("r91-enc"), /must be encrypted/, "r91-enc"],
    ["g13. and refused under another algorithm than registered",
     K.jwe(good("r91-enc"), { alg: "ECDH-ES", enc: "A128CBC-HS256",
       jwk: encEc, header: { cty: "JWT", kid: encEc.kid } }), /registered/,
     "r91-enc"]
  ];
  for (const one of refusals) {
    const r = await sent(one[1], one[3]);
    check(one[0], function () {
      assert.ok(refused(r, "invalid_request_object", one[2]), K.shown(r));
    });
  }
  let r = await sent(rsaJwe(good("r91-enc"), encRsa), "r91-enc");
  check("g14. and accepted encrypted as registered", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  const otherJwks = (await K.send(K.rb(other) + "/oauth2/jwks")).json;
  const otherRsa = otherJwks.keys.filter(function (k) {
    return k.use === "enc" && k.kty === "RSA";
  })[0];
  r = await sent(rsaJwe(good("r91"), otherRsa));
  check("g15. another realm's published key opens nothing here",
        function () {
    assert.ok(otherRsa && otherRsa.kid !== encRsa.kid);
    assert.ok(refused(r, "invalid_request_object", /encrypted to the key/),
              K.shown(r));
  });
  log.debug("Leaving encryption().");
  return encRsa;
}

// --------------------------------------------------------------------- h
async function profiles(encRsa) {
  log.debug("Entering profiles().");
  log.info("=== h. profile narrowing and PAR ===");
  const api = K.rb(D) + "/admin-api/authorization-servers";
  const setMember = function (member, value) {
    log.debug("Entering setMember().");
    log.debug("Leaving setMember().");
    return K.ok(api + "/set", { profile: "r91np", member: member,
                                value: value }, "set " + member);
  };
  await K.ok(api + "/create", { id: "r91np" }, "created r91np");
  await setMember("request_parameter_supported", "false");
  let r = await authorize({ client_id: "r91", request: good("r91", {
    aud: ISS + "/r91np" }) }, "/r91np");
  check("h1. request_parameter_supported false: request_not_supported",
        function () {
    assert.ok(refused(r, "request_not_supported"), K.shown(r));
  });
  await setMember("request_uri_parameter_supported", "false");
  r = await authorize({ client_id: "r91", request_uri: L.origin +
                        "/ro/good" }, "/r91np");
  check("h2. request_uri_parameter_supported false: " +
        "request_uri_not_supported", function () {
    assert.ok(refused(r, "request_uri_not_supported"), K.shown(r));
  });
  r = await authorize({ client_id: "r91",
    request_uri: "urn:ietf:params:oauth:request_uri:not-a-real-one" },
    "/r91np");
  check("h3. RFC 9126 section 5: a pushed request's URN is not refused by " +
        "request_uri_parameter_supported false", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(!/request_uri_parameter_supported/.test(r.text), K.shown(r));
  });
  await K.ok(api + "/remove", { profile: "r91np",
    member: "request_parameter_supported" }, "removed the member");
  await setMember("request_object_signing_alg_values_supported",
                  "[\"RS256\"]");
  r = await authorize({ client_id: "r91", request: good("r91", {
    aud: ISS + "/r91np" }) }, "/r91np");
  check("h4. a profile listing only RS256 refuses ES256", function () {
    assert.ok(refused(r, "invalid_request_object", /RS256/), K.shown(r));
  });
  const rs = K.jws("RS256", { kid: "r91-rsa" },
                   claimsFor("r91", { aud: ISS + "/r91np" }), RSA);
  r = await authorize({ client_id: "r91", request: rs }, "/r91np");
  check("h5. and accepts RS256", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  await setMember("request_object_encryption_alg_values_supported",
                  "[\"ECDH-ES\"]");
  r = await authorize({ client_id: "r91", request: K.jwe(rs, {
    alg: "RSA-OAEP-256", enc: "A128CBC-HS256", jwk: encRsa,
    header: { cty: "JWT", kid: encRsa.kid } }) }, "/r91np");
  check("h6. a profile listing only ECDH-ES refuses RSA-OAEP-256",
        function () {
    assert.ok(refused(r, "invalid_request_object", /decrypts request objects/),
              K.shown(r));
  });
  r = await authorize({ client_id: "r91",
    request_uri: "urn:ietf:params:oauth:request_uri:not-a-real-one" });
  check("h7. a PAR URN is never matched against request_uris or fetched",
        function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(!/not one client/.test(r.text), K.shown(r));
  });
  const narrowed = (await K.send(K.rb(D) +
    "/.well-known/oauth-authorization-server/r91np")).json;
  check("h8. a named authorization server's document says what its " +
        "endpoint did", function () {
    assert.strictEqual(narrowed.request_uri_parameter_supported, false);
    assert.deepStrictEqual(
      narrowed.request_object_signing_alg_values_supported, ["RS256"]);
  });
  log.debug("Leaving profiles().");
}

// --------------------------------------------------------------------- i
async function roundTrip() {
  log.debug("Entering roundTrip().");
  log.info("=== i. the round trip ===");
  const loginClaims = claimsFor("r91", { prompt: "login" });
  let r = await start({ client_id: "r91", request: K.jws("ES256",
    { kid: "r91-ec", typ: "oauth-authz-req+jwt" }, loginClaims, EC) });
  const f = await flow(r);
  check("i1. prompt=login inside the object is honoured once and does not " +
        "loop back to the sign-in screen", function () {
    assert.ok(/jar_prompt_honoured=1/.test(f.back), f.back);
    assert.ok(codeAt(f.final, loginClaims.state), K.shown(f.final));
  });
  await K.unset(D, "oauth2.consentRequired");
  await K.set(D, "oauth2.consentRequired", true);
  let drawn;
  try {
    const consentClaims = claimsFor("r91-consent",
                                    { scope: "openid email" });
    r = await start({ client_id: "r91-consent", request: K.jws("ES256",
      { kid: "r91-ec" }, consentClaims, EC) });
    const b = r.b;
    const done = await K.signIn(D, b, r, PERSON, PASSWORD);
    drawn = done.consent
      ? await require("./authn_signin").consentPage(done.consent, {
          cookie: Object.keys(b.jar).map(function (k) {
            return k + "=" + b.jar[k];
          }).join("; ") })
      : { text: "" };
    drawn.where = done.consent;
  } finally {
    await K.set(D, "oauth2.consentRequired", false);
  }
  check("i2. section 11.1: the consent screen's view says the request was " +
        "a verified signed request object", function () {
    assert.ok(/\/oauth2\/consent/.test(drawn.where || ""), drawn.where);
    assert.ok(/signed request object \(ES256\)/.test(drawn.text),
              String(drawn.text).slice(0, 300));
  });
  log.debug("Leaving roundTrip().");
}

// --------------------------------------------------------------------- j
async function metadataAndRegistration() {
  log.debug("Entering metadataAndRegistration().");
  log.info("=== j. metadata, registration and the console's writes ===");
  let meta = (await K.send(K.rb(D) + "/.well-known/openid-configuration"))
    .json;
  check("j2. the OpenID Provider Configuration publishes every request " +
        "object member, none included in development", function () {
    assert.strictEqual(meta.request_parameter_supported, true);
    assert.strictEqual(meta.request_uri_parameter_supported, true);
    assert.strictEqual(meta.require_request_uri_registration, true);
    assert.strictEqual(meta.require_signed_request_object, false);
    assert.ok(meta.request_object_signing_alg_values_supported
      .indexOf("ES256") >= 0);
    assert.ok(meta.request_object_signing_alg_values_supported
      .indexOf("none") >= 0);
    assert.ok(meta.request_object_encryption_alg_values_supported
      .indexOf("RSA-OAEP-256") >= 0);
    assert.ok(meta.request_object_encryption_enc_values_supported
      .indexOf("A128CBC-HS256") >= 0);
  });
  await K.set(D, "oauth2.requireSignedRequestObject", true);
  try {
    meta = (await K.send(K.rb(D) +
      "/.well-known/oauth-authorization-server")).json;
  } finally {
    await K.unset(D, "oauth2.requireSignedRequestObject");
  }
  check("j3. with signing required, RFC 8414 says so and stops " +
        "advertising none", function () {
    assert.strictEqual(meta.require_signed_request_object, true);
    assert.ok(meta.request_object_signing_alg_values_supported
      .indexOf("none") < 0);
  });
  let r = await K.send(K.rb(D) + "/oauth2/register", { json: {
    client_name: "r91 registered " + K.STAMP, redirect_uris: [REDIRECT],
    request_uris: ["https://rp.r91.example/ro.jwt"],
    request_object_signing_alg: "PS256",
    request_object_encryption_alg: "ECDH-ES",
    request_object_encryption_enc: "A256GCM",
    require_signed_request_object: true } });
  const registered = r.json || {};
  check("j4. RFC 7591: a registration with the five members is accepted " +
        "and echoes them", function () {
    assert.ok(r.status === 201 || r.status === 200, K.shown(r));
    assert.strictEqual(registered.request_object_signing_alg, "PS256");
    assert.strictEqual(registered.request_object_encryption_enc, "A256GCM");
    assert.strictEqual(registered.require_signed_request_object, true);
    assert.deepStrictEqual(registered.request_uris,
                           ["https://rp.r91.example/ro.jwt"]);
  });
  const read = await K.send(K.rb(D) + "/oauth2/register/" +
    encodeURIComponent(registered.client_id), { headers: {
      Authorization: "Bearer " + registered.registration_access_token } });
  check("j5. RFC 7592: and read back", function () {
    assert.strictEqual(read.status, 200, K.shown(read));
    assert.strictEqual(read.json.request_object_signing_alg, "PS256");
    assert.strictEqual(read.json.request_object_encryption_alg, "ECDH-ES");
    assert.strictEqual(read.json.require_signed_request_object, true);
  });
  r = await K.send(K.rb(D) + "/oauth2/register", { json: {
    client_name: "r91 bad", redirect_uris: [REDIRECT],
    request_uris: ["ftp://rp.r91.example/ro.jwt"] } });
  check("j6. a registration with an unusable request_uri is refused",
        function () {
    assert.ok(refused(r, "invalid_client_metadata"), K.shown(r));
  });
  r = await K.send(K.rb(D) + "/oauth2/register", { json: {
    client_name: "r91 bad2", redirect_uris: [REDIRECT],
    request_object_encryption_enc: "A256GCM" } });
  check("j7. a registration with an enc and no alg is refused", function () {
    assert.ok(refused(r, "invalid_client_metadata"), K.shown(r));
  });
  const write = function (attribute, value, mode) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return K.send(K.rb(D) + "/admin-api/applications/" + (mode || "set"),
      { json: { application: "r91", attribute: attribute, value: value } });
  };
  const notOk = function (w) {
    log.debug("Entering notOk().");
    log.debug("Leaving notOk().");
    return w.status >= 400 || (w.json && w.json.ok === false);
  };
  let w = await write("oauthRequestUri", "ftp://x.example/ro", "add");
  check("j8. the registry refuses an unusable request URI, naming it",
        function () {
    assert.ok(notOk(w) && /oauthRequestUri/.test(w.text), K.shown(w));
  });
  w = await write("oauthRequireSignedRequestObject", "yes");
  check("j9. and a require flag that is not TRUE or FALSE", function () {
    assert.ok(notOk(w), K.shown(w));
  });
  w = await write("oauthRequestObjectEncryptionEnc", "A128GCM");
  check("j10. and an enc on an entry with no encryption alg", function () {
    assert.ok(notOk(w), K.shown(w));
  });
  w = await write("oauthRequestObjectSigningAlg", "ES384");
  r = await sent(good("r91"));
  check("j11. and accepts a usable signing algorithm, which the endpoint " +
        "then holds the client to", function () {
    assert.strictEqual(w.status, 200, K.shown(w));
    assert.ok(refused(r, "invalid_request_object",
                      /registered request_object/), K.shown(r));
  });
  meta = (await K.send(K.rb(D) +
    "/.well-known/oauth-authorization-server")).json;
  const cm = await K.send(K.rb(D) + "/admin-api/crypto");
  const text = JSON.stringify(cm.json || {});
  const rowOf = function (label) {
    log.debug("Entering rowOf().");
    let found = null;
    const walk = function (node) {
      log.debug("Entering walk().");
      if (found || !node || typeof node !== "object") {
        log.debug("Leaving walk().");
        return;
      }
      if (Array.isArray(node)) {
        if (node[0] === label && node.length >= 2) {
          found = node[1];
          log.debug("Leaving walk().");
          return;
        }
        node.forEach(walk);
        log.debug("Leaving walk().");
        return;
      }
      if ((node.name === label || node.label === label ||
           node.what === label) &&
          (node.algorithms || node.values || node.value)) {
        found = node.algorithms || node.values || node.value;
        log.debug("Leaving walk().");
        return;
      }
      Object.keys(node).forEach(function (k) {
        walk(node[k]);
      });
      log.debug("Leaving walk().");
    };
    walk(cm.json);
    log.debug("Leaving rowOf().");
    return found;
  };
  const signing = rowOf("Request object signature (RFC 9101)");
  const decryption = rowOf("Request object decryption (RFC 9101)");
  check("j12. /admin-api/crypto (the crypto-metadata page) lists what " +
        "the metadata advertises", function () {
    assert.strictEqual(cm.status, 200, text.slice(0, 300));
    assert.deepStrictEqual(signing,
      meta.request_object_signing_alg_values_supported.filter(
        function (alg) {
          return alg !== "none";
        }), JSON.stringify(signing));
    assert.deepStrictEqual(decryption,
      meta.request_object_encryption_alg_values_supported);
  });
  log.debug("Leaving metadataAndRegistration().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("r91", "development",
                    { "federation.outboundAllowHttp": true });
  const other = await K.realm("r91other", "development");
  ISS = (await K.send(K.rb(D) + "/.well-known/oauth-authorization-server"))
    .json.issuer;
  await K.person(D, PERSON, PASSWORD);
  L = await clientHost();
  try {
    const refs = ["/ro/good", "/ro/jwt", "/ro/plain", "/ro/missing",
                  "/ro/redirect", "/ro/big", "/ro/slow", "/ro/digest",
                  "/ro/hangup"].map(function (p) {
                    return L.origin + p;
                  });
    await K.app(D, "r91", fields("r91", { oauthRequestUri: refs }));
    await K.app(D, "r91-nokeys", fields("r91-nokeys", { oauthJwks: null }));
    await K.app(D, "r91-es256", fields("r91-es256",
      { oauthRequestObjectSigningAlg: "ES256" }));
    await K.app(D, "r91-enc", fields("r91-enc",
      { oauthRequestObjectEncryptionAlg: "RSA-OAEP-256" }));
    await K.app(D, "r91-strict", fields("r91-strict",
      { oauthRequireSignedRequestObject: "TRUE" }));
    await K.app(D, "r91-consent", fields("r91-consent"));
    await byValue();
    await algorithms();
    await unsignedAndRequired();
    await byReference();
    await productRows();
    const encRsa = await encryption(other);
    await profiles(encRsa);
    await roundTrip();
    await metadataAndRegistration();
  } finally {
    L.close();
  }
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
