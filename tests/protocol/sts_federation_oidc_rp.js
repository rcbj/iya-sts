// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_oidc_rp.js
//
// ===========================================================================
// AN INBOUND OPENID CONNECT RELATIONSHIP AS THE RELYING-PARTY PLANS HOLD IT,
// OVER THE WIRE (#930; #444 D12, phase 7).
//
// `tests/federation_oidc_rp.js` runs the stack and a small OpenID Provider
// in one child process. Here the provider is `oidc_partner_kit.js`'s, in
// THIS process, and the service dials it at OUTBOUND_TEST_HOST from a
// development realm with `federation.outboundAllowHttp` and
// `federation.outboundSkipTlsVerification` on (realm settings). Each
// relationship is written through `/admin-api/federation/*`, each browser
// leg is this job's own request, each code is read off the realm's audit
// log, and what the service dialled is the partner's own record:
//
//   1. the code flow: a good ID Token signs in and UserInfo is asked; no
//      sub (STS-FED-0195), no iat (0196), a foreign azp or two audiences
//      and no azp (0197), no nonce (0198), another nonce (0039), issued a
//      week ago or an hour ahead (0253) and another algorithm than the
//      registered one (0208) are each refused before UserInfo; UserInfo
//      for another sub (0202); check-partner reads the key set;
//   2. `code id_token`: PKCE and form_post asked; no c_hash or another
//      code's (0199) refused before the code is redeemed; the two ID Tokens
//      naming two subjects (0201);
//   3. `id_token token` by fragment: the bare GET answers the fragment page
//      and its one script under `script-src 'self'` with `frame-ancestors`
//      kept; a wrong at_hash (0200), no nonce (0198); a right one asks
//      UserInfo with the front access token; `query` is not ready;
//   4. discovery: ready with no endpoint written, the document read at the
//      sign-in, another issuer refused (0204);
//   5. the login initiation endpoint: off (0205), another iss (0206), the
//      partner's own starting the sign-in with its login_hint and a foreign
//      target dropped;
//   6. refresh tokens through `federation.partner-refresh` run by
//      `/admin-api/scheduler/run`: refreshed with UserInfo asked under the
//      new token; another iss (0211) and a refused refresh (0210) end the
//      session; the ended one is not refreshed again; fedUserinfo off;
//   7. self-registration and Request Objects by reference: the registered
//      metadata with one public key, the object verifying with it and
//      answered once (0218), no second registration, register-partner and
//      alg none; the registered client's Basic header form-encoded;
//   8. WebFinger: off (0215), the form, an address looked up as acct: with
//      nothing continuing by itself, continuing registers at the found
//      issuer, an issuer outside fedPeer (0217) — and 9b, an issuer on
//      another port of fedPeer's host (0217).
//
// NOT HERE: section 9's table (`issuerWithin()` as a function; 9b is its
// endpoint half), 6f's two overlapping runs (two `scheduler/run` calls are
// queued one after the other by the scheduler, so the overlap the
// in-process file makes cannot be made over the wire), and section 10, the
// FAPI client, which is `sts_federation_fapi_client.js`.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_federation_oidc_rp");
const P = require("./oidc_partner_kit.js");

const log = K.log;
let SP = null;
let OP = null;
let op = null;
const SECRET = "frp-secret-" + K.STAMP;

function api(path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(SP) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

async function setField(id, field, value) {
  log.debug("Entering setField(). " + id + " " + field);
  const r = await api("/federation/set", { id: id, field: field,
                                           value: String(value) });
  assert.strictEqual(r.status, 200, "setting " + field + " on " + id + ": " +
                     r.text.slice(0, 300));
  log.debug("Leaving setField().");
}

// A RELATIONSHIP, as the in-process `make()` writes it: every endpoint at
// the partner unless a field is given null.
async function make(id, fields) {
  log.debug("Entering make(). " + id);
  const base = OP.base;
  const made = await api("/federation/create", { id: id,
    role: "service-provider", protocol: "oidc",
    peer: (fields && fields.fedPeer) || base });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const all = Object.assign({ fedClientId: "frp-client",
    fedClientSecret: SECRET, fedAutocreateUsers: "TRUE",
    fedSsoUrl: base + "authorize", fedTokenUrl: base + "token",
    fedJwksUri: base + "jwks", fedUserinfoUrl: base + "userinfo",
    fedScope: "openid profile email" }, fields || {});
  delete all.fedPeer;
  for (const field of Object.keys(all)) {
    if (all[field] !== null) {
      await setField(id, field, all[field]);
    }
  }
  const on = await api("/federation/enable", { id: id });
  assert.strictEqual(on.status, 200, on.text.slice(0, 300));
  log.debug("Leaving make().");
  return id;
}

async function readiness(id) {
  log.debug("Entering readiness(). " + id);
  const r = await api("/federation?relationship=" + encodeURIComponent(id));
  log.debug("Leaving readiness().");
  return { ready: !!(r.json && r.json.ready),
           missing: (r.json && r.json.missing) || [], json: r.json || {} };
}

// The authorization request the login endpoint sends the browser with.
async function begin(id, b) {
  log.debug("Entering begin(). " + id);
  const r = await b.go(K.rb(SP) + "/federation/login/" + id);
  const at = new URL(r.location || "http://x/");
  log.debug("Leaving begin(). " + r.status);
  return { status: r.status, location: r.location, params: at.searchParams,
           text: r.text };
}

function claims(started, extra) {
  log.debug("Entering claims().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving claims().");
  return Object.assign({ iss: OP.base, sub: "frp-person",
    aud: "frp-client", iat: now, exp: now + 300,
    nonce: started.params.get("nonce") }, extra || {});
}

function without(object, name) {
  log.debug("Entering without(). " + name);
  const out = Object.assign({}, object);
  delete out[name];
  log.debug("Leaving without().");
  return out;
}

function asked() {
  log.debug("Entering asked().");
  log.debug("Leaving asked().");
  return op.calls.map(function (c) {
    return c.path;
  });
}

function acs(id) {
  log.debug("Entering acs(). " + id);
  log.debug("Leaving acs().");
  return K.rb(SP) + "/federation/acs/" + id;
}

// ------------------------------------------------------------------- 1
async function codeFlow() {
  log.debug("Entering codeFlow().");
  log.info("=== 1. the code flow ===");
  const CODE = await make("frp-code");
  const codeCase = async function (back, userinfo, code) {
    log.debug("Entering codeCase().");
    const b = K.browser();
    const started = await begin(CODE, b);
    op.calls = [];
    op.scenario = { backClaims: function () {
      return back(started);
    }, userinfo: userinfo };
    const act = function () {
      return b.go(acs(CODE) + "?state=" +
        encodeURIComponent(started.params.get("state")) + "&code=c-1");
    };
    const got = code ? await K.coded(SP, code, act)
                     : { answer: await act(), rose: 0 };
    log.debug("Leaving codeCase().");
    return { r: got.answer, rose: got.rose, asked: asked(),
             started: started };
  };
  let got = await codeCase(function (s) {
    return claims(s);
  });
  K.check("1a. a good ID Token signs in, PKCE asked, and UserInfo is asked",
          function () {
            assert.ok(got.r.status < 400, K.shown(got.r));
            assert.ok(got.asked.indexOf("/op/userinfo") >= 0,
                      JSON.stringify(got.asked));
            assert.ok(got.started.params.get("code_challenge"));
          });
  const refusals = [
    ["1b. no sub", function (s) {
      return without(claims(s), "sub");
    }, "STS-FED-0195"],
    ["1c. no iat", function (s) {
      return without(claims(s), "iat");
    }, "STS-FED-0196"],
    ["1d. an azp that is not this client", function (s) {
      return claims(s, { azp: "somebody-else" });
    }, "STS-FED-0197"],
    ["1e. two audiences and no azp", function (s) {
      return claims(s, { aud: ["frp-client", "another"] });
    }, "STS-FED-0197"],
    ["1f. no nonce", function (s) {
      return without(claims(s), "nonce");
    }, "STS-FED-0198"],
    ["1g. another nonce", function (s) {
      return claims(s, { nonce: "n-not-this-one" });
    }, "STS-FED-0039"],
    ["1h. issued a week before the sign-in began", function (s) {
      return claims(s, { iat: Math.floor(Date.now() / 1000) - 604800 });
    }, "STS-FED-0253"],
    ["1i. issued an hour in the future", function (s) {
      return claims(s, { iat: Math.floor(Date.now() / 1000) + 3600 });
    }, "STS-FED-0253"]
  ];
  for (const one of refusals) {
    got = await codeCase(one[1], null, one[2]);
    K.check(one[0] + ": refused (" + one[2] + ") and UserInfo never asked",
            function () {
              assert.strictEqual(got.r.status, 401, K.shown(got.r));
              assert.ok(got.rose >= 1, "no " + one[2] + " row");
              assert.ok(got.asked.indexOf("/op/userinfo") < 0,
                        JSON.stringify(got.asked));
            });
  }
  got = await codeCase(function (s) {
    return claims(s);
  }, { sub: "somebody-else" }, "STS-FED-0202");
  K.check("1j. UserInfo answering for another sub is refused (STS-FED-0202)",
          function () {
            assert.strictEqual(got.r.status, 401, K.shown(got.r));
            assert.ok(got.rose >= 1);
          });
  await setField(CODE, "fedIdTokenSignedResponseAlg", "ES256");
  got = await codeCase(function (s) {
    return claims(s);
  }, null, "STS-FED-0208");
  K.check("1k. an ID Token under another algorithm than " +
          "fedIdTokenSignedResponseAlg is refused (STS-FED-0208) before " +
          "UserInfo", function () {
    assert.strictEqual(got.r.status, 401, K.shown(got.r));
    assert.ok(got.rose >= 1);
    assert.ok(got.asked.indexOf("/op/userinfo") < 0);
  });
  await setField(CODE, "fedIdTokenSignedResponseAlg", "RS256");
  got = await codeCase(function (s) {
    return claims(s);
  });
  K.check("1l. and accepted under the registered one", function () {
    assert.ok(got.r.status < 400, K.shown(got.r));
  });
  op.scenario = {};
  op.calls = [];
  const checked = await api("/federation/check-partner", { id: CODE });
  K.check("1m. check-partner reads the partner's key set and reports it, " +
          "with no code in the answer", function () {
    const c = checked.json || {};
    assert.strictEqual(checked.status, 200, checked.text.slice(0, 300));
    assert.ok(c.ok && c.keys === 1 && c.readable === 1 &&
              c.discovered === false, JSON.stringify(c));
    assert.strictEqual((c.endpoints || {}).jwks_uri, OP.base + "jwks");
    assert.ok(!("errorCode" in c) && !/STS-[A-Z]+-\d{4}/.test(checked.text),
              checked.text.slice(0, 300));
    assert.ok(asked().indexOf("/op/jwks") >= 0, JSON.stringify(asked()));
  });
  log.debug("Leaving codeFlow().");
  return CODE;
}

// ------------------------------------------------------------------- 2
async function hybrid() {
  log.debug("Entering hybrid().");
  log.info("=== 2. code id_token ===");
  const HYBRID = await make("frp-hyb", { fedResponseType: "code id_token" });
  const hybridCase = async function (front, back, code) {
    log.debug("Entering hybridCase().");
    const b = K.browser();
    const started = await begin(HYBRID, b);
    op.calls = [];
    op.scenario = { backClaims: function () {
      return back(started);
    } };
    const act = function () {
      return b.go(acs(HYBRID), { form: {
        state: started.params.get("state"), code: "c-hybrid",
        id_token: OP.sign(front(started)) } });
    };
    const got = code ? await K.coded(SP, code, act)
                     : { answer: await act(), rose: 0 };
    log.debug("Leaving hybridCase().");
    return { r: got.answer, rose: got.rose, asked: asked(),
             started: started };
  };
  let got = await hybridCase(function (s) {
    return claims(s, { c_hash: P.halfHash("c-hybrid") });
  }, function (s) {
    return claims(s);
  });
  K.check("2a. code id_token: PKCE and form_post asked, a good c_hash signs " +
          "in after the code is redeemed", function () {
    assert.ok(got.r.status < 400, K.shown(got.r));
    assert.ok(got.asked.indexOf("/op/token") >= 0);
    assert.strictEqual(got.started.params.get("response_type"),
                       "code id_token");
    assert.strictEqual(got.started.params.get("response_mode"), "form_post");
    assert.strictEqual(got.started.params.get("code_challenge_method"),
                       "S256");
  });
  got = await hybridCase(function (s) {
    return claims(s);
  }, function (s) {
    return claims(s);
  }, "STS-FED-0199");
  K.check("2b. no c_hash: refused (STS-FED-0199) and the code never redeemed",
          function () {
            assert.strictEqual(got.r.status, 401, K.shown(got.r));
            assert.ok(got.rose >= 1);
            assert.ok(got.asked.indexOf("/op/token") < 0,
                      JSON.stringify(got.asked));
          });
  got = await hybridCase(function (s) {
    return claims(s, { c_hash: P.halfHash("another code") });
  }, function (s) {
    return claims(s);
  }, "STS-FED-0199");
  K.check("2c. a c_hash of another code: refused (STS-FED-0199)",
          function () {
            assert.strictEqual(got.r.status, 401, K.shown(got.r));
            assert.ok(got.rose >= 1);
          });
  got = await hybridCase(function (s) {
    return claims(s, { c_hash: P.halfHash("c-hybrid") });
  }, function (s) {
    return claims(s, { sub: "somebody-else" });
  }, "STS-FED-0201");
  K.check("2d. the token endpoint's ID Token naming another sub: refused " +
          "(STS-FED-0201)", function () {
    assert.strictEqual(got.r.status, 401, K.shown(got.r));
    assert.ok(got.rose >= 1);
  });
  log.debug("Leaving hybrid().");
}

// ------------------------------------------------------------------- 3
async function implicit(CODE) {
  log.debug("Entering implicit().");
  log.info("=== 3. id_token token, in the fragment mode ===");
  const IMPLICIT = await make("frp-imp", { fedResponseType: "id_token token",
                                           fedResponseMode: "fragment" });
  let r = await K.send(acs(IMPLICIT));
  const csp = String(r.headers.get("content-security-policy") || "");
  K.check("3a. the bare GET is answered with the fragment page and its one " +
          "script, under script-src 'self' with frame-ancestors kept",
          function () {
            assert.strictEqual(r.status, 200, K.shown(r));
            assert.ok(r.text.indexOf(
              "<script src=\"/federation/fragment.js\"></script>") > 0 ||
              /<script src="[^"]*\/federation\/fragment\.js"><\/script>/
                .test(r.text), r.text.slice(0, 400));
            assert.ok(r.text.indexOf("id=\"fed-fragment\"") > 0);
            assert.ok(/script-src 'self'/.test(csp), csp);
            assert.ok(/frame-ancestors/.test(csp), csp);
            assert.ok(/no-store/.test(String(r.headers.get("cache-control"))));
          });
  r = await K.send(K.base + "/federation/fragment.js");
  K.check("3b. the script is served", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/javascript/.test(String(r.headers.get("content-type"))));
    assert.ok(r.text.indexOf("fed-fragment") > 0);
    assert.ok(r.text.indexOf("replaceState") > 0);
  });
  r = await K.send(acs(CODE));
  K.check("3c. a relationship that did not choose the fragment mode never " +
          "answers with the page", function () {
    assert.ok(r.status !== 200 || r.text.indexOf("fragment.js") < 0,
              K.shown(r));
  });
  const implicitCase = async function (front, access, code) {
    log.debug("Entering implicitCase().");
    const b = K.browser();
    const started = await begin(IMPLICIT, b);
    op.calls = [];
    op.bearer = "";
    op.scenario = {};
    const act = function () {
      return b.go(acs(IMPLICIT), { form: {
        state: started.params.get("state"), access_token: access,
        token_type: "Bearer", id_token: OP.sign(front(started)) } });
    };
    const got = code ? await K.coded(SP, code, act)
                     : { answer: await act(), rose: 0 };
    log.debug("Leaving implicitCase().");
    return { r: got.answer, rose: got.rose, asked: asked(),
             started: started };
  };
  let got = await implicitCase(function (s) {
    return claims(s, { at_hash: P.halfHash("another token") });
  }, "at-front", "STS-FED-0200");
  K.check("3d. id_token token by fragment: no response_mode asked, and a " +
          "wrong at_hash refused (STS-FED-0200) before UserInfo",
          function () {
            assert.strictEqual(got.r.status, 401, K.shown(got.r));
            assert.ok(got.rose >= 1);
            assert.strictEqual(got.started.params.get("response_mode"), null,
                               got.started.location);
            assert.ok(got.asked.indexOf("/op/userinfo") < 0);
          });
  got = await implicitCase(function (s) {
    return without(claims(s), "nonce");
  }, "at-front", "STS-FED-0198");
  K.check("3e. a front-channel ID Token with no nonce: refused " +
          "(STS-FED-0198)", function () {
    assert.strictEqual(got.r.status, 401, K.shown(got.r));
    assert.ok(got.rose >= 1);
  });
  got = await implicitCase(function (s) {
    return claims(s, { at_hash: P.halfHash("at-front") });
  }, "at-front");
  K.check("3f. a right at_hash signs in, asking UserInfo with the front " +
          "access token", function () {
    assert.ok(got.r.status < 400, K.shown(got.r));
    assert.strictEqual(op.bearer, "Bearer at-front");
  });
  const QUERY = await make("frp-query", { fedResponseType: "id_token token",
                                          fedResponseMode: "query" });
  const ready = await readiness(QUERY);
  K.check("3g. id_token token with fedResponseMode=query is not ready",
          function () {
            assert.ok(!ready.ready, JSON.stringify(ready.missing));
            assert.ok(ready.missing.some(function (one) {
              return /fedResponseMode/.test(JSON.stringify(one));
            }), JSON.stringify(ready.missing));
          });
  log.debug("Leaving implicit().");
}

// ------------------------------------------------------------------- 4
async function discovery() {
  log.debug("Entering discovery().");
  log.info("=== 4. discovery ===");
  const DISCO = await make("frp-disco", { fedDiscovery: "TRUE",
    fedSsoUrl: null, fedTokenUrl: null, fedJwksUri: null,
    fedUserinfoUrl: null });
  const ready = await readiness(DISCO);
  K.check("4a. a discovering relationship is ready with no endpoint written",
          function () {
            assert.ok(ready.ready, JSON.stringify(ready.missing));
          });
  op.calls = [];
  op.scenario = { issuer: OP.base, base: OP.base };
  let started = await begin(DISCO, K.browser());
  K.check("4b. the sign-in reads the discovery document and goes to the " +
          "authorization endpoint it names", function () {
    assert.strictEqual(started.status, 302, started.text.slice(0, 300));
    assert.strictEqual(started.location.indexOf(
      OP.base + "disco-authorize?"), 0, started.location);
    assert.ok(asked().indexOf("/op/.well-known/openid-configuration") >= 0,
              JSON.stringify(asked()));
  });
  op.scenario = { issuer: OP.base + "someone-else/", base: OP.base };
  const got = await K.coded(SP, "STS-FED-0204", function () {
    return begin(DISCO, K.browser());
  });
  started = got.answer;
  K.check("4c. a document naming another issuer is refused (STS-FED-0204)",
          function () {
            assert.strictEqual(started.status, 502, started.text.slice(0,
                                                                     300));
            assert.ok(got.rose >= 1);
          });
  log.debug("Leaving discovery().");
}

// ------------------------------------------------------------------- 5
async function initiation(CODE) {
  log.debug("Entering initiation().");
  log.info("=== 5. the login initiation endpoint ===");
  const at = K.rb(SP) + "/federation/initiate-login/" + CODE;
  let got = await K.coded(SP, "STS-FED-0205", function () {
    return K.send(at + "?iss=" + encodeURIComponent(OP.base));
  });
  K.check("5a. off by default: refused (STS-FED-0205)", function () {
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  await setField(CODE, "fedInitiateLogin", "TRUE");
  got = await K.coded(SP, "STS-FED-0206", function () {
    return K.send(at + "?iss=" +
                  encodeURIComponent("https://another.example/"));
  });
  K.check("5b. another issuer: refused (STS-FED-0206)", function () {
    assert.strictEqual(got.answer.status, 400, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  const r = await K.send(at, { form: { iss: OP.base,
    login_hint: "frp@example.org",
    target_link_uri: "https://elsewhere.example/steal" } });
  const sent = new URL(r.location || "http://x/");
  K.check("5c. the partner's own issuer starts the sign-in, its login_hint " +
          "passed on and a foreign target dropped", function () {
    assert.strictEqual(r.status, 302, K.shown(r));
    assert.strictEqual(r.location.indexOf(OP.base + "authorize?"), 0,
                       r.location);
    assert.strictEqual(sent.searchParams.get("login_hint"),
                       "frp@example.org");
    assert.ok(r.location.indexOf("elsewhere.example") < 0, r.location);
  });
  log.debug("Leaving initiation().");
}

// ------------------------------------------------------------------- 6
async function runRefresh() {
  log.debug("Entering runRefresh().");
  const r = await K.send(K.rb(SP) + "/admin-api/scheduler/run",
    { json: { job: "federation.partner-refresh", realm: SP } });
  assert.ok((r.status === 200 || r.status === 202) && r.json && r.json.ok,
            "the partner refresh did not run: " + K.shown(r));
  // The run is queued (202): its detail is read until it has ended.
  let detail = null;
  for (let i = 0; i < 100; i += 1) {
    const d = await K.send(K.rb(SP) + "/admin-api/scheduler?run=" +
                           encodeURIComponent(r.json.runId));
    detail = (d.json && d.json.detail) || null;
    if (detail && (detail.state === "succeeded" ||
                   detail.state === "failed")) {
      break;
    }
    await K.sleep(200);
  }
  assert.ok(detail && detail.state === "succeeded",
            "the partner refresh did not succeed: " +
            JSON.stringify(detail).slice(0, 400));
  log.debug("Leaving runRefresh().");
  return detail;
}

async function refresh() {
  log.debug("Entering refresh().");
  log.info("=== 6. refresh tokens ===");
  const REFRESH = await make("frp-ref", { fedRefreshTokens: "TRUE",
                                          fedRefreshEverySeconds: "1" });
  const fresh = function () {
    log.debug("Entering fresh().");
    const now = Math.floor(Date.now() / 1000);
    log.debug("Leaving fresh().");
    return { iss: OP.base, sub: "frp-person", aud: "frp-client", iat: now,
             exp: now + 300 };
  };
  // One sign-in that holds `rt`, then (after the token is due) one run.
  const signedIn = async function (rt, how) {
    log.debug("Entering signedIn(). " + rt);
    const b = K.browser();
    const started = await begin(REFRESH, b);
    op.byToken[rt] = how;
    op.calls = [];
    op.scenario = { rt: rt, backClaims: function () {
      return claims(started);
    } };
    const r = await b.go(acs(REFRESH) + "?state=" +
      encodeURIComponent(started.params.get("state")) + "&code=c-r");
    assert.ok(r.status < 400, "signing in to hold " + rt + ": " +
              K.shown(r));
    log.debug("Leaving signedIn().");
    return b;
  };
  const refreshed = async function () {
    log.debug("Entering refreshed().");
    await K.sleep(1600);
    op.calls = [];
    await runRefresh();
    log.debug("Leaving refreshed().");
    return op.calls.filter(function (c) {
      return /\/token$/.test(c.path) && /refresh_token=/.test(c.body);
    }).map(function (c) {
      return new URLSearchParams(c.body).get("refresh_token");
    });
  };
  const bearers = function () {
    log.debug("Entering bearers().");
    log.debug("Leaving bearers().");
    return op.calls.filter(function (c) {
      return c.path === "/op/userinfo";
    }).map(function (c) {
      return c.auth;
    });
  };
  await signedIn("rt-good", { claims: fresh });
  let presented = await refreshed();
  K.check("6a. a held refresh token is refreshed when due, and UserInfo " +
          "asked with the new access token", function () {
    assert.ok(presented.indexOf("rt-good") >= 0, JSON.stringify(presented));
    assert.ok(bearers().indexOf("Bearer at-rt-good") >= 0,
              JSON.stringify(bearers()));
  });
  await signedIn("rt-iss", { claims: function () {
    return Object.assign(fresh(), { iss: "https://another.example/" });
  } });
  let got = await K.coded(SP, "STS-FED-0211", refreshed);
  K.check("6b. a refreshed ID Token naming another iss ends the session " +
          "(STS-FED-0211), and UserInfo is not asked for it", function () {
    assert.ok(got.answer.indexOf("rt-iss") >= 0, JSON.stringify(got.answer));
    assert.ok(got.rose >= 1, "no STS-FED-0211 row");
    assert.ok(bearers().indexOf("Bearer at-rt-iss") < 0,
              JSON.stringify(bearers()));
  });
  await signedIn("rt-refused", { refuse: true });
  got = await K.coded(SP, "STS-FED-0210", refreshed);
  K.check("6c. a refresh the partner refuses ends the session " +
          "(STS-FED-0210)", function () {
    assert.ok(got.answer.indexOf("rt-refused") >= 0);
    assert.ok(got.rose >= 1, "no STS-FED-0210 row");
  });
  presented = await refreshed();
  K.check("6d. an ended session's token is gone: only the live one is " +
          "refreshed again", function () {
    assert.ok(presented.indexOf("rt-good") >= 0, JSON.stringify(presented));
    assert.ok(presented.indexOf("rt-iss") < 0 &&
              presented.indexOf("rt-refused") < 0,
              JSON.stringify(presented));
  });
  await setField(REFRESH, "fedUserinfo", "off");
  let view = await readiness(REFRESH);
  K.check("6e. fedUserinfo written as off is stored FALSE", function () {
    assert.ok(/"fedUserinfo":\s*"FALSE"/.test(JSON.stringify(view.json)),
              JSON.stringify((view.json.fields || {}).fedUserinfo ||
                             view.json).slice(0, 300));
  });
  await signedIn("rt-noui", { claims: fresh });
  const signInAsked = bearers().length;
  presented = await refreshed();
  K.check("6f. with fedUserinfo off neither the sign-in nor a due refresh " +
          "asks UserInfo, and the refresh stands on the ID Token alone",
          function () {
            assert.strictEqual(signInAsked, 0);
            assert.ok(presented.indexOf("rt-noui") >= 0,
                      JSON.stringify(presented));
            assert.strictEqual(bearers().length, 0,
                               JSON.stringify(bearers()));
          });
  await setField(REFRESH, "fedUserinfo", "");
  view = await readiness(REFRESH);
  K.check("6g. fedUserinfo emptied stays empty (on, the default)",
          function () {
            assert.ok(!/"fedUserinfo":\s*"(TRUE|FALSE)"/.test(
              JSON.stringify(view.json)), JSON.stringify(view.json)
              .slice(0, 300));
          });
  log.debug("Leaving refresh().");
}

// ------------------------------------------------------------------- 7
function stateOf(text) {
  log.debug("Entering stateOf().");
  const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ""));
  log.debug("Leaving stateOf().");
  return m ? JSON.parse(m[1].replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")) : null;
}

async function registration() {
  log.debug("Entering registration().");
  log.info("=== 7. self-registration and Request Objects ===");
  const DYN = await make("frp-dyn", { fedDiscovery: "TRUE",
    fedRegister: "TRUE", fedRequestObject: "request_uri",
    fedRequestObjectSigningAlg: "RS256", fedClientId: null,
    fedClientSecret: null, fedSsoUrl: null, fedTokenUrl: null,
    fedJwksUri: null, fedUserinfoUrl: null });
  let ready = await readiness(DYN);
  K.check("7a. a registering relationship is ready with no client written",
          function () {
            assert.ok(ready.ready, JSON.stringify(ready.missing));
          });
  op.scenario = { issuer: OP.base, base: OP.base };
  const b = K.browser();
  let started = await begin(DYN, b);
  ready = await readiness(DYN);
  const fields = ready.json.fields || {};
  const md = op.registered || {};
  const key = ((md.jwks || {}).keys || [])[0] || {};
  const acsAt = ((ready.json.endpoints || {}).assertionConsumerService) || "";
  K.check("7b. the sign-in registers the relationship at the partner, keeps " +
          "the client it is given, and registers one public RSA key",
          function () {
            assert.strictEqual(started.status, 302, started.text.slice(0,
                                                                     300));
            assert.strictEqual(started.params.get("client_id"), "dyn-1");
            assert.ok(JSON.stringify(ready.json).indexOf("\"dyn-1\"") >= 0,
                      JSON.stringify(fields).slice(0, 300));
            assert.strictEqual(md.request_object_signing_alg, "RS256");
            assert.strictEqual(key.kty, "RSA");
            assert.ok(!key.d);
            assert.strictEqual((md.redirect_uris || [])[0], acsAt);
          });
  const requestUri = String(started.params.get("request_uri") || "");
  let r = await K.send(requestUri);
  const parts = r.text.split(".");
  const objectClaims = (P.jwtParts(r.text) || {}).claims || {};
  const verifies = parts.length === 3 && nodeCrypto.verify("sha256",
    Buffer.from(parts[0] + "." + parts[1]),
    nodeCrypto.createPublicKey({ key: key, format: "jwk" }),
    Buffer.from(parts[2], "base64url"));
  K.check("7c. the Request Object at request_uri carries the request, " +
          "verifies with the registered key, iss the client and aud the " +
          "partner", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(/oauth-authz-req\+jwt/.test(
      String(r.headers.get("content-type"))));
    assert.ok(verifies);
    assert.strictEqual(objectClaims.iss, "dyn-1");
    assert.strictEqual(objectClaims.aud, OP.base);
    assert.strictEqual(objectClaims.client_id, "dyn-1");
    assert.strictEqual(objectClaims.state, started.params.get("state"));
    assert.strictEqual(objectClaims.nonce, started.params.get("nonce"));
  });
  const again = await K.coded(SP, "STS-FED-0218", function () {
    return K.send(requestUri);
  });
  K.check("7d. a Request Object is answered once (STS-FED-0218)",
          function () {
            assert.strictEqual(again.answer.status, 404);
            assert.ok(again.rose >= 1);
          });
  // 7g first, on the client just registered: a code sign-in through it, and
  // the Basic header its token request carried (RFC 6749 section 2.3.1).
  op.calls = [];
  op.scenario = { issuer: OP.base, base: OP.base, backClaims: function () {
    return claims(started, { aud: "dyn-1" });
  } };
  r = await b.go(acs(DYN) + "?state=" +
    encodeURIComponent(started.params.get("state")) + "&code=c-dyn");
  const tokenCall = op.calls.filter(function (c) {
    return /\/token$/.test(c.path);
  })[0] || { auth: "" };
  const joined = Buffer.from(tokenCall.auth.replace(/^Basic /, ""), "base64")
    .toString("utf8");
  const colon = joined.indexOf(":");
  const formDecoded = function (v) {
    log.debug("Entering formDecoded().");
    log.debug("Leaving formDecoded().");
    return decodeURIComponent(String(v).replace(/\+/g, " "));
  };
  K.check("7g. the registered client's Basic header form-urlencodes the id " +
          "and the secret, so a secret holding % + : < and a space decodes " +
          "to itself", function () {
    assert.ok(r.status < 400, K.shown(r));
    assert.ok(colon > 0, tokenCall.auth);
    assert.strictEqual(formDecoded(joined.slice(0, colon)), "dyn-1");
    assert.strictEqual(formDecoded(joined.slice(colon + 1)),
                       "dyn %+:<é/secret-1");
    assert.ok(joined.slice(colon + 1).indexOf(":") < 0, joined);
  });
  started = await begin(DYN, K.browser());
  K.check("7e. a relationship already registered with this issuer does not " +
          "register again", function () {
    assert.strictEqual(op.registrations, 1);
  });
  await setField(DYN, "fedRequestObjectSigningAlg", "none");
  const rereg = await api("/federation/register-partner", { id: DYN });
  started = await begin(DYN, K.browser());
  r = await K.send(String(started.params.get("request_uri") || ""));
  K.check("7f. register-partner registers again; an unsigned Request " +
          "Object registers no key and is sent alg none", function () {
    assert.strictEqual(rereg.status, 200, rereg.text.slice(0, 300));
    assert.strictEqual(op.registrations, 2);
    assert.strictEqual(op.registered.request_object_signing_alg, "none");
    assert.ok(!op.registered.jwks);
    assert.ok(/\.$/.test(r.text), r.text.slice(0, 80));
    assert.strictEqual(JSON.parse(Buffer.from(r.text.split(".")[0],
      "base64url").toString()).alg, "none");
  });
  log.debug("Leaving registration().");
  return DYN;
}

// ------------------------------------------------------------------- 8
async function webfinger(DYN) {
  log.debug("Entering webfinger().");
  log.info("=== 8. WebFinger from a typed identifier ===");
  const at = K.rb(SP) + "/federation/webfinger/" + DYN;
  let got = await K.coded(SP, "STS-FED-0215", function () {
    return K.send(at + "?resource=" +
                  encodeURIComponent("acct:a@" + OP.tlsHost));
  });
  K.check("8a. off by default: refused (STS-FED-0215)", function () {
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  await setField(DYN, "fedWebFinger", "TRUE");
  let r = await K.send(at);
  let view = (stateOf(r.text) || {}).view || {};
  K.check("8b. the page asks for an identifier", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(view.kind, "webfinger");
    assert.strictEqual(view.step, "ask");
  });
  op.scenario = { issuer: OP.base + "tenant7", base: OP.base,
                  webfingerIssuer: OP.base + "tenant7" };
  op.calls = [];
  const b = K.browser();
  r = await b.go(at + "?resource=" + encodeURIComponent("a@" + OP.tlsHost));
  view = (stateOf(r.text) || {}).view || {};
  K.check("8c. an address is looked up as acct:, the issuer found and its " +
          "discovery document read, and nothing goes on by itself",
          function () {
            assert.strictEqual(r.status, 200, K.shown(r));
            assert.strictEqual(view.step, "found", JSON.stringify(view));
            assert.strictEqual(view.issuer, OP.base + "tenant7");
            assert.strictEqual(op.webfinger, "acct:a@" + OP.tlsHost);
            assert.ok(asked().indexOf(
              "/op/tenant7/.well-known/openid-configuration") >= 0,
              JSON.stringify(asked()));
            assert.ok(!asked().some(function (p) {
              return /authorize|register/.test(p);
            }), JSON.stringify(asked()));
          });
  const before = op.registrations;
  // Root-relative: the page's runtime puts the realm's prefix on
  // (`WebPage.realmLinks()`), as this does.
  r = await b.go(K.rb(SP) + String(view.continueHref || ""));
  const after = await readiness(DYN);
  K.check("8d. continuing signs in at that issuer, registering there first",
          function () {
            assert.strictEqual(r.status, 302, K.shown(r));
            assert.strictEqual(r.location.indexOf(OP.base +
                                                  "disco-authorize"), 0);
            assert.strictEqual(op.registrations, before + 1);
            assert.ok(JSON.stringify(after.json).indexOf(OP.base +
                                                         "tenant7") >= 0);
          });
  op.scenario.webfingerIssuer = "https://elsewhere.example/";
  got = await K.coded(SP, "STS-FED-0217", function () {
    return K.send(at + "?resource=" +
                  encodeURIComponent("https://" + OP.tlsHost + "/x"));
  });
  K.check("8e. an issuer outside fedPeer is refused (STS-FED-0217)",
          function () {
            assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
            assert.ok(got.rose >= 1);
          });
  // 9b: fedPeer the bare host and an issuer on another port of it, which a
  // string prefix admits — only the parsed bound can refuse it.
  const BOUND = await make("frp-bound", { fedDiscovery: "TRUE",
    fedWebFinger: "TRUE", fedPeer: "http://" + K.HOST, fedSsoUrl: null,
    fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
  op.scenario = { webfingerIssuer: OP.base, issuer: OP.base, base: OP.base };
  got = await K.coded(SP, "STS-FED-0217", function () {
    return K.send(K.rb(SP) + "/federation/webfinger/" + BOUND +
                  "?resource=" + encodeURIComponent("a@" + OP.tlsHost));
  });
  K.check("9b. an issuer on another port of fedPeer's host is refused " +
          "(STS-FED-0217)", function () {
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  log.debug("Leaving webfinger().");
}

async function test() {
  log.debug("Entering test().");
  OP = await P.partner(K, { sub: "frp-person" });
  op = OP.op;
  try {
    SP = await K.realm("frp", "development", {
      "federation.outboundAllowHttp": "true",
      "federation.outboundSkipTlsVerification": "true" });
    const CODE = await codeFlow();
    await hybrid();
    await implicit(CODE);
    await discovery();
    await initiation(CODE);
    await refresh();
    const DYN = await registration();
    await webfinger(DYN);
  } finally {
    OP.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 50);
