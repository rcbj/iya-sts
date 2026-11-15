// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_implicit_token_responses.js
//
// ---------------------------------------------------------------------------
// RFC 9700 SECTION 2.1.2 WAIVED BY AN ADMINISTRATOR, AND THE IMPLICIT GRANT
// BESIDE id_token (#1295, #1296), OVER THE WIRE.
//
// D12 (#444): carries `tests/implicit_token_responses.js` to a running
// service, at `/oauth2/register`, `/oauth2/authorize`, both discovery
// documents, `/oauth2/rfc9700` and `/admin-api/applications`, in throwaway
// realms of this job's own (one per combination of mode and switch); every
// code is read off `/admin-api/audit`:
//
//   A. THE DEFECT FIXED, the waiver OFF (RFC 9700 mode and product): a
//      registration of `id_token` or `code id_token` with
//      `grant_types: ["implicit"]` is accepted (RFC 7591 section 2.1).
//   B. THE WAIVER (`oauth2.allowImplicitTokenResponses`): off, each of the
//      four token response types is refused at the authorization endpoint
//      (unsupported_response_type, STS-OAUTH-0163) and at registration
//      beside the implicit grant (STS-OAUTH-0133), and neither discovery document advertises them;
//      on, both advertise every response type and `implicit` and still not
//      `password`, an application listing the type
//      (`oauthAllowedTokenResponseTypes`) may use it, one that does not is
//      refused unauthorized_client (STS-OAUTH-0998), a public client with no
//      PKCE is still refused (STS-OAUTH-0127), and a registration of a
//      token type is refused STS-OAUTH-0999 while the dynamic list is empty.
//   C. OAUTH 2.1 MODE AND FAPI still refuse with the waiver on (0163, and a
//      registration), and their discovery advertises no token type.
//   D. THE REPORT: `/oauth2/rfc9700`'s `no-implicit` row reads `waived`,
//      naming the setting, `waived` lists it; with the waiver off nothing is
//      waived.
//   G. DYNAMIC REGISTRATION (`oauth2.dynamicRegistrationTokenResponseTypes`):
//      a listed type registers, and the registered client may use it; an
//      unlisted one is STS-OAUTH-0999.
//   H. THE ADMINISTRATOR'S WRITE: a create listing a token type in a realm
//      that does not allow them is refused STS-REG-0364, allowed where the
//      waiver is on, and a value outside the four is refused STS-REG-0203.
//
// NOT carried, and why: I (every switch on in OAuth 2.1 and FAPI) is C's
// answer once more; J (the owner's write through the access-control
// policy) needs an owner's console token and is held by p34's
// `sts_owners`; K's drawn pages are the console bundle's (class (d)), and
// `mode.report()`'s BCP row is read here only through `/oauth2/rfc9700`;
// H's canonical storage order and the never-refused remove are a write
// path's internals.
//
// WHERE THE WIRE DIFFERS FROM THE IN-PROCESS CLAIM: a registration reaches
// the RFC 9700 checks only once RFC 7591 section 2.1's consistency check
// (STS-REG-0183) has passed. So `implicit` beside `code` alone, or with no
// response type, is STS-REG-0183 rather than STS-OAUTH-0133, and a token
// response type WITHOUT the implicit grant is STS-REG-0183 rather than
// STS-OAUTH-0134 — 0134 is unreachable over the wire; with the implicit
// grant a token type is STS-OAUTH-0133. At the authorization endpoint a
// token type the realm does not advertise is refused by the profile check
// first, STS-OAUTH-0163 (an HTTP 400 page), so STS-OAUTH-0126 is not
// reached over the wire either.
//
// OWNED HERE (local: true): realm settings and applications of this
// service's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_implicit_token_responses");
const log = K.log;

const KEY = "oauth2.allowImplicitTokenResponses";
const DYN = "oauth2.dynamicRegistrationTokenResponseTypes";
const REDIRECT = "https://rp.itr.example/cb";
const TOKEN_TYPES = ["token", "code token", "id_token token",
                     "code id_token token"];
const ALL_TYPES = ["code", "id_token", "code id_token"].concat(TOKEN_TYPES);
const FLOOR = 37;
const R = {};

function check(what, fn) {
  K.check(what, fn);
}

function slug(type) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return type.replace(/ /g, "-");
}

// The grant_types RFC 7591 section 2.1 asks of `type`, so that a
// registration reaches the RFC 9700 checks rather than the consistency one.
function grantsFor(type) {
  log.debug("Entering grantsFor().");
  log.debug("Leaving grantsFor().");
  return /code/.test(type) ? ["authorization_code", "implicit"]
    : ["implicit"];
}

function register(realm, grants, types) {
  log.debug("Entering register().");
  const meta = { redirect_uris: [REDIRECT],
                 token_endpoint_auth_method: "client_secret_basic" };
  if (grants) {
    meta.grant_types = grants;
  }
  if (types) {
    meta.response_types = types;
  }
  log.debug("Leaving register().");
  return K.send(K.rb(realm) + "/oauth2/register", { json: meta });
}

async function registerCoded(realm, code, grants, types) {
  log.debug("Entering registerCoded(). " + code);
  const seen = await K.coded(realm, code, function () {
    return register(realm, grants, types);
  });
  log.debug("Leaving registerCoded().");
  return seen;
}

async function publicApp(realm, id, types) {
  log.debug("Entering publicApp(). " + id);
  const fields = { oauthClientId: [id], oauthRedirectUri: [REDIRECT],
                   oauthTokenEndpointAuthMethod: "none" };
  if (types) {
    fields.oauthAllowedTokenResponseTypes = types;
    // Product holds a client to what it DECLARES (#1453, #1479), so the
    // flows are declared too; the attribute under test is the one above.
    fields.oauthResponseType = ["code"].concat(TOKEN_TYPES);
    fields.oauthGrantType = ["authorization_code", "implicit"];
  }
  const r = await K.send(K.rb(realm) + "/admin-api/applications/create",
    { json: { identifier: id, name: id, protocols: ["oauth2", "oidc"],
              fields: fields } });
  log.debug("Leaving publicApp(). " + r.status);
  return r;
}

function authorize(realm, type, clientId, noPkce) {
  log.debug("Entering authorize(). " + type);
  const q = { client_id: clientId, response_type: type,
              redirect_uri: REDIRECT, scope: "openid", nonce: "n-1",
              state: "s-1" };
  if (!noPkce) {
    const p = K.pkce();
    q.code_challenge = p.challenge;
    q.code_challenge_method = "S256";
  }
  log.debug("Leaving authorize().");
  return K.send(K.rb(realm) + "/oauth2/authorize?" + new URLSearchParams(q));
}

// The error an authorization request was answered with, at the client or on
// a page; "" when it went on to the sign-in screen.
function errorOf(r) {
  log.debug("Entering errorOf().");
  if (K.toSignIn(r)) {
    log.debug("Leaving errorOf(). accepted");
    return "";
  }
  const p = K.answerAt(r, REDIRECT);
  let out = p ? (p.get("error") || "") : "";
  if (!out) {
    const m = /(unsupported_response_type|unauthorized_client|invalid_request)/
      .exec(r.text);
    out = m ? m[1] : "unknown " + K.shown(r);
  }
  log.debug("Leaving errorOf(). " + out);
  return out;
}

async function authorizeCoded(realm, code, type, clientId, noPkce) {
  log.debug("Entering authorizeCoded(). " + code);
  const seen = await K.coded(realm, code, function () {
    return authorize(realm, type, clientId, noPkce);
  });
  log.debug("Leaving authorizeCoded().");
  return { error: errorOf(seen.answer), rose: seen.rose, r: seen.answer };
}

async function discovery(realm) {
  log.debug("Entering discovery().");
  const oidc = (await K.send(K.rb(realm) +
                             "/.well-known/openid-configuration")).json;
  const as = (await K.send(K.rb(realm) +
                           "/.well-known/oauth-authorization-server")).json;
  log.debug("Leaving discovery().");
  return [oidc, as];
}

function advertisesToken(meta) {
  log.debug("Entering advertisesToken().");
  log.debug("Leaving advertisesToken().");
  return (meta.response_types_supported || []).some(function (one) {
    return /(^| )token( |$)/.test(one);
  });
}

async function defectFixed() {
  log.debug("Entering defectFixed().");
  log.info("=== A. implicit beside id_token, the waiver off ===");
  for (const name of ["BCP", "PROD"]) {
    const a1 = await register(R[name], ["implicit"], ["id_token"]);
    const a2 = await register(R[name], ["authorization_code", "implicit"],
                              ["code id_token"]);
    check("A1. " + name + ": implicit beside id_token, and beside code " +
          "id_token, registers", function () {
      assert.strictEqual(a1.status, 201, K.shown(a1));
      assert.strictEqual(a2.status, 201, K.shown(a2));
    });
    const a4 = await registerCoded(R[name], "STS-REG-0183",
      ["authorization_code", "implicit"], ["code"]);
    check("A2. " + name + ": implicit beside code alone is refused — by " +
          "RFC 7591's consistency check, first (STS-REG-0183)", function () {
      assert.strictEqual(a4.answer.status, 400, K.shown(a4.answer));
      assert.strictEqual(a4.rose, 1, "STS-REG-0183 rows: " + a4.rose);
    });
    const a5 = await registerCoded(R[name], "STS-REG-0183", ["implicit"],
                                   null);
    check("A3. " + name + ": and implicit with no response type (code) the " +
          "same way (STS-REG-0183)", function () {
      assert.strictEqual(a5.answer.status, 400, K.shown(a5.answer));
      assert.strictEqual(a5.rose, 1, "STS-REG-0183 rows: " + a5.rose);
    });
  }
  log.debug("Leaving defectFixed().");
}

async function waiverOff() {
  log.debug("Entering waiverOff().");
  log.info("=== B. the waiver off ===");
  for (const name of ["BCP", "PROD"]) {
    const realm = R[name];
    // Listing a token type is refused where the realm does not allow them
    // (H), so these clients list none.
    for (const type of TOKEN_TYPES) {
      const made = await publicApp(realm, "itr-off-" + slug(type), null);
      assert.ok(made.status === 200 && made.json.ok !== false,
                K.shown(made));
    }
    const rows = [];
    for (const type of TOKEN_TYPES) {
      rows.push(await authorizeCoded(realm, "STS-OAUTH-0163", type,
                                     "itr-off-" + slug(type)));
    }
    check("B1. " + name + ": each token response type is refused " +
          "unsupported_response_type at the authorization endpoint, as a " +
          "type this realm does not advertise (STS-OAUTH-0163)", function () {
      rows.forEach(function (one, i) {
        assert.strictEqual(one.error, "unsupported_response_type",
                           TOKEN_TYPES[i] + ": " + one.error);
        assert.strictEqual(one.rose, 1, TOKEN_TYPES[i] + " rows " +
                           one.rose);
      });
    });
    const reg = [];
    for (const type of TOKEN_TYPES) {
      reg.push(await registerCoded(realm, "STS-OAUTH-0133", grantsFor(type),
                                   [type]));
    }
    check("B2. " + name + ": registering a token response type with the " +
          "implicit grant is refused (STS-OAUTH-0133)", function () {
      reg.forEach(function (one, i) {
        assert.strictEqual(one.answer.status, 400, TOKEN_TYPES[i]);
        assert.strictEqual(one.rose, 1, TOKEN_TYPES[i] + " rows " +
                           one.rose);
      });
    });
    const metas = await discovery(realm);
    check("B3. " + name + ": neither discovery document advertises a " +
          "token response type, and both keep implicit beside id_token",
          function () {
      metas.forEach(function (m) {
        assert.ok(!advertisesToken(m), JSON.stringify(
          m.response_types_supported));
        assert.ok((m.grant_types_supported || []).indexOf("implicit") >= 0,
                  JSON.stringify(m.grant_types_supported));
      });
    });
  }
  const rep = (await K.send(K.rb(R.BCP) + "/oauth2/rfc9700")).json;
  const row = (rep.requirements || []).find(function (one) {
    return one.id === "no-implicit";
  }) || {};
  check("D1. with the waiver off nothing is waived and no-implicit is " +
        "enforced", function () {
    assert.deepStrictEqual(rep.waived, []);
    assert.strictEqual(row.enforced, "yes");
  });
  log.debug("Leaving waiverOff().");
}

async function waiverOn() {
  log.debug("Entering waiverOn().");
  log.info("=== B. the waiver on ===");
  for (const name of ["SWITCH", "PRODON"]) {
    const realm = R[name];
    const metas = await discovery(realm);
    check("B4. " + name + ": discovery advertises every response type and " +
          "implicit, and still not password", function () {
      metas.forEach(function (m) {
        ALL_TYPES.forEach(function (t) {
          assert.ok(m.response_types_supported.indexOf(t) >= 0, t + " in " +
                    JSON.stringify(m.response_types_supported));
        });
        assert.ok(m.grant_types_supported.indexOf("implicit") >= 0);
        assert.ok(m.grant_types_supported.indexOf("password") < 0);
      });
    });
    for (const type of TOKEN_TYPES) {
      const made = await publicApp(realm, "itr-on-" + slug(type), [type]);
      assert.ok(made.status === 200 && made.json.ok !== false,
                K.shown(made));
      await publicApp(realm, "itr-other-" + slug(type),
                      TOKEN_TYPES.filter(function (one) {
                        return one !== type;
                      }));
    }
    const on = [];
    const other = [];
    for (const type of TOKEN_TYPES) {
      on.push(errorOf(await authorize(realm, type, "itr-on-" + slug(type))));
      other.push(await authorizeCoded(realm, "STS-OAUTH-0998", type,
                                      "itr-other-" + slug(type)));
    }
    check("B5. " + name + ": an application listing the type may use it",
          function () {
      on.forEach(function (one, i) {
        assert.strictEqual(one, "", TOKEN_TYPES[i] + ": " + one);
      });
    });
    check("B6. " + name + ": one listing every OTHER type is refused " +
          "unauthorized_client (STS-OAUTH-0998)", function () {
      other.forEach(function (one, i) {
        assert.strictEqual(one.error, "unauthorized_client",
                           TOKEN_TYPES[i] + ": " + one.error);
        assert.strictEqual(one.rose, 1, TOKEN_TYPES[i] + " rows " +
                           one.rose);
      });
    });
    const noPkce = await authorizeCoded(realm, "STS-OAUTH-0127", "code",
                                        "itr-on-token", true);
    check("B7. " + name + ": every other requirement holds — a public " +
          "client with no PKCE is still refused (STS-OAUTH-0127)",
          function () {
      assert.ok(noPkce.error, K.shown(noPkce.r));
      assert.strictEqual(noPkce.rose, 1, "rows " + noPkce.rose);
    });
    const reg = await registerCoded(realm, "STS-OAUTH-0999", ["implicit"],
                                    ["id_token token"]);
    check("B8. " + name + ": a registration of a token type is past 0133 " +
          "and refused STS-OAUTH-0999 while the dynamic list is empty",
          function () {
      assert.strictEqual(reg.answer.status, 400, K.shown(reg.answer));
      assert.strictEqual(reg.rose, 1, "rows " + reg.rose);
    });
  }
  const rep = (await K.send(K.rb(R.SWITCH) + "/oauth2/rfc9700")).json;
  const row = (rep.requirements || []).find(function (one) {
    return one.id === "no-implicit";
  }) || {};
  check("D2. /oauth2/rfc9700's no-implicit row reads waived, naming the " +
        "setting", function () {
    assert.strictEqual(row.enforced, "waived", JSON.stringify(row));
    assert.ok(JSON.stringify(row).indexOf(KEY) >= 0, JSON.stringify(row));
  });
  check("D3. and waived lists it", function () {
    assert.ok(JSON.stringify(rep.waived).indexOf(KEY) >= 0,
              JSON.stringify(rep.waived));
  });
  log.debug("Leaving waiverOn().");
}

async function stillRefused() {
  log.debug("Entering stillRefused().");
  log.info("=== C. OAuth 2.1 and FAPI still refuse ===");
  for (const name of ["V21", "FAPI"]) {
    const realm = R[name];
    // A create listing a token type is refused here too (STS-REG-0364), so
    // the client lists none.
    const made = await publicApp(realm, "itr-c-token", null);
    assert.ok(made.status === 200 && made.json.ok !== false, K.shown(made));
    const a = await authorizeCoded(realm, "STS-OAUTH-0163", "token",
                                   "itr-c-token");
    const reg = await register(realm, ["implicit"], ["id_token token"]);
    const metas = await discovery(realm);
    check("C1. " + name + ": with the waiver on a token type is still " +
          "refused as unadvertised (STS-OAUTH-0163), and so is its " +
          "registration",
          function () {
      assert.ok(a.error, K.shown(a.r));
      assert.strictEqual(a.rose, 1, "rows " + a.rose + " " + a.error);
      assert.strictEqual(reg.status, 400, K.shown(reg));
    });
    check("C2. " + name + ": and its discovery advertises no token type",
          function () {
      metas.forEach(function (m) {
        assert.ok(!advertisesToken(m), JSON.stringify(
          m.response_types_supported));
      });
    });
  }
  log.debug("Leaving stillRefused().");
}

async function dynamic() {
  log.debug("Entering dynamic().");
  log.info("=== G. the dynamic-registration list ===");
  const realm = R.BCPDYN;
  const ok = await register(realm, ["implicit"], ["id_token token"]);
  const no = await registerCoded(realm, "STS-OAUTH-0999", ["implicit"],
                                 ["token"]);
  check("G1. a listed type registers", function () {
    assert.strictEqual(ok.status, 201, K.shown(ok));
  });
  check("G2. an unlisted one is STS-OAUTH-0999", function () {
    assert.strictEqual(no.answer.status, 400, K.shown(no.answer));
    assert.strictEqual(no.rose, 1, "rows " + no.rose);
  });
  const app = await K.send(K.rb(realm) + "/admin-api/applications?" +
    new URLSearchParams({ application: ok.json.client_id }));
  check("G3. the registration records it on the attribute", function () {
    const f = (app.json && app.json.fields) || {};
    assert.ok([].concat(f.oauthAllowedTokenResponseTypes || [])
      .indexOf("id_token token") >= 0, JSON.stringify(f).slice(0, 400));
  });
  const used = errorOf(await authorize(realm, "id_token token",
                                       ok.json.client_id));
  check("G4. and the registered client may then use it", function () {
    assert.strictEqual(used, "", used);
  });
  log.debug("Leaving dynamic().");
}

async function administrator() {
  log.debug("Entering administrator().");
  log.info("=== H. the administrator's write ===");
  const refused = await K.coded(R.BCP, "STS-REG-0364", function () {
    return publicApp(R.BCP, "itr-h-refused", ["token"]);
  });
  check("H1. a create listing a token type where the realm does not allow " +
        "them is refused (STS-REG-0364), naming the attribute and the " +
        "setting", function () {
    const r = refused.answer;
    assert.ok(r.status >= 400 || r.json.ok === false, K.shown(r));
    assert.ok(r.text.indexOf("oauthAllowedTokenResponseTypes") >= 0, r.text);
    assert.ok(r.text.indexOf(KEY) >= 0, r.text);
    assert.strictEqual(refused.rose, 1, "rows " + refused.rose);
  });
  const allowed = await publicApp(R.SWITCH, "itr-h-allowed", ["token"]);
  check("H2. and allowed where the waiver is on", function () {
    assert.ok(allowed.status === 200 && allowed.json.ok !== false,
              K.shown(allowed));
  });
  const wrong = await K.coded(R.SWITCH, "STS-REG-0203", function () {
    return publicApp(R.SWITCH, "itr-h-wrong", ["code"]);
  });
  check("H3. a value outside the four is refused (STS-REG-0203)",
        function () {
    assert.ok(wrong.answer.status >= 400 || wrong.answer.json.ok === false,
              K.shown(wrong.answer));
    assert.strictEqual(wrong.rose, 1, "rows " + wrong.rose);
  });
  check("no refusal names a code", function () {
    [refused.answer, wrong.answer].forEach(function (r) {
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), r.text);
    });
  });
  log.debug("Leaving administrator().");
}

async function test() {
  log.debug("Entering test().");
  const specs = {
    BCP: ["development", { "oauth2.rfc9700": true }],
    PROD: ["product", {}],
    SWITCH: ["development", { "oauth2.rfc9700": true, [KEY]: true }],
    PRODON: ["product", { [KEY]: true }],
    V21: ["development", { "oauth2.oauth21": true, [KEY]: true }],
    FAPI: ["development", { "oauth2.fapi": "1-baseline", [KEY]: true }],
    BCPDYN: ["development", { "oauth2.rfc9700": true, [KEY]: true,
                              [DYN]: "id_token token" }]
  };
  for (const name of Object.keys(specs)) {
    R[name] = await K.realm("itr" + name.toLowerCase(), specs[name][0],
                            Object.assign({ "oauth2.openRegistration": true },
                                          specs[name][1]));
  }
  await defectFixed();
  await waiverOff();
  await waiverOn();
  await stillRefused();
  await dynamic();
  await administrator();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
