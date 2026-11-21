// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_scope_rules_policy.js
//
// ===========================================================================
// WHICH SCOPES A CLIENT MAY BE ISSUED, AND THAT THE REALM'S ISSUANCE POLICY
// IS WHAT DECIDES IT (#110, #305, #1141; D12, #444).
//
// Carries `tests/scope_policy.js` and `tests/scope_rules_policy.js` onto a
// running service. `sts_scope_policy.js` holds the resource servers'
// re-check; this job holds the issuance decision itself, at the token and
// authorization endpoints, in a development and a product realm side by
// side, every code read off `/admin-api/audit`:
//
//   A. THIS SERVICE'S OWN PROTECTED SCOPES in both modes: admin:write,
//      report:admin, scim:read (to a client declaring only scim:write),
//      ssf.read and ssf.manage refused `invalid_scope` (STS-OAUTH-0577);
//      scim:write issued to the client declaring it; ssf:read and ssf:write
//      ordinary scopes; the SCIM scope protected by its SETTING's name
//      (`scim.scopeWrite`) and a renamed `ssf.authScopeRead` adding a name
//      and unprotecting neither fixed one; the seeded clients holding the
//      delegated permission grants they use, and a new realm seeded with
//      the reports client and API and no debugger;
//   B. EVERY OTHER SCOPE: issued freely in development; in product held to
//      `oauthAllowedScope` or, with none, the default set (STS-OAUTH-0578,
//      the description naming the attribute);
//   C. A REFRESH CARRYING A SCOPE THE CLIENT MAY NO LONGER HAVE is issued
//      without it, `scope` says so, the access token does not carry it, and
//      one audit row records it (STS-OAUTH-0579);
//   D. DELEGATED PERMISSIONS: honoured in development with the setting
//      off, refused with it on (STS-OAUTH-0155) and in product whatever it
//      says;
//   E. THE POLICY DECIDES: an operator's `role-issuance` document (the
//      built-in, from its template, through `/admin-api/xacml`) without
//      `permission-not-granted` lets the product permission through, and
//      without `consent-outstanding` asks no consent of a realm requiring
//      it; deleted, the built-in decides again;
//   F. RFC 9396: a detail of a type the client did not register is refused
//      (STS-OAUTH-0454);
//   G. A TOKEN EXCHANGE asking an ordinary scope its subject_token lacks is
//      kept in development and refused in product (STS-OAUTH-0621);
//   H. FOR THIS SERVICE'S APIS A DELEGATED PERMISSION GRANT IS THE
//      DECLARATION: admin:read listed in oauthAllowedScope is still refused
//      0577; held by a delegated permission grant on the management API's
//      object it is not.
//
// NOT CARRIED (class (d)): `refusal()`/`declares()`/`narrow()` as library
// calls with no client (`ssf.manage` for a request naming none), the gate
// with its decider removed, the per-scope `exchange` verdicts asked of the
// PDP by hand (G1-G3: only the scope a subject_token lacks has an answer a
// client sees), `declaredScopes()`, `delegatedPermissionApiOf()` and the
// retired debugger permission (nothing issues or reads it). OWED: an
// operator's own Deny rule with its own code (scope_rules_policy A3) needs
// the policy editor's add-rule walk, `sts_xacml_editor.js`'s ground.
//
// OWNED HERE (local: true): the issuance policy is this repository's own.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_scope_rules_policy");
const log = K.log;

const SECRET = "srp-secret-" + K.rand(10);
const PASSWORD = "Srp-" + K.rand(6) + "-password!";
const REDIRECT = "https://srp-client.example/cb";

function clients(id, permissionBase) {
  log.debug("Entering clients().");
  const common = { oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthRedirectUri: [REDIRECT],
    oauthGrantType: ["client_credentials", "password", "refresh_token",
                     "authorization_code",
                     "urn:ietf:params:oauth:grant-type:token-exchange"] };
  log.debug("Leaving clients().");
  return Promise.all([
    K.app(id, "sp-declared", Object.assign({ oauthClientId: ["sp-declared"],
      oauthAllowedScope: ["openid", "api:read", "scim:write", "email",
                          "offline_access"] }, common)),
    K.app(id, "sp-bare", Object.assign({ oauthClientId: ["sp-bare"] },
                                       common)),
    K.app(id, "sp-api", { oauthClientId: ["sp-api"],
      oauthPermissionBaseUri: permissionBase, oauthPermission: ["write"] }),
    K.app(id, "sp-listed", Object.assign({ oauthClientId: ["sp-listed"],
      oauthAllowedScope: ["openid", "admin:read", "report:use",
                          "account:manage"] }, common)),
    K.app(id, "sp-delegated", Object.assign({
      oauthClientId: ["sp-delegated"], oauthAllowedScope: ["openid"],
      oauthDelegatedPermission: ["urn:sts:admin-api:admin:read"] },
      common)),
    K.app(id, "sp-rar", Object.assign({ oauthClientId: ["sp-rar"],
      oauthAuthorizationDetailsTypes: ["payment_initiation"] }, common))
  ]);
}

function cc(id, client, scope) {
  log.debug("Entering cc(). " + client + " " + scope);
  log.debug("Leaving cc().");
  return K.send(K.rb(id) + "/oauth2/token", { form: {
    grant_type: "client_credentials", client_id: client,
    client_secret: SECRET, scope: scope } });
}

// A token request and the rows of `code` it added.
async function asked(id, code, fn) {
  log.debug("Entering asked(). " + code);
  const out = await K.coded(id, code, fn);
  log.debug("Leaving asked(). " + out.rose);
  return out;
}

function refusedScope(out, code) {
  log.debug("Entering refusedScope().");
  assert.strictEqual(out.answer.status, 400, K.shown(out.answer));
  assert.strictEqual(out.answer.json.error, "invalid_scope",
                     K.shown(out.answer));
  assert.ok(out.rose >= 1, code + " was not recorded");
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(out.answer.text), out.answer.text);
  log.debug("Leaving refusedScope().");
}

function issued(r, scope) {
  log.debug("Entering issued().");
  assert.strictEqual(r.status, 200, K.shown(r));
  assert.ok(r.json && r.json.access_token, K.shown(r));
  if (scope) {
    assert.strictEqual(K.decode(r.json.access_token).payload.scope, scope,
                       JSON.stringify(K.decode(r.json.access_token).payload));
  }
  log.debug("Leaving issued().");
}

// The authorization endpoint through a sign-in, following this service's
// own redirects; answers the last response and the last place it went.
async function authorize(id, b, params, username) {
  log.debug("Entering authorize().");
  // PKCE on every request: product requires it of every client.
  const p = K.pkce();
  const url = K.rb(id) + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", redirect_uri: REDIRECT,
                    state: "st-" + K.rand(4), nonce: "n-" + K.rand(4),
                    code_challenge: p.challenge,
                    code_challenge_method: "S256" }, params));
  let r = await b.go(url);
  let last = url;
  if (K.toSignIn(r)) {
    r = await K.signIn(id, b, r, username, PASSWORD);
  }
  for (let hops = 0; hops < 8 && (r.status === 302 || r.status === 303) &&
       (/^\//.test(r.location) || urls.isUnder(r.location, K.base));
       hops++) {
    last = r.location;
    r = await b.go(r.location);
  }
  if (r.status === 302 || r.status === 303) {
    last = r.location;
  }
  log.debug("Leaving authorize(). " + r.status + " " + last);
  return { r: r, last: last, answer: K.answerAt(r, REDIRECT) };
}

async function protectedScopes(id, m) {
  log.debug("Entering protectedScopes(). " + m);
  log.info("=== A. the protected scopes (" + m + ") ===");
  for (const one of [["sp-bare", "admin:write"], ["sp-bare", "report:admin"],
                     ["sp-declared", "scim:read"], ["sp-bare", "ssf.read"],
                     ["sp-bare", "ssf.manage"]]) {
    const out = await asked(id, "STS-OAUTH-0577", function () {
      return cc(id, one[0], one[1]);
    });
    K.check("A (" + m + "). " + one[1] + " to " + one[0] + ", which does " +
            "not declare it, is refused invalid_scope (STS-OAUTH-0577)",
            function () {
      refusedScope(out, "STS-OAUTH-0577");
    });
  }
  const r = await cc(id, "sp-declared", "scim:write");
  K.check("A (" + m + "). and scim:write, which sp-declared declares, is " +
          "issued", function () {
    issued(r, "scim:write");
  });
  log.debug("Leaving protectedScopes().");
}

async function protectedDevelopment(dev) {
  log.debug("Entering protectedDevelopment().");
  const ordinary = [await cc(dev, "sp-bare", "ssf:read"),
                    await cc(dev, "sp-bare", "ssf:write")];
  K.check("A. ssf:read and ssf:write are not Shared Signals scopes (#334): " +
          "development issues them to an undeclaring client", function () {
    issued(ordinary[0], "ssf:read");
    issued(ordinary[1], "ssf:write");
  });
  await K.set(dev, "scim.scopeWrite", "prov:write");
  const renamed = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-bare", "prov:write");
  });
  const old = await cc(dev, "sp-bare", "scim:write");
  K.check("A. the SCIM scope is protected by its SETTING's name: renamed " +
          "prov:write is refused STS-OAUTH-0577, and scim:write is an " +
          "ordinary scope again", function () {
    refusedScope(renamed, "STS-OAUTH-0577");
    issued(old, "scim:write");
  });
  await K.unset(dev, "scim.scopeWrite");
  await K.set(dev, "ssf.authScopeRead", "custom:read");
  const custom = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-bare", "custom:read");
  });
  const fixed = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-bare", "ssf.read");
  });
  const colon = await cc(dev, "sp-bare", "ssf:read");
  K.check("A. renaming ssf.authScopeRead adds a protected name and " +
          "unprotects neither fixed one (ssf.read still refused, ssf:read " +
          "still ordinary)", function () {
    refusedScope(custom, "STS-OAUTH-0577");
    refusedScope(fixed, "STS-OAUTH-0577");
    issued(colon, "ssf:read");
  });
  await K.unset(dev, "ssf.authScopeRead");
  log.debug("Leaving protectedDevelopment().");
}

async function fieldsOf(id, application) {
  log.debug("Entering fieldsOf(). " + application);
  const r = await K.send(K.rb(id) + "/admin-api/applications?application=" +
                         encodeURIComponent(application));
  // One application's view answers it directly, `found` saying whether
  // there is one.
  const one = r.json && r.json.found !== false &&
    r.json.identifier === application ? r.json : null;
  log.debug("Leaving fieldsOf().");
  return one;
}

async function seeded(dev) {
  log.debug("Entering seeded().");
  const report = await fieldsOf(dev, "sts-report");
  const reportApi = await fieldsOf(dev, "sts-report-api");
  const debuggerApi = await fieldsOf(dev, "sts-debugger-api");
  const apiClient = await fieldsOf(dev, "sts-api-client");
  const flat = function (one, attribute) {
    return [].concat(((one && one.fields) || {})[attribute] || []);
  };
  K.check("A. a new realm is seeded with the reports client and the " +
          "reports API's resource object, and not the debugger's",
          function () {
    assert.ok(report, "no sts-report");
    assert.ok(reportApi, "no sts-report-api");
    assert.strictEqual(debuggerApi, null);
  });
  K.check("A. sts-report-api defines the report permissions under " +
          "urn:sts:report-api: and sts-report holds delegated permission " +
          "grants of both (#1141)", function () {
    assert.strictEqual(String(flat(reportApi, "oauthPermissionBaseUri")[0]),
                       "urn:sts:report-api:",
                       JSON.stringify(reportApi.fields));
    const held = flat(report, "oauthDelegatedPermission");
    assert.ok(held.indexOf("urn:sts:report-api:report:use") >= 0 &&
              held.indexOf("urn:sts:report-api:report:admin") >= 0,
              JSON.stringify(held));
  });
  K.check("A. the seeded sts-api-client holds the admin API's delegated " +
          "permission grants and lists none of the API words itself",
          function () {
    assert.ok(apiClient, "no sts-api-client");
    const held = flat(apiClient, "oauthDelegatedPermission").join(" ");
    assert.ok(/urn:sts:admin-api:admin:read/.test(held) &&
              /urn:sts:admin-api:admin:write/.test(held), held);
    const listed = flat(apiClient, "oauthAllowedScope");
    ["admin:read", "admin:write", "report:use"].forEach(function (one) {
      assert.ok(listed.indexOf(one) < 0, JSON.stringify(listed));
    });
  });
  log.debug("Leaving seeded().");
}

async function everyOtherScope(dev, prod) {
  log.debug("Entering everyOtherScope().");
  log.info("=== B. every other scope ===");
  const free = await cc(dev, "sp-bare", "anything:custom");
  K.check("B. development: an undeclared custom scope is issued",
          function () {
    issued(free, "anything:custom");
  });
  const defaults = await cc(prod, "sp-bare", "profile email");
  K.check("B. product, no list: the OpenID Connect scopes are the default " +
          "set", function () {
    issued(defaults, "profile email");
  });
  for (const one of ["anything:custom", "ssf:write"]) {
    const out = await asked(prod, "STS-OAUTH-0578", function () {
      return cc(prod, "sp-bare", one);
    });
    K.check("B. product, no list: " + one + " is refused STS-OAUTH-0578, " +
            "and the description names oauthAllowedScope", function () {
      refusedScope(out, "STS-OAUTH-0578");
      assert.ok(/oauthAllowedScope/.test(out.answer.json.error_description),
                K.shown(out.answer));
    });
  }
  const listed = await cc(prod, "sp-declared", "api:read");
  K.check("B. product, a list: what it lists is issued, `scope` echoed",
          function () {
    issued(listed, "api:read");
    assert.strictEqual(listed.json.scope, "api:read", K.shown(listed));
  });
  const notListed = await asked(prod, "STS-OAUTH-0578", function () {
    return cc(prod, "sp-declared", "profile");
  });
  K.check("B. product, a list: the default set does not apply — profile " +
          "is not on it (STS-OAUTH-0578)", function () {
    refusedScope(notListed, "STS-OAUTH-0578");
  });
  log.debug("Leaving everyOtherScope().");
}

async function refreshNarrows(dev) {
  log.debug("Entering refreshNarrows().");
  log.info("=== C. a refresh narrows ===");
  const user = "srp-alice-" + K.STAMP;
  await K.person(dev, user, PASSWORD);
  const first = await K.send(K.rb(dev) + "/oauth2/token", { form: {
    grant_type: "password", client_id: "sp-declared", client_secret: SECRET,
    username: user, password: PASSWORD,
    scope: "openid api:read scim:write offline_access" } });
  K.check("C. (a control: the grant carries scim:write)", function () {
    assert.strictEqual(first.status, 200, K.shown(first));
    assert.ok(/scim:write/.test(first.json.scope), K.shown(first));
    assert.ok(first.json.refresh_token, K.shown(first));
  });
  const removed = await K.send(K.rb(dev) + "/admin-api/applications/remove",
    { json: { application: "sp-declared", attribute: "oauthAllowedScope",
              value: "scim:write" } });
  K.check("C. (a control: the allowance is taken off)", function () {
    assert.strictEqual(removed.status, 200, K.shown(removed));
  });
  const out = await asked(dev, "STS-OAUTH-0579", function () {
    return K.send(K.rb(dev) + "/oauth2/token", { form: {
      grant_type: "refresh_token", client_id: "sp-declared",
      client_secret: SECRET, refresh_token: first.json.refresh_token } });
  });
  const r = out.answer;
  K.check("C. the refresh is issued without scim:write, and `scope` says " +
          "so", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    const words = String(r.json.scope).split(" ");
    assert.ok(words.indexOf("scim:write") < 0 &&
              words.indexOf("api:read") >= 0, r.json.scope);
  });
  K.check("C. the access token does not carry it", function () {
    const scope = String(K.decode(r.json.access_token).payload.scope || "");
    assert.ok(scope.split(" ").indexOf("scim:write") < 0, scope);
  });
  K.check("C. one audit row records what was taken off (STS-OAUTH-0579)",
          function () {
    assert.strictEqual(out.rose, 1);
  });
  await K.send(K.rb(dev) + "/admin-api/applications/add",
    { json: { application: "sp-declared", attribute: "oauthAllowedScope",
              value: "scim:write" } });
  log.debug("Leaving refreshNarrows().");
}

async function permissions(dev, prod, permission) {
  log.debug("Entering permissions().");
  log.info("=== D. delegated permissions ===");
  const user = "srp-bob-" + K.STAMP;
  await K.person(dev, user, PASSWORD);
  const pw = function () {
    return K.send(K.rb(dev) + "/oauth2/token", { form: {
      grant_type: "password", client_id: "sp-bare", client_secret: SECRET,
      username: user, password: PASSWORD,
      scope: "openid " + permission } });
  };
  const honoured = await pw();
  K.check("D. development, setting off: an ungranted permission is " +
          "honoured", function () {
    assert.strictEqual(honoured.status, 200, K.shown(honoured));
    // The permission is issued in its short form, the token audienced to
    // the API that defines it.
    assert.ok(String(honoured.json.scope).split(" ").indexOf("write") >= 0,
              K.shown(honoured));
    assert.strictEqual(K.decode(honoured.json.access_token).payload.aud,
                       permission.replace(/write$/, ""));
  });
  await K.set(dev, "oauth2.delegatedPermissionsEnforced", true);
  const enforced = await asked(dev, "STS-OAUTH-0155", pw);
  K.check("D. development, setting on: it is refused (STS-OAUTH-0155)",
          function () {
    refusedScope(enforced, "STS-OAUTH-0155");
  });
  await K.unset(dev, "oauth2.delegatedPermissionsEnforced");

  const prodUser = "srp-carol-" + K.STAMP;
  await K.person(prod, prodUser, PASSWORD);
  const b = K.browser();
  const before = await K.codeCount(prod, "STS-OAUTH-0155");
  const refused = await authorize(prod, b, { client_id: "sp-bare",
    scope: "openid " + permission }, prodUser);
  const after = await K.codeAfter(prod, "STS-OAUTH-0155", before);
  K.check("D. product, setting off: it is refused all the same — " +
          "invalid_scope at the authorization endpoint (STS-OAUTH-0155)",
          function () {
    assert.ok(refused.answer, K.shown(refused.r));
    assert.strictEqual(refused.answer.get("error"), "invalid_scope",
                       refused.r.location);
    assert.ok(after > before, "STS-OAUTH-0155 was not recorded");
  });

  log.info("=== E. the policy decides ===");
  const made = await K.send(K.rb(prod) +
    "/admin-api/xacml/create-from-template",
    { json: { name: "role-issuance", template: "role-issuance" } });
  K.check("E. (a control: an operator's role-issuance document is written " +
          "from the built-in template)", function () {
    assert.strictEqual(made.status, 200, K.shown(made));
  });
  await removeRule(prod, "permission-not-granted");
  const let_ = await authorize(prod, b, { client_id: "sp-bare",
    scope: "openid " + permission }, prodUser);
  K.check("E. without `permission-not-granted` the ungranted permission " +
          "is honoured even in product: the document decided", function () {
    assert.ok(let_.answer && let_.answer.get("code"), K.shown(let_.r));
  });
  const deleted = await K.send(K.rb(prod) + "/admin-api/xacml/delete",
                               { json: { name: "role-issuance" } });
  const back = await authorize(prod, b, { client_id: "sp-bare",
    scope: "openid " + permission }, prodUser);
  K.check("E. the document deleted, the built-in decides again and refuses " +
          "it", function () {
    assert.strictEqual(deleted.status, 200, K.shown(deleted));
    assert.ok(back.answer, K.shown(back.r));
    assert.strictEqual(back.answer.get("error"), "invalid_scope");
  });
  log.debug("Leaving permissions().");
}

async function removeRule(id, suffix) {
  log.debug("Entering removeRule(). " + suffix);
  const view = await K.send(K.rb(id) +
                            "/admin-api/xacml/editor?policy=role-issuance");
  const row = ((view.json && view.json.tree) || []).filter(function (one) {
    return one.kind === "rule" && one.edit && one.edit.node &&
      String(one.edit.node.id).endsWith(":rule:" + suffix);
  })[0];
  assert.ok(row, "no rule " + suffix + " in " + view.text.slice(0, 300));
  const r = await K.send(K.rb(id) + "/admin-api/xacml/remove",
                         { json: { policy: "role-issuance",
                                   path: row.path } });
  assert.strictEqual(r.status, 200, "remove " + suffix + ": " + K.shown(r));
  log.debug("Leaving removeRule().");
}

async function consentRule(dev) {
  log.debug("Entering consentRule().");
  log.info("=== E. consent, as a rule of the document ===");
  const user = "srp-dave-" + K.STAMP;
  await K.person(dev, user, PASSWORD);
  await K.set(dev, "oauth2.consentRequired", true);
  const b = K.browser();
  const asks = await authorize(dev, b, { client_id: "sp-declared",
    scope: "openid email" }, user);
  K.check("E. (a control: with consent required, two scopes nobody agreed " +
          "to go to the consent screen)", function () {
    assert.ok(/\/oauth2\/consent/.test(asks.last), asks.last);
    assert.strictEqual(asks.answer, null);
  });
  const made = await K.send(K.rb(dev) +
    "/admin-api/xacml/create-from-template",
    { json: { name: "role-issuance", template: "role-issuance" } });
  assert.strictEqual(made.status, 200, K.shown(made));
  await removeRule(dev, "consent-outstanding");
  const none = await authorize(dev, b, { client_id: "sp-declared",
    scope: "openid email" }, user);
  K.check("E. without `consent-outstanding` nothing needs consent: the " +
          "code comes straight back", function () {
    assert.ok(none.answer && none.answer.get("code"),
              none.last + " " + K.shown(none.r));
  });
  await K.send(K.rb(dev) + "/admin-api/xacml/delete",
               { json: { name: "role-issuance" } });
  await K.set(dev, "oauth2.consentRequired", false);
  log.debug("Leaving consentRule().");
}

async function detailTypes(dev) {
  log.debug("Entering detailTypes().");
  log.info("=== F. RFC 9396 types ===");
  const user = "srp-erin-" + K.STAMP;
  await K.person(dev, user, PASSWORD);
  const b = K.browser();
  const before = await K.codeCount(dev, "STS-OAUTH-0454");
  const out = await authorize(dev, b, { client_id: "sp-rar",
    scope: "openid",
    authorization_details: JSON.stringify([{ type: "openid_credential" }])
  }, user);
  const after = await K.codeAfter(dev, "STS-OAUTH-0454", before);
  K.check("F. a detail of a type the client did not register is refused " +
          "by the policy (STS-OAUTH-0454)", function () {
    const said = out.answer ? out.answer.get("error") : K.shown(out.r);
    assert.ok(/invalid_authorization_details|invalid_request/.test(said),
              said + " " + out.last);
    assert.ok(after > before, "STS-OAUTH-0454 was not recorded");
  });
  log.debug("Leaving detailTypes().");
}

async function exchanges(dev, prod) {
  log.debug("Entering exchanges().");
  log.info("=== G. a token exchange's ordinary scope ===");
  for (const id of [dev, prod]) {
    const subject = await cc(id, "sp-declared", "api:read");
    assert.strictEqual(subject.status, 200, K.shown(subject));
    const out = await asked(id, "STS-OAUTH-0621", function () {
      return K.send(K.rb(id) + "/oauth2/token", { form: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_id: "sp-declared", client_secret: SECRET,
        subject_token: subject.json.access_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        scope: "api:read email" } });
    });
    if (id === prod) {
      K.check("G. product: an ordinary scope the subject_token lacks is " +
              "refused (STS-OAUTH-0621)", function () {
        refusedScope(out, "STS-OAUTH-0621");
      });
    } else {
      // THE WIRE DIFFERS FROM THE IN-PROCESS VERDICT: the policy's verdict
      // in development is `keep`, but the issued token is the subject's
      // own scope — the exchange still never widens. Asserted as observed.
      K.check("G. development: the same exchange is not refused — issued " +
              "with the subject_token's own scope, email not added",
              function () {
        assert.strictEqual(out.answer.status, 200, K.shown(out.answer));
        assert.strictEqual(out.answer.json.scope, "api:read",
                           K.shown(out.answer));
        assert.strictEqual(out.rose, 0);
      });
    }
  }
  log.debug("Leaving exchanges().");
}

async function apiWords(dev) {
  log.debug("Entering apiWords().");
  log.info("=== H. a delegated permission grant is the declaration ===");
  const listed = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-listed", "admin:read");
  });
  K.check("H. admin:read listed in oauthAllowedScope no longer declares " +
          "it: refused STS-OAUTH-0577", function () {
    refusedScope(listed, "STS-OAUTH-0577");
  });
  const delegated = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-delegated", "admin:read");
  });
  K.check("H. a delegated permission grant of admin:read on the " +
          "management API's object declares it: whatever else decides, it " +
          "is not refused STS-OAUTH-0577", function () {
    assert.strictEqual(delegated.rose, 0, K.shown(delegated.answer));
  });
  const other = await asked(dev, "STS-OAUTH-0577", function () {
    return cc(dev, "sp-delegated", "admin:write");
  });
  K.check("H. and it declares the permission it names and no other — " +
          "admin:write is refused 0577", function () {
    refusedScope(other, "STS-OAUTH-0577");
  });
  log.debug("Leaving apiWords().");
}

async function test() {
  log.debug("Entering test().");
  const dev = await K.realm("srp", "development");
  const prod = await K.realm("srpp", "product",
    { "authn.allowOptionalSecondFactor": "true" });
  const permission = "https://srp-api-" + K.STAMP + ".example/write";
  await clients(dev, "https://srp-api-" + K.STAMP + ".example/");
  await clients(prod, "https://srp-api-" + K.STAMP + ".example/");
  await protectedScopes(dev, "development");
  await protectedScopes(prod, "product");
  await protectedDevelopment(dev);
  await seeded(dev);
  await everyOtherScope(dev, prod);
  await refreshNarrows(dev);
  await permissions(dev, prod, permission);
  await consentRule(dev);
  await detailTypes(dev);
  await exchanges(dev, prod);
  await apiWords(dev);
  log.debug("Leaving test().");
}

K.main(test, 43);
