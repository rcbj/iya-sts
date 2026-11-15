// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_fields.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S FIELDS, OVER THE WIRE: THE RULES EACH ONE WRITES BY.
//
// D12 (#444): the in-process tests that held these called
// `adminActions.applicationsAction()` and read the registry back; this job
// asks the same of `POST /realm/<r>/admin-api/applications/<action>` and
// reads the answers, the application's own `GET` and the realm's audit log,
// so the rules stay covered when Rust replaces Node. It carries over:
//
//   A. tests/application_cors_field.js — `appCorsOrigin` (2026-09-18): one
//      declaration of role `cors` for every family, published by
//      `GET /admin-api/applications/new`; a create with no family stores the
//      origins normalised and de-duplicated; one value that is not an origin
//      refuses the whole create (STS-REG-0150); the page's add and remove;
//      the application page's grid leaves it to the Browser origins tab; and
//      what CORS answers — the client's own list for a request naming the
//      client, the realm's union for one that names none.
//   B. tests/application_description.js — `description` is ONE value
//      (#456): set, replaced, two refused, cleared, the add refused, and
//      the registry's note when none is typed.
//   C. tests/application_semantics_choices.js — the delegation semantics as
//      their two values, and a third refused.
//   D. tests/application_primary_name.js — the family's identifier
//      attribute defaults to the identifier (#393), a typed list is the
//      whole list, a save that newly declares a family fills it, a re-save
//      does not refill a cleared one, and a named value wins.
//   E. tests/application_generate_secret.js — the secret a create carries
//      is stored as `client_secret_basic` and gets a token; the minted
//      secret is base64url and new each time (through `regenerate-secret`,
//      which mints with the same function: the console's own
//      `generate-secret` is an `/admin-api/console` operation this API
//      client cannot call, and this API refuses it by name); the first
//      secret's lifetime (#394), STS-REG-0359 and STS-REG-0360.
//   F. tests/application_reveal_secret.js — `reveal-secret` (#446): a
//      secret by id, STS-ADMIN-0842 three ways, the audit row naming the id
//      and never the value, and no GET answer carrying a value.
//   G. tests/application_field_search.js — the self-reference rule
//      (STS-REG-0335) at a create, an add and the grid's save, by
//      identifier, client_id and audience; the application and group
//      searches' `q`, `per=5`, paging and `exclude`; `appMayAct` (#461) by
//      DN, refused for the application's own entry, and the `may_act` claim
//      a client_credentials token then carries.
//   H. tests/flow_type_choices.js — `oauthGrantType` and
//      `oauthResponseType` as closed sets equal to what the metadata
//      promises with every switch on; a write outside them refused
//      (STS-REG-0203); a response type stored with its words sorted; a
//      remove in another order still removing; the observed lists no field
//      of the grid; `oauthScope` refused at a set or add (STS-REG-0361)
//      while a remove still works.
//
// What stays in process (class (d)): the console bundle's own helpers and
// drawing — `webAnswers.*`, `WebKit.fieldGridCell()`, the lifetime field's
// markup, `withRealmLinks()` and the sub-tab's rendering — which run in a
// browser over the answers this job asserts.
//
// Every write is in a throwaway realm this job creates, left standing as
// every job leaves its realms, and removed at the end only when
// STS_TEST_REMOVE_REALMS=1 (removeRealms() says why). OWNED HERE
// (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_application_fields",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("appf-" + STAMP).slice(0, 31);
const FLOWS = ("appflow-" + STAMP).slice(0, 31);
const API = base + "/realm/" + REALM + "/admin-api";
const TAG = "af" + STAMP.slice(-8);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

// One application action in this job's realm.
function act(action, payload) {
  log.debug("Entering act(). " + action);
  log.debug("Leaving act().");
  return post(API + "/applications/" + action, payload);
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await post(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// The application's own GET answer, or null when it is not there.
async function detail(identifier) {
  log.debug("Entering detail(). " + identifier);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving detail().");
  return r.body && r.body.found !== false ? r.body : null;
}

function values(v) {
  log.debug("Entering values().");
  log.debug("Leaving values().");
  return [].concat(v === undefined || v === null ? [] : v).map(String);
}

function refusedWith(r, pattern) {
  log.debug("Entering refusedWith().");
  const text = ((r.body && r.body.errors) || []).join(" ");
  log.debug("Leaving refusedWith().");
  return r.status === 400 && r.body && r.body.ok === false &&
         pattern.test(text);
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// How many refusals carrying `code` the realm's audit log holds for the
// applications action endpoint. A code is never sent, so this is where it
// is read.
async function codeCount(code, realmApi) {
  log.debug("Entering codeCount(). " + code);
  const r = await send((realmApi || API) + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  const rows = (r.body && r.body.events) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// Runs `fn` and answers whether the audit log gained a row carrying
// `code`.
async function recordsCode(code, fn, realmApi) {
  log.debug("Entering recordsCode(). " + code);
  const before = await codeCount(code, realmApi);
  const out = await fn();
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(100);
    after = await codeCount(code, realmApi);
  }
  log.debug("Leaving recordsCode(). " + before + " -> " + after);
  return { out: out, recorded: after > before };
}

function fieldOf(list, attribute) {
  log.debug("Entering fieldOf().");
  log.debug("Leaving fieldOf().");
  return (list || []).filter(function (one) {
    return one.attribute === attribute;
  })[0] || null;
}

async function token(realm, clientId, secret, origin) {
  log.debug("Entering token(). " + clientId);
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (origin) {
    headers.Origin = origin;
  }
  const r = await send(base + "/realm/" + realm + "/oauth2/token", {
    method: "POST", headers: headers,
    body: new URLSearchParams({ grant_type: "client_credentials",
                                client_id: clientId,
                                client_secret: secret }).toString() });
  log.debug("Leaving token(). " + r.status);
  return r;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt || "").split(".");
  assert.strictEqual(parts.length, 3, "not a JWT: " + String(jwt)
    .slice(0, 80));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function cors(newForm) {
  log.debug("Entering cors().");
  log.info("=== A. appCorsOrigin (application_cors_field.js) ===");
  const ID = TAG + "-cors";
  check("1. appCorsOrigin is a declaration of role cors belonging to " +
        "every family, published by GET /admin-api/applications/new",
        function () {
    const row = fieldOf(newForm.declarations, "appCorsOrigin");
    assert.ok(row && row.role === "cors" && row.kind === "multi" &&
              row.everyFamily === true && row.families.length === 0,
              JSON.stringify(row));
  });
  await ok(API + "/applications/create", { identifier: ID,
    "field.appCorsOrigin": "HTTPS://App.CorsField.example:443\n" +
                           "https://app.corsfield.example\n" +
                           "http://localhost:5173" },
    "created an application with origins and no family");
  const made = await detail(ID);
  check("2a/2b. a create declaring NO family keeps its origins, " +
        "normalised and de-duplicated, a non-default port kept",
        function () {
    assert.deepStrictEqual(values(made.fields.appCorsOrigin),
      ["https://app.corsfield.example", "http://localhost:5173"]);
  });
  check("2c. the page's Configuration grid does not draw appCorsOrigin; " +
        "the Browser origins tab lists the two held", function () {
    assert.ok(!fieldOf(made.page.config.fields, "appCorsOrigin"));
    assert.deepStrictEqual(made.page.cors.map(function (one) {
      return one.canonical;
    }), ["https://app.corsfield.example", "http://localhost:5173"]);
  });
  check("2d. the new-application form still offers it", function () {
    assert.ok(fieldOf(newForm.fields, "appCorsOrigin"));
  });
  const bad = await recordsCode("STS-REG-0150", function () {
    return act("create", { identifier: ID + "-bad",
      "field.appCorsOrigin": "https://ok.corsfield.example\n" +
                             "https://has.a.path.example/callback" });
  });
  check("3. one value that is not an origin refuses the WHOLE create, " +
        "naming the attribute, recorded STS-REG-0150", function () {
    assert.ok(refusedWith(bad.out, /appCorsOrigin.*not an origin/),
              bad.out.raw.slice(0, 300));
    assert.ok(bad.recorded, "no STS-REG-0150 row");
  });
  const leftBad = await detail(ID + "-bad");
  check("3. and nothing was created", function () {
    assert.strictEqual(leftBad, null);
  });
  await ok(API + "/applications/add", { application: ID,
    attribute: "appCorsOrigin", value: "HTTPS://Third.CorsField.example" },
    "added an origin");
  const wild = await act("add", { application: ID,
    attribute: "appCorsOrigin", value: "https://*.corsfield.example" });
  await ok(API + "/applications/remove", { application: ID,
    attribute: "appCorsOrigin", value: "http://localhost:5173" },
    "removed an origin");
  const after = values((await detail(ID)).fields.appCorsOrigin);
  check("4a. the Add box adds one origin, normalised", function () {
    assert.ok(after.indexOf("https://third.corsfield.example") >= 0,
              JSON.stringify(after));
  });
  check("4b. and refuses a wildcard, which is not an origin", function () {
    assert.ok(refusedWith(wild, /appCorsOrigin/), wild.raw.slice(0, 300));
    assert.ok(after.indexOf("https://*.corsfield.example") < 0);
  });
  check("4c. a row's Remove takes that one origin off and leaves the " +
        "others", function () {
    assert.ok(after.indexOf("http://localhost:5173") < 0 &&
              after.indexOf("https://app.corsfield.example") >= 0,
              JSON.stringify(after));
  });

  const CLIENT = ID + "-client";
  const SECRET = "cors-field-" + STAMP + "-secret";
  await ok(API + "/applications/create", { identifier: CLIENT,
    protocols: ["oauth2"], "field.oauthClientId": CLIENT,
    "field.oauthClientSecret": SECRET,
    "field.oauthGrantType": "client_credentials",
    "field.appCorsOrigin": "https://Spa.CorsField.example\n" +
                           "https://admin.corsfield.example:8443" },
    "created an OAuth client with origins");
  const listed = await token(REALM, CLIENT, SECRET,
                             "https://admin.corsfield.example:8443");
  const other = await token(REALM, CLIENT, SECRET,
                            "https://app.corsfield.example");
  check("5a. a request naming this client_id is answered for an origin " +
        "typed on it, and not for another application's", function () {
    assert.strictEqual(listed.status, 200, listed.raw.slice(0, 300));
    assert.strictEqual(listed.headers.get("access-control-allow-origin"),
                       "https://admin.corsfield.example:8443");
    assert.strictEqual(other.headers.get("access-control-allow-origin"),
                       null);
  });
  const disco = await send(base + "/realm/" + REALM +
    "/.well-known/openid-configuration",
    { headers: { Origin: "https://spa.corsfield.example" } });
  const stranger = await send(base + "/realm/" + REALM +
    "/.well-known/openid-configuration",
    { headers: { Origin: "https://stranger.corsfield.example" } });
  check("5b. a request naming NO client is answered from the realm's " +
        "union, and an origin on no application is not", function () {
    assert.strictEqual(disco.headers.get("access-control-allow-origin"),
                       "https://spa.corsfield.example");
    assert.strictEqual(stranger.headers.get("access-control-allow-origin"),
                       null);
  });
  log.debug("Leaving cors().");
}

async function description(newForm) {
  log.debug("Entering description().");
  log.info("=== B. description (application_description.js) ===");
  const ID = TAG + "-desc";
  check("1. description is ONE box on the Every protocol sub-tab, set " +
        "rather than added to", function () {
    const row = fieldOf(newForm.fields, "description");
    assert.ok(row && row.type === "string" && row.editable === "set" &&
              row.everyFamily === true, JSON.stringify(row));
  });
  await ok(API + "/applications/create", { identifier: ID,
    "field.description": "The payroll front end" }, "created");
  const made = await detail(ID);
  check("2. a create keeps the description typed as its one value, " +
        "without the registry's note", function () {
    assert.strictEqual(made.description, "The payroll front end");
    assert.strictEqual(made.fields.description, "The payroll front end");
  });
  await ok(API + "/applications/create", { identifier: ID + "-bare" },
           "created one with no description");
  const bare = await detail(ID + "-bare");
  check("3. a create with none gets the registry's note", function () {
    assert.ok(/created from the console/.test(bare.description),
              JSON.stringify(bare.description));
  });
  const save = function (payload) {
    return act("update-fields", Object.assign({ application: ID,
      present: "description" }, payload));
  };
  const set = await save({ "field.description": "Payroll, renamed" });
  const afterSet = await detail(ID);
  check("4a. Save sets it, replacing the old value", function () {
    assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
    assert.strictEqual(afterSet.description, "Payroll, renamed");
  });
  const two = await save({ "field.description.0": "one",
                           "field.description.1": "two" });
  const afterTwo = await detail(ID);
  check("4b. two values are refused, and the one held is kept",
        function () {
    assert.strictEqual(two.status, 400, two.raw.slice(0, 300));
    assert.strictEqual(afterTwo.description, "Payroll, renamed");
  });
  const cleared = await save({ "field.description": "" });
  const afterClear = await detail(ID);
  check("4c. an emptied box clears it", function () {
    assert.strictEqual(cleared.status, 200, cleared.raw.slice(0, 300));
    assert.ok(!afterClear.description, JSON.stringify(afterClear
      .description));
    assert.strictEqual(afterClear.fields.description, undefined);
  });
  const added = await act("add", { application: ID,
    attribute: "description", value: "a second line" });
  const afterAdd = await detail(ID);
  check("5. the add action — the old list's + — is refused for it",
        function () {
    assert.strictEqual(added.status, 400, added.raw.slice(0, 300));
    assert.ok(!afterAdd.description);
  });
  log.debug("Leaving description().");
}

async function semantics(newForm) {
  log.debug("Entering semantics().");
  log.info("=== C. delegation semantics (application_semantics_choices.js)" +
           " ===");
  const ID = TAG + "-sem";
  const BOTH = ["delegation", "impersonation"];
  check("1. both fields offer delegation and impersonation as choices",
        function () {
    assert.deepStrictEqual(fieldOf(newForm.fields,
      "appDelegationSemantics").choices, BOTH);
    assert.deepStrictEqual(fieldOf(newForm.fields,
      "appDefaultDelegationSemantics").choices, BOTH);
  });
  await ok(API + "/applications/create", { identifier: ID }, "created");
  const page = (await detail(ID)).page.config.fields;
  check("2. on the page the list is an array from the two and the default " +
        "an enum", function () {
    const list = fieldOf(page, "appDelegationSemantics");
    const one = fieldOf(page, "appDefaultDelegationSemantics");
    assert.ok(list && list.type === "array" &&
              (list.choices || []).length === 2, JSON.stringify(list));
    assert.ok(one && one.type === "enum", JSON.stringify(one));
  });
  const bad = await act("set", { application: ID,
    attribute: "appDefaultDelegationSemantics", value: "proxying" });
  const good = await act("add", { application: ID,
    attribute: "appDelegationSemantics", value: "impersonation" });
  check("3. a value outside the two is refused at the write, and one of " +
        "them is taken", function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.strictEqual(good.status, 200, good.raw.slice(0, 300));
  });
  log.debug("Leaving semantics().");
}

async function primaryName(newForm) {
  log.debug("Entering primaryName().");
  log.info("=== D. primary names (application_primary_name.js) ===");
  const ID = TAG + "-pn";
  check("1. the four families' identifiers are primary names; a " +
        "certificate subject, a bind DN and a SPIFFE ID are not",
        function () {
    ["oauthClientId", "samlEntityId", "wsfedRealm",
     "krb5ServicePrincipalName"].forEach(function (name) {
      assert.strictEqual(fieldOf(newForm.fields, name).primaryName, true,
                         name);
    });
    ["oauthTlsClientAuthSubjectDn", "ldapBindDn",
     "spiffeWorkloadId"].forEach(function (name) {
      const row = fieldOf(newForm.fields, name);
      assert.ok(!row || row.primaryName === false, name);
    });
  });
  await ok(API + "/applications/create", { identifier: ID,
    protocols: ["oauth2", "saml2"] }, "created for OAuth and SAML");
  const made = (await detail(ID)).fields;
  check("2. a create with nothing typed gets the identifier as its one " +
        "client_id and its one entityID, and no certificate subject",
        function () {
    assert.deepStrictEqual(values(made.oauthClientId), [ID]);
    assert.deepStrictEqual(values(made.samlEntityId), [ID]);
    assert.strictEqual(values(made.oauthTlsClientAuthSubjectDn).length, 0);
  });
  await ok(API + "/applications/create", { identifier: ID + "-l",
    protocols: ["oauth2"], "field.oauthClientId.0": ID + "-l-dev",
    "field.oauthClientId.1": ID + "-l-prod" }, "created with two ids");
  const listed = (await detail(ID + "-l")).fields;
  check("3. two client ids typed on the create are the whole list",
        function () {
    assert.deepStrictEqual(values(listed.oauthClientId).sort(),
                           [ID + "-l-dev", ID + "-l-prod"]);
  });
  const resave = function (protocols, extra) {
    return act("update-fields", Object.assign({ application: ID,
      protocolsPresent: "1", protocols: protocols },
      extra || {}));
  };
  const declared = await resave(["oauth2", "saml2", "wsfed"]);
  const afterDeclare = (await detail(ID)).fields;
  check("4a. ticking WS-Federation on a save fills wsfedRealm with the " +
        "identifier", function () {
    assert.strictEqual(declared.status, 200, declared.raw.slice(0, 300));
    assert.deepStrictEqual(values(afterDeclare.wsfedRealm), [ID]);
  });
  const clearedId = await act("update-fields", { application: ID,
    present: "oauthClientId", "field.oauthClientId": "" });
  const again = await resave(["oauth2", "saml2", "wsfed"]);
  const afterAgain = (await detail(ID)).fields;
  check("4b. a re-save of the same families leaves a cleared client_id " +
        "cleared", function () {
    assert.strictEqual(clearedId.status, 200, clearedId.raw.slice(0, 300));
    assert.strictEqual(again.status, 200, again.raw.slice(0, 300));
    assert.strictEqual(values(afterAgain.oauthClientId).length, 0);
  });
  const named = await resave(["oauth2", "saml2", "wsfed", "krb5"],
    { present: "krb5ServicePrincipalName",
      "field.krb5ServicePrincipalName": "HTTP/primary.example.com" });
  const afterNamed = (await detail(ID)).fields;
  check("5. an SPN named on the save that declares Kerberos is the one " +
        "kept", function () {
    assert.strictEqual(named.status, 200, named.raw.slice(0, 300));
    assert.deepStrictEqual(values(afterNamed.krb5ServicePrincipalName),
                           ["HTTP/primary.example.com"]);
  });
  log.debug("Leaving primaryName().");
}

async function secrets() {
  log.debug("Entering secrets().");
  log.info("=== E. secrets and their lifetime " +
           "(application_generate_secret.js) ===");
  const ID = TAG + "-gs";
  const helper = await act("generate-secret", {});
  check("the console's generate-secret is not an operation of this API, " +
        "and the refusal says where it is", function () {
    assert.strictEqual(helper.status, 404, helper.raw.slice(0, 300));
    assert.ok(/\/admin-api\/console\/applications\/generate-secret/
      .test(helper.raw), helper.raw.slice(0, 300));
  });
  const SECRET = "typed-" + STAMP + "-client-secret";
  await ok(API + "/applications/create", { identifier: ID,
    protocols: ["oauth2"], "field.oauthClientId": ID,
    "field.oauthClientSecret": SECRET }, "created with a secret");
  const made = await detail(ID);
  check("3a/3b. a create carrying a secret and naming no method is " +
        "recorded client_secret_basic", function () {
    assert.strictEqual(made.credentials.clientSecret.held, true);
    assert.strictEqual(made.credentials.clientSecret.authMethod,
                       "client_secret_basic");
    assert.deepStrictEqual(values(made.fields.oauthTokenEndpointAuthMethod),
                           ["client_secret_basic"]);
  });
  const got = await token(REALM, ID, SECRET);
  check("3. and the secret it carries gets a token as a form parameter",
        function () {
    assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  });
  const one = await ok(API + "/applications/regenerate-secret",
                       { application: ID }, "regenerated");
  const two = await ok(API + "/applications/regenerate-secret",
                       { application: ID }, "regenerated again");
  check("1. a minted client secret is base64url, and no two are alike",
        function () {
    assert.ok(/^[A-Za-z0-9_-]{32,}$/.test(one.clientSecret),
              one.clientSecret);
    assert.notStrictEqual(one.clientSecret, two.clientSecret);
  });
  const fresh = await token(REALM, ID, two.clientSecret);
  check("and the minted one is the secret the token endpoint takes",
        function () {
    assert.strictEqual(fresh.status, 200, fresh.raw.slice(0, 300));
  });

  await ok(API + "/config/set", { key: "oauth2.clientSecretLifetimeDays",
                                  value: "7" }, "set the default lifetime");
  const DAY = 86400;
  const create = function (suffix, secret, lifetimeDays) {
    const body = { identifier: ID + "-" + suffix, protocols: ["oauth2"],
                   "field.oauthClientId": ID + "-" + suffix };
    if (secret !== undefined) {
      body["field.oauthClientSecret"] = secret;
    }
    if (lifetimeDays !== undefined) {
      body.lifetimeDays = lifetimeDays;
    }
    return act("create", body);
  };
  const recordOf = async function (suffix) {
    const entry = await detail(ID + "-" + suffix);
    return entry ? entry.credentials.clientSecret.secrets[0] : null;
  };
  await create("d30", two.clientSecret + "x", "30");
  const r30 = await recordOf("d30");
  check("5a. a secret created with lifetimeDays 30 expires 30 days after " +
        "it was made", function () {
    assert.ok(r30 && r30.expiresAt === r30.createdAt + 30 * DAY,
              JSON.stringify(r30));
  });
  await create("d0", "zero-" + STAMP + "-secret", 0);
  const r0 = await recordOf("d0");
  check("5b. lifetimeDays 0 never expires, over a setting of 7",
        function () {
    assert.ok(r0 && r0.expiresAt === 0, JSON.stringify(r0));
  });
  await create("dempty", "empty-" + STAMP + "-secret", "");
  const re = await recordOf("dempty");
  check("5c. an empty lifetime takes oauth2.clientSecretLifetimeDays",
        function () {
    assert.ok(re && re.expiresAt === re.createdAt + 7 * DAY,
              JSON.stringify(re));
  });
  for (const badValue of ["731", "-1", "1.5", "soon"]) {
    const refused = await recordsCode("STS-REG-0359", function () {
      return create("bad", "bad-" + STAMP + "-secret", badValue);
    });
    const left = await detail(ID + "-bad");
    check("5d. lifetimeDays " + JSON.stringify(badValue) + " is refused " +
          "STS-REG-0359 and nothing is created", function () {
      assert.strictEqual(refused.out.status, 400,
                         refused.out.raw.slice(0, 300));
      assert.ok(refused.recorded, "no STS-REG-0359 row");
      assert.strictEqual(left, null);
    });
  }
  const none = await recordsCode("STS-REG-0360", function () {
    return create("nosecret", undefined, "30");
  });
  const whole = await recordsCode("STS-REG-0360", function () {
    return create("whole", JSON.stringify({ id: "cs-000000000001",
      secret: "whole-record-" + STAMP, created: 1700000000, expires: 0,
      description: "" }), "30");
  });
  const leftNone = await detail(ID + "-nosecret");
  const leftWhole = await detail(ID + "-whole");
  check("5e. a lifetime with no client secret is refused STS-REG-0360",
        function () {
    assert.ok(refusedWith(none.out, /no new client secret/),
              none.out.raw.slice(0, 300));
    assert.ok(none.recorded && leftNone === null);
  });
  check("5f. a lifetime beside a whole secret record is refused " +
        "STS-REG-0360", function () {
    assert.strictEqual(whole.out.status, 400, whole.out.raw.slice(0, 300));
    assert.ok(whole.recorded && leftWhole === null);
  });
  await ok(API + "/config/reset", { key: "oauth2.clientSecretLifetimeDays" },
           "reset the default lifetime");
  log.debug("Leaving secrets().");
}

function carries(value, secret) {
  log.debug("Entering carries().");
  log.debug("Leaving carries().");
  return JSON.stringify(value).indexOf(secret) >= 0;
}

async function reveal() {
  log.debug("Entering reveal().");
  log.info("=== F. reveal-secret (application_reveal_secret.js) ===");
  const ID = TAG + "-rv";
  const SECRET = "reveal-" + STAMP + "-" + String(Date.now()).slice(-6);
  await ok(API + "/applications/create", { identifier: ID,
    protocols: ["oauth2"], "field.oauthClientId": ID,
    "field.oauthClientSecret": SECRET }, "created");
  const id = (await detail(ID)).credentials.clientSecret.secrets[0].id;
  const shown = await ok(API + "/applications/reveal-secret",
                         { application: ID, secret: id }, "revealed");
  check("1a. a client secret is revealed by its id", function () {
    assert.strictEqual(shown.value, SECRET);
    assert.strictEqual(shown.secret, id);
  });
  const refusals = [
    ["2a. an application with no registration access token has none to " +
     "reveal", { application: ID, secret: "registration-access-token" }],
    ["2b. an id the application does not hold is refused",
     { application: ID, secret: "cs-not-there" }],
    ["2c. so is an application nobody recorded",
     { application: ID + "-nobody", secret: id }]];
  for (const one of refusals) {
    const r = await recordsCode("STS-ADMIN-0842", function () {
      return act("reveal-secret", one[1]);
    });
    check(one[0] + ", STS-ADMIN-0842", function () {
      assert.strictEqual(r.out.status, 400, r.out.raw.slice(0, 300));
      assert.ok(r.recorded, "no STS-ADMIN-0842 row");
      assert.ok(!carries(r.out.body, SECRET));
    });
  }
  const rows = await send(API + "/audit?per=50&action=" +
                          "application.secret-revealed");
  const mine = ((rows.body && rows.body.events) || []).filter(function (r) {
    return r.target === ID;
  });
  check("3. the reveal is audited once, naming the secret's id and never " +
        "its value", function () {
    assert.strictEqual(mine.length, 1, JSON.stringify(mine));
    assert.ok(!carries(mine[0], SECRET) && carries(mine[0], id));
  });
  const answer = await detail(ID);
  const list = await send(API + "/applications?q=" + encodeURIComponent(ID));
  check("4. the application's GET answer, and the list's, carry no secret " +
        "value", function () {
    assert.ok(!carries(answer, SECRET));
    assert.ok(!carries(list.body, SECRET) &&
              list.body.applications.length === 1);
  });
  for (const page of ["applications", "directory"]) {
    const r = await send(API + "/ldap/" + page + "?q=" +
                         encodeURIComponent(ID));
    check("4c. nor does /admin-api/ldap/" + page + "'s", function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.ok(r.raw.indexOf(SECRET) < 0);
    });
  }
  const PERSON = (TAG + "-person").slice(0, 40);
  await ok(API + "/users/create", { username: PERSON, invent: false,
    attributes: { cn: "Reveal Person", sn: "Person" },
    credential: "password", password: "Reveal-Secret-" + STAMP + "!x" },
    "created a person with a password");
  const person = await send(API + "/users?user=" + encodeURIComponent(PERSON));
  check("5. a person's answer shows their password masked, never its hash",
        function () {
    const attrs = (person.body && person.body.ldap && person.body.ldap.entry &&
                   person.body.ldap.entry.attributes) || {};
    assert.deepStrictEqual(attrs.userPassword, ["(set — not returned)"]);
  });
  log.debug("Leaving reveal().");
}

async function fieldSearch() {
  log.debug("Entering fieldSearch().");
  log.info("=== G. the delegation lists' search " +
           "(application_field_search.js) ===");
  const ID = TAG + "-fs";
  const others = [];
  for (let i = 0; i < 7; i += 1) {
    others.push(ID + "-other-" + i);
  }
  const SECRET = "field-search-" + STAMP + "-secret";
  await ok(API + "/applications/create", { identifier: ID,
    protocols: ["oauth2"], "field.oauthClientId": ID,
    "field.oauthClientSecret": SECRET,
    "field.oauthGrantType": "client_credentials",
    "field.oauthAudience": "https://" + ID + ".example/api" }, "created");
  for (const one of others) {
    await ok(API + "/applications/create", { identifier: one,
      name: "Partner " + one }, "created " + one);
  }
  const SELF = /names this application itself/;
  const createSelf = await recordsCode("STS-REG-0335", function () {
    return act("create", { identifier: ID + "-new",
      "field.appAllowedToDelegateTo": ID + "-new" });
  });
  const leftNew = await detail(ID + "-new");
  check("1b. a create whose appAllowedToDelegateTo names itself is refused " +
        "STS-REG-0335, and nothing is created", function () {
    assert.ok(refusedWith(createSelf.out, SELF),
              createSelf.out.raw.slice(0, 300));
    assert.ok(createSelf.recorded && leftNew === null);
  });
  const byCid = await act("create", { identifier: ID + "-new2",
    protocols: ["oauth2"], "field.oauthClientId": ID + "-new2-cid",
    "field.appAllowedToActOnBehalfOf": ID + "-new2-cid" });
  check("1c. so is one naming a client_id the same create gives it",
        function () {
    assert.ok(refusedWith(byCid, /appAllowedToActOnBehalfOf.*itself/),
              byCid.raw.slice(0, 300));
  });
  const ways = ["by its identifier", "by its client_id", "by its audience"];
  const ownNames = [ID, ID, "https://" + ID + ".example/api"];
  for (const attribute of ["appAllowedToDelegateTo",
                           "appAllowedToActOnBehalfOf"]) {
    for (let n = 1; n < 3; n += 1) {
      const added = await act("add", { application: ID,
        attribute: attribute, value: ownNames[n] });
      check("1d. an add of " + attribute + " naming the application " +
            ways[n] + " is refused", function () {
        assert.ok(refusedWith(added, SELF), added.raw.slice(0, 300));
      });
    }
    const grid = await act("update-fields", { application: ID,
      present: attribute, ["field." + attribute + ".0"]: others[0],
      ["field." + attribute + ".1"]: ID });
    const held = values((await detail(ID)).fields[attribute]);
    check("1e. the grid's Save of " + attribute + " refuses the value " +
          "naming itself and writes the other application", function () {
      assert.ok(refusedWith(grid, SELF), grid.raw.slice(0, 300));
      assert.ok(held.indexOf(ID) < 0 && held.indexOf(others[0]) >= 0,
                JSON.stringify(held));
    });
  }

  const listed = function (query) {
    return send(API + "/applications?" + query);
  };
  const exclude = "&exclude=" + encodeURIComponent(ID) +
                  "&exclude=" + encodeURIComponent(others[0]);
  const first = (await listed("q=" + encodeURIComponent(ID.toUpperCase()) +
                              "&per=5&page=1" + exclude)).body;
  const ids = first.applications.map(function (one) {
    return one.identifier;
  });
  check("2a. q matches in any case, five to a page, with the application " +
        "itself and a held value left out BEFORE the paging", function () {
    assert.strictEqual(first.matched, 6, JSON.stringify(ids));
    assert.strictEqual(first.applications.length, 5);
    assert.strictEqual(first.pages, 2);
    assert.ok(ids.indexOf(ID) < 0 && ids.indexOf(others[0]) < 0);
  });
  const second = (await listed("q=" + encodeURIComponent(ID) +
                               "&per=5&page=2" + exclude)).body;
  check("2b. the second page holds the sixth, and no row of the first",
        function () {
    assert.strictEqual(second.page, 2);
    assert.strictEqual(second.applications.length, 1);
    assert.ok(ids.indexOf(second.applications[0].identifier) < 0);
  });
  const single = (await listed("q=" + encodeURIComponent(ID) +
    "&per=5&exclude=" + encodeURIComponent(ID))).body;
  check("2c. one exclude, and the answer says what it left out",
        function () {
    assert.strictEqual(single.matched, 7);
    assert.deepStrictEqual(single.filter.exclude, [ID]);
  });

  for (let i = 0; i < 6; i += 1) {
    await ok(API + "/groups/create", { group: ID + "-group-" + i },
             "created a group");
  }
  const all = (await send(API + "/groups?q=" + encodeURIComponent(ID))).body;
  const dns = all.groups.map(function (one) { return one.dn; });
  check("3a. the six groups are there", function () {
    assert.strictEqual(dns.length, 6, JSON.stringify(dns));
  });
  const odd = dns[0].toUpperCase().replace(/,/g, ", ");
  const page1 = (await send(API + "/groups?q=" +
    encodeURIComponent(ID.toUpperCase()) + "&per=5&page=1&exclude=" +
    encodeURIComponent(odd))).body;
  check("3b. groups match five to a page, a held DN left out however its " +
        "case and spacing are written", function () {
    const shown = page1.groups.map(function (one) { return one.dn; });
    assert.strictEqual(page1.matched, 5);
    assert.strictEqual(shown.length, 5);
    assert.strictEqual(page1.pages, 1);
    assert.ok(shown.indexOf(dns[0]) < 0);
  });
  const paged = (await send(API + "/groups?q=" + encodeURIComponent(ID) +
                            "&per=5&page=2")).body;
  check("3c. and page two of six holds one", function () {
    assert.strictEqual(paged.page, 2);
    assert.strictEqual(paged.groups.length, 1);
  });

  log.info("--- appMayAct (#461) ---");
  const ownDn = String((await detail(ID)).dn || "");
  const selfDn = await recordsCode("STS-REG-0335", function () {
    return act("set", { application: ID, attribute: "appMayAct",
                        value: ownDn.toUpperCase().replace(/,/g, ", ") });
  });
  check("5a. appMayAct naming the application's own entry is refused " +
        "STS-REG-0335, however the DN is written", function () {
    assert.ok(ownDn.length > 0);
    assert.ok(refusedWith(selfDn.out,
                          /appMayAct: .* is this application's own entry/),
              selfDn.out.raw.slice(0, 300));
    assert.ok(selfDn.recorded);
  });
  const container = ownDn.replace(/^[^,]*,/, "");
  const createDn = await act("create", { identifier: ID + "-ma",
    "field.appMayAct": "cn=" + ID + "-ma," + container });
  const leftMa = await detail(ID + "-ma");
  check("5b. so is a create naming the DN its entry is about to be given",
        function () {
    assert.ok(refusedWith(createDn, /own entry/), createDn.raw.slice(0, 300));
    assert.strictEqual(leftMa, null);
  });
  const PERSON = (ID + "-p").slice(0, 40);
  await ok(API + "/users/create", { username: PERSON, invent: false,
    attributes: { cn: "May Act", sn: "Act" } }, "created a person");
  const people = (await send(API + "/users?q=" + encodeURIComponent(PERSON) +
                             "&per=5")).body;
  const row = (people.users || []).filter(function (one) {
    return one.key === PERSON || one.name === PERSON;
  })[0] || {};
  const personDn = String(row.dn || "");
  check("5c. a users-list row carries its entry's DN", function () {
    assert.ok(/^uid=/i.test(personDn), JSON.stringify(row).slice(0, 300));
  });
  await ok(API + "/applications/set", { application: ID,
    attribute: "appMayAct", value: personDn }, "set appMayAct to a person");
  const personToken = await token(REALM, ID, SECRET);
  const personClaims = claimsOf(personToken.body &&
                                personToken.body.access_token);
  check("5d. appMayAct set to that DN is accepted, and may_act on the " +
        "client's token names the person by their urn:uuid subject",
        function () {
    assert.ok(personClaims.may_act &&
              /^urn:uuid:/.test(String(personClaims.may_act.sub)),
              JSON.stringify(personClaims.may_act));
  });
  const otherDn = String((((await listed("q=" + encodeURIComponent(
    others[1]) + "&per=5&exclude=" + encodeURIComponent(ID))).body
    .applications || [])[0] || {}).dn || "");
  await ok(API + "/applications/set", { application: ID,
    attribute: "appMayAct", value: otherDn }, "set appMayAct to an app");
  const appClaims = claimsOf((await token(REALM, ID, SECRET)).body
    .access_token);
  check("5e. an applications-list row's DN is accepted too, and may_act " +
        "names that application", function () {
    assert.ok(/^cn=/i.test(otherDn), otherDn);
    assert.strictEqual(appClaims.may_act && appClaims.may_act.sub,
                       others[1], JSON.stringify(appClaims.may_act));
  });
  log.debug("Leaving fieldSearch().");
}

function sorted(list) {
  log.debug("Entering sorted().");
  log.debug("Leaving sorted().");
  return [].concat(list || []).slice(0).sort();
}

async function flows() {
  log.debug("Entering flows().");
  log.info("=== H. the declared flow lists (flow_type_choices.js) ===");
  await ok(base + "/admin-api/realms/create", { id: FLOWS,
    domain: FLOWS + ".example.net", name: "Flow types " + STAMP },
    "created the realm " + FLOWS);
  const FAPI = base + "/realm/" + FLOWS + "/admin-api";
  for (const key of ["oauth2.jwtBearerGrant", "oauth2.saml2BearerGrant",
                     "oauth2.ciba", "oauth2.deviceAuthorization",
                     "uma.enabled"]) {
    await ok(FAPI + "/config/set", { key: key, value: "true" },
             "switched " + key + " on");
  }
  const form = (await send(FAPI + "/applications/new")).body;
  const grants = fieldOf(form.fields, "oauthGrantType");
  const responses = fieldOf(form.fields, "oauthResponseType");
  const meta = await send(base + "/realm/" + FLOWS +
                          "/.well-known/openid-configuration");
  check("A1/B1. oauthGrantType is a list from a closed set, and that set " +
        "is grant_types_supported with every switch on", function () {
    assert.ok(grants && grants.type === "array");
    assert.strictEqual(meta.status, 200);
    assert.deepStrictEqual(sorted(grants.choices),
                           sorted(meta.body.grant_types_supported));
  });
  check("A1/B2. oauthResponseType likewise, against " +
        "response_types_supported", function () {
    assert.ok(responses && responses.type === "array");
    assert.deepStrictEqual(sorted(responses.choices),
                           sorted(meta.body.response_types_supported));
  });
  check("B3. every response type choice is written with its words sorted",
        function () {
    responses.choices.forEach(function (one) {
      assert.strictEqual(one.split(" ").sort().join(" "), one);
    });
  });
  check("A2. the observed lists are no field of the grid", function () {
    assert.ok(!fieldOf(form.fields, "oauthGrantTypeObserved"));
    assert.ok(!fieldOf(form.fields, "oauthResponseTypeObserved"));
  });
  const WEB = TAG + "-ftweb";
  const WEB_SECRET = "flow-types-" + STAMP + "-secret";
  await ok(FAPI + "/applications/create", { identifier: WEB,
    protocols: ["oauth2", "oidc"], "field.oauthClientId": WEB,
    "field.oauthGrantType.0": "authorization_code",
    "field.oauthGrantType.1": "refresh_token",
    "field.oauthGrantType.2": "client_credentials",
    "field.oauthClientSecret": WEB_SECRET,
    "field.oauthResponseType.0": "id_token code",
    "field.oauthResponseType.1": "code" }, "created the client");
  const held = async function () {
    const r = await send(FAPI + "/applications?application=" +
                         encodeURIComponent(WEB));
    return values(r.body.fields.oauthResponseType);
  };
  const madeTypes = await held();
  check("C1. a create stores a response type with its words sorted",
        function () {
    assert.deepStrictEqual(sorted(madeTypes), ["code", "code id_token"]);
  });
  const flowAct = function (action, payload) {
    return post(FAPI + "/applications/" + action, payload);
  };
  const badCreate = await recordsCode("STS-REG-0203", function () {
    return flowAct("create", { identifier: WEB + "-bad",
      protocols: ["oauth2"],
      "field.oauthGrantType": "urn:example:not-a-grant" });
  }, FAPI);
  check("C2. a create naming a grant this service does not implement is " +
        "refused, STS-REG-0203", function () {
    assert.strictEqual(badCreate.out.status, 400,
                       badCreate.out.raw.slice(0, 300));
    assert.ok(badCreate.recorded);
  });
  const badAdd = await recordsCode("STS-REG-0203", function () {
    return flowAct("add", { application: WEB, attribute: "oauthGrantType",
                            value: "authorisation_code" });
  }, FAPI);
  const badType = await recordsCode("STS-REG-0203", function () {
    return flowAct("add", { application: WEB,
      attribute: "oauthResponseType", value: "code code_token" });
  }, FAPI);
  check("C3. an add outside either set is refused, STS-REG-0203",
        function () {
    assert.ok(badAdd.out.status === 400 && badAdd.recorded,
              badAdd.out.raw.slice(0, 300));
    assert.ok(badType.out.status === 400 && badType.recorded,
              badType.out.raw.slice(0, 300));
  });
  const add = await flowAct("add", { application: WEB,
    attribute: "oauthResponseType", value: "token  id_token code" });
  const afterAdd = await held();
  check("C4. an add stores its response type with its words sorted",
        function () {
    assert.strictEqual(add.status, 200, add.raw.slice(0, 300));
    assert.ok(afterAdd.indexOf("code id_token token") >= 0,
              JSON.stringify(afterAdd));
  });
  const remove = await flowAct("remove", { application: WEB,
    attribute: "oauthResponseType", value: "token code id_token" });
  const afterRemove = await held();
  check("C5. a remove in another word order still removes it", function () {
    assert.strictEqual(remove.status, 200, remove.raw.slice(0, 300));
    assert.ok(afterRemove.indexOf("code id_token token") < 0,
              JSON.stringify(afterRemove));
  });
  // H2. A set of `oauthScope` is refused by this API's schema, which does
  // not offer the attribute to a set at all; the add reaches the action and
  // is the door #708 closes (STS-REG-0361); a remove still works.
  const scopeSet = await flowAct("set", { application: WEB,
    attribute: "oauthScope", value: "email" });
  const scopeAdd = await recordsCode("STS-REG-0361", function () {
    return flowAct("add", { application: WEB, attribute: "oauthScope",
                            value: "email" });
  }, FAPI);
  const scopeRemove = await flowAct("remove", { application: WEB,
    attribute: "oauthScope", value: "email" });
  check("H2. oauthScope is refused at an add, STS-REG-0361, and at a set; " +
        "a remove still works", function () {
    assert.ok(refusedWith(scopeSet, /"oauthScope", which is not one of/),
              scopeSet.raw.slice(0, 300));
    assert.ok(refusedWith(scopeAdd.out, /cannot be added by hand/),
              scopeAdd.out.raw.slice(0, 300));
    assert.ok(scopeAdd.recorded, "no STS-REG-0361 row");
    assert.strictEqual(scopeRemove.status, 200,
                       scopeRemove.raw.slice(0, 300));
  });
  const got = await token(FLOWS, WEB, WEB_SECRET);
  const seen = (await send(FAPI + "/applications?application=" +
    encodeURIComponent(WEB))).body.page.config.observed || {};
  check("D1. a grant the client used is recorded as seen, on the page's " +
        "observed member, marked as on its declared list", function () {
    assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
    const rows = seen.oauthGrantTypeObserved || [];
    const hit = rows.filter(function (one) {
      return one.value === "client_credentials";
    })[0];
    assert.ok(hit && hit.declared === true, JSON.stringify(seen));
  });
  log.debug("Leaving flows().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Application fields " + STAMP },
    "created the realm " + REALM);
  const formReply = await send(API + "/applications/new");
  assert.strictEqual(formReply.status, 200, formReply.raw.slice(0, 300));
  const newForm = formReply.body;
  await cors(newForm);
  await description(newForm);
  await semantics(newForm);
  await primaryName(newForm);
  await secrets();
  await reveal();
  await fieldSearch();
  await flows();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN (#444 D12). tests/CLAUDE.md's *No job removes a realm*
// is the rule for a suite run, whose realms an operator reads afterwards;
// a run against a private probe sets STS_TEST_REMOVE_REALMS=1 so that the
// realms this job made do not fill a directory shared with other runs.
async function removeRealms(ids) {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of ids) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves the realm standing, which is what a
      // suite run does anyway; the job's verdict is already decided.
    }
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms([REALM, FLOWS]);
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
}

main();
