"use strict";
//
// File: sts_delegation_policy.js
//
// ---------------------------------------------------------------------------
// WHO MAY ACT FOR WHOM AT WS-TRUST AND THE TOKEN EXCHANGE (iya-sts #108,
// 2026-09-23).
//
// Until that day a WS-Trust requester that could authenticate got a token
// about anybody for any AppliesTo through <wst:OnBehalfOf> or <wst14:ActAs>,
// and any client could exchange any verified token (RFC 8693) for one about
// its subject addressed anywhere. Now `common/delegation_policy.ts` decides,
// from Kerberos's model on application entries — appAllowedToDelegateTo,
// appAllowedToActOnBehalfOf, appDelegationSubjectGroup,
// appTrustedToImpersonate — and the person's stsNotDelegated and stsMayAct.
// ENFORCED in product; in development the policy is asked and each act says
// what would have been refused. Asserted over HTTP in a throwaway realm left
// standing, in whichever mode the service is in:
//
//   1. WS-TRUST ActAs with no policy: product answers a SOAP Fault whose
//      Subcode is wst:RequestFailed (WS-Trust 1.4 section 11), development
//      issues; with appAllowedToDelegateTo set through /admin-api it is
//      issued and the act on /admin-api/delegation names the attribute.
//   2. OnBehalfOf (impersonation) needs appTrustedToImpersonate as well.
//   3. A PERSON requester — no application entry — is refused in product.
//   4. stsNotDelegated, set through POST /admin-api/users/set-not-delegated,
//      refuses a delegation of that person in product.
//   5. RFC 8693: an impersonation by a client without the flag is
//      invalid_request in product; with the attributes it is issued.
//   6. `act` NESTS across two exchanges (RFC 8693 section 4.1).
//   7. `may_act`: stsMayAct set through POST /admin-api/users/set-may-act puts
//      may_act on the token issued about the person; an exchange of it by
//      anybody else is invalid_request IN EVERY MODE, by the named party it is
//      issued.
//   8. A scope wider than the subject_token's is invalid_scope in product.
//   9. GET /admin-api/delegation/policy lists the pairs and the people, paged;
//      product's refusals are refused acts on /admin-api/delegation.
//
// OWNED HERE (local: true): the policy is this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_delegation_policy",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("delegpol").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const PASSWORD = "Dp!" + crypto.randomBytes(12).toString("base64url") + "9z";
const SECRET = "delegation-policy-" + crypto.randomBytes(8).toString("hex");
const ALICE = "dp-alice";
const CAROL = "dp-carol";
const ESB = "dp-esb";
const MID = "dp-mid";
const MID2 = "dp-mid2";
const BACK = "dp-back";
const TARGET = "https://dp-back.example";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
let PRODUCT = false;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setAttribute(identifier, attribute, mode, value) {
  log.debug("Entering setAttribute().");
  await ok(realmApi + "/applications/" + mode,
           { application: identifier, attribute: attribute, value: value },
           mode + " " + attribute + "=" + value + " on " + identifier);
  log.debug("Leaving setAttribute().");
}

// ---------------------------------------------------------------------------
// WS-TRUST
// ---------------------------------------------------------------------------
function usernameToken(user) {
  log.debug("Entering usernameToken().");
  log.debug("Leaving usernameToken().");
  return "<wsse:UsernameToken><wsse:Username>" + user +
    "</wsse:Username><wsse:Password>" + PASSWORD +
    "</wsse:Password></wsse:UsernameToken>";
}

function rst(security, inner, tokenType) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' + security +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
    'Issue</wst:RequestType>' +
    (tokenType ? '<wst:TokenType>' + tokenType + '</wst:TokenType>' : '') +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>' + TARGET + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' + (inner || '') +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

async function sts(body) {
  log.debug("Entering sts().");
  const r = await call("POST", realmBase + "/sts", body,
                       { "Content-Type": "application/soap+xml" });
  log.debug("Leaving sts(). " + r.status);
  return r;
}

function requestedToken(text) {
  log.debug("Entering requestedToken().");
  const m = /<wst:RequestedSecurityToken>([\s\S]*?)<\/wst:RequestedSecurityToken>/
    .exec(String(text));
  log.debug("Leaving requestedToken().");
  return m ? m[1] : "";
}

// A token this realm issued about Alice, for her own password.
async function alicesAssertion() {
  log.debug("Entering alicesAssertion().");
  const r = await sts(rst(usernameToken(ALICE)));
  assert.strictEqual(r.status, 200, "Alice's own assertion: " +
                     r.text.slice(0, 400));
  log.debug("Leaving alicesAssertion().");
  return requestedToken(r.text);
}

async function delegate(requester, element, subjectAssertion) {
  log.debug("Entering delegate().");
  const wrapped = element === "ActAs"
    ? '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/ws-trust/' +
      '200802">' + subjectAssertion + '</wst14:ActAs>'
    : '<wst:OnBehalfOf>' + subjectAssertion + '</wst:OnBehalfOf>';
  log.debug("Leaving delegate().");
  return sts(rst(usernameToken(requester), wrapped));
}

function refusedRequestFailed(r, code) {
  log.debug("Entering refusedRequestFailed().");
  assert.strictEqual(r.status, 500, r.text.slice(0, 400));
  assert.ok(/<soap:Subcode><soap:Value xmlns:wst="[^"]+">wst:RequestFailed</
              .test(r.text), "the fault's Subcode is wst:RequestFailed: " +
            r.text.slice(0, 600));
  log.debug("Leaving refusedRequestFailed(). " + code);
}

async function newestAct(type) {
  log.debug("Entering newestAct().");
  const r = await call("GET", realmApi + "/delegation?type=" + type);
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving newestAct().");
  return (r.json.acts || [])[0] || null;
}

async function wsTrust() {
  log.debug("Entering wsTrust().");
  log.info("=== 1-4. WS-Trust OnBehalfOf and ActAs ===");
  const assertion = await alicesAssertion();
  let r = await delegate(ESB, "ActAs", assertion);
  check("1a. ActAs with no policy is " + (PRODUCT
        ? "a wst:RequestFailed fault" : "issued in development"),
        function () {
          if (PRODUCT) {
            refusedRequestFailed(r, "STS-WSTRUST-0018");
          } else {
            assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          }
        });
  let act = await newestAct("wstrust-actas");
  check("1b. and the act says " + (PRODUCT ? "it was refused"
        : "it WOULD have been refused"), function () {
    assert.ok(act, "an act was recorded");
    if (PRODUCT) {
      assert.strictEqual(act.outcome, "refused", JSON.stringify(act));
    } else {
      assert.ok(/WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
                act.authorizedBy);
    }
  });
  await setAttribute(ESB, "appAllowedToDelegateTo", "add", BACK);
  r = await delegate(ESB, "ActAs", assertion);
  act = await newestAct("wstrust-actas");
  check("1c. with appAllowedToDelegateTo naming the target it is issued, " +
        "and the act names the attribute", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/appAllowedToDelegateTo/.test(act.authorizedBy),
              act.authorizedBy);
  });
  r = await delegate(ESB, "OnBehalfOf", assertion);
  check("2a. OnBehalfOf (impersonation) without appTrustedToImpersonate is " +
        (PRODUCT ? "refused" : "issued in development"), function () {
    if (PRODUCT) {
      refusedRequestFailed(r, "STS-WSTRUST-0018");
      assert.ok(/appTrustedToImpersonate/.test(r.text), r.text.slice(0, 500));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    }
  });
  await setAttribute(ESB, "appTrustedToImpersonate", "set", "TRUE");
  r = await delegate(ESB, "OnBehalfOf", assertion);
  check("2b. with it, it is issued", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await delegate(CAROL, "ActAs", assertion);
  check("3. a PERSON requester is " + (PRODUCT ? "refused, told only an " +
        "application may delegate" : "issued in development"), function () {
    if (PRODUCT) {
      refusedRequestFailed(r, "STS-WSTRUST-0019");
      assert.ok(/only an application/.test(r.text), r.text.slice(0, 500));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    }
  });
  await ok(realmApi + "/users/set-not-delegated",
           { user: ALICE, value: true }, "set stsNotDelegated on Alice");
  r = await delegate(ESB, "ActAs", assertion);
  check("4. stsNotDelegated on the subject is " + (PRODUCT ? "refused"
        : "issued in development"), function () {
    if (PRODUCT) {
      refusedRequestFailed(r, "STS-WSTRUST-0018");
      assert.ok(/stsNotDelegated/.test(r.text), r.text.slice(0, 500));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    }
  });
  await ok(realmApi + "/users/set-not-delegated",
           { user: ALICE, value: false }, "cleared stsNotDelegated");
  log.debug("Leaving wsTrust().");
}

// ---------------------------------------------------------------------------
// RFC 8693
// ---------------------------------------------------------------------------
function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || "").split(".")[1] || "";
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function token(form) {
  log.debug("Entering token().");
  const r = await call("POST", realmBase + "/oauth2/token",
    new URLSearchParams(form).toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving token(). " + r.status);
  return r;
}

async function exchange(client, subjectToken, subjectType, extra) {
  log.debug("Entering exchange().");
  log.debug("Leaving exchange().");
  return token(Object.assign({ grant_type: EXCHANGE, client_id: client,
    client_secret: SECRET, subject_token: subjectToken,
    subject_token_type: subjectType, audience: TARGET }, extra || {}));
}

async function tokenExchange() {
  log.debug("Entering tokenExchange().");
  log.info("=== 5-8. RFC 8693 token exchange ===");
  const jwt = requestedToken((await sts(rst(usernameToken(ALICE), "",
                                            JWT_TYPE))).text)
    .replace(/<[^>]+>/g, "").trim();
  assert.ok(jwt.split(".").length === 3, "a WS-Trust JWT for Alice: " +
            jwt.slice(0, 80));
  let r = await exchange(MID, jwt, JWT_TYPE, { scope: "api" });
  check("5a. an impersonation by a client without appTrustedToImpersonate " +
        "is " + (PRODUCT ? "invalid_request" : "issued in development"),
        function () {
          if (PRODUCT) {
            assert.strictEqual(r.status, 400, r.text.slice(0, 300));
            assert.strictEqual(r.json.error, "invalid_request", r.text);
          } else {
            assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          }
        });
  await setAttribute(MID, "appAllowedToDelegateTo", "add", BACK);
  await setAttribute(MID, "appTrustedToImpersonate", "set", "TRUE");
  r = await exchange(MID, jwt, JWT_TYPE, { scope: "api" });
  check("5b. with the flag and appAllowedToDelegateTo it is issued",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
        });
  const first = r.json.access_token;
  // 6. act nests: two delegations, each naming the client as the actor.
  const cc = await token({ grant_type: "client_credentials", client_id: MID,
                           client_secret: SECRET });
  assert.strictEqual(cc.status, 200, cc.text.slice(0, 300));
  const actor = cc.json.access_token;
  const hop1 = await exchange(MID, first, ACCESS, { actor_token: actor,
    actor_token_type: ACCESS, scope: "api" });
  const hop2 = await exchange(MID, hop1.json && hop1.json.access_token,
    ACCESS, { actor_token: actor, actor_token_type: ACCESS, scope: "api" });
  check("6. `act` NESTS: the second hop carries the first hop's actor " +
        "beneath its own (RFC 8693 section 4.1)", function () {
    assert.strictEqual(hop1.status, 200, hop1.text.slice(0, 300));
    assert.strictEqual(hop2.status, 200, hop2.text.slice(0, 300));
    const nested = claimsOf(hop2.json.access_token).act;
    assert.ok(nested && nested.act && nested.act.sub === nested.sub,
              JSON.stringify(nested));
  });
  // 7. may_act.
  const mid2 = await call("GET", realmApi + "/applications?application=" +
                          encodeURIComponent(MID2));
  assert.strictEqual(mid2.status, 200, mid2.text.slice(0, 300));
  const mid2Dn = (mid2.json.application || mid2.json).dn;
  await ok(realmApi + "/users/set-may-act",
           { user: ALICE, delegate: mid2Dn }, "named " + MID2 + " as " +
           "Alice's delegate");
  r = await exchange(MID, jwt, JWT_TYPE, { scope: "api" });
  const withMayAct = r.json && r.json.access_token;
  check("7a. the token issued about her now carries may_act naming " + MID2,
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.deepStrictEqual(claimsOf(withMayAct).may_act,
                                 { sub: MID2 });
        });
  r = await exchange(MID, withMayAct, ACCESS, { scope: "api" });
  check("7b. an exchange of it by anybody else is invalid_request, in " +
        "every mode", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_request", r.text);
    assert.ok(/may_act/.test(r.text), r.text);
  });
  r = await exchange(MID2, withMayAct, ACCESS, { scope: "api" });
  check("7c. and by the party it names it is issued — may_act stands in " +
        "for appTrustedToImpersonate", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  await ok(realmApi + "/users/set-may-act", { user: ALICE, delegate: "" },
           "cleared Alice's delegate");
  // 8. scope.
  r = await exchange(MID, first, ACCESS, { scope: "api openid" });
  check("8. a scope wider than the subject_token's is " + (PRODUCT
        ? "invalid_scope" : "issued in development"), function () {
    if (PRODUCT) {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.strictEqual(r.json.error, "invalid_scope", r.text);
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    }
  });
  log.debug("Leaving tokenExchange().");
}

async function policyResource() {
  log.debug("Entering policyResource().");
  log.info("=== 9. GET /admin-api/delegation/policy ===");
  let r = await call("GET", realmApi + "/delegation/policy?per=1");
  check("9a. the policy is listed, paged on its own parameters", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.enforced, PRODUCT, r.text.slice(0, 300));
    assert.strictEqual(r.json.pairs.length, 1, r.text.slice(0, 300));
    assert.ok(r.json.pairsPaging.pages >= 2, r.text.slice(0, 300));
  });
  r = await call("GET", realmApi + "/delegation/policy");
  check("9b. with the pair set through /admin-api", function () {
    assert.ok(r.json.pairs.some(function (one) {
      return one.intermediary === ESB && one.target === BACK;
    }), JSON.stringify(r.json.pairs));
  });
  if (PRODUCT) {
    r = await call("GET", realmApi + "/delegation?outcome=refused");
    check("9c. product's refusals are REFUSED acts on /admin-api/delegation",
          function () {
            assert.ok((r.json.acts || []).length >= 4,
                      JSON.stringify(r.json.byOutcome));
          });
  }
  log.debug("Leaving policyResource().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the delegation policy at " + realmBase);
  PRODUCT = await registry.isProduct(base);
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "Delegation policy" }, "created the realm");
  for (const who of [ALICE, CAROL, ESB]) {
    await ok(realmApi + "/users/create",
             { username: who, invent: false, credential: "password",
               password: PASSWORD,
               attributes: { cn: who, sn: who } }, "created " + who);
  }
  await ok(realmApi + "/applications/create",
           { identifier: BACK, protocols: ["oauth2", "wstrust"],
             fields: { oauthClientId: BACK, oauthAudience: [TARGET],
                       wstrustAppliesTo: [TARGET] } }, "the target");
  await ok(realmApi + "/applications/create",
           { identifier: ESB, protocols: ["wstrust"], fields: {} },
           "the WS-Trust intermediary's application entry");
  for (const client of [MID, MID2]) {
    await ok(realmApi + "/applications/create",
             { identifier: client, protocols: ["oauth2"],
               fields: { oauthClientId: [client], oauthClientSecret: SECRET,
                         oauthTokenEndpointAuthMethod: "client_secret_post",
                         oauthGrantType: ["client_credentials", EXCHANGE],
                         oauthAllowedScope: ["api", "openid"] } },
             "the client " + client);
  }
  await setAttribute(MID2, "appAllowedToDelegateTo", "add", BACK);
  await wsTrust();
  await tokenExchange();
  await policyResource();
  // Sixteen in every mode, and product's refused-acts check beside them.
  assert.ok(checks >= (PRODUCT ? 17 : 16), "only " + checks + " checks ran; " +
            "a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_delegation_policy")
  .description("Who may act for whom at WS-Trust OnBehalfOf / ActAs and the " +
    "RFC 8693 token exchange: the attribute policy, may_act, nested act, " +
    "scope, and the policy resource.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
