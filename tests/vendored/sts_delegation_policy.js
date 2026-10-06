// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_delegation_policy.js
//
// ---------------------------------------------------------------------------
// WHO MAY ACT FOR WHOM, AND AS WHAT, OVER HTTP (iya-sts #108, #186).
//
// The issuance policy decides every act at WS-Trust OnBehalfOf / ActAs and
// the RFC 8693 token exchange, from facts `common/delegation_policy.ts`
// gathers off the entries: the actor (the requester, the client or the
// actor_token's subject), the subject, S (the application the subject's
// token was issued for — the delegated assertion's Audience, the
// subject_token's aud) and R (the AppliesTo, the audience). ENFORCED in
// product; development issues and the act says it WOULD have been refused.
// In a throwaway realm left standing, in whichever mode the service is in,
// EVERY OUTCOME AT BOTH DOORS:
//
//   W. WS-TRUST: ActAs (delegation) by S with no relationship, then with
//      appAllowedToDelegateTo; OnBehalfOf (impersonation) by an actor
//      allowing delegation only, then with appDelegationSemantics; a person
//      requester without and with delegation.actorRole; a protected subject;
//      an unregistered AppliesTo; no AppliesTo by an actor that is not S;
//      both elements in one request (refused in every mode).
//   O. RFC 8693: delegation by S, by R, by an actor R accepts, and by a
//      person through an actor_token without and with the role; no
//      relationship; impersonation refused and allowed (no `act`); an
//      unusable exchange_semantics (every mode); a protected subject; an
//      unregistered, two, or no audience; a self exchange; authority lost
//      since the subject token was issued; may_act (every mode); `act`
//      NESTING over two hops; a wider scope.
//   P. GET /admin-api/delegation/policy, paged, and product's refusals as
//      refused acts on /admin-api/delegation.
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
const BOB = "dp-bob";
const CAROL = "dp-carol";
// The WS-Trust requester: an application entry, and a person of the same
// name holding the password its UsernameToken carries.
const ESB = "dp-esb";
// Clients: S for most exchanges, S through R's acceptance, a stranger, an
// application requiring a role, and the end of a second hop.
const MID = "dp-mid";
const MID2 = "dp-mid2";
const OTHER = "dp-other";
const PAYROLL = "dp-payroll";
const FINAL = "dp-final";
// R, a client too so that it can be the actor.
const BACK = "dp-back";
const url = function (identifier) {
  log.debug("Entering url().");
  log.debug("Leaving url().");
  return "https://" + identifier + ".example";
};
const TARGET = url(BACK);
const NOWHERE = "https://nowhere.example";
const ACTOR_ROLE = "DELEGATION_ACTOR";
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

async function call(method, target, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(target, { method: method, redirect: "manual",
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

async function ok(target, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", target, body);
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

// The parties a SAML 2.0 assertion's Delegation Restriction names, in order.
function delegatesIn(xml) {
  log.debug("Entering delegatesIn().");
  const out = [];
  const re = /<del:Delegate[^>]*><saml:NameID[^>]*>([^<]+)<\/saml:NameID>/g;
  let m;
  while ((m = re.exec(String(xml))) !== null) {
    out.push(m[1]);
  }
  log.debug("Leaving delegatesIn().");
  return out;
}

async function newestAct(type) {
  log.debug("Entering newestAct().");
  const r = await call("GET", realmApi + "/delegation?type=" + type);
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving newestAct().");
  return (r.json.acts || [])[0] || null;
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

// An Issue whose security header carries `security`, for `appliesTo` ('' for
// none), its body carrying `inner`.
function rst(security, appliesTo, inner, tokenType) {
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
    (appliesTo ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/' +
      '2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/' +
      '2005/08/addressing"><wsa:Address>' + appliesTo + '</wsa:Address>' +
      '</wsa:EndpointReference></wsp:AppliesTo>' : '') + (inner || '') +
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

// A token this realm issued about `who` for `forApp` — S — on their own
// password: a SAML assertion, or a JWT for the token exchange.
async function tokenAbout(who, forApp, jwt) {
  log.debug("Entering tokenAbout().");
  const r = await sts(rst(usernameToken(who), url(forApp), "",
                          jwt ? JWT_TYPE : ""));
  assert.strictEqual(r.status, 200, who + "'s token for " + forApp + ": " +
                     r.text.slice(0, 400));
  const token = requestedToken(r.text);
  log.debug("Leaving tokenAbout().");
  return jwt ? token.replace(/<[^>]+>/g, "").trim() : token;
}

async function delegate(requester, element, assertion, appliesTo) {
  log.debug("Entering delegate().");
  const wrap = function (one) {
    log.debug("Entering wrap().");
    log.debug("Leaving wrap().");
    return one === "ActAs"
      ? '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
        'ws-trust/200802">' + assertion + '</wst14:ActAs>'
      : '<wst:OnBehalfOf>' + assertion + '</wst:OnBehalfOf>';
  };
  const inner = element === "both" ? wrap("ActAs") + wrap("OnBehalfOf")
                                   : wrap(element);
  log.debug("Leaving delegate().");
  return sts(rst(usernameToken(requester),
                 appliesTo === undefined ? TARGET : appliesTo, inner));
}

// A refusal as the mode speaks it at WS-Trust: product a SOAP Fault whose
// Subcode is `subcode` (WS-Trust 1.4 section 11); development issued, the
// act saying it WOULD have been refused.
async function wsRefused(r, type, subcode) {
  log.debug("Entering wsRefused().");
  if (PRODUCT) {
    assert.strictEqual(r.status, 500, r.text.slice(0, 400));
    assert.ok(new RegExp('<soap:Subcode><soap:Value xmlns:wst="[^"]+">' +
                         'wst:' + (subcode || "RequestFailed") + '<')
                .test(r.text), "the fault's Subcode: " + r.text.slice(0, 600));
    const act = await newestAct(type);
    assert.ok(act && act.outcome === "refused", JSON.stringify(act));
  } else {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    const act = await newestAct(type);
    assert.ok(act && /WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
              JSON.stringify(act && act.authorizedBy));
  }
  log.debug("Leaving wsRefused().");
}

const SAYS = function () {
  log.debug("Entering SAYS().");
  log.debug("Leaving SAYS().");
  return PRODUCT ? "refused" : "issued, the act saying it would have been " +
                               "refused";
};

async function wsTrust() {
  log.debug("Entering wsTrust().");
  log.info("=== W. WS-Trust OnBehalfOf and ActAs ===");
  const forEsb = await tokenAbout(ALICE, ESB);
  let r = await delegate(ESB, "ActAs", forEsb);
  await wsRefused(r, "wstrust-actas");
  check("W1. ActAs by S with no relationship to R is " + SAYS(),
        function () {});
  await setAttribute(ESB, "appAllowedToDelegateTo", "add", BACK);
  r = await delegate(ESB, "ActAs", forEsb);
  let act = await newestAct("wstrust-actas");
  const forBack = requestedToken(r.text);
  check("W2. with appAllowedToDelegateTo naming R it is issued, NAMES the " +
        "requester (SAML V2.0 Delegation Restriction), and the act says the " +
        "policy allowed a delegation", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(delegatesIn(forBack), [ESB], forBack);
    assert.ok(/issuance policy allowed delegation/.test(act.authorizedBy),
              act.authorizedBy);
  });
  // Two hops: R hands the ActAs token on to FINAL, and the chain grows.
  r = await delegate(BACK, "ActAs", forBack, url(FINAL));
  check("W11. an ActAs of an ActAs token keeps the chain: two delegates, " +
        "least to most recent", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(delegatesIn(requestedToken(r.text)), [ESB, BACK],
                           r.text.slice(0, 1600));
  });
  r = await delegate(ESB, "OnBehalfOf", forEsb);
  await wsRefused(r, "wstrust-onbehalfof");
  check("W3. OnBehalfOf (impersonation) by an actor allowing delegation " +
        "only is " + SAYS(), function () {});
  await setAttribute(ESB, "appDelegationSemantics", "add", "delegation");
  await setAttribute(ESB, "appDelegationSemantics", "add", "impersonation");
  r = await delegate(ESB, "OnBehalfOf", forEsb);
  act = await newestAct("wstrust-onbehalfof");
  check("W4. with appDelegationSemantics allowing it, it is issued",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.ok(/allowed impersonation/.test(act.authorizedBy),
                    act.authorizedBy);
        });
  r = await delegate(CAROL, "ActAs", forEsb);
  await wsRefused(r, "wstrust-actas");
  check("W5. a PERSON requester without " + ACTOR_ROLE + " is " + SAYS(),
        function () {});
  const forBob = await tokenAbout(BOB, ESB);
  await ok(realmApi + "/users/set-not-delegated", { user: BOB, value: true },
           "set stsNotDelegated on Bob");
  r = await delegate(ESB, "ActAs", forBob);
  await wsRefused(r, "wstrust-actas");
  check("W6. a subject carrying stsNotDelegated is " + SAYS(), function () {});
  r = await delegate(ESB, "ActAs", forEsb, NOWHERE);
  await wsRefused(r, "wstrust-actas");
  check("W7. an AppliesTo no application registers is " + SAYS(),
        function () {});
  const forMid = await tokenAbout(ALICE, MID);
  r = await delegate(ESB, "ActAs", forMid, "");
  await wsRefused(r, "wstrust-actas");
  check("W8. no AppliesTo, the requester not S, is " + SAYS(), function () {});
  r = await delegate(ESB, "both", forEsb);
  check("W9. ActAs and OnBehalfOf in one request: wst:InvalidRequest, in " +
        "every mode", function () {
    assert.strictEqual(r.status, 500, r.text.slice(0, 400));
    assert.ok(/InvalidRequest/.test(r.text), r.text.slice(0, 600));
  });
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
  // A value that is an array is sent as the parameter repeated.
  const params = new URLSearchParams();
  Object.keys(form).forEach(function (k) {
    [].concat(form[k]).forEach(function (v) {
      params.append(k, v);
    });
  });
  const r = await call("POST", realmBase + "/oauth2/token", params.toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving token(). " + r.status);
  return r;
}

// An exchange by `client` of `subjectToken` (a JWT this realm issued) for
// R unless `extra` says otherwise (`audience: null` sends none).
async function exchange(client, subjectToken, extra) {
  log.debug("Entering exchange().");
  const form = Object.assign({ grant_type: EXCHANGE, client_id: client,
    client_secret: SECRET, subject_token: subjectToken,
    subject_token_type: JWT_TYPE, audience: TARGET, scope: "api" },
  extra || {});
  Object.keys(form).forEach(function (k) {
    if (form[k] === null) {
      delete form[k];
    }
  });
  log.debug("Leaving exchange().");
  return token(form);
}

// A refusal as the mode speaks it at the token endpoint: product `error`;
// development issued, the act of `type` saying it WOULD have been refused.
async function oauthRefused(r, error, type) {
  log.debug("Entering oauthRefused().");
  if (PRODUCT) {
    assert.strictEqual(r.status, 400, r.text.slice(0, 400));
    assert.strictEqual(r.json.error, error, r.text.slice(0, 400));
    assert.ok(!r.json.access_token, "nothing was issued");
  } else {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    const act = await newestAct(type || "oauth-delegation");
    assert.ok(act && /WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
              JSON.stringify(act && act.authorizedBy));
  }
  log.debug("Leaving oauthRefused().");
}

async function tokenExchange() {
  log.debug("Entering tokenExchange().");
  log.info("=== O. RFC 8693 token exchange ===");
  // THE FORM A CLIENT IS NAMED BY AS AN ACTOR (#471): its own subject in the
  // realm's mode — `urn:sts:client:<id>` in RFC 9700 mode (which product
  // implies), the bare client_id otherwise — read off a client_credentials
  // token, whose `sub` is that subject. The exchanges below send no
  // actor_token, so the policy's delegation names the exchanging client;
  // until #471 it did so by the bare client_id in every mode.
  const cc = await token({ grant_type: "client_credentials", client_id: MID,
                           client_secret: SECRET, scope: "api" });
  assert.strictEqual(cc.status, 200, "a client_credentials token for " +
                     MID + ": " + cc.text.slice(0, 300));
  const namespaced = /^urn:sts:client:/.test(
    String(claimsOf(cc.json.access_token).sub || ""));
  assert.ok(!PRODUCT || namespaced, "a product realm names a client " +
            "urn:sts:client:<id>: " + claimsOf(cc.json.access_token).sub);
  const asActor = function (identifier) {
    log.debug("Entering asActor().");
    log.debug("Leaving asActor().");
    return namespaced ? "urn:sts:client:" + identifier : identifier;
  };
  const forMid = await tokenAbout(ALICE, MID, true);
  assert.ok(forMid.split(".").length === 3, "a JWT for Alice: " +
            forMid.slice(0, 80));
  let r = await exchange(MID, forMid);
  let claims = r.json && r.json.access_token
    ? claimsOf(r.json.access_token) : {};
  check("O1. DELEGATION by S to R it delegates to: issued, `act` naming S, " +
        "for R", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(claims.act && claims.act.sub, asActor(MID),
                       JSON.stringify(claims.act));
    assert.strictEqual(claims.act.iss, claims.iss, "the act entry names " +
                       "this issuer (#471): " + JSON.stringify(claims));
    assert.ok([].concat(claims.aud).indexOf(TARGET) >= 0,
              JSON.stringify(claims.aud));
  });
  r = await exchange(BACK, forMid);
  claims = r.json && r.json.access_token ? claimsOf(r.json.access_token) : {};
  check("O2. by R itself, holding the token S was handed: `act` naming R",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.strictEqual(claims.act && claims.act.sub, asActor(BACK),
                             JSON.stringify(claims.act));
        });
  const forMid2 = await tokenAbout(ALICE, MID2, true);
  r = await exchange(MID2, forMid2);
  check("O3. RESOURCE-BASED: R's appAllowedToActOnBehalfOf names S",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const forOther = await tokenAbout(ALICE, OTHER, true);
  r = await exchange(OTHER, forOther);
  await oauthRefused(r, "invalid_target");
  check("O4. no relationship between S and R is " + SAYS() +
        " (invalid_target)", function () {});
  r = await exchange(MID, forMid, { exchange_semantics: "impersonation" });
  await oauthRefused(r, "invalid_request", "oauth-impersonation");
  check("O5. exchange_semantics=impersonation by an actor allowing " +
        "delegation only is " + SAYS() + " (invalid_request)", function () {});
  r = await exchange(MID2, forMid2, { exchange_semantics: "impersonation" });
  claims = r.json && r.json.access_token ? claimsOf(r.json.access_token) : {};
  check("O6. by an actor allowing it, R accepting it: issued, no `act`",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.ok(!claims.act, JSON.stringify(claims.act));
        });
  r = await exchange(MID, forMid, { exchange_semantics: "sideways" });
  check("O7. an exchange_semantics that is neither: invalid_request in " +
        "every mode", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_request", r.text);
  });
  const bobForMid = await tokenAbout(BOB, MID, true);
  r = await exchange(MID, bobForMid);
  await oauthRefused(r, "invalid_request");
  check("O8. a subject carrying stsNotDelegated is " + SAYS() +
        " (invalid_request)", function () {});
  r = await exchange(MID, forMid, { audience: NOWHERE });
  await oauthRefused(r, "invalid_target");
  check("O9. an audience no application registers is " + SAYS() +
        " (invalid_target)", function () {});
  r = await exchange(MID, forMid, { audience: [TARGET, url(FINAL)] });
  check("O10. two audiences: invalid_target in every mode (product's " +
        "policy, and RFC 9068 section 3 in development)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_target", r.text);
  });
  r = await exchange(BACK, forMid, { audience: null });
  await oauthRefused(r, "invalid_target");
  check("O11. no audience by an actor that is not S is " + SAYS() +
        " (invalid_target)", function () {});
  r = await exchange(MID, forMid, { audience: null });
  claims = r.json && r.json.access_token ? claimsOf(r.json.access_token) : {};
  check("O12. S itself with no audience: a SELF exchange, for S, no `act`",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.ok(!claims.act, JSON.stringify(claims.act));
          assert.ok([].concat(claims.aud).indexOf(url(MID)) >= 0,
                    JSON.stringify(claims.aud));
        });
  // Authority lost since the subject token was issued. The CLIENT is R
  // (BACK), which requires nothing: were it S, the token endpoint's own role
  // gate would refuse first (access_denied) and the policy's authority rule
  // would never be reached. S is PAYROLL, which delegates to R.
  const forPayroll = await tokenAbout(ALICE, PAYROLL, true);
  await setAttribute(PAYROLL, "appRequiredRole", "add", "dp-payroll-staff");
  r = await exchange(BACK, forPayroll);
  await oauthRefused(r, "invalid_request");
  check("O13. a subject holding none of the roles S now requires is " +
        SAYS() + " (invalid_request)", function () {});
  // A person acting, through an actor_token.
  const carolsToken = await tokenAbout(CAROL, OTHER, true);
  r = await exchange(OTHER, forMid, { actor_token: carolsToken,
                                      actor_token_type: JWT_TYPE });
  await oauthRefused(r, "invalid_request");
  check("O14. a PERSON actor (actor_token) R accepts, without " +
        ACTOR_ROLE + ", is " + SAYS() + " (invalid_request)", function () {});
  // may_act.
  const mid2 = await call("GET", realmApi + "/applications?application=" +
                          encodeURIComponent(MID2));
  assert.strictEqual(mid2.status, 200, mid2.text.slice(0, 300));
  const mid2Dn = (mid2.json.application || mid2.json).dn;
  await ok(realmApi + "/users/set-may-act", { user: ALICE, delegate: mid2Dn },
           "named " + MID2 + " as Alice's delegate");
  r = await exchange(MID, forMid);
  const withMayAct = r.json && r.json.access_token;
  check("O15. stsMayAct puts may_act naming " + MID2 + " on the token issued " +
        "about her", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(claimsOf(withMayAct).may_act, { sub: MID2 });
  });
  r = await exchange(MID, withMayAct, { subject_token_type: ACCESS });
  check("O16. an exchange of a token whose may_act names somebody else: " +
        "invalid_request in every mode", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_request", r.text);
    assert.ok(/may_act/.test(r.text), r.text);
  });
  await ok(realmApi + "/users/set-may-act", { user: ALICE, delegate: "" },
           "cleared Alice's delegate");
  // act nests: S hands to R, R hands on to FINAL.
  r = await exchange(MID, forMid);
  const hop1 = r.json && r.json.access_token;
  r = await exchange(BACK, hop1, { subject_token_type: ACCESS,
                                   audience: url(FINAL) });
  claims = r.json && r.json.access_token ? claimsOf(r.json.access_token) : {};
  check("O17. `act` NESTS: R's act outermost, S's beneath it (RFC 8693 " +
        "section 4.1)", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(claims.act && claims.act.sub === asActor(BACK) &&
              claims.act.act && claims.act.act.sub === asActor(MID) &&
              claims.act.iss === claims.iss &&
              claims.act.act.iss === claims.iss, JSON.stringify(claims));
  });
  // A subject token CARRYING a scope (the first hop, scope `api`): a WS-Trust
  // JWT carries none, so there is nothing to compare and nothing is refused.
  r = await exchange(BACK, hop1, { subject_token_type: ACCESS,
                                   audience: url(FINAL),
                                   scope: "api openid" });
  check("O18. a scope wider than the subject_token's is " + (PRODUCT
        ? "invalid_scope" : "issued in development"), function () {
    if (PRODUCT) {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.strictEqual(r.json.error, "invalid_scope", r.text);
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    }
  });
  log.debug("Leaving tokenExchange().");
  return { forMid: forMid, carolsToken: carolsToken };
}

// The role turns both person cases round.
async function actorRole(kept) {
  log.debug("Entering actorRole().");
  log.info("=== W and O: a person holding " + ACTOR_ROLE + " ===");
  await ok(realmApi + "/roles/create-role", { role: ACTOR_ROLE },
           "created " + ACTOR_ROLE);
  await ok(realmApi + "/roles/add-member",
           { role: ACTOR_ROLE, kind: "user", member: CAROL },
           "gave " + CAROL + " " + ACTOR_ROLE);
  const forEsb = await tokenAbout(ALICE, ESB);
  let r = await delegate(CAROL, "ActAs", forEsb);
  check("W10. a PERSON requester holding " + ACTOR_ROLE + " whom R accepts: " +
        "issued", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await exchange(OTHER, kept.forMid, { actor_token: kept.carolsToken,
                                           actor_token_type: JWT_TYPE });
  const claims = r.json && r.json.access_token
    ? claimsOf(r.json.access_token) : {};
  check("O19. and through an actor_token: issued, `act` naming her",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.strictEqual(claims.act && claims.act.sub,
                             claimsOf(kept.carolsToken).sub,
                             JSON.stringify(claims.act));
        });
  log.debug("Leaving actorRole().");
}

async function policyResource() {
  log.debug("Entering policyResource().");
  log.info("=== P. GET /admin-api/delegation/policy ===");
  let r = await call("GET", realmApi + "/delegation/policy?per=1");
  check("P1. the policy is listed, paged on its own parameters", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.enforced, PRODUCT, r.text.slice(0, 300));
    assert.strictEqual(r.json.pairs.length, 1, r.text.slice(0, 300));
    assert.ok(r.json.pairsPaging.pages >= 2, r.text.slice(0, 300));
  });
  r = await call("GET", realmApi + "/delegation/policy");
  check("P2. with the pairs set through /admin-api, and the semantics",
        function () {
          assert.ok(r.json.pairs.some(function (one) {
            return one.intermediary === ESB && one.target === BACK;
          }), JSON.stringify(r.json.pairs));
          assert.ok(r.json.intermediaries.some(function (one) {
            return one.application === ESB &&
                   one.semantics.indexOf("impersonation") >= 0;
          }), JSON.stringify(r.json.intermediaries));
        });
  if (PRODUCT) {
    r = await call("GET", realmApi + "/delegation?outcome=refused");
    check("P3. product's refusals are REFUSED acts on /admin-api/delegation",
          function () {
            // `matched`, not the page: the list is paged.
            assert.ok(Number(r.json.matched) >= 12,
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
  // ESB and BACK are WS-Trust requesters too: a person entry of the same
  // name holds the password their UsernameToken carries.
  for (const who of [ALICE, BOB, CAROL, ESB, BACK]) {
    await ok(realmApi + "/users/create",
             { username: who, invent: false, credential: "password",
               password: PASSWORD,
               attributes: { cn: who, sn: who } }, "created " + who);
  }
  // Every application is a WS-Trust relying party (its URL its AppliesTo,
  // so a token about somebody can be issued FOR it) and a confidential
  // OAuth client declaring OIDC too (an `openid` scope is an OIDC issuance).
  const app = async function (identifier, fields) {
    log.debug("Entering app().");
    await ok(realmApi + "/applications/create",
             { identifier: identifier,
               protocols: ["oauth2", "oidc", "wstrust"],
               fields: Object.assign({ oauthClientId: [identifier],
                 oauthClientSecret: SECRET,
                 oauthTokenEndpointAuthMethod: "client_secret_post",
                 oauthGrantType: ["client_credentials", EXCHANGE],
                 oauthAllowedScope: ["api", "openid"],
                 oauthAudience: [url(identifier)],
                 wstrustAppliesTo: [url(identifier)] }, fields || {}) },
             "the application " + identifier);
    log.debug("Leaving app().");
  };
  await app(BACK, { appAllowedToActOnBehalfOf: [MID2, CAROL],
                    appAllowedToDelegateTo: [FINAL] });
  await app(ESB);
  await app(MID, { appAllowedToDelegateTo: [BACK] });
  await app(MID2, { appDelegationSemantics: ["delegation", "impersonation"] });
  await app(OTHER);
  await app(PAYROLL, { appAllowedToDelegateTo: [BACK] });
  await app(FINAL);
  await wsTrust();
  const kept = await tokenExchange();
  await actorRole(kept);
  await policyResource();
  const expected = (PRODUCT ? 3 : 2) + 11 + 19;
  assert.ok(checks >= expected, "only " + checks + " of " + expected +
            " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_delegation_policy")
  .description("Who may act for whom, and as what, at WS-Trust OnBehalfOf / " +
    "ActAs and the RFC 8693 token exchange: every outcome of the issuance " +
    "policy at both doors, may_act, nested act, scope, the policy resource.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
