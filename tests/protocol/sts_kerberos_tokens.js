// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_tokens.js
//
// ---------------------------------------------------------------------------
// KERBEROS TOKENS IN WS-TRUST AND THE TOKEN EXCHANGE, OVER THE WIRE
// (iya-sts #658, 2026-11-03).
//
// The Web Services Security Kerberos Token Profile 1.1's AP-REQ, with
// tickets this job obtains from the service's KDC over TCP 88 with this
// suite's own client (`krb5_wire.js`), presented at POST /sts and POST
// /oauth2/token. It builds its OWN services and person through /admin-api,
// as `sts_kerberos_delegation.js` does, so it runs in either mode:
//
//   1. a person's AP-REQ for the service's own SPN (`krb5.servicePrincipal`)
//      as the WS-Trust requester's credential: a SAML 2.0 assertion about
//      them with the Kerberos class; the same AP-REQ again refused;
//   2. an S4U2Proxy ticket the front end obtained for them to the service's
//      SPN, inside ActAs beside the front end's own: an assertion naming
//      the front end as a delegate; the same from another service refused;
//   3. wst:TokenType asking for a GSS Kerberos token for the back end
//      (wstrust.issueKerberos turned on for the job, and reset after): its
//      ticket opens with the back end's keytab key and names the person,
//      the proof token is the Authenticator's subkey;
//   4. RFC 8693: the S4U2Proxy ticket as a subject_token, exchanged for an
//      access token with the front end in `act`, and — with
//      oauth2.tokenExchangeKerberosOutput on — for a Kerberos token for the
//      back end naming the front end in S4U_DELEGATION_INFO.
//
// WHAT IT CHANGES: two services, a person and the service SPN's
// application entry (created if absent), and the two output settings, each
// reset in a `finally`. Nothing is loosened.
// WHERE IT DIALS: the KDC at the service URL's host and `krb5.kdcPort`, or
// STS_KDC_HOST / STS_KDC_PORT (sts_kerberos_spnego.js's convention).
// OWNED HERE (local: true): this repository's WS-Trust, token endpoint and
// KDC.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");
const { declineToRun } = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_tokens",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";
const msgs = wire.msgs;
const kcrypto = wire.kcrypto;
const SUFFIX = crypto.randomBytes(3).toString("hex");
const PERSON = usernameFor("kt-person");
const PASSWORD = "Kt!" + crypto.randomBytes(12).toString("base64url") + "7x";
const KEYTAB_PASSWORD = "Kp!" + crypto.randomBytes(12).toString("base64url") +
                        "6w";
const BACK_URL = "https://kt-back-" + SUFFIX + ".example";
const CLIENT_ID = "kt-front-" + SUFFIX;
const CLIENT_SECRET = "kt-front-secret-" + crypto.randomBytes(16)
  .toString("hex");
const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const WST14 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
const WSSE = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-wssecurity-secext-1.0.xsd";
const GSS = "http://docs.oasis-open.org/wss/" +
  "oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const KEYS_WAIT_MS = 20000;
const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            transport: null, spn: "" };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, where, body) {
  log.debug("Entering call(). " + method + " " + where);
  const r = await fetch(api + where, { method: method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving call(). HTTP " + r.status);
  return { status: r.status, body: parsed, text: raw };
}

async function ok(where, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", where, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            what + ": " + r.status + " " + String(r.text).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function host(role) {
  log.debug("Entering host().");
  log.debug("Leaving host().");
  return "kt-" + role + "-" + SUFFIX + ".example.com";
}

function idOf(role) {
  log.debug("Entering idOf().");
  log.debug("Leaving idOf().");
  return "HTTP/" + host(role) + "@" + K.realm;
}

function keysOf(keytabB64) {
  log.debug("Entering keysOf().");
  const keys = {};
  wire.readKeytab(Buffer.from(String(keytabB64), "base64"))
    .forEach(function (one) {
      keys[one.etype] = one.key;
    });
  log.debug("Leaving keysOf().");
  return keys;
}

async function tgtWith(name, keys) {
  log.debug("Entering tgtWith(). " + name);
  const started = Date.now();
  let got = await wire.asExchange(K.transport, K.realm, name, { keys: keys });
  while (!got.tgt && Date.now() - started < KEYS_WAIT_MS) {
    await pause(500);
    got = await wire.asExchange(K.transport, K.realm, name, { keys: keys });
  }
  assert.ok(got.tgt, "a TGT for " + name + ": " +
            JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtWith().");
  return got.tgt;
}

function stsName() {
  log.debug("Entering stsName().");
  log.debug("Leaving stsName().");
  return { type: 3, name: K.spn.split("/") };
}

async function ticketTo(tgt, sname, opts) {
  log.debug("Entering ticketTo().");
  const r = await wire.tgsExchange(K.transport, tgt, sname, K.realm, opts);
  assert.ok(r.ok, "a ticket for " + sname.name.join("/") + ": " +
            String(r.error || ""));
  log.debug("Leaving ticketTo().");
  return r;
}

async function delegated(w) {
  log.debug("Entering delegated().");
  const self = await wire.tgsExchange(K.transport, w.tgts.front,
    w.tgts.front.client, K.realm, {
      padata: async function () {
        return [await wire.paForUser(w.tgts.front, PERSON, K.realm)];
      } });
  assert.ok(self.ok && self.flagNames.indexOf("forwardable") >= 0,
            "a forwardable S4U2Self ticket: " + String(self.error ||
                                                        self.flagNames));
  const proxy = await ticketTo(w.tgts.front, stsName(), {
    kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
    additionalTickets: [self.ticket] });
  log.debug("Leaving delegated().");
  return proxy;
}

function bst(bytes) {
  log.debug("Entering bst().");
  log.debug("Leaving bst().");
  return "<wsse:BinarySecurityToken xmlns:wsse=\"" + WSSE + "\" ValueType=\"" +
    GSS + "\">" + Buffer.from(bytes).toString("base64") +
    "</wsse:BinarySecurityToken>";
}

function rst(security, inner, tokenType) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
    "<s:Header><wsse:Security xmlns:wsse=\"" + WSSE + "\">" + security +
    "</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken " +
    "xmlns:wst=\"" + WST + "\"><wst:RequestType>" + WST + "/Issue" +
    "</wst:RequestType>" + (tokenType ? "<wst:TokenType>" + tokenType +
                            "</wst:TokenType>" : "") +
    "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/" +
    "policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/" +
    "08/addressing\"><wsa:Address>" + BACK_URL + "</wsa:Address>" +
    "</wsa:EndpointReference></wsp:AppliesTo>" + (inner || "") +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
}

async function postRst(xml) {
  log.debug("Entering postRst().");
  const r = await fetch(stsUrl, { method: "POST",
    headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
    body: xml });
  const text = await r.text();
  log.debug("Leaving postRst(). HTTP " + r.status);
  return { status: r.status, text: text };
}

function textOf(xml, local) {
  log.debug("Entering textOf().");
  const m = new RegExp("<(?:[A-Za-z0-9_]+:)?" + local + "(?:\\s[^>]*)?>" +
                       "([^<]*)</").exec(String(xml));
  log.debug("Leaving textOf().");
  return m ? m[1].trim() : "";
}

// Opens a GSS Kerberos token with the target's keys: the ticket, then the
// Authenticator under the ticket's session key, then the PAC's delegation
// info.
async function openToken(b64, keys) {
  log.debug("Entering openToken().");
  const bytes = Buffer.from(String(b64).replace(/-/g, "+").replace(/_/g, "/"),
                            "base64");
  // The InitialContextToken: [APPLICATION 0] { OID, TOK_ID, AP-REQ }.
  const read = wire.gss ? wire.gss.decodeInitialContextToken(bytes) : null;
  const apReqBytes = read ? read.inner : null;
  assert.ok(apReqBytes, "the token is a GSS InitialContextToken");
  const apReq = msgs.readApReq(apReqBytes);
  const etype = apReq.ticket.encPart.etype;
  const key = keys[etype];
  assert.ok(key, "the target's keytab holds a key of enctype " + etype);
  const part = msgs.readEncTicketPart(await kcrypto.etypeById(etype).decrypt(
    key, kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher));
  const authenticator = msgs.readAuthenticator(await kcrypto.etypeById(
    apReq.authenticator.etype).decrypt(part.key.key,
    kcrypto.KEY_USAGE.AP_REQ_AUTH, apReq.authenticator.cipher));
  log.debug("Leaving openToken().");
  return { part: part, authenticator: authenticator };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== set-up: two services, a person, the service SPN's entry ===");
  const keys = {};
  for (const role of ["front", "back", "other"]) {
    const made = await call("POST", "/kerberos/principals/create-service",
                            { spn: "HTTP/" + host(role) });
    assert.ok(made.status === 200 && made.body.keytab, "create-service " +
              role + ": " + String(made.text).slice(0, 300));
    keys[role] = keysOf(made.body.keytab);
  }
  const stsId = K.spn + "@" + K.realm;
  // The service SPN's application entry: a registered target the front
  // end's S4U2Proxy may name. Created when absent; an existing one is used.
  const sts = await call("POST", "/applications/create", {
    identifier: stsId, protocols: ["krb5"] });
  log.info("the service SPN's entry: HTTP " + sts.status);
  const set = async function (application, attribute, mode, value) {
    log.debug("Entering set().");
    await ok("/applications/" + mode, { application: application,
             attribute: attribute, value: value },
             mode + " " + attribute + " on " + application);
    log.debug("Leaving set().");
  };
  await set(idOf("front"), "appAllowedToDelegateTo", "add", stsId);
  await set(idOf("front"), "appAllowedToDelegateTo", "add", idOf("back"));
  await set(idOf("other"), "appAllowedToDelegateTo", "add", stsId);
  await set(idOf("front"), "appDelegationSemantics", "add", "delegation");
  await set(idOf("front"), "appDelegationSemantics", "add", "impersonation");
  await set(idOf("other"), "appDelegationSemantics", "add", "impersonation");
  await set(idOf("back"), "wstrustAppliesTo", "add", BACK_URL);
  await set(idOf("back"), "oauthAudience", "add", BACK_URL);
  await set(idOf("front"), "oauthClientId", "add", CLIENT_ID);
  await set(idOf("front"), "oauthClientSecret", "set", CLIENT_SECRET);
  await set(idOf("front"), "oauthTokenEndpointAuthMethod", "add",
            "client_secret_post");
  await set(idOf("front"), "oauthGrantType", "add", EXCHANGE);
  await ok("/users/create", { username: PERSON, invent: false,
                              credential: "password", password: PASSWORD,
                              attributes: { cn: PERSON, givenName: "KT",
                                            sn: PERSON,
                                            mail: PERSON + "@kt.test" } },
           "created " + PERSON);
  const keytab = await call("POST", "/kerberos/principals/reset-person-keytab",
    { username: PERSON, password: KEYTAB_PASSWORD });
  assert.ok(keytab.status === 200 && keytab.body.keytab,
            "a keytab for the person: " + String(keytab.text).slice(0, 300));
  const tgts = {
    front: await tgtWith("HTTP/" + host("front"), keys.front),
    other: await tgtWith("HTTP/" + host("other"), keys.other),
    person: await tgtWith(PERSON, keysOf(keytab.body.keytab))
  };
  log.debug("Leaving setUp().");
  return { keys: keys, tgts: tgts };
}

async function requesterSection(w) {
  log.debug("Entering requesterSection().");
  log.info("=== 1. the requester's Kerberos token ===");
  const built = await wire.apRequest(await ticketTo(w.tgts.person,
                                                    stsName()));
  let r = await postRst(rst(bst(built.token)));
  check("1a. a person's AP-REQ for " + K.spn + " is an assertion about them " +
        "with the Kerberos class", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    assert.strictEqual(textOf(r.text, "NameID"), PERSON);
    assert.strictEqual(textOf(r.text, "AuthnContextClassRef"),
                       "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos");
  });
  r = await postRst(rst(bst(built.token)));
  check("1b. the same AP-REQ again is refused: a replay", function () {
    assert.strictEqual(r.status, 500, r.text.slice(0, 300));
    assert.ok(/FailedAuthentication/.test(r.text), r.text.slice(0, 300));
  });
  log.debug("Leaving requesterSection().");
}

async function delegatedSection(w) {
  log.debug("Entering delegatedSection().");
  log.info("=== 2. a delegated Kerberos ticket inside ActAs ===");
  const proxy = await delegated(w);
  const frontCredential = async function (tgt) {
    log.debug("Entering frontCredential().");
    const built = await wire.apRequest(await ticketTo(tgt, stsName()));
    log.debug("Leaving frontCredential().");
    return bst(built.token);
  };
  let r = await postRst(rst(await frontCredential(w.tgts.front),
    "<wst14:ActAs xmlns:wst14=\"" + WST14 + "\">" +
    bst((await wire.apRequest(proxy)).token) + "</wst14:ActAs>"));
  check("2a. an S4U2Proxy ticket inside ActAs, from the front end that " +
        "obtained it, is an assertion about the person naming the front " +
        "end as a delegate", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    assert.strictEqual(textOf(r.text, "NameID"), PERSON);
    assert.strictEqual(textOf(r.text, "Delegate"), idOf("front"));
  });
  r = await postRst(rst(await frontCredential(w.tgts.other),
    "<wst14:ActAs xmlns:wst14=\"" + WST14 + "\">" +
    bst((await wire.apRequest(proxy)).token) + "</wst14:ActAs>"));
  check("2b. the same ticket from another service is refused", function () {
    assert.strictEqual(r.status, 500, r.text.slice(0, 300));
    assert.ok(/InvalidRequest/.test(r.text), r.text.slice(0, 300));
  });
  log.debug("Leaving delegatedSection().");
}

async function issuedSection(w) {
  log.debug("Entering issuedSection().");
  log.info("=== 3. a Kerberos token issued ===");
  await ok("/config/set", { key: "wstrust.issueKerberos", value: true },
           "turned wstrust.issueKerberos on");
  try {
    const ut = "<wsse:UsernameToken><wsse:Username>" + PERSON +
      "</wsse:Username><wsse:Password>" + KEYTAB_PASSWORD +
      "</wsse:Password></wsse:UsernameToken>";
    const r = await postRst(rst(ut, "", GSS));
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    const opened = await openToken(textOf(r.text, "BinarySecurityToken"),
                                   w.keys.back);
    check("3a. wst:TokenType GSS: the back end's key opens the ticket, " +
          "which names the person; the proof token is the subkey",
          function () {
      assert.strictEqual(opened.part.cname.name.join("/"), PERSON);
      assert.ok(opened.authenticator.subkey, "the Authenticator has a subkey");
      assert.strictEqual(textOf(r.text, "BinarySecret"),
        Buffer.from(opened.authenticator.subkey.key).toString("base64"));
    });
  } finally {
    await call("POST", "/config/reset", { key: "wstrust.issueKerberos" });
  }
  log.debug("Leaving issuedSection().");
}

async function exchange(form) {
  log.debug("Entering exchange().");
  const r = await fetch(base + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(Object.assign({ grant_type: EXCHANGE,
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      audience: BACK_URL }, form)).toString() });
  const text = await r.text();
  let json = {};
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in exchange(): " + ((e && e.message) || e));
    json = { text: text };
  }
  log.debug("Leaving exchange(). HTTP " + r.status);
  return { status: r.status, json: json };
}

async function exchangeSection(w) {
  log.debug("Entering exchangeSection().");
  log.info("=== 4. RFC 8693 ===");
  let proxy = await delegated(w);
  let x = await exchange({
    subject_token: Buffer.from((await wire.apRequest(proxy)).token)
      .toString("base64url"),
    subject_token_type: GSS });
  check("4a. an S4U2Proxy subject_token is exchanged for an access token " +
        "with the front end in act", function () {
    assert.strictEqual(x.status, 200, JSON.stringify(x.json));
    const claims = JSON.parse(Buffer.from(String(x.json.access_token)
      .split(".")[1], "base64url").toString("utf8"));
    assert.ok(claims.act && String(claims.act.sub).indexOf(CLIENT_ID) >= 0,
              JSON.stringify(claims.act));
  });
  await ok("/config/set", { key: "oauth2.tokenExchangeKerberosOutput",
                            value: true },
           "turned oauth2.tokenExchangeKerberosOutput on");
  try {
    proxy = await delegated(w);
    x = await exchange({
      subject_token: Buffer.from((await wire.apRequest(proxy)).token)
        .toString("base64url"),
      subject_token_type: GSS, requested_token_type: GSS });
    assert.strictEqual(x.status, 200, JSON.stringify(x.json));
    const opened = await openToken(x.json.access_token, w.keys.back);
    check("4b. requested_token_type GSS: a Kerberos token for the back end, " +
          "issued_token_type the URI, token_type N_A, and a session key",
          function () {
      assert.strictEqual(x.json.issued_token_type, GSS);
      assert.strictEqual(x.json.token_type, "N_A");
      assert.ok(x.json.session_key, "a session_key");
      assert.strictEqual(opened.part.cname.name.join("/"), PERSON);
    });
  } finally {
    await call("POST", "/config/reset",
               { key: "oauth2.tokenExchangeKerberosOutput" });
  }
  log.debug("Leaving exchangeSection().");
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  K.product = await facts.isProduct(api);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(api, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  K.spn = String(await facts.setting(api, "krb5.servicePrincipal") || "");
  K.transport = wire.tcpTransport(K.kdcHost, K.kdcPort);
  assert.ok(K.realm && K.spn, "the service reports no krb5.realm or " +
            "krb5.servicePrincipal");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort + ", SPN " +
           K.spn);
  const w = await setUp();
  await requesterSection(w);
  await delegatedSection(w);
  await issuedSection(w);
  await exchangeSection(w);
  assert.ok(checks >= 8, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_tokens")
  .description("Kerberos tokens in WS-Trust and the RFC 8693 token " +
    "exchange, with tickets from the KDC over TCP 88 (#658).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
