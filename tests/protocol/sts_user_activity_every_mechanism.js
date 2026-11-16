// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_user_activity_every_mechanism.js
//
// ---------------------------------------------------------------------------
// A PERSON'S PAGE SHOWS EVERY WAY THEY AUTHENTICATED, OVER THE WIRE.
//
// rcbj, 2026-11-16: on a product cluster with request workers, people who
// had authenticated many times with a TLS client certificate and with
// RFC 7523 had nothing under Sessions & tokens, and "these tabs have always
// been broken for some authentication types". `tests/user_activity_every_
// mechanism.js` holds the same contract in one process on the memory store;
// this job holds it where that cannot reach — the persisted, on-demand
// registers, a page answered by a different worker from the one that issued,
// and product mode.
//
// One fresh ordinary person per mechanism, signed in once through it, and
// then `GET /admin-api/users?user=` — the model Directory → Users → that
// person is drawn from — asked until it shows the sign-in (the registers are
// written behind the request, so a short wait is allowed, never a long one):
//
//   * AUTHENTICATIONS: `authenticationEvents` holds an accepted
//     `authentication` row;
//   * SESSIONS & TOKENS: the sign-on session the mechanism started
//     (`sessions`), the tokens it issued (`sessions[].tokens`,
//     `tokensWithNoSession`, `tokensOnEndedSessions`), and the assertions
//     it issued (`artifacts`), each where the mechanism produces one.
//
// In a DEVELOPMENT realm: the sign-in screen's password and a code flow,
// with its refresh; `GET /tls/sign-in` with an EST-enrolled certificate; the
// password grant; an RFC 7523 self-assertion on the person's own key pair;
// an RFC 8693 exchange of the person's own token;
// a WS-Trust UsernameToken; SAML 2.0, SAML 1.1 and WS-Federation browser
// sign-ins. In a PRODUCT realm, the two that product allows unchanged for an
// unregistered caller: the code flow and the RFC 7523 self-assertion.
//
// OWNED HERE (local: true): this repository's console model of a person.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const path = require("path");
const zlib = require("zlib");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const est = require("./est_client.js");
const K = require("./oauth_wire_kit.js").kit(
  "sts_user_activity_every_mechanism");
const log = K.log;

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const FLOOR = 40;
const PW = "Uam-" + nodeCrypto.randomBytes(15).toString("base64url");
const REDIRECT = "https://rp.uam.example.test/cb";
const SECRET = "uam-" + nodeCrypto.randomBytes(18).toString("hex");
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
// How long a page may take to show what was just done: the registers are
// written behind the request and read by whichever worker answers.
const SETTLE_MS = 15000;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// What the person's page shows, from the management API's user view.
function pageOf(json) {
  log.debug("Entering pageOf().");
  const j = json || {};
  const sessions = [].concat(j.sessions || []);
  const page = {
    events: [].concat(j.authenticationEvents || []).filter(function (e) {
      return e.action === "authentication";
    }).map(function (e) {
      return e.protocol + "/" + ((e.detail || {}).method || "");
    }),
    sessions: sessions.length,
    tokensOnSessions: sessions.reduce(function (n, s) {
      return n + [].concat(s.tokens || []).length;
    }, 0),
    tokensSessionless: [].concat(j.tokensWithNoSession || []).length,
    tokensEnded: [].concat(j.tokensOnEndedSessions || []).length,
    artifacts: [].concat(j.artifacts || []).length,
    registryTokens: (((j.user || {}).tokens) || {}).issued || 0,
    refused: [].concat(j.authenticationEvents || []).filter(function (e) {
      return e.action === "authentication.refused";
    }).length,
    withoutActivity: (j.authenticationsWithoutActivity || {}).total || 0
  };
  log.debug("Leaving pageOf().");
  return page;
}

// Whether a page shows everything `want` asks of it.
function shows(page, want) {
  log.debug("Entering shows().");
  const tokens = page.tokensOnSessions + page.tokensSessionless +
                 page.tokensEnded;
  if (want.refused) {
    log.debug("Leaving shows(). A refusal.");
    return page.refused >= 1;
  }
  const yes = page.events.length >= 1 &&
    (!want.withoutActivity || page.withoutActivity >= 1) &&
    (!want.session || page.sessions >= 1) &&
    (!want.tokens || tokens >= want.tokens) &&
    (!want.session || !want.tokens || page.tokensOnSessions >= want.tokens) &&
    (!want.artifacts || page.artifacts >= want.artifacts);
  log.debug("Leaving shows(). " + yes);
  return yes;
}

// The person's page, asked until it shows `want` or SETTLE_MS passes.
async function settled(realm, who, want) {
  log.debug("Entering settled(). " + who);
  const until = Date.now() + SETTLE_MS;
  let page = null;
  for (;;) {
    const r = await K.send(K.rb(realm) + "/admin-api/users?user=" +
                           encodeURIComponent(who));
    page = Object.assign(pageOf(r.json), { status: r.status });
    if (shows(page, want) || Date.now() > until) {
      break;
    }
    await K.sleep(500);
  }
  log.debug("Leaving settled().");
  return page;
}

// The checks for one mechanism's person.
async function expect(realm, mechanism, who, want) {
  log.debug("Entering expect(). " + mechanism);
  const page = await settled(realm, who, want);
  const said = JSON.stringify(page);
  const tokens = page.tokensOnSessions + page.tokensSessionless +
                 page.tokensEnded;
  if (want.refused) {
    check(realm + ": " + mechanism + ": the refused attempt is on the " +
          "Authentications tab", function () {
      assert.ok(page.refused >= 1, said);
    });
    log.debug("Leaving expect(). A refusal.");
    return;
  }
  if (want.withoutActivity) {
    check(realm + ": " + mechanism + ": Sessions & tokens says it made no " +
          "session and issued nothing", function () {
      assert.ok(page.withoutActivity >= 1, said);
    });
  }
  check(realm + ": " + mechanism + ": the Authentications tab lists the " +
        "sign-in", function () {
    assert.ok(page.events.length >= 1, said);
  });
  if (want.session) {
    check(realm + ": " + mechanism + ": Sessions & tokens lists the " +
          "sign-on session", function () {
      assert.ok(page.sessions >= 1, said);
    });
  }
  if (want.tokens) {
    check(realm + ": " + mechanism + ": Sessions & tokens lists the " +
          "token(s) issued", function () {
      assert.ok(tokens >= want.tokens, said);
    });
    if (want.session) {
      check(realm + ": " + mechanism + ": under the session they were " +
            "issued on", function () {
        assert.ok(page.tokensOnSessions >= want.tokens, said);
      });
    }
  }
  if (want.artifacts) {
    check(realm + ": " + mechanism + ": Sessions & tokens lists the " +
          "assertion(s) issued", function () {
      assert.ok(page.artifacts >= want.artifacts, said);
    });
  }
  log.debug("Leaving expect().");
}

async function person(realm, tag) {
  log.debug("Entering person(). " + tag);
  const who = "uam-" + tag + "-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
    invent: false, credential: "password", password: PW,
    attributes: { cn: who, givenName: who, sn: who,
                  mail: who + "@uam.example.test" } }, "created " + who);
  log.debug("Leaving person().");
  return who;
}

// `product`: no password grant, which RFC 9700 mode (implied by product)
// does not allow.
async function client(realm, product) {
  log.debug("Entering client().");
  const id = "uam-rp-" + K.STAMP;
  await K.app(realm, id, { oauthClientId: id, oauthClientSecret: SECRET,
    oauthRedirectUri: [REDIRECT],
    oauthGrantType: ["authorization_code", "refresh_token", JWT_BEARER,
                     "urn:ietf:params:oauth:grant-type:token-exchange"]
      .concat(product ? [] : ["password"]),
    oauthAllowedScope: ["openid", "offline_access"],
    oauthTokenEndpointAuthMethod: "client_secret_basic" });
  log.debug("Leaving client().");
  return id;
}

function token(realm, clientId, fields) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(realm) + "/oauth2/token", { form: fields,
    headers: { authorization: K.basic(clientId, SECRET) } });
}

// THE SIGN-IN SCREEN'S PASSWORD, through an OpenID Connect code flow, and
// the refresh of what it issued.
async function codeFlow(realm, clientId, who) {
  log.debug("Entering codeFlow().");
  const b = K.browser();
  const pk = K.pkce();
  const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: clientId, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid offline_access", state: "s",
      nonce: K.rand(8), code_challenge: pk.challenge,
      code_challenge_method: "S256" }).toString());
  const done = await K.signIn(realm, b, first, who, PW);
  const answer = K.answerAt(done, REDIRECT);
  const code = answer && answer.get("code");
  assert.ok(code, realm + ": the code flow for " + who + " answered " +
            done.status + " " + done.location + " " +
            String(done.text || "").slice(0, 300));
  const got = await token(realm, clientId, { grant_type: "authorization_code",
    code: code, redirect_uri: REDIRECT, code_verifier: pk.verifier });
  assert.strictEqual(got.status, 200, K.shown(got));
  if (got.json.refresh_token) {
    const refreshed = await token(realm, clientId, {
      grant_type: "refresh_token", refresh_token: got.json.refresh_token });
    assert.strictEqual(refreshed.status, 200, K.shown(refreshed));
  }
  log.debug("Leaving codeFlow().");
}

// RFC 7523: a key pair issued to the person, and a self-assertion with it.
async function jwtBearer(realm, clientId, who, stranger) {
  log.debug("Entering jwtBearer().");
  let pem = "";
  if (stranger) {
    // A key nobody registered: the grant is refused.
    pem = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ type: "pkcs8", format: "pem" });
  } else {
    const issued = await K.ok(K.rb(realm) + "/admin-api/pki/issue", {
      target: "person", purpose: "jwt", identifier: who,
      leafKeyAlg: "rsa-2048" }, "issued " + who + " a key pair");
    pem = String(issued.privateKeyPem || "");
    assert.ok(/PRIVATE KEY/.test(pem), "no private key in " +
              JSON.stringify(Object.keys(issued)));
  }
  const now = Math.floor(Date.now() / 1000);
  const head = K.b64u({ alg: "RS256", typ: "JWT" });
  const body = K.b64u({ iss: who, sub: who,
    aud: K.rb(realm) + "/oauth2/token", iat: now, exp: now + 120,
    jti: K.rand(16) });
  const sig = nodeCrypto.sign("sha256", Buffer.from(head + "." + body), pem)
    .toString("base64url");
  const got = await token(realm, clientId, { grant_type: JWT_BEARER,
    assertion: head + "." + body + "." + sig, scope: "openid" });
  assert.strictEqual(got.status, stranger ? 400 : 200, K.shown(got));
  log.debug("Leaving jwtBearer().");
}

// A `tls-client` certificate over EST with the person's password, and
// `GET /tls/sign-in` presenting it.
async function tlsSignIn(realm, who) {
  log.debug("Entering tlsSignIn().");
  const rb = K.rb(realm);
  const pair = await keys.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "CN=" + who,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem });
  const r = await est.send({ method: "POST",
    url: rb + "/.well-known/est/tls-client/simpleenroll",
    headers: { "Content-Type": "application/pkcs10" },
    body: est.requestBody(csr.der), basic: [who, PW] });
  assert.strictEqual(r.status, 200, "EST enrolment: " + r.status + " " +
                     String(r.body).slice(0, 200));
  const leaf = est.parseCertsOnly(est.base64Body(r.body)).certificates[0];
  const ca = await est.send({ method: "GET",
    url: rb + "/.well-known/est/tls-client/cacerts" });
  const chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
  const u = new URL(rb + "/tls/sign-in");
  const answer = await new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "GET", agent: false,
      headers: { accept: "application/json" },
      cert: leaf + chain.join(""), key: pair.privatePem }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on("error", reject);
    req.end();
  });
  assert.ok(/"signedIn":true/.test(answer.text), "GET /tls/sign-in: " +
            answer.status + " " + answer.text.slice(0, 300));
  log.debug("Leaving tlsSignIn().");
}

// A simple bind on the stack's LDAP port as the person's entry: answers the
// LDAP result code (0 for success).
async function ldapBind(realm, who, password) {
  log.debug("Entering ldapBind().");
  const r = await K.send(K.rb(realm) + "/admin-api/users?user=" +
                         encodeURIComponent(who));
  const dn = String((((r.json || {}).ldap || {}).entry || {}).dn || "");
  assert.ok(dn, "no DN for " + who + ": " + K.shown(r));
  const url = "ldap://" + new URL(K.base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  const code = await new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url, reconnect: false });
    client.on("error", function (e) {
      log.debug("Caught in ldapBind(): " + e.message);
      resolve(-1);
    });
    client.bind(dn, password, function (e) {
      client.unbind();
      resolve(e ? e.code : 0);
    });
  });
  log.debug("Leaving ldapBind(). " + code);
  return code;
}

// WS-Trust: an Issue on a UsernameToken.
async function wsTrust(realm, who) {
  log.debug("Entering wsTrust().");
  const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
  const envelope = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/" +
    "soap-envelope\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/" +
    "oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header>" +
    "<wsse:Security><wsse:UsernameToken><wsse:Username>" + who +
    "</wsse:Username><wsse:Password>" + PW + "</wsse:Password>" +
    "</wsse:UsernameToken></wsse:Security></s:Header><s:Body>" +
    "<wst:RequestSecurityToken xmlns:wst=\"" + WST + "\">" +
    "<wst:RequestType>" + WST + "/Issue</wst:RequestType>" +
    "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/" +
    "policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/" +
    "08/addressing\"><wsa:Address>https://rp.uam.example.test/ws" +
    "</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>" +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
  const r = await K.send(K.rb(realm) + "/sts", { raw: envelope,
    headers: { "Content-Type": "application/soap+xml" } });
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving wsTrust().");
}

// A browser sign-in through a protocol's own endpoint: the screen
// answered with the password, and the protocol's answer page returned.
async function browserSignIn(realm, who, start, marker) {
  log.debug("Entering browserSignIn().");
  const b = K.browser();
  const first = await b.go(K.rb(realm) + start);
  const done = await K.signIn(realm, b, first, who, PW);
  assert.ok(marker.test(String(done.text || "")), start.split("?")[0] +
            ": " + done.status + " " + done.location + " " +
            String(done.text || "").slice(0, 300));
  log.debug("Leaving browserSignIn().");
}

function saml2Start() {
  log.debug("Entering saml2Start().");
  const xml = "<samlp:AuthnRequest " +
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"_uam" + K.rand(8) + "\" Version=\"2.0\" IssueInstant=\"" +
    new Date().toISOString() + "\" " +
    "AssertionConsumerServiceURL=\"https://sp.uam.example.test/acs\">" +
    "<saml:Issuer>urn:uam:sp</saml:Issuer></samlp:AuthnRequest>";
  log.debug("Leaving saml2Start().");
  return "/saml2/sso?SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml)).toString("base64"));
}

async function developmentRealm() {
  log.debug("Entering developmentRealm().");
  const realm = await K.realm("uamdev");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Uam" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const clientId = await client(realm);

  let who = await person(realm, "pw");
  await codeFlow(realm, clientId, who);
  await expect(realm, "password screen + code flow", who,
               { session: true, tokens: 2 });

  who = await person(realm, "tls");
  await tlsSignIn(realm, who);
  await expect(realm, "GET /tls/sign-in", who, { session: true });

  who = await person(realm, "ropc");
  const ropc = await token(realm, clientId, { grant_type: "password",
    username: who, password: PW, scope: "openid" });
  assert.strictEqual(ropc.status, 200, K.shown(ropc));
  await expect(realm, "password grant", who, { tokens: 1 });

  who = await person(realm, "jwt");
  await jwtBearer(realm, clientId, who);
  await expect(realm, "RFC 7523 self-assertion", who, { tokens: 1 });

  who = await person(realm, "wst");
  await wsTrust(realm, who);
  await expect(realm, "WS-Trust UsernameToken", who, { artifacts: 1 });

  who = await person(realm, "saml2");
  await browserSignIn(realm, who, saml2Start(), /SAMLResponse/);
  await expect(realm, "SAML 2.0 Web Browser SSO", who,
               { session: true, artifacts: 1 });

  who = await person(realm, "saml11");
  await browserSignIn(realm, who, "/saml11/sso?providerId=" +
    encodeURIComponent("urn:uam:saml11") + "&shire=" +
    encodeURIComponent("https://rp11.uam.example.test/acs") + "&target=t",
    /SAMLResponse/);
  await expect(realm, "SAML 1.1 Browser/POST", who,
               { session: true, artifacts: 1 });

  who = await person(realm, "wsfed");
  await browserSignIn(realm, who, "/wsfed?wa=wsignin1.0&wtrealm=" +
    encodeURIComponent("urn:uam:wsfed") + "&wreply=" +
    encodeURIComponent("https://wsfed.uam.example.test/"), /wresult/);
  await expect(realm, "WS-Federation passive", who,
               { session: true, artifacts: 1 });

  // RFC 8693: the person's own access token exchanged for another, which
  // is on their page beside it.
  who = await person(realm, "exch");
  const subjectToken = await token(realm, clientId, { grant_type: "password",
    username: who, password: PW, scope: "openid" });
  assert.strictEqual(subjectToken.status, 200, K.shown(subjectToken));
  const held = await settled(realm, who, { tokens: 1 });
  const heldBefore = held.tokensOnSessions + held.tokensSessionless +
                     held.tokensEnded;
  const exchanged = await token(realm, clientId, {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: subjectToken.json.access_token,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token" });
  assert.strictEqual(exchanged.status, 200, K.shown(exchanged));
  await expect(realm, "token exchange (RFC 8693)", who,
               { tokens: heldBefore + 1 });

  who = await person(realm, "ldap");
  assert.strictEqual(await ldapBind(realm, who, PW), 0, "the LDAP bind");
  await expect(realm, "LDAP simple bind", who, { withoutActivity: true });

  // THE REFUSALS: the reserved password `invalid`, refused in every mode,
  // and an assertion signed with a key nobody registered.
  who = await person(realm, "rscreen");
  const b = K.browser();
  const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: clientId, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid", state: "s",
      nonce: K.rand(8) }).toString());
  await K.signIn(realm, b, first, who, "invalid");
  await expect(realm, "password screen (refused)", who, { refused: true });

  who = await person(realm, "rropc");
  await token(realm, clientId, { grant_type: "password", username: who,
    password: "invalid", scope: "openid" });
  await expect(realm, "password grant (refused)", who, { refused: true });

  who = await person(realm, "rjwt");
  await jwtBearer(realm, clientId, who, true);
  await expect(realm, "RFC 7523 (refused)", who, { refused: true });

  who = await person(realm, "rldap");
  assert.strictEqual(await ldapBind(realm, who, "invalid"), 49,
                     "the refused LDAP bind");
  await expect(realm, "LDAP simple bind (refused)", who, { refused: true });
  log.debug("Leaving developmentRealm().");
}

async function productRealm() {
  log.debug("Entering productRealm().");
  const realm = await K.realm("uamprod", "product");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Uam" },
             "built the CA");
  const clientId = await client(realm, true);

  let who = await person(realm, "pw");
  await codeFlow(realm, clientId, who);
  await expect(realm, "password screen + code flow", who,
               { session: true, tokens: 2 });

  who = await person(realm, "jwt");
  await jwtBearer(realm, clientId, who);
  await expect(realm, "RFC 7523 self-assertion", who, { tokens: 1 });

  // A wrong password at the sign-in screen (product verifies it; its
  // password grant is refused for being one, before anybody is named).
  who = await person(realm, "rscreen");
  const b = K.browser();
  const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: clientId, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid", state: "s",
      nonce: K.rand(8), code_challenge: K.pkce().challenge,
      code_challenge_method: "S256" }).toString());
  await K.signIn(realm, b, first, who, "wrong-" + PW);
  await expect(realm, "password screen (refused)", who, { refused: true });

  who = await person(realm, "rjwt");
  await jwtBearer(realm, clientId, who, true);
  await expect(realm, "RFC 7523 (refused)", who, { refused: true });
  log.debug("Leaving productRealm().");
}

async function test() {
  log.debug("Entering test().");
  await developmentRealm();
  await productRealm();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
