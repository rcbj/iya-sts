// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// ---------------------------------------------------------------------------
// tests/protocol/sts_outside_values.js
//
// WHAT SOMEBODY OUTSIDE THIS SERVICE WRITES DOES NOT TAKE A PAGE DOWN (#1353).
//
// Every answer of the published APIs is held to a closed model, and one that
// does not match is a 500 rather than an answer. So a value written outside the
// service, kept, and shown later under a model can break an administrator's
// page, and one row can break a whole list. An audit on 2026-11-06 reproduced
// each case here over HTTP; this job is that reproduction, kept. Each runs in a
// throwaway realm of its own: a person, a forged presentation, an unverified
// token, a partner's document, an LDAP write, then the page that shows it.
//
// **THE ASSERTION IS THE PAGE, NOT THE WRITE**, which is why this runs in every
// mode. Product refuses the unverified token and an unbound LDAP write, and the
// page must stand either way. A write development accepts is said in the log.
// And #1354: a federation act's answer names no credential.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const zlib = require("zlib");
const ldap = require("ldapjs");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const PORTAL_SIGNIN = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_outside_values",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const root = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 10);
const PASSWORD = "0utside-Values-" + TAG;
let checks = 0;

function b64(value) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function hop(method, url, json) {
  log.debug("Entering hop(). " + method + " " + url);
  const headers = { accept: "application/json" };
  let body;
  if (json !== undefined) {
    body = JSON.stringify(json);
    headers["content-type"] = "application/json";
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const text = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    // Not JSON: a redirect's empty body, or a page.
    parsed = null;
  }
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, json: parsed, text: text,
           location: r.headers.get("location") || "" };
}

async function postForm(url, fields) {
  log.debug("Entering postForm().");
  const r = await fetch(url, { method: "POST",
    body: new URLSearchParams(fields),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
  const text = await r.text();
  log.debug("Leaving postForm(). " + r.status);
  return { status: r.status, text: text };
}

function stands(what, answer) {
  log.debug("Entering stands().");
  check(what + " still answers", function () {
    assert.strictEqual(answer.status, 200, answer.text.slice(0, 300));
    assert.ok(answer.json, "and in JSON: " + answer.text.slice(0, 200));
  });
  log.debug("Leaving stands().");
}

async function makeRealm(key) {
  log.debug("Entering makeRealm(). " + key);
  const id = ("ov-" + key + "-" + TAG).slice(0, 31).replace(/-+$/, "");
  const made = await hop("POST", root + "/admin-api/realms/create",
                         { id: id, domain: id + ".example.net",
                           name: "Outside values " + key });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  log.debug("Leaving makeRealm().");
  return { id: id, base: root + "/realm/" + id,
           api: root + "/realm/" + id + "/admin-api",
           dc: "dc=" + id + ",dc=example,dc=net" };
}

async function makePerson(realm, username) {
  log.debug("Entering makePerson(). " + username);
  const made = await hop("POST", realm.api + "/users/create", {
    username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "O " + username, givenName: "O", sn: username,
                  mail: username + "@outside.test" } });
  assert.ok(made.status === 200 && made.json.ok, made.text.slice(0, 300));
  log.debug("Leaving makePerson().");
  return "uid=" + username + ",ou=users," + realm.dc;
}

function ldapUrl() {
  log.debug("Entering ldapUrl().");
  log.debug("Leaving ldapUrl().");
  return process.env.STS_LDAP_URL ||
    "ldap://" + new URL(root).hostname + ":389";
}

// One LDAP act with no bind, whose answer is the point in development and a
// refusal in product. Answers whether it was accepted.
function ldapAct(act) {
  log.debug("Entering ldapAct().");
  return new Promise(function (resolve) {
    const client = ldap.createClient({ url: ldapUrl(), connectTimeout: 10000,
                                       timeout: 10000 });
    const finish = function (e) {
      if (e) {
        log.info("  the LDAP write was refused: " + ((e && e.message) || e));
      }
      client.destroy();
      log.debug("Leaving ldapAct(). " + !e);
      resolve(!e);
    };
    client.on("error", finish);
    client.on("connectError", finish);
    client.on("connectTimeout", finish);
    act(client, finish);
  });
}

function ldapReplace(dn, attributes) {
  log.debug("Entering ldapReplace(). " + dn);
  log.debug("Leaving ldapReplace().");
  return ldapAct(function (client, finish) {
    client.modify(dn, Object.keys(attributes).map(function (name) {
      return new ldap.Change({ operation: "replace", modification:
        new ldap.Attribute({ type: name, values: [attributes[name]] }) });
    }), finish);
  });
}

async function aDelegate() {
  log.info("=== 1. a person names a delegate: no bad input at all ===");
  const realm = await makeRealm("dlg");
  await makePerson(realm, "ovalice");
  const bob = await makePerson(realm, "ovbob");
  const portal = await PORTAL_SIGNIN.signInToThePortal(realm.base, "ovalice",
    null, { password: PASSWORD });
  const named = await portal.api("POST", "/account-api/delegate",
                                 { delegate: bob });
  assert.strictEqual(named.status, 200, JSON.stringify(named.json));
  const detail = await hop("GET", realm.api + "/users?user=ovalice");
  stands("the administrator's page for that person", detail);
  check("and it says who the delegate is", function () {
    assert.strictEqual(detail.json.page.delegation.delegate.dn, bob);
    assert.ok(/^urn:uuid:/.test(detail.json.page.delegation.delegate.sub));
  });
}

async function aTrustAnchor() {
  log.info("=== 2. a Trust Anchor is added, and that is answered ===");
  const realm = await makeRealm("anc");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
                            { kid: "k1" });
  const added = await hop("POST", realm.api + "/oidfed/add-trust-anchor",
    { entityId: "https://anchor.example",
      jwks: JSON.stringify({ keys: [jwk] }) });
  stands("adding it", added);
  check("and the answer says so", function () {
    assert.strictEqual(added.json.ok, true);
  });
}

async function aForgedPresentation() {
  log.info("=== 3. a forged presentation, refused, with its verdict kept ===");
  const realm = await makeRealm("vp");
  const started = await hop("POST", realm.api + "/verifications/start",
                            { by: "reference", format: "dc+sd-jwt" });
  assert.strictEqual(started.status, 200, started.text.slice(0, 300));
  const requestUri = new URL(started.json.walletUrl).searchParams
    .get("request_uri");
  const jwt = (await hop("GET", requestUri)).text;
  const ro = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
  const disclosure = b64(["s", { k: 1 }, 1]);
  const token = b64({ typ: "dc+sd-jwt", alg: "ES256" }) + "." +
    b64({ sub: { a: 1 }, vct: { b: 2 }, _sd_alg: "sha-256",
          _sd: [crypto.createHash("sha256").update(disclosure)
            .digest("base64url")] }) + ".x~" + disclosure + "~kb";
  const vpToken = {};
  vpToken[ro.dcql_query.credentials[0].id] = [token];
  const sent = await postForm(realm.base + "/oid4vp/response",
    { state: ro.state, vp_token: JSON.stringify(vpToken) });
  check("the presentation is refused", function () {
    assert.strictEqual(sent.status, 400, sent.text.slice(0, 200));
  });
  const detail = await hop("GET", realm.api + "/verifications?state=" +
                                  encodeURIComponent(ro.state));
  stands("that verification's detail", detail);
  check("and what it shows is text, or nothing", function () {
    assert.strictEqual(detail.json.verdict.sub, "");
    assert.strictEqual(detail.json.verdict.vct, "");
    assert.deepStrictEqual(detail.json.verdict.disclosed, []);
  });
  stands("the list", await hop("GET", realm.api + "/verifications"));
}

async function anUnverifiedToken() {
  log.info("=== 4. an unverified token's sub, at the token exchange ===");
  const cases = [["obj", { sub: { a: 1 } }],
                 ["num", { sub: 42, username: "ovalice" }]];
  for (const [key, claims] of cases) {
    const realm = await makeRealm("x" + key);
    await makePerson(realm, "ovalice");
    const r = await postForm(realm.base + "/oauth2/token", {
      client_id: "ov-nobody",
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      subject_token: b64({ alg: "none" }) + "." + b64(claims) + ".x" });
    log.info("  the exchange answered " + r.status);
    if (r.status === 200) {
      const minted = JSON.parse(Buffer.from(
        JSON.parse(r.text).access_token.split(".")[1], "base64url").toString());
      check("no token is minted about that sub", function () {
        assert.ok(minted.sub === undefined || typeof minted.sub === "string",
                  JSON.stringify(minted.sub));
      });
    }
    stands("the users list", await hop("GET", realm.api + "/users"));
    stands("the tokens page", await hop("GET", realm.api + "/tokens"));
    stands("the person's page",
           await hop("GET", realm.api + "/users?user=ovalice"));
  }
}

async function aDeviceKey() {
  log.info("=== 5. a device key's JWK, written by the person proving it ===");
  const realm = await makeRealm("dev");
  await makePerson(realm, "ovalice");
  const portal = await PORTAL_SIGNIN.signInToThePortal(realm.base, "ovalice",
    null, { password: PASSWORD });
  const issued = await portal.api("POST", "/account-api/devices/challenge",
                                  { purpose: "key" });
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
                            { note: { a: 1 } });
  const input = b64({ alg: "ES256", typ: "device-key-proof+jwt", jwk: jwk }) +
    "." + b64({ nonce: issued.json.challenge, aud: issued.json.audience,
                iat: Math.floor(Date.now() / 1000) });
  const signature = crypto.sign("sha256", Buffer.from(input),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
  const proved = await portal.api("POST", "/account-api/devices/proof", {
    challenge: issued.json.challenge, label: "Outside", platform: "android",
    proof: input + "." + signature.toString("base64url") });
  log.info("  the proof answered " + proved.status);
  const list = await hop("GET", realm.api + "/devices");
  stands("the realm's device list", list);
  if (proved.status === 201) {
    check("the key is kept, without what no JWK member is", function () {
      const kept = list.json.devices[0].keys[0].material.jwk;
      assert.strictEqual(kept.kty, "EC");
      assert.strictEqual(kept.note, undefined);
    });
  }
}

async function aHeldTrustMark() {
  log.info("=== 6. a held Trust Mark whose exp no date can hold ===");
  const realm = await makeRealm("mark");
  const before = await hop("GET", realm.api + "/oidfed");
  const mark = function (exp) {
    return b64({ typ: "trust-mark+jwt", alg: "ES256" }) + "." +
      b64({ iss: "https://tmi.example", sub: before.json.entityId, exp: exp,
            trust_mark_type: "https://t.example/x" }) + ".x";
  };
  const huge = await hop("POST", realm.api + "/oidfed/add-held-mark",
                         { trustMark: mark(10000000000000) });
  check("it is refused", function () {
    assert.strictEqual(huge.status, 400, huge.text.slice(0, 200));
  });
  const sane = await hop("POST", realm.api + "/oidfed/add-held-mark",
    { trustMark: mark(Math.floor(Date.now() / 1000) + 3600) });
  stands("one with a real exp", sane);
  const view = await hop("GET", realm.api + "/oidfed");
  stands("the realm's OpenID Federation page", view);
  check("and lists the one it took", function () {
    assert.strictEqual(view.json.heldMarks.length, 1);
    assert.ok(view.json.heldMarks[0].expiresAt);
  });
}

async function aSamlCacheDuration() {
  log.info("=== 7. a service provider's cacheDuration no date can hold ===");
  const realm = await makeRealm("saml");
  const sp = "https://sp-" + TAG + ".example/saml";
  const made = await hop("POST", realm.api + "/applications/create", {
    identifier: sp, name: "Outside SP", protocols: ["saml2"],
    fields: { samlEntityId: [sp] } });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const document = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:' +
    '2.0:metadata" entityID="' + sp + '" cacheDuration="P300000Y">' +
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:' +
    '2.0:protocol"><md:AssertionConsumerService index="0" isDefault="true" ' +
    'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ' +
    'Location="https://sp.example/acs"/></md:SPSSODescriptor>' +
    '</md:EntityDescriptor>';
  const up = await hop("POST", realm.api + "/saml2/upload-metadata",
                       { sp: sp, document: document });
  assert.strictEqual(up.status, 200, up.text.slice(0, 300));
  stands("the service provider's page",
         await hop("GET", realm.api + "/saml2?sp=" + encodeURIComponent(sp)));
  const request = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:' +
    '2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_' +
    crypto.randomBytes(8).toString("hex") + '" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>' + sp +
    '</saml:Issuer></samlp:AuthnRequest>';
  const signIn = await fetch(realm.base + "/saml2/sso?SAMLRequest=" +
    encodeURIComponent(zlib.deflateRawSync(Buffer.from(request))
      .toString("base64")), { redirect: "manual" });
  // A 500 is the failure: freshness() threw. What else it answers is the mode's:
  // development goes on to the screen, and product refuses this unsigned
  // request (STS-SAML-0063), a check that runs after freshness() has been read.
  check("and its sign-in does not fail on that duration: " + signIn.status,
        function () {
          assert.ok(signIn.status === 303 || signIn.status === 403,
                    "answered " + signIn.status);
        });
}

async function ldapWrites() {
  log.info("=== 8. what an LDAP client writes ===");
  const sources = await makeRealm("lsrc");
  const added = await ldapAct(function (client, finish) {
    client.add("cn=x,ou=attributesources," + sources.dc,
      { objectClass: ["top", "stsAttributeSource"], cn: "x",
        stsAttributeSourceData: JSON.stringify({ rogue: 1, port: "x" }) },
      finish);
  });
  const list = await hop("GET", sources.api + "/attribute-sources");
  stands("the attribute sources", list);
  if (added) {
    check("an extra member and a wrong type are not read", function () {
      assert.strictEqual(list.json.sources[0].rogue, undefined);
      assert.strictEqual(list.json.sources[0].port, undefined);
    });
  }
  const claim = await makeRealm("lclm");
  const claimant = await makePerson(claim, "ovalice");
  await ldapReplace(claimant, { stsClaimSourceTokens:
    JSON.stringify({ p: { sub: 5, linked_at: "x" }, q: null }) });
  stands("the Claims Providers", await hop("GET",
                                           claim.api + "/claim-providers"));
  const facts = await makeRealm("lfct");
  const person = await makePerson(facts, "ovalice");
  await ldapReplace(person, { stsIdaVerification: JSON.stringify(
    [{ verification: {}, claims: {}, rogue: 1, id: 5 }]) });
  await ldapReplace(person, { stsPasswordResetToken: "x",
                              stsPasswordResetExpires: "abc" });
  stands("that person's page", await hop("GET",
                                         facts.api + "/users?user=ovalice"));
  const rotation = await makeRealm("lrot");
  const owner = await makePerson(rotation, "ovowner");
  const account = await hop("POST", rotation.api + "/users/create", {
    username: "ovsvc", invent: false, serviceAccount: true, owners: [owner],
    attributes: { cn: "svc", sn: "svc" } });
  // Product holds a new account to its own rules: the list is still the point.
  log.info("  creating the service account answered " + account.status);
  await ldapReplace("uid=ovsvc,ou=users," + rotation.dc,
                    { stsRotationFailures: "Infinity" });
  await ldapReplace("uid=ovsvc,ou=users," + rotation.dc,
                    { stsRotationLastAttempt: "1e300" });
  stands("the service accounts", await hop("GET",
                                           rotation.api + "/service-accounts"));
}

async function aFederationAnswer() {
  log.info("=== 9. a federation act's answer names no credential (#1354) ===");
  const realm = await makeRealm("fed");
  const id = "ov-partner";
  const secret = "ov-secret-" + TAG;
  const made = await hop("POST", realm.api + "/federation/create",
    { id: id, role: "service-provider", protocol: "oidc",
      peer: "https://partner.example" });
  assert.ok(made.status === 200 && made.json.ok, made.text.slice(0, 300));
  const set = await hop("POST", realm.api + "/federation/set",
                        { id: id, field: "fedClientSecret", value: secret });
  stands("setting the secret", set);
  check("the answer does not say it", function () {
    assert.ok(set.text.indexOf(secret) < 0, "the secret was answered");
    assert.strictEqual(set.json.relationship.fedClientSecret, undefined);
    assert.strictEqual(set.json.relationship.entry, undefined);
  });
  const enable = await hop("POST", realm.api + "/federation/enable",
                           { id: id });
  check("nor does a later act's", function () {
    assert.ok(enable.text.indexOf(secret) < 0, "the secret was answered");
  });
}

async function aNamedServersMetadata() {
  log.info("=== 10. a named server's metadata member that is an object ===");
  const realm = await makeRealm("ns");
  const aliases = { token_endpoint: "https://mtls.example/token" };
  const made = await hop("POST", realm.api + "/authorization-servers/create",
                         { id: "ov-server", label: "Outside server" });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const set = await hop("POST", realm.api + "/authorization-servers/set",
    { profile: "ov-server", member: "mtls_endpoint_aliases",
      value: JSON.stringify(aliases) });
  stands("setting it", set);
  const page = await hop("GET", realm.api + "/sts-metadata");
  stands("the metadata page", page);
  check("and it is shown as it was set", function () {
    const server = page.json.namedServers.filter(function (one) {
      return one.id === "ov-server";
    })[0];
    assert.deepStrictEqual(server.overrides.mtls_endpoint_aliases, aliases);
  });
}

async function test() {
  log.debug("Entering test().");
  await aDelegate();
  await aTrustAnchor();
  await aForgedPresentation();
  await anUnverifiedToken();
  await aDeviceKey();
  await aHeldTrustMark();
  await aSamlCacheDuration();
  await ldapWrites();
  await aFederationAnswer();
  await aNamedServersMetadata();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .description("What somebody outside this service writes does not take an " +
    "administrator's page down (#1353), and a federation act's answer names " +
    "no credential (#1354).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
