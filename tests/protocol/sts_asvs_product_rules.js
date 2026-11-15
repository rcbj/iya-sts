// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_asvs_product_rules.js
//
// ---------------------------------------------------------------------------
// WHAT PRODUCT MODE LIMITS FOR ASVS 5.0.0, AND A REFUSAL THAT LEAVES NOTHING
// BEHIND, OVER THE WIRE.
//
// D12 (#444): carries the parts a client can see of
// `tests/asvs_product_limits.js` (#1453–#1496), `tests/asvs_protocol_rules.js`
// and `tests/asvs_all_or_nothing.js`,
// in a development realm and a product realm of this job's own, every
// opt-out written on the REALM through `/admin-api/realms/set`:
//
//   A. ALL OR NOTHING: an application create whose SAML metadata is refused
//      is refused and leaves no application; a person's save refused in part
//      (an unknown country) is refused, says nothing was saved, and the
//      field it would have changed is unchanged.
//   B. GRANTS AND RESPONSE TYPES (#1453, #1479): in product a client that
//      declares none is held to the code flow — client_credentials refused
//      for declaring no grant_types, refresh_token and the code past that
//      check, id_token and `code id_token` refused unauthorized_client at the
//      authorization endpoint while `code` is not — and
//      `oauth2.allowUndeclaredGrants` lifts both; development is unchanged.
//   C. SCEP answers 503 in product, sending no code, until
//      `scep.allowInProduct`; development answers.
//   D. JWE (#1486): product's discovery offers no CBC-HMAC content
//      encryption in any of the four lists, and `crypto.allowCbcJwe` brings
//      it back.
//   E. SCIM AND SHARED SIGNALS (#1473): with HTTP Basic and a person's own
//      password, a person with no console role is refused at SCIM and at
//      SSF, and `security.allowUnscopedPeople` lifts it; in a trust realm
//      Admin Read and Admin Write granted through the realm's own
//      `/admin-api/rbac/grant` are seen there: Admin Read reads SCIM,
//      Admin Write writes it and reaches SSF.
//   F. A SECOND FACTOR FOR EVERYBODY (#1490): with the optional-second-factor
//      opt-out cleared, the person's own password is refused at SCIM, and an
//      app password for that door works with no second factor held.
//   G. A CERTIFICATE SIGN-IN FROM A BROWSER (#1484): `/tls/sign-in` refuses
//      a cross-site navigation, an image and a frame, and answers a typed
//      address, a same-origin link and a program.
//   H. PKCE (#1494): a confidential client with no code_challenge is refused
//      at the authorization endpoint in product.
//   I. PRODUCT'S DEFAULTS, read off `/admin-api/config` in both realms: the
//      plain LDAP listener off, a 30-minute idle timeout, RSA-3072 keys, a
//      30-day refresh chain (none in development), one TOTP step (one either
//      side in development), HSTS on subdomains, scrypt at p=3.
//   J. REPEATED PARAMETERS: product's token endpoint refuses a repeated
//      parameter invalid_request; development does not.
//   K. THE MODE PAGE: `/admin-api/mode` describes main-port-https,
//      legacy-ciphers and declared-grants, and reports the self-minted
//      certificate under public-certificate as waived.
//
// NOT carried, and why — class (d) unless said: the XML encryption and
// OAEP-hash decisions (a library's encrypt/decrypt calls), the Kerberos
// enctype list (restart-only), the bootstrap administrator's generated name
// (p34's `sts_console_bootstrap_product` holds the realm's, with its defect),
// the directory's withheld-attribute list and SCIM's map (generated model
// files), named CA files under `security.fileRoots` (the service's own
// filesystem), the SPNEGO step cookie (a test-mounted route), the SSF push
// dialer's internal-address refusal and the issuance gate's throwing decider
// (in-process slots), the bootstrap password file, the GNAP grace and the
// cleartext start-up refusal (start-up), and from asvs_protocol_rules every
// predicate asked of `mode.js`, `oauth21.js`, the outbound host vetting, the
// trusted-proxy reading, the signing-algorithm list, the SPA client's nonce
// and issuer checks, the federation `returnTo` reading, the management API's
// re-authentication predicate (it needs a two-hour-old sign-in), the
// scheduler's clock skew, the audit checksum chain, a realm id purged
// again, and the partner sign-in time — each a module question.
//
// OWNED HERE (local: true): realm settings, applications and people of this
// service's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_asvs_product_rules");
const log = K.log;

const CLIENT = "pl-no-grants";
const SECRET = "a-long-enough-client-secret-" + K.rand(12);
const REDIRECT = "https://rp.pl.example/cb";
const PASS = "A-long-enough-probe-passphrase-" + K.rand(6);
const FLOOR = 35;

let DEV;
let PROD;

function check(what, fn) {
  K.check(what, fn);
}

function noCode(r) {
  log.debug("Entering noCode().");
  log.debug("Leaving noCode().");
  return !/STS-[A-Z]+-\d{4}/.test(String(r.text));
}

async function allOrNothing() {
  log.debug("Entering allOrNothing().");
  log.info("=== A. all or nothing ===");
  const id = "aon-app-" + K.rand(3);
  const made = await K.send(K.rb(DEV) + "/admin-api/applications/create", {
    json: { identifier: id, name: id, protocols: ["saml2"],
            fields: { samlSpMetadata: "this is not metadata" } } });
  const after = await K.send(K.rb(DEV) + "/admin-api/applications?" +
    new URLSearchParams({ application: id }));
  check("A1. a create whose metadata is refused is refused", function () {
    assert.ok(made.status >= 400 || (made.json && made.json.ok === false),
              K.shown(made));
  });
  check("A2. and leaves no application behind", function () {
    assert.ok(!(after.json && after.json.found === true), K.shown(after));
  });
  const who = "aon-person-" + K.STAMP;
  await K.ok(K.rb(DEV) + "/admin-api/users/create", { username: who,
    invent: false, attributes: { cn: who, sn: "before", title: "before",
      givenName: who, mail: who + "@example.com" } }, "created " + who);
  const saved = await K.send(K.rb(DEV) + "/admin-api/users/update-fields",
    { json: { user: who, fields: { title: "after", c: "zz" } } });
  const read = await K.send(K.rb(DEV) + "/admin-api/users?" +
    new URLSearchParams({ user: who }));
  check("A3. a save refused in part is refused, and says nothing was saved",
        function () {
    assert.ok(saved.json && saved.json.ok === false, K.shown(saved));
    assert.ok(/Nothing was saved/.test(saved.text), saved.text);
  });
  check("A4. and what it would have changed is unchanged", function () {
    assert.ok(read.text.indexOf("\"before\"") >= 0, read.text.slice(0, 300));
    assert.ok(read.text.indexOf("\"after\"") < 0, read.text.slice(0, 300));
  });
  log.debug("Leaving allOrNothing().");
}

function grant(realm, type) {
  log.debug("Entering grant(). " + type);
  log.debug("Leaving grant().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(CLIENT, SECRET) },
    form: { grant_type: type } });
}

function refusedGrant(r) {
  log.debug("Entering refusedGrant().");
  log.debug("Leaving refusedGrant().");
  return r.status === 400 && /declares no grant_types/.test(r.text);
}

function authorize(realm, type, extra) {
  log.debug("Entering authorize(). " + type);
  log.debug("Leaving authorize().");
  return K.send(K.rb(realm) + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ client_id: CLIENT, redirect_uri: REDIRECT,
      scope: "openid", nonce: "n", state: "s", response_type: type },
    extra || {})));
}

function noResponseTypes(r) {
  log.debug("Entering noResponseTypes().");
  log.debug("Leaving noResponseTypes().");
  return /unauthorized_client|declares(?:\+|%20| )no(?:\+|%20| )response/
    .test(String(r.location) + r.text);
}

async function grants() {
  log.debug("Entering grants().");
  log.info("=== B. grants and response types ===");
  const devCc = await grant(DEV, "client_credentials");
  check("B1. development: a client with no list may use any grant",
        function () {
    assert.ok(!refusedGrant(devCc), K.shown(devCc));
  });
  const cc = await grant(PROD, "client_credentials");
  const rt = await grant(PROD, "refresh_token");
  const ac = await grant(PROD, "authorization_code");
  check("B2. product: no list, no client_credentials, and no code sent",
        function () {
    assert.ok(refusedGrant(cc), K.shown(cc));
    assert.ok(noCode(cc));
  });
  check("B3. refresh_token and the code flow get past this check",
        function () {
    assert.ok(!refusedGrant(rt), K.shown(rt));
    assert.ok(!refusedGrant(ac), K.shown(ac));
  });
  const it = await authorize(PROD, "id_token");
  const hy = await authorize(PROD, "code id_token");
  const code = await authorize(PROD, "code", { code_challenge:
    K.pkce().challenge, code_challenge_method: "S256" });
  check("B4. product: no list, no implicit flow and no hybrid flow at the " +
        "authorization endpoint", function () {
    assert.ok(noResponseTypes(it), K.shown(it));
    assert.ok(noResponseTypes(hy), K.shown(hy));
  });
  check("B5. while the code flow gets past this check", function () {
    assert.ok(!noResponseTypes(code), K.shown(code));
  });
  await K.set(PROD, "oauth2.allowUndeclaredGrants", true);
  const ccOpen = await grant(PROD, "client_credentials");
  const itOpen = await authorize(PROD, "id_token");
  check("B6. oauth2.allowUndeclaredGrants lifts both", function () {
    assert.ok(!refusedGrant(ccOpen), K.shown(ccOpen));
    assert.ok(!noResponseTypes(itOpen), K.shown(itOpen));
  });
  await K.unset(PROD, "oauth2.allowUndeclaredGrants");
  log.debug("Leaving grants().");
}

async function scep() {
  log.debug("Entering scep().");
  log.info("=== C. SCEP ===");
  const caps = function (realm) {
    return K.send(K.rb(realm) + "/enroll/scep?operation=GetCACaps");
  };
  const dev = await caps(DEV);
  const prod = await caps(PROD);
  check("C1. development: SCEP answers", function () {
    assert.ok(dev.status !== 503, K.shown(dev));
  });
  check("C2. product: SCEP answers 503 and sends no error code",
        function () {
    assert.strictEqual(prod.status, 503, K.shown(prod));
    assert.ok(noCode(prod), prod.text);
  });
  await K.set(PROD, "scep.allowInProduct", true);
  const open = await caps(PROD);
  check("C3. until an operator opts in", function () {
    assert.ok(open.status !== 503, K.shown(open));
  });
  await K.unset(PROD, "scep.allowInProduct");
  log.debug("Leaving scep().");
}

const ENC_LISTS = ["id_token_encryption_enc_values_supported",
  "userinfo_encryption_enc_values_supported",
  "authorization_encryption_enc_values_supported",
  "request_object_encryption_enc_values_supported"];

async function jwe() {
  log.debug("Entering jwe().");
  log.info("=== D. JWE content encryption ===");
  const read = async function () {
    return (await K.send(K.rb(PROD) +
                         "/.well-known/openid-configuration")).json;
  };
  const d = await read();
  check("D1. product: discovery offers no CBC-HMAC content encryption in " +
        "any of its four lists", function () {
    ENC_LISTS.forEach(function (m) {
      assert.ok(Array.isArray(d[m]) && d[m].length, m);
      assert.ok(!d[m].some(function (one) {
        return /CBC/.test(one);
      }), m + ": " + d[m]);
    });
  });
  await K.set(PROD, "crypto.allowCbcJwe", true);
  const open = await read();
  check("D2. crypto.allowCbcJwe brings it back", function () {
    assert.ok(open.id_token_encryption_enc_values_supported
      .some(function (one) {
        return /CBC/.test(one);
      }), String(open.id_token_encryption_enc_values_supported));
  });
  await K.unset(PROD, "crypto.allowCbcJwe");
  log.debug("Leaving jwe().");
}

function basicAs(who, pass) {
  log.debug("Entering basicAs().");
  log.debug("Leaving basicAs().");
  return "Basic " + Buffer.from(who + ":" + pass).toString("base64");
}

function scimRead(who, pass) {
  log.debug("Entering scimRead().");
  log.debug("Leaving scimRead().");
  return K.send(K.rb(PROD) + "/scim/v2/Users", { headers: {
    Authorization: basicAs(who, pass), Accept: "application/scim+json" } });
}

function scimWrite(who, pass) {
  log.debug("Entering scimWrite().");
  log.debug("Leaving scimWrite().");
  return K.send(K.rb(PROD) + "/scim/v2/Users", { method: "POST",
    headers: { Authorization: basicAs(who, pass),
               "Content-Type": "application/scim+json" },
    raw: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "pl-made-" + who + "-" + K.rand(3) }) });
}

function ssf(who, pass) {
  log.debug("Entering ssf().");
  log.debug("Leaving ssf().");
  return K.send(K.rb(PROD) + "/ssf/stream", { headers: {
    Authorization: basicAs(who, pass) } });
}

async function roles() {
  log.debug("Entering roles().");
  log.info("=== E. SCIM and Shared Signals need a console role ===");
  await K.set(PROD, "authn.allowOptionalSecondFactor", true);
  const plain = "pl-plain-" + K.STAMP;
  const reader = "pl-reader-" + K.STAMP;
  const writer = "pl-writer-" + K.STAMP;
  for (const name of [plain, reader, writer]) {
    await K.person(PROD, name, PASS);
  }
  const api = K.rb(PROD) + "/admin-api/rbac/grant";
  await K.ok(api, { username: reader, role: "read" },
             "Admin Read to " + reader);
  await K.ok(api, { username: writer, role: "write" },
             "Admin Write to " + writer);
  const p = await scimRead(plain, PASS);
  const r = await scimRead(reader, PASS);
  const rw = await scimWrite(reader, PASS);
  check("E1. product: a password with no role is refused at SCIM",
        function () {
    assert.strictEqual(p.status, 403, K.shown(p));
  });
  const sp = await ssf(plain, PASS);
  const sr = await ssf(reader, PASS);
  const sw = await ssf(writer, PASS);
  const ww = await scimWrite(writer, PASS);
  check("E2. at SSF a password with no role is refused", function () {
    assert.strictEqual(sp.status, 403, K.shown(sp));
  });
  // A TRUST REALM's console roles, granted through its own
  // `/admin-api/rbac/grant`, are what SCIM and SSF ask of a Basic
  // credential (until fix/node-defects-1114 the default realm's roster was
  // read, and both were refused STS-SCIM-0060 / STS-XACML-0044).
  check("E3. in a trust realm, Admin Read granted on the realm reads SCIM " +
        "(200) and does not write it", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(rw.status, 403, K.shown(rw));
  });
  check("E4. and Admin Write writes SCIM and reaches SSF", function () {
    assert.strictEqual(ww.status, 201, K.shown(ww));
    assert.ok(sw.status !== 401 && sw.status !== 403, K.shown(sw));
    assert.ok(!/does not hold Admin Write/.test(sw.text), sw.text);
    log.info("E4. Admin Read at SSF answered " + sr.status);
  });
  await K.set(PROD, "security.allowUnscopedPeople", true);
  const lifted = await scimRead(plain, PASS);
  check("E5. security.allowUnscopedPeople lifts it", function () {
    assert.strictEqual(lifted.status, 200, K.shown(lifted));
  });

  log.info("=== F. a second factor for everybody ===");
  // The role check stays lifted, so what is asked here is the second
  // factor alone.
  await K.unset(PROD, "authn.allowOptionalSecondFactor");
  const own = await scimRead(reader, PASS);
  const made = await K.send(K.rb(PROD) +
    "/admin-api/users/create-app-password", { json: { user: reader,
      name: "a job " + K.rand(2), doors: ["scim"] } });
  const appPass = String((made.json && made.json.appPassword) || "");
  const viaApp = await scimRead(reader, appPass);
  check("F1. product: the person's own password is refused at a " +
        "password-only door", function () {
    assert.ok(own.status === 401 || own.status === 403, K.shown(own));
  });
  check("F2. an app password can be made with no second factor held",
        function () {
    assert.ok(made.status === 200 && appPass, K.shown(made));
  });
  check("F3. and works there with no second factor", function () {
    assert.strictEqual(viaApp.status, 200, K.shown(viaApp));
  });
  await K.unset(PROD, "security.allowUnscopedPeople");
  log.debug("Leaving roles().");
}

function raw(url, headers) {
  log.debug("Entering raw(). " + url);
  const u = new URL(url);
  const lib = u.protocol === "https:" ? require("https") : require("http");
  log.debug("Leaving raw().");
  return new Promise(function (resolve, reject) {
    const req = lib.request({ hostname: u.hostname, port: u.port,
      path: u.pathname + u.search, method: "GET", headers: headers,
      agent: false }, function (res) {
      let text = "";
      res.on("data", function (d) {
        text += d;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, text: text, location:
                  res.headers.location || "" });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function certificateSignIn() {
  log.debug("Entering certificateSignIn().");
  log.info("=== G. a certificate sign-in from a browser ===");
  // Not fetch(): undici drops a caller's Sec-Fetch-* headers (they are
  // forbidden request headers) and sends `sec-fetch-mode: cors` itself, so
  // every request would look the same. A plain https request sends exactly
  // the headers given, as a browser and a program each would.
  const ask = function (site, dest, fetched) {
    return raw(K.rb(PROD) + "/tls/sign-in", site === undefined ? {}
      : { "Sec-Fetch-Site": site, "Sec-Fetch-Dest": dest,
          "Sec-Fetch-Mode": fetched });
  };
  const cross = await ask("cross-site", "document", "navigate");
  const image = await ask("same-origin", "image", "no-cors");
  const frame = await ask("same-origin", "iframe", "navigate");
  check("G1. product: a link from another site, an image and a frame start " +
        "nothing", function () {
    assert.strictEqual(cross.status, 403, K.shown(cross));
    assert.strictEqual(image.status, 403, K.shown(image));
    assert.strictEqual(frame.status, 403, K.shown(frame));
  });
  const typed = await ask("none", "document", "navigate");
  const link = await ask("same-origin", "document", "navigate");
  const program = await ask(undefined);
  check("G2. a typed address, a same-origin link and a program are " +
        "answered", function () {
    assert.strictEqual(typed.status, 200, K.shown(typed));
    assert.strictEqual(link.status, 200, K.shown(link));
    assert.strictEqual(program.status, 200, K.shown(program));
  });
  log.debug("Leaving certificateSignIn().");
}

async function pkce() {
  log.debug("Entering pkce().");
  log.info("=== H. PKCE ===");
  const asked = await authorize(PROD, "code");
  check("H. product: a confidential client with no code_challenge is " +
        "refused at the authorization endpoint", function () {
    assert.ok(/invalid_request|PKCE/.test(String(asked.location) +
                                          asked.text), K.shown(asked));
  });
  log.debug("Leaving pkce().");
}

async function settingsOf(realm) {
  log.debug("Entering settingsOf().");
  const cfg = await K.send(K.rb(realm) + "/admin-api/config");
  const out = {};
  ((cfg.json && cfg.json.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (one) {
      out[one.key] = one.value;
    });
  });
  log.debug("Leaving settingsOf().");
  return out;
}

async function defaults() {
  log.debug("Entering defaults().");
  log.info("=== I. product's defaults ===");
  const p = await settingsOf(PROD);
  const d = await settingsOf(DEV);
  check("I1. product: the plain LDAP listener is off by default",
        function () {
    assert.strictEqual(p["ldap.plainListener"], false);
  });
  check("I2. product: a 30-minute idle timeout and RSA-3072 keys",
        function () {
    assert.strictEqual(Number(p["authn.sessionIdleTimeoutS"]), 1800);
    assert.strictEqual(p["pki.keyAlgorithm"], "rsa-3072");
  });
  check("I3. product caps a refresh chain at 30 days; development has no " +
        "cap", function () {
    assert.strictEqual(Number(p["oauth2.refreshTokenMaxChainS"]), 2592000);
    assert.strictEqual(Number(d["oauth2.refreshTokenMaxChainS"]), 0);
  });
  check("I4. product accepts one TOTP step; development one either side",
        function () {
    assert.strictEqual(Number(p["totp.window"]), 0);
    assert.strictEqual(Number(d["totp.window"]), 1);
  });
  check("I5. product applies HSTS to subdomains and stores scrypt at p=3",
        function () {
    assert.strictEqual(p["security.hstsIncludeSubDomains"], true);
    assert.strictEqual(Number(p["security.passwordHashP"]), 3);
  });
  log.debug("Leaving defaults().");
}

async function repeated() {
  log.debug("Entering repeated().");
  log.info("=== J. repeated parameters ===");
  const body = "grant_type=client_credentials&grant_type=client_credentials";
  const ask = function (realm) {
    return K.send(K.rb(realm) + "/oauth2/token", {
      headers: { Authorization: K.basic(CLIENT, SECRET) }, form: body });
  };
  const p = await ask(PROD);
  const d = await ask(DEV);
  check("J1. product refuses a repeated token parameter invalid_request",
        function () {
    assert.strictEqual(p.status, 400, K.shown(p));
    assert.strictEqual(p.json.error, "invalid_request");
    assert.ok(/grant_type/.test(p.json.error_description), p.text);
  });
  check("J2. development does not ask", function () {
    assert.ok(!(d.json && d.json.error === "invalid_request" &&
                /repeat/i.test(d.json.error_description)), K.shown(d));
  });
  log.debug("Leaving repeated().");
}

async function modePage() {
  log.debug("Entering modePage().");
  log.info("=== K. the mode page ===");
  const r = await K.send(K.rb(PROD) + "/admin-api/mode");
  const rows = (r.json && r.json.requirements) || [];
  const byId = {};
  rows.forEach(function (one) {
    byId[one.id] = one;
  });
  check("K1. main-port-https, legacy-ciphers and declared-grants are " +
        "described", function () {
    ["main-port-https", "legacy-ciphers", "declared-grants"]
      .forEach(function (id) {
        assert.ok(byId[id], id);
      });
  });
  check("K2. a self-minted certificate is reported under " +
        "public-certificate, waived", function () {
    const row = byId["public-certificate"];
    assert.ok(row, K.shown(r));
    assert.ok(Array.isArray(row.waived) && row.waived.length === 1,
              JSON.stringify(row));
  });
  log.debug("Leaving modePage().");
}

async function test() {
  log.debug("Entering test().");
  DEV = await K.realm("asvsdev", "development");
  PROD = await K.realm("asvsprod", "product");
  for (const realm of [DEV, PROD]) {
    await K.app(realm, CLIENT, { oauthClientId: [CLIENT],
      oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
      oauthTokenEndpointAuthMethod: "client_secret_basic" },
      { protocols: ["oauth2", "oidc"] });
  }
  await allOrNothing();
  await grants();
  await scep();
  await jwe();
  await roles();
  await certificateSignIn();
  await pkce();
  await defaults();
  await repeated();
  await modePage();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
