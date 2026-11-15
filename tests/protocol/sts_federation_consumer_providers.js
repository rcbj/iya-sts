// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_consumer_providers.js
//
// ===========================================================================
// CONSUMER AND SOCIAL PROVIDERS AS FEDERATION RELATIONSHIPS, DRIVEN THROUGH
// THEIR OWN PROFILES OVER THE WIRE (#565, #729; #444 D12, phase 7).
//
// `tests/federation_consumer_providers.js` runs the stack and provider-
// shaped servers in one child; `sts_federation_consumer.js` (vendored)
// holds the category over the wire against another realm through the
// `generic-oidc` profile. This job carries the three first PROFILES —
// Discord, GitHub and Google — through real federated sign-ins against
// provider-shaped servers in THIS process (the SHAPE of each provider: the
// authorization endpoint answers at once with a code, the token endpoint
// checks the PKCE verifier and records the client authentication, the
// profile endpoints answer what each provider documents), dialled at
// OUTBOUND_TEST_HOST from a development realm with
// `federation.outboundAllowHttp` and `federation.consumerProviders` on:
//
//   A. what creation writes from a profile: the role and protocol a
//      provider alone implies, the endpoints, issuer and scope on the entry,
//      GitHub's second endpoint and client_secret_post, disabled,
//      jit-namespaced and auto-create on, the realm's
//      federation.consumerProvisionCap written (10000), Google OIDC with no
//      encryption key, another protocol / the other role / an unknown
//      provider refused, the client credentials named as missing;
//   D. Discord: the namespaced entry `<relationship>~<id>`, the profile's
//      claims on it, client_secret_basic at the token endpoint, the link
//      `<relationship> https://discord.com <id>`, the stsProvisionedBy stamp;
//   E. GitHub: the primary verified address from /user/emails and not
//      /user's public one, client_secret_post, PKCE to a plain OAuth 2.0
//      provider, and /user/emails failing costing the address and never the
//      sign-in (STS-FED-0176);
//   F. Google: a signed ID Token against the provider's keys, the bare-host
//      alias not accepted for a peer that is not accounts.google.com, an
//      ID Token naming another issuer refused;
//   N. the portal's disconnect of the provider that is a newcomer's only way
//      in refused (409, STS-PORTAL-0614) and the link kept; with a second
//      connection the same disconnect allowed and the link gone.
//
// NOT HERE: C's `readPath()` / `extract()` / `issuersFor()` (functions; D,
// E and F are their outcomes), N9/N10's federated finish refused after a
// risk step-up (STS-FED-0192: a stubbed step that disables the
// relationship between the step-up and the browser's return), and the
// other twenty-odd profiles (#746) beyond the three first.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const http = require("http");
const nodeCrypto = require("crypto");
const portal = require("./portal_signin.js");
const K = require("./oauth_wire_kit.js").kit(
  "sts_federation_consumer_providers");

const log = K.log;
let SP = null;
let PBASE = "";
const people = {};
const seen = { discord: [], github: [], google: [] };
const codes = {};
const failEmails = { on: false };
const GOOGLE_KEY = nodeCrypto.generateKeyPairSync("rsa",
  { modulusLength: 2048 });
const GOOGLE_JWK = Object.assign(GOOGLE_KEY.publicKey.export(
  { format: "jwk" }), { kid: "fake-google-1", alg: "RS256", use: "sig" });

function signJwt(claims) {
  log.debug("Entering signJwt().");
  const input = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT",
    kid: "fake-google-1" })).toString("base64url") + "." +
    Buffer.from(JSON.stringify(claims)).toString("base64url");
  log.debug("Leaving signJwt().");
  return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
    GOOGLE_KEY.privateKey).toString("base64url");
}

// THE PROVIDERS, one server under three path prefixes. A hot path: each
// request is recorded in `seen` or `codes`, which is what a case reads.
function providerHandler(req, res) {
  const url = new URL(req.url, "http://x");
  const parts = url.pathname.split("/").filter(Boolean);
  const who = parts[0];
  const what = parts.slice(1).join("/");
  let body = "";
  req.on("data", function (c) {
    body += c;
  });
  req.on("end", function () {
    const json = function (status, value) {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (what === "authorize") {
      const code = who + "-" + nodeCrypto.randomBytes(8).toString("hex");
      codes[code] = { who: who,
        challenge: url.searchParams.get("code_challenge"),
        nonce: url.searchParams.get("nonce") || "",
        clientId: url.searchParams.get("client_id"), person: people[who] };
      const back = new URL(url.searchParams.get("redirect_uri"));
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state"));
      res.writeHead(302, { location: back.toString() });
      res.end();
      return;
    }
    if (what === "token") {
      const form = new URLSearchParams(body);
      seen[who].push({ authorization: req.headers.authorization || "",
                       form: Object.fromEntries(form.entries()) });
      const grant = codes[form.get("code")];
      delete codes[form.get("code")];
      const digest = nodeCrypto.createHash("sha256")
        .update(form.get("code_verifier") || "").digest("base64url");
      if (!grant || grant.challenge !== digest) {
        json(400, { error: "invalid_grant" });
        return;
      }
      const token = "at-" + nodeCrypto.randomBytes(8).toString("hex");
      codes["at:" + token] = grant;
      const answer = { access_token: token, token_type: "Bearer" };
      if (who === "google") {
        const now = Math.floor(Date.now() / 1000);
        answer.id_token = signJwt(Object.assign({
          iss: grant.person.iss || PBASE + "/google", aud: grant.clientId,
          nonce: grant.nonce, iat: now, exp: now + 300 },
        grant.person.claims));
      }
      json(200, answer);
      return;
    }
    if (who === "google" && what === "jwks") {
      json(200, { keys: [GOOGLE_JWK] });
      return;
    }
    const granted = codes["at:" + String(req.headers.authorization || "")
      .replace(/^Bearer /, "")];
    if (!granted) {
      json(401, { error: "invalid_token" });
      return;
    }
    if (who === "discord" && what === "users/@me") {
      json(200, granted.person.profile);
      return;
    }
    if (who === "github" && what === "user") {
      json(200, granted.person.profile);
      return;
    }
    if (who === "github" && what === "user/emails") {
      if (failEmails.on) {
        json(500, { message: "unavailable" });
        return;
      }
      json(200, granted.person.emails || []);
      return;
    }
    json(404, { error: "not_found" });
  });
}

function api(path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(SP) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

async function rel(id) {
  log.debug("Entering rel(). " + id);
  const r = await api("/federation?relationship=" + id);
  log.debug("Leaving rel().");
  return r.json || {};
}

function fieldOf(view, name) {
  log.debug("Entering fieldOf(). " + name);
  const f = view.fields || {};
  const v = f[name];
  log.debug("Leaving fieldOf().");
  return v && typeof v === "object" && "value" in v ? v.value : v;
}

async function entry(name) {
  log.debug("Entering entry(). " + name);
  const r = await api("/users?user=" + encodeURIComponent(name));
  const ldap = (r.json && r.json.ldap) || {};
  log.debug("Leaving entry().");
  return { found: !!ldap.found, attrs: (ldap.entry || {}).attributes || {},
           json: r.json || {} };
}

function attr(e, name) {
  log.debug("Entering attr(). " + name);
  const v = e.attrs[name];
  log.debug("Leaving attr().");
  return v === undefined ? [] : [].concat(v);
}

async function signIn(id) {
  log.debug("Entering signIn(). " + id);
  const b = K.browser();
  let r = await b.go(K.rb(SP) + "/federation/login/" + id);
  for (let i = 0; i < 10 && r.status >= 300 && r.status < 400 && r.location;
       i += 1) {
    // The browser reaches the providers on this host's loopback; the
    // service reaches them at OUTBOUND_TEST_HOST.
    r = await b.go(new URL(r.location, K.base).toString()
      .replace("//" + K.HOST + ":", "//127.0.0.1:"));
  }
  log.debug("Leaving signIn(). " + r.status);
  return { r: r, b: b };
}

async function point(id, who, extra) {
  log.debug("Entering point(). " + id);
  const fields = Object.assign({ fedSsoUrl: PBASE + "/" + who + "/authorize",
    fedTokenUrl: PBASE + "/" + who + "/token",
    fedClientId: "client-" + who, fedClientSecret: "secret-" + who },
  extra || {});
  for (const f of Object.keys(fields)) {
    await K.ok(K.rb(SP) + "/admin-api/federation/set", { id: id, field: f,
      value: fields[f] }, "set " + f + " on " + id);
  }
  await K.ok(K.rb(SP) + "/admin-api/federation/enable", { id: id },
             "enabled " + id);
  log.debug("Leaving point().");
}

// ------------------------------------------------------------------- A
async function creation() {
  log.debug("Entering creation().");
  log.info("=== A. what creation writes from a profile ===");
  const made = {};
  for (const who of ["discord", "github", "google"]) {
    made[who] = await api("/federation/create", { id: "cp-" + who,
                                                  provider: who });
  }
  const d0 = await rel("cp-discord");
  K.check("A1. a provider alone says the role and the protocol", function () {
    assert.strictEqual(made.discord.status, 200,
                       made.discord.text.slice(0, 300));
    assert.strictEqual(d0.role, "service-provider");
    assert.strictEqual(d0.protocol, "oauth2");
    assert.strictEqual(d0.category, "consumer");
  });
  K.check("A2. the profile's endpoints, issuer and scope are ON THE ENTRY",
          function () {
            assert.strictEqual(fieldOf(d0, "fedSsoUrl"),
                               "https://discord.com/oauth2/authorize");
            assert.strictEqual(fieldOf(d0, "fedTokenUrl"),
                               "https://discord.com/api/oauth2/token");
            assert.strictEqual(fieldOf(d0, "fedUserinfoUrl"),
                               "https://discord.com/api/users/@me");
            assert.strictEqual(d0.peer, "https://discord.com");
            assert.strictEqual(fieldOf(d0, "fedScope"), "identify email");
          });
  const g0 = await rel("cp-github");
  K.check("A3. GitHub's second endpoint and client_secret_post are written",
          function () {
            assert.strictEqual(fieldOf(g0, "fedEmailsUrl"),
                               "https://api.github.com/user/emails");
            assert.strictEqual(fieldOf(g0, "fedTokenAuth"),
                               "client_secret_post");
          });
  K.check("A4. created disabled, jit-namespaced, auto-create on, and the " +
          "realm's consumer provision cap (10000) written", function () {
    assert.strictEqual(d0.enabled, false);
    assert.strictEqual(fieldOf(d0, "fedSubjectPolicy"), "jit-namespaced");
    assert.strictEqual(String(fieldOf(d0, "fedAutocreateUsers")), "TRUE");
    assert.strictEqual(String(fieldOf(d0, "fedProvisionCap")), "10000");
  });
  const go = await rel("cp-google");
  K.check("A5. a Google relationship is OIDC and is given no encryption key",
          function () {
            assert.strictEqual(go.protocol, "oidc");
            assert.ok(!go.encrypts, JSON.stringify(go.encryption)
              .slice(0, 200));
            assert.ok(!((go.encryption || {}).keys || []).length);
          });
  const wrong = [
    await api("/federation/create", { id: "cp-bad1", provider: "discord",
                                      protocol: "oidc" }),
    await api("/federation/create", { id: "cp-bad2", provider: "discord",
                                      role: "identity-provider" }),
    await api("/federation/create", { id: "cp-bad3", provider: "myspace" })
  ];
  K.check("A6. another protocol, the other role, an unknown provider are " +
          "refused", function () {
    wrong.forEach(function (r) {
      assert.strictEqual(r.status, 400, r.text.slice(0, 200));
    });
  });
  K.check("A7. a new provider relationship names the client credentials it " +
          "still needs", function () {
    assert.ok((d0.missing || []).indexOf("fedClientId") >= 0,
              JSON.stringify(d0.missing));
    assert.ok((d0.missing || []).indexOf("fedClientSecret") >= 0);
  });
  log.debug("Leaving creation().");
}

// ------------------------------------------------------------------- D
async function discord() {
  log.debug("Entering discord().");
  log.info("=== D. Discord ===");
  await point("cp-discord", "discord",
              { fedUserinfoUrl: PBASE + "/discord/users/@me" });
  people.discord = { profile: { id: "80351110224678912", username: "nelly",
    global_name: "Nelly", email: "nelly@example.com", verified: true,
    locale: "en-US", mfa_enabled: true } };
  const got = await signIn("cp-discord");
  const name = "cp-discord~80351110224678912";
  const e = await entry(name);
  K.check("D1. a Discord sign-in creates the namespaced entry " + name,
          function () {
            assert.strictEqual(got.r.status, 200, K.shown(got.r));
            assert.ok(e.found);
          });
  K.check("D2. the profile's claims reached the entry", function () {
    assert.strictEqual(attr(e, "mail")[0], "nelly@example.com");
    assert.strictEqual(attr(e, "cn")[0], "Nelly");
  });
  const basic = (seen.discord[0] || {}).authorization || "";
  K.check("D3. client_secret_basic reached Discord's token endpoint",
          function () {
            assert.ok(/^Basic /.test(basic), basic);
            assert.strictEqual(Buffer.from(basic.slice(6), "base64")
              .toString(), "client-discord:secret-discord");
            assert.ok(!(seen.discord[0] || { form: {} }).form.client_secret);
          });
  const links = JSON.stringify((e.json || {}).federationLinks || []);
  K.check("D4. the link is the relationship, the issuer and the id",
          function () {
            assert.ok(/cp-discord/.test(links) &&
                      links.indexOf("https://discord.com") >= 0 &&
                      links.indexOf("80351110224678912") >= 0, links);
          });
  K.check("D5. the newcomer carries stsProvisionedBy federation:cp-discord",
          function () {
            assert.ok(/"stsProvisionedBy":\s*\[?"federation:cp-discord"/
              .test(JSON.stringify(e.json)), JSON.stringify(e.attrs)
              .slice(0, 300));
          });
  log.debug("Leaving discord().");
  return { name: name, b: got.b };
}

// ------------------------------------------------------------------- E
async function github() {
  log.debug("Entering github().");
  log.info("=== E. GitHub ===");
  await point("cp-github", "github", {
    fedUserinfoUrl: PBASE + "/github/user",
    fedEmailsUrl: PBASE + "/github/user/emails" });
  people.github = { profile: { id: 583231, login: "octocat",
    name: "The Octocat", email: "public-octo@example.com" },
  emails: [{ email: "old@example.com", primary: false, verified: true },
           { email: "octo@example.com", primary: true, verified: true }] };
  const got = await signIn("cp-github");
  const e = await entry("cp-github~583231");
  K.check("E1. GitHub: the primary verified address, not /user's public one",
          function () {
            assert.strictEqual(got.r.status, 200, K.shown(got.r));
            assert.strictEqual(attr(e, "mail")[0], "octo@example.com");
          });
  const form = (seen.github[0] || { form: {} }).form;
  K.check("E2. client_secret_post: the secret in the body, no Basic header",
          function () {
            assert.strictEqual(form.client_secret, "secret-github");
            assert.strictEqual(form.client_id, "client-github");
            assert.ok(!(seen.github[0] || {}).authorization);
          });
  K.check("E3. PKCE is sent to a plain OAuth 2.0 provider too", function () {
    assert.ok(form.code_verifier);
  });
  people.github = { profile: { id: 99, login: "nomail",
                               email: "public-nomail@example.com" },
                    emails: [] };
  failEmails.on = true;
  const failed = await K.coded(SP, "STS-FED-0176", function () {
    return signIn("cp-github");
  });
  failEmails.on = false;
  const e2 = await entry("cp-github~99");
  K.check("E4. /user/emails failing costs the address, never the sign-in " +
          "(STS-FED-0176), and /user's public address is not used instead",
  function () {
    assert.strictEqual(failed.answer.r.status, 200, K.shown(failed.answer.r));
    assert.ok(e2.found);
    assert.ok(attr(e2, "mail").indexOf("public-nomail@example.com") < 0,
              JSON.stringify(attr(e2, "mail")));
    assert.ok(failed.rose >= 1, "no STS-FED-0176 row");
  });
  log.debug("Leaving github().");
}

// ------------------------------------------------------------------- F
async function google() {
  log.debug("Entering google().");
  log.info("=== F. Google ===");
  await point("cp-google", "google", { fedJwksUri: PBASE + "/google/jwks",
                                       fedPeer: PBASE + "/google" });
  people.google = { claims: { sub: "110169484474386276334",
    email: "gina@example.com", email_verified: true, name: "Gina" } };
  const got = await signIn("cp-google");
  const e = await entry("cp-google~110169484474386276334");
  K.check("F1. a Google sign-in on a verified ID Token", function () {
    assert.strictEqual(got.r.status, 200, K.shown(got.r));
    assert.strictEqual(attr(e, "mail")[0], "gina@example.com");
  });
  people.google = { iss: "accounts.google.com",
    claims: { sub: "2", email: "b@example.com", email_verified: true } };
  const alias = await signIn("cp-google");
  K.check("F2. the bare-host alias is Google's, so it is NOT accepted for a " +
          "peer that is not accounts.google.com", function () {
    assert.notStrictEqual(alias.r.status, 200, K.shown(alias.r));
  });
  people.google = { iss: "https://evil.example",
                    claims: { sub: "3", email: "c@example.com" } };
  const evil = await signIn("cp-google");
  K.check("F3. an ID Token naming another issuer is refused", function () {
    assert.strictEqual(evil.r.status, 401, K.shown(evil.r));
  });
  log.debug("Leaving google().");
}

// ------------------------------------------------------------------- N
async function disconnect(newcomer) {
  log.debug("Entering disconnect().");
  log.info("=== N. the portal's disconnect of the only way in ===");
  const cookie = Object.keys(newcomer.b.jar).map(function (k) {
    return k + "=" + newcomer.b.jar[k];
  }).join("; ");
  const client = await portal.signInToThePortal(K.rb(SP), newcomer.name, log,
                                                { cookie: cookie });
  const refused = await K.coded(SP, "STS-PORTAL-0614", function () {
    return client.act("/portal/connected-accounts",
                      { action: "disconnect", id: "cp-discord" });
  });
  let e = await entry(newcomer.name);
  K.check("N1. disconnecting the provider that is a newcomer's only way in " +
          "is refused (409, STS-PORTAL-0614), and the link kept", function () {
    assert.strictEqual(refused.answer.status, 409,
                       JSON.stringify(refused.answer.json || refused.answer)
                         .slice(0, 300));
    assert.ok(refused.rose >= 1);
    assert.ok(/cp-discord/.test(JSON.stringify(e.json.federationLinks)));
    assert.ok(!/STS-PORTAL-0614/.test(JSON.stringify(refused.answer.json)));
  });
  await K.ok(K.rb(SP) + "/admin-api/users/federation-link", {
    user: newcomer.name, relationship: "cp-github", subject: "9599" },
  "a second connection");
  const allowed = await client.act("/portal/connected-accounts",
                                   { action: "disconnect", id: "cp-discord" });
  e = await entry(newcomer.name);
  K.check("N2. with a second connection the same disconnect is allowed and " +
          "the provider's link is gone", function () {
    assert.strictEqual(allowed.status, 200, JSON.stringify(allowed.json ||
                                                           allowed));
    assert.ok(!/"cp-discord"|cp-discord https/.test(
      JSON.stringify(e.json.federationLinks)) &&
              /cp-github/.test(JSON.stringify(e.json.federationLinks)),
              JSON.stringify(e.json.federationLinks));
  });
  log.debug("Leaving disconnect().");
}

async function test() {
  log.debug("Entering test().");
  const server = http.createServer(providerHandler);
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  PBASE = "http://" + K.HOST + ":" + server.address().port;
  try {
    SP = await K.realm("fcp", "development", {
      "federation.outboundAllowHttp": "true",
      "federation.consumerProviders": "true" });
    await creation();
    const newcomer = await discord();
    await github();
    await google();
    await disconnect(newcomer);
  } finally {
    server.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 20);
