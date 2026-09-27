"use strict";
//
// File: sts_client_attestation.js
//
// ---------------------------------------------------------------------------
// OAUTH 2.0 ATTESTATION-BASED CLIENT AUTHENTICATION, OVER THE WIRE (#229,
// draft-ietf-oauth-attestation-based-client-auth-11).
//
// A throwaway realm (left behind), a client attester made HERE at run time —
// a certificate authority and an attester certificate it issued, by
// node-forge — and client instance keys made by node:
//
//   a. A realm that trusts no attester advertises neither method nor a
//      challenge endpoint, and POST /oauth2/challenge refuses.
//   b. The anchor configured: discovery names both methods, the
//      challenge_endpoint and section 8's lists; the challenge endpoint
//      answers a fresh, uncacheable challenge.
//   c. PAR for an attest_jwt_client_auth client: no attestation, no
//      challenge (400 use_attestation_challenge with a fresh one in the
//      OAuth-Client-Attestation-Challenge header), an attester nobody
//      trusts — refused; then accepted, with a fresh challenge again.
//   d. The code, bound through PAR to the client instance: redeemed by
//      another instance key refused, by the right one issued; the same PoP
//      again is a replay.
//   e. The refresh token, bound to the instance key: another key and no
//      attestation refused, the right one accepted.
//   f. The DPoP combined mode for an attest_jwt_client_auth_dpop client:
//      the attested key's DPoP proof alone authenticates it; another
//      key's, or a PoP JWT beside it, is refused.
//   g. Introspection takes the PoP mode too.
//
// What each check refuses in detail, with every error code, is
// `tests/client_attestation.js`, in process.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_client_attestation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("attest-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://wallet.attest.example.test/cb";
const PASSWORD = "Attest-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("attest-alice");
const SCOPE = "openid profile";
const CHALLENGE_HEADER = "oauth-client-attestation-challenge";
const FLOOR = 20;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

// The last challenge this service handed out, from whichever response
// carried one — the client's side of section 6.2.
let lastChallenge = "";

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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  const challenge = r.headers.get(CHALLENGE_HEADER) || "";
  if (challenge) {
    lastChallenge = challenge;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, challenge: challenge,
           cacheControl: r.headers.get("cache-control") || "",
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// One browser, with a cookie jar.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200, "the sign-in screen: " + page.status +
                     " " + page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  log.debug("Leaving signIn().");
  return posted;
}

// Follows redirects inside this service, signing in when asked, until the
// answer leaves it or is a page.
async function follow(b, first, who) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 12; i++) {
    if (!(r.status === 302 || r.status === 303)) {
      break;
    }
    const where = absolute(r.location);
    if (where.indexOf(base) !== 0) {
      break;
    }
    if (/\/authn\/login\?authn=/.test(where) && who) {
      r = await signIn(b, where, who);
      continue;
    }
    r = await b.go("GET", where);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// ---------------------------------------------------------------------------
// THE ATTESTER, made here: a root and an attester certificate it issued (RSA,
// which is what forge makes), and a stranger's root beside it. Nothing is
// kept on disk.
// ---------------------------------------------------------------------------
function certificate(subject, publicKey, issuer, signingKey, ca) {
  log.debug("Entering certificate(). " + subject);
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = "0" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 3600 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 86400 * 1000);
  cert.setSubject([{ name: "commonName", value: subject }]);
  cert.setIssuer([{ name: "commonName", value: issuer }]);
  cert.setExtensions(ca
    ? [{ name: "basicConstraints", cA: true, critical: true },
       { name: "keyUsage", keyCertSign: true, cRLSign: true,
         critical: true }]
    : [{ name: "basicConstraints", cA: false },
       { name: "keyUsage", digitalSignature: true, critical: true }]);
  cert.sign(signingKey, forge.md.sha256.create());
  log.debug("Leaving certificate().");
  return cert;
}

function attesterOf(rootName) {
  log.debug("Entering attesterOf(). " + rootName);
  const rootKeys = forge.pki.rsa.generateKeyPair(2048);
  const root = certificate(rootName, rootKeys.publicKey, rootName,
                           rootKeys.privateKey, true);
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = certificate(rootName + " attester", leafKeys.publicKey,
                           rootName, rootKeys.privateKey, false);
  log.debug("Leaving attesterOf().");
  return {
    rootPem: forge.pki.certificateToPem(root),
    leafDer: forge.util.encode64(forge.asn1.toDer(
      forge.pki.certificateToAsn1(leaf)).getBytes()),
    key: nodeCrypto.createPrivateKey(forge.pki.privateKeyToPem(
      leafKeys.privateKey))
  };
}

function instanceKey() {
  log.debug("Entering instanceKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving instanceKey().");
  return { privateKey: pair.privateKey,
           jwk: pair.publicKey.export({ format: "jwk" }) };
}

function jws(header, claims, key) {
  log.debug("Entering jws(). " + header.alg);
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(claims))
                  .toString("base64url");
  const sig = header.alg === "ES256"
    ? nodeCrypto.sign("sha256", Buffer.from(input),
                      { key: key, dsaEncoding: "ieee-p1363" })
    : nodeCrypto.sign("sha256", Buffer.from(input), key);
  log.debug("Leaving jws().");
  return input + "." + sig.toString("base64url");
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

// Section 4: the attester's statement about a client instance's key.
function attestationFor(attester, clientId, instance) {
  log.debug("Entering attestationFor().");
  log.debug("Leaving attestationFor().");
  return jws({ typ: "oauth-client-attestation+jwt", alg: "RS256",
               x5c: [attester.leafDer] },
             { iss: "https://attester.example.test", sub: clientId,
               iat: now(), exp: now() + 600,
               cnf: { jwk: instance.jwk } }, attester.key);
}

// Section 5.1: the instance's proof, carrying the last challenge.
function popFor(instance, issuer) {
  log.debug("Entering popFor().");
  log.debug("Leaving popFor().");
  return jws({ typ: "oauth-client-attestation-pop+jwt", alg: "ES256" },
             { aud: issuer, jti: nodeCrypto.randomUUID(), iat: now(),
               challenge: lastChallenge }, instance.privateKey);
}

function dpopProof(instance, url) {
  log.debug("Entering dpopProof().");
  log.debug("Leaving dpopProof().");
  return jws({ typ: "dpop+jwt", alg: "ES256", jwk: instance.jwk },
             { jti: nodeCrypto.randomUUID(), htm: "POST", htu: url,
               iat: now() }, instance.privateKey);
}

function postForm(url, fields, headers) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type":
                               "application/x-www-form-urlencoded" },
                           headers || {}),
    body: form(fields) });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving OAuth 2.0 Attestation-Based Client Authentication at " +
           base + R);

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Client attestation " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Attest " + ALICE, givenName: "Attest", sn: ALICE,
                  mail: ALICE + "@attest.test" } }, "created " + ALICE);
  const attester = attesterOf("attest root " + STAMP);
  const stranger = attesterOf("stranger root " + STAMP);
  const k1 = instanceKey();
  const k2 = instanceKey();

  log.info("=== a. a realm that trusts no attester ===");
  let disco = (await send(base + R +
                          "/.well-known/oauth-authorization-server")).body;
  check("neither method nor a challenge endpoint is advertised", function () {
    assert.ok(disco.token_endpoint_auth_methods_supported
      .indexOf("attest_jwt_client_auth") < 0);
    assert.strictEqual(disco.challenge_endpoint, undefined);
  });
  let r = await postForm(base + R + "/oauth2/challenge", {});
  check("POST /oauth2/challenge refuses", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  log.info("=== b. the anchor configured ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.clientAttestationTrustAnchors",
             value: attester.rootPem }, "trusted the attester's root");
  disco = (await send(base + R +
                      "/.well-known/oauth-authorization-server")).body;
  const issuer = disco.issuer;
  check("discovery names both methods, the challenge endpoint and " +
        "section 8's lists", function () {
    ["attest_jwt_client_auth", "attest_jwt_client_auth_dpop"]
      .forEach(function (m) {
        assert.ok(disco.token_endpoint_auth_methods_supported.indexOf(m) >=
                  0, m);
      });
    assert.strictEqual(disco.challenge_endpoint,
                       base + R + "/oauth2/challenge");
    assert.ok(disco.client_attestation_signing_alg_values_supported
      .indexOf("RS256") >= 0);
    assert.ok(disco.client_attestation_pop_signing_alg_values_supported
      .indexOf("ES256") >= 0);
    assert.deepStrictEqual(disco.client_attestation_pop_methods_supported,
                           ["attestation_pop_jwt", "dpop_combined", "none"]);
  });
  r = await postForm(disco.challenge_endpoint, {});
  check("the challenge endpoint answers a fresh challenge, uncacheable",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.ok(/no-store/.test(r.cacheControl), r.cacheControl);
    assert.ok(/^[A-Za-z0-9_-]{16,}$/.test(r.body.attestation_challenge),
              r.raw);
  });
  lastChallenge = r.body.attestation_challenge;

  log.info("=== c. PAR for an attest_jwt_client_auth client ===");
  const registered = await postJson(base + R + "/oauth2/register", {
    redirect_uris: [REDIRECT], token_endpoint_auth_method:
      "attest_jwt_client_auth",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"], scope: SCOPE,
    client_name: "attested wallet " + STAMP });
  check("a client registers attest_jwt_client_auth", function () {
    assert.strictEqual(registered.status, 201, registered.raw.slice(0, 400));
  });
  const clientId = registered.body.client_id;
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: clientId, scope: one },
             "consented " + one + " for everybody");
  }
  const p = pkce();
  const params = { client_id: clientId, response_type: "code",
    redirect_uri: REDIRECT, scope: SCOPE, state: "st-" + STAMP,
    code_challenge: p.challenge, code_challenge_method: "S256" };
  const parUrl = base + R + "/oauth2/par";
  const attested = function (instance, att) {
    return { "OAuth-Client-Attestation":
               att || attestationFor(attester, clientId, instance),
             "OAuth-Client-Attestation-PoP": popFor(instance, issuer) };
  };
  r = await postForm(parUrl, params);
  check("a push with no attestation is refused invalid_client", function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client");
  });
  r = await postForm(parUrl, params, {
    "OAuth-Client-Attestation": attestationFor(attester, clientId, k1),
    "OAuth-Client-Attestation-PoP": jws(
      { typ: "oauth-client-attestation-pop+jwt", alg: "ES256" },
      { aud: issuer, jti: nodeCrypto.randomUUID(), iat: now() },
      k1.privateKey) });
  check("a PoP without a challenge is 400 use_attestation_challenge, with " +
        "a fresh one in the header (section 6.1)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "use_attestation_challenge");
    assert.ok(r.challenge, "no OAuth-Client-Attestation-Challenge");
  });
  r = await postForm(parUrl, params, attested(k1,
    attestationFor(stranger, clientId, k1)));
  check("an attester nobody trusts is refused invalid_client", function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client");
  });
  r = await postForm(parUrl, params, attested(k1));
  check("an attested push with the challenge is accepted, and hands out " +
        "the next challenge", function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
    assert.ok(r.challenge, "no fresh challenge on the success");
  });
  const requestUri = r.body.request_uri;

  log.info("=== d. the code, bound to the client instance ===");
  const alice = browser("alice");
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
    form({ client_id: clientId, request_uri: requestUri })), ALICE);
  const back = r.location && r.location.indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams : null;
  check("the code comes back to the wallet", function () {
    assert.ok(back && back.get("code"), r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
  });
  const tokenUrl = base + R + "/oauth2/token";
  const redeem = { grant_type: "authorization_code", code: back.get("code"),
                   redirect_uri: REDIRECT, code_verifier: p.verifier };
  r = await postForm(tokenUrl, redeem, attested(k2));
  check("the code redeemed by another client instance key is refused " +
        "invalid_grant (section 10.4)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_grant");
  });
  const proof = attested(k1);
  r = await postForm(tokenUrl, redeem, proof);
  check("and by the instance it was pushed by, issued", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 400));
    assert.ok(r.body.refresh_token, "no refresh token");
    assert.ok(r.challenge, "no fresh challenge on the token response");
  });
  const tokens = r.body;
  r = await postForm(tokenUrl, { grant_type: "refresh_token",
                                 refresh_token: tokens.refresh_token },
                     proof);
  check("the same PoP a second time is a replay, refused invalid_client",
        function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client");
  });

  log.info("=== e. the refresh token, bound to the client instance ===");
  const refresh = { grant_type: "refresh_token",
                    refresh_token: tokens.refresh_token };
  r = await postForm(tokenUrl, refresh);
  check("a refresh with no attestation is refused (section 10.3) — " +
        "invalid_grant, since nothing names the client", function () {
    assert.ok(r.status === 400 || r.status === 401, r.raw.slice(0, 300));
    assert.ok(["invalid_grant", "invalid_client"].indexOf(r.body.error) >= 0,
              r.raw.slice(0, 300));
  });
  r = await postForm(tokenUrl, refresh, attested(k2));
  check("a refresh by another instance key is refused invalid_grant",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_grant");
  });
  r = await postForm(tokenUrl, refresh, attested(k1));
  check("a refresh by the bound instance key is accepted", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  });
  const accessToken = r.body.access_token;

  log.info("=== g. introspection takes the PoP mode ===");
  r = await postForm(base + R + "/oauth2/introspect",
                     { token: accessToken, client_id: clientId },
                     Object.assign({ Accept: "application/json" },
                                   attested(k1)));
  check("an attested caller introspects the token it holds", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.strictEqual(r.body.active, true, r.raw.slice(0, 300));
  });

  log.info("=== f. the DPoP combined mode ===");
  const combinedRegistration = await postJson(base + R + "/oauth2/register", {
    redirect_uris: [REDIRECT], token_endpoint_auth_method:
      "attest_jwt_client_auth_dpop",
    grant_types: ["client_credentials"],
    scope: "profile", client_name: "combined wallet " + STAMP });
  check("a client registers attest_jwt_client_auth_dpop", function () {
    assert.strictEqual(combinedRegistration.status, 201,
                       combinedRegistration.raw.slice(0, 400));
  });
  const combinedId = combinedRegistration.body.client_id;
  const cc = { grant_type: "client_credentials", scope: "profile" };
  r = await postForm(tokenUrl, cc, {
    "OAuth-Client-Attestation": attestationFor(attester, combinedId, k1),
    DPoP: dpopProof(k2, tokenUrl) });
  check("a DPoP proof by another key than the attested one is refused",
        function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
  });
  r = await postForm(tokenUrl, cc, {
    "OAuth-Client-Attestation": attestationFor(attester, combinedId, k1),
    "OAuth-Client-Attestation-PoP": popFor(k1, issuer),
    DPoP: dpopProof(k1, tokenUrl) });
  check("a PoP JWT beside the DPoP proof is refused: the client declared " +
        "the combined mode", function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
  });
  r = await postForm(tokenUrl, cc, {
    "OAuth-Client-Attestation": attestationFor(attester, combinedId, k1),
    DPoP: dpopProof(k1, tokenUrl) });
  check("the attested key's DPoP proof alone authenticates the client, and " +
        "the token is DPoP-bound (section 5.2)", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 400));
    assert.strictEqual(r.body.token_type, "DPoP");
  });

  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section " +
                                             "has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_client_attestation")
  .description("OAuth 2.0 Attestation-Based Client Authentication over the " +
               "wire (#229).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
