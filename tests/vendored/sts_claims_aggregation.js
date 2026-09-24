"use strict";
//
// File: sts_claims_aggregation.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT CLAIMS AGGREGATION (#147, 2026-09-24), over HTTP, with THIS
// SERVICE ON BOTH ENDS: a throwaway realm is the OpenID Provider, a second
// throwaway realm is the Claims Provider, and the second realm's UserInfo
// carries a configured claim (`credit_score`) the first has no way to answer.
//
//   1. THE REGISTER: the provider registered by discovery on /admin-api, the
//      redirect URI to register at it, discovery's claim_types_supported.
//   2. THE SETUP PHASE: the person links the provider on
//      /portal/claim-sources — to the provider realm, signed in and agreed
//      there, back to the callback — and the link is listed, never a token.
//   3. AGGREGATED: a relying party's claims request for credit_score gets
//      `_claim_names` / `_claim_sources` in the ID Token and in UserInfo, the
//      source a JWT the provider realm signed (verified here against its
//      JWKS), about the person's subject THERE; a claim the entry answers
//      (email) is never referenced.
//   4. DISTRIBUTED: the provider switched to distributed hands over its
//      endpoint and an access token, which answers credit_score.
//   5. REFUSALS AND REVOCATION: linking an unknown provider; the administrator
//      revokes the link and the next ID Token carries no source; the person
//      unlinks on the portal.
//
// OWNED HERE (local: true): this repository's authorization server, portal
// and management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const tls = require("tls");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const facts = require("./service_facts.js");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_claims_aggregation",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const OP = "ca-op-" + TAG;
const CP = "ca-cp-" + TAG;
const opBase = root + "/realm/" + OP;
const cpBase = root + "/realm/" + CP;
const PERSON = names.usernameFor("ca-person");
const CP_PERSON = names.usernameFor("ca-cp-person");
const PASSWORD = "Ca-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const RP_REDIRECT = "https://rp.claims.example/cb";
const SCORE = "742";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
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

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// The realm base a URL on this service is under.
function realmBaseOf(url) {
  log.debug("Entering realmBaseOf().");
  const m = /^(https?:\/\/[^/]+(?:\/realm\/[^/?#]+)?)/.exec(String(url));
  log.debug("Leaving realmBaseOf().");
  return m ? m[1] : root;
}

// Follows redirects inside this service from `first`, signing in on each
// realm's own screen as the person that realm knows, and allowing a consent
// screen, until the answer leaves the service or is a page.
async function follow(who, first) {
  log.debug("Entering follow().");
  let r = first;
  let at = "";
  for (let i = 0; i < 20; i++) {
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const realmBase = realmBaseOf(at);
      const fields = hiddenFields(r.text);
      fields.username = realmBase === cpBase ? CP_PERSON : PERSON;
      fields.password = PASSWORD;
      fields.action = "login";
      at = realmBase + "/authn/login";
      r = await hop(who, "POST", at, { form: fields });
      continue;
    }
    if (r.status === 200 && /id="consent-allow"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      at = realmBaseOf(at) + "/oauth2/consent";
      r = await hop(who, "POST", at, { form: fields });
      continue;
    }
    if (!(r.status === 302 || r.status === 303) ||
        r.location.indexOf(root + "/") !== 0) {
      break;
    }
    at = r.location;
    r = await hop(who, "GET", at);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

// A JWT the provider realm signed, verified against its published keys.
async function verifiedByProvider(jwt) {
  log.debug("Entering verifiedByProvider().");
  const keys = (await hop(null, "GET", cpBase + "/oauth2/jwks")).json.keys;
  const [h, p, s] = String(jwt).split(".");
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
  const jwk = keys.filter(function (k) {
    return k.kid === header.kid;
  })[0];
  assert.ok(jwk, "the provider's JWKS has the kid " + header.kid);
  const digest = "sha" + String(header.alg).slice(2);
  const verified = crypto.verify(digest, Buffer.from(h + "." + p),
    { key: crypto.createPublicKey({ key: jwk, format: "jwk" }),
      padding: /^PS/.test(header.alg) ?
        crypto.constants.RSA_PKCS1_PSS_PADDING : undefined,
      dsaEncoding: /^ES/.test(header.alg) ? "ieee-p1363" : undefined },
    Buffer.from(s, "base64url"));
  log.debug("Leaving verifiedByProvider(). " + verified);
  return verified ? payloadOf(jwt) : null;
}

// The relying party's code flow in the OP realm, asking by name for
// credit_score and email; the token response.
async function rpTokens(browser, client) {
  log.debug("Entering rpTokens().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const q = new URLSearchParams({
    response_type: "code", client_id: client.client_id,
    redirect_uri: RP_REDIRECT, scope: "openid", state: "s-" + TAG,
    nonce: "n-" + TAG, code_challenge: challenge,
    code_challenge_method: "S256",
    claims: JSON.stringify({
      id_token: { credit_score: null, email: null },
      userinfo: { credit_score: null } }) });
  const landed = await follow(browser, await hop(browser, "GET",
    opBase + "/oauth2/authorize?" + q.toString()));
  assert.ok(/^https:\/\/rp\.claims\.example\/cb\?/.test(landed.location),
            "the authorization response: " + landed.status + " " +
            (landed.location || landed.text.slice(0, 300)));
  const code = new URL(landed.location).searchParams.get("code");
  const tokens = await hop(null, "POST", opBase + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code,
    redirect_uri: RP_REDIRECT, code_verifier: verifier,
    client_id: client.client_id, client_secret: client.client_secret } });
  assert.strictEqual(tokens.status, 200, "the token response: " +
                     tokens.text.slice(0, 300));
  log.debug("Leaving rpTokens().");
  return tokens.json;
}

// THE OP REALM MUST TRUST THIS SERVICE, because the Claims Provider it dials
// is a realm of this same service, whose certificate is issued under a Root
// made at start that its own outbound client does not know. The Root is read
// off the handshake and published in the directory shared with the service —
// a file of this job's own, so no other job's CA file is replaced — and named
// as the OP realm's federation.outboundCaFile, which product honours (#171).
// With no shared directory a development service is told to skip
// verification in the OP realm alone, as sts_ciba.js does; product refuses
// that, and the job says why.
async function trustThisService(product) {
  log.debug("Entering trustThisService().");
  const where = testCa.caLocation();
  if (where) {
    const target = new URL(root);
    const rootPem = await new Promise(function (resolve, reject) {
      const socket = tls.connect({ host: target.hostname,
        port: Number(target.port || 443), servername: target.hostname,
        rejectUnauthorized: false }, function () {
          let cert = socket.getPeerCertificate(true);
          while (cert && cert.issuerCertificate &&
                 cert.issuerCertificate !== cert &&
                 cert.issuerCertificate.fingerprint256 !==
                   cert.fingerprint256) {
            cert = cert.issuerCertificate;
          }
          socket.end();
          resolve("-----BEGIN CERTIFICATE-----\n" +
            cert.raw.toString("base64").match(/.{1,64}/g).join("\n") +
            "\n-----END CERTIFICATE-----\n");
        });
      socket.on("error", reject);
    });
    const name = "claims-aggregation-root-" + TAG + ".crt";
    fs.mkdirSync(where.dir, { recursive: true });
    fs.writeFileSync(path.join(where.dir, name), rootPem, { mode: 0o644 });
    await ok(opBase + "/admin-api/config/set", { key:
      "federation.outboundCaFile", value:
      path.join(path.dirname(where.serviceFile), name) },
      "named this service's Root as the OP realm's outbound CA");
    log.debug("Leaving trustThisService(). CA file.");
    return;
  }
  assert.ok(!product, testCa.skipReason());
  await ok(opBase + "/admin-api/config/set", { key:
    "federation.outboundSkipTlsVerification", value: true },
    "let the OP realm reach the provider realm");
  log.debug("Leaving trustThisService(). Verification skipped.");
}

async function register(realmBase, metadata) {
  log.debug("Entering register().");
  const r = await hop(null, "POST", realmBase + "/oauth2/register",
                      { json: metadata });
  assert.strictEqual(r.status, 201, "registration: " + r.text.slice(0, 300));
  log.debug("Leaving register().");
  return r.json;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms: " + OP + " (the OP) and " + CP +
           " (the Claims Provider) ===");
  for (const id of [OP, CP]) {
    await ok(root + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Claims Aggregation " + id },
      "created " + id);
    await ok(root + "/realm/" + id + "/admin-api/config/set",
             { key: "oauth2.openRegistration", value: true },
             "opened registration in " + id);
  }
  await trustThisService(await facts.isProduct(root + "/admin-api"));
  await registry.ensurePerson(opBase, PERSON, PASSWORD);
  await registry.ensurePerson(cpBase, CP_PERSON, PASSWORD);
  // The provider realm's UserInfo carries credit_score for everybody — a
  // claim the OP realm's catalogue has no name for.
  const sets = (await hop(null, "GET", cpBase + "/admin-api/userinfo-claims"))
    .json;
  const setId = (sets.sets || sets.claimSets || [])
    .map(function (s) { return s.id || s; })[0] || "userinfo";
  await ok(cpBase + "/admin-api/userinfo-claims/add",
           { set: setId, name: "credit_score", value: SCORE },
           "configured credit_score in the provider realm");
  const cpClient = await register(cpBase, {
    redirect_uris: [opBase + "/portal/claim-sources/callback"],
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"], scope: "openid profile",
    userinfo_signed_response_alg: "RS256", client_name: "OP " + OP });

  log.info("=== 1. the register ===");
  const added = await ok(opBase + "/admin-api/claim-providers/add-provider", {
    id: "cp", name: "The provider realm", issuer: cpBase, discover: true,
    clientId: cpClient.client_id, clientSecret: cpClient.client_secret,
    authMethod: "client_secret_basic", scope: "openid",
    claims: ["credit_score"], delivery: "aggregated" },
    "registered the Claims Provider by discovery");
  const view = (await hop(null, "GET", opBase + "/admin-api/claim-providers"))
    .json;
  const discovery = (await hop(null, "GET", opBase +
                               "/.well-known/openid-configuration")).json;
  check("registered by discovery, the secret held and never shown, the " +
        "redirect URI given, and all three claim types published",
        function () {
    assert.ok(/registered/.test(added.message), JSON.stringify(added));
    const p = view.providers.filter(function (x) {
      return x.id === "cp";
    })[0];
    assert.ok(p, JSON.stringify(view).slice(0, 400));
    assert.strictEqual(p.tokenEndpoint, cpBase + "/oauth2/token");
    assert.strictEqual(p.claimsEndpoint, cpBase + "/oauth2/userinfo");
    assert.strictEqual(p.hasSecret, true);
    assert.ok(JSON.stringify(view).indexOf(cpClient.client_secret) < 0);
    assert.strictEqual(view.redirectUri,
                       opBase + "/portal/claim-sources/callback");
    assert.deepStrictEqual(discovery.claim_types_supported,
                           ["normal", "aggregated", "distributed"]);
  });

  log.info("=== 2. the person links the provider on the portal ===");
  const browser = jar();
  const page = await follow(browser, await hop(browser, "GET",
    opBase + "/portal/claim-sources"));
  assert.strictEqual(page.status, 200, "the portal page: " +
                     page.text.slice(0, 300));
  const unknown = await hop(browser, "POST", opBase + "/portal/claim-sources",
    { form: { action: "link", id: "nobody", csrf_token: csrfOf(page.text) } });
  const started = await hop(browser, "POST", opBase + "/portal/claim-sources",
    { form: { action: "link", id: "cp", csrf_token: csrfOf(page.text) } });
  const back = await follow(browser, started);
  const links = (await hop(null, "GET", opBase + "/admin-api/claim-providers"))
    .json.links;
  check("an unknown provider is refused; Link goes to the provider realm, " +
        "and the person comes back linked, with no token shown anywhere",
        function () {
    assert.strictEqual(unknown.status, 400, unknown.status + " " +
      (/class="(?:error|msg)[^"]*"[^>]*>([^<]*)/.exec(unknown.text) || [])[1]);
    assert.strictEqual(started.status, 303);
    assert.ok(started.location.indexOf(cpBase + "/oauth2/authorize?") === 0,
              started.location);
    assert.ok(/code_challenge_method=S256/.test(started.location));
    assert.strictEqual(back.status, 200, back.status + " " +
                       back.text.slice(0, 300));
    assert.ok(/Linked/.test(back.text), back.status + " " +
      ((/<title>([^<]*)/.exec(back.text) || [])[1] || "") + " " +
      ((/class="(?:error|err|msg|flash)[^"]*"[^>]*>([^<]*)/
        .exec(back.text) || [])[1] || back.text.replace(/<style[^]*?<\/style>/, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 900)));
    const mine = links.filter(function (l) {
      return l.username === PERSON && l.provider === "cp";
    });
    assert.strictEqual(mine.length, 1, JSON.stringify(links).slice(0, 300));
    assert.ok(mine[0].sub, "the person's subject at the provider");
    assert.ok(JSON.stringify(links).indexOf("access_token") < 0);
  });
  const theirSub = links.filter(function (l) {
    return l.username === PERSON;
  })[0].sub;

  log.info("=== 3. aggregated claims in the ID Token and UserInfo ===");
  const rp = await register(opBase, {
    redirect_uris: [RP_REDIRECT], token_endpoint_auth_method:
      "client_secret_post", grant_types: ["authorization_code"],
    response_types: ["code"], scope: "openid email", client_name: "RP" });
  const tokens = await rpTokens(browser, rp);
  const idToken = payloadOf(tokens.id_token);
  const userinfo = await hop(null, "GET", opBase + "/oauth2/userinfo",
    { headers: { Authorization: "Bearer " + tokens.access_token } });
  const fromIdToken = idToken._claim_sources && idToken._claim_sources.cp &&
    await verifiedByProvider(idToken._claim_sources.cp.JWT);
  const fromUserinfo = userinfo.json && userinfo.json._claim_sources &&
    await verifiedByProvider(userinfo.json._claim_sources.cp.JWT);
  check("the ID Token references credit_score to the provider, whose " +
        "signed JWT carries it about the person's subject there; email is " +
        "the entry's own", function () {
    assert.deepStrictEqual(idToken._claim_names, { credit_score: "cp" },
                           JSON.stringify(idToken).slice(0, 400));
    assert.ok(fromIdToken, "the source verified against the provider's keys");
    assert.strictEqual(fromIdToken.iss, cpBase);
    assert.strictEqual(fromIdToken.sub, theirSub);
    assert.strictEqual(String(fromIdToken.credit_score), SCORE);
    assert.strictEqual(idToken.credit_score, undefined);
    assert.ok(!idToken._claim_names.email);
  });
  check("UserInfo carries the same aggregated source", function () {
    assert.strictEqual(userinfo.status, 200, userinfo.text.slice(0, 300));
    assert.deepStrictEqual(userinfo.json._claim_names,
                           { credit_score: "cp" });
    assert.strictEqual(String(fromUserinfo.credit_score), SCORE);
  });

  log.info("=== 4. distributed ===");
  await ok(opBase + "/admin-api/claim-providers/update-provider",
           { id: "cp", delivery: "distributed" }, "switched to distributed");
  const distributed = payloadOf((await rpTokens(browser, rp)).id_token);
  const source = (distributed._claim_sources || {}).cp || {};
  const fetched = source.endpoint ? await hop(null, "GET", source.endpoint,
    { headers: { Authorization: "Bearer " + source.access_token } }) :
    { status: 0, text: "" };
  check("a distributed source is the provider's endpoint and a token that " +
        "answers credit_score there", function () {
    assert.strictEqual(source.endpoint, cpBase + "/oauth2/userinfo",
                       JSON.stringify(distributed).slice(0, 400));
    assert.ok(source.access_token && !source.JWT);
    assert.strictEqual(fetched.status, 200, fetched.text.slice(0, 200));
    const answered = fetched.json || payloadOf(fetched.text);
    assert.strictEqual(String(answered.credit_score), SCORE);
  });
  await ok(opBase + "/admin-api/claim-providers/update-provider",
           { id: "cp", delivery: "aggregated" }, "back to aggregated");

  log.info("=== 5. revocation and unlinking ===");
  await ok(opBase + "/admin-api/claim-providers/revoke-link",
           { username: PERSON, provider: "cp" }, "revoked the link");
  const afterRevoke = payloadOf((await rpTokens(browser, rp)).id_token);
  const again = await hop(null, "POST", opBase +
    "/admin-api/claim-providers/revoke-link",
    { json: { username: PERSON, provider: "cp" } });
  const pageAgain = await hop(browser, "GET", opBase + "/portal/claim-sources");
  const unlink = await hop(browser, "POST", opBase + "/portal/claim-sources",
    { form: { action: "unlink", id: "cp",
              csrf_token: csrfOf(pageAgain.text) } });
  check("a revoked link sends no source; revoking twice and unlinking what " +
        "is not linked are refused", function () {
    assert.strictEqual(afterRevoke._claim_sources, undefined,
                       JSON.stringify(afterRevoke).slice(0, 300));
    assert.strictEqual(again.status, 400, again.text.slice(0, 200));
    assert.strictEqual(unlink.status, 400, unlink.text.slice(0, 200));
  });

  assert.ok(checks >= 6, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Connect Claims Aggregation (#147): the register, " +
    "linking a provider on the portal, aggregated and distributed claims, " +
    "revocation — with a realm of this service as the Claims Provider.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
