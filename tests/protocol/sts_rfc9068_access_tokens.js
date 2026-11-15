// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9068_access_tokens.js
//
// ---------------------------------------------------------------------------
// EVERY ACCESS TOKEN IS AN RFC 9068 JWT ACCESS TOKEN, AND EVERY RESOURCE
// SERVER HERE CHECKS SECTION 4, OVER THE WIRE.
//
// D12 (#444): carries section 3 of `tests/rfc9068_access_tokens.js` — the
// endpoints — to a running service, in a throwaway realm whose clients,
// resource servers and roles are written through `/admin-api`; the codes are
// read off `/admin-api/audit`:
//
//   a–e. client_credentials: the header is typ at+jwt, the seven REQUIRED
//      claims are there, iss is this realm and aud the client itself, no
//      scope claim for a token granted none, no end user, sub is the client,
//      and `roles` is what the APPLICATION holds (not a person of the same
//      name) (#93);
//   f–h. the password grant with openid profile: an access token and an ID
//      Token, no profile claim on the access token (they are UserInfo's,
//      #395), and UserInfo answering them for that token;
//   j–k. an ID Token presented as an access token is refused for its
//      header at UserInfo and at `/admin-api` (STS-OAUTH-0247);
//   l–m. resource=partner: aud is the partner, openid left off, the ID Token
//      still issued, and UserInfo refusing it for its audience
//      (STS-OAUTH-0114);
//   n. openid profile <API>: aud is the API alone, no OpenID Connect scope,
//      an ID Token; n-ii. client_credentials for the API carries the
//      client's realm-wide role and its API role (#93, #310);
//   o–r. the token endpoint's refusals: two APIs in a scope (invalid_scope,
//      STS-OAUTH-0244), a resource beside a scope naming another API
//      (STS-OAUTH-0245), two resources and a scope tied to neither
//      (invalid_target, STS-OAUTH-0246), and two resources with no scope
//      issued, addressed to both.
//
// NOT carried, and why: sections 1 and 2 (the `typ` reader's case and prefix
// rules, the issuer and audience readers, the audience plan as a decision)
// are a library's, observed here only through the answers above — class
// (d); 3i, a token presented under ANOTHER host name (STS-OAUTH-0248), needs
// a service whose issuer follows the Host header, and a stack with
// `publicBaseUrl` set (every launcher's, and this probe's) names one issuer
// whatever the Host says — class (d) here.
//
// OWNED HERE (local: true): applications and roles of this service's own
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_rfc9068_access_tokens");
const log = K.log;

const ID = "r9-client";
const SECRET = "r9-secret-" + K.rand(16) + "-0123456789abcdef";
const PERSON = "r9-alice-" + K.STAMP;
const PASSWORD = "R9-" + K.rand(9) + "-pw!";
const PARTNER = "https://api.partner.example/resource";
const FLOOR = 20;

let R;
let ISS;

function check(what, fn) {
  K.check(what, fn);
}

function claimsOf(token) {
  log.debug("Entering claimsOf().");
  const d = K.decode(token);
  assert.ok(d, "not a JWS: " + token);
  log.debug("Leaving claimsOf().");
  return d;
}

function token(form) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(R) + "/oauth2/token", { form: typeof form === "string"
    ? form + "&client_id=" + ID + "&client_secret=" + SECRET
    : Object.assign({ client_id: ID, client_secret: SECRET }, form) });
}

function bearer(path, value) {
  log.debug("Entering bearer().");
  log.debug("Leaving bearer().");
  return K.send(K.rb(R) + path, { headers: {
    Authorization: "Bearer " + value } });
}

async function setUp() {
  log.debug("Entering setUp().");
  R = await K.realm("r9068", "development");
  ISS = (await K.send(K.rb(R) + "/.well-known/openid-configuration"))
    .json.issuer;
  await K.app(R, ID, { oauthClientId: [ID], oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthGrantType: ["password", "client_credentials"] },
    { protocols: ["oauth2"] });
  for (const api of ["r9-api-a", "r9-api-b"]) {
    await K.app(R, api, { oauthClientId: [api] }, { protocols: ["oauth2"] });
  }
  for (const pair of [["r9-partner", PARTNER],
                      ["r9-x", "https://x.example/"],
                      ["r9-a", "https://a.example/"],
                      ["r9-b", "https://b.example/"]]) {
    await K.ok(K.rb(R) + "/admin-api/applications/create", {
      identifier: pair[0], name: pair[0], kind: "oauth2-resource-server",
      protocols: ["oauth2"], fields: { oauthAudience: [pair[1]] } },
      "registered the resource " + pair[0]);
  }
  await K.person(R, PERSON, PASSWORD);
  // A person NAMED like the client, holding a role the client must never
  // be found holding (#93).
  await K.person(R, ID, PASSWORD);
  const api = K.rb(R) + "/admin-api/roles/";
  await K.ok(api + "create-role", { role: "r9-batch" }, "role r9-batch");
  await K.ok(api + "add-member", { role: "r9-batch", kind: "application",
                                   member: ID }, "r9-batch to the client");
  await K.ok(api + "create-role", { role: "reader", application: "r9-api-a",
    memberTypes: ["application"] }, "role reader of r9-api-a");
  await K.ok(api + "add-member", { role: "reader@r9-api-a",
    kind: "application", member: ID }, "reader to the client");
  await K.ok(api + "create-role", { role: "r9-person-role" },
             "role r9-person-role");
  await K.ok(api + "add-member", { role: "r9-person-role", kind: "user",
                                   member: ID }, "it to the person");
  log.debug("Leaving setUp().");
}

async function clientCredentials() {
  log.debug("Entering clientCredentials().");
  log.info("=== a-e. client_credentials ===");
  const r = await token({ grant_type: "client_credentials" });
  assert.strictEqual(r.status, 200, K.shown(r));
  const d = claimsOf(r.json.access_token);
  const c = d.payload;
  check("a. section 2.1: the header is typ at+jwt with a signing alg",
        function () {
    assert.strictEqual(d.header.typ, "at+jwt");
    assert.ok(d.header.alg && d.header.alg !== "none", d.header.alg);
  });
  check("b. section 2.2: iss, exp, aud, sub, client_id, iat and jti are " +
        "all there", function () {
    ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
      .forEach(function (k) {
        assert.ok(c[k] !== undefined, k + " in " + JSON.stringify(c));
      });
  });
  check("c. iss is this realm's issuer and aud, for a token asking for " +
        "nothing, the client itself (#550)", function () {
    assert.strictEqual(c.iss, ISS);
    assert.strictEqual(c.aud, ID, JSON.stringify(c.aud));
  });
  check("d. section 2.2.3: a token granted no scope carries no scope claim",
        function () {
    assert.ok(!("scope" in c), JSON.stringify(c));
  });
  check("e. no end user: no preferred_username, username or auth_time, and " +
        "sub and client_id are the client (#93)", function () {
    assert.ok(!("preferred_username" in c) && !("username" in c) &&
              !("auth_time" in c), JSON.stringify(c));
    assert.strictEqual(c.sub, ID);
    assert.strictEqual(c.client_id, ID);
  });
  check("e-ii. roles is the roles the APPLICATION holds, not the person " +
        "of the same name's", function () {
    assert.deepStrictEqual(c.roles, ["r9-batch"], JSON.stringify(c.roles));
  });
  log.debug("Leaving clientCredentials().");
}

async function password() {
  log.debug("Entering password().");
  log.info("=== f-k. the password grant, UserInfo, an ID Token ===");
  const r = await token({ grant_type: "password", username: PERSON,
                          password: PASSWORD, scope: "openid profile" });
  check("f. the password grant issued an access token and an ID Token",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(r.json.access_token && r.json.id_token);
  });
  const c = claimsOf(r.json.access_token).payload;
  check("g. section 2.2.2 and #395: no profile claim on the access token; " +
        "username and scope are", function () {
    assert.ok(c.preferred_username === undefined &&
              c.given_name === undefined && c.name === undefined,
              JSON.stringify(c));
    assert.strictEqual(c.username, PERSON);
    assert.strictEqual(c.scope, "openid profile");
  });
  const u = await bearer("/oauth2/userinfo", r.json.access_token);
  check("h. UserInfo accepts it and answers the profile claims",
        function () {
    assert.strictEqual(u.status, 200, K.shown(u));
    assert.ok(/^urn:uuid:/.test(u.json.sub), u.text);
    assert.strictEqual(u.json.sub, c.sub);
    assert.strictEqual(u.json.preferred_username, PERSON);
  });
  const id = await K.coded(R, "STS-OAUTH-0247", function () {
    return bearer("/oauth2/userinfo", r.json.id_token);
  });
  check("j. section 4 step 1: an ID Token signed by the same key is " +
        "refused at UserInfo for its header (STS-OAUTH-0247)", function () {
    assert.strictEqual(id.answer.status, 401, K.shown(id.answer));
    assert.ok(/at\+jwt/.test(id.answer.text), id.answer.text);
    assert.ok(id.rose >= 1, "STS-OAUTH-0247 rows: " + id.rose);
  });
  const admin = await bearer("/admin-api/status", r.json.id_token);
  check("k. and at /admin-api, whose gate verifies with the same key",
        function () {
    assert.strictEqual(admin.status, 401, K.shown(admin));
    assert.ok(/at\+jwt/.test(admin.text), admin.text);
  });
  log.debug("Leaving password().");
}

async function audiences() {
  log.debug("Entering audiences().");
  log.info("=== l-n. audiences ===");
  const p = await token({ grant_type: "password", username: PERSON,
                          password: PASSWORD, scope: "openid",
                          resource: PARTNER });
  assert.strictEqual(p.status, 200, K.shown(p));
  const pc = claimsOf(p.json.access_token).payload;
  check("l. resource=partner: aud is the partner, openid is left off the " +
        "access token and the ID Token is still issued", function () {
    assert.strictEqual(pc.aud, PARTNER, JSON.stringify(pc));
    assert.ok(!("scope" in pc), JSON.stringify(pc));
    assert.ok(p.json.id_token);
  });
  const ui = await K.coded(R, "STS-OAUTH-0114", function () {
    return bearer("/oauth2/userinfo", p.json.access_token);
  });
  check("m. and UserInfo refuses it for its audience (STS-OAUTH-0114): a " +
        "URL ending in /resource is not this resource server", function () {
    assert.strictEqual(ui.answer.status, 401, K.shown(ui.answer));
    assert.ok(/aud/.test(ui.answer.text), ui.answer.text);
    assert.ok(ui.rose >= 1, "STS-OAUTH-0114 rows: " + ui.rose);
  });
  const n = await token({ grant_type: "password", username: PERSON,
    password: PASSWORD, scope: "openid profile r9-api-a" });
  check("n. openid profile r9-api-a: aud is r9-api-a alone, no OpenID " +
        "Connect scope on it or in the response, and an ID Token",
        function () {
    assert.strictEqual(n.status, 200, K.shown(n));
    const c = claimsOf(n.json.access_token).payload;
    assert.strictEqual(c.aud, "r9-api-a", JSON.stringify(c));
    assert.ok(!("scope" in c), JSON.stringify(c));
    assert.ok(n.json.id_token);
    assert.ok(!/openid/.test(n.json.scope || ""), n.json.scope);
  });
  const cc = await token({ grant_type: "client_credentials",
                           scope: "r9-api-a" });
  check("n-ii. client_credentials for r9-api-a carries the client's " +
        "realm-wide role and its r9-api-a role as reader (#93, #310)",
        function () {
    assert.strictEqual(cc.status, 200, K.shown(cc));
    const c = claimsOf(cc.json.access_token).payload;
    assert.strictEqual(c.aud, "r9-api-a");
    assert.deepStrictEqual(c.roles, ["r9-batch", "reader"],
                           JSON.stringify(c.roles));
    assert.ok(!("username" in c));
  });
  log.debug("Leaving audiences().");
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== o-r. the token endpoint's refusals ===");
  const o = await K.coded(R, "STS-OAUTH-0244", function () {
    return token({ grant_type: "client_credentials",
                   scope: "r9-api-a r9-api-b" });
  });
  check("o. two applications in one scope: invalid_scope (STS-OAUTH-0244)",
        function () {
    assert.strictEqual(o.answer.status, 400, K.shown(o.answer));
    assert.strictEqual(o.answer.json.error, "invalid_scope");
    assert.strictEqual(o.rose, 1, "STS-OAUTH-0244 rows: " + o.rose);
  });
  const p = await K.coded(R, "STS-OAUTH-0245", function () {
    return token({ grant_type: "client_credentials", scope: "r9-api-a",
                   resource: "https://x.example/" });
  });
  check("p. resource=X with a scope naming r9-api-a: invalid_scope " +
        "(STS-OAUTH-0245)", function () {
    assert.strictEqual(p.answer.status, 400, K.shown(p.answer));
    assert.strictEqual(p.answer.json.error, "invalid_scope");
    assert.strictEqual(p.rose, 1, "STS-OAUTH-0245 rows: " + p.rose);
  });
  const two = "&resource=" + encodeURIComponent("https://a.example/") +
    "&resource=" + encodeURIComponent("https://b.example/");
  const q = await K.coded(R, "STS-OAUTH-0246", function () {
    return token("grant_type=client_credentials&scope=read" + two);
  });
  check("q. two resources and a scope tied to neither: invalid_target " +
        "(STS-OAUTH-0246)", function () {
    assert.strictEqual(q.answer.status, 400, K.shown(q.answer));
    assert.strictEqual(q.answer.json.error, "invalid_target");
    assert.strictEqual(q.rose, 1, "STS-OAUTH-0246 rows: " + q.rose);
  });
  const r = await token("grant_type=client_credentials" + two);
  check("r. two resources and no scope: issued, addressed to both",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    const aud = claimsOf(r.json.access_token).payload.aud;
    assert.ok(Array.isArray(aud) && aud.length === 2, JSON.stringify(aud));
  });
  check("no refusal names a code", function () {
    [o, p, q].forEach(function (one) {
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(one.answer.text), one.answer.text);
    });
  });
  log.debug("Leaving refusals().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await clientCredentials();
  await password();
  await audiences();
  await refusals();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
