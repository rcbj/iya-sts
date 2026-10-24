// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_own_token_chain.js
//
// ---------------------------------------------------------------------------
// THE FOUR-TIER WS-TRUST OnBehalfOf CHAIN, WITH EACH TIER AUTHENTICATED BY A
// TOKEN IT WAS ISSUED FOR ITSELF, AND THE MATRIX OF EVERY TOKEN TYPE IN EVERY
// SEAT (#519).
//
// rcbj, 2026-10-08: "maximum flexibility in supported input / output token
// types for the WS-Trust protocol", and these tests are, in part, the proof
// of it. Three seats take a token in an RST:
//
//   * the requester's credential, in `wsse:Security`;
//   * the token about the person, inside `<wst:OnBehalfOf>`;
//   * and the token asked for, `wst:TokenType`.
//
// Each takes SAML 2.0, SAML 1.1 and JWT, and the requester's seat a
// UsernameToken besides.
//
// **1. THE CHAINS** (one per token type: SAML 2.0, SAML 1.1, JWT). The
// shape is `sts_wstrust_chain_impersonation.js`'s — bob signs in to
// webapp1 with his UsernameToken, then webapp1, apigw1 and esb1 each send an
// `<wst:OnBehalfOf>` for the next tier's registered identifier — with one
// difference at every hop, which is the point of the job:
//
//   a. the tier first sends an Issue of its own: a UsernameToken naming
//      its APPLICATION with one of that application's client secrets, for
//      its OWN registered identifier (rcbj's decisions on #519: the token is
//      for the tier itself, and no service account sits beside the
//      application). The token that comes back is about the tier;
//   b. the OnBehalfOf then carries THAT token in `wsse:Security`, where the
//      UsernameToken was, and the token about bob from the hop before inside
//      the element.
//
// What each hop issues is asserted exactly as the matching existing job
// asserts it (the kit's `assertChainAssertion()`, `assertChainAssertion11()`
// and `assertChainJwt()`): about bob, restricted to the next tier, a new
// identifier, the application's claim settings, and for a JWT `client_id`
// the requester's application. The tier's own token is asserted to be about
// the tier and for the tier. The register's act names the requester's own
// token as its credential — the identifier of the token the tier was issued
// for itself — beside the token it consumed inside the element; and no
// person is made for any tier, which is what "no service account" means in
// the directory.
//
// **2. THE MATRIX.** webapp1, for apigw1, in one RST each: every requester
// credential (its application's UsernameToken, and its own SAML 2.0, SAML
// 1.1 and JWT) × every OnBehalfOf input (bob's sign-in token in each of the
// three types) × every issued type — thirty-six requests, each answered
// with a token of the type asked for, about bob, for apigw1.
//
// IN DEVELOPMENT AND PRODUCT MODE ALIKE (GET /admin-api/mode). The entries
// are left behind; a rerun reconciles them and mints fresh secrets.
//
// OWNED HERE (local: true): the chain and the matrix are this repository's
// own scenario.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./wstrust_chain_kit.js");
const http = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_wstrust_own_token_chain",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const SEMANTICS = "impersonation";
const ELEMENT = "OnBehalfOf";
// The clock skew the target allows itself when it reads the Conditions.
const SKEW_MS = 60000;
// One cast per token type; a tag of its own keeps each one's entries apart.
const KINDS = [
  { tag: "wsot2", type: "saml", label: "SAML 2.0" },
  { tag: "wsot11", type: "saml11", label: "SAML 1.1" },
  { tag: "wsotj", type: "jwt", label: "JWT" }
];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// A JWT's claims, decoded: the service verified it when it was presented,
// and the chain's own checks verify every JWT about bob.
function claimsOf(token) {
  log.debug("Entering claimsOf().");
  const parts = String(token || "").split(".");
  assert.strictEqual(parts.length, 3, "not a compact JWS: " +
                     String(token).slice(0, 80));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// The token type URI an RST asks for, by the kit's short name.
function typeUri(type) {
  log.debug("Entering typeUri(). " + type);
  log.debug("Leaving typeUri().");
  return type === "jwt" ? kit.JWT_TOKEN_TYPE
    : type === "saml11" ? kit.SAML11_TOKEN_TYPE : kit.SAML2_TOKEN_TYPE;
}

// THE TIER'S OWN TOKEN IS ABOUT THE TIER AND FOR THE TIER, whatever its
// type: a SAML NameID / NameIdentifier naming its application, or a JWT
// whose sub is its client subject and whose client_id is its own.
function assertOwnToken(tier, own, type, namespaced) {
  log.debug("Entering assertOwnToken(). " + tier.identifier + " " + type);
  let id = "";
  if (type === "jwt") {
    const c = claimsOf(own.jwt);
    const sub = namespaced ? "urn:sts:client:" + tier.identifier
                           : tier.identifier;
    assert.strictEqual(c.sub, sub, tier.identifier + "'s own JWT is about " +
                       JSON.stringify(c.sub) + " rather than " + sub);
    assert.strictEqual(c.aud, tier.appliesTo, tier.identifier + "'s own " +
                       "JWT is for " + JSON.stringify(c.aud));
    assert.strictEqual(c.client_id, tier.identifier, tier.identifier +
                       "'s own JWT names the client " + c.client_id);
    assert.strictEqual(c.act, undefined, tier.identifier + "'s own JWT " +
                       "names an actor");
    id = String(c.jti || "");
  } else {
    const got = type === "saml11" ? kit.read11(own.assertion)
                                  : kit.read(own.assertion);
    assert.strictEqual(got.nameId, tier.identifier, tier.identifier +
                       "'s own assertion is about " + got.nameId);
    assert.deepStrictEqual(got.audiences, [tier.appliesTo], tier.identifier +
                           "'s own assertion is for " +
                           JSON.stringify(got.audiences));
    id = got.id;
  }
  assert.ok(id, tier.identifier + "'s own token carries no identifier");
  log.debug("Leaving assertOwnToken().");
  return id;
}

// NO PERSON IS MADE FOR A TIER: the directory holds no `uid=<tier>` entry.
async function assertNoPerson(base, tier) {
  log.debug("Entering assertNoPerson(). " + tier.identifier);
  const r = await http.adminGet(base, "/ldap/directory?q=" +
                                encodeURIComponent(tier.identifier) +
                                "&per=50");
  assert.ok(r && Array.isArray(r.entries), "GET /admin-api/ldap/directory " +
            "answered no entries list: " + JSON.stringify(r).slice(0, 300));
  const rows = r.entries;
  const people = rows.filter(function (row) {
    return /^uid=/i.test(String(row.dn || "")) &&
      String(row.dn || "").toLowerCase()
        .indexOf("uid=" + tier.identifier.toLowerCase() + ",") === 0;
  });
  assert.strictEqual(people.length, 0, "the directory holds a person for " +
                     "the application " + tier.identifier + ": " +
                     JSON.stringify(people.map(function (one) {
                       return one.dn;
                     })));
  log.debug("Leaving assertNoPerson().");
}

// ---------------------------------------------------------------------------
// 1. ONE CHAIN, of `kind`'s token type.
// ---------------------------------------------------------------------------
async function chainOf(base, kind, product) {
  log.debug("Entering chainOf(). " + kind.label);
  const cast = kit.castFor(kind.tag, kind.type);
  const jwt = kind.type === "jwt";
  const saml11 = kind.type === "saml11";
  log.info("=== The " + kind.label + " chain, each tier on its own token: " +
           cast.user + " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " ===");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS,
                          { applicationSecrets: true });
  check("1a (" + kind.label + "). the four applications register their " +
        "identifiers, the three requesters impersonate towards the next " +
        "tier only, and each holds a fresh client secret", function () {
    cast.requesters.forEach(function (tier) {
      assert.ok(tier.secret, tier.identifier + " has no client secret");
    });
  });
  const namespaced = await kit.clientSubjectsNamespaced(base, product);
  const keys = jwt ? await kit.jwks(base) : null;
  const issuer = jwt ? await kit.publishedIssuer(base) : "";
  const issuers = [];
  if (!jwt) {
    for (let i = 0; i < cast.tiers.length; i++) {
      issuers.push(await kit.samlIssuerFor(base, cast.tiers[i], product));
    }
  }

  // THE SIGN-IN, as in the matching existing job.
  const signedIn = await kit.signIn(base, cast);
  const assertHop = function (answer, expect) {
    log.debug("Entering assertHop(). " + expect.what);
    let out;
    if (jwt) {
      out = kit.assertChainJwt(cast, answer, keys, {
        what: expect.what, audience: expect.audience, issuer: issuer,
        sub: expect.sub, clientId: expect.clientId, act: undefined,
        product: product, notJtis: expect.notIds });
    } else if (saml11) {
      out = kit.assertChainAssertion11(cast, answer.assertion, {
        what: expect.what, audience: expect.audience,
        issuer: issuers[expect.index], notAudience: expect.notAudience,
        notIds: expect.notIds, authnMethod: expect.first
          ? kit.AM_PASSWORD : kit.AM_UNSPECIFIED });
    } else {
      out = kit.assertChainAssertion(cast, answer.assertion, {
        what: expect.what, audience: expect.audience,
        issuer: issuers[expect.index], notAudience: expect.notAudience,
        notIds: expect.notIds, delegates: [], authnContext: expect.first
          ? kit.AC_PASSWORD : kit.AC_UNSPECIFIED });
    }
    log.debug("Leaving assertHop().");
    return out;
  };
  const idOf = function (one) {
    log.debug("Entering idOf().");
    log.debug("Leaving idOf().");
    return jwt ? one.claims.jti : one.id;
  };
  const tokens = [];
  check("1b (" + kind.label + "). bob's sign-in token: about " + cast.user +
        ", for " + cast.webapp.appliesTo, function () {
    tokens.push(assertHop(signedIn, {
      what: cast.user + "'s sign-in token", audience: cast.webapp.appliesTo,
      index: 0, first: true, clientId: "", notIds: [] }));
  });

  const answers = [signedIn];
  const ownIds = [];
  for (let i = 0; i < cast.requesters.length; i++) {
    const tier = cast.requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier + " asks for " +
             "its own " + kind.label + ", then <OnBehalfOf> for " +
             next.appliesTo + " with it ===");
    const own = await kit.selfToken(base, cast, tier);
    check("1c" + "abc"[i] + " (" + kind.label + "). " + tier.identifier +
          "'s application, by its client secret, is issued a token about " +
          "itself and for itself (" + tier.appliesTo + ")", function () {
      ownIds.push(assertOwnToken(tier, own, kind.type, namespaced));
    });
    const answer = await kit.exchangeWith(base, cast, tier, ELEMENT,
                                          answers[i].inner, own);
    answers.push(answer);
    check("1d" + "abc"[i] + " (" + kind.label + "). " + tier.identifier +
          ", authenticated by its own token, is issued a token about " +
          cast.user + " for " + next.appliesTo + " and no tier it has left",
          function () {
      tokens.push(assertHop(answer, {
        what: tier.identifier + "'s OnBehalfOf token",
        audience: next.appliesTo, index: i + 1, first: false,
        sub: jwt ? tokens[0].claims.sub : undefined,
        clientId: tier.identifier,
        notAudience: cast.tiers.slice(0, i + 1).map(function (one) {
          return one.appliesTo;
        }),
        notIds: tokens.map(idOf) }));
    });
  }

  const final = tokens[tokens.length - 1];
  if (jwt) {
    check("1e (JWT). sp1's own validation: the published key, typ at+jwt, " +
          cast.provider.appliesTo + " in aud, the issuer GET /sts names, " +
          "the clock", function () {
      kit.validateJwtAtTarget(final.token, keys, cast.provider.appliesTo,
                              issuer, SKEW_MS);
    });
  } else {
    const certPem = await kit.signingCertificate(base);
    check("1e (" + kind.label + "). sp1's own validation: the signature " +
          "against the realm's published certificate, the Conditions, " +
          cast.provider.appliesTo + " the one audience, about " + cast.user,
          function () {
      const atTarget = saml11
        ? kit.validateAtTarget11(final.xml, certPem,
                                 cast.provider.appliesTo, SKEW_MS)
        : kit.validateAtTarget(final.xml, certPem,
                               cast.provider.appliesTo, SKEW_MS);
      assert.strictEqual(atTarget.nameId, cast.user);
    });
  }

  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = cast.requesters.map(function (tier, i) {
    return { clientId: tier.identifier, target: tier.next,
             appliesTo: kit.tierNamed(cast, tier.next).appliesTo,
             consumedId: idOf(tokens[i]), producedId: idOf(tokens[i + 1]),
             ownId: ownIds[i] };
  });
  hops.forEach(function (hop, i) {
    const act = kit.actProducing(since.acts, hop.producedId, hop.clientId +
                                 "'s OnBehalfOf token");
    check("1f" + "abc"[i] + " (" + kind.label + "). the register: one " +
          "wstrust-onbehalfof act by " + hop.clientId + " for " + cast.user +
          " to " + hop.target + ", its credential the token " + hop.ownId +
          " it was issued for itself, consuming " + hop.consumedId +
          " and producing " + hop.producedId, function () {
      kit.assertAct(cast, act, {
        type: "wstrust-onbehalfof", mode: "impersonation",
        semantics: SEMANTICS, requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, requesterTokenId: hop.ownId,
        producedKind: jwt ? "JWT" : saml11 ? "SAML 1.1 assertion"
                                           : "SAML 2.0 assertion",
        product: product });
    });
  });
  check("1g (" + kind.label + "). the picture: " + cast.gateway.identifier +
        " and " + cast.esb.identifier + " each ONE box, reached by one hop " +
        "and in the middle of the next", function () {
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(0, 2),
                            "impersonation");
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(1, 3),
                            "impersonation");
  });
  for (let i = 0; i < cast.requesters.length; i++) {
    const tier = cast.requesters[i];
    await assertNoPerson(base, tier);
    check("1h" + "abc"[i] + " (" + kind.label + "). no person was made for " +
          "the application " + tier.identifier, function () {});
  }
  log.debug("Leaving chainOf().");
  return cast;
}

// ---------------------------------------------------------------------------
// 2. THE MATRIX: webapp1, for apigw1, every credential × every input ×
// every output, in the SAML 2.0 chain's cast.
// ---------------------------------------------------------------------------
async function matrix(base, cast, product) {
  log.debug("Entering matrix().");
  const webapp = cast.webapp;
  const gateway = cast.gateway;
  const types = ["saml", "saml11", "jwt"];
  const label = { saml: "SAML 2.0", saml11: "SAML 1.1", jwt: "JWT" };
  const tokenOf = function (answer) {
    log.debug("Entering tokenOf().");
    log.debug("Leaving tokenOf().");
    return answer.jwt ? answer.inner : answer.assertion;
  };
  // bob's sign-in token, in each type: the OnBehalfOf input.
  const inputs = {};
  for (const type of types) {
    inputs[type] = await kit.sts(base, kit.rstWith(
      kit.usernameToken(cast.user, cast.password), typeUri(type),
      webapp.appliesTo, "", ""), cast.user + "'s " + label[type] +
      " sign-in", typeUri(type));
  }
  const bobSub = claimsOf(inputs.jwt.jwt).sub;
  // webapp1's credential: its application's UsernameToken, and its own
  // token in each type.
  const credentials = [{ name: "its application's UsernameToken",
                         security: kit.usernameToken(webapp.identifier,
                                                     webapp.secret) }];
  for (const type of types) {
    const own = await kit.selfToken(base, cast, webapp, typeUri(type));
    credentials.push({ name: "its own " + label[type],
                       security: kit.securityOf(own) });
  }
  let asked = 0;
  for (const credential of credentials) {
    for (const input of types) {
      for (const output of types) {
        const what = "webapp1 with " + credential.name + ", OnBehalfOf " +
          "bob's " + label[input] + ", asking for " + label[output];
        const answer = await kit.sts(base, kit.rstWith(
          credential.security, typeUri(output), gateway.appliesTo, ELEMENT,
          tokenOf(inputs[input])), what, typeUri(output));
        asked += 1;
        if (output === "jwt") {
          const c = claimsOf(answer.jwt);
          assert.strictEqual(c.sub, bobSub, what + ": sub " + c.sub);
          assert.strictEqual(c.aud, gateway.appliesTo, what + ": aud " +
                             JSON.stringify(c.aud));
          assert.strictEqual(c.client_id, webapp.identifier, what + ": " +
                             "client_id " + c.client_id);
        } else {
          const got = output === "saml11" ? kit.read11(answer.assertion)
                                          : kit.read(answer.assertion);
          assert.strictEqual(got.nameId, cast.user, what + ": about " +
                             got.nameId);
          assert.deepStrictEqual(got.audiences, [gateway.appliesTo], what +
                                 ": for " + JSON.stringify(got.audiences));
        }
        log.info("[matrix] " + what + ": answered");
      }
    }
  }
  check("2. the matrix (" + (product ? "product" : "development") + "): " +
        asked + " RSTs — every requester credential (a UsernameToken, and " +
        "the requester's own SAML 2.0, SAML 1.1 and JWT) × every " +
        "OnBehalfOf input × every issued type — each answered with the " +
        "type asked for, about " + cast.user + ", for " + gateway.appliesTo,
        function () {
    assert.strictEqual(asked, 36, "the matrix asked " + asked + " RSTs");
  });
  log.debug("Leaving matrix().");
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const product = await kit.isProduct(base);
  log.info("WS-Trust chains on each tier's own token, and the token-type " +
           "matrix, at " + base + " (" + (product ? "product" :
           "development") + " mode).");
  const casts = [];
  for (const kind of KINDS) {
    casts.push(await chainOf(base, kind, product));
  }
  await matrix(base, casts[0], product);
  assert.ok(checks >= 49, "only " + checks + " of 49 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_own_token_chain")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider over WS-Trust OnBehalfOf, each tier authenticated by " +
    "a token it was issued for itself with its application's client " +
    "secret, in SAML 2.0, SAML 1.1 and JWT; and every token type in every " +
    "seat of an RST.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
