// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_jwt_chain_delegation.js
//
// ---------------------------------------------------------------------------
// THE FOUR-TIER DELEGATION CHAIN OVER WS-TRUST WITH JWT RESPONSE TOKENS
// (#473): one sign-in, then three RequestSecurityTokens, each carrying
// `<wst14:ActAs>`, every RST asking for `wst:TokenType`
// `urn:ietf:params:oauth:token-type:jwt`.
//
// `sts_wstrust_chain_delegation.js` with JWTs where that job has SAML
// assertions. rcbj: "follow RFC-9068 and OAuth2 Token Exchange spec for
// claims in the JWT", and only there ("The only time oauth2 token exchange
// and rfc9068 should be followed is for response token JWT structure and
// contents"). So the exchange is WS-Trust's, exactly as in the SAML job:
//
//   * a UsernameToken sign-in;
//   * each requester authenticated as its own service account;
//   * each AppliesTo the next tier's registered identifier;
//   * each hop presenting, inside ActAs, the token the hop before produced,
//     as its RSTR carried it: a JWT in a wsse:BinarySecurityToken.
//
// The JWT is held to RFC 9068 and RFC 8693, in this service's OAuth tokens'
// shape where RFC 8693 permits more than one:
//
//   * RFC 9068 section 2.1: `typ: at+jwt`, and a `kid` the realm's key set
//     (`GET /oauth2/jwks`) publishes, which its signature verifies with.
//   * RFC 9068 section 2.2: `iss` (the realm's OAuth issuer, #480: what
//     /.well-known/oauth-authorization-server publishes and `GET /sts` names
//     as `JWT issuer:`), `exp` (the
//     RSTR's own wst:Lifetime Expires, to the second), `aud` (exactly the
//     registered identifier asked for), `sub` (bob's `urn:uuid:`, the same
//     at every hop), `client_id` (the requester: webapp1-wjdel, apigw1-wjdel,
//     esb1-wjdel), `iat` and a fresh `jti`.
//   * RFC 8693 section 4.1: `act`, the current actor outermost, prior actors
//     nested. sp1's token reads
//
//       "act": { "sub": <esb1>, "iss": <iss>,
//                "act": { "sub": <apigw1>, "iss": <iss>,
//                         "act": { "sub": <webapp1>, "iss": <iss> } } }
//
//     — the OAuth delegation job's final shape (#443, #471). Each actor is
//     an application named by its client subject: `urn:sts:client:<id>` in
//     RFC 9700 mode (product implies it), bare otherwise. `iss` is in every
//     entry. The original client at the bottom is webapp1, here because it
//     made the first ActAs (the kit's decision 3).
//   * RFC 8693 section 4.4: no `may_act`, since bob names no delegate.
//
// EXCEPTIONS, each argued in `ws-trust/CLAUDE.md` (#476) and asserted as
// what is right:
//
//   * the sign-in's JWT has NO `client_id`. bob asked for it with his own
//     UsernameToken, and a person asking for themselves has no client;
//   * `scope` is the AppliesTo's `wstrustJwtScope` (#485), judged as an
//     OAuth access token's: its declared `chain.read` kept, its undeclared
//     `chain.undeclared` left off in product (kept in development);
//   * no SAML: the Delegation Restriction is the SAML pair's.
//
// NEEDS #476 AND #477. Against a service without them the sign-in's JWT
// fails 2a (no `typ: at+jwt`), and the first hop is refused in product
// (`STS-WSTRUST-0008`, a JWT is not an assertion).
//
// WHAT IT ASSERTS, in the SAML job's four layers:
//
//   1. THE REGISTRY, as there.
//   2. THE WIRE: every RSTR a 200 whose wst:TokenType is the JWT type, with
//      each JWT as above, compared in full.
//   3. THE TARGET'S VALIDATION at sp1: the published key, `typ`, its own
//      identifier in `aud`, the published issuer, the clock — and who acted.
//   4. THE REGISTER AND THE PICTURE: one `wstrust-actas` act per hop, found
//      by the `jti` of the JWT it produced and consuming the `jti` of the
//      one presented, the issuance policy's ALLOWED sentence, policed in
//      product; apigw1 and esb1 each ONE box.
//
// In development and product mode alike. The entries (`-wjdel`, apart from
// the SAML pair's, whose semantics are the same but whose runs must not
// meet in a pool) are left behind and reconciled on a rerun.
//
// OWNED HERE (local: true): the chain is this repository's own scenario.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./wstrust_chain_kit.js");

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
var log = bunyan.createLogger({ name: "sts_wstrust_jwt_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "wjdel";
const SEMANTICS = "delegation";
const ELEMENT = "ActAs";
const SKEW_MS = 60000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The `act` chain the first `n` requesters make, current actor outermost.
function actChain(requesters, n, form, issuer) {
  log.debug("Entering actChain(). " + n);
  let act;
  requesters.slice(0, n).forEach(function (tier) {
    const next = { sub: form(tier.identifier), iss: issuer };
    if (act) {
      next.act = act;
    }
    act = next;
  });
  log.debug("Leaving actChain().");
  return act;
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const cast = kit.castFor(TAG, "jwt");
  const product = await kit.isProduct(base);
  const namespaced = await kit.clientSubjectsNamespaced(base, product);
  const form = function (identifier) {
    log.debug("Entering form().");
    log.debug("Leaving form().");
    return namespaced ? "urn:sts:client:" + identifier : identifier;
  };
  log.info("The WS-Trust JWT delegation chain at " + base + ": " +
           cast.user + " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " (" + (product ? "product" : "development") +
           " mode; a client actor is " + form("<id>") + ").");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries register their identifiers on " +
        "wstrustAppliesTo and samlEntityId, and the three requesters " +
        "delegate to the next tier only", function () {});
  const keys = await kit.jwks(base);
  const issuer = await kit.publishedIssuer(base);

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. the sign-in's JWT: typ at+jwt, verified with the published " +
        "key, iss " + issuer + ", aud " + cast.webapp.appliesTo + ", exp " +
        "the wst:Lifetime, no client_id (bob asked for himself), no act",
        function () {
    first = kit.assertChainJwt(cast, signedIn, keys, {
      what: cast.user + "'s sign-in JWT", audience: cast.webapp.appliesTo,
      issuer: issuer, clientId: "", act: undefined,
      product: product });
  });

  const requesters = cast.requesters;
  const tokens = [first];
  const answers = [signedIn];
  for (let i = 0; i < requesters.length; i++) {
    const tier = requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier + " <ActAs> for " +
             next.appliesTo + " ===");
    const answer = await kit.exchange(base, cast, tier, ELEMENT,
                                      answers[i].inner);
    answers.push(answer);
    const expected = actChain(requesters, i + 1, form, issuer);
    check("2" + "bcd"[i] + ". " + tier.identifier + "'s JWT: about " +
          cast.user + ", aud " + next.appliesTo + ", client_id " +
          tier.identifier + ", act " + JSON.stringify(expected), function () {
      tokens.push(kit.assertChainJwt(cast, answer, keys, {
        what: tier.identifier + "'s ActAs JWT", audience: next.appliesTo,
        issuer: issuer, sub: first.claims.sub, clientId: tier.identifier,
        act: expected,
        product: product,
        notJtis: tokens.map(function (one) {
          return one.claims.jti;
        }) }));
    });
  }
  const final = tokens[tokens.length - 1];
  log.info("=== The final JWT's claims ===");
  log.info(JSON.stringify(final.claims, null, 2));

  check("3. sp1's own validation: the published key, typ at+jwt, " +
        cast.provider.appliesTo + " in aud, the issuer GET /sts names, the " +
        "clock; and the act chain names esb1, apigw1 and webapp1",
        function () {
    const atTarget = kit.validateJwtAtTarget(final.token, keys,
                                             cast.provider.appliesTo,
                                             issuer, SKEW_MS);
    assert.deepStrictEqual(atTarget.claims.act,
                           actChain(requesters, 3, form, issuer));
  });

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = requesters.map(function (tier, i) {
    return { clientId: tier.identifier, target: tier.next,
             appliesTo: kit.tierNamed(cast, tier.next).appliesTo,
             consumedId: tokens[i].claims.jti,
             producedId: tokens[i + 1].claims.jti };
  });
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.producedId, hop.clientId +
                            "'s ActAs JWT");
  });
  hops.forEach(function (hop, i) {
    check("4" + "abc"[i] + ". the register: one wstrust-actas act " +
          "(delegation) by " + hop.clientId + " for " + cast.user + " to " +
          hop.target + ", consuming jti " + hop.consumedId + " and " +
          "producing jti " + hop.producedId + ", allowed by the issuance " +
          "policy" + (product ? ", policed" : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: "wstrust-actas", mode: "delegation", semantics: SEMANTICS,
        requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, producedKind: "JWT",
        product: product });
    });
  });
  const findings = acts.reduce(function (all, act) {
    return all.concat(kit.actNotes(act, ELEMENT, product,
                                       true));
  }, []);
  check("4d. the picture: a delegation line from " + cast.user + " to " +
        "each requester, and " + cast.gateway.identifier + " and " +
        cast.esb.identifier + " each ONE box (#468)", function () {
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(0, 2),
                            "delegation");
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(1, 3),
                            "delegation");
  });

  assert.ok(checks >= 10, "only " + checks + " of 10 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed" + (findings.length
    ? "; " + findings.length + " finding(s) logged as WARN" : "") + ".");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_jwt_chain_delegation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one WS-Trust sign-in and three <wst14:ActAs> " +
    "exchanges asking for JWTs, each held to RFC 9068 and RFC 8693's " +
    "nested act, asserted on the wire, by the target's own validation and " +
    "in the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
