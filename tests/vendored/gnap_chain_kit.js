// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: gnap_chain_kit.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO GNAP CHAIN JOBS SHARE (#497): the four tiers of the
// token-exchange chain jobs (#467), the WS-Trust ones (#473) and the
// Kerberos ones (#486) — a web application, an API gateway, an enterprise
// service bus and a service provider — carried by GNAP access tokens (RFC
// 9635) and RFC 9767's token derivation instead. rcbj: "implement the
// token-exchange, WS-Trust and Kerberos chain use cases in GNAP".
//
// WHAT IS REUSED. `token_exchange_chain_kit.js` holds the parts that do not
// depend on the protocol — where the service is, which mode it is in, the
// register's baseline by TIME, an act found by the jti it produced, the
// picture's one-box rule (#468), and the browser's authorization-code walk
// with a desktop User-Agent — and they are taken from it. `gnap_client.js`
// is the independent GNAP client (RFC 9421 signatures, nothing from
// `gnap/`), and `gnap_flow.js` the resource owner: the sign-in and the
// approval page. Everything else here is GNAP's own.
//
// ---------------------------------------------------------------------------
// THE MAPPING, AND WHY (gnap/CLAUDE.md, *Delegation*).
//
// GNAP HAS NO IMPERSONATION OF ITS OWN. This service maps the two use cases
// onto the two ways GNAP gives a party a token about somebody else, and
// asks #186's delegation policy about each, as it does the token exchange,
// WS-Trust and the KDC:
//
//   **IMPERSONATION** is a `gnapSkipInteraction` client presenting a
//   VERIFIED user assertion (RFC 9635 sections 2.3.3 and 2.4) — Kerberos's
//   S4U2Self. bob signs in to webapp1 through this service's OpenID Connect
//   authorization endpoint, so webapp1 holds an ID Token ISSUED TO IT (its
//   `aud` is webapp1). webapp1, trusted to skip interaction and allowed
//   `impersonation`, presents that ID Token as `user.assertions` and is
//   issued a token about bob for apigw1 that names NO actor. Then apigw1 and
//   esb1 derive, below. The coordinator's design change on #497: webapp1,
//   not apigw1, presents the assertion, because RFC 9635 section 11.13 says
//   a captured assertion presented by a client that is not its audience is
//   exactly how an end user is impersonated, and the case section 2.4
//   allows is an assertion the AS issued to the presenting client. The job
//   asserts that refusal too: apigw1 presenting webapp1's ID Token as its
//   own is refused (STS-GNAP-0073, added by #497 — until then the service
//   checked the signature, issuer and expiry, and never the audience).
//
//   **DELEGATION** is RFC 9767 section 4's TOKEN DERIVATION by a resource
//   server — Kerberos's S4U2Proxy. bob approves webapp1's grant on the
//   approval page (interaction), and webapp1 gets a token for apigw1; apigw1,
//   signing with its own key and presenting `existing_access_token`, derives
//   one for esb1, and esb1 one for sp1. Each derived token is a subset of
//   the one it came from and names the deriving resource server in RFC 8693
//   section 4.1's `act`, outermost, so sp1's reads esb1 over apigw1.
//   `gnap.maxDerivationDepth` (default 2) is exactly three tiers.
//
// So each chain has its register rows in [MS-SFU]'s pattern: impersonation
// is ONE `gnap-impersonation` row (webapp1 → apigw1) and then two
// `gnap-derivation` rows; delegation is two `gnap-derivation` rows. bob's
// approval of webapp1's grant is not a delegation act — webapp1 is the
// person's own client, as it is in the OAuth jobs, and asks nobody's leave
// but bob's.
//
// ---------------------------------------------------------------------------
// WHERE GNAP RECORDS THE ORIGINAL CLIENT (#443's question, asked of GNAP).
// Not in `act`: RFC 8693's chain names only the parties that ACTED, and
// webapp1 asked for a token for itself. Not in `client_id` either: a derived
// token's `client_id` (introspection's `instance_id`) is the DERIVING
// resource server, which is the client of the derivation grant. The record
// is the GRANT: every derived token carries the ORIGINAL grant's identifier
// — `grant_id` in a JWT format and at introspection (#432 phase 5, so a
// derivation spends the same budget rather than a second one) — and that
// grant, read on `GET /admin-api/gnap`, names its client (webapp1) and its
// resource owner (bob). The derivation grants beside it name the token each
// was derived from (`derivedFrom`, a jti). The delegation job follows that
// path from sp1's token back to webapp1 and asserts each step. Nothing is
// invented: no claim the service does not write is looked for.
//
// ---------------------------------------------------------------------------
// THE COMMON ACCESS RIGHT, and the catalogue's one rule that shapes it.
// `app1-scope` is the scope every access token of the OAuth chains carries.
// Its GNAP counterpart is an access right of a CATALOGUED type (#432 phase
// 4; product refuses an uncatalogued one, STS-GNAP-0810) — but the catalogue
// lets ONE application declare a type ("A type names one resource server",
// STS-OAUTH-0462), so "a type all four declare" cannot be written. So:
//
//   APP1 (`https://app1-<tag>.example.com/app1`, actions `read`), declared
//   by sp1 — the API at the end of the path — with the three resource
//   servers' addresses as its `locations`, and `derivableFrom` the gateway's
//   and the bus's types. Every token carries `{type: APP1, actions: [read],
//   locations: [<the tier it is for>]}`.
//
//   One type per resource-server tier as well, owned by that tier — the
//   gateway's, the bus's (derivable from the gateway's) and the provider's
//   (derivable from the bus's). Each token carries its tier's.
//
// Why both. The service holds a derived token to a SUBSET of the original
// (rcbj's decision 3, STS-GNAP-0513), and `locations` is a dimension of
// that subset: a right located at apigw1 does not cover one at esb1. Without
// the catalogue's one extension point — a type `derivableFrom` a type the
// original carries (`derivableBeyond()`) — every hop's token would have to
// carry every downstream location from the start, and webapp1's token would
// be good at sp1 directly. With it, each token has ONE audience, the
// registered resource server of the next tier. And INTROSPECTION IS
// FILTERED PER RESOURCE SERVER (RFC 9767 section 3.3; a right of a type
// another resource server owns is withheld), so an intermediate tier sees
// its own type and not APP1, and sp1 sees both. Each tier's view is
// asserted exactly as the service gives it.
//
// ---------------------------------------------------------------------------
// WHAT EVERY TOKEN IS HELD TO, as its resource server would hold it: the
// JWS verified against the realm's `/oauth2/jwks` with node's own crypto
// (the default format, `jwt-signed`); `sub` bob's subject, `aud` the tier's
// registered identifier, `client_id` the party that asked, `act` exactly the
// chain so far, `access` the two rights; then introspection BY THAT TIER,
// signing with its own key — active, the same subject, audience, actor
// chain and grant, and the rights filtered for it.
//
// Every tier is a REGISTERED application in both modes (#496 makes product
// refuse an unregistered one), with its own ES256 key on `gnapKey`. Each
// job passes a TAG (`gnimp`, `gndel`) and gets four entries and a person of
// its own (`bob_end_user-<tag>`), in the DEFAULT realm, LEFT BEHIND for the
// picture; a rerun reconciles them and replaces every key.
//
// THE CAPTURE HOOK. With STS_CHAIN_CAPTURE naming a directory, each job
// writes `<job>.json` there through `chain_capture.js`, the helper every
// chain kit shares: one layer per hop — what each tier was handed, raw and
// decoded — so the protocols' chains can be compared side by side. No
// private key and no secret is in it. Unset, nothing is written.
//
// OWNED HERE (a LOCAL helper, tests/vendored/MANIFEST.js).
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const registry = require("./sts_applications.js");
const capture = require("./chain_capture.js");
const chain = require("./token_exchange_chain_kit.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gnap_chain_kit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // A hand run without CONFIG_FILE still loads; the level falls back.
      return "info";
    }
  })()
});

// The scenario's person; each cast is `<this>-<tag>` (#482's rule).
const USER = process.env.DELEGATION_USER || "bob_end_user";

// A password the realm's policy accepts, generated per process and never
// derivable: the entry outlives the run on a kept deployment.
function freshPassword() {
  log.debug("Entering freshPassword().");
  log.debug("Leaving freshPassword().");
  return "Gnap-" + crypto.randomBytes(15).toString("base64url") + "-4c!";
}

// ---------------------------------------------------------------------------
// THE CAST, for one job's tag. `next` is the tier each one forwards to, and
// the one table the entries' `appAllowedToDelegateTo`, the catalogue and the
// hops are all read from, so they cannot describe different chains.
// ---------------------------------------------------------------------------
function castFor(tag) {
  log.debug("Entering castFor(). tag=" + tag);
  const named = function (stem, what, resourceServer) {
    log.debug("Entering named(). " + stem);
    const identifier = stem + "-" + tag;
    const tier = { stem: stem, what: what, identifier: identifier,
                   name: identifier + " (" + what + ")",
                   resourceServer: resourceServer,
                   uri: resourceServer
                     ? "https://" + identifier + ".example.com/api" : "",
                   // This tier's own access type, owned by it.
                   type: resourceServer
                     ? "https://" + identifier + ".example.com/access" : "",
                   client: new gnap.Client({ key: gnap.newKey("ES256") }) };
    log.debug("Leaving named().");
    return tier;
  };
  const webapp = named("webapp1", "web application", false);
  const gateway = named("apigw1", "API gateway", true);
  const esb = named("esb1", "enterprise service bus", true);
  const provider = named("sp1", "service provider", true);
  webapp.next = gateway;
  gateway.next = esb;
  esb.next = provider;
  provider.next = null;
  // Each derived type is derivable from the type of the tier before it.
  gateway.derivableFrom = [];
  esb.derivableFrom = [gateway.type];
  provider.derivableFrom = [esb.type];
  const cast = {
    tag: tag, user: USER + "-" + tag, password: freshPassword(),
    webapp: webapp, gateway: gateway, esb: esb, provider: provider,
    tiers: [webapp, gateway, esb, provider],
    common: "https://app1-" + tag + ".example.com/app1",
    redirectUri: "https://" + webapp.identifier + ".example.com/callback"
  };
  log.debug("Leaving castFor().");
  return cast;
}

// ---------------------------------------------------------------------------
// WHERE AND WHAT THE SERVICE IS, and the harness bound to the DEFAULT realm
// with this cast's person's password.
// ---------------------------------------------------------------------------
async function start(tag) {
  log.debug("Entering start(). " + tag);
  const base = chain.serviceBase();
  const product = await chain.isProduct(base);
  const cast = castFor(tag);
  const h = flowLib.harness({ base: base, realm: "", password: cast.password,
                              log: log });
  // The entries are written here, with these keys; the registrar must not
  // file a key a second time under a name of its own.
  cast.tiers.forEach(function (tier) {
    h.noteJobKey({ fields: { gnapKey: JSON.stringify(
      tier.client.keyObject()) } });
  });
  const G = { base: base, api: base + "/admin-api", product: product, h: h,
              capture: newCapture(tag) };
  log.info("[gnap] " + (product ? "product" : "development") + " mode, the " +
           "default realm at " + base);
  log.debug("Leaving start().");
  return { G: G, cast: cast };
}

// ---------------------------------------------------------------------------
// /admin-api. tools/attach-admin-token.js puts the run's token on each call.
// ---------------------------------------------------------------------------
async function adminCall(G, method, where, body) {
  log.debug("Entering adminCall(). " + method + " " + where);
  const r = await fetch(G.api + where, { method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in adminCall(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into whatever message names it.
    json = null;
  }
  log.debug("Leaving adminCall(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function adminOk(G, where, body, what) {
  log.debug("Entering adminOk(). " + where);
  const r = await adminCall(G, "POST", where, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving adminOk().");
  return r.json;
}

// One multi-valued attribute brought to exactly `wanted`: what the entry
// holds and this job does not want comes off, what is missing goes on.
async function settleList(G, identifier, attribute, wanted) {
  log.debug("Entering settleList(). " + identifier + " " + attribute);
  const entry = await registry.entryOf(G.base, identifier);
  const held = registry.valuesOf(entry && entry.fields &&
                                 entry.fields[attribute]);
  for (const value of held) {
    if (wanted.indexOf(value) < 0) {
      await adminOk(G, "/applications/remove", { application: identifier,
                    attribute: attribute, value: value },
                    "removing " + value + " from " + identifier + "'s " +
                    attribute);
    }
  }
  for (const value of wanted) {
    if (held.indexOf(value) < 0) {
      await adminOk(G, "/applications/add", { application: identifier,
                    attribute: attribute, value: value },
                    "adding " + value + " to " + identifier + "'s " +
                    attribute);
    }
  }
  log.debug("Leaving settleList().");
}

async function settleOne(G, identifier, attribute, value) {
  log.debug("Entering settleOne(). " + identifier + " " + attribute);
  const entry = await registry.entryOf(G.base, identifier);
  const held = registry.valuesOf(entry && entry.fields &&
                                 entry.fields[attribute]);
  if (!value) {
    if (held.length) {
      await settleList(G, identifier, attribute, []);
    }
  } else if (held.length !== 1 || held[0] !== value) {
    await adminOk(G, "/applications/set", { application: identifier,
                  attribute: attribute, value: value },
                  "setting " + identifier + "'s " + attribute);
  }
  log.debug("Leaving settleOne().");
}

// ---------------------------------------------------------------------------
// THE CATALOGUE: what each tier declares on `oauthAuthorizationDetailsType`.
// Each resource-server tier its own type; sp1 the common one too.
// ---------------------------------------------------------------------------
function declaredTypes(cast, tier) {
  log.debug("Entering declaredTypes(). " + tier.identifier);
  if (!tier.resourceServer) {
    log.debug("Leaving declaredTypes(). A client declares none.");
    return [];
  }
  const own = { type: tier.type,
                description: "What " + tier.name + " answers for (#497).",
                actions: ["read"] };
  if (tier.derivableFrom.length) {
    own.derivableFrom = tier.derivableFrom.slice();
  }
  const out = [JSON.stringify(own)];
  if (tier === cast.provider) {
    out.push(JSON.stringify({
      type: cast.common,
      description: "The right every token of the " + cast.tag + " chain " +
                   "carries: GNAP's app1-scope (#497).",
      actions: ["read"],
      locations: [cast.gateway.uri, cast.esb.uri, cast.provider.uri],
      derivableFrom: [cast.gateway.type, cast.esb.type] }));
  }
  log.debug("Leaving declaredTypes().");
  return out;
}

// The two rights a token FOR `tier` carries: its own type, and the common
// right located at it.
function rightsFor(cast, tier) {
  log.debug("Entering rightsFor(). " + tier.identifier);
  log.debug("Leaving rightsFor().");
  return [{ type: tier.type, actions: ["read"] },
          { type: cast.common, actions: ["read"], locations: [tier.uri] }];
}

// ---------------------------------------------------------------------------
// PROVISIONING. `plan[stem]` is `{ semantics: [...], default }` for a tier
// that acts; a tier absent from the plan acts for nobody and its delegation
// attributes are cleared. `opts.oidcClient` makes webapp1 an OpenID Connect
// public client too (the impersonation job's sign-in); `opts.finish` gives
// it a registered finish URI (the delegation job's interaction).
//
//   appAllowedToDelegateTo     the next tier, on every tier that acts —
//                              "the actor must reach R" for webapp1's
//                              impersonation, "S must delegate to R" for a
//                              derivation, whose S is the deriving tier;
//   appDelegationSemantics     impersonation for webapp1 (impersonation job
//                              only), delegation for apigw1 and esb1 — an
//                              RFC 9767 derivation is always asked as one.
// ---------------------------------------------------------------------------
function fieldsFor(cast, tier, opts) {
  log.debug("Entering fieldsFor(). " + tier.identifier);
  const fields = { gnapKey: JSON.stringify(tier.client.keyObject()) };
  if (tier.resourceServer) {
    fields.gnapResourceServerUri = [tier.uri];
    fields.oauthAuthorizationDetailsType = declaredTypes(cast, tier);
  }
  if (tier === cast.webapp && opts.skipInteraction) {
    fields.gnapSkipInteraction = "TRUE";
  }
  if (tier === cast.webapp && opts.finish) {
    fields.gnapFinishUri = [opts.finish];
  }
  if (tier === cast.webapp && opts.oidcClient) {
    fields.oauthClientId = tier.identifier;
    fields.oauthTokenEndpointAuthMethod = ["none"];
    fields.oauthRedirectUri = [cast.redirectUri];
    fields.oauthGrantType = ["authorization_code"];
    fields.oauthResponseType = ["code"];
    fields.oauthAllowedScope = ["openid"];
  }
  log.debug("Leaving fieldsFor().");
  return fields;
}

async function provisionCast(G, cast, plan, opts) {
  log.debug("Entering provisionCast(). " + cast.tag);
  const options = opts || {};
  log.info("=== Provisioning " + cast.user + " and the four GNAP parties ===");
  await registry.ensurePerson(G.base, cast.user, cast.password);
  // No `stsMayAct`: it names ONE delegate, and a chain has several actors.
  await adminOk(G, "/users/set-may-act", { user: cast.user, delegate: "" },
                "clearing " + cast.user + "'s stsMayAct");
  for (const tier of cast.tiers) {
    const fields = fieldsFor(cast, tier, options);
    const protocols = tier === cast.webapp && options.oidcClient
      ? ["gnap", "oauth2", "oidc"] : ["gnap"];
    await registry.provision(G.base, {
      identifier: tier.identifier, name: tier.name, protocols: protocols,
      fields: fields,
      why: "the " + tier.what + " of the GNAP " + cast.tag + " chain" });
    // Exactly, not "at least": a rerun of an older shape leaves nothing.
    const wants = plan[tier.stem] || null;
    await settleList(G, tier.identifier, "appAllowedToDelegateTo",
                     wants && tier.next ? [tier.next.identifier] : []);
    await settleList(G, tier.identifier, "appDelegationSemantics",
                     wants ? wants.semantics : []);
    await settleOne(G, tier.identifier, "appDefaultDelegationSemantics",
                    wants ? wants.default : "");
    await settleList(G, tier.identifier, "oauthAuthorizationDetailsType",
                     fields.oauthAuthorizationDetailsType || []);
    await settleOne(G, tier.identifier, "gnapSkipInteraction",
                    fields.gnapSkipInteraction || "");
  }
  // Read back: the reply to a write is the service describing what it
  // wrote, and the question is what the registry holds.
  for (const tier of cast.tiers) {
    const entry = await registry.entryOf(G.base, tier.identifier);
    assert.ok(entry, "the registry has no " + tier.identifier);
    const field = function (name) {
      log.debug("Entering field(). " + name);
      log.debug("Leaving field().");
      return registry.valuesOf(entry.fields && entry.fields[name]);
    };
    assert.ok((entry.allowedProtocols || []).indexOf("gnap") >= 0,
              tier.identifier + " is not declared for GNAP: " +
              JSON.stringify(entry.allowedProtocols));
    assert.deepStrictEqual(field("gnapKey").map(function (one) {
      return JSON.parse(one);
    }), [tier.client.keyObject()], tier.identifier + "'s gnapKey is not " +
                                   "the key this run holds");
    const wants = plan[tier.stem] || null;
    assert.deepStrictEqual(field("appAllowedToDelegateTo"),
      wants && tier.next ? [tier.next.identifier] : [],
      tier.identifier + "'s appAllowedToDelegateTo");
    assert.deepStrictEqual(field("appDelegationSemantics").slice().sort(),
      (wants ? wants.semantics : []).slice().sort(),
      tier.identifier + "'s appDelegationSemantics");
    if (tier.resourceServer) {
      assert.deepStrictEqual(field("gnapResourceServerUri"), [tier.uri],
                             tier.identifier + "'s gnapResourceServerUri");
    }
    log.info("[registry] " + tier.identifier + ": " +
             (tier.resourceServer ? "resource server at " + tier.uri
                                  : "client instance") +
             "; delegates to " +
             (field("appAllowedToDelegateTo").join(", ") || "nobody") +
             "; semantics " +
             (field("appDelegationSemantics").join(", ") || "none") + ".");
  }
  log.debug("Leaving provisionCast().");
}

// ---------------------------------------------------------------------------
// THE FIRST STEP OF EACH CHAIN.
// ---------------------------------------------------------------------------
// IMPERSONATION: bob signs in to webapp1 through the OpenID Connect
// authorization endpoint — a browser's code walk with PKCE, webapp1 being a
// public client — and webapp1 redeems the code for an ID Token whose `aud`
// is webapp1.
async function oidcSignIn(G, cast) {
  log.debug("Entering oidcSignIn().");
  const granted = await chain.authorizationCode(G.base, {
    clientId: cast.webapp.identifier, redirectUri: cast.redirectUri,
    username: cast.user, password: cast.password, scope: "openid" });
  const r = await chain.tokenRequest(G.base, {
    grant_type: "authorization_code", code: granted.code,
    redirect_uri: cast.redirectUri, code_verifier: granted.verifier,
    client_id: cast.webapp.identifier });
  assert.strictEqual(r.status, 200, cast.webapp.identifier + "'s code " +
                     "redeemed: " + r.text.slice(0, 400));
  assert.ok(r.json.id_token, "no ID Token: " + r.text.slice(0, 400));
  const jwks = await jwksOf(G);
  const verified = verifyJws(r.json.id_token, jwks, "bob's ID Token");
  const audiences = [].concat(verified.claims.aud);
  assert.deepStrictEqual(audiences, [cast.webapp.identifier], "bob's ID " +
    "Token should be issued to webapp1 and only to it; aud is " +
    JSON.stringify(verified.claims.aud));
  log.info("[sign-in] " + cast.user + " signed in to " +
           cast.webapp.identifier + " (OpenID Connect); the ID Token's aud " +
           "is " + audiences.join(", ") + ".");
  log.debug("Leaving oidcSignIn().");
  return { value: r.json.id_token, header: verified.header,
           claims: verified.claims };
}

// A grant request by `tier` presenting `idToken` as its user assertion,
// asking for the rights for `target`, with no interaction.
function presentAssertion(G, tier, idToken, target, cast) {
  log.debug("Entering presentAssertion(). " + tier.identifier);
  log.debug("Leaving presentAssertion().");
  return tier.client.send("POST", G.h.GRANT, { json: {
    client: { key: tier.client.keyObject() },
    access_token: { access: rightsFor(cast, target) },
    user: { assertions: [{ format: "id_token", value: idToken }] } } });
}

// DELEGATION: webapp1 asks for the rights for apigw1 with interaction, and
// bob signs in and approves on the approval page.
async function approvedGrant(G, cast) {
  log.debug("Entering approvedGrant().");
  const done = await G.h.redirectGrant(cast.webapp.client, cast.user, {
    access_token: { access: rightsFor(cast, cast.gateway) } });
  assert.ok(done.released && done.released.access_token,
            "webapp1's grant released no access token: " +
            JSON.stringify(done.released));
  log.info("[approval] " + cast.user + " approved " + cast.webapp.identifier +
           "'s grant on the approval page; it holds a token for " +
           cast.gateway.identifier + ".");
  log.debug("Leaving approvedGrant().");
  return done.released.access_token;
}

// RFC 9767 section 4: `tier` signs with its own key, presents the token it
// was handed as `existing_access_token`, indicates no interaction, and asks
// for the rights for the next tier.
async function derive(G, cast, tier, existing) {
  log.debug("Entering derive(). " + tier.identifier);
  const r = await tier.client.send("POST", G.h.GRANT, { json: {
    client: { key: tier.client.keyObject() },
    existing_access_token: existing,
    access_token: { access: rightsFor(cast, tier.next) } } });
  assert.strictEqual(r.status, 200, tier.identifier + "'s derivation for " +
                     tier.next.identifier + " was refused: " +
                     String(r.text).slice(0, 400));
  assert.ok(r.json.access_token && r.json.access_token.value,
            tier.identifier + "'s derivation issued no token: " + r.text);
  assert.ok(!r.json.interact, "a derivation needs no interaction: " +
            r.text.slice(0, 300));
  log.info("[derive] " + tier.identifier + " derived a token for " +
           tier.next.identifier + " (RFC 9767 section 4).");
  log.debug("Leaving derive().");
  return r.json.access_token;
}

// ---------------------------------------------------------------------------
// THE FORMAT'S OWN CHECKS: a JWS verified against the realm's published
// key set with node's crypto, nothing from the service.
// ---------------------------------------------------------------------------
async function jwksOf(G) {
  log.debug("Entering jwksOf().");
  if (!G.jwks) {
    const r = await fetch(G.base + "/oauth2/jwks");
    assert.strictEqual(r.status, 200, "GET /oauth2/jwks answered " + r.status);
    G.jwks = await r.json();
  }
  log.debug("Leaving jwksOf().");
  return G.jwks;
}

function b64json(segment) {
  log.debug("Entering b64json().");
  log.debug("Leaving b64json().");
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

function verifyJws(compact, jwks, what) {
  log.debug("Entering verifyJws(). " + what);
  const parts = String(compact || "").split(".");
  assert.strictEqual(parts.length, 3, what + " is not a compact JWS: " +
                     String(compact).slice(0, 60));
  const header = b64json(parts[0]);
  const jwk = (jwks.keys || []).filter(function (k) {
    return k.kid === header.kid;
  })[0];
  assert.ok(jwk, what + ": the JWS kid " + header.kid + " is not in the " +
            "published JWKS");
  const hash = "sha" + String(header.alg).slice(2);
  const signed = Buffer.from(parts[0] + "." + parts[1]);
  const signature = Buffer.from(parts[2], "base64url");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  let good;
  if (/^PS/.test(header.alg)) {
    good = crypto.verify(hash, signed, { key: key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  } else if (/^ES/.test(header.alg)) {
    good = crypto.verify(hash, signed,
                         { key: key, dsaEncoding: "ieee-p1363" }, signature);
  } else {
    good = crypto.verify(hash, signed, key, signature);
  }
  assert.ok(good, what + ": the JWS signature does not verify against the " +
            "published key " + header.kid + " (" + header.alg + ")");
  log.debug("Leaving verifyJws().");
  return { header: header, claims: b64json(parts[1]) };
}

// ---------------------------------------------------------------------------
// ONE TOKEN, AS ITS RESOURCE SERVER WOULD HOLD IT. `expect`: { holder (the
// tier that asked), target (the tier it is for), act (the chain, or null),
// subject }. Answers what it learned, for the next steps and the capture.
// ---------------------------------------------------------------------------
async function assertToken(G, cast, token, expect) {
  log.debug("Entering assertToken(). for " + expect.target.identifier);
  const what = expect.holder.identifier + "'s token for " +
               expect.target.identifier;
  const value = token.value;
  // Introspection BY THE TIER IT IS FOR, signing with its own key — what
  // tells the format, and what a resource server that cannot read the
  // format relies on.
  const r = await expect.target.client.send("POST",
    G.h.realmBase + "/gnap/introspect", { json: {
      access_token: value,
      resource_server: { key: expect.target.client.keyObject() } } });
  assert.strictEqual(r.status, 200, what + ": introspection answered " +
                     r.status + " " + String(r.text).slice(0, 300));
  const seen = r.json;
  assert.strictEqual(seen.active, true, what + " is not active at " +
                     expect.target.identifier + ": " + r.text);
  assert.strictEqual(seen.format, "jwt-signed", what + "'s format is " +
    seen.format + "; this job reads the default format, jwt-signed");
  // The format's own checks.
  const jwks = await jwksOf(G);
  const jws = verifyJws(value, jwks, what);
  const claims = jws.claims;
  assert.strictEqual(claims.sub, expect.subject, what + " is about " +
    claims.sub + " rather than " + cast.user + " (" + expect.subject + ")");
  assert.strictEqual(claims.aud, expect.target.identifier, what + "'s aud " +
    "is " + JSON.stringify(claims.aud) + ": it should be the ONE registered " +
    "resource server it is for");
  assert.strictEqual(claims.client_id, expect.holder.identifier, what +
    "'s client_id is " + claims.client_id + " rather than the party that " +
    "asked for it");
  assert.deepStrictEqual(claims.act === undefined ? null : claims.act,
    expect.act, what + "'s act chain is " + JSON.stringify(claims.act) +
    " and should be " + JSON.stringify(expect.act));
  assert.deepStrictEqual(claims.access, rightsFor(cast, expect.target),
    what + " should carry exactly its tier's right and the common right " +
    "located at it; it carries " + JSON.stringify(claims.access));
  assert.ok(claims.grant_id, what + " names no grant_id");
  // Introspection agrees, and is FILTERED for the tier (RFC 9767 section
  // 3.3): the common right is sp1's type, so only sp1 is told of it.
  assert.strictEqual(seen.sub, claims.sub, what + ": introspection's sub");
  assert.strictEqual(seen.aud, claims.aud, what + ": introspection's aud");
  assert.strictEqual(seen.instance_id, expect.holder.identifier,
                     what + ": introspection's instance_id");
  assert.deepStrictEqual(seen.act === undefined ? null : seen.act,
                         expect.act, what + ": introspection's act");
  assert.strictEqual(seen.grant_id, claims.grant_id,
                     what + ": introspection's grant_id");
  const shown = rightsFor(cast, expect.target).filter(function (one) {
    return one.type !== cast.common ||
      expect.target === cast.provider;
  });
  assert.deepStrictEqual(seen.access, shown, what + ": introspection by " +
    expect.target.identifier + " should show " + JSON.stringify(shown) +
    " — a right of a type another resource server owns is withheld — and " +
    "shows " + JSON.stringify(seen.access));
  log.info("[token] " + what + ": JWS verified; sub " + claims.sub +
           ", aud " + claims.aud + ", client_id " + claims.client_id +
           ", act " + JSON.stringify(claims.act || null) + ", grant_id " +
           claims.grant_id + "; introspected by " +
           expect.target.identifier + " — " + seen.access.length +
           " right(s) shown.");
  log.debug("Leaving assertToken().");
  return { value: value, header: jws.header, claims: claims,
           introspection: seen };
}

// RFC 8693 section 4.1's chain, the most recent actor outermost, as the
// OAuth2 token exchange writes it (#526, after #443 and #471): the original
// client — webapp1, whose token the first derivation was made from — at the
// foot, and every entry `urn:sts:client:<id>` with the GNAP authorization
// server's issuer, the grant endpoint.
function actChain(G, cast, tiers) {
  log.debug("Entering actChain().");
  const entry = function (identifier) {
    return { sub: "urn:sts:client:" + identifier, iss: G.h.GRANT };
  };
  let out = tiers.length ? entry(cast.webapp.identifier) : null;
  for (let i = 0; i < tiers.length; i++) {
    out = Object.assign(entry(tiers[i].identifier), { act: out });
  }
  log.debug("Leaving actChain().");
  return out;
}

// ---------------------------------------------------------------------------
// A REFUSAL BY ITS CODE: the GNAP error (RFC 9635 section 3.6) on the wire,
// and the operator's code on a new audit row (a code is recorded, never
// sent — sts_gnap_delegation.js's arrangement).
// ---------------------------------------------------------------------------
async function codeCount(G, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await adminCall(G, "GET", "/audit?per=500&code=" +
                            encodeURIComponent(code));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function refusedAs(G, code, gnapError, what, fn) {
  log.debug("Entering refusedAs(). " + code);
  const before = await codeCount(G, code);
  const r = await fn();
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 250);
    });
    after = await codeCount(G, code);
  }
  G.h.refused(r, gnapError, what);
  assert.ok(after > before, what + ": no new audit row carries " + code +
            " (" + before + " before, " + after + " after)");
  log.info("[refused] " + what + ": " + r.status + " " + gnapError +
           ", " + code + " on the audit.");
  log.debug("Leaving refusedAs().");
  return r;
}

// ---------------------------------------------------------------------------
// THE ORIGINAL CLIENT, as GNAP records it (the header): the grant a token's
// `grant_id` names, read on GET /admin-api/gnap, page by page.
// ---------------------------------------------------------------------------
async function grantRows(G) {
  log.debug("Entering grantRows().");
  const rows = [];
  for (let page = 1; page <= 200; page += 1) {
    const r = await adminCall(G, "GET", "/gnap?per=500&grantsPage=" + page);
    assert.strictEqual(r.status, 200, "GET /admin-api/gnap answered " +
                       r.status + " " + r.text.slice(0, 300));
    const grants = r.json.grants || {};
    (grants.rows || []).forEach(function (one) {
      rows.push(one);
    });
    const paging = grants.paging || {};
    if (!paging.pages || page >= Number(paging.pages)) {
      break;
    }
  }
  log.debug("Leaving grantRows(). " + rows.length);
  return rows;
}

async function assertOriginalClient(G, cast, tokens) {
  log.debug("Entering assertOriginalClient().");
  const last = tokens[tokens.length - 1].claims;
  const rows = await grantRows(G);
  const byId = function (id) {
    log.debug("Entering byId().");
    log.debug("Leaving byId().");
    return rows.filter(function (one) {
      return one.id === id;
    })[0] || null;
  };
  const original = byId(last.grant_id);
  assert.ok(original, "sp1's token names grant " + last.grant_id + ", and " +
            "GET /admin-api/gnap lists no such grant among " + rows.length);
  assert.strictEqual(original.client, cast.webapp.identifier, "the grant " +
    "sp1's token is counted against should be webapp1's — the ORIGINAL " +
    "client — and is " + original.client + "'s");
  assert.strictEqual(original.resourceOwner, cast.user, "the original " +
    "grant's resource owner is " + original.resourceOwner);
  assert.strictEqual(original.derivedFrom, null, "the original grant was " +
                     "derived from " + original.derivedFrom);
  // Every token of the chain is counted against that one grant.
  tokens.forEach(function (one, i) {
    assert.strictEqual(one.claims.grant_id, original.id, "token " + i +
      " of the chain names grant " + one.claims.grant_id + ", not the " +
      "original " + original.id);
  });
  // The derivation grants: each names the token it was derived from, and
  // its client is the deriving tier.
  for (let i = 1; i < tokens.length; i += 1) {
    const from = tokens[i - 1].claims.jti;
    const derived = rows.filter(function (one) {
      return one.derivedFrom === from;
    });
    assert.strictEqual(derived.length, 1, "exactly one grant should be " +
      "derived from token " + from + "; " + derived.length + " are");
    assert.strictEqual(derived[0].client, tokens[i].claims.client_id,
      "the grant derived from " + from + " belongs to " + derived[0].client);
  }
  log.info("[original client] sp1's token's grant_id " + original.id +
           " is the grant " + original.client + " was issued for " +
           original.resourceOwner + "; the derivation grants name the " +
           "tokens they came from. act names only those that acted.");
  log.debug("Leaving assertOriginalClient().");
  return original;
}

// ---------------------------------------------------------------------------
// THE REGISTER. Each act is found by the jti of the token it produced
// (`token_exchange_chain_kit.js`'s `actProducing()`).
// ---------------------------------------------------------------------------
// `expect`: { type, mode, actor, target, semantics, consumedKind,
// consumedIdentifier }.
function assertAct(G, cast, act, expect) {
  log.debug("Entering assertAct(). " + expect.type);
  assert.strictEqual(act.protocol, "GNAP", "protocol " + act.protocol);
  assert.strictEqual(act.type, expect.type, "the act was filed as " +
                     act.type);
  assert.strictEqual(act.mode, expect.mode, "the " + expect.type + " act's " +
                     "mode is \"" + act.mode + "\"");
  assert.strictEqual(act.outcome, "issued", "outcome " + act.outcome);
  assert.strictEqual(act.policed, true, "this service decides every GNAP " +
                     "delegation act, and this one is not policed");
  assert.strictEqual(act.initial.presented, cast.user, "the act is for \"" +
    act.initial.presented + "\" rather than " + cast.user);
  assert.strictEqual(act.intermediary.application, expect.actor.identifier,
    "the act's middle is \"" + act.intermediary.application + "\"");
  assert.strictEqual(act.target.application, expect.target.identifier,
    "the act reached \"" + act.target.application + "\" rather than " +
    expect.target.identifier + ", the registered resource server the " +
    "rights resolve to");
  const allowed = "the issuance policy allowed " + expect.semantics +
      " by \"" + expect.actor.identifier + "\" for \"" + cast.user +
      "\" to \"" + expect.target.identifier + "\"";
  const said = String(act.authorizedBy || "");
  assert.ok(said.indexOf(allowed) >= 0, "the act should say \"" + allowed +
            " …\" and says \"" + said + "\". \"WOULD HAVE BEEN REFUSED\" " +
            "means the entries this job provisioned are not what the " +
            "service read.");
  const consumed = (act.consumed || []).filter(function (one) {
    return one.kind === expect.consumedKind;
  });
  assert.ok(consumed.length === 1 &&
            consumed[0].identifier === expect.consumedIdentifier,
            "the act should record consuming " + expect.consumedKind + " " +
            expect.consumedIdentifier + " and records " +
            JSON.stringify(act.consumed));
  log.info("[register] " + act.type + " (" + act.mode + "): " +
           act.initial.presented + " -> " + act.intermediary.application +
           " -> " + act.target.application + "; " + said);
  log.debug("Leaving assertAct().");
}

// THE PICTURE: each tier ONE box, found by its application (#468).
function boxOf(graph, tier) {
  log.debug("Entering boxOf(). " + tier.identifier);
  const boxes = (graph.nodes || []).filter(function (n) {
    return n.application === tier.identifier || n.id === tier.identifier;
  });
  assert.strictEqual(boxes.length, 1, "the picture should hold exactly one " +
    "box standing for " + tier.identifier + ", and holds " +
    JSON.stringify(boxes.map(function (n) {
      return n.id;
    })) + " (#468)");
  log.debug("Leaving boxOf(). " + boxes[0].id);
  return boxes[0];
}

// `hops`: the acts in order, each { actor, mode }. Each actor after the
// first is ONE box, reached by the hop before and in the middle of its own.
function assertPicture(cast, graph, hops) {
  log.debug("Entering assertPicture().");
  const lines = JSON.stringify((graph.edges || []).map(function (e) {
    return e.from + " -" + e.relation + "/" + e.mode + "-> " + e.to;
  }));
  hops.forEach(function (hop, i) {
    const box = boxOf(graph, hop.actor);
    assert.ok(box.roles.intermediary >= 1, hop.actor.identifier + " is in " +
              "the middle of nothing in the picture");
    const line = (graph.edges || []).filter(function (e) {
      return e.relation === "acts-for" && e.from === cast.user &&
             e.to === box.id && e.mode === hop.mode;
    });
    assert.ok(line.length >= 1, "the picture draws no " + hop.mode +
              " line from " + cast.user + " to " + box.id + ": " + lines);
    if (i > 0) {
      assert.ok(box.roles.target >= 1, hop.actor.identifier + " should be " +
        "ONE box, reached by the hop before it and acting in its own; it " +
        "is reached " + box.roles.target + " time(s) (#468)");
    }
    log.info("[picture] " + hop.actor.identifier + " is one box (" + box.id +
             "): reached " + box.roles.target + " time(s), in the middle " +
             box.roles.intermediary + " time(s); " + hop.mode + ".");
  });
  log.debug("Leaving assertPicture().");
}

// ---------------------------------------------------------------------------
// THE CAPTURE HOOK (the header). One layer per hop, in order, in exactly
// the shape every chain kit writes.
// ---------------------------------------------------------------------------
function newCapture(tag) {
  log.debug("Entering newCapture(). " + tag);
  log.debug("Leaving newCapture().");
  return { protocol: "GNAP", useCase: "", layers: [] };
}

// WHICH ACT MADE A LAYER, from what the jobs say about it: the ID Token is
// the OpenID Connect sign-in, a derived token is RFC 9767 section 4, and the
// first access token is the grant itself — by a user assertion with no
// interaction (impersonation) or by the person's approval (delegation).
function mechanismOf(layer) {
  log.debug("Entering mechanismOf().");
  if (layer.mechanism) {
    log.debug("Leaving mechanismOf(). Named.");
    return layer.mechanism;
  }
  if (layer.kind === "ID Token") {
    log.debug("Leaving mechanismOf(). Sign-in.");
    return "OpenID Connect authorization code";
  }
  if (/^derived by /.test(String(layer.notes || ""))) {
    log.debug("Leaving mechanismOf(). Derivation.");
    return "GNAP token derivation (RFC 9767 section 4)";
  }
  if (/user assertion/.test(String(layer.notes || ""))) {
    log.debug("Leaving mechanismOf(). Assertion.");
    return "GNAP grant by user assertion, no interaction";
  }
  log.debug("Leaving mechanismOf(). Approval.");
  return "GNAP grant approved through interaction";
}

// `layer`: { hop, requester, target, kind, format, value, header, claims,
// act, notes } — written through chain_capture.js, the helper every chain
// kit shares, so the twelve chains have one shape. The nested `act` becomes
// that helper's `actChain`, oldest first.
function captureLayer(G, layer) {
  log.debug("Entering captureLayer(). " + layer.hop);
  const entry = {
    hop: layer.hop, requester: layer.requester, target: layer.target,
    kind: layer.kind, format: layer.format, value: layer.value,
    header: layer.header === undefined ? null : layer.header,
    claims: layer.claims === undefined ? null : layer.claims,
    act: layer.act === undefined ? null : layer.act,
    notes: layer.notes || "" };
  G.capture.layers.push(entry);
  capture.layer({
    hop: entry.hop, requester: entry.requester, target: entry.target,
    mechanism: mechanismOf(layer), kind: entry.kind, format: entry.format,
    value: entry.value, header: entry.header, claims: entry.claims,
    actChain: capture.actChain(entry.act,
                               entry.claims && entry.claims.iss),
    notes: entry.notes });
  log.debug("Leaving captureLayer().");
}

// The record's own fields. The file itself is written by chain_capture.js
// as each layer arrives; this names the protocol, the use case, the service
// and its mode on it. Unset STS_CHAIN_CAPTURE, nothing is written.
function writeCapture(G, job, useCase) {
  log.debug("Entering writeCapture(). " + job);
  capture.set({ protocol: G.capture.protocol, useCase: useCase,
                service: G.base,
                mode: G.product ? "product" : "development" });
  log.debug("Leaving writeCapture().");
}

module.exports = {
  start: start,
  provisionCast: provisionCast,
  oidcSignIn: oidcSignIn,
  presentAssertion: presentAssertion,
  approvedGrant: approvedGrant,
  derive: derive,
  assertToken: assertToken,
  actChain: actChain,
  rightsFor: rightsFor,
  refusedAs: refusedAs,
  assertOriginalClient: assertOriginalClient,
  registerBaseline: chain.registerBaseline,
  registerSince: chain.registerSince,
  actProducing: chain.actProducing,
  assertAct: assertAct,
  assertPicture: assertPicture,
  captureLayer: captureLayer,
  writeCapture: writeCapture
};
