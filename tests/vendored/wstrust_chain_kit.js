// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: wstrust_chain_kit.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO WS-TRUST CHAIN JOBS SHARE (#473): the four tiers of the
// token-exchange chain jobs (#467) — a web application, an API gateway, an
// enterprise service bus and a service provider — carried by SAML 2.0
// assertions and WS-Trust instead of access tokens and RFC 8693. Each tier
// is provisioned through /admin-api. bob_end_user signs in to the first tier.
// Then come three RequestSecurityToken hops, each made by a different tier
// with `<wst:OnBehalfOf>` or `<wst14:ActAs>`. The final assertion is
// validated as the service provider would validate it, and the delegation
// register and its graph are read back. Nothing comes from the service's own
// code.
//
// WHAT IS REUSED, AND WHY ONLY THAT. `token_exchange_chain_kit.js` holds
// four things that do not depend on the protocol, and they are taken from it
// rather than copied:
//
//   * where the service is;
//   * which mode it is in;
//   * the cast's names (its `next` table is the one both the policy and the
//     hops read);
//   * the register's baseline, read by time rather than by `seq`, the read
//     after the run, and the picture's one-box rule (#468).
//
// Everything else here is WS-Trust's own. That covers the requests, the
// requester's credential, the registered AppliesTo, the assertion's XML,
// its signature and the act's shape.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS, EACH OF WHICH CHANGES WHAT THE JOBS PROVE.
//
// **1. EVERY HOP NAMES ITS TARGET BY THE NEXT TIER'S REGISTERED IDENTIFIER**
// (rcbj's rule for the OAuth jobs, carried over). Each tier registers
// `https://<tier>-<tag>.example.com` on `wstrustAppliesTo`, which is what an
// RST names it by, and on `samlEntityId`, which is the audience an assertion
// for it carries. The two are one string, because WS-Trust copies the
// AppliesTo into the issued assertion's AudienceRestriction.
// `applications.forAppliesTo()` reads `wstrustAppliesTo` first, so the
// register files every act against the APPLICATION, and the delegation
// policy resolves S and R the same way. Each AudienceRestriction is asserted
// to be exactly that URI.
//
// **2. THE SIGN-IN IS A WS-TRUST ISSUE WITH BOB'S USERNAMETOKEN, ADDRESSED TO
// webapp1.** The parent project's `tests/wstrust_delegation_chain.js` signs
// in through the SAML 2.0 Web Browser SSO profile in Chrome. Over plain HTTP
// that profile has two costs here:
//
//   * the service finds a service provider by its IDENTIFIER, which is its
//     entityID (`saml2_sso.ts`, `applications.get()`), so webapp1 would
//     have to be an entry named by a URL. The name it authenticates as on
//     its own hops, and the box the picture draws, would then be a second
//     name for the same application;
//   * product requires a signed AuthnRequest, so a per-run certificate would
//     be needed as well.
//
// The Issue is this service's non-browser sign-in. `sts_delegation_policy.js`
// section W uses it (`tokenAbout()`), and it yields what the SSO yields: an
// assertion about bob, signed by this realm and RESTRICTED TO webapp1. Its
// AuthnContext is PasswordProtectedTransport. In product the password is
// verified against bob's `userPassword`.
//
// **3. webapp1 MAKES THE FIRST HOP, AND THAT IS WHERE THE "ORIGINAL CLIENT"
// (#443) COMES FROM.** In OAuth the sign-in asks for the gateway's audience
// directly. The token comes back issued TO webapp1 (`client_id`) and FOR
// apigw1. The token-chaining profile #443 cites then has the first exchange
// nest that client beneath the gateway, because only the client_id says
// webapp1 was ever involved. SAML has no such field. An assertion from a
// sign-in is restricted to the party signed in to, and a UsernameToken Issue
// addressed straight to apigw1 would name nobody but bob. That would be
// correct: the STS cannot name a party it never met. So webapp1 gets a token
// for the gateway the way a SAML relying party does. It presents bob's
// assertion in its own RST, `AppliesTo` apigw1, and under ActAs WS-Trust 1.4
// section 9.3 makes it the party ACTING. The issued assertion then names it
// as the first `<del:Delegate>`, by the ordinary rule and with no special
// case. The final chain is [webapp1, apigw1, esb1], least to most recent
// (sstc-saml-delegation-cs-01: "the earliest element is the farthest removed
// from the immediate use of the assertion"). That is the WS-Trust spelling
// of the nested `act` the OAuth delegation job ends with. So there are THREE
// exchanges here where the OAuth jobs have two, and the register holds three
// acts.
//
// **4. EACH REQUESTER AUTHENTICATES AS ITSELF, WITH A SERVICE ACCOUNT OF ITS
// OWN NAME** (#221). WS-Trust's requester credential is a WS-Security
// UsernameToken, verified against a `userPassword`. The application entry
// cannot hold one, so `ws-trust/CLAUDE.md` keeps it on a service account
// entry of the same name: "the APPLICATION entry is what the policy reads".
// A service account rather than a plain person, so the console does not list
// three people who are programs. The realm's service-account policy allows
// the WS-Trust door by default and requires an owner. The owner is the
// console's Admin Write group (`admin.writeGroup`), the operators answerable
// for what is provisioned through /admin-api. sp1 calls nothing and has no
// account.
//
// **5. NO app1-scope.** The OAuth jobs carry one declared scope on every
// token. A SAML assertion has no scope. The nearest things are an attribute,
// which this service puts on an assertion only when an administrator
// configures one for every relying party, and the AudienceRestriction, which
// is different at every hop by design. Inventing either would assert a
// fixture rather than the protocol, so there is none.
//
// **6. A SECOND PAIR ASKS FOR JWTs** (rcbj: "another set of these tests
// with JWTs as the response token type", following RFC 9068 and RFC 8693
// "for response token JWT structure and contents" and nowhere else). Same
// tiers, same requesters, same exchange: `castFor(tag, "jwt")` makes every
// RST ask for `urn:ietf:params:oauth:token-type:jwt`. Each hop presents the
// token the hop before produced, exactly as its RSTR carried it: a JWT in a
// `wsse:BinarySecurityToken`. The JWT is then read as its relying party
// reads one: `typ`, its claims and `act` (`assertChainJwt()`), its signature
// against the realm's PUBLISHED key set (`GET /oauth2/jwks`), and its issuer
// against the one `GET /sts` names. Those jobs need #476 (the JWT's claims)
// and #477 (a JWT accepted inside OnBehalfOf / ActAs).
//
// **7. EVERY TOKEN CARRIES THE AppliesTo's CLAIM SETTINGS** (#483, #484).
// Each tier sets the groups claim (`teams`, by cn), a custom access-token
// claim and a custom SAML attribute (`tier`). The person is in a group that
// holds a role. Every assertion and JWT is checked for all three, plus the
// roles claim, and the values are always the person's: the requesters are
// in neither the group nor the role.
//
// Each job passes a TAG (`wsimp`, `wsdel`, `wjimp`, `wjdel`) and gets
// entries of its own. The
// two jobs differ in the semantics their tiers allow, and
// `appDefaultDelegationSemantics` holds one value. The OAuth jobs' `-imp` and
// `-del` entries carry OAuth configuration and the same single-valued
// semantics, so neither pair can be shared with the other. The entries are
// LEFT BEHIND, for the picture, and a rerun reconciles them.
//
// OWNED HERE (a LOCAL helper, tests/vendored/MANIFEST.js).
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const registry = require("./sts_applications.js");
const chain = require("./token_exchange_chain_kit.js");
const capture = require("./chain_capture.js");
const { DOMParser } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "wstrust_chain_kit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // A hand run without CONFIG_FILE still loads; the level falls back.
      return "info";
    }
  })()
});

const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_DEL = "urn:oasis:names:tc:SAML:2.0:conditions:delegation";
const NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
const ENTITY_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
const AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
    "PasswordProtectedTransport";
const AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
    "wssecurity-secext-1.0.xsd";
const WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const WST14_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
// The two token types an RST asks for here: WS-Security's SAML token
// profile's SAML 2.0 URI, and the JWT URI this STS answers a JWT for (RFC
// 8693 section 3's, which WS-Trust takes as an opaque wst:TokenType).
const SAML2_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-" +
    "token-profile-1.1#SAMLV2.0";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
// And SAML 1.1 (#487), the profile's SAML 1.1 URI.
const SAML11_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-" +
    "token-profile-1.1#SAMLV1.1";
const NS_SAML11 = "urn:oasis:names:tc:SAML:1.0:assertion";
const AM_PASSWORD = "urn:oasis:names:tc:SAML:1.0:am:password";
const AM_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

// ---------------------------------------------------------------------------
// THE CAST: `token_exchange_chain_kit.js`'s, so the names and the `next`
// table are one table. Each tier gets its REGISTERED identifier
// (`appliesTo`), webapp1 included, since the sign-in's assertion is
// addressed to it. Each REQUESTER also gets a password for its service
// account, generated per process and SET every run, so a rerun replaces the
// last run's.
// ---------------------------------------------------------------------------
// `tokenType` is what every RST of the cast asks for: "saml" (the default),
// "jwt" (#473's second pair) or "saml11" (#487's third).
function castFor(tag, tokenType) {
  log.debug("Entering castFor(). tag=" + tag);
  const cast = chain.castFor(tag);
  cast.tokenType = tokenType === "jwt" ? JWT_TOKEN_TYPE
    : tokenType === "saml11" ? SAML11_TOKEN_TYPE : SAML2_TOKEN_TYPE;
  cast.tiers.forEach(function (tier) {
    tier.appliesTo = "https://" + tier.identifier + ".example.com";
    tier.password = tier.next
      ? "Svc-" + crypto.randomBytes(18).toString("base64url") + "-7b!"
      : "";
  });
  // #483: a group the person is in and a role the group holds, so the
  // groups claim and the roles claim have something to say at every hop.
  cast.team = "chain-" + tag + "-team";
  cast.role = "chain-" + tag + "-role";
  cast.requesters = cast.tiers.filter(function (tier) {
    return !!tier.next;
  });
  capture.set({ protocol: "WS-Trust (" + (tokenType === "jwt"
    ? "JWT" : tokenType === "saml11" ? "SAML 1.1 assertions"
      : "SAML 2.0 assertions") + ")" });
  log.debug("Leaving castFor().");
  return cast;
}

function tierNamed(cast, identifier) {
  log.debug("Entering tierNamed(). " + identifier);
  const found = cast.tiers.filter(function (one) {
    return one.identifier === identifier;
  })[0];
  assert.ok(found, "no tier is called " + identifier);
  log.debug("Leaving tierNamed().");
  return found;
}

// ---------------------------------------------------------------------------
// HTTP.
// ---------------------------------------------------------------------------
async function call(method, target, body, headers) {
  log.debug("Entering call(). " + method + " " + target);
  const r = await fetch(target, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json",
                             Accept: "application/json" }, headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON (an RSTR, a certificate); `text` carries it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function adminOk(base, path, body, what) {
  log.debug("Entering adminOk(). " + path);
  const r = await call("POST", base + "/admin-api" + path, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving adminOk().");
  return r.json;
}

// ---------------------------------------------------------------------------
// WHAT EACH ENTRY HOLDS, as one table, the same in both modes:
//
//   appAllowedProtocol        wstrust (it is a relying party of an RST) and
//                             saml2 (it is the audience of an assertion);
//   wstrustAppliesTo,         its registered identifier, one URI on both
//   samlEntityId              (decision 1);
//   the delegation policy     on the three requesters: the semantics the job
//                             uses, as their only and default semantics, and
//                             `appAllowedToDelegateTo` naming the tier after
//                             them. Under rule 10, for an impersonation the
//                             actor must reach R. For a delegation S must
//                             delegate to R, and the actor must be S. Here
//                             S, the actor and the requester are one tier,
//                             because each assertion is restricted to the
//                             tier that presents it. Nothing is wider:
//                             apigw1 may not reach sp1.
// ---------------------------------------------------------------------------
// THE CLAIM SETTINGS EVERY TIER CARRIES (#483, #484), since every tier is
// the AppliesTo of one token: the groups claim under a name and in a form
// of its own (`teams`, the group's cn), and one custom claim and one custom
// SAML attribute naming the person (`${username}` is a JWT context's,
// `${subject}` a SAML one's), the attribute with a NameFormat.
const BASIC_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
// And #485's configured JWT scopes: one this application declares on
// `oauthAllowedScope`, and one it does not, which product leaves off.
const DECLARED_SCOPE = "chain.read";
const UNDECLARED_SCOPE = "chain.undeclared";
const CLAIM_FIELDS = {
  oauthAllowedScope: [DECLARED_SCOPE],
  wstrustJwtScope: [DECLARED_SCOPE, UNDECLARED_SCOPE],
  appGroupsClaim: "TRUE",
  appGroupsClaimName: "teams",
  appGroupsClaimValue: "cn",
  oauthClaimsAccessToken: JSON.stringify(
    [{ name: "tier", value: "gold-${username}" }]),
  saml2CustomAttributes: JSON.stringify(
    [{ name: "tier", value: "gold-${subject}", nameFormat: BASIC_FORMAT }]),
  // #487: the SAML 1.1 form, with a namespace of its own.
  saml11CustomAttributes: JSON.stringify(
    [{ name: "tier", value: "gold-${subject}",
       namespace: "urn:example:chain" }])
};

function fieldsFor(tier, semantics) {
  log.debug("Entering fieldsFor(). " + tier.identifier);
  const fields = Object.assign({ wstrustAppliesTo: [tier.appliesTo],
                                 samlEntityId: [tier.appliesTo] },
                               CLAIM_FIELDS);
  if (tier.next) {
    fields.appDelegationSemantics = [semantics];
    fields.appDefaultDelegationSemantics = semantics;
    fields.appAllowedToDelegateTo = [tier.next];
  }
  log.debug("Leaving fieldsFor().");
  return fields;
}

// The person was given this process's password when the cast was
// provisioned (provisionGroupAndRole()), ONCE: a product realm's password
// history refuses the same password set twice. Each job has its own person,
// `bob_end_user-<tag>` (#482, `token_exchange_chain_kit.js`), so no other
// job can change it in between.
async function preparePerson(base, cast) {
  log.debug("Entering preparePerson().");
  // No `stsMayAct`: it names ONE delegate and this chain has three.
  await adminOk(base, "/users/set-may-act", { user: cast.user, delegate: "" },
                "clearing " + cast.user + "'s stsMayAct");
  log.debug("Leaving preparePerson().");
}

// One requester's SERVICE ACCOUNT (decision 4): created as one, or made one
// and given this run's password on a rerun.
async function ensureServiceAccount(base, tier, owner) {
  log.debug("Entering ensureServiceAccount(). " + tier.identifier);
  const created = await call("POST", base + "/admin-api/users/create", {
    username: tier.identifier, invent: false, credential: "password",
    password: tier.password, serviceAccount: true, owner: owner,
    attributes: { cn: tier.identifier, sn: tier.identifier,
                  displayName: tier.name } });
  if (!(created.status === 200 && created.json && created.json.ok)) {
    log.info("[registry] " + tier.identifier + "'s service account is " +
             "already here (" + created.text.slice(0, 160).replace(/\s+/g,
             " ") + "); reconciling it.");
    await adminOk(base, "/users/set-service-account",
                  { user: tier.identifier, serviceAccount: true,
                    owner: owner },
                  "making " + tier.identifier + " a service account");
    await adminOk(base, "/users/set-password",
                  { user: tier.identifier, password: tier.password },
                  "setting " + tier.identifier + "'s password");
  }
  log.debug("Leaving ensureServiceAccount().");
}

// The four entries, then every one READ BACK: the reply to a write is the
// service describing what it wrote, and the question is what it holds.
// The person, in a group that holds a role (#483): created, or reconciled
// on a rerun. A create of something already there, and a role given to a
// group that already holds it, are answered "already" and moved past; a
// group membership add is idempotent.
async function provisionGroupAndRole(base, cast) {
  log.debug("Entering provisionGroupAndRole().");
  await registry.ensurePerson(base, cast.user, cast.password);
  const tolerant = async function (path, body) {
    log.debug("Entering tolerant(). " + path);
    const r = await call("POST", base + "/admin-api" + path, body);
    assert.ok(r.status === 200 || /already|exists/i.test(r.text),
              path + ": " + r.status + " " + r.text.slice(0, 300));
    log.debug("Leaving tolerant().");
  };
  await tolerant("/groups/create", { group: cast.team });
  await adminOk(base, "/groups/add-member",
                { group: cast.team, member: cast.user },
                "putting " + cast.user + " in " + cast.team);
  await tolerant("/roles/create-role", { role: cast.role });
  // Not idempotent: a group that already holds the role is answered 400.
  await tolerant("/roles/add-member",
                 { role: cast.role, kind: "group", member: cast.team });
  log.info("[registry] " + cast.user + " is in " + cast.team + ", which " +
           "holds " + cast.role + ".");
  log.debug("Leaving provisionGroupAndRole().");
}

async function provisionCast(base, cast, semantics) {
  log.debug("Entering provisionCast(). " + cast.tag + " " + semantics);
  await provisionGroupAndRole(base, cast);
  log.info("=== Provisioning the four applications and three service " +
           "accounts (" + semantics + ") ===");
  capture.set({ useCase: semantics });
  const owner = String(await registry.setting(base, "admin.writeGroup") ||
                       "");
  assert.ok(owner, "admin.writeGroup is empty, so there is no group to own " +
            "the requesters' service accounts.");
  for (let i = 0; i < cast.tiers.length; i++) {
    const tier = cast.tiers[i];
    await registry.provision(base, {
      identifier: tier.identifier, name: tier.name,
      // oauth2 too, for #485's `oauthAllowedScope`: the declaration a
      // configured JWT scope is judged against.
      protocols: ["wstrust", "saml2", "saml11", "oauth2"],
      fields: fieldsFor(tier, semantics),
      why: "the " + tier.name + " of the WS-Trust " + semantics + " chain"
    });
    if (tier.next) {
      await ensureServiceAccount(base, tier, owner);
    }
  }
  for (let i = 0; i < cast.tiers.length; i++) {
    const tier = cast.tiers[i];
    const entry = await registry.entryOf(base, tier.identifier);
    assert.ok(entry, "the registry has no " + tier.identifier);
    const f = entry.fields || {};
    ["wstrustAppliesTo", "samlEntityId"].forEach(function (attribute) {
      const held = registry.valuesOf(f[attribute]);
      assert.ok(held.indexOf(tier.appliesTo) >= 0, tier.identifier +
        " should register " + tier.appliesTo + " on " + attribute +
        " and holds " + JSON.stringify(held));
    });
    Object.keys(CLAIM_FIELDS).forEach(function (attribute) {
      assert.deepStrictEqual(registry.valuesOf(f[attribute]).slice().sort(),
                             [].concat(CLAIM_FIELDS[attribute]).sort(),
                             tier.identifier + "'s " + attribute);
    });
    if (tier.next) {
      assert.deepStrictEqual(registry.valuesOf(f.appAllowedToDelegateTo),
        [tier.next], tier.identifier + " should delegate to " + tier.next +
        " and nothing else");
      assert.deepStrictEqual(registry.valuesOf(f.appDelegationSemantics),
        [semantics], tier.identifier + "'s semantics");
    }
    log.info("[registry] " + tier.identifier + ": AppliesTo and entityID " +
             tier.appliesTo + (tier.next ? "; " + semantics + " to " +
             tier.next + ", authenticating as the service account " +
             tier.identifier : "; calls nothing"));
  }
  log.debug("Leaving provisionCast().");
}

// ---------------------------------------------------------------------------
// WS-TRUST.
// ---------------------------------------------------------------------------
function xmlText(value) {
  log.debug("Entering xmlText().");
  log.debug("Leaving xmlText().");
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function usernameToken(user, password) {
  log.debug("Entering usernameToken(). " + user);
  log.debug("Leaving usernameToken().");
  return "<wsse:UsernameToken><wsse:Username>" + xmlText(user) +
    "</wsse:Username><wsse:Password>" + xmlText(password) +
    "</wsse:Password></wsse:UsernameToken>";
}

// An Issue in SOAP 1.2: the requester's UsernameToken, the token type, the
// AppliesTo, and the delegated token in `element` (OnBehalfOf, ActAs, or
// none) — an assertion, or the BinarySecurityToken a JWT came in.
function rst(user, password, tokenType, appliesTo, element, assertion) {
  log.debug("Entering rst(). " + user + " " + (element || "Issue"));
  let inner = "";
  if (element === "ActAs") {
    inner = '<wst14:ActAs xmlns:wst14="' + WST14_NS + '">' + assertion +
      "</wst14:ActAs>";
  } else if (element === "OnBehalfOf") {
    inner = "<wst:OnBehalfOf>" + assertion + "</wst:OnBehalfOf>";
  }
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE_NS + '"><s:Header><wsse:Security>' +
    usernameToken(user, password) + "</wsse:Security></s:Header><s:Body>" +
    '<wst:RequestSecurityToken xmlns:wst="' + WST_NS + '">' +
    "<wst:RequestType>" + WST_NS + "/Issue</wst:RequestType>" +
    "<wst:TokenType>" + tokenType + "</wst:TokenType>" +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>' + xmlText(appliesTo) + "</wsa:Address>" +
    "</wsa:EndpointReference></wsp:AppliesTo>" + inner +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
}

// The RSTR, read for what the cast asked for: a SAML 2.0 assertion, or a
// JWT in the wsse:BinarySecurityToken this STS carries one in. Either way
// the RSTR's own wst:TokenType must be the one asked for, and `inner` is
// the element the next hop presents in its OnBehalfOf / ActAs as it came.
async function sts(base, body, what, tokenType) {
  log.debug("Entering sts(). " + what);
  const r = await call("POST", base + "/sts", body,
                       { "Content-Type": "application/soap+xml",
                         Accept: "application/soap+xml" });
  assert.strictEqual(r.status, 200, what + " answered " + r.status +
    " rather than an RSTR: " + r.text.replace(/\s+/g, " ").slice(0, 700));
  const m = /<wst:RequestedSecurityToken>([\s\S]*?)<\/wst:RequestedSecurityToken>/
    .exec(r.text);
  assert.ok(m, what + ": the RSTR carries no RequestedSecurityToken: " +
            r.text.slice(0, 500));
  const answered = (/<wst:TokenType>([^<]+)<\/wst:TokenType>/.exec(r.text) ||
                    [])[1];
  assert.strictEqual(answered, tokenType, what + ": the RSTR's " +
                     "wst:TokenType");
  const expires = (/<wsu:Expires>([^<]+)<\/wsu:Expires>/.exec(r.text) ||
                   [])[1];
  const inner = m[1].trim();
  if (tokenType === JWT_TOKEN_TYPE) {
    const jwt = /^<wsse:BinarySecurityToken([^>]*)>([^<]+)<\/wsse:BinarySecurityToken>$/
      .exec(inner);
    assert.ok(jwt && jwt[1].indexOf('ValueType="' + JWT_TOKEN_TYPE + '"') >=
              0, what + ": the requested token is not a JWT in a " +
              "BinarySecurityToken: " + inner.slice(0, 200));
    log.debug("Leaving sts(). A JWT.");
    return { rstr: r.text, inner: inner, jwt: jwt[2].trim(),
             expires: expires || "" };
  }
  assert.ok(/^<saml:Assertion[\s>]/.test(inner), what + ": the " +
    "requested token is not a SAML 2.0 assertion: " + inner.slice(0, 200));
  log.debug("Leaving sts(). An assertion.");
  return { rstr: r.text, inner: inner, assertion: inner,
           expires: expires || "" };
}

// THE SIGN-IN (decision 2): bob's UsernameToken, for webapp1's registered
// identifier.
async function signIn(base, cast) {
  log.debug("Entering signIn().");
  await preparePerson(base, cast);
  const out = await sts(base, rst(cast.user, cast.password, cast.tokenType,
                                  cast.webapp.appliesTo, "", ""),
                        cast.user + "'s sign-in to " +
                        cast.webapp.identifier, cast.tokenType);
  log.info("[sign-in] " + cast.user + " signed in to " +
           cast.webapp.identifier + " with a UsernameToken, AppliesTo " +
           cast.webapp.appliesTo + ".");
  captureToken(cast, out, {
    hop: capture.hop("bob", "webapp1"), requester: cast.user,
    target: cast.webapp.identifier,
    mechanism: "WS-Trust Issue (UsernameToken)",
    notes: "AppliesTo " + cast.webapp.appliesTo });
  log.debug("Leaving signIn().");
  return out;
}

// ONE HOP: `tier`, authenticated as its own service account, presents
// `inner` — the token the hop before produced, as it came — in `element`
// and asks for the next tier's registered identifier.
async function exchange(base, cast, tier, element, inner) {
  log.debug("Entering exchange(). " + tier.identifier + " " + element);
  const next = tierNamed(cast, tier.next);
  const out = await sts(base, rst(tier.identifier, tier.password,
                                  cast.tokenType, next.appliesTo, element,
                                  inner),
                        tier.identifier + "'s <" + element + "> for " +
                        next.appliesTo, cast.tokenType);
  captureToken(cast, out, {
    hop: capture.hop(chain.stemOf(cast, tier.identifier),
                     chain.stemOf(cast, next.identifier)),
    requester: tier.identifier, target: next.identifier,
    mechanism: "WS-Trust " + element,
    notes: tier.identifier + " authenticated with its service account's " +
      "UsernameToken; AppliesTo " + next.appliesTo });
  log.debug("Leaving exchange().");
  return out;
}

// ---------------------------------------------------------------------------
// THE CAPTURE (`chain_capture.js`, STS_CHAIN_CAPTURE): what each RSTR
// carried, written down where it arrives — a JWT decoded, an assertion
// summarised off its DOM by read() / read11() below. Nothing here runs
// unless the variable names a directory, and nothing here fails the job.
// ---------------------------------------------------------------------------
function samlSummary(got, version) {
  log.debug("Entering samlSummary(). SAML " + version);
  const out = {
    version: version,
    ID: got.id,
    IssueInstant: got.issueInstant,
    Issuer: got.issuer,
    Subject: { NameID: got.nameId, Format: got.nameIdFormat },
    Audience: got.audiences,
    Conditions: { NotBefore: got.notBefore,
                  NotOnOrAfter: got.notOnOrAfter },
    AuthnStatement: version === "2.0"
      ? { AuthnInstant: got.authnInstant,
          AuthnContextClassRef: got.authnContext }
      : { AuthenticationInstant: got.authnInstant,
          AuthenticationMethod: got.authnMethod },
    Attributes: got.attributes,
    DelegationRestriction: version === "2.0"
      ? (got.restricted ? got.delegates.map(function (d) {
        return { NameID: d.nameId, Format: d.format,
                 DelegationInstant: d.instant,
                 ConfirmationMethod: d.confirmationMethod || null };
      }) : null)
      : null,
    signed: !!got.signature
  };
  log.debug("Leaving samlSummary().");
  return out;
}

function captureToken(cast, out, f) {
  log.debug("Entering captureToken(). " + f.hop);
  if (!capture.enabled()) {
    log.debug("Leaving captureToken(). Not capturing.");
    return;
  }
  const notes = f.notes + (out.expires ? "; RSTR Lifetime Expires " +
                           out.expires : "");
  if (cast.tokenType === JWT_TOKEN_TYPE) {
    chain.captureJwt({ hop: f.hop, requester: f.requester,
                       target: f.target, mechanism: f.mechanism,
                       token: out.jwt, notes: notes +
                         "; carried in a wsse:BinarySecurityToken" });
    log.debug("Leaving captureToken(). A JWT.");
    return;
  }
  const saml11 = cast.tokenType === SAML11_TOKEN_TYPE;
  let claims = null;
  let chainOf = [];
  let problem = "";
  try {
    const got = saml11 ? read11(out.assertion) : read(out.assertion);
    claims = samlSummary(got, saml11 ? "1.1" : "2.0");
    chainOf = got.delegates.map(function (d) {
      return d.nameId;
    });
  } catch (e) {
    log.debug("Caught in captureToken(): " + ((e && e.message) || e));
    // The job's own assertions say what is wrong with it; the capture
    // keeps the XML and says it could not summarise it.
    problem = "; not summarised: " + ((e && e.message) || e);
  }
  capture.layer({
    hop: f.hop, requester: f.requester, target: f.target,
    mechanism: f.mechanism,
    kind: saml11 ? "SAML 1.1 assertion" : "SAML 2.0 assertion",
    format: "XML (saml:Assertion, enveloped ds:Signature)",
    value: out.assertion, header: null, claims: claims, actChain: chainOf,
    notes: notes + problem });
  log.debug("Leaving captureToken().");
}

// ---------------------------------------------------------------------------
// AN ASSERTION, READ AS A RELYING PARTY READS ONE.
// ---------------------------------------------------------------------------
function parse(xml) {
  log.debug("Entering parse().");
  const errors = [];
  const doc = new DOMParser({ onError: function (level, message) {
    log.debug("Entering onError(). " + level);
    errors.push(level + ": " + message);
    log.debug("Leaving onError().");
  } }).parseFromString(xml, "text/xml");
  assert.ok(doc && doc.documentElement && errors.length === 0,
            "the assertion does not parse on its own: " + errors.join("; "));
  log.debug("Leaving parse().");
  return doc;
}

function children(el, ns, local) {
  log.debug("Entering children(). " + local);
  const out = [];
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) {
      out.push(n);
    }
  }
  log.debug("Leaving children().");
  return out;
}

function child(el, ns, local) {
  log.debug("Entering child(). " + local);
  const all = el ? children(el, ns, local) : [];
  log.debug("Leaving child().");
  return all.length === 1 ? all[0] : null;
}

function textOf(el) {
  log.debug("Entering textOf().");
  log.debug("Leaving textOf().");
  return el ? String(el.textContent || "").trim() : "";
}

// Everything the jobs assert on, off the DOM rather than by pattern, because
// a relying party reads the elements and a pattern can match a value that
// sits in the wrong place.
function read(xml) {
  log.debug("Entering read().");
  const doc = parse(xml);
  const a = doc.documentElement;
  assert.ok(a.namespaceURI === NS_SAML && a.localName === "Assertion",
            "the document is not a saml:Assertion");
  const subject = child(a, NS_SAML, "Subject");
  const conditions = child(a, NS_SAML, "Conditions");
  assert.ok(conditions, "the assertion has no single <saml:Conditions>");
  const audiences = [];
  children(conditions, NS_SAML, "AudienceRestriction").forEach(function (r) {
    children(r, NS_SAML, "Audience").forEach(function (one) {
      audiences.push(textOf(one));
    });
  });
  // The SAML V2.0 Condition for Delegation Restriction: a <saml:Condition>
  // whose xsi:type is del:DelegationRestrictionType. Its Delegates are read
  // as children, in document order, which the profile makes the order of
  // delegation.
  const restrictions = children(conditions, NS_SAML, "Condition")
    .filter(function (one) {
      return /DelegationRestrictionType$/.test(String(one.getAttributeNS(
        "http://www.w3.org/2001/XMLSchema-instance", "type") || ""));
    });
  assert.ok(restrictions.length <= 1, "the assertion carries " +
            restrictions.length + " Delegation Restrictions");
  const delegates = restrictions.length
    ? children(restrictions[0], NS_DEL, "Delegate").map(function (d) {
      const nameIds = children(d, NS_SAML, "NameID");
      return {
        nameId: textOf(nameIds[0]),
        nameIds: nameIds.length,
        format: nameIds[0] ? String(nameIds[0].getAttribute("Format") || "")
                           : "",
        instant: String(d.getAttribute("DelegationInstant") || ""),
        confirmationMethod: String(d.getAttribute("ConfirmationMethod") ||
                                   "")
      };
    })
    : [];
  // Every <saml:Attribute>, by name: its NameFormat and its values.
  const attributes = {};
  const statement = child(a, NS_SAML, "AttributeStatement");
  (statement ? children(statement, NS_SAML, "Attribute") : [])
    .forEach(function (one) {
      attributes[String(one.getAttribute("Name") || "")] = {
        nameFormat: String(one.getAttribute("NameFormat") || ""),
        values: children(one, NS_SAML, "AttributeValue").map(textOf)
      };
    });
  const authnStatement = child(a, NS_SAML, "AuthnStatement");
  const classRef = authnStatement
    ? textOf(child(child(authnStatement, NS_SAML, "AuthnContext"), NS_SAML,
                   "AuthnContextClassRef"))
    : "";
  const nameIdEl = child(subject, NS_SAML, "NameID");
  const out = {
    xml: xml,
    id: String(a.getAttribute("ID") || ""),
    issueInstant: String(a.getAttribute("IssueInstant") || ""),
    issuer: textOf(child(a, NS_SAML, "Issuer")),
    nameId: textOf(nameIdEl),
    nameIdFormat: nameIdEl ? String(nameIdEl.getAttribute("Format") || "")
                           : "",
    authnInstant: authnStatement
      ? String(authnStatement.getAttribute("AuthnInstant") || "") : "",
    notBefore: String(conditions.getAttribute("NotBefore") || ""),
    notOnOrAfter: String(conditions.getAttribute("NotOnOrAfter") || ""),
    audiences: audiences,
    restricted: restrictions.length === 1,
    delegates: delegates,
    authnContext: classRef,
    attributes: attributes,
    signature: child(a, NS_DSIG, "Signature")
  };
  log.debug("Leaving read(). " + out.id);
  return out;
}

// What every assertion in the chain is held to: the PERSON as its subject,
// addressed to exactly the registered identifier it was asked for and to
// none it has left, a fresh ID, this realm's issuer, and the delegates
// `expect.delegates` names (identifiers, least to most recent; [] for none
// and for no restriction at all).
function assertChainAssertion(cast, xml, expect) {
  log.debug("Entering assertChainAssertion(). " + expect.what);
  const got = read(xml);
  assert.ok(got.id, expect.what + " has no ID");
  (expect.notIds || []).forEach(function (one) {
    assert.notStrictEqual(got.id, one, expect.what + " reuses the ID " + one +
      " of the assertion it was exchanged for; an STS echoing its input " +
      "issues nothing.");
  });
  assert.strictEqual(got.nameId, cast.user, expect.what + " is about \"" +
    got.nameId + "\" rather than " + cast.user + ". An exchange carries the " +
    "SUBJECT forward; an assertion naming the requester is the tier acting " +
    "as itself.");
  assert.ok(got.issuer, expect.what + " names no Issuer");
  if (expect.issuer) {
    assert.strictEqual(got.issuer, expect.issuer, expect.what + " was " +
                       "issued by " + got.issuer + ", not by the realm " +
                       "that issued the rest of the chain");
  }
  assert.deepStrictEqual(got.audiences, [expect.audience], expect.what +
    " should be restricted to exactly " + expect.audience + ", the " +
    "registered identifier it was asked for by, and its audiences are " +
    JSON.stringify(got.audiences));
  (expect.notAudience || []).forEach(function (one) {
    assert.ok(got.audiences.indexOf(one) < 0, expect.what + " is still " +
              "addressed to " + one);
  });
  assert.ok(got.signature, expect.what + " carries no ds:Signature of its " +
            "own");
  assert.deepStrictEqual(got.delegates.map(function (d) {
    return d.nameId;
  }), expect.delegates, expect.what + " should name the delegates " +
    JSON.stringify(expect.delegates) + " (sstc-saml-delegation-cs-01: " +
    "\"ordered from least to most recent\") and names " +
    JSON.stringify(got.delegates));
  assert.strictEqual(got.restricted, expect.delegates.length > 0,
    expect.what + (got.restricted ? " carries a Delegation Restriction " +
    "naming nobody" : " has no Delegation Restriction"));
  got.delegates.forEach(function (d) {
    // One NameID, in the entity format: each delegate is an APPLICATION.
    // No ConfirmationMethod, which the profile defines "if the delegate
    // presented a SAML assertion to authenticate itself"; each delegate
    // here authenticated with a UsernameToken.
    assert.strictEqual(d.nameIds, 1, expect.what + ": a Delegate with " +
                       d.nameIds + " NameIDs");
    assert.strictEqual(d.format, ENTITY_FORMAT, expect.what + ": the " +
                       "delegate " + d.nameId + " has Format " + d.format);
    assert.ok(!isNaN(Date.parse(d.instant)), expect.what + ": the " +
              "delegate " + d.nameId + "'s DelegationInstant \"" +
              d.instant + "\"");
    assert.strictEqual(d.confirmationMethod, "", expect.what + ": the " +
      "delegate " + d.nameId + " carries ConfirmationMethod " +
      d.confirmationMethod + ", and it authenticated with a password");
  });
  if (expect.authnContext) {
    assert.strictEqual(got.authnContext, expect.authnContext, expect.what +
                       "'s AuthnContextClassRef");
  }
  // THE APPLICATION'S CLAIM SETTINGS (#483, #484), on the subject: the
  // groups claim as `teams` (cn), the roles claim, and the custom attribute
  // with its NameFormat — the AppliesTo's own settings, the person's own
  // group and role, whoever asked.
  const attrs = got.attributes;
  assert.ok(attrs.teams && JSON.stringify(attrs.teams.values) ===
            JSON.stringify([cast.team]), expect.what + " should carry the " +
            "groups claim as `teams` [" + cast.team + "]: " +
            JSON.stringify(attrs));
  assert.ok(attrs.groups === undefined, expect.what + " carries the " +
            "realm's `groups` attribute beside the application's `teams`");
  assert.ok(attrs.roles && attrs.roles.values.indexOf(cast.role) >= 0,
            expect.what + " should carry the roles claim with " + cast.role +
            ": " + JSON.stringify(attrs.roles));
  assert.ok(attrs.tier && attrs.tier.nameFormat === BASIC_FORMAT &&
            JSON.stringify(attrs.tier.values) ===
              JSON.stringify(["gold-" + cast.user]),
            expect.what + " should carry the custom attribute tier=gold-" +
            cast.user + " (" + BASIC_FORMAT + "): " +
            JSON.stringify(attrs.tier));
  log.info("[assertion] " + expect.what + ": ID=" + got.id + ", subject=" +
           got.nameId + ", audience=" + JSON.stringify(got.audiences) +
           ", delegates=" + JSON.stringify(got.delegates.map(function (d) {
             return d.nameId;
           })) + ", AuthnContext=" + got.authnContext);
  log.debug("Leaving assertChainAssertion().");
  return got;
}

// ---------------------------------------------------------------------------
// THE TARGET'S OWN VALIDATION. There is no introspection for an assertion,
// so sp1 does what a SAML relying party does. It verifies the enveloped
// signature against the realm's PUBLISHED signing certificate
// (`GET /sts/cert`), and only that signature, the one whose Reference is
// this assertion's ID. It checks the Conditions' window against its own
// clock and its own entityID in the AudienceRestriction. xml-crypto and
// xmldom are this repository's root dependencies; node's crypto checks the
// certificate. Nothing here is the service's code.
// ---------------------------------------------------------------------------
async function signingCertificate(base) {
  log.debug("Entering signingCertificate().");
  const r = await call("GET", base + "/sts/cert", undefined,
                       { Accept: "*/*" });
  assert.strictEqual(r.status, 200, "GET /sts/cert: " + r.status);
  const pem = (/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
    .exec(r.text) || [])[0];
  assert.ok(pem, "GET /sts/cert published no PEM certificate: " +
            r.text.slice(0, 200));
  const cert = new crypto.X509Certificate(pem);
  log.info("[target] the realm's published signing certificate: " +
           cert.subject.replace(/\n/g, ", ") + ", valid to " + cert.validTo);
  log.debug("Leaving signingCertificate().");
  return pem;
}

function validateAtTarget(xml, certPem, audience, skewMs) {
  log.debug("Entering validateAtTarget().");
  const got = read(xml);
  assert.ok(got.signature, "the assertion is unsigned");
  const refs = got.signature.getElementsByTagNameNS(NS_DSIG, "Reference");
  assert.strictEqual(refs.length, 1, "the signature has " + refs.length +
                     " References");
  assert.strictEqual(String(refs[0].getAttribute("URI") || ""), "#" + got.id,
    "the signature covers " + refs[0].getAttribute("URI") + " and not this " +
    "assertion (" + got.id + ")");
  let verified = false;
  try {
    const sig = new SignedXml({ publicCert: certPem });
    sig.loadSignature(got.signature);
    verified = sig.checkSignature(xml);
  } catch (e) {
    log.debug("Caught in validateAtTarget(): " + ((e && e.message) || e));
    // xml-crypto throws for most failures; its message is the diagnosis.
    assert.fail("the assertion's signature does not verify against the " +
                "realm's published certificate: " + e.message);
  }
  assert.strictEqual(verified, true, "the assertion's signature does not " +
                     "verify against the realm's published certificate");
  const now = Date.now();
  assert.ok(Date.parse(got.notBefore) <= now + skewMs, "NotBefore " +
            got.notBefore + " is in the future");
  assert.ok(Date.parse(got.notOnOrAfter) > now - skewMs, "NotOnOrAfter " +
            got.notOnOrAfter + " has passed");
  assert.deepStrictEqual(got.audiences, [audience], "the target's own " +
    "entityID must be the assertion's one audience: " +
    JSON.stringify(got.audiences));
  log.debug("Leaving validateAtTarget().");
  return got;
}

// ---------------------------------------------------------------------------
// A SAML 1.1 ASSERTION, READ AS A RELYING PARTY READS ONE (#487's pair).
// SAML 1.1 names things differently: the Issuer is an ATTRIBUTE, the
// identifier is `AssertionID`, the subject a NameIdentifier, the audience an
// AudienceRestrictionCondition, and an attribute is AttributeName plus
// AttributeNamespace. It has no Delegation Restriction, so an ActAs answered
// in SAML 1.1 names nobody but the subject (ws-trust/CLAUDE.md's exception).
// ---------------------------------------------------------------------------
function read11(xml) {
  log.debug("Entering read11().");
  const doc = parse(xml);
  const a = doc.documentElement;
  assert.ok(a.namespaceURI === NS_SAML11 && a.localName === "Assertion" &&
            a.getAttribute("MajorVersion") === "1" &&
            a.getAttribute("MinorVersion") === "1",
            "the document is not a SAML 1.1 saml:Assertion");
  const conditions = child(a, NS_SAML11, "Conditions");
  assert.ok(conditions, "the SAML 1.1 assertion has no single Conditions");
  const audiences = [];
  children(conditions, NS_SAML11, "AudienceRestrictionCondition")
    .forEach(function (one) {
      children(one, NS_SAML11, "Audience").forEach(function (aud) {
        audiences.push(textOf(aud));
      });
    });
  const authn = child(a, NS_SAML11, "AuthenticationStatement");
  const subject = authn ? child(authn, NS_SAML11, "Subject") : null;
  const attributes = {};
  const statement = child(a, NS_SAML11, "AttributeStatement");
  (statement ? children(statement, NS_SAML11, "Attribute") : [])
    .forEach(function (one) {
      attributes[String(one.getAttribute("AttributeName") || "")] = {
        namespace: String(one.getAttribute("AttributeNamespace") || ""),
        values: children(one, NS_SAML11, "AttributeValue").map(textOf)
      };
    });
  const nameIdEl = subject ? child(subject, NS_SAML11, "NameIdentifier")
                           : null;
  const out = {
    xml: xml,
    id: String(a.getAttribute("AssertionID") || ""),
    issueInstant: String(a.getAttribute("IssueInstant") || ""),
    issuer: String(a.getAttribute("Issuer") || ""),
    nameId: textOf(nameIdEl),
    nameIdFormat: nameIdEl ? String(nameIdEl.getAttribute("Format") || "")
                           : "",
    authnInstant: authn ? String(authn.getAttribute("AuthenticationInstant") ||
                                 "") : "",
    notBefore: String(conditions.getAttribute("NotBefore") || ""),
    notOnOrAfter: String(conditions.getAttribute("NotOnOrAfter") || ""),
    audiences: audiences,
    authnMethod: authn ? String(authn.getAttribute("AuthenticationMethod") ||
                                "") : "",
    attributes: attributes,
    delegates: [],
    hasDelegation: xml.indexOf("Delegat") >= 0,
    signature: child(a, NS_DSIG, "Signature")
  };
  log.debug("Leaving read11(). " + out.id);
  return out;
}

// What every SAML 1.1 assertion in the chain is held to: the claims
// assertChainAssertion() checks, in SAML 1.1's spelling, and NO delegate
// chain whatever was asked.
function assertChainAssertion11(cast, xml, expect) {
  log.debug("Entering assertChainAssertion11(). " + expect.what);
  const got = read11(xml);
  assert.ok(got.id, expect.what + " has no AssertionID");
  (expect.notIds || []).forEach(function (one) {
    assert.notStrictEqual(got.id, one, expect.what + " reuses the " +
                          "AssertionID " + one);
  });
  assert.strictEqual(got.nameId, cast.user, expect.what + " is about \"" +
                     got.nameId + "\" rather than " + cast.user);
  if (expect.issuer) {
    assert.strictEqual(got.issuer, expect.issuer, expect.what + "'s Issuer");
  }
  assert.deepStrictEqual(got.audiences, [expect.audience], expect.what +
    " should be restricted to exactly " + expect.audience + ": " +
    JSON.stringify(got.audiences));
  (expect.notAudience || []).forEach(function (one) {
    assert.ok(got.audiences.indexOf(one) < 0, expect.what + " is still " +
              "addressed to " + one);
  });
  assert.ok(got.signature, expect.what + " carries no ds:Signature");
  assert.ok(!got.hasDelegation, expect.what + " carries a delegation " +
            "element, and SAML 1.1 has none to carry");
  if (expect.authnMethod) {
    assert.strictEqual(got.authnMethod, expect.authnMethod, expect.what +
                       "'s AuthenticationMethod");
  }
  // THE APPLICATION'S SAML 1.1 SETTINGS (#487, #483's plumbing): `teams`,
  // `roles`, and `saml11CustomAttributes`' `tier` in its own namespace.
  const attrs = got.attributes;
  assert.ok(attrs.teams && JSON.stringify(attrs.teams.values) ===
            JSON.stringify([cast.team]), expect.what + " should carry " +
            "teams [" + cast.team + "]: " + JSON.stringify(attrs));
  assert.ok(attrs.roles && attrs.roles.values.indexOf(cast.role) >= 0,
            expect.what + " should carry " + cast.role + " in roles: " +
            JSON.stringify(attrs.roles));
  assert.ok(attrs.tier && attrs.tier.namespace === "urn:example:chain" &&
            JSON.stringify(attrs.tier.values) ===
              JSON.stringify(["gold-" + cast.user]),
            expect.what + " should carry tier=gold-" + cast.user + " in " +
            "urn:example:chain: " + JSON.stringify(attrs.tier));
  log.info("[assertion 1.1] " + expect.what + ": AssertionID=" + got.id +
           ", Issuer=" + got.issuer + ", subject=" + got.nameId +
           ", audience=" + JSON.stringify(got.audiences) + ", method=" +
           got.authnMethod);
  log.debug("Leaving assertChainAssertion11().");
  return got;
}

// The target's own validation of a SAML 1.1 assertion: the signature over
// THIS assertion (its Reference names the AssertionID, which xml-crypto is
// told is the identifier attribute), the Conditions, its own audience.
function validateAtTarget11(xml, certPem, audience, skewMs) {
  log.debug("Entering validateAtTarget11().");
  const got = read11(xml);
  assert.ok(got.signature, "the SAML 1.1 assertion is unsigned");
  const refs = got.signature.getElementsByTagNameNS(NS_DSIG, "Reference");
  assert.strictEqual(refs.length, 1, "the signature has " + refs.length +
                     " References");
  assert.strictEqual(String(refs[0].getAttribute("URI") || ""), "#" + got.id,
                     "the signature covers " + refs[0].getAttribute("URI"));
  let verified = false;
  try {
    const sig = new SignedXml({ publicCert: certPem,
                                idAttribute: "AssertionID" });
    sig.loadSignature(got.signature);
    verified = sig.checkSignature(xml);
  } catch (e) {
    log.debug("Caught in validateAtTarget11(): " + ((e && e.message) || e));
    assert.fail("the SAML 1.1 assertion's signature does not verify " +
                "against the realm's published certificate: " + e.message);
  }
  assert.strictEqual(verified, true, "the SAML 1.1 assertion's signature " +
                     "does not verify against the published certificate");
  const now = Date.now();
  assert.ok(Date.parse(got.notBefore) <= now + skewMs, "NotBefore " +
            got.notBefore + " is in the future");
  assert.ok(Date.parse(got.notOnOrAfter) > now - skewMs, "NotOnOrAfter " +
            got.notOnOrAfter + " has passed");
  assert.deepStrictEqual(got.audiences, [audience], "the target's own " +
    "identifier must be the one audience: " + JSON.stringify(got.audiences));
  log.debug("Leaving validateAtTarget11().");
  return got;
}

// ---------------------------------------------------------------------------
// A JWT, READ AS ITS RELYING PARTY READS ONE (#473's second pair). RFC 9068
// and RFC 8693 govern the JWT's STRUCTURE AND CONTENTS and nothing else
// (rcbj): the header's `typ`, the claim set and `act`. The exchange that
// produced it is WS-Trust's, read above.
//
// The signature is checked against the realm's PUBLISHED key set
// (`GET /oauth2/jwks`, where the JWT's `kid` is published) with node's own
// crypto, and the issuer against the one the STS names on `GET /sts`.
// ---------------------------------------------------------------------------
function jwtParts(token, what) {
  log.debug("Entering jwtParts(). " + what);
  const parts = String(token || "").split(".");
  assert.strictEqual(parts.length, 3, what + " is not a compact JWS");
  const out = {
    token: token,
    header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
  };
  log.debug("Leaving jwtParts().");
  return out;
}

async function jwks(base) {
  log.debug("Entering jwks().");
  const r = await call("GET", base + "/oauth2/jwks");
  assert.ok(r.status === 200 && r.json && Array.isArray(r.json.keys),
            "GET /oauth2/jwks: " + r.status + " " + r.text.slice(0, 200));
  log.debug("Leaving jwks(). " + r.json.keys.length + " key(s).");
  return r.json.keys;
}

// THE ISSUER OF A WS-TRUST JWT (#480): the realm's OAuth 2.0 issuer, what
// `/.well-known/oauth-authorization-server` publishes — RFC 9068 section 4's
// check — and what `GET /sts` names on its `JWT issuer:` line. Both are
// read, and must agree.
async function publishedIssuer(base) {
  log.debug("Entering publishedIssuer().");
  const meta = await call("GET", base +
                          "/.well-known/oauth-authorization-server");
  assert.ok(meta.status === 200 && meta.json && meta.json.issuer,
            "the authorization server metadata at " + base + ": " +
            meta.status + " " + meta.text.slice(0, 200));
  const r = await call("GET", base + "/sts", undefined, { Accept: "*/*" });
  const named = (/JWT issuer:\s*(\S+)/.exec(r.text) || [])[1] || "";
  assert.strictEqual(named, meta.json.issuer, "GET /sts should name the " +
    "JWT issuer as the authorization server metadata does (#480): " +
    r.text.slice(0, 300));
  log.debug("Leaving publishedIssuer(). " + named);
  return named;
}

// THE ISSUER A WS-TRUST SAML ASSERTION FOR `tier` CARRIES (#480, #494), in
// EITHER mode since #494: the entityID this identity provider publishes to
// that registered application in its own `/saml2/metadata/{sp}` — the
// per-SP entityID SAML SSO names itself by, where
// `saml2.perApplicationEntityId` is on. And ONE NAME PER APPLICATION: the
// application's own WS-Federation metadata, `/wsfed/metadata/{rp}`, must
// name the same entityID. `product` is kept for the callers and no longer
// changes the answer.
async function samlIssuerFor(base, tier, product) {
  log.debug("Entering samlIssuerFor(). " + tier.identifier +
            (product ? " (product)" : ""));
  const r = await call("GET", base + "/saml2/metadata/" +
                       encodeURIComponent(tier.identifier), undefined,
                       { Accept: "application/samlmetadata+xml, */*" });
  const out = (/entityID="([^"]+)"/.exec(r.text) || [])[1] || "";
  assert.ok(r.status === 200 && out, "/saml2/metadata/" + tier.identifier +
            ": " + r.status + " " + r.text.slice(0, 200));
  assert.notStrictEqual(out, "urn:wstrust:mock:sts", "the service " +
                        "publishes the development placeholder as its " +
                        "entityID (#494 retired it)");
  const f = await call("GET", base + "/wsfed/metadata/" +
                       encodeURIComponent(tier.identifier), undefined,
                       { Accept: "application/xml, */*" });
  const wsfed = (/entityID="([^"]+)"/.exec(f.text) || [])[1] || "";
  assert.strictEqual(wsfed, out, "/wsfed/metadata/" + tier.identifier +
                     " should name the application's one entityID, as " +
                     "/saml2/metadata/" + tier.identifier + " does (#494): " +
                     f.status + " " + f.text.slice(0, 200));
  log.debug("Leaving samlIssuerFor(). " + out);
  return out;
}

// Whether a client's own subject is `urn:sts:client:<id>` at the service:
// RFC 9700 mode, which product implies and a realm or the process may turn
// on (oauth2.rfc9700, or OAuth 2.1 mode, which implies it). The form the
// service's OAuth tokens give a client actor (#471), and so the form its
// WS-Trust JWTs do since #476.
async function clientSubjectsNamespaced(base, product) {
  log.debug("Entering clientSubjectsNamespaced().");
  if (product) {
    log.debug("Leaving clientSubjectsNamespaced(). Product.");
    return true;
  }
  const on = function (value) {
    log.debug("Entering on().");
    log.debug("Leaving on().");
    return value === true || String(value) === "true";
  };
  const answer = on(await registry.setting(base, "oauth2.rfc9700")) ||
    on(await registry.setting(base, "oauth2.oauth21"));
  log.debug("Leaving clientSubjectsNamespaced(). " + answer);
  return answer;
}

const JWS_HASHES = { RS256: "sha256", RS384: "sha384", RS512: "sha512",
                     PS256: "sha256", PS384: "sha384", PS512: "sha512",
                     ES256: "sha256", ES384: "sha384", ES512: "sha512" };

// The JWS signature over the key the set publishes under its `kid`.
function verifyWithJwks(parsed, keys, what) {
  log.debug("Entering verifyWithJwks(). " + what);
  const alg = String(parsed.header.alg || "");
  const jwk = keys.filter(function (k) {
    return k.kid === parsed.header.kid;
  })[0];
  assert.ok(jwk, what + "'s kid " + parsed.header.kid + " is not in the " +
            "realm's published key set");
  const segments = parsed.token.split(".");
  const data = Buffer.from(segments[0] + "." + segments[1]);
  const signature = Buffer.from(segments[2], "base64url");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  let ok;
  if (alg === "EdDSA") {
    ok = crypto.verify(null, data, key, signature);
  } else {
    assert.ok(JWS_HASHES[alg], what + " is signed with " + alg + ", which " +
              "this relying party does not verify");
    const options = { key: key };
    if (/^PS/.test(alg)) {
      options.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
      options.saltLength = Number(alg.slice(2)) / 8;
    }
    if (/^ES/.test(alg)) {
      options.dsaEncoding = "ieee-p1363";
    }
    ok = crypto.verify(JWS_HASHES[alg], data, options, signature);
  }
  assert.strictEqual(ok, true, what + "'s signature does not verify with " +
                     "the published key " + jwk.kid);
  log.debug("Leaving verifyWithJwks().");
}

// What every JWT in the chain is held to. `expect`: { what, audience,
// issuer, sub (the person's subject, once known), clientId ('' for none),
// act (the whole expected chain, or undefined for none), notJtis,
// expires (the RSTR's wst:Lifetime Expires), product }. Answers the parsed
// JWT.
function assertChainJwt(cast, out, keys, expect) {
  log.debug("Entering assertChainJwt(). " + expect.what);
  const parsed = jwtParts(out.jwt, expect.what);
  const h = parsed.header;
  const c = parsed.claims;
  // RFC 9068 section 2.1.
  assert.strictEqual(h.typ, "at+jwt", expect.what + "'s header typ is " +
    JSON.stringify(h.typ) + "; RFC 9068 section 2.1 has \"at+jwt\"");
  verifyWithJwks(parsed, keys, expect.what);
  // RFC 9068 section 2.2: iss, exp, aud, sub, client_id, iat, jti.
  assert.strictEqual(c.iss, expect.issuer, expect.what + "'s iss");
  assert.ok(Number.isInteger(c.iat) && Number.isInteger(c.exp) &&
            c.exp > c.iat, expect.what + "'s iat / exp: " + c.iat + " / " +
            c.exp);
  // WS-Trust's own lifetime and the JWT's are one decision: the RSTR's
  // wst:Lifetime Expires is `exp`, to the second.
  assert.ok(Math.abs(c.exp * 1000 - Date.parse(out.expires)) <= 2000,
            expect.what + "'s exp " + new Date(c.exp * 1000).toISOString() +
            " is not the RSTR's wst:Lifetime Expires " + out.expires);
  assert.deepStrictEqual([].concat(c.aud), [expect.audience], expect.what +
    " should be addressed to exactly " + expect.audience + ", the " +
    "registered identifier it was asked for by: aud=" +
    JSON.stringify(c.aud));
  assert.ok(/^urn:uuid:/.test(String(c.sub || "")), expect.what + "'s sub " +
            c.sub + " is not this service's subject for a person");
  if (expect.sub) {
    assert.strictEqual(c.sub, expect.sub, expect.what + " is about " +
                       c.sub + " and the chain is about " + expect.sub);
  }
  assert.strictEqual(c.name, cast.user, expect.what + " names " + c.name);
  assert.ok(typeof c.jti === "string" && c.jti.length >= 16, expect.what +
            "'s jti " + c.jti);
  (expect.notJtis || []).forEach(function (one) {
    assert.notStrictEqual(c.jti, one, expect.what + " reuses the jti of " +
                          "the token it was exchanged for");
  });
  if (expect.clientId) {
    assert.strictEqual(c.client_id, expect.clientId, expect.what + " was " +
      "issued to " + c.client_id + " rather than the requester " +
      expect.clientId + " (RFC 9068 section 2.2, RFC 8693 section 4.3)");
  } else {
    // THE EXCEPTION: a person asking for themselves has no client.
    assert.strictEqual(c.client_id, undefined, expect.what + " names a " +
      "client_id (" + c.client_id + ") and nobody but the person asked");
  }
  // THE APPLICATION'S CONFIGURED SCOPES (#485): `wstrustJwtScope`, judged
  // as an OAuth access token's are — the declared one kept, the undeclared
  // one left off in product and kept in development.
  const scope = expect.product ? DECLARED_SCOPE
                               : DECLARED_SCOPE + " " + UNDECLARED_SCOPE;
  assert.strictEqual(c.scope, scope, expect.what + "'s scope should be \"" +
                     scope + "\" (wstrustJwtScope, " + (expect.product
                       ? "the undeclared one dropped in product)"
                       : "development grants the undeclared one)") +
                     " and is " + JSON.stringify(c.scope));
  assert.deepStrictEqual(c.act, expect.act, expect.what + " should carry " +
    "act " + JSON.stringify(expect.act) + " (RFC 8693 section 4.1: the " +
    "current actor outermost) and carries " + JSON.stringify(c.act));
  // THE APPLICATION'S CLAIM SETTINGS (#483, #484), as an OAuth access token
  // for it carries them: `teams` (cn), `roles`, and the custom `tier`.
  assert.deepStrictEqual(c.teams, [cast.team], expect.what + " should " +
                         "carry the groups claim as `teams`");
  assert.strictEqual(c.groups, undefined, expect.what + " carries the " +
                     "realm's `groups` claim beside the application's");
  assert.ok(Array.isArray(c.roles) && c.roles.indexOf(cast.role) >= 0,
            expect.what + " should carry " + cast.role + " in roles: " +
            JSON.stringify(c.roles));
  assert.strictEqual(c.tier, "gold-" + cast.user, expect.what + "'s " +
                     "custom claim tier");
  // RFC 8693 section 4.4: none, since the person names no delegate.
  assert.strictEqual(c.may_act, undefined, expect.what + " carries may_act " +
                     JSON.stringify(c.may_act));
  log.info("[jwt] " + expect.what + ": typ=" + h.typ + ", kid=" + h.kid +
           ", sub=" + c.sub + ", aud=" + JSON.stringify(c.aud) +
           ", client_id=" + c.client_id + ", act=" + JSON.stringify(c.act) +
           ", jti=" + c.jti);
  log.debug("Leaving assertChainJwt().");
  return parsed;
}

// The target's own validation of a JWT: the published key, `typ`, its own
// identifier in `aud`, the issuer the STS publishes, and the clock.
function validateJwtAtTarget(token, keys, audience, issuer, skewMs) {
  log.debug("Entering validateJwtAtTarget().");
  const parsed = jwtParts(token, "the token at the target");
  verifyWithJwks(parsed, keys, "the token at the target");
  assert.strictEqual(parsed.header.typ, "at+jwt");
  assert.strictEqual(parsed.claims.iss, issuer, "iss " + parsed.claims.iss +
                     " is not the issuer GET /sts names, " + issuer);
  assert.ok([].concat(parsed.claims.aud).indexOf(audience) >= 0,
            "the target's identifier is not in aud: " +
            JSON.stringify(parsed.claims.aud));
  const now = Date.now();
  assert.ok(parsed.claims.exp * 1000 > now - skewMs, "the token has expired");
  assert.ok(parsed.claims.iat * 1000 <= now + skewMs, "iat is in the future");
  if (parsed.claims.nbf !== undefined) {
    assert.ok(parsed.claims.nbf * 1000 <= now + skewMs, "nbf is in the " +
              "future");
  }
  log.debug("Leaving validateJwtAtTarget().");
  return parsed;
}

// ---------------------------------------------------------------------------
// THE REGISTER. Each act is found by the ID of the assertion it PRODUCED,
// which is the assertion this job received, so neither a pool of other jobs
// nor a rerun of this one can be mistaken for it, and no `seq` is read.
// ---------------------------------------------------------------------------
function actProducing(acts, id, what) {
  log.debug("Entering actProducing(). " + id);
  const found = acts.filter(function (row) {
    return (row.produced || []).some(function (one) {
      return one.identifier === id;
    });
  });
  assert.strictEqual(found.length, 1, "the delegation register should " +
    "hold exactly ONE act that produced " + what + " (ID " + id + "), and " +
    "holds " + found.length + ". Since this run started it holds: " +
    JSON.stringify(acts.map(function (row) {
      return row.type + " " + row.initial.presented + " -> " +
        row.intermediary.presented + " -> " + row.target.application;
    })));
  log.debug("Leaving actProducing().");
  return found[0];
}

// One act, for one hop. `expect`: { type, mode, semantics, requester,
// target, appliesTo, consumedId, producedId, producedKind, product } —
// `producedKind` "SAML 2.0 assertion" when absent, "JWT" for a JWT.
function assertAct(cast, act, expect) {
  log.debug("Entering assertAct(). " + expect.requester);
  assert.strictEqual(act.protocol, "WS-Trust", "protocol " + act.protocol);
  assert.strictEqual(act.type, expect.type, "the act was filed as \"" +
                     act.type + "\" and should be \"" + expect.type + "\".");
  assert.strictEqual(act.mode, expect.mode, "the act's mode is \"" +
                     act.mode + "\" and should be \"" + expect.mode + "\".");
  assert.strictEqual(act.outcome, "issued", "outcome " + act.outcome);
  assert.strictEqual(act.initial.presented, cast.user, "the act is for \"" +
                     act.initial.presented + "\" rather than " + cast.user);
  // The requester in the middle: the service account it authenticated as,
  // and the APPLICATION of the same name the register found for it.
  assert.strictEqual(act.intermediary.presented, expect.requester,
    "the act names \"" + act.intermediary.presented + "\" as the requester " +
    "rather than " + expect.requester);
  assert.strictEqual(act.intermediary.application, expect.requester,
    "the requester " + expect.requester + " should be found as the " +
    "application of that name, and the act says \"" +
    act.intermediary.application + "\"");
  assert.strictEqual(act.target.application, expect.target,
    "the act reached \"" + act.target.application + "\" rather than " +
    expect.target + ", whose registered identifier " + expect.appliesTo +
    " the RST asked for. Naming the URI is the registry lookup " +
    "(applications.forAppliesTo()) not happening.");
  const what = String(act.target.what || "");
  assert.ok(what.indexOf(expect.appliesTo) >= 0 &&
            what.indexOf("wstrustAppliesTo") >= 0,
    "the act's target should say which AppliesTo resolved, on " +
    "wstrustAppliesTo: \"" + what + "\"");
  // In WS-Trust's own words (#481): the application the AppliesTo names,
  // and the token inside the element, which was issued for the requester
  // itself (each tier presents what was addressed to it) — not RFC 8693's
  // "subject token".
  const element = expect.type === "wstrust-actas" ? "<wst14:ActAs>"
                                                  : "<wst:OnBehalfOf>";
  const allowed = "the issuance policy allowed " + expect.semantics +
      " by \"" + expect.requester + "\" for \"" + cast.user + "\" to \"" +
      expect.target + "\", the application the AppliesTo names (the " +
      "token inside " + element + " was issued for \"" + expect.requester +
      "\").";
  assert.ok(String(act.authorizedBy || "") === allowed,
    "the act should say \"" + allowed + "\" and says \"" +
    act.authorizedBy + "\". \"WOULD HAVE BEEN REFUSED\" means the policy " +
    "this job provisioned is not the one the service read.");
  assert.strictEqual(act.reason, "", "an issued act carries a refusal " +
                     "reason: \"" + act.reason + "\"");
  const consumed = act.consumed || [];
  const delegated = consumed.filter(function (one) {
    return one.kind === "delegated token";
  });
  assert.ok(delegated.length === 1 &&
            delegated[0].identifier === expect.consumedId,
    "the act should record consuming the assertion " + expect.consumedId +
    " and records " + JSON.stringify(consumed));
  assert.ok(consumed.some(function (one) {
    return one.kind === "WS-Security credential";
  }), "the act does not record the requester's own credential: " +
    JSON.stringify(consumed));
  const produced = act.produced || [];
  assert.ok(produced.length === 1 &&
            produced[0].kind === (expect.producedKind ||
                                  "SAML 2.0 assertion") &&
            produced[0].identifier === expect.producedId,
    "the act should record producing the assertion " + expect.producedId +
    " and records " + JSON.stringify(produced));
  if (expect.product) {
    assert.strictEqual(act.policed, true, "a product service enforces the " +
                       "delegation policy, and this act was not policed.");
  }
  log.info("[register] " + act.typeLabel + ": " + act.initial.presented +
           " -> " + act.intermediary.presented + " -> " +
           act.target.application + "; " + act.authorizedBy);
  log.debug("Leaving assertAct().");
}

// WHAT THE ACT'S OWN NOTES SAY, held to what the jobs just verified on the
// wire. The note on an ActAs act says the issued token names who acted, in
// that token's vocabulary — a SAML Delegation Restriction or a JWT's `act`
// — and an OnBehalfOf act's says it adds nobody (#478; until then it said
// no ActAs token carried the composite fact, and the jobs WARNed on it).
// The consumed token's note says whether it was verified, by mode (#479).
// What is still only reported, as a WARN naming the finding, answers the
// list this returns.
function actNotes(act, element, product, jwt, saml11) {
  log.debug("Entering actNotes().");
  const out = [];
  const note = String(act.note || "");
  if (saml11) {
    // #487: SAML 1.1 has no element to say who acted, and the note says so.
    assert.ok(element === "ActAs"
      ? /a SAML 1\.1 assertion has no element to say so/.test(note)
      : /the SAML 1\.1 assertion names the subject and adds nobody/
        .test(note), "the " + element + " act's note for a SAML 1.1 token " +
      "says: \"" + note + "\"");
  } else if (element === "ActAs") {
    assert.ok(/ActAs is COMPOSITE/.test(note) &&
              (jwt ? /nested `act` claim/.test(note)
                   : /Delegation Restriction/.test(note)),
      "the ActAs act's note should say the " + (jwt ? "JWT" : "assertion") +
      " names who acted (" + (jwt ? "its `act`" : "its Delegation " +
      "Restriction") + ") and says: \"" + note + "\"");
  } else {
    assert.ok(/OnBehalfOf is IMPERSONATION/.test(note) &&
              /adds nobody/.test(note) &&
              note.indexOf("the " + (jwt ? "JWT" : "assertion") + " names") >=
              0,
      "the OnBehalfOf act's note should say the token adds nobody and " +
      "says: \"" + note + "\"");
  }
  // The consumed token's note follows the mode (#479): product verified it,
  // development did not.
  const delegated = (act.consumed || []).filter(function (one) {
    return one.kind === "delegated token";
  })[0] || {};
  const consumed = String(delegated.note || "");
  if (product) {
    assert.ok(/VERIFIED/.test(consumed) &&
              consumed.indexOf(jwt ? "a JWT" : "a SAML assertion") >= 0 &&
              !/not checked/.test(consumed),
      "a product service verified the consumed " + (jwt ? "JWT" :
      "assertion") + " and the act's note says: \"" + consumed + "\"");
  } else {
    assert.ok(/NOT verified/.test(consumed), "a development service did " +
              "not verify the consumed token and the act's note says: \"" +
              consumed + "\"");
  }
  out.forEach(function (one) {
    log.warn("[finding] " + one + ".");
  });
  log.debug("Leaving actNotes(). " + out.length);
  return out;
}

module.exports = {
  AC_PASSWORD: AC_PASSWORD,
  AM_PASSWORD: AM_PASSWORD,
  AM_UNSPECIFIED: AM_UNSPECIFIED,
  SAML11_TOKEN_TYPE: SAML11_TOKEN_TYPE,
  read11: read11,
  assertChainAssertion11: assertChainAssertion11,
  validateAtTarget11: validateAtTarget11,
  JWT_TOKEN_TYPE: JWT_TOKEN_TYPE,
  jwks: jwks,
  publishedIssuer: publishedIssuer,
  samlIssuerFor: samlIssuerFor,
  clientSubjectsNamespaced: clientSubjectsNamespaced,
  assertChainJwt: assertChainJwt,
  validateJwtAtTarget: validateJwtAtTarget,
  AC_UNSPECIFIED: AC_UNSPECIFIED,
  serviceBase: chain.serviceBase,
  isProduct: chain.isProduct,
  registerBaseline: chain.registerBaseline,
  registerSince: chain.registerSince,
  assertGraphIsAChain: chain.assertGraphIsAChain,
  castFor: castFor,
  tierNamed: tierNamed,
  provisionCast: provisionCast,
  signIn: signIn,
  exchange: exchange,
  read: read,
  assertChainAssertion: assertChainAssertion,
  signingCertificate: signingCertificate,
  validateAtTarget: validateAtTarget,
  actProducing: actProducing,
  assertAct: assertAct,
  actNotes: actNotes
};
