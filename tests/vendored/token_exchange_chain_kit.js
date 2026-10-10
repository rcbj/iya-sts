// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: token_exchange_chain_kit.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO TOKEN-EXCHANGE CHAIN JOBS SHARE (#467): a web application, an
// API gateway, an enterprise service bus and a service provider, provisioned
// through /admin-api; a person signed in to the first by the authorization
// code flow over plain HTTP; two RFC 8693 hops, each made by a different
// tier; introspection at the far end; and the delegation register and its
// graph read back. Nothing from the service.
//
// THE PATTERN IS THE PARENT PROJECT'S. `tests/oauth2_delegation_chain.js` in
// id-proto-debugger drives the same four tiers through the debugger's pages
// in Chrome (PR #355 made it pass in product mode). These jobs keep what that
// file learned and drop the browser: every call here is one HTTP request to
// the service, so the jobs can run anywhere the protocol half runs — an AWS
// target and the product stack included. What that file's header says about
// the scenario is true here as well, and the parts that carry over are
// restated where they are used:
//
//   * EVERY HOP NAMES THE TOKEN IT WANTS BY THE NEXT TIER'S REGISTERED
//     AUDIENCE (rcbj, #467) — the URI on that application's `oauthAudience`.
//     The exchanges send it as RFC 8693's `audience`, as the parent does;
//     the sign-in sends it as RFC 8707's `resource`, where the parent puts
//     the gateway's client_id in the scope instead (this service reads such
//     a scope as the audience, and `aud` comes back as the bare client_id).
//     So every `aud` here IS a registered URI, and the register files each
//     act against the application that registered it;
//   * the four entries are LEFT BEHIND, because they are what the delegation
//     picture is a picture of — and a rerun reconciles them rather than
//     failing on "already in this registry";
//   * product mode needs a person with a password, confidential middle tiers
//     with secrets, a public web application with PKCE and a registered
//     callback, declared scopes and grants, and the delegation policy
//     SATISFIED rather than switched off;
//   * the register is baselined by TIME, never by `seq` (a counter per
//     process on a service running request workers) — and here each act is
//     found by the jti of the token it produced, which needs no baseline at
//     all.
//
// WHAT IS NEW HERE IS `app1-scope`. rcbj's request: one scope present in
// every access token of both chains. It is a DECLARED scope —
// `oauthAllowedScope` on every one of the four applications, the declaration
// product mode holds every non-protected scope to (#110) — requested at the
// sign-in, at both exchanges and at the actor tokens' client_credentials
// grants. It is an ordinary scope in RFC 9068's plan (not OpenID Connect, not
// a client_id, not a delegated permission), so a token with one audience
// keeps it. It is NOT an RFC 9396 access type: `oauthAuthorizationDetailsType`
// is the catalogue `authorization_details` and GNAP rights are held to, and
// nothing reads it for a scope.
//
// WHY EACH JOB HAS ITS OWN FOUR ENTRIES. The two jobs differ exactly in the
// delegation semantics the middle tiers are configured with —
// `appDefaultDelegationSemantics` is one value — so one set of entries shared
// by both would be reconfigured by whichever ran last, and the two would
// fail each other in a pool. So each job passes a TAG and its applications
// are `webapp1-<tag>`, `apigw1-<tag>`, `esb1-<tag>` and `sp1-<tag>`, with
// audiences `https://<name>-<tag>.example.com`.
//
// AND, FOR THE DELEGATION JOB, TWO SERVICE PROVIDERS WITH PERMISSIONS
// (#549). `castFor(tag, { permissions: true })` puts sp1 AND sp2 after
// esb1, each exposing three delegated permissions — read, write and admin
// (`oauthPermissionBaseUri` + `oauthPermission`) — of which read and write
// are delegated to esb1 (`oauthDelegatedPermission`) and admin is not.
// esb1 exchanges once per service provider, asking for all three, and the
// issuance policy keeps the two it holds and DROPS admin. Each provider's
// audience is its permission base, so a permission's audience and the
// exchange's `audience` are one URI (RFC 9068 section 2.2.3). The same cast
// carries ROLES, GROUPS AND A CUSTOM CLAIM: the person in a group that
// holds a role, and every tier's groups claim (`teams`, by cn) and custom
// access-token claim (`tier`), which every person-bearing token carries.
// Without the option the cast is the four tiers it always was, which is
// what the impersonation job and the other protocols' kits use.
//
// AND ITS OWN PERSON (#482). The scenario's person is `bob_end_user`, and
// each job signs in as `bob_end_user-<tag>`. Every chain job sets a fresh
// random password on its person before it signs in. While they shared one
// entry, two jobs running at once in the suite's pool could reset it
// between the other's setting and its sign-in, and the sign-in failed with
// the right password of a moment before. A person per job has nothing to
// race on. The WS-Trust chain jobs take theirs from this cast, so all six
// are apart.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const registry = require("./sts_applications.js");
const capture = require("./chain_capture.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "token_exchange_chain_kit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // A hand run without CONFIG_FILE still loads; the level falls back.
      return "info";
    }
  })()
});

const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const SECRET_METHODS = ["client_secret_basic", "client_secret_post"];
// The scenario's scopes for the sign-in, which RFC 9068's plan takes off a
// token for another resource server (they stay on the ID Token and the
// refresh token), and the one scope every access token must carry.
const OIDC_SCOPE = "openid email profile offline_access";
const COMMON_SCOPE = "app1-scope";
// #549: the delegated permissions each service provider exposes, and the
// ones delegated to esb1. ADMIN IS NEVER DELEGATED, and a token carrying it
// is the bug the delegation job exists to catch.
const PERMISSION_NAMES = ["read", "write", "admin"];
const DELEGATED_PERMISSIONS = ["read", "write"];
// #549: the claim settings every tier carries when the cast asks for them —
// the groups claim under a name and in a form of its own (`teams`, the
// group's cn) and one custom claim naming the person, on the access token
// and, for the web application, the ID Token.
const CLAIM_FIELDS = {
  appGroupsClaim: "TRUE",
  appGroupsClaimName: "teams",
  appGroupsClaimValue: "cn",
  oauthClaimsAccessToken: JSON.stringify(
    [{ name: "tier", value: "gold-${username}" }])
};
const ID_TOKEN_CLAIMS = JSON.stringify(
  [{ name: "tier", value: "gold-${username}" }]);
// The scenario's person; each cast signs in as `<this>-<tag>` (#482).
const USER = process.env.DELEGATION_USER || "bob_end_user";
// Generated per process and never derivable: the entry outlives the run on a
// kept deployment. The fixed ends satisfy a password policy's classes.
const USER_PASSWORD = process.env.DELEGATION_USER_PASSWORD ||
    ("Chain-" + crypto.randomBytes(15).toString("base64url") + "-9a!");

// ---------------------------------------------------------------------------
// WHERE THE SERVICE IS. The launchers set WSTRUST_STS_URL (the WS-Trust
// endpoint, so `/sts` comes off) and OID4VCI_ISSUER_URL (the service).
// ---------------------------------------------------------------------------
function serviceBase() {
  log.debug("Entering serviceBase().");
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  const out = String(process.env.OID4VCI_ISSUER_URL ||
                     stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
  log.debug("Leaving serviceBase(). " + out);
  return out;
}

// ---------------------------------------------------------------------------
// THE CAST, for one job's tag. `next` is the tier each one forwards to, and
// is the one table both the delegation policy and the hops are read from, so
// the two cannot describe different chains.
// ---------------------------------------------------------------------------
function castFor(tag, opts) {
  log.debug("Entering castFor(). tag=" + tag);
  const withPermissions = !!(opts && opts.permissions);
  const named = function (stem, what, withAudience) {
    log.debug("Entering named(). " + stem);
    const identifier = stem + "-" + tag;
    log.debug("Leaving named().");
    return { identifier: identifier, name: identifier + " (" + what + ")",
             audience: withAudience
               ? "https://" + identifier + ".example.com" : "" };
  };
  const webapp = named("webapp1", "web application", false);
  const gateway = named("apigw1", "API gateway", true);
  const esb = named("esb1", "enterprise service bus", true);
  const provider = named("sp1", "service provider", true);
  webapp.next = gateway.identifier;
  gateway.next = esb.identifier;
  esb.next = provider.identifier;
  provider.next = "";
  const providers = [provider];
  if (withPermissions) {
    // A permission's audience is its BASE with the separator the registry
    // adds (`permissionBaseOf()`), so each provider registers that one URI
    // as its audience and as its permission base.
    const provider2 = named("sp2", "service provider", true);
    provider2.next = "";
    providers.push(provider2);
    providers.forEach(function (one) {
      one.audience = one.audience + "/";
      one.permissionBase = one.audience;
    });
    esb.delegatesTo = providers.map(function (one) {
      return one.identifier;
    });
  }
  const cast = {
    tag: tag, user: USER + "-" + tag, password: USER_PASSWORD,
    webapp: webapp, gateway: gateway, esb: esb, provider: provider,
    providers: providers,
    tiers: [webapp, gateway, esb].concat(providers),
    redirectUri: "https://" + webapp.identifier + ".example.com/callback",
    secrets: {},
    // #549: the permissions each provider exposes, and the ones delegated
    // to esb1 — admin never is.
    permissions: withPermissions
      ? { names: PERMISSION_NAMES, delegated: DELEGATED_PERMISSIONS }
      : null,
    // #549: roles, groups and a custom claim on every person's token.
    claims: withPermissions,
    team: "oauth-chain-" + tag + "-team",
    role: "oauth-chain-" + tag + "-role"
  };
  capture.set({ protocol: "OAuth 2.0 token exchange (RFC 8693)" });
  log.debug("Leaving castFor().");
  return cast;
}

// One tier's client secret, generated per process and written onto the entry
// by `set` every run, so a rerun REPLACES the last run's rather than needing
// to know it. 48 bytes, the size the service mints its own.
function secretOf(cast, identifier) {
  log.debug("Entering secretOf(). " + identifier);
  if (!cast.secrets[identifier]) {
    cast.secrets[identifier] = crypto.randomBytes(48).toString("base64url");
  }
  log.debug("Leaving secretOf().");
  return cast.secrets[identifier];
}

// ---------------------------------------------------------------------------
// HTTP. `fetch` throughout; tools/attach-admin-token.js (preloaded by
// run-report.js, and required by each job for a hand run) puts the run's
// access token on every call to `/admin-api`.
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
    // Not JSON; `text` carries it into whatever message names it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function adminJson(base, path) {
  log.debug("Entering adminJson(). " + path);
  const r = await call("GET", base + "/admin-api" + path);
  assert.strictEqual(r.status, 200, "GET /admin-api" + path + " answered " +
    r.status + ": " + r.text.slice(0, 300) + ". A 401 is the management " +
    "API without its access token — STS_ADMIN_API_TOKEN, which " +
    "tools/attach-admin-token.js presents.");
  log.debug("Leaving adminJson().");
  return r.json;
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
// WHICH MODE THE SERVICE IS IN, ASKED OF THE SERVICE: `GET /admin-api/mode`,
// the document the console's mode page is drawn from, and `global.mode`
// through /admin-api/config for a service from before that operation.
// ---------------------------------------------------------------------------
async function isProduct(base) {
  log.debug("Entering isProduct().");
  const r = await call("GET", base + "/admin-api/mode");
  if (r.status === 404) {
    const product = await registry.isProduct(base);
    capture.set({ service: base,
                  mode: product ? "product" : "development" });
    log.debug("Leaving isProduct(). From global.mode: " + product);
    return product;
  }
  assert.ok(r.status === 200 && r.json &&
            typeof r.json.isProduct === "boolean",
    "GET /admin-api/mode should answer 200 with `isProduct` and answered " +
    r.status + ": " + r.text.slice(0, 300));
  log.info("[mode] the service says it is in " + r.json.mode + " mode.");
  capture.set({ service: base, mode: r.json.mode ||
                (r.json.isProduct ? "product" : "development") });
  log.debug("Leaving isProduct(). " + r.json.isProduct);
  return r.json.isProduct;
}

// ---------------------------------------------------------------------------
// WHAT EACH ENTRY HOLDS, AS ONE TABLE — the same in both modes. Development
// would issue every token here without most of it; provisioning the product
// configuration everywhere means the two modes run one chain, and what
// differs between them is only what the service ENFORCES.
//
//   oauthClientId, oauthAudience   who each tier is, and the URI a token for
//                                  it is addressed to (not webapp1: a browser
//                                  application is issued tokens and is never
//                                  the audience of one);
//   oauthAllowedScope              app1-scope everywhere; webapp1 also the
//                                  scenario's OpenID Connect scopes;
//   webapp1                        PUBLIC (`none`), so PKCE is required of
//                                  it, with its callback REGISTERED and the
//                                  code and refresh grants;
//   apigw1, esb1                   CONFIDENTIAL with a secret, the token-
//                                  exchange grant, and client_credentials
//                                  where the job sends an actor_token;
//   sp1                            CONFIDENTIAL with a secret, because
//                                  introspection authenticates its caller in
//                                  product, and no grant: it calls nothing;
//   the delegation policy          on the two middle tiers, below.
// ---------------------------------------------------------------------------
function policyFieldsFor(tier, semantics) {
  log.debug("Entering policyFieldsFor(). " + tier.identifier);
  if (!tier.next || /^webapp1-/.test(tier.identifier)) {
    log.debug("Leaving policyFieldsFor(). Not a middle tier.");
    return {};
  }
  // The issuance policy's rules 7 and 10 (docs/delegation.md). The tier may
  // use these semantics and uses them when the request names none — neither
  // job sends `exchange_semantics` — and it delegates to the tier after it:
  // for an IMPERSONATION that is "the actor must reach R", and for a
  // DELEGATION "S must delegate to R" with the actor being S, which it is
  // here (the subject token's audience is the tier exchanging it, and so is
  // the actor_token's subject). Nothing wider: apigw1 may not reach sp1.
  log.debug("Leaving policyFieldsFor(). " + semantics + " towards " +
            tier.next + ".");
  return {
    appDelegationSemantics: [semantics],
    appDefaultDelegationSemantics: semantics,
    appAllowedToDelegateTo: tier.delegatesTo || [tier.next]
  };
}

function fieldsFor(cast, tier, semantics) {
  log.debug("Entering fieldsFor(). " + tier.identifier);
  const fields = { oauthClientId: tier.identifier };
  if (tier.audience) {
    fields.oauthAudience = [tier.audience];
  }
  if (cast.claims) {
    Object.assign(fields, CLAIM_FIELDS);
  }
  if (cast.permissions && tier.permissionBase) {
    // What this provider exposes (#549). The grants to esb1 are made after
    // every entry exists: a permission must be defined before it can be
    // granted, and esb1 is provisioned before the providers.
    fields.oauthPermissionBaseUri = tier.permissionBase;
    fields.oauthPermission = cast.permissions.names.slice();
  }
  if (tier === cast.webapp) {
    if (cast.claims) {
      fields.oauthClaimsIdToken = ID_TOKEN_CLAIMS;
    }
    fields.oauthAllowedScope = OIDC_SCOPE.split(" ").concat([COMMON_SCOPE]);
    fields.oauthTokenEndpointAuthMethod = ["none"];
    fields.oauthRedirectUri = [cast.redirectUri];
    fields.oauthGrantType = ["authorization_code", "refresh_token"];
    fields.oauthResponseType = ["code"];
    log.debug("Leaving fieldsFor(). The public client.");
    return fields;
  }
  fields.oauthAllowedScope = [COMMON_SCOPE];
  fields.oauthConfidential = "TRUE";
  fields.oauthTokenEndpointAuthMethod = SECRET_METHODS;
  if (tier.next) {
    fields.oauthGrantType = semantics === "delegation"
      ? [EXCHANGE_GRANT, "client_credentials"] : [EXCHANGE_GRANT];
  }
  Object.assign(fields, policyFieldsFor(tier, semantics));
  log.debug("Leaving fieldsFor(). A confidential client.");
  return fields;
}

// `none` may not be held beside another method — public and confidential
// are exclusive and the registry refuses the mixture — so whatever an
// existing entry holds that this tier does not use comes off first.
async function settleAuthMethods(base, identifier, wanted) {
  log.debug("Entering settleAuthMethods(). " + identifier);
  const entry = await registry.entryOf(base, identifier);
  const held = registry.valuesOf(entry && entry.fields &&
                                 entry.fields.oauthTokenEndpointAuthMethod);
  const extra = held.filter(function (one) {
    return wanted.indexOf(one) < 0;
  });
  for (let i = 0; i < extra.length; i++) {
    await adminOk(base, "/applications/remove",
                  { application: identifier,
                    attribute: "oauthTokenEndpointAuthMethod",
                    value: extra[i] },
                  "removing " + extra[i] + " from " + identifier);
  }
  log.debug("Leaving settleAuthMethods(). Removed " + extra.length + ".");
}

// ---------------------------------------------------------------------------
// PROVISIONING: the person, then the four entries — created, or reconciled
// on a rerun — then each confidential tier's secret, then every entry READ
// BACK, because the reply to a write is the service describing what it wrote
// and the question is what the registry holds. The ABSENCE is asserted as
// well: webapp1 must be the audience of nothing.
// ---------------------------------------------------------------------------
async function provisionCast(base, cast, semantics) {
  log.debug("Entering provisionCast(). " + cast.tag + " " + semantics);
  log.info("=== Provisioning " + cast.user + " and the four applications " +
           "(" + semantics + ") ===");
  capture.set({ useCase: semantics });
  await registry.ensurePerson(base, cast.user, cast.password);
  // No `stsMayAct` on the person, ever: it names ONE delegate, and a chain
  // has two actors, so a `may_act` naming either refuses the other in every
  // mode. Cleared rather than assumed, because the entry is shared.
  await adminOk(base, "/users/set-may-act", { user: cast.user, delegate: "" },
                "clearing " + cast.user + "'s stsMayAct");
  if (cast.claims) {
    await provisionGroupAndRole(base, cast);
  }
  for (let i = 0; i < cast.tiers.length; i++) {
    const tier = cast.tiers[i];
    const fields = fieldsFor(cast, tier, semantics);
    await settleAuthMethods(base, tier.identifier,
                            fields.oauthTokenEndpointAuthMethod);
    await registry.provision(base, {
      identifier: tier.identifier, name: tier.name,
      protocols: ["oauth2", "oidc"], fields: fields,
      why: "the " + tier.name + " of the " + semantics + " chain"
    });
    if (tier !== cast.webapp) {
      await adminOk(base, "/applications/set",
                    { application: tier.identifier,
                      attribute: "oauthClientSecret",
                      value: secretOf(cast, tier.identifier) },
                    "setting " + tier.identifier + "'s client secret");
    }
  }
  if (cast.permissions) {
    await delegatePermissions(base, cast);
  }
  for (let i = 0; i < cast.tiers.length; i++) {
    const tier = cast.tiers[i];
    const entry = await registry.entryOf(base, tier.identifier);
    assert.ok(entry, "the registry has no " + tier.identifier);
    const audiences = registry.valuesOf(entry.fields &&
                                        entry.fields.oauthAudience);
    const scopes = registry.valuesOf(entry.fields &&
                                     entry.fields.oauthAllowedScope);
    if (tier.audience) {
      assert.ok(audiences.indexOf(tier.audience) >= 0, tier.identifier +
        " should register " + tier.audience + " and holds " +
        JSON.stringify(audiences));
    } else {
      assert.strictEqual(audiences.length, 0, tier.identifier + " is a " +
        "browser application and should be the audience of nothing; it " +
        "registers " + JSON.stringify(audiences));
    }
    assert.ok(scopes.indexOf(COMMON_SCOPE) >= 0, tier.identifier +
      " should declare " + COMMON_SCOPE + " on oauthAllowedScope and " +
      "declares " + JSON.stringify(scopes));
    log.info("[registry] " + tier.identifier + ": audience " +
             (audiences.join(", ") || "(none, by design)") + "; declares " +
             scopes.join(" "));
  }
  log.debug("Leaving provisionCast().");
}

// The person, in a group that holds a role (#549, `wstrust_chain_kit.js`'s
// arrangement): created, or reconciled on a rerun. A create of something
// already there, and a role given to a group that already holds it, are
// answered "already" and moved past; a membership add is idempotent.
async function provisionGroupAndRole(base, cast) {
  log.debug("Entering provisionGroupAndRole().");
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
  await tolerant("/roles/add-member",
                 { role: cast.role, kind: "group", member: cast.team });
  log.info("[registry] " + cast.user + " is in " + cast.team + ", which " +
           "holds " + cast.role + ".");
  log.debug("Leaving provisionGroupAndRole().");
}

// A provider's permission identifier: its base and a name, as the registry
// composes one (`permissionIdOf()`).
function permissionId(provider, name) {
  log.debug("Entering permissionId(). " + provider.identifier);
  log.debug("Leaving permissionId().");
  return provider.permissionBase + name;
}

// THE GRANTS (#549): read and write on every provider, delegated to esb1;
// admin taken OFF esb1 where an earlier run, or anybody, left it — the
// negative test means nothing if esb1 happens to hold it. Then read back.
async function delegatePermissions(base, cast) {
  log.debug("Entering delegatePermissions().");
  const esb = cast.esb;
  let entry = await registry.entryOf(base, esb.identifier);
  let held = registry.valuesOf(entry && entry.fields &&
                               entry.fields.oauthDelegatedPermission);
  for (let p = 0; p < cast.providers.length; p++) {
    const provider = cast.providers[p];
    for (let n = 0; n < cast.permissions.names.length; n++) {
      const name = cast.permissions.names[n];
      const id = permissionId(provider, name);
      const delegated = cast.permissions.delegated.indexOf(name) >= 0;
      if (delegated && held.indexOf(id) < 0) {
        await adminOk(base, "/applications/add",
                      { application: esb.identifier,
                        attribute: "oauthDelegatedPermission", value: id },
                      "delegating " + id + " to " + esb.identifier);
      } else if (!delegated && held.indexOf(id) >= 0) {
        await adminOk(base, "/applications/remove",
                      { application: esb.identifier,
                        attribute: "oauthDelegatedPermission", value: id },
                      "taking " + id + " off " + esb.identifier);
      }
    }
  }
  entry = await registry.entryOf(base, esb.identifier);
  held = registry.valuesOf(entry && entry.fields &&
                           entry.fields.oauthDelegatedPermission);
  cast.providers.forEach(function (provider) {
    cast.permissions.names.forEach(function (name) {
      const id = permissionId(provider, name);
      const delegated = cast.permissions.delegated.indexOf(name) >= 0;
      assert.strictEqual(held.indexOf(id) >= 0, delegated, esb.identifier +
        (delegated ? " should hold " : " must NOT hold ") + id +
        " on oauthDelegatedPermission, and holds " + JSON.stringify(held));
    });
  });
  log.info("[registry] " + esb.identifier + " holds " +
           held.filter(function (one) {
             return cast.providers.some(function (provider) {
               return one.indexOf(provider.permissionBase) === 0;
             });
           }).join(", ") + "; admin on no provider.");
  log.debug("Leaving delegatePermissions().");
}

// ---------------------------------------------------------------------------
// TOKENS.
// ---------------------------------------------------------------------------
function basicAuth(identifier, secret) {
  log.debug("Entering basicAuth().");
  log.debug("Leaving basicAuth().");
  return "Basic " + Buffer.from(encodeURIComponent(identifier) + ":" +
                                encodeURIComponent(secret)).toString("base64");
}

async function tokenRequest(base, form, authorization) {
  log.debug("Entering tokenRequest(). " + form.grant_type);
  const params = new URLSearchParams();
  Object.keys(form).forEach(function (k) {
    if (form[k] !== undefined && form[k] !== null && form[k] !== "") {
      params.append(k, form[k]);
    }
  });
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (authorization) {
    headers.Authorization = authorization;
  }
  const r = await call("POST", base + "/oauth2/token", params.toString(),
                       headers);
  logToken(form, r);
  log.debug("Leaving tokenRequest(). " + r.status);
  return r;
}

// TOKEN LOGGING, OFF UNLESS ASKED FOR: with STS_TOKEN_LOG set (any value),
// every token request and its answer is one `[token-log] {...}` line in this
// job's log, so a reviewer can read the chain hop by hop. The request's form
// is logged without its credentials — the Authorization header (the client
// secret) is never logged — and the answer whole, tokens included: these are
// a throwaway realm's test tokens, and the switch is for a run made to read
// them.
function logToken(form, r) {
  log.debug("Entering logToken().");
  if (!process.env.STS_TOKEN_LOG) {
    log.debug("Leaving logToken(). Off.");
    return;
  }
  const request = {};
  Object.keys(form || {}).forEach(function (k) {
    if (k !== "client_secret" && k !== "client_assertion" &&
        form[k] !== undefined && form[k] !== null && form[k] !== "") {
      request[k] = form[k];
    }
  });
  let answer = r && r.json;
  if (!answer && r && r.text) {
    try {
      answer = JSON.parse(r.text);
    } catch (e) {
      log.debug("Caught in logToken(): " + ((e && e.message) || e));
      answer = { raw: String(r.text).slice(0, 2000) };
    }
  }
  log.info("[token-log] " + JSON.stringify({ at: new Date().toISOString(),
    status: r && r.status, request: request, response: answer || null }));
  log.debug("Leaving logToken().");
}

function claimsOf(token, what) {
  log.debug("Entering claimsOf(). " + what);
  const parts = String(token || "").split(".");
  assert.strictEqual(parts.length, 3, what + " is not a compact JWS: " +
                     String(token).slice(0, 60));
  const claims = JSON.parse(Buffer.from(parts[1], "base64url")
    .toString("utf8"));
  log.debug("Leaving claimsOf().");
  return claims;
}

// ---------------------------------------------------------------------------
// A CODE, THE WAY A BROWSER GETS ONE — and AS a browser. This is
// `sts_applications.authorizationCode()`'s walk (the authorization request
// with a fresh PKCE pair, the sign-in screen, the person's password, the
// consent screen passed, the code read off the redirect), written here for
// one reason: every request carries a DESKTOP BROWSER'S User-Agent. A
// product service scores every sign-in for risk (#62), and on the 8081
// product stack a password sign-in sent with node's own `User-Agent: node`
// came back "Authentication failed" with the right password — the parent
// test met the same refusal from headless Chrome and gives the browser a
// desktop agent for it (`browser_flags.addDesktopUserAgent()`).
// `sts_applications.js` is vendored from the parent and is not edited here,
// and its walk takes no headers, so the walk is repeated rather than the
// helper changed.
// ---------------------------------------------------------------------------
const DESKTOP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

function setCookieHeader(response) {
  log.debug("Entering setCookieHeader().");
  const lines = typeof response.headers.getSetCookie === "function"
    ? response.headers.getSetCookie()
    : [String(response.headers.get("set-cookie") || "")];
  const cookie = lines.map(function (line) {
    return String(line).split(";")[0];
  }).filter(function (pair) {
    return /=./.test(pair);
  }).join("; ");
  log.debug("Leaving setCookieHeader().");
  return cookie;
}

async function authorizationCode(base, opts) {
  log.debug("Entering authorizationCode(). " + opts.clientId);
  const consentScreen = require("./consent_screen.js");
  const pair = registry.pkce();
  const agent = { "User-Agent": DESKTOP_USER_AGENT };
  const absolute = function (location) {
    log.debug("Entering absolute().");
    log.debug("Leaving absolute().");
    return new URL(location, base).toString();
  };
  const url = base + "/oauth2/authorize?" + new URLSearchParams(Object.assign({
    response_type: "code", client_id: opts.clientId,
    redirect_uri: opts.redirectUri, scope: opts.scope,
    state: "s-" + crypto.randomBytes(8).toString("hex"),
    code_challenge: pair.challenge, code_challenge_method: pair.method
  }, opts.extra || {})).toString();
  const first = await fetch(url, { redirect: "manual", headers: agent });
  const screenAt = first.headers.get("location") || "";
  assert.ok(/\/authn\/login\?authn=/.test(screenAt), "the authorization " +
    "request for " + opts.clientId + " should reach the sign-in screen; it " +
    "answered " + first.status + " " + screenAt + " " +
    String(await first.text()).slice(0, 300));
  const screen = await fetch(absolute(screenAt),
                            { redirect: "manual", headers: agent });
  const page = await screen.text();
  const authnId = (page.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  const csrf = (page.match(/name="csrf_token" value="([^"]+)"/) || [])[1] ||
      "";
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  // Posted back to the path the screen was served from (a realm's own).
  const screenUrl = new URL(absolute(screenAt));
  const signedIn = await fetch(screenUrl.origin + screenUrl.pathname, {
    method: "POST", redirect: "manual",
    headers: Object.assign({
      "Content-Type": "application/x-www-form-urlencoded" }, agent),
    body: new URLSearchParams({ authn_id: authnId, username: opts.username,
                                password: opts.password, action: "login",
                                csrf_token: csrf }).toString()
  });
  const cookie = setCookieHeader(signedIn);
  const next = signedIn.headers.get("location") || "";
  if (!cookie || !next) {
    // What the screen said, so a refusal names itself.
    const said = String(await signedIn.text())
      .replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ").slice(0, 500);
    assert.fail("signing " + opts.username + " in should establish a " +
      "session and redirect; the screen answered " + signedIn.status +
      ": " + said);
  }
  const headers = Object.assign({ Cookie: cookie }, agent);
  const back = await fetch(absolute(next),
                           { redirect: "manual", headers: headers });
  let location = back.headers.get("location") || "";
  const settled = await consentScreen.settleAuthorization({
    base: base, location: location, cookie: cookie, headers: agent });
  location = settled.location || location;
  const code = (location.match(/[?&]code=([^&]+)/) || [])[1];
  assert.ok(code, "no code for " + opts.clientId + "; the flow ended at " +
    String(location).slice(0, 200));
  log.debug("Leaving authorizationCode().");
  return { code: decodeURIComponent(code), verifier: pair.verifier };
}

// ---------------------------------------------------------------------------
// THE CAPTURE (`chain_capture.js`, STS_CHAIN_CAPTURE): each token this chain
// is issued, written down where it arrives. Nothing here runs unless the
// variable names a directory, and nothing here can fail the job.
// ---------------------------------------------------------------------------
// A tier's name without the job's tag: `apigw1-del` -> `apigw1`, so every
// protocol's hops read the same in the spreadsheet.
function stemOf(cast, identifier) {
  log.debug("Entering stemOf(). " + identifier);
  const suffix = "-" + cast.tag;
  const id = String(identifier || "");
  log.debug("Leaving stemOf().");
  return id.slice(-suffix.length) === suffix
    ? id.slice(0, -suffix.length) : id;
}

// One JWT layer: its header and claims decoded, `act` flattened.
function captureJwt(f) {
  log.debug("Entering captureJwt(). " + f.hop);
  if (!capture.enabled()) {
    log.debug("Leaving captureJwt(). Not capturing.");
    return;
  }
  const read = capture.jwt(f.token);
  const claims = read.claims && typeof read.claims === "object"
    ? read.claims : {};
  const kind = capture.jwtKind(read.header) +
      (f.kind ? ", " + f.kind : "");
  capture.layer({
    hop: f.hop, requester: f.requester, target: f.target,
    mechanism: f.mechanism,
    kind: f.kindExact || kind,
    format: read.encrypted ? "JWE (compact)" : "JWT (compact JWS)",
    value: f.token, header: read.header, claims: read.claims,
    actChain: capture.actChain(claims.act, claims.iss),
    notes: f.notes || null });
  log.debug("Leaving captureJwt().");
}

// The sign-in's response: the ID Token is webapp1's own, the access token
// is what webapp1 hands the gateway, and the refresh token stays with
// webapp1 (a JWE's protected header is all anybody else can read of it).
function captureSignIn(cast, json) {
  log.debug("Entering captureSignIn().");
  if (!capture.enabled()) {
    log.debug("Leaving captureSignIn(). Not capturing.");
    return;
  }
  const bobToWebapp = capture.hop("bob", "webapp1");
  if (json.id_token) {
    captureJwt({ hop: bobToWebapp, requester: cast.webapp.identifier,
                 target: cast.webapp.identifier,
                 mechanism: "authorization code (OpenID Connect, PKCE)",
                 token: json.id_token, kindExact: "ID Token",
                 notes: cast.user + " signed in to " +
                   cast.webapp.identifier });
  }
  if (json.refresh_token) {
    captureJwt({ hop: bobToWebapp, requester: cast.webapp.identifier,
                 target: cast.webapp.identifier,
                 mechanism: "authorization code (OpenID Connect, PKCE)",
                 token: json.refresh_token, kindExact: "refresh token",
                 notes: "held by " + cast.webapp.identifier + " and " +
                   "presented only to this service's token endpoint" });
  }
  captureJwt({ hop: capture.hop("webapp1", "apigw1"),
               requester: cast.webapp.identifier,
               target: cast.gateway.identifier,
               mechanism: "authorization code (OpenID Connect, PKCE)",
               token: json.access_token,
               notes: "issued to " + cast.webapp.identifier + " at the " +
                 "sign-in with resource=" + cast.gateway.audience +
                 ", and presented to " + cast.gateway.identifier });
  log.debug("Leaving captureSignIn().");
}

// THE SIGN-IN: a code the way a browser gets one (above), then redeemed by
// the PUBLIC client with its verifier and no secret.
//
// THE TOKEN IS ASKED FOR BY THE GATEWAY'S REGISTERED AUDIENCE (rcbj, #467):
// RFC 8707's `resource`, on the authorization request and again on the
// token request, naming `https://apigw1-<tag>.example.com` — the URI apigw1
// registers on `oauthAudience`. The parent test names the gateway instead by
// putting its CLIENT_ID in the scope, which this service reads as the
// audience and which comes back as `aud: "apigw1"`; here every hop names its
// target the same way, by the registered URI, and every `aud` IS that URI.
// RFC 9068's plan then treats the token as one for another resource server:
// the OpenID Connect scopes stay granted (the ID Token, the refresh token)
// and off the access token, and app1-scope, an ordinary scope on a token
// with one audience, stays on it.
async function signIn(base, cast) {
  log.debug("Entering signIn().");
  const scope = OIDC_SCOPE + " " + COMMON_SCOPE;
  const resource = cast.gateway.audience;
  const granted = await authorizationCode(base, {
    clientId: cast.webapp.identifier, redirectUri: cast.redirectUri,
    username: cast.user, password: cast.password, scope: scope,
    extra: { resource: resource } });
  const r = await tokenRequest(base, {
    grant_type: "authorization_code", code: granted.code,
    redirect_uri: cast.redirectUri, code_verifier: granted.verifier,
    client_id: cast.webapp.identifier, resource: resource });
  assert.strictEqual(r.status, 200, cast.webapp.identifier + "'s code " +
                     "redeemed: " + r.text.slice(0, 400));
  assert.ok(r.json.access_token, r.text.slice(0, 400));
  log.info("[sign-in] " + cast.user + " signed in to " +
           cast.webapp.identifier + " asking for \"" + scope + "\" with " +
           "resource=" + resource + "; the response carries " +
           Object.keys(r.json).join(", ") + ".");
  captureSignIn(cast, r.json);
  log.debug("Leaving signIn().");
  return r.json;
}

// A TIER'S OWN TOKEN: client_credentials with its own client_id and secret,
// so the token's subject is the tier itself — the actor_token of a
// delegation. It asks for app1-scope like every other grant here.
async function clientCredentials(base, cast, tier) {
  log.debug("Entering clientCredentials(). " + tier.identifier);
  const r = await tokenRequest(base, {
    grant_type: "client_credentials", scope: COMMON_SCOPE },
    basicAuth(tier.identifier, secretOf(cast, tier.identifier)));
  assert.strictEqual(r.status, 200, tier.identifier + "'s client_" +
                     "credentials grant: " + r.text.slice(0, 400));
  captureJwt({
    hop: capture.hop(stemOf(cast, tier.identifier), "authorization server"),
    requester: tier.identifier, target: tier.identifier,
    mechanism: "client_credentials", token: r.json.access_token,
    kind: "actor token", notes: tier.identifier + "'s own token, about " +
      "itself, sent as the actor_token of its exchange (delegation)" });
  log.debug("Leaving clientCredentials().");
  return r.json;
}

// ONE HOP: `tier` exchanges `subjectToken` for a token addressed to the
// tier after it — `audience` its REGISTERED URI — asking for app1-scope, and
// with `actorToken` when the job sends one.
// `options` (#549): `target`, the tier to address the token to where it
// is not `tier.next`, and `scope`, the scope to ask for where it is not
// app1-scope alone.
async function exchange(base, cast, tier, subjectToken, actorToken,
                        options) {
  log.debug("Entering exchange(). " + tier.identifier);
  const next = (options && options.target) ||
    cast.tiers.filter(function (one) {
      return one.identifier === tier.next;
    })[0];
  const scope = (options && options.scope) || COMMON_SCOPE;
  const r = await tokenRequest(base, {
    grant_type: EXCHANGE_GRANT,
    subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    actor_token: actorToken || "",
    actor_token_type: actorToken ? ACCESS_TOKEN_TYPE : "",
    audience: next.audience, scope: scope },
    basicAuth(tier.identifier, secretOf(cast, tier.identifier)));
  assert.strictEqual(r.status, 200, tier.identifier + "'s exchange for " +
                     next.audience + ": " + r.text.slice(0, 500));
  assert.strictEqual(r.json.issued_token_type, ACCESS_TOKEN_TYPE,
                     r.text.slice(0, 400));
  captureJwt({
    hop: capture.hop(stemOf(cast, tier.identifier),
                     stemOf(cast, next.identifier)),
    requester: tier.identifier, target: next.identifier,
    mechanism: "RFC 8693 token exchange" +
      (actorToken ? " with actor_token" : ""),
    token: r.json.access_token,
    notes: "audience " + next.audience + "; issued_token_type " +
      r.json.issued_token_type });
  log.debug("Leaving exchange().");
  return r.json;
}

// The issuer's own reading of a token, asked by the far end — sp1, which
// authenticates (product introspection refuses an unauthenticated caller).
async function introspect(base, cast, token, asTier) {
  log.debug("Entering introspect().");
  const caller = asTier || cast.provider;
  const r = await call("POST", base + "/oauth2/introspect",
    "token=" + encodeURIComponent(token) + "&token_type_hint=access_token",
    { "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuth(caller.identifier,
                               secretOf(cast, caller.identifier)) });
  assert.strictEqual(r.status, 200, "introspection: " + r.text.slice(0, 300));
  log.debug("Leaving introspect(). active=" + r.json.active);
  return r.json;
}

// ---------------------------------------------------------------------------
// WHAT EVERY ACCESS TOKEN HERE IS HELD TO.
// ---------------------------------------------------------------------------
function audienceList(claims) {
  log.debug("Entering audienceList().");
  const aud = claims && claims.aud;
  if (aud === undefined || aud === null) {
    log.debug("Leaving audienceList(). None.");
    return [];
  }
  log.debug("Leaving audienceList().");
  return (Array.isArray(aud) ? aud : [aud]).map(String);
}

function scopesOf(claims) {
  log.debug("Entering scopesOf().");
  log.debug("Leaving scopesOf().");
  return String((claims && claims.scope) || "").split(/\s+/)
    .filter(Boolean);
}

// app1-scope, present — the assertion rcbj asked for, on every token.
function assertCommonScope(claims, what) {
  log.debug("Entering assertCommonScope(). " + what);
  assert.ok(scopesOf(claims).indexOf(COMMON_SCOPE) >= 0,
    what + " does not carry " + COMMON_SCOPE + ": scope=" +
    JSON.stringify(claims.scope) + ", aud=" + JSON.stringify(claims.aud) +
    ". It is declared on every application in the chain and asked for at " +
    "every grant, and it is an ordinary scope on a token with one audience, " +
    "which RFC 9068's plan keeps.");
  log.debug("Leaving assertCommonScope().");
}

// What a token in the chain (the sign-in's or an exchange's) must be true
// of: the PERSON, app1-scope, the next tier as audience and not as scope,
// none of the OpenID Connect scopes, the client that asked for it.
function assertChainToken(cast, token, expect) {
  log.debug("Entering assertChainToken(). " + expect.what);
  const claims = claimsOf(token, expect.what);
  assert.strictEqual(claims.username, cast.user, expect.what + " names " +
    claims.username + " rather than " + cast.user + ". An exchange carries " +
    "the SUBJECT forward; a token naming the client is the tier acting as " +
    "itself.");
  assertCommonScope(claims, expect.what);
  const scopes = scopesOf(claims);
  OIDC_SCOPE.split(" ").concat(cast.tiers.map(function (one) {
    return one.identifier;
  })).forEach(function (one) {
    assert.ok(scopes.indexOf(one) < 0, expect.what + " carries \"" + one +
      "\" in its scope (" + JSON.stringify(claims.scope) + "). OpenID " +
      "Connect scopes mean nothing to another resource server (RFC 9068 " +
      "section 2.2.3), and a scope naming an application is an audience.");
  });
  // The audience IS the registered URI that was asked for — that one, and
  // nothing beside it (not this service's own resource, not a client_id).
  assert.deepStrictEqual(audienceList(claims), [expect.audience],
    expect.what + " should be addressed to exactly " + expect.audience +
    ", the registered audience it was asked for by, and its aud is " +
    JSON.stringify(claims.aud));
  (expect.notAudience || []).forEach(function (one) {
    assert.ok(audienceList(claims).indexOf(one) < 0, expect.what +
      " is still addressed to " + one + ": aud=" + JSON.stringify(claims.aud));
  });
  assert.strictEqual(claims.client_id, expect.clientId, expect.what +
    " was issued to " + claims.client_id + " rather than " + expect.clientId);
  log.info("[token] " + expect.what + ": username=" + claims.username +
           ", client_id=" + claims.client_id + ", aud=" +
           JSON.stringify(claims.aud) + ", scope=\"" + claims.scope +
           "\", act=" + JSON.stringify(claims.act) + ", jti=" + claims.jti);
  log.debug("Leaving assertChainToken().");
  return claims;
}

// THE CLAIM SETTINGS (#549), on a token about the person: `teams` (the
// groups claim by cn, the application's name for it, with no realm `groups`
// beside it), `roles` with the cast's role, and the custom `tier`.
function assertChainClaims(cast, claims, what) {
  log.debug("Entering assertChainClaims(). " + what);
  assert.deepStrictEqual(claims.teams, [cast.team], what + " should carry " +
    "the groups claim as `teams` [" + cast.team + "] and carries " +
    JSON.stringify(claims.teams));
  assert.strictEqual(claims.groups, undefined, what + " carries the " +
                     "realm's `groups` claim beside the application's: " +
                     JSON.stringify(claims.groups));
  assert.ok(Array.isArray(claims.roles) &&
            claims.roles.indexOf(cast.role) >= 0,
            what + " should carry " + cast.role + " in roles: " +
            JSON.stringify(claims.roles));
  assert.strictEqual(claims.tier, "gold-" + cast.user, what + "'s custom " +
                     "claim tier is " + JSON.stringify(claims.tier));
  log.info("[claims] " + what + ": teams=" + JSON.stringify(claims.teams) +
           ", roles=" + JSON.stringify(claims.roles) + ", tier=" +
           claims.tier);
  log.debug("Leaving assertChainClaims().");
}

// ---------------------------------------------------------------------------
// THE REGISTER. Each act is found by the jti of the token it PRODUCED — the
// token this job received — so neither a pool of other jobs nor a rerun of
// this one can be mistaken for it, and no `seq` is read (a counter per
// process; #465 is making it unique). The newest act's time before the run
// is still read, to say how many acts this job's run added.
// ---------------------------------------------------------------------------
async function registerBaseline(base) {
  log.debug("Entering registerBaseline().");
  const before = await adminJson(base, "/delegation?per=1");
  const newest = (before.acts || [])[0];
  const at = newest ? Number(newest.at || 0) : 0;
  log.info("[register] " + before.held + " act(s) held; this run's are " +
           "after " + (at ? new Date(at).toISOString() : "none") + ".");
  log.debug("Leaving registerBaseline().");
  return at;
}

async function registerSince(base, cast, baselineAt) {
  log.debug("Entering registerSince().");
  const after = await adminJson(base, "/delegation?q=" +
                                encodeURIComponent(cast.user) + "&per=200");
  const mine = (after.acts || []).filter(function (row) {
    return Number(row.at || 0) > baselineAt;
  });
  log.debug("Leaving registerSince(). " + mine.length + " act(s).");
  return { acts: mine, graph: after.graph || {} };
}

function actProducing(acts, jti, what) {
  log.debug("Entering actProducing(). " + jti);
  const found = acts.filter(function (row) {
    return (row.produced || []).some(function (one) {
      return one.kind === "access_token" && one.identifier === jti;
    });
  });
  assert.strictEqual(found.length, 1, "the delegation register should " +
    "hold exactly ONE act that produced " + what + " (jti " + jti + "), " +
    "and holds " + found.length + ". What it holds since this run started: " +
    JSON.stringify(acts.map(function (row) {
      return row.type + " " + row.initial.presented + " -> " +
        row.intermediary.application + " -> " + row.target.application;
    })));
  log.debug("Leaving actProducing().");
  return found[0];
}

// One act, for one hop. `expect`: { type, mode, clientId, target, audience,
// presented, subjectJti, actorJti, product, semantics }.
function assertAct(cast, act, expect) {
  log.debug("Entering assertAct(). " + expect.clientId);
  assert.strictEqual(act.protocol, "OAuth 2.0", "protocol " + act.protocol);
  assert.strictEqual(act.type, expect.type, "the act was filed as \"" +
                     act.type + "\" and should be \"" + expect.type + "\".");
  assert.strictEqual(act.mode, expect.mode, "the act's mode is \"" +
                     act.mode + "\" and should be \"" + expect.mode + "\".");
  assert.strictEqual(act.outcome, "issued", "outcome " + act.outcome);
  assert.strictEqual(act.initial.presented, cast.user, "the act is for \"" +
                     act.initial.presented + "\" rather than " + cast.user);
  assert.strictEqual(act.intermediary.application, expect.clientId,
    "the act's middle tier is \"" + act.intermediary.application +
    "\" rather than " + expect.clientId);
  assert.strictEqual(act.intermediary.presented, expect.presented,
    "the act names \"" + act.intermediary.presented + "\" as the identity " +
    "in the middle, and should name \"" + expect.presented + "\" — " +
    (expect.presented ? "the actor_token's subject." : "nobody: an " +
     "impersonation's middle is the client alone."));
  assert.strictEqual(act.target.application, expect.target,
    "the act reached \"" + act.target.application + "\" rather than " +
    expect.target + ", whose registered audience " + expect.audience +
    " the exchange asked for. Naming the URI is the registry lookup " +
    "(applications.forAudience()) not happening.");
  assert.ok(String(act.target.what || "").indexOf(expect.audience) >= 0,
    "the act's target does not say which audience resolved: \"" +
    act.target.what + "\"");
  // WHAT ALLOWED IT. Every part of the policy is provisioned, so the policy
  // ALLOWS this act in both modes, and the row says so by name — the
  // semantics, the actor, the subject and the application reached. Product
  // ENFORCED that answer (policed); development asked the same question.
  const allowed = "the issuance policy allowed " + expect.semantics +
      " by \"" + expect.clientId + "\" for \"" + cast.user + "\" to \"" +
      expect.target + "\"";
  assert.ok(String(act.authorizedBy || "").indexOf(allowed) === 0,
    "the act should say \"" + allowed + " …\" and says \"" +
    act.authorizedBy + "\". \"WOULD HAVE BEEN REFUSED\" means the policy " +
    "this job provisioned is not the one the service read.");
  assert.strictEqual(act.reason, "", "an issued act carries a refusal " +
                     "reason: \"" + act.reason + "\"");
  const consumed = act.consumed || [];
  const subject = consumed.filter(function (one) {
    return one.kind === "subject_token";
  });
  assert.ok(subject.length === 1 &&
            subject[0].identifier === expect.subjectJti,
    "the act should record consuming the subject token " + expect.subjectJti +
    " and records " + JSON.stringify(consumed));
  const actor = consumed.filter(function (one) {
    return one.kind === "actor_token";
  });
  if (expect.actorJti) {
    assert.ok(actor.length === 1 && actor[0].identifier === expect.actorJti,
      "the act should record consuming the actor token " + expect.actorJti +
      " and records " + JSON.stringify(consumed));
  } else {
    assert.strictEqual(actor.length, 0, "no actor_token was sent and the " +
                       "act records one: " + JSON.stringify(consumed));
  }
  if (expect.product) {
    assert.strictEqual(act.policed, true, "a product service enforces the " +
                       "delegation policy, and this act was not policed.");
    assert.ok(/verified/.test(String(subject[0].note || "")),
      "a product service verifies the subject token; the act's note is \"" +
      subject[0].note + "\"");
    if (expect.actorJti) {
      assert.ok(/verified/.test(String(actor[0].note || "")) &&
                !/without verifying/.test(String(actor[0].note || "")),
        "a product service verifies the actor token; the act's note is \"" +
        actor[0].note + "\"");
    }
  }
  log.info("[register] " + act.typeLabel + ": " + act.initial.presented +
           " -> " + act.intermediary.application +
           (act.intermediary.presented
             ? " (actor " + act.intermediary.presented + ")" : "") +
           " -> " + act.target.application + "; " + act.authorizedBy);
  log.debug("Leaving assertAct().");
}

// ---------------------------------------------------------------------------
// THE PICTURE'S MODEL — the graph /admin/delegation/map is drawn from. The
// one property that makes two exchanges a CHAIN: the tier in the middle is
// reached by the first hop and acts in the second, and the picture should
// draw that as ONE box.
//
// A box stands for an application (`application`, or its id) or for an
// identity. An impersonation's middle is the client alone, keyed by its
// identifier, so the box the first hop reaches and the box the second hop
// leaves from are the same box. A DELEGATION's middle presents the
// actor_token's SUBJECT, which here is the tier's own client_credentials
// subject — `esb1-del` in development, `urn:sts:client:esb1-del` in RFC 9700
// mode (product, section 4.13's namespace) — and the picture draws a
// client's own subject as that client's APPLICATION (#468,
// `common/delegation.js`'s `clientApplicationOf()`). So in both modes the
// middle box is keyed by the tier's identifier, and the tier the first hop
// reached and the tier acting in the second are ONE box. Until #468 product
// drew them as two, keyed `esb1-del` and `urn:sts:client:esb1-del`, and this
// function said so in a WARN line; it is an assertion now.
// ---------------------------------------------------------------------------
// `hops`: [{ clientId, actorSub? }]. `actorSub` is the delegation's actor
// token subject; its box is the application it is the subject of.
function assertGraphIsAChain(cast, graph, hops, mode) {
  log.debug("Entering assertGraphIsAChain().");
  const describe = function () {
    log.debug("Entering describe().");
    log.debug("Leaving describe().");
    return JSON.stringify((graph.nodes || []).map(function (n) {
      return n.id + (n.application ? "=" + n.application : "") + " " +
        JSON.stringify(n.roles);
    }));
  };
  const lines = function () {
    log.debug("Entering lines().");
    log.debug("Leaving lines().");
    return JSON.stringify((graph.edges || []).map(function (e) {
      return e.from + " -" + e.relation + "/" + e.mode + "-> " + e.to;
    }));
  };
  // The box each hop's middle is drawn as, and the person's line to it: the
  // tier's own application, whatever form its subject took (#468).
  const middles = hops.map(function (hop) {
    const key = hop.clientId;
    (graph.nodes || []).forEach(function (n) {
      assert.ok(!hop.actorSub || hop.actorSub === key || n.id !== hop.actorSub,
        "the picture draws a box keyed by the actor's subject " +
        hop.actorSub + " beside the application " + key + " (#468): " +
        describe());
    });
    const boxes = (graph.nodes || []).filter(function (n) {
      return n.id === key;
    });
    assert.strictEqual(boxes.length, 1, "the picture should hold one box " +
      "keyed " + key + " for " + hop.clientId + "'s act: " + describe());
    assert.ok(boxes[0].application === hop.clientId ||
              boxes[0].id === hop.clientId,
      "the box " + key + " should stand for the application " +
      hop.clientId + ": " + describe());
    assert.ok(boxes[0].roles.intermediary >= 1, "the box " + key +
      " is in the middle of nothing: " + describe());
    const actsFor = (graph.edges || []).filter(function (e) {
      return e.relation === "acts-for" && e.to === key &&
             e.from === cast.user && e.mode === mode;
    });
    assert.ok(actsFor.length >= 1, "the picture draws no " + mode +
      " line from " + cast.user + " to " + key + ". Its lines: " + lines());
    return boxes[0];
  });
  // The first hop's TARGET, which is the second hop's middle.
  const reached = (graph.nodes || []).filter(function (n) {
    return (n.id === hops[1].clientId || n.application === hops[1].clientId) &&
           n.roles.target >= 1;
  });
  assert.ok(reached.length >= 1, "the picture shows nothing standing for " +
    hops[1].clientId + " as the target of the first hop: " + describe());
  const middle = middles[1];
  assert.ok(reached.length === 1 && reached[0] === middle,
    hops[1].clientId + " should be ONE box, reached by the first hop and " +
    "in the middle of the second, and is drawn as " + reached.map(
      function (n) {
        return n.id;
      }).concat([middle.id]).join(" and ") + " (#468): " + describe());
  log.info("[picture] " + hops[1].clientId + " is ONE box (" + middle.id +
           "): reached " + middle.roles.target + " time(s), in the " +
           "middle " + middle.roles.intermediary + " time(s).");
  log.debug("Leaving assertGraphIsAChain().");
}

module.exports = {
  EXCHANGE_GRANT: EXCHANGE_GRANT,
  ACCESS_TOKEN_TYPE: ACCESS_TOKEN_TYPE,
  OIDC_SCOPE: OIDC_SCOPE,
  COMMON_SCOPE: COMMON_SCOPE,
  serviceBase: serviceBase,
  castFor: castFor,
  isProduct: isProduct,
  // The browser's code walk and the token request, for a chain kit whose
  // first tier signs in through OpenID Connect without this kit's cast —
  // `gnap_chain_kit.js`'s webapp1 (#497).
  authorizationCode: authorizationCode,
  tokenRequest: tokenRequest,
  provisionCast: provisionCast,
  signIn: signIn,
  clientCredentials: clientCredentials,
  exchange: exchange,
  introspect: introspect,
  claimsOf: claimsOf,
  audienceList: audienceList,
  scopesOf: scopesOf,
  assertCommonScope: assertCommonScope,
  assertChainToken: assertChainToken,
  assertChainClaims: assertChainClaims,
  permissionId: permissionId,
  registerBaseline: registerBaseline,
  registerSince: registerSince,
  actProducing: actProducing,
  assertAct: assertAct,
  assertGraphIsAChain: assertGraphIsAChain,
  stemOf: stemOf,
  captureJwt: captureJwt
};
