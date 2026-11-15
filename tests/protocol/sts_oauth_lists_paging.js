// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oauth_lists_paging.js
//
// ===========================================================================
// FOUR OAUTH 2.0 / OIDC CONSOLE LISTS, PAGED, AS THE API ANSWERS THEM
// (#313's sweep; D12, #444).
//
// Carries `tests/oauth_lists_paging.js` onto a running service, with rows
// made the way a client and an operator make them, in a throwaway realm:
//
//   1. GRANTS (`GET /admin-api/grants`): seven grants made by
//      `grant_management_action=create` at the token endpoint, for three
//      clients — one page of `per`, the total whole, on `grantsPage`; a page
//      past the end clamped to the last; `grantq` narrowing before the page,
//      case-insensitively; and a walk of every page reading each grant
//      once;
//   2. CLAIMS PROVIDERS (`GET /admin-api/claim-providers`): seven providers
//      through `add-provider` — the providers on `providersPage` and the
//      links on `linksPage`, each counted whole, one moving only its own
//      list, clamped, walked;
//   3. OPENID PROVIDER COMMANDS and OUTBOUND DELIVERIES: every list on a
//      parameter of its own (`clientsPage`, `accountsPage`, `runsPage`,
//      `deliveriesPage`; one per delivery kind), `per` sizing them all.
//
// NOT CARRIED (class (d)): the past-the-old-cut volumes (612 command
// accounts, 540 deliveries, 230 back-channel tokens) — making them over the
// wire is hundreds of relying parties' traffic, which is why the in-process
// file used stand-in registers; and `linkq` over links, which only a person
// linking a provider's account makes (sts_claims_aggregation.js's flow).
//
// OWNED HERE (local: true): the console's own API.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_oauth_lists_paging");
const log = K.log;

const SECRET = "olp-secret-" + K.rand(10);
const PASSWORD = "Olp-" + K.rand(6) + "-password!";
const REDIRECT = "https://olp-client.example/cb";
const GRANTS = 7;
const PROVIDERS = 7;

async function oneGrant(id, b, client, user) {
  log.debug("Entering oneGrant(). " + client);
  const p = K.pkce();
  const url = K.rb(id) + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: client, redirect_uri: REDIRECT,
    scope: "openid offline_access", state: "s", nonce: "n",
    code_challenge: p.challenge, code_challenge_method: "S256",
    grant_management_action: "create" });
  let r = await b.go(url);
  r = await K.signIn(id, b, r, user, PASSWORD);
  const answer = K.answerAt(r, REDIRECT);
  assert.ok(answer && answer.get("code"), K.shown(r));
  const t = await K.send(K.rb(id) + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: answer.get("code"),
    redirect_uri: REDIRECT, code_verifier: p.verifier,
    client_id: client, client_secret: SECRET } });
  assert.strictEqual(t.status, 200, K.shown(t));
  assert.ok(t.json.grant_id, K.shown(t));
  log.debug("Leaving oneGrant().");
  return t.json.grant_id;
}

async function view(id, path) {
  log.debug("Entering view(). " + path);
  const r = await K.send(K.rb(id) + path);
  assert.strictEqual(r.status, 200, path + ": " + K.shown(r));
  log.debug("Leaving view().");
  return r.json;
}

async function walk(id, path, param, rowsOf) {
  log.debug("Entering walk(). " + param);
  const seen = [];
  for (let page = 1; page <= 50; page++) {
    const one = await view(id, path + "&" + param + "=" + page);
    const got = rowsOf(one);
    seen.push.apply(seen, got.rows);
    if (page >= got.paging.pages) {
      break;
    }
  }
  log.debug("Leaving walk(). " + seen.length);
  return seen;
}

function distinct(ids) {
  log.debug("Entering distinct().");
  log.debug("Leaving distinct().");
  return ids.filter(function (one, i) {
    return ids.indexOf(one) === i;
  }).length;
}

async function grants(id) {
  log.debug("Entering grants().");
  log.info("=== 1. grants ===");
  const user = "olp-alice-" + K.STAMP;
  await K.person(id, user, PASSWORD);
  const clientIds = ["olp-a", "olp-b", "olp-c"];
  for (const client of clientIds) {
    await K.app(id, client, { oauthClientId: [client],
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthRedirectUri: [REDIRECT],
      oauthAllowedScope: ["openid", "offline_access"],
      oauthGrantType: ["authorization_code", "refresh_token"] });
  }
  const b = K.browser();
  const made = [];
  for (let i = 0; i < GRANTS; i++) {
    made.push(await oneGrant(id, b, clientIds[i % 3], user));
  }
  K.check("1. (a control: seven distinct grants were made)", function () {
    assert.strictEqual(distinct(made), GRANTS);
  });
  const first = await view(id, "/admin-api/grants?per=3");
  K.check("1. one page of three on grantsPage, the total whole", function () {
    assert.strictEqual(first.grants.length, 3, JSON.stringify(first.paging));
    assert.strictEqual(first.total, GRANTS);
    assert.strictEqual(first.matched, GRANTS);
    assert.strictEqual(first.paging.grants.pages, 3);
    assert.strictEqual(first.paging.grants.param, "grantsPage");
  });
  const past = await view(id, "/admin-api/grants?per=3&grantsPage=9");
  K.check("1. a page past the end is the last page", function () {
    assert.strictEqual(past.paging.grants.page, 3);
    assert.strictEqual(past.grants.length, 1);
  });
  const searched = await view(id, "/admin-api/grants?per=3&grantq=OLP-B");
  K.check("1. grantq narrows before the page, case-insensitively — two of " +
          "seven are olp-b's", function () {
    assert.strictEqual(searched.matched, 2, JSON.stringify(searched.filter));
    assert.strictEqual(searched.total, GRANTS);
    assert.strictEqual(searched.filter.q, "OLP-B");
    searched.grants.forEach(function (g) {
      assert.strictEqual(g.clientId, "olp-b", JSON.stringify(g));
    });
  });
  const seen = await walk(id, "/admin-api/grants?per=2", "grantsPage",
    function (v) {
      return { rows: v.grants.map(function (g) {
        return g.grantId;
      }), paging: v.paging.grants };
    });
  K.check("1. walking every page reads every grant once, and they are the " +
          "grants made", function () {
    assert.strictEqual(seen.length, GRANTS);
    assert.strictEqual(distinct(seen), GRANTS);
    made.forEach(function (one) {
      assert.ok(seen.indexOf(one) >= 0, one);
    });
  });
  log.debug("Leaving grants().");
}

async function claimProviders(id) {
  log.debug("Entering claimProviders().");
  log.info("=== 2. claims providers ===");
  for (let i = 0; i < PROVIDERS; i++) {
    const host = "https://cp-" + i + "-" + K.STAMP + ".example";
    await K.ok(K.rb(id) + "/admin-api/claim-providers/add-provider", {
      id: "cp" + i, name: "Provider " + i, issuer: host, discover: false,
      authorizationEndpoint: host + "/authorize",
      tokenEndpoint: host + "/token", jwksUri: host + "/jwks",
      claimsEndpoint: host + "/claims", clientId: "olp",
      clientSecret: "cp-secret-" + K.rand(8),
      authMethod: "client_secret_basic", scope: "openid",
      claims: ["credit_score"], delivery: "aggregated" },
      "registered provider " + i);
  }
  const first = await view(id, "/admin-api/claim-providers?per=3");
  K.check("2. one page of each list, both counted whole, each on its own " +
          "parameter", function () {
    assert.strictEqual(first.providers.length, 3);
    assert.strictEqual(first.counts.providers, PROVIDERS);
    assert.strictEqual(first.counts.links, 0);
    assert.strictEqual(first.paging.providers.param, "providersPage");
    assert.strictEqual(first.paging.links.param, "linksPage");
  });
  const moved = await view(id,
    "/admin-api/claim-providers?per=3&providersPage=2&linksPage=4");
  K.check("2. providersPage moves the providers, and linksPage the links " +
          "alone (clamped to its one page)", function () {
    assert.strictEqual(moved.paging.providers.page, 2);
    assert.strictEqual(moved.paging.links.page, 1);
    assert.notStrictEqual(moved.providers[0].id, first.providers[0].id);
  });
  const past = await view(id,
    "/admin-api/claim-providers?per=3&providersPage=99");
  K.check("2. a page past the end is the last page", function () {
    assert.strictEqual(past.paging.providers.page, 3);
    assert.strictEqual(past.providers.length, 1);
  });
  const seen = await walk(id, "/admin-api/claim-providers?per=2",
    "providersPage", function (v) {
      return { rows: v.providers.map(function (p) {
        return p.id;
      }), paging: v.paging.providers };
    });
  K.check("2. walking every page reads every provider once", function () {
    assert.strictEqual(seen.length, PROVIDERS);
    assert.strictEqual(distinct(seen), PROVIDERS);
  });
  log.debug("Leaving claimProviders().");
}

async function commandsAndDeliveries(id) {
  log.debug("Entering commandsAndDeliveries().");
  log.info("=== 3. provider commands and deliveries ===");
  const commands = await view(id, "/admin-api/commands?per=4");
  K.check("3. the commands view pages four lists, each on its own " +
          "parameter, `per` sizing them all", function () {
    const want = { clients: "clientsPage", accounts: "accountsPage",
                   runs: "runsPage", deliveries: "deliveriesPage" };
    Object.keys(want).forEach(function (list) {
      const p = commands.paging[list];
      assert.ok(p, list + " " + JSON.stringify(commands.paging));
      assert.strictEqual(p.param, want[list]);
      assert.strictEqual(p.perPage, 4);
    });
    assert.ok(commands.listCounts, JSON.stringify(Object.keys(commands)));
  });
  const moved = await view(id, "/admin-api/commands?per=4&runsPage=7");
  K.check("3. a page past the end of one list is clamped, and the others " +
          "stay on page one", function () {
    assert.strictEqual(moved.paging.runs.page, moved.paging.runs.pages);
    assert.strictEqual(moved.paging.accounts.page, 1);
  });
  const deliveries = await view(id, "/admin-api/deliveries?per=4");
  K.check("3. every delivery kind is paged on a parameter of its own, " +
          "named for the kind", function () {
    const params = deliveries.kinds.map(function (k) {
      assert.strictEqual(k.paging.perPage, 4, k.id);
      return k.paging.param;
    });
    assert.ok(params.indexOf("backchannelLogoutPage") >= 0,
              JSON.stringify(params));
    assert.strictEqual(distinct(params), params.length,
                       JSON.stringify(params));
  });
  log.debug("Leaving commandsAndDeliveries().");
}

async function test() {
  log.debug("Entering test().");
  const id = await K.realm("olp", "development");
  await grants(id);
  await claimProviders(id);
  await commandsAndDeliveries(id);
  log.debug("Leaving test().");
}

K.main(test, 12);
