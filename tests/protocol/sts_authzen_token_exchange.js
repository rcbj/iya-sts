// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_token_exchange.js
//
// ===========================================================================
// THE AUTHZEN BINDING FOR OAUTH 2.0 TOKEN EXCHANGE, DIRECTION A, OVER THE
// WIRE (#444 D12 phase 8; #1181).
//
// `tests/authzen_token_exchange.js` drives `AuthzenSurface`'s item path in
// process. This job asks `POST /access/v1/evaluations` (and the metadata)
// as another authorization server would, with a client certificate in
// `authzen-peps`, in a development and a product realm with
// `authzen.tokenExchange` on, and reads each code off `/admin-api/audit`
// (a code is recorded, never sent):
//
//   F. THE FIXED RULES: a context member in the wrong JSON type (STS-
//      AUTHZEN-0100, and a subject token claim), a subject.type outside
//      user/client/workload (0102), a binding member on a tuple that is not
//      the binding's (0101) — each a 400 asked as ONE evaluation, and in a
//      batch the item's `context.error` (WIRE: a batch item's code is not
//      recorded; only a single evaluation marks its answer) — another grant
//      (0103) and an unregistered token
//      type (0104) each a decision false, a scope tuple with no gate
//      (0105), a third party for one target (0107) and a scope tuple naming
//      somebody else (0106);
//   C. THE CATALOGUE may not override a member the fixed rules read, nor a
//      path under one (0011), and may add the realm's own;
//   E. THE SAME DECISION AS A LOCAL EXCHANGE, in both modes: allowed; a
//      requesting party with no relationship (product false, 0109;
//      development true, 0110); a subject never delegated; an unregistered
//      target; a may_act naming somebody else (false in every mode); the
//      realm's own issuance policy refusing both gates;
//   N. NARROWING ONLY: the subject gate's `context.issuance` carries
//      token_lifetime (no more than the subject token has left) and the
//      granted scope (narrowed to the client's declaration in product,
//      whole in development), nothing else; a subject token with no life
//      left is a false subject gate (0114);
//   S. SCOPE TUPLES: declared and carried, true; undeclared (product false,
//      0112); wider than the subject token (product false, 0111);
//   J. ID-JAG and TXN-TOKEN, in product as in process: both ID-JAG gates
//      and a level-2 scope tuple; a client with no delegation into the trust
//      domain; a workload's own scope tuples; outside a Txn-Token a scope tuple for the requesting
//      party (0106);
//   M. THE METADATA advertises the token issuance capability only while
//      the binding is on; off, a gate tuple is the root policy's.
//
// (d), with the reason: F1-F4 (the classifier, the token-type table, the
// docs table, the reserved list) and L1 (the XACML request's attribute
// list) and E9 (the question built) are functions and documents; their
// outcomes are this job's decisions. N3 (`narrowOnly()` dropping a wider
// value) is the function under N1.
//
// OWNED HERE (local: true): the AuthZEN API is ours.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const K = require("./oauth_wire_kit.js").kit("sts_authzen_token_exchange");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;
const BACK = "https://azx-back.example";
const PEER = "https://azx-peer.example";
const ACCESS = "issue:access_token:token_exchange";
const TOKEN_ISSUANCE = "urn:openid:authzen:capability:token-issuance";
const REFUSE_FRONT = [
  "namespace azxrefuse {",
  "    attribute act { category = actionCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"",
  "        type = string }",
  "    attribute actor { category = intermediarySubjectCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:subject:subject-id\"",
  "        type = string }",
  "    policy azxRefuseFront {",
  "        id = \"urn:test:azx-refuse-front\"",
  "        apply denyOverrides",
  "        rule refuseFront {",
  "            deny",
  "            target clause act == \"exchange-token\"",
  "                and actor == \"azx-front\"",
  "            on deny {",
  "                obligation \"urn:sts:xacml:obligation:exchange\" {",
  "                    \"urn:sts:xacml:exchange-verdict\" = \"refuse\"",
  "                    \"urn:sts:xacml:exchange-refusal\" = \"policy\"",
  "                    \"urn:sts:xacml:exchange-enforced\" = true",
  "                }",
  "            }",
  "        }",
  "    }",
  "}"
].join("\n");

const added = [];
const stored = [];
let caller = null;
let CN = "";

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return K.send(url).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return K.send(url, { json: payload || {} }).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

function pep(method, path, payload) {
  log.debug("Entering pep(). " + method + " " + path);
  return new Promise(function (resolve, reject) {
    const target = new URL(K.base + path);
    const data = payload === undefined ? null : JSON.stringify(payload);
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: method,
      rejectUnauthorized: false, cert: caller.certPem, key: caller.keyPem,
      headers: data ? { "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data) } : {}
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) {
        text += chunk;
      });
      response.on("end", function () {
        let body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in pep(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the status and the text.
          body = null;
        }
        log.debug("Leaving pep(). " + response.statusCode);
        resolve({ status: response.statusCode, json: body, text: text });
      });
    });
    request.on("error", reject);
    if (data) {
      request.write(data);
    }
    request.end();
  });
}

// The binding's two gates for an exchange of `subject`'s token by `party`.
function gates(subject, party, target, context, tokenType) {
  log.debug("Entering gates().");
  const action = { name: "issue:" + (tokenType || "access_token") +
                         ":token_exchange" };
  const items = [{ subject: subject, action: action }];
  if (party) {
    items.push({ subject: party, action: action });
  }
  log.debug("Leaving gates().");
  return { resource: { type: "audience", id: target }, context: context,
           evaluations: items };
}

function user(id) {
  log.debug("Entering user().");
  log.debug("Leaving user().");
  return { type: "user", id: id };
}

function client(id) {
  log.debug("Entering client().");
  log.debug("Leaving client().");
  return { type: "client", id: id };
}

function scopeTuple(subject, scope, target) {
  log.debug("Entering scopeTuple().");
  log.debug("Leaving scopeTuple().");
  return { subject: subject, action: { name: scope },
           resource: { type: "protected_resource", id: target || BACK } };
}

// One batch in realm `r`: `{ status, answers: [ { decision, context } ] }`.
async function ask(r, body) {
  log.debug("Entering ask().");
  const one = await pep("POST", "/realm/" + r.id + "/access/v1/evaluations",
                        body);
  log.debug("Leaving ask(). " + one.status);
  return { status: one.status, text: one.text,
           answers: (one.json && one.json.evaluations) || [] };
}

// One evaluation in realm `r`, answered as `/access/v1/evaluation` does.
async function askOne(r, body) {
  log.debug("Entering askOne().");
  const one = await pep("POST", "/realm/" + r.id + "/access/v1/evaluation",
                        body);
  log.debug("Leaving askOne(). " + one.status);
  return { status: one.status, text: one.text, json: one.json,
           answers: one.json ? [one.json] : [] };
}

function decisions(a) {
  log.debug("Entering decisions().");
  log.debug("Leaving decisions().");
  return a.answers.map(function (one) {
    return one.decision;
  });
}

// `act` while `code` is counted in realm `r`: its answer, and the rise.
async function coded(r, code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(r.id, code, act);
  check(r.mode + ": " + what + " (" + code + ")", function () {
    verdict(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

function shown(a) {
  log.debug("Entering shown().");
  log.debug("Leaving shown().");
  return a.status + " " + String(a.text).slice(0, 600);
}

async function setUp(mode) {
  log.debug("Entering setUp(). " + mode);
  const id = await K.realm("azx" + mode.slice(0, 3), mode);
  const r = { id: id, mode: mode,
              api: function (path) {
                return K.rb(id) + "/admin-api" + path;
              } };
  for (const name of ["azx-alice", "azx-bob", "azx-carol"]) {
    await K.ok(r.api("/users/create"), { username: name, invent: false,
      attributes: { cn: name, sn: name, givenName: name,
                    mail: name + "@azx.example" } }, "created " + name);
  }
  await K.ok(r.api("/users/set-not-delegated"), { user: "azx-bob",
    value: true }, "azx-bob carries stsNotDelegated");
  const apps = [
    ["azx-back", { oauthAudience: [BACK] }],
    ["azx-front", { appAllowedToDelegateTo: ["azx-back"],
                    oauthAllowedScope: ["read:docs"] }],
    ["azx-mid", {}],
    ["azx-peer", { oauthAudience: [PEER] }],
    ["azx-idp", { appAllowedToDelegateTo: ["azx-peer"],
                  oauthAllowedScope: ["files.read"] }],
    ["azx-wl", { appAllowedToDelegateTo: ["azx-back"],
                 oauthAllowedScope: ["txn:read", "read:docs"] }]];
  for (const one of apps) {
    await K.app(id, one[0], Object.assign({ oauthClientId: [one[0]] },
                                          one[1]), { protocols: ["oauth2"] });
  }
  stored.push(await credentials.storeOnEntry({ get: get, post: post },
    K.base, "/realm/" + id, CN, caller.leaf.pem));
  await K.ok(r.api("/groups/add-member"), { group: "authzen-peps",
    member: CN }, "the caller in authzen-peps");
  await K.ok(r.api("/xacml/authzen/set-scope"), { caller: CN,
    applications: ["azx-back"] }, "the caller's scope");
  log.debug("Leaving setUp().");
  return r;
}

async function fixedRules(r) {
  log.debug("Entering fixedRules().");
  log.info("=== F. the fixed rules, in " + r.mode + " ===");
  // A refused ITEM of a batch carries its status in `context.error` and
  // records no code (only a single evaluation marks its answer), so the
  // four 400s are asked as single evaluations, and each batch's item is
  // held to its in-band status beside it.
  const bad = function (a) {
    assert.strictEqual(a.status, 400, shown(a));
  };
  const isFalse = function (i) {
    return function (a) {
      assert.strictEqual(a.status, 200, shown(a));
      assert.strictEqual(a.answers[i].decision, false, shown(a));
    };
  };
  const inBand = function (a) {
    const one = a.answers[0] || {};
    assert.strictEqual(a.status, 200, shown(a));
    assert.strictEqual(one.decision, false, shown(a));
    assert.strictEqual(((one.context || {}).error || {}).status, 400,
                       shown(a));
  };
  const single = function (body) {
    const item = Object.assign({}, body, body.evaluations[0]);
    delete item.evaluations;
    return askOne(r, item);
  };
  const cases = [
    ["STS-AUTHZEN-0100", "F5. a fixed context member in the wrong JSON " +
     "type is 400", gates(user("azx-alice"), null, BACK, { client_id: 7 })],
    ["STS-AUTHZEN-0100", "F6. and so is a subject token claim a rule reads",
     gates(user("azx-alice"), null, BACK, { subject_token: { aud: 3 } })],
    ["STS-AUTHZEN-0102", "F7. subject.type is user, client or workload",
     gates({ type: "person", id: "azx-alice" }, null, BACK, {})],
    ["STS-AUTHZEN-0101", "F8. a binding context member on a tuple that is " +
     "not the binding's is 400",
     { resource: { type: "document", id: "d1" },
       context: { may_act: { sub: "x" } },
       evaluations: [{ subject: user("azx-alice"),
                       action: { name: "read" } }] }]];
  for (const one of cases) {
    await coded(r, one[0], one[1], function () {
      return single(one[2]);
    }, bad);
    const batched = await ask(r, one[2]);
    check(r.mode + ": " + one[1].slice(0, 3) + " in a batch: the item's " +
          "context.error is 400 and its decision false", function () {
      inBand(batched);
    });
  }
  const other = { resource: { type: "audience", id: BACK },
                  evaluations: [
                    { subject: user("azx-alice"), action: { name:
                      "issue:access_token:authorization_code" } },
                    { subject: user("azx-alice"), action: { name:
                      "issue:widget:token_exchange" } }] };
  await coded(r, "STS-AUTHZEN-0103", "F9a. another grant is a decision " +
              "false", function () {
    return ask(r, other);
  }, isFalse(0));
  await coded(r, "STS-AUTHZEN-0104", "F9b. an unregistered token type is a " +
              "decision false", function () {
    return ask(r, other);
  }, isFalse(1));
  await coded(r, "STS-AUTHZEN-0105", "F10. a scope tuple with no gate " +
              "beside it is false", function () {
    return ask(r, { evaluations: [scopeTuple(user("azx-alice"),
                                             "read:docs")] });
  }, isFalse(0));
  const third = gates(user("azx-alice"), client("azx-front"), BACK,
                      { client_id: "azx-front",
                        subject_token: { aud: "azx-front" } });
  third.evaluations.push({ subject: client("azx-mid"),
                           action: { name: ACCESS } });
  third.evaluations.push(scopeTuple(user("azx-carol"), "read:docs"));
  await coded(r, "STS-AUTHZEN-0107", "F11a. a third party for one target " +
              "is false", function () {
    return ask(r, third);
  }, isFalse(2));
  await coded(r, "STS-AUTHZEN-0106", "F11b. a scope tuple naming somebody " +
              "other than the exchange subject is false", function () {
    return ask(r, third);
  }, isFalse(3));
  log.debug("Leaving fixedRules().");
}

async function catalogue(r) {
  log.debug("Entering catalogue().");
  log.info("=== C. the catalogue adds and never overrides ===");
  for (const member of ["client_id", "subject_token.scope"]) {
    await coded(r, "STS-AUTHZEN-0011", "C1. a catalogue row naming " +
                member + " (a member the fixed rules read, or a path under " +
                "one) is refused", function () {
      return K.send(r.api("/xacml/authzen/set-attribute"), { json: {
        object: "context", property: member,
        attributeId: "urn:example:azx-" + member.replace(/\W/g, "-") } });
    }, function (a) {
      assert.ok(a.status >= 400 || (a.json && a.json.ok === false),
                K.shown(a));
    });
  }
  const own = await K.send(r.api("/xacml/authzen/set-attribute"), { json: {
    object: "context", property: "tenant",
    attributeId: "urn:example:tenant" } });
  check(r.mode + ": C3. a row of the realm's own is accepted", function () {
    assert.ok(own.status === 200 && own.json && own.json.ok !== false,
              K.shown(own));
  });
  log.debug("Leaving catalogue().");
}

function exchange(actor, subject, target, mayAct) {
  log.debug("Entering exchange().");
  const context = { client_id: actor, subject_token: { aud: "azx-front" } };
  if (mayAct) {
    context.may_act = mayAct;
  }
  log.debug("Leaving exchange().");
  return gates(user(subject), client(actor), target, context);
}

async function sameDecision(r) {
  log.debug("Entering sameDecision().");
  log.info("=== E. the same decision as a local exchange, in " + r.mode +
           " ===");
  const product = r.mode === "product";
  let a = await ask(r, exchange("azx-front", "azx-alice", BACK));
  check(r.mode + ": E1. allowed — both gates true", function () {
    assert.deepStrictEqual(decisions(a), [true, true], shown(a));
  });
  const code = product ? "STS-AUTHZEN-0109" : "STS-AUTHZEN-0110";
  a = await coded(r, code, "E2. a requesting party with no relationship: " +
                  (product ? "its gate false" : "true, and product would " +
                   "refuse"), function () {
    return ask(r, exchange("azx-mid", "azx-alice", BACK));
  }, function (one) {
    assert.strictEqual(one.answers[1].decision, !product, shown(one));
  });
  a = await ask(r, exchange("azx-front", "azx-bob", BACK));
  check(r.mode + ": E3. a subject never delegated — " +
        (product ? "both gates false" : "issued, as development issues it"),
        function () {
    assert.deepStrictEqual(decisions(a), product ? [false, false]
                                                 : [true, true], shown(a));
  });
  a = await ask(r, exchange("azx-front", "azx-alice",
                            "https://azx-nowhere.example"));
  check(r.mode + ": E4. an unregistered target — " +
        (product ? "the subject gate false" : "issued"), function () {
    assert.strictEqual(a.answers[0].decision, !product, shown(a));
  });
  a = await ask(r, exchange("azx-front", "azx-alice", BACK,
                            { sub: "azx-carol" }));
  check(r.mode + ": E5. a may_act naming somebody else refuses the " +
        "requesting party's gate in every mode", function () {
    assert.strictEqual(a.answers[1].decision, false, shown(a));
  });
  if (product) {
    await K.ok(r.api("/xacml/import-alfa"), { name: "azx-refuse-front",
      alfa: REFUSE_FRONT }, "imported the realm's refusing policy");
    await K.set(r.id, "xacml.issuancePolicy", "azx-refuse-front");
    a = await ask(r, exchange("azx-front", "azx-alice", BACK));
    check(r.mode + ": E8. the realm's own issuance policy refuses both " +
          "gates", function () {
      assert.deepStrictEqual(decisions(a), [false, false], shown(a));
    });
    await K.unset(r.id, "xacml.issuancePolicy");
  }
  log.debug("Leaving sameDecision().");
}

async function narrowing(r) {
  log.debug("Entering narrowing().");
  log.info("=== N. narrowing only ===");
  const exp = Math.floor(Date.now() / 1000) + 120;
  const a = await ask(r, gates(user("azx-alice"), client("azx-front"), BACK,
    { client_id: "azx-front", subject_token: { aud: "azx-front", exp: exp,
      scope: "read:docs write:docs" } }));
  const issuance = ((a.answers[0] || {}).context || {}).issuance || {};
  check(r.mode + ": N1. the subject gate carries token_lifetime (no more " +
        "than the subject token has left) and the subject token's scope — " +
        "in product narrowed to what the client declares, in development " +
        "whole — nothing else, on that gate alone", function () {
    assert.deepStrictEqual(decisions(a), [true, true], shown(a));
    assert.ok(issuance.token_lifetime > 0 &&
              issuance.token_lifetime <= 120, shown(a));
    assert.strictEqual(issuance.granted_scope, r.mode === "product"
      ? "read:docs" : "read:docs write:docs", shown(a));
    assert.deepStrictEqual(Object.keys(issuance).sort(),
                           ["granted_scope", "token_lifetime"], shown(a));
    assert.ok(!((a.answers[1] || {}).context || {}).issuance, shown(a));
  });
  await coded(r, "STS-AUTHZEN-0114", "N2. a subject token with no life " +
              "left is a false subject gate", function () {
    return ask(r, gates(user("azx-alice"), client("azx-front"), BACK,
      { client_id: "azx-front", subject_token: { aud: "azx-front",
        exp: Math.floor(Date.now() / 1000) - 5 } }));
  }, function (one) {
    assert.strictEqual(one.answers[0].decision, false, shown(one));
  });
  log.debug("Leaving narrowing().");
}

async function scopes(r) {
  log.debug("Entering scopes().");
  log.info("=== S. scope tuples, in " + r.mode + " ===");
  const product = r.mode === "product";
  const body = function () {
    const g = gates(user("azx-alice"), client("azx-front"), BACK,
      { client_id: "azx-front", subject_token: { aud: "azx-front",
        scope: "read:docs write:docs" } });
    ["read:docs", "write:docs", "admin:all"].forEach(function (scope) {
      g.evaluations.push(scopeTuple(user("azx-alice"), scope));
    });
    return g;
  };
  const what = "S1. a declared, carried scope is true and with scope " +
    "tuples there is no granted_scope; S2. one the client does not declare " +
    "is " + (product ? "false" : "true, as development issues it");
  const verdict = function (one) {
    const d = decisions(one);
    assert.deepStrictEqual(d.slice(0, 3), [true, true, true], shown(one));
    const issued = ((one.answers[0] || {}).context || {}).issuance || {};
    assert.strictEqual(issued.granted_scope, undefined, shown(one));
    assert.strictEqual(d[3], !product, shown(one));
  };
  let a;
  if (product) {
    a = await coded(r, "STS-AUTHZEN-0112", what, function () {
      return ask(r, body());
    }, verdict);
  } else {
    a = await ask(r, body());
    check(r.mode + ": " + what, function () {
      verdict(a);
    });
  }
  if (product) {
    check(r.mode + ": S3. a scope wider than the subject token's is " +
          "refused at the exchange stage", function () {
      assert.strictEqual(a.answers[4].decision, false, shown(a));
    });
    const c = await K.codeCount(r.id, "STS-AUTHZEN-0111");
    check(r.mode + ": S3. and STS-AUTHZEN-0111 is recorded", function () {
      assert.ok(c >= 1, "STS-AUTHZEN-0111 " + c);
    });
  }
  log.debug("Leaving scopes().");
}

async function tokenTypes(r) {
  log.debug("Entering tokenTypes().");
  log.info("=== J. ID-JAG and Txn-Token, in " + r.mode + " ===");
  const jag = gates(user("azx-alice"), client("azx-idp"), PEER,
    { client_id: "azx-idp",
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      subject_token: { aud: "azx-idp", scope: "files.read" } }, "id_jag");
  jag.evaluations.push(scopeTuple(user("azx-alice"), "files.read",
                                  "https://api.app.example"));
  let a = await ask(r, jag);
  check(r.mode + ": J1. an ID-JAG: both level-1 gates on the peer " +
        "authorization server and a level-2 scope tuple are true",
        function () {
    assert.deepStrictEqual(decisions(a), [true, true, true], shown(a));
  });
  a = await ask(r, gates(user("azx-alice"), client("azx-mid"), PEER,
    { client_id: "azx-mid", subject_token: { aud: "azx-mid" } }, "id_jag"));
  check(r.mode + ": J2. an ID-JAG for a client with no delegation into " +
        "that trust domain refuses its gate", function () {
    assert.deepStrictEqual(decisions(a), [true, false], shown(a));
  });
  const txn = gates(user("azx-alice"), { type: "workload", id: "azx-wl" },
    BACK, { subject_token: { aud: "azx-wl", scope: "read:docs" },
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt" },
    "txn_token");
  txn.evaluations.push(scopeTuple({ type: "workload", id: "azx-wl" },
                                  "txn:read"));
  txn.evaluations.push(scopeTuple({ type: "workload", id: "azx-wl" },
                                  "txn:write"));
  a = await ask(r, txn);
  check(r.mode + ": J3. a Txn-Token: the workload's own scope tuples are " +
        "decided as the workload's — one it declares true, one it does not " +
        "false", function () {
    assert.deepStrictEqual(decisions(a), [true, true, true, false],
                           shown(a));
  });
  const plain = gates(user("azx-alice"), client("azx-front"), BACK,
    { client_id: "azx-front", subject_token: { aud: "azx-front" } });
  plain.evaluations.push(scopeTuple(client("azx-front"), "read:docs"));
  await coded(r, "STS-AUTHZEN-0106", "J4. outside a Txn-Token, a scope " +
              "tuple for the requesting party is false", function () {
    return ask(r, plain);
  }, function (one) {
    assert.strictEqual(one.answers[2].decision, false, shown(one));
  });
  log.debug("Leaving tokenTypes().");
}

async function metadata(r) {
  log.debug("Entering metadata().");
  log.info("=== M. the metadata, and off ===");
  const url = K.base + "/.well-known/authzen-configuration/realm/" + r.id;
  const on = await K.send(url);
  await K.set(r.id, "authzen.tokenExchange", false);
  const off = await K.send(url);
  check(r.mode + ": M1. the token issuance capability is advertised only " +
        "while the binding answers", function () {
    assert.ok(((on.json || {}).capabilities || [])
      .indexOf(TOKEN_ISSUANCE) >= 0, on.text.slice(0, 600));
    assert.ok(((off.json || {}).capabilities || [])
      .indexOf(TOKEN_ISSUANCE) < 0, off.text.slice(0, 600));
  });
  const a = await ask(r, gates(user("azx-alice"), null, BACK,
                               { client_id: 7 }));
  check(r.mode + ": M2. off, a gate tuple is the root policy's: the " +
        "binding's type rule (0100) no longer refuses it", function () {
    assert.strictEqual(a.status, 200, shown(a));
  });
  log.debug("Leaving metadata().");
}

async function test() {
  log.debug("Entering test().");
  CN = "azx-pep-" + K.STAMP;
  caller = await credentials.mint({ subject: "CN=" + CN +
                                    ",OU=authzen,O=iya-sts tests" });
  const posted = await credentials.trustRecorded(K.base, caller.anchorPem,
                                                 added);
  assert.ok(posted.ok, "the client truststore took the test Root: " +
            posted.status);
  try {
    for (const mode of ["development", "product"]) {
      const r = await setUp(mode);
      await K.set(r.id, "authzen.tokenExchange", true);
      await fixedRules(r);
      if (mode === "development") {
        await catalogue(r);
      }
      await sameDecision(r);
      await narrowing(r);
      await scopes(r);
      if (mode === "product") {
        await tokenTypes(r);
      }
      await metadata(r);
    }
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  log.debug("Leaving test().");
}

K.main(test, 56);
