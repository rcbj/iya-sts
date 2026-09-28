// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: rehearse-cell-conversion.js
//
// ===========================================================================
// THE HTTP HALF OF tests/tools/rehearse-cell-conversion.sh (#98). Not a job:
// that script runs this twice inside the tests image, on its own isolated
// stack, around a run of `persistence/cell_convert.js`.
//
//   node tests/tools/rehearse-cell-conversion.js seed   <dir>
//   node tests/tools/rehearse-cell-conversion.js verify <dir>
//
// SEED, against a SINGLE-CELL product-mode service (`https://sts:8081`):
// a realm beside the default one, and in each a public client, four people
// with passwords, a group of two of them and the client, a successful
// sign-in per person and two refused ones, and — in the default realm — a
// tiny SYNTHETIC operator deny list (documentation addresses, never a
// licensed dataset). It records each realm's JWKS key ids, each person's
// subject and risk history, and the service's trust anchor, in
// `<dir>/record.json` and `<dir>/sts-certificate.pem`.
//
// VERIFY, against the two cells the converted store became — cell A
// (`https://sts:8081`, on the converted database) and cell B
// (`https://sts2:8081`) — with the SAME anchor file, so a Root that did not
// survive the conversion fails the first request: every key id recorded is
// still published, at both cells, and an ID token issued before the
// conversion verifies at both; every person signs in at cell A with the
// subject they had; one person per realm who STARTS at cell B is restarted
// at cell A (the routing index the conversion backfilled is the only thing
// cell B can find them by) and gets a code; every person's risk history
// still holds every assessment recorded before; and the index counts every
// person as homed in cell A. Writes `<dir>/verified.json` and exits 1 on the
// first failure, saying which.
//
// Node built-ins, bunyan and tests/vendored/cells_kit.js (a kit, not a job).
// ===========================================================================
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const kit = require("../vendored/cells_kit");
const trust = require("./trust");
const log = require("bunyan").createLogger({ name: "rehearse-cells",
  level: process.env.LOG_LEVEL || "info" });

const A = "https://sts:8081";
const B = "https://sts2:8081";
const REALM = "f98crh";
const CLIENT = "rehearse-client";
const REDIRECT = "https://client.example.test/rehearse/cb";
const GROUP = "rehearsers";
const PEOPLE = ["rh-ada", "rh-bea", "rh-cyd", "rh-dov"];
const PASSWORD = "Rehearse-Conv3rsion!Pass";

// The realm prefixes a cell is addressed under.
function realmsAt(cell) {
  log.debug("Entering realmsAt().");
  log.debug("Leaving realmsAt().");
  return { default: cell, [REALM]: cell + "/realm/" + REALM };
}

// A sign-in at one realm base: the code flow with a password, redeemed.
// Answers `{ ok, sub, restarted, pinned }`.
async function signIn(base, redeemAt, username, password) {
  log.debug("Entering signIn(). " + username);
  const jar = new kit.Jar();
  const pair = kit.pkce();
  const state = "rh-" + Date.now();
  const start = kit.authorizeUrl(base, CLIENT, REDIRECT, pair, state);
  const first = await kit.signInScreen(jar, start, username, password);
  let posted = first.posted;
  let restarted = false;
  // A PERSON HOMED ELSEWHERE: 303 back to the authorization request with the
  // `sts_cell` pin and no session (sts_cells_traveller.js); the request is
  // made again with the pin and the cell relays it home.
  if (posted.status === 303 && posted.location === start &&
      jar.get("sts_cell")) {
    restarted = true;
    const again = await kit.signInScreen(jar, start, username, password);
    posted = again.posted;
  }
  if (!(posted.status >= 300 && posted.status < 400 && posted.location)) {
    log.debug("Leaving signIn(). Refused.");
    return { ok: false, status: posted.status, said: kit.said(posted.text),
             restarted: restarted };
  }
  const flow = await kit.drive(jar, posted.location, REDIRECT);
  if (!flow.code) {
    log.debug("Leaving signIn(). No code.");
    return { ok: false, status: 0, restarted: restarted,
             said: flow.stopped ? flow.stopped.status + " " +
               kit.said(flow.stopped.text) : flow.error };
  }
  const tokens = await kit.tokenCall(redeemAt, {
    grant_type: "authorization_code", code: flow.code,
    redirect_uri: REDIRECT, client_id: CLIENT,
    code_verifier: pair.verifier });
  assert.strictEqual(tokens.status, 200, "redeeming " + username + "'s " +
    "code answered " + tokens.status + ": " + tokens.raw.slice(0, 300));
  const claims = kit.claimsOf(tokens.body.id_token);
  log.debug("Leaving signIn().");
  return { ok: true, sub: String(claims.sub), restarted: restarted,
           pinned: !!jar.get("sts_cell"), idToken: tokens.body.id_token };
}

// A realm's key ids, sorted.
async function kidsAt(base) {
  log.debug("Entering kidsAt().");
  const jwks = await kit.jwksAt(base);
  log.debug("Leaving kidsAt().");
  return (jwks.keys || []).map(function (k) {
    return String(k.kid);
  }).sort();
}

// A person's assessments, as the ids of their rows.
async function historyOf(base, sub) {
  log.debug("Entering historyOf().");
  const got = await kit.api(base, "GET", "/risk?subject=" +
                            encodeURIComponent(sub) + "&per=200");
  assert.strictEqual(got.status, 200, "the risk view answered " +
    got.status + ": " + got.raw.slice(0, 300));
  const rows = (got.body.assessments && got.body.assessments.rows) || [];
  log.debug("Leaving historyOf(). " + rows.length);
  return rows.map(function (r) {
    return String(r.id || r.assessmentId || (r.at + ":" + r.subject));
  }).sort();
}

async function seed(dir) {
  log.debug("Entering seed().");
  const made = await kit.api(A, "POST", "/realms/create", {
    id: REALM, domain: REALM + ".example.net", name: "Rehearsal" });
  assert.ok(made.status === 200, "creating the realm answered " +
    made.status + ": " + made.raw.slice(0, 300));
  const record = { realms: {}, anchor: "sts-certificate.pem" };
  const bases = realmsAt(A);
  for (const realm of Object.keys(bases)) {
    const base = bases[realm];
    await kit.publicClient(base, CLIENT, REDIRECT);
    for (const person of PEOPLE) {
      const out = await kit.createPerson(base, person, PASSWORD, "");
      assert.strictEqual(out.status, 200, "creating " + person + " in " +
        realm + " answered " + out.status + ": " + out.raw.slice(0, 300));
    }
    const app = await kit.api(base, "GET", "/applications?application=" +
                              encodeURIComponent(CLIENT));
    const appDn = String((app.body && (app.body.dn ||
      (app.body.application && app.body.application.dn))) || "");
    const group = await kit.api(base, "POST", "/groups/create", {
      group: GROUP, members: [PEOPLE[0], PEOPLE[1]].concat(appDn ? [appDn]
                                                                 : []) });
    assert.strictEqual(group.status, 200, "creating the group answered " +
      group.status + ": " + group.raw.slice(0, 300));
    const people = {};
    for (const person of PEOPLE) {
      const s = await signIn(base, base, person, PASSWORD);
      assert.ok(s.ok, person + " could not sign in to " + realm + ": " +
        JSON.stringify(s));
      people[person] = { sub: s.sub };
      if (!record.tokens) {
        record.tokens = {};
      }
      record.tokens[realm] = record.tokens[realm] || s.idToken;
    }
    for (let i = 0; i < 2; i++) {
      const bad = await signIn(base, base, PEOPLE[2], PASSWORD + "-wrong");
      assert.ok(!bad.ok, "a wrong password was accepted in " + realm);
    }
    if (realm === "default") {
      const list = await kit.api(base, "POST", "/risk/import", {
        dataset: "iplist.operator-deny", realm: "default",
        format: "ip-list", version: "rehearsal-1",
        content: "198.51.100.0/25\n198.51.100.128/25\n203.0.113.7\n" });
      assert.strictEqual(list.status, 200, "importing the synthetic deny " +
        "list answered " + list.status + ": " + list.raw.slice(0, 300));
    }
    for (const person of PEOPLE) {
      people[person].history = await historyOf(base, people[person].sub);
      assert.ok(people[person].history.length >= 1, person + " in " +
        realm + " has no risk history");
    }
    record.realms[realm] = { kids: await kidsAt(base), people: people,
                             groupApplication: appDn };
  }
  const anchor = await trust.readTrust(A, 1);
  fs.writeFileSync(path.join(dir, record.anchor), anchor.pem);
  fs.writeFileSync(path.join(dir, "record.json"),
                   JSON.stringify(record, null, 2));
  log.info("rehearse: seeded " + Object.keys(record.realms).length +
           " realm(s), " + PEOPLE.length + " people each; key ids " +
           JSON.stringify(Object.keys(record.realms).map(function (r) {
             return r + "=" + record.realms[r].kids.length;
           })));
  log.debug("Leaving seed().");
}

async function verify(dir) {
  log.debug("Entering verify().");
  const record = JSON.parse(fs.readFileSync(path.join(dir, "record.json"),
                                            "utf8"));
  const out = { realms: {} };
  const atA = realmsAt(A);
  const atB = realmsAt(B);
  for (const realm of Object.keys(record.realms)) {
    const was = record.realms[realm];
    const seen = { kidsA: await kidsAt(atA[realm]),
                   kidsB: await kidsAt(atB[realm]), people: {} };
    // EVERY KEY THE SINGLE-CELL SERVICE PUBLISHED IS STILL PUBLISHED, at
    // both cells, and both publish one set. The set may have GROWN: a cell
    // pre-publishes a next generation for an algorithm that has none yet
    // (the post-quantum ones, generated lazily), as a restart of the
    // single-cell service would — which is not a key replaced.
    const missing = function (kids) {
      return was.kids.filter(function (k) {
        return kids.indexOf(k) < 0;
      });
    };
    assert.deepStrictEqual(missing(seen.kidsA), [], realm + ": cell A no " +
      "longer publishes keys the single-cell service did");
    assert.deepStrictEqual(missing(seen.kidsB), [], realm + ": cell B does " +
      "not publish keys the single-cell service did");
    assert.deepStrictEqual(seen.kidsA, seen.kidsB, realm + ": the two " +
      "cells publish different key sets");
    seen.kidsAdded = seen.kidsA.filter(function (k) {
      return was.kids.indexOf(k) < 0;
    });
    // And a token the single-cell service signed verifies at both cells.
    const old = record.tokens[realm];
    kit.verifyJwt(old, await kit.jwksAt(atA[realm]));
    kit.verifyJwt(old, await kit.jwksAt(atB[realm]));
    seen.oldTokenVerifies = true;
    // The history BEFORE this phase's own sign-ins add to it.
    for (const person of Object.keys(was.people)) {
      const history = await historyOf(atA[realm], was.people[person].sub);
      const lost = was.people[person].history.filter(function (id) {
        return history.indexOf(id) < 0;
      });
      assert.strictEqual(lost.length, 0, realm + ": " + person + "'s risk " +
        "history lost " + lost.length + " assessment(s)");
      seen.people[person] = { historyBefore: was.people[person].history
        .length, historyNow: history.length };
    }
    for (const person of Object.keys(was.people)) {
      const s = await signIn(atA[realm], atA[realm], person, PASSWORD);
      assert.ok(s.ok, realm + ": " + person + " could not sign in at cell " +
        "A: " + JSON.stringify(s));
      assert.ok(!s.restarted, realm + ": " + person + " was sent away from " +
        "cell A, their home");
      assert.strictEqual(s.sub, was.people[person].sub, realm + ": " +
        person + "'s subject changed");
      seen.people[person].signedInAtA = true;
    }
    // A person homed at A who starts at B: restarted at A through the
    // backfilled index.
    const traveller = Object.keys(was.people)[3];
    const t = await signIn(atB[realm], atB[realm], traveller, PASSWORD);
    assert.ok(t.restarted, realm + ": " + traveller + " starting at cell B " +
      "was not restarted at home — the routing index did not find them: " +
      JSON.stringify(t));
    assert.ok(t.ok, realm + ": " + traveller + " restarted at cell A could " +
      "not finish signing in: " + JSON.stringify(t));
    assert.strictEqual(t.sub, was.people[traveller].sub, realm + ": the " +
      "traveller's subject changed");
    seen.traveller = { person: traveller, restarted: t.restarted,
                       pinned: t.pinned };
    const homed = await kit.peopleIn(atA[realm], realm);
    assert.ok((homed.cella || 0) >= Object.keys(was.people).length,
      realm + ": the routing index holds " + JSON.stringify(homed) +
      " people, not every person in cella");
    // Nobody was created at cell B, so nobody is homed there — in
    // particular no second bootstrap administrator (server.js,
    // bootstrapHomedElsewhere()).
    assert.ok(!(homed.cellb > 0), realm + ": the routing index homes " +
      homed.cellb + " person(s) in cellb, where nobody was created");
    seen.index = homed;
    out.realms[realm] = seen;
  }
  fs.writeFileSync(path.join(dir, "verified.json"),
                   JSON.stringify(out, null, 2));
  log.info("rehearse: verified " + JSON.stringify(out));
  log.debug("Leaving verify().");
}

async function main() {
  log.debug("Entering main().");
  const phase = process.argv[2];
  const dir = process.argv[3] || "/rehearse";
  if (phase === "seed") {
    await seed(dir);
  } else if (phase === "verify") {
    await verify(dir);
  } else {
    throw new Error("usage: rehearse-cell-conversion.js seed|verify <dir>");
  }
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}, function (e) {
  log.error("rehearse: FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
