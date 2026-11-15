// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/used-assertions-vectors.js
//
// ---------------------------------------------------------------------------
// THE USED-ASSERTION HISTORY, AS NODE KEYS AND ANSWERS IT (#444, phase 5,
// the `oauth6` slice): the vectors
// `rust/crates/sts-oauth/tests/used_assertions_vectors.rs` reads, run by
// `crypto-vectors.js` (`used-assertions-node.json`) in a child of its own.
//
//   keys      keyOf(format, issuer, identifier) over awkward inputs — the
//             row key both runtimes write into `sts_used_assertions`, so a
//             document either spent is refused by the other;
//   usedAs    usedAs(existing): the clause a replay refusal appends;
//   claims    a run of claim() and peek() against this process's history
//             (the memory store), with each answer's outcome: the same
//             document under another use, a request object, the cap.
//
// And `checkRust()`: the keys Rust computed (`used-assertions-rust.json`),
// computed again by Node. A builder is a tool, not service code, and logs
// nothing.
// ---------------------------------------------------------------------------

const path = require('path');

const INPUTS = [
  ['jwt', 'client-a', 'jti-1'],
  ['jwt', 'https://issuer.example/', 'a\nb'],
  ['saml', 'https://idp.example/saml', '_0123456789abcdef'],
  ['saml11', 'urn:idp', 'ID-1'],
  ['jwt', 'ünïcødé', '日本語'],
  ['attestation-challenge', 'c', ''.padEnd(600, 'x')]
];

const ROWS = [
  { format: 'jwt', use: 'client-authentication', state: 'spent' },
  { format: 'jwt', use: 'client-authentication', state: 'reserved' },
  { format: 'jwt', use: 'authorization-grant', state: 'spent' },
  { format: 'saml', use: 'authorization-grant', state: 'spent' },
  { format: 'saml', use: 'client-authentication', state: 'reserved' },
  { format: 'jwt', use: 'request-object', state: 'reserved' },
  { format: 'jwt', use: 'client-attestation-pop', state: 'spent' },
  { format: 'jwt', use: 'token-exchange', state: 'spent' }
];

function outcome(answer) {
  if (answer.ok) {
    return { ok: true };
  }
  return { ok: false, reason: answer.reason,
           usedAs: answer.existing ? answer.existing.use : '' };
}

async function claims(used, config) {
  const out = [];
  const exp = Date.now() + 60000;
  const one = function (use, issuer, identifier) {
    return { format: 'jwt', use: use, issuer: issuer,
             identifier: identifier, expiresAt: exp, clientId: issuer };
  };
  const steps = [
    ['claim', one('client-authentication', 'c1', 'j1')],
    ['claim', one('client-authentication', 'c1', 'j1')],
    ['claim', one('request-object', 'c1', 'j1')],
    ['claim', one('authorization-grant', 'c1', 'j1')],
    ['peek', one('', 'c1', 'j1')],
    ['peek', one('', 'c1', 'j2')],
    ['claim', one('request-object', 'c1', 'j2')],
    ['claim', one('client-authentication', 'c2', 'j1')]
  ];
  for (const step of steps) {
    if (step[0] === 'claim') {
      out.push({ step: 'claim', ask: step[1],
                 answer: outcome(await used.claim(step[1])) });
    } else {
      const seen = await used.peek(step[1]);
      out.push({ step: 'peek', ask: step[1],
                 answer: { used: !!seen.used } });
    }
  }
  // The cap: a realm holding as many live rows as it may (three now)
  // refuses `full`.
  config.setOverride('oauth2.assertionReplayCacheSize', 3);
  out.push({ step: 'claim', cap: 3,
             ask: one('client-authentication', 'c3', 'j1'),
             answer: outcome(await used.claim(one('client-authentication',
                                                  'c3', 'j1'))) });
  config.setOverride('oauth2.assertionReplayCacheSize', 1000);
  return out;
}

async function build(ROOT) {
  const config = require(path.join(ROOT, 'common', 'config'));
  const used = require(path.join(ROOT, 'common', 'used_assertions'));
  const out = { problems: [] };
  try {
    out.keys = INPUTS.map(function (row) {
      return { format: row[0], issuer: row[1], identifier: row[2],
               key: used.keyOf(row[0], row[1], row[2]) };
    });
    out.usedAs = ROWS.map(function (row) {
      return { existing: row, clause: used.usedAs(row) };
    });
    out.claims = await claims(used, config);
  } catch (e) {
    out.problems.push(String((e && e.stack) || e));
  }
  return out;
}

// THE OTHER DIRECTION: the keys Rust computed, computed again here.
function checkRust(ROOT, rows, check) {
  const used = require(path.join(ROOT, 'common', 'used_assertions'));
  (rows.keys || []).forEach(function (row) {
    const mine = used.keyOf(row.format, row.issuer, row.identifier);
    check(mine === row.key, 'used assertions: Node keys the document Rust ' +
          'keyed (' + row.format + ', ' + String(row.issuer).slice(0, 40) +
          ')', mine + ' vs ' + row.key);
  });
  (rows.usedAs || []).forEach(function (row) {
    const mine = used.usedAs(row.existing);
    check(mine === row.clause, 'used assertions: Node says the replay ' +
          'clause Rust said (' + row.existing.use + ', ' +
          row.existing.state + ')', mine + ' vs ' + row.clause);
  });
}

module.exports = { build: build, checkRust: checkRust };
