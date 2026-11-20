// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/mdoc_authority_held.js — A LOST mdoc CLAIM FINDS THE PAIR A SIBLING
// MADE (CI run #532).
//
// `GET /oid4vci/mdoc-iaca` timed out for every input of
// tests/protocol/sts_route_inputs.js in the cluster, cells and MariaDB
// modes, and the service logged STS-PKI-0288 "did not arrive within
// 15000ms" on both nodes. Every request that lost the mint claim waited for
// a pair it could never see: `MdocAuthority.pairFrom()` read the
// certificates from the keystore but the document signer's private key
// through the kid of the REQUEST'S OWN key set's row, and only the process
// that minted has that row. So each loser waited out the whole bound and
// then minted a second authority.
//
// This file stands in for the store-backed service without one: the
// keystore's held-row readers answer the pair a "sibling" minted, and the
// cluster claim answers `used` as it does to every loser. What it holds:
//
//   1. a key set with no mdoc rows of its own, whose claim is lost, gets
//      the sibling's IACA and document signer promptly, and mints nothing;
//   2. concurrent first requests in one process ask the claim ONCE and
//      share one authority.
// ===========================================================================

delete process.env.CONFIG_FILE;

const keystore = require('../common/keystore');
const claims = require('../cluster/cluster_claims');
const mdocAuthority = require('../oid4vc/mdoc_authority');

const log = require('bunyan').createLogger({ name: 'mdoc_authority_held',
  level: process.env.LOG_LEVEL || 'info' });

const ISSUER = 'https://sts.test';
const REALM = 'mdoc-held';
// Far below the authority's 15 s wait and the route-input probe's 8 s
// request timeout: the pair is already held, so finding it is one read.
const PROMPT_MS = 2000;

function fresh() {
  log.debug("Entering fresh().");
  log.debug("Leaving fresh().");
  return new mdocAuthority.MdocAuthority(
    mdocAuthority.MdocAuthority.defaultDeps());
}

// The keystore and claim doors the authority reaches, replaced for the
// duration of `fn` and always put back.
async function withStubs(stubs, fn) {
  log.debug("Entering withStubs().");
  const saved = {
    held: keystore.credentialSignersHeldFor,
    priv: keystore.credentialSignerPrivateFor,
    remember: keystore.remember,
    publish: keystore.publishShared,
    claim: claims.claim
  };
  keystore.credentialSignersHeldFor = stubs.held;
  keystore.credentialSignerPrivateFor = stubs.priv;
  keystore.remember = stubs.remember;
  keystore.publishShared = stubs.publish;
  claims.claim = stubs.claim;
  try {
    const out = await fn();
    log.debug("Leaving withStubs().");
    return out;
  } finally {
    keystore.credentialSignersHeldFor = saved.held;
    keystore.credentialSignerPrivateFor = saved.priv;
    keystore.remember = saved.remember;
    keystore.publishShared = saved.publish;
    claims.claim = saved.claim;
  }
}

async function lostClaimFindsSibling(t) {
  log.debug("Entering lostClaimFindsSibling().");
  // The sibling: a key set with no realm mints without a claim and keeps
  // both rows on itself, private halves included.
  const sibling = { credentialSigners: [] };
  const made = await fresh().ensure(sibling, ISSUER);
  const rows = sibling.credentialSigners;
  let claimsAsked = 0;
  let written = 0;
  const stubs = {
    // What the store or the shared blob answers in another process:
    // public halves and certificates, no private key on the row.
    held: function (realmId) {
      if (realmId !== REALM) {
        return null;
      }
      return rows.map(function (one) {
        return { group: one.group, slot: one.slot, alg: one.alg,
                 kind: one.kind, pairedSlot: null,
                 publicJwk: one.publicJwk, certPem: one.certPem };
      });
    },
    priv: function (realmId, kid) {
      const row = rows.filter(function (one) {
        return realmId === REALM && one.publicJwk.kid === kid;
      })[0];
      return row ? row.privateKey : null;
    },
    remember: function () {
      written = written + 1;
    },
    publish: function () {
      written = written + 1;
      return true;
    },
    claim: async function () {
      claimsAsked = claimsAsked + 1;
      return { ok: false, reason: 'used' };
    }
  };
  // This process's view of the realm: the same realm, no mdoc rows.
  const here = { realm: REALM, kid: 'sts-test', credentialSigners: [] };
  const started = Date.now();
  const got = await withStubs(stubs, function () {
    return fresh().ensure(here, ISSUER);
  });
  const took = Date.now() - started;
  t.check(got && got.iacaPem === made.iacaPem &&
          got.dsPem === made.dsPem,
          '1a. a lost claim answers the IACA and document signer the ' +
          'sibling minted');
  t.check(took < PROMPT_MS,
          '1b. and answers promptly, not after the mint wait',
          took + 'ms');
  t.check(written === 0 && here.credentialSigners.length === 0,
          '1c. nothing is minted or written in this process',
          written + ' write(s)');
  t.check(!!got && !!got.dsKey && got.dsKid === made.dsKid,
          '1d. the document signer\'s private key is the sibling\'s',
          got ? got.dsKid : 'none');
  log.debug("Leaving lostClaimFindsSibling(). " + claimsAsked +
            " claim(s).");
}

async function concurrentShareOneMint(t) {
  log.debug("Entering concurrentShareOneMint().");
  let claimsAsked = 0;
  const stubs = {
    held: function () {
      return null;
    },
    priv: function () {
      return null;
    },
    remember: function () {
      return undefined;
    },
    publish: function () {
      return true;
    },
    claim: async function () {
      claimsAsked = claimsAsked + 1;
      return claimsAsked === 1 ? { ok: true, reason: '' }
                               : { ok: false, reason: 'used' };
    }
  };
  const keys = { realm: REALM + '-2', kid: 'sts-test',
                 credentialSigners: [] };
  const authority = fresh();
  const started = Date.now();
  const all = await withStubs(stubs, function () {
    const asks = [];
    for (let i = 0; i < 8; i++) {
      asks.push(authority.ensure(keys, ISSUER));
    }
    return Promise.all(asks);
  });
  const took = Date.now() - started;
  const distinct = new Set(all.map(function (one) {
    return one.iacaPem;
  }));
  t.check(claimsAsked === 1,
          '2a. eight concurrent first requests ask the claim once',
          claimsAsked + ' claim(s)');
  t.check(distinct.size === 1,
          '2b. and all eight answer one authority', distinct.size + '');
  t.check(took < PROMPT_MS, '2c. promptly', took + 'ms');
  log.debug("Leaving concurrentShareOneMint().");
}

async function run(t) {
  log.debug("Entering run().");
  await lostClaimFindsSibling(t);
  await concurrentShareOneMint(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mdoc_authority_held',
  describe: 'a lost mdoc mint claim finds the pair a sibling made, ' +
            'promptly, and concurrent requests share one mint (CI #532)',
  run: run
};
