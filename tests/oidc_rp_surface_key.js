// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: oidc_rp_surface_key.js
//
// ===========================================================================
// A HOSTED SURFACE'S SIGNING KEY, RE-ISSUED AS OFTEN AS IT HAS TO BE (#296,
// 2026-09-27).
//
// `common/oidc_rp.ts`'s `surfaceKey()` issues the key the console (or the
// portal) signs its client assertion with, under a cluster claim so that two
// processes do not issue two. The claim was held for its whole lifetime after
// the issuance instead of released, so a key that stopped being usable inside
// that window — the Root replaced twice in a row — could not be issued again:
// the next caller was told `used`, waited out the window, and failed with
// STS-AUTHN-0208. The claim is a mutual exclusion and is released now, and a
// waiter re-claims rather than only re-reading. What this holds:
//
//   A. SEQUENTIAL. A key issued, then found unusable at once: the next call
//      issues again, promptly, and the claim is free afterwards.
//   B. CONCURRENT. Two callers at once with no usable key: ONE issues, and
//      the other takes that key rather than issuing a second.
//   C. A HOLDER THAT FAILED. The issuer fails and leaves no key: the waiter
//      takes the claim and issues, instead of waiting out the window.
//   D. A HOLDER THAT THREW. The claim is released anyway.
//
// In process, on one OidcRelyingParty with its key lookups replaced by
// counters and the real (memory) cluster claims.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'oidc_rp_surface_key',
  level: process.env.LOG_LEVEL || 'info' });

const oidcRp = require('../common/oidc_rp');
const clusterClaims = require('../cluster/cluster_claims');
const errorCodes = require('../common/error_codes');

const SURFACE = { clientId: 'sts-surface-key-test', label: 'Test surface' };

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// An OidcRelyingParty whose key lookups are this test's: `state.held` is the
// usable key (or null), `issue` decides what an issuance does.
function partyWith(state, issue) {
  log.debug("Entering partyWith().");
  const party = new oidcRp.OidcRelyingParty(
    oidcRp.OidcRelyingParty.defaultDeps());
  const anyParty = /** @type {any} */ (party);
  anyParty.usableSurfaceKey = function () {
    return Promise.resolve(state.held);
  };
  anyParty.issueSurfaceKey = async function () {
    state.issued += 1;
    return issue(state);
  };
  log.debug("Leaving partyWith().");
  return anyParty;
}

async function claimIsFree() {
  log.debug("Entering claimIsFree().");
  const probe = await clusterClaims.claim({ scope: 'oidc_rp.surface-key',
    realm: 'default', value: SURFACE.clientId, ttlMs: 1000 });
  if (probe.ok) {
    await clusterClaims.release(probe.handle);
  }
  log.debug("Leaving claimIsFree().");
  return !!probe.ok;
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. issued, found unusable at once, issued again ===');
  const a = { held: null, issued: 0 };
  const partyA = partyWith(a, function (s) {
    // The key it issued is not usable a moment later — the Root replaced.
    s.held = null;
    return { ok: true, kid: 'k' + s.issued, privateKeyPem: 'pem' };
  });
  const a1 = await partyA.surfaceKey(SURFACE);
  const began = Date.now();
  const a2 = await partyA.surfaceKey(SURFACE);
  const took = Date.now() - began;
  t.check(a1.ok && a2.ok && a1.kid === 'k1' && a2.kid === 'k2',
          'A1. the second call issues a key of its own rather than being ' +
          'told the claim is used', JSON.stringify([a1, a2]));
  t.check(took < 2000, 'A2. promptly — not after waiting out the claim\'s ' +
          'window (~21 s), which is what failed with STS-AUTHN-0208',
          took + ' ms');
  t.check(await claimIsFree(), 'A3. and the claim is free afterwards: it ' +
          'is released when the issuance ends');

  t.log.info('=== B. two callers at once: one issues ===');
  const b = { held: null, issued: 0 };
  const partyB = partyWith(b, async function (s) {
    await sleep(300);
    const key = { ok: true, kid: 'b' + s.issued, privateKeyPem: 'pem' };
    s.held = key;
    return key;
  });
  const both = await Promise.all([partyB.surfaceKey(SURFACE),
                                  partyB.surfaceKey(SURFACE)]);
  t.check(b.issued === 1 && both[0].ok && both[1].ok &&
          both[0].kid === both[1].kid,
          'B1. one issuance, and both callers hold its key',
          JSON.stringify({ issued: b.issued, kids: both.map(function (k) {
            return k.kid;
          }) }));
  t.check(await claimIsFree(), 'B2. the claim is free afterwards');

  t.log.info('=== C. the holder failed: the waiter issues ===');
  const c = { held: null, issued: 0 };
  const partyC = partyWith(c, async function (s) {
    await sleep(300);
    if (s.issued === 1) {
      return errorCodes.mark({ ok: false, why: 'the first issuance failed' },
                             'STS-AUTHN-0207');
    }
    const key = { ok: true, kid: 'c' + s.issued, privateKeyPem: 'pem' };
    s.held = key;
    return key;
  });
  const cBegan = Date.now();
  const c2 = await Promise.all([partyC.surfaceKey(SURFACE),
                                sleep(50).then(function () {
                                  return partyC.surfaceKey(SURFACE);
                                })]);
  const cTook = Date.now() - cBegan;
  t.check(!c2[0].ok && c2[1].ok && c2[1].kid === 'c2' && c.issued === 2,
          'C1. the first caller\'s failure is its own, and the waiter took ' +
          'the claim and issued', JSON.stringify(c2));
  t.check(cTook < 3000, 'C2. at once, not at the end of the window',
          cTook + ' ms');

  t.log.info('=== D. the holder threw: the claim is released anyway ===');
  const d = { held: null, issued: 0 };
  const partyD = partyWith(d, function () {
    throw new Error('an issuance that threw');
  });
  let threw = false;
  try {
    await partyD.surfaceKey(SURFACE);
  } catch (e) {
    threw = /threw/.test(String(e && e.message));
  }
  t.check(threw && await claimIsFree(),
          'D1. the throw reaches the caller and the claim is released');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidc_rp_surface_key',
  describe: 'a hosted surface\'s signing key re-issued as often as it has ' +
            'to be (#296): the claim released when an issuance ends, one ' +
            'issuer among concurrent callers, a waiter that takes over from ' +
            'a failed holder',
  run: run
};
