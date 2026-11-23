// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signing_certificate_stability.js
//
// ===========================================================================
// A SIGNING KEY'S CERTIFICATE LIVES AS LONG AS THE KEY (GitHub Actions run
// 45189343764, 2026-11-23).
//
// `sts_admin_console` failed in the single-node, mariadb, cells and cluster
// modes with seven links from the keys page answering 404: the RS256 key's
// certificate and the six curve keys'. The page was drawn at 14:54; at 15:00
// the hourly `signing.rotate` minted a `next` key for the units that had none
// (the post-quantum units, made after its first run), `replaceGeneration()`
// asked `certifyKeySet()` to certify the new generation, and that RE-ISSUED
// every RSA and curve certificate over keys that had not changed. The
// fingerprints the page had linked were then held nowhere. The memory mode
// passed because development mode does not run the rotation; the run before
// passed because its crawl did not cross the hour (it did the same at 10:00).
//
// The post-quantum keys kept their certificates, because `certifyPqKeys()`
// has always left a current one alone. This file holds the same for the
// classical keys, and holds that everything which SHOULD re-certify still
// does:
//
//   A. certifying the set again, after a new generation is minted the way
//      the hourly job mints one, keeps every RSA and curve certificate —
//      same serial, same SHA-256 — and says how many it kept;
//   B. a certificate an operator revoked over a key the realm still signs
//      with is certified again (common/CLAUDE.md, *What is still
//      re-certified whatever was revoked*);
//   C. a reissued Issuing CA re-certifies every key under it, so no leaf is
//      left chaining to the authority it replaced.
// ===========================================================================

delete process.env.CONFIG_FILE;

const pki = require('../common/pki');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');
const revocation = require('../common/pki_revocation');

const log = require('bunyan').createLogger({
  name: 'signing_certificate_stability',
  level: process.env.LOG_LEVEL || 'info' });

// The default realm: `helpers.stsKeysFor.of('')` and the PKI row it is
// certified into are the same realm's (see tests/pki_hierarchy.js's note on
// why a made-up realm id would compare two unconnected things).
const REALM = '';

// Every RSA and curve slot the key set is certified into, as
// `{ unit: { serial, thumbprint } }`.
function classicalSlots(keys) {
  log.debug("Entering classicalSlots().");
  const out = {};
  const add = function (useCase, slot) {
    const held = pki.certificateFor(REALM, useCase, slot);
    out[useCase + ':' + slot] = held
      ? { serial: held.serialHex, thumbprint: held.thumbprint }
      : null;
  };
  add('jose', 'RS256');
  add('xml', 'RS256');
  (keys.extraKeys || []).forEach(function (one) {
    const jwk = one.publicJwk || {};
    add('jose', jwk.crv ? one.alg + ':' + jwk.crv : one.alg);
  });
  log.debug("Leaving classicalSlots(). " + Object.keys(out).length + ".");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  await keystore.start();
  const started = await pki.start({ realmIds: [] });
  t.check(started.ok, 'pki.start() builds the tree', JSON.stringify(started));

  let keys = helpers.stsKeysFor.of(REALM);
  const first = await pki.certifyKeySet(REALM, keys);
  t.check(first.ok, 'the default realm\'s key set certifies',
          (first.failed || []).join('; '));
  const before = classicalSlots(keys);
  const units = Object.keys(before);
  t.equal(units.length, 2 + (keys.extraKeys || []).length,
          'the RSA key in two slots (JOSE and XML) and one slot per curve key');
  t.check(units.every(function (u) {
    return before[u] && before[u].serial && before[u].thumbprint;
  }), 'and every one of them holds a certificate', JSON.stringify(before));

  t.log.info('=== A. a new generation keeps the certificates of keys that ' +
             'did not change ===');
  // A `next` key for ONE unit, which is what the hourly `signing.rotate`
  // does for a unit that lacks one; `replaceGeneration()` then certifies
  // the set (`certifyLater()`, not awaited), and the call below is that
  // same certification, awaited so the comparison is not a race.
  const curveUnit = helpers.signingUnitsOf(keys).filter(function (u) {
    return u.useCase === 'jose' && u.slot !== 'RS256' &&
           String(u.slot).indexOf(':') > 0;
  })[0];
  t.check(!!curveUnit, 'the set has a curve unit to mint a next key for');
  const minted = await helpers.ensureNextGenerations(REALM,
    { units: [curveUnit.unit] });
  t.check(minted.ok && minted.minted.indexOf(curveUnit.unit) >= 0,
          'a next key is minted for ' + curveUnit.unit + ', moving the set ' +
          'to a new generation', JSON.stringify(minted));
  // The certification replaceGeneration() started, settled first.
  await helpers.prepareKeySet(REALM);
  keys = helpers.stsKeysFor.of(REALM);
  const again = await pki.certifyKeySet(REALM, keys);
  t.check(again.ok, 'the new generation certifies',
          (again.failed || []).join('; '));
  const after = classicalSlots(keys);
  const moved = units.filter(function (u) {
    return !after[u] || after[u].serial !== before[u].serial ||
           after[u].thumbprint !== before[u].thumbprint;
  });
  t.equal(moved.join(', '), '',
          'A1. every RSA and curve certificate is the one it was: same ' +
          'serial, same SHA-256 — a link to it drawn before the new ' +
          'generation still resolves after it. Re-issued: ' +
          moved.join(', '));
  t.equal(again.unchanged, units.length,
          'A2. and certifyKeySet() says it kept all ' + units.length + ' ' +
          '(the count the service log reports)');
  t.log.info('=== B. a revoked certificate over a live key is certified ' +
             'again ===');
  const joseBefore = pki.certificateFor(REALM, 'jose', 'RS256');
  const revoked = revocation.revoke(REALM, 'jose',
    { serialHex: joseBefore.serialHex, reason: 'superseded' });
  t.check(revoked && revoked.ok !== false,
          'the RS256 key\'s JOSE certificate is revoked',
          JSON.stringify(revoked && revoked.errors));
  const third = await pki.certifyKeySet(REALM, keys);
  t.check(third.ok, 'the set certifies after the revocation',
          (third.failed || []).join('; '));
  const joseAfter = pki.certificateFor(REALM, 'jose', 'RS256');
  t.check(!!joseAfter && joseAfter.serialHex !== joseBefore.serialHex,
          'B1. the revoked certificate is replaced: the key still signs, so ' +
          'it is certified from the live authority again',
          JSON.stringify({ before: joseBefore.serialHex,
                           after: joseAfter && joseAfter.serialHex }));
  t.equal(third.unchanged, units.length - 1,
          'B2. and only that one: every other RSA and curve certificate is ' +
          'kept');

  t.log.info('=== C. a reissued Issuing CA re-certifies what it signed ===');
  const xmlBefore = pki.certificateFor(REALM, 'xml', 'RS256');
  const reissued = await pki.reissueUseCase(REALM, 'jose');
  t.check(reissued.ok, 'the JOSE Issuing CA is reissued',
          (reissued.errors || []).join(' '));
  const fourth = await pki.certifyKeySet(REALM, helpers.stsKeysFor.of(REALM));
  t.check(fourth.ok, 'the set certifies under the reissued authority',
          (fourth.failed || []).join('; '));
  const issuingNow = pki.describeTree([REALM]).scopes.filter(function (s) {
    return s.kind !== 'process';
  })[0].issuing.filter(function (uc) {
    return uc.id === 'jose';
  })[0].ca.certificatePem;
  const joseSlots = units.filter(function (u) {
    return u.indexOf('jose:') === 0;
  });
  const stale = joseSlots.filter(function (u) {
    const slot = u.slice('jose:'.length);
    const held = pki.certificateFor(REALM, 'jose', slot);
    return !held || (held.chainPem || [])[0] !== issuingNow;
  });
  t.equal(stale.join(', '), '',
          'C1. every JOSE certificate chains to the reissued Issuing CA — ' +
          'none was kept over the authority it replaced. Stale: ' +
          stale.join(', '));
  const xmlAfter = pki.certificateFor(REALM, 'xml', 'RS256');
  t.equal(xmlAfter && xmlAfter.serialHex, xmlBefore.serialHex,
          'C2. while the XML certificate, under an authority nobody ' +
          'reissued, is kept');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'signing_certificate_stability',
  describe: 'A signing key\'s RSA or curve certificate is kept while it is ' +
            'current, so a new key generation (the hourly signing.rotate) ' +
            'does not move the fingerprints the console links; a revoked ' +
            'certificate and a reissued Issuing CA still re-certify',
  run: run
};
