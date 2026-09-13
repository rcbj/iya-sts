'use strict';
//
// File: pki_defaults.js
//
// ===========================================================================
// THE CERTIFICATE AUTHORITY'S DEFAULTS, READ BY EVERY BUILD AND NOT ONLY BY
// THE FORM (2026-09-12).
//
// An audit for hard-coded values found four places `common/pki.js` decided
// something a setting claimed to decide:
//
//   1. `pki.signatureAlgorithm` was honoured by the console's Build form, which
//      reads it itself, and by NOTHING ELSE — the startup auto-build, a realm
//      created at runtime and the repair `certify()` makes on a stale branch
//      all passed `{}` and got the per-key default;
//   2. `issueSigningKeyPair()` defaulted a leaf to the literal 365 days while
//      `certify()` beside it read `pki.leafLifetimeDays`, so the setting
//      described as "the default lifetime of an issued key pair" governed
//      every issued key pair except the ones it was written for;
//   3. the three CA tiers' lifetimes could be given on the form and nowhere
//      else — and the Root's could not be given on the form either, because
//      `buildRoot()` was handed the `{ root, intermediate, issuing }` object
//      and did `Number(object)`;
//   4. a full workbench store DISCARDED ITS OLDEST OBJECT, private key and all,
//      to make room for the one being issued.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS.
//
// Three of the four are about what a build does when NOBODY NAMED A VALUE, and
// the builds that name none are the ones no request drives: the auto-build
// runs before the listener binds, and the drift repair needs a Root replaced
// without its branches, which `pki_anchor_drift.js` records only a caller
// inside the process can arrange. The fourth needs a store at its cap, which
// over HTTP is two hundred issued certificates to prove one refusal.
//
// All four were at their defaults in every stack, which is why nothing
// noticed: 365 is 365, `""` is the per-key default, 0 years is the profile,
// and nobody had ever issued two hundred objects in one realm.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const pki = require('../common/pki');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pki_defaults',
  level: process.env.LOG_LEVEL || 'info' });

// A scope per section, so no section passes because of what another built.
const SIG_SCOPE = 'pki-defaults-sig';
const YEARS_SCOPE = 'pki-defaults-years';
const LEAF_SCOPE = 'pki-defaults-leaf';
const STORE_SCOPE = 'pki-defaults-store';

// Set, run, and put back whatever happens — a setting left behind is the next
// file's starting state (tests/CLAUDE.md).
async function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function yearsOf(tier) {
  log.debug("Entering yearsOf().");
  log.debug("Leaving yearsOf().");
  return new Date(tier.notAfter).getUTCFullYear() -
         new Date(tier.notBefore).getUTCFullYear();
}

async function run(t) {
  log.debug("Entering run().");
  // -----------------------------------------------------------------------
  t.log.info('=== 1. pki.signatureAlgorithm is the default of every build ===');
  await withSettings({ 'pki.signatureAlgorithm': 'sha384-rsa' },
                     async function () {
    const built = await pki.buildScope(SIG_SCOPE, {});
    t.check(built.ok, 'a branch is built with no algorithms named at all — ' +
            'the shape of the auto-build and the drift repair',
            (built.errors || []).join(' '));
    const described = built.chain && built.chain.tiers && built.chain.tiers[1];
    t.equal(described && described.signatureAlg, 'sha384-rsa',
            'and its Intermediate is signed with the SETTING\'s algorithm ' +
            'rather than the per-key default — which is what the auto-build ' +
            'and the drift repair got before, silently');
    const issuing = built.chain && built.chain.tiers &&
                    built.chain.tiers[built.chain.tiers.length - 1];
    t.equal(issuing && issuing.signatureAlg, 'sha384-rsa',
            'and so is the Issuing CA under it');

    // The setting names an RSA digest. A build that names an EC key must still
    // BUILD — the SPIFFE use case prefers EC in every realm — so a configured
    // value the key cannot produce is skipped rather than refused.
    const ec = await pki.buildScope(SIG_SCOPE + '-ec', { keyAlg: 'ec-p256' });
    t.check(ec.ok, 'an EC build is not refused because the default names an ' +
            'RSA digest — the setting is a default and not a constraint',
            (ec.errors || []).join(' '));
    const ecIssuing = ec.chain && ec.chain.tiers &&
                      ec.chain.tiers[ec.chain.tiers.length - 1];
    t.check(ecIssuing && /ecdsa/.test(String(ecIssuing.signatureAlg)),
            'and its tiers sign with an ECDSA digest',
            ecIssuing && ecIssuing.signatureAlg);

    // A CALLER naming the impossible pair is still refused: that is somebody
    // asking for it rather than a default not fitting.
    const bad = await pki.buildScope(SIG_SCOPE + '-bad',
                                     { keyAlg: 'ec-p256',
                                       signatureAlg: 'sha256-rsa' });
    t.check(!bad.ok && /cannot produce/.test((bad.errors || []).join(' ')),
            'while a caller that NAMES a mismatched pair is refused by name',
            (bad.errors || []).join(' '));
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 2. the tiers\' lifetimes, with no form ===');
  t.equal(pki.tierYearsFrom({ root: 3, intermediate: 2 }, 'root'), 3,
          'the Root\'s member of the form\'s object is read — it was NaN');
  t.equal(pki.tierYearsFrom({ root: 3, intermediate: 2 }, 'intermediate'), 2,
          'and the Intermediate\'s');
  t.equal(pki.tierYearsFrom(30, 'root'), 30,
          'a bare number, which is what build-root passes, is the Root\'s');
  t.equal(pki.tierYearsFrom(30, 'issuing'), 0,
          'and is NOT spread onto the other tiers of a branch');
  await withSettings({ 'pki.issuingLifetimeYears': 2,
                       'pki.intermediateLifetimeYears': 4 }, async function () {
    t.equal(pki.tierYearsFrom(undefined, 'issuing'), 2,
            'with nothing asked for, pki.issuingLifetimeYears is the answer');
    const built = await pki.buildScope(YEARS_SCOPE, {});
    t.check(built.ok, 'a branch is built with no years named',
            (built.errors || []).join(' '));
    const tiers = (built.chain && built.chain.tiers) || [];
    t.equal(tiers[1] && yearsOf(tiers[1]), 4,
            'its Intermediate lives pki.intermediateLifetimeYears');
    t.equal(tiers[2] && yearsOf(tiers[2]), 2,
            'and its Issuing CA pki.issuingLifetimeYears — which the startup ' +
            'build and a realm created at runtime could not be told before');
  });
  t.equal(pki.tierYearsFrom(undefined, 'issuing'), 0,
          'and cleared, zero — which issueCaTier() reads as the profile\'s ' +
          'own');

  // -----------------------------------------------------------------------
  t.log.info('=== 3. an issued key pair lives pki.leafLifetimeDays ===');
  const leafChain = await pki.buildChain(LEAF_SCOPE, {});
  t.check(leafChain.ok, 'a branch to issue from',
          (leafChain.errors || []).join(' '));
  await withSettings({ 'pki.leafLifetimeDays': 30 }, async function () {
    const issued = await pki.issueSigningKeyPair(LEAF_SCOPE,
                                                 { identifier:
                                                     'defaults-probe' });
    t.check(issued.ok, 'a key pair is issued with no lifetime named',
            (issued.errors || []).join(' '));
    const record = issued.issued || {};
    const days = Math.round((new Date(record.notAfter).getTime() -
                             new Date(record.notBefore).getTime()) / 86400000);
    t.equal(days, 30, 'and it lives the SETTING\'s thirty days, not the ' +
            'literal 365 this door defaulted to');
    const cert = new nodeCrypto.X509Certificate(record.certificatePem);
    t.check(Math.abs(new Date(cert.validTo).getTime() -
                     new Date(record.notAfter).getTime()) < 2000,
            'and the certificate itself says so, not only the record',
            cert.validTo);
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 4. a full store refuses rather than evicting ===');
  await withSettings({ 'pki.maxStoredObjects': 2 }, async function () {
    t.equal(pki.MAX_OBJECTS, 2,
            'pki.MAX_OBJECTS reads the setting, so the pane draws the live ' +
            'cap');
    const first = pki.putObject(STORE_SCOPE,
                                { id: 'obj-1', privateKeyPem: 'k1' });
    const second = pki.putObject(STORE_SCOPE,
                                 { id: 'obj-2', privateKeyPem: 'k2' });
    t.check(first.ok && second.ok, 'two objects fit in a store of two');
    t.equal(pki.roomForObject(STORE_SCOPE, 'obj-3'), false,
            'and roomForObject() says a third will not, before anybody ' +
            'spends a key generation finding out');
    t.equal(pki.roomForObject(STORE_SCOPE, 'obj-2'), true,
            'while it says there IS room to replace one already held — a ' +
            'mutant answering on the count alone survived until this line');
    const third = pki.putObject(STORE_SCOPE,
                                { id: 'obj-3', privateKeyPem: 'k3' });
    t.check(!third.ok && third.full,
            'the third is REFUSED', (third.errors || []).join(' '));
    t.check(/pki\.maxStoredObjects/.test((third.errors || []).join(' ')),
            'with a sentence naming the setting and what to do');
    const held = pki.objects(STORE_SCOPE)
                    .map(function (one) { return one.id; });
    t.equal(held.join(','), 'obj-1,obj-2',
            'and the OLDEST IS STILL THERE — it used to be discarded, ' +
            'private key and all, for an object somebody else was issuing');
    t.equal(pki.objectFor(STORE_SCOPE, 'obj-1').privateKeyPem, 'k1',
            'with its private key untouched');
    const replaced = pki.putObject(STORE_SCOPE,
                                   { id: 'obj-2', privateKeyPem: 'k2b' });
    t.check(replaced.ok &&
            pki.objectFor(STORE_SCOPE, 'obj-2').privateKeyPem === 'k2b',
            'while REPLACING an object already held is never refused — it ' +
            'does not grow the row');
    // AND THE WORKBENCH'S OWN DOOR SAYS SO. `pki_authoring.issue()` did not
    // read `putObject()`'s answer, so issuing into a full store drew "Issued"
    // over an object that was never stored. It asks before generating a key.
    const authoring = require('../common/pki_authoring');
    const refused = await authoring.issue(STORE_SCOPE,
      { pki_dn_cn: 'full.store.test' });
    t.check(refused && refused.ok === false,
            'pki_authoring.issue() into a full store is REFUSED rather than ' +
            'reporting an issue that stored nothing',
            JSON.stringify((refused && refused.errors) || refused));
    t.check(/pki\.maxStoredObjects/.test(((refused &&
                                           refused.errors) || []).join(' ')),
            'and its sentence names the setting');
    pki.removeObject(STORE_SCOPE, 'obj-1');
    pki.removeObject(STORE_SCOPE, 'obj-2');
  });
  t.equal(pki.MAX_OBJECTS, 200, 'and cleared, the cap is the old constant');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_defaults',
  describe: 'the CA\'s settings are the defaults of EVERY build — the ' +
            'signature algorithm, the three tier lifetimes and an issued ' +
            'leaf\'s — and a full workbench store refuses rather than ' +
            'discarding a private key somebody kept',
  run: run
};
