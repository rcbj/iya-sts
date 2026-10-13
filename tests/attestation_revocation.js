// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: attestation_revocation.js
//
// ===========================================================================
// GOOGLE'S ANDROID ATTESTATION STATUS LIST (#256), in process: the list as a
// risk dataset and the consultation, with a synthetic list built here.
//
// `common/attestation_revocation.ts` and `risk/risk_datasets.ts` argue the
// design. What is held here (the verifiers' own cases are in
// `tests/device_enrolment.js` section 3 and `tests/webauthn_attestation.js`):
//
//   A. THE FORMAT: a list's entries become rows keyed by the serial in
//      lower-case hexadecimal with no leading zeros, however it was written;
//      only REVOKED and SUSPENDED count; a document that is not a list is
//      refused (STS-RISK-0045) and nothing is loaded.
//   B. THE IMPORT: the provider needs no terms acceptance; the list is
//      active at once, a second identical one is a duplicate, and a newer
//      one replaces it (the latest only).
//   C. THE LOOKUP: a listed serial is a hit with its status and reason; no
//      list and a stale list are `checked: false` with why.
//   D. THE CONSULTATION: `consult()` over a real certificate reads its
//      serial through `pki.certificateSerialHex()`; `untrusts()` is true for
//      revoked and suspended, false for good, and for unchecked only in
//      product with devices.androidRevocationRequired.
//   E. THE DOWNLOAD: the refresh job's work fetches through
//      `federation_http.fetchPublished()` (stubbed) and imports; an empty
//      address dials nobody.
//   F. THE RECHECK'S WEBAUTHN HALF (the device half is
//      `tests/device_enrolment.js` 3i): a stored credential the list now
//      revokes is made untrusted and CAEP credential-change (`update`) is
//      sent; a good one and an unchecked one are left alone.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const pki = require('../common/pki');
const datasets = require('../risk/risk_datasets');
const revocation = require('../common/attestation_revocation');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'attestation_revocation',
  level: process.env.LOG_LEVEL || 'info' });

const DATASET = 'android.attestation-status';
const FORMAT = 'android-attestation-status-json';

function list(entries) {
  log.debug('Entering list().');
  log.debug('Leaving list().');
  return JSON.stringify({ entries: entries });
}

async function load(content) {
  log.debug('Entering load().');
  const out = await datasets.importVersion({ dataset: DATASET, format: FORMAT,
    content: content, source: 'upload', actor: 'the test' });
  log.debug('Leaving load().');
  return out;
}

async function withSettings(pairs, fn) {
  log.debug('Entering withSettings().');
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug('Leaving withSettings().');
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

module.exports = {
  name: 'attestation revocation',
  describe: 'Google\'s Android attestation status list (#256): the format, ' +
            'the import, the lookup, the consultation, the download and the ' +
            'recheck',
  run: async function (t) {
    log.debug('Entering run().');

    // A. THE FORMAT.
    t.check(datasets.androidSerialKey('00AB:CD') === 'abcd' &&
            datasets.androidSerialKey('0x000f') === 'f' &&
            datasets.androidSerialKey('0') === '0' &&
            datasets.androidSerialKey('not hex') === '',
            'A1. a serial is lower-case hex with no leading zeros or ' +
            'separators');
    const rows = datasets.androidStatusRowsOf({ entries: {
      '00C35747A084470C3135AEEFE2B8D40CD6': { status: 'REVOKED',
                                             reason: 'KEY_COMPROMISE' },
      'aa': { status: 'SUSPENDED', reason: 'SOFTWARE_FLAW' },
      'bb': { status: 'SOMETHING-ELSE' } } });
    t.check(rows.length === 2 &&
            rows[0].key === 'c35747a084470c3135aeefe2b8d40cd6' &&
            rows[0].latestStatus === 'REVOKED' && rows[0].compromised &&
            rows[1].latestStatus === 'SUSPENDED' && !rows[1].compromised,
            'A2. REVOKED and SUSPENDED become rows; a key compromise is ' +
            'marked; anything else is not a row', JSON.stringify(rows));
    t.check(datasets.androidStatusRowsOf([]) === null &&
            datasets.androidStatusRowsOf({ entries: [] }) === null,
            'A3. a document that is not an object of entries is not a list');

    // C (before any list). No list.
    const before = await datasets.lookupAttestationSerials(['aa']);
    t.check(before.checked === false && /no Android/.test(before.why),
            'C1. with no list nothing is checked, and it says so',
            JSON.stringify(before));

    const refused = await load('this is not json');
    t.equal(errorCodes.codeOf(refused), 'STS-RISK-0045',
            'A4. a document that is not the list is refused, nothing loaded');

    // B. THE IMPORT.
    const first = await load(list({ aa: { status: 'REVOKED',
                                         reason: 'CA_COMPROMISE' } }));
    t.check(first.ok && first.activated && first.rows === 1,
            'B1. a list loads and is active at once, with no terms to ' +
            'accept', JSON.stringify(first));
    const again = await load(list({ aa: { status: 'REVOKED',
                                         reason: 'CA_COMPROMISE' } }));
    t.check(again.ok && again.duplicate === true,
            'B2. the same list again is a duplicate, and loads nothing');

    // C. THE LOOKUP.
    const hit = await datasets.lookupAttestationSerials(['00AA', 'bb']);
    t.check(hit.checked && hit.hits.length === 1 &&
            hit.hits[0].serial === 'aa' && hit.hits[0].status === 'REVOKED' &&
            hit.hits[0].reason === 'CA_COMPROMISE',
            'C2. a listed serial is a hit, however it is written; an ' +
            'unlisted one is not', JSON.stringify(hit));
    await withSettings({ 'devices.androidStatusStaleHours': 1 },
      async function () {
        const stale = new datasets.RiskDatasets(Object.assign(
          datasets.RiskDatasets.defaultDeps(), {
            now: function () {
              return Date.now() + 2 * 3600 * 1000;
            } }));
        const old = await stale.lookupAttestationSerials(['aa']);
        t.check(old.checked === false && /stale/.test(old.why),
                'C3. a stale list checks nothing, and says so',
                JSON.stringify(old));
      });
    const second = await load(list({ cc: { status: 'SUSPENDED' } }));
    const replaced = await datasets.lookupAttestationSerials(['aa', 'cc']);
    t.check(second.ok && second.activated && replaced.hits.length === 1 &&
            replaced.hits[0].serial === 'cc',
            'B3. a newer list replaces the old one: the latest only',
            JSON.stringify(replaced));

    // D. THE CONSULTATION, over a real certificate.
    const root = await kit.root('Synthetic Android', 'ec');
    const serial = pki.certificateSerialHex(root.der);
    t.check(/^[0-9a-f]+$/.test(serial) && !/^0/.test(serial),
            'D1. pki reads a certificate\'s serial as the list keys it');
    await load(list((function () {
      const e = {};
      e[serial.toUpperCase()] = { status: 'REVOKED',
                                  reason: 'KEY_COMPROMISE' };
      return e;
    }())));
    const verdict = await revocation.consult([root.der]);
    t.check(verdict.status === 'revoked' && verdict.serial === serial &&
            verdict.reason === 'KEY_COMPROMISE' &&
            verdict.chainSerials[0] === serial && revocation.untrusts(verdict),
            'D2. a chain with a listed certificate is revoked, and untrusted',
            JSON.stringify(verdict));
    const other = await kit.root('Synthetic Other', 'ec');
    const good = await revocation.consult([other.der.toString('base64')]);
    t.check(good.status === 'good' && !revocation.untrusts(good),
            'D3. a chain with none listed is good, from base64 DER too');
    const unchecked = { status: 'unchecked', why: 'no list' };
    t.check(!revocation.untrusts(unchecked),
            'D4. unchecked is trusted by default (decision 1)');
    await withSettings({ 'global.mode': 'product',
                         'devices.androidRevocationRequired': true },
      function () {
        t.check(revocation.untrusts(unchecked),
                'D5. and untrusted in product with ' +
                'devices.androidRevocationRequired');
      });
    await withSettings({ 'devices.androidRevocationRequired': true },
      function () {
        t.check(!revocation.untrusts(unchecked),
                'D6. but never in development, whatever the setting');
      });

    // E. THE DOWNLOAD.
    await withSettings({ 'devices.androidStatusUrl': '' }, async function () {
      const none = await datasets.refreshAndroidStatus();
      t.check(none.fetched === false && /empty/.test(none.why),
              'E1. an empty address dials nobody');
    });
    const asked = [];
    const fetcher = new datasets.RiskDatasets(Object.assign(
      datasets.RiskDatasets.defaultDeps(), {
        federationHttp: function () {
          return { fetchPublished: function (url, opts) {
            asked.push({ url: url, opts: opts });
            return Promise.resolve({ ok: true, status: 200,
              body: Buffer.from(list({ dd: { status: 'REVOKED' } })) });
          } };
        } }));
    const fetched = await fetcher.refreshAndroidStatus();
    t.check(fetched.fetched && fetched.imported && asked.length === 1 &&
            asked[0].url === 'https://android.googleapis.com/attestation/' +
                              'status' &&
            asked[0].opts.maxBytes ===
              Number(config.value('devices.androidStatusMaxBytes')),
            'E2. the job fetches Google\'s address through fetchPublished(), ' +
            'with its cap, and imports what it got', JSON.stringify(fetched));

    // F. THE RECHECK'S WEBAUTHN HALF, over stubs.
    await load(list({ ee: { status: 'REVOKED', reason: 'KEY_COMPROMISE' } }));
    const untrusted = [];
    const said = [];
    const deps = Object.assign(
      revocation.AttestationRevocation.defaultDeps(), {
        devices: function () {
          return { androidAttestedKeys: function () {
            return [];
          } };
        },
        credentials: function () {
          return {
            androidAttestedCredentials: function () {
              return [{ username: 'ar-alice', credentialId: 'cred-revoked',
                        chainSerials: ['00EE'] },
                      { username: 'ar-alice', credentialId: 'cred-good',
                        chainSerials: ['ff'] }];
            },
            untrustKeyAttestation: function (user, id, verdict) {
              untrusted.push({ user: user, id: id, verdict: verdict });
              return true;
            }
          };
        },
        accountSignals: function () {
          return { credentialChanged: function (change) {
            said.push(change);
            return Promise.resolve({ sent: 0 });
          } };
        }
      });
    const rechecker = new revocation.AttestationRevocation(deps);
    const counts = await rechecker.recheckAll();
    t.check(counts.checked >= 2 && untrusted.length === counts.realms &&
            untrusted.every(function (one) {
              return one.id === 'cred-revoked' &&
                     one.verdict.status === 'revoked';
            }) && said.length === untrusted.length &&
            said[0].changeType === 'update' &&
            said[0].initiatingEntity === 'system',
            'F1. a stored credential the list revokes is made untrusted, ' +
            'with CAEP credential-change update; a good one is left alone',
            JSON.stringify({ counts: counts, untrusted: untrusted.length,
                             said: said.length }));
    log.debug('Leaving run().');
  }
};
