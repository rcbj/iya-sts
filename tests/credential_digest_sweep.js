// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_digest_sweep.js
//
// ===========================================================================
// THE STORES #614'S SWEEP FOUND KEEP DIGESTS, NOT THE VALUES THEY HAND OUT.
//
// Each of these stores is keyed by a value this service gives to a client —
// and only ever looks up, spends or forgets — so it holds
// `credentialDigest(value)` (`common/crypto.js`) and the value itself is in no
// key and no row:
//
//   A. `acme.usedNonces` — a spent Replay-Nonce; spending it twice is still
//      refused.
//   B. `scim.digestNonces` and `scim.hobaChallenges` — the Digest nonce and
//      the HOBA challenge a `WWW-Authenticate` header carries.
//   C. `federation_sp.contexts` — the handle a RelayState, wctx or state
//      carries; `takeContext()` still answers the record with its handle, once.
//   D. `credentials.pendingBackupCodes` — the handle a form confirms a set of
//      recovery codes with; the set is still found and discarded by it.
//
// `spnego.pending` is held by `cluster_limits_challenges_retention.js`
// section D, which restores and reads its rows under the digest; the SAML
// artifact stores by `saml_artifact_digests.js`.
//
// WHY IN PROCESS: what is asserted is the SHAPE of a store's rows, which no
// HTTP client can see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'credential_digest_sweep',
  level: process.env.LOG_LEVEL || 'info' });

// Every key and value of the default realm's partition, as text.
function rowsOf(realms, handle) {
  log.debug("Entering rowsOf().");
  const row = realms.handleFor(handle);
  const out = row ? row.dump(realms.DEFAULT_REALM.id).map(function (r) {
    return { key: String(r.key), text: String(r.key) + ' ' +
                                       JSON.stringify(r.value) };
  }) : [];
  log.debug("Leaving rowsOf().");
  return out;
}

// Whether a store holds `value` under its digest and nowhere in the clear.
function heldAsDigest(stsCrypto, rows, value) {
  log.debug("Entering heldAsDigest().");
  const digest = stsCrypto.credentialDigest(value);
  const keyed = rows.some(function (r) {
    return r.key === digest || r.key.slice(-digest.length) === digest;
  });
  const clear = rows.some(function (r) {
    return r.text.indexOf(value) >= 0;
  });
  log.debug("Leaving heldAsDigest().");
  return keyed && !clear;
}

async function run(t) {
  log.debug("Entering run().");
  const stsCrypto = require('../common/crypto');
  const realms = require('../common/realms');
  require('../ldap/ldap_server');

  // -------------------------------------------------------------------------
  t.log.info('A. acme.usedNonces');
  // -------------------------------------------------------------------------
  const acmeStore = require('../acme/acme_store');
  const nonce = 'sweep-nonce-' + stsCrypto.randomBytes(12).toString('hex');
  const nowS = Math.floor(Date.now() / 1000);
  const first = acmeStore.spendNonce(nonce, nowS + 60);
  const second = acmeStore.spendNonce(nonce, nowS + 60);
  t.check(first === true && second === false,
          'a Replay-Nonce is spent once, and the second spend is refused');
  t.check(heldAsDigest(stsCrypto, rowsOf(realms, 'acme.usedNonces'), nonce),
          'the spent nonce is held under its digest, and in no row in the ' +
          'clear');

  // -------------------------------------------------------------------------
  t.log.info('B. the SCIM Digest nonce and HOBA challenge');
  // -------------------------------------------------------------------------
  const scimAuth = require('../scim/scim_auth');
  const headers = [].concat(scimAuth.challenges({
    headers: {}, method: 'GET', originalUrl: '/scim/v2/Users' }) || []);
  const all = headers.join('\n');
  const digestNonce = (/Digest [^\n]*?nonce="([^"]+)"/.exec(all) || [])[1];
  const hobaChallenge = (/HOBA challenge="([^"]+)"/.exec(all) || [])[1];
  t.check(!!digestNonce && heldAsDigest(stsCrypto,
            rowsOf(realms, 'scim.digestNonces'), digestNonce),
          'the Digest nonce on the challenge is held under its digest only',
          String(digestNonce));
  t.check(!!hobaChallenge && heldAsDigest(stsCrypto,
            rowsOf(realms, 'scim.hobaChallenges'), hobaChallenge),
          'the HOBA challenge on the header is held under its digest only',
          String(hobaChallenge));

  // -------------------------------------------------------------------------
  t.log.info('C. federation_sp.contexts');
  // -------------------------------------------------------------------------
  const fedSp = require('../federation/federation_sp');
  const handle = fedSp.putContext({ kind: 'sweep-test', id: 'sweep',
                                    returnTo: '/after' });
  t.check(/^fed-/.test(handle) &&
          heldAsDigest(stsCrypto, rowsOf(realms, 'federation_sp.contexts'),
                       handle),
          'a flow\'s context is held under its handle\'s digest, and the ' +
          'handle is in no row', handle);
  const taken = fedSp.takeContext(handle);
  t.check(taken && taken.handle === handle && taken.kind === 'sweep-test' &&
          taken.returnTo === '/after',
          'takeContext() answers the record with the handle it was asked for');
  t.check(fedSp.takeContext(handle) === null,
          'and spends it: a second take finds nothing');

  // -------------------------------------------------------------------------
  t.log.info('D. credentials.pendingBackupCodes');
  // -------------------------------------------------------------------------
  const credentials = require('../common/credentials');
  const begun = credentials.beginBackupCodes('alice');
  if (!begun || !begun.ok) {
    // No directory with a backup-code store in this process: nothing to
    // hold, and saying so rather than passing.
    t.check(false, 'a set of recovery codes can be begun for alice',
            JSON.stringify(begun));
  } else {
    t.check(heldAsDigest(stsCrypto,
              rowsOf(realms, 'credentials.pendingBackupCodes'), begun.handle),
            'a pending set is held under its handle\'s digest, and the ' +
            'handle is in no row');
    t.check(!!credentials.pendingBackupCodesFor('alice', begun.handle),
            'the form\'s handle still finds the pending set');
    const gone = credentials.discardBackupCodes('alice', begun.handle);
    t.check(gone && gone.discarded === true &&
            !credentials.pendingBackupCodesFor('alice', begun.handle),
            'and discards it');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential_digest_sweep',
  describe: 'the stores #614\'s sweep found keep digests of the nonces, ' +
            'challenges and handles they hand out',
  run: run
};
