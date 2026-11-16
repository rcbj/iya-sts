// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pki_rebuild_keeps_revocations.js
//
// ===========================================================================
// A CERTIFICATE AUTHORITY REBUILT DOES NOT UNDO A REVOCATION (2026-11-16).
//
// `pki.recertifyUseCase()` re-mints the certificates an Issuing CA holds in
// its register's SLOTS — a person's or an application's TLS client
// certificate, a message-signing certificate, a pinned pair, the realm's own
// signing-key certificates — from the key each old certificate is over. It
// re-minted EVERY slot, so a certificate somebody had revoked came back
// under a NEW serial, unrevoked, signed by the renewed or replaced authority:
// the holder's revocation was undone by an operator's renewal. The same was
// true of `recertifyOrphanedSlots()`, which a cluster merge calls for a slot
// left under an authority the row no longer holds.
//
// What a rebuild re-mints now is what is still GOOD — not revoked (any
// reason, a hold included) and not expired. Each act is driven here through
// the console's own action (`/admin/pki` and `POST /admin-api/pki/*` are the
// one `pkiAction()`), with a person's revoked certificate and a valid one
// beside it:
//
//   A. RECERTIFY (a renewal): the revoked certificate keeps its record, its
//      serial and its entry — reason and date — and OCSP still answers
//      `revoked` for it; the valid one is re-minted and its old serial is
//      superseded.
//   B. REISSUE (a new key for the Issuing CA): the same, and the old
//      authority is on its Intermediate's list.
//   C. A HOLD AND AN EXPIRED CERTIFICATE are not re-minted either.
//   D. IMPORT: the replaced Issuing CA is superseded at its Intermediate
//      (it was left valid, so a leaf it had signed and somebody revoked
//      chained to a live authority whose revocation answers no responder
//      gave any more), and nothing revoked is re-minted.
//   F. UNDER PARANOID PKI MODE AND HARD-FAIL (after B): the re-minted
//      certificate verifies and is good; the revoked one does not.
//   E. THE MERGE'S ORPHANS: `pki_merge.orphanedSlots()` does not report a
//      revoked or expired slot, and `recertifyOrphanedSlots()` does not
//      re-mint one it is handed.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const pki = require('../common/pki');
const pkiMerge = require('../common/pki_merge');
const keystore = require('../common/keystore');
const realms = require('../common/realms');
const revocation = require('../common/pki_revocation');
const pkiAdmin = require('../admin-ui/pki_admin');
const status = require('../common/revocation_status');
const config = require('../common/config');

const log = require('bunyan').createLogger({
  name: 'pki_rebuild_keeps_revocations',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'rebuild-revoked-' + nodeCrypto.randomBytes(3).toString('hex');
const OTHER = 'rebuild-revoked-b-' + nodeCrypto.randomBytes(3)
  .toString('hex');
const USE = 'tls-client';

let scratch = '';

function keyPem() {
  log.debug("Entering keyPem().");
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  log.debug("Leaving keyPem().");
  return pair.publicKey.export({ type: 'spki', format: 'pem' });
}

function serialOf(text) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return revocation.normalSerial(text);
}

// One person's TLS client certificate, in a slot of its own — what
// `tls_client_certificates.issue()` records through the same `certify()`.
async function issue(who) {
  log.debug("Entering issue(). " + who);
  const slot = 'person:' + who + ':' + nodeCrypto.randomBytes(6)
    .toString('hex');
  const made = await pki.certify(REALM, USE, {
    slot: slot, alg: 'ES256', label: who + ' tls', commonName: who,
    keyAlg: 'p-256', publicKeyPem: keyPem(), profile: 'tls-client',
    keyUsage: ['digitalSignature'],
    extensions: { extKeyUsage: { present: true, critical: false,
                                 usages: ['clientAuth'] } } });
  log.debug("Leaving issue().");
  return { slot: slot, made: made };
}

function recordOf(slot) {
  log.debug("Entering recordOf().");
  log.debug("Leaving recordOf().");
  return (pki.rawRowFor(REALM).certs || {})[USE + ':' + slot] || null;
}

async function act(body) {
  log.debug("Entering act(). " + body.action);
  const answer = await realms.run(realms.get(REALM), function () {
    return pkiAdmin.pkiAction(Object.assign({ scope: REALM }, body));
  });
  log.debug("Leaving act().");
  return answer;
}

// OCSP, through OpenSSL for `tests/pki_revocation.js`'s reason: a request
// pkijs built would be this implementation agreeing with itself. Answers ''
// where the image has no openssl, and the caller says so.
function haveOpenSsl() {
  log.debug("Entering haveOpenSsl().");
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    log.debug("Leaving haveOpenSsl().");
    return true;
  } catch (e) {
    log.debug("Caught in haveOpenSsl(): " + ((e && e.message) || e));
    log.debug("Leaving haveOpenSsl().");
    return false;
  }
}

async function ocspStatus(issuerPem, serialHex) {
  log.debug("Entering ocspStatus().");
  if (!haveOpenSsl()) {
    log.debug("Leaving ocspStatus(). No openssl.");
    return '';
  }
  const issuerFile = path.join(scratch, 'issuer.pem');
  const out = path.join(scratch, 'req.der');
  fs.writeFileSync(issuerFile, issuerPem);
  execFileSync('openssl', ['ocsp', '-no_nonce', '-issuer', issuerFile,
                           '-serial', '0x' + serialHex, '-reqout', out],
               { stdio: 'pipe' });
  const answer = await revocation.answerOcsp(REALM, USE,
                                             fs.readFileSync(out));
  log.debug("Leaving ocspStatus().");
  return ((answer.answers || [])[0] || {}).status || answer.status || '';
}

// The checks every act owes the revoked certificate and the valid one.
async function revokedStaysRevoked(t, label, revoked, entryBefore) {
  log.debug("Entering revokedStaysRevoked(). " + label);
  const now = recordOf(revoked.slot);
  t.check(!!now && serialOf(now.serialHex) ===
          serialOf(revoked.made.record.serialHex) &&
          now.certificatePem === revoked.made.record.certificatePem,
          label + ': THE REVOKED CERTIFICATE IS NOT RE-MINTED — its slot ' +
          'still holds the revoked certificate, under the same serial',
          JSON.stringify(now && { was: revoked.made.record.serialHex,
                                  now: now.serialHex }));
  const entry = revocation.isRevoked(REALM, USE, now.serialHex);
  t.check(!!entry && entry.reason === entryBefore.reason &&
          entry.revokedAt === entryBefore.revokedAt,
          label + ': and its entry is unchanged — the reason and the moment ' +
          'it was revoked', JSON.stringify(entry));
  const valid = pki.certificatesFor(REALM, USE).filter(function (one) {
    return one.slot === revoked.slot &&
      !revocation.isRevoked(REALM, USE, one.serialHex);
  });
  t.equal(valid.length, 0, label + ': nothing valid stands in that slot');
  log.debug("Leaving revokedStaysRevoked().");
}

// --- F. what was re-minted holds under paranoid PKI mode and hard-fail -------
// The re-minted certificate is a fresh leaf of the live authority, so the
// strictest settings this service has accept it; the revoked one, under the
// authority the reissue replaced, is refused by them.
async function underHardFail(t, revokedOne, validOne) {
  log.debug("Entering underHardFail().");
  t.log.info('=== F. paranoid PKI mode and hard-fail revocation ===');
  const keys = ['pki.paranoid', 'pki.revocationCheck'];
  const set = [config.setOverride('pki.paranoid', 'on'),
               config.setOverride('pki.revocationCheck', 'hard-fail')];
  try {
    t.check(set.every(function (one) {
      return one.ok;
    }), 'F: paranoid PKI mode on, revocation hard-fail',
            JSON.stringify(set));
    const good = recordOf(validOne.slot);
    const accepted = await pki.verifyLeaf(REALM, good.certificatePem,
                                          good.chainPem);
    t.check(accepted.ok, 'F: the RE-MINTED certificate verifies to the ' +
            'Root through the realm\'s branch', accepted.why);
    const goodVerdict = status.localVerdictFor({
      leaf: good.certificatePem, chain: good.chainPem, verified: true });
    t.check(!goodVerdict.refused && goodVerdict.status === 'good',
            'F: and the register calls it good under hard-fail',
            goodVerdict.why);
    const bad = recordOf(revokedOne.slot);
    const refused = await pki.verifyLeaf(REALM, bad.certificatePem,
                                         bad.chainPem);
    t.check(!refused.ok, 'F: the REVOKED certificate, left under the ' +
            'replaced authority, does not', refused.why);
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving underHardFail().");
}

async function sections(t) {
  log.debug("Entering sections().");
  const built = await pki.ensureScope(REALM);
  t.check(built.ok, 'the realm has a branch', JSON.stringify(built.errors));

  // --- A. recertify ----------------------------------------------------------
  t.log.info('=== A. a renewal re-mints what is valid and nothing revoked ===');
  const alice = await issue('rk-alice');
  const bob = await issue('rk-bob');
  t.check(alice.made.ok && bob.made.ok, 'alice and bob hold a TLS client ' +
          'certificate each', JSON.stringify([alice.made.errors,
                                              bob.made.errors]));
  const revoked = revocation.revoke(REALM, USE, {
    serialHex: alice.made.record.serialHex, reason: 'keyCompromise',
    subject: alice.made.record.subject, note: 'the test' });
  t.check(revoked.ok, 'alice\'s certificate is revoked (keyCompromise)',
          JSON.stringify(revoked.errors));
  const aliceEntry = revocation.isRevoked(REALM, USE,
                                          alice.made.record.serialHex);
  const bobBefore = recordOf(bob.slot);
  let answer = await act({ action: 'recertify', useCase: USE });
  t.check(answer.ok, 'the recertify action answers ok',
          JSON.stringify(answer.errors || answer.why));
  await revokedStaysRevoked(t, 'A', alice, aliceEntry);
  const bobAfter = recordOf(bob.slot);
  t.check(serialOf(bobAfter.serialHex) !== serialOf(bobBefore.serialHex) &&
          !revocation.isRevoked(REALM, USE, bobAfter.serialHex) &&
          (revocation.isRevoked(REALM, USE, bobBefore.serialHex) || {})
            .reason === 'superseded',
          'A: bob\'s valid certificate IS re-minted, and the one it replaces ' +
          'is superseded', JSON.stringify([bobBefore.serialHex,
                                           bobAfter.serialHex]));
  const issuerPem = pki.rawRowFor(REALM).issuing[USE].certificatePem;
  const status = await ocspStatus(issuerPem,
                                  serialOf(alice.made.record.serialHex));
  if (status) {
    t.equal(status, 'revoked', 'A: the renewed Issuing CA\'s OCSP responder ' +
                               'still answers `revoked` for alice\'s serial');
  } else {
    t.log.info('A: no openssl in this image; the OCSP question is asked of ' +
               'the register alone');
  }

  // --- B. reissue ------------------------------------------------------------
  t.log.info('=== B. a reissue re-mints what is valid and nothing ' +
             'revoked ===');
  const oldCa = pki.rawRowFor(REALM).issuing[USE];
  const bobBeforeReissue = recordOf(bob.slot);
  answer = await act({ action: 'reissue-use-case', useCase: USE });
  t.check(answer.ok, 'the reissue action answers ok',
          JSON.stringify(answer.errors || answer.why));
  await revokedStaysRevoked(t, 'B', alice, aliceEntry);
  const bobReissued = recordOf(bob.slot);
  const newCa = pki.rawRowFor(REALM).issuing[USE];
  t.check(newCa.certificatePem !== oldCa.certificatePem &&
          (bobReissued.chainPem || [])[0] === newCa.certificatePem &&
          serialOf(bobReissued.serialHex) !==
            serialOf(bobBeforeReissue.serialHex),
          'B: bob\'s valid certificate is re-minted from the NEW authority');
  t.check(!!revocation.isRevoked(REALM, 'intermediate', oldCa.serialHex),
          'B: and the old authority is on its Intermediate\'s list, so a ' +
          'leaf it signed chains to a revoked authority');

  await underHardFail(t, alice, bob);

  // --- C. a hold and an expired certificate ----------------------------------
  t.log.info('=== C. a hold and an expired certificate are not re-minted ===');
  const carol = await issue('rk-carol');
  const dave = await issue('rk-dave');
  t.check(carol.made.ok && dave.made.ok, 'carol and dave hold one each');
  const held = revocation.revoke(REALM, USE, {
    serialHex: carol.made.record.serialHex, reason: 'certificateHold' });
  t.check(held.ok, 'carol\'s certificate is put on hold');
  const carolEntry = revocation.isRevoked(REALM, USE,
                                          carol.made.record.serialHex);
  // Expired by hand: a leaf lives at least a day, and the question is what a
  // renewal does with a record whose validity is over.
  const daveRecord = recordOf(dave.slot);
  daveRecord.notAfter = new Date(Date.now() - 60000).toISOString();
  const answerC = await pki.recertifyUseCase(REALM, USE);
  await revokedStaysRevoked(t, 'C (hold)', carol, carolEntry);
  const daveNow = recordOf(dave.slot);
  t.check(serialOf(daveNow.serialHex) ===
            serialOf(dave.made.record.serialHex) &&
          new Date(daveNow.notAfter).getTime() < Date.now(),
          'C: dave\'s EXPIRED certificate is not re-minted either',
          JSON.stringify({ was: dave.made.record.serialHex,
                           now: daveNow.serialHex }));
  const skippedSlots = (answerC.skipped || []).map(function (one) {
    return one.slot;
  });
  t.check(skippedSlots.indexOf(alice.slot) >= 0 &&
          skippedSlots.indexOf(carol.slot) >= 0 &&
          skippedSlots.indexOf(dave.slot) >= 0 &&
          skippedSlots.indexOf(bob.slot) < 0,
          'C: and recertifyUseCase() answers which it left, and why',
          JSON.stringify(answerC.skipped));

  // --- D. import -------------------------------------------------------------
  t.log.info('=== D. an imported Issuing CA supersedes the one it replaces ' +
             '===');
  const otherBuilt = await pki.ensureScope(OTHER);
  t.check(otherBuilt.ok, 'a second realm has a branch to import from');
  const beforeImport = pki.rawRowFor(REALM).issuing[USE];
  const bobBeforeImport = recordOf(bob.slot);
  const theirs = keystore.pkiFor(OTHER).issuing[USE];
  answer = await act({ action: 'import-ca', useCase: USE,
                       certificatePem: theirs.certificatePem,
                       privateKeyPem: theirs.privateKeyPem });
  t.check(answer.ok, 'the import action answers ok',
          JSON.stringify(answer.errors || answer.why));
  await revokedStaysRevoked(t, 'D', alice, aliceEntry);
  t.check((revocation.isRevoked(REALM, 'intermediate',
                                beforeImport.serialHex) || {}).reason ===
            'superseded',
          'D: THE REPLACED ISSUING CA IS SUPERSEDED at its Intermediate — ' +
          'left valid, it went on vouching for alice\'s revoked leaf while ' +
          'no responder this service runs would say so');
  const bobImported = recordOf(bob.slot);
  t.check(serialOf(bobImported.serialHex) !==
            serialOf(bobBeforeImport.serialHex) &&
          (bobImported.chainPem || [])[0] === theirs.certificatePem,
          'D: bob\'s valid certificate is re-minted from the imported CA');

  // --- E. the merge's orphans ------------------------------------------------
  t.log.info('=== E. a merge reports and re-mints no revoked or expired ' +
             'orphan ===');
  const row = pki.rawRowFor(REALM);
  const orphaned = pkiMerge.orphanedSlots(row);
  const aliceKey = USE + ':' + alice.slot;
  const carolKey = USE + ':' + carol.slot;
  const daveKey = USE + ':' + dave.slot;
  t.check(orphaned.indexOf(aliceKey) < 0 && orphaned.indexOf(carolKey) < 0 &&
          orphaned.indexOf(daveKey) < 0,
          'E: orphanedSlots() does not report a revoked, held or expired ' +
          'slot, although each is under an authority the row no longer ' +
          'holds', JSON.stringify(orphaned));
  const again = await pki.recertifyOrphanedSlots(REALM,
                                                 [aliceKey, carolKey,
                                                  daveKey]);
  t.check(again.recertified === 0, 'E: and recertifyOrphanedSlots(), handed ' +
          'them anyway, re-mints none', JSON.stringify(again));
  await revokedStaysRevoked(t, 'E', alice, aliceEntry);
  log.debug("Leaving sections().");
}

async function run(t) {
  log.debug("Entering run().");
  const hadRoot = !!keystore.pkiFor(pki.SERVICE_SCOPE);
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-rebuild-rev-'));
  [REALM, OTHER].forEach(function (id) {
    if (!realms.get(id)) {
      realms.create({ id: id, name: id });
    }
  });
  try {
    await sections(t);
  } finally {
    // Whatever this file made, it removes: `run.js` runs every file in one
    // process, and a Root left behind is the Root `tests/pki.js` meets.
    [REALM, OTHER].forEach(function (id) {
      keystore.attachPki(id, null);
      if (realms.get(id)) {
        realms.remove(id);
      }
    });
    if (!hadRoot && keystore.pkiFor(pki.SERVICE_SCOPE)) {
      keystore.attachPki(pki.SERVICE_SCOPE, null);
    }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_rebuild_keeps_revocations',
  describe: 'A certificate authority renewed, reissued or replaced by an ' +
            'import re-mints only the certificates that are still good: a ' +
            'revoked, held or expired one keeps its serial and its entry, ' +
            'OCSP still answers revoked, an imported Issuing CA supersedes ' +
            'the one it replaces, and a merge neither reports nor re-mints ' +
            'a revoked orphan.',
  run: run
};
