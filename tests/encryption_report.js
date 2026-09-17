'use strict';
//
// File: encryption_report.js
//
// ===========================================================================
// WHAT THIS SERVICE ENCRYPTS AT REST, AND THE COUNTERS UNDER IT (2026-09-11).
//
// `/admin/encryption` is a page and this is not a test of a page. It is a test
// of the two things behind it that nothing else in this repository can check:
//
//   * **THE TABLE AND THE CALL SITES AGREE.** The page describes each class
//     of sealed data by a LABEL (`admin-ui/encryption_admin.ts`'s
//     `DATA_CLASSES`), and the labels are passed by call sites in several
//     different modules. A class described here and never sealed
//     is a row about something that does not happen; a label passed by a call
//     site with no row is a class of data the page silently does not mention.
//     **Neither is an error anywhere** — the page renders perfectly in both
//     cases — which is exactly the argument `tests/pki_authoring.js` makes
//     about a field parsed and never drawn, one layer along.
//   * **THE COUNTERS COUNT.** They are taken at the one funnel both operations
//     pass through rather than at the call sites, and the whole reason for
//     that is a total assembled from call sites is wrong the first time
//     somebody adds another one and is wrong SILENTLY.
//
// **THE NEGATIVES ARE THE VALUABLE HALF HERE TOO.** A report that says
// AES-256-GCM is a report; a report that cannot be caught reporting a
// decryption that failed as one that succeeded, or reporting `sealed` on a
// service whose key dies with the process, is a report somebody can act on.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives.
delete process.env.CONFIG_FILE;

const crypto = require('../common/crypto');
const encryption = require('../admin-ui/encryption_admin');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'encryption_report',
  level: process.env.LOG_LEVEL || 'info' });

const KEK = 'a'.repeat(64);
const OTHER_KEK = 'b'.repeat(64);

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. the algorithm is READ from the module that performs it ' +
             '===');

  const params = crypto.KEK_PARAMETERS;
  t.equal(params.cipher, 'aes-256-gcm',
          'AES-256-GCM and deliberately not CBC: GCM is AUTHENTICATED, so a ' +
          'ciphertext somebody altered fails to decrypt instead of yielding ' +
          'a subtly different key — and a signing key that decrypted to the ' +
          'wrong bytes would produce signatures nothing can verify, ' +
          'surfacing at somebody else\'s relying party as "the signature is ' +
          'invalid"');
  t.equal(params.keyBits, 256, 'a 256-bit key');
  t.equal(params.ivBits, 96,
          'a 96-bit nonce, which is NIST SP 800-38D\'s recommended GCM length');
  t.equal(params.kdf, 'HKDF-SHA256',
          'and a per-record subkey rather than the key-encryption key ' +
          'encrypting anything directly');
  t.check(params.perRecordSubkey === true && params.kdfSaltBits === 128,
          'derived over a random salt per record, so no record\'s IV matters ' +
          'to any other — one key encrypting many records under many IVs is ' +
          'one IV-reuse bug away from catastrophic in GCM');

  const view = encryption.encryptionView();
  t.equal(view.algorithm.cipher, params.cipher,
          'and the REPORT reads that table rather than restating it, which ' +
          'is `/admin/crypto-metadata`\'s rule applied one layer down: an ' +
          'algorithm written down on a page is a page that goes on looking ' +
          'complete while being wrong');

  t.log.info('=== B. the counters count, at the funnel ===');

  const PLAINTEXT = 'a signing key, say';
  const before = crypto.kekAccounting();
  const sealed = crypto.encryptWithKek(KEK, PLAINTEXT, 'probe-a');
  // MEASURED AFTER THE ENCRYPT AND BEFORE THE DECRYPT, on purpose. The
  // decrypt counts the plaintext it produced, so a check made after both
  // passes even when the encrypt counts nothing — which is a mutant that
  // survived the first version of this file.
  const midway = crypto.kekAccounting();
  t.equal(midway.plaintextBytes, before.plaintextBytes +
          Buffer.byteLength(PLAINTEXT, 'utf8'),
          'an encryption counts the plaintext it was given, exactly');
  t.check(midway.ciphertextBytes > before.ciphertextBytes,
          'and the ciphertext it produced');
  const opened = crypto.decryptWithKek(KEK, sealed, 'probe-a');
  t.equal(opened, PLAINTEXT, 'a round trip works');

  const after = crypto.kekAccounting();
  t.equal(after.encryptions, before.encryptions + 1, 'one encryption counted');
  t.equal(after.decryptions, before.decryptions + 1, 'one decryption counted');
  t.equal(after.operations, before.operations + 2,
          'and `operations` is their sum rather than a third counter that ' +
          'could drift from both');
  t.equal(after.plaintextBytes, before.plaintextBytes +
          2 * Buffer.byteLength(PLAINTEXT, 'utf8'),
          'and the decryption counts the plaintext it PRODUCED, so a round ' +
          'trip of one value is counted twice — which is what makes "how ' +
          'much" a different question from "how often"');

  const row = after.labels.filter(function (one) {
    return one.label === 'probe-a';
  })[0];
  t.check(!!row && row.encryptions === 1 && row.decryptions === 1,
          'the LABEL breaks the total down by what kind of data it was, ' +
          'which is the only thing the call site knows and the funnel does not',
          JSON.stringify(row || null));
  t.check(row.lastAt >= row.firstAt && row.firstAt > 0,
          'and each row remembers when it first and last happened');

  // **A CALLER THAT PASSES NO LABEL IS STILL COUNTED**, which is the whole
  // reason the count is taken here rather than at the call sites: a missing
  // label costs a ROW and never a NUMBER.
  const anonymousBefore = crypto.kekAccounting().encryptions;
  crypto.encryptWithKek(KEK, 'no label on this one');
  const anonymousAfter = crypto.kekAccounting();
  t.equal(anonymousAfter.encryptions, anonymousBefore + 1,
          'an operation with no label is counted in the TOTAL');
  t.check(anonymousAfter.labels.some(function (one) {
            return one.label === '(unlabelled)' && one.encryptions >= 1;
          }),
          'and appears under `(unlabelled)` rather than vanishing — so a ' +
          'call site somebody adds without a label is visible on the page ' +
          'instead of quietly making the totals not add up');

  t.log.info('=== C. a failure is its own figure, and it still throws ===');

  const failuresBefore = crypto.kekAccounting().failures;
  let threw = false;
  try {
    crypto.decryptWithKek(OTHER_KEK, sealed, 'probe-a');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw,
          'decrypting under the WRONG key-encryption key THROWS and is not ' +
          'softened into a return. That is the whole point of GCM here: ' +
          '`keystore.js` turns it into a fatal at startup, because a service ' +
          'that cannot read its own signing key must not come up generating ' +
          'a new one and silently invalidating every token it ever issued');
  const failed = crypto.kekAccounting();
  t.equal(failed.failures, failuresBefore + 1,
          'and it is counted — which is the figure an operator who has just ' +
          'rotated a key-encryption key actually wants');
  t.equal(failed.decryptions, anonymousAfter.decryptions,
          'and it is NOT counted as a decryption. Nine hundred decryptions ' +
          'and nine hundred decryptions with four hundred failures are very ' +
          'different reports, and one number could only have told the first');

  let malformedThrew = false;
  try {
    crypto.decryptWithKek(KEK, 'this is not a sealed value at all', 'probe-a');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    malformedThrew = true;
  }
  t.check(malformedThrew, 'a value this service did not write is refused');
  t.equal(crypto.kekAccounting().failures, failuresBefore + 2,
          'and counted as a failure too — a caller cannot tell a bad tag ' +
          'from a bad shape and neither should the figure, which would ' +
          'otherwise be three columns of which two are always zero');

  t.check(crypto.isEncryptedWithKek(sealed) &&
          !crypto.isEncryptedWithKek('-----BEGIN PRIVATE KEY-----'),
          'and a sealed value SAYS SO by its prefix rather than by a marker ' +
          'attribute beside it — which is what stops a value copied from one ' +
          'entry to another being sealed twice, and what lets a value ' +
          'carried between modes be read correctly');

  t.log.info('=== D. the table and the call sites agree ===');

  const classes = encryption.dataClasses();
  const sealedClasses = classes.filter(function (one) { return one.sealed; });
  t.check(sealedClasses.length >= 6,
          'six classes of data are sealed at rest',
          sealedClasses.map(function (one) { return one.label; }).join(', '));
  t.check(sealedClasses.every(function (one) { return !!one.label; }),
          'every sealed class names the LABEL its call sites pass, which is ' +
          'what joins this table to the counters');
  t.check(classes.some(function (one) { return !one.sealed; }),
          'and the table carries the NOT-sealed classes too — the question a ' +
          'reader brings is almost always "is THIS encrypted", and a table ' +
          'of only the yeses answers it by silence');
  classes.filter(function (one) { return !one.sealed; })
    .forEach(function (one) {
      t.check(one.label === null,
              'a class that is not sealed carries NO label, because there is ' +
              'nothing to count for it: null means "nothing here to count" ' +
              'where zero would mean "sealed and not yet used", and one ' +
              'number could only have said the second',
              one.what);
    });

  const labels = sealedClasses.map(function (one) { return one.label; });
  t.equal(labels.length, new Set(labels).size,
          'and no label appears twice — two rows for one label would split ' +
          'one class\'s counts across two lines that both look right');

  // **THE JOIN, IN THE DIRECTION THAT CATCHES A NEW CALL SITE.** Anything the
  // funnel has counted that this table has no row for is reported by the view
  // rather than dropped, so a call site added without a row shows up on the
  // page instead of as totals that do not add up to the rows beneath them.
  const live = encryption.encryptionView();
  t.check(Array.isArray(live.unclassified),
          'the view reports labels it counted and cannot classify');
  crypto.encryptWithKek(KEK, 'x', 'a-label-no-row-describes');
  const drifted = encryption.encryptionView();
  t.check(drifted.unclassified.some(function (one) {
            return one.label === 'a-label-no-row-describes';
          }),
          'and a label with no row really does appear there — which is the ' +
          'check that makes the table self-policing rather than a list ' +
          'somebody has to remember to update',
          JSON.stringify(drifted.unclassified.map(function (one) {
            return one.label;
          })));

  t.log.info('=== E. the report never carries key material ===');

  const serialised = JSON.stringify(drifted);
  t.check(serialised.indexOf('PRIVATE KEY') < 0,
          'no PEM is anywhere in the report');
  t.check(serialised.indexOf(sealed) < 0,
          'and no CIPHERTEXT either. A sealed value is a private key, an ' +
          'authenticator\'s shared secret or somebody\'s recovery codes, and ' +
          'printing either half of one would hand over exactly what the ' +
          'sealing exists to protect');
  t.check(serialised.indexOf(KEK) < 0,
          'and the key-encryption key itself is not in it — `key.where` ' +
          'names the PROVIDER it is read from and never the key');
  t.check(typeof drifted.noSamples === 'string' &&
          drifted.noSamples.length > 60,
          'and the reply SAYS that it carries none, because a machine ' +
          'reading it may be about to go looking for the samples');

  t.log.info('=== F. the two key flags are different questions ===');

  // `present` and `persists` are not the same claim and a report carrying
  // only the first would say "encrypted" about a service whose key dies with
  // the process — which is why every write site tests `keystore.persists()`
  // and not `keystore.sealed()`.
  t.check(typeof drifted.key.present === 'boolean' &&
          typeof drifted.key.persists === 'boolean' &&
          typeof drifted.key.ephemeral === 'boolean',
          'the report answers all three');
  t.check(!drifted.key.persists || drifted.key.present,
          'a key that persists is necessarily present');
  t.equal(drifted.key.ephemeral, drifted.key.present && !drifted.key.persists,
          'and EPHEMERAL is exactly present-but-not-durable, which is what ' +
          'development mode has: a key generated per run so the ' +
          'request-worker pool can share minted rows, and never written ' +
          'down. Sealing a directory attribute under it would be WORSE than ' +
          'the clear — the entry survives a restart in the ldif and postgres ' +
          'stores and the key does not, so the value would come back as ' +
          'permanent garbage');
  t.check(String(drifted.key.note).length > 100,
          'and the report says which of the two states it is in, in words, ' +
          'rather than leaving a reader to infer it from two booleans');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'encryption_report',
  describe: 'What /admin/encryption reports: the algorithm read from the ' +
            'module that performs it, counters taken at the one funnel with ' +
            'an unlabelled row for a caller that names nothing, a failure ' +
            'that is its own figure and still throws, the table checked ' +
            'against the labels the call sites really pass, no key material ' +
            'anywhere in the reply, and present-versus-persists',
  run: run
};
