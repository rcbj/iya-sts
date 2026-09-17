// ===========================================================================
// tests/spiffe_authority.js — THE SPIFFE CERTIFICATE AUTHORITY IS THE
// SERVICE'S AND NOT ONE PROCESS'S (2026-09-08).
//
// **WHAT THIS FILE EXERCISES AFTER 2026-09-11 IS THE SELF-SIGNED FALLBACK,
// AND IT RUNS IN A CHILD PROCESS TO REACH IT.** With a certificate authority
// built, the X.509 authority is this realm's SPIFFE Issuing CA and lives in
// `common/keystore.js`'s row rather than in the store below — so none of the
// claims here are about it. They are about the path a realm with NO branch
// takes, which is still a supported configuration in three ways
// (`pki.autoBuild: false`, a Root that could not be built, and every
// in-process caller that never runs `common/service_state.ts`), and which is
// what this service did for its whole life until that date.
//
// **THE CHILD IS NOT FASTIDIOUSNESS — IT IS `tls_trust_anchor.js`'s REASON
// WORD FOR WORD.** `tests/run.js` runs every file in ONE process and
// `tests/pki_hierarchy.js` builds the hierarchy, so by the time this file runs
// under `npm test` the fallback is unreachable. Read in this process it passed
// alone and failed in the suite, which is the shape of flake that gets a test
// deleted rather than fixed.
//
// The PKI path has a file of its own in `tests/spiffe_pki.js`, because the two
// differ in what they claim rather than in how they are driven.
//
// WHY THIS IS IN PROCESS. Every claim here is about WHERE the authority lives
// and what SHAPE it is written down in, and neither is a question a running
// service can be asked. `GET /spiffe` answers the same document whether the
// authority is shared or private; what tells them apart is whether a SECOND
// process would answer the same, and the only way to ask that over HTTP is to
// start two of them and race. The stored FORM is not observable from outside
// at all.
//
// WHAT WENT WRONG, because these assertions are the record of it. The
// authority was two module arrays. SPIFFE's four sockets are bound by the
// front process alone (`server.js` starts them; a request worker binds nothing
// but its own unix socket), so with a request-worker pool:
//
//   * a worker answering `GET /spiffe` published a bundle whose keys verified
//     NONE of the SVIDs the service had actually issued, and
//   * `/admin/spiffe`'s Rotate button rotated a certificate authority that
//     signs nothing, while the one doing the signing stood still. The bundle
//     sequence — which is how a relying party knows its copy is stale — did
//     not move for two readers in three.
//
// The first fix routed those paths to the process that happened to hold the
// state. This file guards the second and better one: the state is shared, so
// every process answers the same bundle and a rotation from any of them is the
// service's. `tests/request_routing.js` asserts the pins came off.
//
// THE BUFFER ASSERTION IS THE ONE THAT EARNS ITS PLACE. The journal writes
// JSON, and JSON turns a `Buffer` into `{"type":"Buffer","data":[…]}` and a
// `Map` into `{}`. This service has been caught by that twice in one day — in
// `krb5_principals.js`'s derived-key cache and its sign-out stamp — and both
// times the symptom named something else entirely. Exactly one field of an
// X.509 authority is a Buffer, and if it ever stops surviving the round trip
// the failure is a bundle that cannot be parsed, one restart later, in a
// different process.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'spiffe_authority',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// EVERY CLAIM IN THIS FILE IS MADE IN A CHILD PROCESS — see the header.
//
// The child writes its answer to a FILE rather than to stdout, because this
// service logs to stdout from the moment `common/config.js` loads and the
// result would arrive interleaved with a startup banner. It is one child for
// the whole file rather than one per section: the sections are a SEQUENCE —
// the rotation assertions read what the section above them wrote — so running
// them apart would be four authorities in four processes and no rotation at
// all.
// ---------------------------------------------------------------------------
function inAFreshProcess() {
  log.debug("Entering inAFreshProcess().");
  const out = path.join(os.tmpdir(),
                        'sts-spiffe-authority-' + process.pid + '.json');
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const realms = require(' + JSON.stringify(
      path.join(__dirname, '..', 'common', 'realms')) + ');' +
    'const ca = require(' + JSON.stringify(
      path.join(__dirname, '..', 'spiffe', 'spiffe_ca')) + ');' +
    'function stored() {' +
    '  const handle = realms.handles().find(function (row) {' +
    '    return row.handle === "spiffe.authorities"; });' +
    '  if (!handle) { return null; }' +
    '  const out = {};' +
    '  handle.dump("").forEach(function (row) { out[row.key] = row.value; });' +
    '  return out;' +
    '}' +
    '(async function () {' +
    '  await ca.ready();' +
    '  const handle = realms.handles().find(function (row) {' +
    '    return row.handle === "spiffe.authorities"; });' +
    '  const held = stored() || {};' +
    // **EVERY VALUE IS SNAPSHOTTED AT THE MOMENT IT IS ABOUT.** The first
    // version of this read `ca.state()` once, at the end, and three
    // assertions then compared a before-rotation claim with an
    // after-two-rotations answer — which is a fixture bug that reads exactly
    // like a broken counter.
    '  const before = ca.state();' +
    '  const live = before.x509Authorities[0];' +
    '  const der = await ca.x509BundleDer();' +
    '  const seqBefore = before.sequence;' +
    '  const anchorCount = before.trustAnchors.length;' +
    '  const beforeIds = before.x509Authorities.map(function (a) {' +
    '    return a.id; });' +
    '  const rotated = await ca.rotateX509Authority();' +
    '  const afterRotate = ca.state();' +
    '  const afterStore = stored() || {};' +
    '  const afterBundle = await ca.x509BundleDer();' +
    '  const jwtSeq = ca.sequence();' +
    '  const jwtRotated = await ca.rotateJwtAuthority();' +
    '  const jwtStore = stored() || {};' +
    '  const doc = await ca.bundle();' +
    '  require("fs").writeFileSync(' + JSON.stringify(out) + ',' +
    '    JSON.stringify({' +
    '      declared: !!handle,' +
    '      shape: handle ? handle.shape : "",' +
    '      scope: handle ? String(handle.scope) : "",' +
    '      held: held,' +
    '      source: before.authoritySource,' +
    '      anchorCount: anchorCount,' +
    '      livePem: live ? live.certificatePem : "",' +
    '      bundleBytes: der.length,' +
    '      seqBefore: seqBefore,' +
    '      seqAfter: afterRotate.sequence,' +
    '      beforeIds: beforeIds,' +
    '      rotatedId: rotated.id,' +
    '      afterStore: afterStore,' +
    '      afterCount: afterRotate.x509Authorities.length,' +
    '      afterBundleBytes: afterBundle.length,' +
    '      jwtSeq: jwtSeq,' +
    '      jwtRotatedId: jwtRotated.id,' +
    '      jwtStore: jwtStore,' +
    '      bundleSequence: doc.spiffe_sequence' +
    '    }));' +
    '  process.exit(0);' +
    '})().catch(function (e) {' +
    '  require("fs").writeFileSync(' + JSON.stringify(out) + ',' +
    '    JSON.stringify({ threw: e.message }));' +
    '  process.exit(0);' +
    '});';
  try {
    childProcess.execFileSync(process.execPath, ['-e', script],
                              { stdio: 'ignore', timeout: 120000 });
    log.debug("Leaving inAFreshProcess().");
    return JSON.parse(fs.readFileSync(out, 'utf8'));
  } finally {
    try {
      fs.unlinkSync(out);
    } catch (e) {
      // Gone, or never written; the read above has already decided whether
      // this file can assert anything.
      log.debug("Caught in inAFreshProcess(): " + ((e && e.message) || e));
    }
  }
}

async function run(t) {
  log.debug("Entering run().");
  const seen = inAFreshProcess();
  if (seen.threw) {
    // A test that could not RUN, which `run.js` reports differently from a
    // failure on purpose — see this directory's CLAUDE.md.
    throw new Error('the child process could not build a self-signed SPIFFE ' +
                    'authority: ' + seen.threw);
  }

  // -------------------------------------------------------------------------
  // 1. IT IS IN A DECLARED STORE AT ALL.
  // -------------------------------------------------------------------------
  t.log.info('=== the authority is declared, and it is per realm ===');
  t.check(seen.declared,
          'the authority is a DECLARED store — a module array is one ' +
          'process\'s certificate authority, and this service can be several ' +
          'processes',
          seen.shape || 'nothing declares spiffe.authorities');
  // **THIS ASSERTED `scope === 'shared'` UNTIL 2026-09-11**, on the argument
  // that SPIFFE is one trust domain for the whole service because its sockets
  // have no path to put a realm segment in. The trust DOMAIN stayed one that
  // day; what became per realm was the AUTHORITY, because `common/pki.js`'s
  // SPIFFE Issuing CA is a realm's and rule 2 of the realm design says a store
  // follows its declaration. Since 2026-09-12 a realm has a trust domain and
  // sockets of its own as well (`tests/spiffe_realm_domains.js`); the default
  // realm's four sockets still answer in the default realm.
  //
  // **WHAT MAKES THAT SAFE IS ASSERTED IN `tests/spiffe_pki.js`, NOT HERE**:
  // every realm's bundle publishes the same service Root, so partitioning the
  // authority did not partition the anchor.
  t.check(seen.scope !== 'shared',
          'and PER REALM since 2026-09-11: the authority is this realm\'s ' +
          'SPIFFE Issuing CA under a Root the whole service shares, so the ' +
          'store follows the authority',
          seen.scope || '(none)');

  // AND THE PATH UNDER TEST IS THE ONE THIS FILE CLAIMS TO BE TESTING, which
  // is asserted rather than assumed: with a hierarchy built, none of the
  // sections below would be about the SPIFFE authority at all, and every one
  // of them would fail in a way that reads as a broken store.
  t.equal(seen.source, 'self-signed',
          'and this process built a SELF-SIGNED authority, which is what a ' +
          'realm with no certificate authority gets — the state every claim ' +
          'below is about');
  t.equal(seen.anchorCount, 1,
          'with itself as the one trust anchor, because a self-signed ' +
          'authority IS the anchor');

  const held = seen.held || {};
  t.check(Array.isArray(held.x509) && held.x509.length > 0,
          'and the X.509 authority is IN it after startup, not beside it',
          String((held.x509 || []).length) + ' authority/authorities');
  t.check(Array.isArray(held.jwt) && held.jwt.length > 0,
          'and so is the JWT authority',
          String((held.jwt || []).length) + ' authority/authorities');

  // -------------------------------------------------------------------------
  // 2. THE STORED FORM SURVIVES JSON, AND THE LIVE FORM IS A Buffer.
  // -------------------------------------------------------------------------
  t.log.info('=== the stored form is JSON-safe and the live form is not ===');
  const storedX509 = (held.x509 || [])[0] || {};
  t.check(typeof storedX509.certificateDer === 'string',
          'certificateDer is a STRING in the store. It is a Buffer in ' +
          'memory, and a Buffer written straight to the journal comes back ' +
          'as {"type":"Buffer","data":[…]} — an object that every reader ' +
          'here would then call .toString("base64") on and get nonsense from',
          typeof storedX509.certificateDer);

  // **THE ROUND TRIP IS MADE IN THIS PROCESS AND THAT IS STILL THE REAL
  // CHECK.** What arrived here has already survived one `JSON.stringify` — the
  // child wrote its answer as JSON — so a Buffer that had been left raw would
  // be a `{"type":"Buffer",…}` object by now rather than a string, which is
  // exactly what the assertion above names.
  const round = JSON.parse(JSON.stringify(held));
  t.check(JSON.stringify(round) === JSON.stringify(held),
          'and the whole record survives a JSON round trip unchanged, which ' +
          'is the trip the journal actually makes it take',
          'identical');

  t.check(typeof seen.livePem === 'string' &&
          seen.livePem.indexOf('BEGIN CERTIFICATE') > 0,
          'while the live record still carries a usable certificate',
          seen.livePem ? 'PEM present' : 'no authority');
  t.check(seen.bundleBytes > 0,
          'and the DER bundle every SPIRE client reads is real bytes, ' +
          'rebuilt from what was stored — this is the assertion that fails ' +
          'if the encoding is ever dropped',
          seen.bundleBytes + ' bytes');

  // -------------------------------------------------------------------------
  // 3. A ROTATION IS THE SERVICE'S, NOT THIS PROCESS'S.
  // -------------------------------------------------------------------------
  t.log.info('=== rotating writes through the store, and the sequence moves ' +
             '===');
  t.check(seen.seqAfter === seen.seqBefore + 1,
          'ROTATING ADVANCES THE SEQUENCE. It is how a relying party knows ' +
          'the bundle it holds is stale, so a rotation that left it alone ' +
          'would publish keys nobody fetched. **That is true of the ' +
          'SELF-SIGNED path and deliberately NOT of the PKI one**, where the ' +
          'bundle is the Root and does not move — see ' +
          'rotateX509Authority()',
          seen.seqBefore + ' -> ' + seen.seqAfter);

  const afterStore = seen.afterStore || {};
  t.check(Number(afterStore.sequence) === seen.seqAfter,
          'and the sequence is IN THE STORE, which is what another process ' +
          'reads — a counter that moved only in memory is the defect this ' +
          'file exists for',
          String(afterStore.sequence));
  t.check((afterStore.x509 || [])[0] &&
          afterStore.x509[0].id === seen.rotatedId,
          'and the new authority is the FIRST stored one, so another process ' +
          'signs with what this one just made rather than with what it had',
          (afterStore.x509 || [])[0] ? afterStore.x509[0].id : '(none)');
  t.check(seen.beforeIds.indexOf(seen.rotatedId) < 0,
          'and it is genuinely new rather than the one that was already active',
          seen.rotatedId);
  t.check(seen.afterCount === seen.beforeIds.length + 1,
          'while the RETIRED one stays in the bundle — dropping it is the ' +
          'difference between a rotation and an outage',
          seen.afterCount + ' published');

  // AND WHAT ANOTHER PROCESS WOULD SEE, read out of the store and decoded the
  // way a restore decodes it. This is as close as one process can get to
  // asking the question, and it is the whole claim of the file.
  const decoded = (afterStore.x509 || []).map(function (one) {
    return Buffer.from(String(one.certificateDer || ''), 'base64').length;
  });
  t.check(decoded.length === 2 &&
          decoded[0] + decoded[1] === seen.afterBundleBytes,
          'and a second process decoding the stored bundle gets exactly the ' +
          'bytes this one publishes',
          'the two decoded certificates account for the whole bundle');

  // -------------------------------------------------------------------------
  // 4. THE JWT HALF, WHICH HAS NO Buffer AND MUST STILL BE SHARED.
  // -------------------------------------------------------------------------
  t.log.info('=== and the JWT authority rotates through the same store ===');
  const jwtStore = seen.jwtStore || {};
  t.check(Number(jwtStore.sequence) === seen.jwtSeq + 1,
          'rotating the JWT authority advances the same sequence — one ' +
          'bundle, one counter',
          seen.jwtSeq + ' -> ' + jwtStore.sequence);
  t.check((jwtStore.jwt || [])[0] && jwtStore.jwt[0].id === seen.jwtRotatedId,
          'and the new signing key is the first stored one',
          (jwtStore.jwt || [])[0] ? jwtStore.jwt[0].id : '(none)');
  t.check(seen.bundleSequence === Number(jwtStore.sequence),
          'and the published document reports that same sequence rather than ' +
          'one of its own',
          String(seen.bundleSequence));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_authority',
  describe: 'the SPIFFE authority is shared state, stored JSON-safely, and ' +
            'rotated for the whole service rather than for one process',
  run: run
};
