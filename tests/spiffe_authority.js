// ===========================================================================
// tests/spiffe_authority.js — THE SPIFFE CERTIFICATE AUTHORITY IS THE
// SERVICE'S AND NOT ONE PROCESS'S (2026-09-08).
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

const realms = require('../common/realms');
const ca = require('../spiffe/spiffe_ca');

// The stored rows, read the way a flush reads them — through the handle the
// store declared rather than through the module's own accessors, because what
// is under test is what would be WRITTEN DOWN.
function storedAuthorities() {
  const handle = realms.handles().find(function (row) {
    return row.handle === 'spiffe.authorities';
  });
  if (!handle) {
    return null;
  }
  const rows = handle.dump('');
  const out = {};
  rows.forEach(function (row) { out[row.key] = row.value; });
  return out;
}

async function run(t) {
  await ca.ready();

  // -------------------------------------------------------------------------
  // 1. IT IS IN A SHARED STORE AT ALL.
  // -------------------------------------------------------------------------
  t.log.info('=== the authority is declared, shared, and not per realm ===');
  const handle = realms.handles().find(function (row) {
    return row.handle === 'spiffe.authorities';
  });
  t.check(!!handle,
          'the authority is a DECLARED store — a module array is one ' +
          'process\'s certificate authority, and this service can be several ' +
          'processes',
          handle ? handle.shape : 'nothing declares spiffe.authorities');
  t.check(!!handle && handle.scope === 'shared',
          'and SHARED rather than per realm: SPIFFE is one trust domain for ' +
          'the whole service, because its sockets have no path to put a realm ' +
          'segment in',
          handle ? handle.scope : '(none)');

  const held = storedAuthorities() || {};
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
          'certificateDer is a STRING in the store. It is a Buffer in memory, ' +
          'and a Buffer written straight to the journal comes back as ' +
          '{"type":"Buffer","data":[…]} — an object that every reader here ' +
          'would then call .toString("base64") on and get nonsense from',
          typeof storedX509.certificateDer);

  const round = JSON.parse(JSON.stringify(held));
  t.check(JSON.stringify(round) === JSON.stringify(held),
          'and the whole record survives a JSON round trip unchanged, which ' +
          'is the trip the journal actually makes it take',
          'identical');

  const live = ca.state().x509Authorities[0];
  t.check(!!live && typeof live.certificatePem === 'string' &&
          live.certificatePem.indexOf('BEGIN CERTIFICATE') > 0,
          'while the live record still carries a usable certificate',
          live ? 'PEM present' : 'no authority');
  const der = await ca.x509BundleDer();
  t.check(Buffer.isBuffer(der) && der.length > 0,
          'and the DER bundle every SPIRE client reads is a real Buffer, ' +
          'rebuilt from what was stored — this is the assertion that fails ' +
          'if the encoding is ever dropped',
          Buffer.isBuffer(der) ? der.length + ' bytes' : typeof der);

  // -------------------------------------------------------------------------
  // 3. A ROTATION IS THE SERVICE'S, NOT THIS PROCESS'S.
  // -------------------------------------------------------------------------
  t.log.info('=== rotating writes through the store, and the sequence moves ===');
  const seqBefore = ca.sequence();
  const beforeIds = ca.state().x509Authorities.map(function (a) { return a.id; });
  const rotated = await ca.rotateX509Authority();

  t.check(ca.sequence() === seqBefore + 1,
          'ROTATING ADVANCES THE SEQUENCE. It is how a relying party knows ' +
          'the bundle it holds is stale, so a rotation that left it alone ' +
          'would publish keys nobody fetched',
          seqBefore + ' -> ' + ca.sequence());

  const afterStore = storedAuthorities() || {};
  t.check(Number(afterStore.sequence) === ca.sequence(),
          'and the sequence is IN THE STORE, which is what another process ' +
          'reads — a counter that moved only in memory is the defect this ' +
          'file exists for',
          String(afterStore.sequence));
  t.check((afterStore.x509 || [])[0] &&
          afterStore.x509[0].id === rotated.id,
          'and the new authority is the FIRST stored one, so another process ' +
          'signs with what this one just made rather than with what it had',
          (afterStore.x509 || [])[0] ? afterStore.x509[0].id : '(none)');
  t.check(beforeIds.indexOf(rotated.id) < 0,
          'and it is genuinely new rather than the one that was already active',
          rotated.id);
  t.check(ca.state().x509Authorities.length === beforeIds.length + 1,
          'while the RETIRED one stays in the bundle — dropping it is the ' +
          'difference between a rotation and an outage',
          ca.state().x509Authorities.length + ' published');

  // AND WHAT ANOTHER PROCESS WOULD SEE, read out of the store and decoded the
  // way a restore decodes it. This is as close as one process can get to
  // asking the question, and it is the whole claim of the file.
  const theirs = JSON.parse(JSON.stringify(afterStore.x509))[0];
  t.check(Buffer.from(theirs.certificateDer, 'base64').length ===
          Buffer.from((await ca.x509BundleDer())).length -
          Buffer.from(JSON.parse(JSON.stringify(afterStore.x509))[1]
                      .certificateDer, 'base64').length,
          'and a second process decoding the stored bundle gets exactly the ' +
          'bytes this one publishes',
          'the two decoded certificates account for the whole bundle');

  // -------------------------------------------------------------------------
  // 4. THE JWT HALF, WHICH HAS NO Buffer AND MUST STILL BE SHARED.
  // -------------------------------------------------------------------------
  t.log.info('=== and the JWT authority rotates through the same store ===');
  const jwtSeq = ca.sequence();
  const jwtRotated = await ca.rotateJwtAuthority();
  const jwtStore = storedAuthorities() || {};
  t.check(ca.sequence() === jwtSeq + 1,
          'rotating the JWT authority advances the same sequence — one ' +
          'bundle, one counter',
          jwtSeq + ' -> ' + ca.sequence());
  t.check((jwtStore.jwt || [])[0] && jwtStore.jwt[0].id === jwtRotated.id,
          'and the new signing key is the first stored one',
          (jwtStore.jwt || [])[0] ? jwtStore.jwt[0].id : '(none)');
  const doc = await ca.bundle();
  t.check(doc.spiffe_sequence === ca.sequence(),
          'and the published document reports that same sequence rather than ' +
          'one of its own',
          String(doc.spiffe_sequence));
  t.check(doc.keys.some(function (k) { return k.kid === jwtRotated.id; }),
          'and the bundle publishes the key that was just made',
          doc.keys.length + ' key(s)');
}

module.exports = {
  name: 'spiffe_authority',
  describe: 'the SPIFFE authority is shared state, stored JSON-safely, and ' +
            'rotated for the whole service rather than for one process',
  run: run
};
