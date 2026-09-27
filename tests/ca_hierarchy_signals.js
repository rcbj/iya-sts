'use strict';
//
// File: ca_hierarchy_signals.js
//
// ===========================================================================
// A CHANGE TO THE CERTIFICATE HIERARCHY TELLS THE PEOPLE UNDER IT (#244).
//
// `ssf/service_signals.ts` decides, per certificate a PERSON holds, what an
// act on the tiers above it did, and hands each holder's events to the one
// funnel (`ssf/account_signals.ts`), which is stood in for here so every
// notice is seen:
//
//   A. WHAT IS HELD. A person's TLS client certificate (a register slot) and
//      an ACME enrolment (the issued register) are held; an application's
//      enrolment is not a person's.
//   B. A REISSUE RE-MINTS A SLOT. `reissue-use-case` on tls-client sends the
//      holder `update`, naming the NEW certificate.
//   C. AND ORPHANS AN ENROLMENT. On acme it sends `revoke`, naming the OLD
//      one — this service keeps no key to re-certify an enrolment from, which
//      settles #244's unverified question: ACME, EST and SCEP certificates are
//      never re-minted.
//   D. ONCE. A second reissue says nothing more about a certificate an
//      earlier act already orphaned.
//   E. AN ISSUING CA REVOKED walks down to every holder beneath it:
//      `revoke`, and RISC `credential-compromise` for cACompromise.
//   F. AN INTERMEDIATE REVOKED reaches every use case of its scope; a
//      superseded reason sends no compromise.
//   G. A BRANCH REBUILT through `/admin/pki`'s own action orphans the TLS
//      client certificate (the rebuild re-certifies only the realm's signing
//      keys) and says so in its answer.
//   H. THE FAN-OUT IS BATCHED: at most `BATCH` people's events in flight,
//      with a turn of the event loop between batches.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const realms = require('../common/realms');
const revocation = require('../common/pki_revocation');
const pkiAdmin = require('../admin-ui/pki_admin');
const accountSignals = require('../ssf/account_signals');
const serviceSignals = require('../ssf/service_signals');

const log = require('bunyan').createLogger({ name: 'ca_hierarchy_signals',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'hier-signals-' + nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'hs-alice';
const BOB = 'hs-bob';
const APP = 'hs-app';

// Every notice the funnel was handed, as `{ kind, username, changeType,
// serial, issuer }`.
const seen = [];

function standIn() {
  log.debug("Entering standIn().");
  const real = { changed: accountSignals.credentialChanged,
                 compromised: accountSignals.credentialCompromised };
  accountSignals.credentialChanged = function (n) {
    seen.push({ kind: 'change', username: n.username,
                changeType: n.changeType, type: n.credentialType,
                serial: n.x509Serial, issuer: n.x509Issuer });
    return Promise.resolve({ sent: 0, streams: 0 });
  };
  accountSignals.credentialCompromised = function (n) {
    seen.push({ kind: 'compromise', username: n.username,
                type: n.credentialType });
    return Promise.resolve({ sent: 0, streams: 0 });
  };
  log.debug("Leaving standIn().");
  return real;
}

// Waits (bounded) for the fan-out, which runs behind the act, to settle.
async function settle(count) {
  log.debug("Entering settle(). " + count);
  for (let i = 0; i < 100 && seen.length < count; i++) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 20);
    });
  }
  // And a little longer, so a notice that should NOT come has had the
  // chance to.
  await new Promise(function (resolve) {
    setTimeout(resolve, 60);
  });
  log.debug("Leaving settle(). " + seen.length);
}

function take() {
  log.debug("Entering take().");
  const out = seen.splice(0, seen.length);
  log.debug("Leaving take(). " + out.length);
  return out;
}

function keyPem() {
  log.debug("Entering keyPem().");
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  log.debug("Leaving keyPem().");
  return pair.publicKey.export({ type: 'spki', format: 'pem' });
}

async function enrol(who, kind) {
  log.debug("Entering enrol(). " + who);
  const issued = await pki.issueEnrolled(REALM, 'acme', {
    subject: [{ name: 'CN', value: who }], publicKeyPem: keyPem(),
    profile: 'tls-client', subjectAltName: [], days: 1,
    identifier: who, subjectKind: kind, holderSubject: '' });
  log.debug("Leaving enrol().");
  return issued;
}

function serialOf(text) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return revocation.normalSerial(text);
}

async function sections(t) {
  log.debug("Entering sections().");
  const built = await pki.ensureScope(REALM);
  t.check(built.ok, 'the realm has a branch', JSON.stringify(built.errors));

  // --- A. what is held -------------------------------------------------------
  const slot = 'person:' + ALICE + ':' + nodeCrypto.randomBytes(6)
    .toString('hex');
  const tlsCert = await pki.certify(REALM, 'tls-client', {
    slot: slot, alg: 'ES256', label: 'alice tls', commonName: ALICE,
    publicKeyPem: keyPem(), profile: 'tls-client' });
  t.check(tlsCert.ok, 'alice holds a TLS client certificate',
          JSON.stringify(tlsCert.errors));
  const enrolled = await enrol(ALICE, 'person');
  t.check(enrolled.ok, 'and an ACME enrolment',
          JSON.stringify(enrolled.errors));
  const appEnrolled = await enrol(APP, 'application');
  t.check(appEnrolled.ok, 'an application holds one too',
          JSON.stringify(appEnrolled.errors));
  const held = serviceSignals.holdingsOf(REALM);
  const heldBy = held.map(function (h) {
    return h.username + ':' + h.useCase + ':' + h.kind;
  }).sort().join(', ');
  t.equal(heldBy, [ALICE + ':acme:pair', ALICE + ':tls-client:slot'].sort()
                    .join(', '),
          'A. the person\'s TLS client certificate and enrolment are held; ' +
          'the application\'s enrolment is not a person\'s');

  // --- B. a reissue re-mints a slot ------------------------------------------
  const tlsBefore = pki.rawRowFor(REALM).certs['tls-client:' + slot];
  let before = serviceSignals.snapshot([REALM], 'tls-client');
  let done = await pki.reissueUseCase(REALM, 'tls-client');
  t.check(done.ok, 'the tls-client Issuing CA is reissued',
          JSON.stringify(done.errors));
  let counts = serviceSignals.hierarchyChanged(before,
                                               { via: 'the test (B)' });
  await settle(1);
  let got = take();
  const tlsAfter = pki.rawRowFor(REALM).certs['tls-client:' + slot];
  t.check(counts.updated === 1 && counts.revoked === 0 &&
          got.length === 1 && got[0].username === ALICE &&
          got[0].changeType === 'update' && got[0].type === 'x509' &&
          got[0].serial === serialOf(tlsAfter.serialHex) &&
          got[0].serial !== serialOf(tlsBefore.serialHex) &&
          /CN=/.test(String(got[0].issuer)),
          'B. REISSUING tls-client re-mints alice\'s certificate: one ' +
          'credential-change (x509, update) naming the NEW serial',
          JSON.stringify([counts, got]));

  // --- C. and orphans an enrolment -------------------------------------------
  before = serviceSignals.snapshot([REALM], 'acme');
  done = await pki.reissueUseCase(REALM, 'acme');
  t.check(done.ok, 'the acme Issuing CA is reissued',
          JSON.stringify(done.errors));
  counts = serviceSignals.hierarchyChanged(before, { via: 'the test (C)' });
  await settle(1);
  got = take();
  t.check(counts.revoked === 1 && counts.updated === 0 &&
          got.length === 1 && got[0].username === ALICE &&
          got[0].changeType === 'revoke' &&
          got[0].serial === serialOf(enrolled.serialHex),
          'C. REISSUING acme ORPHANS alice\'s enrolment — never re-minted, ' +
          'since this service holds no key for it: credential-change ' +
          '(x509, revoke) naming the OLD serial; the application is told ' +
          'nothing', JSON.stringify([counts, got]));

  // --- D. once ------------------------------------------------------------------
  before = serviceSignals.snapshot([REALM], 'acme');
  done = await pki.reissueUseCase(REALM, 'acme');
  counts = serviceSignals.hierarchyChanged(before, { via: 'the test (D)' });
  await settle(0);
  got = take();
  t.check(done.ok && counts.revoked === 0 && got.length === 0,
          'D. a second reissue says nothing more about a certificate the ' +
          'first one already orphaned', JSON.stringify([counts, got]));

  // --- E. an Issuing CA revoked --------------------------------------------------
  const bobs = await enrol(BOB, 'person');
  t.check(bobs.ok, 'bob enrols under the current acme Issuing CA',
          JSON.stringify(bobs.errors));
  const acmeCa = pki.rawRowFor(REALM).issuing.acme;
  const onList = revocation.revoke(REALM, 'intermediate',
    { serialHex: acmeCa.serialHex, reason: 'cACompromise' });
  t.check(onList.ok, 'the acme Issuing CA goes on its Intermediate\'s list',
          JSON.stringify(onList.errors));
  let reached = serviceSignals.caRevoked(REALM, 'intermediate',
    acmeCa.serialHex, 'cACompromise', { via: 'the test (E)' });
  await settle(2);
  got = take();
  t.check(reached.tier === 'issuing-ca' && reached.people === 1 &&
          got.length === 2 &&
          got.some(function (one) {
            return one.kind === 'change' && one.username === BOB &&
                   one.changeType === 'revoke' &&
                   one.serial === serialOf(bobs.serialHex);
          }) &&
          got.some(function (one) {
            return one.kind === 'compromise' && one.username === BOB &&
                   one.type === 'x509';
          }),
          'E. REVOKING AN ISSUING CA for cACompromise walks down to bob: ' +
          'credential-change (x509, revoke) AND RISC credential-compromise; ' +
          'alice, under another Issuing CA, is not told',
          JSON.stringify([reached, got]));
  reached = serviceSignals.caRevoked(REALM, 'intermediate', 'abcdef0123',
                                     'keyCompromise', {});
  t.equal(reached.tier, '', 'E. a serial that is no current tier reaches ' +
                            'nobody');

  // --- F. an Intermediate revoked ------------------------------------------------
  const intermediate = pki.rawRowFor(REALM).intermediate;
  reached = serviceSignals.caRevoked(REALM, 'root', intermediate.serialHex,
                                     'superseded', { via: 'the test (F)' });
  await settle(2);
  got = take();
  const names = got.map(function (one) {
    return one.kind + ':' + one.username;
  }).sort().join(', ');
  t.check(reached.tier === 'intermediate-ca' && reached.people === 2 &&
          names === 'change:' + ALICE + ', change:' + BOB,
          'F. REVOKING THE INTERMEDIATE reaches every use case beneath it — ' +
          'alice\'s TLS client certificate and bob\'s enrolment — and ' +
          '"superseded" sends no compromise', JSON.stringify([reached, got]));

  // --- G. a branch rebuilt, through the console's own action ----------------
  const answer = await realms.run(realms.get(REALM), function () {
    return pkiAdmin.pkiAction({ action: 'build-scope', scope: REALM });
  });
  await settle(2);
  got = take();
  const toAlice = got.filter(function (one) {
    return one.username === ALICE;
  })[0];
  t.check(answer.ok && !!toAlice && toAlice.changeType === 'revoke' &&
          got.every(function (one) {
            return one.changeType === 'revoke';
          }) &&
          /held by people were affected/.test(String(answer.why)),
          'G. REBUILDING THE BRANCH on /admin/pki orphans alice\'s TLS client ' +
          'certificate (the rebuild re-certifies only the realm\'s signing ' +
          'keys): revoke, and the answer says how many people were affected',
          JSON.stringify([answer.ok, answer.why, got]));
  log.debug("Leaving sections().");
}

async function batching(t) {
  log.debug("Entering batching().");
  const Cls = serviceSignals.ServiceSignals;
  let inFlight = 0;
  let most = 0;
  let turns = 0;
  let told = 0;
  const own = new Cls(Object.assign(Cls.defaultDeps(), {
    accountSignals: function () {
      return {
        credentialChanged: function () {
          inFlight += 1;
          most = Math.max(most, inFlight);
          return new Promise(function (resolve) {
            setImmediate(function () {
              inFlight -= 1;
              told += 1;
              resolve({ sent: 1 });
            });
          });
        },
        credentialCompromised: function () {
          return Promise.resolve({ sent: 0 });
        }
      };
    },
    yieldTurn: function () {
      turns += 1;
      return Promise.resolve();
    }
  }));
  const notices = [];
  for (let i = 0; i < 120; i++) {
    notices.push({ scope: REALM, username: 'bulk-' + i, changeType: 'revoke',
                   issuer: 'CN=x', serialHex: String(i + 1),
                   compromised: false });
  }
  const handed = await own.fanOut(notices, { via: 'the test (H)' });
  t.check(handed === 120 && told === 120 && most <= Cls.BATCH &&
          most === Cls.BATCH && turns === 2,
          'H. 120 people\'s events go out in batches of ' + Cls.BATCH +
          ' — never more in flight — with a turn of the event loop between ' +
          'batches', JSON.stringify({ handed: handed, told: told, most: most,
                                      turns: turns }));
  log.debug("Leaving batching().");
}

async function run(t) {
  log.debug("Entering run().");
  const hadRoot = !!keystore.pkiFor(pki.SERVICE_SCOPE);
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  const real = standIn();
  try {
    await sections(t);
    await batching(t);
  } finally {
    accountSignals.credentialChanged = real.changed;
    accountSignals.credentialCompromised = real.compromised;
    // Whatever this file made, it removes: `run.js` runs every file in one
    // process, and a Root left behind is the Root `tests/pki.js` meets.
    keystore.attachPki(REALM, null);
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
    if (!hadRoot && keystore.pkiFor(pki.SERVICE_SCOPE)) {
      keystore.attachPki(pki.SERVICE_SCOPE, null);
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ca_hierarchy_signals',
  describe: 'A change to the certificate hierarchy tells the people under ' +
            'it (#244): a reissue re-mints a TLS client certificate (update) ' +
            'and orphans an enrolment (revoke), once; a revoked Issuing CA ' +
            'or Intermediate walks down to every holder, with RISC ' +
            'credential-compromise for a compromise reason; a rebuilt ' +
            'branch orphans; the fan-out is batched.',
  run: run
};
