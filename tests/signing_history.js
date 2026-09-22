'use strict';
//
// File: tests/signing_history.js
//
// ---------------------------------------------------------------------------
// EVERY SIGNING KEY A REALM HAS EVER HELD (2026-09-22, #42's follow-up).
//
// `signing.retire` DROPS a retired key once it passes its grace, and its
// private half is gone — which is the security rule. What #42's follow-up
// added is the record that the key existed: the unit it belonged to, when it
// was minted, promoted, retired and dropped, and the CERTIFICATE that vouched
// for it, so a signature captured months ago can still be read back.
//
// Six claims, and the first is the one the whole feature rests on:
//
//   1. NO PRIVATE MATERIAL REACHES A ROW. The key set a row is derived from
//      holds `privateKeyPem`, a `KeyObject` and a BBS secret key; a row is
//      searched for every one of them, as bytes, at every stage.
//   2. A ROW PER KEY THE SET HOLDS, and observing twice records nothing —
//      because the history is a PROJECTION of the set rather than a log of
//      events, and a projection that grew on every read would be a log.
//   3. A KEY THE SET NO LONGER HOLDS IS MARKED DROPPED, with its certificate
//      KEPT. That is option B in one assertion: the key is gone, the record
//      is not.
//   4. THE TIMESTAMPS ONLY MOVE FORWARD FROM ABSENT TO SET. An observation
//      that sees a key in a role it was already in must not restamp it, or
//      every read would report the key as promoted a moment ago.
//   5. THE CERTIFICATE IS CAPTURED ONCE AND NEVER REPLACED. A re-certification
//      issues a new certificate over the same key; what the row is for is what
//      vouched for that key while it was live.
//   6. THE READ SIDE: newest first, an unknown unit answered as NOT FOUND
//      rather than as an empty history, and the units index counting what it
//      holds.
//
// Sections A–E drive the CLASS with injected dependencies, which is what lets
// a key set be a literal and a certificate authority be four lines — every
// input here is a state a running service reaches only by rotating keys over
// months. Section F drives the REAL `common/helpers.js` generations end to
// end (mint, promote, retire) against a realm of its own, so the projection is
// shown to be taken from the set this service actually keeps rather than from
// a fixture shaped like one.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const signingHistory = require('../common/signing_history');
const SigningHistory = signingHistory.SigningHistory;

const log = require('bunyan').createLogger({ name: 'signing_history',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// A private key nothing may leak, as bytes a search can look for.
const SECRET_PEM = '-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n' +
                   '-----END PRIVATE KEY-----\n';
const SECRET_BBS = Buffer.from('BBSSECRETKEYMATERIAL');

// ---------------------------------------------------------------------------
// A key set of the shape `helpers.signingUnitsOf()` and `standbyOf()` read,
// with private material in every place the real one has it.
// ---------------------------------------------------------------------------
function keySet(spec) {
  log.debug("Entering keySet().");
  const s = spec || {};
  log.debug("Leaving keySet().");
  return {
    realm: s.realm || 'r1',
    kid: s.current || 'sts-rsa-1',
    privateKeyPem: SECRET_PEM,
    privateKey: { theKeyObject: true },
    bbsKey: { secretKey: SECRET_BBS, publicKey: Buffer.from('BBSPUBLIC') },
    generations: { standby: (s.standby || []).slice(), rotated: {},
                   generation: Number(s.generation) || 1 }
  };
}

// The two functions this module asks of `helpers`, over that set.
function fakeHelpers(state) {
  log.debug("Entering fakeHelpers().");
  log.debug("Leaving fakeHelpers().");
  return {
    stsKeysFor: {
      existing: function () {
        return new Map(state.held ? [[state.realmId, state.keys]] : []);
      }
    },
    // TOLERANT OF A SET THAT IS NOT THERE, deliberately: the real
    // `signingUnitsOf()` would throw on null and so would hide the guard
    // that stops a process holding no keys marking every row dropped. A fake
    // that throws makes that guard untestable — the first mutation round
    // found exactly that, and this is the fixture it asked for.
    signingUnitsOf: function (keys) {
      if (!keys) {
        return [];
      }
      const out = [{ unit: 'jose:RS256', useCase: 'jose', slot: 'RS256',
                     alg: 'RS256', kind: 'rsa', kid: keys.kid }];
      if (keys.bbsKey) {
        out.push({ unit: 'bbs:BBS', useCase: 'bbs', slot: 'BBS', alg: 'BBS',
                   kind: 'bbs', kid: 'bbs-' + state.bbsKid });
      }
      return out;
    },
    standbyOf: function (keys, unit) {
      const all = (keys && keys.generations && keys.generations.standby) || [];
      return unit ? all.filter(function (one) {
        return one.unit === unit;
      }) : all.slice();
    }
  };
}

// A certificate authority that answers for the keys `state.certs` names, in
// `pki.describeCertificate()`'s shape.
function fakePki(state) {
  log.debug("Entering fakePki().");
  log.debug("Leaving fakePki().");
  return {
    certificateFor: function (scope, useCase, slot, kid) {
      state.asked.push(String(kid));
      const held = state.certs[String(kid)];
      return held || null;
    }
  };
}

function certificateFor(kid, serial) {
  log.debug("Entering certificateFor().");
  log.debug("Leaving certificateFor().");
  return { serialHex: serial, subject: 'CN=' + kid, notBefore: '2026-01-01',
           notAfter: '2027-01-01', thumbprint: 'TP-' + kid, keyAlg: 'RSA',
           signatureAlg: 'SHA256withRSA',
           certificatePem: '-----BEGIN CERTIFICATE-----\n' + kid +
                           '\n-----END CERTIFICATE-----\n',
           chainPem: ['-----BEGIN CERTIFICATE-----\nISSUING\n' +
                      '-----END CERTIFICATE-----\n'] };
}

// A module instance over one mutable state, and a clock the test moves.
function instanceOver(state) {
  log.debug("Entering instanceOver().");
  log.debug("Leaving instanceOver().");
  return new SigningHistory({
    log: QUIET,
    realms: require('../common/realms'),
    errorCodes: require('../common/error_codes'),
    helpers: function () {
      return fakeHelpers(state);
    },
    pki: function () {
      return fakePki(state);
    },
    now: function () {
      return state.clock;
    }
  });
}

// A retired standby entry, with the private material a real one carries.
function retiredEntry(unit, kid, at, until) {
  log.debug("Entering retiredEntry().");
  log.debug("Leaving retiredEntry().");
  return { unit: unit, role: 'retired', alg: 'RS256', kind: 'rsa',
           useCase: 'jose', slot: 'RS256', kid: kid, createdAt: at - 1000,
           retiredAt: at, retiredUntil: until, reason: 'rotated',
           privateKeyPem: SECRET_PEM, privateKey: { theKeyObject: true } };
}

// Is any private material anywhere in what a caller would be handed?
function leaks(value) {
  log.debug("Entering leaks().");
  const text = JSON.stringify(value, function (k, v) {
    if (Buffer.isBuffer(v)) {
      return v.toString('latin1');
    }
    return v;
  }) || '';
  log.debug("Leaving leaks().");
  return text.indexOf('SECRETKEYMATERIAL') >= 0 ||
         text.indexOf('BBSSECRETKEYMATERIAL') >= 0 ||
         text.indexOf('theKeyObject') >= 0;
}

async function run(t) {
  log.debug("Entering run().");
  const realmId = 'history-test-' + process.pid;
  const state = { realmId: realmId, held: true, clock: 1000000,
                  bbsKid: 'aaa', certs: {}, asked: [],
                  keys: keySet({ realm: realmId, current: 'sts-rsa-1' }) };
  const history = instanceOver(state);
  signingHistory.forgetForTests(realmId);
  try {
    // =======================================================================
    // A. A ROW PER KEY, AND NOTHING PRIVATE IN ONE.
    // =======================================================================
    state.certs['sts-rsa-1'] = certificateFor('sts-rsa-1', '01');
    const first = history.observe(realmId, { reason: 'the first look' });
    t.equal(first.recorded, 2,
            'the current RSA key and the BBS key are each recorded once');
    t.equal(first.dropped, 0, 'and nothing is marked dropped on a first look');
    const unitsA = history.unitsOf(realmId);
    t.equal(unitsA.length, 2, 'both units have a history');
    const rsa = history.rowsOf(realmId, 'jose:RS256');
    t.equal(rsa.length, 1, 'the RSA unit has one generation so far');
    t.equal(rsa[0].role, 'current', 'and that generation is the current key');

    // THE CLAIM THE WHOLE FEATURE RESTS ON.
    t.check(!leaks(history.historyView(realmId, { unit: 'jose:RS256' })),
            'no private key material is anywhere in what a reader is handed',
            'searched for the PEM, the BBS secret and the KeyObject');
    t.check(!leaks(rsa) && !leaks(history.rowsOf(realmId, 'bbs:BBS')),
            'nor in the stored rows themselves');

    // The BBS key has no certificate — bbs-2023 keys are not X.509 subjects —
    // and that is reported as none rather than as a missing row.
    const bbs = history.rowsOf(realmId, 'bbs:BBS');
    t.equal(bbs[0].certificate, null,
            'a unit with no certificate records none, and is still a row');

    // =======================================================================
    // B. OBSERVING AGAIN RECORDS NOTHING. A projection that grew on every
    //    read would be a log of reads.
    // =======================================================================
    state.clock += 60000;
    const again = history.observe(realmId, { reason: 'the second look' });
    t.check(again.recorded === 0 && again.updated === 0 && again.dropped === 0,
            'observing an unchanged key set records nothing at all',
            JSON.stringify(again));
    const promotedAt = history.rowsOf(realmId, 'jose:RS256')[0].promotedAt;
    state.clock += 60000;
    history.observe(realmId, {});
    t.equal(history.rowsOf(realmId, 'jose:RS256')[0].promotedAt, promotedAt,
            'and a key seen again in the role it was already in is not ' +
            'restamped');

    // =======================================================================
    // C. A ROTATION: the key that was current is retired and the next one is
    //    current, and BOTH are in the history.
    // =======================================================================
    state.clock += 60000;
    const retiredAt = state.clock;
    state.keys = keySet({ realm: realmId, current: 'sts-rsa-2',
                          standby: [retiredEntry('jose:RS256', 'sts-rsa-1',
                                                 retiredAt,
                                                 retiredAt + 100000)] });
    state.certs['sts-rsa-2'] = certificateFor('sts-rsa-2', '02');
    const rotated = history.observe(realmId, { reason: 'a rotation' });
    t.check(rotated.recorded === 1 && rotated.updated === 1,
            'a rotation records the new key and moves the old one',
            JSON.stringify(rotated));
    const afterRotation = history.rowsOf(realmId, 'jose:RS256');
    t.equal(afterRotation.length, 2, 'the unit now has two generations');
    const byKid = {};
    afterRotation.forEach(function (row) {
      byKid[row.kid] = row;
    });
    t.equal(byKid['sts-rsa-2'].role, 'current', 'the new key is current');
    t.equal(byKid['sts-rsa-1'].role, 'retired', 'and the old one is retired');
    t.equal(byKid['sts-rsa-1'].retiredAt, retiredAt,
            'with the moment the set says it was retired');
    t.equal(byKid['sts-rsa-1'].reason, 'a rotation',
            'and the reason of the ACT that moved it, which is richer than ' +
            'the set\'s own generic word for it');
    t.equal(byKid['sts-rsa-2'].reason, '',
            'while a row whose role did not move in this act takes no ' +
            'reason from it — otherwise every key would be stamped with ' +
            'whatever happened to another one');
    t.check(!leaks(afterRotation),
            'the retired generation carries no private key either, though ' +
            'the standby entry it was read from does');

    // A RE-CERTIFICATION DOES NOT REPLACE WHAT THE ROW CAPTURED, asserted
    // while the key is still in the set — once it is dropped it is never
    // looked at again, so the same assertion after the drop cannot tell a
    // module that keeps the first certificate from one that replaces it.
    state.certs['sts-rsa-1'] = certificateFor('sts-rsa-1', 'FF');
    state.clock += 60000;
    history.observe(realmId, {});
    t.equal(history.rowsOf(realmId, 'jose:RS256')
      .filter(function (row) {
        return row.kid === 'sts-rsa-1';
      })[0].certificate.serialHex, '01',
            'a re-certification does not replace the certificate a row ' +
            'captured: the row is about what vouched for that key while it ' +
            'was live');

    // =======================================================================
    // D. THE DROP — the claim option B is about. The key is gone from the
    //    set; the row and its certificate are not.
    // =======================================================================
    state.clock += 200000;
    state.keys = keySet({ realm: realmId, current: 'sts-rsa-2' });
    const dropped = history.observe(realmId,
                                    { reason: 'dropped past its grace' });
    t.equal(dropped.dropped, 1, 'the key the set no longer holds is dropped');
    const gone = history.rowsOf(realmId, 'jose:RS256')
      .filter(function (row) {
        return row.kid === 'sts-rsa-1';
      })[0];
    t.equal(gone.role, 'dropped', 'its row says so');
    t.equal(gone.droppedAt, state.clock, 'with the moment it happened');
    t.equal(gone.reason, 'dropped past its grace',
            'and why — the reason the act gave');
    t.check(!!gone.certificate &&
            gone.certificate.serialHex === '01' &&
            /BEGIN CERTIFICATE/.test(gone.certificate.certificatePem),
            'AND ITS CERTIFICATE IS STILL THERE, which is the whole of ' +
            'option B: the private key went at the grace and the record of ' +
            'the key did not',
            gone.certificate && gone.certificate.serialHex);
    t.check(!leaks(gone), 'a dropped generation leaks nothing either');
    t.equal(history.rowsOf(realmId, 'jose:RS256').length, 2,
            'and nothing was removed: the history only grows');

    // =======================================================================
    // E. THE READ SIDE.
    // =======================================================================
    const view = history.historyView(realmId, { unit: 'jose:RS256' });
    t.check(view.found && view.total === 2 && view.rows.length === 2,
            'the view answers the named unit\'s whole history');
    t.equal(view.rows[0].kid, 'sts-rsa-1',
            'newest first — the dropped key moved most recently');
    t.check(typeof view.rows[0].droppedAt === 'string' &&
            view.rows[0].verifiesUntil,
            'and its timestamps are ISO strings, as every other view here ' +
            'answers');
    const unknown = history.historyView(realmId, { unit: 'jose:NOSUCH' });
    t.check(unknown.found === false && unknown.rows.length === 0,
            'a unit this realm has no record of is NOT FOUND rather than an ' +
            'empty history, which is a different answer');
    const counted = history.unitsOf(realmId).filter(function (one) {
      return one.unit === 'jose:RS256';
    })[0];
    t.check(counted.generations === 2 && counted.live === 1 &&
            counted.dropped === 1 && counted.withCertificate === 2,
            'the index counts what the unit holds',
            JSON.stringify(counted));

    // A REALM THIS PROCESS HOLDS NO KEYS FOR RECORDS NOTHING — and, crucially,
    // marks nothing dropped: not holding a realm's keys is the ordinary state
    // of a node that has never answered a request in it, and is no evidence
    // that its keys are gone.
    state.held = false;
    const absent = history.observe(realmId, {});
    t.check(absent.recorded === 0 && absent.dropped === 0,
            'a realm whose key set this process does not hold records ' +
            'nothing and drops nothing',
            JSON.stringify(absent));
    t.equal(history.rowsOf(realmId, 'jose:RS256').length, 2,
            'and its history is untouched');
    state.held = true;

    // =======================================================================
    // F. THE REAL GENERATIONS, END TO END. Everything above is a fixture
    //    shaped like a key set; this is the key set this service keeps.
    // =======================================================================
    await realGenerations(t, log);
  } finally {
    signingHistory.forgetForTests(realmId);
  }
  log.debug("Leaving run().");
}

// ---------------------------------------------------------------------------
// The real thing: a realm of its own, its RSA signing unit minted, promoted
// and then dropped through `common/helpers.js`, with the history observed
// after each act by the module the service uses rather than by an instance
// this file built.
// ---------------------------------------------------------------------------
async function realGenerations(t, logger) {
  logger.debug("Entering realGenerations().");
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const realmId = 'sighist' + String(process.pid).slice(-4) +
                  crypto.randomBytes(2).toString('hex');
  const made = realms.create({ id: realmId, name: 'signing history' });
  if (!made || made.ok === false) {
    t.check(false, 'the test realm could be created',
            JSON.stringify(made && made.errors));
    logger.debug("Leaving realGenerations(). No realm.");
    return;
  }
  signingHistory.forgetForTests(realmId);
  try {
    const before = helpers.stsKeysFor.of(realmId);
    signingHistory.observe(realmId, { reason: 'the first look' });
    const firstKid = before.kid;
    const rows = signingHistory.rowsOf(realmId, 'jose:RS256');
    t.check(rows.length === 1 && rows[0].kid === firstKid,
            'the realm\'s real RSA signing key is recorded, by its own kid',
            firstKid);

    // A ROTATION, with a grace this test can outlive.
    const done = await helpers.promoteGenerations(realmId,
      { units: ['jose:RS256'], graceMs: 1000 });
    t.check(done.ok && done.rotated.length === 1,
            'the real unit rotates', JSON.stringify(done.rotated || []));
    signingHistory.observe(realmId, { reason: 'a rotation' });
    const afterKid = helpers.stsKeysFor.of(realmId).kid;
    const two = signingHistory.rowsOf(realmId, 'jose:RS256');
    const roles = {};
    two.forEach(function (row) {
      roles[row.kid] = row.role;
    });
    t.check(two.length >= 2 && roles[firstKid] === 'retired' &&
            roles[afterKid] === 'current',
            'and the history has both generations, the old one retired',
            JSON.stringify(roles));
    t.check(!leaks(two) && !leaks(signingHistory.historyView(realmId,
                                    { unit: 'jose:RS256' })),
            'with no private key material in any of it, from the REAL set');

    // AND THE DROP: past the grace, `retireExpiredGenerations()` takes the
    // private half and the history keeps the row.
    const gone = helpers.retireExpiredGenerations(realmId,
                                                  Date.now() + 60000);
    t.check(gone.ok && (gone.dropped || []).some(function (one) {
      return one.kid === firstKid;
    }), 'the retired key is dropped past its grace',
            JSON.stringify((gone.dropped || []).map(function (one) {
              return one.kid;
            })));
    t.check(!helpers.standbyOf(helpers.stsKeysFor.of(realmId), 'jose:RS256')
      .some(function (one) {
        return one.kid === firstKid;
      }), 'so the key set no longer holds it at all — the private half is ' +
          'gone, which is the rule this feature may not bend');
    signingHistory.observe(realmId, { reason: 'dropped past its grace' });
    const record = signingHistory.rowsOf(realmId, 'jose:RS256')
      .filter(function (row) {
        return row.kid === firstKid;
      })[0];
    t.check(!!record && record.role === 'dropped' &&
            Number(record.droppedAt) > 0,
            'and the record of it survives, marked dropped',
            record && record.reason);
  } finally {
    signingHistory.forgetForTests(realmId);
    // The realm goes: `tests/realm_isolation.js` asserts that only the
    // default realm is left, so a realm left behind fails another file about
    // a service that is correct.
    try {
      realms.remove(realmId);
    } catch (e) {
      logger.debug("Caught in realGenerations(): " + ((e && e.message) || e));
    }
  }
  logger.debug("Leaving realGenerations().");
}

module.exports = {
  name: 'signing_history',
  describe: 'a realm records every signing key it has ever held — the ' +
            'metadata and the certificate, never the private half — and a ' +
            'key dropped past its grace keeps its row',
  run: run
};
