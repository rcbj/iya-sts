// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_unregistered_instances.js
//
// ===========================================================================
// AN UNREGISTERED KEY AS AN INSTANCE OF A REGISTERED GNAP CLIENT (#1216).
//
// rcbj, 2026-10-30, the default: a browser application makes a key per
// browser, so a key nobody registered is accepted as an instance of the
// registered GNAP client its request's `class_id` names — when that client
// lists a registered gnapFinishUri — and such an instance never skips the
// approval page (`GnapGrants.classInstanceOf()`).
//
//   I1. product: an unknown key naming an eligible client is identified as an
//       instance of it, and nothing is written to the entry;
//   I2. product: a class_id naming no GNAP client, a resource server, an entry
//       development filed on first sight, or a client with no registered
//       finish URI is 401 invalid_client (STS-GNAP-0906); no class_id is
//       STS-GNAP-0082 as before;
//   I3. gnap.unregisteredInstances off: the eligible claim is refused
//       STS-GNAP-0082, as before #1216;
//   I4. development: the eligible claim is an instance too, and no gnap-*
//       entry is created for the key; with no class_id one still is;
//   I5. an instance_id handed to such a key resolves to the same client and
//       is still an instance; with the setting off it no longer resolves
//       (STS-GNAP-0080);
//   I6. a remembered approval does not stand in for the page for such an
//       instance, while it does for the registered key of the same client;
//   I7. a registered key is unchanged: identified, and not an instance;
//   I8. #1219: such an instance's grant is live at use (grantProblem and
//       tokenProblem) although its key is not on the entry, while another
//       grant bound to a key the entry does not name is STS-GNAP-0731;
//   I9. #1219: with gnap.unregisteredInstances off it is refused at use
//       (STS-GNAP-0907);
//   I10. #1219: an edit of the entry's key fields ends a grant bound to a
//        key it no longer names, and leaves the instance's grant alone.
//
// IN PROCESS, in a throwaway realm, with the key proof stubbed: what is held
// is who a proved key belongs to, decided after the proof verifies
// (unregistered_applications.js G1 does the same).
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
// The directory the application register lives in. Loaded here, not left to
// a test that happens to sort earlier in the same process (#1219).
require('../ldap/ldap_server');

const log = require('bunyan').createLogger({
  name: 'gnap_unregistered_instances',
  level: process.env.LOG_LEVEL || 'info' });

const FINISH = 'https://ui-spa.example/callback';

// A GNAP JWK carries alg and kid (STS-GNAP-0012 otherwise).
function keyObject() {
  log.debug("Entering keyObject().");
  const jwk = Object.assign(nodeCrypto.generateKeyPairSync('ed25519')
    .publicKey.export({ format: 'jwk' }), { alg: 'EdDSA',
                                            kid: nodeCrypto.randomUUID() });
  log.debug("Leaving keyObject().");
  return { proof: 'httpsig', jwk: jwk };
}

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { method: 'POST', path: '/gnap', originalUrl: '/gnap', query: {},
           headers: { host: 'sts.ui.example' }, protocol: 'https',
           get: function (name) {
             return this.headers[String(name).toLowerCase()];
           } };
}

function withSettings(settings, fn) {
  log.debug("Entering withSettings().");
  Object.keys(settings).forEach(function (key) {
    config.setOverride(key, settings[key]);
  });
  const done = function () {
    Object.keys(settings).forEach(function (key) {
      config.clearOverride(key);
    });
  };
  return Promise.resolve().then(fn).then(function (out) {
    done();
    log.debug("Leaving withSettings().");
    return out;
  }, function (e) {
    log.debug("Caught in withSettings(): " + ((e && e.message) || e));
    done();
    throw e;
  });
}

async function cases(t, suffix) {
  log.debug("Entering cases().");
  const grantsModule = require('../gnap/gnap_grants');
  const store = require('../gnap/gnap_store');
  const SPA = 'ui-spa-' + suffix;
  const NO_FINISH = 'ui-nofinish-' + suffix;
  const RS = 'ui-rs-' + suffix;
  const SEEN = 'ui-seen-' + suffix;
  const registeredKey = keyObject();
  const made = [
    applications.createApplication({ identifier: SPA, kind: 'gnap-client',
      protocols: ['gnap'], fields: { gnapFinishUri: [FINISH],
                                     gnapSkipInteraction: 'TRUE' } }),
    applications.createApplication({ identifier: NO_FINISH,
      kind: 'gnap-client', protocols: ['gnap'], fields: {} }),
    applications.createApplication({ identifier: RS,
      kind: 'gnap-resource-server', protocols: ['gnap'],
      fields: { gnapFinishUri: [FINISH],
                gnapResourceServerUri: ['https://ui-rs.example/api'] } }),
    applications.createApplication({ identifier: 'ui-keyed-' + suffix,
      kind: 'gnap-client', protocols: ['gnap'],
      fields: { gnapKey: JSON.stringify(registeredKey),
                gnapFinishUri: [FINISH] } })
  ];
  config.setOverride('global.mode', 'development');
  try {
    applications.seen({ identifier: SEEN, kind: 'gnap-client',
                        protocol: 'GNAP', counts: false,
                        fields: { gnapFinishUri: FINISH },
                        note: 'filed by ' + __filename });
  } finally {
    config.clearOverride('global.mode');
  }
  t.check(made.every(function (one) { return one && one.ok; }) &&
          !!applications.get(SEEN) && !applications.get(SEEN).registeredBy,
          'precondition: registered clients, a resource server and a ' +
          'seen-only client', JSON.stringify(made));

  const deps = grantsModule.GnapGrants.defaultDeps();
  deps.proof = Object.assign({}, deps.proof, {
    verifyRequestOnce: function () {
      return Promise.resolve({ ok: true });
    } });
  const grants = new grantsModule.GnapGrants(deps);
  const identify = function (m, member, settings) {
    log.debug("Entering identify(). " + m);
    return withSettings(Object.assign({ 'global.mode': m }, settings || {}),
                        async function () {
      const out = await grants.identifyCaller(fakeReq(), {},
        Object.assign({ display: null, classId: null, reference: null,
                        key: null }, member), 'gnap-client');
      log.debug("Leaving identify().");
      return { ok: !!out.ok, code: out.errorCode || '',
               error: out.gnapError || '', status: out.status || 0,
               app: out.app ? out.app.identifier : '',
               classInstance: !!out.classInstance, created: !!out.created };
    });
  };

  // I1.
  const browserKey = keyObject();
  const before = applications.get(SPA);
  const i1 = await identify('product', { key: browserKey, classId: SPA });
  const after = applications.get(SPA);
  t.check(i1.ok && i1.app === SPA && i1.classInstance && !i1.created,
          'I1. product: an unknown key whose class_id names a registered ' +
          'client with a registered finish URI is an instance of it',
          JSON.stringify(i1));
  t.check(!(after.fields && after.fields.gnapKey) &&
          JSON.stringify((after.fields || {}).gnapKeyIdentity || null) ===
          JSON.stringify((before.fields || {}).gnapKeyIdentity || null),
          'I1b. and nothing about the key is written to the entry',
          JSON.stringify(after.fields));

  // I2.
  const refusals = await Promise.all([
    identify('product', { key: keyObject(), classId: 'ui-nobody-' + suffix }),
    identify('product', { key: keyObject(), classId: RS }),
    identify('product', { key: keyObject(), classId: SEEN }),
    identify('product', { key: keyObject(), classId: NO_FINISH })
  ]);
  t.check(refusals.every(function (r) {
    return !r.ok && r.code === 'STS-GNAP-0906' &&
      r.error === 'invalid_client' && r.status === 401;
  }), 'I2. product: a class_id naming no GNAP client, a resource server, a ' +
      'seen-only client, or a client with no registered finish URI is 401 ' +
      'invalid_client (STS-GNAP-0906)', JSON.stringify(refusals));
  const bare = await identify('product', { key: keyObject() });
  t.check(!bare.ok && bare.code === 'STS-GNAP-0082',
          'I2b. and an unknown key with no class_id is STS-GNAP-0082, as ' +
          'before', JSON.stringify(bare));

  // I3.
  const off = await identify('product', { key: keyObject(), classId: SPA },
                             { 'gnap.unregisteredInstances': false });
  t.check(!off.ok && off.code === 'STS-GNAP-0082',
          'I3. gnap.unregisteredInstances off: the same claim is refused ' +
          'STS-GNAP-0082, as before #1216', JSON.stringify(off));

  // I4.
  const countBefore = applications.list().length;
  const dev = await identify('development', { key: keyObject(),
                                              classId: SPA });
  const countAfter = applications.list().length;
  t.check(dev.ok && dev.app === SPA && dev.classInstance && !dev.created &&
          countAfter === countBefore,
          'I4. development: the eligible claim is an instance too, and no ' +
          'gnap-* entry is created for the key', JSON.stringify(dev));
  const devBare = await identify('development', { key: keyObject() });
  t.check(devBare.ok && devBare.created && !devBare.classInstance,
          'I4b. while an unknown key with no class_id is still given an ' +
          'entry on first sight', JSON.stringify(devBare));
  if (devBare.app) {
    applications.deleteApplication(devBare.app);
  }

  // I5.
  const instanceId = 'ui-inst-' + suffix;
  const instanceKey = keyObject();
  store.putInstance(instanceId, { identifier: SPA, key: instanceKey,
                                  classInstance: true });
  const byReference = await identify('product', { reference: instanceId });
  const referenceOff = await identify('product', { reference: instanceId },
    { 'gnap.unregisteredInstances': false });
  t.check(byReference.ok && byReference.app === SPA &&
          byReference.classInstance,
          'I5. an instance_id handed to such a key resolves to the same ' +
          'client and is still an instance', JSON.stringify(byReference));
  t.check(!referenceOff.ok && referenceOff.code === 'STS-GNAP-0080',
          'I5b. and with the setting off it no longer resolves ' +
          '(STS-GNAP-0080)', JSON.stringify(referenceOff));

  // I6.
  const right = { type: 'ui-type', actions: ['read'] };
  const digest = grants.digestTokenOf(right);
  const consentDeps = grantsModule.GnapGrants.defaultDeps();
  consentDeps.consent = Object.assign({}, consentDeps.consent, {
    consentsOf: function () {
      return [{ client: SPA, scope: digest }];
    } });
  const consenting = new grantsModule.GnapGrants(consentDeps);
  const grantFor = function (classInstance) {
    return { requirement: { interaction: 'skippable' },
             client: { identifier: SPA, classInstance: classInstance },
             request: { tokens: [{ access: [right] }], subject: null } };
  };
  const remembered = await withSettings({ 'gnap.consentRequired': true,
                                          'gnap.rememberApprovals': true },
                                        function () {
    return [consenting.rememberedFor(grantFor(false), 'ui-person'),
            consenting.rememberedFor(grantFor(true), 'ui-person')];
  });
  t.check(remembered[0] === true && remembered[1] === false,
          'I6. a remembered approval skips the page for the client\'s ' +
          'registered key, and not for an unregistered instance',
          JSON.stringify(remembered));

  // I7.
  const keyed = await identify('product', { key: registeredKey,
                                            classId: SPA });
  t.check(keyed.ok && keyed.app === 'ui-keyed-' + suffix &&
          !keyed.classInstance,
          'I7. a registered key is identified by its key, whatever class_id ' +
          'it sends, and is not an instance', JSON.stringify(keyed));

  // I8-I10 (#1219).
  const revocation = require('../gnap/gnap_revocation');
  const instanceGrant = store.newGrant({ client: { identifier: SPA,
    key: browserKey, keyIdentity: 'ui-browser-' + suffix,
    classInstance: true }, ro: null, request: { tokens: [] } });
  const strayGrant = store.newGrant({ client: { identifier: SPA,
    key: keyObject(), classInstance: false }, ro: null,
    request: { tokens: [] } });
  const live = [revocation.grantProblem(instanceGrant),
                revocation.tokenProblem({ grantId: instanceGrant.id }),
                revocation.grantProblem(strayGrant)];
  t.check(live[0] === null && live[1] === null && live[2] &&
          live[2].code === 'STS-GNAP-0731',
          'I8. an unregistered instance\'s grant and its token are live at ' +
          'use although its key is not on the entry, while a grant bound to ' +
          'a key the entry does not name is STS-GNAP-0731',
          JSON.stringify(live));
  const offProblem = await withSettings({ 'gnap.unregisteredInstances':
                                          false }, function () {
    return [revocation.grantProblem(instanceGrant),
            revocation.tokenProblem({ grantId: instanceGrant.id })];
  });
  t.check(offProblem.every(function (one) {
    return one && one.code === 'STS-GNAP-0907';
  }), 'I9. with gnap.unregisteredInstances off it is refused at use ' +
      '(STS-GNAP-0907)', JSON.stringify(offProblem));
  const swept = revocation.endForClientKeyChange(SPA,
    { why: 'test: the entry\'s key fields edited', actor: 'test',
      via: __filename, initiatingEntity: 'admin' });
  const afterSweep = [store.getGrant(instanceGrant.id),
                      store.getGrant(strayGrant.id)];
  const FINALIZED = store.STATE.FINALIZED;
  t.check(swept === 1 && afterSweep[0] && afterSweep[0].state !== FINALIZED &&
          afterSweep[1] && afterSweep[1].state === FINALIZED,
          'I10. an edit of the entry\'s key fields ends the grant bound to a ' +
          'key it no longer names, and leaves the unregistered instance\'s ' +
          'grant alone', JSON.stringify({ swept: swept,
            instance: afterSweep[0] && afterSweep[0].state,
            stray: afterSweep[1] && afterSweep[1].state }));

  [SPA, NO_FINISH, RS, SEEN, 'ui-keyed-' + suffix].forEach(function (one) {
    applications.deleteApplication(one);
  });
  log.debug("Leaving cases().");
}

function run(t) {
  log.debug("Entering run().");
  const suffix = nodeCrypto.randomBytes(4).toString('hex');
  const id = 'ui-' + suffix;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  let done;
  try {
    done = realms.run(made.realm, function () {
      return cases(t, suffix);
    });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  }
  log.debug("Leaving run().");
  return Promise.resolve(done).then(function () {
    realms.remove(id);
  }, function (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  });
}

module.exports = {
  name: 'gnap_unregistered_instances',
  describe: 'an unregistered GNAP key whose class_id names a registered ' +
            'client is an instance of it, by default, and never skips the ' +
            'approval page, and its grant is not refused at use for a key ' +
            'the entry never held (#1216, #1219)',
  run: run
};
