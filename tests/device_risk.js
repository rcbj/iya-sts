'use strict';
//
// File: device_risk.js
//
// ===========================================================================
// #164 PHASE 5 (2026-09-26), in process: the registered device in risk
// scoring (decision 4) — the signals, the device feature and the device's own
// risk level.
//
// In a child process, because it loads the whole protocol stack, and in a
// THROWAWAY REALM, because it writes real devices, real assessments and real
// Security Event Tokens. The engine is handed the recognition fact exactly as
// `authn/authn.ts` hands it (`registeredDevice`), and section G proves that
// authn does hand it.
//
//   A. THE INDEX: `byCredentialId()` and `holdsAny()` answer from the
//      directory's index, and an owner moved to somebody else is followed.
//   B. `unregistered-device`: not for a person who registered nothing, not
//      before `risk.minimumHistory`, yes for a device owner signing in with
//      none (or with somebody else's), and yes for anybody where the realm
//      sets `devices.expectRegistered`.
//   C. `non-compliant-device` and `compromised-device` (HIGH on its own).
//   D. THE LOWERING FACTORS: `compliant-device` (×0.8) for a self-asserted
//      device and `compliant-attested-device` (×0.5) for an attested one,
//      each scoring below the same sign-in without it — and neither making
//      a first sign-in scored on its own.
//   E. THE DEVICE FEATURE: the person's own registered device is counted
//      under `registered:<id>` and is never `new-device`, where a browser
//      fingerprint never seen is.
//   F. THE DEVICE'S RISK LEVEL: set to the sign-in's level with CAEP
//      risk-level-change (principal DEVICE) only on a change; a compromised
//      device's HIGH is held.
//   G. AUTHN HANDS IT OVER: a sign-in whose WebAuthn credential is linked
//      to a device is assessed with that device on the assessment.
//   H. THE PAGE: Monitoring → Risk draws the device beside the browser.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'device_risk',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.DR_ROOT;
  const OUT = process.env.DR_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function settle(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms || 150);
    });
  }
  function payloadOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
      .toString('utf8'));
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const devices = require(ROOT + '/common/devices');
    const recognition = require(ROOT + '/common/device_recognition');
    const authn = require(ROOT + '/authn/authn');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const engine = require(ROOT + '/risk/risk_engine');
    const stsCrypto = require(ROOT + '/common/crypto');
    const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
    const RUN = nodeCrypto.randomBytes(3).toString('hex');
    ['ssf.enabled', 'caep.enabled', 'caep.autoEmit'].forEach(function (key) {
      config.setOverride(key, 'true');
    });
    const realm = realms.create({ id: 'drisk-' + RUN,
                                  name: 'device risk ' + RUN }).realm;
    await realms.run(realm, async function () {
      const REALM = realms.currentId();
      const ALICE = 'drisk-alice-' + RUN;
      const BOB = 'drisk-bob-' + RUN;
      const CAROL = 'drisk-carol-' + RUN;
      [ALICE, BOB, CAROL].forEach(function (name) {
        ldap.createUser(name, { invent: false, attributes: {} });
      });
      const helpers = require(ROOT + '/common/helpers');
      const subOf = function (name) {
        return String(helpers.userFor(name).sub);
      };
      const stream = streams.createStream({
        delivery: { method: streams.DELIVERY_POLL },
        events_requested: [CAEP + 'risk-level-change'] },
        { issuer: 'https://sts.test/realm/drisk', principal: 'drisk-all',
          audience: 'https://receiver.test/drisk' }).stream;
      async function drain() {
        await settle(300);
        const got = [];
        for (let i = 0; i < 10; i += 1) {
          const answer = streams.poll(streams.getStream(stream.stream_id),
                                      { maxEvents: 100 });
          const jtis = Object.keys(answer.sets || {});
          jtis.forEach(function (jti) {
            got.push(payloadOf(answer.sets[jti]));
          });
          if (jtis.length) {
            streams.poll(streams.getStream(stream.stream_id),
                         { ack: jtis, maxEvents: 0 });
          }
          if (!answer.moreAvailable) {
            break;
          }
        }
        return got;
      }
      function deviceLevelEvents(list, id) {
        return list.filter(function (set) {
          const e = set.events && set.events[CAEP + 'risk-level-change'];
          const sub = set.sub_id || {};
          return e && e.principal === 'DEVICE' &&
            ((sub.device && sub.device.sub === id) || sub.sub === id);
        }).map(function (set) {
          return set.events[CAEP + 'risk-level-change'];
        });
      }
      const signalsOf = function (a) {
        return (a && a.signals || []).map(function (s) {
          return s.signal;
        });
      };
      const has = function (a, id) {
        return signalsOf(a).indexOf(id) >= 0;
      };
      const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 ' +
        'Safari/537.36';
      function signIn(name, fact, extra) {
        const e = extra || {};
        return engine.assess({
          realm: REALM, subject: subOf(name), username: name,
          sessionId: '', door: 'the device risk test', clientId: 'c',
          context: Object.assign({ address: '192.0.2.40',
                                   uaFingerprint: 'fp-drisk',
                                   credential: { kind: 'password' } },
                                 e.context || {}),
          registeredDevice: fact || null, userAgent: UA });
      }

      // --- A. the index ----------------------------------------------------
      const pub = function () {
        return nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
          .publicKey.export({ format: 'jwk' });
      };
      const aliceJwk = pub();
      const laptop = devices.create({ owner: ALICE, label: 'drisk laptop',
        keys: [{ kind: 'jwk', value: aliceJwk }] }, 'drisk-admin');
      note(laptop.ok, 'precondition: Alice registers a device with a JWK',
           JSON.stringify(laptop.errors));
      const id = laptop.device.id;
      const thumb = stsCrypto.jwkThumbprint(aliceJwk);
      credentials.addKey(ALICE, { credentialId: 'drisk-cred-' + RUN,
        publicKeyJwk: pub(), signCount: 0, label: 'platform key',
        attachment: 'platform' }, 'mfa');
      const linked = devices.addKey(id, { kind: 'webauthn',
                                          value: 'drisk-cred-' + RUN });
      const asked = [];
      const realStore = credentials.deviceStore;
      credentials.deviceStore = function (operation, args) {
        asked.push(operation);
        return realStore.call(credentials, operation, args);
      };
      const byCred = devices.byCredentialId('drisk-cred-' + RUN);
      const aliceHolds = devices.holdsAny(ALICE);
      const carolHolds = devices.holdsAny(CAROL);
      credentials.deviceStore = realStore;
      note(linked.ok && byCred && byCred.id === id && aliceHolds &&
           !carolHolds && asked.indexOf('listDeviceEntries') < 0,
           'A1. byCredentialId() and holdsAny() answer from the index, ' +
           'never copying the register', JSON.stringify(asked));
      const spare = devices.create({ owner: BOB, label: 'drisk spare',
        keys: [{ kind: 'jwk', value: pub() }] }, 'drisk-admin');
      note(spare.ok && devices.holdsAny(BOB), 'precondition: Bob holds one');
      devices.update(spare.device.id, { owner: CAROL, ownerKind: 'person' },
                     'drisk-admin');
      note(!devices.holdsAny(BOB) && devices.holdsAny(CAROL),
           'A2. a device given to somebody else moves with its owner — a ' +
           'stale owner hit rebuilds rather than answering for the old one');
      devices.remove(spare.device.id, undefined, 'drisk-admin');
      note(!devices.holdsAny(CAROL), 'A3. and a removed one is gone');

      // --- B. unregistered-device ------------------------------------------
      const aliceFirst = await signIn(ALICE, null);
      note(aliceFirst && aliceFirst.level === 'UNSCORED' &&
           !has(aliceFirst, 'unregistered-device'),
           'B1. a device owner\'s FIRST sign-in without it is not an ' +
           'unregistered-device: an absence waits for risk.minimumHistory',
           JSON.stringify(signalsOf(aliceFirst)));
      config.setOverride('risk.minimumHistory', 1);
      const carolPlain = await signIn(CAROL, null);
      await signIn(CAROL, null);
      const carolAgain = await signIn(CAROL, null);
      note(carolAgain && !has(carolAgain, 'unregistered-device') &&
           !has(carolPlain, 'unregistered-device'),
           'B2. a person who registered nothing is never unregistered-device',
           JSON.stringify(signalsOf(carolAgain)));
      const aliceNone = await signIn(ALICE, null);
      note(aliceNone && has(aliceNone, 'unregistered-device') &&
           aliceNone.signals.filter(function (s) {
             return s.signal === 'unregistered-device';
           })[0].factor === 2,
           'B3. a person who registered a device, signing in with none, ' +
           'is unregistered-device (×2)', JSON.stringify(signalsOf(aliceNone)));
      const bobDevice = devices.create({ owner: BOB, label: 'drisk bob',
        keys: [{ kind: 'jwk', value: pub() }] }, 'drisk-admin');
      const bobFact = recognition.recognize({
        dpopJkt: bobDevice.device.keys[0].thumbprint, subject: ALICE });
      const aliceOnBobs = await signIn(ALICE, bobFact);
      note(bobFact && bobFact.ownerMatches === false &&
           has(aliceOnBobs, 'unregistered-device') &&
           !has(aliceOnBobs, 'compliant-device'),
           'B4. somebody else\'s device is not the person\'s own: still ' +
           'unregistered-device, and never a lowering factor',
           JSON.stringify(signalsOf(aliceOnBobs)));
      config.setOverride('devices.expectRegistered', true);
      const carolExpected = await signIn(CAROL, null);
      config.clearOverride('devices.expectRegistered');
      note(has(carolExpected, 'unregistered-device'),
           'B5. devices.expectRegistered makes it fire for anybody',
           JSON.stringify(signalsOf(carolExpected)));

      // --- C. non-compliant and compromised ---------------------------------
      devices.setCompliance(id, 'not-compliant', 'admin', 'drisk-admin');
      const nc = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      note(has(nc, 'non-compliant-device') &&
           !has(nc, 'unregistered-device') && !has(nc, 'compliant-device'),
           'C1. a not-compliant device of the person\'s own is ' +
           'non-compliant-device (×3), and not unregistered',
           JSON.stringify(signalsOf(nc)));
      const compromisedFact = Object.assign(recognition.recognize({
        dpopJkt: thumb, subject: ALICE }), { status: 'compromised',
                                             compliance: 'compliant' });
      const cp = await signIn(ALICE, compromisedFact);
      note(has(cp, 'compromised-device') && cp.level === 'HIGH' &&
           !has(cp, 'compliant-device') &&
           !has(cp, 'compliant-attested-device'),
           'C2. a compromised device is compromised-device (×50) — HIGH on ' +
           'its own — and never "compliant", whatever its compliance says',
           cp && cp.level + ' ' + JSON.stringify(signalsOf(cp)));

      // --- D. the lowering factors -----------------------------------------
      devices.setCompliance(id, 'compliant', 'admin', 'drisk-admin');
      const without = await signIn(ALICE, null);
      const selfAsserted = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      const attestedFact = Object.assign(recognition.recognize({
        dpopJkt: thumb, subject: ALICE }), { attestation: 'attested' });
      const attested = await signIn(ALICE, attestedFact);
      const factorOf = function (a, sig) {
        return (a.signals.filter(function (s) {
          return s.signal === sig;
        })[0] || {}).factor;
      };
      note(has(selfAsserted, 'compliant-device') &&
           factorOf(selfAsserted, 'compliant-device') === 0.8 &&
           has(attested, 'compliant-attested-device') &&
           factorOf(attested, 'compliant-attested-device') === 0.5 &&
           !has(attested, 'compliant-device'),
           'D1. a compliant device of the person\'s own lowers the score: ' +
           '×0.8 self-asserted, ×0.5 attested, one or the other',
           JSON.stringify([signalsOf(selfAsserted), signalsOf(attested)]));
      note(selfAsserted.score < without.score * 0.8 * 1.0001 &&
           attested.score < selfAsserted.score,
           'D2. and each scores BELOW the same sign-in without it, the ' +
           'attested one lowest', [without.score, selfAsserted.score,
                                   attested.score].join(' > '));
      config.setOverride('risk.minimumHistory', 50);
      const lonely = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      config.setOverride('risk.minimumHistory', 1);
      note(lonely && lonely.level === 'UNSCORED' &&
           has(lonely, 'compliant-device'),
           'D3. a lowering factor alone never makes an UNSCORED sign-in ' +
           'scored', lonely && lonely.level);

      // --- E. the device feature -------------------------------------------
      const fingerprinted = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }),
        { context: { device: 'fp-never-seen-' + RUN } });
      const plainNew = await signIn(ALICE, null,
        { context: { device: 'fp-never-seen-2-' + RUN } });
      const model = (fingerprinted.signals || [])[0] || {};
      note(!has(fingerprinted, 'new-device') && has(plainNew, 'new-device') &&
           model.device && model.device.id === id && model.device.own,
           'E1. the person\'s own registered device is never new-device ' +
           '(a fingerprint never seen still is, without one), and the ' +
           'assessment records the device', JSON.stringify([
             signalsOf(fingerprinted), signalsOf(plainNew), model.device]));
      const counted = await require(ROOT + '/risk/risk_store').featureCounts(
        REALM, subOf(ALICE), [{ feature: 'device', value: 'registered:' +
                                                           id }], false);
      note(counted.length === 1 && counted[0].count >= 1,
           'E2. the history counts it under registered:<id>',
           JSON.stringify(counted));
      note(engine.riskOf(fingerprinted).device.registered === id,
           'E3. and the session\'s risk carries the registered id',
           JSON.stringify(engine.riskOf(fingerprinted).device));

      // --- F. the device's own risk level ----------------------------------
      await drain();
      config.setOverride('risk.signalFactors', 'compliant-device=0.000001');
      const low = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      await settle(100);
      const afterLow = devices.byId(id);
      const lowSets = deviceLevelEvents(await drain(), id);
      note(low.level === 'LOW' && afterLow.riskLevel === 'LOW' &&
           afterLow.riskChange.source === 'risk',
           'F1. after a LOW sign-in the device proved, the device is LOW, ' +
           'set by risk scoring', JSON.stringify(afterLow.riskChange));
      const again = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      const quiet = deviceLevelEvents(await drain(), id);
      config.setOverride('risk.signalFactors', 'compliant-device=100000');
      const high = await signIn(ALICE, recognition.recognize({
        dpopJkt: thumb, subject: ALICE }));
      const highSets = deviceLevelEvents(await drain(), id);
      config.clearOverride('risk.signalFactors');
      note(again.level === 'LOW' && quiet.length === 0 &&
           high.level === 'HIGH' && devices.byId(id).riskLevel === 'HIGH' &&
           highSets.length === 1 && highSets[0].current_level === 'HIGH' &&
           highSets[0].previous_level === 'LOW',
           'F2. CAEP risk-level-change (principal DEVICE) only when the ' +
           'level MOVES: LOW again says nothing, HIGH says LOW → HIGH',
           JSON.stringify([lowSets.length, quiet, highSets]));
      devices.setStatus(id, 'compromised', 'drisk-admin', 'lost',
                        { initiatingEntity: 'admin' });
      const held = devices.setRiskLevel(id, 'LOW', 'a quiet sign-in',
                                        { source: 'risk' });
      note(held.ok && held.changed === false &&
           devices.byId(id).riskLevel === 'HIGH',
           'F3. risk scoring never lowers a compromised device\'s HIGH',
           JSON.stringify(held));
      devices.setStatus(id, 'active', 'drisk-admin', 'found',
                        { initiatingEntity: 'admin' });

      // --- G. authn hands the device over ----------------------------------
      config.setOverride('risk.minimumHistory', 1);
      const before = (await engine.view(REALM, { subject: subOf(ALICE),
                                                 days: 1 })).assessments.total;
      const started = authn.startSession({ headers: [], set: function () {},
                                           req: null }, ALICE, ['hwk'], '1',
        'Test', { credential: { kind: 'webauthn', id: 'drisk-cred-' + RUN },
                  cookie: false });
      await settle(600);
      const view = await engine.view(REALM, { subject: subOf(ALICE),
                                              days: 1 });
      const newest = view.assessments.rows[0] || {};
      const event = started && authn.sessionById(started.id)
        ? authn.registeredDeviceOf(authn.sessionById(started.id)) : null;
      note(started && event && event.id === id && event.via === 'webauthn' &&
           event.ownerMatches === true && view.assessments.total > before &&
           newest.signals && newest.signals[0].device &&
           newest.signals[0].device.id === id,
           'G1. a sign-in with a linked WebAuthn credential is recognised ' +
           'as the person\'s own device on its event, and assessed with it',
           JSON.stringify({ event: event, device: newest.signals &&
                                                  newest.signals[0].device }));

      // --- H. the page -------------------------------------------------------
      const riskAdmin = require(ROOT + '/admin-ui/risk_admin');
      let html = '';
      try {
        const RiskAdmin = riskAdmin.RiskAdmin;
        const inst = new RiskAdmin(RiskAdmin.defaultDeps());
        // The page draws its two pagers off `riskView()`'s raw paging (the
        // Risk page's paging, which reached develop beside #164), so the
        // view handed in carries them as `riskView()` does.
        const adminViews = require(ROOT + '/admin-core/admin_views');
        const drawn = { assessments: view.assessments, subjects: [],
                        signals: view.signals };
        Object.defineProperty(drawn, 'assessmentsPagingRaw', {
          value: adminViews.pagingOf({}, view.assessments.total,
                                     { name: 'assessments',
                                       noun: 'assessments' }) });
        Object.defineProperty(drawn, 'subjectsPagingRaw', {
          value: adminViews.pagingOf({}, 0, { name: 'subjects',
                                              noun: 'people' }) });
        html = inst.assessmentsHtml({ query: {} }, drawn);
      } catch (e) {
        html = 'threw: ' + (e && e.message);
      }
      note(html.indexOf('registered device') >= 0 &&
           html.indexOf('/admin/devices?device=' + id) >= 0,
           'H1. Monitoring → Risk draws the registered device on the ' +
           'assessment, linked to its page', html.slice(0, 300));
    });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'device-risk-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', DR_ROOT: ROOT,
                                  DR_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!findings) {
    t.check(false, 'the child process reported its findings',
            String(result.stderr || result.error || '').slice(-2000));
    log.debug("Leaving run(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'device_risk',
  describe: '#164 phase 5: the registered device in risk scoring — ' +
            'unregistered-device and its scope, non-compliant-device, ' +
            'compromised-device, the two lowering factors, the device ' +
            'feature replacing the fingerprint, the device\'s own risk ' +
            'level with CAEP risk-level-change (DEVICE), and the index ' +
            'lookups the sign-in path uses',
  run: run
};
