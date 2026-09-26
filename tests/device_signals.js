'use strict';
//
// File: device_signals.js
//
// ===========================================================================
// #164 PHASES 3 AND 4 (2026-09-26), in process: device compliance and the
// MDM feed, and what the device register says over CAEP and RISC.
//
// In a child process, because it loads the whole protocol stack, and in a
// THROWAWAY REALM, because it revokes real certificates, ends real sessions
// and writes real devices. Every Security Event Token is read back off a
// POLL stream the realm holds, so each assertion is on the event exactly as
// a receiver would get it.
//
//   A. THE INDEX: byId(), byKeyThumbprint() and bySecret() answer from the
//      directory's deviceEntryByIndex() and never copy the register; a key
//      added is found, a key removed is not, another realm's is not.
//   B. COMPLIANCE → CAEP device-compliance-change: CAEP section 3.5.1's two
//      values (unknown sent as not-compliant, so unknown → not-compliant is
//      no event), initiating_entity by source, reason_admin a language map,
//      the complex subject { user, device } with the device as iss_sub.
//   C. RISK → CAEP risk-level-change, principal DEVICE: previous_level only
//      where there was one, and a level outside CAEP's three refused.
//   D. CREDENTIALS → CAEP credential-change: a JWK key created and deleted
//      (this service's device-key type), a Native SSO secret created and
//      revoked (its device-secret type).
//   E. COMPROMISE: the session the device authenticated ENDED (and its CAEP
//      session-revoked names the device), the EST certificate REVOKED for
//      keyCompromise, the secret revoked, risk HIGH, and RISC
//      credential-compromise and sessions-revoked with the account AND the
//      device in the subject.
//   F. REMOVAL: the certificate revoked for cessationOfOperation, RISC
//      sessions-revoked.
//   G. STREAM SUBJECTS: SSF 1.0 section 8.1.3.1 — a stream that added
//      { device } gets that device's events and not another's; the
//      section's own three examples.
//   H. THE MDM FEED: device:compliance is a protected scope (refused to a
//      client that does not declare it, kept for one that does), the
//      DEVICE_COMPLIANCE role is held off it and ADMIN_WRITE is not, the
//      gate recognises only its path, and a batch by thumbprint, by
//      certificate and by id applies with an unknown device refused alone.
//   I. THE TEST CONTROL: answers in development, 403 in product.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'device_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.DS_ROOT;
  const OUT = process.env.DS_OUT;
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
    const pki = require(ROOT + '/common/pki');
    const revocation = require(ROOT + '/common/pki_revocation');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const devices = require(ROOT + '/common/devices');
    const core = require(ROOT + '/common/cert_enrollment');
    const authn = require(ROOT + '/authn/authn');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const scopePolicy = require(ROOT + '/common/scope_policy');
    const roles = require(ROOT + '/common/roles');
    const applications = require(ROOT + '/common/applications');
    const devicesAdmin = require(ROOT + '/admin-ui/devices_admin');
    const stsCrypto = require(ROOT + '/common/crypto');
    const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
    const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
    const RUN = nodeCrypto.randomBytes(3).toString('hex');
    ['ssf.enabled', 'caep.enabled', 'risc.enabled', 'caep.autoEmit',
     'risc.autoEmit'].forEach(function (key) {
      config.setOverride(key, 'true');
    });
    if (!pki.hasRoot()) {
      await pki.start({});
    }
    const realm = realms.create({ id: 'dsig-' + RUN,
                                  name: 'device signals ' + RUN }).realm;
    await realms.run(realm, async function () {
      await pki.ensureScope(realms.currentId());
      const ALICE = 'dsig-alice-' + RUN;
      const BOB = 'dsig-bob-' + RUN;
      const HOST = 'dsig-host-' + RUN;
      [ALICE, BOB].forEach(function (name) {
        ldap.createUser(name, { invent: false, attributes: {} });
      });
      applications.createApplication({ identifier: HOST,
        protocols: ['oauth2'], fields: { oauthClientId: HOST } });
      const everything = streams.createStream({
        delivery: { method: streams.DELIVERY_POLL },
        events_requested: [
          CAEP + 'device-compliance-change', CAEP + 'risk-level-change',
          CAEP + 'credential-change', CAEP + 'session-revoked',
          RISC + 'credential-compromise', RISC + 'sessions-revoked'] },
        { issuer: 'https://sts.test/realm/dsig', principal: 'dsig-all',
          audience: 'https://receiver.test/all' }).stream;
      note(!!everything, 'precondition: a poll stream taking the six ' +
           'device-related types', '');
      const drained = [];
      async function drain() {
        await settle(250);
        const got = [];
        for (let i = 0; i < 10; i += 1) {
          const answer = streams.poll(streams.getStream(everything.stream_id),
                                      { maxEvents: 100 });
          const jtis = Object.keys(answer.sets || {});
          jtis.forEach(function (jti) {
            got.push(payloadOf(answer.sets[jti]));
          });
          if (jtis.length) {
            streams.poll(streams.getStream(everything.stream_id),
                         { ack: jtis, maxEvents: 0 });
          }
          if (!answer.moreAvailable) {
            break;
          }
        }
        got.forEach(function (one) {
          drained.push(one);
        });
        return got;
      }
      function ofType(list, uri, deviceId) {
        return list.filter(function (set) {
          const sub = set.sub_id || {};
          return set.events && set.events[uri] &&
            (!deviceId || (sub.device && sub.device.sub === deviceId));
        });
      }

      // --- A. the index ----------------------------------------------------
      const pair = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      const laptop = devices.create({ owner: ALICE, label: 'dsig laptop',
                                      keys: [{ kind: 'jwk', value: jwk }] },
                                    'dsig-admin');
      note(laptop.ok, 'precondition: a person\'s device with a JWK key',
           JSON.stringify(laptop.errors));
      const id = laptop.device.id;
      const thumb = stsCrypto.jwkThumbprint(jwk);
      const asked = [];
      const realStore = credentials.deviceStore;
      credentials.deviceStore = function (operation, args) {
        asked.push(operation);
        return realStore.call(credentials, operation, args);
      };
      const byId = devices.byId(id);
      const byThumb = devices.byKeyThumbprint(thumb, 'jwk');
      const byAnyKind = devices.byKeyThumbprint(thumb);
      credentials.deviceStore = realStore;
      note(byId && byId.id === id && byThumb && byThumb.id === id &&
           byAnyKind && byAnyKind.id === id &&
           asked.indexOf('listDeviceEntries') < 0 &&
           asked.indexOf('deviceEntryByIndex') >= 0,
           'A1. byId() and byKeyThumbprint() answer from the index and never ' +
           'copy the register', JSON.stringify(asked));
      note(devices.byKeyThumbprint(thumb, 'x509') === null &&
           devices.byKeyThumbprint('no-such-' + RUN) === null,
           'A2. the kind narrows it, and an unknown key finds nothing');
      const second = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
      const added = devices.addKey(id, { kind: 'jwk', value: second },
                                   'dsig-admin');
      const secondThumb = stsCrypto.jwkThumbprint(second);
      note(added.ok &&
           (devices.byKeyThumbprint(secondThumb, 'jwk') || {}).id === id,
           'A3. a key added is found at once — the index follows the ' +
           'directory, not a copy');
      devices.removeKey(id, added.key.id, 'dsig-admin');
      note(devices.byKeyThumbprint(secondThumb, 'jwk') === null,
           'A4. and a key removed is not');
      const other = realms.create({ id: 'dsig-o-' + RUN, name: 'o' }).realm;
      realms.run(other, function () {
        note(devices.byId(id) === null &&
             devices.byKeyThumbprint(thumb, 'jwk') === null,
             'A5. another realm\'s index does not hold this realm\'s device');
      });
      await drain();

      // --- B. compliance -----------------------------------------------------
      devices.setCompliance(id, 'not-compliant', 'mdm', 'dsig-mdm', 'posture');
      const quiet = await drain();
      note(ofType(quiet, CAEP + 'device-compliance-change').length === 0,
           'B1. unknown → not-compliant sends NOTHING: CAEP has no unknown, ' +
           'and unknown is sent as not-compliant', String(quiet.length));
      const up = devices.setCompliance(id, 'compliant', 'mdm', 'dsig-mdm', '');
      const upSets = ofType(await drain(), CAEP + 'device-compliance-change',
                            id);
      const upEvent = upSets.length
        ? upSets[0].events[CAEP + 'device-compliance-change'] : {};
      const upSub = upSets.length ? upSets[0].sub_id : {};
      note(up.ok && up.signalled && upSets.length === 1 &&
           upEvent.previous_status === 'not-compliant' &&
           upEvent.current_status === 'compliant' &&
           upEvent.initiating_entity === 'system' &&
           upEvent.reason_admin &&
           typeof upEvent.reason_admin.en === 'string' &&
           typeof upEvent.event_timestamp === 'number',
           'B2. not-compliant → compliant from the MDM feed: both statuses, ' +
           'initiating_entity system, reason_admin a language map, ' +
           'event_timestamp a number', JSON.stringify(upSets));
      note(upSub.format === 'complex' && upSub.device &&
           upSub.device.format === 'iss_sub' && upSub.device.sub === id &&
           upSub.user && upSub.user.format === 'iss_sub' &&
           upSub.user.sub === helpers.subjectForName(ALICE) &&
           upSub.device.iss === upSub.user.iss && !upSub.session,
           'B3. the subject is SSF section 3.3\'s complex subject: the ' +
           'device as iss_sub under this realm\'s issuer, and its owner',
           JSON.stringify(upSub));
      devices.setCompliance(id, 'compliant', 'admin', 'dsig-admin', '');
      note(ofType(await drain(), CAEP + 'device-compliance-change').length ===
           0, 'B4. compliant → compliant sends nothing');
      devices.setCompliance(id, 'unknown', 'admin', 'dsig-admin', 'withdrawn');
      const downSets = ofType(await drain(), CAEP + 'device-compliance-change',
                              id);
      const down = downSets.length ? downSets[0].events[CAEP +
                                              'device-compliance-change'] : {};
      note(downSets.length === 1 && down.previous_status === 'compliant' &&
           down.current_status === 'not-compliant' &&
           down.initiating_entity === 'admin' &&
           down.reason_admin.en === 'withdrawn',
           'B5. an administrator withdrawing the vouch (→ unknown) goes out ' +
           'as compliant → not-compliant, initiating_entity admin, the ' +
           'reason given', JSON.stringify(down));
      const timeline = devices.timeline(2);
      note(timeline.totals.compliance.mdm >= 2 &&
           timeline.totals.compliance.admin >= 1,
           'B6. Monitoring counts compliance changes by source',
           JSON.stringify(timeline.totals.compliance));

      // --- C. risk -----------------------------------------------------------
      const medium = devices.setRiskLevel(id, 'MEDIUM', 'UNAPPROVED_SOFTWARE');
      const high = devices.setRiskLevel(id, 'HIGH', 'MALWARE');
      const riskSets = ofType(await drain(), CAEP + 'risk-level-change', id);
      const r1 = riskSets[0] ? riskSets[0].events[CAEP +
                                                'risk-level-change'] : {};
      const r2 = riskSets[1] ? riskSets[1].events[CAEP +
                                                'risk-level-change'] : {};
      note(medium.ok && high.ok && riskSets.length === 2 &&
           r1.principal === 'DEVICE' && r1.current_level === 'MEDIUM' &&
           !('previous_level' in r1) &&
           r1.risk_reason === 'UNAPPROVED_SOFTWARE' &&
           r2.current_level === 'HIGH' && r2.previous_level === 'MEDIUM',
           'C1. risk-level-change, principal DEVICE: previous_level only ' +
           'where there was one', JSON.stringify([r1, r2]));
      note(errorCodes.codeOf(devices.setRiskLevel(id, 'SEVERE')) ===
           'STS-DEVICE-0033' && devices.byId(id).riskLevel === 'HIGH',
           'C2. a level outside CAEP\'s three is refused');
      devices.setRiskLevel(id, '', 'forgotten');
      note(ofType(await drain(), CAEP + 'risk-level-change').length === 0,
           'C3. forgetting the level sends nothing — CAEP has no level for ' +
           'unassessed');

      // --- D. credentials ----------------------------------------------------
      const third = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
      const k3 = devices.addKey(id, { kind: 'jwk', value: third, label: 'k3' },
                                'dsig-admin');
      devices.removeKey(id, k3.key.id, 'dsig-admin');
      const minted = devices.issueForSession({ username: ALICE,
        clientId: HOST, sessionId: 'dsig-sess-' + RUN, label: 'native' });
      devices.revokeSecret(minted.secret);
      const credSets = ofType(await drain(), CAEP + 'credential-change');
      const changes = credSets.map(function (set) {
        const e = set.events[CAEP + 'credential-change'];
        return e.credential_type + '/' + e.change_type;
      });
      note(changes.indexOf('urn:iya:sts:credential-type:device-key/create') >=
           0 && changes.indexOf('urn:iya:sts:credential-type:device-key/' +
                                'delete') >= 0 &&
           changes.indexOf('urn:iya:sts:credential-type:device-secret/' +
                           'create') >= 0 &&
           changes.indexOf('urn:iya:sts:credential-type:device-secret/' +
                           'revoke') >= 0,
           'D1. a device key created and deleted, and a Native SSO secret ' +
           'created and revoked, each a credential-change', changes.join(', '));
      const keyEvent = credSets.filter(function (set) {
        return set.events[CAEP + 'credential-change'].friendly_name === 'k3';
      })[0];
      note(!!keyEvent && keyEvent.sub_id.device &&
           keyEvent.sub_id.device.sub === id && keyEvent.sub_id.user,
           'D2. its subject names the device and the owner',
           JSON.stringify(keyEvent && keyEvent.sub_id));

      // --- E. compromise -----------------------------------------------------
      const certPair = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'P-256' });
      const issued = await core.issue({ family: 'est', profile: 'device',
        principal: { kind: 'person', id: ALICE, admin: false, hasEntry: true,
                     via: 'test' },
        target: { kind: 'person', id: ALICE },
        publicKeyPem: certPair.publicKey.export({ type: 'spki',
                                                 format: 'pem' }),
        requested: {}, attestations: [], keySource: 'client', via: 'test' });
      note(issued.ok, 'precondition: EST issued a device certificate',
           JSON.stringify(issued.errors || issued.why));
      const phoneId = issued.device;
      const phone = devices.byId(phoneId);
      const certKey = phone.keys[0];
      const serial = certKey.material.serial;
      const session = authn.startSession({ headers: [], set: function () {},
                                           req: null }, ALICE, ['pwd'], '1',
                                         'Test', { key: 'k-dsig-' + RUN,
                                                   cookie: false });
      const held = authn.sessions.get(session.id);
      held.events[held.events.length - 1].registeredDevice = { id: phoneId };
      const unrelated = authn.startSession({ headers: [],
        set: function () {}, req: null }, ALICE, ['pwd'], '1', 'Test',
        { key: 'k-dsig-u-' + RUN, cookie: false });
      await drain();
      const compromised = devices.setStatus(phoneId, 'compromised',
                                            'dsig-admin', 'stolen',
                                            { initiatingEntity: 'admin' });
      const sets = await drain();
      note(compromised.ok && compromised.sessionsEnded === 1 &&
           authn.sessionById(session.id) === null &&
           authn.sessionById(unrelated.id) !== null,
           'E1. the session the device authenticated is ENDED, and the ' +
           'person\'s other session is not', JSON.stringify(compromised));
      const revoked = revocation.isRevoked(realms.currentId(), 'est', serial);
      note(compromised.certificatesRevoked === 1 && revoked &&
           revoked.reason === 'keyCompromise',
           'E2. the certificate EST issued it is REVOKED for keyCompromise, ' +
           'so the CRL and OCSP say so', JSON.stringify(revoked));
      const after = devices.byId(phoneId);
      note(after.status === 'compromised' && !after.secretHash &&
           after.riskLevel === 'HIGH' && after.keys.length === 1,
           'E3. its Native SSO secret is revoked, its risk level is HIGH, ' +
           'and it keeps its key — the register still recognises it');
      const sessionRevoked = ofType(sets, CAEP + 'session-revoked', phoneId);
      note(sessionRevoked.length === 1 &&
           sessionRevoked[0].sub_id.session &&
           sessionRevoked[0].sub_id.user &&
           sessionRevoked[0].events[CAEP + 'session-revoked']
             .initiating_entity === 'admin',
           'E4. CAEP session-revoked for the ended session carries the ' +
           'device member beside user and session', JSON.stringify(
             sessionRevoked.map(function (s) { return s.sub_id; })));
      const compromise = ofType(sets, RISC + 'credential-compromise', phoneId);
      const types = compromise.map(function (set) {
        return set.events[RISC + 'credential-compromise'].credential_type;
      }).sort();
      note(types.join(',') === 'x509' && !compromised.secretRevoked &&
           compromise[0].sub_id.format === 'complex' &&
           compromise[0].sub_id.user,
           'E5. RISC credential-compromise for each kind of credential it ' +
           'held — its certificate (it holds no Native SSO secret) — naming ' +
           'the account and the device',
           JSON.stringify(compromise.map(function (s) { return s.sub_id; })));
      const plural = ofType(sets, RISC + 'sessions-revoked', phoneId);
      note(plural.length === 1 && plural[0].sub_id.user &&
           plural[0].sub_id.device.sub === phoneId,
           'E6. RISC sessions-revoked names the account AND the device',
           JSON.stringify(plural.map(function (s) { return s.sub_id; })));
      const risk = ofType(sets, CAEP + 'risk-level-change', phoneId);
      note(risk.length === 1 && risk[0].events[CAEP + 'risk-level-change']
             .current_level === 'HIGH' &&
           risk[0].events[CAEP + 'risk-level-change'].principal === 'DEVICE',
           'E7. and CAEP risk-level-change raises it to HIGH');
      const restored = devices.setStatus(phoneId, 'active', 'dsig-admin',
                                         'found');
      note(restored.ok && devices.byId(phoneId).riskLevel === '' &&
           revocation.isRevoked(realms.currentId(), 'est', serial),
           'E8. restoring it puts back the level the compromise raised ' +
           '(none), and nothing revoked comes back');
      await drain();
      const native = devices.issueForSession({ username: ALICE,
        clientId: HOST, sessionId: 'dsig-sess3-' + RUN, label: 'native 2' });
      await drain();
      const nativeHit = devices.setStatus(native.device.id, 'compromised',
                                          'dsig-admin', 'lost');
      const nativeSets = await drain();
      const nativeTypes = ofType(nativeSets, RISC + 'credential-compromise',
                                 native.device.id).map(function (set) {
        return set.events[RISC + 'credential-compromise'].credential_type;
      });
      note(nativeHit.secretRevoked &&
           devices.bySecret(native.secret) === null &&
           nativeTypes.join(',') ===
             'urn:iya:sts:credential-type:device-secret' &&
           ofType(nativeSets, CAEP + 'credential-change', native.device.id)
             .some(function (set) {
               return set.events[CAEP + 'credential-change'].change_type ===
                      'revoke';
             }),
           'E9. a compromised Native SSO device loses its secret — ' +
           'credential-change revoke and RISC credential-compromise of this ' +
           'service\'s device-secret type', nativeTypes.join(','));

      // --- F. removal --------------------------------------------------------
      const tabletPair = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'P-256' });
      const tablet = await core.issue({ family: 'est', profile: 'device',
        principal: { kind: 'person', id: BOB, admin: false, hasEntry: true,
                     via: 'test' },
        target: { kind: 'person', id: BOB },
        publicKeyPem: tabletPair.publicKey.export({ type: 'spki',
                                                   format: 'pem' }),
        requested: {}, attestations: [], keySource: 'client', via: 'test' });
      const tabletSerial = devices.byId(tablet.device).keys[0].material.serial;
      await drain();
      const gone = devices.remove(tablet.device, BOB, BOB);
      const removedSets = await drain();
      const tabletRevoked = revocation.isRevoked(realms.currentId(), 'est',
                                                 tabletSerial);
      note(gone.ok && tabletRevoked &&
           tabletRevoked.reason === 'cessationOfOperation',
           'F1. removing a device revokes its certificate for ' +
           'cessationOfOperation', JSON.stringify(tabletRevoked));
      note(ofType(removedSets, RISC + 'sessions-revoked', tablet.device)
             .length === 1 &&
           ofType(removedSets, CAEP + 'credential-change', tablet.device)
             .some(function (set) {
               const e = set.events[CAEP + 'credential-change'];
               return e.credential_type === 'x509' &&
                      e.change_type === 'delete' && e.x509_serial &&
                      e.initiating_entity === 'user';
             }),
           'F2. and sends RISC sessions-revoked, and credential-change ' +
           'delete for its certificate, initiated by its owner');

      // --- G. stream subjects ------------------------------------------------
      const iss = upSub.device.iss;
      const byDevice = streams.createStream({
        delivery: { method: streams.DELIVERY_POLL },
        events_requested: [CAEP + 'device-compliance-change'] },
        { issuer: 'https://sts.test/realm/dsig', principal: 'dsig-dev',
          audience: 'https://receiver.test/dev' }).stream;
      const addedSubject = streams.addSubject(byDevice.stream_id, {
        format: 'complex', device: { format: 'iss_sub', iss: iss, sub: id } },
        true);
      const otherDevice = devices.create({ owner: BOB, label: 'other' },
                                         'dsig-admin');
      devices.setCompliance(id, 'compliant', 'admin', 'dsig-admin', '');
      devices.setCompliance(otherDevice.device.id, 'compliant', 'admin',
                            'dsig-admin', '');
      await settle(300);
      const devPoll = streams.poll(streams.getStream(byDevice.stream_id),
                                   { maxEvents: 50 });
      const devSets = Object.keys(devPoll.sets || {}).map(function (jti) {
        return payloadOf(devPoll.sets[jti]);
      });
      note(addedSubject.ok && devSets.length === 1 &&
           devSets[0].sub_id.device.sub === id,
           'G1. a stream that ADDED { device } gets that device\'s event and ' +
           'not another\'s (SSF 1.0 section 8.1.3.1)', JSON.stringify(
             devSets.map(function (s) { return s.sub_id; })));
      await drain();
      const email = function (e) {
        return { format: 'email', email: e };
      };
      note(streams.complexSubjectsMatch(
             { format: 'complex', tenant: { format: 'opaque', id: 't' } },
             { format: 'complex', tenant: { format: 'opaque', id: 't' },
               user: email('j@x') }) &&
           streams.complexSubjectsMatch(
             { format: 'complex', user: email('j@x'),
               device: { format: 'ip-addresses',
                         'ip-addresses': ['10.0.0.1'] } },
             { format: 'complex', user: email('j@x') }) &&
           !streams.complexSubjectsMatch(
             { format: 'complex', user: email('j@x'),
               group: { format: 'did', url: 'did:example:1' } },
             { format: 'complex', user: email('j@x'),
               group: { format: 'did', url: 'did:example:9' } }) &&
           !streams.complexSubjectsMatch(
             { format: 'complex', tenant: { format: 'opaque', id: 't' } },
             { format: 'complex', user: email('j@x') }),
           'G2. section 8.1.3.1\'s three examples, and no member in common ' +
           'is not a match');

      // --- H. the MDM feed ---------------------------------------------------
      const MDM = 'dsig-mdm-' + RUN;
      const NOT_MDM = 'dsig-notmdm-' + RUN;
      applications.createApplication({ identifier: MDM,
        protocols: ['oauth2'], fields: { oauthClientId: MDM,
          oauthAllowedScope: ['device:compliance'] } });
      applications.createApplication({ identifier: NOT_MDM,
        protocols: ['oauth2'], fields: { oauthClientId: NOT_MDM,
          oauthAllowedScope: ['openid'] } });
      const undeclared = scopePolicy.judge('device:compliance', NOT_MDM);
      const declaredJudge = scopePolicy.judge('device:compliance', MDM);
      config.setOverride('global.mode', 'product');
      const undeclaredProduct = scopePolicy.judge('device:compliance',
                                                  NOT_MDM);
      config.clearOverride('global.mode');
      note(scopePolicy.isProtected('device:compliance') &&
           undeclared.protectedRefused.indexOf('device:compliance') >= 0 &&
           undeclaredProduct.protectedRefused.indexOf('device:compliance') >=
             0,
           'H1. device:compliance is a PROTECTED scope, refused to a client ' +
           'that does not declare it, in both modes',
           JSON.stringify(undeclared));
      note(declaredJudge.kept.indexOf('device:compliance') >= 0 &&
           scopePolicy.declares(MDM, 'device:compliance'),
           'H2. and kept for one that does', JSON.stringify(declaredJudge));
      const held2 = roles.rolesOf({ kind: 'application', name: MDM,
        authenticated: true, scopes: ['device:compliance'] });
      note(held2.indexOf('DEVICE_COMPLIANCE') >= 0 &&
           held2.indexOf('ADMIN_WRITE') < 0 &&
           held2.indexOf('ADMIN_READ') < 0,
           'H3. the scope holds DEVICE_COMPLIANCE and no admin role',
           held2.join(','));
      const certPem = phone.keys[0].material.certificate;
      const feed = devicesAdmin.mdmFeed({ reports: [
        { thumbprint: thumb, keyKind: 'jwk', status: 'not-compliant',
          reason: 'jailbroken' },
        { certificate: certPem, status: 'compliant' },
        { id: 'no-such-device-' + RUN, status: 'compliant' },
        { id: otherDevice.device.id, status: 'sideways' }] }, MDM, 'mdm');
      note(feed.ok && feed.applied === 2 && feed.refused === 2 &&
           feed.results[0].id === id && feed.results[1].id === phoneId &&
           errorCodes.codeOf(feed.results[2]) === 'STS-DEVICE-0007' &&
           errorCodes.codeOf(feed.results[3]) === 'STS-DEVICE-0011',
           'H4. a batch by key thumbprint and by certificate applies, and an ' +
           'unknown device and an unknown status are refused on their own',
           JSON.stringify(feed));
      const change = devices.byId(id).complianceChange;
      note(change.source === 'mdm' && change.actor === MDM &&
           change.reason === 'jailbroken',
           'H5. recorded with source mdm and the client as actor',
           JSON.stringify(change));
      note(errorCodes.codeOf(devicesAdmin.mdmFeed({ reports: [] }, MDM)) ===
           'STS-DEVICE-0034',
           'H6. an empty batch is refused whole');

      // --- I. the test control -----------------------------------------------
      const routes = {};
      const fakeApp = { get: function () {}, post: function (p, fn) {
        routes[p] = fn;
      } };
      new devicesAdmin.DevicesAdmin(devicesAdmin.DevicesAdmin.defaultDeps
        ? devicesAdmin.DevicesAdmin.defaultDeps() : {})
        .registerRoutes(fakeApp);
      function call(body) {
        const res = { statusCode: 200, body: null, headers: {},
          set: function (k, v) { this.headers[k] = v; return this; },
          status: function (c) { this.statusCode = c; return this; },
          json: function (b) { this.body = b; return this; },
          locals: {} };
        routes['/devices/test/compliance']({ body: JSON.stringify(body),
          headers: { 'content-type': 'application/json' }, method: 'POST',
          query: {} }, res);
        return res;
      }
      const dev = call({ id: id, status: 'compliant' });
      note(dev.statusCode === 200 && dev.body.applied === 1 &&
           devices.byId(id).complianceChange.source === 'test-control',
           'I1. in development the test control sets compliance with no ' +
           'credential, source test-control', JSON.stringify(dev.body));
      config.setOverride('global.mode', 'product');
      const prod = call({ id: id, status: 'not-compliant' });
      config.clearOverride('global.mode');
      note(prod.statusCode === 403 &&
           devices.byId(id).compliance === 'compliant',
           'I2. in product it is refused 403 and nothing changes',
           JSON.stringify(prod.body));
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
  const out = path.join(os.tmpdir(), 'device-signals-' + process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', DS_ROOT: ROOT,
                                  DS_OUT: out }),
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
  name: 'device_signals',
  describe: '#164 phases 3 and 4: device compliance and the MDM feed under ' +
            'device:compliance, the test control\'s mode split, CAEP ' +
            'device-compliance-change, risk-level-change (DEVICE) and ' +
            'credential-change, a compromise ending sessions and revoking ' +
            'certificates with RISC credential-compromise and ' +
            'sessions-revoked, stream subjects matching on a device, and ' +
            'the device index',
  run: run
};
