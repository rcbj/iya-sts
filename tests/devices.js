'use strict';
//
// File: devices.js
//
// ===========================================================================
// THE DEVICE REGISTER'S MODEL (#164 phase 1, #218, 2026-09-26), in process,
// against the real directory. `native_sso.js` beside it holds what #130 built
// — the Native SSO door, the bound at a sign-in, revocation — and this file
// holds what an ADMINISTRATOR does and what every later phase reads:
//
//   1. create: a person-owned and an APPLICATION-owned device, and the
//      refusals — no owner, an unknown one, an unknown owner kind, a label
//      that is not one line, an unknown platform, an unknown application;
//   2. the bounds: devices.maxPerPerson REFUSES an administrator's create
//      (nothing is evicted), devices.maxPerApplication likewise, and
//      devices.maxKeysPerDevice;
//   3. keys: a certificate's thumbprint is SHA-256 over its
//      SubjectPublicKeyInfo (checked against node's own export), a JWK's is
//      RFC 7638, a private JWK and a symmetric key are refused, a key one
//      device holds cannot be another's, a WebAuthn key must be one its
//      owner enrolled; every key is `admin`-proven and self-asserted, and
//      removal by id;
//   4. the entry: the derived attributes (the thumbprint index, the
//      attestation level) and the JSON values, as the directory holds them;
//   5. update: a new owner takes the device WITHOUT its Native SSO secret;
//      the application list is replaced;
//   6. compliance and status: the closed lists and the previous value;
//   7. list and page: every filter, ANDed, a value outside a list matching
//      nothing, and a page past the end clamped;
//   8. counts and the timeline: by owner kind, compliance, attestation, key
//      kind and enrolment; created, removed and evicted events per day;
//   9. the console's action door refuses an unknown action in the sentence
//      the parity jobs read (seven since #164 phase 3 added set-compliance
//      and set-status), and never forwards a proof or an attestation.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const credentials = require('../common/credentials');
const devices = require('../common/devices');
const errorCodes = require('../common/error_codes');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({ name: 'devices',
  level: process.env.LOG_LEVEL || 'info' });

const OVERRIDDEN = ['devices.maxPerPerson', 'devices.maxPerApplication',
                    'devices.maxKeysPerDevice'];

function run(t) {
  log.debug("Entering run().");
  try {
    body(t);
  } finally {
    OVERRIDDEN.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

function code(result) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(result);
}

function publicJwk() {
  log.debug("Entering publicJwk().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  log.debug("Leaving publicJwk().");
  return { pub: pair.publicKey.export({ format: 'jwk' }),
           priv: pair.privateKey.export({ format: 'jwk' }) };
}

function body(t) {
  log.debug("Entering body().");
  // The pid AND a random suffix: a search for the bare pid (`q: STAMP`) —
  // "17" in a container — also matched any other file's device whose random
  // id or thumbprint happened to contain it, and failed 7a by chance.
  const STAMP = String(process.pid) + 'x' +
                nodeCrypto.randomBytes(3).toString('hex');
  const ALICE = 'dev-alice-' + STAMP;
  const BOB = 'dev-bob-' + STAMP;
  const HOST = 'dev-host-' + STAMP;
  const APP = 'dev-app-' + STAMP;
  ldap.createUser(ALICE, { invent: false,
    attributes: { givenName: 'Alice', sn: 'Device' } });
  ldap.createUser(BOB, { invent: false,
    attributes: { givenName: 'Bob', sn: 'Device' } });
  const made = [
    applications.createApplication({ identifier: HOST,
      protocols: ['oauth2'], fields: { oauthClientId: HOST } }),
    applications.createApplication({ identifier: APP,
      protocols: ['oauth2', 'oidc'], fields: { oauthClientId: APP } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the two applications were created',
          JSON.stringify(made));

  // --- 1. create -----------------------------------------------------------
  t.log.info('=== 1. create ===');
  const laptop = devices.create({ owner: ALICE, label: 'Alice laptop',
    platform: 'macos', model: 'MacBook', os: 'macOS 16',
    applications: [APP] }, 'the-admin');
  const hostDevice = devices.create({ owner: HOST, ownerKind: 'application',
    label: 'Build host', platform: 'linux' }, 'the-admin');
  t.check(laptop.ok && laptop.device.ownerKind === 'person' &&
          /^uid=/i.test(laptop.device.owner) &&
          /,ou=devices,/.test(laptop.device.dn) &&
          laptop.device.enrolment.method === 'admin' &&
          laptop.device.enrolment.actor === 'the-admin' &&
          laptop.device.applications.length === 1 &&
          laptop.device.platform === 'macos' &&
          laptop.device.compliance === 'unknown' &&
          laptop.device.attestation === 'self-asserted' &&
          laptop.device.status === 'active',
          '1a. an administrator registers a person\'s device',
          JSON.stringify(laptop));
  t.check(hostDevice.ok && hostDevice.device.ownerKind === 'application' &&
          devices.ownerOf(hostDevice.device.owner).name === HOST &&
          devices.ownerOf(hostDevice.device.owner).kind === 'application',
          '1b. and an APPLICATION\'s — one owner, of either kind',
          JSON.stringify(hostDevice));
  t.check(code(devices.create({ label: 'x' })) === 'STS-DEVICE-0001' &&
          code(devices.create({ owner: 'nobody-' + STAMP })) ===
            'STS-DEVICE-0001' &&
          code(devices.create({ owner: ALICE, ownerKind: 'robot' })) ===
            'STS-DEVICE-0001' &&
          code(devices.create({ owner: ALICE, ownerKind: 'application' })) ===
            'STS-DEVICE-0001',
          '1c. no owner, an unknown one, an unknown kind, or a person named ' +
          'as an application: refused');
  t.check(code(devices.create({ owner: ALICE, label: 'two\nlines' })) ===
            'STS-DEVICE-0010' &&
          code(devices.create({ owner: ALICE, platform: 'amiga' })) ===
            'STS-DEVICE-0010' &&
          code(devices.create({ owner: ALICE, applications: ['no-app-' +
                                                              STAMP] })) ===
            'STS-DEVICE-0012' &&
          code(devices.create({ owner: ALICE, method: 'native-sso' })) ===
            'STS-DEVICE-0010',
          '1d. a label on two lines, an unknown platform, an unknown ' +
          'application, and native-sso as an administrator\'s method');

  // --- 2. the bounds -------------------------------------------------------
  t.log.info('=== 2. the bounds ===');
  config.setOverride('devices.maxPerPerson', 1);
  const full = devices.create({ owner: ALICE, label: 'one too many' });
  t.check(code(full) === 'STS-DEVICE-0002' &&
          devices.listFor(ALICE).length === 1 &&
          !!devices.byId(laptop.device.id),
          '2a. an administrator\'s create at devices.maxPerPerson is refused ' +
          'and nothing is evicted', JSON.stringify(full));
  config.clearOverride('devices.maxPerPerson');
  config.setOverride('devices.maxPerApplication', 1);
  t.check(code(devices.create({ owner: HOST, ownerKind: 'application' })) ===
            'STS-DEVICE-0003',
          '2b. devices.maxPerApplication, likewise');
  config.clearOverride('devices.maxPerApplication');

  // --- 3. keys -------------------------------------------------------------
  t.log.info('=== 3. keys ===');
  const cert = stsCrypto.selfSignedRsaCertificate({ commonName: 'dev-' +
                                                    STAMP, bits: 2048 });
  const spki = nodeCrypto.createHash('sha256').update(
    new nodeCrypto.X509Certificate(cert.certPem).publicKey
      .export({ type: 'spki', format: 'der' })).digest('base64url');
  const x509 = devices.addKey(laptop.device.id, { kind: 'x509',
    value: cert.certPem, label: 'device certificate' }, 'the-admin');
  t.check(x509.ok && x509.key.thumbprint === spki &&
          x509.key.proof === 'admin' &&
          x509.key.attestation.level === 'self-asserted' &&
          x509.key.material.certificate === cert.certPem.trim() &&
          /dev-/.test(x509.key.material.subject),
          '3a. a certificate\'s thumbprint is SHA-256 over its ' +
          'SubjectPublicKeyInfo', JSON.stringify(x509.key || x509));
  const ec = publicJwk();
  const jwk = devices.addKey(laptop.device.id, { kind: 'jwk',
    value: JSON.stringify(ec.pub) }, 'the-admin');
  t.check(jwk.ok && jwk.key.thumbprint === stsCrypto.jwkThumbprint(ec.pub) &&
          jwk.key.material.jwk.d === undefined,
          '3b. a JWK\'s is RFC 7638 — DPoP\'s jkt');
  t.check(code(devices.addKey(laptop.device.id, { kind: 'jwk',
            value: ec.priv })) === 'STS-DEVICE-0004' &&
          code(devices.addKey(laptop.device.id, { kind: 'jwk',
            value: { kty: 'oct', k: 'c2VjcmV0' } })) === 'STS-DEVICE-0004' &&
          code(devices.addKey(laptop.device.id, { kind: 'x509',
            value: 'not a certificate' })) === 'STS-DEVICE-0004' &&
          code(devices.addKey(laptop.device.id, { kind: 'rsa' })) ===
            'STS-DEVICE-0004',
          '3c. a private JWK, a symmetric key, an unreadable certificate ' +
          'and an unknown kind are refused');
  t.check(code(devices.addKey(hostDevice.device.id, { kind: 'jwk',
            value: ec.pub })) === 'STS-DEVICE-0005' &&
          code(devices.addKey(laptop.device.id, { kind: 'jwk',
            value: ec.pub })) === 'STS-DEVICE-0005',
          '3d. a key one device holds is nobody else\'s — nor the same ' +
          'device\'s twice');
  t.check(devices.byKeyThumbprint(spki).id === laptop.device.id &&
          devices.byKeyThumbprint(spki, 'jwk') === null,
          '3e. the device a thumbprint belongs to');
  const enrolled = credentials.addKey(ALICE, {
    credentialId: 'dev-cred-' + STAMP,
    publicKeyJwk: publicJwk().pub, signCount: 0, label: 'platform key',
    attachment: 'platform' }, 'mfa');
  const webauthn = devices.addKey(laptop.device.id, { kind: 'webauthn',
    value: 'dev-cred-' + STAMP });
  t.check(enrolled.ok && webauthn.ok &&
          webauthn.key.material.credentialId === 'dev-cred-' + STAMP &&
          webauthn.key.material.attachment === 'platform' &&
          code(devices.addKey(laptop.device.id, { kind: 'webauthn',
            value: 'not-enrolled' })) === 'STS-DEVICE-0015' &&
          code(devices.addKey(hostDevice.device.id, { kind: 'webauthn',
            value: 'dev-cred-' + STAMP })) === 'STS-DEVICE-0015',
          '3f. a WebAuthn key is one its OWNER enrolled; an application ' +
          'owns none', JSON.stringify(webauthn));
  config.setOverride('devices.maxKeysPerDevice', 3);
  t.check(code(devices.addKey(laptop.device.id, { kind: 'jwk',
            value: publicJwk().pub })) === 'STS-DEVICE-0006',
          '3g. devices.maxKeysPerDevice');
  config.clearOverride('devices.maxKeysPerDevice');
  t.check(code(devices.removeKey(laptop.device.id, 'k-none')) ===
            'STS-DEVICE-0008' &&
          devices.removeKey(laptop.device.id, webauthn.key.id).ok &&
          devices.byId(laptop.device.id).keys.length === 2,
          '3h. a key is removed by its id');

  // --- 4. the entry --------------------------------------------------------
  t.log.info('=== 4. the entry ===');
  const entry = (credentials.deviceStore('listDeviceEntries', []) || [])
    .filter(function (e) {
      return (e.attributes.cn || [])[0] === laptop.device.id;
    })[0];
  const a = entry ? entry.attributes : {};
  t.check(!!entry && (a.stsdeviceownerkind || [])[0] === 'person' &&
          (a.stsdevicekey || []).length === 2 &&
          (a.stsdevicekeythumbprint || []).indexOf('x509:' + spki) >= 0 &&
          (a.stsdeviceattestation || [])[0] === 'self-asserted' &&
          JSON.parse(a.stsdeviceenrolment[0]).method === 'admin' &&
          (a.stsdeviceplatform || [])[0] === 'macos' &&
          (a.objectclass || []).indexOf('stsDevice') >= 0,
          '4a. the entry carries the owner kind, one JSON value per key, the ' +
          'thumbprint index, the derived attestation level and the ' +
          'enrolment', JSON.stringify(a).slice(0, 600));

  // --- 5. update -----------------------------------------------------------
  t.log.info('=== 5. update ===');
  const sso = devices.issueForSession({ username: ALICE, clientId: APP,
    sessionId: 'dev-sess-' + STAMP, label: 'phone' });
  t.check(sso.ok && devices.byId(sso.device.id).enrolment.method ===
            'native-sso', 'precondition: a Native SSO device of Alice\'s');
  const moved = devices.update(sso.device.id, { owner: BOB, label: 'Bob ' +
                                                'phone' }, 'the-admin');
  const after = devices.byId(sso.device.id);
  t.check(moved.ok && moved.changed.indexOf('owner') >= 0 &&
          devices.ownerOf(after.owner).name === BOB &&
          after.secretHash === '' && after.session === '' &&
          !devices.bySecret(sso.secret) && after.label === 'Bob phone',
          '5a. a new owner takes the device WITHOUT its Native SSO secret',
          JSON.stringify(moved));
  const apps = devices.update(laptop.device.id, { applications: [HOST] });
  t.check(apps.ok && devices.byId(laptop.device.id).applications.length ===
            1 && devices.ownerOf(devices.byId(laptop.device.id)
              .applications[0]).name === HOST &&
          code(devices.update('no-such-device', { label: 'x' })) ===
            'STS-DEVICE-0007',
          '5b. the applications list is replaced; an unknown device is ' +
          'refused');

  // --- 6. compliance and status --------------------------------------------
  t.log.info('=== 6. compliance and status ===');
  const compliant = devices.setCompliance(laptop.device.id, 'compliant',
                                          'admin', 'the-admin', 'checked');
  const back = devices.setCompliance(laptop.device.id, 'not-compliant',
                                     'mdm', 'feed', 'disk not encrypted');
  const held = devices.byId(laptop.device.id);
  t.check(compliant.ok && compliant.previous === 'unknown' && back.ok &&
          back.previous === 'compliant' &&
          held.compliance === 'not-compliant' &&
          held.complianceChange.previous === 'compliant' &&
          held.complianceChange.source === 'mdm' &&
          code(devices.setCompliance(laptop.device.id, 'fine', 'admin')) ===
            'STS-DEVICE-0011' &&
          code(devices.setCompliance(laptop.device.id, 'compliant',
                                     'rumour')) === 'STS-DEVICE-0011',
          '6a. compliance keeps its previous value and its source; a value ' +
          'or a source outside the lists is refused');
  t.check(devices.setStatus(hostDevice.device.id, 'compromised', 'x').ok &&
          devices.byId(hostDevice.device.id).status === 'compromised' &&
          code(devices.setStatus(hostDevice.device.id, 'lost')) ===
            'STS-DEVICE-0011',
          '6b. a device can be marked compromised');

  // --- 7. list and page ----------------------------------------------------
  t.log.info('=== 7. list and page ===');
  const ids = function (list) {
    log.debug("Entering ids().");
    log.debug("Leaving ids().");
    return list.map(function (d) { return d.id; }).sort().join(',');
  };
  t.check(devices.list({ ownerKind: 'application', q: STAMP }).length ===
            1 &&
          ids(devices.list({ owner: ALICE })) === laptop.device.id &&
          ids(devices.list({ owner: HOST, ownerKind: 'application' })) ===
            hostDevice.device.id &&
          ids(devices.list({ compliance: 'not-compliant', q: STAMP })) ===
            laptop.device.id &&
          ids(devices.list({ keyKind: 'x509', q: STAMP })) ===
            laptop.device.id &&
          ids(devices.list({ status: 'compromised', q: STAMP })) ===
            hostDevice.device.id &&
          ids(devices.list({ application: HOST })) === laptop.device.id &&
          devices.list({ compliance: 'complaint' }).length === 0 &&
          devices.list({ q: spki.slice(0, 20) }).length === 1,
          '7a. every filter, ANDed; a value outside a list matches nothing; ' +
          'the search reaches a key\'s thumbprint');
  const paged = devices.page({ q: STAMP }, 99, 1);
  t.check(paged.total >= 1 && paged.page === paged.pages &&
          paged.rows.length === 1,
          '7b. a page past the end is clamped to the last one',
          JSON.stringify({ total: paged.total, page: paged.page,
                           pages: paged.pages }));

  // --- 8. counts and the timeline ------------------------------------------
  t.log.info('=== 8. counts and the timeline ===');
  const before = devices.timeline(7).totals;
  t.check(devices.remove(hostDevice.device.id, undefined, 'the-admin').ok,
          'precondition: the host\'s device is removed');
  const counts = devices.counts(function () { return false; });
  const timeline = devices.timeline(7);
  const today = timeline.rows[timeline.rows.length - 1];
  t.check(counts.total >= 2 && counts.byOwnerKind.person >= 2 &&
          counts.byCompliance['not-compliant'] >= 1 &&
          counts.byKeyKind.x509 >= 1 && counts.byKeyKind.jwk >= 1 &&
          counts.byEnrolment.admin >= 1 &&
          counts.byAttestation['self-asserted'] >= 2,
          '8a. the counts by owner kind, compliance, key kind, enrolment ' +
          'and attestation', JSON.stringify(counts));
  t.check(timeline.rows.length === 7 &&
          timeline.totals.removed === before.removed + 1 &&
          today.created >= 3 && today.removed >= 1 &&
          /^\d{4}-\d{2}-\d{2}$/.test(today.day),
          '8b. every registration and removal is an event on today\'s row',
          JSON.stringify(today));
  config.setOverride('devices.maxPerPerson', 1);
  const evictedBefore = devices.timeline(7).totals.evicted;
  const second = devices.issueForSession({ username: BOB, clientId: APP,
    sessionId: 'dev-sess-2-' + STAMP, label: 'another phone' });
  config.clearOverride('devices.maxPerPerson');
  t.check(second.ok && devices.timeline(7).totals.evicted ===
            evictedBefore + 1 && devices.listFor(BOB).length === 1,
          '8c. a Native SSO sign-in at the bound evicts, and that is an ' +
          'event too');

  // --- 9. the console's door -----------------------------------------------
  t.log.info('=== 9. the console\'s door ===');
  const devicesAdmin = require('../admin-ui/devices_admin');
  const unknown = devicesAdmin.action({ action: 'frobnicate' }, 'a', 'b');
  t.check(code(unknown) === 'STS-DEVICE-0013' &&
          unknown.errors[0] === 'Unknown action "frobnicate". The seven ' +
            'are: create, update, remove, add-key, remove-key, ' +
            'set-compliance and set-status.',
          '9a. an unknown action is refused naming the seven',
          JSON.stringify(unknown));
  const claimed = devicesAdmin.action({ action: 'add-key',
    id: laptop.device.id, kind: 'jwk', value: publicJwk().pub,
    proof: 'webauthn', attestation: { level: 'attested', format: 'packed' } },
    'the-admin', 'the admin console');
  const stored = devices.byId(laptop.device.id).keys.filter(function (k) {
    return k.id === claimed.key;
  })[0];
  t.check(claimed.ok && stored && stored.proof === 'admin' &&
          stored.attestation.level === 'self-asserted' &&
          devices.byId(laptop.device.id).attestation === 'self-asserted',
          '9b. a body claiming a proof and an attestation is recorded as ' +
          'neither', JSON.stringify(stored || claimed));
  const listed = devicesAdmin.listView({ query: {} }, { owner: ALICE });
  t.check(listed.devices.length === 1 && listed.devices[0].ownerName ===
            ALICE && listed.devices[0].secretHash === undefined &&
          listed.devicesPaging && listed.devicesPaging.page === 1,
          '9c. the list view names the owner, pages, and never carries a ' +
          'hash', JSON.stringify(listed).slice(0, 400));
  const one = devicesAdmin.listView({ query: {} }, { device: 'nope' });
  t.check(one.found === false && one.device === null,
          '9d. an unknown device is an answer, not a 404');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'devices',
  describe: 'The device register (#164 phase 1, #218): owners of both ' +
            'kinds, keys and their thumbprints, the bounds, the entry, ' +
            'update, compliance, the filters, the counts and the console\'s ' +
            'door',
  run: run
};
