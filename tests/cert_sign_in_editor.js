// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cert_sign_in_editor.js
//
// ===========================================================================
// CERTIFICATE SIGN-IN'S SETTINGS AS FORM FIELDS (#2080).
//
// `admin-ui/web_cert_sign_in.ts` draws six structured settings as editors
// over the box that still carries each value, and a person's
// `stsCertificateBinding` as a sub-tab; the console's inspection helper
// (`admin-core/certificate_views.ts`'s `inspectView()`) reads what a
// certificate says. This holds:
//
//   A. the profile editor writes exactly what `certSignIn.profiles`' write
//      rule (STS-TLS-0065) accepts — every field, set the way a reader sets
//      it — and a profile written by hand loads and is written back
//      unchanged, members and order alike;
//   B. a low-affinity binding is refused unless `lowAffinity` is ticked,
//      and unticking it takes them out; the write rule refuses one written
//      by hand without it;
//   C. the editor's lists are `common/certificate_binding.ts`'s;
//   D. the SubjectPublicKeyInfo SHA-256 the helper answers is the one node
//      computes independently, for a CA handed in and for a truststore
//      anchor's row;
//   E. a person's three binding values are derived from their certificate
//      — the issuer found among what was handed in — and equal what the
//      resolution looks the certificate up by (`keyOf()`);
//   F. the listener, mapping and PEM editors round-trip their values;
//   G. Protocols → PIV and the Listeners page draw the editors, the group
//      and the links, and a person's sub-tab draws the binding forms;
//   H. the helper is a console operation that writes nothing, and refuses
//      a text with no certificate with its code, marked and never sent.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const path = require('path');
const asn1js = require('asn1js');
const errorCodes = require('../common/error_codes');
const binding = require('../common/certificate_binding');
const certificateViews = require('../admin-core/certificate_views');
const Editors = require('../admin-ui/web_cert_sign_in');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'cert_sign_in_editor',
  level: process.env.LOG_LEVEL || 'info' });

const HASH_A = 'a'.repeat(64);
const HASH_B = '0123456789abcdef'.repeat(4);

// An independent SubjectPublicKeyInfo SHA-256: node's, not crypto.js's.
function spkiOf(pem) {
  log.debug("Entering spkiOf().");
  const der = new nodeCrypto.X509Certificate(pem).publicKey
    .export({ type: 'spki', format: 'der' });
  log.debug("Leaving spkiOf().");
  return nodeCrypto.createHash('sha256').update(der).digest('hex');
}

function ab(bytes) {
  log.debug("Entering ab().");
  log.debug("Leaving ab().");
  return Uint8Array.from(Buffer.from(bytes)).buffer;
}

// A CA and a leaf under it with a subjectKeyIdentifier.
async function pair() {
  log.debug("Entering pair().");
  const root = await kit.root('Editor Test ' + Date.now(), 'ec');
  const keys = await kit.keyPair('ec');
  const ski = nodeCrypto.randomBytes(20);
  const leaf = await kit.certificate({
    subject: [['2.5.4.3', 'SMITH.JANE.EDITOR']],
    publicKey: keys.crypto.publicKey, issuer: root,
    extensions: [kit.extension('2.5.29.14', false, new asn1js.OctetString({
      valueHex: ab(ski) }).toBER(false))] });
  log.debug("Leaving pair().");
  return { root: root, leaf: leaf, ski: ski.toString('hex') };
}

// What a reader does to a new profile, one act at a time.
function edited() {
  log.debug("Entering edited().");
  let state = { profiles: [], problem: '' };
  const act = function (one) {
    state = Editors.applyProfile(state.profiles, one);
    return state.problem;
  };
  act({ op: 'add' });
  act({ op: 'text', index: 0, field: 'id', value: 'federal-piv' });
  act({ op: 'text', index: 0, field: 'description',
        value: 'Federal PIV cards' });
  act({ op: 'value', index: 0, field: 'issuers',
        value: 'SHA256:' + HASH_B.toUpperCase().match(/../g).join(':') });
  act({ op: 'value', index: 0, field: 'issuers', value: HASH_A });
  act({ op: 'toggle', index: 0, field: 'keyUsage',
        value: 'digitalSignature', on: true });
  Editors.EKU_PRESETS.forEach(function (one) {
    act({ op: 'toggle', index: 0, field: 'extendedKeyUsage',
          value: one.oid, on: true });
  });
  act({ op: 'value', index: 0, field: 'extendedKeyUsage',
        value: '1.3.6.1.4.1.67607.99.9' });
  act({ op: 'toggle', index: 0, field: 'policies',
        value: Editors.POLICY_PRESETS[0].oid, on: true });
  act({ op: 'toggle', index: 0, field: 'bindings', value: 'card-uuid',
        on: true });
  act({ op: 'toggle', index: 0, field: 'bindings', value: 'issuer-serial',
        on: false });
  act({ op: 'flag', index: 0, field: 'smartCard', on: true });
  act({ op: 'add' });
  act({ op: 'value', index: 1, field: 'issuers', value: HASH_A });
  act({ op: 'move', index: 1, delta: -1 });
  log.debug("Leaving edited().");
  return state;
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. the profile editor writes what the rule accepts ===');
  const made = edited();
  const text = Editors.profilesText(made.profiles);
  const written = JSON.parse(text);
  t.check(binding.CertificateBinding.writeRule('certSignIn.profiles',
                                               text) === null,
          'A1. the write rule takes what the editor wrote', text);
  t.check(written.length === 2 && written[0].id === 'profile-2' &&
          written[1].id === 'federal-piv',
          'A2. add, and move up, put the second profile first',
          written.map(function (p) { return p.id; }).join(','));
  t.check(JSON.stringify(written[1]) === JSON.stringify({
    id: 'federal-piv', description: 'Federal PIV cards',
    issuers: [HASH_B, HASH_A], keyUsage: ['digitalSignature'],
    extendedKeyUsage: ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2',
                       '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.67607.99.9'],
    policies: ['2.16.840.1.101.3.2.1.3.13'],
    bindings: ['certificate-sha256', 'card-uuid'], smartCard: true }),
          'A3. every field is written as it was set, a pasted hash ' +
          'canonical', JSON.stringify(written[1]));
  t.check(JSON.stringify(written[0]) === JSON.stringify({
    id: 'profile-2', issuers: [HASH_A] }),
          'A4. a member never set is not written (bindings keep their ' +
          'default)', JSON.stringify(written[0]));
  const byHand = '[{"smartCard":false,"id":"enterprise","bindings":' +
    '["spki-sha256","upn"],"lowAffinity":true,"issuers":["' + HASH_A +
    '"],"description":"","keyUsage":[],"policies":["1.2.3"]},' +
    '{"id":"plain","issuers":["' + HASH_B + '"]}]';
  const read = Editors.parseProfiles(byHand);
  t.check(read.ok && Editors.profilesText(read.profiles) ===
          JSON.stringify(JSON.parse(byHand)),
          'A5. a profile written by hand loads and is written back ' +
          'unchanged, members and order alike',
          read.ok ? Editors.profilesText(read.profiles) : read.problem);
  t.check(binding.CertificateBinding.writeRule('certSignIn.profiles',
            Editors.profilesText(read.profiles)) === null &&
          Editors.parseProfiles('').ok &&
          Editors.profilesText([]) === '',
          'A6. which the rule takes too, and none is the empty value');
  ['{"id":1}', '[{"id":"x","shape":"round"}]', '[1]', 'not json']
    .forEach(function (bad) {
      t.check(!Editors.parseProfiles(bad).ok,
              'A7. a value the editor cannot show is left to the box: ' + bad,
              Editors.parseProfiles(bad).problem);
    });
  t.check(Editors.applyProfile(made.profiles, { op: 'value', index: 0,
            field: 'issuers', value: 'abc' }).problem === 'badHash' &&
          Editors.applyProfile(made.profiles, { op: 'value', index: 0,
            field: 'policies', value: 'piv' }).problem === 'badOid',
          'A8. a typed issuer that is no SHA-256, and a policy that is no ' +
          'OID, are refused in the editor');

  t.log.info('=== B. low affinity is an opt-in ===');
  let low = Editors.applyProfile(made.profiles, { op: 'toggle', index: 1,
    field: 'bindings', value: 'upn', on: true });
  t.check(low.problem === 'lowNeedsOptIn' &&
          low.profiles[1].bindings.indexOf('upn') < 0,
          'B1. a name method is not taken without lowAffinity',
          low.problem);
  low = Editors.applyProfile(made.profiles, { op: 'flag', index: 1,
    field: 'lowAffinity', on: true });
  low = Editors.applyProfile(low.profiles, { op: 'toggle', index: 1,
    field: 'bindings', value: 'email', on: true });
  const lowText = Editors.profilesText(low.profiles);
  t.check(low.problem === '' && JSON.parse(lowText)[1].lowAffinity === true &&
          JSON.parse(lowText)[1].bindings.indexOf('email') >= 0 &&
          binding.CertificateBinding.writeRule('certSignIn.profiles',
                                               lowText) === null,
          'B2. with lowAffinity ticked it is, and the rule takes it',
          lowText);
  low = Editors.applyProfile(low.profiles, { op: 'flag', index: 1,
    field: 'lowAffinity', on: false });
  t.check(JSON.parse(Editors.profilesText(low.profiles))[1].bindings
            .every(function (m) {
              return binding.LOW_AFFINITY.indexOf(m) < 0;
            }),
          'B3. unticking lowAffinity takes the name methods out',
          Editors.profilesText(low.profiles));
  const refused = binding.CertificateBinding.writeRule('certSignIn.profiles',
    '[{"id":"x","issuers":["' + HASH_A + '"],"bindings":["subject"]}]');
  t.check(refused && refused.code === 'STS-TLS-0065',
          'B4. the rule refuses a name method written by hand without it',
          JSON.stringify(refused));
  const drawn = Editors.profilesEditor({ profiles: made.profiles,
                                         anchors: [] },
                                       require('../admin-ui/web_kit')
                                         .context().t);
  const lowBoxes = drawn.match(/data-cs-value="(upn|email|issuer-subject|subject)"[^>]*>/g) || [];
  t.check(lowBoxes.length === 8 && lowBoxes.every(function (b) {
    return / disabled/.test(b);
  }), 'B5. the low-affinity boxes are drawn disabled until it is ticked',
          lowBoxes.length + ' drawn');

  t.log.info('=== C. the lists are the binding module\'s ===');
  t.check(JSON.stringify(Editors.HIGH_AFFINITY) ===
            JSON.stringify(binding.HIGH_AFFINITY) &&
          JSON.stringify(Editors.LOW_AFFINITY) ===
            JSON.stringify(binding.LOW_AFFINITY) &&
          JSON.stringify(Editors.DEFAULT_BINDINGS) ===
            JSON.stringify(binding.CertificateBinding.DEFAULT_BINDINGS),
          'C1. the editor\'s methods are certificate_binding.ts\'s');
  t.check(binding.CertificateBinding.profileProblem({ id: 'all',
            issuers: [HASH_A], keyUsage: Editors.KEY_USAGE_NAMES }) === '',
          'C2. and every keyUsage box names a bit the rule knows');

  t.log.info('=== D. the SubjectPublicKeyInfo SHA-256 ===');
  const p = await pair();
  const inspected = certificateViews.inspectView({ pem: p.root.pem });
  t.check(inspected.ok && inspected.certificates.length === 1 &&
          inspected.certificates[0].spkiSha256 === spkiOf(p.root.pem) &&
          inspected.certificates[0].ca === true &&
          inspected.certificates[0].sha256 ===
            nodeCrypto.createHash('sha256').update(p.root.der)
              .digest('hex'),
          'D1. a CA handed in is answered with the SHA-256 node computes ' +
          'of its SubjectPublicKeyInfo, and of its DER',
          inspected.ok ? inspected.certificates[0].spkiSha256 : '');
  const tls = require('../tls/tls_server');
  const added = tls.truststore.add(p.root.pem, { actor: 'test' });
  const row = (tls.truststore.list().anchors || []).filter(function (one) {
    return one.subject && one.subject.indexOf('Editor Test') >= 0;
  })[0];
  t.check(row && row.spkiSha256 === spkiOf(p.root.pem),
          'D2. the truststore\'s row for that CA carries the same digest',
          JSON.stringify(row ? row.spkiSha256 : added) || 'no row');

  t.log.info('=== E. a person\'s bindings from their certificate ===');
  const derived = certificateViews.inspectView({
    pem: p.leaf.pem + p.root.pem, bindings: true });
  const valueOf = function (method) {
    return (derived.bindings || []).filter(function (b) {
      return b.method === method;
    }).map(function (b) { return b.value; })[0] || '';
  };
  const issuerKey = spkiOf(p.root.pem);
  const serial = new nodeCrypto.X509Certificate(p.leaf.pem).serialNumber
    .toLowerCase().replace(/^0+(?=[0-9a-f])/, '');
  t.check(derived.ok && derived.issuer && derived.issuer.from === 'bundle' &&
          valueOf('spki-sha256') === 'spki-sha256:' + spkiOf(p.leaf.pem) &&
          valueOf('issuer-serial') === 'issuer-serial:' + issuerKey + ':' +
            serial &&
          valueOf('issuer-ski') === 'issuer-ski:' + issuerKey + ':' + p.ski,
          'E1. spki-sha256, issuer-serial and issuer-ski are derived, each ' +
          'as computed independently', JSON.stringify(derived.bindings));
  const resolver = new binding.CertificateBinding(
    binding.CertificateBinding.defaultDeps());
  const stsCrypto = require('../common/crypto');
  const leafFacts = stsCrypto.certificateFacts(p.leaf.der);
  const rootFacts = stsCrypto.certificateFacts(p.root.der);
  t.check(['spki-sha256', 'issuer-serial', 'issuer-ski'].every(
    function (method) {
      const key = resolver.keyOf(method, p.leaf.der, leafFacts, rootFacts);
      return key && key.value === valueOf(method);
    }), 'E2. and each is what the resolution looks the certificate up by');
  const alone = certificateViews.inspectView({ pem: p.leaf.pem,
                                               bindings: true });
  t.check(alone.ok && (alone.issuer === null ||
                       alone.issuer.from === 'truststore') &&
          (alone.issuer !== null || alone.bindings.length === 1),
          'E3. with no issuer handed in, it is looked for in the ' +
          'truststore, and only spki-sha256 is derived without one',
          JSON.stringify(alone.issuer));
  const t2 = require('../admin-ui/web_kit').context().t;
  const panel = Editors.personBindings(t2, 'jane',
    [valueOf('spki-sha256')], true);
  t.check(/name="action" value="remove-attribute"/.test(panel) &&
          panel.indexOf('value="' + valueOf('spki-sha256') + '"') >= 0 &&
          /data-cert-binding="jane"/.test(panel),
          'E4. the sub-tab lists a held value with its Remove and offers ' +
          'the derivation');
  const result = Editors.derivedBindings(t2, 'jane', derived,
                                         [valueOf('spki-sha256')]);
  t.check((result.match(/value="add-attribute"/g) || []).length === 2 &&
          result.indexOf('value="' + valueOf('issuer-ski') + '"') >= 0 &&
          result.indexOf('stsCertificateBinding') >= 0,
          'E5. each derived value not held is an Add through ' +
          'users/add-attribute');

  t.log.info('=== F. the other editors round-trip ===');
  const listeners = '[{"id":"cards","port":9443,"publicBaseUrl":' +
    '"https://cards.example.com:9443","clientAuth":"required","tls":' +
    '{"minVersion":"TLSv1.3","disableTls12":true,"sessionTimeoutS":60}},' +
    '{"label":"","id":"admin","port":9444,"publicBaseUrl":' +
    '"https://a.example.com:9444","hostnames":["a.example.com"]}]';
  const lr = Editors.parseListeners(listeners);
  t.check(lr.ok && Editors.listenersText(lr.listeners) ===
          JSON.stringify(JSON.parse(listeners)),
          'F1. listener definitions load and are written back unchanged',
          lr.ok ? Editors.listenersText(lr.listeners) : lr.problem);
  let ll = Editors.applyListener(lr.listeners, { op: 'tls-add', index: 1 });
  ll = Editors.applyListener(ll, { op: 'tls-name', index: 1, row: 0,
                                   value: 'pqcOnly' });
  ll = Editors.applyListener(ll, { op: 'tls-value', index: 1, row: 0,
                                   value: 'true' });
  ll = Editors.applyListener(ll, { op: 'text', index: 1, field: 'port',
                                   value: '9555' });
  const lj = JSON.parse(Editors.listenersText(ll));
  const mapped = require('../common/listener_map').parseListeners(
    Editors.listenersText(ll), 'default');
  t.check(lj[1].tls.pqcOnly === true && lj[1].port === 9555 &&
          mapped.problem === null,
          'F2. a TLS row and a port are written typed, and the listener ' +
          'map reads the result',
          JSON.stringify(lj[1]) + ' ' + JSON.stringify(mapped.problem));
  const map = '{"admin-console":{"listeners":["admin"]},' +
    '"certificate-sign-in":{"advertised":"cards","listeners":["main",' +
    '"cards"]}}';
  const ar = Editors.parseApplications(map);
  t.check(ar.ok && Editors.applicationsText(ar.entries) ===
          JSON.stringify(JSON.parse(map)),
          'F3. the mapping loads and is written back unchanged',
          ar.ok ? Editors.applicationsText(ar.entries) : ar.problem);
  const pems = Editors.parsePems(p.root.pem);
  const more = Editors.addPems(pems.blocks, p.leaf.pem + p.root.pem);
  t.check(pems.ok && pems.blocks.length === 1 && more.added === 1 &&
          more.blocks.length === 2 &&
          Editors.parsePems(Editors.pemsText(more.blocks)).blocks.length ===
            2 && !Editors.parsePems('nothing here').ok,
          'F4. a PEM list adds each certificate once and reads back');

  t.log.info('=== G. the pages draw them ===');
  const consolePage = require('./tools/console_page')
    .consolePage(path.join(__dirname, '..'));
  const piv = await consolePage.draw('/admin/piv', {});
  const html = piv.html || '';
  t.check(piv.status === 200 &&
          html.indexOf('data-structured="profiles"') >= 0 &&
          html.indexOf('name="certSignIn.profiles"') >= 0 &&
          html.indexOf('data-structured="pems"') >= 0 &&
          html.indexOf('name="tls.trustedProxyAddresses"') >= 0,
          'G1. Protocols → PIV draws the Certificate sign-in group, the ' +
          'profile editor and the PEM lists', String(piv.status));
  t.check(['/admin/tls/trust', '/admin/pki', '/admin/listeners#tab-custom',
           '/admin/listeners#tab-main', '/admin/policies#authn',
           'configure-tls.html#smart-card-and-certificate-sign-in']
    .every(function (href) { return html.indexOf(href) >= 0; }),
          'G2. and links to everything a smart-card sign-in needs');
  const lp = await consolePage.draw('/admin/listeners', {});
  t.check(lp.status === 200 &&
          (lp.html || '').indexOf('id="tab-cert-sign-in"') >= 0 &&
          (lp.html || '').indexOf('name="certSignIn.handoff"') >= 0 &&
          (lp.html || '').indexOf('data-structured-for=' +
                                  '"listeners-definitions"') >= 0,
          'G3. the Listeners page keeps the group, on a tab of its own, ' +
          'and draws the listener editor', String(lp.status));

  t.log.info('=== H. the helper ===');
  const adminApi = require('../mgmt-api/admin_api');
  const route = adminApi.ROUTES.filter(function (one) {
    return one.route === '/admin-api/console/certificates/:action';
  })[0];
  t.check(route && route.kind === 'console' && route.method === 'POST' &&
          route.actions.length === 1 &&
          route.actions[0].operationId === 'inspectCertificates' &&
          route.actions[0].writesNothing === true,
          'H1. the helper is a console operation that writes nothing');
  const none = certificateViews.inspectView({ pem: 'no certificate' });
  t.check(!none.ok && errorCodes.codeOf(none) === 'STS-ADMIN-0953' &&
          JSON.stringify(none).indexOf('STS-') < 0,
          'H2. a text with no certificate is refused with its code, ' +
          'marked and never sent', JSON.stringify(none));
  const bad = certificateViews.inspectView({ pem:
    '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----' });
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-ADMIN-0954',
          'H3. a block that is not a certificate is refused with its own');
  if (row) {
    // The process's truststore is shared with every later file: the
    // anchor goes, as it came.
    tls.truststore.remove(row.fingerprint256);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cert_sign_in_editor',
  describe: 'certificate sign-in\'s settings as form fields, and a person\'s ' +
            'binding editor (#2080)',
  run: run
};
