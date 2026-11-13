// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml11_metadata_written.js
//
// ===========================================================================
// A RELYING PARTY'S METADATA WRITTEN TO AN ENTRY THAT ALREADY EXISTS IS
// CONSUMED, AND ITS SHIRE'S BINDING PICKS THE SAML 1.1 PROFILE (run 22).
//
// The vendored `tests/protocol/sts_saml11.js` registers its relying party
// with a metadata document whose `acs` is browser-post and `artifactAcs` is
// artifact-01, the way a Shibboleth SP's /SAML/POST and /SAML/Artifact are,
// and then signs in with `shire=artifactAcs`, expecting a 303 carrying
// SAMLart. In a development service the entry already EXISTS by then — the
// job's own GET /saml11/metadata/{rp} filed it — so the job's registry
// helper reconciles it: `add` per value and `set samlSpMetadata`. That `set`
// stored the document and consumed none of it, so no `samlAcsEndpoint`
// named the artifact consumer, profileFor() fell back to
// saml11.defaultProfile, and the artifact shire was answered with a
// Browser/POST form (200). The create door and the upload consumed; the
// third door did not.
//
//   A. The job's sequence, on an entry the metadata ask filed: `add` the
//      family and the consumers, `set` the document. The document is
//      consumed (samlAcsEndpoint names both bindings), the artifact shire is
//      a 303 with a 42-byte type 0x0001 SAMLart and TARGET, the POST shire
//      the auto-post form, and a consumer with no binding the default.
//   B. The field grid's save (`update-fields`) consumes it too.
//   C. A document that is refused writes nothing (STS-ADMIN-0935), and
//      an empty `set` (the attribute holds one value) still clears it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml11_metadata_written',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.1:protocol';
const P11 = 'urn:oasis:names:tc:SAML:1.0:profiles:';

// The job's own document: each consumer with its profile, no isDefault.
function saml11Metadata(entityId, endpoints) {
  log.debug("Entering saml11Metadata().");
  const consumers = endpoints.map(function (one, i) {
    return '<md:AssertionConsumerService index="' + (i + 1) + '" ' +
      'Binding="' + P11 + one[0] + '" Location="' + one[1] + '"/>';
  }).join('');
  log.debug("Leaving saml11Metadata().");
  return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:' +
    'metadata" entityID="' + entityId + '"><md:SPSSODescriptor ' +
    'protocolSupportEnumeration="' + NS_SAMLP11 + '">' + consumers +
    '</md:SPSSODescriptor></md:EntityDescriptor>';
}

function hiddenField(html, name) {
  log.debug("Entering hiddenField().");
  const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(
    String(html || ''));
  log.debug("Leaving hiddenField().");
  return m ? m[1].replace(/&amp;/g, '&').replace(/&quot;/g, '"') : '';
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const app = require('../common/app');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const authn = require('../authn/authn');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  const adminActions = require('../admin-core/admin_actions');
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
  const sso11 = kit.handlerFor(app, 'get', '/saml11/sso');
  const metadata11 = kit.handlerFor(app, 'get', '/saml11/metadata/:rp');
  const stamp = nodeCrypto.randomBytes(5).toString('hex');
  const created = [];
  const ctx = { actor: 'saml11_metadata_written', via: 'test' };

  const act = function (body) {
    log.debug("Entering act().");
    const answer = adminActions.applicationsAction(body, [], ctx);
    log.debug("Leaving act().");
    return answer;
  };
  const endpointsOf = function (rp) {
    log.debug("Entering endpointsOf().");
    const entry = applications.get(rp);
    log.debug("Leaving endpointsOf().");
    return [].concat((entry && entry.fields &&
                      entry.fields.samlAcsEndpoint) || []).map(String);
  };
  const res0 = kit.fakeRes();
  const session = authn.startSession(res0, 'm11-' + stamp, ['pwd'], '1',
                                     'a test', {});
  t.check(!!session, 'a session to sign in with');
  const cookie = String(res0.headers['set-cookie'] || '').split(';')[0];
  const signIn = async function (rp, shire, target) {
    log.debug("Entering signIn().");
    const q = { providerId: rp, shire: shire, TARGET: target };
    const res = kit.fakeRes();
    sso11(kit.fakeReq('GET', '/saml11/sso', q,
                      new URLSearchParams(q).toString(), undefined,
                      { headers: { host: 'idp.test', cookie: cookie } }),
          res);
    await Promise.race([res.done, new Promise(function (resolve) {
      setTimeout(resolve, 5000);
    })]);
    log.debug("Leaving signIn().");
    return res;
  };
  // Every profile assertion about one relying party's three consumers.
  const profiles = async function (label, rp, post, artifact, unbound) {
    log.debug("Entering profiles().");
    const target = 'https://' + label + '.test/done?x=1';
    const art = await signIn(rp, artifact, target);
    const sAMLart = decodeURIComponent(
      (/[?&]SAMLart=([^&]+)/.exec(art.location || '') || [])[1] || '');
    const raw = Buffer.from(sAMLart, 'base64');
    t.check(art.statusCode === 303 &&
            String(art.location).indexOf(artifact) === 0 &&
            /[?&]TARGET=/.test(art.location) && raw.length === 42 &&
            raw.readUInt16BE(0) === 1,
            label + ': the shire registered on artifact-01 is answered on ' +
            'Browser/Artifact — a 303 to it carrying TARGET and a 42-byte ' +
            'type 0x0001 SAMLart',
            art.statusCode + ' ' + String(art.location).slice(0, 140) +
            ' ' + raw.length + ' bytes');
    const posted = await signIn(rp, post, target);
    t.check(posted.statusCode === 200 &&
            !!hiddenField(posted.body, 'SAMLResponse') &&
            hiddenField(posted.body, 'TARGET') === target &&
            posted.body.indexOf('action="' + post + '"') >= 0,
            label + ': the shire registered on browser-post is answered ' +
            'with the Browser/POST form, posting to it',
            posted.statusCode + ' ' + String(posted.body).slice(0, 160));
    if (unbound) {
      const plain = await signIn(rp, unbound, target);
      t.check(plain.statusCode === 200 &&
              !!hiddenField(plain.body, 'SAMLResponse'),
              label + ': a consumer registered with no binding gets ' +
              'saml11.defaultProfile (post)',
              plain.statusCode + ' ' + String(plain.location || ''));
    }
    log.debug("Leaving profiles().");
  };

  try {
    // -----------------------------------------------------------------------
    t.log.info('A. the job\'s sequence: an entry already filed, `set` ' +
               'samlSpMetadata');
    // -----------------------------------------------------------------------
    t.check(String(config.value('saml11.defaultProfile') || 'post') ===
            'post', 'the default profile is post, so only the registered ' +
            'binding can make the artifact answer');
    const rp = 'urn:test:saml11:written:' + stamp;
    created.push(rp);
    const md = kit.fakeRes();
    metadata11(kit.fakeReq('GET', '/saml11/metadata/' + rp, {}, '',
                           undefined, { params: { rp: rp } }), md);
    await Promise.race([md.done, new Promise(function (resolve) {
      setTimeout(resolve, 5000);
    })]);
    if (!applications.get(rp)) {
      // The ask files the entry in development; if it did not here, file
      // one the way a sighting does, so the reconcile path is still the one
      // under test.
      applications.createApplication({ identifier: rp,
        kind: 'saml11-relying-party', protocol: 'SAML 1.1',
        fields: { samlEntityId: rp } });
    }
    t.check(!!applications.get(rp) && endpointsOf(rp).length === 0,
            'the relying party is on file before it is registered, with no ' +
            'consumer endpoints', md.statusCode + ' ' +
            JSON.stringify(endpointsOf(rp)));
    const host = 'https://rp-' + stamp + '.saml11.example.test';
    const post = host + '/SAML/POST';
    const artifact = host + '/SAML/Artifact/rp';
    const unbound = host + '/SAML/Unbound';
    const steps = [
      { action: 'add', attribute: 'appAllowedProtocol', value: 'saml11' },
      { action: 'add', attribute: 'samlAssertionConsumerService',
        value: post },
      { action: 'add', attribute: 'samlAssertionConsumerService',
        value: artifact },
      { action: 'add', attribute: 'samlAssertionConsumerService',
        value: unbound }
    ];
    steps.forEach(function (step) {
      const done = act(Object.assign({ application: rp }, step));
      t.check(done && done.ok, 'reconcile: ' + step.action + ' ' +
              step.attribute, JSON.stringify(done && done.errors));
    });
    const document = saml11Metadata(rp, [['browser-post', post],
                                         ['artifact-01', artifact]]);
    const set = act({ action: 'set', application: rp,
                      attribute: 'samlSpMetadata', value: document });
    t.check(set && set.ok === true && set.changed === true &&
            !!set.application,
            'A1. `set samlSpMetadata` on the existing entry is accepted',
            JSON.stringify(set && (set.errors || set.message)));
    const endpoints = endpointsOf(rp);
    t.check(endpoints.some(function (one) {
      return one.indexOf(P11 + 'artifact-01 ' + artifact) >= 0;
    }) && endpoints.some(function (one) {
      return one.indexOf(P11 + 'browser-post ' + post) >= 0;
    }), 'A2. and CONSUMED: samlAcsEndpoint names each consumer with its ' +
        'profile', JSON.stringify(endpoints));
    const acs = [].concat(applications.get(rp).fields
      .samlAssertionConsumerService || []).map(String);
    t.check(acs.indexOf(unbound) >= 0 && acs.indexOf(artifact) >= 0,
            'A3. the consumer registered by hand is kept beside the ' +
            'document\'s', JSON.stringify(acs));
    t.check(String(applications.get(rp).fields.samlSpMetadata || '') ===
            document || [].concat(applications.get(rp).fields
              .samlSpMetadata || [])[0] === document,
            'A4. the document itself is on the entry');
    await profiles('A5', rp, post, artifact, unbound);

    // -----------------------------------------------------------------------
    t.log.info('B. the field grid\'s save consumes it too');
    // -----------------------------------------------------------------------
    const rpB = 'urn:test:saml11:written-grid:' + stamp;
    created.push(rpB);
    const madeB = applications.createApplication({ identifier: rpB,
      kind: 'saml11-relying-party', protocol: 'SAML 1.1',
      fields: { samlEntityId: rpB } });
    t.check(madeB.ok, 'B0. an entry on file', JSON.stringify(madeB.errors));
    const postB = host + '/B/SAML/POST';
    const artB = host + '/B/SAML/Artifact';
    const grid = act({ action: 'update-fields', application: rpB,
                       protocols: ['saml11'],
                       fields: { samlAssertionConsumerService: [postB, artB],
                                 samlSpMetadata: saml11Metadata(rpB, [
                                   ['browser-post', postB],
                                   ['artifact-01', artB]]) } });
    t.check(grid && grid.ok === true &&
            (grid.changed || []).indexOf('samlSpMetadata') >= 0,
            'B1. update-fields with a document is accepted and names it ' +
            'saved', JSON.stringify(grid && (grid.errors || grid.changed)));
    t.check(endpointsOf(rpB).some(function (one) {
      return one.indexOf(P11 + 'artifact-01 ' + artB) >= 0;
    }), 'B2. and the document was consumed', JSON.stringify(endpointsOf(rpB)));
    await profiles('B3', rpB, postB, artB, '');

    // -----------------------------------------------------------------------
    t.log.info('C. a refused document writes nothing; remove is plain');
    // -----------------------------------------------------------------------
    const before = JSON.stringify(applications.get(rp).fields);
    const bad = act({ action: 'set', application: rp,
                      attribute: 'samlSpMetadata',
                      value: '<md:EntityDescriptor xmlns:md="urn:oasis:' +
                        'names:tc:SAML:2.0:metadata" entityID="urn:other:' +
                        stamp + '"/>' });
    t.check(bad && bad.ok === false &&
            errorCodes.codeOf(bad) === 'STS-ADMIN-0935',
            'C1. a document that does not describe this relying party is ' +
            'refused, STS-ADMIN-0935',
            JSON.stringify(bad) + ' ' + errorCodes.codeOf(bad));
    t.check(JSON.stringify(applications.get(rp).fields) === before,
            'C2. and nothing on the entry changed');
    const removed = act({ action: 'set', application: rp,
                          attribute: 'samlSpMetadata', value: '' });
    t.check(removed && removed.ok === true &&
            !applications.get(rp).fields.samlSpMetadata,
            'C3. an empty `set` clears the document as a plain write',
            JSON.stringify(removed && (removed.errors || removed.message)));
  } finally {
    created.forEach(function (identifier) {
      if (applications.get(identifier)) {
        applications.deleteApplication(identifier);
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml11_metadata_written',
  describe: 'a SAML 1.1 relying party\'s metadata written to an existing ' +
            'entry is consumed, and its shire\'s binding picks the profile ' +
            '(run 22)',
  run: run
};
