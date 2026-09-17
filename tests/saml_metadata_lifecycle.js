'use strict';
//
// File: saml_metadata_lifecycle.js
//
// ===========================================================================
// A SERVICE PROVIDER'S METADATA AFTER IT IS CONSUMED: EXPIRY, STALENESS, THE
// BACKGROUND REFRESH, TRUST ANCHORS, AGGREGATES, MDQ — AND WHAT IT SAYS ABOUT
// ENCRYPTION (2026-09-17, #37 follow-up).
//
// The claims, each against the running code:
//
//   3. EXPIRY AND STALENESS. Past its effective validUntil — the earliest
//      on the EntitiesDescriptor, EntityDescriptor and SPSSODescriptor — a
//      service provider's SSO and SLO requests are REFUSED (STS-SAML-0074)
//      and the console/API view says `expired`; past its cacheDuration a
//      document with a URL is STALE and one sweep of the background
//      refresher fetches it again from a local HTTP server; a sweep whose
//      fetch fails changes nothing, records the failure as a state, and the
//      old document keeps working until validUntil; an UPLOADED stale
//      document is shown stale, is not fetched, and works.
//   D. TRUST. A document signed by a REALM trust anchor
//      (saml2.metadataTrustAnchors) is verified; an unsigned one, or one
//      signed by another key, is refused (STS-SAML-0065); an
//      EntitiesDescriptor aggregate is consumed for the right entity (by its
//      own signature, or the entity's) and one that does not describe the
//      entity is refused; the Metadata Query Protocol fetches an entity by
//      name from the local server — success (creating the entry), 404
//      (nothing created) and a product-mode outbound refusal of the loopback
//      address (STS-SAML-0079, nothing dialled); an SSO request from an SP
//      with no metadata is answered at once and the MDQ lookup it starts
//      happens AFTER, and no request dials anything while it is answered.
//   E. ENCRYPTION. With saml2.encryptAssertion on and no certificate,
//      product answers Responder with no assertion (STS-SAML-0011) and
//      development sends it in clear; a service provider whose metadata
//      publishes a use="encryption" key is encrypted to in both modes with
//      the setting off; an unqualified EC key is not an encryption key.
//
// WHY IN PROCESS: time, a local HTTP server, product mode mid-run and a
// session are all things this file controls directly.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const zlib = require('zlib');
const nodeCrypto = require('crypto');
const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_metadata_lifecycle',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const B_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const B_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

function entity(entityId, o) {
  log.debug("Entering entity().");
  const opts = o || {};
  const key = function (use, b64) {
    log.debug("Entering key().");
    log.debug("Leaving key().");
    return '<md:KeyDescriptor' + (use ? ' use="' + use + '"' : '') + '>' +
      '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '<ds:X509Data><ds:X509Certificate>' + b64 +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
  };
  log.debug("Leaving entity().");
  return '<md:EntityDescriptor' + (opts.ns === false ? ''
      : ' xmlns:md="' + NS_MD + '"') +
    ' ID="' + (opts.id || '_e' + nodeCrypto.randomBytes(4).toString('hex')) +
    '" entityID="' + entityId + '"' +
    (opts.validUntil ? ' validUntil="' + opts.validUntil + '"' : '') +
    (opts.cacheDuration ? ' cacheDuration="' + opts.cacheDuration + '"' : '') +
    '><md:SPSSODescriptor protocolSupportEnumeration="' + NS_SAMLP + '">' +
    (opts.signing ? key('signing', opts.signing) : '') +
    (opts.encryption ? key('encryption', opts.encryption) : '') +
    (opts.unqualified ? key('', opts.unqualified) : '') +
    '<md:SingleLogoutService Binding="' + B_REDIRECT + '" Location="' +
    (opts.acs || 'https://sp.test/acs') + '/slo"/>' +
    '<md:AssertionConsumerService Binding="' + B_POST + '" Location="' +
    (opts.acs || 'https://sp.test/acs') + '" index="0"/>' +
    '</md:SPSSODescriptor></md:EntityDescriptor>';
}

function aggregate(inner, o) {
  log.debug("Entering aggregate().");
  const opts = o || {};
  log.debug("Leaving aggregate().");
  return '<md:EntitiesDescriptor xmlns:md="' + NS_MD + '" ID="' +
    (opts.id || '_agg' + nodeCrypto.randomBytes(4).toString('hex')) + '"' +
    (opts.validUntil ? ' validUntil="' + opts.validUntil + '"' : '') +
    (opts.cacheDuration ? ' cacheDuration="' + opts.cacheDuration + '"' : '') +
    ' Name="urn:test:federation">' + inner + '</md:EntitiesDescriptor>';
}

function inSeconds(s) {
  log.debug("Entering inSeconds().");
  log.debug("Leaving inSeconds().");
  return new Date(Date.now() + s * 1000).toISOString();
}

function wait(ms) {
  log.debug("Entering wait().");
  log.debug("Leaving wait().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const app = require('../common/app');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const saml2sso = require('../saml/saml2_sso');
  const spMetadata = require('../saml/sp_metadata');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  const authn = require('../authn/authn');
  saml2sso.registerRoutes(app);
  const sso = kit.handlerFor(app, 'get', '/saml2/sso');
  const slo = kit.handlerFor(app, 'get', '/saml2/slo');
  const direct = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
  const stamp = String(Date.now());
  const created = [];

  // THE LOCAL SERVER: a path -> { status, body } table, and a count of hits.
  const served = {};
  const hits = {};
  const server = http.createServer(function (req, res) {
    const path = decodeURIComponent(String(req.url).split('?')[0]);
    hits[path] = (hits[path] || 0) + 1;
    const answer = served[path] || { status: 404, body: 'no' };
    res.writeHead(answer.status, { 'content-type':
                                   'application/samlmetadata+xml' });
    res.end(answer.body);
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = 'http://127.0.0.1:' + server.address().port;
  config.setOverride('federation.outboundAllowInsecure', true);
  config.setOverride('federation.outbound', true);

  const codeOf = function (res) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(res) || '';
  };
  const fieldsOf = function (id) {
    log.debug("Entering fieldsOf().");
    log.debug("Leaving fieldsOf().");
    return (applications.get(id) || {}).fields || {};
  };
  const newSp = function (name, fields) {
    log.debug("Entering newSp().");
    const id = 'https://' + name + '-' + stamp + '.md.test/saml';
    const made = applications.createApplication({
      identifier: id, kind: 'saml2-service-provider', protocol: 'SAML 2.0',
      fields: Object.assign({ samlEntityId: id }, fields || {}) });
    t.check(made.ok, 'created ' + name, JSON.stringify(made.errors || ''));
    created.push(id);
    log.debug("Leaving newSp().");
    return id;
  };
  const redirect = function (handler, path, xml, field) {
    log.debug("Entering redirect().");
    const raw = (field || 'SAMLRequest') + '=' + encodeURIComponent(
      zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64'));
    const res = kit.fakeRes();
    handler(kit.fakeReq('GET', path,
                        { [field || 'SAMLRequest']: new URLSearchParams(raw)
                          .get(field || 'SAMLRequest') }, raw), res);
    log.debug("Leaving redirect().");
    return res;
  };
  const authnRequest = function (issuer, id) {
    log.debug("Entering authnRequest().");
    log.debug("Leaving authnRequest().");
    return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
      'IssueInstant="' + new Date().toISOString() + '">' +
      '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
  };
  const logoutRequest = function (issuer, id) {
    log.debug("Entering logoutRequest().");
    log.debug("Leaving logoutRequest().");
    return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
      'IssueInstant="' + new Date().toISOString() + '">' +
      '<saml:Issuer>' + issuer + '</saml:Issuer>' +
      '<saml:NameID>alice</saml:NameID></samlp:LogoutRequest>';
  };
  const toSignIn = function (res) {
    log.debug("Entering toSignIn().");
    log.debug("Leaving toSignIn().");
    return res.statusCode === 303 && /authn/.test(res.location);
  };
  const view = function (id) {
    log.debug("Entering view().");
    log.debug("Leaving view().");
    return adminViews.saml2DetailJson(
      kit.fakeReq('GET', '/admin/saml2', { sp: id }, ''), id).json.metadata;
  };

  try {
    // -----------------------------------------------------------------------
    t.log.info('3a. an expired document refuses SSO and SLO');
    // -----------------------------------------------------------------------
    const spX = newSp('expiring');
    const soon = spMetadata.upload(spX, entity(spX,
      { validUntil: inSeconds(2) }));
    t.check(soon.ok, 'a document valid for two more seconds is consumed',
            JSON.stringify(soon.errors || ''));
    t.equal(spMetadata.freshness(fieldsOf(spX)).state, 'fresh',
            'and it is FRESH');
    t.check(toSignIn(redirect(sso, '/saml2/sso', authnRequest(spX, '_x1'))),
            'while fresh, its AuthnRequest goes on to the sign-in screen');
    await wait(2200);
    t.equal(view(spX).state, 'expired',
            'past validUntil the console/API view says EXPIRED');
    t.check(view(spX).expired === true,
            'and `expired` is true on GET /admin-api/saml2?sp=');
    const expiredSso = redirect(sso, '/saml2/sso', authnRequest(spX, '_x2'));
    t.check(expiredSso.statusCode === 403 &&
            codeOf(expiredSso) === 'STS-SAML-0074' &&
            /expired/i.test(expiredSso.body),
            'its AuthnRequest is REFUSED, STS-SAML-0074, on a page that says ' +
            'the metadata expired',
            expiredSso.statusCode + ' ' + codeOf(expiredSso));
    const expiredSlo = redirect(slo, '/saml2/slo', logoutRequest(spX, '_x3'));
    t.check(expiredSlo.statusCode === 403 &&
            codeOf(expiredSlo) === 'STS-SAML-0074',
            'and so is its LogoutRequest, STS-SAML-0074',
            expiredSlo.statusCode + ' ' + codeOf(expiredSlo));
    const prodExpired = kit.withSettings(config,
      { 'global.mode': 'product' },
      function () {
        return redirect(sso, '/saml2/sso', authnRequest(spX, '_x4'));
      });
    t.equal(codeOf(prodExpired), 'STS-SAML-0074', 'in product mode too');
    const renewed = spMetadata.upload(spX, entity(spX,
      { validUntil: inSeconds(3600) }));
    t.check(renewed.ok && toSignIn(redirect(sso, '/saml2/sso',
                                            authnRequest(spX, '_x5'))),
            'a newer document ends the refusal');

    // The effective validUntil is the earliest in the chain.
    const spChain = newSp('chain');
    const chained = spMetadata.upload(spChain, aggregate(
      entity('https://someone-else.test/sp') +
      entity(spChain, { validUntil: inSeconds(7200),
                        cacheDuration: 'PT2H' }),
      { validUntil: inSeconds(600), cacheDuration: 'PT10M' }));
    t.check(chained.ok, 'an aggregate is consumed for this entity',
            JSON.stringify(chained.errors || ''));
    const chainExpiry = Date.parse(fieldsOf(spChain).samlSpMetadataValidUntil);
    t.check(chainExpiry < Date.now() + 700000,
            'the EFFECTIVE validUntil is the PARENT EntitiesDescriptor\'s, ' +
            'the earlier one', fieldsOf(spChain).samlSpMetadataValidUntil);
    t.equal(fieldsOf(spChain).samlSpMetadataCacheDuration, 'PT10M',
            'and the effective cacheDuration the shortest');
    t.check([].concat(fieldsOf(spChain).samlSingleLogoutService || [])
              .indexOf('https://sp.test/acs/slo') >= 0 &&
            [].concat(fieldsOf(spChain).samlAssertionConsumerService || [])
              .length === 1,
            'and what it registered is this entity\'s alone');
    const missing = spMetadata.upload(spChain, aggregate(
      entity('https://someone-else.test/sp')));
    t.check(!missing.ok && /does not describe/.test(missing.errors.join(' ')),
            'an aggregate that does not describe the entity is REFUSED',
            JSON.stringify(missing.errors));

    // -----------------------------------------------------------------------
    t.log.info('3b. a stale document with a URL is refreshed in the ' +
               'background');
    // -----------------------------------------------------------------------
    const spR = newSp('refreshed', {
      samlSpMetadataUrl: base + '/md/refreshed' });
    served['/md/refreshed'] = { status: 200, body: entity(spR, {
      acs: 'https://one.test/acs', cacheDuration: 'PT0S',
      validUntil: inSeconds(3600) }) };
    const first = await spMetadata.refresh(spR);
    t.check(first.ok, 'the first document is fetched and consumed',
            JSON.stringify(first.errors || ''));
    t.equal(spMetadata.freshness(fieldsOf(spR)).state, 'stale',
            'with cacheDuration PT0S it is STALE at once');
    t.check(spMetadata.freshness(fieldsOf(spR)).refreshable,
            'and refreshable, because the entry names a URL');
    const hitsBefore = hits['/md/refreshed'] || 0;
    t.check(toSignIn(redirect(sso, '/saml2/sso', authnRequest(spR, '_r1'))),
            'a stale document still WORKS');
    t.equal(hits['/md/refreshed'] || 0, hitsBefore,
            'and answering that request dialled NOTHING');
    served['/md/refreshed'] = { status: 200, body: entity(spR, {
      acs: 'https://two.test/acs', cacheDuration: 'PT0S',
      validUntil: inSeconds(3600) }) };
    const swept = await spMetadata.sweepOnce();
    t.check(swept.refreshed >= 1,
            'one sweep of the refresher REFRESHED it', JSON.stringify(swept));
    t.equal(hits['/md/refreshed'], hitsBefore + 1,
            'with one request to the local server');
    t.check([].concat(fieldsOf(spR).samlAssertionConsumerService || [])
              .indexOf('https://two.test/acs') >= 0 &&
            [].concat(fieldsOf(spR).samlAssertionConsumerService || [])
              .indexOf('https://one.test/acs') < 0,
            'and the entry now holds the NEW document\'s endpoint',
            JSON.stringify(fieldsOf(spR).samlAssertionConsumerService));
    t.check(spMetadata.refreshStatus(spR).ok,
            'the refresher records a success');

    const consumedBefore = fieldsOf(spR).samlSpMetadataConsumedAt;
    served['/md/refreshed'] = { status: 500, body: 'down' };
    const failed = await spMetadata.sweepOnce();
    t.check(failed.failed >= 1, 'a sweep whose fetch FAILS counts a failure',
            JSON.stringify(failed));
    t.equal(fieldsOf(spR).samlSpMetadataConsumedAt, consumedBefore,
            'and changes NOTHING on the entry');
    const state = spMetadata.refreshStatus(spR);
    t.check(state && !state.ok && state.failingSince &&
            /500/.test(state.why),
            'the failure is recorded as a STATE, with why',
            JSON.stringify(state));
    t.check(view(spR).refresh && view(spR).refresh.ok === false,
            'and the console/API view shows it');
    t.check(toSignIn(redirect(sso, '/saml2/sso', authnRequest(spR, '_r2'))),
            'the last good document KEEPS WORKING until its validUntil');
    applications.replaceSamlMetadataFields(spR, {
      samlSpMetadataValidUntil: new Date(Date.now() - 1000).toISOString()
    }, { how: 'test' });
    t.equal(codeOf(redirect(sso, '/saml2/sso', authnRequest(spR, '_r3'))),
            'STS-SAML-0074', 'and once that passes it is refused');
    const offSweep = await kit.withSettings(config,
      { 'saml2.spMetadataRefresh': false },
      function () {
        return spMetadata.sweepOnce();
      });
    t.equal(offSweep.due, 0,
            'with saml2.spMetadataRefresh off a sweep looks at nothing');

    // -----------------------------------------------------------------------
    t.log.info('3c. an uploaded stale document is shown stale and works');
    // -----------------------------------------------------------------------
    const spU = newSp('uploaded');
    t.check(spMetadata.upload(spU, entity(spU, { cacheDuration: 'PT0S' }))
              .ok, 'an uploaded document with cacheDuration PT0S');
    t.equal(view(spU).state, 'stale', 'is shown STALE');
    t.equal(view(spU).refreshable, false, 'and not refreshable');
    const uploadSweep = await spMetadata.sweepOnce();
    t.check(spMetadata.refreshStatus(spU) === null,
            'the refresher does not try it', JSON.stringify(uploadSweep));
    t.check(toSignIn(redirect(sso, '/saml2/sso', authnRequest(spU, '_u1'))),
            'and it WORKS');
    t.equal(spMetadata.durationMs('P1DT2H3M4.5S'),
            ((24 + 2) * 60 + 3) * 60000 + 4500,
            'xs:duration is read (P1DT2H3M4.5S)');
    t.equal(spMetadata.durationMs('P'), -1, 'and a bare P is unreadable');

    // -----------------------------------------------------------------------
    t.log.info('D1. a realm trust anchor');
    // -----------------------------------------------------------------------
    const anchor = kit.keyFor(kit.FAMILIES.filter(function (row) {
      return row[0] === 'ecdsa-p256-sha256';
    })[0]);
    const stranger = kit.keyFor(kit.FAMILIES.filter(function (row) {
      return row[0] === 'ed25519';
    })[0]);
    const spA = newSp('anchored');
    await kit.withSettings(config,
      { 'saml2.metadataTrustAnchors': anchor.cert.b64 + ',notacertificate' },
      async function () {
        t.check(spMetadata.anchorProblems().length === 1,
                'an anchor that is not a certificate is NAMED',
                spMetadata.anchorProblems().join(' '));
        const unsigned = spMetadata.upload(spA, entity(spA));
        t.check(!unsigned.ok && /trust anchor/.test(unsigned.errors.join(' ')),
                'with a realm anchor set, an UNSIGNED document is refused',
                JSON.stringify(unsigned.errors));
        const foreign = spMetadata.upload(spA, kit.signEnveloped(stsCrypto,
          entity(spA), stranger));
        t.check(!foreign.ok, 'one signed by another key is refused',
                JSON.stringify(foreign.errors));
        const good = spMetadata.upload(spA, kit.signEnveloped(stsCrypto,
          entity(spA), anchor));
        t.check(good.ok && fieldsOf(spA).samlSpMetadataSignature ===
                'verified',
                'one signed by the realm anchor is VERIFIED and consumed',
                JSON.stringify(good.errors || ''));
        const signedAggregate = kit.signEnveloped(stsCrypto, aggregate(
          entity('https://other.test/sp') +
          entity(spA, { acs: 'https://agg.test/acs', ns: false })), anchor);
        const agg = spMetadata.upload(spA, signedAggregate);
        t.check(agg.ok && [].concat(fieldsOf(spA)
          .samlAssertionConsumerService || []).indexOf(
          'https://agg.test/acs') >= 0,
                'an EntitiesDescriptor SIGNED AS A WHOLE by the anchor is ' +
                'consumed for this entity', JSON.stringify(agg.errors || ''));
        const tamperedAgg = spMetadata.upload(spA, signedAggregate.replace(
          'https://other.test/sp', 'https://evil.test/sp'));
        t.check(!tamperedAgg.ok,
                'and a tampered aggregate is refused',
                JSON.stringify(tamperedAgg.errors));
        const innerSigned = aggregate(
          entity('https://other.test/sp') +
          kit.signEnveloped(stsCrypto, entity(spA,
            { acs: 'https://inner.test/acs' }), anchor));
        const inner = spMetadata.upload(spA, innerSigned);
        t.check(inner.ok && [].concat(fieldsOf(spA)
          .samlAssertionConsumerService || []).indexOf(
          'https://inner.test/acs') >= 0,
                'an unsigned aggregate whose ENTITY is signed by the anchor ' +
                'is consumed', JSON.stringify(inner.errors || ''));
      });
    const unanchored = spMetadata.upload(spA, entity(spA));
    t.check(unanchored.ok &&
            fieldsOf(spA).samlSpMetadataSignature === 'unsigned',
            'with no anchor at all, an unsigned document is consumed and ' +
            'recorded unsigned', JSON.stringify(unanchored.errors || ''));
    const unqualified = spMetadata.upload(spA, entity(spA,
      { unqualified: anchor.cert.b64 }));
    t.check(unqualified.ok &&
            [].concat(fieldsOf(spA).samlSigningCertificate || [])
              .indexOf(anchor.cert.b64) >= 0 &&
            fieldsOf(spA).samlSpWantAssertionsEncrypted === 'FALSE',
            'an UNQUALIFIED EC key registers as a signing key, is not an ' +
            'encryption key, and does not refuse the document',
            JSON.stringify(unqualified.errors || ''));

    // -----------------------------------------------------------------------
    t.log.info('D2. the Metadata Query Protocol');
    // -----------------------------------------------------------------------
    const mdqName = 'https://mdq-' + stamp + '.md.test/saml';
    created.push(mdqName);
    const unconfigured = await spMetadata.mdqImport(mdqName);
    t.check(!unconfigured.ok &&
            errorCodes.codeOf(unconfigured) === 'STS-SAML-0075',
            'with no responder configured an import is refused, STS-SAML-0075');
    config.setOverride('saml2.mdqBaseUrl', base + '/mdq/');
    t.equal(spMetadata.mdqUrlFor(mdqName),
            base + '/mdq/entities/' + encodeURIComponent(mdqName),
            'the MDQ URL is <base>/entities/<percent-encoded entityID>');
    served['/mdq/entities/' + mdqName] = { status: 200,
      body: entity(mdqName, { acs: 'https://mdq.test/acs' }) };
    const imported = await adminActions.saml2Action({ action: 'mdq-import',
                                                      sp: mdqName });
    t.check(imported.ok && imported.created &&
            / mdq$/.test(fieldsOf(mdqName).samlSpMetadataConsumedAt),
            'an import CREATES the entry and consumes the answer (how: mdq), ' +
            'through the console/API action',
            JSON.stringify(imported.errors || imported.message));
    const unknownName = 'https://nobody-' + stamp + '.md.test/saml';
    const notFound = await spMetadata.mdqImport(unknownName);
    t.check(!notFound.ok && errorCodes.codeOf(notFound) === 'STS-SAML-0048' &&
            !applications.get(unknownName),
            'a 404 imports nothing and creates no entry',
            JSON.stringify(notFound.errors));
    const prodName = 'https://prod-' + stamp + '.md.test/saml';
    const prodBefore = hits['/mdq/entities/' + prodName] || 0;
    const prodRefused = await kit.withSettings(config,
      { 'global.mode': 'product' },
      function () {
        return spMetadata.mdqImport(prodName);
      });
    t.check(!prodRefused.ok &&
            errorCodes.codeOf(prodRefused) === 'STS-SAML-0079' &&
            (hits['/mdq/entities/' + prodName] || 0) === prodBefore,
            'in PRODUCT mode the loopback responder is refused by the ' +
            'outbound policy, STS-SAML-0079, and nothing is dialled',
            JSON.stringify(prodRefused.errors));
    // MDQ-sourced metadata is refreshable by the sweep.
    served['/mdq/entities/' + mdqName] = { status: 200,
      body: entity(mdqName, { acs: 'https://mdq2.test/acs',
                              cacheDuration: 'PT0S' }) };
    await spMetadata.refresh(mdqName);
    t.check(spMetadata.freshness(fieldsOf(mdqName)).refreshable &&
            [].concat(fieldsOf(mdqName).samlAssertionConsumerService || [])
              .indexOf('https://mdq2.test/acs') >= 0,
            'an entry with no URL is refreshed FROM the MDQ responder, and ' +
            'is refreshable in the background');

    // An SSO request from an unknown SP: answered now, looked up after.
    const lazyName = 'https://lazy-' + stamp + '.md.test/saml';
    created.push(lazyName);
    served['/mdq/entities/' + lazyName] = { status: 200,
      body: entity(lazyName, { acs: 'https://lazy.test/acs' }) };
    const lazyRes = redirect(sso, '/saml2/sso',
                             authnRequest(lazyName, '_z1'));
    t.check(lazyRes.statusCode === 303 && !codeOf(lazyRes),
            'a request from an SP with no metadata is ANSWERED NOW ' +
            '(development: on to the sign-in screen)',
            lazyRes.statusCode + ' ' + codeOf(lazyRes));
    t.equal(hits['/mdq/entities/' + lazyName] || 0, 0,
            'and nothing was dialled while it was answered');
    for (let i = 0; i < 50 && !(applications.get(lazyName) &&
         fieldsOf(lazyName).samlSpMetadataConsumedAt); i++) {
      await wait(40);
    }
    t.equal(hits['/mdq/entities/' + lazyName], 1,
            'the lookup it started happened AFTERWARDS, once');
    t.check(/ mdq$/.test(String(fieldsOf(lazyName)
      .samlSpMetadataConsumedAt || '')),
            'and the NEXT request finds the registration');
    redirect(sso, '/saml2/sso', authnRequest(lazyName, '_z2'));
    await wait(100);
    t.equal(hits['/mdq/entities/' + lazyName], 1,
            'a registered SP starts no further lookup');
    const ghost = 'https://ghost-' + stamp + '.md.test/saml';
    created.push(ghost);
    redirect(sso, '/saml2/sso', authnRequest(ghost, '_z3'));
    redirect(sso, '/saml2/sso', authnRequest(ghost, '_z4'));
    await wait(200);
    t.equal(hits['/mdq/entities/' + ghost], 1,
            'an entityID nobody publishes is asked for ONCE per interval, ' +
            'however many requests name it');
    config.clearOverride('saml2.mdqBaseUrl');

    // -----------------------------------------------------------------------
    t.log.info('E. encryption per mode');
    // -----------------------------------------------------------------------
    const cookieJar = [];
    const session = authn.startSession({
      req: null,
      getHeader: function () {
        log.debug("Entering getHeader().");
        log.debug("Leaving getHeader().");
        return cookieJar.slice();
      },
      setHeader: function (name, value) {
        log.debug("Entering setHeader().");
        cookieJar.length = 0;
        [].concat(value).forEach(function (v) {
          cookieJar.push(v);
        });
        log.debug("Leaving setHeader().");
      }
    }, 'alice', [], '1', 'Test', {});
    const issue = function (sp, id) {
      log.debug("Entering issue().");
      const res = kit.fakeRes();
      direct.issueSignInResponse(res, {
        request: direct.readAuthnRequest(authnRequest(sp, id)),
        session: session, spEntityId: sp,
        idpEntityId: 'https://idp.test/saml2/metadata',
        acsUrl: 'https://sp.test/acs', binding: B_POST, relayState: ''
      });
      const m = /name="SAMLResponse" value="([^"]+)"/.exec(res.body);
      res.xml = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
      log.debug("Leaving issue().");
      return res;
    };
    const spNoCert = newSp('no-cert');
    await kit.withSettings(config, { 'saml2.encryptAssertion': true },
      async function () {
        const dev = issue(spNoCert, '_e1');
        t.check(/<saml:Assertion\b/.test(dev.xml) &&
                !/EncryptedAssertion/.test(dev.xml),
                'DEVELOPMENT, encryption on, no certificate: the assertion ' +
                'goes in CLEAR', dev.xml.slice(0, 200));
        const prod = kit.withSettings(config, { 'global.mode': 'product' },
          function () {
            return issue(spNoCert, '_e2');
          });
        t.check(/status:Responder/.test(prod.xml) &&
                !/<saml:Assertion\b|EncryptedAssertion/.test(prod.xml) &&
                codeOf(prod) === 'STS-SAML-0011',
                'PRODUCT: Responder, NO assertion, STS-SAML-0011',
                codeOf(prod) + ' ' + prod.xml.slice(0, 300));
      });
    const encryptionKey = stsCrypto.selfSignedRsaCertificate({
      commonName: 'sp-encryption', bits: 2048 });
    const spWants = newSp('wants-encryption');
    const wants = spMetadata.upload(spWants, entity(spWants,
      { encryption: encryptionKey.certB64 }));
    t.check(wants.ok &&
            fieldsOf(spWants).samlSpWantAssertionsEncrypted === 'TRUE',
            'metadata publishing a use="encryption" key is recorded as ' +
            'WANTING encrypted assertions',
            JSON.stringify(wants.errors || ''));
    t.equal(config.value('saml2.encryptAssertion'), false,
            'with saml2.encryptAssertion OFF');
    ['development', 'product'].forEach(function (mode) {
      const answered = kit.withSettings(config, { 'global.mode': mode },
        function () {
          return issue(spWants, '_w' + mode);
        });
      t.check(/EncryptedAssertion/.test(answered.xml) &&
              !/<saml:Assertion\b/.test(answered.xml),
              mode + ': the assertion is ENCRYPTED to the metadata\'s key',
              answered.xml.slice(0, 200));
    });
  } finally {
    config.clearOverride('saml2.mdqBaseUrl');
    config.clearOverride('federation.outboundAllowInsecure');
    config.clearOverride('federation.outbound');
    created.forEach(function (id) {
      if (applications.get(id)) {
        applications.deleteApplication(id);
      }
    });
    await new Promise(function (resolve) {
      server.close(resolve);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_metadata_lifecycle',
  describe: 'SP metadata after consumption: validUntil refuses, ' +
            'cacheDuration refreshes in the background, realm trust ' +
            'anchors, aggregates, MDQ, and encryption by mode (#37 ' +
            'follow-up)',
  run: run
};
