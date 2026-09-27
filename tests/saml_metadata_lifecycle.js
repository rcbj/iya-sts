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
//   F. WHAT AN UNKNOWN SERVICE PROVIDER CAN CAUSE (#112). In PRODUCT an
//      anonymous AuthnRequest from an unknown entityID with MDQ configured
//      asks the responder NOTHING without a realm trust anchor
//      (STS-SAML-0080), and with one registers the entity only when the
//      answer verifies against it (an unsigned or foreign-signed answer is
//      STS-SAML-0081); a registered entry is still looked up; an operator's
//      import with no anchor is refused (STS-SAML-0084) unless
//      saml2.mdqImportWithoutAnchors is on, when the reply warns; the
//      refused entityIDs are listed newest first on GET /admin-api/saml2
//      and the page; every per-provider path of both profiles is a 404
//      for a name that is not a registered provider of THAT profile
//      (STS-SAML-0082, 0083). DEVELOPMENT is unchanged throughout.
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
  const saml11sso = require('../saml/saml11_sso');
  const spMetadata = require('../saml/sp_metadata');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  const authn = require('../authn/authn');
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
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
  config.setOverride('federation.outboundAllowHttp', true);
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
      'IssueInstant="' + new Date().toISOString() + '" ' +
      'Destination="https://idp.test/saml2/sso">' +
      '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
  };
  const logoutRequest = function (issuer, id) {
    log.debug("Entering logoutRequest().");
    log.debug("Leaving logoutRequest().");
    return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
      'IssueInstant="' + new Date().toISOString() + '" ' +
      'Destination="https://idp.test/saml2/slo">' +
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
    // IN PRODUCT PLAIN HTTP IS REFUSED FIRST (#171), whatever
    // federation.outboundAllowHttp says; the address rule is then asked of
    // the same responder over https, which is refused before any connection
    // is opened and so needs no listener that speaks it.
    // Both are an OPERATOR's import with saml2.mdqImportWithoutAnchors on,
    // so that the only refusal left to reach is the transport's (#112 put
    // two in front of it; section F holds those).
    const prodPlain = await kit.withSettings(config,
      { 'global.mode': 'product', 'saml2.mdqImportWithoutAnchors': true },
      function () {
        return spMetadata.mdqImport(prodName, { origin: 'operator' });
      });
    t.check(!prodPlain.ok &&
            /product mode/.test(JSON.stringify(prodPlain.errors || '')) &&
            !/trust anchor/.test(JSON.stringify(prodPlain.errors || '')) &&
            (hits['/mdq/entities/' + prodName] || 0) === prodBefore,
            'in PRODUCT mode a plain-http responder is refused whatever ' +
            'federation.outboundAllowHttp says, and nothing is dialled',
            JSON.stringify(prodPlain.errors));
    const prodRefused = await kit.withSettings(config,
      { 'global.mode': 'product', 'saml2.mdqImportWithoutAnchors': true,
        'saml2.mdqBaseUrl': base.replace(/^http:/, 'https:') + '/mdq/' },
      function () {
        return spMetadata.mdqImport(prodName, { origin: 'operator' });
      });
    t.check(!prodRefused.ok &&
            errorCodes.codeOf(prodRefused) === 'STS-SAML-0079' &&
            (hits['/mdq/entities/' + prodName] || 0) === prodBefore,
            'in PRODUCT mode the loopback responder is refused by the ' +
            'outbound policy, STS-SAML-0079, and nothing is dialled',
            JSON.stringify(prodRefused.errors));
    // withSettings() CLEARS what it set, so the responder the rest of this
    // file uses is set again.
    config.setOverride('saml2.mdqBaseUrl', base + '/mdq/');
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
    t.log.info('F1. #112: what a request-started MDQ lookup may register');
    // -----------------------------------------------------------------------
    // THE TRANSPORT IS STUBBED HERE, AND ONLY HERE. Product mode refuses both
    // plain http and a loopback responder before a connection is opened
    // (D2 above holds both), so a product-mode answer can only reach
    // mdqImport() through a fetcher that hands it the local server's
    // document directly. What is under test is what the ANSWER may do; the
    // fetch has its own checks in D2.
    config.setOverride('saml2.mdqBaseUrl', base + '/mdq/');
    const probe = new spMetadata.SpMetadata(
      spMetadata.SpMetadata.defaultDeps());
    const asked = [];
    probe.fetchMetadata = function (url) {
      log.debug("Entering probe.fetchMetadata().");
      asked.push(url);
      const path = decodeURIComponent(new URL(url).pathname);
      const answer = served[path] || { status: 404, body: 'no' };
      log.debug("Leaving probe.fetchMetadata().");
      return Promise.resolve(answer.status === 200
        ? { ok: true, xml: answer.body }
        : { ok: false, errorCode: 'STS-SAML-0048',
            why: 'the responder answered ' + answer.status });
    };
    const probeSso = new saml2sso.Saml2Sso(Object.assign(
      saml2sso.Saml2Sso.defaultDeps(), { spMetadata: probe }));
    const probeHandler = function (req, res) {
      log.debug("Entering probeHandler().");
      log.debug("Leaving probeHandler().");
      return probeSso.singleSignOn(req, res);
    };
    const askedFor = function (name) {
      log.debug("Entering askedFor().");
      log.debug("Leaving askedFor().");
      return asked.filter(function (u) {
        return u.indexOf(encodeURIComponent(name)) >= 0;
      }).length;
    };
    const settle = async function (name, n) {
      log.debug("Entering settle().");
      for (let i = 0; i < 50 && askedFor(name) < n; i++) {
        await wait(20);
      }
      await wait(60);
      log.debug("Leaving settle().");
    };
    const refusedRow = function (name) {
      log.debug("Entering refusedRow().");
      log.debug("Leaving refusedRow().");
      return probe.mdqRefusalList().filter(function (row) {
        return row.entityId === name;
      })[0] || null;
    };
    const unknown = function (label) {
      log.debug("Entering unknown().");
      const name = 'https://' + label + '-' + stamp + '.md.test/saml';
      created.push(name);
      served['/mdq/entities/' + name] = { status: 200,
        body: entity(name, { acs: 'https://' + label + '.test/acs' }) };
      log.debug("Leaving unknown().");
      return name;
    };

    const bare = unknown('prod-bare');
    await kit.withSettings(config, { 'global.mode': 'product' },
      async function () {
        const res = redirect(probeHandler, '/saml2/sso',
                             authnRequest(bare, '_p1'));
        t.check(res.statusCode === 403,
                'PRODUCT: an anonymous AuthnRequest from an unknown SP is ' +
                'refused (unsigned)', res.statusCode + ' ' + codeOf(res));
        await settle(bare, 1);
      });
    t.equal(askedFor(bare), 0,
            'PRODUCT, no trust anchor: the MDQ responder is NEVER ASKED');
    t.check(!applications.get(bare), 'and nothing is registered');
    t.check(refusedRow(bare) && refusedRow(bare).errorCode ===
            'STS-SAML-0080',
            'the entityID is listed as refused, STS-SAML-0080',
            JSON.stringify(refusedRow(bare)));
    await kit.withSettings(config, { 'global.mode': 'product' },
      async function () {
        const direct80 = await probe.mdqImport(bare);
        t.check(!direct80.ok && errorCodes.codeOf(direct80) ===
                'STS-SAML-0080' && askedFor(bare) === 0,
                'mdqImport() with no origin is a REQUEST lookup, and is ' +
                'refused the same way without dialling',
                JSON.stringify(direct80.errors));
        redirect(probeHandler, '/saml2/sso', authnRequest(bare, '_p1b'));
      });
    t.equal(refusedRow(bare).count, 3,
            'a second request for it counts, and is one row');

    await kit.withSettings(config,
      { 'global.mode': 'product',
        'saml2.metadataTrustAnchors': anchor.cert.b64 },
      async function () {
        const unsignedName = unknown('prod-unsigned');
        redirect(probeHandler, '/saml2/sso',
                 authnRequest(unsignedName, '_p2'));
        await settle(unsignedName, 1);
        t.equal(askedFor(unsignedName), 1,
                'PRODUCT with a realm anchor: the responder IS asked');
        t.check(!applications.get(unsignedName),
                'an UNSIGNED answer registers nothing');
        t.equal((refusedRow(unsignedName) || {}).errorCode,
                'STS-SAML-0081', 'and it is listed, STS-SAML-0081');

        const strangerName = unknown('prod-stranger');
        served['/mdq/entities/' + strangerName].body = kit.signEnveloped(
          stsCrypto, entity(strangerName), stranger);
        redirect(probeHandler, '/saml2/sso',
                 authnRequest(strangerName, '_p3'));
        await settle(strangerName, 1);
        t.check(!applications.get(strangerName) &&
                (refusedRow(strangerName) || {}).errorCode ===
                'STS-SAML-0081',
                'an answer signed by ANOTHER key registers nothing, ' +
                'STS-SAML-0081');

        const goodName = unknown('prod-signed');
        served['/mdq/entities/' + goodName].body = kit.signEnveloped(
          stsCrypto, entity(goodName, { acs: 'https://good.test/acs' }),
          anchor);
        redirect(probeHandler, '/saml2/sso', authnRequest(goodName, '_p4'));
        await settle(goodName, 1);
        for (let i = 0; i < 25 && !applications.get(goodName); i++) {
          await wait(20);
        }
        t.check(applications.get(goodName) &&
                fieldsOf(goodName).samlSpMetadataSignature === 'verified' &&
                [].concat(fieldsOf(goodName).samlAssertionConsumerService ||
                          []).indexOf('https://good.test/acs') >= 0,
                'an answer that VERIFIES against the realm anchor registers ' +
                'the service provider', JSON.stringify(fieldsOf(goodName)
                  .samlSpMetadataSignature));
        t.check(!refusedRow(goodName), 'and is not listed as refused');
      });

    const devName = unknown('dev-lookup');
    redirect(probeHandler, '/saml2/sso', authnRequest(devName, '_d1'));
    await settle(devName, 1);
    for (let i = 0; i < 25 && !applications.get(devName); i++) {
      await wait(20);
    }
    t.check(askedFor(devName) === 1 && applications.get(devName) &&
            fieldsOf(devName).samlSpMetadataSignature === 'unsigned',
            'DEVELOPMENT is unchanged: no anchor, an unsigned answer, and ' +
            'the request\'s lookup registers the service provider');

    // An entry that EXISTS is refreshed from MDQ as before, in product too.
    const existing = newSp('prod-existing');
    served['/mdq/entities/' + existing] = { status: 200,
      body: entity(existing, { acs: 'https://existing.test/acs' }) };
    await kit.withSettings(config, { 'global.mode': 'product' },
      async function () {
        redirect(probeHandler, '/saml2/sso', authnRequest(existing, '_e0'));
        await settle(existing, 1);
      });
    t.check(askedFor(existing) === 1 && [].concat(fieldsOf(existing)
      .samlAssertionConsumerService || []).indexOf(
      'https://existing.test/acs') >= 0,
            'PRODUCT: a REGISTERED service provider with no metadata is ' +
            'still looked up and consumed');

    // -----------------------------------------------------------------------
    t.log.info('F2. #112: an operator\'s MDQ import');
    // -----------------------------------------------------------------------
    const opName = unknown('operator');
    await kit.withSettings(config, { 'global.mode': 'product' },
      async function () {
        const refused = await probe.mdqImport(opName, { origin: 'operator' });
        t.check(!refused.ok && errorCodes.codeOf(refused) ===
                'STS-SAML-0084' && askedFor(opName) === 0 &&
                !applications.get(opName),
                'PRODUCT, no anchor: an operator import is REFUSED, ' +
                'STS-SAML-0084, and nothing is fetched',
                JSON.stringify(refused.errors));
        const viaAction = await adminActions.saml2Action({
          action: 'mdq-import', sp: opName });
        t.check(!viaAction.ok && /trust anchor/.test(
          JSON.stringify(viaAction.errors)) && !applications.get(opName),
                'and so is the console/API action',
                JSON.stringify(viaAction.errors));
        const allowed = await kit.withSettings(config,
          { 'saml2.mdqImportWithoutAnchors': true },
          function () {
            return probe.mdqImport(opName, { origin: 'operator' });
          });
        t.check(allowed.ok && allowed.created &&
                /WITHOUT a signature check/.test(
                  (allowed.warnings || []).join(' ') + allowed.message),
                'with saml2.mdqImportWithoutAnchors ON it is imported, ' +
                'and the reply WARNS that nothing was verified',
                JSON.stringify(allowed.errors || allowed.warnings));
        const signedOp = unknown('operator-signed');
        served['/mdq/entities/' + signedOp].body = kit.signEnveloped(
          stsCrypto, entity(signedOp), anchor);
        const anchored = await kit.withSettings(config,
          { 'saml2.metadataTrustAnchors': anchor.cert.b64 },
          function () {
            return probe.mdqImport(signedOp, { origin: 'operator' });
          });
        t.check(anchored.ok && !anchored.warnings &&
                fieldsOf(signedOp).samlSpMetadataSignature === 'verified',
                'with a realm anchor an operator import is verified and ' +
                'carries no warning', JSON.stringify(anchored.errors || ''));
      });
    const devOp = unknown('operator-dev');
    const devImported = await probe.mdqImport(devOp, { origin: 'operator' });
    t.check(devImported.ok && devImported.created && !devImported.warnings,
            'DEVELOPMENT: an operator import with no anchor works as before',
            JSON.stringify(devImported.errors || ''));

    // -----------------------------------------------------------------------
    t.log.info('F3. #112: the refused entityIDs on the page and the API');
    // -----------------------------------------------------------------------
    const listed = adminViews.saml2ListJson(kit.fakeReq('GET', '/admin/saml2',
      { per: '1', mdqRefusedPage: '1' }, '')).json;
    // The record is the module's, shared by every instance of it, so the
    // probe's refusals are listed too; one more is refused through the
    // module's own facade so the newest row is known.
    t.check(Array.isArray(listed.mdqRefused) && listed.mdqRefusedPaging &&
            listed.mdqRefusedPaging.param === 'mdqRefusedPage',
            'GET /admin-api/saml2 carries mdqRefused with its own pager',
            JSON.stringify(listed.mdqRefusedPaging));
    const viaModule = unknown('listed');
    kit.withSettings(config, { 'global.mode': 'product' }, function () {
      spMetadata.queueMdqLookup(viaModule);
    });
    const relisted = adminViews.saml2ListJson(kit.fakeReq('GET',
      '/admin/saml2', {}, '')).json;
    t.check(relisted.mdqRefused.length >= 1 &&
            relisted.mdqRefused[0].entityId === viaModule &&
            relisted.mdqRefused[0].errorCode === 'STS-SAML-0080',
            'the newest refusal is FIRST',
            JSON.stringify(relisted.mdqRefused.slice(0, 2)));
    // The page's own view, below the console gate.
    const drawn = require('../admin-ui/admin').saml2View(
      kit.fakeReq('GET', '/admin/saml2', {}, '')).inner;
    t.check(/Metadata Query lookups refused/.test(drawn) &&
            drawn.indexOf(viaModule) >= 0,
            'and the SAML 2.0 page draws it');
    config.clearOverride('saml2.mdqBaseUrl');

    // -----------------------------------------------------------------------
    t.log.info('F4. #112: per-provider paths for an unregistered name');
    // -----------------------------------------------------------------------
    const scopedGet = function (handler, path, name, param) {
      log.debug("Entering scopedGet().");
      const res = kit.fakeRes();
      const params = {};
      params[param] = name;
      handler(kit.fakeReq('GET', path + '/' + encodeURIComponent(name), {},
                          '', '', { params: params }), res);
      log.debug("Leaving scopedGet().");
      return res;
    };
    const scopedPost = function (handler, path, name, param) {
      log.debug("Entering scopedPost().");
      const res = kit.fakeRes();
      const params = {};
      params[param] = name;
      handler(kit.fakeReq('POST', path + '/' + encodeURIComponent(name), {},
                          '', '<x/>', { params: params }), res);
      log.debug("Leaving scopedPost().");
      return res;
    };
    const meta2 = kit.handlerFor(app, 'get', '/saml2/metadata/:sp');
    const sso2 = kit.handlerFor(app, 'get', '/saml2/sso/:sp');
    const slo2 = kit.handlerFor(app, 'get', '/saml2/slo/:sp');
    const ars2 = kit.handlerFor(app, 'post', '/saml2/ars/:sp');
    const meta11 = kit.handlerFor(app, 'get', '/saml11/metadata/:rp');
    const sso11 = kit.handlerFor(app, 'get', '/saml11/sso/:rp');
    const responder11 = kit.handlerFor(app, 'post', '/saml11/responder/:rp');
    const nobody = 'https://nobody-at-all-' + stamp + '.md.test/saml';
    created.push(nobody);
    const registered2 = newSp('published');
    const rp11 = 'https://rp11-' + stamp + '.md.test/saml';
    t.check(applications.createApplication({
      identifier: rp11, kind: 'saml11-relying-party', protocol: 'SAML 1.1',
      fields: { samlEntityId: rp11 } }).ok, 'a SAML 1.1 relying party');
    created.push(rp11);
    const oauthClient = 'oauth-only-' + stamp;
    t.check(applications.createApplication({
      identifier: oauthClient, kind: 'oauth2-client', protocol: 'OAuth 2.0',
      fields: { oauthClientId: oauthClient } }).ok, 'an OAuth client');
    created.push(oauthClient);
    const is404 = function (res, code) {
      log.debug("Entering is404().");
      log.debug("Leaving is404().");
      return res.statusCode === 404 && codeOf(res) === code &&
             /text\/plain/.test(res.headers['content-type'] || '') &&
             res.headers['cache-control'] === 'no-store';
    };
    await kit.withSettings(config, { 'global.mode': 'product' },
      async function () {
        const m = scopedGet(meta2, '/saml2/metadata', nobody, 'sp');
        t.check(is404(m, 'STS-SAML-0082') && !applications.get(nobody),
                'PRODUCT: /saml2/metadata/{unregistered} is 404, ' +
                'text/plain, no-store, STS-SAML-0082, and registers nothing',
                m.statusCode + ' ' + codeOf(m) + ' ' + m.body.slice(0, 120));
        [['sso', sso2, scopedGet], ['slo', slo2, scopedGet],
         ['ars', ars2, scopedPost]].forEach(function (row) {
          const r = row[2](row[1], '/saml2/' + row[0], nobody, 'sp');
          t.check(is404(r, 'STS-SAML-0082'),
                  'PRODUCT: /saml2/' + row[0] + '/{unregistered} is 404 too',
                  r.statusCode + ' ' + codeOf(r));
        });
        const asOauth = scopedGet(meta2, '/saml2/metadata', oauthClient,
                                  'sp');
        t.check(is404(asOauth, 'STS-SAML-0082'),
                'an application that is NOT a SAML 2.0 service provider ' +
                'is 404 as well', asOauth.statusCode + ' ' + codeOf(asOauth));
        const mine = scopedGet(meta2, '/saml2/metadata', registered2, 'sp');
        t.check(mine.statusCode === 200 && /EntityDescriptor/.test(mine.body),
                'a REGISTERED service provider\'s document is 200',
                mine.statusCode + ' ' + mine.body.slice(0, 160));
        const bySlug = scopedGet(meta2, '/saml2/metadata',
                                 saml2sso.slugOf(registered2), 'sp');
        t.equal(bySlug.statusCode, 200, 'and by its slug');
        const m11 = scopedGet(meta11, '/saml11/metadata', nobody, 'rp');
        t.check(is404(m11, 'STS-SAML-0083'),
                'PRODUCT: /saml11/metadata/{unregistered} is 404, ' +
                'STS-SAML-0083', m11.statusCode + ' ' + codeOf(m11));
        const s11 = scopedGet(sso11, '/saml11/sso', nobody, 'rp');
        const r11 = scopedPost(responder11, '/saml11/responder', nobody,
                               'rp');
        t.check(is404(s11, 'STS-SAML-0083') && is404(r11, 'STS-SAML-0083'),
                'and so are /saml11/sso/{rp} and /saml11/responder/{rp}',
                s11.statusCode + ' ' + r11.statusCode);
        const byRp = scopedGet(meta11, '/saml11/metadata', rp11, 'rp');
        t.check(byRp.statusCode === 200 &&
                /EntityDescriptor/.test(byRp.body),
                'a REGISTERED relying party\'s document is 200',
                byRp.statusCode + ' ' + byRp.body.slice(0, 160));
        const saml2As11 = scopedGet(meta11, '/saml11/metadata', registered2,
                                    'rp');
        t.check(is404(saml2As11, 'STS-SAML-0083'),
                'a SAML 2.0 service provider is not a SAML 1.1 relying ' +
                'party', saml2As11.statusCode + ' ' + codeOf(saml2As11));
      });
    const devMeta = scopedGet(meta2, '/saml2/metadata', nobody, 'sp');
    const devMeta11 = scopedGet(meta11, '/saml11/metadata', nobody, 'rp');
    t.check(devMeta.statusCode === 200 && devMeta11.statusCode === 200,
            'DEVELOPMENT is unchanged: both documents are minted for a ' +
            'name nobody registered', devMeta.statusCode + ' ' +
            devMeta11.statusCode);

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
    config.clearOverride('federation.outboundAllowHttp');
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
