'use strict';
//
// File: saml_interop_findings.js
//
// ===========================================================================
// WHAT THE FOUR SAML INTEROPERABILITY HARNESSES FOUND, HELD IN PROCESS
// (#189–#192).
//
// Shibboleth SP 3, pysaml2, SimpleSAMLphp and Keycloak each found something in
// saml/ that a round trip between two copies of this service's own
// understanding never could. Each fix has a check here, so it is held on
// every `npm test` and not only where a peer container runs:
//
//   A. THE ENVELOPE (#190, pysaml2): an AuthnRequest addressed elsewhere
//      (STS-SAML-0085), signed with no Destination (0085), stale or from the
//      future (0086), not Version 2.0 (0087), or replayed (0088) is refused;
//      a LogoutRequest's Destination is held to the same rule.
//   B. BACK-CHANNEL LOGOUT (#192, Keycloak): a LogoutRequest with no cookie
//      ends the session its SessionIndex names when that session gave the
//      service provider that NameID; another NameID ends nothing and is
//      answered UnknownPrincipal (0090).
//   C. IDENTITY-PROVIDER-INITIATED LOGOUT (#192): the LogoutRequest a link
//      carries is signed on the Redirect binding's QUERY STRING, carries no
//      enveloped signature, and names the NameID the session was given there.
//   D. IDENTITY-PROVIDER-INITIATED SSO (#189): /saml2/unsolicited, its
//      refusals (0091–0093, 0082) and an unsolicited Response with no
//      InResponseTo, at the registered ACS, carrying the X.500/LDAP names.
//   E. THE ATTRIBUTE AUTHORITY (#189): /saml2/aa answers about a subject a
//      live session gave the asking SP, echoes the NameID's qualifiers, narrows
//      to what was asked, and refuses the rest (0094, 0095).
//   F. THE METADATA (#189, #191): an AttributeAuthorityDescriptor; no
//      HTTP-Artifact SingleSignOnService; SAML 1.1's protocolSupportEnumeration
//      naming urn:mace:shibboleth:1.0.
//   G. SAML 1.1 (#189): Shibboleth's lower-case `target`, the profile taken
//      from the shire's registered binding, saml11.doNotCacheCondition, the
//      attribute names Shibboleth's map reads, and the product release
//      policy for a query (0039, 0096).
//   H. FEDERATION (#189, found by sts_federation_realms): a partner's value
//      sent under two names that map to one directory attribute — this
//      service's own `mail`, now under the claim URI and urn:oid — is written
//      once, not twice.
//
// The SimpleSign octets (#189) are held by saml_artifact_and_simplesign.js.
//
// WHY IN PROCESS: every section changes settings mid-run, several put a
// session in place directly, and the refusals are read off the response.
// ===========================================================================

delete process.env.CONFIG_FILE;

const zlib = require('zlib');
const nodeCrypto = require('crypto');
const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_interop_findings',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
const NS_SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
const B_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const B_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
const P11_POST = 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post';
const P11_ARTIFACT = 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01';
const UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
const IDP = 'https://idp.test';

function id() {
  log.debug("Entering id().");
  log.debug("Leaving id().");
  return '_f' + nodeCrypto.randomBytes(10).toString('hex');
}

function authnRequest(o) {
  log.debug("Entering authnRequest().");
  log.debug("Leaving authnRequest().");
  return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + (o.id || id()) + '" ' +
    'Version="' + (o.version || '2.0') + '"' +
    (o.issueInstant === null ? ''
      : ' IssueInstant="' + (o.issueInstant || new Date().toISOString()) +
        '"') +
    (o.destination === null ? ''
      : ' Destination="' + (o.destination || IDP + '/saml2/sso') + '"') +
    ' AssertionConsumerServiceURL="' + o.acs + '">' +
    '<saml:Issuer>' + o.issuer + '</saml:Issuer></samlp:AuthnRequest>';
}

function logoutRequest(o) {
  log.debug("Entering logoutRequest().");
  log.debug("Leaving logoutRequest().");
  return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id() + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '" Destination="' +
    (o.destination || IDP + '/saml2/slo') + '"><saml:Issuer>' + o.issuer +
    '</saml:Issuer><saml:NameID Format="' + UNSPECIFIED + '">' + o.nameId +
    '</saml:NameID>' + (o.sessionIndex ? '<samlp:SessionIndex>' +
    o.sessionIndex + '</samlp:SessionIndex>' : '') +
    '</samlp:LogoutRequest>';
}

function deflate(xml) {
  log.debug("Entering deflate().");
  log.debug("Leaving deflate().");
  return zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

function inflate(b64) {
  log.debug("Entering inflate().");
  log.debug("Leaving inflate().");
  return zlib.inflateRawSync(Buffer.from(b64, 'base64')).toString('utf8');
}

// A form body, as the POST binding sends one.
function form(fields) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(fields).toString();
}

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    '</soap:Body></soap:Envelope>';
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
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
  const sso = kit.handlerFor(app, 'get', '/saml2/sso');
  const sloPost = kit.handlerFor(app, 'post', '/saml2/slo');
  const unsolicited = kit.handlerFor(app, 'get', '/saml2/unsolicited');
  const aa = kit.handlerFor(app, 'post', '/saml2/aa');
  const metadata = kit.handlerFor(app, 'get', '/saml2/metadata/:sp');
  const metadata11 = kit.handlerFor(app, 'get', '/saml11/metadata/:rp');
  const sso11 = kit.handlerFor(app, 'get', '/saml11/sso');
  const responder = kit.handlerFor(app, 'post', '/saml11/responder');
  const direct = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
  const stamp = String(Date.now());
  const created = [];
  const codeOf = function (res) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(res) || '';
  };
  const newParty = function (name, kind, fields) {
    log.debug("Entering newParty().");
    const identifier = 'https://' + name + '-' + stamp + '.interop.test/sp';
    const made = applications.createApplication({
      identifier: identifier, kind: kind,
      protocol: kind === 'saml11-relying-party' ? 'SAML 1.1' : 'SAML 2.0',
      fields: Object.assign({ samlEntityId: identifier }, fields || {}) });
    t.check(made.ok, 'created ' + name, JSON.stringify(made.errors || ''));
    created.push(identifier);
    log.debug("Leaving newParty().");
    return identifier;
  };
  const getSso = function (xml) {
    log.debug("Entering getSso().");
    const res = kit.fakeRes();
    const raw = 'SAMLRequest=' + encodeURIComponent(deflate(xml));
    sso(kit.fakeReq('GET', '/saml2/sso', { SAMLRequest: deflate(xml) }, raw),
        res);
    log.debug("Leaving getSso().");
    return res;
  };
  // A session for `who`, and the cookie that names it.
  const sessionFor = function (who) {
    log.debug("Entering sessionFor().");
    const res = kit.fakeRes();
    const session = authn.startSession(res, who, ['pwd'], '1', 'a test',
                                       {});
    const cookie = String(res.headers['set-cookie'] || '').split(';')[0];
    log.debug("Leaving sessionFor().");
    return { session: session, cookie: cookie };
  };
  const withCookie = function (cookie) {
    log.debug("Entering withCookie().");
    log.debug("Leaving withCookie().");
    return { headers: { host: 'idp.test', cookie: cookie } };
  };
  const product = { 'global.mode': 'product',
                    'saml2.entityId': 'https://idp.test/saml2/idp' };

  try {
    // -----------------------------------------------------------------------
    t.log.info('A. the envelope of an AuthnRequest and a LogoutRequest');
    // -----------------------------------------------------------------------
    const spA = newParty('envelope', 'saml2-service-provider', {
      samlAssertionConsumerService: 'https://envelope.test/acs' });
    const base = { issuer: spA, acs: 'https://envelope.test/acs' };
    const elsewhere = getSso(authnRequest(Object.assign({
      destination: 'https://other-idp.test/sso' }, base)));
    t.check(elsewhere.statusCode === 400 &&
            codeOf(elsewhere) === 'STS-SAML-0085',
            'an AuthnRequest whose Destination is another endpoint is ' +
            'REFUSED, STS-SAML-0085', elsewhere.statusCode + ' ' +
            codeOf(elsewhere));
    const stale = getSso(authnRequest(Object.assign({
      issueInstant: new Date(Date.now() - 3600000).toISOString() }, base)));
    t.equal(codeOf(stale), 'STS-SAML-0086',
            'one issued an hour ago is REFUSED, STS-SAML-0086');
    const future = getSso(authnRequest(Object.assign({
      issueInstant: new Date(Date.now() + 600000).toISOString() }, base)));
    t.equal(codeOf(future), 'STS-SAML-0086',
            'one issued ten minutes in the future is refused too');
    const noInstant = getSso(authnRequest(Object.assign({
      issueInstant: null }, base)));
    t.equal(codeOf(noInstant), 'STS-SAML-0086',
            'and one with no IssueInstant');
    const oldVersion = getSso(authnRequest(Object.assign({ version: '1.1' },
                                                         base)));
    t.equal(codeOf(oldVersion), 'STS-SAML-0087',
            'a Version other than 2.0 is REFUSED, STS-SAML-0087');
    const once = authnRequest(Object.assign({ id: id() }, base));
    const first = getSso(once);
    const again = getSso(once);
    t.check(first.statusCode === 303 && /authn/.test(first.location),
            'a fresh unsigned request (development) goes on to the sign-in ' +
            'screen', first.statusCode + ' ' + codeOf(first));
    t.check(again.statusCode === 400 && codeOf(again) === 'STS-SAML-0088',
            'the SAME request again is a REPLAY, refused STS-SAML-0088',
            again.statusCode + ' ' + codeOf(again));
    const unaddressed = getSso(authnRequest(Object.assign({
      destination: null }, base)));
    t.check(unaddressed.statusCode === 303,
            'an UNSIGNED request with no Destination is still answered ' +
            '(only a signed one must name it)', unaddressed.statusCode + ' ' +
            codeOf(unaddressed));
    const lrElsewhere = kit.fakeRes();
    sloPost(kit.fakeReq('POST', '/saml2/slo', {}, '', form({
      SAMLRequest: Buffer.from(logoutRequest({
        issuer: spA, nameId: 'nobody', destination: 'https://x.test/slo' }))
        .toString('base64') })), lrElsewhere);
    t.check(lrElsewhere.statusCode === 400 &&
            codeOf(lrElsewhere) === 'STS-SAML-0085',
            'a LogoutRequest addressed elsewhere is REFUSED, STS-SAML-0085, ' +
            'and ends nothing', lrElsewhere.statusCode + ' ' +
            codeOf(lrElsewhere));

    // -----------------------------------------------------------------------
    t.log.info('B. a back-channel LogoutRequest ends the session it names');
    // -----------------------------------------------------------------------
    const spB = newParty('backchannel', 'saml2-service-provider', {
      samlSingleLogoutService: 'https://backchannel.test/slo' });
    const whoB = 'bc-' + stamp;
    // The STORE's copy, which is what a request finds.
    const heldB = authn.sessionById(sessionFor(whoB).session.id);
    heldB.saml2ServiceProviders = { [spB]: {
      acs: 'https://backchannel.test/acs', idpEntityId: 'urn:x',
      at: Date.now(), nameId: whoB, nameIdFormat: UNSPECIFIED } };
    authn.noteSessionChanged(heldB);
    const other = authn.sessionById(sessionFor('bc2-' + stamp).session.id);
    other.saml2ServiceProviders = { [spB]: {
      acs: 'https://backchannel.test/acs', idpEntityId: 'urn:x',
      at: Date.now(), nameId: 'bc2-' + stamp, nameIdFormat: UNSPECIFIED } };
    authn.noteSessionChanged(other);
    const wrong = kit.fakeRes();
    sloPost(kit.fakeReq('POST', '/saml2/slo', {}, '', form({
      SAMLRequest: Buffer.from(logoutRequest({
        issuer: spB, nameId: whoB, sessionIndex: other.id }))
        .toString('base64') })), wrong);
    t.check(codeOf(wrong) === 'STS-SAML-0090' &&
            /UnknownPrincipal/.test(Buffer.from(
              hiddenField(wrong.body, 'SAMLResponse'), 'base64')
              .toString('utf8')) &&
            !!authn.sessionById(other.id),
            'a SessionIndex naming ANOTHER person\'s session ends nothing ' +
            'and is answered UnknownPrincipal, STS-SAML-0090', codeOf(wrong));
    const right = kit.fakeRes();
    sloPost(kit.fakeReq('POST', '/saml2/slo', {}, '', form({
      SAMLRequest: Buffer.from(logoutRequest({
        issuer: spB, nameId: whoB, sessionIndex: heldB.id }))
        .toString('base64') })), right);
    t.check(!authn.sessionById(heldB.id) &&
            /status:Success/.test(Buffer.from(
              hiddenField(right.body, 'SAMLResponse'), 'base64')
              .toString('utf8')),
            'with NO cookie, the LogoutRequest ENDS the session its ' +
            'SessionIndex names and answers Success (#192)',
            right.statusCode + ' ' + codeOf(right));

    // -----------------------------------------------------------------------
    t.log.info('C. identity-provider-initiated logout signs the query string');
    // -----------------------------------------------------------------------
    const spC = newParty('idplogout', 'saml2-service-provider', {
      samlSingleLogoutService: 'https://idplogout.test/slo' });
    const targets = direct.logoutTargetsFor({
      id: 'sid-' + stamp, user: { username: 'c-' + stamp },
      saml2ServiceProviders: { [spC]: {
        idpEntityId: 'urn:x', nameId: '_transient-c',
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' }
      } });
    const url = new URL(targets[0].url);
    const sent = inflate(url.searchParams.get('SAMLRequest') || '');
    t.check(!!url.searchParams.get('SigAlg') &&
            !!url.searchParams.get('Signature') &&
            !/<ds:Signature/.test(sent),
            'its LogoutRequest is signed on the QUERY STRING and carries no ' +
            'enveloped signature (saml-bindings-2.0-os 3.4.4.1)',
            url.search.slice(0, 200));
    t.check(/>_transient-c<\/saml:NameID>/.test(sent) &&
            /nameid-format:transient/.test(sent),
            'and names the NameID the session GAVE that service provider',
            sent.slice(0, 600));

    // -----------------------------------------------------------------------
    t.log.info('D. identity-provider-initiated SSO');
    // -----------------------------------------------------------------------
    const acsD = 'https://unsolicited.test/acs';
    const spD = newParty('unsolicited', 'saml2-service-provider', {
      samlAssertionConsumerService: acsD });
    const ask = function (query, extra) {
      log.debug("Entering ask().");
      const res = kit.fakeRes();
      const raw = new URLSearchParams(query).toString();
      unsolicited(kit.fakeReq('GET', '/saml2/unsolicited', query, raw,
                              undefined, extra), res);
      log.debug("Leaving ask().");
      return res;
    };
    const off = kit.withSettings(config, { 'saml2.unsolicitedSso': false },
      function () {
        return ask({ providerId: spD });
      });
    t.equal(codeOf(off), 'STS-SAML-0091',
            'turned off for the realm: refused, STS-SAML-0091');
    t.equal(codeOf(ask({})), 'STS-SAML-0092',
            'no service provider named: refused, STS-SAML-0092');
    t.equal(codeOf(ask({ providerId: spD, binding: 'redirect' })),
            'STS-SAML-0093',
            'a Response on HTTP-Redirect: refused, STS-SAML-0093');
    const stranger = kit.withSettings(config, product, function () {
      return ask({ providerId: 'https://never-registered-' + stamp +
                               '.test/sp' });
    });
    t.check(stranger.statusCode === 404 &&
            codeOf(stranger) === 'STS-SAML-0082',
            'PRODUCT: an unregistered service provider is a 404, ' +
            'STS-SAML-0082', stranger.statusCode + ' ' + codeOf(stranger));
    const anonymous = ask({ providerId: spD });
    t.check(anonymous.statusCode === 303 && /authn/.test(anonymous.location),
            'with no session it goes to the sign-in screen',
            anonymous.statusCode + ' ' + anonymous.location);
    const whoD = 'd-' + stamp;
    const cookieD = sessionFor(whoD).cookie;
    const sentD = ask({ providerId: spD, shire: acsD, target: 'rs-' + stamp },
                      withCookie(cookieD));
    const responseD = Buffer.from(hiddenField(sentD.body, 'SAMLResponse'),
                                  'base64').toString('utf8');
    t.check(/<samlp:Response\b/.test(responseD) &&
            !/InResponseTo=/.test(responseD) &&
            responseD.indexOf('Destination="' + acsD + '"') >= 0 &&
            hiddenField(sentD.body, 'RelayState') === 'rs-' + stamp,
            'with one: an UNSOLICITED Response — no InResponseTo — goes to ' +
            'the registered ACS with the target as RelayState',
            sentD.statusCode + ' ' + codeOf(sentD) + ' ' +
            responseD.slice(0, 300));
    t.check(/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.1"[^>]*FriendlyName="uid"/
              .test(responseD) &&
            new RegExp('>' + whoD + '</saml:AttributeValue>').test(responseD),
            'carrying the X.500/LDAP attribute profile\'s names (#189)',
            responseD.slice(0, 200));
    const elsewhereD = ask({ providerId: spD, shire: 'https://evil.test/acs' },
                           withCookie(cookieD));
    t.check(kit.withSettings(config, product, function () {
      return ask({ providerId: spD, shire: 'https://evil.test/acs' },
                 withCookie(cookieD));
    }).statusCode === 400 && elsewhereD.statusCode === 200,
            'an unregistered shire is refused in PRODUCT (development ' +
            'delivers anywhere, as its SSO does)');

    // -----------------------------------------------------------------------
    t.log.info('E. the SAML 2.0 attribute authority');
    // -----------------------------------------------------------------------
    const spE = newParty('aa', 'saml2-service-provider', {});
    const whoE = 'e-' + stamp;
    const heldE = authn.sessionById(sessionFor(whoE).session.id);
    heldE.saml2ServiceProviders = { [spE]: {
      acs: 'https://aa.test/acs', idpEntityId: 'urn:x', at: Date.now(),
      nameId: whoE, nameIdFormat: UNSPECIFIED } };
    authn.noteSessionChanged(heldE);
    const query = function (nameId, attrs, issuer) {
      log.debug("Entering query().");
      log.debug("Leaving query().");
      return soap('<samlp:AttributeQuery xmlns:samlp="' + NS_SAMLP + '" ' +
        'xmlns:saml="' + NS_SAML + '" ID="' + id() + '" Version="2.0" ' +
        'IssueInstant="' + new Date().toISOString() + '">' +
        '<saml:Issuer>' + (issuer || spE) + '</saml:Issuer><saml:Subject>' +
        '<saml:NameID NameQualifier="urn:qual:idp" SPNameQualifier="' +
        spE + '" Format="' + UNSPECIFIED + '">' + nameId + '</saml:NameID>' +
        '</saml:Subject>' + (attrs || '') + '</samlp:AttributeQuery>');
    };
    const askAa = async function (body) {
      log.debug("Entering askAa().");
      const res = kit.fakeRes();
      aa(kit.fakeReq('POST', '/saml2/aa', {}, '', body), res);
      await res.done;
      log.debug("Leaving askAa().");
      return res;
    };
    const noQuery = await askAa(soap('<nothing/>'));
    t.equal(codeOf(noQuery), 'STS-SAML-0095',
            'a body that is not an AttributeQuery: Requester, STS-SAML-0095');
    const unknown = await askAa(query('nobody-' + stamp));
    t.check(codeOf(unknown) === 'STS-SAML-0094' &&
            /UnknownPrincipal/.test(unknown.body),
            'a subject no live session gave this SP: UnknownPrincipal, ' +
            'STS-SAML-0094', codeOf(unknown));
    const known = await askAa(query(whoE));
    t.check(/status:Success/.test(known.body) &&
            new RegExp('>' + whoE + '</saml:AttributeValue>')
              .test(known.body) &&
            /NameQualifier="urn:qual:idp"/.test(known.body) &&
            known.body.indexOf('SPNameQualifier="' + spE + '"') >= 0 &&
            !/AuthnStatement/.test(known.body) &&
            !/SubjectConfirmation/.test(known.body),
            'the subject a live session gave it: Success, the NameID\'s ' +
            'qualifiers echoed (a STRONG match), no AuthnStatement and no ' +
            'SubjectConfirmation', known.body.slice(0, 400));
    const narrowed = await askAa(query(whoE,
      '<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" ' +
      'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>'));
    t.check(/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.3"/
              .test(narrowed.body) &&
            !/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.1"/
              .test(narrowed.body),
            'an attribute named in the query narrows the answer to it',
            narrowed.body.slice(0, 300));
    const unsignedProd = await kit.withSettings(config, product,
                                                function () {
      return askAa(query(whoE));
    });
    t.check(!/status:Success/.test(unsignedProd.body) &&
            codeOf(unsignedProd) === 'STS-SAML-0077',
            'PRODUCT: an unauthenticated caller is refused, STS-SAML-0077',
            codeOf(unsignedProd));

    // -----------------------------------------------------------------------
    t.log.info('F. the metadata');
    // -----------------------------------------------------------------------
    const md = kit.fakeRes();
    const mdReq = kit.fakeReq('GET', '/saml2/metadata/x', {}, '');
    mdReq.params = { sp: spE };
    metadata(mdReq, md);
    t.check(/<md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2\.0:protocol">/
              .test(md.body) &&
            /<md:AttributeService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:SOAP" Location="[^"]*\/saml2\/aa\//
              .test(md.body),
            'the SAML 2.0 metadata publishes the attribute authority',
            md.body.slice(0, 200));
    t.check(!new RegExp('SingleSignOnService Binding="' + B_ARTIFACT + '"')
              .test(md.body),
            'and NO HTTP-Artifact SingleSignOnService, which no request can ' +
            'arrive on (#191)');
    const md11 = kit.fakeRes();
    const md11Req = kit.fakeReq('GET', '/saml11/metadata/x', {}, '');
    md11Req.params = { rp: spE };
    metadata11(md11Req, md11);
    t.check(/<md:IDPSSODescriptor[^>]*protocolSupportEnumeration="urn:oasis:names:tc:SAML:1\.1:protocol urn:mace:shibboleth:1\.0"/
              .test(md11.body),
            'the SAML 1.1 IDPSSODescriptor names urn:mace:shibboleth:1.0 ' +
            'beside SAML 1.1, as a Shib1 initiator requires (#189)',
            md11.body.slice(0, 300));

    // -----------------------------------------------------------------------
    t.log.info('G. SAML 1.1');
    // -----------------------------------------------------------------------
    const rpPost = 'https://rp11.test/SAML/POST';
    const rpArt = 'https://rp11.test/SAML/Artifact';
    const rp = newParty('rp11', 'saml11-relying-party', {
      samlAssertionConsumerService: [rpPost, rpArt] });
    // What consuming its metadata writes: each ACS with its profile.
    const endpoints = applications.replaceSamlMetadataFields(rp, {
      samlAcsEndpoint: ['5 - ' + P11_POST + ' ' + rpPost,
                        '6 - ' + P11_ARTIFACT + ' ' + rpArt] });
    t.check(endpoints.ok, 'the relying party\'s endpoints are registered ' +
            'with their profiles', JSON.stringify(endpoints.errors || ''));
    const whoG = 'g-' + stamp;
    const cookieG = sessionFor(whoG).cookie;
    const shib = function (shire, extraSettings) {
      log.debug("Entering shib().");
      const q = { providerId: rp, shire: shire, target: 'ss:mem:' + stamp,
                  time: String(Math.floor(Date.now() / 1000)) };
      const res = kit.fakeRes();
      const go = function () {
        log.debug("Entering go().");
        sso11(kit.fakeReq('GET', '/saml11/sso', q,
                          new URLSearchParams(q).toString(), undefined,
                          withCookie(cookieG)), res);
        log.debug("Leaving go().");
        return res;
      };
      log.debug("Leaving shib().");
      return extraSettings ? kit.withSettings(config, extraSettings, go)
                           : go();
    };
    const posted = shib(rpPost);
    const assertion11 = Buffer.from(hiddenField(posted.body, 'SAMLResponse'),
                                    'base64').toString('utf8');
    t.check(hiddenField(posted.body, 'TARGET') === 'ss:mem:' + stamp,
            'Shibboleth\'s lower-case `target` comes back as TARGET',
            posted.body.slice(0, 300));
    t.check(/DoNotCacheCondition/.test(assertion11),
            'by default a Browser/POST assertion is marked DoNotCache');
    t.check(assertion11.indexOf('AttributeName="urn:mace:dir:attribute-def:' +
                                'uid" AttributeNamespace="urn:mace:' +
                                'shibboleth:1.0:attributeNamespace:uri"') >= 0,
            'and names uid the way Shibboleth\'s attribute map reads it',
            assertion11.slice(0, 200));
    const plain = shib(rpPost, { 'saml11.doNotCacheCondition': false });
    t.check(!/DoNotCacheCondition/.test(Buffer.from(
              hiddenField(plain.body, 'SAMLResponse'), 'base64')
              .toString('utf8')),
            'saml11.doNotCacheCondition off: no DoNotCacheCondition');
    const artifact = shib(rpArt);
    t.check(artifact.statusCode === 303 &&
            /SAMLart=/.test(artifact.location) &&
            artifact.location.indexOf(rpArt) === 0,
            'a shire registered on artifact-01 is answered on the ARTIFACT ' +
            'profile with no `profile` parameter (#189)',
            artifact.statusCode + ' ' + artifact.location.slice(0, 120));

    const rpCert = kit.keyFor(kit.FAMILIES.filter(function (row) {
      return row[0] === 'ecdsa-p256-sha256';
    })[0]);
    applications.updateApplication(rp, {
      attribute: 'samlSigningCertificate', mode: 'add',
      value: rpCert.cert.b64 });
    const heldG = authn.sessionById(cookieG.split('=')[1].split('.')[0]);
    const query11 = function (nameId, resource) {
      log.debug("Entering query11().");
      log.debug("Leaving query11().");
      return soap('<samlp:Request xmlns:samlp="' + NS_SAMLP11 + '" ' +
        'MajorVersion="1" MinorVersion="1" RequestID="' + id() + '" ' +
        'IssueInstant="' + new Date().toISOString() + '"><samlp:' +
        'AttributeQuery Resource="' + resource + '"><saml:Subject ' +
        'xmlns:saml="' + NS_SAML11 + '"><saml:NameIdentifier>' + nameId +
        '</saml:NameIdentifier></saml:Subject></samlp:AttributeQuery>' +
        '</samlp:Request>');
    };
    const tls = { authorized: false,
                  getPeerCertificate: function () {
                    log.debug("Entering getPeerCertificate().");
                    log.debug("Leaving getPeerCertificate().");
                    return { raw: rpCert.cert.der };
                  } };
    const ask11 = async function (body, socket) {
      log.debug("Entering ask11().");
      const res = kit.fakeRes();
      responder(kit.fakeReq('POST', '/saml11/responder', {}, '', body,
                            socket ? { socket: socket } : {}), res);
      await res.done;
      log.debug("Leaving ask11().");
      return res;
    };
    const inProduct = function (fn) {
      log.debug("Entering inProduct().");
      log.debug("Leaving inProduct().");
      return kit.withSettings(config, product, fn);
    };
    const noParty = await inProduct(function () {
      return ask11(query11(whoG, 'https://nobody.test/sp'), tls);
    });
    t.equal(codeOf(noParty), 'STS-SAML-0039',
            'PRODUCT: a query for an unregistered relying party is refused, ' +
            'STS-SAML-0039');
    const anonymous11 = await inProduct(function () {
      return ask11(query11(whoG, rp));
    });
    t.check(/samlp:Requester/.test(anonymous11.body) &&
            ['STS-SAML-0039', 'STS-SAML-0077']
              .indexOf(codeOf(anonymous11)) >= 0,
            'PRODUCT: an unauthenticated caller is refused',
            codeOf(anonymous11));
    const stranger11 = await inProduct(function () {
      return ask11(query11('nobody-' + stamp, rp), tls);
    });
    t.equal(codeOf(stranger11), 'STS-SAML-0096',
            'PRODUCT: a subject no live session gave it is refused, ' +
            'STS-SAML-0096');
    const released11 = await inProduct(function () {
      return ask11(query11(whoG, rp), tls);
    });
    t.check(!!heldG && /samlp:Success/.test(released11.body) &&
            new RegExp('>' + whoG + '<').test(released11.body),
            'PRODUCT: the authenticated relying party, about the subject it ' +
            'holds a live session for, is ANSWERED (#189 — every query was ' +
            'refused in product until then)', released11.body.slice(0, 400));

    // H. ONE FACT UNDER TWO NAMES IS ONE VALUE (#189). Since the identity
    // provider sends `mail` as the claim URI and as the X.500/LDAP name, a
    // federation relationship in front of it mapped both to `mail` and wrote
    // the address twice (sts_federation_realms found it). The values of an
    // LDAP attribute are a set; two DIFFERENT values still both arrive.
    const federationMap = require('../federation/federation_map');
    const address = 'fed-' + stamp + '@partner.test';
    const both = federationMap.mapIncoming(null, {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
        [address],
      'urn:oid:0.9.2342.19200300.100.1.3': [address]
    }, 'fed-' + stamp);
    t.equal(JSON.stringify(both.attributes.mail), JSON.stringify([address]),
            'federation: mail sent under the claim URI AND urn:oid is ONE ' +
            'value on the entry, not two (RFC 4512 section 2.3)');
    t.equal(both.mapped.length, 2,
            'federation: both incoming names are still reported as mapped');
    const two = federationMap.mapIncoming(null, {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
        [address],
      'urn:oid:0.9.2342.19200300.100.1.3': ['other-' + address]
    }, 'fed-' + stamp);
    t.equal(JSON.stringify(two.attributes.mail),
            JSON.stringify([address, 'other-' + address]),
            'federation: two DIFFERENT values under the two names are both ' +
            'kept, as they always were');
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
  name: 'saml_interop_findings',
  describe: 'what the Shibboleth, pysaml2, SimpleSAMLphp and Keycloak ' +
            'interoperability harnesses found in saml/, held in process ' +
            '(#189–#192)',
  run: run
};
