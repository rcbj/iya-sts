'use strict';
//
// File: saml_family_hardcoded.js
//
// ===========================================================================
// THE SAML / WS-TRUST / WS-FEDERATION / FEDERATION HALF OF THE 2026-09-12 SWEEP
// FOR HARD-CODED VALUES.
//
// `mode_hardcoded_foundation.js` holds the pieces every family was handed; this
// file holds what those four families did with them. Every section is either a
// PRODUCT-MODE REFUSAL (and the matching development-mode behaviour that must
// not have moved) or a defect fixed in both modes:
//
//   A. how a session authenticated, in both SAML vocabularies — the defect that
//      called a certificate, a Kerberos ticket, a federated sign-in and the
//      unauthenticated session a PASSWORD, in every mode;
//   B. where a response may be delivered — any address in development, only a
//      registered one in product, and never a built-in mock;
//   C. the configured signature algorithm reaching a signature that verifies;
//   D. the two builders' defaults and the SAML 1.1 AttributeQuery shape;
//   E. WS-Trust: no credential, an unverified assertion, a delegation with no
//      requester, the unbounded lifetime, the JWT's jti and algorithm, the
//      plaintext fallback, and the session a delegation used to start;
//   F. federation: the audience refusal, the partner's amr, the algorithm
//      allowlist, and fedPeer required;
//   G. the SAML 1.1 responder's queries;
//   H. the SAML 2.0 SSO service and WS-Federation refusing an unregistered
//      address, and an empty issuer, in product mode;
//   I. SP metadata honouring federation.outbound; WS-Federation metadata
//      describing what its mode emits.
//
// WHY IN PROCESS. Every claim here is decided by a function this repository
// owns, and several of them cannot be reached over HTTP on demand: a session
// with amr ["swk"] and a SAML 2.0 AuthnRequest in the same browser, a realm in
// product mode with no directory, a partner assertion with two audience
// restrictions. The route handlers are called straight off the express router
// with a fake request and response, so no port is bound.
// ===========================================================================

delete process.env.CONFIG_FILE;

const zlib = require('zlib');
const { DOMParser } = require('@xmldom/xmldom');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'saml_family_hardcoded',
  level: process.env.LOG_LEVEL || 'info' });

// --- plumbing ----------------------------------------------------------------

function fakeReq(method, path, query, body, cookie) {
  log.debug("Entering fakeReq().");
  const headers = { host: 'idp.test' };
  if (cookie) {
    headers.cookie = cookie;
  }
  log.debug("Leaving fakeReq().");
  return {
    method: method, path: path, url: path, originalUrl: path,
    query: query || {}, params: {}, body: body === undefined ? '' : body,
    protocol: 'https', headers: headers, ip: '127.0.0.1',
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return headers[String(name).toLowerCase()];
    }
  };
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: '', location: '' };
  res.status = function (code) {
    log.debug("Entering status().");
    res.statusCode = code;
    log.debug("Leaving status().");
    return res;
  };
  res.type = function (t) {
    log.debug("Entering type().");
    res.headers['content-type'] = t;
    log.debug("Leaving type().");
    return res;
  };
  res.set = function (k, v) {
    log.debug("Entering set().");
    res.headers[String(k).toLowerCase()] = v;
    log.debug("Leaving set().");
    return res;
  };
  res.setHeader = res.set;
  res.getHeader = function (k) {
    log.debug("Entering getHeader().");
    log.debug("Leaving getHeader().");
    return res.headers[String(k).toLowerCase()];
  };
  res.send = function (b) {
    log.debug("Entering send().");
    res.body = String(b);
    log.debug("Leaving send().");
    return res;
  };
  res.redirect = function (code, url) {
    log.debug("Entering redirect().");
    res.statusCode = code;
    res.location = url;
    log.debug("Leaving redirect().");
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

// The handler a route registered, found on the shared router. Calling it
// directly skips the realm middleware, which is the default realm — exactly
// what these tests want.
function handlerFor(app, method, path) {
  log.debug("Entering handlerFor().");
  const stack = (app._router && app._router.stack) || [];
  for (let i = 0; i < stack.length; i++) {
    const route = stack[i].route;
    if (route && route.path === path && route.methods[method]) {
      log.debug("Leaving handlerFor().");
      return route.stack[route.stack.length - 1].handle;
    }
  }
  log.debug("Leaving handlerFor().");
  throw new Error('no ' + method.toUpperCase() + ' ' + path + ' is registered');
}

function withMode(config, which, fn) {
  log.debug("Entering withMode().");
  config.setOverride('global.mode', which);
  try {
    log.debug("Leaving withMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function soapRequest(inner) {
  log.debug("Entering soapRequest().");
  log.debug("Leaving soapRequest().");
  return '<soap:Envelope ' +
    'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>' +
    '<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" ' +
    'MinorVersion="1" RequestID="_q1" ' +
    'IssueInstant="' + new Date().toISOString() + '">' + inner +
    '</samlp:Request></soap:Body></soap:Envelope>';
}

function rst(inner, security) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<s:Header>' +
    (security ? '<wsse:Security>' + security + '</wsse:Security>' : '') +
    '</s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    inner + '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const app = require('../common/app');
  const authnContext = require('../saml/authn_context');
  const returnAddress = require('../saml/return_address');
  const documentSettings = require('../saml/document_settings');
  const personAttributes = require('../saml/person_attributes');
  const saml2 = require('../saml/saml2');
  const saml11 = require('../saml/saml11');
  const wstrust = require('../ws-trust/wstrust');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  const wsfed = require('../ws-federation/wsfed');
  // The three families whose handlers this file looks up. Loading a module
  // registers nothing since #50's R1 (`common/protocol_stack.ts` does), so
  // they are registered here, in the composition root's order.
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
  wsfed.registerRoutes(app);
  const federation = require('../federation/federation');
  const fedSp = require('../federation/federation_sp');
  const spMetadata = require('../saml/sp_metadata');
  const authn = require('../authn/authn');

  // -------------------------------------------------------------------------
  t.log.info('A. how a session authenticated, once, for both vocabularies');
  // -------------------------------------------------------------------------
  const read = authnContext.forSession;
  const PPT =
      'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
  t.equal(read({ amr: ['pwd'], acr: '1' }).saml2, PPT,
          'an ordinary password sign-in is PasswordProtectedTransport, ' +
          'exactly as before');
  t.equal(read({ amr: ['pwd'], acr: '1' }).saml11,
          'urn:oasis:names:tc:SAML:1.0:am:password',
          'and am:password in SAML 1.1, exactly as before');
  t.equal(read({ amr: ['pwd', 'hwk'], acr: 'mfa' }).saml2,
          'http://schemas.microsoft.com/claims/multipleauthn',
          'a password and a key is multipleauthn, as before');
  t.equal(read({ amr: ['hwk'], acr: '1' }).saml11,
          'urn:oasis:names:tc:SAML:1.0:am:HardwareToken',
          'a key alone is HardwareToken in 1.1, as before');
  t.equal(read({ amr: ['pwd', 'otp'], acr: 'mfa' }).multiFactor, true,
          'a password and a one-time code is two factors');
  t.equal(read({ amr: ['swk'], acr: '1' }).saml2,
          'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient',
          'A TLS CLIENT CERTIFICATE IS TLSClient AND NOT A PASSWORD — the ' +
          'defect, in both modes');
  t.equal(read({ amr: ['swk'], acr: '1' }).saml11, 'urn:ietf:rfc:2246',
          'and urn:ietf:rfc:2246 in SAML 1.1');
  t.equal(read({ amr: ['pwd'], acr: '1', via: 'Kerberos v5 (SPNEGO)' }).saml2,
          'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos',
          'A KERBEROS TICKET IS Kerberos even when its KDC ' +
          'pre-authentication put pwd in the amr');
  t.equal(read({ amr: [], acr: '0', authenticated: false }).saml2,
          'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
          'THE UNAUTHENTICATED SESSION IS unspecified — it used to be signed ' +
          'as a password');
  t.equal(read({ amr: [], acr: '' }).saml11,
          'urn:oasis:names:tc:SAML:1.0:am:unspecified',
          'an amr naming nothing is unspecified');
  t.equal(read({ amr: ['federated'], acr: PPT }).saml2, PPT,
          'a federated session carries the SAML 2.0 class the PARTNER ' +
          'asserted');
  t.equal(read({ amr: ['federated'], acr: PPT }).saml11,
          'urn:oasis:names:tc:SAML:1.0:am:password',
          'translated into SAML 1.1 where the two mean the same');
  t.equal(read({ amr: ['federated'],
                 acr: 'urn:oasis:names:tc:SAML:1.0:am:password' }).saml2, PPT,
          'and a SAML 1.1 partner\'s method is translated into SAML 2.0');
  t.equal(read({ amr: ['federated', 'pwd', 'hwk'], acr: '' }).multiFactor, true,
          'an OpenID partner\'s amr behind `federated` is read as its ' +
          'statement');
  t.equal(read({ amr: ['federated'], acr: '' }).saml2,
          'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
          'a partner that said nothing is unspecified — no factor is invented');

  // -------------------------------------------------------------------------
  t.log.info('B. where a response may be delivered');
  // -------------------------------------------------------------------------
  const spec = function (requested, registered) {
    log.debug("Entering spec().");
    log.debug("Leaving spec().");
    return { requested: requested, registered: registered,
             fallback: 'https://idp.test/saml2/sp',
             attribute: 'samlAssertionConsumerService',
             parameter: 'AssertionConsumerServiceURL',
             application: 'sp-1' };
  };
  withMode(config, 'development', function () {
    t.equal(returnAddress.resolve(spec('https://anywhere.test/acs', [])).url,
            'https://anywhere.test/acs', 'development: an unregistered ' +
                                         'address is used');
    t.equal(returnAddress.resolve(spec('', ['https://a/1', 'https://a/2'])).url,
            'https://a/2',
            'development: with none named, the LAST registered value, as ' +
            'both SAML modules took');
    t.equal(returnAddress.resolve(spec('', [])).url,
            'https://idp.test/saml2/sp',
            'development: with nothing at all, the built-in mock');
  });
  withMode(config, 'product', function () {
    const refused = returnAddress.resolve(spec('https://evil.test/acs',
                                               ['https://sp.test/acs']));
    t.equal(refused.ok, false, 'PRODUCT: an address not registered is refused');
    t.check(/samlAssertionConsumerService/.test(refused.why) &&
            /PRODUCT/.test(refused.why),
            'and the refusal names the attribute to register it on',
            refused.why);
    t.equal(returnAddress.resolve(spec('https://sp.test/acs/../x',
                                       ['https://sp.test/acs'])).ok,
            false, 'the comparison is exact, not a prefix');
    t.equal(returnAddress.resolve(spec('https://sp.test/acs',
                                       ['https://sp.test/acs'])).ok, true,
            'a registered address is delivered to');
    t.equal(returnAddress.resolve(spec('', ['https://sp.test/acs'])).url,
            'https://sp.test/acs',
            'with none named, the registered one');
    t.equal(returnAddress.resolve(spec('', [])).ok, false,
            'PRODUCT: with nothing registered there is NO fallback to the ' +
            'built-in mock');
  });

  // -------------------------------------------------------------------------
  t.log.info('C. the configured signature algorithm reaches a verifying ' +
             'signature');
  // -------------------------------------------------------------------------
  try {
    config.setOverride('saml.signatureAlgorithm', 'rsa-sha384');
    const signed = saml2.buildSamlAssertion('alice', 'https://sp.test', 5);
    // The XML signer, `STS.xml`, since the RSA key split (#42, D2).
    const verdict = stsCrypto.verifyXmlSignature(signed,
      { element: 'Assertion', certPem: helpers.STS.xml.certPem });
    t.equal(verdict.ok, true, 'an assertion signed with rsa-sha384 verifies',
            verdict.why);
    t.check(/rsa-sha384/.test(verdict.signatureMethod),
            'and its SignatureMethod is the configured one',
            verdict.signatureMethod);
    const s11 = saml11.buildSaml11Assertion({ subject: 'alice',
                                              audience: 'rp' });
    const v11 = stsCrypto.verifyXmlSignature(s11, { element: 'Assertion',
                                                    certPem:
                                                      helpers.STS.xml.certPem
                                                  });
    t.check(v11.ok && /rsa-sha384/.test(v11.signatureMethod),
            'the SAML 1.1 builder reads the same setting',
            v11.signatureMethod + ' ' + v11.why);
  } finally {
    config.clearOverride('saml.signatureAlgorithm');
  }
  t.equal(documentSettings.signatureOptions().sigAlg, stsCrypto.SIG_RSA_SHA256,
          'the default is RSA-SHA256, which is what every signer used before ' +
          'the setting');
  try {
    config.setOverride('saml.organizationName', '');
    t.equal(documentSettings.organizationElement('https://idp.test'), '',
            'an emptied organisation name omits <md:Organization> entirely');
  } finally {
    config.clearOverride('saml.organizationName');
  }
  t.check(/<md:OrganizationName xml:lang="en">sts</.test(
            documentSettings.organizationElement('https://idp.test')),
          'and the default is the product name, sts (mock-sts until ' +
          '2026-09-12)');

  // -------------------------------------------------------------------------
  t.log.info('D. the builders say nothing they were not told');
  // -------------------------------------------------------------------------
  t.check(/AuthnContextClassRef>urn:oasis:names:tc:SAML:2\.0:ac:classes:unspecified</.test(
            saml2.buildSamlAssertion('alice', 'x', 5, { sign: false })),
          'a SAML 2.0 caller that names no class gets unspecified, not ' +
          'PasswordProtectedTransport');
  const noStatement = saml11.buildSaml11Assertion({
    subject: 'alice', audience: 'rp', authenticationStatement: false,
    sign: false,
    attributes: [{ namespace: 'urn:x', name: 'uid', value: 'alice' }] });
  t.check(!/AuthenticationStatement/.test(noStatement) &&
          /AttributeStatement/.test(noStatement),
          'authenticationStatement: false leaves the AuthenticationStatement ' +
          'out', noStatement);
  withMode(config, 'product', function () {
    const person = personAttributes.personFor(helpers.userFor('nobody-here'));
    t.check(!('email' in person) || !person.email,
            'product: a person with no directory entry gets no invented mail ' +
            'address');
    const rows = personAttributes.withoutAbsent([
      { name: 'mail', value: undefined },
                                                 { name: 'uid', value: 'x' }]);
    t.equal(rows.length, 1, 'and an attribute with no value is omitted ' +
                            'rather than signed');
  });

  // -------------------------------------------------------------------------
  t.log.info('E. WS-Trust');
  // -------------------------------------------------------------------------
  const devAnon = withMode(config, 'development', function () {
    return wstrust.handleRst(rst(''), 'application/soap+xml');
  });
  t.equal(devAnon.status, 200, 'development: a request with no credential ' +
                               'still issues');
  t.check(/ac:classes:unspecified/.test(devAnon.body),
          'and the assertion no longer claims a password sign-in for it',
          devAnon.body.slice(0, 200));
  const prodAnon = withMode(config, 'product', function () {
    return wstrust.handleRst(rst(''), 'application/soap+xml');
  });
  t.check(prodAnon.status >= 400 &&
          /No credential was presented/.test(prodAnon.body),
          'PRODUCT: a request with no credential is a Fault naming what to ' +
          'present',
          prodAnon.body.slice(0, 300));

  const issued = saml2.buildSamlAssertion('carol', 'https://rp.test', 5);
  const prodAssertion = withMode(config, 'product', function () {
    return wstrust.handleRst(rst('', issued), 'application/soap+xml');
  });
  t.equal(prodAssertion.status, 200,
          'PRODUCT: an assertion THIS STS signed is accepted as a credential',
          prodAssertion.body.slice(0, 300));
  t.check(/PreviousSession/.test(prodAssertion.body),
          'and the token it issues says PreviousSession, not a password');
  const forged = saml2.buildSamlAssertion('carol', 'https://rp.test', 5,
                                          { sign: false });
  const prodForged = withMode(config, 'product', function () {
    return wstrust.handleRst(rst('', forged), 'application/soap+xml');
  });
  t.check(prodForged.status >= 400 && /does not verify/.test(prodForged.body),
          'PRODUCT: an unsigned assertion is refused rather than believed',
          prodForged.body.slice(0, 300));
  const devForged = withMode(config, 'development', function () {
    return wstrust.handleRst(rst('', forged), 'application/soap+xml');
  });
  t.equal(devForged.status, 200, 'development: the same assertion is still ' +
                                 'believed');

  const obo = '<wst:OnBehalfOf>' + issued + '</wst:OnBehalfOf>';
  const prodObo = withMode(config, 'product', function () {
    return wstrust.handleRst(rst(obo), 'application/soap+xml');
  });
  t.check(prodObo.status >= 400 &&
          /presents no credential of its own/.test(prodObo.body),
          'PRODUCT: a delegation with no requester credential is refused',
          prodObo.body.slice(0, 300));
  const devObo = withMode(config, 'development', function () {
    return wstrust.handleRst(rst(obo), 'application/soap+xml');
  });
  t.equal(devObo.status, 200, 'development: an anonymous delegation still ' +
                              'issues');
  t.equal(devObo.signIn, null,
          'BUT NO SESSION IS STARTED FOR THE DELEGATED SUBJECT — in either ' +
          'mode');

  const yearLong = '<wst:Lifetime ' +
    'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<wsu:Created>2026-01-01T00:00:00Z</wsu:Created><wsu:Expires>' +
    '2027-01-01T00:00:00Z</wsu:Expires></wst:Lifetime>';
  const long = withMode(config, 'development', function () {
    return wstrust.handleRst(rst(yearLong), 'application/soap+xml');
  });
  const expires = /<wsu:Expires>([^<]+)</.exec(long.body);
  const minutes = expires ? (Date.parse(expires[1]) - Date.now()) / 60000 :
                  Infinity;
  t.check(minutes <= Number(config.value('wstrust.maxTokenLifetimeMin')) + 1,
          'a year-long wst:Lifetime is CLAMPED to ' +
          'wstrust.maxTokenLifetimeMin, in development too',
          'issued for ' + Math.round(minutes) + ' minutes');

  try {
    config.setOverride('wstrust.jwtAlgorithm', 'ES256');
    const jwtRst = withMode(config, 'development', function () {
      return wstrust.handleRst(rst('<wst:TokenType>' +
                                   'urn:ietf:params:oauth:token-type:jwt</wst:TokenType>'),
                               'application/soap+xml');
    });
    const token = (/ValueType="urn:ietf:params:oauth:token-type:jwt">([^<]+)</.exec(jwtRst.body) || [])[1] || '';
    const header = token ? helpers.jsonFromB64u(token.split('.')[0]) : {};
    const payload = token ? helpers.jsonFromB64u(token.split('.')[1]) : {};
    t.equal(header.alg, 'ES256', 'the WS-Trust JWT is signed with ' +
                                 'wstrust.jwtAlgorithm');
    t.check(!!header.kid, 'and names the key it was signed with');
    t.check(typeof payload.jti === 'string' && payload.jti.length > 10,
            'and CARRIES A jti, which it never did', JSON.stringify(payload));
  } finally {
    config.clearOverride('wstrust.jwtAlgorithm');
  }

  const devNoCert = withMode(config, 'development', function () {
    return wstrust.handleRst(rst(''), 'application/soap+xml',
                             { encrypt: true });
  });
  t.equal(devNoCert.status, 200,
          'development: ?encrypt=1 with no recipient certificate still ' +
          'returns the plaintext');
  const prodNoCert = withMode(config, 'product', function () {
    return wstrust.handleRst(rst('',
                                 saml2.buildSamlAssertion('dan', 'x',
                                                          5)).replace(
      /<ds:X509Certificate>[^<]*<\/ds:X509Certificate>/g,
      ''), 'application/soap+xml', { encrypt: true });
  });
  t.check(prodNoCert.status >= 400,
          'PRODUCT: ?encrypt=1 that cannot encrypt is a Fault, not a ' +
          'plaintext assertion',
          prodNoCert.body.slice(0, 300));

  // -------------------------------------------------------------------------
  t.log.info('F. federation');
  // -------------------------------------------------------------------------
  const record = { fedId: 'p1', fedClientId: '' };
  const ours = fedSp.ourEntityId('https://sp.test', record);
  const assertionWith = function (audiences) {
    log.debug("Entering assertionWith().");
    const restriction = audiences === null ? '' :
                        audiences.map(function (group) {
      return '<saml:AudienceRestriction>' + group.map(function (a) {
        return '<saml:Audience>' + a + '</saml:Audience>';
      }).join('') + '</saml:AudienceRestriction>';
    }).join('');
    log.debug("Leaving assertionWith().");
    return new DOMParser().parseFromString(
      '<saml:Assertion ' +
      'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Conditions>' +
      restriction + '</saml:Conditions></saml:Assertion>',
      'text/xml').documentElement;
  };
  t.equal(fedSp.audienceCheck(assertionWith([[ours]]), 'https://sp.test',
                              record, true).ok, true,
          'an assertion addressed to this service is accepted');
  const other = fedSp.audienceCheck(assertionWith(
      [['https://another-sp.test']]),
                                    'https://sp.test', record, true);
  t.equal(other.ok, false,
          'AN ASSERTION ADDRESSED TO ANOTHER SERVICE PROVIDER IS REFUSED — ' +
          'it was a warning');
  t.check(/fedLocalEntityId/.test(other.why), 'and the refusal names the way ' +
                                              'out', other.why);
  t.equal(fedSp.audienceCheck(assertionWith([['https://x.test', ours]]),
                              'https://sp.test',
                              record, true).ok, true,
          'several audiences in one restriction are an OR');
  t.equal(fedSp.audienceCheck(assertionWith([[ours], ['https://x.test']]),
                              'https://sp.test',
                              record, true).ok, false,
          'several restrictions are an AND');
  t.equal(fedSp.audienceCheck(assertionWith(null), 'https://sp.test', record,
                              true).ok, false,
          'SAML 2.0 with no audience restriction is refused (the profile ' +
          'requires one)');
  t.equal(fedSp.audienceCheck(assertionWith(null), 'https://sp.test', record,
                              false).ok, true,
          'SAML 1.1 / WS-Federation with none is accepted with a warning');
  t.equal(fedSp.ourEntityId('https://sp.test',
                            { fedId: 'p1', fedLocalEntityId: 'urn:us' }),
          'urn:us', 'fedLocalEntityId pins what this service is called to a ' +
                    'partner');
  t.equal(fedSp.federatedAmr(['pwd', 'hwk']).join(','), 'federated,pwd,hwk',
          'a partner\'s amr is carried BEHIND federated instead of thrown ' +
          'away');
  t.equal(fedSp.federatedAmr(['federated', 'pwd']).join(','), 'federated,pwd',
          'and applying it twice changes nothing');
  try {
    config.setOverride('federation.jwtAlgorithms', 'RS256,HS256');
    t.equal(fedSp.familyAlgorithms('RSA').join(','), 'RS256',
            'federation.jwtAlgorithms narrows the key\'s family and cannot ' +
            'add HS256 to it');
  } finally {
    config.clearOverride('federation.jwtAlgorithms');
  }
  const noPeer = federation.readinessOf({ fedRole: 'service-provider',
                                          fedProtocol: 'saml2',
                                          fedSsoUrl: 'https://p/sso',
                                          fedSigningCertificate: 'MII' });
  t.check(noPeer.missing.indexOf('fedPeer') >= 0,
          'A SAML 2.0 RELATIONSHIP WITH NO fedPeer IS NOT FULLY CONFIGURED, ' +
          'in every mode',
          JSON.stringify(noPeer.missing));
  ['saml11', 'wsfed', 'oidc', 'oauth2'].forEach(function (protocol) {
    const r = federation.readinessOf({ fedRole: 'service-provider',
                                       fedProtocol: protocol });
    t.check(r.missing.indexOf('fedPeer') >= 0, protocol + ' needs fedPeer too',
            JSON.stringify(r.missing));
  });

  // -------------------------------------------------------------------------
  t.log.info('G. the SAML 1.1 responder');
  // -------------------------------------------------------------------------
  const responder = handlerFor(app, 'post', '/saml11/responder');
  const ask = function (inner) {
    log.debug("Entering ask().");
    const res = fakeRes();
    const req = fakeReq('POST', '/saml11/responder', {}, soapRequest(inner));
    responder(req, res);
    log.debug("Leaving ask().");
    return res;
  };
  const attributeQuery = '<samlp:AttributeQuery Resource="urn:rp:test">' +
    '<saml:Subject><saml:NameIdentifier>erin</saml:NameIdentifier>' +
    '</saml:Subject></samlp:AttributeQuery>';
  const devAttr = withMode(config, 'development',
                           function () { return ask(attributeQuery); });
  t.check(/samlp:Success/.test(devAttr.body) &&
          /AttributeStatement/.test(devAttr.body),
          'development: an AttributeQuery is still answered with its ' +
          'attributes');
  t.check(!/AuthenticationStatement/.test(devAttr.body),
          'BUT CLAIMS NO AUTHENTICATION — it used to carry am:password at ' +
          'the instant of the query');
  const authQuery = function (name) {
    log.debug("Entering authQuery().");
    log.debug("Leaving authQuery().");
    return '<samlp:AuthenticationQuery><saml:Subject><saml:NameIdentifier>' +
      name +
      '</saml:NameIdentifier></saml:Subject></samlp:AuthenticationQuery>';
  };
  const devNobody = withMode(config, 'development', function () {
    return ask(authQuery('never-signed-in-' + Date.now()));
  });
  t.check(/samlp:Success/.test(devNobody.body) &&
          !/<saml:Assertion/.test(devNobody.body) &&
          /no authentication is recorded/.test(devNobody.body),
          'AN AUTHENTICATION QUERY ABOUT SOMEBODY WHO NEVER SIGNED IN ' +
          'RETURNS NO ASSERTION, in either mode', devNobody.body.slice(0, 400));
  const who = 'aq-' + Date.now();
  authn.startSession(fakeRes(), who, ['swk'], '1', 'a client certificate', {});
  const devReal = withMode(config, 'development',
                           function () { return ask(authQuery(who)); });
  t.check(/AuthenticationMethod="urn:ietf:rfc:2246"/.test(devReal.body),
          'and one about a real session states how THAT session authenticated',
          devReal.body.slice(0, 600));
  const prodAttr = withMode(config, 'product',
                            function () { return ask(attributeQuery); });
  t.check(/samlp:Requester/.test(prodAttr.body) &&
          /PRODUCT/.test(prodAttr.body),
          'PRODUCT: an unauthenticated AttributeQuery is refused',
          prodAttr.body.slice(0, 400));

  // -------------------------------------------------------------------------
  t.log.info('H. the browser profiles refuse an unregistered address in ' +
             'product');
  // -------------------------------------------------------------------------
  const sso = handlerFor(app, 'get', '/saml2/sso');
  // A DIFFERENT service provider per mode, and that is load-bearing: in
  // development the SSO service RECORDS the ACS URL it was sent onto the
  // application entry as `samlAssertionConsumerService` — the attribute product
  // mode reads as the registration — so reusing one entityID would have the
  // development call register the very address the product call must refuse,
  // whenever a directory is loaded in this process (it is, in a full `npm
  // test`).
  const callSso = function (issuer) {
    log.debug("Entering callSso().");
    const authnRequest = '<samlp:AuthnRequest ' +
      'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
      'AssertionConsumerServiceURL="https://attacker.test/acs">' +
      '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
    const samlRequest = zlib.deflateRawSync(Buffer.from(authnRequest))
                            .toString('base64');
    const res = fakeRes();
    sso(fakeReq('GET', '/saml2/sso', { SAMLRequest: samlRequest }), res);
    log.debug("Leaving callSso().");
    return res;
  };
  const stamp = Date.now();
  const devSso = withMode(config, 'development', function () {
    return callSso('https://dev-sp-' + stamp + '.test');
  });
  t.equal(devSso.statusCode, 303,
          'development: an unregistered AssertionConsumerServiceURL goes on ' +
          'to the sign-in screen');
  // THE SIGNATURE POLICY IS TURNED OFF FOR THIS ONE CALL (2026-09-17, #37):
  // product refuses an UNSIGNED AuthnRequest before it looks at the address
  // (`saml2.requireSignedAuthnRequests` is on there by default), and what this
  // check is about is the address rule. `tests/saml_request_signatures.js`
  // holds the signature rule.
  const prodSso = withMode(config, 'product', function () {
    config.setOverride('saml2.requireSignedAuthnRequests', 'off');
    try {
      return callSso('https://prod-sp-' + stamp + '.test');
    } finally {
      config.clearOverride('saml2.requireSignedAuthnRequests');
    }
  });
  t.check(prodSso.statusCode === 400 && /not registered/.test(prodSso.body),
          'PRODUCT: the same AuthnRequest is refused on a page, and no ' +
          'assertion goes anywhere',
          prodSso.statusCode + ' ' + prodSso.body.slice(0, 200));

  const passive = handlerFor(app, 'get', '/wsfed');
  // A realm per mode, for the reason given above the SAML half.
  const callWsfed = function (realm) {
    log.debug("Entering callWsfed().");
    const res = fakeRes();
    passive(fakeReq('GET', '/wsfed', { wa: 'wsignin1.0', wtrealm: realm,
                                       wreply: 'https://attacker.test/reply' }),
            res);
    log.debug("Leaving callWsfed().");
    return res;
  };
  t.equal(withMode(config, 'development', function () {
    return callWsfed('urn:dev:rp:' + stamp);
  }).statusCode, 303, 'development: an unregistered wreply goes on to the ' +
                      'sign-in screen');
  const prodWsfed = withMode(config, 'product', function () {
    return callWsfed('urn:prod:rp:' + stamp);
  });
  t.check(prodWsfed.statusCode === 400 && /wsfedReplyUrl/.test(prodWsfed.body),
          'PRODUCT: an unregistered wreply is refused, naming wsfedReplyUrl',
          prodWsfed.statusCode + ' ' + prodWsfed.body.slice(0, 200));

  try {
    config.setOverride('saml2.entityId', '');
    t.equal(withMode(config, 'development',
                     function () { return saml2sso.idpEntityIdFor(''); }),
            'urn:sts:idp', 'development: an empty saml2.entityId still falls ' +
                           'back');
    const metadata = handlerFor(app, 'get', '/saml2/metadata');
    const prodMeta = withMode(config, 'product', function () {
      const res = fakeRes();
      metadata(fakeReq('GET', '/saml2/metadata', {}), res);
      return res;
    });
    t.check(prodMeta.statusCode === 503 &&
            /saml2\.entityId/.test(prodMeta.body),
            'PRODUCT: an empty saml2.entityId publishes no metadata under an ' +
            'invented name',
            prodMeta.statusCode + ' ' + prodMeta.body);
  } finally {
    config.clearOverride('saml2.entityId');
  }

  // -------------------------------------------------------------------------
  t.log.info('I. outbound switch and metadata honesty');
  // -------------------------------------------------------------------------
  let outboundDone = null;
  try {
    config.setOverride('federation.outbound', false);
    outboundDone = spMetadata.fetchMetadata('https://127.0.0.1:1/metadata');
  } finally {
    config.clearOverride('federation.outbound');
  }
  const productClaims = withMode(config, 'product', function () {
    return wsfed.federationMetadata('https://idp.test');
  });
  t.check(!/Always &quot;Mock&quot;|Always "Mock"|@sts\.example(?!\.com)/.test(
      productClaims),
          'PRODUCT: the signed WS-Federation metadata does not describe ' +
          'invented values');
  t.check(/Always "Mock"|Always &quot;Mock&quot;/.test(
      wsfed.federationMetadata('https://idp.test')),
          'development: it still does, because development still emits them');
  log.debug("Leaving run().");
  return outboundDone.then(function (answer) {
    t.check(answer.ok === false && /federation\.outbound/.test(answer.why),
            'SP metadata is not fetched when federation.outbound is off',
            answer.why);
  });
}

module.exports = {
  name: 'saml_family_hardcoded',
  describe: 'the SAML, WS-Trust, WS-Federation and federation half of the ' +
            '2026-09-12 hard-coded-values sweep: product-mode refusals, and ' +
            'the defects fixed in both modes',
  run: run
};
