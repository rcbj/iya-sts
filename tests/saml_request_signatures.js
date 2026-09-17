'use strict';
//
// File: saml_request_signatures.js
//
// ===========================================================================
// A SAML 2.0 SERVICE PROVIDER'S SIGNATURES ARE CHECKED, AND ITS METADATA IS
// CONSUMED (2026-09-17, #37).
//
// Until #37 both were "recorded, neither checked": a signed AuthnRequest's
// certificate was written onto the entry off its own ds:KeyInfo, nothing
// verified anything, the IdP metadata said WantAuthnRequestsSigned="false",
// and a service provider's metadata yielded one encryption certificate.
// `saml/CLAUDE.md` (*A SERVICE PROVIDER'S SIGNATURE, AND ITS METADATA*) argues
// what replaced that. The claims here, each against the running handlers:
//
//   A. the policy: `saml2.requireSignedAuthnRequests` in both modes, its
//      product default, and a service provider's metadata overriding it;
//   B. the HTTP Redirect binding: a query signature made with a REGISTERED key
//      is verified and recorded; RelayState or SigAlg changed after signing is
//      refused (STS-SAML-0061), and so is a Signature with no SigAlg;
//   C. the HTTP POST binding: an enveloped signature verifies; an altered
//      request is refused (0061), a wrapping attempt is refused (0062), and
//      an inclusive-c14n signature is refused (0064);
//   D. a certificate that is only in the request's KeyInfo is NOT trusted:
//      the request is `no-certificate`, the certificate is OBSERVED and not
//      registered, development encrypts to it and product does not, and
//      confirming it makes the next request `verified`;
//   E. unsigned: accepted with the setting off, refused (0063) with it on,
//      and refused in product by default;
//   F. WantAuthnRequestsSigned in the metadata follows the setting, and the
//      per-service-provider document follows that service provider's own
//      AuthnRequestsSigned;
//   G. metadata consumption: every field onto the entry, the entityID,
//      expiry and metadata-signature refusals, and a second consumption
//      retiring what the first registered;
//   H. using it: AssertionConsumerServiceIndex, the default endpoint, an
//      unregistered URL (0070) and an unknown index (0069), InvalidNameIDPolicy
//      (0071), WantAssertionsSigned in each mode;
//   I. Single Logout: a signed LogoutRequest is verified and answered at the
//      consumed ResponseLocation; a tampered one ends no session; an unsigned
//      one is refused where signatures are required;
//   J. the console/API action: the certificate is validated and normalised,
//      and the observed certificate is confirmed or discarded.
//
// WHY IN PROCESS: every claim is decided by a function this repository owns,
// several need a realm in product mode mid-run, and a signed request needs a
// key the test holds. The route handlers are called straight off the express
// router with a fake request and response, so no port is bound.
// ===========================================================================

delete process.env.CONFIG_FILE;

const zlib = require('zlib');

const log = require('bunyan').createLogger({ name: 'saml_request_signatures',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const B_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const B_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const B_PAOS = 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const F_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const F_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const F_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

// --- plumbing ----------------------------------------------------------------

function fakeReq(method, path, query, rawQuery, body) {
  log.debug("Entering fakeReq().");
  const headers = { host: 'idp.test' };
  log.debug("Leaving fakeReq().");
  return {
    method: method, path: path, url: path,
    originalUrl: path + (rawQuery ? '?' + rawQuery : ''),
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
  res.type = function (value) {
    log.debug("Entering type().");
    res.headers['content-type'] = value;
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
  res.append = res.set;
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

function withSettings(config, pairs, fn) {
  log.debug("Entering withSettings().");
  Object.keys(pairs).forEach(function (key) {
    config.setOverride(key, pairs[key]);
  });
  try {
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    Object.keys(pairs).forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// An AuthnRequest. `extra` goes inside the root after the Issuer.
function authnRequest(opts) {
  log.debug("Entering authnRequest().");
  const o = opts || {};
  log.debug("Leaving authnRequest().");
  return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + (o.id || '_req1') + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '"' +
    (o.acs ? ' AssertionConsumerServiceURL="' + o.acs + '"' : '') +
    (o.index !== undefined ? ' AssertionConsumerServiceIndex="' + o.index +
                             '"' : '') +
    (o.binding ? ' ProtocolBinding="' + o.binding + '"' : '') +
    '><saml:Issuer>' + o.issuer + '</saml:Issuer>' + (o.extra || '') +
    (o.format ? '<samlp:NameIDPolicy Format="' + o.format + '"/>' : '') +
    '</samlp:AuthnRequest>';
}

function logoutRequest(issuer, id) {
  log.debug("Entering logoutRequest().");
  log.debug("Leaving logoutRequest().");
  return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + (id || '_lo1') + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    '<saml:Issuer>' + issuer + '</saml:Issuer>' +
    '<saml:NameID>alice</saml:NameID></samlp:LogoutRequest>';
}

function deflate(xml) {
  log.debug("Entering deflate().");
  log.debug("Leaving deflate().");
  return zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

// The Redirect binding's octets and signature, section 3.4.4.1.
function redirectQuery(stsCrypto, xml, relayState, key, sigAlg, field) {
  log.debug("Entering redirectQuery().");
  let q = (field || 'SAMLRequest') + '=' + encodeURIComponent(deflate(xml));
  if (relayState !== undefined) {
    q += '&RelayState=' + encodeURIComponent(relayState);
  }
  if (key) {
    q += '&SigAlg=' + encodeURIComponent(sigAlg || RSA_SHA256);
    q += '&Signature=' + encodeURIComponent(
      stsCrypto.signQueryString(q, key, sigAlg || RSA_SHA256));
  }
  log.debug("Leaving redirectQuery().");
  return q;
}

function queryObject(raw) {
  log.debug("Entering queryObject().");
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) {
    if (!Object.prototype.hasOwnProperty.call(out, k)) {
      out[k] = v;
    }
  });
  log.debug("Leaving queryObject().");
  return out;
}

function inflateParam(url, name) {
  log.debug("Entering inflateParam().");
  const at = url.indexOf('?');
  const value = new URLSearchParams(url.slice(at + 1)).get(name) || '';
  log.debug("Leaving inflateParam().");
  return zlib.inflateRawSync(Buffer.from(value, 'base64')).toString('utf8');
}

function spMetadataDocument(entityId, opts) {
  log.debug("Entering spMetadataDocument().");
  const o = opts || {};
  const key = function (use, b64) {
    log.debug("Entering key().");
    log.debug("Leaving key().");
    return '<md:KeyDescriptor' + (use ? ' use="' + use + '"' : '') + '>' +
      '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '<ds:X509Data><ds:X509Certificate>' + b64 +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
  };
  log.debug("Leaving spMetadataDocument().");
  return '<md:EntityDescriptor ' +
    'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_md1" ' +
    'entityID="' + entityId + '"' +
    (o.validUntil ? ' validUntil="' + o.validUntil + '"' : '') +
    ' cacheDuration="PT6H">' +
    '<md:SPSSODescriptor protocolSupportEnumeration="' + NS_SAMLP + '"' +
    ' AuthnRequestsSigned="' + (o.requestsSigned ? 'true' : 'false') + '"' +
    ' WantAssertionsSigned="true">' +
    (o.signing ? key('signing', o.signing) : '') +
    (o.encryption ? key('encryption', o.encryption) : '') +
    (o.slo || []).map(function (e) {
      return '<md:SingleLogoutService Binding="' + e[0] + '" Location="' +
             e[1] + '"' + (e[2] ? ' ResponseLocation="' + e[2] + '"' : '') +
             '/>';
    }).join('') +
    (o.formats || []).map(function (f) {
      return '<md:NameIDFormat>' + f + '</md:NameIDFormat>';
    }).join('') +
    (o.acs || []).map(function (e) {
      return '<md:AssertionConsumerService Binding="' + e.binding +
             '" Location="' + e.location + '" index="' + e.index + '"' +
             (e.isDefault !== undefined ? ' isDefault="' + e.isDefault + '"'
                                        : '') + '/>';
    }).join('') +
    '</md:SPSSODescriptor></md:EntityDescriptor>';
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const app = require('../common/app');
  // The registry's store is the directory; requiring it fills the slot. It
  // binds no port.
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const saml2sso = require('../saml/saml2_sso');
  const spMetadata = require('../saml/sp_metadata');
  const requestSignature = require('../saml/request_signature');
  const adminActions = require('../admin-core/admin_actions');
  saml2sso.registerRoutes(app);
  const sso = handlerFor(app, 'get', '/saml2/sso');
  const ssoPost = handlerFor(app, 'post', '/saml2/sso');
  const slo = handlerFor(app, 'get', '/saml2/slo');
  // An instance of the class, for the decisions the routes make privately.
  const direct = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());

  const stamp = String(Date.now());
  const keyA = stsCrypto.selfSignedRsaCertificate({ commonName: 'sp-a',
                                                    bits: 2048 });
  const keyB = stsCrypto.selfSignedRsaCertificate({ commonName: 'sp-b',
                                                    bits: 2048 });
  const keyC = stsCrypto.selfSignedRsaCertificate({ commonName: 'sp-c',
                                                    bits: 2048 });

  const newSp = function (name, certs) {
    log.debug("Entering newSp().");
    const id = 'https://' + name + '-' + stamp + '.sp.test/saml';
    const made = applications.createApplication({
      identifier: id, kind: 'saml2-service-provider', protocol: 'SAML 2.0',
      fields: { samlEntityId: id }
    });
    t.check(made.ok, 'created the service provider ' + name,
            JSON.stringify(made.errors || ''));
    (certs || []).forEach(function (one) {
      const added = applications.updateApplication(id, {
        attribute: 'samlSigningCertificate', mode: 'add', value: one });
      t.check(added.ok, 'registered a signing certificate on ' + name,
              JSON.stringify(added.errors || ''));
    });
    log.debug("Leaving newSp().");
    return id;
  };
  const fieldsOf = function (id) {
    log.debug("Entering fieldsOf().");
    log.debug("Leaving fieldsOf().");
    return (applications.get(id) || {}).fields || {};
  };
  const getSso = function (raw) {
    log.debug("Entering getSso().");
    const res = fakeRes();
    sso(fakeReq('GET', '/saml2/sso', queryObject(raw), raw), res);
    log.debug("Leaving getSso().");
    return res;
  };
  const postSso = function (xml) {
    log.debug("Entering postSso().");
    const res = fakeRes();
    const b64 = Buffer.from(xml, 'utf8').toString('base64');
    ssoPost(fakeReq('POST', '/saml2/sso', {}, '',
                    'SAMLRequest=' + encodeURIComponent(b64)), res);
    // A POST-binding request is held and turned into a GET; follow it, which
    // is where the sighting is recorded.
    if (res.statusCode === 303 && /\?rid=/.test(res.location)) {
      const rid = res.location.split('?rid=')[1];
      const next = fakeRes();
      sso(fakeReq('GET', '/saml2/sso', { rid: decodeURIComponent(rid) },
                  'rid=' + rid), next);
      next.held = res;
      log.debug("Leaving postSso(). Followed the hold.");
      return next;
    }
    log.debug("Leaving postSso().");
    return res;
  };
  const codeOf = function (res) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(res) || '';
  };
  const toSignIn = function (res) {
    log.debug("Entering toSignIn().");
    log.debug("Leaving toSignIn().");
    return res.statusCode === 303 && /authn/.test(res.location);
  };
  const signPost = function (xml, key, extra) {
    log.debug("Entering signPost().");
    log.debug("Leaving signPost().");
    return stsCrypto.signXml(xml, Object.assign({
      privateKeyPem: key.privateKeyPem, certPem: key.certPem,
      placement: stsCrypto.PLACEMENT.AFTER_ISSUER, what: 'test request'
    }, extra || {}));
  };

  // -------------------------------------------------------------------------
  t.log.info('A. the policy');
  // -------------------------------------------------------------------------
  const devNeed = withSettings(config, { 'global.mode': 'development' },
    function () { return requestSignature.requiresSignedRequests({}); });
  t.equal(devNeed.required, false,
          'development, auto: an unsigned request is accepted', devNeed.why);
  const prodNeed = withSettings(config, { 'global.mode': 'product' },
    function () { return requestSignature.requiresSignedRequests({}); });
  t.equal(prodNeed.required, true,
          'PRODUCT, auto (the default): signed requests are required',
          prodNeed.why);
  t.equal(String(config.value('saml2.requireSignedAuthnRequests')), 'auto',
          'the setting defaults to auto');
  t.equal(withSettings(config, { 'global.mode': 'product',
                                 'saml2.requireSignedAuthnRequests': 'off' },
    function () {
      return requestSignature.requiresSignedRequests({}).required;
    }), false, 'product with the setting off: not required');
  t.equal(withSettings(config, { 'saml2.requireSignedAuthnRequests': 'on' },
    function () {
      return requestSignature.requiresSignedRequests({}).required;
    }), true, 'development with the setting on: required');
  t.equal(withSettings(config, { 'saml2.requireSignedAuthnRequests': 'off' },
    function () {
      return requestSignature.requiresSignedRequests(
        { samlSpAuthnRequestsSigned: 'TRUE' }).required;
    }), true, 'a service provider whose metadata says AuthnRequestsSigned is ' +
              'held to it even with the setting off');

  // -------------------------------------------------------------------------
  t.log.info('B. the HTTP Redirect binding');
  // -------------------------------------------------------------------------
  const spA = newSp('redirect', [keyA.certB64]);
  const signedRaw = redirectQuery(stsCrypto,
    authnRequest({ issuer: spA, id: '_rB1' }), 'state-1', keyA.privateKeyPem);
  const okRedirect = getSso(signedRaw);
  t.check(toSignIn(okRedirect),
          'a query signature made with the REGISTERED key is accepted — the ' +
          'request goes on to the sign-in screen',
          okRedirect.statusCode + ' ' + okRedirect.location + ' ' +
          okRedirect.body.slice(0, 300));
  t.check(/^verified redirect .*rsa-sha256/.test(
            String(fieldsOf(spA).samlAuthnRequestVerification)),
          'and it is RECORDED as verified on the entry',
          String(fieldsOf(spA).samlAuthnRequestVerification));
  t.equal(fieldsOf(spA).samlAuthnRequestSigned, 'TRUE',
          'and as signed');

  const tamperedRelay = signedRaw.replace('RelayState=state-1',
                                          'RelayState=state-2');
  const badRelay = getSso(tamperedRelay);
  t.check(badRelay.statusCode === 403 && codeOf(badRelay) === 'STS-SAML-0061',
          'RelayState changed after signing is REFUSED, STS-SAML-0061',
          badRelay.statusCode + ' ' + codeOf(badRelay));
  const tamperedAlg = signedRaw.replace(
    'SigAlg=' + encodeURIComponent(RSA_SHA256),
    'SigAlg=' + encodeURIComponent(RSA_SHA512));
  t.check(tamperedAlg !== signedRaw, 'the SigAlg was substituted');
  const badAlg = getSso(tamperedAlg);
  t.check(badAlg.statusCode === 403 && codeOf(badAlg) === 'STS-SAML-0061',
          'SigAlg changed after signing is REFUSED, STS-SAML-0061',
          badAlg.statusCode + ' ' + codeOf(badAlg));
  const wrongKey = getSso(redirectQuery(stsCrypto,
    authnRequest({ issuer: spA, id: '_rB2' }), 'state-3', keyB.privateKeyPem));
  t.check(wrongKey.statusCode === 403 &&
          codeOf(wrongKey) === 'STS-SAML-0061',
          'a signature by a key that is not registered is REFUSED',
          wrongKey.statusCode + ' ' + codeOf(wrongKey));
  t.check(/refused/.test(badRelay.body) || /not accepted/.test(badRelay.body),
          'and the refusal is a page that says so',
          badRelay.body.slice(0, 200));
  const ecAlg = getSso(signedRaw.replace(
    'SigAlg=' + encodeURIComponent(RSA_SHA256),
    'SigAlg=' + encodeURIComponent(
      'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256')));
  t.check(ecAlg.statusCode === 403 && codeOf(ecAlg) === 'STS-SAML-0062',
          'a SigAlg this service has no verifier for (ECDSA) cannot be ' +
          'checked and is REFUSED, STS-SAML-0062 — not reported as a wrong ' +
          'signature', ecAlg.statusCode + ' ' + codeOf(ecAlg));
  const noAlg = getSso(signedRaw.replace(/&SigAlg=[^&]*/, ''));
  t.check(noAlg.statusCode === 403 && codeOf(noAlg) === 'STS-SAML-0062',
          'a Signature with no SigAlg cannot be checked and is REFUSED, ' +
          'STS-SAML-0062', noAlg.statusCode + ' ' + codeOf(noAlg));
  // Lower-case percent-encoding is still the octets that were signed.
  let lower = 'SAMLRequest=' + encodeURIComponent(
    deflate(authnRequest({ issuer: spA, id: '_rB3' })))
    .replace(/%[0-9A-F]{2}/g, function (m) { return m.toLowerCase(); }) +
    '&RelayState=a%2fb';
  lower += '&SigAlg=' + encodeURIComponent(RSA_SHA256).toLowerCase();
  lower += '&Signature=' + encodeURIComponent(
    stsCrypto.signQueryString(lower, keyA.privateKeyPem, RSA_SHA256));
  t.check(toSignIn(getSso(lower)),
          'the octets are the parameters AS THEY ARRIVED: lower-case ' +
          'percent-encoding verifies');
  const sha1 = getSso(redirectQuery(stsCrypto,
    authnRequest({ issuer: spA, id: '_rB4' }), undefined, keyA.privateKeyPem,
    RSA_SHA1));
  t.check(toSignIn(sha1) &&
          / weak$/.test(String(fieldsOf(spA).samlAuthnRequestVerification)),
          'SHA-1 verifies (no weak-algorithm policy exists) and is recorded ' +
          'as weak', String(fieldsOf(spA).samlAuthnRequestVerification));

  // -------------------------------------------------------------------------
  t.log.info('C. the HTTP POST binding');
  // -------------------------------------------------------------------------
  const spP = newSp('post', [keyA.certB64]);
  const signedPost = signPost(authnRequest({ issuer: spP, id: '_pC1',
    acs: 'https://' + stamp + '.acs.test/one' }), keyA);
  const okPost = postSso(signedPost);
  t.check(toSignIn(okPost) && okPost.held.statusCode === 303,
          'an enveloped signature by the registered key verifies — held, ' +
          'turned into a GET, and on to the sign-in screen',
          okPost.statusCode + ' ' + okPost.location + ' ' +
          okPost.body.slice(0, 300));
  t.check(/^verified post /.test(
            String(fieldsOf(spP).samlAuthnRequestVerification)),
          'recorded as verified on the POST binding',
          String(fieldsOf(spP).samlAuthnRequestVerification));
  const altered = signedPost.replace('https://' + stamp + '.acs.test/one',
                                     'https://evil.test/acs');
  const badPost = postSso(altered);
  t.check(badPost.statusCode === 403 && codeOf(badPost) === 'STS-SAML-0061',
          'an AuthnRequest altered after signing is REFUSED, STS-SAML-0061',
          badPost.statusCode + ' ' + codeOf(badPost));
  // WRAPPING: the signed original tucked inside an unsigned root whose own
  // signature is the original's, still naming the original's ID.
  const sigStart = signedPost.indexOf('<ds:Signature');
  const sigEnd = signedPost.indexOf('</ds:Signature>') +
                 '</ds:Signature>'.length;
  const signature = signedPost.slice(sigStart, sigEnd);
  const wrapped = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="_evil" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '" ' +
    'AssertionConsumerServiceURL="https://evil.test/acs">' +
    '<saml:Issuer>' + spP + '</saml:Issuer>' + signature +
    '<samlp:Extensions>' + signedPost + '</samlp:Extensions>' +
    '</samlp:AuthnRequest>';
  const badWrap = postSso(wrapped);
  t.check(badWrap.statusCode === 403 && codeOf(badWrap) === 'STS-SAML-0062',
          'a SIGNATURE-WRAPPING attempt — the root carries a signature ' +
          'referencing the nested original — is REFUSED, STS-SAML-0062',
          badWrap.statusCode + ' ' + codeOf(badWrap));
  const unsignedWrap = wrapped.replace(signature, '');
  const wrapRequired = withSettings(config,
    { 'saml2.requireSignedAuthnRequests': 'on' },
    function () { return postSso(unsignedWrap); });
  t.check(wrapRequired.statusCode === 403 &&
          codeOf(wrapRequired) === 'STS-SAML-0063',
          'a root with NO signature of its own around a signed original is ' +
          'UNSIGNED — refused where signatures are required',
          wrapRequired.statusCode + ' ' + codeOf(wrapRequired));
  let inclusive = null;
  try {
    inclusive = signPost(authnRequest({ issuer: spP, id: '_pC2' }), keyA,
      { c14nAlg: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (inclusive && /REC-xml-c14n-20010315/.test(inclusive)) {
    const badC14n = postSso(inclusive);
    t.check(badC14n.statusCode === 403 &&
            codeOf(badC14n) === 'STS-SAML-0064',
            'an inclusive-c14n signature is REFUSED, STS-SAML-0064',
            badC14n.statusCode + ' ' + codeOf(badC14n));
  } else {
    t.check(false, 'the signer produced an inclusive-c14n signature to ' +
                   'test with', String(inclusive).slice(0, 200));
  }

  // -------------------------------------------------------------------------
  t.log.info('D. a KeyInfo certificate is observed, not trusted');
  // -------------------------------------------------------------------------
  const spK = newSp('keyinfo', []);
  const keyInfoOnly = postSso(signPost(authnRequest({ issuer: spK,
                                                      id: '_kD1' }), keyC));
  t.check(toSignIn(keyInfoOnly),
          'development: a request signed by a key the entry does not hold is ' +
          'accepted', keyInfoOnly.statusCode + ' ' + codeOf(keyInfoOnly));
  t.check(/^no-certificate /.test(
            String(fieldsOf(spK).samlAuthnRequestVerification)),
          'but it is recorded as no-certificate — NOT verified — because the ' +
          'certificate in its KeyInfo is not a trust anchor',
          String(fieldsOf(spK).samlAuthnRequestVerification));
  t.equal(fieldsOf(spK).samlObservedSigningCertificate, keyC.certB64,
          'the KeyInfo certificate is recorded as OBSERVED');
  t.equal([].concat(fieldsOf(spK).samlSigningCertificate || []).length, 0,
          'and NOT written onto samlSigningCertificate');
  const observedRequired = withSettings(config,
    { 'saml2.requireSignedAuthnRequests': 'on' },
    function () {
      return postSso(signPost(authnRequest({ issuer: spK, id: '_kD2' }),
                              keyC));
    });
  t.check(observedRequired.statusCode === 403 &&
          codeOf(observedRequired) === 'STS-SAML-0063',
          'where signatures are required, a signature only its own KeyInfo ' +
          'vouches for is refused as unsigned',
          observedRequired.statusCode + ' ' + codeOf(observedRequired));
  const devEnc = withSettings(config, { 'global.mode': 'development' },
    function () { return direct.encryptionCertificateFor(spK); });
  t.check(/observed/.test(devEnc.source) && /BEGIN CERTIFICATE/.test(
            devEnc.pem),
          'development still ENCRYPTS to the observed certificate',
          devEnc.source);
  const prodEnc = withSettings(config, { 'global.mode': 'product' },
    function () { return direct.encryptionCertificateFor(spK); });
  t.check(!prodEnc.pem && prodEnc.observedWithheld,
          'PRODUCT does not encrypt to an unconfirmed certificate',
          JSON.stringify(prodEnc));
  const confirmed = adminActions.saml2Action(
    { action: 'confirm-signing-certificate', sp: spK });
  t.check(confirmed.ok, 'the observed certificate is CONFIRMED',
          JSON.stringify(confirmed.errors || ''));
  t.check([].concat(fieldsOf(spK).samlSigningCertificate || [])
            .indexOf(keyC.certB64) >= 0 &&
          !fieldsOf(spK).samlObservedSigningCertificate,
          'confirming MOVES it onto samlSigningCertificate');
  postSso(signPost(authnRequest({ issuer: spK, id: '_kD3' }), keyC));
  t.check(/^verified /.test(String(fieldsOf(spK).samlAuthnRequestVerification)),
          'and the next request signed with it is verified',
          String(fieldsOf(spK).samlAuthnRequestVerification));
  const prodEncAfter = withSettings(config, { 'global.mode': 'product' },
    function () { return direct.encryptionCertificateFor(spK); });
  t.equal(prodEncAfter.source, 'samlSigningCertificate',
          'and product encrypts to it once it is registered');
  const againObserved = postSso(signPost(authnRequest({ issuer: spK,
                                                        id: '_kD4' }), keyB));
  t.check(againObserved.statusCode === 403 &&
          codeOf(againObserved) === 'STS-SAML-0061',
          'with a certificate registered, a request signed by ANOTHER key ' +
          'carrying its own KeyInfo is refused, not observed',
          againObserved.statusCode + ' ' + codeOf(againObserved));
  const discardNothing = adminActions.saml2Action(
    { action: 'discard-signing-certificate', sp: spK });
  t.check(!discardNothing.ok && errorCodes.codeOf(discardNothing) ===
          'STS-REG-0163', 'discarding with nothing observed is refused by ' +
          'name', JSON.stringify(discardNothing.errors));
  const spK2 = newSp('keyinfo-discard', []);
  postSso(signPost(authnRequest({ issuer: spK2, id: '_kD5' }), keyC));
  const discarded = adminActions.saml2Action(
    { action: 'discard-signing-certificate', sp: spK2 });
  t.check(discarded.ok && !fieldsOf(spK2).samlObservedSigningCertificate &&
          ![].concat(fieldsOf(spK2).samlSigningCertificate || []).length,
          'a DISCARDED observed certificate is gone and registered nowhere');

  // -------------------------------------------------------------------------
  t.log.info('E. unsigned requests and the setting');
  // -------------------------------------------------------------------------
  const spU = newSp('unsigned', []);
  const unsignedRaw = redirectQuery(stsCrypto,
    authnRequest({ issuer: spU, id: '_uE1' }), 'u');
  t.check(toSignIn(withSettings(config,
    { 'saml2.requireSignedAuthnRequests': 'off' },
    function () { return getSso(unsignedRaw); })),
          'setting OFF: an unsigned request is accepted');
  t.check(/^unsigned /.test(String(fieldsOf(spU).samlAuthnRequestVerification)),
          'and recorded as unsigned',
          String(fieldsOf(spU).samlAuthnRequestVerification));
  const unsignedOn = withSettings(config,
    { 'saml2.requireSignedAuthnRequests': 'on' },
    function () { return getSso(unsignedRaw); });
  t.check(unsignedOn.statusCode === 403 &&
          codeOf(unsignedOn) === 'STS-SAML-0063',
          'setting ON: an unsigned request is REFUSED, STS-SAML-0063',
          unsignedOn.statusCode + ' ' + codeOf(unsignedOn));
  const unsignedProd = withSettings(config, { 'global.mode': 'product' },
    function () { return getSso(unsignedRaw); });
  t.check(unsignedProd.statusCode === 403 &&
          codeOf(unsignedProd) === 'STS-SAML-0063',
          'PRODUCT, by default: an unsigned request is REFUSED',
          unsignedProd.statusCode + ' ' + codeOf(unsignedProd));
  t.check(toSignIn(getSso(unsignedRaw)),
          'development, by default: the same request is accepted');

  // -------------------------------------------------------------------------
  t.log.info('F. WantAuthnRequestsSigned follows the setting');
  // -------------------------------------------------------------------------
  const want = function (xml) {
    log.debug("Entering want().");
    const m = /WantAuthnRequestsSigned="(true|false)"/.exec(xml);
    log.debug("Leaving want().");
    return m ? m[1] : '(missing)';
  };
  t.equal(want(direct.metadataFor('https://idp.test', '')), 'false',
          'development, auto: WantAuthnRequestsSigned="false"');
  t.equal(want(withSettings(config,
    { 'saml2.requireSignedAuthnRequests': 'on' },
    function () { return direct.metadataFor('https://idp.test', ''); })),
          'true', 'the setting on: WantAuthnRequestsSigned="true"');
  t.equal(want(withSettings(config, { 'global.mode': 'product' },
    function () { return direct.metadataFor('https://idp.test', ''); })),
          'true', 'product, auto: WantAuthnRequestsSigned="true"');

  // -------------------------------------------------------------------------
  t.log.info('G. consuming a service provider\'s metadata');
  // -------------------------------------------------------------------------
  const spM = newSp('metadata', []);
  const base = 'https://' + stamp + '.m.test';
  const docM = spMetadataDocument(spM, {
    requestsSigned: true, signing: keyA.certB64, encryption: keyB.certB64,
    formats: [F_EMAIL, F_PERSISTENT],
    slo: [[B_REDIRECT, base + '/slo', base + '/slo-response'],
          [B_POST, base + '/slo-post']],
    acs: [{ binding: B_POST, location: base + '/acs0', index: 0,
            isDefault: 'false' },
          { binding: B_REDIRECT, location: base + '/acs1', index: 1,
            isDefault: 'true' },
          { binding: B_PAOS, location: base + '/ecp', index: 2 }]
  });
  const consumed = adminActions.saml2Action({ action: 'upload-metadata',
                                              sp: spM, document: docM });
  t.check(consumed.ok, 'the metadata document is consumed',
          JSON.stringify(consumed.errors || consumed));
  const fm = fieldsOf(spM);
  t.check([].concat(fm.samlSigningCertificate || []).join() === keyA.certB64,
          'its use="signing" certificate is REGISTERED',
          JSON.stringify(fm.samlSigningCertificate));
  t.equal(String(fm.samlEncryptionCertificate), keyB.certB64,
          'its use="encryption" certificate is the encryption certificate');
  t.equal([].concat(fm.samlAcsEndpoint || []).length, 3,
          'all three assertion consumer services are recorded, with index, ' +
          'isDefault, binding and location');
  t.check([].concat(fm.samlAcsEndpoint || [])
            .indexOf('1 true ' + B_REDIRECT + ' ' + base + '/acs1') >= 0,
          'as `<index> <isDefault> <binding> <location>`',
          JSON.stringify(fm.samlAcsEndpoint));
  t.check([base + '/acs0', base + '/acs1', base + '/ecp'].every(function (u) {
    return [].concat(fm.samlAssertionConsumerService || []).indexOf(u) >= 0;
  }), 'and their locations are REGISTERED return addresses',
          JSON.stringify(fm.samlAssertionConsumerService));
  t.check(applications.returnAddressesOf(fm, 'samlAssertionConsumerService')
            .registered.length >= 3 &&
          withSettings(config, { 'global.mode': 'product' }, function () {
            return applications.returnAddressesOf(
              fieldsOf(spM), 'samlAssertionConsumerService').unconfirmed;
          }).length === 0,
          'which product believes: none is marked observed');
  t.check([].concat(fm.samlSloEndpoint || [])
            .indexOf(B_REDIRECT + ' ' + base + '/slo ' + base +
                     '/slo-response') >= 0 &&
          [].concat(fm.samlSingleLogoutService || [])
            .indexOf(base + '/slo-post') >= 0,
          'the SingleLogoutService endpoints, with their ResponseLocation',
          JSON.stringify(fm.samlSloEndpoint));
  t.equal([].concat(fm.samlSpNameIdFormat || []).join(' '),
          F_EMAIL + ' ' + F_PERSISTENT, 'the NameIDFormats');
  t.equal(fm.samlSpAuthnRequestsSigned, 'TRUE', 'AuthnRequestsSigned');
  t.equal(fm.samlSpWantAssertionsSigned, 'TRUE', 'WantAssertionsSigned');
  t.equal(fm.samlSpMetadataCacheDuration, 'PT6H', 'cacheDuration');
  t.equal(fm.samlSpMetadataSignature, 'unsigned',
          'the document\'s own signature: unsigned');
  t.check(/ upload$/.test(String(fm.samlSpMetadataConsumedAt)),
          'and when, and how', String(fm.samlSpMetadataConsumedAt));
  t.equal(want(direct.metadataFor('https://idp.test', spM)), 'true',
          'the metadata minted FOR this service provider says ' +
          'WantAuthnRequestsSigned="true", because it said ' +
          'AuthnRequestsSigned');
  t.equal(want(direct.metadataFor('https://idp.test', spU)), 'false',
          'and another service provider\'s still says false');
  const viewM = require('../admin-core/admin_views').saml2DetailJson(
    fakeReq('GET', '/admin/saml2', { sp: spM }, ''), spM).json;
  t.check(viewM.metadata.consumed &&
          viewM.metadata.assertionConsumerServices.length === 3 &&
          viewM.signedRequestsRequired.required === true &&
          viewM.signingCertificates.length === 1,
          'GET /admin-api/saml2?sp= shows what was consumed',
          JSON.stringify(viewM.metadata).slice(0, 300));

  const other = adminActions.saml2Action({ action: 'upload-metadata',
    sp: spM, document: spMetadataDocument('https://somebody.else/saml', {}) });
  t.check(!other.ok && /somebody\.else/.test(other.errors.join(' ')),
          'a document for ANOTHER entityID is refused',
          JSON.stringify(other.errors));
  const expired = adminActions.saml2Action({ action: 'upload-metadata',
    sp: spM, document: spMetadataDocument(spM,
      { validUntil: '2001-01-01T00:00:00Z' }) });
  t.check(!expired.ok && /expired/.test(expired.errors.join(' ')),
          'an EXPIRED document is refused', JSON.stringify(expired.errors));
  t.equal(String(fieldsOf(spM).samlSpMetadataCacheDuration), 'PT6H',
          'and a refusal changed nothing');
  const empty = adminActions.saml2Action({ action: 'upload-metadata',
                                           sp: spM });
  t.check(!empty.ok, 'an upload with no document is refused');

  // The metadata's own signature, against a configured certificate.
  const spS = newSp('signed-metadata', []);
  const setAnchor = adminActions.saml2Action({
    action: 'set-metadata-signing-certificate', sp: spS,
    value: keyC.certPem });
  t.check(setAnchor.ok, 'the metadata signing certificate is set (PEM ' +
                        'accepted)', JSON.stringify(setAnchor.errors || ''));
  const plainS = spMetadataDocument(spS, { acs: [{ binding: B_POST,
    location: base + '/s-acs', index: 0 }] });
  const unsignedS = adminActions.saml2Action({ action: 'upload-metadata',
                                               sp: spS, document: plainS });
  t.check(!unsignedS.ok && /signed with that key/.test(
            unsignedS.errors.join(' ')),
          'with it set, an UNSIGNED document is refused',
          JSON.stringify(unsignedS.errors));
  const signedS = stsCrypto.signXml(plainS, {
    privateKeyPem: keyC.privateKeyPem, certPem: keyC.certPem,
    placement: stsCrypto.PLACEMENT.FIRST, what: 'test metadata' });
  const wrongS = stsCrypto.signXml(plainS, {
    privateKeyPem: keyB.privateKeyPem, certPem: keyB.certPem,
    placement: stsCrypto.PLACEMENT.FIRST, what: 'test metadata' });
  const refusedS = adminActions.saml2Action({ action: 'upload-metadata',
                                              sp: spS, document: wrongS });
  t.check(!refusedS.ok, 'one signed by another key is refused',
          JSON.stringify(refusedS.errors));
  const acceptedS = adminActions.saml2Action({ action: 'upload-metadata',
                                               sp: spS, document: signedS });
  t.check(acceptedS.ok && fieldsOf(spS).samlSpMetadataSignature ===
          'verified', 'one signed by that key is consumed and recorded as ' +
          'verified', JSON.stringify(acceptedS.errors || ''));
  const spS2 = newSp('signed-metadata-2', []);
  const signedNoAnchor = stsCrypto.signXml(
    spMetadataDocument(spS2, {}), {
      privateKeyPem: keyC.privateKeyPem, certPem: keyC.certPem,
      placement: stsCrypto.PLACEMENT.FIRST, what: 'test metadata' });
  const noAnchor = spMetadata.upload(spS2, signedNoAnchor);
  t.check(noAnchor.ok && fieldsOf(spS2).samlSpMetadataSignature ===
          'signed-not-verified',
          'with no certificate configured, a signed document is recorded as ' +
          'signed-not-verified — never verified against its own key',
          String(fieldsOf(spS2).samlSpMetadataSignature));

  // A second consumption retires what the first registered.
  const spR = newSp('retire', []);
  spMetadata.upload(spR, spMetadataDocument(spR, { acs: [
    { binding: B_POST, location: base + '/old', index: 0 }] }));
  const declared = applications.updateApplication(spR, {
    attribute: 'samlAssertionConsumerService', mode: 'add',
    value: base + '/by-hand' });
  t.check(declared.ok, 'an address was added by hand');
  spMetadata.upload(spR, spMetadataDocument(spR, { acs: [
    { binding: B_POST, location: base + '/new', index: 0 }] }));
  const acsR = [].concat(fieldsOf(spR).samlAssertionConsumerService || []);
  t.check(acsR.indexOf(base + '/old') < 0 && acsR.indexOf(base + '/new') >= 0 &&
          acsR.indexOf(base + '/by-hand') >= 0,
          'a later document RETIRES the endpoint the earlier one registered, ' +
          'adds its own, and keeps the one added by hand',
          JSON.stringify(acsR));

  // -------------------------------------------------------------------------
  t.log.info('H. the SSO service uses what was consumed');
  // -------------------------------------------------------------------------
  // A NameIDPolicy the metadata does not declare is answered with a Response
  // — which is also where the chosen endpoint is visible.
  const probe = function (opts) {
    log.debug("Entering probe().");
    const raw = redirectQuery(stsCrypto, authnRequest(Object.assign(
      { issuer: spM, format: F_TRANSIENT }, opts)), 'p',
      keyA.privateKeyPem);
    log.debug("Leaving probe().");
    return getSso(raw);
  };
  const byDefault = probe({ id: '_h1' });
  t.check(byDefault.statusCode === 303 &&
          byDefault.location.indexOf(base + '/acs1?') === 0,
          'no ACS named: the DEFAULT endpoint (isDefault="true"), on its own ' +
          'Redirect binding', byDefault.statusCode + ' ' + byDefault.location);
  t.equal(codeOf(byDefault), 'STS-SAML-0071',
          'and a NameIDPolicy the metadata does not declare is refused, ' +
          'STS-SAML-0071');
  if (byDefault.location) {
    const answered = inflateParam(byDefault.location, 'SAMLResponse');
    t.check(/InvalidNameIDPolicy/.test(answered) && /Requester/.test(answered),
            'as a Response carrying Requester / InvalidNameIDPolicy',
            answered.slice(0, 400));
  }
  const byIndex = probe({ id: '_h2', index: 0 });
  t.check(byIndex.statusCode === 200 &&
          byIndex.body.indexOf('action="' + base + '/acs0"') >= 0,
          'AssertionConsumerServiceIndex="0": that endpoint, on ITS binding ' +
          '(a form POST)', byIndex.statusCode + ' ' +
          byIndex.body.slice(0, 200));
  const byUrl = probe({ id: '_h3', acs: base + '/acs0' });
  t.check(byUrl.statusCode === 200 &&
          byUrl.body.indexOf('action="' + base + '/acs0"') >= 0,
          'a registered AssertionConsumerServiceURL is answered there',
          byUrl.statusCode);
  const badIndex = probe({ id: '_h4', index: 7 });
  t.check(badIndex.statusCode === 400 &&
          codeOf(badIndex) === 'STS-SAML-0069',
          'an unknown AssertionConsumerServiceIndex is REFUSED, STS-SAML-0069',
          badIndex.statusCode + ' ' + codeOf(badIndex));
  const paosIndex = probe({ id: '_h5', index: 2 });
  t.check(paosIndex.statusCode === 400 &&
          codeOf(paosIndex) === 'STS-SAML-0069',
          'an index whose endpoint is PAOS is refused too',
          paosIndex.statusCode + ' ' + codeOf(paosIndex));
  const badUrl = probe({ id: '_h6', acs: 'https://evil.test/acs' });
  t.check(badUrl.statusCode === 400 && codeOf(badUrl) === 'STS-SAML-0070',
          'IN DEVELOPMENT, an ACS URL not in the consumed metadata is ' +
          'REFUSED, STS-SAML-0070', badUrl.statusCode + ' ' + codeOf(badUrl));
  const goodFormat = probe({ id: '_h7', format: F_EMAIL });
  t.check(toSignIn(goodFormat),
          'a declared NameIDPolicy Format goes on to the sign-in screen',
          goodFormat.statusCode + ' ' + codeOf(goodFormat));
  const unsignedM = getSso(redirectQuery(stsCrypto,
    authnRequest({ issuer: spM, id: '_h8' }), 'x'));
  t.check(unsignedM.statusCode === 403 &&
          codeOf(unsignedM) === 'STS-SAML-0063',
          'IN DEVELOPMENT, an unsigned request from a service provider whose ' +
          'metadata says AuthnRequestsSigned is REFUSED',
          unsignedM.statusCode + ' ' + codeOf(unsignedM));
  t.equal(direct.nameIdFormatFor({ nameIdFormat: '' }, spM), F_EMAIL,
          'with no Format asked for, the default comes from the declared ' +
          'formats when the setting\'s value is not among them');
  withSettings(config, { 'saml2.signAssertion': false }, function () {
    t.equal(direct.signsAssertionFor(spM), false,
            'WantAssertionsSigned in DEVELOPMENT: the setting (off) is ' +
            'honoured — it is the test case');
    t.equal(withSettings(config, { 'global.mode': 'product' }, function () {
      return direct.signsAssertionFor(spM);
    }), true, 'WantAssertionsSigned in PRODUCT: the assertion is signed ' +
              'anyway');
    t.equal(withSettings(config, { 'global.mode': 'product' }, function () {
      return direct.signsAssertionFor(spU);
    }), false, 'and a service provider that did not ask gets the setting');
  });

  // -------------------------------------------------------------------------
  t.log.info('I. Single Logout');
  // -------------------------------------------------------------------------
  const getSlo = function (raw) {
    log.debug("Entering getSlo().");
    const res = fakeRes();
    slo(fakeReq('GET', '/saml2/slo', queryObject(raw), raw), res);
    log.debug("Leaving getSlo().");
    return res;
  };
  const signedLogout = redirectQuery(stsCrypto, logoutRequest(spM, '_i1'),
                                     'lo', keyA.privateKeyPem);
  const okLogout = getSlo(signedLogout);
  t.check(okLogout.statusCode === 303 &&
          okLogout.location.indexOf(base + '/slo-response?') === 0,
          'a signed LogoutRequest is verified and answered at the consumed ' +
          'SingleLogoutService ResponseLocation, on the Redirect binding it ' +
          'arrived on', okLogout.statusCode + ' ' + okLogout.location);
  if (okLogout.location) {
    t.check(/LogoutResponse/.test(
              inflateParam(okLogout.location, 'SAMLResponse')),
            'and what goes there is a LogoutResponse');
  }
  const tamperedLogout = getSlo(signedLogout.replace('RelayState=lo',
                                                     'RelayState=LO'));
  t.check(tamperedLogout.statusCode === 403 &&
          codeOf(tamperedLogout) === 'STS-SAML-0061' &&
          /NOT ended/.test(tamperedLogout.body),
          'a LogoutRequest tampered with after signing is REFUSED and ends ' +
          'no session', tamperedLogout.statusCode + ' ' +
          codeOf(tamperedLogout));
  const unsignedLogout = getSlo(redirectQuery(stsCrypto,
    logoutRequest(spM, '_i2'), 'lo'));
  t.check(unsignedLogout.statusCode === 403 &&
          codeOf(unsignedLogout) === 'STS-SAML-0063',
          'an UNSIGNED LogoutRequest from a service provider that must sign ' +
          'is refused', unsignedLogout.statusCode + ' ' +
          codeOf(unsignedLogout));
  const unsignedLogoutDev = getSlo(redirectQuery(stsCrypto,
    logoutRequest(spU, '_i3'), 'lo'));
  t.check(unsignedLogoutDev.statusCode !== 403,
          'development: an unsigned LogoutRequest from a service provider ' +
          'that need not sign is still answered',
          String(unsignedLogoutDev.statusCode));
  const signedResponse = redirectQuery(stsCrypto,
    '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
    NS_SAML + '" ID="_i4" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>' + spM + '</saml:Issuer>' +
    '<samlp:Status><samlp:StatusCode ' +
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    '</samlp:LogoutResponse>', 'r', keyB.privateKeyPem, RSA_SHA256,
    'SAMLResponse');
  const badResponse = getSlo(signedResponse);
  t.check(badResponse.statusCode === 403 &&
          codeOf(badResponse) === 'STS-SAML-0061',
          'a LogoutResponse signed by the wrong key is refused too',
          badResponse.statusCode + ' ' + codeOf(badResponse));

  // -------------------------------------------------------------------------
  t.log.info('J. the console and API actions');
  // -------------------------------------------------------------------------
  const spJ = newSp('actions', []);
  const junk = adminActions.saml2Action({ action: 'set-signing-certificate',
                                          sp: spJ, value: 'MIIBnotacert' });
  t.check(!junk.ok && errorCodes.codeOf(junk) === 'STS-REG-0160',
          'a value that is not a certificate is refused, STS-REG-0160',
          JSON.stringify(junk.errors));
  const pem = adminActions.saml2Action({ action: 'set-signing-certificate',
                                         sp: spJ, value: keyA.certPem });
  t.check(pem.ok && pem.changed &&
          [].concat(fieldsOf(spJ).samlSigningCertificate).join() ===
            keyA.certB64,
          'a PEM is registered as base64 DER',
          JSON.stringify(pem.errors || ''));
  adminActions.saml2Action({ action: 'set-signing-certificate', sp: spJ,
                             value: keyB.certB64 });
  t.equal([].concat(fieldsOf(spJ).samlSigningCertificate).join(),
          keyB.certB64, 'set REPLACES the list');
  const removed = adminActions.saml2Action({
    action: 'remove-signing-certificate', sp: spJ, value: keyB.certPem });
  t.check(removed.ok && !fieldsOf(spJ).samlSigningCertificate,
          'remove takes one off, by value (a PEM is normalised)');
  const unknown = adminActions.saml2Action({ action: 'nope', sp: spJ });
  t.check(/The nine are: .*upload-metadata/.test(unknown.errors.join(' ')),
          'an unknown action names all nine', unknown.errors.join(' '));
  t.check(/verifyQueryString/.test(String(stsCrypto.verifyQueryString)) ||
          typeof stsCrypto.verifyQueryString === 'function',
          'the detached verifier lives in common/crypto.js');
  const noCert = stsCrypto.verifyQueryString('a=b', { signature: 'AA==',
                                                      sigAlg: RSA_SHA256 });
  t.check(!noCert.ok && errorCodes.codeOf(noCert) === 'STS-KEYS-0060',
          'and refuses to verify without a certificate');
  t.check(helpers.STS.certB64 && direct.implicitCertificatesFor(
            'https://idp.test', 'https://idp.test/saml2/sp')[0] ===
          helpers.STS.certB64 &&
          !direct.implicitCertificatesFor('https://idp.test',
                                          'https://other.test/saml2/sp')
            .length,
          'this service\'s own key is trusted for its own mock service ' +
          'provider and for nobody else');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_request_signatures',
  describe: 'SAML 2.0 request signatures verified against registered ' +
            'certificates, observed KeyInfo certificates, the signing ' +
            'requirement, and SP metadata consumed and used (#37)',
  run: run
};
