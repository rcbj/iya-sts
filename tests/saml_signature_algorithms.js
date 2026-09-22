'use strict';
//
// File: saml_signature_algorithms.js
//
// ===========================================================================
// EVERY XML SIGNATURE ALGORITHM THE SERVICE VERIFIES IS VERIFIED, ON EVERY
// PATH, AND SHA-1 IS A SETTING (2026-09-17, #37 follow-up).
//
// Until the follow-up a SAML signature had to be RSA: the vendored engine
// implements RSA and nothing injected a verifier for anything else, so an EC
// certificate could not even be registered. `common/crypto.js` section 1a now
// verifies RSA (PKCS#1 v1.5 and PSS), ECDSA, EdDSA, DSA, ML-DSA and SLH-DSA,
// and refuses SHA-1 unless `saml.allowSha1Signatures` is on. The claims:
//
//   1. for each family — a service provider's AuthnRequest on the POST
//      binding (enveloped) and on the Redirect binding (detached) is
//      VERIFIED with a certificate of that family registered, and a tampered
//      one is refused (STS-SAML-0061); a LogoutRequest and a LogoutResponse
//      likewise for a subset; a metadata document signed with that key
//      verifies against samlSpMetadataSigningCertificate and a tampered one
//      is refused; the certificate is REGISTERED by the console action and
//      CONSUMED from a metadata KeyDescriptor;
//   2. SHA-1 — as the SignatureMethod and as a DigestMethod — is refused by
//      default (STS-SAML-0073 on a request, STS-SAML-0065 on metadata,
//      STS-KEYS-0062 underneath), and with the setting on it verifies and is
//      recorded `weak`; the setting defaults to false in BOTH modes;
//   A. the same verifier on the other paths: a federation partner's
//      assertion (/federation/acs) and an RFC 7522 assertion — EC, EdDSA and
//      ML-DSA accepted, SHA-1 refused then accepted — and the paths whose
//      anchor is THIS service's own RSA key (WS-Trust, WS-Federation,
//      SAML 1.1, GNAP), where SHA-1 is refused then accepted;
//   and the algorithms nothing verifies (MD5, HMAC, HSS/LMS) are refused by
//   name as not checkable, never as a wrong signature.
//
// WHY IN PROCESS: a signature in every family needs keys the test holds and
// settings changed mid-run; the handlers are called off the router.
// ===========================================================================

delete process.env.CONFIG_FILE;

const zlib = require('zlib');
const nodeCrypto = require('crypto');
const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_signature_algorithms',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const U = kit.URIS;

function authnRequest(issuer, id) {
  log.debug("Entering authnRequest().");
  log.debug("Leaving authnRequest().");
  return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '">' +
    '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
}

function logoutRequest(issuer, id) {
  log.debug("Entering logoutRequest().");
  log.debug("Leaving logoutRequest().");
  return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '">' +
    '<saml:Issuer>' + issuer + '</saml:Issuer>' +
    '<saml:NameID>alice</saml:NameID></samlp:LogoutRequest>';
}

function logoutResponse(issuer, id) {
  log.debug("Entering logoutResponse().");
  log.debug("Leaving logoutResponse().");
  return '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '">' +
    '<saml:Issuer>' + issuer + '</saml:Issuer><samlp:Status>' +
    '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>' +
    '</samlp:Status></samlp:LogoutResponse>';
}

function metadataFor(entityId, signingB64) {
  log.debug("Entering metadataFor().");
  log.debug("Leaving metadataFor().");
  return '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="_md' +
    Date.now() + '" entityID="' + entityId + '">' +
    '<md:SPSSODescriptor protocolSupportEnumeration="' + NS_SAMLP + '">' +
    (signingB64
      ? '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="' + U.DS +
        '"><ds:X509Data><ds:X509Certificate>' + signingB64 +
        '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
      : '') +
    '<md:AssertionConsumerService ' +
    'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ' +
    'Location="https://sp.test/acs" index="0"/>' +
    '</md:SPSSODescriptor></md:EntityDescriptor>';
}

// The Redirect binding's query, signed with `key` (the kit's value).
function redirectQuery(xml, key, field, relayState) {
  log.debug("Entering redirectQuery().");
  let q = (field || 'SAMLRequest') + '=' + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64'));
  if (relayState !== undefined) {
    q += '&RelayState=' + encodeURIComponent(relayState);
  }
  if (key) {
    q += '&SigAlg=' + encodeURIComponent(key.uri);
    q += '&Signature=' + encodeURIComponent(
      kit.signatureValue(key, Buffer.from(q, 'utf8')).toString('base64'));
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

// A SAML 2.0 assertion with a Subject and an audience, for the other paths.
function assertionXml(issuer, audience, id) {
  log.debug("Entering assertionXml().");
  const now = Date.now();
  const iso = function (ms) {
    log.debug("Entering iso().");
    log.debug("Leaving iso().");
    return new Date(now + ms).toISOString().replace(/\.\d+Z$/, 'Z');
  };
  log.debug("Leaving assertionXml().");
  return '<saml:Assertion xmlns:saml="' + NS_SAML + '" ID="' + id + '" ' +
    'Version="2.0" IssueInstant="' + iso(0) + '"><saml:Issuer>' + issuer +
    '</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID>' +
    '<saml:SubjectConfirmation ' +
    'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    '<saml:SubjectConfirmationData NotOnOrAfter="' + iso(120000) + '" ' +
    'Recipient="' + audience + '"/></saml:SubjectConfirmation>' +
    '</saml:Subject><saml:Conditions NotBefore="' + iso(-60000) + '" ' +
    'NotOnOrAfter="' + iso(120000) + '"><saml:AudienceRestriction>' +
    '<saml:Audience>' + audience + '</saml:Audience>' +
    '</saml:AudienceRestriction></saml:Conditions>' +
    '<saml:AuthnStatement AuthnInstant="' + iso(0) + '">' +
    '<saml:AuthnContext><saml:AuthnContextClassRef>' +
    'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified' +
    '</saml:AuthnContextClassRef></saml:AuthnContext>' +
    '</saml:AuthnStatement></saml:Assertion>';
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const app = require('../common/app');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const saml2sso = require('../saml/saml2_sso');
  const spMetadata = require('../saml/sp_metadata');
  const adminActions = require('../admin-core/admin_actions');
  saml2sso.registerRoutes(app);
  const sso = kit.handlerFor(app, 'get', '/saml2/sso');
  const ssoPost = kit.handlerFor(app, 'post', '/saml2/sso');
  const slo = kit.handlerFor(app, 'get', '/saml2/slo');
  const stamp = String(Date.now());
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
  const fieldsOf = function (id) {
    log.debug("Entering fieldsOf().");
    log.debug("Leaving fieldsOf().");
    return (applications.get(id) || {}).fields || {};
  };
  const newSp = function (name) {
    log.debug("Entering newSp().");
    const id = 'https://' + name + '-' + stamp + '.alg.test/saml';
    const made = applications.createApplication({
      identifier: id, kind: 'saml2-service-provider', protocol: 'SAML 2.0',
      fields: { samlEntityId: id } });
    t.check(made.ok, 'created ' + name, JSON.stringify(made.errors || ''));
    log.debug("Leaving newSp().");
    return id;
  };
  const getSso = function (raw) {
    log.debug("Entering getSso().");
    const res = kit.fakeRes();
    sso(kit.fakeReq('GET', '/saml2/sso', queryObject(raw), raw), res);
    log.debug("Leaving getSso().");
    return res;
  };
  const getSlo = function (raw) {
    log.debug("Entering getSlo().");
    const res = kit.fakeRes();
    slo(kit.fakeReq('GET', '/saml2/slo', queryObject(raw), raw), res);
    log.debug("Leaving getSlo().");
    return res;
  };
  const postSso = function (xml) {
    log.debug("Entering postSso().");
    const res = kit.fakeRes();
    const b64 = Buffer.from(xml, 'utf8').toString('base64');
    ssoPost(kit.fakeReq('POST', '/saml2/sso', {}, '',
                        'SAMLRequest=' + encodeURIComponent(b64)), res);
    if (res.statusCode === 303 && /\?rid=/.test(res.location)) {
      const rid = res.location.split('?rid=')[1];
      const next = kit.fakeRes();
      sso(kit.fakeReq('GET', '/saml2/sso', { rid: decodeURIComponent(rid) },
                      'rid=' + rid), next);
      log.debug("Leaving postSso(). Followed the hold.");
      return next;
    }
    log.debug("Leaving postSso().");
    return res;
  };
  const verification = function (id) {
    log.debug("Entering verification().");
    log.debug("Leaving verification().");
    return String(fieldsOf(id).samlAuthnRequestVerification || '');
  };

  // -------------------------------------------------------------------------
  t.log.info('0. the table');
  // -------------------------------------------------------------------------
  const table = stsCrypto.xmlSignatureAlgorithms();
  const verified = table.verified.map(function (row) {
    return row.uri;
  });
  kit.FAMILIES.forEach(function (row) {
    t.check(verified.indexOf(row[1]) >= 0,
            'section 1a VERIFIES ' + row[0], row[1]);
  });
  ['rsa-md5', 'hmac-md5'].forEach(function (name) {
    t.check(verified.indexOf(U.MORE + name) < 0 &&
            table.refused.some(function (r) {
              return r.uri === U.MORE + name;
            }), name + ' is refused BY NAME, not verified');
  });
  t.check(table.refused.some(function (r) {
    return /hss-lms/.test(r.uri) && /stateful/.test(r.why);
  }), 'HSS/LMS is named as not verifiable, with the reason');
  t.check(stsCrypto.xmldsig.SIG_METHODS[U.MORE21 + 'eddsa-ed25519'] &&
          stsCrypto.xmldsig.DIGEST_METHODS[U.MORE + 'sha224'],
          'the new rows are REGISTERED into the vendored tables (additive)');
  t.equal(stsCrypto.xmldsig.SIG_METHODS[U.DS + 'rsa-sha1'].label,
          'RSA-SHA1 (insecure)',
          'and a row the vendored table already had is untouched');
  t.equal(config.value('saml.allowSha1Signatures'), false,
          'saml.allowSha1Signatures defaults to FALSE');
  t.equal(kit.withSettings(config, { 'global.mode': 'product' },
    function () { return config.value('saml.allowSha1Signatures'); }),
    false, 'and to false in product mode too');

  // -------------------------------------------------------------------------
  t.log.info('1. every family, on every surface #37 verifies');
  // -------------------------------------------------------------------------
  const keys = {};
  for (let i = 0; i < kit.FAMILIES.length; i++) {
    const row = kit.FAMILIES[i];
    let key;
    try {
      key = kit.keyFor(row);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      t.check(false, 'this runtime generates a ' + row[0] + ' key',
              e.message);
      continue;
    }
    keys[row[0]] = key;
    const sp = newSp('fam-' + row[0].replace(/[^a-z0-9]/g, ''));
    const registered = adminActions.saml2Action({
      action: 'set-signing-certificate', sp: sp, value: key.cert.pem });
    t.check(registered.ok, row[0] + ': the certificate is REGISTERED',
            JSON.stringify(registered.errors || ''));

    const post = postSso(kit.signEnveloped(stsCrypto,
      authnRequest(sp, '_p' + i), key));
    t.check(toSignIn(post) && /^verified post /.test(verification(sp)),
            row[0] + ': a POST-binding AuthnRequest is VERIFIED',
            post.statusCode + ' ' + codeOf(post) + ' ' + verification(sp));
    const tampered = kit.signEnveloped(stsCrypto,
      authnRequest(sp, '_q' + i), key).replace('Version="2.0"',
                                                'Version="2.0" ' +
                                                'IsPassive="false"');
    const badPost = postSso(tampered);
    t.check(badPost.statusCode === 403 &&
            codeOf(badPost) === 'STS-SAML-0061',
            row[0] + ': a tampered POST request is REFUSED, STS-SAML-0061',
            badPost.statusCode + ' ' + codeOf(badPost));

    const raw = redirectQuery(authnRequest(sp, '_r' + i), key, 'SAMLRequest',
                              'rs-' + i);
    const redirect = getSso(raw);
    t.check(toSignIn(redirect) &&
            verification(sp).indexOf('verified redirect ' + row[1]) === 0,
            row[0] + ': a Redirect-binding AuthnRequest is VERIFIED',
            redirect.statusCode + ' ' + codeOf(redirect) + ' ' +
            verification(sp));
    const badRedirect = getSso(raw.replace('RelayState=rs-' + i,
                                           'RelayState=rX-' + i));
    t.check(badRedirect.statusCode === 403 &&
            codeOf(badRedirect) === 'STS-SAML-0061',
            row[0] + ': a tampered Redirect request is REFUSED',
            badRedirect.statusCode + ' ' + codeOf(badRedirect));

    // The metadata document, signed with this key.
    const anchored = newSp('md-' + row[0].replace(/[^a-z0-9]/g, ''));
    const anchor = adminActions.saml2Action({
      action: 'set-metadata-signing-certificate', sp: anchored,
      value: key.cert.b64 });
    t.check(anchor.ok, row[0] + ': the metadata signing certificate is set',
            JSON.stringify(anchor.errors || ''));
    const document = kit.signEnveloped(stsCrypto,
      metadataFor(anchored, key.cert.b64), key);
    const bad = spMetadata.upload(anchored,
      document.replace('https://sp.test/acs', 'https://evil.test/acs'));
    t.check(!bad.ok, row[0] + ': a tampered signed metadata document is ' +
            'REFUSED', JSON.stringify(bad.errors || ''));
    const good = spMetadata.upload(anchored, document);
    t.check(good.ok &&
            fieldsOf(anchored).samlSpMetadataSignature === 'verified',
            row[0] + ': a metadata document signed with it is VERIFIED',
            JSON.stringify(good.errors || ''));
    t.check([].concat(fieldsOf(anchored).samlSigningCertificate || [])
              .indexOf(key.cert.b64) >= 0,
            row[0] + ': and its KeyDescriptor certificate is CONSUMED as a ' +
            'registered signing certificate');
  }

  // Single Logout, for a subset.
  ['ecdsa-p384-sha384', 'ed25519', 'ml-dsa-44'].forEach(function (name, i) {
    const key = keys[name];
    if (!key) {
      return;
    }
    const sp = newSp('slo-' + name.replace(/[^a-z0-9]/g, ''));
    adminActions.saml2Action({ action: 'set-signing-certificate', sp: sp,
                               value: key.cert.b64 });
    applications.updateApplication(sp, {
      attribute: 'samlSingleLogoutService', mode: 'add',
      value: 'https://sp.test/slo' });
    const raw = redirectQuery(logoutRequest(sp, '_l' + i), key,
                              'SAMLRequest', 'lo');
    const ok = getSlo(raw);
    t.check(ok.statusCode !== 403,
            name + ': a signed LogoutRequest is ACCEPTED',
            ok.statusCode + ' ' + codeOf(ok));
    const bad = getSlo(raw.replace('RelayState=lo', 'RelayState=LO'));
    t.check(bad.statusCode === 403 && codeOf(bad) === 'STS-SAML-0061' &&
            /NOT ended/.test(bad.body),
            name + ': a tampered LogoutRequest is REFUSED and ends nothing',
            bad.statusCode + ' ' + codeOf(bad));
    const answered = getSlo(redirectQuery(logoutResponse(sp, '_m' + i), key,
                                          'SAMLResponse'));
    t.check(answered.statusCode === 200 && /verified/.test(answered.body),
            name + ': a signed LogoutResponse is VERIFIED',
            answered.statusCode + ' ' + codeOf(answered));
    const wrong = getSlo(redirectQuery(logoutResponse(sp, '_n' + i),
                                       keys['rsa-sha256'], 'SAMLResponse'));
    t.check(wrong.statusCode === 403 && codeOf(wrong) === 'STS-SAML-0061',
            name + ': a LogoutResponse signed by another key is REFUSED',
            wrong.statusCode + ' ' + codeOf(wrong));
  });

  // Refused by name.
  const md5Sp = newSp('md5');
  adminActions.saml2Action({ action: 'set-signing-certificate', sp: md5Sp,
                             value: keys['rsa-sha256'].cert.b64 });
  const md5Key = Object.assign({}, keys['rsa-sha256'],
                               { uri: U.MORE + 'rsa-md5' });
  const md5 = getSso(redirectQuery(authnRequest(md5Sp, '_md5'), md5Key));
  t.check(md5.statusCode === 403 && codeOf(md5) === 'STS-SAML-0062',
          'RSA-MD5 cannot be checked and is REFUSED, STS-SAML-0062',
          md5.statusCode + ' ' + codeOf(md5));
  const hmacVerdict = stsCrypto.verifyQueryString('a=b', {
    signature: 'AAAA', sigAlg: U.MORE + 'hmac-sha256',
    certPem: keys['rsa-sha256'].cert.pem });
  t.check(!hmacVerdict.ok && !hmacVerdict.usable &&
          errorCodes.codeOf(hmacVerdict) === 'STS-KEYS-0061',
          'an HMAC SigAlg is not checkable (STS-KEYS-0061), not wrong',
          hmacVerdict.why);
  const lmsVerdict = stsCrypto.xmlAlgorithmVerdict(
    stsCrypto.xmldsig.HSS_LMS_URI, []);
  t.check(lmsVerdict.code === 'STS-KEYS-0061' &&
          /stateful/.test(lmsVerdict.problem),
          'an HSS/LMS signature is refused as not checkable, with the reason',
          lmsVerdict.problem);

  // Registration refuses what signs nothing verifiable.
  const x25519 = nodeCrypto.generateKeyPairSync('x25519');
  const kemCert = kit.certificateFor(x25519.publicKey, 'x25519');
  const junk = adminActions.saml2Action({ action: 'set-signing-certificate',
    sp: md5Sp, value: kemCert.b64 });
  t.check(!junk.ok && errorCodes.codeOf(junk) === 'STS-REG-0160',
          'an X25519 certificate (a key that signs nothing) is refused at ' +
          'registration, STS-REG-0160', JSON.stringify(junk.errors));

  // -------------------------------------------------------------------------
  t.log.info('2. SHA-1 is a setting, off by default');
  // -------------------------------------------------------------------------
  const sha1Rsa = kit.keyFor(['sha1-rsa'].concat(kit.SHA1.rsa));
  const sha1Ec = kit.keyFor(['sha1-ec'].concat(kit.SHA1.ecdsa));
  const shaSp = newSp('sha1');
  applications.updateApplication(shaSp, { attribute: 'samlSigningCertificate',
    mode: 'add', value: sha1Rsa.cert.b64 });
  applications.updateApplication(shaSp, { attribute: 'samlSigningCertificate',
    mode: 'add', value: sha1Ec.cert.b64 });
  const sha256Rsa = Object.assign({}, sha1Rsa, {
    uri: U.MORE + 'rsa-sha256', how: { hash: 'sha256' } });
  [['RSA-SHA1 SignatureMethod on POST', function (id) {
    return postSso(kit.signEnveloped(stsCrypto, authnRequest(shaSp, id),
                                     sha1Rsa));
  }], ['ECDSA-SHA1 SignatureMethod on Redirect', function (id) {
    return getSso(redirectQuery(authnRequest(shaSp, id), sha1Ec));
  }], ['a SHA-1 DigestMethod under RSA-SHA256', function (id) {
    return postSso(kit.signEnveloped(stsCrypto, authnRequest(shaSp, id),
                                     sha256Rsa,
                                     { digestUri: kit.SHA1.digest }));
  }]].forEach(function (pair, i) {
    const off = pair[1]('_s' + i);
    t.check(off.statusCode === 403 && codeOf(off) === 'STS-SAML-0073',
            pair[0] + ': REFUSED by default, STS-SAML-0073',
            off.statusCode + ' ' + codeOf(off));
    const on = kit.withSettings(config, { 'saml.allowSha1Signatures': true },
      function () {
        return pair[1]('_t' + i);
      });
    t.check(toSignIn(on) && /^verified .* weak$/.test(verification(shaSp)),
            pair[0] + ': with the setting ON it is verified and recorded ' +
            'WEAK', on.statusCode + ' ' + codeOf(on) + ' ' +
            verification(shaSp));
  });
  const prodSha1 = kit.withSettings(config, { 'global.mode': 'product' },
    function () {
      return getSso(redirectQuery(authnRequest(shaSp, '_u1'), sha1Ec));
    });
  t.check(prodSha1.statusCode === 403 && codeOf(prodSha1) === 'STS-SAML-0073',
          'and in PRODUCT mode by default too',
          prodSha1.statusCode + ' ' + codeOf(prodSha1));
  const lowLevel = stsCrypto.verifyXmlSignature(
    kit.signEnveloped(stsCrypto, authnRequest(shaSp, '_v1'), sha1Rsa),
    { element: 'AuthnRequest', certPem: sha1Rsa.cert.pem });
  t.check(!lowLevel.ok && errorCodes.codeOf(lowLevel) === 'STS-KEYS-0062' &&
          lowLevel.sha1 && lowLevel.weak,
          'underneath, the verifier says STS-KEYS-0062 and marks it sha1 and ' +
          'weak', lowLevel.why);

  // Metadata signed with SHA-1.
  const shaMd = newSp('sha1-md');
  adminActions.saml2Action({ action: 'set-metadata-signing-certificate',
                             sp: shaMd, value: sha1Rsa.cert.b64 });
  const shaDoc = kit.signEnveloped(stsCrypto, metadataFor(shaMd), sha1Rsa);
  const mdOff = spMetadata.upload(shaMd, shaDoc);
  t.check(!mdOff.ok && /saml\.allowSha1Signatures/.test(
            (mdOff.errors || []).join(' ')),
          'a SHA-1-signed METADATA document is refused by default, naming ' +
          'the setting', JSON.stringify(mdOff.errors));
  const mdOn = kit.withSettings(config, { 'saml.allowSha1Signatures': true },
    function () {
      return spMetadata.upload(shaMd, shaDoc);
    });
  t.check(mdOn.ok && fieldsOf(shaMd).samlSpMetadataSignature === 'verified',
          'and consumed as verified with the setting on',
          JSON.stringify(mdOn.errors || ''));

  // -------------------------------------------------------------------------
  t.log.info('A. the other paths share the verifier');
  // -------------------------------------------------------------------------
  // A federation partner's assertion (/federation/acs's verifier).
  const federationSp = require('../federation/federation_sp');
  const fedSp = new federationSp.FederationSp(
    federationSp.FederationSp.defaultDeps());
  ['ecdsa-p256-sha256', 'ed448', 'ml-dsa-87', 'slh-dsa-sha2-128f']
    .forEach(function (name, i) {
      const key = keys[name];
      if (!key) {
        return;
      }
      const record = { fedSigningCertificate: key.cert.b64 };
      const signed = kit.signEnveloped(stsCrypto,
        assertionXml('https://partner.test', 'https://sp.test', '_f' + i),
        key);
      const ok = fedSp.verifyXmlSignature(signed, record, 'Assertion');
      t.check(ok.ok, 'federation ACS: a ' + name + ' assertion VERIFIES',
              ok.why);
      const bad = fedSp.verifyXmlSignature(signed.replace('alice', 'mallory'),
                                           record, 'Assertion');
      t.check(!bad.ok, 'federation ACS: a tampered ' + name +
              ' assertion is refused', bad.why);
    });
  const fedRecord = { fedSigningCertificate: sha1Rsa.cert.b64 };
  const fedSha1 = kit.signEnveloped(stsCrypto,
    assertionXml('https://partner.test', 'https://sp.test', '_fs'), sha1Rsa);
  const fedOff = fedSp.verifyXmlSignature(fedSha1, fedRecord, 'Assertion');
  t.check(!fedOff.ok && /saml\.allowSha1Signatures/.test(fedOff.why),
          'federation ACS: SHA-1 REFUSED by default', fedOff.why);
  const fedOn = kit.withSettings(config, { 'saml.allowSha1Signatures': true },
    function () {
      return fedSp.verifyXmlSignature(fedSha1, fedRecord, 'Assertion');
    });
  t.check(fedOn.ok, 'federation ACS: SHA-1 accepted with the setting on',
          fedOn.why);

  // RFC 7522: an assertion signed with a registered EC, Ed25519 or ML-DSA
  // certificate this realm's CA issued (its chain has to hold).
  const pki = require('../common/pki');
  const grant = require('../oauth-oidc/saml_assertion_grant');
  const AUD = 'https://sts.example.test/oauth2/token';
  const keyMaterial = require('../common/vendored/key_material.js');
  const mlDsaId = keyMaterial.POST_QUANTUM_KEY_ALG_ORDER.filter(function (id) {
    return /ml-?dsa/i.test(id) && !/composite|ed25519|ed448|rsa|p256|p384/i
      .test(id);
  })[0];
  t.check(!!mlDsaId, 'the key registry names a pure ML-DSA key algorithm',
          keyMaterial.POST_QUANTUM_KEY_ALG_ORDER.join(', '));
  // THE REALM NEEDS A HIERARCHY TO ISSUE FROM, and what is built here goes
  // again at the end — `tests/saml_assertion_grant.js`'s arrangement.
  const built = await pki.buildChain(undefined, { organisation: 'Test' });
  t.check(built.ok, 'RFC 7522: a hierarchy for this realm',
          (built.errors || []).join(' '));
  const grantKeys = ['ec-p256', 'ed25519'].concat(mlDsaId ? [mlDsaId] : []);
  let pqDone = false;
  for (let i = 0; i < grantKeys.length; i++) {
    const keyAlg = grantKeys[i];
    const pair = await pki.issueSigningKeyPair(undefined, {
      identifier: 'rfc7522-' + keyAlg, purpose: 'saml', keyAlg: keyAlg });
    if (!pair.ok) {
      t.check(false, 'RFC 7522: a ' + keyAlg + ' key pair is issued',
              (pair.errors || []).join(' '));
      continue;
    }
    const privateKey = nodeCrypto.createPrivateKey(pair.issued.privateKeyPem);
    const type = privateKey.asymmetricKeyType;
    const uri = type === 'ec' ? U.MORE + 'ecdsa-sha256'
      : (type === 'ed25519' ? U.MORE21 + 'eddsa-ed25519'
                            : U.PQ + String(type));
    if (/^ml-dsa/.test(type)) {
      pqDone = true;
    }
    const key = { name: keyAlg, uri: uri, privateKey: privateKey,
                  how: type === 'ec' ? { hash: 'sha256', p1363: true }
                                     : { oneShot: true },
                  cert: { pem: pair.issued.certificatePem } };
    const signed = kit.signEnveloped(stsCrypto,
      assertionXml('https://issuer.test/saml', AUD, '_g' + i), key,
      { keyInfo: false });
    const verdict = await grant.verify({
      assertion: Buffer.from(signed, 'utf8').toString('base64url'),
      clientId: 'alice', registeredCertificate: pair.issued.certificatePem,
      audiences: [AUD] });
    t.check(verdict.ok, 'RFC 7522: an assertion signed with a registered ' +
            type + ' certificate is ACCEPTED', verdict.description);
    const tampered = await grant.verify({
      assertion: Buffer.from(signed.replace('alice', 'mallory'), 'utf8')
        .toString('base64url'),
      clientId: 'alice', registeredCertificate: pair.issued.certificatePem,
      audiences: [AUD] });
    t.check(!tampered.ok && tampered.errorCode === 'STS-OAUTH-0067',
            'RFC 7522: and a tampered one is REFUSED, STS-OAUTH-0067',
            tampered.errorCode + ' ' + tampered.description);
  }
  t.check(pqDone, 'RFC 7522: a post-quantum (ML-DSA) key pair was among ' +
          'those tried');
  const rsaPair = await pki.issueSigningKeyPair(undefined, {
    identifier: 'rfc7522-sha1', purpose: 'saml' });
  const rsaKey = { name: 'rsa-sha1', uri: kit.SHA1.rsa[0],
    privateKey: nodeCrypto.createPrivateKey(rsaPair.issued.privateKeyPem),
    how: { hash: 'sha1' }, cert: { pem: rsaPair.issued.certificatePem } };
  const grantSha1 = function (id) {
    log.debug("Entering grantSha1().");
    log.debug("Leaving grantSha1().");
    return grant.verify({
      assertion: Buffer.from(kit.signEnveloped(stsCrypto,
        assertionXml('https://issuer.test/saml', AUD, id), rsaKey,
        { keyInfo: false, digestUri: kit.SHA1.digest }), 'utf8')
        .toString('base64url'),
      clientId: 'alice', registeredCertificate: rsaPair.issued.certificatePem,
      audiences: [AUD] });
  };
  const grantOff = await grantSha1('_h1');
  t.check(!grantOff.ok && /saml\.allowSha1Signatures/.test(
            grantOff.description),
          'RFC 7522: SHA-1 REFUSED by default', grantOff.description);
  const grantOn = await kit.withSettings(config,
    { 'saml.allowSha1Signatures': true },
    function () {
      return grantSha1('_h2');
    });
  t.check(grantOn.ok, 'RFC 7522: SHA-1 accepted with the setting on',
          grantOn.description);
  pki.clearChain(undefined);

  // The paths whose anchor is THIS service's own key. The key is RSA, so an
  // EC signature cannot be the anchor's; what they share is the SHA-1 rule.
  const STS = helpers.STS;
  const ownSha1 = function (xml) {
    log.debug("Entering ownSha1().");
    log.debug("Leaving ownSha1().");
    return stsCrypto.signXml(xml, {
      privateKeyPem: STS.xml.privateKeyPem, certPem: STS.xml.certPem,
      sigAlg: kit.SHA1.rsa[0], what: 'a SHA-1 test document' });
  };
  const own = ownSha1(assertionXml(
    'https://idp.test', 'https://rp.test', '_o1'));
  const wsfed = require('../ws-federation/wsfed');
  const wstrust = require('../ws-trust/wstrust');
  const saml11sso = require('../saml/saml11_sso');
  const s11 = new saml11sso.Saml11Sso(saml11sso.Saml11Sso.defaultDeps());
  const gnapSubject = require('../gnap/gnap_subject');
  const gnap = new gnapSubject.GnapSubject(
    gnapSubject.GnapSubject.defaultDeps());
  const xmldom = require('@xmldom/xmldom');
  const ownPaths = [
    ['WS-Federation', function () {
      return wsfed.verifyAssertionSignature(own, 'Assertion').ok;
    }],
    ['WS-Trust', function () {
      const element = new xmldom.DOMParser()
        .parseFromString(own, 'text/xml').documentElement;
      const checked = wstrust.checkedAssertion(element, 'test token');
      if (checked.ok) {
        return true;
      }
      // Refused FOR SHA-1 is `false`; refused for anything else is a
      // sentence, which fails both assertions below and says why.
      return /saml\.allowSha1Signatures/.test(String(checked.reason || ''))
        ? false : 'refused otherwise: ' + checked.reason;
    }],
    ['SAML 1.1', function () {
      return s11.verifySignature(own, 'Assertion').ok;
    }],
    ['GNAP', function () {
      return gnap.usernameFromAssertion({ format: 'saml2',
        value: Buffer.from(own, 'utf8').toString('base64url') }, {}).ok;
    }]
  ];
  ownPaths.forEach(function (path) {
    t.equal(path[1](), false, path[0] + ': a SHA-1 signature by this ' +
            'service\'s own key is REFUSED by default');
    t.equal(kit.withSettings(config, { 'saml.allowSha1Signatures': true },
      path[1]), true, path[0] + ': and ACCEPTED with the setting on');
  });
  const ownSha256 = stsCrypto.signXml(assertionXml(
    'https://idp.test', 'https://rp.test', '_o2'), {
    privateKeyPem: STS.xml.privateKeyPem, certPem: STS.xml.certPem,
    what: 'an ordinary test document' });
  t.check(wsfed.verifyAssertionSignature(ownSha256, 'Assertion').ok &&
          s11.verifySignature(ownSha256, 'Assertion').ok,
          'and the service\'s ordinary RSA-SHA256 signature still verifies ' +
          'on those paths');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_signature_algorithms',
  describe: 'every XML signature family (RSA, PSS, ECDSA, EdDSA, DSA, ' +
            'ML-DSA, SLH-DSA) verified on every SAML path, and SHA-1 behind ' +
            'saml.allowSha1Signatures (#37 follow-up)',
  run: run
};
