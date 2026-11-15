// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/wssec-vectors.js
//
// ---------------------------------------------------------------------------
// THE WS-SECURITY MESSAGE SIGNATURE (#521, #658), AS NODE READS, VERIFIES
// AND SIGNS IT (#444, phase 7, the `saml` slice): the vectors
// `rust/crates/sts-crypto/tests/wssec_vectors.rs` reads, run by
// `crypto-vectors.js` (`wssec-node.json`) in a child of its own.
//
//   signed    signWsSecurity() over fixed envelopes with one RSA key, in
//             the four RSA methods, with and without the Timestamp — RSA
//             PKCS#1 v1.5 is deterministic, so Rust must make the same
//             BYTES;
//   cases     an envelope and how it is asked about — `read`
//             (readWsSecuritySignature), `verify` (with a certificate) or
//             `hmac` (with a shared key) — and Node's whole answer, its
//             code included: every refusal the reading makes, the engine's
//             verdicts, the Kerberos HMAC, and the refusal that follows
//             from Node verifying a SERIALIZED copy of the signature (a
//             PrefixList prefix an ancestor declares);
//   policy    the XML signature policy the answers were given under.
//
// And `checkRust()`: the envelopes Rust signed (`wssec-rust.json`),
// verified by Node, and Rust's answers to its own cases given again by
// Node. A builder is a tool, not service code, and logs nothing.
// ---------------------------------------------------------------------------

const path = require('path');
const nodeCrypto = require('crypto');

const WSSE = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-secext-1.0.xsd';
const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-utility-1.0.xsd';
const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509v3';
const THUMBPRINT = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
const SKI = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
const BASE64 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const KRB = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-kerberos-token-profile-1.1#';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

function settingList(ROOT, key) {
  const raw = require(path.join(ROOT, 'common', 'config.js')).value(key);
  return (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) {
      return String(one).trim();
    })
    .filter(function (one) {
      return one.length > 0;
    });
}

// What sts_crypto::xmldsig::XmlPolicy carries (crypto-vectors.js's
// xmlPolicyNow(), for this file's own child).
function policyNow(ROOT) {
  const crypto = require(path.join(ROOT, 'common', 'crypto.js'));
  const mode = require(path.join(ROOT, 'common', 'mode.js'));
  const config = require(path.join(ROOT, 'common', 'config.js'));
  return {
    sha1Allowed: crypto.xmlSignatureAlgorithms().sha1Allowed,
    brokenAlgorithms: mode.usesBrokenAlgorithms(),
    signatureAlgorithms: settingList(ROOT, 'saml.signatureAlgorithms'),
    acceptedSignatureAlgorithms:
      settingList(ROOT, 'saml.acceptedSignatureAlgorithms'),
    acceptedDigestAlgorithms:
      settingList(ROOT, 'saml.acceptedDigestAlgorithms'),
    pqcOnly: config.value('keys.pqcOnly') === true,
    joseSigningAlgorithms: settingList(ROOT, 'keys.signingAlgorithms'),
    joseAcceptedAlgorithms:
      settingList(ROOT, 'keys.acceptedSigningAlgorithms'),
    omitsUnapprovedCurves: mode.omitsUnapprovedSigningCurves(),
    allowsLegacyHashes: mode.allowsLegacyHashes()
  };
}

// An RST, unsigned, with fixed instants and a fixed Context.
function envelope(opts) {
  const o = opts || {};
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '"><s:Header>' +
    (o.header || '') + '<wsse:Security>' +
    '<wsu:Timestamp wsu:Id="ts"><wsu:Created>2026-11-15T10:00:00.000Z' +
    '</wsu:Created><wsu:Expires>2026-11-15T10:05:00.000Z</wsu:Expires>' +
    '</wsu:Timestamp>' + (o.token || '') + (o.security || '') +
    '</wsse:Security></s:Header>' +
    '<s:Body wsu:Id="body">' +
    '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/' +
    'ws-sx/ws-trust/200512" Context="urn:uuid:5d1c1f86-8a5c-4c38-9e8d-' +
    '6a0b7d6c1a2e"><wst:RequestType>http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200512/Issue</wst:RequestType><!-- a comment -->' +
    (o.inner || '') + '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function b64OfPem(pem) {
  return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

function x509Token(certPem) {
  return '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="' + X509V3 +
    '" EncodingType="' + BASE64 + '">' + b64OfPem(certPem) +
    '</wsse:BinarySecurityToken>';
}

function strOf(inner) {
  return '<ds:KeyInfo><wsse:SecurityTokenReference>' + inner +
    '</wsse:SecurityTokenReference></ds:KeyInfo>';
}

// A JSON copy of an answer, and its code.
function answerOf(ROOT, v) {
  const code = require(path.join(ROOT, 'common', 'error_codes.js'))
    .codeOf(v) || null;
  return { answer: JSON.parse(JSON.stringify(v)), code: code };
}

function build(ROOT) {
  const crypto = require(path.join(ROOT, 'common', 'crypto.js'));
  const engine = require(path.join(ROOT, 'common', 'crypto_impl',
                                   'xmldsig.js'));
  const pki = require(path.join(ROOT, 'common', 'pki.js'));
  const rsa = engine.generateKeyPair(2048, 'WS-Security Signer');
  const other = engine.generateKeyPair(2048, 'Somebody Else');
  const x509 = new nodeCrypto.X509Certificate(rsa.certPem);
  const signed = [];
  const cases = [];

  // THE SIGNER: the same bytes, every RSA method, with and without the
  // Timestamp.
  [MORE + 'rsa-sha256', MORE + 'rsa-sha384', MORE + 'rsa-sha512',
   DS + 'rsa-sha1'].forEach(function (sigAlg) {
    [true, false].forEach(function (signTimestamp) {
      const input = envelope({ token: x509Token(rsa.certPem) });
      signed.push({ name: sigAlg.replace(/.*#/, '') +
                      (signTimestamp ? ' with the Timestamp' : ' Body only'),
                    input: input, sigAlg: sigAlg,
                    signTimestamp: signTimestamp,
                    signed: engine.signWsSecurity(input, {
                      privateKeyPem: rsa.privateKeyPem, certPem: rsa.certPem,
                      sigAlg: sigAlg, signTimestamp: signTimestamp }) });
    });
  });

  const sign = function (xml, opts) {
    return engine.signWsSecurity(xml, Object.assign({
      privateKeyPem: rsa.privateKeyPem, certPem: rsa.certPem,
      signTimestamp: true }, opts || {}));
  };
  const withKeyInfo = function (xml, keyInfo) {
    return xml.replace(/<ds:KeyInfo>[\s\S]*?<\/ds:KeyInfo>/, keyInfo);
  };
  const add = function (name, xml, how, extra) {
    const e = extra || {};
    let v;
    if (how === 'read') {
      v = crypto.readWsSecuritySignature(xml);
    } else if (how === 'verify') {
      v = crypto.verifyWsSecuritySignature(xml, { certPem: e.certPem });
    } else {
      v = crypto.verifyWsSecurityHmac(xml,
        { key: Buffer.from(e.keyB64 || '', 'base64') });
    }
    const a = answerOf(ROOT, v);
    cases.push({ name: name, xml: xml, how: how,
                 certPem: e.certPem || null, keyB64: e.keyB64 || null,
                 answer: a.answer, code: a.code });
  };

  const token = x509Token(rsa.certPem);
  const good = withKeyInfo(sign(envelope({ token: token })),
                           strOf('<wsse:Reference URI="#x509" ValueType="' +
                                 X509V3 + '"/>'));
  add('by reference, read', good, 'read');
  add('by reference, verified', good, 'verify', { certPem: rsa.certPem });
  add('by reference, base64 DER', good, 'verify',
      { certPem: b64OfPem(rsa.certPem) });
  add('another certificate', good, 'verify', { certPem: other.certPem });
  add('an unreadable certificate', good, 'verify', { certPem: 'AAAA' });
  add('no certificate', good, 'verify', {});
  add('the Body altered', good.replace('Issue</wst:RequestType>',
                                       'Renew</wst:RequestType>'),
      'verify', { certPem: rsa.certPem });
  add('the Timestamp altered', good.replace('10:05:00.000Z',
                                            '11:05:00.000Z'),
      'verify', { certPem: rsa.certPem });
  add('the value garbled', good.replace(/<ds:SignatureValue>[^<]{8}/,
                                        '<ds:SignatureValue>AAAAAAAA'),
      'verify', { certPem: rsa.certPem });
  add('the comment in the Body', good.replace('<!-- a comment -->',
                                              '<!-- another -->'),
      'verify', { certPem: rsa.certPem });

  // The other three key forms.
  const thumb = nodeCrypto.createHash('sha1').update(x509.raw)
    .digest('base64');
  const skiHex = pki.pathFactsOf(pki.certificateFromDer(x509.raw))
    .keyIdentifier;
  const bare = sign(envelope({}));
  [['a thumbprint', strOf('<wsse:KeyIdentifier ValueType="' + THUMBPRINT +
     '" EncodingType="' + BASE64 + '">' + thumb + '</wsse:KeyIdentifier>')],
   ['a thumbprint in hex', strOf('<wsse:KeyIdentifier ValueType="' +
     THUMBPRINT + '" EncodingType="urn:x#HexBinary">' +
     Buffer.from(thumb, 'base64').toString('hex').toUpperCase() +
     '</wsse:KeyIdentifier>')],
   ['a short thumbprint', strOf('<wsse:KeyIdentifier ValueType="' +
     THUMBPRINT + '">AAAA</wsse:KeyIdentifier>')],
   ['a Subject Key Identifier', strOf('<wsse:KeyIdentifier ValueType="' +
     SKI + '" EncodingType="' + BASE64 + '">' +
     Buffer.from(String(skiHex || '00'), 'hex').toString('base64') +
     '</wsse:KeyIdentifier>')],
   ['an issuer and serial', strOf('<ds:X509Data><ds:X509IssuerSerial>' +
     '<ds:X509IssuerName> ' + x509.issuer.split('\n').join(',') +
     ' </ds:X509IssuerName><ds:X509SerialNumber> ' +
     BigInt('0x' + x509.serialNumber).toString() +
     ' </ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data>')],
   ['a serial that is not a number', strOf('<ds:X509Data>' +
     '<ds:X509IssuerSerial><ds:X509IssuerName>CN=x</ds:X509IssuerName>' +
     '<ds:X509SerialNumber>0x1f</ds:X509SerialNumber>' +
     '</ds:X509IssuerSerial></ds:X509Data>')],
   ['an unknown KeyIdentifier', strOf('<wsse:KeyIdentifier ValueType="' +
     'urn:other">AAAA</wsse:KeyIdentifier>')],
   ['no SecurityTokenReference', '<ds:KeyInfo><ds:X509Data>' +
     '<ds:X509Certificate>' + b64OfPem(rsa.certPem) +
     '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'],
   ['a reference to nothing', strOf('<wsse:Reference URI="#nothing"/>')],
   ['a reference with no hash', strOf('<wsse:Reference URI="x509"/>')],
   ['nothing it reads', strOf('<wsse:Embedded/>')]]
    .forEach(function (row) {
      const xml = withKeyInfo(bare, row[1]);
      add(row[0] + ', read', xml, 'read');
      add(row[0] + ', verified', xml, 'verify', { certPem: rsa.certPem });
    });
  add('a SAML token by reference', withKeyInfo(sign(envelope({
    token: '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="urn:saml">' +
      'AAAA</wsse:BinarySecurityToken>' })),
  strOf('<wsse:Reference URI="#x509"/>')), 'read');

  // The structural refusals, in the reading's order.
  add('no security header', envelope({}).replace(/<wsse:Security>[\s\S]*?<\/wsse:Security>/,
                                                 ''), 'read');
  add('no signature', envelope({}), 'read');
  add('not XML', '<s:Envelope><s:Header>', 'read');
  add('two security headers', good.replace('<s:Header>',
    '<s:Header><wsse:Security/>'), 'read');
  add('a signature in another namespace', envelope({
    security: '<x:Signature xmlns:x="urn:x"/>' }), 'read');
  add('two signatures', good.replace('<wsse:Security>',
    '<wsse:Security>' + /<ds:Signature[\s\S]*?<\/ds:Signature>/
      .exec(good)[0]), 'read');
  add('the Body id twice', good.replace('<s:Header>',
    '<s:Header><x:Copy xmlns:x="urn:x" wsu:Id="body"/>'), 'read');
  add('two ids twice', good.replace('<s:Header>',
    '<s:Header><x:Copy xmlns:x="urn:x" wsu:Id="body"/><x:Copy ' +
    'xmlns:x="urn:x" Id="ts"/><x:Copy xmlns:x="urn:x" ID="ts"/>'), 'read');
  add('a KeyInfo and no SignedInfo', envelope({
    security: '<ds:Signature xmlns:ds="' + DS + '"><ds:KeyInfo/>' +
      '</ds:Signature>' }), 'read');
  add('no SignatureValue', good.replace(
    /<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, ''), 'read');
  add('no SignatureMethod', good.replace(/<ds:SignatureMethod [^>]*\/>/, ''),
      'read');
  add('a whole-envelope reference', good.replace('URI="#body"', 'URI=""'),
      'read');
  add('a reference elsewhere', good.replace('URI="#body"',
                                            'URI="http://x/#body"'), 'read');
  add('an enveloped transform', good.replace('<ds:Transforms>',
    '<ds:Transforms><ds:Transform Algorithm="' + DS +
    'enveloped-signature"/>'), 'read');
  add('no transforms', good.replace(/<ds:Transforms>[\s\S]*?<\/ds:Transforms>/,
                                    ''), 'read');
  add('an inclusive transform', good.replace('<ds:Transform Algorithm="' +
    EXC + '"/>', '<ds:Transform Algorithm="http://www.w3.org/TR/2001/' +
    'REC-xml-c14n-20010315"/>'), 'read');
  add('a transform with no Algorithm', good.replace('<ds:Transform ' +
    'Algorithm="' + EXC + '"/>', '<ds:Transform/>'), 'read');
  add('an inclusive SignedInfo', good.replace(
    '<ds:CanonicalizationMethod Algorithm="' + EXC + '"/>',
    '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/' +
    'REC-xml-c14n-20010315"/>'), 'read');
  add('no CanonicalizationMethod', good.replace(
    '<ds:CanonicalizationMethod Algorithm="' + EXC + '"/>', ''), 'read');
  add('the Body alone', withKeyInfo(sign(envelope({ token: token }),
    { signTimestamp: false }), strOf('<wsse:Reference URI="#x509"/>')),
  'read');
  add('a Body with no id', good.replace('<s:Body wsu:Id="body">',
                                        '<s:Body>'), 'read');
  add('a Body under another id', good.replace('<s:Body wsu:Id="body">',
                                              '<s:Body Id="body">'), 'verify',
      { certPem: rsa.certPem });
  add('two Timestamps', good.replace('<wsse:Security>',
    '<wsse:Security><wsu:Timestamp wsu:Id="ts2"/>'), 'read');
  add('the Body covered by a copy', good.replace('wsu:Id="body"',
    'wsu:Id="real"').replace('<s:Header>', '<s:Header><s:Body ' +
    'wsu:Id="body"/>'), 'read');

  // The algorithms.
  add('SHA-1, refused by default', withKeyInfo(sign(envelope({
    token: token }), { sigAlg: DS + 'rsa-sha1' }),
  strOf('<wsse:Reference URI="#x509"/>')), 'verify',
      { certPem: rsa.certPem });
  add('an unknown method', good.replace(MORE + 'rsa-sha256', 'urn:none'),
      'read');
  add('an MD5 method', good.replace(MORE + 'rsa-sha256', MORE + 'rsa-md5'),
      'read');
  add('a Whirlpool digest', good.replace(
    'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2007/05/xmldsig-more#whirlpool'), 'read');
  add('an HMAC with a certificate', good.replace(MORE + 'rsa-sha256',
                                                 MORE + 'hmac-sha256'),
      'verify', { certPem: rsa.certPem });
  add('an RSA method and a shared key', good, 'hmac',
      { keyB64: Buffer.from('k').toString('base64') });

  // THE SERIALIZED COPY: a PrefixList prefix declared on the Envelope.
  // Signed correctly in place — and refused, because Node verifies the
  // signature serialized on its own, where `s` is not declared.
  [['s', 'a PrefixList prefix an ancestor declares'],
   ['ds', 'a PrefixList prefix the copy declares'],
   ['#default', 'a PrefixList naming the default namespace']]
    .forEach(function (row) {
      const xml = withKeyInfo(sign(envelope({ token: token })),
                              strOf('<wsse:Reference URI="#x509"/>'));
      const listed = xml.replace(
        '<ds:CanonicalizationMethod Algorithm="' + EXC + '"/>',
        '<ds:CanonicalizationMethod Algorithm="' + EXC + '"><ec:' +
        'InclusiveNamespaces xmlns:ec="' + EXC + '" PrefixList="' + row[0] +
        '"/></ds:CanonicalizationMethod>');
      const doc = engine.parseXmlStrict(listed, 'the envelope');
      const si = doc.getElementsByTagNameNS(DS, 'SignedInfo')[0];
      const octets = engine.canonicalize(si, {
        prefixes: row[0].split(' ') });
      const value = nodeCrypto.createSign('RSA-SHA256')
        .update(Buffer.from(octets, 'utf8')).sign(rsa.privateKeyPem,
                                                  'base64');
      const resigned = listed.replace(
        /<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/,
        '<ds:SignatureValue>' + value + '</ds:SignatureValue>');
      add(row[1], resigned, 'verify', { certPem: rsa.certPem });
    });

  // THE KERBEROS TOKEN'S SESSION KEY (#658): an HMAC.
  const sessionKey = nodeCrypto.randomBytes(32);
  const krbToken = '<wsse:BinarySecurityToken wsu:Id="krb" ValueType="' +
    KRB + 'GSS_Kerberosv5_AP_REQ" EncodingType="' + BASE64 +
    '">YIIBAgYJKoZIhvcSAQICAQBuggEA</wsse:BinarySecurityToken>';
  const hmacSign = function (xml, sigAlg, keyInfoInner, key) {
    return engine.signWsSecurity(xml, {
      sigAlg: sigAlg, signTimestamp: true,
      keyInfoXml: '<wsse:SecurityTokenReference xmlns:wsse="' + WSSE + '">' +
        keyInfoInner +
        '</wsse:SecurityTokenReference>',
      signer: function (octets, spec) {
        return nodeCrypto.createHmac(spec.hash || 'sha256', key || sessionKey)
          .update(Buffer.from(octets, 'binary')).digest();
      } });
  };
  const keyB64 = sessionKey.toString('base64');
  [MORE + 'hmac-sha256', MORE + 'hmac-sha384', MORE + 'hmac-sha512',
   DS + 'hmac-sha1'].forEach(function (sigAlg) {
    let xml;
    try {
      xml = hmacSign(envelope({ token: krbToken }), sigAlg,
                     '<wsse:Reference URI="#krb"/>');
    } catch (e) {
      return;
    }
    signed.push({ name: sigAlg.replace(/.*#/, '') + ' with a session key',
                  input: envelope({ token: krbToken }), sigAlg: sigAlg,
                  signTimestamp: true, keyB64: keyB64,
                  keyInfoXml: '<wsse:SecurityTokenReference xmlns:wsse="' +
                    WSSE + '">' +
                    '<wsse:Reference URI="#krb"/>' +
                    '</wsse:SecurityTokenReference>',
                  signed: xml });
    add(sigAlg.replace(/.*#/, '') + ', read', xml, 'read');
    add(sigAlg.replace(/.*#/, '') + ', with the key', xml, 'hmac',
        { keyB64: keyB64 });
  });
  const kxml = hmacSign(envelope({ token: krbToken }), MORE + 'hmac-sha256',
                        '<wsse:Reference URI="#krb"/>');
  add('an HMAC with another key', kxml, 'hmac',
      { keyB64: nodeCrypto.randomBytes(32).toString('base64') });
  add('an HMAC with no key', kxml, 'hmac', {});
  add('an HMAC, the Body altered', kxml.replace('Issue</wst:RequestType>',
                                                'Renew</wst:RequestType>'),
      'hmac', { keyB64: keyB64 });
  add('a truncated HMAC', kxml.replace(
    '<ds:SignatureMethod Algorithm="' + MORE + 'hmac-sha256"/>',
    '<ds:SignatureMethod Algorithm="' + MORE + 'hmac-sha256">' +
    '<ds:HMACOutputLength>128</ds:HMACOutputLength></ds:SignatureMethod>'),
      'hmac', { keyB64: keyB64 });
  add('an HMAC verified with a certificate', kxml, 'verify',
      { certPem: rsa.certPem });
  ['Kerberosv5_AP_REQ', 'Kerberosv5_AP_REQ1510', 'GSS_Kerberosv5_AP_REQ4120',
   'Kerberosv5_AP_REQ9999'].forEach(function (type) {
    const xml = kxml.replace('GSS_Kerberosv5_AP_REQ"', type + '"');
    add('a Kerberos ' + type, xml, 'read');
  });
  const kid = hmacSign(envelope({ token: krbToken }), MORE + 'hmac-sha256',
    '<wsse:KeyIdentifier ValueType="' + KRB + 'Kerberosv5APREQSHA1">' +
    'q2Fm8C1lRSqBWOw5mUv4m6vA0xA=</wsse:KeyIdentifier>');
  add('a Kerberos key identifier, read', kid, 'read');
  add('a Kerberos key identifier, with the key', kid, 'hmac',
      { keyB64: keyB64 });

  return { policy: policyNow(ROOT), signed: signed, cases: cases,
           key: { privateKeyPem: rsa.privateKeyPem, certPem: rsa.certPem } };
}

// A value with every object's keys in order, so two answers compare as
// JSON whatever order each runtime wrote them in.
function sorted(v) {
  if (Array.isArray(v)) {
    return v.map(sorted);
  }
  if (v && typeof v === 'object') {
    const out = {};
    Object.keys(v).sort().forEach(function (k) {
      out[k] = sorted(v[k]);
    });
    return out;
  }
  return v;
}

// What Rust made and answered, checked by Node: each envelope Rust signed
// verifies here, and each of Rust's own cases is answered here as Rust
// answered it.
function checkRust(ROOT, rows, check) {
  const crypto = require(path.join(ROOT, 'common', 'crypto.js'));
  (rows.signed || []).forEach(function (row) {
    const v = row.keyB64
      ? crypto.verifyWsSecurityHmac(row.signed,
        { key: Buffer.from(row.keyB64, 'base64') })
      : crypto.verifyWsSecuritySignature(row.signed,
        { certPem: row.certPem });
    check(v.ok === row.expectOk, 'wssec: Node ' +
          (row.expectOk ? 'verifies' : 'refuses') + ' the envelope Rust ' +
          'signed (' + row.name + ')', v.why || '');
  });
  (rows.cases || []).forEach(function (row) {
    let v;
    if (row.how === 'read') {
      v = crypto.readWsSecuritySignature(row.xml);
    } else if (row.how === 'verify') {
      v = crypto.verifyWsSecuritySignature(row.xml, { certPem: row.certPem });
    } else {
      v = crypto.verifyWsSecurityHmac(row.xml,
        { key: Buffer.from(row.keyB64 || '', 'base64') });
    }
    const a = answerOf(ROOT, v);
    // What follows "could not be read: " is OpenSSL's own words in each
    // runtime.
    const words = function (answer) {
      const why = String(answer.why || '');
      const at = why.indexOf('could not be read: ');
      return at < 0 ? answer : Object.assign({}, answer, {
        why: why.slice(0, at + 'could not be read: '.length) });
    };
    a.answer = words(a.answer);
    row.answer = words(row.answer);
    const same = JSON.stringify(sorted(a.answer)) ===
      JSON.stringify(sorted(row.answer)) &&
      a.code === row.code;
    check(same, 'wssec: Node answers Rust\'s case as Rust did (' +
          row.name + ')', JSON.stringify(a).slice(0, 400) + ' vs ' +
          JSON.stringify({ answer: row.answer, code: row.code })
            .slice(0, 400));
  });
}

module.exports = { build: build, checkRust: checkRust };
