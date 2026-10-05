#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: crypto-vectors.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE CRYPTOGRAPHIC PARITY PROOF (#444, rust/DESIGN.md
// sections 6 and 10.2).
//
// For every algorithm in a row of the design's table, this writes what the
// Node service produces — keys, signatures, tokens, JWEs — as
// `jws-node.json` and `jwe-node.json` in a vectors directory, and
// `sts-crypto`'s tests must verify or decrypt every one of them, and match
// byte for byte where the scheme is deterministic. Those tests write what the
// Rust crate produces into the same directory (`jws-rust.json`,
// `jwe-rust.json`), and `tests/rust_crypto_vectors.js` verifies and decrypts
// every one of THEM in Node.
//
// **THE DIRECTORY IS NEVER COMMITTED**: the vectors carry private keys and
// shared secrets, and this repository commits no key material, generated or
// borrowed (`tests/tools/fetch-vectors.sh`). It is
// `tests/vectors/sts-crypto/` by default — gitignored and dockerignored
// with the other external vectors — or `STS_CRYPTO_VECTORS`.
//
//   node tests/tools/crypto-vectors.js [directory]
//   STS_CRYPTO_VECTORS=<dir> STS_WRITE_VECTORS=1 cargo test -p sts-crypto
//   node tests/run.js --only=rust_crypto_vectors
//
// Loading common/crypto.js needs its npm dependencies and node 24 (the
// post-quantum keys use its `raw-public` export format), as in the service
// image.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const OUT = process.argv[2] || process.env.STS_CRYPTO_VECTORS ||
  path.join(ROOT, 'tests', 'vectors', 'sts-crypto');

const crypto = require(path.join(ROOT, 'common', 'crypto.js'));
const pqJose = require(path.join(ROOT, 'common', 'pq_jose.js'));

const DETERMINISTIC = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                       'EdDSA'];

const CURVES = { ES256: 'prime256v1', ES384: 'secp384r1',
                 ES512: 'secp521r1', ES256K: 'secp256k1' };

// A key for `alg`: the JWK a Rust verifier is handed, and what signJws()
// signs with here.
function keyFor(alg) {
  if (/^HS/.test(alg)) {
    const secret = nodeCrypto.randomBytes(Number(alg.slice(2)) / 8);
    return { jwk: { kty: 'oct', k: secret.toString('base64url') },
             signing: secret };
  }
  if (pqJose.isPqAlg(alg)) {
    const pair = pqJose.generate(alg);
    return { jwk: { kty: 'AKP', alg: alg, pub: pair.pub.toString('base64url'),
                    priv: pair.priv.toString('base64url') },
             signing: pair.priv };
  }
  const pair = /^(RS|PS)/.test(alg)
    ? nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : alg === 'EdDSA' ? nodeCrypto.generateKeyPairSync('ed25519')
      : nodeCrypto.generateKeyPairSync('ec', { namedCurve: CURVES[alg] });
  return { jwk: pair.privateKey.export({ format: 'jwk' }),
           signing: pair.privateKey };
}

function jws() {
  return crypto.JWS_SIGNING_ALGS.map(function (alg) {
    const key = keyFor(alg);
    const input = Buffer.from('eyJhbGciOiJ4In0.eyJzdWIiOiJhbGljZSJ9',
                              'ascii');
    const signature = /^(HS|RS|PS|ES(256|384|512)$)/.test(alg)
      ? nodeSignature(alg, key.signing, input)
      : crypto.jwsSignatureOver(alg, key.signing, input);
    const token = crypto.signJws({ sub: 'alice', iat: 1000 }, key.signing,
                                 { algorithm: alg, keyid: 'node-1' });
    return { alg: alg, deterministic: DETERMINISTIC.indexOf(alg) >= 0,
             jwk: key.jwk, input: input.toString('ascii'),
             signature: signature.toString('base64url'), token: token,
             idTokenHalfHash: crypto.idTokenHalfHash('the-access-token',
                                                     alg) };
  });
}

// The signature node's crypto makes for the rows jsonwebtoken signs, with
// the same parameters crypto.js verifies them with.
function nodeSignature(alg, key, input) {
  const hash = 'sha' + alg.slice(2);
  if (/^HS/.test(alg)) {
    return nodeCrypto.createHmac(hash, key).update(input).digest();
  }
  const params = { key: key };
  if (/^PS/.test(alg)) {
    params.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
    params.saltLength = Number(alg.slice(2)) / 8;
  }
  if (/^ES/.test(alg)) {
    params.dsaEncoding = 'ieee-p1363';
  }
  return nodeCrypto.sign(hash, input, params);
}

// A JWE per alg (with A256GCM, or none for an Integrated HPKE alg), and
// RSA-OAEP-256 with every enc: the recipient's private key and the compact
// JWE Node encrypted to it.
function jweSecretFor(alg, enc) {
  const sizes = { A128KW: 16, A192KW: 24, A256KW: 32, A128GCMKW: 16,
                  A192GCMKW: 24, A256GCMKW: 32 };
  if (sizes[alg]) {
    return nodeCrypto.randomBytes(sizes[alg]);
  }
  if (alg === 'dir') {
    return nodeCrypto.randomBytes(crypto.JWE_ENCS[enc].cekBytes);
  }
  return Buffer.from('a password for PBES2', 'utf8');
}

function jweRecipient(alg) {
  if (crypto.JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
    return null;
  }
  if (crypto.JWE_RSA_ALGS.indexOf(alg) >= 0 ||
      crypto.JWE_ECDH_ALGS.indexOf(alg) >= 0) {
    const pair = crypto.JWE_RSA_ALGS.indexOf(alg) >= 0
      ? nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
      : nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    return { publicJwk: pair.publicKey.export({ format: 'jwk' }),
             privateJwk: pair.privateKey.export({ format: 'jwk' }) };
  }
  return crypto.generateJweKemKeyPair(alg, 'node-1');
}

function jwe() {
  const cases = crypto.JWE_ALGS.map(function (alg) {
    return { alg: alg, enc: 'A256GCM' };
  }).concat(Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'RSA-OAEP-256', enc: enc };
  }), Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'dir', enc: enc };
  }));
  return cases.map(function (one) {
    const recipient = jweRecipient(one.alg);
    const secret = recipient ? null : jweSecretFor(one.alg, one.enc);
    const compact = crypto.encryptJweCompact('{"sub":"alice"}', {
      alg: one.alg, enc: one.enc,
      jwk: recipient ? recipient.publicJwk : undefined,
      secret: secret || undefined });
    return { alg: one.alg, enc: one.enc,
             privateJwk: recipient ? recipient.privateJwk : null,
             secret: secret ? secret.toString('base64url') : null,
             compact: compact };
  });
}

// CANONICAL XML: every element of every document, in all four forms, as
// common/vendored/xmldsig.js computes it in place — the bytes every XML
// signature here is made and checked over, which sts-xml must reproduce
// exactly. The documents are the hand-written edge cases below and, when
// STS_C14N_CORPUS names a directory, every .xml file under it (the W3C
// interop cases tests/tools/fetch-w3c-xmlsec.sh fetches). A document Node
// refuses to parse is recorded as refused, and Rust must refuse it too.
const C14N_CASES = [
  '<a:r xmlns:a="urn:a" xmlns:b="urn:b" z="1" a:y="&lt;2&gt;"><c>x&amp;y</c></a:r>',
  '<r xmlns="urn:d"><c xmlns=""><d xmlns="urn:e"/></c><!-- c --><?pi data?></r>',
  '<r xmlns:p="urn:p"><p:c p:a="1" b="2" xml:lang="en"><e xmlns:p="urn:p"/></p:c></r>',
  '<r>\r\n<a b="t\tn\nr\r">&#xD;&#x9;\t</a><![CDATA[<x> & ]]></r>',
  '<r xmlns:a="urn:z" xmlns:b="urn:a"><e b:y="1" a:x="2" c="3" b:a="4"/></r>',
  '<s:Envelope xmlns:s="urn:s" xmlns:xsi="urn:xsi"><s:Body><t xsi:type="s:T" ' +
    'xmlns="urn:t">\u00e9\u4e2d\ud83d\ude00</t></s:Body></s:Envelope>',
  '<r xmlns="urn:a"><a xmlns="urn:a"/><b xmlns=""/><c xmlns="urn:c"><d xmlns=""/></c></r>',
  '<r><!--x--><a><!--y--></a></r>',
  '<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>',
  '<r><a></b></r>'
];

function c14nCorpus() {
  const out = C14N_CASES.map(function (xml, i) {
    return { name: 'case-' + i, xml: xml };
  });
  const dir = process.env.STS_C14N_CORPUS;
  if (dir) {
    const walk = function (d) {
      fs.readdirSync(d, { withFileTypes: true }).forEach(function (e) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (/\.xml$/.test(e.name)) {
          out.push({ name: path.relative(dir, full),
                     xml: fs.readFileSync(full, 'utf8') });
        }
      });
    };
    walk(dir);
  }
  return out;
}

function c14n() {
  const xmldsig = require(path.join(ROOT, 'common', 'vendored',
                                    'xmldsig.js'));
  return c14nCorpus().map(function (one) {
    let doc;
    try {
      doc = xmldsig.parseXmlStrict(one.xml, 'a corpus document');
    } catch (e) {
      return { name: one.name, xml: one.xml, refused: e.message };
    }
    const forms = [];
    const all = doc.getElementsByTagName('*');
    for (let i = 0; i < all.length; i++) {
      forms.push([
        xmldsig.canonicalize(all[i], {}),
        xmldsig.canonicalize(all[i], { comments: true }),
        xmldsig.canonicalizeInclusive(all[i], {}),
        xmldsig.canonicalizeInclusive(all[i], { comments: true })
      ]);
    }
    // And the document as XMLSerializer writes it back, which is what a
    // signed document is returned as: the signed bytes are compared too.
    return { name: one.name, xml: one.xml, forms: forms,
             serialized: new XMLSerializer().serializeToString(doc) };
  });
}

// XML SIGNATURE: what crypto.signXml() makes with each of the ten
// SignatureMethods saml.signatureAlgorithm offers, over a handful of
// documents, every canonicalization and placement; what
// crypto.verifyXmlSignature() answers about each of them and about the ways
// a signature is refused; the general engine's signatures in every other
// method crypto.js verifies; and the Redirect binding's query-string
// signatures. RSA PKCS#1 v1.5 is deterministic, so Rust must make the same
// BYTES; the rest it must verify, and answer about as Node does.
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const MORE07 = 'http://www.w3.org/2007/05/xmldsig-more#';
const MORE21 = 'http://www.w3.org/2021/04/xmldsig-more#';
const MORE26 = 'http://www.w3.org/2026/08/xmldsig-more#';
const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const INC = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const C14NS = [EXC, EXC + 'WithComments', INC, INC + '#WithComments'];

const XML_DOCS = {
  saml2: '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'xmlns:xs="http://www.w3.org/2001/XMLSchema" ' +
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_a1" ' +
    'Version="2.0"><saml:Issuer>https://idp.example/é</saml:Issuer>' +
    '<!-- a comment --><saml:Subject><saml:NameID>alice &amp; bob' +
    '</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute ' +
    'Name="mail"><saml:AttributeValue xsi:type="xs:string">a@b.example' +
    '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>' +
    '</saml:Assertion>',
  response: '<?xml version="1.0" encoding="UTF-8"?>\n<samlp:Response ' +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">' +
    '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp' +
    '</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:' +
    'tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml=' +
    '"urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2"><saml:Issuer>idp' +
    '</saml:Issuer></saml:Assertion></samlp:Response>',
  saml11: '<Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" ' +
    'AssertionID="_s11" MajorVersion="1"><Conditions NotBefore="2026-01-01' +
    'T00:00:00Z"/>\n\t<AttributeStatement>x中</AttributeStatement>' +
    '</Assertion>',
  noid: '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:' +
    'metadata" entityID="https://sp.example/"><md:SPSSODescriptor ' +
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>' +
    '</md:EntityDescriptor>'
};

const XML_SIGNERS = [
  ['rsa-sha256', MORE + 'rsa-sha256', 'rsa'],
  ['rsa-sha384', MORE + 'rsa-sha384', 'rsa'],
  ['rsa-sha512', MORE + 'rsa-sha512', 'rsa'],
  ['rsa-sha1', DS + 'rsa-sha1', 'rsa'],
  ['ecdsa-sha256', MORE + 'ecdsa-sha256', 'p256'],
  ['ecdsa-sha384', MORE + 'ecdsa-sha384', 'p384'],
  ['ml-dsa-44', MORE26 + 'ml-dsa-44', 'ML-DSA-44'],
  ['ml-dsa-65', MORE26 + 'ml-dsa-65', 'ML-DSA-65'],
  ['ml-dsa-87', MORE26 + 'ml-dsa-87', 'ML-DSA-87'],
  ['slh-dsa-sha2-128s', MORE26 + 'slh-dsa-sha2-128s', 'SLH-DSA-SHA2-128s']
];

// The keys: PEMs for the classical ones (the RSA one with a certificate,
// so the KeyInfo path and its subject are checked), raw keys and an SPKI
// PEM for the post-quantum ones.
function xmlKeys() {
  const keys = {};
  const rsa = require(path.join(ROOT, 'common', 'vendored', 'xmldsig.js'))
    .generateKeyPair(2048, 'Vector Signer');
  keys.rsa = { privateKeyPem: rsa.privateKeyPem,
               publicKeyPem: rsa.publicKeyPem, certPem: rsa.certPem };
  const pem = function (pair) {
    return { privateKeyPem: pair.privateKey.export({ type: 'pkcs8',
                                                     format: 'pem' }),
             publicKeyPem: pair.publicKey.export({ type: 'spki',
                                                   format: 'pem' }) };
  };
  keys.p256 = pem(nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'prime256v1' }));
  keys.p384 = pem(nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'secp384r1' }));
  ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128s']
    .forEach(function (alg) {
      const pair = pqJose.generate(alg);
      keys[alg] = {
        alg: alg, priv: pair.priv.toString('base64'),
        pub: pair.pub.toString('base64'), privRaw: pair.priv,
        publicKeyPem: nodeCrypto.createPublicKey({ key: pair.pub,
          format: 'raw-public', asymmetricKeyType: alg.toLowerCase() })
          .export({ type: 'spki', format: 'pem' })
      };
    });
  return keys;
}

function verdictOf(v) {
  const code = require(path.join(ROOT, 'common', 'error_codes.js'))
    .codeOf(v) || null;
  return { ok: !!v.ok, present: !!v.present, usable: v.usable, why: v.why,
           code: code, signatureValid: v.signatureValid,
           referencesValid: v.referencesValid,
           signatureMethod: v.signatureMethod,
           canonicalization: v.canonicalization,
           signerSubject: v.signerSubject, signerCertB64: v.signerCertB64,
           referenceUri: v.referenceUri, digestMethods: v.digestMethods,
           weak: v.weak, sha1: v.sha1 };
}

function rootName(xml) {
  return /<(?:[\w.-]+:)?([\w.-]+)[\s>]/.exec(xml.replace(/^<\?[^>]*\?>\s*/,
                                                           ''))[1];
}

function xmldsig() {
  const keys = xmlKeys();
  const signed = [];
  const verify = [];
  const check = function (name, xml, element, opts) {
    verify.push({ name: name, xml: xml, element: element,
                  certPem: opts.certPem || null,
                  publicKeyPem: opts.publicKeyPem || null,
                  verdict: verdictOf(crypto.verifyXmlSignature(xml,
                    Object.assign({ element: element }, opts))) });
  };
  XML_SIGNERS.forEach(function (signer) {
    const key = keys[signer[2]];
    const pq = !!key.alg;
    const docs = pq ? ['saml2', 'response'] : Object.keys(XML_DOCS);
    const c14ns = pq ? [EXC, INC] : C14NS;
    const placements = pq ? ['after-issuer'] :
      signer[2] === 'rsa' ? ['after-issuer', 'first', 'last'] :
        ['after-issuer', 'last'];
    docs.forEach(function (docName) {
      c14ns.forEach(function (c14n) {
        placements.forEach(function (placement) {
          const opts = { sigAlg: signer[1], c14nAlg: c14n,
                         placement: placement };
          if (pq) {
            opts.privateKey = key.privRaw;
          } else {
            opts.privateKeyPem = key.privateKeyPem;
          }
          if (key.certPem) {
            opts.certPem = key.certPem;
          } else if (!pq) {
            // An ECDSA KeyInfo needs a certificate; the RSA one's text is
            // embedded, which signing never reads.
            opts.certPem = keys.rsa.certPem;
          }
          const xml = crypto.signXml(XML_DOCS[docName], opts);
          const name = [signer[0], docName, c14n.replace(/.*[#/]/, '') ||
                        'c14n', placement].join(' ');
          signed.push({ name: name, input: XML_DOCS[docName],
                        key: signer[2], sigAlg: signer[1], c14nAlg: c14n,
                        placement: placement,
                        certPem: opts.certPem || null,
                        deterministic: signer[2] === 'rsa',
                        signed: xml });
          check(name, xml, rootName(XML_DOCS[docName]),
                { publicKeyPem: key.publicKeyPem });
        });
      });
    });
  });

  // The refusals, each over an RSA signature.
  const base = crypto.signXml(XML_DOCS.saml2, {
    privateKeyPem: keys.rsa.privateKeyPem, certPem: keys.rsa.certPem });
  const rsaPub = { publicKeyPem: keys.rsa.publicKeyPem };
  check('the KeyInfo certificate', base, 'Assertion', {});
  check('a named certificate', base, 'Assertion',
        { certPem: keys.rsa.certPem });
  check('tampered', base.replace('alice', 'mallory'), 'Assertion', rsaPub);
  check('no such element', base, 'Response', rsaPub);
  check('an unsigned element', base, 'Subject', rsaPub);
  check('a reference elsewhere', base.replace('URI="#_a1"', 'URI="#_x"'),
        'Assertion', rsaPub);
  check('the wrong key', base, 'Assertion',
        { publicKeyPem: keys.p256.publicKeyPem });
  check('another RSA key', base, 'Assertion', {
    publicKeyPem: nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 }).publicKey.export({ type: 'spki',
                                                  format: 'pem' }) });
  check('an MD5 method', base.replace(MORE + 'rsa-sha256', MORE + 'rsa-md5'),
        'Assertion', rsaPub);
  check('an unknown method', base.replace(MORE + 'rsa-sha256',
                                          'urn:no-such-method'),
        'Assertion', rsaPub);
  check('a Whirlpool digest', base.replace(
    'http://www.w3.org/2001/04/xmlenc#sha256',
    MORE07 + 'whirlpool'), 'Assertion', rsaPub);
  check('a garbled value', base.replace(/<ds:SignatureValue>[^<]{8}/,
                                        '<ds:SignatureValue>AAAAAAAA'),
        'Assertion', rsaPub);
  check('SHA-1, refused by default', crypto.signXml(XML_DOCS.saml2, {
    privateKeyPem: keys.rsa.privateKeyPem, sigAlg: DS + 'rsa-sha1' }),
  'Assertion', rsaPub);
  check('an unreadable certificate', base, 'Assertion',
        { certPem: 'AAAA' });
  // A signed assertion inside a response: exclusive verifies, inclusive is
  // refused as nested.
  ['exc', 'inc'].forEach(function (which) {
    const inner = crypto.signXml('<saml:Assertion xmlns:saml="urn:oasis:' +
      'names:tc:SAML:2.0:assertion" ID="_n1"><saml:Issuer>idp' +
      '</saml:Issuer></saml:Assertion>', {
      privateKeyPem: keys.rsa.privateKeyPem,
      c14nAlg: which === 'exc' ? EXC : INC });
    const outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:' +
      '2.0:protocol" ID="_o1">' + inner + '</samlp:Response>';
    check('a nested assertion, ' + which, outer, 'Assertion', rsaPub);
  });
  check('not XML', '<a><b></a>', 'Assertion', rsaPub);

  // The general engine, in every other method crypto.js verifies.
  const general = [];
  const engine = require(path.join(ROOT, 'common', 'vendored',
                                   'xmldsig.js'));
  const pair = function (type, o) {
    return nodeCrypto.generateKeyPairSync(type, o);
  };
  const rsaPair = pair('rsa', { modulusLength: 2048 });
  const others = [
    [MORE + 'rsa-sha224', rsaPair, 'sha224', 'rsa'],
    [MORE + 'rsa-ripemd160', rsaPair, 'ripemd160', 'rsa'],
    [MORE07 + 'sha1-rsa-MGF1', rsaPair, 'sha1', 'pss'],
    [MORE07 + 'sha256-rsa-MGF1', rsaPair, 'sha256', 'pss'],
    [MORE07 + 'sha3-256-rsa-MGF1', rsaPair, 'sha3-256', 'pss'],
    [MORE07 + 'sha512-rsa-MGF1', rsaPair, 'sha512', 'pss'],
    [MORE + 'ecdsa-sha512', pair('ec', { namedCurve: 'secp521r1' }),
     'sha512', 'ec'],
    [MORE21 + 'ecdsa-sha3-256', pair('ec', { namedCurve: 'secp256k1' }),
     'sha3-256', 'ec'],
    [MORE07 + 'ecdsa-ripemd160', pair('ec',
      { namedCurve: 'brainpoolP256r1' }), 'ripemd160', 'ec'],
    [MORE + 'ecdsa-sha256', pair('ec', { namedCurve: 'prime192v1' }),
     'sha256', 'ec'],
    [MORE21 + 'eddsa-ed25519', pair('ed25519'), null, 'ed'],
    [MORE21 + 'eddsa-ed448', pair('ed448'), null, 'ed'],
    [MORE + 'ecdsa-sha256', pair('ec', { namedCurve: 'prime256v1' }),
     'sha256', 'ec-der'],
    [MORE26 + 'slh-dsa-shake-128f', pair('slh-dsa-shake-128f'), null, 'ed']
  ];
  let dsa = null;
  try {
    dsa = pair('dsa', { modulusLength: 2048, divisorLength: 256 });
  } catch (e) {
    dsa = null;
  }
  if (dsa) {
    others.push([MORE.replace('2001/04/xmldsig-more', '2009/xmldsig11') +
                 'dsa-sha256', dsa, 'sha256', 'dsa']);
  }
  others.forEach(function (row) {
    const signerFn = function (octets) {
      const data = Buffer.from(octets, 'binary');
      const k = { key: row[1].privateKey };
      if (row[3] === 'pss') {
        k.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
        k.saltLength = nodeCrypto.createHash(row[2]).digest().length;
      }
      if (row[3] === 'ec' || row[3] === 'dsa') {
        k.dsaEncoding = 'ieee-p1363';
      }
      return nodeCrypto.sign(row[2], data, k);
    };
    const out = engine.signXml(XML_DOCS.saml2, {
      mode: 'enveloped', sigAlg: row[0], keyInfo: 'none',
      signer: signerFn });
    const publicKeyPem = row[1].publicKey.export({ type: 'spki',
                                                   format: 'pem' });
    const name = 'general ' + row[0].replace(/.*#/, '') + ' ' + row[3];
    general.push({ name: name, sigAlg: row[0], publicKeyPem: publicKeyPem,
                   signed: out.xml });
    check(name, out.xml, 'Assertion', { publicKeyPem: publicKeyPem });
  });

  // The Redirect binding: Node's signature over a query string with each
  // signer, and what verifyQueryString() says with the RSA certificate.
  const query = 'SAMLRequest=fZJNb%2BIwEIb%2FiuV7&RelayState=%C3%A9x&' +
    'SigAlg=';
  const queries = XML_SIGNERS.map(function (signer) {
    const key = keys[signer[2]];
    const q = query + encodeURIComponent(signer[1]);
    const signature = key.alg
      ? crypto.signQueryString(q, null, signer[1], key.privRaw)
      : crypto.signQueryString(q, key.privateKeyPem, signer[1]);
    return { name: signer[0], query: q, sigAlg: signer[1], key: signer[2],
             signature: signature, deterministic: signer[2] === 'rsa',
             verdict: signer[2] === 'rsa'
               ? verdictOf(crypto.verifyQueryString(q, {
                 signature: signature, sigAlg: signer[1],
                 certPem: keys.rsa.certPem }))
               : null };
  });
  const rsaQuery = queries[0];
  const queryChecks = [
    ['tampered', rsaQuery.query + 'x', rsaQuery.signature, rsaQuery.sigAlg,
     keys.rsa.certPem],
    ['no certificate', rsaQuery.query, rsaQuery.signature, rsaQuery.sigAlg,
     null],
    ['no signature', rsaQuery.query, '', rsaQuery.sigAlg, keys.rsa.certPem],
    ['not base64', rsaQuery.query, 'a*b', rsaQuery.sigAlg, keys.rsa.certPem],
    ['an unknown SigAlg', rsaQuery.query, rsaQuery.signature, 'urn:x',
     keys.rsa.certPem],
    ['SHA-1', queries[3].query, queries[3].signature, queries[3].sigAlg,
     keys.rsa.certPem]
  ].map(function (row) {
    return { name: row[0], query: row[1], signature: row[2],
             sigAlg: row[3], certPem: row[4],
             verdict: verdictOf(crypto.verifyQueryString(row[1], {
               signature: row[2], sigAlg: row[3], certPem: row[4] })) };
  });

  Object.keys(keys).forEach(function (k) {
    delete keys[k].privRaw;
  });
  return { policy: { sha1Allowed: crypto.xmlSignatureAlgorithms()
    .sha1Allowed, brokenAlgorithms: require(path.join(ROOT, 'common',
                                                      'mode.js'))
    .usesBrokenAlgorithms() },
           keys: keys, signed: signed, verify: verify, general: general,
           queries: queries, queryChecks: queryChecks };
}

// XML ENCRYPTION: what crypto.encryptElement() makes for an RSA recipient
// in every cipher and key transport and for an EC one in every curve and
// key wrap, what crypto.decryptElement() answers about each — and about the
// ways a document is refused. Every encryption is randomised, so Rust must
// decrypt Node's, make the same document but for the random values, and
// give every verdict Node gives. The EC certificates come from the openssl
// command line, as forge makes RSA ones only.
function ecCertificate(curve) {
  const os = require('os');
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xmlenc-'));
  try {
    childProcess.execFileSync('openssl', ['req', '-x509', '-newkey', 'ec',
      '-pkeyopt', 'ec_paramgen_curve:' + curve, '-nodes', '-keyout',
      path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'),
      '-subj', '/CN=xmlenc ' + curve, '-days', '2'], { stdio: 'ignore' });
    return { privateKeyPem: fs.readFileSync(path.join(dir, 'key.pem'),
                                            'utf8'),
             certPem: fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function decryptVerdict(v) {
  return { ok: !!v.ok, xml: v.xml || '', why: v.why || '',
           code: require(path.join(ROOT, 'common', 'error_codes.js'))
             .codeOf(v) || null,
           refused: !!v.refused, algorithm: v.algorithm || '',
           keyTransport: v.keyTransport || '', keyWrap: v.keyWrap || '',
           oaepDigest: v.oaepDigest || '' };
}

function xmlenc() {
  const engine = require(path.join(ROOT, 'common', 'vendored',
                                   'xmldsig.js'));
  const rsa = engine.generateKeyPair(2048, 'xmlenc rsa');
  const recipients = { rsa: { privateKeyPem: rsa.privateKeyPem,
                              certPem: rsa.certPem } };
  ['P-256', 'P-384', 'P-521'].forEach(function (curve) {
    recipients[curve] = ecCertificate(curve);
  });
  const plain = {
    assertion: '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion" ID="_e1"><saml:Issuer>idp é</saml:Issuer>' +
      '</saml:Assertion>',
    nameid: '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-' +
      'format:emailAddress">a@b.example</saml:NameID>'
  };
  const ciphers = ['aes256-gcm', 'aes128-gcm', 'aes256-cbc', 'aes128-cbc',
                   'aes192-gcm', 'aes192-cbc'];
  const cases = [];
  const decrypt = function (name, xml, recipient, opts) {
    return { name: name, xml: xml, recipient: recipient,
             options: opts || {},
             verdict: decryptVerdict(crypto.decryptElement(xml,
               recipients[recipient].privateKeyPem, opts || {})) };
  };
  ciphers.forEach(function (cipher) {
    ['rsa-oaep', 'rsa-oaep-mgf1p', 'rsa-1_5'].forEach(function (transport) {
      const opts = { algorithm: cipher, keyTransport: transport,
                     wrapper: 'saml:EncryptedID' };
      const enc = crypto.encryptElement(plain.nameid, rsa.certPem, opts);
      const c = decrypt(cipher + ' ' + transport, enc, 'rsa');
      c.encrypt = { plain: plain.nameid, options: opts };
      cases.push(c);
    });
  });
  ['P-256', 'P-384', 'P-521'].forEach(function (curve) {
    ['kw-aes128', 'kw-aes192', 'kw-aes256'].forEach(function (wrap) {
      const opts = { keyWrap: wrap };
      const enc = crypto.encryptElement(plain.assertion,
                                        recipients[curve].certPem, opts);
      const c = decrypt(curve + ' ' + wrap, enc, curve);
      c.encrypt = { plain: plain.assertion, options: opts };
      cases.push(c);
    });
  });
  ciphers.forEach(function (cipher) {
    const opts = { algorithm: cipher };
    const enc = crypto.encryptElement(plain.assertion,
                                      recipients['P-256'].certPem, opts);
    const c = decrypt('P-256 ' + cipher, enc, 'P-256');
    c.encrypt = { plain: plain.assertion, options: opts };
    cases.push(c);
  });

  // The refusals.
  const gcm = crypto.encryptElement(plain.assertion, rsa.certPem,
                                    { keyTransport: 'rsa-oaep' });
  const cbc = crypto.encryptElement(plain.assertion, rsa.certPem,
                                    { algorithm: 'aes128-cbc' });
  const ec = crypto.encryptElement(plain.assertion,
                                   recipients['P-256'].certPem, {});
  const flip = function (xml) {
    // The last CipherValue is the data's; change one character of it.
    const at = xml.lastIndexOf('</xenc:CipherValue>') - 6;
    return xml.slice(0, at) + (xml[at] === 'A' ? 'B' : 'A') +
      xml.slice(at + 1);
  };
  const other = engine.generateKeyPair(2048, 'other');
  recipients.other = { privateKeyPem: other.privateKeyPem,
                       certPem: other.certPem };
  recipients['P-256b'] = ecCertificate('P-256');
  const refusals = [
    decrypt('GCM tampered', flip(gcm), 'rsa'),
    decrypt('CBC tampered', flip(cbc), 'rsa'),
    decrypt('the wrong RSA key (OAEP)', gcm, 'other'),
    decrypt('the wrong RSA key (1_5)', crypto.encryptElement(plain.assertion,
      rsa.certPem, { keyTransport: 'rsa-1_5' }), 'other'),
    decrypt('an unknown cipher', gcm.replace(
      'http://www.w3.org/2009/xmlenc11#aes256-gcm', 'urn:x'), 'rsa'),
    decrypt('an unknown transport', gcm.replace(
      'http://www.w3.org/2009/xmlenc11#rsa-oaep', 'urn:y'), 'rsa'),
    decrypt('no EncryptedData', '<x/>', 'rsa'),
    decrypt('not XML', '<x>', 'rsa'),
    decrypt('a cipher not allowed', gcm, 'rsa',
            { allowedCiphers: ['aes128-gcm'] }),
    decrypt('a transport not allowed', gcm, 'rsa',
            { allowedKeyManagement: ['ecdh-es'] }),
    decrypt('an OAEP digest not allowed', gcm, 'rsa',
            { allowedOaepDigests: ['sha512'] }),
    decrypt('nothing allowed', gcm, 'rsa', { allowedCiphers: [] }),
    decrypt('an OAEP digest pair that differs', gcm.replace(
      'http://www.w3.org/2009/xmlenc11#mgf1sha256',
      'http://www.w3.org/2009/xmlenc11#mgf1sha1'), 'rsa'),
    decrypt('another agreement', ec.replace(
      'http://www.w3.org/2009/xmlenc11#ECDH-ES', 'urn:dh'), 'P-256'),
    decrypt('a SHA-1 ConcatKDF', ec.replace(
      '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"' +
      '/></xenc11:ConcatKDFParams>',
      '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"' +
      '/></xenc11:ConcatKDFParams>'), 'P-256'),
    decrypt('an agreement to an RSA key', ec, 'rsa'),
    decrypt('an agreement to another EC key', ec, 'P-384'),
    decrypt('an agreement to another P-256 key', ec, 'P-256b'),
    decrypt('no CipherValue', gcm.replace(/<xenc:CipherValue>[^<]*<\/xenc:Ci/,
                                          '<xenc:CipherValu></xenc:CipherValu' +
                                          '><xenc:Ci'), 'rsa')
  ];
  return { brokenAlgorithms: require(path.join(ROOT, 'common', 'mode.js'))
    .usesBrokenAlgorithms(),
           recipients: recipients, cases: cases, refusals: refusals };
}

// SECRETS: HOTP in every digest and length, scrypt hashes at the floor
// cost, envelopes under both kinds of data key and wrapped data keys, and
// the deterministic derivations (deriveDek(), deriveSharedCredential(),
// kekBytes()) — which Rust must reproduce byte for byte.
function secrets() {
  const kekText = 'an operator\'s passphrase long enough to be a KEK';
  const kekHex = nodeCrypto.randomBytes(32).toString('hex');
  const kekB64 = nodeCrypto.randomBytes(48).toString('base64');
  const hotp = [];
  ['SHA1', 'SHA256', 'SHA512'].forEach(function (alg) {
    [6, 8, 10].forEach(function (digits) {
      const key = nodeCrypto.randomBytes(alg === 'SHA1' ? 20 : 32);
      [0, 1, 59, 1111111109, 2000000000].forEach(function (counter) {
        hotp.push({ key: key.toString('base64'), counter: counter,
                    digits: digits, algorithm: alg,
                    code: crypto.hotpCode(key, counter,
                                          { digits: digits, algorithm: alg })
        });
      });
    });
  });
  const hashes = ['', 'password', 'pässwörd 🔑',
                  'x'.repeat(300)].map(function (plain) {
    return { plain: plain, stored: crypto.hashSecret(plain) };
  });
  const envelopes = ['aes-256-gcm', 'aes-256-siv'].map(function (alg) {
    const key = crypto.generateDek(alg);
    const id = crypto.generateDekId();
    return { alg: alg, key: key.toString('base64'), id: id,
             plain: 'a value é 中',
             sealed: crypto.encryptWithDek(id, key, 'a value é 中',
                                           'vectors') };
  });
  const dek = crypto.generateDek('aes-256-gcm');
  const wraps = [kekText, kekHex, kekB64].map(function (kek) {
    return { kek: kek, aad: 'id|realm|class', dek: dek.toString('base64'),
             wrapped: crypto.wrapDek(kek, dek, 'id|realm|class') };
  });
  const derived = [kekText, kekHex, kekB64].map(function (kek) {
    const d = crypto.deriveDek(kek, 'realm|default|directory');
    return { kek: kek, context: 'realm|default|directory', id: d.id,
             key: d.key.toString('base64'),
             kekBytes: crypto.kekBytes(kek).toString('base64') };
  });
  const kekRefusals = ['', 'short', 'ab'.repeat(15)].map(function (kek) {
    let refused = false;
    try {
      crypto.kekBytes(kek);
    } catch (e) {
      refused = true;
    }
    return { kek: kek, refused: refused };
  });
  const credentials = [
    ['secret', 'ssf-receiver', ['default', 'console']],
    ['sécret', 'label', []],
    ['k', 'a', ['b', 'c']], ['k', 'a', ['bc']], ['k', 'ab', ['c']]
  ].map(function (row) {
    return { secret: row[0], label: row[1], parts: row[2],
             credential: crypto.deriveSharedCredential.apply(null,
               [row[0], row[1]].concat(row[2])) };
  });
  return { hotp: hotp, hashes: hashes, envelopes: envelopes, wraps: wraps,
           derived: derived, kekRefusals: kekRefusals,
           credentials: credentials };
}

// KERBEROS, SESSION STATE AND DKIM: all deterministic, so Rust must
// produce the same bytes — n-fold at every size, the PRF and PRF+ for every
// enctype, KRB-FX-CF2 across enctypes, `session_state` with a given salt,
// and DKIM signatures in both algorithms over messages whose
// canonicalization is the hard part (folding, tabs, 0xA0, bare LF, empty
// and trailing-blank bodies, a repeated header).
function kerberosAndDkim() {
  const sizes = { 17: 16, 18: 32, 19: 16, 20: 32, 23: 16 };
  const nfold = [];
  ['', 'a', 'kerberos', 'Rough Consensus', 'éè'].forEach(function (s) {
    [7, 8, 16, 21, 24, 32].forEach(function (n) {
      if (!s) {
        return;
      }
      nfold.push({ input: Buffer.from(s, 'utf8').toString('base64'), bytes: n,
                   out: crypto.krb5Nfold(Buffer.from(s, 'utf8'), n)
                     .toString('base64') });
    });
  });
  const prf = [];
  const cf2 = [];
  Object.keys(sizes).forEach(function (etype) {
    const key = nodeCrypto.randomBytes(sizes[etype]);
    [Buffer.alloc(0), Buffer.from('prf'), nodeCrypto.randomBytes(33)]
      .forEach(function (input) {
        prf.push({ etype: Number(etype), key: key.toString('base64'),
                   input: input.toString('base64'),
                   out: Buffer.from(crypto.krb5Prf(Number(etype), key, input))
                     .toString('base64'),
                   plus: Buffer.from(crypto.krb5PrfPlus(Number(etype), key,
                                                        input, 77))
                     .toString('base64') });
      });
    Object.keys(sizes).forEach(function (other) {
      const k2 = nodeCrypto.randomBytes(sizes[other]);
      const out = crypto.krbFxCf2({ etype: Number(etype), key: key },
                                  { etype: Number(other), key: k2 },
                                  'armorkey', 'ticketarmor');
      cf2.push({ etype1: Number(etype), key1: key.toString('base64'),
                 etype2: Number(other), key2: k2.toString('base64'),
                 out: Buffer.from(out.key).toString('base64') });
    });
  });
  const sessionStates = [['client', 'https://rp.example', 'bs', 'salt1'],
                         ['cé', 'https://x.example:8443', '', 'Zz']]
    .map(function (r) {
      return { args: r, out: crypto.sessionStateHash(r[0], r[1], r[2],
                                                     r[3]) };
    });
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const keys = {
    rsa: { privateKeyPem: rsa.privateKey.export({ type: 'pkcs8',
                                                  format: 'pem' }),
           publicKeyPem: rsa.publicKey.export({ type: 'spki',
                                                format: 'pem' }) },
    ed25519: { privateKeyPem: ed.privateKey.export({ type: 'pkcs8',
                                                     format: 'pem' }),
               publicKeyPem: ed.publicKey.export({ type: 'spki',
                                                   format: 'pem' }) }
  };
  const messages = [
    'From: Iya <noreply@example.com>\r\nTo: a@b.example\r\n' +
      'Subject:  Hello\r\n\tthere \r\nDate: Mon, 5 Oct 2026 06:00:00 +0000' +
      '\r\n\r\nBody  line \r\n\r\n\r\n',
    'from: x@example.com\nsubject: bare LF\n\nline\twith\ttabs\nend',
    'From: a@example.com\r\nTo: one@x.example\r\nTo: two@x.example\r\n' +
      'Subject:  nbsp \r\n\r\n',
    'From: a@example.com\r\nMessage-ID: <1@x>\r\nReferences: <0@x>\r\n ' +
      '<9@x>\r\n\r\n \r\n\t\r\nlast'
  ];
  const dkim = [];
  messages.forEach(function (m, i) {
    ['rsa-sha256', 'ed25519-sha256'].forEach(function (alg) {
      const key = alg === 'rsa-sha256' ? keys.rsa : keys.ed25519;
      const field = crypto.dkimSign(Buffer.from(m, 'binary'), {
        privateKeyPem: key.privateKeyPem, selector: 's2026',
        domain: 'mail.example.com', algorithm: alg, timestamp: 1791100000 });
      const signed = field + '\r\n' + m;
      dkim.push({ name: 'message ' + i + ' ' + alg, algorithm: alg,
                  message: Buffer.from(m, 'binary').toString('base64'),
                  field: field,
                  verified: crypto.dkimVerify(Buffer.from(signed, 'binary'),
                                              key.publicKeyPem) });
    });
  });
  return { nfold: nfold, prf: prf, cf2: cf2, sessionStates: sessionStates,
           dkimKeys: keys, dkim: dkim };
}

// POST-QUANTUM KEYS IN X.509: for every algorithm pqc_x509.js knows — 15
// ML-DSA and SLH-DSA sets, 3 ML-KEM sets, 16 composites — a key pair, its
// SubjectPublicKeyInfo and PKCS#8 (all three CHOICE arms where there are
// three), and for the signature algorithms a signature. Every encoding is
// DER and so must be Rust's bytes; Rust must verify every signature, and
// Node verifies Rust's (tests/rust_crypto_vectors.js).
async function pqX509() {
  const pqcX509 = require(path.join(ROOT, 'common', 'vendored',
                                    'pqc_x509.js'));
  const message = Buffer.from('a certificate\'s to-be-signed bytes');
  const out = [];
  for (const id of pqcX509.algIds()) {
    const entry = pqcX509.alg(id);
    const pair = await pqcX509.generateKeyPair(id);
    const row = { id: id, family: entry.family, oid: entry.oid,
                  label: pqcX509.labelFor(id),
                  pub: Buffer.from(pair.pub).toString('base64'),
                  priv: Buffer.from(pair.priv).toString('base64'),
                  spki: Buffer.from(pqcX509.encodeSpki(id, pair.pub))
                    .toString('base64'),
                  pkcs8: {} };
    const forms = entry.family === 'ML-DSA' || entry.family === 'ML-KEM'
      ? ['seed', 'expandedKey', 'both'] : ['seed'];
    forms.forEach(function (form) {
      row.pkcs8[form] = Buffer.from(pqcX509.encodePkcs8(id, pair.priv,
                                                        { form: form }))
        .toString('base64');
    });
    if (entry.use === 'sig') {
      row.message = message.toString('base64');
      row.signature = Buffer.from(await pqcX509.sign(id, message, pair.priv))
        .toString('base64');
    }
    out.push(row);
  }
  return out;
}

const VECTORS = [{ file: 'jws-node.json', build: jws },
                 { file: 'jwe-node.json', build: jwe },
                 { file: 'c14n-node.json', build: c14n },
                 { file: 'xmldsig-node.json', build: xmldsig },
                 { file: 'xmlenc-node.json', build: xmlenc },
                 { file: 'secrets-node.json', build: secrets },
                 { file: 'krb5-dkim-node.json', build: kerberosAndDkim },
                 { file: 'pq-x509-node.json', build: pqX509 }];

if (require.main === module) {
  fs.mkdirSync(OUT, { recursive: true });
  // One at a time, awaiting a builder that is asynchronous (pqX509).
  (async function () {
    for (const one of VECTORS) {
      const built = await one.build();
      fs.writeFileSync(path.join(OUT, one.file),
                       JSON.stringify(built, null, 1) + '\n');
      console.log('wrote ' + path.relative(ROOT, path.join(OUT, one.file)));
    }
  })().catch(function (e) {
    console.error(e);
    process.exitCode = 1;
  });
}
