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

// SIGNATURES OVER RAW BYTES AND THE TPM (section 8): Node's verdict from
// verifyRawSignature() on a signature in every family and encoding — and on
// the same signature tampered with, under the wrong key and under the
// wrong salt — which Rust must give; TPM KDFa (deterministic, so Rust's
// bytes); MakeCredential's output with the endorsement key's private half,
// which Rust activates; and CMS SignedData made by the openssl command
// line, with the signer's certificate embedded and (AWS's shape) without.
async function rawSignatures() {
  const pqcX509 = require(path.join(ROOT, 'common', 'vendored',
                                    'pqc_x509.js'));
  const data = Buffer.from('a challenge the attestor signs');
  const spkiOf = function (pub) {
    return pub.export({ type: 'spki', format: 'der' });
  };
  const rows = [];
  const add = async function (name, scheme, spki, sig, wrongSpki) {
    const verdict = function (bytes, key) {
      return crypto.verifyRawSignature(scheme, crypto.publicKeyFromSpki(key),
                                       data, bytes);
    };
    const tampered = Buffer.from(sig);
    tampered[tampered.length - 1] ^= 1;
    rows.push({ name: name, scheme: scheme,
                spki: Buffer.from(spki).toString('base64'),
                wrongSpki: Buffer.from(wrongSpki).toString('base64'),
                signature: Buffer.from(sig).toString('base64'),
                ok: await verdict(sig, spki),
                tampered: await verdict(tampered, spki),
                wrongKey: await verdict(sig, wrongSpki) });
  };
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const ed448 = nodeCrypto.generateKeyPairSync('ed448');
  for (const hash of ['sha1', 'sha256', 'sha384', 'sha512']) {
    await add('rsa-pkcs1 ' + hash, { family: 'rsa-pkcs1', hash: hash },
              spkiOf(rsa.publicKey), nodeCrypto.sign(hash, data,
                { key: rsa.privateKey,
                  padding: nodeCrypto.constants.RSA_PKCS1_PADDING }),
              spkiOf(ed.publicKey));
  }
  for (const salt of [[20, 'auto'], [32, 32], [20, 32]]) {
    await add('rsa-pss sha256 salt ' + salt.join('/'),
              { family: 'rsa-pss', hash: 'sha256', saltLength: salt[1] },
              spkiOf(rsa.publicKey), nodeCrypto.sign('sha256', data,
                { key: rsa.privateKey,
                  padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                  saltLength: salt[0] }), spkiOf(ed.publicKey));
  }
  for (const curve of [['prime256v1', 'sha256'], ['secp384r1', 'sha384'],
                       ['secp521r1', 'sha512']]) {
    const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve[0] });
    for (const encoding of ['der', 'p1363']) {
      await add('ecdsa ' + curve[0] + ' ' + encoding,
                { family: 'ecdsa', hash: curve[1], encoding: encoding },
                spkiOf(ec.publicKey), nodeCrypto.sign(curve[1], data,
                  { key: ec.privateKey,
                    dsaEncoding: encoding === 'der' ? 'der'
                                                    : 'ieee-p1363' }),
                spkiOf(rsa.publicKey));
    }
  }
  await add('eddsa ed25519', { family: 'eddsa' }, spkiOf(ed.publicKey),
            nodeCrypto.sign(null, data, ed.privateKey), spkiOf(ed448.publicKey));
  await add('eddsa ed448', { family: 'eddsa' }, spkiOf(ed448.publicKey),
            nodeCrypto.sign(null, data, ed448.privateKey),
            spkiOf(ed.publicKey));
  for (const id of ['ML-DSA-44', 'SLH-DSA-SHA2-128f',
                    'mldsa65-rsa3072-pss-sha512', 'mldsa44-ed25519-sha512']) {
    const pair = await pqcX509.generateKeyPair(id);
    await add('pq ' + id, { family: 'pq' }, pqcX509.encodeSpki(id, pair.pub),
              await pqcX509.sign(id, data, pair.priv), spkiOf(rsa.publicKey));
  }
  const kdfa = [];
  [['sha256', 'STORAGE', 128], ['sha256', 'INTEGRITY', 256],
   ['sha1', 'X', 17], ['sha384', 'IDENTITY', 300]].forEach(function (r) {
    const key = nodeCrypto.randomBytes(16);
    const u = nodeCrypto.randomBytes(34);
    const v = nodeCrypto.randomBytes(5);
    kdfa.push({ hash: r[0], label: r[1], bits: r[2],
                key: key.toString('base64'), u: u.toString('base64'),
                v: v.toString('base64'),
                out: crypto.tpmKdfa(r[0], key, r[1], u, v, r[2])
                  .toString('base64') });
  });
  const ek = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akName = Buffer.concat([Buffer.from([0, 0x0b]),
                                nodeCrypto.randomBytes(32)]);
  const made = crypto.tpmMakeCredential(akName, ek.publicKey, 16,
                                        Buffer.from('the challenge'),
                                        'sha256');
  const credential = {
    akName: akName.toString('base64'),
    ekPrivatePem: ek.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    ekPublicPem: ek.publicKey.export({ type: 'spki', format: 'pem' }),
    secret: 'the challenge', credential: made.credential.toString('base64'),
    encryptedSecret: made.secret.toString('base64')
  };
  const integers = [['prime256v1', '0001', '02'], ['secp384r1', 'ff', '00ff'],
                    ['secp521r1', '01' + 'ab'.repeat(65), '7f'],
                    ['prime256v1', '01'.repeat(33), '02']].map(function (r) {
    const out = crypto.ecdsaIntegersToP1363(r[0], Buffer.from(r[1], 'hex'),
                                            Buffer.from(r[2], 'hex'));
    return { curve: r[0], r: r[1], s: r[2],
             out: out ? out.toString('hex') : null };
  });
  // CMS from the openssl command line.
  const os = require('os');
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cms-'));
  const pkcs7 = [];
  try {
    const run = function (args) {
      childProcess.execFileSync('openssl', args, { cwd: dir,
                                                   stdio: 'ignore' });
    };
    run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
         'key.pem', '-out', 'cert.pem', '-subj', '/CN=instance signer',
         '-days', '2']);
    fs.writeFileSync(path.join(dir, 'doc.json'),
                     '{"instanceId":"i-0123456789abcdef0","region":"eu-west-1"}');
    run(['cms', '-sign', '-nodetach', '-binary', '-in', 'doc.json',
         '-signer', 'cert.pem', '-inkey', 'key.pem', '-outform', 'DER',
         '-out', 'with.der']);
    run(['cms', '-sign', '-nodetach', '-binary', '-nocerts', '-in',
         'doc.json', '-signer', 'cert.pem', '-inkey', 'key.pem',
         '-outform', 'DER', '-out', 'without.der']);
    const certDer = new nodeCrypto.X509Certificate(
      fs.readFileSync(path.join(dir, 'cert.pem'))).raw;
    for (const c of [['embedded', 'with.der', []],
                     ['given', 'without.der', [certDer]],
                     ['missing', 'without.der', []]]) {
      const der = fs.readFileSync(path.join(dir, c[1]));
      const v = await crypto.verifyPkcs7SignedData(der,
                                                   { certificates: c[2] });
      pkcs7.push({ name: c[0], der: der.toString('base64'),
                   certificates: c[2].map(function (x) {
                     return Buffer.from(x).toString('base64');
                   }),
                   ok: v.ok, content: v.content
                     ? v.content.toString('base64') : null,
                   signer: v.signerDer ? v.signerDer.toString('base64')
                                       : null,
                   embedded: (v.embeddedDers || []).length });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { signatures: rows, kdfa: kdfa, credential: credential,
           integers: integers, pkcs7: pkcs7 };
}

// WEBAUTHN (section 10): Node's verdict from verifyCoseSignature() for
// every COSE algorithm — on the signature, tampered with, under the key of
// another algorithm, a fully specified one on the wrong curve, RS1 with and
// without the insecure flag — with the key as a JWK; and Node's parse of
// TPM structures and attestation extensions built field by field here.
function webauthn() {
  const asn1js = require('asn1js');
  const data = Buffer.from('authenticatorData || clientDataHash');
  const jwkOf = function (pub) {
    return pub.export({ format: 'jwk' });
  };
  const keyFor = {
    ec256: nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    ec384: nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }),
    ec521: nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' }),
    k1: nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' }),
    ed25519: nodeCrypto.generateKeyPairSync('ed25519'),
    ed448: nodeCrypto.generateKeyPairSync('ed448'),
    rsa: nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
    rsa1024: nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 1024 })
  };
  const plan = [
    [-7, 'ec256'], [-35, 'ec384'], [-36, 'ec521'], [-8, 'ed25519'],
    [-8, 'ed448'], [-257, 'rsa'], [-258, 'rsa'], [-259, 'rsa'],
    [-37, 'rsa'], [-38, 'rsa'], [-39, 'rsa'], [-9, 'ec256'], [-9, 'ec384'],
    [-51, 'ec384'], [-52, 'ec521'], [-47, 'k1'], [-19, 'ed25519'],
    [-19, 'ed448'], [-53, 'ed448'], [-65535, 'rsa'], [-257, 'rsa1024'],
    [-48, 'ML-DSA-44'], [-49, 'ML-DSA-65'], [-50, 'ML-DSA-87']
  ];
  const cose = plan.map(function (row) {
    const spec = crypto.coseSignatureAlg(row[0]);
    let jwk;
    let sig;
    if (spec.family === 'pq') {
      const pair = pqJose.generate(spec.name);
      jwk = { kty: 'AKP', alg: spec.name, pub: pair.pub.toString('base64url') };
      sig = Buffer.from(pqJose.sign(spec.name, pair.priv, data));
    } else {
      const pair = keyFor[row[1]];
      jwk = jwkOf(pair.publicKey);
      const opts = { key: pair.privateKey };
      if (spec.family === 'rsa-pss') {
        opts.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
        opts.saltLength = spec.saltLength;
      }
      if (spec.family === 'rsa-pkcs1') {
        opts.padding = nodeCrypto.constants.RSA_PKCS1_PADDING;
      }
      sig = nodeCrypto.sign(spec.hash, data, opts);
    }
    const tampered = Buffer.from(sig);
    tampered[tampered.length - 1] ^= 1;
    const other = jwkOf(keyFor[row[1] === 'rsa' ? 'ec256' : 'rsa'].publicKey);
    return { alg: row[0], key: row[1], jwk: jwk, wrongJwk: other,
             signature: sig.toString('base64'),
             ok: crypto.verifyCoseSignature(row[0], jwk, data, sig),
             okInsecure: crypto.verifyCoseSignature(row[0], jwk, data, sig,
                                                    { allowInsecure: true }),
             tampered: crypto.verifyCoseSignature(row[0], jwk, data,
                                                  tampered),
             wrongKey: crypto.verifyCoseSignature(row[0], other, data, sig) };
  });
  // TPM structures, built field by field.
  const u16 = function (n) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n, 0);
    return b;
  };
  const u32 = function (n) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };
  const sized = function (b) {
    return Buffer.concat([u16(b.length), b]);
  };
  const rsaPub = Buffer.concat([u16(0x0001), u16(0x000b), u32(0x00060472),
    sized(nodeCrypto.randomBytes(32)), u16(0x0010), u16(0x0014), u16(0x000b),
    u16(2048), u32(0), sized(nodeCrypto.randomBytes(256))]);
  const eccPub = Buffer.concat([u16(0x0023), u16(0x000b), u32(0x00050072),
    sized(Buffer.alloc(0)), u16(0x0006), u16(128), u16(0x0043), u16(0x001a),
    u16(0x000b), u16(1), u16(0x0003), u16(0x0010),
    sized(nodeCrypto.randomBytes(31)), sized(nodeCrypto.randomBytes(32))]);
  const badCurve = Buffer.concat([u16(0x0023), u16(0x000b), u32(0),
    sized(Buffer.alloc(0)), u16(0x0010), u16(0x0010), u16(0x0009),
    u16(0x0010), sized(Buffer.alloc(32)), sized(Buffer.alloc(32))]);
  const attest = Buffer.concat([u32(0xff544347), u16(0x8017),
    sized(nodeCrypto.randomBytes(34)), sized(nodeCrypto.randomBytes(32)),
    Buffer.from('0000000000abcdef', 'hex'), u32(7), u32(9), Buffer.from([1]),
    Buffer.from('0102030405060708', 'hex'), sized(nodeCrypto.randomBytes(34)),
    sized(nodeCrypto.randomBytes(34))]);
  const sigs = [
    Buffer.concat([u16(0x0014), u16(0x000b), sized(nodeCrypto.randomBytes(256))]),
    Buffer.concat([u16(0x0018), u16(0x000b), sized(Buffer.from('0102', 'hex')),
                   sized(Buffer.from('81ff', 'hex'))]),
    Buffer.concat([u16(0x0018), u16(0x000b), sized(nodeCrypto.randomBytes(32)),
                   sized(nodeCrypto.randomBytes(32))]),
    nodeCrypto.randomBytes(64)
  ];
  const tpm = {
    publics: [rsaPub, eccPub, badCurve, rsaPub.subarray(0, 20),
              Buffer.concat([eccPub, Buffer.from([0])])].map(function (b) {
      let parsed = null;
      let error = null;
      try {
        const p = crypto.tpmParsePublic(b);
        parsed = { type: p.type, nameAlg: p.nameAlg, attributes: p.attributes,
                   scheme: p.scheme, schemeHash: p.schemeHash,
                   keyBits: p.keyBits, exponent: p.exponent,
                   curveId: p.curveId, kdf: p.kdf, jwk: p.jwk,
                   name: crypto.tpmName(p).toString('base64') };
      } catch (e) {
        error = e.message;
      }
      return { bytes: b.toString('base64'), parsed: parsed, error: error };
    }),
    attest: (function () {
      const a = crypto.tpmParseAttest(attest);
      return { bytes: attest.toString('base64'), magic: a.magic,
               type: a.type, extraData: a.extraData.toString('base64'),
               clock: String(a.clock), resetCount: a.resetCount,
               restartCount: a.restartCount, safe: a.safe,
               firmwareVersion: String(a.firmwareVersion),
               name: a.name.toString('base64'),
               qualifiedName: a.qualifiedName.toString('base64') };
    })(),
    signatures: sigs.map(function (b) {
      const p = crypto.tpmParseSignature(b);
      return { bytes: b.toString('base64'),
               parsed: p ? { sigAlg: p.sigAlg, hash: p.hash,
                             signature: p.signature.toString('base64') }
                         : null };
    })
  };
  // Extensions.
  const der = function (schema) {
    return Buffer.from(schema.toBER(false));
  };
  const aaguid = nodeCrypto.randomBytes(16);
  const nonce = nodeCrypto.randomBytes(32);
  const ctx = function (n, inner) {
    return new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: n },
                                    value: [inner] });
  };
  const authList = function (purposes, all, origin) {
    const fields = [ctx(1, new asn1js.Set({ value: purposes.map(function (p) {
      return new asn1js.Integer({ value: p });
    }) }))];
    if (all) {
      fields.push(ctx(600, new asn1js.Null()));
    }
    if (origin !== null) {
      fields.push(ctx(702, new asn1js.Integer({ value: origin })));
    }
    return new asn1js.Sequence({ value: fields });
  };
  const challenge = nodeCrypto.randomBytes(32);
  const keyDescription = der(new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 200 }), new asn1js.Enumerated({ value: 1 }),
    new asn1js.Integer({ value: 200 }), new asn1js.Enumerated({ value: 1 }),
    new asn1js.OctetString({ valueHex: challenge }),
    new asn1js.OctetString({ valueHex: new Uint8Array(0) }),
    authList([2], false, null), authList([2, 3], true, 0)] }));
  const extensions = {
    aaguid: { value: der(new asn1js.OctetString({ valueHex: aaguid }))
      .toString('base64'),
              out: Buffer.from(crypto.fidoAaguidExtension(der(
                new asn1js.OctetString({ valueHex: aaguid })))).toString('base64') },
    apple: (function () {
      const v = der(new asn1js.Sequence({ value: [ctx(1,
        new asn1js.OctetString({ valueHex: nonce }))] }));
      return { value: v.toString('base64'),
               out: crypto.appleAttestationNonce(v).toString('base64') };
    })(),
    android: (function () {
      const d = crypto.androidKeyDescription(keyDescription);
      return { value: keyDescription.toString('base64'),
               attestationVersion: d.attestationVersion,
               attestationSecurityLevel: d.attestationSecurityLevel,
               attestationChallenge: d.attestationChallenge.toString('base64'),
               softwareEnforced: d.softwareEnforced,
               teeEnforced: d.teeEnforced };
    })()
  };
  // A CSR attestation bundle with a tcg-attest-tpm-certify statement.
  const certDer = new nodeCrypto.X509Certificate(
    require(path.join(ROOT, 'common', 'vendored', 'xmldsig.js'))
      .generateKeyPair(1024, 'bundle').certPem).raw;
  const stmt = new asn1js.Sequence({ value: [
    new asn1js.OctetString({ valueHex: sized(attest) }),
    new asn1js.OctetString({ valueHex: sigs[1] }),
    new asn1js.OctetString({ valueHex: rsaPub })] });
  const bundle = der(new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: '2.23.133.20.1' }), stmt] })] }),
    new asn1js.Sequence({ value: [
      asn1js.fromBER(new Uint8Array(certDer)).result,
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 3 },
                               value: [new asn1js.Null()] })] })] }));
  const b = crypto.csrAttestationBundle(bundle);
  const t = crypto.tcgTpmCertifyStatement(b.attestations[0].stmt);
  const csr = { bundle: bundle.toString('base64'),
                types: b.attestations.map(function (a) { return a.type; }),
                stmt: b.attestations[0].stmt.toString('base64'),
                certs: b.certs.map(function (c) { return c.toString('base64'); }),
                otherCerts: b.otherCerts,
                tpmSAttest: t.tpmSAttest.toString('base64'),
                signature: t.signature.toString('base64'),
                tpmTPublic: t.tpmTPublic.toString('base64') };
  return { cose: cose, tpm: tpm, extensions: extensions, csr: csr,
           brokenAlgorithms: require(path.join(ROOT, 'common', 'mode.js'))
             .usesBrokenAlgorithms() };
}

// SIGSTORE AND TUF (section 11): Node's two canonical forms over values
// that tell them apart (control characters, non-ASCII and astral keys,
// numbers JavaScript spells its own way); TUF threshold verdicts over keys
// of every kind cosign reads — Ed25519 as hex, ECDSA and RSA as PEM, a
// post-quantum PEM — with a keyid twice, a keyid the role does not name, a
// tampered signature, odd hex and thresholds Number() reads oddly; Rekor
// SETs good, tampered and from an unknown log; DSSE PAE and the two hashes.
async function sigstore() {
  const pqcX509 = require(path.join(ROOT, 'common', 'vendored',
                                    'pqc_x509.js'));
  const values = [
    null, true, 0, -0, 1, -17, 1e21, 1e20, 0.1, 1.5e-7, 123.456,
    5e-324, 9007199254740993, '', 'plain', 'a"b\\c', 'tab\there\nnl\r',
    '\u0000\u0001\u001f\u007f', '  ', 'café 😀',
    [1, [2, [3, {}]], []],
    { b: 1, a: 2, A: 3, '': 4, 'é': 5, '😀': 6,
      '￿': 7, 'aa': 8, 'a\u0000': 9 },
    { nested: { z: [true, false, null], y: 'x\u0007y' }, n: -12345678901 },
    { f: 1.25 }, [0.5]
  ];
  const canonical = values.map(function (v) {
    const row = { value: v, jcs: crypto.jcsCanonicalJson(v) };
    try {
      row.olpc = crypto.olpcCanonicalJson(v);
    } catch (e) {
      row.olpcError = e.message;
    }
    return row;
  });
  const pemOf = function (pub) {
    return pub.export({ type: 'spki', format: 'pem' });
  };
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const ec = nodeCrypto.generateKeyPairSync('ec',
                                            { namedCurve: 'prime256v1' });
  const ec384 = nodeCrypto.generateKeyPairSync('ec',
                                               { namedCurve: 'secp384r1' });
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pq = await pqcX509.generateKeyPair('ML-DSA-65');
  const pqSpki = Buffer.from(pqcX509.encodeSpki('ML-DSA-65', pq.pub));
  const signed = { _type: 'root', version: 7, expires: '2030-01-01T00:00:00Z',
                   note: 'ctl\u0001 café "q" \\', roles: { a: [1, 2] } };
  const bytes = Buffer.from(crypto.olpcCanonicalJson(signed), 'utf8');
  const sig = {
    ed: nodeCrypto.sign(null, bytes, ed.privateKey).toString('hex'),
    ec: nodeCrypto.sign('sha256', bytes, ec.privateKey).toString('hex'),
    ec384: nodeCrypto.sign('sha256', bytes, ec384.privateKey).toString('hex'),
    rsa: nodeCrypto.sign('sha256', bytes, rsa.privateKey).toString('hex'),
    pq: Buffer.from(await pqcX509.sign('ML-DSA-65', bytes, pq.priv))
      .toString('hex')
  };
  const edHex = ed.publicKey.export({ format: 'jwk' }).x;
  const keys = {
    ed: { keytype: 'ed25519', scheme: 'ed25519',
          keyval: { public: Buffer.from(edHex, 'base64url').toString('hex') } },
    ec: { keytype: 'ecdsa', scheme: 'ecdsa-sha2-nistp256',
          keyval: { public: pemOf(ec.publicKey) } },
    ec384: { keytype: 'ecdsa-sha2-nistp384', scheme: 'ecdsa-sha2-nistp384',
             keyval: { public: pemOf(ec384.publicKey) } },
    rsa: { keytype: 'rsa', scheme: 'rsassa-pss-sha256',
           keyval: { public: pemOf(rsa.publicKey) } },
    pq: { keytype: 'ml-dsa', scheme: 'ml-dsa-65',
          keyval: { public: crypto.publicKeyPemOfSpki(pqSpki) } },
    junk: { keytype: 'ecdsa', keyval: { public: 'not a key!' } },
    bare: { keytype: 'ecdsa',
            keyval: { public: pemOf(ec.publicKey)
              .replace(/-----[A-Z ]+-----/g, '') } }
  };
  const flip = function (hex) {
    return (hex[0] === '0' ? '1' : '0') + hex.slice(1);
  };
  const all = ['ed', 'ec', 'ec384', 'rsa', 'pq'];
  const cases = [
    { name: 'all five of five', role: { keyids: all, threshold: 5 },
      sigs: all.map(function (k) { return { keyid: k, sig: sig[k] }; }) },
    { name: 'one keyid twice', role: { keyids: all, threshold: 2 },
      sigs: [{ keyid: 'ed', sig: sig.ed }, { keyid: 'ed', sig: sig.ed }] },
    { name: 'a keyid the role does not name',
      role: { keyids: ['ed'], threshold: 2 },
      sigs: [{ keyid: 'ed', sig: sig.ed }, { keyid: 'ec', sig: sig.ec }] },
    { name: 'tampered', role: { keyids: all, threshold: 1 },
      sigs: all.map(function (k) { return { keyid: k, sig: flip(sig[k]) }; }) },
    { name: 'odd hex', role: { keyids: ['ed'], threshold: 1 },
      sigs: [{ keyid: 'ed', sig: sig.ed + 'a' }] },
    { name: 'not hex', role: { keyids: ['ed'], threshold: 1 },
      sigs: [{ keyid: 'ed', sig: sig.ed.slice(0, -1) + 'g' }] },
    { name: 'threshold zero', role: { keyids: all, threshold: 0 },
      sigs: [{ keyid: 'ed', sig: sig.ed }] },
    { name: 'threshold 1.5', role: { keyids: all, threshold: 1.5 },
      sigs: [{ keyid: 'ed', sig: sig.ed }] },
    { name: 'threshold "2"', role: { keyids: all, threshold: '2' },
      sigs: [{ keyid: 'ed', sig: sig.ed }, { keyid: 'rsa', sig: sig.rsa }] },
    { name: 'threshold "x"', role: { keyids: all, threshold: 'x' },
      sigs: [{ keyid: 'ed', sig: sig.ed }] },
    { name: 'a key that is not one', role: { keyids: ['junk'], threshold: 1 },
      sigs: [{ keyid: 'junk', sig: sig.ec }] },
    { name: 'a bare base64 PEM body', role: { keyids: ['bare'], threshold: 1 },
      sigs: [{ keyid: 'bare', sig: sig.ec }] },
    { name: 'no signatures', role: { keyids: all, threshold: 1 },
      sigs: 'none' },
    { name: 'a key under the wrong keyid', role: { keyids: all, threshold: 1 },
      sigs: [{ keyid: 'rsa', sig: sig.ec }] }
  ];
  const threshold = [];
  for (const c of cases) {
    const v = await crypto.verifyThresholdSignatures(signed, c.sigs, keys,
                                                     c.role);
    threshold.push({ name: c.name, role: c.role, signatures: c.sigs,
                     ok: v.ok, valid: v.valid, threshold: v.threshold });
  }
  const rekorKey = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'prime256v1' });
  const rekorSpki = rekorKey.publicKey.export({ type: 'spki', format: 'der' });
  const logIdHex = crypto.sha256Hex(rekorSpki);
  const payload = { body: 'eyJhIjoiXHUwMDAxIn0=', integratedTime: 1700000000,
                    logIndex: 123456789, logID: logIdHex };
  const set = nodeCrypto.sign('sha256',
                              Buffer.from(crypto.jcsCanonicalJson(payload)),
                              rekorKey.privateKey);
  const logs = [{ logIdHex: logIdHex.toUpperCase(),
                  spki: rekorSpki.toString('base64') }];
  const nodeLogs = [{ logIdHex: logIdHex.toUpperCase(), spki: rekorSpki }];
  const tampered = Object.assign({}, payload, { logIndex: 123456790 });
  const unknown = Object.assign({}, payload, { logID: 'ab'.repeat(32) });
  const rekor = [];
  for (const one of [{ name: 'good', payload: payload },
                     { name: 'tampered', payload: tampered },
                     { name: 'unknown log', payload: unknown }]) {
    rekor.push({ name: one.name, payload: one.payload,
                 answer: await crypto.verifyRekorSet(one.payload, set,
                                                     nodeLogs) });
  }
  const blobs = ['', 'abc', 'café', 'x'.repeat(1000)];
  return {
    canonical: canonical,
    signed: signed,
    keys: keys,
    threshold: threshold,
    rekor: { set: set.toString('base64'), logs: logs, cases: rekor },
    pae: blobs.map(function (b) {
      return { type: 'application/vnd.in-toto+json', payload: b,
               pae: crypto.dssePae('application/vnd.in-toto+json',
                                   Buffer.from(b)).toString('base64'),
               sha256: crypto.sha256Hex(Buffer.from(b)),
               sha512: crypto.sha512Hex(Buffer.from(b)) };
    }),
    spkiPem: crypto.publicKeyPemOfSpki(pqSpki),
    pqSpki: pqSpki.toString('base64')
  };
}

const VECTORS = [{ file: 'jws-node.json', build: jws },
                 { file: 'jwe-node.json', build: jwe },
                 { file: 'c14n-node.json', build: c14n },
                 { file: 'xmldsig-node.json', build: xmldsig },
                 { file: 'xmlenc-node.json', build: xmlenc },
                 { file: 'secrets-node.json', build: secrets },
                 { file: 'krb5-dkim-node.json', build: kerberosAndDkim },
                 { file: 'pq-x509-node.json', build: pqX509 },
                 { file: 'raw-sig-node.json', build: rawSignatures },
                 { file: 'webauthn-node.json', build: webauthn },
                 { file: 'sigstore-node.json', build: sigstore }];

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
