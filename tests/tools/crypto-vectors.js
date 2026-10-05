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
//   STS_ONLY=limbo node tests/tools/crypto-vectors.js   (one file's prefix)
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

// X.509 (the parent project's `x509.js`, which `sts-pki` ports): every
// profile, every extension with values of every kind, every signature
// algorithm under a chain, a hybrid certificate, PKCS#10 requests, and the
// refusals — each with Node's DER, its describeCertificate() and its
// verifyChain(), so Rust can issue the same spec and match the bytes where
// the signer is deterministic and the TBSCertificate everywhere.
async function x509Vectors() {
  const x509 = require(path.join(ROOT, 'common', 'vendored', 'x509.js'));
  const pqcX509 = require(path.join(ROOT, 'common', 'vendored',
                                    'pqc_x509.js'));
  const bytes = require(path.join(ROOT, 'common', 'vendored',
                                  'crypto_bytes.js'));
  const pair = function (type, options) {
    const k = nodeCrypto.generateKeyPairSync(type, options);
    return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
             pub: k.publicKey.export({ type: 'spki', format: 'pem' }) };
  };
  const pqPair = async function (id) {
    const k = await pqcX509.generateKeyPair(id);
    const out = { pub: bytes.derToPem(pqcX509.encodeSpki(id, k.pub),
                                      'PUBLIC KEY') };
    if (pqcX509.alg(id).use === 'sig') {
      out.priv = bytes.derToPem(pqcX509.encodePkcs8(id, k.priv,
                                                    { form: 'seed' }),
                                'PRIVATE KEY');
    }
    return out;
  };
  const keys = {
    rsa: pair('rsa', { modulusLength: 2048 }),
    rsa2: pair('rsa', { modulusLength: 3072 }),
    p256: pair('ec', { namedCurve: 'prime256v1' }),
    p384: pair('ec', { namedCurve: 'secp384r1' }),
    p521: pair('ec', { namedCurve: 'secp521r1' }),
    ed25519: pair('ed25519'),
    mldsa65: await pqPair('ML-DSA-65'),
    slh: await pqPair('SLH-DSA-SHA2-128f'),
    composite: await pqPair('mldsa65-ecdsa-p256-sha512'),
    mlkem: await pqPair('ML-KEM-768')
  };
  const keyFor = { 'sha256-rsa': 'rsa', 'sha384-rsa': 'rsa',
                   'sha512-rsa': 'rsa', 'sha1-rsa': 'rsa',
                   'sha256-rsapss': 'rsa', 'sha384-rsapss': 'rsa',
                   'sha512-rsapss': 'rsa', 'sha256-ecdsa': 'p256',
                   'sha384-ecdsa': 'p384', 'sha512-ecdsa': 'p521',
                   'sha1-ecdsa': 'p256', ed25519: 'ed25519',
                   'ml-dsa-65': 'mldsa65', 'slh-dsa-sha2-128f': 'slh',
                   'mldsa65-ecdsa-p256-sha512': 'composite' };
  const window = { notBefore: '2026-01-02T03:04:05.000Z',
                   notAfter: '2036-01-02T03:04:05.000Z' };
  const everything = x509.defaultExtensions('tls-server');
  Object.assign(everything.subjectAltName, { present: true, names: [
    { kind: 'dns', value: 'host.example' },
    { kind: 'email', value: 'a@example.com' },
    { kind: 'uri', value: 'spiffe://example.org/w' },
    { kind: 'ip', value: '192.0.2.7' },
    { kind: 'ip', value: '2001:db8::1' },
    { kind: 'dirName', value: 'CN=Inner, O=Org, C=US' },
    { kind: 'registeredID', value: '1.2.3.4.5' },
    { kind: 'upn', value: 'alice@example.com' },
    { kind: 'krb5', value: 'alice@EXAMPLE.COM' },
    { kind: 'otherName', oid: '1.2.3.9', value: 'DAVoZWxsbw==' }] });
  Object.assign(everything.issuerAltName, { present: true,
    names: [{ kind: 'uri', value: 'https://ca.example/' }] });
  Object.assign(everything.cRLDistributionPoints, { present: true,
    urls: ['http://crl.example/a.crl', 'http://crl.example/b.crl'] });
  Object.assign(everything.freshestCRL, { present: true,
    urls: ['http://crl.example/delta.crl'] });
  Object.assign(everything.authorityInfoAccess, { present: true, entries: [
    { method: 'ocsp', url: 'http://ocsp.example/' },
    { method: 'caIssuers', url: 'http://ca.example/ca.cer' }] });
  Object.assign(everything.subjectInfoAccess, { present: true, entries: [
    { method: 'caRepository', url: 'http://repo.example/' },
    { method: '1.2.3.4', url: 'http://other.example/' }] });
  Object.assign(everything.certificatePolicies, { present: true, policies: [
    { oid: '2.23.140.1.2.1' },
    { oid: '1.3.6.1.4.1.99.1', cps: 'https://cps.example/',
      notice: 'Notice text é' }] });
  Object.assign(everything.policyMappings, { present: true, mappings: [
    { issuer: '1.2.3.1', subject: '1.2.3.2' }] });
  Object.assign(everything.policyConstraints, { present: true,
    requireExplicitPolicy: '0', inhibitPolicyMapping: 3 });
  Object.assign(everything.nameConstraints, { present: true,
    permitted: [{ kind: 'dns', value: '.example' },
                { kind: 'ip', value: '10.0.0.0/12' },
                { kind: 'ip', value: '2001:db8::/32', minimum: 0,
                  maximum: '' },
                { kind: 'email', value: 'example.com', minimum: 1,
                  maximum: 5 }],
    excluded: [{ kind: 'dirName', value: 'O=Bad' }] });
  Object.assign(everything.inhibitAnyPolicy, { present: true,
    skipCerts: '2' });
  Object.assign(everything.privateKeyUsagePeriod, { present: true,
    notBefore: '2026-01-02T03:04:05Z', notAfter: '2027-06-30T00:00:00Z' });
  Object.assign(everything.tlsFeature, { present: true,
    features: [5, '17', 'x'] });
  Object.assign(everything.netscapeCertType, { present: true,
    types: ['sslServer', 'objectSigningCA'] });
  Object.assign(everything.netscapeComment, { present: true,
    text: 'a comment' });
  everything.ocspNoCheck.present = true;
  everything.extKeyUsage.usages.push('1.2.3.99', 'kdcAuthentication');
  everything.authorityKeyIdentifier.includeIssuerAndSerial = true;
  everything.custom = [{ oid: '1.2.3.77', critical: true, value: 'BQA=' },
                       { oid: '1.2.3.78', value: '' }];

  const certs = [];
  const issue = async function (name, spec, chain) {
    const row = { name: name, spec: spec };
    try {
      const out = await x509.issueCertificate(spec);
      row.der = Buffer.from(out.der).toString('base64');
      row.pem = out.pem;
      row.result = { serialHex: out.serialHex, subject: out.subject,
                     issuer: out.issuer, notBefore: out.notBefore,
                     notAfter: out.notAfter, signatureAlg: out.signatureAlg };
      row.describe = await x509.describeCertificate(out.pem);
      row.chain = [out.pem].concat(chain || []);
      row.links = await x509.verifyChain(row.chain);
    } catch (e) {
      row.error = e.message;
    }
    certs.push(row);
    return row;
  };
  const selfSigned = function (alg, extra) {
    const k = keys[keyFor[alg]];
    return Object.assign({ subject: 'CN=' + alg + ', O=Example, C=US',
                           subjectPublicKey: k.pub, issuerPrivateKey: k.priv,
                           signatureAlg: alg, serial: '0a1b2c', profile:
                           'root-ca' }, window, extra || {});
  };

  for (const id of x509.profileIds()) {
    await issue('profile ' + id, Object.assign({
      subject: [{ name: 'CN', value: x509.defaultSubjectCN(id) },
                { name: 'O', value: 'Example Corp' },
                { name: 'C', value: 'US' },
                { name: 'emailAddress', value: 'x@example.com' },
                { name: 'DC', value: 'example' },
                { oid: '1.2.3.4', value: 'custom' },
                { name: 'OU', value: '' }],
      subjectPublicKey: keys.rsa.pub, issuerPrivateKey: keys.rsa.priv,
      signatureAlg: 'sha256-rsa', serial: 'ff01', profile: id,
      extensions: x509.defaultExtensions(id) }, window));
  }
  const roots = {};
  for (const alg of Object.keys(keyFor)) {
    roots[alg] = await issue('self-signed ' + alg, selfSigned(alg));
  }
  // A leaf under each root, by a different key, with every extension.
  for (const alg of Object.keys(keyFor)) {
    const root = roots[alg];
    if (!root.pem) continue;
    const k = keys[keyFor[alg]];
    await issue('leaf under ' + alg, Object.assign({
      subject: 'CN=leaf ' + alg + ', O=Example, C=US',
      subjectPublicKey: keys.p256.pub,
      issuer: { certificatePem: root.pem, privateKeyPem: k.priv },
      signatureAlg: alg, serial: '00ab', extensions: everything
    }, window), [root.pem]);
  }
  await issue('an ML-KEM leaf', Object.assign({
    subject: 'CN=kem', subjectPublicKey: keys.mlkem.pub,
    issuer: { certificatePem: roots['sha256-rsa'].pem,
              privateKeyPem: keys.rsa.priv },
    signatureAlg: 'sha256-rsa', serial: '42', profile: 'key-encipherment'
  }, window), [roots['sha256-rsa'].pem]);
  await issue('after 2050, with milliseconds', selfSigned('ed25519', {
    notBefore: '2051-02-03T04:05:06.789Z',
    notAfter: '2061-02-03T04:05:06.000Z' }));
  await issue('no notAfter: the profile\'s years', selfSigned('ed25519', {
    notBefore: '2028-02-29T00:00:00.000Z', notAfter: undefined,
    profile: 'issuing-ca' }));
  await issue('no extensions: the profile\'s', selfSigned('sha256-rsa', {
    profile: 'ocsp-responder' }));
  await issue('extensions all absent', selfSigned('sha256-rsa', {
    extensions: { basicConstraints: { present: false } } }));
  await issue('a serial with its top bit set', selfSigned('sha256-rsa', {
    serial: '80:00:01' }));

  // The hybrid: a classical root with an ML-DSA alternative key, and a
  // leaf it signs both ways.
  const hybridRoot = await issue('hybrid root', selfSigned('sha256-rsa', {
    subjectAltPublicKey: keys.mldsa65.pub,
    altSignature: { signatureAlg: 'ml-dsa-65',
                    privateKeyPem: keys.mldsa65.priv } }));
  await issue('hybrid leaf', Object.assign({
    subject: 'CN=hybrid leaf', subjectPublicKey: keys.p256.pub,
    subjectAltPublicKey: keys.slh.pub,
    issuer: { certificatePem: hybridRoot.pem, privateKeyPem: keys.rsa.priv },
    signatureAlg: 'sha256-rsa', serial: '01',
    altSignature: { signatureAlg: 'ml-dsa-65',
                    privateKeyPem: keys.mldsa65.priv, critical: true },
    extensions: x509.defaultExtensions('tls-server') }, window),
  [hybridRoot.pem]);
  await issue('hybrid with an RSA-PSS alternative', selfSigned('ed25519', {
    subjectAltPublicKey: keys.rsa2.pub,
    altSignature: { signatureAlg: 'sha384-rsapss',
                    privateKeyPem: keys.rsa2.priv } }));

  // The refusals.
  const refusals = [
    ['an empty subject', selfSigned('sha256-rsa', { subject: '' })],
    ['an unknown algorithm', selfSigned('sha256-rsa',
                                        { signatureAlg: 'md5-rsa' })],
    ['a KEM as the algorithm', selfSigned('sha256-rsa',
                                          { signatureAlg: 'ML-KEM-768' })],
    ['no issuer key', selfSigned('sha256-rsa', { issuerPrivateKey: '' })],
    ['an unknown DN attribute', selfSigned('sha256-rsa', {
      subject: [{ name: 'XX', value: 'y' }] })],
    ['a bad otherName', selfSigned('sha256-rsa', { extensions: {
      subjectAltName: { present: true, names: [
        { kind: 'otherName', oid: '1.2.3', value: 'not base64!' }] } } })],
    ['an otherName that is not DER', selfSigned('sha256-rsa', {
      extensions: { subjectAltName: { present: true, names: [
        { kind: 'otherName', oid: '1.2.3', value: 'AAAA' }] } } })],
    ['an otherName with no OID', selfSigned('sha256-rsa', {
      extensions: { subjectAltName: { present: true, names: [
        { kind: 'otherName', value: 'BQA=' }] } } })],
    ['a bad IP', selfSigned('sha256-rsa', { extensions: {
      subjectAltName: { present: true, names: [
        { kind: 'ip', value: '300.1.1.1' }] } } })],
    ['a prefix out of range', selfSigned('sha256-rsa', { extensions: {
      nameConstraints: { present: true, permitted: [
        { kind: 'ip', value: '10.0.0.0/33' }] } } })],
    ['an unknown general name', selfSigned('sha256-rsa', { extensions: {
      subjectAltName: { present: true, names: [
        { kind: 'x400', value: 'q' }] } } })],
    ['an unknown alternative algorithm', selfSigned('sha256-rsa', {
      altSignature: { signatureAlg: 'nope', privateKeyPem: 'x' } })],
    ['an alternative with no key', selfSigned('sha256-rsa', {
      altSignature: { signatureAlg: 'ml-dsa-65' } })],
    ['a custom extension not base64', selfSigned('sha256-rsa', {
      extensions: { custom: [{ oid: '1.2.3', value: '$$' }] } })]
  ];
  for (const r of refusals) {
    await issue('refused: ' + r[0], r[1]);
  }

  const csrs = [];
  const csrSpecs = [
    ['RSA with everything', { subject: 'CN=req, O=Example',
      publicKeyPem: keys.rsa.pub, privateKeyPem: keys.rsa.priv,
      subjectAltName: [{ kind: 'uri', value: 'spiffe://example.org/w' },
                       { kind: 'dns', value: 'w.example' }],
      keyUsage: ['digitalSignature', 'keyAgreement'],
      extKeyUsage: ['clientAuth'],
      basicConstraints: { ca: true, pathLen: 0 } }],
    ['RSA-PSS', { subject: 'CN=pss', publicKeyPem: keys.rsa.pub,
                  privateKeyPem: keys.rsa.priv,
                  signatureAlg: 'sha512-rsapss' }],
    ['P-384 by default', { subject: 'C=US, O=SPIRE',
                           publicKeyPem: keys.p384.pub,
                           privateKeyPem: keys.p384.priv }],
    ['Ed25519', { subject: [{ name: 'CN', value: 'ed' }],
                  publicKeyPem: keys.ed25519.pub,
                  privateKeyPem: keys.ed25519.priv, keyUsage: [] }],
    ['ML-DSA-65', { subject: 'CN=pq', publicKeyPem: keys.mldsa65.pub,
                    privateKeyPem: keys.mldsa65.priv,
                    extKeyUsage: ['serverAuth'] }],
    ['refused: no subject', { subject: '', publicKeyPem: keys.rsa.pub,
                              privateKeyPem: keys.rsa.priv }],
    ['refused: no public key', { subject: 'CN=x',
                                 privateKeyPem: keys.rsa.priv }],
    ['refused: no private key', { subject: 'CN=x',
                                  publicKeyPem: keys.rsa.pub }],
    ['refused: a KEM key', { subject: 'CN=x', publicKeyPem: keys.mlkem.pub,
                             privateKeyPem: keys.rsa.priv }],
    ['refused: an unknown algorithm', { subject: 'CN=x',
      publicKeyPem: keys.rsa.pub, privateKeyPem: keys.rsa.priv,
      signatureAlg: 'nope' }]
  ];
  for (const c of csrSpecs) {
    const row = { name: c[0], spec: c[1] };
    try {
      const out = await x509.certificationRequest(c[1]);
      row.der = Buffer.from(out.der).toString('base64');
      row.subject = out.subject;
      row.signatureAlg = out.signatureAlg;
    } catch (e) {
      row.error = e.message;
    }
    csrs.push(row);
  }
  const ecdsa = [];
  for (let i = 0; i < 40; i++) {
    const raw = nodeCrypto.randomBytes(132);
    if (i % 3 === 0) raw.fill(0, 0, 2);
    if (i % 5 === 0) raw.fill(0, 66, 68);
    if (i % 7 === 0) raw[0] = 0x80;
    const der = x509.ecdsaRawToDer(raw);
    ecdsa.push({ raw: raw.toString('base64'),
                 der: Buffer.from(der).toString('base64'),
                 back: Buffer.from(x509.ecdsaDerToRaw(der, 66))
                   .toString('base64') });
  }
  return { keys: keys, certificates: certs, requests: csrs, ecdsa: ecdsa,
           defaults: x509.profileIds().map(function (id) {
             return { id: id, extensions: x509.defaultExtensions(id),
                      cn: x509.defaultSubjectCN(id),
                      san: x509.defaultSubjectAltName(id) };
           }),
           signatureAlgorithms: ['rsa', 'ec', 'okp'].map(function (kind) {
             return { kind: kind, ids: x509.signatureAlgorithmsFor(kind) };
           }),
           parsedDns: ['CN=a, O=b (x, y), C=US', 'bogus=1, 2.5.4.3=q',
                       ' CN = spaced ,,O=', 'no equals'].map(function (t) {
             return { text: t, attrs: x509.parseDnString(t) };
           }) };
}

// PATH VALIDATION (`pki.js`'s RFC 5280 rules, #201): Node's verdict on every
// C2SP x509-limbo case through `verifyPathToAnchors()` and
// `verifyIssuedDirectly()`, at the case's validation time (or the instant
// recorded beside it), for `sts-pki`'s path module to give. Only when
// STS_X509_LIMBO_DIR names the fetched corpus
// (`tests/tools/fetch-x509-limbo.sh`).
async function limbo() {
  const dir = process.env.STS_X509_LIMBO_DIR;
  if (!dir) {
    return null;
  }
  const pki = require(path.join(ROOT, 'common', 'pki.js'));
  const bytes = require(path.join(ROOT, 'common', 'vendored',
                                  'crypto_bytes.js'));
  const corpus = JSON.parse(fs.readFileSync(path.join(dir, 'limbo.json'),
                                            'utf8'));
  const derOf = function (pem) {
    return Buffer.from(bytes.pemToDer(pem));
  };
  const now = Date.now();
  const out = [];
  for (const t of corpus.testcases) {
    const at = t.validation_time ? Date.parse(t.validation_time) : now;
    const anchors = t.trusted_certs.map(function (pem) {
      return pki.certificateFromDer(derOf(pem));
    }).filter(Boolean);
    const a = await pki.verifyPathToAnchors(derOf(t.peer_certificate),
      t.untrusted_intermediates.map(derOf), anchors, { now: at });
    const d = pki.verifyIssuedDirectly(derOf(t.peer_certificate),
      t.trusted_certs.map(derOf), { now: at });
    out.push({ id: t.id, now: at,
               anchors: { ok: a.ok, check: a.check || '',
                          reason: a.reason || '',
                          chain: (a.chain || []).length,
                          policies: a.policies || [] },
               direct: { ok: d.ok, check: d.check || '',
                         reason: d.reason || '',
                         index: d.index === undefined ? null : d.index } });
  }
  return { cases: out };
}

// SOMEBODY ELSE'S CERTIFICATES (`pki.js` #40, #105, #170, #62 P5): PEM
// bundles, WebAuthn attestation certificate facts, OpenSSH keys and host
// certificates (written here field by field, PROTOCOL.certkeys), the FIDO
// MDS3 BLOB under a generated chain, sigstore signer facts, and embedded
// SCTs from a generated CT log — each with Node's answer.
async function foreign() {
  const pki = require(path.join(ROOT, 'common', 'pki.js'));
  const x509 = require(path.join(ROOT, 'common', 'vendored', 'x509.js'));
  const pqcX509 = require(path.join(ROOT, 'common', 'vendored',
                                    'pqc_x509.js'));
  const bytes = require(path.join(ROOT, 'common', 'vendored',
                                  'crypto_bytes.js'));
  const pair = function (type, options) {
    const k = nodeCrypto.generateKeyPairSync(type, options);
    return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
             pub: k.publicKey.export({ type: 'spki', format: 'pem' }),
             privateKey: k.privateKey, publicKey: k.publicKey };
  };
  const window = { notBefore: '2026-01-01T00:00:00.000Z',
                   notAfter: '2036-01-01T00:00:00.000Z' };
  const now = Date.parse('2027-06-01T00:00:00.000Z');
  const rsa = pair('rsa', { modulusLength: 2048 });
  const p256 = pair('ec', { namedCurve: 'prime256v1' });
  const p384 = pair('ec', { namedCurve: 'secp384r1' });
  const ed = pair('ed25519');
  const pq = await pqcX509.generateKeyPair('ML-DSA-65');
  const pqPub = bytes.derToPem(pqcX509.encodeSpki('ML-DSA-65', pq.pub),
                               'PUBLIC KEY');
  const root = await x509.issueCertificate(Object.assign({
    subject: 'CN=Foreign Root, O=Example, C=US', subjectPublicKey: rsa.pub,
    issuerPrivateKey: rsa.priv, signatureAlg: 'sha256-rsa', serial: '01',
    profile: 'root-ca' }, window));
  const inter = await x509.issueCertificate(Object.assign({
    subject: 'CN=Foreign Intermediate, O=Example', subjectPublicKey: p384.pub,
    issuer: { certificatePem: root.pem, privateKeyPem: rsa.priv },
    signatureAlg: 'sha256-rsa', serial: '02', profile: 'intermediate-ca' },
    window));
  const leafOf = async function (subject, pub, extensions, serial) {
    return x509.issueCertificate(Object.assign({
      subject: subject, subjectPublicKey: pub,
      issuer: { certificatePem: inter.pem, privateKeyPem: p384.priv,
                keyAlg: 'ec-p384' },
      signatureAlg: 'sha384-ecdsa', serial: serial || '03',
      extensions: extensions }, window));
  };
  const leafExt = x509.defaultExtensions('tls-client');
  const sanExt = x509.defaultExtensions('digital-signature');
  Object.assign(sanExt.subjectAltName, { present: true, critical: true,
    names: [{ kind: 'dirName',
              value: '2.23.133.2.1=id:414D4400, 2.23.133.2.2=SLB9670, ' +
                     '2.23.133.2.3=id:0D' },
            { kind: 'dns', value: 'tpm.example' },
            { kind: 'ip', value: '192.0.2.1' }] });
  Object.assign(sanExt.extKeyUsage, { present: true,
                                      usages: ['2.23.133.8.3'] });
  const leaves = {
    rsa: await leafOf('CN=leaf rsa, O=Vendor, OU=Authenticator Attestation, ' +
                      'C=US', rsa.pub, leafExt),
    p256: await leafOf('CN=leaf p256, O=Vendor', p256.pub, leafExt, '04'),
    ed: await leafOf('CN=leaf ed', ed.pub, leafExt, '05'),
    pq: await leafOf('CN=leaf ml-dsa', pqPub, x509.defaultExtensions(
      'digital-signature'), '06'),
    tpm: await leafOf([{ name: 'CN', value: '' }], p256.pub, sanExt, '07')
  };
  const bundleText = [root.pem, 'junk', inter.pem,
                      '-----BEGIN CERTIFICATE-----\nAAAA\n' +
                      '-----END CERTIFICATE-----\n', leaves.rsa.pem]
    .join('\n');
  const attestation = {};
  for (const name of Object.keys(leaves)) {
    const der = Buffer.from(leaves[name].der);
    const facts = pki.attestationCertificateFacts(der);
    const ext = {};
    Object.keys(facts.extensions).forEach(function (oid) {
      ext[oid] = { critical: facts.extensions[oid].critical,
                   value: facts.extensions[oid].value.toString('base64') };
    });
    facts.extensions = ext;
    attestation[name] = { der: der.toString('base64'), facts: facts,
                          keyIdentifier: pki.attestationKeyIdentifier(der),
                          rsaBits: pki.rsaKeyBits(pki.certificateFromDer(der)) };
  }

  // OpenSSH, written out.
  const u32 = function (n) {
    const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b;
  };
  const u64 = function (n) {
    const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b;
  };
  const str = function (v) {
    const b = Buffer.from(v); return Buffer.concat([u32(b.length), b]);
  };
  const mpint = function (v) {
    let b = Buffer.from(v);
    while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return str(b);
  };
  const sshKey = function (kp, type) {
    const jwk = kp.publicKey.export({ format: 'jwk' });
    const b = function (x) { return Buffer.from(x, 'base64url'); };
    if (type === 'ssh-rsa') {
      return { type: type, fields: Buffer.concat([mpint(b(jwk.e)),
                                                  mpint(b(jwk.n))]) };
    }
    if (type === 'ssh-ed25519') {
      return { type: type, fields: str(b(jwk.x)) };
    }
    const curve = type.replace('ecdsa-sha2-', '');
    return { type: type, fields: Buffer.concat([str(curve), str(
      Buffer.concat([Buffer.from([4]), b(jwk.x), b(jwk.y)]))]) };
  };
  const blobOf = function (k) {
    return Buffer.concat([str(k.type), k.fields]);
  };
  const sshSign = function (kp, type, data, format) {
    if (type === 'ssh-rsa') {
      const hash = { 'ssh-rsa': 'sha1', 'rsa-sha2-256': 'sha256',
                     'rsa-sha2-512': 'sha512' }[format];
      return Buffer.concat([str(format), str(nodeCrypto.sign(hash, data,
                                                              kp.privateKey))]);
    }
    if (type === 'ssh-ed25519') {
      return Buffer.concat([str(type), str(nodeCrypto.sign(null, data,
                                                            kp.privateKey))]);
    }
    const hash = { 'ecdsa-sha2-nistp256': 'sha256',
                   'ecdsa-sha2-nistp384': 'sha384',
                   'ecdsa-sha2-nistp521': 'sha512' }[type];
    const raw = nodeCrypto.sign(hash, data, { key: kp.privateKey,
                                               dsaEncoding: 'ieee-p1363' });
    const half = raw.length / 2;
    return Buffer.concat([str(type), str(Buffer.concat([
      mpint(raw.subarray(0, half)), mpint(raw.subarray(half))]))]);
  };
  const options = function (pairs) {
    return Buffer.concat(pairs.map(function (p) {
      return Buffer.concat([str(p[0]), str(p[1] === '' ? Buffer.alloc(0)
                                                         : str(p[1]))]);
    }));
  };
  const sshKeys = {
    'ssh-rsa': pair('rsa', { modulusLength: 2048 }),
    'ecdsa-sha2-nistp256': pair('ec', { namedCurve: 'prime256v1' }),
    'ecdsa-sha2-nistp384': pair('ec', { namedCurve: 'secp384r1' }),
    'ecdsa-sha2-nistp521': pair('ec', { namedCurve: 'secp521r1' }),
    'ssh-ed25519': pair('ed25519')
  };
  const certOf = function (subjectType, caType, spec) {
    const subject = sshKey(sshKeys[subjectType], subjectType);
    const ca = sshKey(sshKeys[caType], caType);
    const body = Buffer.concat([
      str(subjectType + '-cert-v01@openssh.com'), str(Buffer.alloc(32, 7)),
      subject.fields, u64(spec.serial || 1), u32(spec.kind || 2),
      str(spec.keyId || 'host key'),
      str(Buffer.concat((spec.principals || []).map(str))),
      u64(spec.validAfter === undefined ? 0 : spec.validAfter),
      u64(spec.validBefore === undefined ? '18446744073709551615'
                                         : spec.validBefore),
      str(options(spec.critical || [])), str(options(spec.extensions || [])),
      str(Buffer.alloc(0)), str(blobOf(ca))]);
    let signature = sshSign(sshKeys[caType], caType, body,
                            spec.format || caType);
    if (spec.tamper) {
      signature = Buffer.from(signature);
      signature[signature.length - 1] ^= 1;
    }
    return Buffer.concat([body, str(signature)]);
  };
  const ssh = { keys: [], certs: [], authorized: [] };
  for (const type of Object.keys(sshKeys)) {
    const blob = blobOf(sshKey(sshKeys[type], type));
    const parsed = pki.parseSshPublicKey(blob);
    const data = Buffer.from('data the key signs');
    const formats = type === 'ssh-rsa'
      ? ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'] : [type];
    const signatures = [];
    for (const f of formats) {
      const sig = sshSign(sshKeys[type], type, data, f);
      const r = { format: f, blob: Buffer.alloc(0) };
      const inner = sig.subarray(4 + sig.readUInt32BE(0));
      r.blob = inner.subarray(4, 4 + inner.readUInt32BE(0));
      signatures.push({ format: f, blob: r.blob.toString('base64'),
                        ok: await pki.verifySshSignature(parsed, data, r),
                        wrongFormat: await pki.verifySshSignature(parsed, data,
                          { format: 'ssh-ed25519x', blob: r.blob }) });
    }
    ssh.keys.push({ type: type, blob: blob.toString('base64'),
                    fingerprint: pki.sshFingerprint(parsed),
                    curve: parsed.curve, data: data.toString('base64'),
                    signatures: signatures });
  }
  const authority = pki.parseSshPublicKey(blobOf(sshKey(sshKeys['ssh-ed25519'],
                                                        'ssh-ed25519')));
  const certSpecs = [
    ['good', 'ecdsa-sha2-nistp256', 'ssh-ed25519',
     { principals: ['host.example'], validAfter: 1000,
       validBefore: 4000000000 }],
    ['any principal', 'ssh-rsa', 'ssh-ed25519', {}],
    ['other principal', 'ssh-ed25519', 'ssh-ed25519',
     { principals: ['other.example'] }],
    ['a user certificate', 'ssh-ed25519', 'ssh-ed25519', { kind: 1 }],
    ['expired', 'ssh-ed25519', 'ssh-ed25519', { validBefore: 1000 }],
    ['not yet', 'ssh-ed25519', 'ssh-ed25519', { validAfter: 4000000000 }],
    ['a critical option', 'ssh-ed25519', 'ssh-ed25519',
     { critical: [['force-command', '/bin/true']] }],
    ['source-address only', 'ssh-ed25519', 'ssh-ed25519',
     { critical: [['source-address', '10.0.0.0/8']],
       extensions: [['permit-pty', '']] }],
    ['tampered', 'ssh-ed25519', 'ssh-ed25519', { tamper: true }],
    ['unknown authority', 'ssh-ed25519', 'ecdsa-sha2-nistp384', {}],
    ['an RSA authority, SHA-512', 'ssh-ed25519', 'ssh-rsa',
     { format: 'rsa-sha2-512' }]
  ];
  const rsaAuthority = pki.parseSshPublicKey(blobOf(sshKey(sshKeys['ssh-rsa'],
                                                           'ssh-rsa')));
  for (const c of certSpecs) {
    const blob = certOf(c[1], c[2], c[3]);
    let parsed = null;
    let error = '';
    try {
      parsed = pki.parseSshPublicKey(blob);
    } catch (e) {
      error = e.message;
    }
    const row = { name: c[0], blob: blob.toString('base64'), error: error };
    if (parsed) {
      row.parsed = { type: parsed.type, certType: parsed.certType,
                     serial: String(parsed.serial), kind: parsed.kind,
                     keyId: parsed.keyId, principals: parsed.principals,
                     validAfter: String(parsed.validAfter),
                     validBefore: String(parsed.validBefore),
                     criticalOptions: parsed.criticalOptions,
                     extensions: parsed.extensions,
                     fingerprint: pki.sshFingerprint(parsed),
                     authority: pki.sshFingerprint(parsed.signatureKey) };
      row.check = await pki.checkSshHostCertificate(parsed, 'host.example',
        [authority, rsaAuthority], now / 1000);
    }
    ssh.certs.push(row);
  }
  ssh.authorityBlobs = [authority.blob.toString('base64'),
                        rsaAuthority.blob.toString('base64')];
  const edBlob = blobOf(sshKey(sshKeys['ssh-ed25519'], 'ssh-ed25519'))
    .toString('base64');
  for (const line of ['ssh-ed25519 ' + edBlob + ' alice@host',
                      'command="echo \\"hi there\\"",no-pty ssh-ed25519 ' +
                        edBlob,
                      '# ssh-ed25519 ' + edBlob, '', 'ssh-rsa ' + edBlob,
                      'from="a b" ecdsa-sha2-nistp256 ' + Buffer.from(
                        blobOf(sshKey(sshKeys['ecdsa-sha2-nistp256'],
                                      'ecdsa-sha2-nistp256')))
                        .toString('base64') + ' c']) {
    const k = pki.parseSshAuthorizedKey(line);
    ssh.authorized.push({ line: line,
                          fingerprint: k ? pki.sshFingerprint(k) : null });
  }

  // The FIDO MDS3 BLOB.
  const mdsSigner = await leafOf('CN=MDS signer', p256.pub,
                                 x509.defaultExtensions('digital-signature'),
                                 '08');
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  const derB64 = function (pem) {
    return Buffer.from(bytes.pemToDer(pem)).toString('base64');
  };
  const jwsOf = function (header, payload, key, alg) {
    const input = b64u(header) + '.' + b64u(payload);
    const sig = alg === 'ES256'
      ? nodeCrypto.sign('sha256', Buffer.from(input), { key: key,
                                                        dsaEncoding: 'ieee-p1363' })
      : nodeCrypto.sign('sha256', Buffer.from(input), key);
    return input + '.' + sig.toString('base64url');
  };
  const blobPayload = { no: 42, nextUpdate: '2027-07-01',
                        legalHeader: 'x', entries: [{ aaguid: 'a' }] };
  const x5c = [derB64(mdsSigner.pem), derB64(inter.pem)];
  const goodBlob = jwsOf({ alg: 'ES256', typ: 'JWT', x5c: x5c }, blobPayload,
                         p256.privateKey, 'ES256');
  const otherRoot = await x509.issueCertificate(Object.assign({
    subject: 'CN=Other Root', subjectPublicKey: ed.pub,
    issuerPrivateKey: ed.priv, signatureAlg: 'ed25519', serial: '09',
    profile: 'root-ca' }, window));
  const blobs = [
    ['good', goodBlob, root.pem, false],
    ['good, overridden anyway', goodBlob, root.pem, true],
    ['not a JWS', 'a.b', root.pem, false],
    ['no x5c', jwsOf({ alg: 'ES256' }, blobPayload, p256.privateKey, 'ES256'),
     root.pem, false],
    ['the wrong anchor', goodBlob, otherRoot.pem, false],
    ['the wrong anchor, overridden', goodBlob, otherRoot.pem, true],
    ['a tampered signature', goodBlob.slice(0, -4) + 'AAAA', root.pem, false],
    ['a tampered signature, overridden', goodBlob.slice(0, -4) + 'AAAA',
     root.pem, true],
    ['RS256 by an EC key', jwsOf({ alg: 'RS256', x5c: x5c }, blobPayload,
                                 rsa.privateKey, 'RS256'), root.pem, false],
    ['not a BLOB', jwsOf({ alg: 'ES256', x5c: x5c }, { hello: 1 },
                         p256.privateKey, 'ES256'), root.pem, false],
    ['no anchors', goodBlob, '', false]
  ];
  const mds = [];
  for (const b of blobs) {
    const anchors = b[2] ? pki.certificateBundle(b[2]).certificates : [];
    const v = b[2] || b[3] ? await pki.verifyFidoMdsBlob(b[1], {
      anchorsPem: b[2], now: now, overrideSignature: b[3] }) : null;
    mds.push({ name: b[0], token: b[1], anchors: b[2], override: b[3],
               verdict: v, anchorCount: anchors.length });
  }

  // Sigstore signer facts and an embedded SCT.
  const fulcio = x509.defaultExtensions('code-signing');
  Object.assign(fulcio.subjectAltName, { present: true, critical: true,
    names: [{ kind: 'email', value: 'signer@example.com' },
            { kind: 'uri', value: 'https://github.com/o/r/.github/w.yml@x' }] });
  fulcio.custom = [
    { oid: '1.3.6.1.4.1.57264.1.1',
      value: Buffer.concat([Buffer.from([0x0c, 23]),
                            Buffer.from('https://issuer.v1.example')
                              .subarray(0, 23)]).toString('base64') },
    { oid: '1.3.6.1.4.1.57264.1.8',
      value: 'DBdodHRwczovL2lzc3Vlci52Mi5leGFtcGxl' }];
  const ctLog = pair('ec', { namedCurve: 'prime256v1' });
  const ctSpki = ctLog.publicKey.export({ type: 'spki', format: 'der' });
  const logId = nodeCrypto.createHash('sha256').update(ctSpki).digest();
  const pre = await leafOf([{ name: 'CN', value: '' }], p256.pub, fulcio,
                          '0a');
  const preTbs = Buffer.from(pkiTbs(pre.der));
  const ts = 1767500000000;
  const issuerKeyHash = nodeCrypto.createHash('sha256').update(Buffer.from(
    bytes.pemToDer(p384.pub))).digest();
  const t8 = Buffer.alloc(8); t8.writeBigUInt64BE(BigInt(ts));
  const len3 = Buffer.alloc(3); len3.writeUIntBE(preTbs.length, 0, 3);
  const signed = Buffer.concat([Buffer.from([0, 0]), t8, Buffer.from([0, 1]),
                                issuerKeyHash, len3, preTbs,
                                Buffer.from([0, 0])]);
  const sctSig = nodeCrypto.sign('sha256', signed, ctLog.privateKey);
  const sct = Buffer.concat([Buffer.from([0]), logId, t8, Buffer.from([0, 0]),
                             Buffer.from([4, 3]), u16(sctSig.length), sctSig]);
  const junkSct = Buffer.concat([Buffer.from([1]), Buffer.alloc(50)]);
  const list = Buffer.concat([u16(junkSct.length), junkSct, u16(sct.length),
                              sct]);
  const listWrapped = Buffer.concat([u16(list.length), list]);
  const sctExt = JSON.parse(JSON.stringify(fulcio));
  sctExt.custom.push({ oid: '1.3.6.1.4.1.11129.2.4.2',
                       value: derOctetString(listWrapped)
                         .toString('base64') });
  const withSct = await leafOf([{ name: 'CN', value: '' }], p256.pub,
                              sctExt, '0a');
  const logs = [{ logIdHex: logId.toString('hex'), spki: ctSpki }];
  const sctCases = [];
  for (const c of [['good', withSct.der, logs],
                   ['no SCT', pre.der, logs],
                   ['an unknown log', withSct.der, [{ logIdHex: '00'.repeat(32),
                                                      spki: ctSpki }]],
                   ['outside the log key window', withSct.der,
                    [{ logIdHex: logId.toString('hex'), spki: ctSpki,
                       startMs: ts + 1 }]],
                   ['the wrong log key', withSct.der,
                    [{ logIdHex: logId.toString('hex'),
                       spki: p256.publicKey.export({ type: 'spki',
                                                     format: 'der' }) }]]]) {
    sctCases.push({ name: c[0], leaf: Buffer.from(c[1]).toString('base64'),
                    logs: c[2].map(function (l) {
                      return { logIdHex: l.logIdHex,
                               spki: Buffer.from(l.spki).toString('base64'),
                               startMs: l.startMs || null };
                    }),
                    verdict: await pki.verifyEmbeddedScts(Buffer.from(c[1]),
                      Buffer.from(bytes.pemToDer(inter.pem)), c[2]) });
  }
  const sigstoreFacts = pki.sigstoreSignerFacts(Buffer.from(withSct.der));
  sigstoreFacts.spki = sigstoreFacts.spki.toString('base64');
  return {
    now: now,
    bundle: { text: bundleText,
              described: pki.describeCertificateBundle(bundleText, now) },
    attestation: attestation,
    ssh: ssh,
    mds: mds,
    sigstore: { der: Buffer.from(withSct.der).toString('base64'),
                facts: sigstoreFacts },
    scts: { issuer: derB64(inter.pem), cases: sctCases }
  };
}

function u16(n) {
  const b = Buffer.alloc(2); b.writeUInt16BE(n); return b;
}

// An OCTET STRING around bytes, for an extension value.
function derOctetString(content) {
  const len = content.length < 128 ? Buffer.from([content.length])
    : content.length < 256 ? Buffer.from([0x81, content.length])
      : Buffer.from([0x82, content.length >> 8, content.length & 0xff]);
  return Buffer.concat([Buffer.from([0x04]), len, content]);
}

// A certificate's TBSCertificate, as it is encoded.
function pkiTbs(der) {
  const pkijs = require('pkijs');
  return pkijs.Certificate.fromBER(new Uint8Array(der)).tbsView;
}

// TRUST REALMS (`common/realms.js`): with realms really created here, Node's
// answer for every id, domain and path question `sts-core::realm` answers —
// under three values of `realms.pathSegment`, the EST label position
// included.
function realmsVectors() {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const realms = require(path.join(ROOT, 'common', 'realms.js'));
  const profiles = require(path.join(ROOT, 'common',
                                     'enrollment_profiles.js'));
  const created = [
    realms.create({ id: 'acme', name: 'Acme', domain: 'Acme.Example.COM.' }),
    realms.create({ id: 'dev', name: 'Dev', domain: 'dev.acme.example.com' }),
    realms.create({ id: 'x1', name: 'X1' }),
    realms.create({ id: 'bücher', name: 'bad' }),
    realms.create({ id: 'zz', name: 'bad domain', domain: 'acme.example.com' })
  ].map(function (r) {
    return { ok: r.ok, errors: r.errors,
             realm: r.realm ? { id: r.realm.id, domain: r.realm.domain }
                            : null };
  });
  const ids = ['acme', 'default', 'Upper', '-lead', 'a'.repeat(31),
               'a'.repeat(32), 'ok-1', 'x1', 'simpleenroll', '', 'b_c'];
  const domains = ['example.com', 'acme.example.com', 'new.example.org',
                   'nodot', '123.456', 'a..b', '-x.com', 'x-.com',
                   'é.example', 'x.' + 'a'.repeat(64) + '.com', ''];
  const paths = ['/', '/realm/acme/oauth2/token', '/realm/acme',
                 '/realm/acme/', '/realm/nope/oauth2/token', '/acme/x',
                 '/t/acme/x', '/.well-known/est/acme/simpleenroll',
                 '/.well-known/est/simpleenroll',
                 '/.well-known/est/newrealm/cacerts',
                 '/.well-known/est/tls-server/simpleenroll', '/realm/x1',
                 '/realm/Bad/x', '/oauth2/token', '/dev/a/b'];
  const bySegment = [];
  for (const segment of ['realm', '', '/t/']) {
    config.setOverride('realms.pathSegment', segment);
    bySegment.push({
      segment: segment,
      prefixes: realms.list().map(function (r) {
        return realms.prefixOf(r);
      }),
      matches: paths.map(function (p) {
        const m = realms.matchPath(p);
        return { path: p, match: m ? { realm: m.realm.id, rest: m.rest,
                                       est: m.form === 'est-label' } : null,
                 unknown: realms.unknownRealmPath(p) };
      }),
      hrefs: realms.run(realms.get('acme'), function () {
        return ['/oauth2/token', '/realm/acme/x', 'https://a/b', 'rel',
                realms.currentPrefix()].map(realms.href);
      })
    });
  }
  config.clearOverride('realms.pathSegment');
  return {
    globalDomain: config.value('global.domain'),
    estLabels: profiles.EST_LABELS,
    created: created,
    ids: ids.map(function (id) {
      return { id: id, errors: realms.validateId(id) };
    }),
    domains: domains.map(function (d) {
      return { raw: d, normalized: realms.normalizeDomain(d),
               errors: realms.validateDomain(realms.normalizeDomain(d),
                                             'new') };
    }),
    baseDns: realms.list().map(function (r) {
      return { id: r.id, domain: realms.domainOf(r),
               baseDn: realms.baseDnOf(r),
               est: realms.estLabelPath(r) };
    }),
    mail: realms.run(realms.get('dev'), function () {
      return ['alice', 'bob@x.org', '@lead'].map(realms.inventedMailOf);
    }),
    bySegment: bySegment
  };
}

// THE LDIF STORE (`persistence/persistence_ldif.js`): the files Node's
// driver writes for entries that exercise every encoding rule — a leading
// space, colon or '<', a trailing space, CR, LF, NUL, non-ASCII, a line
// long enough to fold — and its parse of LDIF it did not write (folded
// lines, CRLF, URL values, a line before any dn:, comments).
async function ldifVectors() {
  const os = require('os');
  const driverModule = require(path.join(ROOT, 'persistence',
                                         'persistence_ldif.js'));
  const bunyan = require('bunyan');
  const log = bunyan.createLogger({ name: 'vectors', level: 'fatal' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ldif-vectors-'));
  const driver = driverModule.create({ dir: dir, log: log });
  await driver.open();
  const entries = [
    { dn: 'dc=example,dc=com', origin: 'seed',
      attributes: { objectClass: ['top', 'domain'], dc: ['example'],
                    createTimestamp: ['20260101000000Z'] } },
    { dn: 'cn=Zoë Ünïcode,ou=people,dc=example,dc=com',
      attributes: { cn: ['Zoë Ünïcode'], description: [' leading',
        'trailing ', ':colon', '<angle', 'line\nbreak', 'cr\rhere',
        'nul\u0000x', '', 'plain value', 'x'.repeat(200)],
        mail: ['zoe@example.com'],
        modifyTimestamp: ['20260102000000Z'] } },
    { dn: 'uid=' + 'long'.repeat(30) + ',dc=example,dc=com',
      attributes: { uid: ['long'.repeat(30)] } }
  ];
  const all = new Map([['default', entries], ['acme', entries.slice(1)]]);
  await driver.saveDirectory({ removedRealms: [], touched: ['default',
                                                           'acme'],
                               all: all });
  await driver.saveRealms([{ id: 'acme', name: 'Acme', domain: 'a.example',
                             overrides: { 'x.y': 3, 'z': 'é' } }]);
  await driver.saveOverrides({ 'global.logLevel': 'debug', 'n': 0.5 });
  const files = {};
  fs.readdirSync(dir).sort().forEach(function (name) {
    files[name] = fs.readFileSync(path.join(dir, name), 'utf8');
  });
  const foreign = [
    'version: 1\r\n\r\n# sts-origin: seed\r\ndn: cn=a,dc=x\r\ncn: a\r\n' +
      'description: folded\r\n  across lines\r\n\r\n',
    'cn: before any dn\ndn: cn=b,dc=x\njpegPhoto:< file:///etc/passwd\n' +
      'CN:: w6k=\nsn:value-with-no-space\nsn:  two spaces\n\n' +
      '# sts-origin: lost\n\ndn: cn=c,dc=x\nnocolon\n',
    'dn:: Y249ZMOpLGRjPXg=\ncreateTimestamp: 20250101000000Z\n'
  ];
  const parsed = foreign.map(function (t) {
    return driverModule.fromLdif(t, log);
  });
  const reread = await driver.loadDirectory();
  fs.rmSync(dir, { recursive: true, force: true });
  return { entries: entries, files: files, foreign: foreign,
           parsed: parsed, reread: reread };
}

// THE THREE-WAY MERGE (`persistence/directory_merge.js`): every combination
// of base, mine and theirs drawn from a pool of entries built to reach each
// branch — one entry and two (by entryUUID), a seeded entry with no
// entryUUID, single-valued credentials, `member` and an unlisted attribute
// that is a list only by count, the timestamps, origins — plus
// `mergeValues()` and `canonicalJson()` alone.
function mergeVectors() {
  const merge = require(path.join(ROOT, 'persistence', 'directory_merge.js'));
  const e = function (uuid, attrs, extra) {
    const a = Object.assign({}, attrs);
    if (uuid) {
      a.entryuuid = [uuid];
    }
    return Object.assign({ dn: 'cn=g,dc=x', attributes: a,
                           createdAt: '20260101000000Z',
                           modifiedAt: '20260101000000Z' }, extra || {});
  };
  const U1 = 'AAAA-1';
  const U2 = 'bbbb-2';
  const pool = [
    null,
    e(U1, { objectclass: ['top', 'groupOfNames'], member: ['a'],
            cn: ['g'] }),
    e(U1, { objectclass: ['top', 'groupOfNames'], member: ['a', 'b'],
            cn: ['g'], modifytimestamp: ['20260103000000Z'] },
      { modifiedAt: '20260103000000Z' }),
    e('aaaa-1', { objectclass: ['top', 'groupOfNames'], member: ['c'],
                  cn: ['g2'], userpassword: ['p1'],
                  modifytimestamp: ['20260102000000Z'] },
      { modifiedAt: '20260102000000Z', origin: 'scim' }),
    e(U1, { objectclass: ['top'], cn: ['g'], userpassword: ['p2'],
            mail: ['x@y', 'z@y'], createtimestamp: ['20250101000000Z'] }),
    e(U2, { objectclass: ['top', 'person'], cn: ['h'], sn: ['s'],
            member: ['a', 'd'] }, { origin: 'seed', createdAt: '' }),
    e(U2, { objectclass: ['top', 'person'], cn: ['h'], mail: ['z@y'],
            userpassword: ['p3'] }, { modifiedAt: null }),
    e('', { objectclass: ['top', 'groupOfNames'], member: ['e'],
            cn: ['g'] }),
    e(U1, { objectclass: ['top', 'groupOfNames'], cn: ['g'],
            mail: ['x@y'], member: [] })
  ];
  const cases = [];
  pool.forEach(function (base, bi) {
    pool.forEach(function (mine, mi) {
      pool.forEach(function (theirs, ti) {
        cases.push({ base: bi, mine: mi, theirs: ti,
                     result: merge.mergeEntry(base, mine, theirs) });
      });
    });
  });
  const lists = [undefined, [], ['a'], ['a', 'b'], ['b', 'c'], ['c', 'a', 'd']];
  const values = [];
  lists.forEach(function (b) {
    lists.forEach(function (m) {
      lists.forEach(function (t) {
        values.push({ base: b === undefined ? null : b,
                      mine: m === undefined ? null : m,
                      theirs: t === undefined ? null : t,
                      merged: merge.mergeValues(b, m, t) || null });
      });
    });
  });
  return { pool: pool, cases: cases, values: values,
           canonical: pool.map(function (one) {
             return merge.canonicalJson(one);
           }),
           single: merge.SINGLE, multi: merge.MULTI };
}

// THE SCHEDULER'S CORE (`cluster/scheduler.ts`, #49): a Scheduler built with
// stand-in deps over settings the vectors carry, and a set of job
// descriptors both sides build the same jobs from. Slots, schedule text,
// off-reasons, next delays, run ids, row ranks and expiries, refused
// registrations, and croner's previous and next occurrence (the npm
// package's, which the Rust crate must read alike).
function schedulerVectors() {
  const S = require(path.join(ROOT, 'cluster', 'scheduler.js')).Scheduler;
  const bunyan = require('bunyan');
  const settings = { 'scheduler.enabled': true, 'scheduler.tickS': 15,
                     'scheduler.disabledJobs': ['x.listed'],
                     'scheduler.maxConcurrentRuns': 4,
                     'scheduler.runTimeoutS': 300,
                     'scheduler.runHistoryCount': 50,
                     'scheduler.runHistoryHours': 24,
                     'a.everyS': 30, 'a.everyMin': 0, 'a.everyH': 2,
                     'a.everyDays': 3, 'a.everyMs': 250 };
  let pool = 0;
  const sched = new S({
    log: bunyan.createLogger({ name: 'vectors', level: 'fatal' }),
    config: { value: function (k) { return settings[k]; } },
    realms: { list: function () { return [{ id: 'default' }]; },
              run: function (r, fn) { return fn(); },
              get: function () { return null; }, DEFAULT_ID: 'default' },
    errorCodes: require(path.join(ROOT, 'common', 'error_codes.js')),
    audit: { record: function () {} },
    cluster: {}, claims: {}, store: { realmMap: function () {
      return new Map();
    } },
    dbNow: function () { return Promise.resolve(0); },
    now: function () { return 0; },
    setTimer: function () { return null; }, clearTimer: function () {},
    cronPrev: S.cronPrev, cronNext: S.cronNext,
    storeConnections: function () { return pool; },
    host: 'h', pid: 1, isRequestWorker: function () { return false; }
  });
  const descriptors = [
    { id: 'a.seconds', everySetting: 'a.everyS' },
    { id: 'a.minutes', everySetting: 'a.everyMin', unit: 'min' },
    { id: 'a.hours', everySetting: 'a.everyH', unit: 'h', scope: 'realm',
      off: { acme: 'acme is retiring' } },
    { id: 'a.days', everySetting: 'a.everyDays', unit: 'days',
      timeoutS: 7 },
    { id: 'a.millis', everySetting: 'a.everyMs', unit: 'ms',
      kind: 'per-process', quiet: true },
    { id: 'b.fixed', everyMs: 90000, kind: 'per-process' },
    { id: 'b.fraction', everyMs: 1500.5 },
    { id: 'c.nightly', cron: '0 3 * * *' },
    { id: 'c.seconds', cron: '*/20 * * * * *' },
    { id: 'd.manual', manualOnly: true },
    { id: 'x.listed', everyMs: 1000 },
    { id: 'x.throws', everyMs: 5000, offThrows: 'no store' }
  ];
  const specOf = function (d) {
    const spec = { id: d.id, title: 'T ' + d.id, describe: 'D', owner: 'O',
                   run: function () { return null; } };
    ['kind', 'scope', 'quiet', 'cron', 'manualOnly', 'everySetting',
     'timeoutS'].forEach(function (k) {
      if (d[k] !== undefined) {
        spec[k] = d[k];
      }
    });
    if (d.unit) {
      spec.everySettingUnit = d.unit;
    }
    if (d.everyMs !== undefined) {
      spec.everyMs = function () { return d.everyMs; };
    }
    if (d.off) {
      spec.off = function (realm) { return d.off[realm] || ''; };
    }
    if (d.offThrows) {
      spec.off = function () { throw new Error(d.offThrows); };
    }
    return spec;
  };
  descriptors.forEach(function (d) {
    sched.register(specOf(d));
  });
  const times = [0, 999, 1000, 29999, 30000, Date.UTC(2026, 0, 2, 3, 0, 0),
                 Date.UTC(2026, 0, 2, 3, 0, 0, 999),
                 Date.UTC(2026, 0, 2, 2, 59, 59, 999),
                 Date.UTC(2026, 9, 5, 9, 17, 41, 123)];
  const jobs = descriptors.map(function (d) {
    const job = sched.job(d.id);
    return {
      id: d.id,
      interval: sched.intervalMs(job),
      text: sched.scheduleText(job),
      off: ['default', 'acme'].map(function (r) {
        return sched.offReason(job, r);
      }),
      timeout: sched.timeoutMsOf(job),
      slots: times.map(function (t) { return sched.slotAt(job, t); }),
      runIds: [0, 1, 1767322800000].map(function (slot) {
        return sched.runIdFor(job, 'acme', slot);
      })
    };
  });
  const delays = times.map(function (t) {
    sched.deps.now = function () { return t; };
    return { cluster: sched.nextDelayMs('cluster'),
             perProcess: sched.nextDelayMs('per-process') };
  });
  const concurrency = [0, 1, 2, 3, 10].map(function (n) {
    pool = n;
    return sched.maxConcurrentRuns();
  });
  const refused = [
    { id: 'Bad', title: '', describe: 'd', owner: 'o', everyMs: 1 },
    { id: 'one', title: 't', describe: 'd', owner: 'o', everyMs: 1 },
    { id: 'c.broken', title: 't', describe: 'd', owner: ' ',
      cron: '61 * * * *' },
    { id: 'q.quiet', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      quiet: true },
    { id: 'p.manual', title: 't', describe: 'd', owner: 'o',
      kind: 'per-process', manualOnly: true },
    { id: 'a.seconds', title: 't', describe: 'd', owner: 'o', everyMs: 1 }
  ].map(function (d) {
    try {
      sched.register(specOf(d));
      return { descriptor: d, error: null };
    } catch (e) {
      return { descriptor: d, error: e.message };
    }
  });
  const rows = [
    { kind: 'run', jobId: 'a.seconds', state: 'succeeded', endedAt: 1000 },
    { kind: 'run', jobId: 'a.seconds', state: 'running', endedAt: 1000 },
    { kind: 'run', jobId: 'c.nightly', state: 'failed', endedAt: 1000 },
    { kind: 'run', jobId: 'nope.job', state: 'failed', endedAt: 1000 },
    { kind: 'run', jobId: 'a.hours', state: 'abandoned', updatedAt: '5000',
      keepUntil: 9e12 },
    { kind: 'process', jobId: 'a.millis', endedAt: 7 },
    { kind: 'process', jobId: 'b.fixed', queuedAt: 7 },
    { kind: 'process', jobId: 'b.fixed' },
    { kind: 'command', state: 'queued', queuedAt: 3 },
    { kind: 'command', state: 'succeeded', queuedAt: 3 },
    { kind: 'leader', updatedAt: 3 }
  ];
  const expiries = rows.map(function (r) { return sched.expiryOf(r); });
  const ranks = [
    [{ attempt: 1 }, { attempt: 2 }],
    [{ attempt: 2, fenceAt: 1 }, { attempt: 2, fenceAt: 0 }],
    [{ state: 'running' }, { state: 'queued' }],
    [{ state: 'failed' }, { state: 'running', updatedAt: 9 }],
    [{ state: 'failed', updatedAt: 2 }, { state: 'succeeded', updatedAt: 2 }],
    [{ attempt: '3' }, { attempt: 3 }],
    [{ attempt: 'x' }, {}]
  ].map(function (pair) {
    return { a: pair[0], b: pair[1], order: S.compareRows(pair[0], pair[1]) };
  });
  const exprs = ['0 3 * * *', '*/20 * * * * *', '15 14 1 * *',
                 '0 0 * * MON', '0 0 29 2 *', '5 4 * * SUN',
                 '61 * * * *', 'not cron', '* * * *'];
  const cron = exprs.map(function (expr) {
    let error = null;
    try {
      S.cronNext(expr, 0);
    } catch (e) {
      error = e.message;
    }
    return { expr: expr, valid: error === null,
             at: error ? [] : times.map(function (t) {
               // croner 10 THROWS for some previous occurrences before the
               // epoch's first (a TypeError inside recurseBackward); that is
               // recorded as the answer, and Rust answers none there.
               const guard = function (fn) {
                 try {
                   return fn(expr, t);
                 } catch (e) {
                   return 'throws';
                 }
               };
               return { t: t, prev: guard(S.cronPrev),
                        next: guard(S.cronNext) };
             }) };
  });
  return { settings: settings, descriptors: descriptors, times: times,
           jobs: jobs, delays: delays, concurrency: concurrency,
           refused: refused, rows: rows, expiries: expiries, ranks: ranks,
           cron: cron,
           spans: [0, 499, 500, 1000, 59499, 59500, 60000, 252000, 3600000,
                   3660000, 7500000, 86400000, 7776000000, 90061000, -5],
           spanText: [0, 499, 500, 1000, 59499, 59500, 60000, 252000,
                      3600000, 3660000, 7500000, 86400000, 7776000000,
                      90061000, -5].map(S.span) };
}

// THE SCHEDULER'S HISTORY AND REPORT (`cluster/scheduler.ts`, #338 and the
// status /admin/scheduler draws): the TypeScript Scheduler over a store the
// vectors carry — runs finished, running and queued, old and new, process
// rows, commands, the leader's row, rows of a realm that is gone — asked
// for its purge plan, its status (whole and confined to a realm), recent
// runs by filter, a run by id, and then made to purge in small batches.
async function schedulerHistoryVectors() {
  const S = require(path.join(ROOT, 'cluster', 'scheduler.js')).Scheduler;
  const bunyan = require('bunyan');
  const H = 3600000;
  const now = Date.UTC(2026, 9, 5, 12, 0, 0);
  const settings = { 'scheduler.enabled': true, 'scheduler.tickS': 15,
                     'scheduler.disabledJobs': ['x.off', 'nobody.here'],
                     'scheduler.maxConcurrentRuns': 4,
                     'scheduler.runTimeoutS': 300,
                     'scheduler.runHistoryCount': 2,
                     'scheduler.runHistoryHours': 1 };
  const realmIds = ['default', 'acme'];
  const store = new Map(realmIds.concat(['gone']).map(function (r) {
    return [r, new Map()];
  }));
  const settles = [];
  const sched = new S({
    log: bunyan.createLogger({ name: 'vectors', level: 'fatal' }),
    config: { value: function (k) { return settings[k]; } },
    realms: { list: function () {
      return realmIds.map(function (id) { return { id: id }; });
    }, run: function (r, fn) { return fn(); },
    get: function (id) {
      return realmIds.indexOf(id) >= 0 ? { id: id } : null;
    }, DEFAULT_ID: 'default' },
    errorCodes: require(path.join(ROOT, 'common', 'error_codes.js')),
    audit: { record: function () {} },
    cluster: { enabled: function () { return true; },
               nodeId: function () { return 'n1'; },
               nodeName: function () { return 'node-one'; },
               state: function () {
                 return Promise.resolve({ leases: [{ name: 'ops.scheduler',
                   holder: 'node-n1', token: 12, acquiredAt: now - H,
                   expiresAt: now + 30000 }] });
               } },
    claims: {},
    store: { realmMap: function (id) {
      if (!store.has(id)) {
        store.set(id, new Map());
      }
      return store.get(id);
    } },
    dbNow: function () { return Promise.resolve(now); },
    now: function () { return now; },
    setTimer: function () { return null; }, clearTimer: function () {},
    cronPrev: S.cronPrev, cronNext: S.cronNext,
    settle: function () {
      settles.push(Array.from(store.get('default').keys()).length);
      return Promise.resolve(null);
    },
    host: 'h1', pid: 41, isRequestWorker: function () { return false; }
  });
  const descriptors = [
    { id: 'a.every', everyMs: 10 * 60000 },
    { id: 'a.realm', everyMs: 30 * 60000, scope: 'realm' },
    { id: 'a.night', cron: '0 3 * * *' },
    { id: 'a.manual', manualOnly: true },
    { id: 'p.pull', everyMs: 1000, kind: 'per-process', quiet: true },
    { id: 'p.sweep', everyMs: 0, kind: 'per-process' },
    { id: 'x.off', everyMs: 60000 }
  ];
  descriptors.forEach(function (d) {
    const spec = { id: d.id, title: 'T ' + d.id, describe: 'D', owner: 'O',
                   run: function () { return null; } };
    ['kind', 'scope', 'quiet', 'cron', 'manualOnly'].forEach(function (k) {
      if (d[k] !== undefined) {
        spec[k] = d[k];
      }
    });
    if (d.everyMs !== undefined) {
      spec.everyMs = function () { return d.everyMs; };
    }
    sched.register(spec);
  });
  sched.leading = true;
  const rows = [];
  const put = function (realm, row) {
    rows.push({ realm: realm, row: row });
  };
  // a.every: five finished in the default realm, ended 10 min apart.
  for (let i = 0; i < 5; i++) {
    put('default', { runId: 'e' + i, kind: 'run', jobId: 'a.every',
                     realm: 'default', trigger: 'schedule',
                     state: i === 3 ? 'failed' : 'succeeded', attempt: 1,
                     fenceAt: now - (i + 1) * 40 * 60000 - 5,
                     startedAt: now - (i + 1) * 40 * 60000,
                     endedAt: now - (i + 1) * 40 * 60000 + 900,
                     durationMs: 900, result: 'ok ' + i,
                     errorCode: i === 3 ? 'STS-SCHED-0001' : '',
                     why: i === 3 ? 'no luck' : '', node: 'n1', pid: 41,
                     updatedAt: now - (i + 1) * 40 * 60000 + 900 });
  }
  // The current slot of a.every is running; a manual run queued.
  put('default', { runId: sched.runIdFor(sched.job('a.every'), 'default',
                                          Math.floor(now / 600000)),
                   kind: 'run', jobId: 'a.every', realm: 'default',
                   trigger: 'schedule', state: 'running', attempt: 1,
                   fenceAt: now - 1000, startedAt: now - 1000,
                   dueAt: now - (now % 600000), node: 'n1', pid: 41,
                   updatedAt: now - 1000 });
  put('default', { runId: 'm-queued', kind: 'run', jobId: 'a.manual',
                   realm: 'default', trigger: 'manual', state: 'queued',
                   params: { x: 1 }, requestedBy: 'alice',
                   requestedVia: '/admin/scheduler', queuedAt: now - 2000,
                   attempt: 0, fenceAt: 0, updatedAt: now - 2000 });
  // a.realm in acme: old, three of them; one abandoned.
  ['r0', 'r1', 'r2'].forEach(function (id, i) {
    put('acme', { runId: id, kind: 'run', jobId: 'a.realm', realm: 'acme',
                  trigger: 'schedule',
                  state: i === 2 ? 'abandoned' : 'succeeded',
                  abandonedOf: i === 2 ? 'r1' : undefined,
                  startedAt: now - (i + 2) * H, endedAt: now - (i + 2) * H,
                  attempt: i + 1, fenceAt: 0,
                  updatedAt: now - (i + 2) * H });
  });
  // a.night: one, three days ago, and a pinned one older still.
  put('default', { runId: 'night1', kind: 'run', jobId: 'a.night',
                   realm: 'default', trigger: 'schedule', state: 'succeeded',
                   startedAt: now - 72 * H, endedAt: now - 72 * H,
                   updatedAt: now - 72 * H });
  // A job nobody registers any more.
  put('default', { runId: 'old1', kind: 'run', jobId: 'gone.job',
                   realm: 'default', state: 'succeeded',
                   endedAt: now - 5 * H, updatedAt: now - 5 * H });
  put('default', { runId: 'old2', kind: 'run', jobId: 'gone.job',
                   realm: 'default', state: 'succeeded',
                   endedAt: now - 10 * 60000, updatedAt: now - 10 * 60000 });
  // Process rows: current, stale, and of a removed realm.
  put('default', { runId: 'process|p.pull|default|n1|41', kind: 'process',
                   jobId: 'p.pull', realm: 'default', state: 'succeeded',
                   nodeName: 'node-one', pid: 41, startedAt: now - 500,
                   endedAt: now - 400, nextAt: now + 600, slot: 7,
                   updatedAt: now - 400 });
  put('default', { runId: 'process|p.pull|default|n2|9', kind: 'process',
                   jobId: 'p.pull', realm: 'default', state: 'failed',
                   errorCode: 'STS-SCHED-0015', why: 'boom',
                   nodeName: 'node-two', pid: 9, worker: true,
                   startedAt: now - 3 * H, endedAt: now - 3 * H,
                   updatedAt: now - 3 * H });
  put('default', { runId: 'process|p.pull|gone|n1|41', kind: 'process',
                   jobId: 'p.pull', realm: 'gone', state: 'succeeded',
                   endedAt: now - 1000, updatedAt: now - 1000 });
  // Commands: one queued, one old and obeyed, one recent and obeyed.
  put('default', { runId: 'command|q', kind: 'command',
                   command: 'step-down', state: 'queued',
                   requestedBy: 'bob', queuedAt: now - 3000,
                   leaderAtRequest: { node: 'n1', pid: 41, token: 12 },
                   updatedAt: now - 3000 });
  put('default', { runId: 'command|old', kind: 'command',
                   command: 'step-down', state: 'succeeded',
                   queuedAt: now - 6 * H, endedAt: now - 6 * H,
                   obeyedBy: { node: 'n1' }, updatedAt: now - 6 * H });
  put('default', { runId: 'command|new', kind: 'command',
                   command: 'step-down', state: 'succeeded',
                   queuedAt: now - 60000, endedAt: now - 59000,
                   updatedAt: now - 59000 });
  // The leader.
  put('default', { runId: 'leader', kind: 'leader', node: 'n1',
                   nodeName: 'node-one', host: 'h1', pid: 41, token: 12,
                   since: now - H, lastTickAt: now - 5000, event: 'tick',
                   clustered: true, updatedAt: now - 5000 });
  // A finished run in the default realm's partition naming a removed realm.
  put('default', { runId: 'orphan', kind: 'run', jobId: 'a.realm',
                   realm: 'gone', state: 'succeeded', endedAt: now - 1000,
                   updatedAt: now - 1000 });
  rows.forEach(function (one) {
    store.get(one.realm).set(one.row.runId, JSON.parse(JSON.stringify(
      one.row)));
  });
  const keysOf = function (list) {
    return list.map(function (one) { return one.realm + '|' + one.key; });
  };
  const plan = sched.historyPlan(now);
  const status = await sched.status({});
  const acme = await sched.status({ realm: 'acme' });
  const queries = [{}, { job: 'a.every' }, { outcome: 'failed' },
                   { realm: 'acme' }, { realm: 'acme', job: 'a.every' }];
  const recent = queries.map(function (q) {
    return { query: q, runs: sched.recentRuns(q, now).map(function (r) {
      return r.runId;
    }) };
  });
  const found = ['e1', 'process|p.pull|default|n1|41', 'leader', 'nope']
    .map(function (id) { return sched.findRun(id); });
  const expiries = rows.map(function (one) {
    return sched.expiryOf(one.row);
  });
  const purged = await sched.purgeHistory({ batch: 3, maxBatches: 2,
                                            at: now });
  const remaining = {};
  store.forEach(function (m, realm) {
    remaining[realm] = Array.from(m.keys());
  });
  const pinned = [];
  store.forEach(function (m, realm) {
    m.forEach(function (r) {
      if (r.keepUntil) {
        pinned.push(realm + '|' + r.runId + '|' + r.keepUntil);
      }
    });
  });
  return { now: now, settings: settings, descriptors: descriptors,
           realms: realmIds, rows: rows,
           plan: { deletes: keysOf(plan.deletes), pins: keysOf(plan.pins) },
           status: status, acme: acme, recent: recent, found: found,
           expiries: expiries, purged: purged, remaining: remaining,
           pinned: pinned, settles: settles };
}

// A TRUST REALM'S LIFE (`common/realms.js`): realms created, refused,
// changed one setting and whole, cleared, and removed, in development and in
// a realm carrying product mode. The keys a refusal is about are chosen from
// config.js's own table (a restart-only one, a per-process one, a
// development-only one), so the vectors name them for the Rust side.
async function realmLifecycleVectors() {
  const realms = require(path.join(ROOT, 'common', 'realms.js'));
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const errorCodes = require(path.join(ROOT, 'common', 'error_codes.js'));
  const rows = config.SETTINGS || config.settings || config.rows;
  const all = typeof config.describeAll === 'function' ? config.describeAll()
    : rows;
  const pick = function (test) {
    const row = (all || []).filter(test)[0];
    return row ? row.key : null;
  };
  const restartKey = pick(function (r) {
    return !r.runtime && !r.realmRuntime && !r.perProcess &&
      r.key.indexOf('realms.') !== 0;
  });
  const perProcessKey = pick(function (r) { return r.perProcess; });
  const devOnlyKey = pick(function (r) {
    return r.onlyWhile && r.type === 'bool' && r.runtime;
  });
  const answer = function (result) {
    return { ok: !!result.ok, errors: result.errors || [],
             code: errorCodes.codeOf(result) || null };
  };
  const steps = [];
  const create = function (id, overrides, extra) {
    const spec = Object.assign({ id: id, overrides: overrides }, extra || {});
    const result = realms.create(spec);
    steps.push({ op: 'create', id: id, overrides: overrides || {},
                 name: spec.name || '', description: spec.description || '',
                 domain: spec.domain || '', result: answer(result) });
  };
  create('acme', {});
  create('bad', { 'realms.pathSegment': 'x' });
  create('pp', { [perProcessKey]: 5 });
  create('rs', { [restartKey]: 'x' });
  create('uk', { 'nope.key': 1 });
  create('prod', { 'global.mode': 'product', [devOnlyKey]: true });
  create('prod2', { 'global.mode': 'product' }, { name: '  Prod Two ',
    description: ' second ', domain: 'Prod2.Example.ORG.' });
  create('Bad_Id', {});
  create('dup', {}, { domain: 'prod2.example.org' });
  const set = function (id, key, raw) {
    steps.push({ op: 'set', id: id, key: key, raw: raw,
                 result: answer(realms.setOverride(id, key, raw)) });
  };
  const clear = function (id, key) {
    steps.push({ op: 'clear', id: id, key: key,
                 result: answer(realms.clearOverride(id, key)) });
  };
  const update = function (id, changes) {
    steps.push({ op: 'update', id: id, changes: changes,
                 result: answer(realms.update(id, changes)) });
  };
  set('prod2', devOnlyKey, true);
  set('acme', devOnlyKey, true);
  set('nosuch', devOnlyKey, true);
  set('acme', 'realms.pathSegment', 'x');
  set('acme', 'nope.key', 1);
  clear('acme', 'nope.key');
  clear('acme', devOnlyKey);
  clear('nosuch', 'x');
  update('acme', { domain: 'other.example.com' });
  update('acme', { overrides: { 'realms.x': 1 } });
  update('prod2', { overrides: { 'global.mode': 'product',
                                 [devOnlyKey]: true } });
  update('acme', { name: '  New Name ', description: ' d ' });
  update('nosuch', { name: 'x' });
  const listed = function () {
    return realms.list().filter(function (r) { return !r.builtin; })
      .map(function (r) {
        return { id: r.id, name: r.name, description: r.description,
                 domain: r.domain, overrides: r.overrides,
                 retiring: !!realms.isRetiring(r.id) };
      });
  };
  const before = listed();
  const retired = await realms.retire('acme', {});
  steps.push({ op: 'retire', id: 'acme', result: answer(retired) });
  steps.push({ op: 'remove', id: 'acme', result: answer(realms.remove('acme')) });
  steps.push({ op: 'remove', id: 'prod2',
               result: answer(realms.remove('prod2')) });
  const after = listed();
  return { keys: { restart: restartKey, perProcess: perProcessKey,
                   devOnly: devOnlyKey },
           steps: steps, before: before, after: after };
}

// THE HTTP LAYER (`common/app.js`): the real express app, with a few probe
// routes registered after its middleware, asked over HTTP. What is recorded
// is what the Rust layer owns — the realm prefix stripped and put back on
// links and redirects, the security headers, a page's own CSP kept or
// replaced, the one framed page, and the 404 an unrouted path answers — and
// the two CSP builders on their own.
async function httpVectors() {
  const app = require(path.join(ROOT, 'common', 'app.js'));
  const realms = require(path.join(ROOT, 'common', 'realms.js'));
  const http = require('http');
  realms.create({ id: 'acme' });
  app.get('/probe/html', function (req, res) {
    res.type('html').send('<a href="/x">x</a> <form action="/y?q=1"></form>' +
                          ' <img src="//cdn.example/z"> <a href="rel">r</a>');
  });
  app.get('/probe/redirect', function (req, res) {
    res.redirect('/oauth2/authorize?x=1');
  });
  app.get('/probe/own-csp', function (req, res) {
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.type('text').send('mine');
  });
  app.get('/probe/relaxed', function (req, res) {
    res.setHeader('Content-Security-Policy', app.contentSecurityPolicy({
      'script-src': "'self'", 'frame-ancestors': '*', 'base-uri': null,
      'connect-src': "'self'" }));
    res.type('text').send('relaxed');
  });
  app.get('/probe/framed', function (req, res) {
    res.setHeader('Content-Security-Policy',
                  app.framedContentSecurityPolicy(
                    ['https://rp.example', 'javascript:x', 'http://a:8080']));
    res.removeHeader('X-Frame-Options');
    res.type('html').send('<p>framed</p>');
  });
  app.get('/probe/realm', function (req, res) {
    res.type('text').send('realm=' + realms.currentId());
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const paths = ['/probe/html', '/realm/acme/probe/html', '/probe/redirect',
                 '/realm/acme/probe/redirect', '/probe/own-csp',
                 '/probe/relaxed', '/probe/framed', '/probe/realm',
                 '/realm/acme/probe/realm?x=1', '/nope', '/realm/nope/x',
                 '/realm/acme/nope', '/probe/<script>'];
  const answers = [];
  for (const p of paths) {
    const got = await new Promise(function (resolve, reject) {
      http.get({ host: '127.0.0.1', port: port, path: p }, function (res) {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', function (c) { body += c; });
        res.on('end', function () {
          const h = {};
          ['content-type', 'content-security-policy', 'x-frame-options',
           'x-content-type-options', 'referrer-policy', 'location']
            .forEach(function (k) {
              h[k] = res.headers[k] === undefined ? null : res.headers[k];
            });
          resolve({ path: p, status: res.statusCode, headers: h,
                    body: body });
        });
      }).on('error', reject);
    });
    answers.push(got);
  }
  server.close();
  const builds = [{}, { 'script-src': "'self'" },
                  { 'frame-ancestors': '*', 'base-uri': '*' },
                  { 'img-src': null, 'connect-src': "'self' https://x" }];
  return {
    answers: answers,
    csp: builds.map(function (o) {
      return { overrides: o, value: app.contentSecurityPolicy(o) };
    }),
    framed: [[], ['https://a.example', 'https://b.example:8443'],
             ['*', 'data:', 'https://ok.example/path']].map(function (o) {
      return { origins: o, value: app.framedContentSecurityPolicy(o) };
    })
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
                 { file: 'sigstore-node.json', build: sigstore },
                 { file: 'x509-node.json', build: x509Vectors },
                 { file: 'limbo-node.json', build: limbo },
                 { file: 'foreign-node.json', build: foreign },
                 { file: 'realms-node.json', build: realmsVectors },
                 { file: 'ldif-node.json', build: ldifVectors },
                 { file: 'merge-node.json', build: mergeVectors },
                 { file: 'scheduler-node.json', build: schedulerVectors },
                 { file: 'scheduler-history-node.json',
                   build: schedulerHistoryVectors },
                 { file: 'realm-lifecycle-node.json',
                   build: realmLifecycleVectors },
                 { file: 'http-node.json', build: httpVectors },
                 { file: 'keystore-node.json', build: keystoreVectors }];

// THE KEYSTORE'S DATA KEYS (#444): values sealed by `common/keystore.js`
// under a durable key-encryption key — with the data-key rows it wrote to
// its store — and under an ephemeral one, with keyed digests under both, for
// the Rust keystore to open and reproduce. Run in a child process, because
// the key settings are read from the environment once per process. The KEK
// is generated here and written only into the vectors directory, which is
// never committed.
function keystoreVectors() {
  const childProcess = require('child_process');
  const kekFile = path.join(OUT, 'keystore-kek.txt');
  const kekText = nodeCrypto.randomBytes(32).toString('base64');
  fs.writeFileSync(kekFile, kekText + '\n', { mode: 0o600 });
  const program = [
    "'use strict';",
    'const path = require("path");',
    'const ROOT = process.argv[1];',
    'const keystore = require(path.join(ROOT, "common", "keystore.js"));',
    'const LABELS = ["authn-sessions", "authorization-codes", "totp-secret",',
    '                "Odd Label!", ""];',
    'const REALMS = ["", "acme"];',
    'function sealAll() {',
    '  const out = [];',
    '  LABELS.forEach(function (label) {',
    '    REALMS.forEach(function (realm) {',
    '      const text = "value of " + label + " in [" + realm + "] é";',
    '      out.push({ label: label, realm: realm, text: text,',
    '                 cipher: keystore.seal(text, label, undefined,',
    '                                       { realm: realm }) });',
    '    });',
    '  });',
    '  return out;',
    '}',
    'function digests() {',
    '  return ["cluster-fingerprint", "directory:uid", ""].map(function (l) {',
    '    return { label: l, text: "hunter2",',
    '             digest: keystore.keyedDigest(l, "hunter2") };',
    '  });',
    '}',
    '(async function () {',
    '  const rows = new Map();',
    '  keystore.setStore({',
    '    loadKeys: function () {',
    '      return Promise.resolve(Array.from(rows, function (e) {',
    '        return { realm: e[0], material: e[1] };',
    '      }));',
    '    },',
    '    saveKeys: function (realm, material) {',
    '      rows.set(realm, material);',
    '      return Promise.resolve();',
    '    }',
    '  });',
    '  await keystore.start();',
    '  const durable = { sealed: sealAll(), digests: digests() };',
    '  if (keystore.persists()) {',
    '    // The default realm\'s signing key set, made and stored as the',
    '    // service makes it, and what the service calls it.',
    '    const helpers = require(path.join(ROOT, "common", "helpers.js"));',
    '    const set = helpers.stsKeysFor();',
    '    durable.signing = { kid: set.kid,',
    '                        certB64: set.selfSignedCertB64 || set.certB64 };',
    '  }',
    '  await keystore.settleDeks();',
    '  await keystore.settleAll();',
    '  durable.rows = Array.from(rows, function (e) {',
    '    return { realm: e[0], material: e[1] };',
    '  });',
    '  keystore.reset();',
    '  require("fs").writeFileSync(process.argv[2],',
    '                              JSON.stringify({ durable: durable }));',
    '})().catch(function (e) { console.error(e); process.exitCode = 1; });'
  ].join('\n');
  // The child writes its answer to a file: its log shares stdout.
  const answerFile = path.join(OUT, 'keystore-answer.json');
  const run = function (text, env) {
    childProcess.execFileSync(process.execPath, ['-e', text, ROOT, answerFile],
      { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal' }, env),
        stdio: ['ignore', 'ignore', 'inherit'] });
    const answer = JSON.parse(fs.readFileSync(answerFile, 'utf8')).durable;
    fs.unlinkSync(answerFile);
    return answer;
  };
  const durable = run(program, { STS_KEYS_SOURCE: 'persisted',
                                 STS_KEYS_KEK_PROVIDER: 'file',
                                 STS_KEYS_KEK_FILE: kekFile });
  // The ephemeral half: a KEK handed over as text, derived data keys.
  const ephemeralKek = nodeCrypto.randomBytes(32).toString('hex');
  const ephemeral = run(program.replace('await keystore.start();',
                                        'keystore.useEphemeralKek("' +
                                        ephemeralKek + '");'),
                        { STS_KEYS_SOURCE: 'generated' });
  delete ephemeral.rows;
  return { kekFile: path.basename(kekFile), kekText: kekText,
           durable: durable, ephemeralKek: ephemeralKek,
           ephemeral: ephemeral };
}

if (require.main === module) {
  fs.mkdirSync(OUT, { recursive: true });
  // One at a time, awaiting a builder that is asynchronous (pqX509).
  (async function () {
    // STS_ONLY=<prefix> writes only the files it names the start of, so one
    // family's vectors can be rewritten without changing every other key.
    const only = process.env.STS_ONLY || '';
    for (const one of VECTORS) {
      if (only && one.file.indexOf(only) !== 0) {
        continue;
      }
      const built = await one.build();
      if (built === null) {
        continue;
      }
      fs.writeFileSync(path.join(OUT, one.file),
                       JSON.stringify(built, null, 1) + '\n');
      console.log('wrote ' + path.relative(ROOT, path.join(OUT, one.file)));
    }
  })().catch(function (e) {
    console.error(e);
    process.exitCode = 1;
  });
}
