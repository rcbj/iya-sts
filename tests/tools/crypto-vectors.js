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
  return jwsRows().concat(certificateJwsRows());
}

// A COMPACT JWS VERIFIED WITH THE KEY IN A CERTIFICATE (#1713): a token per
// certificate kind — RSA, and each ML-DSA set, whose key only the
// certificate's own SubjectPublicKeyInfo can carry — and Node's
// verifyCompactJwsWithCertificate() answer, with the certificate as PEM and
// as bare base64 DER; and a refusal for what is not a certificate.
function certificateJwsRows() {
  const rows = [];
  const tokenOf = function (alg, sign) {
    const input = Buffer.from(JSON.stringify({ alg: alg, kid: 'cert-1' }))
      .toString('base64url') + '.' +
      Buffer.from(JSON.stringify({ sub: 'alice' })).toString('base64url');
    return input + '.' +
      Buffer.from(sign(Buffer.from(input, 'ascii'))).toString('base64url');
  };
  const answer = function (token, certificate, alg) {
    try {
      const out = crypto.verifyCompactJwsWithCertificate(token, certificate,
                                                         { algorithms: [alg] });
      return { ok: true, sub: out.claims.sub };
    } catch (e) {
      return { ok: false, refusal: e.message };
    }
  };
  const rsa = crypto.selfSignedRsaCertificate({ commonName: 'jws signer',
                                                bits: 2048 });
  const rsaToken = tokenOf('RS256', function (input) {
    return nodeCrypto.sign('sha256', input, rsa.privateKeyPem);
  });
  const ec = crypto.selfSignedMlDsaCertificate({ algorithm: 'ML-DSA-44',
                                                 commonName: 'other' });
  const certs = [['RS256', rsa.certPem, rsaToken]];
  ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'].forEach(function (alg) {
    const made = crypto.selfSignedMlDsaCertificate({
      algorithm: alg.toLowerCase(), commonName: 'jws signer ' + alg });
    const jwk = nodeCrypto.createPrivateKey(made.privateKeyPem)
      .export({ format: 'jwk' });
    certs.push([alg, made.certPem, tokenOf(alg, function (input) {
      return pqJose.sign(alg, Buffer.from(jwk.priv, 'base64url'), input);
    })]);
  });
  certs.forEach(function (c) {
    const der = c[1].replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    rows.push({ certificateRow: true, alg: c[0], token: c[2],
                certificate: c[1], pem: answer(c[2], c[1], c[0]),
                der: answer(c[2], der, c[0]),
                otherCertificate: ec.certPem,
                wrongCertificate: answer(c[2], ec.certPem, c[0]) });
  });
  rows.push({ certificateRow: true, alg: 'RS256', token: rsaToken,
              certificate: 'not a certificate',
              pem: answer(rsaToken, 'not a certificate', 'RS256') });
  return rows;
}

function jwsRows() {
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

// PBES2 IS DERIVED OFF THE EVENT LOOP (ASVS 5.0.0 11.4.4): the synchronous
// door refuses a PBES2 JWE, so every row is made with
// `encryptJweCompactAsync()`, which is the synchronous door for every other
// alg. After the rows, the refusals Rust must make in the same words: the
// synchronous door handed a PBES2 JWE, and the asynchronous one handed a
// `p2c` below the floor or above the ceiling.
async function jwe() {
  const cases = crypto.JWE_ALGS.map(function (alg) {
    return { alg: alg, enc: 'A256GCM' };
  }).concat(Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'RSA-OAEP-256', enc: enc };
  }), Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'dir', enc: enc };
  }));
  const rows = [];
  for (const one of cases) {
    const recipient = jweRecipient(one.alg);
    const secret = recipient ? null : jweSecretFor(one.alg, one.enc);
    const compact = await crypto.encryptJweCompactAsync('{"sub":"alice"}', {
      alg: one.alg, enc: one.enc,
      jwk: recipient ? recipient.publicJwk : undefined,
      secret: secret || undefined });
    rows.push({ alg: one.alg, enc: one.enc,
                privateJwk: recipient ? recipient.privateJwk : null,
                secret: secret ? secret.toString('base64url') : null,
                compact: compact });
  }
  return rows.concat(await jweRefusals());
}

// A PBES2 JWE with its header's `p2c` replaced: the ciphertext no longer
// matters, because the count is refused before anything is derived.
function withP2c(compact, p2c) {
  const parts = compact.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url')
    .toString('utf8'));
  header.p2c = p2c;
  parts[0] = Buffer.from(JSON.stringify(header), 'utf8')
    .toString('base64url');
  return parts.join('.');
}

async function jweRefusals() {
  const out = [];
  const secret = Buffer.from('a password for PBES2', 'utf8');
  for (const alg of crypto.JWE_ALGS.filter(function (a) {
    return /^PBES2-/.test(a);
  })) {
    const compact = await crypto.encryptJweCompactAsync('{"sub":"alice"}',
      { alg: alg, enc: 'A256GCM', secret: secret });
    const refused = async function (door, text, minIterations) {
      try {
        if (door === 'sync') {
          crypto.decryptJweCompact(text, { secret: secret });
        } else {
          await crypto.decryptJweCompactAsync(text, { secret: secret });
        }
      } catch (e) {
        out.push({ alg: alg, enc: 'A256GCM', door: door,
                   secret: secret.toString('base64url'), compact: text,
                   minIterations: minIterations,
                   refusal: (e && e.message) || String(e) });
        return;
      }
      throw new Error(alg + ': the ' + door + ' door did not refuse');
    };
    let syncEncrypt = null;
    try {
      crypto.encryptJweCompact('{"sub":"alice"}',
                               { alg: alg, enc: 'A256GCM', secret: secret });
    } catch (e) {
      syncEncrypt = (e && e.message) || String(e);
    }
    out.push({ alg: alg, enc: 'A256GCM', door: 'sync-encrypt',
               secret: secret.toString('base64url'), compact: null,
               refusal: syncEncrypt });
    await refused('sync', compact, null);
    // npm-tests runs in development, whose floor is RFC 7518's 1000.
    await refused('async', withP2c(compact, 999), 1000);
    await refused('async', withP2c(compact, '12x'), 1000);
    await refused('async', withP2c(compact, 1000001), 1000);
  }
  return out;
}

// CANONICAL XML: every element of every document, in all four forms, as
// common/crypto_impl/xmldsig.js computes it in place — the bytes every XML
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
  '<r><a></b></r>',
  // common/xml_parser.js refuses a declaration by the TEXT, wherever it is
  // (2026-11-10): in a comment, in CDATA, in any case; `<!DOCTYPEx` is not
  // one, and neither is the bare word.
  '<r><!-- <!doctype r --></r>',
  '<r><![CDATA[<! \u00a0EnTiTy x]]></r>',
  '<r><!--<!DOCTYPEx--><!-- DOCTYPE --></r>'
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
  const xmldsig = require(path.join(ROOT, 'common', 'crypto_impl',
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
  const rsa = require(path.join(ROOT, 'common', 'crypto_impl', 'xmldsig.js'))
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

// THE SETTINGS A POLICY CASE RUNS UNDER (#1368, #1455, #1469, ASVS 5.0.0
// 11.6.1). Each is set in order — a list may not leave out the algorithm a
// sibling setting already names, so the sibling goes first — refused loudly
// if a write rule says no, and cleared afterwards, last first.
function underSettings(settings, fn) {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const set = [];
  try {
    settings.forEach(function (row) {
      const written = config.setOverride(row[0], row[1]);
      if (written && written.ok === false) {
        throw new Error(row[0] + ': ' + written.errors.join('; '));
      }
      set.push(row[0]);
    });
    return fn();
  } finally {
    set.reverse().forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// signature_policy.ts's `parsed()`: a csv setting as a list.
function settingList(key) {
  const raw = require(path.join(ROOT, 'common', 'config.js')).value(key);
  return (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) {
      return String(one).trim();
    })
    .filter(function (one) {
      return one.length > 0;
    });
}

// What sts_crypto::xmldsig::XmlPolicy carries: every input the XML half of
// signature_policy.ts and section 1a read, as they stand now.
function xmlPolicyNow() {
  const mode = require(path.join(ROOT, 'common', 'mode.js'));
  const config = require(path.join(ROOT, 'common', 'config.js'));
  return {
    sha1Allowed: crypto.xmlSignatureAlgorithms().sha1Allowed,
    brokenAlgorithms: mode.usesBrokenAlgorithms(),
    signatureAlgorithms: settingList('saml.signatureAlgorithms'),
    acceptedSignatureAlgorithms:
      settingList('saml.acceptedSignatureAlgorithms'),
    acceptedDigestAlgorithms: settingList('saml.acceptedDigestAlgorithms'),
    pqcOnly: config.value('keys.pqcOnly') === true,
    joseSigningAlgorithms: settingList('keys.signingAlgorithms'),
    joseAcceptedAlgorithms: settingList('keys.acceptedSigningAlgorithms'),
    omitsUnapprovedCurves: mode.omitsUnapprovedSigningCurves(),
    allowsLegacyHashes: mode.allowsLegacyHashes()
  };
}

// A signer's answer, or its refusal: the message and the code it carries.
function signedOrRefused(fn) {
  try {
    return { signed: fn() };
  } catch (e) {
    return { refused: e.message,
             code: require(path.join(ROOT, 'common', 'error_codes.js'))
               .codeOf(e) || null };
  }
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

  // THE SIGNER'S CHAIN IN KeyInfo (#1064): `keyInfoXml` in place of the bare
  // certificate, down each of the three paths — RSA's and ECDSA's take it,
  // the post-quantum one does not.
  const chain = '<ds:X509Data><ds:X509Certificate>' +
    keys.rsa.certPem.replace(/-----[^-]+-----|\s+/g, '') +
    '</ds:X509Certificate><ds:X509Certificate>MIIBchain' +
    '</ds:X509Certificate></ds:X509Data>';
  [['rsa-sha256', 'rsa'], ['ecdsa-sha256', 'p256'], ['ml-dsa-44', 'ML-DSA-44']]
    .forEach(function (pair) {
      const signer = XML_SIGNERS.filter(function (row) {
        return row[0] === pair[0];
      })[0];
      const key = keys[pair[1]];
      const opts = { sigAlg: signer[1], keyInfoXml: chain,
                     certPem: keys.rsa.certPem };
      if (key.alg) {
        opts.privateKey = key.privRaw;
      } else {
        opts.privateKeyPem = key.privateKeyPem;
      }
      const name = pair[0] + ' saml2 a chain in KeyInfo';
      const xml = crypto.signXml(XML_DOCS.saml2, opts);
      signed.push({ name: name, input: XML_DOCS.saml2, key: pair[1],
                    sigAlg: signer[1], c14nAlg: null,
                    placement: 'after-issuer', certPem: keys.rsa.certPem,
                    keyInfoXml: chain, deterministic: pair[1] === 'rsa',
                    signed: xml });
      check(name, xml, 'Assertion', { publicKeyPem: key.publicKeyPem });
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
  // An HMAC needs a shared key (#658): a certificate cannot check one.
  check('an HMAC method', base.replace(MORE + 'rsa-sha256',
                                       MORE + 'hmac-sha256'),
        'Assertion', rsaPub);
  // A transform outside XML_ACCEPTED_TRANSFORMS (ASVS 5.0.0 1.2.7) is
  // refused before anything is digested.
  const ENVELOPED = '<ds:Transform Algorithm="' + DS +
    'enveloped-signature"/>';
  [['an XSLT transform', 'http://www.w3.org/TR/1999/REC-xslt-19991116'],
   ['an XPath transform', 'http://www.w3.org/TR/1999/REC-xpath-19991116'],
   ['a base64 transform', DS + 'base64']].forEach(function (row) {
    check(row[0], base.replace(ENVELOPED, ENVELOPED +
      '<ds:Transform Algorithm="' + row[1] + '"/>'), 'Assertion', rsaPub);
  });
  check('a transform in another namespace', base.replace(ENVELOPED,
    ENVELOPED + '<x:Transform xmlns:x="urn:x" Algorithm="urn:t"/>'),
  'Assertion', rsaPub);
  // A declaration anywhere in the text (common/xml_parser.js, 2026-11-10).
  check('a DOCTYPE', '<!DOCTYPE Assertion>' + base, 'Assertion', rsaPub);
  check('an ENTITY in a comment', base.replace('<!-- a comment -->',
    '<!-- <!ENTITY x "y"> -->'), 'Assertion', rsaPub);

  // The general engine, in every other method crypto.js verifies.
  const general = [];
  const engine = require(path.join(ROOT, 'common', 'crypto_impl',
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

  // THE POLICY (#1368, ASVS 5.0.0 11.6.1): what the lists, keys.pqcOnly and
  // product mode change, each case under the settings its scenario names.
  const base384 = crypto.signXml(XML_DOCS.saml2, {
    privateKeyPem: keys.rsa.privateKeyPem, certPem: keys.rsa.certPem,
    sigAlg: MORE + 'rsa-sha384' });
  const es256 = crypto.signXml(XML_DOCS.saml2, {
    privateKeyPem: keys.p256.privateKeyPem, certPem: keys.rsa.certPem,
    sigAlg: MORE + 'ecdsa-sha256' });
  const generalNamed = function (name) {
    return general.filter(function (row) {
      return row.name === name;
    })[0];
  };
  const k1 = generalNamed('general ecdsa-sha3-256 ec');
  const p192 = generalNamed('general ecdsa-sha256 ec');
  const toVerify = {
    'rsa-sha256': [base, keys.rsa.publicKeyPem],
    'rsa-sha384': [base384, keys.rsa.publicKeyPem],
    'ecdsa-sha256': [es256, keys.p256.publicKeyPem],
    'ecdsa secp256k1': [k1.signed, k1.publicKeyPem],
    'ecdsa prime192v1': [p192.signed, p192.publicKeyPem]
  };
  const SCENARIOS = [
    // An accept list must hold what the realm signs with (RS256 here).
    ['an accept list', [['saml.acceptedSignatureAlgorithms', 'RS256,ES256']],
     ['rsa-sha256', 'rsa-sha384', 'ecdsa-sha256'], [],
     ['rsa-sha256', 'rsa-sha384']],
    ['a digest list', [['saml.acceptedDigestAlgorithms', 'SHA-512']],
     ['rsa-sha256'], [], []],
    ['a sign list', [['saml.signatureAlgorithm', 'rsa-sha384'],
                     ['saml.signatureAlgorithms', 'RS384']],
     ['rsa-sha256'], ['rsa-sha256', 'rsa-sha384', 'ecdsa-sha256',
                      'ml-dsa-44'], []],
    ['keys.pqcOnly', [['keys.pqcOnly', true]],
     ['rsa-sha256'], ['rsa-sha256', 'ml-dsa-65'], []],
    ['a JOSE accept list without ES256K',
     [['keys.acceptedSigningAlgorithms', 'RS256']],
     ['ecdsa secp256k1', 'rsa-sha256'], [], []],
    ['product', [['global.mode', 'product']],
     ['rsa-sha256', 'ecdsa secp256k1', 'ecdsa prime192v1'], [],
     ['rsa-sha256']],
    ['product, ES256K listed', [['global.mode', 'product'],
                                ['keys.acceptedSigningAlgorithms',
                                 'ES256K,RS256']],
     ['ecdsa secp256k1'], [], []]
  ];
  const policies = SCENARIOS.map(function (scenario) {
    return underSettings(scenario[1], function () {
      const out = { name: scenario[0], settings: scenario[1],
                    policy: xmlPolicyNow(), verify: [], sign: [],
                    queries: [] };
      scenario[2].forEach(function (which) {
        out.verify.push({ name: which, xml: toVerify[which][0],
          element: 'Assertion', publicKeyPem: toVerify[which][1],
          verdict: verdictOf(crypto.verifyXmlSignature(toVerify[which][0], {
            element: 'Assertion', publicKeyPem: toVerify[which][1] })) });
      });
      scenario[3].forEach(function (which) {
        const signer = XML_SIGNERS.filter(function (row) {
          return row[0] === which;
        })[0];
        const key = keys[signer[2]];
        const opts = { sigAlg: signer[1], certPem: keys.rsa.certPem };
        if (key.alg) {
          opts.privateKey = key.privRaw;
        } else {
          opts.privateKeyPem = key.privateKeyPem;
        }
        out.sign.push(Object.assign({ name: which, key: signer[2],
                                      sigAlg: signer[1],
                                      input: XML_DOCS.saml2,
                                      deterministic: signer[2] === 'rsa' },
          signedOrRefused(function () {
            return crypto.signXml(XML_DOCS.saml2, opts);
          }),
          { query: query + encodeURIComponent(signer[1]) },
          { queryResult: signedOrRefused(function () {
            const q = query + encodeURIComponent(signer[1]);
            return key.alg
              ? crypto.signQueryString(q, null, signer[1], key.privRaw)
              : crypto.signQueryString(q, key.privateKeyPem, signer[1]);
          }) }));
      });
      scenario[4].forEach(function (which) {
        const row = queries.filter(function (q) {
          return q.name === which;
        })[0];
        out.queries.push({ name: which, query: row.query,
          signature: row.signature, sigAlg: row.sigAlg,
          certPem: keys.rsa.certPem,
          verdict: verdictOf(crypto.verifyQueryString(row.query, {
            signature: row.signature, sigAlg: row.sigAlg,
            certPem: keys.rsa.certPem })) });
      });
      return out;
    });
  });

  Object.keys(keys).forEach(function (k) {
    delete keys[k].privRaw;
  });
  return { policy: xmlPolicyNow(),
           registry: xmlRegistry(),
           keys: keys, signed: signed, verify: verify, general: general,
           queries: queries, queryChecks: queryChecks, policies: policies };
}

// The XML rows of the one algorithm registry (#1368), as crypto.js reads
// them: each SignatureMethod with its row id, and the DigestMethods. Rust's
// tables are held to these, row for row and in order.
function xmlRegistry() {
  const registry = require(path.join(ROOT, 'common', 'crypto_impl',
                                     'algorithm_registry.js'));
  const methods = registry.xmlSignatureMethods();
  return {
    methods: Object.keys(methods).map(function (uri) {
      const row = registry.bySpelling('xml', uri);
      return Object.assign({ uri: uri, id: row.id, pqc: row.pqc !== null },
                           methods[uri]);
    }),
    refused: registry.xmlSignaturesRefused(),
    digests: registry.xmlDigestMethods(),
    digestsRefused: registry.xmlDigestsRefused()
  };
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
  const engine = require(path.join(ROOT, 'common', 'crypto_impl',
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
  // THE MODE (#1455, #1469, ASVS 5.0.0 11.3.2 and 11.4.1): product reads
  // only AES-GCM, unwraps no OAEP over SHA-1 unless crypto.allowLegacyHashes
  // is on, and encrypts with rsa-oaep where rsa-oaep-mgf1p was named or
  // defaulted.
  const caseNamed = function (name) {
    return cases.filter(function (c) {
      return c.name === name;
    })[0];
  };
  const policies = [
    ['product', [['global.mode', 'product']]],
    ['product, legacy hashes', [['global.mode', 'product'],
                                ['crypto.allowLegacyHashes', true]]]
  ].map(function (scenario) {
    return underSettings(scenario[1], function () {
      const now = xmlPolicyNow();
      const out = { name: scenario[0], settings: scenario[1],
                    policy: { brokenAlgorithms: now.brokenAlgorithms,
                              allowsLegacyHashes: now.allowsLegacyHashes },
                    cases: [] };
      ['aes256-gcm rsa-oaep', 'aes256-gcm rsa-oaep-mgf1p',
       'aes256-cbc rsa-oaep', 'aes128-cbc rsa-1_5', 'aes256-gcm rsa-1_5',
       'P-256 kw-aes256', 'P-256 aes256-cbc'].forEach(function (name) {
        const c = caseNamed(name);
        out.cases.push(decrypt(name, c.xml, c.recipient));
      });
      [{}, { algorithm: 'aes128-cbc' }, { keyTransport: 'rsa-oaep-mgf1p' },
       { keyTransport: 'rsa-oaep' }].forEach(function (opts) {
        const enc = crypto.encryptElement(plain.assertion, rsa.certPem, opts);
        const c = decrypt('encrypted ' + JSON.stringify(opts), enc, 'rsa');
        c.encrypt = { plain: plain.assertion, options: opts };
        out.cases.push(c);
      });
      return out;
    });
  });
  return { brokenAlgorithms: require(path.join(ROOT, 'common', 'mode.js'))
    .usesBrokenAlgorithms(),
           allowsLegacyHashes: require(path.join(ROOT, 'common', 'mode.js'))
             .allowsLegacyHashes(),
           recipients: recipients, cases: cases, refusals: refusals,
           policies: policies };
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
  return Object.assign({ hotp: hotp, hashes: hashes, envelopes: envelopes,
                         wraps: wraps, derived: derived,
                         kekRefusals: kekRefusals,
                         credentials: credentials }, passwordVectors());
}

// A PERSON'S PASSWORD (#847, #872): what the password policy's spec becomes,
// hashes under each algorithm, and what the upgrade on sign-in asks of a
// stored value — its parameters, whether it matches a spec, whether it is
// weaker. The asks include out-of-range and missing values, because
// passwordHashSpec() clamps; the stored values include forms this service
// writes, the pre-#872 cost, and argon2id strings outside the bounds a
// verification will compute.
function passwordVectors() {
  const asks = [
    {}, { algorithm: 'scrypt' }, { algorithm: 'argon2id' },
    { algorithm: 'scrypt', logN: 13 }, { algorithm: 'scrypt', logN: 14 },
    { algorithm: 'scrypt', logN: 16, p: 1 }, { algorithm: 'scrypt', logN: 17 },
    { algorithm: 'scrypt', logN: 99, r: 1, p: 99 },
    { algorithm: 'scrypt', logN: 15.9, r: 12.5, p: '' },
    { algorithm: 'argon2id', memory: 1, passes: 1, parallelism: 0 },
    { algorithm: 'argon2id', memory: 65536, passes: 3, parallelism: 4 },
    { algorithm: 'argon2id', memory: 9e9, passes: 99, parallelism: 99 },
    { algorithm: 'bcrypt' }
  ];
  const specs = asks.map(function (ask) {
    return { ask: ask, spec: crypto.passwordHashSpec(ask) };
  });
  const plains = ['', 'password', 'pässwörd 🔑'];
  const passwords = [];
  [{ algorithm: 'argon2id' },
   { algorithm: 'argon2id', memory: 20000, passes: 3, parallelism: 2 },
   {}, { algorithm: 'scrypt', logN: 14 }].forEach(function (ask) {
    plains.forEach(function (plain) {
      passwords.push({ ask: ask, plain: plain,
                       stored: crypto.hashPassword(plain, ask) });
    });
  });
  const salt = nodeCrypto.randomBytes(16).toString('base64')
    .replace(/=+$/, '');
  const tag = nodeCrypto.randomBytes(32).toString('base64')
    .replace(/=+$/, '');
  const stored = passwords.map(function (row) {
    return row.stored;
  }).concat([
    crypto.hashSecret('legacy'),
    '$argon2id$v=19$m=4194304,t=2,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=19456,t=17,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=16,t=1,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=15,t=1,p=2$' + salt + '$' + tag,
    '$argon2id$v=18$m=19456,t=2,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=19456,t=2,p=1,x=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=19456,t=2,p=1$' + salt + '=$' + tag,
    '$argon2id$v=19$m=19456,t=2,p=1$AAAA$' + tag,
    '$scrypt$30000$8$1$' + salt + '$' + tag,
    '$scrypt$x$8$1$' + salt + '$' + tag,
    'plain-text', '', '{SSHA}abc'
  ]);
  const storedRows = stored.map(function (one) {
    return {
      stored: one,
      hashed: crypto.isHashedSecret(one),
      parameters: crypto.storedSecretParameters(one),
      matches: asks.map(function (ask) {
        return crypto.storedSecretMatchesSpec(one, ask);
      }),
      weaker: asks.map(function (ask) {
        return crypto.storedSecretIsWeaker(one, ask);
      })
    };
  });
  const digests = ['', 'an authorization code', 'é 中 🔑',
                   'x'.repeat(1000)].map(function (value) {
    return { value: value, digest: crypto.credentialDigest(value) };
  });
  return { passwordAsks: asks, passwordSpecs: specs, passwords: passwords,
           storedSecrets: storedRows, credentialDigests: digests };
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
  const pqcX509 = require(path.join(ROOT, 'common', 'crypto_impl',
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
  const pqcX509 = require(path.join(ROOT, 'common', 'crypto_impl',
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
  // THE PQ FAMILY WITH THE ALGORITHM NAMED (#1368): the raw AKP key bytes
  // a Data Integrity proof holds, every JOSE post-quantum algorithm, signed
  // by signRawSignature() and judged by verifyRawSignature().
  const named = [];
  for (const alg of pqJose.PQ_ALGS) {
    const pair = pqJose.generate(alg);
    const other = pqJose.generate(alg);
    const scheme = { family: 'pq', alg: alg };
    const sig = crypto.signRawSignature(scheme, pair.priv, data);
    const tampered = Buffer.from(sig);
    tampered[tampered.length - 1] ^= 1;
    named.push({ alg: alg, pub: pair.pub.toString('base64'),
                 priv: pair.priv.toString('base64'),
                 otherPub: other.pub.toString('base64'),
                 signature: Buffer.from(sig).toString('base64'),
                 ok: await crypto.verifyRawSignature(scheme, pair.pub, data,
                                                     sig),
                 tampered: await crypto.verifyRawSignature(scheme, pair.pub,
                                                           data, tampered),
                 wrongKey: await crypto.verifyRawSignature(scheme, other.pub,
                                                           data, sig) });
  }
  return { signatures: rows, kdfa: kdfa, credential: credential,
           integers: integers, pkcs7: pkcs7, named: named };
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
    require(path.join(ROOT, 'common', 'crypto_impl', 'xmldsig.js'))
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
           coseSign1: coseSign1Vectors(keyFor),
           brokenAlgorithms: require(path.join(ROOT, 'common', 'mode.js'))
             .usesBrokenAlgorithms() };
}

// COSE_SIGN1 (#1368): coseSign1Sign() over a protected header, a payload
// and external AAD, for every COSE algorithm it signs with, and
// coseSign1Verify()'s verdicts on the signature, a tampered one, and the
// same signature under other AAD. RS1 is never signed with, and its refusal
// is a row. The private key travels so that Rust signs with Node's key: the
// deterministic ones (RSA PKCS#1, EdDSA) must be the same bytes.
function coseSign1Vectors(keyFor) {
  const protectedBytes = Buffer.from('a10126', 'hex');
  const payload = Buffer.from('a COSE_Sign1 payload \u00e9', 'utf8');
  const external = Buffer.from('external aad');
  const plan = [
    [-7, 'ec256'], [-35, 'ec384'], [-36, 'ec521'], [-8, 'ed25519'],
    [-8, 'ed448'], [-257, 'rsa'], [-258, 'rsa'], [-259, 'rsa'],
    [-37, 'rsa'], [-38, 'rsa'], [-39, 'rsa'], [-9, 'ec256'], [-51, 'ec384'],
    [-52, 'ec521'], [-47, 'k1'], [-19, 'ed25519'], [-53, 'ed448'],
    [-48, 'ML-DSA-44'], [-49, 'ML-DSA-65'], [-50, 'ML-DSA-87']
  ];
  const rows = plan.map(function (row) {
    const spec = crypto.coseSignatureAlg(row[0]);
    let publicKey;
    let privateKey;
    let out;
    if (spec.family === 'pq') {
      const pair = pqJose.generate(spec.name);
      publicKey = { kty: 'AKP', alg: spec.name,
                    pub: pair.pub.toString('base64url') };
      privateKey = pair.priv.toString('base64');
      out = { publicJwk: publicKey, privateRaw: privateKey };
      privateKey = pair.priv;
    } else {
      const pair = keyFor[row[1]];
      publicKey = pair.publicKey.export({ format: 'jwk' });
      privateKey = pair.privateKey;
      out = { publicJwk: publicKey,
              privatePem: pair.privateKey.export({ type: 'pkcs8',
                                                   format: 'pem' }) };
    }
    const sig = crypto.coseSign1Sign(row[0], privateKey, protectedBytes,
                                     payload, { external: external });
    const tampered = Buffer.from(sig);
    tampered[tampered.length - 1] ^= 1;
    const verdict = function (bytes, aad) {
      return crypto.coseSign1Verify(row[0], publicKey, protectedBytes,
                                    payload, bytes, { external: aad });
    };
    return Object.assign(out, {
      alg: row[0], key: row[1],
      deterministic: spec.family === 'rsa-pkcs1' || spec.family === 'eddsa',
      signature: Buffer.from(sig).toString('base64'),
      ok: verdict(sig, external), tampered: verdict(tampered, external),
      otherAad: verdict(sig, Buffer.from('other aad')) });
  });
  let refusal = null;
  try {
    crypto.coseSign1Sign(-65535, keyFor.rsa.privateKey, protectedBytes,
                         payload, {});
  } catch (e) {
    refusal = e.message;
  }
  return { protected: protectedBytes.toString('base64'),
           payload: payload.toString('base64'),
           external: external.toString('base64'),
           rows: rows, rs1Refusal: refusal };
}

// SIGSTORE AND TUF (section 11): Node's two canonical forms over values
// that tell them apart (control characters, non-ASCII and astral keys,
// numbers JavaScript spells its own way); TUF threshold verdicts over keys
// of every kind cosign reads — Ed25519 as hex, ECDSA and RSA as PEM, a
// post-quantum PEM — with a keyid twice, a keyid the role does not name, a
// tampered signature, odd hex and thresholds Number() reads oddly; Rekor
// SETs good, tampered and from an unknown log; DSSE PAE and the two hashes.
async function sigstore() {
  const pqcX509 = require(path.join(ROOT, 'common', 'crypto_impl',
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
  const x509 = require(path.join(ROOT, 'common', 'crypto_impl', 'x509.js'));
  const pqcX509 = require(path.join(ROOT, 'common', 'crypto_impl',
                                    'pqc_x509.js'));
  const bytes = require(path.join(ROOT, 'common', 'crypto_impl',
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
    // The composite whose ECDSA half is P-521, the one whose DER
    // `pqc_x509.js` now writes itself (#445).
    composite521: await pqPair('mldsa87-ecdsa-p521-sha512'),
    // Too short for section 18's key-strength check (#1360).
    rsa1024: pair('rsa', { modulusLength: 1024 }),
    k256: pair('ec', { namedCurve: 'secp256k1' }),
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
                   'mldsa65-ecdsa-p256-sha512': 'composite',
                   'mldsa87-ecdsa-p521-sha512': 'composite521' };
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
  // DER's shortest form (X.690 8.3.2, 2026-11-05): a caller's leading zero
  // bytes are dropped while the value stays positive.
  await issue('a serial with leading zeros', selfSigned('sha256-rsa', {
    serial: '00:3f:01' }));
  await issue('a serial of zeros before a high bit', selfSigned('sha256-rsa', {
    serial: '00:00:80:01' }));
  await issue('a serial of one zero byte', selfSigned('sha256-rsa', {
    serial: '00' }));
  const underRsa = function (name, pub) {
    return issue(name, Object.assign({
      subject: 'CN=' + name, subjectPublicKey: pub,
      issuer: { certificatePem: roots['sha256-rsa'].pem,
                privateKeyPem: keys.rsa.priv },
      signatureAlg: 'sha256-rsa', serial: '43', profile: 'tls-client'
    }, window), [roots['sha256-rsa'].pem]);
  };
  await underRsa('a 1024-bit RSA key', keys.rsa1024.pub);
  await underRsa('a secp256k1 key', keys.k256.pub);
  const wild = x509.defaultExtensions('tls-server');
  Object.assign(wild.subjectAltName, { present: true, names: [
    { kind: 'dns', value: '*.wild.example' },
    { kind: 'dns', value: 'f*.part.example' },
    { kind: 'dns', value: 'Mixed.Example' },
    { kind: 'email', value: 'Bob@Example.COM' },
    { kind: 'ip', value: '10.1.2.3' }] });
  await issue('wildcard names', selfSigned('sha256-rsa', {
    profile: 'tls-server', extensions: wild }));
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
  const sections = await x509Section18(x509, keys, keyFor, roots,
                                         certs, window);
  return { keys: keys, certificates: certs, requests: csrs, ecdsa: ecdsa,
           fields: sections.fields, paths: sections.paths,
           anchors: sections.anchors, registry: sections.registry,
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

// THE PURE HALF OF THE ONE VALIDATION DOOR (#1360, #1368): `crypto.js`
// section 18 (a certificate's facts, its field problems under a role and a
// use case, its names), the two rules `pathRuleProblem()` gained (the X.509
// accept list and the leaf's own fields), and a truststore's admission rule
// (`anchorProblem()`, `anchorProblemSync()`), each with Node's answer for
// `sts-pki` to give. The door's purposes, settings and stores are not here:
// they are the phases that port the door itself.
async function x509Section18(x509, keys, keyFor, roots, certs, window) {
  const pki = require(path.join(ROOT, 'common', 'pki.js'));
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const registry = require(path.join(ROOT, 'common', 'crypto_impl',
                                     'algorithm_registry.js'));
  const EKU = crypto.EKU;
  const now = Date.parse('2027-01-01T00:00:00.000Z');
  const b64 = function (der) {
    return Buffer.from(der).toString('base64');
  };
  const fieldOptions = [
    {},
    { role: 'intermediate' },
    { role: 'anchor', keyUsage: ['keyCertSign'] },
    { keyUsage: ['digitalSignature'],
      eku: { oids: [EKU.serverAuth], required: true } },
    { keyUsage: ['keyEncipherment', 'keyAgreement'],
      eku: { oids: [EKU.clientAuth], required: false } },
    { eku: { oids: [EKU.codeSigning], required: true }, mayBeCa: true },
    { eku: { oids: [EKU.ocspSigning, EKU.tcgAik] } },
    { allowSha1: true, mayBeCa: true, allowCritical: ['1.2.3.77'] },
    { now: Date.parse('2040-01-01T00:00:00.000Z'), skewMs: 1000 },
    { now: Date.parse('2020-01-01T00:00:00.000Z') },
    { now: Date.parse('2036-01-02T03:04:05.999Z') },
    { now: Date.parse('2026-01-02T03:04:04.000Z'), skewMs: 1000 },
    { now: Date.parse('2040-01-01T00:00:00.000Z'),
      validityAt: Date.parse('2030-01-01T00:00:00.000Z') }
  ];
  const nameSets = [
    {}, { dns: 'host.example' }, { dns: 'HOST.EXAMPLE' },
    { dns: 'other.example' }, { ip: '192.0.2.7' }, { ip: '2001:db8::1' },
    { ip: '192.0.2.8' }, { email: 'a@example.com' },
    { email: 'A@EXAMPLE.COM' }, { email: 'a@EXAMPLE.com' },
    { uri: 'spiffe://example.org/w' }, { uri: 'spiffe://example.org/W' },
    { dns: 'host.example', ip: '192.0.2.8' },
    { dns: 'a.wild.example' }, { dns: 'a.b.wild.example' },
    { dns: 'wild.example' }, { dns: 'foo.part.example' },
    { dns: 'oof.part.example' }, { dns: 'mixed.example' },
    { dns: '.mixed.example' }, { dns: 'mixed.example.' },
    { email: 'Bob@example.com' }, { email: 'bob@Example.COM' },
    { ip: '10.1.2.3' }, { ip: '::ffff:10.1.2.3' }, { ip: 'not an ip' },
    { dns: 'kem' }, { dns: 'localhost' }
  ];
  const attempt = function (f) {
    try {
      return f();
    } catch (e) {
      return { error: e.message };
    }
  };
  const fields = [];
  for (const row of certs) {
    if (!row.der) {
      continue;
    }
    const der = Buffer.from(row.der, 'base64');
    fields.push({
      name: row.name,
      facts: attempt(function () {
        return crypto.certificateFacts(der);
      }),
      problems: fieldOptions.map(function (o) {
        return attempt(function () {
          return crypto.certificateFieldProblems(der,
            Object.assign({ now: now }, o));
        });
      }),
      names: nameSets.map(function (n) {
        return attempt(function () {
          return crypto.certificateNameMatches(der, n);
        });
      })
    });
  }

  // Paths: a leaf under every root, a two-hop path, and a CA as the leaf.
  const issued = async function (spec) {
    return x509.issueCertificate(Object.assign({}, window, spec));
  };
  const chains = [];
  for (const alg of Object.keys(roots)) {
    const root = roots[alg];
    if (!root.pem) {
      continue;
    }
    // An ECDSA issuer certifies a key on its own curve: Node cannot issue
    // across curves (the defect `x509_vectors.rs` pins).
    const subjectKey = /-ecdsa$/.test(alg) ? keys[keyFor[alg]] : keys.p256;
    const leaf = await issued({
      subject: 'CN=path leaf ' + alg, subjectPublicKey: subjectKey.pub,
      issuer: { certificatePem: root.pem,
                privateKeyPem: keys[keyFor[alg]].priv },
      signatureAlg: alg, serial: '0c',
      extensions: x509.defaultExtensions('tls-server') });
    chains.push({ name: 'under ' + alg, leaf: leaf.der, intermediates: [],
                  anchors: [Buffer.from(root.der, 'base64')] });
  }
  const rsaRoot = roots['sha256-rsa'];
  const inter = await issued({
    subject: 'CN=path intermediate, O=Example', subjectPublicKey: keys.p384.pub,
    issuer: { certificatePem: rsaRoot.pem, privateKeyPem: keys.rsa.priv },
    signatureAlg: 'sha256-rsa', serial: '0d', profile: 'intermediate-ca' });
  const deep = await issued({
    subject: 'CN=path leaf two hops', subjectPublicKey: keys.ed25519.pub,
    issuer: { certificatePem: inter.pem, privateKeyPem: keys.p384.priv,
              keyAlg: 'ec-p384' },
    signatureAlg: 'sha384-ecdsa', serial: '0e',
    extensions: x509.defaultExtensions('tls-client') });
  const rsaRootDer = Buffer.from(rsaRoot.der, 'base64');
  chains.push({ name: 'two hops', leaf: deep.der, intermediates: [inter.der],
                anchors: [rsaRootDer] });
  const caLeaf = await issued({
    subject: 'CN=path CA leaf', subjectPublicKey: keys.p256.pub,
    issuer: { certificatePem: rsaRoot.pem, privateKeyPem: keys.rsa.priv },
    signatureAlg: 'sha256-rsa', serial: '0f', profile: 'issuing-ca' });
  chains.push({ name: 'a CA as the leaf', leaf: caLeaf.der,
                intermediates: [], anchors: [rsaRootDer] });
  const accepts = ['', 'RS256', 'ES256,ES384', 'PS384', 'PS256,PS512',
                   'ML-DSA-65', 'RS1,ECDSA-SHA1', 'Ed25519',
                   'ML-DSA-65-ES256,ML-DSA-87-ECDSA-P521-SHA512',
                   'SLH-DSA-SHA2-128f,RS512'];
  const leafRules = [
    null,
    { keyUsage: ['digitalSignature'],
      eku: { oids: [EKU.serverAuth], required: true } },
    { keyUsage: ['digitalSignature'],
      eku: { oids: [EKU.clientAuth], required: true } },
    { keyUsage: ['keyCertSign'], eku: null, mayBeCa: true },
    { keyUsage: ['cRLSign'], eku: null }
  ];
  const paths = [];
  for (const accept of accepts) {
    const set = config.setOverride('pki.acceptedSignatureAlgorithms', accept);
    if (accept && !(set && set.ok !== false)) {
      throw new Error('pki.acceptedSignatureAlgorithms=' + accept + ': ' +
                      JSON.stringify(set));
    }
    for (const c of chains) {
      for (let r = 0; r < leafRules.length; r++) {
        for (const allowSha1 of r === 0 ? [false, true] : [false]) {
          const options = { now: now, allowCritical: [] };
          if (leafRules[r]) {
            options.leaf = leafRules[r];
          }
          if (allowSha1) {
            options.allowSha1 = true;
          }
          const v = await pki.verifyPathToAnchors(Buffer.from(c.leaf),
            c.intermediates.map(function (d) {
              return Buffer.from(d);
            }), c.anchors.map(function (d) {
              return pki.certificateFromDer(Buffer.from(d));
            }).filter(Boolean), options);
          paths.push({ name: c.name, accept: accept, leafRule: r,
                       allowSha1: allowSha1, now: now,
                       leaf: b64(c.leaf), intermediates: c.intermediates
                         .map(b64), anchors: c.anchors.map(b64),
                       verdict: { ok: v.ok, check: v.check || '',
                                  reason: v.reason || '',
                                  chain: (v.chain || []).length } });
        }
      }
    }
  }
  config.clearOverride('pki.acceptedSignatureAlgorithms');

  // A truststore's admission rule, both doors.
  const candidates = Object.keys(roots).filter(function (alg) {
    return roots[alg].pem;
  }).map(function (alg) {
    return { name: 'root ' + alg, pem: roots[alg].pem };
  }).concat([{ name: 'intermediate', pem: inter.pem },
             { name: 'CA leaf', pem: caLeaf.pem },
             { name: 'leaf', pem: deep.pem },
             { name: 'not a certificate', pem: 'nope' }]);
  const anchors = [];
  for (const one of candidates) {
    for (const role of [undefined, 'anchor', 'intermediate']) {
      for (const at of [now, Date.parse('2040-01-01T00:00:00.000Z')]) {
        const opts = { role: role, heldAnchors: [rsaRoot.pem], now: at };
        anchors.push({ name: one.name, pem: one.pem, role: role || '',
                       now: at,
                       held: [rsaRoot.pem],
                       async: await pki.anchorProblem(one.pem, opts),
                       sync: pki.anchorProblemSync(one.pem, opts) });
      }
    }
  }
  return {
    fields: { now: now, options: fieldOptions, names: nameSets,
              certificates: fields },
    paths: paths,
    anchors: anchors,
    registry: registry.on('x509').map(function (row) {
      return { id: row.id, oid: row.oid, hash: row.hash, x509: row.x509 };
    })
  };
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
  const bytes = require(path.join(ROOT, 'common', 'crypto_impl',
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
  const x509 = require(path.join(ROOT, 'common', 'crypto_impl', 'x509.js'));
  const pqcX509 = require(path.join(ROOT, 'common', 'crypto_impl',
                                    'pqc_x509.js'));
  const bytes = require(path.join(ROOT, 'common', 'crypto_impl',
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
    { id: 'x.throws', everyMs: 5000, offThrows: 'no store' },
    // Where a body runs and how patient it is (#408).
    { id: 'f.front', everyMs: 60000, onFront: 'it holds a socket' },
    { id: 'n.patient', everyMs: 60000, nice: 19 },
    { id: 'n.manual', manualOnly: true, nice: 7 }
  ];
  const specOf = function (d) {
    const spec = { id: d.id, title: 'T ' + d.id, describe: 'D', owner: 'O',
                   run: function () { return null; } };
    ['kind', 'scope', 'quiet', 'cron', 'manualOnly', 'everySetting',
     'timeoutS', 'onFront', 'nice'].forEach(function (k) {
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
      nice: job.nice,
      onFront: job.onFront || null,
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
  // The default cap (the setting at 0) with no request workers: two, the
  // floor (2026-11-10), still never every store connection.
  settings['scheduler.maxConcurrentRuns'] = 0;
  const concurrencyDefault = [0, 1, 2, 3, 10].map(function (n) {
    pool = n;
    return sched.maxConcurrentRuns();
  });
  settings['scheduler.maxConcurrentRuns'] = 4;
  const refused = [
    { id: 'Bad', title: '', describe: 'd', owner: 'o', everyMs: 1 },
    { id: 'one', title: 't', describe: 'd', owner: 'o', everyMs: 1 },
    { id: 'c.broken', title: 't', describe: 'd', owner: ' ',
      cron: '61 * * * *' },
    { id: 'q.quiet', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      quiet: true },
    { id: 'p.manual', title: 't', describe: 'd', owner: 'o',
      kind: 'per-process', manualOnly: true },
    { id: 'a.seconds', title: 't', describe: 'd', owner: 'o', everyMs: 1 },
    { id: 'f.empty', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      onFront: '  ' },
    { id: 'f.process', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      kind: 'per-process', onFront: 'a reason' },
    { id: 'n.high', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      nice: 20 },
    { id: 'n.half', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      nice: 2.5 },
    { id: 'n.low', title: 't', describe: 'd', owner: 'o', everyMs: 1,
      nice: -1 }
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
           concurrencyDefault: concurrencyDefault,
           refused: refused, rows: rows, expiries: expiries, ranks: ranks,
           cron: cron,
           whys: [null, 'text', { why: '' }, { why: 7 }, { why: 'short' },
                  { why: 'w'.repeat(600) }, ['why']].map(function (r) {
             return { result: r, why: S.whyOf(r) };
           }),
           spans: [0, 499, 500, 1000, 59499, 59500, 60000, 252000, 3600000,
                   3660000, 7500000, 86400000, 7776000000, 90061000, -5],
           spanText: [0, 499, 500, 1000, 59499, 59500, 60000, 252000,
                      3600000, 3660000, 7500000, 86400000, 7776000000,
                      90061000, -5].map(S.span) };
}

// THE SCHEDULER'S TICK (`cluster/scheduler.ts`, #408, #623, #883, #98): the
// TypeScript Scheduler's own `tick()` over stand-in claims, a runner whose
// load each scenario sets, and a durable run reader that answers, is empty
// or fails as the scenario says. Per tick: the claims asked (scope, value,
// realm), the reads asked (realm, ids) and the held bodies dropped; after
// the ticks, every run row's state, where it ran and how long it was held.
// Rust drives its own Scheduler through the same scenarios
// (`sts-cluster/tests/tick_vectors.rs`).
async function schedulerTickVectors() {
  const S = require(path.join(ROOT, 'cluster', 'scheduler.js')).Scheduler;
  const bunyan = require('bunyan');
  const cells = require(path.join(ROOT, 'common', 'cells.js'));
  const t0 = Date.UTC(2026, 9, 5, 12, 0, 0);
  const base = { 'scheduler.enabled': true, 'scheduler.tickS': 15,
                 'scheduler.disabledJobs': [],
                 'scheduler.maxConcurrentRuns': 10,
                 'scheduler.runTimeoutS': 300,
                 'scheduler.runHistoryCount': 50,
                 'scheduler.runHistoryHours': 24,
                 'scheduler.niceBusyThreshold': 3,
                 'scheduler.niceLagMs': 200,
                 'scheduler.niceMaxDeferS': 120 };
  const settle = async function () {
    for (let i = 0; i < 20; i++) {
      await new Promise(function (r) { setImmediate(r); });
    }
  };
  // One scenario: `jobs` as descriptors, `realms`, and per tick `{ at,
  // loads, reads, claim }` (loads null: no runner at all).
  const scenario = async function (sc) {
    const settings = Object.assign({}, base, sc.settings || {});
    const store = new Map();
    const mapOf = function (id) {
      if (!store.has(id)) {
        store.set(id, new Map());
      }
      return store.get(id);
    };
    let clock = sc.ticks[0].at;
    let current = sc.ticks[0];
    let events = [];
    let watcher = null;
    const deps = {
      log: bunyan.createLogger({ name: 'vectors', level: 'fatal' }),
      config: { value: function (k) { return settings[k]; } },
      realms: { list: function () {
        return sc.realms.map(function (id) { return { id: id }; });
      }, run: function (r, fn) { return fn(); },
      get: function (id) {
        return sc.realms.indexOf(id) >= 0 ? { id: id } : null;
      }, DEFAULT_ID: 'default' },
      errorCodes: require(path.join(ROOT, 'common', 'error_codes.js')),
      audit: { record: function () {} },
      cluster: { enabled: function () { return true; },
                 nodeId: function () { return 'n1'; },
                 nodeName: function () { return 'node-one'; },
                 stepDown: function () {
                   events.push({ stepDown: true });
                   return Promise.resolve({ ok: true });
                 } },
      claims: {
        claim: function (o) {
          events.push({ claim: [o.scope, o.value, o.realm] });
          const used = current.claimUsed &&
            current.claimUsed.indexOf(o.scope) >= 0;
          return Promise.resolve(used ? { ok: false, reason: 'used' } :
            { ok: true, claimedAt: clock, handle: { v: o.value } });
        },
        release: function () { return Promise.resolve(null); }
      },
      store: { realmMap: mapOf,
               watch: function (fn) { watcher = fn; },
               dropHeld: function (realm, key) {
                 events.push({ drop: [realm, key] });
                 mapOf(realm).delete(key);
                 return true;
               },
               restoreRow: function (realm, key, row) {
                 mapOf(realm).set(key, row);
                 if (watcher) {
                   watcher(realm, row);
                 }
               } },
      dbNow: function () { return Promise.resolve(clock); },
      now: function () { return clock; },
      setTimer: function () { return null; }, clearTimer: function () {},
      cronPrev: S.cronPrev, cronNext: S.cronNext,
      host: 'h1', pid: 41, isRequestWorker: function () { return false; }
    };
    if (sc.history) {
      deps.persisted = function () { return true; };
      deps.readRuns = function (realm, ids) {
        events.push({ read: [realm, ids.slice()] });
        const how = (current.reads || {})[realm];
        if (how === 'fail' ||
            (how === 'fail-batch' && ids.length > 2) ||
            (Array.isArray(how) && ids.some(function (id) {
              return how.indexOf(id) >= 0;
            }))) {
          return Promise.reject(new Error('the store is unwell'));
        }
        if (how === 'none') {
          return Promise.resolve(null);
        }
        const out = new Map();
        (sc.stored || []).forEach(function (r) {
          if (r.realm === realm && ids.indexOf(r.runId) >= 0) {
            out.set(r.runId, r);
          }
        });
        return Promise.resolve(out);
      };
    }
    deps.runner = function () {
      if (!current.loads) {
        return null;
      }
      return { workers: function () { return current.loads; },
               run: function () {
                 return Promise.resolve({ ok: true, result: null });
               },
               fence: function () {}, renew: function () {} };
    };
    const sched = new S(deps);
    const specOf = function (d) {
      const spec = { id: d.id, title: 'T ' + d.id, describe: 'D', owner: 'O',
                     run: function () { return null; } };
      ['kind', 'scope', 'manualOnly', 'onFront', 'nice'].forEach(function (k) {
        if (d[k] !== undefined) {
          spec[k] = d[k];
        }
      });
      if (d.everyMs !== undefined) {
        spec.everyMs = function () { return d.everyMs; };
      }
      return spec;
    };
    sc.jobs.forEach(function (d) {
      sched.register(specOf(d));
    });
    (sc.admitted || []).forEach(function (one) {
      mapOf(one.realm).set(one.row.runId, Object.assign({}, one.row));
      if (one.watched) {
        watcher(one.realm, Object.assign({}, one.row));
      }
    });
    sched.leading = true;
    const ticks = [];
    const wasMulti = cells.isMulti;
    cells.isMulti = function () { return !!sc.cells; };
    try {
      for (const t of sc.ticks) {
        current = t;
        clock = t.at;
        events = [];
        await sched.tick();
        await settle();
        ticks.push(events);
      }
    } finally {
      cells.isMulti = wasMulti;
    }
    const rows = [];
    store.forEach(function (m, realm) {
      m.forEach(function (row) {
        if (row.kind !== 'run') {
          return;
        }
        rows.push({ realm: realm, runId: row.runId, jobId: row.jobId,
                    state: row.state, trigger: row.trigger,
                    attempt: row.attempt, ranIn: row.ranIn === undefined ?
                      null : row.ranIn,
                    deferredMs: row.deferredMs === undefined ? null :
                      row.deferredMs });
      });
    });
    rows.sort(function (a, b) {
      return (a.realm + a.runId).localeCompare(b.realm + b.runId);
    });
    return { name: sc.name, ticks: ticks, rows: rows };
  };
  const heavy = [{ id: 5, inFlight: 4, lagMs: 10 },
                 { id: 3, inFlight: 4, lagMs: null }];
  const lagging = [{ id: 2, inFlight: 0, lagMs: 250 }];
  const light = [{ id: 7, inFlight: 1, lagMs: 20 },
                 { id: 4, inFlight: 1, lagMs: 20 }];
  const H = function (job, realm, slot) {
    return S.prototype.runIdFor.call({ deps: { log: { debug: function () {} } } },
                                     { id: job }, realm, slot);
  };
  const realmJobs = [{ id: 'a.one', everyMs: 600000, scope: 'realm' },
                     { id: 'a.two', everyMs: 600000, scope: 'realm' },
                     { id: 'a.three', everyMs: 600000, scope: 'realm' },
                     { id: 'a.four', everyMs: 600000, scope: 'realm' }];
  const slotNow = Math.floor(t0 / 600000);
  const scenarios = [
    { name: 'hold-for-load', realms: ['default'],
      jobs: [{ id: 'n.patient', everyMs: 600000, nice: 19 },
             { id: 'n.zero', everyMs: 600000, nice: 0 },
             { id: 'n.front', everyMs: 600000, onFront: 'it holds a socket' },
             { id: 'n.mid', everyMs: 60000, nice: 10 },
             { id: 'n.lag', everyMs: 600000, nice: 5 }],
      ticks: [{ at: t0, loads: heavy }, { at: t0 + 20000, loads: heavy },
              { at: t0 + 40000, loads: heavy },
              { at: t0 + 50000, loads: light }] },
    { name: 'lag-alone', realms: ['default'],
      jobs: [{ id: 'n.lag', everyMs: 600000, nice: 5 }],
      ticks: [{ at: t0, loads: lagging }, { at: t0 + 1000, loads: [] },
              { at: t0 + 2000, loads: lagging }] },
    { name: 'no-runner', realms: ['default'],
      jobs: [{ id: 'n.patient', everyMs: 600000, nice: 19 }],
      ticks: [{ at: t0, loads: null }] },
    { name: 'pending-index', realms: ['default', 'acme'],
      jobs: [{ id: 'm.manual', manualOnly: true }],
      admitted: [
        { realm: 'default', watched: true, row: {
          runId: 'm1', kind: 'run', jobId: 'm.manual', realm: 'default',
          trigger: 'manual', state: 'queued', params: null, attempt: 0,
          fenceAt: 0, queuedAt: t0 - 2000, updatedAt: t0 - 2000 } },
        { realm: 'acme', watched: false, row: {
          runId: 'm2', kind: 'run', jobId: 'm.manual', realm: 'acme',
          trigger: 'manual', state: 'queued', params: null, attempt: 0,
          fenceAt: 0, queuedAt: t0 - 3000, updatedAt: t0 - 3000 } },
        { realm: 'acme', watched: true, row: {
          runId: 'm3', kind: 'run', jobId: 'm.manual', realm: 'acme',
          trigger: 'manual', state: 'queued', params: null, attempt: 0,
          fenceAt: 0, queuedAt: t0 - 1000, updatedAt: t0 - 1000 } },
        { realm: 'default', watched: false, row: {
          runId: 'command|silent', kind: 'command', command: 'step-down',
          state: 'queued', queuedAt: t0 - 500, updatedAt: t0 - 500 } }],
      ticks: [{ at: t0, loads: null }] },
    { name: 'finished-slots', realms: ['default', 'acme'], history: true,
      jobs: realmJobs,
      stored: [{ runId: H('a.one', 'default', slotNow), kind: 'run',
                 jobId: 'a.one', realm: 'default', trigger: 'schedule',
                 state: 'succeeded', attempt: 1, fenceAt: t0 - 9,
                 startedAt: t0 - 9, endedAt: t0 - 5, updatedAt: t0 - 5 }],
      ticks: [{ at: t0 + 1000, loads: null,
                reads: { acme: [H('a.two', 'acme', slotNow),
                                H('a.three', 'acme', slotNow)] } },
              { at: t0 + 2000, loads: null, reads: { acme: 'none' } }] },
    { name: 'read-outage', realms: ['default', 'acme'], history: true,
      jobs: realmJobs,
      ticks: [{ at: t0 + 1000, loads: null,
                reads: { default: 'fail', acme: 'fail' } }] },
    { name: 'global-claim', realms: ['default'], cells: true,
      jobs: [{ id: 'signing.rotate', everyMs: 600000 },
             { id: 'x.local', everyMs: 600000 }],
      ticks: [{ at: t0, loads: null, claimUsed: ['scheduler.run.global'] },
              { at: t0 + 1000, loads: null,
                claimUsed: ['scheduler.run.global'] }] },
    { name: 'global-claim-one-cell', realms: ['default'], cells: false,
      jobs: [{ id: 'signing.rotate', everyMs: 600000 }],
      ticks: [{ at: t0, loads: null }] }
  ];
  const out = [];
  for (const sc of scenarios) {
    out.push(Object.assign({ scenario: sc }, await scenario(sc)));
  }
  // The default cap with request workers (2026-11-10): the larger of two
  // and one fewer than the workers, never every store connection.
  let workers = 0;
  let pool = 0;
  const capSched = new S({
    log: bunyan.createLogger({ name: 'vectors', level: 'fatal' }),
    config: { value: function (k) {
      return k === 'scheduler.maxConcurrentRuns' ? 0 : base[k];
    } },
    realms: { list: function () { return []; }, DEFAULT_ID: 'default',
              get: function () { return null; } },
    errorCodes: require(path.join(ROOT, 'common', 'error_codes.js')),
    store: { realmMap: function () { return new Map(); } },
    requestWorkers: function () { return workers; },
    storeConnections: function () { return pool; },
    now: function () { return 0; }, host: 'h', pid: 1,
    isRequestWorker: function () { return false; }
  });
  const caps = [];
  [0, 1, 2, 3, 8].forEach(function (w) {
    [0, 3, 20].forEach(function (p) {
      workers = w;
      pool = p;
      caps.push({ workers: w, pool: p, cap: capSched.maxConcurrentRuns() });
    });
  });
  return { settings: base, scenarios: out, caps: caps,
           leastLoaded: [heavy, lagging, light, [], [
             { id: 9, inFlight: 0, lagMs: null },
             { id: 8, inFlight: 0, lagMs: 0 }]].map(function (l) {
             return { loads: l, id: S.leastLoaded(l) };
           }) };
}

// THE CACHE REGISTRY (`common/cache_registry.js`, rule 3ap, #74, #704): three
// stores the vectors describe — one per process with entries expired and not,
// one per realm whose lookup is not counted, and one replay store that
// TALLIES rather than lists — asked for the report `/admin/caches` draws, one
// store's detail, the compact snapshot a heartbeat carries, and an ejection,
// with the report after it. The registry is the process's one, so every store
// another module registered is forgotten first.
async function cacheRegistryVectors() {
  const reg = require(path.join(ROOT, 'common', 'cache_registry.js'));
  reg.names().forEach(function (n) {
    reg.forget(n);
  });
  const now = Date.UTC(2026, 9, 5, 12, 0, 0);
  const procRows = new Map([['k1', now - 5], ['k2', now + 1000],
                            ['k3', null]]);
  const realmRows = [{ realm: 'acme', key: 'a1', validUntil: now + 5 },
                     { realm: 'acme', key: 'a2', validUntil: now - 1 },
                     { realm: null, key: 'd1', validUntil: now + 9 }];
  const descriptors = [
    { name: 'v.process', title: 'Process store', description: 'D one',
      owner: 'o/one.js', scope: 'process', bound: 'ENFORCED: three.',
      settings: ['v.max'] },
    { name: 'v.realm', title: 'Realm store', description: 'D two',
      owner: 'o/two.js', scope: 'realm', counted: false,
      notCountedWhy: 'its lookup is elsewhere' },
    { name: 'v.tally', title: 'Replay store', description: 'D three',
      owner: 'o/three.js', scope: 'realm', kind: 'replay', persisted: true,
      hitMeaning: 'a value seen before' }
  ];
  const c1 = reg.register(Object.assign({}, descriptors[0], {
    maxEntries: function () { return 3; },
    lifetime: function () { return 'five minutes'; },
    entries: function (at) {
      return Array.from(procRows.entries()).map(function (e) {
        return { realm: null, key: e[0], validUntil: e[1],
                 valid: e[1] === null || e[1] > at,
                 basis: e[1] === null ? 'no expiry' : 'time' };
      });
    },
    eject: function (at) {
      let n = 0;
      procRows.forEach(function (until, key) {
        if (until !== null && until <= at) {
          procRows.delete(key);
          n += 1;
        }
      });
      return n;
    }
  }));
  const c2 = reg.register(Object.assign({}, descriptors[1], {
    maxEntries: function () { return 2; },
    lifetime: function () { return 'an hour'; },
    entries: function (at) {
      return realmRows.map(function (r) {
        return { realm: r.realm, key: r.key, validUntil: r.validUntil,
                 valid: r.validUntil > at, basis: 'time' };
      });
    }
  }));
  const c3 = reg.register(Object.assign({}, descriptors[2], {
    maxEntries: function () { return 100; },
    lifetime: function () { return 'a day'; },
    entries: function () { return []; },
    tally: function () { return { size: 10, largestRealm: 6, valid: 7 }; }
  }));
  c1.hit(); c1.hit(); c1.hit(); c1.miss(); c1.evicted(2);
  c2.hit(); c2.refused();
  c3.miss();
  const out = { now: now, descriptors: descriptors,
                procRows: Array.from(procRows.entries()),
                realmRows: realmRows,
                report: reg.report(now),
                detail: reg.detail('v.process', now),
                snapshot: reg.snapshot(now) };
  out.ejected = await reg.ejectExpiredAsync(now);
  out.after = reg.report(now);
  out.snapshotAsync = await reg.snapshotAsync(now);
  ['v.process', 'v.realm', 'v.tally'].forEach(function (n) {
    reg.forget(n);
  });
  return out;
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
  // recentRuns() and findRun() answer promises since the run store became
  // windowed (they may read a realm's partition from the store).
  const recent = [];
  for (const q of queries) {
    recent.push({ query: q, runs: (await sched.recentRuns(q, now))
      .map(function (r) {
        return r.runId;
      }) });
  }
  const found = [];
  for (const id of ['e1', 'process|p.pull|default|n1|41', 'leader',
                    'nope']) {
    found.push(await sched.findRun(id));
  }
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
  // A name or description the store could never hold (#1463).
  create('nul', {}, { name: 'a\u0000b', description: 'd\u0000' });
  // The cluster's cap (#368): at the count, a create is refused.
  const cap = function (raw) {
    if (raw === null) {
      config.clearOverride('realms.maxCount');
    } else {
      config.setOverride('realms.maxCount', raw);
    }
    steps.push({ op: 'config', key: 'realms.maxCount', raw: raw,
                 result: { ok: true, errors: [], code: null } });
  };
  cap(realms.list().length);
  create('full', {});
  cap(null);
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
  update('acme', { description: 'bad\u0000' });
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
  // Bodies that are not pages (Qualys QID 150207) and types owed a charset
  // (#1439), each written with the bare type so the flush is what adds it.
  const raw = function (type, body) {
    return function (req, res) {
      res.setHeader('Content-Type', type);
      res.end(body);
    };
  };
  app.get('/probe/json', raw('application/json', '{"a":1}'));
  app.get('/probe/jrd', raw('application/jrd+json', '{}'));
  app.get('/probe/xml', raw('application/samlmetadata+xml', '<x/>'));
  app.get('/probe/text-xml', raw('text/xml', '<x/>'));
  app.get('/probe/svg', raw('image/svg+xml', '<svg/>'));
  app.get('/probe/css', raw('text/css', 'a{}'));
  app.get('/probe/named', raw('text/plain; charset=iso-8859-1', 'x'));
  app.get('/probe/octets', raw('application/octet-stream', 'x'));
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const paths = ['/probe/html', '/realm/acme/probe/html', '/probe/redirect',
                 '/realm/acme/probe/redirect', '/probe/own-csp',
                 '/probe/relaxed', '/probe/framed', '/probe/realm',
                 '/realm/acme/probe/realm?x=1', '/nope', '/realm/nope/x',
                 '/realm/acme/nope', '/probe/<script>', '/probe/json',
                 '/probe/jrd', '/probe/xml', '/probe/text-xml', '/probe/svg',
                 '/probe/css', '/probe/named', '/probe/octets'];
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
           'x-content-type-options', 'referrer-policy', 'location',
           'permissions-policy']
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
      return { origins: o, overrides: {},
               value: app.framedContentSecurityPolicy(o) };
    }).concat([
      // `script-src` names scripts exactly or not at all (#1297).
      { 'script-src': "'unsafe-inline' 'self' 'sha256-AbC+/9=' nonce-x" },
      { 'script-src': "'unsafe-inline' 'unsafe-eval' * https://x" },
      { 'script-src': "'none' 'sha384-q' 'sha512-a===' 'sha1-abc'" },
      { 'script-src': null, 'connect-src': "'self'" }
    ].map(function (o) {
      return { origins: ['https://rp.example'], overrides: o,
               value: app.framedContentSecurityPolicy(['https://rp.example'],
                                                      o) };
    })),
    notAPage: app.NOT_A_PAGE_POLICY || null
  };
}

// THE KERBEROS CODEC (#444, phase 2b): what kerberos/'s codec modules make
// of a broad set of messages, keys and tokens — every enctype's
// string-to-key, derived keys, encryptions (the confounder fixed, so Node is
// deterministic) and checksums, RFC 3962's and RFC 8009's published vectors,
// every RFC 4120 message decoded and re-encoded (and refused, with Node's
// sentence), the RFC 4121 0x8003 checksum, MIC and Wrap tokens, SPNEGO,
// FAST, PKINIT and the MS-KKDCP envelope — for `sts-kerberos`'s
// `tests/node_vectors.rs` to reproduce. Nothing here is secret: the keys
// are derived from fixed strings.
async function krb5Codec() {
  const K = path.join(ROOT, 'kerberos');
  const prim = require(path.join(K, 'krb5_primitives.js'));
  const asn1 = require(path.join(K, 'krb5_asn1.js'));
  const kc = require(path.join(K, 'krb5_crypto.js'));
  const m = require(path.join(K, 'krb5_messages.js'));
  const gss = require(path.join(K, 'krb5_gss.js'));
  const sp = require(path.join(K, 'krb5_spnego.js'));
  const fc = require(path.join(K, 'krb5_fast_codec'));
  const pc = require(path.join(K, 'krb5_pkinit_codec'));
  const hex = function (b) { return Buffer.from(b).toString('hex'); };
  const unhex = function (s) { return new Uint8Array(Buffer.from(s, 'hex')); };
  const utf = function (s) { return new Uint8Array(Buffer.from(s, 'utf8')); };
  // Node's answer as JSON: bytes as hex, a Date as ISO 8601, `undefined`
  // dropped — the form `sts-kerberos` serializes its structures to.
  const norm = function (v) {
    if (v === null || v === undefined) {
      return v === null ? null : undefined;
    }
    if (v instanceof Uint8Array) {
      return hex(v);
    }
    if (v instanceof Date) {
      return v.toISOString();
    }
    if (Array.isArray(v)) {
      return v.map(norm);
    }
    if (typeof v === 'object') {
      const out = {};
      Object.keys(v).forEach(function (k) {
        const n = norm(v[k]);
        if (n !== undefined) {
          out[k] = n;
        }
      });
      return out;
    }
    return v;
  };
  const stripRaw = function (v) {
    if (v instanceof Uint8Array || v instanceof Date || v === null ||
        typeof v !== 'object') {
      return v;
    }
    if (Array.isArray(v)) {
      return v.map(stripRaw);
    }
    const out = {};
    Object.keys(v).forEach(function (k) {
      if (k !== 'raw') {
        out[k] = stripRaw(v[k]);
      }
    });
    return out;
  };
  const attempt = function (f) {
    try {
      return { ok: f() };
    } catch (e) {
      return { error: (e && e.message) || String(e) };
    }
  };
  const attemptAsync = async function (f) {
    try {
      return { ok: await f() };
    } catch (e) {
      return { error: (e && e.message) || String(e) };
    }
  };
  const T = function (s) { return new Date(s); };
  const pn = function (type, name) { return { type: type, name: name }; };

  // ---- primitives -------------------------------------------------------
  const inputs = ['', 'a', 'abc', 'message digest', 'kerberos',
    'The quick brown fox jumps over the lazy dog', 'é漢字𝄞',
    'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'x'.repeat(200)];
  const primitives = inputs.map(function (s) {
    const b = utf(s);
    return { text: s, input: hex(b), md4: hex(prim.md4(b)),
             md5: hex(prim.md5(b)), utf16le: hex(prim.utf16le(s)),
             hmacShort: hex(prim.hmacMd5(utf('key'), b)),
             hmacLong: hex(prim.hmacMd5(new Uint8Array(100).fill(7), b)),
             rc4: hex(prim.rc4(utf('Secret'), b)),
             fromUtf8: prim.fromUtf8(b) };
  });
  [[0xc3], [0xc0, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80],
   [0x80], [0xe2, 0x82]].forEach(function (bad) {
    primitives.push({ text: null, input: hex(new Uint8Array(bad)),
                      fromUtf8: prim.fromUtf8(new Uint8Array(bad)) });
  });
  const nfold = [];
  ['012345', 'password', 'Rough Consensus, and Running Code', 'kerberos',
   'Q', 'ba', '', 'prf'].forEach(function (s) {
    [0, 8, 56, 64, 128, 168, 256].forEach(function (bits) {
      const r = attempt(function () { return prim.nfold(utf(s), bits); });
      nfold.push({ input: hex(utf(s)), bits: bits,
                   out: r.ok ? hex(r.ok) : null, error: r.error || null });
    });
  });

  // ---- enctypes ---------------------------------------------------------
  const IDS = [17, 18, 19, 20, 23];
  const profiles = IDS.map(function (id) {
    const e = kc.ETYPES[id];
    return { id: e.id, name: e.name, keyBytes: e.keyBytes,
             blockBytes: e.blockBytes, confounderBytes: e.confounderBytes,
             checksumBytes: e.checksumBytes, checksumType: e.checksumType,
             defaultIterations: e.defaultIterations, rfc: e.rfc,
             legacy: e.legacy };
  });
  const etypeNames = [];
  for (let id = -1; id <= 30; id++) {
    const r = attempt(function () { return kc.etypeById(id); });
    etypeNames.push({ id: id, name: kc.etypeName(id),
                      supported: kc.isSupportedEtype(id),
                      error: r.error || null });
  }
  const s2k = [];
  const salts = [['password', 'ATHENA.MIT.EDUraeburn'],
    ['pässwörd', 'EXAMPLE.COMalice'], ['', ''],
    ['𝄞', 'EXAMPLE.COMpianist'], ['Pa55w0rd!', 'host/x']];
  for (const id of IDS) {
    for (const [pw, salt] of salts) {
      for (const params of [null, unhex('00000001'), unhex('00000002'),
                            unhex('000003e8'), unhex('00000000'),
                            unhex('0001')]) {
        const r = await attemptAsync(function () {
          return kc.ETYPES[id].stringToKey(pw, utf(salt), params);
        });
        s2k.push({ etype: id, password: pw, salt: hex(utf(salt)),
                   params: params ? hex(params) : null,
                   key: r.ok ? hex(r.ok) : null, error: r.error || null });
      }
    }
  }
  // RFC 3962 appendix B: string-to-key for both AES-SHA1 sizes.
  const RFC3962 = [
    [1, 'password', utf('ATHENA.MIT.EDUraeburn'),
     '42263c6e89f4fc28b8df68ee09799f15',
     'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161'],
    [2, 'password', utf('ATHENA.MIT.EDUraeburn'),
     'c651bf29e2300ac27fa469d693bdda13',
     'a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff'],
    [1200, 'password', utf('ATHENA.MIT.EDUraeburn'),
     '4c01cd46d632d01e6dbe230a01ed642a',
     '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a'],
    [5, 'password', unhex('1234567878563412'),
     'e9b23d52273747dd5c35cb55be619d8e',
     '97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31'],
    [1200, 'X'.repeat(64), utf('pass phrase equals block size'),
     '59d1bb789a828b1aa54ef9c2883f69ed',
     '89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34'],
    [1200, 'X'.repeat(65), utf('pass phrase exceeds block size'),
     'cb8005dc5f90179a7f02104c0018751d',
     'd78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b'],
    [50, '𝄞', utf('EXAMPLE.COMpianist'),
     'f149c1f2e154a73452d43e7fe62a56e5',
     '4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e']];
  for (const [iter, pw, salt, k128, k256] of RFC3962) {
    const params = new Uint8Array(4);
    new DataView(params.buffer).setUint32(0, iter);
    for (const [id, expect] of [[17, k128], [18, k256]]) {
      s2k.push({ etype: id, password: pw, salt: hex(salt),
                 params: hex(params), expect: expect,
                 key: hex(await kc.ETYPES[id].stringToKey(pw, salt, params)),
                 error: null });
    }
  }
  // RFC 8009 appendix A: string-to-key, the derived keys, encryptions and
  // checksums for both AES-SHA2 sizes.
  const r8009Salt = unhex('10df9dd783e5bc8acea1730e74355f61' +
                          hex(utf('ATHENA.MIT.EDUraeburn')));
  s2k.push({ etype: 19, password: 'password', salt: hex(r8009Salt),
             params: null, expect: '089bca48b105ea6ea77ca5d2f39dc5e7',
             key: hex(await kc.ETYPES[19].stringToKey('password', r8009Salt)),
             error: null });
  s2k.push({ etype: 20, password: 'password', salt: hex(r8009Salt),
             params: null,
             expect: '45bd806dbf6a833a9cffc1c94589a222' +
                     '367a79bc21c413718906e9f578a78467',
             key: hex(await kc.ETYPES[20].stringToKey('password', r8009Salt)),
             error: null });
  const R8009 = {
    19: { base: '3705d96080c17728a0e800eab6e0d23c',
          kc: 'b31a018a48f54776f403e9a396325dc3',
          ke: '9b197dd1e8c5609d6e67c3e37c62c72e',
          ki: '9fda0e56ab2d85e1569a688696c26a6c',
          enc: [['', '7e5895eaf2672435bad817f545a37148',
                 'ef85fb890bb8472f4dab20394dca781dad877eda39d50c87' +
                 '0c0d5a0a8e48c718'],
                ['000102030405', '7bca285e2fd4130fb55b1a5c83bc5b24',
                 '84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877c' +
                 'e99e247e52d16ed4' +
                 '421dfdf8976c'],
                ['000102030405060708090a0b0c0d0e0f',
                 '56ab21713ff62c0a1457200f6fa9948f',
                 '3517d640f50ddc8ad3628722b3569d2ae07493fa82632540' +
                 '80ea65c1008e8fc2' +
                 '95fb4852e7d83e1e7c48c37eebe6b0d3'],
                ['000102030405060708090a0b0c0d0e0f1011121314',
                 'a7a4e29a4728ce10664fb64e49ad3fac',
                 '720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c' +
                 '5573544c31c813bc' +
                 'e1e6d072c186b39a413c2f92ca9b8334a287ffcbfc']],
          cksum: 'd78367186643d67b411cba9139fc1dee' },
    20: { base: '6d404d37faf79f9df0d33568d320669800eb4836472ea8a0' +
                '26d16b7182460c52',
          kc: 'ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d',
          ke: '56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c383' +
              '12980c442e5c7e49',
          ki: '69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f',
          enc: [['', 'f764e9fa15c276478b2c7d0c4e5f58e4',
                 '41f53fa5bfe7026d91faf9be959195a058707273a96a40f0' +
                 'a01960621ac61274' +
                 '8b9bbfbe7eb4ce3c'],
                ['000102030405', 'b80d3251c1f6471494256ffe712d0b9a',
                 '4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559' +
                 'c7f664f69eab7b60' +
                 '92237526ea0d1f61cb20d69d10f2'],
                ['000102030405060708090a0b0c0d0e0f',
                 '53bf8a0d105265d4e276428624ce5e63',
                 'bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f' +
                 '49beca92027764f6' +
                 '8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266'],
                ['000102030405060708090a0b0c0d0e0f1011121314',
                 '763e65367e864f02f55153c7e3b58af1',
                 '40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae' +
                 '79db3c3ee86429f2' +
                 'b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62']],
          cksum: '45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a' } };
  const keyFor = function (id, n) {
    // A key of the etype's size, from a fixed string.
    const seed = nodeCrypto.createHash('sha256')
      .update('krb5-codec ' + id + ' ' + n).digest();
    return new Uint8Array(seed.subarray(0, kc.ETYPES[id].keyBytes));
  };
  const derived = [];
  const encryptions = [];
  const checksums = [];
  const decryptErrors = [];
  const USAGES = [1, 2, 3, 7, 8, 9, 11, 12, 13, 22, 23, 24, 25, 51, 1024];
  const LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100];
  for (const id of IDS) {
    const e = kc.ETYPES[id];
    for (let n = 0; n < 2; n++) {
      const key = keyFor(id, n);
      for (const usage of USAGES) {
        if (e.encryptionKey) {
          derived.push({ etype: id, key: hex(key), usage: usage,
            ke: hex(await e.encryptionKey(key, usage)),
            ki: hex(await e.integrityKey(key, usage)),
            kc: hex(await e.checksumKey(key, usage)) });
        }
        for (const len of LENGTHS) {
          const plain = new Uint8Array(len).map(function (_, i) {
            return (i * 7 + usage) & 0xff;
          });
          const conf = new Uint8Array(e.confounderBytes).map(function (_, i) {
            return (i * 13 + len + n) & 0xff;
          });
          encryptions.push({ etype: id, key: hex(key), usage: usage,
            plain: hex(plain), confounder: hex(conf),
            cipher: hex(await e.encrypt(key, usage, plain, conf)) });
          checksums.push({ etype: id, key: hex(key), usage: usage,
            message: hex(plain),
            checksum: hex(await e.checksum(key, usage, plain)) });
        }
      }
      // Refusals: a flipped bit, the wrong usage, a short ciphertext.
      const good = await e.encrypt(key, 3, utf('hello'),
                                   new Uint8Array(e.confounderBytes));
      const flipped = new Uint8Array(good);
      flipped[flipped.length - 1] ^= 1;
      for (const [usage, cipher] of [[3, flipped], [4, good],
                                     [3, good.subarray(0, 10)],
                                     [3, good.subarray(0, 27)]]) {
        const r = await attemptAsync(function () {
          return e.decrypt(key, usage, cipher);
        });
        decryptErrors.push({ etype: id, key: hex(key), usage: usage,
                             cipher: hex(cipher), error: r.error || null,
                             plain: r.ok ? hex(r.ok) : null });
      }
    }
    if (R8009[id]) {
      const r = R8009[id];
      const base = unhex(r.base);
      derived.push({ etype: id, key: r.base, usage: 2,
        ke: hex(await e.encryptionKey(base, 2)),
        ki: hex(await e.integrityKey(base, 2)),
        kc: hex(await e.checksumKey(base, 2)),
        expect: { ke: r.ke, ki: r.ki, kc: r.kc } });
      for (const [plain, conf, cipher] of r.enc) {
        encryptions.push({ etype: id, key: r.base, usage: 2, plain: plain,
          confounder: conf, expect: cipher,
          cipher: hex(await e.encrypt(base, 2, unhex(plain), unhex(conf))) });
      }
      checksums.push({ etype: id, key: r.base, usage: 2,
        message: '000102030405060708090a0b0c0d0e0f1011121314',
        expect: r.cksum,
        checksum: hex(await e.checksum(base, 2,
          unhex('000102030405060708090a0b0c0d0e0f1011121314'))) });
    }
  }
  // RFC 3962 appendix B's CTS vectors.
  const ctsKey = utf('chicken teriyaki');
  const soup = utf('I would like the General Gau\'s Chicken, please, ' +
                   'and wonton soup.');
  const CTS = [[17, 'c6353568f2bf8cb4d8a580362da7ff7f97'],
    [31, 'fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5'],
    [32, '39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584'],
    [47, '97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e' +
         '39312523a78662d5be7fcbcc98ebf5'],
    [48, '97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd8' +
         '39312523a78662d5be7fcbcc98ebf5a8'],
    [64, '97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8' +
         '4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8']];
  const cts = [];
  for (const [len, expect] of CTS) {
    cts.push({ key: hex(ctsKey), plain: hex(soup.subarray(0, len)),
      expect: expect,
      cipher: hex(await kc.ctsEncrypt(ctsKey, new Uint8Array(16),
                                      soup.subarray(0, len))) });
  }
  for (const len of [0, 15, 16, 20, 33, 80]) {
    const r = await attemptAsync(function () {
      return kc.ctsEncrypt(keyFor(18, 0), new Uint8Array(16),
                           new Uint8Array(len).fill(len));
    });
    cts.push({ key: hex(keyFor(18, 0)),
               plain: hex(new Uint8Array(len).fill(len)),
               cipher: r.ok ? hex(r.ok) : null, error: r.error || null });
  }

  // ---- messages ---------------------------------------------------------
  const messages = [];
  const tlvOf = function (b) { return asn1.readTlv(b, 0); };
  // kind -> [read(bytes), encode(read result)]. A null encoder means Node
  // has no encoder for that reader.
  const KINDS = {
    PrincipalName: [function (b) { return m.readPrincipalName(tlvOf(b)); },
                    m.encPrincipalName],
    EncryptedData: [function (b) { return m.readEncryptedData(tlvOf(b)); },
                    m.encEncryptedData],
    EncryptionKey: [function (b) { return m.readEncryptionKey(tlvOf(b)); },
                    m.encEncryptionKey],
    Checksum: [function (b) { return m.readChecksum(tlvOf(b)); },
               m.encChecksum],
    PaData: [function (b) { return m.readPaData(tlvOf(b)); }, m.encPaData],
    HostAddresses: [function (b) { return m.readHostAddresses(tlvOf(b)); },
                    m.encHostAddresses],
    AuthorizationData: [function (b) {
      return m.readAuthorizationData(tlvOf(b));
    }, m.encAuthorizationData],
    Ticket: [m.readTicket, m.encTicket],
    EncTicketPart: [m.readEncTicketPart, m.encEncTicketPart],
    KdcReqBody: [function (b) { return m.readKdcReqBody(tlvOf(b)); },
                 m.encKdcReqBody],
    KdcReq: [m.readKdcReq, m.encKdcReq],
    KdcRep: [m.readKdcRep, m.encKdcRep],
    EncKdcRepPart: [m.readEncKdcRepPart, function (p) {
      return m.encEncKdcRepPart(p, p.taggedAs === 'EncTGSRepPart' ? 26 : 25);
    }],
    Authenticator: [m.readAuthenticator, m.encAuthenticator],
    ApReq: [m.readApReq, m.encApReq],
    ApRep: [m.readApRep, m.encApRep],
    EncApRepPart: [m.readEncApRepPart, m.encEncApRepPart],
    KrbError: [m.readKrbError, m.encKrbError],
    PaEncTsEnc: [m.readPaEncTsEnc, function (p) {
      return m.encPaEncTsEnc(p.patimestamp, p.pausec);
    }],
    EtypeInfo2: [m.readEtypeInfo2, m.encEtypeInfo2],
    EtypeInfo: [m.readEtypeInfo, null],
    PaPacRequest: [m.readPaPacRequest, function (p) {
      return p.includePac === undefined ? null
        : m.encPaPacRequest(p.includePac);
    }],
    PaForUser: [m.readPaForUser, m.encPaForUser],
    PaPacOptions: [m.readPaPacOptions, function (p) {
      return m.encPaPacOptions(p.flags);
    }],
    EncKrbCredPart: [m.readEncKrbCredPart, m.encEncKrbCredPart],
    KrbCred: [m.readKrbCred, m.encKrbCred],
    KdcResponse: [m.readKdcResponse, null],
    'fast.Armor': [function (b) { return fc.readArmor(tlvOf(b)); },
                   fc.encArmor],
    'fast.FastRequest': [fc.readFastRequest, fc.encFastRequest],
    'fast.FastReq': [fc.readFastReq, fc.encFastReq],
    'fast.FastReply': [fc.readFastReply, fc.encFastReply],
    'fast.FastResponse': [fc.readFastResponse, fc.encFastResponse],
    'fast.FastFinished': [function (b) {
      return fc.readFastFinished(tlvOf(b));
    }, fc.encFastFinished],
    'fast.OtpChallenge': [fc.readOtpChallenge, fc.encOtpChallenge],
    'fast.TokenInfo': [function (b) { return fc.readTokenInfo(tlvOf(b)); },
                       fc.encTokenInfo],
    'fast.OtpRequest': [fc.readOtpRequest, fc.encOtpRequest],
    'fast.OtpEncData': [fc.readOtpEncData, null],
    'fast.VerifierMac': [function (b) {
      return fc.readVerifierMac(tlvOf(b));
    }, fc.encVerifierMac],
    'fast.Cammac': [fc.readCammac, fc.encCammac],
    'fast.Indicators': [fc.readIndicators, fc.encIndicators],
    'pkinit.Krb5PrincipalName': [pc.readKrb5PrincipalName, function (p) {
      return pc.encKrb5PrincipalName(p.realm, p.name);
    }],
    'pkinit.PaPkAsReq': [pc.readPaPkAsReq, pc.encPaPkAsReq],
    'pkinit.AuthPack': [pc.readAuthPack, pc.encAuthPack],
    'pkinit.KdfAlgorithmId': [function (b) {
      return pc.readKdfAlgorithmId(tlvOf(b));
    }, pc.encKdfAlgorithmId],
    'pkinit.KdcDhKeyInfo': [pc.readKdcDhKeyInfo, pc.encKdcDhKeyInfo],
    'pkinit.PaPkAsRep': [pc.readPaPkAsRep, pc.encPaPkAsRep],
    'pkinit.TypedData': [pc.readTypedData, pc.encTypedData]
  };
  const add = function (kind, bytes, note) {
    const [read, enc] = KINDS[kind];
    const r = attempt(function () { return read(bytes); });
    const row = { kind: kind, note: note || null, bytes: hex(bytes) };
    if (r.error !== undefined) {
      row.error = r.error;
    } else {
      row.decoded = norm(r.ok);
      if (enc) {
        const again = attempt(function () { return enc(r.ok); });
        row.reencoded = again.ok ? hex(again.ok) : null;
        const rebuilt = attempt(function () { return enc(stripRaw(r.ok)); });
        row.rebuilt = rebuilt.ok ? hex(rebuilt.ok) : null;
      }
    }
    messages.push(row);
  };
  // Raw DER helpers for hand-made inputs.
  const tlv = function (tag, bytes) {
    return asn1.tlv(tag, bytes);
  };
  const cat = function () {
    return prim.concat(Array.prototype.slice.call(arguments));
  };
  const ctx = function (n, inner) { return asn1.encContext(n, inner); };
  const seq = function () {
    return asn1.encSequence(Array.prototype.slice.call(arguments));
  };
  const app = function (n, inner) { return asn1.encApplication(n, inner); };
  const int = asn1.encInteger;
  const gstr = asn1.encGeneralString;
  const oct = asn1.encOctetString;
  const ktime = asn1.encKerberosTime;

  const alice = pn(1, ['alice']);
  const krbtgt = pn(2, ['krbtgt', 'EXAMPLE.COM']);
  const http = pn(3, ['HTTP', 'web.example.com']);
  const enc1 = { etype: 18, kvno: 2, cipher: unhex('00112233445566778899') };
  const enc2 = { etype: 23, cipher: new Uint8Array(0) };
  const ticket = { realm: 'EXAMPLE.COM', sname: krbtgt, encPart: enc1 };
  const ticketBytes = m.encTicket(ticket);
  const ticket2 = { realm: 'PARTÉ.COM', sname: http,
                    encPart: { etype: 17, kvno: 0, cipher: unhex('ff') } };
  const t0 = T('2026-11-14T10:00:00Z');
  const t1 = T('2026-11-14T20:00:00Z');
  const t2 = T('2026-11-21T10:00:00Z');

  add('PrincipalName', m.encPrincipalName(alice));
  add('PrincipalName', m.encPrincipalName(pn(10, ['alice@example.com'])));
  add('PrincipalName', m.encPrincipalName(pn(-128, [])));
  add('PrincipalName', m.encPrincipalName(pn(3, ['host', 'a.b', 'x', 'é'])));
  add('EncryptedData', m.encEncryptedData(enc1));
  add('EncryptedData', m.encEncryptedData(enc2));
  add('EncryptedData', m.encEncryptedData({ etype: 26, kvno: 70000,
                                            cipher: unhex('01') }));
  add('EncryptedData', m.encEncryptedData({ etype: 3, cipher: unhex('02') }));
  add('EncryptionKey', m.encEncryptionKey({ etype: 20,
                                            key: keyFor(20, 0) }));
  add('Checksum', m.encChecksum({ type: -138, checksum: unhex('aa') }));
  add('Checksum', m.encChecksum({ type: 0x8003,
                                 checksum: new Uint8Array(24) }));
  for (const t of [1, 2, 3, 11, 19, 128, 129, 130, 133, 136, 137, 138, 167,
                   999]) {
    add('PaData', m.encPaData({ type: t, value: unhex('3000') }));
  }
  add('PaData', seq(ctx(1, int(2))), 'a PA-DATA with no value');
  add('HostAddresses', m.encHostAddresses([
    { type: 2, address: unhex('c0a80001') },
    { type: 24, address: unhex('20010db8000000000000000000000001') }]));
  add('HostAddresses', m.encHostAddresses([]));
  add('AuthorizationData', m.encAuthorizationData([
    { type: 1, data: unhex('3000') }, { type: 128, data: unhex('0102') }]));
  add('Ticket', ticketBytes);
  add('Ticket', m.encTicket(ticket2));
  const etp = { flags: [1, 8, 9, 10, 13, 15], key: { etype: 18,
    key: keyFor(18, 1) }, crealm: 'EXAMPLE.COM', cname: alice,
    transited: { type: 1, contents: utf('EXAMPLE.COM,') },
    authtime: t0, starttime: t0, endtime: t1, renewTill: t2,
    caddr: [{ type: 2, address: unhex('0a000001') }],
    authorizationData: [{ type: 1, data: unhex('3003020101') }] };
  add('EncTicketPart', m.encEncTicketPart(etp));
  add('EncTicketPart', m.encEncTicketPart({ flags: [], key: { etype: 23,
    key: keyFor(23, 0) }, crealm: 'R', cname: alice, authtime: t0,
    endtime: t1, caddr: [], authorizationData: [] }));
  const body = { kdcOptions: [1, 3, 8, 15, 27], cname: alice,
    realm: 'EXAMPLE.COM', sname: krbtgt, from: t0, till: t1, rtime: t2,
    nonce: 0x7fffffff, etypes: [18, 17, 20, 19, 23],
    addresses: [{ type: 20, address: utf('WORKSTATION     ') }] };
  add('KdcReqBody', m.encKdcReqBody(body));
  add('KdcReqBody', m.encKdcReqBody({ realm: 'EXAMPLE.COM', till: t1,
    nonce: 0, etypes: [], encAuthorizationData: enc1,
    additionalTickets: [ticket, ticket2] }));
  const tsEnc = m.encPaEncTsEnc(t0, 123456);
  const asReq = { msgType: 10, padata: [
    { type: 2, value: m.encEncryptedData({ etype: 18, cipher: tsEnc }) },
    { type: 128, value: m.encPaPacRequest(true) },
    { type: 167, value: m.encPaPacOptions([0, 3]) }], reqBody: body };
  add('KdcReq', m.encKdcReq(asReq));
  add('KdcReq', m.encKdcReq({ msgType: 10, reqBody: body }));
  const apReq = { apOptions: [], ticket: ticket, authenticator: enc1 };
  const tgsReq = { msgType: 12, padata: [
    { type: 1, value: m.encApReq(apReq) },
    { type: 129, value: m.encPaForUser({ userName: alice,
      userRealm: 'EXAMPLE.COM', cksum: { type: -138,
      checksum: new Uint8Array(16) } }) }],
    reqBody: Object.assign({}, body, { cname: null, sname: http,
      additionalTickets: [ticket] }) };
  add('KdcReq', m.encKdcReq(tgsReq));
  const asRep = { msgType: 11, padata: [{ type: 19,
    value: m.encEtypeInfo2([{ etype: 18, salt: 'EXAMPLE.COMalice' }]) }],
    crealm: 'EXAMPLE.COM', cname: alice, ticket: ticket, encPart: enc1 };
  add('KdcRep', m.encKdcRep(asRep));
  add('KdcRep', m.encKdcRep(Object.assign({}, asRep, { msgType: 13,
    padata: [], ticket: ticket2 })));
  const ekrp = { key: { etype: 18, key: keyFor(18, 0) },
    lastReq: [{ type: 0, value: t0 }, { type: -6, value: t1 }],
    nonce: -5, keyExpiration: t2, flags: [1, 9, 10], authtime: t0,
    starttime: t0, endtime: t1, renewTill: t2, srealm: 'EXAMPLE.COM',
    sname: krbtgt, caddr: [{ type: 2, address: unhex('7f000001') }],
    encryptedPaData: [{ type: 149, value: unhex('00') }] };
  add('EncKdcRepPart', m.encEncKdcRepPart(ekrp, 25));
  add('EncKdcRepPart', m.encEncKdcRepPart(Object.assign({}, ekrp,
    { lastReq: [], keyExpiration: null, encryptedPaData: [],
      caddr: null }), 26));
  const auth = { crealm: 'EXAMPLE.COM', cname: alice,
    cksum: { type: 0x8003, checksum: gss.buildGssChecksum({
      flags: [2, 32] }) }, cusec: 999999, ctime: t0,
    subkey: { etype: 18, key: keyFor(18, 0) }, seqNumber: 0xffffffff,
    authorizationData: [{ type: 141, data: unhex('00') }] };
  add('Authenticator', m.encAuthenticator(auth));
  add('Authenticator', m.encAuthenticator({ crealm: 'X', cname: alice,
    ctime: t0 }));
  add('ApReq', m.encApReq({ apOptions: [2], ticket: ticket,
                            authenticator: enc1 }));
  add('ApRep', m.encApRep({ encPart: enc1 }));
  add('EncApRepPart', m.encEncApRepPart({ ctime: t0, cusec: 5,
    subkey: { etype: 17, key: keyFor(17, 0) }, seqNumber: 12345 }));
  add('EncApRepPart', m.encEncApRepPart({ ctime: t0 }));
  const err0 = { stime: t0, susec: 0, errorCode: 25, realm: 'EXAMPLE.COM',
    sname: krbtgt };
  add('KrbError', m.encKrbError(err0));
  add('KrbError', m.encKrbError(Object.assign({}, err0, { ctime: t1,
    cusec: 7, crealm: 'EXAMPLE.COM', cname: alice, eText: 'need preauth',
    eData: asn1.encSequence([m.encPaData({ type: 19,
      value: m.encEtypeInfo2([{ etype: 18, salt: 'EXAMPLE.COMalice',
      s2kparams: unhex('00001000') }, { etype: 23, salt: '' }]) }),
      m.encPaData({ type: 2, value: new Uint8Array(0) })]) })));
  for (const code of [0, 6, 14, 24, 37, 52, 60, 68, 93, 4242]) {
    add('KrbError', m.encKrbError(Object.assign({}, err0,
      { errorCode: code, crealm: '', eText: '' })));
  }
  add('KrbError', m.encKrbError(Object.assign({}, err0,
    { eData: unhex('0102') })), 'e-data that is not PA-DATA');
  add('KrbError', m.encKrbError(Object.assign({}, err0,
    { eData: new Uint8Array(0) })), 'an empty e-data');
  add('KrbError', m.encKrbError(Object.assign({}, err0,
    { eData: seq(seq(ctx(2, oct(unhex('00'))))) })),
      'PA-DATA without a type');
  add('PaEncTsEnc', tsEnc);
  add('PaEncTsEnc', m.encPaEncTsEnc(t1));
  add('EtypeInfo2', m.encEtypeInfo2([{ etype: 18, salt: 'S',
    s2kparams: unhex('00001000') }, { etype: 23 }, { etype: 25, salt: '' }]));
  add('EtypeInfo', seq(seq(ctx(0, int(17)), ctx(1, oct(unhex('41e9')))),
                       seq(ctx(0, int(3)))));
  add('PaPacRequest', m.encPaPacRequest(true));
  add('PaPacRequest', m.encPaPacRequest(false));
  add('PaPacRequest', seq(), 'no field');
  add('PaPacRequest', seq(ctx(0, tlv(1, new Uint8Array(0)))), 'empty BOOLEAN');
  add('PaForUser', m.encPaForUser({ userName: pn(10, ['bob@example.com']),
    userRealm: 'EXAMPLE.COM', cksum: { type: -138, checksum: unhex('11') },
    authPackage: 'Kerberos' }));
  add('PaPacOptions', m.encPaPacOptions([0, 1, 2, 3]));
  const credPart = { ticketInfo: [
    { key: { etype: 18, key: keyFor(18, 0) }, prealm: 'EXAMPLE.COM',
      pname: alice, flags: [1, 2], authtime: t0, starttime: t0, endtime: t1,
      renewTill: t2, srealm: 'EXAMPLE.COM', sname: krbtgt,
      caddr: [{ type: 2, address: unhex('01020304') }] },
    { key: { etype: 23, key: keyFor(23, 1) }, prealm: '', flags: [] }],
    nonce: 42, timestamp: t0, usec: 1,
    sAddress: { type: 2, address: unhex('01020304') },
    rAddress: { type: 2, address: unhex('05060708') } };
  add('EncKrbCredPart', m.encEncKrbCredPart(credPart));
  add('EncKrbCredPart', m.encEncKrbCredPart({ ticketInfo: [] }));
  add('KrbCred', m.encKrbCred({ tickets: [ticket, ticket2], encPart: enc1 }));
  add('KdcResponse', m.encKdcRep(asRep));
  add('KdcResponse', m.encKrbError(err0));

  // Hand-made inputs Node reads leniently, and the refusals, with Node's
  // sentence.
  const ticketWith = function (realmTlv, extra) {
    return app(1, seq(ctx(0, int(5)), ctx(1, realmTlv),
      ctx(2, m.encPrincipalName(krbtgt)), ctx(3, m.encEncryptedData(enc1)),
      extra || new Uint8Array(0)));
  };
  add('Ticket', ticketWith(tlv(0x16, utf('IA5.REALM'))), 'IA5String realm');
  add('Ticket', ticketWith(tlv(0x1b, unhex('e9746f'))), 'Latin-1 realm');
  add('Ticket', ticketWith(gstr('R'), ctx(9, int(1))), 'an unknown field');
  add('Ticket', ticketWith(gstr('R'), ctx(1, gstr('LATER'))),
      'a duplicate field: the later wins');
  add('Ticket', app(1, seq(ctx(3, m.encEncryptedData(enc1)),
    ctx(2, m.encPrincipalName(krbtgt)), ctx(1, gstr('R')), ctx(0, int(5)))),
      'fields out of order');
  add('Ticket', cat(unhex('61'), unhex('8200'), new Uint8Array(0)),
      'a truncated long-form length');
  add('Ticket', ticketWith(tlv(0x0c, utf('UTF8'))), 'a UTF8String realm');
  add('Ticket', app(2, seq()), 'the wrong application');
  add('Ticket', seq(), 'not an application');
  add('Ticket', unhex('6180'), 'an indefinite length');
  add('Ticket', unhex('6185ffffffffff'), 'a five-byte length');
  add('Ticket', unhex('61'), 'one byte');
  add('Ticket', unhex('610530033001'), 'a length past the end');
  add('Ticket', app(1, cat(seq(), seq())), 'two elements');
  add('Ticket', app(1, int(1)), 'not a SEQUENCE inside');
  add('Ticket', app(1, seq(int(5))), 'a field that is not context-tagged');
  add('Ticket', app(1, seq(ctx(0, cat(int(5), int(5))))), 'two in one tag');
  add('Ticket', app(1, seq(ctx(0, int(5)))), 'no realm');
  add('Ticket', app(1, seq(ctx(0, int(5)), ctx(1, gstr('R')))), 'no sname');
  add('Ticket', app(1, seq(ctx(0, tlv(2, unhex('01020304050607'))))),
      'a seven-byte INTEGER');
  add('Ticket', app(1, seq(ctx(0, tlv(2, new Uint8Array(0))))),
      'a zero-length INTEGER');
  add('Ticket', app(1, seq(ctx(0, tlv(2, unhex('800000000000'))))),
      'a six-byte negative INTEGER');
  add('Ticket', app(1, seq(ctx(0, int(5)), ctx(1, oct(utf('R'))))),
      'an OCTET STRING realm');
  add('EncApRepPart', app(27, seq(ctx(0, tlv(0x18, utf('20261332256161Z'))),
    ctx(1, int(0)))), 'a KerberosTime that rolls over');
  add('EncApRepPart', app(27, seq(ctx(0, tlv(0x18, utf('00500101000000Z'))),
    ctx(1, int(0)))), 'a two-digit year');
  add('EncApRepPart', app(27, seq(ctx(0, tlv(0x18, utf('2026010100000Z'))),
    ctx(1, int(0)))), 'a short KerberosTime');
  add('EncApRepPart', app(27, seq(ctx(0, tlv(0x18,
    utf('20260101000000.5Z'))), ctx(1, int(0)))), 'fractional seconds');
  add('EncApRepPart', app(27, seq(ctx(0, tlv(0x18, unhex('22'))),
    ctx(1, int(0)))), 'a quote in a KerberosTime');
  add('EncApRepPart', app(27, seq(ctx(1, int(0)))), 'no ctime');
  add('KdcReq', app(10, seq(ctx(1, int(4)), ctx(2, int(10)),
    ctx(4, m.encKdcReqBody(body)))), 'pvno 4');
  add('KdcReq', app(11, seq()), 'an AS-REP');
  add('KdcReq', app(10, seq(ctx(1, int(5)), ctx(2, int(10)))), 'no body');
  add('KdcReq', app(10, seq(ctx(1, int(5)), ctx(2, int(10)),
    ctx(4, seq(ctx(0, tlv(3, new Uint8Array(0))))))), 'an empty BIT STRING');
  add('KdcReq', app(10, seq(ctx(1, int(5)), ctx(2, int(10)),
    ctx(4, seq(ctx(0, tlv(3, unhex('000102')))))) ), 'a short body');
  add('KdcRep', app(10, seq()), 'an AS-REQ');
  add('KdcRep', app(11, seq(ctx(0, int(5)), ctx(1, int(11)),
    ctx(3, gstr('R')), ctx(4, m.encPrincipalName(alice)))), 'no ticket');
  add('EncKdcRepPart', app(27, seq()), 'an EncAPRepPart');
  add('KrbCred', app(22, seq(ctx(0, int(5)), ctx(1, int(21)))),
      'the wrong msg-type');
  add('KrbCred', app(22, seq(ctx(0, int(5)), ctx(1, int(22)),
    ctx(2, seq()), ctx(3, m.encEncryptedData(enc1)))), 'no tickets');
  add('EncKrbCredPart', app(29, seq(ctx(0, seq(seq(ctx(1, gstr('R'))))))),
      'a KrbCredInfo with no key');
  add('KdcResponse', unhex('3000'), 'not a message');
  add('KdcResponse', m.encApRep({ encPart: enc1 }), 'an AP-REP');
  add('KrbError', app(30, seq(ctx(0, int(5)))), 'no error-code');
  add('Authenticator', app(2, seq(ctx(0, int(5)), ctx(1, gstr('R')),
    ctx(2, m.encPrincipalName(alice)), ctx(4, int(0)),
    ctx(5, tlv(0x17, utf('261114100000Z'))))), 'a UTCTime ctime');
  let deep = int(1);
  for (let i = 0; i < 40; i++) {
    deep = seq(deep);
  }
  add('PrincipalName', deep, 'forty SEQUENCEs deep');

  // ---- FAST ---------------------------------------------------------
  const fastReq = { fastOptions: [1], padata: [{ type: 133,
    value: utf('cookie') }], reqBody: body };
  const fastReqBytes = fc.encFastReq(fastReq);
  add('fast.FastReq', fastReqBytes);
  add('fast.FastReq', fc.encFastReq({ reqBody: body }));
  add('fast.Armor', fc.encArmor({ type: 1, value: m.encApReq(apReq) }));
  add('fast.FastRequest', fc.encFastRequest({
    armor: { type: 1, value: m.encApReq(apReq) },
    reqChecksum: { type: 16, checksum: new Uint8Array(12) },
    encFastReq: enc1 }));
  add('fast.FastRequest', fc.encFastRequest({
    reqChecksum: { type: 16, checksum: new Uint8Array(12) },
    encFastReq: enc1 }));
  add('fast.FastReply', fc.encFastReply(enc1));
  const fin = { timestamp: t0, usec: 77, crealm: 'EXAMPLE.COM',
    cname: alice, ticketChecksum: { type: 16, checksum: unhex('ab') } };
  add('fast.FastFinished', fc.encFastFinished(fin));
  add('fast.FastResponse', fc.encFastResponse({ padata: [{ type: 133,
    value: utf('c2') }], strengthenKey: { etype: 18, key: keyFor(18, 1) },
    finished: fin, nonce: 31337 }));
  add('fast.FastResponse', fc.encFastResponse({ nonce: 0 }));
  const tokenInfos = [
    { flags: [1, 3], vendor: 'Iya', challenge: unhex('0102'), length: 6,
      format: 0, tokenId: utf('tok-1'), algId: 'hotp' },
    { flags: [] },
    { flags: [5], length: 0, format: 4 }];
  tokenInfos.forEach(function (ti) {
    add('fast.TokenInfo', fc.encTokenInfo(ti));
  });
  add('fast.OtpChallenge', fc.encOtpChallenge({ nonce: unhex('aabbcc'),
    service: 'EXAMPLE OTP', tokenInfo: tokenInfos, salt: 'EXAMPLE.COMalice',
    s2kparams: unhex('00001000') }));
  add('fast.OtpChallenge', fc.encOtpChallenge({ nonce: unhex('00'),
    tokenInfo: [] }));
  add('fast.OtpRequest', fc.encOtpRequest({ flags: [1], nonce: unhex('aa'),
    encData: enc1, value: '123456', pin: '0000', time: t0,
    vendor: 'Iya' }));
  add('fast.OtpRequest', fc.encOtpRequest({ encData: enc1, pin: '' }));
  add('fast.OtpRequest', seq(tlv(0x80, unhex('0000000000')),
    tlv(0xa2, m.encEncryptedData(enc1).subarray(2)),
    tlv(0x83, unhex('00')), tlv(0x84, unhex('05')),
    tlv(0x85, unhex('e9'))), 'a hashed OTP, a Latin-1 value');
  add('fast.OtpRequest', seq(tlv(0x80, unhex('0000000000')),
    tlv(0x84, unhex('00')), tlv(0xa2,
    m.encEncryptedData(enc1).subarray(2))), 'an iteration count of 0');
  add('fast.OtpRequest', seq(tlv(0x80, unhex('0000000000'))),
      'no encData');
  add('fast.OtpRequest', seq(int(1)), 'a universal field');
  add('fast.OtpEncData', m.encPaEncTsEnc(t0));
  add('fast.OtpEncData', fc.encOtpEncRequest(unhex('0102')));
  add('fast.OtpEncData', seq(int(1)), 'neither');
  add('fast.OtpEncData', int(1), 'not a SEQUENCE');
  const vmac = { identifier: krbtgt, kvno: 3, enctype: 18,
    mac: { type: 16, checksum: unhex('00') } };
  add('fast.VerifierMac', fc.encVerifierMac(vmac));
  add('fast.VerifierMac', fc.encVerifierMac({ mac: vmac.mac }));
  const elements = m.encAuthorizationData([{ type: 97,
    data: fc.encIndicators(['otp', 'pkinit']) }]);
  add('fast.Cammac', fc.encCammac({ elementsBytes: elements,
    kdcVerifier: vmac, svcVerifier: vmac }));
  add('fast.Cammac', fc.encCammac({ elementsBytes: elements }));
  add('fast.Indicators', fc.encIndicators(['otp', 'hardened', 'é']));
  add('fast.Indicators', fc.encIndicators([]));
  add('fast.Indicators', seq(tlv(0x0c, unhex('ff61'))), 'malformed UTF-8');
  add('fast.Indicators', seq(gstr('otp')), 'a GeneralString');
  add('fast.FastRequest', ctx(1, seq()), 'the wrong tag');
  add('fast.FastRequest', ctx(0, cat(seq(), seq())), 'two elements');
  add('fast.FastRequest', ctx(0, int(1)), 'not a SEQUENCE');
  add('fast.FastRequest', ctx(0, seq()), 'no checksum');
  add('fast.FastResponse', seq(ctx(0, seq())), 'no nonce');
  add('fast.Cammac', seq(), 'no elements');
  add('fast.TokenInfo', seq(), 'no flags');

  // ---- PKINIT -------------------------------------------------------
  add('pkinit.Krb5PrincipalName', pc.encKrb5PrincipalName('EXAMPLE.COM',
    alice));
  add('pkinit.PaPkAsReq', pc.encPaPkAsReq({ signedAuthPack: unhex('3003'),
    kdcPkId: unhex('0405') }));
  add('pkinit.PaPkAsReq', pc.encPaPkAsReq({ signedAuthPack: unhex('30') }));
  add('pkinit.PaPkAsReq', seq(tlv(0x80, unhex('01')), tlv(0xa1, seq()),
    tlv(0x82, unhex('02'))), 'with trustedCertifiers');
  add('pkinit.PaPkAsReq', seq(tlv(0xa0, unhex('0400'))),
      'a constructed signedAuthPack');
  add('pkinit.PaPkAsReq', seq(), 'no signedAuthPack');
  const KDFS = ['1.3.6.1.5.2.3.6.1', '1.3.6.1.5.2.3.6.2',
                '1.3.6.1.5.2.3.6.3', '2.999.1', '1.2.840.113549.1.1.11'];
  add('pkinit.AuthPack', pc.encAuthPack({ cusec: 1, ctime: t0, nonce: 99,
    paChecksum: new Uint8Array(20), freshnessToken: unhex('0f'),
    clientPublicValue: seq(seq(tlv(6, unhex('2a8648ce3d0201'))),
      tlv(3, unhex('0004'))), clientDhNonce: unhex('aa55'),
    supportedKdfs: KDFS }));
  add('pkinit.AuthPack', pc.encAuthPack({ cusec: 0, ctime: t0, nonce: 0 }));
  add('pkinit.AuthPack', seq(ctx(0, seq(ctx(0, int(0)), ctx(1, ktime(t0)),
    ctx(2, int(1)))), ctx(2, seq(seq(), seq(), seq()))),
      'three supportedCMSTypes');
  KDFS.forEach(function (oid) {
    add('pkinit.KdfAlgorithmId', pc.encKdfAlgorithmId(oid));
  });
  add('pkinit.KdcDhKeyInfo', pc.encKdcDhKeyInfo({
    subjectPublicKey: unhex('0201ff'), nonce: 7 }));
  add('pkinit.KdcDhKeyInfo', seq(ctx(0, tlv(3, unhex('0700'))),
    ctx(1, int(1))), 'unused bits');
  add('pkinit.PaPkAsRep', pc.encPaPkAsRep({ dhSignedData: unhex('3000'),
    kdf: KDFS[1] }));
  add('pkinit.PaPkAsRep', pc.encPaPkAsRep({ dhSignedData: unhex('3000') }));
  add('pkinit.PaPkAsRep', ctx(0, cat(tlv(0x80, unhex('3000')),
    ctx(2, pc.encKdfAlgorithmId(KDFS[0])))), 'the implicit form');
  add('pkinit.PaPkAsRep', ctx(1, oct(unhex('00'))), 'encKeyPack');
  add('pkinit.PaPkAsRep', ctx(0, seq()), 'no dhSignedData');
  add('pkinit.TypedData', pc.encTypedData([{ type: 104,
    value: unhex('3000') }, { type: 109 }]));
  const otherInfo = pc.encOtherInfo({ kdf: KDFS[0], client: utf('client'),
    server: utf('server'), etype: 18, asReq: m.encKdcReq(asReq),
    pkAsRep: pc.encPaPkAsRep({ dhSignedData: unhex('3000') }) });
  const epis = [{ subjectName: unhex('3000'),
    issuerAndSerialNumber: unhex('3003020101'),
    subjectKeyIdentifier: unhex('0102') }, {}];
  const pkinit = {
    otherInfo: { kdf: KDFS[0], client: hex(utf('client')),
      server: hex(utf('server')), etype: 18, asReq: hex(m.encKdcReq(asReq)),
      pkAsRep: hex(pc.encPaPkAsRep({ dhSignedData: unhex('3000') })),
      bytes: hex(otherInfo) },
    epis: epis.map(function (e) {
      return { subjectName: e.subjectName ? hex(e.subjectName) : null,
        issuerAndSerialNumber: e.issuerAndSerialNumber
          ? hex(e.issuerAndSerialNumber) : null,
        subjectKeyIdentifier: e.subjectKeyIdentifier
          ? hex(e.subjectKeyIdentifier) : null,
        bytes: hex(pc.encExternalPrincipalIdentifier(e)) };
    }),
    initialVerifiedCas: norm(pc.initialVerifiedCas(epis)),
    oids: ['1.2', '2.999', '2.999.3', '1.2.840.113549',
           '1.3.6.1.4.1.311.20.2.3', '0.0', '2.40.18446744073709551616']
      .map(function (oid) {
        const enc = hex(pc.encOid(oid));
        return { oid: oid, bytes: enc,
                 back: pc.decOid(asn1.readTlv(unhex(enc), 0)) };
      })
  };

  // ---- tree, identify, principals, flags, errors ----------------------
  const tree = [m.encKdcReq(asReq), m.encKrbError(err0), deep,
    seq(tlv(0x1b, unhex('e9')), tlv(2, unhex('01020304050607')),
        tlv(3, unhex('0080000001')), tlv(0x04, new Uint8Array(80)),
        tlv(0x05, new Uint8Array(0)), tlv(0x30, new Uint8Array(0)),
        tlv(0x31, int(1)), tlv(0xc1, unhex('00')), tlv(0xe2, int(1)),
        tlv(0x9f, unhex('01')), tlv(0x13, utf('P')), tlv(0x41, unhex('00')),
        tlv(0x30, unhex('0201'))),
    unhex('3003020101ff')]
    .map(function (b) {
      const r = attempt(function () { return asn1.tree(b); });
      return { bytes: hex(b), tree: r.ok ? norm(r.ok) : null,
               error: r.error || null };
    });
  const identify = [m.encKdcReq(asReq), m.encTicket(ticket), unhex('7f00'),
    unhex('6c'), unhex('3000'), new Uint8Array(0), app(30, seq())]
    .map(function (b) { return { bytes: hex(b), id: m.identify(b) }; });
  const principals = [];
  [['alice', undefined], ['alice@EXAMPLE.COM', undefined],
   ['krbtgt/EXAMPLE.COM@EXAMPLE.COM', undefined],
   ['HTTP/web.example.com', undefined], ['  a//b/ @R  ', undefined],
   ['@R', undefined], ['user@host@REALM', undefined], ['', undefined],
   ['//', undefined], ['bob@example.com@EXAMPLE.COM', 10],
   ['krbtgt', undefined]].forEach(function (c) {
    const r = attempt(function () { return m.parsePrincipal(c[0], c[1]); });
    principals.push({ text: c[0], defaultType: c[1] === undefined
      ? null : c[1], parsed: r.ok ? norm(r.ok) : null,
      error: r.error || null,
      text2: r.ok ? m.principalToString(r.ok, r.ok.realm) : null });
  });
  const allBits = [];
  for (let i = 0; i < 33; i++) {
    allBits.push(i);
  }
  const flags = { kdc: m.kdcOptionNames(allBits),
    ticket: m.ticketFlagNames(allBits), ap: m.apOptionNames(allBits),
    fromBits: hex(asn1.flagsFromBits([0, 7, 8, 31])),
    bits: asn1.bitsFromFlags(unhex('8001ff00')) };
  const errorsTable = [];
  for (let c = -1; c <= 100; c++) {
    errorsTable.push(m.describeError(c));
  }
  const ints = [0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, -32768,
    65535, 0x7fffffff, -0x80000000, 0xffffffff, 2 ** 40, -(2 ** 40),
    2 ** 47 - 1, -(2 ** 47)].map(function (v) {
    return { value: v, der: hex(asn1.encInteger(v)) };
  });
  const times = ['2026-11-14T10:00:00Z', '1970-01-01T00:00:00Z',
    '2038-01-19T03:14:08Z', '1999-12-31T23:59:59Z', '9999-12-31T23:59:59Z',
    '1000-01-01T00:00:00Z', '2000-02-29T12:00:00Z']
    .map(function (s) {
      return { iso: s, secs: Date.parse(s) / 1000,
               der: hex(asn1.encKerberosTime(T(s))) };
    });

  // ---- GSS ----------------------------------------------------------
  const cred = m.encKrbCred({ tickets: [ticket], encPart: enc1 });
  const gssChecksums = [
    { flags: [] }, { flags: [2, 32, 8] },
    { flags: [1, 2], delegation: cred },
    { flags: [2], channelBindings: new Uint8Array(16).fill(0xcb) },
    { flags: [2], extensions: unhex('deadbeef') },
    { flags: [2], channelBindings: new Uint8Array(15) },
    { flags: [2], delegation: cred }].map(function (o) {
    const r = attempt(function () { return gss.buildGssChecksum(o); });
    return { flags: o.flags,
      channelBindings: o.channelBindings ? hex(o.channelBindings) : null,
      delegation: o.delegation ? hex(o.delegation) : null,
      extensions: o.extensions ? hex(o.extensions) : null,
      bytes: r.ok ? hex(r.ok) : null, error: r.error || null };
  });
  const parsedChecksums = gssChecksums.filter(function (c) {
    return c.bytes;
  }).map(function (c) { return unhex(c.bytes); }).concat([
    new Uint8Array(23), cat(unhex('00000010'), new Uint8Array(20)),
    cat(unhex('11000000'), new Uint8Array(20)),
    cat(unhex('10000000'), new Uint8Array(16), unhex('01000000'),
        unhex('0100')),
    cat(unhex('10000000'), new Uint8Array(16), unhex('01000000'),
        unhex('01000900'), unhex('aa'))]).map(function (b) {
    const r = attempt(function () { return gss.parseGssChecksum(b); });
    return { bytes: hex(b), parsed: r.ok ? norm(r.ok) : null,
             error: r.error || null };
  });
  const apReqBytes = m.encApReq(apReq);
  const ict = [gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReqBytes),
    gss.encodeInitialContextToken(gss.TOK_ID.AP_REP, unhex('00')),
    gss.encodeInitialContextToken([9, 9], new Uint8Array(0)),
    gss.encodeInitialContextToken(gss.TOK_ID.KRB_ERROR,
                                  new Uint8Array(300)),
    apReqBytes, new Uint8Array(0), unhex('6003060100'),
    cat(unhex('600a'), sp.SPNEGO_OID_DER, unhex('a000')),
    cat(unhex('600d'), unhex('060b2b06010401823702020a'),
        unhex('00')),
    cat(unhex('600b'), gss.KRB5_MECH_OID_DER),
    cat(unhex('600c'), gss.KRB5_MECH_OID_DER, unhex('01'))]
    .map(function (b) {
      const r = attempt(function () {
        return gss.decodeInitialContextToken(b);
      });
      return { bytes: hex(b), decoded: r.ok ? norm(r.ok) : null,
               error: r.error || null };
    });
  const mics = [];
  const wraps = [];
  const message = utf('a GSS message, of no particular length');
  for (const id of IDS) {
    const key = keyFor(id, 0);
    for (const role of ['initiator', 'acceptor']) {
      for (const sub of [false, true]) {
        for (const seqNo of [0, 1, 0xffffffff, 2 ** 40 + 5]) {
          const token = await gss.getMic({ key: key, etype: id, role: role,
            acceptorSubkey: sub, message: message, sequenceNumber: seqNo });
          const tampered = new Uint8Array(token);
          tampered[token.length - 1] ^= 1;
          mics.push({ etype: id, key: hex(key), role: role,
            acceptorSubkey: sub, sequenceNumber: seqNo,
            message: hex(message), token: hex(token),
            verdict: norm(await gss.verifyMic({ key: key, etype: id,
              token: token, message: message })),
            tampered: hex(tampered),
            tamperedVerdict: norm(await gss.verifyMic({ key: key, etype: id,
              token: tampered, message: message })) });
        }
        for (const [ec, rrc] of [[0, 0], [0, 28], [16, 0], [3, 12],
                                 [0, 1000]]) {
          const token = await gss.wrap({ key: key, etype: id, role: role,
            acceptorSubkey: sub, message: message, sequenceNumber: 77,
            extraCount: ec, rrc: rrc });
          wraps.push({ etype: id, key: hex(key), role: role,
            acceptorSubkey: sub, sequenceNumber: 77, extraCount: ec,
            rrc: rrc, message: hex(message), token: hex(token),
            unwrapped: norm(await gss.unwrap({ key: key, etype: id,
              token: token })) });
        }
      }
    }
  }
  const unwrapErrors = [];
  const okWrap = unhex(wraps[0].token);
  const badHeader = new Uint8Array(okWrap);
  badHeader[2] ^= 0x04;
  const unsealed = new Uint8Array(okWrap);
  unsealed[2] &= ~0x02;
  for (const t of [okWrap.subarray(0, 10), unhex('0404' + '00'.repeat(20)),
                   unsealed, badHeader]) {
    const r = await attemptAsync(function () {
      return gss.unwrap({ key: keyFor(17, 0), etype: 17, token: t });
    });
    unwrapErrors.push({ etype: 17, key: hex(keyFor(17, 0)), token: hex(t),
                        error: r.error || null });
  }
  for (const t of [unhex('0404'), unhex('0504' + '00'.repeat(20))]) {
    const r = await attemptAsync(function () {
      return gss.verifyMic({ key: keyFor(17, 0), etype: 17, token: t,
                             message: message });
    });
    unwrapErrors.push({ etype: 17, key: hex(keyFor(17, 0)), token: hex(t),
                        mic: true, error: r.error || null });
  }
  const rotations = [];
  for (const n of [0, 1, 5, 9, 10, 23]) {
    rotations.push({ count: n, bytes: '00010203040506070809',
      right: hex(gss.rotateRight(unhex('00010203040506070809'), n)),
      left: hex(gss.rotateLeft(unhex('00010203040506070809'), n)) });
  }

  // ---- SPNEGO -------------------------------------------------------
  const inits = [
    { mechTypes: undefined },
    { mechTypes: [sp.MS_KRB5_MECH_OID, sp.KRB5_MECH_OID,
      '1.3.6.1.4.1.311.2.2.10'], mechToken: unhex('6000'),
      mechListMic: unhex('0404') },
    { mechTypes: ['1.3.6.1.4.1.311.2.2.30', '1.2.840.113554.1.2.2.3'] },
    { mechTypes: [] }, { mechTypes: [sp.SPNEGO_OID] },
    { mechTypes: ['1'] }, { mechTypes: ['3.1'] }, { mechTypes: ['1.40'] },
    { mechTypes: ['2.100.3'] }, { mechTypes: ['1..2'] },
    { mechTypes: ['1.x'] }].map(function (o) {
    const r = attempt(function () { return sp.encodeNegTokenInit(o); });
    return { mechTypes: o.mechTypes === undefined ? null : o.mechTypes,
      mechToken: o.mechToken ? hex(o.mechToken) : null,
      mechListMic: o.mechListMic ? hex(o.mechListMic) : null,
      token: r.ok ? hex(r.ok.token) : null,
      mechListDer: r.ok ? hex(r.ok.mechListDer) : null,
      error: r.error || null };
  });
  const resps = [{ negState: 0, supportedMech: sp.KRB5_MECH_OID,
    responseToken: unhex('6f00') }, { negState: 1 }, { negState: 2 },
    { negState: 3, mechListMic: unhex('00') }, { negState: 7 },
    { supportedMech: sp.MS_KRB5_MECH_OID }, {},
    { responseToken: new Uint8Array(0) }].map(function (o) {
    return { negState: o.negState === undefined ? null : o.negState,
      supportedMech: o.supportedMech || null,
      responseToken: o.responseToken ? hex(o.responseToken) : null,
      mechListMic: o.mechListMic ? hex(o.mechListMic) : null,
      token: hex(sp.encodeNegTokenResp(o)) };
  });
  const spOid = sp.SPNEGO_OID_DER;
  const wrapInit = function (inner) {
    const b = cat(spOid, ctx(0, inner));
    return cat(unhex('60'), asn1.encodeLength(b.length), b);
  };
  const negTokens = inits.filter(function (i) { return i.token; })
    .map(function (i) { return unhex(i.token); })
    .concat(resps.map(function (r) { return unhex(r.token); }))
    .concat([
      wrapInit(seq(ctx(0, seq(sp.encodeOid(sp.KRB5_MECH_OID))),
        ctx(1, tlv(3, unhex('0002'))), ctx(3, seq(ctx(0, gstr('hint')),
        ctx(1, oct(unhex('0a'))))))),
      wrapInit(seq(ctx(0, seq(sp.encodeOid(sp.SPNEGO_OID))),
        ctx(4, oct(unhex('01'))), ctx(7, int(1)))),
      wrapInit(seq()), wrapInit(int(1)),
      cat(unhex('600c'), spOid, ctx(1, seq())),
      cat(unhex('6009'), spOid, unhex('02')),
      ctx(1, seq(ctx(0, int(2)), ctx(9, int(1)))),
      ctx(1, seq(ctx(0, tlv(4, unhex('01'))))),
      ctx(1, int(0)), new Uint8Array(0), unhex('6e00'), unhex('3000'),
      gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReqBytes),
      cat(unhex('600d'), unhex('060b2b06010401823702020a'), unhex('00')),
      cat(unhex('6004'), unhex('06028f00')),
      cat(unhex('6003'), unhex('0a0100'))]);
  const decodedTokens = negTokens.map(function (b) {
    const r = attempt(function () { return sp.decodeNegotiationToken(b); });
    return { bytes: hex(b), decoded: r.ok ? norm(r.ok) : null,
             error: r.error || null };
  });
  const oids = ['1.2.840.113554.1.2.2', '1.3.6.1.5.5.2', '2.5', '0.39',
    '1.2.840.48018.1.2.2', '1.3.6.1.4.1.311.2.2.10', '2.100.3',
    '1.2.4294967296', '2.999.3'].map(function (oid) {
    const r = attempt(function () { return sp.encodeOidContent(oid); });
    return { oid: oid, content: r.ok ? hex(r.ok) : null,
      back: r.ok ? sp.decodeOidContent(r.ok) : null,
      error: r.error || null };
  });
  ['', '80', '2a86', '7f', 'ff7f'].forEach(function (h) {
    const r = attempt(function () { return sp.decodeOidContent(unhex(h)); });
    oids.push({ oid: null, content: h, back: r.ok || null,
                error: r.error || null });
  });
  const micLists = [];
  for (const id of IDS) {
    const der = unhex(inits[1].mechListDer);
    const mic = await sp.computeMechListMic({ key: keyFor(id, 1), etype: id,
      role: 'acceptor', acceptorSubkey: true, mechListDer: der,
      sequenceNumber: 9 });
    micLists.push({ etype: id, key: hex(keyFor(id, 1)), role: 'acceptor',
      acceptorSubkey: true, sequenceNumber: 9, mechListDer: hex(der),
      mic: hex(mic), verdict: norm(await sp.verifyMechListMic({
        key: keyFor(id, 1), etype: id, mic: mic, mechListDer: der })) });
  }
  const requirements = [[[sp.KRB5_MECH_OID], sp.KRB5_MECH_OID],
    [[sp.MS_KRB5_MECH_OID, sp.KRB5_MECH_OID], sp.KRB5_MECH_OID],
    [[], sp.KRB5_MECH_OID], [[sp.KRB5_MECH_OID], null],
    [['9.9'], '9.9'], [['9.9', '1.3.6.1.4.1.311.2.2.10'],
                       '1.3.6.1.4.1.311.2.2.10']]
    .map(function (c) {
      return { mechTypes: c[0], selected: c[1],
               requirement: sp.micRequirement(c[0], c[1]) };
    });
  const negStates = [-1, 0, 1, 2, 3, 4].map(function (v) {
    return { value: v, info: sp.negStateInfo(v) };
  });

  // ---- MS-KKDCP -----------------------------------------------------
  // The /KdcProxy handler's own reading (krb5_kdc.js), line for line, and
  // the cell router's (krb5_home.ts's messageOf()).
  let home = null;
  try {
    home = require(path.join(K, 'krb5_home'));
  } catch (e) {
    console.error('krb5_home did not load: ' + ((e && e.message) || e));
  }
  const proxyRead = function (body) {
    if (!body || !body.length) {
      return { refusal: 'STS-KRB-0055',
               body: 'a KDC-PROXY-MESSAGE is required' };
    }
    let framed;
    try {
      const outer = asn1.readTlv(prim.toBytes(body), 0);
      const fields = asn1.readTaggedSequence(outer.value);
      framed = asn1.decOctetString(fields[0]);
    } catch (e) {
      return { refusal: 'STS-KRB-0056',
               body: 'the KDC-PROXY-MESSAGE does not decode: ' + e.message };
    }
    if (framed.length < 4) {
      return { refusal: 'STS-KRB-0057',
               body: 'the kerb-message is too short to be framed' };
    }
    const declared = (framed[0] << 24 | framed[1] << 16 | framed[2] << 8 |
                      framed[3]) >>> 0;
    return { message: hex(framed.subarray(4, 4 + declared)) };
  };
  const frame = function (reply) {
    const out = new Uint8Array(4 + reply.length);
    out[0] = (reply.length >>> 24) & 255;
    out[1] = (reply.length >>> 16) & 255;
    out[2] = (reply.length >>> 8) & 255;
    out[3] = reply.length & 255;
    out.set(reply, 4);
    return out;
  };
  const asReqBytes = m.encKdcReq(asReq);
  const kkdcp = [
    seq(ctx(0, oct(frame(asReqBytes)))),
    seq(ctx(0, oct(frame(asReqBytes))), ctx(1, gstr('EXAMPLE.COM')),
        ctx(2, int(0))),
    seq(ctx(0, oct(cat(unhex('00000003'), unhex('0102'))))),
    seq(ctx(0, oct(cat(unhex('00000001'), unhex('010203'))))),
    seq(ctx(0, oct(unhex('000000')))), seq(ctx(0, oct(new Uint8Array(0)))),
    seq(), seq(ctx(0, int(1))), unhex('30'), unhex('300a'),
    new Uint8Array(0), int(1)].map(function (b) {
    return { body: hex(b), read: proxyRead(b),
             messageOf: home ? (function () {
               const got = home.messageOf(Buffer.from(b));
               return got ? hex(got) : null;
             })() : 'unavailable' };
  });
  const replies = [asReqBytes, m.encKrbError(err0), new Uint8Array(0),
    new Uint8Array(300)].map(function (r) {
    return { reply: hex(r),
             envelope: hex(asn1.encSequence([asn1.encContext(0,
               asn1.encOctetString(frame(r)))])) };
  });

  // ---- the keytab file format (krb5_keytab.ts) ----------------------
  const kt = require(path.join(K, 'krb5_keytab'));
  const ktEntries = [
    { realm: 'EXAMPLE.COM', components: ['HTTP', 'web.example.com'],
      timestamp: 1800000000, kvno: 3, etype: 18, key: keyFor(18, 0) },
    { realm: 'EXAMPLE.COM', components: ['host', 'hé.example.com'],
      nameType: 3, timestamp: 4294967297, kvno: 300, etype: -138,
      key: keyFor(23, 0) },
    // Not 0: Node writes `timestamp || now`, so 0 is the time of writing.
    { realm: '', components: ['x'], timestamp: 1, kvno: 0, etype: 23,
      key: unhex('01') }];
  const keytab = { written: [], read: [] };
  [[ktEntries[0]], ktEntries, [], [{ realm: 'R', components: [],
    timestamp: 0, kvno: 1, etype: 17, key: unhex('01') }],
   [{ realm: 'R', components: ['a', ''], timestamp: 0, kvno: 1, etype: 17,
      key: unhex('01') }],
   [{ realm: 'R', components: ['a'], timestamp: 0, kvno: 1, etype: 17,
      key: new Uint8Array(0) }],
   [{ realm: 'R', components: ['a'.repeat(70000)], timestamp: 0, kvno: 1,
      etype: 17, key: unhex('01') }]].forEach(function (list) {
    const r = attempt(function () { return kt.writeKeytab(list); });
    keytab.written.push({ entries: list.map(function (e) {
      return { realm: e.realm, components: e.components,
               nameType: e.nameType === undefined ? null : e.nameType,
               timestamp: e.timestamp, kvno: e.kvno, etype: e.etype,
               key: hex(e.key) };
    }), bytes: r.ok ? hex(r.ok) : null, error: r.error || null });
  });
  const goodTab = kt.writeKeytab(ktEntries);
  const be32 = function (n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, n);
    return b;
  };
  const oneEntry = kt.writeKeytab([ktEntries[0]]).subarray(2);
  [goodTab, cat(unhex('0502'), be32(-5), new Uint8Array(5), oneEntry),
   cat(unhex('0502'), oneEntry.subarray(0, oneEntry.length - 4)),
   cat(unhex('0502'), be32(oneEntry.length - 8),
       oneEntry.subarray(4, oneEntry.length - 4)),
   unhex('0501'), unhex('05'), unhex('0502'), unhex('050200'),
   cat(unhex('0502'), be32(-9), new Uint8Array(2)),
   cat(unhex('0502'), be32(100), new Uint8Array(3)),
   cat(unhex('0502'), be32(0)), cat(unhex('0502'), be32(1), unhex('00')),
   cat(unhex('0502'), be32(6), unhex('0001'), unhex('0009'), unhex('00')),
   cat(unhex('0502'), be32(8), unhex('0000'), unhex('0001'), unhex('41'),
       unhex('000000')),
   cat(unhex('0502'), be32(17), unhex('0001'), unhex('0001'), unhex('ff'),
       unhex('0000'), new Uint8Array(11), unhex('0000')),
   cat(unhex('0502'), be32(16), unhex('0000'), unhex('0000'),
       new Uint8Array(11), unhex('0001'), unhex('aa')),
   cat(unhex('0502'), be32(4), unhex('0000'))].forEach(function (b) {
    const r = attempt(function () { return kt.readKeytab(b); });
    keytab.read.push({ bytes: hex(b), entries: r.ok ? norm(r.ok) : null,
                       error: r.error || null });
  });

  return {
    primitives: primitives, nfold: nfold, profiles: profiles,
    etypeNames: etypeNames, stringToKey: s2k, derived: derived,
    encryptions: encryptions, checksums: checksums,
    decryptErrors: decryptErrors, cts: cts, messages: messages,
    pkinit: pkinit, tree: tree, identify: identify, principals: principals,
    flags: flags, errors: errorsTable, integers: ints, times: times,
    gss: { checksums: gssChecksums, parsed: parsedChecksums, ict: ict,
           mics: mics, wraps: wraps, errors: unwrapErrors,
           rotations: rotations },
    spnego: { inits: inits, resps: resps, decoded: decodedTokens,
              oids: oids, mics: micLists, requirements: requirements,
              negStates: negStates,
              mechs: sp.MECHS },
    kkdcp: { bodies: kkdcp, replies: replies },
    keytab: keytab,
    usage: kc.KEY_USAGE, preference: kc.DEFAULT_ETYPE_PREFERENCE
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
                 { file: 'scheduler-tick-node.json',
                   build: schedulerTickVectors },
                 { file: 'cache-registry-node.json',
                   build: cacheRegistryVectors },
                 { file: 'realm-lifecycle-node.json',
                   build: realmLifecycleVectors },
                 { file: 'http-node.json', build: httpVectors },
                 { file: 'keystore-node.json', build: keystoreVectors },
                 // The XACML engine's: tests/tools/xacml-vectors.js.
                 { file: 'xacml-node.json',
                   build: function () {
                     return require('./xacml-vectors.js').build(ROOT);
                   } },
                 { file: 'krb5-codec-node.json', build: krb5Codec },
                 // The directory's wire layer: tests/tools/ldap-wire-vectors.js.
                 { file: 'ldap-wire-node.json',
                   build: function () {
                     return require('./ldap-wire-vectors.js').build(ROOT);
                   } },
                 { file: 'pkcs8-node.json', build: pkcs8Vectors },
                 // The audit log's and the mail channel's (#444, phase 4):
                 // tests/tools/auditmail-vectors.js.
                 { file: 'auditmail-node.json', build: auditMailVectors }];

// THE AUDIT LOG AND THE MAIL CHANNEL (#444, phase 4): `sts-audit`'s and
// `sts-mail`'s vectors, built by the two files `auditmail-vectors.js` names.
function auditMailVectors() {
  return require('./auditmail-vectors.js').build(ROOT, OUT);
}

// A PRIVATE KEY MADE PKCS#8 (#444, phase 3): the conversion `sts-core`'s
// secrets reader needs for OpenBao's PKCS#1 client key, as node does it —
// `createPrivateKey(pem).export({ type: 'pkcs8', format: 'pem' })` — for an
// RSA key in PKCS#1 and in PKCS#8, an EC key in SEC1 and an Ed25519 key in
// PKCS#8, each generated per run; and a key that is not one, refused.
function pkcs8Vectors() {
  const nodeCrypto = require('crypto');
  const cases = [];
  const add = function (name, input) {
    let pkcs8 = null;
    let refusal = null;
    try {
      pkcs8 = nodeCrypto.createPrivateKey(input)
        .export({ type: 'pkcs8', format: 'pem' });
    } catch (e) {
      refusal = (e && e.message) || String(e);
    }
    cases.push({ name: name, input: input, pkcs8: pkcs8, refusal: refusal });
  };
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  add('rsa pkcs1', rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }));
  add('rsa pkcs8', rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  add('ec sec1', ec.privateKey.export({ type: 'sec1', format: 'pem' }));
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  add('ed25519 pkcs8', ed.privateKey.export({ type: 'pkcs8',
                                               format: 'pem' }));
  add('not a key', '-----BEGIN PRIVATE KEY-----\nAAAA\n' +
                   '-----END PRIVATE KEY-----\n');
  return { cases: cases };
}

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
    '    // A hierarchy over it: the service Root, the realm\'s Intermediate',
    '    // and Issuing CAs, the signing key certified — and what the JWKS',
    '    // then publishes for it.',
    '    const pki = require(path.join(ROOT, "common", "pki.js"));',
    '    await pki.ensureRoot();',
    '    await pki.ensureScope(set.realm || "default");',
    '    await pki.certifyKeySet(set.realm || "default", set);',
    '    const held = pki.publishedCertificateFor(set.realm || "default",',
    '                                             "jose", "RS256", set.kid);',
    '    durable.published = held ? { scope: set.realm || "default",',
    '      certB64: set.certB64, chainPem: held.chainPem } : null;',
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
    // EVERY SET IN A PROCESS OF ITS OWN when no STS_ONLY names one (#444,
    // phase 2b). The builders share the service's modules, and a module
    // keeps its state: the realms realmsVectors() creates were still defined
    // when realmLifecycleVectors() began, so that set described a registry
    // nobody else would see, and only a run of the whole generator showed
    // it. A child per set starts each one from a fresh service, as each was
    // written and checked.
    if (!only) {
      const childProcess = require('child_process');
      for (const one of VECTORS) {
        const child = childProcess.spawnSync(process.execPath,
          [__filename].concat(process.argv.slice(2)),
          { env: Object.assign({}, process.env, { STS_ONLY: one.file }),
            stdio: 'inherit' });
        if (child.status !== 0) {
          console.error(one.file + ': the builder failed (' +
            (child.status === null ? child.signal : child.status) + ')');
          process.exitCode = 1;
        }
      }
      return;
    }
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
