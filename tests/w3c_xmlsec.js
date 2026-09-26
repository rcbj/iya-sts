'use strict';
//
// File: w3c_xmlsec.js
//
// ===========================================================================
// THE W3C XML SIGNATURE AND XML ENCRYPTION INTEROP CASES, AGAINST
// common/crypto.js (#193).
//
// `common/crypto.js` is the one place this service signs, verifies, encrypts
// and decrypts XML (root CLAUDE.md, rule 3r), and until this file nothing
// held it to anybody's reading but the parent project's xmlsec1 round trip —
// which is the same engine, `common/vendored/xmldsig.js`, at the other end.
// The working groups' own interop cases are documents somebody ELSE signed
// and encrypted, with their keys and expected results published beside them,
// and they are the only second opinion there is.
//
// WHAT RUNS (tests/tools/W3C-XMLSEC-PROVENANCE.md has every URL):
//
//   SIGNATURES   the XML Signature 1.1 interop cases (Oracle: ECDSA on three
//                curves in both KeyValue forms, SHA-2, SHA-224, HMAC output
//                truncation, DEREncodedKeyValue, KeyInfoReference,
//                X509Digest); the second-round XML Signature interop set
//                (merlin-xmldsig-twenty-three) and Phaos's; the Exclusive
//                C14N interop sets (merlin-exc-c14n-one, merlin-c14n-three,
//                merlin-iaikTests-two); the XML Signature Second Edition
//                test cases (C14N 1.1, default canonicalization, XPointer,
//                distinguished names); the signatures in the Decryption
//                Transform and XML Encryption interop sets.
//   ENCRYPTION   the XML Encryption 1.1 interop cases (Oracle, Microsoft,
//                IBM: RSA-OAEP with digest, MGF and PSource variants,
//                ECDH-ES and DH-ES with ConcatKDF and PBKDF2, AES-GCM, AES
//                key wrap, derived keys); merlin-xmlenc-five and Phaos's
//                xmlenc-3.
//   C14N         every published canonical form the sets above carry — the
//                `c14n-N.txt` intermediate outputs of the merlin sets (C14N
//                1.0 and Exclusive C14N 1.0, with and without comments and
//                InclusiveNamespaces) and the C14N 1.1 expected outputs.
//
// HOW EACH CASE IS JUDGED. The EXPECTATION is this file's own table, never
// crypto.js's answer read back: which algorithms the service verifies and
// which it refuses BY NAME (section 1a of crypto.js, argued there), the SHA-1
// policy by mode, and the cases the working groups published as ones that
// must FAIL. A case is then driven through crypto.js and its outcome compared:
//
//   pass       the outcome is the expected one — verified, decrypted to the
//              published plaintext, reproduced the published canonical form,
//              or refused under the code this table names;
//   fail       anything else;
//   exception  the case needs something this service deliberately does not
//              do (EXCEPTIONS below says what and why). It is STILL RUN, and
//              the one assertion made is that it was NOT reported verified
//              or decrypted — a feature that is absent must be refused, never
//              waved through.
//
// THE MODES. Every signature case runs three times: development with the
// defaults (SHA-1 refused, STS-KEYS-0062), development with
// `saml.allowSha1Signatures` on (the old SHA-1 cases really verified), and
// product with the setting on (still refused: `mode.valueInForce()` makes it
// development's alone). Every encryption case runs in development and in
// product, where rsa-1_5 is never unwrapped (STS-KEYS-0070).
//
// WHY IN PROCESS: the cases are documents, not requests. crypto.js answers
// them without a port, a realm or a clock, and the settings the modes need
// are changed mid-run — the arrangement tests/saml_signature_algorithms.js
// already argues.
//
// THE CORPUS IS NOT IN THIS REPOSITORY. It carries private keys (the
// decryption keys, and PKCS#12 files for the ECDH and RSA cases), so
// tests/tools/fetch-w3c-xmlsec.sh downloads it into the tests image at build
// time, every file pinned by sha256 in tests/tools/w3c-xmlsec.sha256, and
// STS_W3C_XMLSEC_DIR names where. Without that variable this file FAILS,
// naming it: a harness that skipped itself silently would report a green run
// having checked nothing.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const forge = require('node-forge');
const xmldom = require('@xmldom/xmldom');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'w3c_xmlsec', level: process.env.LOG_LEVEL || 'info' });

const ENV = 'STS_W3C_XMLSEC_DIR';
const LIST = path.join(__dirname, 'tools', 'w3c-xmlsec.sha256');

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
const C14N11 = 'http://www.w3.org/2006/12/xml-c14n11';
const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const TRANSFORM_XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';
const TRANSFORM_XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116';
const TRANSFORM_BASE64 = DS + 'base64';
const TRANSFORM_ENVELOPED = DS + 'enveloped-signature';

// ---------------------------------------------------------------------------
// THE EXCEPTIONS: every reason a case is not expected to verify or decrypt,
// each a deliberate property of this service or a documented limit of the
// vendored engine it may not edit (common/vendored/CLAUDE.md). A case is
// filed under the FIRST that applies, in this order.
// ---------------------------------------------------------------------------
const EXCEPTIONS = {
  c14n11: 'Canonical XML 1.1 is not implemented: the vendored engine offers ' +
    'C14N 1.0 and Exclusive C14N 1.0 only, and says why (the xml:base, ' +
    'xml:lang and xml:space inheritance of a document subset). A signature ' +
    'naming it is refused by name ("Unsupported CanonicalizationMethod" / ' +
    '"Unsupported Transform")',
  xpath: 'the XPath transform (and XPath-selected document subsets) needs ' +
    'the DOM\'s XPath engine, which @xmldom/xmldom does not have; the ' +
    'vendored engine refuses it by name. No protocol this service speaks ' +
    'uses it (SAML core 5.4.4 allows only enveloped-signature and exclusive ' +
    'c14n)',
  xslt: 'the XSLT transform is not implemented, deliberately: running a ' +
    'stylesheet a signer chose is code execution on the verifier',
  decryptTransform: 'the Decryption Transform for XML Signature is not ' +
    'implemented; nothing this service verifies uses one',
  xpointer: 'a Reference URI in the #xpointer(...) form is not resolved by ' +
    'the vendored engine (it resolves "" and "#id" only), although XMLDSig ' +
    'core 4.3.3.3 asks for #xpointer(/) and #xpointer(id(\'ID\')). SAML ' +
    'core 5.4.2 allows only "" and "#ID", so no signature this service ' +
    'checks uses it; the engine fix belongs in the parent project',
  external: 'a Reference to an EXTERNAL resource (a URL or a sibling file) ' +
    'is never dereferenced: this service fetches nothing a signed document ' +
    'names (root CLAUDE.md, "Dial a URL a CALLER supplied")',
  noKey: 'the verification key is identified only by something this ' +
    'harness cannot turn into a key — a RetrievalMethod to an external ' +
    'resource, or a key agreed or transported inside KeyInfo — which a ' +
    'relying party of this service replaces with the certificate it ' +
    'registered',
  symmetric: 'the content or key-encryption key is a SECRET known out of ' +
    'band (KeyName, a DerivedKey from a shared master key, a key wrapped ' +
    'under a named symmetric key): decryptElement() decrypts only with this ' +
    'service\'s own private key, by key transport or ECDH-ES agreement, and ' +
    'refuses the rest by name (STS-KEYS-0018 / 0019)',
  binaryPlaintext: 'the plaintext is binary octets, and decryptElement() ' +
    'decrypts an ELEMENT (a SAML EncryptedAssertion or EncryptedID): it ' +
    'refuses output that is not XML (STS-KEYS-0023). Reaching that refusal ' +
    'proves the key agreement, the unwrap and the GCM tag all succeeded',
  xmlAttributes: 'the vendored canonicalizer does not render the xml:* ' +
    'attributes an apex inherits under inclusive C14N 1.0 (section 2.4) — ' +
    'adding them reproduces the published form exactly. Its signer omits ' +
    'them too, so the fix is the parent project\'s, in both halves at once',
  dsaEncryption: 'the recipient key is a DSA/DH key; this service agrees ' +
    'keys by ECDH-ES only and refuses DH and DH-ES by name (STS-KEYS-0073)'
};

// ===========================================================================
// SMALL UTILITIES
// ===========================================================================

function parse(xml) {
  log.debug("Entering parse().");
  const doc = new xmldom.DOMParser({
    onError: function () {
      // A warning from the parser is not a failure of the case; the cases
      // that are malformed on purpose are judged by what crypto.js answers.
    } }).parseFromString(String(xml), 'text/xml');
  log.debug("Leaving parse().");
  return doc;
}

function byLocal(node, name) {
  log.debug("Entering byLocal(). " + name);
  const out = [];
  const all = node ? node.getElementsByTagNameNS('*', name) : [];
  for (let i = 0; i < all.length; i++) {
    out.push(all[i]);
  }
  log.debug("Leaving byLocal(). " + out.length);
  return out;
}

function childElements(node) {
  log.debug("Entering childElements().");
  const out = [];
  for (let c = node ? node.firstChild : null; c; c = c.nextSibling) {
    if (c.nodeType === 1) {
      out.push(c);
    }
  }
  log.debug("Leaving childElements().");
  return out;
}

function walk(dir) {
  log.debug("Entering walk(). " + dir);
  let out = [];
  if (!fs.existsSync(dir)) {
    log.debug("Leaving walk(). Absent.");
    return out;
  }
  fs.readdirSync(dir).sort().forEach(function (name) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) {
      out = out.concat(walk(full));
    } else {
      out.push(full);
    }
  });
  log.debug("Leaving walk(). " + out.length);
  return out;
}

function b64(text) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(String(text || '').replace(/\s+/g, ''), 'base64');
}

// A DER length and a TLV, for the one key this file has to build by hand: a
// DSA public key from a DSAKeyValue, which node cannot import as a JWK.
function derTlv(tag, body) {
  log.debug("Entering derTlv().");
  let len;
  if (body.length < 128) {
    len = Buffer.from([body.length]);
  } else {
    const bytes = [];
    for (let n = body.length; n > 0; n = Math.floor(n / 256)) {
      bytes.unshift(n % 256);
    }
    len = Buffer.from([0x80 | bytes.length].concat(bytes));
  }
  log.debug("Leaving derTlv().");
  return Buffer.concat([Buffer.from([tag]), len, body]);
}

function derInteger(bytes) {
  log.debug("Entering derInteger().");
  let b = Buffer.from(bytes);
  while (b.length > 1 && b[0] === 0 && b[1] < 0x80) {
    b = b.subarray(1);
  }
  if (b[0] >= 0x80) {
    b = Buffer.concat([Buffer.from([0]), b]);
  }
  log.debug("Leaving derInteger().");
  return derTlv(0x02, b);
}

function dsaPublicKey(kv) {
  log.debug("Entering dsaPublicKey().");
  const part = function (name) {
    log.debug("Entering part(). " + name);
    const el = byLocal(kv, name)[0];
    log.debug("Leaving part().");
    return el ? b64(el.textContent) : null;
  };
  const p = part('P');
  const q = part('Q');
  const g = part('G');
  const y = part('Y');
  if (!p || !q || !g || !y) {
    log.debug("Leaving dsaPublicKey(). Incomplete.");
    return null;
  }
  const oid = Buffer.from('06072a8648ce380401', 'hex');
  const algorithm = derTlv(0x30, Buffer.concat([oid, derTlv(0x30,
    Buffer.concat([derInteger(p), derInteger(q), derInteger(g)]))]));
  const bits = derTlv(0x03, Buffer.concat([Buffer.from([0]),
                                           derInteger(y)]));
  log.debug("Leaving dsaPublicKey().");
  return nodeCrypto.createPublicKey({
    key: derTlv(0x30, Buffer.concat([algorithm, bits])),
    format: 'der', type: 'spki' });
}

const EC_CURVES = {
  'urn:oid:1.2.840.10045.3.1.7': { crv: 'P-256', bytes: 32 },
  'urn:oid:1.3.132.0.34': { crv: 'P-384', bytes: 48 },
  'urn:oid:1.3.132.0.35': { crv: 'P-521', bytes: 66 }
};

function fixedBytes(big, length) {
  log.debug("Entering fixedBytes().");
  let hex = BigInt(big).toString(16);
  hex = hex.padStart(length * 2, '0');
  log.debug("Leaving fixedBytes().");
  return Buffer.from(hex, 'hex');
}

function ecPublicKey(curveUri, x, y) {
  log.debug("Entering ecPublicKey(). " + curveUri);
  const curve = EC_CURVES[curveUri];
  if (!curve) {
    log.debug("Leaving ecPublicKey(). Unknown curve.");
    return null;
  }
  log.debug("Leaving ecPublicKey().");
  return nodeCrypto.createPublicKey({ format: 'jwk', key: {
    kty: 'EC', crv: curve.crv, x: x.toString('base64url'),
    y: y.toString('base64url') } });
}

// ===========================================================================
// KEYS. The sets publish their verification keys in every form XML
// Signature has — a certificate, a KeyValue of each family, a DER key, a
// name, a digest, an issuer and serial — and a relying party of this service
// replaces all of them with the certificate it REGISTERED. So this resolves
// what a case carries to CANDIDATE public keys, and, where the case names a
// key only by reference, to every certificate the set publishes: the
// candidates are tried in turn, as crypto.js treats "another registered
// certificate may be the right one".
// ===========================================================================

function keysOfKeyInfo(keyInfo, doc, published) {
  log.debug("Entering keysOfKeyInfo().");
  const keys = [];
  const add = function (key) {
    log.debug("Entering add().");
    if (key) {
      keys.push(key);
    }
    log.debug("Leaving add().");
  };
  let byReference = false;
  childElements(keyInfo).forEach(function (el) {
    const name = el.localName;
    if (name === 'X509Data') {
      byLocal(el, 'X509Certificate').forEach(function (c) {
        add(new nodeCrypto.X509Certificate(b64(c.textContent)).publicKey);
      });
      if (!byLocal(el, 'X509Certificate').length) {
        byReference = true;
      }
    } else if (name === 'DEREncodedKeyValue') {
      add(nodeCrypto.createPublicKey({ key: b64(el.textContent),
                                       format: 'der', type: 'spki' }));
    } else if (name === 'KeyValue') {
      const rsa = byLocal(el, 'RSAKeyValue')[0];
      const dsa = byLocal(el, 'DSAKeyValue')[0];
      const ec = byLocal(el, 'ECKeyValue')[0];
      const ec4050 = byLocal(el, 'ECDSAKeyValue')[0];
      if (rsa) {
        add(nodeCrypto.createPublicKey({ format: 'jwk', key: { kty: 'RSA',
          n: b64(byLocal(rsa, 'Modulus')[0].textContent)
            .toString('base64url'),
          e: b64(byLocal(rsa, 'Exponent')[0].textContent)
            .toString('base64url') } }));
      } else if (dsa) {
        add(dsaPublicKey(dsa));
      } else if (ec) {
        const curve = byLocal(ec, 'NamedCurve')[0];
        const point = b64(byLocal(ec, 'PublicKey')[0].textContent);
        const spec = EC_CURVES[curve ? curve.getAttribute('URI') : ''];
        if (spec && point[0] === 4) {
          add(ecPublicKey(curve.getAttribute('URI'),
                          point.subarray(1, 1 + spec.bytes),
                          point.subarray(1 + spec.bytes)));
        }
      } else if (ec4050) {
        // RFC 4050: the curve by URN and the point as two decimal integers.
        const curve = byLocal(ec4050, 'NamedCurve')[0];
        const urn = curve ? curve.getAttribute('URN') : '';
        const spec = EC_CURVES[urn];
        if (spec) {
          add(ecPublicKey(urn, fixedBytes(
            byLocal(ec4050, 'X')[0].getAttribute('Value'), spec.bytes),
          fixedBytes(byLocal(ec4050, 'Y')[0].getAttribute('Value'),
                     spec.bytes)));
        }
      }
    } else if (name === 'KeyInfoReference') {
      const id = String(el.getAttribute('URI') || '').replace(/^#/, '');
      const target = byIdAttribute(doc, id);
      if (target) {
        keysOfKeyInfo(target, doc, published).forEach(add);
      }
    } else if (name === 'KeyName') {
      byReference = true;
    } else if (name === 'RetrievalMethod') {
      const uri = String(el.getAttribute('URI') || '');
      const target = uri.indexOf('#') === 0
        ? byIdAttribute(doc, uri.slice(1)) : null;
      if (target && target.localName === 'X509Data') {
        const holder = doc.createElementNS(DS, 'KeyInfo');
        holder.appendChild(target.cloneNode(true));
        keysOfKeyInfo(holder, doc, published).forEach(add);
      } else if (uri.indexOf('#') === 0) {
        byReference = true;
      }
    }
  });
  if (!keys.length && byReference) {
    published.forEach(add);
  }
  log.debug("Leaving keysOfKeyInfo(). " + keys.length);
  return keys;
}

function byIdAttribute(doc, id) {
  log.debug("Entering byIdAttribute(). " + id);
  const all = doc.getElementsByTagName('*');
  for (let i = 0; i < all.length; i++) {
    const el = all[i];
    for (let j = 0; j < el.attributes.length; j++) {
      const a = el.attributes[j];
      if (/^(Id|ID|id)$/.test(a.localName || a.name) && a.value === id) {
        log.debug("Leaving byIdAttribute(). Found.");
        return el;
      }
    }
  }
  log.debug("Leaving byIdAttribute(). None.");
  return null;
}

// Every certificate a set publishes beside its cases, as public keys.
function publishedCertificates(dir) {
  log.debug("Entering publishedCertificates(). " + dir);
  const out = [];
  walk(dir).forEach(function (file) {
    if (!/\.(crt|der|cer)$/.test(file) || /key/i.test(path.basename(file))) {
      return;
    }
    try {
      const raw = fs.readFileSync(file);
      const text = raw.toString('latin1');
      out.push(new nodeCrypto.X509Certificate(
        text.indexOf('-----BEGIN') >= 0 ? text : raw).publicKey);
    } catch (e) {
      // Not a certificate (a key file the name did not give away): skipped,
      // since nothing but certificates is a candidate verification key.
      log.debug("Caught in publishedCertificates(): " +
                ((e && e.message) || e));
    }
  });
  log.debug("Leaving publishedCertificates(). " + out.length);
  return out;
}

// ===========================================================================
// SIGNATURES
// ===========================================================================

const SIGNATURE_SETS = [
  { id: 'xmldsig11', dir: 'xmldsig11-interop/oracle',
    match: /^signature-.*\.xml$/, certs: 'xmldsig11-interop/oracle/keys' },
  { id: 'merlin-xmldsig-23', dir: 'archives/merlin-xmldsig-twenty-three',
    match: /^signature.*\.xml$/,
    certs: 'archives/merlin-xmldsig-twenty-three/certs' },
  { id: 'phaos-xmldsig-3',
    dir: 'archives/phaos-xmldsig-three/phaos-xmldsig-three',
    match: /^signature.*\.xml$/,
    certs: 'archives/phaos-xmldsig-three/phaos-xmldsig-three/certs' },
  { id: 'merlin-exc-c14n-1', dir: 'archives/merlin-exc-c14n-one',
    match: /\.xml$/ },
  { id: 'merlin-c14n-3', dir: 'archives/merlin-c14n-three',
    match: /^signature\.xml$/ },
  { id: 'merlin-iaik-2', dir: 'archives/merlin-iaikTests-two',
    match: /^signature\.xml$/ },
  { id: 'merlin-decrypt-2', dir: 'archives/merlin-decrypt-two',
    match: /\.xml$/ },
  { id: 'merlin-xmlenc-5-sig', dir: 'archives/merlin-xmlenc-five',
    match: /^(encsig|decryption-transform).*\.xml$/ },
  { id: 'xmldsig2ed-c14n11', dir: 'xmldsig2ed/xmldsig/c14n11',
    match: /-(IAIK|IBM|ORCL|SUN|UPC)\.xml$/ },
  { id: 'xmldsig2ed-defCan', dir: 'xmldsig2ed/xmldsig',
    match: /^defCan-.*\.xml$/, flat: true },
  { id: 'xmldsig2ed-dname', dir: 'xmldsig2ed/xmldsig/dname',
    match: /-(IAIK|IBM|ORCL|SUN|UPC)\.xml$/,
    certs: 'xmldsig2ed/xmldsig/dname/certs' },
  { id: 'xmldsig2ed-xpointer', dir: 'xmldsig2ed/xmldsig/xpointer',
    match: /-(IAIK|IBM|ORCL|SUN|UPC)\.xml$/ }
];

// The cases each set PUBLISHED as ones that must fail. Everything else in
// these sets is a valid signature.
const MUST_FAIL = [
  /truncated40\.xml$/,           // XMLDSig 1.1 interop 6.2: below 80 bits
  /hmac-sha1-40\.xml$/,          // merlin: HMAC truncated to 40 bits
  /-40-.*c14n.*\.xml$/,          // phaos: the same truncation
  /bad-digest-val\.xml$/,
  /bad-sig\.xml$/,
  /bad-retrieval-method\.xml$/,
  /decrypt-xml-bad-type\.xml$/,
  /decrypt-xml-undecryptable\.xml$/,
  /unresolvable-xpointer\.xml$/
];

// The service's verified and refused algorithms, as THIS FILE reads section
// 1a of crypto.js — deliberately a separate statement of it.
function signatureAlgorithmClass(uri) {
  log.debug("Entering signatureAlgorithmClass(). " + uri);
  let out;
  if (/hmac|md5/i.test(uri)) {
    // A MAC needs a secret shared with the signer; this service verifies
    // against certificates only. MD5 is broken (RFC 9231).
    out = 'refused';
  } else if (/#(rsa-sha1|dsa-sha1|ecdsa-sha1)$/.test(uri)) {
    out = 'sha1';
  } else if (/#(rsa|ecdsa)-sha(224|256|384|512)$/.test(uri) ||
             /#dsa-sha256$/.test(uri)) {
    out = 'verified';
  } else {
    out = 'refused';
  }
  log.debug("Leaving signatureAlgorithmClass(). " + out);
  return out;
}

function digestClass(uri) {
  log.debug("Entering digestClass(). " + uri);
  let out = 'refused';
  if (uri === DS + 'sha1') {
    out = 'sha1';
  } else if ([XENC + 'sha256', XENC + 'sha512', MORE + 'sha224',
              MORE + 'sha384', XENC + 'ripemd160'].indexOf(uri) >= 0) {
    out = 'verified';
  }
  log.debug("Leaving digestClass(). " + out);
  return out;
}

function analyseSignature(file, xml) {
  log.debug("Entering analyseSignature(). " + file);
  const doc = parse(xml);
  const sig = byLocal(doc, 'Signature').filter(function (el) {
    return el.namespaceURI === DS;
  })[0];
  if (!sig) {
    log.debug("Leaving analyseSignature(). No Signature.");
    return null;
  }
  const signedInfo = childElements(sig).filter(function (el) {
    return el.localName === 'SignedInfo';
  })[0];
  const refs = childElements(signedInfo).filter(function (el) {
    return el.localName === 'Reference';
  });
  const method = byLocal(signedInfo, 'SignatureMethod')[0];
  const c14n = byLocal(signedInfo, 'CanonicalizationMethod')[0];
  const transforms = [];
  refs.forEach(function (ref) {
    byLocal(ref, 'Transform').forEach(function (t) {
      transforms.push(String(t.getAttribute('Algorithm') || ''));
    });
  });
  const out = {
    doc: doc, sig: sig, signedInfo: signedInfo,
    signatureMethod: method ? String(method.getAttribute('Algorithm')) : '',
    c14n: c14n ? String(c14n.getAttribute('Algorithm')) : '',
    uris: refs.map(function (ref) {
      return String(ref.getAttribute('URI') || '');
    }),
    digests: refs.map(function (ref) {
      const d = byLocal(ref, 'DigestMethod')[0];
      return d ? String(d.getAttribute('Algorithm')) : '';
    }),
    transforms: transforms,
    parent: sig.parentNode && sig.parentNode.nodeType === 1
      ? sig.parentNode : null
  };
  log.debug("Leaving analyseSignature().");
  return out;
}

// Which EXCEPTION a signature case falls under, if any, from what it names.
function signatureException(a, keys) {
  log.debug("Entering signatureException().");
  const all = [a.c14n].concat(a.transforms);
  let why = '';
  if (all.some(function (u) {
    return u.indexOf(C14N11) === 0;
  })) {
    why = 'c14n11';
  } else if (a.transforms.some(function (u) {
    return u === TRANSFORM_XSLT;
  })) {
    why = 'xslt';
  } else if (a.transforms.some(function (u) {
    return /xmlenc|decrypt/i.test(u) && u !== TRANSFORM_ENVELOPED;
  })) {
    why = 'decryptTransform';
  } else if (a.transforms.some(function (u) {
    return u === TRANSFORM_XPATH || /xmldsig-filter2/.test(u);
  })) {
    why = 'xpath';
  } else if (a.uris.some(function (u) {
    return /^#xpointer\(/.test(u);
  })) {
    why = 'xpointer';
  } else if (a.uris.some(function (u) {
    return u !== '' && u.indexOf('#') !== 0;
  })) {
    why = 'external';
  } else if (!keys.length) {
    why = 'noKey';
  }
  log.debug("Leaving signatureException(). " + (why || 'none'));
  return why;
}

// What this table expects of a case in a mode: 'verified', 'rejected',
// or a refusal code.
function signatureExpectation(file, a, sha1On) {
  log.debug("Entering signatureExpectation().");
  const classes = [signatureAlgorithmClass(a.signatureMethod)]
    .concat(a.digests.map(digestClass));
  let out;
  if (classes.indexOf('refused') >= 0) {
    out = 'STS-KEYS-0061';
  } else if (classes.indexOf('sha1') >= 0 && !sha1On) {
    out = 'STS-KEYS-0062';
  } else {
    out = MUST_FAIL.some(function (re) {
      return re.test(file);
    }) ? 'rejected' : 'verified';
  }
  log.debug("Leaving signatureExpectation(). " + out);
  return out;
}

// The key text crypto.js strips from a Signature before the vendored engine
// sees it, for the same reason: the engine would read a certificate with
// forge, which reads RSA only, and the key here is already decided.
function withoutCertificateText(xml) {
  log.debug("Entering withoutCertificateText().");
  log.debug("Leaving withoutCertificateText().");
  return String(xml).replace(
    /(<(?:[A-Za-z_][\w.-]*:)?X509Certificate\b[^>]*>)[^<]*(<\/)/g, '$1$2');
}

// ONE KEY, ONE CASE, through crypto.js. An ENVELOPED signature on an element
// goes through verifyXmlSignature() — the service's own entry point, which
// refuses to guess which element it is checking. An enveloping or detached
// one has no such element, and that function is element-bound BY DESIGN (the
// signature-wrapping defence its header argues), so it is driven through
// exactly the pieces verifyXmlSignature() is built from: the algorithm
// verdict, the vendored engine, and crypto.js's verifier primitive.
function verifyWithKey(stsCrypto, a, xml, key) {
  log.debug("Entering verifyWithKey().");
  const pem = key.export({ type: 'spki', format: 'pem' }).toString();
  // Enveloped in the sense verifyXmlSignature() means: the signature is a
  // child of the element its FIRST reference names ("" or that element's
  // own id). A signature that sits inside an element and signs something
  // else (merlin's signature.xml) is a detached one that happens to be
  // nested, and that function rightly refuses it (STS-KEYS-0009).
  const first = a.uris[0];
  const parentId = a.parent ? stsCrypto.idOf(a.parent) : '';
  const enveloped = a.parent &&
    a.transforms.indexOf(TRANSFORM_ENVELOPED) >= 0 &&
    (first === '' || (parentId !== '' && first === '#' + parentId));
  if (enveloped) {
    const r = stsCrypto.verifyXmlSignature(xml, {
      element: a.parent.localName, publicKeyPem: pem });
    log.debug("Leaving verifyWithKey(). Enveloped: " + r.ok);
    return { ok: !!r.ok, code: errorCodes.codeOf(r), why: r.why || '' };
  }
  const verdict = stsCrypto.xmlAlgorithmVerdict(a.signatureMethod, a.digests);
  if (verdict.problem) {
    log.debug("Leaving verifyWithKey(). Refused: " + verdict.code);
    return { ok: false, code: verdict.code, why: verdict.problem };
  }
  let result;
  try {
    result = stsCrypto.xmldsig.verifyXml(withoutCertificateText(xml), {
      verifier: function (octets, signature) {
        return stsCrypto.verifyXmlSignatureValue(a.signatureMethod, key,
          Buffer.from(String(octets), 'binary'),
          Buffer.from(String(signature), 'binary'), null);
      } });
  } catch (e) {
    log.debug("Caught in verifyWithKey(): " + ((e && e.message) || e));
    log.debug("Leaving verifyWithKey(). Threw.");
    return { ok: false, code: '', why: (e && e.message) || String(e) };
  }
  const why = result.valid ? '' : (result.error || result.signatureError ||
    (result.references || []).map(function (r) {
      return r.reason || '';
    }).filter(Boolean).join('; ') || 'the signature value did not verify');
  log.debug("Leaving verifyWithKey(). " + !!result.valid);
  return { ok: !!result.valid, code: '', why: why };
}

function verifyCase(stsCrypto, a, xml, keys) {
  log.debug("Entering verifyCase().");
  let last = { ok: false, code: '', why: 'no candidate key' };
  const tried = keys.length ? keys : [null];
  for (let i = 0; i < tried.length; i++) {
    if (!tried[i]) {
      // No key at all: the algorithm verdict still speaks first, which is
      // what a refused algorithm is judged on.
      const v = stsCrypto.xmlAlgorithmVerdict(a.signatureMethod, a.digests);
      last = v.problem ? { ok: false, code: v.code, why: v.problem } : last;
      break;
    }
    last = verifyWithKey(stsCrypto, a, xml, tried[i]);
    if (last.ok || /^STS-KEYS-006[12]$/.test(last.code)) {
      break;
    }
  }
  log.debug("Leaving verifyCase(). " + last.ok);
  return last;
}

// ===========================================================================
// CANONICALIZATION: the merlin sets' `c14n-N.txt` files are the canonical
// forms their signer produced — each Reference's, in order, and the
// SignedInfo's LAST. The SignedInfo is compared exactly; each Reference this
// engine can process must reproduce one of the published forms; a published
// form produced by something the engine does not do is an exception.
// ===========================================================================

function referenceTarget(doc, uri) {
  log.debug("Entering referenceTarget(). " + uri);
  let out = null;
  if (uri === '' || uri === '#xpointer(/)') {
    out = doc.documentElement;
  } else {
    const m = /^#(?:xpointer\(id\('([^']*)'\)\)|([^(]*))$/.exec(uri);
    out = m ? byIdAttribute(doc, m[1] || m[2]) : null;
  }
  log.debug("Leaving referenceTarget(). " + !!out);
  return out;
}

function readTransformList(ref) {
  log.debug("Entering readTransformList().");
  const out = byLocal(ref, 'Transform').map(function (t) {
    const incl = byLocal(t, 'InclusiveNamespaces')[0];
    return { algorithm: String(t.getAttribute('Algorithm') || ''),
             prefixList: incl ? incl.getAttribute('PrefixList') || '' : '' };
  });
  log.debug("Leaving readTransformList(). " + out.length);
  return out;
}

function c14nCase(t, stsCrypto, counts, id, file, expectedFiles) {
  log.debug("Entering c14nCase(). " + id);
  const xml = fs.readFileSync(file, 'utf8');
  const a = analyseSignature(file, xml);
  const expected = expectedFiles.map(function (f) {
    return { file: path.basename(f), bytes: fs.readFileSync(f),
             matched: false };
  });
  const last = expected[expected.length - 1];
  const cm = byLocal(a.signedInfo, 'CanonicalizationMethod')[0];
  const incl = cm ? byLocal(cm, 'InclusiveNamespaces')[0] : null;
  let prefixes = null;
  if (incl) {
    prefixes = {};
    String(incl.getAttribute('PrefixList') || '').split(/\s+/)
      .filter(Boolean).forEach(function (p) {
        prefixes[p] = true;
      });
  }
  const si = Buffer.from(stsCrypto.xmldsig.canonicalizeBy(a.c14n,
    a.signedInfo, { prefixes: prefixes }), 'binary');
  let outcome = si.equals(last.bytes) ? 'pass' : 'fail';
  let why = outcome === 'pass' ? '' : firstDifference(si, last.bytes);
  if (outcome === 'fail' && a.c14n.indexOf('xml-exc-c14n') < 0) {
    // THE ONE KNOWN ENGINE DEFECT, CONFIRMED RATHER THAN ASSUMED: C14N 1.0
    // section 2.4 renders the xml:* attributes of the apex's ancestors on
    // the apex, and the vendored canonicalizer does not. If adding them —
    // on a copy, here — makes the output the published one, that is the
    // whole difference, and it is recorded as the parent's to fix; the
    // engine's SIGNER omits them the same way, so a verifier-only fix in
    // crypto.js would break this service's own inclusive signatures.
    const copy = parse(xml);
    const copySig = byLocal(copy, 'Signature').filter(function (el) {
      return el.namespaceURI === DS;
    })[0];
    const copySi = childElements(copySig).filter(function (el) {
      return el.localName === 'SignedInfo';
    })[0];
    const XML_NS = 'http://www.w3.org/XML/1998/namespace';
    for (let n = copySi.parentNode; n && n.nodeType === 1; n = n.parentNode) {
      for (let i = 0; i < n.attributes.length; i++) {
        const at = n.attributes[i];
        if (at.namespaceURI === XML_NS &&
            !copySi.hasAttributeNS(XML_NS, at.localName)) {
          copySi.setAttributeNS(XML_NS, 'xml:' + at.localName, at.value);
        }
      }
    }
    const fixed = Buffer.from(stsCrypto.xmldsig.canonicalizeBy(a.c14n,
      copySi, { prefixes: prefixes }), 'binary');
    if (fixed.equals(last.bytes)) {
      outcome = 'exception';
      why = EXCEPTIONS.xmlAttributes;
    }
  }
  tally(t, counts, 'c14n', outcome, id + ' SignedInfo (' + last.file + ')',
        why);
  last.matched = true;
  const refs = childElements(a.signedInfo).filter(function (el) {
    return el.localName === 'Reference';
  });
  refs.forEach(function (ref, i) {
    const uri = String(ref.getAttribute('URI') || '');
    const list = readTransformList(ref);
    const label = id + ' Reference ' + i + ' (URI="' + uri + '")';
    const unsupported = list.filter(function (tr) {
      return !stsCrypto.xmldsig.C14N_METHODS[tr.algorithm] &&
        tr.algorithm !== TRANSFORM_ENVELOPED &&
        tr.algorithm !== TRANSFORM_BASE64;
    })[0];
    // THE DEREFERENCE IS DONE HERE, as XMLDSig core 4.3.3.3 defines it,
    // and the canonicalizer under test is handed its node-set: a document
    // parsed afresh for each Reference, with COMMENTS REMOVED for the two
    // bare-name forms ("" and "#id") and kept for #xpointer(id('id')). The
    // vendored engine does not remove them for "" and "#id" under a
    // #WithComments method — on its signing side as well as its verifying
    // one, so the two agree with each other and not with the specification
    // (recorded on #193 for the parent project). #xpointer(/) is the
    // DOCUMENT node, whose comments and PIs outside the document element
    // an element-apex canonicalizer cannot emit: an exception.
    const fresh = parse(xml);
    const target = uri === '#xpointer(/)' ? null
      : referenceTarget(fresh, uri);
    if (unsupported || !target || list.some(function (tr) {
      return tr.algorithm === TRANSFORM_BASE64;
    })) {
      log.debug(label + ': not canonicalized here (' +
                (unsupported ? unsupported.algorithm : 'no target') + ')');
      return;
    }
    if (uri === '' || /^#[^(]*$/.test(uri)) {
      removeComments(target);
    }
    const freshSig = byLocal(fresh, 'Signature').filter(function (el) {
      return el.namespaceURI === DS;
    })[0];
    let octets;
    try {
      octets = Buffer.from(stsCrypto.xmldsig.transformOctets(target, list,
        { doc: fresh, sigNode: freshSig }).octets, 'binary');
    } catch (e) {
      log.debug("Caught in c14nCase(): " + ((e && e.message) || e));
      tally(t, counts, 'c14n', 'fail', label, e.message);
      return;
    }
    const hit = expected.filter(function (x) {
      return x !== last && !x.matched && x.bytes.equals(octets);
    })[0];
    if (hit) {
      hit.matched = true;
    }
    tally(t, counts, 'c14n', hit ? 'pass' : 'fail',
          label + (hit ? ' = ' + hit.file : ''),
          hit ? '' : 'matches none of the published forms');
  });
  expected.forEach(function (x) {
    if (!x.matched) {
      tally(t, counts, 'c14n', 'exception', id + ' ' + x.file,
            'produced by a Reference this engine does not canonicalize ' +
            '(XPath, XSLT, an external document or a Manifest)');
    }
  });
  log.debug("Leaving c14nCase().");
}

function removeComments(node) {
  log.debug("Entering removeComments().");
  const walkAndDrop = function (n) {
    log.debug("Entering walkAndDrop().");
    for (let c = n.firstChild; c;) {
      const next = c.nextSibling;
      if (c.nodeType === 8) {
        n.removeChild(c);
      } else if (c.nodeType === 1) {
        walkAndDrop(c);
      }
      c = next;
    }
    log.debug("Leaving walkAndDrop().");
  };
  walkAndDrop(node);
  log.debug("Leaving removeComments().");
}

function firstDifference(got, want) {
  log.debug("Entering firstDifference().");
  let i = 0;
  while (i < got.length && i < want.length && got[i] === want[i]) {
    i++;
  }
  log.debug("Leaving firstDifference(). " + i);
  return 'first difference at octet ' + i + ': got ' +
    JSON.stringify(got.subarray(Math.max(0, i - 20), i + 40).toString()) +
    ', published ' +
    JSON.stringify(want.subarray(Math.max(0, i - 20), i + 40).toString());
}

// ===========================================================================
// ENCRYPTION
// ===========================================================================

function pkcs12Keys(file, password) {
  log.debug("Entering pkcs12Keys(). " + path.basename(file));
  const der = forge.util.createBuffer(fs.readFileSync(file).toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), password);
  const out = [];
  [forge.pki.oids.pkcs8ShroudedKeyBag, forge.pki.oids.keyBag].forEach(
    function (type) {
      (p12.getBags({ bagType: type })[type] || []).forEach(function (bag) {
        if (bag.key) {
          out.push(nodeCrypto.createPrivateKey(
            forge.pki.privateKeyToPem(bag.key)));
        } else if (bag.asn1) {
          // An EC key forge cannot model: its PKCS#8 DER is still here.
          out.push(nodeCrypto.createPrivateKey({
            key: Buffer.from(forge.asn1.toDer(bag.asn1).getBytes(),
                             'binary'),
            format: 'der', type: 'pkcs8' }));
        }
      });
    });
  log.debug("Leaving pkcs12Keys(). " + out.length);
  return out;
}

function pkcs8Key(file) {
  log.debug("Entering pkcs8Key(). " + path.basename(file));
  log.debug("Leaving pkcs8Key().");
  return nodeCrypto.createPrivateKey({ key: fs.readFileSync(file),
                                       format: 'der', type: 'pkcs8' });
}

const ENCRYPTION_SETS = [
  { id: 'xmlenc11-oracle', dir: 'xmlenc11-interop/oracle',
    match: /^cipherText.*\.xml$/, plaintext: 'plaintext.xml' },
  { id: 'xmlenc11-microsoft', dir: 'xmlenc11-interop/microsoft',
    match: /^(cipherText|xenc11|dkey).*\.xml$/,
    plaintext: '../oracle/plaintext.xml',
    // AGRMNT.4-6 and AGRMNT.8 of the test-cases page: binary plaintext.
    binary: /^cipherText__/ },
  { id: 'xmlenc11-ibm', dir: 'xmlenc11-interop/ibm',
    match: /\.xml$/, plaintext: 'clearText' },
  { id: 'merlin-xmlenc-5', dir: 'archives/merlin-xmlenc-five',
    match: /^(bad-)?encrypt-.*\.xml$/, plaintext: 'plaintext.xml' },
  { id: 'phaos-xmlenc-3', dir: 'archives/01-phaos-xmlenc-3',
    match: /^(bad-alg-)?enc-.*\.xml$/, plaintext: 'payment.xml' }
];

// The private key each case was encrypted to, as each set documents it.
function recipientKeys(root, set, name) {
  log.debug("Entering recipientKeys(). " + name);
  const dir = path.join(root, set.dir);
  let out = [];
  const oracle = /__(RSA-\d+|EC-P\d+|DH-\d+)__/.exec(name);
  try {
    if (set.id === 'xmlenc11-oracle' && oracle) {
      const p12 = walk(dir).filter(function (f) {
        return path.basename(f).indexOf(oracle[1] + '_') === 0;
      })[0];
      out = p12 ? pkcs12Keys(p12, 'passwd') : [];
    } else if (set.id === 'xmlenc11-microsoft' && oracle &&
               /^EC-/.test(oracle[1])) {
      out = pkcs12Keys(path.join(dir, oracle[1] + '.pfx'), '1234');
    } else if (set.id === 'merlin-xmlenc-5') {
      out = [pkcs8Key(path.join(dir, /dh/.test(name) ? 'dh1.p8'
                                                      : 'rsa.p8'))];
    } else if (set.id === 'phaos-xmlenc-3') {
      out = [pkcs8Key(path.join(dir, /-ka-dh/.test(name)
        ? 'dh-priv-key.der' : 'rsa-priv-key.der'))];
    }
  } catch (e) {
    // A key that cannot be read leaves the case with no key, which the
    // case then reports as a failure naming this.
    log.debug("Caught in recipientKeys(): " + ((e && e.message) || e));
  }
  log.debug("Leaving recipientKeys(). " + out.length);
  return out;
}

// What THIS FILE expects of an encryption case, from what the case names:
// a refusal code, 'decrypted', 'rejected' (a published bad case), or an
// exception with the code its refusal must carry.
function encryptionExpectation(name, doc, product) {
  log.debug("Entering encryptionExpectation(). " + name);
  const data = byLocal(doc, 'EncryptedData')[0];
  const method = childElements(data).filter(function (el) {
    return el.localName === 'EncryptionMethod';
  })[0];
  const cipher = method ? String(method.getAttribute('Algorithm')) : '';
  const keyInfo = childElements(data).filter(function (el) {
    return el.localName === 'KeyInfo';
  })[0];
  const ek = (keyInfo && childElements(keyInfo).filter(function (el) {
    return el.localName === 'EncryptedKey';
  })[0]) || byLocal(doc, 'EncryptedKey')[0];
  const agreement = byLocal(doc, 'AgreementMethod')[0];
  const ekMethod = ek ? childElements(ek).filter(function (el) {
    return el.localName === 'EncryptionMethod';
  })[0] : null;
  const transport = ekMethod ? String(ekMethod.getAttribute('Algorithm'))
                             : '';
  const out = { expect: '', exception: '' };
  const ciphers = ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'aes128-gcm',
                   'aes192-gcm', 'aes256-gcm'];
  if (ciphers.indexOf(cipher.replace(/^.*#/, '')) < 0) {
    out.expect = 'STS-KEYS-0017';
  } else if (!ek && !(agreement && keyInfo &&
                      childElements(keyInfo).indexOf(agreement) >= 0)) {
    out.expect = 'STS-KEYS-0018';
    out.exception = 'symmetric';
  } else if (ek && /#kw-/.test(transport) && !agreement) {
    out.expect = 'STS-KEYS-0019';
    out.exception = 'symmetric';
  } else if (agreement && !/#ECDH-ES$/.test(
    String(agreement.getAttribute('Algorithm')))) {
    out.expect = 'STS-KEYS-0073';
    out.exception = 'dsaEncryption';
  } else if (agreement) {
    const kdf = byLocal(agreement, 'KeyDerivationMethod')[0];
    const kdfDigest = kdf ? byLocal(kdf, 'DigestMethod')[0] : null;
    if (!kdf || !/#ConcatKDF$/.test(String(kdf.getAttribute('Algorithm'))) ||
        !kdfDigest || /#sha1$/.test(kdfDigest.getAttribute('Algorithm'))) {
      out.expect = 'STS-KEYS-0090';
    }
  } else if (/#rsa-1_5$/.test(transport) && product) {
    out.expect = 'STS-KEYS-0070';
  } else if (/#rsa-oaep/.test(transport)) {
    const digest = childElements(ekMethod).filter(function (el) {
      return el.localName === 'DigestMethod';
    })[0];
    const mgf = childElements(ekMethod).filter(function (el) {
      return el.localName === 'MGF';
    })[0];
    const d = digest ? String(digest.getAttribute('Algorithm'))
      .replace(/^.*#/, '') : 'sha1';
    const m = /#rsa-oaep-mgf1p$/.test(transport) ? 'sha1'
      : (mgf ? String(mgf.getAttribute('Algorithm')).replace(/^.*#mgf1/, '')
             : 'sha1');
    if (d !== m) {
      // Node derives MGF1 from the OAEP digest, so a pair that differs is
      // refused by name (crypto.js section 2) — never unwrapped under the
      // wrong one and misreported as a wrong key.
      out.expect = 'STS-KEYS-0072';
    }
  }
  if (!out.expect) {
    out.expect = /^bad-/.test(name) ? 'rejected' : 'decrypted';
  }
  log.debug("Leaving encryptionExpectation(). " + out.expect);
  return out;
}

// The decrypted text is the published plaintext's — or, for an element or
// its content, a part of it — compared as CANONICAL XML, because the
// encrypter serialized the plaintext it encrypted and the published file is
// another serialization of the same infoset (Oracle's writes `<Expires/>`
// where the file has `<Expires></Expires>`). The namespace declarations a
// fragment has to repeat are set aside.
function plaintextMatches(stsCrypto, decrypted, plaintext) {
  log.debug("Entering plaintextMatches().");
  const norm = function (s) {
    log.debug("Entering norm().");
    const body = String(s).replace(/<\?xml[^>]*\?>/, '');
    let text = body;
    try {
      const doc = parse('<w>' + body + '</w>');
      text = Buffer.from(stsCrypto.xmldsig.canonicalizeBy(
        stsCrypto.xmldsig.C14N_INCLUSIVE, doc.documentElement, {}),
      'binary').toString('utf8');
    } catch (e) {
      // A fragment with a prefix it does not declare: compared as text.
      log.debug("Caught in norm(): " + ((e && e.message) || e));
    }
    log.debug("Leaving norm().");
    return text.replace(/^<w>|<\/w>$/g, '')
      .replace(/\s+xmlns(:\w+)?="[^"]*"/g, '').replace(/>\s+</g, '><')
      .replace(/\s+/g, ' ').trim();
  };
  const d = norm(decrypted);
  const ok = d.length > 0 && norm(plaintext).indexOf(d) >= 0;
  log.debug("Leaving plaintextMatches(). " + ok);
  return ok;
}

// ===========================================================================
// THE RUN
// ===========================================================================

function tally(t, counts, section, outcome, what, detail) {
  log.debug("Entering tally().");
  const row = counts[section] ||
    (counts[section] = { pass: 0, fail: 0, exception: 0 });
  row[outcome]++;
  if (outcome === 'fail') {
    t.bad(section + ': ' + what, detail);
  } else if (outcome === 'exception') {
    counts.exceptions.push(section + ': ' + what + ' — ' + detail);
    log.debug(section + ' exception: ' + what + ' — ' + detail);
  } else {
    log.debug(section + ' pass: ' + what);
  }
  log.debug("Leaving tally().");
}

function withMode(config, pairs, fn) {
  log.debug("Entering withMode().");
  Object.keys(pairs).forEach(function (key) {
    config.setOverride(key, pairs[key]);
  });
  try {
    log.debug("Leaving withMode().");
    return fn();
  } finally {
    Object.keys(pairs).forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

const SIGNATURE_MODES = [
  { name: 'development', sha1: false, pairs: {} },
  { name: 'development+sha1', sha1: true,
    pairs: { 'saml.allowSha1Signatures': true } },
  { name: 'product+sha1', sha1: false,
    pairs: { 'global.mode': 'product', 'saml.allowSha1Signatures': true } }
];

function signatureCases(root) {
  log.debug("Entering signatureCases().");
  const cases = [];
  SIGNATURE_SETS.forEach(function (set) {
    const dir = path.join(root, set.dir);
    const published = set.certs
      ? publishedCertificates(path.join(root, set.certs)) : [];
    const files = (set.flat ? fs.readdirSync(dir).map(function (f) {
      return path.join(dir, f);
    }) : walk(dir)).filter(function (f) {
      return set.match.test(path.basename(f));
    }).sort();
    files.forEach(function (file) {
      const xml = fs.readFileSync(file, 'utf8');
      const a = analyseSignature(file, xml);
      if (!a) {
        return;
      }
      let keys = [];
      const keyInfo = childElements(a.sig).filter(function (el) {
        return el.localName === 'KeyInfo';
      })[0];
      try {
        keys = keyInfo ? keysOfKeyInfo(keyInfo, a.doc, published)
                       : published.slice(0);
      } catch (e) {
        // A key the case publishes in a form node cannot read: the case
        // goes on with the candidates found so far, and is judged on them.
        log.debug("Caught in signatureCases(): " + ((e && e.message) || e));
      }
      cases.push({ name: set.id + '/' + path.basename(file), file: file,
                   xml: xml, a: a, keys: keys,
                   exception: signatureException(a, keys) });
    });
  });
  log.debug("Leaving signatureCases(). " + cases.length);
  return cases;
}

// One mode at a time, its settings changed ONCE around every case — a
// setting changed per case is a config log line per case.
function runSignatures(t, stsCrypto, config, root, counts) {
  log.debug("Entering runSignatures().");
  const cases = signatureCases(root);
  counts.signatureCases = cases.length;
  SIGNATURE_MODES.forEach(function (m) {
    withMode(config, m.pairs, function () {
      cases.forEach(function (c) {
        judgeSignature(t, stsCrypto, counts, c, m);
      });
    });
  });
  log.debug("Leaving runSignatures().");
}

function judgeSignature(t, stsCrypto, counts, c, m) {
  log.debug("Entering judgeSignature(). " + c.name);
  const label = c.name + ' [' + m.name + ']';
  const expect = signatureExpectation(c.file, c.a, m.sha1);
  const got = verifyCase(stsCrypto, c.a, c.xml, c.keys);
  if (/^STS-/.test(expect)) {
    tally(t, counts, 'signature', got.code === expect && !got.ok
      ? 'pass' : 'fail', label + ' refused ' + expect,
    'got ok=' + got.ok + ' code=' + got.code + ' ' + got.why);
  } else if (c.exception) {
    tally(t, counts, 'signature', got.ok ? 'fail' : 'exception',
          label, got.ok ? 'VERIFIED although it needs ' + c.exception
            : EXCEPTIONS[c.exception] + ' [' + got.why + ']');
  } else if (expect === 'rejected') {
    tally(t, counts, 'signature', got.ok ? 'fail' : 'pass',
          label + ' must fail', got.ok ? 'it verified' : got.why);
  } else {
    tally(t, counts, 'signature', got.ok ? 'pass' : 'fail',
          label + ' verifies', got.why);
  }
  log.debug("Leaving judgeSignature().");
}

function runCanonicalization(t, stsCrypto, root, counts) {
  log.debug("Entering runCanonicalization().");
  // The merlin sets: one signature, or several, each with its c14n files.
  [['merlin-xmldsig-23', 'archives/merlin-xmldsig-twenty-three'],
   ['merlin-exc-c14n-1', 'archives/merlin-exc-c14n-one'],
   ['merlin-c14n-3', 'archives/merlin-c14n-three'],
   ['merlin-iaik-2', 'archives/merlin-iaikTests-two']].forEach(function (s) {
    const dir = path.join(root, s[1]);
    fs.readdirSync(dir).filter(function (f) {
      return /\.xml$/.test(f) && !/^iaikTests\./.test(f);
    }).sort().forEach(function (f) {
      const stem = f.replace(/\.xml$/, '');
      const re = new RegExp('^' + (s[0] === 'merlin-xmldsig-23'
        ? stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '-' : '') +
        'c14n-(\\d+)\\.txt$');
      const outputs = fs.readdirSync(dir).filter(function (g) {
        return re.test(g);
      }).sort(function (x, y) {
        return Number(re.exec(x)[1]) - Number(re.exec(y)[1]);
      }).map(function (g) {
        return path.join(dir, g);
      });
      if (outputs.length) {
        c14nCase(t, stsCrypto, counts, s[0] + '/' + f, path.join(dir, f),
                 outputs);
      }
    });
  });
  // The Second Edition's C14N 1.1 cases: an input, an XPath selecting the
  // document subset, and the canonical form. Both halves are exceptions,
  // and the assertion is that the engine REFUSES C14N 1.1 by name.
  const c14n11 = path.join(root, 'xmldsig2ed/c14n11');
  fs.readdirSync(c14n11).filter(function (f) {
    return /\.xpath$/.test(f);
  }).sort().forEach(function (f) {
    let refused = '';
    try {
      stsCrypto.xmldsig.canonicalizeBy(C14N11, parse('<a/>').documentElement,
                                       {});
    } catch (e) {
      log.debug("Caught in runCanonicalization(): " +
                ((e && e.message) || e));
      refused = e.message;
    }
    tally(t, counts, 'c14n', /Unsupported CanonicalizationMethod/.test(
      refused) ? 'exception' : 'fail', 'xmldsig2ed/c14n11/' + f,
    refused ? EXCEPTIONS.c14n11 + '; ' + EXCEPTIONS.xpath
      : 'C14N 1.1 was NOT refused');
  });
  log.debug("Leaving runCanonicalization().");
}

function encryptionCases(root) {
  log.debug("Entering encryptionCases().");
  const cases = [];
  // The key the refusals are asked with, where a case names no key of this
  // service's kind at all: any RSA key will do, since each of those cases is
  // refused before a key is used.
  const anyKey = pkcs8Key(path.join(root, 'archives/merlin-xmlenc-five',
                                    'rsa.p8'));
  ENCRYPTION_SETS.forEach(function (set) {
    const dir = path.join(root, set.dir);
    const plaintext = fs.readFileSync(path.join(dir, set.plaintext), 'utf8');
    fs.readdirSync(dir).filter(function (f) {
      return set.match.test(f);
    }).sort().forEach(function (f) {
      const xml = fs.readFileSync(path.join(dir, f), 'utf8');
      const doc = parse(xml);
      if (!byLocal(doc, 'EncryptedData').length) {
        return;
      }
      const keys = recipientKeys(root, set, f);
      cases.push({ name: set.id + '/' + f, file: f, xml: xml, doc: doc,
                   keys: keys, key: keys[0] || anyKey, plaintext: plaintext,
                   binary: !!(set.binary && set.binary.test(f)) });
    });
  });
  log.debug("Leaving encryptionCases(). " + cases.length);
  return cases;
}

function runEncryption(t, stsCrypto, config, root, counts) {
  log.debug("Entering runEncryption().");
  const cases = encryptionCases(root);
  counts.encryptionCases = cases.length;
  [false, true].forEach(function (product) {
    withMode(config, product ? { 'global.mode': 'product' } : {},
             function () {
               cases.forEach(function (c) {
                 const want = encryptionExpectation(c.file, c.doc, product);
                 if (want.expect === 'decrypted' && c.binary) {
                   want.expect = 'STS-KEYS-0023';
                   want.exception = 'binaryPlaintext';
                 }
                 const got = stsCrypto.decryptElement(c.xml, c.key);
                 judgeDecryption(t, stsCrypto, counts, c.name + ' [' +
                   (product ? 'product' : 'development') + ']', want, got,
                 errorCodes.codeOf(got), c.plaintext, c.keys);
               });
             });
  });
  log.debug("Leaving runEncryption().");
}

function judgeDecryption(t, stsCrypto, counts, label, want, got, code,
                         plaintext, keys) {
  log.debug("Entering judgeDecryption().");
  const detail = 'got ok=' + got.ok + ' code=' + code + ' ' + (got.why || '');
  if (want.exception) {
    tally(t, counts, 'encryption', !got.ok && code === want.expect
      ? 'exception' : 'fail', label, !got.ok && code === want.expect
      ? EXCEPTIONS[want.exception] : 'expected the refusal ' + want.expect +
        '; ' + detail);
  } else if (/^STS-/.test(want.expect)) {
    tally(t, counts, 'encryption', !got.ok && code === want.expect
      ? 'pass' : 'fail', label + ' refused ' + want.expect, detail);
  } else if (want.expect === 'rejected') {
    tally(t, counts, 'encryption', got.ok ? 'fail' : 'pass',
          label + ' must fail', detail);
  } else if (!keys.length) {
    tally(t, counts, 'encryption', 'fail', label,
          'no recipient key could be read for it');
  } else {
    const ok = got.ok && plaintextMatches(stsCrypto, got.xml, plaintext);
    tally(t, counts, 'encryption', ok ? 'pass' : 'fail',
          label + ' decrypts to the published plaintext',
          got.ok ? 'decrypted, but not to the plaintext: ' +
            String(got.xml).slice(0, 120) : detail);
  }
  log.debug("Leaving judgeDecryption().");
}

// ---------------------------------------------------------------------------
// THE PSource LABEL (#193 regression). The one published case that carries
// `<xenc:OAEPparams>` (WRAP.4) also names a digest pair node cannot unwrap
// with, so it is refused before the label matters. This takes the published
// RSA-2048 case, unwraps its content key with the published private key,
// wraps it again to the same certificate WITH a label, and writes the label
// into the EncryptionMethod: decryptElement() must read it — and the same
// document without it must fail, which is what proves it was read.
// ---------------------------------------------------------------------------
function oaepLabelRegression(t, stsCrypto, root, counts) {
  log.debug("Entering oaepLabelRegression().");
  const dir = path.join(root, 'xmlenc11-interop/oracle');
  const name = 'cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml';
  const xml = fs.readFileSync(path.join(dir, name), 'utf8');
  const key = pkcs12Keys(path.join(dir, 'RSA-2048_SHA256WithRSA.p12'),
                         'passwd')[0];
  const doc = parse(xml);
  const ek = byLocal(doc, 'EncryptedKey')[0];
  const cipherValue = byLocal(ek, 'CipherValue')[0];
  const contentKey = nodeCrypto.privateDecrypt({ key: key,
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
  b64(cipherValue.textContent));
  const label = Buffer.from('w3c-193 PSource');
  const rewrapped = nodeCrypto.publicEncrypt({
    key: nodeCrypto.createPublicKey(key),
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1',
    oaepLabel: label }, contentKey);
  cipherValue.textContent = rewrapped.toString('base64');
  const unlabelled = new xmldom.XMLSerializer().serializeToString(doc);
  const method = childElements(ek).filter(function (el) {
    return el.localName === 'EncryptionMethod';
  })[0];
  const params = doc.createElementNS(XENC, 'xenc:OAEPparams');
  params.textContent = label.toString('base64');
  method.insertBefore(params, method.firstChild);
  const labelled = new xmldom.XMLSerializer().serializeToString(doc);
  const plaintext = fs.readFileSync(path.join(dir, 'plaintext.xml'), 'utf8');
  const withLabel = stsCrypto.decryptElement(labelled, key);
  const without = stsCrypto.decryptElement(unlabelled, key);
  tally(t, counts, 'encryption', withLabel.ok &&
        plaintextMatches(stsCrypto, withLabel.xml, plaintext)
    ? 'pass' : 'fail', 'OAEPparams (PSource) is read as the OAEP label',
  withLabel.why || '');
  tally(t, counts, 'encryption', !without.ok ? 'pass' : 'fail',
        'and the same key without its OAEPparams does not unwrap',
        without.ok ? 'it decrypted' : '');
  log.debug("Leaving oaepLabelRegression().");
}

// Every file the pinned list names is where the fetch put it: a corpus that
// has quietly lost files still reports counts, and the counts are what
// everybody reads.
function checkCorpus(t, root) {
  log.debug("Entering checkCorpus().");
  const rows = fs.readFileSync(LIST, 'utf8').split('\n').filter(function (l) {
    return l && l.charAt(0) !== '#';
  });
  const missing = rows.map(function (l) {
    return l.split(' ')[1];
  }).filter(function (rel) {
    return !fs.existsSync(path.join(root, rel));
  });
  t.check(rows.length > 300 && missing.length === 0,
          'every one of the ' + rows.length + ' pinned files is in ' + root,
          missing.slice(0, 5).join(', '));
  log.debug("Leaving checkCorpus().");
  return missing.length === 0;
}

// The exceptions, grouped by reason, so the run says what was NOT tested
// and why rather than a bare number.
function reportExceptions(t, counts) {
  log.debug("Entering reportExceptions().");
  const byReason = {};
  counts.exceptions.forEach(function (line) {
    const m = /^(\w+): .*? — (.*)$/.exec(line);
    const reason = m ? m[1] + ': ' + m[2].replace(/ \[.*$/, '')
      .slice(0, 90) : line;
    byReason[reason] = (byReason[reason] || 0) + 1;
  });
  Object.keys(byReason).sort().forEach(function (reason) {
    t.log.info('  exception x' + byReason[reason] + ' — ' + reason);
  });
  log.debug("Leaving reportExceptions().");
}

function run(t) {
  log.debug("Entering run().");
  const root = process.env[ENV];
  if (!root || !fs.existsSync(root)) {
    t.bad('the W3C XML Security corpus is not here',
          ENV + '=' + (root || '(unset)') + ' — it is fetched into the ' +
          'tests image by tests/tools/fetch-w3c-xmlsec.sh; run this file ' +
          'there (./docker-npm-test.sh --only=w3c_xmlsec), or fetch it and ' +
          'set ' + ENV);
    log.debug("Leaving run(). No corpus.");
    return;
  }
  if (!checkCorpus(t, root)) {
    log.debug("Leaving run(). Incomplete corpus.");
    return;
  }
  const stsCrypto = require('../common/crypto');
  const config = require('../common/config');
  const counts = { exceptions: [] };
  runSignatures(t, stsCrypto, config, root, counts);
  runCanonicalization(t, stsCrypto, root, counts);
  runEncryption(t, stsCrypto, config, root, counts);
  oaepLabelRegression(t, stsCrypto, root, counts);
  reportExceptions(t, counts);
  ['signature', 'c14n', 'encryption'].forEach(function (section) {
    const row = counts[section] || { pass: 0, fail: 0, exception: 0 };
    t.check(row.fail === 0, section + ': ' + row.pass + ' pass, ' +
            row.fail + ' fail, ' + row.exception + ' exception',
    row.fail + ' failed; each is listed above');
  });
  const all = ['signature', 'c14n', 'encryption'].reduce(function (n, s) {
    const row = counts[s] || { pass: 0 };
    return n + row.pass;
  }, 0);
  t.check(all > 0, 'the W3C interop cases ran: ' + all + ' passed');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'w3c_xmlsec',
  describe: 'the W3C XML Signature, XML Encryption and C14N interop cases ' +
    'against common/crypto.js',
  run: run,
  EXCEPTIONS: EXCEPTIONS
};
