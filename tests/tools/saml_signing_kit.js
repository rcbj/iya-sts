'use strict';
//
// File: tests/tools/saml_signing_kit.js
//
// ===========================================================================
// KEYS, CERTIFICATES AND SIGNATURES IN EVERY XML SIGNATURE FAMILY, FOR THE
// TESTS OF `common/crypto.js` SECTION 1a (#37 follow-up).
//
// A HELPER, NOT A TEST: it lives under `tools/` so `run.js` does not discover
// it (the directory rule `tests/CLAUDE.md` describes).
//
// WHY IT SIGNS WITH NODE DIRECTLY. The service verifies with node's OpenSSL
// behind the vendored canonicalizer; these helpers produce the signature
// VALUE with node too, but from a table written here — per algorithm, the
// hash, the padding, the salt and the r||s encoding — so a mistake in the
// service's table (a wrong hash for a URI, DER where XMLDSig 1.1 says r||s,
// the wrong PSS salt) is a signature that does not verify rather than one
// that agrees with itself. The XML around the value is the vendored general
// engine's `signXml()`, whose digests the service registers, which is the
// same engine the parent project's debugger signs with.
//
// AND THE FAKE REQUEST AND RESPONSE the SAML route handlers are driven with,
// straight off the express router, so no port is bound — the arrangement
// `tests/saml_request_signatures.js` introduced, shared here by the three
// follow-up files rather than copied into each.
//
// THE CERTIFICATES ARE BUILT BY HAND, because nothing in this repository
// issues an Ed448, DSA or SLH-DSA certificate, and the verifier only needs
// the SUBJECT KEY: each one is a minimal X.509 v3 structure carrying the key,
// signed by a throwaway RSA issuer. Node parses it; nothing here validates
// the issuer, which is the point — the tests are about the key.
// ===========================================================================

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'saml_signing_kit',
  level: process.env.LOG_LEVEL || 'info' });

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const MORE7 = 'http://www.w3.org/2007/05/xmldsig-more#';
const MORE21 = 'http://www.w3.org/2021/04/xmldsig-more#';
const PQ = 'http://www.w3.org/2026/08/xmldsig-more#';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';

// [ SignatureMethod, key generation type, options, how to sign ].
// `how`: { hash, pss: saltLength, p1363: true } or { oneShot: true }.
const FAMILIES = [
  ['rsa-sha256', MORE + 'rsa-sha256', 'rsa', { modulusLength: 2048 },
   { hash: 'sha256' }],
  ['rsa-sha224', MORE + 'rsa-sha224', 'rsa', { modulusLength: 2048 },
   { hash: 'sha224' }],
  ['rsa-sha512', MORE + 'rsa-sha512', 'rsa', { modulusLength: 2048 },
   { hash: 'sha512' }],
  ['rsa-pss-sha256', MORE7 + 'sha256-rsa-MGF1', 'rsa',
   { modulusLength: 2048 }, { hash: 'sha256', pss: 32 }],
  ['rsa-pss-sha3-384', MORE7 + 'sha3-384-rsa-MGF1', 'rsa',
   { modulusLength: 2048 }, { hash: 'sha3-384', pss: 48 }],
  ['rsa-pss-params', MORE7 + 'rsa-pss', 'rsa', { modulusLength: 2048 },
   { hash: 'sha256', pss: 32 }],
  ['ecdsa-p256-sha256', MORE + 'ecdsa-sha256', 'ec',
   { namedCurve: 'P-256' }, { hash: 'sha256', p1363: true }],
  ['ecdsa-p384-sha384', MORE + 'ecdsa-sha384', 'ec',
   { namedCurve: 'P-384' }, { hash: 'sha384', p1363: true }],
  ['ecdsa-p521-sha512', MORE + 'ecdsa-sha512', 'ec',
   { namedCurve: 'P-521' }, { hash: 'sha512', p1363: true }],
  ['ecdsa-p256-sha224', MORE + 'ecdsa-sha224', 'ec',
   { namedCurve: 'P-256' }, { hash: 'sha224', p1363: true }],
  ['ecdsa-p256-sha3-256', MORE21 + 'ecdsa-sha3-256', 'ec',
   { namedCurve: 'P-256' }, { hash: 'sha3-256', p1363: true }],
  ['ed25519', MORE21 + 'eddsa-ed25519', 'ed25519', {}, { oneShot: true }],
  ['ed448', MORE21 + 'eddsa-ed448', 'ed448', {}, { oneShot: true }],
  ['dsa-sha256', 'http://www.w3.org/2009/xmldsig11#dsa-sha256', 'dsa',
   { modulusLength: 2048, divisorLength: 256 },
   { hash: 'sha256', p1363: true }],
  ['ml-dsa-44', PQ + 'ml-dsa-44', 'ml-dsa-44', {}, { oneShot: true }],
  ['ml-dsa-87', PQ + 'ml-dsa-87', 'ml-dsa-87', {}, { oneShot: true }],
  ['slh-dsa-sha2-128f', PQ + 'slh-dsa-sha2-128f', 'slh-dsa-sha2-128f', {},
   { oneShot: true }]
];

// The SHA-1 methods, which the setting governs.
const SHA1 = {
  rsa: [DS + 'rsa-sha1', 'rsa', { modulusLength: 2048 }, { hash: 'sha1' }],
  ecdsa: [MORE + 'ecdsa-sha1', 'ec', { namedCurve: 'P-256' },
          { hash: 'sha1', p1363: true }],
  digest: DS + 'sha1'
};

// --- a minimal DER writer ----------------------------------------------------
function derLength(n) {
  log.debug("Entering derLength().");
  if (n < 128) {
    log.debug("Leaving derLength().");
    return Buffer.from([n]);
  }
  const bytes = [];
  let rest = n;
  while (rest) {
    bytes.unshift(rest & 255);
    rest = rest >> 8;
  }
  log.debug("Leaving derLength().");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function tlv(tag, body) {
  log.debug("Entering tlv().");
  log.debug("Leaving tlv().");
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function sequence(parts) {
  log.debug("Entering sequence().");
  log.debug("Leaving sequence().");
  return tlv(0x30, Buffer.concat(parts));
}

function oid(text) {
  log.debug("Entering oid().");
  const parts = text.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  parts.slice(2).forEach(function (value) {
    const stack = [value & 127];
    let rest = value >> 7;
    while (rest) {
      stack.unshift((rest & 127) | 128);
      rest = rest >> 7;
    }
    out.push.apply(out, stack);
  });
  log.debug("Leaving oid().");
  return tlv(6, Buffer.from(out));
}

function utcTime(date) {
  log.debug("Entering utcTime().");
  log.debug("Leaving utcTime().");
  return tlv(0x17, Buffer.from(date.toISOString()
    .replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
}

function commonName(cn) {
  log.debug("Entering commonName().");
  log.debug("Leaving commonName().");
  return sequence([tlv(0x31, sequence([oid('2.5.4.3'),
                                       tlv(0x0c, Buffer.from(cn))]))]);
}

let issuer = null;

// A certificate for `publicKey`, as `{ der, b64, pem }`.
function certificateFor(publicKey, cn) {
  log.debug("Entering certificateFor().");
  if (!issuer) {
    issuer = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  }
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const algorithm = sequence([oid('1.2.840.113549.1.1.11'),
                              Buffer.from([5, 0])]);
  const tbs = sequence([
    tlv(0xa0, tlv(2, Buffer.from([2]))),
    tlv(2, Buffer.concat([Buffer.from([1]), nodeCrypto.randomBytes(8)])),
    algorithm, commonName('xml-signing-keys issuer'),
    sequence([utcTime(new Date(Date.now() - 60000)),
              utcTime(new Date(Date.now() + 86400000))]),
    commonName(cn || 'xml-signing-keys subject'), spki
  ]);
  const value = nodeCrypto.sign('sha256', tbs, issuer.privateKey);
  const der = sequence([tbs, algorithm,
                        tlv(3, Buffer.concat([Buffer.from([0]), value]))]);
  const b64 = der.toString('base64');
  log.debug("Leaving certificateFor().");
  return {
    der: der, b64: b64,
    pem: '-----BEGIN CERTIFICATE-----\n' +
         b64.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n'
  };
}

// A key pair and its certificate: `{ name, uri, publicKey, privateKey, cert,
// how }`.
function keyFor(row) {
  log.debug("Entering keyFor(). " + row[0]);
  const pair = nodeCrypto.generateKeyPairSync(row[2], row[3]);
  log.debug("Leaving keyFor().");
  return { name: row[0], uri: row[1], type: row[2], how: row[4],
           publicKey: pair.publicKey, privateKey: pair.privateKey,
           cert: certificateFor(pair.publicKey, row[0]) };
}

// The signature VALUE over `octets` (a Buffer) — see the header.
function signatureValue(key, octets) {
  log.debug("Entering signatureValue(). " + key.name);
  const how = key.how;
  let value;
  if (how.oneShot) {
    value = nodeCrypto.sign(null, octets, key.privateKey);
  } else if (how.pss !== undefined) {
    value = nodeCrypto.sign(how.hash, octets, {
      key: key.privateKey, saltLength: how.pss,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING });
  } else if (how.p1363) {
    value = nodeCrypto.sign(how.hash, octets,
      { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  } else {
    value = nodeCrypto.sign(how.hash, octets, key.privateKey);
  }
  log.debug("Leaving signatureValue().");
  return value;
}

// An enveloped signature over `xml`'s root, after its <Issuer> (or first).
// `opts.digestUri` chooses the DigestMethod (SHA-256 by default),
// `opts.keyInfo` false leaves the certificate out, `opts.c14nAlg` chooses
// the canonicalization.
function signEnveloped(stsCrypto, xml, key, opts) {
  log.debug("Entering signEnveloped(). " + key.name);
  const o = opts || {};
  const hasIssuer = /<(?:[A-Za-z_][\w.-]*:)?Issuer\b/.test(xml);
  const signed = stsCrypto.xmldsig.signXml(xml, {
    sigAlg: key.uri,
    digestUri: o.digestUri || XENC + 'sha256',
    c14nAlg: o.c14nAlg,
    placement: o.placement || (hasIssuer ? 'after-issuer' : 'first'),
    keyInfo: o.keyInfo === false ? 'none' : 'x509',
    certPem: key.cert.pem,
    transforms: [{ algorithm: DS + 'enveloped-signature' },
                 { algorithm: o.c14nAlg ||
                   'http://www.w3.org/2001/10/xml-exc-c14n#' }],
    signer: function (octets) {
      return signatureValue(key, Buffer.from(octets, 'binary'))
        .toString('binary');
    }
  });
  log.debug("Leaving signEnveloped().");
  return signed.xml;
}

// --- the route plumbing ------------------------------------------------------
function fakeReq(method, path, query, rawQuery, body, extra) {
  log.debug("Entering fakeReq().");
  const headers = { host: 'idp.test' };
  const req = Object.assign({
    method: method, path: path, url: path,
    originalUrl: path + (rawQuery ? '?' + rawQuery : ''),
    query: query || {}, params: {}, body: body === undefined ? '' : body,
    protocol: 'https', headers: headers, ip: '127.0.0.1',
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return headers[String(name).toLowerCase()];
    }
  }, extra || {});
  log.debug("Leaving fakeReq().");
  return req;
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: '', location: '',
                headersSent: false };
  let settle = null;
  res.done = new Promise(function (resolve) {
    settle = resolve;
  });
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
    res.headersSent = true;
    settle(res);
    log.debug("Leaving send().");
    return res;
  };
  res.redirect = function (code, url) {
    log.debug("Entering redirect().");
    res.statusCode = code;
    res.location = url;
    res.headersSent = true;
    settle(res);
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
  throw new Error('no ' + method.toUpperCase() + ' ' + path +
                  ' is registered');
}

// Run `fn` with settings overridden, and put them back. A promise `fn` is
// waited for before the settings are cleared.
function withSettings(config, pairs, fn) {
  log.debug("Entering withSettings().");
  Object.keys(pairs).forEach(function (key) {
    config.setOverride(key, pairs[key]);
  });
  const clear = function () {
    log.debug("Entering clear().");
    Object.keys(pairs).forEach(function (key) {
      config.clearOverride(key);
    });
    log.debug("Leaving clear().");
  };
  let out;
  try {
    out = fn();
  } catch (e) {
    log.debug("Caught in withSettings(): " + ((e && e.message) || e));
    clear();
    throw e;
  }
  if (out && typeof out.then === 'function') {
    log.debug("Leaving withSettings(). A promise.");
    return out.then(function (value) {
      clear();
      return value;
    }, function (e) {
      clear();
      throw e;
    });
  }
  clear();
  log.debug("Leaving withSettings().");
  return out;
}

module.exports = {
  fakeReq: fakeReq,
  fakeRes: fakeRes,
  handlerFor: handlerFor,
  withSettings: withSettings,
  FAMILIES: FAMILIES,
  SHA1: SHA1,
  URIS: { DS: DS, MORE: MORE, MORE7: MORE7, MORE21: MORE21, PQ: PQ,
          XENC: XENC },
  certificateFor: certificateFor,
  keyFor: keyFor,
  signatureValue: signatureValue,
  signEnveloped: signEnveloped
};
