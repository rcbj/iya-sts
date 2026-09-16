// @ts-check
'use strict';
//
// File: certificate_details.js
//
// ===========================================================================
// ONE CERTIFICATE, EVERY FIELD, AND THE PATH IT BUILDS (2026-09-13).
//
// `/admin/pki` and `/admin/crypto-metadata` both draw certificates and, until
// this date, both stopped at a subject, a serial prefix, a date and sixteen
// characters of a thumbprint — so the question a reader brings to a
// certificate authority (what is IN it, and does it chain) had to be answered
// with `openssl x509 -text` on a PEM copied out of a `<details>`. This is the
// MODEL both pages and `GET /admin-api/certificates` answer from, so the three
// cannot describe one certificate three ways.
//
// ---------------------------------------------------------------------------
// THE MECHANISM IS THE VENDORED INSPECTOR'S AND THE COMPLETENESS IS HERE.
//
// `common/vendored/x509.js`'s `describeCertificate()`, `describeExtension()`
// and `verifyChain()` are the parent project's own certificate inspector — the
// code behind its PKI / X.509 page and `saml_cert.html` — so an extension this
// service names and one that project names are named by ONE table, and a
// signature verified here and there is verified by one function. That is
// `crypto.js`'s split made again: the vendored file is the mechanism, and this
// one adds what a DETAILS view owes and that inspector deliberately does not
// carry — the tbsCertificate's inner signature algorithm beside the outer one,
// every RDN of both names with its attribute OID, the time TYPE of each
// validity bound (a 2050 date written as UTCTime is a certificate that expired
// in 1950), the public key's parameters and bytes, the two unique identifiers,
// and the signature value.
//
// **THE FINGERPRINTS ARE NODE'S AND NOT THE INSPECTOR'S.** That one computes
// them with Web Crypto and answers nulls where there is none, which is right
// for a browser page on a plain-HTTP origin and wrong for a server: node always
// has a digest, and a details view with two blank fingerprint rows would read
// as a certificate that has none.
//
// ---------------------------------------------------------------------------
// THE CHAIN IS BUILT, NOT ASSUMED.
//
// A certificate record here usually carries a `chainPem` beside it, and it is
// a SNAPSHOT — taken when the leaf was issued, and wrong the moment a Root is
// replaced (`tls/CLAUDE.md` records what that looked like). So `pathFor()`
// walks issuer to subject over the CANDIDATES it is handed, matching the name
// AND verifying the signature at every hop, and reports where it stopped and
// why. A snapshot that no longer signs the leaf is therefore reported as a
// broken link rather than drawn as a chain, which is the whole value of a
// trust-chain view: one that agreed with whatever the record said would be
// right exactly when nobody needed it.
//
// **IT READS NO CALLER'S PEM.** This module describes what it is handed and
// decides nothing about where that came from; `admin-core/certificate_views.js`
// is what guarantees every certificate reaching it is one this service holds.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, node's
// `crypto`, `pkijs`, `asn1js` and the vendored `x509` and `pqc_x509` modules —
// none of which requires it back — so it is a LEAF and anything here may
// require it.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'certificate_details',
  level: config.value('global.logLevel')
});

const nodeCrypto = require('crypto');
const pkijs = require('pkijs');
const asn1js = require('asn1js');
// The parent project's own inspector, byte-identical. DO NOT EDIT IT HERE.
const x509 = require('./vendored/x509');
// Its post-quantum registry, for the one thing the inspector's summary gets
// wrong — see `publicKeyLabel()`.
const pqcX509 = require('./vendored/pqc_x509');

// How far a path may be walked. Every hierarchy this service builds is at most
// five certificates deep (a leaf under a SPIFFE downstream CA: Root, realm
// Intermediate, SPIFFE Issuing CA, downstream CA, leaf); a limit well past
// that is only a guard against a loop two certificates could make.
const MAX_PATH = 8;

// ---------------------------------------------------------------------------
// The readable name of an extension, from the vendored module's own NAME for
// it — `subjectKeyIdentifier` becomes "Subject Key Identifier". A handful do
// not split into English and are written out; everything else is derived, so
// an extension the vendored table learns tomorrow is labelled the day it does.
// ---------------------------------------------------------------------------
const EXTENSION_LABELS = {
  cRLDistributionPoints: 'CRL Distribution Points',
  extKeyUsage: 'Extended Key Usage',
  authorityInfoAccess: 'Authority Information Access',
  subjectInfoAccess: 'Subject Information Access',
  freshestCRL: 'Freshest CRL (Delta CRL Distribution Point)',
  ocspNoCheck: 'OCSP No Check',
  netscapeCertType: 'Netscape Certificate Type',
  subjectAltPublicKeyInfo: 'Subject Alternative Public Key Info',
  tlsFeature: 'TLS Feature (Must-Staple)'
};

function extensionLabel(name, oid) {
  log.debug("Entering extensionLabel().");
  if (EXTENSION_LABELS[name]) {
    log.debug("Leaving extensionLabel().");
    return EXTENSION_LABELS[name];
  }
  if (!name || name === oid) {
    log.debug("Leaving extensionLabel(). Unknown extension.");
    return 'Unrecognised extension';
  }
  const words = String(name).replace(/([a-z0-9])([A-Z])/g, '$1 $2');
  log.debug("Leaving extensionLabel().");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  const first = String(pem || '').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  log.debug("Leaving pemToDer().");
  return Buffer.from(String(first ? first[0] : pem)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
}

// Every PEM certificate in a bundle, in order. A chain attribute on a
// directory entry is several certificates concatenated.
function splitPem(text) {
  log.debug("Entering splitPem().");
  const found = String(text || '').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving splitPem(). " + found.length + " certificate(s).");
  return found.map(function (one) { return one + '\n'; });
}

function colonHex(buffer) {
  log.debug("Entering colonHex().");
  const hex = Buffer.from(buffer).toString('hex').toUpperCase();
  log.debug("Leaving colonHex().");
  return (hex.match(/.{2}/g) || [hex]).join(':');
}

// The SHA-256 of the DER, lower-case hex with no separators. It is the
// HANDLE a page links a certificate by, and it is the same computation
// `common/pki.js`'s `thumbprintOf()` makes, so a thumbprint already printed on
// either page is a handle that works.
function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  log.debug("Leaving fingerprintOf().");
  return nodeCrypto.createHash('sha256').update(pemToDer(pem)).digest('hex');
}

function parse(pem) {
  log.debug("Entering parse().");
  const der = pemToDer(pem);
  const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
  log.debug("Leaving parse().");
  return { der: der, cert: cert };
}

// ---------------------------------------------------------------------------
// A NAME, RDN BY RDN. The string form is the vendored module's, so it matches
// what `/admin/pki` already prints; the rows are what a string cannot say —
// which attribute each value is, by OID, and in what order the certificate
// actually carries them.
// ---------------------------------------------------------------------------
const DN_BY_OID = (function buildDnByOid() {
  log.debug("Entering buildDnByOid().");
  const out = {};
  Object.keys(x509.DN_ATTRS || {}).forEach(function (short) {
    const entry = x509.DN_ATTRS[short];
    out[entry.oid] = { short: short, label: entry.label };
  });
  log.debug("Leaving buildDnByOid().");
  return out;
})();

function nameOf(name) {
  log.debug("Entering nameOf().");
  const rdns = (name.typesAndValues || []).map(function (one) {
    const known = DN_BY_OID[one.type] || null;
    const block = one.value && one.value.valueBlock;
    return {
      oid: one.type,
      short: known ? known.short : '',
      label: known ? known.label : 'Attribute ' + one.type,
      value: block && block.value !== undefined ? String(block.value)
        : (block && block.valueHexView
          ? Buffer.from(block.valueHexView).toString('hex') : '')
    };
  });
  log.debug("Leaving nameOf(). " + rdns.length + " attribute(s).");
  return { text: x509.dnToString(name), attributes: rdns };
}

// A validity bound, with the ASN.1 type it is written in. RFC 5280 section
// 4.1.2.5 requires UTCTime through 2049 and GeneralizedTime from 2050, and a
// certificate that gets that wrong is read by every validator as a date a
// century off — so the type is a FIELD here, not a formatting detail.
function timeOf(time) {
  log.debug("Entering timeOf().");
  log.debug("Leaving timeOf().");
  return {
    iso: time.value.toISOString(),
    type: time.type === 1 ? 'GeneralizedTime' : 'UTCTime'
  };
}

function algorithmOf(identifier) {
  log.debug("Entering algorithmOf().");
  const oid = identifier.algorithmId;
  const sig = x509.sigAlgForOid ? x509.sigAlgForOid(oid) : null;
  const params = identifier.algorithmParams;
  let parameters = 'absent';
  if (params instanceof asn1js.Null) {
    parameters = 'NULL';
  } else if (params instanceof asn1js.ObjectIdentifier) {
    parameters = params.valueBlock.toString();
  } else if (params) {
    parameters = Buffer.from(params.toBER(false)).toString('hex');
  }
  log.debug("Leaving algorithmOf().");
  return { oid: oid, name: sig ? (sig.label || sig.id) : '',
           parameters: parameters };
}

// What node's OpenSSL can say about the key beyond its algorithm: the RSA
// modulus and exponent, the EC curve. A post-quantum key is one it may not be
// able to read (every one on node 22, the composites on 24), and that is an
// ANSWER rather than an error — the SubjectPublicKeyInfo still names its
// algorithm and its size.
function keyFactsOf(spkiDer) {
  log.debug("Entering keyFactsOf().");
  try {
    const key = nodeCrypto.createPublicKey({ key: Buffer.from(spkiDer),
                                             format: 'der', type: 'spki' });
    const out = { type: key.asymmetricKeyType };
    const details = key.asymmetricKeyDetails || {};
    if (details.modulusLength) {
      out.modulusBits = details.modulusLength;
    }
    if (details.publicExponent !== undefined) {
      out.publicExponent = String(details.publicExponent);
    }
    if (details.namedCurve) {
      out.namedCurve = details.namedCurve;
    }
    log.debug("Leaving keyFactsOf().");
    return out;
  } catch (e) {
    log.debug("Caught in keyFactsOf(): " + ((e && e.message) || e));
    log.debug("Leaving keyFactsOf(). Not readable by this runtime.");
    return null;
  }
}

// ---------------------------------------------------------------------------
// WHAT KIND OF KEY, IN ONE PHRASE. The inspector's summary imports the key to
// learn a modulus or a curve and, for a composite ML-DSA key, reports whatever
// its CLASSICAL half imported as — so an ML-DSA-44 + Ed25519 key was summarised
// as "Ed25519", which is the half that is not post-quantum and the one claim
// about that certificate a reader must not be misled on. A post-quantum OID is
// therefore named from the registry that defines it, and every other key keeps
// the inspector's answer.
// ---------------------------------------------------------------------------
function publicKeyLabel(oid, inspectorSays) {
  log.debug("Entering publicKeyLabel().");
  const pq = pqcX509.algForOid(oid);
  log.debug("Leaving publicKeyLabel().");
  return pq ? pqcX509.labelFor(pq.id) : inspectorSays;
}

// ---------------------------------------------------------------------------
// ONE CERTIFICATE, DESCRIBED WHOLE.
//
// The order of `fields` is the order of the ASN.1 — tbsCertificate first,
// then the outer signature algorithm and value — because that is the order
// RFC 5280 section 4.1 writes them in and the order `openssl x509 -text`
// prints them in, and a reader comparing the two should not have to hunt.
// ---------------------------------------------------------------------------
async function describe(pem) {
  log.debug("Entering describe().");
  const parsed = parse(pem);
  const cert = parsed.cert;
  const summary = await x509.describeCertificate(new Uint8Array(parsed.der));
  const spki = cert.subjectPublicKeyInfo;
  const spkiDer = Buffer.from(spki.toSchema().toBER(false));
  const publicKeyBytes = Buffer.from(spki.subjectPublicKey.valueBlock
    .valueHexView);
  const signatureBytes = Buffer.from(cert.signatureValue.valueBlock
    .valueHexView);
  const serialHex = Buffer.from(cert.serialNumber.valueBlock.valueHexView)
    .toString('hex');
  const now = Date.now();
  const notBefore = cert.notBefore.value.getTime();
  const notAfter = cert.notAfter.value.getTime();
  const tbsSignature = algorithmOf(cert.signature);
  const outerSignature = algorithmOf(cert.signatureAlgorithm);
  const uniqueId = function (value) {
    log.debug("Entering uniqueId().");
    log.debug("Leaving uniqueId().");
    return value && value.byteLength
      ? Buffer.from(value).toString('hex') : null;
  };
  const extensions = (summary.extensions || []).map(function (one) {
    return {
      oid: one.oid,
      name: one.name === one.oid ? '' : one.name,
      label: extensionLabel(one.name, one.oid),
      critical: !!one.critical,
      value: one.value === undefined ? null : one.value,
      text: x509.extensionValueText(one),
      parseError: one.parseError || null
    };
  });
  const out = {
    fingerprint: fingerprintOf(pem),
    pem: pem.replace(/\s*$/, '\n'),
    summary: {
      subject: summary.subject,
      issuer: summary.issuer,
      serialHex: serialHex,
      notBefore: summary.notBefore,
      notAfter: summary.notAfter,
      expired: notAfter < now,
      notYetValid: notBefore > now,
      daysRemaining: Math.floor((notAfter - now) / 86400000),
      publicKey: publicKeyLabel(spki.algorithm.algorithmId, summary.publicKey),
      signatureAlgorithm: summary.signatureAlgorithm,
      // Whether the NAMES match. Whether the certificate signed itself is a
      // property of the path, and `pathFor()` is what checks it.
      selfIssued: summary.subject === summary.issuer,
      ca: extensions.some(function (one) {
        return one.name === 'basicConstraints' && one.value &&
               one.value.ca === true;
      }),
      extensionCount: extensions.length
    },
    fingerprints: {
      sha1: colonHex(nodeCrypto.createHash('sha1').update(parsed.der)
        .digest()),
      sha256: colonHex(nodeCrypto.createHash('sha256').update(parsed.der)
        .digest())
    },
    fields: {
      tbsCertificate: {
        version: { value: summary.version, encoded: summary.version - 1 },
        serialNumber: {
          hex: serialHex,
          decimal: serialHex ? BigInt('0x' + serialHex).toString() : '0',
          octets: serialHex.length / 2
        },
        signature: tbsSignature,
        issuer: nameOf(cert.issuer),
        validity: {
          notBefore: timeOf(cert.notBefore),
          notAfter: timeOf(cert.notAfter)
        },
        subject: nameOf(cert.subject),
        subjectPublicKeyInfo: {
          algorithm: {
            oid: spki.algorithm.algorithmId,
            name: summary.publicKeyAlgorithm,
            parameters: algorithmOf(spki.algorithm).parameters
          },
          description: publicKeyLabel(spki.algorithm.algorithmId,
                                      summary.publicKey),
          key: keyFactsOf(spkiDer),
          publicKeyOctets: publicKeyBytes.length,
          publicKeyHex: publicKeyBytes.toString('hex'),
          // The SHA-256 of the whole SubjectPublicKeyInfo, which is what an
          // HPKP-style pin and `STS_SPKI_PIN` are made of.
          spkiSha256: nodeCrypto.createHash('sha256').update(spkiDer)
            .digest('base64')
        },
        issuerUniqueID: uniqueId(cert.issuerUniqueID),
        subjectUniqueID: uniqueId(cert.subjectUniqueID),
        extensions: extensions
      },
      signatureAlgorithm: outerSignature,
      // RFC 5280 section 4.1.1.2: the outer algorithm MUST equal the one
      // inside the signed part. A certificate where they differ is one a
      // validator refuses and a reader would never spot in a summary.
      signatureAlgorithmsAgree: tbsSignature.oid === outerSignature.oid &&
                                tbsSignature.parameters ===
                                outerSignature.parameters,
      signatureValue: {
        octets: signatureBytes.length,
        hex: signatureBytes.toString('hex')
      }
    }
  };
  log.debug("Leaving describe(). " + out.summary.subject);
  return out;
}

// ---------------------------------------------------------------------------
// THE PATH FROM A CERTIFICATE UP TO A SELF-SIGNED ONE, OVER THE CANDIDATES
// GIVEN.
//
// At every hop: every candidate whose SUBJECT is this certificate's ISSUER is
// tried, and the first whose key VERIFIES the signature is taken. Names alone
// are not enough and this is the case that proves it — a replaced Root has the
// same subject as the one it replaced, so a walk by name would draw a complete
// chain to a certificate that signs nothing on it.
//
// `status` is one of four, and each is a different thing to do about it:
//
//   complete     ends at a certificate that signed itself
//   incomplete   no candidate carries the issuer's name
//   unverified   candidates carry the name and none of their keys verifies
//   too-deep     the walk passed MAX_PATH, which only a loop produces
// ---------------------------------------------------------------------------
async function signedBy(childPem, parentPem) {
  log.debug("Entering signedBy().");
  try {
    const links = await x509.verifyChain([childPem, parentPem]);
    log.debug("Leaving signedBy().");
    return !!(links[0] && links[0].signatureValid);
  } catch (e) {
    log.debug("Caught in signedBy(): " + ((e && e.message) || e));
    log.debug("Leaving signedBy(). It could not be checked.");
    return false;
  }
}

async function pathFor(pem, candidates) {
  log.debug("Entering pathFor().");
  const pool = [];
  const seen = {};
  (candidates || []).forEach(function (one) {
    const text = typeof one === 'string' ? one : one && one.pem;
    if (!text) {
      return;
    }
    let fp;
    let names;
    try {
      fp = fingerprintOf(text);
      const cert = parse(text).cert;
      names = { subject: x509.dnToString(cert.subject),
                issuer: x509.dnToString(cert.issuer) };
    } catch (e) {
      log.debug("Caught in pathFor(): " + ((e && e.message) || e));
      return;
    }
    if (seen[fp]) {
      return;
    }
    seen[fp] = true;
    pool.push({ pem: text, fingerprint: fp, subject: names.subject,
                issuer: names.issuer });
  });

  const start = parse(pem).cert;
  const path = [{ pem: pem, fingerprint: fingerprintOf(pem),
                  subject: x509.dnToString(start.subject),
                  issuer: x509.dnToString(start.issuer) }];
  let status = 'complete';
  let reason = '';
  while (true) {
    const current = path[path.length - 1];
    if (current.subject === current.issuer &&
        await signedBy(current.pem, current.pem)) {
      break;
    }
    if (path.length >= MAX_PATH) {
      status = 'too-deep';
      reason = 'The walk passed ' + MAX_PATH + ' certificates without ' +
               'reaching one that signed itself, which only a loop produces.';
      break;
    }
    const named = pool.filter(function (one) {
      return one.subject === current.issuer &&
             one.fingerprint !== current.fingerprint &&
             !path.some(function (p) {
               return p.fingerprint === one.fingerprint;
             });
    });
    if (!named.length) {
      status = 'incomplete';
      reason = 'No certificate this service holds is named "' +
               current.issuer + '", so the path stops at "' +
               current.subject + '".';
      break;
    }
    let found = null;
    for (let i = 0; i < named.length && !found; i++) {
      if (await signedBy(current.pem, named[i].pem)) {
        found = named[i];
      }
    }
    if (!found) {
      status = 'unverified';
      reason = named.length + ' certificate(s) held here are named "' +
               current.issuer + '" and none of their keys verifies the ' +
               'signature on "' + current.subject + '" — the issuer was ' +
               'replaced by one with the same name.';
      break;
    }
    path.push(found);
  }
  log.debug("Leaving pathFor(). " + path.length + " certificate(s), " +
            status + ".");
  return { path: path, status: status, reason: reason };
}

// ---------------------------------------------------------------------------
// A CERTIFICATE AND ITS TRUST CHAIN, which is what a details view draws.
//
// `options.anchors` maps a fingerprint to a sentence naming what that anchor
// is to THIS service ("this service's Root CA"), so a chain that ends at a
// self-signed certificate says whether it is one anybody here has installed.
// ---------------------------------------------------------------------------
async function detailsFor(pem, candidates, options) {
  log.debug("Entering detailsFor().");
  const opts = options || {};
  const anchors = opts.anchors || {};
  const built = await pathFor(pem, candidates);
  const links = await x509.verifyChain(built.path.map(function (one) {
    return one.pem;
  }));
  const chain = [];
  for (let i = 0; i < built.path.length; i++) {
    const one = built.path[i];
    const link = links[i] || {};
    const last = i === built.path.length - 1;
    const endsSelfSigned = last && built.status === 'complete';
    // What this certificate's issuer is allowed to do, judged at the position:
    // everything above the first certifies the one below it.
    const above = !last ? links[i + 1] : (endsSelfSigned ? link : null);
    const usage = above && above.keyUsage;
    const described = await describe(one.pem);
    chain.push({
      position: i,
      fingerprint: one.fingerprint,
      subject: one.subject,
      issuer: one.issuer,
      role: i === 0 ? 'the certificate'
        : (endsSelfSigned ? 'trust anchor' : 'intermediate'),
      // A link that is not the last is always signed by the next; the last is
      // checked against ITSELF only when the walk ended there.
      signatureValid: (!last || endsSelfSigned) ? !!link.signatureValid
                                                : null,
      signedBy: !last ? built.path[i + 1].subject
        : (endsSelfSigned ? one.subject : null),
      expired: !!link.expired,
      notYetValid: !!link.notYetValid,
      issuerMayCertify: usage
        ? x509.keyUsagePermits(usage, 'keyCertSign') : null,
      anchor: endsSelfSigned ? (anchors[one.fingerprint] || null) : null,
      certificate: described
    });
  }
  const first = chain[0].certificate;
  const out = {
    fingerprint: first.fingerprint,
    certificate: first,
    chain: chain,
    chainStatus: built.status,
    chainReason: built.reason,
    chainTrusted: built.status === 'complete' &&
                  chain.every(function (one) {
                    return one.signatureValid !== false && !one.expired &&
                           !one.notYetValid &&
                           one.issuerMayCertify !== false;
                  }) &&
                  !!anchors[chain[chain.length - 1].fingerprint]
  };
  log.debug("Leaving detailsFor(). " + chain.length + " link(s), " +
            built.status + ".");
  return out;
}

module.exports = {
  MAX_PATH: MAX_PATH,
  fingerprintOf: fingerprintOf,
  splitPem: splitPem,
  extensionLabel: extensionLabel,
  describe: describe,
  pathFor: pathFor,
  detailsFor: detailsFor
};
