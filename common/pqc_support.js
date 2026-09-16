// @ts-check
'use strict';
//
// File: pqc_support.js
//
// ===========================================================================
// DOES THIS KEY PAIR USE A POST-QUANTUM ALGORITHM? — ONE ANSWER (2026-09-13).
//
// `/admin/pki` and `/admin/keys` mark every key pair that uses a post-quantum
// algorithm with an icon. The two pages name keys in FOUR vocabularies — a
// JOSE `alg` (`ML-DSA-44-ES256`), a vendored key-material id
// (`mldsa44-ecdsa-p256-sha256`), an SPKI OID, and the SubjectPublicKeyInfo of a
// certificate — and a page that decided for itself would decide with whichever
// spelling it happened to be holding. This is the one function both ask, so an
// icon cannot appear on one page and not the other for the same key.
//
// ---------------------------------------------------------------------------
// FOUR KINDS, BECAUSE "PQC" IS FOUR DIFFERENT CLAIMS.
//
//   pq         the key IS post-quantum — ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
//   composite  ONE key made of a post-quantum half and a classical half, both
//              of which must verify (draft-ietf-lamps-pq-composite-sigs, and
//              its JOSE twin)
//   kem        a post-quantum KEY-ESTABLISHMENT key — ML-KEM (FIPS 203). It
//              signs nothing, and saying "PQC" about it without saying that
//              would let a reader assume a signature.
//   hybrid     a CLASSICAL key whose certificate also carries an ALTERNATIVE
//              post-quantum key (X.509 (2019) clause 9.8). The primary key is
//              not post-quantum at all; the certificate is ready for a
//              relying party that is.
//
// A classical key is `null`, never a fifth kind: the icon marks what has a
// post-quantum property, and the absence of one is not a thing to draw.
//
// **THE CLASSIFICATION IS THE KEY'S, NOT THE SIGNATURE ON ITS CERTIFICATE.** A
// classical key certified by a post-quantum CA does not become a post-quantum
// key pair, and an ML-DSA key certified by an RSA CA — which is every ML-DSA
// key this service holds — is one. The question the icon answers is what the
// holder of the private key can do.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `pkijs`,
// `asn1js`, `pq_jose.js` and the vendored PQC registry, none of which requires
// it back, so it is a LEAF.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'pqc_support',
  level: config.value('global.logLevel')
});

const pkijs = require('pkijs');
const asn1js = require('asn1js');
// This service's own JOSE reading of the post-quantum algorithms, for the
// JOSE composite names the X.509 registry does not use.
const pqJose = require('./pq_jose');
// The vendored registry: every post-quantum algorithm by id, name and OID.
const pqcX509 = require('./vendored/pqc_x509');

// The standard each family is defined in, for the sentence a reader is shown.
const STANDARDS = {
  'ML-DSA': 'FIPS 204',
  'SLH-DSA': 'FIPS 205',
  'ML-KEM': 'FIPS 203',
  'Composite ML-DSA': 'draft-ietf-lamps-pq-composite-sigs'
};

// X.509 (2019) clause 9.8 (ITU-T, not RFC 5280): the alternative public key
// extension.
const ALT_KEY_OID = '2.5.29.72';

function describeTrad(trad) {
  log.debug("Entering describeTrad().");
  if (!trad) {
    log.debug("Leaving describeTrad().");
    return 'a classical key';
  }
  let out = trad.name || '';
  if (trad.kind === 'rsa') {
    out = 'RSA-' + trad.bits + (trad.pss ? '-PSS' : '');
  } else if (trad.kind === 'ec') {
    out = 'ECDSA ' + trad.curve;
  }
  log.debug("Leaving describeTrad().");
  return out;
}

function fromRegistry(entry) {
  log.debug("Entering fromRegistry().");
  if (entry.family === 'Composite ML-DSA') {
    const trad = entry.composite && entry.composite.trad;
    log.debug("Leaving fromRegistry(). Composite.");
    return { kind: 'composite', algorithm: entry.id,
             label: entry.composite.mldsa + ' + ' + describeTrad(trad),
             family: entry.family, standard: STANDARDS[entry.family] };
  }
  log.debug("Leaving fromRegistry().");
  return { kind: entry.use === 'kem' ? 'kem' : 'pq', algorithm: entry.id,
           label: entry.name, family: entry.family,
           standard: STANDARDS[entry.family] || '' };
}

// ---------------------------------------------------------------------------
// BY NAME: a JOSE `alg`, a vendored key-material id, a node key type
// (`ml-dsa-65`) or an OID. Anything else — every classical spelling — is null.
// ---------------------------------------------------------------------------
function ofAlgorithm(name) {
  log.debug("Entering ofAlgorithm(). name=" + name);
  const text = String(name || '').trim();
  if (!text) {
    log.debug("Leaving ofAlgorithm(). Nothing named.");
    return null;
  }
  const jose = pqJose.COMPOSITES[text];
  if (jose) {
    log.debug("Leaving ofAlgorithm(). A JOSE composite.");
    return { kind: 'composite', algorithm: text,
             label: jose.ml + ' + ' + jose.trad,
             family: 'Composite ML-DSA',
             standard: 'draft-ietf-jose-pq-composite-sigs' };
  }
  const entry = /^[0-9]+(\.[0-9]+)+$/.test(text)
    ? pqcX509.algForOid(text) : pqcX509.alg(text);
  log.debug("Leaving ofAlgorithm(). " + (entry ? entry.id : 'classical'));
  return entry ? fromRegistry(entry) : null;
}

// ---------------------------------------------------------------------------
// BY CERTIFICATE: the SubjectPublicKeyInfo's algorithm, and — for a classical
// key — whether the certificate carries an alternative post-quantum key.
// A certificate that will not parse is null: the icon marks what is known.
// ---------------------------------------------------------------------------
function ofCertificate(pem) {
  log.debug("Entering ofCertificate().");
  const text = String(pem || '');
  const block = text.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!block) {
    log.debug("Leaving ofCertificate(). No certificate.");
    return null;
  }
  let cert;
  try {
    const der = Buffer.from(block[0].replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    cert = pkijs.Certificate.fromBER(new Uint8Array(der));
  } catch (e) {
    log.debug("Caught in ofCertificate(): " + ((e && e.message) || e));
    log.debug("Leaving ofCertificate(). Unreadable.");
    return null;
  }
  const primary = ofAlgorithm(cert.subjectPublicKeyInfo.algorithm.algorithmId);
  if (primary) {
    log.debug("Leaving ofCertificate(). " + primary.kind);
    return primary;
  }
  const alt = (cert.extensions || []).filter(function (one) {
    return one.extnID === ALT_KEY_OID;
  })[0];
  if (!alt) {
    log.debug("Leaving ofCertificate(). Classical.");
    return null;
  }
  try {
    const parsed = asn1js.fromBER(alt.extnValue.valueBlock.valueHexView);
    const oid = /** @type {any} */ (parsed.result).valueBlock.value[0]
      .valueBlock.value[0]
      .valueBlock.toString();
    const altKey = ofAlgorithm(oid);
    if (altKey) {
      log.debug("Leaving ofCertificate(). Hybrid.");
      return { kind: 'hybrid', algorithm: altKey.algorithm,
               label: 'alternative ' + altKey.label + ' key',
               family: altKey.family,
               standard: 'X.509 (2019) clause 9.8, ' + altKey.standard };
    }
  } catch (e) {
    log.debug("Caught in ofCertificate(): " + ((e && e.message) || e));
  }
  log.debug("Leaving ofCertificate(). Classical, with a classical alt key.");
  return null;
}

// ---------------------------------------------------------------------------
// THE FIRST ANSWER AMONG SEVERAL SPELLINGS OF ONE KEY — a certificate first,
// because it is the most specific (it is the only one that can see a hybrid),
// then each name in the order given.
// ---------------------------------------------------------------------------
function of(options) {
  log.debug("Entering of().");
  const opts = options || {};
  const fromCert = opts.certificatePem ? ofCertificate(opts.certificatePem)
                                       : null;
  if (fromCert) {
    log.debug("Leaving of(). From the certificate.");
    return fromCert;
  }
  const names = [].concat(opts.algorithms || []);
  for (let i = 0; i < names.length; i++) {
    const found = ofAlgorithm(names[i]);
    if (found) {
      log.debug("Leaving of(). From a name.");
      return found;
    }
  }
  log.debug("Leaving of(). Classical.");
  return null;
}

// The sentence the icon's tooltip and accessible name carry.
function sentence(info) {
  log.debug("Entering sentence().");
  if (!info) {
    log.debug("Leaving sentence().");
    return '';
  }
  const text = {
    pq: 'Post-quantum key pair: ' + info.label,
    composite: 'Composite post-quantum key pair: ' + info.label +
               ' — both halves must verify',
    kem: 'Post-quantum key-establishment key: ' + info.label +
         ' — it signs nothing',
    hybrid: 'Hybrid: a classical key whose certificate carries an ' +
            info.label
  }[info.kind] || 'Post-quantum: ' + info.label;
  log.debug("Leaving sentence().");
  return text + (info.standard ? ' (' + info.standard + ')' : '');
}

module.exports = {
  KINDS: ['pq', 'composite', 'kem', 'hybrid'],
  ofAlgorithm: ofAlgorithm,
  ofCertificate: ofCertificate,
  of: of,
  sentence: sentence
};
