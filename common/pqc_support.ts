'use strict';
//
// File: pqc_support.ts
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
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16). `PqcSupport` takes the logger, the
// JOSE composite table and the vendored registry through its constructor, as
// `PqcSupportDeps`. The module still exports `KINDS`, `ofAlgorithm`,
// `ofCertificate`, `of` and `sentence` from ONE TRANSITIONAL instance built
// with the real modules below, for the unconverted callers; it goes when the
// composition root exists. The two helpers that were free functions are
// private static methods, logging through the logger they are handed.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('./config');

const log = bunyan.createLogger({
  name: 'pqc_support',
  level: config.value('global.logLevel')
});

import pkijs = require('pkijs');
import asn1js = require('asn1js');
// This service's own JOSE reading of the post-quantum algorithms, for the
// JOSE composite names the X.509 registry does not use.
import pqJose = require('./pq_jose');
// The vendored registry: every post-quantum algorithm by id, name and OID.
import pqcX509 = require('./vendored/pqc_x509');

type PqcKind = 'pq' | 'composite' | 'kem' | 'hybrid';

// What every answer is: a kind, the algorithm, and the words a reader sees.
interface PqcInfo {
  kind: PqcKind;
  algorithm: string;
  label: string;
  family: string;
  standard: string;
}

// The classical half of a composite, as the vendored registry describes it.
interface TradDescription {
  kind?: string;
  name?: string;
  bits?: number;
  pss?: boolean;
  curve?: string;
}

// One entry of the vendored registry, in the fields this module reads.
interface RegistryEntry {
  id: string;
  name: string;
  family: string;
  use?: string;
  composite?: { mldsa: string; trad?: TradDescription };
}

interface Logger {
  debug(message: string): void;
}

interface PqcSupportDeps {
  log: Logger;
  joseComposites: Record<string, { ml: string; trad: string }>;
  registry: {
    alg(name: string): RegistryEntry | null | undefined;
    algForOid(oid: string): RegistryEntry | null | undefined;
  };
}

interface OfOptions {
  certificatePem?: string;
  algorithms?: string | string[];
}

// The standard each family is defined in, for the sentence a reader is shown.
const STANDARDS: Record<string, string> = {
  'ML-DSA': 'FIPS 204',
  'SLH-DSA': 'FIPS 205',
  'ML-KEM': 'FIPS 203',
  'Composite ML-DSA': 'draft-ietf-lamps-pq-composite-sigs'
};

// X.509 (2019) clause 9.8 (ITU-T, not RFC 5280): the alternative public key
// extension.
const ALT_KEY_OID = '2.5.29.72';

class PqcSupport {
  static readonly KINDS: PqcKind[] = ['pq', 'composite', 'kem', 'hybrid'];

  constructor(private readonly deps: PqcSupportDeps) {
    deps.log.debug("Entering PqcSupport.constructor().");
    deps.log.debug("Leaving PqcSupport.constructor().");
  }

  private static describeTrad(log: Logger,
                              trad: TradDescription | undefined): string {
    log.debug("Entering PqcSupport.describeTrad().");
    if (!trad) {
      log.debug("Leaving PqcSupport.describeTrad().");
      return 'a classical key';
    }
    let out = trad.name || '';
    if (trad.kind === 'rsa') {
      out = 'RSA-' + trad.bits + (trad.pss ? '-PSS' : '');
    } else if (trad.kind === 'ec') {
      out = 'ECDSA ' + trad.curve;
    }
    log.debug("Leaving PqcSupport.describeTrad().");
    return out;
  }

  private static fromRegistry(log: Logger, entry: RegistryEntry): PqcInfo {
    log.debug("Entering PqcSupport.fromRegistry().");
    if (entry.family === 'Composite ML-DSA') {
      const trad = entry.composite && entry.composite.trad;
      log.debug("Leaving PqcSupport.fromRegistry(). Composite.");
      return { kind: 'composite', algorithm: entry.id,
               label: entry.composite.mldsa + ' + ' +
                 PqcSupport.describeTrad(log, trad),
               family: entry.family, standard: STANDARDS[entry.family] };
    }
    log.debug("Leaving PqcSupport.fromRegistry().");
    return { kind: entry.use === 'kem' ? 'kem' : 'pq', algorithm: entry.id,
             label: entry.name, family: entry.family,
             standard: STANDARDS[entry.family] || '' };
  }

  // -------------------------------------------------------------------------
  // BY NAME: a JOSE `alg`, a vendored key-material id, a node key type
  // (`ml-dsa-65`) or an OID. Anything else — every classical spelling — is
  // null.
  // -------------------------------------------------------------------------
  ofAlgorithm(name: unknown): PqcInfo | null {
    const { log, joseComposites, registry } = this.deps;
    log.debug("Entering PqcSupport.ofAlgorithm(). name=" + name);
    const text = String(name || '').trim();
    if (!text) {
      log.debug("Leaving PqcSupport.ofAlgorithm(). Nothing named.");
      return null;
    }
    const jose = joseComposites[text];
    if (jose) {
      log.debug("Leaving PqcSupport.ofAlgorithm(). A JOSE composite.");
      return { kind: 'composite', algorithm: text,
               label: jose.ml + ' + ' + jose.trad,
               family: 'Composite ML-DSA',
               standard: 'draft-ietf-jose-pq-composite-sigs' };
    }
    const entry = /^[0-9]+(\.[0-9]+)+$/.test(text)
      ? registry.algForOid(text) : registry.alg(text);
    log.debug("Leaving PqcSupport.ofAlgorithm(). " +
              (entry ? entry.id : 'classical'));
    return entry ? PqcSupport.fromRegistry(log, entry) : null;
  }

  // -------------------------------------------------------------------------
  // BY CERTIFICATE: the SubjectPublicKeyInfo's algorithm, and — for a
  // classical key — whether the certificate carries an alternative
  // post-quantum key. A certificate that will not parse is null: the icon
  // marks what is known.
  // -------------------------------------------------------------------------
  ofCertificate(pem: unknown): PqcInfo | null {
    const { log } = this.deps;
    log.debug("Entering PqcSupport.ofCertificate().");
    const text = String(pem || '');
    const block = text.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    if (!block) {
      log.debug("Leaving PqcSupport.ofCertificate(). No certificate.");
      return null;
    }
    let cert: pkijs.Certificate;
    try {
      const der = Buffer.from(block[0].replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, ''), 'base64');
      cert = pkijs.Certificate.fromBER(new Uint8Array(der));
    } catch (e) {
      log.debug("Caught in PqcSupport.ofCertificate(): " +
                ((e && e.message) || e));
      log.debug("Leaving PqcSupport.ofCertificate(). Unreadable.");
      return null;
    }
    const primary = this.ofAlgorithm(
      cert.subjectPublicKeyInfo.algorithm.algorithmId);
    if (primary) {
      log.debug("Leaving PqcSupport.ofCertificate(). " + primary.kind);
      return primary;
    }
    const alt = (cert.extensions || []).filter(function (one) {
      return one.extnID === ALT_KEY_OID;
    })[0];
    if (!alt) {
      log.debug("Leaving PqcSupport.ofCertificate(). Classical.");
      return null;
    }
    try {
      const parsed = asn1js.fromBER(alt.extnValue.valueBlock.valueHexView);
      // asn1js types the parse result as a generic BaseBlock; the value
      // blocks walked here are the SEQUENCE / OBJECT IDENTIFIER the
      // extension is defined as.
      const oid = (parsed.result as any).valueBlock.value[0]
        .valueBlock.value[0]
        .valueBlock.toString();
      const altKey = this.ofAlgorithm(oid);
      if (altKey) {
        log.debug("Leaving PqcSupport.ofCertificate(). Hybrid.");
        return { kind: 'hybrid', algorithm: altKey.algorithm,
                 label: 'alternative ' + altKey.label + ' key',
                 family: altKey.family,
                 standard: 'X.509 (2019) clause 9.8, ' + altKey.standard };
      }
    } catch (e) {
      log.debug("Caught in PqcSupport.ofCertificate(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving PqcSupport.ofCertificate(). Classical, with a " +
              "classical alt key.");
    return null;
  }

  // -------------------------------------------------------------------------
  // THE FIRST ANSWER AMONG SEVERAL SPELLINGS OF ONE KEY — a certificate
  // first, because it is the most specific (it is the only one that can see a
  // hybrid), then each name in the order given.
  // -------------------------------------------------------------------------
  of(options?: OfOptions | null): PqcInfo | null {
    const { log } = this.deps;
    log.debug("Entering PqcSupport.of().");
    const opts = options || {};
    const fromCert = opts.certificatePem
      ? this.ofCertificate(opts.certificatePem) : null;
    if (fromCert) {
      log.debug("Leaving PqcSupport.of(). From the certificate.");
      return fromCert;
    }
    const names: string[] = [].concat(opts.algorithms || []);
    for (let i = 0; i < names.length; i++) {
      const found = this.ofAlgorithm(names[i]);
      if (found) {
        log.debug("Leaving PqcSupport.of(). From a name.");
        return found;
      }
    }
    log.debug("Leaving PqcSupport.of(). Classical.");
    return null;
  }

  // The sentence the icon's tooltip and accessible name carry.
  sentence(info: PqcInfo | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering PqcSupport.sentence().");
    if (!info) {
      log.debug("Leaving PqcSupport.sentence().");
      return '';
    }
    const text = ({
      pq: 'Post-quantum key pair: ' + info.label,
      composite: 'Composite post-quantum key pair: ' + info.label +
                 ' — both halves must verify',
      kem: 'Post-quantum key-establishment key: ' + info.label +
           ' — it signs nothing',
      hybrid: 'Hybrid: a classical key whose certificate carries an ' +
              info.label
    } as Record<string, string>)[info.kind] ||
      'Post-quantum: ' + info.label;
    log.debug("Leaving PqcSupport.sentence().");
    return text + (info.standard ? ' (' + info.standard + ')' : '');
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one.
const support = new PqcSupport({
  log: log,
  joseComposites: pqJose.COMPOSITES,
  registry: pqcX509
});

export = {
  PqcSupport: PqcSupport,
  KINDS: PqcSupport.KINDS,
  ofAlgorithm: support.ofAlgorithm.bind(support) as
    PqcSupport['ofAlgorithm'],
  ofCertificate: support.ofCertificate.bind(support) as
    PqcSupport['ofCertificate'],
  of: support.of.bind(support) as PqcSupport['of'],
  sentence: support.sentence.bind(support) as PqcSupport['sentence']
};
