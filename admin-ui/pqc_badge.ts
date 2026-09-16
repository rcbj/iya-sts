'use strict';
//
// File: pqc_badge.ts
//
// ===========================================================================
// THE POST-QUANTUM ICON, DRAWN ONE WAY ON EVERY PAGE (2026-09-13).
//
// `/admin/pki` and `/admin/keys` mark each key pair that uses a post-quantum
// algorithm. WHETHER a key does is `common/pqc_support.ts`'s answer; this file
// is how that answer LOOKS, and nothing else draws it — so the icon on a
// Root CA row and the icon on an ML-DSA signing key are one element with one
// meaning, and the certificate details dialog shows the same one.
//
// **THE ICON IS A LATTICE** — nine points joined in a grid — because ML-DSA and
// ML-KEM are lattice constructions and the picture should say "a different
// kind of mathematics" rather than "secure", which a padlock or a shield would
// claim and a key pair's algorithm does not. SLH-DSA is hash-based and gets
// the same mark: the icon says post-quantum, the tooltip says which.
//
// **FOUR KINDS, FOUR WORDS BESIDE THE ICON**, because they are four claims:
// `PQC` for a post-quantum key, `PQC+` for a composite (a post-quantum half and
// a classical half), `PQC KEM` for a key-establishment key that signs nothing,
// and `PQC alt` — dashed — for a CLASSICAL key whose certificate carries an
// alternative post-quantum key. A reader who sees only the icon on a hybrid row
// and concludes the key is post-quantum has been told something false, so the
// hybrid is drawn visibly weaker.
//
// **NO SCRIPT, NO STYLESHEET, NO IMAGE REQUEST.** An inline SVG is markup, so
// `script-src 'none'` and `img-src` are both untouched; the style is on the
// element because this file does not own either page's `<style>`, and a badge
// that depended on a stylesheet one page forgot to include would be unstyled
// there with nothing failing. The sentence is in `title` for a pointer and in
// `aria-label` for a screen reader, which reads the element as one image.
//
// A LIBRARY: it registers no route. It requires `admin-ui/admin.ts` for the
// escaper and `common/pqc_support.ts` for the sentence.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PqcBadge` takes the logger, the console's escaper and note drawer,
// and `pqc_support` through its constructor. The module still exports `WORDS`
// and its three functions from a TRANSITIONAL instance at the bottom, for
// `admin-ui/certificate_dialog.ts`, `admin-ui/crypto_metadata.ts`,
// `admin-ui/pki_admin.ts` and the test; `PqcBadge` is exported beside them
// for the composition root.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({
  name: 'pqc_badge',
  level: config.value('global.logLevel')
});

import admin = require('./admin');
import pqcSupport = require('../common/pqc_support');

type PqcKind = 'pq' | 'composite' | 'kem' | 'hybrid';

// What `badge()` reads of a classification: `pqc_support.of()`'s answer, or
// a hand-built one for the legend.
interface PqcInfo {
  kind?: string;
  label?: string;
  standard?: string;
  [key: string]: any;
}

interface PqcBadgeDeps {
  log: { debug(message: string): void };
  // The console's HTML escaper, `admin.esc`.
  esc: (value: any) => string;
  // The console's collapsible note, `admin.note`.
  note: (html: string, summary?: string) => string;
  pqcSupport: {
    sentence(info: any): string;
    of(options: any): any;
  };
}

const WORDS: Record<PqcKind, string> = {
  pq: 'PQC', composite: 'PQC+', kem: 'PQC KEM', hybrid: 'PQC alt'
};

// Nine points on a 3x3 grid and the lines between them. `currentColor`, so the
// icon takes the badge's colour.
const LATTICE = '<svg width="12" height="12" viewBox="0 0 12 12" ' +
  'aria-hidden="true" focusable="false" style="flex:0 0 auto">' +
  '<path d="M2 2H10M2 6H10M2 10H10M2 2V10M6 2V10M10 2V10" fill="none" ' +
  'stroke="currentColor" stroke-width="0.9" opacity="0.55"/>' +
  '<g fill="currentColor"><circle cx="2" cy="2" r="1.35"/>' +
  '<circle cx="6" cy="2" r="1.35"/><circle cx="10" cy="2" r="1.35"/>' +
  '<circle cx="2" cy="6" r="1.35"/><circle cx="6" cy="6" r="1.35"/>' +
  '<circle cx="10" cy="6" r="1.35"/><circle cx="2" cy="10" r="1.35"/>' +
  '<circle cx="6" cy="10" r="1.35"/><circle cx="10" cy="10" r="1.35"/></g>' +
  '</svg>';

const BASE_STYLE = 'display:inline-flex;align-items:center;gap:3px;' +
  'font-size:11px;font-weight:600;line-height:1;padding:2px 6px;' +
  'border-radius:999px;vertical-align:middle;white-space:nowrap;' +
  'margin-left:4px;';

const KIND_STYLE: Record<PqcKind, string> = {
  pq: 'background:#ece3f8;color:#4b1f7a;border:1px solid #c4a8e6;',
  composite: 'background:#ece3f8;color:#4b1f7a;border:1px solid #c4a8e6;',
  kem: 'background:#e3eef8;color:#1f4b7a;border:1px solid #a8c6e6;',
  hybrid: 'background:#ffffff;color:#5b3a82;border:1px dashed #b194d6;'
};

class PqcBadge {
  static readonly WORDS = WORDS;

  constructor(private readonly deps: PqcBadgeDeps) {
    deps.log.debug("Entering PqcBadge.constructor().");
    deps.log.debug("Leaving PqcBadge.constructor().");
  }

  // The icon for a classification, or '' where there is none — so a caller
  // can concatenate it after every row's algorithm without asking first.
  badge(info: PqcInfo | null | undefined): string {
    const { log, esc, pqcSupport } = this.deps;
    log.debug("Entering PqcBadge.badge().");
    if (!info || !WORDS[info.kind as PqcKind]) {
      log.debug("Leaving PqcBadge.badge(). Classical.");
      return '';
    }
    const kind = info.kind as PqcKind;
    const said = pqcSupport.sentence(info);
    log.debug("Leaving PqcBadge.badge(). " + kind);
    return '<span class="pqc-badge pqc-' + esc(kind) + '" role="img" ' +
      'aria-label="' + esc(said) + '" title="' + esc(said) + '" style="' +
      BASE_STYLE + KIND_STYLE[kind] + '">' + LATTICE +
      '<span aria-hidden="true">' + esc(WORDS[kind]) + '</span></span>';
  }

  // The icon for a key given in any of its spellings — `pqcSupport.of()`'s
  // arguments — which is what a row usually has to hand.
  badgeFor(options: any): string {
    const { log, pqcSupport } = this.deps;
    log.debug("Entering PqcBadge.badgeFor().");
    log.debug("Leaving PqcBadge.badgeFor().");
    return this.badge(pqcSupport.of(options));
  }

  // The key a page draws once, above its tables: what each of the four marks
  // means, drawn with the marks themselves so the legend cannot drift from
  // them.
  legend(): string {
    const { log, note } = this.deps;
    const self = this;
    log.debug("Entering PqcBadge.legend().");
    const sample = function (kind: string, label: string,
                             standard: string): string {
      log.debug("Entering sample().");
      log.debug("Leaving sample().");
      return self.badge({ kind: kind, label: label, standard: standard });
    };
    log.debug("Leaving PqcBadge.legend().");
    return note(
      '<strong>' + sample('pq', 'ML-DSA-65', 'FIPS 204') + ' marks a key ' +
      'pair ' +
      'that uses a post-quantum algorithm</strong> — ML-DSA or SLH-DSA. ' +
      sample('composite', 'ML-DSA-44 + Ed25519',
             'draft-ietf-lamps-pq-composite-sigs') + ' is a COMPOSITE: one ' +
      'key ' +
      'with a post-quantum half and a classical half, both of which must ' +
      'verify. ' + sample('kem', 'ML-KEM-768', 'FIPS 203') + ' is a ' +
      'post-quantum key-ESTABLISHMENT key, which signs nothing. ' +
      sample('hybrid', 'alternative ML-DSA-65 key',
             'X.509 (2019) clause 9.8') + ' is a CLASSICAL key whose ' +
      'certificate also carries an alternative post-quantum key — the key ' +
      'itself is not post-quantum. Hover an icon for the algorithm. A key ' +
      'with ' +
      'no icon is classical (RSA, ECDSA or EdDSA). What decides it is the ' +
      'key\'s own algorithm, not the signature on its certificate: an ML-DSA ' +
      'key certified by an RSA CA is marked, and an RSA key certified by an ' +
      'ML-DSA CA is not.',
      'Post-quantum key pairs');
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules,
// as the composition root will build one.
const pqcBadge = new PqcBadge({
  log: log,
  esc: admin.esc,
  note: admin.note,
  pqcSupport: pqcSupport
});

export = {
  PqcBadge: PqcBadge,
  WORDS: WORDS,
  badge: pqcBadge.badge.bind(pqcBadge) as PqcBadge['badge'],
  badgeFor: pqcBadge.badgeFor.bind(pqcBadge) as PqcBadge['badgeFor'],
  legend: pqcBadge.legend.bind(pqcBadge) as PqcBadge['legend']
};
