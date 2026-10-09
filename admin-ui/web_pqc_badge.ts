// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pqc_badge.ts
//
// ---------------------------------------------------------------------------
// THE POST-QUANTUM ICON, AS A RENDERER A BROWSER CAN LOAD (#446, 2026-10-05).
//
// `admin-ui/pqc_badge.ts` argues the icon — a lattice, four kinds, four words,
// no script, stylesheet or image request — and this is its drawing, moved so
// that a page drawn in the browser marks a key exactly as the server-rendered
// console does. What it draws from is a CLASSIFICATION (`kind`, `label`,
// `standard`), which `common/pqc_support.ts` makes on the server from a
// certificate or an algorithm name; a view carries it, and a renderer never
// parses a certificate.
//
// The SENTENCE the tooltip and the accessible name carry is here too, for
// the same reason: `pqc_support.sentence()` calls this one.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import webMessages = require('./web_messages');

type PqcKind = 'pq' | 'composite' | 'kem' | 'hybrid';

// What `badge()` reads of a classification: `pqc_support.of()`'s answer, or
// a hand-built one for the legend.
interface PqcInfo {
  kind?: string;
  label?: string;
  standard?: string;
  [key: string]: any;
}

/**
 * The word drawn beside the icon for each kind: `PQC`, `PQC+` for a composite,
 * `PQC KEM` and `PQC alt` for a classical key with an alternative post-quantum
 * key.
 */
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

/**
 * Draws the post-quantum icon and its legend from a classification.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PqcBadgeView {
  /**
   * The word beside the icon for each kind.
   */
  static readonly WORDS = WORDS;

  // The sentence the icon's tooltip and accessible name carry.
  /**
   * Returns the sentence the icon's tooltip and accessible name carry.
   *
   * @param info - a classification
   * @param t - the page's translator (#539); the default (English in node)
   *   when absent, which is what the server-side callers —
   *   `common/pqc_support.ts`, `admin-ui/pqc_badge.ts` — draw with
   * @returns the sentence, or '' for none
   */
  static sentence(info: PqcInfo | null | undefined, t?: any): string {
    if (!info) {
      return '';
    }
    t = t || webMessages.WebTranslator.fallback();
    // Plain text, not markup: the caller escapes it into an attribute. The
    // label and the standard are names, so they go in as parameters.
    const label = { label: info.label };
    const text = ({
      pq: t.text('consolePqcBadge.sentencePq', label),
      composite: t.text('consolePqcBadge.sentenceComposite', label),
      kem: t.text('consolePqcBadge.sentenceKem', label),
      hybrid: t.text('consolePqcBadge.sentenceHybrid', label)
    } as Record<string, string>)[String(info.kind)] ||
      t.text('consolePqcBadge.sentenceOther', label);
    return text + (info.standard ? ' (' + info.standard + ')' : '');
  }

  // The icon for a classification, or '' where there is none — so a caller
  // can concatenate it after every row's algorithm without asking first.
  /**
   * Draws the icon for a classification.
   *
   * @param info - a classification of a key
   * @param t - the page's translator (#539); the default when absent
   * @returns the badge's markup, or '' where there is none
   */
  static badge(info: PqcInfo | null | undefined, t?: any): string {
    const esc = kit.esc;
    if (!info || !WORDS[info.kind as PqcKind]) {
      return '';
    }
    const kind = info.kind as PqcKind;
    const said = PqcBadgeView.sentence(info, t);
    return '<span class="pqc-badge pqc-' + esc(kind) + '" role="img" ' +
      'aria-label="' + esc(said) + '" title="' + esc(said) + '" style="' +
      BASE_STYLE + KIND_STYLE[kind] + '">' + LATTICE +
      '<span aria-hidden="true">' + esc(WORDS[kind]) + '</span></span>';
  }

  // The key a page draws once, above its tables: what each of the four marks
  // means, drawn with the marks themselves so the legend cannot drift from
  // them.
  /**
   * Draws the key a page shows once above its tables: what each of the four
   * marks means, drawn with the marks themselves.
   *
   * @param t - the page's translator (#539); the default when absent
   * @returns the legend's markup
   */
  static legend(t?: any): string {
    t = t || webMessages.WebTranslator.fallback();
    const sample = function (kind: string, label: string,
                             standard: string): string {
      return PqcBadgeView.badge({ kind: kind, label: label,
                                  standard: standard }, t);
    };
    // Each mark is markup a message cannot carry, so the sentences are cut
    // where a mark stands and the marks are put back here, in order. The
    // first sentence's <strong> spans the mark, so it is opened and closed
    // in code around it.
    return kit.note(
      '<strong>' + sample('pq', 'ML-DSA-65', 'FIPS 204') +
      t.html('consolePqcBadge.legendPq') + '</strong>' +
      t.html('consolePqcBadge.legendPqAfter') +
      sample('composite', 'ML-DSA-44 + Ed25519',
             'draft-ietf-lamps-pq-composite-sigs') +
      t.html('consolePqcBadge.legendComposite') +
      sample('kem', 'ML-KEM-768', 'FIPS 203') +
      t.html('consolePqcBadge.legendKem') +
      sample('hybrid', t.text('consolePqcBadge.legendHybridLabel'),
             'X.509 (2019) clause 9.8') +
      t.html('consolePqcBadge.legendHybrid'),
      t.html('consolePqcBadge.legendTitle'));
  }
}

export = PqcBadgeView;
