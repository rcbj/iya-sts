// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_outcome.ts
//
// ---------------------------------------------------------------------------
// THE ONE RENDERER OF AN ERROR OR OUTCOME PAGE (#580, 2026-10-12).
//
// #580's second step: the pages of this service's own flows that only SAY
// something — a refusal that ends the flow, a page that is not there — are
// drawn by one function rather than by each family's copy. A page in this
// shape is a heading, what was refused (`.bad`), the sentence that says
// why (a plain paragraph, or the `.err` box a sign-in step draws), notes
// under it (`.meta`) and the ways on, in that order, and nothing else:
//
//   * the federation pages' refusals and their two "not here" pages
//     (`federation/web_federation_views.ts`, #580);
//   * the emailed factor's `end` page (`authn/web_authn_email.ts`, #573),
//     byte for byte what it drew before.
//
// WORDS ARE THE CALLER'S. A refusal's are English (#539's decision 6) and
// arrive as TEXT, escaped here; `notes` are MARKUP the caller built (from a
// catalog, or English with a `<code>` in it) and are put in as they are.
// The ids are the caller's too, since tests and the runtime find elements
// by them.
//
// A `web_` MODULE: it requires nothing and logs nothing.
// ---------------------------------------------------------------------------

/**
 * What an outcome page says.
 */
interface Outcome {
  // The heading, as text.
  heading: string;
  // What was refused, as text: a `.bad` paragraph under the heading.
  what?: string;
  // Why, as text.
  why?: string;
  // How `why` is drawn: a plain paragraph (`plain`, the default) or the
  // sign-in steps' `.err` box (`err`).
  whyTone?: 'plain' | 'err';
  // The elements' ids, where the caller's tests or runtime need them.
  ids?: { what?: string; why?: string; links?: string };
  // Notes under it, as MARKUP, each a `.meta` paragraph.
  notes?: string[];
  // The ways on: `{ href, label, id? }`, the label as text, one line.
  links?: Array<{ href: string; label: string; id?: string }>;
}

/**
 * Draws an error or outcome page. A static utility class.
 */
class WebOutcome {
  /**
   * Draws an outcome page's body.
   *
   * @param o - what it says
   * @returns the markup
   */
  static draw(o: Outcome): string {
    const esc = WebOutcome.esc;
    const ids = o.ids || {};
    const idOf = function (id?: string): string {
      return id ? ' id="' + esc(id) + '"' : '';
    };
    const links = (o.links || []).map(function (one) {
      return '<a href="' + esc(one.href) + '"' + idOf(one.id) + '>' +
        esc(one.label) + '</a>';
    });
    return '<h1>' + esc(o.heading) + '</h1>' +
      (o.what ? '<p class="bad"' + idOf(ids.what) + '>' + esc(o.what) +
                '</p>' : '') +
      (o.why
        ? (o.whyTone === 'err'
            ? '<div class="err"' + idOf(ids.why) + '>' + esc(o.why) +
              '</div>'
            : '<p' + idOf(ids.why) + '>' + esc(o.why) + '</p>')
        : '') +
      (o.notes || []).map(function (note: string): string {
        return '<p class="meta">' + note + '</p>';
      }).join('') +
      (links.length ? '<p' + idOf(ids.links) + '>' + links.join(' · ') +
                      '</p>' : '');
  }

  /**
   * Escapes text for HTML, as `Html.esc()` does.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

export = WebOutcome;
