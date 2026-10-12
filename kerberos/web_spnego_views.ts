// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spnego_views.ts
//
// ---------------------------------------------------------------------------
// THE SPNEGO DEMONSTRATION PAGES' RENDERERS (#583, 2026-10-12).
//
// Each page is drawn from the view its shell carried (`spnego_pages.ts`,
// `data-sts-state`), by the view's `kind`:
//
//   * `advert` — `GET /spnego`: what is protected, which service principal
//     it is behind, the mechanisms, the sign-in door beside it, and the
//     three knobs that make the negotiation fail on purpose;
//   * `verdict` — the BODY of `GET /spnego/protected`'s answer, over
//     `spnego_exchange.js`'s verdict: a heading per outcome, what it means,
//     and the acceptor's checks. The answer's status and its
//     `WWW-Authenticate` are the exchange's and are not drawn from here —
//     RFC 4559 is untouched (#569's rule).
//
// These are `spnego.js`'s `GET /spnego` page, `acceptedPage()`,
// `refusalPage()` and `detailFor()`, moved to the browser; one case per
// outcome, and a verdict this page does not know falls into the REJECTED
// page, as `refusalPage()`'s did. The page's own words are the
// `spnegoPages` catalogs'. WHAT THE ACCEPTOR SAYS IS DATA, and English: a
// verdict's reason, the section 5 requirement and the checks table, which is
// a diagnostic as the sign-in's is (#575).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebOutcome = require('../common/web_outcome');

type Json = any;

const esc = WebOutcome.esc;

const ADVERT_PATH = '/spnego';
const PROTECTED_PATH = '/spnego/protected';
const SIGN_IN_PATH = '/authn/spnego';

// The heading and the title each verdict code gets, by their catalog keys;
// anything not here is a REJECT, and they share one page (`spnego.js`'s
// `HEADINGS`). Every key whole, so `tests/i18n_catalogs.js` E finds each.
const HEADINGS: Record<string, [string, string]> = {
  'no-authorization': ['spnegoPages.verdict.noAuthorization.heading',
                       'spnegoPages.verdict.noAuthorization.title'],
  'wrong-scheme': ['spnegoPages.verdict.wrongScheme.heading',
                   'spnegoPages.verdict.wrongScheme.title'],
  'empty-token': ['spnegoPages.verdict.emptyToken.heading',
                  'spnegoPages.verdict.emptyToken.title'],
  'no-mech-token': ['spnegoPages.verdict.noMechToken.heading',
                    'spnegoPages.verdict.noMechToken.title'],
  'ticket-refused': ['spnegoPages.verdict.ticketRefused.heading',
                     'spnegoPages.verdict.ticketRefused.title'],
  'request-mic': ['spnegoPages.verdict.requestMic.heading',
                  'spnegoPages.verdict.requestMic.title'],
  'accepted': ['spnegoPages.verdict.accepted.heading',
               'spnegoPages.verdict.accepted.title']
};
const REJECTED: [string, string] = ['spnegoPages.verdict.rejected.heading',
                                    'spnegoPages.verdict.rejected.title'];

/**
 * The SPNEGO demonstration pages' renderers. A static utility class.
 */
class WebSpnegoViews {
  /**
   * Draws a view by its kind.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    if (v.kind === 'advert') {
      return WebSpnegoViews.advert(v, ctx.t);
    }
    if (v.kind === 'verdict') {
      return v.ok ? WebSpnegoViews.accepted(v, ctx.t)
                  : WebSpnegoViews.refused(v, ctx.t);
    }
    return WebOutcome.draw({ heading: 'This page could not be drawn',
      why: 'The service sent a view this page does not know (' +
           String(v.kind) + ').', whyTone: 'err' });
  }

  /**
   * The document's title for a view, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    const kind = String((view && view.kind) || '');
    if (kind === 'advert') {
      return ctx.t.text('spnegoPages.advert.title');
    }
    if (kind === 'verdict') {
      return ctx.t.text(WebSpnegoViews.headingKeys(view)[1]);
    }
    return 'SPNEGO';
  }

  /**
   * A verdict's heading and title keys: its code's, or the REJECTED page's.
   *
   * @param v - the `verdict` view
   * @returns `[heading key, title key]`
   */
  static headingKeys(v: Json): [string, string] {
    const code = String((v && v.code) || '');
    return Object.prototype.hasOwnProperty.call(HEADINGS, code)
      ? HEADINGS[code] : REJECTED;
  }

  /**
   * An object identifier in `<code>`, with its name where it has one.
   *
   * @param oid - the identifier
   * @param name - its name, or ''
   * @returns the markup
   */
  static mech(oid: Json, name: Json): string {
    return '<code>' + esc(oid) + '</code>' +
      (name ? ' (' + esc(name) + ')' : '');
  }

  /**
   * The acceptor's checks: English, a diagnostic (`spnego.js`'s
   * `checksTable()`).
   *
   * @param checks - `[{ name, ok, detail }]`
   * @returns the table
   */
  static checks(checks: Json): string {
    const rows = (Array.isArray(checks) ? checks : [])
      .map(function (c: Json): string {
        return '<tr><td>' + esc(c.name) + '</td><td class="' +
          (c.ok ? 'pass">passed' : 'fail">FAILED') + '</td><td>' +
          esc(c.detail == null ? '' : String(c.detail)) + '</td></tr>';
      }).join('');
    return '<table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' +
      rows + '</table>';
  }

  /**
   * `GET /spnego`: the advertisement.
   *
   * @param v - the `advert` view
   * @param t - the translator
   * @returns the body
   */
  static advert(v: Json, t: Json): string {
    const mechanisms = (Array.isArray(v.mechanisms) ? v.mechanisms : [])
      .map(function (one: Json): string {
        return WebSpnegoViews.mech(one.oid, one.name);
      }).join('<br>');
    const knob = function (query: string, said: string): string {
      return '<li><code>?' + query + '</code> ' + said + '</li>';
    };
    return '<h1>' + t.html('spnegoPages.advert.heading') +
      '</h1><p class="sub">' + t.html('spnegoPages.advert.lead') +
      '</p><p><a href="' + PROTECTED_PATH + '"><strong>' + PROTECTED_PATH +
      '</strong></a> ' + t.html('spnegoPages.advert.challenge') + '</p><h2>' +
      t.html('spnegoPages.advert.signInHeading') + '</h2><p><a href="' +
      SIGN_IN_PATH + '"><strong>' + SIGN_IN_PATH + '</strong></a> ' +
      t.html('spnegoPages.advert.signIn') + '</p><p>' +
      t.html('spnegoPages.advert.difference') +
      (v.signInEnabled ? '' : ' ' + t.html('spnegoPages.advert.off')) + ' ' +
      t.html('spnegoPages.advert.knobsOwn') + '</p><h2>' +
      t.html('spnegoPages.advert.needs') + '</h2><table><tr><th>' +
      t.html('spnegoPages.advert.thing') + '</th><th>' +
      t.html('spnegoPages.advert.value') + '</th></tr><tr><td>' +
      t.html('spnegoPages.advert.spn') + '</td><td><code>' +
      esc(v.servicePrincipalName) + '</code></td></tr><tr><td>' +
      t.html('spnegoPages.advert.realm') + '</td><td><code>' +
      esc(v.realm) + '</code></td></tr><tr><td>' +
      t.html('spnegoPages.advert.scheme') + '</td><td><code>' +
      esc(v.scheme || 'Negotiate') + '</code></td></tr><tr><td>' +
      t.html('spnegoPages.advert.mechanisms') + '</td><td>' + mechanisms +
      '</td></tr></table><p>' + t.html('spnegoPages.advert.notInExchange') +
      '</p><h2>' + t.html('spnegoPages.advert.misconfig') + '</h2><p>' +
      t.html('spnegoPages.advert.misconfigLead') + '</p><ul>' +
      knob('mic=require', t.html('spnegoPages.advert.mic')) +
      knob('mech=none', t.html('spnegoPages.advert.mech')) +
      knob('mutual=off', t.html('spnegoPages.advert.mutual')) +
      '</ul><p class="sub"><a href="' + ADVERT_PATH + '?format=json">' +
      t.html('spnegoPages.advert.asJson') +
      '</a> · <a href="/krb5/principals">' +
      t.html('spnegoPages.advert.principals') + '</a> · <a ' +
      'href="/admin/sts-metadata">' + t.html('spnegoPages.advert.everything') +
      '</a></p>';
  }

  /**
   * The paragraph under a refused verdict's heading, per outcome
   * (`spnego.js`'s `detailFor()`).
   *
   * @param v - the `verdict` view
   * @param t - the translator
   * @returns the markup
   */
  static detail(v: Json, t: Json): string {
    const offered: Json[] = Array.isArray(v.offered) ? v.offered : [];
    const names: Json[] = Array.isArray(v.offeredNames) ? v.offeredNames : [];
    const supported: Json[] = Array.isArray(v.supported) ? v.supported : [];
    switch (v.code) {
      case 'no-authorization':
        return '<p>' + t.html('spnegoPages.detail.noAuthorization') +
          '</p><p>' + t.html('spnegoPages.detail.noAuthorizationWork',
                             { spn: String(v.spn || '') }) + '</p>';
      case 'wrong-scheme':
        return '<div class="err">' +
          t.html('spnegoPages.detail.wrongScheme',
                 { scheme: String(v.scheme || '') }) + '</div>';
      case 'empty-token':
        return '<div class="err">' +
          t.html('spnegoPages.detail.emptyToken') + '</div>';
      case 'undecodable':
        return '<p>' + t.html('spnegoPages.detail.undecodable') + '</p>';
      case 'no-common-mechanism':
        return '<p>' + t.html('spnegoPages.detail.offered',
                              { count: offered.length }) + ' ' +
          offered.map(function (oid: Json, i: number): string {
            return WebSpnegoViews.mech(oid, names[i]);
          }).join(', ') + '. ' +
          (supported.length
            ? t.html('spnegoPages.detail.supports') + ' ' +
              supported.map(function (oid: Json): string {
                return WebSpnegoViews.mech(oid, '');
              }).join(', ') + '.'
            : t.html('spnegoPages.detail.supportsNothing')) + '</p>';
      case 'no-mech-token':
        return '<p>' + t.html('spnegoPages.detail.noMechToken',
                              { mech: String(v.selectedName || '') }) +
          '</p>';
      case 'non-kerberos-mechanism':
        return '<p>' + t.html('spnegoPages.detail.nonKerberos',
                              { mech: String(v.selected || '') }) + '</p>';
      case 'ticket-refused':
        return '<div class="err">' +
          t.html('spnegoPages.detail.ticketRefused') + '</div><p>' +
          t.html('spnegoPages.detail.ticketRefusedWhy') + '</p>';
      case 'bad-mech-list-mic':
        // TWO WORDINGS FOR ONE CODE, and the distinction is the verdict's:
        // on the first token the MIC was computed over the wrong bytes; on
        // the continuation the client got its one task wrong.
        return '<p>' + (v.continuation
          ? t.html('spnegoPages.detail.badMicContinuation')
          : t.html('spnegoPages.detail.badMic')) + '</p>';
      case 'mic-required':
        return '<p>' + esc(v.requirementReason) + '</p>';
      case 'request-mic':
        return '<p>' + t.html('spnegoPages.detail.requestMic') + '</p><p>' +
          t.html('spnegoPages.detail.requestMicAnswer') + '</p>';
      case 'no-pending-continuation':
        return '<p>' + t.html('spnegoPages.detail.noPending') + '</p>';
      case 'continuation-no-mic':
        return '<p>' + t.html('spnegoPages.detail.continuationNoMic') +
          '</p>';
      default:
        return '';
    }
  }

  /**
   * Every answer that is not the protected content
   * (`spnego.js`'s `refusalPage()`).
   *
   * @param v - the `verdict` view
   * @param t - the translator
   * @returns the body
   */
  static refused(v: Json, t: Json): string {
    const keys = WebSpnegoViews.headingKeys(v);
    const rejected = keys === REJECTED;
    // The banner is the REASON, drawn only where the heading has not said
    // it already: the bare-challenge pages put their sentence in the
    // detail, where it reads as an explanation.
    return '<h1 id="spnego-verdict">' +
      t.html(keys[0]) + '</h1>' +
      (rejected ? '<div class="err" id="spnego-reason">' + esc(v.reason) +
                  '</div>' : '') +
      WebSpnegoViews.detail(v, t) +
      (Array.isArray(v.checks)
        ? '<h2>' + t.html('spnegoPages.checked') + '</h2>' +
          WebSpnegoViews.checks(v.checks)
        : '') +
      (rejected ? '<p class="sub">' + t.html('spnegoPages.rejectedNote') +
                  '</p>' : '');
  }

  /**
   * The protected content (`spnego.js`'s `acceptedPage()`): everything on
   * it read off the verdict, including whether an AP-REP went back and
   * whether the mechanism list was protected.
   *
   * @param v - the `verdict` view
   * @param t - the translator
   * @returns the body
   */
  static accepted(v: Json, t: Json): string {
    const client = String(v.client || '') ||
      t.text('spnegoPages.accepted.unknown');
    return '<h1 id="spnego-verdict">' +
      t.html('spnegoPages.verdict.accepted.heading') +
      '</h1><div class="ok" id="spnego-client">' +
      t.html('spnegoPages.accepted.as',
             { client: client, spn: String(v.spn || '') }) + '</div><p>' +
      t.html('spnegoPages.accepted.content') + '</p><table><tr><th>' +
      t.html('spnegoPages.accepted.what') + '</th><th>' +
      t.html('spnegoPages.accepted.value') + '</th></tr><tr><td>' +
      t.html('spnegoPages.accepted.client') + '</td><td><code>' +
      esc(client) + '</code></td></tr><tr><td>' +
      t.html('spnegoPages.accepted.mechanism') + '</td><td>' +
      WebSpnegoViews.mech(v.selected, v.selectedName) + '</td></tr><tr><td>' +
      t.html('spnegoPages.accepted.negotiation') + '</td><td>' +
      (v.rawKerberos ? t.html('spnegoPages.accepted.bare')
                     : t.html('spnegoPages.accepted.spnego')) +
      '</td></tr><tr><td>mechListMIC</td><td>' +
      (v.micVerified
        ? '<span class="pass">' + t.html('spnegoPages.accepted.verified') +
          '</span>'
        : '<span class="fail">' + t.html('spnegoPages.accepted.notSent') +
          '</span> — ' + esc(v.requirementReason)) +
      '</td></tr><tr><td>' + t.html('spnegoPages.accepted.mutual') +
      '</td><td>' +
      (v.mutual
        ? t.html('spnegoPages.accepted.mutualYes')
        : v.mutualOff
          ? '<span class="fail">' + t.html('spnegoPages.accepted.none') +
            '</span> — ' + t.html('spnegoPages.accepted.mutualOff')
          : t.html('spnegoPages.accepted.mutualNone')) + '</td></tr>' +
      (v.micNote ? '<tr><td>' + t.html('spnegoPages.accepted.note') +
                   '</td><td>' + esc(v.micNote) + '</td></tr>' : '') +
      '</table>' +
      (Array.isArray(v.checks)
        ? '<h2>' + t.html('spnegoPages.checked') + '</h2>' +
          WebSpnegoViews.checks(v.checks)
        : '');
  }
}

export = WebSpnegoViews;
