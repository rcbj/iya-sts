// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_self_issued.ts
//
// ---------------------------------------------------------------------------
// `/portal/self-issued`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/self-issued` (`portal_self_issued.ts`): the enrolled SIOPv2
// subjects, a Remove button each, a Prefer button on each proved DID (#693),
// and the link that enrols one by proving it at `/authn/wallet` — a plain
// link, because that is a sign-in, not a form. And `/portal/self-issued/did`
// (2026-10-20), one enrolled did:jwk's or did:key's resolved document.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/self-issued';
// The DID document of one enrolled did:jwk or did:key (2026-10-20).
const DID_PATH = PATH + '/did';
// What a subject's one-line cell shows of it: its start and its end.
const MIDDLE_HEAD = 13;
const MIDDLE_TAIL = 7;

/**
 * `/portal/self-issued`. A static utility class.
 */
class SelfIssuedPages {
  /**
   * The page's body.
   *
   * @param view - `GET /account-api/self-issued`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    // A REFUSAL (STS-PORTAL-0616, no entry for the person): the runtime says
    // why above the page, and the page draws no list — an empty one would
    // read as "none enrolled", which is what the refusal exists to avoid.
    if (view.ok === false) {
      return '<div class="card"><h2>' + t.html('portalSelfIssued.heading') +
        '</h2><p class="sub">' + t.html('portalSelfIssued.sub') +
        '</p></div>';
    }
    const held: Json[] = view.subjects || [];
    const rows = held.map(function (one: Json) {
      // The enrolment instant in the reader's own way of writing a date
      // (#539).
      // ONE LINE, AND THE WHOLE VALUE ON HOVER (2026-10-20, rcbj): a
      // did:jwk is two hundred characters, wrapped it took a dozen lines,
      // so the cell shows its START AND ITS END (`middle()`) and its
      // `title` is the value; the CSS ellipsis is only the guard on a
      // screen too narrow even for that. Under it, where there is one, the
      // link to the DID's document (`didLink()`).
      return '<tr><td><code class="oneline subject" title="' +
        kit.esc(one.subject) + '">' +
        kit.esc(SelfIssuedPages.middle(one.subject)) + '</code>' +
        SelfIssuedPages.didLink(one, ctx) + '</td><td>' +
        kit.esc(one.label || '') + '</td><td>' +
        kit.esc(one.enrolledAt ? t.date(one.enrolledAt) : '') +
        (one.by ? ' (' + kit.esc(one.by) + ')' : '') + '</td><td>' +
        // How it was enrolled (#693): proved with the person's wallet, or
        // by an administrator, unproven.
        (one.proof === 'wallet' ? t.html('portalSelfIssued.proofWallet')
                                : t.html('portalSelfIssued.proofAdmin')) +
        '</td><td>' + SelfIssuedPages.locationCell(one.location, t) +
        '</td><td>' + SelfIssuedPages.preferCell(one, t) + '</td><td>' +
        '<form method="post" action="' + kit.esc(PATH) + '">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="subject" value="' + kit.esc(one.subject) +
        '"><button class="danger" type="submit">' +
        t.html('portalSelfIssued.remove') + '</button></form></td></tr>';
    });
    return (view.notice ? '<div class="ok">' + kit.esc(view.notice) +
                          '</div>' : '') +
      '<div class="card"><h2>' + t.html('portalSelfIssued.heading') +
      '</h2><p class="sub">' + t.html('portalSelfIssued.sub') + '</p>' +
      (held.length
        // `grid`: a heading ROW over seven columns, not the portal's
        // name-and-value table whose first `th` takes a third of the width;
        // `scrollx` keeps it inside the card on a screen too narrow for
        // even the cut-down cells.
        ? '<div class="scrollx"><table class="grid"><tr><th>' +
          t.html('portalSelfIssued.subject') +
          '</th><th>' + t.html('portalSelfIssued.label') + '</th><th>' +
          t.html('portalSelfIssued.enrolled') + '</th><th>' +
          t.html('portalSelfIssued.how') + '</th><th>' +
          t.html('portalSelfIssued.location') + '</th><th>' +
          t.html('portalSelfIssued.preferred') + '</th><th></th></tr>' +
          rows.join('') + '</table></div>' +
          // What the mark is for (#693), and whether this realm releases it.
          '<p class="sub" id="siop-preferred-note">' +
          t.html(view.didClaim ? 'portalSelfIssued.preferredNoteOn'
                               : 'portalSelfIssued.preferredNoteOff') +
          '</p>'
        : '<p id="siop-none">' + t.html('portalSelfIssued.none') + '</p>') +
      (view.enabled
        ? '<p><a class="button" id="siop-enrol" href="/authn/wallet?siop=1' +
          '&amp;enrol=1' +
          // This tab's account, so a browser holding several sessions
          // enrols for this one (`portal_self_issued.ts`, `loginHint`).
          (view.loginHint ? '&amp;login_hint=' +
            kit.esc(encodeURIComponent(String(view.loginHint))) : '') +
          '">' + t.html('portalSelfIssued.enrol') +
          '</a></p><p class="sub">' + t.html('portalSelfIssued.enrolNote') +
          ' ' + t.html('portalSelfIssued.reprove') + '</p>'
        : '<p class="sub" id="siop-off">' + t.html('portalSelfIssued.off') +
          '</p>') + '</div>';
  }

  /**
   * A long value cut in its MIDDLE for its one-line cell (2026-10-20, rcbj
   * on 8081): every thumbprint subject starts `urn:ietf:params:oauth:` and
   * every did:jwk `did:jwk:eyJ`, so an end ellipsis drew rows that could
   * not be told apart. The first 13 characters, `…`, and the last 7 — 21,
   * what the column's 13em holds in its monospace — or the value itself
   * where it is no longer.
   *
   * @param value - the value
   * @returns the text to show
   */
  static middle(value: unknown): string {
    const text = String(value === undefined || value === null ? '' : value);
    if (text.length <= MIDDLE_HEAD + MIDDLE_TAIL + 1) {
      return text;
    }
    return text.slice(0, MIDDLE_HEAD) + '\u2026' + text.slice(-MIDDLE_TAIL);
  }

  /**
   * The link to a row's DID document, on a line under the subject, or ''
   * (2026-10-20, rcbj: "a simple hyperlink with a mouseover that shows the
   * full URL", opening "a new tab that displays the DID"). A did:web's is
   * its PUBLISHED document, at the address the server's view names
   * (`didDocumentUrl`, `Siop.didWebUrl()`); a did:jwk's or did:key's is
   * `/portal/self-issued/did`, the document resolved from the identifier
   * (`didResolved`). A thumbprint has none. The `title` is the whole
   * address — for the portal's own page, absolute and in the realm, since
   * a title is not rewritten as an `href` is (`realmLinks()`). A new tab:
   * the runtime leaves a `_blank` link to the browser, and the tab signs in
   * from the browser's session as any fresh portal tab does.
   *
   * @param one - the row
   * @param ctx - the render context (`origin`, `prefix`)
   * @returns the HTML
   */
  static didLink(one: Json, ctx: Json): string {
    let href = '';
    let full = '';
    if (one.didDocumentUrl) {
      href = String(one.didDocumentUrl);
      full = href;
    } else if (one.didResolved) {
      href = DID_PATH + '?subject=' + encodeURIComponent(String(one.subject));
      full = String(ctx.origin || '') + String(ctx.prefix || '') + href;
    }
    if (!href) {
      return '';
    }
    return '<div class="didlink"><a href="' + kit.esc(href) + '" title="' +
      kit.esc(full) + '" target="_blank" rel="noopener noreferrer">' +
      ctx.t.html('portalSelfIssued.didLink') + '</a></div>';
  }

  /**
   * `/portal/self-issued/did`'s body (2026-10-20): one enrolled did:jwk's or
   * did:key's DID document, RESOLVED FROM THE IDENTIFIER — the method makes
   * the identifier its own document, so nothing is published and nothing
   * is fetched — from `GET /account-api/self-issued/did`. With no subject
   * named, or a refusal (the runtime says why above the page), a pointer
   * back to the list and no document.
   *
   * @param view - the operation's answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static renderDid(view: Json, ctx: Json): string {
    const t = ctx.t;
    const back = '<p><a href="' + kit.esc(PATH) + '">' +
      t.html('portalSelfIssued.didBack') + '</a></p>';
    const head = '<div class="card didpage"><h2>' +
      t.html('portalSelfIssued.didHeading') + '</h2>';
    if (view.ok === false || !view.subject || !view.document) {
      return head + '<p class="sub" id="siop-did-none">' +
        t.html('portalSelfIssued.didChoose') + '</p>' + back + '</div>';
    }
    return head + '<p><code id="siop-did">' + kit.esc(view.subject) +
      '</code></p><p class="sub">' +
      t.html('portalSelfIssued.didResolvedNote') + '</p><pre class="diddoc" id="siop-did-document">' +
      kit.esc(JSON.stringify(view.document, null, 2)) + '</pre>' + back +
      '</div>';
  }

  /**
   * One row's Location cell (2026-10-20): where the key came from, as ONE
   * short line — a web wallet's host, an app's reported name, or a short
   * label — with the whole of it in the `title`: the web wallet's address,
   * the app's full reported name, or a sentence saying what the label
   * means. Every value is escaped, the app's name above all: it is what a
   * wallet said about itself.
   *
   * @param location - the row's `location`, or null
   * @param t - the translator
   * @returns the HTML
   */
  static locationCell(location: Json, t: Json): string {
    const kind = location && location.kind ? String(location.kind) : '';
    const value = location && location.value ? String(location.value) : '';
    let shown = '';
    let tip = '';
    if (kind === 'web') {
      shown = SelfIssuedPages.hostOf(value) ||
        t.text('portalSelfIssued.locationWeb');
      tip = t.text('portalSelfIssued.locationWebTip', { url: value });
    } else if (kind === 'app') {
      shown = value || t.text('portalSelfIssued.locationAppUnnamed');
      tip = value ? t.text('portalSelfIssued.locationAppTip', { name: value })
                  : t.text('portalSelfIssued.locationAppUnnamedTip');
    } else if (kind === 'dc_api') {
      shown = t.text('portalSelfIssued.locationDcApi');
      tip = value
        ? t.text('portalSelfIssued.locationDcApiOriginTip', { origin: value })
        : t.text('portalSelfIssued.locationDcApiTip');
    } else if (kind === 'admin') {
      shown = t.text('portalSelfIssued.locationAdmin');
      tip = t.text('portalSelfIssued.locationAdminTip');
    } else {
      shown = t.text('portalSelfIssued.locationNone');
      tip = t.text('portalSelfIssued.locationNoneTip');
    }
    return '<span class="oneline location" title="' + kit.esc(tip) + '">' +
      kit.esc(shown) + '</span>';
  }

  /**
   * A web wallet's host and port, for its one-line cell; '' when the
   * address does not parse.
   *
   * @param url - the address
   * @returns the host
   */
  static hostOf(url: string): string {
    try {
      return new URL(url).host;
    } catch (e) {
      // Not an address after all: the cell says "web wallet", and the
      // tooltip still carries what was stored.
      return '';
    }
  }

  /**
   * One row's preferred-DID cell (#693): the mark and a button that clears
   * it, a button that sets it on a proved DID, and nothing on a subject that
   * cannot be preferred — one an administrator added, or a thumbprint.
   *
   * @param one - the row
   * @param t - the translator
   * @returns the HTML
   */
  static preferCell(one: Json, t: Json): string {
    const form = function (action: string, label: string): string {
      return '<form method="post" action="' + kit.esc(PATH) + '">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="subject" value="' + kit.esc(one.subject) +
        '"><button type="submit">' + label + '</button></form>';
    };
    if (one.preferred) {
      return '<strong>' + t.html('portalSelfIssued.isPreferred') +
        '</strong> ' + form('unprefer', t.html('portalSelfIssued.unprefer'));
    }
    if (one.proof === 'wallet' && /^did:/.test(String(one.subject))) {
      return form('prefer', t.html('portalSelfIssued.prefer'));
    }
    return '';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/self-issued',
      render: SelfIssuedPages.render },
    // A SUB-PAGE, not a column entry: the frame heads it and marks the
    // column as its parent's (`PortalShell.navPathFor()`).
    { path: DID_PATH, operation: '/account-api/self-issued/did',
      render: SelfIssuedPages.renderDid }
  ];
}

export = SelfIssuedPages;
