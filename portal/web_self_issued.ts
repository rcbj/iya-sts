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
// And since #1291 the DIDs this realm PUBLISHES for the person: *Publish a
// DID*, each one's document, custody, versions and state, *Add key*,
// *Rotate key* and *Deactivate*, and a downloaded key's one-time pane.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/self-issued';
// A published DID's acts (#1291).
const DIDS_PATH = PATH + '/dids';
// Where a wallet round trip starts.
const WALLET = '/authn/wallet?siop=1&enrol=1';
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
        // by an administrator, unproven — or a DID this realm published
        // with a key it keeps or handed over (#1291).
        SelfIssuedPages.proofText(one.proof, t) +
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
          SelfIssuedPages.turnOnNote(view.turnOn, t) + '</p>') + '</div>' +
      SelfIssuedPages.publishedCard(view, ctx);
  }

  /**
   * How a subject was enrolled, in words: proved with a wallet, added by
   * an administrator, or a DID this realm published with a key it keeps or
   * handed over (#1291).
   *
   * @param proof - the row's `proof`
   * @param t - the translator
   * @returns the HTML
   */
  static proofText(proof: string, t: Json): string {
    if (proof === 'wallet') {
      return t.html('portalSelfIssued.proofWallet');
    }
    if (proof === 'realm') {
      return t.html('portalSelfIssued.proofRealm');
    }
    if (proof === 'issued') {
      return t.html('portalSelfIssued.proofIssued');
    }
    return t.html('portalSelfIssued.proofAdmin');
  }

  /**
   * A wallet round trip's link for a published DID's act (#1291), in this
   * tab's account.
   *
   * @param act - the `did_act` marker
   * @param view - the page's view, for `loginHint`
   * @returns the href, escaped
   */
  static walletLink(act: string, view: Json): string {
    return kit.esc(WALLET + '&did_act=' + encodeURIComponent(act) +
      (view.loginHint ? '&login_hint=' +
        encodeURIComponent(String(view.loginHint)) : ''));
  }

  /**
   * One button posting a published DID's act (#1291).
   *
   * @param action - the act
   * @param rid - the DID's id, or ''
   * @param label - the button's text, already HTML
   * @param cls - the button's class, or ''
   * @returns the HTML
   */
  static didForm(action: string, rid: string, label: string,
                 cls: string): string {
    return '<form method="post" action="' + kit.esc(DIDS_PATH) + '">' +
      '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
      (rid ? '<input type="hidden" name="rid" value="' + kit.esc(rid) +
             '">' : '') +
      '<button type="submit"' + (cls ? ' class="' + cls + '"' : '') + '>' +
      label + '</button></form>';
  }

  /**
   * The DIDs this realm publishes for the person (#1291): the custody, the
   * cap, *Publish a DID*, each DID with its document, versions, state and
   * acts, and — once — a downloaded private key.
   *
   * @param view - the page's view
   * @param ctx - the render context
   * @returns the HTML, or '' where the realm publishes none and they hold
   *   none
   */
  static publishedCard(view: Json, ctx: Json): string {
    const t = ctx.t;
    const pub = view.published;
    if (!pub || (!pub.enabled && !(pub.dids || []).length)) {
      return '';
    }
    const rows = (pub.dids || []).map(function (one: Json): string {
      return SelfIssuedPages.publishedRow(one, view, t);
    });
    let publish = '';
    if (pub.enabled && pub.canPublish) {
      publish = pub.custody === 'wallet'
        ? '<p><a class="button" id="did-publish" href="' +
          SelfIssuedPages.walletLink('publish', view) + '">' +
          t.html('portalSelfIssued.pubPublish') + '</a></p>'
        : SelfIssuedPages.didForm('publish', '',
                                  t.html('portalSelfIssued.pubPublish'), '');
    }
    return SelfIssuedPages.freshPane(view, t) +
      '<div class="card" id="did-published"><h2>' +
      t.html('portalSelfIssued.pubHeading') + '</h2><p class="sub">' +
      t.html('portalSelfIssued.pubSub') + '</p>' +
      (pub.enabled
        ? '<p class="sub" id="did-custody">' +
          (pub.custody === 'realm'
            ? t.html('portalSelfIssued.pubCustodyRealm')
            : pub.custody === 'download'
              ? t.html('portalSelfIssued.pubCustodyDownload')
              : t.html('portalSelfIssued.pubCustodyWallet')) + '</p>' +
          '<p class="sub">' + t.html('portalSelfIssued.pubCap',
            { active: String(pub.active), max: String(pub.maxPerPerson) }) +
          '</p>'
        : '<p class="sub" id="did-off">' +
          t.html('portalSelfIssued.pubOff') + '</p>') +
      (rows.length
        ? '<div class="scrollx"><table class="grid"><tr><th>' +
          t.html('portalSelfIssued.pubColDid') + '</th><th>' +
          t.html('portalSelfIssued.pubColCustody') + '</th><th>' +
          t.html('portalSelfIssued.pubColVersions') + '</th><th>' +
          t.html('portalSelfIssued.pubColState') + '</th><th></th></tr>' +
          rows.join('') + '</table></div>'
        : '<p id="did-none">' + t.html('portalSelfIssued.pubNone') + '</p>') +
      publish + '</div>';
  }

  /**
   * One published DID's row (#1291).
   *
   * @param one - the DID, as the view lists it
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static publishedRow(one: Json, view: Json, t: Json): string {
    const active = one.state === 'active';
    const custody = one.custody === 'realm'
      ? t.html('portalSelfIssued.pubCustodyShortRealm')
      : one.custody === 'download'
        ? t.html('portalSelfIssued.pubCustodyShortDownload')
        : t.html('portalSelfIssued.pubCustodyShortWallet');
    const versions = (one.versions || []).map(function (v: Json): string {
      const change = v.change === 'add-key'
        ? t.html('portalSelfIssued.pubChangeAdd')
        : v.change === 'rotate-key'
          ? t.html('portalSelfIssued.pubChangeRotate')
          : t.html('portalSelfIssued.pubChangeCreate');
      return '<li>' + t.html('portalSelfIssued.pubVersionLine',
        { n: String(v.versionId), when: v.created ? t.date(v.created) : '' }) +
        ' ' + change +
        ' (' + (v.keys || []).map(function (k: Json): string {
          return '<code title="' + kit.esc(k.id) + '">' +
            kit.esc(SelfIssuedPages.middle(k.id)) + '</code>';
        }).join(', ') + ')</li>';
    });
    let acts = '';
    if (active && one.custody === 'realm') {
      acts = SelfIssuedPages.didForm('add-key', one.rid,
               t.html('portalSelfIssued.pubAddKey'), '') +
             SelfIssuedPages.didForm('rotate-key', one.rid,
               t.html('portalSelfIssued.pubRotateKey'), '');
    } else if (active && one.proof === 'wallet') {
      acts = one.pending
        ? '<p class="sub">' + t.html('portalSelfIssued.pubPendingNote') +
          '</p><a class="button" href="' +
          SelfIssuedPages.walletLink('key.' + one.rid, view) + '">' +
          t.html('portalSelfIssued.pubProveNew') + '</a>'
        : '<a class="button" href="' +
          SelfIssuedPages.walletLink('authorize-add.' + one.rid, view) +
          '">' + t.html('portalSelfIssued.pubAddKey') + '</a> ' +
          '<a class="button" href="' +
          SelfIssuedPages.walletLink('authorize-rotate.' + one.rid, view) +
          '">' + t.html('portalSelfIssued.pubRotateKey') + '</a>';
    } else if (active && one.proof === 'issued') {
      acts = '<p class="sub">' + t.html('portalSelfIssued.pubProveIssued') +
        '</p>';
    }
    if (active) {
      acts += SelfIssuedPages.didForm('deactivate', one.rid,
                t.html('portalSelfIssued.pubDeactivate'), 'danger');
    }
    return '<tr id="did-' + kit.esc(one.rid) + '"><td><code class="oneline ' +
      'subject" title="' + kit.esc(one.did) + '">' +
      kit.esc(SelfIssuedPages.middle(one.did)) + '</code>' +
      '<div class="didlink"><a href="' + kit.esc(one.documentUrl) +
      '" title="' + kit.esc(one.documentUrl) + '" target="_blank" ' +
      'rel="noopener noreferrer">' + t.html('portalSelfIssued.pubDocument') +
      '</a></div></td><td>' +
      custody + '</td><td>' +
      '<details><summary>' + t.html('portalSelfIssued.pubCurrent',
        { n: String(one.currentVersion) }) + '</summary><ul>' +
      versions.join('') + '</ul></details></td><td>' +
      t.html(one.state === 'active' ? 'portalSelfIssued.pubStateActive'
        : one.state === 'suspended' ? 'portalSelfIssued.pubStateSuspended'
          : 'portalSelfIssued.pubStateDeactivated') + '</td><td>' + acts +
      '</td></tr>';
  }

  /**
   * A downloaded DID key's one-time pane (#1291, #671's pattern): the file
   * the answer carried, offered once, and a warning that it will not come
   * back. '' on every other drawing.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static freshPane(view: Json, t: Json): string {
    const fresh = view.fresh;
    if (!fresh || fresh.kind !== 'did-key' || !fresh.file) {
      return '';
    }
    return '<div class="fresh" id="did-fresh"><h3>' +
      t.html('portalSelfIssued.pubFreshHeading') + '</h3><p><code>' +
      kit.esc(String(fresh.did)) + '</code></p><p>' +
      t.html('portalSelfIssued.pubFreshNote') + '</p>' +
      '<div class="dl-row"><a class="dl" id="did-fresh-download" ' +
      'download="' + kit.esc(fresh.file.name) + '" title="' +
      kit.esc(fresh.file.name) + '" href="' +
      kit.esc('data:' + fresh.file.mime + ';base64,' + fresh.file.base64) +
      '">' + t.html('portalSelfIssued.pubFreshDownload') + '</a></div></div>';
  }

  /**
   * How the sign-in is turned on, after the sentence saying it is off
   * (#655), or '': to a person who may change the realm's settings, the
   * setting, its environment variable and a link to the console tab that
   * draws it; to anybody else, the setting to ask an administrator for.
   * The link is root-relative, so the runtime puts it in the realm as it
   * does every other (`realmLinks()`).
   *
   * @param turnOn - the view's `turnOn`, or nothing
   * @param t - the translator
   * @returns the HTML
   */
  static turnOnNote(turnOn: Json, t: Json): string {
    if (!turnOn || !turnOn.setting) {
      return '';
    }
    const named = { setting: String(turnOn.setting),
                    env: String(turnOn.env || '') };
    if (turnOn.administrator === true && turnOn.page) {
      return ' <span id="siop-turn-on">' +
        t.html('portalSelfIssued.offAdmin', named) + ' <a href="' +
        kit.esc(String(turnOn.page)) + '">' +
        t.html('portalSelfIssued.offAdminLink') + '</a></span>';
    }
    return ' <span id="siop-ask-admin">' +
      t.html('portalSelfIssued.offAsk', named) + '</span>';
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
      t.html('portalSelfIssued.pubHeading') + '</h2>';
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
    // A proved DID, or one this realm published for them (#1291).
    if ((one.proof === 'wallet' || one.proof === 'realm' ||
         one.proof === 'issued') && /^did:/.test(String(one.subject))) {
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
