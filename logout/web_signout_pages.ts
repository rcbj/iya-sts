// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_signout_pages.ts
//
// ---------------------------------------------------------------------------
// THE SIGN-OUT'S PAGE TABLE AND RENDERERS (#577, 2026-10-12).
//
// `/logout` is a static surface (#569, `common/CLAUDE.md` 3cl): one page,
// drawn from `GET /authn-api/logout` — everything the person still holds,
// the global sign-out and every live session in one list on the first tab,
// a checkbox against each row that can be ended, and each family's details
// on the second — and, where the act left the browser
// nothing to fan out, the result of `POST /authn-api/logout`, drawn in place
// from the act's answer. A result that fans out is the server-drawn
// signed-out document (`logout.ts`, `resultPage()`), and is not drawn here.
//
// The markup is what `logout.ts`'s `inventoryPage()` and `resultPage()`
// drew, in the `logout` catalogs' words (#539), over the same stylesheet
// (`/logout/signout.css`, `LOGOUT_CSS`). A family's label, protocol, prose
// and rows, and the result's messages, are the MODEL's words — the same
// strings `/admin/logout` and the JSON door answer with — and are drawn as
// they come; refusals are English.
//
// It is also the renderers' bundle, `logout/signout.bundle.js` under the
// global `StsSignout`, which `tests/web_surfaces.js` loads to draw a page
// from a view after the wire and compare it, byte for byte, with this
// process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

// THE CONSOLE'S FOLDS (`note()`, `warn()`), as the server-drawn page used
// them: one fold rule for both, rather than a second copy of when a
// paragraph is long enough to collapse. A leaf `web_` module.
import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Escapes text for HTML.
 *
 * @param value - anything
 * @returns the escaped text
 */
function esc(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * An instant as the page prints it: ISO 8601, or a dash for none.
 *
 * @param ms - milliseconds since the epoch, or 0
 * @returns the text
 */
function whenText(ms: unknown): string {
  return ms ? new Date(Number(ms)).toISOString() : '—';
}

// THE FAMILIES THAT ARE SESSIONS (rcbj, 2026-10-12): what the Sign out
// tab lists — a sign-on session, the relying-party sessions it carries, a
// federation partner's, a held directory connection and a Kerberos ticket.
// Every other family is a token or a credential (tokens, grants, codes,
// wallet items, GNAP grants, what was issued) and is on the Details tab,
// with checkboxes of its own. By the model's family ids (`logout.ts`).
const SESSION_FAMILIES = ['session', 'oidc-rp', 'wsfed-rp', 'saml2-sp',
                          'federation-partner', 'ldap', 'krb5'];

/**
 * Whether a family is one of the sessions the Sign out tab lists.
 *
 * @param family - the family, as the view lists it
 * @returns true for a session family
 */
function isSessionFamily(family: Json): boolean {
  return SESSION_FAMILIES.indexOf(String(family && family.id)) >= 0;
}

/**
 * The sign-out's pages. A static utility class.
 */
class SignoutPages {
  /**
   * One family's details, for the Details tab: its label, the protocol and
   * specification, what a sign-out does to it, and each row's detail and,
   * where it cannot be ended, why. Read-only: the controls are on the
   * Sign out tab, in the one list. A family that could not be read is a
   * failure, and stays English.
   *
   * @param family - the family, as the view lists it
   * @param t - the translator
   * @returns the HTML
   */
  static familyDetails(family: Json, t: Json, selectable?: boolean): string {
    const head = '<h2>' + esc(family.label) + '</h2>' +
      '<div class="spec">' + esc(family.protocol) + ' — ' +
      esc(family.spec) + '</div>' + kit.note(esc(family.what));
    if (family.failure) {
      return head + '<div class="err">This could not be read: ' +
        esc(family.failure) + '. Everything else on this page is ' +
        'unaffected, and a global logout still tries this family again.' +
        '</div>';
    }
    const rows = family.rows || [];
    if (!rows.length) {
      return head + '<p class="sub">' + t.html('logout.family.nothingLive') +
        '</p>';
    }
    const body = rows.map(function (r: Json) {
      const box = !selectable ? '' : '<td>' + (r.terminable
        ? '<input type="checkbox" name="select" value="' + esc(r.id) + '">'
        : '<span class="cannot" title="' + esc(r.why) + '">—</span>') +
        '</td>';
      return '<tr>' + box + '<td><code>' + esc(r.label) + '</code><br><span ' +
        'class="sub">' + esc(r.detail) + '</span>' +
        (r.terminable ? '' :
         '<br><span class="cannot">' + esc(r.why) + '</span>') +
        '</td><td>' + esc(r.kind) + '</td></tr>';
    }).join('');
    return head +
      '<table><thead><tr>' + (selectable
        ? '<th>' + t.html('logout.family.colEnd') + '</th>' : '') + '<th>' +
      t.html('logout.family.colWhat') +
      '</th><th>' + t.html('logout.family.colKind') + '</th></tr></thead>' +
      '<tbody>' + body + '</tbody></table>' +
      (family.notListed
        ? kit.note(t.html('logout.family.notListed',
          { count: family.notListed, held: family.held }))
        : '');
  }

  /**
   * Every live session in one list, whatever its protocol: a checkbox for
   * each that can be ended (a dash, with the reason as its tooltip, for one
   * that cannot), what it is, the protocol family it belongs to, and when it
   * started and ends.
   *
   * @param families - the view's families
   * @param t - the translator
   * @returns the HTML
   */
  static sessionList(families: Json[], t: Json): string {
    const rows: string[] = [];
    families.forEach(function (family: Json) {
      (family.rows || []).forEach(function (r: Json) {
        const box = r.terminable
          ? '<input type="checkbox" name="select" value="' + esc(r.id) +
            '">'
          : '<span class="cannot" title="' + esc(r.why) + '">—</span>';
        rows.push('<tr><td>' + box + '</td><td><code>' + esc(r.label) +
          '</code></td><td>' + esc(family.label) + '</td><td class="sub">' +
          esc(whenText(r.startedAt)) + '</td><td class="sub">' +
          esc(whenText(r.expiresAt)) + '</td></tr>');
      });
    });
    if (!rows.length) {
      return '<p class="sub">' + t.html('logout.family.nothingLive') +
        '</p>';
    }
    return '<table class="sessions"><thead><tr><th>' +
      t.html('logout.family.colEnd') + '</th><th>' +
      t.html('logout.family.colWhat') + '</th><th>' +
      t.html('logout.list.colProtocol') + '</th><th>' +
      t.html('logout.family.colSince') + '</th><th>' +
      t.html('logout.family.colUntil') + '</th></tr></thead><tbody>' +
      rows.join('') + '</tbody></table>';
  }

  /**
   * The inventory, in two tabs: Sign out — the global sign-out first, what
   * nearly everybody arriving here came to press and the default, then every
   * live session in one list with its checkbox, and the ticked-items button
   * — and Details: the count, every family's explanation and rows, and who
   * may be named here.
   *
   * @param view - `GET /authn-api/logout`'s view
   * @param ctx - the render context
   * @returns the HTML
   */
  static inventory(view: Json, ctx: Json): string {
    const t = ctx.t;
    const families = view.families || [];
    const held = families.filter(function (f: Json) {
      return (f.rows || []).length;
    }).length;
    // The account the step chose (#561), carried by every form after it so
    // the act is for the same person; only where the view names one.
    const who = '<input type="hidden" name="username" value="' +
      esc(view.username) + '">' + (view.account
      ? '<input type="hidden" name="account" value="' + esc(view.account) +
        '">' : '');
    const naming = view.naming === 'open'
      ? t.html('logout.inventory.anyUserOpen')
      : (view.naming === 'off' ? t.html('logout.inventory.anyUserOff')
                               : t.html('logout.inventory.productMode'));
    // TWO TABS (rcbj, 2026-10-12): what a person came to do — the global
    // sign-out, and every live session in ONE list with a protocol column —
    // then everything that explains it, family by family.
    const signOut = '<form method="post" action="/logout">' + who +
      '<input type="hidden" name="scope" value="global"><div ' +
      'class="actions"><button type="submit" class="global">' +
      t.html('logout.inventory.globalButton') + '</button><span ' +
      'class="sub">' + t.html('logout.inventory.globalNote') +
      '</span></div></form>' +
      '<form method="post" action="/logout">' + who +
      SignoutPages.sessionList(families.filter(isSessionFamily), t) +
      '<div class="actions"><button type="submit" name="scope" ' +
      'value="selected">' + t.html('logout.inventory.selectedButton') +
      '</button><span class="sub">' +
      t.html('logout.inventory.listNote') + '</span></div></form>';
    const details = kit.warn(t.html('logout.inventory.liveCount',
                                    { total: view.total, families: held })) +
      // The tokens and credentials, each family with its checkboxes and
      // their own ticked-items button: they are ended here, not from the
      // Sign out tab.
      '<form method="post" action="/logout">' + who +
      families.filter(function (family: Json) {
        return !isSessionFamily(family);
      }).map(function (family: Json) {
        return SignoutPages.familyDetails(family, t, true);
      }).join('') +
      '<div class="actions"><button type="submit" name="scope" ' +
      'value="selected">' + t.html('logout.inventory.selectedButton') +
      '</button><span class="sub">' +
      t.html('logout.inventory.detailsNote') + '</span></div></form>' +
      // And the sessions' own explanations, read-only.
      families.filter(isSessionFamily).map(function (family: Json) {
        return SignoutPages.familyDetails(family, t);
      }).join('') +
      kit.note(naming + ' ' + t.html('logout.inventory.operatorView'));
    return '<h1>' + t.html('logout.heading') + '</h1>' +
      '<p class="sub">' + t.html('logout.inventory.holding',
                                 { username: view.username }) + '</p>' +
      kit.tabbedPanels('logout-tabs', [
        { id: 'logout-signout', label: t.text('logout.tab.signOut'),
          html: signOut },
        { id: 'logout-details', label: t.text('logout.tab.details'),
          html: details }
      ]);
  }

  /**
   * The account step (#561): a browser holding several signed-in accounts
   * chooses which to sign out — one of them, then that person's inventory —
   * or every account in this browser. The one `login_hint` named is
   * preselected; otherwise the browser's default.
   *
   * @param view - the step's view
   * @param ctx - the render context
   * @returns the HTML
   */
  static accounts(view: Json, ctx: Json): string {
    const t = ctx.t;
    const accounts = view.accounts || [];
    const chosen = String(view.preselected || '') ||
      String((accounts.filter(function (one: Json) {
        return one.current;
      })[0] || {}).key || '');
    const rows = accounts.map(function (one: Json) {
      const name = one.displayName && one.displayName !== one.username
        ? esc(one.displayName) + ' <span class="sub">(' + esc(one.username) +
          ')</span>'
        : esc(one.username);
      return '<li><label><input type="radio" name="account" value="' +
        esc(one.key) + '"' + (one.key === chosen ? ' checked' : '') + '> ' +
        name + (one.current
          ? ' <span class="sub">' + t.html('logout.accounts.current') +
            '</span>' : '') + '</label></li>';
    }).join('');
    return '<h1>' + t.html('logout.heading') + '</h1>' +
      '<p class="sub">' + t.html('logout.accounts.intro',
                                 { count: accounts.length }) + '</p>' +
      '<form method="post" action="/logout/accounts" ' +
      'data-sts-step="accounts"><ul class="accounts">' + rows +
      '<li><label><input type="radio" name="account" value="all"' +
      (chosen ? '' : ' checked') + '> ' + t.html('logout.accounts.all') +
      '</label></li></ul><div class="actions"><button type="submit">' +
      t.html('logout.accounts.continue') + '</button><span class="sub">' +
      t.html('logout.accounts.note') + '</span></div></form>';
  }

  /**
   * A result with nothing to fan out: what was ended, what was not and why,
   * and how much is still live.
   *
   * @param view - the act's `view`
   * @param ctx - the render context
   * @returns the HTML
   */
  static result(view: Json, ctx: Json): string {
    const t = ctx.t;
    const listOf = function (rows: Json[], cls: string): string {
      return '<table><tbody>' + rows.map(function (one: Json) {
        return '<tr><td><code>' + esc(one.label || one.id) +
          '</code></td><td class="' + cls + '">' + esc(one.message) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    };
    const terminated = view.terminated || [];
    const skipped = view.skipped || [];
    // TWO TABS, as the server-drawn signed-out document (rcbj, 2026-10-12):
    // Sign out says only that the person is signed out and offers the way
    // on; what was ended and what is still live are on Details.
    const signOut =
      (terminated.length
        ? '<div class="ok">' + t.html('logout.result.brief') + '</div>'
        : '<div class="warn">' + t.html('logout.result.nothingEnded') +
          '</div>') +
      // Close the tab (rcbj, 2026-10-20): what this service held is ended,
      // but the tab still holds whatever pages it showed, so the person is
      // told to close it. On every outcome, the same as the server-drawn
      // document's copy in logout.ts.
      '<p><strong>' + t.html('logout.result.closeTab') + '</strong></p>' +
      '<p class="sub">' + t.html('logout.result.seeDetails') + '</p>' +
      // A root-relative link, which the runtime puts under the realm.
      '<p><a class="btn" href="/portal">' +
      t.html('logout.result.toPortal') + '</a></p>';
    const details = '<p class="sub">' + esc(view.message) + '</p>' +
      (terminated.length
        ? '<h2>' + t.html('logout.result.ended') + '</h2>' +
          listOf(terminated, 'sub')
        : '<div class="warn">' + t.html('logout.result.nothingEnded') +
          '</div>') +
      (skipped.length
        ? '<h2>' + t.html('logout.result.notEnded') + '</h2>' +
          listOf(skipped, 'cannot') +
          kit.note(t.html('logout.result.notEndedNote'))
        : '') +
      '<h2>' + t.html('logout.result.stillLive') + '</h2>' +
      (view.remaining
        ? '<p class="sub">' + t.html('logout.result.remain',
                                     { total: view.remaining }) +
          ' <a href="' + esc('/logout?username=' +
                             encodeURIComponent(String(view.key || ''))) +
          '">' + t.html('logout.result.lookAgain') + '</a>' +
          t.html('logout.result.lookAgainEnd') + '</p>'
        : '<div class="ok">' + t.html('logout.result.nothingLeft',
                                      { key: view.key }) + '</div>');
    return '<h1>' + (view.scope === 'global'
        ? t.html('logout.result.headingGlobal')
        : t.html('logout.result.headingSelected')) + '</h1>' +
      kit.tabbedPanels('logout-tabs', [
        { id: 'logout-signout', label: t.text('logout.tab.signOut'),
          html: signOut },
        { id: 'logout-details', label: t.text('logout.tab.details'),
          html: details }
      ]);
  }

  /**
   * A page the view refuses: a name that may not be used, or nobody to act
   * on. The refusal itself is over the page (the API's `errors`); this is
   * the rest of it, in English as it always was. The way back is a
   * navigation (`data-sts-navigate`), so the server can send a browser with
   * no session to sign in first.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static refused(view: Json, ctx: Json): string {
    const t = ctx.t;
    if (view.state === 'refused') {
      return '<h1>' + t.html('logout.heading') + '</h1><p class="sub">' +
        (view.verifiesCredentials
          ? 'Signing yourself out needs no role; signing somebody else ' +
            'out is an act on their account and needs the operator\'s ' +
            'door.'
          : 'Sign in as that person at <code>/authn/login</code> — no ' +
            'password is checked in development mode') +
        ' <code>/admin/logout</code> is the operator\'s door and is behind ' +
        'the console\'s two roles.</p>';
    }
    return '<h1>' + t.html('logout.heading') + '</h1><p class="sub"><a ' +
      'href="/logout" data-sts-navigate="1">' + t.html('logout.startAgain') +
      '</a>' + t.html('logout.startAgainEnd') + '</p>';
  }

  /**
   * Draws the page's body from its view, by the view's `state`.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static page(view: Json, ctx: Json): string {
    if (view.state === 'result') {
      return SignoutPages.result(view, ctx);
    }
    if (view.state === 'inventory') {
      return SignoutPages.inventory(view, ctx);
    }
    if (view.state === 'accounts') {
      return SignoutPages.accounts(view, ctx);
    }
    return SignoutPages.refused(view, ctx);
  }

  /**
   * The document's title for the view.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    return view && view.state === 'result'
      ? ctx.t.text('logout.result.title') : ctx.t.text('logout.title');
  }

  /**
   * Draws a page's body from its view, for the round trip.
   *
   * @param path - the page's path
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = PAGES.filter(function (one) {
      return one.path === path;
    })[0];
    return row ? row.render(view, ctx) : '';
  }
}

/**
 * The surface's one page: `/logout`, drawn from `GET /authn-api/logout`
 * asked with the location's `username`, and — several accounts in one
 * browser (#561) — its `account` and `login_hint`.
 */
const PAGES = [
  { path: '/logout',
    operation: function (query: Json): string {
      const asked = ['username', 'account', 'login_hint']
        .filter(function (name) {
          return !!query[name];
        }).map(function (name) {
          return name + '=' + encodeURIComponent(String(query[name]));
        });
      return '/authn-api/logout' + (asked.length ? '?' + asked.join('&')
                                                 : '');
    },
    render: function (view: Json, ctx: Json): string {
      return SignoutPages.page(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return SignoutPages.title(view, ctx);
    } }
];

/**
 * The page table, and the renderers by name for the round trip.
 * @namespace
 */
export = {
  PAGES: PAGES,
  SignoutPages: SignoutPages,
  render: SignoutPages.render
};
