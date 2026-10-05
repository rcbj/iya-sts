// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_applications.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → APPLICATIONS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/applications` and its drill-down from the answer of `GET
// /admin-api/applications`: every application in the registry, filtered and
// paged, the two ways to add one, and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:applicationsListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

const APPLICATIONS_LINKS =
  '<p class="sub"><a href="/admin/ldap/applications">the same registry as ' +
  'the directory sees it, with the schema</a> &middot; <a ' +
  'href="/admin/users">the identities on the other side of these</a> ' +
  '&middot; <a href="/admin/ldap/directory">every entry in the ' +
  'directory</a></p>';

/**
 * Draws `/admin/applications` and its drill-down from the answer of `GET
 * /admin-api/applications`: every application in the registry, filtered and
 * paged, the two ways to add one, and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ApplicationsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const wantedText = json.filter.q || '';
    const wantedKind = json.filter.kind || '';
    const paging = json.paging;
    const filterParams = { q: wantedText, kind: wantedKind,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/applications', filterParams, paging);

    const listView = kit.listViewOf('/admin/applications', ctx.query);
    const rows = json.applications.map(function (row) {
      // The link carries the list AS IT IS BEING VIEWED, which is what lets the
      // trail on the other side come back to this page of this filter rather
      // than to the top of everything. See kit.listViewOf().
      const href = '/admin/applications' +
                   kit.queryWith(listView, { application: row.identifier });
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.identifier) +
        '</code></a>' +
        // The DN on every row rather than only where the RDN is a digest. These
        // entries ARE the registry, so the DN is what an ldapsearch or
        // ldapmodify is aimed at; showing it only in the odd case made it look
        // like a note about a special entry instead of the address of every one
        // of them.
        (row.dn ? '<div class="sub"><code>' + kit.esc(row.dn) + '</code>' +
          (row.identifier === row.dnLabel ? '' :
            ' &mdash; the identifier is too long for a readable RDN, so the ' +
            '<code>cn</code> is a digest of it') + '</div>' : '') +
        '</td><td>' + kit.esc(row.name) +
        ApplicationsPage.secretExpiryNote(row.secretExpiry) +
        '</td>' +
        '<td>' + ApplicationsPage.applicationKindCells(row) + '</td>' +
        // BOTH PROTOCOL LISTS IN ONE CELL, and the declared half is labelled
        // rather than run in with the other. An application created by hand has
        // no observed protocols at all — it has never connected — so this cell
        // was blank on exactly the entries somebody had just finished
        // describing, which reads as the create having lost what was ticked.
        // The two are not the same claim, so they are not the same line: the
        // labels are what HAPPENED and the ids under them are what was
        // DECLARED.
        // DECLARED FIRST since 2026-09-18 — applicationProtocolCell() says why.
        '<td>' + ApplicationsPage.applicationProtocolCell(row, json.protocols) +
        '</td>' +
        '<td>' + ApplicationsPage.applicationRegisteredCell(row) + '</td>' +
        '<td class="num">' + row.authentications + '</td>' +
        '<td class="num">' + row.sessions + '</td>' +
        '<td class="num">' + row.users + '</td>' +
        '<td><code>' + kit.esc(row.lastSeen) + '</code></td></tr>';
    }).join('');

    const kindOptions = ['<option value=""' + (wantedKind ? '' : ' selected') +
                         '>any kind</option>']
      .concat(json.kinds.map(function (one) {
        // Counted over EVERYTHING rather than over the filtered set, so the
        // numbers do not change as the reader narrows the list — a select whose
        // options renumber themselves on every Filter is one nobody can use to
        // find out where the rows went.
        const n = json.kindCounts[one.kind] || 0;
        return '<option value="' + kit.esc(one.kind) + '"' +
               (one.kind === wantedKind ? ' selected' : '') + '>' +
               kit.esc(one.label) + ' (' + n + ')</option>';
      })).join('');


    const inner = '<div class="tiles">' +
      kit.tile(json.applicationCount, 'Applications') +
      kit.tile(json.registered, 'Registered') +
      kit.tile(json.authentications, 'Authentications') +
      kit.tile(json.max === null ? '' : json.max, 'Maximum held') +
      '</div><form method="get" action="/admin/applications"><div ' +
      'class="formrow"><label for="q">Application</label><input type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) +
      '" ' +
      'size="28" placeholder="client_id, wtrealm, entityID, SPN or ' +
      'name"><label for="kind">Kind</label><select id="kind" ' +
      'name="kind">' + kindOptions + '</select>' +
      '<label for="per">Show</label>' +
      '<select id="per" name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">Filter</button>' +
      ((wantedText || wantedKind)
        ? ' <a href="/admin/applications">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th><th>' +
      'Protocols</th><th>Registered</th><th class="num">Auth</th><th ' +
      'class="num">Sessions</th><th class="num">Users</th><th>Last ' +
      'seen</th></tr>' +
      (rows || '<tr><td colspan="9">No application matches. ' +
               ((wantedText || wantedKind)
                 ? 'The filter above may be hiding some.'
                 : 'One appears the first time a client_id, wtrealm, ' +
                   'AppliesTo, entityID or service principal name is ' +
                   'accepted here.') + '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>Add an application</h2>' +
      // ---------------------------------------------------------------------
      // THE DOOR TO THE FULLER FORM IS A BUTTON, AND SINCE 2026-09-06 IT IS THE
      // ONLY WAY TO IT.
      //
      // `/admin/applications/new` had a row in the sidebar and lost it (see
      // SECTIONS): it is the longer of two forms on this page rather than a
      // place in this console. What that leaves is this control, so it cannot
      // go on being a link inside a sentence — a `<p class="sub">` is what a
      // reader skims past, and skipping it now means not finding the protocol
      // families, the per-protocol identifiers or the redirect URIs at all.
      //
      // `a.btn` rather than a form with a submit in it, because nothing is
      // written by pressing it: it is a link that looks like the next action,
      // which is exactly what it is. `/admin/users/new`'s door is a GET FORM
      // instead, and the difference is a real one rather than an inconsistency
      // — that box carries the typed username onward and this page has no field
      // to carry, since the short row below is where a bare identifier goes.
      // ---------------------------------------------------------------------
      '<p><a class="btn" href="/admin/applications/new">New application ' +
      '&rsaquo;</a></p>' +
      kit.note('<strong>The button opens the fuller form</strong> &mdash; ' +
      'the same action, with the PROTOCOL FAMILIES this application is ' +
      'declared for and a sentence about each, its per-protocol identifiers ' +
      'and its redirect URIs. It has no tab of its own in the sidebar ' +
      'because it is not a place in this console: it is the long way in from ' +
      'this page, and the row below is the short one. Both post here and ' +
      'reach one function.') +
      kit.note('For a relying party that has not connected yet. An entry ' +
      'usually appears because an identifier was ACCEPTED — a client_id at ' +
      'the token endpoint, a wtrealm on a sign-in response — and this is how ' +
      'to get one in ahead of that, which is what RFC 9700 mode needs if it ' +
      'is to judge a client against its own redirect URIs rather than ' +
      'against the <code>oauth2.redirectUris</code> setting. It records that ' +
      'it was created by hand, so it cannot be mistaken for one that turned ' +
      'up once and never came back.') +
      '<form method="post" action="/admin/applications"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="create"><label for="identifier">Identifier</label><input ' +
      'type="text" id="identifier" name="identifier" size="30" required ' +
      'placeholder="e.g. my-web-app"' +
      kit.tip('The key every protocol presents for this application: a ' +
               'client_id, wtrealm, AppliesTo, SAML entityID or Kerberos ' +
               'SPN. At most 512 characters, no line break.') +
      '><label for="newname">Name</label><input type="text" id="newname" ' +
      'name="name" size="18" placeholder="e.g. My Web App (optional)"' +
      kit.tip('What pages call it. With none, the identifier is the name.') +
      '><button ' +
      'type="submit">Add</button></div></form>' +
      kit.note('This row takes the identifier and a name and nothing else ' +
      '&mdash; it is the short way in for somebody already looking at the ' +
      'list. The <em>Kind</em> select that used to sit in it is gone for the ' +
      'reason <a href="/admin/applications/new">New application</a> gives at ' +
      'length: it asked the same question the protocol families do, in a ' +
      'vocabulary that does not line up with theirs, and it is DERIVED ' +
      'rather than declared &mdash; a kind is written when a protocol ' +
      'actually recognises the identifier. The fuller form is where the ' +
      'families, the per-protocol identifiers and the redirect URIs are, and ' +
      'an entry made here can be given all of them afterwards from its own ' +
      'page.') +
      kit.note('<strong>One entry per identifier, whatever protocol brought ' +
      'it.</strong> The key is the identifier exactly as it arrived &mdash; ' +
      'not lower-cased and not namespaced by protocol &mdash; so an ' +
      'application appearing under one name in two protocols is one row with ' +
      'two kinds rather than two rows. That is the same rule that makes ' +
      '<code>alice</code>, her <code>urn:uuid:</code> subject and ' +
      '<code>alice@REALM</code> one person on the users page.') +
      kit.note('<strong>Sessions and Users are counts of CHANGES, not of ' +
      'distinct sets.</strong> The ids themselves are deliberately not kept ' +
      'on the entry &mdash; an application used by two thousand people would ' +
      'otherwise carry two thousand values &mdash; so the count moves when ' +
      'the id differs from the last one recorded. Right for the ordinary ' +
      'case, and it undercounts somebody alternating between two ' +
      'applications.') +
      // The two applications.* rows: how many entries this registry remembers,
      // and whether the console and the management API are seeded into it as
      // applications of their own.
      SettingsForms.forms(json.settings, '/admin/applications') +
      ApplicationsPage.applicationsCaveat() + APPLICATIONS_LINKS;

    return inner;
  }

  // The mark itself, from the judgement `admin_views.secretExpiryOf()` makes
  // (#446): a page drawn from an answer has the judgement and not the clock.
  /**
   * Draws the note under an application whose client secret is expired or
   * about to expire.
   *
   * @param expiry - `{ state, at }`, from `secretExpiryOf()`
   * @returns the note as HTML, or ''
   */
  static secretExpiryNote(expiry) {
    const one = expiry || {};
    if (one.state === 'expired') {
      return '<div class="sub warn">Client secret EXPIRED ' +
        kit.esc(one.at) + '</div>';
    }
    if (one.state === 'soon') {
      return '<div class="sub warn">Client secret expires ' +
        kit.esc(one.at) + '</div>';
    }
    return '';
  }

  // AN APPLICATION'S KINDS, RECORDED AND DECLARED TOGETHER (2026-09-18). The
  // Kind column read `row.kinds` alone, which a create does not write — so an
  // application declared on /admin/applications/new for OAuth 2.0 and SAML
  // 2.0 showed "unstated" beside that declaration. It is known; the entry just
  // keeps the two apart (see `declaredKinds` in applications.js's view()).
  /**
   * Draws an application's recorded and declared kinds together as one
   * cell.
   *
   * @param row - the application's registry view
   * @returns the cell's HTML
   */
  static applicationKindCells(row) {
    const kinds = (row.kinds || []).slice(0);
    (row.declaredKinds || []).forEach(function (kind) {
      if (kinds.indexOf(kind) < 0) {
        kinds.push(kind);
      }
    });
    return kit.kindCells(kinds);
  }

  // THE PROTOCOLS CELL: WHAT IT IS FOR FIRST, THEN WHAT HAS HAPPENED
  // (2026-09-18). It used to lead with the observed list, so a new
  // application read "none recorded" and then "declared: oauth2, oidc, …" —
  // two lines that looked like they disagreed. A declared application now
  // shows its families by name, with what has been seen (or that nothing has
  // yet) under them; one that was never declared shows what was seen.
  /**
   * Draws the Protocols cell: the declared families by name with what has
   * been seen under them, or only what was seen when nothing was declared.
   *
   * @param row - the application's registry view
   * @param protocols - the register's protocol families (`PROTOCOLS`)
   * @returns the cell's HTML
   */
  static applicationProtocolCell(row, protocols) {
    const declared = (row.allowedProtocols || []).map(function (id) {
      const known = (protocols || []).filter(function (p) {
        return p.id === id;
      })[0];
      return known ? known.label : id;
    });
    const seen = row.protocols || [];
    if (!declared.length) {
      return seen.length ? kit.esc(seen.join(', '))
                         : '<span class="state-none">none</span>';
    }
    return kit.esc(declared.join(', ')) +
      '<div class="sub">' + (seen.length
        ? 'seen: ' + kit.esc(seen.join(', '))
        : 'not used yet') + '</div>';
  }

  // REGISTERED MEANS SOMEBODY PUT IT HERE ON PURPOSE (2026-09-18) — an
  // administrator, RFC 7591, or this service's own seeding — as against an
  // identifier that merely turned up. It read `row.registered`, which is RFC
  // 7591's flag, and so said "no" about an application just created on
  // /admin/applications/new. The flag itself is unchanged: it is what RFC
  // 9700 mode and RFC 7592 turn on (see appRegisteredBy's schema row).
  /**
   * Draws the Registered cell: yes and by whom (an administrator, RFC 7591
   * or startup), or no for an identifier that merely turned up.
   *
   * @param row - the application's registry view
   * @returns the cell's HTML
   */
  static applicationRegisteredCell(row) {
    const by = String(row.registeredBy || (row.registered ? 'rfc7591' : ''));
    if (!by) {
      return '<span class="state-none">no</span>';
    }
    const how = by === 'administrator' ? 'by an administrator'
      : by === 'rfc7591' ? 'RFC 7591'
      : by === 'startup' ? 'at startup'
      : by;
    return '<span class="state-valid">yes</span><div class="sub">' +
           kit.esc(how) + '</div>';
  }

  /**
   * Draws the caveat the applications pages carry.
   *
   * @returns the caveat as HTML
   */
  static applicationsCaveat() {
    return (
      kit.note('<strong>An entry here grants nothing.</strong> Being ' +
      'in this registry does not let an application do anything it could not ' +
      'do before &mdash; this service issues a token to any client_id that ' +
      'asks. The one place it is READ is RFC 9700 mode ' +
      '(<code>oauth2.rfc9700</code>), which matches a redirect_uri against ' +
      '<code>oauthRedirectUri</code> by exact string comparison, decides ' +
      'public-versus-confidential from ' +
      '<code>oauthTokenEndpointAuthMethod</code>, and checks ' +
      '<code>oauthClientSecret</code> at the token endpoint. With that mode ' +
      'off, ' +
      'these entries are a record and nothing more.') +
      kit.note('<strong>Two attributes hold credentials</strong> &mdash; ' +
      '<code>oauthClientSecret</code> and ' +
      '<code>appRegistrationAccessToken</code>. Both are SEALED at rest ' +
      'wherever this process holds a durable key-encryption key, so this ' +
        'page ' +
      'shows their ciphertext; without one (development) they are in the ' +
      'clear. They are never written to the audit log.'));
  }
}

export = ApplicationsPage;
