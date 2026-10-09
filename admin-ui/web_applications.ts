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
import TokenLifetimesPage = require('./web_token_lifetimes');
import SettingsForms = require('./web_settings');

type Json = any;

// The links the applications pages end with. A function of the translator
// since #539, where it was the constant APPLICATIONS_LINKS.
const applicationsLinks = function (t) {
  return '<p class="sub"><a href="/admin/ldap/applications">' +
    t.html('consoleApplications.a1.linkSameRegistry') + '</a> &middot; <a ' +
    'href="/admin/users">' + t.html('consoleApplications.a1.linkIdentities') +
    '</a> ' +
    '&middot; <a href="/admin/ldap/directory">' +
    t.html('consoleApplications.a1.linkEveryEntry') + '</a></p>';
};

// ---------------------------------------------------------------------------
// CONFIGURE AN APPLICATION FROM ITS RFC 9728 METADATA (2026-09-13).
//
// A protected resource publishes a document saying what it is, and this page
// can be handed one — pasted, uploaded, or fetched from a URL — and turn it
// into the create form, filled in: the `resource` as the default name, the
// permission base URI and the audience; `scopes_supported` as the permissions;
// a client_id minted at random. `oauth-oidc/protected_resource_metadata.ts` is
// the reading and argues every rule; what is decided HERE is the page.
//
// **TWO ROUND TRIPS AND NO SCRIPT.** A file can only reach a server without a
// script as multipart/form-data, and a document read on the server can only
// reach the page as a page — so Load is a POST that answers with this page and
// the pane on it, and Create is a second POST. Both go to
// `/admin/applications/new`, which is why that path takes a POST now: a create
// that was refused must come back HERE with the document still loaded and every
// edit still in its box, and the list page's 303 would lose both. It is the
// arrangement `/admin/users/new` argues for a refused create, and for its
// reason.
//
// **THE TABS ARE CSS.** Three radio buttons and the sibling combinator, in the
// console's one stylesheet — see `page()`. The third tab's boxes are fields of
// the create form whichever tab is showing, so editing them and pressing Create
// from the first tab submits what was edited.
//
// **IT IS NOT A SECOND DOOR EITHER.** Load is `load-resource-metadata` and
// Create is `create`, both through `applicationsAction()` — the switch
// `POST /admin/applications` and `POST /admin-api/applications/{action}`
// dispatch on — so the page adds TRANSPORT and nothing it decides.
// ---------------------------------------------------------------------------
const RESOURCE_METADATA_OWNED = ['oauthClientId', 'oauthPermissionBaseUri',
                                 'oauthAudience', 'oauthPermission',
                                 'oauthAuthorizationDetailsType',
                                 'oauthResourceMetadata',
                                 'oauthResourceMetadataUrl'];

// What each recorded provenance of a managed key pair means, in the words the
// section draws. KEY_SOURCES in `common/applications.js` is the vocabulary;
// `unrecorded` is this page's own word for an entry that holds a certificate
// and no provenance, which only a hand edit or an older build produces.
const keySourceSentence = function (source, t) {
  // A function of the translator since #539, where it was a table of
  // sentences: a key per provenance, literal, so the catalog test can see
  // each one. An unknown source answers null, as the table's miss did.
  switch (source) {
    case 'issued':
      return t.html('consoleApplications.a2.keyIssued');
    case 'uploaded-realm-ca':
      return t.html('consoleApplications.a2.keyUploadedRealm');
    case 'uploaded-external-ca':
      return t.html('consoleApplications.a2.keyUploadedExternal');
    case 'unrecorded':
      return t.html('consoleApplications.a2.keyUnrecorded');
    default:
      return null;
  }
};

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
    const t = ctx.t;
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
            t.html('consoleApplications.a1.dnDigest')) + '</div>' : '') +
        '</td><td>' + kit.esc(row.name) +
        ApplicationsPage.secretExpiryNote(row.secretExpiry, t) +
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
        '<td>' + ApplicationsPage.applicationProtocolCell(row, json.protocols,
                                                          t) +
        '</td>' +
        '<td>' + ApplicationsPage.applicationRegisteredCell(row, t) + '</td>' +
        '<td class="num">' + row.authentications + '</td>' +
        '<td class="num">' + row.sessions + '</td>' +
        '<td class="num">' + row.users + '</td>' +
        '<td><code>' + kit.esc(row.lastSeen) + '</code></td></tr>';
    }).join('');

    const kindOptions = ['<option value=""' + (wantedKind ? '' : ' selected') +
                         '>' + t.html('consoleApplications.a1.anyKind') +
                         '</option>']
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

    const th = function (cls, key) {
      return '<th' + cls + '>' + t.html(key) + '</th>';
    };
    const inner = '<div class="tiles">' +
      kit.tile(json.applicationCount,
               t.text('consoleApplications.a1.tileApplications')) +
      kit.tile(json.registered,
               t.text('consoleApplications.a1.tileRegistered')) +
      kit.tile(json.authentications,
               t.text('consoleApplications.a1.tileAuthentications')) +
      kit.tile(json.max === null ? '' : json.max,
               t.text('consoleApplications.a1.tileMax')) +
      '</div><form method="get" action="/admin/applications"><div ' +
      'class="formrow"><label for="q">' +
      t.html('consoleApplications.a1.filterApplication') +
      '</label><input type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) +
      '" ' +
      'size="28" placeholder="' +
      kit.esc(t.text('consoleApplications.a1.filterPlaceholder')) +
      '"><label for="kind">' + t.html('consoleApplications.a1.kind') +
      '</label><select id="kind" ' +
      'name="kind">' + kindOptions + '</select>' +
      '<label for="per">' + t.html('consoleApplications.a1.show') +
      '</label>' +
      '<select id="per" name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">' + t.html('consoleApplications.a1.filter') +
      '</button>' +
      ((wantedText || wantedKind)
        ? ' <a href="/admin/applications">' +
          t.html('consoleApplications.a1.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr>' + th('', 'consoleApplications.a1.colIdentifier') +
      th('', 'consoleApplications.a1.colName') +
      th('', 'consoleApplications.a1.colKind') +
      th('', 'consoleApplications.a1.colProtocols') +
      th('', 'consoleApplications.a1.colRegistered') +
      th(' class="num"', 'consoleApplications.a1.colAuth') +
      th(' class="num"', 'consoleApplications.a1.colSessions') +
      th(' class="num"', 'consoleApplications.a1.colUsers') +
      th('', 'consoleApplications.a1.colLastSeen') + '</tr>' +
      (rows || '<tr><td colspan="9">' +
               t.html('consoleApplications.a1.noMatch') +
               ((wantedText || wantedKind)
                 ? t.html('consoleApplications.a1.filterHiding')
                 : t.html('consoleApplications.a1.appearsFirst')) +
               '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleApplications.a1.addHeading') + '</h2>' +
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
      '<p><a class="btn" href="/admin/applications/new">' +
      t.html('consoleApplications.a1.newButton') + '</a></p>' +
      kit.note(t.html('consoleApplications.a1.fullerForm')) +
      kit.note(t.html('consoleApplications.a1.notConnected')) +
      '<form method="post" action="/admin/applications"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="create"><label for="identifier">' +
      t.html('consoleApplications.a1.identifier') + '</label><input ' +
      'type="text" id="identifier" name="identifier" size="30" required ' +
      'placeholder="' + kit.esc(t.text('consoleApplications.a1.egMyWebApp')) +
      '"' +
      kit.tip(t.html('consoleApplications.a1.identifierTip')) +
      '><label for="newname">' + t.html('consoleApplications.a1.name') +
      '</label><input type="text" id="newname" ' +
      'name="name" size="18" placeholder="' +
      kit.esc(t.text('consoleApplications.a1.egMyWebAppName')) + '"' +
      kit.tip(t.html('consoleApplications.a1.nameTip')) +
      '><button ' +
      'type="submit">' + t.html('consoleApplications.a1.add') +
      '</button></div></form>' +
      kit.note(t.html('consoleApplications.a1.shortRowA') +
      '<a href="/admin/applications/new">' +
      t.html('consoleApplications.a1.newApplication') + '</a>' +
      t.html('consoleApplications.a1.shortRowB')) +
      kit.note(t.html('consoleApplications.a1.oneEntry')) +
      kit.note(t.html('consoleApplications.a1.countsOfChanges')) +
      // The two applications.* rows: how many entries this registry remembers,
      // and whether the console and the management API are seeded into it as
      // applications of their own.
      SettingsForms.forms(json.settings, '/admin/applications', undefined,
                          t) +
      ApplicationsPage.applicationsCaveat(t) + applicationsLinks(t);

    return inner;
  }

  // The mark itself, from the judgement `admin_views.secretExpiryOf()` makes
  // (#446): a page drawn from an answer has the judgement and not the clock.
  /**
   * Draws the note under an application whose client secret is expired or
   * about to expire.
   *
   * @param expiry - `{ state, at }`, from `secretExpiryOf()`
   * @param t - the page's translator (#539)
   * @returns the note as HTML, or ''
   */
  static secretExpiryNote(expiry, t) {
    const one = expiry || {};
    if (one.state === 'expired') {
      return '<div class="sub warn">' +
        t.html('consoleApplications.a1.secretExpired', { at: one.at }) +
        '</div>';
    }
    if (one.state === 'soon') {
      return '<div class="sub warn">' +
        t.html('consoleApplications.a1.secretExpires', { at: one.at }) +
        '</div>';
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
   * @param t - the page's translator (#539)
   * @returns the cell's HTML
   */
  static applicationProtocolCell(row, protocols, t) {
    const declared = (row.allowedProtocols || []).map(function (id) {
      const known = (protocols || []).filter(function (p) {
        return p.id === id;
      })[0];
      return known ? known.label : id;
    });
    const seen = row.protocols || [];
    if (!declared.length) {
      return seen.length ? kit.esc(seen.join(', '))
                         : '<span class="state-none">' +
                           t.html('consoleApplications.a1.none') + '</span>';
    }
    return kit.esc(declared.join(', ')) +
      '<div class="sub">' + (seen.length
        ? t.html('consoleApplications.a1.seen') + kit.esc(seen.join(', '))
        : t.html('consoleApplications.a1.notUsedYet')) + '</div>';
  }

  // REGISTERED MEANS SOMEBODY PUT IT HERE ON PURPOSE (2026-09-18) — an
  // administrator, RFC 7591, or this service's own seeding — as against an
  // identifier that merely turned up. It read `row.registered`, which is RFC
  // 7591's flag, and so said "no" about an application just created on
  // /admin/applications/new. The flag itself is unchanged: it is what RFC
  // 9700 mode and RFC 7592 turn on (see appRegisteredBy's schema row).
  /**
   * Draws the Registered cell: yes and by whom (an administrator, RFC 7591,
   * an LDAP add or startup), or no for an identifier that merely turned up.
   *
   * @param row - the application's registry view
   * @param t - the page's translator (#539)
   * @returns the cell's HTML
   */
  static applicationRegisteredCell(row, t) {
    const by = String(row.registeredBy || (row.registered ? 'rfc7591' : ''));
    if (!by) {
      return '<span class="state-none">' +
        t.html('consoleApplications.a1.no') + '</span>';
    }
    // `ldap:<who>` names the binder, which is data and drawn as it is.
    const how = by === 'administrator'
        ? t.html('consoleApplications.a1.byAdministrator')
      : by === 'rfc7591' ? 'RFC 7591'
      : by === 'startup' ? t.html('consoleApplications.a1.atStartup')
      : by === 'ldap' ? t.html('consoleApplications.a1.byLdapAdd')
      : by.indexOf('ldap:') === 0
        ? t.html('consoleApplications.a1.byLdapAddWho', { who: by.slice(5) })
      : kit.esc(by);
    return '<span class="state-valid">' +
           t.html('consoleApplications.a1.yes') + '</span><div class="sub">' +
           how + '</div>';
  }

  /**
   * Draws the caveat the applications pages carry.
   *
   * @param t - the page's translator (#539)
   * @returns the caveat as HTML
   */
  static applicationsCaveat(t) {
    return (
      kit.note(t.html('consoleApplications.a1.grantsNothing')) +
      kit.note(t.html('consoleApplications.a1.twoCredentials')));
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static newApplicationBody(ctx, json) {
    const t = ctx.t;
    const given = json.state || {};
    const loaded = given.loaded || null;
    // THE FORM AS IT WAS POSTED, on a redraw from one of this page's own
    // round trips — a refused create, or Generate Secret — so that no box
    // comes back empty. Absent on a plain GET.
    const draft = given.draft || null;
    // WHICH FIELDS: the simplified view by default, the advanced one when the
    // switch, a redraw or `?view=advanced` says so.
    const view = (given.view || ctx.query.view) === 'advanced'
      ? 'advanced' : 'simple';
    const drafted = function (name) {
      const value = draft ? draft[name] : undefined;
      return value == null ? '' : String(value);
    };
    const container = json.container;
    const max = json.max;
    const held = json.applicationCount;
    const realm = json.realm;
    let inner;
    if (!container) {
      inner = '<p class="warn">' +
        t.html('consoleApplications.a1.noDirectory') +
        '</p>' + applicationsLinks(t);
    } else {

      // The identifier and the name, as the form draws them with no document
      // loaded. With one loaded they are on the pane's third tab instead, and
      // drawing them here as well would post each name twice.
      const calledSection =
        '<h2>' + t.html('consoleApplications.a1.calledHeading') +
        '</h2><div class="formrow"><label ' +
        'for="identifier">' + t.html('consoleApplications.a1.identifier') +
        '</label><input type="text" ' +
          'id="identifier" ' +
        'name="identifier" size="42" required placeholder="' +
        kit.esc(t.text('consoleApplications.a1.egIdentifierLong')) + '"' +
        kit.tip(t.html('consoleApplications.a1.identifierTip')) +
        ' value="' + kit.esc(drafted('identifier')) + '"></div>' +
        kit.note(t.html('consoleApplications.a1.theKey')) +
        '<div class="formrow"><label for="newname">' +
        t.html('consoleApplications.a1.name') + '</label><input ' +
        'type="text" id="newname" name="name" size="24" ' +
        'placeholder="' +
        kit.esc(t.text('consoleApplications.a1.egMyWebAppName')) + '"' +
        kit.tip(t.html('consoleApplications.a1.nameTip')) +
        ' value="' + kit.esc(drafted('name')) + '"></div>' +
        kit.note(t.html('consoleApplications.a1.nameIs')) +
        kit.note(t.html('consoleApplications.a1.noKind'));
      // The families ticked: the ones a refused create had ticked, or OAuth 2.0
      // for a document describing an OAuth protected resource.
      const ticked = given.protocols ||
                     (loaded ? loaded.plan.protocols : []);

      // The refusal is drawn in English, as every refusal is (#539); the
      // load's message and the notice are the view's sentences.
      inner = kit.flash((given.error && given.error.length
          ? '<div class="warn"><strong>' +
            kit.esc(given.errorTitle || 'That was refused.') + '</strong><ul>' +
            given.error.map(function (one) {
              return '<li>' + kit.esc(one) + '</li>';
            }).join('') + '</ul></div>'
          : '') +
        (loaded ? '<div class="ok">' + kit.esc(loaded.message) +
          '</div>' : '') +
        (given.notice ? '<div class="ok">' + kit.esc(given.notice) + '</div>' :
         '')) +
        '<div class="tiles">' +
        kit.tile(held, t.text('consoleApplications.a1.tileInRegistry')) +
        kit.tile(json.protocols.length,
                 t.text('consoleApplications.a1.tileFamilies')) +
        kit.tile(json.kinds.length,
                 t.text('consoleApplications.a1.tileKinds')) +
        '</div>' +
        kit.note(t.html('consoleApplications.a1.landsIn',
                        { container: container }) +
        (max ? t.html('consoleApplications.a1.holdsAtMost',
                      { max: String(max) }) : '') +
        t.html('consoleApplications.a1.oneRealm',
               { realm: realm ? realm.name : 'Default' })) +
        kit.note(t.html('consoleApplications.a1.notSecondDoor')) +

        ApplicationsPage.resourceMetadataLoadSection(given,
          json.resourceMetadataImport, t) +

        // EVERY POST OF THIS FORM COMES BACK HERE (2026-09-30), so a refused
        // create redraws this page with every box kept rather than 303ing to
        // the
        // list with a message; the create itself is the same action.
        '<form method="post" action="/admin/applications/new" class="newapp">' +
        '<input type="hidden" name="action" value="create">' +
        '<input type="hidden" name="view" value="' + kit.esc(view) + '">' +
        // THE DEFAULT BUTTON. Enter in a text box submits with the FIRST submit
        // button in the form, and since 2026-09-18 that would otherwise be
        // Generate Secret, halfway down — so a person who pressed Enter in the
        // Identifier would get a secret instead of an application. This one is
        // first, creates, and is off-screen and out of the tab order; the
        // visible Create button at the foot does the same thing.
        '<button type="submit" class="default-submit" tabindex="-1" ' +
        'aria-hidden="true">' + t.html('consoleApplications.a1.create') +
        '</button>' +
        (loaded
          ? '<h2>' + t.html('consoleApplications.a1.loadedHeading') + '</h2>' +
            ApplicationsPage.resourceMetadataPane(loaded, given.draft,
              given.tab, t) +
            '<h2>' + t.html('consoleApplications.a1.calledHeading') +
            '</h2>' +
            kit.note(t.html('consoleApplications.a1.onEditableTab'))
          : calledSection) +

        '<h2>' + t.html('consoleApplications.a1.familiesHeading') + '</h2>' +
        kit.note(t.html('consoleApplications.a1.familiesNote')) +
        '<table><tr><th>' + t.html('consoleApplications.a1.colFor') +
        '</th><th>' + t.html('consoleApplications.a1.colFamily') +
        '</th><th>' + t.html('consoleApplications.a1.colValue') + '</th>' +
        '<th>' + t.html('consoleApplications.a1.colRecordedAs') +
        '</th><th>' + t.html('consoleApplications.a1.colMeans') +
        '</th></tr>' +
        json.familyChoices.map(function (row) {
          return ApplicationsPage.protocolChoiceRow(row,
            row.families.some(function (id) {
            return ticked.indexOf(id) >= 0;
          }), t);
        }).join('') +
        '</table>' +

        // THE FIELD GRID (2026-09-30): the simplified view is the fields this
        // page has always offered — the declarations, the per-application
        // setting overrides and where SAML 2.0 encryption gets its key — and
        // the advanced view is every field an application has. Both are one
        // grid, typed, shown for the families ticked; the switch is a submit
        // button, so whatever has been typed is carried into the other view.
        '<h2>' + (view === 'advanced'
          ? t.html('consoleApplications.a1.everyField')
          : t.html('consoleApplications.a1.itsFields')) +
        '</h2>' +
        '<div class="formrow fg-view"><span class="sub">' +
        (view === 'advanced'
          ? t.html('consoleApplications.a1.advancedView')
          : t.html('consoleApplications.a1.simplifiedView')) +
        '</span><button type="submit" class="secondary" name="switchview" ' +
        'value="' + (view === 'advanced' ? 'simple' : 'advanced') +
        '" formaction="/admin/applications/new" formnovalidate' +
        kit.tip(t.html('consoleApplications.a1.switchTip')) + '>' +
        (view === 'advanced'
          ? t.html('consoleApplications.a1.showSimplified')
          : t.html('consoleApplications.a1.showEvery')) + '</button></div>' +
        // THE PROMPT THAT STANDS IN FOR THE HIDDEN FIELDS. It is inside the
        // form
        // so the `:has()` rule that hides it can reach it, and it is always in
        // the markup: a browser without `:has()` shows it beside every field,
        // where it reads as a description of the page rather than as a broken
        // instruction.
        '<div class="pf-hint">' + t.html('consoleApplications.a1.pfHint') +
        '</div>' +
        kit.fieldGridOf(
          ApplicationsPage.newApplicationFieldRows(json, view,
            loaded ? RESOURCE_METADATA_OWNED : []),
          json.fieldGroups,
          draft ? kit.gridValuesFromDraft(draft, json.longTextAttributes)
                : {},
          { redraw: '/admin/applications/new',
            generateSecret: '/admin/applications/new',
            protocols: json.protocols }) +

        '<div class="formrow"><button type="submit">' +
        t.html('consoleApplications.a1.create') + '</button>' +
        kit.note(t.html('consoleApplications.a1.createdWith')) +
        '</div></form>' +

        ApplicationsPage.newApplicationNotes(json.persistence, t) +
          ApplicationsPage.applicationsCaveat(t) + applicationsLinks(t);

    }

    return inner;
  }

  // One protocol family as a row of the checkbox table. `kind` is what the
  // registry WOULD record this application as when a protocol of that family
  // finally recognises the identifier — shown rather than written, because a
  // declaration is not a sighting (see createApplication()) — and a family with
  // no kind at all is marked, because the alternative is a reader wondering for
  // the third time why the LDAP row never fills that column in. `checked` is
  // the one argument this row did not have until the RFC 9728 import: a
  // document describes an OAuth protected resource, so OAuth 2.0 comes ticked,
  // and a refused create redraws the boxes the reader had ticked. It is a
  // separate argument and not `Array.prototype.map`'s index, which a bare
  // `.map(protocolChoiceRow)` would have passed as a truthy number.
  /**
   * Draws one protocol family as a checkbox row of the new-application
   * form, with the kind it would be recorded as.
   *
   * @param row - the choice's row from FAMILY_CHOICES: a family, or a
   *   combined choice standing for several
   * @param checked - true to draw the box ticked
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static protocolChoiceRow(row, checked, t) {
    const kindCell = row.kind
      ? '<code>' + kit.esc(row.kind) + '</code>'
      : '<span class="state-none">' +
        t.html('consoleApplications.a1.noKindRecorded') + '</span>';
    // The family's own sentence appears TWICE and neither is the only copy: as
    // a tooltip on the checkbox's label, where somebody deciding whether to
    // tick it is already pointing, and folded in the last column, where it can
    // be read from a keyboard and on a touch screen. See kit.tip() for why
    // nothing
    // is ever said only in a title attribute.
    return '<tr><td><input type="checkbox" id="proto-' + kit.esc(row.id) +
           '" ' +
      'name="protocol" value="' + kit.esc(row.id) + '"' +
      (checked === true ? ' checked' : '') + kit.tip(row.what) + '></td>' +
      '<td><label for="proto-' + kit.esc(row.id) + '"' + kit.tip(row.what) +
      '>' +
      kit.esc(row.label) + '</label></td>' +
      '<td><code>' + kit.esc((row.families || [row.id]).join(', ')) +
      '</code></td>' +
      '<td>' + kindCell + '</td>' +
      '<td class="why">' + kit.note(kit.esc(row.what)) + '</td></tr>';
  }

  // The form that gives the document. The checkbox shows the three sources; it
  // has no name, so it is never posted, and it is ticked whenever a document is
  // on the page or was just refused, so the reader is not left hunting for the
  // form their error is about.
  /**
   * Draws the form that loads OAuth 2.0 Protected Resource Metadata
   * (RFC 9728) to configure the new application from.
   *
   * @param state - the page state, for the last input and any load error
   * @param facts - the answer's `resourceMetadataImport`: the well-known
   *   path and what this mode accepts and dials
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static resourceMetadataLoadSection(state, facts, t) {
    const given = (state && state.loadInput) || {};
    const open = !!(state && (state.loaded || state.loadError));
    return '<h2>' + t.html('consoleApplications.a1.prmHeading') + '</h2>' +
      kit.note(t.html('consoleApplications.a1.prmIntro',
                      { wellKnown: facts.wellKnown })) +
      '<form method="post" action="/admin/applications/new" ' +
      'enctype="multipart/form-data" class="prm-load">' +
      '<input type="hidden" name="action" value="load-resource-metadata">' +
      '<input type="checkbox" id="prm-use" class="prm-use"' +
      (open ? ' checked' : '') + '> <label for="prm-use"><strong>' +
      t.html('consoleApplications.a1.prmUse') + '</strong></label>' +
      '<div class="prm-source">' +
      kit.note(t.html('consoleApplications.a1.prmOneWay',
                      { mode: facts.acceptsNonconforming ? 'dev' : 'product',
                        internal: facts.dialsInternalAddresses ? 'yes'
                                                               : 'no' })) +
      '<div class="formrow"><label for="prm-document">' +
      t.html('consoleApplications.a1.prmPaste') + '</label>' +
      '<textarea id="prm-document" name="document" rows="8" cols="60" ' +
      'placeholder="{&quot;resource&quot;: ' +
      '&quot;https://api.example.com&quot;, ' +
      '&quot;scopes_supported&quot;: [&quot;read&quot;]}">' +
      kit.esc(String(given.document || '')) + '</textarea></div>' +
      '<div class="formrow"><label for="prm-file">' +
      t.html('consoleApplications.a1.prmUpload') + '</label>' +
      '<input type="file" id="prm-file" name="file" ' +
      'accept="application/json,.json"></div>' +
      '<div class="formrow"><label for="prm-url">' +
      t.html('consoleApplications.a1.prmFetch') + '</label>' +
      '<input type="text" id="prm-url" name="url" size="60" value="' +
      kit.esc(String(given.url || '')) + '" ' +
        'placeholder="https://api.example.com' +
      kit.esc(facts.wellKnown) + '"></div>' +
      '<div class="formrow"><button type="submit">' +
      t.html('consoleApplications.a1.prmLoad') + '</button>' +
      '</div></div></form>';
  }

  // THE THREE TABS. `tab` picks which one is open: the raw JSON on a fresh
  // load, and the editable fields when a refused create is redrawn, because
  // those are what the refusal is about.
  /**
   * Draws the loaded metadata as three tabs (the raw JSON, its members and
   * the editable fields), without a script.
   *
   * @param loaded - the loaded document and what it was read as
   * @param draft - the posted form, or nothing
   * @param tab - the tab to open; the raw JSON when empty
   * @param t - the page's translator (#539)
   * @returns the pane as HTML
   */
  static resourceMetadataPane(loaded, draft, tab, t) {
    const values = ApplicationsPage.resourceMetadataValues(loaded, draft);
    const open = tab || 'json';
    const radio = function (id) {
      return '<input type="radio" name="prm-tab" id="prm-tab-' + id + '" ' +
             'form="prm-tabs-not-a-form"' + (open === id ? ' checked' : '') +
             '>';
    };
    const source = loaded.source === 'url'
      ? t.html('consoleApplications.a1.fetchedFrom', { url: loaded.url })
      : (loaded.source === 'upload'
        ? (loaded.filename
          ? t.html('consoleApplications.a1.uploadedAs',
                   { filename: loaded.filename })
          : t.html('consoleApplications.a1.uploaded'))
        : t.html('consoleApplications.a1.pasted'));

    const matchOf = {};
    loaded.authorizationServers.rows.forEach(function (row) {
      matchOf[row.issuer] = row;
    });
    const tableRows = loaded.members.map(function (row) {
      let value = ApplicationsPage.resourceMetadataValueCell(row.value, t);
      if (row.member === 'authorization_servers' && Array.isArray(row.value)) {
        value = row.value.map(function (issuer) {
          const match = matchOf[issuer];
          return '<code>' + kit.esc(issuer) + '</code> ' +
                 (match && match.matched
            ? '<span class="state-valid">' +
              t.html('consoleApplications.a1.matchesRealm',
                     { as: match.authorizationServer }) + '</span>'
            : '<span class="state-expired">' +
              t.html('consoleApplications.a1.notRealmAs') + '</span>');
        }).join('<br>');
      }
      return '<tr><td><code>' + kit.esc(row.member) + '</code></td><td>' +
             value +
        '</td><td>' + (row.known ? kit.esc(row.type)
                                 : '<span class="state-none">' +
                                   t.html('consoleApplications.a1.extension') +
                                   '</span>') +
        '</td><td class="why">' + kit.esc(row.maps || '') + '</td>' +
        '<td class="why">' + kit.note(kit.esc(row.what)) + '</td></tr>';
    }).join('');
    const permissionRows = loaded.plan.permissions.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.scope) + '</code></td><td><code>' +
        kit.esc(one.name) + '</code></td><td><code>' + kit.esc(one.id) +
        '</code></td><td>' + (one.problem
          ? '<span class="state-expired">' +
            t.html('consoleApplications.a1.notUsable') + '</span>'
          : (one.duplicate
            ? '<span class="state-none">' +
              t.html('consoleApplications.a1.duplicate') + '</span>'
            : (one.sameAsAdvertised
              ? '<span class="state-valid">' +
                t.html('consoleApplications.a1.asAdvertised') + '</span>'
              : '<span class="state-none">' +
                t.html('consoleApplications.a1.asksIdentifier') +
                '</span>'))) + '</td></tr>';
    }).join('');
    const signed = loaded.signedMetadata
      ? '<h3>' + t.html('consoleApplications.a1.signedHeading') + '</h3>' +
        kit.note(t.html('consoleApplications.a1.signedNote')) +
        '<pre><code>' + kit.esc(JSON.stringify({
          header: loaded.signedMetadata.header,
          claims: loaded.signedMetadata.claims
        }, null, 2)) + '</code></pre>'
      : '';

    const memberRows = loaded.members.filter(function (row) {
      return row.known && row.type !== 'jwt';
    }).map(function (row) {
      const id = 'prm-member-' + row.member.replace(/[^A-Za-z0-9_-]/g, '_');
      const name = 'metadata.' + row.member;
      const current = values.members[row.member];
      let control = '';
      if (row.type === 'bool') {
        control = '<select id="' + kit.esc(id) + '" name="' + kit.esc(name) +
                  '">' +
          ['true', 'false', ''].map(function (option) {
            return '<option value="' + option + '"' +
              (current === option ? ' selected' : '') + '>' +
              (option || t.html('consoleApplications.a1.removeMember')) +
              '</option>';
          }).join('') + '</select>';
      } else if (row.type === 'string-list' || row.type === 'uri-list') {
        control = '<textarea id="' + kit.esc(id) + '" name="' +
                  kit.esc(name) + '" ' +
          'rows="3" cols="50" placeholder="' +
          kit.esc(t.text('consoleApplications.a1.onePerLine')) + '">' +
          kit.esc(current) + '</textarea>';
      } else {
        control = '<input type="text" id="' + kit.esc(id) + '" name="' +
          kit.esc(name) + '" size="50" value="' + kit.esc(current) + '" ' +
          'placeholder="' +
          kit.esc(t.text('consoleApplications.a1.emptyRemoves')) + '">';
      }
      return '<tr><td><label for="' + kit.esc(id) + '"><code>' +
             kit.esc(row.member) +
        '</code></label></td><td>' + control + '</td><td class="why">' +
        kit.note(kit.esc(row.what)) + '</td></tr>';
    }).join('');

    const field = function (id, name, label, value, what, multi?) {
      return '<tr><td><label for="' + id + '">' + label + '</label></td><td>' +
        (multi
          ? '<textarea id="' + id + '" name="' + kit.esc(name) +
            '" rows="4" cols="50">' + kit.esc(value) + '</textarea>'
          : '<input type="text" id="' + id + '" name="' + kit.esc(name) +
            '" size="50" value="' + kit.esc(value) + '">') +
        '</td><td class="why">' + kit.note(what) + '</td></tr>';
    };

    const html = ApplicationsPage.resourceMetadataBanners(loaded, t) +
      '<div class="prm-tabs">' +
      radio('json') + radio('table') + radio('fields') +
      '<div class="prm-tablist" role="tablist">' +
      '<label for="prm-tab-json">' + t.html('consoleApplications.a1.tabJson') +
      '</label>' +
      '<label for="prm-tab-table">' +
      t.html('consoleApplications.a1.tabTable') + '</label>' +
      '<label for="prm-tab-fields">' +
      t.html('consoleApplications.a1.tabFields') + '</label></div>' +

      '<div class="prm-panel prm-panel-json">' +
      '<p class="sub">' + t.html('consoleApplications.a1.asRead') + source +
      '.</p>' +
      '<pre><code>' + kit.esc(loaded.pretty) + '</code></pre></div>' +

      '<div class="prm-panel prm-panel-table">' +
      '<table><tr><th>' + t.html('consoleApplications.a1.colMember') +
      '</th><th>' + t.html('consoleApplications.a1.colValue') + '</th><th>' +
      t.html('consoleApplications.a1.colType') + '</th>' +
      '<th>' + t.html('consoleApplications.a1.colUsedFor') + '</th><th>' +
      t.html('consoleApplications.a1.colWhatItIs') + '</th></tr>' +
      tableRows + '</table>' +
      '<h3>' + t.html('consoleApplications.a1.scopesHeading') + '</h3>' +
      (permissionRows
        ? '<table><tr><th>' + t.html('consoleApplications.a1.colScope') +
          '</th><th>' + t.html('consoleApplications.a1.colPermission') +
          '</th>' +
          '<th>' + t.html('consoleApplications.a1.colClientAsks') +
          '</th><th></th></tr>' +
          permissionRows + '</table>'
        : kit.note(t.html('consoleApplications.a1.noScopes'))) +
      '<h3>' + t.html('consoleApplications.a1.realmAsHeading') + '</h3>' +
      '<table><tr><th>' + t.html('consoleApplications.a1.colAs') +
      '</th><th>' + t.html('consoleApplications.a1.colIssuer') + '</th></tr>' +
      loaded.authorizationServers.realm.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.id) + '</code></td><td><code>' +
               kit.esc(row.issuer) + '</code></td></tr>';
      }).join('') + '</table>' + signed + '</div>' +

      '<div class="prm-panel prm-panel-fields">' +
      kit.note(t.html('consoleApplications.a1.fieldsOfForm')) +
      '<input type="hidden" name="metadata" value="' +
      kit.esc(loaded.compact) +
      '">' +
      '<input type="hidden" name="metadataSource" value="' +
      kit.esc(loaded.source) + '">' +
      '<input type="hidden" name="metadataFilename" value="' +
      kit.esc(loaded.filename) + '">' +
      '<table><tr><th>' + t.html('consoleApplications.a1.colSetting') +
      '</th><th>' + t.html('consoleApplications.a1.colValue') + '</th><th>' +
      t.html('consoleApplications.a1.colCameFrom') + '</th>' +
      '</tr>' +
      field('prm-identifier', 'identifier',
            t.html('consoleApplications.a1.identifier'), values.identifier,
            t.html('consoleApplications.a1.fIdentifier')) +
      field('prm-name', 'name', t.html('consoleApplications.a1.name'),
            values.name, t.html('consoleApplications.a1.fName')) +
      field('prm-client-id', 'field.oauthClientId',
            '<code>oauthClientId</code>', values.clientId,
            t.html('consoleApplications.a1.fClientId')) +
      field('prm-base', 'field.oauthPermissionBaseUri',
            '<code>oauthPermissionBaseUri</code>', values.baseUri,
            t.html('consoleApplications.a1.fBase')) +
      field('prm-audience', 'field.oauthAudience',
            '<code>oauthAudience</code>', values.audience,
            t.html('consoleApplications.a1.fAudience'), true) +
      field('prm-permissions', 'field.oauthPermission',
            '<code>oauthPermission</code>', values.permissions,
            t.html('consoleApplications.a1.fPermissions'), true) +
      field('prm-details-types', 'field.oauthAuthorizationDetailsType',
            '<code>oauthAuthorizationDetailsType</code>', values.detailsTypes,
            t.html('consoleApplications.a1.fDetailsTypes'), true) +
      (values.url
        ? field('prm-url-field', 'field.oauthResourceMetadataUrl',
                '<code>oauthResourceMetadataUrl</code>', values.url,
                t.html('consoleApplications.a1.fUrl'))
        : '') +
      '</table>' +
      '<h3>' + t.html('consoleApplications.a1.membersHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a1.membersA') +
      (loaded.extensions.length
        ? t.html('consoleApplications.a1.extensionsA',
                 { n: loaded.extensions.length }) +
          loaded.extensions.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(', ') + t.html('consoleApplications.a1.extensionsB')
        : '') +
      t.html('consoleApplications.a1.membersB')) +
      (memberRows
        ? '<table><tr><th>' + t.html('consoleApplications.a1.colMember') +
          '</th><th>' + t.html('consoleApplications.a1.colValue') +
          '</th><th>' + t.html('consoleApplications.a1.colWhatItIs') +
          '</th></tr>' +
          memberRows + '</table>'
        : '') +
      '</div></div>';
    return html;
  }

  // The banners above the tabs: the authorization-server comparison, section
  // 3.3, and every warning the reading produced. ABOVE the tabs rather than on
  // one of them, because a reader on the raw JSON tab must not miss that none
  // of the authorization servers is this realm's.
  /**
   * Draws the banners above the metadata tabs: how the authorization servers
   * compare with this realm's, section 3.3, and every reading warning.
   *
   * @param loaded - the loaded document and what it was read as
   * @param t - the page's translator (#539)
   * @returns the banners as HTML
   */
  static resourceMetadataBanners(loaded, t) {
    const servers = loaded.authorizationServers;
    let html = '';
    if (!servers.listed) {
      html += kit.note(t.html('consoleApplications.a1.namesNoAs'));
    } else if (servers.allMatched) {
      html += '<div class="ok">' + t.html('consoleApplications.a1.allMatch') +
        servers.rows.map(function (row) {
          return t.html('consoleApplications.a1.issuerIs',
                        { issuer: row.issuer,
                          as: row.authorizationServer });
        }).join(', ') + '.</div>';
    } else {
      const unmatched = servers.rows.filter(function (row) {
        return !row.matched;
      });
      // NOT kit.warn(), which folds prose longer than a line behind its opening
      // sentence: the issuers that did not match ARE this banner, and a fold
      // would put them where a reader skimming for the colour does not look.
      html += '<div class="warn">' +
        t.html('consoleApplications.a1.unmatchedA',
               { u: unmatched.length, listed: servers.listed }) +
        unmatched.map(function (row) {
          return '<code>' + kit.esc(row.issuer) + '</code>';
        }).join(', ') +
        t.html('consoleApplications.a1.unmatchedB', { u: unmatched.length }) +
        servers.realm.map(function (row) {
          return '<code>' + kit.esc(row.issuer) + '</code>';
        }).join(', ') + '.</div>';
    }
    // `why` is the reading's own sentence, drawn as it comes (#539).
    const check = loaded.resourceCheck;
    if (check.checked && check.matches) {
      html += '<div class="ok"><strong>' +
              t.html('consoleApplications.a1.section33') + '</strong> ' +
              kit.esc(check.why) + '</div>';
    } else if (!check.checked) {
      html += kit.note(t.html('consoleApplications.a1.section33NotChecked') +
                        kit.esc(check.why));
    }
    if (loaded.warnings.length) {
      html += '<div class="warn">' +
        t.html('consoleApplications.a1.thingsToKnow',
               { n: loaded.warnings.length }) + '<ul>' +
        loaded.warnings.map(function (one) {
          return '<li>' + kit.esc(one) + '</li>';
        }).join('') + '</ul></div>';
    }
    return html;
  }

  // One JSON value, readable in a table cell.
  /**
   * Draws one JSON value readably in a table cell.
   *
   * @param value - the value
   * @param t - the page's translator (#539)
   * @returns the cell's HTML
   */
  static resourceMetadataValueCell(value, t) {
    if (Array.isArray(value)) {
      return value.map(function (one) {
        return '<code>' + kit.esc(typeof one === 'string' ? one :
                                   JSON.stringify(one)) + '</code>';
      }).join('<br>') || '<span class="state-none">' +
        t.html('consoleApplications.a1.empty') + '</span>';
    }
    return '<code>' + kit.esc(typeof value === 'string' ? value :
                               JSON.stringify(value)) + '</code>';
  }

  // What the third tab's boxes hold: the plan's defaults, or — on a redraw
  // after a refused create — what the reader had typed. A key present in the
  // posted body is what they typed, including an emptied box.
  /**
   * Returns what the imported metadata's editable fields hold: the plan's
   * defaults, or what was typed when a refused create is redrawn.
   *
   * @param loaded - the loaded document and its plan
   * @param draft - the posted form, or nothing
   * @returns the field values, with the document's members under `members`
   */
  static resourceMetadataValues(loaded, draft) {
    const plan = loaded.plan;
    const posted = draft || null;
    const pick = function (key, fallback) {
      return posted && Object.prototype.hasOwnProperty.call(posted, key)
        ? String(posted[key]) : fallback;
    };
    const members = {};
    loaded.members.forEach(function (row) {
      if (!row.known || row.type === 'jwt') {
        return;
      }
      const fallback = Array.isArray(row.value) ? row.value.join('\n')
                                                : String(row.value);
      members[row.member] = pick('metadata.' + row.member, fallback);
    });
    return {
      identifier: pick('identifier', plan.identifier),
      name: pick('name', plan.name),
      clientId: pick('field.oauthClientId', plan.clientId),
      baseUri: pick('field.oauthPermissionBaseUri', plan.baseUri),
      audience: pick('field.oauthAudience', plan.audience),
      permissions: pick('field.oauthPermission',
                        plan.permissionLines.join('\n')),
      detailsTypes: pick('field.oauthAuthorizationDetailsType',
                         (plan.detailsTypeLines || []).join('\n')),
      url: pick('field.oauthResourceMetadataUrl', loaded.url),
      members: members
    };
  }

  // The fields the new-application form draws in a view, out of the answer's
  // `fields` (#446): every field in the advanced view, the declared ones, the
  // overrides and a service provider's key sources in the simplified one,
  // less the ones a loaded protected resource metadata document owns.
  /**
   * Picks the fields the new-application form draws in a view.
   *
   * @param json - the form's answer, whose `fields` are every field, typed
   * @param view - `simple` or `advanced`
   * @param omit - attributes to leave out
   * @returns the rows
   */
  static newApplicationFieldRows(json, view, omit) {
    const skip = omit || [];
    const rows = json.fields.filter(function (row) {
      return skip.indexOf(row.attribute) < 0 &&
             (view === 'advanced' || row.inSimple);
    });
    return rows;
  }

  /**
   * Draws the notes at the foot of New application.
   *
   * @param store - the persistence store's `persistsDirectory` and `mode`
   * @param t - the page's translator (#539)
   * @returns the notes as HTML
   */
  static newApplicationNotes(store, t) {
    return (
      kit.note(t.html('consoleApplications.a1.declaringA') +
      '<a href="/admin/applications">' +
      t.html('consoleApplications.a1.applicationsLink') + '</a>' +
      t.html('consoleApplications.a1.declaringB')) +
      kit.note(t.html('consoleApplications.a1.declaredVsHappened')) +
      kit.note(t.html('consoleApplications.a1.oneEntryRefused')) +
      // WHETHER an application entry survives a restart is a property of the
      // whole service rather than of this page, which is why this note is
      // computed here rather than asserted: an application IS a directory
      // entry, so it persists exactly when the directory does.
      (store.persistsDirectory
        ? '<div class="ok">' +
          t.html('consoleApplications.a1.survivesA', { mode: store.mode }) +
          '<a href="/admin/persistence">' +
          t.html('consoleApplications.a1.persistence') + '</a>.</div>'
        : kit.note(t.html('consoleApplications.a1.notPersistedA') +
          '<a href="/admin/persistence">' +
          t.html('consoleApplications.a1.persistence') + '</a>' +
          t.html('consoleApplications.a1.notPersistedB'))));
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const t = ctx.t;
    const given = json.state || {};
    const row = json;
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/applications', ctx.query),
                         {})) + '">';
    let inner;
    // An identifier with no entry is a not-found answer, whose words stay
    // English with the other refusals (#539).
    if (!json.found) {
      inner = '<p class="warn">No application called <code>' +
          kit.esc(json.identifier) +
          '</code> is recorded here. That is not the same as one this ' +
          'service has refused: an entry appears the first time an ' +
          'identifier is ACCEPTED, so a client whose every request was ' +
          'turned away has none.</p>' + applicationsLinks(ctx.t);
    } else {
      // EVERY attribute the entry carries, operational ones and entryDN
      // included.
      // This used to be the schema half minus the twelve names applications.js
      // reads into named members, under a heading that said "every attribute
      // the
      // entry carries" — so objectClass, cn, appIdentifier, both timestamps and
      // the DN itself were all missing from the one table on this service whose
      // whole job is to be complete. Credentials are masked in it (#446).
      const nav = kit.pageNavPair('/admin/applications',
        kit.pageParamsOf(ctx.query),
                                   json.attributesPaging);
      const attrHtml = json.attributesShown.map(function (attr) {
        // What each attribute MEANS rather than only what it holds. The
        // registry's own table is the first answer and is the same table the
        // entry was written from — a second description here would be the one
        // that went stale — and applicationAttributeNote() carries the other
        // three cases.
        const note = json.page.notes[attr.name] ||
                     { text: '', sensitive: false };
        // The two titles were raw text in the markup, an apostrophe and all,
        // so their messages go in unescaped, as `t.html` returns them (#539).
        return '<tr><td><code>' + kit.esc(attr.name) + '</code>' +
          (note.sensitive ? ' <span class="state-revoked">' +
           t.html('consoleApplications.a2.credentialBadge') + '</span>' :
           '') +
          (attr.sealedAtRest
            ? ' <span class="state-valid" title="' +
              t.html('consoleApplications.a2.sealedTitle') + '">' +
              t.html('consoleApplications.a2.sealedAtRest') + '</span>'
            : '') +
          (attr.operational
            ? ' <span class="state-none" title="' +
              t.html('consoleApplications.a2.operationalTitle') + '">' +
              t.html('consoleApplications.a2.operational') + '</span>'
            : '') +
          '</td><td>' + attr.values.map(function (v) {
            return '<code>' + kit.esc(v) + '</code>';
          }).join('<br>') + '</td><td class="sub">' + kit.esc(note.text) +
            '</td></tr>';
      }).join('');

      // A refused save is a refusal, and stays English (#539).
      const refused = given.error && given.error.length
        ? '<div class="warn"><strong>The save was refused.</strong><ul>' +
          given.error.map(function (one) {
            return '<li>' + kit.esc(one) + '</li>';
          }).join('') + '</ul></div>'
        : '';
      // THE PAGE IS TABS (2026-10-01), one per section that has something to
      // show, so a reader is not scrolling past a dozen sections to reach one.
      // `kit.tabbedPanels()` argues the mechanism: no script, the fragment
      // decides.
      // A TAB FOR A PROTOCOL THIS APPLICATION IS NOT DECLARED FOR IS NOT
      // DRAWN (rcbj, 2026-10-01): the page offers what its protocols use.
      const declaredHere = [].concat(row.allowedProtocols || []);
      const forFamilies = function (families, html) {
        return families.some(function (one) {
          return declaredHere.indexOf(one) >= 0;
        }) ? html : '';
      };
      const OAUTH = ['oauth2', 'oidc', 'oid4vci', 'mtls'];
      const metadataUrl = ApplicationsPage.firstFieldValue(row,
                                                           'samlSpMetadataUrl');
      const consumedAt = ApplicationsPage.firstFieldValue(row,
        'samlSpMetadataConsumedAt');
      const panels = [
        { id: 'tab-overview',
          label: t.text('consoleApplications.a2.tabOverview'),
          html: '<h3>' + t.html('consoleApplications.a2.whatItIs') + '</h3>' +
        '<table><tr><th>' + t.html('consoleApplications.a2.colThing') +
        '</th><th>' + t.html('consoleApplications.a2.colValue') +
        '</th></tr>' +
        // FIRST, because it is the thing this page could not previously answer:
        // where in the tree this application lives. The registry is the
        // directory, so the DN is what an ldapsearch or an ldapmodify is aimed
        // at, and a console that showed only the cn made an operator
        // reconstruct
        // it.
        '<tr><td>' + t.html('consoleApplications.a2.dn') + '</td><td>' +
        (row.dn
          ? '<code>' + kit.esc(row.dn) + '</code>' +
            (row.identifier === row.dnLabel ? '' :
              '<div class="sub">' +
              t.html('consoleApplications.a2.rdnDigestA') + '<code>' +
              kit.esc(row.identifier) +
              '</code>' + t.html('consoleApplications.a2.rdnDigestB') +
              '</div>')
          : '<span class="state-none">' +
            t.html('consoleApplications.a2.noDirectory') + '</span>') +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a2.name') + '</td><td>' +
        kit.esc(row.name) + '</td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a2.kind') + '</td><td>' +
        ApplicationsPage.applicationKindCells(row) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a2.protocols') +
        '</td><td>' +
        ApplicationsPage.applicationProtocolCell(row,
          json.page.config.protocols, ctx.t) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a2.registered') +
        '</td><td>' +
          ApplicationsPage.applicationRegisteredCell(row, ctx.t) +
        '</td></tr><tr><td>' + t.html('consoleApplications.a2.firstSeen') +
        '</td><td><code>' + kit.esc(row.firstSeen) +
        '</code></td></tr><tr><td>' +
        t.html('consoleApplications.a2.lastSeen') +
        '</td><td><code>' + kit.esc(row.lastSeen) +
        '</code></td></tr><tr><td>' +
        t.html('consoleApplications.a2.description') + '</td><td>' +
        (row.description
          ? kit.esc(row.description)
          : '<span class="state-none">' +
            t.html('consoleApplications.a2.nothingRecorded') + '</span>') +
        '</td></tr>' +
        '</table>' +
            ApplicationsPage.protocolFamilySection(row, t) },
        { id: 'tab-config',
          label: t.text('consoleApplications.a2.tabConfig'),
          html: ApplicationsPage.applicationFieldsSection(ctx, row, carryBack,
            given) },
        // EVERY CREDENTIAL IN ONE PLACE (rcbj, 2026-10-01): the DID key pair is
        // here as well as on the DID configuration tab, for an application
        // declared for `did`.
        { id: 'tab-credentials',
          label: t.text('consoleApplications.a2.tabCredentials'),
          html: forFamilies(OAUTH,
            ApplicationsPage.applicationCredentialsSection(ctx, json,
              carryBack)) +
            forFamilies(['did'], '<h3 id="credentials-did">' +
              t.html('consoleApplications.a2.didKeyPair') + '</h3>' +
              ApplicationsPage.applicationDidPanel(ctx, row, carryBack,
                'credentials')) +
            forFamilies(['acme', 'est', 'scep'],
              '<h3 id="credentials-enroll">' +
              t.html('consoleApplications.a2.enrollHeading') +
              '</h3>' + ApplicationsPage.applicationEnrollmentPanel(ctx,
                row, carryBack,
                                                            'credentials')) },
        { id: 'tab-origins',
          label: t.text('consoleApplications.a2.tabOrigins'),
          html: ApplicationsPage.applicationCorsSection(row, carryBack, t) },
        // THE ACCESS-TYPE CATALOGUE (#432 phase 4): the types this
        // application, as a resource server, owns — read by RFC 9396 and GNAP
        // alike, so drawn for either.
        { id: 'tab-access-types',
          label: t.text('consoleApplications.a2.tabAccessTypes'),
          html: forFamilies(OAUTH.concat(['gnap']),
            ApplicationsPage.applicationAccessTypesSection(row, carryBack,
              t)) },
        // THE CLAIMS ITS OWN SCOPES CARRY (2026-10-09): per permission it
        // exposes as a resource server, the catalogue attributes an access
        // token addressed to it carries when that permission is granted.
        { id: 'tab-scope-claims',
          label: t.text('consoleApplications.sc.tab'),
          html: forFamilies(OAUTH,
            ApplicationsPage.applicationScopeClaimsSection(ctx, row,
              carryBack)) },
        { id: 'tab-signals', label: 'Shared Signals',
          html: forFamilies(['ssf'],
            ApplicationsPage.applicationSignalsSection(json,
            carryBack, ctx.write, t)) },
        { id: 'tab-statements',
          label: t.text('consoleApplications.a2.tabStatements'),
          html: forFamilies(OAUTH,
            ApplicationsPage.applicationSoftwareStatementSection(ctx,
            json, carryBack)) },
        { id: 'tab-addresses',
          label: t.text('consoleApplications.a2.tabAddresses'),
          html: ApplicationsPage.applicationObservedAddressesSection(ctx, json,
            carryBack) },
        // AFTER the generic attribute editor in the page this was. The editor
        // can already write `oauthDelegatedPermission` by hand — it is an
        // ordinary multi-valued attribute in the EDITABLE table — so this
        // section is a second DOOR onto it and not a second place it lives,
        // which is the one-store rule /admin/token-lifetimes' header argues.
        { id: 'tab-permissions',
          label: t.text('consoleApplications.a2.tabPermissions'),
          html: forFamilies(OAUTH,
            ApplicationsPage.applicationPermissionsSection(ctx, row,
              carryBack)) },
        // AND WHAT IT MAY DO AS ITSELF (#93): the roles it holds. FIRST, THE
        // ROLES IT REQUIRES (#458), moved here from the Configuration grid:
        // the question asked before any other, so drawn above the one asked
        // after it, and the two relations side by side where a reader can see
        // that they are opposite.
        { id: 'tab-roles', label: t.text('consoleApplications.a2.tabRoles'),
          html: ApplicationsPage.applicationRequiredRolesSection(row,
            json.page.roles, carryBack, t) +
            ApplicationsPage.applicationRolesSection(row, json.page.roles,
              carryBack, t) },
        // THE METADATA REFRESH, the only control on this page that reaches off
        // this machine, drawn only for an application that names a URL — see
        // sp_metadata.ts.
        { id: 'tab-metadata',
          label: t.text('consoleApplications.a2.tabMetadata'),
          html: !forFamilies(['saml2'],
            'x') ? '' : (metadataUrl
          ? '<h2>' + t.html('consoleApplications.a2.spMetadataHeading') +
            '</h2>' +
            kit.note(t.html('consoleApplications.a2.spMetadataA') + '<code>' +
                      kit.esc(metadataUrl) +
            '</code>' + t.html('consoleApplications.a2.spMetadataB') + '<a ' +
            'href="/admin/saml2?sp=' + encodeURIComponent(row.identifier) +
            '">' + t.html('consoleApplications.a2.saml2Page') + '</a>' +
            t.html('consoleApplications.a2.spMetadataC')) +
            '<form method="post" action="/admin/applications">' + carryBack +
            '<div class="formrow">' +
            '<input type="hidden" name="action" value="refresh-metadata">' +
            '<input type="hidden" name="application" value="' +
            kit.esc(row.identifier) + '"><button ' +
            'type="submit">' +
            t.html('consoleApplications.a2.refreshMetadata') +
            '</button><span class="sub">' +
            (consumedAt
              ? t.html('consoleApplications.a2.consumedA') +
                kit.esc(consumedAt) +
                t.html('consoleApplications.a2.consumedB')
              : t.html('consoleApplications.a2.notConsumed')) +
            t.html('consoleApplications.a2.dialsAnything') +
            '</span></div></form>'
          : '') },
        { id: 'tab-entry', label: t.text('consoleApplications.a2.tabEntry'),
          html:       '<h2>' + t.html('consoleApplications.a2.entryHeading') +
            '</h2><p class="sub">' +
            t.html('consoleApplications.a2.entryNote') + '</p>' +
        (row.dn
          ? '<p class="sub"><code>' + kit.esc(row.dn) + '</code>' +
            (row.createdAt ?
             t.html('consoleApplications.a2.createdAt') + '<code>' +
             kit.esc(row.createdAt) + '</code>' : '') +
            (row.modifiedAt ?
             t.html('consoleApplications.a2.modifiedAt') + '<code>' +
             kit.esc(row.modifiedAt) + '</code>' : '') +
            (row.origin ?
             t.html('consoleApplications.a2.writtenBy') + '<code>' +
             kit.esc(row.origin) + '</code>' : '') +
            '</p>'
          : '') +
        nav.head +
        '<table><tr><th>' + t.html('consoleApplications.a2.colAttribute') +
        '</th><th>' + t.html('consoleApplications.a2.colValue') + '</th><th>' +
        t.html('consoleApplications.a2.colWhatItIs') + '</th></tr>' +
        // Reachable only where no directory is loaded in this process. Every
        // real
        // entry carries objectClass, cn, appIdentifier and its two timestamps
        // at
        // the least, so "no attributes" is now a statement about the STORE
        // rather
        // than about this application — which is what it says.
        (attrHtml || '<tr><td colspan="3">' +
         t.html('consoleApplications.a2.noEntry') + '</td></tr>') +
        '</table>' +
        nav.foot +
            // THE ONE-ATTRIBUTE FORMS reach every editable attribute by name,
            // folded, for what the grid leaves to a control of its own and for
            // an ldapmodify-shaped edit.
        '<details class="fold section"><summary><h3>' +
        t.html('consoleApplications.a2.oneAttrHeading') + '</h3></summary>' +
        kit.note(t.html('consoleApplications.a2.oneAttrNote')) +
        '<form method="post" action="/admin/applications">' + carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="set"><input ' +
        'type="hidden" name="application" value="' + kit.esc(row.identifier) +
        '"><label for="setattr">' + t.html('consoleApplications.a2.setLabel') +
        '</label><select id="setattr" ' +
        'name="attribute">' +
          ApplicationsPage.editableOptions(json.page.editable.set, '', t) +
        '</select><label ' +
        'for="setval">' + t.html('consoleApplications.a2.to') +
        '</label><input type="text" id="setval" name="value" ' +
        'size="34" placeholder="' +
        kit.esc(t.text('consoleApplications.a2.emptyClears')) + '"><button ' +
        'type="submit">' + t.html('consoleApplications.a2.setButton') +
        '</button></div></form><form method="post" ' +
        'action="/admin/applications">' + carryBack + '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="add"><input ' +
        'type="hidden" name="application" value="' + kit.esc(row.identifier) +
        '"><label for="addattr">' + t.html('consoleApplications.a2.addTo') +
        '</label><select id="addattr" ' +
        'name="attribute">' +
        ApplicationsPage.editableOptions(json.page.editable.multi,
          'oauthRedirectUri', t) +
        '</select><label for="addval">' +
        t.html('consoleApplications.a2.theValue') + '</label><input ' +
        'type="text" ' +
        'id="addval" name="value" size="34" required><button ' +
        'type="submit">' + t.html('consoleApplications.a2.add') +
        '</button></div></form><form method="post" ' +
        'action="/admin/applications">' + carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="remove"><input type="hidden" name="application" ' +
        'value="' + kit.esc(row.identifier) + '">' +
        '<label for="remattr">' + t.html('consoleApplications.a2.removeFrom') +
        '</label>' +
        // NO `row` HERE, AND THAT IS THE RULE READ EXACTLY: the family scope
        // refuses a SET and an ADD and never a REMOVE, for
        // updateApplication()'s
        // reason — a value can arrive by `ldapmodify` or be left behind when a
        // family is untimed from the entry, and a console that would not offer
        // to
        // remove it would be the one door that could tidy it up, shut. So this
        // select keeps offering everything editable. Nothing family-scoped is
        // `multi` today; the asymmetry is here so that the first one that is
        // behaves correctly.
        '<select id="remattr" name="attribute">' +
        ApplicationsPage.editableOptions(json.page.editable.multiAll,
          'oauthRedirectUri', t) +
        '</select>' +
        '<label for="remval">' + t.html('consoleApplications.a2.theValue') +
        '</label>' +
        '<input type="text" id="remval" name="value" size="34" required>' +
        '<button type="submit">' + t.html('consoleApplications.a2.remove') +
        '</button>' +
        '</div></form>' +
        kit.note(t.html('consoleApplications.a2.wontChange')) +
        '</details>' },
        { id: 'tab-remove', label: t.text('consoleApplications.a2.tabRemove'),
          html:       '<h2>' + t.html('consoleApplications.a2.takeOutHeading') +
            '</h2>' +
        (row.registered
          ? '<form method="post" action="/admin/applications">' + carryBack +
            '<div class="formrow"><input type="hidden" name="action" ' +
            'value="revoke-registration"><input type="hidden" ' +
            'name="application" value="' + kit.esc(row.identifier) +
            '"><button type="submit">' +
            t.html('consoleApplications.a2.revokeRegistration') +
            '</button><span class="sub">' +
            t.html('consoleApplications.a2.revokeRegistrationNote') +
            '</span></div></form>'
          : kit.note(t.html('consoleApplications.a2.noRegistration'))) +
        '<form method="post" action="/admin/applications">' + carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="forget"><input type="hidden" name="application" ' +
        'value="' + kit.esc(row.identifier) + '"><button ' +
        'type="submit" class="danger">' +
        t.html('consoleApplications.a2.deleteEntry') + '</button><span ' +
        'class="sub">' +
        t.html('consoleApplications.a2.deleteEntryNote',
               { n: row.authentications }) +
        '</span></div></form>' }
      ];
      // A CREDENTIAL JUST REVEALED (#446): shown once, here, on the page that
      // answered the reveal, and never in a link.
      const revealed = given.revealed
        ? '<div class="ok"><strong>' + (given.revealed.secret ===
            'registration-access-token'
            ? t.html('consoleApplications.a2.revealedRat')
            : t.html('consoleApplications.a2.revealedSecret') + '<code>' +
              kit.esc(given.revealed.secret) +
              '</code>') + '</strong>: <code>' +
          kit.esc(given.revealed.value) + '</code> ' +
          '<span class="sub">' + t.html('consoleApplications.a2.shownOnce') +
          '</span></div>'
        : '';
      inner = kit.flash(refused + revealed) +
        '<h2><code>' + kit.esc(row.identifier) + '</code></h2>' +
        '<div class="tiles">' +
        kit.tile(row.authentications,
                 t.text('consoleApplications.a2.tileAuthentications')) +
        kit.tile(row.sessions, t.text('consoleApplications.a2.tileSessions')) +
        kit.tile(row.users, t.text('consoleApplications.a2.tileUsers')) +
        kit.tile(row.registered || row.registeredBy
                   ? t.text('consoleApplications.a2.yes')
                   : t.text('consoleApplications.a2.no'),
                  t.text('consoleApplications.a2.tileRegistered')) +
        '</div>' +
        kit.tabbedPanels('apptabs', panels) +
        ApplicationsPage.applicationsCaveat(t) +
        '<p class="sub"><a href="' +
        kit.esc('/admin/applications' +
                 kit.queryWith(kit.listViewOf('/admin/applications', ctx.query),
                           {})) +
        '">' + t.html('consoleApplications.a2.backToList') + '</a> &middot; ' +
        '<a href="/admin/ldap/applications">' +
        t.html('consoleApplications.a2.registryAsDirectory') + '</a></p>';

      // The same two lists the section above drew, for the reply. One pure
      // function, called twice with the same arguments — see its header.
    }

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION'S FIELD GRID (2026-09-30): the protocol families it is
  // declared for, as a row of checkboxes, and every field of
  // `applications.applicationFields()` the page can edit, typed, shown for the
  // families ticked — one form, saved by `update-fields`.
  //
  // **It posts to `/admin/applications/edit`, not to `/admin/applications`**,
  // because a refused save has to come back to THIS page with every box as
  // the reader left it, and the list page's 303 cannot carry a form. The same
  // route redraws for "+" and delete. `present` names every field drawn, so a
  // field emptied on the page is cleared; `protocolsPresent` says the
  // checkbox column was drawn, so unticking every box means "none".
  //
  // **It leaves out what has a control of its own**: credentials (the
  // Credentials section regenerates, issues and uploads them, and a secret
  // re-posted by every save is a secret in every request body) and what
  // `applications.applicationFields()` already leaves out.
  // ---------------------------------------------------------------------------
  /**
   * Draws an application's field grid: its declared families and every
   * editable field for them, in one form saved by `update-fields`.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's view
   * @param carryBack - the hidden `back` field
   * @param state - optional; a redraw: `draft`, the posted form
   * @returns the section as HTML
   */
  static applicationFieldsSection(ctx, row, carryBack, state?) {
    const t = ctx.t;
    const draft = state && state.draft ? state.draft : null;
    // The fields, typed, and the entry's values are the answer's
    // (`page.config`, #446); the credentials are not among them.
    const config = row.page.config;
    const rows = config.fields;
    // WHAT THE ENTRY HOLDS, WITH WHAT WAS POSTED LAID OVER IT. A redraw is of
    // one sub-tab's form, so only the attributes that form named (`present`)
    // are taken from the post; every other group shows the entry.
    const values = {};
    Object.keys(config.values).forEach(function (name) {
      values[name] = config.values[name].slice(0);
    });
    if (draft) {
      const posted = kit.gridValuesFromDraft(draft,
                                              config.longTextAttributes);
      String(draft.present || '').split(/[\s,]+/).forEach(function (name) {
        if (name && Object.prototype.hasOwnProperty.call(values, name)) {
          values[name] = posted[name] || [];
        }
      });
    }
    // A refused save's families were read off its body by the console
    // (`state.declared`): the page has the posted form, not the request.
    const declared = draft && draft.protocolsPresent && state.declared
      ? state.declared
      : [].concat(row.allowedProtocols || []);
    // A FIELD IS SHOWN when it belongs to every family or to a family this
    // application is declared for, and to no other (rcbj, 2026-10-01): a
    // value an undeclared family's field still holds is inert — product mode
    // refuses that family's requests — and stays visible on the Directory
    // entry tab. Decided here rather than by the create page's `:has()`
    // rules, because each group is a form of its own and the family
    // checkboxes are in another.
    const shown = rows.filter(function (one) {
      return one.everyFamily || one.families.some(function (f) {
        return declared.indexOf(f) >= 0;
      });
    });
    const groups = config.groups.filter(function (group) {
      return shown.some(function (one) { return one.group === group.id; }) ||
        // The Verifiable Credentials sub-tab carries the credential claims
        // section (#495) for an OpenID4VCI client, whose fields are all on
        // the OAuth one.
        (group.id === 'vc' && declared.indexOf('oid4vci') >= 0);
    });
    // The label arrives as text, and is escaped here as it always was: a
    // translation is text like any other (#539).
    const saveButton = function (label) {
      return '<div class="formrow"><button type="submit"' +
        kit.tip(t.html('consoleApplications.a2.saveTip')) + '>' +
        kit.esc(label) + '</button></div>';
    };
    const formOpen = function (group, present, extra?) {
      return '<form method="post" action="/admin/applications/edit#cfg-' +
        kit.esc(group) + '" class="appgrid">' + carryBack +
        '<input type="hidden" name="action" value="update-fields">' +
        '<input type="hidden" name="application" value="' +
        kit.esc(row.identifier) + '">' +
        '<input type="hidden" name="group" value="' + kit.esc(group) + '">' +
        (present ? '<input type="hidden" name="present" value="' +
                   kit.esc(present.join(' ')) + '">' : '') + (extra || '') +
        // THE DEFAULT BUTTON, first in the form, for the reason the create
        // form has one: Enter in a box presses the first submit button,
        // which would otherwise be a "+" or a delete.
        '<button type="submit" class="default-submit" tabindex="-1" ' +
        'aria-hidden="true">' + t.html('consoleApplications.a2.save') +
        '</button>';
    };
    const familiesPanel = '<div class="subpanel first" id="cfg-families">' +
      '<h3>' + t.html('consoleApplications.a2.familiesHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a2.familiesNote')) +
      formOpen('families', null,
               '<input type="hidden" name="protocolsPresent" value="1">') +
      '<div class="fg-protos" role="group" ' +
      'aria-label="' + t.html('consoleApplications.a2.familiesHeading') +
      '">' +
      // One box per CHOICE: OpenID4VCI and OpenID4VP are one, Verifiable
      // Credentials, ticked when either is declared and declaring both.
      config.familyChoices.map(function (choice) {
        const on = choice.families.some(function (family) {
          return declared.indexOf(family) >= 0;
        });
        return '<label class="fg-proto"' + kit.tip(choice.what) + '>' +
          '<input type="checkbox" name="protocol" value="' +
          kit.esc(choice.id) + '"' + (on ? ' checked' : '') + '>' +
          kit.esc(choice.label) + '</label>';
      }).join('') + '</div>' +
      saveButton(t.text('consoleApplications.a2.saveFamilies')) + '</form>' +
      '</div>';
    const groupPanels = groups.map(function (group) {
      const mine = shown.filter(function (one) {
        return one.group === group.id;
      });
      // THE SUB-TAB'S TWO VIEWS (#500): the simplified one unless this is a
      // redraw of this sub-tab's own form posted from the advanced one.
      const views = kit.hasViews(mine);
      const advancedRows = mine.filter(function (one) {
        return !one.simple;
      });
      const viewSwitch = !views ? ''
        : kit.viewSwitch(group.label,
            !!draft && String(draft.group || '') === group.id &&
              String(draft.view || '') === 'advanced',
            advancedRows.length,
            advancedRows.filter(function (one) {
              return (values[one.attribute] || []).some(function (v) {
                return String(v).trim() !== '';
              });
            }).length);
      // THE SUB-TAB'S SECTIONS: the realm's pages for this application, and
      // the DID and enrollment panels.
      const sections =
        (group.id === 'did'
          ? ApplicationsPage.applicationDidPanel(ctx, row, carryBack,
            'config') : '') +
        (group.id === 'enroll'
          ? ApplicationsPage.applicationEnrollmentPanel(ctx, row, carryBack,
            'config')
          : '') +
        // The realm's Token lifetimes, Custom claims and UserInfo claims
        // pages, and its Custom SAML attributes page, for this application
        // (2026-10-01): sections of the tab they belong to, under its fields
        // since #500.
        (group.id === 'oauth'
          ? ApplicationsPage.applicationTokenLifetimesSection(row, t) +
            ApplicationsPage.applicationClaimsSection(ctx, row, carryBack,
              ['access_token', 'id_token', 'userinfo'], 'cfg-oauth-claims',
              t.text('consoleApplications.a2.customClaims')) +
            // And the ticked catalogue beside the rows (#495).
            ApplicationsPage.applicationClaimSelectionSection(ctx, row,
              carryBack, ['access_token', 'id_token', 'userinfo'],
              'cfg-oauth')
          : '') +
        (group.id === 'saml'
          ? ApplicationsPage.applicationClaimsSection(ctx, row, carryBack,
              ['saml2', 'saml11'], 'cfg-saml-attributes',
              t.text('consoleApplications.a2.customSamlAttributes')) +
            ApplicationsPage.applicationClaimSelectionSection(ctx, row,
              carryBack, ['saml2', 'saml11'], 'cfg-saml')
          : '') +
        // The realm's Credential claims page, for an OpenID4VCI client
        // (#495).
        (group.id === 'vc'
          ? ApplicationsPage.applicationClaimSelectionSection(ctx, row,
              carryBack, ['credential'], 'cfg-vc')
          : '') +
        // The realm's Kerberos PAC claims page, for this service (#493):
        // added to a service ticket for one of its SPNs.
        (group.id === 'krb5'
          ? ApplicationsPage.applicationClaimsSection(ctx, row, carryBack,
              ['kerberos-pac'], 'cfg-krb5-claims',
              t.text('consoleApplications.a2.pacClaims'))
          : '');
      // The sub-tab's own fields, in one form.
      const fieldForm =
        // A sub-tab drawn only for a section has no fields to save.
        (!mine.length ? '' : formOpen(group.id, mine.map(function (one) {
          return one.attribute;
        })) + viewSwitch +
        kit.fieldGridOf(mine, config.groups, values,
                           { redraw: '/admin/applications/edit',
                             showSet: true, protocols: config.protocols,
                             views: views,
                             // The lists with a search, and the last
                             // search's results for each (#459).
                             searches: config.fieldSearches || {},
                             finds: (state && state.finds) || {},
                             // #488: the scope policy's warnings, by field.
                             fieldWarnings: config.fieldWarnings || {} }) +
        saveButton(t.text('consoleApplications.a2.saveGroup',
                          { label: group.label })) + '</form>');
      // ON OAUTH AND SAML THE FIELDS COME FIRST (rcbj, 2026-10-07, #500):
      // their simplified view is the attributes most often set, and the
      // claims and lifetimes sections were drawn above it. Elsewhere the
      // section is the sub-tab's main content and stays at its head.
      const fieldsFirst = group.id === 'oauth' || group.id === 'saml';
      return '<div class="subpanel" id="cfg-' + kit.esc(group.id) + '">' +
        (fieldsFirst ? fieldForm + sections : sections + fieldForm) +
        '</div>';
    }).join('');
    const bar = '<nav class="tabbar subbar" aria-label="' +
      t.html('consoleApplications.a2.tabConfig') + '">' +
      '<a class="first" href="#cfg-families">' +
      t.html('consoleApplications.a2.protocolFamilies') + '</a>' +
      groups.map(function (group) {
        return '<a href="#cfg-' + kit.esc(group.id) + '">' +
          kit.esc(group.label) + '</a>';
      }).join('') + '</nav>';
    return '<h2 id="fields">' + t.html('consoleApplications.a2.cfgHeading') +
      '</h2>' +
      kit.note(t.html('consoleApplications.a2.cfgNoteA') +
      '<a href="#tab-origins">' + t.html('consoleApplications.a2.tabOrigins') +
      '</a>' + t.html('consoleApplications.a2.cfgNoteB') + '<a ' +
      'href="#tab-roles">' + t.html('consoleApplications.a2.tabRoles') +
      '</a>' + t.html('consoleApplications.a2.cfgNoteC')) +
      '<div class="subtabs">' + bar + familiesPanel + groupPanels + '</div>';
  }

  /**
   * Draws an application's Credentials section: the client secret with its
   * regenerate and rotate forms, the assertion profiles' key pairs with
   * their issue, upload and take-off controls, and mutual TLS.
   *
   * The key-pair and mutual TLS parts are drawn only for an application
   * declared for OAuth 2.0 or OpenID Connect.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param json - the application's answer, with its `page`
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static applicationCredentialsSection(ctx, json, carryBack) {
    const t = ctx.t;
    const row = json;
    const state = json.page.credentials;
    const id = row.identifier;
    const hidden = function (name, value) {
      return '<input type="hidden" name="' + name + '" value="' +
             kit.esc(value) +
             '">';
    };
    const secret = state.clientSecret;
    const isoOf = function (seconds) {
      return new Date(seconds * 1000).toISOString();
    };
    // ONE ROW PER SECRET (2026-10-01, rcbj): its id and description, its
    // value behind a fold as the one secret always was, when it EXPIRES —
    // the column this section was asked for — and a Remove button.
    const secretRows = secret.secrets.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.id) + '</code>' +
        (one.primary ? ' <span class="state-valid" title="' +
          t.html('consoleApplications.a2.primaryTitle') + '">' +
          t.html('consoleApplications.a2.primary') + '</span>'
          : '') +
        (one.description ? '<div class="sub">' + kit.esc(one.description) +
          '</div>' : '') +
        (one.createdAt ? '<div class="sub">' +
          t.html('consoleApplications.a2.created') + '<code>' +
          kit.esc(isoOf(one.createdAt)) + '</code></div>' : '') +
        '</td><td>' + ApplicationsPage.revealControl(id, one.id,
          t.text('consoleApplications.a2.whatClientSecret'),
                                          carryBack, t) + '</td>' +
        '<td>' + (one.expiresAt
          ? '<code>' + kit.esc(isoOf(one.expiresAt)) + '</code>' +
            (one.expired ? '<div class="sub warn">' +
              t.html('consoleApplications.a2.expiredRefused') + '</div>' : '')
          : '<span class="state-none">' +
            t.html('consoleApplications.a2.never') + '</span>') + '</td>' +
        '<td><form method="post" action="/admin/applications">' + carryBack +
        hidden('action', 'remove-secret') + hidden('application', id) +
        hidden('secret', one.id) +
        '<button type="submit" class="danger">' +
        t.html('consoleApplications.a2.remove') + '</button></form></td>' +
        '</tr>';
    }).join('');
    const atCap = secret.secrets.length >= secret.max;
    const secretHtml = '<h3 id="credentials-secret">' +
      t.html('consoleApplications.a2.secretsHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a2.secretsNote',
                      { max: String(secret.max) })) +
      '<table><tr><th>' + t.html('consoleApplications.a2.colSecret') +
      '</th><th>' + t.html('consoleApplications.a2.colValue') + '</th><th>' +
      t.html('consoleApplications.a2.colExpires') + '</th><th></th>' +
      '</tr>' +
      (secretRows || '<tr><td colspan="4"><span class="state-none">' +
        t.html('consoleApplications.a2.noSecret') + '</span></td></tr>') +
      '</table>' +
      (secret.authMethod
        ? '<p class="sub">' + t.html('consoleApplications.a2.authMethod') +
          '<code>' + kit.esc(secret.authMethod) + '</code>.</p>' : '') +
      '<table><tr><th>' + t.html('consoleApplications.a2.colCredential') +
      '</th><th>' + t.html('consoleApplications.a2.colHeld') + '</th></tr>' +
      '<tr><td><code>appRegistrationAccessToken</code><div class="sub">' +
      t.html('consoleApplications.a2.ratDescription') + '</div></td><td>' +
      (secret.registrationAccessTokenHeld
        ? ApplicationsPage.revealControl(id, 'registration-access-token',
            t.text('consoleApplications.a2.whatRat'), carryBack, t)
        : '<span class="state-none">' +
          t.html('consoleApplications.a2.none') + '</span>') +
      '</td></tr></table>' +
      // ADD ONE BESIDE THE OTHERS (2026-10-01): the new secret is the newest,
      // so it becomes the primary; the others go on authenticating.
      (atCap
        ? kit.note(t.html('consoleApplications.a2.atCap',
                          { n: secret.secrets.length }))
        : '<form method="post" action="/admin/applications">' + carryBack +
          '<div class="formrow">' + hidden('action', 'add-secret') +
          hidden('application', id) +
          '<label for="secret-lifetime">' +
          t.html('consoleApplications.a2.lifetimeDays') + '</label>' +
          '<input type="number" id="secret-lifetime" name="lifetimeDays" ' +
          'min="0" max="730" step="1" placeholder="' +
          kit.esc(String(secret.defaultLifetimeDays)) + '">' +
          '<label for="secret-description">' +
          t.html('consoleApplications.a2.description') + '</label>' +
          '<input type="text" id="secret-description" name="description" ' +
          'size="28" maxlength="200" placeholder="' +
          kit.esc(t.text('consoleApplications.a2.whatFor')) + '">' +
          '<button type="submit">' +
          t.html('consoleApplications.a2.addSecret') + '</button>' +
          '<span class="sub">' +
          t.html('consoleApplications.a2.emptyLifetime',
                 { days: secret.defaultLifetimeDays
                     ? String(secret.defaultLifetimeDays) : 'never' }) +
          '</span></div></form>') +
      // ROTATION WITH AN OVERLAP (#49 P5): the one to use for a client in
      // service — the live secrets keep working while it changes over.
      (secret.held && !atCap
        ? '<form method="post" action="/admin/applications">' + carryBack +
          '<div class="formrow">' + hidden('action', 'rotate-secret') +
          hidden('application', id) +
          '<button type="submit">' +
          t.html('consoleApplications.a2.rotateSecret') + '</button>' +
          '<span class="sub">' +
          t.html('consoleApplications.a2.rotateNote',
                 { s: String(secret.overlapS) }) +
          '</span></div></form>'
        : '') +
      '<form method="post" action="/admin/applications">' + carryBack +
      '<div class="formrow">' + hidden('action', 'regenerate-secret') +
      hidden('application', id) +
      '<button type="submit"' + (secret.held ? ' class="danger"' : '') + '>' +
      (secret.held ? t.html('consoleApplications.a2.regenerateAll')
                   : t.html('consoleApplications.a2.generateSecret')) +
      '</button>' +
      '<span class="sub">' + (secret.held
        ? t.html('consoleApplications.a2.regenerateNote')
        : t.html('consoleApplications.a2.holdsNone')) +
      '</span></div></form>';

    const algOptions = state.ca.keyAlgorithms.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' + kit.esc(one.label) +
             '</option>';
    }).join('');
    const purposeHtml = state.purposes.map(function (p) {
      const names = p.attributes;
      const anchor = 'credentials-' + p.id;
      const chainCells = p.chain.length
        ? '<ol>' + p.chain.map(function (link) {
            return '<li>' + ApplicationsPage.certificateCells(link, t) +
              '</li>';
          }).join('') + '</ol>'
        : (p.held
          ? '<span class="state-none">' +
            t.html('consoleApplications.a2.noneStored') + '</span>'
          : '&mdash;');
      const managed = p.held
        ? '<table><tr><th>' + t.html('consoleApplications.a2.colFact') +
          '</th><th>' + t.html('consoleApplications.a2.colValue') +
          '</th></tr>' +
          '<tr><td>' + t.html('consoleApplications.a2.source') +
          '<div class="sub"><code>' + kit.esc(names.source) +
          '</code></div></td><td><code>' + kit.esc(p.source) + '</code>' +
          '<div class="sub">' + (keySourceSentence(p.source, t) ||
                                 kit.esc(p.source)) + '</div></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a2.certificate') +
          '<div class="sub"><code>' +
          kit.esc(names.certificate) +
          '</code></div></td><td>' +
            ApplicationsPage.certificateCells(p.certificate, t) +
          '</td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a2.chain') +
          '<div class="sub"><code>' + kit.esc(names.chain) +
          '</code></div></td><td>' + chainCells + '</td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a2.keyHandle') +
          '<div class="sub"><code>' + kit.esc(names.handle) +
          '</code></div></td><td><code>' + kit.esc(p.handle || '—') +
          '</code> <span class="sub">(' + kit.esc(p.handleLabel) +
          ')</span></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a2.privateKey') +
          '<div class="sub"><code>' +
          kit.esc(names.privateKey) + '</code></div></td><td>' +
          (p.privateKeyHeld
            ? '<span class="state-valid">' +
              t.html('consoleApplications.a2.heldHere') + '</span>' +
              (p.sealedAtRest
                ? t.html('consoleApplications.a2.sealedSuffix') : '') +
              '<div class="sub">' +
              t.html('consoleApplications.a2.collectIt') +
              '</div>'
            : '<span class="state-none">' +
              t.html('consoleApplications.a2.notHeldHere') +
              '</span><div class="sub">' +
              t.html('consoleApplications.a2.keepsOwnKey') + '</div>') +
          '</td></tr><tr><td>' +
          t.html('consoleApplications.a2.declaredIssuer') +
          '<div class="sub"><code>' +
          kit.esc(names.issuer) +
          '</code></div></td><td>' + (p.issuers.length
            ? p.issuers.map(function (iss) {
                return '<code>' + kit.esc(iss) + '</code>';
              }).join('<br>')
            : t.html('consoleApplications.a2.noIssuer')) +
          '</td></tr></table>'
        : kit.note(t.html('consoleApplications.a2.noKeyPair'));

      const issueForm = state.ca.available
        ? '<form method="post" action="/admin/pki">' + carryBack +
          '<div class="formrow">' + hidden('action', 'issue') +
          hidden('from', '/admin/applications') + hidden('identifier', id) +
          hidden('purpose', p.id) +
          '<label for="' + anchor + '-alg">' +
          t.html('consoleApplications.a2.keyAlgorithm') + '</label>' +
          '<select id="' + anchor + '-alg" name="leafKeyAlg">' +
          '<option value="">' + t.html('consoleApplications.a2.issuingCaAlg') +
          kit.esc(state.ca.keyAlg) +
          ')</option>' + algOptions + '</select>' +
          '<label for="' + anchor + '-days">' +
          t.html('consoleApplications.a2.days') + '</label>' +
          '<input type="number" id="' + anchor + '-days" name="days" min="1" ' +
          'value="' + kit.esc(String(state.ca.leafLifetimeDays)) + '">' +
          '<button type="submit">' + (p.held
            ? t.html('consoleApplications.a2.replaceFromCa')
            : t.html('consoleApplications.a2.issueFromCa')) + '</button>' +
          '</div></form>'
        : kit.note(t.html('consoleApplications.a2.noCaA') + '<a ' +
                    'href="/admin/pki">' +
                    t.html('consoleApplications.a2.buildOnPki') + '</a>' +
                    t.html('consoleApplications.a2.noCaB'));

      const uploadForm = '<form method="post" action="/admin/pki">' +
                         carryBack +
        hidden('action', 'upload-certificate') +
        hidden('from', '/admin/applications') + hidden('identifier', id) +
        hidden('purpose', p.id) +
        '<div class="formrow"><label for="' + anchor + '-cert">' +
        t.html('consoleApplications.a2.certificatePem') +
        '</label><textarea id="' + anchor + '-cert" name="certificate" ' +
        'rows="6" required placeholder="-----BEGIN ' +
        'CERTIFICATE-----"></textarea></div><div class="formrow"><label ' +
        'for="' + anchor + '-chain">' +
        t.html('consoleApplications.a2.chainPem') + '</label><textarea id="' +
        anchor +
        '-chain" name="chain" rows="6" placeholder="-----BEGIN ' +
        'CERTIFICATE-----"></textarea></div><div class="formrow"><button ' +
        'type="submit">' +
        (p.held ? t.html('consoleApplications.a2.replaceWithCert') :
         t.html('consoleApplications.a2.uploadCert')) +
        '</button></div></form>';

      const takeOff = p.held
        ? '<form method="post" action="/admin/pki">' + carryBack +
          '<div class="formrow">' + hidden('action', 'revoke') +
          hidden('from', '/admin/applications') + hidden('identifier', id) +
          hidden('purpose', p.id) +
          '<button type="submit" class="danger">' +
          t.html('consoleApplications.a2.takeOff') + '</button><span ' +
          'class="sub">' + t.html('consoleApplications.a2.takeOffNote') +
          '</span></div></form>'
        : '';

      // A registration problem is the view's sentence, drawn as it comes
      // (#539).
      const registered = p.registered;
      const registeredRows = p.id === 'jwt'
        ? (registered.keys.length
          ? '<table><tr><th>kid</th><th>' +
            t.html('consoleApplications.a2.colKey') + '</th><th>' +
            t.html('consoleApplications.a2.certificate') + '</th></tr>' +
            registered.keys.map(function (key) {
              return '<tr><td><code>' + kit.esc(key.kid || '—') +
                     '</code></td>' +
                '<td><code>' + kit.esc(key.kty) + '</code>' +
                (key.alg ? ' <code>' + kit.esc(key.alg) + '</code>' : '') +
                '</td><td>' + (key.certificate
                  ? ApplicationsPage.certificateCells(key.certificate, t)
                  : '<span class="state-none">' +
                    t.html('consoleApplications.a2.bareKey') + '</span>') +
                '</td></tr>';
            }).join('') + '</table>'
          : '<p class="sub">' + (registered.problem
            ? '<span class="state-revoked">' + kit.esc(registered.problem) +
              '</span>'
            : t.html('consoleApplications.a2.noneRegistered')) + '</p>')
        : (registered.certificates.length
          ? '<table><tr><th>' + t.html('consoleApplications.a2.certificate') +
            '</th></tr>' +
            registered.certificates.map(function (cert) {
              return '<tr><td>' +
                ApplicationsPage.certificateCells(cert, t) +
                '</td></tr>';
            }).join('') + '</table>'
          : '<p class="sub">' + (registered.problem
            ? '<span class="state-revoked">' + kit.esc(registered.problem) +
              '</span>'
            : t.html('consoleApplications.a2.noneRegistered')) + '</p>');

      return '<h3 id="' + anchor + '">' + kit.esc(p.label) + '</h3>' +
        managed +
        '<h4>' + t.html('consoleApplications.a2.regenerateHeading') +
        '</h4>' +
        kit.note(t.html('consoleApplications.a2.regenerateKeyNote')) +
        issueForm + uploadForm + takeOff +
        '<h4>' + t.html('consoleApplications.a2.registeredHeading') +
        '</h4>' +
        kit.note('<code>' + kit.esc(registered.attribute) + '</code>' +
        t.html('consoleApplications.a2.registeredNote')) +
        registeredRows;
    }).join('');

    // THE ASSERTION PROFILES ONLY FOR AN OAUTH 2.0 CLIENT (2026-09-13). See
    // `oauthDeclared` in admin-core/admin_views.ts. The markup above is still
    // built and then dropped rather than guarded, so the two branches cannot
    // drift in what a profile section says.
    const heldElsewhere = state.purposes.filter(function (p) {
      return p.held || p.issuers.length;
    });
    const assertionHtml = state.oauthDeclared
      ? purposeHtml
      : '<h3 id="credentials-assertions">' +
        t.html('consoleApplications.a2.assertionHeading') + '</h3>' +
        kit.note(t.html('consoleApplications.a2.assertionNote')) +
        (heldElsewhere.length
          ? kit.warn(t.html('consoleApplications.a2.alreadyCarriesA') +
                      heldElsewhere.map(function (p) {
              return kit.esc(p.label);
            }).join(t.html('consoleApplications.a2.and')) +
            t.html('consoleApplications.a2.alreadyCarriesB'),
            t.text('consoleApplications.a2.stillInEffect'))
          : '');

    return '<h2 id="credentials">' +
      t.html('consoleApplications.a2.tabCredentials') + '</h2>' +
      kit.note(t.html('consoleApplications.a2.credentialsNote')) +
      secretHtml + assertionHtml +
      (state.oauthDeclared
        ? ApplicationsPage.applicationMtlsSection(state.mtls, id, carryBack, t)
        : '');
  }

  // ---------------------------------------------------------------------------
  // MUTUAL TLS — RFC 8705, ON THE APPLICATION'S OWN PAGE (2026-09-13).
  //
  // Both halves of the RFC read off one model (`applicationMtlsState()` in
  // admin-core/admin_views.ts): how the token endpoint will authenticate this
  // application by certificate, and whether its tokens are bound to one.
  //
  // **THE ISSUE CONTROL IS THE IMPLICIT MAPPING'S REGISTRATION.** A certificate
  // issued here names the application in its subjectAltName and is listed on
  // the application's record, and that is everything `tls_client_auth` needs —
  // so the subject parameters below are for a certificate from somebody ELSE's
  // authority, and are set with the attribute editor like every other
  // attribute. The issue answers with a page of downloads rather than a
  // redirect; see `answerIssuedTlsClientCertificate()`.
  //
  // **NO SCRIPT**: a form per certificate to revoke it, and two password
  // fields.
  // ---------------------------------------------------------------------------
  /**
   * Draws an application's RFC 8705 mutual TLS subsection: the certificates
   * issued to it with a revoke form each, the issue form, and the subject
   * parameters for a certificate from another authority.
   *
   * @param state - the mutual TLS model from `applicationMtlsState()`
   * @param id - the application's identifier
   * @param carryBack - the hidden `back` field every form carries
   * @param t - the page's translator (#539)
   * @returns the subsection as HTML
   */
  static applicationMtlsSection(state, id, carryBack, t) {
    const hidden = function (name, value) {
      return '<input type="hidden" name="' + name + '" value="' +
             kit.esc(value) +
             '">';
    };
    // The method and the subject values are the entry's, so they stay in the
    // code between messages rather than going in as parameters (#539).
    const methodSentence = state.certificateMethod
      ? t.html('consoleApplications.a2.mtlsHeldA') + '<code>' +
        kit.esc(state.authMethod) +
        '</code>' + t.html('consoleApplications.a2.mtlsHeldB')
      : t.html('consoleApplications.a2.mtlsNotA') +
        (state.authMethod ? '<code>' + kit.esc(state.authMethod) + '</code>'
                          : t.html('consoleApplications.a2.notSet')) +
        t.html('consoleApplications.a2.mtlsNotB');
    const rows = state.certificates.length
      ? '<table><tr><th>' + t.html('consoleApplications.a2.certificate') +
        '</th><th>' + t.html('consoleApplications.a2.colState') +
        '</th><th></th></tr>' +
        state.certificates.map(function (cert) {
          const revokeForm = cert.state === 'valid'
            ? '<form method="post" action="/admin/applications">' + carryBack +
              hidden('action', 'revoke-tls-client-certificate') +
              hidden('application', id) + hidden('serialHex', cert.serialHex) +
              '<div class="formrow"><select name="reason" ' +
              'aria-label="' + t.html('consoleApplications.a2.reason') + '">' +
              state.revocationReasons.map(function (reason) {
                return '<option value="' + kit.esc(reason) + '">' +
                       kit.esc(reason) +
                       '</option>';
              }).join('') + '</select><button type="submit" class="danger">' +
              t.html('consoleApplications.a2.revoke') +
              '</button></div></form>'
            : '';
          return '<tr><td><code>' + kit.esc(cert.subject) + '</code><div ' +
            'class="sub">' +
            (cert.label ? kit.esc(cert.label) + ' &middot; ' : '') +
            t.html('consoleApplications.a2.serial') + '<code>' +
            kit.esc(cert.serialHex) + '</code> &middot; ' +
            kit.esc(cert.keyAlg) +
            t.html('consoleApplications.a2.validUntil') + '<code>' +
            kit.esc(cert.notAfter) + '</code><br>' +
            t.html('consoleApplications.a2.thumbprint') + '<code>' +
            kit.esc(cert.thumbprint) + '</code></div></td><td><span ' +
              'class="state-' +
            (cert.state === 'valid' ? 'valid' : 'revoked') + '">' +
            kit.esc(cert.state) + '</span>' + (cert.reason
              ? '<div class="sub">' + kit.esc(cert.reason) + '</div>' : '') +
            '</td><td>' + revokeForm + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('consoleApplications.a2.noTlsCerts') +
        '</p>';
    const issueForm = state.caAvailable
      ? (state.active >= state.max
        ? kit.note(t.html('consoleApplications.a2.tlsAtMax',
                          { n: state.active }))
        : '<form method="post" action="/admin/applications">' + carryBack +
          hidden('action', 'issue-tls-client-certificate') +
          hidden('application', id) +
          '<div class="formrow"><label for="mtls-label">' +
          t.html('consoleApplications.a2.nameIt') + '</label>' +
          '<input id="mtls-label" name="label" maxlength="40" ' +
          'placeholder="' +
          kit.esc(t.text('consoleApplications.a2.instanceOne')) +
          '"><label for="mtls-alg">' + t.html('consoleApplications.a2.colKey') +
          '</label>' +
          '<select id="mtls-alg" name="keyAlg">' +
          state.keyAlgorithms.map(function (alg) {
            return '<option value="' + kit.esc(alg) + '"' +
                   (alg === state.defaultKeyAlg ? ' selected' : '') + '>' +
                   kit.esc(alg) + '</option>';
          }).join('') + '</select></div>' +
          '<div class="formrow"><label for="mtls-password">' +
          t.html('consoleApplications.a2.filePassword') +
          '</label><input type="password" id="mtls-password" name="password" ' +
          'minlength="' + state.passwordMin + '" required autocomplete=' +
          '"new-password"><label for="mtls-confirm">' +
          t.html('consoleApplications.a2.again') + '</label><input ' +
          'type="password" id="mtls-confirm" name="confirm" minlength="' +
          state.passwordMin + '" required autocomplete="new-password"></div>' +
          '<div class="formrow"><button type="submit">' +
          t.html('consoleApplications.a2.issueTlsCert') +
          '</button><span class="sub">' +
          t.html('consoleApplications.a2.shownOnceDownloads') +
          '</span></div></form>')
      : kit.note(t.html('consoleApplications.a2.mtlsNoCa') + '<a ' +
                  'href="/admin/pki">' +
                  t.html('consoleApplications.a2.buildOnPki') + '</a>.');
    const subjectRows = '<table><tr><th>' +
      t.html('consoleApplications.a2.colParameter') + '</th><th>' +
      t.html('consoleApplications.a2.colAttribute') + '</th>' +
      '<th>' + t.html('consoleApplications.a2.registered') + '</th></tr>' +
      state.subjects.map(function (subject) {
        return '<tr><td><code>' + kit.esc(subject.member) + '</code><div ' +
          'class="sub">' + kit.esc(subject.label) + '</div></td><td><code>' +
          kit.esc(subject.attribute) + '</code></td><td>' + (subject.value
            ? '<code>' + kit.esc(subject.value) + '</code>'
            : '<span class="state-none">' +
              t.html('consoleApplications.a2.none') + '</span>') +
          '</td></tr>';
      }).join('') + '</table>';
    const html = '<h3 id="credentials-tls-client">' +
      t.html('consoleApplications.a2.mtlsHeading') + '</h3>' +
      kit.note(methodSentence) +
      '<h4>' + t.html('consoleApplications.a2.issuedItHeading') + '</h4>' +
      kit.note(t.html('consoleApplications.a2.implicitA') + '<code>' +
      kit.esc(state.implicitName) +
      '</code>' + t.html('consoleApplications.a2.implicitB')) +
      rows + issueForm +
      '<h4>' + t.html('consoleApplications.a2.otherAuthorityHeading') +
      '</h4>' +
      kit.note(t.html('consoleApplications.a2.explicitA') + '<a ' +
      'href="/tls/trust">/tls/trust</a>' +
      t.html('consoleApplications.a2.explicitB') +
      (state.selfSignedThumbprint ? ' (<code>' +
        kit.esc(state.selfSignedThumbprint) + '</code>)'
        : t.html('consoleApplications.a2.noneParen')) +
      t.html('consoleApplications.a2.explicitC')) +
      subjectRows +
      '<h4>' + t.html('consoleApplications.a2.boundHeading') + '</h4>' +
      kit.note((state.bindingAvailable
        ? t.html('consoleApplications.a2.bindingYes')
        : t.html('consoleApplications.a2.bindingNo')) +
      '<code>' + kit.esc(state.boundTokensAttribute) + '</code>' +
      t.html('consoleApplications.a2.boundIs') + '<code>' +
      (state.boundTokens ? 'TRUE' : 'FALSE') + '</code>' + (state.boundTokens
        ? t.html('consoleApplications.a2.boundYes')
        : t.html('consoleApplications.a2.boundNo')));
    return html;
  }

  /**
   * Draws a certificate summary: subject, issuer, serial, expiry and key
   * type, or `none` or `unreadable`.
   *
   * @param summary - the certificate summary, or nothing
   * @param t - the page's translator (#539); none means the default,
   *   English in node
   * @returns the cell's HTML
   */
  static certificateCells(summary, t?) {
    // `web_users.ts` calls this with no translator: the default one is
    // English in node and the console's runtime passes its own (#539).
    t = t || kit.context().t;
    if (!summary) {
      return '<span class="state-none">' +
        t.html('consoleApplications.a2.none') + '</span>';
    }
    // The reason a certificate could not be read is the view's, drawn as it
    // comes (#539).
    if (summary.unreadable) {
      return '<span class="state-revoked">' +
             t.html('consoleApplications.a2.unreadable') +
             kit.esc(summary.unreadable) + '</span>';
    }
    return '<code>' + kit.esc(summary.subject) + '</code>' +
      '<div class="sub">' + t.html('consoleApplications.a2.issuedBy') +
      '<code>' + kit.esc(summary.issuer) +
      '</code>' +
      (summary.selfSigned ? t.html('consoleApplications.a2.selfSigned') : '') +
      ' &middot; ' + t.html('consoleApplications.a2.serial') + '<code>' +
      kit.esc(summary.serialHex) + '</code>' +
      t.html('consoleApplications.a2.validUntil') + '<code>' +
      kit.esc(summary.notAfter) + '</code>' +
      (summary.expired ? ' <span class="state-revoked">' +
        t.html('consoleApplications.a2.expired') + '</span>' : '') +
      ' &middot; ' + kit.esc(summary.keyType) + '</div>';
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION'S DID, ON ITS CONFIGURATION TAB (2026-10-01): the DID this
  // service advertises for it, the document's address (a link, so a reader can
  // see exactly what a resolver gets), whether it resolves yet, and the
  // *Generate a key pair* form. The form posts `generate-did-key` to
  // /admin/applications and is answered by a page carrying the private key
  // once; it is drawn for Admin Write only, like every write on the page.
  // ---------------------------------------------------------------------------
  /**
   * Draws the DID block on an application's Decentralized Identifier
   * configuration tab: its DID, its document, and the key-pair form.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's view
   * @param carryBack - the hidden `back` field the page's forms carry
   * @param where - `config` (the DID tab) or `credentials` (the
   *   Credentials tab), which the Generate form returns to
   * @returns the HTML
   */
  static applicationDidPanel(ctx, row, carryBack, where?) {
    const t = ctx.t;
    // What the document advertises is the answer's (`page.did`, #446).
    const facts = row.page.did;
    const identifier = String(row.identifier || '');
    const did = facts.did;
    const url = facts.url;
    const canWrite = ctx.write;
    const algorithms = ['ES256', 'ES384', 'EdDSA'];
    // Each algorithm's tooltip, by a literal key apiece: the catalog test
    // reads keys out of the source, so a key built from the name would be
    // one it could not see (#539).
    const algorithmTip = function (alg) {
      return alg === 'ES256'
        ? t.html('consoleApplications.a2.tipES256')
        : (alg === 'ES384' ? t.html('consoleApplications.a2.tipES384')
                           : t.html('consoleApplications.a2.tipEdDSA'));
    };
    const anchor = where === 'credentials' ? '#credentials-did' : '#cfg-did';
    const keys = facts.methods;
    const keyTable = keys.length
      ? '<table><tr><th>' +
        t.html('consoleApplications.a2.colVerificationMethod') + '</th><th>' +
        t.html('consoleApplications.a2.colKey') + '</th>' +
        '<th>' + t.html('consoleApplications.a2.colAlgorithm') + '</th><th>' +
        t.html('consoleApplications.a2.colPrivateHalf') + '</th></tr>' +
        keys.map(function (m) {
          return '<tr><td><code>' + kit.esc('#' + m.kid) +
            '</code></td><td>' + kit.esc(m.kty + (m.crv ? ' ' + m.crv : '')) +
            '</td><td>' + kit.esc(m.alg || '—') + '</td><td>' +
            (m.kept
              ? '<span class="state-valid">' +
                t.html('consoleApplications.a2.keptSealed') + '</span>'
              : '<span class="state-none">' +
                t.html('consoleApplications.a2.notHere') + '</span>') +
            '</td></tr>';
        }).join('') + '</table>' +
        kit.note(t.html('consoleApplications.a2.didKeptNote'))
      : '<p class="sub">' + t.html('consoleApplications.a2.noDidKey') +
        '</p>';
    // THE DOMAIN LINKAGE, one per LinkedDomains origin (2026-10-01): a
    // download of the DID Configuration resource to host at
    // https://<origin>/.well-known/did-configuration.json, signed on request
    // with a kept key. A POST, because signing is an act; Admin Write.
    const origins = facts.origins;
    const linkage = '<h4>' + t.html('consoleApplications.a2.linkageHeading') +
      '</h4>' + (origins.length
      ? '<table><tr><th>' + t.html('consoleApplications.a2.colOrigin') +
        '</th><th>' + t.html('consoleApplications.a2.colHostAt') +
        '</th><th></th></tr>' +
        origins.map(function (origin) {
          const at = origin.replace(/\/+$/, '') +
                     '/.well-known/did-configuration.json';
          return '<tr><td><code>' + kit.esc(origin) + '</code></td><td>' +
            '<code>' + kit.esc(at) + '</code></td><td>' + (canWrite
              ? '<form method="post" action="/admin/applications' + anchor +
                '" class="inline">' + carryBack +
                '<input type="hidden" name="action" ' +
                'value="sign-domain-linkage"><input type="hidden" ' +
                'name="application" value="' + kit.esc(identifier) + '">' +
                '<input type="hidden" name="origin" value="' +
                kit.esc(origin) + '"><input type="hidden" name="from" ' +
                'value="' + (where === 'credentials' ? 'credentials'
                                                     : 'config') + '">' +
                '<button type="submit" class="secondary"' +
                kit.tip(t.html('consoleApplications.a2.linkageTip')) +
                '>' + t.html('consoleApplications.a2.downloadDidConfig') +
                '</button></form>'
              : '') + '</td></tr>';
        }).join('') + '</table>' +
        kit.note(t.html('consoleApplications.a2.linkageNote'))
      : '<p class="sub">' + t.html('consoleApplications.a2.noLinkedDomains') +
        '</p>');
    // Why a document is not advertised yet is the view's sentence, drawn as
    // it comes (#539).
    const html = '<table><tr><th>DID</th><td><code>' + kit.esc(did) +
      '</code></td></tr><tr><th>' +
      t.html('consoleApplications.a2.document') + '</th><td><a href="' +
      kit.esc(url) +
      '"><code>' + kit.esc(url) + '</code></a><div class="sub">' +
      (facts.ok
        ? '<span class="state-valid">' +
          t.html('consoleApplications.a2.advertised') + '</span>' +
          t.html('consoleApplications.a2.nKeys', { n: facts.methods.length })
        : '<span class="state-none">' +
          t.html('consoleApplications.a2.notAdvertised') + '</span>: ' +
          kit.esc(facts.why)) +
      '</div></td></tr></table>' +
      kit.note(t.html('consoleApplications.a2.didWebNote')) + keyTable +
      linkage +
      (canWrite
        ? '<form method="post" action="/admin/applications' + anchor +
          '">' + carryBack +
          '<input type="hidden" name="action" value="generate-did-key">' +
          '<input type="hidden" name="from" value="' +
          (where === 'credentials' ? 'credentials' : 'config') + '">' +
          '<input type="hidden" name="application" value="' +
          kit.esc(identifier) + '"><div class="formrow">' +
          '<span>' + t.html('consoleApplications.a2.generateKeyPair') +
          '</span> ' +
          algorithms.map(function (alg, index) {
            return '<label' + kit.tip(algorithmTip(alg)) +
              '><input type="radio" name="algorithm" value="' +
              alg + '"' + (index === 0 ? ' checked' : '') + '> ' + alg +
              '</label>';
          }).join(' ') +
          ' <label' + kit.tip(t.html('consoleApplications.a2.replaceTip')) +
          '><input ' +
          'type="checkbox" name="replace" value="yes"> ' +
          t.html('consoleApplications.a2.replaceKeys') +
          '</label> <button type="submit"' +
          kit.tip(t.html('consoleApplications.a2.generateTip')) +
          '>' + t.html('consoleApplications.a2.generate') +
          '</button></div>' +
          '</form>' +
          kit.note(t.html('consoleApplications.a2.generateNote'))
        : '');
    return html;
  }

  // AN APPLICATION'S CERTIFICATES OVER ACME, EST AND SCEP (rcbj,
  // 2026-10-01): generation and tracking on the application's own page, on
  // its Credentials tab and on its Certificate enrollment configuration
  // tab, for an application declared for any of the three. It DRAWS
  // `adminViews.applicationEnrollmentState()` and POSTS to the three
  // protocols' own console actions (`/admin/acme`, `/admin/est`,
  // `/admin/scep`) — moving a form is not moving an action, so every control
  // keeps its `/admin-api` mirror (rule 7) — each carrying `from=application`,
  // `where` and the application, which `enrollmentReturnTo()` turns back into
  // this page. Nothing here reads a secret: an EAB HMAC key, a challenge and
  // a server-generated private key are shown once on the page the action
  // answers with, which links back here.
  /**
   * Draws an application's certificate enrollment: the rules in force, its
   * certificates with a Revoke each, its EAB keys and SCEP challenges, the
   * three generation forms and its host names.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's view
   * @param carryBack - the hidden `back` field
   * @param where - `credentials` or `config`, which tab it is drawn on
   * @returns the markup
   */
  static applicationEnrollmentPanel(ctx, row, carryBack, where) {
    const t = ctx.t;
    // TWO COPIES ON ONE PAGE, TWO PAGERS (2026-10-01). The panel is drawn on
    // the Credentials tab and on the Certificate enrollment sub-tab, and a
    // pager's links carry `#list-<param>`, the id of the pager above its
    // list — which opens the tab holding it. With one paging name both
    // copies had that id, and a next page from the Credentials tab landed on
    // the Configuration tab's copy. Each copy pages on a name of its own.
    // Both copies are the answer's (`page.enrollment`, #446).
    const state = row.page.enrollment[where === 'credentials' ? 'credentials'
                                                              : 'config'];
    if (!state.families.length) {
      return '<p class="sub">' + t.html('consoleApplications.a3.enrollTick') +
        '</p>';
    }
    const id = String(row.identifier || '');
    const canWrite = ctx.write;
    const tab = where === 'credentials' ? 'credentials' : 'config';
    const anchor = tab === 'credentials' ? '#credentials-enroll'
                                         : '#cfg-enroll';
    const source = function (one) {
      return one === 'application'
        ? ' <span class="sub">' +
          t.html('consoleApplications.a3.thisApplication') + '</span>'
        : ' <span class="sub">' + t.html('consoleApplications.a3.theRealm') +
          '</span>';
    };
    // Every form here opens the same way: the protocol's action, the
    // application named as the entry, and where to come back to.
    const formOpen = function (family, action, extra?) {
      return '<form method="post" action="/admin/' + family + anchor +
        '" class="inline">' + carryBack +
        '<input type="hidden" name="action" value="' + kit.esc(action) +
        '"><input type="hidden" name="from" value="application">' +
        '<input type="hidden" name="where" value="' + tab + '">' +
        '<input type="hidden" name="application" value="' + kit.esc(id) +
        '">' + (extra || '');
    };
    const entryFields = '<input type="hidden" name="kind" ' +
      'value="application"><input type="hidden" name="identifier" value="' +
      kit.esc(id) + '">';
    const profileSelect = function (rule) {
      return '<select name="profile">' + rule.allowedProfiles.map(
        function (one) {
          return '<option value="' + kit.esc(one) + '"' +
            (one === rule.defaultProfile ? ' selected' : '') + '>' +
            kit.esc(one) + '</option>';
        }).join('') + '</select>';
    };
    const onOff = function (on) {
      return on ? 'yes' : 'no';
    };
    // THE RULES IN FORCE, so a reader sees what an override changed.
    const rulesTable = '<table><tr><th>' +
      t.html('consoleApplications.a3.colProtocol') + '</th><th>' +
      t.html('consoleApplications.a3.colProfilesIssued') + '</th><th>' +
      t.html('consoleApplications.a3.colDefault') + '</th><th>' +
      t.html('consoleApplications.a3.colLifetime') + '</th></tr>' +
      state.rules.map(function (rule) {
        return '<tr><td>' + kit.esc(rule.label) + '</td><td>' +
          rule.allowedProfiles.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(' ') + source(rule.allowedProfilesSource) + '</td><td>' +
          '<code>' + kit.esc(rule.defaultProfile) + '</code>' +
          source(rule.defaultProfileSource) + '</td><td>' +
          t.html('consoleApplications.a3.days',
                 { n: rule.certificateLifetimeDays }) +
          source(rule.certificateLifetimeSource) + '</td></tr>';
      }).join('') + '</table><p class="sub">' +
      t.html('consoleApplications.a3.capA', { n: state.cap.value }) +
      source(state.cap.source) + '.' + (state.est
        ? t.html('consoleApplications.a3.estBasic',
                 { on: onOff(state.est.basicAuthentication.on) }) +
          source(state.est.basicAuthentication.source) +
          t.html('consoleApplications.a3.estCertificate',
                 { on: onOff(state.est.certificateAuthentication.on) }) +
          source(state.est.certificateAuthentication.source) +
          t.html('consoleApplications.a3.estKeys',
                 { on: onOff(state.est.serverKeyGeneration.on) }) +
          source(state.est.serverKeyGeneration.source) + '.'
        : '') + t.html('consoleApplications.a3.overridesNote') + '</p>';
    // THE CERTIFICATES IT WAS ISSUED, newest first, paged.
    const nav = kit.pageNavPair('/admin/applications',
      Object.assign({}, kit.pageParamsOf(ctx.query), { application: id }),
      state.paged.paging);
    const serialField = { acme: 'serial', est: 'serialHex', scep: 'serial' };
    const certificateRows = state.paged.shown.length
      ? state.paged.shown.map(function (one) {
        const family = String(one.family || '');
        const download = one.certificatePem
          ? '<a download="' + kit.esc(one.serialHex) + '.pem" href="' +
            kit.esc('data:application/x-pem-file;base64,' +
              kit.base64Utf8(one.certificatePem)) + '"' +
            kit.tip(t.html('consoleApplications.a3.downloadTip')) + '>PEM</a>'
          : '';
        const revoke = canWrite && one.status === 'valid' &&
          serialField[family]
          ? formOpen(family, 'revoke-certificate',
              '<input type="hidden" name="' + serialField[family] +
              '" value="' + kit.esc(one.serialHex) + '">') +
            '<button type="submit" class="secondary"' +
            kit.tip(t.html('consoleApplications.a3.revokeTip')) + '>' +
            t.html('consoleApplications.a3.revoke') + '</button></form>'
          : '';
        return '<tr><td>' + kit.esc(String(family).toUpperCase()) +
          '</td><td><code>' + kit.esc(one.profile || '') + '</code></td>' +
          '<td><code>' + kit.esc(one.serialHex || '') + '</code></td><td>' +
          (one.names || []).map(function (n) {
            return '<code>' + kit.esc(n) + '</code>';
          }).join('<br>') + '</td><td>' + kit.esc(one.issuedAt || '') +
          '</td><td>' + kit.esc(one.notAfter || '') + '</td><td>' +
          '<span class="state-' + (one.status === 'valid' ? 'valid'
                                                           : 'none') + '">' +
          kit.esc(one.status || '') + '</span></td><td>' + download + ' ' +
          revoke + '</td></tr>';
      }).join('')
      : '<tr><td colspan="8" class="sub">' +
        t.html('consoleApplications.a3.noCertificates') + '</td></tr>';
    const certificates = '<h4>' +
      t.html('consoleApplications.a3.certificatesHeading') + '</h4>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleApplications.a3.colProtocol') +
      '</th><th>' + t.html('consoleApplications.a3.colProfile') +
      '</th><th>' + t.html('consoleApplications.a3.colSerial') + '</th>' +
      '<th>' + t.html('consoleApplications.a3.colNames') + '</th><th>' +
      t.html('consoleApplications.a3.colIssued') + '</th><th>' +
      t.html('consoleApplications.a3.colExpires') + '</th><th>' +
      t.html('consoleApplications.a3.colStatus') + '</th>' +
      '<th></th></tr>' + certificateRows + '</table>' + nav.foot;
    // GENERATION, per declared protocol.
    let generation = '';
    if (state.families.indexOf('acme') >= 0) {
      const eabRows = state.eabKeys.length
        ? state.eabKeys.map(function (k) {
          return '<tr><td><code>' + kit.esc(k.kid) + '</code></td><td>' +
            kit.esc(k.createdAt || '') + '</td><td>' +
            kit.esc(k.expiresAt || '') + '</td><td>' + kit.esc(k.status) +
            (k.boundAccount ? ' <span class="sub">' +
              t.html('consoleApplications.a3.accountPrefix') +
              kit.esc(k.boundAccount) + '</span>' : '') + '</td><td>' +
            (canWrite && !k.boundAccount
              ? formOpen('acme', 'delete-eab', '<input type="hidden" ' +
                  'name="kid" value="' + kit.esc(k.kid) + '">') +
                '<button type="submit" class="secondary"' +
                kit.tip(t.html('consoleApplications.a3.deleteEabTip')) +
                '>' + t.html('consoleApplications.a3.delete') +
                '</button></form>'
              : '') + '</td></tr>';
        }).join('')
        : '<tr><td colspan="5" class="sub">' +
          t.html('consoleApplications.a3.none') + '</td></tr>';
      generation += '<h4>' + t.html('consoleApplications.a3.eabHeading') +
        '</h4>' +
        '<table><tr><th>' + t.html('consoleApplications.a3.colKeyId') +
        '</th><th>' + t.html('consoleApplications.a3.colCreated') +
        '</th><th>' + t.html('consoleApplications.a3.colUnusedUntil') +
        '</th>' +
        '<th>' + t.html('consoleApplications.a3.colStatus') +
        '</th><th></th></tr>' + eabRows + '</table>' +
        (canWrite
          ? formOpen('acme', 'create-eab', entryFields) +
            '<button type="submit"' +
            kit.tip(t.html('consoleApplications.a3.createEabTip')) +
            '>' + t.html('consoleApplications.a3.createEab') +
            '</button></form>'
          : '');
    }
    if (state.families.indexOf('est') >= 0) {
      const rule = state.rules.filter(function (one) {
        return one.family === 'est';
      })[0];
      generation += '<h4>' + t.html('consoleApplications.a3.estHeading') +
        '</h4>' +
        (canWrite && state.est.serverKeyGeneration.on
          ? formOpen('est', 'issue-server-key', entryFields) +
            '<label' +
            kit.tip(t.html('consoleApplications.a3.estProfileTip')) + '>' +
            t.html('consoleApplications.a3.profileLabel') + ' ' +
            profileSelect(rule) +
            '</label> ' +
            '<label' + kit.tip(t.html('consoleApplications.a3.keyTip')) +
            '>' + t.html('consoleApplications.a3.keyLabel') +
            ' <select name="keyAlg">' +
            state.keyAlgorithms.map(function (alg) {
              return '<option value="' + kit.esc(alg) + '"' +
                (alg === 'ec-p256' ? ' selected' : '') + '>' +
                kit.esc(alg) + '</option>';
            }).join('') + '</select></label> ' +
            '<button type="submit"' +
            kit.tip(t.html('consoleApplications.a3.issueTip')) + '>' +
            t.html('consoleApplications.a3.issue') + '</button></form>'
          : '<p class="sub">' + (state.est.serverKeyGeneration.on
            ? t.html('consoleApplications.a3.needsAdminWrite')
            : t.html('consoleApplications.a3.serverKeysOff')) +
            '</p>') +
        '<p class="sub">' + t.html('consoleApplications.a3.estClientNote') +
        '</p>';
    }
    if (state.families.indexOf('scep') >= 0) {
      const rule = state.rules.filter(function (one) {
        return one.family === 'scep';
      })[0];
      const challengeRows = state.challenges.length
        ? state.challenges.map(function (c) {
          return '<tr><td><code>' + kit.esc(c.id) + '</code></td><td>' +
            '<code>' + kit.esc(c.profile || '') + '</code></td><td>' +
            kit.esc(c.createdAt || '') + '</td><td>' +
            kit.esc(c.expiresAt || '') + '</td><td>' + kit.esc(c.status) +
            '</td><td>' + (canWrite && c.status === 'unused'
              ? formOpen('scep', 'delete-challenge', '<input type="hidden" ' +
                  'name="id" value="' + kit.esc(c.id) + '">') +
                '<button type="submit" class="secondary"' +
                kit.tip(t.html('consoleApplications.a3.deleteChallengeTip')) +
                '>' + t.html('consoleApplications.a3.delete') +
                '</button></form>'
              : '') + '</td></tr>';
        }).join('')
        : '<tr><td colspan="6" class="sub">' +
          t.html('consoleApplications.a3.none') + '</td></tr>';
      generation += '<h4>' + t.html('consoleApplications.a3.scepHeading') +
        '</h4>' +
        '<table><tr><th>' + t.html('consoleApplications.a3.colId') +
        '</th><th>' + t.html('consoleApplications.a3.colProfile') +
        '</th><th>' + t.html('consoleApplications.a3.colCreated') +
        '</th>' +
        '<th>' + t.html('consoleApplications.a3.colExpires') + '</th><th>' +
        t.html('consoleApplications.a3.colStatus') + '</th><th></th></tr>' +
        challengeRows +
        '</table>' + (canWrite
          ? formOpen('scep', 'create-challenge', entryFields) +
            '<label' +
            kit.tip(t.html('consoleApplications.a3.scepProfileTip')) +
            '>' + t.html('consoleApplications.a3.profileLabel') + ' ' +
            profileSelect(rule) + '</label> ' +
            '<button type="submit"' +
            kit.tip(t.html('consoleApplications.a3.createChallengeTip')) +
            '>' + t.html('consoleApplications.a3.createChallenge') +
            '</button></form>'
          : '');
    }
    // THE HOST NAMES, shared by the three: a server certificate names only a
    // host registered here.
    const hostFamily = state.families[0];
    const hostRows = state.hostNames.length
      ? state.hostNames.map(function (h) {
        return '<li><code>' + kit.esc(h) + '</code> ' + (canWrite
          ? formOpen(hostFamily, 'remove-host-name', entryFields +
              '<input type="hidden" name="hostName" value="' + kit.esc(h) +
              '">') + '<button type="submit" class="secondary"' +
            kit.tip(t.html('consoleApplications.a3.removeHostTip')) +
            '>' + t.html('consoleApplications.a3.remove') + '</button></form>'
          : '') + '</li>';
      }).join('')
      : '<li class="sub">' + t.html('consoleApplications.a3.none') + '</li>';
    const hosts = '<h4>' + t.html('consoleApplications.a3.hostsHeading') +
      '</h4><ul>' + hostRows + '</ul>' + (canWrite
      ? formOpen(hostFamily, 'add-host-name', entryFields) +
        '<input type="text" name="hostName" placeholder="web1.example.com"' +
        kit.tip(t.html('consoleApplications.a3.hostFieldTip')) + '> ' +
        '<button type="submit"' +
        kit.tip(t.html('consoleApplications.a3.addHostTip')) +
        '>' + t.html('consoleApplications.a3.add') + '</button></form>'
      : '') + '<p class="sub">' + t.html('consoleApplications.a3.hostsNote') +
      '</p>';
    return rulesTable + certificates + generation + hosts;
  }

  /**
   * Draws an application's CORS origins (`appCorsOrigin`), one row each with
   * a Remove button that posts the value as stored, and a form to add one.
   *
   * @param row - the application's registry view
   * @param carryBack - the hidden `back` field every form carries
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static applicationCorsSection(row, carryBack, t) {
    // Each origin with the one it is matched as (`page.cors`, #446).
    const held = row.page.cors;
    const rows = held.map(function (one) {
      const stored = one.stored;
      // A value an `ldapmodify` wrote in another spelling is shown with the
      // origin a browser would actually send, because that is the string the
      // Origin header is compared against — and a reader wondering why a
      // listed origin is refused needs to see the two side by side. Asked of
      // the registry's own reader one value at a time, so this is the
      // normalisation `common/cors.js` compares against and not a copy of it.
      const canonical = one.canonical;
      const differs = canonical && canonical !== stored;
      return '<tr><td><code>' + kit.esc(stored) + '</code>' +
        (differs ? '<br><span class="sub">' +
                   t.html('consoleApplications.a3.matchedAs') + ' <code>' +
                   kit.esc(canonical) + '</code></span>' : '') +
        '</td><td><form method="post" action="/admin/applications" ' +
        'class="inline">' + carryBack +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="application" value="' +
        kit.esc(row.identifier) + '">' +
        '<input type="hidden" name="attribute" value="appCorsOrigin">' +
        '<input type="hidden" name="value" value="' + kit.esc(stored) + '">' +
        '<button type="submit" class="secondary" title="' +
        kit.esc(t.text('consoleApplications.a3.corsRemoveTitle',
                       { origin: stored })) + '">' +
        t.html('consoleApplications.a3.remove') + '</button></form></td></tr>';
    }).join('');
    return '<h2>' + t.html('consoleApplications.a3.corsHeading') + '</h2>' +
      '<p>' + t.html('consoleApplications.a3.corsIntro') + '</p>' +
      kit.note(t.html('consoleApplications.a3.corsNoClient')) +
      '<table><tr><th>' + t.html('consoleApplications.a3.colOrigin') +
      '</th><th></th></tr>' +
      (rows || '<tr><td colspan="2"><span class="state-none">' +
       t.html('consoleApplications.a3.corsNone') + '</span></td></tr>') +
      '</table>' +
      '<form method="post" action="/admin/applications">' + carryBack +
      '<div class="formrow">' +
      '<input type="hidden" name="action" value="add">' +
      '<input type="hidden" name="application" value="' +
      kit.esc(row.identifier) + '">' +
      '<input type="hidden" name="attribute" value="appCorsOrigin">' +
      '<label for="add-cors-origin">' +
      t.html('consoleApplications.a3.addOrigin') + '</label>' +
      '<input type="text" id="add-cors-origin" name="value" size="42" ' +
      'required placeholder="https://app.example.com">' +
      '<button type="submit">' + t.html('consoleApplications.a3.add') +
      '</button></div></form>' +
      kit.note(t.html('consoleApplications.a3.corsOneOrigin'));
  }

  // THE TWO PROTOCOL LISTS AN APPLICATION ENTRY CARRIES, SIDE BY SIDE.
  //
  // `appAllowedProtocol` is DECLARED — ticked on /admin/applications/new, or
  // added here — and what the entry has been RECORDED as is derived from its
  // KINDS. Both are in the attribute table below like everything else; this
  // section exists because comparing them is the whole question a reader has,
  // and the comparison cannot be made by eye: one list holds ids (`oauth2`) and
  // the entry's own `Protocols` row holds the prose labels /admin/users spells
  // protocols with (`OAuth 2.0 / OIDC`).
  //
  // **THE MATCH IS ON KINDS AND NOT ON THOSE LABELS**, which is the one thing
  // to know before editing this. Matching on labels is what this was written as
  // and it was wrong: a FEDERATION partner's sighting is recorded under
  // whichever protocol its relationship speaks, so by label every ordinary
  // OAuth client read as a federation partner. applications.js's
  // `protocolIdsForKinds()` is the translation and its header carries the
  // argument; a second copy of that map in this file would be a second answer
  // to "has this family been seen".
  //
  // **A family with no kind at all is marked**, and that is the row this
  // section is really for. LDAP, SCIM, SPIFFE, mutual TLS and OpenID4VCI record
  // no application identifier anywhere in this service, so nothing will EVER
  // record one — a bare "no" beside them would read as an application that has
  // not been used, when it means the question cannot be answered here.
  //
  // **"Recorded" IS NOT "HAS AUTHENTICATED"**, and the column is named for what
  // it actually reads. A kind is usually written when a protocol recognises the
  // identifier, but createApplication() takes one, so a hand-made entry can
  // carry a kind and no authentications at all. The page says so rather than
  // letting a reader take the column for evidence of traffic; the
  // Authentications tile is the figure that is.
  //
  // Only the families that are declared or recorded are listed. Sixteen rows of
  // "no, no" on every drill-down would be a table nobody reads, and the ones
  // that say nothing are exactly the ones with nothing to say.
  // ---------------------------------------------------------------------------
  // THE CORS ORIGINS ON AN APPLICATION'S PAGE (2026-09-18).
  //
  // `appCorsOrigin` configures CORS on every endpoint this service publishes
  // (`common/cors.js`), and it is a LIST — so it is edited the way this
  // console edits every other list a person maintains by hand (the claims on
  // /admin/claims, the trust anchors on /admin/tls): one row per value, a
  // Remove button ON the row, and one box beneath to add another. The generic
  // Set / Add to / Remove from controls further down reach the same attribute
  // and still do; they make a person retype a value to remove it, which for
  // an origin is exactly the string most likely to be mistyped.
  //
  // **THE REMOVE BUTTON POSTS THE VALUE AS STORED, NOT AS NORMALISED.** A
  // write through this service stores the normalised origin, but an
  // `ldapmodify` stores what it was given, and `updateApplication()` removes
  // the value as typed or, failing that, its normalised spelling. Posting the
  // normalised form of a value that was stored in mixed case would match
  // neither, and the button would do nothing while looking as if it worked.
  //
  // THIS PAGE DOES NOT DECIDE ANYTHING: both forms post `add` and `remove` to
  // /admin/applications, which is `updateApplication()` — the origin check
  // (`STS-REG-0150`) and the normalisation are there, and
  // `POST /admin-api/applications/add|remove` reaches the same function.
  // ---------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // THE ACCESS TYPES TAB (#432 phase 4): every type this application declares
  // in the access-type catalogue — `oauthAuthorizationDetailsType`, one
  // definition per value — with what each declares, a form that declares or
  // replaces one from named fields, and a Remove per type. Both post to
  // `/admin/applications` (`set-access-type`, `remove-access-type`), the
  // actions `/admin-api/applications/{action}` takes too (rule 7).
  // -------------------------------------------------------------------------
  /**
   * Draws an application's Access types tab: the catalogue entries it owns,
   * and the forms that declare, replace and remove one.
   *
   * @param row - the application
   * @param carryBack - the hidden field that returns to the list's view
   * @param t - the page's translator (#539)
   * @returns the tab's HTML
   */
  // A RESOURCE SERVER'S SCOPE CLAIMS (2026-10-09): for each permission it
  // exposes, the catalogue's attributes as boxes, the ones mapped ticked,
  // with Save and Clear. One form per permission, so a save names the one
  // it changes and the others stay as held.
  /**
   * Draws the Scope claims tab: the claims each of a resource server's
   * permissions carries on the access tokens addressed to it.
   *
   * @param ctx - the console context (`write`)
   * @param row - the application's view, with its `page`
   * @param carryBack - the hidden fields that return to this page
   * @returns the markup
   */
  static applicationScopeClaimsSection(ctx, row, carryBack) {
    // The page's translator (#539); English is the catalog's English.
    const t = ctx.t;
    const state = row.page.permissionClaims;
    if (!state) {
      return '';
    }
    const id = String(row.identifier || '');
    const anchor = 'scope-claims';
    const intro = kit.note(t.html('consoleApplications.sc.intro'));
    if (!state.permissions.length) {
      return '<h3 id="' + anchor + '">' +
        t.html('consoleApplications.sc.heading') + '</h3>' + intro +
        kit.note('<span class="state-none">' +
          t.html('consoleApplications.sc.noPermission') + '</span>' +
          t.html('consoleApplications.sc.noPermissionRest'));
    }
    const formOpen = function (action, permission) {
      return '<form method="post" action="/admin/applications#' + anchor +
        '"' + (action === 'set-permission-claims' ? '' : ' class="inline"') +
        '>' + carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="application" value="' + kit.esc(id) +
        '"><input type="hidden" name="permission" value="' +
        kit.esc(permission) + '">';
    };
    const html = state.permissions.map(function (p) {
      const held = p.attributes.map(function (one) {
        return one.toLowerCase();
      });
      const boxes = state.catalogue.map(function (one) {
        const on = held.indexOf(one.ldap.toLowerCase()) >= 0;
        return '<tr><td>' + (ctx.write
          ? '<input type="checkbox" name="attributes" value="' +
            kit.esc(one.ldap) + '"' + (on ? ' checked' : '') +
            ' aria-label="' + kit.esc(one.ldap) + '">'
          : (on ? t.html('consoleApplications.sc.yes') : '')) +
          '</td><td><code>' + kit.esc(one.ldap) +
          '</code></td><td><code>' + kit.esc(one.claim) + '</code></td><td>' +
          kit.esc(one.label || '') + '</td></tr>';
      }).join('');
      return '<h4>' + '<code>' + kit.esc(p.name) + '</code>' +
        (p.description ? ' &mdash; ' + kit.esc(p.description) : '') +
        '</h4>' + kit.note((p.id ? t.html('consoleApplications.sc.askedFor') +
          ' <code>' + kit.esc(p.id) + '</code>. '
          : '<span class="state-none">' +
            t.html('consoleApplications.sc.noBaseUri') + '</span> ') +
          (p.attributes.length
            ? t.html('consoleApplications.sc.carries') + ' ' +
              kit.codeList(p.attributes) + '.'
            : '<span class="state-none">' +
              t.html('consoleApplications.sc.carriesNone') + '</span>')) +
        (ctx.write ? formOpen('set-permission-claims', p.name) +
          '<input type="hidden" name="attributes" value="">' : '') +
        '<details class="fold"><summary>' +
        t.html('consoleApplications.sc.attributes') + '</summary>' +
        '<table><tr><th>' + t.html('consoleApplications.sc.thMapped') +
        '</th><th>' + t.html('consoleApplications.sc.thLdap') + '</th><th>' +
        t.html('consoleApplications.sc.thClaim') + '</th><th>' +
        t.html('consoleApplications.sc.thWhat') + '</th></tr>' + boxes +
        '</table></details>' +
        (ctx.write
          ? '<div class="formrow"><button type="submit"' +
            kit.tip(t.text('consoleApplications.sc.saveTip')) + '>' +
            t.html('consoleApplications.sc.save') + ' ' + kit.esc(p.name) +
            '</button></div>' +
            '</form>' + (p.attributes.length ? '<div class="formrow">' +
              formOpen('clear-permission-claims', p.name) +
              '<button type="submit" class="secondary"' +
              kit.tip(t.text('consoleApplications.sc.clearTip')) + '>' +
              t.html('consoleApplications.sc.clear') + '</button></form>' +
              '</div>' : '')
          : '');
    }).join('');
    const stale = state.stale.length
      ? kit.note('<span class="state-revoked">' +
          t.html('consoleApplications.sc.stale') + '</span> ' +
          kit.codeList(state.stale) + '. ' +
          t.html('consoleApplications.sc.staleRest'))
      : '';
    return '<h3 id="' + anchor + '">' +
      t.html('consoleApplications.sc.heading') + '</h3>' + intro + stale +
      html;
  }

  static applicationAccessTypesSection(row, carryBack, t) {
    // Each declared type, read (`page.accessTypes`, #446).
    const held = row.page.accessTypes;
    const none = '<span class="state-none">' +
      t.html('consoleApplications.a3.noneLower') + '</span>';
    const listed = function (values) {
      return values && values.length
        ? values.map(function (one) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(', ') : '<span class="state-none">' +
          t.html('consoleApplications.a3.any') + '</span>';
    };
    const rows = held.map(function (d) {
      const stored = d.stored;
      // A definition that does not read is a problem drawn from the view's
      // own sentence, and stays English with it (#539).
      if (d.problem) {
        return '<tr><td colspan="3"><span class="state-revoked">unusable' +
          '</span> <code>' + kit.esc(stored.slice(0, 200)) + '</code> ' +
          '&mdash; ' + kit.esc(d.problem) + '</td></tr>';
      }
      const facts = [
        [t.html('consoleApplications.a3.factActions'), listed(d.actions)],
        [t.html('consoleApplications.a3.factDatatypes'), listed(d.datatypes)],
        [t.html('consoleApplications.a3.factPrivileges'),
         listed(d.privileges)],
        [t.html('consoleApplications.a3.factLocations'),
         d.locations.length ? listed(d.locations)
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.ownAddresses') + '</span>'],
        [t.html('consoleApplications.a3.factRequired'),
         d.required.length ? listed(d.required) : none],
        [t.html('consoleApplications.a3.factBearer'), d.bearer === false
          ? t.html('consoleApplications.a3.refused') : (d.bearer === true
          ? t.html('consoleApplications.a3.allowed')
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.noRuleOfItsOwn') + '</span>')],
        [t.html('consoleApplications.a3.factMaxLifetime'), d.maxLifetimeS
          ? t.html('consoleApplications.a3.seconds', { n: d.maxLifetimeS })
          : none],
        [t.html('consoleApplications.a3.factDerivable'),
         d.derivableFrom.length ? listed(d.derivableFrom)
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.nothing') + '</span>'],
        [t.html('consoleApplications.a3.factIntrospection'),
         d.introspectionClaims.length
          ? listed(d.introspectionClaims)
          : none],
        [t.html('consoleApplications.a3.factLimits'), d.limits ? '<code>' +
          kit.esc(JSON.stringify(d.limits)) + '</code>'
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.limitsRefused') + '</span>'],
        [t.html('consoleApplications.a3.factInteraction'),
         kit.esc(d.interaction) +
          (d.consentActions.length
            ? t.html('consoleApplications.a3.consentForcedBy') +
              listed(d.consentActions) : '')],
        [t.html('consoleApplications.a3.factAcr'), d.acr
          ? '<code>' + kit.esc(d.acr) + '</code>'
          : none]
      ].map(function (pair) {
        return '<div><strong>' + pair[0] + ':</strong> ' + pair[1] + '</div>';
      }).join('');
      return '<tr><td><code>' + kit.esc(d.type) + '</code>' +
        (d.description ? '<div class="sub">' + kit.esc(d.description) +
                         '</div>' : '') + '</td><td>' + facts + '</td><td>' +
        '<form method="post" action="/admin/applications" class="inline">' +
        carryBack + '<input type="hidden" name="action" ' +
        'value="remove-access-type"><input type="hidden" name="application" ' +
        'value="' + kit.esc(row.identifier) + '"><input type="hidden" ' +
        'name="type" value="' + kit.esc(d.type) + '"><button type="submit" ' +
        'class="secondary">' + t.html('consoleApplications.a3.remove') +
        '</button></form></td></tr>';
    }).join('');
    const box = function (id, label, help, rowsN?) {
      return '<div class="formrow"><label for="at-' + id + '">' + label +
        '</label>' + (rowsN
          ? '<textarea id="at-' + id + '" name="' + id + '" rows="' + rowsN +
            '" cols="48"></textarea>'
          : '<input type="text" id="at-' + id + '" name="' + id +
            '" size="40">') +
        '<span class="sub">' + help + '</span></div>';
    };
    const anyPerLine = t.html('consoleApplications.a3.onePerLineAny');
    return '<h2>' + t.html('consoleApplications.a3.accessHeading') + '</h2>' +
      '<p>' + t.html('consoleApplications.a3.accessIntro') + '</p>' +
      kit.note(t.html('consoleApplications.a3.accessNote',
                      { dev: row.page.grantsUncataloguedAccess ? 'yes'
                                                               : 'no' })) +
      '<table><tr><th>' + t.html('consoleApplications.a3.colType') +
      '</th><th>' + t.html('consoleApplications.a3.colDeclares') +
      '</th><th></th></tr>' +
      (rows || '<tr><td colspan="3"><span class="state-none">' +
       t.html('consoleApplications.a3.none') + '</span>' +
       '</td></tr>') + '</table>' +
      '<h3>' + t.html('consoleApplications.a3.declareHeading') + '</h3>' +
      '<form method="post" action="/admin/applications">' + carryBack +
      '<input type="hidden" name="action" value="set-access-type">' +
      '<input type="hidden" name="application" value="' +
      kit.esc(row.identifier) + '">' +
      box('type', t.html('consoleApplications.a3.colType'),
          t.html('consoleApplications.a3.helpType')) +
      box('description', t.html('consoleApplications.a3.boxDescription'),
          t.html('consoleApplications.a3.helpDescription')) +
      box('actions', t.html('consoleApplications.a3.factActions'),
          anyPerLine, 3) +
      box('datatypes', t.html('consoleApplications.a3.factDatatypes'),
          anyPerLine, 2) +
      box('privileges', t.html('consoleApplications.a3.factPrivileges'),
          anyPerLine, 2) +
      box('locations', t.html('consoleApplications.a3.factLocations'),
          t.html('consoleApplications.a3.helpLocations'), 2) +
      box('requiredMembers', t.html('consoleApplications.a3.factRequired'),
          t.html('consoleApplications.a3.helpRequired'), 2) +
      box('bearer', t.html('consoleApplications.a3.factBearer'),
          t.html('consoleApplications.a3.helpBearer')) +
      box('maxLifetimeS', t.html('consoleApplications.a3.boxMaxLifetime'),
          t.html('consoleApplications.a3.helpMaxLifetime')) +
      box('derivableFrom', t.html('consoleApplications.a3.factDerivable'),
          t.html('consoleApplications.a3.helpDerivable'), 2) +
      box('introspectionClaims',
          t.html('consoleApplications.a3.factIntrospection'),
          t.html('consoleApplications.a3.helpIntrospection'), 2) +
      box('schema', t.html('consoleApplications.a3.boxSchema'),
          t.html('consoleApplications.a3.helpSchema'), 4) +
      box('limits', t.html('consoleApplications.a3.factLimits'),
          t.html('consoleApplications.a3.helpLimits'), 4) +
      box('interaction', t.html('consoleApplications.a3.factInteraction'),
          t.html('consoleApplications.a3.helpInteraction')) +
      box('consentActions', t.html('consoleApplications.a3.boxConsent'),
          t.html('consoleApplications.a3.onePerLine'), 2) +
      box('acr', t.html('consoleApplications.a3.factAcr'),
          t.html('consoleApplications.a3.helpAcr')) +
      '<div class="formrow"><button type="submit">' +
      t.html('consoleApplications.a3.saveType') + '</button>' +
      '</div></form>' +
      kit.note(t.html('consoleApplications.a3.accessRefusedNote'));
  }

  // ---------------------------------------------------------------------------
  // CREDENTIALS: THE CLIENT SECRET AND THE KEY PAIRS, ON THE APPLICATION'S OWN
  // PAGE (2026-09-13).
  //
  // Every value here was already on the entry and in the attribute table below;
  // what this adds is the READING — which certificate, issued by whom, through
  // what chain, and whether this service holds the private half — and the
  // controls that REPLACE a key pair, which lived only on `/admin/pki` where
  // the application had to be typed into a box.
  //
  // **THREE CONTROLS PER PROFILE, AND NONE OF THEM IS NEW AS AN ACTION BUT
  // ONE.** Issue and Take off post to `/admin/pki`'s existing `issue` and
  // `revoke`; Upload posts `upload-certificate` beside them. All three carry
  // `from`, so that page's handler sends the reader back here
  // (`applicationReturnTo()`), and all three reach `/admin-api/pki/{action}`
  // with no second operation — rule 7 read the way `/admin/delegation`'s grant
  // form reads it.
  //
  // **THE ISSUE CONTROL IS NOT DRAWN IN A REALM WITH NO CERTIFICATE
  // AUTHORITY**, because its only outcome there is a refusal. Upload still is:
  // a certificate from somebody else's authority needs nothing from this
  // realm's.
  //
  // **NO SCRIPT.** The secret is behind a `<details>`, which is how this
  // console folds everything, and the upload is two textareas.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE APPLICATION'S SHARED SIGNALS STREAMS (2026-10-01). Each stream this
  // application created at /ssf/stream, with the members its RECEIVER set
  // (SSF 1.0 section 8.1.1: delivery, events_requested, format,
  // description) shown and not edited here — changing them is the
  // receiver's act through the stream management API. What an administrator
  // may do to a stream is its STATUS, which is a transmitter-initiated change
  // section 8.1.2 says must be announced: Pause and Enable post the existing
  // `status` action, which sends stream-updated first. Beneath it, every
  // per-receiver setting in force for these streams and where it comes from;
  // they are edited in the field grid's Shared Signals group.
  // ---------------------------------------------------------------------------
  /**
   * Draws the Shared Signals section of an application's page: its streams,
   * Pause and Enable for each, and the settings in force for them.
   *
   * @param json - the application's answer, with its `page`
   * @param carryBack - the hidden field carrying the list's place
   * @param writable - whether the reader holds Admin Write, which is what
   *   draws the Pause and Enable buttons
   * @param t - the page's translator (#539)
   * @returns the section as HTML, or '' for an application that has no
   *   Shared Signals family declared and owns no stream
   */
  static applicationSignalsSection(json, carryBack, writable, t) {
    const row = json;
    const state = json.page.signals;
    const declared = (row.allowedProtocols || []).indexOf('ssf') >= 0;
    if (!state || (!declared && !state.streams.length)) {
      return '';
    }
    // The hidden `reason` is data the stream records, not a word of the
    // page, and stays English (#539).
    const statusForm = function (stream, status, label) {
      return '<form method="post" action="/admin/ssf" class="inline">' +
        carryBack +
        '<input type="hidden" name="action" value="status">' +
        '<input type="hidden" name="stream_id" value="' +
        kit.esc(stream.stream_id) + '">' +
        '<input type="hidden" name="status" value="' + status + '">' +
        '<input type="hidden" name="reason" value="set by an administrator ' +
        'from the application\'s page">' +
        '<input type="hidden" name="from" value="application">' +
        '<input type="hidden" name="application" value="' +
        kit.esc(row.identifier) + '">' +
        '<button type="submit" class="secondary"' +
        kit.tip(status === 'paused'
          ? t.html('consoleApplications.a3.pauseTip')
          : t.html('consoleApplications.a3.enableTip')) + '>' + label +
        '</button></form>';
    };
    const list = function (values) {
      return values.length ? values.map(function (one) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join('<br>') : '<span class="state-none">' +
        t.html('consoleApplications.a3.noneLower') + '</span>';
    };
    const streams = state.streams.map(function (stream) {
      return '<tr><td><code>' + kit.esc(stream.stream_id) + '</code><br>' +
        '<span class="sub">aud <code>' + kit.esc(String(stream.aud)) +
        '</code></span></td><td>' + kit.esc(stream.status) +
        (stream.statusReason
          ? '<br><span class="sub">' + kit.esc(stream.statusReason) +
            '</span>' : '') + '</td><td><code>' +
        kit.esc((stream.delivery && stream.delivery.method) || '') +
        '</code>' + (stream.delivery && stream.delivery.endpoint_url
          ? '<br><code>' + kit.esc(stream.delivery.endpoint_url) + '</code>'
          : '') + '</td><td>' + list(stream.events_requested) + '</td><td>' +
        list(stream.events_delivered) + '</td><td>' +
        (stream.format ? '<code>' + kit.esc(stream.format) + '</code>'
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.default') + '</span>') +
        (stream.description
          ? '<br><span class="sub">' + kit.esc(stream.description) +
            '</span>' : '') + '</td><td>' +
        (writable
          ? (stream.status === 'enabled'
            ? statusForm(stream, 'paused',
                         t.html('consoleApplications.a3.pause'))
            : statusForm(stream, 'enabled',
                         t.html('consoleApplications.a3.enable')))
          : '') + '</td></tr>';
    }).join('');
    const settings = state.settings.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.setting) + '</code></td><td>' +
        '<code>' + kit.esc(String(one.value)) + '</code></td><td>' +
        (one.source === 'application'
          ? t.html('consoleApplications.a3.thisApplicationAttr') + ' (<code>' +
            kit.esc(one.attribute) + '</code>)'
          : t.html('consoleApplications.a3.theSetting')) + '</td></tr>';
    }).join('');
    return '<h2 id="signals">Shared Signals</h2>' +
      kit.note(t.html('consoleApplications.a3.signalsNote')) +
      (state.installed ? '' : kit.warn(
        t.html('consoleApplications.a3.ssfNotLoaded'))) +
      (state.streams.length
        ? '<table><tr><th>' + t.html('consoleApplications.a3.colStream') +
          '</th><th>' + t.html('consoleApplications.a3.colStatus') +
          '</th><th>' + t.html('consoleApplications.a3.colDelivery') +
          '</th>' +
          '<th>' + t.html('consoleApplications.a3.colRequested') +
          '</th><th>' + t.html('consoleApplications.a3.colDelivered') +
          '</th><th>' + t.html('consoleApplications.a3.colFormat') +
          '</th><th></th></tr>' +
          streams + '</table>'
        : '<p class="sub">' + t.html('consoleApplications.a3.noStream') +
          '</p>') +
      '<h3>' + t.html('consoleApplications.a3.sentWithHeading') + '</h3>' +
      '<table><tr><th>' + t.html('consoleApplications.a3.colSetting') +
      '</th><th>' + t.html('consoleApplications.a3.colInForce') +
      '</th><th>' + t.html('consoleApplications.a3.colFrom') + '</th></tr>' +
      settings + '</table>';
  }

  // ---------------------------------------------------------------------------
  // SOFTWARE STATEMENTS (RFC 7591 section 2.3), ON THE APPLICATION'S OWN PAGE
  // (2026-09-13).
  //
  // Three halves, each drawn only where it says something: the issuers this
  // application vouches for as a PUBLISHER, the statement this realm ISSUED for
  // it with the one control on the section, and — for a client that registered
  // with a statement — how that statement let it in. The declaration is an
  // ordinary attribute, set with the attribute editor further down; the issue
  // is `issue-software-statement` on `/admin/applications`, which `POST
  // /admin-api/applications/issue-software-statement` mirrors.
  //
  // **NO SCRIPT.** The statement is behind a `<details>`, and the metadata a
  // new one fixes is a textarea of JSON.
  // ---------------------------------------------------------------------------
  /**
   * Draws an application's RFC 7591 software statements: the issuers it
   * vouches for, the statement this realm issued with the issue form, and
   * how a statement let it register.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param json - the application's answer, with its `page`
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static applicationSoftwareStatementSection(ctx, json, carryBack) {
    const t = ctx.t;
    const row = json;
    const state = json.page.softwareStatement;
    const settings = state.settings;
    const hidden = function (name, value) {
      return '<input type="hidden" name="' + name + '" value="' +
             kit.esc(value) +
             '">';
    };

    const publisherHtml = '<h3 id="software-statements-publisher">' +
      t.html('consoleApplications.a3.asPublisher') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.publisherNote')) +
      '<table><tr><th>' + t.html('consoleApplications.a3.colDeclaredIssuer') +
      '</th><th>' + t.html('consoleApplications.a3.colKeysVerify') +
      '</th></tr>' +
      (state.issuers.length
        ? state.issuers.map(function (iss) {
            return '<tr><td><code>' + kit.esc(iss) + '</code></td><td>' +
              (state.usableKeys
                ? '<span class="state-valid">' +
                  t.html('consoleApplications.a3.nKeys',
                         { n: state.usableKeys }) + '</span>'
                : '<span class="state-revoked">' +
                  t.html('consoleApplications.a3.noKeys') + '</span>') +
              '</td></tr>';
          }).join('')
        : '<tr><td colspan="2"><span class="state-none">' +
          t.html('consoleApplications.a3.noneDeclared') +
          '</span></td></tr>') + '</table>';

    // `issued.why` is the view's sentence and is drawn as it comes; an
    // unreadable statement is a problem banner and stays English (#539).
    const issued = state.issued;
    const issuedRows = issued
      ? (issued.readable
        ? '<table><tr><th>' + t.html('consoleApplications.a3.colFact') +
          '</th><th>' + t.html('consoleApplications.a3.colValue') +
          '</th></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.rowIssuer') +
          '</td><td><code>' + kit.esc(issued.issuer) +
          '</code></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.colIssued') +
          '</td><td><code>' +
          kit.esc(kit.whenText(issued.issuedAt)) +
          '</code></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.colExpires') +
          '</td><td><code>' +
          (issued.expiresAt ? kit.esc(kit.whenText(issued.expiresAt))
                            : t.html('consoleApplications.a3.never')) +
          '</code></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.rowVerifiesNow') +
          '</td><td>' + (issued.verifies
            ? '<span class="state-valid">' +
              t.html('consoleApplications.a3.verifiesYes') + '</span>'
            : '<span class="state-revoked">' +
              t.html('consoleApplications.a3.no') + '</span><div ' +
              'class="sub">' + kit.esc(issued.why) +
              t.html('consoleApplications.a3.issueNewOne') + '</div>') +
          '</td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.rowFixes') +
          '</td><td><code>' +
          kit.esc(JSON.stringify(issued.metadata)) + '</code></td></tr>' +
          '<tr><td>' + t.html('consoleApplications.a3.rowStatement') +
          '</td><td><details class="fold"><summary>' +
          t.html('consoleApplications.a3.showStatement') +
          '</summary><code>' + kit.esc(state.issuedToken) +
          '</code></details></td></tr></table>'
        : kit.warn(kit.esc(issued.why), 'Unreadable'))
      : '<p class="sub"><span class="state-none">' +
        t.html('consoleApplications.a3.noneIssued') + '</span></p>';

    const issueForm = '<form method="post" action="/admin/applications">' +
      carryBack + hidden('action', 'issue-software-statement') +
      hidden('application', row.identifier) +
      '<div class="formrow"><label for="software-statement-metadata">' +
      t.html('consoleApplications.a3.metadataLabel') + '</label><textarea ' +
      'id="software-statement-metadata" name="metadata" rows="6" ' +
      'placeholder="{&quot;redirect_uris&quot;: ' +
      '[&quot;https://app.example/cb&quot;], &quot;grant_types&quot;: ' +
      '[&quot;authorization_code&quot;]}"></textarea></div>' +
      '<div class="formrow"><label ' +
      'for="software-statement-lifetime">' +
      t.html('consoleApplications.a3.lifetimeLabel') +
      '</label><input id="software-statement-lifetime" ' +
      'name="lifetimeSeconds" type="number" min="0" placeholder="' +
      kit.esc(String(settings.lifetimeSeconds)) + '"></div>' +
      '<div class="formrow"><button type="submit">' +
      (issued ? t.html('consoleApplications.a3.issueNew')
              : t.html('consoleApplications.a3.issueStatement')) +
      '</button>' +
      '<span class="sub">' + (issued
        ? t.html('consoleApplications.a3.replacesShown')
        : t.html('consoleApplications.a3.signedWithKey')) +
      '</span></div></form>';

    const issuedHtml = '<h3 id="software-statements-issued">' +
      t.html('consoleApplications.a3.issuedHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.issuedNote')) +
      issuedRows + issueForm;

    const facts = state.registeredWith;
    const registeredHtml = facts
      ? '<h3 id="software-statements-registered">' +
        t.html('consoleApplications.a3.registeredHeading') + '</h3>' +
        '<table><tr><th>' + t.html('consoleApplications.a3.colFact') +
        '</th><th>' + t.html('consoleApplications.a3.colValue') +
        '</th></tr>' +
        '<tr><td>' + t.html('consoleApplications.a3.rowStatementIssuer') +
        '<div class="sub"><code>' +
        'appSoftwareStatementIssuer</code></div></td><td><code>' +
        kit.esc(facts.issuer) + '</code></td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a3.rowTrusted') +
        '<div class="sub"><code>appSoftwareStatementTrusted' +
        '</code></div></td><td>' + (facts.trusted
          ? '<span class="state-valid">' +
            t.html('consoleApplications.a3.yes') + '</span>'
          : '<span class="state-revoked">' +
            t.html('consoleApplications.a3.acceptedUnverified') +
            '</span>') + '</td></tr>' +
        '<tr><td>' + t.html('consoleApplications.a3.rowThrough') +
        '<div class="sub"><code>appSoftwareStatementPublisher' +
        '</code></div></td><td>' + (facts.publisher
          ? '<a href="/admin/applications?application=' +
            encodeURIComponent(facts.publisher) + '"><code>' +
            kit.esc(facts.publisher) + '</code></a>'
          : '&mdash;') + '</td></tr></table>'
      : '';

    // AN OAUTH 2.0 CLIENT'S SECTION, for the Credentials section's reason: a
    // statement is presented at POST /oauth2/register, so an application not
    // declared for OAuth 2.0 or OpenID Connect gets a sentence rather than
    // controls — unless it already carries something, which stays in effect.
    if (!json.page.credentials.oauthDeclared && !state.issuers.length &&
        !issued && !facts) {
      return '<h2 id="software-statements">' +
        t.html('consoleApplications.a3.statementsHeading') + '</h2>' +
        kit.note(t.html('consoleApplications.a3.statementsUndeclared'));
    }
    return '<h2 id="software-statements">' +
      t.html('consoleApplications.a3.statementsHeading') + '</h2>' +
      kit.note(t.html('consoleApplications.a3.statementsNote',
                      { req: settings.requireTrustedIssuer ? 'yes' : 'no',
                        opens: settings.opensRegistration ? 'yes' : 'no',
                        must: settings.required ? 'yes' : 'no' }) +
      '<a href="/admin/oauth2">/admin/oauth2</a>.') +
      publisherHtml + issuedHtml + registeredHtml;
  }

  // ---------------------------------------------------------------------------
  // RETURN ADDRESSES A DEVELOPMENT-MODE REQUEST PUT ON THIS ENTRY (2026-09-12).
  //
  // A SAML ACS URL, a SAML 1.1 `shire`, a WS-Federation `wreply` or this
  // service's own learnt callback, written by a sighting and marked OBSERVED on
  // `appReturnAddressObserved`. Product mode refuses a marked address until it
  // is confirmed — `applications.returnAddressesOf()` is the rule — and this is
  // where an operator decides which way each one goes, BEFORE switching a realm
  // to product rather than after its first refused sign-in.
  //
  // **TWO FORMS PER ROW AND NOT ONE WITH TWO BUTTONS.** Two submit buttons in
  // one form would both have to be named `action`, and `form.elements.action`
  // is then a RadioNodeList whose `.value` is empty — which is how
  // `tests/vendored/sts_admin_console.js` finds a form, so the pair would read
  // as controls that reach nothing (the trap `/admin/users/new` met). Each form
  // names its verb in one hidden field, so it does one thing however submitted.
  //
  // Drawn only as markup here; the rows and their paging are
  // `adminViews.applicationDetailJson()`'s, so the table and
  // `GET /admin-api/applications?application=` are one computation.
  // ---------------------------------------------------------------------------
  /**
   * Draws the return addresses a development-mode request put on the entry,
   * each with Confirm and Discard; product mode refuses them until
   * confirmed.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param json - the application's answer, with its `page`
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static applicationObservedAddressesSection(ctx, json, carryBack) {
    const t = ctx.t;
    const row = json;
    const shown = json.page.observed.shown;
    const nav = kit.pageNavPair('/admin/applications',
      kit.pageParamsOf(ctx.query),
                                 json.page.observed.paging);
    const product = !json.page.acceptsUnregisteredAddresses;
    const rows = shown.map(function (one) {
      function button(action, label, cls?) {
        return '<form method="post" action="/admin/applications">' + carryBack +
          '<input type="hidden" name="action" value="' + action + '">' +
          '<input type="hidden" name="application" value="' +
          kit.esc(row.identifier) + '"><input ' +
          'type="hidden" name="attribute" ' +
          'value="' + kit.esc(one.attribute) + '"><input ' +
          'type="hidden" name="value" value="' + kit.esc(one.value) + '">' +
          '<button type="submit"' + (cls ? ' class="' + cls + '"' : '') + '>' +
          label +
          '</button></form>';
      }
      return '<tr><td><code>' + kit.esc(one.attribute) + '</code></td>' +
        '<td><code>' + kit.esc(one.value) + '</code>' +
        (one.held ? '' : '<div class="sub">' +
                         t.html('consoleApplications.a3.markLeft') +
                         '</div>') + '</td>' +
        '<td>' + (one.trusted
          ? '<span class="state-valid">' +
            t.html('consoleApplications.a3.usedDevelopment') + '</span>'
          : '<span class="state-revoked">' +
            t.html('consoleApplications.a3.refusedProduct') + '</span>') +
        '</td>' +
        '<td>' + button('confirm-address',
                        t.html('consoleApplications.a3.confirm')) +
        button('discard-address', t.html('consoleApplications.a3.discard'),
               'danger') + '</td></tr>';
    }).join('');
    const html = '<h2>' + t.html('consoleApplications.a3.observedHeading') +
      '</h2>' +
      kit.note(t.html('consoleApplications.a3.observedNote',
                      { product: product ? 'yes' : 'no' })) +
      nav.head +
      '<table><tr><th>' + t.html('consoleApplications.a3.colAttribute') +
      '</th><th>' + t.html('consoleApplications.a3.colAddress') +
      '</th><th>' + t.html('consoleApplications.a3.colRealmMode') +
      '</th><th>' + t.html('consoleApplications.a3.colDecide') +
      '</th></tr>' +
      (rows || '<tr><td colspan="4">' +
               t.html('consoleApplications.a3.noneObserved') + '</td></tr>') +
      '</table>' +
      nav.foot;
    return html;
  }

  /**
   * Draws an application's delegated permissions, both halves: those it
   * holds, with Revoke, and a form to grant it another; and — for this
   * application only — its base URI, the permissions it exposes, with
   * Remove, and the grants of them to other applications, with Revoke and a
   * form to grant one.
   *
   * The forms post to `/admin/delegation-settings`.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's registry view
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static applicationPermissionsSection(ctx, row, carryBack) {
    const t = ctx.t;
    const identifier = row.identifier;
    // The permissions state is the answer's (`page.permissions`, #446).
    const state = row.page.permissions;
    const held = state.held;
    const exposes = state.exposes;
    const offerable = state.offerable;
    const heldPage = state.heldPage;
    const exposedPage = state.exposedPage;
    const navParams = kit.pageParamsOf(ctx.query);
    const heldNav = kit.pageNavPair('/admin/applications', navParams,
                                     heldPage.paging);
    const exposedNav = kit.pageNavPair('/admin/applications', navParams,
                                        exposedPage.paging);
    const grantedOutPage = state.grantedOutPage;
    const grantedNav = kit.pageNavPair('/admin/applications', navParams,
                                        grantedOutPage.paging);
    const baseUri = ApplicationsPage.firstFieldValue(row,
      'oauthPermissionBaseUri') || '';
    // THE RESOURCE HALF'S HIDDEN FIELDS (2026-10-01). `resource` is this
    // entry, so no form on this tab can configure another application's
    // permissions. There was a `page` field too, which brought the
    // server-rendered console back here (permissionsReturnTo()); nothing
    // reads it since #446, and the operations' closed schemas dropped it
    // (`console_web_bundle` F1b, 2026-10-08).
    const resourceHidden = function (action) {
      return carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="from" value="/admin/applications">' +
        '<input type="hidden" name="resource" value="' +
        kit.esc(identifier) + '">';
    };
    // Its own permissions that a client could ask for — those with an
    // identifier — and every other application to grant them to.
    const grantOwnOptions = exposes.filter(function (one) {
      return !!one.id;
    }).map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' + kit.esc(one.id) +
             '</option>';
    }).join('');
    // WHO TO GRANT IT TO: A SEARCH, NOT A <select> (2026-10-01, rcbj). A
    // registry can hold thousands of applications, and a dropdown of every
    // one of them is a control whose size is the registry's. It is
    // kit.chooserPane() — the same twenty-at-a-time pane, the same clamped
    // offset — and, as on /admin/caep, a result is a LINK back to this page
    // with `grantto` naming the pick, which the grant form below then
    // carries as a hidden `client`. Its three names (`granttoq`,
    // `granttofrom`, `grantto`) are this pane's own: `q` is the application
    // list's search, carried in the page's query, and `grantq` is the
    // register's on the delegation pages.
    const grantCarry = kit.pageParamsOf(ctx.query);
    delete grantCarry.grantto;
    const grantEntries = state.clients.map(function (one) {
      return {
        key: one.identifier,
        names: [one.identifier, one.name],
        label: one.name !== one.identifier
          ? one.name + ' — ' + one.identifier : one.identifier,
        href: '/admin/applications' + kit.queryWith(grantCarry,
          { application: identifier, grantto: one.identifier }) +
          '#find-granttoq'
      };
    });
    // THE PICK, honoured only when it is still an application this page
    // offers — another application in the registry, never this one. A
    // hand-written `grantto` naming anything else draws no form at all.
    const picked = String(kit.pageParamsOf(ctx.query).grantto || '').trim();
    const grantTo = state.clients.filter(function (one) {
      return one.identifier === picked;
    })[0] || null;
    const grantChooser = !state.clients.length ? '' : kit.chooserPane({
      here: { path: '/admin/applications', query: ctx.query },
      param: 'granttoq', fromParam: 'granttofrom',
      label: t.text('consoleApplications.a3.grantTo'),
      placeholder: t.text('consoleApplications.a3.grantToPlaceholder'),
      entries: grantEntries, selectedKey: grantTo ? grantTo.identifier : '',
      nothing: t.text('consoleApplications.a3.grantToNothing')
    });
    // The `title` attributes below were written into the markup unescaped,
    // apostrophes and all; a translation is drawn the same way, so the
    // catalogs keep double quotes out of these messages (#539).
    const askedFor = '<span class="state-valid">' +
      t.html('consoleApplications.a3.askedFor') + '</span>';
    const neverAskedFor = '<span class="state-none">' +
      t.html('consoleApplications.a3.neverAskedFor') + '</span>';
    const grantedRows = grantedOutPage.shown.map(function (one) {
      return '<tr><td><a href="' + kit.esc('/admin/applications' +
          kit.queryWith(kit.listViewOf('/admin/applications', ctx.query),
                    { application: one.client })) + '">' +
        kit.esc(one.clientName) + '</a></td>' +
        '<td><code>' + kit.esc(one.permissionName) + '</code></td>' +
        '<td><code>' + kit.esc(one.permissionId) + '</code></td>' +
        '<td><code>aud: ' + kit.esc(one.baseUri) + '</code><br>' +
        '<code>scope: ' + kit.esc(one.permissionName) + '</code></td>' +
        '<td>' + (one.asked ? askedFor : neverAskedFor) + '</td>' +
        '<td><form method="post" action="/admin/delegation-settings">' +
          carryBack + '<div class="formrow">' +
          '<input type="hidden" name="action" value="revoke-permission">' +
          '<input type="hidden" name="from" value="/admin/applications">' +
          '<input type="hidden" name="client" value="' +
          kit.esc(one.client) + '"><input type="hidden" ' +
          'name="permission" value="' + kit.esc(one.permissionId) + '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleApplications.a3.revoke') + '</button>' +
          '</div></form></td></tr>';
    }).join('');
    const options = offerable.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' + kit.esc(one.id) +
             t.html('consoleApplications.a3.exposedBy') +
             kit.esc(one.resourceName) + '</option>';
    }).join('');

    const heldRows = heldPage.shown.map(function (one) {
      return '<tr>' +
        '<td>' + (one.resource
          ? '<a href="' + kit.esc('/admin/applications' +
              kit.queryWith(kit.listViewOf('/admin/applications', ctx.query),
                        { application: one.resource })) + '">' +
            kit.esc(one.resourceName) + '</a>'
          : '<span class="state-revoked" title="' +
            t.text('consoleApplications.a3.danglingTitle') + '">' +
            t.html('consoleApplications.a3.dangling') + '</span>') + '</td>' +
        '<td>' + (one.permissionName
          ? '<code>' + kit.esc(one.permissionName) + '</code>' +
            (one.description
              ? '<br><span class="state-none">' + kit.esc(one.description) +
                '</span>'
              : '')
          : '<span class="state-none">&mdash;</span>') + '</td>' +
        '<td><code>' + kit.esc(one.permissionId) + '</code></td>' +
        '<td>' + (one.baseUri
          ? '<code>aud: ' + kit.esc(one.baseUri) + '</code><br>' +
            '<code>scope: ' + kit.esc(one.permissionName) + '</code>'
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.doesNotResolve') + '</span>') +
        '</td><td>' + (one.asked
          ? '<span class="state-valid" title="' +
            t.text('consoleApplications.a3.askedForTitle') + '">' +
            t.html('consoleApplications.a3.askedFor') + '</span>'
          : '<span class="state-none" title="' +
            t.text('consoleApplications.a3.neverAskedForTitle') + '">' +
            t.html('consoleApplications.a3.neverAskedFor') + '</span>') +
        '</td>' +
        // THE ROW BUTTON POSTS TO /admin/delegation-settings TOO, for the
        // reason the header gives — and it needs no `client` select either,
        // because the row IS the pair.
        '<td><form method="post" action="/admin/delegation-settings">' +
          carryBack +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="revoke-permission">' +
          '<input type="hidden" name="from" value="/admin/applications">' +
          '<input type="hidden" name="client" value="' + kit.esc(identifier) +
          '"><input type="hidden" name="permission" value="' +
            kit.esc(one.permissionId) + '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleApplications.a3.revoke') + '</button>' +
          '</div></form></td>' +
        '</tr>';
    }).join('');

    const exposedRows = exposedPage.shown.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code>' +
        (one.description
          ? '<br><span class="state-none">' + kit.esc(one.description) +
            '</span>' :
         '') +
        '</td><td>' + (one.id
          ? '<code>' + kit.esc(one.id) + '</code>'
          : '<span class="state-revoked" title="' +
            t.text('consoleApplications.a3.noIdentifierTitle') + '">' +
            t.html('consoleApplications.a3.noIdentifier') + '</span>') +
        '</td>' +
        '<td class="num">' + (one.grantedTo.length
          ? '<span class="state-valid">' + one.grantedTo.length + '</span>'
          : '<span class="state-none" title="' +
            t.text('consoleApplications.a3.nothingHoldsTitle') +
            '">0</span>') + '</td>' +
        '<td class="who">' + (one.grantedTo.length
          ? one.grantedTo.map(function (who) {
              return kit.esc(who.name) + (who.asked ? '' :
                ' <span class="state-none" title="' +
                t.text('consoleApplications.a3.unusedTitle') + '">' +
                t.html('consoleApplications.a3.unused') + '</span>');
            }).join('<br>')
          : '<span class="state-none">&mdash;</span>') + '</td>' +
        // REMOVE, for this application's own permission (2026-10-01). It
        // does not revoke the grants naming it; they become dangling, as on
        // the register.
        '<td><form method="post" action="/admin/delegation-settings">' +
        resourceHidden('remove-permission') +
        '<input type="hidden" name="name" value="' + kit.esc(one.name) +
        '"><button type="submit" class="danger">' +
        t.html('consoleApplications.a3.remove') + '</button></form>' +
        '</td></tr>';
    }).join('');

    return '<h2 id="permissions">' +
      t.html('consoleApplications.a3.permsHeading') + '</h2>' +

      kit.note(t.html('consoleApplications.a3.permsWhichA') + '<a ' +
      'href="/admin/delegation-settings#allowed">' +
      t.html('consoleApplications.a3.linkDelegation') + '</a>' +
      t.html('consoleApplications.a3.permsWhichB') +
      '<a href="/admin/delegation/allowed">' +
      t.html('consoleApplications.a3.linkPicture') + '</a>' +
      t.html('consoleApplications.a3.permsWhichC')) +

      kit.note(t.html('consoleApplications.a3.permsScopeA') +
      '<a href="/admin/oauth2">' +
      t.html('consoleApplications.a3.linkOauthSettings') + '</a>' +
      t.html('consoleApplications.a3.permsScopeB')) +

      '<h3>' + t.html('consoleApplications.a3.holdsHeading') + '</h3>' +
      heldNav.head +
      '<table><tr><th>' + t.html('consoleApplications.a3.colResource') +
      '</th><th>' + t.html('consoleApplications.a3.colPermission') +
      '</th><th>' + t.html('consoleApplications.a3.colIdentifier') +
      '</th><th>' + t.html('consoleApplications.a3.colTokenSays') +
      '</th><th>' + t.html('consoleApplications.a3.colEverAsked') +
      '</th><th></th></tr>' +
      (heldRows || '<tr><td colspan="6">' +
        t.html('consoleApplications.a3.holdsNone') + '</td></tr>') +
      '</table>' +
      heldNav.foot +

      '<h3>' + t.html('consoleApplications.a3.grantHeading') + '</h3>' +
      (options
        ? kit.note(t.html('consoleApplications.a3.grantNote')) +
          '<form method="post" action="/admin/delegation-settings">' +
          carryBack + '<div class="formrow">' +
            '<input type="hidden" name="action" value="grant-permission">' +
            // WHERE TO GO AFTERWARDS. Not a URL — a NAME, checked against a
            // table in permissionsReturnTo() and spent by rebuilding the path
            // from `client`. A redirect target taken out of a request body is
            // an open redirect, and one carrying a newline is a header
            // injection.
            '<input type="hidden" name="from" value="/admin/applications">' +
            '<input type="hidden" name="client" value="' +
            kit.esc(identifier) +
          '"><label ' +
            'for="grant-permission">' +
            t.html('consoleApplications.a3.colPermission') +
            '</label><select ' +
            'id="grant-permission" name="permission">' + options +
              '</select>' +
            '<button type="submit">' +
            t.html('consoleApplications.a3.grantIt') + '</button>' +
          '</div></form>'
        : kit.note(t.html('consoleApplications.a3.nothingToOffer') +
          (state.registerPermissions
            ? t.html('consoleApplications.a3.everyPermissionIs')
            : t.html('consoleApplications.a3.noApiYet')) +
          t.html('consoleApplications.a3.anotherExposes') +
          '<a href="/admin/delegation-settings#allowed">' +
          t.html('consoleApplications.a3.linkDelegation') + '</a>' +
          t.html('consoleApplications.a3.appearsHere'))) +

      '<h3 id="permissions-exposed">' +
      t.html('consoleApplications.a3.exposesHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.exposesNote') + '<a ' +
      'href="/admin/delegation-settings#allowed">' +
      t.html('consoleApplications.a3.linkDelegation') + '</a>' +
      t.html('consoleApplications.a3.sameRegister')) +
      exposedNav.head +
      '<table><tr><th>' + t.html('consoleApplications.a3.colPermission') +
      '</th><th>' + t.html('consoleApplications.a3.colIdentifierSends') +
      '</th><th>' + t.html('consoleApplications.a3.colHeldBy') +
      '</th><th>' + t.html('consoleApplications.a3.colWhichApps') +
      '</th><th></th></tr>' +
      (exposedRows || '<tr><td colspan="5">' +
        t.html('consoleApplications.a3.exposesNone') + '</td></tr>') +
      '</table>' +
      exposedNav.foot +

      '<h4>' + t.html('consoleApplications.a3.exposeHeading') + '</h4>' +
      kit.note(t.html('consoleApplications.a3.baseOneAnswer') +
      (baseUri
        ? t.html('consoleApplications.a3.baseThisOnesA') + '<code>' +
          kit.esc(baseUri) + '</code>.'
        : t.html('consoleApplications.a3.baseNone')) +
      t.html('consoleApplications.a3.baseTrailing')) +
      '<form method="post" action="/admin/delegation-settings">' +
      resourceHidden('set-permission-base') +
      '<div class="formrow"><label for="app-baseUri">' +
      t.html('consoleApplications.a3.baseUri') + '</label>' +
      '<input type="text" id="app-baseUri" name="baseUri" size="34" ' +
      'value="' + kit.esc(baseUri) + '" ' +
      'placeholder="https://example.com/"><button type="submit">' +
      t.html('consoleApplications.a3.setBase') + '</button></div></form>' +

      '<h4>' + t.html('consoleApplications.a3.defineHeading') + '</h4>' +
      kit.note(t.html('consoleApplications.a3.defineNote')) +
      '<form method="post" action="/admin/delegation-settings">' +
      resourceHidden('define-permission') +
      '<div class="formrow"><label for="app-perm-name">' +
      t.html('consoleApplications.a3.name') + '</label>' +
      '<input type="text" id="app-perm-name" name="name" size="18" ' +
      'placeholder="write"><label for="app-perm-description">' +
      t.html('consoleApplications.a3.boxDescription') +
      '</label><input type="text" id="app-perm-description" ' +
      'name="description" size="34" placeholder="' +
      t.text('consoleApplications.a3.descriptionPlaceholder') +
      '"><button type="submit">' +
      t.html('consoleApplications.a3.defineIt') + '</button>' +
      '</div></form>' +

      '<h4 id="permissions-granted">' +
      t.html('consoleApplications.a3.grantsHeading') + '</h4>' +
      kit.note(t.html('consoleApplications.a3.grantsNoteA') + '<code>' +
      kit.esc(identifier) + '</code>' +
      t.html('consoleApplications.a3.grantsNoteB')) +
      grantedNav.head +
      '<table><tr><th>' + t.html('consoleApplications.a3.colClientAsk') +
      '</th><th>' + t.html('consoleApplications.a3.colPermission') +
      '</th>' +
      '<th>' + t.html('consoleApplications.a3.colIdentifier') + '</th><th>' +
      t.html('consoleApplications.a3.colTokenSays') + '</th>' +
      '<th>' + t.html('consoleApplications.a3.colEverAsked') +
      '</th><th></th></tr>' +
      (grantedRows || '<tr><td colspan="6">' +
        t.html('consoleApplications.a3.grantedNone') + '</td></tr>') +
      '</table>' +
      grantedNav.foot +
      (grantOwnOptions && state.clients.length
        ? grantChooser +
          (grantTo
            ? '<form method="post" action="/admin/delegation-settings">' +
              resourceHidden('grant-permission') +
              '<input type="hidden" name="client" value="' +
              kit.esc(grantTo.identifier) + '">' +
              '<div class="formrow"><span>' +
              t.html('consoleApplications.a3.grantWord') + ' <strong>' +
              kit.esc(grantTo.name !== grantTo.identifier
                ? grantTo.name + ' — ' + grantTo.identifier
                : grantTo.identifier) +
              '</strong></span><label for="grant-own-permission">' +
              t.html('consoleApplications.a3.thePermission') +
              '</label><select id="grant-own-permission" ' +
              'name="permission">' + grantOwnOptions + '</select>' +
              '<button type="submit">' +
              t.html('consoleApplications.a3.grantIt') +
              '</button></div></form>'
            : kit.note(t.html('consoleApplications.a3.searchAbove')))
        : kit.note(grantOwnOptions
          ? t.html('consoleApplications.a3.noOtherApp')
          : t.html('consoleApplications.a3.nothingOwnYet')));
  }

  // ---------------------------------------------------------------------------
  // APPLICATION PERMISSIONS (#93): the roles this application holds AS
  // ITSELF, which its client_credentials tokens carry — beside the delegated
  // permissions above, which it holds on a PERSON's behalf. One store, the
  // role entry: the forms post to /admin/roles as add-member and
  // remove-member with `kind=application`, the same act as on that page and
  // audited the same (`roles.grant`, `roles.revoke`); granting here is the
  // administrator's consent, and there is no second step. The static console
  // (#446) comes back to the page the form was on, so the `from` and `client`
  // the server-rendered console returned by are gone.
  // ---------------------------------------------------------------------------
  /**
   * Draws an application's application permissions: the roles it holds as
   * itself, each with Remove, and a form to grant another.
   *
   * The forms post to `/admin/roles`.
   *
   * @param row - the application's registry view
   * @param state - `adminViews.applicationRolesState()`
   * @param carryBack - the hidden `back` field every form carries
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static applicationRolesSection(row, state, carryBack, t) {
    const identifier = row.identifier;
    const hidden = function (action, role) {
      return carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="kind" value="application">' +
        '<input type="hidden" name="member" value="' + kit.esc(identifier) +
        '">' + (role === null ? '' : '<input type="hidden" name="role" ' +
        'value="' + kit.esc(role) + '">');
    };
    const rows = (state.held || []).map(function (one) {
      return '<tr><td><a href="/admin/roles#roles"><code>' +
        kit.esc(one.name) + '</code></a>' +
        (one.displayName ? '<br><span class="sub">' +
          kit.esc(one.displayName) + '</span>' : '') + '</td>' +
        '<td>' + (one.application
          ? t.html('consoleApplications.a3.tokenFor') + ' <code>' +
            kit.esc(one.application) + '</code>' +
            t.html('consoleApplications.a3.commaAs') + ' ' +
            '<code>' + kit.esc(one.carriedAs) + '</code>'
          : t.html('consoleApplications.a3.everyTokenAs') + ' <code>' +
            kit.esc(one.carriedAs) + '</code>') +
        '</td><td>' + (one.permissions.length
          ? one.permissions.map(function (permission) {
              return '<div><code>' + kit.esc(permission) + '</code></div>';
            }).join('')
          : '<span class="state-none">' +
            t.html('consoleApplications.a3.noneLower') + '</span>') +
        '</td>' +
        '<td><form method="post" action="/admin/roles">' +
        hidden('remove-member', one.name) +
        '<button type="submit" class="danger">' +
        t.html('consoleApplications.a3.remove') + '</button></form></td>' +
        '</tr>';
    }).join('');
    const options = (state.offerable || []).map(function (name) {
      return '<option value="' + kit.esc(name) + '">' + kit.esc(name) +
             '</option>';
    }).join('');
    return '<h3 id="app-roles">' +
      t.html('consoleApplications.a3.appPermsHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.appPermsNoteA') + '<code>' +
        kit.esc(identifier) + '</code>' +
        t.html('consoleApplications.a3.appPermsNoteB') +
        '<a href="/admin/roles">' + t.html('consoleApplications.a3.roles') +
        '</a>.') +
      '<table><thead><tr><th>' + t.html('consoleApplications.a3.colRole') +
      '</th><th>' + t.html('consoleApplications.a3.colCarriedIn') +
      '</th><th>' + t.html('consoleApplications.a3.colAuthorizes') +
      '</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="4"><span class="state-none">' +
               t.html('consoleApplications.a3.holdsNoRole') +
               '</span></td></tr>') + '</tbody></table>' +
      (options
        ? '<form method="post" action="/admin/roles"><div class="formrow">' +
          hidden('add-member', null) +
          '<label>' + t.html('consoleApplications.a3.grantWord') +
          ' <select name="role">' + options + '</select>' +
          '</label><button type="submit">' +
          t.html('consoleApplications.a3.grantWord') + '</button></div></form>'
        : '<p class="sub">' + t.html('consoleApplications.a3.noRoleAdmits') +
          '<a href="/admin/roles#create">' +
          t.html('consoleApplications.a3.roles') + '</a>.</p>');
  }

  // ---------------------------------------------------------------------------
  // THE ROLES SOMEBODY MUST HOLD TO USE IT (#458): `appRequiredRole`, moved
  // here from the Configuration grid's Every protocol sub-tab so the two
  // relations a role has with an application are on one tab — what it HOLDS
  // (the section below) and what it DEMANDS (this one). Shaped like that
  // section on purpose: a table of what is there with a Remove per row, and a
  // select of what could be added. One store, the application entry: the
  // forms post the ordinary `add` and `remove` application actions with
  // `attribute=appRequiredRole`, the same act as `POST
  // /admin-api/applications/add` and `remove`, audited the same.
  //
  // EACH ROW SAYS WHAT IT RESOLVES TO, because the one way to get this wrong
  // silently is to name a role nothing defines: that requirement refuses
  // everybody, correctly, and reads as a broken application. /admin/roles
  // flags it for the whole realm; this flags it where it was written.
  // ---------------------------------------------------------------------------
  /**
   * Draws the roles an application requires (`appRequiredRole`): one row
   * each with what it resolves to and a Remove, and a form to add one.
   *
   * The forms post to `/admin/applications`.
   *
   * @param row - the application's registry view
   * @param state - `adminViews.applicationRolesState()`
   * @param carryBack - the hidden `back` field every form carries
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static applicationRequiredRolesSection(row, state, carryBack, t) {
    const identifier = row.identifier;
    const hidden = function (action) {
      return carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="application" value="' +
        kit.esc(identifier) + '">' +
        '<input type="hidden" name="attribute" value="appRequiredRole">';
    };
    const resolution = function (one) {
      if (one.resolves === 'built-in') {
        return t.html('consoleApplications.a3.resolvesBuiltIn');
      }
      if (one.resolves === 'application') {
        return t.html('consoleApplications.a3.resolvesOwn') + ' <code>' +
          kit.esc(one.role) + '</code>';
      }
      if (one.resolves === 'realm') {
        return t.html('consoleApplications.a3.resolvesRealm');
      }
      return '<span class="state-invalid">' +
        t.html('consoleApplications.a3.resolvesNothing') + '</span>';
    };
    // The role's name goes into the tooltip as the original wrote it, raw,
    // between two messages, so the tooltip's escaping is the one it had
    // (#539).
    const rows = (state.required || []).map(function (one) {
      return '<tr><td>' + (one.role
        ? '<a href="/admin/roles#roles"><code>' + kit.esc(one.name) +
          '</code></a>'
        : '<code>' + kit.esc(one.name) + '</code>') +
        (one.displayName ? '<br><span class="sub">' +
          kit.esc(one.displayName) + '</span>' : '') + '</td>' +
        '<td>' + resolution(one) + '</td>' +
        '<td><form method="post" action="/admin/applications">' +
        hidden('remove') +
        '<input type="hidden" name="value" value="' + kit.esc(one.name) +
        '">' +
        '<button type="submit" class="danger"' +
        kit.tip(t.html('consoleApplications.a3.stopRequiringA') + one.name +
          t.html('consoleApplications.a3.stopRequiringB')) +
        '>' + t.html('consoleApplications.a3.remove') +
        '</button></form></td></tr>';
    }).join('');
    const options = (state.requirable || []).map(function (name) {
      return '<option value="' + kit.esc(name) + '">' + kit.esc(name) +
             '</option>';
    }).join('');
    return '<h3 id="app-required-roles"' +
      kit.tip(t.html('consoleApplications.a3.requiredTip')) + '>' +
      t.html('consoleApplications.a3.requiredHeading') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.requiredNoteA') + '<code>' +
        kit.esc(identifier) + '</code>' +
        t.html('consoleApplications.a3.requiredNoteB')) +
      '<table><thead><tr><th>' + t.html('consoleApplications.a3.colRole') +
      '</th><th>' + t.html('consoleApplications.a3.colResolvesTo') +
      '</th><th></th></tr>' +
      '</thead><tbody>' +
      (rows || '<tr><td colspan="3"><span class="state-none">' +
               t.html('consoleApplications.a3.requiredNone') +
               '</span></td></tr>') +
      '</tbody></table>' +
      (options
        ? '<form method="post" action="/admin/applications"><div ' +
          'class="formrow">' + hidden('add') +
          '<label' + kit.tip(t.html('consoleApplications.a3.requireFieldTip')) +
          '>' + t.html('consoleApplications.a3.require') + ' <select ' +
          'name="value">' + options + '</select></label>' +
          '<button type="submit"' +
          kit.tip(t.html('consoleApplications.a3.requireButtonTip')) +
          '>' + t.html('consoleApplications.a3.require') +
          '</button></div></form>'
        : '<p class="sub">' +
          t.html('consoleApplications.a3.everyRoleRequired') +
          '<a href="/admin/roles#create">' +
          t.html('consoleApplications.a3.roles') + '</a>.</p>') +
      kit.note(t.html('consoleApplications.a3.whoHoldsA') +
        '<a href="/admin/roles">' + t.html('consoleApplications.a3.roles') +
        '</a>' + t.html('consoleApplications.a3.whoHoldsB') + '<a ' +
        'href="/admin/xacml/decide">' +
        t.html('consoleApplications.a3.tryDecision') + '</a>.');
  }

  /**
   * Draws the protocol families an application is declared for beside the
   * ones recorded from its kinds, listing only families that are either.
   *
   * @param row - the application's registry view
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static protocolFamilySection(row, t) {
    const declared = row.allowedProtocols || [];
    const seen = row.recordedProtocols || [];
    // The protocol rows are the answer's (`page.protocolRows`, #446).
    const known = row.page.protocolRows;
    const shown = known.map(function (one) {
      return one.id;
    }).filter(function (id) {
      return declared.indexOf(id) >= 0 || seen.indexOf(id) >= 0;
    });

    const yes = '<span class="state-valid">' +
      t.html('consoleApplications.a3.yes') + '</span>';
    const no = '<span class="state-none">' +
      t.html('consoleApplications.a3.no') + '</span>';
    const rows = shown.map(function (id) {
      const meta = known.filter(function (one) {
        return one.id === id;
      })[0] || { label: id, kinds: [], kind: '' };
      const isDeclared = declared.indexOf(id) >= 0;
      const isSeen = seen.indexOf(id) >= 0;
      const seenCell = isSeen
        ? yes
        : ((meta.kinds || []).length
            ? no
            : '<span class="state-none" title="' +
              t.text('consoleApplications.a3.neverRecordedTitle') + '">' +
              t.html('consoleApplications.a3.neverRecorded') + '</span>');
      return '<tr><td>' + kit.esc(meta.label) + '</td><td><code>' +
             kit.esc(id) +
        '</code></td><td>' + (isDeclared ? yes : no) + '</td>' +
        '<td>' + seenCell + '</td></tr>';
    }).join('');

    return '<h2>' + t.html('consoleApplications.a3.familiesHeading') +
      '</h2>' +
      kit.note(t.html('consoleApplications.a3.declaredNoteA') +
      '<a href="/admin/applications/new">' +
      t.html('consoleApplications.a3.linkNewApplication') + '</a>' +
      t.html('consoleApplications.a3.declaredNoteB')) +
      kit.note(t.html('consoleApplications.a3.recordedNote')) +
      '<table><tr><th>' + t.html('consoleApplications.a3.colFamily') +
      '</th><th>' + t.html('consoleApplications.a3.colValue') +
      '</th><th>' + t.html('consoleApplications.a3.colDeclared') +
      '</th><th>' + t.html('consoleApplications.a3.colRecorded') +
      '</th></tr>' +
      (rows || '<tr><td colspan="4">' +
               t.html('consoleApplications.a3.familiesNone') + '</td></tr>') +
      '</table>';
  }

  // The two selects the edit forms offer, built from applications.js's EDITABLE
  // table so that a form cannot offer a field the action would refuse — the
  // same reason the audit page's filters are built from the audit vocabulary.
  //
  // `row` IS THE ENTRY BEING EDITED, and it is here because that rule acquired
  // a second half on 2026-09-01. An attribute whose SCHEMA row carries
  // `families` may only be written onto an entry declared for one of them —
  // `oauthTokenExchangeRefreshToken` and, since 2026-09-12, `ssfAllowedEvents`
  // — and `updateApplication()` refuses it. Offering it in this select on a
  // SAML-only application would be exactly the drift this function exists to
  // prevent: a control that looks like a control and answers with a refusal.
  // Both halves come off the same SCHEMA member, so a second family-scoped
  // attribute needs nothing here.
  //
  // The entry is optional: `editableOptions(mode, selected)` with no entry
  // offers everything, which is what a caller with no application in hand
  // should get.
  /**
   * Draws the options of an edit form's attribute select from the
   * registry's EDITABLE table, leaving out family-scoped attributes the
   * entry is not declared for.
   *
   * @param attributes - the attributes offered, from the answer's
   *   `page.editable`
   * @param selected - the attribute to mark selected
   * @param t - the page's translator (#539)
   * @returns the option elements as HTML
   */
  static editableOptions(attributes, selected, t) {
    // The attributes are the answer's (`page.editable`, #446), already
    // narrowed to the families the application is declared for where the
    // menu is.
    return attributes.map(function (attribute) {
      return '<option value="' + kit.esc(attribute.name) + '"' +
        (attribute.name === selected ? ' selected' : '') + '>' +
             kit.esc(attribute.name) +
        (attribute.sensitive
          ? t.html('consoleApplications.a3.credentialSuffix') : '') +
        '</option>';
    }).join('');
  }

  // One value off an application view's fields, whichever shape it is in. The
  // registry hands `multi` attributes back as arrays and `single` ones as
  // strings, and a page that assumed either would be wrong for half the schema.
  /**
   * Returns the first value of one attribute of an application view,
   * whether the registry holds it as an array or a string.
   *
   * @param row - the application's registry view
   * @param attribute - the attribute name
   * @returns the value trimmed, or an empty string
   */
  static firstFieldValue(row, attribute) {
    const value = (row && row.fields && row.fields[attribute]);
    const one = Array.isArray(value) ? value[0] : value;
    return String(one == null ? '' : one).trim();
  }

  // AN APPLICATION'S OWN CUSTOM CLAIMS OR SAML ATTRIBUTES (rcbj,
  // 2026-10-01): the realm's Custom claims, UserInfo claims and Custom SAML
  // attributes pages, for one application, on its configuration tabs. Each
  // set shows the rows IN FORCE for it — the realm's, and its own, which are
  // added and win by name — with a Remove on its own rows and a form to set
  // one. Both post to `/admin/applications` (`set-custom-claim`,
  // `remove-custom-claim`), mirrored at `/admin-api/applications/<action>`.
  /**
   * Draws an application's own claim sets beside the realm's, with the
   * controls that set and remove its own rows.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's view
   * @param carryBack - the hidden `back` field
   * @param setIds - which of the five sets to draw
   * @param anchor - the section's id, which a form comes back to
   * @param title - the section's heading
   * @returns the markup
   */
  static applicationClaimsSection(ctx, row, carryBack, setIds, anchor, title) {
    const t = ctx.t;
    const canWrite = ctx.write;
    const id = String(row.identifier || '');
    const sets = row.page.claims
      .filter(function (one) { return setIds.indexOf(one.id) >= 0; });
    if (!sets.length) {
      return '';
    }
    const formOpen = function (action, setId) {
      return '<form method="post" action="/admin/applications#' + anchor +
        '" class="inline">' + carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="application" value="' + kit.esc(id) +
        '"><input type="hidden" name="set" value="' + kit.esc(setId) + '">';
    };
    // `${…}` holds braces a message may not, so it is a parameter (#539).
    const html = '<h3 id="' + kit.esc(anchor) + '">' + kit.esc(title) +
      '</h3>' +
      kit.note(t.html('consoleApplications.a3.claimsNote',
                      { placeholder: '${…}' })) +
      sets.map(function (set) {
        const isSaml = set.id === 'saml2' || set.id === 'saml11';
        // A PAC row carries one of the four PAC claim types (#493), typed
        // value or attribute alike.
        const isPac = set.id === 'kerberos-pac';
        const rows = set.effective.length
          ? set.effective.map(function (claim) {
            const what = claim.attribute
              ? t.html('consoleApplications.a3.attributeWord') + ' <code>' +
                kit.esc(claim.attribute) + '</code>' +
                (claim.multi
                  ? t.html('consoleApplications.a3.everyValueSuffix') : '') +
                (claim.type ? ', ' + kit.esc(claim.type) : '')
              : '<code>' + kit.esc(claim.value) + '</code>';
            const extra = claim.nameFormat
              ? ' <span class="sub">' + kit.esc(claim.nameFormat) + '</span>'
              : (claim.namespace ? ' <span class="sub">' +
                kit.esc(claim.namespace) + '</span>' : '');
            return '<tr><td><code>' + kit.esc(claim.name) + '</code>' +
              extra + '</td><td>' + what + '</td><td>' +
              (claim.source === 'application'
                ? '<span class="state-valid">' +
                  t.html('consoleApplications.a3.thisApplicationAttr') +
                  '</span>' +
                  (claim.replacesRealm ? ' <span class="sub">' +
                    t.html('consoleApplications.a3.replacesRealm') +
                    '</span>' : '')
                : '<span class="state-none">' +
                  t.html('consoleApplications.a3.theRealmWord') + '</span>') +
              '</td><td>' +
              (canWrite && claim.source === 'application'
                ? formOpen('remove-custom-claim', set.id) +
                  '<input type="hidden" name="name" value="' +
                  kit.esc(claim.name) + '"><button type="submit" ' +
                  'class="secondary"' +
                  kit.tip(t.html('consoleApplications.a3.removeRowTip')) +
                  '>' + t.html('consoleApplications.a3.remove') +
                  '</button></form>'
                : '') + '</td></tr>';
          }).join('')
          : '<tr><td colspan="4" class="sub">' +
            t.html('consoleApplications.a3.noClaims') + '</td></tr>';
        // The option list's variable was `t` until #539 made `t` the
        // translator; it is `type` now.
        const typeSelect = isSaml ? '' : ' <label' + kit.tip(isPac
            ? t.html('consoleApplications.a3.pacTypeTip')
            : t.html('consoleApplications.a3.jsonTypeTip')) + '>' +
          t.html('consoleApplications.a3.typeLabel') + ' <select ' +
          'name="type">' +
          (isPac ? ['string', 'int64', 'uint64', 'boolean']
                 : ['string', 'number', 'boolean', 'json'])
            .map(function (type) {
              return '<option value="' + type + '">' + type + '</option>';
            }).join('') + '</select></label>';
        const samlExtra = set.id === 'saml2'
          ? ' <label' +
            kit.tip(t.html('consoleApplications.a3.nameFormatTip')) +
            '>NameFormat <input ' +
            'type="text" name="nameFormat" placeholder="urn:oasis:names:tc:' +
            'SAML:2.0:attrname-format:uri"></label>'
          : (set.id === 'saml11'
            ? ' <label' +
              kit.tip(t.html('consoleApplications.a3.namespaceTip')) + '>' +
              t.html('consoleApplications.a3.namespaceLabel') + ' <input ' +
              'type="text" name="namespace" placeholder="http://schemas.' +
              'xmlsoap.org/ws/2005/05/identity/claims"></label>'
            : '');
        // The set's label is the view's, and goes into the Set tooltip as
        // the original wrote it, between two messages (#539).
        return '<h4>' + kit.esc(set.label) + '</h4>' +
          '<table><tr><th>' + t.html('consoleApplications.a3.name') +
          '</th><th>' + t.html('consoleApplications.a3.colValue') +
          '</th><th>' + t.html('consoleApplications.a3.colFrom') +
          '</th><th></th></tr>' +
          rows + '</table>' + (canWrite
            ? formOpen('set-custom-claim', set.id) + '<div class="formrow">' +
              '<label' + kit.tip(t.html('consoleApplications.a3.nameTip')) +
              '>' + t.html('consoleApplications.a3.name') + ' ' +
              '<input type="text" name="name" required placeholder="' +
              (isSaml ? 'department' : 'tenant') + '"></label> ' +
              '<label' +
              kit.tip(t.html('consoleApplications.a3.valueTip',
                             { placeholders: '${placeholders}' })) + '>' +
              t.html('consoleApplications.a3.colValue') + ' ' +
              '<input type="text" name="value" placeholder="' +
              (isSaml ? '${subject}' : '${username}') + '">' +
              '</label> <label' +
              kit.tip(t.html('consoleApplications.a3.attributeTip')) + '>' +
              t.html('consoleApplications.a3.orAttribute') +
              ' <input type="text" ' +
              'name="attribute" placeholder="departmentNumber"></label> ' +
              '<label' + kit.tip(t.html('consoleApplications.a3.multiTip')) +
              '><input type="checkbox" name="multi" ' +
              'value="yes"> ' + t.html('consoleApplications.a3.everyValue') +
              '</label>' + typeSelect + samlExtra +
              ' <button type="submit"' +
              kit.tip(t.html('consoleApplications.a3.setTipA') + set.label +
                      t.html('consoleApplications.a3.setTipB')) + '>' +
              t.html('consoleApplications.a3.set') + '</button></div></form>'
            : '');
      }).join('');
    return html;
  }

  // AN APPLICATION'S OWN DIRECTORY-ATTRIBUTE SELECTIONS (#495): the ticked
  // catalogue of the realm's Custom claims, UserInfo claims, Custom SAML
  // attributes and Credential claims pages, for this application, under the
  // rows above. ONE TABLE PER SET, the boxes ticked as IN FORCE — the
  // realm's while the application inherits, its own once saved — beside
  // what each attribute would say about one person; Save writes the ticked
  // boxes as this application's whole selection, which REPLACES the realm's
  // (unticking is how one of the realm's attributes is dropped for it), and
  // Use the realm's takes its own off. Both post to `/admin/applications`
  // (`set-claim-attributes`, `inherit-claim-attributes`), mirrored at
  // `/admin-api/applications/<action>`. The hidden empty `attributes` is
  // what an all-unticked form sends: a list of no names.
  /**
   * Draws an application's directory-attribute selections for some of its
   * claim sets, or its credential claims, with a preview for one person.
   *
   * @param ctx - the render context (`kit.context()`)
   * @param row - the application's view, with its `page`
   * @param carryBack - the hidden `back` field every form carries
   * @param setIds - the claim sets to draw, or `['credential']`
   * @param anchor - the sub-tab's fragment the forms return to
   * @returns the markup, or '' when there is nothing to draw
   */
  static applicationClaimSelectionSection(ctx, row, carryBack, setIds,
                                          anchor) {
    const t = ctx.t;
    const state = row.page.claimSelections;
    if (!state) {
      return '';
    }
    const id = String(row.identifier || '');
    const wanted = setIds.indexOf('credential') >= 0
      ? (state.credential ? [Object.assign({ id: 'credential',
          label: 'Verifiable Credential' }, state.credential)] : [])
      : state.sets.filter(function (one) {
        return setIds.indexOf(one.id) >= 0;
      });
    if (!wanted.length) {
      return '';
    }
    const values = state.preview.byLdap || {};
    const formOpen = function (action, setId) {
      return '<form method="post" action="/admin/applications#' +
        kit.esc(anchor) + '"' + (action === 'set-claim-attributes' ? ''
                                 : ' class="inline"') + '>' + carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="application" value="' + kit.esc(id) +
        '"><input type="hidden" name="set" value="' + kit.esc(setId) + '">';
    };
    const previewForm = '<form method="get" action="/admin/applications#' +
      kit.esc(anchor) + '"><div class="formrow">' +
      '<input type="hidden" name="application" value="' + kit.esc(id) + '">' +
      '<label' + kit.tip(t.html('consoleApplications.a3.previewTip')) + '>' +
      t.html('consoleApplications.a3.previewFor') + ' <input type="text" ' +
      'name="claimsUser" size="16" value="' + kit.esc(state.preview.user) +
      '"></label> <button type="submit" class="secondary">' +
      t.html('consoleApplications.a3.show') + '</button>' +
      '</div></form>';
    // The previewed username is drawn by `kit.esc()` after a message rather
    // than as a parameter, whose escaping of an apostrophe differs (#539).
    const html = wanted.map(function (set) {
      const isSaml = set.id === 'saml2' || set.id === 'saml11';
      const isVc = set.id === 'credential';
      const inForce = set.effective.map(function (one) {
        return one.toLowerCase();
      });
      const realm = set.realm.map(function (one) {
        return one.toLowerCase();
      });
      const rows = state.catalogue.map(function (one) {
        const key = one.ldap.toLowerCase();
        const on = inForce.indexOf(key) >= 0;
        const found = values[key];
        return '<tr><td>' + (ctx.write
          ? '<input type="checkbox" name="attributes" value="' +
            kit.esc(one.ldap) + '"' + (on ? ' checked' : '') +
            ' aria-label="' + kit.esc(one.ldap) + '">'
          : (on ? t.html('consoleApplications.a3.yes') : '')) +
          '</td><td><code>' + kit.esc(one.ldap) +
          '</code></td><td><code>' + kit.esc(one.claim) + '</code>' +
          (isVc && !one.ldpTerm
            ? ' <span class="sub">' +
              t.html('consoleApplications.a3.notInLdpVc') + '</span>' : '') +
          '</td><td>' + (realm.indexOf(key) >= 0
            ? '<span class="state-valid">' +
              t.html('consoleApplications.a3.ticked') + '</span>'
            : '<span class="state-none">' +
              t.html('consoleApplications.a3.no') + '</span>') + '</td><td>' +
          (found ? '<code>' + kit.esc(found.value) + '</code> <span ' +
            'class="sub">' + kit.esc(found.source) + '</span>'
            : '<span class="state-none">—</span>') + '</td></tr>';
      }).join('');
      const report = set.report.length
        ? '<table><tr><th>' + (isSaml
            ? t.html('consoleApplications.a3.colAttribute')
            : t.html('consoleApplications.a3.colClaim')) +
          '</th><th>' + t.html('consoleApplications.a3.colValue') +
          '</th><th>' + t.html('consoleApplications.a3.colFrom') +
          '</th></tr>' +
          set.report.map(function (item) {
            return '<tr><td><code>' + kit.esc(item.claim) + '</code></td>' +
              '<td><code>' + kit.esc(typeof item.value === 'string'
                ? item.value : JSON.stringify(item.value)) + '</code></td>' +
              '<td>' + kit.esc(item.source) + '</td></tr>';
          }).join('') + '</table>'
        : kit.note(t.html('consoleApplications.a3.noneInForce') +
            (isVc ? t.html('consoleApplications.a3.noneInForceVc')
                  : t.html('consoleApplications.a3.noneInForceRows')));
      const noAttribute = t.html('consoleApplications.a3.noAttribute');
      return '<h4>' + (isVc
          ? t.html('consoleApplications.a3.credentialClaims')
          : kit.esc(set.label)) +
        t.html('consoleApplications.a3.directoryAttributesSuffix') + '</h4>' +
        kit.note(set.inherited
          ? '<span class="state-none">' +
            t.html('consoleApplications.a3.realmSelection') + '</span>' +
            t.html('consoleApplications.a3.isInForce') +
            (set.realm.length ? kit.codeList(set.realm) : noAttribute) +
            t.html('consoleApplications.a3.inheritedTail')
          : '<span class="state-valid">' +
            t.html('consoleApplications.a3.ownSelection') + '</span>' +
            t.html('consoleApplications.a3.isInForce') + (set.own.length
              ? kit.codeList(set.own) : noAttribute) +
            t.html('consoleApplications.a3.inPlaceOf') +
            (set.realm.length ? kit.codeList(set.realm)
                              : t.html('consoleApplications.a3.noneLower')) +
            ').' +
            (isVc ? t.html('consoleApplications.a3.vcMetadata') : '')) +
        (ctx.write ? formOpen('set-claim-attributes', set.id) +
          '<input type="hidden" name="attributes" value="">' : '') +
        '<table><tr><th>' + t.html('consoleApplications.a3.colIn') +
        '</th><th>' + t.html('consoleApplications.a3.colLdap') + '</th><th>' +
        (isSaml ? t.html('consoleApplications.a3.colAttributeName')
                : t.html('consoleApplications.a3.colClaim')) +
        '</th><th>' + t.html('consoleApplications.a3.colRealms') +
        '</th><th>' + t.html('consoleApplications.a3.forPrefix') +
        kit.esc(state.preview.user) +
        '</th></tr>' + rows +
        '</table>' + (ctx.write
          ? '<div class="formrow"><button type="submit"' +
            kit.tip(t.html('consoleApplications.a3.saveSelectionTip')) +
            '>' + t.html('consoleApplications.a3.saveSelection') +
            '</button></div></form>' +
            (set.inherited ? '' : '<div class="formrow">' +
              formOpen('inherit-claim-attributes', set.id) +
              '<button type="submit" class="secondary"' +
              kit.tip(t.html('consoleApplications.a3.useRealmTip')) + '>' +
              t.html('consoleApplications.a3.useRealm') +
              '</button></form></div>')
          : '') +
        '<h5>' + t.html('consoleApplications.a3.wouldCarryPrefix') +
        kit.esc(state.preview.user) +
        '</h5>' + report;
    }).join('');
    return '<h3 id="' + kit.esc(anchor) + '-attributes">' +
      t.html('consoleApplications.a3.directoryAttributes') + '</h3>' +
      kit.note(t.html('consoleApplications.a3.selectionNote')) +
      previewForm + html;
  }

  // AN APPLICATION'S TOKEN LIFETIMES (rcbj, 2026-10-01): the realm's Token
  // lifetimes page, for one application, at the head of its OAuth / OpenID
  // Connect configuration tab. The four overrides were already fields on
  // that tab (`oauthAccessTokenTtlS` and three more); this draws the value
  // IN FORCE for each, where it came from, and the realm page's warnings
  // over the application's own values. Clock skew stays realm-wide.
  /**
   * Draws the token lifetimes in force for an application, with the realm
   * page's warnings.
   *
   * @param json - the application's answer, with its `page`
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static applicationTokenLifetimesSection(json, t) {
    const state = json.page.lifetimes;
    const byKey = {};
    state.rows.forEach(function (one) { byKey[one.setting] = one; });
    const html = '<h3 id="cfg-oauth-lifetimes">' +
      t.html('consoleApplications.a3.lifetimesHeading') + '</h3>' +
      '<table><tr><th>' + t.html('consoleApplications.a3.colToken') +
      '</th><th>' + t.html('consoleApplications.a3.colInForce') +
      '</th><th>' + t.html('consoleApplications.a3.colFrom') + '</th>' +
      '<th>' + t.html('consoleApplications.a3.colRealms') + '</th><th>' +
      t.html('consoleApplications.a3.colOverride') + '</th></tr>' +
      state.rows.map(function (one) {
        return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
          kit.esc(kit.humanSeconds(one.value)) + '</td><td>' +
          (one.source === 'application'
            ? '<span class="state-valid">' +
              t.html('consoleApplications.a3.thisApplicationAttr') + '</span>'
            : '<span class="state-none">' +
              t.html('consoleApplications.a3.theRealmWord') + '</span>') +
          '</td><td>' +
          kit.esc(kit.humanSeconds(one.realmValue)) + '</td><td>' +
          '<code>' + kit.esc(one.attribute) + '</code></td></tr>';
      }).join('') + '</table>' +
      TokenLifetimesPage.tokenLifetimeWarningsFor(
        byKey['oauth2.accessTokenTtlS'].value,
        byKey['oauth2.refreshTokenTtlS'].value, state.skew, t) +
      kit.note(t.html('consoleApplications.a3.lifetimesNote',
                      { skew: kit.humanSeconds(state.skew) }));
    return html;
  }

  // A CREDENTIAL'S VALUE, ASKED FOR (#446, rcbj 2026-10-05). The page shows
  // no secret: the answer it is drawn from carries none. This button asks
  // `reveal-secret` for the one it names, and the value comes back on the
  // page that answers — once, and on no URL.
  /**
   * Draws the button that reveals one credential of an application.
   *
   * @param application - the application's identifier
   * @param secret - a client secret's id, or `registration-access-token`
   * @param what - what it is, for the button
   * @param carryBack - the hidden back field the form carries, as HTML
   * @param t - the page's translator (#539)
   * @returns the form as HTML
   */
  static revealControl(application, secret, what, carryBack, t) {
    // `what` is the caller's words, drawn into the tooltip as they were,
    // between two messages (#539).
    return '<form method="post" action="/admin/applications" class="inline">' +
      carryBack +
      '<input type="hidden" name="action" value="reveal-secret">' +
      '<input type="hidden" name="application" value="' +
      kit.esc(application) + '">' +
      '<input type="hidden" name="secret" value="' + kit.esc(secret) + '">' +
      '<button type="submit" class="secondary"' +
      kit.tip(t.html('consoleApplications.a3.revealTipA') + what +
              t.html('consoleApplications.a3.revealTipB')) +
      '>' + t.html('consoleApplications.a3.reveal') + '</button></form>';
  }
}

export = ApplicationsPage;
