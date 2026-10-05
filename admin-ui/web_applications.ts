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

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static newApplicationBody(ctx, json) {
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
      inner = '<p class="warn"><strong>There is no embedded directory ' +
        'loaded in ' +
          'this process</strong>, so there is no ' +
          '<code>ou=applications</code> container to create an entry in and ' +
          'this form is not drawn. The applications registry has no store of ' +
          'its own on purpose &mdash; the directory IS the registry &mdash; ' +
          'so this is a build without <code>ldap/ldap_server.js</code> ' +
          'rather than a fault.</p>' + APPLICATIONS_LINKS;
    } else {

      // The identifier and the name, as the form draws them with no document
      // loaded. With one loaded they are on the pane's third tab instead, and
      // drawing them here as well would post each name twice.
      const calledSection =
        '<h2>What it is called</h2><div class="formrow"><label ' +
        'for="identifier">Identifier</label><input type="text" ' +
          'id="identifier" ' +
        'name="identifier" size="42" required placeholder="e.g. my-web-app ' +
          'or ' +
        'https://sp.example.com/saml/metadata"' +
        kit.tip('The key every protocol presents for this application: a ' +
                 'client_id, wtrealm, AppliesTo, SAML entityID or Kerberos ' +
                 'SPN. At most 512 characters, no line break.') +
        ' value="' + kit.esc(drafted('identifier')) + '"></div>' +
        kit.note('THE KEY, exactly as the protocol will present it. At most ' +
        '512 characters, and no line break: an entry whose <code>cn</code> ' +
        'would be longer than 64 characters is filed under <code>app-&lt;12 ' +
        'hex&gt;</code> instead, and <code>appIdentifier</code> is the ' +
        'attribute to search on either way.') +
        '<div class="formrow"><label for="newname">Name</label><input ' +
        'type="text" id="newname" name="name" size="24" ' +
        'placeholder="e.g. My Web App (optional)"' +
        kit.tip('What pages call it. With none, the identifier is the name.') +
        ' value="' + kit.esc(drafted('name')) + '"></div>' +
        kit.note('The name is what pages call it; with none given the ' +
        'identifier is the name, because inventing a friendly name for an ' +
        'opaque id would be inventing a fact.') +
        kit.note('<strong>There is no <em>Kind</em> to choose and that is ' +
        'deliberate.</strong> It used to be a select here, and it asked the ' +
        'same question the protocol families below do in a vocabulary that ' +
        'does not line up with theirs &mdash; eight kinds against fourteen ' +
        'families, five of which have no kind at all. It is also the wrong ' +
        'side of the line this registry draws: a family is DECLARED and a ' +
          'kind ' +
        'is DERIVED, written when a protocol actually recognises the ' +
        'identifier, so choosing one here was a form asserting a sighting ' +
          'that ' +
        'had not happened. Tick the families instead; the kinds fill ' +
        'themselves in as this application is used.');
      // The families ticked: the ones a refused create had ticked, or OAuth 2.0
      // for a document describing an OAuth protected resource.
      const ticked = given.protocols ||
                     (loaded ? loaded.plan.protocols : []);

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
        kit.tile(held, 'In the registry') +
        kit.tile(json.protocols.length, 'Protocol families') +
        kit.tile(json.kinds.length, 'Kinds') +
        '</div>' +
        kit.note('<strong>The entry lands in this realm\'s directory, at ' +
          '<code>' +
        kit.esc(container) + '</code></strong>' +
        (max ? ', which holds at most ' + kit.esc(String(max)) +
        ' application(s)' : '') + '. The console shows one trust realm at a ' +
        'time and this form writes the one it is showing &mdash; ' +
        '<strong>' + kit.esc(realm ? realm.name : 'Default') +
        '</strong> &mdash; because the realm is taken from the path this ' +
        'request arrived on. Applications are NOT shared between realms: an ' +
        '<code>ldapsearch</code> with that base DN is the same entry this ' +
        'creates, and another realm\'s registry has never heard of it.') +
        kit.note('<strong>This is not a second door onto the ' +
        'registry.</strong> The form below posts to ' +
        '<code>/admin/applications</code> with <code>action=create</code> ' +
        '&mdash; the same action the list page\'s own <em>Add an ' +
        'application</em> row posts, calling the same function in ' +
        '<code>applications.js</code> that a protocol endpoint and an ' +
        '<code>ldapmodify</code> reach. Two forms over one function are two ' +
        'doors; there is one store behind them and nothing caches it.') +

        ApplicationsPage.resourceMetadataLoadSection(given,
          json.resourceMetadataImport) +

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
        'aria-hidden="true">Create the application</button>' +
        (loaded
          ? '<h2>The protected resource metadata that was loaded</h2>' +
            ApplicationsPage.resourceMetadataPane(loaded, given.draft,
              given.tab) +
            '<h2>What it is called</h2>' +
            kit.note('<strong>The identifier, the name and the client_id are ' +
            'on the <em>Editable fields</em> tab above</strong>, filled in ' +
            'from the document: the name is its <code>resource</code> and ' +
              'the ' +
            'identifier is the client_id generated for it.')
          : calledSection) +

        '<h2>Protocol families it is declared for</h2>' +
        kit.note('Tick as many as apply. The list is CLOSED &mdash; a value ' +
        'that is not one of these is refused rather than recorded, because a ' +
        'typo that silently became a new family is how one application comes ' +
        'to be declared for two spellings of one thing.') +
        '<table><tr><th>For</th><th>Family</th><th>Value</th>' +
        '<th>Recorded as, when it turns up</th><th>What it means</th></tr>' +
        json.familyChoices.map(function (row) {
          return ApplicationsPage.protocolChoiceRow(row,
            row.families.some(function (id) {
            return ticked.indexOf(id) >= 0;
          }));
        }).join('') +
        '</table>' +

        // THE FIELD GRID (2026-09-30): the simplified view is the fields this
        // page has always offered — the declarations, the per-application
        // setting overrides and where SAML 2.0 encryption gets its key — and
        // the advanced view is every field an application has. Both are one
        // grid, typed, shown for the families ticked; the switch is a submit
        // button, so whatever has been typed is carried into the other view.
        '<h2>' + (view === 'advanced' ? 'Every field' : 'Its fields') +
        '</h2>' +
        '<div class="formrow fg-view"><span class="sub">' +
        (view === 'advanced'
          ? 'Advanced view: every field an application has, for the families ' +
            'ticked.'
          : 'Simplified view: the fields most applications need.') +
        '</span><button type="submit" class="secondary" name="switchview" ' +
        'value="' + (view === 'advanced' ? 'simple' : 'advanced') +
        '" formaction="/admin/applications/new" formnovalidate' +
        kit.tip('Draw the other view of this form. Nothing is created, and ' +
                 'everything typed so far is kept.') + '>' +
        (view === 'advanced' ? 'Show the simplified view'
          : 'Show every field (advanced view)') + '</button></div>' +
        // THE PROMPT THAT STANDS IN FOR THE HIDDEN FIELDS. It is inside the
        // form
        // so the `:has()` rule that hides it can reach it, and it is always in
        // the markup: a browser without `:has()` shows it beside every field,
        // where it reads as a description of the page rather than as a broken
        // instruction.
        '<div class="pf-hint">Most fields depend on which families you tick ' +
        'above &mdash; a field appears when the protocol it belongs to is ' +
        'selected, so an OAuth client is not asked for a SAML entityID. ' +
          'Tick a ' +
        'family to see its fields. <strong>If you can see them all ' +
        'already</strong>, this browser does not support the ' +
        '<code>:has()</code> selector and the form is showing everything ' +
        '&mdash; nothing you type is affected either way, because the server ' +
        'reads what was posted and not what was visible.</div>' +
        kit.fieldGridOf(
          ApplicationsPage.newApplicationFieldRows(json, view,
            loaded ? RESOURCE_METADATA_OWNED : []),
          json.fieldGroups,
          draft ? kit.gridValuesFromDraft(draft, json.longTextAttributes)
                : {},
          { redraw: '/admin/applications/new',
            generateSecret: '/admin/applications/new',
            protocols: json.protocols }) +

        '<div class="formrow"><button type="submit">Create the ' +
        'application</button>' +
        kit.note('It is created with zero counters and a description saying ' +
        'it was made by hand, so it cannot be mistaken for one that turned ' +
          'up ' +
        'once and never came back. You land on its entry.') + '</div></form>' +

        ApplicationsPage.newApplicationNotes(json.persistence) +
          ApplicationsPage.applicationsCaveat() + APPLICATIONS_LINKS;

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
   * @returns the table row as HTML
   */
  static protocolChoiceRow(row, checked) {
    const kindCell = row.kind
      ? '<code>' + kit.esc(row.kind) + '</code>'
      : '<span class="state-none">none &mdash; this service records no ' +
        'application identifier in that family</span>';
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
   * @returns the section as HTML
   */
  static resourceMetadataLoadSection(state, facts) {
    const given = (state && state.loadInput) || {};
    const open = !!(state && (state.loaded || state.loadError));
    return '<h2>Configure it from OAuth 2.0 Protected Resource Metadata ' +
      '(RFC 9728)</h2>' +
      kit.note('A protected resource publishes a JSON document describing ' +
      'itself &mdash; at <code>' + kit.esc(facts.wellKnown) +
      '</code> under its own host. Give this page that document and it fills ' +
      'in the form below: the <code>resource</code> becomes the default ' +
      'NAME, the permission base URI (<code>oauthPermissionBaseUri</code>) ' +
      'and the AUDIENCE of tokens issued for it ' +
      '(<code>oauthAudience</code>); <code>scopes_supported</code> becomes ' +
      'the permissions it exposes; a client_id is generated at random; and ' +
      'OAuth 2.0 is ticked. Nothing is created until you press Create, and ' +
      'every value can be changed first.') +
      '<form method="post" action="/admin/applications/new" ' +
      'enctype="multipart/form-data" class="prm-load">' +
      '<input type="hidden" name="action" value="load-resource-metadata">' +
      '<input type="checkbox" id="prm-use" class="prm-use"' +
      (open ? ' checked' : '') + '> <label for="prm-use"><strong>Use a ' +
      'protected resource metadata document</strong></label>' +
      '<div class="prm-source">' +
      kit.note('Give it ONE way. A document fetched from a URL is held to ' +
      'RFC 9728 section 3.3 &mdash; its <code>resource</code> must be the ' +
      'identifier the well-known URL was built from &mdash; which ' +
      (facts.acceptsNonconforming
        ? 'this development-mode service reports and does not refuse'
        : 'this product-mode service refuses') + '. The fetch follows the ' +
      'federation outbound policy: no redirects, a size cap, a timeout, ' +
      'https with the certificate verified (plain http and a skipped ' +
      'check only in development mode)' +
      (facts.dialsInternalAddresses
        ? '.'
        : ', and never to a loopback, private or link-local address.')) +
      '<div class="formrow"><label for="prm-document">Paste it</label>' +
      '<textarea id="prm-document" name="document" rows="8" cols="60" ' +
      'placeholder="{&quot;resource&quot;: ' +
      '&quot;https://api.example.com&quot;, ' +
      '&quot;scopes_supported&quot;: [&quot;read&quot;]}">' +
      kit.esc(String(given.document || '')) + '</textarea></div>' +
      '<div class="formrow"><label for="prm-file">or upload it</label>' +
      '<input type="file" id="prm-file" name="file" ' +
      'accept="application/json,.json"></div>' +
      '<div class="formrow"><label for="prm-url">or fetch it from</label>' +
      '<input type="text" id="prm-url" name="url" size="60" value="' +
      kit.esc(String(given.url || '')) + '" ' +
        'placeholder="https://api.example.com' +
      kit.esc(facts.wellKnown) + '"></div>' +
      '<div class="formrow"><button type="submit">Load the document</button>' +
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
   * @returns the pane as HTML
   */
  static resourceMetadataPane(loaded, draft, tab) {
    const values = ApplicationsPage.resourceMetadataValues(loaded, draft);
    const open = tab || 'json';
    const radio = function (id) {
      return '<input type="radio" name="prm-tab" id="prm-tab-' + id + '" ' +
             'form="prm-tabs-not-a-form"' + (open === id ? ' checked' : '') +
             '>';
    };
    const source = loaded.source === 'url'
      ? 'fetched from <code>' + kit.esc(loaded.url) + '</code>'
      : (loaded.source === 'upload'
        ? 'uploaded' +
          (loaded.filename ? ' as <code>' + kit.esc(loaded.filename) +
                        '</code>' : '')
        : 'pasted');

    const matchOf = {};
    loaded.authorizationServers.rows.forEach(function (row) {
      matchOf[row.issuer] = row;
    });
    const tableRows = loaded.members.map(function (row) {
      let value = ApplicationsPage.resourceMetadataValueCell(row.value);
      if (row.member === 'authorization_servers' && Array.isArray(row.value)) {
        value = row.value.map(function (issuer) {
          const match = matchOf[issuer];
          return '<code>' + kit.esc(issuer) + '</code> ' +
                 (match && match.matched
            ? '<span class="state-valid">matches this realm\'s <code>' +
              kit.esc(match.authorizationServer) + '</code></span>'
            : '<span class="state-expired">not an authorization server of ' +
              'this realm</span>');
        }).join('<br>');
      }
      return '<tr><td><code>' + kit.esc(row.member) + '</code></td><td>' +
             value +
        '</td><td>' + (row.known ? kit.esc(row.type)
                                 : '<span class="state-none">extension' +
                                   '</span>') +
        '</td><td class="why">' + kit.esc(row.maps || '') + '</td>' +
        '<td class="why">' + kit.note(kit.esc(row.what)) + '</td></tr>';
    }).join('');
    const permissionRows = loaded.plan.permissions.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.scope) + '</code></td><td><code>' +
        kit.esc(one.name) + '</code></td><td><code>' + kit.esc(one.id) +
        '</code></td><td>' + (one.problem
          ? '<span class="state-expired">not usable</span>'
          : (one.duplicate
            ? '<span class="state-none">a duplicate</span>'
            : (one.sameAsAdvertised
              ? '<span class="state-valid">the scope as advertised</span>'
              : '<span class="state-none">a client asks for the identifier, ' +
                'not the scope</span>'))) + '</td></tr>';
    }).join('');
    const signed = loaded.signedMetadata
      ? '<h3>signed_metadata, decoded and not verified</h3>' +
        kit.note('Shown so it can be read. This service holds no key for ' +
        'the resource to verify it with, and none of its claims were ' +
        'applied.') +
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
              (option || '(remove the member)') + '</option>';
          }).join('') + '</select>';
      } else if (row.type === 'string-list' || row.type === 'uri-list') {
        control = '<textarea id="' + kit.esc(id) + '" name="' +
                  kit.esc(name) + '" ' +
          'rows="3" cols="50" placeholder="one per line; empty removes the ' +
          'member">' + kit.esc(current) + '</textarea>';
      } else {
        control = '<input type="text" id="' + kit.esc(id) + '" name="' +
          kit.esc(name) + '" size="50" value="' + kit.esc(current) + '" ' +
          'placeholder="empty removes the member">';
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

    const html = ApplicationsPage.resourceMetadataBanners(loaded) +
      '<div class="prm-tabs">' +
      radio('json') + radio('table') + radio('fields') +
      '<div class="prm-tablist" role="tablist">' +
      '<label for="prm-tab-json">Raw JSON</label>' +
      '<label for="prm-tab-table">Table of values</label>' +
      '<label for="prm-tab-fields">Editable fields</label></div>' +

      '<div class="prm-panel prm-panel-json">' +
      '<p class="sub">The document as it was read, ' + source + '.</p>' +
      '<pre><code>' + kit.esc(loaded.pretty) + '</code></pre></div>' +

      '<div class="prm-panel prm-panel-table">' +
      '<table><tr><th>Member</th><th>Value</th><th>Type</th>' +
      '<th>Used for</th><th>What it is</th></tr>' + tableRows + '</table>' +
      '<h3>The scopes, as permissions</h3>' +
      (permissionRows
        ? '<table><tr><th>Scope</th><th>Permission</th>' +
          '<th>Identifier a client asks for</th><th></th></tr>' +
          permissionRows + '</table>'
        : kit.note('The document names no <code>scopes_supported</code>, so ' +
                    'the application is created exposing no permissions.')) +
      '<h3>This trust realm\'s authorization servers</h3>' +
      '<table><tr><th>Authorization server</th><th>Issuer</th></tr>' +
      loaded.authorizationServers.realm.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.id) + '</code></td><td><code>' +
               kit.esc(row.issuer) + '</code></td></tr>';
      }).join('') + '</table>' + signed + '</div>' +

      '<div class="prm-panel prm-panel-fields">' +
      kit.note('These are fields of the form below, whichever tab is ' +
      'showing: edit them here and press <strong>Create the ' +
      'application</strong> at the foot of the page. Everything else on the ' +
      'page below still applies.') +
      '<input type="hidden" name="metadata" value="' +
      kit.esc(loaded.compact) +
      '">' +
      '<input type="hidden" name="metadataSource" value="' +
      kit.esc(loaded.source) + '">' +
      '<input type="hidden" name="metadataFilename" value="' +
      kit.esc(loaded.filename) + '">' +
      '<table><tr><th>Setting</th><th>Value</th><th>Where it came from</th>' +
      '</tr>' +
      field('prm-identifier', 'identifier', 'Identifier', values.identifier,
            'The key this registry files the entry under. It defaults to the ' +
            'generated client_id, which is what a protocol sighting would ' +
            'file an OAuth client under.') +
      field('prm-name', 'name', 'Name', values.name,
            'What pages call it &mdash; the document\'s ' +
            '<code>resource</code>.') +
      field('prm-client-id', 'field.oauthClientId',
            '<code>oauthClientId</code>', values.clientId,
            'Generated at random, in the shape a dynamic client registration ' +
            'mints.') +
      field('prm-base', 'field.oauthPermissionBaseUri',
            '<code>oauthPermissionBaseUri</code>', values.baseUri,
            'The document\'s <code>resource</code>. A permission is this ' +
            'followed by its name.') +
      field('prm-audience', 'field.oauthAudience',
            '<code>oauthAudience</code>', values.audience,
            'The document\'s <code>resource</code>: the audience a token for ' +
            'this application carries. One per line.', true) +
      field('prm-permissions', 'field.oauthPermission',
            '<code>oauthPermission</code>', values.permissions,
            'One per line, <code>name</code> or ' +
            '<code>name|description</code>, from ' +
            '<code>scopes_supported</code> with the resource prefix taken ' +
            'off. A scope that cannot be a permission is left out.', true) +
      field('prm-details-types', 'field.oauthAuthorizationDetailsType',
            '<code>oauthAuthorizationDetailsType</code>', values.detailsTypes,
            'One per line, from <code>authorization_details_types_supported' +
            '</code> (RFC 9396): the types a rich authorization request may ' +
            'name for this API. A line may be a JSON definition with a ' +
            '<code>schema</code>; <code>openid_credential</code> and a type ' +
            'another application declares are left out.', true) +
      (values.url
        ? field('prm-url-field', 'field.oauthResourceMetadataUrl',
                '<code>oauthResourceMetadataUrl</code>', values.url,
                'Where the document was fetched from. Recorded, never ' +
                'fetched again.')
        : '') +
      '</table>' +
      '<h3>The document\'s members</h3>' +
      kit.note('What the document said, editable. The document stored on ' +
      'the entry as <code>oauthResourceMetadata</code> is the one you loaded ' +
      'with these edits applied; an emptied box removes that member. ' +
      (loaded.extensions.length
        ? 'Its ' + loaded.extensions.length + ' extension member(s) &mdash; ' +
          loaded.extensions.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(', ') + ' &mdash; are kept as they were. '
        : '') +
      'Changing a member here does not change the settings above: the name, ' +
      'base URI and audience were filled in from <code>resource</code> when ' +
      'the document was loaded.') +
      (memberRows
        ? '<table><tr><th>Member</th><th>Value</th><th>What it is</th></tr>' +
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
   * @returns the banners as HTML
   */
  static resourceMetadataBanners(loaded) {
    const servers = loaded.authorizationServers;
    let html = '';
    if (!servers.listed) {
      html += kit.note('<strong>The document names no authorization ' +
        'server.</strong> <code>authorization_servers</code> is optional, so ' +
        'there is nothing to compare with this realm\'s.');
    } else if (servers.allMatched) {
      html += '<div class="ok"><strong>Every authorization server it names ' +
        'is one this trust realm publishes</strong> &mdash; ' +
        servers.rows.map(function (row) {
          return '<code>' + kit.esc(row.issuer) + '</code> is <code>' +
                 kit.esc(row.authorizationServer) + '</code>';
        }).join(', ') + '.</div>';
    } else {
      const unmatched = servers.rows.filter(function (row) {
        return !row.matched;
      });
      // NOT kit.warn(), which folds prose longer than a line behind its opening
      // sentence: the issuers that did not match ARE this banner, and a fold
      // would put them where a reader skimming for the colour does not look.
      html += '<div class="warn"><strong>' + unmatched.length + ' of the ' +
        servers.listed +
        ' authorization server(s) this document names ' +
        (unmatched.length === 1 ? 'is' : 'are') + ' not one this trust realm ' +
        'publishes:</strong> ' + unmatched.map(function (row) {
          return '<code>' + kit.esc(row.issuer) + '</code>';
        }).join(', ') + '. The resource expects tokens from ' +
        (unmatched.length === 1 ? 'an issuer' : 'issuers') + ' this service ' +
        'is not, at the address this page was reached on. You can still ' +
        'create the application; a token this realm issues for it will carry ' +
        'an <code>iss</code> the resource was not told to trust. This realm ' +
        'publishes ' + servers.realm.map(function (row) {
          return '<code>' + kit.esc(row.issuer) + '</code>';
        }).join(', ') + '.</div>';
    }
    const check = loaded.resourceCheck;
    if (check.checked && check.matches) {
      html += '<div class="ok"><strong>RFC 9728 section 3.3:</strong> ' +
              kit.esc(check.why) + '</div>';
    } else if (!check.checked) {
      html += kit.note('<strong>RFC 9728 section 3.3 was not ' +
        'checked.</strong> ' +
                        kit.esc(check.why));
    }
    if (loaded.warnings.length) {
      html += '<div class="warn"><strong>' + loaded.warnings.length +
        ' thing(s) to know before creating it:</strong><ul>' +
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
   * @returns the cell's HTML
   */
  static resourceMetadataValueCell(value) {
    if (Array.isArray(value)) {
      return value.map(function (one) {
        return '<code>' + kit.esc(typeof one === 'string' ? one :
                                   JSON.stringify(one)) + '</code>';
      }).join('<br>') || '<span class="state-none">(empty)</span>';
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
   * @returns the notes as HTML
   */
  static newApplicationNotes(store) {
    return (
      kit.note('<strong>Declaring a protocol family grants nothing, ' +
      'and in product mode it refuses the rest.</strong> The issuance ' +
      'policy refuses, in product mode, an issuance through a family the ' +
      'application is not declared for: an application declared for SAML 2.0 ' +
      'alone is refused an access token at <code>/oauth2/token</code>. In ' +
      'development the declaration is a RECORD OF INTENT &mdash; what this ' +
      'application is FOR &mdash; and refuses nothing, and an application ' +
      'declared for nothing at all is refused nothing in either mode. The ' +
      'configuration that ' +
      'DOES take effect is the attributes underneath: give the entry its ' +
      'redirect URIs, its grant types and its secret from <a ' +
      'href="/admin/applications">Applications</a>, and ' +
      'RFC 9700 mode judges the next request against them.') +
      kit.note('<strong>The families are DECLARED; ' +
      '<code>appProtocol</code> is what HAPPENED.</strong> Those two ' +
      'attributes sit next to each other on the entry and must not be read ' +
        'as ' +
      'one thing. This form writes the first; the second is accumulated by ' +
        'the ' +
      'protocol endpoints as they accept this identifier and is not editable ' +
      'here, for the reason every derived attribute on that page is not ' +
      '&mdash; a form that could rewrite it would make this console lie ' +
        'about ' +
      'the service\'s own behaviour, in a way indistinguishable from the ' +
      'recording being broken. The Applications drill-down shows both side ' +
        'by ' +
      'side, and says ' +
      'which of the declared families the entry has actually been recorded ' +
        'in.') +
      kit.note('<strong>One entry per identifier, whatever protocol ' +
      'brought it.</strong> The key is the identifier exactly as it arrives ' +
      '&mdash; not lower-cased and not namespaced by protocol &mdash; so ' +
        'this ' +
      'is refused if the registry already holds one under that name, and an ' +
      'application that appears under one name in two protocols is one entry ' +
      'with two kinds. Change what an existing one holds rather than ' +
        'creating ' +
      'it ' +
      'again.') +
      // WHETHER an application entry survives a restart is a property of the
      // whole service rather than of this page, which is why this note is
      // computed here rather than asserted: an application IS a directory
      // entry, so it persists exactly when the directory does.
      (store.persistsDirectory
        ? '<div class="ok"><strong>This entry will survive a ' +
          'restart.</strong> ' +
          'An application here is a directory entry under ' +
          '<code>ou=applications</code>, and this process is running with ' +
          '<code>persistence.mode=' +
          kit.esc(store.mode) + '</code> ' +
          '— so it is written down along with every other application, ' +
            'person, ' +
          'group, federation relationship and SPIFFE registration. That is a ' +
          'property of the whole service and not of this page; see <a ' +
          'href="/admin/persistence">Persistence</a>.</div>'
        : kit.note('<strong>Nothing here is persisted on this ' +
          'process.</strong> The entry is gone on restart, along with every ' +
          'other application, person and group in the directory. That is a ' +
          'property of the whole service and not of this page, and it is ' +
          'changeable: <a href="/admin/persistence">Persistence</a> writes ' +
            'the ' +
          'directory down, and is off by default.')));
  }
}

export = ApplicationsPage;
