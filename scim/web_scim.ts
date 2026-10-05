// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scim.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SCIM AND MONITORING → SCIM, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Draws SCIM from the answer of `GET /admin-api/scim` and SCIM activity from
// that of `GET /admin-api/scim/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/scim` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws SCIM from the answer of `GET /admin-api/scim` and SCIM activity from
 * that of `GET /admin-api/scim/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ScimPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const counters = json.counters;

    // The `<div class="tiles">` around them was missing since this page was
    // written, so its six tiles were six full-width blocks down the page
    // where every other page here has one row. Nothing failed and nothing
    // could have shown it: `.tile` draws correctly on its own, and it is the
    // CONTAINER that makes a row.
    const tiles = '<div class="tiles">' +
      kit.tile(counters.total, 'SCIM requests') +
      kit.tile(counters.ok, 'answered') +
      kit.tile(counters.failed, 'refused') +
      kit.tile(json.store ? json.store.userCount : '—',
                'people in the directory') +
      kit.tile(json.store ? json.store.groupCount : '—', 'groups') +
      kit.tile(json.store ? json.store.entryCount + ' / ' +
                json.store.maxEntries :
                '—', 'entries ' +
          '/ max') +
      '</div>';

    const operationRows = counters.operations.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) + '</code> ' +
             kit.esc(row.label) +
        '</td><td ' +
        'class="num">' + row.count + '</td>' +
        '<td class="sub">' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const typeRows = counters.resourceTypes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td class="num">' + row.count + '</td></tr>';
    }).join('');

    const statusRows = Object.keys(counters.byStatus).sort()
      .map(function (code) {
      return '<tr><td><code>' + kit.esc(code) + '</code></td><td ' +
        'class="num">' +
        counters.byStatus[code] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">Nothing has been answered yet.</td></tr>';

    const scimTypeRows = Object.keys(counters.byScimType)
                               .sort()
                               .map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
        'class="num">' +
        counters.byScimType[name] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">Nothing has been refused yet, which on ' +
                   'a server this permissive usually means nothing has ' +
                   'tried the error paths.</td></tr>';

    const endpointRows = json.endpoints.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) +
             '</code></td><td><code>' +
        kit.esc(row.path) + '</code></td><td class="sub">' +
        kit.esc(row.what) +
        '</td></tr>';
    }).join('');

    const negativeRows = json.reachableNegatives.map(function (row) {
      return '<tr><td>' + kit.esc(row.what) + '</td><td>' +
             kit.esc(row.answer) +
             '</td></tr>';
    }).join('');

    function mappingTable(rows) {
      return '<table><tr><th>SCIM</th><th>LDAP attribute</th><th>How</th>' +
        '<th>Defined by</th></tr>' +
        rows.map(function (row) {
          return '<tr><td><code>' + kit.esc(row.scim) + '</code>' +
            (row.required ? ' <span class="state-valid">required</span>' :
             '') +
            (row.extension ?
             ' <span class="sub">(enterprise extension)</span>' :
             '') +
            '</td>' +
            '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
            '<td>' + kit.esc(row.kind) +
            (row.readOnly ? ', read-only' : '') +
            (row.note ? '<div class="sub">' + kit.esc(row.note) + '</div>' :
             '') +
            '</td><td ' +
            'class="sub">' + kit.esc(row.schema) + '</td></tr>';
        }).join('') + '</table>';
    }

    const inner = (!json.installed
        ? '<div class="err"><strong>SCIM is not loaded in this ' +
          'process.</strong> The module registers no routes here, so there ' +
          'is nothing to report. Everything else on this console is ' +
          'unaffected.</div>'
        : '') +

      // WHERE THE TRAFFIC QUESTION IS ANSWERED. This page keeps the headline
      // counts — a page about a surface with no evidence anything ever called
      // it is a page about a hypothesis — and everything past them is over
      // there: who is calling, how long it took, what came back, and the last
      // fifty requests individually. Both are drawn from ONE set of counters
      // in `admin_stats.js` through two functions, so there is no second
      // tally to disagree with this one.
      kit.note('The counters below are the headline. <strong><a ' +
      'href="/admin/scim/monitor">Monitoring &rarr; SCIM ' +
      'metrics</a></strong> is the traffic in full: who is calling &mdash; ' +
      'one row per authenticated principal &mdash; how long each kind of ' +
      'call took, how many bytes went back, what the failures were, and ' +
      'the last fifty requests one by one. Both pages read one set of ' +
      'numbers, so they cannot disagree; this page is about what the ' +
      'surface IS, and that one about what it is DOING.') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>SCIM is turned off</strong> ' +
          '(<code>scim.enabled</code>). The routes are still registered ' +
          'and answer <code>501</code> rather than <code>404</code>, ' +
          'because the feature being off and the URL being wrong are ' +
          'different sentences to a client. Turn it back on in the ' +
          'settings at the foot of this page.')
        : '') +

      kit.note('SCIM 2.0 — RFC 7642, 7643 and 7644 — at <code>' +
      kit.esc(json.baseUrl || '/scim/v2') + '</code>. It is the only ' +
      'protocol family here whose purpose is to WRITE, and what it writes ' +
      'is the embedded LDAP directory: there is no second store and no ' +
      'cache. A <code>POST /scim/v2/Users</code> and an ' +
      '<code>ldapadd</code> create the same entry, so somebody provisioned ' +
      'over SCIM appears on <a href="/admin/users">Users</a>, gains ' +
      'whatever attributes <a href="/admin/vc">Credential claims</a> ' +
      'selects, and lands in whatever group a client puts them in on <a ' +
      'href="/admin/groups">Groups</a>.') +

      kit.warn('<strong>These endpoints create and delete accounts, and ' +
      'they are the one surface in this service that requires a credential' +
      (json.authentication && !json.authentication.required
        ? ' — except that it is currently turned off here, so ' +
          'right now they do not'
        : '') + '.</strong> Almost nothing is checked about it: every ' +
      'scheme below is permissive, so this is a turnstile rather than a ' +
      'lock. What it buys is that a client\'s 401, 403 and ' +
      'challenge-response paths can be exercised at all. <strong>And ' +
      '<code>active: false</code> disables the account</strong> (since ' +
      '2026-09-17) — it writes the password-policy lock ' +
      '<code>pwdAccountLockedTime</code>, every door then refuses the ' +
      'person, and everything they held is ended, as the Disable button ' +
      'on their <code>/admin/users</code> page does.') +

      tiles +

      (json.authentication ?
       ScimPage.authenticationSection(json.authentication, counters) : '') +

      '<h2>Operations</h2>' +
      kit.note('Every operation this server implements, including the ' +
      'ones nothing has used yet — a table listing only what has happened ' +
      'would answer &ldquo;does this support PATCH?&rdquo; by omission. ' +
      '<strong>The column does not tally</strong>, on purpose: one ' +
      '<code>Bulk</code> carrying five creates is one bulk AND five ' +
      'creates, because each of the five really is performed.') +
      '<table><tr><th>Operation</th><th class="num">Count</th><th>What it ' +
      'is</th></tr>' +
      operationRows + '</table>' +

      '<h2>By resource type</h2>' +
      '<table><tr><th>Resource type</th><th class="num">Count</th></tr>' +
      typeRows +
      '</table>' +

      '<h2>What went back</h2>' +
      kit.note('The HTTP status of every answer, and the ' +
      '<code>scimType</code> of every refusal (RFC 7644 section 3.12). ' +
      '<code>(none)</code> is a refusal that carried no such code — a 404 ' +
      'has none — and is counted rather than dropped, so the two failure ' +
      'tables agree with each other.') +
      '<div class="tiles" style="align-items:flex-start">' +
      '<div><table><tr><th>Status</th><th class="num">Count</th></tr>' +
      statusRows +
      '</table></div>' +
      '<div><table><tr><th>scimType</th><th class="num">Count</th></tr>' +
      scimTypeRows + '</table></div></div>' +

      (json.identifiers
        ? '<h2>The <code>id</code> is the DN</h2>' +
          kit.note(kit.esc(json.identifiers.why)) +
          kit.note('For example: <code>' +
                    kit.esc(json.identifiers.example) +
          '</code>')
        : '') +

      (endpointRows
        // NOT "Endpoints": that heading is the realm's addresses, which
        // `respond()` draws at the top of every Protocols page. This table is
        // what each operation DOES, by method and path under `/scim/v2`.
        ? '<h2>What each operation does</h2><table><tr><th>Method</th>' +
          '<th>Path</th><th>' +
          'What</th></tr>' + endpointRows + '</table>'
        : '') +

      (json.doesNotDo.length
        ? '<h2>What it deliberately does not do</h2><ul>' +
          json.doesNotDo.map(function (text) {
            return ScimPage.bullet(kit.esc(text));
          }).join('') + '</ul>'
        : '') +

      (negativeRows
        ? '<h2>Things you can make fail</h2>' +
          kit.note('A permissive server is hard to write error handling ' +
          'against, so these are here on purpose — the same device as the ' +
          'reserved password <code>invalid</code> everywhere else in this ' +
          'service.') +
          '<table><tr><th>Do this</th><th>Get this</th></tr>' + negativeRows +
          '</table>'
        : '') +

      '<h2>The User mapping</h2>' +
      kit.note('Which LDAP attribute each SCIM member is. The attribute ' +
      'spellings are the same catalogue <a href="/admin/vc">Credential ' +
      'claims</a> and <a href="/admin/claims">Custom claims</a> read, ' +
      'checked against it at startup rather than copied — four ' +
      'independently maintained lists of spellings is how one of them ' +
      'comes to be quietly wrong.') +
      mappingTable(json.mapping.user) +

      '<h2>The Group mapping</h2>' +
      mappingTable(json.mapping.group) +

      // THIS PAGE USED TO SAY IT HAD NO CONTROLS, and the sentence it said it
      // in was the one every other page here cited: "a form here would be a
      // second door to one setting". What that argument was actually
      // protecting is the ONE-STORE rule, and the form below does not break
      // it — it is `configSection()`, posting to the same action against the
      // same override map as /admin/config, which is the arrangement
      // /admin/token-lifetimes established. What has changed is only which
      // page draws the door.
      SettingsForms.forms(json.settings, '/admin/scim') +
      kit.note('These are the settings; everything else on this page is a ' +
      'reading. What SCIM has WRITTEN is not configuration at all — it ' +
      'went into the embedded directory, so it is on <a ' +
      'href="/admin/users">Users</a> and <a ' +
      'href="/admin/groups">Groups</a>.') +

      kit.note('<a href="/scim">What this is, for a person</a> &middot; ' +
      '<a href="/admin/scim/monitor">what it has actually been asked to ' +
      'do</a> &middot; <a href="/admin/scim?format=json">this page as ' +
      'JSON</a> &middot; <a href="/admin-api/scim">the same over the ' +
      'management API</a> &middot; <a href="/admin/ldap/service">the ' +
      'directory it writes into</a>');

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE AUTHENTICATION SECTION OF /admin/scim.
  //
  // Two tables and a list, and the division between them is the one this page
  // already draws everywhere else: the SCHEMES come from scim.js's
  // description() — which is scim_auth.js's table, the same one that builds the
  // WWW-Authenticate challenge and the ServiceProviderConfig — while the COUNTS
  // come from admin_stats.js. So a scheme that is offered cannot be missing
  // from this page and a count cannot be attributed to a scheme that does not
  // exist.
  //
  // Every scheme is drawn INCLUDING the ones at zero and the ones turned off,
  // for the reason the operations table below draws its zeroes: "can I use
  // Digest against this server" is the question somebody arrives with, and a
  // table that listed only what had been used would answer it by omission.
  //
  // There are no CONTROLS in this section, which is what keeps rule 7 satisfied
  // with only a GET on /admin-api/scim: every one of these is a config.js row,
  // drawn in the page's settings block (`configFormsFor('/admin/scim')`), which
  // posts to /admin/config — and POST /admin-api/config/set already has the
  // operation. A second form here would be a second door to one setting.
  // ---------------------------------------------------------------------------
  /**
   * Draws the Authentication section of /admin/scim: every scheme with its
   * state, scope and request count, the anonymous and refused counts, and
   * the access control policy.
   *
   * @param auth - the authentication description from scim.js
   * @param counters - the SCIM counters, with byAuthScheme
   * @returns the section as HTML
   */
  static authenticationSection(auth, counters) {
    const counts = (counters && counters.byAuthScheme) || {};
    const rows = auth.schemes.map(function (row) {
      return '<tr><td>' + kit.esc(row.name) +
        (row.primary ? ' <span class="sub">(primary)</span>' : '') +
        // The scheme's description is scim_auth.js's own and is a paragraph on
        // every row, so five of them made this the longest table on the page
        // while the column somebody scans — the scheme's NAME — was one line.
        kit.note(kit.esc(row.description)) + '</td>' +
        '<td><code>' + kit.esc(row.type) + '</code>' +
        (row.canonical ? '' : '<div class="sub">no canonical value in RFC ' +
          '7643 section 5 — published beside the four that have one</div>') +
          '</td>' +
        '<td>' + (row.enabled
          ? '<span class="state-valid">offered</span>'
          : '<span class="state-none">off</span>') +
        '<div class="sub"><code>' + kit.esc(row.setting) +
        '</code></div></td>' +
        '<td>' + (row.scoped ? 'what its scopes say' : 'everything') + '</td>' +
        '<td class="num">' + (counts[row.id] || 0) + '</td></tr>';
    }).join('');
    const extra = ['anonymous', 'refused'].map(function (name) {
      return '<tr><td>' + kit.esc(name === 'anonymous'
        ? 'Nothing (an open discovery call, or authentication turned off)'
        : 'Refused before any handler ran') +
          '</td><td></td><td></td><td></td>' +
        '<td class="num">' + (counts[name] || 0) + '</td></tr>';
    }).join('');
    const policy = auth.policy.map(function (text) {
      return ScimPage.bullet(kit.esc(text));
    }).join('');
    const out = '<h2>Authentication</h2>' +
      kit.note('RFC 7644 section 2 defines no credential of its own — it ' +
      'delegates to TLS and RFC 7235 and NAMES six schemes, and all six are ' +
      'here. Its one SHALL is that the schemes be indicated in ' +
      '<code>WWW-Authenticate</code>, which every 401 from these endpoints ' +
      'carries; its one MUST is that an authenticated client be mappable to ' +
      'an access control policy, which is the list below. Realm <code>' +
      kit.esc(auth.realm) + '</code>. Discovery is ' +
      (auth.discoveryOpen
        ? 'OPEN, because a client has to be able to read which schemes exist ' +
          'before it can use one'
        : 'closed as well (<code>scim.authDiscovery</code>)') + '. Every ' +
      'switch here is in the settings at the foot of this page.') +
      '<table><tr><th>Scheme</th><th>type</th><th>State</th><th>May do</th>' +
      '<th class="num">Requests</th></tr>' + rows + extra + '</table>' +
      kit.note('The two OAuth scopes are <code>' + kit.esc(auth.scopes.read) +
      '</code> and <code>' + kit.esc(auth.scopes.write) + '</code> — the ' +
      'first scope requirement anywhere in this service — and they are ' +
      'published in <code>scopes_supported</code> in both discovery ' +
      'documents. Digest offers ' +
      kit.esc(auth.digestAlgorithms.join(', ')) + '; HOBA keys are ' +
      'registered at <code>' + kit.esc(auth.hobaRegistration) + '</code> ' +
      'and land on the person\'s own directory entry, so <a ' +
      'href="/admin/users">Users</a> shows them.') +
      '<h3>The access control policy</h3><ul class="note">' + policy + '</ul>';
    return out;
  }

  // One item of a prose list — the *what it deliberately does not do* lists,
  // and nothing else. Every one of those bullets opens with a bolded headline
  // and then argues it for a paragraph, which is exactly the shape a fold
  // suits: the list stays a list of claims, and the argument for each is under
  // it.
  /**
   * Draws one item of a prose list, folded when longer than a line.
   *
   * An item opening with a link is never folded; one opening with `<code>`
   * keeps it in the summary.
   *
   * @param html - the item as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the `<li>` as HTML
   */
  static bullet(html, label?) {
    // Coerced once, here: a caller may hand this a number of rows or a
    // fragment built by a .map(), and everything below slices and measures.
    html = String(html == null ? '' : html);
    const text = kit.plainTextOf(html);
    if (!label && kit.visibleLength(text) <= kit.ONE_LINE_CHARS) {
      return '<li>' + html + '</li>';
    }

    // AN ITEM THAT OPENS WITH A LINK IS NEVER FOLDED, and this is the rule that
    // stops this helper quietly breaking two lists. The Overview page's list of
    // every console page and the sidebar's are the same list, and each row of
    // it IS a link — folding one puts the only control in the row behind a
    // summary made of text, so the reader has to open the thing to find out it
    // was the link they were looking for. A link inside a <summary> is also a
    // control inside a control, which browsers resolve differently from each
    // other.
    if (/^\s*<a\b/i.test(html)) {
      return '<li>' + html + '</li>';
    }

    // AN ITEM THAT OPENS WITH A CODE PATH KEEPS IT IN THE SUMMARY. The
    // machine-readable lists here are a URL and then a paragraph about it, and
    // the URL is what somebody came for — but <code> is not interactive, so it
    // can sit in the summary beside the teaser rather than forcing the whole
    // row open. This is why fold.summary is escaped everywhere else and this
    // one place composes markup: the prefix is the caller's own element, and
    // only the text after it is escaped.
    const lead = /^\s*(<code\b[^>]*>[\s\S]*?<\/code>)/i.exec(html);
    if (!label && lead) {
      const rest = html.slice(lead[0].length).replace(/^[\s,—-]+/, '');
      return '<li class="foldli"><details class="fold"><summary>' + lead[1] +
             ' ' +
             kit.teaserOf(kit.plainTextOf(rest)) + '</summary><div ' +
               'class="foldbody">' +
             rest + '</div></details></li>';
    }

    const fold = kit.foldOf(html, label);
    return '<li class="foldli"><details class="fold"><summary>' + fold.summary +
           '</summary><div class="foldbody">' + fold.body +
           '</div></details></li>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const c: any = json.counters;

    const tiles = '<div class="tiles">' +
      kit.tile(c.calls, 'API calls') +
      kit.tile(c.ok, 'successful') +
      kit.tile(c.failed, 'failed') +
      kit.tile(c.successRate === null ? '—' : c.successRate + '%',
                'success rate') +
      kit.tile(c.authentication.distinct, 'clients') +
      kit.tile(c.latency.averageMs === null ? '—' : c.latency.averageMs +
                ' ms',
                'average') +
      '</div>';

    // THE BREAKDOWN BY CALL TYPE, which is the table this page exists for.
    // Every operation the server implements is drawn INCLUDING the ones at
    // zero — the vocabulary is admin_stats.js's SCIM_OPERATIONS, so an
    // operation cannot be performed and go unreported nor be reported and
    // never occur.
    const operationRows = c.operations.map(function (row) {
      return '<tr><td>' +
        (row.method ? '<code>' + kit.esc(row.method) + '</code> ' : '') +
        kit.esc(row.label) + '</td>' +
        '<td class="num">' + row.count + '</td>' +
        '<td class="num">' + row.ok + '</td>' +
        '<td class="num">' + row.failed + '</td>' +
        '<td class="num">' + (row.averageMs === null ? '—' :
                              row.averageMs) + '</td><td ' +
        'class="num">' + (row.maxMs === null ? '—' : row.maxMs) + '</td>' +
        '<td class="num">' + row.bytes + '</td>' +
        '<td class="sub">' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const resourceRows = c.resourceTypes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td class="num">' + row.count + '</td></tr>';
    }).join('');

    // THE CLIENTS. Sorted busiest first by the snapshot, because that and
    // "most recent" are the two orders somebody reading a traffic page wants
    // and alphabetical is neither.
    const clientRows = c.clients.map(function (row) {
      return '<tr><td>' + kit.shortened(row.principal, 40) + '</td>' +
        '<td>' + (row.kind === 'application'
          ? 'application <span class="sub">(a client_id)</span>'
          : 'identity') + '</td>' +
        '<td>' + row.schemes.map(function (s) {
          return '<code>' + kit.esc(s) + '</code>';
        }).join(' ') + '</td>' +
        '<td class="num">' + row.calls + '</td>' +
        '<td class="num">' + row.ok + '</td>' +
        '<td class="num">' + row.failed + '</td>' +
        '<td>' + kit.esc(row.lastOperation || '—') + ' <span class="sub">' +
        kit.esc(row.lastStatus || '') + '</span></td>' +
        '<td class="sub">' + kit.esc(kit.whenText(row.firstAt)) + '</td>' +
        '<td class="sub">' + kit.esc(kit.whenText(row.lastAt)) +
        '</td></tr>';
    }).join('') || '<tr><td colspan="9">Nothing has authenticated yet. ' +
      (json.authRequired
        ? 'Every call to <code>/scim/v2</code> needs a credential, so this ' +
          'table filling up is the first sign a provisioning client has ' +
          'been configured at all. <strong>The gate being on is not the ' +
          'same as the credential being checked</strong>: what ' +
          '<code>global.mode</code> decides is whether the answer is ' +
          'VERIFIED, and the turnstile is there in both modes.'
        : '<strong>The SCIM gate is off in this build</strong> ' +
          '(<code>mode.gatesScim()</code>), so callers are not asked for a ' +
          'credential and are counted as anonymous rather than as clients. ' +
          'This table stays empty however much traffic there is until it ' +
          'is on.') +
      '</td></tr>';

    // The scheme table, with the declared vocabulary first and anything
    // counted under a name it does not declare after it.
    const declared = {};
    const schemeRows = json.schemes.map(function (row) {
      declared[row.id] = true;
      return ScimPage.scimSchemeRow(row.id, row.name, row.enabled,
                                c.authentication.byScheme[row.id] || 0,
                                kit.esc(row.spec || ''));
    }).join('') +
    ScimPage.scimSchemeRow('anonymous', '', null,
                       c.authentication.byScheme.anonymous || 0,
      'Nothing authenticated the caller: a discovery endpoint, which is ' +
      'open unless <code>scim.authDiscovery</code> says otherwise.') +
    ScimPage.scimSchemeRow('refused', '', null,
                       c.authentication.byScheme.refused || 0,
      '<strong>The gate turned the caller away.</strong> These are counted ' +
      'here and deliberately NOT attributed to a client, even when the ' +
      'credential carried a name.') +
    Object.keys(c.authentication.byScheme).sort().filter(function (id) {
      return !declared[id] && id !== 'anonymous' && id !== 'refused';
    }).map(function (id) {
      return ScimPage.scimSchemeRow(id, '', null, c.authentication.byScheme[id],
        'Counted under a name the surface does not declare. Shown rather ' +
        'than dropped, so the column still adds up.');
    }).join('');

    const statusClassRows = Object.keys(c.byStatusClass).sort()
      .map(function (k) {
      return '<tr><td><code>' + kit.esc(k) + '</code></td><td class="num">' +
        c.byStatusClass[k] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">Nothing has been answered yet.</td></tr>';

    const statusRows = Object.keys(c.byStatus).sort().map(function (code) {
      return '<tr><td><code>' + kit.esc(code) + '</code></td><td ' +
        'class="num">' +
        c.byStatus[code] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">Nothing has been answered yet.</td></tr>';

    const scimTypeRows = Object.keys(c.byScimType).sort()
      .map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
        'class="num">' +
        c.byScimType[name] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">Nothing has been refused yet.</td></tr>';

    const recentRows = c.recent.map(function (row) {
      return '<tr><td class="sub">' + kit.esc(kit.whenText(row.at)) +
             '</td>' +
        '<td>' +
        (row.method ? '<code>' + kit.esc(row.method) + '</code> ' : '') +
        kit.esc(row.operation) + '</td>' +
        '<td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td>' +
        (row.ok ? '<span class="state-valid">' + kit.esc(row.status) +
         '</span>'
                         : '<span class="state-revoked">' +
                           kit.esc(row.status) +
                           '</span>') +
        (row.scimType ? ' <span class="sub">' + kit.esc(row.scimType) +
         '</span>' :
         '') +
        '</td>' +
        '<td>' + (row.principal ? kit.shortened(row.principal, 24)
                                : '<span class="sub">' +
                                  kit.esc(row.scheme) +
                                  '</span>') +
        '</td>' +
        '<td class="num">' + (row.ms === null ? '—' : row.ms) + '</td>' +
        '<td class="num">' + row.bytes + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="7">Nothing has been called yet.</td></tr>';

    const inner = (!json.installed
        ? '<div class="err"><strong>SCIM is not loaded in this ' +
          'process.</strong> The module registers no routes here, so there ' +
          'is no traffic to report and the zeroes below mean "no such ' +
          'endpoint" rather than "no calls". Everything else on this ' +
          'console is unaffected.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>SCIM is turned off</strong> ' +
          '(<code>scim.enabled</code>), so every call under ' +
          '<code>/scim/v2</code> is answered <code>501</code> — and IS ' +
          'COUNTED HERE, because it is a request this service answered. A ' +
          'page whose totals went flat while a client kept calling would ' +
          'be hiding the very thing somebody came to this page to find. ' +
          'Turn it back on at <a href="/admin/scim">Protocols &rarr; ' +
          'SCIM</a>.')
        : '') +

      kit.note('<strong>What the provisioning surface has actually been ' +
      'asked to do</strong>, since this process started at <code>' +
      kit.esc(kit.whenText(c.since)) + '</code>. Every request the SCIM ' +
      'implementation had an opinion about is counted here — including the ' +
      'ones its own authentication gate refused, because a ' +
      '<code>401</code> is a call this service answered and a total that ' +
      'quietly omitted them would be smaller than the access log for no ' +
      'stated reason. The counters are IN MEMORY and per trust realm (this ' +
      'is <code>' + kit.esc(c.realm.name || c.realm.id ||
      'the default realm') + '</code>): they die with the process, because ' +
      'these are observations and this service persists nothing it ' +
      'observes. The durable record of what SCIM was ASKED to do is the <a ' +
      'href="/admin/audit">audit log</a>, which has the actor and the ' +
      'target as well as the count. What the surface IS — the schemes, the ' +
      'endpoints, the attribute mapping and the eighteen settings — is <a ' +
      'href="/admin/scim">Protocols &rarr; SCIM</a>; both pages read one ' +
      'set of counters, so they cannot disagree.') +

      tiles +

      '<h2>By API call type</h2>' +
      kit.note('Every operation this server implements, <strong>including ' +
      'the ones nothing has called</strong> — a table listing only what ' +
      'has happened would answer &ldquo;does this support PATCH?&rdquo; by ' +
      'omission. <strong>The count column does not tally with the call ' +
      'total, on purpose</strong>: one <code>Bulk</code> carrying five ' +
      'creates is one <code>bulk</code> AND five <code>create</code>s, ' +
      'because each of the five really is performed. A duration is shown ' +
      'as <code>&mdash;</code> rather than <code>0</code> where nothing ' +
      'was measured, because an average over no samples is absent and not ' +
      'zero — a column of <code>0.0</code> would read as a server ' +
      'answering instantly.') +
      '<table><tr><th>Operation</th><th class="num">Calls</th>' +
      '<th class="num">OK</th><th class="num">Failed</th>' +
      '<th class="num">Avg ms</th><th class="num">Max ms</th>' +
      '<th class="num">Bytes out</th><th>What it is</th></tr>' +
      operationRows + '</table>' +

      '<h2>By resource type</h2>' +
      '<table><tr><th>Resource type</th><th class="num">Calls</th></tr>' +
      resourceRows + '</table>' +

      '<h2>Clients</h2>' +
      kit.note('<strong>A client here is an authenticated principal, not ' +
      'a connection.</strong> SCIM is stateless HTTP — there is no ' +
      'session, no registration and nothing to be connected — so the only ' +
      'honest reading of &ldquo;how many clients&rdquo; is how many ' +
      'distinct names have successfully authenticated since this process ' +
      'started. The figure never goes down: a provisioning client that has ' +
      'stopped calling is indistinguishable from one that is between ' +
      'calls. The name is whatever the credential carried — a username for ' +
      'the five user-bearing schemes, a <code>client_id</code> for a ' +
      'Bearer token minted for an application (shown as ' +
      '<em>application</em>), and an RFC 4514 subject DN for a client ' +
      'certificate. <strong>A caller the gate refused is not a client and ' +
      'is not in this table</strong>, even when the credential carried a ' +
      'name: Basic and Digest both put one on the wire, and attributing ' +
      'traffic to an identity this service declined to believe is the one ' +
      'mistake this page could make that would matter. Those are the ' +
      '<code>refused</code> row below.') +
      '<div class="tiles">' +
      kit.tile(c.authentication.distinct, 'distinct clients') +
      kit.tile(c.authentication.identities, 'people') +
      kit.tile(c.authentication.applications, 'applications') +
      kit.tile(c.authentication.anonymous, 'anonymous calls') +
      kit.tile(c.authentication.refused, 'refused at the gate') +
      '</div>' +
      (c.authentication.capped
        ? kit.warn('<strong>The client table stopped growing at ' +
          c.authentication.cap + ' names.</strong> Every call is still ' +
          'counted in every total above; it is only this breakdown that is ' +
          'capped, because the principal is whatever the caller typed — ' +
          'Basic here accepts any username — and an unbounded table is a ' +
          'store somebody else decides the size of. The cap is said out ' +
          'loud rather than letting the page under-report quietly.')
        : '') +
      '<table><tr><th>Principal</th><th>Kind</th><th>Schemes</th><th ' +
      'class="num">Calls</th><th class="num">OK</th><th ' +
      'class="num">Failed</th><th>Last</th><th>First seen</th><th>Last ' +
      'seen</th></tr>' +
      clientRows + '</table>' +

      '<h2>By authentication scheme</h2>' +
      kit.note('All six schemes RFC 7644 section 2 names, whether each is ' +
      'switched on, and how many calls came in over it — the ones at zero ' +
      'included, because a scheme that is OFF and unused is the most ' +
      'useful row here for somebody asking why a client cannot get in. The ' +
      'list is <code>scim_auth.js</code>\'s own, the same table the ' +
      '<code>WWW-Authenticate</code> challenge and the ' +
      '<code>ServiceProviderConfig</code> are built from, so this cannot ' +
      'name a scheme a client would not be offered.') +
      '<table><tr><th>Scheme</th><th>Enabled</th><th class="num">Calls</th>' +
      '<th>Notes</th></tr>' + schemeRows + '</table>' +

      '<h2>What went back</h2>' +
      kit.note('The status class, the exact status of every answer, and ' +
      'the <code>scimType</code> of every refusal (RFC 7644 section 3.12). ' +
      '<code>(none)</code> is a refusal that carried no such code — a ' +
      '<code>404</code> has none — and is counted rather than dropped, so ' +
      'the two failure tables agree with each other.') +
      '<div class="tiles" style="align-items:flex-start">' +
      '<div><table><tr><th>Class</th><th class="num">Count</th></tr>' +
      statusClassRows + '</table></div>' +
      '<div><table><tr><th>Status</th><th class="num">Count</th></tr>' +
      statusRows + '</table></div>' +
      '<div><table><tr><th>scimType</th><th class="num">Count</th></tr>' +
      scimTypeRows + '</table></div></div>' +

      '<h2>Volume</h2>' +
      '<div class="tiles">' +
      kit.tile(c.bytesOut, 'bytes returned') +
      kit.tile(c.latency.maxMs, 'slowest call (ms)') +
      kit.tile(c.latency.totalMs, 'total time (ms)') +
      '</div>' +
      // THE TWO INSTANTS ARE A SENTENCE AND NOT TWO MORE TILES. A tile draws
      // its value in the headline face, and a timestamp there is twenty-four
      // characters set like a three-digit count — it reads as the most
      // important figure on the page and is the least. Every other tile in
      // this console holds a number for the same reason.
      kit.note('First call <code>' + kit.esc(kit.whenText(c.firstAt)) +
                '</code>, last ' +
      'call <code>' + kit.esc(kit.whenText(c.lastAt)) + '</code>. ' +
      '<code>Bytes returned</code> is the SCIM payload this service ' +
      'wrote, headers excluded. It answers one question and it is a common ' +
      'one: whether a client is listing the whole directory on every poll. ' +
      'The time figures are a SUM and a maximum rather than a running ' +
      'mean, so any other statistic can still be computed from them.') +

      '<h2>The last ' + c.recentCap + ' calls</h2>' +
      kit.note('Newest first. Everything else on this page is an ' +
      'aggregate, and an aggregate cannot answer &ldquo;what did the call ' +
      'that just failed actually look like&rdquo; — which is the first ' +
      'thing anybody asks. It is a ring ' +
      'of ' + c.recentCap + ', so anything older has been dropped; the ' +
      'durable record is the <a href="/admin/audit">audit log</a>. Where ' +
      'no principal authenticated, the scheme is shown instead.') +
      '<table><tr><th>When</th><th>Operation</th><th>Resource</th><th>' +
      'Status</th><th>Who</th><th class="num">ms</th><th ' +
      'class="num">Bytes</th></tr>' +
      recentRows + '</table>' +

      (json.store
        ? '<h2>What it wrote</h2>' +
          // The opening sentence carries no HTML entity, deliberately: the
          // console derives an h2 tooltip from it through plainTextOf() and
          // esc(), which leaves an entity showing as its own source text.
          // Every other note here happens to be cut before its first one;
          // this was the first that was not, and rewording it was cheaper
          // than teaching the tooltip pass to decode.
          kit.note('The directory as it is NOW, which is the other half ' +
          'of the question and is not a counter: a page reporting four ' +
          'hundred successful creates beside a directory holding three ' +
          'people is reporting something worth knowing. There is no second ' +
          'store — a SCIM <code>POST</code> and an <code>ldapadd</code> ' +
          'write the same entry — so these are the same figures <a ' +
          'href="/admin/users">Users</a> and <a ' +
          'href="/admin/groups">Groups</a> are drawn from.') +
          '<div class="tiles">' +
          kit.tile(json.store.userCount, 'people in the directory') +
          kit.tile(json.store.groupCount, 'groups') +
          kit.tile(json.store.entryCount + ' / ' + json.store.maxEntries,
                    'entries / max') +
          '</div>'
        : '') +

      kit.note('<strong>There is no reset button, and it was refused ' +
      'rather than forgotten.</strong> A console that could zero its own ' +
      'monitoring would make every number on this page a number somebody ' +
      'might have zeroed — and the <a href="/admin/audit">audit log</a>, ' +
      'which is the durable record, cannot be reset either. Restarting the ' +
      'process is the only way these go back to zero, which is why the ' +
      'epoch is printed above.') +

      kit.note('<a href="/admin/scim">the surface these calls arrive ' +
      'at</a> &middot; <a href="/admin/scim/monitor?format=json">this page ' +
      'as JSON</a> &middot; <a href="/admin-api/scim/monitor">the same ' +
      'over the management API</a> &middot; <a href="/admin/audit">the ' +
      'durable record</a> &middot; <a href="/admin/metrics">every endpoint ' +
      'call, by route</a>');

    return inner;
  }

  // One row of the by-scheme table. Not folded into the page body because the
  // same rows are wanted in two orders — the schemes the surface declares, then
  // anything counted under a name it does not declare — and a second copy of
  // the markup is how the two come to be formatted differently.
  /**
   * Draws one row of the SCIM by-scheme table.
   *
   * @param id - the scheme's id
   * @param name - optional; the scheme's name
   * @param enabled - true, false, or null when the state does not apply
   * @param count - the number of requests counted under it
   * @param note - optional; a note for the last cell, as HTML
   * @returns the table row as HTML
   */
  static scimSchemeRow(id, name, enabled, count, note) {
    return '<tr><td><code>' + kit.esc(id) + '</code>' +
      (name ? ' ' + kit.esc(name) : '') + '</td>' +
      '<td>' + (enabled === null ? '<span class="sub">—</span>'
        : (enabled ? '<span class="state-valid">on</span>'
                   : '<span class="state-none">off</span>')) + '</td>' +
      '<td class="num">' + count + '</td>' +
      '<td class="sub">' + (note || '') + '</td></tr>';
  }
}

export = ScimPage;
