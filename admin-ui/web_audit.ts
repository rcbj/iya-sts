// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_audit.ts
//
// ---------------------------------------------------------------------------
// AUDIT → AUDIT LOG, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws the Audit log from the answer of `GET /admin-api/audit`: what was
// done, by whom, from where and with what outcome, filtered and paged, and the
// settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/audit` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws the Audit log from the answer of `GET /admin-api/audit`: what was
 * done, by whom, from where and with what outcome, filtered and paged, and the
 * settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class AuditPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const paging = json.paging;
    const summary = json;
    const known = json.knownActors;
    // What every paging link carries with it. The page number is not in here
    // — kit.pageNavPair() supplies that per link — for the reason the tokens
    // page
    // gives: a "next" that dropped the filter would be page 2 of a different
    // list.
    const filterParams = { category: (json.filter.category || ''),
                           action: (json.filter.action || ''),
                           outcome: (json.filter.outcome || ''),
                           actor: (json.filter.actor || ''),
                           q: (json.filter.q || ''),
                             code: (json.filter.code || ''),
                           address: (json.filter.address || ''),
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/audit', filterParams, paging);

    const rows = json.events.map(function (row) {
      return AuditPage.auditRow(row, known);
    }).join('');

    const categoryOptions = ['<option value=""' +
                             ((json.filter.category || '') ? '' : ' ' +
        'selected') +
                             '>any category</option>']
      .concat(json.categories.map(function (entry) {
        return '<option value="' + kit.esc(entry.category) + '"' +
               (entry.category === (json.filter.category || '')
                 ? ' selected' : '') +
               '>' +
               kit.esc(entry.label) + ' (' +
               (summary.byCategory[entry.category] || 0) + ')</option>';
      })).join('');

    // Grouped by category, and built from the SAME table the category select
    // is, so the two cannot come to disagree about which action belongs where
    // — which they would, being two hand-written lists of the same
    // twenty-four strings.
    const actionOptions = '<option value=""' +
      ((json.filter.action || '') ? '' : ' ' +
        'selected') +
      '>any action</option>' +
      json.categories.map(function (entry) {
        const inGroup = json.actions.filter(function (a) {
          return a.category === entry.category;
        });
        return '<optgroup label="' + kit.esc(entry.label) + '">' +
               inGroup.map(function (a) {
          return '<option value="' + kit.esc(a.action) + '"' +
                 (a.action === (json.filter.action || '') ? ' selected' : '') +
                   '>' +
                 kit.esc(a.action) + ' (' +
                 (summary.byAction[a.action] || 0) +
                 ')</option>';
        }).join('') + '</optgroup>';
      }).join('');

    const outcomeOptions = ['<option value=""' +
                            ((json.filter.outcome || '') ? '' : ' ' +
        'selected') +
                            '>any outcome</option>']
      .concat(json.outcomes.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === (json.filter.outcome || '') ? ' selected' : '') + '>' +
               kit.esc(name) +
               ' (' + (summary.byOutcome[name] || 0) + ')</option>';
      })).join('');

    const perOptions = kit.perPageOptions(paging.perPage);

    const f = json.filter;
    const filtering = f.category || f.action || f.outcome || f.actor ||
                      f.q || f.code || f.address || '';

    const inner = '<div class="tiles">' +
        kit.tile(summary.held, 'events held') +
        kit.tile(summary.recorded, 'events recorded') +
        kit.tile(summary.dropped, 'dropped (oldest first)') +
        kit.tile(summary.byCategory.directory || 0, 'directory') +
        kit.tile(summary.byCategory.authentication || 0, 'authentications') +
        kit.tile(summary.byCategory.session || 0, 'session events') +
      '</div>' +

      kit.note('What this service has been asked to do, in the order it ' +
      'was asked, newest first. The other pages here are <em>state</em> — ' +
      'how many calls, which tokens are still valid, who is in ' +
      '<code>cn=developers</code>. This one is <em>history</em>: the ' +
      'metrics page can say the directory holds eleven entries, and only ' +
      'this page can say that a twelfth was created at 14:02 and deleted ' +
      'at 14:03 by somebody bound as <code>uid=carol</code>, over LDAPS.') +

      kit.note('<strong>No credential is ever recorded here.</strong> Not ' +
      'a password, not a bearer token, not an assertion, and no request or ' +
      'response body. An event carries the facts of what happened — who, ' +
      'what, where, the outcome — and the identifiers that are already ' +
      'safe to show. A modify names the attributes it changed and never ' +
      'their values, because a modify is where a <code>userPassword</code> ' +
      'gets set; a compare says whether it matched and not what was tried; ' +
      'an <code>authorization code</code> in a query string is replaced ' +
      'with <code>(redacted)</code>. The debug log is where somebody who ' +
      'wants the bodies looks, and it is a log rather than a web page.') +

      kit.note('<strong>One act usually produces several rows, and they ' +
      'are not duplicates.</strong> Signing in at ' +
      '<code>/authn/login</code> writes three: the HTTP call ' +
      '(<code>protocol.call</code>), the credential being accepted ' +
      '(<code>authentication</code>) and the session that came out of it ' +
      '(<code>session.start</code>). Those are three facts at three ' +
      'layers, and which one answers your question depends on the question ' +
      '— a Kerberos AS-REQ authenticates somebody and starts no session at ' +
      'all, and an LDAP bind does both without an HTTP request anywhere in ' +
      'it. Collapsing them would mean choosing, once and for everybody, ' +
      'which of the three this page can answer.') +

      kit.note('<strong>This log observes itself.</strong> Drawing this ' +
      'page is console access, so fetching it records an ' +
      '<code>admin.view</code> event and the list is one row longer than ' +
      'it was when you asked. That is not a defect being left unfixed: ' +
      'suppressing it would put a blind spot exactly where the person ' +
      'reading the audit log stands. Filter by category to read past it.') +

      '<h2>What happened</h2>' +
      // No `page` input in this form, deliberately: changing a filter or the
      // page size returns to page 1. Carrying the old page number over would
      // land somebody on page 6 of a two-page result and the clamp in
      // pagingOf() would then move them again, which reads as the form
      // ignoring them.
      '<form method="get" action="/admin/audit"><div ' +
        'class="formrow"><label for="category">Category</label><select ' +
        'id="category" name="category">' +
          categoryOptions + '</select>' +
        '<label for="action">Action</label><select id="action" ' +
        'name="action">' +
          actionOptions + '</select>' +
        '<label for="outcome">Outcome</label><select id="outcome" ' +
        'name="outcome">' +
          outcomeOptions + '</select>' +
        '<label for="per">Per page</label><select id="per" name="per">' +
      perOptions +
          '</select>' +
      '</div><div class="formrow">' +
        '<label for="actor">Actor</label>' +
        '<input type="text" id="actor" name="actor" size="20" value="' +
          kit.esc((json.filter.actor || '')) + '" placeholder="alice">' +
        '<label for="q">Text</label>' +
        '<input type="text" id="q" name="q" size="30" value="' +
      kit.esc((json.filter.q || '')) +
          '" placeholder="a DN, a path, anything in the summary">' +
        '<label for="code">Error code</label>' +
        '<input type="text" id="code" name="code" size="16" value="' +
          kit.esc((json.filter.code || '')) + '" placeholder="STS-OAUTH">' +
        '<label for="address">From</label>' +
        '<input type="text" id="address" name="address" size="16" ' +
          'value="' + kit.esc((json.filter.address || '')) +
          '" placeholder="10.0.0.">' +
        '<button class="secondary">Filter</button>' +
        (filtering ? ' <a href="/admin/audit">clear</a>' : '') +
      '</div></form>' +
      kit.note('Category and Action narrow together, like any two ' +
      'filters, so an action from another category matches nothing — which ' +
      'is what an empty table below then means. Actor matches a substring ' +
      'of either spelling of the name, because the actor on a directory ' +
      'row is a bind DN and the one on a Kerberos row is ' +
      '<code>alice@REALM</code>; the collapse to a single key can only be ' +
      'done where an identity is normalised. Error code matches the front ' +
      'of a code, so <code>STS-OAUTH</code> is every OAuth failure and a ' +
      'whole code is one condition; every refused or failed request ' +
      'carries one, listed on the <em>Error codes</em> page of the ' +
      'documentation. A code is recorded here and in the service log and ' +
      'is never sent to the client; <a href="/admin/error-codes">Error ' +
      'codes</a> says what each one means.') +
      nav.head +
      '<table><tr><th class="num">#</th><th>When</th><th>Category</th><th>' +
      'Action</th><th>Outcome</th><th>Actor</th><th>From</th>' +
      '<th>Target</th><th>What happened</th><th>Detail</th></tr>' +
      (rows || '<tr><td colspan="10">Nothing matches.</td></tr>') +
      '</table>' +
      nav.foot +

      kit.note(json.matched + ' row(s) match' +
      (paging.pages > 1 ?
       ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                          ' are on this page (' + paging.page + ' of ' +
                          paging.pages + ')' : '') +
      '; ' + summary.held + ' held of ' + summary.recorded + ' recorded ' +
      'since this process started' +
      (summary.dropped
        ? ', and <strong>' + summary.dropped + ' dropped</strong> — the ' +
                                               'log holds at most ' +
          summary.maxEvents + ' events and discards the oldest first. ' +
          'Raise <code>audit.maxEvents</code> in the settings at the foot ' +
          'of this page if that is losing something you need.'
        : '. The cap is ' + summary.maxEvents + ' events and nothing has ' +
                                                'been dropped yet.')) +

      kit.note('The <strong>#</strong> column is a sequence number, ' +
      'unique across every process of this service and never reused — ' +
      'including across a drop and a restart — and rising within each ' +
      'process. That is what makes it a stable name for an event, where a ' +
      'row number would silently name a different event as soon as ' +
      'anything was discarded. It is NOT one order across processes: ' +
      'several worker threads or cluster nodes each number from blocks of ' +
      'their own. To read what is new, resume by time ' +
      '(<code>at</code>), with <code>seq</code> as the tie-break. ' +
      '<code>?format=json</code> carries <code>oldestSeq</code> and ' +
      '<code>newestSeq</code>, the numbers of the oldest and newest ' +
      'events held.') +

      '<h3>Where the rows come from</h3>' +
      kit.note('Six categories and five recording points, rather than a ' +
      'recording site per feature. Each of these is a funnel this service ' +
      'already had:') +
      '<ul>' + json.categories.map(function (entry) {
        // The label, the category and the count stay on the row and the
        // paragraph explaining the category folds under them, which is the
        // shape every legend on this console now has.
        return '<li><strong>' + kit.esc(entry.label) + '</strong> (<code>' +
               kit.esc(entry.category) +
               '</code>, ' + (summary.byCategory[entry.category] || 0) +
               ') ' +
               kit.note(kit.esc(entry.what)) + '</li>';
      }).join('') + '</ul>' +

      kit.note('<strong>Every row says where it came from</strong> ' +
      '(since 2026-09-18): <em>From</em> is the client\'s IP address for ' +
      'whatever the request, LDAP operation, Kerberos message or SPIRE ' +
      'Server API call caused — an authentication, a refused sign-in, a ' +
      'consent, a sign-out — and is empty for what this service did on its ' +
      'own. It is the address <code>global.trustProxy</code> and ' +
      '<code>global.trustedProxies</code> resolve: the right-most ' +
      '<code>X-Forwarded-For</code> hop that is not a proxy you named, or ' +
      'the client in a PROXY protocol header. <strong>With neither set ' +
      'behind a proxy, it is the proxy</strong> — on a laptop, the compose ' +
      'bridge — because that is the nearest hop that did not say who it ' +
      'forwarded for. The CHANNEL is still under the target: ' +
      '<code>http</code>, <code>ldap</code>, <code>ldaps</code>, ' +
      '<code>kerberos</code>, <code>grpc</code>, <code>tls</code>, ' +
      '<code>console</code> (an act on this console or ' +
      '<code>/admin-api</code>), <code>internal</code> (something this ' +
      'service did on its own), or <code>none</code> (a session that ' +
      'expired).') +

      kit.note('<strong>It is in memory and dies with the ' +
      'process</strong>, like the counters, the sessions and the signing ' +
      'key. There is no compliance story here to serve: this service ' +
      'checks no password anywhere, so an audit log of it is a debugging ' +
      'aid and not a record of anything. It also has no clear button, and ' +
      'that is a decision rather than an omission — an erase control on an ' +
      'unprotected console would make the page unable to answer the one ' +
      'question an audit log exists for. Restarting the service is how you ' +
      'get an empty one.') +

      // THE TWO SETTINGS ARE ON THIS PAGE NOW rather than being described
      // here and typed in somewhere else. `audit.protocolCalls` is the reason
      // this one matters: it is the noisy category, and somebody turning it
      // off is doing it BECAUSE they are looking at this page and cannot read
      // it.
      SettingsForms.forms(json.settings, '/admin/audit') +
      kit.note('<code>audit.protocolCalls</code> (now ' +
      (summary.protocolCalls ? 'on' : '<strong>off</strong>') + ') is the ' +
      'noisy one — every JWKS poll and metadata fetch is an event — so ' +
      'turning it off is how somebody watching the directory or the ' +
      'console gets a readable page. It never affects the other five ' +
      'categories, and <a href="/admin/metrics">the metrics page</a> ' +
      'counts every call either way. Both take effect immediately, and ' +
      'lowering <code>audit.maxEvents</code> ' +
      '(now ' + summary.maxEvents + ') discards ' +
      'the oldest rows at once rather than on the next event.') +

      kit.note('<strong>One request is deliberately never a row here: ' +
      '<code>GET /healthcheck</code> when it answered 200.</strong> It is ' +
      'asked every few seconds for the whole life of this service — by the ' +
      'compose healthcheck and by every launcher that waits for it to come ' +
      'up — and it always answers the same thing, so recorded it would be ' +
      'by a wide margin the most common row on this page and would push ' +
      'everything you came here to read off the end of the cap above. A ' +
      'probe that answered anything ELSE is recorded as usual, which is ' +
      'the half worth knowing: a failing healthcheck is exactly the event ' +
      'somebody hunting a start-up failure is looking for. <a ' +
      'href="/admin/metrics">The metrics page</a> counts every probe ' +
      'either way.') +

      kit.note('Paging is <code>?page=</code> and <code>?per=</code> (at ' +
        'most ' +
      kit.MAX_ROWS + ' rows a page) and both work with ' +
      '<code>?format=json</code>, whose reply carries <code>page</code>, ' +
      '<code>pages</code> and <code>matched</code> so a test can walk the ' +
      'whole list without guessing where it ends. The same list is at ' +
      '<code>GET /admin-api/audit</code> with the same parameters.');

    return inner;
  }

  /**
   * Draws one row of the audit log table.
   *
   * @param row - an audit row
   * @param known - the usernames this console has seen, as object keys
   * @returns a <tr> as HTML
   */
  static auditRow(row, known) {
    return '<tr>' +
      '<td class="num">' + kit.esc(row.seq) + '</td>' +
      '<td>' + kit.esc(kit.whenText(row.at)) + '</td>' +
      '<td>' + kit.esc(row.category) + '</td>' +
      '<td><code>' + kit.esc(row.action) + '</code></td>' +
      '<td>' + AuditPage.outcomeCell(row.outcome) +
        (row.errorCode ? '<br><a href="/admin/audit?code=' +
                         encodeURIComponent(row.errorCode) + '"><code>' +
                         kit.esc(row.errorCode) + '</code></a>' : '') +
                             '</td>' +
      '<td class="who">' + AuditPage.auditActorCell(row, known) + '</td>' +
      '<td class="who">' + AuditPage.auditAddressCell(row) + '</td>' +
      '<td class="who">' +
      (row.target ? '<code>' + kit.esc(row.target) + '</code>'
                                       : '<span class="state-none">—</span>') +
        (row.channel ? '<br><span class="state-none">' + kit.esc(row.channel) +
                       (row.protocol ? ' — ' + kit.esc(row.protocol) : '') +
                       '</span>' : '') +
      '</td>' +
      '<td>' + kit.esc(row.summary) + '</td>' +
      '<td class="who">' + AuditPage.auditDetailCell(row.detail) + '</td>' +
      '</tr>';
  }

  // Who did it. The console key links to their page where this service has seen
  // them authenticate, following the same three-state rule the groups page uses
  // — a name it knows, a name it could file somebody under but never has, and
  // no name at all. The PRESENTED form is shown underneath when it differs,
  // because the collapse from `uid=alice,ou=users,dc=example,dc=com` to `alice`
  // is a thing an auditor has to be able to see rather than take on trust.
  /**
   * Draws who did an audited act.
   *
   * The actor links to their user page when the console knows them, and
   * the presented form is shown underneath when it differs.
   *
   * @param row - an audit row
   * @param known - the usernames this console has seen, as object keys
   * @returns the cell's content as HTML
   */
  static auditActorCell(row, known) {
    if (!row.actor && !row.actorForm) {
      return '<span class="state-none" title="Nothing here names an actor. ' +
        'An unauthenticated protocol call and an anonymous LDAP bind both ' +
        'look like this, and both are ordinary on a service that ' +
        'authenticates nobody.">—</span>';
    }
    const parts = [];
    if (row.actor) {
      parts.push(known[row.actor]
        ? '<a href="' +
          kit.esc('/admin/users' + kit.queryWith({ user: row.actor }, {})) +
          '">' + kit.esc(row.actor) + '</a>'
        : '<span class="state-none" title="The console has no row for this ' +
          'name: nothing has authenticated as them in this process. A ' +
          'directory bind DN yields a name without there being anybody ' +
          'behind it.">' +
          kit.esc(row.actor) + ' <em>(never here)</em></span>');
    }
    if (row.actorForm && row.actorForm !== row.actor) {
      parts.push('<code>' + kit.esc(row.actorForm) + '</code>');
    }
    return parts.join('<br>');
  }

  // WHERE THE ACT CAME FROM (2026-09-18): the client's address, linked to
  // every row from it. A dash where nobody sent it — a timer, an expiry, a
  // background delivery, a seed at start-up — or where it came over a Unix
  // socket, which has no address; the tooltip says which that can be.
  /**
   * Draws an audit row's client address as a link to its other rows.
   *
   * @param row - an audit row
   * @returns the link as HTML, or a dash when no address was recorded
   */
  static auditAddressCell(row) {
    if (!row.address) {
      return '<span class="state-none" title="No client address: this was ' +
        'done by the service on its own (a timer, an expiry, a background ' +
        'delivery, start-up), arrived over a Unix socket, or was recorded ' +
        'before rows carried an address.">—</span>';
    }
    return '<a href="/admin/audit?address=' +
           encodeURIComponent(row.address) + '"><code>' +
           kit.esc(row.address) + '</code></a>';
  }

  // The detail object as one cell. Rendered as `key=value` pairs rather than as
  // JSON because the column is narrow and a reader is scanning for one fact,
  // not parsing a document; `?format=json` has the object itself for anything
  // that is not a person.
  /**
   * Draws an audit row's detail object as key=value pairs.
   *
   * @param detail - the row's detail object
   * @returns the pairs as HTML, or a dash when there are none
   */
  static auditDetailCell(detail) {
    const keys = Object.keys(detail || {});
    if (!keys.length) {
      return '<span class="state-none">—</span>';
    }
    return keys.map(function (key) {
      return '<code>' + kit.esc(key) + '=' + kit.esc(detail[key]) + '</code>';
    }).join(' ');
  }

  // The outcome, in the same three colours the token states use — so that a
  // page somebody has learned to skim once reads the same way here. `refused`
  // is amber rather than red on purpose: it is this service working correctly
  // and saying no, which is most of what a debugger of a protocol client wants
  // to see, and painting it as a failure would bury the 5xx rows that are one.
  /**
   * Draws an audit outcome in the state colours.
   *
   * @param outcome - `success`, `refused` or another outcome
   * @returns a <span> as HTML
   */
  static outcomeCell(outcome) {
    const cls = outcome === 'success' ? 'state-valid'
              : (outcome === 'refused' ? 'state-expired' : 'state-revoked');
    return '<span class="' + cls + '">' + kit.esc(outcome) + '</span>';
  }
}

export = AuditPage;
