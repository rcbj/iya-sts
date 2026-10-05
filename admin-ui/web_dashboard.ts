// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_dashboard.ts
//
// ---------------------------------------------------------------------------
// THE CONSOLE INDEX, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin` from the answer of `GET /admin-api/status`: the totals, every
// page this reader may see grouped as the sidebar is, what the console
// deliberately does not do, and where the JSON is.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws `/admin` from the answer of `GET /admin-api/status`: the totals, every
 * page this reader may see grouped as the sidebar is, what the console
 * deliberately does not do, and where the JSON is.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DashboardPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const inner = '<div class="tiles">' +
        kit.tile(json.calls, 'endpoint calls') +
        kit.tile(json.tokensHeld, 'tokens issued') +
        kit.tile(json.tokensRevoked, 'tokens revoked') +
        kit.tile(json.artifactsHeld, 'other artifacts') +
        kit.tile(json.usersKnown, 'users known') +
        kit.tile(json.signOnSessions, 'sign-on sessions') +
        kit.tile(kit.durationText(json.uptimeMs), 'uptime') +
      '</div>' +
      '<h2>What this console is</h2>' +
      kit.note('This service exists to exercise clients, and the pages ' +
      'here exist to exercise the parts of a client that only show ' +
      'themselves when something changes underneath it: what happens when ' +
      'a token it holds stops being valid, and what happens when a token ' +
      'it reads grows a claim it was not expecting.') +
      kit.note('Every page in the sidebar is below, in the sidebar\'s own ' +
      'order and grouping, because this list is DERIVED from the same ' +
      'table the sidebar is drawn from. A page cannot be added to this ' +
      'console and left out of here; one added without a description says ' +
      'so on its own row rather than going quietly.') +
      DashboardPage.consoleGuide('/admin', json.sections) +
      '<h2>What it deliberately does not do</h2>' +
      kit.note('Worth knowing before looking for a control that is not ' +
      'here. Most of these are things this console CANNOT do rather than ' +
      'things somebody has not got to yet, and each says which.') +
      '<ul>' +
      kit.bullet('<strong>It does not invalidate a SAML assertion, a ' +
      'Kerberos ticket or a credential.</strong> It counts them, it lists ' +
      'the first two on the tokens page beside the JWTs, and it says when ' +
      'each expires — but none of those has a revocation mechanism a ' +
      'relying party consults. A SAML assertion is valid because its ' +
      'signature verifies and its Conditions hold, and a Kerberos ticket ' +
      'because the service it names can decrypt it; nothing about this ' +
      'service is asked in either case. A button claiming to revoke one ' +
      'would change a number here and nothing at all out there, which is ' +
      'why those rows carry a dash and the reason for it. The same is true ' +
      'one family further out: <strong>an X509-SVID already handed to a ' +
      'workload keeps working until it expires</strong>, and banning a ' +
      'SPIFFE identity records who may still be ISSUED one, which is a ' +
      'different claim.') +
      kit.bullet('<strong>It DOES end a sign-on session now, and it used ' +
      'to say it did not.</strong> The old reason was a good one: ' +
      '<code>/oauth2/logout</code> and WS-Federation\'s ' +
      '<code>wsignout1.0</code> each had a fan-out written into it, so a ' +
      'third button here would have been a third copy that quietly ' +
      'notified nobody. What changed on 2026-08-24 is that those fan-outs ' +
      'became FUNCTIONS owned by the protocol module they belong to, and ' +
      'one function in <code>authn.js</code> is the only place a session ' +
      'actually stops existing. <a href="/admin/logout">/admin/logout</a> ' +
      'calls them; so does <a href="/logout">/logout</a>, which is the ' +
      'same act without a console role. What this console still cannot do ' +
      'is DELIVER the front-channel notifications — each is an iframe in ' +
      'the signed-out person\'s own browser, and this is not that ' +
      'browser. The back-channel Logout Tokens need no browser, and this ' +
      'service sends them whichever door ended the session.') +
      kit.bullet('<strong>It does not keep the tokens ' +
      'themselves</strong>, only their claims. A page listing a thousand ' +
      'live bearer credentials in a form a browser will render is a page ' +
      'that leaks them, and the <code>jti</code> is all any button here ' +
      'needs. One configured field is held back for the same reason and no ' +
      'stronger one: a federation relationship\'s ' +
      '<code>fedClientSecret</code> is this service\'s own credential AT a ' +
      'real foreign service, so it is never printed here and never reaches ' +
      'the audit log — an <code>ldapsearch</code> shows it anyway, and ' +
      'this console not being a second way to read it is not a security ' +
      'boundary.') +
      kit.bullet('<strong>NOTHING THIS SERVICE MINTS SURVIVES A RESTART, ' +
      'and a restart is not a reload.</strong> The counters, the token and ' +
      'artifact registries, the audit ring, the sessions, the ' +
      'authorization codes and the Kerberos tickets are all in memory, and ' +
      'the signing key is REGENERATED on every start — so a token issued ' +
      'by the previous process no longer verifies against the published ' +
      'JWKS. That is deliberate rather than a limitation, and it is what ' +
      'makes the rest of it impossible: a statistics file, or a stored ' +
      'token, that outlived the key it was signed under would be worse ' +
      'than none. ' +
      (json.persistence.enabled
        ? '<strong>THREE THINGS DO SURVIVE on this process</strong>, ' +
          'because <code>persistence.mode</code> is <code>' +
          kit.esc(json.persistence.mode) + '</code>: ' +
          'the embedded directory — which is also the applications ' +
          'registry, the federation register and the SPIFFE registry — the ' +
          'trust realm registry, and the settings changed on these pages. ' +
          'Those are the things somebody TYPED. See <a ' +
          'href="/admin/persistence">Persistence</a>.'
        : 'THREE THINGS CAN BE MADE TO SURVIVE and are not on this process ' +
          '— the embedded directory, the trust realms and the settings ' +
          'changed here. See <a href="/admin/persistence">Persistence</a>, ' +
          'which is off by default.')) +
      kit.bullet('<strong>It does not remember everything, ' +
      'either.</strong> The token, artifact and user registries and the ' +
      'audit ring are CAPPED and drop their oldest rows — and each says ' +
      'how many it dropped rather than pretending they were never there: ' +
      '<code>forgotten</code> on <a href="/admin/metrics">Metrics</a>, ' +
      '<code>dropped</code> on <a href="/admin/audit">the audit log</a>, ' +
      'and one collapsed row for the paths that matched no route. A count ' +
      'that grew without limit would be one a scanner inventing URLs could ' +
      'exhaust.') +
      kit.bullet('<strong>It checks no password — not even at its own ' +
      'door.</strong> The gate proves that somebody typed a name that ' +
      'holds one of two roles, and nothing verifies that it is them. The ' +
      'roles are ordinary directory groups, so an <code>ldapmodify</code> ' +
      'or a SCIM PATCH grants them too; while neither group has a member, ' +
      'anybody who signs in holds both; and ' +
      '<strong><code>/admin-api</code> is deliberately NOT gated</strong>, ' +
      'which is what a test drives and the way back in when nobody holds a ' +
      'role — and also means anybody who can reach this port can grant ' +
      'themselves both. The gate exists so a client can be driven through ' +
      '302, 401, 403 and a role model. It does not make this port safe to ' +
      'expose.') +
      kit.bullet('<strong>It enforces nothing by default, and widening is ' +
      'what most of these pages do.</strong> RFC 9700 mode is the one MODE ' +
      'that makes this service refuse what it would otherwise accept, and ' +
      'it is off unless <a href="/admin/oauth2">the OAuth 2.0 / OIDC ' +
      'settings</a> turn it on. Three surfaces ask for a credential ' +
      'without it — <a href="/admin/scim">SCIM</a>, the SPIRE Server API ' +
      'and this console — and all three are a turnstile rather than a ' +
      'lock: each can be switched off, and none of them checks a password. ' +
      '<a href="/admin/federation">Federation</a> is the one refusal that ' +
      'is not a mode and cannot be switched off, because at an assertion ' +
      'consumer service there is no permissive answer available.') +
      kit.bullet('<strong>It does not decide who may delegate to ' +
      'whom.</strong> <a href="/admin/delegation">Delegation</a> reports ' +
      'eight mechanisms and polices none of them: Kerberos is the only ' +
      'family here that polices delegation at all, and that policy belongs ' +
      'to the principal database rather than to this console. WS-Trust\'s ' +
      '<code>OnBehalfOf</code> and RFC 8693\'s token exchange are ' +
      'unpoliced, and the rows say so rather than being tidied into an em ' +
      'dash.') +
      kit.bullet('<strong>It does not attest a workload or a ' +
      'node</strong>, and no setting on <a href="/admin/spiffe">SPIFFE</a> ' +
      'turns that on. The Workload API authenticates nobody because its ' +
      'specification says it MUST NOT — a workload has no root of trust ' +
      'until that call gives it one — so what is missing there is ' +
      'attestation rather than authentication.') +
      kit.bullet('<strong>It deletes CONFIGURATION and never a ' +
      'person.</strong> An authorization server, a SPIFFE registration ' +
      'entry, an attested agent\'s record and a federation relationship ' +
      'can all be removed here. A PERSON cannot be: somebody can be ' +
      'created on <a href="/admin/users">Users</a> ahead of their first ' +
      'sign-in and a SPIFFE identity can be banned so that no further SVID ' +
      'is issued to it, but no control in this console deletes an entry ' +
      'under <code>ou=users</code>. One name is ONE entry however that ' +
      'name authenticated, which is the property most of these pages are ' +
      'reading. <a href="/admin/scim">SCIM</a> is the exception and it is ' +
      'a whole protocol rather than a button — a <code>DELETE ' +
      '/scim/v2/Users/{id}</code> really does remove the entry, while its ' +
      '<code>active: false</code> DISABLES the account (2026-09-17), ' +
        'which is ' +
      'the same act as Disable on a person\'s page.') +
      kit.bullet('<strong>It shows ONE trust realm at a time, and it ' +
      'writes the one it is read in.</strong> Every page here reports the ' +
      'realm in the path it was reached by, and the switcher above the nav ' +
      'is how you leave it — so a setting saved on any of these pages ' +
      'changes that realm and no other. A realm has administrators of its ' +
      'own since 2026-09-14: the two role groups in its own directory, ' +
      'confined to that realm, while the default realm\'s two groups ' +
      'remain the service administrators over every realm. A realm ' +
      'administrator does not see the pages about the whole process, and ' +
      'is refused them if they ask.') +
      kit.bullet('<strong>It runs no script, and that costs one thing ' +
      'worth naming.</strong> <code>script-src \'none\'</code> holds over ' +
      'every page in this console, which is what makes a family of ' +
      'reflected-content problems moot here rather than merely unlikely. ' +
      '<a href="/admin/delegation/map">The delegation picture</a> is ' +
      'therefore laid out on the SERVER and arrives as ordinary markup, so ' +
      'it does not pan or zoom — <code>?format=svg</code> hands over the ' +
      'document for something that does.') +
      '</ul>' +
      '<h2>Reading it from a test</h2>' +
      kit.note('Every page above answers <code>?format=json</code>, and ' +
      'so does every drill-down under one — the same object, the same 200, ' +
      'the same <code>Cache-Control: no-store</code>. A caller that asks ' +
      'for JSON is never redirected to a sign-in screen either: it gets ' +
      '401 or 403 with a body, because a 302 to an HTML login page arrives ' +
      'at a program as a 200 full of markup. Every form takes a JSON body, ' +
      'and the same service is at <a href="/admin-api">/admin-api</a>, ' +
      'which is not gated at all.') +
      '<ul><li><code>GET ' + kit.esc(json.base) +
      '/admin/metrics?format=json</code></li>' +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
                  '/admin/groups?format=json</code>, and ' +
      '<code>GET ' + kit.esc(json.base) +
      '/admin/groups?group=cn=developers,ou=groups,...&amp;format=json' +
      '</code> ' +
      '— the second carries every attribute of that group and every member ' +
      'resolved.') +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
                  '/admin/users?format=json</code>, and ' +
      '<code>GET ' + kit.esc(json.base) +
      '/admin/users?user=alice&amp;format=json</code> — the second carries ' +
      '<code>sessions</code>, each with the tokens issued on it, plus the ' +
      'tokens that belong to no session and the artifacts') +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/tokens?format=json&amp;page=1&amp;per=100</code> ' +
      '— the reply carries <code>page</code>, <code>pages</code> and ' +
      '<code>matched</code>, so walking the whole list needs no guess ' +
      'about where it ends. Every paged list here answers the same three ' +
      'fields, so one walker serves all of them.') +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/sts-metadata?format=json</code> ' +
      '— every endpoint this process registered, which is the list to ' +
      'check a client\'s assumptions against rather than this page.') +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/delegation/map?format=json</code> ' +
      'for the graph, and <code>?format=svg</code> for the drawing alone — ' +
      'the one page here with a fourth shape.') +
      '<li><code>POST ' + kit.esc(json.base) + '/admin/tokens</code> with ' +
      '<code>{"action":"revoke","target":"&lt;jti or ' +
      'token&gt;"}</code></li><li><code>POST ' + kit.esc(json.base) +
      '/admin/claims</code> with <code>' +
      '{"action":"replace","set":"id_token","claims":[{"name":"dept",' +
      '"value":"engineering"}]}</code></li></ul>';
    return inner;
  }

  /**
   * Draws the overview's list of every page, grouped as the sidebar is.
   *
   * The page being drawn on is left out, and so is a section left empty.
   *
   * @param activePath - the path of the page the list is drawn on
   * @param sections - the sections this reader may see
   *   (`visibleSections()`'s answer, carried as the dashboard's `sections`)
   * @returns the guide as HTML
   */
  static consoleGuide(activePath, sections) {
    const out = [];
    sections.forEach(function (section) {
      const items = [];
      // One list of rows, a group drawn as its heading over its own rows —
      // which may hold a group again (Cert issuance › SPIFFE) — and dropped
      // when the page being drawn was all it held.
      const rows = function (list, out) {
        list.forEach(function (item) {
          if (DashboardPage.isNavGroup(item)) {
            const inner = [];
            rows(item.items, inner);
            if (!inner.length) {
              return;
            }
            // The group's own description folds like a page's, for the same
            // reason: SAML's runs to five lines and sat between the heading
            // and the three pages under it.
            out.push('<li><span class="grp">' + kit.esc(item.title) +
                     '</span>' +
                     kit.note(kit.esc(item.what)) +
                     '<ul>' + inner.join('') + '</ul></li>');
            return;
          }
          if (item.path === activePath) {
            return;
          }
          out.push(DashboardPage.guideItem(item));
        });
      };
      rows(section.items, items);
      if (!items.length) {
        return;
      }
      out.push('<h3>' + kit.esc(section.title) + '</h3>' +
               kit.note(kit.esc(section.what)) +
               '<ul>' + items.join('') + '</ul>');
    });
    return '<div class="guide">' + out.join('') + '</div>';
  }

  // ---------------------------------------------------------------------------
  // THE OVERVIEW PAGE'S OWN LIST OF WHAT IS HERE, DERIVED FROM `SECTIONS`.
  //
  // It was a hand-written `<ul>` in the route below until 2026-08-25, and it
  // had drifted to describing SEVEN of twenty-five pages — so the one page
  // whose whole job is to point at the others was the least complete
  // description of this console in the repository. Nothing could have shown
  // that: a list of links is correct-looking whatever it omits, which is
  // exactly the shape of problem `/admin/sts-metadata` exists to make
  // impossible for endpoints.
  //
  // So it is built from the same table the sidebar is built from, and three
  // rules follow from that rather than from taste:
  //
  //   * **A page with no `blurb` is DRAWN, marked as undescribed.** The
  //     tempting alternative — skip it — is the bug over again with a mechanism
  //     behind it, since a page added to `SECTIONS` and not described here
  //     would silently vanish from the front door exactly as nineteen of them
  //     had.
  //   * **The page being drawn ON is dropped**, which is `/admin` and only ever
  //     `/admin`. `trailBar()`'s last-crumb rule is the same one: a link that
  //     reloads the page you are standing on teaches a reader not to trust the
  //     ones beside it. A section left empty by that drop is dropped with it,
  //     rather than leaving a heading over nothing.
  //   * **The GROUPS are kept**, unlike `sectionPages()`, which flattens them.
  //     The sidebar's grouping is a fact about the sidebar — but this list is
  //     the sidebar EXPLAINED, and a reader looking for `Registration entries`
  //     needs the same "these three are SPIFFE" that made the group worth
  //     having.
  //
  // The blurbs are prose in `SECTIONS` beside each page's `path` and `label`.
  // This function knows nothing about any particular page, which is what stops
  // it becoming a second place a page has to be described.
  /**
   * Draws one page's entry in the overview's list of pages.
   *
   * A page with no blurb in SECTIONS is drawn and marked as undescribed.
   *
   * @param page - a page row from SECTIONS
   * @returns an <li> as HTML
   */
  static guideItem(page) {
    if (!page.blurb) {
      // NOT an omission and not a throw. A console that will not start is worse
      // than one line that says what is missing — the same call `admin_rbac.js`
      // makes about a slot nobody filled — and this is the only report anything
      // makes about a page nobody described.
      return kit.bullet('<a href="' + kit.esc(page.path) + '">' +
                         kit.esc(page.label) +
             '</a> — <span class="undescribed">this page has no description ' +
             'in <code>SECTIONS</code>. It was added to the nav and not ' +
             'described here; the list you are reading is derived from that ' +
             'table, so this row is the report rather than a gap.</span>');
    }
    // THE LINK STAYS ON THE ROW AND THE BLURB FOLDS UNDER IT. Every blurb in
    // SECTIONS runs to between three and six lines — they are the description
    // of a page rather than a caption for it — so this list, which is the one
    // page in this console whose whole job is pointing at the others, was
    // twenty-six paragraphs deep and the twenty-six links were scattered
    // through it. It is an index again: the labels are a column somebody can
    // run an eye down, and the paragraph is under whichever one they stopped
    // at.
    //
    // The link is deliberately NOT inside the summary. kit.bullet() refuses to
    // fold an item that opens with one for the reason given there — a link
    // inside a <summary> is a control inside a control — and this row would
    // have been the first place that bit.
    return '<li><a href="' + kit.esc(page.path) + '">' + kit.esc(page.label) +
           '</a>' +
           kit.note(page.blurb) + '</li>';
  }

  // Is this row of a section's `items` a GROUP of pages rather than a page? One
  // predicate, used by both the flattening and the sidebar, so the two cannot
  // disagree about what they are looking at. A group has `items`; a page has a
  // `path` and never has `items`.
  /**
   * Tells whether a row of a section's items is a group of pages.
   *
   * @param item - a row of a section's `items`
   * @returns true when the row has an `items` array
   */
  static isNavGroup(item) {
    return item != null && Array.isArray(item.items);
  }
}

export = DashboardPage;
