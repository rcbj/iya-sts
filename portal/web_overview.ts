// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_overview.ts
//
// ---------------------------------------------------------------------------
// THE PORTAL'S *YOUR ACCOUNT* PAGES, DRAWN IN THE BROWSER (#568): the
// Overview (`/portal`), Applications (`/portal/applications`) and Security
// activity (`/portal/signals`), from the views `account_overview.ts`
// answers. The markup is what `portal.ts` drew on the server, moved; the
// reasoning about what each page shows is beside the view that builds it.
//
// **`<details>` IS MARKUP AND NOT SCRIPT**: the directory's empty attributes
// and a security event's detail fold without anything running.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const BASE = kit.BASE;
const esc = kit.esc;

/**
 * The *Your account* pages. A static utility class.
 */
class OverviewPages {
  /**
   * An instant as the server-rendered pages printed it.
   *
   * @param ms - milliseconds since the epoch
   * @returns the ISO text
   */
  static iso(ms: number): string {
    return new Date(Number(ms) || 0).toISOString();
  }

  /**
   * The paging control under a list.
   *
   * @param path - the page's path
   * @param at - the page shown
   * @param pages - how many there are
   * @param t - the translator
   * @returns the HTML, '' for one page
   */
  static paging(path: string, at: number, pages: number, t: Json): string {
    if (pages <= 1) {
      return '';
    }
    return '<p class="pagenav">' +
      (at > 1
        ? '<a href="' + esc(path + '?page=' + (at - 1)) + '">' +
          t.html('portal.paging.previous') + '</a>'
        : '<span class="off">' + t.html('portal.paging.previous') +
          '</span>') +
      '<span class="here">' + t.html('portal.paging.page',
        { at: at, pages: pages }) + '</span>' +
      (at < pages
        ? '<a href="' + esc(path + '?page=' + (at + 1)) + '">' +
          t.html('portal.paging.next') + '</a>'
        : '<span class="off">' + t.html('portal.paging.next') + '</span>') +
      '</p>';
  }

  // ---------------------------------------------------------------------------
  // EVERY STANDARD inetOrgPerson ATTRIBUTE, from the fixed list the view was
  // built from. The three object classes are the headings; the ones with
  // values are drawn plainly and the rest one fold per class. With no entry,
  // the sign-in's two facts and a sentence saying why nothing more is shown.
  // ---------------------------------------------------------------------------
  /**
   * The directory block.
   *
   * @param view - the Overview's view
   * @param t - the translator
   * @returns the HTML
   */
  static directoryBlock(view: Json, t: Json): string {
    const described = view.directory;
    if (!described) {
      const session = view.session || {};
      const fallback = [
        session.email ? [t.text('portal.directory.email'), session.email]
                      : null,
        session.name ? [t.text('portal.directory.name'), session.name] : null
      ].filter(Boolean);
      return (fallback.length
        ? '<table>' + fallback.map(function (pair: string[]): string {
            return '<tr><th>' + esc(pair[0]) + '</th><td>' + esc(pair[1]) +
              '<div class="attr">' + t.html('portal.directory.fromSession') +
              '</div></td></tr>';
          }).join('') + '</table>'
        : '') +
        '<p class="note">' + t.html('portal.directory.notShowing') + '</p>';
    }
    const row = function (one: Json): string {
      let value;
      if (one.secret) {
        value = '<span class="set">' + t.html('portal.directory.set') +
                '</span> <span class="sub">' +
                t.html('portal.directory.secret') + '</span>';
      } else if (one.binary) {
        value = '<span class="set">' + t.html('portal.directory.set') +
                '</span> <span class="sub">' +
                (one.count > 1
                  ? t.html('portal.directory.binaryMany',
                           { bytes: one.bytes, count: one.count })
                  : t.html('portal.directory.binary', { bytes: one.bytes })) +
                '</span>';
      } else if (one.count > 1) {
        // MULTI-VALUED IS THE ORDINARY CASE IN LDAP: a list, never a comma.
        value = '<ul class="vals">' + one.values.map(function (v: string) {
          return '<li>' + esc(v) + '</li>';
        }).join('') + '</ul>';
      } else {
        value = esc((one.values || [])[0] || '');
      }
      return '<tr><th title="' + esc(one.ldap + ' — ' + one.rfc +
               (one.note ? '. ' + String(one.note).replace(/\*\*/g, '')
                         : '')) + '">' + esc(one.label) +
             (one.must ? ' <span class="must" title="' +
               esc(t.text('portal.directory.requiredTitle')) + '">' +
               t.html('portal.directory.required') + '</span>' : '') +
             '</th><td>' + value + '<div class="attr"><code>' +
             esc(one.ldap) + '</code> &middot; ' + esc(one.rfc) +
             '</div></td></tr>';
    };
    const sections = (described.classes || []).map(function (klass: Json) {
      const set = klass.rows.filter(function (one: Json): boolean {
        return one.present;
      });
      const unset = klass.rows.filter(function (one: Json): boolean {
        return !one.present;
      });
      return '<h3 class="dirclass" title="' +
             esc(klass.name + ' — ' + klass.rfc + ', OID ' + klass.oid +
                 '. ' + klass.what) + '"><code>' + esc(klass.name) +
             '</code> <span class="sub">' +
             t.html('portal.directory.classHeld',
                    { held: klass.held, total: klass.total }) +
             '</span></h3>' +
             (set.length
               ? '<table>' + set.map(row).join('') + '</table>'
               : '<p class="note">' +
                 t.html('portal.directory.nothingFromClass') + '</p>') +
             (unset.length
               ? '<details><summary>' +
                 t.html('portal.directory.others', { n: unset.length }) +
                 '</summary><table>' + unset.map(function (one: Json) {
                   return '<tr><th title="' + esc(one.ldap + ' — ' + one.rfc) +
                     '">' + esc(one.label) +
                     (one.must ? ' <span class="must">' +
                       t.html('portal.directory.required') + '</span>' : '') +
                     '</th><td><span class="unset">' +
                     t.html('portal.directory.notSet') + '</span>' +
                     '<div class="attr"><code>' + esc(one.ldap) +
                     '</code> &middot; ' + esc(one.rfc) + '</div></td></tr>';
                 }).join('') + '</table></details>'
               : '');
    }).join('');
    return '<h3 class="dirhead">' + t.html('portal.directory.heading') +
      '</h3><p class="note">' + t.html('portal.directory.every',
        { held: described.held, total: described.total }) +
      ' <code>' + esc('objectClass: top, person, organizationalPerson, ' +
                      'inetOrgPerson') + '</code></p>' + sections +
      '<p class="note">' + t.html('portal.directory.notEditable') + '</p>';
  }

  // THE LANGUAGE ON THE PERSON'S OWN ACCOUNT (#539): a real form and a real
  // select, posting to `/portal/language`; "Use my browser's language"
  // removes the attribute, which the header's chooser cannot do.
  /**
   * The language card.
   *
   * @param language - `{ held, offered }`
   * @param t - the translator
   * @returns the HTML
   */
  static languageCard(language: Json, t: Json): string {
    const held = String((language && language.held) || '');
    const offered: Json[] = (language && language.offered) || [];
    const mine = held.toLowerCase();
    const named = offered.filter(function (one: Json): boolean {
      return String(one.tag).toLowerCase() === mine;
    })[0];
    const options = '<option value=""' + (named ? '' : ' selected') + '>' +
      t.html('portal.language.browser') + '</option>' +
      offered.map(function (one: Json): string {
        return '<option value="' + esc(one.tag) + '" lang="' + esc(one.tag) +
          '"' + (one === named ? ' selected' : '') + '>' + esc(one.name) +
          '</option>';
      }).join('');
    return '<div class="card" id="language"><h2>' +
      t.html('portal.language.heading') + '</h2><p class="sub">' +
      (held ? t.html('portal.language.current',
                     { name: named ? named.name : held })
            : t.html('portal.language.none')) + '</p>' +
      '<form method="post" action="' + BASE + '/language">' +
      '<label for="portal-language">' + t.html('portal.language.label') +
      '</label><select id="portal-language" name="lang">' + options +
      '</select><button type="submit">' + t.html('portal.language.save') +
      '</button></form><p class="note">' + t.html('portal.language.note') +
      '</p></div>';
  }

  /**
   * The Overview's body.
   *
   * @param view - `GET /account-api/overview`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static overview(view: Json, ctx: Json): string {
    const t = ctx.t;
    const m = view.mechanisms || {};
    const signOn = view.signOn || {};
    const backup = m.backupCodes || {};
    // WHICH FACTOR, AND NOT MERELY WHETHER: "required" on its own leaves
    // somebody unable to guess what they will be asked for.
    const secondFactor = !m.mfaRequired
      ? t.html('portal.overview.notRequired')
      : (m.secondFactor === 'webauthn'
        ? (m.totp ? t.html('portal.overview.requiredPasskeyOrCode')
                  : t.html('portal.overview.requiredPasskey'))
        : t.html('portal.overview.requiredCode'));
    return '<div class="card"><h2>' + t.html('portal.overview.you') +
      '</h2><p class="sub">' + t.html('portal.overview.youSub') +
      '</p><table><tr><th>' + t.html('portal.overview.username') +
      '</th><td>' + esc(view.username) + '</td></tr><tr><th>' +
      t.html('portal.overview.subject') + '</th><td><code>' +
      esc(view.sub || '') + '</code></td></tr>' +
      (view.entry
        ? '<tr><th>' + t.html('portal.overview.directoryEntry') +
          '</th><td><code>' + esc(view.entry.dn) + '</code></td></tr>'
        : '') +
      '<tr><th>' + t.html('portal.overview.signedIn') + '</th><td>' +
      esc(OverviewPages.iso(signOn.startedAt)) + '</td></tr>' +
      (signOn.authentications > 1
        ? '<tr><th>' + t.html('portal.overview.lastAuthenticated') +
          '</th><td>' + esc(OverviewPages.iso(signOn.authTime)) + ' ' +
          t.html('portal.overview.authentications',
                 { n: signOn.authentications }) + '</td></tr>'
        : '') +
      '<tr><th>' + t.html('portal.overview.how') + '</th><td>' +
      ((signOn.amr || []).length ? esc(signOn.amr.join(', '))
                                 : t.html('portal.overview.unstated')) +
      ' (acr ' + esc(signOn.acr) + ')</td></tr>' +
      // Whether the sign-on session is bound to this browser's key (#725).
      '<tr><th>' + t.html('portal.overview.deviceBound') + '</th><td>' +
      (signOn.deviceBound && signOn.deviceBound.bound
        ? t.html('portal.overview.deviceBoundYes',
                 { alg: signOn.deviceBound.alg || '' })
        : t.html('portal.overview.deviceBoundNo')) + '</td></tr><tr><th>' +
      t.html('portal.overview.sessionEnds') + '</th><td>' +
      esc(OverviewPages.iso(view.sessionEnds)) + '</td></tr>' +
      (view.timesSignedIn !== null && view.timesSignedIn !== undefined
        ? '<tr><th>' + t.html('portal.overview.timesSignedIn') +
          '</th><td>' + esc(String(view.timesSignedIn)) + '</td></tr>'
        : '') +
      '</table>' + OverviewPages.directoryBlock(view, t) + '</div>' +

      '<div class="card"><h2>' + t.html('portal.overview.howHeading') +
      '</h2><table><tr><th>' + t.html('portal.overview.password') +
      '</th><td>' +
      (m.password ? t.html('portal.overview.set')
                  : '<em>' + t.html('portal.overview.noneSet') + '</em>') +
      ' — <a href="' + esc(BASE + '/password') + '">' +
      t.html('portal.overview.changeIt') + '</a></td></tr><tr><th>' +
      t.html('portal.overview.passkeys') + '</th><td>' +
      (m.keys ? t.html('portal.overview.registered', { n: m.keys })
              : '<em>' + t.html('portal.overview.noneYet') + '</em>') +
      ' — <a href="' + esc(BASE + '/keys') + '">' +
      t.html('portal.overview.seeThem') + '</a></td></tr><tr><th>' +
      t.html('portal.overview.authenticatorApp') + '</th><td>' +
      (m.totp
        ? (m.totpUsable ? t.html('portal.overview.enrolled')
                        : t.html('portal.overview.unreadable'))
        : '<em>' + t.html('portal.overview.notSetUp') + '</em>') +
      ' — <a href="' + esc(BASE + '/mfa') + '">' +
      t.html('portal.overview.setItUp') + '</a></td></tr>' +
      // THE WAY BACK, as a COUNT: a set is never topped up, so *3 of 10
      // left* is an instruction and *issued* is not.
      '<tr><th>' + t.html('portal.overview.recoveryCodes') + '</th><td>' +
      (backup.present
        ? (backup.usable
            ? t.html('portal.overview.unused',
                     { remaining: backup.remaining, total: backup.total })
            : t.html('portal.overview.issuedUnreadable'))
        : '<em>' + t.html('portal.overview.noneIssued') + '</em>') +
      ' — <a href="' + esc(BASE + '/mfa') + '">' +
      t.html('portal.overview.seeThem') + '</a></td></tr><tr><th>' +
      t.html('portal.overview.secondFactor') + '</th><td>' + secondFactor +
      '</td></tr></table></div>' +

      OverviewPages.languageCard(view.language, t) +

      // THE WIDER SIGN-OUT, `/logout`: every session and credential this
      // identity holds in every protocol. Not a portal form, so the runtime
      // leaves it to the browser, which carries the sign-on cookie. A GET
      // since #577: the sign-out page is a static surface whose act is
      // bound to that cookie by a CSRF token no other page holds, so this
      // button opens it, and its Global logout — first on the page — is
      // the press that ends everything.
      '<div class="card"><h2>' + t.html('portal.overview.signOutAll') +
      '</h2><form method="get" action="/logout">' +
      '<button class="secondary">' + t.html('portal.overview.signOutAll') +
      '</button></form><p class="note">' +
      t.html('portal.overview.signOutAllNote') + '</p></div>';
  }

  // THE APPLICATION'S NAME, AS A LINK TO ITS DECLARED HOME PAGE OR AS A
  // GREYED-OUT LABEL — never a guess from a redirect URI. It is still not a
  // launch button; the one launch is OpenID Connect Core section 4's.
  /**
   * An application's name.
   *
   * @param row - the row
   * @param t - the translator
   * @returns the HTML
   */
  static linkedName(row: Json, t: Json): string {
    if (!row.homePage) {
      return '<span class="unlinked" title="' +
        esc(t.text('portal.apps.unlinkedTitle')) + '">' + esc(row.name) +
        '</span>';
    }
    return '<a class="home" rel="noopener" href="' + esc(row.homePage) +
      '">' + esc(row.name) + '</a>';
  }

  /**
   * The Applications page's body.
   *
   * @param view - `GET /account-api/applications`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static applications(view: Json, ctx: Json): string {
    const t = ctx.t;
    // WHAT A ROW WOULD BE ISSUED, in the reader's language (#539); one the
    // table gains and this does not name is drawn as written.
    const ways: Json = {
      'an ID Token': t.text('portal.apps.wayIdToken'),
      'an access token': t.text('portal.apps.wayAccessToken'),
      'a SAML 2.0 assertion': t.text('portal.apps.waySaml2'),
      'a SAML 1.1 assertion': t.text('portal.apps.waySaml11'),
      'a WS-Federation token': t.text('portal.apps.wayWsfed')
    };
    const rows: Json[] = view.rows || [];
    const table = rows.length
      ? '<table class="grid"><tr><th>' + t.html('portal.apps.application') +
        '</th><th>' + t.html('portal.apps.signIn') + '</th><th>' +
        t.html('portal.apps.issued') + '</th></tr>' +
        rows.map(function (row: Json): string {
          const launch = row.launch
            ? '<a class="launch" rel="noopener" href="' + esc(row.launch) +
              '">' + t.html('portal.signIn') + '</a>' : '';
          return '<tr><td><strong>' + OverviewPages.linkedName(row, t) +
            '</strong>' + (launch ? ' ' + launch : '') +
            '<span class="ident"><code>' + esc(row.identifier) +
            '</code></span>' +
            (row.description ? '<span class="ident">' +
              esc(row.description) + '</span>' : '') + '</td><td>' +
            (row.families || []).map(function (label: string): string {
              return '<span class="tag">' + esc(label) + '</span>';
            }).join('') +
            ((row.withheld || []).length
              ? '<span class="ident">' + t.html('portal.apps.withheld',
                  { families: row.withheld.join(', '),
                    n: row.families.length }) + '</span>'
              : '') +
            '</td><td>' + esc((row.ways || []).map(function (how: string) {
              return ways[how] || how;
            }).join(', ')) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="note">' + t.html('portal.apps.nothing') + '</p>';
    return '<div class="card"><p class="sub">' + t.html('portal.apps.sub') +
      '</p>' + table +
      OverviewPages.paging(BASE + '/applications', view.page, view.pages, t) +
      '</div><div class="card"><h2>' + t.html('portal.apps.notListed') +
      '</h2><table><tr><th>' + t.html('portal.apps.notPermitted') +
      '</th><td>' + t.html('portal.apps.notPermittedWhat',
                           { n: view.refused }) +
      '</td></tr><tr><th>' + t.html('portal.apps.notDestinations') +
      '</th><td>' + t.html('portal.apps.notDestinationsWhat',
                           { n: view.notSignIn }) + '</td></tr>' +
      (view.truncated
        ? '<tr><th>' + t.html('portal.apps.notLooked') + '</th><td>' +
          t.html('portal.apps.notLookedWhat',
            { skipped: view.total - view.scanned, total: view.total,
              limit: view.limit }) + '</td></tr>'
        : '') +
      '</table><p class="note">' + t.html('portal.apps.note') + '</p></div>';
  }

  // WHETHER SECURITY EVENTS ABOUT THIS ACCOUNT ARE SHARED (#146): only the
  // moves the state diagram allows from where the account is get a button;
  // a service account (#221) is told why it has none.
  /**
   * The RISC participation card.
   *
   * @param p - the view's `participation`, or null while RISC is off
   * @param t - the translator
   * @returns the HTML
   */
  static participationCard(p: Json, t: Json): string {
    if (!p) {
      return '';
    }
    if (p.applies === false) {
      return '<div class="card"><h2>' + t.html('portal.risc.heading') +
        '</h2><p>' + t.html('portal.risc.alwaysShared') + '</p><p ' +
        'class="note">' + esc(String(p.why || '')) + '</p></div>';
    }
    const said = p.state === 'opt-in'
      ? t.html('portal.risc.shared')
      : p.state === 'opt-out-initiated'
        ? (p.since ? t.html('portal.risc.stoppingSince',
                            { since: p.since, hours: p.hours })
                   : t.html('portal.risc.stopping', { hours: p.hours }))
        : t.html('portal.risc.notShared');
    const labels: Json = { optOutInitiated: t.html('portal.risc.stop'),
                           optOutCancelled: t.html('portal.risc.cancel'),
                           optIn: t.html('portal.risc.again') };
    const buttons = (p.moves || []).map(function (move: string): string {
      return '<form method="post" action="' + esc(BASE + '/signals') + '">' +
        '<input type="hidden" name="move" value="' + esc(move) + '">' +
        '<button' + (move === 'optOutInitiated' ? ' class="danger"' : '') +
        '>' + (labels[move] || esc(move)) + '</button></form>';
    }).join('');
    return '<div class="card"><h2>' + t.html('portal.risc.heading') +
      '</h2><p>' + said + '</p>' + buttons + '<p class="note">' +
      t.html('portal.risc.note', { hours: p.hours }) + '</p></div>';
  }

  /**
   * The Security activity page's body.
   *
   * @param view - `GET /account-api/signals`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static signals(view: Json, ctx: Json): string {
    const t = ctx.t;
    const rows: Json[] = view.rows || [];
    // WHY THERE MIGHT BE NOTHING, ABOVE THE LIST, in a person's words rather
    // than an operator's, pointing at who can change it.
    const why = view.incomplete
      ? '<div class="err"><p>' + t.html('portal.signals.incomplete') +
        ' <a href="/admin/signals">' + t.html('portal.signals.consoleCopy') +
        '</a>' + t.html('portal.signals.incompleteAfter') + '</p></div>'
      : '';
    const list = rows.length
      ? '<table class="grid"><tr><th>' + t.html('portal.signals.when') +
        '</th><th>' + t.html('portal.signals.what') + '</th><th>' +
        t.html('portal.signals.detail') + '</th></tr>' +
        rows.map(function (row: Json): string {
          const payload = row.payload || {};
          return '<tr><td>' + esc(row.at) + '</td><td><strong>' +
            esc(row.name) + '</strong><span class="ident"><span ' +
            'class="tag">' + esc(row.vocabulary) + '</span> ' +
            esc(row.type || '') + '</span></td><td>' +
            (Object.keys(payload).length
              ? '<details><summary>' + t.html('portal.signals.details',
                  { n: Object.keys(payload).length }) + '</summary><pre>' +
                esc(JSON.stringify(payload, null, 2)) + '</pre></details>'
              : '<span class="ident">' +
                t.html('portal.signals.nothingMore') + '</span>') +
            '<span class="ident">' +
            (row.verified ? t.html('portal.signals.verified')
              : t.html('portal.signals.notVerified',
                       { note: row.verificationNote })) + '</span>' +
            // WHAT THIS PORTAL DID WITH IT (#62): signed you out here, if
            // the signal-response policy said to.
            (row.reactions || []).map(function (r: Json): string {
              return '<span class="ident signal-reaction">' +
                (r.failed ? t.html('portal.signals.couldNot')
                  : r.skipped ? t.html('portal.signals.left',
                                       { why: r.skipped })
                  : (r.observed ? t.html('portal.signals.would')
                    : (Number(r.ended) > 0
                        ? t.html('portal.signals.signedOut')
                        : t.html('portal.signals.noSession')))) +
                '</span>';
            }).join('') + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="note">' + t.html('portal.signals.empty') + '</p>';
    return OverviewPages.participationCard(view.participation, t) +
      '<div class="card"><h2>' + t.html('portal.signals.heading') +
      '</h2><p class="sub">' + t.html('portal.signals.sub') + '</p>' + why +
      list + OverviewPages.paging(BASE + '/signals', view.page, view.pages,
                                  t) +
      '</div><div class="card"><h2>' + t.html('portal.signals.isNot') +
      '</h2><p class="note">' + t.html('portal.signals.onlyYou') +
      '</p><p class="note">' + t.html('portal.signals.record') + ' ' +
      t.html('portal.signals.toEnd') + ' <a href="/logout">' +
      t.html('portal.signals.signOutAll') + '</a>' +
      t.html('portal.signals.toChange') + '</p><p class="note">' +
      t.html('portal.signals.caepRisc') + '</p></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: BASE, operation: '/account-api/overview',
      render: OverviewPages.overview },
    { path: BASE + '/applications', operation: '/account-api/applications',
      render: OverviewPages.applications },
    { path: BASE + '/signals', operation: '/account-api/signals',
      render: OverviewPages.signals }
  ];
}

export = OverviewPages;
