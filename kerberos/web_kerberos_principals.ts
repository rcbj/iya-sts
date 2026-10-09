// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_kerberos_principals.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → KERBEROS PRINCIPALS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws Kerberos principals from the answer of `GET
// /admin-api/kerberos/principals`: this realm's KDC principals, people and
// services, with their keys and the forms that change them.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/kerberos/principals` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws Kerberos principals from the answer of `GET
 * /admin-api/kerberos/principals`: this realm's KDC principals, people and
 * services, with their keys and the forms that change them.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class KerberosPrincipalsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // THE WORDS ARE THE CATALOG'S (#539): `consoleKerberosPrincipals`, whose
    // English is exactly what this page drew before. A value from the view
    // that kit.esc() drew is still drawn by kit.esc() — through t.text() for
    // a message with no markup — because t.html() escapes an apostrophe as
    // &#39; where kit.esc() writes &apos;, and English must not move a byte.
    const t = ctx.t;
    const mayChange = ctx.write;
    const back = kit.queryWith(kit.listViewOf('/admin/kerberos/principals',
                                           ctx.query),
                           {});
    const peopleNav = kit.pageNavPair('/admin/kerberos/principals',
      kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'peoplePage',
                      noun: t.html('consoleKerberosPrincipals.nounPeople'),
                      offset: 0 },
                    json.peoplePaging));
    const servicesNav = kit.pageNavPair('/admin/kerberos/principals',
      kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'servicesPage',
                      noun: t.html('consoleKerberosPrincipals.nounServices'),
                      offset: 0 },
                    json.servicesPaging));
    const etypeList = function (etypes) {
      return (etypes || []).map(function (one) {
        return '<code>' + kit.esc(one.name) + '</code>';
      }).join(' ');
    };

    // THE PREVIOUS VERSIONS A KEY STILL KEEPS (2026-09-12): kvno, enctypes
    // and when each stops being accepted. Never a key — the row carries none.
    const retainedCell = function (retained) {
      return (retained || []).length
        ? retained.map(function (one) {
            return 'kvno ' + kit.esc(String(one.kvno)) + ' ' +
                   etypeList(one.etypes) +
              '<br><span class="sub">' +
              kit.esc(t.text('consoleKerberosPrincipals.until',
                             { at: one.expiresAt })) +
              '</span>';
          }).join('<br>')
        : '<span class="sub">' + t.html('consoleKerberosPrincipals.none') +
          '</span>';
    };

    const rowButton = function (action, field, value, label, title) {
      return '<form method="post" action="/admin/kerberos/principals">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) +
        '"><input type="hidden" name="' + kit.esc(field) + '" value="' +
        kit.esc(value) +
        '"><input ' +
        'type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<button type="submit" class="secondary" title="' + kit.esc(title) +
        '">' +
        kit.esc(label) + '</button></form>';
    };
    const atRest = function (sealed) {
      return sealed ? t.html('consoleKerberosPrincipals.sealed')
                    : t.html('consoleKerberosPrincipals.clearDev');
    };
    const serviceRows = json.services.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.principal) + '</code>' +
        (row.held ? '' : '<div class="state-invalid">' +
          kit.esc(t.text('consoleKerberosPrincipals.keyMissing')) +
          '</div>') + '</td>' +
        '<td>' + kit.esc(row.kvno == null ? '—' : String(row.kvno)) +
        '</td><td>' + etypeList(row.etypes) + '</td>' +
        '<td class="sub">' + kit.esc(row.createdAt || '—') +
        (row.rotatedAt ? '<br>' +
          kit.esc(t.text('consoleKerberosPrincipals.rotated',
                         { at: row.rotatedAt })) : '') +
        '</td><td>' + retainedCell(row.retained) + '</td>' +
        '<td>' + atRest(row.sealed) + '</td>' +
        '<td>' + (mayChange
          ? rowButton('rotate-service', 'spn', row.spn,
              t.text('consoleKerberosPrincipals.rotateService'),
              t.text('consoleKerberosPrincipals.rotateServiceTitle',
                     { kvno: String(Number(row.kvno) + 1) })) +
            ((row.retained || []).length
              ? rowButton('drop-previous-service-keys', 'spn', row.spn,
                  t.text('consoleKerberosPrincipals.dropPrevious'),
                  t.text('consoleKerberosPrincipals.dropServiceTitle',
                    { list: row.retained.map(function (one) {
                      return one.kvno;
                    }).join(', ') }))
              : '') +
            rowButton('delete-service', 'spn', row.spn,
              t.text('consoleKerberosPrincipals.deleteKey'),
              t.text('consoleKerberosPrincipals.deleteServiceTitle'))
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="7">' +
      kit.esc(t.text('consoleKerberosPrincipals.noServices')) + '</td></tr>';
    const peopleRows = json.people.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.principal) + '</code></td>' +
        '<td>' + kit.esc(row.kvno == null ? '—' : String(row.kvno)) +
        '</td><td>' + etypeList(row.etypes) + '</td>' +
        '<td class="sub">' + kit.esc(row.derivedAt || '—') +
        (row.derivedOn ? '<br>' +
          kit.esc(t.text('consoleKerberosPrincipals.onPassword',
                         { at: row.derivedOn })) :
         '') +
        '</td><td>' + (row.current ? t.html('consoleKerberosPrincipals.yes')
          : '<span class="state-invalid" title="' +
            kit.esc(t.text('consoleKerberosPrincipals.notCurrentTitle')) +
            '">' + t.html('consoleKerberosPrincipals.no') + '</span>') +
        '</td>' +
        '<td>' + retainedCell(row.retained) + '</td>' +
        '<td>' + atRest(row.sealed) + '</td>' +
        '<td>' + (mayChange
          ? rowButton('clear-person-keys', 'username', row.username,
              t.text('consoleKerberosPrincipals.clearKeys'),
              t.text('consoleKerberosPrincipals.clearPersonTitle')) +
            ((row.retained || []).length
              ? rowButton('drop-previous-person-keys', 'username',
                          row.username,
                  t.text('consoleKerberosPrincipals.dropPrevious'),
                  t.text('consoleKerberosPrincipals.dropPersonTitle',
                    { list: row.retained.map(function (one) {
                      return one.kvno;
                    }).join(', ') }))
              : '')
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="8">' + kit.esc(json.productKdc
      ? t.text('consoleKerberosPrincipals.nobodyProduct')
      : t.text('consoleKerberosPrincipals.nobodyDevelopment')) +
      '</td></tr>';

    // THE REALM'S KRBTGT (#169): its own block, because none of the
    // service-principal controls applies to it — no keytab is ever made
    // for it — and two controls of its own do, both of which QUEUE a run
    // of `krb5.krbtgt-rotate-now` on the scheduler rather than rotating in
    // this request. The invalidate form is a typed confirmation, not a
    // script: the word goes in a text field and the action refuses
    // without it (STS-ADMIN-0610).
    const k = json.krbtgt;
    const sources = {
      stored: t.text('consoleKerberosPrincipals.srcStored'),
      password: t.text('consoleKerberosPrincipals.srcPassword'),
      none: t.text('consoleKerberosPrincipals.srcNone'),
      unreadable: t.text('consoleKerberosPrincipals.srcUnreadable')
    };
    const krbtgtSection = !k ? '' :
      '<h2>' + t.html('consoleKerberosPrincipals.hKrbtgt') + '</h2>' +
      kit.note(t.html('consoleKerberosPrincipals.krbtgtIntro') +
        (k.source === 'password'
          ? t.html('consoleKerberosPrincipals.krbtgtPassword')
          : t.html('consoleKerberosPrincipals.krbtgtRandom1') + '<code>' +
            kit.esc(k.principal || '') + '</code>' +
            t.html('consoleKerberosPrincipals.krbtgtRandom2')) +
        t.html('consoleKerberosPrincipals.krbtgtRotation',
               { ttl: String(k.retainedTtlSeconds) })) +
      (k.source === 'unreadable'
        ? kit.warn(t.html('consoleKerberosPrincipals.unreadable1') +
            kit.esc(k.why) +
            t.html('consoleKerberosPrincipals.unreadable2'))
        : k.source === 'none'
          ? kit.warn(t.html('consoleKerberosPrincipals.noneStored'))
          : '') +
      '<table class="key">' +
      '<tr><th>' + t.html('consoleKerberosPrincipals.thPrincipal') +
      '</th><td><code>' + kit.esc(k.principal || '—') +
      '</code></td></tr>' +
      '<tr><th>' + t.html('consoleKerberosPrincipals.thKeyFrom') +
      '</th><td>' + kit.esc(sources[k.source] || k.source) + '</td></tr>' +
      '<tr><th>kvno</th><td>' + kit.esc(k.kvno == null ? '—'
                                                        : String(k.kvno)) +
      '</td></tr><tr><th>' + t.html('consoleKerberosPrincipals.thEnctypes') +
      '</th><td>' + etypeList(k.etypes) +
      '</td></tr><tr><th>' + t.html('consoleKerberosPrincipals.thCreated') +
      '</th><td class="sub">' +
      kit.esc(k.createdAt || '—') + '</td></tr>' +
      '<tr><th>' + t.html('consoleKerberosPrincipals.thLastRotated') +
      '</th><td class="sub">' +
      kit.esc(k.lastRotatedAt || t.text('consoleKerberosPrincipals.never')) +
      (k.invalidatedAt ? '<br>' +
        kit.esc(t.text('consoleKerberosPrincipals.lastInvalidated',
                       { at: k.invalidatedAt })) : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleKerberosPrincipals.thNextRotation') +
      '</th><td class="sub">' +
      (k.scheduled
        ? kit.esc(k.nextDueAt || '—') +
          t.html('consoleKerberosPrincipals.every',
                 { days: String(k.intervalDays) })
        : t.html('consoleKerberosPrincipals.noneDash') +
          kit.esc(k.offReason)) + '</td></tr>' +
      '<tr><th>' + t.html('consoleKerberosPrincipals.thPrevious') +
      '</th><td>' + retainedCell(k.retained) +
      '</td></tr></table>' +
      (mayChange
        ? '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" value="rotate-krbtgt">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) +
          '"><button type="submit" title="' +
          kit.esc(t.text('consoleKerberosPrincipals.rotateKrbtgtTitle')) +
          '">' + t.html('consoleKerberosPrincipals.rotateKrbtgt') +
          '</button></form>' +
          ((k.retained || []).length
            ? rowButton('drop-previous-service-keys', 'spn',
                String(k.principal || '').replace(/@[^@]*$/, ''),
                t.text('consoleKerberosPrincipals.dropPrevious'),
                t.text('consoleKerberosPrincipals.dropKrbtgtTitle',
                  { list: k.retained.map(function (one) {
                    return one.kvno;
                  }).join(', ') }))
            : '') +
          '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" ' +
          'value="rotate-krbtgt-invalidate">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) +
          '"><div class="formrow"><label for="krbtgt-confirm">' +
          t.html('consoleKerberosPrincipals.typeConfirm1') +
          '<code>' + kit.esc(k.confirmWord || 'invalidate') + '</code>' +
          t.html('consoleKerberosPrincipals.typeConfirm2') + '</label>' +
          '<input type="text" id="krbtgt-confirm" name="confirm" size="12" ' +
          'autocomplete="off">' +
          '<button type="submit" class="danger">' +
          t.html('consoleKerberosPrincipals.rotateInvalidate') +
          '</button></div></form>'
        : kit.note(t.html('consoleKerberosPrincipals.needWriteKrbtgt')));

    // The notes' sentences after each headline are the view's, drawn as
    // they come.
    const inner = kit.note(t.html('consoleKerberosPrincipals.whoFor') +
                kit.esc(json.notes.mode)) +
      kit.warn(t.html('consoleKerberosPrincipals.noKey') +
                kit.esc(json.notes.keys)) +
      kit.note(kit.esc(json.notes.realm) + ' ' +
                kit.esc(json.notes.window)) +
      kit.note(t.html('consoleKerberosPrincipals.previous') +
                kit.esc(json.notes.previous) +
                t.html('consoleKerberosPrincipals.now', {
                  versions: String(json.retention.versions),
                  ttl: String(json.retention.ttlSeconds) }) +
                (json.retention.ttlSetting > 0 ? '' :
                  t.html('consoleKerberosPrincipals.ttlZero')) + '.') +
      '<div class="tiles">' +
      kit.tile(json.peopleTotal,
               t.text('consoleKerberosPrincipals.tilePeople')) +
      kit.tile(json.servicesTotal,
               t.text('consoleKerberosPrincipals.tileServices')) +
      kit.tile(json.enctypes.length,
               t.text('consoleKerberosPrincipals.tileEnctypes')) +
      kit.tile(json.startingKvno,
               t.text('consoleKerberosPrincipals.tileKvno')) +
      '</div>' +
      kit.note(t.html('consoleKerberosPrincipals.acceptor') +
                '<code>' + kit.esc(json.acceptor.spn ||
                  t.text('consoleKerberosPrincipals.noSpn')) +
                '</code>' +
                (json.acceptor.storedKey
                  ? t.html('consoleKerberosPrincipals.acceptorStored')
                  : json.acceptor.available
                    ? t.html('consoleKerberosPrincipals.acceptorPassword')
                    : t.html('consoleKerberosPrincipals.acceptorNone')) +
                (json.personKeys
                  ? t.html('consoleKerberosPrincipals.personKeysOn')
                  : t.html('consoleKerberosPrincipals.personKeysOff'))) +
      krbtgtSection +
      '<h2>' + t.html('consoleKerberosPrincipals.hServices') + '</h2>' +
      servicesNav.head +
      '<table><tr><th>' + t.html('consoleKerberosPrincipals.thPrincipal') +
      '</th><th>kvno</th><th>' +
      t.html('consoleKerberosPrincipals.thEnctypes') + '</th>' +
      '<th>' + t.html('consoleKerberosPrincipals.thCreated') + '</th><th>' +
      t.html('consoleKerberosPrincipals.thPrevious') + '</th><th>' +
      t.html('consoleKerberosPrincipals.thAtRest') + '</th><th></th></tr>' +
      serviceRows + '</table>' +
      servicesNav.foot +
      (mayChange
        ? '<h3>' + t.html('consoleKerberosPrincipals.hCreate') + '</h3>' +
          kit.note(t.html('consoleKerberosPrincipals.create1') +
                    '<code>@' + kit.esc(json.realm) + '</code>' +
                    t.html('consoleKerberosPrincipals.create2',
                           { kvno: String(json.startingKvno) })) +
          '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" value="create-service">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<div class="formrow"><label for="krb5-spn">SPN</label>' +
          '<input type="text" id="krb5-spn" name="spn" size="40" ' +
          'placeholder="HTTP/web.example.com">' +
          '<button type="submit">' +
          t.html('consoleKerberosPrincipals.createShow') +
          '</button></div></form>'
        : kit.note(t.html('consoleKerberosPrincipals.needWriteServices'))) +
      '<h2>' + t.html('consoleKerberosPrincipals.hPeople') + '</h2>' +
      peopleNav.head +
      '<table><tr><th>' + t.html('consoleKerberosPrincipals.thPrincipal') +
      '</th><th>kvno</th><th>' +
      t.html('consoleKerberosPrincipals.thEnctypes') + '</th>' +
      '<th>' + t.html('consoleKerberosPrincipals.thDerived') + '</th><th>' +
      t.html('consoleKerberosPrincipals.thMatches') + '</th><th>' +
      t.html('consoleKerberosPrincipals.thPrevious') + '</th><th>' +
      t.html('consoleKerberosPrincipals.thAtRest') + '</th><th></th></tr>' +
      peopleRows + '</table>' + peopleNav.foot +
      kit.perPageForm('/admin/kerberos/principals', 'peoplePage', '1',
                       json.peoplePaging.perPage) +
      '<h2>' + t.html('consoleKerberosPrincipals.hNoButton') + '</h2>' +
      kit.note(t.html('consoleKerberosPrincipals.noButton')) +
      kit.note('<a href="/admin/kerberos/principals?format=json">' +
                t.html('consoleKerberosPrincipals.linkJson') +
                '</a> &middot; <a ' +
                'href="/admin-api/kerberos/principals">' +
                t.html('consoleKerberosPrincipals.linkApi') +
                '</a> &middot; <a href="/admin/kerberos">' +
                t.html('consoleKerberosPrincipals.linkSettings') +
                '</a> &middot; <a ' +
                'href="/krb5/principals">' +
                t.html('consoleKerberosPrincipals.linkDb') + '</a>');

    return inner;
  }
}

export = KerberosPrincipalsPage;
