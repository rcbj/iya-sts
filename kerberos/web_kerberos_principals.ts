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
    const mayChange = ctx.write;
    const back = kit.queryWith(kit.listViewOf('/admin/kerberos/principals',
                                           ctx.query),
                           {});
    const peopleNav = kit.pageNavPair('/admin/kerberos/principals',
      kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'peoplePage', noun: 'people', offset: 0 },
                    json.peoplePaging));
    const servicesNav = kit.pageNavPair('/admin/kerberos/principals',
      kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'servicesPage', noun: 'service principals',
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
              '<br><span class="sub">until ' + kit.esc(one.expiresAt) +
              '</span>';
          }).join('<br>')
        : '<span class="sub">none</span>';
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
    const serviceRows = json.services.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.principal) + '</code>' +
        (row.held ? '' : '<div class="state-invalid">' +
          kit.esc('The key record is missing; the info attribute is all ' +
                   'that is left.') +
          '</div>') + '</td>' +
        '<td>' + kit.esc(row.kvno == null ? '—' : String(row.kvno)) +
        '</td><td>' + etypeList(row.etypes) + '</td>' +
        '<td class="sub">' + kit.esc(row.createdAt || '—') +
        (row.rotatedAt ? '<br>rotated ' + kit.esc(row.rotatedAt) : '') +
        '</td><td>' + retainedCell(row.retained) + '</td>' +
        '<td>' + (row.sealed ? 'sealed' : 'clear (development)') + '</td>' +
        '<td>' + (mayChange
          ? rowButton('rotate-service', 'spn', row.spn, 'Rotate and show ' +
                                                        'the keytab',
              'Makes new random keys at kvno ' + (Number(row.kvno) + 1) +
              ' and shows their keytab once, with the kvno it replaces ' +
              'still in it. Tickets already issued under the current key ' +
              'go on being accepted for krb5.retainedKeyTtlS.') +
            ((row.retained || []).length
              ? rowButton('drop-previous-service-keys', 'spn', row.spn,
                  'Drop previous versions',
                  'Stops accepting tickets under kvno ' +
                  row.retained.map(function (one) {
                    return one.kvno;
                  }).join(', ') + ' now, rather than when their window ' +
                  'ends. The current key is untouched.')
              : '') +
            rowButton('delete-service', 'spn', row.spn, 'Delete the key',
              'Removes the stored key and every previous version. Tickets ' +
              'for this SPN are then keyed as they were before a key was ' +
              'stored.')
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="7">' + kit.esc('No service principal ' +
      'holds a stored key.') + '</td></tr>';
    const peopleRows = json.people.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.principal) + '</code></td>' +
        '<td>' + kit.esc(row.kvno == null ? '—' : String(row.kvno)) +
        '</td><td>' + etypeList(row.etypes) + '</td>' +
        '<td class="sub">' + kit.esc(row.derivedAt || '—') +
        (row.derivedOn ? '<br>on a password ' + kit.esc(row.derivedOn) :
         '') +
        '</td><td>' + (row.current ? 'yes'
          : '<span class="state-invalid" title="' +
            kit.esc('The password on the entry is not the one these keys ' +
              'were derived from, so the KDC refuses them. The next ' +
              'verified sign-in derives new ones.') + '">no</span>') +
        '</td>' +
        '<td>' + retainedCell(row.retained) + '</td>' +
        '<td>' + (row.sealed ? 'sealed' : 'clear (development)') + '</td>' +
        '<td>' + (mayChange
          ? rowButton('clear-person-keys', 'username', row.username,
                      'Clear ' +
              'the keys',
              'Removes this person\'s Kerberos keys, previous versions ' +
              'included. Their next AS-REQ is refused with "sign in once"; ' +
              'their next verified sign-in derives new keys at the next ' +
              'kvno.') +
            ((row.retained || []).length
              ? rowButton('drop-previous-person-keys', 'username',
                          row.username,
                  'Drop previous versions',
                  'Stops accepting tickets sealed under kvno ' +
                  row.retained.map(function (one) { return one.kvno; })
                              .join(', ') +
                  ' — this person\'s keys before their last password ' +
                  'change — now. Their current keys, and so their sign-in, ' +
                  'are untouched.')
              : '')
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="8">' + kit.esc(json.productKdc
      ? 'Nobody holds Kerberos keys yet. A person gets them the first time ' +
        'their password is set or verified.'
      : 'Development mode keys every user from krb5.userPassword, so ' +
        'nobody here holds stored keys.') + '</td></tr>';

    // THE REALM'S KRBTGT (#169): its own block, because none of the
    // service-principal controls applies to it — no keytab is ever made
    // for it — and two controls of its own do, both of which QUEUE a run
    // of `krb5.krbtgt-rotate-now` on the scheduler rather than rotating in
    // this request. The invalidate form is a typed confirmation, not a
    // script: the word goes in a text field and the action refuses
    // without it (STS-ADMIN-0610).
    const k = json.krbtgt;
    const krbtgtSection = !k ? '' :
      '<h2>The krbtgt key</h2>' +
      kit.note('Every ticket-granting ticket this realm issues is sealed ' +
        'under this key. ' + (k.source === 'password'
          ? 'In this development realm it is derived from the published ' +
            '<code>krb5.krbtgtPassword</code>, so a reader can decrypt a ' +
            'TGT; rotating it here replaces it with a random stored key.'
          : 'It is a RANDOM key per enctype, kept sealed on the directory ' +
            'entry <code>' + kit.esc(k.principal || '') + '</code> and ' +
            'never shown — there is no keytab for it.') +
        ' A rotation keeps the version it replaces for ' +
        kit.esc(String(k.retainedTtlSeconds)) + ' seconds (the longest a ' +
        'TGT under it can live, renewals included), so every TGT goes on ' +
        'working; <strong>rotate and invalidate</strong> keeps nothing — ' +
        'Active Directory\'s double reset in one act — and every TGT in ' +
        'the realm is refused at its next use.') +
      (k.source === 'unreadable'
        ? kit.warn('<strong>The stored krbtgt key cannot be opened ' +
            'here</strong> (' + kit.esc(k.why) + '), so this KDC issues ' +
            'no ticket. Only <strong>rotate and invalidate</strong> ' +
            'replaces it.')
        : k.source === 'none'
          ? kit.warn('No krbtgt key is stored for this realm yet, so its ' +
              'KDC issues no ticket. It is made at the next start, or by ' +
              'the <code>krb5.krbtgt-rotate</code> job, or by a rotation ' +
              'here.')
          : '') +
      '<table class="key">' +
      '<tr><th>Principal</th><td><code>' + kit.esc(k.principal || '—') +
      '</code></td></tr>' +
      '<tr><th>Key from</th><td>' + kit.esc({
        stored: 'a random key stored on the directory',
        password: 'krb5.krbtgtPassword (development)',
        none: 'nothing yet', unreadable: 'a record this service cannot open'
      }[k.source] || k.source) + '</td></tr>' +
      '<tr><th>kvno</th><td>' + kit.esc(k.kvno == null ? '—'
                                                        : String(k.kvno)) +
      '</td></tr><tr><th>Enctypes</th><td>' + etypeList(k.etypes) +
      '</td></tr><tr><th>Created</th><td class="sub">' +
      kit.esc(k.createdAt || '—') + '</td></tr>' +
      '<tr><th>Last rotated</th><td class="sub">' +
      kit.esc(k.lastRotatedAt || 'never') +
      (k.invalidatedAt ? '<br>last invalidated ' +
        kit.esc(k.invalidatedAt) : '') + '</td></tr>' +
      '<tr><th>Next scheduled rotation</th><td class="sub">' +
      (k.scheduled
        ? kit.esc(k.nextDueAt || '—') + ' (every ' +
          kit.esc(String(k.intervalDays)) + ' days, ' +
          '<code>krb5.krbtgtRotationIntervalDays</code>)'
        : 'none — ' + kit.esc(k.offReason)) + '</td></tr>' +
      '<tr><th>Previous versions</th><td>' + retainedCell(k.retained) +
      '</td></tr></table>' +
      (mayChange
        ? '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" value="rotate-krbtgt">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) +
          '"><button type="submit" title="' + kit.esc('A new random ' +
            'krbtgt key at the next kvno; the current one is kept for the ' +
            'TGTs already sealed under it. Queued on the scheduler.') +
          '">Rotate the krbtgt key</button></form>' +
          ((k.retained || []).length
            ? rowButton('drop-previous-service-keys', 'spn',
                String(k.principal || '').replace(/@[^@]*$/, ''),
                'Drop previous versions',
                'Stops accepting TGTs sealed under kvno ' +
                k.retained.map(function (one) {
                  return one.kvno;
                }).join(', ') + ' now. The current key is untouched.')
            : '') +
          '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" ' +
          'value="rotate-krbtgt-invalidate">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) +
          '"><div class="formrow"><label for="krbtgt-confirm">Type ' +
          '<code>' + kit.esc(k.confirmWord || 'invalidate') + '</code> ' +
          'to end every TGT in the realm</label>' +
          '<input type="text" id="krbtgt-confirm" name="confirm" size="12" ' +
          'autocomplete="off">' +
          '<button type="submit" class="danger">Rotate and ' +
          'invalidate</button></div></form>'
        : kit.note('Rotating the krbtgt key needs <strong>Admin ' +
                    'Write</strong>.'));

    const inner = kit.note('<strong>Who this KDC holds a stored key ' +
      'for.</strong> ' +
                kit.esc(json.notes.mode)) +
      kit.warn('<strong>No key is on this page, and none is in its ' +
        'JSON.</strong> ' +
                kit.esc(json.notes.keys)) +
      kit.note(kit.esc(json.notes.realm) + ' ' +
                kit.esc(json.notes.window)) +
      kit.note('<strong>Previous key versions.</strong> ' +
                kit.esc(json.notes.previous) +
                ' Now: ' + kit.esc(String(json.retention.versions)) + ' ' +
                  'kept, each for ' +
                kit.esc(String(json.retention.ttlSeconds)) + ' seconds' +
                (json.retention.ttlSetting > 0 ? '' : ' (the ticket ' +
                  'lifetime plus the clock skew, because ' +
                  '<code>krb5.retainedKeyTtlS</code> is 0)') + '.') +
      '<div class="tiles">' +
      kit.tile(json.peopleTotal, 'people with keys') +
      kit.tile(json.servicesTotal, 'service principals') +
      kit.tile(json.enctypes.length, 'enctypes (krb5.enctypes)') +
      kit.tile(json.startingKvno, 'starting kvno') +
      '</div>' +
      kit.note('The acceptor on <code>krb5.servicePort</code> and ' +
                '<code>/authn/spnego</code> answers as ' +
                '<code>' + kit.esc(json.acceptor.spn || '(no SPN)') +
                '</code>' +
                (json.acceptor.storedKey
                  ? ', keyed from a service principal stored here.'
                  : json.acceptor.available
                    ? ', keyed from krb5.servicePassword. Creating that ' +
                      'SPN here gives it a random key and a keytab instead.'
                    : ', and holds no key: create that SPN here to give it ' +
                      'one.') +
                ' <code>krb5.personKeys</code> is ' +
                (json.personKeys ? 'on' : 'OFF') + '.') +
      krbtgtSection +
      '<h2>Service principals</h2>' + servicesNav.head +
      '<table><tr><th>Principal</th><th>kvno</th><th>Enctypes</th>' +
      '<th>Created</th><th>Previous versions</th><th>At ' +
      'rest</th><th></th></tr>' +
      serviceRows + '</table>' +
      servicesNav.foot +
      (mayChange
        ? '<h3>Create a service principal</h3>' +
          kit.note('A service principal name — ' +
                    '<code>HTTP/web.example.com</code>, with or without ' +
                    '<code>@' + kit.esc(json.realm) + '</code>. It gets a ' +
                    'RANDOM key for every enctype in ' +
                    '<code>krb5.enctypes</code> (never rc4-hmac in product ' +
                    'mode) at kvno ' +
                    kit.esc(String(json.startingKvno)) + ', stored sealed ' +
                    'on its application entry, and the next page shows its ' +
                    'keytab ONCE. <code>krbtgt</code> is refused: it has ' +
                    'its own block above, and no keytab.') +
          '<form method="post" action="/admin/kerberos/principals">' +
          '<input type="hidden" name="action" value="create-service">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<div class="formrow"><label for="krb5-spn">SPN</label>' +
          '<input type="text" id="krb5-spn" name="spn" size="40" ' +
          'placeholder="HTTP/web.example.com">' +
          '<button type="submit">Create and show the ' +
          'keytab</button></div></form>'
        : kit.note('Creating, rotating and deleting a service principal ' +
                    'needs <strong>Admin Write</strong>.')) +
      '<h2>People</h2>' + peopleNav.head +
      '<table><tr><th>Principal</th><th>kvno</th><th>Enctypes</th>' +
      '<th>Derived</th><th>Matches the password</th><th>Previous ' +
      'versions</th><th>At rest</th><th></th></tr>' +
      peopleRows + '</table>' + peopleNav.foot +
      kit.perPageForm('/admin/kerberos/principals', 'peoplePage', '1',
                       json.peoplePaging.perPage) +
      '<h2>What there is deliberately no button for</h2>' +
      kit.note('<strong>Downloading a keytab again.</strong> A stored key ' +
                'is never read back out: a service principal\'s keytab is ' +
                'handed over by the create or rotate that made it, and a ' +
                'lost one is replaced by rotating. A PERSON\'s keytab ' +
                '(#59) is derived from a password in hand: <strong>Reset ' +
                'password and download keytab</strong> on their page ' +
                'under Directory &rarr; Users, or their own password on ' +
                '<code>/portal/kerberos</code>. <strong>Setting a ' +
                'person\'s keys.</strong> ' +
                'They come from the person\'s password and from nothing ' +
                'else; clearing them is the one control, and the next ' +
                'verified sign-in derives them again.') +
      kit.note('<a href="/admin/kerberos/principals?format=json">this ' +
                'page as JSON</a> &middot; <a ' +
                'href="/admin-api/kerberos/principals">the same over the ' +
                'management API</a> &middot; <a href="/admin/kerberos">the ' +
                'Kerberos settings</a> &middot; <a ' +
                'href="/krb5/principals">the principal database</a>');

    return inner;
  }
}

export = KerberosPrincipalsPage;
