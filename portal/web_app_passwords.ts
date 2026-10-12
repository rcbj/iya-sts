// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_app_passwords.ts
//
// ---------------------------------------------------------------------------
// `/portal/app-passwords`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/app-passwords` (`portal_app_passwords.ts`): which doors refuse
// the person's own password, the app passwords they hold with a Revoke each,
// and the form that makes one. A password an act just made arrives in the
// answer's `view.fresh` and is drawn here, once.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/app-passwords';

/**
 * `/portal/app-passwords`. A static utility class.
 */
class AppPasswordsPages {
  // A time a person reads, in their language (#539): `t.date()` gives it in
  // UTC and says so. Answers TEXT, which the caller escapes.
  /**
   * A time, or "never".
   *
   * @param when - milliseconds, or nothing
   * @param t - the translator
   * @returns the text
   */
  static readable(when: unknown, t: Json): string {
    const at = new Date(Number(when || 0));
    return !Number(when) || isNaN(at.getTime())
      ? t.text('portalAppPasswords.never') : t.date(at);
  }

  // What speaks a door, in the reader's language (#539). Each key is named
  // literally, so the catalog test's scan sees them, and an id the table
  // grows later falls back to the table's English.
  /**
   * What speaks a door.
   *
   * @param one - a door row
   * @param t - the translator
   * @returns the text
   */
  static doorWhat(one: Json, t: Json): string {
    const known: { [id: string]: string } = {
      ldap: t.text('portalAppPasswords.door.ldap'),
      wstrust: t.text('portalAppPasswords.door.wstrust'),
      scim: t.text('portalAppPasswords.door.scim'),
      ssf: t.text('portalAppPasswords.door.ssf'),
      est: t.text('portalAppPasswords.door.est')
    };
    return Object.prototype.hasOwnProperty.call(known, one.id)
      ? known[one.id] : String(one.what);
  }

  /**
   * Doors by their labels, escaped.
   *
   * @param doors - door ids
   * @param view - the view, for its labels
   * @returns the HTML
   */
  static doorList(doors: string[], view: Json): string {
    const labels = view.doorLabels || {};
    return (doors || []).map(function (door: string) {
      return kit.esc(labels[door] || door);
    }).join(', ');
  }

  /**
   * The password just made, shown once.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static freshCard(view: Json, t: Json): string {
    const fresh = view.fresh;
    // The warning sits in the `err` box for its colour; it is an
    // instruction, not a refusal, so it is translated.
    return '<div class="card"><h2>' +
      t.html('portalAppPasswords.fresh.heading') + '</h2>' +
      '<div class="err">' + t.html('portalAppPasswords.fresh.copyNow') +
      '</div><table><tr><th>' + t.html('portalAppPasswords.th.appPassword') +
      '</th><td><code class="app-password">' + kit.esc(fresh.password) +
      '</code></td></tr><tr><th>' + t.html('portalAppPasswords.th.name') +
      '</th><td>' + kit.esc(fresh.name) + '</td></tr><tr><th>' +
      t.html('portalAppPasswords.th.acceptedAt') + '</th><td>' +
      AppPasswordsPages.doorList(fresh.doors, view) + '</td></tr><tr><th>' +
      t.html('portalAppPasswords.th.username') + '</th><td><code>' +
      kit.esc(view.username) + '</code></td></tr></table>' +
      '<p class="note">' + t.html('portalAppPasswords.fresh.note') +
      '</p></div>';
  }

  // Which doors refuse this person's own password, said on the page that is
  // the answer to it.
  /**
   * The doors card.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static doorsCard(view: Json, t: Json): string {
    const doors = view.doors || { refused: [] };
    const rows = (view.doorTable || []).map(function (one: Json) {
      const refused = (doors.refused || []).indexOf(one.id) >= 0;
      return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
        kit.esc(AppPasswordsPages.doorWhat(one, t)) + '</td><td>' +
        (refused
          ? '<strong>' + t.html('portalAppPasswords.doors.onlyApp') +
            '</strong>'
          : t.html('portalAppPasswords.doors.either')) + '</td></tr>';
    }).join('');
    const lead = !doors.secondFactor
      ? t.html('portalAppPasswords.doors.leadNoFactor')
      : !doors.applies
        ? t.html('portalAppPasswords.doors.leadDevelopment')
        : t.html('portalAppPasswords.doors.leadRefused');
    return '<div class="card"><h2>' +
      t.html('portalAppPasswords.doors.heading') + '</h2>' +
      '<p class="sub">' + lead + '</p><table><tr><th>' +
      t.html('portalAppPasswords.th.door') + '</th><th>' +
      t.html('portalAppPasswords.th.whatSpeaks') + '</th><th>' +
      t.html('portalAppPasswords.th.whatAccepts') + '</th></tr>' + rows +
      '</table></div>';
  }

  /**
   * The passwords held, each with its Revoke.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static listCard(view: Json, t: Json): string {
    const heading = '<h2>' + t.html('portalAppPasswords.list.heading') +
      '</h2>';
    if (view.unreadable) {
      // An error, and so English (#539).
      return '<div class="card">' + heading + '<div ' +
        'class="err">The app passwords on your account cannot be read, so ' +
        'none of them is accepted. Ask an administrator to look at your ' +
        'entry.</div></div>';
    }
    const held: Json[] = view.passwords || [];
    if (!held.length) {
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalAppPasswords.list.none') + '</p></div>';
    }
    const rows = held.map(function (one: Json) {
      return '<tr><td>' + kit.esc(one.name) + '</td><td><code>' +
        kit.esc(one.id) + '</code></td><td>' +
        AppPasswordsPages.doorList(one.doors, view) + '</td><td>' +
        kit.esc(AppPasswordsPages.readable(one.createdAt, t)) + '</td><td>' +
        kit.esc(AppPasswordsPages.readable(one.lastUsedAt, t)) +
        (one.lastUsedAt && one.lastUsedDoor
          ? ' (' + AppPasswordsPages.doorList([one.lastUsedDoor], view) + ')'
          : '') +
        '</td><td><form method="post" action="' + PATH + '">' +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="id" value="' + kit.esc(one.id) + '">' +
        '<button class="danger" type="submit">' +
        t.html('portalAppPasswords.list.revoke') + '</button></form>' +
        '</td></tr>';
    }).join('');
    return '<div class="card">' + heading +
      '<table><tr><th>' + t.html('portalAppPasswords.th.name') + '</th><th>' +
      t.html('portalAppPasswords.th.id') + '</th><th>' +
      t.html('portalAppPasswords.th.acceptedAt') + '</th><th>' +
      t.html('portalAppPasswords.th.made') + '</th><th>' +
      t.html('portalAppPasswords.th.lastUsed') + '</th><th></th></tr>' +
      rows + '</table><p class="note">' +
      t.html('portalAppPasswords.list.note') + '</p></div>';
  }

  /**
   * The form that makes one.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static createCard(view: Json, t: Json): string {
    const heading = '<h2>' + t.html('portalAppPasswords.create.heading') +
      '</h2>';
    if (!view.enabled) {
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalAppPasswords.create.off') + '</p></div>';
    }
    const boxes = (view.doorTable || []).map(function (one: Json) {
      return '<label><input type="checkbox" name="door_' + kit.esc(one.id) +
        '" value="on"> ' + kit.esc(one.label) + '</label> ';
    }).join('');
    return '<div class="card">' + heading +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="create">' +
      '<p><label>' + t.html('portalAppPasswords.th.name') +
      ' <input type="text" name="name" maxlength="' +
      kit.esc(String(view.maxName)) + '" required placeholder="' +
      kit.esc(t.text('portalAppPasswords.create.namePlaceholder')) +
      '"></label></p><fieldset><legend>' +
      t.html('portalAppPasswords.th.acceptedAt') + '</legend>' + boxes +
      '</fieldset><p><button type="submit">' +
      t.html('portalAppPasswords.create.button') + '</button></p></form>' +
      '<p class="note">' + t.html('portalAppPasswords.create.note') +
      '</p></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/app-passwords`' answer, or an act's
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    return (view.fresh ? AppPasswordsPages.freshCard(view, t) : '') +
      AppPasswordsPages.doorsCard(view, t) +
      AppPasswordsPages.listCard(view, t) +
      AppPasswordsPages.createCard(view, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/app-passwords',
      render: AppPasswordsPages.render }
  ];
}

export = AppPasswordsPages;
