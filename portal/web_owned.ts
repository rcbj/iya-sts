// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_owned.ts
//
// ---------------------------------------------------------------------------
// RESOURCES I OWN (#604), DRAWN IN THE BROWSER, from `GET
// /account-api/owned/<kind>` (`portal_owned.ts`): the roles, groups, service
// accounts and applications whose owner values name the person or a group
// they are in, one page each, with how each is theirs.
//
// AND ONE OF THEM, ADMINISTERED (#607). `?name=` on a kind's page draws that
// object from the MANAGEMENT API with the portal's owner token — the page's
// `admin()` — and its forms post there (`data-admin`), so a change is the
// operation the console's own control sends, decided by the access-control
// policy's owner rule. Nothing here decides who may: a control drawn for a
// change the rule refuses is refused, and the refusal is drawn. Without
// owner:write (a read-only token) the page draws no form at all.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const KINDS = ['roles', 'groups', 'service-accounts', 'applications'];

// Where each kind's object is read on the management API, by the query
// parameter its operation takes (`mgmt-api/admin_api.ts`, OWNER_OPERATIONS).
const READS: Record<string, string> = {
  'roles': '/admin-api/roles?role=',
  'groups': '/admin-api/groups?group=',
  'service-accounts': '/admin-api/service-accounts?account=',
  'applications': '/admin-api/applications?application='
};

// The application attributes an owner's page offers, single or one a line:
// the access-control template's default `ownerApplicationAttributes`.
const APPLICATION_FIELDS: { name: string; lines: boolean }[] = [
  { name: 'appName', lines: false },
  { name: 'appHomePageUrl', lines: false },
  { name: 'appCorsOrigin', lines: true },
  { name: 'oauthRedirectUri', lines: true },
  { name: 'oauthPostLogoutRedirectUri', lines: true },
  { name: 'oauthFrontchannelLogoutUri', lines: false },
  { name: 'oauthBackchannelLogoutUri', lines: false },
  { name: 'samlAssertionConsumerService', lines: true },
  { name: 'samlSingleLogoutService', lines: true }
];

/**
 * `/portal/owned/*`. A static utility class.
 */
class OwnedPages {
  /**
   * A page's body: the list, or one object where the query names it.
   *
   * @param view - `GET /account-api/owned/<kind>`'s answer, or
   *   `{ owned }` for one object (#607)
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    if (view && view.owned) {
      return OwnedPages.renderOne(view.owned, ctx);
    }
    const t = ctx.t;
    const kind = KINDS.indexOf(view.kind) >= 0 ? view.kind : 'roles';
    const rows: Json[] = view.rows || [];
    const path = kit.BASE + '/owned/' + kind;
    const how = function (via: Json): string {
      const parts: string[] = [];
      if (via && via.you) {
        parts.push(t.html('portalOwned.you'));
      }
      ((via && via.groups) || []).forEach(function (cn: string) {
        parts.push(t.html('portalOwned.viaGroup', { group: cn }));
      });
      return parts.join('<br>');
    };
    // EACH ROW'S NAME OPENS ITS PAGE (#607), unless the object is closed to
    // its owners, which the row says instead.
    const name = function (row: Json): string {
      const label = '<strong>' + kit.esc(row.name) + '</strong>';
      if (row.closed || !row.id) {
        return label + '<br><small>' + t.html('portalOwned.closed') +
          '</small>';
      }
      return '<a href="' + kit.esc(path + kit.queryOf({ name: row.id })) +
        '">' + label + '</a>';
    };
    const body = rows.length
      ? '<table><tr><th>' + t.html('portalOwned.thName') + '</th><th>' +
        t.html('portalOwned.thDetail') + '</th><th>' +
        t.html('portalOwned.thHow') + '</th></tr>' +
        rows.map(function (row: Json): string {
          return '<tr><td>' + name(row) +
            (row.dn ? '<br><small><code>' + kit.esc(row.dn) +
                      '</code></small>' : '') + '</td><td>' +
            kit.esc(row.detail || '') + '</td><td>' + how(row.via) +
            '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalOwned.none', { kind: kind }) +
        '</p>';
    return '<div class="card"><h2>' + t.html('portalOwned.heading',
      { kind: kind }) + '</h2><p class="sub">' +
      t.html('portalOwned.sub') + '</p>' + body +
      // ALWAYS DRAWN (rcbj, 2026-10-13), one page or many, so each of the
      // four pages says where in the list it is.
      kit.pageNav(path, ctx.query, view.paging, 'page', t, true) + '</div>';
  }

  // --- one object (#607) ---------------------------------------------------

  /**
   * A form to one management API operation: `data-admin` is where the
   * runtime sends it, with the owner token.
   *
   * @param op - `/admin-api/<kind>/<action>`
   * @param hidden - the fields that name the object
   * @param inner - the visible fields, and a `<button>`
   * @param danger - whether the button is drawn as a destructive one
   * @returns the HTML
   */
  static form(op: string, hidden: Json, inner: string,
              danger?: boolean): string {
    return '<form method="post" data-admin="' + kit.esc(op) + '">' +
      Object.keys(hidden).map(function (name: string) {
        return '<input type="hidden" name="' + kit.esc(name) + '" value="' +
          kit.esc(hidden[name]) + '">';
      }).join('') + inner.replace('<button>', '<button type="submit"' +
        (danger ? ' class="danger"' : '') + '>') + '</form>';
  }

  /**
   * One labelled text box, or a box of lines.
   *
   * @param label - the label's HTML
   * @param name - the field's name
   * @param value - its value; an array is one value a line
   * @param lines - whether it is a box of lines
   * @returns the HTML
   */
  static field(label: string, name: string, value: unknown,
               lines?: boolean): string {
    const text = Array.isArray(value) ? value.join('\n')
                                      : String(value == null ? '' : value);
    return '<p><label>' + label + '<br>' + (lines
      ? '<textarea name="' + kit.esc(name) + '" rows="3" cols="60">' +
        kit.esc(text) + '</textarea>'
      : '<input type="text" name="' + kit.esc(name) + '" size="60" ' +
        'value="' + kit.esc(text) + '">') + '</label></p>';
  }

  /**
   * The owners card, the same on every kind: each owner with a Remove while
   * there are two or more — the last cannot go here (rcbj's decision 3) —
   * and an Add.
   *
   * @param owners - `[{ dn, kind, name }]`
   * @param ops - `{ add, remove }`, the two operations
   * @param hidden - the fields that name the object
   * @param write - whether the token carries owner:write
   * @param t - the translator
   * @returns the HTML
   */
  static ownersCard(owners: Json[], ops: Json, hidden: Json, write: boolean,
                    t: Json): string {
    const list: Json[] = owners || [];
    const rows = list.map(function (one: Json): string {
      return '<tr><td>' + kit.esc(one.name || one.dn) + '</td><td><code>' +
        kit.esc(one.dn) + '</code></td><td>' + kit.esc(one.kind || '') +
        '</td><td>' + (write && list.length > 1
          ? OwnedPages.form(ops.remove, Object.assign({}, hidden,
              { owner: one.dn }),
              '<button>' + t.html('portalOwned.edit.remove') + '</button>',
              true)
          : '') + '</td></tr>';
    }).join('');
    return '<div class="card"><h2>' +
      t.html('portalOwned.edit.owners.heading') + '</h2>' +
      (rows ? '<table><tr><th>' + t.html('portalOwned.thName') +
              '</th><th>' + t.html('portalOwned.edit.th.entry') +
              '</th><th>' + t.html('portalOwned.edit.th.kind') +
              '</th><th></th></tr>' + rows + '</table>'
            : '<p class="sub">' + t.html('portalOwned.edit.owners.none') +
              '</p>') +
      (write
        ? '<p class="note">' + t.html('portalOwned.edit.owners.last') +
          '</p>' + OwnedPages.form(ops.add, hidden,
            OwnedPages.field(t.html('portalOwned.edit.owners.value'),
                             'owner', '') +
            '<button>' + t.html('portalOwned.edit.owners.add') +
            '</button>')
        : '') + '</div>';
  }

  /**
   * A role's cards, from `GET /admin-api/roles?role=`'s `{ role }`.
   *
   * @param answer - the answer
   * @param write - whether the token carries owner:write
   * @param t - the translator
   * @returns the HTML
   */
  static roleCards(answer: Json, write: boolean, t: Json): string {
    const role = answer.role || {};
    const hidden = { role: role.name };
    const about = '<div class="card"><h2>' +
      t.html('portalOwned.edit.about.heading') + '</h2>' + (write
        ? OwnedPages.form('/admin-api/roles/describe-role', hidden,
            OwnedPages.field(t.html('portalOwned.edit.displayName'),
                             'displayName', role.displayName) +
            OwnedPages.field(t.html('portalOwned.edit.description'),
                             'description', role.description, true) +
            '<button>' + t.html('portalOwned.edit.save') + '</button>')
        : '<p>' + kit.esc(role.displayName || '') + '</p><p class="sub">' +
          kit.esc(role.description || '') + '</p>') + '</div>';
    const memberRows: string[] = [];
    [['user', role.users], ['group', role.groups],
     ['application', role.applications]].forEach(function (pair: Json) {
      (pair[1] || []).forEach(function (member: string) {
        memberRows.push('<tr><td>' + kit.esc(member) + '</td><td>' +
          t.html('portalOwned.edit.memberKind', { kind: pair[0] }) +
          '</td><td>' + (write
            ? OwnedPages.form('/admin-api/roles/remove-member',
                Object.assign({}, hidden, { kind: pair[0], member: member }),
                '<button>' + t.html('portalOwned.edit.remove') +
                '</button>', true)
            : '') + '</td></tr>');
      });
    });
    const members = '<div class="card"><h2>' +
      t.html('portalOwned.edit.members.heading') + '</h2>' +
      (memberRows.length
        ? '<table><tr><th>' + t.html('portalOwned.thName') + '</th><th>' +
          t.html('portalOwned.edit.th.kind') + '</th><th></th></tr>' +
          memberRows.join('') + '</table>'
        : '<p class="sub">' + t.html('portalOwned.edit.members.none') +
          '</p>') +
      (write
        ? OwnedPages.form('/admin-api/roles/add-member', hidden,
            '<p><label>' + t.html('portalOwned.edit.th.kind') +
            '<br><select name="kind">' +
            ['user', 'group', 'application'].map(function (kind: string) {
              return '<option value="' + kind + '">' +
                t.html('portalOwned.edit.memberKind', { kind: kind }) +
                '</option>';
            }).join('') + '</select></label></p>' +
            OwnedPages.field(t.html('portalOwned.edit.members.value'),
                             'member', '') +
            '<button>' + t.html('portalOwned.edit.members.add') +
            '</button>')
        : '') + '</div>';
    return about + members + OwnedPages.ownersCard(role.owners,
      { add: '/admin-api/roles/add-owner',
        remove: '/admin-api/roles/remove-owner' }, hidden, write, t);
  }

  /**
   * A group's cards, from `GET /admin-api/groups?group=`'s `{ group }`.
   *
   * @param answer - the answer
   * @param write - whether the token carries owner:write
   * @param query - the page's query, for the members' pager
   * @param t - the translator
   * @returns the HTML
   */
  static groupCards(answer: Json, write: boolean, query: Json,
                    t: Json): string {
    const group = answer.group || {};
    const hidden = { group: group.dn };
    const rows = (group.members || []).map(function (one: Json): string {
      return '<tr><td>' + kit.esc(one.displayName || one.cn || one.value) +
        '</td><td><code>' + kit.esc(one.dn || one.value) + '</code></td>' +
        '<td>' + (one.present ? '' : t.html('portalOwned.edit.dangling')) +
        '</td></tr>';
    }).join('');
    const paging = answer.membersPaging || null;
    const members = '<div class="card"><h2>' +
      t.html('portalOwned.edit.members.heading') + '</h2>' +
      (group.description ? '<p class="sub">' + kit.esc(group.description) +
                           '</p>' : '') +
      (rows ? '<table><tr><th>' + t.html('portalOwned.thName') +
              '</th><th>' + t.html('portalOwned.edit.th.entry') +
              '</th><th></th></tr>' + rows + '</table>'
            : '<p class="sub">' + t.html('portalOwned.edit.members.none') +
              '</p>') +
      (paging ? kit.pageNav(kit.BASE + '/owned/groups', query, paging,
                            paging.param || 'membersPage', t) : '') +
      (write
        ? OwnedPages.form('/admin-api/groups/add-member', hidden,
            OwnedPages.field(t.html('portalOwned.edit.members.value'),
                             'member', '') +
            '<button>' + t.html('portalOwned.edit.members.add') +
            '</button>')
        : '') + '</div>';
    return members + OwnedPages.ownersCard(group.owners,
      { add: '/admin-api/groups/add-owner',
        remove: '/admin-api/groups/remove-owner' }, hidden, write, t);
  }

  /**
   * A service account's cards, from `GET
   * /admin-api/service-accounts?account=`'s `{ account }`.
   *
   * @param answer - the answer
   * @param write - whether the token carries owner:write
   * @param t - the translator
   * @returns the HTML
   */
  static serviceAccountCards(answer: Json, write: boolean,
                             t: Json): string {
    const account = answer.account || {};
    const hidden = { user: account.username };
    const destination = '<div class="card"><h2>' +
      t.html('portalOwned.edit.destination.heading') + '</h2>' + (write
        ? OwnedPages.form('/admin-api/users/set-service-account-destination',
            hidden,
            OwnedPages.field(t.html('portalOwned.edit.destination.dn'),
                             'destination', account.destination) +
            OwnedPages.field(t.html('portalOwned.edit.destination.secret'),
                             'secretName', account.secretName) +
            '<button>' + t.html('portalOwned.edit.destination.save') +
            '</button>') +
          (account.destination
            ? '<p class="note">' + t.html('portalOwned.edit.rotate.note') +
              '</p>' + OwnedPages.form('/admin-api/users/rotate-password',
                hidden, '<button>' + t.html('portalOwned.edit.rotate') +
                '</button>')
            : '')
        : '<p><code>' + kit.esc(account.destination || '') + '</code> ' +
          kit.esc(account.secretName || '') + '</p>') + '</div>';
    return destination + OwnedPages.ownersCard(account.owners,
      { add: '/admin-api/users/add-service-account-owner',
        remove: '/admin-api/users/remove-service-account-owner' },
      hidden, write, t);
  }

  /**
   * An application's cards, from `GET
   * /admin-api/applications?application=`.
   *
   * @param answer - the answer
   * @param write - whether the token carries owner:write
   * @param t - the translator
   * @returns the HTML
   */
  static applicationCards(answer: Json, write: boolean, t: Json): string {
    const hidden = { application: answer.identifier };
    const fields = answer.fields || {};
    const settings = '<div class="card"><h2>' +
      t.html('portalOwned.edit.settings.heading') + '</h2>' + (write
        ? OwnedPages.form('/admin-api/applications/update-fields', hidden,
            APPLICATION_FIELDS.map(function (one) {
              return OwnedPages.field(
                t.html('portalOwned.edit.field', { name: one.name }),
                (one.lines ? 'lines.' : 'fields.') + one.name,
                fields[one.name], one.lines);
            }).join('') +
            '<button>' + t.html('portalOwned.edit.save') + '</button>')
        : '<table>' + APPLICATION_FIELDS.map(function (one) {
          return '<tr><th>' + t.html('portalOwned.edit.field',
            { name: one.name }) + '</th><td>' +
            kit.esc([].concat(fields[one.name] || []).join(', ')) +
            '</td></tr>';
        }).join('') + '</table>') + '</div>';
    const secret = write
      ? '<div class="card"><h2>' +
        t.html('portalOwned.edit.secret.heading') + '</h2><p class="note">' +
        t.html('portalOwned.edit.secret.note') + '</p>' +
        OwnedPages.form('/admin-api/applications/regenerate-secret', hidden,
          '<button>' + t.html('portalOwned.edit.secret.regenerate') +
          '</button>', true) + '</div>'
      : '';
    return settings + secret + OwnedPages.ownersCard(answer.owners,
      { add: '/admin-api/applications/add-owner',
        remove: '/admin-api/applications/remove-owner' }, hidden, write, t);
  }

  /**
   * One object a person owns, drawn from the management API (#607).
   *
   * @param owned - `{ status, answer, canWrite, query }`
   * @param ctx - the render context
   * @returns the HTML
   */
  static renderOne(owned: Json, ctx: Json): string {
    const t = ctx.t;
    const query = owned.query || {};
    const kind = OwnedPages.kindOfPath(ctx.here);
    const list = kit.BASE + '/owned/' + kind;
    const answer = owned.answer || {};
    const head = '<div class="card"><p><a href="' + kit.esc(list) + '">' +
      t.html('portalOwned.edit.back', { kind: kind }) + '</a></p><h2>' +
      t.html('portalOwned.edit.heading', { kind: kind }) + ' ' +
      kit.esc(query.name || '') + '</h2>';
    // A REFUSAL, DRAWN: the owner rule's sentence, or why there is no owner
    // token. In English, as every refusal is (#539).
    if (owned.status !== 200) {
      return head + '<div class="err">' +
        kit.esc((answer.errors || []).join(' ') ||
                'The management API answered ' + owned.status + '.') +
        '</div></div>';
    }
    const write = owned.canWrite === true;
    const intro = head + (write ? '' : '<p class="note">' +
      t.html('portalOwned.edit.readOnly') + '</p>') + '</div>';
    if (kind === 'roles') {
      return intro + OwnedPages.roleCards(answer, write, t);
    }
    if (kind === 'groups') {
      return intro + OwnedPages.groupCards(answer, write, query, t);
    }
    if (kind === 'service-accounts') {
      return intro + OwnedPages.serviceAccountCards(answer, write, t);
    }
    return intro + OwnedPages.applicationCards(answer, write, t);
  }

  /**
   * The kind a portal path is the page of.
   *
   * @param here - the path and query, under the realm
   * @returns one of the kinds; `roles` where none matches
   */
  static kindOfPath(here: unknown): string {
    const found = /\/portal\/owned\/([a-z-]+)/.exec(String(here || ''));
    return found && KINDS.indexOf(found[1]) >= 0 ? found[1] : 'roles';
  }

  /**
   * The pages, for `web_portal_pages.ts`: each kind's list, and with
   * `?name=` one of them, read from the management API (#607).
   */
  static readonly PAGES: PortalPage[] = KINDS.map(function (kind: string) {
    return { path: kit.BASE + '/owned/' + kind,
             operation: '/account-api/owned/' + kind,
             render: OwnedPages.render,
             admin: function (query: Json): string | null {
               const name = String((query && query.name) || '');
               if (!name) {
                 return null;
               }
               // The group's members' page rides along.
               const more = kind === 'groups' && query.membersPage
                 ? '&membersPage=' +
                   encodeURIComponent(String(query.membersPage)) : '';
               return READS[kind] + encodeURIComponent(name) + more;
             } };
  });
}

export = OwnedPages;
