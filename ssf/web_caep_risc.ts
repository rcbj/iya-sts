// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_caep_risc.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → CAEP AND RISC, AND THEIR MONITORING PAGES, DRAWN FROM THEIR
// VIEWS ALONE (#446, 2026-10-05).
//
// Draws CAEP from the answer of `GET /admin-api/caep` and RISC from that of
// `GET /admin-api/risc`, with the sessions and accounts each one's monitoring
// pages list.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/caep` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws CAEP from the answer of `GET /admin-api/caep` and RISC from that of
 * `GET /admin-api/risc`, with the sessions and accounts each one's monitoring
 * pages list.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CaepRiscPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static caepBody(ctx, json) {
    // THE LANGUAGE (#539): the reader's translator. Every word this page
    // writes is a message of `consoleCaepRisc`; what the view says (a
    // type's name and description, the settings) is drawn as it comes.
    const t = ctx.t;

    const catalogue = (json.catalogue || []).map(function (row) {
      const members = row.members.map(function (member) {
        return '<tr><td><code>' + kit.esc(member.name) + '</code></td>' +
          '<td class="' + (member.required ? '' : 'sub') + '">' +
          (member.required ? t.html('consoleCaepRisc.required')
                           : t.html('consoleCaepRisc.optional')) + '</td>' +
          '<td class="sub"><code>' + kit.esc(member.type) + '</code>' +
          (member.values.length
            ? ' ' + kit.esc(member.values.join(' | ')) : '') + '</td>' +
          '<td class="sub">' + kit.esc(member.what) + '</td></tr>';
      }).join('');
      return '<div class="card"><h3>' + kit.esc(row.name) + ' &mdash; ' +
        '<code>' +
        kit.esc(row.short) + '</code>' +
        (row.offered ? '' :
         ' <span class="state-invalid">' +
         t.html('consoleCaepRisc.notOffered') + '</span>') +
        '</h3><div class="sub">' + kit.esc(row.what) + '</div>' +
        '<table><tr><th>' + t.html('consoleCaepRisc.th.member') +
        '</th><th></th><th>' + t.html('consoleCaepRisc.th.type') +
        '</th><th>' + t.html('consoleCaepRisc.th.whatItIs') +
        '</th></tr>' + members + '</table></div>';
    }).join('');

    // WHICH SESSION THE FORM WILL EMIT ABOUT, and it comes off the query
    // string now rather than out of a `<select>`. See caepSessionChooser(). A
    // `?session=` naming a row that is gone — a stale link, a session revoked
    // since the reader searched — resolves to nothing and the form says so
    // rather than posting an identifier the register will not recognise.
    const here = { path: '/admin/caep', query: ctx.query };
    const wantedSession = kit.queryOne(here.query, 'session').trim();
    const liveSessions = (json.sessions || []).filter(function (row) {
      return String(row.state || '') !== 'revoked';
    });
    let picked = null;
    liveSessions.forEach(function (row) {
      if (String(row.sessionId || '') === wantedSession) {
        picked = row;
      }
    });
    const sessionChooser = CaepRiscPage.caepSessionChooser(here,
      json.sessions || [],
        picked ? picked.sessionId : '', t);

    const typeOptions = (json.catalogue || []).map(function (row) {
      return '<option value="' + kit.esc(row.short) + '">' +
             kit.esc(row.name) +
        '</option>';
    }).join('');

    // The `err` box stays English: an error is never translated (#539).
    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so CAEP has nothing to run on. CAEP is a ' +
          'VOCABULARY over SSF rather than a family of its own: its events ' +
          'travel on SSF streams, are signed by the SSF signer and are ' +
          'delivered by the two SSF deliveries.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleCaepRisc.caep.off'))
        : '') +

      // The link's words are a product's name and stay as they are; the
      // sentence is split around it, because a message carries no link.
      kit.note(t.html('consoleCaepRisc.caep.intro1') +
      '<a href="/admin/ssf">Shared Signals</a>' +
      t.html('consoleCaepRisc.caep.intro2')) +

      kit.warn(t.html('consoleCaepRisc.caep.autoWarn')) +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0,
               t.text('consoleCaepRisc.tile.sessionsTracked')) +
      kit.tile((json.eventTypes || []).length,
               t.text('consoleCaepRisc.tile.eventTypes')) +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), t.text('consoleCaepRisc.tile.eventsSent')) +
      kit.tile((json.autoEmitActs || []).length,
               t.text('consoleCaepRisc.tile.actsEmit')) +
      '</div>' +

      (json.installed
        ? '<h2>' + t.html('consoleCaepRisc.emitHeading') + '</h2>' +
          kit.note(t.html('consoleCaepRisc.caep.emitNote')) +
          sessionChooser +
          (picked
            ? '<p class="note">' +
              t.html('consoleCaepRisc.caep.emittingAbout', {
                who: String(picked.username || picked.sub ||
                            t.text('consoleCaepRisc.unnamed')),
                id: picked.sessionId,
                hasProtocol: picked.protocol ? 'yes' : 'no',
                protocol: picked.protocol }) + '</p>'
            : (wantedSession
                ? kit.warn(t.html('consoleCaepRisc.caep.noLive1',
                                  { id: wantedSession }) +
                  '<a href="/admin/caep-sessions">' +
                  t.html('consoleCaepRisc.caep.sessionsPageLink') + '</a>' +
                  t.html('consoleCaepRisc.caep.noLive2'))
                : kit.note(t.html('consoleCaepRisc.caep.pickNote')))) +
          (picked
            ? '<form method="post" action="/admin/caep"><div ' +
          'class="formrow"><input type="hidden" name="action" value="emit">' +
          '<input type="hidden" name="session_id" value="' +
          kit.esc(picked.sessionId) + '">' +
          '<label>' + t.html('consoleCaepRisc.form.event') +
          ' <select name="type">' + typeOptions +
          '</select></label> ' +
          '<label>' + t.html('consoleCaepRisc.form.initiatedBy') +
          ' <select name="initiating_entity">' +
          '<option value="admin">admin</option>' +
          '<option value="user">user</option>' +
          '<option value="policy">policy</option>' +
          '<option value="system">system</option></select></label>' +
          '</div><div class="formrow">' +
          '<label>' + t.html('consoleCaepRisc.form.payload') + ' ' +
          '<input type="text" name="payload" size="60" ' +
          'placeholder="{&quot;current_status&quot;:' +
          '&quot;not-compliant&quot;}">' +
          '</label>' +
          '</div><div class="formrow">' +
          '<label>reason_admin <input type="text" name="reason_admin" ' +
          'size="40"></label> ' +
          '<label>reason_user <input type="text" name="reason_user" ' +
          'size="40"></label>' +
          '</div><div class="formrow"><button>' +
          t.html('consoleCaepRisc.form.emit') + '</button></div></form>'
            : '') +
          (liveSessions.length
            ? ''
            : kit.warn(t.html('consoleCaepRisc.caep.noLiveSessions')))
        : '') +

      // THE CATALOGUE IS FOLDED AND STARTS CLOSED, which is the one place on
      // this console where a section rather than a paragraph is behind a
      // disclosure. Eight cards, each with a table of the event's own
      // members, is five screens of REFERENCE sitting between the settings
      // above it and the links below — so the controls somebody came for were
      // off the bottom of the page on every visit, and the reference they
      // were scrolling past is the half nobody needs twice. Closed by default
      // rather than open: a reader who wants the members knows they want
      // them, and the summary says how many are there. Native <details>, so
      // `script-src 'none'` is untouched — the same answer kit.note() gives,
      // one
      // level up.
      (json.installed
        ? '<details class="fold section"><summary>' +
          t.html('consoleCaepRisc.caep.eightTypes') +
          '</summary><div class="foldbody">' +
          kit.note(t.html('consoleCaepRisc.caep.catalogueNote')) +
          catalogue +
          '</div></details>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/caep', undefined, t) +

      kit.note('<a href="/admin/caep-sessions">' +
      t.html('consoleCaepRisc.links.caepSessions') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streamsOut') +
      '</a> &middot; ' +
      '<a href="/admin/caep?format=json">' +
      t.html('consoleCaepRisc.links.asJson') + '</a> &middot; ' +
      '<a href="/admin-api/caep">' + t.html('consoleCaepRisc.links.overApi') +
      '</a>');

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE CAEP SESSION CHOOSER — search by PERSON, pick one of their live
  // sessions.
  //
  // **IT WAS A `<select name="session_id">` UNTIL 2026-09-03**, and the
  // argument for replacing it is kit.chooserPane()'s own, one register further
  // on:
  // a control on this page must be the same size whatever is behind it, and
  // this register grows BY ONE ROW PER SIGN-IN for the life of the process and
  // never shrinks — `caep.ts` keeps a row after the session has been signed
  // out, deliberately, because the row is the evidence that it existed and was
  // revoked. So a console left running for an afternoon of testing had a
  // dropdown of several hundred options, sorted by nothing a reader knows, each
  // labelled with a 24-character random identifier.
  //
  // **THE SEARCH IS OVER THE PERSON AND THE RESULTS ARE SESSIONS**, which is
  // the asymmetry worth stating because it is what makes the control useful.
  // Nobody knows a session identifier by heart — it is random and it is the
  // thing they came here to find — but everybody knows who they signed in as.
  // So `names` holds the username and the subject, and the LABEL holds the
  // session, with the protocol that minted it and the state beside it.
  //
  // **ONLY LIVE SESSIONS ARE OFFERED, and that is a deliberate narrowing.** A
  // revoked row stays in the register and stays on /admin/caep-sessions, where
  // it is evidence; it is not offered HERE because this form emits an event
  // ABOUT a session, and the model's one hard refusal is a `session-presented`
  // about a session already revoked. Offering rows that the very next click
  // would be refused for is a control that invites a mistake. The note under
  // the pane says so and points at the page that still lists them.
  //
  // Paging is CHOOSER_HITS — the same twenty every other chooser here uses, and
  // the same clamping of a stale offset, because it is the same function.
  // ---------------------------------------------------------------------------
  /**
   * Draws the CAEP page's session chooser: a search by person over the
   * sessions still live, each result linking to /admin/caep with it chosen.
   *
   * Revoked sessions are left out, since an event about one is refused.
   *
   * @param here - the page this is drawn on, as path and query
   * @param sessions - the CAEP session register's rows
   * @param selectedId - the session already chosen, marked in the pane
   * @param t - the page's translator (#539)
   * @returns the chooser as HTML
   */
  static caepSessionChooser(here, sessions, selectedId, t) {
    const query = (here && here.query) || {};
    const carry = kit.pageParamsOf(query);
    delete carry.session;
    const live = (sessions || []).filter(function (row) {
      return String(row.state || '') !== 'revoked';
    });
    const entries = live.map(function (row) {
      const who = String(row.username || row.sub ||
                         t.text('consoleCaepRisc.unnamed'));
      const id = String(row.sessionId || '');
      return {
        key: id,
        // SEARCHED BY PERSON. The session identifier is in here too so that a
        // reader who has one — from a log, from an event they are chasing — can
        // paste it, which is the other half of how this control gets used.
        names: [who, String(row.sub || ''), id],
        label: who + ' — ' + id,
        detail: (row.protocol ? row.protocol + ', ' : '') +
          String(row.state || 'established') + ', ' +
          (row.total
            ? t.text('consoleCaepRisc.chooser.eventsSent', { n: row.total })
            : t.text('consoleCaepRisc.chooser.nothingSent')),
        href: '/admin/caep' + kit.queryWith(carry, { session: id }) +
          '#find-sessq'
      };
    });
    // The pane escapes all three of its words, `nothing` included — so the
    // link in it has always been drawn as text, and still is.
    return kit.chooserPane({
      here: here, param: 'sessq', fromParam: 'sessfrom',
      label: t.text('consoleCaepRisc.chooser.findPerson'),
      placeholder: t.text('consoleCaepRisc.chooser.sessionPlaceholder'),
      entries: entries, selectedKey: selectedId,
      nothing: t.text('consoleCaepRisc.chooser.noLiveMatch1') +
        '<a href="/admin/caep-sessions">' +
        t.text('consoleCaepRisc.caep.sessionsPageLink') + '</a>' +
        t.text('consoleCaepRisc.chooser.noLiveMatch2')
    }, t);
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static riscBody(ctx, json) {
    // THE LANGUAGE (#539), as on the CAEP page.
    const t = ctx.t;

    const catalogue = (json.catalogue || []).map(function (row) {
      const members = row.members.map(function (member) {
        return '<tr><td><code>' + kit.esc(member.name) + '</code></td>' +
          '<td class="' + (member.required ? '' : 'sub') + '">' +
          (member.required ? t.html('consoleCaepRisc.required')
                           : t.html('consoleCaepRisc.optional')) + '</td>' +
          '<td class="sub"><code>' + kit.esc(member.type) + '</code>' +
          (member.values.length
            ? ' ' + kit.esc(member.values.join(' | ')) : '') + '</td>' +
          '<td class="sub">' + kit.esc(member.what) + '</td></tr>';
      }).join('');
      return '<div class="card"><h3>' + kit.esc(row.name) + ' &mdash; ' +
        '<code>' +
        kit.esc(row.short) + '</code>' +
        (row.offered ? '' :
         ' <span class="state-invalid">' +
         t.html('consoleCaepRisc.notOffered') + '</span>') +
        (row.deprecated
          ? ' <span class="state-invalid">' +
            t.html('consoleCaepRisc.deprecated') + '</span>' : '') +
        '</h3><div class="sub">' + kit.esc(row.what) + '</div>' +
        // The formats are joined with markup and then escaped, as they
        // always were: the parameter is escaped exactly as kit.esc() did.
        ((row.subjectFormats || []).length
          ? '<div class="sub">' + t.html('consoleCaepRisc.risc.subjectMust',
            { formats: row.subjectFormats.join('</code> or <code>') }) +
            '</div>'
          : '') +
        (members
          ? '<table><tr><th>' + t.html('consoleCaepRisc.th.member') +
            '</th><th></th><th>' + t.html('consoleCaepRisc.th.type') +
            '</th>' +
            '<th>' + t.html('consoleCaepRisc.th.whatItIs') + '</th></tr>' +
            members + '</table>'
          : '<div class="sub">' + t.html('consoleCaepRisc.risc.noMembers') +
            '</div>') +
        '</div>';
    }).join('');

    // WHICH ACCOUNT THE FORM WILL EMIT ABOUT. Off the query string, like the
    // CAEP page's session — see riscAccountChooser(), and note the one place
    // this page is deliberately more permissive than that one.
    const here = { path: '/admin/risc', query: ctx.query };
    const wantedAccount = kit.queryOne(here.query, 'acctq2').trim();
    let picked = null;
    (json.accounts || []).forEach(function (row) {
      if (String(row.accountId || '') === wantedAccount) {
        picked = row;
      }
    });
    const accountChooser = CaepRiscPage.riscAccountChooser(here,
      json.accounts || [],
        picked ? picked.accountId : '', t);

    const typeOptions = (json.catalogue || []).map(function (row) {
      return '<option value="' + kit.esc(row.short) + '">' +
             kit.esc(row.name) +
        (row.deprecated
          ? ' (' + t.html('consoleCaepRisc.deprecated') + ')' : '') +
        '</option>';
    }).join('');

    // The `err` box stays English: an error is never translated (#539).
    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so RISC has nothing to run on. RISC is a ' +
          'VOCABULARY over SSF rather than a family of its own: its events ' +
          'travel on SSF streams, are signed by the SSF signer and are ' +
          'delivered by the two SSF deliveries.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleCaepRisc.risc.off'))
        : '') +

      // Split around the two links; their words are names and stay.
      kit.note(t.html('consoleCaepRisc.risc.intro1') +
      '<a href="/admin/ssf">Shared Signals</a>' +
      t.html('consoleCaepRisc.risc.intro2') +
      '<a href="/admin/caep">CAEP</a>' +
      t.html('consoleCaepRisc.risc.intro3')) +

      kit.warn(t.html('consoleCaepRisc.risc.subjectIsMessage')) +

      kit.warn(t.html('consoleCaepRisc.risc.directory1') +
      '<a href="/admin/scim">SCIM</a>' +
      t.html('consoleCaepRisc.risc.directory2') + '<a ' +
      'href="/admin/ldap">LDAP</a>' +
      t.html('consoleCaepRisc.risc.directory3')) +

      kit.note(t.html('consoleCaepRisc.risc.activeNote')) +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0,
               t.text('consoleCaepRisc.tile.accountsTracked')) +
      kit.tile((json.eventTypes || []).length,
               t.text('consoleCaepRisc.tile.eventTypes')) +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), t.text('consoleCaepRisc.tile.eventsSent')) +
      kit.tile((json.autoEmitActs || []).length,
               t.text('consoleCaepRisc.tile.actsEmit')) +
      '</div>' +

      (json.installed && json.googleSubjectType
        ? kit.warn(t.html('consoleCaepRisc.risc.googleWarn'))
        : '') +

      (json.installed
        ? '<h2>' + t.html('consoleCaepRisc.emitHeading') + '</h2>' +
          kit.note(t.html('consoleCaepRisc.risc.emitNote')) +
          accountChooser +
          (picked
            ? '<p class="note">' +
              t.html('consoleCaepRisc.risc.emittingAbout', {
                who: String(picked.username || picked.accountId),
                subject: picked.subject || '',
                lifecycle: picked.lifecycle,
                optOut: picked.optOut }) + '</p>'
            : kit.note(t.html('consoleCaepRisc.risc.pickNote'))) +
          '<form method="post" action="/admin/risc"><div class="formrow">' +
          '<input type="hidden" name="action" value="emit">' +
          '<label>' + t.html('consoleCaepRisc.form.account') +
          ' <input type="text" name="account_id" size="24" ' +
          'value="' + kit.esc(picked ? picked.accountId : '') +
          '"></label> <label>' + t.html('consoleCaepRisc.form.event') +
          ' <select name="type">' + typeOptions +
          '</select></label>' +
          '</div><div class="formrow">' +
          '<label>' + t.html('consoleCaepRisc.form.payload') + ' ' +
          '<input type="text" name="payload" size="60" ' +
          'placeholder="{&quot;reason&quot;:&quot;hijacking&quot;}">' +
          '</label>' +
          '</div><div class="formrow">' +
          '<label>reason_admin <input type="text" name="reason_admin" ' +
          'size="40"></label> ' +
          '<label>reason_user <input type="text" name="reason_user" ' +
          'size="40"></label>' +
          '</div>' +
          kit.note(t.html('consoleCaepRisc.risc.reasonNote')) +
          '<div class="formrow"><button>' +
          t.html('consoleCaepRisc.form.emit') + '</button></div></form>'
        : '') +

      // Folded and closed by default, for the reason the CAEP catalogue is:
      // fourteen cards is seven screens of REFERENCE between the controls
      // above and the settings below.
      (json.installed
        ? '<details class="fold section"><summary>' +
          t.html('consoleCaepRisc.risc.fourteenTypes') +
          '</summary><div class="foldbody">' +
          kit.note(t.html('consoleCaepRisc.risc.catalogueNote')) +
          catalogue +
          '</div></details>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/risc', undefined, t) +

      kit.note('<a href="/admin/risc-accounts">' +
      t.html('consoleCaepRisc.links.riscAccounts') + '</a> &middot; ' +
      '<a href="/admin/caep">' +
      t.html('consoleCaepRisc.links.otherVocabulary') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streamsOut') +
      '</a> &middot; ' +
      '<a href="/admin/risc?format=json">' +
      t.html('consoleCaepRisc.links.asJson') + '</a> &middot; ' +
      '<a href="/admin-api/risc">' + t.html('consoleCaepRisc.links.overApi') +
      '</a>');

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE RISC ACCOUNT CHOOSER, and the one place it is deliberately more
  // permissive than the CAEP session chooser beside it.
  //
  // That control offers only LIVE sessions, because emitting about a revoked
  // one is the CAEP register's single hard refusal and a chooser that offered
  // rows the next click would refuse is a control inviting a mistake. **This
  // one offers every row, including purged accounts**, and the reason is what
  // the two events mean: a session that has ended cannot be presented, and an
  // account that has been purged can perfectly well have a credential of its
  // discovered in a breach corpus afterwards. Only `account-enabled` on a
  // purged account is refused, and that is one event type rather than a whole
  // row.
  //
  // **AND THE FORM ACCEPTS A NAME THAT IS IN NO ROW AT ALL**, which the CAEP
  // form does not. That is the specifications' difference and not an
  // inconsistency: a CAEP event names a SESSION, and a session identifier this
  // service never minted is one it can compose no subject from. A RISC event
  // names a PERSON, this service can name any person, and RISC is aimed ACROSS
  // providers — so the account a receiver is being warned about is usually one
  // it has never seen. This pane is therefore a convenience over the text field
  // below it rather than the only way in.
  //
  // The search reaches `formerIdentifiers` for the reason riscAccountsState()'s
  // does: the address a reader is holding is routinely the one the account no
  // longer has, because `identifier-changed` is an event about the key itself.
  // ---------------------------------------------------------------------------
  /**
   * Draws the RISC page's account chooser: a search over every tracked
   * account, purged ones and former identifiers included, each result
   * linking to /admin/risc with it chosen.
   *
   * @param here - the page this is drawn on, as path and query
   * @param accounts - the RISC account register's rows
   * @param selectedId - the account already chosen, marked in the pane
   * @param t - the page's translator (#539)
   * @returns the chooser as HTML
   */
  static riscAccountChooser(here, accounts, selectedId, t) {
    const query = (here && here.query) || {};
    const carry = kit.pageParamsOf(query);
    delete carry.acctq2;
    const entries = (accounts || []).map(function (row) {
      const who = String(row.username || row.accountId ||
                         t.text('consoleCaepRisc.unnamed'));
      const id = String(row.accountId || '');
      return {
        key: id,
        names: [who, id, String(row.sub || ''), String(row.email || '')]
          .concat(row.formerIdentifiers || []),
        label: who + (row.email && row.email !== who ? ' — ' + row.email : ''),
        detail: String(row.lifecycle || 'active') + ', ' +
          String(row.optOut || 'opt-in') + ', ' +
          (row.total
            ? t.text('consoleCaepRisc.chooser.eventsSent', { n: row.total })
            : t.text('consoleCaepRisc.chooser.nothingSent')) +
          (row.suppressed
            ? ', ' + t.text('consoleCaepRisc.chooser.suppressed',
                            { n: row.suppressed })
            : ''),
        href: '/admin/risc' + kit.queryWith(carry, { acctq2: id }) +
          '#find-acctq2'
      };
    });
    return kit.chooserPane({
      here: here, param: 'acctq2', fromParam: 'acctfrom',
      label: t.text('consoleCaepRisc.chooser.findAccount'),
      placeholder: t.text('consoleCaepRisc.chooser.accountPlaceholder'),
      entries: entries, selectedKey: selectedId,
      nothing: t.text('consoleCaepRisc.chooser.noAccountMatch')
    }, t);
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static caepSessionsBody(ctx, json) {
    const t = ctx.t;
    const shorts = CaepRiscPage.caepShortNames(json);
    const prefix = 'https://schemas.openid.net/secevent/caep/event-type/';

    const headers = shorts.map(function (short) {
      return '<th title="' + kit.esc(prefix + short) + '">' +
        kit.esc(short.replace('session-', '').replace('-change', '')) +
        '</th>';
    }).join('');

    // ---------------------------------------------------------------------
    // THE SEARCH AND THE PAGING OVER THE SESSIONS TABLE (2026-09-04).
    //
    // This list is unbounded up to `caep.maxSessionsTracked`, which is 200 by
    // default and settable to anything — one row per session this service has
    // held, including every session it has since forgotten — so the page grew
    // by one row per sign-in for the life of the process and the streams
    // table under it went out of reach. It is `sectionSearchForm` +
    // `pagedRows` + `pageNavPair`, the arrangement every other list in this
    // console has, and the parameters are NAMED after the list for
    // pagingOf()'s reason: this page carries a second table and a bare `page`
    // could not serve both.
    //
    // THE SEARCH IS OVER WHO AND WHICH, because those are the two things a
    // reader arrives holding — a username somebody complained about, or a
    // session identifier out of a log — and they do not know which column it
    // will be in. The subject spelling is matched too, since that is what a
    // receiver saw and is therefore what a reader comparing a Security Event
    // Token against this page has in front of them.
    //
    // Filter first, then page — pagingOf()'s rule, for its reason: paging a
    // list and then filtering it gives a page 2 whose length depends on what
    // page 1 happened to hold.
    const sessWanted = json.filter.sessions || '';
    const sessPage = { shown: json.shown.sessions,
                       paging: json.paging.sessions };
    const appState = { wanted: json.filter.applications || '',
                       matched: { length: json.matched.applications },
                       page: { shown: json.shown.applications,
                               paging: json.paging.applications } };
    const appNav = kit.pageNavPair('/admin/caep-sessions',
                                    kit.pageParamsOf(ctx.query),
                                    appState.page.paging, t);
    // EVERY parameter the reader is already carrying, so that paging this
    // table moves nothing else on the page. kit.pageNavPair() overrides only
    // the
    // one name off the paging object it is handed.
    const navParams = kit.pageParamsOf(ctx.query);
    const sessNav = kit.pageNavPair('/admin/caep-sessions', navParams,
                                     sessPage.paging, t);
    // The list AS THE READER LEFT IT, for the drill-down links and for the
    // Reset buttons' `back` field. kit.listViewOf() is the whitelist; `back` is
    // the same set as a query string, rebuilt from it rather than echoed.
    const listView = kit.listViewOf('/admin/caep-sessions', ctx.query);
    const back = kit.queryWith(listView, {});

    const rows = sessPage.shown.length
      ? sessPage.shown.map(function (row) {
          return CaepRiscPage.caepSessionRow(row, shorts, prefix, listView,
            back, t);
        }).join('')
      : '<tr><td colspan="' + (shorts.length + 8) + '">' +
        (sessWanted
          ? t.html('consoleCaepRisc.sessions.noMatch',
                   { wanted: sessWanted }) + ' ' +
            ((json.sessions || []).length
              ? t.html('consoleCaepRisc.sessions.otherNames',
                       { n: (json.sessions || []).length })
              : t.html('consoleCaepRisc.noneTracked'))
          : t.html('consoleCaepRisc.sessions.none')) +
        '</td></tr>';

    const streamRows = (json.streams || []).length
      ? json.streams.map(function (row) {
          return '<tr><td><code>' + kit.esc(row.stream_id) + '</code></td>' +
            '<td class="sub">' + kit.esc(row.aud) + '</td><td class="' +
            (row.status === 'enabled' ? 'state-valid' : 'sub') +
            '">' + kit.esc(row.status) + '</td>' +
            '<td class="sub">' + kit.esc(row.delivery) + '</td>' +
            '<td class="sub">' + kit.esc(String(row.subjects)) + '</td>' +
            '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
            kit.esc(row.takes.length ? row.takes.join(', ')
              : t.text('consoleCaepRisc.caep.noneOfEight')) + '</td></tr>';
        }).join('')
      : '<tr><td colspan="6">' + t.html('consoleCaepRisc.sessions.noStreams') +
        '</td></tr>';

    // The `err` box stays English: an error is never translated (#539).
    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so no session state is tracked.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleCaepRisc.sessions.caepOff'))
        : '') +
      (json.installed && json.enabled && !json.autoEmit
        ? kit.warn(t.html('consoleCaepRisc.sessions.autoOff1') +
          '<a href="/admin/caep">' +
          t.html('consoleCaepRisc.sessions.caepPageLink') + '</a>' +
          t.html('consoleCaepRisc.sessions.autoOff2'))
        : '') +

      kit.note(t.html('consoleCaepRisc.sessions.intro1') + '<a ' +
      'href="/admin/caep-sessions/session">' +
      t.html('consoleCaepRisc.sessions.introLink') + '</a>' +
      t.html('consoleCaepRisc.sessions.intro2')) +

      (json.installed && json.omitEventTimestamp
        ? kit.warn(t.html('consoleCaepRisc.sessions.omitWarn'))
        : '') +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, t.text('consoleCaepRisc.tile.sessions')) +
      kit.tile((json.sessions || []).filter(function (row) {
        return row.state === 'revoked';
      }).length, t.text('consoleCaepRisc.tile.revoked')) +
      kit.tile((json.sessions || []).filter(function (row) {
        return row.state === 'presented';
      }).length, t.text('consoleCaepRisc.tile.presented')) +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), t.text('consoleCaepRisc.tile.eventsSent')) +
      kit.tile((json.streams || []).filter(function (row) {
        return row.takes.length;
      }).length, t.text('consoleCaepRisc.tile.streamsCaep')) +
      '</div>' +

      '<h2>' + t.html('consoleCaepRisc.sessions.heading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.sessions.drillNote')) +
      kit.sectionSearchForm({
        path: '/admin/caep-sessions', query: ctx.query,
        param: 'sessq', pageParam: 'sessionsPage',
        label: t.text('consoleCaepRisc.sessions.searchLabel'),
        placeholder: t.text('consoleCaepRisc.sessions.searchPlaceholder'),
        what: t.html('consoleCaepRisc.sessions.searchWhat')
      }, t) +
      kit.perPageForm('/admin/caep-sessions', 'sessq', sessWanted,
                       sessPage.paging.perPage,
                       t.html('consoleCaepRisc.sessions.perPage'),
                       {}, t) +
      sessNav.head +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.session') + '</th><th>' +
      t.html('consoleCaepRisc.th.who') + '</th><th>' +
      t.html('consoleCaepRisc.th.state') + '</th>' +
      '<th>' + t.html('consoleCaepRisc.th.assurance') + '</th><th>' +
      t.html('consoleCaepRisc.th.device') + '</th><th>' +
      t.html('consoleCaepRisc.th.risk') + '</th>' + headers +
      '<th>' + t.html('consoleCaepRisc.th.total') + '</th><th></th></tr>' +
      rows + '</table>' +
      sessNav.foot +

      '<h2>' + t.html('consoleCaepRisc.sessions.whereHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.sessions.zeroNote')) +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.stream') +
      '</th><th>aud</th><th>' + t.html('consoleCaepRisc.th.status') +
      '</th><th>' + t.html('consoleCaepRisc.th.delivery') +
      '</th>' +
      '<th>' + t.html('consoleCaepRisc.th.subjects') + '</th><th>' +
      t.html('consoleCaepRisc.th.caepTypes') + '</th></tr>' + streamRows +
      '</table>' +

      '<h2>' + t.html('consoleCaepRisc.perAppHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.sessions.perApp1')) +
      kit.note(t.html('consoleCaepRisc.sessions.perApp2')) +
      kit.note(t.html('consoleCaepRisc.sessions.perApp3')) +
      kit.sectionSearchForm({
        path: '/admin/caep-sessions', query: ctx.query,
        param: 'appq', pageParam: 'applicationsPage',
        label: t.text('consoleCaepRisc.receiverLabel'),
        placeholder: t.text('consoleCaepRisc.receiverPlaceholder'),
        what: t.html('consoleCaepRisc.sessions.receiverWhat')
      }, t) +
      appNav.head +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.receiver') +
      '</th><th>' + t.html('consoleCaepRisc.th.streams') +
      '</th><th>aud</th><th>' + t.html('consoleCaepRisc.th.takes') +
      '</th>' +
      headers + '<th>' + t.html('consoleCaepRisc.th.total') + '</th><th>' +
      t.html('consoleCaepRisc.th.sessions') + '</th><th>' +
      t.html('consoleCaepRisc.th.deliveredFailed') + '</th>' +
      '</tr>' +
      (appState.page.shown.length
        ? appState.page.shown.map(function (row) {
            return CaepRiscPage.caepApplicationRow(row, shorts, prefix, t);
          }).join('')
        : '<tr><td colspan="' + (shorts.length + 7) + '">' +
          (appState.wanted
            ? t.html('consoleCaepRisc.apps.noMatch',
                     { wanted: appState.wanted }) + ' ' +
              ((json.applications || []).length
                ? t.html('consoleCaepRisc.apps.otherNames',
                         { n: (json.applications || []).length })
                : t.html('consoleCaepRisc.apps.noneKnown'))
            : t.html('consoleCaepRisc.apps.none1') +
              '<a href="/admin/applications/new">' +
              t.html('consoleCaepRisc.apps.newAppLink') + '</a>' +
              t.html('consoleCaepRisc.apps.none2')) +
          '</td></tr>') +
      '</table>' +
      appNav.foot +
      kit.note(t.html('consoleCaepRisc.apps.match',
                      { n: appState.matched.length }) +
      (appState.page.paging.pages > 1
        ? t.html('consoleCaepRisc.apps.matchPaged', {
            first: appState.page.paging.firstRow,
            last: appState.page.paging.lastRow,
            page: appState.page.paging.page,
            pages: appState.page.paging.pages })
        : '') +
      t.html('consoleCaepRisc.apps.matchTail')) +


      (json.installed
        ? '<form method="post" action="/admin/caep">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="from" value="sessions">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<button class="secondary">' +
          t.html('consoleCaepRisc.clearRegister') + '</button>' +
          '</div></form>' +
          kit.note(t.html('consoleCaepRisc.sessions.clearNote'))
        : '') +

      kit.note('<a href="/admin/caep">' +
      t.html('consoleCaepRisc.links.caepSettings') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streams') +
      '</a> &middot; ' +
      '<a href="/admin/metrics">' +
      t.html('consoleCaepRisc.links.heldSessions') + '</a> ' +
      '&middot; <a href="/admin/caep-sessions?format=json">' +
      t.html('consoleCaepRisc.links.asJson') + '</a>');

    // WHAT THE BROWSER WAS SHOWN, BESIDE THE WHOLE LIST RATHER THAN INSTEAD
    // OF IT — the arrangement /admin/delegation's configured half already
    // has. `sessions` stays ENTIRE, because GET /admin-api/caep answers with
    // this same report and a caller that had to walk fifty-row pages of it
    // would be paying for this page's layout, which is not a fact about the
    // register. But a `?sessq=` the markup honours and the reply ignores is
    // exactly the silent disagreement this console keeps warning about, so
    // what the page did is REPORTED: `paging.sessions.total` against
    // `sessions.length` shows the filter that was applied and the slice that
    // was drawn, neither of them guessed from the markup.
    // THE SAME DOCUMENT `caepSessionsJson()` BUILDS FOR THE API — called
    // since #446 rather than assembled here, so the page is drawn from the
    // answer a caller of the API receives.
    return inner;
  }

  // One row of it. The eight count columns are in the SAME ORDER as the
  // sessions table's, off the same `caepShortNames()`, because a reader moving
  // between the two tables is reading one vocabulary — and a column that moved
  // between them would be worse than a column too many.
  /**
   * Draws one receiver application's row of the CAEP table: who, streams,
   * audience, the types it takes, a count per type and its deliveries.
   *
   * @param row - the application as the reporter describes it
   * @param shorts - the event types' short names, in column order
   * @param prefix - what each short name is prefixed with to key `counts`
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static caepApplicationRow(row, shorts, prefix, t) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    // WHERE IT IS IN THE REGISTRY, when it is there at all. A receiver seen
    // when a stream was created has an entry; one that agreed a stream while
    // the stream endpoint was not gated has none, and that row is the collected
    // total for all of them rather than an application. The gate was
    // `ssf.authRequired` until 2026-09-06 and is `mode.gatesSharedSignals()`
    // now (ssf/ssf_auth.ts); the page's note below still names the old setting.
    const who = row.registered
      ? '<a href="' + kit.esc('/admin/applications' +
          kit.queryWith({ application: row.identifier }, {})) + '">' +
        kit.esc(row.name || row.identifier) + '</a>' +
        (row.name && row.name !== row.identifier
          ? '<div class="sub"><code>' + kit.esc(row.identifier) +
            '</code></div>'
          : '')
      : '<span class="sub">' + kit.esc(row.name || row.identifier) + '</span>';
    const streams = row.streamCount
      ? kit.esc(String(row.streamCount)) +
        (row.enabled === row.streamCount
          ? ''
          : ' <span class="state-invalid">' +
            t.html('consoleCaepRisc.appRow.enabled', { n: row.enabled }) +
            '</span>') +
        '<div class="sub">' + kit.esc(row.deliveries.join(', ')) + '</div>'
      : '<span class="state-none" title="' +
        kit.esc(t.text('consoleCaepRisc.appRow.noStreamTip')) +
        '">' + t.html('consoleCaepRisc.appRow.none') + '</span>';
    // THE AUDIENCE, BESIDE THE IDENTIFIER RATHER THAN INSTEAD OF IT. They are
    // different fields — one is what the receiver authenticated as and the
    // other is what it asked its SETs to be addressed to — and a receiver whose
    // `aud` is not its own name is doing something legitimate that is invisible
    // anywhere else in this console. kit.shortened() rather than the whole
    // string,
    // for the reason the tokens page uses it on a jti: an `aud` is routinely a
    // URL, `code` is `word-break: break-all`, and a fifteen-column table gives
    // this one about three characters of width — so the untruncated value
    // wrapped to six lines and made every row on the page that tall. The whole
    // value is the tooltip.
    const audience = row.audiences.length
      ? (row.audiences.length === 1 && row.audiences[0] === row.identifier
          ? '<span class="sub" title="' +
            kit.esc(t.text('consoleCaepRisc.appRow.sameTip')) +
            '">' + t.html('consoleCaepRisc.appRow.same') + '</span>'
          : kit.shortened(row.audiences.join(', '), 20))
      : '<span class="sub" title="' +
        kit.esc(t.text('consoleCaepRisc.appRow.noAudTip')) +
        '">&mdash;</span>';
    const out = '<tr>' +
      '<td>' + who + '</td>' +
      '<td>' + streams + '</td>' +
      '<td class="sub">' + audience + '</td>' +
      '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
      kit.esc(row.takes.length
        ? t.text('consoleCaepRisc.appRow.ofEight', { n: row.takes.length })
        : t.text('consoleCaepRisc.caep.noneOfEight')) + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="sub">' + kit.esc(String(row.sessions)) + '</td>' +
      '<td class="sub">' + kit.esc(String(row.delivered)) + ' / ' +
      '<span class="' + (row.failed ? 'state-invalid' : 'sub') + '">' +
      kit.esc(String(row.failed)) + '</span>' +
      (row.lastPushError
        ? '<div class="sub" title="' + kit.esc(row.lastPushError) +
          '">' + t.html('consoleCaepRisc.appRow.lastError') + '</div>'
        : '') + '</td>' +
      '</tr>';
    return out;
  }

  // ONE ROW OF THE SESSIONS TABLE, and its first cell is the way IN since
  // 2026-09-04. What used to be under this table — a card per session listing
  // every event sent about it — is /admin/caep-sessions/session now, one
  // session at a time. `listView` is what the reader was looking at when they
  // clicked, so the drill-down's trail comes back to the search and the page
  // they left rather than to the top of an unfiltered list.
  //
  // `back` is the same query as a POSTable field, for the Reset button in the
  // last cell: resetting a row on page three used to answer with page one, so
  // the row somebody had just acted on was off screen and so was its neighbour.
  /**
   * Draws one row of the CAEP sessions table, its first cell linking to the
   * session's page and its last a Reset form posting to /admin/caep.
   *
   * @param row - the session as the reporter describes it
   * @param shorts - the event types' short names, in column order
   * @param prefix - what each short name is prefixed with to key `counts`
   * @param listView - the list's query, carried into the drill-down link
   * @param back - the same query as a field, so Reset returns to this page
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static caepSessionRow(row, shorts, prefix, listView, back, t) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    const href = '/admin/caep-sessions/session' +
      kit.queryWith(listView || {}, { id: row.sessionId });
    const out = '<tr>' +
      '<td><a href="' + kit.esc(href) + '" title="' +
      kit.esc(t.text('consoleCaepRisc.sessionRow.tip')) +
      '"><code>' + kit.esc(row.sessionId) + '</code></a>' +
      '<div class="sub">' + kit.esc(row.protocol || '') + '</div></td>' +
      '<td>' + kit.esc(row.username || row.sub ||
                       t.text('consoleCaepRisc.unknown')) +
      '<div class="sub"><code>' + kit.esc(row.sub) + '</code></div></td>' +
      CaepRiscPage.caepStateCell(row.state) +
      '<td class="sub">' + kit.esc(row.assurance.level
        ? (row.assurance.namespace + ' ' + row.assurance.level) : '—') +
      '</td>' +
      '<td class="' + (row.compliance === 'not-compliant'
        ? 'state-invalid' : 'sub') + '">' +
      kit.esc(row.compliance || '—') + '</td>' +
      '<td class="' + (row.risk.level === 'HIGH' ? 'state-invalid' : 'sub') +
      '">' + kit.esc(row.risk.level || '—') + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      // IT POSTS TO /admin/caep AND NOT TO THE PAGE IT IS ON, which is the
      // arrangement the applications page's permission forms already have with
      // /admin/delegation: a form may live on one page and post to another's
      // handler, and MOVING A FORM IS NOT MOVING AN ACTION. There is one CAEP
      // action handler, it has one operation on /admin-api, and a second route
      // here would have wanted a second operation over the same function —
      // which is the duplication rule 7 is trying to prevent rather than
      // require. `from` and `back` are what bring the reader back to this page.
      '<td><form method="post" action="/admin/caep">' +
      '<input type="hidden" name="action" value="reset-session">' +
      '<input type="hidden" name="session_id" value="' +
      kit.esc(row.sessionId) + '">' +
      '<input type="hidden" name="from" value="sessions">' +
      '<input type="hidden" name="back" value="' + kit.esc(back || '') + '">' +
      '<button class="secondary">' + t.html('consoleCaepRisc.reset') +
      '</button></form></td>' +
      '</tr>';
    return out;
  }

  // The short name of every CAEP event type, in catalogue order, so that the
  // count columns on the monitoring table are in the same order as the emit
  // form's menu. Derived from the reporter rather than written out, because a
  // list typed here would be the one place RISC's arrival is forgotten.
  /**
   * Lists the short name of every CAEP event type, in catalogue order.
   *
   * @param json - the CAEP report, whose `eventTypes` are read
   * @returns the short names
   */
  static caepShortNames(json) {
    const out = (json.eventTypes || []).map(function (row) {
      return row.short;
    });
    return out;
  }

  // What a session's CAEP state is called on the screen, with the class that
  // colours it. `revoked` is the one that must not read as ordinary: it is the
  // whole point of the profile.
  /**
   * Draws a session's CAEP state as a table cell, `revoked` marked invalid.
   *
   * @param state - the session's state
   * @returns the cell as HTML
   */
  static caepStateCell(state) {
    const cls = state === 'revoked' ? 'state-invalid'
      : (state === 'presented' ? 'state-valid' : 'sub');
    const out = '<td class="' + cls + '">' + kit.esc(state) + '</td>';
    return out;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static riscAccountsBody(ctx, json) {
    const t = ctx.t;
    const shorts = CaepRiscPage.riscShortNames(json);
    const prefix = 'https://schemas.openid.net/secevent/risc/event-type/';

    const headers = shorts.map(function (short) {
      return '<th title="' + kit.esc(prefix + short) + '">' +
        kit.esc(CaepRiscPage.riscColumnLabel(short)) + '</th>';
    }).join('');

    const state = { wanted: json.filter.accounts || '',
                    page: { shown: json.shown.accounts,
                            paging: json.paging.accounts } };
    const appState = { wanted: json.filter.applications || '',
                       page: { shown: json.shown.applications,
                               paging: json.paging.applications } };
    const navParams = kit.pageParamsOf(ctx.query);
    const acctNav = kit.pageNavPair('/admin/risc-accounts', navParams,
                                     state.page.paging, t);
    const appNav = kit.pageNavPair('/admin/risc-accounts', navParams,
                                    appState.page.paging, t);
    const listView = kit.listViewOf('/admin/risc-accounts', ctx.query);
    const back = kit.queryWith(listView, {});

    const rows = state.page.shown.length
      ? state.page.shown.map(function (row) {
          return CaepRiscPage.riscAccountRow(row, shorts, prefix, listView,
            back, t);
        }).join('')
      : '<tr><td colspan="' + (shorts.length + 8) + '">' +
        (state.wanted
          ? t.html('consoleCaepRisc.accounts.noMatch',
                   { wanted: state.wanted }) + ' ' +
            ((json.accounts || []).length
              ? t.html('consoleCaepRisc.accounts.otherNames',
                       { n: (json.accounts || []).length })
              : t.html('consoleCaepRisc.noneTracked'))
          : t.html('consoleCaepRisc.accounts.none1') +
            '<a href="/admin/scim">SCIM</a>' +
            t.html('consoleCaepRisc.accounts.none2')) +
        '</td></tr>';

    const streamRows = (json.streams || []).length
      ? json.streams.map(function (row) {
          return '<tr><td><code>' + kit.esc(row.stream_id) + '</code></td>' +
            '<td class="sub">' + kit.esc(row.aud) + '</td><td class="' +
            (row.status === 'enabled' ? 'state-valid' : 'sub') +
            '">' + kit.esc(row.status) + '</td>' +
            '<td class="sub">' + kit.esc(row.delivery) + '</td>' +
            '<td class="sub">' + kit.esc(String(row.subjects)) + '</td>' +
            '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
            kit.esc(row.takes.length ? row.takes.join(', ')
              : t.text('consoleCaepRisc.risc.noneOfFourteen')) + '</td></tr>';
        }).join('')
      : '<tr><td colspan="6">' +
        t.html('consoleCaepRisc.accounts.noStreams') + '</td></tr>';

    // The `err` box stays English: an error is never translated (#539).
    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so no account state is tracked.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleCaepRisc.accounts.riscOff'))
        : '') +
      (json.installed && json.enabled && !json.autoEmit
        ? kit.warn(t.html('consoleCaepRisc.accounts.autoOff') +
          '<a href="/admin/risc">' +
          t.html('consoleCaepRisc.accounts.riscPageLink') + '</a>' +
          t.html('consoleCaepRisc.accounts.autoOff2'))
        : '') +

      kit.note(t.html('consoleCaepRisc.accounts.intro') + '<a ' +
      'href="/admin/risc-accounts/account">' +
      t.html('consoleCaepRisc.accounts.introLink') + '</a>' +
      t.html('consoleCaepRisc.period')) +

      kit.note(t.html('consoleCaepRisc.accounts.twoColumns')) +

      (json.installed && json.honourOptOut
        ? kit.note(t.html('consoleCaepRisc.accounts.honourOn'))
        : kit.warn(t.html('consoleCaepRisc.accounts.honourOff'))) +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, t.text('consoleCaepRisc.tile.accounts')) +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.lifecycle === 'purged';
      }).length, t.text('consoleCaepRisc.tile.purged')) +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.lifecycle === 'disabled';
      }).length, t.text('consoleCaepRisc.tile.disabled')) +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.optOut !== 'opt-in';
      }).length, t.text('consoleCaepRisc.tile.optedOut')) +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), t.text('consoleCaepRisc.tile.eventsSent')) +
      kit.tile((json.streams || []).filter(function (row) {
        return row.takes.length;
      }).length, t.text('consoleCaepRisc.tile.streamsRisc')) +
      '</div>' +

      '<h2>' + t.html('consoleCaepRisc.accounts.heading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.accounts.drillNote')) +
      kit.sectionSearchForm({
        path: '/admin/risc-accounts', query: ctx.query,
        param: 'acctq', pageParam: 'accountsPage',
        label: t.text('consoleCaepRisc.accounts.searchLabel'),
        placeholder: t.text('consoleCaepRisc.accounts.searchPlaceholder'),
        what: t.html('consoleCaepRisc.accounts.searchWhat')
      }, t) +
      kit.perPageForm('/admin/risc-accounts', 'acctq', state.wanted,
                       state.page.paging.perPage,
                       t.html('consoleCaepRisc.accounts.perPage'), {}, t) +
      acctNav.head +
      kit.wideTable(t.text('consoleCaepRisc.accounts.heading'),
        '<table><tr><th>' + t.html('consoleCaepRisc.th.account') +
        '</th><th>' + t.html('consoleCaepRisc.th.subject') + '</th><th>' +
        t.html('consoleCaepRisc.th.lifecycle') + '</th>' +
        '<th>' + t.html('consoleCaepRisc.th.optOut') + '</th><th>' +
        t.html('consoleCaepRisc.th.credential') + '</th>' + headers +
        '<th>' + t.html('consoleCaepRisc.th.total') + '</th><th>' +
        t.html('consoleCaepRisc.th.suppressed') + '</th><th></th></tr>' +
        rows + '</table>') +
      acctNav.foot +

      '<h2>' + t.html('consoleCaepRisc.accounts.whereHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.accounts.zeroNote')) +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.stream') +
      '</th><th>aud</th><th>' + t.html('consoleCaepRisc.th.status') +
      '</th><th>' + t.html('consoleCaepRisc.th.delivery') +
      '</th>' +
      '<th>' + t.html('consoleCaepRisc.th.subjects') + '</th><th>' +
      t.html('consoleCaepRisc.th.riscTypes') + '</th></tr>' + streamRows +
      '</table>' +

      '<h2>' + t.html('consoleCaepRisc.perAppHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.accounts.perApp')) +
      kit.sectionSearchForm({
        path: '/admin/risc-accounts', query: ctx.query,
        param: 'rappq', pageParam: 'rapplicationsPage',
        label: t.text('consoleCaepRisc.receiverLabel'),
        placeholder: t.text('consoleCaepRisc.receiverPlaceholder'),
        what: t.html('consoleCaepRisc.accounts.receiverWhat')
      }, t) +
      appNav.head +
      kit.wideTable(t.text('consoleCaepRisc.perAppHeading'),
        '<table><tr><th>' + t.html('consoleCaepRisc.th.receiver') +
        '</th><th>' + t.html('consoleCaepRisc.th.streams') +
        '</th><th>aud</th>' +
        '<th>' + t.html('consoleCaepRisc.th.takes') + '</th>' + headers +
        '<th>' + t.html('consoleCaepRisc.th.total') + '</th><th>' +
        t.html('consoleCaepRisc.th.accounts') + '</th><th>' +
        t.html('consoleCaepRisc.th.deliveredFailed') + '</th></tr>' +
        (appState.page.shown.length
          ? appState.page.shown.map(function (row) {
              return CaepRiscPage.riscApplicationRow(row, shorts, prefix, t);
            }).join('')
          : '<tr><td colspan="' + (shorts.length + 7) + '">' +
            (appState.wanted
              ? t.html('consoleCaepRisc.apps.noMatch',
                       { wanted: appState.wanted })
              : t.html('consoleCaepRisc.apps.noneRisc')) +
            '</td></tr>') +
        '</table>') +
      appNav.foot +

      (json.installed
        ? '<form method="post" action="/admin/risc">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="from" value="accounts">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<button class="secondary">' +
          t.html('consoleCaepRisc.clearRegister') + '</button>' +
          '</div></form>' +
          kit.note(t.html('consoleCaepRisc.accounts.clearNote'))
        : '') +

      kit.note('<a href="/admin/risc">' +
      t.html('consoleCaepRisc.links.caepSettings') + '</a> &middot; ' +
      '<a href="/admin/caep-sessions">' +
      t.html('consoleCaepRisc.links.sessionsSaid') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streams') +
      '</a> &middot; ' +
      '<a href="/admin/users">' + t.html('consoleCaepRisc.links.people') +
      '</a> &middot; ' +
      '<a href="/admin/risc-accounts?format=json">' +
      t.html('consoleCaepRisc.links.asJson') + '</a>');

    return inner;
  }

  // ONE ROW OF THE ACCOUNTS TABLE, and its first cell is the way in — the
  // arrangement /admin/caep-sessions has, for its reason.
  /**
   * Draws one row of the RISC accounts table, its first cell linking to the
   * account's page and its last a Reset form posting to /admin/risc.
   *
   * @param row - the account as the reporter describes it
   * @param shorts - the event types' short names, in column order
   * @param prefix - what each short name is prefixed with to key `counts`
   * @param listView - the list's query, carried into the drill-down link
   * @param back - the same query as a field, so Reset returns to this page
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static riscAccountRow(row, shorts, prefix, listView, back, t) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    const href = '/admin/risc-accounts/account' +
      kit.queryWith(listView || {}, { id: row.accountId });
    const out = '<tr>' +
      '<td><a href="' + kit.esc(href) + '" title="' +
      kit.esc(t.text('consoleCaepRisc.accountRow.tip')) +
      '"><code>' + kit.esc(row.accountId) + '</code></a>' +
      (row.email
        ? '<div class="sub">' + kit.esc(row.email) + '</div>' : '') + '</td>' +
      '<td class="sub">' + kit.esc(row.subject || '—') + '</td>' +
      CaepRiscPage.riscLifecycleCell(row.lifecycle) +
      CaepRiscPage.riscOptCell(row.optOut, t) +
      '<td class="' + (row.credentialStanding === 'compromised'
        ? 'state-invalid' : 'sub') + '">' +
      kit.esc(row.credentialStanding || '—') + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="' + (row.suppressed ? 'state-invalid' : 'sub') + '" title="' +
      kit.esc(t.text('consoleCaepRisc.accountRow.suppressedTip')) +
      '">' + kit.esc(String(row.suppressed)) + '</td>' +
      // IT POSTS TO /admin/risc AND NOT TO THE PAGE IT IS ON, for the reason
      // the CAEP table's Reset does: there is one RISC action handler and one
      // operation on /admin-api over it, and moving a form is not moving an
      // action.
      '<td><form method="post" action="/admin/risc">' +
      '<input type="hidden" name="action" value="reset-account">' +
      '<input type="hidden" name="account_id" value="' +
      kit.esc(row.accountId) + '">' +
      '<input type="hidden" name="from" value="accounts">' +
      '<input type="hidden" name="back" value="' + kit.esc(back || '') + '">' +
      '<button class="secondary">' + t.html('consoleCaepRisc.reset') +
      '</button></form></td>' +
      '</tr>';
    return out;
  }

  /**
   * Draws one receiver application's row of the RISC table: who, streams,
   * audience, the types it takes, a count per type and its deliveries.
   *
   * @param row - the application as the reporter describes it
   * @param shorts - the event types' short names, in column order
   * @param prefix - what each short name is prefixed with to key `counts`
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static riscApplicationRow(row, shorts, prefix, t) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    const who = row.registered
      ? '<a href="' + kit.esc('/admin/applications' +
          kit.queryWith({ application: row.identifier }, {})) + '">' +
        kit.esc(row.name || row.identifier) + '</a>' +
        (row.name && row.name !== row.identifier
          ? '<div class="sub"><code>' + kit.esc(row.identifier) +
            '</code></div>'
          : '')
      : '<span class="sub">' + kit.esc(row.name || row.identifier) + '</span>';
    const streams = row.streamCount
      ? kit.esc(String(row.streamCount)) +
        (row.enabled === row.streamCount
          ? ''
          : ' <span class="state-invalid">' +
            t.html('consoleCaepRisc.appRow.enabled', { n: row.enabled }) +
            '</span>') +
        '<div class="sub">' + kit.esc(row.deliveries.join(', ')) + '</div>'
      : '<span class="state-none" title="' +
        kit.esc(t.text('consoleCaepRisc.appRow.noStreamTipShort')) +
        '">' + t.html('consoleCaepRisc.appRow.none') + '</span>';
    const audience = row.audiences.length
      ? (row.audiences.length === 1 && row.audiences[0] === row.identifier
          ? '<span class="sub">' + t.html('consoleCaepRisc.appRow.same') +
            '</span>'
          : kit.shortened(row.audiences.join(', '), 20))
      : '<span class="sub">&mdash;</span>';
    const out = '<tr>' +
      '<td>' + who + '</td>' +
      '<td>' + streams + '</td>' +
      '<td class="sub">' + audience + '</td>' +
      '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
      kit.esc(row.takes.length
        ? t.text('consoleCaepRisc.appRow.ofFourteen', { n: row.takes.length })
        : t.text('consoleCaepRisc.risc.noneOfFourteen')) + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="sub">' + kit.esc(String(row.accounts)) + '</td>' +
      '<td class="sub">' + kit.esc(String(row.delivered)) + ' / ' +
      '<span class="' + (row.failed ? 'state-invalid' : 'sub') + '">' +
      kit.esc(String(row.failed)) + '</span>' +
      (row.lastPushError
        ? '<div class="sub" title="' + kit.esc(row.lastPushError) +
          '">' + t.html('consoleCaepRisc.appRow.lastError') + '</div>'
        : '') + '</td>' +
      '</tr>';
    return out;
  }

  // A RISC event type's column heading, which has to be SHORT and has to stay
  // distinguishable — and those two pull against each other harder here than
  // they do for CAEP. Four of the fourteen begin `opt-out-` and three begin
  // `account-`, so dropping a common prefix the way the CAEP table drops
  // `session-` would leave three columns headed `-in`, `-initiated` and
  // `-cancelled`. The rule is therefore: drop `account-`, which leaves four
  // distinct words, and keep everything else whole. The whole URI is the title.
  /**
   * Makes a RISC event type's column heading by dropping a leading
   * `account-` and keeping the rest whole.
   *
   * @param short - the type's short name
   * @returns the heading text
   */
  static riscColumnLabel(short) {
    const out = String(short || '').replace(/^account-/, '');
    return out;
  }

  // The short name of every RISC event type, in catalogue order, so that the
  // count columns on the monitoring table are in the same order as the emit
  // form's menu. Derived from the reporter rather than written out.
  /**
   * Lists the short name of every RISC event type, in catalogue order.
   *
   * @param json - the RISC report, whose `eventTypes` are read
   * @returns the short names
   */
  static riscShortNames(json) {
    const out = (json.eventTypes || []).map(function (row) {
      return row.short;
    });
    return out;
  }

  // What an account's RISC lifecycle is called on the screen, with the class
  // that colours it. `purged` is the one that must not read as ordinary: RISC
  // defines it as permanently deleted and it is the only terminal state in the
  // vocabulary.
  /**
   * Draws an account's RISC lifecycle as a table cell, `purged` and
   * `disabled` marked invalid.
   *
   * @param state - the lifecycle state
   * @returns the cell as HTML
   */
  static riscLifecycleCell(state) {
    const cls = (state === 'purged' || state === 'disabled') ? 'state-invalid'
      : 'sub';
    const out = '<td class="' + cls + '">' + kit.esc(state) + '</td>';
    return out;
  }

  // And its opt-out state, which is a SECOND dimension and not a variant of the
  // first. An account can be opted out and perfectly healthy, or compromised
  // and still exchanging — so the two are two columns, and folding them into
  // one word would mean choosing which of the two questions this page answers.
  /**
   * Draws an account's RISC opt-out state as a table cell with a title
   * saying what the state means.
   *
   * @param state - the opt-out state
   * @param t - the page's translator (#539)
   * @returns the cell as HTML
   */
  static riscOptCell(state, t) {
    const cls = state === 'opt-out' ? 'state-invalid'
      : (state === 'opt-out-initiated' ? '' : 'sub');
    const title = state === 'opt-out'
      ? t.text('consoleCaepRisc.opt.optOut')
      : (state === 'opt-out-initiated'
          ? t.text('consoleCaepRisc.opt.initiated')
          : t.text('consoleCaepRisc.opt.in'));
    const out = '<td class="' + cls + '" title="' + kit.esc(title) + '">' +
      kit.esc(state) + '</td>';
    return out;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static caepSessionBody(ctx, json) {
    const t = ctx.t;
    const row = json.session;
    const listView = kit.listViewOf('/admin/caep-sessions', ctx.query);
    const upHref = '/admin/caep-sessions' + kit.queryWith(listView, {});
    const backLink = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">' + t.html('consoleCaepRisc.session.back') + '</a>');
    // The list view as a POSTable field, for the reset form below: the reader
    // came from page three of a search and should go back to it.
    const back = kit.queryWith(listView, {});

    if (!row) {
      const inner = backLink +
        kit.note(json.id
          ? t.html('consoleCaepRisc.session.notFound', { id: json.id })
          : t.html('consoleCaepRisc.session.name1') +
            '<a href="' + kit.esc(upHref) + '">' +
            t.html('consoleCaepRisc.session.tableLink') + '</a>' +
            t.html('consoleCaepRisc.session.name2'));
      return inner;
    }

    // The events, paged. `eventsPage` rather than `page` because this list is
    // named for pagingOf()'s reason and because the parameter travels back to
    // the list page in the trail, where a bare `page` would be the sessions
    // table's.
    const navParams = kit.pageParamsOf(ctx.query);
    const eventNav = kit.pageNavPair('/admin/caep-sessions/session',
                                      navParams,
                                      json.paging.events, t);

    const eventRows = json.events.length
      ? json.events.map(function (one) {
          return CaepRiscPage.caepEventRow(one, t);
        }).join('')
      : '<tr><td colspan="5">' + t.html('consoleCaepRisc.session.nothing1') +
        '<a href="/admin/caep-sessions">' +
        t.html('consoleCaepRisc.streamsTableLink') + '</a>' +
        t.html('consoleCaepRisc.nothingEnd') + '</td></tr>';

    const inner = backLink +

      kit.note(t.html('consoleCaepRisc.session.intro')) +

      '<h2>' + t.html('consoleCaepRisc.session.heading') + '</h2>' +
      CaepRiscPage.caepSessionFacts(row, t) +

      '<h2>' + t.html('consoleCaepRisc.saidHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.session.warningNote')) +
      kit.perPageForm('/admin/caep-sessions/session', 'id', json.id,
                       json.paging.events.perPage,
                       t.html('consoleCaepRisc.eventsPerPage'), listView, t) +
      eventNav.head +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.when') + '</th><th>' +
      t.html('consoleCaepRisc.th.event') + '</th><th>jti</th><th>' +
      t.html('consoleCaepRisc.th.stream') + '</th>' +
      '<th>' + t.html('consoleCaepRisc.th.noticed') + '</th></tr>' +
      eventRows + '</table>' +
      eventNav.foot +

      '<h2>' + t.html('consoleCaepRisc.perTypeHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.session.perTypeNote')) +
      CaepRiscPage.caepSessionCounts(row, json.eventTypes || [], t) +

      '<h2>' + t.html('consoleCaepRisc.session.resetHeading') + '</h2>' +
      '<form method="post" action="/admin/caep">' +
      '<input type="hidden" name="action" value="reset-session">' +
      '<input type="hidden" name="session_id" value="' +
      kit.esc(row.sessionId) +
      '">' +
      // WHICH PAGE PRESSED IT. Read as an enum by caepSessionsBackTo(), never
      // as a path — see its header.
      '<input type="hidden" name="from" value="session">' +
      '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
      '<div class="formrow"><button class="secondary">' +
      t.html('consoleCaepRisc.reset') + '</button></div>' +
      '</form>' +
      kit.note(t.html('consoleCaepRisc.session.resetNote')) +

      kit.note('<a href="/admin/caep-sessions">' +
      t.html('consoleCaepRisc.links.everySession') + '</a> &middot; ' +
      '<a href="/admin/caep">' +
      t.html('consoleCaepRisc.links.caepSettingsLower') + '</a> &middot; ' +
      '<a href="' +
      kit.esc('/admin/caep' + kit.queryWith({ session: row.sessionId },
                                                       {})) +
      '">' + t.html('consoleCaepRisc.links.emitSession') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streams') +
      '</a> &middot; ' +
      '<a href="' + kit.esc('/admin/caep-sessions/session' +
        kit.queryWith(kit.pageParamsOf(ctx.query), { format: 'json' })) +
      '">' + t.html('consoleCaepRisc.links.asJson') + '</a>');

    return inner;
  }

  // The facts about one session that are not events: who it belongs to, what
  // state it is in, and the three CAEP dimensions a receiver acts on. Drawn as
  // a table rather than as the run of `<div class="sub">` lines the card used,
  // because on a page of its own this is the summary somebody reads first and a
  // paragraph of eight facts is not read at all.
  /**
   * Draws the facts about one CAEP session that are not events — who, state,
   * assurance, compliance, risk and the rest — as a table.
   *
   * @param row - the session as the reporter describes it
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static caepSessionFacts(row, t) {
    function line(label, value, cls?) {
      return '<tr><th>' + kit.esc(label) + '</th><td' +
        (cls ? ' class="' + cls + '"' : '') + '>' + value + '</td></tr>';
    }
    const out = '<table>' +
      line(t.text('consoleCaepRisc.facts.session'),
           '<code>' + kit.esc(row.sessionId) + '</code>') +
      line(t.text('consoleCaepRisc.facts.who'),
        kit.esc(row.username || row.sub || t.text('consoleCaepRisc.unknown')) +
        ' <span class="sub"><code>' + kit.esc(row.sub) + '</code></span>') +
      line(t.text('consoleCaepRisc.facts.subject'),
           '<span class="sub">' + kit.esc(row.subject) + '</span>') +
      line(t.text('consoleCaepRisc.facts.issuer'),
        '<span class="sub"><code>' + kit.esc(row.iss || '—') +
        '</code></span>') +
      line(t.text('consoleCaepRisc.facts.protocol'),
        '<span class="sub">' + kit.esc(row.protocol || '—') +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.state'), kit.esc(row.state),
        row.state === 'revoked' ? 'state-invalid'
          : (row.state === 'presented' ? 'state-valid' : 'sub')) +
      line(t.text('consoleCaepRisc.facts.established'),
        '<span class="sub">' + kit.esc(row.establishedAt) +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.lastChanged'),
        '<span class="sub">' + kit.esc(row.updatedAt) +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.assurance'),
        '<span class="sub">' + kit.esc(row.assurance.level
        ? (row.assurance.namespace + ' ' + row.assurance.level) : '—') +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.compliance'),
        kit.esc(row.compliance || '—'),
        row.compliance === 'not-compliant' ? 'state-invalid' : 'sub') +
      line(t.text('consoleCaepRisc.facts.risk'),
        kit.esc(row.risk.level || '—') +
        (row.risk.subject ? ' <span class="sub">' + kit.esc(row.risk.subject) +
          '</span>' : ''),
        row.risk.level === 'HIGH' ? 'state-invalid' : 'sub') +
      line('acr / amr', '<span class="sub"><code>' + kit.esc(row.acr || '—') +
        '</code> / <code>' + kit.esc((row.amr || []).join(' ') || '—') +
        '</code></span>') +
      (Object.keys(row.claims).length
        ? line(t.text('consoleCaepRisc.facts.claimsChanged'),
               '<code>' + kit.esc(JSON.stringify(row.claims)) +
          '</code>')
        : '') +
      ((row.credentials || []).length
        ? line(t.text('consoleCaepRisc.facts.credentials'),
          '<span class="sub">' +
          kit.esc(row.credentials.join(', ')) + '</span>')
        : '') +
      ((row.notes || []).length
        ? line(t.text('consoleCaepRisc.facts.notes'),
          '<span class="sub">' + kit.esc(row.notes.join(' ')) +
          '</span>')
        : '') +
      '</table>';
    return out;
  }

  // One session, opened out: what has actually been sent about it, in order,
  // with the findings the register made as each one was applied. The counts on
  // the table above say HOW MANY and this says WHICH, and the two are different
  // questions — see caep.ts on why the ring and the counters are separate.
  //
  // **IT IS A PAGE OF ITS OWN SINCE 2026-09-04 AND USED TO BE A CARD PER
  // SESSION UNDER THE TABLE.** That block was drawn for EVERY session the
  // register held, each with a table of its own, so a service driven for an
  // afternoon answered /admin/caep-sessions with a couple of hundred nested
  // tables under the one table anybody had come to read — and the sessions
  // table itself was then off the top of the screen for the whole of it. One
  // session at a time, reached by clicking the identifier, is the arrangement
  // /admin/tokens and its credential drill-down already have.
  /**
   * Draws one event sent about a CAEP session as a table row.
   *
   * @param one - the event: when, name, jti, stream and warnings
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static caepEventRow(one, t) {
    return '<tr><td class="sub">' + kit.esc(one.at) + '</td>' +
      '<td>' + kit.esc(one.name) + '</td>' +
      '<td><code>' + kit.esc(one.jti) + '</code></td>' +
      '<td><code>' + kit.esc(one.streamId ||
                             t.text('consoleCaepRisc.noneParen')) +
      '</code></td>' +
      '<td class="sub">' + kit.esc((one.warnings || []).join(' ') || '—') +
      '</td></tr>';
  }

  // What has been said about this session PER TYPE, which is the row of the
  // sessions table the reader clicked, drawn the long way round. It is here and
  // not only there because the eight columns of that table are headed by an
  // abbreviation — `revoked`, `established`, `credential` — and this is the one
  // place there is room for the type's whole name and its URI.
  /**
   * Draws how many events of each CAEP type were sent about one session,
   * with each type's whole name.
   *
   * @param row - the session, whose `counts` are keyed by type URI
   * @param types - the CAEP event types
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static caepSessionCounts(row, types, t) {
    const rows = types.map(function (type) {
      const n = row.counts[type.uri] || 0;
      return '<tr><td>' + kit.esc(type.name) + '</td>' +
        '<td class="sub"><code>' + kit.esc(type.short) + '</code></td>' +
        '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
        '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleCaepRisc.th.eventType') +
      '</th><th>' + t.html('consoleCaepRisc.th.shortName') + '</th><th>' +
      t.html('consoleCaepRisc.th.sent') + '</th></tr>' +
      rows + '</table>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static riscAccountBody(ctx, json) {
    const t = ctx.t;
    const row = json.account;
    const listView = kit.listViewOf('/admin/risc-accounts', ctx.query);
    const upHref = '/admin/risc-accounts' + kit.queryWith(listView, {});
    const backLink = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">' + t.html('consoleCaepRisc.account.back') + '</a>');
    const back = kit.queryWith(listView, {});

    if (!row) {
      const inner = backLink +
        kit.note(json.id
          ? t.html('consoleCaepRisc.account.notFound', { id: json.id })
          : t.html('consoleCaepRisc.account.name1') +
            '<a href="' + kit.esc(upHref) + '">' +
            t.html('consoleCaepRisc.account.tableLink') + '</a>' +
            t.html('consoleCaepRisc.account.name2'));
      return inner;
    }

    const eventNav = kit.pageNavPair('/admin/risc-accounts/account',
                                      kit.pageParamsOf(ctx.query),
                                      json.paging.events, t);

    const eventRows = json.events.length
      ? json.events.map(function (one) {
          return CaepRiscPage.riscEventRow(one, t);
        }).join('')
      : '<tr><td colspan="5">' + t.html('consoleCaepRisc.account.nothing1') +
        '<a href="/admin/risc-accounts">' +
        t.html('consoleCaepRisc.streamsTableLink') + '</a>' +
        t.html('consoleCaepRisc.nothingEnd') + '</td></tr>';

    const inner = backLink +

      kit.note(t.html('consoleCaepRisc.account.intro')) +

      '<h2>' + t.html('consoleCaepRisc.account.heading') + '</h2>' +
      CaepRiscPage.riscAccountFacts(row, t) +

      '<h2>' + t.html('consoleCaepRisc.saidHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.account.warningNote')) +
      kit.perPageForm('/admin/risc-accounts/account', 'id', json.id,
                       json.paging.events.perPage,
                       t.html('consoleCaepRisc.eventsPerPage'), listView, t) +
      eventNav.head +
      '<table><tr><th>' + t.html('consoleCaepRisc.th.when') + '</th><th>' +
      t.html('consoleCaepRisc.th.event') + '</th><th>jti</th><th>' +
      t.html('consoleCaepRisc.th.stream') + '</th>' +
      '<th>' + t.html('consoleCaepRisc.th.noticed') + '</th></tr>' +
      eventRows + '</table>' +
      eventNav.foot +

      '<h2>' + t.html('consoleCaepRisc.perTypeHeading') + '</h2>' +
      kit.note(t.html('consoleCaepRisc.account.perTypeNote')) +
      CaepRiscPage.riscAccountCounts(row, json.eventTypes || [], t) +

      '<h2>' + t.html('consoleCaepRisc.account.resetHeading') + '</h2>' +
      '<form method="post" action="/admin/risc">' +
      '<input type="hidden" name="action" value="reset-account">' +
      '<input type="hidden" name="account_id" value="' +
      kit.esc(row.accountId) +
      '">' +
      '<input type="hidden" name="from" value="account">' +
      '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
      '<div class="formrow"><button class="secondary">' +
      t.html('consoleCaepRisc.reset') + '</button></div>' +
      '</form>' +
      kit.note(t.html('consoleCaepRisc.account.resetNote')) +

      kit.note('<a href="/admin/risc-accounts">' +
      t.html('consoleCaepRisc.links.everyAccount') + '</a> &middot; ' +
      '<a href="' +
      kit.esc('/admin/risc' + kit.queryWith({ acctq2: row.accountId },
                                                       {})) +
      '">' + t.html('consoleCaepRisc.links.emitAccount') + '</a> &middot; ' +
      '<a href="/admin/risc">' +
      t.html('consoleCaepRisc.links.settingsCatalogue') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleCaepRisc.links.streams') +
      '</a> &middot; ' +
      '<a href="' + kit.esc('/admin/risc-accounts/account' +
        kit.queryWith(kit.pageParamsOf(ctx.query), { format: 'json' })) +
      '">' + t.html('consoleCaepRisc.links.asJson') + '</a>');

    return inner;
  }

  // The facts about one account that are not events. It is longer than the CAEP
  // equivalent by exactly the amount RISC's model is larger: a session has one
  // state and an account has three that move independently, and the identifiers
  // it has been known by are a list rather than a value — because
  // `identifier-changed` is an event about the key itself.
  /**
   * Draws the facts about one RISC account that are not events — its three
   * states, contact details, former identifiers and the rest — as a table.
   *
   * @param row - the account as the reporter describes it
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static riscAccountFacts(row, t) {
    function line(label, value, cls?) {
      return '<tr><th>' + kit.esc(label) + '</th><td' +
        (cls ? ' class="' + cls + '"' : '') + '>' + value + '</td></tr>';
    }
    const yesNo = function (on) {
      return on ? t.html('consoleCaepRisc.yes')
                : '<span class="sub">' + t.html('consoleCaepRisc.no') +
                  '</span>';
    };
    const out = '<table>' +
      line(t.text('consoleCaepRisc.facts.account'),
           '<code>' + kit.esc(row.accountId) + '</code>') +
      line(t.text('consoleCaepRisc.facts.subject'),
        '<span class="sub">' + kit.esc(row.subject || '—') +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.issuer'),
        '<span class="sub"><code>' + kit.esc(row.iss || '—') +
        '</code></span>') +
      line(t.text('consoleCaepRisc.facts.directoryEntry'),
           '<span class="sub"><code>' + kit.esc(row.dn || '—') +
        '</code></span>') +
      line(t.text('consoleCaepRisc.facts.lifecycle'), kit.esc(row.lifecycle),
        (row.lifecycle === 'purged' || row.lifecycle === 'disabled')
          ? 'state-invalid' : 'sub') +
      line(t.text('consoleCaepRisc.facts.optOut'), kit.esc(row.optOut),
        row.optOut === 'opt-out' ? 'state-invalid' : 'sub') +
      line(t.text('consoleCaepRisc.facts.standing'),
        kit.esc(row.credentialStanding || '—'),
        row.credentialStanding === 'compromised' ? 'state-invalid' : 'sub') +
      line(t.text('consoleCaepRisc.facts.changeRequired'),
           yesNo(row.credentialChangeRequired)) +
      line(t.text('consoleCaepRisc.facts.recovery'),
           yesNo(row.recoveryActivated)) +
      line(t.text('consoleCaepRisc.facts.email'),
           '<span class="sub">' + kit.esc(row.email || '—') + '</span>') +
      line(t.text('consoleCaepRisc.facts.phone'),
           '<span class="sub">' + kit.esc(row.phone || '—') + '</span>') +
      ((row.formerIdentifiers || []).length
        ? line(t.text('consoleCaepRisc.facts.formerly'),
          '<span class="sub" title="' +
          kit.esc(t.text('consoleCaepRisc.facts.formerlyTip')) +
          '">' + kit.esc(row.formerIdentifiers.join(', ')) + '</span>')
        : '') +
      line(t.text('consoleCaepRisc.facts.firstSeen'),
        '<span class="sub">' + kit.esc(row.createdAt) +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.lastChanged'),
        '<span class="sub">' + kit.esc(row.updatedAt) +
        '</span>') +
      line(t.text('consoleCaepRisc.facts.suppressed'),
        kit.esc(String(row.suppressed || 0)),
        row.suppressed ? 'state-invalid' : 'sub') +
      ((row.identifierChanges || []).length
        ? line(t.text('consoleCaepRisc.facts.identifierChanges'),
          '<span class="sub">' +
          kit.esc(row.identifierChanges.map(function (one) {
            return (one.from || t.text('consoleCaepRisc.noneParen')) +
              ' → ' + (one.to || t.text('consoleCaepRisc.facts.notSaid'));
          }).join(', ')) + '</span>')
        : '') +
      ((row.credentials || []).length
        ? line(t.text('consoleCaepRisc.facts.compromised'),
          '<span class="sub">' +
          kit.esc(row.credentials.map(function (one) {
            return one.credentialType ||
              t.text('consoleCaepRisc.facts.unstated');
          }).join(', ')) + '</span>')
        : '') +
      ((row.notes || []).length
        ? line(t.text('consoleCaepRisc.facts.notes'),
          '<span class="sub">' + kit.esc(row.notes.join(' ')) +
          '</span>')
        : '') +
      '</table>';
    return out;
  }

  /**
   * Draws one event sent about a RISC account as a table row.
   *
   * @param one - the event: when, name, jti, stream and warnings
   * @param t - the page's translator (#539)
   * @returns the row as HTML
   */
  static riscEventRow(one, t) {
    return '<tr><td class="sub">' + kit.esc(one.at) + '</td>' +
      '<td>' + kit.esc(one.name) + '</td>' +
      '<td><code>' + kit.esc(one.jti) + '</code></td>' +
      '<td><code>' + kit.esc(one.streamId ||
                             t.text('consoleCaepRisc.noneParen')) +
      '</code></td>' +
      '<td class="sub">' + kit.esc((one.warnings || []).join(' ') || '—') +
      '</td></tr>';
  }

  // What has been said about this account PER TYPE, written the long way round.
  // It carries a DEPRECATED column that the CAEP equivalent has no need of: one
  // of RISC's fourteen is deprecated by its own specification in favour of a
  // CAEP event, and a count in that row is a fact about the receiver's future
  // rather than about this account.
  /**
   * Draws how many events of each RISC type were sent about one account,
   * marking the type its specification deprecates.
   *
   * @param row - the account, whose `counts` are keyed by type URI
   * @param types - the RISC event types
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static riscAccountCounts(row, types, t) {
    const rows = types.map(function (type) {
      const n = row.counts[type.uri] || 0;
      return '<tr><td>' + kit.esc(type.name) + '</td>' +
        '<td class="sub"><code>' + kit.esc(type.short) + '</code></td>' +
        '<td class="' + (type.deprecated ? 'state-invalid' : 'sub') + '">' +
        (type.deprecated
          ? t.html('consoleCaepRisc.counts.deprecatedUse',
                   { type: String(type.deprecated).split('/').pop() })
          : '&mdash;') + '</td>' +
        '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
        '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleCaepRisc.th.eventType') +
      '</th><th>' + t.html('consoleCaepRisc.th.shortName') +
      '</th><th></th>' +
      '<th>' + t.html('consoleCaepRisc.th.sent') + '</th></tr>' + rows +
      '</table>';
  }
}

export = CaepRiscPage;
