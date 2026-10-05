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

    const catalogue = (json.catalogue || []).map(function (row) {
      const members = row.members.map(function (member) {
        return '<tr><td><code>' + kit.esc(member.name) + '</code></td>' +
          '<td class="' + (member.required ? '' : 'sub') + '">' +
          (member.required ? 'required' : 'optional') + '</td>' +
          '<td class="sub"><code>' + kit.esc(member.type) + '</code>' +
          (member.values.length
            ? ' ' + kit.esc(member.values.join(' | ')) : '') + '</td>' +
          '<td class="sub">' + kit.esc(member.what) + '</td></tr>';
      }).join('');
      return '<div class="card"><h3>' + kit.esc(row.name) + ' &mdash; ' +
        '<code>' +
        kit.esc(row.short) + '</code>' +
        (row.offered ? '' :
         ' <span class="state-invalid">not offered</span>') +
        '</h3><div class="sub">' + kit.esc(row.what) + '</div>' +
        '<table><tr><th>Member</th><th></th><th>Type</th><th>What it is' +
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
        picked ? picked.sessionId : '');

    const typeOptions = (json.catalogue || []).map(function (row) {
      return '<option value="' + kit.esc(row.short) + '">' +
             kit.esc(row.name) +
        '</option>';
    }).join('');

    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so CAEP has nothing to run on. CAEP is a ' +
          'VOCABULARY over SSF rather than a family of its own: its events ' +
          'travel on SSF streams, are signed by the SSF signer and are ' +
          'delivered by the two SSF deliveries.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>CAEP is turned off</strong> ' +
          '(<code>caep.enabled</code>). The eight event types are dropped ' +
          'from <code>events_supported</code>, so a stream asking for one ' +
          'gets it back missing from <code>events_delivered</code> &mdash; ' +
          'which is the only notice SSF gives, and is exactly the case a ' +
          'receiver ought to be tested against. SSF itself is unaffected.')
        : '') +

      kit.note('<strong>CAEP</strong> (OpenID Continuous Access ' +
      'Evaluation Profile 1.0, final 2 September 2025) is the enterprise ' +
      '<strong>session</strong> vocabulary spoken over ' +
      '<a href="/admin/ssf">Shared Signals</a>. SSF is the PIPE and ' +
      'defines two events of its own, both about the pipe; these eight are ' +
      'about a session, and the sentence they carry is <em>this session is ' +
      'no longer trustworthy</em>. RISC says <em>this account is no longer ' +
      'trustworthy</em>, which is a different sentence and the whole ' +
      'reason there are two profiles.') +

      kit.warn('<strong>This is the one place in this service where an ' +
      'endpoint is not what starts the work.</strong> With ' +
      '<code>caep.autoEmit</code> on, a sign-in emits ' +
      '<code>session-established</code>, an authorization request answered ' +
      'from a session that already existed emits ' +
      '<code>session-presented</code>, and a sign-out emits ' +
      '<code>session-revoked</code> &mdash; on every stream that asked for ' +
      'the type and whose subjects cover that session, with nobody having ' +
      'typed anything. Every other family here answers a request. Turning ' +
      'it off restores the older and equally honest behaviour: every ' +
      'Security Event Token this service sends was asked for.') +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, 'sessions tracked') +
      kit.tile((json.eventTypes || []).length, 'event types') +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), 'events sent') +
      kit.tile((json.autoEmitActs || []).length, 'acts emit on their own') +
      '</div>' +

      (json.installed
        ? '<h2>Emit one by hand</h2>' +
          kit.note('Every one of the eight is also sent on its own when ' +
          'the act it describes happens here (a device\'s compliance ' +
          'since #164); this form sends one on demand, with the payload ' +
          'you choose. The subject is composed from the ' +
          'session you pick: SSF\'s <strong>complex</strong> subject, ' +
          'naming the person AND the session, because the person is not ' +
          'revoked and one session of theirs is. Leave the payload empty ' +
          'for a conforming specimen of the type.') +
          sessionChooser +
          (picked
            ? '<p class="note">Emitting about <strong>' +
              kit.esc(String(picked.username || picked.sub || '(unnamed)')) +
              '</strong>&rsquo;s session <code>' +
              kit.esc(picked.sessionId) +
              '</code>' +
              (picked.protocol
                ? ', established over ' + kit.esc(picked.protocol) : '') +
              '. The subject below is composed from it.</p>'
            : (wantedSession
                ? kit.warn('No live session has the id <code>' +
                  kit.esc(wantedSession) + '</code>. It may have been ' +
                  'signed out since this link was made &mdash; a revoked ' +
                  'row stays on <a href="/admin/caep-sessions">the ' +
                  'sessions page</a> and is not offered here. Search again ' +
                  'above.')
                : kit.note('Pick a session above and the form below will ' +
                  'emit about it. Until one is picked there is nothing to ' +
                  'be about: a CAEP event names a SESSION, and this form ' +
                  'will not compose a subject out of an identifier nobody ' +
                  'chose.'))) +
          (picked
            ? '<form method="post" action="/admin/caep"><div ' +
          'class="formrow"><input type="hidden" name="action" value="emit">' +
          '<input type="hidden" name="session_id" value="' +
          kit.esc(picked.sessionId) + '">' +
          '<label>Event <select name="type">' + typeOptions +
          '</select></label> ' +
          '<label>Initiated by <select name="initiating_entity">' +
          '<option value="admin">admin</option>' +
          '<option value="user">user</option>' +
          '<option value="policy">policy</option>' +
          '<option value="system">system</option></select></label>' +
          '</div><div class="formrow">' +
          '<label>Payload (JSON, optional) ' +
          '<input type="text" name="payload" size="60" ' +
          'placeholder="{&quot;current_status&quot;:' +
          '&quot;not-compliant&quot;}">' +
          '</label>' +
          '</div><div class="formrow">' +
          '<label>reason_admin <input type="text" name="reason_admin" ' +
          'size="40"></label> ' +
          '<label>reason_user <input type="text" name="reason_user" ' +
          'size="40"></label>' +
          '</div><div class="formrow"><button>Emit</button></div></form>'
            : '') +
          (liveSessions.length
            ? ''
            : kit.warn('There are no LIVE sessions to emit about. A CAEP ' +
              'event is ABOUT a session &mdash; the subject names one ' +
              '&mdash; so sign somebody in first. Anything that starts a ' +
              'session will do, and that is the point rather than a ' +
              'convenience: CAEP is a vocabulary about SESSIONS and not ' +
              'about OAuth, so an OIDC flow, a SAML 2.0 or SAML 1.1 ' +
              'sign-in, WS-Federation and SPNEGO all reach the same funnel ' +
              'here and all produce a row.'))
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
        ? '<details class="fold section"><summary>The eight event types' +
          '</summary><div class="foldbody">' +
          kit.note('Each row\'s members are the specification\'s own, ' +
          'with the four CAEP section 2 gives EVERY event beneath them: ' +
          '<code>event_timestamp</code>, <code>initiating_entity</code>, ' +
          '<code>reason_admin</code> and <code>reason_user</code>. All ' +
          'four are OPTIONAL, which surprises people about the first ' +
          '&mdash; a receiver deciding whether to end a session wants it ' +
          'more than anything else in the payload, and a conforming ' +
          'transmitter need not send one. ' +
          '<code>caep.omitEventTimestamp</code> produces that event on ' +
          'purpose.') +
          catalogue +
          '</div></details>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/caep') +

      kit.note('<a href="/admin/caep-sessions">The sessions and what has ' +
      'been said about them</a> &middot; ' +
      '<a href="/admin/ssf">the streams it all goes out on</a> &middot; ' +
      '<a href="/admin/caep?format=json">this page as JSON</a> &middot; ' +
      '<a href="/admin-api/caep">the same over the management API</a>');

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
   * @returns the chooser as HTML
   */
  static caepSessionChooser(here, sessions, selectedId) {
    const query = (here && here.query) || {};
    const carry = kit.pageParamsOf(query);
    delete carry.session;
    const live = (sessions || []).filter(function (row) {
      return String(row.state || '') !== 'revoked';
    });
    const entries = live.map(function (row) {
      const who = String(row.username || row.sub || '(unnamed)');
      const id = String(row.sessionId || '');
      return {
        key: id,
        // SEARCHED BY PERSON. The session identifier is in here too so that a
        // reader who has one — from a log, from an event they are chasing — can
        // paste it, which is the other half of how this control gets used.
        names: [who, String(row.sub || ''), id],
        label: who + ' — ' + id,
        detail: (row.protocol ? row.protocol + ', ' : '') +
          String(row.state || 'established') +
          (row.total ? ', ' + row.total + ' event(s) sent' : ', nothing sent'),
        href: '/admin/caep' + kit.queryWith(carry, { session: id }) +
          '#find-sessq'
      };
    });
    return kit.chooserPane({
      here: here, param: 'sessq', fromParam: 'sessfrom',
      label: 'Find a person',
      placeholder: 'part of a username, a subject or a session id',
      entries: entries, selectedKey: selectedId,
      nothing: 'No live session belongs to anybody matching that. This list ' +
        'holds the sessions this service still considers OPEN — a revoked ' +
        'one stays on <a href="/admin/caep-sessions">the sessions page</a> ' +
        'as evidence and is deliberately not offered here, because the state ' +
        'machine refuses a session-presented about a session that has ended.'
    });
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static riscBody(ctx, json) {

    const catalogue = (json.catalogue || []).map(function (row) {
      const members = row.members.map(function (member) {
        return '<tr><td><code>' + kit.esc(member.name) + '</code></td>' +
          '<td class="' + (member.required ? '' : 'sub') + '">' +
          (member.required ? 'required' : 'optional') + '</td>' +
          '<td class="sub"><code>' + kit.esc(member.type) + '</code>' +
          (member.values.length
            ? ' ' + kit.esc(member.values.join(' | ')) : '') + '</td>' +
          '<td class="sub">' + kit.esc(member.what) + '</td></tr>';
      }).join('');
      return '<div class="card"><h3>' + kit.esc(row.name) + ' &mdash; ' +
        '<code>' +
        kit.esc(row.short) + '</code>' +
        (row.offered ? '' :
         ' <span class="state-invalid">not offered</span>') +
        (row.deprecated
          ? ' <span class="state-invalid">deprecated</span>' : '') +
        '</h3><div class="sub">' + kit.esc(row.what) + '</div>' +
        ((row.subjectFormats || []).length
          ? '<div class="sub"><strong>Its subject must be</strong> <code>' +
            kit.esc(row.subjectFormats.join('</code> or <code>')) +
            '</code>, and it carries the OLD value.</div>'
          : '') +
        (members
          ? '<table><tr><th>Member</th><th></th><th>Type</th>' +
            '<th>What it is</th></tr>' + members + '</table>'
          : '<div class="sub">No payload members at all. The subject ' +
            'carries the entire message.</div>') +
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
        picked ? picked.accountId : '');

    const typeOptions = (json.catalogue || []).map(function (row) {
      return '<option value="' + kit.esc(row.short) + '">' +
             kit.esc(row.name) +
        (row.deprecated ? ' (deprecated)' : '') + '</option>';
    }).join('');

    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so RISC has nothing to run on. RISC is a ' +
          'VOCABULARY over SSF rather than a family of its own: its events ' +
          'travel on SSF streams, are signed by the SSF signer and are ' +
          'delivered by the two SSF deliveries.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>RISC is turned off</strong> ' +
          '(<code>risc.enabled</code>). The fourteen event types are ' +
          'dropped from <code>events_supported</code>, so a stream asking ' +
          'for one gets it back missing from <code>events_delivered</code> ' +
          '&mdash; which is the only notice SSF gives. SSF and CAEP are ' +
          'unaffected.')
        : '') +

      kit.note('<strong>RISC</strong> (OpenID RISC Profile Specification ' +
      '1.0, published 29 August 2025 and final on 2 September 2025) is the ' +
      '<strong>account</strong> vocabulary spoken over ' +
      '<a href="/admin/ssf">Shared Signals</a>, and the second of the two. ' +
      '<a href="/admin/caep">CAEP</a> says <em>this session is no longer ' +
      'trustworthy</em>; RISC says <em>this account is no longer ' +
      'trustworthy</em>. Those are two different sentences and the second ' +
      'is the larger by orders of magnitude &mdash; a revoked session is ' +
      'one sign-in at one relying party, and a purged account is every ' +
      'session that person has anywhere, for ever. CAEP is aimed WITHIN an ' +
      'enterprise and RISC ACROSS providers: its origin is a consumer ' +
      'provider noticing an account has been taken over and telling every ' +
      'site that account signs in to.') +

      kit.warn('<strong>Eleven of the fourteen carry no payload members ' +
      'at all, so the subject IS the message.</strong> ' +
      '<code>account-purged</code> says nothing but its own type and who ' +
      'it is about &mdash; which means a subject naming the wrong person ' +
      'is not a partly wrong event, it is a completely wrong one with ' +
      'nothing else in it to notice by. <code>risc.subjectFormat</code> ' +
      'below is therefore the most consequential setting on this page.') +

      kit.warn('<strong>This service emits RISC events when its own ' +
      'DIRECTORY changes</strong>, which is a different observer from ' +
      'CAEP\'s. With <code>risc.autoEmit</code> on, a person deleted emits ' +
      '<code>account-purged</code>, <code>active</code> going false or ' +
      'true emits <code>account-disabled</code> or ' +
      '<code>account-enabled</code>, and a changed mail address or ' +
      'telephone number emits <code>identifier-changed</code>. Those acts ' +
      'reach this directory over <a href="/admin/scim">SCIM</a>, over <a ' +
      'href="/admin/ldap">LDAP</a> and from the console alike, because the ' +
      'observer sits on the WRITE rather than on any one door.') +

      kit.note('<strong>Setting <code>active</code> to false DISABLES ' +
      'the account</strong> since 2026-09-17 — it read "deactivates ' +
      'nobody" until then. It writes the password-policy lock ' +
      '<code>pwdAccountLockedTime</code>, every door refuses that person ' +
      'while it is set, and everything they hold is ended at once. The ' +
      'RISC event is unchanged and is what it always was: a transmitter ' +
      'reports and a receiver decides — what changed is that this service ' +
      'now acts on it too.') +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, 'accounts tracked') +
      kit.tile((json.eventTypes || []).length, 'event types') +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), 'events sent') +
      kit.tile((json.autoEmitActs || []).length, 'acts emit on their own') +
      '</div>' +

      (json.installed && json.googleSubjectType
        ? kit.warn('<code>risc.googleSubjectType</code> is on, so every ' +
          'RISC subject leaving here spells its discriminator ' +
          '<code>subject_type</code> rather than <code>format</code>. That ' +
          'is RISC section 3.1\'s own compatibility note about a ' +
          'production transmitter in the field: the specification says new ' +
          'services MUST NOT use the name and then tells relying parties ' +
          'they need code to work around it anyway. This is how a receiver ' +
          'finds out whether it has that code. CAEP and SSF events are ' +
          'untouched.')
        : '') +

      (json.installed
        ? '<h2>Emit one by hand</h2>' +
          kit.note('Ten of the fourteen describe things nothing here does ' +
          '&mdash; no breach corpus is searched by this service and no ' +
          'recovery flow runs in it &mdash; so this form is the only way ' +
          'they are ever produced. <strong>Four of those ten CHANGE REAL ' +
          'STATE when they go</strong>: RISC section 2.8 defines each ' +
          'opt-out event as <em>the account is in this state</em> rather ' +
          'than as a report that it moved, so emitting one here IS the ' +
          'transition. The subject is composed from the account you pick, ' +
          'in the format <code>risc.subjectFormat</code> names &mdash; ' +
          'except for the two identifier events, which use an email ' +
          'address regardless, because for those two the identifier is the ' +
          'message.') +
          accountChooser +
          (picked
            ? '<p class="note">Emitting about <strong>' +
              kit.esc(String(picked.username || picked.accountId)) +
              '</strong> &mdash; <code>' + kit.esc(picked.subject || '') +
              '</code>. Its lifecycle is <code>' +
              kit.esc(picked.lifecycle) +
              '</code> and its opt-out state is <code>' +
              kit.esc(picked.optOut) +
              '</code>.</p>'
            : kit.note('Pick an account above, or type one below. ' +
              '<strong>An account this service has never held is ' +
              'accepted</strong>, which is the opposite of what the CAEP ' +
              'form does with an unknown session and is the ' +
              'specification\'s difference rather than an inconsistency: a ' +
              'session identifier this service never minted is one it can ' +
              'compose no subject from, and an account is a person. RISC ' +
              'is aimed ACROSS providers, so the account a receiver is ' +
              'warned about is usually one it has never seen.')) +
          '<form method="post" action="/admin/risc"><div class="formrow">' +
          '<input type="hidden" name="action" value="emit">' +
          '<label>Account <input type="text" name="account_id" size="24" ' +
          'value="' + kit.esc(picked ? picked.accountId : '') +
          '"></label> <label>Event <select name="type">' + typeOptions +
          '</select></label>' +
          '</div><div class="formrow">' +
          '<label>Payload (JSON, optional) ' +
          '<input type="text" name="payload" size="60" ' +
          'placeholder="{&quot;reason&quot;:&quot;hijacking&quot;}">' +
          '</label>' +
          '</div><div class="formrow">' +
          '<label>reason_admin <input type="text" name="reason_admin" ' +
          'size="40"></label> ' +
          '<label>reason_user <input type="text" name="reason_user" ' +
          'size="40"></label>' +
          '</div>' +
          kit.note('The two reason fields reach the wire for ONE of the ' +
          'fourteen types. RISC gives <code>reason_admin</code>, ' +
          '<code>reason_user</code> and <code>event_timestamp</code> to ' +
          '<code>credential-compromise</code> and to nothing else &mdash; ' +
          'where CAEP gives four claims to all eight of its own &mdash; so ' +
          'on any other type they are composed and dropped by the ' +
          'catalogue rather than sent as members the specification does ' +
          'not define.') +
          '<div class="formrow"><button>Emit</button></div></form>'
        : '') +

      // Folded and closed by default, for the reason the CAEP catalogue is:
      // fourteen cards is seven screens of REFERENCE between the controls
      // above and the settings below.
      (json.installed
        ? '<details class="fold section"><summary>The fourteen event types' +
          '</summary><div class="foldbody">' +
          kit.note('<strong>Only one of the fourteen has a required ' +
          'member</strong> &mdash; <code>credential-compromise</code>\'s ' +
          '<code>credential_type</code>, which RISC defines BY REFERENCE ' +
          'to CAEP\'s <code>credential-change</code>, so the two lists are ' +
          'the same list rather than two alike ones. Eleven have no ' +
          'members at all. And one member name in the whole of Shared ' +
          'Signals uses a HYPHEN: <code>identifier-changed</code>\'s ' +
          '<code>new-value</code>, where everything else in all three ' +
          'vocabularies is snake_case, so <code>new_value</code> typed ' +
          'from habit produces an event that delivers and says nothing.') +
          catalogue +
          '</div></details>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/risc') +

      kit.note('<a href="/admin/risc-accounts">The accounts and what has ' +
      'been said about them</a> &middot; ' +
      '<a href="/admin/caep">the other vocabulary</a> &middot; ' +
      '<a href="/admin/ssf">the streams it all goes out on</a> &middot; ' +
      '<a href="/admin/risc?format=json">this page as JSON</a> &middot; ' +
      '<a href="/admin-api/risc">the same over the management API</a>');

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
   * @returns the chooser as HTML
   */
  static riscAccountChooser(here, accounts, selectedId) {
    const query = (here && here.query) || {};
    const carry = kit.pageParamsOf(query);
    delete carry.acctq2;
    const entries = (accounts || []).map(function (row) {
      const who = String(row.username || row.accountId || '(unnamed)');
      const id = String(row.accountId || '');
      return {
        key: id,
        names: [who, id, String(row.sub || ''), String(row.email || '')]
          .concat(row.formerIdentifiers || []),
        label: who + (row.email && row.email !== who ? ' — ' + row.email : ''),
        detail: String(row.lifecycle || 'active') + ', ' +
          String(row.optOut || 'opt-in') +
          (row.total ? ', ' + row.total + ' event(s) sent' : ', nothing sent') +
          (row.suppressed ? ', ' + row.suppressed + ' suppressed' : ''),
        href: '/admin/risc' + kit.queryWith(carry, { acctq2: id }) +
          '#find-acctq2'
      };
    });
    return kit.chooserPane({
      here: here, param: 'acctq2', fromParam: 'acctfrom',
      label: 'Find an account',
      placeholder: 'part of a username, a subject or an email address',
      entries: entries, selectedKey: selectedId,
      nothing: 'No tracked account matches that. This register holds one row ' +
        'per account this service has been told anything about &mdash; ' +
        'including ones that no longer exist &mdash; and it will be empty ' +
        'until the directory changes or somebody emits an event by hand. You ' +
        'can type an account name into the form below regardless: a RISC ' +
        'event names a person, and this service can name any person at all.'
    });
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static caepSessionsBody(ctx, json) {
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
                                    appState.page.paging);
    // EVERY parameter the reader is already carrying, so that paging this
    // table moves nothing else on the page. kit.pageNavPair() overrides only
    // the
    // one name off the paging object it is handed.
    const navParams = kit.pageParamsOf(ctx.query);
    const sessNav = kit.pageNavPair('/admin/caep-sessions', navParams,
                                     sessPage.paging);
    // The list AS THE READER LEFT IT, for the drill-down links and for the
    // Reset buttons' `back` field. kit.listViewOf() is the whitelist; `back` is
    // the same set as a query string, rebuilt from it rather than echoed.
    const listView = kit.listViewOf('/admin/caep-sessions', ctx.query);
    const back = kit.queryWith(listView, {});

    const rows = sessPage.shown.length
      ? sessPage.shown.map(function (row) {
          return CaepRiscPage.caepSessionRow(row, shorts, prefix, listView,
            back);
        }).join('')
      : '<tr><td colspan="' + (shorts.length + 8) + '">' +
        (sessWanted
          ? 'No tracked session matches <code>' + kit.esc(sessWanted) +
            '</code>. ' +
            ((json.sessions || []).length
              ? (json.sessions || []).length + ' session(s) are tracked ' +
                'under other names.'
              : 'None is tracked at all yet.')
          : 'No sessions are tracked. Sign somebody in &mdash; an OIDC ' +
            'flow, a SAML 2.0 sign-in, WS-Federation &mdash; and a row ' +
            'appears here whether or not any stream is agreed, which is ' +
            'what makes &ldquo;nothing arrived&rdquo; traceable to ' +
            '&ldquo;nobody asked&rdquo;.') +
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
              : 'none of CAEP\'s eight') + '</td></tr>';
        }).join('')
      : '<tr><td colspan="6">No streams. Nothing this service says about a ' +
        'session has anywhere to go, and every row above will show a count ' +
        'of zero however many people sign in.</td></tr>';

    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so no session state is tracked.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>CAEP is turned off</strong> ' +
          '(<code>caep.enabled</code>), so nothing new is being recorded ' +
          'here. What is below is what was recorded before it was turned ' +
          'off.')
        : '') +
      (json.installed && json.enabled && !json.autoEmit
        ? kit.warn('<strong>Automatic emission is off</strong> ' +
          '(<code>caep.autoEmit</code>). Sessions still appear here and ' +
          'their state still follows what really happens, and nothing goes ' +
          'out unless somebody emits it from <a href="/admin/caep">the ' +
          'CAEP page</a>. That is this service\'s older behaviour: every ' +
          'Security Event Token it sends was asked for.')
        : '') +

      kit.note('One row per session this service has held, ' +
      '<strong>including sessions it no longer holds</strong>. That is ' +
      'deliberate and it is the whole reason this page exists: the session ' +
      'store forgets a session the moment it is signed out, so a row whose ' +
      'state is <code>revoked</code> is the only remaining evidence that ' +
      'it existed and was revoked. The counts are per event type and they ' +
      'never forget; WHICH events those were is <a ' +
      'href="/admin/caep-sessions/session">each session\'s own page</a>, ' +
      'which is a different question and is a click away from every ' +
      'identifier below.') +

      (json.installed && json.omitEventTimestamp
        ? kit.warn('<code>caep.omitEventTimestamp</code> is on, so every ' +
          'event leaving here carries NO <code>event_timestamp</code>. ' +
          'That is perfectly conforming &mdash; CAEP section 2 makes it ' +
          'optional &mdash; and it is what a receiver that assumes one ' +
          'falls over on.')
        : '') +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, 'sessions') +
      kit.tile((json.sessions || []).filter(function (row) {
        return row.state === 'revoked';
      }).length, 'revoked') +
      kit.tile((json.sessions || []).filter(function (row) {
        return row.state === 'presented';
      }).length, 'presented (SSO)') +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), 'events sent') +
      kit.tile((json.streams || []).filter(function (row) {
        return row.takes.length;
      }).length, 'streams taking CAEP') +
      '</div>' +

      '<h2>Sessions</h2>' +
      kit.note('<strong>Every identifier in the first column opens that ' +
      'session on its own page</strong> &mdash; what has actually been ' +
      'sent about it, in order, with what the register noticed as each one ' +
      'was applied. That was a card per session under this table until ' +
      '2026-09-04, which meant this table was off the top of the screen ' +
      'the moment more than a handful of people had signed in.') +
      kit.sectionSearchForm({
        path: '/admin/caep-sessions', query: ctx.query,
        param: 'sessq', pageParam: 'sessionsPage',
        label: 'Narrow to a person or a session',
        placeholder: 'a username, a subject or a session id',
        what: 'It matches the username, the <code>sub</code>, the session ' +
          'identifier, the SSF subject as a receiver was sent it, and the ' +
          'protocol the session was started through &mdash; because a ' +
          'reader arrives holding exactly one of those and does not know ' +
          'which column it will be in. It narrows this table only; the ' +
          'streams below it are about the transmitter rather than about ' +
          'anybody.'
      }) +
      kit.perPageForm('/admin/caep-sessions', 'sessq', sessWanted,
                       sessPage.paging.perPage,
                       'Only the sessions table is paged. The streams ' +
                       'under it are one row per stream agreed with this ' +
                       'transmitter, which is a number somebody configured ' +
                       'rather than one that grows by itself.',
                       {}) +
      sessNav.head +
      '<table><tr><th>Session</th><th>Who</th><th>State</th>' +
      '<th>Assurance</th><th>Device</th><th>Risk</th>' + headers +
      '<th>Total</th><th></th></tr>' + rows + '</table>' +
      sessNav.foot +

      '<h2>Where a CAEP event could go</h2>' +
      kit.note('A session with a count of zero almost always means ' +
      '<strong>no stream asked for that type</strong> rather than anything ' +
      'being wrong. SSF has no refusal for an event type a transmitter ' +
      'will not deliver &mdash; its absence from ' +
      '<code>events_delivered</code> is the only notice a receiver gets ' +
      '&mdash; so this table is where that shows up.') +
      '<table><tr><th>Stream</th><th>aud</th><th>Status</th><th>Delivery' +
      '</th>' +
      '<th>Subjects</th><th>CAEP types it takes</th></tr>' + streamRows +
      '</table>' +

      '<h2>Per application</h2>' +
      kit.note('<strong>What this transmitter has said to each receiver, ' +
      'across every session.</strong> The table above this one is per ' +
      'STREAM and the one above that is per SESSION; this is the third ' +
      'question, and it is the one somebody actually arrives with once ' +
      'more than one receiver exists: <em>is the application I am testing ' +
      'getting anything, and what.</em> The counts are per event type and ' +
      'they never forget &mdash; they are counted when the Security Event ' +
      'Token is built and queued, which is when this service has SAID ' +
      'something, so a poll stream nobody has polled yet still shows what ' +
      'is waiting for it.') +
      kit.note('<strong>An application with no stream is a row rather ' +
      'than an omission</strong>, and it is the commonest state a receiver ' +
      'under test is in: declared here with the Shared Signals box ticked, ' +
      'nothing agreed yet. Every count is zero and the <em>Streams</em> ' +
      'column says so, which is the first thing to check when nothing ' +
      'arrives. A row whose <em>Takes</em> column says <code>none of ' +
      'CAEP\'s eight</code> is the second: SSF has no refusal for a type a ' +
      'transmitter will not deliver, so the type\'s absence from ' +
      '<code>events_delivered</code> is the only notice a receiver ever ' +
      'gets.') +
      kit.note('<strong>The identifier is what the receiver authenticated ' +
      'as when it created the stream, and <code>aud</code> is what it ' +
      'asked its Security Event Tokens to be addressed to.</strong> They ' +
      'are different fields and this is the only place both are shown: ' +
      '<code>aud</code> is REQUIRED on a stream and is deliberately never ' +
      'defaulted to the caller, because an audience this service invented ' +
      'would be one the receiver never learns it has to check for. Where ' +
      'they agree the column says so rather than repeating the name. A row ' +
      'named <em>(no application)</em> is the collected total for streams ' +
      'agreed while <code>ssf.authRequired</code> was off &mdash; there ' +
      'was no principal to record, and those events are real.') +
      kit.sectionSearchForm({
        path: '/admin/caep-sessions', query: ctx.query,
        param: 'appq', pageParam: 'applicationsPage',
        label: 'Narrow to a receiver',
        placeholder: 'an application name, an identifier or an aud',
        what: 'It matches the application name, the identifier it ' +
          'authenticated as, and the <code>aud</code> on its streams ' +
          '&mdash; the three strings a reader arrives holding, which are ' +
          'routinely different. It does NOT match the event types: a ' +
          'receiver that takes none of the eight is exactly the row ' +
          'somebody is looking for when they ask why nothing arrived.'
      }) +
      appNav.head +
      '<table><tr><th>Receiver</th><th>Streams</th><th>aud</th><th>Takes' +
      '</th>' +
      headers + '<th>Total</th><th>Sessions</th><th>Delivered / failed</th>' +
      '</tr>' +
      (appState.page.shown.length
        ? appState.page.shown.map(function (row) {
            return CaepRiscPage.caepApplicationRow(row, shorts, prefix);
          }).join('')
        : '<tr><td colspan="' + (shorts.length + 7) + '">' +
          (appState.wanted
            ? 'No receiver matches <code>' + kit.esc(appState.wanted) +
              '</code>. ' +
              ((json.applications || []).length
                ? (json.applications || []).length + ' receiver(s) are ' +
                  'known under other names.'
                : 'None is known at all yet.')
            : 'No application here supports Shared Signals yet. An entry ' +
              'appears the moment a receiver creates a stream at ' +
              '<code>/ssf/stream</code>, and one can be declared ahead of ' +
              'that by ticking Shared Signals on ' +
              '<a href="/admin/applications/new">a new application</a>.') +
          '</td></tr>') +
      '</table>' +
      appNav.foot +
      kit.note((appState.matched.length) + ' receiver(s) match' +
      (appState.page.paging.pages > 1
        ? ', of which rows ' + appState.page.paging.firstRow + '&ndash;' +
          appState.page.paging.lastRow + ' are on this page (' +
          appState.page.paging.page + ' of ' + appState.page.paging.pages +
          ')'
        : '') +
      '. Busiest first. <em>Delivered / failed</em> is the PIPE &mdash; ' +
      'how many Security Event Tokens left this service and how many could ' +
      'not be handed over &mdash; and it is a different number from the ' +
      'total beside it, which is what was SAID: on a poll stream nothing ' +
      'is delivered until the receiver asks, and the two agreeing is a ' +
      'property of push delivery rather than of a healthy transmitter. ' +
      '<em>Sessions</em> counts the DISTINCT sessions this receiver has ' +
      'been told about, across all of its streams together.') +


      (json.installed
        ? '<form method="post" action="/admin/caep">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="from" value="sessions">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<button class="secondary">Clear the register</button>' +
          '</div></form>' +
          kit.note('Clearing forgets the RECORD. Nobody is signed out and ' +
          'no stream is touched &mdash; this page is what has been SAID ' +
          'about these sessions, and a control here that ended one would ' +
          'be a monitoring page with a weapon on it.')
        : '') +

      kit.note('<a href="/admin/caep">The settings, the catalogue and the ' +
      'by-hand emit form</a> &middot; ' +
      '<a href="/admin/ssf">the streams</a> &middot; ' +
      '<a href="/admin/metrics">the sessions this service still holds</a> ' +
      '&middot; <a href="/admin/caep-sessions?format=json">this page as ' +
      'JSON</a>');

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
   * @returns the row as HTML
   */
  static caepApplicationRow(row, shorts, prefix) {
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
          : ' <span class="state-invalid">(' + kit.esc(String(row.enabled)) +
            ' enabled)</span>') +
        '<div class="sub">' + kit.esc(row.deliveries.join(', ')) + '</div>'
      : '<span class="state-none" title="' +
        kit.esc('Declared for Shared Signals and no stream has been agreed. ' +
                 'That is the ordinary state of a receiver that has not ' +
                 'connected yet, and it is the first thing to check when ' +
                 'nothing arrives.') +
        '">none</span>';
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
            kit.esc('The receiver asked its Security Event Tokens to be ' +
                     'addressed to the same name it authenticated as. That ' +
                     'is the ordinary case and not a requirement: `aud` is ' +
                     'the receiver\'s own choice and this service never ' +
                     'defaults it.') +
            '">the same</span>'
          : kit.shortened(row.audiences.join(', '), 20))
      : '<span class="sub" title="' +
        kit.esc('No stream, so nothing is addressed anywhere yet.') +
        '">&mdash;</span>';
    const out = '<tr>' +
      '<td>' + who + '</td>' +
      '<td>' + streams + '</td>' +
      '<td class="sub">' + audience + '</td>' +
      '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
      kit.esc(row.takes.length ? String(row.takes.length) + ' of 8'
                                : 'none of CAEP\'s eight') + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="sub">' + kit.esc(String(row.sessions)) + '</td>' +
      '<td class="sub">' + kit.esc(String(row.delivered)) + ' / ' +
      '<span class="' + (row.failed ? 'state-invalid' : 'sub') + '">' +
      kit.esc(String(row.failed)) + '</span>' +
      (row.lastPushError
        ? '<div class="sub" title="' + kit.esc(row.lastPushError) +
          '">last error recorded</div>'
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
   * @returns the row as HTML
   */
  static caepSessionRow(row, shorts, prefix, listView, back) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    const href = '/admin/caep-sessions/session' +
      kit.queryWith(listView || {}, { id: row.sessionId });
    const out = '<tr>' +
      '<td><a href="' + kit.esc(href) + '" title="' +
      kit.esc('Everything that has been said about this session, in order') +
      '"><code>' + kit.esc(row.sessionId) + '</code></a>' +
      '<div class="sub">' + kit.esc(row.protocol || '') + '</div></td>' +
      '<td>' + kit.esc(row.username || row.sub || '(unknown)') +
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
      '<button class="secondary">Reset</button></form></td>' +
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
                                     state.page.paging);
    const appNav = kit.pageNavPair('/admin/risc-accounts', navParams,
                                    appState.page.paging);
    const listView = kit.listViewOf('/admin/risc-accounts', ctx.query);
    const back = kit.queryWith(listView, {});

    const rows = state.page.shown.length
      ? state.page.shown.map(function (row) {
          return CaepRiscPage.riscAccountRow(row, shorts, prefix, listView,
            back);
        }).join('')
      : '<tr><td colspan="' + (shorts.length + 8) + '">' +
        (state.wanted
          ? 'No tracked account matches <code>' + kit.esc(state.wanted) +
            '</code>. ' +
            ((json.accounts || []).length
              ? (json.accounts || []).length + ' account(s) are tracked ' +
                'under other names.'
              : 'None is tracked at all yet.')
          : 'No accounts are tracked. Change one in the directory &mdash; ' +
            'delete a person, set <code>active</code> to false over ' +
            '<a href="/admin/scim">SCIM</a>, change a mail address with an ' +
            '<code>ldapmodify</code> &mdash; and a row appears here ' +
            'whether or not any stream is agreed, which is what makes ' +
            '&ldquo;nothing arrived&rdquo; traceable to &ldquo;nobody ' +
            'asked&rdquo;.') +
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
              : 'none of RISC\'s fourteen') + '</td></tr>';
        }).join('')
      : '<tr><td colspan="6">No streams. Nothing this service says about ' +
        'an account has anywhere to go, and every row above will show a ' +
        'count of zero however much the directory changes.</td></tr>';

    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process</strong>, so no account state is tracked.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>RISC is turned off</strong> ' +
          '(<code>risc.enabled</code>), so nothing new is being recorded ' +
          'here. What is below is what was recorded before it was turned ' +
          'off.')
        : '') +
      (json.installed && json.enabled && !json.autoEmit
        ? kit.warn('<strong>Automatic emission is off</strong> ' +
          '(<code>risc.autoEmit</code>). Accounts still appear here and ' +
          'their state still follows what really happens in the directory, ' +
          'and nothing goes out unless somebody emits it from ' +
          '<a href="/admin/risc">the RISC page</a>.')
        : '') +

      kit.note('One row per account this service has been told anything ' +
      'about, <strong>including accounts that no longer exist</strong>. ' +
      'That is deliberate and it is the whole reason this page exists: a ' +
      'purged account is gone from the directory entirely, so a row whose ' +
      'lifecycle is <code>purged</code> is the only remaining evidence ' +
      'that this service ever told anybody it was. The counts are per ' +
      'event type and they never forget; WHICH events those were is <a ' +
      'href="/admin/risc-accounts/account">each account\'s own page</a>.') +

      kit.note('<strong>The lifecycle and the opt-out state are two ' +
      'columns and not one.</strong> They move independently: an account ' +
      'can be opted out and perfectly healthy, or compromised and still ' +
      'exchanging. A CAEP session has one state because a session is alive ' +
      'or it is not; an account has three that a receiver acts on ' +
      'differently.') +

      (json.installed && json.honourOptOut
        ? kit.note('<code>risc.honourOptOut</code> is on, so an account ' +
          'in the <code>opt-out</code> state has its events SUPPRESSED and ' +
          'the <em>Suppressed</em> column counts them &mdash; the one ' +
          'number on this page that says a receiver heard nothing on ' +
          'purpose. The four opt-out events themselves are never ' +
          'suppressed: <code>opt-out-effective</code> is an event ' +
          'announcing that there will be no more events, and ' +
          '<code>opt-in</code> is the only way a receiver ever learns the ' +
          'account came back.')
        : kit.warn('<code>risc.honourOptOut</code> is OFF, so events go ' +
          'out about accounts that have opted out of RISC exchange. RISC ' +
          'section 2.8 says an opted-out account is not participating; ' +
          'this is how a receiver that ignores an opt-out gets to be shown ' +
          'doing it.')) +

      '<div class="tiles">' +
      kit.tile(json.tracked || 0, 'accounts') +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.lifecycle === 'purged';
      }).length, 'purged') +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.lifecycle === 'disabled';
      }).length, 'disabled') +
      kit.tile((json.accounts || []).filter(function (row) {
        return row.optOut !== 'opt-in';
      }).length, 'opted out') +
      kit.tile(Object.keys(json.totals || {}).reduce(function (n, uri) {
        return n + json.totals[uri];
      }, 0), 'events sent') +
      kit.tile((json.streams || []).filter(function (row) {
        return row.takes.length;
      }).length, 'streams taking RISC') +
      '</div>' +

      '<h2>Accounts</h2>' +
      kit.note('<strong>Every identifier in the first column opens that ' +
      'account on its own page</strong> &mdash; what has actually been ' +
      'sent about it, in order, with what the register noticed as each one ' +
      'was applied.') +
      kit.sectionSearchForm({
        path: '/admin/risc-accounts', query: ctx.query,
        param: 'acctq', pageParam: 'accountsPage',
        label: 'Narrow to an account',
        placeholder: 'a username, a subject, an email address or a DN',
        what: 'It matches the account identifier, the <code>sub</code>, ' +
          'the email address, the telephone number, the SSF subject as a ' +
          'receiver was sent it, the directory DN &mdash; and every ' +
          'identifier this account has been known by FORMERLY. That last ' +
          'one is not thoroughness: <code>identifier-changed</code> is an ' +
          'event about the key itself, so the address a reader arrives ' +
          'holding is routinely the one the account no longer has.'
      }) +
      kit.perPageForm('/admin/risc-accounts', 'acctq', state.wanted,
                       state.page.paging.perPage,
                       'Only the accounts table is paged.', {}) +
      acctNav.head +
      kit.wideTable('Accounts',
        '<table><tr><th>Account</th><th>Subject</th><th>Lifecycle</th>' +
        '<th>Opt-out</th><th>Credential</th>' + headers +
        '<th>Total</th><th>Suppressed</th><th></th></tr>' + rows +
        '</table>') +
      acctNav.foot +

      '<h2>Where a RISC event could go</h2>' +
      kit.note('An account with a count of zero almost always means ' +
      '<strong>no stream asked for that type</strong> rather than anything ' +
      'being wrong. SSF has no refusal for an event type a transmitter ' +
      'will not deliver &mdash; its absence from ' +
      '<code>events_delivered</code> is the only notice a receiver gets ' +
      '&mdash; so this table is where that shows up.') +
      '<table><tr><th>Stream</th><th>aud</th><th>Status</th><th>Delivery' +
      '</th>' +
      '<th>Subjects</th><th>RISC types it takes</th></tr>' + streamRows +
      '</table>' +

      '<h2>Per application</h2>' +
      kit.note('<strong>What this transmitter has said to each receiver, ' +
      'across every account.</strong> The table above this one is per ' +
      'STREAM and the one above that is per ACCOUNT; this is the third ' +
      'question, and it is the one somebody arrives with once more than ' +
      'one receiver exists.') +
      kit.sectionSearchForm({
        path: '/admin/risc-accounts', query: ctx.query,
        param: 'rappq', pageParam: 'rapplicationsPage',
        label: 'Narrow to a receiver',
        placeholder: 'an application name, an identifier or an aud',
        what: 'It matches the application name, the identifier it ' +
          'authenticated as, and the <code>aud</code> on its streams. It ' +
          'does NOT match the event types: a receiver that takes none of ' +
          'the fourteen is exactly the row somebody is looking for when ' +
          'they ask why nothing arrived.'
      }) +
      appNav.head +
      kit.wideTable('Per application',
        '<table><tr><th>Receiver</th><th>Streams</th><th>aud</th>' +
        '<th>Takes</th>' + headers +
        '<th>Total</th><th>Accounts</th><th>Delivered / failed</th></tr>' +
        (appState.page.shown.length
          ? appState.page.shown.map(function (row) {
              return CaepRiscPage.riscApplicationRow(row, shorts, prefix);
            }).join('')
          : '<tr><td colspan="' + (shorts.length + 7) + '">' +
            (appState.wanted
              ? 'No receiver matches <code>' + kit.esc(appState.wanted) +
                '</code>.'
              : 'No application here supports Shared Signals yet. An entry ' +
                'appears the moment a receiver creates a stream at ' +
                '<code>/ssf/stream</code>.') +
            '</td></tr>') +
        '</table>') +
      appNav.foot +

      (json.installed
        ? '<form method="post" action="/admin/risc">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="from" value="accounts">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<button class="secondary">Clear the register</button>' +
          '</div></form>' +
          kit.note('Clearing forgets the RECORD. <strong>Nobody is ' +
          'disabled, nobody is deleted and no directory entry is ' +
          'touched</strong> &mdash; this page is what has been SAID about ' +
          'these accounts, and a control here that purged one would be a ' +
          'monitoring page with a weapon on it.')
        : '') +

      kit.note('<a href="/admin/risc">The settings, the catalogue and the ' +
      'by-hand emit form</a> &middot; ' +
      '<a href="/admin/caep-sessions">what has been said about ' +
      'SESSIONS</a> &middot; ' +
      '<a href="/admin/ssf">the streams</a> &middot; ' +
      '<a href="/admin/users">the people themselves</a> &middot; ' +
      '<a href="/admin/risc-accounts?format=json">this page as JSON</a>');

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
   * @returns the row as HTML
   */
  static riscAccountRow(row, shorts, prefix, listView, back) {
    const counts = shorts.map(function (short) {
      const n = row.counts[prefix + short] || 0;
      return '<td class="' + (n ? '' : 'sub') + '">' + kit.esc(String(n)) +
             '</td>';
    }).join('');
    const href = '/admin/risc-accounts/account' +
      kit.queryWith(listView || {}, { id: row.accountId });
    const out = '<tr>' +
      '<td><a href="' + kit.esc(href) + '" title="' +
      kit.esc('Everything that has been said about this account, in order') +
      '"><code>' + kit.esc(row.accountId) + '</code></a>' +
      (row.email
        ? '<div class="sub">' + kit.esc(row.email) + '</div>' : '') + '</td>' +
      '<td class="sub">' + kit.esc(row.subject || '—') + '</td>' +
      CaepRiscPage.riscLifecycleCell(row.lifecycle) +
      CaepRiscPage.riscOptCell(row.optOut) +
      '<td class="' + (row.credentialStanding === 'compromised'
        ? 'state-invalid' : 'sub') + '">' +
      kit.esc(row.credentialStanding || '—') + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="' + (row.suppressed ? 'state-invalid' : 'sub') + '" title="' +
      kit.esc('Events this transmitter built and did NOT send, because the ' +
               'account is in the RISC opt-out state. A count here is the ' +
               'one number on this page that says a receiver heard nothing ' +
               'ON PURPOSE.') +
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
      '<button class="secondary">Reset</button></form></td>' +
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
   * @returns the row as HTML
   */
  static riscApplicationRow(row, shorts, prefix) {
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
          : ' <span class="state-invalid">(' + kit.esc(String(row.enabled)) +
            ' enabled)</span>') +
        '<div class="sub">' + kit.esc(row.deliveries.join(', ')) + '</div>'
      : '<span class="state-none" title="' +
        kit.esc('Declared for Shared Signals and no stream has been agreed.') +
        '">none</span>';
    const audience = row.audiences.length
      ? (row.audiences.length === 1 && row.audiences[0] === row.identifier
          ? '<span class="sub">the same</span>'
          : kit.shortened(row.audiences.join(', '), 20))
      : '<span class="sub">&mdash;</span>';
    const out = '<tr>' +
      '<td>' + who + '</td>' +
      '<td>' + streams + '</td>' +
      '<td class="sub">' + audience + '</td>' +
      '<td class="' + (row.takes.length ? '' : 'state-invalid') + '">' +
      kit.esc(row.takes.length ? String(row.takes.length) + ' of 14'
                                : 'none of RISC\'s fourteen') + '</td>' +
      counts +
      '<td><strong>' + kit.esc(String(row.total)) + '</strong></td>' +
      '<td class="sub">' + kit.esc(String(row.accounts)) + '</td>' +
      '<td class="sub">' + kit.esc(String(row.delivered)) + ' / ' +
      '<span class="' + (row.failed ? 'state-invalid' : 'sub') + '">' +
      kit.esc(String(row.failed)) + '</span>' +
      (row.lastPushError
        ? '<div class="sub" title="' + kit.esc(row.lastPushError) +
          '">last error recorded</div>'
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
   * @returns the cell as HTML
   */
  static riscOptCell(state) {
    const cls = state === 'opt-out' ? 'state-invalid'
      : (state === 'opt-out-initiated' ? '' : 'sub');
    const title = state === 'opt-out'
      ? 'RISC section 2.8: this account is not participating in event ' +
        'exchange, so nothing but an opt-out event is sent about it while ' +
        'risc.honourOptOut is on.'
      : (state === 'opt-out-initiated'
          ? 'The person asked to stop and exchange CARRIES ON for a while. ' +
            'That delay exists to stop a hijacker opting out the moment they ' +
            'take an account over and silencing the events that would report ' +
            'them.'
          : 'Participating in RISC event exchange.');
    const out = '<td class="' + cls + '" title="' + kit.esc(title) + '">' +
      kit.esc(state) + '</td>';
    return out;
  }
}

export = CaepRiscPage;
