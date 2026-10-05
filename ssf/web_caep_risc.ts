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
      // `script-src 'none'` is untouched — the same answer kit.note() gives, one
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
  // argument for replacing it is kit.chooserPane()'s own, one register further on:
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
}

export = CaepRiscPage;
