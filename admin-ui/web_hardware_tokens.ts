// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_hardware_tokens.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → HARDWARE TOKENS (#1955 P1), drawn in the browser from `GET
// /admin-api/hardware-tokens` (`mgmt-api/hardware_tokens_api.ts`): the
// realm's physical security keys and smart cards, each recorded from its own
// attestation (`common/hardware_tokens.ts`), paged and searched by serial or
// person, with a "Report lost" button on each active one, which posts
// `lost` to `/admin/hardware-tokens` and so reaches `POST
// /admin-api/hardware-tokens/lost` (rule 7).
//
// IN DIRECTORY because its store is somebody's and it is a destination
// (`admin-ui/CLAUDE.md`, the filing rule): the device register's sibling,
// beside it. Two tabs, framed as every Directory tab is; the lead is the
// Metadata:
//
//   * `tokens`, the register's list (P1);
//   * `oath` (#1955 P4), the imported OATH token inventory, composed from
//     `GET /admin-api/hardware-tokens/oath` under its own query names
//     (`oq`, `ostatus`, `opage`, so its pager moves its list and not the
//     register's), with the import form (a PSKC seed file pasted or loaded
//     from disk into the textarea in the browser, and its pre-shared key or
//     password, which the browser sends once and nothing keeps), an Assign
//     form on each unassigned token and Remove on each that is not
//     assigned. Each posts to `/admin/hardware-tokens` and so reaches `POST
//     /admin-api/hardware-tokens/{import-pskc,assign-oath,remove-oath}`.
//
// #1955 P2 adds two tabs: Enrol PIV (the PIV enrolment form for a named
// person: the slot profile, the request and the two attestation
// certificates, posting `enrol-piv`) and Escrowed keys (a person's escrowed
// piv-key-management certificates, the view's `escrowed` when the search
// names a person, each with "Recover key", posting `recover-key`, which the
// access-control policy decides on PIV_KEY_RECOVERY). What either act hands
// over is drawn once by `web_answers.ts`.
//
// A static utility class, on `web_kit.ts`'s terms: it holds no state, logs
// nothing, and is bundled for a browser.
// ---------------------------------------------------------------------------
import WebKit = require('./web_kit');

type Json = any;

const PAGE = '/admin/hardware-tokens';

/**
 * Draws Directory → Hardware tokens from its view.
 */
class HardwareTokensPage {
  /**
   * One token's credentials, a line each.
   *
   * @param t - the translator
   * @param r - the token
   * @returns the HTML
   */
  static credentialsCell(t: Json, r: Json): string {
    const esc = WebKit.esc;
    const list: Json[] = r.credentials || [];
    return list.length ? list.map(function (c: Json): string {
      return '<code>' + esc(c.kind) + '</code> ' +
        esc(c.label || String(c.ref).slice(0, 24)) +
        (c.algorithm ? ' <small>' + esc(c.algorithm) + '</small>' : '') +
        (c.holder && c.holder !== r.holder
          ? ' <small>(' + esc(c.holder) + ')</small>' : '') +
        (c.smartCard ? ' <small>' +
          t.html('consoleHardwareTokens.smartCard') + '</small>' : '') +
        (c.retired ? ' <strong>' + t.html('consoleHardwareTokens.retired') +
          '</strong>' : '');
    }).join('<br>') : '—';
  }

  // THE REGISTER'S TABLE, drawn by the tokens tab and, with the person
  // fixed, by that person's Hardware tokens sub-tab on Directory → Users
  // (#2052): one table, so the two cannot disagree about a token.
  /**
   * The tokens table, a Report lost on each active token.
   *
   * @param t - the translator
   * @param tokens - the tokens to draw
   * @param c - the render context
   * @returns the HTML
   */
  static tokensTable(t: Json, tokens: Json[], c: Json): string {
    const esc = WebKit.esc;
    const rows = tokens.map(function (r: Json): string {
      const lost = r.status === 'lost';
      return '<tr><td>' + esc(r.model || r.vendor) + '<br><small><code>' +
        esc(r.key) + '</code></small></td><td>' + esc(r.holder || '—') +
        '</td><td>' + esc((r.evidenceSources || []).join(', ')) +
        '</td><td>' + HardwareTokensPage.credentialsCell(t, r) + '</td><td>' +
        (lost ? t.html('consoleHardwareTokens.lostOn', { at: r.lostAt,
                                                         by: r.lostBy })
              : t.html('consoleHardwareTokens.active')) + '</td><td>' +
        (lost || !c.write ? '' : '<form method="post" action="' + PAGE +
          '" class="inline"><input type="hidden" name="action" ' +
          'value="lost"><input type="hidden" name="key" value="' +
          esc(r.key) + '"><button class="danger" type="submit">' +
          t.html('consoleHardwareTokens.reportLost') + '</button></form>') +
        '</td></tr>';
    }).join('');
    const table = tokens.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html('consoleHardwareTokens.thToken') + '</th><th>' +
        t.html('consoleHardwareTokens.thHolder') + '</th><th>' +
        t.html('consoleHardwareTokens.thEvidence') + '</th><th>' +
        t.html('consoleHardwareTokens.thCredentials') + '</th><th>' +
        t.html('consoleHardwareTokens.thStatus') + '</th><th></th></tr>' +
        '</thead><tbody>' + rows + '</tbody></table>'
      : WebKit.note(t.html('consoleHardwareTokens.none'));
    return table;
  }

  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/hardware-tokens`'s answer
   * @param ctx - the render context: the translator, the page's query and
   *   whether the reader may write
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const v = view || {};
    const esc = WebKit.esc;
    const self = HardwareTokensPage;
    const params: Json = {};
    if (v.q) {
      params.q = v.q;
    }
    if (v.status) {
      params.status = v.status;
    }
    const nav = WebKit.pageNavPair(PAGE, params, v.paging, t);
    // The fragment is the tokens tab. A GET with none reloads onto
    // Metadata, and this list stays on this panel.
    const filters = '<form method="get" action="' + PAGE +
      '#hardware-tokens-tab-tokens">' +
      '<div class="formrow"><label for="hwt-q">' +
      t.html('consoleHardwareTokens.search') + '</label>' +
      '<input type="text" id="hwt-q" name="q" size="24" maxlength="256" ' +
      'value="' + esc(v.q || '') + '"><label for="hwt-status">' +
      t.html('consoleHardwareTokens.status') + '</label>' +
      '<select id="hwt-status" name="status">' +
      ['', 'active', 'lost'].map(function (s: string): string {
        return '<option value="' + s + '"' + (s === (v.status || '')
          ? ' selected' : '') + '>' + (s === 'active'
            ? t.html('consoleHardwareTokens.active')
            : (s === 'lost' ? t.html('consoleHardwareTokens.lost')
                            : t.html('consoleHardwareTokens.any'))) +
          '</option>';
      }).join('') + '</select><button type="submit">' +
      t.html('consoleHardwareTokens.filter') + '</button></div></form>';
    const table = self.tokensTable(t, v.tokens || [], c);
    return WebKit.note(t.html('consoleHardwareTokens.lead'),
                       t.text('consoleHardwareTokens.whatThisIs')) +
      '<h2 data-tab="tokens">' + t.html('console.nav.hardware-tokens') +
      '</h2>' +
      WebKit.frame(filters + (v.capped
        ? WebKit.note(t.html('consoleHardwareTokens.capped')) : '') +
        nav.head + table + nav.foot +
        WebKit.note(t.html('consoleHardwareTokens.lostWhat'))) +
      '<h2 data-tab="oath">' + t.html('consoleHardwareTokens.oath.heading') +
      '</h2>' + self.oathTab(v, c) +
      '<h2 data-tab="enrol">' + t.html('consoleHardwareTokens.enrolTab') +
      '</h2>' + WebKit.frame(self.enrolForm(t, v, c)) +
      '<h2 data-tab="escrow">' + t.html('consoleHardwareTokens.escrowTab') +
      '</h2>' + WebKit.frame(self.escrowList(t, v, c)) +
      '<h2 data-tab="ssh">' + t.html('consoleHardwareTokens.sshTab') +
      '</h2>' + WebKit.frame(self.sshList(t, v, c));
  }

  /**
   * A person's SSH user certificates, when the search names a person (the
   * #1955 review): each revocable, which puts it on the realm's KRL.
   *
   * @param t - the translator
   * @param v - the view
   * @param c - the render context
   * @returns the HTML
   */
  static sshList(t: Json, v: Json, c: Json): string {
    const esc = WebKit.esc;
    const rows: Json[] = v.sshCertificates || [];
    const lead = WebKit.note(t.html('consoleHardwareTokens.sshWhat'));
    if (!v.q) {
      return lead + WebKit.note(t.html('consoleHardwareTokens.sshSearch'));
    }
    if (!rows.length) {
      return lead + WebKit.note(t.html('consoleHardwareTokens.sshNone',
                                       { who: v.q }));
    }
    return lead + '<table class="grid"><thead><tr><th>' +
      t.html('consoleHardwareTokens.sshSerial') + '</th><th>' +
      t.html('consoleHardwareTokens.sshKey') + '</th><th>' +
      t.html('consoleHardwareTokens.sshPrincipals') + '</th><th>' +
      t.html('consoleHardwareTokens.sshExpires') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.serialHex) + '</code>' +
          (r.authority === 'ssh-mldsa-65' ? ' <small>ML-DSA</small>' : '') +
          '</td><td>' + esc(r.keyType) + '<br><small><code>' +
          esc(r.keyFingerprint) + '</code></small>' +
          (r.hardwareBound ? ' <small>' +
            t.html('consoleHardwareTokens.sshHardware') + '</small>' : '') +
          '</td><td>' + esc((r.principals || []).join(', ')) + '</td><td>' +
          esc(r.notAfter) + (r.revoked ? ' <strong>' +
            t.html('consoleHardwareTokens.sshRevoked') + '</strong>' : '') +
          '</td><td>' + (c.write && !r.revoked
            ? '<form method="post" action="' + PAGE + '" class="inline">' +
              '<input type="hidden" name="action" value="revoke-ssh">' +
              '<input type="hidden" name="username" value="' + esc(v.q) +
              '"><input type="hidden" name="serial" value="' +
              esc(r.serialHex) + '"><button class="danger" type="submit">' +
              t.html('consoleHardwareTokens.sshRevoke') + '</button></form>'
            : '') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  /**
   * The OATH tab (#1955 P4): the inventory, its filters and the forms.
   *
   * @param v - the page's view, the inventory composed as `oath`
   * @param c - the render context
   * @returns the tab's HTML
   */
  static oathTab(v: Json, c: Json): string {
    const t = c.t;
    const esc = WebKit.esc;
    const o = v.oath || { tokens: [], paging: { pages: 1 } };
    const params: Json = {};
    if (v.q) {
      params.q = v.q;
    }
    if (v.status) {
      params.status = v.status;
    }
    if (o.q) {
      params.oq = o.q;
    }
    if (o.status) {
      params.ostatus = o.status;
    }
    // THE TAB'S OWN PAGE PARAMETER, so its pager moves this list only.
    const nav = WebKit.pageNavPair(PAGE, params,
      Object.assign({}, o.paging || { pages: 1 }, { param: 'opage' }), t);
    const statusName = function (s: string): string {
      return s === 'unassigned'
        ? t.html('consoleHardwareTokens.oath.status.unassigned')
        : (s === 'assigned'
          ? t.html('consoleHardwareTokens.oath.status.assigned')
          : (s === 'retired'
            ? t.html('consoleHardwareTokens.oath.status.retired')
            : t.html('consoleHardwareTokens.any')));
    };
    // The OATH tab's own fragment: the tokens filter above names the
    // other panel, and a GET with none shows Metadata.
    const filters = '<form method="get" action="' + PAGE +
      '#hardware-tokens-tab-oath">' +
      '<div class="formrow"><label for="oath-q">' +
      t.html('consoleHardwareTokens.search') + '</label>' +
      '<input type="text" id="oath-q" name="oq" size="24" maxlength="256" ' +
      'value="' + esc(o.q || '') + '"><label for="oath-status">' +
      t.html('consoleHardwareTokens.status') + '</label>' +
      '<select id="oath-status" name="ostatus">' +
      ['', 'unassigned', 'assigned', 'retired'].map(function (s: string) {
        return '<option value="' + s + '"' + (s === (o.status || '')
          ? ' selected' : '') + '>' + statusName(s) + '</option>';
      }).join('') + '</select><button type="submit">' +
      t.html('consoleHardwareTokens.filter') + '</button></div></form>';
    const tokens: Json[] = o.tokens || [];
    const rows = tokens.map(function (r: Json): string {
      const assign = r.status === 'unassigned' && c.write
        ? '<form method="post" action="' + PAGE + '" class="inline">' +
          '<input type="hidden" name="action" value="assign-oath">' +
          '<input type="hidden" name="key" value="' + esc(r.key) + '">' +
          '<input type="text" name="username" size="16" maxlength="256" ' +
          'required aria-label="' +
          esc(t.text('consoleHardwareTokens.oath.assignTo')) +
          '" placeholder="' +
          esc(t.text('consoleHardwareTokens.oath.assignTo')) + '">' +
          '<button type="submit">' +
          t.html('consoleHardwareTokens.oath.assign') + '</button></form>'
        : '';
      const remove = r.status !== 'assigned' && c.write
        ? ' <form method="post" action="' + PAGE + '" class="inline">' +
          '<input type="hidden" name="action" value="remove-oath">' +
          '<input type="hidden" name="key" value="' + esc(r.key) + '">' +
          '<button class="danger" type="submit">' +
          t.html('consoleHardwareTokens.oath.remove') + '</button></form>'
        : '';
      return '<tr><td>' + esc(r.model || r.vendor) + '<br><small><code>' +
        esc(r.key) + '</code></small></td><td><code>' + esc(r.kind) +
        '</code> ' + esc(String(r.digits)) + ' ' +
        t.html('consoleHardwareTokens.oath.digits') +
        (r.kind === 'totp' ? ', ' + esc(String(r.period)) + ' s' : '') +
        '</td><td>' + statusName(r.status) +
        (r.holder ? '<br>' + esc(r.holder) : '') + '</td><td>' +
        esc(r.importedAt) + '<br><small>' + esc(r.importedBy) + ', ' +
        esc(r.protection) + '</small></td><td>' + assign + remove +
        '</td></tr>';
    }).join('');
    const table = tokens.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html('consoleHardwareTokens.thToken') + '</th><th>' +
        t.html('consoleHardwareTokens.oath.thKind') + '</th><th>' +
        t.html('consoleHardwareTokens.thStatus') + '</th><th>' +
        t.html('consoleHardwareTokens.oath.thImported') + '</th><th></th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>'
      : WebKit.note(t.html('consoleHardwareTokens.oath.none'));
    const importForm = !c.write ? '' : WebKit.frame(
      '<h3>' + t.html('consoleHardwareTokens.oath.importHeading') + '</h3>' +
      WebKit.note(t.html('consoleHardwareTokens.oath.importLead')) +
      '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="import-pskc">' +
      '<div class="formrow"><label for="oath-pskc">' +
      t.html('consoleHardwareTokens.oath.file') + '</label>' +
      '<textarea id="oath-pskc" name="pskc" rows="8" cols="64" required ' +
      'placeholder="&lt;KeyContainer Version=&quot;1.0&quot; ...&gt;">' +
      '</textarea></div><div class="formrow">' +
      '<button type="button" class="secondary" ' +
      'data-load-file="oath-pskc-file">' +
      t.html('consoleHardwareTokens.oath.load') + '</button>' +
      '<input type="file" id="oath-pskc-file" hidden ' +
      'accept=".pskc,.xml,application/pskc+xml,text/xml" ' +
      'data-load-into="oath-pskc"></div>' +
      '<div class="formrow"><label for="oath-psk">' +
      t.html('consoleHardwareTokens.oath.preSharedKey') + '</label>' +
      '<input type="password" id="oath-psk" name="preSharedKey" size="40" ' +
      'maxlength="128" autocomplete="off"></div>' +
      '<div class="formrow"><label for="oath-password">' +
      t.html('consoleHardwareTokens.oath.password') + '</label>' +
      '<input type="password" id="oath-password" name="password" ' +
      'size="32" maxlength="1024" autocomplete="off"></div>' +
      '<div class="formrow"><button type="submit">' +
      t.html('consoleHardwareTokens.oath.import') + '</button></div>' +
      '</form>');
    return WebKit.frame(filters + (o.capped
      ? WebKit.note(t.html('consoleHardwareTokens.capped')) : '') +
      nav.head + table + nav.foot +
      WebKit.note(t.html('consoleHardwareTokens.oath.what'))) + importForm;
  }

  /**
   * The PIV enrolment form; with `user`, for that person alone (#2052).
   *
   * @param t - the translator
   * @param v - the view (its `piv` rules)
   * @param c - the render context
   * @param user - optional; the person the form is fixed to
   * @returns the HTML
   */
  static enrolForm(t: Json, v: Json, c: Json, user?: string): string {
    const esc = WebKit.esc;
    const rules = v.piv || { profiles: [] };
    if (!(rules.profiles || []).length) {
      return WebKit.note(t.html('consoleHardwareTokens.enrolNone'));
    }
    if (!c.write) {
      return WebKit.note(t.html('consoleHardwareTokens.enrolWhat'));
    }
    return WebKit.note(t.html('consoleHardwareTokens.enrolWhat')) +
      '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="enrol-piv">' +
      '<div class="formrow">' + (user
        ? '<input type="hidden" name="username" value="' + esc(user) + '">'
        : '<label for="hwt-user">' +
          t.html('consoleHardwareTokens.enrolUser') + '</label>' +
          '<input type="text" id="hwt-user" name="username" ' +
          'maxlength="256">') +
      '<label for="hwt-profile">' +
      t.html('consoleHardwareTokens.enrolProfile') + '</label>' +
      '<select id="hwt-profile" name="profile">' +
      rules.profiles.map(function (p: string): string {
        return '<option value="' + esc(p) + '">' + esc(p) + '</option>';
      }).join('') + '</select></div>' +
      '<label for="hwt-csr">' + t.html('consoleHardwareTokens.enrolCsr') +
      '</label><textarea id="hwt-csr" name="csr" rows="6"></textarea>' +
      '<label for="hwt-attest">' +
      t.html('consoleHardwareTokens.enrolAttestation') + '</label>' +
      '<textarea id="hwt-attest" name="attestationCertificate" rows="6">' +
      '</textarea><label for="hwt-f9">' +
      t.html('consoleHardwareTokens.enrolIssuer') + '</label>' +
      '<textarea id="hwt-f9" name="attestationIssuer" rows="6"></textarea>' +
      WebKit.note(t.html(rules.requireAttestation
        ? 'consoleHardwareTokens.enrolRequired'
        : 'consoleHardwareTokens.enrolOptional')) +
      '<button type="submit">' + t.html('consoleHardwareTokens.enrolButton') +
      '</button></form>';
  }

  /**
   * A person's escrowed keys, when the search names a person (#1955 P2).
   *
   * @param t - the translator
   * @param v - the view
   * @param c - the render context
   * @returns the HTML
   */
  static escrowList(t: Json, v: Json, c: Json): string {
    const esc = WebKit.esc;
    const rows: Json[] = v.escrowed || [];
    const lead = WebKit.note(t.html((v.piv && v.piv.keyEscrow)
      ? 'consoleHardwareTokens.escrowWhat'
      : 'consoleHardwareTokens.escrowOff'));
    if (!v.q) {
      return lead + WebKit.note(t.html('consoleHardwareTokens.escrowSearch'));
    }
    if (!rows.length) {
      return lead + WebKit.note(t.html('consoleHardwareTokens.escrowNone',
                                       { who: v.q }));
    }
    return lead + '<table class="grid"><thead><tr><th>' +
      t.html('consoleHardwareTokens.escrowSerial') + '</th><th>' +
      t.html('consoleHardwareTokens.escrowSubject') + '</th><th>' +
      t.html('consoleHardwareTokens.escrowExpires') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.serialHex) + '</code></td><td>' +
          esc(r.subject) + '</td><td>' + esc(r.notAfter) +
          (r.revoked ? ' <strong>' +
            t.html('consoleHardwareTokens.retired') + '</strong>' : '') +
          '</td><td>' + (c.write ? '<form method="post" action="' + PAGE +
            '" class="inline"><input type="hidden" name="action" ' +
            'value="recover-key"><input type="hidden" name="username" ' +
            'value="' + esc(v.q) + '"><input type="hidden" name="serial" ' +
            'value="' + esc(r.serialHex) + '"><button type="submit">' +
            t.html('consoleHardwareTokens.escrowRecover') +
            '</button></form>' : '') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }
  // ---------------------------------------------------------------------
  // A PERSON'S SUB-TABS ON DIRECTORY → USERS (#2052, rcbj 2026-11-23: "I
  // also want it to be a tab on individual user objects. Reuse the code for
  // these pages."). Each is drawn by the functions above with the person
  // fixed — the same table, the same lists, the same forms — from the
  // answers the users drill composes: `GET /admin-api/hardware-tokens` with
  // `q` the person, and `GET /admin-api/hardware-tokens/oath` with `q` the
  // person. Every form posts to `/admin/hardware-tokens`, so it reaches the
  // same operation as the central page (rule 7), and the runtime returns to
  // the sub-tab it was sent from. A search names a person or a serial, so
  // each list keeps the person's own rows only.
  // ---------------------------------------------------------------------

  /**
   * Whether a composed answer can be drawn: a refusal is said in a note.
   *
   * @param t - the translator
   * @param v - the composed answer
   * @returns the note when it cannot, else an empty string
   */
  static refusedNote(t: Json, v: Json): string {
    if (v && v.ok !== false && !v.error) {
      return '';
    }
    return WebKit.note(t.html('consoleHardwareTokens.person.unavailable'));
  }

  /**
   * The person's view: the composed answer with the search fixed to them.
   *
   * @param v - the composed answer
   * @param user - the person
   * @returns the view
   */
  static personView(v: Json, user: string): Json {
    const out = Object.assign({}, v || {}, { q: user });
    out.tokens = ((v && v.tokens) || []).filter(function (r: Json) {
      return r.holder === user || (r.credentials || []).some(
        function (one: Json): boolean { return one.holder === user; });
    });
    return out;
  }

  /**
   * The Hardware tokens sub-tab: the person's tokens, with Report lost.
   *
   * @param t - the translator
   * @param v - `GET /admin-api/hardware-tokens?q=<person>`'s answer
   * @param c - the render context
   * @param user - the person
   * @returns the HTML
   */
  static personTokens(t: Json, v: Json, c: Json, user: string): string {
    const refused = HardwareTokensPage.refusedNote(t, v);
    if (refused) {
      return WebKit.frame(refused);
    }
    const mine = HardwareTokensPage.personView(v, user);
    return WebKit.frame(WebKit.note(
      t.html('consoleHardwareTokens.lead'),
      t.text('consoleHardwareTokens.whatThisIs')) +
      HardwareTokensPage.tokensTable(t, mine.tokens, c) +
      WebKit.note(t.html('consoleHardwareTokens.lostWhat')) +
      HardwareTokensPage.centralLink(t));
  }

  /**
   * The OATH tokens sub-tab: the tokens assigned to the person, an Assign
   * by key, and their one-time code token from the users answer.
   *
   * @param t - the translator
   * @param o - `GET /admin-api/hardware-tokens/oath?q=<person>`'s answer
   * @param c - the render context
   * @param user - the person
   * @param enrolled - the person's one-time code token, drawn by the users
   *   page (`mfaSection()`'s `hotp`), with its Clear
   * @returns the HTML
   */
  static personOath(t: Json, o: Json, c: Json, user: string,
                    enrolled: string): string {
    const esc = WebKit.esc;
    const refused = HardwareTokensPage.refusedNote(t, o);
    const rows: Json[] = refused ? [] : ((o && o.tokens) || []).filter(
      function (r: Json): boolean { return r.holder === user; });
    const list = rows.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html('consoleHardwareTokens.thToken') + '</th><th>' +
        t.html('consoleHardwareTokens.oath.thKind') + '</th><th>' +
        t.html('consoleHardwareTokens.thStatus') + '</th></tr></thead>' +
        '<tbody>' + rows.map(function (r: Json): string {
          return '<tr><td>' + esc(r.model || r.vendor) + '<br><small><code>' +
            esc(r.key) + '</code></small></td><td><code>' + esc(r.kind) +
            '</code> ' + esc(String(r.digits)) + ' ' +
            t.html('consoleHardwareTokens.oath.digits') + '</td><td>' +
            esc(r.status) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : WebKit.note(t.html('consoleHardwareTokens.person.noOath'));
    const assign = c.write
      ? '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="assign-oath">' +
        '<input type="hidden" name="username" value="' + esc(user) + '">' +
        '<input type="text" name="key" size="24" maxlength="256" required ' +
        'aria-label="' + esc(t.text('consoleHardwareTokens.person.tokenKey')) +
        '" placeholder="' +
        esc(t.text('consoleHardwareTokens.person.tokenKey')) + '">' +
        '<button type="submit">' +
        t.html('consoleHardwareTokens.oath.assign') + '</button></form>'
      : '';
    return WebKit.frame((refused || list) + assign +
      WebKit.note(t.html('consoleHardwareTokens.oath.what')) +
      HardwareTokensPage.centralLink(t)) + (enrolled ? WebKit.frame(enrolled)
                                                    : '');
  }

  /**
   * The YubiKey OTP sub-tab: assign an imported YubiKey by serial, and the
   * person's YubiKey OTP from the users answer.
   *
   * @param t - the translator
   * @param c - the render context
   * @param user - the person
   * @param enrolled - the person's YubiKey OTP, drawn by the users page
   *   (`mfaSection()`'s `yubi`), with its Clear
   * @returns the HTML
   */
  static personYubi(t: Json, c: Json, user: string,
                    enrolled: string): string {
    const esc = WebKit.esc;
    const assign = c.write
      ? '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="assign-yubiotp">' +
        '<input type="hidden" name="username" value="' + esc(user) + '">' +
        '<div class="formrow"><label for="hwt-yubi-serial">' +
        t.html('consoleHardwareTokens.person.yubiSerial') + '</label>' +
        '<input type="text" id="hwt-yubi-serial" name="serial" size="12" ' +
        'maxlength="16" required><label for="hwt-yubi-otp">' +
        t.html('consoleHardwareTokens.person.yubiOtp') + '</label>' +
        '<input type="text" id="hwt-yubi-otp" name="otp" size="48" ' +
        'maxlength="64" autocomplete="off"><button type="submit">' +
        t.html('consoleHardwareTokens.oath.assign') + '</button></div></form>'
      : '';
    return (enrolled ? WebKit.frame(enrolled) : WebKit.frame(
      WebKit.note(t.html('consoleHardwareTokens.person.noYubi')))) +
      WebKit.frame(WebKit.note(
        t.html('consoleHardwareTokens.person.yubiWhat')) + assign);
  }

  /**
   * The PIV sub-tab: the enrolment form fixed to the person, and their
   * escrowed keys with Recover key.
   *
   * @param t - the translator
   * @param v - `GET /admin-api/hardware-tokens?q=<person>`'s answer
   * @param c - the render context
   * @param user - the person
   * @returns the HTML
   */
  static personPiv(t: Json, v: Json, c: Json, user: string): string {
    const refused = HardwareTokensPage.refusedNote(t, v);
    if (refused) {
      return WebKit.frame(refused);
    }
    const mine = HardwareTokensPage.personView(v, user);
    return WebKit.frame(HardwareTokensPage.enrolForm(t, mine, c, user)) +
      WebKit.frame(HardwareTokensPage.escrowList(t, mine, c));
  }

  /**
   * The SSH user certificates sub-tab: the person's certificates, each
   * revocable.
   *
   * @param t - the translator
   * @param v - `GET /admin-api/hardware-tokens?q=<person>`'s answer
   * @param c - the render context
   * @param user - the person
   * @returns the HTML
   */
  static personSsh(t: Json, v: Json, c: Json, user: string): string {
    const refused = HardwareTokensPage.refusedNote(t, v);
    if (refused) {
      return WebKit.frame(refused);
    }
    return WebKit.frame(HardwareTokensPage.sshList(t,
      HardwareTokensPage.personView(v, user), c) +
      WebKit.note(t.html('consoleHardwareTokens.person.sshIssue')));
  }

  /**
   * The link from a person's sub-tab to the central page.
   *
   * @param t - the translator
   * @returns the HTML
   */
  static centralLink(t: Json): string {
    return '<p class="sub"><a href="' + PAGE + '">' +
      t.html('consoleHardwareTokens.person.central') + '</a></p>';
  }
}

export = HardwareTokensPage;
