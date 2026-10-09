// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_xacml.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → XACML AND ITS PAGES, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Draws XACML's overview, its policies, the remote PEPs, the decisions and the
// decision form from the answers of `GET /admin-api/xacml`, `/xacml/policies`,
// `/xacml/peps`, `/xacml/monitor` and `/xacml/decide`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `XacmlAdmin`'s in `xacml/xacml_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws XACML's overview, its policies, the remote PEPs, the decisions and the
 * decision form from the answers of `GET /admin-api/xacml`, `/xacml/policies`,
 * `/xacml/peps`, `/xacml/monitor` and `/xacml/decide`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class XacmlPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return XacmlPage.overviewBody(ctx, view);
  }

  // ---------------------------------------------------------------------------
  // SMALL RENDERING HELPERS. Local rather than exported from admin.js, because
  // they are about POLICIES rather than about the console.
  // ---------------------------------------------------------------------------
  static select(name: string, options: any[], selected: unknown,
                 extra?: string): string {
    const body = options.map(function (one) {
      const value = one.value === undefined ? one.uri : one.value;
      return '<option value="' + esc(value) + '"' +
        (String(value) === String(selected) ? ' selected' : '') + '>' +
        esc(one.label) + '</option>';
    }).join('');
    return '<select name="' + esc(name) + '"' + (extra || '') + '>' + body +
      '</select>';
  }

  static hidden(name: string, value: unknown): string {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
      esc(value === null || value === undefined ? '' : value) + '">';
  }

  static textField(name: string, value: unknown, size?: number): string {
    return '<input type="text" name="' + esc(name) + '" value="' +
      esc(value === null || value === undefined ? '' : value) + '"' +
      (size ? ' size="' + size + '"' : '') + '>';
  }

  // ---------------------------------------------------------------------------
  // THE SECTION THAT SAYS THE TABLE ABOVE IS NOT THE WHOLE ANSWER.
  //
  // Drawn under the repository table because the ORDER is the argument: a
  // reader arrives to look at policies, sees the ones that are stored, and is
  // then told which two are deciding and are not among them. Above the table it
  // would read as a preamble to be scrolled past; in a fold it would be exactly
  // the fact that was already invisible, hidden once more.
  //
  // **THE STATE COMES FROM THE SAME FUNCTIONS THE PEPs CALL**, through
  // `issuancePolicyState()` and `accessPolicyState()`, which are thin wrappers
  // over the very `issuancePolicy()` / `accessPolicy()` the decision goes
  // through. A page that worked out for itself which document was in force
  // would be a second answer to that question, and it would be the one that is
  // wrong after somebody disables an override.
  // ---------------------------------------------------------------------------
  // The one line the EDITOR needs about the same two policies. It is not the
  // section above said again: what a reader standing in the editor needs is why
  // the chooser does not offer them and where to go, and the section on the
  // Policies page is where the argument lives. Two full copies of that argument
  // would be two things to keep in step, which is the failure this whole change
  // is about.
  static serviceOwnEditorNote(rows: any[], t: Json): string {
    const overridden = (rows || []).filter(function (one) {
      return one.entry;
    }).length;
    // The link is markup a message cannot carry, so the sentence around it
    // is two messages (#539).
    return kit.note(
      '<p>' + t.html('consoleXacml.editorNote.lead') +
      '</p><p>' +
      (overridden
        ? t.html('consoleXacml.editorNote.overridden')
        : t.html('consoleXacml.editorNote.none')) +
      t.html('consoleXacml.editorNote.createBefore') +
      '<a href="/admin/xacml/policies#service-own">' +
      t.html('consoleXacml.link.policies') + '</a>' +
      t.html('consoleXacml.editorNote.createAfter') + '</p>',
      t.text('consoleXacml.editorNote.label'));
  }

  static renderServiceOwnPolicies(rows: any[], writable: boolean,
                                  t: Json): string {
    const self = this;
    const body = rows.map(function (row) {
      // WHERE THE DOCUMENT COMES FROM, in three states rather than two. "No
      // override has been written" and "an override was written and disabled"
      // are opposite situations that `builtIn` alone cannot tell apart, and the
      // second is the one somebody needs to see.
      let source;
      if (!row.ok) {
        source = '<strong style="color:#b00">' +
          t.html('consoleXacml.own.nothingEvaluated') + '</strong>';
      } else if (!row.builtIn) {
        source = t.html('consoleXacml.own.repositoryEntry') +
          ' <a href="/admin/xacml/editor?policy=' +
          encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
          '</code></a>';
      } else if (row.entry) {
        source = t.html('consoleXacml.own.builtInDisabled', { name: row.name });
      } else {
        source = t.html('consoleXacml.own.builtInTemplate',
          { template: row.template });
      }
      // The override is created through the SAME action the template forms
      // below use, prefilled with the name the setting already names — so a
      // reader who presses it gets an entry the PEP will actually pick up,
      // rather than one named after the template and silently ignored. Moving a
      // form is not moving an action: `create-from-template` keeps its one
      // operation on /admin-api and gains no second door.
      const make = writable && !row.entry
        ? '<form method="post" action="/admin/xacml/policies" class="inline">' +
          self.hidden('action', 'create-from-template') +
          self.hidden('template', row.template) +
          self.hidden('name', row.name) +
          '<button type="submit">' +
          t.html('consoleXacml.own.createOverride') + '</button></form>'
        : (row.entry
            ? '<a href="/admin/xacml/editor?policy=' +
              encodeURIComponent(row.name) + '">' +
              t.html('consoleXacml.own.editIt') + '</a>'
            : '<span class="sub">' + t.html('consoleXacml.readOnly') +
              '</span>');
      return '<tr><td><strong>' + esc(row.label) + '</strong>' +
        '<div class="sub">' +
        t.html('consoleXacml.own.namedBy', { setting: row.setting,
                                            name: row.name }) +
        '</div></td>' +
        '<td>' + esc(row.decides) + '<div class="sub">' +
        t.html('consoleXacml.own.askedAt') + ' ' +
        esc(row.asked).replace(/`([^`]+)`/g, '<code>$1</code>') +
        '</div></td>' +
        '<td>' + source + '</td>' +
        '<td>' + esc(row.effect) + '</td>' +
        '<td>' + make + '</td></tr>';
    }).join('');
    return '<h2 id="service-own">' +
      t.html('consoleXacml.own.heading') + '</h2>' +
      kit.warn(
        '<p>' + t.html('consoleXacml.own.warn1') +
        '</p><p>' + t.html('consoleXacml.own.warn2') +
        '</p><p>' + t.html('consoleXacml.own.warn3') +
        '</p>',
        t.text('consoleXacml.own.warnLabel')) +
      '<table><tr><th>' + t.html('consoleXacml.th.policy') + '</th><th>' +
      t.html('consoleXacml.th.decides') + '</th>' +
      '<th>' + t.html('consoleXacml.th.inForce') + '</th><th>' +
      t.html('consoleXacml.th.rightNow') + '</th><th></th></tr>' +
      body + '</table>';
  }

  // ---------------------------------------------------------------------------
  // THE SENTENCE AN EMPTY REGISTER GETS, AND IT SAYS WHICH OF THE TWO EMPTIES
  // IT IS (2026-09-06).
  //
  // `ou=peps` is per realm and every page here draws ONE realm, so "no remote
  // Policy Enforcement Point has registered" was a sentence with two causes and
  // named neither: nothing anywhere, or nothing IN THE REALM BEING READ while
  // another realm holds one. That is `/admin/realms`'s own lesson — **a
  // predicate that is false for two reasons must not be rendered as a message
  // that names one of them** — made again in a different file.
  //
  // **THE WALK IS `peps.elsewhere()` AND LIVES IN THE REGISTRY**, not here:
  // which realms hold a registration is a fact about the REGISTER, and this
  // module renders and decides nothing, like every other page module in this
  // console. It is carried in the JSON as well, so `GET /admin-api/xacml/peps`
  // answers the same question the page does (rule 7) — a caller reading an
  // empty `peps` array has exactly the ambiguity the page had.
  //
  // `where` is that function's answer.
  static noPepsHere(where: any[], t: Json): string {
    const shared = t.html('consoleXacml.noPeps.shared');
    if (!where.length) {
      return t.html('consoleXacml.noPeps.anywhere') + ' ' +
        shared;
    }
    const list = where.map(function (one) {
      return '<a href="/realm/' + esc(one.id) + '/admin/xacml/peps"><code>' +
        esc(one.id) + '</code></a> (' + one.count + ')';
    }).join(', ');
    return t.html('consoleXacml.noPeps.elsewhere', { n: where.length }) +
      list + t.html('consoleXacml.noPeps.perRealm') +
      ' ' + shared;
  }

  // A count that is a proportion of another, as "n (p%)". Zero of zero is drawn
  // as a dash rather than as "0 (0%)" or NaN: nothing has happened yet, and a
  // percentage of nothing is not a fact about this service.
  static share(n: number, of: number): string {
    if (!of) {
      return n ? String(n) : '&mdash;';
    }
    return String(n) + ' <span class="sub">(' +
           Math.round((n / of) * 100) + '%)</span>';
  }

  // The four decisions on one row, or a dash where the row does not have them —
  // which is every REMOTE row, because a remote PEP reports what it ENFORCED
  // and the breakdown by PDP decision is known only to the process that
  // evaluated.
  static decisionCells(row: any, t: Json): string {
    if (row.permit === null || row.permit === undefined) {
      return '<td colspan="4" class="sub">' +
             t.html('consoleXacml.monitor.notReported') +
             '</td>';
    }
    return '<td class="num state-valid">' + row.permit + '</td>' +
      '<td class="num state-revoked">' + row.deny + '</td>' +
      '<td class="num">' + row.notApplicable + '</td>' +
      '<td class="num state-expired">' + row.indeterminate + '</td>';
  }

  // The allowed/refused pair, or the EMPTY cell that says this asker never
  // enforced anything. `/xacml/pdp` is the one row that gets it, and the
  // distinction is the point: a zero would read as "it refused nothing".
  static enforcementCells(row: any, t: Json): string {
    const self = this;
    if (!row.enforces || row.allowed === null || row.allowed === undefined) {
      return '<td colspan="2" class="sub">' +
             t.html('consoleXacml.monitor.notEnforced') +
             '</td>';
    }
    return '<td class="num state-valid">' +
      self.share(row.allowed, row.decisions) +
      '</td><td class="num state-revoked">' +
      self.share(row.refused, row.decisions) +
      '</td>';
  }

  static monitorRow(row: any, t: Json): string {
    const self = this;
    const state = [];
    if (row.kind === 'remote') {
      state.push(row.remote.current
        ? '<span title="' + esc(t.text('consoleXacml.pep.currentTip')) +
          '">' + t.html('consoleXacml.pep.current') + '</span>'
        : '<strong title="' + esc(t.text('consoleXacml.pep.notCurrentTip')) +
          '">' + t.html('consoleXacml.pep.notCurrent') + '</strong>');
      state.push(row.remote.stale
        ? '<strong>' + t.html('consoleXacml.pep.stale') + '</strong>'
        : t.html('consoleXacml.pep.live'));
      if (!row.remote.authenticated) {
        state.push('<strong>' + t.html('consoleXacml.pep.unauthenticated') +
                   '</strong>');
      }
    } else {
      // AN EMBEDDED PEP IS ALWAYS LIVE AND THAT IS NOT A REASSURANCE, it is a
      // tautology worth stating: it is compiled into this process, so it is
      // running exactly when this page is being drawn. There is nothing to be
      // stale about and no registration to have failed.
      state.push('<span title="' +
        esc(t.text('consoleXacml.monitor.inProcessTip')) +
                 '">' + t.html('consoleXacml.monitor.inProcess') + '</span>');
    }
    const counts = row.decisions
      ? esc(row.lastDecision || '') +
        (row.lastAllowed === null || row.lastAllowed === undefined
          ? ''
          : ', ' + (row.lastAllowed ? t.html('consoleXacml.monitor.allowed')
                                    : t.html('consoleXacml.monitor.refused'))) +
        '<div class="sub">' + esc(row.lastAt || '') + '</div>'
      : '<span class="sub">' + t.html('consoleXacml.monitor.nothingYet') +
      '</span>';
    return '<tr><td><strong>' + esc(row.label) + '</strong>' +
      '<div class="sub">' + esc(row.kind) + ' &middot; <code>' +
      esc(row.where) + '</code></div>' +
      '<div class="sub">' + esc(row.guards) + '</div></td>' +
      '<td>' + state.join('<br>') +
      (row.kind === 'remote' && row.remote.policyCount !== null
        ? '<div class="sub">' +
          t.html('consoleXacml.monitor.holds', { n: row.remote.policyCount }) +
          '</div>'
        : '') +
      '</td>' +
      '<td>' + (row.bias ? esc(row.bias)
        : '<span class="sub">' + t.html('consoleXacml.monitor.na') +
        '</span>') +
      (row.kind === 'remote'
        ? '<div class="sub">' + t.html('consoleXacml.monitor.reportedByIt') +
        '</div>'
        : (row.id === 'protected'
            ? '<div class="sub"><code>xacml.pepBias</code></div>'
            : '')) +
      '</td>' +
      '<td class="num">' + row.decisions + '</td>' +
      self.enforcementCells(row, t) +
      self.decisionCells(row, t) +
      '<td>' + counts + '</td></tr>';
  }

  // FIVE PAGES' BODIES (#446), each one method so that it can be one
  // renderer, where each was the body of its route. The policy editor's is
  // not among them: its forms are built from the policy parsed on the
  // server, and moving it is a change to its view of its own.
  /**
   * Draws Protocols → XACML from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `overviewJson()`'s answer
   * @returns the body as HTML
   */
  static overviewBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const tiles = '<div class="tiles">' +
      kit.tile(json.policies, t.text('consoleXacml.tile.policies')) +
      kit.tile(json.enabledPolicies, t.text('consoleXacml.tile.enabled')) +
      kit.tile(json.root || '—', t.text('consoleXacml.tile.root')) +
      kit.tile(json.pepBias, t.text('consoleXacml.tile.pepBias')) +
      kit.tile(json.pipAvailable ? t.text('consoleXacml.yes')
        : t.text('consoleXacml.no'),
               t.text('consoleXacml.tile.pip')) +
      '</div>';

    // The link is markup a message cannot carry (#539).
    const rootWarning = json.root ? '' : kit.warn(
      t.html('consoleXacml.overview.noRootBefore') +
      '<a href="/admin/xacml/policies">' +
      t.html('consoleXacml.link.policies') +
      '</a>' + t.html('consoleXacml.pagePeriod'),
      t.text('consoleXacml.overview.noRootLabel'));

    const what = kit.note(
      '<p>' + t.html('consoleXacml.overview.p1') +
      '</p><p>' + t.html('consoleXacml.overview.p2') +
      '</p><p>' + t.html('consoleXacml.overview.p3') +
      '</p><p>' + t.html('consoleXacml.overview.p4') +
      '</p>',
      t.text('consoleXacml.overview.label'));
    return tiles + rootWarning + what +
                  SettingsForms.forms(json.settings, '/admin/xacml',
                                      undefined, t);
  }

  /**
   * Draws XACML policies from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `policiesJson()`'s answer
   * @returns the body as HTML
   */
  static policiesBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const writable = ctx.write;

    const rows = json.policies.map(function (row) {
      const problems = row.problems.length
        ? '<div class="sub" style="color:#b00">' +
          row.problems.map(esc).join('<br>') + '</div>'
        : '';
      const actions = writable ? '<form method="post" ' +
        'action="/admin/xacml/policies" style="display:inline">' +
        self.hidden('action', row.enabled ? 'disable' : 'enable') +
        self.hidden('name', row.name) +
        '<button type="submit">' + (row.enabled
          ? t.html('consoleXacml.policies.disable')
          : t.html('consoleXacml.policies.enable')) +
        '</button></form> ' +
        (row.isRoot ? '' : '<form method="post" ' +
          'action="/admin/xacml/policies" style="display:inline">' +
          self.hidden('action', 'set-root') + self.hidden('name', row.name) +
          '<button type="submit">' + t.html('consoleXacml.policies.makeRoot') +
          '</button></form> ') +
        '<form method="post" action="/admin/xacml/policies" ' +
        'style="display:inline">' +
        self.hidden('action', 'delete') + self.hidden('name', row.name) +
        '<button type="submit">' + t.html('consoleXacml.policies.delete') +
        '</button></form>'
        : '<span class="sub">' + t.html('consoleXacml.readOnly') + '</span>';
      return '<tr><td><a href="/admin/xacml/editor?policy=' +
        encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
        '</code></a>' + (row.isRoot
          ? ' <strong>' + t.html('consoleXacml.policies.root') + '</strong>'
          : '') +
        '</td><td><code>' + esc(row.policyId) + '</code>' + problems +
        '</td><td>' + esc(row.kind) + '</td><td>' +
        esc(String(row.combiningAlgId)
          .replace(/^urn:oasis:names:tc:xacml:[0-9.]+:function:/, '')
          .replace(/^.*combining-algorithm:/, '')) +
        '</td><td>' + (row.enabled ? t.html('consoleXacml.policies.enabled')
          : '<em>' + t.html('consoleXacml.policies.disabled') + '</em>') +
        '</td><td>' + actions + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="6">' + t.html('consoleXacml.policies.empty') +
      '</td></tr>';

    // THE TEMPLATE FORMS ARE DERIVED FROM `xacml_templates.ts`'s table.
    // Adding a template is a row there and nothing here — which is the
    // promise that file makes, and this loop is what keeps it.
    const templateForms = writable ? json.templates.map(function (one) {
      const fields = one.parameters.map(function (parameter) {
        return '<tr><td>' + esc(parameter.label) + '</td><td>' +
          self.textField('p_' + parameter.name, parameter.dflt, 40) +
          '</td><td class="sub">' + esc(parameter.help || '') + '</td></tr>';
      }).join('');
      return '<details><summary>' + esc(one.label) + '</summary>' +
        '<p>' + esc(one.blurb) + '</p><p class="sub">' + esc(one.what) +
        '</p>' +
        '<form method="post" action="/admin/xacml/policies">' +
        self.hidden('action', 'create-from-template') +
        self.hidden('template', one.id) +
        '<table><tr><td>' + t.html('consoleXacml.template.name') +
        '</td><td>' +
        self.textField('name', one.id, 30) +
        '</td><td class="sub">' + t.html('consoleXacml.template.nameHelp') +
        '</td></tr>' +
        fields +
        '</table><button type="submit">' +
        t.html('consoleXacml.template.create') +
        '</button></form></details>';
    }).join('') : '';

    const body = kit.note(
      '<p>' + t.html('consoleXacml.policies.p1') +
      '</p><p>' + t.html('consoleXacml.policies.p2') +
      '</p><p>' + t.html('consoleXacml.policies.p3') +
      '</p>',
      t.text('consoleXacml.whatThisPageIs')) +
      '<table><tr><th>' + t.html('consoleXacml.th.name') +
      '</th><th>PolicyId</th><th>' +
      t.html('consoleXacml.th.kind') + '</th>' +
      '<th>' + t.html('consoleXacml.th.combining') + '</th><th>' +
      t.html('consoleXacml.th.state') + '</th><th>' +
      t.html('consoleXacml.th.actions') +
      '</th></tr>' + rows +
      '</table>' +
      self.renderServiceOwnPolicies(json.serviceOwn, writable, t) +
      (writable
        ? '<h2>' + t.html('consoleXacml.alfa.heading') + '</h2>' + kit.note(
            '<p>' + t.html('consoleXacml.alfa.p1') +
            '</p><p>' + t.html('consoleXacml.alfa.p2') +
            '</p>',
            t.text('consoleXacml.alfa.label')) +
          '<form method="post" action="/admin/xacml/policies">' +
          self.hidden('action', 'import-alfa') +
          '<p>' + t.html('consoleXacml.th.name') + ' ' +
          self.textField('name', 'imported', 24) + '</p>' +
          '<textarea name="alfa" rows="14" cols="88" ' +
          'placeholder="namespace example { ... }"></textarea>' +
          '<p><button type="submit">' + t.html('consoleXacml.alfa.import') +
          '</button></p></form>'
        : '') +
      (templateForms
        ? '<h2>' + t.html('consoleXacml.template.heading') + '</h2>' +
          kit.note(
            '<p>' + t.html('consoleXacml.template.p1') +
            '</p><p>' + t.html('consoleXacml.template.p2') +
            '</p><p>' + t.html('consoleXacml.template.p3') +
            '</p>',
            t.text('consoleXacml.template.label')) + templateForms
        : '');
    return body;
  }

  /**
   * Draws Remote PEPs from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `pepsJson()`'s answer
   * @returns the body as HTML
   */
  static pepsBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const writable = ctx.write;

    const rows = json.peps.map(function (row) {
      const state = [];
      state.push(row.current
        ? '<span title="' + esc(t.text('consoleXacml.pep.currentTip')) +
          '">' + t.html('consoleXacml.pep.current') + '</span>'
        : '<strong title="' + esc(t.text('consoleXacml.pep.notCurrentTip')) +
          '">' + t.html('consoleXacml.pep.notCurrent') + '</strong>');
      state.push(row.stale
        ? '<strong title="' + esc(t.text('consoleXacml.pep.staleTip')) +
          '">' + t.html('consoleXacml.pep.stale') + '</strong>'
        : t.html('consoleXacml.pep.live'));
      if (!row.enabled) {
        state.push('<em>' + t.html('consoleXacml.pep.notNudged') + '</em>');
      }
      // THE AUTHENTICATION IS ON THE ROW AND NOT IN A FOOTNOTE. A
      // registration that proved nothing must not look the same as one that
      // proved something, which is the whole reason the flag is stored rather
      // than inferred from whether a subject happens to be present.
      const who = row.authenticated
        ? '<code>' + esc(row.certificateSubject) + '</code>'
        : '<strong>' + t.html('consoleXacml.pep.unauthenticated') +
          '</strong><div class="sub">' +
          t.html('consoleXacml.pep.unauthenticatedNote') +
          '</div>';
      const notify = row.notifyUrl
        ? '<code>' + esc(row.notifyUrl) + '</code>' +
          (row.notifyProblem
            ? '<div class="sub" style="color:#b00">' +
            esc(row.notifyProblem) +
              '</div>'
            : '') +
          (row.lastNotify
            ? '<div class="sub">' + esc(row.lastNotify) + '</div>'
            : '')
        : '<span class="sub">' +
          t.html('consoleXacml.pep.noNotify') +
          '</span>';
      // THE HTTPS LISTENER CERTIFICATE (2026-09-13). What this realm ISSUED,
      // and never whether the PEP is serving it: nothing on this page reaches
      // into another process, and the PEP's own GET / is where that is said.
      const held = row.listenerCertificate;
      const listener = (held
        ? '<code>' + esc(held.serialHex) + '</code>' +
          '<div class="sub">' +
          esc(held.dnsNames.concat(held.ipAddresses).join(', ')) + '</div>' +
          '<div class="sub">' +
          (held.expired
            ? '<strong>' + t.html('consoleXacml.pep.expired') + '</strong> '
              : '') +
          t.html('consoleXacml.pep.until', { at: held.notAfter }) + '</div>'
        : '<span class="sub">' + t.html('consoleXacml.pep.noneIssued') +
        '</span>') +
        (writable
          ? '<form method="post" action="/admin/xacml/peps">' +
            self.hidden('action', 'issue-pep-certificate') +
            self.hidden('name', row.name) +
            '<div class="sub">' + t.html('consoleXacml.pep.moreDns') +
            ' <input name="dnsNames" ' +
            'size="18" placeholder="pep.example.test"></div>' +
            '<div class="sub">' + t.html('consoleXacml.pep.ipAddresses') +
            ' <input name="ipAddresses" ' +
            'size="14" placeholder="10.0.0.5"></div>' +
            '<div class="sub">' + t.html('consoleXacml.pep.key') + ' ' +
            self.select('keyAlg', json.listenerCertificates.keyAlgorithms
              .map(function (one) {
                return { value: one, label: one };
              }), json.listenerCertificates.defaultKeyAlg) + ' ' +
            '<button type="submit">' + (held
              ? t.html('consoleXacml.pep.reissue')
              : t.html('consoleXacml.pep.issue')) +
            '</button></div></form>'
          : '');
      const actions = writable
        ? '<form method="post" action="/admin/xacml/peps" ' +
          'style="display:inline">' +
          self.hidden('action', row.enabled ? 'disable-pep' : 'enable-pep') +
          self.hidden('name', row.name) +
          '<button type="submit">' +
          (row.enabled ? t.html('consoleXacml.pep.stopNudging')
                       : t.html('consoleXacml.pep.nudge')) +
          '</button></form> ' +
          '<form method="post" action="/admin/xacml/peps" ' +
          'style="display:inline">' +
          self.hidden('action', 'forget-pep') +
          self.hidden('name', row.name) +
          '<button type="submit">' + t.html('consoleXacml.pep.forget') +
          '</button></form>'
        : '<span class="sub">' + t.html('consoleXacml.readOnly') + '</span>';
      return '<tr><td><code>' + esc(row.name) + '</code>' +
        (row.resource ? '<div class="sub">' +
                        t.html('consoleXacml.pep.guards',
                          { resource: row.resource }) +
                        '</div>' : '') +
        (row.version
          ? '<div class="sub">' + esc(row.version) + '</div>'
          : '') +
        '</td><td>' + who + '</td><td>' + state.join(', ') +
        '<div class="sub">' + t.html('consoleXacml.pep.lastSeen', {
          at: row.lastSeen || t.text('consoleXacml.pep.never') }) +
        '</div></td><td>' +
        esc(row.bias || t.text('consoleXacml.pep.notReported')) +
        '</td><td>' + t.html('consoleXacml.pep.counts', {
          decisions: row.decisions, allowed: row.allowed,
          refused: row.refused }) +
        (row.undischargeable
          ? '<div class="sub">' +
            t.html('consoleXacml.pep.undischargeable',
              { n: row.undischargeable }) +
            '</div>'
          : '') +
        '</td><td>' + notify + '</td><td>' + listener + '</td><td>' +
        actions +
        '</td></tr>';
    }).join('') ||
      '<tr><td colspan="8">' + self.noPepsHere(json.elsewhere, t) +
      '</td></tr>';

    const body = kit.note(
      '<p>' + t.html('consoleXacml.peps.p1') +
      '</p><p>' + t.html('consoleXacml.peps.p2') +
      '</p><p>' + t.html('consoleXacml.peps.p3') +
      '</p><p>' + t.html('consoleXacml.peps.p4') +
      '</p>',
      t.text('consoleXacml.whatThisPageIs')) +
      '<p>' + t.html('consoleXacml.peps.sync', {
        token: json.syncToken, current: json.current,
        total: json.peps.length, stale: json.stale,
        after: json.staleAfterS }) + '</p>' +
      (json.enabled ? ''
        : '<p>' + t.html('consoleXacml.peps.off') +
          '</p>') +
      (json.notify.on ? ''
        : '<p>' + t.html('consoleXacml.peps.notifyOff') +
          '</p>') +
      '<table><tr><th>PEP</th><th>' + t.html('consoleXacml.th.certificate') +
      '</th><th>' + t.html('consoleXacml.th.state') + '</th>' +
      '<th>' + t.html('consoleXacml.th.itsBias') + '</th><th>' +
      t.html('consoleXacml.th.enforced') + '</th><th>' +
      t.html('consoleXacml.th.notify') + '</th>' +
      '<th>' + t.html('consoleXacml.th.listener') + '</th>' +
      '<th>' + t.html('consoleXacml.th.actions') + '</th></tr>' + rows +
      '</table>' +
      kit.note(
        '<p>' + t.html('consoleXacml.peps.cert1') +
        '</p><p>' + t.html('consoleXacml.peps.cert2') +
        '</p>',
        t.text('consoleXacml.peps.certLabel')) +
      kit.note(
        '<p>' + t.html('consoleXacml.peps.numbers1') +
        '</p><p>' + t.html('consoleXacml.peps.numbers2') +
        '</p>',
        t.text('consoleXacml.peps.numbersLabel'));
    return body;
  }

  /**
   * Draws XACML decisions from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `monitorJson()`'s answer
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const here = json.decisions.here;
    const there = json.decisions.remote;
    const combined = json.decisions.combined;

    // ---------------------------------------------------------------------
    // SECTION ONE: THE GLOBAL FIGURES.
    //
    // The tiles carry the COMBINED decisions, allows and declines, because
    // that is the deployment-wide number somebody came for — and the table
    // under them splits it into the two kinds of evidence, because that is
    // the number that is actually true about this process. Putting the split
    // first and the total second was the other option and it is the wrong way
    // round: a reader who wants the caveat will read on, and a reader who
    // wants the figure should not have to add two numbers up in their head.
    // ---------------------------------------------------------------------
    const tiles = '<div class="tiles">' +
      kit.tile(json.policies.total, t.text('consoleXacml.tile.policies')) +
      kit.tile(json.policies.enabled, t.text('consoleXacml.tile.enabled')) +
      kit.tile(json.peps.total, t.text('consoleXacml.tile.points')) +
      kit.tile(combined.decisions, t.text('consoleXacml.tile.decisions')) +
      kit.tile(combined.allowed, t.text('consoleXacml.tile.allows')) +
      kit.tile(combined.refused, t.text('consoleXacml.tile.declines')) +
      '</div>';

    // THE FOUR COLUMNS ADD UP, AND THE FOURTH IS WHY. `allowed + refused` is
    // LESS than `decisions` on any service that has answered `POST
    // /xacml/pdp`, because those decisions were enforced by somebody else's
    // PEP in somebody else's process. Leaving the gap unexplained was the
    // first draft and it made the row look like an arithmetic error, which is
    // the kind of thing that makes a reader distrust every other number
    // beside it.
    const evidenceRow = function (label, figures, what) {
      return '<tr><td><strong>' + label + '</strong></td>' +
        '<td class="num">' + figures.decisions + '</td>' +
        '<td class="num state-valid">' + figures.allowed + '</td>' +
        '<td class="num state-revoked">' + figures.refused + '</td>' +
        '<td class="num">' + figures.unenforced + '</td>' +
        '<td class="num">' + figures.undischargeable + '</td>' +
        '<td class="sub">' + what + '</td></tr>';
    };
    const evidence =
      '<h2>' + t.html('consoleXacml.monitor.figuresHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleXacml.th.counted') +
      '</th><th class="num">' + t.html('consoleXacml.th.decisions') + '</th>' +
      '<th class="num">' + t.html('consoleXacml.th.allowed') +
      '</th><th class="num">' + t.html('consoleXacml.th.refused') + '</th>' +
      '<th class="num">' + t.html('consoleXacml.th.notEnforcedHere') + '</th>' +
      '<th class="num">' + t.html('consoleXacml.th.refusedObligation') +
      '</th><th>' + t.html('consoleXacml.th.whatItIs') + '</th></tr>' +
      evidenceRow(t.html('consoleXacml.monitor.here'), here,
        t.html('consoleXacml.monitor.hereWhat', { since: json.since })) +
      evidenceRow(t.html('consoleXacml.monitor.remote'), there,
        t.html('consoleXacml.monitor.remoteWhat')) +
      evidenceRow(t.html('consoleXacml.monitor.combined'), combined,
        t.html('consoleXacml.monitor.combinedWhat')) +
      '</table>' +
      kit.note(
        '<p>' + t.html('consoleXacml.monitor.addUp') +
        '</p>',
        t.text('consoleXacml.monitor.addUpLabel'));

    // The audit-log link is markup a message cannot carry (#539).
    const what = kit.note(
      '<p>' + t.html('consoleXacml.monitor.p1') +
      '</p><p>' + t.html('consoleXacml.monitor.p2') +
      '</p><p>' + t.html('consoleXacml.monitor.p3before') +
      '<a href="/admin/audit">' + t.html('consoleXacml.link.auditLog') +
      '</a>' +
      t.html('consoleXacml.monitor.p3after', {
        realm: json.realm.name || json.realm.id }) +
      '</p><p>' + t.html('consoleXacml.monitor.p4') +
      '</p>',
      t.text('consoleXacml.whatThisPageIs'));

    const off = json.enabled ? '' : kit.warn(
      t.html('consoleXacml.monitor.off'),
      t.text('consoleXacml.monitor.offLabel'));

    // ---------------------------------------------------------------------
    // SECTION TWO: EVERY ENFORCEMENT POINT.
    //
    // ONE TABLE FOR BOTH KINDS rather than two, and that is the decision
    // worth recording. Embedded and remote PEPs differ in where they run and
    // in how this service learns their figures, and they do NOT differ in
    // what a reader wants from the row — who it is, what it guards, its bias,
    // and how many it allowed and refused. Two tables would have meant two
    // renderers that could drift into disagreeing about how a decision is
    // displayed, and a reader comparing an embedded PEP against a remote one
    // would have had to do it across a page break.
    //
    // The `pdp` row is in it as well and is NOT a PEP: it is the endpoint
    // somebody else's PEP asked. It earns its place here because a reader
    // counting decisions has to be able to see all of them, and it is marked
    // as an endpoint on the row with an empty enforcement cell rather than a
    // zero.
    // ---------------------------------------------------------------------
    const allRows = (json.rows as any[]).concat(json.remoteRows);
    const table = '<h2>' + t.html('consoleXacml.monitor.everyPoint') + '</h2>' +
      '<table><tr><th>' + t.html('consoleXacml.th.point') + '</th><th>' +
      t.html('consoleXacml.th.state') + '</th><th>' +
      t.html('consoleXacml.th.bias') + '</th>' +
      '<th class="num">' + t.html('consoleXacml.th.decisions') +
      '</th><th class="num">' + t.html('consoleXacml.th.allowed') + '</th>' +
      '<th class="num">' + t.html('consoleXacml.th.refused') +
      '</th><th class="num">Permit</th>' +
      '<th class="num">Deny</th><th class="num">NotApplicable</th>' +
      '<th class="num">Indeterminate</th><th>' +
      t.html('consoleXacml.th.last') +
      '</th></tr>' +
      allRows.map(function (row) {
        return self.monitorRow(row, t);
      }).join('') + '</table>' +
      kit.note(
        '<p>' + t.html('consoleXacml.monitor.list1') +
        '</p><p>' + t.html('consoleXacml.monitor.list2') +
        '</p><p>' + t.html('consoleXacml.monitor.list3before') +
        '<a href="/admin/xacml/peps">' +
        t.html('consoleXacml.link.remotePeps') + '</a>' +
        t.html('consoleXacml.monitor.list3after') +
        '</p>' +
        // WHERE THE REMOTE ROWS WOULD BE IF THEY ARE NOT HERE (2026-09-06).
        // The register is per realm and this page draws one realm, so a table
        // with no remote row in it has two causes; `noPepsHere()` on the
        // Remote PEPs page argues the whole of it, and this is the same
        // sentence on the page a reader is more likely to be standing on when
        // the question occurs to them. It is drawn ONLY when there are no
        // remote rows here — a page that already lists one does not need
        // telling where to look.
        (json.remoteRows.length
          ? ''
          : '<p>' + self.noPepsHere(json.elsewhere, t) + '</p>'),
        t.text('consoleXacml.monitor.listLabel')) +
      kit.note(
        '<p>' + t.html('consoleXacml.monitor.refusal1before') +
        '<a href="/admin/audit">' + t.html('consoleXacml.link.auditLog') +
        '</a>' +
        t.html('consoleXacml.monitor.refusal1after') +
        '</p><p>' + t.html('consoleXacml.monitor.refusal2before') +
        '<a href="/admin/xacml/decide">' +
        t.html('consoleXacml.link.tryDecision') +
        '</a>' + t.html('consoleXacml.monitor.refusal2after') +
        '</p><p>' + t.html('consoleXacml.monitor.refusal3') +
        '</p>',
        t.text('consoleXacml.monitor.refusalLabel'));

    // The title is the nav label rather than the bare word `Monitor`: this
    // page is drawn among Metrics, Sessions and Tokens now, where `Monitor`
    // alone would name the section it is in instead of the thing it is about.
    return tiles + off + what + evidence + table;
  }

  /**
   * Draws Try a decision from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `decideJson()`'s answer
   * @returns the body as HTML
   */
  static decideBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const form = '<form method="get" action="/admin/xacml/decide">' +
      '<table><tr><td>' + t.html('consoleXacml.decide.subject') + '</td><td>' +
      self.textField('subject', json.subject || 'alice', 24) +
      '</td><td class="sub">' + t.html('consoleXacml.decide.subjectHelp') +
      '</td></tr>' +
      '<tr><td>' + t.html('consoleXacml.decide.action') + '</td><td>' +
      self.textField('action', json.action || 'GET', 24) +
      '</td><td class="sub">' + t.html('consoleXacml.decide.actionHelp') +
      '</td></tr><tr><td>' + t.html('consoleXacml.decide.resource') +
      '</td><td>' +
      self.textField('resource', json.resource || '', 40) +
      '</td><td class="sub">' + t.html('consoleXacml.decide.resourceHelp') +
      '</td></tr></table>' +
      '<button type="submit">' + t.html('consoleXacml.decide.ask') +
      '</button></form>';

    let answer = '';
    if (json.asked) {
      const policies = json.applicablePolicies.length
        ? json.applicablePolicies.map(function (one) {
            return '<code>' + esc(one.id) + '</code>';
          }).join(', ')
        : '<em>' + t.html('consoleXacml.decide.noneApplied') +
          '</em>';
      answer = '<h2>' + esc(json.decision) + '</h2>' +
        '<div class="tiles">' +
        kit.tile(json.decision, t.text('consoleXacml.tile.pdpDecision')) +
        kit.tile(json.enforcement.allowed
          ? t.text('consoleXacml.monitor.allowed')
          : t.text('consoleXacml.monitor.refused'),
                   t.text('consoleXacml.tile.embeddedPep')) +
        kit.tile(json.enforcement.bias, t.text('consoleXacml.tile.pepBias')) +
        '</div>' +
        '<p>' + esc(json.enforcement.why) + '</p>' +
        '<table><tr><th>' + t.html('consoleXacml.decide.applicable') +
        '</th><td>' + policies +
        '</td></tr>' +
        '<tr><th>' + t.html('consoleXacml.decide.obligations') + '</th><td>' +
        (json.obligations.length ? json.obligations.map(esc).join(', ')
                                 : '<em>' + t.html('consoleXacml.none') +
                                 '</em>') +
        '</td></tr>' +
        '<tr><th>' + t.html('consoleXacml.decide.advice') + '</th><td>' +
        (json.advice.length ? json.advice.map(esc).join(', ')
                            : '<em>' + t.html('consoleXacml.none') + '</em>') +
        '</td></tr>' +
        '<tr><th>' + t.html('consoleXacml.decide.status') + '</th><td><code>' +
        esc((json.status || {}).code || '') + '</code>' +
        ((json.status || {}).message
          ? '<div class="sub">' + esc(json.status.message) + '</div>' : '') +
        '</td></tr></table>';
    }

    const explain = kit.note(
      '<p>' + t.html('consoleXacml.decide.p1') +
      '</p><p>' + t.html('consoleXacml.decide.p2') +
      '</p>',
      t.text('consoleXacml.decide.label'));
    return explain + form + answer;
  }

  /**
   * Draws the policy editor from the answer of `GET /admin-api/xacml/editor`:
   * the chooser, the warnings, the policy as a tree with each node's next
   * valid elements and edit form, and the document.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer
   * @returns the body as HTML
   */
  static editorBody(ctx: Json, json: Json): string {
    const t = ctx.t;
    if (!json.policy) {
      // **AN EMPTY REPOSITORY IS NOT AN UNGATED SERVICE**, and this branch
      // used to imply that it was: "there is nothing to edit" on a service
      // whose issuance and access decisions are both being made, every
      // request, by documents this page has never mentioned. The note goes
      // here as well as under the table for exactly that reason — it is the
      // branch where the wrong conclusion is easiest to draw.
      // The link sits inside a <strong>, so the sentence is split around
      // it with the <strong> in the code (#539).
      return kit.warn(t.html('consoleXacml.editor.emptyBefore') +
                      ' <strong>' +
                      t.html('consoleXacml.editor.creatingBefore') +
                      ' <a href="/admin/xacml/policies">' +
                      t.html('consoleXacml.link.policies') + '</a> ' +
                      t.html('consoleXacml.editor.creatingPage') + '</strong>' +
                      t.html('consoleXacml.editor.emptyAfter'),
                      t.text('consoleXacml.editor.nothingLabel')) +
                    XacmlPage.serviceOwnEditorNote(json.serviceOwn, t);
    }

    // The document parsed when the answer was built; a document that does
    // not parse answers its `problem` and no tree.
    const parsed = !json.problem;

    const chooser = '<form method="get" action="/admin/xacml/editor">' +
      t.html('consoleXacml.th.policy') + ' ' +
        XacmlPage.select('policy', json.policies.map(function (one) {
        return { value: one, label: one };
      }), json.policy.name) +
      ' <button type="submit">' + t.html('consoleXacml.editor.open') +
      '</button></form>' +
      XacmlPage.serviceOwnEditorNote(json.serviceOwn, t);

    // WHY THERE IS NO "NEW POLICY" BUTTON ON THIS PAGE, said on the page
    // rather than left to be wondered at. This editor applies ONE structural
    // edit to a STORED document — every control on it posts a policy name and
    // a path into that document — so there is nowhere for a policy that has
    // not been written yet to live. The chooser above offers what the
    // repository holds and cannot offer what it does not.
    //
    // The note is here as well as on the empty-repository branch above
    // because the two readers are different people: that one has no policies
    // at all and this one has some, has opened one, and is looking for the
    // button that makes another. Sending them to the same page for the same
    // reason is the whole of what this says.
    const whereToCreate = kit.note(
      '<p>' + t.html('consoleXacml.editor.where1') +
      ' <strong>' + t.html('consoleXacml.editor.creatingOne') + ' <a ' +
      'href="/admin/xacml/policies">' + t.html('consoleXacml.link.policies') +
      '</a> ' +
      t.html('consoleXacml.editor.creatingPage') + '</strong>' +
      t.html('consoleXacml.editor.where1after') +
      '</p><p>' + t.html('consoleXacml.editor.where2') +
      '</p>',
      t.text('consoleXacml.editor.whereLabel'));

    const liveWarning = json.policy.enabled && json.policy.isRoot
      ? kit.warn(
          t.html('consoleXacml.editor.liveBefore') +
          '<a href="/admin/xacml/policies">' +
          t.html('consoleXacml.link.policies') +
          '</a>' + t.html('consoleXacml.pagePeriod'),
          t.text('consoleXacml.editor.liveLabel'))
      : '';

    const xpathGap = json.xpathVersionGaps.length
      // The list of names is markup built here, so the sentence is drawn
      // around it (#539).
      ? kit.warn(
          (json.xpathVersionGaps.length === 1
             ? t.html('consoleXacml.xpath.one', {
                 name: json.xpathVersionGaps[0] })
             : t.html('consoleXacml.xpath.many') + ': <code>' +
             json.xpathVersionGaps.map(esc).join('</code>, <code>') +
             '</code>') +
          t.html('consoleXacml.xpath.rest'),
          t.text('consoleXacml.xpath.label'))
      : '';

    const problems = json.problems.length
      ? kit.warn('<ul><li>' + json.problems.map(esc).join('</li><li>') +
                   '</li></ul><p>' +
                   t.html('consoleXacml.editor.typeCheck') +
                   '</p>',
                   t.text('consoleXacml.editor.typeCheckLabel'))
      : '';

    const rows = parsed ? json.tree.map(function (row) {
      const adds = row.options.additions;
      const menu = ctx.write && adds.length
        ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
          XacmlPage.hidden('policy', json.policy.name) +
          XacmlPage.hidden('path', row.path) +
          XacmlPage.select('action', adds.map(function (one) {
            return { value: one.action, label: one.label };
          }), '') +
          ' <button type="submit">' + t.html('consoleXacml.editor.add') +
          '</button></form>'
        : '';
      const remove = ctx.write && row.options.removable
        ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
          XacmlPage.hidden('policy', json.policy.name) +
          XacmlPage.hidden('path', row.path) +
          XacmlPage.hidden('action', 'remove') +
          '<button type="submit">' + t.html('consoleXacml.editor.remove') +
          '</button></form>'
        : '';
      const helps = adds.filter(function (one) { return one.help; })
        .map(function (one) {
          return '<strong>' + esc(one.label) + '</strong> — ' + esc(one.help);
        }).join('<br>');
      return '<tr><td style="padding-left:' + (row.depth * 1.4) + 'rem">' +
        '<code>' + esc(row.label) + '</code>' +
        (row.detail ? '<div class="sub">' + esc(row.detail) + '</div>' : '') +
        (ctx.write ? XacmlPage.editFormFor(json, row, t) : '') +
        (helps ? '<div class="sub">' + helps + '</div>' : '') +
        '</td><td class="sub">' + esc(row.kind) + '</td>' +
        '<td>' + menu + ' ' + remove + '</td></tr>';
    }).join('') : '';

    const explain = kit.note(
      '<p>' + t.html('consoleXacml.how.p1') +
      '</p><p>' + t.html('consoleXacml.how.p2before') + '<a ' +
      'href="/admin/xacml/policies">' + t.html('consoleXacml.link.policies') +
      '</a>' +
      t.html('consoleXacml.how.p2after') +
      '</p><p>' + t.html('consoleXacml.how.p3') +
      '</p><p>' + t.html('consoleXacml.how.p4') +
      '</p><p>' + t.html('consoleXacml.how.p5') +
      '</p><p>' + t.html('consoleXacml.how.p6') +
      '</p>',
      t.text('consoleXacml.how.label'));

    const body = chooser + whereToCreate + liveWarning + problems + xpathGap +
      explain +
      '<table><tr><th>' + t.html('consoleXacml.th.element') + '</th><th>' +
      t.html('consoleXacml.th.kind') + '</th><th>' +
      t.html('consoleXacml.th.addRemove') +
      '</th></tr>' +
      rows + '</table>' +
      '<details><summary>' + t.html('consoleXacml.editor.asAlfa') +
      '</summary>' +
      kit.note(
        '<p>' + t.html('consoleXacml.editor.alfa1') +
        '</p><p>' + t.html('consoleXacml.editor.alfa2') +
        '</p>',
        t.text('consoleXacml.editor.alfaLabel')) +
      '<pre>' + esc(json.alfa || '') + '</pre></details>' +
      '<details><summary>' + t.html('consoleXacml.editor.asStored') +
      '</summary><pre>' +
      esc(json.document) + '</pre></details>';

    return body;
  }

  // The inline edit form for one node, or '' where the node has no fields of
  // its own. This is where the "next valid element" idea stops being a menu and
  // becomes a form: a Match's function dropdown carries only the two-argument
  // boolean predicates, and choosing one RESETS the datatype of both its value
  // and its attribute, because a Match whose literal is a string and whose
  // designator is an integer does not typecheck.
  //
  // SEVERAL ROWS CARRY MORE THAN ONE FORM, and they are separate on purpose
  // rather than being one wide one. Every edit action here keeps whatever the
  // submitted form did not mention, so a small form that changes a Match's
  // function cannot disturb its attribute — and a person pressing Update under
  // "Reference" can see that the function is not part of what they are
  // changing.
  static editFormFor(json: Json, row: Json, t: Json): string {
    if (!row.edit) {
      return '';
    }
    const node = row.edit.node;
    const head = '<form method="post" action="/admin/xacml/editor" ' +
      'class="inline">' + XacmlPage.hidden('policy', json.policy.name) +
      XacmlPage.hidden('path', row.path);

    // A POLICY AND A POLICY SET TAKE THE SAME FORM AND NOT THE SAME MENU. The
    // rule-combining and policy-combining algorithm URIs differ by one segment
    // and a set carrying the rule spelling names an algorithm no combiner can
    // find, so the menu comes from `algorithmMenuFor()` — one function, used
    // here and by the handler that validates the answer, so the page cannot
    // offer something the edit then refuses.
    if (row.kind === 'policy' || row.kind === 'policySet') {
      const menu = row.edit.algorithms || [];
      const chosen: any = menu.filter(function (one) {
        return one.uri === node.combiningAlgId;
      })[0] || {};
      return head + XacmlPage.hidden('action', 'edit-policy') +
        (row.kind === 'policySet' ? 'PolicySetId ' : 'PolicyId ') +
        XacmlPage.textField('id', node.id, 40) + ' ' +
        XacmlPage.select('combiningAlgId', menu.map(function (one) {
          return { value: one.uri, label: one.label };
        }), node.combiningAlgId) +
        ' Version ' + XacmlPage.textField('version', node.version || '1.0', 6) +
        '<br>Description ' +
        XacmlPage.textField('description', node.description, 60) +
        '<br>MaxDelegationDepth ' +
        XacmlPage.textField('maxDelegationDepth', node.maxDelegationDepth, 4) +
        ' XPathVersion ' +
        XacmlPage.textField('xpathVersion', node.xpathVersion, 44) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' + esc(chosen.what || '') + '</div>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.policyHelp', {
          defaults: row.kind === 'policySet' ? 'PolicySetDefaults'
                                             : 'PolicyDefaults' }) +
        '</div>';
    }

    if (row.kind === 'reference') {
      return head + XacmlPage.hidden('action', 'edit-reference') +
        esc(node.kind) + ' ' + XacmlPage.textField('ref', node.ref, 44) +
        ' Version ' + XacmlPage.textField('version', node.version, 8) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.referenceHelp') +
        '</div>';
    }

    if (row.kind === 'rule') {
      return head + XacmlPage.hidden('action', 'edit-rule') +
        XacmlPage.select('effect', [{ value: 'Permit', label: 'Permit' },
                          { value: 'Deny', label: 'Deny' }], node.effect) +
        ' RuleId ' + XacmlPage.textField('id', node.id, 36) +
        ' Description ' +
          XacmlPage.textField('description', node.description, 40) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>';
    }

    if (row.kind === 'variable') {
      const rename = head + XacmlPage.hidden('action', 'edit-variable') +
        // FROM THE PATH rather than from the label: the label is prose this
        // page composes and a change to it would silently start renaming
        // variables to something with a description stuck on the end.
        'VariableId $' + XacmlPage.textField('variableId',
                                   String(row.path).split('.').pop(), 12) +
        ' <button type="submit">' + t.html('consoleXacml.form.rename') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.variableHelp') +
        '</div>';
      // The definition IS an expression, so the expression's own form follows —
      // one row, two forms, rather than a variable you can rename and whose
      // value you cannot reach.
      return rename + XacmlPage.expressionForm(json, row, node, t);
    }

    if (row.kind === 'match') {
      const menu = json.menus.matchFunctions;
      const reference = node.reference || {};
      const selector = reference.kind === 'selector';
      const test = head + XacmlPage.hidden('action', 'edit-match') +
        XacmlPage.select('matchId', menu, node.matchId) + ' ' +
        XacmlPage.textField('value', node.value.lexical, 18) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.matchType', {
          type: row.edit.valueShortType }) + '</div>';
      const against = head + XacmlPage.hidden('action', 'edit-match') +
        t.html('consoleXacml.form.against') + ' ' +
        XacmlPage.select('referenceKind',
               [{ value: 'designator',
                  label: t.text('consoleXacml.form.anAttribute') },
                { value: 'selector',
                  label: t.text('consoleXacml.form.aSelector') }],
               selector ? 'selector' : 'designator') + ' ' +
        (selector ? 'Path ' + XacmlPage.textField('path', reference.path, 24)
                  : 'AttributeId ' +
                    XacmlPage.textField('attributeId',
                                        reference.attributeId, 24)) +
        ' ' + t.html('consoleXacml.form.in') + ' ' +
        XacmlPage.select('category',
                         json.menus.categories, reference.category) +
        (selector
           ? ' ContextSelectorId ' +
             XacmlPage.textField('contextSelectorId',
                            reference.contextSelectorId, 20)
           : ' Issuer ' + XacmlPage.textField('issuer', reference.issuer, 16)) +
        ' ' + t.html('consoleXacml.form.mustBePresent') + ' ' +
        XacmlPage.yesNo('mustBePresent', reference.mustBePresent, t) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.matchHelp') +
        '</div>';
      return test + against;
    }

    if (row.kind === 'assignment') {
      return head + XacmlPage.hidden('action', 'edit-assignment') +
        'AttributeId ' +
          XacmlPage.textField('attributeId', node.attributeId, 30) +
        ' Category ' + XacmlPage.select('category',
                              [{ value: '',
                                 label: t.text('consoleXacml.form.noneParen') }]
                                .concat(json.menus.categories),
                              node.category || '') +
        ' Issuer ' + XacmlPage.textField('issuer', node.issuer, 16) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.assignmentHelp') +
        '</div>';
    }

    if (row.kind === 'obligation') {
      return head + XacmlPage.hidden('action', 'edit-obligation') +
        XacmlPage.textField('id', node.id, 40) + ' ' +
        t.html('consoleXacml.form.firesOn') + ' ' +
        XacmlPage.select('on', [{ value: 'Permit', label: 'Permit' },
                      { value: 'Deny', label: 'Deny' }], node.on) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>';
    }

    if (row.kind === 'expression') {
      return XacmlPage.expressionForm(json, row, node, t);
    }
    return '';
  }
  // The five expression kinds that have fields of their own. Separate from
  // `editFormFor()` because a VariableDefinition is an expression too and needs
  // exactly these forms under its rename box — written twice they would drift,
  // and the sixth kind (`variableRef`) is deliberately absent from both: its
  // whole content is which variable it names, and that is chosen by REPLACING
  // it from the Add menu, where the list of legal names is computed.
  static expressionForm(json: Json, row: Json, node: Json, t: Json): string {
    const head = '<form method="post" action="/admin/xacml/editor" ' +
      'class="inline">' + XacmlPage.hidden('policy', json.policy.name) +
      XacmlPage.hidden('path', row.path);

    if (node.kind === 'value') {
      const xpath = node.type === json.menus.xpathType;
      return head + XacmlPage.hidden('action', 'edit-value') +
        XacmlPage.textField('lexical', node.lexical, 24) + ' ' +
        t.html('consoleXacml.form.as') + ' ' +
        XacmlPage.select('type', json.menus.types, node.type) +
        (xpath
           ? ' ' + t.html('consoleXacml.form.over') + ' ' +
             XacmlPage.select('xpathCategory', json.menus.categories,
                               node.xpathCategory ||
                                 json.menus.resourceCategory)
           : '') +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        (xpath
           ? '<div class="sub">' +
             t.html('consoleXacml.form.xpathHelp') +
             '</div>'
           : '');
    }

    if (node.kind === 'designator') {
      return head + XacmlPage.hidden('action', 'edit-designator') +
        XacmlPage.textField('attributeId', node.attributeId, 24) + ' ' +
        t.html('consoleXacml.form.in') + ' ' +
        XacmlPage.select('category', json.menus.categories, node.category) +
        ' ' + t.html('consoleXacml.form.as') + ' ' +
        XacmlPage.select('dataType', json.menus.types, node.dataType) +
        ' Issuer ' + XacmlPage.textField('issuer', node.issuer, 16) +
        ' ' + t.html('consoleXacml.form.mustBePresent') + ' ' +
        XacmlPage.yesNo('mustBePresent', node.mustBePresent, t) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.issuerHelp') +
        '</div>';
    }

    if (node.kind === 'selector') {
      const bindings = Object.keys(node.namespaces || {})
        .filter(function (prefix) {
          return prefix !== '';
        }).sort().map(function (prefix) {
          return '<code>' + esc(prefix) + '</code> → <code>' +
            esc(node.namespaces[prefix]) + '</code>';
        }).join(', ');
      return head + XacmlPage.hidden('action', 'edit-selector') +
        'Path ' + XacmlPage.textField('path', node.path, 30) + ' ' +
        t.html('consoleXacml.form.over') + ' ' +
        XacmlPage.select('category', json.menus.categories, node.category) +
        ' ' + t.html('consoleXacml.form.as') + ' ' +
        XacmlPage.select('dataType', json.menus.types, node.dataType) +
        '<br>ContextSelectorId ' +
        XacmlPage.textField('contextSelectorId', node.contextSelectorId, 24) +
        ' ' + t.html('consoleXacml.form.mustBePresent') + ' ' +
        XacmlPage.yesNo('mustBePresent', node.mustBePresent, t) +
        ' &nbsp; ' + t.html('consoleXacml.form.namespace') + ' ' +
        XacmlPage.textField('namespacePrefix', '', 6) +
        ' = ' +
        XacmlPage.textField('namespaceUri', '', 30) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.selectorHelp') +
        '</div>' +
        '<div class="sub">' + t.html('consoleXacml.form.bindings') +
        (bindings ? ': ' + bindings : ': ' + t.html('consoleXacml.none')) +
        t.html('consoleXacml.form.bindingsHelp') +
        '</div>';
    }

    if (node.kind === 'function') {
      return head + XacmlPage.hidden('action', 'edit-function') +
        XacmlPage.select('functionId',
                         json.menus.functions, node.functionId) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.functionHelp') +
        '</div>';
    }

    if (node.kind === 'apply') {
      return head + XacmlPage.hidden('action', 'edit-apply') +
        XacmlPage.select('functionId',
                         json.menus.functions, node.functionId) +
        ' Description ' +
          XacmlPage.textField('description', node.description, 30) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>';
    }

    if (node.kind === 'variableRef') {
      // POINTING IT AT ANOTHER VARIABLE IS A REPLACEMENT, and the same action
      // the Add menu uses: `set-expression-variable` puts a new
      // VariableReference where this one is. The menu is the variables THIS
      // POLICY defines — computed by the grammar rather than listed here, so a
      // reference to a variable belonging to a sibling policy cannot be chosen.
      const scope = row.edit.scope || [];
      if (!scope.length) {
        return '<div class="sub">' +
          t.html('consoleXacml.form.undefinedVariable', {
            name: node.variableId }) +
          '</div>';
      }
      return head + XacmlPage.hidden('action', 'set-expression-variable') +
        XacmlPage.select('variableId', scope.map(function (one) {
          return { value: one.id, label: '$' + one.id + '  — ' + one.detail };
        }), node.variableId) +
        ' <button type="submit">' + t.html('consoleXacml.editor.update') +
        '</button></form>' +
        '<div class="sub">' +
        t.html('consoleXacml.form.scopeHelp') +
        '</div>';
    }
    return '';
  }

  // A yes/no select, the editor's boolean control.
  /**
   * Draws a yes/no select.
   *
   * @param name - the field's name
   * @param value - whether it is yes
   * @param t - the page's translator (#539): the option LABELS are words,
   *   the values stay `false` and `true`
   * @returns the select as HTML
   */
  static yesNo(name: string, value: unknown, t: Json): string {
    return XacmlPage.select(name, [{ value: 'false',
      label: t.text('consoleXacml.no') },
                         { value: 'true', label: t.text('consoleXacml.yes') }],
                  value ? 'true' : 'false');
  }

}

export = XacmlPage;
