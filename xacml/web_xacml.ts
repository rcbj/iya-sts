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

  // ---------------------------------------------------------------------------
  // THE REMOTE PEP'S FIELD TOOLTIPS (#1760, rcbj 2026-11-14: "Make better
  // field tooltips on all the new tabs under Protocols->XACML"). The
  // console's one mechanism, `kit.tip()` as a `title`, given the WHOLE
  // sentence (`Infinity`): each says what the field does, its values and
  // default, when it takes effect and, where it applies, the precedence.
  // The prose has two other doors, which is the condition admin-ui/CLAUDE.md
  // sets for a tooltip-only sentence: docs/remote-pep.md and the management
  // API's own descriptions.
  // ---------------------------------------------------------------------------
  static tipOf(t: Json, key: string, vars?: Json): string {
    return kit.tip(t.text(key, vars), Infinity);
  }

  // A table heading with its tooltip.
  static th(t: Json, labelKey: string, tipKey: string): string {
    return '<th' + XacmlPage.tipOf(t, tipKey) + '>' + t.html(labelKey) +
      '</th>';
  }

  // A form field's label with its tooltip, around the control.
  static labelled(t: Json, labelKey: string, tipKey: string, control: string,
                  extraTip?: string): string {
    const tip = t.text(tipKey) + (extraTip ? ' ' + t.text(extraTip) : '');
    return '<label' + kit.tip(tip, Infinity) + '>' + t.html(labelKey) + ' ' +
      control + '</label>';
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
        source = '<strong class="xacml-alert">' +
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
      return '<a href="/realm/' + esc(one.id) +
        '/admin/xacml#xacml-tab-peps"><code>' +
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
        : '') +
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
      '</p>',
      t.text('consoleXacml.overview.label'));
    return tiles + rootWarning + what +
                  SettingsForms.forms(json.settings, '/admin/xacml',
                                      undefined, t);
  }

  /**
   * Draws the AuthZEN tab (#563) from `GET /admin-api/xacml/authzen`: the
   * API's state and settings, its attribute catalogue with the form that
   * adds a row, the callers in the AUTHZEN_PEPS group with their scopes and
   * callback URLs, and the realm's access requests with their acts (#1180).
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the tab's view
   * @returns the body as HTML
   */
  static authzenBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const writable = ctx.write;
    // Moved onto the tab by `WebPages.xacmlTabLinks()`, as the other tabs'
    // forms are: `/admin/xacml#xacml-tab-authzen`, which the operations
    // mirror.
    const PAGE = '/admin/xacml/authzen';
    const view = json || {};
    const cat = view.catalogue || { rows: [], problems: [], objects: [],
                                    categories: [], dataTypes: [],
                                    multiplicities: [] };
    const tail = function (uri) {
      return String(uri || '').replace(/^.*[#:]/, '');
    };
    const tiles = '<div class="tiles">' +
      kit.tile(view.enabled && view.xacmlEnabled && view.apiObject
        ? t.text('consoleXacml.yes') : t.text('consoleXacml.no'),
               t.text('consoleXacml.authzen.tile.answers')) +
      kit.tile(view.callerAuthentication || 'mtls',
               t.text('consoleXacml.authzen.tile.door')) +
      kit.tile(cat.rows.length, t.text('consoleXacml.authzen.tile.rows')) +
      kit.tile(view.callersTotal || 0,
               t.text('consoleXacml.authzen.tile.callers')) +
      '</div>';
    const what = kit.note(
      '<p>' + t.html('consoleXacml.authzen.p1') + '</p><p>' +
      t.html('consoleXacml.authzen.p2') + '</p>',
      t.text('consoleXacml.authzen.label'));
    const missing = view.apiObject ? '' : kit.warn(
      t.html('consoleXacml.authzen.noObject'),
      t.text('consoleXacml.authzen.noObjectLabel'));
    const problems = cat.problems.length ? kit.warn(
      cat.problems.map(esc).join('<br>'),
      t.text('consoleXacml.authzen.problemsLabel')) : '';
    const rows = cat.rows.map(function (row) {
      const remove = writable
        ? '<form method="post" action="' + PAGE + '" class="inline">' +
          self.hidden('action', 'remove-attribute') +
          self.hidden('object', row.object) +
          self.hidden('property', row.property) +
          '<button type="submit">' +
          t.html('consoleXacml.authzen.remove') + '</button></form>'
        : '<span class="sub">' + t.html('consoleXacml.readOnly') + '</span>';
      return '<tr><td><code>' + esc(row.object + '.' + row.property) +
        '</code>' + (row.description
          ? '<div class="sub">' + esc(row.description) + '</div>' : '') +
        '</td><td><code>' + esc(row.attributeId) + '</code></td><td>' +
        esc(tail(row.category)) + '</td><td>' + esc(tail(row.dataType)) +
        '</td><td>' + esc(row.multiplicity) + '</td><td>' + remove +
        '</td></tr>';
    }).join('') || '<tr><td colspan="6">' +
      t.html('consoleXacml.authzen.noRows') + '</td></tr>';
    const options = function (values, blank?) {
      return (blank ? [{ value: '', label: blank }] : []).concat(
        (values || []).map(function (one) {
          return { value: one, label: one };
        }));
    };
    const add = writable
      ? '<h3>' + t.html('consoleXacml.authzen.addHeading') + '</h3>' +
        '<form method="post" action="' + PAGE + '">' +
        self.hidden('action', 'set-attribute') +
        '<table><tr><td>' + t.html('consoleXacml.authzen.object') +
        '</td><td>' + self.select('object', options(cat.objects), '') +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.property') +
        '</td><td>' + self.textField('property', '', 30) +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.attributeId') +
        '</td><td>' + self.textField('attributeId', '', 50) +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.category') +
        '</td><td>' + self.select('category', options(cat.categories,
          t.text('consoleXacml.authzen.objectsOwn')), '') +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.dataType') +
        '</td><td>' + self.select('dataType', options(cat.dataTypes),
                                  'string') +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.multiplicity') +
        '</td><td>' + self.select('multiplicity',
                                  options(cat.multiplicities), 'single') +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.description') +
        '</td><td>' + self.textField('description', '', 50) +
        '</td></tr></table><p class="sub">' +
        t.html('consoleXacml.authzen.reserved') + '</p>' +
        '<button type="submit">' + t.html('consoleXacml.authzen.save') +
        '</button></form>'
      : '';
    const callers = (view.callers || []).map(function (one) {
      return '<tr><td><code>' + esc(one.name) + '</code><div class="sub">' +
        esc(one.dn || '') + '</div></td><td>' + esc(one.kind) + '</td><td>' +
        ((one.applications || []).length
          ? (one.applications || []).map(function (app) {
            return '<code>' + esc(app) + '</code>';
          }).join(', ')
          : '<em>' + t.html('consoleXacml.authzen.noScope') + '</em>') +
        '</td><td>' + ((one.callbacks || []).map(function (url) {
          return '<code>' + esc(url) + '</code>';
        }).join('<br>') || '—') +
        '</td></tr>';
    }).join('') || '<tr><td colspan="4">' +
      t.html('consoleXacml.authzen.noCallers') + '</td></tr>';
    // THE CALLBACK URLS A CALLER MAY NAME (#1180): replaced whole.
    const callbackForm = writable
      ? '<h3>' + t.html('consoleXacml.authzen.callbacksHeading') + '</h3>' +
        '<form method="post" action="' + PAGE + '">' +
        self.hidden('action', 'set-callbacks') +
        '<table><tr><td>' + t.html('consoleXacml.authzen.caller') +
        '</td><td>' + self.textField('caller', '', 40) +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.callbacks') +
        '</td><td>' + self.textField('callbacks', '', 60) +
        '</td></tr></table><p class="sub">' +
        t.html('consoleXacml.authzen.callbacksNote') + '</p>' +
        '<button type="submit">' +
        t.html('consoleXacml.authzen.setCallbacks') + '</button></form>'
      : '';
    // THE ACCESS REQUESTS (#1180): every one of the realm's, newest first,
    // with the acts an administrator may take — each asked of the
    // access-control policy as an approver's is in the portal.
    const ar = view.accessRequests || { enabled: false, rows: [] };
    const actForm = function (action, id, label, danger) {
      return '<form method="post" action="' + PAGE + '" ' +
        'class="inline">' + self.hidden('action', action) +
        self.hidden('request', id) + '<button type="submit"' +
        (danger ? ' class="danger"' : '') + '>' + label +
        '</button></form> ';
    };
    const code = function (value) {
      return '<code>' + esc(String(value == null ? '' : value)) + '</code>';
    };
    const requestRows = (ar.rows || []).map(function (row) {
      const subject = row.subject || {};
      const resource = row.resource || {};
      const acts = !writable ? '' : (row.status === 'pending'
        ? actForm('approve-access-request', row.id,
                  t.html('consoleXacml.authzen.approve'), false) +
          actForm('deny-access-request', row.id,
                  t.html('consoleXacml.authzen.deny'), true) +
          actForm('cancel-access-request', row.id,
                  t.html('consoleXacml.authzen.cancel'), true)
        : (row.status === 'approved' && row.approval &&
           !row.approval.revoked
          ? actForm('revoke-access-request', row.id,
                    t.html('consoleXacml.authzen.revoke'), true) : ''));
      return '<tr><td>' + code(row.id) + '<div class="sub">' +
        esc(t.date(Number(row.createdAt) * 1000)) + '</div></td><td>' +
        code(subject.type) + ' ' + code(subject.id) + '<div class="sub">' +
        code((row.action || {}).name) + ' ' + code(resource.type) + ' ' +
        code(resource.id) + '</div></td><td>' + code(row.application) +
        '<div class="sub">' + code(row.requester) + '</div></td><td>' +
        t.html('consoleXacml.authzen.requestStatus',
               { status: String(row.status) }) +
        (row.emergency ? ' <strong>' +
          t.html('consoleXacml.authzen.emergency') + '</strong>' : '') +
        (row.approval ? '<div class="sub">' +
          t.html(row.approval.revoked ? 'consoleXacml.authzen.revoked'
                                      : 'consoleXacml.authzen.approvedUntil',
                 { who: String(row.approval.approver || ''),
                   when: t.date(Number(row.approval.approvedUntil) * 1000) }) +
          '</div>' : '') + '</td><td>' + acts + '</td></tr>';
    }).join('') || '<tr><td colspan="5">' +
      t.html('consoleXacml.authzen.noRequests') + '</td></tr>';
    const requests = '<h2>' + t.html('consoleXacml.authzen.requestsHeading') +
      '</h2><p class="sub">' + t.html('consoleXacml.authzen.requestsNote') +
      (ar.enabled ? '' : ' ' + t.html('consoleXacml.authzen.requestsOff')) +
      '</p><table><thead><tr><th>' +
      t.html('consoleXacml.authzen.request') + '</th><th>' +
      t.html('consoleXacml.authzen.asked') + '</th><th>' +
      t.html('consoleXacml.authzen.applicationAndPep') + '</th><th>' +
      t.html('consoleXacml.authzen.state') + '</th><th></th></tr></thead>' +
      '<tbody>' + requestRows + '</tbody></table>';
    const scope = writable
      ? '<h3>' + t.html('consoleXacml.authzen.scopeHeading') + '</h3>' +
        '<form method="post" action="' + PAGE + '">' +
        self.hidden('action', 'set-scope') +
        '<table><tr><td>' + t.html('consoleXacml.authzen.caller') +
        '</td><td>' + self.textField('caller', '', 40) +
        '</td></tr><tr><td>' + t.html('consoleXacml.authzen.applications') +
        '</td><td>' + self.textField('applications', '', 50) +
        '</td></tr></table><button type="submit">' +
        t.html('consoleXacml.authzen.setScope') + '</button></form>'
      : '';
    return tiles + missing + what +
      (view.settings ? SettingsForms.forms(view.settings, PAGE, ['AuthZEN'],
                                           t) : '') +
      '<h2>' + t.html('consoleXacml.authzen.catalogueHeading') + '</h2>' +
      problems + '<table><thead><tr><th>' +
      t.html('consoleXacml.authzen.property') + '</th><th>' +
      t.html('consoleXacml.authzen.attributeId') + '</th><th>' +
      t.html('consoleXacml.authzen.category') + '</th><th>' +
      t.html('consoleXacml.authzen.dataType') + '</th><th>' +
      t.html('consoleXacml.authzen.multiplicity') + '</th><th></th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>' + add +
      '<h2>' + t.html('consoleXacml.authzen.callersHeading') + '</h2>' +
      '<p class="sub">' + t.html('consoleXacml.authzen.callersNote') +
      '</p><table><thead><tr><th>' + t.html('consoleXacml.authzen.caller') +
      '</th><th>' + t.html('consoleXacml.authzen.kind') + '</th><th>' +
      t.html('consoleXacml.authzen.applications') + '</th><th>' +
      t.html('consoleXacml.authzen.callbacks') + '</th></tr></thead>' +
      '<tbody>' + callers + '</tbody></table>' + scope + callbackForm +
      requests;
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

    // AN APPLICATION'S OWN POLICY IS LISTED WITH ITS APPLICATION (#564,
    // P5), in the section below, not among the repository's: it is never
    // the root, never pulled, and is removed only as an orphan, so a row
    // beside the root's offering the same three buttons would invite the
    // two the server refuses.
    const rows = json.policies.filter(function (row) {
      return !row.application;
    }).map(function (row) {
      const problems = row.problems.length
        ? '<div class="sub xacml-alert">' +
          row.problems.map(esc).join('<br>') + '</div>'
        : '';
      const actions = writable ? '<form method="post" ' +
        'action="/admin/xacml/policies" class="inline">' +
        self.hidden('action', row.enabled ? 'disable' : 'enable') +
        self.hidden('name', row.name) +
        '<button type="submit">' + (row.enabled
          ? t.html('consoleXacml.policies.disable')
          : t.html('consoleXacml.policies.enable')) +
        '</button></form> ' +
        // An application's own policy (#564) is never offered as the root.
        (row.isRoot || row.application ? '' : '<form method="post" ' +
          'action="/admin/xacml/policies" class="inline">' +
          self.hidden('action', 'set-root') + self.hidden('name', row.name) +
          '<button type="submit">' + t.html('consoleXacml.policies.makeRoot') +
          '</button></form> ') +
        '<form method="post" action="/admin/xacml/policies" ' +
        'class="inline">' +
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
      self.applicationPoliciesSection(json, writable, t) +
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

  // -------------------------------------------------------------------------
  // THE APPLICATIONS' OWN POLICIES (#564, P5), grouped by application —
  // `applicationPolicies` on `GET /admin-api/xacml/policies`. Each policy
  // links into the editor like any other; Enable and Disable are the
  // repository's own actions; **Make root is never offered** (STS-FGA-0002
  // refuses it anyway); and **Remove is offered only for a policy no
  // application names** — an orphan of a deleted application, decision 3's
  // "an administrator removes it" — because the one an application still
  // names is refused (STS-FGA-0022) and is reset from the application's own
  // Fine-grained authorization tab, which the application cell links to.
  // -------------------------------------------------------------------------
  /**
   * Draws the policies applications own, grouped by application.
   *
   * @param json - `policiesJson()`'s answer
   * @param writable - whether the reader may change them
   * @param t - the page's translator (#539)
   * @returns the section's HTML
   */
  static applicationPoliciesSection(json: Json, writable: boolean,
                                    t: Json): string {
    const self = this;
    const groups = json.applicationPolicies || [];
    const rows = groups.map(function (group) {
      const who = group.known
        ? '<a href="/admin/applications?application=' +
          encodeURIComponent(group.application) + '#tab-fga"><code>' +
          esc(group.application) + '</code></a>' + (group.enforced
            ? ' <strong>' + t.html('consoleXacml.fga.enforced') + '</strong>'
            : '')
        : '<code>' + esc(group.application) + '</code> <em>' +
          t.html('consoleXacml.fga.deleted') + '</em>';
      return (group.policies || []).map(function (row, n) {
        const marks = [];
        if (row.orphanedAt) {
          marks.push('<span class="state-revoked">' +
            t.html('consoleXacml.fga.orphaned', { when: row.orphanedAt }) +
            '</span>');
        } else if (!row.referenced) {
          marks.push('<span class="state-revoked">' +
            t.html('consoleXacml.fga.unreferenced') + '</span>');
        }
        const actions = writable
          ? '<form method="post" action="/admin/xacml/policies" ' +
            'class="inline">' +
            self.hidden('action', row.enabled ? 'disable' : 'enable') +
            self.hidden('name', row.name) + '<button type="submit">' +
            (row.enabled ? t.html('consoleXacml.policies.disable')
                         : t.html('consoleXacml.policies.enable')) +
            '</button></form> ' + (row.referenced ? ''
              : '<form method="post" action="/admin/xacml/policies" ' +
                'class="inline">' + self.hidden('action', 'delete') +
                self.hidden('name', row.name) + '<button type="submit" ' +
                'title="' + esc(t.text('consoleXacml.fga.removeTip')) + '">' +
                t.html('consoleXacml.fga.remove') + '</button></form>')
          : '<span class="sub">' + t.html('consoleXacml.readOnly') +
            '</span>';
        return '<tr><td>' + (n === 0 ? who : '') + '</td><td>' +
          '<a href="/admin/xacml/editor?policy=' +
          encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
          '</code></a>' + (marks.length ? '<div class="sub">' +
            marks.join(' ') + '</div>' : '') + '</td><td><code>' +
          esc(row.policyId || '') + '</code></td><td>' +
          esc(row.version || '') + '</td><td>' + (row.enabled
            ? t.html('consoleXacml.policies.enabled')
            : '<em>' + t.html('consoleXacml.policies.disabled') + '</em>') +
          '</td><td>' + actions + '</td></tr>';
      }).join('');
    }).join('') || '<tr><td colspan="6">' +
      t.html('consoleXacml.fga.none') + '</td></tr>';
    return '<h2 id="fga-policies">' + t.html('consoleXacml.fga.heading') +
      '</h2>' + kit.note('<p>' + t.html('consoleXacml.fga.p1') + '</p><p>' +
        t.html('consoleXacml.fga.p2') + '</p>',
        t.text('consoleXacml.fga.label')) +
      '<table><tr><th>' + t.html('consoleXacml.fga.thApplication') +
      '</th><th>' + t.html('consoleXacml.th.name') + '</th><th>PolicyId' +
      '</th><th>' + t.html('consoleXacml.fga.thVersion') + '</th><th>' +
      t.html('consoleXacml.th.state') + '</th><th>' +
      t.html('consoleXacml.th.actions') + '</th></tr>' + rows + '</table>';
  }

  // ONE PEP's STATE, its certificate, its notify address, its listener
  // certificate and its two row actions: drawn on the Remote PEPs table and
  // on the PEP's own page (#1760) from the same row.
  static pepState(t: Json, row: Json): string {
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
    return state.join(', ') +
      '<div class="sub">' + t.html('consoleXacml.pep.lastSeen', {
        at: row.lastSeen || t.text('consoleXacml.pep.never') }) + '</div>';
  }

  // THE AUTHENTICATION IS ON THE ROW AND NOT IN A FOOTNOTE. A registration
  // that proved nothing must not look the same as one that proved
  // something, which is the whole reason the flag is stored rather than
  // inferred from whether a subject happens to be present.
  static pepWho(t: Json, row: Json): string {
    return row.authenticated
      ? '<code>' + esc(row.certificateSubject) + '</code>'
      : '<strong>' + t.html('consoleXacml.pep.unauthenticated') +
        '</strong><div class="sub">' +
        t.html('consoleXacml.pep.unauthenticatedNote') + '</div>';
  }

  // The address the nudge dials: the one set on the PEP's page, else the
  // one it registered with (#1760).
  //
  // A SHORT STATUS, AND THE LONG SENTENCES FOLDED (rcbj, 2026-11-14: "for
  // the very large block of text about it in the notify column … make that
  // collapsable"). The cell says usable, unusable with a one-line reason,
  // or not set, and how the last nudge went in two words; the service's own
  // sentences — why a URL is refused, what the PEP answered — go in a
  // `<details>`, collapsed, which needs no script. The reason is read from
  // the URL itself where it can be (plain http, another scheme) and from
  // the sentence where only the service knows (the host allowlist), so the
  // API's answer did not have to grow a member for it.
  static notifyReason(url: string, problem: string): string {
    if (/^http:\/\//i.test(url)) {
      return 'http';
    }
    if (!/^https:\/\//i.test(url)) {
      return 'scheme';
    }
    if (/pepNotifyAllowedHosts/.test(problem)) {
      return 'host';
    }
    return 'other';
  }

  static pepNotify(t: Json, row: Json): string {
    const url = row.effectiveNotifyUrl || row.notifyUrl;
    // REJECTED BY THE PEP (2026-11-14, rcbj): a notify URL set at its
    // environment or here that is not https. The PEP then advertises none
    // and does not fall back to a derived one (`STS-XPEP-0113`).
    const inUse = row.settingsInUse && row.settingsInUse.values
      ? row.settingsInUse.values.notifyUrl : null;
    const rejected = inUse && inUse.rejected === true
      ? '<div class="sub xacml-alert">' +
        t.html('consoleXacml.pep.notifyRejected',
               { url: String(inUse.value || '') }) + '</div>'
      : '';
    if (!url) {
      return '<span class="sub">' + t.html('consoleXacml.pep.noNotify') +
        '</span>' + rejected;
    }
    const problem = String(row.notifyProblem || '');
    // Each reason by its own key, so the catalogs' check finds them.
    const reasons: Json = {
      http: t.html('consoleXacml.pep.notifyUnusable.http'),
      scheme: t.html('consoleXacml.pep.notifyUnusable.scheme'),
      host: t.html('consoleXacml.pep.notifyUnusable.host'),
      other: t.html('consoleXacml.pep.notifyUnusable.other')
    };
    const status = problem
      ? '<div class="sub xacml-alert">' +
        reasons[this.notifyReason(String(url), problem)] + '</div>'
      : '<div class="sub">' + t.html('consoleXacml.pep.notifyUsable') +
        '</div>';
    const last = String(row.lastNotify || '');
    const lastLine = last
      ? '<div class="sub">' + t.html(/answered 2\d\d/.test(last)
          ? 'consoleXacml.pep.lastNudgeDelivered'
          : 'consoleXacml.pep.lastNudgeFailed') + '</div>'
      : '';
    const details = problem || last
      ? '<details class="sub"><summary>' +
        t.html('consoleXacml.pep.notifyDetails') + '</summary>' +
        (problem ? '<div>' + esc(problem) + '</div>' : '') +
        (last ? '<div>' + esc(last) + '</div>' : '') + '</details>'
      : '';
    // DERIVED BY THE PEP (2026-11-14): with neither the value set here nor
    // `PEP_NOTIFY_URL`, the PEP advertises one built from its HTTPS
    // listener certificate, and says so in the settings it reports.
    const derived = inUse && inUse.source === 'derived' &&
      inUse.value === url
      ? '<div class="sub">' + t.html('consoleXacml.pep.notifyDerived') +
        '</div>'
      : '';
    return '<code>' + esc(url) + '</code>' + derived + rejected + status +
      lastLine + details;
  }

  // THE HTTPS LISTENER CERTIFICATE (2026-09-13). What this realm ISSUED,
  // and never whether the PEP is serving it: nothing on this page reaches
  // into another process, and the PEP's own GET / is where that is said.
  // The issue control is on the PEP's own page (#1760).
  static pepListener(ctx: Json, json: Json, row: Json,
                     withForm: boolean): string {
    const t = ctx.t;
    const self = this;
    const held = row.listenerCertificate;
    return (held
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
      (withForm && ctx.write
        ? '<form method="post" action="/admin/xacml/peps">' +
          self.hidden('action', 'issue-pep-certificate') +
          self.hidden('name', row.name) +
          '<div class="sub">' + self.labelled(t, 'consoleXacml.pep.moreDns',
            'consoleXacml.tip.issue.dnsNames', '<input name="dnsNames" ' +
            'size="18" placeholder="pep.example.test">') + '</div>' +
          '<div class="sub">' + self.labelled(t,
            'consoleXacml.pep.ipAddresses', 'consoleXacml.tip.issue.ipAddresses',
            '<input name="ipAddresses" size="14" placeholder="10.0.0.5">') +
          '</div>' +
          '<div class="sub">' + self.labelled(t, 'consoleXacml.pep.key',
            'consoleXacml.tip.issue.keyAlg',
            self.select('keyAlg', json.listenerCertificates.keyAlgorithms
              .map(function (one) {
                return { value: one, label: one };
              }), json.listenerCertificates.defaultKeyAlg)) + ' ' +
          '<button type="submit">' + (held
            ? t.html('consoleXacml.pep.reissue')
            : t.html('consoleXacml.pep.issue')) +
          '</button></div></form>'
        : '');
  }

  static pepActions(ctx: Json, row: Json): string {
    const t = ctx.t;
    const self = this;
    return ctx.write
      ? '<form method="post" action="/admin/xacml/peps" ' +
        'class="inline">' +
        self.hidden('action', row.enabled ? 'disable-pep' : 'enable-pep') +
        self.hidden('name', row.name) +
        '<button type="submit">' +
        (row.enabled ? t.html('consoleXacml.pep.stopNudging')
                     : t.html('consoleXacml.pep.nudge')) +
        '</button></form> ' +
        '<form method="post" action="/admin/xacml/peps" ' +
        'class="inline">' +
        self.hidden('action', 'forget-pep') +
        self.hidden('name', row.name) +
        '<button type="submit">' + t.html('consoleXacml.pep.forget') +
        '</button></form>'
      : '<span class="sub">' + t.html('consoleXacml.readOnly') + '</span>';
  }

  static pepCounts(t: Json, row: Json): string {
    return t.html('consoleXacml.pep.counts', {
      decisions: row.decisions, allowed: row.allowed,
      refused: row.refused }) +
      (row.undischargeable
        ? '<div class="sub">' +
          t.html('consoleXacml.pep.undischargeable',
            { n: row.undischargeable }) +
          '</div>'
        : '');
  }

  // ONE PEP's PAGE (#1760): its row drills down to `/admin/xacml/pep`.
  static pepHref(name: string): string {
    return '/admin/xacml/pep?pep=' + encodeURIComponent(name);
  }

  // ONE ROUTE's PAGE (#1760): a route id on the Reverse proxy tab drills
  // down to `/admin/xacml/pep/route`.
  static routeHref(name: string, route: string): string {
    return '/admin/xacml/pep/route?pep=' + encodeURIComponent(name) +
      '&route=' + encodeURIComponent(route);
  }

  // THE REVERSE PROXY TAB'S THREE SUB-TABS (rcbj, 2026-11-14), each an
  // anchor a link or a crumb lands on.
  static readonly PROXY_TAB = 'xacml-pep-tab-proxy';
  static readonly PROXY_ROUTES_TAB = 'xacml-pep-proxy-routes';
  static readonly PROXY_NEW_ROUTE_TAB = 'xacml-pep-proxy-new-route';
  static readonly PROXY_MANIFEST_TAB = 'xacml-pep-proxy-manifest';

  // The way back from a route's page: the PEP's Reverse proxy tab, on its
  // Configured Routes.
  static proxyTabHref(name: string): string {
    return XacmlPage.pepHref(name) + '#' + XacmlPage.PROXY_ROUTES_TAB;
  }

  // THE REMOTE PEPS TAB AS A CRUMB (rcbj, 2026-11-14): a PEP's page and a
  // route's name the tab they were opened from, by the tab's own label.
  static pepsTabCrumb(t: Json): { label: string; href: string } {
    return { label: t.text('console.nav.xacml-peps'),
             href: '/admin/xacml#xacml-tab-peps' };
  }

  /**
   * Draws Remote PEPs from its view: the register as a table, each row a
   * link to the PEP's own page (#1760), where the listener certificate's
   * control, the reverse proxy and the managed settings are.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `pepsJson()`'s answer
   * @returns the body as HTML
   */
  static pepsBody(ctx, json) {
    const t = ctx.t;
    const self = this;

    const rows = json.peps.map(function (row) {
      const proxy = row.proxy
        ? t.html('consoleXacml.pepPage.proxySummary',
                 { n: row.proxy.routes.length }) +
          (row.proxy.enabled ? ''
            : ' <strong>' + t.html('consoleXacml.proxy.disabled') +
              '</strong>') +
          ((row.proxyRoutes || []).some(function (one) {
            return !one.usable;
          })
            ? '<div class="sub xacml-alert">' +
              t.html('consoleXacml.proxy.unusable') + '</div>'
            : '')
        : (row.proxyProblem
            ? '<span class="xacml-alert">' +
              t.html('consoleXacml.proxy.problem') + '</span>'
            : '<span class="sub">' +
              t.html('consoleXacml.pepPage.proxyNone') + '</span>');
      return '<tr><td><a href="' + esc(self.pepHref(row.name)) +
        '"><code>' + esc(row.name) + '</code></a>' +
        (row.resource ? '<div class="sub">' +
                        t.html('consoleXacml.pep.guards',
                          { resource: row.resource }) +
                        '</div>' : '') +
        (row.version
          ? '<div class="sub">' + esc(row.version) + '</div>'
          : '') +
        '</td><td>' + self.pepWho(t, row) + '</td><td>' +
        self.pepState(t, row) + '</td><td>' +
        esc(row.bias || t.text('consoleXacml.pep.notReported')) +
        '</td><td>' + self.pepCounts(t, row) +
        '</td><td>' + self.pepNotify(t, row) + '</td><td>' +
        self.pepListener(ctx, json, row, false) + '</td><td>' + proxy +
        '</td><td>' + self.pepActions(ctx, row) + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="9">' + self.noPepsHere(json.elsewhere, t) +
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
      (json.peps.length
        ? '<p class="sub">' + t.html('consoleXacml.pepPage.openRow') + '</p>'
        : '') +
      self.wide(t, 'console.nav.xacml-peps',
      '<table><tr><th' + self.tipOf(t, 'consoleXacml.tip.peps.name') +
      '>PEP</th>' +
      self.th(t, 'consoleXacml.th.certificate',
              'consoleXacml.tip.peps.certificate') +
      self.th(t, 'consoleXacml.th.state', 'consoleXacml.tip.peps.state') +
      self.th(t, 'consoleXacml.th.itsBias', 'consoleXacml.tip.peps.bias') +
      self.th(t, 'consoleXacml.th.enforced',
              'consoleXacml.tip.peps.enforced') +
      self.th(t, 'consoleXacml.th.notify', 'consoleXacml.tip.peps.notify') +
      self.th(t, 'consoleXacml.th.listener',
              'consoleXacml.tip.peps.listener') +
      self.th(t, 'consoleXacml.pepPage.th.proxy',
              'consoleXacml.tip.peps.proxy') +
      self.th(t, 'consoleXacml.th.actions', 'consoleXacml.tip.peps.actions') +
      '</tr>' + rows +
      '</table>') +
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

  // ---------------------------------------------------------------------------
  // THE REVERSE PROXY (#1760). One section per registered PEP: what it pulls
  // from GET /xacml/pep/proxy, the routes as a table, and the document as the
  // editor. The document is edited WHOLE — a route is added, removed or
  // moved by editing the list, first match wins — because the service
  // validates it whole and refuses any part of it by name; a save sends
  // set-pep-proxy, whose refusal the console draws like every other.
  // ---------------------------------------------------------------------------
  static proxyTemplate(): Json {
    return {
      enabled: true,
      upstream: 'http://app.example:8080',
      publicBaseUrl: '',
      upstreamTimeoutMs: 10000,
      maxBodyBytes: 1048576,
      routes: [
        { id: 'public', path: '/public', match: 'prefix',
          methods: ['GET', 'HEAD'], public: true },
        { id: 'api', path: '/api', match: 'prefix', methods: [],
          mechanisms: ['oauth2'], application: 'my-api',
          resource: '', action: '',
          identity: { mode: 'headers',
                      headers: [{ name: 'X-Remote-User',
                                  claim: 'username' }],
                      separator: ',' },
          forwardCredentials: false }
      ]
    };
  }

  static proxyRoutesTable(t: Json, proxy: Json, resolution: Json[],
                          ctx?: Json, name?: string): string {
    const self = this;
    const statusOf: Json = {};
    (resolution || []).forEach(function (one: Json) {
      statusOf[one.route] = one;
    });
    const rows = (proxy.routes || []).map(function (route: Json) {
      const status = statusOf[route.id];
      const decision = route.public
        ? t.html('consoleXacml.proxy.public')
        : esc(route.resource || t.text('consoleXacml.proxy.thePath')) +
          ' / ' + esc(route.action || t.text('consoleXacml.proxy.theMethod'));
      // HOW THE IDENTITY REACHES THE APPLICATION (D11): the header=claim
      // pairs, or the token or assertion the proxy forwards instead.
      const identity = route.identity || { mode: 'headers', headers: [] };
      const headers = identity.mode === 'headers'
        ? (identity.headers || []).map(function (one: Json) {
            return one.name + '=' + one.claim;
          })
        : [identity.mode === 'saml'
            ? t.text('consoleXacml.proxy.identity.cell.saml')
            : t.text('consoleXacml.proxy.identity.cell.jwt')];
      return '<tr><td>' + (name
          ? '<a href="' + esc(self.routeHref(name, route.id)) + '"><code>' +
            esc(route.id) + '</code></a>'
          : '<code>' + esc(route.id) + '</code>') + '</td><td><code>' +
        esc(route.path) + '</code> (' + esc(route.match) + ')</td><td>' +
        (route.methods.length ? esc(route.methods.join(', '))
                              : t.html('consoleXacml.proxy.any')) +
        '</td><td>' + (route.public ? t.html('consoleXacml.proxy.public')
          : esc(route.mechanisms.join(', ')) +
            (route.multipleAccounts
              ? '<div class="sub">' +
                t.html('consoleXacml.proxy.multipleAccounts') + '</div>'
              : '')) + '</td><td>' +
        (route.public ? '<span class="sub">' +
                        t.html('consoleXacml.proxy.noApplication') + '</span>'
          // THE APPLICATION IT FRONTS (D10), linked; what each mechanism
          // needs is read off that entry by the pull.
          : '<a href="/admin/applications?application=' +
            encodeURIComponent(route.application) + '"><code>' +
            esc(route.application) + '</code></a>' +
            (status && !status.usable
              ? '<div class="sub xacml-alert">' +
                t.html('consoleXacml.proxy.unusable') + ' ' +
                esc(status.why || '') + '</div>'
              : '')) +
        '</td><td>' + decision + '</td><td>' +
        (headers.length ? '<code>' + esc(headers.join(', ')) + '</code>'
                        : t.html('consoleXacml.proxy.noHeaders')) +
        '</td><td>' + (route.forwardCredentials
          ? t.html('consoleXacml.proxy.yes')
          : t.html('consoleXacml.proxy.no')) + '</td>' +
        (ctx && ctx.write && name
          ? '<td><form method="post" action="/admin/xacml/peps" ' +
            'class="inline">' + self.hidden('action', 'remove-pep-route') +
            self.hidden('name', name) + self.hidden('route', route.id) +
            '<button type="submit">' +
            t.html('consoleXacml.routeForm.remove') + '</button></form></td>'
          : '') + '</tr>';
    }).join('');
    return self.wide(t, 'consoleXacml.proxy.tab.routes', '<table><tr>' +
      self.th(t, 'consoleXacml.proxy.th.id', 'consoleXacml.tip.routes.id') +
      self.th(t, 'consoleXacml.proxy.th.path',
              'consoleXacml.tip.routes.path') +
      self.th(t, 'consoleXacml.proxy.th.methods',
              'consoleXacml.tip.routes.methods') +
      self.th(t, 'consoleXacml.proxy.th.mechanisms',
              'consoleXacml.tip.routes.mechanisms') +
      self.th(t, 'consoleXacml.proxy.th.application',
              'consoleXacml.tip.routes.application') +
      self.th(t, 'consoleXacml.proxy.th.decision',
              'consoleXacml.tip.routes.decision') +
      self.th(t, 'consoleXacml.proxy.th.headers',
              'consoleXacml.tip.routes.headers') +
      self.th(t, 'consoleXacml.proxy.th.forward',
              'consoleXacml.tip.routes.forward') +
      (ctx && ctx.write && name
        ? self.th(t, 'consoleXacml.th.actions',
                  'consoleXacml.tip.routes.actions') : '') +
      '</tr>' + rows + '</table>');
  }

  // THE SIGNAL STREAMS' HEALTH (#1760), as the PEP last reported it on a
  // heartbeat. A PEP that never sent it (one older than this service, or
  // one with no proxy) is "not reported" rather than zero, because zero
  // streams and an unknown number of streams want different fixes.
  //
  // ONE ROW PER STREAM (rcbj: "organize information in a table"): the
  // application and routes it serves, its stream id, whether it runs, when
  // it started, last polled and last succeeded, its failures in a row and
  // its counters, and healthy or stale. The summary above the table is the
  // whole proxy's; a PEP that reports the summary and no rows (older than
  // the rows) says so.
  static signalsPanel(t: Json, signals: Json): string {
    const heading = '<h4>' + t.html('consoleXacml.proxy.signals.label') +
      '</h4>';
    if (!signals) {
      return heading + '<p class="sub">' +
        t.html('consoleXacml.proxy.signals.notReported') + '</p>';
    }
    const reported = '<div class="sub">' +
      t.html('consoleXacml.proxy.signals.reported',
             { at: signals.at || t.text('consoleXacml.pep.never') }) +
      '</div>';
    if (!signals.receivers) {
      return heading + '<p>' + t.html('consoleXacml.proxy.signals.none') +
        '</p>' + reported;
    }
    const library = signals.librarySessions || {};
    const when = function (at: unknown): string {
      return at ? '<code>' + esc(String(at)) + '</code>'
        : '<span class="sub">' + t.html('consoleXacml.proxy.signals.never') +
          '</span>';
    };
    const streams: Json[] | null = Array.isArray(signals.streams)
      ? signals.streams : null;
    const table = streams === null
      ? '<p class="sub">' + t.html('consoleXacml.proxy.signals.noRows') +
        '</p>'
      : XacmlPage.wide(t, 'consoleXacml.proxy.signals.label', '<table><tr>' +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.serves',
                     'consoleXacml.tip.signals.serves') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.stream',
                     'consoleXacml.tip.signals.stream') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.running',
                     'consoleXacml.tip.signals.running') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.started',
                     'consoleXacml.tip.signals.started') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.lastPoll',
                     'consoleXacml.tip.signals.lastPoll') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.lastSuccess',
                     'consoleXacml.tip.signals.lastSuccess') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.failures',
                     'consoleXacml.tip.signals.failures') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.polls',
                     'consoleXacml.tip.signals.polls') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.sets',
                     'consoleXacml.tip.signals.sets') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.ended',
                     'consoleXacml.tip.signals.ended') +
        XacmlPage.th(t, 'consoleXacml.proxy.signals.th.health',
                     'consoleXacml.tip.signals.health') + '</tr>' +
        streams.map(function (one: Json) {
          const apps = (one.applications || []).map(function (id: string) {
            return '<a href="/admin/applications?application=' +
              encodeURIComponent(id) + '"><code>' + esc(id) + '</code></a>';
          }).join(', ');
          return '<tr><td>' + (apps || '<span class="sub">' +
              t.html('consoleXacml.proxy.signals.unknownClient') + '</span>') +
            ((one.routes || []).length
              ? '<div class="sub">' + t.html('consoleXacml.proxy.signals.routes',
                  { routes: one.routes.join(', ') }) + '</div>' : '') +
            '</td><td>' + (one.streamId ? '<code>' + esc(one.streamId) +
                           '</code>' : '<span class="sub">—</span>') +
            '</td><td>' + (one.running ? t.html('consoleXacml.proxy.yes')
                                       : t.html('consoleXacml.proxy.no')) +
            '</td><td>' + when(one.startedAt) + '</td><td>' +
            when(one.lastPollAt) + '</td><td>' + when(one.lastSuccessAt) +
            '</td><td>' + esc(String(one.consecutiveFailures)) + '</td><td>' +
            t.html('consoleXacml.proxy.signals.pollCounts', {
              polls: one.polls, failed: one.failedPolls }) + '</td><td>' +
            t.html('consoleXacml.proxy.signals.setCounts', {
              accepted: one.setsAccepted, refused: one.setsRefused }) +
            '</td><td>' + esc(String(one.sessionsEnded)) + '</td><td>' +
            (one.healthy ? t.html('consoleXacml.proxy.signals.healthy')
              : '<strong class="xacml-alert">' +
                t.html('consoleXacml.proxy.signals.stale') + '</strong>') +
            '</td></tr>';
        }).join('') + '</table>');
    return heading +
      '<p' + (signals.stale ? ' class="xacml-alert"' : '') + '>' +
      t.html('consoleXacml.proxy.signals.summary', {
        receivers: signals.receivers, healthy: signals.healthy,
        stale: signals.stale, staleAfterMs: signals.staleAfterMs,
        pollIntervalMs: signals.pollIntervalMs }) +
      (signals.stale
        ? ' ' + t.html('consoleXacml.proxy.signals.staleNote') : '') +
      '</p><div class="sub">' +
      (signals.oldestSuccessAgeMs === null ||
       signals.oldestSuccessAgeMs === undefined
        ? t.html('consoleXacml.proxy.signals.neverPolled',
                 { failures: signals.mostConsecutiveFailures })
        : t.html('consoleXacml.proxy.signals.oldest', {
            age: signals.oldestSuccessAgeMs,
            failures: signals.mostConsecutiveFailures })) +
      '</div><div class="sub">' +
      t.html('consoleXacml.proxy.signals.sets', {
        accepted: signals.setsAccepted, refused: signals.setsRefused,
        ended: signals.sessionsEnded }) + '</div>' + table +
      '<div class="sub">' +
      t.html('consoleXacml.proxy.signals.library', {
        held: library.held, max: library.max, ttlSec: library.ttlSec,
        evicted: library.evicted, expired: library.expired }) +
      '</div>' + reported;
  }

  // ONE PEP's REVERSE PROXY, on its page's Reverse proxy tab (#1760), in
  // three sub-tabs (rcbj, 2026-11-14): Configured Routes (the proxy's state
  // and its routes, each id a link to the route's own page, where a route
  // is edited), Create a New Route (the add form) and Manifest (the whole
  // document as the editor, and Clear). Every proxy-level setting is a
  // member of the document, so the Manifest is where each is changed; the
  // Configured Routes summary reads enabled, upstream and publicBaseUrl.
  static proxySection(ctx: Json, row: Json): string {
    const t = ctx.t;
    const self = this;
    const proxy = row.proxy || null;
    const state = proxy
      ? '<p>' + t.html('consoleXacml.proxy.configured', {
          upstream: proxy.upstream, n: proxy.routes.length }) + ' ' +
        (proxy.enabled ? t.html('consoleXacml.proxy.enabled')
                       : '<strong>' + t.html('consoleXacml.proxy.disabled') +
                         '</strong>') +
        (proxy.publicBaseUrl
          ? ' ' + t.html('consoleXacml.proxy.publicBaseUrl',
                         { url: proxy.publicBaseUrl })
          : '') + '</p>' +
        self.proxyRoutesTable(t, proxy, row.proxyRoutes, ctx, row.name)
      : '<p>' + t.html('consoleXacml.proxy.none') + '</p>';
    const problem = row.proxyProblem
      ? '<div class="sub xacml-alert">' +
        t.html('consoleXacml.proxy.problem') + ' ' +
        esc(row.proxyProblem) + '</div>'
      : '';
    const editor = ctx.write
      ? '<form method="post" action="/admin/xacml/peps">' +
        self.hidden('action', 'set-pep-proxy') +
        self.hidden('name', row.name) +
        '<label' + self.tipOf(t, 'consoleXacml.tip.proxy.document') + '>' +
        t.html('consoleXacml.proxy.editLabel') +
        '<br><textarea name="proxy" rows="18" cols="88">' +
        esc(JSON.stringify(proxy || self.proxyTemplate(), null, 2)) +
        '</textarea></label><div class="sub">' +
        t.html('consoleXacml.proxy.editNote') + '</div>' +
        '<button type="submit">' + t.html('consoleXacml.proxy.save') +
        '</button></form>' +
        (proxy
          ? '<form method="post" action="/admin/xacml/peps" ' +
            'class="inline">' +
            self.hidden('action', 'clear-pep-proxy') +
            self.hidden('name', row.name) +
            '<button type="submit">' + t.html('consoleXacml.proxy.clear') +
            '</button></form>'
          : '')
      : '<span class="sub">' + t.html('consoleXacml.readOnly') + '</span>';
    // EDITING A ROUTE IS ON ITS OWN PAGE, which the route id in the table
    // links to (rcbj, 2026-11-14): its identity, its application (the
    // chooser "Map an application to a route" had, which
    // `set-pep-route-application` still offers on the API) and every other
    // value. A collapsed "Edit route <id>" form per route here repeated that
    // page's form with fewer fields. The add form writes the same stored
    // document as the Manifest, through the same checks.
    const json = ctx.json || {};
    const newRoute = !proxy ? ''
      : (ctx.write
          ? '<p class="sub">' + t.html('consoleXacml.routeForm.lead') +
            '</p>' + self.routeForm(t, json, row.name, proxy.routes.length)
          : '<span class="sub">' + t.html('consoleXacml.readOnly') +
            '</span>');
    return kit.note('<p>' + t.html('consoleXacml.proxy.p1') + '</p>',
                    t.text('consoleXacml.proxy.label')) +
      '<h3>' + t.html('consoleXacml.proxy.heading', { name: row.name }) +
      '</h3>' +
      kit.subTabbedPanels(t.text('consoleXacml.pepPage.tab.proxy'),
        self.proxySubTabs(t).map(function (one: Json) {
          const html: Json = {};
          html[XacmlPage.PROXY_ROUTES_TAB] = state + problem;
          html[XacmlPage.PROXY_NEW_ROUTE_TAB] = newRoute;
          html[XacmlPage.PROXY_MANIFEST_TAB] = '<p class="sub">' +
            t.html('consoleXacml.proxy.documentHeading') + '</p>' + editor;
          return Object.assign({}, one, { html: html[one.id] });
        }));
  }

  // ---------------------------------------------------------------------------
  // THE LISTENER TAB (#1760, rcbj: "Model this tab after the Server
  // configuration->Listeners"). That page's shape: the built-in listeners
  // first, read-only and named by the setting that binds them, then the
  // ones an administrator defines with what each is doing, then the forms.
  // Here the built-in four are the PEP's environment's, and what each is
  // doing is what the PEP last reported on its heartbeat, which is the only
  // place this service can learn it — so a PEP that does not report says
  // so rather than being drawn as listening.
  // ---------------------------------------------------------------------------
  static listenerWords(t: Json): Json {
    return {
      source: {
        environment: t.html('consoleXacml.listeners.source.environment'),
        service: t.html('consoleXacml.listeners.source.service')
      },
      purpose: {
        api: t.html('consoleXacml.listeners.purpose.api'),
        proxy: t.html('consoleXacml.listeners.purpose.proxy')
      },
      state: {
        listening: t.html('consoleXacml.listeners.state.listening'),
        waiting: t.html('consoleXacml.listeners.state.waiting'),
        failed: t.html('consoleXacml.listeners.state.failed'),
        off: t.html('consoleXacml.listeners.state.off')
      },
      reason: {
        none: '',
        'address-in-use': t.html('consoleXacml.listeners.reason.addressInUse'),
        'permission-denied':
          t.html('consoleXacml.listeners.reason.permissionDenied'),
        'address-unavailable':
          t.html('consoleXacml.listeners.reason.addressUnavailable'),
        'no-certificate': t.html('consoleXacml.listeners.reason.noCertificate'),
        'certificate-refused':
          t.html('consoleXacml.listeners.reason.certificateRefused'),
        'certificate-request-refused':
          t.html('consoleXacml.listeners.reason.certificateRequestRefused'),
        'proxy-off': t.html('consoleXacml.listeners.reason.proxyOff'),
        'http-off': t.html('consoleXacml.listeners.reason.httpOff'),
        'not-configured': t.html('consoleXacml.listeners.reason.notConfigured'),
        'crl-only': t.html('consoleXacml.listeners.reason.crlOnly'),
        other: t.html('consoleXacml.listeners.reason.other')
      }
    };
  }

  // The certificate a listener serves, as the PEP reported it, and the one
  // this realm issued a defined HTTPS listener.
  static listenerCertificate(t: Json, one: Json): string {
    const served = one.reported && one.reported.certificate;
    const issued = one.issued;
    if (one.protocol !== 'https') {
      return '<span class="sub">' +
        t.html('consoleXacml.listeners.plainHttp') + '</span>';
    }
    const line = function (label: string, value: string): string {
      return value ? '<div class="sub">' + label + ' <code>' + esc(value) +
        '</code></div>' : '';
    };
    return (served
      ? line(t.html('consoleXacml.listeners.cert.subject'), served.subject) +
        line(t.html('consoleXacml.listeners.cert.names'),
             served.subjectAltName) +
        line(t.html('consoleXacml.listeners.cert.issuer'), served.issuer) +
        line(t.html('consoleXacml.listeners.cert.valid'),
             served.validFrom && served.validTo
               ? served.validFrom + ' – ' + served.validTo : '') +
        line(t.html('consoleXacml.listeners.cert.serial'), served.serialHex) +
        line(t.html('consoleXacml.listeners.cert.fingerprint'),
             served.fingerprint256)
      : '<span class="sub">' +
        t.html('consoleXacml.listeners.cert.notServed') + '</span>') +
      (issued
        ? '<div class="sub">' + t.html('consoleXacml.listeners.cert.issued', {
            serial: issued.serialHex, at: issued.notAfter }) +
          (issued.expired
            ? ' <strong>' + t.html('consoleXacml.pep.expired') + '</strong>'
            : '') + '</div>'
        : '');
  }

  // One listener's form: a new one, or a defined one to edit (its id fixed).
  static listenerForm(t: Json, json: Json, name: string,
                      one: Json | null): string {
    const self = this;
    const catalogue = json.listenersCatalogue || { keyAlgorithms: [],
                                                   defaultKeyAlg: '' };
    const d = one || { id: '', protocol: 'https', purpose: 'proxy',
                       address: '0.0.0.0', port: '', dnsNames: [],
                       ipAddresses: [], keyAlg: catalogue.defaultKeyAlg };
    const labels: Json = {
      http: 'HTTP', https: 'HTTPS',
      api: t.text('consoleXacml.listeners.purpose.api'),
      proxy: t.text('consoleXacml.listeners.purpose.proxy')
    };
    const options = function (values: string[]): Json[] {
      return values.map(function (v) {
        return { value: v, label: labels[v] || v };
      });
    };
    return '<form method="post" action="/admin/xacml/peps">' +
      self.hidden('action', 'set-pep-listener') + self.hidden('name', name) +
      (one ? self.hidden('id', d.id)
        : self.labelled(t, 'consoleXacml.listeners.form.id',
            'consoleXacml.tip.listener.id',
            '<input type="text" name="id" size="20" maxlength="64" ' +
            'placeholder="public-https" required>',
            'consoleXacml.tip.listener.when') + ' ') +
      self.labelled(t, 'consoleXacml.listeners.form.protocol',
        'consoleXacml.tip.listener.protocol',
        self.select('protocol', options(['http', 'https']), d.protocol),
        'consoleXacml.tip.listener.when') + ' ' +
      self.labelled(t, 'consoleXacml.listeners.form.purpose',
        'consoleXacml.tip.listener.purpose',
        self.select('purpose', options(['api', 'proxy']), d.purpose),
        'consoleXacml.tip.listener.when') + ' ' +
      self.labelled(t, 'consoleXacml.listeners.form.address',
        'consoleXacml.tip.listener.address',
        '<input type="text" name="address" size="16" maxlength="64" ' +
        'placeholder="0.0.0.0" value="' + esc(d.address) + '">',
        'consoleXacml.tip.listener.when') + ' ' +
      self.labelled(t, 'consoleXacml.listeners.form.port',
        'consoleXacml.tip.listener.port',
        '<input type="number" name="port" min="1" max="65535" required ' +
        'placeholder="8443" value="' + esc(d.port) + '">',
        'consoleXacml.tip.listener.when') +
      '<div class="sub">' + t.html('consoleXacml.listeners.form.httpsOnly') +
      '</div>' +
      self.labelled(t, 'consoleXacml.listeners.form.dnsNames',
        'consoleXacml.tip.listener.dnsNames',
        '<input type="text" name="dnsNames" size="40" ' +
        'placeholder="pep.example.test, pep.internal" value="' +
        esc((d.dnsNames || []).join(', ')) + '">',
        'consoleXacml.tip.listener.when') + ' ' +
      self.labelled(t, 'consoleXacml.listeners.form.ipAddresses',
        'consoleXacml.tip.listener.ipAddresses',
        '<input type="text" name="ipAddresses" size="24" ' +
        'placeholder="10.0.0.5" value="' +
        esc((d.ipAddresses || []).join(', ')) + '">',
        'consoleXacml.tip.listener.when') + ' ' +
      self.labelled(t, 'consoleXacml.listeners.form.keyAlg',
        'consoleXacml.tip.listener.keyAlg',
        self.select('keyAlg', (catalogue.keyAlgorithms || [])
          .map(function (v: string) {
            return { value: v, label: v };
          }), d.keyAlg || catalogue.defaultKeyAlg),
        'consoleXacml.tip.listener.when') + ' ' +
      '<button type="submit">' + (one
        ? t.html('consoleXacml.listeners.form.update')
        : t.html('consoleXacml.listeners.form.add')) + '</button></form>';
  }

  // WHAT ONE LISTENER IS DOING, AS THE STATE CELL DRAWS IT (2026-11-14).
  // A STATE THE PEP DID NOT REPORT IS NEVER DRAWN AS LISTENING: no report,
  // or a report whose state is missing or not one of the four, reads "not
  // reported" (8081 drew both plain-HTTP listeners as listening while they
  // were off and nothing had been reported). An environment plain-HTTP
  // listener with no report reads as its DEFAULT, off unless its switch is
  // true, labelled as the default rather than as a fact; reported `off`
  // (`http-off`) it reads "off (PEP_HTTP=false)". `crl-only` is the API's
  // plain port serving its credential's CRLs alone (PEP_CRL_HTTP).
  static listenerState(t: Json, words: Json, one: Json): string {
    const said = one.reported;
    const known = !!said && typeof said.state === 'string' &&
      Object.prototype.hasOwnProperty.call(words.state, said.state);
    const switched = one.source === 'environment' && one.protocol === 'http'
      ? (one.enable || 'PEP_HTTP') : '';
    const renew = known && one.definition && one.protocol === 'https' &&
      said.renew !== one.definition.renew
      ? '<div class="sub">' + t.html('consoleXacml.listeners.renewPending') +
        '</div>' : '';
    if (!known) {
      return (switched
        ? words.state.off + ' <span class="sub">' +
          t.html('consoleXacml.listeners.offByDefault',
                 { enable: switched }) + '</span>'
        : '') +
        '<div class="sub">' + t.html('consoleXacml.listeners.notReported') +
        '</div>';
    }
    const httpOff = said.reason === 'http-off';
    if (httpOff || (switched && said.state === 'off')) {
      return words.state.off + ' <span class="sub">' +
        t.html('consoleXacml.listeners.offSwitched', { enable: switched ||
                                                       'PEP_HTTP' }) +
        '</span><div class="sub">' +
        t.html('consoleXacml.listeners.httpOffHow', {
          enable: switched || 'PEP_HTTP',
          port: said.port || one.defaultPort }) + '</div>';
    }
    if (said.state === 'listening') {
      return words.state.listening +
        (said.reason === 'crl-only'
          ? '<div class="sub">' + words.reason['crl-only'] + '</div>' : '') +
        renew;
    }
    return '<strong class="xacml-alert">' + words.state[said.state] +
      '</strong>' +
      (said.reason && said.reason !== 'none'
        ? '<div class="sub">' + (words.reason[said.reason] ||
                                 esc(said.reason)) + '</div>'
        : '') + renew;
  }

  /**
   * Draws a remote PEP's Listener tab (#1760): every listener it has —
   * the environment's four, read-only, and the ones defined here — with its
   * protocol, address, purpose, state, certificate and source, the issue
   * control of the environment's pair, and the forms that define, edit,
   * remove and renew the others.
   *
   * @param ctx - the render context
   * @param json - `pepsJson(name)`'s answer
   * @param row - the PEP's row
   * @returns the tab's HTML
   */
  static listenersBody(ctx: Json, json: Json, row: Json): string {
    const t = ctx.t;
    const self = this;
    const words = self.listenerWords(t);
    const rows: Json[] = row.listenerRows || [];
    const reported = !!row.listenersInUse;
    const body = rows.map(function (one: Json) {
      const said = one.reported;
      const where = said && said.port
        ? (said.address || '0.0.0.0') + ':' + said.port
        : (one.definition
            ? one.definition.address + ':' + one.definition.port
            : '');
      const state = self.listenerState(t, words, one);
      const actions = one.source === 'environment'
        ? '<span class="sub">' + t.html('consoleXacml.listeners.envOnly',
            { env: one.env }) + '</span>'
        : (ctx.write
            ? '<form method="post" action="/admin/xacml/peps" ' +
              'class="inline">' + self.hidden('action', 'remove-pep-listener') +
              self.hidden('name', row.name) +
              self.hidden('listener', one.id) + '<button type="submit">' +
              t.html('consoleXacml.listeners.remove') + '</button></form>' +
              (one.protocol === 'https'
                ? ' <form method="post" action="/admin/xacml/peps" ' +
                  'class="inline">' +
                  self.hidden('action', 'renew-pep-listener-certificate') +
                  self.hidden('name', row.name) +
                  self.hidden('listener', one.id) + '<button type="submit">' +
                  t.html('consoleXacml.listeners.renew') + '</button></form>'
                : '')
            : '<span class="sub">' + t.html('consoleXacml.readOnly') +
              '</span>');
      return '<tr id="pep-listener-' + esc(one.id) + '"><th><code>' +
        esc(one.id) + '</code></th><td>' + words.source[one.source] +
        (one.source === 'environment'
          ? '<div class="sub">' + t.html('consoleXacml.listeners.defaultPort',
              { env: one.env, port: one.defaultPort }) + '</div>' +
            (one.enable
              ? '<div class="sub">' +
                t.html('consoleXacml.listeners.enableHint',
                       { enable: one.enable }) + '</div>' : '')
          : '') +
        '</td><td>' + (one.protocol === 'https' ? 'HTTPS' : 'HTTP') +
        '</td><td>' + (where ? '<code>' + esc(where) + '</code>'
                             : '<span class="sub">' +
                               t.html('consoleXacml.listeners.notReported') +
                               '</span>') +
        '</td><td>' + words.purpose[one.purpose] + '</td><td>' + state +
        '</td><td>' + self.listenerCertificate(t, one) + '</td><td>' +
        actions + '</td></tr>';
    }).join('');
    const table = self.wide(t, 'consoleXacml.pepPage.tab.listener',
      '<table><tr>' +
      self.th(t, 'consoleXacml.listeners.th.listener',
              'consoleXacml.tip.listeners.listener') +
      self.th(t, 'consoleXacml.listeners.th.source',
              'consoleXacml.tip.listeners.source') +
      self.th(t, 'consoleXacml.listeners.th.protocol',
              'consoleXacml.tip.listener.protocol') +
      self.th(t, 'consoleXacml.listeners.th.address',
              'consoleXacml.tip.listeners.address') +
      self.th(t, 'consoleXacml.listeners.th.purpose',
              'consoleXacml.tip.listener.purpose') +
      self.th(t, 'consoleXacml.listeners.th.state',
              'consoleXacml.tip.listeners.state') +
      self.th(t, 'consoleXacml.listeners.th.certificate',
              'consoleXacml.tip.listeners.certificate') +
      self.th(t, 'consoleXacml.th.actions',
              'consoleXacml.tip.listeners.actions') +
      '</tr>' + body + '</table>');
    const defined = (row.listeners || []) as Json[];
    const catalogue = json.listenersCatalogue || {};
    const forms = ctx.write
      ? '<h3>' + t.html('consoleXacml.listeners.addHeading') + '</h3>' +
        (catalogue.plainHttpProxyAllowed === false
          ? '<p class="sub">' +
            t.html('consoleXacml.listeners.plainProxyRefused') + '</p>' : '') +
        self.listenerForm(t, json, row.name, null) +
        defined.map(function (one: Json) {
          return '<details><summary>' +
            t.html('consoleXacml.listeners.editHeading', { id: one.id }) +
            '</summary>' + self.listenerForm(t, json, row.name, one) +
            '</details>';
        }).join('')
      : '';
    return kit.note('<p>' + t.html('consoleXacml.listeners.lead') +
                    '</p><p>' + t.html('consoleXacml.listeners.lead2') +
                    '</p>', t.text('consoleXacml.pepPage.tab.listener')) +
      (reported ? ''
        : '<p class="sub">' + t.html('consoleXacml.listeners.olderPep') +
          '</p>') +
      (row.listenersProblem
        ? '<div class="sub xacml-alert">' +
          t.html('consoleXacml.listeners.problem') + ' ' +
          esc(row.listenersProblem) + '</div>' : '') +
      table + forms +
      '<h3>' + t.html('consoleXacml.listeners.envPairHeading') + '</h3>' +
      '<p>' + t.html('consoleXacml.listeners.envPairLead') + '</p>' +
      self.pepListener(ctx, json, row, true) +
      kit.note('<p>' + t.html('consoleXacml.peps.cert1') + '</p><p>' +
               t.html('consoleXacml.peps.cert2') + '</p>',
               t.text('consoleXacml.peps.certLabel'));
  }

  // ---------------------------------------------------------------------------
  // THE ROUTE FORMS (#1760, rcbj: "ability to add paths / routes / Methods /
  // etc" and "Map an application object to a path"). Each posts one route
  // action, which the service turns into the WHOLE document and validates
  // with the document editor's own checks — one validator, never two.
  // ---------------------------------------------------------------------------
  // THE ADD FORM. Editing a route is its own page's form (`routeDetail`).
  static routeForm(t: Json, json: Json, name: string,
                   count: number): string {
    const self = this;
    const r = { id: '', path: '/', match: 'prefix', methods: [],
                public: false, mechanisms: ['session'], application: '',
                resource: '', action: '', forwardCredentials: false,
                signals: true };
    const when = 'consoleXacml.tip.route.when';
    return '<form method="post" action="/admin/xacml/peps">' +
      self.hidden('action', 'set-pep-route') + self.hidden('name', name) +
      self.formRow(self.labelled(t, 'consoleXacml.routeForm.id',
        'consoleXacml.tip.route.id', '<input type="text" name="id" ' +
        'size="16" maxlength="64" placeholder="orders-api" required>',
        when)) +
      self.routeFields(t, json, r, count, 'new', true) +
      self.formRow('<button type="submit">' +
        t.html('consoleXacml.routeForm.add') + '</button>') + '</form>';
  }

  // THE ROUTE'S FIELDS, shared by the Create a New Route form and the
  // route's own page (#1760): every member of a route but its id and its
  // identity, each with its tooltip. `isNew` puts the add form's position
  // (last) in the box's placeholder. ONE FIELD PER LINE (rcbj, 2026-11-14:
  // "busy and hard to follow"): each a `.formrow` of its own, the label
  // then the control, the tooltip on the label, grouped under the fieldset
  // legends Matching, Authentication, Authorization and Order.
  static routeFields(t: Json, json: Json, r: Json, count: number,
                     listKey: string, isNew: boolean,
                     position?: number): string {
    const self = this;
    const when = 'consoleXacml.tip.route.when';
    const box = function (field: string, value: string,
                          on: boolean): string {
      return '<label' + self.tipOf(t, field === 'methods'
          ? 'consoleXacml.tip.route.methods'
          : 'consoleXacml.tip.route.mechanisms') +
        '><input type="checkbox" name="' + field + '" value="' +
        esc(value) + '"' + (on ? ' checked' : '') + '> ' + esc(value) +
        '</label> ';
    };
    const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE',
                     'OPTIONS'].map(function (m) {
      return box('methods', m, (r.methods || []).indexOf(m) >= 0);
    }).join('');
    const mechanisms = ['session', 'oauth2', 'saml2', 'basic']
      .map(function (m) {
        return box('mechanisms', m, (r.mechanisms || []).indexOf(m) >= 0);
      }).join('');
    const listId = 'pep-route-apps-' + listKey;
    const row = function (html: string): string {
      return XacmlPage.formRow(html);
    };
    const group = function (legendKey: string, rows: string): string {
      return XacmlPage.fieldGroup(t, legendKey, rows);
    };
    return group('consoleXacml.routeForm.legend.matching',
        row(self.labelled(t, 'consoleXacml.routeForm.path',
          'consoleXacml.tip.route.path', '<input type="text" name="path" ' +
          'size="28" required placeholder="/api" value="' + esc(r.path) +
          '">', when)) +
        row(self.labelled(t, 'consoleXacml.routeForm.match',
          'consoleXacml.tip.route.match', self.select('match', [
            { value: 'prefix',
              label: t.text('consoleXacml.routeForm.prefix') },
            { value: 'exact',
              label: t.text('consoleXacml.routeForm.exact') }],
            r.match), when)) +
        row(self.checkGroup(t, listId + '-methods',
          'consoleXacml.routeForm.methods', 'consoleXacml.tip.route.methods',
          methods) + '<span class="sub">' +
          t.html('consoleXacml.routeForm.methodsNote') + '</span>')) +
      group('consoleXacml.routeForm.legend.authentication',
        row(self.labelled(t, 'consoleXacml.routeForm.public',
          'consoleXacml.tip.route.public',
          self.yesNo('public', r.public, t), when)) +
        row(self.checkGroup(t, listId + '-mechanisms',
          'consoleXacml.routeForm.mechanisms',
          'consoleXacml.tip.route.mechanisms', mechanisms)) +
        row(self.labelled(t, 'consoleXacml.routeForm.forward',
          'consoleXacml.tip.route.forward',
          self.yesNo('forwardCredentials', r.forwardCredentials, t), when)) +
        row(self.labelled(t, 'consoleXacml.routeForm.signals',
          'consoleXacml.tip.route.signals',
          self.yesNo('signals', r.signals !== false, t), when)) +
        row(self.labelled(t, 'consoleXacml.routeForm.multipleAccounts',
          'consoleXacml.tip.route.multipleAccounts',
          self.yesNo('multipleAccounts', r.multipleAccounts === true, t),
          when))) +
      group('consoleXacml.routeForm.legend.authorization',
        row(self.labelled(t, 'consoleXacml.routeForm.application',
          'consoleXacml.tip.route.application', '<input type="text" ' +
          'name="application" size="24" placeholder="orders-app" list="' +
          listId + '" value="' + esc(r.application) + '">', when) +
          self.applicationList(json, listId)) +
        row(self.labelled(t, 'consoleXacml.routeForm.resource',
          'consoleXacml.tip.route.resource', '<input type="text" ' +
          'name="resource" size="20" ' +
          'placeholder="https://orders.example.test" value="' +
          esc(r.resource) + '">', when)) +
        row(self.labelled(t, 'consoleXacml.routeForm.action',
          'consoleXacml.tip.route.action', '<input type="text" ' +
          'name="routeAction" size="12" placeholder="read" value="' +
          esc(r.action) + '">', when))) +
      group('consoleXacml.routeForm.legend.order',
        row(self.labelled(t, 'consoleXacml.routeForm.position',
          'consoleXacml.tip.route.position', '<input type="number" ' +
          'name="position" min="0" max="' + count + '" placeholder="' +
          (isNew ? String(count) : '') + '"' +
          (position === undefined ? ''
            : ' value="' + esc(String(position)) + '"') + '>', when)));
  }

  // ONE FIELD'S LINE: the console's `.formrow`, a label then its control.
  static formRow(html: string): string {
    return '<div class="formrow">' + html + '</div>';
  }

  // A ROW'S CHECKBOXES UNDER ONE LABEL (Methods, Mechanisms): the label is
  // the row's, drawn as `.formlabel` (with `.tipword`, the dotted
  // underline of a label with a tooltip) so it reads like every `<label>`
  // of a `.formrow` beside it — a bare `<span>` came out larger and not bold —
  // and the boxes are a `role="group"` named by it, the console's way of
  // naming a set of boxes (`web_kit.ts`'s `fg-checks`), since a `<label>`
  // can label one control and a nested `<fieldset>` would draw a second
  // frame inside the group's own.
  static checkGroup(t: Json, id: string, labelKey: string, tipKey: string,
                    boxes: string): string {
    return '<span class="formlabel tipword" id="' + esc(id) + '-label"' +
      XacmlPage.tipOf(t, tipKey) + '>' + t.html(labelKey) + '</span>' +
      '<span role="group" aria-labelledby="' +
      esc(id) + '-label">' + boxes + '</span>';
  }

  // A TABLE THAT MAY BE WIDER THAN ITS CARD at phone width, in the console's
  // own sideways scroller (`kit.wideTable()`, `.wide`): the Configured
  // Routes table was clipped at 390px. `labelKey` names the region.
  static wide(t: Json, labelKey: string, html: string): string {
    return kit.wideTable(t.text(labelKey), html);
  }

  // A LINK INSIDE A TRANSLATED SENTENCE, through a slot (`web_spiffe.ts`'s
  // `compose()` argues it): a message's parameters are escaped and a
  // message may not carry a link, so the message gets a marker and the
  // link replaces it. The sentence stays whole for a translator.
  static linkedSentence(t: Json, key: string, param: string, href: string,
                        labelKey: string): string {
    const slot = '\u0001' + param + '\u0001';
    const vars: Json = {};
    vars[param] = slot;
    return String(t.html(key, vars)).split(slot).join('<a href="' +
      esc(href) + '">' + t.html(labelKey) + '</a>');
  }

  // A GROUP OF A FORM'S FIELDS under a legend, one field per line.
  static fieldGroup(t: Json, legendKey: string, rows: string): string {
    return '<fieldset><legend>' + t.html(legendKey) + '</legend>' + rows +
      '</fieldset>';
  }

  // The realm's applications as a datalist: the chooser SUGGESTS, and the
  // save resolves what was typed (D10), refusing one that does not qualify.
  static applicationList(json: Json, id: string): string {
    return '<datalist id="' + esc(id) + '">' +
      (json.applicationChoices || []).map(function (one: Json) {
        return '<option value="' + esc(one.identifier) + '">' +
          esc(one.name && one.name !== one.identifier
            ? one.name + ' — ' + one.identifier : one.identifier) +
          '</option>';
      }).join('') + '</datalist>';
  }

  // Each managed setting's label, by its own key so the catalogs' check
  // finds them (#1760).
  static settingLabel(t: Json, key: string): string {
    const labels: Json = {
      description: t.html('consoleXacml.pepSettings.key.description'),
      resource: t.html('consoleXacml.pepSettings.key.resource'),
      notifyUrl: t.html('consoleXacml.pepSettings.key.notifyUrl'),
      bias: t.html('consoleXacml.pepSettings.key.bias'),
      pip: t.html('consoleXacml.pepSettings.key.pip'),
      pollIntervalMs: t.html('consoleXacml.pepSettings.key.pollIntervalMs'),
      heartbeatIntervalMs:
        t.html('consoleXacml.pepSettings.key.heartbeatIntervalMs'),
      backoffMaxMs: t.html('consoleXacml.pepSettings.key.backoffMaxMs'),
      timeoutMs: t.html('consoleXacml.pepSettings.key.timeoutMs'),
      maxBodyBytes: t.html('consoleXacml.pepSettings.key.maxBodyBytes'),
      httpsReloadIntervalMs:
        t.html('consoleXacml.pepSettings.key.httpsReloadIntervalMs'),
      logLevel: t.html('consoleXacml.pepSettings.key.logLevel'),
      authzen: t.html('consoleXacml.pepSettings.key.authzen'),
      authzenPdpIdentifier:
        t.html('consoleXacml.pepSettings.key.authzenPdpIdentifier'),
      authzenForwardTimeoutMs:
        t.html('consoleXacml.pepSettings.key.authzenForwardTimeoutMs'),
      proxySessionRecheckMs:
        t.html('consoleXacml.pepSettings.key.proxySessionRecheckMs'),
      proxySessionTtlMs:
        t.html('consoleXacml.pepSettings.key.proxySessionTtlMs'),
      proxyMaxSessions: t.html('consoleXacml.pepSettings.key.proxyMaxSessions'),
      proxyMaxAccounts: t.html('consoleXacml.pepSettings.key.proxyMaxAccounts'),
      proxyJwksTtlMs: t.html('consoleXacml.pepSettings.key.proxyJwksTtlMs'),
      proxyUpstreamInsecure:
        t.html('consoleXacml.pepSettings.key.proxyUpstreamInsecure'),
      proxyRpAllowInsecure:
        t.html('consoleXacml.pepSettings.key.proxyRpAllowInsecure'),
      proxySignalsPollMs:
        t.html('consoleXacml.pepSettings.key.proxySignalsPollMs'),
      proxySignalsStaleMs:
        t.html('consoleXacml.pepSettings.key.proxySignalsStaleMs'),
      proxyStripCookies:
        t.html('consoleXacml.pepSettings.key.proxyStripCookies')
    };
    return Object.prototype.hasOwnProperty.call(labels, key)
      ? labels[key] : esc(key);
  }

  // ONE SETTING'S TOOLTIP (#1760): what it does (by its own key, so the
  // catalogs' check finds each), then the facts every row has — the
  // values it takes, its default, when a change takes effect, and the
  // precedence — from the catalogue the service answers, so they cannot
  // drift from what the save checks.
  static settingTip(t: Json, row: Json, words: Json): string {
    const what: Json = {
      description: t.text('consoleXacml.tip.setting.description'),
      resource: t.text('consoleXacml.tip.setting.resource'),
      notifyUrl: t.text('consoleXacml.tip.setting.notifyUrl'),
      bias: t.text('consoleXacml.tip.setting.bias'),
      pip: t.text('consoleXacml.tip.setting.pip'),
      pollIntervalMs: t.text('consoleXacml.tip.setting.pollIntervalMs'),
      heartbeatIntervalMs:
        t.text('consoleXacml.tip.setting.heartbeatIntervalMs'),
      backoffMaxMs: t.text('consoleXacml.tip.setting.backoffMaxMs'),
      timeoutMs: t.text('consoleXacml.tip.setting.timeoutMs'),
      maxBodyBytes: t.text('consoleXacml.tip.setting.maxBodyBytes'),
      httpsReloadIntervalMs:
        t.text('consoleXacml.tip.setting.httpsReloadIntervalMs'),
      logLevel: t.text('consoleXacml.tip.setting.logLevel'),
      authzen: t.text('consoleXacml.tip.setting.authzen'),
      authzenPdpIdentifier:
        t.text('consoleXacml.tip.setting.authzenPdpIdentifier'),
      authzenForwardTimeoutMs:
        t.text('consoleXacml.tip.setting.authzenForwardTimeoutMs'),
      proxySessionRecheckMs:
        t.text('consoleXacml.tip.setting.proxySessionRecheckMs'),
      proxySessionTtlMs: t.text('consoleXacml.tip.setting.proxySessionTtlMs'),
      proxyMaxSessions: t.text('consoleXacml.tip.setting.proxyMaxSessions'),
      proxyMaxAccounts: t.text('consoleXacml.tip.setting.proxyMaxAccounts'),
      proxyJwksTtlMs: t.text('consoleXacml.tip.setting.proxyJwksTtlMs'),
      proxyUpstreamInsecure:
        t.text('consoleXacml.tip.setting.proxyUpstreamInsecure'),
      proxyRpAllowInsecure:
        t.text('consoleXacml.tip.setting.proxyRpAllowInsecure'),
      proxySignalsPollMs:
        t.text('consoleXacml.tip.setting.proxySignalsPollMs'),
      proxySignalsStaleMs:
        t.text('consoleXacml.tip.setting.proxySignalsStaleMs'),
      proxyStripCookies:
        t.text('consoleXacml.tip.setting.proxyStripCookies')
    };
    const values = row.type === 'integer'
      ? t.text('consoleXacml.pepSettings.range',
               { min: row.min, max: row.max })
      : (row.type === 'boolean' ? 'true, false'
          : (row.type === 'enum' ? (row.values || []).join(', ')
              : (row.type === 'text'
                  ? t.text('consoleXacml.tip.setting.textValues',
                           { max: row.maxLength })
                  : t.text('consoleXacml.tip.setting.urlValues'))));
    const fallback = row.default === '' || row.default === null ||
      row.default === undefined
      ? t.text('consoleXacml.tip.setting.noDefault') : String(row.default);
    const applies = kit.plainTextOf(words.applies[row.applies] ||
                                    String(row.applies));
    return (Object.prototype.hasOwnProperty.call(what, row.key)
      ? what[row.key] + ' ' : '') +
      t.text('consoleXacml.tip.setting.facts', {
        values: values, default: fallback, applies: applies, env: row.env }) +
      (row.refusedInProduct
        ? ' ' + t.text('consoleXacml.pepSettings.refusedInProduct') : '');
  }

  static settingWords(t: Json): Json {
    return {
      group: {
        registration: t.html('consoleXacml.pepSettings.group.registration'),
        enforcement: t.html('consoleXacml.pepSettings.group.enforcement'),
        sync: t.html('consoleXacml.pepSettings.group.sync'),
        listener: t.html('consoleXacml.pepSettings.group.listener'),
        logging: t.html('consoleXacml.pepSettings.group.logging'),
        authzen: t.html('consoleXacml.pepSettings.group.authzen'),
        proxy: t.html('consoleXacml.pepSettings.group.proxy')
      },
      source: {
        service: t.html('consoleXacml.pepSettings.source.service'),
        environment: t.html('consoleXacml.pepSettings.source.environment'),
        derived: t.html('consoleXacml.pepSettings.source.derived'),
        default: t.html('consoleXacml.pepSettings.source.default')
      },
      applies: {
        now: t.html('consoleXacml.pepSettings.applies.now'),
        nextRound: t.html('consoleXacml.pepSettings.applies.nextRound'),
        nextReload: t.html('consoleXacml.pepSettings.applies.nextReload'),
        nextReconcile: t.html('consoleXacml.pepSettings.applies.nextReconcile')
      },
      reason: {
        connect: t.html('consoleXacml.pepSettings.reason.connect'),
        bind: t.html('consoleXacml.pepSettings.reason.bind'),
        file: t.html('consoleXacml.pepSettings.reason.file'),
        listeners: t.html('consoleXacml.pepSettings.reason.listeners'),
        narrowing: t.html('consoleXacml.pepSettings.reason.narrowing')
      }
    };
  }

  // One setting's box: what is set here, or empty for "not set".
  static settingInput(t: Json, row: Json, value: Json,
                      writable: boolean): string {
    const set = value !== undefined && value !== null;
    const off = writable ? '' : ' disabled';
    if (row.type === 'boolean' || row.type === 'enum') {
      const options = row.type === 'boolean' ? ['true', 'false']
        : (row.values || []);
      return '<select name="' + esc(row.key) + '"' + off + '>' +
        '<option value="">' + t.html('consoleXacml.pepSettings.notSet') +
        '</option>' + options.map(function (one: string) {
          return '<option value="' + esc(one) + '"' +
            (set && String(value) === one ? ' selected' : '') + '>' +
            esc(one) + '</option>';
        }).join('') + '</select>' +
        (row.refusedInProduct
          ? '<div class="sub">' +
            t.html('consoleXacml.pepSettings.refusedInProduct') + '</div>'
          : '');
    }
    if (row.type === 'integer') {
      return '<input type="number" name="' + esc(row.key) + '" min="' +
        esc(row.min) + '" max="' + esc(row.max) + '" step="1" value="' +
        (set ? esc(value) : '') + '"' + off + '>' +
        '<div class="sub">' + t.html('consoleXacml.pepSettings.range',
          { min: row.min, max: row.max }) + '</div>';
    }
    return '<input type="text" name="' + esc(row.key) + '" size="32"' +
      (row.maxLength ? ' maxlength="' + esc(row.maxLength) + '"' : '') +
      ' value="' + (set ? esc(value) : '') + '"' + off + '>';
  }

  /**
   * Draws a remote PEP's Settings tab (#1760): every managed setting with
   * what is set here, what the PEP reports in force and from where, and
   * the environment that stays the PEP's own.
   *
   * @param ctx - the render context
   * @param json - `pepsJson(name)`'s answer
   * @param row - the PEP's row
   * @returns the tab's HTML
   */
  static settingsBody(ctx: Json, json: Json, row: Json): string {
    const t = ctx.t;
    const self = this;
    const words = self.settingWords(t);
    const catalogue = json.settingsCatalogue || { settings: [],
                                                  bootstrap: [] };
    const set = row.settings || {};
    const inUse = row.settingsInUse;
    let lastGroup = '';
    const body = catalogue.settings.map(function (one: Json) {
      const heading = one.group !== lastGroup
        ? '<tr><th colspan="5">' + (words.group[one.group] || esc(one.group)) +
          '</th></tr>' : '';
      lastGroup = one.group;
      const reported = inUse && inUse.values ? inUse.values[one.key] : null;
      const tip = kit.tip(self.settingTip(t, one, words), Infinity);
      return heading + '<tr><td><label' + tip + '>' +
        self.settingLabel(t, one.key) + '</label>' +
        '<div class="sub"><code>' + esc(one.env) + '</code></div></td><td' +
        tip + '>' +
        self.settingInput(t, one, set[one.key], !!ctx.write) + '</td><td>' +
        (reported
          ? '<code>' + esc(String(reported.value)) + '</code>' +
            '<div class="sub">' + (words.source[reported.source] ||
                                   esc(reported.source)) + '</div>' +
            (reported.rejected === true
              ? '<div class="sub xacml-alert">' +
                t.html('consoleXacml.pepSettings.rejected') + '</div>'
              : '')
          : '<span class="sub">' +
            t.html('consoleXacml.pepSettings.notReported') + '</span>') +
        '</td><td><code>' + esc(String(one.default)) + '</code></td><td>' +
        (words.applies[one.applies] || esc(one.applies)) + '</td></tr>';
    }).join('');
    const status = !inUse
      ? '<p class="sub">' +
        t.html('consoleXacml.pepSettings.inUseNotReported') + '</p>'
      : (row.settingsCurrent
          ? '<p>' + t.html('consoleXacml.pepSettings.current') + '</p>'
          : '<p class="xacml-alert">' +
            t.html('consoleXacml.pepSettings.notCurrent') + '</p>');
    const problem = row.settingsProblem
      ? '<div class="sub xacml-alert">' +
        t.html('consoleXacml.pepSettings.problem') + ' ' +
        esc(row.settingsProblem) + '</div>'
      : '';
    const table = self.wide(t, 'consoleXacml.pepPage.tab.settings',
      '<table><tr>' +
      self.th(t, 'consoleXacml.pepSettings.th.setting',
              'consoleXacml.tip.settings.setting') +
      self.th(t, 'consoleXacml.pepSettings.th.setHere',
              'consoleXacml.tip.settings.setHere') +
      self.th(t, 'consoleXacml.pepSettings.th.inUse',
              'consoleXacml.tip.settings.inUse') +
      self.th(t, 'consoleXacml.pepSettings.th.default',
              'consoleXacml.tip.settings.default') +
      self.th(t, 'consoleXacml.pepSettings.th.applies',
              'consoleXacml.tip.settings.applies') + '</tr>' + body +
      '</table>');
    const form = ctx.write
      ? '<form method="post" action="/admin/xacml/peps">' +
        self.hidden('action', 'set-pep-settings') +
        self.hidden('name', row.name) + table +
        '<button type="submit">' + t.html('consoleXacml.pepSettings.save') +
        '</button></form>' +
        (row.settings
          ? '<form method="post" action="/admin/xacml/peps" class="inline">' +
            self.hidden('action', 'clear-pep-settings') +
            self.hidden('name', row.name) +
            '<button type="submit">' +
            t.html('consoleXacml.pepSettings.clear') + '</button></form>'
          : '')
      : table + '<span class="sub">' + t.html('consoleXacml.readOnly') +
        '</span>';
    const bootstrap = '<h3>' +
      t.html('consoleXacml.pepSettings.bootstrap.heading') + '</h3><p>' +
      t.html('consoleXacml.pepSettings.bootstrap.lead') + '</p>' +
      self.wide(t, 'consoleXacml.pepSettings.bootstrap.heading', '<table><tr>' +
      self.th(t, 'consoleXacml.pepSettings.th.variable',
              'consoleXacml.tip.settings.variable') +
      self.th(t, 'consoleXacml.pepSettings.th.default',
              'consoleXacml.tip.settings.envDefault') +
      self.th(t, 'consoleXacml.pepSettings.th.why',
              'consoleXacml.tip.settings.why') + '</tr>' +
      catalogue.bootstrap.map(function (one: Json) {
        return '<tr><td><code>' + esc(one.env) + '</code></td><td><code>' +
          esc(one.default) + '</code></td><td>' +
          (words.reason[one.reason] || esc(one.reason)) + '</td></tr>';
      }).join('') + '</table>');
    return kit.note('<p>' + t.html('consoleXacml.pepSettings.lead') +
                    '</p><p>' + t.html('consoleXacml.pepSettings.lead2') +
                    '</p>', t.text('consoleXacml.pepPage.tab.settings')) +
      status + problem + form + bootstrap;
  }

  /**
   * Draws one route's page (#1760, rcbj 2026-11-14: "click on a route name
   * and go to another page and be able to update all the configuration
   * values"), `/admin/xacml/pep/route?pep=<name>&route=<id>`: the route's
   * effective state, then ONE form holding every member of the route —
   * its id (a rename), path and match, methods, public, mechanisms,
   * application, XACML resource and action, credential forwarding,
   * signals, its identity and its position — saved by `set-pep-route`
   * through the document editor's one validator, and Remove behind a
   * confirmation. The upstream is the PEP's, one per proxy: the page says
   * so and links the document that sets it.
   *
   * @param ctx - the render context
   * @param json - `GET /admin-api/xacml/peps?pep=<name>&route=<id>`'s
   *   answer
   * @returns the body as HTML
   */
  static routeDetail(ctx: Json, json: Json): string {
    const t = ctx.t;
    const self = this;
    const name = String(json.pep || '');
    const id = String(json.route || '');
    const back = '<p><a href="' + esc(self.proxyTabHref(name)) + '">' +
      t.html('consoleXacml.routePage.back', { pep: name }) + '</a></p>';
    const row = (json.peps || [])[0];
    const detail = json.routeDetail;
    if (!json.found || !row) {
      return '<p class="warn">' + t.html('consoleXacml.pepPage.notFound',
        { name: name }) + '</p>' + back;
    }
    if (!detail || !detail.found) {
      return '<p class="warn">' + t.html('consoleXacml.routePage.notFound',
        { route: id, pep: name }) + '</p>' + back;
    }
    const r = detail.route;
    const proxy = row.proxy || {};
    const usable = r.public
      ? '<span>' + t.html('consoleXacml.routePage.publicUsable') + '</span>'
      : (detail.usable === true
          ? '<span>' + t.html('consoleXacml.routePage.usable') + '</span>'
          : '<strong class="xacml-alert">' +
            t.html('consoleXacml.routePage.unusable') + '</strong>' +
            (detail.why ? '<div class="sub">' + esc(detail.why) + '</div>'
                        : ''));
    const application = detail.application
      ? '<a href="/admin/applications?application=' +
        encodeURIComponent(detail.application.identifier) + '"><code>' +
        esc(detail.application.identifier) + '</code></a>' +
        (detail.application.name &&
         detail.application.name !== detail.application.identifier
          ? ' ' + esc(detail.application.name) : '') +
        (detail.application.found ? ''
          : '<div class="sub xacml-alert">' +
            t.html('consoleXacml.routePage.noSuchApplication') + '</div>')
      : '<span class="sub">' +
        t.html('consoleXacml.proxy.noApplication') + '</span>';
    const words = self.listenerWords(t);
    const served = (detail.servedBy || []).map(function (one: Json) {
      const state = one.state === null || one.state === undefined
        ? '<span class="sub">' + t.html('consoleXacml.listeners.notReported') +
          '</span>'
        : (one.state === 'listening' ? words.state.listening
            : (words.state[one.state] || esc(one.state)) +
              (one.reason && one.reason !== 'none'
                ? ' <span class="sub">' + (words.reason[one.reason] ||
                                           esc(one.reason)) + '</span>'
                : ''));
      return '<tr><td><code>' + esc(one.id) + '</code></td><td>' +
        (one.protocol === 'https' ? 'HTTPS' : 'HTTP') + '</td><td><code>' +
        esc(String(one.port)) + '</code></td><td>' + state + '</td></tr>';
    }).join('');
    const line = function (labelKey: string, tipKey: string,
                           value: string): string {
      return '<tr><th' + self.tipOf(t, tipKey) + '>' + t.html(labelKey) +
        '</th><td>' + value + '</td></tr>';
    };
    const state = '<h3>' + t.html('consoleXacml.routePage.stateHeading') +
      '</h3>' + self.wide(t, 'consoleXacml.routePage.stateHeading', '<table>' +
      line('consoleXacml.routePage.th.usable',
           'consoleXacml.tip.routePage.usable', usable) +
      line('consoleXacml.proxy.th.application',
           'consoleXacml.tip.route.application', application) +
      line('consoleXacml.routePage.th.position',
           'consoleXacml.tip.route.position',
           t.html('consoleXacml.routePage.positionOf', {
             position: detail.position, count: detail.count })) +
      line('consoleXacml.routePage.th.upstream',
           'consoleXacml.tip.routePage.upstream',
           '<code>' + esc(proxy.upstream || '') + '</code>' +
           '<div class="sub">' + self.linkedSentence(t,
             'consoleXacml.routePage.upstreamNote', 'manifest',
             self.pepHref(name) + '#' + self.PROXY_MANIFEST_TAB,
             'consoleXacml.proxy.tab.manifest') + '</div>') +
      '</table>') + '<h4' +
      self.tipOf(t, 'consoleXacml.tip.routePage.servedBy') +
      '>' + t.html('consoleXacml.routePage.servedBy') + '</h4>' +
      (served
        ? self.wide(t, 'consoleXacml.routePage.servedBy', '<table><tr>' +
          self.th(t, 'consoleXacml.listeners.th.listener',
                  'consoleXacml.tip.listeners.listener') +
          self.th(t, 'consoleXacml.listeners.th.protocol',
                  'consoleXacml.tip.listener.protocol') +
          self.th(t, 'consoleXacml.routePage.th.port',
                  'consoleXacml.tip.listeners.address') +
          self.th(t, 'consoleXacml.listeners.th.state',
                  'consoleXacml.tip.listeners.state') + '</tr>' + served +
          '</table>')
        : '<p class="sub">' + t.html('consoleXacml.routePage.noListeners') +
          '</p>');
    if (!ctx.write) {
      return self.withinPepTabs(t, name,
        kit.note('<p>' + t.html('consoleXacml.routePage.lead') + '</p>') +
        state + '<span class="sub">' + t.html('consoleXacml.readOnly') +
        '</span>', false) + back;
    }
    const when = 'consoleXacml.tip.route.when';
    const identity = r.identity || { mode: 'headers', headers: [],
                                     separator: ',' };
    const editor = '<h3>' + t.html('consoleXacml.routePage.editHeading') +
      '</h3><form method="post" action="/admin/xacml/peps">' +
      self.hidden('action', 'set-pep-route') + self.hidden('name', name) +
      self.hidden('from', r.id) +
      self.formRow(self.labelled(t, 'consoleXacml.routeForm.id',
        'consoleXacml.tip.routePage.rename', '<input type="text" name="id" ' +
        'size="20" maxlength="64" required ' +
        'value="' + esc(r.id) + '">', when)) +
      self.routeFields(t, json, r, Math.max(detail.count - 1, 0),
                       'page-' + r.id, false, detail.position) +
      // THE APPLICATION IS MAPPED HERE (rcbj, 2026-11-14): the Reverse
      // proxy tab's "Map an application to a route" form left for this
      // field, the same chooser, saved through the same validator.
      '<div class="sub">' + t.html('consoleXacml.routePage.applicationNote') +
      '</div>' +
      self.fieldGroup(t, 'consoleXacml.routeForm.legend.identity',
        (r.public
          ? '<p class="sub">' +
            t.html('consoleXacml.routePage.publicIdentity') + '</p>'
          : self.identityFields(t, identity))) +
      self.formRow('<button type="submit"' +
        self.tipOf(t, 'consoleXacml.tip.route.when') + '>' +
        t.html('consoleXacml.routeForm.update') + '</button>') + '</form>';
    // REMOVE, BEHIND A CONFIRMATION: an unnamed required checkbox, so the
    // browser holds the submit until it is ticked and the operation's body
    // is the one `remove-pep-route` has always taken.
    const remove = '<h3>' + t.html('consoleXacml.routePage.removeHeading') +
      '</h3><form method="post" action="/admin/xacml/peps">' +
      self.hidden('action', 'remove-pep-route') + self.hidden('name', name) +
      self.hidden('route', r.id) + '<label' +
      self.tipOf(t, 'consoleXacml.tip.routes.actions') +
      '><input type="checkbox" required> ' +
      t.html('consoleXacml.routePage.removeConfirm', { route: r.id }) +
      '</label> <button type="submit">' +
      t.html('consoleXacml.routeForm.remove') + '</button></form>';
    return self.withinPepTabs(t, name,
      kit.note('<p>' + t.html('consoleXacml.routePage.lead') + '</p>') +
      state + editor + remove, true) + back;
  }

  // `/admin/xacml/pep/route` WITHOUT A ROUTE (#1760): every registered
  // PEP's routes, each a link to its page, so the address alone still
  // leads somewhere.
  static routeIndex(ctx: Json, json: Json): string {
    const t = ctx.t;
    const self = this;
    const rows = (json.peps || []).filter(function (row: Json) {
      return row.proxy && (row.proxy.routes || []).length;
    }).map(function (row: Json) {
      return '<tr><td><a href="' + esc(self.proxyTabHref(row.name)) +
        '"><code>' + esc(row.name) + '</code></a></td><td>' +
        row.proxy.routes.map(function (route: Json) {
          return '<a href="' + esc(self.routeHref(row.name, route.id)) +
            '"><code>' + esc(route.id) + '</code></a> <span class="sub">' +
            esc(route.path) + '</span>';
        }).join('<br>') + '</td></tr>';
    }).join('');
    return kit.note('<p>' + t.html('consoleXacml.routePage.indexLead') +
                    '</p>') +
      (rows
        ? self.wide(t, 'consoleXacml.routePage.th.routes',
          '<table><tr><th>PEP</th>' +
          self.th(t, 'consoleXacml.routePage.th.routes',
                  'consoleXacml.tip.routes.id') + '</tr>' + rows + '</table>')
        : '<p class="sub">' + t.html('consoleXacml.routePage.noRoutes') +
          '</p>') +
      '<p><a href="/admin/xacml#xacml-tab-peps">' +
      t.html('consoleXacml.pepPage.back') + '</a></p>';
  }

  // A route's identity as form members (`mode`, header rows, separator),
  // the identity part of the route page's edit form — the one place the
  // console edits it since 2026-11-14 — read by `identityFromForm()` on the
  // service.
  static identityFields(t: Json, identity: Json): string {
    const self = this;
    const claims = ['sub', 'username', 'email', 'name', 'given_name',
                    'family_name', 'groups', 'mechanism', 'acr', 'amr'];
    const rows = (identity.headers || []).slice();
    const blank = Math.min(16 - rows.length, 2);
    for (let i = 0; i < blank; i++) {
      rows.push({ name: '', claim: '' });
    }
    const labels: Json = {
      headers: t.html('consoleXacml.proxy.identity.mode.headers'),
      saml: t.html('consoleXacml.proxy.identity.mode.saml'),
      jwt: t.html('consoleXacml.proxy.identity.mode.jwt')
    };
    const modes = ['headers', 'saml', 'jwt'].map(function (mode) {
      return '<option value="' + mode + '"' +
        (identity.mode === mode ? ' selected' : '') + '>' + labels[mode] +
        '</option>';
    }).join('');
    const table = rows.map(function (one: Json) {
      const options = ['<option value="">' +
        t.html('consoleXacml.proxy.identity.none') + '</option>']
        .concat(claims.map(function (claim) {
          return '<option value="' + claim + '"' +
            (one.claim === claim ? ' selected' : '') + '>' + claim +
            '</option>';
        })).join('');
      // ONE HEADER PER LINE (rcbj, 2026-11-14), its name then its claim.
      return self.formRow(
        self.labelled(t, 'consoleXacml.proxy.identity.thName',
          'consoleXacml.tip.identity.headerName',
          '<input type="text" name="headerName" value="' +
          esc(one.name || '') + '" placeholder="X-Remote-User">') + ' ' +
        self.labelled(t, 'consoleXacml.proxy.identity.thClaim',
          'consoleXacml.tip.identity.claim',
          '<select name="headerClaim">' + options + '</select>'));
    }).join('');
    return self.formRow(self.labelled(t, 'consoleXacml.proxy.identity.mode',
                         'consoleXacml.tip.identity.mode',
                         '<select name="mode">' + modes + '</select>')) +
      table +
      self.formRow(self.labelled(t, 'consoleXacml.proxy.identity.separator',
                    'consoleXacml.tip.identity.separator',
                    '<input type="text" name="separator" maxlength="1" ' +
                    'size="2" value="' + esc(identity.separator || ',') +
                    '">')) +
      '<div class="sub">' + t.html('consoleXacml.proxy.identity.note') +
      '</div>';
  }

  /**
   * Draws one remote PEP's page (#1760), `/admin/xacml/pep?pep=<name>`:
   * tabs for its overview, its decisions, the settings this service sets
   * for it, its listener certificate, its reverse proxy and its CAEP/RISC
   * signal streams. The breadcrumb leads back to the Remote PEPs tab.
   *
   * @param ctx - the render context
   * @param json - `GET /admin-api/xacml/peps?pep=<name>`'s answer
   * @returns the body as HTML
   */
  static pepDetail(ctx: Json, json: Json): string {
    const t = ctx.t;
    const self = this;
    const row = (json.peps || [])[0];
    const back = '<p><a href="/admin/xacml#xacml-tab-peps">' +
      t.html('consoleXacml.pepPage.back') + '</a></p>';
    if (!json.found || !row) {
      return '<p class="warn">' + t.html('consoleXacml.pepPage.notFound',
        { name: String(json.pep || '') }) + '</p>' + back;
    }
    const line = function (label: string, value: string,
                           tipKey: string): string {
      return '<tr><th' + self.tipOf(t, tipKey) + '>' + label + '</th><td>' +
        value + '</td></tr>';
    };
    const code = function (value: unknown): string {
      return value === undefined || value === null || value === ''
        ? '<span class="sub">' + t.html('consoleXacml.pep.notReported') +
          '</span>'
        : '<code>' + esc(String(value)) + '</code>';
    };
    const overview = kit.note('<p>' + t.html('consoleXacml.pepPage.lead') +
                              '</p>') +
      self.wide(t, 'consoleXacml.pepPage.tab.overview', '<table>' +
      line(t.html('consoleXacml.pepPage.th.name'), code(row.name),
           'consoleXacml.tip.overview.name') +
      line(t.html('consoleXacml.th.certificate'), self.pepWho(t, row),
           'consoleXacml.tip.peps.certificate') +
      line(t.html('consoleXacml.pepPage.th.identity'), code(row.identity),
           'consoleXacml.tip.overview.identity') +
      line(t.html('consoleXacml.pepPage.th.thumbprint'),
           code(row.thumbprint), 'consoleXacml.tip.overview.thumbprint') +
      line(t.html('consoleXacml.pepPage.th.registered'),
           code(row.registeredAt), 'consoleXacml.tip.overview.registered') +
      line(t.html('consoleXacml.pepPage.th.version'), code(row.version),
           'consoleXacml.tip.overview.version') +
      // The hostname the PEP reports (#1760), which the realm's default
      // listener certificate names; "not reported" from an older PEP.
      line(t.html('consoleXacml.pepPage.th.hostname'), code(row.hostname),
           'consoleXacml.tip.overview.hostname') +
      line(t.html('consoleXacml.pepPage.th.description'),
           row.description ? esc(row.description)
             : code(''), 'consoleXacml.tip.overview.description') +
      line(t.html('consoleXacml.pepPage.th.resource'), code(row.resource),
           'consoleXacml.tip.overview.resource') +
      line(t.html('consoleXacml.th.itsBias'), code(row.bias),
           'consoleXacml.tip.peps.bias') +
      line(t.html('consoleXacml.th.state'), self.pepState(t, row),
           'consoleXacml.tip.peps.state') +
      line(t.html('consoleXacml.pepPage.th.syncToken'),
           code(row.syncToken), 'consoleXacml.tip.overview.syncToken') +
      line(t.html('consoleXacml.th.notify'), self.pepNotify(t, row),
           'consoleXacml.tip.peps.notify') +
      line(t.html('consoleXacml.th.actions'), self.pepActions(ctx, row),
           'consoleXacml.tip.peps.actions') +
      '</table>');
    const decisions = self.wide(t, 'consoleXacml.pepPage.tab.decisions',
      '<table>' +
      line(t.html('consoleXacml.th.enforced'), self.pepCounts(t, row),
           'consoleXacml.tip.peps.enforced') +
      line(t.html('consoleXacml.pepPage.th.policies'),
           code(row.policyCount), 'consoleXacml.tip.overview.policies') +
      '</table>') +
      kit.note('<p>' + t.html('consoleXacml.peps.numbers1') + '</p><p>' +
               t.html('consoleXacml.peps.numbers2') + '</p>',
               t.text('consoleXacml.peps.numbersLabel'));
    const listener = self.listenersBody(ctx, json, row);
    const html: Json = {
      'xacml-pep-tab-overview': overview,
      'xacml-pep-tab-decisions': decisions,
      'xacml-pep-tab-settings': self.settingsBody(ctx, json, row),
      'xacml-pep-tab-listener': listener,
      'xacml-pep-tab-proxy': self.proxySection(
        Object.assign({}, ctx, { json: json }), row),
      'xacml-pep-tab-signals': self.signalsPanel(t, row.signals)
    };
    return kit.tabbedPanels('xacml-pep-pages',
      self.pepTabs(t).map(function (one: Json) {
        return Object.assign({}, one, { html: html[one.id] });
      })) + back;
  }

  // THE PEP PAGE'S TABS, in order: drawn by `pepDetail()`, and by a route's
  // page, which keeps them (`withinPepTabs()`).
  static pepTabs(t: Json): Array<{ id: string; label: string }> {
    return [
      { id: 'xacml-pep-tab-overview',
        label: t.text('consoleXacml.pepPage.tab.overview') },
      { id: 'xacml-pep-tab-decisions',
        label: t.text('consoleXacml.pepPage.tab.decisions') },
      { id: 'xacml-pep-tab-settings',
        label: t.text('consoleXacml.pepPage.tab.settings') },
      { id: 'xacml-pep-tab-listener',
        label: t.text('consoleXacml.pepPage.tab.listener') },
      { id: XacmlPage.PROXY_TAB,
        label: t.text('consoleXacml.pepPage.tab.proxy') },
      { id: 'xacml-pep-tab-signals',
        label: t.text('consoleXacml.pepPage.tab.signals') }
    ];
  }

  // THE REVERSE PROXY TAB'S SUB-TABS, in order, by their labels.
  static proxySubTabs(t: Json): Array<{ id: string; label: string }> {
    return [
      { id: XacmlPage.PROXY_ROUTES_TAB,
        label: t.text('consoleXacml.proxy.tab.routes') },
      { id: XacmlPage.PROXY_NEW_ROUTE_TAB,
        label: t.text('consoleXacml.proxy.tab.newRoute') },
      { id: XacmlPage.PROXY_MANIFEST_TAB,
        label: t.text('consoleXacml.proxy.tab.manifest') }
    ];
  }

  // A ROUTE'S PAGE KEEPS THE TABS IT WAS OPENED FROM (rcbj, 2026-11-14):
  // the PEP page's bar with Reverse proxy current, inside it the Reverse
  // proxy sub-tabs with Configured Routes current, and the route inside
  // that. Every other tab and sub-tab is a link to the PEP page at that
  // tab's anchor (`kit.tabbedPanels()`'s `href`), so it is the PEP page's
  // own panel a reader goes to, drawn from the PEP page's own answer.
  static withinPepTabs(t: Json, name: string, html: string,
                       write: boolean): string {
    const self = this;
    const pep = self.pepHref(name);
    const sub = kit.subTabbedPanels(t.text('consoleXacml.pepPage.tab.proxy'),
      self.proxySubTabs(t).filter(function (one: Json) {
        return write || one.id !== XacmlPage.PROXY_NEW_ROUTE_TAB;
      }).map(function (one: Json) {
        return one.id === XacmlPage.PROXY_ROUTES_TAB
          ? Object.assign({}, one, { html: html })
          : Object.assign({}, one, { href: pep + '#' + one.id });
      }));
    return kit.tabbedPanels('xacml-pep-pages',
      self.pepTabs(t).map(function (one: Json) {
        return one.id === XacmlPage.PROXY_TAB
          ? Object.assign({}, one, { html: sub })
          : Object.assign({}, one, { href: pep + '#' + one.id });
      }));
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
    // A TAB PER SECTION (2026-10-12): the tiles, the warning and what this
    // page is are Metadata (`WebPages.protocolTabs()`).
    const evidence =
      '<h2 data-tab="figures">' +
      t.html('consoleXacml.monitor.figuresHeading') + '</h2>' +
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
    const table = '<h2 data-tab="points">' +
      t.html('consoleXacml.monitor.everyPoint') + '</h2>' +
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
      // `.indent-N` in the console's stylesheet, N × 1.4rem: the console's
      // policy allows no `style=""` (2026-11-10).
      return '<tr><td class="indent-' +
        Math.min(Math.max(0, Number(row.depth) || 0), 9) + '">' +
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
