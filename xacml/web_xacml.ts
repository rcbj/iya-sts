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
  static serviceOwnEditorNote(rows: any[]): string {
    const overridden = (rows || []).filter(function (one) {
      return one.entry;
    }).length;
    return kit.note(
      '<p><strong>This chooser lists <code>ou=policies</code>, and two ' +
      'policies that are deciding right now are not in it.</strong> The ' +
      'issuance policy (what this service will issue) and the access policy ' +
      '(who reaches the console, the User Portal, SCIM, the SPIRE Server ' +
      'API) are BUILT IN — called at decision time rather than seeded — so ' +
      'there is no stored document for this editor to open.</p><p>' +
      (overridden
        ? 'One or more of them HAS an override in the repository, so it is ' +
          'in the list above and opens here like any other policy. '
        : 'Neither has an override yet. ') +
      'Create one from its template on the ' +
      '<a href="/admin/xacml/policies#service-own">Policies</a> page and it ' +
      'appears here.</p>',
      'Two policies are deciding and are not in this list');
  }

  static renderServiceOwnPolicies(rows: any[], writable: boolean): string {
    const self = this;
    const body = rows.map(function (row) {
      // WHERE THE DOCUMENT COMES FROM, in three states rather than two. "No
      // override has been written" and "an override was written and disabled"
      // are opposite situations that `builtIn` alone cannot tell apart, and the
      // second is the one somebody needs to see.
      let source;
      if (!row.ok) {
        source = '<strong style="color:#b00">nothing is evaluated</strong>';
      } else if (!row.builtIn) {
        source = 'the repository entry <a href="/admin/xacml/editor?policy=' +
          encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
          '</code></a>';
      } else if (row.entry) {
        source = 'the <strong>built-in</strong> document — the entry <code>' +
          esc(row.name) + '</code> exists and is <em>disabled</em>';
      } else {
        source = 'the <strong>built-in</strong> document, from the <code>' +
          esc(row.template) + '</code> template';
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
          '<button type="submit">Create an override</button></form>'
        : (row.entry
            ? '<a href="/admin/xacml/editor?policy=' +
              encodeURIComponent(row.name) + '">Edit it</a>'
            : '<span class="sub">read-only</span>');
      return '<tr><td><strong>' + esc(row.label) + '</strong>' +
        '<div class="sub">named by <code>' + esc(row.setting) + '</code>: ' +
        '<code>' + esc(row.name) + '</code></div></td>' +
        '<td>' + esc(row.decides) + '<div class="sub">asked at ' +
        esc(row.asked).replace(/`([^`]+)`/g, '<code>$1</code>') +
        '</div></td>' +
        '<td>' + source + '</td>' +
        '<td>' + esc(row.effect) + '</td>' +
        '<td>' + make + '</td></tr>';
    }).join('');
    return '<h2 id="service-own">What this service decides its own ' +
      'boundaries with</h2>' +
      kit.warn(
        '<p><strong>These two policies are IN FORCE and are not in the table ' +
        'above.</strong> That table is <code>ou=policies</code>; these are ' +
        'BUILT IN — the template is called at decision time rather than ' +
        'seeded into the repository — so the editor has never listed them ' +
        'and a reader looking only at the repository would conclude that ' +
        'whatever is root there is what this service enforces. Usually it is ' +
        'not: a seeded example policy decides nothing this service ' +
        'does.</p><p><strong>They are built in rather than seeded on ' +
        'purpose.</strong> <code>ou=policies</code> is per trust realm, so a ' +
        'policy written once into the default realm leaves every realm ' +
        'created afterwards unable to decide anything at all — and falling ' +
        'back to the default realm\'s copy would couple two realms, which is ' +
        'the one thing the realm design does not do. Called rather than ' +
        'seeded, every realm has both of them out of the box with nothing to ' +
        'delete.</p><p><strong>An override is an ordinary policy.</strong> ' +
        'Create one from the same template, named whatever the setting says, ' +
        'and it wins from the next request — it then appears in the table ' +
        'above and in the editor like everything else. Neither is sent to a ' +
        'remote PEP: <code>GET /xacml/pep/policies</code> carries the ' +
        'policies about somebody ELSE\'s boundary, and these two are about ' +
        'this service\'s own.</p>',
        'Two policies decide here and are not in the repository') +
      '<table><tr><th>Policy</th><th>What it decides</th>' +
      '<th>Document in force</th><th>Right now</th><th></th></tr>' +
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
  static noPepsHere(where: any[]): string {
    const shared = 'That does not mean none is running: registering is not ' +
      'what lets a PEP enforce, and one that only ever pulls ' +
      '<code>/xacml/pep/policies</code> works perfectly and never appears ' +
      'here.';
    if (!where.length) {
      return 'No remote Policy Enforcement Point has registered, <strong>in ' +
        'this realm or in any other</strong>. ' + shared;
    }
    const list = where.map(function (one) {
      return '<a href="/realm/' + esc(one.id) + '/admin/xacml/peps"><code>' +
        esc(one.id) + '</code></a> (' + one.count + ')';
    }).join(', ');
    return 'No remote Policy Enforcement Point has registered <strong>in ' +
      'this realm</strong> &mdash; but ' + where.length + ' other realm' +
      (where.length === 1 ? '' : 's') + ' hold' +
      (where.length === 1 ? 's' : '') +
      ' one: ' + list + '. <strong>The register is per realm</strong>, like ' +
      'the policy repository it serves, so a PEP that registered against ' +
      '<code>/realm/&lt;id&gt;</code> is listed there and nowhere ' +
      'else. ' + shared;
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
  static decisionCells(row: any): string {
    if (row.permit === null || row.permit === undefined) {
      return '<td colspan="4" class="sub">not reported &mdash; a remote PEP ' +
             'sends what it enforced, and only the process that EVALUATED ' +
             'knows which of the four decisions each was</td>';
    }
    return '<td class="num state-valid">' + row.permit + '</td>' +
      '<td class="num state-revoked">' + row.deny + '</td>' +
      '<td class="num">' + row.notApplicable + '</td>' +
      '<td class="num state-expired">' + row.indeterminate + '</td>';
  }

  // The allowed/refused pair, or the EMPTY cell that says this asker never
  // enforced anything. `/xacml/pdp` is the one row that gets it, and the
  // distinction is the point: a zero would read as "it refused nothing".
  static enforcementCells(row: any): string {
    const self = this;
    if (!row.enforces || row.allowed === null || row.allowed === undefined) {
      return '<td colspan="2" class="sub">nothing was enforced here &mdash; ' +
             'this service produced the decision and somebody else\'s PEP ' +
             'acted on it, in their process</td>';
    }
    return '<td class="num state-valid">' +
      self.share(row.allowed, row.decisions) +
      '</td><td class="num state-revoked">' +
      self.share(row.refused, row.decisions) +
      '</td>';
  }

  static monitorRow(row: any): string {
    const self = this;
    const state = [];
    if (row.kind === 'remote') {
      state.push(row.remote.current
        ? '<span title="This PEP reported holding the repository digest this ' +
          'service has now.">current</span>'
        : '<strong title="The sync token this PEP last reported is not the ' +
          'one the repository has now. It converges on its next poll.">not ' +
          'current</strong>');
      state.push(row.remote.stale ? '<strong>stale</strong>' : 'live');
      if (!row.remote.authenticated) {
        state.push('<strong>unauthenticated</strong>');
      }
    } else {
      // AN EMBEDDED PEP IS ALWAYS LIVE AND THAT IS NOT A REASSURANCE, it is a
      // tautology worth stating: it is compiled into this process, so it is
      // running exactly when this page is being drawn. There is nothing to be
      // stale about and no registration to have failed.
      state.push('<span title="Compiled into this process. It is running ' +
                 'because this page is.">in this process</span>');
    }
    const counts = row.decisions
      ? esc(row.lastDecision || '') +
        (row.lastAllowed === null || row.lastAllowed === undefined
          ? ''
          : ', ' + (row.lastAllowed ? 'allowed' : 'refused')) +
        '<div class="sub">' + esc(row.lastAt || '') + '</div>'
      : '<span class="sub">nothing yet</span>';
    return '<tr><td><strong>' + esc(row.label) + '</strong>' +
      '<div class="sub">' + esc(row.kind) + ' &middot; <code>' +
      esc(row.where) + '</code></div>' +
      '<div class="sub">' + esc(row.guards) + '</div></td>' +
      '<td>' + state.join('<br>') +
      (row.kind === 'remote' && row.remote.policyCount !== null
        ? '<div class="sub">holds ' + row.remote.policyCount + ' ' +
            'policy/policies</div>'
        : '') +
      '</td>' +
      '<td>' + (row.bias ? esc(row.bias) : '<span class="sub">n/a</span>') +
      (row.kind === 'remote'
        ? '<div class="sub">reported by it</div>'
        : (row.id === 'protected'
            ? '<div class="sub"><code>xacml.pepBias</code></div>'
            : '')) +
      '</td>' +
      '<td class="num">' + row.decisions + '</td>' +
      self.enforcementCells(row) +
      self.decisionCells(row) +
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
    const self = this;
    const tiles = '<div class="tiles">' +
      kit.tile(json.policies, 'policies') +
      kit.tile(json.enabledPolicies, 'enabled') +
      kit.tile(json.root || '—', 'root policy') +
      kit.tile(json.pepBias, 'PEP bias') +
      kit.tile(json.pipAvailable ? 'yes' : 'no', 'PIP has the directory') +
      '</div>';

    const rootWarning = json.root ? '' : kit.warn(
      'No policy is marked as the root, so <strong>every decision is ' +
      'NotApplicable</strong>. A PDP evaluates one document and reaches ' +
      'the rest through <code>PolicyIdReference</code>, so exactly one ' +
      'policy in the repository is where evaluation starts. Choose one on ' +
      'the <a href="/admin/xacml/policies">Policies</a> page.',
      'There is no root policy');

    const what = kit.note(
      '<p>This service is a <strong>Policy Decision Point</strong>. It is ' +
      'the only protocol family here that answers a question about ' +
      'somebody else&rsquo;s boundary: every other one authenticates or ' +
      'provisions a person, and this one is handed a subject who was ' +
      'authenticated somewhere else and asked whether they may.</p>' +
      '<p>Policies live in <code>ou=policies</code> in the embedded ' +
      'directory. That container <em>is</em> the repository rather than a ' +
      'copy of one, so an <code>ldapmodify</code> there changes what the ' +
      'PDP decides on the next request — and a policy survives a restart ' +
      'whenever <code>persistence.mode</code> is not ' +
      '<code>memory</code>.</p><p>The <strong>PIP</strong> reads ' +
      'attributes off the subject&rsquo;s own directory entry, so a policy ' +
      'can grant on <code>employeeType</code> ' +
      'without the caller having to assert it. What the REQUEST carries ' +
      'wins over the directory, because a PEP asserting an attribute is ' +
      'describing that request while the directory is describing the ' +
      'world.</p><p><code>xacml.pepBias</code> below is the <em>embedded ' +
      'PEP&rsquo;s</em> decision and not the PDP&rsquo;s. Deny-biased and ' +
      'permit-biased agree ' +
      'on every Permit and every Deny and differ on Indeterminate and ' +
      'NotApplicable — which is exactly the case nobody tests, and the ' +
      'reason the setting is here to flip.</p>',
      'What this page configures');
    return tiles + rootWarning + what +
                  SettingsForms.forms(json.settings, '/admin/xacml');
  }

  /**
   * Draws XACML policies from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `policiesJson()`'s answer
   * @returns the body as HTML
   */
  static policiesBody(ctx, json) {
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
        '<button type="submit">' + (row.enabled ? 'Disable' : 'Enable') +
        '</button></form> ' +
        (row.isRoot ? '' : '<form method="post" ' +
          'action="/admin/xacml/policies" style="display:inline">' +
          self.hidden('action', 'set-root') + self.hidden('name', row.name) +
          '<button type="submit">Make root</button></form> ') +
        '<form method="post" action="/admin/xacml/policies" ' +
        'style="display:inline">' +
        self.hidden('action', 'delete') + self.hidden('name', row.name) +
        '<button type="submit">Delete</button></form>'
        : '<span class="sub">read-only</span>';
      return '<tr><td><a href="/admin/xacml/editor?policy=' +
        encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
        '</code></a>' + (row.isRoot ? ' <strong>(root)</strong>' : '') +
        '</td><td><code>' + esc(row.policyId) + '</code>' + problems +
        '</td><td>' + esc(row.kind) + '</td><td>' +
        esc(String(row.combiningAlgId)
          .replace(/^urn:oasis:names:tc:xacml:[0-9.]+:function:/, '')
          .replace(/^.*combining-algorithm:/, '')) +
        '</td><td>' + (row.enabled ? 'enabled' : '<em>disabled</em>') +
        '</td><td>' + actions + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="6">The repository is empty, so every decision is ' +
      'NotApplicable. Create one from a template below.</td></tr>';

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
        '<table><tr><td>Name for the policy</td><td>' +
        self.textField('name', one.id, 30) +
        '</td><td class="sub">Names the directory entry. The PolicyId ' +
        'inside the document is separate and may be any URI.</td></tr>' +
        fields +
        '</table><button type="submit">Create</button></form></details>';
    }).join('') : '';

    const body = kit.note(
      '<p><code>ou=policies</code> in the embedded directory ' +
      '<strong>is</strong> this table. An <code>ldapmodify</code> of ' +
      '<code>xacmlPolicyDocument</code> changes what the PDP decides on ' +
      'the next request, and <code>xacmlEnabled</code> takes a policy out ' +
      'of the decision without deleting it.</p>' +
      '<p><strong>Exactly one policy is the root.</strong> A PDP evaluates ' +
      'one document and reaches the rest through ' +
      '<code>PolicyIdReference</code>, so the root is where evaluation ' +
      'starts. A repository with none decides nothing; one with two is ' +
      'refused rather than resolved arbitrarily.</p><p>A policy that does ' +
      'not type-check is shown in red here and was refused when it was ' +
      'written — XACML is statically typed, so such a policy is wrong for ' +
      'every request rather than for some.</p>',
      'What this page is') +
      '<table><tr><th>Name</th><th>PolicyId</th><th>Kind</th>' +
      '<th>Combining</th><th>State</th><th>Actions</th></tr>' + rows +
      '</table>' +
      self.renderServiceOwnPolicies(json.serviceOwn, writable) +
      (writable
        ? '<h2>Import ALFA</h2>' + kit.note(
            '<p>ALFA is the readable syntax for XACML. Paste one here and ' +
            'it is parsed, converted and STORED AS XACML XML — the ' +
            'repository holds one representation, because two would be two ' +
            'things to keep in step.</p>' +
            '<p>Every attribute must be DECLARED before it is used. That ' +
            'is ALFA\'s own rule and it is the most useful refusal in the ' +
            'parser: a typo in an attribute name is otherwise a policy ' +
            'that quietly matches nothing, which looks exactly like a ' +
            'policy that is working and denying you. Open any policy in ' +
            'the editor to see the shape.</p>',
            'What this accepts') +
          '<form method="post" action="/admin/xacml/policies">' +
          self.hidden('action', 'import-alfa') +
          '<p>Name ' + self.textField('name', 'imported', 24) + '</p>' +
          '<textarea name="alfa" rows="14" cols="88" ' +
          'placeholder="namespace example { ... }"></textarea>' +
          '<p><button type="submit">Import</button></p></form>'
        : '') +
      (templateForms
        ? '<h2>Create from a template</h2>' + kit.note(
            '<p>A template is the first twenty clicks of the editor ' +
            'already made: a working, valid, evaluable policy in a shape ' +
            'people actually write. The editor takes it from there.</p>' +
            '<p><strong><code>blank</code> is the exception and it is here ' +
            'on purpose.</strong> It makes no argument and there is ' +
            'nothing in it to read — an empty Policy, or an empty ' +
            'PolicySet, which is the only way to create one of those here ' +
            'without importing ALFA. It <em>denies every request</em> ' +
            'until you put a rule in it, because deny-unless-permit over ' +
            'nothing at all is a Deny. That is the direction a half-built ' +
            'policy should fail in, and it is why building it before ' +
            'making it the root is the right order.</p><p>RBAC asks ' +
            '<em>what role do you hold</em>; ABAC asks <em>what is true ' +
            'about you, this resource and right now</em>. The first is ' +
            'what most deployments have and the second is what they wanted ' +
            '— having both here, producing documents in the same language, ' +
            'is the clearest way to see what the difference costs in ' +
            'policy.</p>',
            'What a template is') + templateForms
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
    const self = this;
    const writable = ctx.write;

    const rows = json.peps.map(function (row) {
      const state = [];
      state.push(row.current
        ? '<span title="This PEP reported holding the repository digest ' +
          'this service has now.">current</span>'
        : '<strong title="The sync token this PEP last reported is not the ' +
          'one the repository has now. It converges on its next poll.">not ' +
          'current</strong>');
      state.push(row.stale
        ? '<strong title="Nothing has been heard from this PEP for longer ' +
          'than xacml.pepStaleAfterS. It may still be enforcing — this ' +
          'service cannot tell.">stale</strong>'
        : 'live');
      if (!row.enabled) {
        state.push('<em>not nudged</em>');
      }
      // THE AUTHENTICATION IS ON THE ROW AND NOT IN A FOOTNOTE. A
      // registration that proved nothing must not look the same as one that
      // proved something, which is the whole reason the flag is stored rather
      // than inferred from whether a subject happens to be present.
      const who = row.authenticated
        ? '<code>' + esc(row.certificateSubject) + '</code>'
        : '<strong>unauthenticated</strong><div class="sub">Registered ' +
          'with no client certificate, which xacml.pepRequireCertificate ' +
          'allowed. Nothing about this row is proven.</div>';
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
        : '<span class="sub">none — never nudged, and it converges on its ' +
          'own poll anyway</span>';
      // THE HTTPS LISTENER CERTIFICATE (2026-09-13). What this realm ISSUED,
      // and never whether the PEP is serving it: nothing on this page reaches
      // into another process, and the PEP's own GET / is where that is said.
      const held = row.listenerCertificate;
      const listener = (held
        ? '<code>' + esc(held.serialHex) + '</code>' +
          '<div class="sub">' +
          esc(held.dnsNames.concat(held.ipAddresses).join(', ')) + '</div>' +
          '<div class="sub">' +
          (held.expired ? '<strong>expired</strong> ' : '') +
          'until ' + esc(held.notAfter) + '</div>'
        : '<span class="sub">none issued</span>') +
        (writable
          ? '<form method="post" action="/admin/xacml/peps">' +
            self.hidden('action', 'issue-pep-certificate') +
            self.hidden('name', row.name) +
            '<div class="sub">More DNS names <input name="dnsNames" ' +
            'size="18" placeholder="pep.example.test"></div>' +
            '<div class="sub">IP addresses <input name="ipAddresses" ' +
            'size="14" placeholder="10.0.0.5"></div>' +
            '<div class="sub">Key ' +
            self.select('keyAlg', json.listenerCertificates.keyAlgorithms
              .map(function (one) {
                return { value: one, label: one };
              }), json.listenerCertificates.defaultKeyAlg) + ' ' +
            '<button type="submit">' + (held ? 'Reissue' : 'Issue') +
            ' certificate</button></div></form>'
          : '');
      const actions = writable
        ? '<form method="post" action="/admin/xacml/peps" ' +
          'style="display:inline">' +
          self.hidden('action', row.enabled ? 'disable-pep' : 'enable-pep') +
          self.hidden('name', row.name) +
          '<button type="submit">' +
          (row.enabled ? 'Stop nudging' : 'Nudge') +
          '</button></form> ' +
          '<form method="post" action="/admin/xacml/peps" ' +
          'style="display:inline">' +
          self.hidden('action', 'forget-pep') +
          self.hidden('name', row.name) +
          '<button type="submit">Forget</button></form>'
        : '<span class="sub">read-only</span>';
      return '<tr><td><code>' + esc(row.name) + '</code>' +
        (row.resource ? '<div class="sub">guards ' + esc(row.resource) +
                        '</div>' : '') +
        (row.version
          ? '<div class="sub">' + esc(row.version) + '</div>'
          : '') +
        '</td><td>' + who + '</td><td>' + state.join(', ') +
        '<div class="sub">last seen ' + esc(row.lastSeen || 'never') +
        '</div></td><td>' + esc(row.bias || 'not reported') +
        '</td><td>' + row.decisions + ' decided, ' + row.allowed +
        ' allowed, ' + row.refused + ' refused' +
        (row.undischargeable
          ? '<div class="sub">' + row.undischargeable +
          ' of those refused for ' +
            'an obligation it could not discharge</div>'
          : '') +
        '</td><td>' + notify + '</td><td>' + listener + '</td><td>' +
        actions +
        '</td></tr>';
    }).join('') ||
      '<tr><td colspan="8">' + self.noPepsHere(json.elsewhere) + '</td></tr>';

    const body = kit.note(
      '<p>A <strong>remote</strong> Policy Enforcement Point runs in ' +
      'another process, holds its own copy of this engine, ' +
      '<strong>pulls</strong> the enabled policies from ' +
      '<code>/xacml/pep/policies</code> and decides locally. That is the ' +
      'point of having one: a PEP that asked this service per request ' +
      'would be <code>POST /xacml/pdp</code> with a network hop in front ' +
      'of every access decision.</p><p><strong>The pull is the ' +
      'contract.</strong> When the repository changes this service also ' +
      'POSTs a few bytes to each PEP that gave a notify URL, saying only ' +
      'that something changed. That is an optimisation over the polling ' +
      'interval and never a replacement for it &mdash; a nudge that is ' +
      'refused, blocked or never delivered costs one polling interval and ' +
      'nothing else, which is why the failure is worth showing here and ' +
      'not worth alarming about.</p><p><strong>Nothing on this page ' +
      'reaches into another process.</strong> &ldquo;Stop nudging&rdquo; ' +
      'stops this service dialling that PEP; it does not stop it ' +
      'enforcing, because it already holds the engine and the policy. ' +
      '&ldquo;Forget&rdquo; removes the row. Neither takes a running ' +
      'enforcement point out of service, and a console that implied ' +
      'otherwise would be worse than one with no controls at ' +
      'all.</p><p>Registering is <em>not</em> a permission. An ' +
      'unregistered PEP can pull and enforce exactly as well; what a row ' +
      'buys is this page and an address for the nudge.</p>',
      'What this page is') +
      '<p>The repository&rsquo;s sync token is <code>' +
      esc(json.syncToken) + '</code>. ' + json.current + ' of ' +
      json.peps.length + ' registered PEP(s) hold it; ' + json.stale +
      ' have not been heard from for ' + json.staleAfterS + 's.</p>' +
      (json.enabled ? ''
        : '<p><strong>Remote Policy Enforcement Points are turned ' +
          'off</strong> ' +
          '(<code>xacml.remotePeps</code>), so the three endpoints under ' +
          '<code>/xacml/pep</code> answer 501 and nothing here is nudged. ' +
          'The register below is untouched and comes back when it is ' +
          'turned on.</p>') +
      (json.notify.on ? ''
        : '<p><strong>The nudge is turned off</strong> ' +
          '(<code>xacml.pepNotify</code>), so nothing below is dialled. ' +
          'Every PEP still converges on its own poll &mdash; that is what ' +
          'makes this safe to turn off.</p>') +
      '<table><tr><th>PEP</th><th>Certificate</th><th>State</th>' +
      '<th>Its bias</th><th>What it enforced</th><th>Notify</th>' +
      '<th>HTTPS listener certificate</th>' +
      '<th>Actions</th></tr>' + rows + '</table>' +
      kit.note(
        '<p>A remote PEP answers its own clients, and the column above is ' +
        'the certificate it answers them with. It is issued by the ' +
        '<strong>Remote PEP listeners</strong> Issuing CA of <em>this</em> ' +
        'realm &mdash; the realm the PEP registered to &mdash; so a client ' +
        'that installed this service&rsquo;s Root CA verifies it, and the ' +
        'chain still says which realm vouched for that front door. It ' +
        'names the PEP&rsquo;s registered name and the host of its notify ' +
        'URL, plus whatever you add.</p><p><strong>The private key is ' +
        'shown once</strong>, on the page that answers the button, and ' +
        'this service keeps no copy. Write the two blocks to the files the ' +
        'container reads (<code>PEP_HTTPS_CERT</code> and ' +
        '<code>PEP_HTTPS_KEY</code>); it picks up a pair written after it ' +
        'started, and reissuing supersedes the certificate it replaces on ' +
        'the issuer&rsquo;s revocation list.</p>',
        'The HTTPS listener certificate') +
      kit.note(
        '<p>The decision counts are the PEP&rsquo;s own, reported by it, ' +
        'cumulative in its process. This service did not see one of those ' +
        'decisions &mdash; that is what a remote PEP is &mdash; so a PEP ' +
        'that restarts makes its counts go down, which is honest rather ' +
        'than broken.</p>' +
        '<p>The bias column is likewise <em>reported</em>. ' +
        '<code>xacml.pepBias</code> on the settings page governs the ' +
        '<em>embedded</em> PEP at <code>/xacml/protected</code> and ' +
        'nothing here; a control that appeared to set a remote PEP&rsquo;s ' +
        'bias would silently do nothing.</p>',
        'Where these numbers come from');
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
      kit.tile(json.policies.total, 'policies') +
      kit.tile(json.policies.enabled, 'enabled') +
      kit.tile(json.peps.total, 'enforcement points') +
      kit.tile(combined.decisions, 'decisions') +
      kit.tile(combined.allowed, 'allows') +
      kit.tile(combined.refused, 'declines') +
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
      '<h2>Where those figures come from</h2>' +
      '<table><tr><th>Counted</th><th class="num">Decisions</th>' +
      '<th class="num">Allowed</th><th class="num">Refused</th>' +
      '<th class="num">Not enforced here</th>' +
      '<th class="num">Refused on an obligation</th><th>What it ' +
      'is</th></tr>' +
      evidenceRow('Here', here,
        'Decisions THIS process made, counted as it happened. Since ' +
        esc(json.since) + '.') +
      evidenceRow('Remote', there,
        'What registered Policy Enforcement Points in OTHER processes ' +
        'REPORT having done, on their heartbeats, cumulative in their own ' +
        'memory. This service saw none of it &mdash; that is what a remote ' +
        'PEP is &mdash; and a PEP that restarts makes this half go down.') +
      evidenceRow('Combined', combined,
        'The two rows added up. It is the figure a deployment wants and it ' +
        'is <em>arithmetic over two different kinds of evidence</em> ' +
        'rather than a measurement, which is why it is a row here and not ' +
        'the only number on the page.') +
      '</table>' +
      kit.note(
        '<p><strong>Allowed + refused + not-enforced = decisions</strong>, ' +
        'on every row. The third column is the one that is easy to be ' +
        'surprised by and it is not a failure: it counts the decisions ' +
        '<code>POST /xacml/pdp</code> produced for somebody ELSE&rsquo;s ' +
        'enforcement point. This service evaluated them and never saw what ' +
        'was done with the answers, so counting them as allowed or refused ' +
        'would be reporting an enforcement it was not present for.</p>',
        'Why the three do not add to the total on their own');

    const what = kit.note(
      '<p>This is the only page in this family about ' +
      '<strong>traffic</strong>. The others are about configuration ' +
      '&mdash; what policies exist, what one of them says, what the PDP ' +
      'would decide about a subject you type in. This one answers the ' +
      'question you have when authorization is misbehaving: how many ' +
      'decisions are being made, by which enforcement point, and how many ' +
      'of them are refusals.</p><p><strong>&ldquo;Decisions&rdquo; and ' +
      '&ldquo;allows&rdquo; are not two views of one tally.</strong> XACML ' +
      'has FOUR decisions &mdash; Permit, Deny, NotApplicable, ' +
      'Indeterminate &mdash; and a PEP has TWO outcomes. What maps between ' +
      'them is the PEP&rsquo;s <em>bias</em>: a deny-biased PEP refuses a ' +
      'NotApplicable and a permit-biased one allows it, from the same ' +
      'decision on the same request. And an obligation a PEP cannot ' +
      'discharge turns a Permit into a refusal (section 7.2) &mdash; the ' +
      'one enforcement outcome that looks like a bug from the client side ' +
      'and is the specification working. So <code>allowed</code> is not ' +
      '<code>permit</code>, and both are drawn.</p><p><strong>The counters ' +
      'are in memory and start when this process does.</strong> They are ' +
      'observations, and this service persists nothing it observes; the ' +
      'durable record of a refusal is the <a href="/admin/audit">audit ' +
      'log</a>, which holds the reason as well as the count. They are also ' +
      '<strong>per trust realm</strong>, like <code>ou=policies</code> ' +
      'itself &mdash; this page is showing <strong>' +
      esc(json.realm.name || json.realm.id) +
      '</strong>, and a decision made ' +
      'under another realm was made against another realm&rsquo;s ' +
      'policies.</p><p><strong>There is no reset button</strong>, ' +
      'deliberately: a console that could zero its own monitoring would ' +
      'make every number here a number somebody might have zeroed. A ' +
      'restart is what clears them.</p>',
      'What this page is');

    const off = json.enabled ? '' : kit.warn(
      '<strong>The XACML family is switched off</strong> ' +
      '(<code>xacml.enabled</code>), so nothing is being evaluated and ' +
      'every figure below has stopped moving. The embedded PEPs answer ' +
      'ALLOWED without asking the PDP &mdash; which is what keeps a ' +
      'service with the family off a smaller service rather than a broken ' +
      'one &mdash; and those allows are counted, because they are what ' +
      'happened.',
      'Nothing is being decided');

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
    const table = '<h2>Every enforcement point</h2>' +
      '<table><tr><th>Point</th><th>State</th><th>Bias</th>' +
      '<th class="num">Decisions</th><th class="num">Allowed</th>' +
      '<th class="num">Refused</th><th class="num">Permit</th>' +
      '<th class="num">Deny</th><th class="num">NotApplicable</th>' +
      '<th class="num">Indeterminate</th><th>Last</th></tr>' +
      allRows.map(function (row) {
        return self.monitorRow(row);
      }).join('') + '</table>' +
      kit.note(
        '<p><strong>An embedded PEP is not &ldquo;registered&rdquo; and ' +
        'cannot be.</strong> It is compiled into this process, so its ' +
        'existence is a fact about the build rather than something it told ' +
        'this service; there are exactly three and they are the catalogue ' +
        'in <code>xacml_monitor.js</code>. A <em>remote</em> PEP registers ' +
        'because it has no other way to be known about &mdash; and even ' +
        'that is not a permission: an unregistered PEP can pull ' +
        '<code>/xacml/pep/policies</code> and enforce perfectly, and never ' +
        'appears here. So <strong>this list is every enforcement point ' +
        'this service KNOWS ABOUT</strong>, which is a smaller claim than ' +
        'every one that exists, and the difference cannot be closed from ' +
        'this end.</p><p><strong>Only the demonstration PEP&rsquo;s bias ' +
        'is settable.</strong> <code>xacml.pepBias</code> governs that ' +
        'one. The issuance and access PEPs are deny-biased by construction ' +
        '&mdash; an issuance or an access that was not permitted does not ' +
        'happen &mdash; and a remote PEP&rsquo;s bias is <em>reported by ' +
        'it</em>, because a control here that appeared to set another ' +
        'process&rsquo;s bias would silently do nothing.</p><p>The remote ' +
        'rows are a summary. <a href="/admin/xacml/peps">Remote PEPs</a> ' +
        'has the sync tokens, the notify URLs, what happened to the last ' +
        'nudge, and the controls.</p>' +
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
          : '<p>' + self.noPepsHere(json.elsewhere) + '</p>'),
        'What this list is, and what it is not') +
      kit.note(
        '<p>A refusal here is a policy decision and the reason is in the ' +
        '<a href="/admin/audit">audit log</a>, not in this table: ' +
        '<code>xacml.issuance.refused</code> for the issuance PEP, ' +
        '<code>xacml.access.refused</code> for the access PEP and ' +
        '<code>xacml.enforcement</code> for the demonstration one. This ' +
        'page says how many; that log says who, what and why.</p><p>To ' +
        'make a decision happen on purpose and watch it land here, use <a ' +
        'href="/admin/xacml/decide">Try a decision</a> &mdash; but note ' +
        'that the enforcement preview on that page is deliberately ' +
        '<em>not</em> counted. It is a what-if rather than a request ' +
        'anybody guarded, and counting it would make this page&rsquo;s ' +
        'numbers grow every time somebody looked at it. <code>GET ' +
        '/xacml/protected</code> is the endpoint that really ' +
        'enforces.</p><p><strong>Drawing THIS page adds one to the access ' +
        'PEP\'s count, and that is right rather than a measurement ' +
        'artefact.</strong> <code>/admin</code> is one of the five gated ' +
        'surfaces, so reading it is a real request that the access policy ' +
        'really decided &mdash; the number would be wrong if it did not ' +
        'move. It is the opposite case from the preview above, and the two ' +
        'are worth telling apart: one is an access that happened, the ' +
        'other is a question somebody typed.</p>',
        'Where a refusal is explained');

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
    const self = this;
    const form = '<form method="get" action="/admin/xacml/decide">' +
      '<table><tr><td>Subject</td><td>' +
      self.textField('subject', json.subject || 'alice', 24) +
      '</td><td class="sub">A name, a DN or a certificate subject — all ' +
      'three resolve the way they do everywhere else here. The PIP reads ' +
      'this person&rsquo;s directory entry for any attribute the policy ' +
      'asks for.</td></tr>' +
      '<tr><td>Action</td><td>' +
      self.textField('action', json.action || 'GET', 24) +
      '</td><td class="sub">Becomes the standard action-id ' +
      'attribute.</td></tr><tr><td>Resource</td><td>' +
      self.textField('resource', json.resource || '', 40) +
      '</td><td class="sub">Optional. Becomes resource-id, as an ' +
      'anyURI.</td></tr></table>' +
      '<button type="submit">Ask the PDP</button></form>';

    let answer = '';
    if (json.asked) {
      const policies = json.applicablePolicies.length
        ? json.applicablePolicies.map(function (one) {
            return '<code>' + esc(one.id) + '</code>';
          }).join(', ')
        : '<em>none — nothing in the repository applied</em>';
      answer = '<h2>' + esc(json.decision) + '</h2>' +
        '<div class="tiles">' +
        kit.tile(json.decision, 'PDP decision') +
        kit.tile(json.enforcement.allowed ? 'allowed' : 'refused',
                   'the embedded PEP') +
        kit.tile(json.enforcement.bias, 'PEP bias') +
        '</div>' +
        '<p>' + esc(json.enforcement.why) + '</p>' +
        '<table><tr><th>Applicable policies</th><td>' + policies +
        '</td></tr>' +
        '<tr><th>Obligations</th><td>' +
        (json.obligations.length ? json.obligations.map(esc).join(', ')
                                 : '<em>none</em>') + '</td></tr>' +
        '<tr><th>Advice</th><td>' +
        (json.advice.length ? json.advice.map(esc).join(', ')
                            : '<em>none</em>') + '</td></tr>' +
        '<tr><th>Status</th><td><code>' +
        esc((json.status || {}).code || '') + '</code>' +
        ((json.status || {}).message
          ? '<div class="sub">' + esc(json.status.message) + '</div>' : '') +
        '</td></tr></table>';
    }

    const explain = kit.note(
      '<p>The <strong>decision</strong> is the PDP&rsquo;s and the ' +
      '<strong>outcome</strong> is the PEP&rsquo;s, and this page shows ' +
      'both because they are not the same answer. A deny-biased PEP ' +
      'refuses an Indeterminate and a permit-biased one allows it; the two ' +
      'agree on every Permit and every Deny. When somebody says a policy ' +
      '&ldquo;is not working&rdquo;, it is nearly always because only one ' +
      'of these two was being looked at.</p>' +
      '<p>Nothing here asserts an attribute in the request beyond the ' +
      'subject, the action and the resource — so anything else the policy ' +
      'needs comes from the <strong>PIP</strong>, off that person&rsquo;s ' +
      'directory entry. That is what makes this a test of the whole path ' +
      'rather than of the engine alone.</p>',
      'What you are looking at');
    return explain + form + answer;
  }
}

export = XacmlPage;
