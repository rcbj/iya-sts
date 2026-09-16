'use strict';
//
// File: xacml_admin.ts
//
// ---------------------------------------------------------------------------
// THE POLICY ADMINISTRATION POINT: THE CONSOLE PAGES.
//
//   /admin/xacml            settings, and what the PDP currently decides with
//   /admin/xacml/policies   the repository — enable, disable, choose the root,
//                           delete, and create from a template
//   /admin/xacml/editor     THE GUIDED EDITOR
//   /admin/xacml/peps       the remote enforcement points (phase five)
//   /admin/xacml/decide     ask the PDP a question and see the answer
//   /admin/xacml/monitor    the decision counters, filed under Monitoring
//
// Drawn HERE rather than in `admin-ui/admin.ts`, the way `ldap/ldap_server.js`
// draws its `/admin/ldap/*` pages: a console page is a `path` and a
// `label` in that file's `SECTIONS` whoever builds the body. What crosses is
// `admin.respond()` for the shell, `admin.configFormsFor()` for the settings
// block and `admin.respondToAction()` for a form POST — three functions rather
// than a copy of the console.
//
// ---------------------------------------------------------------------------
// EVERY CONTROL ON THESE PAGES IS A PLAIN FORM POST, AND THE EDITOR IS THE
// REASON THAT IS WORTH ARGUING RATHER THAN ASSUMING.
//
// `app.js` sets `script-src 'none'` for the whole service and
// `admin-ui/CLAUDE.md` refuses a script NINE times over — twice for pages that
// draw graphs — under a rule that says the argument has to be MADE each time
// and that "the page next door does it" is not one. The test it sets is
// whether the page CANNOT work without a script.
//
// A policy editor can. So the "pick the next valid element" dropdowns are a
// `<select>` per node whose `<option>`s were computed on the server by
// `xacml_editor.ts`, and choosing one is a POST that re-renders the page.
//
// WHAT THAT COSTS: a round trip per element. Building a five-rule policy by
// hand is perhaps forty POSTs, and this page says so rather than leaving
// somebody to discover it. The templates are the answer — they are the first
// twenty clicks already made.
//
// WHAT IT BUYS, and this is the half that is not a consolation: the menu is
// computed by the same process that will validate the policy, against the real
// function library, so THE EDITOR CANNOT OFFER SOMETHING THE VALIDATOR WILL
// REFUSE. A browser-side editor would have needed a second copy of the grammar
// shipped to the page, and a second copy of a grammar is the thing this whole
// directory is arranged to avoid.
//
// ---------------------------------------------------------------------------
// THE EDITOR HOLDS NO SESSION STATE, AND THAT IS DELIBERATE.
//
// The draft IS the stored policy. Every edit loads the document from
// `ou=policies`, applies one change, serializes it and writes it back. There
// is no "unsaved" state anywhere, which means there is nothing to lose when a
// browser is closed, nothing to expire, and no second copy of a policy that
// could disagree with the stored one.
//
// What it costs is that editing is LIVE: a policy being edited is the policy
// the PDP is deciding with, and a half-finished rule affects decisions
// immediately. The page says so. The way to avoid it is to leave a policy
// disabled while working on it, and the editor puts that control at the top
// rather than making somebody find it on another page.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1):
//
//   * **`XacmlAdmin` TAKES EVERY MODULE IT USES THROUGH ITS CONSTRUCTOR**
//     (`XacmlAdminDeps`): the logger and the body parser, the settings, the
//     audit log, the error-code registry, the console, the engine's model and
//     XML modules, and the family's libraries. The three modules this file has
//     always required LAZILY — `./xacml`, `./xacml_role_pep` and
//     `./xacml_access_pep` — arrive as LOADERS and are still required only at
//     the moment they are needed (see *LAZY REQUIRES* below and the comment in
//     `decideJson()`).
//   * **`registerRoutes(app)` HOLDS EVERY ROUTE, IN THE ORIGINAL ORDER**, and
//     `installSlot()` fills `admin.setXacmlPages()`, which the original did
//     after the last route.
//   * **THE MODULE STILL EXPORTS EVERY OLD NAME**, bound to a TRANSITIONAL
//     instance built at the bottom from the real modules, which registers the
//     routes and fills the slot at load, in that order — so the require order,
//     the route order and the slot are what they were. It goes when the
//     composition root exists. `XacmlAdmin` is exported beside it for that
//     root, and the three action lists are its static members as well.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import config = require('../common/config');
import audit = require('../common/audit');
// The error-code registry (a leaf). An action's refusal carries its code as a
// NON-ENUMERABLE mark on the result object, so the console handlers below and
// `/admin-api` mark their response from it and no JSON body can carry it out.
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import model = require('./xacml_model');
import xml = require('./xacml_xml');
import store = require('./xacml_store');
import editor = require('./xacml_editor');
import templates = require('./xacml_templates');
import validate = require('./xacml_validate');
import alfa = require('./xacml_alfa');
import pip = require('./xacml_pip');
import peps = require('./xacml_pep_registry');
import pepHttp = require('./xacml_pep_http');
// A remote PEP's HTTPS listener certificate (2026-09-13). A LIBRARY over
// `common/pki.js` and the register above, registering nothing.
import pepTls = require('./xacml_pep_tls');
import pki = require('../common/pki');
import monitor = require('./xacml_monitor');

type Req = import('express').Request;
type Res = import('express').Response;
type Handler = (req: Req, res: Res) => unknown;

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
}

// What an action answers: `ok`, and a sentence either way. The rest depends on
// the action (a listener certificate's issue carries the certificate).
type ActionResult = Record<string, any>;

// The parts of `xacml.ts` that `decideJson()` asks.
interface XacmlRoutes {
  decide(request: object): any;
  enforce(answer: object): any;
}

// The embedded PEPs' reports about their own policies.
interface RolePep {
  issuancePolicyState(): object;
}
interface AccessPep {
  accessPolicyState(): object;
}

interface XacmlAdminDeps {
  log: typeof helpers.log;
  parseBody(req: Req): any;
  config: typeof config;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  // The console: loosely typed, because it is a very large JavaScript module
  // and this file reads a dozen of its members, some of them optional slots.
  admin: any;
  esc(value: unknown): string;
  model: any;
  xml: any;
  store: any;
  editor: any;
  templates: any;
  validate: any;
  alfa: any;
  pip: any;
  peps: any;
  pepHttp: any;
  pepTls: any;
  pki: any;
  monitor: any;
  // Required at the moment they are needed, never at load.
  loadXacml(): XacmlRoutes;
  loadRolePep(): RolePep;
  loadAccessPep(): AccessPep;
}

// ---------------------------------------------------------------------------
// THE THREE ACTIONS BEHIND THAT PAGE.
//
// Named `-pep` rather than reusing `enable`, `disable` and `delete`, and that
// is not decoration: `combinedAction()` dispatches on the action name across
// all three of this family's POST endpoints, so a second `disable` would be
// ambiguous between a policy and a PEP — and the ambiguity would resolve
// silently in favour of whichever list was tested first.
// ---------------------------------------------------------------------------
// `issue-pep-certificate` (2026-09-13) is the fourth and the only one that is
// ASYNCHRONOUS — generating a key pair and signing a certificate are both
// promises — so `pepAction()` answers a PROMISE for it and a plain result for
// the other three, and every caller settles it with `Promise.resolve()`. The
// three synchronous ones stay synchronous because two in-process test files
// call `combinedAction()` without awaiting.
const PEP_ACTIONS = ['enable-pep', 'disable-pep', 'forget-pep',
                     'issue-pep-certificate'];

// ---------------------------------------------------------------------------
// THE ACTIONS BEHIND THAT PAGE.
//
// The refusal sentence names every action, and the count comes from the list
// rather than being written out — `ssf/CLAUDE.md` records that this exact
// sentence is READ by two tests, and a handler that phrases it its own way
// turns those checks off with nothing failing.
// ---------------------------------------------------------------------------
const POLICY_ACTIONS = ['enable', 'disable', 'set-root', 'delete',
                        'create-from-template', 'import-alfa'];

// The editor's actions: the third list `combinedAction()` routes on — see the
// comment above `installSlot()`.
const EDITOR_ACTIONS = ['remove', 'add-rule', 'add-target-anyof', 'add-allof',
                        'add-match', 'edit-match', 'edit-rule', 'edit-policy',
                        'add-condition', 'set-expression-apply',
                        'set-expression-value', 'set-expression-designator',
                        'set-expression-selector', 'set-expression-function',
                        'set-expression-variable', 'add-argument',
                        'edit-apply', 'edit-value', 'edit-designator',
                        'edit-selector', 'edit-function',
                        'add-rule-obligation', 'add-policy-obligation',
                        'add-rule-advice', 'add-policy-advice',
                        'edit-obligation', 'add-assignment', 'edit-assignment',
                        'add-variable', 'edit-variable',
                        // THE POLICY SET'S FOUR. `add-policy` and `add-rule`
                        // are not two spellings of one move: a set holds
                        // policies and a policy holds rules, and the editor
                        // offered only the second until a policy set could be
                        // edited at all — which is how it came to accept a
                        // rule on a set, report it added, and write a document
                        // without it.
                        'add-policy', 'add-policyset',
                        'add-policy-reference', 'add-policyset-reference',
                        'edit-reference'];

class XacmlAdmin {
  static readonly PEP_ACTIONS = PEP_ACTIONS;
  static readonly POLICY_ACTIONS = POLICY_ACTIONS;
  static readonly EDITOR_ACTIONS = EDITOR_ACTIONS;

  constructor(private readonly deps: XacmlAdminDeps) {
    deps.log.debug("Entering XacmlAdmin.constructor().");
    deps.log.debug("Leaving XacmlAdmin.constructor().");
  }

  // ---------------------------------------------------------------------------
  // SMALL RENDERING HELPERS. Local rather than exported from admin.js, because
  // they are about POLICIES rather than about the console.
  // ---------------------------------------------------------------------------
  private select(name: string, options: any[], selected: unknown,
                 extra?: string): string {
    const { log, esc } = this.deps;
    log.debug("Entering XacmlAdmin.select().");
    const body = options.map(function (one) {
      const value = one.value === undefined ? one.uri : one.value;
      return '<option value="' + esc(value) + '"' +
        (String(value) === String(selected) ? ' selected' : '') + '>' +
        esc(one.label) + '</option>';
    }).join('');
    log.debug("Leaving XacmlAdmin.select().");
    return '<select name="' + esc(name) + '"' + (extra || '') + '>' + body +
      '</select>';
  }

  private hidden(name: string, value: unknown): string {
    const { log, esc } = this.deps;
    log.debug("Entering XacmlAdmin.hidden().");
    log.debug("Leaving XacmlAdmin.hidden().");
    return '<input type="hidden" name="' + esc(name) + '" value="' +
      esc(value === null || value === undefined ? '' : value) + '">';
  }

  private textField(name: string, value: unknown, size?: number): string {
    const { log, esc } = this.deps;
    log.debug("Entering XacmlAdmin.textField().");
    log.debug("Leaving XacmlAdmin.textField().");
    return '<input type="text" name="' + esc(name) + '" value="' +
      esc(value === null || value === undefined ? '' : value) + '"' +
      (size ? ' size="' + size + '"' : '') + '>';
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml — SETTINGS AND WHAT THE PDP DECIDES WITH.
  // ---------------------------------------------------------------------------
  overviewJson(): Record<string, any> {
    const { log, config, admin, store, pip } = this.deps;
    log.debug('Entering XacmlAdmin.overviewJson().');
    const rows = store.all();
    const root = store.root();
    const json = {
      enabled: config.value('xacml.enabled') !== false,
      pepBias: config.value('xacml.pepBias'),
      policies: rows.length,
      enabledPolicies: rows.filter(function (one) {
        return one.enabled;
      }).length,
      root: root ? root.name : null,
      pipAvailable: pip.available(),
      // `configSettingsJson()` and NOT `protocolSettingsJsonFor()`. The second
      // is keyed by admin.js's own PROTOCOL_SETTINGS_PAGES table and throws for
      // a path that table does not carry — which is right for the pages that
      // file generates and wrong for one drawn here. It cost a 500 on this page
      // and nothing else, because it is the only caller outside that table.
      settings: admin.configSettingsJson
        ? admin.configSettingsJson('/admin/xacml') : null
    };
    log.debug('Leaving XacmlAdmin.overviewJson().');
    return json;
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml/policies — THE REPOSITORY.
  // ---------------------------------------------------------------------------
  policiesJson(): Record<string, any> {
    const self = this;
    const { log, store, templates, validate } = this.deps;
    log.debug('Entering XacmlAdmin.policiesJson().');
    const root = store.root();
    const rows = store.all().map(function (row) {
      const view = { name: row.name, policyId: row.id, kind: row.kind,
                     version: row.version, enabled: row.enabled,
                     isRoot: !!(root && root.name === row.name),
                     combiningAlgId: row.combiningAlgId,
                     description: row.description, problems: [] };
      try {
        view.problems = validate.problemsIn(store.parseDocument(row.document));
      } catch (error) {
        log.debug('Caught in XacmlAdmin.policiesJson(): ' +
                  ((error && error.message) || error));
        view.problems = [error.message];
      }
      return view;
    });
    log.debug('Leaving XacmlAdmin.policiesJson(). ' + rows.length +
              ' policy(ies).');
    return { root: root ? root.name : null, policies: rows,
             templates: templates.catalogue(),
             serviceOwn: self.serviceOwnPolicies() };
  }

  // ---------------------------------------------------------------------------
  // THE TWO POLICIES THIS SERVICE DECIDES ITS OWN BOUNDARIES WITH, WHICH ARE
  // NOT IN THE REPOSITORY AND THEREFORE APPEARED NOWHERE IN THIS CONSOLE
  // (2026-09-06).
  //
  // Everything else on these pages is a row in `ou=policies`, and until this
  // date so was everything these pages SAID. That left the most misleading page
  // in the service: a reader opened the editor, saw `seeded-rbac` alone and
  // marked *root*, and reasonably concluded it was what the PDP decides with.
  // It is the one document on that page that decides nothing this service
  // enforces.
  //
  // The two that do are BUILT IN and CALLED rather than seeded —
  // `xacml_role_pep.ts`'s header argues why at length, and the short version is
  // that `ou=policies` is per realm, so a policy seeded once in the default
  // realm leaves every realm created later unable to decide anything. **THE FIX
  // IS TO SAY SO, NOT TO SEED THEM**: seeding is the thing that argument rules
  // out, and a reader who is told where the document comes from can create an
  // override from the same template in one click.
  //
  // ---------------------------------------------------------------------------
  // LAZY REQUIRES, AND BOTH HALVES OF THAT ARE DELIBERATE.
  //
  // It is the pattern this file already uses for `./xacml` (see the editor's
  // POST handler), and here it matters more. Requiring `xacml_role_pep.ts`
  // FILLS `common/issuance_gate.js`'s decider and requiring
  // `xacml_access_pep.ts` ARMS `common/access_gate.ts` — so a top-level require
  // in this file would arm both gates from a CONSOLE module, which is precisely
  // the hazard `admin.js`'s `setRolePreviewer()` slot exists to avoid: a
  // process holding the console and not `xacml/xacml.ts` would gate the whole
  // service with half this family present.
  //
  // It is also free. `xacml/xacml.ts` requires this file at 23c and both PEPs
  // immediately after it, so by the time any route here can be reached both are
  // in `require.cache` and this is a lookup. And it keeps that module's stated
  // arrangement — the pages before the PEPs, "for no technical reason at all,
  // because the pages are what an administrator fixes a refusal with" — which a
  // top-level require here would silently reverse.
  // ---------------------------------------------------------------------------
  private serviceOwnPolicies(): Record<string, any>[] {
    const { log, loadRolePep, loadAccessPep } = this.deps;
    log.debug('Entering XacmlAdmin.serviceOwnPolicies().');
    const rolePep = loadRolePep();
    const accessPep = loadAccessPep();
    const out = [
      Object.assign({
        key: 'issuance',
        label: 'Issuance',
        decides: 'whether this service issues anything at all — the nine ' +
                 'issuance sites: a session, an access token, an ID Token, a ' +
                 'refresh token, an authorization code, a SAML assertion, a ' +
                 'WS-Federation token, a WS-Trust token and a Kerberos ticket.',
        asked: '`common/issuance_gate.js`, from all nine',
        remote: false
      }, rolePep.issuancePolicyState()),
      Object.assign({
        key: 'access',
        label: 'Access control',
        decides: 'whether a subject reaches a gated surface — the admin ' +
                 'console, the management API, the User Portal, SCIM and the ' +
                 'SPIRE Server API.',
        // ALL FIVE, and each asks AFTER its own check rather than instead of
        // it. This sentence said "two of five" for a day and said "all five"
        // wrongly before that, so it names the exception rather than a count.
        asked: '`common/access_gate.ts` — from the admin console, the User ' +
               'Portal, SCIM, the SPIRE Server API, and the management API ' +
               'in PRODUCT MODE (that surface is open in development, so ' +
               'there is no subject to decide about).',
        remote: false
      }, accessPep.accessPolicyState())
    ];
    log.debug('Leaving XacmlAdmin.serviceOwnPolicies(). ' + out.length +
              ' policy(ies).');
    return out;
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
  private serviceOwnEditorNote(rows: any[]): string {
    const { log, admin } = this.deps;
    log.debug('Entering XacmlAdmin.serviceOwnEditorNote().');
    const overridden = (rows || []).filter(function (one) {
      return one.entry;
    }).length;
    log.debug('Leaving XacmlAdmin.serviceOwnEditorNote(). ' + overridden +
              ' overridden.');
    return admin.note(
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

  private renderServiceOwnPolicies(rows: any[], writable: boolean): string {
    const self = this;
    const { log, admin, esc } = this.deps;
    log.debug('Entering XacmlAdmin.renderServiceOwnPolicies().');
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
    log.debug('Leaving XacmlAdmin.renderServiceOwnPolicies(). ' + rows.length +
              ' row(s).');
    return '<h2 id="service-own">What this service decides its own ' +
      'boundaries with</h2>' +
      admin.warn(
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
  // /admin/xacml/peps — THE REMOTE ENFORCEMENT POINTS (phase five).
  //
  // A LIST AND THREE CONTROLS, and it is worth saying what it is NOT before
  // what it is: it is not a control panel for those processes. Nothing on this
  // page reaches into another process. Disabling a PEP here stops this service
  // NUDGING it and takes it off the distribution the console reports; it does
  // not stop it enforcing, because a remote PEP holds its own copy of the
  // engine and its own copy of the policy and will go on deciding with them.
  // The page says that out loud on every disabled row, because a control
  // labelled "disable" that leaves the thing running is the single most
  // misleading thing a console can do.
  //
  // WHAT IT IS FOR is the question a distributed authorization deployment
  // actually has, which is not "is the PDP up" but **"is everybody deciding
  // with the same policy"**. Three columns answer it: whether the PEP is
  // CURRENT (a comparison this service performs between the sync token it holds
  // and the one the repository has now), whether it is STALE (nothing heard for
  // `xacml.pepStaleAfterS`), and what happened to the last nudge. A PEP that is
  // stale AND current is fine and idle; one that is fresh and not current is
  // mid-pull; one that is stale and not current is the state worth seeing, and
  // it is invisible from every other page in this console.
  // ---------------------------------------------------------------------------
  pepsJson(): Record<string, any> {
    const { log, config, peps, pepHttp, pepTls, pki } = this.deps;
    log.debug('Entering XacmlAdmin.pepsJson().');
    const rows = peps.all().map(function (row) {
      const view = Object.assign({}, row);
      // THE NOTIFY URL'S PROBLEM IS COMPUTED RATHER THAN REMEMBERED, so that
      // changing `xacml.pepNotifyAllowedHosts` changes what this page says
      // about a PEP registered an hour ago. A stored verdict would have been
      // right when it was written and wrong from then on.
      view.notifyProblem = pepHttp.urlProblem(row.notifyUrl);
      // THE LISTENER CERTIFICATE THIS REALM ISSUED IT, read from the
      // certificate register rather than stored on the row — the register is
      // where `pki.js` keeps what an Issuing CA certified, and a copy on
      // `ou=peps` would be a second answer that went stale at the first
      // reissue. Public only; the key was handed over once. The chain is left
      // off because it is the realm's and `GET /admin-api/pki` has it.
      const certificate = pepTls.certificateOf(row.name);
      if (certificate) {
        delete certificate.chainPem;
      }
      view.listenerCertificate = certificate;
      return view;
    });
    const json = {
      enabled: config.value('xacml.remotePeps') !== false,
      syncToken: peps.syncToken(),
      staleAfterS: peps.staleAfterS(),
      requiresCertificate:
        config.value('xacml.pepRequireCertificate') !== false,
      notify: {
        on: pepHttp.notifyAllowed(),
        allowedHosts: pepHttp.allowedHosts(),
        allowInsecure: pepHttp.allowInsecure(),
        timeoutMs: pepHttp.timeoutMs()
      },
      peps: rows,
      // EVERY OTHER REALM THAT HOLDS ONE, and it is in the JSON rather than
      // only in the markup so that `GET /admin-api/xacml/peps` answers the same
      // question the page does (rule 7). A caller reading an empty `peps` array
      // has exactly the ambiguity the page had: this says which of the two
      // empties it is looking at. Empty on the ordinary service, where the
      // default realm is the only realm.
      elsewhere: peps.elsewhere(),
      listenerCertificates: {
        useCase: pepTls.USE_CASE,
        keyAlgorithms: pki.TLS_SERVER_KEY_ALGS.slice(),
        defaultKeyAlg: pki.DEFAULT_TLS_SERVER_KEY_ALG
      },
      current: rows.filter(function (row) {
        return row.current;
      }).length,
      stale: rows.filter(function (row) {
        return row.stale;
      }).length
    };
    log.debug('Leaving XacmlAdmin.pepsJson(). ' + rows.length +
              ' registered PEP(s).');
    return json;
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
  private noPepsHere(where: any[]): string {
    const { log, esc } = this.deps;
    log.debug('Entering XacmlAdmin.noPepsHere().');
    const shared = 'That does not mean none is running: registering is not ' +
      'what lets a PEP enforce, and one that only ever pulls ' +
      '<code>/xacml/pep/policies</code> works perfectly and never appears ' +
      'here.';
    if (!where.length) {
      log.debug('Leaving XacmlAdmin.noPepsHere(). None anywhere.');
      return 'No remote Policy Enforcement Point has registered, <strong>in ' +
        'this realm or in any other</strong>. ' + shared;
    }
    const list = where.map(function (one) {
      return '<a href="/realm/' + esc(one.id) + '/admin/xacml/peps"><code>' +
        esc(one.id) + '</code></a> (' + one.count + ')';
    }).join(', ');
    log.debug('Leaving XacmlAdmin.noPepsHere(). ' + where.length +
              ' elsewhere.');
    return 'No remote Policy Enforcement Point has registered <strong>in ' +
      'this realm</strong> &mdash; but ' + where.length + ' other realm' +
      (where.length === 1 ? '' : 's') + ' hold' +
      (where.length === 1 ? 's' : '') +
      ' one: ' + list + '. <strong>The register is per realm</strong>, like ' +
      'the policy repository it serves, so a PEP that registered against ' +
      '<code>/realm/&lt;id&gt;</code> is listed there and nowhere ' +
      'else. ' + shared;
  }

  // ===========================================================================
  // /admin/xacml/monitor — WHAT AUTHORIZATION IS ACTUALLY DOING.
  //
  // Every other page in this family is about CONFIGURATION: what policies
  // exist, what one of them says, what the PDP would decide about a subject you
  // type in. This is the only one about TRAFFIC — how many decisions are being
  // made, by which enforcement point, and how many of them are refusals — which
  // is the question somebody has when authorization is misbehaving and the
  // question nothing here could answer.
  //
  // SO IT IS FILED UNDER **Monitoring** AND NOT UNDER Protocols > XACML, since
  // 2026-09-06. That is the sentence above read as a placement rather than as a
  // remark: this section's heading is "what this service has done", which is
  // exactly what this page reports, and the five configuration pages of this
  // family are somewhere else because they answer a different question. **The
  // path did not move and must not** — it is `/admin/xacml/monitor` still,
  // drawn by this module, because a console page is a `path` and a `label` in
  // `admin-ui/admin.ts`'s `SECTIONS` whoever builds the body; the eight
  // `/admin/ldap/*` pages sit in the Directory section on the same terms. Two
  // things follow for anybody editing this route. Its `active` is its OWN path,
  // so the sidebar bolds Monitoring and the crumb takes the label from `NAV`
  // (`XACML decisions`) rather than from here; and it passes NO `up`, because
  // it is a page of a section rather than a drill-down of `/admin/xacml` — the
  // five pages that ARE in that group still pass one.
  //
  // TWO SECTIONS, and the split is the reader's rather than the code's:
  //
  //   1. **GLOBAL.** Policies, enforcement points, decisions, allows, declines.
  //      What you look at first and what tells you whether to look further.
  //   2. **PER ENFORCEMENT POINT.** Every PEP — the three EMBEDDED ones in this
  //      process and every REMOTE one that has registered — with its own
  //      figures, its bias, and what it guards.
  //
  // ---------------------------------------------------------------------------
  // THE NUMBERS COME FROM TWO KINDS OF EVIDENCE AND THE PAGE NEVER PRETENDS
  // OTHERWISE.
  //
  // The embedded rows are things this process DID and counted as it did them.
  // The remote rows are things another process says it did, on a heartbeat, in
  // its own memory. Those are not the same claim, and a page that added them
  // into one number and stopped there would be asserting this service watched
  // something it did not watch.
  //
  // So the totals are given three ways — here, remote, and the sum, labelled as
  // arithmetic — and every remote row says on its face that the figures are
  // reported. `xacml_monitor.ts`'s header argues the whole distinction; this
  // page renders it.
  //
  // ---------------------------------------------------------------------------
  // WHY "DECISIONS" AND "ALLOWS" ARE TWO COLUMNS AND NOT ONE SUM.
  //
  // XACML has four decisions and a PEP has two outcomes, and the mapping
  // between them is the PEP's BIAS — so a deny-biased PEP refuses a
  // NotApplicable and a permit-biased one allows it, from one identical
  // decision. On top of that, an obligation the PEP cannot discharge turns a
  // Permit into a refusal (section 7.2), which is the one enforcement outcome
  // that looks like a bug from the client side and is the specification
  // working.
  //
  // That means `allowed` is not `permit`, and a monitoring page that showed
  // either one alone would be wrong for whichever question the reader had. Both
  // are drawn, next to each other, with the four decisions broken out on every
  // row that has them.
  //
  // ---------------------------------------------------------------------------
  // THERE IS NO RESET BUTTON, AND ITS ABSENCE IS A DECISION.
  //
  // A console that could zero its own monitoring would make every number on
  // this page a number somebody might have reset — and the durable record of a
  // refusal is the AUDIT LOG, which cannot be reset either. The counters are
  // since this process started, the page says so with the timestamp, and a
  // restart is the only thing that clears them.
  // ===========================================================================
  monitorJson(): Record<string, any> {
    const { log, store, peps, monitor } = this.deps;
    log.debug('Entering XacmlAdmin.monitorJson().');
    const rows = store.all();
    const root = store.root();
    const json = monitor.snapshot({
      total: rows.length,
      enabled: rows.filter(function (one) { return one.enabled; }).length,
      root: root ? root.name : null
    });
    // WHERE THE REMOTE ROWS ARE, WHEN THERE ARE NONE HERE. Added beside the
    // counters rather than inside `monitor.snapshot()` on purpose: that module
    // is a LEAF that may never require the console or the registry — its header
    // argues the route-order reason — and this is a question about the REGISTER
    // rather than about the counts. `/admin-api/xacml/monitor` carries it for
    // the reason the peps resource does: an empty remote list has two causes.
    json.elsewhere = peps.elsewhere();
    log.debug('Leaving XacmlAdmin.monitorJson(). ' + json.elsewhere.length +
              ' other realm(s) hold a remote PEP.');
    return json;
  }

  // A count that is a proportion of another, as "n (p%)". Zero of zero is drawn
  // as a dash rather than as "0 (0%)" or NaN: nothing has happened yet, and a
  // percentage of nothing is not a fact about this service.
  private share(n: number, of: number): string {
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.share().");
    if (!of) {
      log.debug("Leaving XacmlAdmin.share().");
      return n ? String(n) : '&mdash;';
    }
    log.debug("Leaving XacmlAdmin.share().");
    return String(n) + ' <span class="sub">(' +
           Math.round((n / of) * 100) + '%)</span>';
  }

  // The four decisions on one row, or a dash where the row does not have them —
  // which is every REMOTE row, because a remote PEP reports what it ENFORCED
  // and the breakdown by PDP decision is known only to the process that
  // evaluated.
  private decisionCells(row: any): string {
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.decisionCells().");
    if (row.permit === null || row.permit === undefined) {
      log.debug("Leaving XacmlAdmin.decisionCells().");
      return '<td colspan="4" class="sub">not reported &mdash; a remote PEP ' +
             'sends what it enforced, and only the process that EVALUATED ' +
             'knows which of the four decisions each was</td>';
    }
    log.debug("Leaving XacmlAdmin.decisionCells().");
    return '<td class="num state-valid">' + row.permit + '</td>' +
      '<td class="num state-revoked">' + row.deny + '</td>' +
      '<td class="num">' + row.notApplicable + '</td>' +
      '<td class="num state-expired">' + row.indeterminate + '</td>';
  }

  // The allowed/refused pair, or the EMPTY cell that says this asker never
  // enforced anything. `/xacml/pdp` is the one row that gets it, and the
  // distinction is the point: a zero would read as "it refused nothing".
  private enforcementCells(row: any): string {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.enforcementCells().");
    if (!row.enforces || row.allowed === null || row.allowed === undefined) {
      log.debug("Leaving XacmlAdmin.enforcementCells().");
      return '<td colspan="2" class="sub">nothing was enforced here &mdash; ' +
             'this service produced the decision and somebody else\'s PEP ' +
             'acted on it, in their process</td>';
    }
    log.debug("Leaving XacmlAdmin.enforcementCells().");
    return '<td class="num state-valid">' +
      self.share(row.allowed, row.decisions) +
      '</td><td class="num state-revoked">' +
      self.share(row.refused, row.decisions) +
      '</td>';
  }

  private monitorRow(row: any): string {
    const self = this;
    const { log, esc } = this.deps;
    log.debug("Entering XacmlAdmin.monitorRow().");
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
    log.debug("Leaving XacmlAdmin.monitorRow().");
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

  // A plain result, or a promise of one for `issue-pep-certificate`.
  pepAction(body?: any): any {
    const { log, audit, errorCodes, peps, pepTls } = this.deps;
    log.debug('Entering XacmlAdmin.pepAction(). action=' + (body || {}).action);
    const action = String((body || {}).action || '');
    if (action === 'issue-pep-certificate') {
      log.debug('Leaving XacmlAdmin.pepAction(). Issuing a listener ' +
                'certificate.');
      return pepTls.issue(body);
    }
    const name = String((body || {}).name || '');
    if (!name) {
      log.debug('Leaving XacmlAdmin.pepAction(). No name.');
      return errorCodes.mark({ ok: false,
                               why: 'Which registered PEP? Send `name`.' },
                             'STS-XACML-0038');
    }
    const row = peps.read(name);
    if (!row) {
      log.debug('Leaving XacmlAdmin.pepAction(). Not registered.');
      return errorCodes.mark({ ok: false,
               why: 'No Policy Enforcement Point is registered as "' + name +
                    '". The register is ou=peps in the embedded directory ' +
                    'and GET /admin-api/xacml/peps lists it.' },
               'STS-XACML-0038');
    }
    if (action === 'forget-pep') {
      const gone = peps.remove(name);
      audit.audit({ action: 'xacml.pep.forget', actor: '', protocol: 'XACML',
                    detail: 'Removed the register row for remote PEP "' +
                            name + '".' });
      log.debug('Leaving XacmlAdmin.pepAction(). Removed.');
      return gone
        ? { ok: true,
            what: '"' + name + '" is no longer in the register. IT MAY STILL ' +
                  'BE ENFORCING — this removed a row, not a process, and a ' +
                  'PEP that pulls again simply registers again. What has ' +
                  'changed is that this service will not nudge it in the ' +
                  'meantime.' }
        : errorCodes.mark({ ok: false,
                            why: 'The directory would not remove it.' },
                          'STS-XACML-0027');
    }
    const on = action === 'enable-pep';
    const written = peps.setEnabled(name, on);
    if (!written) {
      log.debug('Leaving XacmlAdmin.pepAction(). The directory refused it.');
      return errorCodes.mark({ ok: false,
                               why: 'The directory refused the change.' },
                             'STS-XACML-0027');
    }
    audit.audit({ action: 'xacml.pep.' + (on ? 'enable' : 'disable'), actor: '',
                  protocol: 'XACML',
                  detail: 'Remote PEP "' + name + '" is ' +
                          (on ? 'nudged again.' : 'no longer nudged.') });
    log.debug('Leaving XacmlAdmin.pepAction(). ' +
              (on ? 'Enabled.' : 'Disabled.'));
    return { ok: true,
             what: on
               ? '"' + name + '" is nudged again when the repository changes.'
               : '"' + name + '" is no longer nudged. IT HAS NOT STOPPED ' +
                 'ENFORCING: it holds its own copy of the engine and of the ' +
                 'policy, and it will go on pulling and deciding. What this ' +
                 'changed is that this service no longer dials it, so it now ' +
                 'converges only on its own polling interval.' };
  }

  // ---------------------------------------------------------------------------
  // THE ISSUE, ANSWERED AS A PAGE AND NOT AS A REDIRECT.
  //
  // Every other control on this page 303s back with its sentence on the query
  // string, which is `respondToAction()`'s shape. This one carries a PRIVATE
  // KEY, and a private key on a query string is a private key in the browser
  // history, the access log and the next request's `Referer` — so the reply is
  // a 200 page drawn once, `no-store`, which is what `/admin/pki/person` does
  // for the same reason. A JSON caller gets `respondToAction()`'s JSON,
  // unchanged.
  // ---------------------------------------------------------------------------
  private issueFromConsole(req: Req, res: Res, body: any): void {
    const self = this;
    const { log, errorCodes, admin, esc } = this.deps;
    log.debug('Entering XacmlAdmin.issueFromConsole().');
    Promise.resolve(self.pepAction(body)).then(function (result) {
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0072');
      }
      if (/json/i.test(String(req.headers['content-type'] || ''))) {
        admin.respondToAction(req, res, '/admin/xacml/peps', result);
        log.debug('Leaving XacmlAdmin.issueFromConsole(). Answered JSON.');
        return;
      }
      const back = '<p><a class="btn" href="/admin/xacml/peps">Back to ' +
        'Remote PEPs</a></p>';
      if (!result.ok) {
        admin.respond(req, res, { ok: false }, 'Listener certificate',
                      '/admin/xacml/peps',
                      admin.warn(esc(String(result.why || '')),
                                 'That was refused') + back, '/admin/xacml');
        log.debug('Leaving XacmlAdmin.issueFromConsole(). Refused.');
        return;
      }
      res.set('Cache-Control', 'no-store');
      const page = admin.note('<p>' + esc(result.what) + '</p>') +
        '<table><tr><th>PEP</th><td><code>' + esc(result.pep) + '</code></td>' +
        '</tr><tr><th>Realm</th><td><code>' + esc(result.realm) +
        '</code></td>' +
        '</tr><tr><th>Serial</th><td><code>' + esc(result.serialHex) +
        '</code></td></tr><tr><th>Names</th><td>' +
        esc(result.dnsNames.concat(result.ipAddresses).join(', ')) +
        '</td></tr><tr><th>Valid until</th><td>' + esc(result.notAfter) +
        '</td></tr></table>' +
        admin.warn(
          '<p>This is the only time this service will show you this key. It ' +
          'is not on the PEP&rsquo;s entry and nothing in this console or in ' +
          '<code>/admin-api</code> opens it again. Save it as the file ' +
          '<code>PEP_HTTPS_KEY</code> names.</p>' +
          '<pre>' + esc(result.privateKeyPem) + '</pre>',
          'The private key, once') +
        '<p>The certificate followed by its chain (the Issuing CA and this ' +
        'realm&rsquo;s Intermediate) &mdash; the file ' +
        '<code>PEP_HTTPS_CERT</code> names:</p>' +
        '<pre>' + esc(result.fullChainPem) + '</pre>' +
        '<p>The anchor a client of that listener installs &mdash; this ' +
        'service&rsquo;s Root CA, which the chain deliberately leaves ' +
        'out:</p><pre>' + esc(result.anchorPem) + '</pre>' + back;
      const json = Object.assign({}, result);
      delete json.privateKeyPem;
      admin.respond(req, res, json, 'Listener certificate', '/admin/xacml/peps',
                    page, '/admin/xacml');
      log.debug('Leaving XacmlAdmin.issueFromConsole(). Issued.');
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-XACML-0072') + 'xacml: issuing a remote ' +
                'PEP listener certificate threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-XACML-0072');
      admin.respond(req, res, { ok: false }, 'Listener certificate',
                    '/admin/xacml/peps',
                    admin.warn(esc('That failed: ' +
                                   ((e && e.message) || e)),
                               'That was refused'), '/admin/xacml');
      log.debug('Leaving XacmlAdmin.issueFromConsole(). It threw.');
    });
  }

  policyAction(body?: any, req?: Req | null): ActionResult {
    const self = this;
    const { log, audit, errorCodes, xml, store, templates, alfa } = this.deps;
    log.debug('Entering XacmlAdmin.policyAction(). action=' +
              (body || {}).action);
    const action = String((body || {}).action || '');
    const name = String((body || {}).name || '');

    if (POLICY_ACTIONS.indexOf(action) < 0) {
      log.debug('Leaving XacmlAdmin.policyAction(). Unknown action.');
      return errorCodes.mark({ ok: false,
               why: 'Unknown action "' + action + '". The ' +
                    self.numberWord(POLICY_ACTIONS.length) + ' are: ' +
                    POLICY_ACTIONS.join(', ') + '.' }, 'STS-XACML-0032');
    }

    if (action === 'import-alfa') {
      // ALFA IN, MODEL, XML OUT — which is the whole of what an ALFA compiler
      // is here, and is why this action is nine lines rather than a subsystem.
      // The document that gets STORED is XACML XML, because the store holds one
      // representation and a second would be a second thing to keep in step.
      let policy;
      try {
        policy = alfa.parse(String(body.alfa || ''));
      } catch (error) {
        log.debug('Caught in XacmlAdmin.policyAction(): ' +
                  ((error && error.message) || error));
        log.debug('Leaving XacmlAdmin.policyAction(). The ALFA would not ' +
                  'parse.');
        return errorCodes.mark({ ok: false, why: error.message },
                               'STS-XACML-0037');
      }
      const document = xml.writePolicy(policy);
      const isRoot = !store.root();
      const written = store.write(name || 'imported', document,
                                  { isRoot: isRoot, enabled: true,
                                    description: policy.description });
      if (!written.ok) {
        log.debug('Leaving XacmlAdmin.policyAction(). The store refused.');
        return written;
      }
      audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                    detail: 'Imported "' + (name || 'imported') +
                            '" from ALFA.' });
      log.debug('Leaving XacmlAdmin.policyAction(). Imported.');
      return { ok: true,
               what: 'Imported "' + (name || 'imported') + '" as ' + policy.id +
                     '.' + (isRoot
                       ? ' It is the root, because the repository had none.'
                       : '') };
    }

    if (action === 'create-from-template') {
      const answers = {};
      Object.keys(body || {}).forEach(function (key) {
        if (key.indexOf('p_') === 0) {
          answers[key.slice(2)] = body[key];
        }
      });
      const built = templates.build(String(body.template || ''), answers,
                                    { name: name || body.template });
      if (!built.ok) {
        log.debug('Leaving XacmlAdmin.policyAction(). The template refused.');
        return errorCodes.mark(built, 'STS-XACML-0036');
      }
      const document = xml.writePolicy(built.policy);
      // The FIRST policy in an empty repository becomes the root, because a
      // repository with a policy and no root decides nothing and the person who
      // just created one plainly meant it to be used.
      const isRoot = !store.root();
      const written = store.write(name || built.template.id, document,
                                  { isRoot: isRoot, enabled: true,
                                    description: built.policy.description });
      if (!written.ok) {
        log.debug('Leaving XacmlAdmin.policyAction(). The store refused.');
        return written;
      }
      audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                    detail: 'Created "' + (name || built.template.id) +
                            '" from the ' + built.template.id + ' template.' });
      log.debug('Leaving XacmlAdmin.policyAction(). Created.');
      return { ok: true,
               what: 'Created "' + (name || built.template.id) + '"' +
                     (isRoot
                       ? ' and made it the root, because the repository ' +
                         'had none.'
                       : '.') };
    }

    const existing = store.read(name);
    if (!existing) {
      log.debug('Leaving XacmlAdmin.policyAction(). No such policy.');
      return errorCodes.mark({ ok: false,
                               why: 'There is no policy called "' + name +
                                 '".' },
                             'STS-XACML-0033');
    }

    if (action === 'delete') {
      store.remove(name);
      audit.audit({ action: 'xacml.policy.delete', actor: '',
                    protocol: 'XACML', detail: 'Deleted "' + name + '".' });
      log.debug('Leaving XacmlAdmin.policyAction(). Deleted.');
      return { ok: true, what: 'Deleted "' + name + '".' +
               (existing.isRoot
                 ? ' It was the ROOT, so this repository now decides nothing ' +
                   'until another policy is made the root.' : '') };
    }

    const enabled = action === 'disable' ? false
      : (action === 'enable' ? true : existing.enabled);
    // SET-ROOT CLEARS THE OTHER ONE FIRST. `store.write()` refuses a second
    // root, so promoting a policy has to demote the incumbent — and doing it in
    // this order means a failure leaves the repository with no root rather than
    // with two, which is the recoverable one of the two bad states.
    if (action === 'set-root') {
      const current = store.root();
      if (current && current.name !== name) {
        store.write(current.name, current.document,
                    { isRoot: false, enabled: current.enabled,
                      description: current.description });
      }
    }
    const written = store.write(name, existing.document, {
      isRoot: action === 'set-root' ? true : existing.isRoot,
      enabled: enabled,
      description: existing.description
    });
    if (!written.ok) {
      log.debug('Leaving XacmlAdmin.policyAction(). The store refused.');
      return written;
    }
    audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                  detail: action + ' on "' + name + '".' });
    log.debug('Leaving XacmlAdmin.policyAction(). ' + action + '.');
    return { ok: true, what: action === 'set-root'
      ? '"' + name + '" is now the root policy.'
      : '"' + name + '" is now ' + (enabled ? 'enabled' : 'disabled') + '.' };
  }

  private numberWord(n: number): string {
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.numberWord().");
    const words = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven',
                   'eight', 'nine', 'ten'];
    log.debug("Leaving XacmlAdmin.numberWord().");
    return words[n] || String(n);
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml/editor — THE GUIDED EDITOR.
  //
  // One policy at a time, selected by `?policy=<name>`. The tree comes from
  // `xacml_editor.ts`; every row carries the menu of what may legally be added
  // UNDER it, computed by the same process that will validate the result.
  // ---------------------------------------------------------------------------
  // The ALFA rendering, or a note saying why there is none. Never throws: this
  // is a VIEW, and a policy whose ALFA cannot be produced is still a policy the
  // page has to draw.
  private alfaOf(policy: any): string {
    const { log, alfa } = this.deps;
    log.debug('Entering XacmlAdmin.alfaOf().');
    try {
      const text = alfa.write(policy);
      log.debug('Leaving XacmlAdmin.alfaOf(). ' + text.length + ' bytes.');
      return text;
    } catch (error) {
      log.debug('Caught in XacmlAdmin.alfaOf(): ' +
                ((error && error.message) || error));
      log.debug('Leaving XacmlAdmin.alfaOf(). Could not be rendered.');
      return '// This policy cannot be rendered as ALFA: ' + error.message;
    }
  }

  editorJson(name?: string): Record<string, any> {
    const self = this;
    const { log, store, editor, validate } = this.deps;
    log.debug('Entering XacmlAdmin.editorJson(). name=' + name);
    const rows = store.all();
    const chosen = name ? store.read(name) : (store.root() || rows[0] || null);
    if (!chosen) {
      log.debug('Leaving XacmlAdmin.editorJson(). Nothing to edit.');
      return { policies: rows.map(function (one) { return one.name; }),
               serviceOwn: self.serviceOwnPolicies(),
               policy: null };
    }
    let parsed = null;
    let problem = null;
    try {
      parsed = store.parseDocument(chosen.document);
    } catch (error) {
      log.debug('Caught in XacmlAdmin.editorJson(): ' +
                ((error && error.message) || error));
      problem = error.message;
    }
    const json = {
      policies: rows.map(function (one) { return one.name; }),
      // THE TWO POLICIES THIS CHOOSER CANNOT OFFER, carried so that a caller of
      // this resource is not left believing `policies` is the whole answer —
      // which is exactly what the PAGE used to leave a reader believing.
      serviceOwn: self.serviceOwnPolicies(),
      policy: { name: chosen.name, enabled: chosen.enabled,
                isRoot: chosen.isRoot, policyId: parsed ? parsed.id : null,
                // WHICH IT IS, because a PolicySet and a Policy take different
                // children and a caller of /admin-api/xacml/editor that could
                // not tell them apart would have to guess which actions apply.
                kind: parsed ? (parsed.kind || 'Policy') : null,
                version: parsed ? (parsed.version || '1.0') : null,
                combiningAlgId: parsed ? parsed.combiningAlgId : null,
                description: parsed ? parsed.description : '' },
      problem: problem,
      tree: parsed ? editor.tree(parsed).map(function (row) {
        return { path: row.path, depth: row.depth, kind: row.kind,
                 label: row.label, detail: row.detail,
                 options: editor.optionsAt(parsed, row.path) };
      }) : [],
      problems: parsed ? validate.problemsIn(parsed) : [problem],
      // NOT a static type problem and deliberately kept out of that list: it is
      // a schema rule (section 5.14) that changes no decision this PDP makes,
      // so it is reported on its own rather than mixed in with the errors that
      // stop a policy loading. See `xacml_editor.ts`'s `xpathVersionGaps()`.
      xpathVersionGaps: parsed ? editor.xpathVersionGaps(parsed) : [],
      document: chosen.document,
      // Emitted rather than stored. ALFA is a VIEW of the model here, not a
      // second copy of the policy — a stored ALFA text and a stored XML one
      // would be two documents that could disagree, which is the whole thing
      // this directory is arranged to avoid.
      alfa: parsed ? self.alfaOf(parsed) : null
    };
    log.debug('Leaving XacmlAdmin.editorJson(). ' + json.tree.length +
              ' node(s).');
    return json;
  }

  // A yes/no control that can say NO. It is a <select> and not a checkbox, and
  // that is the one piece of markup on this page worth arguing about: an
  // unchecked checkbox SENDS NOTHING, so a form carrying one could never turn
  // MustBePresent off — the handler cannot tell "unchecked" from "this form
  // does not edit that field", and it has to keep the value for the second case
  // or every other form on the row would silently clear it. Two states that
  // must both be sendable is exactly what a select is for.
  private yesNo(name: string, value: unknown): string {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.yesNo().");
    log.debug("Leaving XacmlAdmin.yesNo().");
    return self.select(name, [{ value: 'false', label: 'no' },
                         { value: 'true', label: 'yes' }],
                  value ? 'true' : 'false');
  }

  private typeOptions(): any[] {
    const { log, editor } = this.deps;
    log.debug("Entering XacmlAdmin.typeOptions().");
    log.debug("Leaving XacmlAdmin.typeOptions().");
    return editor.typeMenu().map(function (one) {
      return { value: one.uri, label: one.label };
    });
  }

  private categoryOptions(): any[] {
    const { log, editor } = this.deps;
    log.debug("Entering XacmlAdmin.categoryOptions().");
    log.debug("Leaving XacmlAdmin.categoryOptions().");
    return editor.CATEGORY_MENU.map(function (one) {
      return { value: one.uri, label: one.label };
    });
  }

  private functionOptions(): any[] {
    const { log, editor } = this.deps;
    log.debug("Entering XacmlAdmin.functionOptions().");
    log.debug("Leaving XacmlAdmin.functionOptions().");
    return editor.applyFunctions().map(function (one) {
      return { value: one.uri,
               label: one.label + '  (' + one.arity + ' → ' + one.returns +
                 ')' };
    });
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
  private editFormFor(policy: any, row: any): string {
    const self = this;
    const { log, editor, esc } = this.deps;
    log.debug("Entering XacmlAdmin.editFormFor().");
    const located = editor.nodeAt(policy, row.path);
    if (!located) {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return '';
    }
    const node = located.node;
    const head = '<form method="post" action="/admin/xacml/editor" ' +
      'class="inline">' + self.hidden('policy', policy.__editorName) +
      self.hidden('path', row.path);

    // A POLICY AND A POLICY SET TAKE THE SAME FORM AND NOT THE SAME MENU. The
    // rule-combining and policy-combining algorithm URIs differ by one segment
    // and a set carrying the rule spelling names an algorithm no combiner can
    // find, so the menu comes from `algorithmMenuFor()` — one function, used
    // here and by the handler that validates the answer, so the page cannot
    // offer something the edit then refuses.
    if (row.kind === 'policy' || row.kind === 'policySet') {
      const menu = editor.algorithmMenuFor(node);
      const chosen: any = menu.filter(function (one) {
        return one.uri === node.combiningAlgId;
      })[0] || {};
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return head + self.hidden('action', 'edit-policy') +
        (row.kind === 'policySet' ? 'PolicySetId ' : 'PolicyId ') +
        self.textField('id', node.id, 40) + ' ' +
        self.select('combiningAlgId', menu.map(function (one) {
          return { value: one.uri, label: one.label };
        }), node.combiningAlgId) +
        ' Version ' + self.textField('version', node.version || '1.0', 6) +
        '<br>Description ' +
        self.textField('description', node.description, 60) +
        '<br>MaxDelegationDepth ' +
        self.textField('maxDelegationDepth', node.maxDelegationDepth, 4) +
        ' XPathVersion ' +
        self.textField('xpathVersion', node.xpathVersion, 44) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">' + esc(chosen.what || '') + '</div>' +
        '<div class="sub">Version is dot-separated numbers. ' +
        '<strong>MaxDelegationDepth is carried and not honoured</strong> — ' +
        'this PDP implements no administrative delegation, so the attribute ' +
        'survives a round trip and is read by nothing. XPathVersion belongs ' +
        'in &lt;' + (row.kind === 'policySet' ? 'PolicySetDefaults'
                                            : 'PolicyDefaults') + '&gt; and ' +
        'the specification asks for it whenever the document holds an ' +
        'AttributeSelector or an xpathExpression.</div>';
    }

    if (row.kind === 'reference') {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return head + self.hidden('action', 'edit-reference') +
        esc(node.kind) + ' ' + self.textField('ref', node.ref, 44) +
        ' Version ' + self.textField('version', node.version, 8) +
        ' <button type="submit">Update</button></form><div class="sub">The ' +
        'id of a policy stored <em>separately</em> in this repository. It is ' +
        'resolved when a decision is made rather than when this document is ' +
        'loaded, so naming one that does not exist yet is allowed — an ' +
        'unresolved reference is reported on the decision. Leave Version ' +
        'empty for no constraint.</div>';
    }

    if (row.kind === 'rule') {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return head + self.hidden('action', 'edit-rule') +
        self.select('effect', [{ value: 'Permit', label: 'Permit' },
                          { value: 'Deny', label: 'Deny' }], node.effect) +
        ' RuleId ' + self.textField('id', node.id, 36) +
        ' Description ' + self.textField('description', node.description, 40) +
        ' <button type="submit">Update</button></form>';
    }

    if (row.kind === 'variable') {
      const rename = head + self.hidden('action', 'edit-variable') +
        // FROM THE PATH rather than from the label: the label is prose this
        // page composes and a change to it would silently start renaming
        // variables to something with a description stuck on the end.
        'VariableId $' + self.textField('variableId',
                                   String(row.path).split('.').pop(), 12) +
        ' <button type="submit">Rename</button></form>' +
        '<div class="sub">Every <code>VariableReference</code> naming it is ' +
        'rewritten with it — a rename that left them behind would produce a ' +
        'document that does not load, and the write would be refused. The ' +
        'scope is <strong>this policy</strong>: a sibling policy in the same ' +
        'set cannot see it.</div>';
      log.debug("Leaving XacmlAdmin.editFormFor().");
      // The definition IS an expression, so the expression's own form follows —
      // one row, two forms, rather than a variable you can rename and whose
      // value you cannot reach.
      return rename + self.expressionForm(policy, row, node);
    }

    if (row.kind === 'match') {
      const menu = editor.matchFunctions().map(function (one) {
        return { value: one.uri, label: one.label };
      });
      const reference = node.reference || {};
      const selector = reference.kind === 'selector';
      const test = head + self.hidden('action', 'edit-match') +
        self.select('matchId', menu, node.matchId) + ' ' +
        self.textField('value', node.value.lexical, 18) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">The datatype follows the function — both sides ' +
        'become ' + esc(editor.shortType(node.value.type)) + '.</div>';
      const against = head + self.hidden('action', 'edit-match') +
        'against ' +
        self.select('referenceKind',
               [{ value: 'designator', label: 'an attribute' },
                { value: 'selector', label: 'an XPath selector' }],
               selector ? 'selector' : 'designator') + ' ' +
        (selector ? 'Path ' + self.textField('path', reference.path, 24)
                  : 'AttributeId ' +
                    self.textField('attributeId', reference.attributeId, 24)) +
        ' in ' +
        self.select('category', self.categoryOptions(), reference.category) +
        (selector
           ? ' ContextSelectorId ' +
             self.textField('contextSelectorId',
                            reference.contextSelectorId, 20)
           : ' Issuer ' + self.textField('issuer', reference.issuer, 16)) +
        ' must be present ' +
        self.yesNo('mustBePresent', reference.mustBePresent) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">A <code>Match</code> holds an ' +
        '<code>AttributeDesignator</code> <em>or</em> an ' +
        '<code>AttributeSelector</code> and never both. Switching the kind ' +
        'redraws this form with the fields that kind takes. <strong>Must be ' +
        'present</strong> is the difference between an absent attribute ' +
        'being an empty bag and being Indeterminate — which is the ' +
        'difference between a policy that quietly does not apply and one ' +
        'that fails closed.</div>';
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return test + against;
    }

    if (row.kind === 'assignment') {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return head + self.hidden('action', 'edit-assignment') +
        'AttributeId ' + self.textField('attributeId', node.attributeId, 30) +
        ' Category ' + self.select('category',
                              [{ value: '', label: '(none)' }]
                                .concat(self.categoryOptions()),
                              node.category || '') +
        ' Issuer ' + self.textField('issuer', node.issuer, 16) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">What the PEP is handed alongside the obligation. ' +
        'Category and Issuer are optional and mean "this assignment is about ' +
        'that category" — leave them empty for a plain named value. The ' +
        'value itself is the expression below.</div>';
    }

    if (row.kind === 'obligation') {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return head + self.hidden('action', 'edit-obligation') +
        self.textField('id', node.id, 40) + ' fires on ' +
        self.select('on', [{ value: 'Permit', label: 'Permit' },
                      { value: 'Deny', label: 'Deny' }], node.on) +
        ' <button type="submit">Update</button></form>';
    }

    if (row.kind === 'expression') {
      log.debug("Leaving XacmlAdmin.editFormFor().");
      return self.expressionForm(policy, row, node);
    }
    log.debug("Leaving XacmlAdmin.editFormFor().");
    return '';
  }

  // The five expression kinds that have fields of their own. Separate from
  // `editFormFor()` because a VariableDefinition is an expression too and needs
  // exactly these forms under its rename box — written twice they would drift,
  // and the sixth kind (`variableRef`) is deliberately absent from both: its
  // whole content is which variable it names, and that is chosen by REPLACING
  // it from the Add menu, where the list of legal names is computed.
  private expressionForm(policy: any, row: any, node: any): string {
    const self = this;
    const { log, model, editor, esc } = this.deps;
    log.debug("Entering XacmlAdmin.expressionForm().");
    const head = '<form method="post" action="/admin/xacml/editor" ' +
      'class="inline">' + self.hidden('policy', policy.__editorName) +
      self.hidden('path', row.path);

    if (node.kind === 'value') {
      const xpath = node.type === model.TYPE.XPATH_EXPRESSION;
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'edit-value') +
        self.textField('lexical', node.lexical, 24) + ' as ' +
        self.select('type', self.typeOptions(), node.type) +
        (xpath
           ? ' over ' + self.select('xpathCategory', self.categoryOptions(),
                               node.xpathCategory || model.CATEGORY.RESOURCE)
           : '') +
        ' <button type="submit">Update</button></form>' +
        (xpath
           ? '<div class="sub">An <code>xpathExpression</code> value is an ' +
             'XPath, and <code>XPathCategory</code> is the request category ' +
             'it runs against. The prefix bindings it uses travel with the ' +
             'document.</div>'
           : '');
    }

    if (node.kind === 'designator') {
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'edit-designator') +
        self.textField('attributeId', node.attributeId, 24) + ' in ' +
        self.select('category', self.categoryOptions(), node.category) +
        ' as ' +
        self.select('dataType', self.typeOptions(), node.dataType) +
        ' Issuer ' + self.textField('issuer', node.issuer, 16) +
        ' must be present ' + self.yesNo('mustBePresent', node.mustBePresent) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">An empty <strong>Issuer</strong> means ' +
        '<em>any</em> issuer, which is not the same as an issuer whose name ' +
        'is the empty string — so clearing the box removes the attribute ' +
        'rather than writing one.</div>';
    }

    if (node.kind === 'selector') {
      const bindings = Object.keys(node.namespaces || {})
        .filter(function (prefix) {
          return prefix !== '';
        }).sort().map(function (prefix) {
          return '<code>' + esc(prefix) + '</code> → <code>' +
            esc(node.namespaces[prefix]) + '</code>';
        }).join(', ');
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'edit-selector') +
        'Path ' + self.textField('path', node.path, 30) + ' over ' +
        self.select('category', self.categoryOptions(), node.category) +
        ' as ' +
        self.select('dataType', self.typeOptions(), node.dataType) +
        '<br>ContextSelectorId ' +
        self.textField('contextSelectorId', node.contextSelectorId, 24) +
        ' must be present ' + self.yesNo('mustBePresent', node.mustBePresent) +
        ' &nbsp; namespace ' + self.textField('namespacePrefix', '', 6) +
        ' = ' +
        self.textField('namespaceUri', '', 30) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">An <code>AttributeSelector</code> runs an XPath ' +
        'over the <code>&lt;Content&gt;</code> of a request category and ' +
        'returns a <strong>bag</strong>, exactly as a designator does — so ' +
        'most functions still need a <code>one-and-only</code> around it. ' +
        '<code>ContextSelectorId</code> names an attribute holding the node ' +
        'to start from; empty means the whole content.</div>' +
        '<div class="sub">Namespace bindings' +
        (bindings ? ': ' + bindings : ': none') + '. A prefix in the path ' +
        'means nothing without one, and they travel with the document. Type ' +
        'a prefix and a URI to add or change one; a prefix with an empty URI ' +
        'removes it.</div>';
    }

    if (node.kind === 'function') {
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'edit-function') +
        self.select('functionId', self.functionOptions(), node.functionId) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">Named here as a <strong>value</strong> rather than ' +
        'applied — this is the first argument of a higher-order function ' +
        'such as <code>any-of</code>, <code>all-of</code> or ' +
        '<code>map</code>. Applying it instead is the commonest way to write ' +
        'one of those wrongly.</div>';
    }

    if (node.kind === 'apply') {
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'edit-apply') +
        self.select('functionId', self.functionOptions(), node.functionId) +
        ' Description ' + self.textField('description', node.description, 30) +
        ' <button type="submit">Update</button></form>';
    }

    if (node.kind === 'variableRef') {
      // POINTING IT AT ANOTHER VARIABLE IS A REPLACEMENT, and the same action
      // the Add menu uses: `set-expression-variable` puts a new
      // VariableReference where this one is. The menu is the variables THIS
      // POLICY defines — computed by the grammar rather than listed here, so a
      // reference to a variable belonging to a sibling policy cannot be chosen.
      const scope = editor.variablesInScope(policy, row.path);
      if (!scope.length) {
        log.debug("Leaving XacmlAdmin.expressionForm().");
        return '<div class="sub">Names <code>$' + esc(node.variableId) +
          '</code>, which this policy does not define — so the document will ' +
          'not load. Add a variable definition to the policy, or replace ' +
          'this expression from the Add menu.</div>';
      }
      log.debug("Leaving XacmlAdmin.expressionForm().");
      return head + self.hidden('action', 'set-expression-variable') +
        self.select('variableId', scope.map(function (one) {
          return { value: one.id, label: '$' + one.id + '  — ' + one.detail };
        }), node.variableId) +
        ' <button type="submit">Update</button></form>' +
        '<div class="sub">Only the variables <strong>this policy</strong> ' +
        'defines are offered. A VariableReference may not name one belonging ' +
        'to a sibling policy in the same set — section 5.24 — and the ' +
        'document would not load.</div>';
    }
    log.debug("Leaving XacmlAdmin.expressionForm().");
    return '';
  }

  // ---------------------------------------------------------------------------
  // ONE EDIT: LOAD, APPLY, SERIALIZE, WRITE BACK.
  //
  // The write goes through `store.write()`, which validates — so an edit that
  // would produce a policy that does not type-check is REFUSED and the stored
  // document is unchanged. That is the property that makes a live editor
  // tolerable: you cannot break the running policy by half-finishing an
  // expression, because the half-finished version never lands.
  // ---------------------------------------------------------------------------
  editorAction(body?: any): ActionResult {
    const { log, audit, errorCodes, xml, store, editor } = this.deps;
    log.debug('Entering XacmlAdmin.editorAction(). action=' +
              (body || {}).action);
    const name = String((body || {}).policy || '');
    const path = String((body || {}).path || '');
    const action = String((body || {}).action || '');
    const existing = store.read(name);
    if (!existing) {
      log.debug('Leaving XacmlAdmin.editorAction(). No such policy.');
      return errorCodes.mark({ ok: false,
                               why: 'There is no policy called "' + name +
                                 '".' },
                             'STS-XACML-0033');
    }
    let policy;
    try {
      policy = store.parseDocument(existing.document);
    } catch (error) {
      log.debug('Caught in XacmlAdmin.editorAction(): ' +
                ((error && error.message) || error));
      log.debug('Leaving XacmlAdmin.editorAction(). It will not load.');
      return errorCodes.mark({ ok: false,
               why: 'That policy does not load, so it cannot be edited here: ' +
                    error.message }, 'STS-XACML-0034');
    }
    // A DEEP COPY, because `applyEdit()` mutates and `parseDocument()` returns
    // the CACHED parse — editing that object in place would leave the cache
    // holding a policy that no longer matches the document it is keyed by, and
    // every later reader would get the edit whether or not it was saved.
    policy = xml.parsePolicy(xml.writePolicy(policy));
    const applied = editor.applyEdit(policy, path, action, body);
    if (!applied.ok) {
      log.debug('Leaving XacmlAdmin.editorAction(). The edit was refused.');
      return errorCodes.mark(applied, 'STS-XACML-0035');
    }
    const document = xml.writePolicy(policy);
    const written = store.write(name, document, {
      isRoot: existing.isRoot, enabled: existing.enabled,
      description: existing.description
    });
    if (!written.ok) {
      log.debug('Leaving XacmlAdmin.editorAction(). The store refused.');
      return errorCodes.mark({ ok: false,
               why: 'That edit would leave the policy invalid, so it was not ' +
                    'saved and the stored document is unchanged. ' +
                    written.why },
                             errorCodes.codeOf(written) || 'STS-XACML-0028');
    }
    audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                  detail: action + ' at "' + (path || '(root)') + '" in "' +
                          name + '".' });
    log.debug('Leaving XacmlAdmin.editorAction(). ' + applied.what);
    return { ok: true, what: applied.what };
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml/decide — ASK THE PDP.
  //
  // A form that builds a request and shows the answer. It exists because a
  // policy you cannot try is a policy you are guessing about, and because the
  // interesting part of a decision is never the decision alone — it is WHICH
  // POLICIES applied, what the PIP found, and what the PEP would then do with
  // it. All four are on this page.
  // ---------------------------------------------------------------------------
  decideJson(query?: any): Record<string, any> {
    const { log, model, loadXacml } = this.deps;
    log.debug('Entering XacmlAdmin.decideJson().');
    const subject = String((query || {}).subject || '');
    const action = String((query || {}).action || 'GET');
    const resource = String((query || {}).resource || '');
    if (!subject && !resource) {
      log.debug('Leaving XacmlAdmin.decideJson(). Nothing asked.');
      return { asked: false };
    }
    // Required late so that requiring this file does not pull the routes module
    // in — `xacml.ts` requires THIS file, so a require the other way at the top
    // would be a cycle, and node answers a cycle with a half-initialised module
    // whose exports are undefined rather than with an error.
    const xacml = loadXacml();
    const categories = [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subject
          ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID, issuer: null,
               includeInResult: true,
               values: [{ type: model.TYPE.STRING, lexical: subject }] }]
          : [] },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                       includeInResult: true,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ];
    if (resource) {
      categories.push({ category: model.CATEGORY.RESOURCE, id: null,
                        content: null,
                        attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID,
                                       issuer: null, includeInResult: true,
                                       values: [{ type: model.TYPE.ANYURI,
                                                  lexical: resource }] }] });
    }
    const request = { returnPolicyIdList: true, combinedDecision: false,
                      categories: categories };
    const answer = xacml.decide(request);
    const enforcement = xacml.enforce(answer);
    log.debug('Leaving XacmlAdmin.decideJson(). ' + answer.decision);
    return { asked: true, subject: subject, action: action,
             resource: resource || null,
             decision: answer.decision, status: answer.status,
             obligations: (answer.obligations || []).map(function (one) {
               return one.id;
             }),
             advice: (answer.advice || []).map(function (one) {
               return one.id;
             }),
             applicablePolicies: answer.policyIdentifiers || [],
             enforcement: { allowed: enforcement.allowed,
                            bias: enforcement.bias, why: enforcement.why } };
  }

  actionNames(): string[] {
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.actionNames().");
    log.debug("Leaving XacmlAdmin.actionNames().");
    return POLICY_ACTIONS.concat(EDITOR_ACTIONS).concat(PEP_ACTIONS);
  }

  // A plain result, or a promise of one (see `PEP_ACTIONS`).
  combinedAction(body?: any): any {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlAdmin.combinedAction(). action=' +
              (body || {}).action);
    const action = String((body || {}).action || '');
    if (POLICY_ACTIONS.indexOf(action) >= 0) {
      log.debug('Leaving XacmlAdmin.combinedAction(). A repository action.');
      return self.policyAction(body, null);
    }
    if (EDITOR_ACTIONS.indexOf(action) >= 0) {
      log.debug('Leaving XacmlAdmin.combinedAction(). An editor action.');
      return self.editorAction(body);
    }
    if (PEP_ACTIONS.indexOf(action) >= 0) {
      log.debug('Leaving XacmlAdmin.combinedAction(). A remote PEP action.');
      return self.pepAction(body);
    }
    // The refusal sentence names every action and counts them, which is the
    // shape `ssf/CLAUDE.md` records two tests as READING — a handler that
    // phrased it its own way would turn both checks off with nothing failing.
    const all = self.actionNames();
    log.debug('Leaving XacmlAdmin.combinedAction(). Unknown action.');
    return errorCodes.mark({ ok: false,
             why: 'Unknown action "' + action + '". There are ' + all.length +
                  ': ' + all.join(', ') + '.' }, 'STS-XACML-0032');
  }

  // Every route, in the order this file has always registered them.
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, parseBody, errorCodes, admin, store, editor, esc } = this.deps;
    log.debug("Entering XacmlAdmin.registerRoutes().");

    app.get('/admin/xacml', function (req, res) {
      log.debug('Entering the admin XACML page.');
      const json = self.overviewJson();
      const root = store.root();
      const tiles = '<div class="tiles">' +
        admin.tile(json.policies, 'policies') +
        admin.tile(json.enabledPolicies, 'enabled') +
        admin.tile(root ? root.name : '—', 'root policy') +
        admin.tile(json.pepBias, 'PEP bias') +
        admin.tile(json.pipAvailable ? 'yes' : 'no', 'PIP has the directory') +
        '</div>';

      const rootWarning = root ? '' : admin.warn(
        'No policy is marked as the root, so <strong>every decision is ' +
        'NotApplicable</strong>. A PDP evaluates one document and reaches ' +
        'the rest through <code>PolicyIdReference</code>, so exactly one ' +
        'policy in the repository is where evaluation starts. Choose one on ' +
        'the <a href="/admin/xacml/policies">Policies</a> page.',
        'There is no root policy');

      const what = admin.note(
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

      admin.respond(req, res, json, 'XACML', '/admin/xacml',
                    tiles + rootWarning + what +
                    admin.configFormsFor('/admin/xacml'));
      log.debug('Leaving the admin XACML page.');
    });

    app.get('/admin/xacml/policies', function (req, res) {
      log.debug('Entering the admin XACML policies page.');
      const json = self.policiesJson();
      const writable = admin.mayWrite(req);

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
          esc(editor.shortName(row.combiningAlgId)
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

      const body = admin.note(
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
          ? '<h2>Import ALFA</h2>' + admin.note(
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
          ? '<h2>Create from a template</h2>' + admin.note(
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

      admin.respond(req, res, json, 'XACML policies', '/admin/xacml/policies',
                    body, '/admin/xacml');
      log.debug('Leaving the admin XACML policies page.');
    });

    app.get('/admin/xacml/peps', function (req, res) {
      log.debug('Entering the admin XACML remote PEPs page.');
      const json = self.pepsJson();
      const writable = admin.mayWrite(req);

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

      const body = admin.note(
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
        admin.note(
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
        admin.note(
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

      admin.respond(req, res, json, 'Remote PEPs', '/admin/xacml/peps',
                    body, '/admin/xacml');
      log.debug('Leaving the admin XACML remote PEPs page.');
    });

    app.get('/admin/xacml/monitor', function (req, res) {
      log.debug('Entering the admin XACML monitor page.');
      const json = self.monitorJson();
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
        admin.tile(json.policies.total, 'policies') +
        admin.tile(json.policies.enabled, 'enabled') +
        admin.tile(json.peps.total, 'enforcement points') +
        admin.tile(combined.decisions, 'decisions') +
        admin.tile(combined.allowed, 'allows') +
        admin.tile(combined.refused, 'declines') +
        '</div>';

      // THE FOUR COLUMNS ADD UP, AND THE FOURTH IS WHY. `allowed + refused` is
      // LESS than `decisions` on any service that has answered `POST
      // /xacml/pdp`, because those decisions were enforced by somebody else's
      // PEP in somebody else's process. Leaving the gap unexplained was the
      // first draft and it made the row look like an arithmetic error, which is
      // the kind of thing that makes a reader distrust every other number
      // beside it.
      const evidenceRow = function (label, figures, what) {
        log.debug("Entering evidenceRow().");
        log.debug("Leaving evidenceRow().");
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
        admin.note(
          '<p><strong>Allowed + refused + not-enforced = decisions</strong>, ' +
          'on every row. The third column is the one that is easy to be ' +
          'surprised by and it is not a failure: it counts the decisions ' +
          '<code>POST /xacml/pdp</code> produced for somebody ELSE&rsquo;s ' +
          'enforcement point. This service evaluated them and never saw what ' +
          'was done with the answers, so counting them as allowed or refused ' +
          'would be reporting an enforcement it was not present for.</p>',
          'Why the three do not add to the total on their own');

      const what = admin.note(
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

      const off = json.enabled ? '' : admin.warn(
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
        admin.note(
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
        admin.note(
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
      admin.respond(req, res, json, 'XACML decisions', '/admin/xacml/monitor',
                    tiles + off + what + evidence + table);
      log.debug('Leaving the admin XACML monitor page.');
    });

    app.post('/admin/xacml/peps', function (req, res) {
      log.debug('Entering the admin XACML remote PEPs action.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-XACML-0031');
        admin.respondToAction(req, res, '/admin/xacml/peps',
                              { ok: false,
                                why: 'This console session may read but ' +
                                     'not write.' });
        log.debug('Leaving the admin XACML remote PEPs action. Read-only.');
        return;
      }
      if (String(body.action || '') === 'issue-pep-certificate') {
        self.issueFromConsole(req, res, body);
        log.debug('Leaving the admin XACML remote PEPs action. Issuing.');
        return;
      }
      const result = self.pepAction(body);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0038');
      }
      admin.respondToAction(req, res, '/admin/xacml/peps', result);
      log.debug('Leaving the admin XACML remote PEPs action.');
    });

    app.post('/admin/xacml/policies', function (req, res) {
      log.debug('Entering the admin XACML policies action endpoint.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-XACML-0031');
        admin.respondToAction(req, res, '/admin/xacml/policies',
                              { ok: false,
                                why: 'This console session holds Admin ' +
                                     'Read and not Admin Write.' });
        log.debug('Leaving the admin XACML policies action endpoint. ' +
                  'Read-only.');
        return;
      }
      const result = self.policyAction(body, req);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0028');
      }
      admin.respondToAction(req, res, '/admin/xacml/policies', result);
      log.debug('Leaving the admin XACML policies action endpoint.');
    });

    app.get('/admin/xacml/editor', function (req, res) {
      log.debug('Entering the admin XACML editor page.');
      const name = String(req.query.policy || '');
      const json = self.editorJson(name);
      const writable = admin.mayWrite(req);

      if (!json.policy) {
        // **AN EMPTY REPOSITORY IS NOT AN UNGATED SERVICE**, and this branch
        // used to imply that it was: "there is nothing to edit" on a service
        // whose issuance and access decisions are both being made, every
        // request, by documents this page has never mentioned. The note goes
        // here as well as under the table for exactly that reason — it is the
        // branch where the wrong conclusion is easiest to draw.
        admin.respond(req, res, json, 'Policy editor', '/admin/xacml/editor',
                      admin.warn('The repository is empty, so there is ' +
                                 'nothing to edit. <strong>Creating a ' +
                                 'policy happens on the <a ' +
                                 'href="/admin/xacml/policies">Policies</a> ' +
                                 'page</strong>, in one of three ways: from ' +
                                 'a template, by importing ALFA, or from the ' +
                                 '<code>blank</code> template — an empty ' +
                                 'document with nothing in it, which is the ' +
                                 'starting point for writing one here rather ' +
                                 'than editing one somebody else shaped. ' +
                                 'Come back to this page with it and every ' +
                                 'element goes in from the menus below.',
                                 'Nothing to edit') +
                      self.serviceOwnEditorNote(json.serviceOwn),
                      '/admin/xacml');
        log.debug('Leaving the admin XACML editor page. Nothing to edit.');
        return;
      }

      let parsed = null;
      try {
        parsed = store.parseDocument(json.document);
        parsed.__editorName = json.policy.name;
      } catch (error) {
        log.debug("Caught in a callback in module scope: " +
                  ((error && error.message) || error));
        parsed = null;
      }

      const chooser = '<form method="get" action="/admin/xacml/editor">' +
        'Policy ' + self.select('policy', json.policies.map(function (one) {
          return { value: one, label: one };
        }), json.policy.name) +
        ' <button type="submit">Open</button></form>' +
        self.serviceOwnEditorNote(json.serviceOwn);

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
      const whereToCreate = admin.note(
        '<p>This editor changes a policy that <em>already exists</em>, and ' +
        'the chooser above is every policy in the repository. ' +
        '<strong>Creating one happens on the <a ' +
        'href="/admin/xacml/policies">Policies</a> page</strong> — there is ' +
        'no New button here, because every control on this page names a ' +
        'stored document and a path inside it, and a policy nobody has ' +
        'written yet has neither.</p><p>Three doors on that page: <strong>a ' +
        'template</strong> (a working policy in a shape people actually ' +
        'write, which is the first twenty clicks of this editor already ' +
        'made), <strong>Import ALFA</strong> (paste the readable syntax and ' +
        'it is stored as XACML XML), and the ' +
        '<strong><code>blank</code></strong> template — a Policy with no ' +
        'rules or a PolicySet with no policies, for writing one here from ' +
        'nothing. A blank document <em>denies every request</em> until you ' +
        'put something in it, because deny-unless-permit over no rules at ' +
        'all is a Deny; that is the safe direction for a half-built policy ' +
        'to fail in, but it is worth knowing before making one the root.</p>',
        'Where a new policy comes from');

      const liveWarning = json.policy.enabled && json.policy.isRoot
        ? admin.warn(
            'This policy is <strong>enabled and is the root</strong>, so it ' +
            'is what the PDP is deciding with <em>right now</em>. There is ' +
            'no draft state in this editor — the draft IS the stored policy, ' +
            'and every change below takes effect on the next request. That ' +
            'is deliberate: nothing can be lost by closing the browser, and ' +
            'there is no second copy that could disagree with the stored ' +
            'one. To work on it safely, disable it first on the ' +
            '<a href="/admin/xacml/policies">Policies</a> page.',
            'Editing is live')
        : '';

      const xpathGap = json.xpathVersionGaps.length
        ? admin.warn(
            'This document holds an <code>AttributeSelector</code> or an ' +
            '<code>xpathExpression</code> value, and ' +
            (json.xpathVersionGaps.length === 1
               ? '<code>' + esc(json.xpathVersionGaps[0]) + '</code> declares'
               : 'these declare') +
            ' no <code>XPathVersion</code>' +
            (json.xpathVersionGaps.length === 1 ? '' :
               ': <code>' +
               json.xpathVersionGaps.map(esc).join('</code>, <code>') +
               '</code>') +
            '. Section 5.14 says the element MUST be present when a policy ' +
            'uses one. <strong>Nothing here will refuse the ' +
            'document</strong> — this PDP has one XPath engine and does not ' +
            'choose a dialect by URI, so the decision is the same either way ' +
            '— but a schema validator elsewhere will refuse it, and this is ' +
            'the kind of defect that travels a long way before anybody finds ' +
            'out. The field is on the policy\'s own row above: ' +
            '<code>http://www.w3.org/TR/1999/REC-xpath-19991116</code> is ' +
            'what the conformance suite uses.',
            'No XPathVersion, and this document needs one')
        : '';

      const problems = json.problems.length
        ? admin.warn('<ul><li>' + json.problems.map(esc).join('</li><li>') +
                     '</li></ul><p>XACML is statically typed, so these are ' +
                     'wrong for every request rather than for some. The ' +
                     'policy is stored, but it will not load — the PDP ' +
                     'reports Indeterminate and names the first problem.</p>',
                     'This policy does not type-check')
        : '';

      const rows = parsed ? json.tree.map(function (row) {
        const adds = row.options.additions;
        const menu = writable && adds.length
          ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
            self.hidden('policy', json.policy.name) +
            self.hidden('path', row.path) +
            self.select('action', adds.map(function (one) {
              return { value: one.action, label: one.label };
            }), '') +
            ' <button type="submit">Add</button></form>'
          : '';
        const remove = writable && row.options.removable
          ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
            self.hidden('policy', json.policy.name) +
            self.hidden('path', row.path) +
            self.hidden('action', 'remove') +
            '<button type="submit">Remove</button></form>'
          : '';
        const helps = adds.filter(function (one) { return one.help; })
          .map(function (one) {
            return '<strong>' + esc(one.label) + '</strong> — ' + esc(one.help);
          }).join('<br>');
        return '<tr><td style="padding-left:' + (row.depth * 1.4) + 'rem">' +
          '<code>' + esc(row.label) + '</code>' +
          (row.detail ? '<div class="sub">' + esc(row.detail) + '</div>' : '') +
          (writable ? self.editFormFor(parsed, row) : '') +
          (helps ? '<div class="sub">' + helps + '</div>' : '') +
          '</td><td class="sub">' + esc(row.kind) + '</td>' +
          '<td>' + menu + ' ' + remove + '</td></tr>';
      }).join('') : '';

      const explain = admin.note(
        '<p>Each row is one element of the policy. The <strong>Add</strong> ' +
        'dropdown beside it offers <em>exactly</em> what XACML allows at ' +
        'that point and nothing else — a <code>Match</code> may only go ' +
        'inside an alternative, a <code>Condition</code> only on a rule and ' +
        'only one per rule, and the function list on a Match is the ' +
        'two-argument boolean predicates rather than all 275 ' +
        'functions.</p><p>Those menus are computed <strong>on the ' +
        'server</strong>, by the same code that validates the policy, ' +
        'against the real function library — so the editor cannot offer you ' +
        'something that will then be refused. This console runs under ' +
        '<code>script-src \'none\'</code> and has no JavaScript anywhere, ' +
        'which is why every control is a form and every choice is a round ' +
        'trip. The cost is real: a five-rule policy built by hand is perhaps ' +
        'forty of them. The templates on the <a ' +
        'href="/admin/xacml/policies">Policies</a> page are the first twenty ' +
        'already made.</p><p>Every element you add arrives <em>complete and ' +
        'valid</em> — a new rule has a Target and an Effect, a new Match has ' +
        'a function, a value and an attribute. An editor that produced ' +
        'half-built elements would hold a document that could not be saved, ' +
        'and a document that cannot be saved cannot be evaluated, which is ' +
        'when you most want to look at it.</p><p><strong>A ' +
        '<code>PolicySet</code> is edited here too, and it holds policies ' +
        'rather than rules.</strong> Its children may be a policy written ' +
        'inline, a nested set, or a <code>PolicyIdReference</code> naming a ' +
        'policy stored separately in this repository — which is how a PDP ' +
        'reaches more than one document: the root is evaluated and ' +
        'references are resolved when a decision is made. Its combining ' +
        'algorithm comes from the <em>policy</em>-combining list, which is a ' +
        'different set of URIs from the rule-combining one they are almost ' +
        'spelt the same as.</p><p>The rest of the syntax is here as well: ' +
        '<code>VariableDefinition</code> (named once, evaluated once per ' +
        'request, visible to its own policy only), ' +
        '<code>AttributeSelector</code> (an XPath over a request ' +
        'category\u2019s content, with the namespace bindings its prefixes ' +
        'need), <code>Function</code> as a value (what a higher-order ' +
        'function such as <code>any-of</code> or <code>map</code> takes as ' +
        'its first argument), the attribute assignments under an obligation, ' +
        'and the optional attributes — <code>Version</code>, ' +
        '<code>Issuer</code>, <code>MustBePresent</code>, ' +
        '<code>ContextSelectorId</code>, <code>XPathVersion</code> and ' +
        '<code>MaxDelegationDepth</code>.</p><p><strong>Two things are shown ' +
        'and cannot be added.</strong> The four combiner-parameter elements ' +
        'are drawn and removable, because a document may arrive carrying ' +
        'them and an element you cannot see is one you cannot delete — but ' +
        'there is no Add button, since section C of the specification says ' +
        'none of the twelve standard combining algorithms takes a parameter, ' +
        'and a control that provably changes no decision would be the first ' +
        'such control on this console. <code>&lt;PolicyIssuer&gt;</code> is ' +
        'not here at all: it belongs to the administrative delegation ' +
        'profile, which this PDP does not implement, so a document carrying ' +
        'one loses it here.</p>',
        'How this editor works');

      const body = chooser + whereToCreate + liveWarning + problems + xpathGap +
        explain +
        '<table><tr><th>Element</th><th>Kind</th><th>Add / remove</th></tr>' +
        rows + '</table>' +
        '<details><summary>The same policy as ALFA</summary>' +
        admin.note(
          '<p>ALFA — the Abbreviated Language For Authorization — is the ' +
          'third rendering of this policy and the one worth reading. Forty ' +
          'lines of XML are eight of ALFA and the eight say the same ' +
          'thing.</p><p>It is an OASIS <strong>Committee Specification ' +
          'Draft</strong> rather than a ratified standard: there is no ' +
          'conformance suite for it and no second implementation to disagree ' +
          'with. So the contract here is the one that can actually be kept — ' +
          '<em>anything this emits, it reads back, and the policy decides ' +
          'identically either way</em> — and not that it reads every ALFA ' +
          'document in the world.</p>',
          'What ALFA is') +
        '<pre>' + esc(json.alfa || '') + '</pre></details>' +
        '<details><summary>The document as stored</summary><pre>' +
        esc(json.document) + '</pre></details>';

      admin.respond(req, res, json, 'Policy editor', '/admin/xacml/editor',
                    body, '/admin/xacml');
      log.debug('Leaving the admin XACML editor page.');
    });

    app.post('/admin/xacml/editor', function (req, res) {
      log.debug('Entering the admin XACML editor action endpoint.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-XACML-0031');
        admin.respondToAction(req, res, '/admin/xacml/editor',
                              { ok: false,
                                why: 'This console session holds Admin ' +
                                     'Read and not Admin Write.' });
        log.debug('Leaving the admin XACML editor action endpoint. Read-only.');
        return;
      }
      const result = self.editorAction(body);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0035');
      }
      admin.respondToAction(req, res, '/admin/xacml/editor?policy=' +
                            encodeURIComponent(String(body.policy || '')),
                            result);
      log.debug('Leaving the admin XACML editor action endpoint.');
    });

    app.get('/admin/xacml/decide', function (req, res) {
      log.debug('Entering the admin XACML decide page.');
      const json = self.decideJson(req.query);
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
          admin.tile(json.decision, 'PDP decision') +
          admin.tile(json.enforcement.allowed ? 'allowed' : 'refused',
                     'the embedded PEP') +
          admin.tile(json.enforcement.bias, 'PEP bias') +
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

      const explain = admin.note(
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

      admin.respond(req, res, json, 'Try a decision', '/admin/xacml/decide',
                    explain + form + answer, '/admin/xacml');
      log.debug('Leaving the admin XACML decide page.');
    });

    log.debug("Leaving XacmlAdmin.registerRoutes().");
  }

  // -------------------------------------------------------------------------
  // FILL admin.js's `setXacmlPages()` SLOT, so that `/admin-api` can mirror
  // these pages without requiring this module — which it must not do, because
  // it is 19 in the require order and this file is reached at 23c, and a
  // require the wrong way would register every /xacml route ahead of the
  // management API's own.
  //
  // THE ACTION IS ONE FUNCTION over both surfaces. `/admin/xacml/policies` and
  // `/admin/xacml/editor` are two pages with two POST endpoints, and a
  // management API that mirrored them as two resources would make a caller
  // work out which one owns "enable" — so there is one action function
  // (`combinedAction()`), its names are the union, and it routes on the action
  // itself. The console keeps two endpoints because a form posts back to the
  // page it came from.
  // -------------------------------------------------------------------------
  installSlot(): void {
    const self = this;
    const { log, admin } = this.deps;
    log.debug("Entering XacmlAdmin.installSlot().");
    if (typeof admin.setXacmlPages === 'function') {
      admin.setXacmlPages({
        overview: function () {
          log.debug("Entering overview().");
          log.debug("Leaving overview().");
          return self.overviewJson();
        },
        policies: function () {
          log.debug("Entering policies().");
          log.debug("Leaving policies().");
          return self.policiesJson();
        },
        editor: function (name) {
          log.debug("Entering editor().");
          log.debug("Leaving editor().");
          return self.editorJson(name);
        },
        peps: function () {
          log.debug("Entering peps().");
          log.debug("Leaving peps().");
          return self.pepsJson();
        },
        // THE SIXTH VIEW, AND IT WAS MISSING UNTIL PHASE FIVE. Rule 7 says
        // every console page gets an operation on /admin-api in the same
        // commit, and /admin/xacml/decide shipped in phase three without one —
        // which `tests/vendored/admin_api.js` catches by reading the console's
        // own page list rather than a list in the test, and which nothing
        // noticed because that job had not been run against this branch. The
        // fix is here rather than in a route of its own because the parity is
        // about the VIEW.
        decide: function (query) {
          log.debug("Entering decide().");
          log.debug("Leaving decide().");
          return self.decideJson(query);
        },
        // THE SEVENTH, and it takes nothing: the monitor has no filter, no name
        // to look up and no page to be on. It is also the only one of the seven
        // with no `action` beside it, because that page has no control — see
        // its header for why a reset button was refused rather than forgotten.
        monitor: function () {
          log.debug("Entering monitor().");
          log.debug("Leaving monitor().");
          return self.monitorJson();
        },
        action: self.combinedAction.bind(self),
        actionNames: self.actionNames.bind(self)
      });
    } else {
      log.warn('xacml: the admin console offers no setXacmlPages(), so ' +
               '/admin-api cannot mirror the six /admin/xacml pages. The ' +
               'pages themselves are unaffected.');
    }
    log.debug("Leaving XacmlAdmin.installSlot().");
  }
}

// ---------------------------------------------------------------------------
// THE TRANSITIONAL CODE — see the header. One instance, built from the real
// modules; its routes are registered at load, where they always were, and the
// console's slot is filled after them, as it always was.
// ---------------------------------------------------------------------------
const pages = new XacmlAdmin({
  log: helpers.log,
  parseBody: helpers.parseBody,
  config: config,
  audit: audit,
  errorCodes: errorCodes,
  admin: admin,
  esc: admin.esc,
  model: model,
  xml: xml,
  store: store,
  editor: editor,
  templates: templates,
  validate: validate,
  alfa: alfa,
  pip: pip,
  peps: peps,
  pepHttp: pepHttp,
  pepTls: pepTls,
  pki: pki,
  monitor: monitor,
  loadXacml: function (): XacmlRoutes {
    return require('./xacml');
  },
  loadRolePep: function (): RolePep {
    return require('./xacml_role_pep');
  },
  loadAccessPep: function (): AccessPep {
    return require('./xacml_access_pep');
  }
});
pages.registerRoutes(app);
pages.installSlot();

export = {
  XacmlAdmin: XacmlAdmin,
  overviewJson: pages.overviewJson.bind(pages) as XacmlAdmin['overviewJson'],
  pepsJson: pages.pepsJson.bind(pages) as XacmlAdmin['pepsJson'],
  // The monitor's view, for GET /admin-api/xacml/monitor. Rule 7: every page
  // of this console has an operation. There is no action beside it because
  // that page HAS no control — it reports and changes nothing, deliberately
  // (see the header: a console that could zero its own monitoring would make
  // every number on it a number somebody might have zeroed).
  monitorJson: pages.monitorJson.bind(pages) as XacmlAdmin['monitorJson'],
  pepAction: pages.pepAction.bind(pages) as XacmlAdmin['pepAction'],
  PEP_ACTIONS: XacmlAdmin.PEP_ACTIONS,
  combinedAction: pages.combinedAction.bind(pages) as
    XacmlAdmin['combinedAction'],
  actionNames: pages.actionNames.bind(pages) as XacmlAdmin['actionNames'],
  EDITOR_ACTIONS: XacmlAdmin.EDITOR_ACTIONS,
  editorJson: pages.editorJson.bind(pages) as XacmlAdmin['editorJson'],
  editorAction: pages.editorAction.bind(pages) as XacmlAdmin['editorAction'],
  decideJson: pages.decideJson.bind(pages) as XacmlAdmin['decideJson'],
  policiesJson: pages.policiesJson.bind(pages) as XacmlAdmin['policiesJson'],
  policyAction: pages.policyAction.bind(pages) as XacmlAdmin['policyAction'],
  POLICY_ACTIONS: XacmlAdmin.POLICY_ACTIONS
};
