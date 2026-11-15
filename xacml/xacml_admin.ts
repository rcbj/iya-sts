// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   * **THE MODULE STILL EXPORTS EVERY OLD NAME**, each function a FACADE
//     forwarding to the instance the composition root builds and installs
//     (#50, R2); installing it runs `XacmlAdmin.wire()`, which fills the slot,
//     and a process without the root builds and wires a default when this
//     module loads. It no longer registers the routes (#50, R1): the module
//     exports `registerRoutes(app)` and `common/protocol_stack.ts` calls it
//     at the point in the route order where requiring `./xacml` used to
//     register them — just before `xacml.ts`'s own — so the route order is
//     what it was. The slot is now filled BEFORE the routes exist rather
//     than after; nothing reads it until a request arrives. `XacmlAdmin` is
//     exported for the root, and the three action lists are its static
//     members as well.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
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
// THE ONE REQUEST BUILDER (#306).
import xacmlRequest = require('./xacml_request');
const { AuthorizationRequest } = xacmlRequest;
import peps = require('./xacml_pep_registry');
import pepHttp = require('./xacml_pep_http');
// A remote PEP's HTTPS listener certificate (2026-09-13). A LIBRARY over
// `common/pki.js` and the register above, registering nothing.
import pepTls = require('./xacml_pep_tls');
// The remote PEP's reverse proxy (#1760): the grammar `set-pep-proxy` is
// held to and the session mechanism's client. A LIBRARY, registering nothing.
import pepProxy = require('./xacml_pep_proxy');
// A remote PEP's managed settings (#1760): `set-pep-settings`'s grammar.
import pepSettings = require('./xacml_pep_settings');
// A remote PEP's listeners (#1760): the grammar `set-pep-listener` is held to.
import pepListeners = require('./xacml_pep_listeners');
// The realm's application register, for the route form's chooser (#1760).
import applications = require('../common/applications');
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
  enforce(answer: object, bias?: string): any;
}

// The embedded PEPs' reports about their own policies.
interface RolePep {
  issuancePolicyState(): object;
}
interface AccessPep {
  accessPolicyState(): object;
}

// The applications' fine-grained policies (#564, P5): who names a policy,
// and every owned one grouped by its application.
interface FgaPolicyReader {
  holderOf(row: { name: string; application?: string | null }): string;
  ownedPolicies(): any[];
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
  pepProxy: any;
  pepSettings: any;
  pepListeners: any;
  // The realm's applications, as the route form's chooser lists them.
  applicationChoices(): Array<{ identifier: string; name: string }>;
  pki: any;
  monitor: any;
  // Required at the moment they are needed, never at load.
  loadXacml(): XacmlRoutes;
  loadRolePep(): RolePep;
  loadAccessPep(): AccessPep;
  // LAZY TOO (#564, P5): `fga_policies.ts` is built by the composition
  // root at 23c, beside this family, and asked only when a page is drawn
  // or a policy deleted — a require at load would run its slot's build
  // here, ahead of where `protocol_stack.ts` installs it.
  loadFga(): FgaPolicyReader;
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
// `set-pep-proxy` and `clear-pep-proxy` (#1760) are the reverse proxy's:
// the configuration the PEP pulls from `GET /xacml/pep/proxy`.
// `set-pep-settings` and `clear-pep-settings` (#1760) are the PEP's managed
// settings, pulled from `GET /xacml/pep/settings`.
const PEP_ACTIONS = ['enable-pep', 'disable-pep', 'forget-pep',
                     'issue-pep-certificate', 'set-pep-proxy',
                     'clear-pep-proxy', 'set-pep-route-identity',
                     'set-pep-settings', 'clear-pep-settings',
                     'set-pep-listener', 'remove-pep-listener',
                     'renew-pep-listener-certificate', 'set-pep-route',
                     'remove-pep-route', 'set-pep-route-application'];

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

/**
 * The Policy Administration Point's console pages under `/admin/xacml`: the
 * settings, the repository, the guided editor, the remote PEPs, the decide
 * form and the monitor.
 *
 * Every control is a plain form POST; the editor holds no state of its own,
 * the stored policy being the draft.
 */
class XacmlAdmin {
  /**
   * The remote-PEP actions; `issue-pep-certificate` is the one answered with
   * a promise.
   */
  static readonly PEP_ACTIONS = PEP_ACTIONS;
  /**
   * The repository actions.
   */
  static readonly POLICY_ACTIONS = POLICY_ACTIONS;
  /**
   * The guided editor's actions.
   */
  static readonly EDITOR_ACTIONS = EDITOR_ACTIONS;

  /**
   * Builds the pages over the dependencies given.
   *
   * @param deps - the console shell, settings, audit log, policy store,
   * editor, templates, engine modules, PIP, PEP register and monitor
   */
  constructor(private readonly deps: XacmlAdminDeps) {
    deps.log.debug("Entering XacmlAdmin.constructor().");
    deps.log.debug("Leaving XacmlAdmin.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules, as the composition
   * root passes them.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): XacmlAdminDeps {
    helpers.log.debug("Entering XacmlAdmin.defaultDeps().");
    helpers.log.debug("Leaving XacmlAdmin.defaultDeps().");
    return {
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
      pepProxy: pepProxy,
      pepSettings: pepSettings,
      pepListeners: pepListeners,
      applicationChoices: function () {
        helpers.log.debug("Entering applicationChoices().");
        const rows = applications.list().map(function (row: any) {
          return { identifier: String(row.identifier || ''),
                   name: String(row.name || row.identifier || '') };
        });
        helpers.log.debug("Leaving applicationChoices(). " + rows.length);
        return rows;
      },
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
      },
      loadFga: function (): FgaPolicyReader {
        return require('./fga_policies');
      }
    };
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml — SETTINGS AND WHAT THE PDP DECIDES WITH.
  // ---------------------------------------------------------------------------
  /**
   * Describes `/admin/xacml`: whether XACML is on, the policy counts, the root policy, whether the PIP has a directory, and the
   * settings.
   *
   * @returns the overview as JSON
   */
  overviewJson(): Record<string, any> {
    const { log, config, admin, store, pip } = this.deps;
    log.debug('Entering XacmlAdmin.overviewJson().');
    const rows = store.all();
    const root = store.root();
    const json = {
      enabled: config.value('xacml.enabled') !== false,
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
      // XACML's own group: AuthZEN's, homed on this page too (#563), is
      // drawn on its own tab from GET /admin-api/xacml/authzen.
      settings: admin.configSettingsJson
        ? admin.configSettingsJson('/admin/xacml', ['XACML']) : null
    };
    log.debug('Leaving XacmlAdmin.overviewJson().');
    return json;
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml/policies — THE REPOSITORY.
  // ---------------------------------------------------------------------------
  /**
   * Describes the policy repository: every policy with its state, whether it
   * is the root, and any validation problems, plus the templates.
   *
   * @returns the repository view as JSON
   */
  policiesJson(): Record<string, any> {
    const self = this;
    const { log, store, templates, validate } = this.deps;
    log.debug('Entering XacmlAdmin.policiesJson().');
    const root = store.root();
    const rows = store.all().map(function (row) {
      // `application` and `orphanedAt` (#564): a policy an application owns
      // is drawn without the make-root control, which the action refuses
      // anyway (STS-FGA-0002).
      const view = { name: row.name, policyId: row.id, kind: row.kind,
                     version: row.version, enabled: row.enabled,
                     isRoot: !!(root && root.name === row.name),
                     combiningAlgId: row.combiningAlgId,
                     description: row.description,
                     application: row.application || null,
                     orphanedAt: row.orphanedAt || null, problems: [] };
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
    // THE APPLICATIONS' OWN POLICIES, GROUPED (#564, P5): the same rows,
    // by owner, each marked with whether its application still names it —
    // which is what decides whether the tab offers Remove (an orphan, or a
    // policy no application names) or a link to the application's page.
    // `policies` keeps every row, owned ones included, for a caller that
    // reads the repository whole.
    return { root: root ? root.name : null, policies: rows,
             applicationPolicies: this.deps.loadFga().ownedPolicies(),
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
  /**
   * Describes the register of remote enforcement points, including whether
   * each is current with the repository and whether it has gone stale.
   *
   * @returns the remote PEP view as JSON
   */
  pepsJson(pep?: string, route?: string): Record<string, any> {
    const { log, config, peps, pepHttp, pepTls, pki,
            pepProxy, pepSettings, pepListeners } = this.deps;
    log.debug('Entering XacmlAdmin.pepsJson().');
    // ONE PEP's PAGE (#1760), `/admin/xacml/pep?pep=<name>`: the same
    // answer narrowed to that row, as `/admin-api/applications`'
    // `?application=` is, with `found` saying whether it is registered.
    const one = typeof pep === 'string' && pep !== '' ? pep : null;
    const rows = peps.all().filter(function (row) {
      return one === null || row.name === one;
    }).map(function (row) {
      const view = Object.assign({}, row);
      // THE IDENTITY ENTRY AS A SERVICE ACCOUNT (#1760): the person the
      // certificate resolves to, whether it is a service account, and its
      // owners — read where it is, never stored on the row. Null where the
      // row names no person entry here.
      view.identityAccount = row.identity
        ? require('../common/service_accounts').identityOf(row.identity)
        : null;
      // THE MANAGED SETTINGS (#1760), read through the validator the pull
      // uses, so the page shows what the PEP would be sent; the stored
      // text itself is not answered. `settingsInUse` is the PEP's own
      // report of what it has in force, and `settingsCurrent` whether it
      // was applied from what would be sent now.
      const stored = pepSettings.stored(row.settings || '');
      view.settings = stored.settings;
      view.settingsProblem = stored.problem;
      view.settingsCurrent = !!row.settingsInUse &&
        row.settingsInUse.token ===
          pepSettings.pull(row, row.name).token;
      // THE REVERSE PROXY (#1760), read through the validator the pull
      // uses, so the page shows what the PEP would be sent: the document,
      // or null with the reason a stored value is refused. The stored text
      // itself is not answered.
      // Each route's application resolved as the pull would (D10), as the
      // REFERENCE and whether it is usable — never what was read off the
      // application, which is the pull's alone (its secret above all).
      view.proxy = null;
      view.proxyProblem = null;
      view.proxyRoutes = [];
      // Which routes and applications each OIDC client serves, for the
      // signal streams' table: a stream is a client's, and the PEP's report
      // names the client.
      const servedBy: Record<string, { routes: string[];
                                       applications: string[] }> = {};
      if (row.proxy) {
        const checked = pepProxy.validate(row.proxy);
        if (checked.ok) {
          view.proxy = checked.proxy;
          view.proxyRoutes = checked.proxy.routes.map(function (route) {
            const one = pepProxy.resolveRoute(route, checked.proxy).resolved;
            if (one.clientId) {
              const at = servedBy[one.clientId] ||
                (servedBy[one.clientId] = { routes: [], applications: [] });
              at.routes.push(route.id);
              if (at.applications.indexOf(route.application) < 0) {
                at.applications.push(route.application);
              }
            }
            return { route: route.id, application: route.application,
                     usable: one.usable, why: one.usable ? null : one.why };
          });
        } else {
          view.proxyProblem = checked.why;
        }
      }
      // THE NOTIFY URL'S PROBLEM IS COMPUTED RATHER THAN REMEMBERED, so that
      // changing `xacml.pepNotifyAllowedHosts` changes what this page says
      // about a PEP registered an hour ago. A stored verdict would have been
      // right when it was written and wrong from then on.
      // The URL the nudge dials: the one set here, else the registered one.
      view.effectiveNotifyUrl = pepSettings.notifyUrlOf(row);
      view.notifyProblem = pepHttp.urlProblem(view.effectiveNotifyUrl);
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
      // THE SIGNAL STREAMS, ONE ROW EACH (#1760): the stream's client joined
      // to the routes and applications this PEP's configuration says it
      // serves. A client id the configuration does not name is answered
      // empty rather than echoed: the PEP wrote it.
      if (view.signals && Array.isArray(view.signals.streams)) {
        view.signals = Object.assign({}, view.signals, {
          streams: view.signals.streams.map(function (one: any) {
            const known = Object.prototype.hasOwnProperty.call(servedBy,
                                                               one.clientId);
            return Object.assign({}, one, {
              clientId: known ? one.clientId : '',
              routes: known ? servedBy[one.clientId].routes : [],
              applications: known ? servedBy[one.clientId].applications : []
            });
          })
        });
      }
      // THE LISTENERS (#1760): the definitions read through the validator
      // the pull uses (the stored text is not answered), and every
      // listener — the environment's four and the defined ones — joined to
      // what the PEP last reported about it and, for a defined HTTPS one,
      // the certificate this realm issued it. `listenersInUse` null is a
      // PEP that does not report listeners (one older than them).
      const defined = pepListeners.stored(row.listeners || '',
                                          row.listenersInUse);
      view.listeners = defined.listeners;
      view.listenersProblem = defined.problem;
      view.listenerRows = pepListeners.rows(defined.listeners || [],
                                            row.listenersInUse)
        .map(function (one: any) {
          const held: any = one.source === 'service' &&
            one.protocol === 'https'
            ? pepTls.certificateOf(pepListeners.slotOf(row.name, one.id))
            : null;
          return Object.assign(one, {
            issued: held ? {
              subject: held.subject, serialHex: held.serialHex,
              notBefore: held.notBefore, notAfter: held.notAfter,
              expired: held.expired, thumbprint: held.thumbprint,
              dnsNames: held.dnsNames, ipAddresses: held.ipAddresses
            } : null
          });
        });
      return view;
    });
    const json: Record<string, any> = {
      enabled: config.value('xacml.remotePeps') !== false,
      syncToken: peps.syncToken(),
      staleAfterS: peps.staleAfterS(),
      requiresCertificate:
        config.value('xacml.pepRequireCertificate') !== false,
      notify: {
        on: pepHttp.notifyAllowed(),
        allowedHosts: pepHttp.allowedHosts(),
        // #171: `xacml.pepNotifyAllowHttp`, the certificate check and the CA
        // file, as they are IN FORCE here — a skip stored in a product realm
        // reads false.
        transport: pepHttp.transportSettings(),
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
      }).length,
      // What may be set on a PEP's page, and what stays its environment.
      settingsCatalogue: pepSettings.catalogue(),
      // What a listener may be (#1760): the environment's four, the closed
      // sets and whether this realm allows a plain-HTTP proxy listener.
      listenersCatalogue: pepListeners.catalogue()
    };
    if (one !== null) {
      json.pep = one;
      json.found = rows.length > 0;
      // The route form's application chooser (#1760), on the PEP's own
      // page only, as the roles page carries its own.
      json.applicationChoices = this.deps.applicationChoices();
      // ONE ROUTE'S OWN PAGE (#1760, rcbj: "click on a route name and go
      // to another page and be able to update all the configuration
      // values"): `?pep=&route=` adds the route, where it stands, whether
      // its application resolves and which proxy listeners serve it.
      if (typeof route === 'string' && route !== '') {
        json.route = route;
        json.routeDetail = this.routeDetailOf(rows[0] || null, route,
                                              json.applicationChoices);
      }
    }
    log.debug('Leaving XacmlAdmin.pepsJson(). ' + rows.length +
              ' registered PEP(s).');
    return json;
  }

  // ONE ROUTE, as its page draws it (#1760). Read off the row `pepsJson()`
  // built — the document as the validator normalised it, each route's
  // resolution and every listener joined to the PEP's report — so the page
  // shows nothing the PEP's own page does not. A route is served by EVERY
  // proxy listener: the route table is the proxy's, not a listener's.
  private routeDetailOf(row: any, id: string,
                        choices: any[]): Record<string, any> {
    const { log } = this.deps;
    log.debug('Entering XacmlAdmin.routeDetailOf().');
    const routes = row && row.proxy ? row.proxy.routes : [];
    const at = routes.map(function (one: any) {
      return one.id;
    }).indexOf(id);
    if (at < 0) {
      log.debug('Leaving XacmlAdmin.routeDetailOf(). Not found.');
      return { found: false, route: null, position: 0, count: routes.length,
               usable: null, why: null, application: null, servedBy: [] };
    }
    const route = routes[at];
    const state = (row.proxyRoutes || []).filter(function (one: any) {
      return one.route === id;
    })[0] || null;
    const chosen = route.public ? null
      : (choices || []).filter(function (one: any) {
          return one.identifier === route.application;
        })[0] || null;
    const servedBy = (row.listenerRows || []).filter(function (one: any) {
      return one.purpose === 'proxy';
    }).map(function (one: any) {
      const said = one.reported;
      return {
        id: one.id, source: one.source, protocol: one.protocol,
        port: said && said.port ? said.port
          : (one.definition ? one.definition.port : one.defaultPort),
        state: said ? said.state : null,
        reason: said ? said.reason : null
      };
    });
    log.debug('Leaving XacmlAdmin.routeDetailOf(). At ' + at);
    return {
      found: true, route: route, position: at, count: routes.length,
      usable: route.public ? true : (state ? state.usable : null),
      why: state && !state.usable ? state.why : null,
      application: route.public ? null
        : { identifier: route.application,
            name: chosen ? chosen.name : '', found: !!chosen },
      servedBy: servedBy
    };
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
  /**
   * Describes the decision counters for `/admin/xacml/monitor`, per
   * enforcement point, since this process started.
   *
   * @returns the monitor view as JSON
   */
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

  // A plain result, or a promise of one for `issue-pep-certificate`.
  /**
   * Applies one remote-PEP action: enable, disable, forget, or issue a
   * listener certificate.
   *
   * @param given - the form or API body, with `action` and the PEP's `name`
   *   (or `pep`, the name `GET /admin-api/xacml/peps` takes)
   * @returns a result with `ok` and `what` or `why`, or a promise of one for
   * `issue-pep-certificate`
   */
  pepAction(given?: any): any {
    const { log, audit, errorCodes, peps, pepTls } = this.deps;
    log.debug('Entering XacmlAdmin.pepAction(). action=' + (given || {}).action);
    const action = String((given || {}).action || '');
    // `pep` AS WELL AS `name` (2026-11-14). `GET /admin-api/xacml/peps` names
    // a PEP with `?pep=` and every act took `name` in its body, so a caller
    // that read one and wrote the other was refused for a member it did
    // send. Both are accepted, `name` as it always was; both given and
    // different is refused, rather than guessing which was meant.
    const named = String((given || {}).name || '');
    const aliased = String((given || {}).pep || '');
    if (named && aliased && named !== aliased) {
      log.debug('Leaving XacmlAdmin.pepAction(). pep and name differ.');
      return errorCodes.mark({ ok: false,
               why: '`pep` and `name` name two different PEPs ("' + aliased +
                    '" and "' + named + '"). Send one of them.' },
               'STS-XACML-0038');
    }
    const body = named || !aliased ? given
      : Object.assign({}, given, { name: aliased });
    if (action === 'issue-pep-certificate') {
      log.debug('Leaving XacmlAdmin.pepAction(). Issuing a listener ' +
                'certificate.');
      return pepTls.issue(body);
    }
    const name = String((body || {}).name || '');
    if (!name) {
      log.debug('Leaving XacmlAdmin.pepAction(). No name.');
      return errorCodes.mark({ ok: false,
                               why: 'Which registered PEP? Send `name` ' +
                                    '(or `pep`).' },
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
    if (action === 'set-pep-proxy' || action === 'clear-pep-proxy' ||
        action === 'set-pep-route-identity' || action === 'set-pep-route' ||
        action === 'remove-pep-route' ||
        action === 'set-pep-route-application') {
      log.debug('Leaving XacmlAdmin.pepAction(). The reverse proxy.');
      return this.proxyAction(action, name, body);
    }
    if (action === 'set-pep-settings' || action === 'clear-pep-settings') {
      log.debug('Leaving XacmlAdmin.pepAction(). The settings.');
      return this.settingsAction(action, name, body);
    }
    if (action === 'set-pep-listener' || action === 'remove-pep-listener' ||
        action === 'renew-pep-listener-certificate') {
      log.debug('Leaving XacmlAdmin.pepAction(). The listeners.');
      return this.listenerAction(action, name, body || {});
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

  // ===========================================================================
  // THE REVERSE PROXY'S TWO ACTIONS (#1760).
  //
  // `set-pep-proxy` validates the WHOLE document (`xacml_pep_proxy.ts`),
  // resolves every route's APPLICATION in the realm's registry (D10) and
  // refuses one that does not qualify, and writes what the validator
  // normalised. Nothing is created: the application behind the proxy is
  // an ordinary entry an administrator configured, and the pull reads what
  // each mechanism needs off it.
  //
  // `clear-pep-proxy` removes the configuration; the applications its routes
  // named are untouched.
  // ===========================================================================
  // The stored proxy document with one route's identity replaced, or a
  // refusal: `set-pep-route-identity`'s first half.
  private withRouteIdentity(name: string, body: any): any {
    const { log, errorCodes, peps, pepProxy } = this.deps;
    log.debug('Entering XacmlAdmin.withRouteIdentity().');
    const row = peps.read(name);
    const checked = row && row.proxy ? pepProxy.validate(row.proxy) : null;
    if (!checked || !checked.ok) {
      log.debug('Leaving XacmlAdmin.withRouteIdentity(). No document.');
      return errorCodes.mark({ ok: false,
               why: '"' + name + '" holds no valid reverse-proxy ' +
                    'configuration to edit a route of; save one with ' +
                    'set-pep-proxy first.' }, 'STS-XACML-0201');
    }
    const routeId = String(body.route || '');
    const proxy = JSON.parse(JSON.stringify(checked.proxy));
    const route = proxy.routes.filter(function (one: any) {
      return one.id === routeId;
    })[0];
    if (!route) {
      log.debug('Leaving XacmlAdmin.withRouteIdentity(). No such route.');
      return errorCodes.mark({ ok: false,
               why: '"' + name + '" has no route "' + routeId + '".' },
               'STS-XACML-0230');
    }
    route.identity = this.identityFromForm(body);
    log.debug('Leaving XacmlAdmin.withRouteIdentity().');
    return { ok: true, proxy: proxy };
  }

  // A route's identity from a form's members (`mode`, the paired
  // `headerName` and `headerClaim` rows, `separator`): one reading for
  // set-pep-route-identity and the route page's set-pep-route. A row with
  // no header name is left out; the validator judges the rest.
  private identityFromForm(body: any): any {
    const { log } = this.deps;
    log.debug('Entering XacmlAdmin.identityFromForm().');
    const list = function (value: unknown): string[] {
      log.debug('Entering list().');
      log.debug('Leaving list().');
      return (Array.isArray(value) ? value : (value === undefined ||
                                              value === null ? [] : [value]))
        .map(function (one: unknown) {
          return String(one).trim();
        });
    };
    const names = list(body.headerName);
    const claims = list(body.headerClaim);
    const headers: Array<{ name: string; claim: string }> = [];
    names.forEach(function (one, i) {
      if (one) {
        headers.push({ name: one, claim: claims[i] || '' });
      }
    });
    const mode = String(body.mode || 'headers');
    log.debug('Leaving XacmlAdmin.identityFromForm(). ' + mode);
    return mode === 'headers'
      ? { mode: mode, headers: headers,
          separator: String(body.separator === undefined ||
                            body.separator === '' ? ',' : body.separator) }
      : { mode: mode };
  }

  // A form or API boolean: true, false, or undefined for "not given".
  private flagOf(value: unknown): boolean | undefined {
    const { log } = this.deps;
    log.debug('Entering XacmlAdmin.flagOf().');
    const out = value === true || value === 'true' || value === 'on'
      ? true : (value === false || value === 'false' ? false : undefined);
    log.debug('Leaving XacmlAdmin.flagOf().');
    return out;
  }

  // A list from a JSON array, a repeated form field or one text box.
  private listOf(value: unknown): string[] {
    const { log } = this.deps;
    log.debug('Entering XacmlAdmin.listOf().');
    const out = (Array.isArray(value) ? value
      : (value === undefined || value === null || value === ''
          ? [] : String(value).split(/[\s,]+/)))
      .map(function (one: unknown) {
        return String(one).trim();
      }).filter(Boolean);
    log.debug('Leaving XacmlAdmin.listOf(). ' + out.length);
    return out;
  }

  // The stored proxy document as a copy to edit, or a refusal: the first
  // half of every one-route action.
  private proxyToEdit(name: string): any {
    const { log, errorCodes, peps, pepProxy } = this.deps;
    log.debug('Entering XacmlAdmin.proxyToEdit().');
    const row = peps.read(name);
    const checked = row && row.proxy ? pepProxy.validate(row.proxy) : null;
    if (!checked || !checked.ok) {
      log.debug('Leaving XacmlAdmin.proxyToEdit(). No document.');
      return errorCodes.mark({ ok: false,
               why: '"' + name + '" holds no valid reverse-proxy ' +
                    'configuration to edit a route of; save one with ' +
                    'set-pep-proxy first.' }, 'STS-XACML-0201');
    }
    log.debug('Leaving XacmlAdmin.proxyToEdit().');
    return { ok: true, proxy: JSON.parse(JSON.stringify(checked.proxy)) };
  }

  // ---------------------------------------------------------------------------
  // ONE ROUTE FROM A FORM (#1760, rcbj: "ability to add paths / routes /
  // Methods"). `set-pep-route` adds a route or replaces the one with its id,
  // `remove-pep-route` removes one, and `set-pep-route-application` binds a
  // route to an application of the realm's registry. Each builds the WHOLE
  // document from the stored one and hands it to the same `validate()` and
  // `resolutionProblem()` `set-pep-proxy` uses: one grammar, never two, so a
  // route the form can save is a route the document editor could have, and
  // the reverse.
  // ---------------------------------------------------------------------------
  private withRoute(action: string, name: string, body: any): any {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering XacmlAdmin.withRoute(). ' + action);
    const held = this.proxyToEdit(name);
    if (!held.ok) {
      log.debug('Leaving XacmlAdmin.withRoute(). No document.');
      return held;
    }
    const proxy = held.proxy;
    const ids = proxy.routes.map(function (one: any) { return one.id; });
    if (action === 'remove-pep-route' ||
        action === 'set-pep-route-application') {
      const id = String(body.route || '');
      const at = ids.indexOf(id);
      if (at < 0) {
        log.debug('Leaving XacmlAdmin.withRoute(). No such route.');
        return errorCodes.mark({ ok: false,
                 why: '"' + name + '" has no route "' + id + '".' },
                 'STS-XACML-0230');
      }
      if (action === 'remove-pep-route') {
        proxy.routes.splice(at, 1);
      } else {
        const application = String(body.application || '').trim();
        if (!application) {
          log.debug('Leaving XacmlAdmin.withRoute(). No application.');
          return errorCodes.mark({ ok: false,
                   why: 'set-pep-route-application names the route and ' +
                        '`application`, the identifier of an application ' +
                        'in this realm\'s registry.' }, 'STS-XACML-0256');
        }
        proxy.routes[at].application = application;
      }
      log.debug('Leaving XacmlAdmin.withRoute(). ' + action);
      return { ok: true, proxy: proxy };
    }
    // set-pep-route: `route` as an object (or its JSON), or the form's
    // members on the body.
    let given: any = body.route;
    if (typeof given === 'string' && given.trim().charAt(0) === '{') {
      try {
        given = JSON.parse(given);
      } catch (e) {
        log.debug('Caught in XacmlAdmin.withRoute(): ' +
                  ((e && e.message) || e));
        given = null;
      }
    }
    if (given === undefined || typeof given === 'string') {
      const isPublic = self.flagOf(body.public) === true;
      given = {
        id: String(body.id || '').trim(),
        path: String(body.path || ''),
        match: body.match || 'prefix',
        methods: self.listOf(body.methods),
        public: isPublic,
        mechanisms: isPublic ? [] : self.listOf(body.mechanisms),
        application: isPublic ? '' : String(body.application || '').trim(),
        resource: String(body.resource || ''),
        action: String(body.routeAction || '')
      };
      const forward = self.flagOf(body.forwardCredentials);
      const signals = self.flagOf(body.signals);
      const multiple = self.flagOf(body.multipleAccounts);
      if (multiple !== undefined && !isPublic) {
        given.multipleAccounts = multiple;
      }
      if (forward !== undefined) {
        given.forwardCredentials = forward;
      }
      if (signals !== undefined) {
        given.signals = signals;
      }
      // THE ROUTE PAGE SENDS THE IDENTITY TOO (#1760): with `mode`, the
      // form's identity members are the route's identity; a public route
      // forwards nobody, so it takes none.
      if (body.mode !== undefined && body.mode !== '' && !isPublic) {
        given.identity = self.identityFromForm(body);
      }
    }
    if (!given || typeof given !== 'object' || Array.isArray(given)) {
      log.debug('Leaving XacmlAdmin.withRoute(). No route.');
      return errorCodes.mark({ ok: false,
               why: 'set-pep-route takes `route`, one route object (id, ' +
                    'path, match, methods, public, mechanisms, ' +
                    'application, resource, action, identity, ' +
                    'forwardCredentials, signals), or the console form\'s ' +
                    'members.' }, 'STS-XACML-0256');
    }
    // A RENAME (#1760, the route's own page): `from` is the route being
    // edited and `id` what it is called after the save. Only `from` is
    // taken out, so a new id another route already holds is refused by
    // the validator's own "two routes are called" (STS-XACML-0192). The
    // pull carries the new id, and a PEP still holding the old document
    // asks for the old one until its next poll.
    const from = body.from === undefined || body.from === null ||
      body.from === '' ? null : String(body.from);
    if (from !== null && ids.indexOf(from) < 0) {
      log.debug('Leaving XacmlAdmin.withRoute(). No route to rename.');
      return errorCodes.mark({ ok: false,
               why: '"' + name + '" has no route "' + from + '" to edit.' },
               'STS-XACML-0230');
    }
    const at = ids.indexOf(from !== null ? from : given.id);
    // AN EDIT KEEPS THE ROUTE'S IDENTITY where the form says nothing of it:
    // the identity has a form of its own (`set-pep-route-identity`), and a
    // route turned public forwards nobody.
    if (at >= 0 && given.identity === undefined && !given.public) {
      given.identity = proxy.routes[at].identity;
    }
    const position = body.position === undefined || body.position === ''
      ? null : Number(body.position);
    if (position !== null && !(Number.isInteger(position) && position >= 0 &&
                               position <= proxy.routes.length)) {
      log.debug('Leaving XacmlAdmin.withRoute(). Position.');
      return errorCodes.mark({ ok: false,
               why: '`position` is where the route goes in the list, from 0 ' +
                    'to ' + proxy.routes.length + '; the first route that ' +
                    'matches wins.' }, 'STS-XACML-0256');
    }
    if (at >= 0) {
      proxy.routes.splice(at, 1);
    }
    const where = position !== null ? Math.min(position, proxy.routes.length)
      : (at >= 0 ? at : proxy.routes.length);
    proxy.routes.splice(where, 0, given);
    log.debug('Leaving XacmlAdmin.withRoute(). At ' + where);
    return { ok: true, proxy: proxy };
  }

  // ===========================================================================
  // A REMOTE PEP'S LISTENERS' THREE ACTIONS (#1760).
  //
  // `set-pep-listener` adds a listener or replaces the one with its id (an
  // edit keeps its `renew`), `remove-pep-listener` removes one and
  // `renew-pep-listener-certificate` moves an HTTPS listener's `renew`, so
  // the PEP generates a new key and asks for a new certificate on its next
  // pull. Validated whole by `xacml_pep_listeners.ts` against the PEP's
  // environment listeners as it last reported them; each refusal coded.
  // ===========================================================================
  private listenerAction(action: string, name: string, body: any): any {
    const { log, audit, errorCodes, peps, pepListeners } = this.deps;
    log.debug('Entering XacmlAdmin.listenerAction(). ' + action);
    const row = peps.read(name);
    const current = pepListeners.stored(row.listeners || '',
                                        row.listenersInUse);
    if (!current.listeners) {
      log.debug('Leaving XacmlAdmin.listenerAction(). Stored invalid.');
      return errorCodes.mark({ ok: false,
               why: 'The listeners stored for "' + name + '" do not ' +
                    'validate (' + current.problem + '); correct the ' +
                    'attribute xacmlPepListeners first.' },
               'STS-XACML-0252');
    }
    let checked: any;
    let id = String(body.listener || body.id || '');
    if (action === 'set-pep-listener') {
      let given: any = body.listener;
      if (typeof given === 'string') {
        try {
          given = JSON.parse(given);
        } catch (e) {
          log.debug('Caught in XacmlAdmin.listenerAction(): ' +
                    ((e && e.message) || e));
          given = null;
        }
      }
      if (given === undefined) {
        given = {};
        ['id', 'protocol', 'purpose', 'address', 'port', 'dnsNames',
         'ipAddresses', 'keyAlg'].forEach(function (key) {
          if (body[key] !== undefined && body[key] !== '') {
            given[key] = body[key];
          }
        });
        if (given.protocol === 'http') {
          delete given.dnsNames;
          delete given.ipAddresses;
          delete given.keyAlg;
        }
      }
      id = String((given && given.id) || '');
      checked = pepListeners.withListener(current.listeners, given,
                                          row.listenersInUse);
    } else {
      checked = pepListeners.without(current.listeners,
                                     String(body.listener || body.id || ''),
                                     action ===
                                       'renew-pep-listener-certificate');
    }
    if (!checked.ok) {
      log.debug('Leaving XacmlAdmin.listenerAction(). Refused: ' +
                checked.code);
      return errorCodes.mark({ ok: false, why: checked.why }, checked.code);
    }
    const list = checked.listeners;
    const written = peps.setListeners(name, list.length
                                              ? JSON.stringify(list) : null);
    if (!written) {
      log.debug('Leaving XacmlAdmin.listenerAction(). Not written.');
      return errorCodes.mark({ ok: false,
                               why: 'The directory refused the change.' },
                             'STS-XACML-0251');
    }
    const verb = action === 'set-pep-listener' ? 'set'
      : (action === 'remove-pep-listener' ? 'remove' : 'renew');
    audit.audit({ action: 'xacml.pep.listener.' + verb, actor: '',
                  protocol: 'XACML',
                  detail: (verb === 'set' ? 'Defined' : verb === 'remove'
                    ? 'Removed' : 'Asked for a new certificate for') +
                          ' listener "' + id + '" of remote PEP "' + name +
                          '"; ' + list.length + ' defined.' });
    log.debug('Leaving XacmlAdmin.listenerAction(). ' + list.length);
    return { ok: true, listeners: list,
             what: verb === 'renew'
               ? '"' + name + '" generates a new key for listener "' + id +
                 '" and asks for a new certificate on its next pull; the ' +
                 'old one is superseded when the new one is issued.'
               : '"' + name + '"\'s listeners are saved (' + list.length +
                 ' defined); the PEP binds and unbinds them on its next ' +
                 'pull, with no restart, and reports each one on its next ' +
                 'heartbeat.' };
  }

  // ===========================================================================
  // THE MANAGED SETTINGS' TWO ACTIONS (#1760).
  //
  // `set-pep-settings` REPLACES the whole document with what it is sent:
  // `settings` (an object; a member it does not name is refused), or the
  // members on the body itself (the console's form, where an empty box is
  // "not set"). Validated whole by `xacml_pep_settings.ts`, each refusal
  // coded. Nothing set is the same as clear: no attribute is written.
  // `clear-pep-settings` removes them, so every setting is the PEP's
  // environment again from its next pull.
  // ===========================================================================
  private settingsAction(action: string, name: string, body: any): any {
    const { log, audit, errorCodes, peps, pepSettings } = this.deps;
    log.debug('Entering XacmlAdmin.settingsAction(). ' + action);
    let settings: Record<string, unknown> = {};
    if (action === 'set-pep-settings') {
      const given = Object.assign({}, body || {});
      delete given.action;
      delete given.name;
      const checked = pepSettings.validate(given);
      if (!checked.ok) {
        log.debug('Leaving XacmlAdmin.settingsAction(). Refused: ' +
                  checked.code);
        return errorCodes.mark({ ok: false, why: checked.why },
                               checked.code);
      }
      settings = checked.settings;
    }
    const keys = Object.keys(settings);
    const written = peps.setSettings(name,
                                     keys.length ? JSON.stringify(settings)
                                                 : null);
    if (!written) {
      log.debug('Leaving XacmlAdmin.settingsAction(). Not written.');
      return errorCodes.mark({ ok: false,
                               why: 'The directory refused the change.' },
                             'STS-XACML-0241');
    }
    audit.audit({ action: 'xacml.pep.settings.' +
                          (keys.length ? 'set' : 'clear'),
                  actor: '', protocol: 'XACML',
                  detail: (keys.length
                    ? 'Set ' + keys.length + ' setting(s) of remote PEP "' +
                      name + '": ' + keys.join(', ') + '.'
                    : 'Cleared the managed settings of remote PEP "' + name +
                      '".') });
    log.debug('Leaving XacmlAdmin.settingsAction(). ' + keys.length +
              ' set.');
    return { ok: true, settings: keys.length ? settings : null,
             what: keys.length
               ? '"' + name + '"\'s settings are saved (' + keys.length +
                 ' set); the PEP applies them on its next pull, and uses its ' +
                 'environment for every other setting.'
               : '"' + name + '" has no managed settings; from its next pull ' +
                 'every setting is its environment\'s or the default.' };
  }

  private proxyAction(action: string, name: string, body: any): any {
    const { log, audit, errorCodes, peps, pepProxy } = this.deps;
    log.debug('Entering XacmlAdmin.proxyAction(). ' + action);
    if (action === 'clear-pep-proxy') {
      const cleared = peps.setProxy(name, null);
      if (!cleared) {
        log.debug('Leaving XacmlAdmin.proxyAction(). Not cleared.');
        return errorCodes.mark({ ok: false,
                                 why: 'The directory refused the change.' },
                               'STS-XACML-0202');
      }
      audit.audit({ action: 'xacml.pep.proxy.clear', actor: '',
                    protocol: 'XACML',
                    detail: 'Removed the reverse-proxy configuration of ' +
                            'remote PEP "' + name + '".' });
      log.debug('Leaving XacmlAdmin.proxyAction(). Cleared.');
      return { ok: true,
               what: '"' + name + '" holds no reverse-proxy configuration; ' +
                     'its proxy answers 404 to everything from its next ' +
                     'pull. The applications its routes named are ' +
                     'unchanged.' };
    }
    let given = (body || {}).proxy;
    if (action === 'set-pep-route' || action === 'remove-pep-route' ||
        action === 'set-pep-route-application') {
      const built = this.withRoute(action, name, body || {});
      if (!built.ok) {
        log.debug('Leaving XacmlAdmin.proxyAction(). Route refused.');
        return built;
      }
      given = built.proxy;
    }
    if (action === 'set-pep-route-identity') {
      // ONE ROUTE'S IDENTITY (D11), from the console's mode choice and its
      // header/claim table: the stored document with that route's
      // `identity` replaced, then saved through the same checks as a whole
      // document. A row with no header name is an unused row of the table.
      const built = this.withRouteIdentity(name, body || {});
      if (!built.ok) {
        log.debug('Leaving XacmlAdmin.proxyAction(). No route.');
        return built;
      }
      given = built.proxy;
    }
    if (given === undefined || given === null || given === '') {
      log.debug('Leaving XacmlAdmin.proxyAction(). No document.');
      return errorCodes.mark({ ok: false,
               why: 'set-pep-proxy takes `proxy`, the configuration ' +
                    'document: upstream, publicBaseUrl, the timeouts and ' +
                    'the ordered routes. clear-pep-proxy removes one.' },
               'STS-XACML-0201');
    }
    const checked = pepProxy.validate(given);
    if (!checked.ok) {
      log.debug('Leaving XacmlAdmin.proxyAction(). Refused: ' + checked.code);
      return errorCodes.mark({ ok: false, why: checked.why }, checked.code);
    }
    // EVERY ROUTE'S APPLICATION MUST RESOLVE NOW (D10): an unknown one, a
    // session route's client that is not confidential, lacks the code grant
    // or the callback, an oauth2 route's with no audience, a saml2 route's
    // with no entity ID — each refused by its code. The pull asks again.
    const unusable = pepProxy.resolutionProblem(checked.proxy);
    if (unusable) {
      log.debug('Leaving XacmlAdmin.proxyAction(). Unresolved: ' +
                unusable.code);
      return errorCodes.mark({ ok: false, why: unusable.why },
                             unusable.code);
    }
    const written = peps.setProxy(name, JSON.stringify(checked.proxy));
    if (!written) {
      log.debug('Leaving XacmlAdmin.proxyAction(). Not written.');
      return errorCodes.mark({ ok: false,
                               why: 'The directory refused the change.' },
                             'STS-XACML-0202');
    }
    audit.audit({ action: 'xacml.pep.proxy.set', actor: '',
                  protocol: 'XACML',
                  detail: 'Set the reverse-proxy configuration of remote ' +
                          'PEP "' + name + '": ' +
                          checked.proxy.routes.length + ' route(s), ' +
                          (checked.proxy.enabled ? 'enabled' : 'disabled') +
                          '.' });
    log.debug('Leaving XacmlAdmin.proxyAction(). Saved.');
    return { ok: true, proxy: checked.proxy,
             what: '"' + name + '"\'s reverse-proxy configuration is saved ' +
                   '(' + checked.proxy.routes.length + ' route(s)); the ' +
                   'proxy picks it up on its next pull.' };
  }

  /**
   * Applies one repository action: enable, disable, set the root, delete,
   * create from a template, or import ALFA.
   *
   * @param body - the form or API body, with `action`, `name` and the
   * action's own fields
   * @param req - the request, when there is one
   * @returns a result with `ok` and `what` or `why`
   */
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

    // AN APPLICATION'S LIVE POLICY IS NOT DELETED HERE (#564, P5): the
    // application would be left naming an entry that is not there, and an
    // enforcing one would refuse every detail (STS-FGA-0004). Decision 3
    // gives an administrator the ORPHAN to remove — a policy whose
    // application was deleted, or that no application names any more —
    // and that is what `holderOf()` tells apart. A live one is reset from
    // its application's page instead.
    if (action === 'delete' && existing.application) {
      const holder = this.deps.loadFga().holderOf(existing);
      if (holder) {
        log.debug('Leaving XacmlAdmin.policyAction(). An application\'s ' +
                  'live policy.');
        return errorCodes.mark({ ok: false,
                 why: '"' + name + '" is the fine-grained authorization ' +
                      'policy the application "' + holder + '" names ' +
                      '(appFgaPolicy), so it is not deleted. Reset it from ' +
                      'that application\'s Fine-grained authorization tab, ' +
                      'or delete the application, which keeps it as an ' +
                      'orphan this page can remove.' }, 'STS-FGA-0022');
      }
    }
    if (action === 'delete') {
      store.remove(name);
      audit.audit({ action: 'xacml.policy.delete', actor: '',
                    protocol: 'XACML',
                    detail: 'Deleted "' + name + '".' +
                            (existing.application
                              ? ' It was the fine-grained authorization ' +
                                'policy of the application "' +
                                existing.application + '", which no ' +
                                'longer names it' +
                                (existing.orphanedAt
                                  ? ' (orphaned since ' +
                                    existing.orphanedAt + ')'
                                  : '') + '.'
                              : '') });
      log.debug('Leaving XacmlAdmin.policyAction(). Deleted.');
      return { ok: true, what: 'Deleted "' + name + '".' +
               (existing.isRoot
                 ? ' It was the ROOT, so this repository now decides nothing ' +
                   'until another policy is made the root.' : '') };
    }

    // AN APPLICATION'S POLICY IS NEVER THE ROOT (#564), and that is refused
    // HERE, before the incumbent is demoted below: `store.write()` refuses it
    // too (STS-FGA-0001), but by then the old root would already have lost
    // its flag and the repository would be left deciding nothing.
    if (action === 'set-root' && existing.application) {
      log.debug('Leaving XacmlAdmin.policyAction(). An application\'s ' +
                'policy as the root.');
      return errorCodes.mark({ ok: false,
               why: '"' + name + '" is the fine-grained authorization ' +
                    'policy of the application "' + existing.application +
                    '" and cannot be the root of this repository. The root ' +
                    'is unchanged.' }, 'STS-FGA-0002');
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

  /**
   * Describes the guided editor's view of one policy: the tree with the
   * choices valid at each node, its problems and its ALFA rendering.
   *
   * @param name - the policy to edit; the root, or the first, when omitted
   * @returns the editor view as JSON
   */
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
                 options: editor.optionsAt(parsed, row.path),
                 // WHAT THE ROW'S EDIT FORM IS DRAWN FROM (#446): the node's
                 // own fields and the row-specific menus, which the page used
                 // to read out of the parsed document while drawing it.
                 edit: self.editDataFor(parsed, row) };
      }) : [],
      // The menus every edit form chooses from, once for the page.
      menus: parsed ? self.editorMenus() : null,
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

  // ONE TREE ROW'S EDIT DATA (#446): the node at the row's path with its own
  // fields only — never its children, which are rows of their own — and what
  // the row's form needs that depends on where it is: the combining
  // algorithms a policy or set may name, the variables in scope of a
  // reference, the short name of a Match's datatype. The console's form
  // builder drew from the parsed document directly; `web_xacml.ts`'s
  // `editFormFor()` draws from this.
  /**
   * Builds the data one tree row's edit form is drawn from.
   *
   * @param parsed - the parsed policy document
   * @param row - the tree row
   * @returns `{ node, algorithms?, scope?, valueShortType? }`, or null where
   *   no node is at the path
   */
  private editDataFor(parsed: any, row: any): any {
    const { log, editor } = this.deps;
    log.debug("Entering XacmlAdmin.editDataFor(). path=" + row.path);
    const located = editor.nodeAt(parsed, row.path);
    if (!located) {
      log.debug("Leaving XacmlAdmin.editDataFor(). No node.");
      return null;
    }
    const node = located.node;
    const own: Record<string, any> = {};
    Object.keys(node).forEach(function (name) {
      const value = node[name];
      if (value === null || typeof value !== 'object') {
        own[name] = value;
      }
    });
    // The three sub-objects a form reads a field of.
    ['value', 'reference', 'namespaces'].forEach(function (name) {
      if (node[name] && typeof node[name] === 'object' &&
          !Array.isArray(node[name])) {
        own[name] = Object.assign({}, node[name]);
      }
    });
    const out: Record<string, any> = { node: own };
    if (row.kind === 'policy' || row.kind === 'policySet') {
      out.algorithms = editor.algorithmMenuFor(node).map(function (one) {
        return { uri: one.uri, label: one.label, what: one.what || '' };
      });
    }
    if (row.kind === 'match' && node.value) {
      out.valueShortType = editor.shortType(node.value.type);
    }
    if (node.kind === 'variableRef') {
      out.scope = editor.variablesInScope(parsed, row.path)
        .map(function (one) {
          return { id: one.id, detail: one.detail };
        });
    }
    log.debug("Leaving XacmlAdmin.editDataFor().");
    return out;
  }

  // THE MENUS EVERY EDIT FORM CHOOSES FROM (#446), once for the page: the
  // datatypes, the categories, the functions an Apply may call, the
  // functions a Match may use, and the two constants a value form reads.
  /**
   * Builds the menus the editor's forms choose from.
   *
   * @returns the menus
   */
  private editorMenus(): any {
    const { log, editor, model } = this.deps;
    log.debug("Entering XacmlAdmin.editorMenus().");
    log.debug("Leaving XacmlAdmin.editorMenus().");
    return {
      types: this.typeOptions(),
      categories: this.categoryOptions(),
      functions: this.functionOptions(),
      matchFunctions: editor.matchFunctions().map(function (one) {
        return { value: one.uri, label: one.label };
      }),
      xpathType: model.TYPE.XPATH_EXPRESSION,
      resourceCategory: model.CATEGORY.RESOURCE
    };
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
  /**
   * Applies one editor action to a stored policy and writes it back.
   *
   * The write validates, so an edit that would leave the policy invalid is
   * refused and the stored document is unchanged.
   * @param body - the form or API body, with `policy`, `path`, `action` and
   * the action's own fields
   * @returns a result with `ok` and `what` or `why`
   */
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
  /**
   * Asks the PDP a question built from a subject, action and resource, and
   * reports the decision, the applicable policies and what the PEP would do.
   *
   * @param query - `subject`, `action` and `resource`
   * @returns the answer as JSON, or `{ asked: false }` when nothing was asked
   */
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
    // THROUGH THE ONE BUILDER (#306), in this page's order: subject,
    // action, environment, and the resource only when one was named.
    const built = new AuthorizationRequest({ includeInResult: true });
    [model.CATEGORY.ACCESS_SUBJECT, model.CATEGORY.ACTION,
     model.CATEGORY.ENVIRONMENT].forEach(function (id) {
      built.category(id);
    });
    if (subject) {
      built.subject(model.ATTRIBUTE.SUBJECT_ID, [subject]);
    }
    built.requestedAction(action);
    if (resource) {
      built.target(resource, model.TYPE.ANYURI);
    }
    const request = built.build();
    const answer = xacml.decide(request);
    // WHAT A PEP WOULD DO WITH IT, under BOTH biases (#596): the setting that
    // chose one, `xacml.pepBias`, went with the demonstration PEP it
    // governed, and a what-if has no PEP of its own to configure. The first is
    // deny-biased — every embedded PEP's, and the remote PEP's default — and
    // is the one the page draws.
    const enforcements = ['deny-biased', 'permit-biased']
      .map(function (bias) {
        const one = xacml.enforce(answer, bias);
        return { allowed: one.allowed, bias: one.bias, why: one.why };
      });
    const enforcement = enforcements[0];
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
             enforcement: enforcement,
             enforcements: enforcements };
  }

  /**
   * Lists every action `combinedAction()` accepts.
   *
   * @returns the repository, editor and PEP action names
   */
  actionNames(): string[] {
    const { log } = this.deps;
    log.debug("Entering XacmlAdmin.actionNames().");
    log.debug("Leaving XacmlAdmin.actionNames().");
    return POLICY_ACTIONS.concat(EDITOR_ACTIONS).concat(PEP_ACTIONS);
  }

  // A plain result, or a promise of one (see `PEP_ACTIONS`).
  /**
   * Routes an action to the repository, the editor or the PEP register by
   * its name, as the management API calls it.
   *
   * @param body - the body, with `action`
   * @returns the routed action's result, or a promise of it; a refusal
   * naming every action when the name is unknown
   */
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
  /**
   * Registers the `/admin/xacml` pages and their POST handlers.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, parseBody, errorCodes, admin, store, editor, esc } = this.deps;
    log.debug("Entering XacmlAdmin.registerRoutes().");










    log.debug("Leaving XacmlAdmin.registerRoutes().");
  }

  // -------------------------------------------------------------------------
  // FILL admin.js's `setXacmlPages()` SLOT, so that `/admin-api` can mirror
  // these pages without requiring this module — which it must not do, because
  // it is 19 in the require order and this file is reached at 23c, and until
  // #50's R1 a require the wrong way would have registered every /xacml
  // route ahead of the management API's own. Requiring it registers nothing
  // now (the route order is `common/protocol_stack.ts`'s `register()` calls),
  // but it would still move this file's load — and the slot fill — to 19.
  //
  // THE ACTION IS ONE FUNCTION over both surfaces. `/admin/xacml/policies` and
  // `/admin/xacml/editor` are two pages with two POST endpoints, and a
  // management API that mirrored them as two resources would make a caller
  // work out which one owns "enable" — so there is one action function
  // (`combinedAction()`), its names are the union, and it routes on the action
  // itself. The console keeps two endpoints because a form posts back to the
  // page it came from.
  // -------------------------------------------------------------------------
  /**
   * Fills the console's XACML slot (`admin.setXacmlPages()`) with this
   * instance's views and actions.
   */
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
        peps: function (req?: any) {
          log.debug("Entering peps().");
          const one = req && req.query ? req.query.pep : undefined;
          const route = req && req.query ? req.query.route : undefined;
          log.debug("Leaving peps().");
          return self.pepsJson(typeof one === 'string' ? one : undefined,
                               typeof route === 'string' ? route : undefined);
        },
        // THE SIXTH VIEW, AND IT WAS MISSING UNTIL PHASE FIVE. Rule 7 says
        // every console page gets an operation on /admin-api in the same
        // commit, and /admin/xacml/decide shipped in phase three without one —
        // which `tests/protocol/admin_api.js` catches by reading the console's
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

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: the console's slot fill. The root installs this instance
  // before it registers the routes, so the slot is still filled before they
  // exist; nothing reads it until a request arrives.
  /**
   * Runs the load-time work for the installed instance: the slot fill.
   *
   * @param instance - the installed instance
   */
  static wire(instance: XacmlAdmin): void {
    helpers.log.debug("Entering XacmlAdmin.wire().");
    instance.installSlot();
    helpers.log.debug("Leaving XacmlAdmin.wire().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlAdmin>(
  'xacml/xacml_admin',
  () => new XacmlAdmin(XacmlAdmin.defaultDeps()),
  XacmlAdmin.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The XACML Policy Administration Point's console pages and the views and
 * actions the management API shares with them.
 *
 * Exports the class for the composition root and facades that forward to
 * the installed instance.
 * @namespace
 */
export = {
  registerRoutes: (target: any): void => slot.get().registerRoutes(target),
  XacmlAdmin: XacmlAdmin,
  installInstance: (instance: XacmlAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  overviewJson: slot.forward('overviewJson'),
  pepsJson: slot.forward('pepsJson'),
  // The monitor's view, for GET /admin-api/xacml/monitor. Rule 7: every page
  // of this console has an operation. There is no action beside it because
  // that page HAS no control — it reports and changes nothing, deliberately
  // (see the header: a console that could zero its own monitoring would make
  // every number on it a number somebody might have zeroed).
  monitorJson: slot.forward('monitorJson'),
  pepAction: slot.forward('pepAction'),
  PEP_ACTIONS: XacmlAdmin.PEP_ACTIONS,
  combinedAction: slot.forward('combinedAction'),
  actionNames: slot.forward('actionNames'),
  EDITOR_ACTIONS: XacmlAdmin.EDITOR_ACTIONS,
  editorJson: slot.forward('editorJson'),
  editorAction: slot.forward('editorAction'),
  decideJson: slot.forward('decideJson'),
  policiesJson: slot.forward('policiesJson'),
  policyAction: slot.forward('policyAction'),
  POLICY_ACTIONS: XacmlAdmin.POLICY_ACTIONS
};
