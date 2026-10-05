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
import pki = require('../common/pki');
import monitor = require('./xacml_monitor');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import XacmlPage = require('./web_xacml');

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
    };
  }

  // ---------------------------------------------------------------------------
  // /admin/xacml — SETTINGS AND WHAT THE PDP DECIDES WITH.
  // ---------------------------------------------------------------------------
  /**
   * Describes `/admin/xacml`: whether XACML is on, the PEP bias, the policy
   * counts, the root policy, whether the PIP has a directory, and the
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
      }).length
    };
    log.debug('Leaving XacmlAdmin.pepsJson(). ' + rows.length +
              ' registered PEP(s).');
    return json;
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
   * @param body - the form or API body, with `action` and the PEP's `name`
   * @returns a result with `ok` and `what` or `why`, or a promise of one for
   * `issue-pep-certificate`
   */
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

  // DRAWN BY `web_xacml.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  overviewBody(req, json) {
    const { log, admin } = this.deps;
    log.debug("Entering XacmlAdmin.overviewBody().");
    const drawn = XacmlPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving XacmlAdmin.overviewBody().");
    return drawn;
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
