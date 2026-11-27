// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: role_selection.ts
//
// ===========================================================================
// WHAT A SIGN-IN CHOSE, AND WHAT A TOKEN MAY STILL CARRY OF IT (#1072,
// phases P3 to P5).
//
// A dynamic selectable role (`common/roles.js`) is held only by being CHOSEN
// at sign-in, for the application that sign-in is for, from the roles the
// role's own policy permits (`xacml/role_eligibility.ts`). This module is
// the two halves of that the eligibility module does not own:
//
//   validateChoice()   what a person ticked, held against what the step
//                      OFFERED them and against the policy NOW — never what
//                      the browser says it was offered
//   selectedFor()      the reader `roles.js`'s selection slot calls at every
//                      issuance: the session's choice for the token's
//                      application, each role asked of its policy again
//
// **THE SELECTION IS ON THE SESSION AND NOWHERE ELSE** (the ticket's 8.1).
// `authn.ts` stamps `selectedRoles` — `{ role, application, at }` rows —
// on the session record when the sign-in completes. Nothing is written to
// the role, a group or the person's entry, so a role chosen today is not a
// role held tomorrow, and a session that ends takes its choice with it.
//
// **A CHOICE IS FOR ITS APPLICATION ONLY** (rcbj's decision 4, 2026-11-20):
// single sign-on into another application carries none of it. To choose
// roles for another application a person starts from the portal's
// application list with *Sign in again*, which forces a sign-in and so a
// new choice.
//
// **RE-ASKED AT EVERY ISSUANCE, AND NEVER WIDENED** (8.2, 8.3): a chosen
// role the policy no longer permits — the person changed, the policy
// changed, the role was disabled, deleted or made static — is dropped from
// that token and audited (`roles.selection.dropped`); nothing the person
// did not choose is ever added, so a refresh cannot gain a role. A session
// that has ended or expired has no choice to read, which is also what an
// `offline_access` refresh token outliving its session gets (decision 6).
//
// Its `wire` step fills `roles.setSelectionReader()` (rule 3e; roles.js
// argues it both ways round), built at 23c after the eligibility module.
// ===========================================================================
import helpers = require('../common/helpers');
// The role step's refusals as catalog sentences (#2006).
import Sentence = require('../common/sentence');
import InstanceSlot = require('../common/instance_slot');

const { log } = helpers;

// One chosen role on the session record.
interface SelectionRow {
  role: string;
  application: string;
  at: number;
}

interface SelectionDeps {
  log: { debug(message: string): void; warn(message: string): void;
         info(message: string): void };
  errorCodes: { mark<T>(target: T, code: string): T;
                tag(code: string): string };
  audit: { audit(row: Record<string, unknown>): unknown };
  roles: {
    read(name: string): any;
    setSelectionReader(reader: any): void;
  };
  // `authn.ts` and `xacml/role_eligibility.ts`, read inside a call: both
  // are built before this module, and neither may be required at load.
  loadAuthn(): { sessionById(id: string): any };
  loadEligibility(): { decide(question: any): any;
                       applicationOf(raw: unknown): string;
                       selectionOn(application: unknown): boolean;
                       requiredFor(question: any): { required: boolean;
                                                     application: string;
                                                     roles: string[] } };
  now(): number;
}

class RoleSelection {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, error codes, the audit log, the role register,
   *   the session store and the eligibility decision (both lazily), a clock
   */
  constructor(private readonly deps: SelectionDeps) {
    deps.log.debug("Entering RoleSelection.constructor().");
    deps.log.debug("Leaving RoleSelection.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SelectionDeps {
    log.debug("Entering RoleSelection.defaultDeps().");
    log.debug("Leaving RoleSelection.defaultDeps().");
    return {
      log: log,
      errorCodes: require('../common/error_codes'),
      audit: require('../common/audit'),
      roles: require('../common/roles'),
      loadAuthn: function (): any {
        log.debug("Entering loadAuthn().");
        log.debug("Leaving loadAuthn().");
        return require('./authn');
      },
      loadEligibility: function (): any {
        log.debug("Entering loadEligibility().");
        log.debug("Leaving loadEligibility().");
        return require('../xacml/role_eligibility');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The rows a session record carries, well-formed only.
  static rowsOf(session: any): SelectionRow[] {
    const rows = session && Array.isArray(session.selectedRoles)
      ? session.selectedRoles : [];
    return rows.filter(function (one: any) {
      return one && typeof one.role === 'string' && one.role;
    }).map(function (one: any) {
      return { role: String(one.role),
               application: String(one.application || ''),
               at: Number(one.at) || 0 };
    });
  }

  // -------------------------------------------------------------------------
  // THE CHOICE. Held against the step's OWN record of what it offered (the
  // ticket's 6.4: the server keeps the authoritative eligible set) and
  // against the policy now (11.1: revalidated before anything is issued).
  // -------------------------------------------------------------------------
  /**
   * Validates what a person chose at the role step.
   *
   * @param question - `username`, `application`, `offered` (the rows the
   *   step offered, as `role_eligibility.offer()` answered them), `chosen`
   *   (the role names ticked), and the sign-in's `acr` and `amr`
   * @returns `{ ok: true, rows }` — the `selectedRoles` rows to stamp on the
   *   session — or `{ ok: false, code, why }`: a role not offered
   *   (STS-XACML-0325), two of one exclusive group (0326), a required role
   *   left out (0327), or a role no longer eligible (0328)
   */
  validateChoice(question: {
    username: string; application: string; offered: any[]; chosen: string[];
    acr?: string; amr?: string[];
  }): { ok: boolean; rows?: SelectionRow[]; code?: string;
         why?: Sentence } {
    const { log, errorCodes, now } = this.deps;
    const asked = question || ({} as any);
    const offered = Array.isArray(asked.offered) ? asked.offered : [];
    const byName: Record<string, any> = {};
    offered.forEach(function (row: any) {
      byName[String(row.name)] = row;
    });
    const chosen = (Array.isArray(asked.chosen) ? asked.chosen : [])
      .map(String).filter(function (one: string, at: number, list: string[]) {
        return one && list.indexOf(one) === at;
      });
    log.debug("Entering RoleSelection.validateChoice(). " + chosen.length +
              " chosen of " + offered.length + " offered.");
    const stranger = chosen.filter(function (one: string) {
      return !Object.prototype.hasOwnProperty.call(byName, one);
    });
    if (stranger.length) {
      log.debug("Leaving RoleSelection.validateChoice(). Not offered.");
      return errorCodes.mark({ ok: false, code: 'STS-XACML-0325',
        why: Sentence.say('refusals.authn.roleNotOffered') },
        'STS-XACML-0325');
    }
    const groups: Record<string, number> = {};
    let clash = '';
    chosen.forEach(function (one: string) {
      const group = String(byName[one].exclusiveGroup || '');
      if (!group) {
        return;
      }
      groups[group] = (groups[group] || 0) + 1;
      if (groups[group] > 1) {
        clash = group;
      }
    });
    if (clash) {
      log.debug("Leaving RoleSelection.validateChoice(). Exclusive.");
      return errorCodes.mark({ ok: false, code: 'STS-XACML-0326',
        why: Sentence.say('refusals.authn.roleExclusive') },
        'STS-XACML-0326');
    }
    const required = offered.filter(function (row: any) {
      return row.selection === 'required';
    });
    if (required.length && !required.some(function (row: any) {
      return chosen.indexOf(String(row.name)) >= 0;
    })) {
      log.debug("Leaving RoleSelection.validateChoice(). Required left out.");
      return errorCodes.mark({ ok: false, code: 'STS-XACML-0327',
        why: Sentence.say('refusals.authn.roleRequiredLeftOut') },
        'STS-XACML-0327');
    }
    // NOW, NOT WHEN THE PAGE WAS DRAWN: the policy is asked again for each
    // role chosen, so a change between the offer and the submit is seen.
    const eligibility = this.deps.loadEligibility();
    const lapsed = chosen.filter(function (one: string) {
      return !eligibility.decide({ role: one, username: asked.username,
                                   application: asked.application,
                                   stage: 'issue', acr: asked.acr,
                                   amr: asked.amr }).eligible;
    });
    if (lapsed.length) {
      log.debug("Leaving RoleSelection.validateChoice(). No longer eligible.");
      return errorCodes.mark({ ok: false, code: 'STS-XACML-0328',
        why: Sentence.say('refusals.authn.roleLapsed') },
        'STS-XACML-0328');
    }
    const at = now();
    // RECORDED BY ITS REGISTRY IDENTIFIER (#1072's follow-ups), the name
    // every issuance looks a choice up by, whatever the protocol called it.
    const application = eligibility.applicationOf(asked.application);
    log.debug("Leaving RoleSelection.validateChoice(). " + chosen.length +
              " role(s).");
    return { ok: true, rows: chosen.map(function (one: string) {
      return { role: one, application: application, at: at };
    }) };
  }

  // -------------------------------------------------------------------------
  // THE READER `roles.js` CALLS AT ISSUANCE.
  // -------------------------------------------------------------------------
  /**
   * Answers the dynamic roles a session chose for one of the given
   * applications and is still eligible for, now.
   *
   * @param context - `username`, `sessionId`, `applications`
   * @returns the role names, each by its full name
   */
  selectedFor(context: { username: string; sessionId: string;
                         applications: string[] }): string[] {
    const { log, audit, now } = this.deps;
    const asked = context || ({} as any);
    log.debug("Entering RoleSelection.selectedFor().");
    const session = asked.sessionId
      ? this.deps.loadAuthn().sessionById(String(asked.sessionId)) : null;
    // A SESSION THAT ENDED, EXPIRED, OR IS SOMEBODY ELSE'S HAS NO CHOICE.
    // `user` is the record `authn.ts`'s `userFor()` builds; a bare name is
    // read too.
    const live = !!session && (!session.expires ||
                               Number(session.expires) > now());
    const holder = live
      ? String((session.user && typeof session.user === 'object')
        ? session.user.username || '' : session.user || '') : '';
    const own = live && holder.toLowerCase() ===
                        String(asked.username || '').toLowerCase();
    if (!own) {
      log.debug("Leaving RoleSelection.selectedFor(). No live session.");
      return [];
    }
    // EACH NAME BY ITS REGISTRY IDENTIFIER (#1072's follow-ups): the
    // applications asked for, and a row a session recorded before rows were
    // recorded that way. And ONLY WHERE DYNAMIC ROLES ARE ON for that
    // application (`roles.dynamicSelection`, `appDynamicRoleSelection`): the
    // setting turns the box, the offer AND the carrying off, so a choice
    // stored while it was on is not carried once it is off.
    const eligibility = this.deps.loadEligibility();
    const applications = (asked.applications || []).map(function (one) {
      return eligibility.applicationOf(one);
    }).filter(function (one: string) {
      return one && eligibility.selectionOn(one);
    });
    const rows = RoleSelection.rowsOf(session).map(function (row) {
      return Object.assign({}, row, {
        application: eligibility.applicationOf(row.application) });
    }).filter(function (row) {
      return row.application && applications.indexOf(row.application) >= 0;
    });
    if (!rows.length) {
      log.debug("Leaving RoleSelection.selectedFor(). Nothing chosen here.");
      return [];
    }
    const out = [];
    rows.forEach(function (row) {
      const answer = eligibility.decide({
        role: row.role, username: holder,
        application: row.application, stage: 'issue',
        acr: session.acr || '', amr: session.amr || [] });
      if (answer.eligible) {
        out.push(row.role);
        return;
      }
      audit.audit({ action: 'roles.selection.dropped',
                    actor: holder, target: row.role,
                    protocol: 'XACML', errorCode: answer.code,
                    detail: 'the dynamic role "' + row.role + '", chosen ' +
                            'for "' + row.application + '", was left off ' +
                            'a token: the person is no longer eligible' });
    });
    log.debug("Leaving RoleSelection.selectedFor(). " + out.length +
              " of " + rows.length + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // SINGLE SIGN-ON INTO AN APPLICATION A REQUIRED ROLE GUARDS (#1072's
  // follow-ups). Decision 4 carries no new choice across single sign-on,
  // and decision 3 makes a required role impossible to skip — so a session
  // that holds no choice for an application that would REQUIRE one of this
  // person (a sign-in for another application, or one at a door with no
  // application, the certificate's) is not an answer to that application.
  // A browser flow sends the person to sign in again, which draws the role
  // step; a passive one is refused. A session that holds a choice for it,
  // even of optional roles only, has made its choice.
  // -------------------------------------------------------------------------
  /**
   * Says whether a session owes a role choice before it may sign in to an
   * application.
   *
   * @param session - the sign-on session (its `user`, `acr`, `amr` and
   *   `selectedRoles`)
   * @param application - the application, in any of its names
   * @returns true when a required role would be offered and the session
   *   recorded no choice for the application
   */
  owedFor(session: any, application: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering RoleSelection.owedFor().");
    const username = session ? String((session.user &&
      typeof session.user === 'object') ? session.user.username || ''
      : session.user || '') : '';
    if (!username || session.authenticated === false) {
      log.debug("Leaving RoleSelection.owedFor(). No person.");
      return false;
    }
    const eligibility = this.deps.loadEligibility();
    const needed = eligibility.requiredFor({
      username: username, application: application,
      acr: String(session.acr || ''),
      amr: Array.isArray(session.amr) ? session.amr.map(String) : [] });
    if (!needed.required) {
      log.debug("Leaving RoleSelection.owedFor(). Nothing required.");
      return false;
    }
    // A choice recorded for this application, by any of its names. The
    // role step records `[]` for nobody: a required role cannot be left out
    // (STS-XACML-0327), so a held step always leaves a row.
    const held = RoleSelection.rowsOf(session).some(function (row) {
      return eligibility.applicationOf(row.application) ===
             needed.application;
    });
    log.debug("Leaving RoleSelection.owedFor(). " + !held);
    return !held;
  }

  // -------------------------------------------------------------------------
  // A FLOW WITH NO BROWSER (rcbj's decision 5): the password grant, a token
  // exchange, the RFC 7523 and RFC 7522 grants, WS-Trust, Kerberos, LDAP,
  // the device grant and CIBA never carry a chosen role, and where the
  // application would REQUIRE one of this person they are refused, because
  // the step that asks cannot be drawn. One refusal for all of them, coded
  // (STS-XACML-0332) and audited as `roles.selection.refused`, so each
  // issuance point is one call and one answer in its protocol's words.
  // -------------------------------------------------------------------------
  /**
   * Refuses a flow that cannot draw the role step where the application
   * would require a dynamic role of the person.
   *
   * @param question - `username`, `application` (any of its names, or ''
   *   for none), `protocol` (for the audit row), and the credential's `acr`
   *   and `amr` where known
   * @returns null where nothing is required, else `{ code, why, roles,
   *   application }` with `code` STS-XACML-0332
   */
  noBrowserRefusal(question: { username: string; application?: string;
                               protocol?: string; acr?: string;
                               amr?: string[] }): any {
    const { log, audit, errorCodes } = this.deps;
    const asked = question || ({} as any);
    log.debug("Entering RoleSelection.noBrowserRefusal(). protocol=" +
              (asked.protocol || ''));
    const username = String(asked.username || '').trim();
    if (!username) {
      log.debug("Leaving RoleSelection.noBrowserRefusal(). Nobody.");
      return null;
    }
    const needed = this.deps.loadEligibility().requiredFor({
      username: username, application: asked.application || '',
      protocol: asked.protocol || '', acr: asked.acr || '',
      amr: Array.isArray(asked.amr) ? asked.amr.map(String) : [] });
    if (!needed.required) {
      log.debug("Leaving RoleSelection.noBrowserRefusal(). Nothing " +
                "required.");
      return null;
    }
    const where = needed.application ? '"' + needed.application + '"'
                                     : 'this realm';
    log.info(errorCodes.tag('STS-XACML-0332') + 'role_selection: ' +
             String(asked.protocol || 'a flow with no browser') + ' for "' +
             username + '" was refused: ' + where + ' requires a dynamic ' +
             'role the person must choose at the sign-in screen (' +
             needed.roles.join(', ') + ').');
    audit.audit({
      action: 'roles.selection.refused', outcome: 'failure',
      actor: username, target: username, errorCode: 'STS-XACML-0332',
      protocol: String(asked.protocol || ''),
      summary: String(asked.protocol || 'a flow with no browser') + ' for ' +
               username + ' was refused: a required dynamic role cannot be ' +
               'chosen there',
      detail: { application: needed.application, roles: needed.roles } });
    log.debug("Leaving RoleSelection.noBrowserRefusal(). Refused.");
    return errorCodes.mark({
      code: 'STS-XACML-0332', roles: needed.roles,
      application: needed.application,
      why: 'This application needs you to choose a role when you sign in, ' +
           'which cannot be done this way. Sign in at this service\'s ' +
           'sign-in screen.' }, 'STS-XACML-0332');
  }

  /**
   * Fills `roles.setSelectionReader()` with this instance.
   */
  installReader(): void {
    const self = this;
    const { log, roles } = this.deps;
    log.debug("Entering RoleSelection.installReader().");
    roles.setSelectionReader({
      selectedFor: function (context: any): string[] {
        return self.selectedFor(context);
      }
    });
    log.debug("Leaving RoleSelection.installReader().");
  }
}

// The module's own work with its instance: the selection slot.
function wireSelection(instance: RoleSelection): void {
  log.debug("Entering wireSelection().");
  instance.installReader();
  log.debug("Leaving wireSelection().");
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c.
const slot = new InstanceSlot<RoleSelection>(
  'authn/role_selection',
  () => new RoleSelection(RoleSelection.defaultDeps()),
  wireSelection,
  helpers.log);

// Standalone, build the default now, as every module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * Dynamic selectable roles (#1072): what a sign-in chose, held to the
 * offer and the policy, and what a token may still carry of it.
 * @namespace
 */
export = {
  RoleSelection: RoleSelection,
  installInstance: (instance: RoleSelection): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  rowsOf: RoleSelection.rowsOf,
  validateChoice: slot.forward('validateChoice'),
  selectedFor: slot.forward('selectedFor'),
  owedFor: slot.forward('owedFor'),
  noBrowserRefusal: slot.forward('noBrowserRefusal')
};
