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
import InstanceSlot = require('../common/instance_slot');

const { log } = helpers;

// One chosen role on the session record.
interface SelectionRow {
  role: string;
  application: string;
  at: number;
}

interface SelectionDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: { mark<T>(target: T, code: string): T };
  audit: { audit(row: Record<string, unknown>): unknown };
  roles: {
    read(name: string): any;
    setSelectionReader(reader: any): void;
  };
  // `authn.ts` and `xacml/role_eligibility.ts`, read inside a call: both
  // are built before this module, and neither may be required at load.
  loadAuthn(): { sessionById(id: string): any };
  loadEligibility(): { decide(question: any): any };
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
  }): { ok: boolean; rows?: SelectionRow[]; code?: string; why?: string } {
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
        why: 'A role was chosen that this sign-in did not offer.' },
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
        why: 'At most one of these roles may be chosen together.' },
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
        why: 'This sign-in needs at least one of its required roles.' },
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
        why: 'A role chosen is no longer available. Choose again.' },
        'STS-XACML-0328');
    }
    const at = now();
    log.debug("Leaving RoleSelection.validateChoice(). " + chosen.length +
              " role(s).");
    return { ok: true, rows: chosen.map(function (one: string) {
      return { role: one, application: String(asked.application || ''),
               at: at };
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
    const applications = (asked.applications || []).map(String);
    const rows = RoleSelection.rowsOf(session).filter(function (row) {
      return row.application && applications.indexOf(row.application) >= 0;
    });
    if (!rows.length) {
      log.debug("Leaving RoleSelection.selectedFor(). Nothing chosen here.");
      return [];
    }
    const eligibility = this.deps.loadEligibility();
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
  selectedFor: slot.forward('selectedFor')
};
