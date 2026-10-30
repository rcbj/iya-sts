// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: policy_selection.ts
//
// ---------------------------------------------------------------------------
// WHICH NAMED POLICY APPLIES, FOR EVERY POLICY KIND (#1235, part of #1234;
// rule 3cx).
//
// Every kind on Directory > Policies may keep NAMED policies beside
// `cn=default`, and rcbj's decisions on #1234 (2026-10-30) say how one is
// chosen, once, for all of them:
//
//   * AN APPLICATION OR A PERSON NAMES ITS POLICY. One single-valued
//     attribute per kind on the application (`app<Kind>Policy`, as
//     `appAuthnPolicy` has done since #1148) and/or on the person
//     (`sts<Kind>Policy`). The policy does not list them.
//   * A POLICY NAMES THE GROUPS IT COVERS (`sts<Kind>SelectGroup`, a group's
//     cn or DN) and carries a precedence (`sts<Kind>Precedence`, 1 to 1000).
//   * THE CANDIDATES are the policy the application names, the policy the
//     person names, and every named policy selecting one of the person's
//     groups. THE LOWEST PRECEDENCE WINS, ties broken by name (#535's rule),
//     and `default` applies where there is no candidate. A reference that is
//     empty or says `default` is no candidate.
//   * A REFERENCE TO A NAME THE REALM DOES NOT HOLD is no candidate either,
//     and is handed back in `missing`: what it MEANS is the kind's (the
//     authentication policy fails closed, #1148; the passkey policy reads its
//     baseline), so this file decides nothing about it.
//
// Matching is trimmed and case-insensitive throughout: a group by cn or DN, a
// reference by the policy's name.
//
// IT IS A LEAF (rule 3): static methods over values the caller hands in — the
// realm's named entries, the references, the person's groups — so it reads no
// directory, requires nothing of this service but the logger, and cannot join
// a require cycle. Who REFERENCES a policy is the registers' own question
// (`applications.js`' `applicationsNamingPolicy()`, the directory's
// `peopleNamingPolicy()`), asked by the kind, lazily.
//
// IT IS SELECTION, NOT AUTHORIZATION (#535's decision): it chooses which rows
// apply; what the rows then allow or refuse is the kind's, and where that is
// a decision, the issuance policy's.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const { log } = helpers;

/**
 * A named policy's entry as a directory hook answers it.
 */
interface PolicyEntry {
  name?: string;
  dn?: string;
  attributes?: Record<string, unknown>;
}

/**
 * How a kind's named policies are told apart: the attribute on a policy that
 * lists its groups (absent for a kind with no group selector) and the one
 * holding its precedence, and the kind's default precedence.
 */
interface SelectionSpec {
  groupAttribute?: string;
  precedenceAttribute: string;
  defaultPrecedence?: number;
}

/**
 * What names a policy: an application's or a person's reference attribute's
 * value. `by` is what the caller calls the holder (`application`, `person`).
 */
interface Reference {
  by: string;
  value: unknown;
}

/**
 * A group a person is in, as `personGroups()` answers it.
 */
interface GroupRef {
  cn?: unknown;
  dn?: unknown;
}

/**
 * One named policy, read.
 */
interface NamedPolicy {
  name: string;
  dn: string;
  precedence: number;
  groups: string[];
}

/**
 * The answer of `rank()`.
 */
interface Ranked {
  name: string;
  by: string;
  precedence: number;
  missing: Array<{ by: string; name: string }>;
}

/**
 * The name of the policy every realm has.
 */
const DEFAULT_NAME = 'default';
/**
 * A named policy's name: what a cn may be.
 */
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
/**
 * The lowest precedence a named policy may have.
 */
const MIN_PRECEDENCE = 1;
/**
 * The highest precedence a named policy may have.
 */
const MAX_PRECEDENCE = 1000;
/**
 * Where a named policy ranks when its entry says nothing readable.
 */
const DEFAULT_PRECEDENCE = 100;

/**
 * Chooses a kind's named policy for a person and an application.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
export = class PolicySelection {
  static readonly DEFAULT_NAME = DEFAULT_NAME;
  static readonly NAME_PATTERN = NAME_PATTERN;
  static readonly MIN_PRECEDENCE = MIN_PRECEDENCE;
  static readonly MAX_PRECEDENCE = MAX_PRECEDENCE;
  static readonly DEFAULT_PRECEDENCE = DEFAULT_PRECEDENCE;

  // THESE THREE CARRY NO Entering/Leaving PAIR: `rank()` asks them once per
  // named policy on every sign-in, and a pair would drown the log (the
  // style's hot-path exception).
  //
  // A value as matched: trimmed and lower-case; '' for nothing.
  static fold(value: unknown): string {
    return String(value === undefined || value === null ? '' : value).trim()
      .toLowerCase();
  }

  // Every value of an attribute, as strings, whatever case the entry's keys
  // are in.
  static valuesOf(attributes: Record<string, unknown> | undefined,
                  name: string): string[] {
    const at = attributes || {};
    let found = at[name];
    if (found === undefined) {
      const key = Object.keys(at).filter(function (one) {
        return one.toLowerCase() === name.toLowerCase();
      })[0];
      found = key === undefined ? undefined : at[key];
    }
    return (Array.isArray(found) ? found : (found === undefined ||
                                            found === null || found === ''
                                              ? [] : [found]))
      .map(String).filter(Boolean);
  }

  // A stored precedence, or the kind's default where it is not a number from
  // 1 to 1000.
  static precedenceOf(attributes: Record<string, unknown> | undefined,
                      spec: SelectionSpec): number {
    const p = Number(PolicySelection.valuesOf(attributes,
                                              spec.precedenceAttribute)[0]);
    return p >= MIN_PRECEDENCE && p <= MAX_PRECEDENCE ? p
      : (spec.defaultPrecedence || DEFAULT_PRECEDENCE);
  }

  /**
   * Reads a realm's named policies — every entry but `default` — with their
   * precedence and groups.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's selector attributes
   * @returns the named policies, unordered
   */
  static named(entries: PolicyEntry[] | null | undefined,
               spec: SelectionSpec): NamedPolicy[] {
    log.debug("Entering PolicySelection.named().");
    const out = (Array.isArray(entries) ? entries : []).filter(function (one) {
      const name = PolicySelection.fold(one && one.name);
      return !!name && name !== DEFAULT_NAME;
    }).map(function (entry) {
      const at = entry.attributes || {};
      return {
        name: PolicySelection.fold(entry.name),
        dn: String(entry.dn || ''),
        precedence: PolicySelection.precedenceOf(at, spec),
        groups: spec.groupAttribute
          ? PolicySelection.valuesOf(at, spec.groupAttribute) : []
      };
    });
    log.debug("Leaving PolicySelection.named(). " + out.length + ".");
    return out;
  }

  /**
   * The order every answer here ranks policies in: the lowest precedence
   * first, ties by name.
   *
   * @param a - one policy
   * @param b - another
   * @returns the comparison
   */
  static compare(a: { name: string; precedence: number },
                 b: { name: string; precedence: number }): number {
    return a.precedence - b.precedence ||
      (a.name < b.name ? -1 : (a.name > b.name ? 1 : 0));
  }

  /**
   * Chooses the policy that applies: of the policies the references name and
   * the named policies selecting one of the person's groups, the lowest
   * precedence (ties by name), else `default`.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's selector attributes
   * @param references - what the application and the person name; an empty
   *   value or `default` is no candidate
   * @param groups - the person's groups, `{ cn, dn }`; empty for nobody yet
   * @returns `{ name, by, precedence, missing }`: the winner, what selected
   *   it (`group`, a reference's `by`, or `default`), its precedence (0 for
   *   `default`), and each reference to a name the realm does not hold
   */
  static rank(entries: PolicyEntry[] | null | undefined, spec: SelectionSpec,
              references: Reference[] | null | undefined,
              groups: GroupRef[] | null | undefined): Ranked {
    log.debug("Entering PolicySelection.rank().");
    const named = PolicySelection.named(entries, spec);
    const byName: Record<string, NamedPolicy> = {};
    named.forEach(function (one) {
      byName[one.name] = one;
    });
    const missing: Array<{ by: string; name: string }> = [];
    const candidates: Array<{ name: string; precedence: number;
                              by: string }> = [];
    (Array.isArray(references) ? references : []).forEach(function (ref) {
      const wanted = PolicySelection.fold(ref && ref.value);
      if (!wanted || wanted === DEFAULT_NAME) {
        return;
      }
      const held = byName[wanted];
      if (!held) {
        missing.push({ by: String(ref.by || ''), name: wanted });
        return;
      }
      candidates.push({ name: held.name, precedence: held.precedence,
                        by: String(ref.by || '') });
    });
    const mine: string[] = [];
    (Array.isArray(groups) ? groups : []).forEach(function (g) {
      [PolicySelection.fold(g && g.cn), PolicySelection.fold(g && g.dn)]
        .forEach(function (one) {
          if (one) {
            mine.push(one);
          }
        });
    });
    if (mine.length) {
      named.forEach(function (one) {
        if (one.groups.some(function (g) {
          return mine.indexOf(PolicySelection.fold(g)) >= 0;
        })) {
          candidates.push({ name: one.name, precedence: one.precedence,
                            by: 'group' });
        }
      });
    }
    candidates.sort(PolicySelection.compare);
    const won = candidates[0];
    const out = won
      ? { name: won.name, by: won.by, precedence: won.precedence,
          missing: missing }
      : { name: DEFAULT_NAME, by: DEFAULT_NAME, precedence: 0,
          missing: missing };
    log.debug("Leaving PolicySelection.rank(). " + out.name + " by " +
              out.by + "; " + missing.length + " missing.");
    return out;
  }

  /**
   * What one holder's reference comes to before any person is known — the
   * application page's answer (#609's, generalised): the policy it names,
   * whether the realm holds it, what applies, and how many named policies
   * select by group and could still win for a person.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's selector attributes
   * @param value - the holder's reference value
   * @returns `{ named, missing, applies, precedence, groupPolicies }`
   */
  static forReference(entries: PolicyEntry[] | null | undefined,
                      spec: SelectionSpec, value: unknown):
      { named: string; missing: boolean; applies: string;
        precedence: number; groupPolicies: number } {
    log.debug("Entering PolicySelection.forReference().");
    const ranked = PolicySelection.rank(entries, spec,
                                        [{ by: 'reference', value: value }],
                                        []);
    const groupPolicies = PolicySelection.named(entries, spec)
      .filter(function (one) {
        return one.groups.length > 0;
      }).length;
    const out = { named: PolicySelection.fold(value) || DEFAULT_NAME,
                  missing: ranked.missing.length > 0,
                  applies: ranked.name, precedence: ranked.precedence,
                  groupPolicies: groupPolicies };
    log.debug("Leaving PolicySelection.forReference(). " + out.applies);
    return out;
  }

  /**
   * Refuses a name no named policy may have: `default` is the realm's own,
   * and a cn is lower-case letters, digits and hyphens, at most 64.
   *
   * @param name - the name given
   * @param noun - what the kind calls one (`passkey policy`)
   * @param allowDefault - true where `default` is a name this act takes
   * @returns the refusal, or null
   */
  static nameProblem(name: unknown, noun: string,
                     allowDefault: boolean): string | null {
    log.debug("Entering PolicySelection.nameProblem().");
    const text = PolicySelection.fold(name);
    if (text === DEFAULT_NAME) {
      log.debug("Leaving PolicySelection.nameProblem(). default.");
      return allowDefault ? null
        : 'A named ' + noun + ' cannot be called "' + DEFAULT_NAME + '": ' +
          'that is the realm\'s own.';
    }
    if (!NAME_PATTERN.test(text)) {
      log.debug("Leaving PolicySelection.nameProblem(). Malformed.");
      return 'A ' + noun + ' is "' + DEFAULT_NAME + '" or a name of ' +
             'lower-case letters, digits and hyphens, at most 64; "' +
             String(name === undefined || name === null ? '' : name)
               .slice(0, 64) + '" is neither.';
    }
    log.debug("Leaving PolicySelection.nameProblem().");
    return null;
  }

  /**
   * Validates a named policy's selectors as a save sends them: its groups (a
   * list, or comma- or line-separated; trimmed, at most `maxValues` of at most
   * `maxLength` characters with no control character) and its precedence (a
   * whole number from 1 to 1000; the kind's default when omitted).
   *
   * @param given - the save's body: `selectGroups` and `precedence`
   * @param spec - the kind's selector attributes; no `groupAttribute` means
   *   the kind has no group selector and `selectGroups` is ignored
   * @param limits - optional `{ maxValues, maxLength }`; 64 and 512
   * @returns `{ groups, precedence, problems }`
   */
  static checkSelectors(given: Record<string, unknown> | null | undefined,
                        spec: SelectionSpec,
                        limits?: { maxValues?: number; maxLength?: number }):
      { groups: string[]; precedence: number; problems: string[] } {
    log.debug("Entering PolicySelection.checkSelectors().");
    const body = given || {};
    const problems: string[] = [];
    const most = (limits && limits.maxValues) || 64;
    const longest = (limits && limits.maxLength) || 512;
    let groups: string[] = [];
    if (spec.groupAttribute) {
      const raw = body.selectGroups;
      groups = (Array.isArray(raw) ? raw : String(raw === undefined ||
                                                  raw === null ? '' : raw)
        .split(/[,\n]/)).map(function (one) {
          return String(one).trim();
        }).filter(Boolean);
      if (groups.length > most || groups.some(function (one) {
        return one.length > longest || /[\u0000-\u001f\u007f]/.test(one);
      })) {
        problems.push('The groups a named policy applies to must be at most ' +
                      most + ' values of at most ' + longest + ' characters ' +
                      'each, with no control character.');
      }
      groups = groups.slice(0, most);
    }
    const raw = body.precedence;
    const text = String(raw === undefined || raw === null || raw === ''
      ? (spec.defaultPrecedence || DEFAULT_PRECEDENCE) : raw).trim();
    let precedence = spec.defaultPrecedence || DEFAULT_PRECEDENCE;
    if (!/^[0-9]{1,4}$/.test(text) || Number(text) < MIN_PRECEDENCE ||
        Number(text) > MAX_PRECEDENCE) {
      problems.push('The precedence of a named policy is a whole number ' +
                    'from ' + MIN_PRECEDENCE + ' to ' + MAX_PRECEDENCE + '; "' +
                    text.slice(0, 40) + '" is not.');
    } else {
      precedence = Number(text);
    }
    log.debug("Leaving PolicySelection.checkSelectors(). " + problems.length +
              " problem(s).");
    return { groups: groups, precedence: precedence, problems: problems };
  }

  /**
   * Words the refusal of a named policy's delete while something still names
   * it — an application or a person would be left naming a policy the realm
   * does not hold. A policy that selects a group is not refused: the
   * selection is on the policy and goes with it.
   *
   * @param noun - what the kind calls one (`passkey policy`)
   * @param name - the policy's name
   * @param holders - `{ applications, people }`, each a list of names
   * @returns the refusal, or null where nothing names it
   */
  static deleteProblem(noun: string, name: string,
                       holders: { applications?: string[];
                                  people?: string[] }): string | null {
    log.debug("Entering PolicySelection.deleteProblem().");
    const apps = (holders && holders.applications) || [];
    const people = (holders && holders.people) || [];
    if (!apps.length && !people.length) {
      log.debug("Leaving PolicySelection.deleteProblem(). Named by nobody.");
      return null;
    }
    const shown = function (list: string[]): string {
      log.debug("Entering deleteProblem() shown().");
      log.debug("Leaving deleteProblem() shown().");
      return list.slice(0, 10).join(', ') +
        (list.length > 10 ? ' and ' + (list.length - 10) + ' more' : '');
    };
    const parts: string[] = [];
    if (apps.length) {
      parts.push('the application(s) ' + shown(apps));
    }
    if (people.length) {
      parts.push('the person or people ' + shown(people));
    }
    log.debug("Leaving PolicySelection.deleteProblem(). Named.");
    return 'The ' + noun + ' "' + name + '" is still named by ' +
      parts.join(' and ') + '. Point them at another policy, or at ' +
      '`default`, first.';
  }
};
