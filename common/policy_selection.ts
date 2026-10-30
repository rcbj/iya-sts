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
// `cn=default`, and rcbj's decisions on #1234 (2026-10-30, twice that day)
// say how one is chosen, once, for all of them:
//
//   * WHAT A POLICY COVERS NAMES IT; THE POLICY LISTS NOTHING. One
//     single-valued attribute per kind on each kind of holder the kind maps
//     to: on the application `app<Kind>Policy` (as `appAuthnPolicy` has done
//     since #1148), and on the person and the group `sts<Kind>Policy`. A
//     named policy keeps only its rows and its PRECEDENCE
//     (`sts<Kind>Precedence`, 1 to 1000).
//   * THE CANDIDATES are the policy the application names, the policy the
//     person names, and the policy each of the person's groups names. THE
//     LOWEST PRECEDENCE WINS, ties broken by name (#535's rule), and
//     `default` applies where there is no candidate. A reference that is
//     empty or says `default` is no candidate.
//   * A REFERENCE TO A NAME THE REALM DOES NOT HOLD is no candidate either,
//     and is handed back in `missing`: what it MEANS is the kind's (the
//     authentication policy fails closed, #1148; the passkey policy reads its
//     baseline), so this file decides nothing about it.
//   * A REFERENCE IS CHECKED AT THE WRITE (`default` or a named policy the
//     realm holds), and A POLICY SOMETHING NAMES IS NOT DELETED.
//
// Matching is trimmed and case-insensitive: a reference by the policy's name.
//
// IT IS A LEAF (rule 3): static methods over values the caller hands in — the
// realm's named entries and the references — so it reads no directory,
// requires nothing of this service but the logger, and cannot join a require
// cycle. Who REFERENCES a policy is each register's own question, asked by
// the kind, lazily: `applications.js`' `applicationsNamingPolicy()`, and the
// directory's `groupsNamingPolicy()` (its group index) and
// `peopleNamingPolicyAsync()` (the holders of the attribute).
//
// ITS ONE PIECE OF STATE is the register of PERSON and GROUP references
// (`declareReference()`): a kind declares its attribute here when its module
// loads, and the person editor and the directory's group writer read the
// register, so the person page and the group page draw one picker per kind
// (a closed set: `default` and the realm's named policies, checked at the
// write) without either requiring any kind's module. The application side
// needs no register here: an application's fields are declared in
// `applications.js`, which checks a reference with its own closed sets
// (CHOICES_CHECKED_HERE).
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
 * How a kind's named policies rank: the attribute holding a policy's
 * precedence, and the kind's default precedence.
 */
interface SelectionSpec {
  precedenceAttribute: string;
  defaultPrecedence?: number;
}

/**
 * What names a policy: an application's, a person's or a group's reference
 * attribute's value. `by` is what the caller calls the holder
 * (`application`, `person`, `group`), and `holder` which one it is.
 */
interface Reference {
  by: string;
  holder?: string;
  value: unknown;
}

/**
 * One named policy, read.
 */
interface NamedPolicy {
  name: string;
  dn: string;
  precedence: number;
}

/**
 * The answer of `rank()`.
 */
interface Ranked {
  name: string;
  by: string;
  holder: string;
  precedence: number;
  missing: Array<{ by: string; holder: string; name: string }>;
}

/**
 * A reference a kind declared on a person or a group: its attribute, what
 * the kind calls a policy, and where its choices come from.
 */
interface DeclaredReference {
  holder: string;
  attribute: string;
  noun: string;
  choices: () => string[];
}

/**
 * The references declared so far (`declareReference()`).
 */
const DECLARED: DeclaredReference[] = [];

/**
 * The holders a reference may be declared on.
 */
const HOLDERS = ['person', 'group'];
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
 * A static utility class; its one state is the register of declared
 * references.
 */
export = class PolicySelection {
  static readonly DEFAULT_NAME = DEFAULT_NAME;
  static readonly NAME_PATTERN = NAME_PATTERN;
  static readonly MIN_PRECEDENCE = MIN_PRECEDENCE;
  static readonly MAX_PRECEDENCE = MAX_PRECEDENCE;
  static readonly DEFAULT_PRECEDENCE = DEFAULT_PRECEDENCE;

  // THESE THREE CARRY NO Entering/Leaving PAIR: `rank()` asks them once per
  // named policy and per reference on every sign-in, and a pair would drown
  // the log (the style's hot-path exception).
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
   * precedence.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's precedence attribute
   * @returns the named policies, unordered
   */
  static named(entries: PolicyEntry[] | null | undefined,
               spec: SelectionSpec): NamedPolicy[] {
    log.debug("Entering PolicySelection.named().");
    const out = (Array.isArray(entries) ? entries : []).filter(function (one) {
      const name = PolicySelection.fold(one && one.name);
      return !!name && name !== DEFAULT_NAME;
    }).map(function (entry) {
      return {
        name: PolicySelection.fold(entry.name),
        dn: String(entry.dn || ''),
        precedence: PolicySelection.precedenceOf(entry.attributes || {}, spec)
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
   * Chooses the policy that applies: of the policies the references name —
   * the application's, the person's, each of the person's groups' — the
   * lowest precedence (ties by name), else `default`.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's precedence attribute
   * @param references - every reference in hand; an empty value or
   *   `default` is no candidate
   * @returns `{ name, by, holder, precedence, missing }`: the winner, what
   *   named it (a reference's `by` and `holder`, or `default`), its
   *   precedence (0 for `default`), and each reference to a name the realm
   *   does not hold
   */
  static rank(entries: PolicyEntry[] | null | undefined, spec: SelectionSpec,
              references: Reference[] | null | undefined): Ranked {
    log.debug("Entering PolicySelection.rank().");
    const byName: Record<string, NamedPolicy> = {};
    PolicySelection.named(entries, spec).forEach(function (one) {
      byName[one.name] = one;
    });
    const missing: Array<{ by: string; holder: string; name: string }> = [];
    const candidates: Array<{ name: string; precedence: number; by: string;
                              holder: string }> = [];
    (Array.isArray(references) ? references : []).forEach(function (ref) {
      const wanted = PolicySelection.fold(ref && ref.value);
      if (!wanted || wanted === DEFAULT_NAME) {
        return;
      }
      const by = String((ref && ref.by) || '');
      const holder = String((ref && ref.holder) || '');
      const held = byName[wanted];
      if (!held) {
        missing.push({ by: by, holder: holder, name: wanted });
        return;
      }
      candidates.push({ name: held.name, precedence: held.precedence,
                        by: by, holder: holder });
    });
    candidates.sort(PolicySelection.compare);
    const won = candidates[0];
    const out = won
      ? { name: won.name, by: won.by, holder: won.holder,
          precedence: won.precedence, missing: missing }
      : { name: DEFAULT_NAME, by: DEFAULT_NAME, holder: '', precedence: 0,
          missing: missing };
    log.debug("Leaving PolicySelection.rank(). " + out.name + " by " +
              out.by + "; " + missing.length + " missing.");
    return out;
  }

  /**
   * The references a person's groups make, as `rank()` takes them: one per
   * group whose reference attribute names something.
   *
   * @param groups - the person's groups, each `{ cn, dn, value }` as the
   *   directory's `personGroupReferences()` answers them
   * @returns the references, `by: 'group'`, `holder` the group's cn or DN
   */
  static groupReferences(groups: Array<{ cn?: unknown; dn?: unknown;
                                         value?: unknown }> | null |
                                   undefined): Reference[] {
    log.debug("Entering PolicySelection.groupReferences().");
    const out = (Array.isArray(groups) ? groups : []).filter(function (g) {
      return !!PolicySelection.fold(g && g.value);
    }).map(function (g) {
      return { by: 'group', holder: String(g.cn || g.dn || ''),
               value: g.value };
    });
    log.debug("Leaving PolicySelection.groupReferences(). " + out.length);
    return out;
  }

  /**
   * What one holder's reference comes to on its own — the application
   * page's answer (#609's, generalised): the policy it names, whether the
   * realm holds it, and what applies before anything else is known.
   *
   * @param entries - the kind's entries as the directory hook answers them
   * @param spec - the kind's precedence attribute
   * @param value - the holder's reference value
   * @returns `{ named, missing, applies, precedence }`
   */
  static forReference(entries: PolicyEntry[] | null | undefined,
                      spec: SelectionSpec, value: unknown):
      { named: string; missing: boolean; applies: string;
        precedence: number } {
    log.debug("Entering PolicySelection.forReference().");
    const ranked = PolicySelection.rank(entries, spec,
                                        [{ by: 'reference', value: value }]);
    const out = { named: PolicySelection.fold(value) || DEFAULT_NAME,
                  missing: ranked.missing.length > 0,
                  applies: ranked.name, precedence: ranked.precedence };
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
   * Validates a named policy's precedence as a save sends it: a whole number
   * from 1 to 1000, the kind's default when omitted.
   *
   * @param given - the save's body: `precedence`
   * @param spec - the kind's precedence attribute and default
   * @returns `{ precedence, problems }`
   */
  static checkPrecedence(given: Record<string, unknown> | null | undefined,
                         spec: SelectionSpec):
      { precedence: number; problems: string[] } {
    log.debug("Entering PolicySelection.checkPrecedence().");
    const body = given || {};
    const problems: string[] = [];
    const fallback = spec.defaultPrecedence || DEFAULT_PRECEDENCE;
    const raw = body.precedence;
    const text = String(raw === undefined || raw === null || raw === ''
      ? fallback : raw).trim();
    let precedence = fallback;
    if (!/^[0-9]{1,4}$/.test(text) || Number(text) < MIN_PRECEDENCE ||
        Number(text) > MAX_PRECEDENCE) {
      problems.push('The precedence of a named policy is a whole number ' +
                    'from ' + MIN_PRECEDENCE + ' to ' + MAX_PRECEDENCE + '; "' +
                    text.slice(0, 40) + '" is not.');
    } else {
      precedence = Number(text);
    }
    log.debug("Leaving PolicySelection.checkPrecedence(). " +
              problems.length + " problem(s).");
    return { precedence: precedence, problems: problems };
  }

  /**
   * Refuses a reference that names neither `default` nor a policy the realm
   * holds — the write-time check every holder's door makes.
   *
   * @param value - the value written; '' clears it and is always allowed
   * @param choices - `default` and the realm's named policies
   * @param attribute - the reference attribute, for the sentence
   * @returns the refusal, or null
   */
  static referenceProblem(value: unknown, choices: string[],
                          attribute: string): string | null {
    log.debug("Entering PolicySelection.referenceProblem().");
    const text = PolicySelection.fold(value);
    if (!text || (choices || []).map(PolicySelection.fold)
      .indexOf(text) >= 0) {
      log.debug("Leaving PolicySelection.referenceProblem(). Allowed.");
      return null;
    }
    log.debug("Leaving PolicySelection.referenceProblem(). Not held.");
    return 'The value for ' + attribute + ' is "' + DEFAULT_NAME + '" or a ' +
      'named policy of this realm (' + (choices || []).join(', ') + '); "' +
      String(value).slice(0, 80) + '" is neither.';
  }

  /**
   * Declares a reference (#1235): the single-valued attribute on a person's
   * or a group's entry by which it names its policy of a kind. Called once,
   * when the kind's module loads; a second declaration of the holder and
   * attribute replaces the first.
   *
   * @param holder - `person` or `group`
   * @param attribute - the attribute (`stsPasskeyPolicy`)
   * @param noun - what the kind calls a policy (`passkey policy`)
   * @param choices - answers the realm's named policies' names, read when
   *   asked, so a policy saved a moment ago is a choice at once
   */
  static declareReference(holder: string, attribute: string, noun: string,
                          choices: () => string[]): void {
    log.debug("Entering PolicySelection.declareReference(). " + holder +
              " " + attribute);
    if (HOLDERS.indexOf(holder) < 0) {
      log.debug("Leaving PolicySelection.declareReference(). Not a holder.");
      throw new Error('policy_selection: a reference is declared on a ' +
                      'person or a group, not "' + holder + '".');
    }
    PolicySelection.withdrawReference(holder, attribute);
    DECLARED.push({ holder: holder, attribute: String(attribute),
                    noun: noun, choices: choices });
    log.debug("Leaving PolicySelection.declareReference().");
  }

  /**
   * Withdraws a declared reference — for a test that declared one.
   *
   * @param holder - `person` or `group`
   * @param attribute - the attribute
   */
  static withdrawReference(holder: string, attribute: string): void {
    log.debug("Entering PolicySelection.withdrawReference().");
    const key = String(attribute || '').toLowerCase();
    for (let n = DECLARED.length - 1; n >= 0; n--) {
      if (DECLARED[n].holder === holder &&
          DECLARED[n].attribute.toLowerCase() === key) {
        DECLARED.splice(n, 1);
      }
    }
    log.debug("Leaving PolicySelection.withdrawReference().");
  }

  /**
   * The reference an attribute is on a holder, with its choices now:
   * `default` first, then the realm's named policies. A source that cannot
   * be read offers `default` alone.
   *
   * @param holder - `person` or `group`
   * @param attribute - an attribute name, in any case
   * @returns `{ attribute, noun, choices }`, or null for an attribute no
   *   kind declared on that holder
   */
  static referenceOf(holder: string, attribute: string):
      { attribute: string; noun: string; choices: string[] } | null {
    log.debug("Entering PolicySelection.referenceOf().");
    const key = String(attribute || '').toLowerCase();
    const found = DECLARED.filter(function (one) {
      return one.holder === holder && one.attribute.toLowerCase() === key;
    })[0];
    if (!found) {
      log.debug("Leaving PolicySelection.referenceOf(). None.");
      return null;
    }
    let names: string[] = [];
    try {
      names = (found.choices() || []).map(PolicySelection.fold);
    } catch (e) {
      log.debug("Caught in PolicySelection.referenceOf(): " +
                ((e && e.message) || e));
      names = [];
    }
    const choices = [DEFAULT_NAME].concat(names.filter(function (one, n, all) {
      return !!one && one !== DEFAULT_NAME && all.indexOf(one) === n;
    }));
    log.debug("Leaving PolicySelection.referenceOf(). " + choices.length +
              " choice(s).");
    return { attribute: found.attribute, noun: found.noun,
             choices: choices };
  }

  /**
   * Every reference declared on a holder, with its choices now — what the
   * group page draws one picker for each of.
   *
   * @param holder - `person` or `group`
   * @returns `[{ attribute, noun, choices }]`, in declaration order
   */
  static referencesOn(holder: string):
      Array<{ attribute: string; noun: string; choices: string[] }> {
    log.debug("Entering PolicySelection.referencesOn(). " + holder);
    const out = DECLARED.filter(function (one) {
      return one.holder === holder;
    }).map(function (one) {
      return PolicySelection.referenceOf(holder, one.attribute);
    }).filter(Boolean);
    log.debug("Leaving PolicySelection.referencesOn(). " + out.length);
    return out;
  }

  /**
   * Words the refusal of a named policy's delete while something still names
   * it — an application, a person or a group would be left naming a policy
   * the realm does not hold.
   *
   * @param noun - what the kind calls one (`passkey policy`)
   * @param name - the policy's name
   * @param holders - `{ applications, people, groups }`, each a list
   * @returns the refusal, or null where nothing names it
   */
  static deleteProblem(noun: string, name: string,
                       holders: { applications?: string[];
                                  people?: string[];
                                  groups?: string[] }): string | null {
    log.debug("Entering PolicySelection.deleteProblem().");
    const lists: Array<[string, string[]]> = [
      ['the application(s) ', (holders && holders.applications) || []],
      ['the group(s) ', (holders && holders.groups) || []],
      ['the person or people ', (holders && holders.people) || []]
    ];
    const shown = function (list: string[]): string {
      log.debug("Entering deleteProblem() shown().");
      log.debug("Leaving deleteProblem() shown().");
      return list.slice(0, 10).join(', ') +
        (list.length > 10 ? ' and ' + (list.length - 10) + ' more' : '');
    };
    const parts = lists.filter(function (one) {
      return one[1].length > 0;
    }).map(function (one) {
      return one[0] + shown(one[1]);
    });
    if (!parts.length) {
      log.debug("Leaving PolicySelection.deleteProblem(). Named by nobody.");
      return null;
    }
    log.debug("Leaving PolicySelection.deleteProblem(). Named.");
    return 'The ' + noun + ' "' + name + '" is still named by ' +
      parts.join(' and ') + '. Point them at another policy, or at ' +
      '`default`, first.';
  }
};
