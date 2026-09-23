'use strict';
//
// File: metadata_policy.ts
//
// ===========================================================================
// OPENID FEDERATION 1.1 SECTION 6: METADATA POLICY AND CONSTRAINTS (#132,
// #133, 2026-09-23).
//
// A superior in a federation does not only vouch for its subordinates' keys;
// it says what their metadata may be. A Trust Anchor states that every
// relying party below it signs with PS256 or ES256, an Intermediate narrows
// that to ES256, and the leaf's own Entity Configuration is then READ
// THROUGH both before anybody uses it. This file is that reading: the seven
// standard operators, the validation of one statement's policy, the MERGE of
// the policies down a chain (section 6.1.4.1) and their APPLICATION to the
// subject's metadata (6.1.4.2), and the three constraints of section 6.2.
//
// **A PURE LIBRARY, AND DELIBERATELY SO.** It fetches nothing, signs nothing
// and reads no setting: a policy and a metadata object go in, a result or a
// policy error comes out. `trust_chain.ts` decides WHICH statements are
// merged — after it has verified every signature on them — and this file
// only does the arithmetic, which is what makes it testable against the
// specification's own examples (section 6.1.5 and table 1 of 6.1.3.1.8,
// both in `tests/oidfed_metadata_policy.js`).
//
// ---------------------------------------------------------------------------
// WHAT A POLICY ERROR MEANS, AND WHY IT IS NEVER SOFTENED.
//
// Section 6.1.4: "if a policy error or another error is encountered during
// the metadata policy resolution or its application, the Trust Chain MUST be
// considered invalid." There is no partial result here — a chain whose
// Intermediate contradicts its Trust Anchor is not a chain with some of the
// Trust Anchor's policy applied, it is no chain at all. So every function
// answers `{ ok: false, code, why }` and the caller refuses the whole chain
// (`invalid_trust_chain` or `invalid_metadata`, section 8.9). The `why`
// names the parameter and the operator, for the operator reading the log.
//
// ---------------------------------------------------------------------------
// THE DECISIONS THE SPECIFICATION LEFT TO AN IMPLEMENTATION, AND THESE ANSWERS.
//
//   * OBJECTS AS VALUES (6.1.3.1.8 makes them optional for every operator but
//     `essential`). Supported everywhere: values are compared by a key-sorted
//     serialisation, so `{"a":1,"b":2}` equals `{"b":2,"a":1}`. A federation
//     that uses object values is not refused for it.
//   * `value: null` beside `one_of`, `subset_of` or `superset_of`. The text
//     says `value` MUST be among / a subset of / a superset of the other's
//     values, which `null` is not — but `null` REMOVES the parameter, and an
//     absent parameter passes each of those three checks by their own
//     definitions ("if the metadata parameter is present"). Allowed, because
//     refusing it would refuse a policy whose result the same specification
//     calls valid. `null` beside `add` is refused (the parameter would be
//     removed and then re-created, which is two policies at war), beside
//     `default` (6.1.3.1.1 says so) and beside `essential: true` (likewise).
//   * ADDITIONAL OPERATORS. This service understands none, so an operator
//     outside the seven is DROPPED during resolution (6.1.3.2: "MUST ignore
//     additional operators that are not understood") unless a statement in
//     the chain lists it in `metadata_policy_crit`, in which case the chain
//     is refused.
//   * `scope` (6.1.3.1.8) is a space-separated string in RFC 7591 metadata
//     and is treated as an array of its values by every operator, then
//     joined again. Any OTHER string parameter an array operator meets is a
//     type error, not a one-element array.
// ===========================================================================

import helpers = require('../common/helpers');

type Json = any;

const log = helpers.log;

// The standard operators, in their ORDER OF APPLICATION (6.1.3.1): `value`
// first, `essential` last, the rest each "after" the one before it.
const OPERATORS = Object.freeze(['value', 'add', 'default', 'one_of',
                                 'subset_of', 'superset_of', 'essential']);

// The operator pairs that may NOT share a parameter policy. Each operator's
// definition lists what it MAY be combined with; these three pairs are the
// ones no list admits (one_of names value, default and essential only).
const FORBIDDEN_PAIRS: [string, string][] = [
  ['one_of', 'add'], ['one_of', 'subset_of'], ['one_of', 'superset_of']
];

// The parameter policies' error codes (common/error_codes.js, OIDFED).
const CODE_STRUCTURE = 'STS-OIDFED-0001';
const CODE_COMBINATION = 'STS-OIDFED-0002';
const CODE_MERGE = 'STS-OIDFED-0003';
const CODE_CRITICAL = 'STS-OIDFED-0004';
const CODE_APPLICATION = 'STS-OIDFED-0005';
const CODE_ESSENTIAL = 'STS-OIDFED-0006';
const CODE_PATH_LENGTH = 'STS-OIDFED-0007';
const CODE_NAMING = 'STS-OIDFED-0008';
const CODE_CONSTRAINTS = 'STS-OIDFED-0009';

interface Outcome {
  ok: boolean;
  code?: string;
  why?: string;
  policy?: Json;
  metadata?: Json;
}

class MetadataPolicy {
  static readonly OPERATORS = OPERATORS;

  // -------------------------------------------------------------------------
  // VALUE COMPARISON. A key-sorted serialisation, so that two JSON objects
  // with the same members in a different order are equal — the comparison
  // 6.1.3.1.8 warns libraries get wrong. Not canonicalisation for a
  // signature (that is `crypto.js`'s); only a stable key for equality.
  // -------------------------------------------------------------------------
  static stable(value: Json): string {
    log.debug("Entering MetadataPolicy.stable().");
    // A HOT PATH: called once per JSON value, recursively, for every value
    // every operator compares — no Entering/Leaving pair here, it would drown
    // the log in two lines per array member.
    const walk = function (v: Json): string {
      if (Array.isArray(v)) {
        return '[' + v.map(walk).join(',') + ']';
      }
      if (v && typeof v === 'object') {
        return '{' + Object.keys(v).sort().map(function (k: string): string {
          return JSON.stringify(k) + ':' + walk(v[k]);
        }).join(',') + '}';
      }
      return JSON.stringify(v);
    };
    const out = walk(value);
    log.debug("Leaving MetadataPolicy.stable().");
    return out;
  }

  static same(a: Json, b: Json): boolean {
    log.debug("Entering MetadataPolicy.same().");
    log.debug("Leaving MetadataPolicy.same().");
    return MetadataPolicy.stable(a) === MetadataPolicy.stable(b);
  }

  // Is every member of `small` in `big`? (Arrays; values compared stably.)
  static subsetOf(small: Json[], big: Json[]): boolean {
    log.debug("Entering MetadataPolicy.subsetOf().");
    const keys = big.map(MetadataPolicy.stable);
    const out = small.every(function (one: Json): boolean {
      return keys.indexOf(MetadataPolicy.stable(one)) >= 0;
    });
    log.debug("Leaving MetadataPolicy.subsetOf(). " + out);
    return out;
  }

  // The union and the intersection, keeping the FIRST array's order and
  // never repeating a value — the arrays these operators produce are sets.
  static union(a: Json[], b: Json[]): Json[] {
    log.debug("Entering MetadataPolicy.union().");
    const seen: string[] = [];
    const out: Json[] = [];
    a.concat(b).forEach(function (one: Json): void {
      const key = MetadataPolicy.stable(one);
      if (seen.indexOf(key) < 0) {
        seen.push(key);
        out.push(one);
      }
    });
    log.debug("Leaving MetadataPolicy.union(). " + out.length);
    return out;
  }

  static intersection(a: Json[], b: Json[]): Json[] {
    log.debug("Entering MetadataPolicy.intersection().");
    const keys = b.map(MetadataPolicy.stable);
    const out = MetadataPolicy.union(a, []).filter(function (one: Json) {
      return keys.indexOf(MetadataPolicy.stable(one)) >= 0;
    });
    log.debug("Leaving MetadataPolicy.intersection(). " + out.length);
    return out;
  }

  private static refuse(code: string, why: string): Outcome {
    log.debug("Entering MetadataPolicy.refuse(). " + code);
    log.debug("Leaving MetadataPolicy.refuse().");
    return { ok: false, code: code, why: why };
  }

  private static plainObject(v: Json): boolean {
    log.debug("Entering MetadataPolicy.plainObject().");
    log.debug("Leaving MetadataPolicy.plainObject().");
    return !!v && typeof v === 'object' && !Array.isArray(v);
  }

  // -------------------------------------------------------------------------
  // ONE OPERATOR'S CONFIGURED VALUE, CHECKED FOR ITS TYPE (6.1.3: "when the
  // operator is configured with a JSON value type that is not supported,
  // the operator MUST produce a policy error"). '' when it is acceptable.
  // -------------------------------------------------------------------------
  static operatorValueProblem(op: string, v: Json): string {
    log.debug("Entering MetadataPolicy.operatorValueProblem(). " + op);
    let problem = '';
    if (op === 'value') {
      problem = v === undefined ? 'has no value' : '';
    } else if (op === 'default') {
      problem = (v === undefined || v === null)
        ? 'may not be null (6.1.3.1.3)' : '';
    } else if (op === 'essential') {
      problem = typeof v === 'boolean' ? '' : 'must be a boolean';
    } else if (op === 'add' || op === 'one_of' || op === 'subset_of' ||
               op === 'superset_of') {
      problem = Array.isArray(v) ? '' : 'must be an array';
      if (!problem && v.some(function (one: Json): boolean {
        return one === null || Array.isArray(one);
      })) {
        problem = 'may hold strings, numbers and objects only';
      }
    }
    log.debug("Leaving MetadataPolicy.operatorValueProblem(). " +
              (problem || 'fine'));
    return problem;
  }

  // -------------------------------------------------------------------------
  // THE COMBINATION RULES OF ONE PARAMETER POLICY (6.1.3.1), applied to a
  // single statement's policy AND to the merged one: a merge of two valid
  // policies can produce an invalid combination (a Trust Anchor's
  // `value: ["a"]` and an Intermediate's `subset_of: ["b"]`), and 6.1.4.1
  // says that too is a policy error. '' when the combination is allowed.
  // -------------------------------------------------------------------------
  static combinationProblem(ops: Json): string {
    log.debug("Entering MetadataPolicy.combinationProblem().");
    const has = function (name: string): boolean {
      log.debug("Entering has(). " + name);
      log.debug("Leaving has().");
      return Object.prototype.hasOwnProperty.call(ops, name);
    };
    for (let i = 0; i < FORBIDDEN_PAIRS.length; i++) {
      const pair = FORBIDDEN_PAIRS[i];
      if (has(pair[0]) && has(pair[1])) {
        log.debug("Leaving MetadataPolicy.combinationProblem(). Forbidden.");
        return pair[0] + ' may not be combined with ' + pair[1];
      }
    }
    const arrayOf = function (v: Json): Json[] | null {
      log.debug("Entering arrayOf().");
      log.debug("Leaving arrayOf().");
      return Array.isArray(v) ? v : null;
    };
    let problem = '';
    if (has('value')) {
      const v = ops.value;
      if (v === null) {
        if (has('add')) {
          problem = 'value null may not be combined with add';
        } else if (has('default')) {
          problem = 'value null may not be combined with default (6.1.3.1.1)';
        } else if (ops.essential === true) {
          problem = 'value null may not be combined with essential true';
        }
      } else {
        if (!problem && has('add')) {
          const values = arrayOf(v);
          if (!values || !MetadataPolicy.subsetOf(ops.add, values)) {
            problem = 'the values of add must be a subset of value';
          }
        }
        if (!problem && has('one_of') &&
            !ops.one_of.some(function (one: Json): boolean {
              return MetadataPolicy.same(one, v);
            })) {
          problem = 'value must be among the one_of values';
        }
        if (!problem && has('subset_of')) {
          const values = arrayOf(v);
          if (!values || !MetadataPolicy.subsetOf(values, ops.subset_of)) {
            problem = 'the values of value must be a subset of subset_of';
          }
        }
        if (!problem && has('superset_of')) {
          const values = arrayOf(v);
          if (!values || !MetadataPolicy.subsetOf(ops.superset_of, values)) {
            problem = 'the values of value must be a superset of superset_of';
          }
        }
      }
    }
    if (!problem && has('add') && has('subset_of') &&
        !MetadataPolicy.subsetOf(ops.add, ops.subset_of)) {
      problem = 'the values of add must be a subset of subset_of';
    }
    if (!problem && has('subset_of') && has('superset_of') &&
        !MetadataPolicy.subsetOf(ops.superset_of, ops.subset_of)) {
      problem = 'subset_of must be a superset of superset_of';
    }
    log.debug("Leaving MetadataPolicy.combinationProblem(). " +
              (problem || 'fine'));
    return problem;
  }

  // -------------------------------------------------------------------------
  // VALIDATE ONE STATEMENT'S `metadata_policy` (6.1.2, 6.1.4.1): three levels
  // of objects, every operator's value of its type, every combination
  // allowed, and no operator this service does not understand that the
  // chain declared critical. Answers `{ ok, policy }` where `policy` is the
  // statement's policy with the operators this service does not understand
  // (and nobody made critical) DROPPED — so the merge below sees only what
  // it can reason about.
  // -------------------------------------------------------------------------
  static validate(policy: Json, critical: string[]): Outcome {
    log.debug("Entering MetadataPolicy.validate().");
    if (!MetadataPolicy.plainObject(policy)) {
      log.debug("Leaving MetadataPolicy.validate(). Not an object.");
      return MetadataPolicy.refuse(CODE_STRUCTURE,
        'metadata_policy is not a JSON object.');
    }
    const out: Json = {};
    const types = Object.keys(policy);
    for (let t = 0; t < types.length; t++) {
      const type = types[t];
      const params = policy[type];
      if (!MetadataPolicy.plainObject(params)) {
        log.debug("Leaving MetadataPolicy.validate(). A type is not an " +
                  "object.");
        return MetadataPolicy.refuse(CODE_STRUCTURE,
          'metadata_policy.' + type + ' is not a JSON object.');
      }
      out[type] = {};
      const names = Object.keys(params);
      for (let p = 0; p < names.length; p++) {
        const name = names[p];
        const ops = params[name];
        if (!MetadataPolicy.plainObject(ops)) {
          log.debug("Leaving MetadataPolicy.validate(). A parameter is not " +
                    "an object.");
          return MetadataPolicy.refuse(CODE_STRUCTURE,
            'metadata_policy.' + type + '.' + name + ' is not a JSON object.');
        }
        const kept: Json = {};
        const opNames = Object.keys(ops);
        for (let o = 0; o < opNames.length; o++) {
          const op = opNames[o];
          if (OPERATORS.indexOf(op) < 0) {
            if (critical.indexOf(op) >= 0) {
              log.debug("Leaving MetadataPolicy.validate(). A critical " +
                        "operator this service does not understand.");
              return MetadataPolicy.refuse(CODE_CRITICAL,
                'metadata_policy.' + type + '.' + name + ' uses the ' +
                'operator "' + op + '", which the chain declares critical ' +
                '(metadata_policy_crit) and this service does not ' +
                'understand (6.1.3.2).');
            }
            // Not understood and not critical: ignored (6.1.3.2).
            continue;
          }
          const problem = MetadataPolicy.operatorValueProblem(op, ops[op]);
          if (problem) {
            log.debug("Leaving MetadataPolicy.validate(). An operator value.");
            return MetadataPolicy.refuse(CODE_STRUCTURE,
              'metadata_policy.' + type + '.' + name + '.' + op + ' ' +
              problem + '.');
          }
          kept[op] = ops[op];
        }
        const combination = MetadataPolicy.combinationProblem(kept);
        if (combination) {
          log.debug("Leaving MetadataPolicy.validate(). A combination.");
          return MetadataPolicy.refuse(CODE_COMBINATION,
            'metadata_policy.' + type + '.' + name + ': ' + combination +
            ' (6.1.3.1).');
        }
        out[type][name] = kept;
      }
    }
    log.debug("Leaving MetadataPolicy.validate(). " + types.length +
              " entity type(s).");
    return { ok: true, policy: out };
  }

  // -------------------------------------------------------------------------
  // MERGE A SUBORDINATE'S VALIDATED POLICY INTO THE CURRENT ONE (6.1.4.1),
  // at the three levels: an entity type or a parameter the current policy
  // lacks is copied; an operator both hold is merged by that operator's own
  // rule; and the merged parameter policy is checked for its combinations
  // again. Neither argument is changed.
  // -------------------------------------------------------------------------
  static merge(current: Json, next: Json): Outcome {
    log.debug("Entering MetadataPolicy.merge().");
    const out: Json = JSON.parse(JSON.stringify(current || {}));
    const types = Object.keys(next || {});
    for (let t = 0; t < types.length; t++) {
      const type = types[t];
      if (!out[type]) {
        out[type] = JSON.parse(JSON.stringify(next[type]));
        continue;
      }
      const names = Object.keys(next[type]);
      for (let p = 0; p < names.length; p++) {
        const name = names[p];
        const sub = next[type][name];
        if (!out[type][name]) {
          out[type][name] = JSON.parse(JSON.stringify(sub));
          continue;
        }
        const held = out[type][name];
        const ops = Object.keys(sub);
        for (let o = 0; o < ops.length; o++) {
          const op = ops[o];
          if (!Object.prototype.hasOwnProperty.call(held, op)) {
            held[op] = JSON.parse(JSON.stringify(sub[op]));
            continue;
          }
          const merged = MetadataPolicy.mergeOperator(op, held[op], sub[op]);
          if (!merged.ok) {
            log.debug("Leaving MetadataPolicy.merge(). An operator merge.");
            return MetadataPolicy.refuse(CODE_MERGE,
              'metadata_policy.' + type + '.' + name + '.' + op + ': ' +
              merged.why + ' (6.1.3.1).');
          }
          held[op] = merged.value;
        }
        const combination = MetadataPolicy.combinationProblem(held);
        if (combination) {
          log.debug("Leaving MetadataPolicy.merge(). A combination after " +
                    "merging.");
          return MetadataPolicy.refuse(CODE_COMBINATION,
            'metadata_policy.' + type + '.' + name + ', merged down the ' +
            'chain: ' + combination + ' (6.1.4.1).');
        }
      }
    }
    log.debug("Leaving MetadataPolicy.merge().");
    return { ok: true, policy: out };
  }

  // One operator's value merge, by that operator's rule.
  static mergeOperator(op: string, a: Json, b: Json): { ok: boolean;
      value?: Json; why?: string } {
    log.debug("Entering MetadataPolicy.mergeOperator(). " + op);
    let out: { ok: boolean; value?: Json; why?: string };
    if (op === 'value' || op === 'default') {
      out = MetadataPolicy.same(a, b) ? { ok: true, value: a }
        : { ok: false, why: 'two superiors set different values, and ' + op +
            ' merges only when they are equal' };
    } else if (op === 'add' || op === 'superset_of') {
      out = { ok: true, value: MetadataPolicy.union(a, b) };
    } else if (op === 'subset_of') {
      out = { ok: true, value: MetadataPolicy.intersection(a, b) };
    } else if (op === 'one_of') {
      const both = MetadataPolicy.intersection(a, b);
      out = both.length ? { ok: true, value: both }
        : { ok: false, why: 'the one_of values of two superiors do not ' +
            'intersect' };
    } else {
      out = { ok: true, value: a === true || b === true };
    }
    log.debug("Leaving MetadataPolicy.mergeOperator(). " + out.ok);
    return out;
  }

  // -------------------------------------------------------------------------
  // RESOLVE A CHAIN'S POLICY (6.1.4.1). `statements` are the SUBORDINATE
  // statements' claim sets, MOST SUPERIOR FIRST — the Trust Anchor's
  // statement about the top Intermediate, down to the subject's Immediate
  // Superior's statement about the subject. The critical operators are
  // gathered from all of them first, then each policy is validated and
  // merged in that order. `{ ok, policy }`; an empty policy when none of
  // them carries one.
  // -------------------------------------------------------------------------
  static resolve(statements: Json[]): Outcome {
    log.debug("Entering MetadataPolicy.resolve(). " + statements.length +
              " statement(s).");
    const critical: string[] = [];
    statements.forEach(function (one: Json): void {
      (Array.isArray(one && one.metadata_policy_crit)
        ? one.metadata_policy_crit : []).forEach(function (name: Json) {
        if (critical.indexOf(String(name)) < 0) {
          critical.push(String(name));
        }
      });
    });
    let policy: Json = {};
    for (let i = 0; i < statements.length; i++) {
      const raw = statements[i] && statements[i].metadata_policy;
      if (raw === undefined) {
        continue;
      }
      const valid = MetadataPolicy.validate(raw, critical);
      if (!valid.ok) {
        log.debug("Leaving MetadataPolicy.resolve(). Statement " + i +
                  " refused.");
        return valid;
      }
      const merged = MetadataPolicy.merge(policy, valid.policy);
      if (!merged.ok) {
        log.debug("Leaving MetadataPolicy.resolve(). The merge refused.");
        return merged;
      }
      policy = merged.policy;
    }
    log.debug("Leaving MetadataPolicy.resolve().");
    return { ok: true, policy: policy };
  }

  // -------------------------------------------------------------------------
  // APPLY A RESOLVED POLICY TO ONE ENTITY TYPE'S METADATA (6.1.4.2), each
  // parameter's operators in their order of application. `scope` is read as
  // its values and joined again (6.1.3.1.8). Answers `{ ok, metadata }`
  // with a NEW object; the argument is not changed.
  // -------------------------------------------------------------------------
  static applyToType(type: string, metadata: Json, policy: Json): Outcome {
    log.debug("Entering MetadataPolicy.applyToType(). " + type);
    const out: Json = JSON.parse(JSON.stringify(metadata || {}));
    const names = Object.keys(policy || {});
    for (let p = 0; p < names.length; p++) {
      const name = names[p];
      const ops = policy[name];
      const isScope = name === 'scope';
      const present = function (): boolean {
        log.debug("Entering present(). " + name);
        log.debug("Leaving present().");
        return Object.prototype.hasOwnProperty.call(out, name);
      };
      // The parameter as the operators see it: `scope` as an array.
      const read = function (): Json {
        log.debug("Entering read(). " + name);
        if (isScope && typeof out[name] === 'string') {
          log.debug("Leaving read(). scope, as its values.");
          return out[name].split(' ').filter(Boolean);
        }
        log.debug("Leaving read().");
        return out[name];
      };
      const write = function (v: Json): void {
        log.debug("Entering write(). " + name);
        out[name] = (isScope && Array.isArray(v)) ? v.join(' ') : v;
        log.debug("Leaving write().");
      };
      const fail = function (code: string, why: string): Outcome {
        log.debug("Entering fail(). " + name);
        log.debug("Leaving fail().");
        return MetadataPolicy.refuse(code,
          type + '.' + name + ': ' + why + ' (6.1.4.2).');
      };
      for (let o = 0; o < OPERATORS.length; o++) {
        const op = OPERATORS[o];
        if (!Object.prototype.hasOwnProperty.call(ops, op)) {
          continue;
        }
        const v = ops[op];
        if (op === 'value') {
          if (v === null) {
            delete out[name];
          } else {
            write(JSON.parse(JSON.stringify(v)));
          }
        } else if (op === 'add') {
          if (!present()) {
            write(JSON.parse(JSON.stringify(v)));
          } else {
            const held = read();
            if (!Array.isArray(held)) {
              log.debug("Leaving MetadataPolicy.applyToType(). add on a " +
                        "non-array.");
              return fail('STS-OIDFED-0005',
                          'add acts on an array, and the parameter is not ' +
                          'one');
            }
            write(MetadataPolicy.union(held, v));
          }
        } else if (op === 'default') {
          if (!present()) {
            write(JSON.parse(JSON.stringify(v)));
          }
        } else if (op === 'one_of') {
          if (present()) {
            const held = read();
            if (Array.isArray(held) ||
                !v.some(function (one: Json): boolean {
                  return MetadataPolicy.same(one, held);
                })) {
              log.debug("Leaving MetadataPolicy.applyToType(). one_of.");
              return fail('STS-OIDFED-0005',
                          'the value is not one of ' + JSON.stringify(v));
            }
          }
        } else if (op === 'subset_of') {
          if (present()) {
            const held = read();
            if (!Array.isArray(held)) {
              log.debug("Leaving MetadataPolicy.applyToType(). subset_of " +
                        "on a non-array.");
              return fail('STS-OIDFED-0005',
                          'subset_of acts on an array, and the parameter ' +
                          'is not one');
            }
            write(MetadataPolicy.intersection(held, v));
          }
        } else if (op === 'superset_of') {
          if (present()) {
            const held = read();
            if (!Array.isArray(held) || !MetadataPolicy.subsetOf(v, held)) {
              log.debug("Leaving MetadataPolicy.applyToType(). " +
                        "superset_of.");
              return fail('STS-OIDFED-0005',
                          'the values must include ' + JSON.stringify(v));
            }
          }
        } else if (op === 'essential') {
          if (v === true && !present()) {
            log.debug("Leaving MetadataPolicy.applyToType(). Essential and " +
                      "absent.");
            return MetadataPolicy.refuse(CODE_ESSENTIAL, type + '.' + name +
              ' is essential and absent (6.1.3.1.7).');
          }
        }
      }
      if (present() && out[name] === null) {
        // 6.1.3: "An operator MUST NOT output a metadata parameter with the
        // null value." Only a metadata value that was null to begin with can
        // reach this, and 5 forbids that too.
        log.debug("Leaving MetadataPolicy.applyToType(). A null value.");
        return fail('STS-OIDFED-0005',
                    'the result is null, which metadata may not hold');
      }
    }
    log.debug("Leaving MetadataPolicy.applyToType().");
    return { ok: true, metadata: out };
  }

  // -------------------------------------------------------------------------
  // APPLY A RESOLVED POLICY TO THE WHOLE `metadata` CLAIM: every entity type
  // the metadata holds and the policy names. A type the policy names and the
  // metadata does not hold is not created — policy constrains the metadata
  // an entity declares, it does not declare roles for it (6.1.4.2: "for
  // every Entity Type metadata ... for which a corresponding metadata
  // parameter policy is present").
  // -------------------------------------------------------------------------
  static apply(metadata: Json, policy: Json): Outcome {
    log.debug("Entering MetadataPolicy.apply().");
    const out: Json = JSON.parse(JSON.stringify(metadata || {}));
    const types = Object.keys(out);
    for (let t = 0; t < types.length; t++) {
      const type = types[t];
      if (!policy || !policy[type]) {
        continue;
      }
      const applied = MetadataPolicy.applyToType(type, out[type],
                                                 policy[type]);
      if (!applied.ok) {
        log.debug("Leaving MetadataPolicy.apply(). " + type + " refused.");
        return applied;
      }
      out[type] = applied.metadata;
    }
    log.debug("Leaving MetadataPolicy.apply().");
    return { ok: true, metadata: out };
  }

  // -------------------------------------------------------------------------
  // THE IMMEDIATE SUPERIOR'S `metadata` (3.1.1): its parameters override the
  // subject's own, for the entity types the SUBJECT declares only, and it
  // is applied BEFORE any policy (6.1.4.2). It has no effect on the
  // subject's subordinates, which is why only the last statement's is used.
  // -------------------------------------------------------------------------
  static overlay(metadata: Json, superior: Json): Json {
    log.debug("Entering MetadataPolicy.overlay().");
    const out: Json = JSON.parse(JSON.stringify(metadata || {}));
    Object.keys(superior || {}).forEach(function (type: string): void {
      if (!MetadataPolicy.plainObject(out[type]) ||
          !MetadataPolicy.plainObject(superior[type])) {
        return;
      }
      Object.keys(superior[type]).forEach(function (name: string): void {
        out[type][name] = JSON.parse(JSON.stringify(superior[type][name]));
      });
    });
    log.debug("Leaving MetadataPolicy.overlay().");
    return out;
  }

  // =========================================================================
  // CONSTRAINTS (6.2)
  // =========================================================================

  // The host of an Entity Identifier, lower-cased, or '' when it has none.
  static hostOf(entityId: string): string {
    log.debug("Entering MetadataPolicy.hostOf().");
    try {
      const host = new URL(String(entityId)).hostname.toLowerCase();
      log.debug("Leaving MetadataPolicy.hostOf(). " + host);
      return host.replace(/^\[|\]$/g, '');
    } catch (e: any) {
      log.debug("Caught in MetadataPolicy.hostOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving MetadataPolicy.hostOf(). Not a URL.");
      return '';
    }
  }

  // RFC 5280 section 4.2.1.10's domain-name rule, which 6.2.2 adopts: a
  // constraint beginning with a period matches any host BELOW it (".example
  // .com" matches "a.example.com" and not "example.com"); any other matches
  // that host exactly. Compared case-insensitively, as DNS names are.
  static hostMatches(host: string, constraint: string): boolean {
    log.debug("Entering MetadataPolicy.hostMatches().");
    const c = String(constraint || '').toLowerCase();
    const h = String(host || '').toLowerCase();
    const out = c.charAt(0) === '.' ? (h.length > c.length &&
                                       h.slice(-c.length) === c)
                                    : h === c;
    log.debug("Leaving MetadataPolicy.hostMatches(). " + out);
    return out;
  }

  // Is a constraints object well formed? '' when it is. Members this service
  // does not understand are ignored (6.2: "If they are not understood, they
  // MUST be ignored").
  static constraintsProblem(constraints: Json): string {
    log.debug("Entering MetadataPolicy.constraintsProblem().");
    let problem = '';
    if (!MetadataPolicy.plainObject(constraints)) {
      problem = 'constraints is not a JSON object';
    } else {
      const max = constraints.max_path_length;
      if (max !== undefined && !(Number.isInteger(max) && max >= 0)) {
        problem = 'max_path_length must be an integer of zero or more';
      }
      const naming = constraints.naming_constraints;
      if (!problem && naming !== undefined) {
        if (!MetadataPolicy.plainObject(naming)) {
          problem = 'naming_constraints is not a JSON object';
        } else {
          ['permitted', 'excluded'].forEach(function (k: string): void {
            if (!problem && naming[k] !== undefined &&
                !(Array.isArray(naming[k]) &&
                  naming[k].every(function (one: Json): boolean {
                    return typeof one === 'string' && one.length > 0;
                  }))) {
              problem = 'naming_constraints.' + k + ' must be an array of ' +
                        'names';
            }
          });
        }
      }
      const types = constraints.allowed_entity_types;
      if (!problem && types !== undefined) {
        if (!Array.isArray(types) || !types.every(function (one: Json) {
          return typeof one === 'string';
        })) {
          problem = 'allowed_entity_types must be an array of entity type ' +
                    'identifiers';
        } else if (types.indexOf('federation_entity') >= 0) {
          problem = 'allowed_entity_types may not name federation_entity, ' +
                    'which is always allowed (6.2.3)';
        }
      }
    }
    log.debug("Leaving MetadataPolicy.constraintsProblem(). " +
              (problem || 'fine'));
    return problem;
  }

  // -------------------------------------------------------------------------
  // CHECK A CHAIN'S CONSTRAINTS (6.2). `chain` is the claim sets in chain
  // order: [0] the subject's Entity Configuration, then the Subordinate
  // Statements up to the Trust Anchor's, and optionally the Trust Anchor's
  // own Entity Configuration last. A Subordinate Statement at position j
  // (j >= 1, iss != sub) has j - 1 Intermediates between its issuer and the
  // subject, and its naming constraints bind the subjects of positions
  // 0..j — its own subject and every entity below that (3.1.3: "the
  // Entity that is the subject of this Subordinate Statement as well as ...
  // all Entities that are Subordinate to it").
  // -------------------------------------------------------------------------
  static checkConstraints(chain: Json[]): Outcome {
    log.debug("Entering MetadataPolicy.checkConstraints(). " + chain.length +
              " statement(s).");
    for (let j = 1; j < chain.length; j++) {
      const statement = chain[j] || {};
      if (statement.iss === statement.sub ||
          statement.constraints === undefined) {
        continue;
      }
      const c = statement.constraints;
      const problem = MetadataPolicy.constraintsProblem(c);
      if (problem) {
        log.debug("Leaving MetadataPolicy.checkConstraints(). Malformed.");
        return MetadataPolicy.refuse(CODE_CONSTRAINTS, 'the statement ' +
          statement.iss + ' made about ' + statement.sub + ': ' + problem +
          ' (6.2).');
      }
      if (c.max_path_length !== undefined && j - 1 > c.max_path_length) {
        log.debug("Leaving MetadataPolicy.checkConstraints(). Too long.");
        return MetadataPolicy.refuse(CODE_PATH_LENGTH, statement.iss +
          ' allows ' + c.max_path_length + ' Intermediate(s) below it and ' +
          'this chain has ' + (j - 1) + ' (6.2.1).');
      }
      const naming = c.naming_constraints;
      if (naming) {
        for (let k = 0; k <= j; k++) {
          const subject = String((chain[k] || {}).sub || '');
          const host = MetadataPolicy.hostOf(subject);
          const excluded = (naming.excluded || []).some(function (n: string) {
            return MetadataPolicy.hostMatches(host, n);
          });
          const permitted = !naming.permitted ||
            naming.permitted.some(function (n: string): boolean {
              return MetadataPolicy.hostMatches(host, n);
            });
          if (!host || excluded || !permitted) {
            log.debug("Leaving MetadataPolicy.checkConstraints(). Naming.");
            return MetadataPolicy.refuse(CODE_NAMING, subject + ' is ' +
              (excluded ? 'excluded by' : 'outside') + ' the naming ' +
              'constraints ' + statement.iss + ' set (6.2.2).');
          }
        }
      }
    }
    log.debug("Leaving MetadataPolicy.checkConstraints().");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // STRIP THE ENTITY TYPES THE CHAIN DOES NOT ALLOW (6.2.3), from the
  // subject's metadata: every `allowed_entity_types` in the chain's
  // Subordinate Statements applies, so a type survives only if every one
  // that is present names it. `federation_entity` always survives.
  // -------------------------------------------------------------------------
  static stripEntityTypes(metadata: Json, chain: Json[]): Json {
    log.debug("Entering MetadataPolicy.stripEntityTypes().");
    const out: Json = JSON.parse(JSON.stringify(metadata || {}));
    chain.slice(1).forEach(function (statement: Json): void {
      const allowed = statement && statement.iss !== statement.sub &&
        statement.constraints &&
        statement.constraints.allowed_entity_types;
      if (!Array.isArray(allowed)) {
        return;
      }
      Object.keys(out).forEach(function (type: string): void {
        if (type !== 'federation_entity' && allowed.indexOf(type) < 0) {
          delete out[type];
        }
      });
    });
    log.debug("Leaving MetadataPolicy.stripEntityTypes().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SUBJECT'S RESOLVED METADATA FROM A VERIFIED CHAIN, in the order the
  // specification fixes: the Immediate Superior's `metadata` first (3.1.1),
  // then the entity-type constraint (6.2.3, "after applying Metadata from a
  // direct superior's Subordinate Statement" and "before applying Metadata
  // Policies"), then the resolved policy (6.1.4). The other two constraints
  // are checked beforehand by `checkConstraints()`.
  // -------------------------------------------------------------------------
  static resolvedMetadata(chain: Json[]): Outcome {
    log.debug("Entering MetadataPolicy.resolvedMetadata().");
    const subordinates = chain.slice(1).filter(function (one: Json) {
      return one && one.iss !== one.sub;
    });
    const immediate = subordinates[0];
    let metadata = (chain[0] && chain[0].metadata) || {};
    if (immediate && immediate.metadata) {
      metadata = MetadataPolicy.overlay(metadata, immediate.metadata);
    }
    metadata = MetadataPolicy.stripEntityTypes(metadata, chain);
    // Most superior first, for the merge.
    const resolved = MetadataPolicy.resolve(subordinates.slice().reverse());
    if (!resolved.ok) {
      log.debug("Leaving MetadataPolicy.resolvedMetadata(). The policy.");
      return resolved;
    }
    const applied = MetadataPolicy.apply(metadata, resolved.policy);
    log.debug("Leaving MetadataPolicy.resolvedMetadata(). " + applied.ok);
    return applied.ok ? { ok: true, metadata: applied.metadata,
                          policy: resolved.policy } : applied;
  }
}

export = MetadataPolicy;
