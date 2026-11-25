// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pattern_safety.js
//
// ---------------------------------------------------------------------------
// A REGULAR EXPRESSION SOMEBODY ELSE WROTE, BOUNDED (#2220, ASVS 5.0.0
// 1.3.12).
//
// JavaScript's engine backtracks and node offers no timeout on a match, so
// the bound is on what may be WRITTEN rather than on how long a match runs:
// at most a caller's number of characters, no backreference, and no
// quantifier on a group that itself contains one or is an alternation —
// `(a+)+`, `(a|aa)*`, the shapes that make a backtracking engine take
// exponential time. A caller also cuts the value tested off at a length of
// its own (`INPUT_MAX` is the usual one).
//
// **WRITTEN ONCE, FOR FEDERATION** (`fedSubjectPattern`, #2220 moved it
// here). Its callers now: federation's subject pattern, XACML's six
// `*-regexp-match` functions (a policy's pattern, at the save and at the
// evaluation), SPIFFE's http_challenge DNS patterns and sigstore identities
// (at the setting's write), and an RFC 9396 access type's JSON Schema
// `pattern`s (at the definition's write). Each keeps its own anchoring and
// its own dialect; this file reads the SOURCE TEXT only.
//
// **IT ERRS TOWARDS REFUSING**: `([a-z]+)?` is refused too, and `[a-z]+`
// does the same job without the group. It does not catch every polynomial
// shape — `.*.*.*x` is cubic and passes — which is why every caller also
// caps the value it matches.
//
// JAVASCRIPT RATHER THAN TYPESCRIPT, deliberately: `common/config.js` checks
// a setting's patterns with it, and `config.js` is loaded on the host by
// tools that run no compiler (`env/generate_defaults.js`, `error_codes.js
// --docs`), where a `.ts` does not resolve.
//
// A static utility class (rcbj's rule on #50): no state, no dependencies,
// and no Entering/Leaving pair in any method — `nestedQuantifier()` runs at
// every XACML regexp-match evaluation, and a pair per call would drown the
// log. That is the hot-path exception the code style allows, stated here as
// it requires.
// ---------------------------------------------------------------------------

/**
 * The checks a regular expression an administrator, a policy author or a
 * caller wrote is held to before this service compiles it.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PatternSafety {
  /**
   * The longest pattern accepted when a caller names no length of its own.
   */
  static get PATTERN_MAX() {
    return 256;
  }

  /**
   * The longest value a caller matches when it names no length of its own.
   */
  static get INPUT_MAX() {
    return 1024;
  }

  /**
   * Says whether a group that holds a quantifier or an alternation (at any
   * depth) is itself followed by a quantifier.
   *
   * A scan rather than a regex over the pattern, because the groups nest and
   * a regex cannot count them. Escapes and character classes are stepped
   * over: `[+]` is a plus sign, not a quantifier.
   *
   * @param {unknown} text - the pattern's source text
   * @returns true for the exponential shape
   */
  static nestedQuantifier(text) {
    const pattern = String(text == null ? '' : text);
    /** @type {{ risky: boolean }[]} */
    const stack = [];
    let i = 0;
    let found = false;
    const quantifierAt = function (at, withOptional) {
      const c = pattern.charAt(at);
      return c === '+' || c === '*' || c === '{' ||
        (withOptional && c === '?');
    };
    while (i < pattern.length && !found) {
      const c = pattern.charAt(i);
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === '[') {
        let j = i + 1;
        while (j < pattern.length && pattern.charAt(j) !== ']') {
          j += pattern.charAt(j) === '\\' ? 2 : 1;
        }
        i = j + 1;
        if (quantifierAt(i, false) && stack.length) {
          stack[stack.length - 1].risky = true;
        }
        continue;
      }
      if (c === '(') {
        stack.push({ risky: false });
        i += 1;
        continue;
      }
      if (c === ')') {
        const group = stack.pop() || { risky: false };
        i += 1;
        const quantified = quantifierAt(i, true);
        if (group.risky && quantified) {
          found = true;
        }
        if (stack.length && (group.risky || quantifierAt(i, false))) {
          stack[stack.length - 1].risky = true;
        }
        continue;
      }
      if (stack.length && (c === '|' || quantifierAt(i, false) ||
                           (c === '?' && i > 0 &&
                            pattern.charAt(i - 1) !== '('))) {
        stack[stack.length - 1].risky = true;
      }
      i += 1;
    }
    return found;
  }

  /**
   * Says why a pattern may not be compiled here: too long, a backreference,
   * or a quantified group that is itself quantified or an alternation.
   * Whether it COMPILES is the caller's question, since each caller has a
   * dialect (an anchoring, XML Schema's `\i`, JSON Schema's `u` flag).
   *
   * @param {unknown} text - the pattern
   * @param {number} [maxLength] - the longest pattern accepted;
   *   `PATTERN_MAX` when omitted
   * @returns the problem as a sentence, or '' when it is usable or empty
   */
  static problem(text, maxLength) {
    const pattern = String(text == null ? '' : text);
    const max = typeof maxLength === 'number' && maxLength > 0
      ? maxLength : PatternSafety.PATTERN_MAX;
    if (!pattern) {
      return '';
    }
    if (pattern.length > max) {
      return 'it is ' + pattern.length + ' characters long, and at most ' +
             max + ' are accepted';
    }
    if (/\\[1-9]|\\k</.test(pattern)) {
      return 'it uses a backreference, which a pattern here may not';
    }
    if (PatternSafety.nestedQuantifier(pattern)) {
      return 'it applies a quantifier to a group that is itself quantified ' +
             'or an alternation, the shape that makes a match take ' +
             'exponential time; write the repetition once';
    }
    return '';
  }
}

module.exports = PatternSafety;
