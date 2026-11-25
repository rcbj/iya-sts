// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML Schema regular expressions, which are not the host language's.
//!
//! Four differences matter, each silently changing what a policy matches:
//!
//! 1. **An XML Schema regex is ANCHORED.** `bc` matches `bc` and not `abcd`.
//!    An unanchored translation grants access far too widely — the single
//!    most dangerous defect this module can have.
//! 2. `\i` and `\c` are XML name-character classes with no equivalent.
//! 3. A hyphen before a nested class is class SUBTRACTION, which is refused
//!    rather than mistranslated.
//! 4. `.` excludes line terminators here as it does in the Node engine.
//!
//! The pattern is wrapped as `^(?:…)$` rather than given bare anchors, so a
//! top-level alternation cannot escape them (`^a|b$` anchors two branches).

use regex::Regex;

use crate::model::{XacmlError, XacmlResult};

/// Translates and compiles an XML Schema regular expression.
pub fn xml_schema_regex(pattern: &str) -> XacmlResult<Regex> {
    if has_class_subtraction(pattern) {
        return Err(XacmlError::processing(format!(
            "The regular expression \"{}\" uses XML Schema character class \
             subtraction, which is not translated here. Refused rather than \
             approximated, because a regex that matches almost the right \
             things is worse than one that fails.",
            pattern
        )));
    }
    let translated = pattern
        .replace(r"\i", "[A-Za-z_:]")
        .replace(r"\I", "[^A-Za-z_:]")
        .replace(r"\c", r"[A-Za-z0-9_:.\-]")
        .replace(r"\C", r"[^A-Za-z0-9_:.\-]");
    Regex::new(&format!("^(?:{})$", translated)).map_err(|error| {
        XacmlError::processing(format!(
            "The regular expression \"{}\" is not valid: {}",
            pattern, error
        ))
    })
}

/// The longest value a regexp-match matches (#2220): the Node engine's
/// `REGEX_INPUT_MAX`, counted as it counts, in UTF-16 code units.
pub const REGEX_INPUT_MAX: usize = 4096;

/// The evaluation's bound on one regexp-match (#2220), the Node engine's
/// `boundedMatch()`: a pattern with a backreference or a quantified group
/// that is itself quantified or an alternation, or a value longer than
/// `REGEX_INPUT_MAX`, is a processing error (Indeterminate).
///
/// This crate's `regex` is linear-time and needs neither rule for its own
/// sake. They are here for PARITY: the service's engine backtracks and
/// refuses these at the evaluation, and a policy stored before #2220 must
/// decide alike at the PDP and at a remote PEP.
pub fn bounded_match(pattern: &str, subject: &str) -> XacmlResult<()> {
    if has_backreference(pattern) {
        return Err(XacmlError::processing(format!(
            "The regular expression \"{}\" is not evaluated: it uses a \
             backreference, which a pattern here may not.",
            pattern.chars().take(200).collect::<String>()
        )));
    }
    if nested_quantifier(pattern) {
        return Err(XacmlError::processing(format!(
            "The regular expression \"{}\" is not evaluated: it applies a \
             quantifier to a group that is itself quantified or an \
             alternation, the shape that makes a match take exponential \
             time; write the repetition once.",
            pattern.chars().take(200).collect::<String>()
        )));
    }
    let length = subject.encode_utf16().count();
    if length > REGEX_INPUT_MAX {
        return Err(XacmlError::processing(format!(
            "A value of {} characters is not matched against a regular \
             expression; at most {} are.",
            length, REGEX_INPUT_MAX
        )));
    }
    Ok(())
}

/// `common/pattern_safety.js`'s `/\\[1-9]|\\k</`: a backslash followed by
/// a digit 1-9 or by `k<`, anywhere.
fn has_backreference(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    for i in 0..chars.len() {
        if chars[i] != '\\' {
            continue;
        }
        match chars.get(i + 1) {
            Some(c) if ('1'..='9').contains(c) => return true,
            Some('k') if chars.get(i + 2) == Some(&'<') => return true,
            _ => {}
        }
    }
    false
}

/// `common/pattern_safety.js`'s `nestedQuantifier()`, step for step: whether
/// a group holding a quantifier or an alternation (at any depth) is itself
/// followed by a quantifier. Escapes and character classes are stepped over.
pub fn nested_quantifier(pattern: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let at = |i: usize| -> char { p.get(i).copied().unwrap_or('\0') };
    let quantifier_at = |i: usize, with_optional: bool| -> bool {
        let c = at(i);
        c == '+' || c == '*' || c == '{' || (with_optional && c == '?')
    };
    let mut stack: Vec<bool> = Vec::new();
    let mut i = 0usize;
    while i < p.len() {
        let c = p[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if c == '[' {
            let mut j = i + 1;
            while j < p.len() && p[j] != ']' {
                j += if p[j] == '\\' { 2 } else { 1 };
            }
            i = j + 1;
            if quantifier_at(i, false) {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            continue;
        }
        if c == '(' {
            stack.push(false);
            i += 1;
            continue;
        }
        if c == ')' {
            let risky = stack.pop().unwrap_or(false);
            i += 1;
            if risky && quantifier_at(i, true) {
                return true;
            }
            if risky || quantifier_at(i, false) {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            continue;
        }
        if c == '|'
            || quantifier_at(i, false)
            || (c == '?' && i > 0 && p[i - 1] != '(')
        {
            if let Some(top) = stack.last_mut() {
                *top = true;
            }
        }
        i += 1;
    }
    false
}

/// The Node engine's test, `/\[[^\]]*-\[/`: an opening bracket, anything but
/// a closing one, then `-[`.
fn has_class_subtraction(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    for (start, &b) in bytes.iter().enumerate() {
        if b != b'[' {
            continue;
        }
        let mut i = start + 1;
        while i < bytes.len() && bytes[i] != b']' {
            if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'[') {
                return true;
            }
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchored() {
        let re = xml_schema_regex("bc").unwrap();
        assert!(re.is_match("bc"));
        assert!(!re.is_match("abcd"));
        let alt = xml_schema_regex("a|b").unwrap();
        assert!(!alt.is_match("ab"));
    }

    #[test]
    fn nested_quantifier_refused_at_evaluation() {
        assert!(nested_quantifier("(a+)+"));
        assert!(nested_quantifier("(a|aa)*"));
        assert!(nested_quantifier("((ab)*c)+"));
        assert!(!nested_quantifier("[a-z]+"));
        assert!(!nested_quantifier("(ab)+"));
        assert!(!nested_quantifier("[(a+)]+"));
        assert!(!nested_quantifier(r"\(a+\)+"));
        assert!(bounded_match("(a+)+$", "aaaa").is_err());
        assert!(bounded_match(r"(a)\1", "aa").is_err());
        assert!(bounded_match("a+", "aaaa").is_ok());
        assert!(bounded_match("a+", &"a".repeat(REGEX_INPUT_MAX)).is_ok());
        assert!(bounded_match("a+", &"a".repeat(REGEX_INPUT_MAX + 1)).is_err());
    }

    #[test]
    fn subtraction_refused() {
        assert!(xml_schema_regex("[a-z-[aeiou]]").is_err());
    }
}
