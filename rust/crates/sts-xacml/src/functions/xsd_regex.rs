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
    fn subtraction_refused() {
        assert!(xml_schema_regex("[a-z-[aeiou]]").is_err());
    }
}
