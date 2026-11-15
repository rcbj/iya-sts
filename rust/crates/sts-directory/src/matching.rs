// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A search filter matched against an entry, as the search handler matches
//! it: `ldap/ldap_matching.ts`'s walk (#632) over `@ldapjs/filter`'s leaves.
//!
//! * AND, OR and NOT as RFC 4511 section 4.5.1.7 and RFC 4526 define them.
//! * An equality or substring assertion on an attribute whose RFC equality
//!   rule ignores case (`CASE_IGNORE_ATTRIBUTES`, the table
//!   `ldap_matching.ts` holds: RFC 4519, RFC 4524, RFC 2798) is compared
//!   with both sides lower-cased.
//! * Every other leaf is the library's own `matches(entry, false)`: an
//!   exact comparison except for `objectClass`, which the library folds; a
//!   presence; an ordering compared as JavaScript compares strings (UTF-16
//!   code units); and approximate and extensible matches, which the library
//!   does not implement and THROWS for — [`Unmatchable`], which the search
//!   handler logs as STS-LDAP-0034 and counts as no match.
//!
//! The filter is `sts_ldap::Filter`: the wire slice's parse of the string
//! the request carries, which is what `operationContext()` re-parses.
//!
//! A substring pattern is the regular expression both the library and
//! `ldap_matching.ts` build, with JavaScript's `.` (any code unit but a
//! line terminator), so a value with a newline between two pieces does not
//! match, exactly as on Node.
//!
//! Asked once per entry in scope of a search: a hot path, so no span.

use std::cmp::Ordering;

use sts_ldap::filter::{Filter, JsStr};

use crate::entry::Attributes;

/// The attributes whose equality rule ignores case, lower-cased.
pub const CASE_IGNORE_ATTRIBUTES: &[&str] = &[
    "businesscategory",
    "c",
    "cn",
    "dc",
    "description",
    "destinationindicator",
    "dnqualifier",
    "generationqualifier",
    "givenname",
    "houseidentifier",
    "initials",
    "l",
    "name",
    "o",
    "ou",
    "physicaldeliveryofficename",
    "postalcode",
    "postofficebox",
    "serialnumber",
    "sn",
    "st",
    "street",
    "title",
    "uid",
    "commonname",
    "surname",
    "gn",
    "countryname",
    "localityname",
    "stateorprovincename",
    "streetaddress",
    "organizationname",
    "organizationalunitname",
    "domaincomponent",
    "userid",
    "mail",
    "rfc822mailbox",
    "associateddomain",
    "buildingname",
    "co",
    "friendlycountryname",
    "documentauthor",
    "documentidentifier",
    "documentlocation",
    "documentpublisher",
    "documenttitle",
    "documentversion",
    "drink",
    "favouritedrink",
    "host",
    "info",
    "organizationalstatus",
    "roomnumber",
    "uniqueidentifier",
    "carlicense",
    "departmentnumber",
    "displayname",
    "employeenumber",
    "employeetype",
    "preferredlanguage",
];

/// A filter the library cannot evaluate: what its leaf throws.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unmatchable(pub String);

/// `LdapMatching.ignoresCase()`: an option (`;lang-en`) is ignored.
pub fn ignores_case(attribute: &str) -> bool {
    let ty = attribute.split(';').next().unwrap_or("").to_lowercase();
    CASE_IGNORE_ATTRIBUTES.contains(&ty.as_str())
}

/// `LdapMatching.matches()`.
pub fn matches(
    filter: &Filter,
    entry: &Attributes,
) -> Result<bool, Unmatchable> {
    match filter {
        Filter::And(clauses) => {
            for one in clauses {
                if !matches(one, entry)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Filter::Or(clauses) => {
            for one in clauses {
                if matches(one, entry)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Filter::Not(inner) => Ok(!matches(inner, entry)?),
        Filter::Equality { attribute, raw } => {
            let value = Filter::equality_value(raw);
            if ignores_case(attribute) {
                let wanted = value.to_lowercase();
                return Ok(values_of(entry, attribute).is_some_and(|v| {
                    v.iter().any(|s| s.to_lowercase() == wanted)
                }));
            }
            Ok(library_equality(attribute, &value, entry))
        }
        Filter::Substring {
            attribute,
            initial,
            any,
            last,
        } => {
            let fold = ignores_case(attribute);
            let Some(values) = values_of(entry, attribute) else {
                return Ok(false);
            };
            let pattern = substring_pattern(initial, any, last, fold)?;
            Ok(values.iter().any(|v| {
                if fold {
                    pattern.is_match(&v.to_lowercase())
                } else {
                    pattern.is_match(v)
                }
            }))
        }
        Filter::Presence { attribute } => {
            Ok(values_of(entry, attribute).is_some())
        }
        Filter::GreaterOrEqual { attribute, value } => {
            Ok(values_of(entry, attribute).is_some_and(|v| {
                v.iter().any(|s| js_cmp(value, s) != Ordering::Greater)
            }))
        }
        Filter::LessOrEqual { attribute, value } => {
            Ok(values_of(entry, attribute).is_some_and(|v| {
                v.iter().any(|s| js_cmp(s, value) != Ordering::Greater)
            }))
        }
        Filter::Approximate { .. } | Filter::Extensible { .. } => {
            Err(Unmatchable("not implemented".to_string()))
        }
    }
}

// `getAttributeValue()` with `strictCase` false: the exact key, then the
// first whose lower case matches.
fn values_of<'a>(
    entry: &'a Attributes,
    attribute: &str,
) -> Option<&'a Vec<String>> {
    if let Some(v) = entry.get(attribute) {
        return Some(v);
    }
    let wanted = attribute.to_lowercase();
    entry
        .iter()
        .find(|(k, _)| k.to_lowercase() == wanted)
        .map(|(_, v)| v)
}

// The library's equality: `objectClass` folded, everything else exact.
fn library_equality(attribute: &str, value: &str, entry: &Attributes) -> bool {
    let Some(values) = values_of(entry, attribute) else {
        return false;
    };
    if attribute.to_lowercase() == "objectclass" {
        let wanted = value.to_lowercase();
        return values.iter().any(|v| v.to_lowercase() == wanted);
    }
    values.iter().any(|v| v == value)
}

// JavaScript's `<` on strings: UTF-16 code units.
fn js_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

// JavaScript's `.`: any code unit but a line terminator.
const DOT_STAR: &str = "[^\\n\\r\\u{2028}\\u{2029}]*";

// `'' + value` of a piece, `String(null)` included, as the two builders
// write it.
fn piece(s: &JsStr) -> Option<String> {
    s.truthy().map(str::to_string)
}

fn substring_pattern(
    initial: &JsStr,
    any: &[Option<String>],
    last: &JsStr,
    fold: bool,
) -> Result<regex::Regex, Unmatchable> {
    let case = |s: &str| {
        if fold {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let mut source = String::new();
    if let Some(i) = piece(initial) {
        source.push('^');
        source.push_str(&regex::escape(&case(&i)));
        source.push_str(DOT_STAR);
    }
    for one in any {
        let text = one.clone().unwrap_or_else(|| "null".to_string());
        source.push_str(&regex::escape(&case(&text)));
        source.push_str(DOT_STAR);
    }
    if let Some(f) = piece(last) {
        source.push_str(&regex::escape(&case(&f)));
        source.push('$');
    }
    regex::Regex::new(&source).map_err(|e| Unmatchable(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pairs: &[(&str, &[&str])]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| {
                (k.to_string(), v.iter().map(|s| s.to_string()).collect())
            })
            .collect()
    }

    fn parsed(text: &str) -> Filter {
        Filter::parse(text).unwrap_or(Filter::And(vec![]))
    }

    #[test]
    fn the_rules_fold_only_what_the_schema_folds() {
        let e = entry(&[
            ("uid", &["alice"]),
            ("memberuid", &["FERN"]),
            ("objectclass", &["inetOrgPerson"]),
        ]);
        assert_eq!(matches(&parsed("(uid=ALICE)"), &e), Ok(true));
        assert_eq!(matches(&parsed("(memberUid=fern)"), &e), Ok(false));
        assert_eq!(
            matches(&parsed("(objectClass=INETORGPERSON)"), &e),
            Ok(true)
        );
        assert!(matches(&parsed("(cn~=x)"), &e).is_err());
    }

    #[test]
    fn a_line_terminator_breaks_a_substring() {
        let e = entry(&[("description", &["ab\ncd"])]);
        assert_eq!(matches(&parsed("(description=a*d)"), &e), Ok(false));
        assert_eq!(matches(&parsed("(description=*cd)"), &e), Ok(true));
    }
}
