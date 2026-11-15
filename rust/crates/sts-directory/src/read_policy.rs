// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Who may read what over the socket (#106): `ldap/directory_read_policy.ts`,
//! the rule table. The directory says who the reader is and what an entry
//! is; this answers whether the entry is visible and which attributes are.
//! Asked for every entry in scope of a search: a hot path, so no span.

/// Who is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderKind {
    /// Development mode: nobody is asked.
    Unrestricted,
    Anonymous,
    Administrator,
    /// An entry of the realm being read.
    Person,
    /// Somebody bound from elsewhere.
    Outsider,
}

/// The reader, once per operation (`readerOf()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader {
    pub kind: ReaderKind,
    /// The bound DN, normalised.
    pub dn: String,
    pub readable_of_others: Vec<String>,
    pub group_members_readable: bool,
}

/// What an entry is (`readKindOf()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Container,
    Person,
    Group,
    Public,
    Other,
}

/// The facts about one entry the rules read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFacts {
    pub kind: EntryKind,
    pub dn: String,
    pub members: Vec<String>,
}

/// Which attributes a reader may read of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRule {
    pub all: bool,
    pub names: Vec<String>,
}

const CONTAINER_ATTRIBUTES: &[&str] = &["objectclass", "ou", "dc", "o"];
const GROUP_ATTRIBUTES: &[&str] = &["objectclass", "cn", "description"];
const GROUP_MEMBER_ATTRIBUTES: &[&str] = &["member", "uniquemember", "memberuid"];
const ALWAYS_WITH_THE_ENTRY: &[&str] = &["entrydn"];

fn names(lists: &[&[&str]]) -> Vec<String> {
    lists
        .iter()
        .flat_map(|l| l.iter().map(|s| s.to_string()))
        .collect()
}

/// `DirectoryReadPolicy.visible()`.
pub fn visible(reader: &Reader, entry: &EntryFacts) -> bool {
    match reader.kind {
        ReaderKind::Unrestricted | ReaderKind::Administrator => return true,
        _ => {}
    }
    if entry.kind == EntryKind::Public {
        return true;
    }
    if reader.kind == ReaderKind::Anonymous {
        return false;
    }
    if !reader.dn.is_empty() && reader.dn == entry.dn {
        return true;
    }
    if entry.kind == EntryKind::Container {
        return true;
    }
    if reader.kind != ReaderKind::Person {
        return false;
    }
    match entry.kind {
        EntryKind::Person => !reader.readable_of_others.is_empty(),
        EntryKind::Group => entry.members.contains(&reader.dn),
        _ => false,
    }
}

/// `DirectoryReadPolicy.attributeRule()`.
pub fn attribute_rule(reader: &Reader, entry: &EntryFacts) -> AttributeRule {
    if matches!(
        reader.kind,
        ReaderKind::Unrestricted | ReaderKind::Administrator
    ) || entry.kind == EntryKind::Public
        || (!reader.dn.is_empty() && reader.dn == entry.dn)
    {
        return AttributeRule {
            all: true,
            names: Vec::new(),
        };
    }
    let names = match entry.kind {
        EntryKind::Container => names(&[CONTAINER_ATTRIBUTES, ALWAYS_WITH_THE_ENTRY]),
        EntryKind::Person => {
            let mut out = reader.readable_of_others.clone();
            out.extend(names(&[ALWAYS_WITH_THE_ENTRY]));
            out
        }
        EntryKind::Group => {
            let members: &[&str] = if reader.group_members_readable {
                GROUP_MEMBER_ATTRIBUTES
            } else {
                &[]
            };
            names(&[GROUP_ATTRIBUTES, members, ALWAYS_WITH_THE_ENTRY])
        }
        _ => Vec::new(),
    };
    AttributeRule { all: false, names }
}

/// `DirectoryReadPolicy.readable()`: the `;binary` option is the type.
pub fn readable(rule: &AttributeRule, name: &str) -> bool {
    if rule.all {
        return true;
    }
    let lower = name.to_lowercase();
    let ty = lower.strip_suffix(";binary").unwrap_or(&lower);
    rule.names.iter().any(|n| n == ty)
}
