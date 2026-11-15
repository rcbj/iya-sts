// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE DIRECTORY'S GROUPS, AS `/admin-api` READS AND WRITES THEM (#444,
//! phase 5, the `apis3` slice): `ldap/ldap_server.js`'s `createGroup()`,
//! `addGroupMember()`, `writeGroupEntry()`, `readGroupEntry()` and
//! `groupsFor()`, over the registers' directory ([`super::LiveDir`]), which
//! puts every entry a write touched back into the live directory and marks
//! it for the store's next flush.
//!
//! `sts-registers`' `People::groups()` is `adminActions.groupsAction()`:
//! it reads the body and keeps the writer's code; this module is the
//! writer (`GroupWriter`), so the two refusals a caller can meet — the
//! act's and the directory's — are Node's, word for word.
//!
//! NOT PORTED, and what happens instead: the account observers a
//! membership change tells (`noteMembershipChange()` — nothing observes in
//! this runtime: no Shared Signals transmitter, no role cache); the audit
//! row, which is logged as `LogAudit` logs every row here; the cluster's
//! create claim (`runClaimed()`), since this runtime runs one process; and
//! the four other group acts (`set-mail`, `set-policy`, `add-owner`,
//! `remove-owner`), which stay unrouted and answer Express's 404.

use std::sync::{Arc, PoisonError};

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::Settings;
use sts_directory::directory::OPERATIONAL;
use sts_directory::{Directory, DirectoryModel, Entry, EntryExt};
use sts_ldap::service_dn::{
    escape_dn_value, is_under, name_usable_in_dn, normalize_dn, parent_dn,
    rdn_pairs, split_rdns, unescape_dn_value,
};
use sts_registers::applications::store::StoredApplication;
use sts_registers::port as rp;

use super::LiveDir;

/// `MEMBER_ATTRIBUTES`: the name and whether its values are `uid`s.
const MEMBER_ATTRIBUTES: [(&str, bool); 3] = [
    ("member", false),
    ("uniquemember", false),
    ("memberuid", true),
];

/// `MAX_GROUP_OWNERS`.
pub const MAX_GROUP_OWNERS: usize = 20;

/// `DN_SHAPED`: `/^[A-Za-z][A-Za-z0-9-]*=/`.
fn dn_shaped(text: &str) -> bool {
    let Some((a, _)) = text.split_once('=') else {
        return false;
    };
    a.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `GROUP_MAIL_SHAPE`: `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`.
fn mail_shaped(text: &str) -> bool {
    let plain = |s: &str| {
        !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c == '@')
    };
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    if !plain(local) || domain.contains('@') {
        return false;
    }
    // `[^\s@]+\.[^\s@]+`: some dot with text on both sides.
    domain.char_indices().any(|(i, c)| {
        c == '.' && plain(&domain[..i]) && plain(&domain[i + 1..])
    }) && !domain.chars().any(char::is_whitespace)
}

fn refused(code: ErrorCode, why: String) -> rp::Marked {
    rp::Marked {
        value: json!({ "ok": false, "errors": [why] }),
        code: Some(code),
    }
}

/// `consoleKeyFor(dn, stored)`: the entry's `uid`, else the RDN's.
fn console_key(dn: &str, stored: Option<&Entry>) -> String {
    if let Some(uid) = stored.and_then(|s| s.first("uid")) {
        return uid.to_string();
    }
    let leaf = split_rdns(Some(dn)).into_iter().next().unwrap_or_default();
    rdn_pairs(Some(&leaf))
        .into_iter()
        .find(|p| p.attribute == "uid")
        .map(|p| unescape_dn_value(Some(&p.value)))
        .unwrap_or_default()
}

/// `commonNameOf(dn)`: the first `cn` of any RDN, unescaped.
fn common_name_of(dn: &str) -> String {
    split_rdns(Some(dn))
        .iter()
        .flat_map(|rdn| rdn_pairs(Some(rdn)))
        .find(|p| p.attribute == "cn")
        .map(|p| unescape_dn_value(Some(&p.value)))
        .unwrap_or_default()
}

/// The directory's reads of one realm's groups.
pub struct Groups<'a> {
    pub tree: &'a Directory,
    pub r: usize,
}

impl<'a> Groups<'a> {
    fn entries(&self) -> impl Iterator<Item = &'a Entry> {
        self.tree
            .realms()
            .get(self.r)
            .into_iter()
            .flat_map(|t| t.entries.values())
    }

    fn rule(&self, stored: &Entry) -> &'static str {
        self.tree.group_rule(self.r, &stored.dn, &stored.attributes)
    }

    /// `dnForResourceId(id)`: a SCIM id (an `entryUUID`) as its entry's DN.
    fn dn_for_resource_id(&self, id: &str) -> String {
        if sts_directory::uuid::uuid_shaped(&id.to_lowercase()) {
            if let Some(e) = self.tree.entry_by_uuid(self.r, id) {
                return e.dn.clone();
            }
        }
        id.to_string()
    }

    /// `groupDnFor(name)`.
    pub fn group_dn_for(&self, name: &str) -> String {
        format!(
            "cn={},{}",
            escape_dn_value(Some(name)),
            self.tree.groups_dn(self.r)
        )
    }

    /// `resolveMember(value, attribute)`.
    fn resolve_member(&self, value: &str, name: &str, uid: bool) -> Json {
        let dn = if uid {
            format!("uid={},{}", value, self.tree.users_dn(self.r))
        } else {
            value.to_string()
        };
        let stored = self.tree.get(self.r, &dn);
        let rule = stored.map(|s| self.rule(s)).unwrap_or("");
        let first = |a: &str| {
            stored
                .and_then(|s| s.first(a))
                .unwrap_or_default()
                .to_string()
        };
        json!({
            "value": value,
            "attribute": DirectoryModel::get().canonical_name(name),
            "holds": if uid { "uid" } else { "dn" },
            "dn": dn,
            "present": stored.is_some(),
            "kind": match (stored.is_some(), rule.is_empty()) {
                (false, _) => "dangling",
                (true, false) => "group",
                (true, true) => "entry",
            },
            "userKey": stored.map(|s| console_key(&dn, Some(s)))
                .unwrap_or_default(),
            "cn": first("cn"),
            "mail": first("mail"),
            "displayName": first("displayname"),
        })
    }

    /// `membersOf(stored)`.
    fn members_of(&self, stored: &Entry) -> Vec<Json> {
        MEMBER_ATTRIBUTES
            .iter()
            .flat_map(|(name, uid)| {
                stored
                    .values(name)
                    .iter()
                    .map(|v| self.resolve_member(v, name, *uid))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// `memberKeysOf(stored)`.
    fn member_keys_of(&self, stored: &Entry) -> Vec<String> {
        let users = self.tree.users_dn(self.r);
        MEMBER_ATTRIBUTES
            .iter()
            .flat_map(|(name, uid)| {
                stored
                    .values(name)
                    .iter()
                    .map(|v| {
                        if *uid {
                            normalize_dn(Some(&format!("uid={v},{users}")))
                        } else {
                            normalize_dn(Some(v))
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The entries whose `memberOf` names this group and which it does not
    /// list back (`unlistedClaimsOf()`), in the store's order.
    fn unlisted_claims_of(&self, group_dn: &str) -> Vec<(String, &'a Entry)> {
        let key = normalize_dn(Some(group_dn));
        let listed: Vec<String> = self
            .tree
            .get(self.r, group_dn)
            .map(|g| self.member_keys_of(g))
            .unwrap_or_default();
        self.entries()
            .filter(|e| {
                e.values("memberof")
                    .iter()
                    .any(|v| normalize_dn(Some(v)) == key)
            })
            .map(|e| (normalize_dn(Some(&e.dn)), e))
            .filter(|(k, _)| !listed.contains(k))
            .collect()
    }

    /// `claimedMembersOf(groupDn)`, sorted by normalised DN.
    fn claimed_members_of(&self, group_dn: &str) -> Vec<Json> {
        let mut rows = self.unlisted_claims_of(group_dn);
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows.into_iter()
            .map(|(_, e)| {
                json!({ "dn": e.dn,
                        "userKey": console_key(&e.dn, Some(e)),
                        "cn": e.first("cn").unwrap_or(""),
                        "mail": e.first("mail").unwrap_or("") })
            })
            .collect()
    }

    /// `resolveServiceAccountOwner(value)`: `{kind, dn, name}`.
    fn owner_of(&self, value: &str) -> (String, String, String) {
        let text = value.trim();
        let mut stored = if text.is_empty() {
            None
        } else {
            self.tree.locate(self.r, text)
        };
        if stored.is_none() && !text.is_empty() && !dn_shaped(text) {
            stored = self.tree.get(self.r, &self.group_dn_for(text));
        }
        let Some(e) = stored else {
            return (String::new(), String::new(), String::new());
        };
        if self.tree.is_person_dn(self.r, &e.dn) {
            return (
                "person".into(),
                e.dn.clone(),
                Directory::person_name_of(e),
            );
        }
        let groups = self.tree.groups_dn(self.r);
        if is_under(Some(&e.dn), Some(&groups))
            && normalize_dn(Some(&e.dn)) != normalize_dn(Some(&groups))
        {
            return (
                "group".into(),
                e.dn.clone(),
                e.first("cn").unwrap_or("").to_string(),
            );
        }
        (String::new(), e.dn.clone(), String::new())
    }

    /// `groupOwnersOf(stored)`.
    fn owners_of(&self, stored: &Entry) -> Vec<Json> {
        stored
            .values("owner")
            .iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(|dn| {
                let (kind, resolved, name) = self.owner_of(&dn);
                json!({ "dn": if kind.is_empty() { dn } else { resolved },
                        "present": !kind.is_empty(),
                        "kind": kind, "name": name })
            })
            .collect()
    }

    /// `readGroupEntry(dn)`: `entryObject()` with `rule` and `members`, or
    /// `None` where nothing there is a group.
    pub fn read_group_entry(&self, dn: &str) -> Option<Json> {
        let dn = self.dn_for_resource_id(dn);
        let stored = self.tree.get(self.r, &dn)?;
        let rule = self.rule(stored);
        if rule.is_empty() {
            return None;
        }
        let mut object = StoredApplication::of(stored).to_json();
        object["rule"] = json!(rule);
        object["members"] = Json::Array(self.members_of(stored));
        Some(object)
    }

    /// `memberDnFor(nameOrDn)`: `(dn, present)`.
    fn member_dn_for(&self, wanted: &str) -> (String, bool) {
        let wanted = wanted.trim();
        if dn_shaped(wanted) {
            return match self.tree.get(self.r, wanted) {
                Some(e) => (e.dn.clone(), true),
                None => (wanted.to_string(), false),
            };
        }
        if let Some(e) = self.tree.existing_user_entry(self.r, wanted) {
            return (e.dn.clone(), true);
        }
        (
            format!(
                "uid={},{}",
                escape_dn_value(Some(wanted)),
                self.tree.users_dn(self.r)
            ),
            false,
        )
    }

    /// `directoryState()`: the realm's containers, the two sockets and the
    /// counts.
    pub fn directory_state(&self, settings: &Settings) -> Map<String, Json> {
        let sockets = crate::ldap_listener::state();
        let int = |k: &str| settings.value_of(k).as_int();
        let mut out = Map::new();
        out.insert("baseDn".into(), json!(self.tree.realms()[self.r].base));
        out.insert("usersDn".into(), json!(self.tree.users_dn(self.r)));
        out.insert("groupsDn".into(), json!(self.tree.groups_dn(self.r)));
        out.insert(
            "port".into(),
            json!(sockets.port.map_or(int("ldap.port"), i64::from)),
        );
        out.insert("listening".into(), json!(sockets.listening));
        out.insert("listenError".into(), json!(sockets.listen_error));
        out.insert("ldapsPort".into(), json!(sockets.ldaps_port));
        out.insert("ldapsListening".into(), json!(sockets.ldaps_listening));
        out.insert("entryCount".into(), json!(self.entries().count()));
        out.insert("maxEntries".into(), json!(int("ldap.maxEntries")));
        out
    }

    /// `groupsFor(dn)`: the directory's state, every group as a row sorted
    /// by normalised DN, and — given a DN — that group in full.
    pub fn groups_for(&self, settings: &Settings, wanted: &str) -> Json {
        let wanted = wanted.trim();
        let mut out = self.directory_state(settings);
        out.insert("requested".into(), json!(wanted));
        out.insert("found".into(), json!(false));
        out.insert("notAGroup".into(), json!(false));
        out.insert("group".into(), Json::Null);
        let mut rows: Vec<(String, Json)> = Vec::new();
        for entry in self.entries() {
            let rule = self.rule(entry);
            if rule.is_empty() {
                continue;
            }
            let keys = self.member_keys_of(entry);
            let present = keys
                .iter()
                .filter(|k| self.tree.get(self.r, k).is_some())
                .count();
            rows.push((
                normalize_dn(Some(&entry.dn)),
                json!({
                    "dn": entry.dn,
                    "cn": entry.first("cn").map(str::to_string)
                        .unwrap_or_else(|| common_name_of(&entry.dn)),
                    "rule": rule,
                    "description": entry.first("description").unwrap_or(""),
                    "objectClass": entry.values("objectclass"),
                    "origin": entry.origin.as_deref().unwrap_or("unstated"),
                    "createdAt": entry.created_at,
                    "modifiedAt": entry.modified_at,
                    "memberCount": keys.len(),
                    "presentCount": present,
                    "danglingCount": keys.len() - present,
                    "claimedCount":
                        self.unlisted_claims_of(&entry.dn).len(),
                    "ownerCount": entry.values("owner").len(),
                    "attributeCount": entry.attributes.len(),
                }),
            ));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let count = rows.len();
        out.insert(
            "groups".into(),
            Json::Array(rows.into_iter().map(|(_, g)| g).collect()),
        );
        out.insert("groupCount".into(), json!(count));
        if wanted.is_empty() {
            return Json::Object(out);
        }
        let Some(stored) =
            self.tree.get(self.r, &self.dn_for_resource_id(wanted))
        else {
            return Json::Object(out);
        };
        let rule = self.rule(stored);
        if rule.is_empty() {
            out.insert("notAGroup".into(), json!(true));
            out.insert("entryDn".into(), json!(stored.dn));
            return Json::Object(out);
        }
        let model = DirectoryModel::get();
        let object = StoredApplication::of(stored);
        // `groupsFor()` builds the attributes WITHOUT `entryDN`, where
        // `entryObject()` adds it.
        let mut attributes = object.attributes.clone();
        attributes.remove(&model.canonical_name("entrydn"));
        if stored.attributes.contains_key("entrydn") {
            attributes.insert(
                model.canonical_name("entrydn"),
                json!(stored.values("entrydn")),
            );
        }
        let members = self.members_of(stored);
        let present = members
            .iter()
            .filter(|m| m["present"] == json!(true))
            .count();
        out.insert("found".into(), json!(true));
        out.insert(
            "group".into(),
            json!({
                "dn": stored.dn,
                "cn": stored.first("cn").map(str::to_string)
                    .unwrap_or_else(|| common_name_of(&stored.dn)),
                "rule": rule,
                "origin": object.origin,
                "createdAt": stored.created_at,
                "modifiedAt": stored.modified_at,
                "operational": object.operational,
                "memberAttributes": MEMBER_ATTRIBUTES
                    .iter()
                    .map(|(n, _)| model.canonical_name(n))
                    .collect::<Vec<_>>(),
                "attributes": attributes,
                "memberCount": members.len(),
                "presentCount": present,
                "danglingCount": members.len() - present,
                "members": members,
                "claimed": self.claimed_members_of(&stored.dn),
                "owners": self.owners_of(stored),
                "maxOwners": MAX_GROUP_OWNERS,
            }),
        );
        Json::Object(out)
    }
}

/// `writeGroupEntry(dn, attributes, origin)`'s refusals, before a write.
enum WriteRefusal {
    NotAGroup,
    Full(i64),
    NoParent(String),
    Dangling,
    Stored(sts_directory::LdapError),
}

impl WriteRefusal {
    fn code(&self) -> ErrorCode {
        match self {
            WriteRefusal::NotAGroup => codes::STS_LDAP_0048,
            WriteRefusal::Full(_) => codes::STS_LDAP_0007,
            WriteRefusal::NoParent(_) => codes::STS_LDAP_0006,
            WriteRefusal::Dangling => codes::STS_LDAP_0212,
            WriteRefusal::Stored(e) => e.code.unwrap_or(codes::STS_LDAP_0008),
        }
    }
    fn reason(&self) -> &'static str {
        match self {
            WriteRefusal::NotAGroup => "notAGroup",
            WriteRefusal::Full(_) => "full",
            WriteRefusal::NoParent(_) => "noParent",
            WriteRefusal::Dangling => "danglingMember",
            WriteRefusal::Stored(_) => "nul",
        }
    }
}

/// The group writer `People::groups()` hands its acts to.
pub struct GroupWriter {
    pub dir: Arc<LiveDir>,
    pub settings: Arc<Settings>,
}

impl GroupWriter {
    fn realm_of(&self, tree: &Directory) -> Option<usize> {
        LiveDir::realm_index(tree, &sts_core::realm::current_id())
    }

    /// `writeGroupEntry()`: the entry stored whole, its `createdAt` kept.
    fn write(
        &self,
        tree: &mut Directory,
        r: usize,
        dn: &str,
        attributes: Vec<(String, Vec<String>)>,
        origin: &str,
    ) -> Result<String, WriteRefusal> {
        let existing = tree.get(r, dn).cloned();
        if let Some(e) = &existing {
            if tree.group_rule(r, &e.dn, &e.attributes).is_empty() {
                return Err(WriteRefusal::NotAGroup);
            }
        }
        let max = self.settings.value_of("ldap.maxEntries").as_int();
        let total: usize = tree.realms().iter().map(|t| t.entries.len()).sum();
        if existing.is_none() && total as i64 >= max {
            tracing::warn!(
                "{}ldap: not creating {}; the directory holds its maximum \
                 of {} entries (ldap.maxEntries).",
                sts_core::log::tag(codes::STS_LDAP_0007),
                dn,
                max
            );
            return Err(WriteRefusal::Full(max));
        }
        let parent = parent_dn(Some(dn));
        if tree.get(r, &parent).is_none() {
            return Err(WriteRefusal::NoParent(parent));
        }
        // `membersNamingNothing(before, after)`: a member the write ADDS
        // must name a stored entry.
        let mut missing: Vec<String> = Vec::new();
        for (name, uid) in MEMBER_ATTRIBUTES {
            let fold = |v: &str| {
                if uid {
                    v.trim().to_lowercase()
                } else {
                    normalize_dn(Some(v))
                }
            };
            let had: Vec<String> = existing
                .as_ref()
                .map(|e| e.values(name).iter().map(|v| fold(v)).collect())
                .unwrap_or_default();
            for (k, values) in &attributes {
                if k.to_lowercase() != name {
                    continue;
                }
                for value in values {
                    let raw = value.trim();
                    if had.contains(&fold(raw)) {
                        continue;
                    }
                    let there = if uid {
                        tree.existing_user_entry(r, raw).is_some()
                    } else {
                        !raw.is_empty() && tree.get(r, raw).is_some()
                    };
                    if !there {
                        missing.push(raw.to_string());
                    }
                }
            }
        }
        if !missing.is_empty() {
            tracing::info!(
                "{}ldap: not writing {}; it would list {}, and nothing is \
                 stored there.",
                sts_core::log::tag(codes::STS_LDAP_0212),
                dn,
                missing.join(", ")
            );
            return Err(WriteRefusal::Dangling);
        }
        let created = existing.as_ref().and_then(|e| e.created_at.clone());
        let origin = existing
            .as_ref()
            .and_then(|e| e.origin.clone())
            .unwrap_or_else(|| origin.to_string());
        let key = tree
            .put_entry(r, dn, &attributes, Some(&origin), None)
            .map_err(WriteRefusal::Stored)?;
        if let Some(c) = created {
            tree.restamp_created(r, dn, &c);
        }
        Ok(key)
    }
}

impl rp::GroupWriter for GroupWriter {
    fn create_group(&self, name: &str, options: &Json) -> rp::Marked {
        let wanted = name.trim().to_string();
        if wanted.is_empty() {
            return refused(
                codes::STS_LDAP_0042,
                "Which group? Send `group` with the name it will be known \
                 by — that string becomes both the `cn` and the RDN, so it \
                 is the whole of what names the entry."
                    .into(),
            );
        }
        let realm_id = sts_core::realm::current_id();
        let outcome = {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(r) = self.realm_of(&tree) else {
                return refused(
                    codes::STS_LDAP_0008,
                    "This realm has no directory.".into(),
                );
            };
            let groups_dn = tree.groups_dn(r);
            if dn_shaped(&wanted) {
                return refused(
                    codes::STS_LDAP_0043,
                    format!(
                        "\"{wanted}\" is a DN and not a group name. Send the \
                         `cn` alone; this function puts it under \
                         {groups_dn}. A group somewhere else in the tree is \
                         an `ldapadd` and is still a group here by the \
                         objectClass rule /admin/groups reports."
                    ),
                );
            }
            if !name_usable_in_dn(Some(&wanted)) {
                return refused(
                    codes::STS_LDAP_0046,
                    format!(
                        "\"{wanted}\" cannot name a group here: it carries a \
                         character RFC 4514 section 2.4 reserves in a DN (one \
                         of , = + < > # ; \" \\), so the entry would be named \
                         something other than what was typed. Refused rather \
                         than escaped, exactly as a username is, and for the \
                         same reason: an `ldapadd` can still create it with \
                         the escaping written out."
                    ),
                );
            }
            let reads = Groups { tree: &tree, r };
            let dn = reads.group_dn_for(&wanted);
            if let Some(existing) = tree.get(r, &dn) {
                let grouped = !tree
                    .group_rule(r, &existing.dn, &existing.attributes)
                    .is_empty();
                return rp::Marked {
                    value: json!({ "ok": false,
                        "errors": [format!(
                            "There is already an entry at {dn}.{}",
                            if grouped {
                                " Add members to it rather than creating it \
                                 again."
                            } else {
                                " It is not counted as a group — see \
                                 /admin/groups for which rule catches what — \
                                 so this would be a create over the top of \
                                 something else."
                            })],
                        "existing": { "dn": existing.dn,
                            "origin": existing.origin.clone()
                                .unwrap_or_default() } }),
                    code: Some(codes::STS_LDAP_0004),
                };
            }
            let asked: Vec<String> = match &options["members"] {
                Json::Array(l) => l
                    .iter()
                    .map(|v| match v {
                        Json::String(t) => t.trim().to_string(),
                        Json::Null => String::new(),
                        other => other.to_string(),
                    })
                    .filter(|t| !t.is_empty())
                    .collect(),
                Json::Null => Vec::new(),
                Json::String(t) if t.trim().is_empty() => Vec::new(),
                Json::String(t) => vec![t.trim().to_string()],
                other => vec![other.to_string()],
            };
            let mut members: Vec<String> = Vec::new();
            let mut dangling: Vec<String> = Vec::new();
            for one in &asked {
                let (member, present) = reads.member_dn_for(one);
                if members.contains(&member) {
                    continue;
                }
                if !present {
                    dangling.push(member.clone());
                }
                members.push(member);
            }
            if !dangling.is_empty() {
                let (it, them) = if dangling.len() == 1 {
                    ("it", "it")
                } else {
                    ("they", "them")
                };
                return refused(
                    codes::STS_LDAP_0212,
                    format!(
                        "Nothing is stored at {}, so {it} cannot be a member \
                         of \"{wanted}\". A group lists only people, groups \
                         and applications that are there: create {them} \
                         first.",
                        dangling.join(", ")
                    ),
                );
            }
            let note = match options["note"].as_str().map(str::trim) {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => "created by hand rather than by a directory client"
                    .to_string(),
            };
            let mail = match &options["mail"] {
                Json::Null => String::new(),
                Json::String(t) => t.trim().to_string(),
                other => other.to_string(),
            };
            if !mail.is_empty() && !mail_shaped(&mail) {
                return refused(
                    codes::STS_LDAP_0177,
                    format!(
                        "\"{mail}\" is not an email address, so it cannot be \
                         the group's mail attribute. Give one address, \
                         local-part@domain, or none."
                    ),
                );
            }
            let mut attributes: Vec<(String, Vec<String>)> = vec![
                (
                    "objectClass".into(),
                    vec!["top".into(), "groupOfNames".into()],
                ),
                ("cn".into(), vec![wanted.clone()]),
                ("description".into(), vec![note.clone()]),
            ];
            if !members.is_empty() {
                attributes.push(("member".into(), members.clone()));
            }
            if !mail.is_empty() {
                attributes.push(("mail".into(), vec![mail]));
            }
            let origin = options["origin"].as_str().unwrap_or("console");
            match self.write(&mut tree, r, &dn, attributes, origin) {
                Err(why) => Err((why, dn, groups_dn)),
                Ok(_) => {
                    let reads = Groups { tree: &tree, r };
                    Ok((
                        tree.get(r, &dn).map(|e| e.dn.clone()).unwrap_or(dn),
                        reads.read_group_entry(&reads.group_dn_for(&wanted)),
                        note,
                        members,
                    ))
                }
            }
        };
        let (dn, entry, note, members) = match outcome {
            Err((why, dn, groups_dn)) => {
                let code = why.code();
                let reason = why.reason();
                let error = match &why {
                    WriteRefusal::Stored(e) => e.message.clone(),
                    WriteRefusal::Full(max) => format!(
                        "This directory holds its maximum of {max} entries \
                         (ldap.maxEntries). Nothing was written."
                    ),
                    WriteRefusal::NoParent(parent) => format!(
                        "There is no {} in this realm, so there is no \
                         container to put a group in.",
                        if parent.is_empty() {
                            &groups_dn
                        } else {
                            parent
                        }
                    ),
                    _ => format!(
                        "The entry at {dn} could not be written ({reason})."
                    ),
                };
                return rp::Marked {
                    value: json!({ "ok": false, "reason": reason,
                                   "errors": [error] }),
                    code: Some(code),
                };
            }
            Ok(v) => v,
        };
        self.dir.write_back();
        tracing::info!(
            "audit: group.create {} in {} with {} member(s); {}",
            dn,
            realm_id,
            members.len(),
            note
        );
        // `written.entry`: `readGroupEntry()` of what was stored, its rule
        // and its resolved members with it.
        let entry = entry.unwrap_or(Json::Null);
        rp::Marked::plain(json!({ "ok": true, "dn": dn, "group": wanted,
                                  "members": members, "entry": entry }))
    }

    fn add_group_member(
        &self,
        group: &str,
        member: &str,
        options: &Json,
    ) -> rp::Marked {
        let wanted_group = group.trim().to_string();
        let wanted_member = member.trim().to_string();
        if wanted_group.is_empty() {
            return refused(
                codes::STS_LDAP_0042,
                "Which group? Send `group` with its `cn` or its whole DN."
                    .into(),
            );
        }
        if wanted_member.is_empty() {
            return refused(
                codes::STS_LDAP_0049,
                "Who? Send `member` with a username, or with the DN of any \
                 entry — a group can hold another group, and no username \
                 names one."
                    .into(),
            );
        }
        let outcome = {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(r) = self.realm_of(&tree) else {
                return refused(
                    codes::STS_LDAP_0008,
                    "This realm has no directory.".into(),
                );
            };
            let reads = Groups { tree: &tree, r };
            let dn = if dn_shaped(&wanted_group) {
                wanted_group.clone()
            } else {
                reads.group_dn_for(&wanted_group)
            };
            let Some(existing) = reads.read_group_entry(&dn) else {
                let why = if tree.get(r, &dn).is_some() {
                    format!(
                        "There is an entry at {dn} and it is not counted as \
                         a group — it neither sits under {} nor carries a \
                         group objectClass. /admin/groups says which rule \
                         catches what.",
                        tree.groups_dn(r)
                    )
                } else {
                    format!(
                        "There is no group at {dn}. Create it first, or name \
                         an existing one — this does not create a group as a \
                         side effect of adding somebody to it, because a \
                         typo in a name would then be a new group rather \
                         than an error."
                    )
                };
                return refused(codes::STS_LDAP_0050, why);
            };
            let existing_dn = existing["dn"].as_str().unwrap_or("").to_string();
            let (target, present) = reads.member_dn_for(&wanted_member);
            if !present {
                return refused(
                    codes::STS_LDAP_0212,
                    format!(
                        "Nothing is stored at {target}, so it cannot be \
                         added to {existing_dn}. A group lists only people, \
                         groups and applications that are there: create it \
                         first."
                    ),
                );
            }
            let target_key = normalize_dn(Some(&target));
            let already = existing["members"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|one| {
                    if one["holds"] == json!("uid") {
                        return one["value"]
                            .as_str()
                            .unwrap_or("")
                            .trim()
                            .to_lowercase()
                            == wanted_member.to_lowercase();
                    }
                    normalize_dn(one["value"].as_str()) == target_key
                        || (one["present"] == json!(true)
                            && normalize_dn(one["dn"].as_str()) == target_key)
                })
                .cloned();
            if let Some(one) = already {
                return rp::Marked::plain(json!({
                    "ok": true, "changed": false, "dn": existing_dn,
                    "member": target, "present": present,
                    "message": format!(
                        "{target} is already listed by {existing_dn} (as {}). \
                         Nothing was changed.",
                        one["attribute"].as_str().unwrap_or(""))
                }));
            }
            // The entry's attributes as `readGroupEntry()` hands them —
            // sorted by lower-cased name, the operational ones left out —
            // with the new value on the member attribute.
            let Some(stored) = tree.get(r, &existing_dn).cloned() else {
                return refused(
                    codes::STS_LDAP_0050,
                    format!("There is no group at {dn}."),
                );
            };
            let mut names: Vec<&String> = stored.attributes.keys().collect();
            names.sort();
            let mut attributes: Vec<(String, Vec<String>)> = names
                .into_iter()
                .filter(|n| !OPERATIONAL.contains(&n.as_str()))
                .map(|n| (n.clone(), stored.values(n).to_vec()))
                .collect();
            match attributes.iter_mut().find(|(n, _)| n == "member") {
                Some((_, values)) => values.push(target.clone()),
                None => {
                    attributes.push(("member".into(), vec![target.clone()]))
                }
            }
            let count = attributes
                .iter()
                .find(|(n, _)| n == "member")
                .map_or(0, |(_, v)| v.len());
            let origin = options["origin"].as_str().unwrap_or("console");
            match self.write(&mut tree, r, &existing_dn, attributes, origin) {
                Err(why) => Err((why, existing_dn)),
                Ok(_) => {
                    let reads = Groups { tree: &tree, r };
                    Ok((
                        existing_dn.clone(),
                        target,
                        count,
                        reads.read_group_entry(&existing_dn),
                    ))
                }
            }
        };
        let (dn, target, count, entry) = match outcome {
            Err((why, existing_dn)) => {
                let code = why.code();
                let reason = why.reason();
                return rp::Marked {
                    value: json!({ "ok": false, "reason": reason,
                        "errors": [format!(
                            "The membership could not be written onto \
                             {existing_dn} ({reason}).")] }),
                    code: Some(code),
                };
            }
            Ok(v) => v,
        };
        self.dir.write_back();
        tracing::info!(
            "audit: group.add-member {} was added to {}",
            target,
            dn
        );
        rp::Marked::plain(json!({
            "ok": true, "changed": true, "dn": dn, "member": target,
            "present": true, "attribute": "member", "memberCount": count,
            "entry": entry,
            "message": format!("{target} is now a member of {dn}."),
        }))
    }

    fn set_group_mail(
        &self,
        _group: &str,
        _mail: &str,
        _options: &Json,
    ) -> rp::Marked {
        not_ported("set-mail")
    }

    fn set_group_policy(
        &self,
        _group: &str,
        _attribute: &str,
        _policy: &str,
        _options: &Json,
    ) -> rp::Marked {
        not_ported("set-policy")
    }

    fn add_group_owner(
        &self,
        _group: &str,
        _owner: &str,
        _options: &Json,
    ) -> rp::Marked {
        not_ported("add-owner")
    }

    fn remove_group_owner(
        &self,
        _group: &str,
        _owner: &str,
        _options: &Json,
    ) -> rp::Marked {
        not_ported("remove-owner")
    }
}

/// An act not routed here (its operation answers Express's 404 before it
/// gets this far); answered rather than left unimplemented.
fn not_ported(action: &str) -> rp::Marked {
    refused(
        codes::STS_ADMIN_0500,
        format!("groups/{action} is not ported to this runtime yet."),
    )
}
