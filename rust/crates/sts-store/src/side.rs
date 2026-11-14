// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The side tables a minted flush keeps beside the sealed bodies, on both
//! engines, exactly as Node keeps them — so a store this runtime wrote is
//! one a Node 1.x process opens, and the reverse (rcbj, 2026-11-14).
//!
//! * **`sts_sessions` (#350)**: one row per sign-on session, the columns a
//!   windowed process asks instead of opening every session. What goes in
//!   them is `authn/authn.ts`'s `sessionIndexOf()` ([`SessionIndex::of`]),
//!   normalised by `persistence_postgres.js`'s `sessionIndexParams()`
//!   ([`SessionIndex::params`]); a body a tombstone refused writes none, and
//!   an ended session's row goes with its body.
//! * **`sts_minted_index` (#820)**: an on-demand store's rows filed under
//!   keyed digests of their lookup values (`indexKeyOf()`), and one SORT
//!   row per row carrying the store's `sortBy` value
//!   ([`SORT_INDEX_KEY`]). An upserted row's index rows are replaced, a
//!   deleted row's go.
//!
//! What a store files where is declared with it ([`IndexHooks`], Node's
//! `indexOf`, `lookupsOf` and `sortOf` on `realms.map()`); the minted flush
//! computes the columns from the plaintext, and a driver writes them in the
//! flush's own transaction.

use std::sync::Arc;

use serde_json::Value as Json;

use crate::keystore::DataKeys;

/// The minted handle whose rows have a session index.
pub const SESSIONS_HANDLE: &str = "authn.sessions";

/// The `index_key` of a row's sort row (`minted_queries.SORT_INDEX_KEY`):
/// `$` is not in base64url, so no lookup digest is this.
pub const SORT_INDEX_KEY: &str = "$sort$";

/// The row that says a store's index is complete: realm '' and a key no
/// digest can be (`MINTED_INDEX_MARK`).
pub const MINTED_INDEX_MARK: &str = "$index-complete$";

/// The row that says the session index is complete
/// (`SESSION_INDEX_MARK_REALM`, `SESSION_INDEX_MARK_KEY`).
pub const SESSION_INDEX_MARK_REALM: &str = "";
pub const SESSION_INDEX_MARK_KEY: &str = "$session-index-complete$";

/// What an index digest is keyed under (`INDEX_LABEL`).
const INDEX_LABEL: &str = "minted-index";

/// `MAX_STORED_EXPIRY`: a sort value past this is not one.
const MAX_STORED: f64 = 9_007_199_254_740_991.0;

/// One `sts_sessions` row's thirteen columns after realm and key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionIndex {
    pub expires_at: Option<i64>,
    pub last_seen_at: i64,
    pub started_at: i64,
    pub subject_key: String,
    pub username_key: String,
    pub chosen: bool,
    pub authenticated: bool,
    pub kind: String,
    pub rp_surface: String,
    pub parent_key: String,
    pub backs_console: bool,
    pub credential_key: String,
    pub partner_relationship: String,
}

/// `Number(x)` for the JSON a session holds: a number, a numeric string,
/// a boolean, or NaN.
fn number(value: Option<&Json>) -> f64 {
    match value {
        None | Some(Json::Null) => f64::NAN,
        Some(Json::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Json::Bool(b)) => f64::from(u8::from(*b)),
        Some(Json::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(_) => f64::NAN,
    }
}

/// `String(x)` of a scalar a session holds, as JavaScript writes it.
fn text(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        Json::Null => "null".to_string(),
        Json::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => {
                format!("{}", f as i64)
            }
            _ => n.to_string(),
        },
        Json::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// JavaScript truthiness of a member.
fn truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Json::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// A finite millisecond count floored, never negative.
fn floored(n: f64) -> i64 {
    if n.is_finite() {
        n.floor().max(0.0) as i64
    } else {
        0
    }
}

impl SessionIndex {
    /// `sessionIndexOf()` (`authn/authn.ts`): the columns of one session,
    /// or `None` when it is not a session or no digest key is held (which
    /// writes no index row).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn of(keys: &DataKeys, value: &Json) -> Option<SessionIndex> {
        let session = value.as_object()?;
        let subject = match session.get("subjectId") {
            None | Some(Json::Null) => String::new(),
            Some(v) => text(v),
        };
        let subject_key = keys.keyed_digest("session-subject", &subject)?;
        let username = session
            .get("user")
            .and_then(Json::as_object)
            .and_then(|u| u.get("username"))
            .filter(|u| !u.is_null())
            .map(text)
            .unwrap_or_default();
        let username_key = keys.keyed_digest("session-username", &username)?;
        let parent_sid = if truthy(session.get("derivedFrom")) {
            session.get("derivedFrom").map(text).unwrap_or_default()
        } else {
            String::new()
        };
        let parent_key = if parent_sid.is_empty() {
            String::new()
        } else {
            keys.keyed_digest("session-parent", &parent_sid)?
        };
        let credential_key = if truthy(session.get("credentialKey")) {
            session.get("credentialKey").map(text).unwrap_or_default()
        } else {
            String::new()
        };
        let kind = if !parent_sid.is_empty() {
            "relying-party"
        } else if !credential_key.is_empty() {
            "keyed"
        } else if session.get("chosen") == Some(&Json::Bool(false)) {
            "arrival"
        } else {
            "sign-on"
        };
        let partner_relationship = session
            .get("fedPartnerSession")
            .and_then(Json::as_object)
            .and_then(|p| p.get("relationship"))
            .filter(|r| truthy(Some(r)))
            .map(text)
            .unwrap_or_default();
        let expires = number(session.get("expires"));
        Some(SessionIndex {
            expires_at: (expires.is_finite() && expires > 0.0)
                .then(|| expires.floor() as i64),
            last_seen_at: floored(number(session.get("lastSeenAt"))),
            started_at: floored(number(session.get("startedAt"))),
            subject_key,
            username_key,
            chosen: session.get("chosen") != Some(&Json::Bool(false)),
            authenticated: session.get("authenticated")
                != Some(&Json::Bool(false)),
            kind: kind.to_string(),
            rp_surface: if truthy(session.get("rpSurface")) {
                session.get("rpSurface").map(text).unwrap_or_default()
            } else {
                String::new()
            },
            parent_key,
            backs_console: session.get("backsConsole")
                == Some(&Json::Bool(true)),
            credential_key,
            partner_relationship,
        })
    }

    /// `sessionIndexParams()`: what is written, an expiry that is not a
    /// positive number kept SQL NULL (`Number(null)` is 0, which would
    /// publish a session as already expired).
    pub fn params(&self) -> SessionIndex {
        SessionIndex {
            expires_at: self.expires_at.filter(|e| *e > 0),
            last_seen_at: self.last_seen_at.max(0),
            started_at: self.started_at.max(0),
            ..self.clone()
        }
    }

    /// The completion mark's row (`SESSION_INDEX_MARK`).
    pub fn mark() -> SessionIndex {
        SessionIndex {
            chosen: false,
            authenticated: false,
            ..SessionIndex::default()
        }
    }
}

/// One `sts_minted_index` row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRow {
    pub handle: String,
    pub realm: String,
    pub index_key: String,
    pub key: String,
    /// The store's `sortBy` value on a sort row; `None` on every other.
    pub sort_at: Option<i64>,
}

/// A store's own lookup values for a row (`lookupsOf(value, key)`).
pub type LookupsOf = Arc<dyn Fn(&Json, &str) -> Vec<Json> + Send + Sync>;
/// A store's sort value for a row (`sortOf(value, key)`).
pub type SortOf = Arc<dyn Fn(&Json, &str) -> Option<Json> + Send + Sync>;
/// A store's side-table columns for a row (`indexOf(value)`).
pub type IndexOf =
    Arc<dyn Fn(&DataKeys, &Json) -> Option<SessionIndex> + Send + Sync>;

/// What a declared store files beside its rows.
#[derive(Clone, Default)]
pub struct IndexHooks {
    pub index_of: Option<IndexOf>,
    pub lookups_of: Option<LookupsOf>,
    pub sort_of: Option<SortOf>,
}

impl IndexHooks {
    /// The sign-on session store's: [`SessionIndex::of`].
    pub fn sessions() -> IndexHooks {
        IndexHooks {
            index_of: Some(Arc::new(SessionIndex::of)),
            ..IndexHooks::default()
        }
    }

    /// `isIndexed()`: whether a deleted row has index rows to remove.
    pub fn indexed(&self) -> bool {
        self.lookups_of.is_some() || self.sort_of.is_some()
    }

    /// `sortAtFor()`: the sort value as a whole number, or `None`.
    pub fn sort_at(&self, value: &Json, key: &str) -> Option<i64> {
        let answer = self.sort_of.as_ref()?(value, key)?;
        let n = match &answer {
            Json::String(s) if s.is_empty() => return None,
            Json::Null => return None,
            other => number(Some(other)),
        };
        (n.is_finite() && n.abs() <= MAX_STORED).then(|| n.trunc() as i64)
    }

    /// `indexKeysFor()`: the digests a flush files the row under, an empty
    /// list for a store that only sorts, `None` for neither.
    pub fn lookups(
        &self,
        keys: &DataKeys,
        handle: &str,
        realm: &str,
        key: &str,
        value: &Json,
    ) -> Option<Vec<String>> {
        let Some(lookups_of) = self.lookups_of.as_ref() else {
            return self.sort_of.as_ref().map(|_| Vec::new());
        };
        Some(
            lookups_of(value, key)
                .iter()
                .filter(|v| {
                    !matches!(v, Json::Null)
                        && !matches!(v, Json::String(s) if s.is_empty())
                })
                .filter_map(|v| {
                    keys.keyed_digest(
                        INDEX_LABEL,
                        &format!("{}\n{}\n{}", handle, realm, text(v)),
                    )
                })
                .collect(),
        )
    }
}

/// The index rows one upsert files (`ixnew_*`): each lookup digest once,
/// and the sort row where there is a sort value.
pub fn filed(
    handle: &str,
    realm: &str,
    key: &str,
    lookups: &[String],
    sort_at: Option<i64>,
) -> Vec<IndexRow> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<IndexRow> = lookups
        .iter()
        .filter(|l| seen.insert(l.as_str()))
        .map(|l| IndexRow {
            handle: handle.to_string(),
            realm: realm.to_string(),
            index_key: l.clone(),
            key: key.to_string(),
            sort_at: None,
        })
        .collect();
    if let Some(at) = sort_at {
        out.push(IndexRow {
            handle: handle.to_string(),
            realm: realm.to_string(),
            index_key: SORT_INDEX_KEY.to_string(),
            key: key.to_string(),
            sort_at: Some(at),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_session_is_indexed_as_node_indexes_it() {
        let keys = DataKeys::ephemeral("a".repeat(44).as_str()).unwrap();
        let s = json!({ "subjectId": "urn:uuid:1", "user": { "username": "al" },
            "expires": 2000.7, "lastSeenAt": "15", "startedAt": -4,
            "chosen": true, "rpSurface": "portal", "backsConsole": true,
            "fedPartnerSession": { "relationship": "p1" } });
        let i = SessionIndex::of(&keys, &s).unwrap();
        assert_eq!(i.expires_at, Some(2000));
        assert_eq!((i.last_seen_at, i.started_at), (15, 0));
        assert_eq!(i.kind, "sign-on");
        assert!(i.chosen && i.authenticated && i.backs_console);
        assert_eq!(i.partner_relationship, "p1");
        assert_eq!(
            Some(i.subject_key.clone()),
            keys.keyed_digest("session-subject", "urn:uuid:1")
        );
        let arrival =
            SessionIndex::of(&keys, &json!({ "chosen": false })).unwrap();
        assert_eq!(arrival.kind, "arrival");
        assert_eq!(arrival.expires_at, None);
        let rp = SessionIndex::of(
            &keys,
            &json!({ "derivedFrom": "sid", "credentialKey": "k" }),
        )
        .unwrap();
        assert_eq!(rp.kind, "relying-party");
        assert!(SessionIndex::of(&keys, &json!("x")).is_none());
    }

    #[test]
    fn a_sort_row_follows_the_lookups() {
        let rows = filed("h", "r", "k", &["a".into(), "a".into()], Some(5));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].index_key, SORT_INDEX_KEY);
        assert_eq!(rows[1].sort_at, Some(5));
    }
}
