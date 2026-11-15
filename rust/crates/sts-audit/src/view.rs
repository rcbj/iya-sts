// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `GET /admin-api/audit` (`admin-core/admin_views.ts`'s `auditView()`):
//! the log, filtered, then paged, with its summary and its vocabulary, as
//! the model's `AuditList` (D15).
//!
//! The filters are Node's: `category`, `action` and `outcome` exact and
//! ANDed; `actor` a case-insensitive substring of either spelling of the
//! actor; `q` a case-insensitive substring of the summary, the target or
//! the action; `code` and `address` case-insensitive PREFIXES, so
//! `STS-OAUTH` is a subsystem and `10.0.` a range. Paging is
//! `pagingOf()`: `per` capped at 300 (50 by default), `page` clamped to
//! the pages there are.
//!
//! Three members come from outside the log, through [`ViewPorts`]: which
//! actors on the page have a user page (`knownUserKeys()`), the page's
//! settings (`configSettingsJson('/admin/audit')`, the settings slice's)
//! and whether minted state persists.

use std::sync::Arc;

use serde_json::{Map, Value as Json};
use sts_core::mode::Mode;
use sts_model_management_components_1 as model;

/// The page settings block a [`ViewPorts`] answers.
pub use sts_model_management_components_1::AuditListSettings;

use crate::js;
use crate::log::AuditLog;
use crate::row::AuditRow;
use crate::vocabulary;

const DEFAULT_PER_PAGE: i64 = 50;
const MAX_ROWS: i64 = 300;

/// What the answer reads from outside the log.
pub trait ViewPorts: Send + Sync {
    /// Whether `name` is a person with a user page.
    fn known_user(&self, name: &str) -> bool;
    /// `configSettingsJson('/admin/audit')`, or `None`.
    fn page_settings(&self) -> Option<model::AuditListSettings>;
    /// `persistence.mintedStatus().persisting`.
    fn persisted(&self) -> bool;
}

/// The query, as text members (`req.query`).
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub category: String,
    pub action: String,
    pub outcome: String,
    pub actor: String,
    pub q: String,
    pub code: String,
    pub address: String,
    pub page: String,
    pub per: String,
}

impl AuditQuery {
    /// From the query's members.
    #[tracing::instrument(level = "debug", skip(query))]
    pub fn from_map(query: &Map<String, Json>) -> AuditQuery {
        let text = |k: &str| js::text_if_truthy(query.get(k));
        AuditQuery {
            category: text("category"),
            action: text("action"),
            outcome: text("outcome"),
            actor: text("actor"),
            q: text("q"),
            code: text("code"),
            address: text("address"),
            page: text("page"),
            per: text("per"),
        }
    }
}

/// `pagingOf(query, total)` for a list with one pager.
#[derive(Debug, Clone, PartialEq)]
pub struct Paging {
    pub page: i64,
    pub per_page: i64,
    pub pages: i64,
    pub offset: i64,
    pub total: i64,
    pub first_row: i64,
    pub last_row: i64,
}

impl Paging {
    /// The paging of `total` rows for `page` and `per` as asked.
    #[tracing::instrument(level = "debug")]
    pub fn of(page: &str, per: &str, total: i64) -> Paging {
        let per_page = match js::parse_int(per) {
            Some(n) if n > 0 => n.min(MAX_ROWS),
            _ => DEFAULT_PER_PAGE.min(MAX_ROWS),
        };
        let pages = ((total + per_page - 1) / per_page).max(1);
        let asked = js::parse_int(page).unwrap_or(1);
        let page = asked.max(1).min(pages);
        let offset = (page - 1) * per_page;
        Paging {
            page,
            per_page,
            pages,
            offset,
            total,
            first_row: if total > 0 { offset + 1 } else { 0 },
            last_row: (offset + per_page).min(total),
        }
    }
}

fn opt(text: &str) -> Option<Option<String>> {
    Some(if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    })
}

fn event_item(row: &AuditRow) -> model::AuditListEventsItem {
    model::AuditListEventsItem {
        seq: Some(row.seq as f64),
        origin: Some(Some(row.origin.clone())),
        at: Some(row.at as f64),
        category: Some(row.category.clone()),
        action: Some(row.action.clone()),
        outcome: Some(row.outcome.clone()),
        error_code: Some(Some(row.error_code.clone())),
        actor: Some(row.actor.clone()),
        actor_form: Some(row.actor_form.clone()),
        mac: row.mac.clone(),
        prev: row.prev.clone(),
        target: Some(row.target.clone()),
        protocol: Some(row.protocol.clone()),
        channel: Some(row.channel.clone()),
        address: Some(row.address.clone()),
        summary: Some(row.summary.clone()),
        detail: Some(Json::Object(row.detail.clone())),
    }
}

/// Builds the answer of `GET /admin-api/audit`.
#[tracing::instrument(level = "debug", skip(log, mode, ports))]
pub fn audit_view(
    log: &AuditLog,
    mode: &Mode,
    ports: &Arc<dyn ViewPorts>,
    query: &AuditQuery,
) -> model::AuditList {
    let code = query.code.trim().to_uppercase();
    let address = query.address.trim().to_lowercase();
    let needle = query.q.to_lowercase();
    let actor_needle = query.actor.to_lowercase();
    let filtered: Vec<AuditRow> = log
        .list()
        .into_iter()
        .filter(|row| {
            (query.category.is_empty() || row.category == query.category)
                && (query.action.is_empty() || row.action == query.action)
                && (query.outcome.is_empty() || row.outcome == query.outcome)
                && (code.is_empty() || row.error_code.starts_with(&code))
                && (address.is_empty()
                    || row.address.to_lowercase().starts_with(&address))
                && (actor_needle.is_empty()
                    || format!("{} {}", row.actor, row.actor_form)
                        .to_lowercase()
                        .contains(&actor_needle))
                && (needle.is_empty()
                    || format!("{} {} {}", row.summary, row.target, row.action)
                        .to_lowercase()
                        .contains(&needle))
        })
        .collect();
    let paging = Paging::of(&query.page, &query.per, filtered.len() as i64);
    let shown: Vec<&AuditRow> = filtered
        .iter()
        .skip(paging.offset as usize)
        .take(paging.per_page as usize)
        .collect();
    let summary = log.summary();
    let int = |k: &str| summary.get(k).and_then(Json::as_i64);
    let map = |k: &str| summary.get(k).and_then(Json::as_object).cloned();
    let mut known = Map::new();
    for row in &shown {
        if !row.actor.is_empty() && ports.known_user(&row.actor) {
            known.insert(row.actor.clone(), Json::Bool(true));
        }
    }
    model::AuditList {
        held: int("held"),
        recorded: int("recorded"),
        dropped: int("dropped"),
        max_events: summary.get("maxEvents").and_then(Json::as_f64),
        protocol_calls: summary.get("protocolCalls").and_then(Json::as_bool),
        matched: Some(filtered.len() as i64),
        shown: Some(shown.len() as i64),
        oldest_seq: summary.get("oldestSeq").and_then(Json::as_f64),
        newest_seq: summary.get("newestSeq").and_then(Json::as_f64),
        by_category: map("byCategory"),
        by_outcome: map("byOutcome"),
        by_action: map("byAction"),
        filter: Some(model::AuditListFilter {
            category: opt(&query.category),
            action: opt(&query.action),
            outcome: opt(&query.outcome),
            actor: opt(&query.actor),
            q: opt(&query.q),
            code: opt(&code),
            address: opt(&address),
        }),
        page: Some(paging.page),
        pages: Some(paging.pages),
        per_page: Some(paging.per_page),
        first_row: Some(paging.first_row),
        last_row: Some(paging.last_row),
        categories: Some(
            vocabulary::categories()
                .iter()
                .map(|c| model::AuditListCategoriesItem {
                    category: Some(c.category.clone()),
                    label: Some(c.label.clone()),
                    what: Some(c.what.clone()),
                })
                .collect(),
        ),
        actions: Some(
            vocabulary::actions()
                .iter()
                .map(|a| model::AuditListActionsItem {
                    action: Some(a.action.clone()),
                    category: Some(a.category.clone()),
                    label: Some(a.label.clone()),
                })
                .collect(),
        ),
        outcomes: Some(vocabulary::outcomes().to_vec()),
        events: Some(shown.iter().map(|r| event_item(r)).collect()),
        paging: Some(model::AuditListPaging {
            page: Some(paging.page),
            pages: Some(paging.pages),
            per_page: Some(paging.per_page),
            first_row: Some(paging.first_row),
            last_row: Some(paging.last_row),
            total: Some(paging.total),
            param: Some("page".to_string()),
            noun: Some("rows".to_string()),
        }),
        known_actors: Some(known),
        settings: ports.page_settings(),
        verifies_credentials: Some(mode.verifies_credentials()),
        persisted: Some(ports.persisted()),
    }
}
