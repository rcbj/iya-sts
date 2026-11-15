// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What `mgmt-api/admin_api.ts` and the console keep in code beside the
//! model, as `tests/tools/export-admin-api-tables.js` exports it
//! (`tables/admin_api.json`): each operation's routing row — what it
//! mirrors, its tag, its console twin and the members only the twin
//! answers — the `:action` routes with their actions and form helpers, the
//! document's frame, the console's settings homes and the realm support
//! table. `build.rs` refuses a row the model does not have, and the other
//! way round.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::Value as Json;

/// One operation's routing row (`ROUTES`, flattened per action).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub method: String,
    pub path: String,
    pub operation_id: String,
    pub mirrors: String,
    pub kind: String,
    pub tag: String,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub drawn_on: Option<Vec<String>>,
    #[serde(default)]
    pub console_members: Option<Vec<String>>,
    #[serde(default)]
    pub console_twin: Option<String>,
    #[serde(default)]
    pub handler_owns_body: bool,
    #[serde(default)]
    pub writes_nothing: bool,
}

/// One `:action` route.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRoute {
    pub method: String,
    /// `/admin-api/realms/:action`.
    pub route: String,
    pub kind: String,
    pub actions: Vec<String>,
    /// The form helpers that moved to the console (#454).
    #[serde(default)]
    pub console_actions: Option<Vec<String>>,
}

/// The document `buildSpec()` makes, less what the model holds.
#[derive(Debug, Clone, Deserialize)]
pub struct Frames {
    pub management: Pair,
    pub console: Pair,
}

/// A frame with the gate on and off.
#[derive(Debug, Clone, Deserialize)]
pub struct Pair {
    pub on: Json,
    pub off: Json,
}

/// The pages a settings block is answered for.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageSettings {
    pub groups: Vec<String>,
    pub shared_with: Json,
}

/// The whole export.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tables {
    pub rows: Vec<Row>,
    pub routes: Vec<ActionRoute>,
    pub frames: Frames,
    pub homes: Json,
    pub home_problems: Json,
    pub page_settings: HashMap<String, PageSettings>,
    pub console_pages: Json,
    pub realm_support: Json,
    /// `SECTIONS`, the console's sidebar, for a service administrator.
    #[serde(default)]
    pub console_sections: Json,
    /// Every page's nav label by path (`shellJson()`'s `navLabels`).
    #[serde(default)]
    pub nav_labels: Json,
    /// `admin_scope.ts`'s `SERVICE_PAGES`: what a realm's administrator
    /// may not reach.
    #[serde(default)]
    pub service_pages: Vec<String>,
    /// `common/inetorgperson.ts`'s `CLASSES`: the schema's fixed list the
    /// Account API's Overview draws an entry against.
    #[serde(default)]
    pub inet_org_person_classes: Json,
    /// The constant tables the certificate enrollment views draw
    /// (`GET /admin-api/acme`, `/est`, `/scep`): the core's profiles and
    /// refusals, the mode's requirement row, each family's operations,
    /// actions and vocabularies — read off Node's modules by the exporter
    /// (#444, phase 5, the `apis2` slice).
    #[serde(default)]
    pub family_views: Json,
}

/// What the frames write for the base URL and the version.
pub const BASE_MARK: &str = "@@BASE@@";
pub const VERSION_MARK: &str = "@@VERSION@@";

const TEXT: &str = include_str!("../tables/admin_api.json");

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    // The file is this crate's own and build.rs has read it; a failure
    // here is a corrupted build, answered as an empty table.
    serde_json::from_str(TEXT).unwrap_or_else(|e| {
        tracing::error!("tables/admin_api.json does not parse: {}", e);
        Tables {
            rows: Vec::new(),
            routes: Vec::new(),
            frames: Frames {
                management: Pair {
                    on: Json::Null,
                    off: Json::Null,
                },
                console: Pair {
                    on: Json::Null,
                    off: Json::Null,
                },
            },
            homes: Json::Array(Vec::new()),
            home_problems: Json::Array(Vec::new()),
            page_settings: HashMap::new(),
            console_pages: Json::Array(Vec::new()),
            realm_support: Json::Array(Vec::new()),
            console_sections: Json::Array(Vec::new()),
            nav_labels: Json::Object(Default::default()),
            service_pages: Vec::new(),
            inet_org_person_classes: Json::Array(Vec::new()),
            family_views: Json::Object(Default::default()),
        }
    })
});

static ROWS_BY_ID: LazyLock<HashMap<String, usize>> = LazyLock::new(|| {
    TABLES
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| (row.operation_id.clone(), i))
        .collect()
});

/// The tables. A hot path: read on every request, so it carries no span.
pub fn tables() -> &'static Tables {
    &TABLES
}

/// The raw text, for the vector test's drift check.
pub const fn text() -> &'static str {
    TEXT
}

/// One operation's row. A hot path: asked once per request.
pub fn row(operation_id: &str) -> Option<&'static Row> {
    ROWS_BY_ID
        .get(operation_id)
        .and_then(|i| TABLES.rows.get(*i))
}

/// The `:action` route a method and path fall under, with the action the
/// path names: `POST /admin-api/realms/frob` is `/admin-api/realms/:action`
/// and `frob`. A hot path: asked once per request.
pub fn action_route(
    method: &str,
    path: &str,
) -> Option<(&'static ActionRoute, String)> {
    TABLES.routes.iter().find_map(|route| {
        let prefix = route.route.strip_suffix(":action")?;
        let action = path.strip_prefix(prefix)?;
        (route.method.eq_ignore_ascii_case(method)
            && !action.is_empty()
            && !action.contains('/'))
        .then(|| (route, action.to_string()))
    })
}
