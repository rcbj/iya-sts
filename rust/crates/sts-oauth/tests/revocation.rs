// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The revoked-token register, held to `tests/revoked_jti_expiry.js`'s
//! claims: a revocation carries its token's `exp` (the latest stated), is
//! purged once that has passed with the skew and not before, an undated
//! one is kept; at `oauth2.maxRevokedJtis` an expired one goes first and
//! otherwise the one that expires SOONEST, an undated one last; each realm
//! has its own; and the observer is told once.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use sts_core::mode::Mode;
use sts_core::realm;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_oauth::revocation::{revoked_exp_of, RevokedTokens};

const NOW_MS: i64 = 1_791_000_000_000;
const NOW_S: i64 = NOW_MS / 1000;

fn register(
    file: serde_json::Value,
) -> (Arc<RevokedTokens>, Arc<RealmLifecycle>) {
    let settings = Arc::new(Settings::new(file, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let handles = StoreHandles::new();
    (
        RevokedTokens::new(&lifecycle, &handles, settings),
        lifecycle,
    )
}

#[test]
fn a_revocation_carries_its_tokens_expiry() {
    let (r, _) = register(json!({ "oauth2": { "clockSkewS": 60 } }));
    let told = Arc::new(Mutex::new(Vec::new()));
    let seen = told.clone();
    r.set_observer(Some(Arc::new(move |jti: &str, via: &str| {
        seen.lock().unwrap().push(format!("{}/{}", jti, via));
    })));
    assert!(r.revoke("a", "/oauth2/revoke", NOW_S + 100, NOW_MS));
    assert!(
        !r.revoke("a", "logout", NOW_S + 50, NOW_MS),
        "already revoked"
    );
    assert_eq!(r.exp_of("a"), Some(NOW_S + 100), "the latest stated");
    assert!(r.revoke("undated", "", 0, NOW_MS));
    assert!(!r.revoke("", "x", 1, NOW_MS));
    assert_eq!(
        *told.lock().unwrap(),
        vec!["a//oauth2/revoke".to_string(), "undated/unstated".into()]
    );
    assert!(r.is_revoked("a") && !r.is_revoked("b") && !r.is_revoked(""));
    // Not before exp plus the skew; then gone; an undated one kept.
    assert_eq!(r.purge_expired((NOW_S + 100) * 1000 + 59_999), 0);
    assert!(r.is_revoked("a"));
    assert_eq!(r.purge_expired((NOW_S + 160) * 1000), 1);
    assert!(!r.is_revoked("a") && r.is_revoked("undated"));
    assert!(r.restore("undated") && !r.restore("undated"));
    assert_eq!(
        revoked_exp_of(&json!(true)),
        0,
        "a value from before #345 is undated"
    );
    assert_eq!(revoked_exp_of(&json!({ "exp": "x" })), 0);
}

#[test]
fn the_cap_forgets_the_soonest_to_expire() {
    let (r, _) =
        register(json!({ "oauth2": { "maxRevokedJtis": 3, "clockSkewS": 0 } }));
    r.revoke("late", "", NOW_S + 300, NOW_MS);
    r.revoke("soon", "", NOW_S + 100, NOW_MS);
    r.revoke("never", "", 0, NOW_MS);
    r.revoke("next", "", NOW_S + 200, NOW_MS);
    assert!(!r.is_revoked("soon"), "the soonest to expire went");
    assert!(
        r.is_revoked("late") && r.is_revoked("never") && r.is_revoked("next")
    );
    // An undated revocation sorts last.
    r.revoke("another", "", NOW_S + 400, NOW_MS);
    assert!(!r.is_revoked("next") && r.is_revoked("never"));
    // With an expired one held, it goes first and nothing live is forgotten.
    let (r, _) =
        register(json!({ "oauth2": { "maxRevokedJtis": 2, "clockSkewS": 0 } }));
    r.revoke("dead", "", NOW_S - 10, NOW_MS);
    r.revoke("live", "", NOW_S + 10, NOW_MS);
    r.revoke("new", "", NOW_S + 20, NOW_MS);
    assert!(
        !r.is_revoked("dead") && r.is_revoked("live") && r.is_revoked("new")
    );
    assert_eq!(r.len(), 2);
}

#[test]
fn each_realm_has_its_own() {
    let (r, lifecycle) = register(json!({ "realms": { "enabled": true } }));
    let other = lifecycle
        .create(
            "other",
            "Other",
            "",
            "other.example",
            &Default::default(),
            false,
        )
        .unwrap();
    r.revoke("mine", "", NOW_S + 10, NOW_MS);
    realm::run_sync(other.clone(), || {
        assert!(!r.is_revoked("mine"));
        r.revoke("theirs", "", NOW_S + 10, NOW_MS);
        assert!(r.is_revoked("theirs"));
    });
    assert!(!r.is_revoked("theirs") && r.is_revoked("mine"));
    // The purge reaches every realm.
    assert_eq!(r.purge_expired((NOW_S + 3600) * 1000), 2);
    realm::run_sync(other, || assert!(r.is_empty()));
}
