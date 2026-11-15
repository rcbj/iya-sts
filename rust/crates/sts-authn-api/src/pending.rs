// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PENDING SIGN-INS AND THEIR STEPS: the three registers
//! `authn/authn.ts` declares at load, under Node's names, so a sign-in a
//! 1.x node began is one this process continues (D11).
//!
//! | Store | Node | A row |
//! |---|---|---|
//! | `authn.pending` | `pending` | a sign-in waiting at the screen: `{ id, returnTo, protocol, application, details, expires, … }` (`beginAuthentication()`) |
//! | `authn.pendingMfa` | `pendingMfa` | a second-factor, set-up or emailed-factor step: `{ authn, username, challenge, factor, … expires }` |
//! | `authn.pendingPasswordChange` | `pendingPasswordChange` | a forced password change: `{ authn, username, secondFactor, notice, expires }` |
//!
//! Each is persisted, retained by age, and expires at its own `expires`
//! (ms) — `realms.map({ persist, retain: 'age', expiresAt:
//! realms.expiryField('expires', 1) })` (#333). A row is Node's JSON,
//! member for member; nothing here renames or reshapes one.

use std::sync::Arc;

use serde_json::Value as Json;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};

/// The three registers.
#[derive(Clone)]
pub struct PendingStores {
    pub pending: RealmMap<Json>,
    pub mfa: RealmMap<Json>,
    pub password_change: RealmMap<Json>,
}

impl PendingStores {
    /// Declares the three, as Node declares them. Before the store opens,
    /// so persistence restores what a node wrote.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> PendingStores {
        let spec = |name: &str| StoreSpec {
            retain: Retain::Age,
            expires_at: Some(expiry_field(Some("expires"), 1.0)),
            ..StoreSpec::persisted(name)
        };
        PendingStores {
            pending: RealmMap::new(lifecycle, handles, spec("authn.pending")),
            mfa: RealmMap::new(lifecycle, handles, spec("authn.pendingMfa")),
            password_change: RealmMap::new(
                lifecycle,
                handles,
                spec("authn.pendingPasswordChange"),
            ),
        }
    }
}
