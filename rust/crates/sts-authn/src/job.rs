// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SWEEP IS A SCHEDULER JOB (rcbj, 2026-09-21; #49): `authn.session-
//! expiry`, a CLUSTER job every `authn.sessionSweepS` seconds (30, and 0
//! switches it off), run on the scheduler's leader. It adds no path of its
//! own to the audit row, CAEP or the Logout Tokens: every end goes through
//! [`crate::Sessions::expire_session`]. What stays where it is: the lazy
//! check at a read, which is correctness rather than housekeeping.

use std::sync::Arc;

use serde_json::json;
use sts_cluster::schedule::{JobSpec, Schedule, Scope, Unit};

use crate::Sessions;

/// The job's id (`SESSION_EXPIRY_JOB`).
pub const SESSION_EXPIRY_JOB: &str = "authn.session-expiry";
/// Its interval's setting (`SESSION_SWEEP_SETTING`).
pub const SESSION_SWEEP_SETTING: &str = "authn.sessionSweepS";

/// `authn.session-expiry`, as `authn.ts` registers it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn session_expiry_job(sessions: Arc<Sessions>) -> JobSpec {
    let mut job = JobSpec::new(
        SESSION_EXPIRY_JOB,
        "Session expiry",
        "Ends every sign-on session whose lifetime or idle timeout has \
         passed, and, in each realm, at most that realm's \
         authn.sessionShedPerSweep of one subject's own surplus sessions.",
        "authn/authn.ts",
        Schedule::EverySetting {
            key: SESSION_SWEEP_SETTING.to_string(),
            unit: Unit::S,
        },
    );
    job.run = Some(Arc::new(move |_ctx| {
        let sessions = sessions.clone();
        Box::pin(async move {
            let ended = sessions.sweep_expired_sessions();
            Ok(json!({ "ended": ended }))
        })
    }));
    job
}

/// `authn.account-set-expiry` (#561), as `authn.ts` registers it: a cluster
/// job run per realm, every minute, each run about a second's work from
/// where the last stopped (#784), so a pass over every set takes about an
/// hour. Nothing waits on it: a set is pruned again whenever its browser
/// draws the picker.
#[tracing::instrument(level = "debug", skip_all)]
pub fn account_set_expiry_job(sessions: Arc<Sessions>) -> JobSpec {
    let mut job = JobSpec::new(
        crate::sessions::accounts::ACCOUNT_SET_EXPIRY_JOB,
        "Account set expiry",
        "Brings every browser's account set up to date (#561): an account \
         whose session ended is remembered as signed out, one remembered \
         longer than authn.rememberedAccountDays is dropped, and an empty \
         set is deleted.",
        "authn/authn.ts",
        Schedule::Every(Arc::new(|| 60.0 * 1000.0)),
    );
    job.scope = Scope::Realm;
    job.run = Some(Arc::new(move |_ctx| {
        let sessions = sessions.clone();
        Box::pin(
            async move { Ok(sessions.sweep_account_sets_budgeted().await) },
        )
    }));
    job
}
