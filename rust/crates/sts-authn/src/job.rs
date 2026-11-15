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
use sts_cluster::schedule::{JobSpec, Schedule, Unit};

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
