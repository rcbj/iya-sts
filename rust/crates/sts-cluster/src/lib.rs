// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Several nodes against one store (`cluster/`, #46): membership, leases
//! with a fencing token every write checks, atomic claims, the secrets every
//! node shares — and the scheduler every periodic job runs on (#49). No
//! module of the runtime starts a repeating timer of its own; anything
//! periodic is a job here.
//!
//! Built a piece at a time: [`schedule`] is the scheduler's core, which
//! needs no leader — what a job is, when it is due, why it is off, which of
//! two copies of a run row is newer and when a row has expired.

#![forbid(unsafe_code)]

pub mod schedule;
