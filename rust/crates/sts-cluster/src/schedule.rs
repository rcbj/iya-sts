// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The scheduler's pure core (`cluster/scheduler.ts`, #49): what a job is,
//! when it is due, why it is off, which of two copies of a run row is newer,
//! and when a row is past every bound the history keeps.
//!
//! **A slot, not a timer.** An interval job's slots are the multiples of its
//! interval on the DATABASE's clock, so every node computes the same slot and
//! the same next time, and a run's id is derived from (job, realm, slot) so
//! two leaders reaching one slot claim ONE row. A slot missed while nobody
//! led runs once when somebody does, because only the current slot is ever
//! due. A cron job's slot is its most recent occurrence, in UTC; the grammar
//! is croner's (the npm package's, which the `croner` crate shares).
//!
//! The leader, the claims and the runs themselves are the runner's, which
//! stands on this module.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{TimeZone, Utc};
use croner::parser::{CronParser, Seconds};
use croner::Cron;
use indexmap::IndexMap;
use openssl::hash::{hash, MessageDigest};
use serde_json::Value as Json;
use sts_core::errors::codes;
use sts_core::log::tag;

/// The lease the leader holds; only its holder runs cluster jobs.
pub const LEADER_LEASE: &str = "ops.scheduler";
/// The claim scope a cluster run is claimed under, its value the run's id.
pub const RUN_SCOPE: &str = "scheduler.run";
/// A run's states. `queued` is a manual run nobody has taken yet; the three
/// after `running` are final.
pub const STATES: &[&str] =
    &["queued", "running", "succeeded", "failed", "abandoned"];
pub const FINAL: &[&str] = &["succeeded", "failed", "abandoned"];
/// A quiet job's run is recorded at most this often while its outcome holds.
pub const QUIET_RECORD_MS: f64 = 60_000.0;
/// How far past the instant the purge would first be free to delete a row
/// its expiry is written, so a job that runs every slot never has a kept
/// row near its expiry.
pub const EXPIRY_SLACK_MS: f64 = 2.0 * 60.0 * 60.0 * 1000.0;
/// Never less than this past its slot before a due job is called overdue.
pub const OVERDUE_FLOOR_MS: f64 = 60_000.0;

/// The scheduler's settings, read where they are used: `0` is a legal value
/// of an interval setting and means OFF.
pub trait SchedulerSettings: Send + Sync {
    fn number(&self, key: &str) -> f64;
    fn flag(&self, key: &str) -> bool;
    fn list(&self, key: &str) -> Vec<String>;
}

impl SchedulerSettings for sts_core::settings::Settings {
    fn number(&self, key: &str) -> f64 {
        self.value_of(key).as_int() as f64
    }
    fn flag(&self, key: &str) -> bool {
        self.value_of(key).as_bool()
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.value_of(key).as_list().to_vec()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Runs once for the service, on the leader.
    Cluster,
    /// Runs in every process that holds the state it cleans.
    PerProcess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Once, in the default realm.
    Service,
    /// In every realm.
    Realm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Ms,
    S,
    Min,
    H,
    Days,
}

impl Unit {
    fn factor(self) -> f64 {
        match self {
            Unit::Ms => 1.0,
            Unit::S => 1000.0,
            Unit::Min => 60_000.0,
            Unit::H => 3_600_000.0,
            Unit::Days => 86_400_000.0,
        }
    }
}

/// When a job runs: exactly one of the four, which the type makes so.
#[derive(Clone)]
pub enum Schedule {
    /// An interval the job computes, in milliseconds.
    Every(Arc<dyn Fn() -> f64 + Send + Sync>),
    /// An interval read from a setting, in its unit.
    EverySetting { key: String, unit: Unit },
    /// A cron expression, in UTC.
    Cron(String),
    /// Only when an administrator asks.
    ManualOnly,
}

pub type OffCheck = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// A registered job's description. The runner adds what it runs.
#[derive(Clone)]
pub struct JobSpec {
    pub id: String,
    pub title: String,
    pub describe: String,
    pub owner: String,
    pub kind: Kind,
    pub scope: Scope,
    pub schedule: Schedule,
    /// A per-process job that runs often: recorded only when its outcome
    /// changes, or once a minute.
    pub quiet: bool,
    /// Whether an administrator may run it now.
    pub manual: bool,
    /// Its own time limit in seconds, else `scheduler.runTimeoutS`.
    pub timeout_s: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    /// Why the job is off in a realm, or `''`; an `Err` is its own check
    /// failing.
    pub off: Option<OffCheck>,
}

impl JobSpec {
    /// A cluster job of the service, run on `schedule`, that an
    /// administrator may also run.
    pub fn new(
        id: &str,
        title: &str,
        describe: &str,
        owner: &str,
        schedule: Schedule,
    ) -> JobSpec {
        JobSpec {
            id: id.to_string(),
            title: title.to_string(),
            describe: describe.to_string(),
            owner: owner.to_string(),
            kind: Kind::Cluster,
            scope: Scope::Service,
            schedule,
            quiet: false,
            manual: true,
            timeout_s: None,
            off: None,
        }
    }

    fn manual_only(&self) -> bool {
        matches!(self.schedule, Schedule::ManualOnly)
    }

    fn cron(&self) -> Option<&str> {
        match &self.schedule {
            Schedule::Cron(c) => Some(c),
            _ => None,
        }
    }
}

/// The slot a job is due for, and when the next one starts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Slot {
    /// The slot's number (an interval's multiple), or a cron occurrence;
    /// `None` for a cron expression with no occurrence yet.
    pub slot: Option<i64>,
    /// Milliseconds; fractional where the interval is (JavaScript's).
    pub starts_at: Option<f64>,
    pub next_at: Option<f64>,
}

/// The run history's bound: a job's last `count` runs or its last
/// `keep_ms`, whichever keeps more.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HistoryBounds {
    pub count: f64,
    pub keep_ms: f64,
}

fn parser() -> CronParser {
    CronParser::builder().seconds(Seconds::Optional).build()
}

/// A cron expression read as croner reads it, or croner's complaint.
pub fn parse_cron(expr: &str) -> Result<Cron, String> {
    parser().parse(expr).map_err(|e| e.to_string())
}

fn whole_second(ms: i64) -> Option<chrono::DateTime<Utc>> {
    Utc.timestamp_opt(ms.div_euclid(1000), 0).single()
}

/// The most recent occurrence at or before `ms`, in UTC. croner counts in
/// whole seconds, so an occurrence at 03:00:00 is found from 03:00:00.999.
pub fn cron_prev(expr: &str, ms: i64) -> Option<i64> {
    let cron = parse_cron(expr).ok()?;
    cron.find_previous_occurrence(&whole_second(ms)?, true)
        .ok()
        .map(|t| t.timestamp_millis())
}

/// The next occurrence after `ms`, in UTC.
pub fn cron_next(expr: &str, ms: i64) -> Option<i64> {
    let cron = parse_cron(expr).ok()?;
    cron.find_next_occurrence(&whole_second(ms)?, false)
        .ok()
        .map(|t| t.timestamp_millis())
}

/// A job id: lower-case words joined by dots and hyphens, at least two.
pub fn valid_job_id(id: &str) -> bool {
    let mut parts = id.split(['.', '-']);
    let Some(first) = parts.next() else {
        return false;
    };
    let word = |w: &str| {
        !w.is_empty()
            && w.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    let rest: Vec<&str> = parts.collect();
    first.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && word(first)
        && !rest.is_empty()
        && rest.iter().all(|w| word(w))
}

/// "4 min 12 s", "2 h 5 min", "90 d" — two units at most.
pub fn span(ms: f64) -> String {
    let mut left = ((ms / 1000.0) + 0.5).floor().max(0.0) as i64;
    let mut parts: Vec<String> = Vec::new();
    for (size, name) in [(86_400, "d"), (3_600, "h"), (60, "min"), (1, "s")] {
        if parts.len() < 2 && (left >= size || (size == 1 && parts.is_empty()))
        {
            let n = left / size;
            left -= n * size;
            parts.push(format!("{} {}", n, name));
        }
    }
    parts.join(" ")
}

/// `Number(x) || 0` of a row's field.
fn num(row: &Json, key: &str) -> f64 {
    let n = match row.get(key) {
        Some(Json::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Json::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse().unwrap_or(f64::NAN)
            }
        }
        Some(Json::Bool(true)) => 1.0,
        _ => 0.0,
    };
    if n.is_nan() {
        0.0
    } else {
        n
    }
}

fn state_rank(state: &str) -> f64 {
    if FINAL.contains(&state) {
        2.0
    } else if state == "running" {
        1.0
    } else {
        0.0
    }
}

fn rank_of(row: &Json) -> [f64; 4] {
    [
        num(row, "attempt"),
        num(row, "fenceAt"),
        state_rank(row.get("state").and_then(Json::as_str).unwrap_or("")),
        num(row, "updatedAt"),
    ]
}

/// Which of two copies of a run row is newer: (attempt, fence, final over
/// running over queued, last update). A total order, so the store's merge
/// converges; on a tie the stored copy stands.
pub fn compare_rows(a: &Json, b: &Json) -> std::cmp::Ordering {
    let (x, y) = (rank_of(a), rank_of(b));
    for i in 0..4 {
        if x[i] != y[i] {
            return if x[i] < y[i] {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
    }
    std::cmp::Ordering::Equal
}

/// The store's merge of two copies of a row: mine only when it ranks above.
pub fn merge_rows<'a>(mine: &'a Json, theirs: &'a Json) -> &'a Json {
    if compare_rows(mine, theirs).is_gt() {
        mine
    } else {
        theirs
    }
}

/// The instant a row ended, for every rule of the history.
pub fn ended_of(row: &Json) -> f64 {
    [
        num(row, "endedAt"),
        num(row, "queuedAt"),
        num(row, "updatedAt"),
    ]
    .into_iter()
    .find(|n| *n != 0.0)
    .unwrap_or(0.0)
}

/// A run's id: from (job, realm, slot), so two leaders reaching one slot
/// claim one row.
pub fn run_id_for(job_id: &str, realm_id: &str, slot: i64) -> String {
    let text = format!("{}\n{}\n{}", job_id, realm_id, slot);
    let digest = hash(MessageDigest::sha256(), text.as_bytes())
        .map(|d| URL_SAFE_NO_PAD.encode(d))
        .unwrap_or_default();
    format!("s-{}", digest.get(..22).unwrap_or(&digest))
}

/// Every registered job and the rules over them that need no leader.
pub struct Schedules {
    jobs: IndexMap<String, JobSpec>,
    settings: Arc<dyn SchedulerSettings>,
    /// How many connections the store's pool holds; 0 where there is none.
    store_connections: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
}

impl Schedules {
    pub fn new(settings: Arc<dyn SchedulerSettings>) -> Schedules {
        Schedules {
            jobs: IndexMap::new(),
            settings,
            store_connections: None,
        }
    }

    pub fn with_store_connections(
        mut self,
        f: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Schedules {
        self.store_connections = Some(f);
        self
    }

    /// Registers a job, refused WHOLE when a member is missing or malformed
    /// (`STS-SCHED-0009`): a job registered half-way would be a row on the
    /// page that never runs.
    pub fn register(&mut self, spec: JobSpec) -> Result<(), String> {
        let mut problems: Vec<String> = Vec::new();
        if !valid_job_id(&spec.id) {
            problems.push(
                "an id of dot- or hyphen-separated lower-case words"
                    .to_string(),
            );
        }
        for (name, value) in [
            ("title", &spec.title),
            ("describe", &spec.describe),
            ("owner", &spec.owner),
        ] {
            if value.trim().is_empty() {
                problems.push(format!("a {}", name));
            }
        }
        if let Some(expr) = spec.cron() {
            if let Err(e) = parse_cron(expr) {
                problems
                    .push(format!("a cron expression croner can read ({})", e));
            }
        }
        if spec.quiet && spec.kind != Kind::PerProcess {
            problems.push(
                "no quiet flag: only a per-process job is recorded quietly, because a cluster job's run row \
                 is its fence"
                    .to_string(),
            );
        }
        if spec.kind == Kind::PerProcess && spec.manual_only() {
            problems.push(
                "a schedule: a per-process job cannot be on demand only, because nothing queues a run in every \
                 process"
                    .to_string(),
            );
        }
        if self.jobs.contains_key(&spec.id) {
            problems.push(format!(
                "an id no other job has (\"{}\" is registered)",
                spec.id
            ));
        }
        if !problems.is_empty() {
            return Err(format!(
                "{}scheduler: the job \"{}\" was not registered. It needs {}.",
                tag(codes::STS_SCHED_0009),
                spec.id,
                problems.join("; ")
            ));
        }
        self.jobs.insert(spec.id.clone(), spec);
        Ok(())
    }

    pub fn job(&self, id: &str) -> Option<&JobSpec> {
        self.jobs.get(id)
    }

    pub fn job_ids(&self) -> Vec<String> {
        self.jobs.keys().cloned().collect()
    }

    pub fn jobs(&self) -> impl Iterator<Item = &JobSpec> {
        self.jobs.values()
    }

    pub fn unregister(&mut self, id: &str) -> bool {
        self.jobs.shift_remove(id).is_some()
    }

    /// How many cluster runs the leader may have going at once:
    /// `scheduler.maxConcurrentRuns`, and never every connection the store's
    /// pool holds — one is always left for the requests.
    pub fn max_concurrent_runs(&self) -> f64 {
        let setting = self.settings.number("scheduler.maxConcurrentRuns");
        let mut n = if setting >= 1.0 { setting } else { 1.0 };
        let pool = self.store_connections.as_ref().map_or(0.0, |f| f());
        if pool > 0.0 {
            n = n.min((pool - 1.0).max(1.0));
        }
        n
    }

    pub fn tick_ms(&self) -> f64 {
        (self.settings.number("scheduler.tickS") * 1000.0).max(1000.0)
    }

    /// A job's interval, or 0 for a job with none.
    pub fn interval_ms(&self, job: &JobSpec) -> f64 {
        match &job.schedule {
            Schedule::Every(f) => {
                let n = f();
                if n.is_nan() {
                    0.0
                } else {
                    n
                }
            }
            Schedule::EverySetting { key, unit } => {
                let value = self.settings.number(key);
                if value > 0.0 {
                    value * unit.factor()
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }

    /// The slot a job is due for at `at`, by the database's clock; `None`
    /// for a job on demand only or with an interval of 0.
    pub fn slot_at(&self, job: &JobSpec, at: i64) -> Option<Slot> {
        match &job.schedule {
            Schedule::ManualOnly => None,
            Schedule::Cron(expr) => {
                let prev = cron_prev(expr, at);
                Some(Slot {
                    slot: prev,
                    starts_at: prev.map(|p| p as f64),
                    next_at: cron_next(expr, at).map(|n| n as f64),
                })
            }
            _ => {
                let every = self.interval_ms(job);
                if every <= 0.0 {
                    return None;
                }
                let slot = (at as f64 / every).floor();
                Some(Slot {
                    slot: Some(slot as i64),
                    starts_at: Some(slot * every),
                    next_at: Some((slot + 1.0) * every),
                })
            }
        }
    }

    /// A job's schedule in words, for the page and the API.
    pub fn schedule_text(&self, job: &JobSpec) -> String {
        match &job.schedule {
            Schedule::ManualOnly => "on demand only".to_string(),
            Schedule::Cron(expr) => format!("cron {} (UTC)", expr),
            schedule => {
                let every = self.interval_ms(job);
                let mut text = if every > 0.0 {
                    format!("every {}", span(every))
                } else {
                    "no interval (0)".to_string()
                };
                if let Schedule::EverySetting { key, .. } = schedule {
                    text.push_str(&format!(", from {}", key));
                }
                text
            }
        }
    }

    /// The job ids named in `scheduler.disabledJobs`.
    pub fn disabled_ids(&self) -> Vec<String> {
        self.settings
            .list("scheduler.disabledJobs")
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Why a job is off in every realm: the scheduler disabled, the job named
    /// in `scheduler.disabledJobs`, or an interval of 0. `''` when none.
    pub fn service_off_reason(&self, job: &JobSpec) -> String {
        if !self.settings.flag("scheduler.enabled") {
            return "scheduler.enabled is off".to_string();
        }
        if self.disabled_ids().contains(&job.id) {
            return "named in scheduler.disabledJobs".to_string();
        }
        let timed =
            !matches!(job.schedule, Schedule::ManualOnly | Schedule::Cron(_));
        if timed && self.interval_ms(job) <= 0.0 {
            let what = match &job.schedule {
                Schedule::EverySetting { key, .. } => key.as_str(),
                _ => "its interval",
            };
            return format!("{} is 0", what);
        }
        String::new()
    }

    /// The job's own `off()` for one realm — the only reason that can differ
    /// from one realm to the next.
    pub fn own_off_reason(&self, job: &JobSpec, realm_id: &str) -> String {
        match &job.off {
            None => String::new(),
            Some(off) => match off(realm_id) {
                Ok(reason) => reason,
                Err(e) => format!("its own check failed: {}", e),
            },
        }
    }

    /// Why a job is off, or `''` when it is on.
    pub fn off_reason(&self, job: &JobSpec, realm_id: &str) -> String {
        let whole = self.service_off_reason(job);
        if !whole.is_empty() {
            return whole;
        }
        self.own_off_reason(job, realm_id)
    }

    /// A run's time limit: the job's own, else `scheduler.runTimeoutS`, and
    /// never under a second.
    pub fn timeout_ms_of(&self, job: &JobSpec) -> f64 {
        let own = job.timeout_s.as_ref().map_or(0.0, |f| f());
        let s = if own > 0.0 {
            own
        } else {
            self.settings.number("scheduler.runTimeoutS")
        };
        (s * 1000.0).max(1000.0)
    }

    /// How long until the next tick of one kind of job: until the earliest
    /// slot boundary of such a job that is on, at most `scheduler.tickS`, at
    /// least 100 ms — so a job whose interval is shorter than a tick runs on
    /// its own interval rather than rounded up.
    pub fn next_delay_ms(
        &self,
        kind: Kind,
        at: i64,
        default_realm: &str,
    ) -> f64 {
        let mut soonest = self.tick_ms();
        for job in self.jobs.values() {
            if job.kind != kind || job.manual_only() {
                continue;
            }
            if job.scope != Scope::Realm
                && !self.off_reason(job, default_realm).is_empty()
            {
                continue;
            }
            let Some(next) = self.slot_at(job, at).and_then(|s| s.next_at)
            else {
                continue;
            };
            if next.is_nan() || next <= 0.0 {
                continue;
            }
            // A few milliseconds past the boundary, so the slot has moved on.
            let wait = next - at as f64 + 5.0;
            if wait < soonest {
                soonest = wait;
            }
        }
        soonest.max(100.0)
    }

    pub fn history_bounds(&self) -> HistoryBounds {
        let count = self.settings.number("scheduler.runHistoryCount");
        let hours = self.settings.number("scheduler.runHistoryHours");
        HistoryBounds {
            count: if count >= 1.0 { count.floor() } else { 1.0 },
            keep_ms: if hours > 0.0 {
                hours * 3_600_000.0
            } else {
                0.0
            },
        }
    }

    /// The interval a per-process row is rewritten at, at the least.
    pub fn process_every_ms(&self, job: &JobSpec) -> f64 {
        let every = self.interval_ms(job);
        if job.quiet {
            QUIET_RECORD_MS.max(every)
        } else if every != 0.0 {
            every
        } else {
            self.tick_ms()
        }
    }

    /// The instant after which a run-store row is past every bound the
    /// history keeps, so a start need not read it back; `None` for a row
    /// that does not expire — the leader's, a queued or running one, one of
    /// a job not registered here or with no interval. Never before a pin
    /// (`keepUntil`).
    pub fn expiry_of(&self, row: &Json) -> Option<f64> {
        if !row.is_object() {
            return None;
        }
        let pinned = num(row, "keepUntil");
        let ended = ended_of(row);
        let bounds = self.history_bounds();
        let text = |k: &str| row.get(k).and_then(Json::as_str).unwrap_or("");
        let job = || self.jobs.get(text("jobId"));
        let at = match text("kind") {
            "command" => (text("state") != "queued" && ended != 0.0)
                .then_some(ended + bounds.keep_ms + EXPIRY_SLACK_MS),
            "process" => match job() {
                Some(job) if ended != 0.0 => Some(
                    ended
                        + bounds.keep_ms.max(3.0 * self.process_every_ms(job))
                        + EXPIRY_SLACK_MS,
                ),
                _ => None,
            },
            "run" if FINAL.contains(&text("state")) && ended != 0.0 => {
                let every = match job() {
                    Some(job) if !job.manual_only() && job.cron().is_none() => {
                        self.interval_ms(job)
                    }
                    _ => 0.0,
                };
                (every > 0.0).then(|| {
                    ended
                        + bounds.keep_ms.max((bounds.count + 1.0) * every)
                        + EXPIRY_SLACK_MS
                })
            }
            _ => None,
        };
        at.map(|at| at.max(pinned))
    }
}
