// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One listener's thread pool, and the figures the heartbeat reports.
//!
//! THE ACCEPT LOOP STAYS ON THE PROCESS RUNTIME. A Tokio `TcpStream` cannot
//! move onto another runtime, so an accepted socket is `into_std()`, set
//! non-blocking, and handed to a worker. The worker owns a current-thread
//! runtime and turns the socket back into a Tokio stream THERE, before the
//! TLS handshake and `serve_connection`. `block_on` is called once per job,
//! never from inside `block_on`. A client that drives its connections
//! with `tokio::spawn` (the proxy's reqwest client) is built on that
//! worker: an idle connection is polled only by the runtime that opened
//! it, and a later request on another worker waits out the upstream
//! timeout on a driver nobody is running.
//!
//! THE QUEUE HOLDS `max` CONNECTIONS. Past that, or past `maxConnections`,
//! the socket is dropped and counted `refused`. The pool starts `min`
//! workers, grows to `max` while the queue is non-empty, and an idle worker
//! above `min` leaves after 30s. Counters are cumulative since this process
//! started except the pool's gauges (`current`, `busy`, `idle`, `queued`).
//!
//! `headersTimeoutS` IS A DEADLINE OF ITS OWN (2026-11-16). hyper's
//! `header_read_timeout` starts when a connection begins waiting for a
//! request head, which on a kept-alive connection is the idle wait, so it
//! can only be armed past the keep-alive (`headers_timeout_s()`), and with
//! `headersTimeoutS` below the keep-alive it was never what closed a slow
//! client — the keep-alive watchdog was, at 60 s. [`drive`] now keeps the
//! deadline itself: from the first byte of a request head to the moment
//! hyper hands the request to the service. A head still unfinished
//! `headersTimeoutS` after its first byte closes the connection, whatever
//! trickle of bytes keeps the idle watchdog quiet. HTTP/2 has no header
//! timeout in hyper; there the deadline runs from the connection's first
//! byte (the preface) to its first request, and is not re-armed, because
//! later frames (a PING, a WINDOW_UPDATE) are not the start of a head.
//!
//! PATHS ARE THE PROCESS'S, NOT A LISTENER'S: one table, method and path
//! with the query stripped, 256 distinct paths, no token and no session id.
//! Memory is read from `/proc/self/status` when the heartbeat is built.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use serde_json::{json, Value};
use sts_core::log::tag;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::listener_tuning::{headers_timeout_s, Tuning};

const IDLE_BEFORE_SHRINK: Duration = Duration::from_secs(30);
const PATH_CAP: usize = 256;

/// HTTP knobs of one connection, snapshotted when the worker starts it so a
/// later save does not rebuild a connection that is already open.
#[derive(Debug, Clone)]
pub struct HttpCfg {
    pub http2: bool,
    pub streams: u32,
    pub keep_alive: Duration,
    /// hyper's own `header_read_timeout`, past the keep-alive.
    pub headers: Duration,
    /// `headersTimeoutS` as asked: from a head's first byte to its end.
    /// `None` is 0, no deadline of its own.
    pub head_deadline: Option<Duration>,
    pub max_requests: u64,
    pub max_connections: u64,
}

impl HttpCfg {
    pub fn from_tuning(tuning: &Tuning, https: bool) -> HttpCfg {
        let keep = tuning.keep_alive_timeout_s.max(1);
        let headers = headers_timeout_s(keep, tuning.headers_timeout_s);
        HttpCfg {
            http2: https && tuning.http2,
            streams: tuning.http2_max_concurrent_streams.max(1),
            keep_alive: Duration::from_secs(keep),
            headers: Duration::from_secs(headers),
            head_deadline: (tuning.headers_timeout_s > 0)
                .then(|| Duration::from_secs(tuning.headers_timeout_s)),
            max_requests: tuning.max_requests_per_socket,
            max_connections: tuning.max_connections,
        }
    }
}

#[derive(Debug)]
struct Counters {
    accepted: AtomicU64,
    open: AtomicU64,
    refused: AtomicU64,
    http1: AtomicU64,
    http2: AtomicU64,
    handshakes: AtomicU64,
    handshake_failures: AtomicU64,
}

impl Counters {
    fn new() -> Counters {
        Counters {
            accepted: AtomicU64::new(0),
            open: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            http1: AtomicU64::new(0),
            http2: AtomicU64::new(0),
            handshakes: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
        }
    }
}

type Job = Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>;

struct PoolInner {
    min: AtomicUsize,
    max: AtomicUsize,
    current: AtomicUsize,
    busy: AtomicUsize,
    queued: AtomicUsize,
    completed: AtomicU64,
    started: AtomicBool,
    stop: AtomicBool,
    queue: Mutex<VecDeque<Job>>,
    cv: Condvar,
    name: String,
}

/// The workers and the queue of one listener.
struct Pool {
    inner: Arc<PoolInner>,
}

impl Pool {
    fn new(name: &str, min: usize, max: usize) -> Pool {
        let (min, max) = bounds(min, max);
        Pool {
            inner: Arc::new(PoolInner {
                min: AtomicUsize::new(min),
                max: AtomicUsize::new(max),
                current: AtomicUsize::new(0),
                busy: AtomicUsize::new(0),
                queued: AtomicUsize::new(0),
                completed: AtomicU64::new(0),
                started: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                queue: Mutex::new(VecDeque::new()),
                cv: Condvar::new(),
                name: name.to_string(),
            }),
        }
    }

    fn set_bounds(&self, min: usize, max: usize) {
        let (min, max) = bounds(min, max);
        self.inner.min.store(min, Ordering::Release);
        self.inner.max.store(max, Ordering::Release);
        if self.inner.started.load(Ordering::Acquire) {
            self.ensure_min();
        }
    }

    fn start(&self) {
        self.inner.started.store(true, Ordering::Release);
        self.ensure_min();
    }

    fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.cv.notify_all();
    }

    /// `false` when the queue already holds `max` jobs: the caller drops
    /// the socket and counts a refusal. The queue depth is the pool's max,
    /// not a separate knob.
    fn enqueue(&self, job: Job) -> bool {
        if self.inner.stop.load(Ordering::Acquire) {
            return false;
        }
        let max = self.inner.max.load(Ordering::Acquire).max(1);
        {
            let mut queue = lock_queue(&self.inner.queue);
            if queue.len() >= max {
                return false;
            }
            queue.push_back(job);
            self.inner.queued.fetch_add(1, Ordering::Release);
        }
        self.inner.cv.notify_one();
        self.grow_if_busy();
        true
    }

    fn ensure_min(&self) {
        let min = self.inner.min.load(Ordering::Acquire);
        while self.inner.current.load(Ordering::Acquire) < min {
            if !self.spawn_one() {
                break;
            }
        }
    }

    fn grow_if_busy(&self) {
        let current = self.inner.current.load(Ordering::Acquire);
        let max = self.inner.max.load(Ordering::Acquire);
        let queued = self.inner.queued.load(Ordering::Acquire);
        let busy = self.inner.busy.load(Ordering::Acquire);
        if queued > 0 && busy >= current && current < max {
            let _ = self.spawn_one();
        }
    }

    fn spawn_one(&self) -> bool {
        if self.inner.stop.load(Ordering::Acquire) {
            return false;
        }
        let max = self.inner.max.load(Ordering::Acquire);
        let current = self.inner.current.load(Ordering::Acquire);
        if current >= max {
            return false;
        }
        if self
            .inner
            .current
            .compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let inner = self.inner.clone();
        let name = format!("pep-{}", &inner.name[..inner.name.len().min(12)]);
        let built = std::thread::Builder::new()
            .name(name)
            .spawn(move || worker(inner));
        if built.is_err() {
            self.inner.current.fetch_sub(1, Ordering::AcqRel);
            tracing::error!(
                "{}xacml-pep: a listener pool worker did not start. The \
                 pool keeps the workers it has.",
                tag("STS-XPEP-0119")
            );
            return false;
        }
        true
    }

    fn snapshot(&self) -> PoolSnap {
        let current = self.inner.current.load(Ordering::Acquire);
        let busy = self.inner.busy.load(Ordering::Acquire).min(current);
        PoolSnap {
            min: self.inner.min.load(Ordering::Acquire),
            max: self.inner.max.load(Ordering::Acquire),
            current,
            busy,
            idle: current - busy,
            queued: self.inner.queued.load(Ordering::Acquire),
            completed: self.inner.completed.load(Ordering::Acquire),
        }
    }
}

struct PoolSnap {
    min: usize,
    max: usize,
    current: usize,
    busy: usize,
    idle: usize,
    queued: usize,
    completed: u64,
}

fn bounds(min: usize, max: usize) -> (usize, usize) {
    let min = min.clamp(1, 256);
    let max = max.clamp(min, 1024);
    (min, max)
}

fn lock_queue(
    queue: &Mutex<VecDeque<Job>>,
) -> std::sync::MutexGuard<'_, VecDeque<Job>> {
    queue.lock().unwrap_or_else(|e| e.into_inner())
}

struct WorkerGuard(Arc<PoolInner>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.current.fetch_sub(1, Ordering::AcqRel);
        if !self.0.stop.load(Ordering::Acquire) {
            // Two idle workers can leave together and land below min. The
            // next one to go brings the pool back; a later submit does too.
            let min = self.0.min.load(Ordering::Acquire);
            if self.0.current.load(Ordering::Acquire) < min
                && self.0.started.load(Ordering::Acquire)
            {
                let pool = Pool {
                    inner: self.0.clone(),
                };
                pool.ensure_min();
            }
        }
        self.0.cv.notify_all();
    }
}

fn worker(inner: Arc<PoolInner>) {
    let _guard = WorkerGuard(inner.clone());
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: a listener pool worker has no runtime ({}). \
                 That worker is not used.",
                tag("STS-XPEP-0119"),
                error
            );
            return;
        }
    };
    loop {
        let job = {
            let mut queue = lock_queue(&inner.queue);
            loop {
                if inner.stop.load(Ordering::Acquire) {
                    return;
                }
                if let Some(job) = queue.pop_front() {
                    inner.queued.fetch_sub(1, Ordering::AcqRel);
                    break job;
                }
                let current = inner.current.load(Ordering::Acquire);
                let over_max = current > inner.max.load(Ordering::Acquire);
                let over_min = current > inner.min.load(Ordering::Acquire);
                if over_max || over_min {
                    let wait = if over_max {
                        Duration::from_millis(1)
                    } else {
                        IDLE_BEFORE_SHRINK
                    };
                    let (guard, status) = inner
                        .cv
                        .wait_timeout(queue, wait)
                        .unwrap_or_else(|e| e.into_inner());
                    queue = guard;
                    if status.timed_out() && queue.is_empty() {
                        let current = inner.current.load(Ordering::Acquire);
                        if current > inner.max.load(Ordering::Acquire)
                            || current > inner.min.load(Ordering::Acquire)
                        {
                            return;
                        }
                    }
                    continue;
                }
                queue = inner.cv.wait(queue).unwrap_or_else(|e| e.into_inner());
            }
        };
        inner.busy.fetch_add(1, Ordering::AcqRel);
        // A job that panics is ONE connection lost, never the worker: the
        // panic is caught, said, and the worker takes the next job.
        if std::panic::catch_unwind(AssertUnwindSafe(|| job(&rt))).is_err() {
            tracing::error!(
                "{}xacml-pep: a listener thread-pool job panicked; its \
                 connection is lost and the worker carries on.",
                sts_core::log::tag("STS-XPEP-0121")
            );
        }
        inner.busy.fetch_sub(1, Ordering::AcqRel);
        inner.completed.fetch_add(1, Ordering::Relaxed);
    }
}

/// One listener's pool and the counters the heartbeat copies.
#[derive(Clone)]
pub struct ListenerRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    pool: Pool,
    http: Mutex<HttpCfg>,
    counters: Counters,
}

impl ListenerRuntime {
    /// `name` is the listener id, used as the worker thread's name. The
    /// pool is not started: an unbound listener reports its min and max
    /// and does not hold threads.
    pub fn new(name: &str, purpose: &str, https: bool) -> ListenerRuntime {
        let tuning = Tuning::defaults(purpose, https);
        ListenerRuntime::from_tuning(name, &tuning, https)
    }

    fn from_tuning(
        name: &str,
        tuning: &Tuning,
        https: bool,
    ) -> ListenerRuntime {
        ListenerRuntime {
            inner: Arc::new(RuntimeInner {
                pool: Pool::new(
                    name,
                    tuning.thread_pool_min,
                    tuning.thread_pool_max,
                ),
                http: Mutex::new(HttpCfg::from_tuning(tuning, https)),
                counters: Counters::new(),
            }),
        }
    }

    /// A saved tuning. Pool bounds and HTTP knobs change for the next
    /// connection; workers already running stay until they are idle.
    pub fn apply(&self, tuning: &Tuning, https: bool) {
        *self.http_lock() = HttpCfg::from_tuning(tuning, https);
        self.inner
            .pool
            .set_bounds(tuning.thread_pool_min, tuning.thread_pool_max);
    }

    /// The accept loop calls this once, when the socket is bound.
    pub fn start(&self) {
        self.inner.pool.start();
    }

    pub fn shutdown(&self) {
        self.inner.pool.shutdown();
    }

    pub fn http(&self) -> HttpCfg {
        self.http_lock().clone()
    }

    fn http_lock(&self) -> std::sync::MutexGuard<'_, HttpCfg> {
        self.inner.http.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn note_handshake(&self) {
        self.inner
            .counters
            .handshakes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_handshake_failure(&self) {
        self.inner
            .counters
            .handshake_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_refused(&self) {
        self.inner.counters.refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves `stream` onto this pool. `work` runs on a worker, on that
    /// worker's runtime, and receives the stream rehydrated there.
    pub fn hand_off<F, Fut>(&self, stream: tokio::net::TcpStream, work: F)
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let std_stream = match stream.into_std() {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(
                    "an accepted socket could not leave the runtime: {}",
                    error
                );
                self.note_refused();
                return;
            }
        };
        if let Err(error) = std_stream.set_nonblocking(true) {
            tracing::debug!(
                "an accepted socket could not be non-blocking: {}",
                error
            );
            self.note_refused();
            return;
        }
        let max_connections = self.http().max_connections;
        if max_connections > 0 {
            let prev = self.inner.counters.open.fetch_add(1, Ordering::AcqRel);
            if prev >= max_connections {
                self.inner.counters.open.fetch_sub(1, Ordering::AcqRel);
                self.note_refused();
                return;
            }
        } else {
            self.inner.counters.open.fetch_add(1, Ordering::AcqRel);
        }
        let runtime = self.clone();
        let job: Job = Box::new(move |rt| {
            let _open = OpenGuard(runtime);
            rt.block_on(async move {
                let stream = match tokio::net::TcpStream::from_std(std_stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::debug!(
                            "a pooled socket was not resumed on its worker: {}",
                            error
                        );
                        return;
                    }
                };
                work(stream).await;
            });
        });
        if self.inner.pool.enqueue(job) {
            self.inner.counters.accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.counters.open.fetch_sub(1, Ordering::AcqRel);
            self.note_refused();
        }
    }

    /// What the heartbeat puts on this listener.
    pub fn stats_json(&self) -> Value {
        let c = &self.inner.counters;
        let pool = self.inner.pool.snapshot();
        json!({
            "accepted": c.accepted.load(Ordering::Relaxed),
            "open": c.open.load(Ordering::Relaxed),
            "refused": c.refused.load(Ordering::Relaxed),
            "http1": c.http1.load(Ordering::Relaxed),
            "http2": c.http2.load(Ordering::Relaxed),
            "handshakes": c.handshakes.load(Ordering::Relaxed),
            "handshakeFailures": c.handshake_failures.load(Ordering::Relaxed),
            "pool": {
                "min": pool.min,
                "max": pool.max,
                "current": pool.current,
                "busy": pool.busy,
                "idle": pool.idle,
                "queued": pool.queued,
                "completed": pool.completed
            }
        })
    }
}

/// Decrements `open` however the job ends, including a panic the worker
/// catches.
struct OpenGuard(ListenerRuntime);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.inner.counters.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serves one connection on the worker that called it: HTTP/1, or HTTP/2
/// when the listener offers it and `alpn_h2` says the handshake chose it.
/// Plain HTTP never offers HTTP/2. The idle watchdog closes a connection
/// with no bytes for `keep_alive`; it is not a deadline on the whole
/// request, because a byte in either direction resets it.
pub async fn drive<I, S, B>(
    io: I,
    service: S,
    cfg: HttpCfg,
    alpn_h2: bool,
    counters: ListenerRuntime,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    if alpn_h2 {
        counters
            .inner
            .counters
            .http2
            .fetch_add(1, Ordering::Relaxed);
    } else {
        counters
            .inner
            .counters
            .http1
            .fetch_add(1, Ordering::Relaxed);
    }
    let last = Arc::new(AtomicU64::new(millis()));
    let head = Arc::new(HeadClock::new());
    let io = ActivityIo {
        inner: io,
        last: last.clone(),
        head: head.clone(),
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let service = RequestLimit {
        inner: service,
        max: cfg.max_requests,
        seen: AtomicU64::new(0),
        shutdown: tx,
        head: head.clone(),
    };
    let head_ms = cfg.head_deadline.map(|d| d.as_millis() as u64);
    // A short deadline is checked more often than the idle watchdog's
    // second, so a 1 s headersTimeoutS closes within about 1.25 s.
    let tick = match cfg.head_deadline {
        Some(d) if d < Duration::from_secs(4) => Duration::from_millis(250),
        _ => Duration::from_secs(1),
    };
    let mut builder = Builder::new(TokioExecutor::new());
    // header_read_timeout panics unless a timer is set first.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(cfg.headers));
    if cfg.http2 {
        builder.http2().max_concurrent_streams(cfg.streams);
    } else {
        builder = builder.http1_only();
    }
    let mut conn =
        std::pin::pin!(builder.serve_connection(TokioIo::new(io), service));
    let mut closing = false;
    let idle_ms = cfg.keep_alive.as_millis() as u64;
    loop {
        tokio::select! {
            biased;
            result = conn.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!("connection ended: {}", error);
                }
                break;
            }
            _ = rx.recv(), if !closing => {
                closing = true;
                conn.as_mut().graceful_shutdown();
            }
            _ = tokio::time::sleep(tick) => {
                if let Some(limit) = head_ms {
                    if head.overdue(millis(), limit) {
                        // A slow client (a slow-loris): its head started
                        // and did not finish in headersTimeoutS. Dropped,
                        // not shut down gracefully — a graceful shutdown
                        // waits for the very head that is not coming.
                        tracing::debug!(
                            "xacml-pep: a request head did not finish \
                             within headersTimeoutS; the connection is \
                             closed."
                        );
                        break;
                    }
                }
                let quiet = millis()
                    .saturating_sub(last.load(Ordering::Relaxed));
                if quiet >= idle_ms {
                    if closing {
                        break;
                    }
                    closing = true;
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    }
}

/// Where the connection is in reading a request head, for the
/// `headersTimeoutS` deadline. `since` is the millisecond of the first byte
/// of the head being read, 0 while none is; `armed` is whether the next
/// byte read starts a head. Hot path: no Entering/Leaving lines, every
/// read of every connection passes here.
struct HeadClock {
    armed: AtomicBool,
    since: AtomicU64,
    /// The first bytes were HTTP/2's preface: armed once, never again.
    h2: AtomicBool,
    seen_first: AtomicBool,
}

impl HeadClock {
    fn new() -> HeadClock {
        HeadClock {
            armed: AtomicBool::new(true),
            since: AtomicU64::new(0),
            h2: AtomicBool::new(false),
            seen_first: AtomicBool::new(false),
        }
    }

    /// Bytes arrived.
    fn read(&self, got: &[u8], now: u64) {
        if got.is_empty() {
            return;
        }
        if !self.seen_first.swap(true, Ordering::AcqRel) {
            self.h2
                .store(got.starts_with(b"PRI * HTTP/2.0"), Ordering::Release);
        }
        if self.armed.load(Ordering::Acquire) {
            // Only the first byte of a head sets it. One task polls a
            // connection, so the load and the store do not race.
            if self.since.load(Ordering::Acquire) == 0 {
                self.since.store(now.max(1), Ordering::Release);
            }
        }
    }

    /// hyper handed a request to the service: its head is complete.
    fn head_done(&self) {
        self.armed.store(false, Ordering::Release);
        self.since.store(0, Ordering::Release);
    }

    /// The response is ready: on HTTP/1 the next byte starts the next head.
    fn answered(&self) {
        if !self.h2.load(Ordering::Acquire) {
            self.armed.store(true, Ordering::Release);
        }
    }

    fn overdue(&self, now: u64, limit_ms: u64) -> bool {
        let since = self.since.load(Ordering::Acquire);
        since != 0 && now.saturating_sub(since) >= limit_ms
    }
}

struct RequestLimit<S> {
    inner: S,
    max: u64,
    seen: AtomicU64,
    shutdown: tokio::sync::mpsc::Sender<()>,
    head: Arc<HeadClock>,
}

type Answered<R, E> = Pin<Box<dyn Future<Output = Result<R, E>> + Send>>;

impl<S, B: 'static> Service<Request<Incoming>> for RequestLimit<S>
where
    S: Service<Request<Incoming>, Response = Response<B>>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Answered<S::Response, S::Error>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        self.head.head_done();
        let n = self.seen.fetch_add(1, Ordering::Relaxed);
        // The Nth request still finishes. graceful_shutdown tells hyper
        // not to read another one, which is this service's
        // maxRequestsPerSocket (0 means there is no cap).
        if self.max > 0 && n + 1 >= self.max {
            // A full channel already holds the signal, and a closed one
            // means the connection is ending anyway: neither is a fault.
            if self.shutdown.try_send(()).is_err() {
                tracing::debug!(
                    "xacml-pep: the connection's shutdown was already asked"
                );
            }
        }
        let answering = self.inner.call(req);
        let head = self.head.clone();
        Box::pin(async move {
            let answer = answering.await;
            head.answered();
            answer
        })
    }
}

struct ActivityIo<T> {
    inner: T,
    last: Arc<AtomicU64>,
    head: Arc<HeadClock>,
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if poll.is_ready() {
            let now = millis();
            self.last.store(now, Ordering::Relaxed);
            if let Some(got) = buf.filled().get(before..) {
                self.head.read(got, now);
            }
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(n)) if n > 0) {
            self.last.store(millis(), Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `/proc/self/status` as the heartbeat's `memory`. Kilobyte fields become
/// bytes. A host without that file sends no `memory` member.
pub fn memory_json() -> Value {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return Value::Null;
    };
    memory_from_status(&text)
}

pub fn memory_from_status(text: &str) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(kb) = status_number(text, "VmRSS:") {
        out.insert("rssBytes".into(), json!(kb.saturating_mul(1024)));
    }
    if let Some(kb) = status_number(text, "VmSize:") {
        out.insert("virtualBytes".into(), json!(kb.saturating_mul(1024)));
    }
    if let Some(kb) = status_number(text, "VmData:") {
        out.insert("dataBytes".into(), json!(kb.saturating_mul(1024)));
    }
    if let Some(n) = status_number(text, "Threads:") {
        out.insert("threads".into(), json!(n));
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Object(out)
    }
}

fn status_number(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key) {
            return parts.next()?.parse().ok();
        }
    }
    None
}

struct PathTable {
    rows: Mutex<Vec<PathRow>>,
}

struct PathRow {
    method: String,
    path: String,
    count: u64,
    refused: u64,
}

fn path_table() -> &'static PathTable {
    static TABLE: OnceLock<PathTable> = OnceLock::new();
    TABLE.get_or_init(|| PathTable {
        rows: Mutex::new(Vec::new()),
    })
}

fn record_path(method: &str, path: &str, refused: bool) {
    let mut rows = path_table().rows.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(row) = rows
        .iter_mut()
        .find(|r| r.method == method && r.path == path)
    {
        row.count = row.count.saturating_add(1);
        if refused {
            row.refused = row.refused.saturating_add(1);
        }
        return;
    }
    if rows.len() >= PATH_CAP {
        return;
    }
    rows.push(PathRow {
        method: method.to_string(),
        path: path.to_string(),
        count: 1,
        refused: if refused { 1 } else { 0 },
    });
}

/// The heartbeat's `paths`, or null when nothing has been counted. The
/// query string is never stored.
pub fn paths_json() -> Value {
    let rows = path_table().rows.lock().unwrap_or_else(|e| e.into_inner());
    if rows.is_empty() {
        return Value::Null;
    }
    Value::Array(
        rows.iter()
            .map(|row| {
                json!({
                    "method": row.method,
                    "path": row.path,
                    "count": row.count,
                    "refused": row.refused
                })
            })
            .collect(),
    )
}

fn kept_method(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > 16 {
        return None;
    }
    if raw.bytes().all(|b| b.is_ascii_uppercase() || b == b'*') {
        Some(raw)
    } else {
        None
    }
}

fn kept_path(raw: &str) -> Option<String> {
    let path = raw.split('?').next().unwrap_or("");
    if path.is_empty() {
        return None;
    }
    let path = if path.len() > 200 { &path[..200] } else { path };
    if path.bytes().any(|b| b <= 0x1f || b == 0x7f || b == b' ') {
        return None;
    }
    Some(path.to_string())
}

/// Counts one request after it has been answered. 401 and 403 are
/// refusals — every PEP failure is a 403 since #2208, so a 503 is no longer
/// one of the PEP's and is not counted as one (an application's own 503,
/// passed through, is not the PEP turning anyone away); a 404 is a count
/// without one, because a missing page is not the PEP turning the caller
/// away.
pub async fn observe(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = kept_method(request.method().as_str()).map(str::to_string);
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    if let (Some(method), Some(path)) = (method, kept_path(&path)) {
        let refused = matches!(response.status().as_u16(), 401 | 403);
        record_path(&method, &path, refused);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_bytes_and_a_thread_count() {
        let text = "\
Name:\txacml-pep\n\
VmSize:\t   2048 kB\n\
VmRSS:\t   512 kB\n\
VmData:\t   256 kB\n\
Threads:\t7\n";
        let memory = memory_from_status(text);
        assert_eq!(memory["rssBytes"], 512 * 1024);
        assert_eq!(memory["virtualBytes"], 2048 * 1024);
        assert_eq!(memory["dataBytes"], 256 * 1024);
        assert_eq!(memory["threads"], 7);
        assert!(memory_from_status("Name:\tnone\n").is_null());
    }

    #[test]
    fn a_path_keeps_no_query_and_no_space() {
        assert_eq!(
            kept_path("/protected?token=1").as_deref(),
            Some("/protected")
        );
        assert!(kept_path("/a b").is_none());
        assert!(kept_method("GET").is_some());
        assert!(kept_method("get").is_none());
    }

    #[test]
    fn the_queue_refuses_past_max() {
        let rt = ListenerRuntime::new("q", "api", false);
        rt.inner.pool.set_bounds(1, 1);
        let blocked = Arc::new(AtomicBool::new(true));
        let flag = blocked.clone();
        let job: Job =
            Box::new(move |_rt| while flag.load(Ordering::Acquire) {});
        assert!(rt.inner.pool.enqueue(job));
        // The one worker takes the blocking job off the queue whenever it
        // is scheduled, which made the next enqueue race it: refused when
        // the job was still waiting, accepted when it had been taken (PR
        // #1871's rust job). Wait until it is RUNNING, so what the queue
        // holds is known: nothing, then the one job max allows.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(10);
        while lock_queue(&rt.inner.pool.inner.queue).len() > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never took the blocking job"
            );
            std::thread::yield_now();
        }
        let job: Job = Box::new(|_rt| {});
        assert!(rt.inner.pool.enqueue(job), "the queue has room for one");
        let job: Job = Box::new(|_rt| {});
        assert!(
            !rt.inner.pool.enqueue(job),
            "the queue holds max, and max is 1"
        );
        blocked.store(false, Ordering::Release);
        rt.shutdown();
    }
}
