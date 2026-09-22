'use strict';
//
// File: tests/tools/scheduler-takeover.js
//
// ===========================================================================
// THE SCHEDULER SURVIVES A CRASHED LEADER (#49, D10(a), 2026-09-22).
//
// The last step of the `cluster` mode, run by `run-tests.sh` from the host
// against the stack the suite has just finished with — because stopping a
// node is something only the host can do, and it removes a node, so nothing
// may run after it. `tests/CLAUDE.md` recorded that the `cluster` mode never
// stopped a node; this is the step that does.
//
//   node scheduler-takeover.js before <base>   prints the leader's node name
//                                              on its last line
//   node scheduler-takeover.js after <base> <the node that was stopped>
//
// Between the two the launcher `docker kill`s the named node's container: a
// CRASH, not a clean stop, so its lease is not released and the survivor has
// to wait out `cluster.nodeTtlMs` for it, which is the case the in-process
// test (`tests/scheduler_cluster.js` C) simulates and this proves.
//
// `after` asserts, through the balancer — so every request that lands on the
// dead node is a connection error, retried — that:
//
//   1. the OTHER node leads, and ticks, within the node lifetime and three
//      ticks;
//   2. a run queued now is run by it, once;
//   3. every slot of the session-expiry job is still one succeeded run — the
//      crash cost the job nothing and doubled nothing;
//   4. a run the dead node had left `running` (the crash can land inside
//      one, rarely) was taken over — `abandoned` beside it — once its claim
//      lapsed, which it waits for only when there is one.
//
// The fence itself — the dead node's late result refused — needs a node that
// wakes, and a crashed container does not; `tests/scheduler_cluster.js` C
// holds that half in process.
// ===========================================================================

const https = require('https');
const http = require('http');

const log = require('bunyan').createLogger({ name: 'scheduler-takeover',
  level: process.env.LOG_LEVEL || 'info' });

function request(url, options, body) {
  log.debug('Entering request().');
  log.debug('Leaving request().');
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === 'http:' ? http : https;
    const opts = Object.assign({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'GET',
      // A new connection per request, so the balancer really picks a node
      // each time — the same reason tools/fresh-connections.js exists.
      agent: false,
      // The run's own anchor is not this tool's to hold; nothing it reads is
      // a secret, and the token it sends is already the run's.
      rejectUnauthorized: false
    }, options || {});
    opts.headers = Object.assign({
      authorization: 'Bearer ' + (process.env.STS_ADMIN_API_TOKEN || '')
    }, (options && options.headers) || {});
    const r = mod.request(opts, function (res) {
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug('Caught in request(): ' + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    r.setTimeout(10000, function () {
      r.destroy(new Error('timed out'));
    });
    r.on('error', reject);
    if (body) {
      r.write(body);
    }
    r.end();
  });
}

// A request that lands on the dead node fails; the next one may not.
async function patiently(url, options, body) {
  log.debug('Entering patiently().');
  let last = null;
  for (let i = 0; i < 12; i++) {
    try {
      const r = await request(url, options, body);
      if (r.status < 500) {
        log.debug('Leaving patiently().');
        return r;
      }
      last = new Error('answered ' + r.status + ' ' + r.text.slice(0, 200));
    } catch (e) {
      log.debug('Caught in patiently(): ' + ((e && e.message) || e));
      last = e;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  log.debug('Leaving patiently(). Gave up.');
  throw last;
}

async function report(base) {
  log.debug('Entering report().');
  const r = await patiently(base + '/admin-api/scheduler?per=500');
  if (r.status !== 200 || !r.json) {
    log.debug('Leaving report(). Refused.');
    throw new Error('GET /admin-api/scheduler answered ' + r.status + ' ' +
                    r.text.slice(0, 300));
  }
  log.debug('Leaving report().');
  return r.json;
}

// Waits on a CONDITION, polled, for at most `limitMs`.
async function until(what, fn, limitMs) {
  log.debug('Entering until(). ' + what);
  const deadline = Date.now() + limitMs;
  for (;;) {
    const got = await fn();
    if (got) {
      log.debug('Leaving until(). Met.');
      return got;
    }
    if (Date.now() > deadline) {
      log.debug('Leaving until(). Timed out.');
      throw new Error('timed out after ' + limitMs + 'ms waiting for ' + what);
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 1000);
    });
  }
}

function fail(message) {
  log.debug('Entering fail().');
  log.error('scheduler-takeover: FAILED: ' + message);
  log.debug('Leaving fail().');
  process.exit(1);
}

async function before(base) {
  log.debug('Entering before().');
  const json = await until('a live scheduler leader', async function () {
    const r = await report(base);
    return r.leader && r.leader.known && r.leader.live && r.leader.nodeName
      ? r : null;
  }, 120000);
  log.info('scheduler-takeover: the scheduler is led by ' +
           json.leader.nodeName + ' (node ' + json.leader.node + ', lease ' +
           'token ' + json.leader.token + ').');
  // The LAST line is what the launcher reads.
  process.stdout.write(String(json.leader.nodeName) + '\n');
  log.debug('Leaving before().');
}

async function after(base, stopped) {
  log.debug('Entering after(). stopped=' + stopped);
  const settings = await patiently(base + '/admin-api/config');
  let ttlMs = 30000;
  let tickS = 15;
  ((settings.json && settings.json.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (row) {
      if (row.key === 'cluster.nodeTtlMs') {
        ttlMs = Number(row.value) || ttlMs;
      }
      if (row.key === 'scheduler.tickS') {
        tickS = Number(row.value) || tickS;
      }
    });
  });
  const limit = ttlMs + 3 * tickS * 1000 + 30000;
  const led = await until('another node to lead', async function () {
    const r = await report(base);
    return r.leader && r.leader.known && r.leader.live &&
           r.leader.nodeName && r.leader.nodeName !== stopped ? r : null;
  }, limit);
  log.info('  ✓ 1. ' + led.leader.nodeName + ' leads within ' + limit +
           'ms of ' + stopped + ' being killed (lease token ' +
           led.leader.token + ').');
  const queued = await patiently(base + '/admin-api/scheduler/run',
    { method: 'POST', headers: { 'content-type': 'application/json' } },
    JSON.stringify({ job: 'scheduler.history' }));
  if (queued.status !== 202 || !queued.json || !queued.json.runId) {
    fail('queueing a run of scheduler.history answered ' + queued.status +
         ' ' + queued.text.slice(0, 300));
  }
  const ran = await until('the queued run to finish', async function () {
    const r = await patiently(base + '/admin-api/scheduler?run=' +
                              encodeURIComponent(queued.json.runId));
    const d = r.json && r.json.detail;
    return d && (d.state === 'succeeded' || d.state === 'failed') ? d : null;
  }, 3 * tickS * 1000 + 30000);
  if (ran.state !== 'succeeded' || ran.nodeName === stopped) {
    fail('the run queued after the crash ended ' + ran.state + ' on ' +
         ran.nodeName + ': ' + JSON.stringify(ran));
  }
  log.info('  ✓ 2. a run queued now is run once, on ' + ran.nodeName + '.');
  const json = await report(base);
  const bySlot = {};
  (json.runs || []).forEach(function (r) {
    if (r.jobId === 'authn.session-expiry' && r.state === 'succeeded' &&
        r.trigger === 'schedule') {
      bySlot[r.dueAt] = (bySlot[r.dueAt] || 0) + 1;
    }
  });
  const doubles = Object.keys(bySlot).filter(function (k) {
    return bySlot[k] > 1;
  });
  if (doubles.length) {
    fail('slots of authn.session-expiry ran twice: ' + doubles.join(', '));
  }
  log.info('  ✓ 3. every one of ' + Object.keys(bySlot).length + ' slots of ' +
           'authn.session-expiry is one succeeded run.');
  const leftRunning = (json.runs || []).filter(function (r) {
    return r.state === 'running' && r.nodeName === stopped;
  });
  if (!leftRunning.length) {
    log.info('  ✓ 4. the crash left no run in progress on ' + stopped +
             ' (it rarely does: the jobs run for milliseconds).');
    log.debug('Leaving after().');
    return;
  }
  const one = leftRunning[0];
  const job = (json.jobs || []).filter(function (j) {
    return j.id === one.jobId;
  })[0];
  const timeoutMs = Number(job && job.timeoutMs) || 600000;
  await until('the dead node\'s run to be taken over', async function () {
    const r = await report(base);
    return (r.runs || []).some(function (x) {
      return x.abandonedOf === one.runId;
    });
  }, timeoutMs + 3 * tickS * 1000 + 30000);
  log.info('  ✓ 4. the run ' + stopped + ' left running was taken over and ' +
           'its attempt recorded abandoned.');
  log.debug('Leaving after().');
}

async function main() {
  log.debug('Entering main().');
  const phase = process.argv[2];
  const base = String(process.argv[3] || '').replace(/\/+$/, '');
  if (!base || (phase !== 'before' && phase !== 'after')) {
    fail('usage: scheduler-takeover.js before|after <base> [stopped node]');
  }
  if (phase === 'before') {
    await before(base);
  } else {
    await after(base, String(process.argv[4] || ''));
  }
  log.debug('Leaving main().');
}

main().catch(function (e) {
  fail((e && e.message) || String(e));
});
