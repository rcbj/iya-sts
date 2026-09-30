// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: cell_consoles.js
//
// ===========================================================================
// EVERY CELL'S CLUSTER, AND EACH CELL'S OWN CONSOLE (#361, 2026-09-30).
//
// On testidpna an operator signed in at one region saw only that region's
// nodes, and had no way into the other region's console: the shared public
// name goes to whichever cell is nearest. This file holds the three pieces
// that answer it:
//
//   A. `cluster-summary` — what a cell tells another about its cluster:
//      its members folded by name, its leases by holder NAME, each node's
//      pools — and never an address (a member row's host, port or pid);
//   B. the Cluster page's section on the other cells, drawn from those
//      answers, a cell that did not answer drawn as unreachable, never
//      dropped;
//   C. the console signing in AT a cell's own console address — callback
//      and authorization request on that host, the callback registered on
//      the console's client as configuration — while every other Host,
//      and every other surface, keeps the shared public name. In a CHILD
//      process, because the cell settings are read from the environment
//      when the service starts and a test must not change this process's.
// ===========================================================================
'use strict';

const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'cell_consoles',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'CELL_CONSOLES_CHILD';

// ---------------------------------------------------------------------------
// C, in the child: the console's sign-in at each kind of Host.
// ---------------------------------------------------------------------------
function fakeReq(host) {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return {
    protocol: 'https',
    headers: { host: host },
    originalUrl: '/admin',
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return String(name).toLowerCase() === 'host' ? host : undefined;
    }
  };
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 0, location: '', ended: false };
  res.status = function (code) {
    log.debug("Entering status().");
    res.statusCode = code;
    log.debug("Leaving status().");
    return res;
  };
  res.set = function (name, value) {
    log.debug("Entering set().");
    if (String(name).toLowerCase() === 'location') {
      res.location = value;
    }
    log.debug("Leaving set().");
    return res;
  };
  res.end = function () {
    log.debug("Entering end().");
    res.ended = true;
    log.debug("Leaving end().");
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function child() {
  log.debug("Entering child().");
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  try {
    const config = require('../common/config');
    const applications = require('../common/applications');
    require('../ldap/ldap_server');
    const oidcRp = require('../common/oidc_rp');
    config.setOverride('global.mode', 'product');
    const uris = function () {
      const cfg = applications.clientConfigOf('sts-admin-console') || {};
      return [].concat(cfg.redirect_uris || []);
    };
    const signIn = function (host, surface) {
      const res = fakeRes();
      const started = oidcRp.beginSignIn(fakeReq(host), res,
                                         surface || 'admin',
                                         { returnTo: '/' + (surface ||
                                                            'admin') });
      return { started: started, res: res };
    };
    const own = signIn('cella.idp.example');
    note(own.started && own.started.ok !== false &&
         own.res.location.indexOf('https://cella.idp.example/oauth2/' +
                                  'authorize?') === 0 &&
         own.res.location.indexOf(encodeURIComponent(
           'https://cella.idp.example/admin/callback')) > 0,
         'C1. the console reached at this cell\'s own address signs in ' +
         'there: its authorization request and its callback are on that host',
         own.res.location.slice(0, 200) + ' ' +
         JSON.stringify(own.started).slice(0, 200));
    note(uris().indexOf('https://cella.idp.example/admin/callback') >= 0,
         'C2. and the callback is REGISTERED on the console\'s client — a ' +
         'configured address, believed in product mode', uris().join(' '));
    const peer = signIn('cellb.idp.example');
    note(peer.res.location.indexOf('https://cellb.idp.example/oauth2/' +
                                   'authorize?') === 0 &&
         uris().indexOf('https://cellb.idp.example/admin/callback') >= 0,
         'C3. so is another cell\'s console address, which a relayed ' +
         'request arrives at', peer.res.location.slice(0, 120));
    const shared = signIn('idp.example');
    note(shared.res.location.indexOf('https://idp.example/oauth2/' +
                                     'authorize?') === 0,
         'C4. the shared public name signs in on the shared name, as before',
         shared.res.location.slice(0, 120));
    const before = uris().length;
    const evil = signIn('evil.example');
    note((evil.res.location === '' ||
          evil.res.location.indexOf('https://idp.example/') === 0) &&
         uris().length === before &&
         uris().join(' ').indexOf('evil.example') < 0,
         'C5. a Host that is no configured console address gets the public ' +
         'name, and plants nothing', evil.res.location.slice(0, 120));
    const portal = signIn('cella.idp.example', 'portal');
    note(portal.res.location.indexOf('https://idp.example/oauth2/' +
                                     'authorize?') === 0,
         'C6. only the CONSOLE signs in at a cell\'s address; the portal ' +
         'keeps the shared name', portal.res.location.slice(0, 120));
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || String(e));
  }
  process.stdout.write('\n@@FINDINGS@@' + JSON.stringify(findings) + '\n');
  log.debug("Leaving child().");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// A. What a cell answers, over stubbed cluster and pool readers.
// ---------------------------------------------------------------------------
async function summary(t) {
  log.debug("Entering summary().");
  const cluster = require('../cluster/cluster');
  const pools = require('../admin-ui/worker_pools_admin');
  const cellsAdmin = require('../admin-ui/cells_admin');
  const now = 5000000;
  const stateWas = cluster.state;
  const poolsWas = pools.workerPoolsView;
  const info = { host: '10.61.0.165', port: 8081, pid: 1234,
                 uptimeMs: 60000, workers: 3, lastStallMs: 2500 };
  cluster.state = function () {
    const nodes = [
      { nodeId: 'id-a', name: 'node-a', mode: 'active-active',
        version: '0.1.1', startedAt: now - 60000, heartbeatAt: now - 1000,
        expiresAt: now + 29000, leftAt: 0, info: info, agrees: true },
      { nodeId: 'id-a-old', name: 'node-a', mode: 'active-active',
        version: '0.1.1', startedAt: now - 900000, heartbeatAt: now - 400000,
        expiresAt: now - 370000, leftAt: 0, info: info, agrees: true },
      { nodeId: 'id-z', name: 'node-z', mode: 'active-active',
        version: '0.1.0', startedAt: now - 900000, heartbeatAt: now - 800000,
        expiresAt: now - 700000, leftAt: now - 790000, info: info,
        agrees: null }];
    return Promise.resolve({
      available: true, now: now, nodes: nodes,
      leases: [{ name: 'ops.scheduler', holder: 'id-a', token: 7,
                 expiresAt: now + 29000 },
               { name: 'ops.gone', holder: 'id-z', token: 2,
                 expiresAt: now - 1 }],
      members: cluster.foldMembers(nodes, now),
      self: { mode: 'active-active' }
    });
  };
  pools.workerPoolsView = function () {
    return Promise.resolve({ nodes: [
      { name: 'node-a', state: 'live', view: { pools: [
        { id: 'protocol', title: 'Request workers', state: 'on',
          currentWorkers: 3, busyWorkers: 1, freeWorkers: 2,
          restarts: { forked: 3, crashed: 1, failedStarts: 0 },
          pid: 99, host: '10.61.0.165' }] } }] });
  };
  let sum = null;
  try {
    sum = await cellsAdmin.clusterSummaryHere();
  } finally {
    cluster.state = stateWas;
    pools.workerPoolsView = poolsWas;
  }
  const text = JSON.stringify(sum);
  t.check(text.indexOf('10.61.0.165') < 0 && text.indexOf('8081') < 0 &&
          text.indexOf('"pid"') < 0 && text.indexOf('1234') < 0,
          'A1. a cell\'s summary carries no host, port or pid — of a member ' +
          'or of a pool', text.slice(0, 300));
  const live = (sum.members && sum.members.live) || [];
  t.check(live.length === 1 && live[0].name === 'node-a' &&
          live[0].workers === 3 && live[0].lastStallMs === 2500 &&
          live[0].leases.join() === 'ops.scheduler',
          'A2. its running members, by name, with what each said about ' +
          'itself and the leases it holds (a lapsed one left out)',
          JSON.stringify(live));
  t.check(sum.members.restarts['node-a'] &&
          sum.members.restarts['node-a'].count === 1 &&
          sum.members.gone.length === 1 && sum.members.gone[0].name ===
          'node-z' && sum.members.gone[0].how === 'left',
          'A3. folded by name: a restart is history, a name with no running ' +
          'member is gone', JSON.stringify(sum.members));
  t.check(sum.pools.length === 1 && sum.pools[0].pools[0].busyWorkers === 1 &&
          sum.pools[0].pools[0].crashed === 1,
          'A4. and each node\'s pools, as counts', JSON.stringify(sum.pools));
  log.debug("Leaving summary().");
  return sum;
}

// ---------------------------------------------------------------------------
// B. The Cluster page's section on the other cells.
// ---------------------------------------------------------------------------
function page(t, sum) {
  log.debug("Entering page().");
  const adminModule = require('../admin-ui/admin');
  const drawer = Object.create(adminModule.AdminConsole.prototype);
  drawer.deps = adminModule.AdminConsole.defaultDeps();
  drawer.peerClustersNow = null;
  const none = drawer.otherCellsBlock();
  t.check(none.html === '' && none.json === null,
          'B1. single-cell mode draws no section');
  drawer.peerClustersNow = { at: 1, rows: [
    { cell: 'cac1', jurisdiction: 'ca', reachable: true, answeredMs: 211,
      summary: sum },
    { cell: 'euw1', jurisdiction: 'eu', reachable: false,
      error: 'connect ETIMEDOUT' }] };
  const drawn = drawer.otherCellsBlock();
  t.check(/Cell <code>cac1<\/code>/.test(drawn.html) &&
          drawn.html.indexOf('node-a') > 0 &&
          drawn.html.indexOf('restarted 1 time(s)') > 0 &&
          drawn.html.indexOf('Request workers') > 0,
          'B2. an answering cell is drawn with its members, their restarts ' +
          'and its pools', drawn.html.slice(0, 200));
  t.check(/Cell <code>euw1<\/code>/.test(drawn.html) &&
          drawn.html.indexOf('did not answer') > 0 &&
          drawn.html.indexOf('ETIMEDOUT') > 0,
          'B3. a cell that did not answer is drawn as unreachable, with why — ' +
          'never dropped');
  t.check(drawn.json && drawn.json.cells.length === 2 &&
          drawn.json.askedAt === 1,
          'B4. and the API carries the same answers (rule 7)');
  log.debug("Leaving page().");
}

// ---------------------------------------------------------------------------
// C, from the parent: run the child and read its findings.
// ---------------------------------------------------------------------------
function signInAtACell(t) {
  log.debug("Entering signInAtACell().");
  const env = Object.assign({}, process.env, {
    [CHILD]: '1',
    STS_CELL_ID: 'cella',
    STS_CELL_JURISDICTION: 'us',
    STS_CELL_PEERS: JSON.stringify([
      { id: 'cellb', jurisdiction: 'ca', url: 'https://b.internal:8446',
        consoleUrl: 'https://cellb.idp.example' }]),
    STS_CELL_CONSOLE_URL: 'https://cella.idp.example',
    STS_PUBLIC_BASE_URL: 'https://idp.example'
  });
  delete env.CONFIG_FILE;
  let out = '';
  try {
    out = childProcess.execFileSync(process.execPath, [__filename],
      { env: env, cwd: path.join(__dirname, '..'), encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
  } catch (e) {
    log.debug("Caught in signInAtACell(): " + ((e && e.message) || e));
    out = String((e && e.stdout) || '');
  }
  const at = out.lastIndexOf('@@FINDINGS@@');
  let findings = [];
  if (at >= 0) {
    try {
      findings = JSON.parse(out.slice(at + 12).split('\n')[0]);
    } catch (e) {
      log.debug("Caught in signInAtACell(): " + ((e && e.message) || e));
    }
  }
  t.check(findings.length >= 6, 'the child reported every finding',
          String(findings.length));
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving signInAtACell().");
}

async function run(t) {
  log.debug("Entering run().");
  const sum = await summary(t);
  page(t, sum);
  signInAtACell(t);
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD]) {
  child();
}

module.exports = {
  name: 'cell_consoles',
  describe: 'Every cell\'s cluster and each cell\'s own console (#361): ' +
            'the cluster-summary a cell answers (no address), the Cluster ' +
            'page\'s other cells, and the console signing in at a cell\'s ' +
            'own address',
  run: run
};
