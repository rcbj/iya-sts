'use strict';
//
// File: cluster_signout_signals.js
//
// ===========================================================================
// ISSUE #46 SECTIONS 4 AND 6: A SIGN-OUT REACHES ANOTHER NODE'S DIRECTORY
// CONNECTION, AND SHARED SIGNALS SAY EACH THING ONCE (2026-09-14).
//
//   1. LDAP. An instruction another node wrote closes this node's socket bound
//      as that identity; this node's own instruction, a stale one, and one in
//      a cluster that is not active-active close nothing (the controls).
//   2. LDAP. This node publishes what it holds; another node's published row
//      is listed by `boundConnections()`, the sign-out inventory and a global
//      sign-out — reported PENDING, never closed — and a row of a node that is
//      not a member is not listed. A global sign-out instructs the cluster even
//      for an identity nothing listed.
//   3. A session's end is reported once: two processes ending one session
//      write one `session.end` row and one CAEP notice when they share a claim
//      store, and two without one (the control, which is the old behaviour).
//   4. A stream's dead declaration is reported once; one process probes.
//   5. A GNAP key proof on the SSF endpoints is spent across the cluster: the
//      same proof at "another node" is refused, and the synchronous path the
//      gate used before spends nothing (the control).
//   6. A poll on a shared store writes no first-delivery row, so it cannot
//      resurrect a SET an acknowledgement on another node just deleted; on a
//      store that is not shared it writes it as before (the control).
//
// **"ANOTHER NODE" IS THIS PROCESS AGAIN**, in the two ways
// `tests/cluster_single_use_protocols.js` argues: a replicated row arriving is
// the accessor call `persistence_minted.js`'s applier makes, and a node that
// has not caught up is this process with its row put back. The claim store is
// a stub with postgres's semantics, installed as `persistence.clusterStore`.
//
// In a CHILD PROCESS: it installs a persist observer and a session observer,
// neither of which can be put back for a later file in `run.js`'s one process.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_signout_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.CSS_ROOT;
  const OUT = process.env.CSS_OUT;
  const EventEmitter = require('events');
  const Module = require('module');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function tick() {
    return new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  function settle() {
    return new Promise(function (resolve) {
      setTimeout(resolve, 20);
    });
  }
  function sharedStore() {
    const rows = new Map();
    return {
      rows: rows,
      claimOnce: function (scope, realm, key, opts) {
        const k = scope + ' ' + realm + ' ' + key;
        const now = Date.now();
        const row = rows.get(k);
        if (row && row.expiresAt > now) {
          return Promise.resolve({ claimed: false, existing: {
            origin: 'another node' } });
        }
        rows.set(k, { reservation: opts.reservation, expiresAt: now +
                      opts.ttlMs });
        return Promise.resolve({ claimed: true });
      },
      releaseClaim: function (scope, realm, key, reservation) {
        const k = scope + ' ' + realm + ' ' + key;
        const row = rows.get(k);
        if (row && row.reservation === reservation) {
          rows.delete(k);
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      },
      claimHeld: function () {
        return Promise.resolve(false);
      },
      purgeClaims: function () {
        return Promise.resolve(0);
      }
    };
  }

  (async function () {
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const journal = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      journal.push({ handle: handle, realm: realmId, key: key });
    });
    config.setOverride('ssf.enabled', 'true');

    // THE GNAP RESOURCE SERVER, stubbed BEFORE anything can load the real one:
    // a token needs a whole grant, and what is under test is what the SSF
    // gate does with a presentation, not the presentation itself.
    let presentations = 0;
    const rsPath = require.resolve(ROOT + '/gnap/gnap_rs');
    const rsModule = new Module(rsPath);
    rsModule.filename = rsPath;
    rsModule.loaded = true;
    rsModule.exports = {
      presentation: function () {
        presentations += 1;
        return { ok: true, value: 'tok', method: 'httpsig',
                 presentedKey: null, replayKeys: ['proof-replay-key-1'],
                 record: { instanceId: 'gnap-instance-1', format: 'jwt',
                           rsIdentifiers: [],
                           access: ['ssf:read', 'ssf:write'] } };
      }
    };
    require.cache[rsPath] = rsModule;

    const persistence = require(ROOT + '/persistence/persistence');
    let store = null;
    persistence.clusterStore = function () {
      return store;
    };
    const claims = require(ROOT + '/cluster/cluster_claims');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const clusterConnections = require(ROOT + '/ldap/ldap_cluster_connections');
    const logout = require(ROOT + '/logout/logout');
    const authn = require(ROOT + '/authn/authn');
    const audit = require(ROOT + '/common/audit');
    const cluster = require(ROOT + '/cluster/cluster');
    const ssfCluster = require(ROOT + '/ssf/ssf_cluster');
    const ssfAuth = require(ROOT + '/ssf/ssf_auth');
    const streams = require(ROOT + '/ssf/ssf_streams');

    // ======================================================================
    // 1 and 2. LDAP.
    // ======================================================================
    const NODE_A = 'aaaaaaaa-0000-4000-8000-000000000001';
    const NODE_B = 'bbbbbbbb-0000-4000-8000-000000000002';
    let on = true;
    let members = [NODE_A, NODE_B];
    const stubCluster = {
      isActiveActive: function () { return on; },
      enabled: function () { return on; },
      nodeId: function () { return NODE_A; },
      status: function () { return { name: 'node-a' }; },
      snapshot: function () {
        return { ageMs: 0, state: { available: true, now: Date.now(),
          nodes: members.map(function (id) {
            return { nodeId: id, expiresAt: Date.now() + 60000, leftAt: 0 };
          }) } };
      },
      state: function () {
        return Promise.resolve(stubCluster.snapshot().state);
      }
    };
    clusterConnections.reset({ cluster: stubCluster });
    const signOutsHandle = realms.handleFor(clusterConnections.SIGNOUTS_HANDLE);
    const tableHandle = realms.handleFor(clusterConnections.CONNECTIONS_HANDLE);
    note(signOutsHandle && signOutsHandle.scope === 'shared' && tableHandle,
         '1. the instruction and the table are declared, persisted stores');

    let port = 41000;
    function fakeSocket(dn) {
      const s = new EventEmitter();
      port += 1;
      s.ldap = { bindDN: dn, id: '127.0.0.1:' + port };
      s.remoteAddress = '127.0.0.1';
      s.remotePort = port;
      s.encrypted = false;
      s.stsBoundAt = Date.now();
      s.destroyed = false;
      s.destroy = function () {
        s.destroyed = true;
        s.emit('close');
      };
      return s;
    }
    const aliceDn = 'uid=css-alice,ou=users,dc=example,dc=com';
    const s1 = fakeSocket(aliceDn);
    ldapServer.holdSocket(s1);
    const aliceRow = ldapServer.localBoundConnections().filter(function (c) {
      return c.dn === aliceDn;
    })[0];
    const aliceKey = aliceRow ? aliceRow.key : '';
    note(!!aliceKey, '1. a socket this node holds is listed with a key',
         JSON.stringify(aliceRow ? { id: aliceRow.id, key: aliceKey } : null));

    function arrive(key, row) {
      signOutsHandle.restore('', key, row);
    }

    // 1a. CONTROLS FIRST: each of these must close nothing.
    on = false;
    arrive(aliceKey, { key: aliceKey, at: Date.now(), node: NODE_B });
    await tick();
    note(!s1.destroyed, '1a. CONTROL: outside active-active an instruction ' +
         'closes nothing (a single node behaves as it did)');
    on = true;
    arrive(aliceKey, { key: aliceKey, at: Date.now(), node: NODE_A });
    await tick();
    note(!s1.destroyed, '1b. CONTROL: this node\'s OWN instruction closes ' +
         'nothing here — the process that answered already closed it');
    arrive(aliceKey, { key: aliceKey,
      at: Date.now() - clusterConnections.INSTRUCTION_TTL_MS - 1000,
      node: NODE_B });
    await tick();
    note(!s1.destroyed, '1c. CONTROL: an instruction older than its lifetime ' +
         '(a hole applied late) closes nothing');

    // 1d. THE CASE.
    arrive(aliceKey, { key: aliceKey, at: Date.now(), node: NODE_B });
    await tick();
    note(s1.destroyed, '1d. ANOTHER NODE\'S SIGN-OUT CLOSES THIS NODE\'S ' +
         'SOCKET BOUND AS THAT IDENTITY');
    note(!ldapServer.localBoundConnections().some(function (c) {
      return c.dn === aliceDn;
    }), '1e. and it is gone from this node\'s list');
    note(clusterConnections.report().closedByInstruction === 1,
         '1f. counted once', JSON.stringify(clusterConnections.report()));

    // 2a. PUBLISH.
    const s2 = fakeSocket('uid=css-dave,ou=users,dc=example,dc=com');
    ldapServer.holdSocket(s2);
    clusterConnections.publishNow();
    const published = tableHandle.read('', NODE_A);
    note(published.present && published.value.rows.some(function (r) {
      return r.dn === 'uid=css-dave,ou=users,dc=example,dc=com';
    }) && !published.value.rows.some(function (r) {
      return 'socket' in r;
    }), '2a. this node publishes what it holds, without the sockets',
         JSON.stringify(published));

    // 2b. ANOTHER NODE'S ROW.
    const bobDn = 'uid=css-bob,ou=users,dc=example,dc=com';
    tableHandle.restore('', NODE_B, { node: NODE_B, name: 'node-b',
      at: Date.now(), rows: [{ id: '10.0.0.9:50000', dn: bobDn,
                               key: 'css-bob', secure: false, port: 389,
                               boundAt: Date.now() }] });
    const listed = ldapServer.boundConnections().filter(function (c) {
      return c.key === 'css-bob';
    });
    note(listed.length === 1 && listed[0].remote &&
         listed[0].node === NODE_B && !listed[0].socket &&
         listed[0].id.indexOf(NODE_B.slice(0, 8) + '/') === 0,
         '2b. A CONNECTION ANOTHER NODE HOLDS IS LISTED, marked remote and ' +
         'named by its node', JSON.stringify(listed));
    note(!ldapServer.connectionSnapshot().some(function (c) {
      return c.key === 'css-bob';
    }), '2c. and is NOT in what this node publishes to its own workers');
    const inventory = logout.inventoryFor('css-bob');
    const ldapFamily = inventory.families.filter(function (f) {
      return f.id === 'ldap';
    })[0];
    note(ldapFamily && ldapFamily.rows.length === 1 &&
         /on node node-b/.test(ldapFamily.rows[0].detail),
         '2d. the sign-out inventory lists it', JSON.stringify(ldapFamily));

    members = [NODE_A];
    note(!ldapServer.boundConnections().some(function (c) {
      return c.key === 'css-bob';
    }), '2e. CONTROL: a row of a node that is not a member is not listed');
    const swept = await clusterConnections.maintain();
    note(swept.swept === 1 && !tableHandle.read('', NODE_B).present,
         '2f. and maintenance deletes it', JSON.stringify(swept));
    members = [NODE_A, NODE_B];
    tableHandle.restore('', NODE_B, { node: NODE_B, name: 'node-b',
      at: Date.now(), rows: [{ id: '10.0.0.9:50000', dn: bobDn,
                               key: 'css-bob', secure: false, port: 389,
                               boundAt: Date.now() }] });

    // 2g. A GLOBAL SIGN-OUT HERE.
    journal.length = 0;
    const result = logout.terminate('css-bob', [], { channel: 'test' });
    const ended = result.terminated.filter(function (one) {
      return one.family === 'ldap';
    });
    note(ended.length === 1 && ended[0].pending === true &&
         /instructed/.test(ended[0].message) && !/was closed/
           .test(ended[0].message),
         '2g. A GLOBAL SIGN-OUT REPORTS ANOTHER NODE\'S CONNECTION AS ' +
         'INSTRUCTED AND PENDING, NEVER AS CLOSED', JSON.stringify(ended));
    const instruction = signOutsHandle.read('', 'css-bob');
    note(instruction.present && instruction.value.node === NODE_A &&
         journal.some(function (row) {
           return row.handle === clusterConnections.SIGNOUTS_HANDLE &&
                  row.key === 'css-bob';
         }), '2h. and the instruction is written through the journal — the ' +
         'flush the barrier holds the answer for', JSON.stringify(instruction));
    note(Array.isArray(result.acrossCluster) &&
         result.acrossCluster.length === 1 && /instructed/.test(result.message),
         '2i. the result says other nodes were instructed',
         JSON.stringify(result.acrossCluster));
    const again = ldapServer.dropConnectionsFor('css-bob');
    note(!again.some(function (c) { return c.remote; }),
         '2j. a second call in the same sign-out does not report the ' +
         'remote row again', JSON.stringify(again));
    logout.terminate('css-nobody-listed', [], { channel: 'test' });
    note(signOutsHandle.read('', 'css-nobody-listed').present,
         '2k. A GLOBAL SIGN-OUT INSTRUCTS THE CLUSTER FOR AN IDENTITY THIS ' +
         'NODE LISTED NOTHING FOR — a bind another node took a moment ago');
    on = false;
    const offResult = logout.terminate('css-off', [], { channel: 'test' });
    note(!signOutsHandle.read('', 'css-off').present &&
         offResult.acrossCluster === undefined,
         '2l. CONTROL: outside active-active nothing is instructed and the ' +
         'result has no new member');
    on = true;
    clusterConnections.reset();

    // ======================================================================
    // 3. A SESSION'S END, ONCE.
    // ======================================================================
    const ends = [];
    const notices = [];
    const realAudit = audit.audit;
    audit.audit = function (row) {
      if (row && row.action === 'session.end') {
        ends.push(row);
      }
      return realAudit.apply(audit, arguments);
    };
    authn.setSessionObserver(function (notice) {
      if (notice.kind === 'revoked') {
        notices.push(notice.session && notice.session.id);
      }
    });
    function noBrowser() {
      return { headers: [], set: function () {}, req: null };
    }
    async function endTwice(label, shared) {
      store = shared ? sharedStore() : null;
      claims.reset();
      ends.length = 0;
      notices.length = 0;
      const session = authn.startSession(noBrowser(), 'css-' + label,
                                         ['pwd'], '1', 'Test',
                                         { key: 'k-css-' + label,
                                           cookie: false });
      const copy = JSON.parse(JSON.stringify(authn.sessions.get(session.id)));
      authn.endSessionById(session.id, 'node one');
      await settle();
      // THE OTHER NODE, which still held the row.
      authn.sessions.set(session.id, copy);
      authn.endSessionById(session.id, 'node two');
      await settle();
      const mine = function (list) {
        return list.filter(function (x) {
          return (x && (x.target || x)) === session.id;
        });
      };
      return { ends: mine(ends), notices: mine(notices) };
    }
    const control = await endTwice('control', false);
    note(control.ends.length === 2 && control.notices.length === 2,
         '3a. CONTROL: with no shared claim store two processes ending one ' +
         'session report it twice — the duplicate the issue describes',
         JSON.stringify({ ends: control.ends.length,
                          notices: control.notices.length }));
    const once = await endTwice('shared', true);
    const success = once.ends.filter(function (r) {
      return r.outcome === 'success';
    });
    const lost = once.ends.filter(function (r) {
      return r.errorCode === 'STS-AUTHN-0191';
    });
    note(success.length === 1 && once.notices.length === 1,
         '3b. WITH A SHARED CLAIM STORE THE END IS REPORTED ONCE: one ' +
         'success row, one CAEP notice',
         JSON.stringify({ success: success.length,
                          notices: once.notices.length }));
    note(lost.length === 1,
         '3c. and the losing sign-out is recorded as refused with its code',
         JSON.stringify(once.ends.map(function (r) { return r.errorCode; })));
    store = { claimOnce: function () {
      return Promise.reject(new Error('database unreachable'));
    }, purgeClaims: function () { return Promise.resolve(0); } };
    claims.reset();
    ends.length = 0;
    notices.length = 0;
    const unasked = authn.startSession(noBrowser(), 'css-unasked', ['pwd'],
      '1', 'Test', { key: 'k-css-unasked', cookie: false });
    authn.endSessionById(unasked.id, 'store down');
    await settle();
    note(notices.filter(function (id) { return id === unasked.id; })
           .length === 1,
         '3d. a claim store that cannot be asked still REPORTS the end — a ' +
         'lost notice is worse than a repeated one');
    // 3e (#242). A claim that REJECTS — or throws before it has a promise —
    // used to be logged and the report dropped. It is asked again, and the
    // end is reported once when a later attempt wins.
    store = sharedStore();
    claims.reset();
    notices.length = 0;
    const realClaim = claims.claim;
    let refusals = 0;
    claims.claim = function () {
      refusals += 1;
      if (refusals === 1) {
        return Promise.reject(new Error('the claim rejected'));
      }
      if (refusals === 2) {
        throw new Error('the claim threw');
      }
      return realClaim.apply(claims, arguments);
    };
    const retried = authn.startSession(noBrowser(), 'css-retried', ['pwd'],
      '1', 'Test', { key: 'k-css-retried', cookie: false });
    authn.endSessionById(retried.id, 'a claim that fails twice', 'admin');
    note(authn.pendingEndReports() === 1,
         '3e. (while the claim is being asked again, the end is PENDING — ' +
         'what a realm\'s removal waits for, #232)',
         authn.pendingEndReports());
    await new Promise(function (resolve) {
      setTimeout(resolve, 1200);
    });
    claims.claim = realClaim;
    note(refusals === 3 &&
         notices.filter(function (id) { return id === retried.id; })
           .length === 1 && authn.pendingEndReports() === 0,
         '3f. a claim that rejects, then throws, is asked a third time and ' +
         'the end is reported ONCE — it used to be logged and lost (#242)',
         JSON.stringify({ attempts: refusals, pending:
           authn.pendingEndReports(), notices: notices.filter(function (id) {
             return id === retried.id;
           }).length }));
    notices.length = 0;
    refusals = 0;
    claims.claim = function () {
      refusals += 1;
      return Promise.reject(new Error('the claim always rejects'));
    };
    const neverAsked = authn.startSession(noBrowser(), 'css-never', ['pwd'],
      '1', 'Test', { key: 'k-css-never', cookie: false });
    authn.endSessionById(neverAsked.id, 'a claim that always fails',
                         'admin');
    await new Promise(function (resolve) {
      setTimeout(resolve, 1200);
    });
    claims.claim = realClaim;
    note(refusals === 3 &&
         notices.filter(function (id) { return id === neverAsked.id; })
           .length === 1,
         '3g. and one that never answers is reported after the third ' +
         'attempt, as a store that cannot be asked is: told twice is the ' +
         'side to err on, never told the one that is not',
         JSON.stringify({ attempts: refusals }));
    audit.audit = realAudit;
    store = null;

    // ======================================================================
    // 4. STREAM HEALTH.
    // ======================================================================
    let reported = 0;
    store = null;
    claims.reset();
    await ssfCluster.transitionOnce('dead', 'css-stream', function () {
      reported += 1;
    });
    await ssfCluster.transitionOnce('dead', 'css-stream', function () {
      reported += 1;
    });
    note(reported === 2, '4a. CONTROL: with no shared store each process ' +
         'reports the declaration inline, as before', String(reported));
    reported = 0;
    store = sharedStore();
    claims.reset();
    await ssfCluster.transitionOnce('dead', 'css-stream', function () {
      reported += 1;
    });
    await ssfCluster.transitionOnce('dead', 'css-stream', function () {
      reported += 1;
    });
    note(reported === 1, '4b. TWO NODES DECLARING ONE STREAM DEAD REPORT IT ' +
         'ONCE', String(reported));
    const saved = { a: cluster.isActiveActive, e: cluster.enabled,
                    h: cluster.holds };
    note(ssfCluster.leadsProbes() === true,
         '4c. CONTROL: outside active-active every process probes');
    cluster.isActiveActive = function () { return true; };
    cluster.enabled = function () { return true; };
    cluster.holds = function () { return false; };
    note(ssfCluster.leadsProbes() === false,
         '4d. in active-active a node without the probe lease does not probe');
    cluster.holds = function (name) {
      return name === ssfCluster.PROBE_LEASE;
    };
    note(ssfCluster.leadsProbes() === true, '4e. the node holding it does');
    process.env.STS_REQUEST_WORKER = '1';
    note(ssfCluster.leadsProbes() === false,
         '4f. and never one of its request workers');
    delete process.env.STS_REQUEST_WORKER;
    cluster.isActiveActive = saved.a;
    cluster.enabled = saved.e;
    cluster.holds = saved.h;

    // ======================================================================
    // 5. THE GNAP KEY PROOF ON THE SSF ENDPOINTS.
    // ======================================================================
    function gnapRequest() {
      return { headers: { authorization: 'GNAP tok' }, method: 'GET',
               originalUrl: '/ssf/stream', url: '/ssf/stream' };
    }
    function throughRoute(req) {
      return new Promise(function (resolve) {
        ssfCluster.spendGnapProof(req, {}, function () {
          resolve(ssfAuth.authenticate(req, 'read'));
        });
      });
    }
    // The GNAP client DECLARES the Shared Signals scopes (#110): the SSF gate
    // asks the application a token was issued to on every call.
    require(ROOT + '/common/applications').createApplication({
      identifier: 'gnap-instance-1', protocols: ['gnap', 'ssf'],
      fields: { oauthAllowedScope: ['ssf:read', 'ssf:write'] } });
    store = null;
    claims.reset();
    const sync1 = ssfAuth.authenticate(gnapRequest(), 'read');
    const sync2 = ssfAuth.authenticate(gnapRequest(), 'read');
    note(sync1.ok && sync2.ok,
         '5a. CONTROL: the synchronous gate spends nothing — the same proof ' +
         'twice is accepted twice unless this process\'s own cache refuses ' +
         'it, which another node\'s is not',
         JSON.stringify([sync1.ok, sync2.ok]));
    store = sharedStore();
    claims.reset();
    presentations = 0;
    const onA = await throughRoute(gnapRequest());
    const onB = await throughRoute(gnapRequest());
    note(onA.ok && onA.scheme === 'gnap', '5b. through the route the proof ' +
         'is spent and the token accepted', JSON.stringify(onA));
    note(!onB.ok && onB.status === 401 && onB.errorCode === 'STS-GNAP-0715',
         '5c. THE SAME PROOF AT ANOTHER NODE IS REFUSED AS SPENT',
         JSON.stringify(onB));
    note(presentations === 2, '5d. and each request judged the ' +
         'presentation once — the gate did not ask again',
         String(presentations));
    const unspent = ssfAuth.authenticate(gnapRequest(), 'read');
    note(!unspent.ok && unspent.errorCode === 'STS-SSF-0099',
         '5e. on a shared store a GNAP proof nothing spent is refused, not ' +
         'trusted', JSON.stringify(unspent));
    store = null;

    // ======================================================================
    // 6. A POLL ON A SHARED STORE WRITES NO FIRST-DELIVERY ROW.
    // ======================================================================
    const realm = realms.create({ id: 'css-poll', name: 'p' }).realm;
    realms.run(realm, function () {
      const made = streams.createStream(
        { delivery: { method: streams.DELIVERY_POLL } },
        { issuer: 'https://sts.test/realm/css-poll', principal: 'css',
          audience: 'https://receiver.test/css' });
      const record = made.stream;
      const entry = function (jti) {
        return { jti: jti, token: 't-' + jti, claims: { jti: jti },
                 queuedAt: new Date().toISOString(), deliveredAt: '',
                 counted: false };
      };
      const queuedRows = function () {
        return journal.filter(function (row) {
          return row.handle === 'ssf_streams.queued';
        }).length;
      };
      store = null;
      streams.enqueue(record, entry('c1'));
      journal.length = 0;
      streams.poll(streams.getStream(record.stream_id), { maxEvents: 5 });
      note(queuedRows() === 1, '6a. CONTROL: on a store that is not shared ' +
           'the first delivery writes the SET\'s row, as before',
           String(queuedRows()));
      streams.poll(streams.getStream(record.stream_id),
                   { ack: ['c1'], maxEvents: 5 });
      store = sharedStore();
      streams.enqueue(record, entry('s1'));
      journal.length = 0;
      const polled = streams.poll(streams.getStream(record.stream_id),
                                  { maxEvents: 5 });
      note(Object.keys(polled.sets).indexOf('s1') >= 0 && queuedRows() === 0,
           '6b. ON A SHARED STORE THE FIRST DELIVERY WRITES NO ROW, so a ' +
           'poll cannot put back a SET another node\'s acknowledgement just ' +
           'deleted', String(queuedRows()));
      store = null;
    });

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'cluster-signout-signals-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_CLUSTER_|STS_MODE$|STS_PERSISTENCE_|STS_REQUEST_WORKER|LOGOUT_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', CSS_ROOT: ROOT, CSS_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== sign-out across nodes and Shared Signals said once (#46 ' +
             'sections 4 and 6), in a child process ===');
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_signout_signals',
  describe: 'issue #46 sections 4 and 6: an LDAP sign-out instruction and ' +
            'connection table across nodes, one session-end report, one ' +
            'dead-stream report and prober, a GNAP proof spent on SSF, and ' +
            'no first-delivery row on a shared store',
  run: run
};
