// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kdc_cluster_barrier.js
//
// ===========================================================================
// A KDC REQUEST CATCHES UP WITH THE OTHER NODES, AND ITS REPLY WAITS FOR ITS
// OWN COMMIT (2026-11-19, GitHub run #569, cluster mode).
//
// `tests/protocol/sts_kerberos_samba.js` in `cluster` mode failed
// `fast_tests.test_fast_ad_fx_fast_armor` with "unexpectedly None": an AS-REQ
// for a fresh name was answered on node A, which created the principal on
// first sight, and the test's TGS-REQ 22 ms later reached node B, which had
// no row for it and issued a service ticket with NO PAC. Two things were
// missing: the KDC caught up with the cluster only with
// `logout.kerberosSignOut` on, and its reply went before what its request
// wrote had committed — `cluster/cluster_barrier.js`'s rules 1 and 2, which
// an HTTP request and an LDAP operation already had.
//
//   A. `cluster_barrier.writePosition()` / `commitAnswered()` over a stub
//      store: no position where rule 2 does not hold; nothing written, not
//      held and nothing committed; written, held for `commitThrough()` of
//      the position at the answer; a failed commit resolved as its texts.
//   B. `krb5_kdc.handleMessage()` with a stub barrier and
//      `logout.kerberosSignOut` OFF: the pull is asked anyway, the reply is
//      not given while it is outstanding, nor while the commit is, the
//      commit is handed the position read at arrival, and the reply is the
//      KDC's own.
//   C. a commit that fails is KDC_ERR_SVC_UNAVAILABLE (29).
//   D. outside active-active nothing is pulled.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const msgs = require('../kerberos/krb5_messages.js');
const clusterBarrier = require('../cluster/cluster_barrier');
const persistence = require('../persistence/persistence');

const log = require('bunyan').createLogger({
  name: 'kdc_cluster_barrier',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = principals.REALM;
const CLIENT = 'kdc-barrier-' + Date.now().toString(36);

function tick() {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

function bareAsReq() {
  log.debug("Entering bareAsReq().");
  log.debug("Leaving bareAsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [CLIENT] },
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', REALM] },
      till: new Date(Date.now() + 3600 * 1000),
      nonce: 0x22220001,
      etypes: [18, 17]
    }
  });
}

// Replaces the barrier members handleMessage() reads with ones that answer
// only when the test says so; `restore()` puts them back.
function stubBarrier(active) {
  log.debug("Entering stubBarrier().");
  const names = ['isActive', 'catchUp', 'writePosition', 'commitAnswered'];
  const saved = {};
  names.forEach(function (name) {
    saved[name] = clusterBarrier[name];
  });
  const stub = { pulls: [], commits: [], releasePull: null,
                 releaseCommit: null, position: { sentinel: true } };
  clusterBarrier.isActive = function () {
    log.debug("Entering the stub isActive().");
    log.debug("Leaving the stub isActive().");
    return active;
  };
  clusterBarrier.catchUp = function (what) {
    log.debug("Entering the stub catchUp().");
    stub.pulls.push(what);
    log.debug("Leaving the stub catchUp().");
    return new Promise(function (resolve) {
      stub.releasePull = resolve;
    });
  };
  clusterBarrier.writePosition = function () {
    log.debug("Entering the stub writePosition().");
    log.debug("Leaving the stub writePosition().");
    return stub.position;
  };
  clusterBarrier.commitAnswered = function (arrival) {
    log.debug("Entering the stub commitAnswered().");
    stub.commits.push(arrival);
    log.debug("Leaving the stub commitAnswered().");
    return new Promise(function (resolve) {
      stub.releaseCommit = resolve;
    });
  };
  stub.restore = function () {
    log.debug("Entering restore().");
    names.forEach(function (name) {
      clusterBarrier[name] = saved[name];
    });
    log.debug("Leaving restore().");
  };
  log.debug("Leaving stubBarrier().");
  return stub;
}

// Replaces the store members the barrier reads; `restore()` puts them back.
function stubStore(holds, generation, commitResults) {
  log.debug("Entering stubStore().");
  const names = ['answersAfterCommit', 'writeGeneration', 'commitThrough',
                 'keysPending'];
  const saved = {};
  names.forEach(function (name) {
    saved[name] = persistence[name];
  });
  const stub = { generation: generation, committed: [] };
  persistence.answersAfterCommit = function () {
    log.debug("Entering the stub answersAfterCommit().");
    log.debug("Leaving the stub answersAfterCommit().");
    return holds;
  };
  persistence.writeGeneration = function () {
    log.debug("Entering the stub writeGeneration().");
    log.debug("Leaving the stub writeGeneration().");
    return Object.assign({}, stub.generation);
  };
  persistence.commitThrough = function (target) {
    log.debug("Entering the stub commitThrough().");
    stub.committed.push(target);
    log.debug("Leaving the stub commitThrough().");
    return Promise.resolve(commitResults);
  };
  persistence.keysPending = function () {
    log.debug("Entering the stub keysPending().");
    log.debug("Leaving the stub keysPending().");
    return false;
  };
  stub.restore = function () {
    log.debug("Entering restore().");
    names.forEach(function (name) {
      persistence[name] = saved[name];
    });
    log.debug("Leaving restore().");
  };
  log.debug("Leaving stubStore().");
  return stub;
}

async function barrierSection(t) {
  log.debug("Entering barrierSection().");
  t.log.info('=== A. writePosition() and commitAnswered() ===');
  let store = stubStore(false, { directory: 1, minted: 0, observed: 0 }, []);
  try {
    t.check(clusterBarrier.writePosition() === null,
            'A1. where rule 2 does not hold there is no position to hold for');
    t.check((await clusterBarrier.commitAnswered(null)).length === 0 &&
            store.committed.length === 0,
            'A2. and no position commits nothing');
  } finally {
    store.restore();
  }
  store = stubStore(true, { directory: 5, minted: 3, observed: 1 }, []);
  try {
    const arrival = clusterBarrier.writePosition();
    t.check(!!arrival && arrival.directory === 5,
            'A3. where it holds, the store\'s position is read',
            JSON.stringify(arrival));
    let failed = await clusterBarrier.commitAnswered(arrival);
    t.check(failed.length === 0 && store.committed.length === 0,
            'A4. nothing written: answered at once, nothing committed',
            JSON.stringify(store.committed));
    store.generation = { directory: 5, minted: 4, observed: 2 };
    failed = await clusterBarrier.commitAnswered(arrival);
    t.check(failed.length === 0 && store.committed.length === 0,
            'A5. a tally alone (minted and observed moving together) is ' +
            'not a write', JSON.stringify(store.committed));
    store.generation = { directory: 5, minted: 5, observed: 2 };
    failed = await clusterBarrier.commitAnswered(arrival);
    t.check(failed.length === 0 && store.committed.length === 1 &&
            store.committed[0].minted === 5,
            'A6. a minted row written (a principal created on first ' +
            'sight): held for commitThrough() of the position at the answer',
            JSON.stringify(store.committed));
  } finally {
    store.restore();
  }
  store = stubStore(true, { directory: 1, minted: 0, observed: 0 },
                    [{ error: 'the store refused' }]);
  try {
    const arrival = clusterBarrier.writePosition();
    store.generation = { directory: 2, minted: 0, observed: 0 };
    const failed = await clusterBarrier.commitAnswered(arrival);
    t.check(failed.length === 1 && /refused/.test(failed[0]),
            'A7. a failed commit is resolved as its texts, never rejected',
            JSON.stringify(failed));
  } finally {
    store.restore();
  }
  log.debug("Leaving barrierSection().");
}

async function kdcSection(t) {
  log.debug("Entering kdcSection().");
  t.log.info('=== B. handleMessage(): pulled, then held for its commit ===');
  config.setOverride('logout.kerberosSignOut', 'false');
  let stub = stubBarrier(true);
  try {
    let reply = null;
    kdc.handleMessage(Buffer.from(bareAsReq())).then(function (r) {
      reply = r;
    });
    await tick();
    t.check(stub.pulls.length === 1 && /Kerberos/.test(stub.pulls[0]),
            'B1. the cluster pull is asked with logout.kerberosSignOut OFF ' +
            '— a principal created on another node is replicated state too',
            JSON.stringify(stub.pulls));
    t.check(reply === null && stub.commits.length === 0,
            'B2. nothing is answered while the pull is outstanding');
    stub.releasePull({ caughtUp: true });
    for (let i = 0; i < 50 && !stub.commits.length; i++) {
      await tick();
    }
    t.check(stub.commits.length === 1 &&
            stub.commits[0] === stub.position,
            'B3. the reply is handed to commitAnswered() with the position ' +
            'read when the request arrived');
    await tick();
    t.check(reply === null,
            'B4. THE REPLY IS NOT GIVEN WHILE ITS COMMIT IS OUTSTANDING — ' +
            'so an AS-REP cannot reach the client before the principal it ' +
            'created can reach another node');
    stub.releaseCommit([]);
    for (let i = 0; i < 50 && !reply; i++) {
      await tick();
    }
    const read = reply ? msgs.readKdcResponse(reply) : null;
    t.check(!!read && read.kind === 'KRB-ERROR' &&
            read.error.errorCode === 25,
            'B5. and once it has committed the KDC\'s own reply goes ' +
            '(KDC_ERR_PREAUTH_REQUIRED for a bare AS-REQ)',
            read && (read.kind + ' ' + (read.error && read.error.errorCode)));
  } finally {
    stub.restore();
  }

  t.log.info('=== C. a commit that fails ===');
  stub = stubBarrier(true);
  try {
    let reply = null;
    kdc.handleMessage(Buffer.from(bareAsReq())).then(function (r) {
      reply = r;
    });
    await tick();
    stub.releasePull({ caughtUp: true });
    for (let i = 0; i < 50 && !stub.commits.length; i++) {
      await tick();
    }
    stub.releaseCommit(['the store refused']);
    for (let i = 0; i < 50 && !reply; i++) {
      await tick();
    }
    const read = reply ? msgs.readKdcResponse(reply) : null;
    t.check(!!read && read.kind === 'KRB-ERROR' &&
            read.error.errorCode === 29,
            'C1. is KDC_ERR_SVC_UNAVAILABLE (29), which clients retry, in ' +
            'place of the reply (STS-KRB-0259)',
            read && (read.kind + ' ' + (read.error && read.error.errorCode)));
  } finally {
    stub.restore();
  }

  t.log.info('=== D. outside active-active ===');
  stub = stubBarrier(false);
  try {
    let reply = null;
    kdc.handleMessage(Buffer.from(bareAsReq())).then(function (r) {
      reply = r;
    });
    for (let i = 0; i < 50 && !stub.commits.length; i++) {
      await tick();
    }
    t.check(stub.pulls.length === 0,
            'D1. nothing is pulled', JSON.stringify(stub.pulls));
    if (stub.releaseCommit) {
      stub.releaseCommit([]);
    }
    for (let i = 0; i < 50 && !reply; i++) {
      await tick();
    }
    t.check(!!reply, 'D2. and the reply is given');
  } finally {
    stub.restore();
    config.clearOverride('logout.kerberosSignOut');
  }
  log.debug("Leaving kdcSection().");
}

async function run(t) {
  log.debug("Entering run().");
  await barrierSection(t);
  await kdcSection(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kdc_cluster_barrier',
  describe: 'a KDC request in active-active catches up with the cluster ' +
            'whatever logout.kerberosSignOut says, and its reply waits ' +
            'for what it wrote to commit (GitHub run #569)',
  run: run
};
