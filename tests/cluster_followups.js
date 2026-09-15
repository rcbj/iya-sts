'use strict';
//
// File: cluster_followups.js
//
// ===========================================================================
// ISSUE #46, THE FOLLOW-UPS BATCHES 1 AND 2 LEFT (2026-09-14).
//
//   A. A REALM'S KEY SET IS MADE OFF THE EVENT LOOP. `helpers.prepareKeySet()`
//      hands the factory four RSA pairs node generated in its thread pool, so
//      the read that follows performs NO synchronous RSA generation — and the
//      CONTROL, the same read without it, performs four, so the spy measures
//      something. A held realm prepares nothing. And a burst of realms
//      prepared stops the loop for less than half of what the same number
//      generated on it does (a relative bound, so a slow machine is not a
//      failure).
//   B. A HEARTBEAT THAT RAN LATE IS NAMED. A loop blocked past the lifetime:
//      the node still exits (the fence is the database clock's), and the
//      stall is recorded (`STS-CLUSTER-0025`, `status().lastStallMs`).
//   C. ACTIVE-ACTIVE REFUSES AN EMPTY `global.publicBaseUrl`
//      (`STS-CLUSTER-0026`); a set one, and active-passive, are not refused.
//   D. A MINTED WRITE ASKS FOR A FLUSH — once per flush, a delete alone
//      included, and not when a failed write's keys are put back. And
//      `persistence.js` hands its scheduler over.
//   E. A CREATE CLAIMS ITS NAME at the doors that did not: two concurrent
//      console creates of one name through `runClaimed()` never overlap — the
//      second waits for the first to release; a create sent the moment the
//      first was answered is not refused as in progress; a claim still held
//      when the wait runs out is refused; where nothing can race it runs
//      synchronously. The three console handlers call it.
//   F. A WEBAUTHN REGISTRATION CLAIMS ITS CREDENTIAL ID: two concurrent
//      registrations of one id for one person — one row; a later one of the
//      same id is refused on the entry.
//   G. A GNAP DECISION IS CLAIMED PER INTERACTION before it is recorded, on
//      every path that records one.
//   H. A RATE-LIMITED FAILURE IS ANSWERED ON THE ATOMIC COUNT. Forty
//      concurrent failures against a limit of 5: exactly 5 answered as
//      failures — and the CONTROL, a count read and written back, answers
//      more. A verified credential at the limit is refused and clears
//      nothing; under it, it clears.
//
// IN A CHILD PROCESS: a stubbed `clusterStore()`, the dispatch settings and a
// keystore armed with a KEK are process-wide.
//
// WHY IN PROCESS, tests/CLAUDE.md's first question: a stalled event loop, two
// requests racing one claim on two nodes and a count read by forty requests at
// once cannot be arranged on demand over HTTP. The live two-node runs are
// recorded in cluster/CLAUDE.md and persistence/CLAUDE.md.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_followups', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file.
function childMain() {
  const ROOT = process.env.CFU_ROOT;
  const OUT = process.env.CFU_OUT;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function later(fn) {
    return new Promise(function (resolve, reject) {
      setImmediate(function () {
        try {
          resolve(fn());
        } catch (e) {
          reject(e);
        }
      });
    });
  }
  // Postgres's semantics for claims and windows: one row per key, each
  // statement atomic, every answer a macrotask later.
  function atomicStore() {
    const claims = new Map();
    const windows = new Map();
    return {
      claimOnce: function (scope, realm, key, opts) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const row = claims.get(k);
          if (row && row.expiresAt > Date.now()) {
            return { claimed: false, existing: { origin: 'node-b' } };
          }
          claims.set(k, { reservation: opts.reservation,
                          expiresAt: Date.now() + opts.ttlMs });
          return { claimed: true };
        });
      },
      releaseClaim: function (scope, realm, key, reservation) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const row = claims.get(k);
          if (row && row.reservation === reservation) {
            claims.delete(k);
            return true;
          }
          return false;
        });
      },
      claimHeld: function (scope, realm, key) {
        return later(function () {
          const row = claims.get(scope + ' ' + realm + ' ' + key);
          return !!row && row.expiresAt > Date.now();
        });
      },
      purgeClaims: function () {
        return later(function () { return 0; });
      },
      countWindow: function (scope, realm, key, windowMs) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const now = Date.now();
          const row = windows.get(k);
          if (!row || row.endsAt <= now) {
            windows.set(k, { count: 1, endsAt: now + windowMs });
            return { count: 1, remainingMs: windowMs };
          }
          row.count += 1;
          return { count: row.count, remainingMs: row.endsAt - now };
        });
      },
      peekWindow: function (scope, realm, key) {
        return later(function () {
          const row = windows.get(scope + ' ' + realm + ' ' + key);
          return row && row.endsAt > Date.now()
            ? { count: row.count, remainingMs: row.endsAt - Date.now() }
            : { count: 0, remainingMs: 0 };
        });
      },
      clearWindow: function (scope, realm, key) {
        return later(function () {
          return windows.delete(scope + ' ' + realm + ' ' + key);
        });
      },
      purgeWindows: function () {
        return later(function () { return 0; });
      }
    };
  }
  function lostUpdateStore() {
    const store = atomicStore();
    const windows = new Map();
    store.countWindow = function (scope, realm, key, windowMs) {
      const k = scope + ' ' + realm + ' ' + key;
      const read = windows.get(k) ||
        { count: 0, endsAt: Date.now() + windowMs };
      return later(function () {
        const written = { count: read.count + 1, endsAt: read.endsAt };
        windows.set(k, written);
        return { count: written.count, remainingMs: windowMs };
      });
    };
    return store;
  }
  function fromAddress(address) {
    return { headers: {}, socket: { remoteAddress: address } };
  }
  function busyWait(ms) {
    const until = Date.now() + ms;
    while (Date.now() < until) {
      nodeCrypto.randomBytes(16);
    }
  }
  function loopGapDuring(work) {
    let maxGap = 0;
    let last = Date.now();
    const timer = setInterval(function () {
      const now = Date.now();
      maxGap = Math.max(maxGap, now - last);
      last = now;
    }, 5);
    return Promise.resolve().then(work).then(function (value) {
      return new Promise(function (resolve) {
        setTimeout(function () {
          clearInterval(timer);
          resolve({ value: value,
                    maxGap: Math.max(maxGap, Date.now() - last) });
        }, 20);
      });
    });
  }

  (async function () {
    try {
      const realms = require(ROOT + '/common/realms');
      const config = require(ROOT + '/common/config');
      const errorCodes = require(ROOT + '/common/error_codes');
      const helpers = require(ROOT + '/common/helpers');

      // ================= A. KEYS OFF THE LOOP ===============================
      const cryptoModule = require('crypto');
      const realSync = cryptoModule.generateKeyPairSync;
      let rsaSync = 0;
      cryptoModule.generateKeyPairSync = function (type) {
        if (type === 'rsa') {
          rsaSync += 1;
        }
        return realSync.apply(this, arguments);
      };
      ['cfu-a1', 'cfu-a2', 'cfu-ctl'].forEach(function (id) {
        realms.create({ id: id, name: id });
      });
      helpers.stsKeysFor.of('default');
      const made = await helpers.prepareKeySet('cfu-a1');
      rsaSync = 0;
      const prepared = helpers.stsKeysFor.of('cfu-a1');
      const afterPrepared = rsaSync;
      rsaSync = 0;
      const direct = helpers.stsKeysFor.of('cfu-ctl');
      const control = rsaSync;
      note(made === true && afterPrepared === 0 && !!prepared.kid &&
           !!prepared.privateKeyPem && !!prepared.refreshTokenEncKeys &&
           !!prepared.requestObjectEncKeys && !!prepared.vciRequestEncKey,
           'A1. A PREPARED REALM\'S KEY SET IS READ WITH NO SYNCHRONOUS RSA ' +
           'GENERATION, and it is a whole set', 'prepared=' + made +
           ' rsaSync=' + afterPrepared + ' kid=' + prepared.kid);
      note(control >= 4 && !!direct.kid,
           'A2. CONTROL: the same read of a realm nobody prepared generates ' +
           'on the loop (' + control + ' RSA generations), so A1 measures ' +
           'the preparation', String(control));
      const again = await helpers.prepareKeySet('cfu-a1');
      note(again === false, 'A3. a realm whose keys are held prepares nothing',
           String(again));
      const privatePem = prepared.privateKeyPem;
      note(/BEGIN RSA PRIVATE KEY/.test(String(privatePem)) &&
           cryptoModule.createPrivateKey(privatePem).asymmetricKeyDetails
             .modulusLength === 2048,
           'A4. the signing key keeps the shape forge wrote (PKCS#1, 2048 bits)',
           String(privatePem).slice(0, 32));
      cryptoModule.generateKeyPairSync = realSync;
      const syncIds = ['cfu-s1', 'cfu-s2', 'cfu-s3'];
      const asyncIds = ['cfu-p1', 'cfu-p2', 'cfu-p3'];
      syncIds.concat(asyncIds).forEach(function (id) {
        realms.create({ id: id, name: id });
      });
      const onLoop = await loopGapDuring(function () {
        syncIds.forEach(function (id) {
          helpers.stsKeysFor.of(id);
        });
      });
      const offLoop = await loopGapDuring(function () {
        return helpers.prepareKeySets(asyncIds);
      });
      note(offLoop.maxGap * 2 < onLoop.maxGap,
           'A5. three realms prepared stop the loop for less than half of ' +
           'what three generated on it do', 'off=' + offLoop.maxGap +
           'ms on=' + onLoop.maxGap + 'ms');

      // ================= B. A LATE HEARTBEAT ================================
      const cluster = require(ROOT + '/cluster/cluster');
      const saved = {};
      ['STS_MODE', 'STS_PERSISTENCE_MODE', 'STS_CLUSTER_MODE',
       'STS_CLUSTER_HEARTBEAT_MS', 'STS_CLUSTER_NODE_TTL_MS',
       'STS_PUBLIC_BASE_URL'].forEach(function (name) {
        saved[name] = process.env[name];
      });
      process.env.STS_MODE = 'product';
      process.env.STS_PERSISTENCE_MODE = 'postgres';
      process.env.STS_CLUSTER_MODE = 'active-passive';
      process.env.STS_CLUSTER_HEARTBEAT_MS = '250';
      process.env.STS_CLUSTER_NODE_TTL_MS = '1000';
      const exits = [];
      let expired = false;
      cluster.reset({ exit: function (code) { exits.push(code); } });
      await cluster.gate({
        setFence: function () {},
        joinCluster: function () {
          return Promise.resolve({ joined: true, differing: [], live: 0 });
        },
        acquireLease: function () {
          return Promise.resolve({ held: true, token: 3 });
        },
        heartbeat: function () {
          return Promise.resolve({ alive: !expired,
                                   leases: [{ name: 'service', token: 3 }] });
        },
        clusterState: function () {
          return Promise.resolve({ nodes: [], leases: [] });
        },
        leaveCluster: function () {
          return Promise.resolve(true);
        }
      });
      await new Promise(function (resolve) { setTimeout(resolve, 300); });
      note(exits.length === 0 && !(cluster.status().lastStallMs > 0),
           'B1. a node whose heartbeats run on time records no stall',
           JSON.stringify(cluster.status().lastStallMs));
      busyWait(1300);
      expired = true;
      await new Promise(function (resolve) { setTimeout(resolve, 400); });
      note(exits.length === 1 && cluster.status().lastStallMs >= 250,
           'B2. A LOOP BLOCKED PAST THE LIFETIME: the node still EXITS — the ' +
           'row expired by the database\'s clock — and the stall is recorded ' +
           'as the likely cause', 'exits=' + JSON.stringify(exits) +
           ' lastStallMs=' + cluster.status().lastStallMs);
      cluster.reset();

      // ================= C. ONE NAME FOR ACTIVE-ACTIVE ======================
      process.env.STS_CLUSTER_MODE = 'active-active';
      delete process.env.STS_PUBLIC_BASE_URL;
      config.clearOverride && config.clearOverride('global.publicBaseUrl');
      const refused = cluster.resolve();
      note(/STS-CLUSTER-0026/.test(String(refused.refused)),
           'C1. ACTIVE-ACTIVE WITH global.publicBaseUrl EMPTY IS REFUSED',
           String(refused.refused).slice(0, 120));
      process.env.STS_PUBLIC_BASE_URL = 'https://cluster.example';
      note(!cluster.resolve().refused,
           'C2. and starts with one set', String(cluster.resolve().refused));
      delete process.env.STS_PUBLIC_BASE_URL;
      process.env.STS_CLUSTER_MODE = 'active-passive';
      note(!cluster.resolve().refused,
           'C3. active-passive is not refused for it — one node answers at a ' +
           'time', String(cluster.resolve().refused));
      Object.keys(saved).forEach(function (name) {
        if (saved[name] === undefined) {
          delete process.env[name];
        } else {
          process.env[name] = saved[name];
        }
      });
      cluster.reset();

      // ================= D. A MINTED WRITE ASKS FOR A FLUSH =================
      const keystore = require(ROOT + '/common/keystore');
      const minted = require(ROOT + '/persistence/persistence_minted');
      const kekFile = path.join(os.tmpdir(), 'cfu-kek-' + process.pid);
      fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                       { mode: 0o600 });
      process.env.STS_KEYS_SOURCE = 'persisted';
      process.env.STS_KEYS_KEK_PROVIDER = 'file';
      process.env.STS_KEYS_KEK_FILE = kekFile;
      keystore.reset();
      keystore.setStore({
        loadKeys: function () { return Promise.resolve([]); },
        saveKeys: function () { return Promise.resolve(); },
        deleteKeys: function () { return Promise.resolve(); }
      });
      await keystore.start();
      config.setOverride('global.mode', 'product');
      config.setOverride('persistence.minted', true);
      let failWrites = false;
      const written = [];
      minted.reset();
      minted.setDriver({
        loadMinted: function () { return Promise.resolve([]); },
        saveMinted: function (upserts, deletes) {
          if (failWrites) {
            return Promise.reject(new Error('the database went away'));
          }
          written.push({ upserts: upserts.length, deletes: deletes.length,
                         tombstones: deletes.filter(function (row) {
                           return row.tombstone;
                         }).length });
          return Promise.resolve({ refused: [], merged: [] });
        }
      }, 'postgres');
      let asked = 0;
      minted.setScheduler(function () {
        asked += 1;
        return true;
      });
      const sessions = realms.map({ persist: 'test.cfu.sessions',
                                    tombstone: true });
      sessions.set('s1', { user: 'alice' });
      sessions.set('s2', { user: 'bob' });
      note(asked === 1, 'D1. THE FIRST WRITE AFTER A FLUSH ASKS FOR ONE, and ' +
           'the second in the same burst does not', String(asked));
      await minted.flush();
      sessions.delete('s1');
      note(asked === 2,
           'D2. A DELETE ALONE ASKS FOR A FLUSH — a sign-out\'s tombstone is ' +
           'written without waiting for an unrelated write', String(asked));
      await minted.flush();
      const last = written[written.length - 1] || {};
      note(last.deletes === 1 && last.tombstones === 1,
           'and the flush it asked for writes the tombstone',
           JSON.stringify(written));
      failWrites = true;
      sessions.set('s3', { user: 'carol' });
      await minted.flush();
      note(asked === 3 && minted.dirty(),
           'D3. a failed write puts its keys back WITHOUT asking again — a ' +
           'database outage is not a loop of zero-delay retries', 'asked=' +
           asked + ' dirty=' + minted.dirty());
      failWrites = false;
      const persistenceSource = fs.readFileSync(
        ROOT + '/persistence/persistence.js', 'utf8').replace(/\s+/g, ' ');
      note(persistenceSource.indexOf('minted.setScheduler(mintedChanged);') >= 0,
           'D4. persistence.js hands mintedChanged() to the journal');
      minted.reset();
      config.clearOverride('persistence.minted');
      config.clearOverride('global.mode');

      // ================= E. CREATE CLAIMS AT THE CONSOLE ====================
      const persistence = require(ROOT + '/persistence/persistence');
      const ldap = require(ROOT + '/ldap/ldap_server');
      const createClaims = require(ROOT + '/ldap/directory_create_claims');
      let ranInline = false;
      createClaims.runClaimed({ username: 'cfu-inline' }, function () {
        ranInline = true;
      }, function () {}, function () {});
      note(ranInline, 'E1. where nothing can race, runClaimed() runs the ' +
           'create synchronously, exactly as the handler did');
      const atomic = atomicStore();
      persistence.clusterStore = function () { return atomic; };
      persistence.syncNow = function () { return Promise.resolve(); };
      persistence.flush = function () { return Promise.resolve(); };
      process.env.STS_WORKERS_REQUEST_COUNT = '1';
      process.env.STS_WORKERS_DISPATCH = '*';
      const outcomes = [];
      let running = 0;
      await Promise.all([1, 2].map(function () {
        return createClaims.runClaimed({ username: 'cfu-dup' },
          function (held) {
            running += 1;
            outcomes.push(running > 1 ? 'overlapped' : 'ran');
            return later(function () {
              running -= 1;
              held.settle(true);
            });
          }, function (held) {
            outcomes.push('refused:' + held.code);
          }, function (e) {
            outcomes.push('threw:' + e.message);
          });
      }));
      note(outcomes.join(',') === 'ran,ran',
           'E2. TWO CONCURRENT CONSOLE CREATES OF ONE NAME NEVER OVERLAP: the ' +
           'second waits for the first to release, then runs (and meets the ' +
           'directory\'s own check)', outcomes.join(','));
      // E2c. A NAME STILL HELD WHEN THE WAIT RUNS OUT IS REFUSED AS IN
      // PROGRESS — the waiting is bounded, and a holder that never finishes
      // (a process that died holding the claim) is not waited on forever.
      const holding = await createClaims.claim({ usernames: ['cfu-held'] });
      const waitedFrom = Date.now();
      const late = await createClaims.claim({ usernames: ['cfu-held'],
                                              waitMs: 300 });
      const waited = Date.now() - waitedFrom;
      holding.settle(false);
      note(holding.ok && !late.ok && late.code === 'STS-LDAP-0092' &&
           waited >= 300 && waited < 3000,
           'E2c. a claim held past the wait is refused STS-LDAP-0092, after ' +
           'the wait and not before it',
           JSON.stringify({ code: late.code, waited: waited }));
      // E2b. SEQUENTIAL IS NOT CONCURRENT (2026-09-15). A door answers
      // before its claim is released (the release follows the flush), so a
      // client that creates the same name again the moment it has its answer
      // finds the name still claimed. It must wait for the release and reach
      // the directory's own "already exists", not a 409 "being created". A
      // dispatch run of sts_admin_api_operations got the 409, 70ms after its
      // own 200.
      const sequence = [];
      await new Promise(function (answered) {
        createClaims.runClaimed({ username: 'cfu-seq' }, function (held) {
          held.settle(true);
          sequence.push('answered');
          answered();
        }, function (held) {
          sequence.push('refused:' + held.code);
          answered();
        }, function (e) {
          sequence.push('threw:' + e.message);
          answered();
        });
      });
      await createClaims.runClaimed({ username: 'cfu-seq' }, function (held) {
        sequence.push('ran');
        held.settle(false);
      }, function (held) {
        sequence.push('refused:' + held.code);
      }, function (e) {
        sequence.push('threw:' + e.message);
      });
      note(sequence.join(',') === 'answered,ran',
           'E2b. the next create of a name, sent the moment the first was ' +
           'answered and before its claim is released, waits and runs rather ' +
           'than being refused as in progress', sequence.join(','));
      const adminSource = fs.readFileSync(ROOT + '/admin-ui/admin.js', 'utf8');
      const handlers = ["app.post('/admin/users',",
                        "app.post('/admin/users/new',",
                        "app.post('/admin/groups',"];
      note(handlers.every(function (head) {
        const at = adminSource.indexOf(head);
        const next = adminSource.indexOf('\napp.', at + head.length);
        return at >= 0 && adminSource.slice(at, next)
          .indexOf('createClaims.runClaimed(') >= 0;
      }), 'E3. the console\'s user, new-user and group create handlers each ' +
          'create through runClaimed()');
      const scimSource = fs.readFileSync(ROOT + '/scim/scim.js', 'utf8');
      note((scimSource.match(/\.ingress\(claimingIngress\('(User|Group)'/g) ||
            []).length === 2,
           'E4. both SCIM ingress handlers — the road a Bulk create takes — ' +
           'claim through claimingIngress()');
      require(ROOT + '/scim/scim');
      const SCIMMY = require(require.resolve('scimmy',
                                             { paths: [ROOT + '/scim'] }));
      const bulkReq = { headers: {}, socket: { remoteAddress: '127.0.0.1' },
                        get: function () { return ''; }, protocol: 'https',
                        originalUrl: '/scim/v2/Bulk' };
      const bulkOnce = function (userName) {
        return new SCIMMY.Messages.BulkRequest({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
          Operations: [{ method: 'POST', path: '/Users', bulkId: 'one',
            data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                    userName: userName } }]
        }, 10).apply([SCIMMY.Resources.User, SCIMMY.Resources.Group],
                     { req: bulkReq }).then(function (answer) {
          return answer.Operations[0];
        });
      };
      const bulk = await Promise.all([bulkOnce('cfu-bulk-dup'),
                                      bulkOnce('cfu-bulk-dup')]);
      const statuses = bulk.map(function (op) {
        return String(op.status);
      }).sort().join(',');
      const lost = bulk.filter(function (op) {
        return String(op.status) === '409';
      })[0];
      note(statuses === '201,409' && lost &&
           /already a user called/.test(
             String(lost.response && lost.response.detail)),
           'E5. TWO CONCURRENT SCIM BULK CREATES OF ONE userName: one 201, ' +
           'and the other waits for its claim and meets the directory\'s own ' +
           '"already a user called" (2026-09-15; it was a 409 "being ' +
           'created" before the wait)', statuses + ' ' +
           String(lost && lost.response && lost.response.detail).slice(0, 80));
      // E5b. AND THE BULK INGRESS REALLY ASKS THE CLAIM: with the name held
      // elsewhere and given back 150ms later, a bulk create of it waits for
      // the release and then creates. In one process the directory's check
      // alone would answer E5 identically, so this is what shows the claim.
      const realmsModule = require(ROOT + '/common/realms');
      const heldElsewhere = await createClaims.claim({
        realm: realmsModule.currentId(), usernames: ['cfu-bulk-wait'] });
      setTimeout(function () {
        heldElsewhere.settle(false);
      }, 150);
      const bulkFrom = Date.now();
      const waitedOp = await bulkOnce('cfu-bulk-wait');
      const bulkWaited = Date.now() - bulkFrom;
      note(heldElsewhere.ok && String(waitedOp.status) === '201' &&
           bulkWaited >= 140,
           'E5b. a SCIM Bulk create of a name another request holds waits ' +
           'for the release and then creates',
           JSON.stringify({ status: waitedOp.status, waited: bulkWaited }));

      // ================= F. A WEBAUTHN REGISTRATION =========================
      const credentials = require(ROOT + '/common/credentials');
      const who = 'cfu-webauthn-' + process.pid;
      ldap.createUser(who, {});
      const key = { credentialId: 'cfu-credential-1',
                    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
                    signCount: 0, label: 'one' };
      const pair = await Promise.all([
        credentials.addKeyClaimed(who, key, 'mfa'),
        credentials.addKeyClaimed(who, Object.assign({}, key, { label: 'two' }),
                                  'mfa')
      ]);
      const rows = credentials.keysOf(who).filter(function (one) {
        return one.credentialId === 'cfu-credential-1';
      });
      note(pair.filter(function (one) { return one.ok; }).length === 1 &&
           pair.some(function (one) {
             return errorCodes.codeOf(one) === 'STS-AUTHN-0193';
           }) && rows.length === 1,
           'F1. TWO CONCURRENT REGISTRATIONS OF ONE CREDENTIAL ID: one row, ' +
           'and the second refused (STS-AUTHN-0193)',
           JSON.stringify(pair.map(function (one) {
             return one.ok || errorCodes.codeOf(one);
           })) + ' rows=' + rows.length);
      const onEntry = credentials.addKey(who, key, 'mfa');
      note(!onEntry.ok && errorCodes.codeOf(onEntry) === 'STS-AUTHN-0095',
           'F2. and a registration of an id already on the entry is refused ' +
           'there, whatever door asks', JSON.stringify(onEntry));

      // ================= G. A GNAP DECISION =================================
      const gnapSource = fs.readFileSync(ROOT + '/gnap/gnap_interact.js',
                                         'utf8');
      const approveAt = gnapSource.indexOf("app.get('/gnap/approve/:id'");
      const tail = gnapSource.slice(approveAt);
      const decides = tail.split('grants.decide(').length - 1;
      const finishes = tail.split('grants.finishInteraction(').length - 1;
      const claimed = tail.split('claimDecision(res, grant)').length - 1;
      note(approveAt > 0 && decides === 2 && finishes === 1 && claimed === 3,
           'G1. EVERY PATH THAT RECORDS A DECISION CLAIMS IT FIRST — the ' +
           'approval, the remembered approval and the cancelled sign-in',
           'decide=' + decides + ' finish=' + finishes + ' claim=' + claimed);
      const gnapStore = require(ROOT + '/gnap/gnap_store');
      const first = await gnapStore.spend('decision', 'g1:a1', 60,
                                          'STS-GNAP-0717');
      const second = await gnapStore.spend('decision', 'g1:a1', 60,
                                           'STS-GNAP-0717');
      note(first.ok && !second.ok && second.errorCode === 'STS-GNAP-0717',
           'G2. and a second decision on one interaction is refused with ' +
           'STS-GNAP-0717', JSON.stringify(second));

      // ================= H. THE ANSWER ON THE ATOMIC COUNT ==================
      const websecurity = require(ROOT + '/common/websecurity');
      delete process.env.STS_WORKERS_REQUEST_COUNT;
      delete process.env.STS_WORKERS_DISPATCH;
      const LIMIT = 5;
      const burst = await Promise.all(Array.from({ length: 40 },
        function (_, i) {
          return websecurity.failedShared('cfu-secret',
            fromAddress('198.51.100.' + (i % 20)), 'client-a',
            { identity: LIMIT, address: 1000 });
        }));
      const answered = burst.filter(function (one) { return one === null; })
                            .length;
      note(answered === LIMIT && burst.some(function (one) {
        return one && errorCodes.codeOf(one) === 'STS-HTTP-0017';
      }), 'H1. FORTY CONCURRENT FAILURES AGAINST A LIMIT OF ' + LIMIT + ': ' +
          'exactly ' + LIMIT + ' are answered as failures, the rest with the ' +
          'lockout', answered + ' answered');
      const lossy = lostUpdateStore();
      persistence.clusterStore = function () { return lossy; };
      const lossyBurst = await Promise.all(Array.from({ length: 40 },
        function (_, i) {
          return websecurity.failedShared('cfu-secret-control',
            fromAddress('198.51.100.' + (i % 20)), 'client-a',
            { identity: LIMIT, address: 1000 });
        }));
      const lossyAnswered = lossyBurst.filter(function (one) {
        return one === null;
      }).length;
      note(lossyAnswered > LIMIT,
           'H2. CONTROL: against a count read and written back the same ' +
           'burst answers more, so H1 measures the atomic count',
           lossyAnswered + ' answered');
      persistence.clusterStore = function () { return atomic; };
      const at = fromAddress('203.0.113.9');
      for (let i = 0; i < 3; i++) {
        await websecurity.failedShared('cfu-bind', at, 'uid=svc', 3);
      }
      const racedOut = await websecurity.succeededShared('cfu-bind', at,
        'uid=svc', { keepAddress: true, unlessBlocked: true, limit: 3 });
      const stillBlocked = await websecurity.blockedShared('cfu-bind', at,
                                                           'uid=svc', 3);
      note(racedOut && racedOut.ok === false && stillBlocked,
           'H3. A VERIFIED CREDENTIAL AT THE LIMIT IS REFUSED like the burst ' +
           'that spent it, and clears nothing', JSON.stringify(racedOut));
      const fresh = fromAddress('203.0.113.10');
      await websecurity.failedShared('cfu-bind2', fresh, 'uid=svc2', 3);
      const cleared = await websecurity.succeededShared('cfu-bind2', fresh,
        'uid=svc2', { unlessBlocked: true, limit: 3 });
      const afterClear = await websecurity.blockedShared('cfu-bind2', fresh,
                                                         'uid=svc2', 1);
      note(cleared === null && afterClear === null,
           'H4. under the limit a verified credential is answered and its ' +
           'buckets cleared (a limit of 1 no longer blocks)',
           JSON.stringify([cleared, afterClear]));
      const oauthSource = fs.readFileSync(ROOT + '/oauth-oidc/oauth2.js',
                                          'utf8');
      const counted = (oauthSource.match(/await countSecretFailure\(/g) ||
                       []).length;
      note(counted === 7 && (oauthSource.match(
             /const overLimit = await countSecretFailure\(/g) || []).length ===
           counted &&
           (oauthSource.match(/await settleSecretSuccess\(/g) || []).length ===
           3,
           'H5. every client-secret failure at the token, PAR and ' +
           'introspection endpoints is answered on its count, and every ' +
           'success is settled before it is answered');
    } catch (e) {
      note(false, 'the child threw', (e && e.stack) || e);
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-cfu-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    CFU_OUT: out, CFU_ROOT: ROOT, LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  delete env.STS_REQUEST_WORKER;
  const program = 'const path = require("path");\n' +
                  'const os = require("os");\n(' + childMain.toString() +
                  ')()';
  const result = childProcess.spawnSync(process.execPath, ['-e', program], {
    cwd: ROOT, env: env, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-3000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_followups',
  describe: 'issue #46 follow-ups: realm keys off the event loop, a late ' +
            'heartbeat named, active-active needs a public base URL, a ' +
            'minted write asks for a flush, create claims at the console ' +
            'and SCIM Bulk, WebAuthn registration and GNAP decision claims, ' +
            'and rate-limited answers decided on the atomic count',
  run: run
};
