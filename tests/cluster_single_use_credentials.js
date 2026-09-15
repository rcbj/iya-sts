'use strict';
//
// File: cluster_single_use_credentials.js
//
// ===========================================================================
// SECOND FACTORS, LINKS, ENROLLMENT CREDENTIALS AND THE BOOTSTRAP, SPENT ONCE
// ACROSS SEVERAL NODES (2026-09-14, #46 sections 2 and 8).
//
// Every value below was spent by reading a directory entry (or a replicated
// map) and writing it back. On one node that is atomic; across nodes it is two
// nodes both accepting inside the change log's window. The claims:
//
//   1. a counter that may only go up refuses the same value twice and a lower
//      one after a higher one, accepts an always-zero counter, and FAILS
//      CLOSED on a store that cannot be asked;
//   2. a TOTP step verified concurrently twice is accepted once, and an entry
//      whose `lastCounter` a stale write took BACKWARDS does not reopen it;
//   3. a recovery code spent concurrently twice is accepted once; a code a
//      stale write-back RESURRECTED on the entry is still refused and the
//      entry is repaired; a spend and the reconcile write back every code
//      another node spent;
//   4. a security-key assertion's challenge is answered once, its signature
//      counter never goes backwards, an always-zero counter is accepted, and
//      a refused counter gives the challenge back;
//   5. an activation link and a password reset link are spent once, and a
//      released claim can be taken again;
//   6. an EAB key binds one of two concurrent accounts, a SCEP challenge is
//      redeemed once, an ACME nonce claimed by another node is refused;
//   7. two nodes cold-starting against one store run the bootstrap ONCE, the
//      loser runs nothing, and a store that cannot be asked runs nothing.
//
// WHY IN PROCESS, and what stands in for "two nodes". Every one of these is a
// decision in one module against the store's answers. `persistence.
// clusterStore()` is replaced by a stub with postgres's semantics — one
// atomic table of claims and one of counters, each answer delivered on a later
// turn of the event loop so that two calls genuinely interleave — and a second
// node is either a second concurrent call against that shared table or a
// stale copy of the entry written back, which is exactly what the change log
// delivers. The SQL itself is `persistence_postgres.js`'s and is exercised by
// a real postgres in the two-node run `cluster/CLAUDE.md` records.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const credentials = require('../common/credentials');
const totp = require('../common/totp');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const persistence = require('../persistence/persistence');
const claims = require('../cluster/cluster_claims');
const counters = require('../cluster/cluster_counters');
// REQUIRED FOR ITS SIDE EFFECT: it fills `credentials.setDirectory()` and
// `cert_enrollment.setDirectory()`.
const ldap = require('../ldap/ldap_server');
const core = require('../common/cert_enrollment');
const acmeStore = require('../acme/acme_store');

const log = require('bunyan').createLogger({
  name: 'cluster_single_use_credentials',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

// ---------------------------------------------------------------------------
// THE SHARED STORE: postgres's semantics, in memory, answering on a later
// tick. `failing` makes every call reject, which is a database that is gone.
// ---------------------------------------------------------------------------
function sharedStore() {
  log.debug("Entering sharedStore().");
  const table = new Map();
  const countersTable = new Map();
  const later = function (fn) {
    log.debug("Entering later().");
    log.debug("Leaving later().");
    return new Promise(function (resolve, reject) {
      setImmediate(function () {
        if (store.failing) {
          reject(new Error('connection refused'));
          return;
        }
        try {
          resolve(fn());
        } catch (e) {
          reject(e);
        }
      });
    });
  };
  const store = {
    failing: false,
    claimOnce: function (scope, realm, key, opts) {
      log.debug("Entering claimOnce().");
      log.debug("Leaving claimOnce().");
      return later(function () {
        const k = scope + ' ' + realm + ' ' + key;
        const row = table.get(k);
        if (row && row.expiresAt > Date.now()) {
          return { claimed: false, existing: { origin: 'node-b',
                                               claimedAt: row.claimedAt,
                                               expiresAt: row.expiresAt } };
        }
        table.set(k, { reservation: opts.reservation, claimedAt: Date.now(),
                       expiresAt: Date.now() + opts.ttlMs });
        return { claimed: true };
      });
    },
    releaseClaim: function (scope, realm, key, reservation) {
      log.debug("Entering releaseClaim().");
      log.debug("Leaving releaseClaim().");
      return later(function () {
        const k = scope + ' ' + realm + ' ' + key;
        const row = table.get(k);
        if (row && row.reservation === reservation) {
          table.delete(k);
          return true;
        }
        return false;
      });
    },
    claimHeld: function (scope, realm, key) {
      log.debug("Entering claimHeld().");
      log.debug("Leaving claimHeld().");
      return later(function () {
        const row = table.get(scope + ' ' + realm + ' ' + key);
        return !!row && row.expiresAt > Date.now();
      });
    },
    purgeClaims: function () {
      log.debug("Entering purgeClaims().");
      log.debug("Leaving purgeClaims().");
      return Promise.resolve(0);
    },
    advanceCounter: function (scope, realm, key, value) {
      log.debug("Entering advanceCounter().");
      log.debug("Leaving advanceCounter().");
      return later(function () {
        const k = scope + ' ' + realm + ' ' + key;
        if (!countersTable.has(k) || countersTable.get(k) < value) {
          countersTable.set(k, value);
          return { advanced: true, highest: value };
        }
        return { advanced: false, highest: countersTable.get(k) };
      });
    }
  };
  log.debug("Leaving sharedStore().");
  return store;
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

function person(label) {
  log.debug("Entering person().");
  const name = 'cluster-' + label + '-' + RUN;
  ldap.createUser(name, { invent: false, attributes: {} });
  log.debug("Leaving person().");
  return name;
}

function storedAttributes(name) {
  log.debug("Entering storedAttributes().");
  const located = ldap.existingUserEntry(name);
  const stored = located && (located.stored || located);
  log.debug("Leaving storedAttributes().");
  return stored ? stored.attributes : null;
}

function snapshot(name, attribute) {
  log.debug("Entering snapshot().");
  const attrs = storedAttributes(name) || {};
  log.debug("Leaving snapshot().");
  return JSON.parse(JSON.stringify(attrs[attribute] || null));
}

// A stale copy of one attribute written back — what a replicated row from a
// node that had not seen this node's write does to the entry.
function writeBack(name, attribute, value) {
  log.debug("Entering writeBack().");
  const attrs = storedAttributes(name);
  if (attrs) {
    attrs[attribute] = value;
  }
  log.debug("Leaving writeBack().");
}

function enrolAuthenticator(name) {
  log.debug("Entering enrolAuthenticator().");
  const begun = credentials.beginTotpEnrolment(name,
                                               { base: 'https://localhost' });
  const done = credentials.confirmTotpEnrolment(name,
    totp.codeAt(begun.secret, Date.now(), begun));
  log.debug("Leaving enrolAuthenticator().");
  return done.ok ? begun : null;
}

async function checkCounters(t, store) {
  log.debug("Entering checkCounters().");
  t.log.info('=== 1. a counter that may only go up ===');
  const key = 'credential-' + RUN;
  const scope = 'test.counter';
  const both = await Promise.all([
    counters.advance({ scope: scope, key: key, value: 5 }),
    counters.advance({ scope: scope, key: key, value: 5 })
  ]);
  t.equal(both.filter(function (one) { return one.ok; }).length, 1,
          'TWO NODES ADVANCING ONE COUNTER TO THE SAME VALUE: exactly one ' +
          'is accepted');
  const lower = await counters.advance({ scope: scope, key: key, value: 3 });
  t.check(!lower.ok && lower.reason === 'behind' && lower.highest === 5,
          'a lower value after a higher one is refused and the highest is ' +
          'reported', JSON.stringify(lower));
  const higher = await counters.advance({ scope: scope, key: key, value: 6 });
  t.check(higher.ok && higher.advanced, 'a higher value advances it');
  const zeroA = await counters.advance({ scope: scope, key: key + '-z',
                                         value: 0 });
  const zeroB = await counters.advance({ scope: scope, key: key + '-z',
                                         value: 0 });
  t.check(zeroA.ok && zeroB.ok && !zeroB.advanced,
          'A COUNTER THAT IS ALWAYS ZERO is accepted every time (WebAuthn ' +
          'Level 3 section 6.1.1) — it is simply not a defence');
  const backToZero = await counters.advance({ scope: scope, key: key,
                                              value: 0 });
  t.check(!backToZero.ok && backToZero.reason === 'behind',
          'but zero after a real value is a counter that went backwards');
  store.failing = true;
  const gone = await counters.advance({ scope: scope, key: key, value: 99 });
  store.failing = false;
  t.check(!gone.ok && gone.reason === 'store',
          'A STORE THAT CANNOT BE ASKED is reason "store", which every ' +
          'caller refuses on');
  log.debug("Leaving checkCounters().");
}

async function checkTotp(t) {
  log.debug("Entering checkTotp().");
  t.log.info('=== 2. a TOTP step, once across nodes ===');
  const name = person('totp');
  const begun = enrolAuthenticator(name);
  t.check(!!begun, 'an authenticator app is enrolled');
  // The step AFTER the confirmation's, which the confirmation did not spend.
  const code = totp.codeAt(begun.secret, Date.now() + 30000, begun);
  const stale = snapshot(name, 'ststotpcredential');
  const both = await Promise.all([
    credentials.verifyTotpAsync(name, code),
    credentials.verifyTotpAsync(name, code)
  ]);
  const accepted = both.filter(function (one) { return one.ok; });
  const refused = both.filter(function (one) { return !one.ok; });
  t.equal(accepted.length, 1,
          'ONE CODE PRESENTED AT TWO NODES AT ONCE IS ACCEPTED ONCE — both ' +
          'passed the entry check, and the store decided');
  t.check(refused.length === 1 && refused[0].reason === 'replay' &&
          codeOf(refused[0]) === 'STS-AUTHN-0106',
          'and the other is refused as a replay, under the replay code',
          JSON.stringify(refused[0]) + ' ' + codeOf(refused[0]));
  // The entry's lastCounter written BACKWARDS by a node that had not seen the
  // spend.
  writeBack(name, 'ststotpcredential', stale);
  const again = await credentials.verifyTotpAsync(name, code);
  t.check(!again.ok && again.reason === 'replay',
          'AN ENTRY WHOSE COUNTER A STALE WRITE TOOK BACKWARDS DOES NOT ' +
          'REOPEN THE STEP: the entry check passes and the store refuses',
          JSON.stringify(again));
  log.debug("Leaving checkTotp().");
}

async function checkRecoveryCodes(t) {
  log.debug("Entering checkRecoveryCodes().");
  t.log.info('=== 3. recovery codes, once across nodes, and never ' +
             'resurrected ===');
  const name = person('recovery');
  enrolAuthenticator(name);
  const begun = credentials.beginBackupCodes(name, { count: 5 });
  t.check(begun.ok && credentials.confirmBackupCodes(name, begun.handle).ok,
          'a set of five codes is issued');
  const codes = begun.codes;
  const both = await Promise.all([
    credentials.verifyBackupCodeAsync(name, codes[0]),
    credentials.verifyBackupCodeAsync(name, codes[0])
  ]);
  t.equal(both.filter(function (one) { return one.ok; }).length, 1,
          'ONE CODE PRESENTED AT TWO NODES AT ONCE IS ACCEPTED ONCE');
  t.check(both.some(function (one) {
    return !one.ok && one.reason === 'spent';
  }), 'and the other is refused as spent');

  // Two nodes spending two DIFFERENT codes: node B's write-back does not know
  // about node A's spend.
  const beforeA = snapshot(name, 'stsbackupcodes');
  const spentOnA = await credentials.verifyBackupCodeAsync(name, codes[1]);
  t.check(spentOnA.ok, 'node A spends code 1');
  writeBack(name, 'stsbackupcodes', beforeA);
  t.equal(credentials.backupCodeStatus(name).remaining, 4,
          'the stale write-back RESURRECTED code 1 on the entry — the ' +
          'defect, reproduced');
  const replayed = await credentials.verifyBackupCodeAsync(name, codes[1]);
  t.check(!replayed.ok && replayed.reason === 'spent' &&
          codeOf(replayed) === 'STS-AUTHN-0091',
          'THE RESURRECTED CODE IS STILL REFUSED: its claim says spent',
          JSON.stringify(replayed));
  t.equal(credentials.backupCodeStatus(name).remaining, 3,
          'and the refusal REPAIRED the entry: code 1 is spent on it again');

  const beforeC = snapshot(name, 'stsbackupcodes');
  t.check((await credentials.verifyBackupCodeAsync(name, codes[2])).ok,
          'node A spends code 2');
  writeBack(name, 'stsbackupcodes', beforeC);
  const onB = await credentials.verifyBackupCodeAsync(name, codes[3]);
  t.check(onB.ok && onB.remaining === 1,
          'A SPEND ON NODE B WRITES BACK THE CODE NODE A SPENT: code 3 and ' +
          'the claimed code 2 are both spent by the one write',
          JSON.stringify(onB));

  const beforeD = snapshot(name, 'stsbackupcodes');
  const lastOne = await credentials.verifyBackupCodeAsync(name, codes[4]);
  t.check(lastOne.ok, 'node A spends the last code');
  writeBack(name, 'stsbackupcodes', beforeD);
  const held = credentials.backupCodeStatus(name);
  const repaired = await credentials.reconcileBackupCodes(name,
    realms.current(), undefined);
  t.check(held.remaining === 1 && repaired.repaired === 1 &&
          credentials.backupCodeStatus(name).remaining === 0,
          'THE RECONCILE a spend schedules writes a claimed-but-unmarked ' +
          'code as spent when nobody presents it',
          JSON.stringify([held.remaining, repaired]));
  log.debug("Leaving checkRecoveryCodes().");
}

async function checkAssertions(t) {
  log.debug("Entering checkAssertions().");
  t.log.info('=== 4. a security-key assertion: the challenge once, the ' +
             'counter only up ===');
  const name = person('webauthn');
  const credentialId = 'cred-' + RUN;
  const spend = function (challenge, signCount) {
    log.debug("Entering spend().");
    log.debug("Leaving spend().");
    return credentials.spendAssertion({ username: name,
      credentialId: credentialId, signCount: signCount,
      challenge: challenge, ttlMs: 300000 });
  };
  const both = await Promise.all([spend('challenge-1', 11),
                                  spend('challenge-1', 11)]);
  const refused = both.filter(function (one) { return !one.ok; })[0];
  t.check(both.filter(function (one) { return one.ok; }).length === 1 &&
          refused && codeOf(refused) === 'STS-AUTHN-0181',
          'ONE ASSERTION POSTED TO TWO NODES SIGNS IN ONCE: the challenge is ' +
          'answered once', JSON.stringify(refused));
  const backwards = await spend('challenge-2', 10);
  t.check(!backwards.ok && backwards.reason === 'counter' &&
          codeOf(backwards) === 'STS-AUTHN-0035',
          'A COUNTER BELOW THE HIGHEST ANY NODE RECORDED IS REFUSED — a ' +
          'cloned authenticator is detected even when the entry says 10',
          JSON.stringify(backwards));
  const retried = await spend('challenge-2', 12);
  t.check(retried.ok,
          'and the refusal GAVE THE CHALLENGE BACK: the same step with a ' +
          'counter that did go up is accepted');
  const race = await Promise.all([spend('challenge-3', 20),
                                  spend('challenge-4', 19)]);
  t.check(race[0].ok && !race[1].ok,
          'two different assertions racing at two nodes cannot leave the ' +
          'counter behind the higher one');
  const zeroId = credentialId + '-passkey';
  const zeroA = await credentials.spendAssertion({ username: name,
    credentialId: zeroId, signCount: 0, challenge: 'z-1', ttlMs: 300000 });
  const zeroB = await credentials.spendAssertion({ username: name,
    credentialId: zeroId, signCount: 0, challenge: 'z-2', ttlMs: 300000 });
  t.check(zeroA.ok && zeroB.ok,
          'a synced passkey whose counter is always 0 signs in every time');
  log.debug("Leaving checkAssertions().");
}

async function checkLinks(t) {
  log.debug("Entering checkLinks().");
  t.log.info('=== 5. activation and password reset links, once ===');
  const name = person('links');
  const link = credentials.issueActivation(name);
  t.check(link.ok, 'an activation link is issued');
  const both = await Promise.all([
    credentials.spendActivation(name, link.token),
    credentials.spendActivation(name, link.token)
  ]);
  const winner = both.filter(function (one) { return one.ok; })[0];
  const loser = both.filter(function (one) { return !one.ok; })[0];
  t.check(!!winner && !!loser && codeOf(loser) === 'STS-AUTHN-0183',
          'ONE LINK POSTED TO TWO NODES AT ONCE: one request may set a ' +
          'password, the other is refused', JSON.stringify(loser));
  await credentials.releaseLink(winner.handle);
  t.check((await credentials.spendActivation(name, link.token)).ok,
          'a request that did not finish gives the claim back, so the link ' +
          'works again as it did on one node');
  const reset = credentials.issuePasswordReset(name);
  t.check(reset.ok, 'a password reset link is issued');
  const resets = await Promise.all([
    credentials.spendPasswordReset(name, reset.token),
    credentials.spendPasswordReset(name, reset.token)
  ]);
  t.equal(resets.filter(function (one) { return one.ok; }).length, 1,
          'and a reset link posted twice at once is spent once');
  log.debug("Leaving checkLinks().");
}

async function checkEnrollment(t) {
  log.debug("Entering checkEnrollment().");
  t.log.info('=== 6. EAB keys, SCEP challenges and ACME nonces ===');
  const name = person('enroll');
  const entry = { kind: 'person', id: name };
  const eab = core.createEab({ target: entry, createdBy: 'test' });
  t.check(eab.ok, 'an EAB key is created');
  const binds = await Promise.all([
    core.bindEabOnce(eab.kid, 'thumb-a-' + RUN),
    core.bindEabOnce(eab.kid, 'thumb-b-' + RUN)
  ]);
  const bindRefused = binds.filter(function (one) { return !one.ok; })[0];
  t.check(binds.filter(function (one) { return one.ok; }).length === 1 &&
          codeOf(bindRefused) === 'STS-ENROLL-0081',
          'TWO ACCOUNTS AT TWO NODES WITH ONE EAB KEY: one is bound, the ' +
          'other refused as a second account', JSON.stringify(bindRefused));
  const challenge = core.createScepChallenge({ target: entry,
                                               profile: 'email',
                                               createdBy: 'test' });
  t.check(challenge.ok, 'a SCEP challenge is created');
  const redeemed = await Promise.all([
    core.redeemScepChallengeOnce(challenge.challenge),
    core.redeemScepChallengeOnce(challenge.challenge)
  ]);
  const redeemRefused = redeemed.filter(function (one) { return !one.ok; })[0];
  t.check(redeemed.filter(function (one) { return one.ok; }).length === 1 &&
          codeOf(redeemRefused) === 'STS-ENROLL-0084',
          'ONE CHALLENGE IN TWO PKCSReqs AT TWO NODES: redeemed once',
          JSON.stringify(redeemRefused));
  const nonce = 'nonce-' + RUN;
  const expiresS = Math.floor(Date.now() / 1000) + 600;
  // Node B spent it; this node's own map has never seen it.
  t.check((await claims.claim({ scope: 'acme.nonce', value: nonce,
                                ttlMs: 600000 })).ok,
          'node B claims a Replay-Nonce');
  const here = await acmeStore.spendNonceOnce(nonce, expiresS);
  t.check(!here.ok && here.reason === 'used',
          'A NONCE ANOTHER NODE SPENT IS REFUSED HERE, though this node\'s ' +
          'replicated map had not heard of it');
  const fresh = await acmeStore.spendNonceOnce(nonce + '-2', expiresS);
  t.check(fresh.ok, 'and a fresh nonce is accepted');
  log.debug("Leaving checkEnrollment().");
}

async function checkBootstrap(t, store) {
  log.debug("Entering checkBootstrap().");
  t.log.info('=== 7. one bootstrap for the cluster ===');
  const generated = [];
  const work = function () {
    log.debug("Entering work().");
    generated.push(nodeCrypto.randomBytes(8).toString('hex'));
    log.debug("Leaving work().");
    return { ran: true };
  };
  const realmId = 'boot-' + RUN;
  const cold = await Promise.all([
    credentials.bootstrapOnce(realmId, work),
    credentials.bootstrapOnce(realmId, work)
  ]);
  t.equal(generated.length, 1,
          'TWO NODES COLD-STARTED AGAINST ONE STORE GENERATE ONE PASSWORD');
  t.check(cold.some(function (one) { return one && one.lost; }),
          'and the node that lost is told so, and ran nothing',
          JSON.stringify(cold));
  const later = await credentials.bootstrapOnce(realmId, work);
  t.check(later.ran && generated.length === 2,
          'the winner gave the claim back once it had committed, so a node ' +
          'starting afterwards asks the question again (and its own ' +
          'bootstrap() finds the credential and does nothing)');
  store.failing = true;
  const blind = await credentials.bootstrapOnce(realmId + '-x', work);
  store.failing = false;
  t.check(!blind.ran && generated.length === 2,
          'A STORE THAT CANNOT BE ASKED RUNS NOTHING — no password a node ' +
          'cannot prove is the only one', JSON.stringify(blind));
  log.debug("Leaving checkBootstrap().");
}

async function run(t) {
  log.debug("Entering run().");
  const store = sharedStore();
  const real = persistence.clusterStore;
  persistence.clusterStore = function () {
    return store;
  };
  claims.reset();
  counters.reset();
  try {
    await checkCounters(t, store);
    await checkTotp(t);
    await checkRecoveryCodes(t);
    await checkAssertions(t);
    await checkLinks(t);
    await checkEnrollment(t);
    await checkBootstrap(t, store);
  } finally {
    persistence.clusterStore = real;
    claims.reset();
    counters.reset();
  }
  t.log.info('=== and on one process, with no shared store ===');
  const name = person('memory');
  const link = credentials.issueActivation(name);
  const alone = await Promise.all([
    credentials.spendActivation(name, link.token),
    credentials.spendActivation(name, link.token)
  ]);
  t.equal(alone.filter(function (one) { return one.ok; }).length, 1,
          'the memory claim is exactly as atomic as the map it stands in for');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_single_use_credentials',
  describe: 'issue #46: a TOTP step, a recovery code, a security-key ' +
            'assertion, activation and reset links, an EAB key, a SCEP ' +
            'challenge, an ACME nonce and the bootstrap password are each ' +
            'spent once across nodes, and a counter never goes backwards',
  run: run
};
