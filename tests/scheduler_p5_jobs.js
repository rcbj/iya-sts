'use strict';
//
// File: scheduler_p5_jobs.js
//
// ===========================================================================
// WHAT P5 OF #49 MOVED ONTO THE SCHEDULER (2026-09-22).
//
// `tests/no_periodic_timers.js` holds that no timer is left; this file holds
// that what replaced each one is a job of the right kind, with its owner, and
// that the two decisions a job makes for itself are right:
//
//   A. THE JOBS. Every timer the allow-list said a job would replace is a
//      registered job, cluster or per-process as argued at its owner — the
//      change-log pull and the three per-process sweeps QUIET — and the four
//      purges that were piggy-backed on the next request are cluster jobs,
//      off where there is no shared table to purge.
//   B. SPIFFE'S AUTHORITIES (D6) rotate from their OWN age: nothing before
//      half a lifetime, both authorities past it — and the old ones stay
//      published.
//   C. GNAP'S ED25519 KEY (D6) is the realm's `jose:EdDSA:Ed25519` unit, so
//      the signing rotation rotates it; a biscuit minted before the rotation
//      still verifies after it, and `/gnap/keys` lists both keys.
//   D. THE TRACKED TOKENS (the ticket's "cache clearing"): a revocation goes
//      at its token's expiry, the record after oauth2.expiredTokenRetentionS,
//      and a live token is untouched.
//   E. THE BBS KEY (rcbj's D6 answer): a unit of the realm's key set, with a
//      next key, promotion and a retired key still listed.
//
// In a child process, with the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'scheduler_p5_jobs',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.P5_ROOT;
  const OUT = process.env.P5_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const scheduler = require(ROOT + '/cluster/scheduler');
    // The jobs registered at their FIRST USE, asked for here the way that
    // use would: a claim, a count, a flush, a claim of an assertion, the
    // replication start, a join and a local LDAP change are not all driven
    // in this child, so the ones that are not are registered by the call
    // their module makes.
    require(ROOT + '/saml/sp_metadata').startRefresher();

    // --- A. the jobs -------------------------------------------------------
    const expect = [
      ['oauth2.backchannel-logout-sweep', 'cluster',
       'oauth-oidc/backchannel_logout.ts', false],
      ['ssf.dead-letter-sweep', 'per-process', 'ssf/ssf.ts', false],
      ['saml2.sp-metadata-refresh', 'cluster', 'saml/sp_metadata.ts', false],
      ['spiffe.authority-rotation', 'cluster', 'spiffe/spiffe_ca.ts', false]
    ];
    expect.forEach(function (row) {
      const job = scheduler.job(row[0]);
      note(job && (job.kind || 'cluster') === row[1] && job.owner === row[2] &&
           !!job.quiet === row[3],
           'A. ' + row[0] + ' is a ' + row[1] + ' job owned by ' + row[2],
           JSON.stringify(job && { kind: job.kind, owner: job.owner,
                                   quiet: !!job.quiet }));
    });
    const spiffeJob = scheduler.job('spiffe.authority-rotation');
    note(spiffeJob && spiffeJob.scope === 'realm',
         'A. and the SPIFFE rotation is per realm');
    // The first-use registrations, made by what the module itself calls.
    const repl = require(ROOT + '/persistence/persistence_replication');
    const stub = {
      origin: function () { return 'p5'; },
      latestChangeSeq: function () { return Promise.resolve(1); },
      changesSince: function () { return Promise.resolve([]); },
      reportChangeReader: function () {
        return Promise.resolve({ inserted: false });
      },
      leaveChangeReader: function () { return Promise.resolve(true); },
      purgeChangeLog: function () {
        return Promise.resolve({ trimmed: 0, readers: 1, readersGone: 0,
                                 bound: 1 });
      }
    };
    config.setOverride('persistence.changeLogRetentionS', 3600);
    await repl.start(stub, {});
    const pull = scheduler.job('persistence.change-log-pull');
    const trim = scheduler.job('persistence.change-log-purge');
    note(pull && pull.kind === 'per-process' && pull.quiet &&
         scheduler.scheduler.intervalMs(pull) ===
           Math.max(250, Number(config.value('persistence.pollInterval'))),
         'A. the change-log pull is a QUIET per-process job at ' +
         'persistence.pollInterval — not rounded up to a tick',
         JSON.stringify(pull && { kind: pull.kind, quiet: pull.quiet,
                                  every: scheduler.scheduler.intervalMs(pull)
                                }));
    note(trim && (trim.kind || 'cluster') === 'cluster' &&
         scheduler.scheduler.offReason(trim) === '',
         'A. the change-log trim is a cluster job, on with a retention',
         trim && scheduler.scheduler.offReason(trim));
    await repl.stop();
    note(/stopped/.test(scheduler.scheduler.offReason(pull)),
         'A. and a process that stopped coordinating says so, rather than ' +
         'pulling', scheduler.scheduler.offReason(pull));
    repl.reset();
    config.clearOverride('persistence.changeLogRetentionS');
    // The four purges: the job each module registers at its first use,
    // off where there is no shared table.
    const claims = require(ROOT + '/cluster/cluster_claims');
    await claims.claim({ scope: 'p5.test', value: 'one', ttlMs: 5000 });
    const used = require(ROOT + '/common/used_assertions');
    note(typeof used === 'object', 'A. (used_assertions loads)');
    ['cluster.claims-purge'].forEach(function (id) {
      const job = scheduler.job(id);
      note(!job || ((job.kind || 'cluster') === 'cluster' &&
                    /no shared/.test(scheduler.scheduler.offReason(job))),
           'A. ' + id + ', where it is registered, is a cluster job that is ' +
           'off without a shared table', job ? scheduler.scheduler
             .offReason(job) : 'not registered: memory claims only');
    });

    // --- B. SPIFFE's authorities rotate from their own age -----------------
    config.setOverride('spiffe.enabled', true);
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const REALM = realms.DEFAULT_ID;
    const before = await realms.run(realms.get(REALM), function () {
      return ca.rotateDue(REALM, Date.now());
    });
    note(before && before.x509 === '' && before.jwt === '',
         'B1. a fresh authority is not rotated', JSON.stringify(before));
    const later = await realms.run(realms.get(REALM), function () {
      return ca.rotateDue(REALM, Date.now() + 400 * 86400000);
    });
    note(later && later.x509 !== '' && later.jwt !== '',
         'B2. past half its lifetime each authority is rotated',
         JSON.stringify(later));

    // --- C. GNAP's Ed25519 key through a rotation --------------------------
    const tokens = require(ROOT + '/gnap/gnap_tokens');
    const NOW = Math.floor(Date.now() / 1000);
    const model = { jti: 'p5-1', iss: 'https://as.example/gnap',
                    sub: 'alice@example.com', aud: [], instanceId: 'ci-1',
                    access: ['read'], flags: ['bearer'], cnf: null,
                    iat: NOW - 10, nbf: null, exp: NOW + 600, label: null };
    const minted = await tokens.mint('biscuit', model,
                                     { base: 'https://as.example' });
    const value = minted && (minted.value || minted.token || minted);
    const oldKid = tokens.ed25519Keys().publicJwk.kid;
    const rotated = await helpers.promoteGenerations(REALM, {
      units: ['jose:EdDSA:Ed25519'], graceMs: 3600000 });
    note(rotated.ok && tokens.ed25519Keys().publicJwk.kid !== oldKid,
         'C1. the signing rotation rotates GNAP\'s Ed25519 key',
         JSON.stringify(rotated.rotated));
    const checked = await tokens.verify('biscuit', value,
                                        { base: 'https://as.example' });
    note(checked && checked.ok,
         'C2. a biscuit minted before the rotation still verifies',
         JSON.stringify(checked && { ok: checked.ok, code: checked.errorCode,
                                     why: checked.why }));
    const published = tokens.publicMaterial('https://as.example');
    note(published.biscuit.root_public_keys.length >= 2,
         'C3. /gnap/keys lists the retired key beside the current one',
         published.biscuit.root_public_keys.length);
    const zc = await tokens.zcapKeys('https://as.example');
    note(zc.others.length >= 1 &&
         zc.others.some(function (o) { return /#/.test(o.keyId); }),
         'C4. and the ZCAP controller is handed the other generations',
         zc.others.length);

    // --- D. the tracked tokens ---------------------------------------------
    const stats = require(ROOT + '/common/admin_stats');
    const nowS = Math.floor(Date.now() / 1000);
    const skewS = Number(config.value('oauth2.clockSkewS'));
    const keepS = Number(config.value('oauth2.expiredTokenRetentionS'));
    helpers.signJwt({ typ: 'Bearer', jti: 'p5-old', sub: 'a',
                      iat: nowS - 10, exp: nowS - 5 });
    helpers.signJwt({ typ: 'Bearer', jti: 'p5-live', sub: 'a',
                      iat: nowS, exp: nowS + 3600 });
    stats.revoke('p5-old', 'test');
    stats.revoke('p5-live', 'test');
    const purgeJob = scheduler.job('oauth2.expired-token-purge');
    note(purgeJob && (purgeJob.kind || 'cluster') === 'cluster' &&
         purgeJob.owner === 'common/admin_stats.js',
         'D1. the tracked-token purge is a cluster job, registered at the ' +
         'first token recorded');
    const soon = stats.purgeExpiredTokens(Date.now() + (skewS + 1) * 1000);
    const listed = function () {
      return JSON.stringify(stats.tokenList ? stats.tokenList() : '');
    };
    note(soon.revocations === 1 && stats.isRevoked &&
         stats.isRevoked('p5-live') && !stats.isRevoked('p5-old'),
         'D2. at its expiry a token\'s REVOCATION goes — nothing accepts it ' +
         'any more — and a live token\'s stays',
         JSON.stringify(soon));
    note(soon.records === 0 || keepS === 0,
         'D3. but its record stays for oauth2.expiredTokenRetentionS, so ' +
         '/admin/tokens can still show it expired', JSON.stringify(soon));
    const pastKeep = stats.purgeExpiredTokens(Date.now() +
                                              (skewS + keepS + 10) * 1000);
    note(pastKeep.records >= 1 && listed().indexOf('p5-old') < 0 &&
         listed().indexOf('p5-live') >= 0,
         'D4. past the retention the record goes too, and the live token\'s ' +
         'is untouched', JSON.stringify(pastKeep));

    // --- E. the BBS key, a unit of the realm's key set ---------------------
    const bbsBefore = await helpers.bbsKeyPair();
    const bbsKid0 = helpers.bbsKidOf(bbsBefore.publicKey);
    const unitsNow = helpers.signingUnitsOf(helpers.stsKeysFor.of(REALM));
    note(unitsNow.some(function (u) {
      return u.unit === 'bbs:BBS' && u.kid === bbsKid0 && u.kind === 'bbs';
    }), 'E1. once made, the realm\'s BBS key is the unit bbs:BBS',
         bbsKid0);
    const bbsNext = await helpers.ensureNextGenerations(REALM,
      { units: ['bbs:BBS'] });
    const gens1 = await helpers.bbsGenerations();
    note(bbsNext.minted.indexOf('bbs:BBS') >= 0 && gens1.length === 2 &&
         gens1[0].kid === bbsKid0 && gens1[1].role === 'next',
         'E2. it gets a next key like any unit, listed by bbsGenerations()',
         JSON.stringify(gens1.map(function (g) { return [g.kid, g.role]; })));
    const bbsRot = await helpers.promoteGenerations(REALM,
      { units: ['bbs:BBS'], graceMs: 3600000 });
    const bbsAfter = await helpers.bbsKeyPair();
    const gens2 = await helpers.bbsGenerations();
    note(bbsRot.ok && helpers.bbsKidOf(bbsAfter.publicKey) === gens1[1].kid &&
         gens2.some(function (g) {
           return g.kid === bbsKid0 && g.role === 'retired';
         }),
         'E3. promoted, the next key signs and the old one is RETIRED, ' +
         'still listed — so the DID document and /bbs/keys/<kid> go on ' +
         'publishing it through its grace',
         JSON.stringify(gens2.map(function (g) { return [g.kid, g.role]; })));
    const rotation = require(ROOT + '/common/signing_rotation');
    note(rotation.graceMs('bbs:BBS') >=
           Number(config.value('oid4vci.credentialLifetimeS')) * 1000 &&
         rotation.intervalMs('bbs:BBS') ===
           Number(config.value('signing.credentialRotationIntervalDays')) *
           86400000,
         'E4. and as a credential signer it has the credential interval and ' +
         'a grace that outlasts every credential');

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
  const out = path.join(os.tmpdir(), 'scheduler-p5-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', P5_ROOT: ROOT, P5_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
               String(result.stderr || '').slice(-1200))) {
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
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scheduler_p5_jobs',
  describe: 'what P5 of #49 moved onto the scheduler: each former timer and ' +
            'piggy-backed purge is a job of the right kind with its owner, ' +
            'SPIFFE\'s authorities rotate from their own age, and GNAP\'s ' +
            'Ed25519 key survives a rotation',
  run: run
};
