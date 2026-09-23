'use strict';
//
// File: cache_eject.js
//
// ===========================================================================
// EJECTING EXPIRED CACHE AND REPLAY-STORE ENTRIES (#49 P5, 2026-09-22).
//
// rcbj's directive of 2026-09-21: cache and store clean-up is periodic work,
// so it is a scheduler job. `caches.eject-expired` (a quiet per-process job,
// `admin-ui/caches_admin.ts`) calls `cacheRegistry.ejectExpired()`, which
// calls every store's own `eject()`. What this file holds:
//
//   A. THE REGISTRY. `ejectExpired()` calls each ejector once, sums what they
//      removed and counts it as evictions on the store's row; an ejector that
//      throws is reported and does not stop the others; `eject` must be a
//      function.
//   B. THE LIST. Exactly the stores whose entries expire carry an ejector —
//      twenty-five — and the two that do not, on purpose, are named.
//   C. THE JOB is registered, per-process and quiet.
//   D. AN EJECTOR DELETES WHAT ITS READER WOULD REFUSE AND NOTHING ELSE:
//      through two replay stores' own doors (ACME's spent nonces and GNAP's
//      signatures), an expired entry goes and a live one stays — so the
//      replay the live one stops is still stopped.
//
// In a child process, with the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'cache_eject',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.CE_ROOT;
  const OUT = process.env.CE_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const registry = require(ROOT + '/common/cache_registry');
    const scheduler = require(ROOT + '/cluster/scheduler');
    const realms = require(ROOT + '/common/realms');

    // --- A. the registry ---------------------------------------------------
    let calls = 0;
    registry.register({ name: 'test.eject-ok', title: 't', description: 't',
      owner: 'tests/cache_eject.js', scope: 'process',
      maxEntries: function () { return 1; },
      lifetime: function () { return 't'; },
      entries: function () { return []; },
      eject: function () { calls++; return 3; } });
    registry.register({ name: 'test.eject-throws', title: 't',
      description: 't', owner: 'tests/cache_eject.js', scope: 'process',
      maxEntries: function () { return 1; },
      lifetime: function () { return 't'; },
      entries: function () { return []; },
      eject: function () { throw new Error('broken'); } });
    const done = registry.ejectExpired(Date.now());
    const row = registry.report().filter(function (r) {
      return r.name === 'test.eject-ok';
    })[0];
    note(calls === 1 && done.byCache['test.eject-ok'] === 3 &&
         done.ejected >= 3,
         'A1. ejectExpired() calls each ejector once and sums what they ' +
         'removed', JSON.stringify(done.byCache));
    note(row && row.evictions === 3,
         'A2. and counts it as evictions on the store\'s row',
         JSON.stringify(row));
    note(done.failed.length === 1 && /test\.eject-throws/.test(done.failed[0]),
         'A3. a store that throws is reported, and the others still ran',
         JSON.stringify(done.failed));
    let refused = '';
    try {
      registry.register({ name: 'test.eject-bad', title: 't',
        description: 't', owner: 'tests/cache_eject.js', scope: 'process',
        maxEntries: function () { return 1; },
        lifetime: function () { return 't'; },
        entries: function () { return []; }, eject: 5 });
    } catch (e) {
      refused = e.message;
    }
    note(/eject as a function/.test(refused),
         'A4. an eject that is not a function is refused', refused);
    registry.forget('test.eject-ok');
    registry.forget('test.eject-throws');

    // --- B. the list -------------------------------------------------------
    // Loading what registers lazily, so every store is in the registry.
    require(ROOT + '/common/used_assertions');
    const expected = [
      'acme.nonces', 'dpop.nonces', 'dpop.proof-ids',
      'federation.release-index', 'gnap.signatures',
      'krb5.authenticator-replay', 'oauth2.redeemed-codes',
      'oauth2.client-jwks', 'oauth2.request-uri', 'oauth2.signed-metadata',
      'oauth2.used-assertions', 'oid4vci.nonces', 'oid4vci.status-entries',
      // OpenID Federation's resolved Trust Chains (#132).
      'oidfed.resolutions',
      'passwords.breach-ranges', 'passwords.breach-verdicts',
      'oid4vci.status-list-tokens', 'oid4vp.sign-in-register',
      'oid4vp.status-lists-fetched', 'oid4vp.transactions',
      'revocation.ca-certificates', 'revocation.crl', 'revocation.failures',
      'revocation.ocsp', 'risk.standings', 'scim.digest-nonce-counts',
      'scim.digest-nonces', 'scim.hoba-challenges', 'scim.hoba-signatures'
    ].sort();
    const ejecting = registry.ejecting().filter(function (n) {
      return !/^test\./.test(n);
    });
    note(JSON.stringify(ejecting) === JSON.stringify(expected),
         'B1. exactly the twenty-nine stores whose entries expire eject them',
         JSON.stringify({ missing: expected.filter(function (n) {
           return ejecting.indexOf(n) < 0;
         }), extra: ejecting.filter(function (n) {
           return expected.indexOf(n) < 0;
         }) }));
    note(ejecting.indexOf('oauth2.backchannelDeliveries') < 0 &&
         ejecting.indexOf('keys.plaintext') < 0,
         'B2. and the two that expire and must NOT be ejected here are not: ' +
         'a Logout Token delivery (its sweep dead-letters it first) and a ' +
         'decrypted key (its own deadline, to the second)');
    const all = registry.ejectExpired(Date.now() + 10 * 365 * 86400000);
    note(all.failed.length === 0,
         'B3. every real ejector runs without throwing, even ten years on',
         JSON.stringify(all.failed));

    // --- C. the job --------------------------------------------------------
    const job = scheduler.job('caches.eject-expired');
    note(job && job.kind === 'per-process' && job.quiet &&
         job.owner === 'admin-ui/caches_admin.ts',
         'C1. caches.eject-expired is a quiet per-process job',
         JSON.stringify(job && { kind: job.kind, quiet: job.quiet }));

    // --- D. what its reader would refuse, and nothing else -----------------
    const acme = require(ROOT + '/acme/acme_store');
    const nowS = Math.floor(Date.now() / 1000);
    await realms.run(realms.get(realms.DEFAULT_ID), async function () {
      acme.spendNonce('ce-expired', nowS - 5);
      acme.spendNonce('ce-live', nowS + 600);
      registry.ejectExpired(Date.now());
      note(acme.spendNonce('ce-live', nowS + 600) === false,
           'D1. a LIVE spent ACME nonce is kept: presenting it again is ' +
           'still the replay it was');
      note(acme.spendNonce('ce-expired', nowS + 600) === true,
           'D2. and an expired one is gone');
      const gnap = require(ROOT + '/gnap/gnap_store');
      gnap.rememberOutcome('ce-sig-expired', 1);
      gnap.rememberOutcome('ce-sig-live', 600);
      registry.ejectExpired(Date.now() + 5000);
      note(gnap.rememberOutcome('ce-sig-live', 600) === 'seen',
           'D3. a live GNAP signature is kept');
      note(gnap.rememberOutcome('ce-sig-expired', 600) === 'new',
           'D4. and one past its lifetime is gone');
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
  const out = path.join(os.tmpdir(), 'cache-eject-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', CE_ROOT: ROOT, CE_OUT: out }),
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
  name: 'cache_eject',
  describe: 'expired cache and replay-store entries ejected by a scheduler ' +
            'job (#49 P5): the registry calls every store\'s own eject(), ' +
            'exactly the stores that expire carry one, and an ejector ' +
            'removes what its reader would refuse and nothing live',
  run: run
};
