'use strict';
//
// File: signing_rotation.js
//
// ===========================================================================
// SIGNING KEY ROTATION ON THE SCHEDULER (#42 P3, 2026-09-22).
//
// `tests/key_generations.js` holds the generations to their promises — a
// next key published, a promotion, a retirement. This file holds
// `common/signing_rotation.ts`, which decides WHEN, to its:
//
//   A. THE JOBS. `signing.rotate` and `signing.retire` are realm-scoped
//      cluster jobs, and rotation is OFF in development mode and at an
//      interval of 0, saying why.
//   B. THE SCHEDULE. A run gives every unit lacking one a next key and
//      rotates nothing; a run a whole interval after that promotes every
//      unit, and the refresh-token encryption keys with them (D7).
//   C. THE GRACE. A retired key verifies at least as long as the longest
//      thing it could have signed — a client's own longer refresh token
//      included — and the credential signer's for as long as a credential
//      lives (D3); `signing.retiredKeyGraceDays` only ever lengthens it.
//   D. THE CREDENTIAL SIGNER'S INTERVAL (D3): its own when no token setting
//      signs with its unit, the token interval when one does.
//   E. REFRESH TOKENS (D7). A refresh token sealed before the rotation still
//      opens after it, and a new one is sealed under the new keys; past the
//      grace the old one is refused.
//   F. RETIRE. Past the grace `retireDue()` drops every retired key and
//      supersedes its certificate on its Issuing CA's list.
//   G. THE RECORD. One audit row per act, and the Shared Signals notice (D4)
//      names the signing keys and never the refresh-token keys.
//
// In a child process, with the whole stack and a clock the test moves.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'signing_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.SR_ROOT;
  const OUT = process.env.SR_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const DAY = 86400000;

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const applications = require(ROOT + '/common/applications');
    const scheduler = require(ROOT + '/cluster/scheduler');
    const rotation = require(ROOT + '/common/signing_rotation');
    const rtCrypto = require(ROOT + '/oauth-oidc/refresh_token_crypto');
    const revocation = require(ROOT + '/common/pki_revocation');
    const pki = require(ROOT + '/common/pki');
    const events = require(ROOT + '/ssf/ssf_events');
    const REALM = realms.DEFAULT_ID;
    // The hierarchy, as `service_state.ts` builds it, so every key has a
    // certificate for a retirement to supersede.
    await require(ROOT + '/common/keystore').start();
    const started = await pki.start({ realmIds: [''],
      keySetFor: function (id) { return helpers.stsKeysFor.of(id); },
      keySetHeldFor: function () { return false; } });
    note(started.ok, 'the certificate hierarchy is built',
         JSON.stringify(started));
    const keysNow = function () {
      return helpers.stsKeysFor.of(REALM);
    };
    const nextOf = function (unit) {
      return helpers.standbyOf(keysNow(), unit).filter(function (one) {
        return one.role === 'next';
      })[0];
    };

    // --- A. the jobs -----------------------------------------------------------
    const rotate = scheduler.job('signing.rotate');
    const retire = scheduler.job('signing.retire');
    note(rotate && retire && rotate.scope === 'realm' &&
         retire.scope === 'realm' && rotate.kind === 'cluster' &&
         retire.kind === 'cluster' &&
         rotate.owner === 'common/signing_rotation.ts',
         'A1. signing.rotate and signing.retire are realm-scoped cluster jobs',
         JSON.stringify(rotate && { scope: rotate.scope, kind: rotate.kind }));
    note(/development mode/.test(scheduler.scheduler.offReason(rotate,
                                                               REALM)),
         'A2. rotation is OFF in development mode, and says why',
         scheduler.scheduler.offReason(rotate, REALM));
    const now = scheduler.job('signing.rotate-now');
    note(now && now.manualOnly && now.scope === 'realm' &&
         scheduler.scheduler.offReason(now, REALM) === '',
         'A2a. signing.rotate-now is manual only and ON in development mode, ' +
         'so a rotation can be asked for there',
         now && scheduler.scheduler.offReason(now, REALM));

    // A SigningRotation of the test's own: product mode, a clock it moves,
    // and a Shared Signals stand-in that records the notice.
    let clock = Date.now();
    const notices = [];
    const Cls = rotation.SigningRotation;
    const own = new Cls(Object.assign(Cls.defaultDeps(), {
      mode: function () {
        return { rotatesSigningKeys: function () { return true; } };
      },
      ssf: function () {
        return { signingKeyRotated: function (n) {
          notices.push(n);
          return Promise.resolve({ sent: 0 });
        } };
      },
      now: function () { return clock; }
    }));
    note(own.offReason() === '', 'A3. in product mode it is on');
    config.setOverride('signing.rotationIntervalDays', 0);
    note(/rotationIntervalDays is 0/.test(own.offReason()),
         'A4. and an interval of 0 switches it off', own.offReason());
    config.clearOverride('signing.rotationIntervalDays');

    // --- B. the schedule ---------------------------------------------------------
    const units = helpers.signingUnitsOf(keysNow()).map(function (u) {
      return u.unit;
    });
    const joseBefore = keysNow().kid;
    const first = await own.rotateDue(REALM);
    note(first.minted.length === units.length && first.rotated.length === 0,
         'B1. the first run gives every unit a next key and rotates nothing',
         JSON.stringify({ minted: first.minted.length, units: units.length,
                          rotated: first.rotated.length }));
    const second = await own.rotateDue(REALM);
    note(second.minted.length === 0 && second.rotated.length === 0,
         'B2. a second run in the same interval does nothing',
         JSON.stringify(second));
    const nextJose = nextOf('jose:RS256');
    const refreshBefore = helpers.refreshTokenKeysFor(keysNow()).secretKid;
    const nowS = Math.floor(Date.now() / 1000);
    const oldToken = rtCrypto.seal(helpers.signJwt({ sub: 'sr-alice',
      typ: 'Refresh', jti: 'sr-1', iat: nowS, exp: nowS + 3600 }));
    clock += own.intervalMs('jose:RS256') + 60000;
    const third = await own.rotateDue(REALM);
    const rotatedUnits = third.rotated.map(function (r) { return r.unit; });
    note(keysNow().kid === (nextJose && nextJose.kid) &&
         rotatedUnits.indexOf('jose:RS256') >= 0 &&
         rotatedUnits.indexOf('xml:RS256') >= 0,
         'B3. a whole interval later the next keys are promoted',
         JSON.stringify(rotatedUnits));
    note(rotatedUnits.indexOf('refresh:enc') >= 0 &&
         helpers.refreshTokenKeysFor(keysNow()).secretKid !== refreshBefore,
         'B4. and the refresh-token encryption keys rotate with them (D7)');
    note(keysNow().kid !== joseBefore, 'B5. the JOSE signer is a new key');

    // --- C. the grace ---------------------------------------------------------------
    const retiredJose = helpers.standbyOf(keysNow(), 'jose:RS256')
      .filter(function (one) { return one.kid === joseBefore; })[0];
    const refreshTtl = Number(config.value('oauth2.refreshTokenTtlS')) * 1000;
    note(retiredJose && retiredJose.role === 'retired' &&
         Number(retiredJose.retiredUntil) - Number(retiredJose.retiredAt) >=
           refreshTtl,
         'C1. the retired JOSE key verifies at least as long as a refresh ' +
         'token lives', JSON.stringify(retiredJose && {
           grace: retiredJose.retiredUntil - retiredJose.retiredAt,
           refreshTtl: refreshTtl }));
    const baseGrace = own.graceMs('jose:RS256');
    const CLIENT = 'sr-long-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthRefreshTokenTtlS: String(refreshTtl / 1000 * 10) } });
    const raised = own.graceMs('jose:RS256') >= refreshTtl * 10;
    note(raised === true,
         'C2. a client whose own refresh tokens live longer lengthens the ' +
         'grace', String(raised) + ' base=' + baseGrace);
    config.setOverride('signing.retiredKeyGraceDays', 3650);
    note(own.graceMs('jose:RS256') >= 3650 * DAY,
         'C3. signing.retiredKeyGraceDays lengthens it');
    config.clearOverride('signing.retiredKeyGraceDays');
    config.setOverride('oid4vci.credentialSigningAlgorithm', 'ES256K');
    const vcUnit = own.credentialUnit();
    // Ten years, far past every token lifetime, so the difference is the
    // credential's alone.
    config.setOverride('oid4vci.credentialLifetimeS', 315360000);
    const credLife = 315360000 * 1000;
    note(vcUnit === 'jose:ES256K:secp256k1' &&
         own.graceMs(vcUnit) >= credLife &&
         own.graceMs('jose:RS256') < credLife,
         'C4. the credential signer\'s grace outlasts every credential (D3), ' +
         'and no other unit\'s is stretched by it',
         vcUnit + ' ' + own.graceMs(vcUnit) + ' >= ' + credLife + ' > ' +
         own.graceMs('jose:RS256'));
    config.clearOverride('oid4vci.credentialLifetimeS');

    // --- D. the credential signer's interval --------------------------------------
    note(own.intervalMs(vcUnit) ===
           Number(config.value('signing.credentialRotationIntervalDays')) *
           DAY,
         'D1. a credential signer no token setting uses keeps its own, ' +
         'longer interval', own.intervalMs(vcUnit));
    config.setOverride('ssf.signingAlgorithm', 'ES256K');
    note(own.intervalMs(vcUnit) ===
           Number(config.value('signing.rotationIntervalDays')) * DAY,
         'D2. one a token setting signs with keeps the token interval',
         own.intervalMs(vcUnit));
    config.clearOverride('ssf.signingAlgorithm');
    config.clearOverride('oid4vci.credentialSigningAlgorithm');
    note(own.intervalMs('jose:RS256') ===
           Number(config.value('signing.rotationIntervalDays')) * DAY,
         'D3. and RS256, the default credential algorithm, is the token ' +
         'signer\'s interval');

    // --- E. refresh tokens ------------------------------------------------------------
    let opened = '';
    try {
      opened = rtCrypto.open(oldToken);
    } catch (e) {
      opened = '';
    }
    note(opened.split('.').length === 3,
         'E1. a refresh token sealed before the rotation still opens');
    const newToken = rtCrypto.seal(helpers.signJwt({ sub: 'sr-alice',
      typ: 'Refresh', jti: 'sr-2', iat: nowS, exp: nowS + 3600 }));
    const header = JSON.parse(Buffer.from(newToken.split('.')[0], 'base64url')
      .toString('utf8'));
    const cur = helpers.refreshTokenKeysFor(keysNow());
    note([cur.secretKid, cur.rsa.publicJwk.kid, cur.ec.publicJwk.kid]
      .indexOf(header.kid) >= 0,
         'E2. a new one is sealed under the new keys', header.kid);

    // --- F. retire --------------------------------------------------------------------
    const retiredXml = helpers.standbyOf(keysNow(), 'xml:RS256')
      .filter(function (one) { return one.role === 'retired'; })[0];
    const scope = String(keysNow().realm || REALM);
    const joseCert = pki.certificateFor(scope, 'jose', 'RS256', joseBefore);
    // The keys were retired on the real clock (`helpers.js` stamps them), so
    // the retirement is asked on it too.
    const early = own.retireDue(REALM, { nowMs: function () {
      return Date.now();
    } });
    note(early.dropped === 0, 'F1. inside the grace nothing is dropped',
         JSON.stringify(early));
    clock = Math.max(Number(retiredJose.retiredUntil),
                     Number(retiredXml && retiredXml.retiredUntil) || 0) + 1;
    const late = own.retireDue(REALM, { nowMs: function () { return clock; } });
    note(late.dropped >= 2 &&
         !helpers.standbyOf(keysNow(), 'jose:RS256').some(function (one) {
           return one.kid === joseBefore;
         }) &&
         !helpers.standbyOf(keysNow(), 'xml:RS256').some(function (one) {
           return retiredXml && one.kid === retiredXml.kid;
         }),
         'F2. past the grace every retired key is dropped',
         JSON.stringify(late));
    const listed = joseCert && revocation.listFor(scope, 'jose')
      .some(function (one) {
        return String(one.serialHex).replace(/^0+/, '').toLowerCase() ===
               String(joseCert.serialHex).replace(/^0+/, '').toLowerCase() &&
               one.reason === 'superseded';
      });
    note(listed && late.superseded >= 1,
         'F3. and its certificate is superseded on the Issuing CA\'s list',
         JSON.stringify({ cert: !!joseCert, superseded: late.superseded }));
    let refused = '';
    try {
      rtCrypto.open(oldToken);
      refused = 'it opened';
    } catch (e) {
      refused = String(e && e.message);
    }
    note(/rotated|not issued/.test(refused),
         'E3. past the grace the old refresh token is refused', refused);

    // --- G. the record -----------------------------------------------------------------
    const rows = audit.list();
    note(rows.some(function (r) { return r.action === 'keys.rotate'; }) &&
         rows.some(function (r) { return r.action === 'keys.retire'; }),
         'G1. one audit row for the rotation and one for the retirement');
    const n = notices[notices.length - 1] || {};
    note(n.realm === REALM && n.reason === 'scheduled' &&
         (n.rotated || []).length >= 2 &&
         !(n.rotated || []).some(function (r) {
           return r.unit === 'refresh:enc';
         }),
         'G2. the Shared Signals notice names the signing keys and never ' +
         'the refresh-token keys', JSON.stringify(n.rotated &&
                                                  n.rotated.map(function (r) {
                                                    return r.unit;
                                                  })));
    const row = events.EVENT_BY_URI[events.SIGNING_KEY_ROTATED];
    note(row && row.subject === 'none' && row.family === 'sts',
         'G3. the event is this service\'s own, with no subject');

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
  const out = path.join(os.tmpdir(), 'signing-rotation-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', SR_ROOT: ROOT, SR_OUT: out }),
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
  name: 'signing_rotation',
  describe: 'signing key rotation on the scheduler (#42 P3): the two jobs, ' +
            'off in development, the schedule, the grace (clients and ' +
            'credentials included), the credential signer\'s interval, the ' +
            'refresh-token keys, retirement with its certificates ' +
            'superseded, and the audit and Shared Signals record',
  run: run
};
