// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: secret_rotation.js
//
// ===========================================================================
// THE SHARED SECRETS THAT ROTATE, AND THE ONES THAT DO NOT (#2220 D).
//
//   A. THE STEPS of a shared secret's rotation, as `nextStep()` decides them:
//      a bare value from an earlier release is DATED and not changed; a due
//      one publishes a NEXT value; that is promoted only after its lead,
//      the old value kept as PREVIOUS; and the previous value is dropped
//      once its overlap ends.
//   B. THE WHOLE ROTATION over a store double: a value stored by an earlier
//      release is read as it was; `text()` stays the current value while
//      `texts()` adds the next and the previous; the pairwise and bootstrap
//      name secrets are identifiers and never change; the bootstrap name
//      secret is seeded from the CSRF value the store held; an operator's
//      environment value is not rotated.
//   C. A VERIFIER ACCEPTS THE PREVIOUS KEY: a CSRF token made under the
//      previous key still verifies, one under any other key does not.
//   D. THE DATABASE POOL dials new connections with a new connection string.
//   E. THE MANAGEMENT API SECRET rotates while pinned, regeneration is still
//      refused, and a changed `adminApi.clientSecret` is adopted once.
//   F. AUTOMATIC CLIENT SECRET ROTATION: a listed application whose secret
//      expires within the lead is rotated, keeping the old secret; one whose
//      push fails is not.
//   G. THE DKIM SELECTOR SWITCH: the next selector signs only once its
//      moment has passed AND DNS answers with its key.
//   H. THE PREVIOUS CELL KEY with no location is refused (STS-CELL-0212).
//
// In a child process: the shared secrets, the settings and the applications
// are module-wide, and nothing set here may outlive this file.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'secret_rotation',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: drives each piece and reports what it found.
 *
 * @returns {Promise<void>}
 */
async function childMain() {
  const ROOT_DIR = process.env.SR_ROOT;
  const OUT = process.env.SR_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const clusterSecrets = require(ROOT_DIR + '/cluster/cluster_secrets');
    const ClusterSecrets = clusterSecrets.ClusterSecrets;
    const DAY = 86400000;

    // --- A ---------------------------------------------------------------
    let counter = 0;
    const fresh = function () {
      counter += 1;
      return 'fresh-' + counter;
    };
    const t0 = Date.UTC(2026, 0, 1);
    const bare = ClusterSecrets.envelopeOf('BARE-VALUE');
    note(bare.v === 1 && bare.current === 'BARE-VALUE' && !bare.rotatedAt,
         'A1. a bare stored value reads as the current value, undated');
    let step = ClusterSecrets.nextStep(bare, t0, 90 * DAY, DAY, fresh);
    note(step.step === 'dated' && step.envelope.current === 'BARE-VALUE' &&
         step.envelope.rotatedAt === t0,
         'A2. NO MASS ROTATION: its first sight only dates it', step.step);
    let env = step.envelope;
    step = ClusterSecrets.nextStep(env, t0 + 89 * DAY, 90 * DAY, DAY, fresh);
    note(step.step === '', 'A3. nothing is due inside the interval',
         step.step);
    step = ClusterSecrets.nextStep(env, t0 + 90 * DAY, 90 * DAY, DAY, fresh);
    env = step.envelope;
    note(step.step === 'next-published' && env.current === 'BARE-VALUE' &&
         env.next === 'fresh-1',
         'A4. a due rotation PUBLISHES a next value and keeps the current one');
    step = ClusterSecrets.nextStep(env, t0 + 90 * DAY + 60000, 90 * DAY, DAY,
                                   fresh);
    note(step.step === '', 'A5. the next value is not made current before ' +
         'its lead', step.step);
    const promotedAt = t0 + 90 * DAY + 11 * 60000;
    step = ClusterSecrets.nextStep(env, promotedAt, 90 * DAY, DAY, fresh);
    env = step.envelope;
    note(step.step === 'promoted' && env.current === 'fresh-1' &&
         env.previous === 'BARE-VALUE' && env.previousUntil ===
         promotedAt + DAY && !env.next,
         'A6. after the lead it is PROMOTED and the old value kept as ' +
         'previous until the overlap ends', JSON.stringify(env));
    step = ClusterSecrets.nextStep(env, promotedAt + DAY, 90 * DAY, DAY,
                                   fresh);
    note(step.step === 'previous-dropped' && !step.envelope.previous,
         'A7. the previous value is dropped when its overlap ends');
    step = ClusterSecrets.nextStep(env, promotedAt + 400 * DAY, 0, DAY,
                                   fresh);
    note(step.step === 'previous-dropped',
         'A8. with the rotation off, only the overlap still ends');
    note(ClusterSecrets.DECLARED['oidc-pairwise'].identifier === true &&
         ClusterSecrets.DECLARED['bootstrap-name'].identifier === true &&
         ClusterSecrets.DECLARED['bootstrap-name'].seedFrom === 'csrf' &&
         !ClusterSecrets.DECLARED.csrf.identifier,
         'A9. the pairwise and bootstrap name secrets are identifiers');

    // --- B ---------------------------------------------------------------
    const rows = new Map();
    // AS AN EARLIER RELEASE LEFT IT: bare values, sealed.
    rows.set('csrf', { material: 'S:LEGACY-CSRF' });
    rows.set('oidc-pairwise', { material: 'S:LEGACY-PAIRWISE' });
    const store = {
      ensureSharedSecret: async function (name, sealed) {
        if (!rows.has(name)) {
          rows.set(name, { material: sealed });
        }
        return rows.get(name);
      },
      readSharedSecret: async function (name) {
        return rows.get(name) || null;
      },
      replaceSharedSecret: async function (name, expected, sealed) {
        const row = rows.get(name);
        if (!row || row.material !== expected) {
          return { replaced: false };
        }
        rows.set(name, { material: sealed });
        return { replaced: true };
      }
    };
    const keystoreDouble = {
      sealed: function () { return true; },
      hasEphemeralKek: function () { return false; },
      seal: function (text) { return 'S:' + text; },
      open: function (material) {
        return String(material).indexOf('S:') === 0
          ? String(material).slice(2) : null;
      }
    };
    let clock = t0;
    const childEnv = { STS_ACME_NONCE_SECRET: 'OPERATOR-SET' };
    const audits = [];
    const instance = new ClusterSecrets({
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} },
      errorCodes: { tag: function (code) { return '[' + code + '] '; } },
      env: childEnv,
      randomBytes: nodeCrypto.randomBytes,
      clusterStore: function () { return store; },
      isActiveActive: function () { return false; },
      setting: function (key) {
        return key === 'cluster.secretRotationDays' ? 90 : 86400;
      },
      now: function () { return clock; },
      audit: function (row) { audits.push(row); }
    });
    instance.reset();
    await instance.start(keystoreDouble);
    note(instance.text('csrf') === 'LEGACY-CSRF' &&
         instance.text('oidc-pairwise') === 'LEGACY-PAIRWISE',
         'B1. a value an earlier release stored is read as it was');
    note(instance.text('bootstrap-name') === 'LEGACY-CSRF' &&
         rows.get('bootstrap-name').material === 'S:LEGACY-CSRF',
         'B2. the bootstrap name secret is seeded from the CSRF value the ' +
         'store held, so the generated name does not change');
    await instance.rotate();
    note(instance.text('csrf') === 'LEGACY-CSRF' &&
         /"rotatedAt"/.test(rows.get('csrf').material),
         'B3. the first run dates the stored value and does not change it');
    clock = t0 + 91 * DAY;
    await instance.rotate();
    const withNext = instance.texts('csrf');
    note(instance.text('csrf') === 'LEGACY-CSRF' && withNext.length === 2 &&
         withNext[0] === 'LEGACY-CSRF',
         'B4. a due rotation publishes a next value every verifier accepts, ' +
         'and MACs are still made under the current one',
         JSON.stringify(withNext.length));
    clock += 11 * 60000;
    await instance.rotate();
    const after = instance.texts('csrf');
    note(instance.text('csrf') !== 'LEGACY-CSRF' &&
         after.indexOf('LEGACY-CSRF') > 0,
         'B5. after the lead the new value is current and the old one is ' +
         'still accepted');
    note(instance.text('oidc-pairwise') === 'LEGACY-PAIRWISE' &&
         instance.text('bootstrap-name') === 'LEGACY-CSRF',
         'B6. the identifiers never rotate');
    note(instance.text('acme-nonce') === 'OPERATOR-SET' &&
         !rows.has('acme-nonce'),
         'B7. an operator\'s environment value is neither stored nor rotated');
    note(audits.some(function (row) {
      return row.action === 'cluster.secret-rotated' &&
             row.target === 'csrf' && JSON.stringify(row).indexOf(
               'LEGACY-CSRF') < 0;
    }), 'B8. a rotation is audited, without the value');
    note(childEnv.STS_CLUSTER_SECRETS_STORED &&
         childEnv.STS_CLUSTER_SECRETS_STORED.split(',').indexOf('csrf') >= 0 &&
         /LEGACY-CSRF/.test(String(childEnv.STS_CLUSTER_SECRET_STATE || '')),
         'B9. a request worker forked now inherits the previous value too');
    clock += DAY;
    await instance.rotate();
    note(instance.texts('csrf').indexOf('LEGACY-CSRF') < 0,
         'B10. and the old value stops being accepted when the overlap ends');

    // --- C ---------------------------------------------------------------
    const ws = require(ROOT_DIR + '/common/websecurity');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const current = Buffer.from('CURRENT-KEY');
    const previous = Buffer.from('PREVIOUS-KEY');
    const security = new ws.WebSecurity(Object.assign(
      ws.WebSecurity.defaultDeps(), {
        clusterSecrets: {
          get: function () { return current; },
          keys: function () { return [current, previous]; }
        }
      }));
    const field = ws.CSRF_FIELD;
    const under = function (key) {
      const body = {};
      body[field] = stsCrypto.hmac('sha256', key, 'session-1', 'base64url');
      return body;
    };
    note(security.checkCsrf('session-1', under(previous)).ok === true,
         'C1. a CSRF token made under the previous key still verifies');
    note(security.checkCsrf('session-1', under(current)).ok === true,
         'C2. as does one under the current key');
    note(security.checkCsrf('session-1',
                            under(Buffer.from('OTHER'))).ok === false,
         'C3. one under any other key is refused');

    // --- D ---------------------------------------------------------------
    const knexStore = require(ROOT_DIR + '/persistence/knex_store');
    const pool = knexStore.openPool({
      connectionString: 'postgres://sts:old-password@127.0.0.1:1/sts' });
    pool.setConnectionString('postgres://sts:new-password@127.0.0.1:1/sts');
    const settings = pool.knex.client.connectionSettings || {};
    note(/new-password/.test(String(settings.connectionString)) &&
         Number(settings.connectionTimeoutMillis) > 0,
         'D1. the pool dials every new connection with the new password',
         String(settings.connectionString).replace(/:[^:@]*@/, ':***@'));
    await pool.end();

    // --- H ---------------------------------------------------------------
    const secrets = require(ROOT_DIR + '/common/secrets');
    process.env.STS_PREVIOUS_CELL_KEK_PROVIDER = 'file';
    let refused = '';
    try {
      await secrets.readPreviousCellKek();
    } catch (e) {
      refused = String((e && e.message) || e);
    }
    delete process.env.STS_PREVIOUS_CELL_KEK_PROVIDER;
    note(/STS-CELL-0212/.test(refused),
         'H1. a previous cell key with no location is refused', refused);

    // --- G ---------------------------------------------------------------
    const mailTransports = require(ROOT_DIR + '/common/mail_transports');
    const pair = nodeCrypto.generateKeyPairSync('rsa',
                                                { modulusLength: 2048 });
    const nextPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const record = stsCrypto.dkimDnsRecord(nextPem);
    note(/^v=DKIM1; k=rsa; p=[A-Za-z0-9+/=]+$/.test(record.record),
         'G1. the record a selector publishes is built from its key');
    const ed = nodeCrypto.generateKeyPairSync('ed25519');
    const edRecord = stsCrypto.dkimDnsRecord(
      ed.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    note(/k=ed25519/.test(edRecord.record) &&
         Buffer.from(edRecord.p, 'base64').length === 32,
         'G2. an Ed25519 record carries the bare 32-byte key (RFC 8463)');
    let answer = [[record.record]];
    let now = Date.UTC(2026, 5, 1);
    const transports = new mailTransports.MailTransports(Object.assign(
      mailTransports.MailTransports.defaultDeps(), {
        readSecret: async function () { return nextPem; },
        resolveTxt: async function () { return answer; },
        now: function () { return now; }
      }));
    const cfg = { dkimDomain: 'example.com', dkimSelector: 'old',
                  dkimNextSelector: 'new', dkimAlgorithm: 'rsa-sha256',
                  dkimSwitchAt: '2026-05-01T00:00:00Z' };
    let chosen = await transports.dkimSigning(cfg, 'CURRENT-PEM');
    note(chosen.selector === 'new' && chosen.key === nextPem,
         'G3. after the switch, with the key published, the next selector ' +
         'signs');
    answer = [['v=DKIM1; k=rsa; p=AAAA']];
    chosen = await transports.dkimSigning(cfg, 'CURRENT-PEM');
    note(chosen.selector === 'old' && chosen.key === 'CURRENT-PEM',
         'G4. a record carrying another key keeps the current selector');
    answer = [[record.record]];
    now = Date.UTC(2026, 3, 1);
    chosen = await transports.dkimSigning(cfg, 'CURRENT-PEM');
    note(chosen.selector === 'old',
         'G5. before the switch moment the current selector signs');

    // --- E and F ---------------------------------------------------------
    const applications = require(ROOT_DIR + '/common/applications');
    require(ROOT_DIR + '/ldap/ldap_server');
    applications.seedInternalApplications({ scope: 'default' });
    process.env.ADMIN_API_CLIENT_SECRET = 'pinned-first-secret';
    const pinnedHeld = function () {
      return applications.clientSecretRecordsOf(
        applications.get('sts-api-client').fields).map(function (one) {
        return one.secret;
      });
    };
    applications.adoptPinnedSecret();
    note(pinnedHeld().indexOf('pinned-first-secret') >= 0,
         'E1. the pinned value is held by sts-api-client');
    const regenerated = applications.regenerateClientSecret('sts-api-client');
    note(!regenerated.ok &&
         /STS-REG-0061/.test(JSON.stringify(regenerated) + String(
           require(ROOT_DIR + '/common/error_codes').codeOf(regenerated))),
         'E2. a regeneration of the pinned secret is still refused');
    const rotated = applications.rotateClientSecret('sts-api-client');
    note(rotated.ok && pinnedHeld().indexOf('pinned-first-secret') >= 0 &&
         pinnedHeld().indexOf(rotated.clientSecret) >= 0 &&
         /adminApi\.clientSecret/.test(rotated.message),
         'E3. a ROTATION of the pinned secret is allowed: the new one is ' +
         'added, the pinned one kept, and the answer says to update the ' +
         'setting', rotated.message);
    process.env.ADMIN_API_CLIENT_SECRET = 'pinned-second-secret';
    const adopted = applications.adoptPinnedSecret();
    const again = applications.adoptPinnedSecret();
    note(adopted === true && again === false &&
         pinnedHeld()[0] === 'pinned-second-secret',
         'E4. a changed adminApi.clientSecret is adopted once, as the ' +
         'primary secret');

    const APP = 'sr-auto-rotate';
    const NOPUSH = 'sr-auto-nopush';
    [APP, NOPUSH].forEach(function (id) {
      applications.createApplication({
        identifier: id, name: id, protocols: ['oauth2'], lifetimeDays: 10,
        fields: { oauthClientSecret: id + '-original-secret' } });
    });
    process.env.STS_OAUTH2_CLIENT_SECRET_AUTO_ROTATE =
      APP + ',' + NOPUSH + '=no-such-destination/a-secret';
    const nowS = Math.floor(Date.now() / 1000);
    const done = await applications.autoRotateClientSecrets(nowS);
    const heldOf = function (id) {
      return applications.clientSecretRecordsOf(
        applications.get(id).fields).map(function (one) {
        return one.secret;
      });
    };
    note(done.rotated.indexOf(APP) >= 0 && heldOf(APP).length === 2 &&
         heldOf(APP).indexOf(APP + '-original-secret') > 0,
         'F1. a listed application whose secret expires within the lead is ' +
         'rotated, and its old secret kept for the overlap',
         JSON.stringify(done));
    note(done.failed.indexOf(NOPUSH) >= 0 && heldOf(NOPUSH).length === 1,
         'F2. one whose new secret cannot be pushed is not rotated at all');
    const later = await applications.autoRotateClientSecrets(nowS);
    note(later.rotated.indexOf(APP) < 0,
         'F3. a fresh secret is not rotated again');
    delete process.env.STS_OAUTH2_CLIENT_SECRET_AUTO_ROTATE;
    [APP, NOPUSH].forEach(function (id) {
      applications.deleteApplication(id);
    });
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sr-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$|ADMIN_API_)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  SR_ROOT: ROOT, SR_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'secret_rotation',
  describe: 'the shared secrets, the database password, the management API ' +
            'and client secrets, the DKIM key and the cell key rotate with ' +
            'an overlap, and the identifiers never do (#2220)',
  run: run
};
