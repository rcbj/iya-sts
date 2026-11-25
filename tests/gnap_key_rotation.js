// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_key_rotation.js
//
// ===========================================================================
// GNAP'S TWO REALM-DERIVED KEYS ACROSS A SIGNING ROTATION (#2212).
//
// `gnap/gnap_tokens.ts` derives the macaroon root keys and the jwt-encrypted
// `dir` key by HKDF from the realm's refresh-token secret, which
// `signing.rotate` replaces. Until #2212 only the CURRENT secret was read, so
// every macaroon and every jwt-encrypted token issued before a rotation
// stopped verifying at it, and the root key written onto a resource server's
// entry was never brought up to date. This file holds:
//
//   A. a macaroon (for a resource server and for none) and a jwt-encrypted
//      token, minted and verified;
//   B. the realm rotated the way the `signing.rotate` job rotates it — its
//      own `rotateDue()`, product mode, a clock moved a whole interval — and
//      all three still verifying after it;
//   C. a token minted after the rotation under the NEW secret, and the
//      resource server's entry carrying the key it was minted under;
//   D. the retained secret's grace covering the longest GNAP access token;
//   E. a second rotation: both earlier generations verify inside their
//      grace, and once `signing.retire` drops the oldest its tokens are
//      refused while the newer ones still verify.
//
// In a child process, with the whole stack, as tests/signing_rotation.js.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'gnap_key_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.GKR_ROOT;
  const OUT = process.env.GKR_OUT;
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
    const applications = require(ROOT + '/common/applications');
    const rotation = require(ROOT + '/common/signing_rotation');
    const pki = require(ROOT + '/common/pki');
    const tokens = require(ROOT + '/gnap/gnap_tokens');
    const grants = require(ROOT + '/gnap/gnap_grants');
    const gnapRs = require(ROOT + '/gnap/gnap_rs');
    const REALM = realms.DEFAULT_ID;
    const BASE = 'https://as.gkr.test';
    await require(ROOT + '/common/keystore').start();
    const started = await pki.start({ realmIds: [''],
      keySetFor: function (id) { return helpers.stsKeysFor.of(id); },
      keySetHeldFor: function () { return false; } });
    note(started.ok, 'the certificate hierarchy is built',
         JSON.stringify(started));

    // The rotation the `signing.rotate` job runs, in product mode and on a
    // clock this test moves (tests/signing_rotation.js's arrangement).
    let clock = Date.now();
    const Cls = rotation.SigningRotation;
    const own = new Cls(Object.assign(Cls.defaultDeps(), {
      mode: function () {
        return { rotatesSigningKeys: function () { return true; } };
      },
      ssf: function () {
        return { signingKeyRotated: function () {
          return Promise.resolve({ sent: 0 });
        } };
      },
      now: function () { return clock; }
    }));
    const rotateOnce = async function () {
      clock += own.intervalMs('jose:RS256') + 60000;
      const done = await own.rotateDue(REALM);
      return done.rotated.map(function (r) { return r.unit; });
    };

    // A resource server, and its root key written onto its entry the way
    // `POST /gnap/resource` writes it.
    const RS = 'gkr-rs';
    applications.createApplication({ identifier: RS,
      kind: grants.KIND_RS, protocols: ['gnap'],
      fields: { gnapResourceServerUri: 'https://rs.gkr.test/api' } });
    const rsHelper = new gnapRs.GnapRs(gnapRs.GnapRs.defaultDeps());
    const storedKey = function () {
      return grants.field(applications.get(RS), 'macaroonKey');
    };
    rsHelper.ensureMacaroonKey(applications.get(RS));
    const storedAtRegistration = storedKey();
    note(storedAtRegistration ===
           tokens.macaroonKeyFor(RS).toString('base64url'),
         'A0. the resource server\'s entry carries its derived root key');

    const NOW = Math.floor(Date.now() / 1000);
    let n = 0;
    const model = function () {
      n += 1;
      return { jti: 'gkr-' + n, iss: BASE + '/gnap', sub: 'alice@gkr.test',
               aud: [], instanceId: 'gkr-ci', access: ['read'],
               flags: ['bearer'], cnf: null, iat: NOW - 10, nbf: null,
               exp: NOW + 600, label: null };
    };
    const mintSet = async function () {
      return {
        rsMac: (await tokens.mint('macaroon', model(),
                                  { base: BASE,
                                    rs: { identity: RS, jweKey: null } }))
          .value,
        asMac: (await tokens.mint('macaroon', model(), { base: BASE }))
          .value,
        jwe: (await tokens.mint('jwt-encrypted', model(), { base: BASE }))
          .value
      };
    };
    const verifySet = async function (set) {
      const out = {};
      out.rsMac = await tokens.verify('macaroon', set.rsMac,
                                      { base: BASE, rsIdentity: RS });
      out.asMac = await tokens.verify('macaroon', set.asMac, { base: BASE });
      out.jwe = await tokens.verify('jwt-encrypted', set.jwe,
                                    { base: BASE });
      return out;
    };
    const brief = function (v) {
      return JSON.stringify(Object.keys(v).map(function (k) {
        return k + ':' + (v[k] && v[k].ok ? 'ok'
          : (v[k] && v[k].errorCode) + ' ' + (v[k] && v[k].why));
      }));
    };
    const allOk = function (v) {
      return v.rsMac && v.rsMac.ok && v.asMac && v.asMac.ok &&
             v.jwe && v.jwe.ok;
    };

    // --- A. before any rotation --------------------------------------------
    const gen0 = await mintSet();
    const before = await verifySet(gen0);
    note(allOk(before), 'A1. a macaroon for a resource server, one for ' +
         'none and a jwt-encrypted token verify', brief(before));

    // --- B. one rotation, as the job runs it -------------------------------
    const secret0 = helpers.refreshTokenKeysFor().secretKid;
    const first = await own.rotateDue(REALM);
    note(first.rotated.length === 0, 'B0. the first run only mints next ' +
         'keys', JSON.stringify(first.rotated));
    const units1 = await rotateOnce();
    note(units1.indexOf('refresh:enc') >= 0 &&
         helpers.refreshTokenKeysFor().secretKid !== secret0,
         'B1. a whole interval later the realm secret GNAP derives from ' +
         'is rotated', JSON.stringify(units1));
    const after1 = await verifySet(gen0);
    note(after1.rsMac && after1.rsMac.ok,
         'B2. the resource server\'s macaroon minted before the rotation ' +
         'still verifies', brief(after1));
    note(after1.asMac && after1.asMac.ok,
         'B3. the macaroon with no resource server still verifies',
         brief(after1));
    note(after1.jwe && after1.jwe.ok,
         'B4. the jwt-encrypted token still decrypts and verifies',
         brief(after1));

    // --- C. new tokens, and the resource server's entry --------------------
    const newKey = tokens.macaroonKeyFor(RS).toString('base64url');
    note(newKey !== storedAtRegistration,
         'C1. the rotation changes the derived root key', newKey);
    const gen1 = await mintSet();
    const fresh = await verifySet(gen1);
    note(allOk(fresh), 'C2. tokens minted after the rotation verify',
         brief(fresh));
    note(storedKey() === newKey,
         'C3. once a macaroon is minted under the new key, the resource ' +
         'server\'s entry carries that key',
         'stored ' + storedKey() + ' derived ' + newKey);
    const macaroonLib = require(ROOT + '/gnap/token_macaroon');
    const underStored = await macaroonLib.verify(gen1.rsMac,
      { rootKey: Buffer.from(String(storedKey()), 'base64url') },
      { base: BASE });
    note(underStored && underStored.ok,
         'C4. and a resource server verifying with the key on its entry ' +
         'accepts the new macaroon', brief({ underStored: underStored }));
    const underOld = await macaroonLib.verify(gen1.rsMac,
      { rootKey: Buffer.from(storedAtRegistration, 'base64url') },
      { base: BASE });
    note(underOld && !underOld.ok && underOld.errorCode === 'STS-GNAP-0314',
         'C5. the new macaroon is minted under the NEW key, not the old one',
         brief({ underOld: underOld }));

    // --- D. the grace covers the longest GNAP access token -----------------
    config.setOverride('gnap.accessTokenLifetimeS', 30 * 86400);
    note(own.refreshGraceMs() >= 30 * 86400000,
         'D1. the retired secret is kept for at least the longest GNAP ' +
         'access-token lifetime', own.refreshGraceMs());
    config.clearOverride('gnap.accessTokenLifetimeS');

    // --- E. a second rotation, and the oldest aged out ---------------------
    // Apart on the real clock, which stamps retiredAt / retiredUntil.
    await new Promise(function (resolve) {
      setTimeout(resolve, 50);
    });
    const units2 = await rotateOnce();
    note(units2.indexOf('refresh:enc') >= 0,
         'E0. a second rotation rotates the secret again',
         JSON.stringify(units2));
    const both0 = await verifySet(gen0);
    const both1 = await verifySet(gen1);
    note(allOk(both0) && allOk(both1),
         'E1. after a second rotation both earlier generations verify ' +
         'inside their grace', brief(both0) + ' ' + brief(both1));
    const retired = (helpers.stsKeysFor.of(REALM).generations
      .retiredRefresh || []).slice().sort(function (a, b) {
      return Number(a.retiredAt) - Number(b.retiredAt);
    });
    const oldestUntil = Number(retired[0] && retired[0].retiredUntil);
    const newerUntil = Number(retired[1] && retired[1].retiredUntil);
    note(retired.length >= 2 && oldestUntil < newerUntil,
         'E2. two retired secrets, the oldest ageing out first',
         JSON.stringify(retired.map(function (r) {
           return [r.kid, r.retiredUntil];
         })));
    own.retireDue(REALM, { nowMs: function () {
      return oldestUntil + 1;
    } });
    const aged0 = await verifySet(gen0);
    const aged1 = await verifySet(gen1);
    note(aged0.rsMac && !aged0.rsMac.ok &&
         aged0.rsMac.errorCode === 'STS-GNAP-0314' &&
         aged0.asMac && !aged0.asMac.ok &&
         aged0.jwe && !aged0.jwe.ok &&
         aged0.jwe.errorCode === 'STS-GNAP-0341',
         'E3. once the oldest secret is dropped, its tokens are refused',
         brief(aged0));
    note(allOk(aged1), 'E4. while the tokens of the newer retired secret ' +
         'still verify', brief(aged1));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'gnap-key-rotation-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', GKR_ROOT: ROOT,
                           GKR_OUT: out }),
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
  name: 'gnap_key_rotation',
  describe: 'GNAP\'s realm-derived keys across a signing rotation (#2212): ' +
            'macaroon and jwt-encrypted tokens minted before a rotation ' +
            'still verify, new ones use the new secret, the resource ' +
            'server\'s entry is brought up to date, and a secret past its ' +
            'grace is no longer accepted',
  run: run
};
