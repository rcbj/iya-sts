// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/paranoid_settings.js — EVERY `pki.paranoid*` ROW PROVES IT WORKS
// (#1360, rcbj's rule: a setting with no test is not finished).
//
// The table and `common/config.js` are read together, so a row cannot be added
// without a case. For each row: the default, `auto` per mode, the switch doing
// something observable through the door, the master winning, and the doors a
// setting arrives through (per realm here, the environment and an appconfig
// file in a child; `POST /admin-api/settings` is
// `tests/protocol/sts_paranoid_pki_settings.js`'s).
//
// A CERTIFICATE EVERY ROW REFUSES: an expired one, because validity is exempt
// nowhere except sigstore's rule, which asks a variant this file does not ask.
//
// AND NO PER-APPLICATION OVERRIDE (rcbj, 2026-11-06): the door's source is read
// for an `appPki*` or `fedPki*` attribute, or a member of a material that could
// carry an exemption.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * `inForce()` answering true for `auto` in development   — 48 red
//   * `applies()` ignoring the row                           — 71 red
//   * `applies()` ignoring the master                        — 92 red
//   * a row of the table naming a setting that does not exist — 7 red
//   * `announce()` logging every time                        — 1 red (F)
// ===========================================================================

// The child is the appconfig file's case, so it keeps what it was handed.
if (!process.env.STS_PARANOID_SETTINGS_CHILD) {
  delete process.env.CONFIG_FILE;
}

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../common/config');
const realms = require('../common/realms');
const trust = require('../common/certificate_trust');
const signers = require('../common/signer_truststore');
const defaults = require('../env/defaults');
const kit = require('./tools/trust_kit');

const log = require('bunyan').createLogger({ name: 'paranoid_settings_test',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_PARANOID_SETTINGS_CHILD';

if (process.env[CHILD]) {
  const answer = {
    master: config.value('pki.paranoid'),
    row: config.value('pki.paranoidJoseSigner'),
    inForce: trust.inForce().inForce,
    applies: trust.applies('jose-signer')
  };
  process.stdout.write('ANSWER ' + JSON.stringify(answer) + '\n');
  process.exit(0);
}

function spawn(env) {
  log.debug("Entering spawn().");
  const out = childProcess.spawnSync(process.execPath, [__filename], {
    env: Object.assign({}, process.env, { [CHILD]: '1', LOG_LEVEL: 'fatal' },
                       env), encoding: 'utf8', timeout: 120000 });
  const line = /ANSWER (.*)/.exec(out.stdout || '');
  log.debug("Leaving spawn().");
  return line ? JSON.parse(line[1]) : { failed: out.stderr };
}

// Nests: a setting put back is put back to what an outer call set.
const held = {};

async function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const before = Object.assign({}, held);
  Object.keys(pairs).forEach(function (key) {
    const out = config.setOverride(key, pairs[key]);
    if (!out.ok) {
      throw new Error('could not set ' + key + ': ' + out.errors.join(' '));
    }
    held[key] = pairs[key];
  });
  try {
    return await fn();
  } finally {
    Object.keys(pairs).forEach(function (key) {
      if (Object.prototype.hasOwnProperty.call(before, key)) {
        config.setOverride(key, before[key]);
        held[key] = before[key];
      } else {
        config.clearOverride(key);
        delete held[key];
      }
    });
    log.debug("Leaving withSettings().");
  }
}

// What the row governs: an expired certificate, accepted or refused because of
// validity. A purpose whose baseline refuses a stranger is asked with its own
// path, so the row is what moves.
function materialFor(purpose, expired) {
  log.debug("Entering materialFor().");
  log.debug("Leaving materialFor().");
  return { leaf: expired.pem, chain: [], pinned: true,
           registered: { chain: [] }, peer: undefined, purpose: purpose.id };
}

module.exports = {
  name: 'paranoid_settings',
  describe: 'every pki.paranoid* row: its default, its switch, the master ' +
            'winning, and the doors a setting arrives through',
  run: async function (t) {
    const settingKeys = config.SETTINGS.filter(function (one) {
      return /^pki\.paranoid/.test(one.key);
    });

    // A. THE TABLE AND THE ROWS ARE ONE LIST.
    t.log.info('A. the table against config.js');
    const named = trust.PURPOSES.map(function (one) {
      return one.setting;
    });
    t.equal(trust.PURPOSES.length, 23, 'A. twenty-three use cases');
    settingKeys.forEach(function (one) {
      t.check(one.key === 'pki.paranoid' || named.indexOf(one.key) !== -1,
              'A. ' + one.key + ' is a row the table names', '');
    });
    named.forEach(function (key) {
      t.check(settingKeys.some(function (one) {
        return one.key === key;
      }), 'A. ' + key + ' exists in config.js', '');
    });
    t.equal(settingKeys.length, 24, 'A. the master and one row per use case');
    const codes = trust.PURPOSES.map(function (one) {
      return one.code;
    });
    t.equal(new Set(codes).size, 23, 'A. each use case has its own code');

    // B. THE DEFAULTS, AND `auto` PER MODE.
    t.log.info('B. the defaults');
    t.equal(defaults.pki.paranoid, 'auto', 'B. env/defaults.js: auto');
    t.equal(config.value('pki.paranoid'), 'auto', 'B. config.value(): auto');
    trust.PURPOSES.forEach(function (one) {
      const row = settingKeys.filter(function (s) {
        return s.key === one.setting;
      })[0];
      t.equal(row && row.dflt, true, 'B. ' + one.setting + ' defaults on');
      t.equal(row && row.runtime, true, 'B. ' + one.setting + ' is runtime');
      t.equal(defaults.pki[one.setting.replace(/^pki\./, '')], true,
              'B. ' + one.setting + ' is in env/defaults.js');
      t.check(!!(row && row.env === 'STS_PKI_PARANOID_' + one.setting
        .replace(/^pki\.paranoid/, '')
        .replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()),
              'B. ' + one.setting + ' has its environment variable',
              row && row.env);
    });
    t.equal(trust.inForce().inForce, false, 'B. auto is off in development');
    await withSettings({ 'global.mode': 'product' }, async () => {
      t.equal(trust.inForce().inForce, true, 'B. auto is on in product');
      await withSettings({ 'pki.paranoid': 'off' }, async () => {
        t.equal(trust.inForce().inForce, false,
                'B. off overrides product');
      });
    });
    await withSettings({ 'pki.paranoid': 'on' }, async () => {
      t.equal(trust.inForce().inForce, true, 'B. on overrides development');
    });

    // C, D. THE SWITCH DOES SOMETHING, AND THE MASTER WINS.
    t.log.info('C. each row, through the door');
    const now = Date.now();
    const previous = signers.installedDirectory();
    signers.setDirectory(kit.signerStoreDouble());
    const expired = await kit.mint({ cn: 'expired fixture', ca: true,
      usages: ['digitalSignature', 'keyEncipherment', 'keyCertSign', 'cRLSign'],
      eku: ['clientAuth', 'serverAuth', 'ocspSigning'],
      notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
    try {
      for (const purpose of trust.PURPOSES) {
        const material = materialFor(purpose, expired);
        const opts = { anchors: [expired.pem] };
        if (purpose.id === 'anchor-admission') {
          opts.role = 'anchor';
        }
        const onOn = await withSettings({ 'pki.paranoid': 'on' }, function () {
          return trust.assess(purpose.id, material, opts);
        });
        t.check(!onOn.ok && onOn.inForce,
                'C. ' + purpose.id + ': master on, row on: refused', onOn.why);
        const onOff = await withSettings({ 'pki.paranoid': 'on',
                                           [purpose.setting]: false },
                                         function () {
          return trust.assess(purpose.id, material, opts);
        });
        t.check(!onOff.inForce,
                'C. ' + purpose.id + ': master on, row off: the baseline',
                JSON.stringify(onOff.checks));
        const offOn = await withSettings({ 'pki.paranoid': 'off' }, function () {
          return trust.assess(purpose.id, material, opts);
        });
        t.check(!offOn.inForce,
                'D. ' + purpose.id + ': master off wins whatever the row says',
                '');
        t.equal(JSON.stringify(offOn.checks), JSON.stringify(onOff.checks),
                'D. ' + purpose.id + ': both ways off are one baseline');
        const auto = await trust.assess(purpose.id, material, opts);
        t.check(!auto.inForce,
                'D. ' + purpose.id + ': auto in development is that baseline',
                '');
        t.equal(JSON.stringify(auto.checks), JSON.stringify(onOff.checks),
                'D. ' + purpose.id + ': and is the same answer');
      }
    } finally {
      if (previous) {
        signers.setDirectory(previous);
      }
    }

    // E. THE DOORS A SETTING ARRIVES THROUGH.
    t.log.info('E. per realm, the environment and an appconfig file');
    const stamp = Date.now();
    const realmA = 'par-a-' + stamp;
    const realmB = 'par-b-' + stamp;
    realms.create({ id: realmA, name: 'A', domain: realmA + '.example.net' });
    realms.create({ id: realmB, name: 'B', domain: realmB + '.example.net' });
    try {
      realms.run(realms.get(realmA), function () {
        config.setOverride('pki.paranoid', 'on');
        config.setOverride('pki.paranoidSamlSigner', false);
      });
      t.equal(trust.inForce(realmA).inForce, true, 'E. set in realm A');
      t.equal(trust.inForce(realmB).inForce, false, 'E. realm B unchanged');
      t.equal(trust.applies('saml-signer', realmA), false,
              'E. a row is per realm: off in A');
      t.equal(trust.applies('jose-signer', realmA), true,
              'E. and no other row moved');
      t.equal(trust.rowOn('saml-signer', realmB), true,
              'E. and it is still on in B');
    } finally {
      [realmA, realmB].forEach(function (id) {
        realms.remove(id);
      });
    }
    const fromEnv = spawn({ STS_PKI_PARANOID: 'on',
                            STS_PKI_PARANOID_JOSE_SIGNER: 'false' });
    t.check(fromEnv.master === 'on' && fromEnv.row === false &&
            fromEnv.inForce === true && fromEnv.applies === false,
            'E. through the environment', JSON.stringify(fromEnv));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-paranoid-'));
    try {
      const file = path.join(dir, 'appconfig.js');
      fs.writeFileSync(file, 'module.exports = { pki: { paranoid: "on", ' +
                             'paranoidJoseSigner: false } };\n');
      const fromFile = spawn({ CONFIG_FILE: file });
      t.check(fromFile.master === 'on' && fromFile.row === false,
              'E. through an appconfig file', JSON.stringify(fromFile));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }

    // F. OFF IN PRODUCT IS SAID ONCE, AND REFUSED BY NOTHING.
    t.log.info('F. the log line');
    await withSettings({ 'global.mode': 'product' }, async () => {
      const said = [];
      const warn = require('../common/helpers').log.warn;
      const log0 = require('../common/helpers').log;
      log0.warn = function (line) {
        said.push(String(line));
      };
      try {
        const wrote = config.setOverride('pki.paranoidCellPeer', false);
        t.check(wrote.ok, 'F. the write is not refused',
                (wrote.errors || []).join(' '));
        trust.applies('cell-peer');
        trust.applies('cell-peer');
      } finally {
        log0.warn = warn;
        config.clearOverride('pki.paranoidCellPeer');
      }
      const lines = said.filter(function (line) {
        return /STS-PKI-0239/.test(line) && /paranoidCellPeer/.test(line);
      });
      t.equal(lines.length, 1, 'F. said once, with its code');
      t.check(trust.announcedSettings().indexOf('pki.paranoidCellPeer') !== -1,
              'F. and recorded as said', '');
    });

    // G. THE TWO OTHER SETTINGS.
    t.log.info('G. the file and the horizon');
    t.equal(config.value('pki.pinnedCertificateWarningDays'), 30,
            'G. thirty days by default');
    const expiring = await kit.mint({ cn: 'expiring pin', notBefore: now -
      kit.DAY, notAfter: now + 10 * kit.DAY, usages: ['digitalSignature'] });
    trust.registerPinSource('paranoid_settings_test', function () {
      return [{ source: 'test', where: 'a test', purpose: 'saml-signer',
                pem: expiring.pem }];
    });
    const statusOf = async function () {
      log.debug("Entering statusOf().");
      const rows = await trust.pinnedCertificates('default');
      log.debug("Leaving statusOf().");
      return rows.filter(function (row) {
        return row.source === 'test';
      })[0].status;
    };
    try {
      t.equal(await statusOf(), 'expiring', 'G. inside the horizon');
      await withSettings({ 'pki.pinnedCertificateWarningDays': 5 }, async () => {
        t.equal(await statusOf(), 'self-signed',
                'G. moving the horizon moves the status');
      });
    } finally {
      trust.forgetPinSource('paranoid_settings_test');
    }
    const fileRow = config.SETTINGS.filter(function (one) {
      return one.key === 'pki.signerTrustAnchorsFile';
    })[0];
    t.check(fileRow && fileRow.perProcess === true && fileRow.runtime === false,
            'G. the file is the process\'s, read at start',
            JSON.stringify(fileRow && fileRow.runtime));

    // H. NO PER-APPLICATION OVERRIDE.
    t.log.info('H. no per-application override');
    const source = fs.readFileSync(path.join(__dirname, '..', 'common',
      'certificate_trust.' + (fs.existsSync(path.join(__dirname, '..',
        'common', 'certificate_trust.ts')) ? 'ts' : 'js')), 'utf8')
      .split('\n').filter(function (line) {
        return !/^\s*(\/\/|\*)/.test(line);
      }).join('\n');
    t.check(!/\b(appPki|fedPki|stsPki|appParanoid|fedParanoid)\w*/.test(source),
            'H. the door reads no attribute of an entry', '');
    t.check(!/material\.(exempt|skip|paranoid|override)/i.test(source) &&
            !/\bm\.(exempt|skip|paranoid|override)/i.test(source),
            'H. and no member of what it is handed can exempt a certificate',
            '');
  }
};
