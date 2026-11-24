// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: stored_override_order.js
//
// ===========================================================================
// THE PROCESS-WIDE OVERRIDES ANOTHER PROCESS WROTE ARE TAKEN AS WRITTEN,
// WHATEVER ORDER THEY ARRIVE IN (GitHub Actions run 45454368120).
//
// `tests/protocol/sts_openpgp_card_mail.js` failed in the mariadb mode only:
// gpg's Web Key Directory lookup answered "No data". The job defines a
// custom listener (`listeners.custom`) and then puts the Certificate
// authority application on it (`listeners.applications`), two writes the
// front process took one after the other, each judged beside the other's
// value. On MariaDB a request worker's one-second poll pulled both in one
// change, and `config.applyPersistedOverrides()` re-checked the stored set
// one key at a time with the rules between settings, in the store's order:
// the mapping first, against a listener list that did not yet hold the
// listener, so STS-CORE-0008 "which is not defined" in three workers, never
// asked again, and every WKD request those workers answered on the listener
// was refused STS-TLS-0047. Taking the two down in the other order refused
// `listeners.custom` the same way.
//
// The realm path has checked a stored value for what it IS since run #300
// (`config.checkStoredOverride()`); the process-wide path does too now.
//
//   1. the scenario is real: the mapping alone is refused by the rule
//      between settings while the listener is not defined;
//   2. the stored pair, mapping first, is applied whole;
//   3. the pair taken down, listener list first, is applied whole;
//   4. a stored value that is not a valid value of its row is still
//      refused, STS-CORE-0008's own case;
//   5. and a write made HERE is still judged beside its companions.
//
// In a CHILD PROCESS: it sets process-wide overrides, which every other test
// in the run shares.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'stored_override_order',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child, as `node -e` source: exempt from the Entering/Leaving
// rule (the root CLAUDE.md, *Code style*), and it reports what it caught on
// the findings it writes.
function child() {
  const ROOT = process.env.SOO_ROOT;
  const OUT = process.env.SOO_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const config = require(ROOT + '/common/config');
    require(ROOT + '/common/listener_map');
    const CUSTOM = JSON.stringify([{ id: 'soolistener', port: 18443,
      publicBaseUrl: 'https://openpgpkey.soo.example.net',
      hostnames: ['openpgpkey.soo.example.net'] }]);
    const APPS = JSON.stringify({ pki: { listeners: ['main', 'soolistener'],
                                         advertised: 'main' } });

    const alone = config.checkOverride('listeners.applications', APPS);
    note(!!alone && /not defined/.test(String(alone)),
         '1. the mapping alone is refused by the rule between settings ' +
         'while its listener is not defined', alone);

    // The order the store answered on MariaDB: the mapping first.
    const up = config.applyPersistedOverrides({
      'listeners.applications': APPS, 'listeners.custom': CUSTOM });
    note(up.indexOf('listeners.applications') >= 0 &&
         up.indexOf('listeners.custom') >= 0 &&
         config.value('listeners.applications') === APPS &&
         config.value('listeners.custom') === CUSTOM,
         '2. a stored listener and the mapping onto it, mapping first, are ' +
         'both applied', JSON.stringify(up));

    // Taken down as the job does, with an empty value each, in the order
    // that refused the listener list. Both put in force through the door
    // first, so the step does not lean on step 2.
    const set = [config.setOverride('listeners.custom', CUSTOM),
                 config.setOverride('listeners.applications', APPS)];
    note(set[0].ok && set[1].ok, '3a. the listener and the mapping are ' +
         'set through the door, in the order it accepts',
         JSON.stringify(set.map(function (one) { return one.errors; })));
    const down = config.applyPersistedOverrides({
      'listeners.custom': '', 'listeners.applications': '' });
    note(down.indexOf('listeners.custom') >= 0 &&
         down.indexOf('listeners.applications') >= 0 &&
         config.value('listeners.custom') === '' &&
         config.value('listeners.applications') === '',
         '3b. both taken down, the listener list first, are both applied',
         JSON.stringify(down));

    const typed = config.applyPersistedOverrides({
      'krb5.clockSkew': 'not a number' });
    note(typed.indexOf('krb5.clockSkew') < 0 &&
         config.sourceOf('krb5.clockSkew') !== 'override',
         '4. a stored value its row refuses is still not applied ' +
         '(STS-CORE-0008)', JSON.stringify(typed));

    const here = config.setOverride('listeners.applications', APPS);
    note(here && here.ok === false,
         '5. a write made here is still judged beside its companions',
         JSON.stringify(here && (here.errors || here.ok)));
  } catch (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'stored-override-order-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', SOO_ROOT: ROOT,
                                  SOO_OUT: out }),
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
  name: 'stored_override_order',
  describe: 'Process-wide overrides another process wrote are applied as ' +
            'written whatever order the store answers them in — no rule ' +
            'between settings is asked again of a stored set — while a ' +
            'value its row refuses still is (run 45454368120)',
  run: run
};
