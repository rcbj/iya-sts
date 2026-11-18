// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_removal_memory.js
//
// ===========================================================================
// A REMOVED REALM LEAVES NOTHING BEHIND IN THE TWO PROCESS-LOCAL MAPS THAT
// KEPT IT (2026-11-18, rcbj: "Identify memory leaks").
//
// Measured on a development node: 81 realms the suite had made were removed
// and the heap fell by 86 of the 206 MB they had added. A heap snapshot then
// found what still named them (common/CLAUDE.md, *Removing a realm takes its
// state with it*), and two of those were genuine — neither is a realm store,
// so `realms.remove()` never reached them:
//
//   A. `common/revocation_status.js`'s parse memo of this service's CA
//      certificates, keyed by PEM and bounded at 8192, which forgot nothing
//      until it was full: the realm's dozen authorities stayed parsed after
//      the realm had gone (664 X509Certificate objects before the removals
//      and 664 after);
//      1. a realm's authorities, once walked, are in the memo;
//      2. removing the realm takes them out, and leaves the default realm's;
//   B. `risk/risk_store.ts`'s in-memory history, keyed by realm where there
//      is no database:
//      1. an assessment recorded in a realm is held;
//      2. removing the realm forgets it (forgetRealm() then finds nothing).
//
// In a CHILD PROCESS: it builds a certificate authority and removes a realm,
// which are process-wide.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'realm_removal_memory',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child: everything above, written to RRM_OUT as findings.
function memoryChild() {
  const ROOT = process.env.RRM_ROOT;
  const OUT = process.env.RRM_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const pki = require(ROOT + '/common/pki');
    const revocation = require(ROOT + '/common/revocation_status');
    const cacheRegistry = require(ROOT + '/common/cache_registry');
    const riskStore = require(ROOT + '/risk/risk_store');
    const ID = 'rrm-a';
    function parsedNaming(text) {
      const d = cacheRegistry.detail('revocation.parsed-tiers');
      return ((d && d.rows) || []).filter(function (row) {
        return String(row.key).indexOf(text) >= 0;
      }).length;
    }
    await pki.ensureScope('');
    realms.create({ id: ID, name: ID });
    const built = await pki.ensureScope(ID);
    note(built && built.ok, '(the realm\'s authority branch was built)',
         JSON.stringify(built && built.errors));
    revocation.heldCertificates();
    const before = parsedNaming('(' + ID + ')');
    const defaults = parsedNaming('Root CA');
    note(before > 0 && defaults > 0,
         'A1. a realm\'s authorities, once walked, are in the parse memo',
         before + ' of the realm, ' + defaults + ' root');

    await riskStore.recordAssessment({ realm: ID, at: Date.now(),
                                       subject: 'urn:uuid:rrm', score: 1 },
                                     false);
    note(riskStore.forgetRealm('no-such-realm') === 0,
         '(forgetRealm() of a realm never held forgets nothing)');

    realms.remove(ID);
    note(parsedNaming('(' + ID + ')') === 0 &&
         parsedNaming('Root CA') === defaults,
         'A2. removing the realm takes its authorities out of the memo and ' +
         'leaves the rest', parsedNaming('(' + ID + ')') + ' left');
    note(riskStore.forgetRealm(ID) === 0,
         'B. removing the realm forgot its in-memory risk history');
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'realm-removal-memory-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/
          .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + memoryChild.toString() + ')()'],
    { env: Object.assign(clean, { LOG_LEVEL: 'fatal', RRM_ROOT: ROOT,
                                  RRM_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // No report: the child died before writing one, and its exit status
    // and stderr below say why.
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
               'findings', 'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_removal_memory',
  describe: 'A removed realm leaves nothing behind in the revocation ' +
            'register\'s parse memo of CA certificates or in the risk ' +
            'store\'s in-memory history (2026-11-18)',
  run: run
};
