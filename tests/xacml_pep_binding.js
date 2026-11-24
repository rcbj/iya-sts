// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: xacml_pep_binding.js
// ===========================================================================
// AN EMBEDDED REMOTE PEP, BOUND TO THE ONE APPLICATION IT IS EMBEDDED IN
// (#2025, part of #1206).
//
// In a child process with the whole stack, through the act layer the
// console and `/admin-api` share (`xacmlAdmin.combinedAction()`):
//
//   R. the refusals, each by its code, writing nothing: no name and nobody
//      (STS-XACML-0334), a person who is not a service account and a
//      service account outside the remote PEPs group (0335), no application
//      and one the registry does not hold (0336);
//   S. a binding set: on the entry, read back by the row (`pepsJson()`),
//      listed on the application's side (`boundTo()`), audited as
//      `xacml.pep.binding`; set again idempotently; replaced by another;
//   C. cleared, and cleared again with nothing to clear (idempotent);
//   D. an application deleted takes its bindings with it, with an audit row,
//      and leaves a binding to another application alone;
//   I. `issue-pep-credential` with an application: a refused binding
//      certifies nothing, a good one certifies and binds in one call;
//   W. the attribute cannot be written through the person editor's door.
//
// WHY IN A CHILD: the stack registers routes on the shared app and fills
// the directory's slots, which a test in `run.js`'s process must not do.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'xacml_pep_binding',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT_DIR = process.env.PB_ROOT;
  const OUT = process.env.PB_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const pki = require(ROOT_DIR + '/common/pki');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const audit = require(ROOT_DIR + '/common/audit');
    const applications = require(ROOT_DIR + '/common/applications');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const personAssertions = require(ROOT_DIR + '/common/person_assertions');
    const xacmlAdmin = require(ROOT_DIR + '/xacml/xacml_admin');
    const PepBinding = require(ROOT_DIR + '/xacml/xacml_pep_binding');
    const tool = require(ROOT_DIR + '/tests/tools/pep-credential.js');

    const stamp = Date.now().toString(36);
    const PEP = 'pb-pep-' + stamp;
    const OTHER = 'pb-other-' + stamp;
    const PLAIN = 'pb-person-' + stamp;
    const LONER = 'pb-loner-' + stamp;
    const OWNER = 'pb-owner-' + stamp;
    const APP = 'pb-app-' + stamp;
    const APP2 = 'pb-app2-' + stamp;
    const GROUP = String(config.value('roles.remotePepGroup') ||
                         'remote-peps');
    const binding = PepBinding.shared();
    const act = function (action, body) {
      return Promise.resolve(xacmlAdmin.combinedAction(
        Object.assign({ action: action }, body)));
    };
    const codeOf = function (result) {
      return String(errorCodes.codeOf(result) || '');
    };
    const audited = function (target) {
      return audit.list().filter(function (one) {
        return one.action === 'xacml.pep.binding' && one.target === target;
      });
    };

    // The cast: two PEPs (service accounts in the group), a plain person, a
    // service account outside the group, and two applications.
    ldap.createUser(OWNER, { invent: false });
    [PEP, OTHER].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      ldap.addGroupMember(GROUP, name);
      if (!serviceAccounts.of(name)) {
        serviceAccounts.set(name, { serviceAccount: true, owners: [OWNER] });
      }
    });
    ldap.createUser(PLAIN, { invent: false });
    ldap.createUser(LONER, { invent: false });
    serviceAccounts.set(LONER, { serviceAccount: true, owners: [OWNER] });
    [APP, APP2].forEach(function (identifier) {
      const made = applications.createApplication({ identifier: identifier,
        name: identifier, protocols: ['oauth2'] });
      note(made && made.ok !== false,
           'the application ' + identifier + ' exists to be bound to',
           JSON.stringify(made && (made.errors || made.ok)));
    });
    note(!!serviceAccounts.of(PEP) && !!serviceAccounts.of(OTHER),
         'the two PEPs are service accounts');

    // R. THE REFUSALS.
    const refusals = [
      ['R1. no name', {}, 'STS-XACML-0334'],
      ['R2. nobody by that name', { name: 'pb-nobody-' + stamp,
                                    application: APP }, 'STS-XACML-0334'],
      ['R3. a person who is not a service account', { name: PLAIN,
                                    application: APP }, 'STS-XACML-0335'],
      ['R4. a service account outside ' + GROUP, { name: LONER,
                                    application: APP }, 'STS-XACML-0335'],
      ['R5. no application', { name: PEP }, 'STS-XACML-0336'],
      ['R6. an application the registry does not hold',
       { name: PEP, application: 'pb-no-app-' + stamp }, 'STS-XACML-0336']
    ];
    for (const [what, body, code] of refusals) {
      const got = await act('set-pep-application', body);
      note(!got.ok && codeOf(got) === code,
           what + ' is refused (' + code + ')',
           codeOf(got) + ' ' + got.why);
    }
    note(binding.of(PEP) === '' && binding.of(PLAIN) === '' &&
         binding.of(LONER) === '', 'R7. no refusal wrote a binding');

    // S. A BINDING SET.
    const set = await act('set-pep-application',
                          { name: PEP, application: APP });
    note(set.ok && set.application === APP && set.previous === '',
         'S1. a binding is set', JSON.stringify(set));
    note(binding.of(PEP) === APP, 'S2. the entry carries it',
         binding.of(PEP));
    note(JSON.stringify(binding.boundTo(APP)) === JSON.stringify([PEP]),
         'S3. the application lists the PEP bound to it',
         JSON.stringify(binding.boundTo(APP)));
    note(audited(PEP).length === 1, 'S4. the binding is audited once',
         audited(PEP).length);
    const again = await act('set-pep-application',
                            { pep: PEP, application: APP });
    note(again.ok && audited(PEP).length === 1,
         'S5. setting the same binding again (by `pep`) changes nothing',
         JSON.stringify(again));
    const moved = await act('set-pep-application',
                            { name: PEP, application: APP2 });
    note(moved.ok && moved.previous === APP && binding.of(PEP) === APP2 &&
         binding.boundTo(APP).length === 0,
         'S6. a binding to another application replaces it',
         JSON.stringify(moved));

    // C. CLEARED.
    const cleared = await act('clear-pep-application', { name: PEP });
    note(cleared.ok && cleared.previous === APP2 && binding.of(PEP) === '',
         'C1. the binding is removed', JSON.stringify(cleared));
    const clearedAgain = await act('clear-pep-application', { name: PEP });
    note(clearedAgain.ok && clearedAgain.previous === '' &&
         audited(PEP).length === 3,
         'C2. removing it again is not a refusal and writes nothing',
         JSON.stringify(clearedAgain) + ' ' + audited(PEP).length);
    const clearNobody = await act('clear-pep-application',
                                  { name: 'pb-nobody-' + stamp });
    note(!clearNobody.ok && codeOf(clearNobody) === 'STS-XACML-0334',
         'C3. clearing for nobody is refused (STS-XACML-0334)',
         codeOf(clearNobody));

    // D. AN APPLICATION DELETED.
    await act('set-pep-application', { name: PEP, application: APP });
    await act('set-pep-application', { name: OTHER, application: APP2 });
    const rowsBefore = audited(PEP).length;
    const otherBefore = audited(OTHER).length;
    const gone = applications.deleteApplication(APP);
    note(gone && gone.ok !== false, 'D1. the application is deleted',
         JSON.stringify(gone && (gone.errors || gone.ok)));
    note(binding.of(PEP) === '', 'D2. its PEP is no longer bound',
         binding.of(PEP));
    note(binding.of(OTHER) === APP2,
         'D3. a binding to another application is left alone',
         binding.of(OTHER));
    note(audited(PEP).length === rowsBefore + 1 &&
         audited(OTHER).length === otherBefore,
         'D4. the removal is audited, once and for that PEP alone',
         rowsBefore + ' -> ' + audited(PEP).length + ', ' + otherBefore +
         ' -> ' + audited(OTHER).length);

    // I. issue-pep-credential WITH AN APPLICATION.
    const built = pki.hasChain() ? { ok: true } : await pki.start({});
    note(built.ok, 'a certificate authority exists to certify from',
         (built.errors || []).join(' '));
    const request = await tool.assertionRequest({ keyAlg: 'ec-p256',
                                                  name: PEP });
    const keysBefore = personAssertions.listFor(PEP, 'jwt').length;
    const refused = await act('issue-pep-credential',
      { name: PEP, csr: request.csrPem, application: 'pb-no-app-' + stamp });
    note(!refused.ok && codeOf(refused) === 'STS-XACML-0336' &&
         personAssertions.listFor(PEP, 'jwt').length === keysBefore,
         'I1. a binding that would be refused certifies nothing',
         codeOf(refused) + ' ' + personAssertions.listFor(PEP, 'jwt').length);
    const issued = await act('issue-pep-credential',
      { name: PEP, csr: request.csrPem, application: APP2 });
    note(issued.ok && issued.application === APP2 && !!issued.kid &&
         binding.of(PEP) === APP2 &&
         personAssertions.listFor(PEP, 'jwt').length === keysBefore + 1,
         'I2. the key is certified and the PEP bound in one call',
         JSON.stringify({ ok: issued.ok, application: issued.application,
                          why: issued.why }));
    const plainIssue = await act('issue-pep-credential',
      { name: OTHER, csr: (await tool.assertionRequest({ keyAlg: 'ec-p256',
                                                         name: OTHER })).csrPem });
    note(plainIssue.ok && plainIssue.application === undefined &&
         binding.of(OTHER) === APP2,
         'I3. without an application the credential leaves the binding as ' +
         'it was', JSON.stringify({ ok: plainIssue.ok, why: plainIssue.why }));

    // W. ANOTHER DOOR CANNOT WRITE IT.
    let wrote = null;
    try {
      wrote = ldap.writePerson ? ldap.writePerson(PLAIN,
        { stsPepApplication: [APP2] }) : null;
    } catch (e) {
      wrote = { ok: false, threw: String(e && e.message) };
    }
    note(binding.of(PLAIN) === '',
         'W1. the person writer does not set stsPepApplication',
         JSON.stringify(wrote && (wrote.errors || wrote.ok || wrote.threw)));

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'pb-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  PB_ROOT: ROOT, PB_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'xacml_pep_binding',
  describe: 'an embedded remote PEP\'s service account is bound to the one ' +
            'application it is embedded in: each refusal by code, the ' +
            'binding read back, cleared, removed with its application, and ' +
            'set by issue-pep-credential in the same call (#2025)',
  run: run
};
