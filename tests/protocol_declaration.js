// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: protocol_declaration.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION IS ISSUED NOTHING THROUGH A PROTOCOL IT IS NOT DECLARED FOR,
// IN PRODUCT MODE (2026-10-01).
//
// `appAllowedProtocol` names the protocol families an administrator declared
// an application for. The issuance policy's `protocol-not-declared` rule
// (`xacml/xacml_templates.ts`) refuses, in product mode, an issuance whose
// families and the declaration share no member; `common/issuance_gate.js`
// works out both and `xacml/xacml_role_pep.ts` sends them and enforces the
// rule's obligation. Asserted:
//
//   A. the rule is in the built-in policy, after the device rules, and
//      `decideProtocols: no` leaves it out;
//   B. the rule against requests built by the PEP: product refuses an ID
//      Token to an application declared for SAML 2.0 alone, with the
//      protocol obligation; development does not; a declaration that shares
//      a family is permitted; an application declared for nothing sends no
//      protocol attribute and is permitted; the rule left out permits;
//   C. the gate: the families of each kind, an explicit `protocolFamilies`
//      winning, the declaration read off the application's entry, nothing
//      for an undeclared application or a session, and the mode predicate.
//
// In a CHILD PROCESS, for `risk_decisions.js`'s reason: loading the PEP arms
// the issuance gate for the whole process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'protocol_declaration',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PD_ROOT;
  const OUT = process.env.PD_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    require(ROOT + '/common/protocol_stack');
    const applications = require(ROOT + '/common/applications');
    const gate = require(ROOT + '/common/issuance_gate');
    const mode = require(ROOT + '/common/mode');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const pdp = require(ROOT + '/xacml/xacml_pdp');
    const rolePep = require(ROOT + '/xacml/xacml_role_pep');
    const PROTOCOL = templates.PROTOCOL_ATTRIBUTE;

    // --- A. The rule in the built-in policy -------------------------------
    const built = templates.build('role-issuance', {},
                                  { name: 'role-issuance' });
    const ids = (built.policy && built.policy.rules || [])
      .map(function (r) { return r.id.split(':rule:')[1]; });
    note(built.ok && ids.indexOf('protocol-not-declared') ===
         ids.indexOf('device-required') + 1,
         'A1. the built-in issuance policy carries protocol-not-declared ' +
         'right after the device rules', ids.join(','));
    const without = templates.build('role-issuance',
      { decideProtocols: 'no' }, { name: 'role-issuance' });
    note(without.ok && without.policy.rules.every(function (r) {
      return !/protocol-not-declared$/.test(r.id);
    }), 'A2. decideProtocols: no builds the policy without it');

    // --- B. The rule against requests the PEP builds ----------------------
    const decide = function (policy, extra) {
      const request = rolePep.buildRequest(Object.assign({
        application: 'pd-app', kind: 'issue-id-token',
        subject: { kind: 'user', name: 'pd-person', authenticated: true }
      }, extra), ['EVERYBODY'], [], ['EVERYBODY']);
      return pdp.evaluate(policy, request, {});
    };
    const obligated = function (answer) {
      return (answer.obligations || []).some(function (o) {
        return o && o.id === PROTOCOL.OBLIGATION;
      });
    };
    let a = decide(built.policy, { mode: 'product',
      declaredProtocols: ['saml2'], protocolFamilies: ['oidc'] });
    note(a.decision === 'Deny' && obligated(a),
         'B1. product: an ID Token to an application declared for SAML 2.0 ' +
         'alone is a Deny carrying the protocol obligation', a.decision);
    a = decide(built.policy, { mode: 'development',
      declaredProtocols: ['saml2'], protocolFamilies: ['oidc'] });
    note(a.decision === 'Permit' && !obligated(a),
         'B2. development: the same issuance is permitted', a.decision);
    a = decide(built.policy, { mode: 'product', kind: 'issue-access-token',
      declaredProtocols: ['oauth2'],
      protocolFamilies: gate.FAMILIES_OF_KIND['issue-access-token'] });
    note(a.decision === 'Permit',
         'B3. product: an access token to an application declared for ' +
         'OAuth 2.0 is permitted', a.decision);
    a = decide(built.policy, { mode: 'product', declaredProtocols: ['oauth2'],
      protocolFamilies: ['oidc'] });
    note(a.decision === 'Deny' && obligated(a),
         'B4. product: an ID Token to an application declared for OAuth 2.0 ' +
         'alone is refused', a.decision);
    a = decide(built.policy, { mode: 'product', declaredProtocols: [],
      protocolFamilies: ['oidc'] });
    note(a.decision === 'Permit',
         'B5. an application declared for nothing is not refused (no ' +
         'protocol attribute is sent)', a.decision);
    a = decide(without.policy, { mode: 'product',
      declaredProtocols: ['saml2'], protocolFamilies: ['oidc'] });
    note(a.decision === 'Permit',
         'B6. with the rule left out, nothing is refused on the protocol',
         a.decision);

    // --- C. The gate ------------------------------------------------------
    note(JSON.stringify(gate.FAMILIES_OF_KIND['issue-id-token']) ===
         '["oidc"]' &&
         gate.FAMILIES_OF_KIND['issue-saml-assertion'].join(',') ===
           'saml2,saml11' &&
         !gate.FAMILIES_OF_KIND['start-session'],
         'C1. an ID Token is OpenID Connect\'s, a SAML assertion either ' +
         'version\'s, a session nobody\'s');
    note(mode.issuesThroughUndeclaredProtocols() === !mode.isProduct(),
         'C2. issuesThroughUndeclaredProtocols() is true in development only');
    applications.createApplication({ identifier: 'pd-saml-sp',
      protocols: ['saml2'], fields: {} });
    applications.createApplication({ identifier: 'pd-nothing',
      protocols: [], fields: {} });
    const asked = [];
    gate.setDecider(function (question) {
      asked.push(question);
      return { allowed: true, decision: 'Permit', why: 'recorded',
               roles: [], required: [], policy: null };
    });
    const ask = function (request) {
      asked.length = 0;
      gate.check(Object.assign({
        subject: { kind: 'user', name: 'pd-person', authenticated: true },
        claims: null }, request));
      return asked[0] || null;
    };
    let q = ask({ application: 'pd-saml-sp', kind: 'issue-id-token' });
    note(q && q.declaredProtocols.join(',') === 'saml2' &&
         q.protocolFamilies.join(',') === 'oidc' && q.mode === mode.current(),
         'C3. the gate reads the declaration off the entry and names the ' +
         'ID Token\'s family and the mode', JSON.stringify(q && {
           d: q.declaredProtocols, f: q.protocolFamilies, m: q.mode }));
    q = ask({ application: 'pd-saml-sp', kind: 'issue-saml-assertion',
              protocolFamilies: ['saml11'] });
    note(q && q.protocolFamilies.join(',') === 'saml11',
         'C4. a caller\'s own protocolFamilies wins over the kind\'s',
         JSON.stringify(q && q.protocolFamilies));
    q = ask({ application: 'pd-nothing', kind: 'issue-id-token' });
    note(q && q.declaredProtocols.length === 0 &&
         q.protocolFamilies.length === 0,
         'C5. an application declared for nothing carries no protocol facts');
    q = ask({ application: 'pd-saml-sp', kind: 'start-session' });
    note(q && q.declaredProtocols.length === 0,
         'C6. a session carries no protocol facts');
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'protocol-declaration-' + process.pid +
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
                         { LOG_LEVEL: 'fatal', PD_ROOT: ROOT, PD_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
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

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'protocol_declaration',
  describe: 'an application is issued nothing through a protocol family it ' +
            'is not declared for, in product mode: the issuance policy\'s ' +
            'protocol-not-declared rule, the facts the gate sends, and the ' +
            'mode predicate',
  run: run
};
