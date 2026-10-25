// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/risk_key_step_up.js
// ===========================================================================
// THE SETUP #899 AND #906 SHARE (#926).
//
// No in-process job turns the risk engine on, gets a medium-or-worse
// assessment, and installs a policy that answers with a security-key
// step-up. Both assertions of `tests/risk_key_step_up.js` need that, so it
// is done here once. `arm()` asserts nothing, creates nobody and listens
// nowhere: it turns enforcement on in development, moves the HIGH line, and
// writes the shipped `role-issuance` document into the default realm's
// policy store. The test says what that produced.
//
// Call it after the stack is loaded. The directory slot the store writes
// through is filled when `ldap/ldap_server.js` is required, which the
// protocol stack does and a bare require of this file does not.
//
// A LIBRARY FOR A TEST: no test of its own. It logs through a bunyan logger
// of its own, and honours `LOG_LEVEL` first because the child that requires
// it sets that and not `STS_LOG_LEVEL`.
// ===========================================================================

const log = require('bunyan').createLogger({
  name: 'risk_key_step_up_setup',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info' });

const config = require('../../common/config');
const realms = require('../../common/realms');
const templates = require('../../xacml/xacml_templates');
const store = require('../../xacml/xacml_store');
const xml = require('../../xacml/xacml_xml');
const rolePep = require('../../xacml/xacml_role_pep');

// What `tests/risk_decisions.js` sends for a browser, and for an automated
// client. Kept here so the two assertions ask for the same strings the
// helper's score arithmetic was written against.
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 ' +
  'Safari/537.36';
const AUTOMATED = 'curl/8.5.0';

/**
 * Turns risk enforcement on, puts HIGH above an automated client's score,
 * and installs the shipped issuance policy.
 *
 * A first sign-in starts at a score of 1, and `automated-client` multiplies
 * that by 10. The default HIGH line is 10 (`risk.highScorePercent` 1000),
 * which would make that sign-in HIGH, and `risk-high` would refuse it
 * before a security-key step-up existed. 1500 puts HIGH at a score of 15,
 * so 10 is MEDIUM and `risk-medium-key` is the rule that answers. The
 * MEDIUM line stays at 3.
 *
 * @returns `{ ok: true, policy, rules, userAgent, browserUserAgent }`, or
 *   `{ ok: false, why }` when a setting or the document was refused
 */
function arm() {
  log.debug("Entering arm().");
  // The default realm's overrides are the process's (`realmFor()` answers
  // null there), which is where a sign-in on the unprefixed paths reads.
  const tuned = realms.run(realms.DEFAULT_REALM, function () {
    return {
      enforced: config.setOverride('risk.enforceInDevelopment', true),
      high: config.setOverride('risk.highScorePercent', 1500)
    };
  });
  if (!tuned.enforced || tuned.enforced.ok === false) {
    log.debug("Leaving arm(). Enforcement was refused.");
    return { ok: false,
             why: ((tuned.enforced && tuned.enforced.errors) || [])
               .join(' ') };
  }
  if (!tuned.high || tuned.high.ok === false) {
    log.debug("Leaving arm(). The HIGH line was refused.");
    return { ok: false,
             why: ((tuned.high && tuned.high.errors) || []).join(' ') };
  }
  const name = rolePep.issuancePolicyName();
  const built = templates.build('role-issuance', {}, { name: name });
  if (!built.ok || !built.policy) {
    log.debug("Leaving arm(). The template did not build.");
    return { ok: false, why: built.why || 'the template did not build' };
  }
  let document = '';
  try {
    document = xml.writePolicy(built.policy);
  } catch (e) {
    // A document the writer cannot serialise is a setup failure, said to
    // the caller rather than thrown out of the child.
    log.debug("Caught in arm(): " + ((e && e.message) || e));
    log.debug("Leaving arm(). The document was not written out.");
    return { ok: false, why: String((e && e.message) || e) };
  }
  let written = null;
  try {
    written = realms.run(realms.DEFAULT_REALM, function () {
      return store.write(name, document, { enabled: true });
    });
  } catch (e) {
    log.debug("Caught in arm(): " + ((e && e.message) || e));
    log.debug("Leaving arm(). The policy was not stored.");
    return { ok: false, why: String((e && e.message) || e) };
  }
  if (!written || written.ok === false) {
    log.debug("Leaving arm(). The directory refused the policy.");
    return { ok: false, why: (written && written.why) || 'not written' };
  }
  const rules = (built.policy.rules || []).map(function (rule) {
    const id = String((rule && rule.id) || '');
    const at = id.lastIndexOf(':rule:');
    if (at < 0) {
      return id;
    }
    return id.slice(at + ':rule:'.length);
  });
  log.debug("Leaving arm().");
  return { ok: true, policy: name, rules: rules, userAgent: AUTOMATED,
           browserUserAgent: CHROME };
}

module.exports = { arm: arm };
