// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_rules.js
//
// ---------------------------------------------------------------------------
// THE PASSKEY RULES READ FROM THE FACTS (#536) — for a DEFECT only.
//
// Whether a passkey may be registered or may sign somebody in is a rule of
// the issuance policy (`xacml/xacml_templates.ts`'s PASSKEY_ATTRIBUTE and its
// passkey rules); `common/passkey_policy.ts` gathers the facts and asks
// through `issuance_gate.checkPasskey()`. Where not even the BUILT-IN
// document gives a verdict — the engine could not be loaded, the template
// would not build — this reading of the same rules answers instead, so a
// broken engine cannot loosen anything. `xacml_transfer_verdicts.js`'s
// `strictReading()` is the precedent.
//
// It is a LEAF in `common/` rather than a function of the verdicts library
// because the case it exists for is the one where that library (which
// requires the engine) cannot be loaded. `tests/passkey_xacml.js` holds this
// and the built-in document to one truth table, so the two cannot drift.
//
// The question's shape is `issuance_gate.checkPasskey()`'s.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');

const REGISTER = 'register-passkey';

// The code each reason records, per stage — the codes the passkey policy's
// refusals had while they were code (#528-#532). A copy of
// PASSKEY_ATTRIBUTE.REASONS, for this module's reason; the test compares
// the two.
const REASONS = {
  'backup-eligible': { register: 'STS-AUTHN-0312', use: 'STS-AUTHN-0313' },
  'pin-length': { register: 'STS-AUTHN-0314', use: 'STS-AUTHN-0315' },
  'serial-missing': { register: 'STS-AUTHN-0321', use: '' },
  'serial-not-held': { register: 'STS-AUTHN-0320', use: '' },
  'attestation-unchecked': { register: '', use: 'STS-AUTHN-0317' },
  'attestation-compromised': { register: '', use: 'STS-AUTHN-0316' },
  'attestation-untrusted': { register: '', use: 'STS-AUTHN-0316' },
  'attestation-aaguid': { register: '', use: 'STS-AUTHN-0316' },
  'attestation-unlisted': { register: '', use: 'STS-AUTHN-0316' },
  'attestation-level': { register: '', use: 'STS-AUTHN-0316' },
  'attestation-fips': { register: '', use: 'STS-AUTHN-0316' }
};

/**
 * The code a reason records at a stage, or ''.
 *
 * @param {string} reason - the rule's reason
 * @param {string} action - `register-passkey` or `use-passkey`
 * @returns {string} the error code, or ''
 */
function codeFor(reason, action) {
  log.debug('Entering codeFor().');
  const row = REASONS[reason];
  const code = row ? row[action === REGISTER ? 'register' : 'use'] : '';
  log.debug('Leaving codeFor(). ' + (code || 'none'));
  return code;
}

/**
 * The built-in passkey rules, read from the facts.
 *
 * @param {Record<string, any>} question - the passkey question
 * @returns {{ verdict: string, code: string, reason: string }}
 */
function strictReading(question) {
  log.debug('Entering strictReading().');
  const q = question || {};
  const groups = (q.groups || []).map(String);
  const carries = function (group) {
    log.debug('Entering carries().');
    log.debug('Leaving carries().');
    return groups.indexOf(group) >= 0;
  };
  const policy = q.policy || {};
  const settings = q.settings || {};
  const att = q.attestation || {};
  const whole = function (value) {
    log.debug('Entering whole().');
    log.debug('Leaving whole().');
    return typeof value === 'number' && Number.isInteger(value);
  };
  const serialBound = !!String(policy.enterpriseSerialAttribute || '');
  const aaguids = (settings.allowedAaguids || []).map(String);
  const requiredRank = Number(settings.requiredRank) > 0
    ? Number(settings.requiredRank) : 0;
  const demandsTrust = settings.attestationPolicy === 'require-trusted' ||
    aaguids.length > 0 || requiredRank > 0 || settings.requireFips === true ||
    serialBound;
  const attestationHeld = carries('attestation') &&
    policy.enforceAttestationAtSignIn === true &&
    (settings.attestationPolicy !== 'off' || demandsTrust);
  const register = q.action === REGISTER;
  let reason = '';
  if (carries('backup-eligible') && q.backupEligible === true &&
      policy.backupEligibility === 'disallow') {
    reason = 'backup-eligible';
  } else if (carries('pin-length') && policy.enforcePinLength === true &&
             ((!whole(q.minPinLength) &&
               policy.pinLengthOnlyIfSupported !== true) ||
              (whole(q.minPinLength) && whole(policy.minPinLength) &&
               q.minPinLength < policy.minPinLength))) {
    reason = 'pin-length';
  } else if (register) {
    const serial = String(q.serial === undefined || q.serial === null
      ? '' : q.serial);
    if (carries('serial') && serialBound && !serial) {
      reason = 'serial-missing';
    } else if (carries('serial') && serialBound && serial && !q.serialHeld) {
      reason = 'serial-not-held';
    }
  } else if (attestationHeld) {
    const levelDemanded = requiredRank > 0 || settings.requireFips === true;
    if (att.unchecked === true) {
      reason = 'attestation-unchecked';
    } else if (att.compromised === true) {
      reason = 'attestation-compromised';
    } else if (demandsTrust && att.trusted !== true) {
      reason = 'attestation-untrusted';
    } else if (aaguids.length &&
               aaguids.indexOf(String(att.aaguid || '')) < 0) {
      reason = 'attestation-aaguid';
    } else if (levelDemanded && att.listed !== true) {
      reason = 'attestation-unlisted';
    } else if (requiredRank > 0 && whole(att.rank) &&
               att.rank < requiredRank) {
      reason = 'attestation-level';
    } else if (settings.requireFips === true && att.listed === true &&
               att.fips !== true) {
      reason = 'attestation-fips';
    }
  }
  const out = reason
    ? { verdict: 'refuse', code: codeFor(reason, q.action), reason: reason }
    : { verdict: 'allow', code: '', reason: '' };
  log.debug('Leaving strictReading(). ' + out.verdict +
            (reason ? ' (' + reason + ')' : ''));
  return out;
}

module.exports = {
  REASONS: REASONS,
  codeFor: codeFor,
  strictReading: strictReading
};
