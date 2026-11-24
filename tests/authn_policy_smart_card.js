// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_policy_smart_card.js
//
// ===========================================================================
// THE AUTHENTICATION POLICY'S SMART-CARD ROWS AND ITS ATTESTED-HARDWARE
// REQUIREMENT (#2031, 2026-11-23), in process.
//
// `common/authn_policy.ts` (FOLLOWING) argues the design. What is held here:
//
//   A. UNSET FOLLOWS: with nothing stored, `smartCardPrimary` answers
//      `certificatePrimary`, `pkinitSmartCardPrimary` answers
//      `kerberosPrimary`, and `smartCardCardAuthPrimary` the
//      `piv.cardAuthSignIn` setting, each with its source `follows …`.
//   B. A POLICY STORED BEFORE THE ROWS keeps its meaning: an entry that
//      turned certificates off and stores no smart-card attribute refuses
//      smart cards too, and a save that omits the rows writes none.
//   C. SET, A ROW STANDS ON ITS OWN, a save that omits it keeps it, and
//      `follow` puts it back to following (no attribute written).
//   D. `requireAttestedHardware`: `no` by default, kept by a save that
//      omits it, `always` refused with no mechanism that can be on hardware,
//      and described.
//   E. THE DOOR'S QUESTION (`authn.ts`'s `authnPolicyRefusal()`): a smart
//      card asks `smartCard` (STS-AUTHN-0590), a ticket with `sc` asks
//      `pkinitSmartCard` (0591), another certificate or ticket asks the
//      generic row (0268), and `always` refuses a credential on no
//      attested token (0592) and exempts the built-in administrator.
//   F. THE CONSOLE'S VIEW carries `follows`, `followsLabel` and `following`,
//      and its form draws the third choice.
//   G. HOTP AND YUBIKEY OTP SAY THEY ARE OFF BY DEFAULT and must be turned
//      on (rcbj, 2026-11-23), in the `what` the page and the API draw.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const authnPolicy = require('../common/authn_policy');
const ldap = require('../ldap/ldap_server');
const policyKinds = require('../admin-core/policy_kinds');
const adminViews = require('../admin-core/admin_views');
const authnModule = require('../authn/authn');

const log = require('bunyan').createLogger({ name: 'authn_policy_smart_card',
  level: process.env.LOG_LEVEL || 'info' });

void ldap;
void policyKinds;

function withRealm(t, stem, fn) {
  log.debug('Entering withRealm(). ' + stem);
  const id = stem + '-' + require('crypto').randomBytes(3).toString('hex');
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withRealm().');
    return realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    // Every other file asserts only the default realm is left.
    realms.remove(id);
  }
}

// A whole profile as an API client written before #2031 sends it: every
// field it knew, none of the four new ones.
function oldClientBody(fields) {
  log.debug('Entering oldClientBody().');
  const body = Object.assign({}, authnPolicy.DEFAULTS, fields || {});
  delete body.smartCardPrimary;
  delete body.smartCardCardAuthPrimary;
  delete body.pkinitSmartCardPrimary;
  delete body.requireAttestedHardware;
  log.debug('Leaving oldClientBody().');
  return body;
}

function storedAttributes() {
  log.debug('Entering storedAttributes().');
  const hooks = authnPolicy.directoryInstalled();
  const entry = hooks.allAuthnPolicies().filter(function (one) {
    return String(one.name).toLowerCase() === 'default';
  })[0];
  log.debug('Leaving storedAttributes().');
  return entry ? Object.keys(entry.attributes || {}).map(function (k) {
    return k.toLowerCase();
  }) : [];
}

function follows(t) {
  log.debug('Entering follows().');
  withRealm(t, 'smart-card-follows', function () {
    const p = authnPolicy.read('default');
    t.check(p.smartCardPrimary === p.certificatePrimary &&
            p.sources.smartCardPrimary === 'follows certificatePrimary' &&
            authnPolicy.following(p, 'smartCardPrimary'),
            'A1. unset, the smart card row answers certificatePrimary and ' +
            'says it follows', JSON.stringify(p.sources.smartCardPrimary));
    t.check(p.pkinitSmartCardPrimary === p.kerberosPrimary &&
            p.sources.pkinitSmartCardPrimary === 'follows kerberosPrimary',
            'A2. unset, the PKINIT smart card row answers kerberosPrimary');
    t.check(p.smartCardCardAuthPrimary === false &&
            p.sources.smartCardCardAuthPrimary ===
              'follows piv.cardAuthSignIn',
            'A3. unset, the card authentication row answers ' +
            'piv.cardAuthSignIn (false by default)');
    config.setOverride('piv.cardAuthSignIn', true);
    try {
      t.check(authnPolicy.allows('smartCardCardAuth', 'primary'),
              'A4. and follows the setting when it is turned on');
    } finally {
      config.clearOverride('piv.cardAuthSignIn');
    }
    t.check(!authnPolicy.allows('smartCardCardAuth', 'primary'),
            'A5. and back when it is turned off');
  });
  log.debug('Leaving follows().');
}

function storedBefore(t) {
  log.debug('Entering storedBefore().');
  withRealm(t, 'smart-card-before', function () {
    const saved = authnPolicy.save('default', oldClientBody({
      certificatePrimary: false, kerberosPrimary: false }));
    t.check(saved.ok, 'B1. a save that names none of the new rows is ' +
            'accepted (optional)', JSON.stringify(saved.errors));
    const attrs = storedAttributes();
    t.check(attrs.indexOf('stsauthnsmartcardprimary') < 0 &&
            attrs.indexOf('stsauthnpkinitsmartcardprimary') < 0 &&
            attrs.indexOf('stsauthnsmartcardcardauthprimary') < 0,
            'B2. and writes no attribute for a row that follows',
            attrs.join(','));
    t.check(!authnPolicy.allows('smartCard', 'primary') &&
            !authnPolicy.allows('pkinitSmartCard', 'primary'),
            'B3. certificates and Kerberos off turn smart cards and PKINIT ' +
            'smart cards off too, as before the rows existed');
    const again = authnPolicy.save('default', oldClientBody({
      certificatePrimary: true, kerberosPrimary: true }));
    t.check(again.ok && authnPolicy.allows('smartCard', 'primary') &&
            authnPolicy.allows('pkinitSmartCard', 'primary'),
            'B4. and turning the generic rows back on is followed');
  });
  log.debug('Leaving storedBefore().');
}

function setRows(t) {
  log.debug('Entering setRows().');
  withRealm(t, 'smart-card-set', function () {
    const saved = authnPolicy.save('default', Object.assign(
      oldClientBody({ certificatePrimary: false }),
      { smartCardPrimary: true }));
    t.check(saved.ok && authnPolicy.allows('smartCard', 'primary') &&
            !authnPolicy.allows('certificate', 'primary') &&
            !authnPolicy.following(saved.profile, 'smartCardPrimary') &&
            storedAttributes().indexOf('stsauthnsmartcardprimary') >= 0,
            'C1. smart cards yes, other certificates no: the row set stands ' +
            'on its own and is stored');
    const kept = authnPolicy.save('default',
                                  oldClientBody({ certificatePrimary: false }));
    t.check(kept.ok && authnPolicy.allows('smartCard', 'primary'),
            'C2. a save that omits it keeps it');
    const reverse = authnPolicy.save('default', Object.assign(
      oldClientBody({ certificatePrimary: true }),
      { smartCardPrimary: 'FALSE' }));
    t.check(reverse.ok && !authnPolicy.allows('smartCard', 'primary') &&
            authnPolicy.allows('certificate', 'primary'),
            'C3. and the reverse: other certificates yes, smart cards no');
    const back = authnPolicy.save('default', Object.assign(
      oldClientBody({ certificatePrimary: true }),
      { smartCardPrimary: 'follow' }));
    t.check(back.ok && authnPolicy.allows('smartCard', 'primary') &&
            authnPolicy.following(back.profile, 'smartCardPrimary') &&
            storedAttributes().indexOf('stsauthnsmartcardprimary') < 0,
            'C4. `follow` puts it back to following, with no attribute');
    const console = authnPolicy.validate(Object.assign({ form: 'console' },
      oldClientBody(), { smartCardPrimary: 'FOLLOW' }));
    t.check(console.problems.length === 0 &&
            console.following.indexOf('smartCardPrimary') >= 0,
            'C5. the console\'s FOLLOW radio is read as following',
            JSON.stringify(console.problems));
    const bad = authnPolicy.validate(Object.assign(oldClientBody(),
      { smartCardPrimary: 'perhaps' }));
    t.check(bad.problems.length === 1,
            'C6. a value that is neither yes, no nor follow is refused');
  });
  log.debug('Leaving setRows().');
}

function attested(t) {
  log.debug('Entering attested().');
  withRealm(t, 'attested-hardware', function () {
    t.equal(authnPolicy.requireAttestedHardware(), 'no',
            'D1. attested hardware is not required by default');
    const saved = authnPolicy.save('default', Object.assign(oldClientBody(),
      { requireAttestedHardware: 'always' }));
    t.check(saved.ok && authnPolicy.requireAttestedHardware() === 'always' &&
            authnPolicy.describe().indexOf(
              authnPolicy.SENTENCES.attestedAlways) >= 0,
            'D2. `always` is saved and described',
            JSON.stringify(saved.errors));
    const kept = authnPolicy.save('default', oldClientBody());
    t.check(kept.ok && authnPolicy.requireAttestedHardware() === 'always',
            'D3. a save that omits it keeps it');
    const none = authnPolicy.save('default', Object.assign(oldClientBody({
      passkeyPrimary: false, securityKeySecondFactor: false,
      certificatePrimary: false }), { smartCardPrimary: false,
                                      requireAttestedHardware: 'always' }));
    t.check(!none.ok && errorCodes.codeOf(none) === 'STS-AUTHN-0243' &&
            /nobody could finish/.test((none.errors || []).join(' ')),
            'D4. `always` with nothing that can be on hardware is refused',
            JSON.stringify(none.errors));
  });
  log.debug('Leaving attested().');
}

// `authnPolicyRefusal()` is the instance's; it is asked here with a `this`
// that holds only what it reads.
function doorQuestion(t) {
  log.debug('Entering doorQuestion().');
  const Authn = authnModule.Authn;
  const ask = function (amr, credential, username, builtIn) {
    return Authn.prototype.authnPolicyRefusal.call({
      deps: { log: log, authnPolicy: authnPolicy },
      builtInAdministrator: function () {
        return !!builtIn;
      }
    }, amr, credential, username || 'someone');
  };
  withRealm(t, 'smart-card-door', function () {
    authnPolicy.save('default', Object.assign(oldClientBody({
      certificatePrimary: true, kerberosPrimary: true }),
      { smartCardPrimary: false, pkinitSmartCardPrimary: false }));
    t.equal(ask(['hwk', 'sc'], { kind: 'certificate', smartCard: true }),
            'STS-AUTHN-0590', 'E1. a smart card asks the smart card row');
    t.equal(ask(['swk'], { kind: 'certificate' }), '',
            'E2. another certificate asks the certificate row');
    t.equal(ask(['hwk', 'sc'], { kind: 'kerberos' }), 'STS-AUTHN-0591',
            'E3. a ticket carrying sc asks the PKINIT smart card row');
    t.equal(ask(['pwd'], { kind: 'kerberos' }), '',
            'E4. another ticket asks the Kerberos row');
    authnPolicy.save('default', Object.assign(oldClientBody({
      certificatePrimary: false }), { smartCardPrimary: true }));
    t.equal(ask(['swk'], { kind: 'certificate' }), 'STS-AUTHN-0268',
            'E5. with certificates off and smart cards on, another ' +
            'certificate is refused');
    t.equal(ask(['hwk', 'sc'], { kind: 'certificate', smartCard: true }), '',
            'E6. and a smart card is taken');
    authnPolicy.save('default', Object.assign(oldClientBody(),
      { requireAttestedHardware: 'always' }));
    t.equal(ask(['pwd'], { kind: 'password' }), 'STS-AUTHN-0592',
            'E7. `always` refuses a password, on no attested token');
    t.equal(ask(['pwd'], { kind: 'password' }, 'admin', true), '',
            'E8. and exempts the built-in administrator');
    t.equal(ask(['pwd'], null), '',
            'E9. a door that names no credential is not asked');
  });
  log.debug('Leaving doorQuestion().');
}

function view(t) {
  log.debug('Entering view().');
  withRealm(t, 'smart-card-view', function () {
    const authn = adminViews.policiesView({}).authn || {};
    const row = (authn.fields || []).filter(function (f) {
      return f.key === 'smartCardPrimary';
    })[0];
    t.check(row && row.follows === 'certificatePrimary' &&
            row.following === true && /TLS client certificate/.test(
              String(row.followsLabel)),
            'F1. the view says what the row follows and that it follows now',
            JSON.stringify(row));
    const plain = (authn.fields || []).filter(function (f) {
      return f.key === 'certificatePrimary';
    })[0];
    t.check(plain && plain.follows === undefined,
            'F2. a row that follows nothing says nothing of it');
    const otp = (authn.fields || []).filter(function (f) {
      return f.key === 'hotpSecondFactor' ||
             f.key === 'yubicoOtpSecondFactor';
    });
    t.check(otp.length === 2 && otp.every(function (f) {
      return /OFF BY DEFAULT, and it must be turned on/.test(
        String(f.what));
    }), 'G1. HOTP and YubiKey OTP say they are off by default and must be ' +
        'turned on', JSON.stringify(otp.map(function (f) {
          return f.what;
        })));
  });
  log.debug('Leaving view().');
}

function consoleRow(t) {
  log.debug('Entering consoleRow().');
  let page = null;
  try {
    page = require('../admin-ui/web_policies');
  } catch (e) {
    log.debug('Caught in consoleRow(): ' + ((e && e.message) || e));
    page = null;
  }
  const PoliciesPage = page && (page.PoliciesPage || page);
  if (!PoliciesPage || typeof PoliciesPage.policyFieldRow !== 'function') {
    t.bad('F3. the console\'s field row could not be loaded');
    log.debug('Leaving consoleRow(). Not loaded.');
    return;
  }
  const words = { 'consolePolicies.yes': 'yes', 'consolePolicies.no': 'no' };
  const tr = {
    text: function (key, vars) {
      return key === 'consolePolicies.follows'
        ? 'as ' + String((vars || {}).row) : (words[key] || key);
    },
    html: function (key) {
      return words[key] || key;
    }
  };
  const html = PoliciesPage.policyFieldRow({ key: 'smartCardPrimary',
    type: 'bool', value: true, follows: 'certificatePrimary',
    followsLabel: 'TLS client certificate', following: true,
    what: 'x', attribute: 'stsAuthnSmartCardPrimary', label: 'Smart card' },
    'ap-', tr);
  t.check(/value="FOLLOW" checked/.test(html) &&
          !/value="TRUE" checked/.test(html) &&
          /as TLS client certificate/.test(html),
          'F3. the console draws the third choice, checked while it follows',
          html.slice(0, 400));
  log.debug('Leaving consoleRow().');
}

module.exports = {
  name: 'authn policy smart card',
  describe: 'The authentication policy\'s smart-card rows (#2031): unset ' +
            'follows the generic row or setting, a policy stored before them ' +
            'keeps its meaning, the attested-hardware requirement, the ' +
            'door\'s question and the console\'s third choice',
  run: async function (t) {
    log.debug('Entering run().');
    follows(t);
    storedBefore(t);
    setRows(t);
    attested(t);
    doorQuestion(t);
    view(t);
    consoleRow(t);
    log.debug('Leaving run().');
  }
};
