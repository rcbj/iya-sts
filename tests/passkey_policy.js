// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_policy.js
//
// ===========================================================================
// THE PASSKEY POLICY (#527), in process:
//
//   P1. the built-in profile: usernameless sign-in OFF, a security key asked
//       for `required`, from the built-in defaults;
//   P2. a save replaces the whole profile and is refused for a missing
//       field, a value that is not one of the enum's (STS-AUTHN-0309) and a
//       second profile (STS-AUTHN-0308);
//   P3. a realm with no entry of its own follows the default realm's, its
//       own entry wins, and a reset goes back to inheriting;
//   P4. rcbj's answers: while `allowUsernameless` is off the security key is
//       asked `required` whatever `securityKeyResidentKey` says; while on,
//       the row; the registration options of both buttons follow;
//   P5. the usernameless door: refused while off, naming the policy row
//       (STS-AUTHN-0301), offered while on;
//   P6. the two settings it replaced are refused at start (REPLACED_SETTINGS)
//       and are no longer settings;
//   P7. the fourth kind on Directory → Policies: in `policy_kinds`, the
//       page's view and its two actions;
//   P8. #528's backupEligibility: allowed by default, and under `disallow`
//       a backup-eligible key refused at registration (STS-AUTHN-0312) and
//       at sign-in (STS-AUTHN-0313);
//   P9. #529's PIN length: not enforced by default; enforced, a reported
//       minimum above, at and below the rule's, and none reported, with and
//       without `pinLengthOnlyIfSupported`; the bounds 4 and 63;
//   P10. #531's hints: the defaults are what each ceremony sent before; a
//       list in order reaches the options of its ceremony; every
//       contradiction with the attachment is refused at save; a stored list
//       a later attachment change contradicts loses the hint.
//
// IN PROCESS: the policy is a library over the directory, and a realm is
// created and removed here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const ldap = require('../ldap/ldap_server');
const webauthnPolicy = require('../authn/webauthn_policy');
const policyKinds = require('../admin-core/policy_kinds');
const adminViews = require('../admin-core/admin_views');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'passkey_policy',
  level: process.env.LOG_LEVEL || 'info' });

void ldap;

function withDefaults(fields) {
  log.debug('Entering withDefaults().');
  log.debug('Leaving withDefaults().');
  return Object.assign({}, passkeyPolicy.DEFAULTS, fields || {});
}

function withRealm(t, fn) {
  log.debug('Entering withRealm().');
  const id = 'passkey-policy-' + require('crypto').randomBytes(3)
    .toString('hex');
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return undefined;
  }
  log.debug('Leaving withRealm().');
  try {
    return realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    // REMOVED AGAIN: every other file in this run asserts that only the
    // default realm is left when it finishes.
    realms.remove(id);
  }
}

// The resident key each enrolment asks for: Create a passkey, Use a
// security key, and one naming no kind.
function asked() {
  log.debug('Entering asked().');
  const out = ['passkey', 'security-key', ''].map(function (kind) {
    return webauthnPolicy.creationOptions('localhost', kind || undefined)
      .authenticatorSelection.residentKey;
  }).join(',');
  log.debug('Leaving asked(). ' + out);
  return out;
}

function builtIn(t) {
  log.debug('Entering builtIn().');
  const p = passkeyPolicy.read();
  t.check(p.from === 'built-in' && p.allowUsernameless === false &&
          p.securityKeyResidentKey === 'required' && p.enforced === true,
          'P1. built in: usernameless sign-in OFF, a security key asked ' +
          'for required, in force in both modes', JSON.stringify(p));
  t.check(asked() === 'required,required,required',
          'P1b. so both buttons, and an enrolment naming no kind, ask for a ' +
          'discoverable credential', asked());
  log.debug('Leaving builtIn().');
}

function saves(t) {
  log.debug('Entering saves().');
  const missing = passkeyPolicy.save('default', { allowUsernameless: true });
  t.check(!missing.ok && errorCodes.codeOf(missing) === 'STS-AUTHN-0309' &&
          /securityKeyResidentKey/.test((missing.errors || []).join(' ')),
          'P2. a save naming one field is refused: a save replaces the ' +
          'whole profile (STS-AUTHN-0309)', JSON.stringify(missing.errors));
  const bad = passkeyPolicy.save('default',
    withDefaults({ securityKeyResidentKey: 'sometimes' }));
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-AUTHN-0309' &&
          /discouraged, preferred, required/.test(
            (bad.errors || []).join(' ')),
          'P2b. a resident key that is not one of WebAuthn\'s three is ' +
          'refused, naming them', JSON.stringify(bad.errors));
  const other = passkeyPolicy.save('admins', withDefaults());
  t.check(!other.ok && errorCodes.codeOf(other) === 'STS-AUTHN-0308',
          'P2c. a second profile is refused (STS-AUTHN-0308; #535 is ' +
          'where several come)', JSON.stringify(other.errors));
  const form = passkeyPolicy.validate({ form: 'console',
                                        securityKeyResidentKey: 'preferred',
                                        backupEligibility: 'allow',
                                        minPinLength: '4',
                                        passkeyHints: 'client-device,hybrid',
                                        securityKeyHints: 'security-key',
                                        signInHints: '' });
  t.check(!form.problems.length && form.values.allowUsernameless === false,
          'P2d. an unticked checkbox on the console\'s form is a no',
          JSON.stringify(form));
  log.debug('Leaving saves().');
}

function inheritance(t) {
  log.debug('Entering inheritance().');
  const saved = realms.run(realms.DEFAULT_REALM, function () {
    return passkeyPolicy.save('default', withDefaults({
      allowUsernameless: true, securityKeyResidentKey: 'preferred' }));
  });
  t.check(saved.ok && saved.profile.from === 'realm',
          'P3. the default realm saves its own profile',
          JSON.stringify(saved.errors));
  try {
    withRealm(t, function () {
      const inherited = passkeyPolicy.read();
      t.check(inherited.from === 'default-realm' &&
              inherited.allowUsernameless === true &&
              inherited.securityKeyResidentKey === 'preferred',
              'P3b. a realm with no entry of its own follows the default ' +
              'realm\'s', JSON.stringify(inherited));
      const own = passkeyPolicy.save('default', withDefaults());
      const mine = passkeyPolicy.read();
      t.check(own.ok && mine.from === 'realm' &&
              mine.allowUsernameless === false,
              'P3c. its own entry wins', JSON.stringify(mine));
      const reset = passkeyPolicy.reset('default');
      t.check(reset.ok && reset.removed &&
              passkeyPolicy.read().from === 'default-realm',
              'P3d. a reset goes back to inheriting',
              JSON.stringify(reset));
    });
  } finally {
    realms.run(realms.DEFAULT_REALM, function () {
      passkeyPolicy.reset('default');
    });
  }
  t.check(passkeyPolicy.read().from === 'built-in',
          'P3e. and the default realm\'s reset puts the built-in profile ' +
          'back');
  log.debug('Leaving inheritance().');
}

function answers(t) {
  log.debug('Entering answers().');
  const run = function (fields, fn) {
    log.debug('Entering answers() run().');
    passkeyPolicy.save('default', withDefaults(fields));
    try {
      log.debug('Leaving answers() run().');
      return fn();
    } finally {
      passkeyPolicy.reset('default');
    }
  };
  run({ allowUsernameless: false, securityKeyResidentKey: 'discouraged' },
      function () {
    t.check(passkeyPolicy.securityKeyResidentKey() === 'required' &&
            asked() === 'required,required,required',
            'P4. usernameless OFF: the security key is asked REQUIRED ' +
            'whatever securityKeyResidentKey says (rcbj\'s answer 1)',
            asked());
  });
  ['discouraged', 'preferred', 'required'].forEach(function (value) {
    run({ allowUsernameless: true, securityKeyResidentKey: value },
        function () {
      t.check(passkeyPolicy.securityKeyResidentKey() === value &&
              asked() === 'required,' + value + ',' + value,
              'P4b. usernameless ON: the security key is asked the row (' +
              value + '); Create a passkey stays required', asked());
    });
  });
  const said = passkeyPolicy.describe(passkeyPolicy.read());
  t.check(said.length === 7 && /names the person first/.test(said[0]) &&
          /synced \(backup-eligible\) passkeys are accepted/.test(said[3]),
          'P4c. the rules in sentences', JSON.stringify(said));
  log.debug('Leaving answers().');
}

function door(t) {
  log.debug('Entering door().');
  const off = webauthnPolicy.usernamelessOffered();
  t.check(!off.ok && errorCodes.codeOf(off) === 'STS-AUTHN-0301' &&
          /allowUsernameless/.test(off.why),
          'P5. usernameless OFF: the door refuses, naming the passkey ' +
          'policy\'s row (STS-AUTHN-0301)', JSON.stringify(off));
  passkeyPolicy.save('default', withDefaults({ allowUsernameless: true }));
  try {
    t.check(webauthnPolicy.usernamelessOffered().ok === true &&
            webauthnPolicy.settings().usernameless === true,
            'P5b. usernameless ON: offered');
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving door().');
}

function synced(t) {
  log.debug('Entering synced().');
  t.check(passkeyPolicy.read().backupEligibility === 'allow' &&
          passkeyPolicy.backupEligibleRefusal(true, 'registration') === null,
          'P8. #528: synced (backup-eligible) passkeys are allowed by ' +
          'default');
  passkeyPolicy.save('default', withDefaults({
    backupEligibility: 'disallow' }));
  try {
    const at = passkeyPolicy.backupEligibleRefusal(true, 'registration');
    const later = passkeyPolicy.backupEligibleRefusal(true, 'sign-in');
    t.check(!!at && at.code === 'STS-AUTHN-0312' &&
            !!later && later.code === 'STS-AUTHN-0313' &&
            /device-bound/.test(at.why) && /device-bound/.test(later.why),
            'P8b. disallow: BE=1 is refused at registration (0312) and at ' +
            'sign-in (0313), saying why', JSON.stringify([at, later]));
    t.check(passkeyPolicy.backupEligibleRefusal(false, 'sign-in') === null &&
            passkeyPolicy.backupEligibleRefusal(undefined, 'sign-in') ===
              null,
            'P8c. a device-bound key, and one whose BE was never read, are ' +
            'not');
    const bad = passkeyPolicy.save('default', withDefaults({
      backupEligibility: 'sometimes' }));
    t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-AUTHN-0309',
            'P8d. a value that is not allow or disallow is refused',
            JSON.stringify(bad.errors));
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving synced().');
}

function pinLength(t) {
  log.debug('Entering pinLength().');
  t.check(passkeyPolicy.pinLengthRule().enforce === false &&
          passkeyPolicy.pinLengthRefusal(2, 'registration') === null,
          'P9. #529: no PIN length is enforced by default');
  passkeyPolicy.save('default', withDefaults({ enforcePinLength: true,
                                                minPinLength: 6 }));
  try {
    const at = function (reported) {
      log.debug('Entering pinLength() at().');
      const out = passkeyPolicy.pinLengthRefusal(reported, 'registration');
      log.debug('Leaving pinLength() at().');
      return out ? out.code : 'ok';
    };
    t.check(at(8) === 'ok' && at(6) === 'ok' &&
            at(5) === 'STS-AUTHN-0314' && at(null) === 'STS-AUTHN-0314' &&
            at('8') === 'STS-AUTHN-0314',
            'P9b. enforced at 6: 8 and 6 pass, 5 and none reported are ' +
            'refused (a string is not a reported length)',
            [at(8), at(6), at(5), at(null), at('8')].join(','));
    const later = passkeyPolicy.pinLengthRefusal(5, 'sign-in');
    t.check(!!later && later.code === 'STS-AUTHN-0315' &&
            /requires at least 6/.test(later.why),
            'P9c. at sign-in the code is STS-AUTHN-0315, saying why',
            JSON.stringify(later));
    passkeyPolicy.save('default', withDefaults({
      enforcePinLength: true, minPinLength: 6,
      pinLengthOnlyIfSupported: true }));
    t.check(at(null) === 'ok' && at(5) === 'STS-AUTHN-0314',
            'P9d. pinLengthOnlyIfSupported: a key that reports nothing ' +
            'passes, a short reported minimum still does not');
    const low = passkeyPolicy.save('default', withDefaults({
      minPinLength: 3 }));
    const high = passkeyPolicy.save('default', withDefaults({
      minPinLength: 64 }));
    const edge = passkeyPolicy.save('default', withDefaults({
      minPinLength: 63 }));
    t.check(!low.ok && !high.ok && edge.ok &&
            errorCodes.codeOf(low) === 'STS-AUTHN-0309',
            'P9e. the minimum is held to 4..63', JSON.stringify([low.errors,
                                                                 high.errors]));
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving pinLength().');
}

function hints(t) {
  log.debug('Entering hints().');
  const config = require('../common/config');
  const sent = function (kind) {
    log.debug('Entering hints() sent().');
    const out = kind === 'sign-in'
      ? webauthnPolicy.requestOptions('localhost').hints
      : webauthnPolicy.creationOptions('localhost', kind || undefined).hints;
    log.debug('Leaving hints() sent().');
    return JSON.stringify(out === undefined ? null : out);
  };
  t.check(sent('passkey') === '["client-device","hybrid"]' &&
          sent('security-key') === '["security-key"]' && sent('') === '[]' &&
          sent('sign-in') === 'null' &&
          webauthnPolicy.discoverableRequestOptions('localhost').hints ===
            undefined,
          'P10. #531: the defaults are what each ceremony sent before',
          [sent('passkey'), sent('security-key'), sent(''), sent('sign-in')]
            .join(' '));
  const saved = passkeyPolicy.save('default', withDefaults({
    passkeyHints: 'hybrid, client-device', securityKeyHints: 'none',
    signInHints: 'security-key,hybrid' }));
  try {
    t.check(saved.ok && sent('passkey') === '["hybrid","client-device"]' &&
            sent('security-key') === '[]' &&
            sent('sign-in') === '["security-key","hybrid"]' &&
            JSON.stringify(webauthnPolicy.discoverableRequestOptions(
              'localhost').hints) === '["security-key","hybrid"]',
            'P10b. a list reaches its ceremony in its order; none sends ' +
            'none', JSON.stringify(saved.errors || []));
  } finally {
    passkeyPolicy.reset('default');
  }
  const bad = passkeyPolicy.save('default', withDefaults({
    securityKeyHints: 'security-key,client-device' }));
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-AUTHN-0309' &&
          /client-device contradicts.*cross-platform/.test(
            (bad.errors || []).join(' ')),
          'P10c. client-device on "Use a security key" (cross-platform) is ' +
          'refused, with the reason', JSON.stringify(bad.errors));
  const junk = passkeyPolicy.save('default', withDefaults({
    passkeyHints: 'hybrid,hybrid' }));
  const unknown = passkeyPolicy.save('default', withDefaults({
    signInHints: 'usb' }));
  t.check(!junk.ok && !unknown.ok,
          'P10d. a hint twice, or one that is not a hint, is refused',
          JSON.stringify([junk.errors, unknown.errors]));
  config.setOverride('webauthn.authenticatorAttachment', 'platform');
  try {
    const conflict = passkeyPolicy.save('default', withDefaults({
      passkeyHints: 'client-device,hybrid' }));
    t.check(!conflict.ok && /hybrid contradicts/.test(
              (conflict.errors || []).join(' ')),
            'P10e. with the attachment platform, hybrid on "Create a ' +
            'passkey" is refused', JSON.stringify(conflict.errors));
    t.check(sent('passkey') === '["client-device"]',
            'P10f. and the default list, stored before the attachment ' +
            'changed, loses the contradicting hint when sent',
            sent('passkey'));
  } finally {
    config.clearOverride('webauthn.authenticatorAttachment');
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving hints().');
}

function retired(t) {
  log.debug('Entering retired().');
  const keys = ['webauthn.usernameless', 'webauthn.residentKey'];
  const settings = config.SETTINGS.filter(function (row) {
    return keys.indexOf(row.key) >= 0;
  });
  const replaced = config.REPLACED_SETTINGS.filter(function (row) {
    return keys.indexOf(row.key) >= 0 &&
           /passkey policy/.test(row.now.join(' ')) && /#527/.test(row.why);
  });
  t.check(!settings.length && replaced.length === 2,
          'P6. webauthn.usernameless and webauthn.residentKey are no longer ' +
          'settings, and a start naming either is refused, naming the ' +
          'passkey policy\'s row', JSON.stringify(replaced.map(function (r) {
            return r.key + ' -> ' + r.now.join(', ');
          })));
  log.debug('Leaving retired().');
}

function kind(t) {
  log.debug('Entering kind().');
  const found = policyKinds.byId('passkey');
  t.check(!!found && found.container === 'ou=passkeyPolicies' &&
          policyKinds.actions().indexOf('save-passkey-policy') >= 0 &&
          policyKinds.actions().indexOf('reset-passkey-policy') >= 0,
          'P7. the fourth kind on Directory → Policies, with its two ' +
          'actions', JSON.stringify(policyKinds.actions()));
  const view = adminViews.policiesView({});
  t.check(!!view.passkey && view.passkey.fields.length === 10 &&
          view.passkey.fields.some(function (field) {
            return field.key === 'securityKeyResidentKey' &&
                   field.type === 'enum' && field.values.length === 3;
          }),
          'P7b. the page\'s view draws it from its fields',
          JSON.stringify(view.passkey && view.passkey.fields));
  const saved = adminActions.policiesAction(Object.assign(
    { action: 'save-passkey-policy' }, withDefaults()), { via: 'api' });
  t.check(saved.ok && saved.kind === 'passkey',
          'P7c. save-passkey-policy is handed to the passkey policy',
          JSON.stringify(saved.errors));
  adminActions.policiesAction({ action: 'reset-passkey-policy' },
                              { via: 'api' });
  log.debug('Leaving kind().');
}

module.exports = {
  name: 'passkey policy',
  describe: 'The passkey policy (#527): usernameless sign-in off by ' +
            'default, a security key asked for a discoverable credential, ' +
            'whole saves, inheritance from the default realm, the two ' +
            'retired settings, and the fourth kind on Directory → Policies',
  run: function (t) {
    log.debug('Entering run().');
    builtIn(t);
    saves(t);
    inheritance(t);
    answers(t);
    door(t);
    synced(t);
    pinLength(t);
    hints(t);
    retired(t);
    kind(t);
    log.debug('Leaving run().');
  }
};
