'use strict';
//
// File: second_factor_doors.js
//
// ===========================================================================
// A SECOND FACTOR AT THE DOORS THAT CANNOT ASK FOR ONE, AND APP PASSWORDS
// (#101, 2026-09-22).
//
// In product mode a person who holds a second factor, or of whom one is
// required, is refused their own RIGHT password at the five password-only
// doors — an LDAP bind, a WS-Security UsernameToken, SCIM, SSF and EST Basic
// — answered exactly as a wrong password, and an APP PASSWORD scoped to the
// door is accepted there instead. This file holds the verifier to that, in
// process, where the code a refusal carries can be read back:
//
//   A. `credentials.verify()` and `verifyAsync()` at each of the five doors:
//      a person holding a security key in the `mfa` role, one required by
//      their entry (stsMfaRequired), everybody required by the realm
//      (the authentication policy) — refused STS-AUTHN-0213 with `ok: false`, the
//      shape a wrong password has; a person with neither is verified; the two
//      declared exemptions (`asked-next`, `session-held`) pass; and
//      `authn.passwordAloneDoors` admits exactly the doors it lists;
//   B. development mode is unchanged;
//   C. a real LDAP bind (`performOperation`) answers invalidCredentials for
//      the refusal and for a wrong password alike, and the refusal counts as
//      a failure against the bind rate limit;
//   D. EST's person authentication (`authenticatePerson()`) answers its one
//      401 for both;
//   E. app passwords: made (hashed, shown once), accepted only at their doors,
//      refused at the sign-in screen (no door) — even as `asked-next` — and
//      at a door outside their scope, last use recorded, refused on a
//      disabled account, surviving a password reset, revoked; the creation
//      refusals each with their code;
//   F. the console's and the API's half: `usersAction()` makes and revokes
//      one, the answer carries the password once, and `appPasswordsJson()`
//      pages the list and never carries a hash;
//   G. an application's secret is not a person's account.
//
// WHY IN PROCESS: the code on a refusal is recorded and never sent, so over
// HTTP a refusal and a wrong password are — deliberately — the same answer.
// `tests/vendored/sts_second_factor_doors.js` drives the five doors over the
// wire against both modes' containers.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const credentials = require('../common/credentials');
const appPasswords = require('../common/app_passwords');
const errorCodes = require('../common/error_codes');
const websecurity = require('../common/websecurity');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const certEnrollment = require('../common/cert_enrollment');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
// #64: a second factor required of everybody is the authentication policy's
// `requireSecondFactor: always` now — it was the `authn.mfaRequired` setting.
const authnPolicy = require('../common/authn_policy');

const log = require('bunyan').createLogger({ name: 'second_factor_doors',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const PASSWORD = 'Sfd-' + STAMP + '-Correct.Horse.Battery.Staple.42';
const WRONG = PASSWORD + '-wrong';
const DOORS = ['ldap', 'wstrust', 'scim', 'ssf', 'est'];

const KEYED = 'sfd-keyed-' + STAMP;       // holds an mfa security key
const FLAGGED = 'sfd-flagged-' + STAMP;   // stsMfaRequired on the entry
const PLAIN = 'sfd-plain-' + STAMP;       // neither
const APPUSER = 'sfd-app-' + STAMP;       // app passwords

let addressCounter = 0;

// A VALUE AS THE APPCONFIG FILE OR THE ENVIRONMENT WOULD GIVE IT (#86). A
// write through `config.setOverride()` of a value outside the setting's
// `csvValues` is refused now, so the reader's own defence — dropping a name it
// does not know — is reached only by a value that arrived by a layer nobody
// checks on write. `config.value()` is answered for this one key for the
// length of `fn`, which is exactly that. Every key it is used for is a
// `csv` row.
function withReadValue(key, raw, fn) {
  log.debug("Entering withReadValue().");
  const was = config.value;
  // A csv row's parse, done here: `config.parseAs()` runs the same check
  // the write does and would refuse the value this exists to deliver.
  const parsed = String(raw).split(',').map(function (part) {
    return part.trim();
  }).filter(function (part) {
    return part.length > 0;
  });
  config.value = function (asked) {
    return asked === key ? parsed : was.apply(config, arguments);
  };
  try {
    log.debug("Leaving withReadValue().");
    return fn();
  } finally {
    config.value = was;
  }
}

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// The authentication policy with `requireSecondFactor: always` for the length
// of `fn`, and this realm's own profile removed again after it.
function withEverybodyRequired(fn) {
  log.debug("Entering withEverybodyRequired().");
  const saved = authnPolicy.save('default', Object.assign({},
    authnPolicy.DEFAULTS, { requireSecondFactor: 'always' }));
  if (!saved.ok) {
    throw new Error('the authentication policy was not saved: ' +
                    JSON.stringify(saved.errors));
  }
  try {
    log.debug("Leaving withEverybodyRequired().");
    return fn();
  } finally {
    authnPolicy.reset('default');
  }
}

async function withSettingsAsync(pairs, fn) {
  log.debug("Entering withSettingsAsync().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettingsAsync().");
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// A fresh address per bind, so the bind limiter's ADDRESS bucket never
// decides a check it is not the subject of.
function nextAddress() {
  log.debug("Entering nextAddress().");
  addressCounter += 1;
  log.debug("Leaving nextAddress().");
  return '198.51.100.' + (addressCounter % 250 + 1);
}

async function bind(dn, password) {
  log.debug("Entering bind().");
  const result = await Promise.resolve(ldap.performOperation('bind', {
    dn: dn, boundDn: '', channel: 'ldaps', credentials: password,
    remoteAddress: nextAddress()
  }));
  log.debug("Leaving bind().");
  return result;
}

function person(name) {
  log.debug("Entering person().");
  ldap.createUser(name, { invent: false });
  const set = credentials.setPassword(name, PASSWORD);
  log.debug("Leaving person().");
  return set;
}

function sameAsWrong(t, name, door, what) {
  log.debug("Entering sameAsWrong().");
  const right = credentials.verify(name, PASSWORD, { via: 'test ' + door,
                                                     door: door });
  const wrong = credentials.verify(name, WRONG, { via: 'test ' + door,
                                                  door: door });
  t.check(right.ok === false && wrong.ok === false,
          what + ' at ' + door + ': the right password is refused, as a ' +
          'wrong one is', JSON.stringify({ right: right, wrong: wrong }));
  t.equal(errorCodes.codeOf(right), 'STS-AUTHN-0213',
          what + ' at ' + door + ': the refusal is recorded as ' +
          'STS-AUTHN-0213');
  t.equal(right.reason, 'second-factor-required',
          what + ' at ' + door + ': and its reason says why, for the log');
  log.debug("Leaving sameAsWrong().");
}

async function run(t) {
  log.debug("Entering run().");
  websecurity.reset();
  [KEYED, FLAGGED, PLAIN, APPUSER].forEach(function (name) {
    const set = person(name);
    t.check(set && set.ok !== false, 'precondition: ' + name + ' has a ' +
                                     'password', JSON.stringify(set));
  });
  const key = credentials.addKey(KEYED, {
    credentialId: 'sfd-key-' + STAMP, label: 'sfd key',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
    signCount: 0 }, 'mfa');
  t.check(key && key.ok !== false, 'precondition: ' + KEYED + ' holds a ' +
                                   'security key in the mfa role',
          JSON.stringify(key));
  const flagged = credentials.setMfaRequired(FLAGGED, true);
  t.check(flagged.ok, 'precondition: a second factor is required of ' +
                      FLAGGED + ' on their entry', JSON.stringify(flagged));

  // -------------------------------------------------------------------------
  t.log.info('=== B. development mode is unchanged ===');
  DOORS.forEach(function (door) {
    const dev = credentials.verify(KEYED, PASSWORD, { door: door });
    t.check(dev.ok === true && dev.reason === 'development-mode',
            'B. development accepts ' + KEYED + '\'s password at ' + door,
            JSON.stringify(dev));
  });
  t.check((await bind(ldap.objectFor(KEYED).entry.dn, PASSWORD)).ok === true,
          'B. and a development LDAP bind with it succeeds');
  t.equal(credentials.passwordOnlyDoors(KEYED).refused.length, 0,
          'B. and no door is reported as refusing it');

  // -------------------------------------------------------------------------
  t.log.info('=== A. product: the five doors ===');
  withSettings({ 'global.mode': 'product' }, function () {
    DOORS.forEach(function (door) {
      sameAsWrong(t, KEYED, door, 'A1. a person holding an mfa key');
      sameAsWrong(t, FLAGGED, door, 'A2. a person required by their entry');
      const plain = credentials.verify(PLAIN, PASSWORD, { door: door });
      t.check(plain.ok === true && plain.reason === 'verified',
              'A3. a person with no second factor is verified at ' + door,
              JSON.stringify(plain));
    });
    const unstated = credentials.verify(KEYED, PASSWORD, { via: 'a door ' +
                                                          'added tomorrow' });
    t.equal(errorCodes.codeOf(unstated), 'STS-AUTHN-0213',
            'A4. REFUSE BY DEFAULT: a caller that states no door and no ' +
            'exemption is refused too');
    ['asked-next', 'session-held'].forEach(function (declared) {
      const exempt = credentials.verify(KEYED, PASSWORD,
                                        { secondFactor: declared });
      t.check(exempt.ok === true && exempt.reason === 'verified',
              'A5. a caller that declares "' + declared + '" is verified',
              JSON.stringify(exempt));
    });
    t.check(credentials.verify(KEYED, WRONG, { secondFactor: 'asked-next' })
      .ok === false, 'A5. and the exemption is not a pass: a wrong password ' +
                     'is still wrong');
    withEverybodyRequired(function () {
      sameAsWrong(t, PLAIN, 'scim', 'A6. everybody required by the realm');
    });
    t.check(config.setOverride('authn.passwordAloneDoors', 'ldap,bogus').ok ===
            false, 'A7. a write naming something that is not a door is ' +
            'refused (#86)', config.text('authn.passwordAloneDoors'));
    withReadValue('authn.passwordAloneDoors', 'ldap,bogus', function () {
      const listed = credentials.verify(KEYED, PASSWORD, { door: 'ldap' });
      t.check(listed.ok === true && listed.reason === 'verified',
              'A7. authn.passwordAloneDoors admits the door it lists',
              JSON.stringify(listed));
      sameAsWrong(t, KEYED, 'scim', 'A7. and only that door —');
      const doors = credentials.passwordOnlyDoors(KEYED);
      t.check(doors.refused.join(',') === 'wstrust,scim,ssf,est' &&
              doors.alone.join(',') === 'ldap',
              'A7. passwordOnlyDoors() reports it, and drops a name that is ' +
              'not a door', JSON.stringify(doors));
    });
    const doors = credentials.passwordOnlyDoors(KEYED);
    t.equal(doors.refused.join(','), DOORS.join(','),
            'A8. passwordOnlyDoors() names all five for a second-factor ' +
            'person');
    t.equal(credentials.passwordOnlyDoors(PLAIN).refused.length, 0,
            'A8. and none for a person with no second factor');
  });
  await withSettingsAsync({ 'global.mode': 'product' }, async function () {
    const refusedAsync = await credentials.verifyAsync(KEYED, PASSWORD,
                                                       { door: 'est' });
    t.equal(errorCodes.codeOf(refusedAsync), 'STS-AUTHN-0213',
            'A9. verifyAsync() refuses it the same way');
    const plainAsync = await credentials.verifyAsync(PLAIN, PASSWORD,
                                                     { door: 'est' });
    t.check(plainAsync.ok === true, 'A9. and verifies a person with none');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== C. a real LDAP bind ===');
  await withSettingsAsync({ 'global.mode': 'product' }, async function () {
    websecurity.reset();
    const dn = ldap.objectFor(KEYED).entry.dn;
    const right = await bind(dn, PASSWORD);
    const wrong = await bind(dn, WRONG);
    t.check(right.ok === false && wrong.ok === false &&
            right.errorName === wrong.errorName &&
            right.errorName === 'InvalidCredentialsError',
            'C1. an LDAP bind with the right password answers ' +
            'invalidCredentials (49), exactly as a wrong one does',
            JSON.stringify({ right: right.errorName, wrong: wrong.errorName }));
    // The limit: each refusal is a FAILURE in the identity bucket, so after
    // the limit even a verified bind for that DN is refused as locked out.
    websecurity.reset();
    const limit = Number(config.value('security.rateLimitPerIdentity')) || 5;
    for (let i = 0; i < limit + 1; i++) {
      await bind(dn, PASSWORD);
    }
    const plainDn = ldap.objectFor(PLAIN).entry.dn;
    t.check((await bind(plainDn, PASSWORD)).ok === true,
            'C2. (another person is not affected)');
    const after = await bind(dn, PASSWORD);
    t.check(after.ok === false && after.errorName !== 'InvalidCredentialsError',
            'C2. the refusals COUNT against the bind rate limit: after ' +
            (limit + 1) + ' of them the DN is locked out like a guesser',
            JSON.stringify(after));
    websecurity.reset();
  });

  // -------------------------------------------------------------------------
  t.log.info('=== D. EST Basic ===');
  await withSettingsAsync({ 'global.mode': 'product' }, async function () {
    const right = await certEnrollment.authenticatePerson(KEYED, PASSWORD,
                                                          'est-basic');
    const wrong = await certEnrollment.authenticatePerson(KEYED, WRONG,
                                                          'est-basic');
    t.check(!right.ok && !wrong.ok && right.status === wrong.status &&
            JSON.stringify(right.errors) === JSON.stringify(wrong.errors),
            'D1. EST refuses the right password with the same 401 and ' +
            'sentence as a wrong one', JSON.stringify({ right: right,
                                                        wrong: wrong }));
    const plain = await certEnrollment.authenticatePerson(PLAIN, PASSWORD,
                                                          'est-basic');
    t.check(plain.ok, 'D2. and accepts a person with no second factor',
            JSON.stringify(plain));
  });

  // -------------------------------------------------------------------------
  t.log.info('=== E. app passwords ===');
  const made = credentials.createAppPassword(APPUSER, {
    name: 'mail client', doors: ['ldap', 'scim'], createdBy: APPUSER });
  t.check(made.ok && /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/.test(made.password),
          'E1. an app password is made: twenty-four characters in six ' +
          'groups', JSON.stringify(made));
  t.equal(made.doors.join(','), 'ldap,scim', 'E1. scoped to the doors asked');
  const raw = ldap.objectFor(APPUSER).entry.attributes;
  const storedKey = Object.keys(raw).filter(function (k) {
    return k.toLowerCase() === 'stsapppassword';
  })[0];
  const stored = String((raw[storedKey] || [])[0] || '');
  t.check(/\$scrypt\$/.test(stored) &&
          stored.indexOf(made.password.replace(/-/g, '')) < 0,
          'E2. what is stored is a scrypt hash, never the password',
          stored.slice(0, 120));
  const listed = credentials.appPasswordsOf(APPUSER).passwords;
  t.check(listed.length === 1 && listed[0].id === made.id &&
          !('hash' in listed[0]) && !('password' in listed[0]),
          'E3. the list carries the id, never the hash or the password',
          JSON.stringify(listed));
  credentials.addKey(APPUSER, {
    credentialId: 'sfd-appkey-' + STAMP, label: 'k',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
    signCount: 0 }, 'mfa');

  await withSettingsAsync({ 'global.mode': 'product' }, async function () {
    websecurity.reset();
    ['ldap', 'scim'].forEach(function (door) {
      const ok = credentials.verify(APPUSER, made.password, { door: door });
      t.check(ok.ok === true && ok.reason === 'app-password' &&
              ok.appPassword && ok.appPassword.id === made.id,
              'E4. accepted at ' + door + ', and the answer says it was an ' +
              'app password', JSON.stringify(ok));
    });
    const lower = credentials.verify(APPUSER,
      made.password.toLowerCase().replace(/-/g, ' '), { door: 'ldap' });
    t.check(lower.ok === true, 'E4. case and the printed separators are ' +
                               'forgiven');
    ['wstrust', 'ssf', 'est'].forEach(function (door) {
      const out = credentials.verify(APPUSER, made.password, { door: door });
      t.check(out.ok === false && errorCodes.codeOf(out) === 'STS-AUTHN-0214',
              'E5. refused at ' + door + ', outside its scope (' +
              'STS-AUTHN-0214)', JSON.stringify(out));
    });
    const signIn = credentials.verify(APPUSER, made.password,
      { via: 'the sign-in screen', allowPasswordReset: true,
        secondFactor: 'asked-next' });
    t.check(signIn.ok === false && errorCodes.codeOf(signIn) ===
            'STS-AUTHN-0214',
            'E6. NEVER at the sign-in screen, whose call names no door',
            JSON.stringify(signIn));
    const asyncOk = await credentials.verifyAsync(APPUSER, made.password,
                                                  { door: 'scim' });
    t.check(asyncOk.ok === true && asyncOk.reason === 'app-password',
            'E7. verifyAsync() accepts it the same way',
            JSON.stringify(asyncOk));
    const tampered = made.password.slice(0, 5) +
      (made.password[5] === 'A' ? 'B' : 'A') + made.password.slice(6);
    const bad = credentials.verify(APPUSER, tampered, { door: 'ldap' });
    t.check(bad.ok === false && errorCodes.codeOf(bad) === 'STS-AUTHN-0054',
            'E8. one character wrong, with the right id, is a wrong password',
            JSON.stringify(bad));
    const own = credentials.verify(APPUSER, PASSWORD, { door: 'ldap' });
    t.equal(errorCodes.codeOf(own), 'STS-AUTHN-0213',
            'E9. while their own password is refused at the same door');
    const bound = await bind(ldap.objectFor(APPUSER).entry.dn, made.password);
    t.check(bound.ok === true, 'E10. a real LDAP bind with it succeeds',
            JSON.stringify(bound));
  });
  const used = credentials.appPasswordsOf(APPUSER).passwords[0];
  t.check(used.lastUsedAt > 0 && !!used.lastUsedDoor,
          'E11. its last use is recorded, with the door',
          JSON.stringify(used));

  withSettings({ 'global.mode': 'product' }, function () {
    credentials.setAccountDisabled(APPUSER, true);
    const disabled = credentials.verify(APPUSER, made.password,
                                        { door: 'ldap' });
    credentials.setAccountDisabled(APPUSER, false);
    t.check(disabled.ok === false && errorCodes.codeOf(disabled) ===
            'STS-AUTHN-0200',
            'E12. a disabled account refuses it (STS-AUTHN-0200)',
            JSON.stringify(disabled));
    const reset = credentials.setPassword(APPUSER, PASSWORD + '-Next!9');
    t.check(reset.ok !== false, 'precondition: the password is reset',
            JSON.stringify(reset));
    t.check(credentials.verify(APPUSER, made.password, { door: 'scim' }).ok,
            'E13. and it survives a password reset');
  });

  // The creation refusals, each with its code.
  const refusal = function (spec, code, what) {
    log.debug("Entering refusal().");
    const out = credentials.createAppPassword(spec.user || APPUSER, spec);
    t.check(out.ok === false && errorCodes.codeOf(out) === code,
            'E14. ' + what + ' is refused (' + code + ')',
            JSON.stringify(out));
    log.debug("Leaving refusal().");
  };
  refusal({ name: '', doors: ['ldap'] }, 'STS-AUTHN-0215', 'no name');
  refusal({ name: 'x'.repeat(65), doors: ['ldap'] }, 'STS-AUTHN-0215',
          'a name over sixty-four characters');
  refusal({ name: 'mail client', doors: ['ldap'] }, 'STS-AUTHN-0215',
          'a name already held');
  refusal({ name: 'nodoor', doors: [] }, 'STS-AUTHN-0216', 'no door');
  refusal({ name: 'baddoor', doors: ['ldap', 'kerberos'] }, 'STS-AUTHN-0216',
          'a door that is not one of the five');
  refusal({ user: 'sfd-nobody-' + STAMP, name: 'n', doors: ['ldap'] },
          'STS-AUTHN-0061', 'somebody who does not exist');
  withSettings({ 'appPasswords.enabled': 'false' }, function () {
    refusal({ name: 'off', doors: ['ldap'] }, 'STS-AUTHN-0218',
            'a make while app passwords are turned off');
  });
  withSettings({ 'appPasswords.maxPerPerson': '1' }, function () {
    refusal({ name: 'second', doors: ['ldap'] }, 'STS-AUTHN-0217',
            'a make past appPasswords.maxPerPerson');
  });

  const revoked = credentials.revokeAppPassword(APPUSER, made.id);
  t.check(revoked.ok && revoked.revoked.id === made.id,
          'E15. it is revoked by its id', JSON.stringify(revoked));
  withSettings({ 'global.mode': 'product' }, function () {
    const after = credentials.verify(APPUSER, made.password, { door: 'ldap' });
    t.check(after.ok === false && errorCodes.codeOf(after) === 'STS-AUTHN-0054',
            'E15. and after that it is only a wrong password',
            JSON.stringify(after));
  });
  const again = credentials.revokeAppPassword(APPUSER, made.id);
  t.equal(errorCodes.codeOf(again), 'STS-AUTHN-0219',
          'E16. revoking it again is refused (STS-AUTHN-0219)');

  // -------------------------------------------------------------------------
  t.log.info('=== F. the console and the API ===');
  const byAdmin = adminActions.usersAction({
    action: 'create-app-password', user: APPUSER, name: 'scim job',
    doors: ['scim', 'ssf'] }, { via: 'api', actor: 'sfd-admin' });
  t.check(byAdmin.ok && /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/.test(
            String(byAdmin.appPassword)) && !('password' in byAdmin) &&
          byAdmin.doors.join(',') === 'scim,ssf',
          'F1. POST /admin-api/users/create-app-password makes one and ' +
          'answers it ONCE', JSON.stringify(byAdmin));
  const byForm = adminActions.usersAction({
    action: 'create-app-password', user: APPUSER, name: 'est device',
    door_est: 'on', door_ldap: 'on' }, { via: 'console', actor: 'sfd-admin' });
  t.check(byForm.ok && byForm.doors.join(',') === 'ldap,est',
          'F2. the console\'s one-checkbox-per-door form scopes it',
          JSON.stringify(byForm));
  const page = adminViews.appPasswordsJson({ user: APPUSER, per: '1' });
  t.check(page.total === 2 && page.passwords.length === 1 &&
          page.pages === 2 && JSON.stringify(page).indexOf('$scrypt$') < 0 &&
          JSON.stringify(page).indexOf(byAdmin.appPassword) < 0,
          'F3. GET /admin-api/users/app-passwords is paged and carries no ' +
          'hash and no password', JSON.stringify(page));
  const mfa = adminViews.mfaJson(APPUSER);
  t.check(mfa && Array.isArray(mfa.appPasswords) &&
          mfa.appPasswords.length === 2 && mfa.passwordOnlyDoors &&
          typeof mfa.passwordOnlyDoors.sentence === 'string',
          'F4. the person\'s /admin/users factors carry the list and the ' +
          'doors sentence', JSON.stringify(mfa && mfa.passwordOnlyDoors));
  const gone = adminActions.usersAction({
    action: 'revoke-app-password', user: APPUSER, id: byAdmin.id },
    { via: 'api', actor: 'sfd-admin' });
  t.check(gone.ok && gone.revoked.id === byAdmin.id,
          'F5. POST /admin-api/users/revoke-app-password revokes it',
          JSON.stringify(gone));
  const missing = adminActions.usersAction({
    action: 'revoke-app-password', user: APPUSER, id: 'ZZZZ' },
    { via: 'api', actor: 'sfd-admin' });
  t.check(missing.ok === false && errorCodes.codeOf(missing) ===
          'STS-AUTHN-0219',
          'F6. and one they do not hold is refused with the store\'s code',
          JSON.stringify(missing));

  // -------------------------------------------------------------------------
  t.log.info('=== G. an application is not a person ===');
  const appId = 'sfd-application-' + STAMP;
  const createdApp = applications.createApplication({ identifier: appId,
    protocols: ['oauth2'], fields: { oauthClientId: appId } });
  t.check(createdApp && createdApp.ok !== false,
          'precondition: an application entry exists',
          JSON.stringify(createdApp && createdApp.errors));
  const appView = applications.get(appId) || {};
  const appDn = String(appView.dn || '');
  t.check(!!appDn, 'precondition: the application has a DN', appDn);
  const appMade = credentials.createAppPassword(appDn, {
    name: 'x', doors: ['ldap'] });
  t.check(appMade.ok === false &&
          ['STS-AUTHN-0221', 'STS-AUTHN-0061'].indexOf(
            errorCodes.codeOf(appMade)) >= 0,
          'G1. an application is not given an app password',
          JSON.stringify(appMade));
  withSettings({ 'global.mode': 'product' }, function () {
    withEverybodyRequired(function () {
      const doors = credentials.passwordOnlyDoors(appDn);
      t.check(doors.secondFactor === false && doors.refused.length === 0,
              'G2. and its secret is not a person\'s account: even with the ' +
              'realm requiring a second factor, no door refuses it on that ' +
              'ground — the entry\'s KIND decides, not its name',
              JSON.stringify(doors));
    });
  });
  t.check(appPasswords.DOOR_IDS.join(',') === DOORS.join(','),
          'G3. the five doors are the five this file drives');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'second_factor_doors',
  describe: 'Product mode refuses a second-factor person\'s own password at ' +
            'the five password-only doors (LDAP, WS-Trust, SCIM, SSF, EST) ' +
            'as a wrong password, and accepts an app password scoped to the ' +
            'door: made, hashed, scoped, never at the sign-in screen, last ' +
            'use recorded, disabled and reset handled, revoked, through the ' +
            'store, the console and the API',
  run: run
};
