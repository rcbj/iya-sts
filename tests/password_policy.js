'use strict';
//
// File: password_policy.js
//
// ===========================================================================
// THE PASSWORD POLICY AND THE COST OF A PASSWORD HASH (2026-09-12).
//
// Two things this service decides when it is handed a password to keep:
//
//   1. **WHAT THE PASSWORD MUST BE.** The default profile of the password
//      policy — `cn=default,ou=passwordPolicies` in the realm's directory, or
//      the built-in defaults while nothing is stored — asks for a minimum
//      length, a symbol count, an uppercase letter and a digit, and refuses the
//      current password and the last N before it. ENFORCED IN PRODUCT MODE, at
//      every door that sets a password: `credentials.setPassword()` behind the
//      console, `/admin-api`, the portal and an activation link, and
//      `credentials.preparePassword()` behind an LDAP add or modify. A
//      GENERATED password is drawn to satisfy it in both modes. This section
//      was a length-only rule read from `security.passwordMinLength` for a few
//      hours on the same day; that setting is retired into the profile.
//   2. **THE SCRYPT COST WAS THREE CONSTANTS.** `security.passwordHashLogN`,
//      `…R` and `…P` decide what the NEXT hash is written under; the stored
//      form names its own parameters, so everything already stored keeps
//      verifying — which is the half worth asserting, since a cost change that
//      broke every existing password would be caught in a minute and one that
//      silently wrote weaker hashes would not.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS.
//
// The parent suite has no product-mode stack, so a refusal's only observable
// over HTTP is one no run could reach; what a hash was WRITTEN under, and what
// `pwdHistory` holds, are in the stored value, which no endpoint returns and
// none should; and the LDAP half needs a modify handler driven with a chosen
// entry state — a stored plaintext an older build left behind is not a state
// any door this service offers can produce.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldapjs = require('ldapjs');
const config = require('../common/config');
const crypto = require('../common/crypto');
const credentials = require('../common/credentials');
const passwordPolicy = require('../common/password_policy');
const ldap = require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminRbac = require('../admin-ui/admin_rbac');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'password_policy',
  level: process.env.LOG_LEVEL || 'info' });

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

// An attribute off the entry, whichever case the store handed it back in.
function attributeOf(username, name) {
  log.debug("Entering attributeOf().");
  const view = ldap.objectFor(username);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === name.toLowerCase();
  })[0];
  log.debug("Leaving attributeOf().");
  return key ? [].concat(attributes[key]).map(String) : [];
}

// The LDAP modify handler, called the way the socket calls it — the realm
// wrapper included, since that is what `localHandler()` hands back.
//
// `boundDn` is who is on the connection. Since 2026-09-12 product mode
// AUTHORIZES a directory write against it (`directoryWriteRefusal()`), so an
// anonymous modify is refused with 50 before the password policy is asked —
// section 1e binds as an administrator so that what it asserts is still the
// POLICY, which applies to an administrator exactly as to anybody else.
function ldapModify(dn, changes, boundDn) {
  log.debug("Entering ldapModify().");
  const handler = ldap.localHandler('modify');
  const req = {
    dn: ldapjs.parseDN(dn),
    changes: changes.map(function (one) {
      return { operation: one[0],
               modification: { type: one[1], values: one.slice(2) } };
    }),
    connection: { encrypted: false,
                  ldap: { bindDN: boundDn || 'cn=anonymous',
                          id: 'password-policy-test' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 },
    logId: 'password-policy-test'
  };
  const out = { ended: false, failure: null };
  handler(req, { end: function () {
    log.debug("Entering end().");
    out.ended = true;
    log.debug("Leaving end().");
  } },
          function (err) { if (err) { out.failure = err; } });
  log.debug("Leaving ldapModify().");
  return out;
}

function checkThePolicy(t, who) {
  log.debug("Entering checkThePolicy().");
  // -----------------------------------------------------------------------
  t.log.info('=== 1a. development records and does not refuse ===');
  passwordPolicy.reset('default');
  const devShort = credentials.setPassword(who, 'x');
  t.check(devShort.ok,
          'DEVELOPMENT mode sets a one-character password, as it always did ' +
          '— nothing there verifies one, so a rule about it would be a rule ' +
          'about a credential nothing reads', JSON.stringify(devShort.errors));
  t.check(credentials.setPassword(who, 'x').ok,
          'and sets the SAME password again: history is not enforced there ' +
          'either');
  t.check(attributeOf(who, 'pwdHistory').length === 1 &&
          /^\d{14}Z#1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.40#\d+#\$scrypt\$/
            .test(attributeOf(who, 'pwdHistory')[0]),
          'but the history IS RECORDED, in draft-behera\'s ' +
          'time#oid#length#data form holding the previous HASH — so a realm ' +
          'switched to product mode starts with ' +
          'one', attributeOf(who, 'pwdHistory')[0]);
  t.check(attributeOf(who, 'pwdChangedTime').length === 1,
          'and pwdChangedTime is stamped');

  // The Pwned Passwords screen off: this file is about the policy, and the
  // screen is tests/breached_passwords.js's (#62 P6).
  withSettings({ 'global.mode': 'product', 'risk.breachCheck': 'off' },
               function () {
    // ---------------------------------------------------------------------
    t.log.info('=== 1b. product mode: the composition rules ===');
    const short = credentials.setPassword(who, 'x');
    t.check(!short.ok && short.reason === 'password-policy',
            'PRODUCT mode REFUSES a password that breaks the profile',
            JSON.stringify(short));
    t.equal((short.problems || []).length, 4,
            'and names EVERY rule it breaks, not the first — length, symbol, ' +
            'uppercase and digit — so a person fixes it once');
    t.check(/\/admin\/policies/.test((short.errors || []).join(' ')),
            'with a sentence naming where the rules are',
            (short.errors || []).join(' '));
    t.check(!credentials.setPassword(who, 'Abcdefghij1').ok,
            'eleven characters with an uppercase letter, a digit and no ' +
            'symbol is refused');
    t.equal(credentials.passwordProblem('Abcdefghijk1'),
            'That password does not meet this realm\'s password policy, ' +
            'which asks for at least 1 symbol (it has 0). The rules are on ' +
            '/admin/policies (profile "default").',
            'and twelve with no symbol is refused for the symbol ALONE');
    t.check(credentials.passwordProblem('Abcdefghij1!') === '',
            'twelve with a symbol, an uppercase letter and a digit passes — ' +
            'the length boundary is "at least", not "more than"');
    t.check(credentials.passwordProblem('ΑβγδεζηθικΛ1!') === '',
            'Greek uppercase is an uppercase letter: the classes are ' +
            'Unicode\'s, not ASCII\'s');
    t.check(credentials.passwordProblem('😀😀😀😀😀😀😀😀😀😀A1') === '' &&
            credentials.passwordProblem('😀😀😀😀😀A1') !== '',
            'twelve code points are twelve characters — an emoji is one, and ' +
            'it is a symbol — and seven are seven, not fourteen UTF-16 units');
    t.check(credentials.passwordProblem('Abc def ghij1') !== '',
            'a SPACE is not a symbol, so a passphrase has to carry one');

    // ---------------------------------------------------------------------
    t.log.info('=== 1c. product mode: the history ===');
    t.check(credentials.setPassword(who, 'First-Passw0rd').ok,
            'a password that meets the profile is set');
    const again = credentials.setPassword(who, 'First-Passw0rd');
    t.check(!again.ok && again.reason === 'password-history',
            'the CURRENT password is refused as a new one',
            JSON.stringify(again));
    ['Second-Passw0rd', 'Third-Passw0rd', 'Fourth-Passw0rd', 'Fifth-Passw0rd',
     'Sixth-Passw0rd'].forEach(function (next) {
      credentials.setPassword(who, next);
    });
    t.equal(attributeOf(who, 'pwdHistory').length, 5,
            'five previous passwords are remembered under the default of ' +
            'five, and no more — the oldest fall off');
    t.check(credentials.setPassword(who, 'Second-Passw0rd').reason ===
              'password-history',
            'one of the last five is refused');
    t.check(credentials.setPassword(who, 'First-Passw0rd').reason ===
              'password-history',
            'and so is the FIFTH one back — pwdInHistory counts PREVIOUS ' +
            'passwords, and the current one is refused beside them');
    t.check(credentials.setPassword(who, 'Seventh-Passw0rd').ok &&
            credentials.setPassword(who, 'First-Passw0rd').ok,
            'one more change pushes it off the end, and it is allowed again');
    t.check(!/Second-Passw0rd|First-Passw0rd/.test(
              attributeOf(who, 'pwdHistory').join(' ')),
            'and no remembered value is a password — every one is a hash');

    const generated = credentials.generatePassword(who);
    t.equal(passwordPolicy.problemsWith(generated,
              passwordPolicy.read('default')).length, 0,
            'a GENERATED password always meets the profile', generated);
    t.check(!/["`]/.test(generated),
            'and carries neither of the two characters left out of the pool');
    t.check(credentials.setPassword(who, generated, { generated: true }).ok,
            'and is set, with the history comparison skipped');

    // ---------------------------------------------------------------------
    t.log.info('=== 1d. the profile is a directory entry ===');
    t.equal(passwordPolicy.read('default').stored, false,
            'with nothing stored, the built-in defaults are in force');
    const partial = passwordPolicy.save('default', { minLength: 4 });
    t.check(!partial.ok && partial.errors.length === 5,
            'a save that leaves fields out is refused by NAME for each, ' +
            'rather than resetting them — a save that quietly loosened a ' +
            'rule nobody mentioned is the mistake nobody ' +
            'sees', JSON.stringify(partial.errors));
    t.check(!passwordPolicy.save('strict', Object.assign({},
              passwordPolicy.DEFAULTS)).ok,
            'a profile other than default is refused: nothing assigns one yet');
    t.check(!passwordPolicy.save('default', Object.assign({},
              passwordPolicy.DEFAULTS,
              { minSymbols: 12, generatedLength: 20 })).ok,
            'a generated length that cannot reliably carry the symbol count ' +
            'is refused');
    const saved = passwordPolicy.save('default', {
      minLength: '8', history: '1', minSymbols: '0', requireUppercase: 'FALSE',
      requireDigit: true, generatedLength: 16 });
    t.check(saved.ok, 'a whole profile is saved, from form strings and JSON ' +
            'values alike', JSON.stringify(saved.errors));
    const stored = passwordPolicy.read('default');
    t.check(stored.stored &&
            /^cn=default,ou=passwordPolicies,/.test(stored.dn) &&
            stored.sources.minLength === 'directory' &&
            stored.minLength === 8 &&
            stored.requireUppercase === false,
            'and read back out of the DIRECTORY — every source says so',
            JSON.stringify(stored));
    const entryNames = Object.keys(
      (passwordPolicy.directoryInstalled().allPasswordPolicies()[0] || {})
        .attributes || {});
    t.check(['pwdMinLength', 'pwdInHistory', 'stsPwdMinSymbols',
             'stsPwdRequireUppercase'].every(function (name) {
              return entryNames.indexOf(name) >= 0;
            }),
            'and the entry is handed out in the schema\'s own spelling ' +
            'rather than the lower case the store keeps — which is what an ' +
            'ldapsearch and /admin/ldap/directory show, and what learnName() ' +
            'is given the schema for', entryNames.join(', '));
    t.check(credentials.setPassword(who, 'eightch1').ok,
            'the stored profile is what is ENFORCED: eight characters, a ' +
            'digit, nothing else');
    t.check(credentials.setPassword(who, 'eightch2').ok &&
            credentials.setPassword(who, 'eightch3').ok &&
            credentials.setPassword(who, 'eightch1').ok,
            'and a history of one refuses only the current and the one before');
    t.check(!credentials.setPassword(who, 'eightch1').ok,
            'which is still the current one');

    const reset = passwordPolicy.reset('default');
    t.check(reset.ok && reset.removed && !passwordPolicy.read('default').stored,
            'a reset deletes the entry and the built-in defaults are back');

    // ---------------------------------------------------------------------
    t.log.info('=== 1e. the LDAP door, in product mode ===');
    const probe = ldap.createUser('password-policy-ldap-probe', {});
    const operatorName = 'password-policy-ldap-operator';
    ldap.createUser(operatorName, { invent: false });
    const operator = ldap.objectFor(operatorName).entry.dn;
    const granted = adminRbac.grant(operatorName, 'write', { via: 'test' });
    const asOperator = function (dn, changes) {
      log.debug("Entering asOperator().");
      log.debug("Leaving asOperator().");
      return ldapModify(dn, changes, operator);
    };
    try {
      const weak = asOperator(probe.dn, [['replace', 'userPassword', 'weak']]);
      t.equal(weak.failure && weak.failure.code, 19,
              'an ldapmodify of a userPassword that breaks the profile is a ' +
              'CONSTRAINT VIOLATION (19), which is what a ppolicy server ' +
              'answers',
              weak.failure && weak.failure.message);
      t.equal(attributeOf('password-policy-ldap-probe', 'userPassword').length,
              0,
              'and the modify is atomic: nothing was written');
      const strong = asOperator(probe.dn,
                                [['replace', 'userPassword',
                                  'Ldap-Passw0rd!']]);
      t.check(!strong.failure && strong.ended, 'a password that meets it is ' +
                                               'accepted',
              strong.failure && strong.failure.message);
      const hashed = attributeOf('password-policy-ldap-probe',
                                 'userPassword')[0];
      t.check(/^\$scrypt\$/.test(hashed) &&
              crypto.verifySecret('Ldap-Passw0rd!', hashed),
              'and STORED AS A HASH — this door used to write the value ' +
              'verbatim, in the clear', String(hashed).slice(0, 20));
      t.check(credentials.verify('password-policy-ldap-probe',
                                 'Ldap-Passw0rd!').ok,
              'which the sign-in verifier accepts, so an LDAP-set password ' +
              'works');
      const unchanged = asOperator(probe.dn,
                                   [['replace', 'userPassword', hashed]]);
      t.check(!unchanged.failure,
              'writing the stored HASH back unchanged is not a password ' +
              'change, and is allowed even though a hash is otherwise refused',
              unchanged.failure && unchanged.failure.message);
      const reuse = asOperator(probe.dn,
                               [['replace', 'userPassword', 'Ldap-Passw0rd!']]);
      t.equal(reuse.failure && reuse.failure.code, 19,
              'but the same password sent in the CLEAR is a change to the ' +
              'current password, and is refused as one');
      const reused = asOperator(probe.dn,
        [['replace', 'userPassword', 'Ldap-Passw0rd!2']]);
      t.check(!reused.failure, 'a second password is accepted');
      const back = asOperator(probe.dn,
                              [['replace', 'userPassword', 'Ldap-Passw0rd!']]);
      t.equal(back.failure && back.failure.code, 19,
              'and the first one, sent in the clear again, meets its own ' +
              'HISTORY through the ' +
              'socket', back.failure && back.failure.message);
      const history = asOperator(probe.dn, [['delete', 'pwdHistory']]);
      t.equal(history.failure && history.failure.code, 19,
              'pwdHistory cannot be deleted over LDAP in product mode — a ' +
              'history anybody can empty is not a history');
      const prehashed = asOperator(probe.dn,
        [['replace', 'userPassword', crypto.hashSecret('whatever')]]);
      t.equal(prehashed.failure && prehashed.failure.code, 19,
              'and a PRE-HASHED value is refused: a hash cannot be checked ' +
              'against a policy');
      const two = asOperator(probe.dn,
                             [['add', 'userPassword', 'Another-Passw0rd!']]);
      t.equal(two.failure && two.failure.code, 19,
              'an ADD of a second userPassword is refused: two values would ' +
              'be an entry where the old password still works');
    } finally {
      if (granted && granted.ok !== false) {
        adminRbac.revoke(operatorName, 'write', { via: 'test' });
      }
    }
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 1f. the LDAP door, in development ===');
  const devProbe = ldap.createUser('password-policy-ldap-dev', {});
  const kept = crypto.hashSecret('moved-between-instances');
  t.check(!ldapModify(devProbe.dn,
                      [['replace', 'userPassword', kept]]).failure &&
          attributeOf('password-policy-ldap-dev', 'userPassword')[0] === kept,
          'development keeps a pre-hashed value as given, which is how a ' +
          'directory is moved between two instances of this service');
  t.check(!ldapModify(devProbe.dn,
                      [['replace', 'userPassword', 'x']]).failure &&
          /^\$scrypt\$/.test(
            attributeOf('password-policy-ldap-dev', 'userPassword')[0]),
          'and a clear value is still HASHED there — storing a password in ' +
          'the clear is a storage defect, not a permissiveness');

  // -----------------------------------------------------------------------
  t.log.info('=== 1g. a new user gets a generated password by default ===');
  const made = adminActions.usersAction({ action: 'create',
                                          username: 'password-policy-new',
                                          invent: 'no' }, { via: 'api' });
  t.check(made.ok && made.credential === 'generate' &&
          made.generated === true &&
          typeof made.password === 'string' &&
          passwordPolicy.problemsWith(made.password,
            passwordPolicy.read('default')).length === 0,
          'a create that names no credential GENERATES one, returns it once, ' +
          'and it meets the profile', JSON.stringify(
            { ok: made.ok, credential: made.credential, errors: made.errors }));
  t.check(credentials.verify('password-policy-new', made.password).ok,
          'and it is the password that was stored');
  const none = adminActions.usersAction({ action: 'create',
                                          username: 'password-policy-none',
                                          invent: 'no', credential: 'none' },
                                        { via: 'api' });
  t.check(none.ok && none.password === undefined && !none.passwordSet,
          '`credential: none` still creates a person holding nothing');
  log.debug("Leaving checkThePolicy().");
}

function run(t) {
  log.debug("Entering run().");
  const who = 'password-policy-probe';
  ldap.createUser(who, {});
  checkThePolicy(t, who);

  // -----------------------------------------------------------------------
  t.log.info('=== 2. the hash cost: new hashes only, and a floor ===');
  const defaults = crypto.scryptParameters();
  t.equal(defaults.N, 32768, 'unedited, N is 2^15 as it always was');
  t.equal(defaults.r + '/' + defaults.p, '8/1', 'and r and p are 8 and 1');
  const old = crypto.hashSecret('an-old-password');
  t.check(/^\$scrypt\$32768\$8\$1\$/.test(old),
          'a hash written now names the parameters it was written under',
          old.slice(0, 24));
  withSettings({ 'security.passwordHashLogN': 14, 'security.passwordHashR': 9 },
    function () {
      const newer = crypto.hashSecret('a-new-password');
      t.check(/^\$scrypt\$16384\$9\$1\$/.test(newer),
              'with the cost changed, the NEXT hash is written under the new ' +
              'parameters', newer.slice(0, 24));
      t.check(crypto.verifySecret('an-old-password', old),
              'and a hash written under the OLD parameters still verifies — ' +
              'the stored form names its own, so a cost change breaks nobody');
      t.check(crypto.verifySecret('a-new-password', newer) &&
              !crypto.verifySecret('a-wrong-password', newer),
              'and the new one verifies, and refuses a wrong password');
    });
  // THE FLOOR. `config.js` refuses a logN under 14 at every door it guards; the
  // clamp in crypto.js is what holds if a value reaches `config.value()` some
  // way the table did not check — which an environment variable at startup is
  // refused for, so this reaches under the table the one way a test can.
  let refused = '';
  try {
    config.setOverride('security.passwordHashLogN', '10');
  } catch (e) {
    refused = e.message;
  } finally {
    config.clearOverride('security.passwordHashLogN');
  }
  const check = config.checkOverride
    ? config.checkOverride('security.passwordHashLogN', '10') : 'no checker';
  t.check(!!refused || !!check,
          'a cost under the floor is refused by the settings table',
          refused || String(check));
  log.debug("Leaving run().");
  return crypto.hashSecretAsync('async-password').then(function (hashed) {
    t.check(/^\$scrypt\$32768\$8\$1\$/.test(hashed) &&
            crypto.verifySecret('async-password', hashed),
            'the asynchronous door writes the same parameters and the value ' +
            'verifies through the synchronous one', hashed.slice(0, 24));
    return withSettings({ 'security.passwordHashLogN': 14 }, function () {
      return crypto.hashSecretAsync('async-cheaper').then(function (cheaper) {
        t.check(/^\$scrypt\$16384\$8\$1\$/.test(cheaper) &&
                crypto.verifySecret('async-cheaper', cheaper),
                'and the job the worker pool is handed carries the ' +
                'configured parameters, encoded as the ones the derivation ' +
                'really used',
                cheaper.slice(0, 24));
      });
    });
  });
}

module.exports = {
  name: 'password_policy',
  describe: 'a minimum password length enforced where a password is ' +
            'verified, and the scrypt cost of a NEW hash as settings that ' +
            'leave every stored hash verifying',
  run: run
};
