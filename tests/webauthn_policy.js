'use strict';
//
// File: webauthn_policy.js
//
// ===========================================================================
// THE WEBAUTHN SETTINGS, AND THE FOUR THINGS THAT GO WRONG QUIETLY
// (2026-09-10).
//
// `authn/webauthn_policy.ts` turned thirteen literals in a string into
// settings. Twelve of them are values passed to a browser, and a browser is not
// something a test can hold — so what this file asserts is not *does the
// ceremony work* (that needs an authenticator, and
// `tests/webauthn_cross_impl.js` in the debugger repository is where a real
// ceremony is verified) but the four places where a settings layer over a
// ceremony fails SILENTLY.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Every claim below is about what this service DECIDES rather than about what
// it serves, and three of the four are unreachable over HTTP:
//
//   * **THE OFFER CAN NEVER NAME AN ALGORITHM THE VERIFIER CANNOT CHECK.** A
//     `pubKeyCredParams` entry this service does not know produces a credential
//     that registers perfectly and then fails EVERY assertion it is ever used
//     for — at sign-in, weeks later, on somebody else's machine. Nothing at the
//     enrolment says anything is wrong. The two tables are in two modules, so
//     the only way this stays true is that one is derived from the other.
//
//   * **AN EMPTY OFFER IS WORSE THAN A WRONG ONE.** `pubKeyCredParams: []` is
//     refused by the browser, and the error a WebAuthn ceremony reports is the
//     same one it reports for a declined prompt, a missing authenticator and a
//     timeout — so one typo in one setting looks exactly like broken hardware.
//
//   * **`authenticatorAttachment` MUST BE ABSENT AND NOT `"any"`.** The options
//     dictionary has no value meaning *no preference*; sending the string is a
//     validation error in the browser, which is the same indistinguishable
//     failure again.
//
//   * **THE RP ID SUFFIX RULE IS FOUR LINES AND `endsWith()` ALONE IS WRONG.**
//     `mple.com` is a string suffix of `example.com` and is not a domain suffix
//     of it. That is the exact confusion WebAuthn's binding exists to prevent,
//     and the value only ever appears inside a ceremony a browser performs, so
//     no HTTP request can ask what it was.
//
// The fifth section is the POLICY half, which is not WebAuthn at all: what this
// service will do with a key. That one COULD be driven over HTTP and is worth
// having here anyway, for the reason `tests/roles.js` gives — the refusal has
// to be at the one place a key is written, and asserting it at a door proves it
// for that door only.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const credentials = require('../common/credentials');
const webauthn = require('../authn/webauthn');
const policy = require('../authn/webauthn_policy');
const ldap = require('../ldap/ldap_server');
const authn = require('../authn/authn');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'webauthn_policy',
  level: process.env.LOG_LEVEL || 'info' });

// A setting for the duration of one call, put back afterwards. `reset` and not
// a write of the old value back, which is the rule every test here follows: a
// setting that had no override before must end with none, and writing the value
// back would leave one behind that reads identically and behaves differently
// the moment a layer under it changes.
function withSetting(key, value, fn) {
  log.debug("Entering withSetting().");
  config.setOverride(key, value);
  try {
    log.debug("Leaving withSetting().");
    return fn();
  } finally {
    config.clearOverride(key);
  }
}

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

function aKey(id) {
  log.debug("Entering aKey().");
  log.debug("Leaving aKey().");
  return { credentialId: id,
           publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
           signCount: 0, label: id };
}

function run(t) {
  log.debug("Entering run().");
  // -------------------------------------------------------------------------
  t.log.info('=== the offer is derived from the verifier and cannot outrun ' +
             'it ===');
  // -------------------------------------------------------------------------
  const verifiable = Object.keys(webauthn.COSE_ALGS).map(function (id) {
    return webauthn.COSE_ALGS[id];
  });
  t.check(policy.algorithmsOffered().every(function (name) {
    return verifiable.indexOf(name) >= 0;
  }), 'every algorithm offered by default is one the verifier can check',
  policy.algorithmsOffered().join(', '));

  t.check(config.setOverride('webauthn.algorithms', 'ES256,NOSUCHALG').ok ===
          false,
          'A WRITE NAMING AN ALGORITHM THE VERIFIER DOES NOT KNOW IS REFUSED ' +
          '(#86) — the setting\'s csvValues are the verifier\'s own names',
          config.text('webauthn.algorithms'));
  withReadValue('webauthn.algorithms', 'ES256,NOSUCHALG,RS256', function () {
    const offered = policy.algorithmsOffered();
    t.check(offered.indexOf('NOSUCHALG') < 0,
      'AN ALGORITHM THE VERIFIER DOES NOT KNOW IS DROPPED FROM THE OFFER — ' +
      'sending it would enrol a credential that registers perfectly and then ' +
      'fails every assertion it is ever used for, at sign-in rather than at ' +
      'enrolment', offered.join(', '));
    t.check(offered.length === 2 && offered[0] === 'ES256' &&
            offered[1] === 'RS256',
      'and the ones beside it survive IN THE ORDER THEY WERE GIVEN, because ' +
      'pubKeyCredParams is a preference list', offered.join(', '));
  });

  withReadValue('webauthn.algorithms', 'NOSUCHALG,ALSONOT', function () {
    const offered = policy.algorithmsOffered();
    t.check(offered.length > 0,
      'A SETTING THAT NAMES NOTHING USABLE FALLS BACK RATHER THAN OFFERING ' +
      'AN EMPTY LIST — an empty pubKeyCredParams is refused by the browser ' +
      'with the same error it reports for a declined prompt, a missing ' +
      'authenticator and a timeout, so one typo would look like broken ' +
      'hardware', offered.join(', '));
    t.check(policy.creationOptions('localhost').algorithms.length > 0,
      'and the options handed to the browser carry those COSE identifiers');
  });

  withSetting('webauthn.algorithms', 'ES256,ES256', function () {
    t.check(policy.algorithmsOffered().length === 1,
      'a name given twice is offered once — a repeated pubKeyCredParams ' +
      'entry is not an error and is not a preference either');
  });

  t.check(Object.keys(policy.ALG_IDS).length === verifiable.length,
    'the JOSE-name table is the verifier\'s COSE table inverted, entry for ' +
    'entry, so an algorithm added to authn/webauthn.js becomes offerable ' +
    'without anything here being edited',
    Object.keys(policy.ALG_IDS).join(', '));

  // -------------------------------------------------------------------------
  t.log.info('=== the ceremony options a browser will actually accept ===');
  // -------------------------------------------------------------------------
  withSetting('webauthn.authenticatorAttachment', 'any', function () {
    const opts = policy.creationOptions('localhost');
    t.check(!Object.prototype.hasOwnProperty
              .call(opts.authenticatorSelection, 'authenticatorAttachment'),
      'WITH NO PREFERENCE THE MEMBER IS ABSENT AND NOT THE STRING "any" — ' +
      'the options dictionary has no value meaning no preference, and ' +
      'sending one is a validation error in the browser rather than a wide ' +
      'filter',
      JSON.stringify(opts.authenticatorSelection));
  });
  withSetting('webauthn.authenticatorAttachment', 'cross-platform',
              function () {
    t.check(policy.creationOptions('localhost')
              .authenticatorSelection.authenticatorAttachment === 'cross-platform',
      'and a real preference IS sent');
  });

  // THE PERSON'S CHOICE ON /portal/keys (2026-09-26): which kind of
  // authenticator the enrolment asks for, narrowing the request only while
  // the realm's setting leaves the choice open.
  withSetting('webauthn.authenticatorAttachment', 'any', function () {
    withSetting('webauthn.residentKey', 'discouraged', function () {
      const built = policy.creationOptions('localhost', 'platform')
        .authenticatorSelection;
      const carried = policy.creationOptions('localhost', 'roaming')
        .authenticatorSelection;
      const neither = policy.creationOptions('localhost', 'bogus')
        .authenticatorSelection;
      t.check(built.authenticatorAttachment === 'platform' &&
              built.residentKey === 'preferred' &&
              built.requireResidentKey === false,
        'a key BUILT INTO THIS DEVICE asks for the platform authenticator ' +
        'and a discoverable credential (preferred), because "discouraged" ' +
        'is what sends Chrome and Edge to a USB key and never the device',
        JSON.stringify(built));
      t.check(carried.authenticatorAttachment === 'cross-platform' &&
              carried.residentKey === 'discouraged',
        'a key THEY CARRY asks for a roaming authenticator and keeps the ' +
        'setting\'s resident-key answer — its slot argument is about them',
        JSON.stringify(carried));
      t.check(!Object.prototype.hasOwnProperty
                .call(neither, 'authenticatorAttachment') &&
              neither.residentKey === 'discouraged',
        'an unknown kind is the request as it always was',
        JSON.stringify(neither));
      t.check(JSON.stringify(policy.authenticatorKinds()) ===
              '["platform","roaming"]',
        'both kinds are offered while the setting is any',
        JSON.stringify(policy.authenticatorKinds()));
    });
    withSetting('webauthn.residentKey', 'required', function () {
      t.check(policy.creationOptions('localhost', 'platform')
                .authenticatorSelection.residentKey === 'required',
        'a setting of REQUIRED is never loosened to preferred');
    });
  });
  withSetting('webauthn.authenticatorAttachment', 'cross-platform',
              function () {
    t.check(policy.creationOptions('localhost', 'platform')
              .authenticatorSelection.authenticatorAttachment ===
              'cross-platform' &&
            JSON.stringify(policy.authenticatorKinds()) === '["roaming"]',
      'a setting that names one wins over the person\'s choice, and the page ' +
      'is offered only that one');
  });

  withSetting('webauthn.residentKey', 'required', function () {
    const sel = policy.creationOptions('localhost').authenticatorSelection;
    t.check(sel.residentKey === 'required' && sel.requireResidentKey === true,
      'a REQUIRED resident key sets the Level 1 `requireResidentKey` too, ' +
      'which WebAuthn Level 3 says MUST be true exactly then — the browsers ' +
      'that still read it are the ones that would otherwise ignore the ' +
      'modern member entirely', JSON.stringify(sel));
  });
  withSetting('webauthn.residentKey', 'preferred', function () {
    t.check(policy.creationOptions('localhost')
              .authenticatorSelection.requireResidentKey === false,
      'and PREFERRED does not, because the Level 1 member has no third state');
  });

  withSetting('webauthn.credProps', false, function () {
    t.check(policy.creationOptions('localhost').credProps === false,
      'credProps off is carried through, so a client can be shown what it ' +
      'does with no extension results at all');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== user verification is the ONE ceremony option this service ' +
             'checks ===');
  // -------------------------------------------------------------------------
  ['discouraged', 'preferred'].forEach(function (level) {
    withSetting('webauthn.userVerification', level, function () {
      t.check(policy.requireUserVerification() === false,
        '"' + level + '" is REQUESTED and not enforced — the ceremony is ' +
        'accepted whatever the UV flag says');
    });
  });
  withSetting('webauthn.userVerification', 'required', function () {
    t.check(policy.requireUserVerification() === true,
      'AND "required" IS ENFORCED, because the UV flag is inside the bytes ' +
      'the authenticator signed — so it is a claim this service can verify ' +
      'rather than a preference it can only express');
    t.check(policy.report().userVerificationEnforced === true,
      'and the report says so, which is what /admin/webauthn draws');
  });
  withSetting('webauthn.attestation', 'enterprise', function () {
    t.check(policy.report().attestationVerified === false,
      'DEVELOPMENT\'S by-mode ATTESTATION POLICY VERIFIES NOTHING whatever ' +
      'the conveyance asks for (#105), and the report says so rather than ' +
      'letting a conveyance setting imply a check');
  });
  withSetting('webauthn.attestationPolicy', 'verify-if-present', function () {
    t.check(policy.report().attestationVerified === true &&
            policy.report().attestationFormats.length === 8,
      'and verify-if-present reports that every statement is verified, in ' +
      'all eight formats — tests/webauthn_attestation.js asserts that it is');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== the RP ID may be WIDENED to a domain suffix and to nothing ' +
             'else ===');
  // -------------------------------------------------------------------------
  t.check(authn.rpIdOf('https://sts.example.com:8443/realm/acme') === 'sts.example.com',
    'with no setting it is the ORIGIN\'S HOST — never the base URL, which ' +
    'carries a realm path, and never the port');

  withSetting('webauthn.rpId', 'example.com', function () {
    t.check(authn.rpIdOf('https://sts.example.com:8443') === 'example.com',
      'a REGISTRABLE DOMAIN SUFFIX is honoured, which is what lets one ' +
      'credential work across the sibling hosts of a deployment');
  });
  withSetting('webauthn.rpId', 'sts.example.com', function () {
    t.check(authn.rpIdOf('https://sts.example.com') === 'sts.example.com',
      'and so is the host itself, which is the same value said twice');
  });
  withSetting('webauthn.rpId', 'mple.com', function () {
    t.check(authn.rpIdOf('https://sts.example.com') === 'sts.example.com',
      'BUT A STRING SUFFIX THAT IS NOT A DOMAIN SUFFIX IS REFUSED — this is ' +
      'the assertion the whole check exists for: endsWith() alone accepts ' +
      '"mple.com" as a suffix of "example.com", which is exactly the ' +
      'confusion WebAuthn\'s binding is there to prevent');
  });
  withSetting('webauthn.rpId', 'attacker.example', function () {
    t.check(authn.rpIdOf('https://sts.example.com') === 'sts.example.com',
      'and so is an unrelated domain — refused HERE, by name, in the log, ' +
      'rather than by the browser with an error indistinguishable from a ' +
      'hardware failure');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== the POLICY rows refuse an ENROLMENT and never an ' +
             'authentication ===');
  // -------------------------------------------------------------------------
  const who = 'webauthn-policy-probe';
  ldap.createUser(who, {});
  credentials.setPassword(who, 'anything');

  withSetting('webauthn.primaryAllowed', false, function () {
    const refused = credentials.addKey(who, aKey('p1'), 'primary');
    t.check(!refused.ok, 'a PRIMARY key is refused where the realm does not ' +
      'allow one', (refused.errors || []).join(' '));
    t.check(/webauthn.primaryAllowed/.test((refused.errors || []).join(' ')),
      'AND THE REFUSAL NAMES THE SETTING — somebody being sent back to a ' +
      'password field needs to know the answer is a knob rather than their ' +
      'hardware');
    t.check(credentials.addKey(who, aKey('m1'), 'mfa').ok,
      'and a SECOND-FACTOR key is unaffected, because the two rows are two ' +
      'policies');
  });

  withSetting('webauthn.mfaAllowed', false, function () {
    t.check(!credentials.addKey(who, aKey('m2'), 'mfa').ok,
      'the mirror image: a second-factor key is refused where that row is off');
    t.check(credentials.mechanismsFor(who).mfaRequired === true,
      'BUT THE KEY ALREADY ENROLLED GOES ON BEING DEMANDED. This is the ' +
      'contract the setting itself states: an account configured for two ' +
      'factors is still configured for two, and a switch that silently ' +
      'downgraded it would be a security control whose off position does ' +
      'something other than what it says');
  });

  withSetting('webauthn.enabled', false, function () {
    t.check(!credentials.addKey(who, aKey('m3'), 'mfa').ok &&
            !credentials.addKey(who, aKey('p3'), 'primary').ok,
      'with the mechanism off, neither role may be enrolled');
    t.check(credentials.mechanismsFor(who).mfaKeys === 1,
      'and the key on the entry is untouched');
    t.check(policy.offered() === false && policy.report().offered === false,
      'and both the door predicate and the report agree, so a page and an ' +
      'endpoint cannot disagree about whether the mechanism is offered');
  });

  withSetting('webauthn.maxKeysPerPerson', 1, function () {
    const refused = credentials.addKey(who, aKey('m4'), 'mfa');
    t.check(!refused.ok, 'the cap refuses the next enrolment',
      (refused.errors || []).join(' '));
    t.check(/webauthn.maxKeysPerPerson/.test((refused.errors || []).join(' ')),
      'and names the setting');
    t.check(credentials.mechanismsFor(who).mfaRequired === true,
      'AND THE CAP IS AN ENROLMENT LIMIT AND NOT AN AUTHENTICATION ONE — ' +
      'somebody already over it goes on signing in, which is what makes ' +
      'lowering it safe');
  });

  t.check(credentials.addKey(who, aKey('m5'), 'mfa').ok,
    'with every policy row back at its default the enrolment succeeds again, ' +
    'so none of the refusals above left an override behind');

  // -------------------------------------------------------------------------
  t.log.info('=== an assertion is checked against the key that NAMED itself ' +
             '===');
  // -------------------------------------------------------------------------
  // **THIS SECTION EXISTS BECAUSE A MUTANT SURVIVED**, which is the lesson
  // `tests/CLAUDE.md` records three times about three other files. The
  // over-HTTP job drives a real ceremony and asserts that a stranger's
  // authenticator is refused — and `keyForAssertion()` returning `usable[0]`
  // instead of the credential the browser NAMED passes that job perfectly,
  // because the person in it holds exactly one key and the two are then the
  // same key. The signature fails for the right outcome and the wrong reason.
  //
  // The shape that reaches the branch is ONE PERSON, TWO KEYS — and **no door
  // in this service could build it when this section was written**: the
  // sign-in screen's checkbox was the only enrolment there was, and it is
  // reserved for people who hold no second factor yet. `/portal/keys` enrols a
  // second key now (`tests/vendored/sts_portal_backup_keys.js`), and the shape
  // is still built here, through the credential layer, so the rule is asserted
  // directly rather than through a door.
  const twoKeys = 'webauthn-two-keys-probe';
  ldap.createUser(twoKeys, {});
  credentials.setPassword(twoKeys, 'anything');
  credentials.addKey(twoKeys, aKey('first-mfa'), 'mfa');
  credentials.addKey(twoKeys, aKey('second-mfa'), 'mfa');
  credentials.addKey(twoKeys, aKey('the-primary'), 'primary');

  t.check(authn.keyForAssertion(twoKeys, 'mfa', 'second-mfa').key
            .credentialId === 'second-mfa',
    'AN ASSERTION NAMING THE SECOND KEY IS CHECKED AGAINST THE SECOND KEY. ' +
    'WebAuthn tolerates several credentials per person precisely because an ' +
    'assertion names the one that produced it; checking against whichever is ' +
    'first is correct only while there is one, and then silently refuses ' +
    'every assertion from the others');
  t.check(authn.keyForAssertion(twoKeys, 'mfa', 'first-mfa').key
            .credentialId === 'first-mfa',
    'and one naming the first is checked against the first');

  const wrongRole = authn.keyForAssertion(twoKeys, 'mfa', 'the-primary');
  t.check(!wrongRole.key,
    'A `primary` KEY DOES NOT ANSWER A SECOND-FACTOR STEP. It signs somebody ' +
    'in on its own, so accepting one here would let a person satisfy "a ' +
    'password AND a second factor" with a credential this service already ' +
    'considers sufficient by itself', wrongRole.why);
  t.check(authn.keyForAssertion(twoKeys, 'primary', 'the-primary').key
            .credentialId === 'the-primary',
    'and it answers a PASSWORDLESS step, which is the role it was enrolled in');

  const stranger = authn.keyForAssertion(twoKeys, 'mfa', 'never-enrolled');
  t.check(!stranger.key && /not one of the 2/.test(stranger.why),
    'a credential this person never enrolled is refused, and the refusal ' +
    'says how many they DO hold — which is a different thing to fix from ' +
    'holding none', stranger.why);

  const nobody = authn.keyForAssertion('webauthn-holds-nothing-at-all', 'mfa',
                                       'x');
  t.check(!nobody.key && /no security key is enrolled/.test(nobody.why),
    'and somebody who holds none is refused differently, because an account ' +
    'that reached that screen holding nothing is a different fault',
    nobody.why);

  // -------------------------------------------------------------------------
  t.log.info('=== the report is read from the modules that do the work ===');
  // -------------------------------------------------------------------------
  const report = policy.report();
  t.check(report.algorithms.length === verifiable.length,
    'EVERY algorithm the verifier knows is on the report, with the offered ' +
    'ones marked — a page that listed only the two being offered could not ' +
    'answer the question somebody comes to it with, which is what else could ' +
    'I ask for', String(report.algorithms.length));
  t.check(report.curves.length === Object.keys(webauthn.COSE_CURVES).length,
    'and so is every curve, from the same module');
  t.check(report.algorithms.filter(function (one) { return one.offered; })
            .length === policy.algorithmsOffered().length,
    'and the marked ones are exactly the offered ones, so the page and the ' +
    'ceremony cannot disagree');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'webauthn policy',
  describe: 'the WebAuthn ceremony settings: that the offer can never name ' +
            'an algorithm the verifier cannot check, that an unusable ' +
            'setting falls back rather than producing an empty offer, that ' +
            'the RP ID may only be widened to a real domain suffix, and that ' +
            'the policy rows refuse an enrolment and never an authentication',
  run: run
};
