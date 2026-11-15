// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: policy-vectors.js
//
// ---------------------------------------------------------------------------
// THE NAMED POLICIES' VECTORS (#444 phase 4, the `sts-policy` crate): what
// the seven kinds on Directory > Policies answer today, over Node's own
// in-memory directory, for the crate to answer identically. Written by
// `tests/tools/crypto-vectors.js` as `policy-node.json` (`STS_ONLY=policy`);
// read by `rust/crates/sts-policy/tests/node_vectors.rs`, which writes
// `policy-rust.json` back under `STS_WRITE_VECTORS=1`, and
// `tests/rust_crypto_vectors.js` holds THAT to Node through `checkRust()`.
//
// THE CASES ARE RECORDED, NOT DESCRIBED. Each kind is built here as the
// service builds it, from its own `defaultDeps()`, with every dependency
// that reaches outside the kind — the directory's hooks, the application
// register, the settings and mode predicates it reads, the service-account
// register, the locale catalogue, the WebAuthn settings — wrapped so that
// each question and its answer is written on the case's TAPE, and each
// write and delete the kind makes is written, with the directory's answer,
// on its MUTATIONS. The Rust crate reaches the same things through ports of
// its own, and its test answers them from the tape: so every case checks
// what Rust asked as well as what it answered, and a write is held to the
// attributes Node wrote. The policy entries the directory answers are
// keyed by a generation that moves on at every write and delete, so a read
// after a save sees what the directory held after it.
//
//   selection  `common/policy_selection.ts`'s ranking and checks over
//              values handed in (it reads nothing)
//   kinds      `admin-core/policy_kinds.ts`'s list: ids, labels, nouns,
//              actions, and the unknown-action refusal
//   cases      every kind's reads, selections, saves, refusals, resets and
//              acts, in the default realm and in `acme`, for applications,
//              groups and people, each with its tape, mutations, answer and
//              error code
//   passwords  `problemsWith()` over passwords and profiles
//
// The service-account register (`common/service_accounts.ts`) and the
// destination register are another slice's, so their answers here are a
// table of this file's (SERVICE_ACCOUNTS, DESTINATIONS), recorded like the
// rest. It needs the compiled tree: run it in the tests image.
// ---------------------------------------------------------------------------

const path = require('path');

/**
 * A JSON copy, which is what a vector holds: `undefined` members go, as
 * they go on the wire.
 *
 * @param {any} value - anything JSON can carry
 * @returns {any} the copy, or null for undefined
 */
function clone(value) {
  return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

// What the policy hooks of each kind are called, by kind id: the reads the
// generation keys, and the writes and deletes recorded as mutations.
const KIND_HOOKS = {
  password: ['allPasswordPolicies', 'writePasswordPolicy',
             'deletePasswordPolicy'],
  authn: ['allAuthnPolicies', 'writeAuthnPolicy', 'deleteAuthnPolicy'],
  serviceAccount: ['allServiceAccountPolicies', 'writeServiceAccountPolicy',
                   'deleteServiceAccountPolicy'],
  passkey: ['allPasskeyPolicies', 'writePasskeyPolicy',
            'deletePasskeyPolicy'],
  locale: ['allLocalePolicies', 'writeLocalePolicy', 'deleteLocalePolicy'],
  attributes: ['allAttributePolicies', 'writeAttributePolicy',
               'deleteAttributePolicy'],
  definitions: ['allAttributeDefinitions', 'writeAttributeDefinition',
                'deleteAttributeDefinition'],
  postLogin: ['allPostLoginPolicies', 'writePostLoginPolicy',
              'deletePostLoginPolicy']
};

// The settings a kind reads by key, recorded when one is read in a case.
const SETTINGS = ['webauthn.algorithms', 'authn.deviceBoundSessions',
                  'webauthn.authenticatorAttachment',
                  'security.passwordContextWords'];

// The mode predicates a kind asks of `common/mode.js` itself.
const MODE_PREDICATES = ['recoversWeakerThanPasskeys'];

// THE SERVICE-ACCOUNT REGISTER, as this file answers it: by realm, each
// account and the profile its `stsServiceAccountPolicy` names.
const SERVICE_ACCOUNTS = {
  default: { 'svc-build': 'rotating', 'svc-ghost': 'gone', 'svc-plain': '' },
  acme: { 'svc-acme': 'acme-rotating' }
};

// How many secret destinations each realm has (the rotation check).
const DESTINATIONS = { default: 1, acme: 0 };

/**
 * Builds the vectors.
 *
 * @param {string} ROOT - the repository's root
 * @returns {Promise<any>} the vectors
 */
async function build(ROOT) {
  delete process.env.CONFIG_FILE;
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const config = req('common/config');
  const realms = req('common/realms');
  const mode = req('common/mode');
  const errorCodes = req('common/error_codes');
  const applications = req('common/applications');
  const ldap = req('ldap/ldap_server');
  const adminActions = req('admin-core/admin_actions');
  const PolicySelection = req('common/policy_selection');
  const policyKinds = req('admin-core/policy_kinds');
  const helpers = req('common/helpers');
  req('common/i18n');
  const MODULES = {
    password: req('common/password_policy'),
    authn: req('common/authn_policy'),
    serviceAccount: req('common/service_account_policy'),
    passkey: req('common/passkey_policy'),
    locale: req('common/locale_policy'),
    attributes: req('common/attribute_policy'),
    postLogin: req('common/post_login_policy')
  };
  const CLASSES = {
    password: 'PasswordPolicy', authn: 'AuthnPolicy',
    serviceAccount: 'ServiceAccountPolicy', passkey: 'PasskeyPolicy',
    locale: 'LocalePolicy', attributes: 'AttributePolicy',
    postLogin: 'PostLoginPolicy'
  };

  // -------------------------------------------------------------------------
  // THE TAPE.
  // -------------------------------------------------------------------------
  let TAPE = null;
  let MUTATIONS = null;
  let GEN = 0;
  const realmId = function () {
    return String(realms.currentId());
  };
  const rec = function (key, value) {
    if (TAPE) {
      TAPE[JSON.stringify(key)] = clone(value);
    }
    return value;
  };
  const wrap = function (label, fn, self) {
    return function () {
      const args = Array.from(arguments);
      const out = fn.apply(self, args);
      if (out && typeof out.then === 'function') {
        return out.then(function (v) {
          rec([label, realmId()].concat(clone(args)), v);
          return v;
        });
      }
      rec([label, realmId()].concat(clone(args)), out);
      return out;
    };
  };
  const hookKind = {};
  Object.keys(KIND_HOOKS).forEach(function (kind) {
    hookKind[KIND_HOOKS[kind][0]] = { kind: kind, verb: 'all' };
    hookKind[KIND_HOOKS[kind][1]] = { kind: kind, verb: 'write' };
    hookKind[KIND_HOOKS[kind][2]] = { kind: kind, verb: 'delete' };
  });
  const entriesOf = function (list) {
    return (Array.isArray(list) ? list : []).map(function (e) {
      return { name: e && e.name, dn: e && e.dn,
               attributes: (e && e.attributes) || {} };
    });
  };
  // The directory's hooks, each recorded: what a kind's slot is handed.
  const proxyOf = function (real) {
    const p = {};
    Object.keys(real || {}).forEach(function (name) {
      const fn = real[name];
      if (typeof fn !== 'function') {
        p[name] = fn;
        return;
      }
      const known = hookKind[name];
      p[name] = function () {
        const args = Array.from(arguments);
        if (known && known.verb === 'all') {
          const out = fn.apply(real, args);
          rec(['hook', GEN, realmId(), name], entriesOf(out));
          return out;
        }
        if (known) {
          const attributes = clone(args[1]);
          const out = fn.apply(real, args);
          if (MUTATIONS) {
            MUTATIONS.push({ hook: name, realm: realmId(),
                             name: String(args[0]),
                             attributes: known.verb === 'write'
                               ? attributes : null,
                             outcome: clone(out) });
          }
          GEN += 1;
          return out;
        }
        if (args.some(function (a) {
          return typeof a === 'function';
        })) {
          return fn.apply(real, args);
        }
        const out = fn.apply(real, args);
        if (out && typeof out.then === 'function') {
          return out.then(function (v) {
            rec([name, realmId()].concat(clone(args)), v);
            return v;
          });
        }
        rec([name, realmId()].concat(clone(args)), out);
        return out;
      };
    });
    return p;
  };

  // The application register, the settings and the mode, recorded.
  ['forClientId', 'get'].forEach(function (name) {
    const fn = applications[name];
    applications[name] = function (one) {
      const row = fn.call(applications, one);
      rec(['app.' + name, realmId(), clone(one)],
          row ? (row.fields || {}) : null);
      return row;
    };
  });
  const naming = applications.applicationsNamingPolicy;
  applications.applicationsNamingPolicy = function (attribute, name) {
    const out = naming.call(applications, attribute, name);
    rec(['app.naming', realmId(), clone(attribute), clone(name)], out);
    return out;
  };
  const value = config.value;
  config.value = function (key) {
    const out = value.apply(config, arguments);
    if (SETTINGS.indexOf(key) >= 0) {
      rec(['setting', realmId(), key], out);
    }
    return out;
  };
  MODE_PREDICATES.forEach(function (name) {
    const fn = mode[name];
    mode[name] = function () {
      const out = fn.apply(mode, arguments);
      rec(['mode.' + name, realmId()], out);
      return out;
    };
  });

  // -------------------------------------------------------------------------
  // THE KINDS, built from their own defaults with each outside question
  // wrapped.
  // -------------------------------------------------------------------------
  const I = {};
  const svcOf = function () {
    return SERVICE_ACCOUNTS[realmId()] || {};
  };
  Object.keys(MODULES).forEach(function (kind) {
    const Cls = MODULES[kind][CLASSES[kind]];
    const deps = Object.assign({}, Cls.defaultDeps());
    if (kind === 'password') {
      const m = deps.mode;
      deps.mode = { verifiesCredentials: wrap('mode.verifiesCredentials',
                                              m.verifiesCredentials, m) };
    }
    if (kind === 'authn') {
      deps.mailAvailable = wrap('mailAvailable', deps.mailAvailable, null);
    }
    if (kind === 'serviceAccount') {
      deps.passwordMinLength = function () {
        return Number(I.password.read().minLength) || 0;
      };
      deps.destinationCount = wrap('destinationCount', function () {
        const n = DESTINATIONS[realmId()];
        return n === undefined ? -1 : n;
      }, null);
      deps.referenceOf = wrap('serviceAccount.reference', function (who) {
        return String(svcOf()[who] || '');
      }, null);
      deps.peopleNaming = wrap('serviceAccount.naming', function (name) {
        const held = svcOf();
        return Object.keys(held).filter(function (one) {
          return held[one] === name;
        });
      }, null);
      deps.isServiceAccount = wrap('serviceAccount.is', function (at) {
        return String(PolicySelection.valuesOf(at, 'stsServiceAccount')[0] ||
                      '').toUpperCase() === 'TRUE';
      }, null);
    }
    if (kind === 'passkey') {
      deps.offersPostQuantum = wrap('webauthn.offersPostQuantum',
                                    deps.offersPostQuantum, null);
      deps.registrationAlgorithmsAllowed = wrap(
        'webauthn.registrationAlgorithmsAllowed',
        deps.registrationAlgorithmsAllowed, null);
      deps.clients = function () {
        return { act: wrap('passkeyClients.act', function (action, body) {
          return req('common/passkey_clients').act(action, body);
        }, null) };
      };
    }
    if (kind === 'locale') {
      const i = deps.i18n;
      deps.i18n = { canonical: wrap('i18n.canonical', i.canonical, i),
                    answers: wrap('i18n.answers', i.answers, i) };
    }
    if (kind === 'attributes') {
      deps.createsIncompletePeople = wrap('mode.createsIncompletePeople',
                                          deps.createsIncompletePeople, null);
      const offered = deps.offered;
      deps.offered = function () {
        let out = null;
        try {
          out = offered();
        } catch (e) {
          rec(['offered', realmId()], { error: String(e && e.message) });
          throw e;
        }
        rec(['offered', realmId()], out);
        return out;
      };
    }
    I[kind] = new Cls(deps);
    I[kind].setDirectory(proxyOf(MODULES[kind].directoryInstalled()));
  });

  // -------------------------------------------------------------------------
  // ONE CASE.
  // -------------------------------------------------------------------------
  const CASES = [];
  const op = async function (kind, realm, method, args, note) {
    TAPE = {};
    MUTATIONS = [];
    GEN = 0;
    let answer;
    let threw = null;
    try {
      answer = await realms.run(realm, function () {
        rec(['realm', realmId()], {
          id: realms.current().id, name: realms.current().name || '',
          domain: String(realms.domainOf(realms.current()) || '') });
        return I[kind][method].apply(I[kind], args);
      });
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    CASES.push({ kind: kind, realm: realm, method: method,
                 args: clone(args), note: note || '', tape: TAPE,
                 mutations: MUTATIONS, answer: clone(answer),
                 code: errorCodes.codeOf(answer) || '', threw: threw });
    TAPE = null;
    MUTATIONS = null;
    return answer;
  };
  const inRealm = function (realm, fn) {
    return realms.run(realm, fn);
  };

  // -------------------------------------------------------------------------
  // THE WORLD: a realm beside the default, people, groups, applications.
  // -------------------------------------------------------------------------
  realms.create({ id: 'acme', name: 'Acme', domain: 'acme.example.com' });
  const PEOPLE = ['alice', 'bob', 'carol'];
  ['default', 'acme'].forEach(function (realm) {
    inRealm(realm, function () {
      PEOPLE.forEach(function (who) {
        ldap.createUser(who, { invent: false });
      });
      ['admins', 'staff', 'interns'].forEach(function (g) {
        ldap.createGroup(g);
      });
      ldap.addGroupMember('admins', 'alice');
      ldap.addGroupMember('staff', 'alice');
      ldap.addGroupMember('staff', 'bob');
      ldap.addGroupMember('interns', 'carol');
      applications.createApplication({ identifier: 'web', protocols: [],
                                       fields: {} });
      applications.createApplication({ identifier: 'mobile', protocols: [],
                                       fields: {} });
    });
  });
  const pointApp = function (realm, app, attribute, v) {
    return inRealm(realm, function () {
      return adminActions.applicationsAction({ action: 'set',
        application: app, attribute: attribute, value: v }, [], {});
    });
  };
  const pointGroup = function (realm, group, attribute, v) {
    return inRealm(realm, function () {
      return ldap.setGroupPolicy(group, attribute, v);
    });
  };
  // A delete made past the console: the directory's own hook.
  const dropPast = function (realm, kind, name) {
    return inRealm(realm, function () {
      return MODULES[kind].directoryInstalled()[KIND_HOOKS[kind][2]](name);
    });
  };
  const SETUP = [];
  const note = function (what, out) {
    SETUP.push({ what: what, ok: !!(out && (out.ok === undefined ||
                                            out.ok)),
                 errors: clone(out && out.errors) });
  };

  // -------------------------------------------------------------------------
  // PASSWORD (3ac).
  // -------------------------------------------------------------------------
  const pw = MODULES.password.DEFAULTS;
  const full = function (extra) {
    return Object.assign({}, pw, extra || {});
  };
  for (const realm of ['default', 'acme']) {
    await op('password', realm, 'read', []);
    await op('password', realm, 'list', []);
    await op('password', realm, 'selectionFor', ['alice', 'web']);
  }
  await op('password', 'default', 'save', ['default', {}], 'every row');
  await op('password', 'default', 'save', ['default', full({
    minLength: '12.5' })]);
  await op('password', 'default', 'save', ['default', full({
    minLength: 0, history: 99 })]);
  await op('password', 'default', 'save', ['default', full({
    requireUppercase: 'yes' })]);
  await op('password', 'default', 'save', ['default', full({
    minSymbols: 2, requireDigit: true })], 'composition');
  await op('password', 'default', 'save', ['default', full({
    minLength: 30, generatedLength: 20 })]);
  await op('password', 'default', 'save', ['default', full({
    hashAlgorithm: 'scrypt', scryptLogN: 14, scryptParallelism: 2 })]);
  await op('password', 'default', 'save', ['default', full({
    hashAlgorithm: 'md5' })]);
  await op('password', 'default', 'save', ['Bad!', full()]);
  await op('password', 'default', 'save', ['default', Object.assign(full(),
    { requireUppercase: undefined, requireDigit: undefined,
      form: 'console' })], 'console form');
  await op('password', 'default', 'save', ['default', {
    minLength: 14, history: 3, minSymbols: 0, requireUppercase: false,
    requireDigit: false, generatedLength: 24 }], 'optional rows kept');
  await op('password', 'default', 'save', ['default', full({
    minLength: 16, description: 'see STS-AUTHN-0107' })], 'operator code');
  await op('password', 'default', 'save', ['default', full({
    minLength: 16, description: 'The realm\'s own' })]);
  await op('password', 'default', 'read', []);
  await op('password', 'default', 'save', ['strict', full({
    precedence: 20, minLength: 20, generatedLength: 32,
    hashAlgorithm: 'argon2id' })]);
  await op('password', 'default', 'save', ['app-pol', full({
    precedence: 10, minLength: 16, generatedLength: 24 })]);
  await op('password', 'default', 'save', ['lax', full({ precedence: 30,
    minLength: 8 })]);
  await op('password', 'default', 'save', ['ranked', full({
    precedence: 0 })]);
  await op('password', 'default', 'save', ['ranked', full({
    precedence: 'abc' })]);
  await op('password', 'default', 'save', ['default', full({
    precedence: 0 })], 'default carries no precedence');
  await op('password', 'default', 'save', ['gone', full({ precedence: 1,
    minLength: 64, generatedLength: 64 })]);
  note('password app', pointApp('default', 'web', 'appPasswordPolicy',
                                'app-pol'));
  note('password admins', pointGroup('default', 'admins',
                                     'stsPasswordPolicy', 'strict'));
  note('password staff', pointGroup('default', 'staff', 'stsPasswordPolicy',
                                    'lax'));
  note('password interns', pointGroup('default', 'interns',
                                      'stsPasswordPolicy', 'gone'));
  dropPast('default', 'password', 'gone');
  for (const [who, app] of [['alice', 'web'], ['alice', ''], ['bob', ''],
                            ['bob', 'web'], ['carol', ''], ['carol', 'web'],
                            ['', 'web'], ['', ''], ['nobody', 'mobile']]) {
    await op('password', 'default', 'selectionFor', [who, app]);
  }
  await op('password', 'default', 'list', []);
  await op('password', 'default', 'read', ['STRICT ']);
  await op('password', 'default', 'read', ['nonesuch']);
  await op('password', 'default', 'namedBy', ['strict']);
  await op('password', 'default', 'reset', ['strict'], 'still named');
  await op('password', 'default', 'reset', ['Bad!']);
  note('password admins clear', pointGroup('default', 'admins',
                                           'stsPasswordPolicy', ''));
  await op('password', 'default', 'reset', ['strict']);
  await op('password', 'default', 'reset', ['default']);
  await op('password', 'default', 'reset', ['default'], 'nothing stored');
  await op('password', 'acme', 'read', ['app-pol'], 'not inherited');

  // -------------------------------------------------------------------------
  // AUTHENTICATION (3bd), the realm's profile and the named policies.
  // -------------------------------------------------------------------------
  const au = MODULES.authn.DEFAULTS;
  const auth = function (extra) {
    return Object.assign({}, au, extra || {});
  };
  const noPrimary = {};
  MODULES.authn.FIELDS.forEach(function (f) {
    if (f.role === 'primary') {
      noPrimary[f.key] = false;
    }
  });
  const noSecond = {};
  MODULES.authn.FIELDS.forEach(function (f) {
    if (f.role === 'second-factor') {
      noSecond[f.key] = false;
    }
  });
  for (const realm of ['default', 'acme']) {
    await op('authn', realm, 'read', []);
    await op('authn', realm, 'list', []);
  }
  await op('authn', 'default', 'save', ['strict', auth()]);
  await op('authn', 'default', 'save', ['default', {}]);
  await op('authn', 'default', 'save', ['default', auth(noPrimary)]);
  await op('authn', 'default', 'save', ['default', auth(Object.assign({
    requireSecondFactor: 'always' }, noSecond))]);
  await op('authn', 'default', 'save', ['default', auth({
    requireSecondFactorForAdministrators: 'always' })]);
  await op('authn', 'default', 'save', ['default', auth({
    requireSecondFactor: 'never' })]);
  await op('authn', 'default', 'save', ['default', auth({
    emailCodeTtlS: 6000 })]);
  await op('authn', 'default', 'save', ['default', auth({
    emailCodePrimary: true })], 'no mail');
  await op('authn', 'default', 'save', ['default', auth({
    rememberedBrowserDays: 7, requireSecondFactor: 'always',
    description: 'default realm' })]);
  await op('authn', 'acme', 'read', [], 'inherited');
  await op('authn', 'acme', 'save', ['default', auth({
    passwordPrimary: false })]);
  await op('authn', 'acme', 'read', []);
  await op('authn', 'acme', 'reset', ['default']);
  await op('authn', 'acme', 'read', [], 'inherited again');
  await op('authn', 'default', 'reset', ['other']);
  const named = function (realm, body) {
    return op('authn', realm, 'act', ['save-named-authn-policy', body]);
  };
  await named('default', { name: 'Default' });
  await named('default', { name: '-x' });
  await named('default', { name: 'passkeys', mechanisms: ['webauthn',
    'telepathy'], secondFactors: 'totp, carrier-pigeon' });
  await named('default', { name: 'passkeys', precedence: 5000 });
  await named('default', { name: 'passkeys', description: 'Passwordless',
    precedence: 50, mechanisms: ['webauthn'], secondFactors: [] });
  await named('default', { name: 'admins-mfa', precedence: 10,
    mechanisms: 'password, password-mfa', secondFactors: ['totp',
      'securityKey', 'totp'] });
  await named('default', { name: 'gone', precedence: 1 });
  await named('default', { name: 'open' });
  await op('authn', 'default', 'named', []);
  await op('authn', 'default', 'namedPolicy', [' PASSKEYS ']);
  note('authn app', pointApp('default', 'web', 'appAuthnPolicy',
                             'passkeys'));
  note('authn admins', pointGroup('default', 'admins', 'stsAuthnPolicy',
                                  'admins-mfa'));
  note('authn interns', pointGroup('default', 'interns', 'stsAuthnPolicy',
                                   'gone'));
  dropPast('default', 'authn', 'gone');
  for (const [fields, who] of [
    [{ appAuthnPolicy: ['passkeys'], identifier: ['web'] }, ''],
    [{ appAuthnPolicy: ['passkeys'], identifier: ['web'] }, 'alice'],
    [{ appAuthnPolicy: ['passkeys'], identifier: ['web'] }, 'bob'],
    [{ appAuthnPolicy: ['passkeys'], identifier: ['web'] }, 'carol'],
    [{ appAuthnPolicy: ['missing-one'], cn: ['legacy'] }, 'bob'],
    [{ appAuthnPolicy: ['default'] }, 'alice'],
    [null, 'bob'], [null, ''], [{}, 'carol']]) {
    await op('authn', 'default', 'mechanismsFor', [fields, who]);
  }
  await op('authn', 'default', 'namedBy', ['passkeys']);
  await op('authn', 'default', 'act', ['delete-named-authn-policy',
    { name: 'passkeys' }], 'still named');
  await op('authn', 'default', 'act', ['delete-named-authn-policy',
    { name: 'nonesuch' }]);
  await op('authn', 'default', 'act', ['delete-named-authn-policy',
    { name: 'open' }]);
  await op('authn', 'default', 'act', ['rename-named-authn-policy', {}]);
  await op('authn', 'acme', 'act', ['save-named-authn-policy', {
    name: 'acme-only', mechanisms: ['password'] }]);
  await op('authn', 'acme', 'named', []);
  await op('authn', 'default', 'reset', ['default']);

  // -------------------------------------------------------------------------
  // SERVICE ACCOUNT (3cd).
  // -------------------------------------------------------------------------
  const sa = MODULES.serviceAccount.DEFAULTS;
  const svc = function (extra) {
    return Object.assign({}, sa, extra || {});
  };
  for (const realm of ['default', 'acme']) {
    await op('serviceAccount', realm, 'read', []);
    await op('serviceAccount', realm, 'list', []);
  }
  await op('serviceAccount', 'default', 'save', ['default', {}]);
  await op('serviceAccount', 'default', 'save', ['default', svc({
    generatedLength: 8 })]);
  await op('serviceAccount', 'default', 'save', ['default', svc({
    generatedLength: 16 })], 'below the password minimum');
  await op('serviceAccount', 'acme', 'save', ['default', svc({
    rotationEnabled: true })], 'no destination');
  await op('serviceAccount', 'default', 'save', ['default', svc({
    rotationEnabled: true, rotationIntervalDays: 7,
    description: 'build robots' })]);
  await op('serviceAccount', 'acme', 'read', [], 'inherited');
  await op('serviceAccount', 'default', 'save', ['rotating', svc({
    precedence: 15, allowScim: false })]);
  await op('serviceAccount', 'default', 'save', ['rotating', svc({
    precedence: '1001' })]);
  await op('serviceAccount', 'default', 'save', ['Not A Name', svc()]);
  await op('serviceAccount', 'acme', 'save', ['acme-rotating', svc({
    exemptFromSecondFactor: false })]);
  await op('serviceAccount', 'acme', 'read', ['rotating'], 'own only');
  for (const who of ['svc-build', 'svc-ghost', 'svc-plain', 'alice', '']) {
    await op('serviceAccount', 'default', 'profileFor', [who]);
  }
  await op('serviceAccount', 'acme', 'profileFor', ['svc-acme']);
  await op('serviceAccount', 'default', 'list', []);
  await op('serviceAccount', 'default', 'namedBy', ['rotating']);
  for (const at of [{ stsServiceAccountPolicy: 'rotating',
                      stsServiceAccount: 'TRUE' },
                    { stsServiceAccountPolicy: ['nonesuch'],
                      stsserviceaccount: ['TRUE'] },
                    { stsServiceAccountPolicy: 'rotating' },
                    { stsServiceAccountPolicy: '' }, {}]) {
    await op('serviceAccount', 'default', 'writeRefusal', [at]);
  }
  await op('serviceAccount', 'default', 'reset', ['rotating'],
           'still named');
  await op('serviceAccount', 'acme', 'reset', ['acme-rotating'],
           'still named');
  await op('serviceAccount', 'default', 'reset', ['default']);
  await op('serviceAccount', 'acme', 'read', [], 'built-in again');

  // -------------------------------------------------------------------------
  // PASSKEY (3ch).
  // -------------------------------------------------------------------------
  const pk = Object.assign({}, MODULES.passkey.DEFAULTS);
  const passkey = function (extra) {
    return Object.assign({}, pk, extra || {});
  };
  for (const realm of ['default', 'acme']) {
    await op('passkey', realm, 'read', []);
    await op('passkey', realm, 'list', []);
  }
  await op('passkey', 'default', 'save', ['default', {}]);
  await op('passkey', 'default', 'save', ['UPPER', passkey()]);
  const passkeyBad = [
    { requireUsernameless: true, allowUsernameless: false },
    { securityKeyResidentKey: 'always' },
    { minPinLength: 3 }, { minPinLength: '8.0' },
    { passkeyHints: 'hybrid,hybrid' }, { signInHints: 'none' },
    { securityKeyHints: 'client-device' },
    { userDisplayName: 'givenName sn, mail, a b c d' },
    { userDisplayName: '1bad' },
    { enterpriseSerialAttribute: 'serial number' },
    { credentialLabel: 'Bad‮Label' },
    { credentialLabel: 'Work  key' },
    { clientRules: 'Chrome 130- on *; Safari' },
    { clientRules: 'chrome 141 on macOS 15-14' },
    { clientRules: '  Chrome   130-140 on  Windows ; Firefox on * ' },
    { registrationAlgorithms: 'ES256,RS1' },
    { registrationAlgorithms: 'ml-dsa-65' },
    { registrationMode: 'classical-only', postQuantumRequired: 'sign-in' },
    { registrationMode: 'classical-only', lanes: 'both' },
    { registrationMode: 'classical-only',
      attestationAlgorithms: 'ml-dsa-44' },
    { registrationMode: 'pq-only', registrationAlgorithms: 'ES256' },
    { registrationMode: 'pq-first' },
    { postQuantumRequired: 'sign-in' },
    { deviceBoundRequired: true },
    { recoveryAssurance: 'nobody' },
    { adminEnrolment: 'on', attestationAlgorithms: 'post-quantum,slh-dsa' },
    { allowUsernameless: 'yes' }
  ];
  for (const bad of passkeyBad) {
    await op('passkey', 'default', 'save', ['default', passkey(bad)]);
  }
  await op('passkey', 'default', 'save', ['default', passkey({
    recoveryAssurance: 'operator-only', registrationAlgorithms:
      'ML-DSA-65,ES256', registrationMode: 'pq-first', lanes: 'one',
    description: 'stored rows' })]);
  await op('passkey', 'default', 'save', ['default', Object.assign(
    passkey(), { recoveryAssurance: undefined, registrationAlgorithms:
      undefined, registrationMode: undefined, lanes: undefined,
    postQuantumAllowCredentials: undefined, clientRules: undefined,
    attestationAlgorithms: undefined, adminEnrolment: undefined,
    deviceBoundRequired: undefined })], 'optional rows kept');
  await op('passkey', 'default', 'read', []);
  await op('passkey', 'acme', 'read', [], 'inherited');
  await op('passkey', 'default', 'save', ['strict', passkey({
    precedence: 5, backupEligibility: 'disallow' })]);
  await op('passkey', 'default', 'save', ['loose', passkey({
    precedence: 50 })]);
  await op('passkey', 'default', 'save', ['gone', passkey({
    precedence: 1 })]);
  note('passkey app', pointApp('default', 'mobile', 'appPasskeyPolicy',
                               'loose'));
  note('passkey staff', pointGroup('default', 'staff', 'stsPasskeyPolicy',
                                   'strict'));
  note('passkey interns', pointGroup('default', 'interns',
                                     'stsPasskeyPolicy', 'gone'));
  dropPast('default', 'passkey', 'gone');
  for (const [who, app] of [['alice', 'mobile'], ['bob', ''],
                            ['carol', 'mobile'], ['carol', ''],
                            ['', 'mobile'], ['', 'web']]) {
    await op('passkey', 'default', 'selectionFor', [who, app]);
  }
  await op('passkey', 'default', 'forApplication', ['loose']);
  await op('passkey', 'default', 'forApplication', ['nonesuch']);
  await op('passkey', 'default', 'forApplication', ['']);
  await op('passkey', 'default', 'list', []);
  await op('passkey', 'default', 'read', ['nonesuch'], 'falls to default');
  await op('passkey', 'default', 'reset', ['strict'], 'still named');
  await op('passkey', 'default', 'act', ['clear-passkey-client',
    { client: 'Chrome 141 on macOS 15' }]);
  await op('passkey', 'default', 'reset', ['default']);

  // -------------------------------------------------------------------------
  // LOCALE (3ci).
  // -------------------------------------------------------------------------
  for (const realm of ['default', 'acme']) {
    await op('locale', realm, 'read', []);
    await op('locale', realm, 'profileNameFor', ['web', 'alice']);
  }
  await op('locale', 'default', 'save', ['default', {}]);
  await op('locale', 'default', 'save', ['default', {
    defaultLocale: 'not a tag!', populatePreferredLanguage: 'maybe' }]);
  await op('locale', 'default', 'save', ['default', {
    defaultLocale: 'FR-ca', populatePreferredLanguage: true }]);
  await op('locale', 'acme', 'read', [], 'inherited');
  await op('locale', 'default', 'save', ['default ', {
    defaultLocale: 'iw', populatePreferredLanguage: 'on', form: 'console',
    description: 'Hebrew' }]);
  await op('locale', 'default', 'save', ['quebec', {
    defaultLocale: 'fr-CA', populatePreferredLanguage: false,
    precedence: 40 }]);
  await op('locale', 'default', 'save', ['tw', {
    defaultLocale: 'zh-tw', populatePreferredLanguage: true,
    precedence: 40 }]);
  await op('locale', 'default', 'save', ['tw', { defaultLocale: 'zh-TW',
    populatePreferredLanguage: true, precedence: -1 }]);
  await op('locale', 'default', 'save', ['gone', { defaultLocale: 'de',
    populatePreferredLanguage: true, precedence: 1 }]);
  note('locale app', pointApp('default', 'web', 'appLocalePolicy', 'tw'));
  note('locale staff', pointGroup('default', 'staff', 'stsLocalePolicy',
                                  'quebec'));
  note('locale interns', pointGroup('default', 'interns',
                                    'stsLocalePolicy', 'gone'));
  dropPast('default', 'locale', 'gone');
  for (const [app, who] of [['web', 'bob'], ['web', ''], ['', 'bob'],
                            ['', 'carol'], ['mobile', 'alice'], ['', '']]) {
    await op('locale', 'default', 'profileNameFor', [app, who]);
    await op('locale', 'default', 'forApplication', [app, who]);
  }
  await op('locale', 'default', 'list', []);
  await op('locale', 'default', 'namedBy', ['tw']);
  await op('locale', 'default', 'reset', ['tw'], 'still named');
  await op('locale', 'default', 'reset', ['NO SUCH']);
  await op('locale', 'default', 'reset', ['default']);

  // -------------------------------------------------------------------------
  // ATTRIBUTES (3co): the profiles and the custom attribute register.
  // -------------------------------------------------------------------------
  for (const realm of ['default', 'acme']) {
    await op('attributes', realm, 'read', []);
    await op('attributes', realm, 'profileNames', []);
  }
  await op('attributes', 'default', 'save', ['default', {}]);
  await op('attributes', 'default', 'save', ['default', {
    requiredAttributes: 'givenName, sn, mail, telepathy, userPassword' }]);
  await op('attributes', 'default', 'save', ['default', {
    requiredAttributes: ['GIVENNAME', 'mail', 'mail', 'title'],
    description: 'the base' }]);
  await op('attributes', 'acme', 'read', [], 'inherited');
  const act = function (realm, action, body) {
    return op('attributes', realm, 'act', [action, body]);
  };
  await act('default', 'define-person-attribute', { name: 'badge',
    label: 'Badge number', syntax: 'string' });
  await act('default', 'define-person-attribute', { name: 'stsBadge',
    label: 'x' });
  await act('default', 'define-person-attribute', { name: 'memberOf',
    label: 'x' });
  await act('default', 'define-person-attribute', { name: 'mail',
    label: 'x' });
  await act('default', 'define-person-attribute', { name: 'badge',
    label: 'again' });
  await act('default', 'define-person-attribute', { name: '9lives',
    label: '', syntax: 'colour', multiValued: 'several',
    portalVisible: 'perhaps' });
  await act('default', 'define-person-attribute', { name: 'nickname',
    label: 'Nickname', multiValued: 'multiple', portalEditable: true,
    description: 'What friends say' });
  await op('attributes', 'default', 'definitions', []);
  await act('default', 'update-person-attribute', { name: 'nickname',
    syntax: 'integer' });
  await act('default', 'update-person-attribute', { name: 'nickname',
    multiValued: 'single', syntax: 'STRING' });
  await act('default', 'update-person-attribute', { name: 'nobody' });
  await act('default', 'update-person-attribute', { name: 'nickname',
    label: '\u0007' });
  await act('default', 'update-person-attribute', { name: 'nickname',
    portalVisible: false, label: 'Nick' });
  await op('attributes', 'default', 'save', ['strict', {
    requiredAttributes: 'badge, nickname, telephoneNumber',
    precedence: 10 }]);
  await op('attributes', 'default', 'save', ['strict', {
    requiredAttributes: 'badge', precedence: 2000 }]);
  await op('attributes', 'default', 'save', ['loose', {
    requiredAttributes: '', precedence: 90, form: 'console' }]);
  await op('attributes', 'default', 'save', ['gone', {
    requiredAttributes: 'title', precedence: 1 }]);
  note('attributes admins', pointGroup('default', 'admins',
                                       'stsAttributePolicy', 'strict'));
  note('attributes interns', pointGroup('default', 'interns',
                                        'stsAttributePolicy', 'gone'));
  dropPast('default', 'attributes', 'gone');
  const subjects = [
    { uid: 'alice' }, { uid: 'bob' }, { uid: 'carol' },
    { uid: 'bob', attributes: { stsAttributePolicy: 'loose' } },
    { uid: 'dave', attributes: { stsAttributePolicy: ['strict'] } },
    { uid: 'erin', attributes: {}, groups: ['admins'] },
    { attributes: { uid: ['frank'], stsAttributePolicy: 'nonesuch' } }, {}];
  for (const s of subjects) {
    await op('attributes', 'default', 'selectionFor', [s]);
    await op('attributes', 'default', 'required', [s]);
  }
  await op('attributes', 'default', 'createRefusal', [{ uid: 'zed',
    cn: 'Zed', sn: 'Z' }, null]);
  await op('attributes', 'default', 'editRefusal', [{ mail: 'a@b',
    title: 'Dr' }, { mail: '' }, { uid: 'bob' }]);
  await op('attributes', 'default', 'list', []);
  await act('default', 'remove-person-attribute', { name: 'badge' });
  await act('default', 'remove-person-attribute', { name: 'nickname' });
  await act('default', 'remove-person-attribute', { name: 'never' });
  await act('default', 'rename-person-attribute', { name: 'x' });
  await op('attributes', 'default', 'reset', ['strict'], 'still named');
  await op('attributes', 'default', 'reset', ['loose']);
  await op('attributes', 'default', 'reset', ['default']);
  await op('attributes', 'acme', 'definitions', [], 'not inherited');

  // -------------------------------------------------------------------------
  // POST-LOGIN (3ct).
  // -------------------------------------------------------------------------
  const pl = MODULES.postLogin.DEFAULTS;
  const post = function (extra) {
    return Object.assign({}, pl, extra || {});
  };
  for (const realm of ['default', 'acme']) {
    await op('postLogin', realm, 'read', []);
    await op('postLogin', realm, 'list', []);
  }
  await op('postLogin', 'default', 'save', ['default', {}]);
  await op('postLogin', 'default', 'save', ['default', post({
    activity: 'dance', snoozeDays: 'x', graceDays: 1000000 })]);
  await op('postLogin', 'default', 'save', ['default', post({
    enabled: true, method: 'UPGRADE', noPasskey: 'invite' })]);
  await op('postLogin', 'acme', 'read', [], 'inherited');
  await op('postLogin', 'default', 'save', ['Default', post()]);
  await op('postLogin', 'default', 'save', ['quiet', post({
    enabled: false, precedence: 5 })]);
  await op('postLogin', 'default', 'save', ['loud', post({
    enabled: true, precedence: 50, graceDays: 30 })]);
  await op('postLogin', 'default', 'save', ['gone', post({
    precedence: 1 })]);
  note('postLogin app', pointApp('default', 'web', 'appPostLoginPolicy',
                                 'quiet'));
  note('postLogin staff', pointGroup('default', 'staff',
                                     'stsPostLoginPolicy', 'loud'));
  note('postLogin interns', pointGroup('default', 'interns',
                                       'stsPostLoginPolicy', 'gone'));
  dropPast('default', 'postLogin', 'gone');
  for (const [who, app] of [['bob', 'web'], ['bob', ''], ['carol', ''],
                            ['alice', 'mobile'], ['', 'web']]) {
    await op('postLogin', 'default', 'profileNameFor', [who, null, app]);
    await op('postLogin', 'default', 'forPerson', [who, null, app]);
  }
  await op('postLogin', 'default', 'list', []);
  await op('postLogin', 'default', 'reset', ['loud'], 'still named');
  await op('postLogin', 'default', 'reset', ['default']);

  // -------------------------------------------------------------------------
  // THE PASSWORD CHECK over profiles read above.
  // -------------------------------------------------------------------------
  const PASSWORDS = [];
  const profiles = [I.password.read('default'),
                    Object.assign({}, I.password.read('default'),
                                  { minLength: 20 })];
  for (const realm of ['default', 'acme']) {
    for (const profile of profiles) {
      for (const p of ['short', 'correct horse battery', 'Iya-Sts-rocks!',
                       'my acme password 1', 'm4g1c-Acm3-l1fe!!',
                       'éèêëéèêëéèêë', '\u{1F600}'.repeat(12),
                       'IyaCyberSecurityRules', 'ex4mple long phrase']) {
        await op('password', realm, 'problemsWith', [p, profile]);
      }
    }
  }

  // -------------------------------------------------------------------------
  // THE SELECTION, PURE.
  // -------------------------------------------------------------------------
  const SPEC = { precedenceAttribute: 'stsTestPrecedence',
                 defaultPrecedence: 100 };
  const entry = function (name, p) {
    return { name: name, dn: 'cn=' + name + ',ou=testPolicies',
             attributes: p === undefined ? {}
               : { stsTestPrecedence: [String(p)] } };
  };
  const ENTRIES = [entry('default', 1), entry('App-Strict', 50),
                   entry('group-admins', 20), entry('person-own', 30),
                   entry('tie-b', 40), entry('tie-a', 40),
                   entry('too-high', 1001), entry('not-a-number', 'x'),
                   entry('zero', 0), entry('', 5),
                   { name: 'lower', dn: 'cn=lower',
                     attributes: { ststestprecedence: '7' } }];
  const REFS = [
    [], [{ by: 'application', holder: 'web', value: 'app-strict' }],
    [{ by: 'application', holder: 'web', value: 'app-strict' },
     { by: 'person', holder: 'alice', value: 'person-own' },
     { by: 'group', holder: 'admins', value: 'group-admins' }],
    [{ by: 'group', value: 'tie-b' }, { by: 'group', value: 'tie-a' }],
    [{ by: 'group', value: 'too-high' }, { by: 'group',
      value: 'not-a-number' }, { by: 'group', value: 'zero' }],
    [{ by: 'application', value: '' }, { by: 'person', value: '  ' },
     { by: 'group', value: 'DEFAULT' }, { by: 'group', value: null }],
    [{ by: 'application', holder: 'web', value: 'gone' },
     { by: 'group', holder: 'admins', value: 'group-admins' }],
    [{ by: 'group', value: '  App-STRICT ' }],
    [{ by: 'group', value: 'lower' }, { by: 'person', value: 'tie-a' }]];
  const SELECTION = [];
  const sel = function (method, args) {
    let answer;
    let threw = null;
    try {
      answer = PolicySelection[method].apply(PolicySelection, args);
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    SELECTION.push({ method: method, args: clone(args),
                     answer: clone(answer), threw: threw });
  };
  REFS.forEach(function (refs) {
    sel('rank', [ENTRIES, SPEC, refs]);
    sel('rank', [[], SPEC, refs]);
  });
  sel('rank', [null, SPEC, null]);
  sel('named', [ENTRIES, SPEC]);
  sel('named', [ENTRIES, { precedenceAttribute: 'stsTestPrecedence' }]);
  ['App-strict', 'nonesuch', '', null, 'default'].forEach(function (v) {
    sel('forReference', [ENTRIES, SPEC, v]);
  });
  sel('groupReferences', [[{ cn: 'admins', dn: 'cn=admins', value: 'x' },
                           { dn: 'cn=nameless', value: 'y' },
                           { cn: 'staff', value: '' }, null]]);
  [['default', 'passkey policy', false], ['default', 'passkey policy', true],
   ['Strict', 'locale policy', true], ['a'.repeat(65), 'x', true],
   ['-lead', 'x', true], [null, 'x', true], ['ok-1', 'x', false],
   [' ok ', 'x', false], ['b'.repeat(80) + '!', 'x', true]]
    .forEach(function (args) {
      sel('nameProblem', args);
    });
  [{}, { precedence: '' }, { precedence: 1 }, { precedence: '1000' },
   { precedence: 1001 }, { precedence: 0 }, { precedence: ' 42 ' },
   { precedence: 12.5 }, { precedence: 'x'.repeat(60) }, null,
   { precedence: -3 }, { precedence: '00007' }].forEach(function (body) {
    sel('checkPrecedence', [body, SPEC]);
    sel('checkPrecedence', [body, { precedenceAttribute: 'x',
                                    defaultPrecedence: 250 }]);
  });
  [['', ['default', 'strict'], 'stsX'], ['STRICT', ['default', 'strict'],
                                          'stsX'],
   ['gone', ['default', 'strict'], 'stsX'], ['x'.repeat(100), [], 'y'],
   ['  ', null, 'z']].forEach(function (args) {
    sel('referenceProblem', args);
  });
  const many = [];
  for (let n = 0; n < 13; n++) {
    many.push('p' + n);
  }
  [[{ applications: ['web'], groups: [], people: [] }],
   [{ applications: [], groups: ['admins', 'staff'], people: ['alice'] }],
   [{ applications: many, people: many.slice(0, 10) }], [{}], [null]]
    .forEach(function (args) {
      sel('deleteProblem', ['passkey policy', 'strict'].concat(args));
    });
  [['a', 'b'], ['a', 'a'], [' x', 'x']].forEach(function (pair) {
    sel('compare', [{ name: pair[0], precedence: 5 },
                    { name: pair[1], precedence: 5 }]);
  });
  ['x', 7, null, ' MiXeD ', true].forEach(function (v) {
    sel('fold', [v]);
  });

  // -------------------------------------------------------------------------
  // THE KINDS' LIST.
  // -------------------------------------------------------------------------
  const kinds = {
    list: policyKinds.list().map(function (k) {
      return { id: k.id, label: k.label, container: k.container,
               governs: k.governs, auditAction: k.auditAction,
               appliesTo: k.appliesTo, fallsBackTo: k.fallsBackTo,
               tabbed: !!k.tabbed, noun: policyKinds.nounOf(k),
               saveAction: policyKinds.saveAction(k),
               resetAction: policyKinds.resetAction(k),
               extraActions: (k.extraActions || []).map(function (x) {
                 return { action: x.action, operationId: x.operationId,
                          auditAction: x.auditAction };
               }) };
    }),
    actions: policyKinds.actions(),
    messages: clone(policyKinds.MESSAGES),
    numberWords: [0, 7, 15, 16, 31].map(function (n) {
      return [n, helpers.numberWord(n)];
    }),
    forAction: ['save-passkey-policy', 'reset-password-policy',
                'save-named-authn-policy', 'define-person-attribute',
                'save-nothing-policy'].map(function (a) {
      const found = policyKinds.forAction(a);
      return { action: a, kind: found ? found.kind.id : null,
               verb: found ? found.verb : null };
    })
  };
  const unknown = adminActions.policiesAction({ action: 'frobnicate' }, {});
  kinds.unknown = { answer: clone(unknown),
                    code: errorCodes.codeOf(unknown) || '' };
  return { setup: SETUP, selection: SELECTION, kinds: kinds, cases: CASES };
}

/**
 * Holds what the Rust crate answered to Node: every case Rust replayed must
 * have answered exactly what Node did, and every password Rust GENERATED
 * must pass Node's check under the profile it was made for.
 *
 * @param {string} ROOT - the repository's root
 * @param {any} rust - policy-rust.json
 * @param {any} node - policy-node.json
 * @param {(ok: boolean, what: string, detail?: string) => void} check -
 *   the runner's check
 */
function checkRust(ROOT, rust, node, check) {
  const same = function (a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
  };
  const wrong = [];
  (rust.cases || []).forEach(function (row, n) {
    const mine = node.cases[n];
    if (!mine || !same(row.answer, mine.answer) || row.code !== mine.code) {
      wrong.push(n + ' ' + (mine ? mine.kind + '.' + mine.method : '?'));
    }
  });
  check(wrong.length === 0 && (rust.cases || []).length ===
          node.cases.length,
        'policy: every one of ' + node.cases.length + ' cases Rust ' +
        'replayed answers what Node answered',
        wrong.slice(0, 10).join('; '));
  const passwordPolicy = require(path.join(ROOT, 'common',
                                           'password_policy'));
  const bad = (rust.generated || []).filter(function (row) {
    return passwordPolicy.problemsWith(row.password, row.profile).length > 0 ||
      Array.from(row.password).length !== Number(row.profile.generatedLength);
  });
  check((rust.generated || []).length > 0 && bad.length === 0,
        'policy: every password Rust generated passes Node\'s password ' +
        'policy at its generated length',
        bad.slice(0, 3).map(function (row) {
          return row.password;
        }).join(' '));
}

module.exports = { build: build, checkRust: checkRust };
