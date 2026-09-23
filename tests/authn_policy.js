'use strict';
//
// File: authn_policy.js
//
// ===========================================================================
// THE AUTHENTICATION POLICY AND THE POLICIES PAGE (#64, 2026-09-23), in
// process.
//
// `common/authn_policy.ts` and `admin-core/policy_kinds.ts` argue the design.
// What is held here:
//
//   A. THE BUILT-IN PROFILE: both email mechanisms off (NIST SP 800-63B-4
//      section 3.1.3.1), a TOTP and a recovery code never a first factor,
//      `requireSecondFactor` `if-held`.
//   B. A SAVE CARRIES EVERY FIELD: one left out is refused by name, except an
//      unticked checkbox on the console's own form; an enum outside its
//      values and a number outside its range are refused; so is a profile
//      that leaves no first factor, or requires a second with none allowed.
//   C. INHERITANCE (D6): a realm with no entry follows the default realm's,
//      then the built-in defaults; its own entry wins; `reset` puts it back
//      to inheriting.
//   D. THE MAIL GUARD: an email row cannot be SAVED on in a realm that cannot
//      send mail, and one already on there is not ACTIVE.
//   E. THE RETIRED SETTINGS (D7): `totp.settings().enabled`,
//      `backupCodes.settings().enabled` and `mfaRequirementFor().byRealm` are
//      the policy's rows.
//   F. ONE PAGE FOR EVERY KIND: the view and the action list are the kinds'
//      union, and a kind registered later appears in the view, the actions
//      and the refusal sentence, and is dispatched to, with no other edit.
//   G. THE RISK ENGINE: an emailed factor meets no step-up (D1).
//   H. THE ISSUANCE POLICY: the built-in `role-issuance` carries no email
//      rule by default; with `refuseEmailFactor` it denies a session whose
//      credential kinds include an emailed one — carrying the obligation the
//      PEP refuses on even where the role question is waived — and permits
//      the same session on an authenticator app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const authnPolicy = require('../common/authn_policy');
const credentials = require('../common/credentials');
const totp = require('../common/totp');
const backupCodes = require('../common/backup_codes');
const ldap = require('../ldap/ldap_server');
const policyKinds = require('../admin-core/policy_kinds');
const adminViews = require('../admin-core/admin_views');
const adminActions = require('../admin-core/admin_actions');
const riskEngine = require('../risk/risk_engine');

const log = require('bunyan').createLogger({ name: 'authn_policy',
  level: process.env.LOG_LEVEL || 'info' });

void ldap;

function withRealm(t, id, overrides, fn) {
  log.debug('Entering withRealm(). ' + id);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: overrides || {} });
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

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + require('crypto').randomBytes(3).toString('hex');
}

function withDefaults(fields) {
  log.debug('Entering withDefaults().');
  log.debug('Leaving withDefaults().');
  return Object.assign({}, authnPolicy.DEFAULTS, fields || {});
}

function builtIn(t) {
  log.debug('Entering builtIn().');
  const p = authnPolicy.read('default');
  t.check(p.from === 'built-in' && !p.stored && !p.inherited,
          'A1. with nothing stored the built-in profile is in force',
          JSON.stringify({ from: p.from, stored: p.stored }));
  t.check(p.emailCodePrimary === false && p.emailCodeSecondFactor === false &&
          p.emailLinkPrimary === false && p.emailLinkSecondFactor === false,
          'A2. both email mechanisms are OFF by default (NIST SP 800-63B-4 ' +
          'section 3.1.3.1)');
  t.check(p.passwordPrimary === true && p.requireSecondFactor === 'if-held',
          'A3. a password is a first factor and a second is required of ' +
          'those who hold one');
  const keys = authnPolicy.FIELDS.map(function (f) {
    return f.key;
  });
  t.check(keys.indexOf('totpPrimary') < 0 &&
          keys.indexOf('recoveryCodePrimary') < 0 &&
          !authnPolicy.allows('totp', 'primary') &&
          !authnPolicy.allows('recoveryCode', 'primary'),
          'A4. a TOTP and a recovery code have no first-factor row at all, ' +
          'so no save can make either one');
  t.check(authnPolicy.FIELD_BY_KEY.requireSecondFactor.values.join(',') ===
          'if-held,always',
          'A5. there is no "never": a held second factor is always asked for');
  log.debug('Leaving builtIn().');
}

function saves(t) {
  log.debug('Entering saves().');
  withRealm(t, realmId('authn-policy-save'), {}, function () {
    const partial = authnPolicy.validate({ passwordPrimary: true });
    t.check(partial.problems.length > 0 &&
            partial.problems.some(function (one) {
              return /`requireSecondFactor`.*required/.test(one);
            }),
            'B1. a save that leaves a field out is refused BY NAME',
            JSON.stringify(partial.problems.slice(0, 2)));
    const form = Object.assign({ form: 'console' }, withDefaults());
    delete form.totpSecondFactor;
    t.check(authnPolicy.validate(form).values.totpSecondFactor === false,
            'B2. on the console\'s own form an unticked box is "no"');
    t.check(authnPolicy.validate(withDefaults({ requireSecondFactor: 'never' }))
      .problems.some(function (one) {
        return /one of if-held, always/.test(one);
      }), 'B3. an enum value that is not one of its values is refused');
    t.check(authnPolicy.validate(withDefaults({ emailCodeTtlS: 900 }))
      .problems.length === 1,
            'B4. an emailed code valid for more than ten minutes is refused');
    const noWayIn = {};
    authnPolicy.MECHANISMS.forEach(function (m) {
      if (m.primary !== null) {
        noWayIn[m.id + 'Primary'] = false;
      }
    });
    const refused = authnPolicy.save('default', withDefaults(noWayIn));
    t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0243' &&
            /nobody could sign in/.test(refused.errors.join(' ')),
            'B5. a profile with no first factor is refused — nobody, the ' +
            'realm\'s administrators included, could sign in',
            JSON.stringify(refused.errors));
    const noSecond = {};
    authnPolicy.MECHANISMS.forEach(function (m) {
      if (m.secondFactor !== null) {
        noSecond[m.id + 'SecondFactor'] = false;
      }
    });
    noSecond.requireSecondFactor = 'always';
    const refused2 = authnPolicy.save('default', withDefaults(noSecond));
    t.check(!refused2.ok && /nobody could finish/.test(
              refused2.errors.join(' ')),
            'B6. a second factor required of everybody with none allowed is ' +
            'refused', JSON.stringify(refused2.errors));
    const other = authnPolicy.save('second', withDefaults());
    t.check(!other.ok && errorCodes.codeOf(other) === 'STS-AUTHN-0242',
            'B7. there is one profile, "default"');
  });
  log.debug('Leaving saves().');
}

function inheritance(t) {
  log.debug('Entering inheritance().');
  const saved = realms.run(realms.DEFAULT_REALM, function () {
    return authnPolicy.save('default', withDefaults({
      requireSecondFactor: 'always', description: 'the service policy' }));
  });
  t.check(saved.ok && saved.profile.from === 'realm',
          'C1. the default realm saves the service\'s profile',
          JSON.stringify(saved.errors));
  try {
    withRealm(t, realmId('authn-policy-inherit'), {}, function () {
      const inherited = authnPolicy.read('default');
      t.check(inherited.from === 'default-realm' && inherited.inherited &&
              !inherited.stored &&
              inherited.requireSecondFactor === 'always' &&
              inherited.sources.requireSecondFactor === 'default realm',
              'C2. a realm with no entry of its own FOLLOWS the default ' +
              'realm\'s', JSON.stringify({ from: inherited.from,
                                           rsf: inherited.requireSecondFactor }));
      t.check(credentials.mfaRequirementFor('nobody-here').byRealm === true,
              'C3. and so does the requirement the sign-in screen asks');
      const own = authnPolicy.save('default', withDefaults({
        requireSecondFactor: 'if-held' }));
      const mine = authnPolicy.read('default');
      t.check(own.ok && mine.from === 'realm' && mine.stored &&
              mine.requireSecondFactor === 'if-held',
              'C4. a realm\'s own entry overrides it, here and nowhere else');
      const reset = authnPolicy.reset('default');
      const back = authnPolicy.read('default');
      t.check(reset.ok && reset.removed && back.from === 'default-realm' &&
              back.requireSecondFactor === 'always',
              'C5. reset removes the realm\'s entry and it INHERITS again');
    });
  } finally {
    realms.run(realms.DEFAULT_REALM, function () {
      authnPolicy.reset('default');
    });
  }
  withRealm(t, realmId('authn-policy-builtin'), {}, function () {
    t.check(authnPolicy.read('default').from === 'built-in',
            'C6. with the default realm\'s entry gone, the built-in defaults');
  });
  log.debug('Leaving inheritance().');
}

function mailGuard(t) {
  log.debug('Entering mailGuard().');
  withRealm(t, realmId('authn-policy-nomail'), { 'mail.transport': 'off' },
            function () {
    t.check(!authnPolicy.mailUsable(),
            'D0. precondition: this realm cannot send mail');
    const refused = authnPolicy.save('default', withDefaults({
      emailCodePrimary: true }));
    t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0244' &&
            /cannot send mail/.test(refused.errors.join(' ')),
            'D1. an email row cannot be SAVED on where mail is not working',
            JSON.stringify(refused.errors));
  });
  withRealm(t, realmId('authn-policy-mail'), {}, function () {
    const saved = authnPolicy.save('default', withDefaults({
      emailCodePrimary: true }));
    t.check(saved.ok && authnPolicy.allows('emailCode', 'primary') &&
            authnPolicy.active('emailCode', 'primary') ===
              authnPolicy.mailUsable(),
            'D3. allowed, and ACTIVE exactly when this realm can send mail');
    config.setOverride('mail.transport', 'off');
    try {
      t.check(authnPolicy.allows('emailCode', 'primary') &&
              !authnPolicy.active('emailCode', 'primary'),
              'D4. mail stops working: still allowed, no longer offered — ' +
              'fail closed');
      const view = adminViews.policiesView({});
      const row = view.authn.fields.filter(function (f) {
        return f.key === 'emailCodePrimary';
      })[0];
      t.check(row && row.disabled === true && /cannot send mail/.test(
                row.disabledWhy) && view.authn.mail.usable === false,
              'D5. the page draws the email rows DISABLED with the reason, ' +
              'rather than leaving them out',
              JSON.stringify(row));
    } finally {
      config.clearOverride('mail.transport');
      authnPolicy.reset('default');
    }
  });
  log.debug('Leaving mailGuard().');
}

function retired(t) {
  log.debug('Entering retired().');
  withRealm(t, realmId('authn-policy-retired'), {}, function () {
    t.check(totp.settings().enabled === true &&
            backupCodes.settings().enabled === true,
            'E1. by default authenticator apps and recovery codes are offered');
    const saved = authnPolicy.save('default', withDefaults({
      totpSecondFactor: false, recoveryCodeSecondFactor: false }));
    t.check(saved.ok && totp.settings().enabled === false &&
            backupCodes.settings().enabled === false,
            'E2. their policy rows are what `enabled` reads now (they were ' +
            'totp.enabled and backupCodes.enabled)');
    const gone = function (key) {
      log.debug('Entering gone().');
      try {
        config.value(key);
      } catch (e) {
        log.debug('Caught in gone(): ' + ((e && e.message) || e));
        // `no such setting` is the answer asked for.
        log.debug('Leaving gone().');
        return /no such setting/.test(String(e && e.message));
      }
      log.debug('Leaving gone(). Still a setting.');
      return false;
    };
    t.check(gone('totp.enabled') && gone('authn.mfaRequired') &&
            gone('backupCodes.enabled'),
            'E3. and the three settings are gone, with no shim');
    authnPolicy.reset('default');
  });
  log.debug('Leaving retired().');
}

function kinds(t) {
  log.debug('Entering kinds().');
  withRealm(t, realmId('authn-policy-kinds'), {}, function () {
    const view = adminViews.policiesView({});
    t.check(view.kinds.map(function (k) {
      return k.id;
    }).join(',') === 'password,authn' && !!view.password && !!view.authn &&
            Array.isArray(view.password.doors) && !!view.password.generator,
            'F1. the page holds both policies, and the password policy says ' +
            'everything it said before', JSON.stringify(view.kinds));
    t.check(view.actions.join(',') === 'save-password-policy,' +
            'reset-password-policy,save-authn-policy,reset-authn-policy',
            'F2. the actions are every kind\'s, the password policy\'s by ' +
            'the names they always had', view.actions.join(','));
    const saved = adminActions.policiesAction(Object.assign(
      { action: 'save-authn-policy' }, withDefaults()), { via: 'api' });
    t.check(saved.ok && saved.kind === 'authn' &&
            saved.profile.from === 'realm',
            'F3. save-authn-policy is handed to the authentication policy',
            JSON.stringify(saved.errors));
    adminActions.policiesAction({ action: 'reset-authn-policy' },
                                { via: 'api' });
    // A KIND REGISTERED LATER: a module with the interface, and a row.
    const store = {};
    const stub = {
      FIELDS: [{ key: 'widgets', attribute: 'stsWidgets', type: 'int',
                 dflt: 3, min: 0, max: 9, label: 'Widgets',
                 what: 'How many.' }],
      DEFAULTS: { widgets: 3 },
      SCHEMA: { container: 'ou=widgetPolicies', objectClasses: [],
                attributes: [] },
      DEFAULT_PROFILE: 'default',
      read: function () {
        return { name: 'default', stored: !!store.w, dn: '', description: '',
                 sources: { widgets: store.w ? 'directory' : 'built-in' },
                 problems: [], enforced: true, widgets: store.w || 3 };
      },
      list: function () {
        return [this.read()];
      },
      save: function (name, body) {
        store.w = Number(body.widgets);
        return { ok: true, profile: this.read() };
      },
      reset: function () {
        const had = !!store.w;
        delete store.w;
        return { ok: true, removed: had, profile: this.read() };
      },
      describe: function (p) {
        return [String((p || this.read()).widgets) + ' widgets'];
      }
    };
    policyKinds.register({ id: 'widget', label: 'Widget policy',
      container: 'ou=widgetPolicies', governs: 'widgets', module: stub,
      auditAction: 'admin.password-policy.change',
      appliesTo: 'the next widget', fallsBackTo: 'three widgets' });
    try {
      const later = adminViews.policiesView({});
      t.check(later.kinds.some(function (k) {
        return k.id === 'widget';
      }) && later.widget && later.widget.fields[0].key === 'widgets' &&
              later.actions.indexOf('save-widget-policy') >= 0,
              'F4. a kind registered later is on the page, in the JSON and ' +
              'in the actions with no other edit');
      const done = adminActions.policiesAction(
        { action: 'save-widget-policy', widgets: '7' }, { via: 'api' });
      t.check(done.ok && store.w === 7,
              'F5. and its save is dispatched to its own module',
              JSON.stringify(done));
      const unknown = adminActions.policiesAction(
        { action: 'no-such-action-exists' }, { via: 'api' });
      t.check(!unknown.ok && /save-widget-policy, reset-widget-policy/.test(
                unknown.errors[0]) && /The six are/.test(unknown.errors[0]),
              'F6. the refusal of an unknown action names every kind\'s — ' +
              'the sentence the parity checks read', unknown.errors[0]);
    } finally {
      policyKinds.unregister('widget');
    }
  });
  log.debug('Leaving kinds().');
}

function risk(t) {
  log.debug('Entering risk().');
  const email = riskEngine.satisfiedBy(['pwd', 'otp'], 'mfa', ['email-code']);
  const code = riskEngine.satisfiedBy(['pwd', 'otp'], 'mfa', ['totp']);
  const key = riskEngine.satisfiedBy(['pwd', 'hwk'], 'mfa', ['email-link']);
  t.check(email.length === 0 && code.join(',') === 'second-factor' &&
          key.indexOf('security-key') >= 0,
          'G1. an emailed second factor meets NO risk step-up; an app code ' +
          'meets the second-factor one; a key still meets the key one',
          JSON.stringify([email, code, key]));
  log.debug('Leaving risk().');
}

function issuancePolicy(t) {
  log.debug('Entering issuancePolicy().');
  const templates = require('../xacml/xacml_templates');
  const pdp = require('../xacml/xacml_pdp');
  const rolePep = require('../xacml/xacml_role_pep');
  const AUTHN = templates.AUTHN_ATTRIBUTE;
  const plain = templates.build('role-issuance', {},
                                { name: 'role-issuance' });
  t.check(plain.ok && !plain.policy.rules.some(function (r) {
    return /:rule:email-factor$/.test(r.id);
  }), 'H1. the built-in issuance policy carries no email rule by default');
  const strict = templates.build('role-issuance',
    { refuseEmailFactor: 'yes' }, { name: 'role-issuance' });
  t.check(strict.ok && strict.policy.rules.some(function (r) {
    return /:rule:email-factor$/.test(r.id);
  }), 'H2. refuseEmailFactor: yes adds one', JSON.stringify(strict.why));
  const request = function (kinds) {
    log.debug('Entering request().');
    log.debug('Leaving request().');
    return rolePep.buildRequest({
      application: 'app', kind: 'start-session',
      subject: { kind: 'user', name: 'someone', authenticated: true },
      authentication: { amr: ['pwd', 'otp'], acr: 'mfa', kinds: kinds } },
      ['EVERYBODY'], [], ['EVERYBODY']);
  };
  const byEmail = pdp.evaluate(strict.policy, request(['email-code']), {});
  const byApp = pdp.evaluate(strict.policy, request(['totp']), {});
  t.check(byEmail.decision === 'Deny' &&
          (byEmail.obligations || []).some(function (o) {
            return o.id === AUTHN.OBLIGATION;
          }) && byApp.decision === 'Permit',
          'H3. it DENIES a session on an emailed code, with the ' +
          'authentication obligation, and permits one on an app',
          byEmail.decision + ' / ' + byApp.decision);
  log.debug('Leaving issuancePolicy().');
}

module.exports = {
  name: 'authn policy',
  describe: 'The authentication policy (#64): the built-in profile, whole ' +
            'saves, inheritance from the default realm, the mail guard, the ' +
            'three retired settings, one Policies page for every kind, and ' +
            'no risk step-up met by email',
  run: async function (t) {
    log.debug('Entering run().');
    builtIn(t);
    saves(t);
    inheritance(t);
    mailGuard(t);
    retired(t);
    kinds(t);
    risk(t);
    issuancePolicy(t);
    log.debug('Leaving run().');
  }
};
