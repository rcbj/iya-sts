// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: named_authn_policies.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION NAMES A SCOPED AUTHENTICATION POLICY (#1148, 2026-10-29).
//
// rcbj: replace `appAuthnMechanism` and `appMfaMechanism` with ONE field that
// points at a named, scoped authentication policy; the application names the
// policy (`appAuthnPolicy`), and a named policy holds two lists only — the
// first-factor mechanisms and the second factors it allows. In a CHILD
// PROCESS that loads the stack, in a throwaway realm:
//
//   A. SAVING: a named policy is saved and listed; a bad name, `default`
//      and an unknown mechanism are refused (STS-AUTHN-0532, 0533).
//   B. THE FIELD: `appAuthnPolicy` takes `default` or a policy of the realm,
//      and refuses one the realm does not hold.
//   C. RESOLVING: `mechanismsFor()` and both `allowedOf()`s read the
//      policy's lists; default allows every one; a name no policy holds
//      allows NOTHING (fail closed).
//   D. DELETING: refused while an application names it (STS-AUTHN-0534),
//      done once none does, and refused for a name nobody holds (0535).
//   E. THE CONSOLE'S DOOR: the two acts through `policiesAction()`, and the
//      policies view's named policies with the applications naming them.
//   F. THE MARKUP: the named policies section — a row each with its lists
//      and who names it, Change and Delete (disabled while named), and the
//      form for a new one with an empty value per checkbox group.
//   G. A POLICY IS ITS REALM'S: another realm does not see it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({
  name: 'named_authn_policies',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.NAP_ROOT;
  const OUT = process.env.NAP_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const authnMechanisms = require(ROOT + '/common/authn_mechanisms');
    const mfaMechanisms = require(ROOT + '/common/mfa_mechanisms');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_policies');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const errorCodes = require(ROOT + '/common/error_codes');
    require(ROOT + '/ldap/ldap_server');
    const stamp = String(Date.now()).slice(-6);
    const realmA = realms.create({ id: 'nap-a-' + stamp, name: 'nap a' })
      .realm;
    const realmB = realms.create({ id: 'nap-b-' + stamp, name: 'nap b' })
      .realm;
    const code = function (answer) {
      return errorCodes.codeOf(answer);
    };
    const act = function (body) {
      return actions.applicationsAction(body, [], {});
    };

    await realms.run(realmA, async function () {
      // --- A. Saving --------------------------------------------------------
      const saved = authnPolicy.saveNamed('passkeys-only', {
        description: 'Passwordless', mechanisms: ['webauthn'],
        secondFactors: ['securityKey', 'totp'] });
      const listed = authnPolicy.named();
      note(saved.ok && listed.length === 1 &&
           listed[0].name === 'passkeys-only' &&
           listed[0].description === 'Passwordless' &&
           listed[0].mechanisms.join() === 'webauthn' &&
           listed[0].secondFactors.join() === 'securityKey,totp' &&
           /^cn=passkeys-only,ou=authnPolicies/.test(listed[0].dn),
           'A1. a named policy is saved in ou=authnPolicies and listed with ' +
           'its two lists', JSON.stringify([saved, listed]));
      const badName = authnPolicy.saveNamed('Bad Name', {});
      const asDefault = authnPolicy.saveNamed('default', {});
      const unknown = authnPolicy.saveNamed('odd', {
        mechanisms: ['smoke-signals'], secondFactors: ['carrier-pigeon'] });
      note(code(badName) === 'STS-AUTHN-0532' &&
           code(asDefault) === 'STS-AUTHN-0532' &&
           code(unknown) === 'STS-AUTHN-0533' &&
           (unknown.errors || []).length === 2,
           'A2. a bad name and `default` are refused (STS-AUTHN-0532), and ' +
           'so is each unknown mechanism (STS-AUTHN-0533)',
           JSON.stringify([badName.errors, asDefault.errors,
                           unknown.errors]));
      note(authnPolicy.saveNamed('open', {}).ok &&
           authnPolicy.namedPolicy('open').mechanisms.length === 0,
           'A3. a policy listing nothing is saved, and allows every one');

      // --- B. The field -----------------------------------------------------
      applications.createApplication({ identifier: 'nap-web',
        protocols: ['oauth2', 'oidc'], fields: {} });
      const named = act({ action: 'set', application: 'nap-web',
                          attribute: 'appAuthnPolicy',
                          value: 'passkeys-only' });
      const ghost = act({ action: 'set', application: 'nap-web',
                          attribute: 'appAuthnPolicy', value: 'ghost' });
      note(named.ok && !ghost.ok &&
           [].concat(applications.get('nap-web').fields.appAuthnPolicy)
             .join() === 'passkeys-only',
           'B1. appAuthnPolicy takes a policy of the realm, and refuses one ' +
           'it does not hold', JSON.stringify([named.errors, ghost.errors]));
      const fields = applications.applicationFields();
      const row = fields.filter(function (one) {
        return one.attribute === 'appAuthnPolicy';
      })[0];
      note(row && JSON.stringify(row.choices) ===
             '["default","open","passkeys-only"]' &&
           !fields.some(function (one) {
             return one.attribute === 'appAuthnMechanism' ||
               one.attribute === 'appMfaMechanism';
           }),
           'B2. its choices are default and the realm\'s policies, and the ' +
           'two old attributes are gone', JSON.stringify(row && row.choices));

      // --- C. Resolving -----------------------------------------------------
      const web = applications.get('nap-web').fields;
      const resolved = authnPolicy.mechanismsFor(web);
      note(resolved.policy === 'passkeys-only' && !resolved.missing &&
           authnMechanisms.allowedOf(web).join() === 'webauthn' &&
           mfaMechanisms.allowedOf(web).join() === 'securityKey,totp',
           'C1. both allowedOf()s read the named policy\'s lists',
           JSON.stringify(resolved));
      const plain = authnPolicy.mechanismsFor({});
      note(plain.policy === 'default' && !plain.missing &&
           authnMechanisms.allowedOf({}).length === 0 &&
           authnMechanisms.allowedOf({ appAuthnPolicy: 'default' })
             .length === 0,
           'C2. no policy, or default, allows every mechanism');
      const missing = authnPolicy.mechanismsFor({ appAuthnPolicy: 'gone' });
      const missingAllowed = authnMechanisms.allowedOf(
        { appAuthnPolicy: 'gone' });
      note(missing.missing && missingAllowed.length === 1 &&
           ['password', 'webauthn', 'spnego', 'wallet']
             .every(function (one) {
               return missingAllowed.indexOf(one) < 0;
             }),
           'C3. a name no policy holds allows no mechanism (fail closed)',
           JSON.stringify(missingAllowed));

      // --- D. Deleting ------------------------------------------------------
      const delAct = function (name) {
        return actions.policiesAction({
          action: 'delete-named-authn-policy', name: name },
          { actor: 'test', via: 'test' });
      };
      const inUse = delAct('passkeys-only');
      note(!inUse.ok && code(inUse) === 'STS-AUTHN-0534' &&
           /nap-web/.test((inUse.errors || []).join(' ')) &&
           !!authnPolicy.namedPolicy('passkeys-only'),
           'D1. a policy an application names is not deleted ' +
           '(STS-AUTHN-0534), and the refusal names the application',
           JSON.stringify(inUse.errors));
      act({ action: 'set', application: 'nap-web',
            attribute: 'appAuthnPolicy', value: 'default' });
      const gone = delAct('passkeys-only');
      const nobody = delAct('never-was');
      note(gone.ok && gone.removed === true &&
           !authnPolicy.namedPolicy('passkeys-only') &&
           !nobody.ok && code(nobody) === 'STS-AUTHN-0535',
           'D2. once nothing names it, it is deleted; a name nobody holds is ' +
           'refused (STS-AUTHN-0535)', JSON.stringify([gone, nobody.errors]));

      // --- E. The console's door ------------------------------------------
      const viaAct = actions.policiesAction({
        action: 'save-named-authn-policy', name: 'wallet-or-key',
        mechanisms: ['wallet', 'webauthn'], secondFactors: [''] },
        { actor: 'test', via: 'console' });
      act({ action: 'set', application: 'nap-web',
            attribute: 'appAuthnPolicy', value: 'wallet-or-key' });
      const view = views.policiesView({});
      const member = view.kinds.filter(function (one) {
        return one.id === 'authn';
      })[0] || {};
      const ap = view.authn || member;
      const shown = ((ap && ap.named) || []).filter(function (one) {
        return one.name === 'wallet-or-key';
      })[0];
      note(viaAct.ok && shown &&
           shown.namedBy.applications.join() === 'nap-web' &&
           shown.namedBy.groups.length === 0 && shown.precedence === 100 &&
           shown.mechanisms.join() === 'wallet,webauthn' &&
           shown.secondFactors.length === 0 &&
           (ap.vocabulary.mechanisms || []).indexOf('spnego') >= 0,
           'E1. the save act through policiesAction() stores the lists (an ' +
           'empty value posts nothing), and the view lists the policy with ' +
           'the applications naming it', JSON.stringify([viaAct, shown]));

      // --- F. The markup ----------------------------------------------------
      const parts = page.namedAuthnPoliciesSection(ap,
        WebKit.context({}, true).t);
      const html = parts.list + parts.add;
      note(/id="authn-named"/.test(html) &&
           /<code>wallet-or-key<\/code>/.test(html) &&
           /value="delete-named-authn-policy"[^]*?<button class="secondary" disabled/
             .test(html) &&
           /name="mechanisms" value="">/.test(html) &&
           /name="secondFactors" value="">/.test(html) &&
           /name="mechanisms" value="wallet"[^>]*checked/.test(html) &&
           (html.match(/value="save-named-authn-policy"/g) || []).length ===
             1 + ap.named.length,
           'F1. the section: a row per policy with its lists and who names ' +
           'it, Delete disabled while named, a Change form each and one for ' +
           'a new policy, each group posting an empty value first',
           html.slice(0, 600));
      const tab = page.authnPolicySection(view, WebKit.context({}, true).t);
      const at = function (id) {
        return tab.indexOf('class="subpanel' +
                           (id === 'default' ? ' first' : '') +
                           '" id="authn-sub-' + id + '"');
      };
      note(at('default') > 0 && at('named') > at('default') &&
           at('new') > at('named') &&
           tab.indexOf('id="authn-named"') > at('named') &&
           tab.indexOf('id="authn-named"') < at('new') &&
           tab.indexOf('id="authn-new"') > at('new') &&
           tab.indexOf('id="authn-schema"') > at('new'),
           'F2. the tab is three sub-tabs, as the passkey policy\'s: ' +
           'Default, Named policies and New policy, the schema under them',
           tab.slice(0, 400));
    });

    // --- G. A policy is its realm's ------------------------------------------
    await realms.run(realmB, async function () {
      note(authnPolicy.named().length === 0 &&
           !authnPolicy.namedPolicy('wallet-or-key'),
           'G1. another realm does not see this realm\'s named policies');
    });
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'named-authn-policies-' + process.pid +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', NAP_ROOT: ROOT,
                                  NAP_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'named_authn_policies',
  describe: 'an application names a scoped authentication policy holding ' +
            'its first-factor and second-factor lists, which replaced ' +
            'appAuthnMechanism and appMfaMechanism (#1148)',
  run: run
};
