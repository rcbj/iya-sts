// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_claim_selections.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S OWN DIRECTORY-ATTRIBUTE SELECTIONS AND CREDENTIAL CLAIMS
// (#495).
//
// The ticked catalogue of the realm's Custom claims, UserInfo claims, Custom
// SAML attributes and Credential claims pages, per application, on its
// configuration tab's protocol sub-tabs. HELD, an application's selection
// REPLACES the realm's for that set; absent, the realm's is in force.
// Asserted, in a CHILD PROCESS that loads the stack, through the functions
// the token endpoint, the SAML builders and the credential issuer call:
//
//   A. the JSON sets: the realm ticks `mail`; an application selecting
//      `givenName` gets givenName and NOT mail, another client still gets
//      mail; an EMPTY selection carries no attribute; inheriting brings the
//      realm's back;
//   B. the refusals (STS-REG-0215): an attribute the catalogue does not
//      hold, an unknown set, a set whose protocol is not declared, a stored
//      value that is not a list of names (written past the action) — and a
//      bad stored value is ignored at issuance;
//   C. SAML 2.0 by audience;
//   D. the credential claims: `applicationRows()` and `rowsForPaths()`
//      against the client's own selection;
//   E. the view model and the markup the sub-tabs draw.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'application_claim_selections',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.AC_ROOT;
  const OUT = process.env.AC_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const stats = require(ROOT + '/common/admin_stats');
    const claimAttributes = require(ROOT + '/common/claim_attributes');
    const vcClaims = require(ROOT + '/oid4vc/vc_claims');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_applications');
    // A render context carries the translator since #539; WebKit.context()
    // gives node's, English (common/i18n.ts installs it).
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const errorCodes = require(ROOT + '/common/error_codes');
    const stamp = String(Date.now()).slice(-6);
    const realm = realms.create({ id: 'acs-' + stamp, name: 'acs' }).realm;
    await realms.run(realm, async function () {
      const act = function (body) {
        return actions.applicationsAction(body, [], {});
      };
      const code = function (answer) {
        return errorCodes.codeOf(answer);
      };
      applications.createApplication({ identifier: 'acs-web',
        protocols: ['oauth2', 'oidc'], fields: {} });
      applications.createApplication({ identifier: 'acs-other',
        protocols: ['oauth2', 'oidc'], fields: {} });
      applications.createApplication({ identifier: 'acs-sp',
        protocols: ['saml2'], fields: {} });
      applications.createApplication({ identifier: 'acs-wallet',
        protocols: ['oauth2', 'oid4vci'], fields: {} });
      claimAttributes.setSelection('id_token', ['mail']);
      claimAttributes.setSelection('saml2', ['mail']);

      // --- A. The JSON sets ---------------------------------------------
      const ctx = function (client) {
        return { client_id: client, sub: 'x', username: 'alice' };
      };
      const before = stats.jwtClaims('id_token', ctx('acs-web'));
      const set = act({ action: 'set-claim-attributes',
        application: 'acs-web', set: 'id_token',
        attributes: ['givenName'] });
      const own = stats.jwtClaims('id_token', ctx('acs-web'));
      const other = stats.jwtClaims('id_token', ctx('acs-other'));
      note(before.email !== undefined,
           'A0. the realm\'s selection reaches the client first',
           JSON.stringify(before));
      note(set.ok && own.given_name !== undefined && own.email === undefined,
           'A1. its own selection REPLACES the realm\'s: givenName in, ' +
           'mail out', JSON.stringify([set.errors, own]));
      note(other.email !== undefined && other.given_name === undefined,
           'A2. another client still gets the realm\'s selection',
           JSON.stringify(other));
      const empty = act({ action: 'set-claim-attributes',
        application: 'acs-web', set: 'id_token', attributes: [''] });
      const none = stats.jwtClaims('id_token', ctx('acs-web'));
      note(empty.ok && none.email === undefined &&
           none.given_name === undefined &&
           String([].concat(applications.get('acs-web').fields
             .oauthClaimAttributesIdToken)[0]) === '[]',
           'A3. an empty selection is held as [] and carries no attribute',
           JSON.stringify([empty.errors, none]));
      const back = act({ action: 'inherit-claim-attributes',
        application: 'acs-web', set: 'id_token' });
      note(back.ok && back.inherited === true &&
           stats.jwtClaims('id_token', ctx('acs-web')).email !== undefined,
           'A4. inheriting brings the realm\'s selection back');

      // --- B. The refusals ----------------------------------------------
      const unknownAttr = act({ action: 'set-claim-attributes',
        application: 'acs-web', set: 'id_token', attributes: ['nope'] });
      const unknownSet = act({ action: 'set-claim-attributes',
        application: 'acs-web', set: 'nope', attributes: [] });
      const wrongFamily = act({ action: 'set-claim-attributes',
        application: 'acs-sp', set: 'id_token', attributes: ['mail'] });
      const notAList = applications.updateApplication('acs-web',
        { mode: 'set', attribute: 'oauthClaimAttributesIdToken',
          value: '"mail"' });
      note(code(unknownAttr) === 'STS-REG-0215' &&
           code(unknownSet) === 'STS-REG-0215' &&
           code(wrongFamily) === 'STS-REG-0215' &&
           code(notAList) === 'STS-REG-0215',
           'B1. an unknown attribute, an unknown set, an undeclared family ' +
           'and a value that is not a list are refused',
           JSON.stringify([code(unknownAttr), code(unknownSet),
                           code(wrongFamily), code(notAList)]));
      note(claimAttributes.applicationSelection('id_token',
             { identifier: 'hand', fields: {
               oauthClaimAttributesIdToken: '["nope"]' } }) === null,
           'B2. a stored selection the catalogue refuses is ignored');

      // --- C. SAML 2.0 ---------------------------------------------------
      act({ action: 'set-claim-attributes', application: 'acs-sp',
            set: 'saml2', attributes: ['givenName'] });
      const names = function (list) {
        return list.map(function (a) { return a.name; });
      };
      const sp = names(stats.samlAttributes('saml2',
        { subject: 'alice', audience: 'acs-sp' }));
      const elsewhere = names(stats.samlAttributes('saml2',
        { subject: 'alice', audience: 'somebody-else' }));
      note(sp.indexOf('given_name') >= 0 && sp.indexOf('email') < 0 &&
           elsewhere.indexOf('email') >= 0,
           'C1. SAML 2.0: the service provider\'s selection replaces the ' +
           'realm\'s by audience', JSON.stringify([sp, elsewhere]));

      // --- D. The credential claims --------------------------------------
      const vcSet = act({ action: 'set-claim-attributes',
        application: 'acs-wallet', set: 'credential',
        attributes: ['givenName'] });
      const vcWrong = act({ action: 'set-claim-attributes',
        application: 'acs-web', set: 'credential',
        attributes: ['givenName'] });
      const wallet = stats.claimApplicationOf('access_token',
        { client_id: 'acs-wallet' });
      const rows = vcClaims.applicationRows(wallet) || [];
      const asked = vcClaims.rowsForPaths([['given_name'], ['family_name']],
                                          'dc+sd-jwt', rows);
      note(vcSet.ok && code(vcWrong) === 'STS-REG-0215' &&
           rows.map(function (r) { return r.ldap; }).join() === 'givenName' &&
           asked.map(function (r) { return r.ldap; }).join() === 'givenName' &&
           vcClaims.applicationRows(applications.get('acs-other')) === null,
           'D1. a client\'s credential selection is held, refused for a ' +
           'client not declared for OpenID4VCI, and narrows a wallet\'s ' +
           'request', JSON.stringify([vcSet.errors, code(vcWrong), rows,
                                      asked]));

      // --- E. The view model and the markup -------------------------------
      act({ action: 'set-claim-attributes', application: 'acs-web',
            set: 'access_token', attributes: ['sn'] });
      const view = views.applicationClaimsState(
        applications.get('acs-web'), 'bob').selections;
      const access = view.sets.filter(function (one) {
        return one.id === 'access_token';
      })[0];
      const idToken = view.sets.filter(function (one) {
        return one.id === 'id_token';
      })[0];
      note(view.preview.user === 'bob' && access.inherited === false &&
           access.own.join() === 'sn' && idToken.inherited === true &&
           idToken.effective.join() === 'mail' && view.credential === null &&
           view.catalogue.length > 5,
           'E1. the model: each set\'s own, the realm\'s and the one in ' +
           'force, no credential section for a client not declared for ' +
           'OpenID4VCI', JSON.stringify([access, idToken]));
      const walletView = views.applicationClaimsState(
        applications.get('acs-wallet')).selections;
      note(walletView.credential && walletView.credential.own.join() ===
             'givenName',
           'E2. an OpenID4VCI client\'s model carries its credential claims',
           JSON.stringify(walletView.credential));
      const html = page.applicationClaimSelectionSection(WebKit.context({}, true),
        { identifier: 'acs-web', page: { claimSelections: view } },
        '', ['access_token', 'id_token'], 'cfg-oauth');
      note(/name="attributes" value="sn" checked/.test(html) &&
           !/name="attributes" value="mail" checked[^>]*aria-label="mail">/
             .test(html.split('Custom claims')[0].split('</table>')[0]) &&
           html.indexOf('inherit-claim-attributes') >= 0 &&
           html.indexOf('set-claim-attributes') >= 0 &&
           html.indexOf('name="claimsUser"') >= 0,
           'E3. the markup: the boxes in force ticked, Save, Use the ' +
           'realm\'s, and the preview form', html.slice(0, 400));
      const readOnly = page.applicationClaimSelectionSection(
        WebKit.context({}, false),
        { identifier: 'acs-web', page: { claimSelections: view } },
        '', ['access_token'], 'cfg-oauth');
      note(readOnly.indexOf('<input type="checkbox"') < 0 &&
           readOnly.indexOf('set-claim-attributes') < 0,
           'E4. a reader without write sees no form');
      claimAttributes.setSelection('id_token', []);
      claimAttributes.setSelection('saml2', []);
    });
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'application-claim-selections-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', AC_ROOT: ROOT, AC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_claim_selections',
  describe: 'an application\'s own directory-attribute selections and ' +
            'credential claims (#495): replacing the realm\'s when held, ' +
            'held to the catalogue, and the configuration tabs\' model ' +
            'and markup',
  run: run
};
