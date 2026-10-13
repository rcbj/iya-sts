// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_enrollment.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S ACME, EST AND SCEP RULES (2026-10-01).
//
// ACME, EST and SCEP are protocol families an application may be declared
// for, and its Certificate enrollment tab carries overrides for them.
// `common/cert_enrollment.ts`'s `applicationRules()` applies them to an
// application subject. Asserted, in a CHILD PROCESS that loads the stack,
// through the core's own functions:
//
//   A. the declaration (#380's rule, kind issue-certificate): in a product
//      realm, an application declared for other families is refused
//      (STS-ENROLL-0094), one declared for the family or for nothing is not;
//      a development realm refuses nothing;
//   B. the profiles: <family>AllowedProfiles OVERRIDES the realm's list —
//      narrower or wider, never a CA profile — checkProfile() refuses a
//      profile outside it (STS-ENROLL-0095), <family>DefaultProfile replaces
//      the realm default for a request that named none, where allowed;
//   C. the lifetime and the cap are the application's where it set them,
//      longer or shorter than the realm's;
//   D. EST: estBasicAuthentication, estCertificateAuthentication and
//      estServerKeyGeneration override the realm's switches both ways —
//      FALSE refuses (STS-ENROLL-0096), TRUE turns on what the realm off;
//   E. the choices the tab offers: every profile, and `device` for EST and
//      SCEP only; a person's entry is untouched by all of it;
//   F. the panel the application's Credentials and Certificate enrollment
//      tabs draw (`applicationEnrollmentState()`): the rules in force, the
//      certificates it was issued, its EAB keys and challenges with no
//      secret, its host names; and `enrollmentReturnTo()`.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'application_enrollment',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.AE_ROOT;
  const OUT = process.env.AE_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const core = require(ROOT + '/common/cert_enrollment');
    const errorCodes = require(ROOT + '/common/error_codes');
    const stamp = String(Date.now()).slice(-6);
    const code = function (answer) {
      return errorCodes.codeOf(answer);
    };
    const app = function (id) {
      return { kind: 'application', id: id };
    };

    const product = realms.create({ id: 'ae-p' + stamp, name: 'ae product',
      overrides: { 'global.mode': 'product' } }).realm;
    await realms.run(product, async function () {
      // --- A. The declaration --------------------------------------------
      applications.createApplication({ identifier: 'ae-oauth',
        protocols: ['oauth2'], fields: {} });
      applications.createApplication({ identifier: 'ae-est',
        protocols: ['est'], fields: {} });
      applications.createApplication({ identifier: 'ae-none',
        protocols: [], fields: {} });
      const refused = core.applicationRules('est', app('ae-oauth'), {},
                                            'tls-client');
      note(refused.ok === false && code(refused) === 'STS-ENROLL-0094',
           'A1. product: an application declared for OAuth 2.0 alone is ' +
           'refused an EST certificate', JSON.stringify(refused.errors));
      note(core.applicationRules('est', app('ae-est'), {}, 'tls-client').ok,
           'A2. product: one declared for EST is not');
      note(core.applicationRules('scep', app('ae-none'), {}, 'tls-client').ok,
           'A3. product: one declared for nothing is not');
      note(core.applicationRules('est', { kind: 'person', id: 'nobody' }, {},
                                 'tls-client').ok,
           'A4. a person\'s entry is not asked about families');
    });

    // The realm narrows EST to two profiles, so an application list naming
    // a third shows that it cannot widen what the realm allows.
    const dev = realms.create({ id: 'ae-d' + stamp, name: 'ae development',
      overrides: { 'est.allowedProfiles': 'tls-server,tls-client' } }).realm;
    await realms.run(dev, async function () {
      applications.createApplication({ identifier: 'ae-oauth',
        protocols: ['oauth2'], fields: {} });
      note(core.applicationRules('est', app('ae-oauth'), {},
                                 'tls-client').ok,
           'A5. development: the same application is not refused');

      // --- B. The profiles -----------------------------------------------
      const realmList = core.allowedProfiles('est');
      const one = realmList[0];
      const other = realmList.filter(function (p) { return p !== one; })[0];
      applications.createApplication({ identifier: 'ae-narrow',
        protocols: ['est'], fields: { estAllowedProfiles: [one],
                                      estDefaultProfile: one } });
      const narrowed = core.allowedProfiles('est', app('ae-narrow'));
      note(narrowed.length === 1 && narrowed[0] === one,
           'B1. estAllowedProfiles replaces the realm\'s list (narrower)',
           JSON.stringify(narrowed));
      if (other) {
        const outside = core.checkProfile('est', other, app('ae-narrow'));
        note(outside.ok === false && code(outside) === 'STS-ENROLL-0095',
             'B2. a profile the realm allows and the application does not ' +
             'is refused', JSON.stringify(outside.errors));
        const ruled = core.applicationRules('est', app('ae-narrow'),
          { profileDefaulted: true }, other);
        note(ruled.ok && ruled.profile === one,
             'B3. a request that named no profile takes the application\'s ' +
             'default', JSON.stringify(ruled));
        const named = core.applicationRules('est', app('ae-narrow'),
          { profileDefaulted: false }, other);
        note(named.ok === false && code(named) === 'STS-ENROLL-0095',
             'B4. a named profile outside the application\'s list is refused');
      }
      note(core.defaultProfile('est', app('ae-narrow')) === one,
           'B5. defaultProfile() answers the application\'s default');
      const outsideRealm = ['tls-server', 'tls-client', 'tls-server-client',
        'digital-signature', 'key-encipherment', 'code-signing', 'email',
        'timestamping', 'smartcard-logon'].filter(function (p) {
        return realmList.indexOf(p) < 0;
      })[0];
      if (outsideRealm) {
        applications.createApplication({ identifier: 'ae-wide',
          protocols: ['est'], fields: {
            estAllowedProfiles: [one, outsideRealm] } });
        note(core.allowedProfiles('est', app('ae-wide')).indexOf(
          outsideRealm) >= 0 &&
             core.checkProfile('est', outsideRealm, app('ae-wide')).ok &&
             core.checkProfile('est', outsideRealm).ok === false,
             'B6. an application list may widen the realm\'s, for that ' +
             'application only', outsideRealm);
        applications.createApplication({ identifier: 'ae-ca',
          protocols: ['est'], fields: {} });
        note(core.checkProfile('est', 'root-ca', app('ae-ca')).ok === false,
             'B7. a CA profile is refused whatever the application lists');
      }

      // --- C. Lifetime and cap -------------------------------------------
      const realmDays = Number(config.value('est.certificateLifetimeDays'));
      const realmCap = Number(config.value(
        'pki.enrollmentMaxCertificatesPerEntry'));
      applications.createApplication({ identifier: 'ae-short',
        protocols: ['est'], fields: { estCertificateLifetimeDays: '1',
                                      enrollMaxCertificates: '1' } });
      const short = core.applicationRules('est', app('ae-short'), {},
                                          realmList[0]);
      note(short.ok && short.days === 1 && short.cap === 1,
           'C1. a shorter lifetime and a lower cap are used',
           JSON.stringify(short));
      applications.createApplication({ identifier: 'ae-long',
        protocols: ['est'], fields: {
          estCertificateLifetimeDays: String(realmDays + 100),
          enrollMaxCertificates: String(realmCap + 7) } });
      const long = core.applicationRules('est', app('ae-long'), {},
                                         realmList[0]);
      note(long.ok && long.days === realmDays + 100 &&
           long.cap === realmCap + 7,
           'C3. a longer lifetime and a higher cap override the realm\'s',
           JSON.stringify(long));
      const plain = core.applicationRules('est', app('ae-est-plain'), {},
                                          realmList[0]);
      note(plain.days === realmDays && plain.cap === realmCap,
           'C2. without overrides the realm\'s values stand',
           JSON.stringify(plain));

      // --- D. EST's authentication ---------------------------------------
      applications.createApplication({ identifier: 'ae-noauth',
        protocols: ['est'], fields: { estBasicAuthentication: 'FALSE',
          estCertificateAuthentication: 'FALSE',
          estServerKeyGeneration: 'FALSE' } });
      const self = { kind: 'application', id: 'ae-noauth' };
      const basic = core.applicationRules('est', app('ae-noauth'),
        { principal: self }, realmList[0]);
      const cert = core.applicationRules('est', app('ae-noauth'),
        { principal: Object.assign({ certificateSerial: '01' }, self) },
        realmList[0]);
      const admin = core.applicationRules('est', app('ae-noauth'),
        { principal: { kind: 'person', id: 'admin', admin: true } },
        realmList[0]);
      const server = core.applicationRules('est', app('ae-noauth'),
        { principal: { kind: 'person', id: 'admin', admin: true },
          keySource: 'server' }, realmList[0]);
      note(code(basic) === 'STS-ENROLL-0096' &&
           code(cert) === 'STS-ENROLL-0096' && admin.ok &&
           code(server) === 'STS-ENROLL-0096',
           'D1. each EST override refuses its own method when the ' +
           'application authenticated itself, and serverkeygen whoever ' +
           'asked', JSON.stringify([basic.errors, cert.errors, admin.ok,
                                    server.errors]));
      note(core.applicationRules('scep', app('ae-noauth'),
        { principal: self }, 'tls-client').ok,
           'D2. the EST overrides do not reach SCEP');
      // TRUE turns on what the realm turned off, for that application only.
      config.setOverride('est.basicAuthentication', false);
      config.setOverride('est.serverKeyGeneration', false);
      applications.createApplication({ identifier: 'ae-on',
        protocols: ['est'], fields: { estBasicAuthentication: 'TRUE',
                                      estServerKeyGeneration: 'TRUE' } });
      const on = { kind: 'application', id: 'ae-on' };
      note(core.estSwitch('basicAuthentication', app('ae-on')) === true &&
           core.estSwitch('basicAuthentication', app('ae-noauth')) === false &&
           core.estSwitch('basicAuthentication') === false &&
           core.applicationRules('est', app('ae-on'),
             { principal: on, keySource: 'server' }, realmList[0]).ok,
           'D3. TRUE overrides a realm switch that is off, for that ' +
           'application only');
      config.clearOverride('est.basicAuthentication');
      config.clearOverride('est.serverKeyGeneration');

      // --- E. The choices ------------------------------------------------
      const rows = applications.applicationFields();
      const choicesOf = function (name) {
        return (rows.filter(function (r) {
          return r.attribute === name;
        })[0] || {}).choices || [];
      };
      note(choicesOf('estAllowedProfiles').indexOf('device') >= 0 &&
           choicesOf('scepDefaultProfile').indexOf('device') >= 0 &&
           choicesOf('acmeAllowedProfiles').indexOf('device') < 0 &&
           choicesOf('acmeAllowedProfiles').indexOf('tls-client') >= 0,
           'E1. the profile choices are the profiles, device for EST and ' +
           'SCEP only');
      note(rows.filter(function (r) {
        return /^(acme|est|scep|enroll)[A-Z]/.test(r.attribute);
      }).every(function (r) { return r.group === 'enroll'; }),
           'E2. every enrollment override is in the Certificate enrollment ' +
           'group');

      // --- F. The panel's model, and where its forms come back to -------
      const pki = require(ROOT + '/common/pki');
      const adminViews = require(ROOT + '/admin-core/admin_views');
      const estConsole = require(ROOT + '/est/est_console');
      if (!pki.hasRoot()) {
        await pki.start({});
      }
      await pki.ensureScope(realms.currentId());
      applications.createApplication({ identifier: 'ae-panel',
        protocols: ['acme', 'est', 'scep'], fields: {
          estCertificateLifetimeDays: '30' } });
      const panelEntry = { kind: 'application', id: 'ae-panel' };
      const issued = await estConsole.estAction({
        action: 'issue-server-key', kind: 'application',
        identifier: 'ae-panel', profile: 'tls-client' }, { via: 'api' });
      const eab = core.createEab({ target: panelEntry, createdBy: 'test' });
      const challenge = core.createScepChallenge({ target: panelEntry,
        profile: 'tls-client', createdBy: 'test' });
      core.addHostName(panelEntry, 'web1.example.com', 'test');
      const state = adminViews.applicationEnrollmentState({ query: {} },
        applications.get('ae-panel'));
      const estRule = state.rules.filter(function (r) {
        return r.family === 'est';
      })[0] || {};
      note(issued && issued.ok && eab.ok && challenge.ok,
           'F0. a certificate, an EAB key and a challenge were made',
           JSON.stringify([issued && issued.errors, eab.errors,
                           challenge.errors]));
      note(state.families.join(',') === 'acme,est,scep' &&
           estRule.certificateLifetimeDays === 30 &&
           estRule.certificateLifetimeSource === 'application',
           'F1. the rules in force name the application\'s own lifetime',
           JSON.stringify(estRule));
      note(state.certificates.length === 1 &&
           state.certificates[0].serialHex === issued.record.serialHex &&
           state.certificates[0].privateKeyPem === undefined &&
           state.json.certificatesPaging.total === 1,
           'F2. the certificate it was issued is listed, with no private ' +
           'key, and paged');
      note(state.eabKeys.length === 1 && !('hmacKey' in state.eabKeys[0]) &&
           state.challenges.length === 1 &&
           JSON.stringify(state.json).indexOf(eab.hmacKey) < 0 &&
           JSON.stringify(state.json).indexOf(challenge.challenge) < 0,
           'F3. its EAB key and challenge are listed with no secret');
      note(state.hostNames.indexOf('web1.example.com') >= 0,
           'F4. its host names are listed');
      const person = adminViews.applicationEnrollmentState({ query: {} },
        { identifier: 'nobody', allowedProtocols: ['oauth2'], fields: {} });
      note(person.families.length === 0 && person.certificates.length === 0,
           'F5. an application declared for none of the three gets nothing');
      const second = adminViews.applicationEnrollmentState({ query: {} },
        applications.get('ae-panel'), 'enrolledConfig');
      note(state.paged.paging.param === 'enrolledPage' &&
           second.paged.paging.param === 'enrolledConfigPage',
           'F7. the list drawn a second time on the page pages on a name ' +
           'of its own, so its pager\'s id differs',
           JSON.stringify([state.paged.paging.param,
                           second.paged.paging.param]));
      // F6, where a form from the application's page came back to, went
      // with the server-rendered console (#446): the static console stays
      // on the page the form was on.
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
  const out = path.join(os.tmpdir(), 'application-enrollment-' + process.pid +
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
                         { LOG_LEVEL: 'fatal', AE_ROOT: ROOT, AE_OUT: out }),
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
  name: 'application_enrollment',
  describe: 'an application\'s ACME, EST and SCEP rules: the declaration in ' +
            'product mode, the profile, lifetime and cap overrides, and ' +
            'EST\'s authentication overrides',
  run: run
};
