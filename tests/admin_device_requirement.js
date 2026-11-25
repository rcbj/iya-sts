// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_device_requirement.js
//
// ===========================================================================
// #2179 (ASVS 5.0.0 8.4.2), in process: the administrative surface requires
// a compliant registered device in product, a setting turns it off, and it
// cannot lock a realm out.
//
// In a child process, because it loads the whole protocol stack and writes
// real people, devices and a roster, none of which outlives it.
//
//   A. THE SWITCH: `devices.requireCompliantDeviceForAdmin=auto` is off in
//      development and on in product (`mode.requiresCompliantDevice-
//      ForAdmin()`); `on` and `off` force it.
//   B. THE FACT: a person's token to the console, or one carrying an admin:*
//      scope, is the administrative surface; a session, an authorization
//      code and an application's (client credentials) token are not.
//   C. OFF, AND DEVELOPMENT: nothing changes — a console token with no
//      device is issued and the requirement bag has no `compliant-admin`.
//   D. IN FORCE, NOT ARMED (the no-lockout path): every administrator is
//      admitted with no device; a person off the roster, a non-compliant
//      device and a preview never arm it; a console administrator issued a
//      console token from their own compliant device ARMS it.
//   E. ARMED: no device, a non-compliant one and somebody else's are
//      refused with the device obligation `admin-not-compliant`, the new
//      sentence and STS-DEVICE-0054 on the audit row; the administrator's
//      own compliant device is admitted; a person's admin:write token
//      through another client is refused; programs (client credentials)
//      and the session are not asked.
//   F. A LATCH: removing the device does not disarm; the setting off
//      admits again and on again is still armed; development (`auto`)
//      admits whatever the latch says.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'admin_device_requirement',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.ADR_ROOT;
  const OUT = process.env.ADR_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const devices = require(ROOT + '/common/devices');
    const recognition = require(ROOT + '/common/device_recognition');
    const gate = require(ROOT + '/common/issuance_gate');
    const audit = require(ROOT + '/common/audit');
    const rbac = require(ROOT + '/admin-ui/admin_rbac');
    const requirement = require(ROOT + '/common/admin_device_requirement');
    const mode = require(ROOT + '/common/mode');
    const stsCrypto = require(ROOT + '/common/crypto');
    const SETTING = 'devices.requireCompliantDeviceForAdmin';
    const CONSOLE = 'sts-admin-console';
    const RUN = nodeCrypto.randomBytes(3).toString('hex');
    // THE DEFAULT REALM of this throwaway child: the console roster a
    // grant writes is the default realm's (a realm created here would be
    // handed a person its roster cannot find), and nothing outlives the
    // child.
    await realms.run(realms.DEFAULT_REALM, async function () {
      const ADMIN = 'adr-admin-' + RUN;
      const OTHER = 'adr-other-' + RUN;
      const PLAIN = 'adr-plain-' + RUN;
      [ADMIN, OTHER, PLAIN].forEach(function (name) {
        ldap.createUser(name, { invent: false, attributes: {} });
      });
      const granted = [ADMIN, OTHER].map(function (name) {
        return rbac.grant(name, 'write', { via: 'test', actor: 'adr' });
      });
      note(granted.every(function (one) {
        return one && one.ok !== false;
      }), 'precondition: two console administrators on the roster',
           JSON.stringify(granted));
      const pub = function () {
        return nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
          .publicKey.export({ format: 'jwk' });
      };
      const adminJwk = pub();
      const plainJwk = pub();
      const laptop = devices.create({ owner: ADMIN, label: 'adr laptop',
        keys: [{ kind: 'jwk', value: adminJwk }] }, 'adr');
      const otherDevice = devices.create({ owner: OTHER, label: 'adr other',
        keys: [{ kind: 'jwk', value: pub() }] }, 'adr');
      const plainDevice = devices.create({ owner: PLAIN, label: 'adr plain',
        keys: [{ kind: 'jwk', value: plainJwk }] }, 'adr');
      note(laptop.ok && otherDevice.ok && plainDevice.ok,
           'precondition: three people\'s devices',
           JSON.stringify([laptop.errors, otherDevice.errors,
                           plainDevice.errors]));
      const id = laptop.device.id;
      const factOf = function (jwk, subject) {
        return recognition.recognize({
          dpopJkt: stsCrypto.jwkThumbprint(jwk), subject: subject });
      };
      const adminsFact = function () {
        return factOf(adminJwk, ADMIN);
      };
      const othersFact = function () {
        return recognition.recognize({
          dpopJkt: otherDevice.device.keys[0].thumbprint, subject: ADMIN });
      };
      // The console's token request, as `oauth2.ts`'s checkIssuance() asks.
      const ask = function (who, fact, extra) {
        return gate.check(Object.assign({
          application: CONSOLE, kind: gate.ISSUANCE.ACCESS_TOKEN,
          subject: { kind: 'user', name: who, authenticated: true },
          scopes: ['openid', 'admin:read', 'admin:write'],
          client: CONSOLE, grantType: 'authorization_code',
          claims: null, risk: null, device: fact }, extra || {}));
      };
      const refusalOf = function (answer) {
        return answer && answer.device ? answer.device.refusal : '';
      };
      const codesSince = function (since) {
        return audit.list().filter(function (row) {
          return Number(row.at) >= since &&
                 row.errorCode === 'STS-DEVICE-0054';
        }).length;
      };

      // --- A. the switch --------------------------------------------------
      const auto = String(config.value(SETTING));
      const devInForce = requirement.inForce();
      config.setOverride('global.mode', 'product');
      const productInForce = requirement.inForce();
      const predicate = mode.requiresCompliantDeviceForAdmin();
      config.setOverride(SETTING, 'off');
      const productOff = requirement.inForce();
      config.clearOverride('global.mode');
      config.setOverride(SETTING, 'on');
      const devOn = requirement.inForce();
      config.clearOverride(SETTING);
      note(auto === 'auto' && devInForce === false &&
           productInForce === true && predicate === true &&
           productOff === false && devOn === true,
           'A1. auto is off in development and on in product; off and on ' +
           'force it either way',
           JSON.stringify([auto, devInForce, productInForce, predicate,
                           productOff, devOn]));

      // --- B. the fact ----------------------------------------------------
      const person = { kind: 'user', name: ADMIN, authenticated: true };
      const surface = function (extra) {
        return requirement.isAdminSurface(Object.assign({
          application: CONSOLE, kind: gate.ISSUANCE.ACCESS_TOKEN,
          subject: person, scopes: [] }, extra));
      };
      note(surface({}) &&
           surface({ kind: gate.ISSUANCE.REFRESH_TOKEN }) &&
           surface({ application: 'adr-cli', scopes: ['admin:write'] }) &&
           !surface({ application: 'adr-cli', scopes: ['openid'] }) &&
           !surface({ kind: gate.ISSUANCE.SESSION }) &&
           !surface({ kind: gate.ISSUANCE.AUTHORIZATION_CODE }) &&
           !surface({ subject: { kind: 'application', name: 'adr-cli' },
                      application: 'adr-cli', scopes: ['admin:write'] }),
           'B1. a person\'s console token or admin:* token is the ' +
           'administrative surface; a session, a code and a program\'s ' +
           'token are not');

      // --- C. off, and development ------------------------------------------
      const devNone = ask(ADMIN, null);
      note(devNone.allowed &&
           gate.deviceRequirementOf().indexOf('compliant-admin') < 0,
           'C1. in development (auto), a console token with no device is ' +
           'issued and the bag has no compliant-admin', devNone.why);
      config.setOverride(SETTING, 'off');
      const offNone = ask(ADMIN, null);
      config.clearOverride(SETTING);
      note(offNone.allowed && !requirement.armedRow(),
           'C2. with the setting off, nothing changes and nothing is armed',
           offNone.why);

      // --- D. in force, not armed: the no-lockout path ---------------------
      config.setOverride(SETTING, 'on');
      const pendingNone = ask(ADMIN, null);
      note(pendingNone.allowed && !requirement.armedRow() &&
           gate.deviceRequirementOf().indexOf('compliant-admin') < 0,
           'D1. in force but not armed, an administrator with no device ' +
           'is admitted: a realm with no compliant device is not locked out',
           pendingNone.why);
      devices.setCompliance(plainDevice.device.id, 'compliant', 'admin',
                            'adr');
      const notAnAdmin = ask(PLAIN, factOf(plainJwk, PLAIN));
      note(notAnAdmin.allowed && !requirement.armedRow(),
           'D2. a person off the console roster, on their own compliant ' +
           'device, does not arm it', notAnAdmin.why);
      devices.setCompliance(id, 'not-compliant', 'admin', 'adr');
      const nonCompliant = ask(ADMIN, adminsFact());
      note(nonCompliant.allowed && !requirement.armedRow(),
           'D3. an administrator on a non-compliant device is admitted and ' +
           'does not arm it', nonCompliant.why);
      devices.setCompliance(id, 'compliant', 'admin', 'adr');
      const previewed = ask(ADMIN, adminsFact(), { preview: true });
      note(previewed.allowed && !requirement.armedRow(),
           'D4. a preview never arms it', previewed.why);
      const session = ask(ADMIN, adminsFact(),
                          { kind: gate.ISSUANCE.SESSION });
      note(session.allowed && !requirement.armedRow(),
           'D5. a session is not the administrative surface and does not ' +
           'arm it', session.why);
      const arming = ask(ADMIN, adminsFact());
      const armed = requirement.armedRow();
      note(arming.allowed && !!armed && Number(armed.at) > 0 &&
           Object.keys(armed).join(',') === 'at' &&
           requirement.view().armed === true &&
           gate.deviceRequirementOf().indexOf('compliant-admin') >= 0,
           'D6. a console administrator issued a console token from their ' +
           'own compliant device ARMS the realm; the row holds only when',
           JSON.stringify([arming.why, armed, requirement.view()]));

      // --- E. armed --------------------------------------------------------
      const since = Date.now() - 1;
      const eNone = ask(OTHER, null);
      devices.setCompliance(otherDevice.device.id, 'not-compliant', 'admin',
                            'adr');
      const eNc = ask(OTHER, recognition.recognize({
        dpopJkt: otherDevice.device.keys[0].thumbprint, subject: OTHER }));
      const eSomebodyElses = ask(OTHER, adminsFact());
      note(!eNone.allowed && refusalOf(eNone) === 'admin-not-compliant' &&
           !eNc.allowed && refusalOf(eNc) === 'admin-not-compliant' &&
           !eSomebodyElses.allowed &&
           refusalOf(eSomebodyElses) === 'admin-not-compliant',
           'E1. armed: no device, a non-compliant one and somebody else\'s ' +
           'compliant one are refused on the administrative device rule',
           JSON.stringify([eNone.why, eNc.why, eSomebodyElses.why]));
      note(String(eNone.why).indexOf('The admin console requires a ' +
                                     'compliant registered device.') === 0,
           'E2. the person is told the console needs a compliant ' +
           'registered device, and how to get one', String(eNone.why));
      note(codesSince(since) >= 3,
           'E3. each refusal is recorded STS-DEVICE-0054 on the audit row',
           codesSince(since));
      const eOwn = ask(ADMIN, adminsFact());
      const eRefresh = ask(ADMIN, adminsFact(),
                           { kind: gate.ISSUANCE.REFRESH_TOKEN });
      note(eOwn.allowed && eRefresh.allowed,
           'E4. the administrator\'s own compliant device is admitted, and ' +
           'its refresh', JSON.stringify([eOwn.why, eRefresh.why]));
      const viaCli = ask(OTHER, null, { application: 'adr-cli',
                                        client: 'adr-cli',
                                        scopes: ['admin:write'] });
      note(!viaCli.allowed && refusalOf(viaCli) === 'admin-not-compliant',
           'E5. a person\'s admin:write token through another client is ' +
           'refused too: /admin-api with a person\'s token', viaCli.why);
      const program = gate.check({
        application: 'sts-api-client', kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'application', name: 'sts-api-client',
                   authenticated: true },
        scopes: ['admin:read', 'admin:write'], client: 'sts-api-client',
        grantType: 'client_credentials', claims: null, risk: null,
        device: null });
      note(program.allowed || refusalOf(program) !== 'admin-not-compliant',
           'E6. a program (client credentials) is never asked about the ' +
           'administrator\'s device', JSON.stringify([program.allowed,
                                                     program.why]));
      const eSession = ask(OTHER, null, { kind: gate.ISSUANCE.SESSION });
      note(eSession.allowed,
           'E7. the sign-in session itself is not refused: the token ' +
           'endpoint is where the device is asked', eSession.why);
      config.setOverride('devices.compliantDeviceAttested', true);
      const selfAsserted = ask(ADMIN, adminsFact());
      config.clearOverride('devices.compliantDeviceAttested');
      note(!selfAsserted.allowed &&
           refusalOf(selfAsserted) === 'admin-not-compliant',
           'E8. with devices.compliantDeviceAttested on, a self-asserted ' +
           'compliant device is refused', selfAsserted.why);

      // --- F. a latch -------------------------------------------------------
      devices.remove(id, undefined, 'adr');
      const afterRemove = ask(ADMIN, null);
      note(!!requirement.armedRow() && !afterRemove.allowed,
           'F1. removing the administrator\'s device (as the portal lets a ' +
           'person do) does not disarm the realm', afterRemove.why);
      config.setOverride(SETTING, 'off');
      const offAgain = ask(ADMIN, null);
      config.setOverride(SETTING, 'on');
      const onAgain = ask(ADMIN, null);
      note(offAgain.allowed && !onAgain.allowed,
           'F2. the setting off admits again (the program\'s way back in), ' +
           'and on again is still armed',
           JSON.stringify([offAgain.why, onAgain.why]));
      config.clearOverride(SETTING);
      const devArmed = ask(ADMIN, null);
      note(devArmed.allowed,
           'F3. development (auto) admits whatever the latch says',
           devArmed.why);
      requirement.forgetForTests();
    });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (error) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: String((error && error.stack) || error) });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'admin-device-requirement-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', ADR_ROOT: ROOT,
                                  ADR_OUT: out }),
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
  if (!findings) {
    t.check(false, 'the child process reported its findings',
            String(result.stderr || result.error || '').slice(-2000));
    log.debug("Leaving run(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_device_requirement',
  describe: '#2179: the administrative surface (the console, a person\'s ' +
            'admin:* token) requires a compliant registered device in ' +
            'product (devices.requireCompliantDeviceForAdmin=auto), armed ' +
            'on first proof so a realm is never locked out, a latch the ' +
            'portal cannot reopen, programs and development unaffected',
  run: run
};
